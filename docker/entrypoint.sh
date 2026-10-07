#!/bin/sh
# proxpass container entrypoint.
#
# Order matters here: sshd resolves proxpass users through NSS, and NSS talks
# to the HTTP API that `proxpass serve' exposes. So we must have a working
# `proxpass serve' BEFORE sshd accepts the first connection, otherwise early
# logins fail with "invalid user" instead of being authenticated.
#
#   1. make sure the sshd host keys exist (persisted, so client known_hosts
#      entries survive a container restart)
#   2. start `proxpass serve' in the background
#   3. wait for its HTTP API to answer
#   4. exec sshd in the foreground
set -eu

PROXPASS_BIN="${PROXPASS_BIN:-/app}"
PROXPASS_DATA_DIR="${PROXPASS_DATA_DIR:-/var/lib/proxpass}"
# Not configurable: the HostKey lines in docker/sshd_config.d/proxpass.conf
# hardcode these paths, so the two would silently drift apart.
PROXPASS_HOST_KEY_DIR="/var/lib/proxpass/ssh"
# Shared home directory for every proxpass login; must match api.HomeDir.
PROXPASS_HOME_DIR="${PROXPASS_HOME_DIR:-/var/empty/proxpass}"
# Must stay in sync with the URLs in /etc/nss_http.json.
PROXPASS_LISTEN="${PROXPASS_LISTEN:-127.0.0.1:8080}"
PROXPASS_READY_TIMEOUT="${PROXPASS_READY_TIMEOUT:-30}"

export PROXPASS_LISTEN

log() {
	echo "entrypoint: $*" >&2
}

serve_pid=""

# Forward SIGTERM/SIGINT to both children so `docker stop' is a clean shutdown
# and not a 10 second wait followed by SIGKILL.
terminate() {
	trap - TERM INT
	if [ -n "${serve_pid}" ]; then
		kill -TERM "${serve_pid}" 2>/dev/null || true
	fi
	# sshd is this shell's foreground child until we exec it away; killing the
	# whole process group covers both cases.
	kill -TERM 0 2>/dev/null || true
}
trap terminate TERM INT

mkdir -p "${PROXPASS_DATA_DIR}" "${PROXPASS_HOST_KEY_DIR}"

# `proxpass session' runs as the logged-in user, not as root. It no longer
# needs to reach the database at all: every session, client and administrator
# alike, goes through the loopback API, and `proxpass serve' is the only
# process that opens the file. The mode is 0600 root:root accordingly.
#
# The two groups REMAIN, and no longer carry access control.
#
# They used to: clients got read access via PROXPASS_GID and the
# administrator write access via PROXPASS_ADMIN_GID, and that split was what
# stopped a client modifying another client's rules. The separation now lives
# in the API -- an admin operation is refused unless the caller's stored
# identity says IsAdmin, which is tested, rather than in a file mode that has
# to be re-derived correctly on every container start.
#
# They are kept because sshd still needs a primary group for each login, the
# NSS directory still has to serve one, and the UID/GID layout is part of the
# published interface (PROXPASS_GID, PROXPASS_ADMIN_GID). Removing them would
# be a visible change to deployments for no security gain. What is gone is
# their power: granting a login the admin gid now grants it nothing.
#
# Neither group is created in /etc/group. nsswitch.conf consults "files"
# before "http", so a local entry would shadow the one the proxpass directory
# serves and the member list would always come back empty.
#
# These are the same variables `proxpass serve' reads (see api.IDLayout), so
# overriding them here and in the environment keeps the filesystem ownership
# and the served gids in agreement. Defaults must match api.DefaultSharedGroupGID
# and api.DefaultAdminGroupGID.
#
# Note the ceiling: on a userns-remapped or rootless daemon only the 65536
# subordinate ids from /etc/subuid exist inside the container, so an id above
# 65535 makes sshd fail the login with "setresuid <uid>: Invalid argument"
# after it has already accepted the key.
PROXPASS_GID="${PROXPASS_GID:-19000}"
PROXPASS_ADMIN_GID="${PROXPASS_ADMIN_GID:-19001}"
export PROXPASS_GID PROXPASS_ADMIN_GID

# The directory is owned by the admin group and setgid, so sqlite's WAL and
# journal siblings inherit it. Clients need to traverse and read it, which
# "other" x+r provides without letting them create or unlink anything.
chown -R "root:${PROXPASS_ADMIN_GID}" "${PROXPASS_DATA_DIR}"
# 2700: only root. `proxpass serve' is the only process that opens anything
# in here -- every session, administrator included, goes through the API --
# so nothing else needs to traverse it. The setgid bit is kept so that a
# pre-existing deployment's files keep their group on upgrade rather than
# changing ownership underneath a running container.
chmod 2700 "${PROXPASS_DATA_DIR}"
# PROXPASS_DATA is either a SQLite path or a postgres:// URL. Only the former
# gets a default, because there is no sensible default for a server nobody has
# told us about.
PROXPASS_DATA="${PROXPASS_DATA:-${PROXPASS_DATA_DIR}/proxpass.db}"
export PROXPASS_DATA

# PROXPASS_DSN_FILE holds the DSN for the sshd helpers.
#
# sshd runs AuthorizedKeysCommand and ForceCommand with a SCRUBBED
# environment, so neither sees PROXPASS_DATA. That went unnoticed while the
# default was the right answer -- the helper fell back to the same SQLite path
# the server used. Pointing proxpass at Postgres makes the fallback wrong
# rather than redundant: the helper would quietly create an EMPTY SQLite
# database, find no keys in it, and every login would be refused.
#
# The file is root-owned and world-readable: it is read by
# AuthorizedKeysCommand (root) and by each session (uid 19999). It may hold a
# password, so it is 0644 rather than group-writable, and it is NOT in the
# data directory clients can list.
PROXPASS_DSN_FILE="/run/proxpass/dsn"
mkdir -p "$(dirname "${PROXPASS_DSN_FILE}")"
printf '%s' "${PROXPASS_DATA}" > "${PROXPASS_DSN_FILE}"
chown root:root "${PROXPASS_DSN_FILE}"
chmod 0644 "${PROXPASS_DSN_FILE}"

# proxpass_uses_postgres reports whether the database lives on a server rather
# than in a file. The file-permission work below is meaningless then: there is
# no file to chmod, and write access is decided by the DSN's credentials.
proxpass_uses_postgres() {
	case "${PROXPASS_DATA}" in
	postgres://* | postgresql://*) return 0 ;;
	*) return 1 ;;
	esac
}
# Host keys stay root-only: sshd reads them before dropping privileges.
chown -R root:root "${PROXPASS_HOST_KEY_DIR}"
chmod 0700 "${PROXPASS_HOST_KEY_DIR}"

# sshd refuses to start a session whose home directory is missing, and warns
# on every login when it cannot chdir there.
mkdir -p "${PROXPASS_HOME_DIR}"
chmod 0755 "${PROXPASS_HOME_DIR}"

# sshd's privilege separation directory lives on tmpfs in a container.
mkdir -p /run/sshd
chmod 0755 /run/sshd

# Host keys live under the volume, so a recreated container keeps its identity.
for type in rsa ecdsa ed25519; do
	key="${PROXPASS_HOST_KEY_DIR}/ssh_host_${type}_key"
	if [ ! -f "${key}" ]; then
		log "generating ${type} host key"
		ssh-keygen -q -t "${type}" -f "${key}" -N "" -C "proxpass"
	fi
	chmod 0600 "${key}"
done

# The key proxpass uses to reach the Proxmox hosts, as an SSH *client*.
#
# This is the opposite direction from the host keys above: those identify this
# container to connecting users, this one identifies proxpass to Proxmox. It
# is ONE key for every instance, because the administrator has to install its
# public half on each host by hand and a key per instance multiplies that work
# without buying any isolation -- whoever can read one can read them all.
#
# Generated here rather than by `proxpass serve' so that it lives on the
# volume as an ordinary file whose public half the administrator can read:
#
#     docker compose exec proxpass cat /var/lib/proxpass/ssh/proxpass_key.pub
#
# `proxpass instance add' also prints it, but only when the host is not yet
# reachable; a deployment that has lost that output needs somewhere to look it
# up. Keeping it on the volume also means recreating the container does NOT
# invalidate the key already installed on every Proxmox host.
#
# PROXPASS_SSH_KEY_FILE names the file, so a deployment that manages the key
# itself can point this at a secrets mount instead. The key is passed by PATH
# rather than by value because only `proxpass serve' ever opens it: handing it
# through the environment would put a Proxmox credential in the environment of
# a process whose /proc/<pid>/environ is readable by anything running as the
# same user.
#
# Must stay in sync with models.DefaultSSHKeyPath, which is what reads it.
PROXPASS_SSH_KEY_FILE="${PROXPASS_SSH_KEY_FILE:-${PROXPASS_HOST_KEY_DIR}/proxpass_key}"
if [ ! -f "${PROXPASS_SSH_KEY_FILE}" ]; then
	log "generating the proxmox client key"
	mkdir -p "$(dirname "${PROXPASS_SSH_KEY_FILE}")"
	# ed25519: Proxmox reads this only as an authorized_keys line, which has
	# no algorithm restriction. (PVE's own known_hosts handling is RSA-only,
	# but that concerns HOST keys -- the ones verified in the other
	# direction -- not this one.)
	ssh-keygen -q -t ed25519 -f "${PROXPASS_SSH_KEY_FILE}" -N "" -C "proxpass"
	log "proxmox client key generated; install the public half on each Proxmox host:"
	log "  $(cat "${PROXPASS_SSH_KEY_FILE}.pub")"
fi
# Root-only, like the host keys: `proxpass serve' runs as root and is the only
# process that opens it. A session is handed the contents by the API after its
# access check, and could not read the file even if it tried.
chmod 0600 "${PROXPASS_SSH_KEY_FILE}"
# The public half is what the administrator installs, so it stays readable.
if [ -f "${PROXPASS_SSH_KEY_FILE}.pub" ]; then
	chmod 0644 "${PROXPASS_SSH_KEY_FILE}.pub"
fi
export PROXPASS_SSH_KEY_FILE

# A 200 on the user list endpoint means `proxpass serve' is far enough along
# that NSS lookups will succeed. --fail turns any non-2xx into a non-zero exit.
nss_api_ready() {
	curl --silent --show-error --fail --max-time 2 \
		--output /dev/null "http://${PROXPASS_LISTEN}/users"
}

if [ "$#" -eq 0 ]; then
	log "starting proxpass serve on ${PROXPASS_LISTEN}"
	# Run serve under a group-writable umask so the database and sqlite's
	# -wal/-journal siblings are writable by the proxpass group, which is
	# every session's primary group. The umask is scoped to this subshell so
	# it does not affect sshd or the host key files.
	(umask 0007; exec "${PROXPASS_BIN}" serve) &
	serve_pid=$!

	# The database must be group writable: sessions run as the logged-in
	# user, not as root, and the admin CLI writes to it. This has to happen
	# after serve has created the file — a chmod beforehand would silently
	# do nothing on a fresh volume and every write would fail with
	# "attempt to write a readonly database".
	# 0600 root:root. NOBODY but root -- which means `proxpass serve' --
	# touches this file. Not the administrator's group either.
	#
	# The history is the point. It was 0664 -- world readable -- because a
	# client session opened this file to list its guests, which also handed
	# it api_token_secret and the instances' ssh_key. It became 0660 when
	# clients moved to the API. It is 0600 now that the ADMIN CLI has moved
	# too: every session, privileged or not, reaches the database through
	# `proxpass serve', which is the only process that opens it.
	#
	# That is what retires the gid split. The admin group no longer needs
	# write access to a file, so the split between it and the client group
	# stops carrying any weight -- see docker/sshd_config.d and the id
	# layout. The separation now lives in the API's admin check, which is
	# tested, rather than in a mode that has to be re-derived on every
	# container start.
	fix_db_mode() {
		# Nothing to do when the database is a server: these permissions
		# exist to control who may write the SQLite FILE.
		proxpass_uses_postgres && return 0
		[ -f "${PROXPASS_DATA}" ] || return 0
		chown "root:${PROXPASS_ADMIN_GID}" "${PROXPASS_DATA}" 2>/dev/null || true
		chmod 0600 "${PROXPASS_DATA}" 2>/dev/null || true
		# sqlite writes -wal/-shm siblings next to the database.
		for sib in "${PROXPASS_DATA}-wal" "${PROXPASS_DATA}-shm" "${PROXPASS_DATA}-journal"; do
			[ -e "${sib}" ] || continue
			chown "root:${PROXPASS_ADMIN_GID}" "${sib}" 2>/dev/null || true
			chmod 0600 "${sib}" 2>/dev/null || true
		done
	}

	log "waiting for the proxpass nss api on ${PROXPASS_LISTEN}"
	waited=0
	until nss_api_ready 2>/dev/null; do
		if ! kill -0 "${serve_pid}" 2>/dev/null; then
			log "proxpass serve exited before becoming ready"
			wait "${serve_pid}" || true
			exit 1
		fi
		if [ "${waited}" -ge "${PROXPASS_READY_TIMEOUT}" ]; then
			log "proxpass nss api did not come up within ${PROXPASS_READY_TIMEOUT}s"
			exit 1
		fi
		sleep 1
		waited=$((waited + 1))
	done
	log "proxpass nss api is up"
	fix_db_mode

	# -D: stay in the foreground, -e: log to stderr so `docker logs' works.
	exec /usr/sbin/sshd -D -e
fi

exec "$@"
