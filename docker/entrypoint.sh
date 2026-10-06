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

# `proxpass session' runs as the logged-in user, not as root, so it needs to
# reach the database. Access is granted through dedicated groups rather than
# by loosening the mode: the database holds proxmox API credentials and every
# client's public keys, so it must not become world readable.
#
# Clients get READ access via gid PROXPASS_GID, the admin gets WRITE access
# via PROXPASS_ADMIN_GID. Splitting them means a client session cannot modify
# another client's access rules or corrupt the database.
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
# 2770, not 2775: nothing outside the administrator's group has any business
# in here. The setgid bit keeps new files in that group so the admin CLI can
# still write them. A client session reaches the directory API over loopback
# and never opens this directory at all.
chmod 2770 "${PROXPASS_DATA_DIR}"
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
	# 0660 root:<admin gid>. The administrator's group reads and writes;
	# EVERYONE ELSE, which means every client login, gets nothing.
	#
	# It used to be 0664, world readable, because a client session opened
	# this file itself to list its guests. That also handed it
	# api_token_secret and the instances' ssh_key -- every Proxmox
	# credential in the deployment -- to anyone who could log in at all.
	# A client session now reads through the loopback API instead and
	# holds no database handle, so the read bit can finally go.
	#
	# Do not widen this back without first moving the admin CLI off the
	# file too: the mode is what enforces the separation; the code is
	# only where the reads happen to come from.
	fix_db_mode() {
		# Nothing to do when the database is a server: these permissions
		# exist to control who may write the SQLite FILE.
		proxpass_uses_postgres && return 0
		[ -f "${PROXPASS_DATA}" ] || return 0
		chown "root:${PROXPASS_ADMIN_GID}" "${PROXPASS_DATA}" 2>/dev/null || true
		chmod 0660 "${PROXPASS_DATA}" 2>/dev/null || true
		# sqlite writes -wal/-shm siblings next to the database.
		for sib in "${PROXPASS_DATA}-wal" "${PROXPASS_DATA}-shm" "${PROXPASS_DATA}-journal"; do
			[ -e "${sib}" ] || continue
			chown "root:${PROXPASS_ADMIN_GID}" "${sib}" 2>/dev/null || true
			chmod 0660 "${sib}" 2>/dev/null || true
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
