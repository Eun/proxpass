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
# serves and the member list would always come back empty. The gids are fixed
# here and must match api.SharedGroupGID and api.AdminGroupGID.
PROXPASS_GID="${PROXPASS_GID:-64000}"
PROXPASS_ADMIN_GID="${PROXPASS_ADMIN_GID:-64001}"

# The directory is owned by the admin group and setgid, so sqlite's WAL and
# journal siblings inherit it. Clients need to traverse and read it, which
# "other" x+r provides without letting them create or unlink anything.
chown -R "root:${PROXPASS_ADMIN_GID}" "${PROXPASS_DATA_DIR}"
chmod 2775 "${PROXPASS_DATA_DIR}"
PROXPASS_DATA="${PROXPASS_DATA:-${PROXPASS_DATA_DIR}/proxpass.db}"
export PROXPASS_DATA
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
	# 0664 root:<admin gid>: the admin group writes, everyone else (i.e. the
	# client logins, via their shared primary group) only reads. Clients must
	# not be able to modify another client's access rules.
	fix_db_mode() {
		[ -f "${PROXPASS_DATA}" ] || return 0
		chown "root:${PROXPASS_ADMIN_GID}" "${PROXPASS_DATA}" 2>/dev/null || true
		chmod 0664 "${PROXPASS_DATA}" 2>/dev/null || true
		# sqlite writes -wal/-shm siblings next to the database.
		for sib in "${PROXPASS_DATA}-wal" "${PROXPASS_DATA}-shm" "${PROXPASS_DATA}-journal"; do
			[ -e "${sib}" ] || continue
			chown "root:${PROXPASS_ADMIN_GID}" "${sib}" 2>/dev/null || true
			chmod 0664 "${sib}" 2>/dev/null || true
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
