# proxpass image.
#
# proxpass no longer speaks the SSH protocol itself: OpenSSH `sshd' terminates
# the connection and proxpass only provides
#   * the authorized keys      (sshd AuthorizedKeysCommand -> `proxpass authorized-keys')
#   * the session              (sshd ForceCommand          -> `proxpass session')
#   * the accounts themselves  (NSS -> libnss_http.so.2 -> `proxpass serve' HTTP API)
#
# The base image MUST be glibc based. NSS is a glibc mechanism and musl has no
# support for it at all (no nss.h, no __nss_* loader hooks, /etc/passwd is read
# directly), so Alpine cannot resolve proxpass users -- this is verified and
# non-negotiable. Hence debian:*-slim.

# Pinned to a tagged release of nss_http-go rather than a branch, so an
# image rebuild cannot silently pick up upstream changes. Bump deliberately,
# and re-run the image tests when you do.
#   https://github.com/Eun/nss_http-go/releases
ARG NSS_HTTP_REPO="https://github.com/Eun/nss_http-go.git"
ARG NSS_HTTP_REF="v1.0.0"
ARG DEBIAN_RELEASE="bookworm"

# --- build stage ------------------------------------------------------------
# Builds libnss_http.so.2 (the NSS module) and the nss_http binary (the
# AuthorizedKeysCommand helper of that project) exactly like its Makefile
# `all' target does. -buildmode=c-shared needs cgo, hence golang + gcc +
# libc6-dev, and the .so must be linked against the SAME glibc as the runtime
# stage -- so both stages use the same Debian release.
FROM golang:1.25-${DEBIAN_RELEASE} AS nss-builder

ARG NSS_HTTP_REPO
ARG NSS_HTTP_REF

RUN set -eux; \
    apt-get update; \
    apt-get install --no-install-recommends -y \
        ca-certificates \
        gcc \
        git \
        libc6-dev \
        make; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN set -eux; \
    git init -q .; \
    git remote add origin "${NSS_HTTP_REPO}"; \
    git fetch -q --depth 1 origin "${NSS_HTTP_REF}"; \
    git checkout -q FETCH_HEAD

# Mirrors the `all' target of the nss_http-go Makefile. The soname must be
# libnss_http.so.2: glibc's NSS loader dlopen()s `libnss_<service>.so.<ver>'
# and refuses a module whose soname does not match.
ENV CGO_ENABLED=1
RUN set -eux; \
    go build -o dist/libnss_http.so -buildmode=c-shared \
        -ldflags="-extldflags '-Wl,-soname,libnss_http.so.2' -s -w"; \
    go build -ldflags="-s -w" -o dist/nss_http

# --- runtime stage ----------------------------------------------------------
FROM debian:${DEBIAN_RELEASE}-slim

ARG BINARY

RUN set -eux; \
    apt-get update; \
    apt-get install --no-install-recommends -y \
        ca-certificates \
        curl \
        openssh-server; \
    rm -rf /var/lib/apt/lists/*; \
    # Debian's openssh-server generates host keys at install time; proxpass
    # generates its own into the volume instead, so drop these to make sure
    # no image-baked (and therefore shared and public) host key is ever used.
    rm -f /etc/ssh/ssh_host_*; \
    # The package also ships a default sshd_config.d drop-in on some releases;
    # keep the directory but make sure only our config lands in it.
    rm -f /etc/ssh/sshd_config.d/*.conf; \
    mkdir -p /etc/ssh/sshd_config.d /run/sshd /var/lib/proxpass; \
    chmod 0700 /var/lib/proxpass

# `make install' of nss_http-go: the module into /lib, the helper into /sbin
# with the nss_http_sshkey alias (the binary switches to `sshkey' mode based on
# argv[0], so the symlink name matters).
COPY --from=nss-builder /src/dist/libnss_http.so /lib/libnss_http.so.2
COPY --from=nss-builder /src/dist/nss_http /sbin/nss_http
RUN set -eux; \
    chmod 0644 /lib/libnss_http.so.2; \
    chmod 0755 /sbin/nss_http; \
    ln -sf /sbin/nss_http /sbin/nss_http_sshkey

# Resolve proxpass users over HTTP, but only after `files'.
COPY docker/nsswitch.conf /etc/nsswitch.conf
# /etc/nss_http.json is plain JSON and cannot carry comments, so the two
# non-obvious settings in it are explained here:
#
#  * "Cache": {"Name": "disabled"} -- an unset or unrecognised cache name does
#    NOT mean "no cache": nss_http falls back to its in-memory cache with a 60s
#    TTL, which would keep serving revoked users and stale public keys for a
#    minute. It has to say "disabled" verbatim.
#
#  * "AllowListingOfUsers"/"AllowListingOfGroups": false -- proxpass only ever
#    needs lookups by name/uid, never enumeration. Leaving enumeration on is
#    also actively harmful: sshd calls getgrent() late in session setup, after
#    it has closed the file descriptors it does not need, and the Go runtime
#    inside the NSS module then aborts the whole sshd child with
#    "netpollBreak write failed with 9" (EBADF). Verified against this image.
COPY docker/nss_http.json /etc/nss_http.json
COPY docker/sshd_config.d/proxpass.conf /etc/ssh/sshd_config.d/proxpass.conf

# sshd rejects an AuthorizedKeysCommand that is not an absolute path, not owned
# by root, or writable by group/other -- hence the explicit 0755 root:root.
COPY docker/proxpass-authorized-keys /usr/local/bin/proxpass-authorized-keys
COPY docker/proxpass-session /usr/local/bin/proxpass-session
COPY docker/entrypoint.sh /usr/local/bin/proxpass-entrypoint
RUN set -eux; \
    chown root:root \
        /usr/local/bin/proxpass-authorized-keys \
        /usr/local/bin/proxpass-session \
        /usr/local/bin/proxpass-entrypoint \
        /etc/nsswitch.conf \
        /etc/nss_http.json \
        /etc/ssh/sshd_config.d/proxpass.conf; \
    chmod 0755 \
        /usr/local/bin/proxpass-authorized-keys \
        /usr/local/bin/proxpass-session \
        /usr/local/bin/proxpass-entrypoint; \
    chmod 0644 \
        /etc/nsswitch.conf \
        /etc/nss_http.json \
        /etc/ssh/sshd_config.d/proxpass.conf

# Provided by goreleaser, which builds the binary into dist/ and then uses
# dist/ as the docker build context.
COPY $BINARY /app

# Host keys, the proxpass database and any other state.
VOLUME ["/var/lib/proxpass"]

ENV PROXPASS_DATA="/var/lib/proxpass/proxpass.db" \
    PROXPASS_LISTEN="127.0.0.1:8080"

EXPOSE 22

ENTRYPOINT ["/usr/local/bin/proxpass-entrypoint"]
