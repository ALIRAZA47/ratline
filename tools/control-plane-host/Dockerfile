# The control plane on Ubuntu 24.04 (RL-M1-055).
#
# A place to RUN Ratline, as opposed to tools/integration-host/Dockerfile, which is a
# host for Ratline to MANAGE. The two are deliberately separate images: this one has
# Node and Postgres and no systemd, that one has systemd as PID 1 and no Node. An
# image that was both would let a test accidentally verify the manager against itself.
#
# Ubuntu 24.04 rather than a node: base image, because the brief's scope is
# self-hosting on an ordinary VPS and "ordinary" means the distribution's own
# packaging is what an operator will hit. Ubuntu 24.04 ships Node 18, which cannot run
# this codebase — `--experimental-strip-types` needs 22.6 — so Node comes from
# NodeSource and Postgres from PGDG, which is exactly the friction a real install has.
# Hiding it behind a prebuilt image would move that discovery to somebody else.
FROM ubuntu:24.04

# Non-interactive, and no recommends: a smaller image is a smaller thing to reason
# about, and `apt` pulling in a recommended package that starts a daemon is how a
# container ends up running something nobody chose.
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl gnupg lsb-release sudo git \
    && rm -rf /var/lib/apt/lists/*

# --- Node 22 from NodeSource -------------------------------------------------
#
# The key is fetched to a keyring and the repository is pinned to it with
# signed-by, rather than the older apt-key path that trusts a key for every
# repository on the system. That distinction is the same one C1 and C2 are about:
# narrow the authority to what the job needs.
RUN curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
      | gpg --dearmor -o /usr/share/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" \
      > /etc/apt/sources.list.d/nodesource.list \
    && apt-get update && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# --- Postgres 17 from PGDG ---------------------------------------------------
#
# 17 specifically. The migrations use `security_invoker` on views, which needs 15+,
# and every row-level-security test in the suite runs against 17 — so an image with
# 16 would be testing a configuration nothing else does.
RUN curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
      | gpg --dearmor -o /usr/share/keyrings/pgdg.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/pgdg.gpg] http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" \
      > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update && apt-get install -y --no-install-recommends \
      postgresql-17 postgresql-client-17 \
    && rm -rf /var/lib/apt/lists/*

# --- The account Ratline runs as --------------------------------------------
#
# NOT root, and this is the point of using a container at all rather than running it
# on the Mac. C1 is about not needing root on managed hosts; the control plane not
# needing it either is the same instinct applied to itself. If anything in the boot
# path turns out to require root, that is a defect and this image is where it surfaces.
RUN useradd --create-home --shell /bin/bash ratline

# The secrets directory. Mode 0700 and owned by the service account: C4 has the
# application generate its own secrets on first run, and a directory anybody could
# read would make that generation pointless.
RUN mkdir -p /var/lib/ratline/secrets \
    && chown -R ratline:ratline /var/lib/ratline \
    && chmod 700 /var/lib/ratline/secrets

WORKDIR /srv/ratline

# Dependencies before source, so editing a file does not reinstall node_modules.
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY . .

# The dashboard is built INSIDE the image (RL-M1-057). Vite is the project's only
# build step, and running it here rather than copying a local dist/ means the image
# cannot ship a stale bundle from whenever somebody last built on their laptop — which
# is the same reason .dockerignore excludes dist/ in the first place.
RUN npm run build:web

RUN chown -R ratline:ratline /srv/ratline

# The database cluster lives in the image's default location and is started by the
# entry script, because Postgres refuses to run as PID 1 usefully and this image has
# no init. One script starting two processes is honest about being a development
# container rather than pretending to be a deployment.
COPY tools/control-plane-host/entrypoint.sh /usr/local/bin/ratline-entrypoint
RUN chmod +x /usr/local/bin/ratline-entrypoint

# 127.0.0.1 by default, which is C5 working rather than being worked around: the
# dashboard is reached with `docker exec`, not by publishing a port. `scripts/stack
# shell` is how you get in. Overriding this needs
# RATLINE_ALLOW_PUBLIC_BIND, which preflight reports loudly on every boot.
# The names matter: resolveBindAddress reads RATLINE_BIND_ADDRESS and resolvePort
# reads RATLINE_BIND_PORT. Setting RATLINE_BIND and RATLINE_PORT — which is what I
# wrote first — would have been silently ignored and the defaults used instead, so the
# container would have appeared configured while nothing read the configuration.
ENV RATLINE_BIND_ADDRESS=127.0.0.1 \
    RATLINE_BIND_PORT=8787 \
    RATLINE_SECRETS_DIR=/var/lib/ratline/secrets \
    DATABASE_URL=postgres://ratline@127.0.0.1:5432/ratline

ENTRYPOINT ["/usr/local/bin/ratline-entrypoint"]
CMD ["serve"]
