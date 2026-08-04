#!/bin/sh
# Bring up Postgres, then Ratline (RL-M1-055).
#
# Two processes in one container, which is not how this would be deployed and is
# stated rather than glossed: a real install has Postgres somewhere else, and ADR 0007
# already treats the database as a separate concern. What this image buys is one
# command that produces a running control plane on Ubuntu 24.04, which is the thing
# nothing in the tracker had ever done.
set -eu

PGBIN=/usr/lib/postgresql/17/bin
PGDATA=/var/lib/ratline/pgdata
PGRUN=/var/lib/ratline/run

start_postgres() {
	# Created every boot: /var/run is a tmpfs on some hosts, and a socket directory
	# that vanished between restarts would fail in the same confusing way.
	mkdir -p "$PGRUN"
	chown ratline:ratline "$PGRUN"

	if [ ! -s "$PGDATA/PG_VERSION" ]; then
		echo "initialising the cluster at $PGDATA"
		mkdir -p "$PGDATA"
		chown ratline:ratline "$PGDATA"
		chmod 700 "$PGDATA"
		# --auth=trust on loopback only, inside one container. The fixtures connect as
		# `ratline_app`, which migration 2 creates NOLOGIN and passwordless on purpose
		# because a login role with a shipped password is the default credential C4
		# forbids. The same reasoning as the CI workflow's POSTGRES_HOST_AUTH_METHOD.
		su ratline -c "$PGBIN/initdb -D $PGDATA --auth=trust --username=ratline -E UTF8" >/dev/null
		# Loopback only. The cluster must not be reachable from outside this container
		# even if somebody publishes a port later.
		echo "listen_addresses = '127.0.0.1'" >> "$PGDATA/postgresql.conf"

		# The socket directory has to move, and this is a real finding rather than a
		# container quirk. Postgres defaults to /var/run/postgresql, which the Debian
		# packaging creates owned by `postgres` — so a cluster run by any other account
		# dies with "could not create lock file ... Permission denied" while still
		# reporting that it is listening on 127.0.0.1. The log says the server started
		# and then shut down, one line apart.
		#
		# Chowning a system directory would fix it and would also mean the service
		# account owns something outside its own tree. Everything Ratline writes lives
		# under /var/lib/ratline instead, which is the same instinct as C1: narrow the
		# authority to what the job needs.
		echo "unix_socket_directories = '$PGRUN'" >> "$PGDATA/postgresql.conf"
	fi

	su ratline -c "$PGBIN/pg_ctl -D $PGDATA -l $PGDATA/server.log -w start" >/dev/null

	if ! su ratline -c "psql -h 127.0.0.1 -U ratline -lqt" | cut -d'|' -f1 | grep -qw ratline; then
		su ratline -c "createdb -h 127.0.0.1 -U ratline ratline"
		echo "created the ratline database"
	fi
}

case "${1:-serve}" in
serve)
	start_postgres
	echo ""
	exec su ratline -c 'cd /srv/ratline && exec node --experimental-strip-types --no-warnings=ExperimentalWarning src/main.ts'
	;;
shell)
	start_postgres
	exec su ratline -c 'cd /srv/ratline && exec bash'
	;;
psql)
	start_postgres
	exec su ratline -c 'psql -h 127.0.0.1 -U ratline ratline'
	;;
*)
	start_postgres
	shift
	exec su ratline -c "cd /srv/ratline && $*"
	;;
esac
