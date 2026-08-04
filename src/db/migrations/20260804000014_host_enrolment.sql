-- Host enrolment and client certificates (RL-M2-005).
--
-- ADR 0002: "Each host holds its own client certificate, issued at enrolment via a
-- single-use short-lived token, and individually revocable."
--
-- Three facts have to be recorded, and they are deliberately in two tables rather
-- than one.
--
-- `hosts` is the machine. It outlives any particular certificate, because rotating a
-- host's certificate must not look like a different host.
--
-- `host_certificates` is one issued certificate. A host has many over its life — a
-- rotation issues a new one and revokes the old — so folding the certificate into
-- `hosts` would mean either losing the history or overwriting the record of what was
-- trusted when. The audit log needs that history: "which certificate signed the
-- connection that ran this operation" is a question an incident asks.
--
-- REVOCATION IS A COLUMN, NOT A CRL. Acceptance 2 says revocation "takes effect on
-- next connection", and a certificate revocation list would take effect whenever the
-- list was next distributed and parsed — which is a different guarantee, weaker, and
-- one that fails silently when distribution fails. The control plane already has to
-- read the database to accept a connection, so checking a column there is both simpler
-- and strictly stronger: there is no window and nothing to distribute.
--
-- ## The enrolment token is a hash, not a token
--
-- `enrolment_token_hash`, never the token. A token stored in the database is a
-- credential readable by anyone who can read the database — which for a control plane
-- includes every backup, every replica, and every `pg_dump` in somebody's downloads
-- folder. The token exists in plaintext exactly once, in the response to the operator
-- who asked for it, and is never written down here.

-- migrate:up

create table hosts (
  id           uuid primary key default gen_random_uuid(),
  org_id       uuid not null references organizations (id) on delete cascade,
  -- The name an operator gave it. Not a hostname: a hostname is what the machine
  -- calls itself and can change without anybody deciding it should.
  name         text not null,
  -- Where the agent connects FROM, recorded on first connection rather than supplied
  -- at enrolment. An address supplied by whoever enrols is a claim; an address
  -- observed on a mutually authenticated connection is an observation.
  last_seen_ip inet,
  last_seen_at timestamptz,
  created_at   timestamptz not null default statement_timestamp(),

  unique (org_id, name),
  constraint hosts_name_present check (length(btrim(name)) > 0)
);

create table host_enrolments (
  id         uuid primary key default gen_random_uuid(),
  org_id     uuid not null references organizations (id) on delete cascade,
  host_id    uuid not null references hosts (id) on delete cascade,

  -- SHA-256 of the token. See the note above about why the token itself is absent.
  token_hash bytea not null,

  -- Short lived, and the ceiling is enforced in the application because "short" is a
  -- policy rather than a schema fact. What the schema enforces is that an expiry
  -- exists at all: a token with no expiry is a permanent credential, and the column
  -- being NOT NULL means nobody can create one by omission.
  expires_at timestamptz not null,

  -- SINGLE USE, enforced here rather than only in code. `spent_at` non-null means the
  -- token has been redeemed, and the partial unique index below makes a second
  -- redemption a database error rather than a race two application processes could
  -- both win.
  spent_at   timestamptz,

  created_by uuid not null,
  created_at timestamptz not null default statement_timestamp(),

  constraint host_enrolments_expiry_after_creation check (expires_at > created_at),
  constraint host_enrolments_token_hash_length check (length(token_hash) = 32)
);

-- At most ONE unspent enrolment per host. Two live tokens for one host would mean two
-- parties could each enrol it, and the second would silently replace the first's
-- certificate — so the loser would be a host that had been enrolled and then locked
-- out, with nothing recording why.
create unique index host_enrolments_one_live_per_host
  on host_enrolments (host_id)
  where spent_at is null;

create index host_enrolments_token_hash on host_enrolments (token_hash);

create table host_certificates (
  id             uuid primary key default gen_random_uuid(),
  org_id         uuid not null references organizations (id) on delete cascade,
  host_id        uuid not null references hosts (id) on delete cascade,

  -- The certificate's serial, as issued. Text rather than numeric: a serial is an
  -- opaque identifier that happens to be an integer in X.509, and doing arithmetic on
  -- it is never correct.
  serial         text not null,
  -- SHA-256 of the DER, which is what a presented certificate is matched on. Matching
  -- on the subject or the serial alone would let a certificate issued by anybody be
  -- matched to this row; the fingerprint is over the bytes the CA signed.
  fingerprint    bytea not null,
  -- The certificate itself, PEM. Stored because it is PUBLIC — the private key never
  -- leaves the host — and because an incident needs to see exactly what was trusted.
  certificate_pem text not null,

  not_before     timestamptz not null,
  not_after      timestamptz not null,

  -- Revocation. Both columns or neither: a reason without a time is not a revocation,
  -- and a time without a reason is a revocation nobody can explain later.
  revoked_at     timestamptz,
  revoked_reason text,
  revoked_by     uuid,

  issued_at      timestamptz not null default statement_timestamp(),

  unique (org_id, serial),
  constraint host_certificates_fingerprint_length check (length(fingerprint) = 32),
  constraint host_certificates_validity check (not_after > not_before),
  constraint host_certificates_revocation_complete check (
    (revoked_at is null and revoked_reason is null and revoked_by is null)
    or (revoked_at is not null and revoked_reason is not null and revoked_by is not null)
  )
);

-- The lookup a connection performs: fingerprint to row. Not unique on fingerprint
-- alone across orgs — two organizations could in principle hold the same bytes only if
-- the CA reissued identically, which it cannot, but the index is scoped anyway because
-- every query is tenant-scoped and an index that is not gives the planner a reason to
-- ignore the policy.
create unique index host_certificates_fingerprint on host_certificates (org_id, fingerprint);

-- At most ONE unrevoked certificate per host. A host with two live certificates is a
-- host where revoking one leaves the other working, which is the opposite of
-- "individually revocable" being a useful property.
create unique index host_certificates_one_live_per_host
  on host_certificates (host_id)
  where revoked_at is null;

-- Row-level security, joining the regime migration 4 established. Enabled AND FORCED:
-- enabled alone is bypassed by the table's owner, and the owner is who runs the
-- migrations, so `force` is what makes the policy apply to the application's own role.
do $$
declare
  t text;
begin
  foreach t in array array['hosts', 'host_enrolments', 'host_certificates'] loop
    execute format('alter table %I enable row level security', t);
    execute format('alter table %I force row level security', t);
    execute format(
      'create policy tenant_isolation on %I using (org_id = current_tenant()) with check (org_id = current_tenant())',
      t
    );
  end loop;
end;
$$;

grant select, insert, update, delete on hosts, host_enrolments, host_certificates to ratline_app;

-- migrate:down

drop policy if exists tenant_isolation on host_certificates;
drop policy if exists tenant_isolation on host_enrolments;
drop policy if exists tenant_isolation on hosts;

drop table if exists host_certificates;
drop table if exists host_enrolments;
drop table if exists hosts;
