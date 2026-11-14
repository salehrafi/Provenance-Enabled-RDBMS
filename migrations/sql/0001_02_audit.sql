-- 0001_02_audit: transactional outbox, the tamper-evident audit chain, checkpoints, capture triggers.
--
-- How the chain works
--   1. A capture trigger on each audited table calls audit_append(), which inserts an UNSEALED
--      audit row (chain_seq IS NULL) and an outbox event, in the writer's own transaction.
--   2. A deferred constraint trigger seals each row at COMMIT: it locks the tenant's chain head,
--      assigns the next chain_seq, and stores SHA-256(previous hash + this record).
--
-- Sealing at commit, rather than at the moment of the change, is deliberate:
--   * The chain-head lock is the last lock a transaction takes and is held only for the commit
--     itself. Sealing inline would hold it for the whole transaction, serialising every writer in
--     the organization and creating lock-order deadlocks with ordinary row locks.
--   * chain_seq becomes commit order, and changed_at is assigned under the same lock, so both are
--     strictly ordered together. "State as of time T" and "state as of record N" always agree.
--   * No reader can ever see an unsealed row: sealing and commit are atomic.

CREATE TABLE outbox_events (
  event_id       bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id      bigint NOT NULL DEFAULT current_tenant_id()
                 CONSTRAINT fk_outbox_tenant REFERENCES tenants(tenant_id),
  event_type     varchar(80) NOT NULL,
  entity         varchar(30),
  entity_id      varchar(100),
  payload        jsonb NOT NULL DEFAULT '{}'::jsonb,
  request_id     varchar(64),
  created_at     timestamptz NOT NULL DEFAULT clock_timestamp(),
  dispatched_at  timestamptz
);

-- The dispatcher only ever looks at undelivered events; a partial index keeps that scan tiny
-- no matter how large the table grows.
CREATE INDEX ix_outbox_pending ON outbox_events (tenant_id, event_id) WHERE dispatched_at IS NULL;
CREATE INDEX ix_outbox_tenant  ON outbox_events (tenant_id, event_id DESC);
CREATE INDEX ix_outbox_request ON outbox_events (tenant_id, request_id) WHERE request_id IS NOT NULL;

CREATE TABLE audit_log (
  audit_id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id          bigint NOT NULL CONSTRAINT fk_audit_tenant REFERENCES tenants(tenant_id),
  chain_seq          bigint,                      -- NULL only inside the writing transaction
  entity             varchar(30)  NOT NULL,
  -- "C" collation: record_pk is an identifier, and prefix searches ('42:%') must use the index.
  record_pk          varchar(100) COLLATE "C" NOT NULL,
  operation          varchar(6)   NOT NULL
                     CONSTRAINT ck_audit_op CHECK (operation IN ('INSERT', 'UPDATE', 'DELETE')),
  old_values         jsonb,
  new_values         jsonb,
  actor              varchar(254) NOT NULL,
  actor_user_id      bigint,
  request_id         varchar(64),
  change_request_id  bigint,
  db_user            varchar(128) NOT NULL,
  changed_at         timestamptz  NOT NULL DEFAULT clock_timestamp(),  -- replaced by the seal time
  prev_hash          varchar(64),
  row_hash           varchar(64),
  CONSTRAINT uq_audit_chain UNIQUE (tenant_id, chain_seq),
  CONSTRAINT ck_audit_sealed CHECK ((chain_seq IS NULL) = (row_hash IS NULL) AND (chain_seq IS NULL) = (prev_hash IS NULL))
);

CREATE INDEX ix_audit_record  ON audit_log (tenant_id, entity, record_pk, chain_seq);
CREATE INDEX ix_audit_time    ON audit_log (tenant_id, changed_at);
CREATE INDEX ix_audit_request ON audit_log (tenant_id, request_id) WHERE request_id IS NOT NULL;
CREATE INDEX ix_audit_actor   ON audit_log (tenant_id, actor, chain_seq);
CREATE INDEX ix_audit_recent  ON audit_log (tenant_id, audit_id DESC);

-- One row per tenant: the tip of the chain. Sealing locks it (FOR UPDATE).
CREATE TABLE audit_chain_head (
  tenant_id  bigint PRIMARY KEY CONSTRAINT fk_head_tenant REFERENCES tenants(tenant_id),
  last_seq   bigint      NOT NULL DEFAULT 0,
  last_hash  varchar(64) NOT NULL DEFAULT repeat('0', 64),
  last_at    timestamptz
);

-- Signed statements "at chain_seq N the hash was H", produced by the worker with a key the
-- database never sees. They are also published to the outbox so customers can keep copies
-- outside this system. A rewritten chain cannot match a checkpoint it did not sign.
CREATE TABLE audit_checkpoints (
  checkpoint_id  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id      bigint NOT NULL DEFAULT current_tenant_id()
                 CONSTRAINT fk_checkpoint_tenant REFERENCES tenants(tenant_id),
  chain_seq      bigint      NOT NULL CHECK (chain_seq > 0),
  row_hash       varchar(64) NOT NULL,
  created_at     timestamptz NOT NULL,
  key_id         varchar(32) NOT NULL,
  signature      text        NOT NULL,
  CONSTRAINT uq_checkpoint UNIQUE (tenant_id, chain_seq)
);

-- ---------------------------------------------------------------------------------------------
-- Hashing. The preimage is a JSON array, so field boundaries are unambiguous (a '|' or a comma
-- inside a value cannot shift content from one field to another). The timestamp is hashed as
-- integer microseconds since the epoch, which is independent of any session time zone.
-- ---------------------------------------------------------------------------------------------
CREATE FUNCTION audit_preimage(p_prev text, p_seq bigint, p_tenant bigint, p_entity text, p_pk text,
                               p_op text, p_actor text, p_actor_id bigint, p_req text, p_cr bigint,
                               p_db_user text, p_ts timestamptz, p_old jsonb, p_new jsonb)
RETURNS text
LANGUAGE sql STABLE
AS $$
  SELECT jsonb_build_array('v1', p_prev, p_seq, p_tenant, p_entity, p_pk, p_op, p_actor, p_actor_id,
                           p_req, p_cr, p_db_user,
                           (extract(epoch FROM p_ts) * 1000000)::bigint,
                           p_old, p_new)::text
$$;

CREATE FUNCTION audit_hash(p_preimage text) RETURNS text
LANGUAGE sql IMMUTABLE
AS $$ SELECT encode(sha256(convert_to(p_preimage, 'UTF8')), 'hex') $$;

-- Not granted to the API role: history is written only by triggers.
CREATE FUNCTION audit_append(p_tenant bigint, p_entity text, p_pk text, p_op text, p_old jsonb, p_new jsonb)
RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = prov, pg_temp
AS $$
DECLARE
  -- session_user is the role that logged in, even inside SECURITY DEFINER code.
  v_actor  text   := COALESCE(NULLIF(current_setting('app.actor', true), ''), 'db:' || session_user);
  v_user   bigint := NULLIF(current_setting('app.user_id', true), '')::bigint;
  v_req    text   := NULLIF(current_setting('app.request_id', true), '');
  v_cr     bigint := NULLIF(current_setting('app.change_request_id', true), '')::bigint;
  v_id     bigint;
BEGIN
  INSERT INTO audit_log (tenant_id, entity, record_pk, operation, old_values, new_values, actor,
                         actor_user_id, request_id, change_request_id, db_user)
  VALUES (p_tenant, p_entity, p_pk, p_op, p_old, p_new, left(v_actor, 254), v_user, v_req, v_cr, session_user)
  RETURNING audit_id INTO v_id;

  INSERT INTO outbox_events (tenant_id, event_type, entity, entity_id, payload, request_id)
  VALUES (p_tenant,
          p_entity || '.' || CASE p_op WHEN 'INSERT' THEN 'created' WHEN 'UPDATE' THEN 'updated' ELSE 'deleted' END,
          p_entity, p_pk,
          jsonb_build_object('audit_id', v_id, 'entity', p_entity, 'record_pk', p_pk, 'operation', p_op,
                             'actor', v_actor, 'old', p_old, 'new', p_new),
          v_req);
  RETURN v_id;
END;
$$;

CREATE FUNCTION audit_seal() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = prov, pg_temp
AS $$
DECLARE
  v_seq   bigint;
  v_prev  text;
  v_last  timestamptz;
  v_ts    timestamptz;
  v_hash  text;
BEGIN
  INSERT INTO audit_chain_head (tenant_id) VALUES (NEW.tenant_id) ON CONFLICT (tenant_id) DO NOTHING;
  SELECT last_seq, last_hash, last_at INTO v_seq, v_prev, v_last
    FROM audit_chain_head WHERE tenant_id = NEW.tenant_id FOR UPDATE;

  v_seq := v_seq + 1;
  -- Strictly increasing per tenant, even if the server clock steps backwards.
  v_ts := GREATEST(clock_timestamp(), COALESCE(v_last, '-infinity'::timestamptz) + interval '1 microsecond');
  v_hash := audit_hash(audit_preimage(v_prev, v_seq, NEW.tenant_id, NEW.entity, NEW.record_pk, NEW.operation,
                                      NEW.actor, NEW.actor_user_id, NEW.request_id, NEW.change_request_id,
                                      NEW.db_user, v_ts, NEW.old_values, NEW.new_values));

  UPDATE audit_log SET chain_seq = v_seq, prev_hash = v_prev, row_hash = v_hash, changed_at = v_ts
   WHERE audit_id = NEW.audit_id;
  UPDATE audit_chain_head SET last_seq = v_seq, last_hash = v_hash, last_at = v_ts WHERE tenant_id = NEW.tenant_id;
  RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER trg_audit_seal
AFTER INSERT ON audit_log
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION audit_seal();

-- Append-only: the single permitted UPDATE is the seal (NULL -> sealed, content untouched).
-- A superuser or the owner can disable this trigger; the hash chain and the signed checkpoints
-- are what make that detectable.
CREATE FUNCTION audit_guard() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  c_seal_cols CONSTANT text[] := ARRAY['chain_seq', 'prev_hash', 'row_hash', 'changed_at'];
BEGIN
  IF TG_OP = 'UPDATE' AND OLD.chain_seq IS NULL AND NEW.chain_seq IS NOT NULL
     AND (to_jsonb(NEW) - c_seal_cols) = (to_jsonb(OLD) - c_seal_cols) THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'audit_log is append-only' USING ERRCODE = 'PV901';
END;
$$;

CREATE TRIGGER trg_audit_guard BEFORE UPDATE OR DELETE ON audit_log
FOR EACH ROW EXECUTE FUNCTION audit_guard();

CREATE FUNCTION reject_mutation() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = 'PV901';
END;
$$;

CREATE TRIGGER trg_audit_no_truncate BEFORE TRUNCATE ON audit_log
FOR EACH STATEMENT EXECUTE FUNCTION reject_mutation();

CREATE TRIGGER trg_checkpoints_immutable BEFORE UPDATE OR DELETE ON audit_checkpoints
FOR EACH ROW EXECUTE FUNCTION reject_mutation();

CREATE TRIGGER trg_checkpoints_no_truncate BEFORE TRUNCATE ON audit_checkpoints
FOR EACH STATEMENT EXECUTE FUNCTION reject_mutation();

-- ---------------------------------------------------------------------------------------------
-- Verification. Runs with the caller's rights, so row-level security limits it to the caller's
-- tenant. Verifies records p_from_seq .. p_from_seq + p_limit - 1 so that very long chains can be
-- checked in slices (the worker verifies incrementally from the last checkpoint).
-- ---------------------------------------------------------------------------------------------
CREATE FUNCTION audit_verify(p_from_seq bigint DEFAULT 1, p_limit integer DEFAULT 100000)
RETURNS TABLE (ok boolean, checked bigint, first_bad_seq bigint, reason text,
               last_seq bigint, last_hash text, head_seq bigint, complete boolean)
LANGUAGE plpgsql STABLE
AS $$
DECLARE
  v_tenant    bigint := current_tenant_id();
  v_prev      text   := repeat('0', 64);
  v_prev_ts   timestamptz;
  v_expected  bigint := GREATEST(p_from_seq, 1);
  v_to        bigint;
  v_head_seq  bigint := 0;
  v_head_hash text   := repeat('0', 64);
  v_orphans   bigint;
  r           audit_log%ROWTYPE;
BEGIN
  IF v_tenant IS NULL THEN
    RAISE EXCEPTION 'No tenant in the transaction context' USING ERRCODE = 'PV900';
  END IF;
  ok := true; checked := 0; first_bad_seq := NULL; reason := NULL; complete := false;

  -- Read the head first and only check rows up to it, so concurrent writers cannot produce a
  -- false alarm.
  SELECT h.last_seq, h.last_hash INTO v_head_seq, v_head_hash FROM audit_chain_head h WHERE h.tenant_id = v_tenant;
  v_head_seq  := COALESCE(v_head_seq, 0);
  v_head_hash := COALESCE(v_head_hash, repeat('0', 64));
  head_seq := v_head_seq;
  v_to := LEAST(v_head_seq, v_expected + GREATEST(p_limit, 1) - 1);

  IF v_expected > 1 THEN
    SELECT a.row_hash, a.changed_at INTO v_prev, v_prev_ts
      FROM audit_log a WHERE a.tenant_id = v_tenant AND a.chain_seq = v_expected - 1;
    IF NOT FOUND THEN
      ok := false; first_bad_seq := v_expected - 1;
      reason := 'Record missing: chain_seq ' || (v_expected - 1) || ' does not exist';
      last_seq := v_expected - 1; last_hash := NULL;
      RETURN NEXT; RETURN;
    END IF;
  END IF;

  FOR r IN SELECT * FROM audit_log a
            WHERE a.tenant_id = v_tenant AND a.chain_seq BETWEEN v_expected AND v_to
            ORDER BY a.chain_seq LOOP
    IF r.chain_seq <> v_expected THEN
      ok := false; first_bad_seq := v_expected;
      reason := 'Record missing: expected chain_seq ' || v_expected || ' but found ' || r.chain_seq;
      EXIT;
    END IF;
    IF r.prev_hash <> v_prev THEN
      ok := false; first_bad_seq := r.chain_seq;
      reason := 'prev_hash does not match the hash of the previous record';
      EXIT;
    END IF;
    IF r.row_hash <> audit_hash(audit_preimage(r.prev_hash, r.chain_seq, r.tenant_id, r.entity, r.record_pk,
                                               r.operation, r.actor, r.actor_user_id, r.request_id,
                                               r.change_request_id, r.db_user, r.changed_at,
                                               r.old_values, r.new_values)) THEN
      ok := false; first_bad_seq := r.chain_seq;
      reason := 'Record content was modified after it was written (hash mismatch)';
      EXIT;
    END IF;
    IF v_prev_ts IS NOT NULL AND r.changed_at <= v_prev_ts THEN
      ok := false; first_bad_seq := r.chain_seq;
      reason := 'Timestamp is not later than the previous record (possible backdating)';
      EXIT;
    END IF;
    checked := checked + 1;
    v_prev := r.row_hash;
    v_prev_ts := r.changed_at;
    v_expected := v_expected + 1;
  END LOOP;

  last_seq := v_expected - 1;
  last_hash := v_prev;

  IF ok AND v_expected - 1 < v_to THEN
    ok := false; first_bad_seq := v_expected;
    reason := CASE WHEN v_to = v_head_seq
                   THEN 'Chain head mismatch: records were removed from the end of the log'
                   ELSE 'Record missing: chain_seq ' || v_expected || ' does not exist' END;
  END IF;

  IF ok AND v_to = v_head_seq THEN
    complete := true;
    IF v_prev <> v_head_hash THEN
      ok := false; first_bad_seq := v_head_seq;
      reason := 'Chain head mismatch: the last record does not match the recorded chain head';
    ELSE
      -- A committed row that was never sealed can only exist if someone wrote to the table
      -- with the sealing trigger disabled. (Rows above the head are legitimate: a writer may
      -- have committed after the head was read.)
      SELECT count(*) INTO v_orphans FROM audit_log a
       WHERE a.tenant_id = v_tenant AND a.chain_seq IS NULL;
      IF v_orphans > 0 THEN
        ok := false; first_bad_seq := v_head_seq + 1;
        reason := v_orphans || ' record(s) exist outside the chain (written with sealing disabled)';
      END IF;
    END IF;
  END IF;

  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------------------------
-- Generic capture trigger.
--   TG_ARGV[0]  entity name written to the audit log
--   TG_ARGV[1]  primary-key column(s), comma separated; composite keys are joined with ':'
--   TG_ARGV[2]  extra columns to leave out (secrets, and noise such as last_login_at)
-- tenant_id, created_at and updated_at are always left out. An UPDATE that changes none of the
-- recorded columns writes nothing, so the log only holds real changes.
-- ---------------------------------------------------------------------------------------------
CREATE FUNCTION audit_capture() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = prov, pg_temp
AS $$
DECLARE
  v_exclude text[] := ARRAY['tenant_id', 'created_at', 'updated_at']
                      || string_to_array(COALESCE(TG_ARGV[2], ''), ',');
  v_row  jsonb;
  v_old  jsonb;
  v_new  jsonb;
  v_pk   text;
BEGIN
  IF TG_OP = 'DELETE' THEN
    v_row := to_jsonb(OLD);
  ELSE
    v_row := to_jsonb(NEW);
    v_new := v_row - v_exclude;
  END IF;
  IF TG_OP <> 'INSERT' THEN
    v_old := to_jsonb(OLD) - v_exclude;
  END IF;
  IF TG_OP = 'UPDATE' AND v_old = v_new THEN
    RETURN NULL;
  END IF;
  SELECT string_agg(v_row ->> col, ':' ORDER BY ord) INTO v_pk
    FROM unnest(string_to_array(TG_ARGV[1], ',')) WITH ORDINALITY AS t(col, ord);
  PERFORM audit_append((v_row ->> 'tenant_id')::bigint, TG_ARGV[0], v_pk, TG_OP, v_old, v_new);
  RETURN NULL;
END;
$$;

CREATE TRIGGER trg_a_audit AFTER INSERT OR UPDATE OR DELETE ON tenants
  FOR EACH ROW EXECUTE FUNCTION audit_capture('organization', 'tenant_id');
CREATE TRIGGER trg_a_audit AFTER INSERT OR UPDATE OR DELETE ON tenant_settings
  FOR EACH ROW EXECUTE FUNCTION audit_capture('settings', 'tenant_id');
CREATE TRIGGER trg_a_audit AFTER INSERT OR UPDATE OR DELETE ON users
  FOR EACH ROW EXECUTE FUNCTION audit_capture('user', 'user_id', 'password_hash,last_login_at');
CREATE TRIGGER trg_a_audit AFTER INSERT OR UPDATE OR DELETE ON customers
  FOR EACH ROW EXECUTE FUNCTION audit_capture('customer', 'customer_id');
CREATE TRIGGER trg_a_audit AFTER INSERT OR UPDATE OR DELETE ON products
  FOR EACH ROW EXECUTE FUNCTION audit_capture('product', 'product_id');
CREATE TRIGGER trg_a_audit AFTER INSERT OR UPDATE OR DELETE ON orders
  FOR EACH ROW EXECUTE FUNCTION audit_capture('order', 'order_id');
CREATE TRIGGER trg_a_audit AFTER INSERT OR UPDATE OR DELETE ON order_items
  FOR EACH ROW EXECUTE FUNCTION audit_capture('order_item', 'order_id,product_id');
CREATE TRIGGER trg_a_audit AFTER INSERT OR UPDATE OR DELETE ON payments
  FOR EACH ROW EXECUTE FUNCTION audit_capture('payment', 'payment_id');

-- Emits "order.status_changed" in addition to the generic order.updated event.
CREATE FUNCTION orders_status_event() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  INSERT INTO outbox_events (tenant_id, event_type, entity, entity_id, payload, request_id)
  VALUES (NEW.tenant_id, 'order.status_changed', 'order', NEW.order_id::text,
          jsonb_build_object('order_id', NEW.order_id, 'from', OLD.status, 'to', NEW.status,
                             'total_amount', NEW.total_amount),
          NULLIF(current_setting('app.request_id', true), ''));
  RETURN NULL;
END;
$$;

CREATE TRIGGER trg_c_status_event AFTER UPDATE OF status ON orders
FOR EACH ROW WHEN (NEW.status <> OLD.status) EXECUTE FUNCTION orders_status_event();
