-- 0003_01_platform: global administration and break-glass access.
--
-- Identity model
--   Platform operators (platform_users) are a separate population from organization users. They have
--   their own credentials, mandatory TOTP MFA and their own token type; tenant APIs reject their tokens.
--   Roles: super_admin (manage organizations and operators) and security_officer (oversight and approval).
--
-- Database boundary
--   The platform console connects as a third role, prov_platform. It has NO privileges on any tenant table.
--   It can read and write only platform tables, and reach tenant data exclusively through the narrow
--   SECURITY DEFINER functions below, which return metadata/aggregates or perform one audited recovery action.
--   Reading business data during break-glass happens through the ordinary RLS-protected application role
--   (prov_app), after breakglass_begin() has validated an active grant and switched the transaction to
--   read-only. Nothing here creates a role with BYPASSRLS.
--
-- Accountability
--   platform_audit_log is a separate SHA-256 hash chain (sealed at commit, like audit_log), with signed
--   checkpoints. Break-glass state changes are also written into the affected organization's own
--   activity_log and outbox, so the customer can see them (unless a legal hold suppresses notification).

-- ---------------------------------------------------------------------------------------------
-- Organization status (suspension by a platform operator)
-- ---------------------------------------------------------------------------------------------
ALTER TABLE tenants ADD COLUMN status varchar(10) NOT NULL DEFAULT 'ACTIVE'
  CONSTRAINT ck_tenants_status CHECK (status IN ('ACTIVE', 'SUSPENDED'));
ALTER TABLE tenants ADD COLUMN status_reason varchar(500);

-- ---------------------------------------------------------------------------------------------
-- Platform operators
-- ---------------------------------------------------------------------------------------------
CREATE TABLE platform_users (
  platform_user_id  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  email             varchar(254) NOT NULL CONSTRAINT uq_platform_users_email UNIQUE
                    CONSTRAINT ck_platform_email_lower CHECK (email = lower(email)),
  full_name         varchar(120) NOT NULL,
  password_hash     varchar(255) NOT NULL,
  role              varchar(20)  NOT NULL
                    CONSTRAINT ck_platform_role CHECK (role IN ('super_admin', 'security_officer')),
  is_active         boolean      NOT NULL DEFAULT true,
  mfa_secret_enc    text,                       -- AES-256-GCM, key held by the application
  mfa_enabled       boolean      NOT NULL DEFAULT false,
  mfa_last_step     bigint       NOT NULL DEFAULT 0,   -- last accepted TOTP time step: codes cannot be replayed
  token_version     integer      NOT NULL DEFAULT 1,
  created_at        timestamptz  NOT NULL DEFAULT now(),
  created_by        varchar(254) NOT NULL,
  last_login_at     timestamptz,
  CONSTRAINT ck_platform_mfa CHECK (NOT mfa_enabled OR mfa_secret_enc IS NOT NULL)
);

-- There must always be an active super admin, whoever makes the change.
CREATE FUNCTION platform_keep_one_super_admin() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(727002);
  IF NOT EXISTS (SELECT 1 FROM platform_users WHERE role = 'super_admin' AND is_active) THEN
    RAISE EXCEPTION 'The platform must keep at least one active super admin' USING ERRCODE = 'PV050';
  END IF;
  RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER trg_platform_keep_super_admin
AFTER UPDATE OF role, is_active ON platform_users
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW WHEN (OLD.role = 'super_admin' AND OLD.is_active)
EXECUTE FUNCTION platform_keep_one_super_admin();

CREATE TRIGGER trg_platform_users_no_delete BEFORE DELETE ON platform_users
FOR EACH ROW EXECUTE FUNCTION reject_mutation();
CREATE TRIGGER trg_platform_users_no_truncate BEFORE TRUNCATE ON platform_users
FOR EACH STATEMENT EXECUTE FUNCTION reject_mutation();

-- ---------------------------------------------------------------------------------------------
-- Platform audit chain
-- ---------------------------------------------------------------------------------------------
CREATE TABLE platform_audit_log (
  audit_id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  seq               bigint CONSTRAINT uq_platform_audit_seq UNIQUE,   -- NULL only inside the writing transaction
  occurred_at       timestamptz  NOT NULL DEFAULT clock_timestamp(),  -- replaced by the seal time
  actor             varchar(254) NOT NULL,
  actor_id          bigint,
  action            varchar(120) NOT NULL,
  outcome           varchar(10)  NOT NULL CONSTRAINT ck_platform_audit_outcome CHECK (outcome IN ('SUCCESS', 'DENIED', 'FAILURE')),
  target_tenant_id  bigint,
  target            varchar(300),
  ip_address        inet,
  user_agent        varchar(300),
  request_id        varchar(64),
  details           jsonb NOT NULL DEFAULT '{}'::jsonb,
  prev_hash         varchar(64),
  row_hash          varchar(64),
  CONSTRAINT ck_platform_audit_sealed CHECK ((seq IS NULL) = (row_hash IS NULL) AND (seq IS NULL) = (prev_hash IS NULL))
);

CREATE INDEX ix_platform_audit_recent ON platform_audit_log (audit_id DESC);
CREATE INDEX ix_platform_audit_actor  ON platform_audit_log (actor, audit_id DESC);
CREATE INDEX ix_platform_audit_tenant ON platform_audit_log (target_tenant_id, audit_id DESC) WHERE target_tenant_id IS NOT NULL;
CREATE INDEX ix_platform_audit_action ON platform_audit_log (action, audit_id DESC);

CREATE TABLE platform_chain_head (
  id         boolean PRIMARY KEY DEFAULT true CONSTRAINT ck_platform_head_single CHECK (id),
  last_seq   bigint      NOT NULL DEFAULT 0,
  last_hash  varchar(64) NOT NULL DEFAULT repeat('0', 64),
  last_at    timestamptz
);
INSERT INTO platform_chain_head DEFAULT VALUES;

CREATE TABLE platform_checkpoints (
  checkpoint_id  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  seq            bigint      NOT NULL CONSTRAINT uq_platform_checkpoint UNIQUE CHECK (seq > 0),
  row_hash       varchar(64) NOT NULL,
  created_at     timestamptz NOT NULL,
  key_id         varchar(32) NOT NULL,
  signature      text        NOT NULL
);

CREATE FUNCTION platform_audit_preimage(p_prev text, p_seq bigint, p_actor text, p_actor_id bigint, p_action text,
                                        p_outcome text, p_tenant bigint, p_target text, p_ip inet, p_ua text,
                                        p_req text, p_ts timestamptz, p_details jsonb)
RETURNS text
LANGUAGE sql STABLE
AS $$
  SELECT jsonb_build_array('platform-v1', p_prev, p_seq, p_actor, p_actor_id, p_action, p_outcome, p_tenant, p_target,
                           host(p_ip), p_ua, p_req, (extract(epoch FROM p_ts) * 1000000)::bigint, p_details)::text
$$;

CREATE FUNCTION platform_audit_seal() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = prov, pg_temp
AS $$
DECLARE
  v_seq  bigint;
  v_prev text;
  v_last timestamptz;
  v_ts   timestamptz;
  v_hash text;
BEGIN
  SELECT last_seq, last_hash, last_at INTO v_seq, v_prev, v_last FROM platform_chain_head WHERE id FOR UPDATE;
  v_seq := v_seq + 1;
  v_ts := GREATEST(clock_timestamp(), COALESCE(v_last, '-infinity'::timestamptz) + interval '1 microsecond');
  v_hash := audit_hash(platform_audit_preimage(v_prev, v_seq, NEW.actor, NEW.actor_id, NEW.action, NEW.outcome,
                                               NEW.target_tenant_id, NEW.target, NEW.ip_address, NEW.user_agent,
                                               NEW.request_id, v_ts, NEW.details));
  UPDATE platform_audit_log SET seq = v_seq, prev_hash = v_prev, row_hash = v_hash, occurred_at = v_ts
   WHERE audit_id = NEW.audit_id;
  UPDATE platform_chain_head SET last_seq = v_seq, last_hash = v_hash, last_at = v_ts WHERE id;
  RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER trg_platform_audit_seal
AFTER INSERT ON platform_audit_log
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION platform_audit_seal();

CREATE FUNCTION platform_audit_guard() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  c_seal_cols CONSTANT text[] := ARRAY['seq', 'prev_hash', 'row_hash', 'occurred_at'];
BEGIN
  IF TG_OP = 'UPDATE' AND OLD.seq IS NULL AND NEW.seq IS NOT NULL
     AND (to_jsonb(NEW) - c_seal_cols) = (to_jsonb(OLD) - c_seal_cols) THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'platform_audit_log is append-only' USING ERRCODE = 'PV901';
END;
$$;

CREATE TRIGGER trg_platform_audit_guard BEFORE UPDATE OR DELETE ON platform_audit_log
FOR EACH ROW EXECUTE FUNCTION platform_audit_guard();
CREATE TRIGGER trg_platform_audit_no_truncate BEFORE TRUNCATE ON platform_audit_log
FOR EACH STATEMENT EXECUTE FUNCTION reject_mutation();
CREATE TRIGGER trg_platform_checkpoints_immutable BEFORE UPDATE OR DELETE ON platform_checkpoints
FOR EACH ROW EXECUTE FUNCTION reject_mutation();
CREATE TRIGGER trg_platform_checkpoints_no_truncate BEFORE TRUNCATE ON platform_checkpoints
FOR EACH STATEMENT EXECUTE FUNCTION reject_mutation();

-- The only way to write the platform chain.
CREATE FUNCTION platform_audit_append(p_actor text, p_actor_id bigint, p_action text, p_outcome text, p_tenant bigint,
                                      p_target text, p_ip text, p_ua text, p_req text, p_details jsonb)
RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = prov, pg_temp
AS $$
DECLARE
  v_id bigint;
  v_ip inet;
BEGIN
  BEGIN
    v_ip := NULLIF(p_ip, '')::inet;
  EXCEPTION WHEN others THEN
    v_ip := NULL;
  END;
  INSERT INTO platform_audit_log (actor, actor_id, action, outcome, target_tenant_id, target, ip_address, user_agent,
                                  request_id, details)
  VALUES (left(COALESCE(p_actor, 'unknown'), 254), p_actor_id, left(p_action, 120), p_outcome, p_tenant,
          left(p_target, 300), v_ip, left(p_ua, 300), left(p_req, 64), COALESCE(p_details, '{}'::jsonb))
  RETURNING audit_id INTO v_id;
  RETURN v_id;
END;
$$;

CREATE FUNCTION platform_audit_verify(p_from_seq bigint DEFAULT 1, p_limit integer DEFAULT 100000)
RETURNS TABLE (ok boolean, checked bigint, first_bad_seq bigint, reason text, last_seq bigint, last_hash text,
               head_seq bigint, complete boolean)
LANGUAGE plpgsql STABLE
AS $$
DECLARE
  v_prev      text   := repeat('0', 64);
  v_prev_ts   timestamptz;
  v_expected  bigint := GREATEST(p_from_seq, 1);
  v_to        bigint;
  v_head_seq  bigint;
  v_head_hash text;
  v_orphans   bigint;
  r           platform_audit_log%ROWTYPE;
BEGIN
  ok := true; checked := 0; first_bad_seq := NULL; reason := NULL; complete := false;
  SELECT h.last_seq, h.last_hash INTO v_head_seq, v_head_hash FROM platform_chain_head h WHERE h.id;
  head_seq := v_head_seq;
  v_to := LEAST(v_head_seq, v_expected + GREATEST(p_limit, 1) - 1);
  IF v_expected > 1 THEN
    SELECT a.row_hash, a.occurred_at INTO v_prev, v_prev_ts FROM platform_audit_log a WHERE a.seq = v_expected - 1;
    IF NOT FOUND THEN
      ok := false; first_bad_seq := v_expected - 1; reason := 'Record missing: seq ' || (v_expected - 1) || ' does not exist';
      last_seq := v_expected - 1; RETURN NEXT; RETURN;
    END IF;
  END IF;
  FOR r IN SELECT * FROM platform_audit_log a WHERE a.seq BETWEEN v_expected AND v_to ORDER BY a.seq LOOP
    IF r.seq <> v_expected THEN
      ok := false; first_bad_seq := v_expected; reason := 'Record missing: expected seq ' || v_expected || ' but found ' || r.seq; EXIT;
    END IF;
    IF r.prev_hash <> v_prev THEN
      ok := false; first_bad_seq := r.seq; reason := 'prev_hash does not match the hash of the previous record'; EXIT;
    END IF;
    IF r.row_hash <> audit_hash(platform_audit_preimage(r.prev_hash, r.seq, r.actor, r.actor_id, r.action, r.outcome,
                                                        r.target_tenant_id, r.target, r.ip_address, r.user_agent,
                                                        r.request_id, r.occurred_at, r.details)) THEN
      ok := false; first_bad_seq := r.seq; reason := 'Record content was modified after it was written (hash mismatch)'; EXIT;
    END IF;
    IF v_prev_ts IS NOT NULL AND r.occurred_at <= v_prev_ts THEN
      ok := false; first_bad_seq := r.seq; reason := 'Timestamp is not later than the previous record'; EXIT;
    END IF;
    checked := checked + 1; v_prev := r.row_hash; v_prev_ts := r.occurred_at; v_expected := v_expected + 1;
  END LOOP;
  last_seq := v_expected - 1; last_hash := v_prev;
  IF ok AND v_expected - 1 < v_to THEN
    ok := false; first_bad_seq := v_expected;
    reason := CASE WHEN v_to = v_head_seq THEN 'Chain head mismatch: records were removed from the end of the log'
                   ELSE 'Record missing: seq ' || v_expected || ' does not exist' END;
  END IF;
  IF ok AND v_to = v_head_seq THEN
    complete := true;
    IF v_prev <> v_head_hash THEN
      ok := false; first_bad_seq := v_head_seq; reason := 'Chain head mismatch: the last record does not match the recorded chain head';
    ELSE
      SELECT count(*) INTO v_orphans FROM platform_audit_log a WHERE a.seq IS NULL;
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
-- Break-glass grants
-- ---------------------------------------------------------------------------------------------
CREATE TABLE break_glass_grants (
  grant_id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id            bigint NOT NULL CONSTRAINT fk_bg_tenant REFERENCES tenants(tenant_id),
  scope                varchar(20) NOT NULL DEFAULT 'READ_ONLY'
                       CONSTRAINT ck_bg_scope CHECK (scope IN ('READ_ONLY', 'ACCOUNT_RECOVERY')),
  reason               text NOT NULL CONSTRAINT ck_bg_reason CHECK (length(btrim(reason)) BETWEEN 20 AND 2000),
  ticket_ref           varchar(100) NOT NULL CONSTRAINT ck_bg_ticket CHECK (length(btrim(ticket_ref)) >= 3),
  duration_minutes     integer NOT NULL CONSTRAINT ck_bg_duration CHECK (duration_minutes BETWEEN 5 AND 240),
  notify_customer      boolean NOT NULL DEFAULT true,   -- false only for a documented legal hold
  status               varchar(10) NOT NULL DEFAULT 'PENDING'
                       CONSTRAINT ck_bg_status CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'ACTIVE', 'EXPIRED', 'REVOKED', 'CLOSED')),
  requested_by         bigint NOT NULL CONSTRAINT fk_bg_requester REFERENCES platform_users(platform_user_id),
  requested_at         timestamptz NOT NULL DEFAULT now(),
  decided_by           bigint CONSTRAINT fk_bg_decider REFERENCES platform_users(platform_user_id),
  decided_at           timestamptz,
  decision_note        varchar(500),
  approval_expires_at  timestamptz,
  activated_at         timestamptz,
  expires_at           timestamptz,
  ended_by             bigint CONSTRAINT fk_bg_ender REFERENCES platform_users(platform_user_id),
  ended_at             timestamptz,
  end_note             varchar(500),
  -- Four eyes: nobody approves (or rejects) their own request.
  CONSTRAINT ck_bg_four_eyes CHECK (decided_by IS NULL OR decided_by <> requested_by),
  -- Access can never outlive the approved duration.
  CONSTRAINT ck_bg_expiry CHECK (expires_at IS NULL OR expires_at <= activated_at + make_interval(mins => duration_minutes)),
  CONSTRAINT ck_bg_legal_hold CHECK (notify_customer OR length(btrim(reason)) >= 40)
);

CREATE INDEX ix_bg_status ON break_glass_grants (status, grant_id DESC);
CREATE INDEX ix_bg_tenant ON break_glass_grants (tenant_id, grant_id DESC);

-- State machine and integrity of a grant, enforced for every client.
CREATE FUNCTION break_glass_guard() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF (NEW.tenant_id, NEW.scope, NEW.reason, NEW.ticket_ref, NEW.duration_minutes, NEW.notify_customer,
      NEW.requested_by, NEW.requested_at)
     IS DISTINCT FROM
     (OLD.tenant_id, OLD.scope, OLD.reason, OLD.ticket_ref, OLD.duration_minutes, OLD.notify_customer,
      OLD.requested_by, OLD.requested_at) THEN
    RAISE EXCEPTION 'The details of a break-glass request cannot be changed' USING ERRCODE = 'PV041';
  END IF;
  IF NEW.status = OLD.status THEN
    RAISE EXCEPTION 'A break-glass grant can only change by moving to a new status' USING ERRCODE = 'PV041';
  END IF;
  IF (OLD.status, NEW.status) NOT IN (('PENDING', 'APPROVED'), ('PENDING', 'REJECTED'), ('PENDING', 'REVOKED'),
                                      ('APPROVED', 'ACTIVE'), ('APPROVED', 'REVOKED'), ('APPROVED', 'EXPIRED'),
                                      ('ACTIVE', 'CLOSED'), ('ACTIVE', 'REVOKED'), ('ACTIVE', 'EXPIRED')) THEN
    RAISE EXCEPTION 'Invalid break-glass transition: % -> %', OLD.status, NEW.status USING ERRCODE = 'PV042';
  END IF;

  -- Timestamps and actors are set here, never trusted from the caller.
  NEW.decided_by := CASE WHEN NEW.status IN ('APPROVED', 'REJECTED') THEN NEW.decided_by ELSE OLD.decided_by END;
  NEW.decided_at := OLD.decided_at; NEW.decision_note := COALESCE(NEW.decision_note, OLD.decision_note);
  NEW.approval_expires_at := OLD.approval_expires_at;
  NEW.activated_at := OLD.activated_at; NEW.expires_at := OLD.expires_at;
  NEW.ended_by := CASE WHEN NEW.status IN ('REVOKED', 'CLOSED') THEN NEW.ended_by ELSE OLD.ended_by END;
  NEW.ended_at := OLD.ended_at;

  IF NEW.status IN ('APPROVED', 'REJECTED') THEN
    IF NEW.decided_by IS NULL OR NEW.decided_by = OLD.requested_by THEN
      RAISE EXCEPTION 'Four-eyes rule: a break-glass request must be decided by a different operator' USING ERRCODE = 'PV043';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM platform_users WHERE platform_user_id = NEW.decided_by AND is_active AND mfa_enabled
                     AND role IN ('super_admin', 'security_officer')) THEN
      RAISE EXCEPTION 'Only an active, MFA-enrolled operator can decide a break-glass request' USING ERRCODE = 'PV043';
    END IF;
    NEW.decided_at := now();
    IF NEW.status = 'APPROVED' THEN
      NEW.approval_expires_at := now() + interval '30 minutes';
    END IF;
  ELSIF NEW.status = 'ACTIVE' THEN
    IF now() > OLD.approval_expires_at THEN
      RAISE EXCEPTION 'The approval has lapsed; request break-glass access again' USING ERRCODE = 'PV044';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM platform_users WHERE platform_user_id = OLD.requested_by AND is_active AND mfa_enabled) THEN
      RAISE EXCEPTION 'The requester is no longer an active, MFA-enrolled operator' USING ERRCODE = 'PV043';
    END IF;
    NEW.activated_at := now();
    NEW.expires_at := now() + make_interval(mins => OLD.duration_minutes);
  ELSIF NEW.status = 'EXPIRED' THEN
    IF (OLD.status = 'ACTIVE' AND now() < OLD.expires_at) OR (OLD.status = 'APPROVED' AND now() <= OLD.approval_expires_at) THEN
      RAISE EXCEPTION 'This grant has not expired yet' USING ERRCODE = 'PV042';
    END IF;
    NEW.ended_at := now();
  ELSE  -- REVOKED, CLOSED
    IF NEW.ended_by IS NULL THEN
      RAISE EXCEPTION 'Revoking or closing a grant must record who did it' USING ERRCODE = 'PV042';
    END IF;
    NEW.ended_at := now();
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_bg_guard BEFORE UPDATE ON break_glass_grants
FOR EACH ROW EXECUTE FUNCTION break_glass_guard();

-- New requests always start PENDING with no decision, activation or end set.
CREATE FUNCTION break_glass_insert_guard() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.status := 'PENDING'; NEW.requested_at := now();
  NEW.decided_by := NULL; NEW.decided_at := NULL; NEW.decision_note := NULL; NEW.approval_expires_at := NULL;
  NEW.activated_at := NULL; NEW.expires_at := NULL; NEW.ended_by := NULL; NEW.ended_at := NULL; NEW.end_note := NULL;
  IF NOT EXISTS (SELECT 1 FROM platform_users WHERE platform_user_id = NEW.requested_by AND is_active AND mfa_enabled) THEN
    RAISE EXCEPTION 'Only an active, MFA-enrolled operator can request break-glass access' USING ERRCODE = 'PV043';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_bg_insert_guard BEFORE INSERT ON break_glass_grants
FOR EACH ROW EXECUTE FUNCTION break_glass_insert_guard();
CREATE TRIGGER trg_bg_no_delete BEFORE DELETE ON break_glass_grants
FOR EACH ROW EXECUTE FUNCTION reject_mutation();
CREATE TRIGGER trg_bg_no_truncate BEFORE TRUNCATE ON break_glass_grants
FOR EACH STATEMENT EXECUTE FUNCTION reject_mutation();

-- Customer transparency: every state change is written into the organization's own activity log and outbox
-- (so it reaches their webhooks), unless the request was filed under a legal hold.
CREATE FUNCTION break_glass_notify() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = prov, pg_temp
AS $$
DECLARE
  v_email   text;
  v_payload jsonb;
BEGIN
  IF NOT NEW.notify_customer THEN
    RETURN NULL;
  END IF;
  SELECT email INTO v_email FROM platform_users WHERE platform_user_id = NEW.requested_by;
  v_payload := jsonb_build_object('grant_id', NEW.grant_id, 'status', NEW.status, 'scope', NEW.scope,
                                  'ticket', NEW.ticket_ref, 'operator', v_email, 'duration_minutes', NEW.duration_minutes,
                                  'activated_at', NEW.activated_at, 'expires_at', NEW.expires_at);
  INSERT INTO activity_log (tenant_id, actor, action, method, route, path, status_code, outcome, details)
  VALUES (NEW.tenant_id, 'platform:' || v_email, 'breakglass.' || lower(NEW.status), 'SYSTEM',
          '/platform/break-glass', '/platform/break-glass/' || NEW.grant_id, 200, 'SUCCESS', v_payload);
  INSERT INTO outbox_events (tenant_id, event_type, entity, entity_id, payload)
  VALUES (NEW.tenant_id, 'security.break_glass', 'break_glass', NEW.grant_id::text, v_payload);
  RETURN NULL;
END;
$$;

CREATE TRIGGER trg_bg_notify AFTER INSERT OR UPDATE OF status ON break_glass_grants
FOR EACH ROW EXECUTE FUNCTION break_glass_notify();

-- Shared validation for the break-glass entry points.
CREATE FUNCTION breakglass_check(p_grant bigint, p_platform_user bigint, p_scope text)
RETURNS break_glass_grants
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = prov, pg_temp
AS $$
DECLARE
  g break_glass_grants%ROWTYPE;
BEGIN
  SELECT * INTO g FROM break_glass_grants WHERE grant_id = p_grant;
  IF g.grant_id IS NULL OR g.status <> 'ACTIVE' OR g.expires_at <= now() OR g.requested_by <> p_platform_user
     OR NOT EXISTS (SELECT 1 FROM platform_users WHERE platform_user_id = p_platform_user AND is_active AND mfa_enabled)
     OR (p_scope IS NOT NULL AND g.scope <> p_scope) THEN
    RAISE EXCEPTION 'Break-glass access is not active for this operator' USING ERRCODE = 'PV040';
  END IF;
  RETURN g;
END;
$$;

-- Called by the application role (prov_app) before reading tenant data during break-glass. Validates the
-- grant, sets the tenant context for row-level security, and makes the rest of the transaction READ ONLY.
CREATE FUNCTION breakglass_begin(p_grant bigint, p_platform_user bigint, p_request_id text)
RETURNS TABLE (tenant_id bigint, scope varchar, expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = prov, pg_temp
AS $$
DECLARE
  g       break_glass_grants%ROWTYPE;
  v_email text;
BEGIN
  g := breakglass_check(p_grant, p_platform_user, NULL);
  SELECT email INTO v_email FROM platform_users WHERE platform_user_id = p_platform_user;
  PERFORM set_config('app.tenant_id', g.tenant_id::text, true),
          set_config('app.user_id', '', true),
          set_config('app.actor', 'breakglass:' || v_email || '#' || g.grant_id, true),
          set_config('app.request_id', COALESCE(p_request_id, ''), true),
          set_config('app.change_request_id', '', true);
  PERFORM set_config('transaction_read_only', 'on', true);
  RETURN QUERY SELECT g.tenant_id, g.scope, g.expires_at;
END;
$$;

-- Account recovery: one narrow, audited write per call. Never a general writable session.
CREATE FUNCTION breakglass_list_users(p_grant bigint, p_platform_user bigint)
RETURNS TABLE (user_id bigint, email varchar, full_name varchar, role varchar, is_active boolean, last_login_at timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = prov, pg_temp
AS $$
DECLARE
  g break_glass_grants%ROWTYPE;
BEGIN
  g := breakglass_check(p_grant, p_platform_user, NULL);
  RETURN QUERY SELECT u.user_id, u.email, u.full_name, u.role, u.is_active, u.last_login_at
                 FROM users u WHERE u.tenant_id = g.tenant_id ORDER BY u.user_id;
END;
$$;

CREATE FUNCTION breakglass_recover_user(p_grant bigint, p_platform_user bigint, p_user_id bigint, p_action text,
                                        p_password_hash text, p_request_id text)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = prov, pg_temp
AS $$
DECLARE
  g        break_glass_grants%ROWTYPE;
  v_op     text;
  v_target text;
  v_n      integer;
BEGIN
  g := breakglass_check(p_grant, p_platform_user, 'ACCOUNT_RECOVERY');
  SELECT email INTO v_op FROM platform_users WHERE platform_user_id = p_platform_user;
  -- The tenant's own audit chain records the change, attributed to the operator and the grant.
  PERFORM set_config('app.tenant_id', g.tenant_id::text, true),
          set_config('app.user_id', '', true),
          set_config('app.actor', 'breakglass:' || v_op || '#' || g.grant_id, true),
          set_config('app.request_id', COALESCE(p_request_id, ''), true);
  SELECT email INTO v_target FROM users WHERE tenant_id = g.tenant_id AND user_id = p_user_id;
  IF v_target IS NULL THEN
    RAISE EXCEPTION 'User not found in this organization' USING ERRCODE = 'PV045';
  END IF;
  IF p_action = 'reset_password' THEN
    IF p_password_hash IS NULL OR p_password_hash NOT LIKE '$argon2%' THEN
      RAISE EXCEPTION 'A password hash is required' USING ERRCODE = 'PV045';
    END IF;
    UPDATE users SET password_hash = p_password_hash, password_changed_at = now(), token_version = token_version + 1
     WHERE tenant_id = g.tenant_id AND user_id = p_user_id;
  ELSIF p_action = 'reactivate' THEN
    UPDATE users SET is_active = true WHERE tenant_id = g.tenant_id AND user_id = p_user_id;
  ELSIF p_action = 'revoke_sessions' THEN
    UPDATE users SET token_version = token_version + 1 WHERE tenant_id = g.tenant_id AND user_id = p_user_id;
  ELSE
    RAISE EXCEPTION 'Unknown recovery action %', p_action USING ERRCODE = 'PV045';
  END IF;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  IF p_action IN ('reset_password', 'revoke_sessions') THEN
    UPDATE refresh_tokens SET revoked_at = now()
     WHERE tenant_id = g.tenant_id AND user_id = p_user_id AND revoked_at IS NULL;
  END IF;
  IF g.notify_customer THEN
    INSERT INTO activity_log (tenant_id, actor, action, method, route, path, status_code, outcome, request_id, details)
    VALUES (g.tenant_id, 'platform:' || v_op, 'breakglass.recovery.' || p_action, 'SYSTEM', '/platform/break-glass',
            '/platform/break-glass/' || g.grant_id, 200, 'SUCCESS', NULLIF(p_request_id, ''),
            jsonb_build_object('grant_id', g.grant_id, 'user_id', p_user_id, 'user_email', v_target));
    INSERT INTO outbox_events (tenant_id, event_type, entity, entity_id, payload, request_id)
    VALUES (g.tenant_id, 'security.break_glass', 'break_glass', g.grant_id::text,
            jsonb_build_object('grant_id', g.grant_id, 'action', 'recovery.' || p_action, 'user_id', p_user_id,
                               'operator', v_op), NULLIF(p_request_id, ''));
  END IF;
  RETURN v_target;
END;
$$;

-- ---------------------------------------------------------------------------------------------
-- Metadata for global administration. Aggregates and status only; no business content.
-- ---------------------------------------------------------------------------------------------
CREATE FUNCTION platform_org_overview()
RETURNS TABLE (tenant_id bigint, name varchar, slug varchar, plan varchar, status varchar, status_reason varchar,
               created_at timestamptz, users bigint, active_users bigint, customers bigint, orders bigint,
               external_events bigint, audit_records bigint, latest_checkpoint_at timestamptz, activity_24h bigint,
               failed_logins_24h bigint, denied_24h bigint, last_activity_at timestamptz, open_critical_alerts bigint,
               active_break_glass bigint)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = prov, pg_temp
AS $$
  SELECT t.tenant_id, t.name, t.slug, t.plan, t.status, t.status_reason, t.created_at,
         (SELECT count(*) FROM users u WHERE u.tenant_id = t.tenant_id),
         (SELECT count(*) FROM users u WHERE u.tenant_id = t.tenant_id AND u.is_active),
         (SELECT count(*) FROM customers c WHERE c.tenant_id = t.tenant_id),
         (SELECT count(*) FROM orders o WHERE o.tenant_id = t.tenant_id),
         (SELECT count(*) FROM external_events e WHERE e.tenant_id = t.tenant_id),
         COALESCE((SELECT h.last_seq FROM audit_chain_head h WHERE h.tenant_id = t.tenant_id), 0),
         (SELECT max(k.created_at) FROM audit_checkpoints k WHERE k.tenant_id = t.tenant_id),
         (SELECT count(*) FROM activity_log a WHERE a.tenant_id = t.tenant_id AND a.occurred_at > now() - interval '24 hours'),
         (SELECT count(*) FROM activity_log a WHERE a.tenant_id = t.tenant_id AND a.occurred_at > now() - interval '24 hours'
             AND a.action IN ('auth.login_failed', 'auth.login_blocked')),
         (SELECT count(*) FROM activity_log a WHERE a.tenant_id = t.tenant_id AND a.occurred_at > now() - interval '24 hours'
             AND a.outcome = 'DENIED'),
         (SELECT max(a.occurred_at) FROM activity_log a WHERE a.tenant_id = t.tenant_id),
         (SELECT count(*) FROM alerts al WHERE al.tenant_id = t.tenant_id AND al.status = 'OPEN' AND al.severity = 'CRITICAL'),
         (SELECT count(*) FROM break_glass_grants b WHERE b.tenant_id = t.tenant_id AND b.status = 'ACTIVE' AND b.expires_at > now())
    FROM tenants t ORDER BY t.tenant_id
$$;

-- Where denied and failed sign-in traffic comes from: IP addresses and counts, no identities or content.
CREATE FUNCTION platform_security_signals(p_hours integer DEFAULT 24)
RETURNS TABLE (tenant_id bigint, tenant_name varchar, ip_address text, failed_logins bigint, denied bigint,
               last_seen timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = prov, pg_temp
AS $$
  SELECT a.tenant_id, t.name, host(a.ip_address),
         count(*) FILTER (WHERE a.action IN ('auth.login_failed', 'auth.login_blocked')),
         count(*) FILTER (WHERE a.outcome = 'DENIED'), max(a.occurred_at)
    FROM activity_log a JOIN tenants t ON t.tenant_id = a.tenant_id
   WHERE a.occurred_at > now() - make_interval(hours => GREATEST(LEAST(p_hours, 720), 1))
     AND a.outcome <> 'SUCCESS' AND a.ip_address IS NOT NULL
   GROUP BY a.tenant_id, t.name, a.ip_address
   ORDER BY 5 DESC, 4 DESC LIMIT 200
$$;

CREATE FUNCTION platform_system_metrics()
RETURNS TABLE (organizations bigint, suspended_organizations bigint, users bigint, outbox_pending bigint,
               deliveries_failing bigint, deliveries_dead bigint, audit_records bigint, activity_24h bigint,
               open_critical_alerts bigint, active_break_glass bigint, pending_break_glass bigint)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = prov, pg_temp
AS $$
  SELECT (SELECT count(*) FROM tenants), (SELECT count(*) FROM tenants WHERE status = 'SUSPENDED'),
         (SELECT count(*) FROM users),
         (SELECT count(*) FROM outbox_events WHERE dispatched_at IS NULL),
         (SELECT count(*) FROM webhook_deliveries WHERE status = 'FAILED'),
         (SELECT count(*) FROM webhook_deliveries WHERE status = 'DEAD'),
         (SELECT COALESCE(sum(last_seq), 0)::bigint FROM audit_chain_head),
         (SELECT count(*) FROM activity_log WHERE occurred_at > now() - interval '24 hours'),
         (SELECT count(*) FROM alerts WHERE status = 'OPEN' AND severity = 'CRITICAL'),
         (SELECT count(*) FROM break_glass_grants WHERE status = 'ACTIVE' AND expires_at > now()),
         (SELECT count(*) FROM break_glass_grants WHERE status IN ('PENDING', 'APPROVED'))
$$;

-- Suspending an organization is recorded in that organization's own audit chain and activity log.
CREATE FUNCTION platform_set_tenant_status(p_tenant bigint, p_status text, p_reason text, p_operator text, p_request_id text)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = prov, pg_temp
AS $$
DECLARE
  v_n integer;
BEGIN
  IF p_status NOT IN ('ACTIVE', 'SUSPENDED') THEN
    RAISE EXCEPTION 'Unknown organization status %', p_status USING ERRCODE = 'PV046';
  END IF;
  PERFORM set_config('app.tenant_id', p_tenant::text, true),
          set_config('app.user_id', '', true),
          set_config('app.actor', 'platform:' || p_operator, true),
          set_config('app.request_id', COALESCE(p_request_id, ''), true);
  UPDATE tenants SET status = p_status, status_reason = CASE WHEN p_status = 'SUSPENDED' THEN p_reason ELSE NULL END
   WHERE tenant_id = p_tenant AND status <> p_status;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  IF v_n > 0 THEN
    INSERT INTO activity_log (tenant_id, actor, action, method, route, path, status_code, outcome, request_id, details)
    VALUES (p_tenant, 'platform:' || p_operator, 'organization.' || lower(p_status), 'SYSTEM', '/platform/organizations',
            '/platform/organizations/' || p_tenant, 200, 'SUCCESS', NULLIF(p_request_id, ''),
            jsonb_build_object('status', p_status, 'reason', p_reason));
  END IF;
  RETURN v_n;
END;
$$;

-- ---------------------------------------------------------------------------------------------
-- Grants. prov_platform gets nothing on tenant tables. prov_app gets nothing on platform tables.
-- ---------------------------------------------------------------------------------------------
REVOKE ALL ON platform_users, platform_audit_log, platform_chain_head, platform_checkpoints, break_glass_grants FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA prov FROM PUBLIC;

GRANT USAGE ON SCHEMA prov TO prov_platform;
GRANT SELECT, INSERT, UPDATE ON platform_users TO prov_platform;
GRANT SELECT, INSERT, UPDATE ON break_glass_grants TO prov_platform;
GRANT SELECT ON platform_audit_log, platform_chain_head TO prov_platform;
GRANT SELECT, INSERT ON platform_checkpoints TO prov_platform;

GRANT EXECUTE ON FUNCTION platform_audit_append(text, bigint, text, text, bigint, text, text, text, text, jsonb) TO prov_platform;
GRANT EXECUTE ON FUNCTION platform_audit_verify(bigint, integer) TO prov_platform;
GRANT EXECUTE ON FUNCTION platform_audit_preimage(text, bigint, text, bigint, text, text, bigint, text, inet, text, text, timestamptz, jsonb) TO prov_platform;
GRANT EXECUTE ON FUNCTION audit_hash(text) TO prov_platform;
GRANT EXECUTE ON FUNCTION platform_org_overview(), platform_security_signals(integer), platform_system_metrics() TO prov_platform;
GRANT EXECUTE ON FUNCTION platform_set_tenant_status(bigint, text, text, text, text) TO prov_platform;
GRANT EXECUTE ON FUNCTION breakglass_list_users(bigint, bigint) TO prov_platform;
GRANT EXECUTE ON FUNCTION breakglass_recover_user(bigint, bigint, bigint, text, text, text) TO prov_platform;
GRANT EXECUTE ON FUNCTION break_glass_guard(), break_glass_insert_guard(), platform_keep_one_super_admin(),
                          platform_audit_guard(), reject_mutation() TO prov_platform;

GRANT EXECUTE ON FUNCTION breakglass_begin(bigint, bigint, text) TO prov_app;
