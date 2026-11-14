-- 0001_03_platform: governance (alerts, approvals), webhooks, API keys, external sources and events,
-- reconciliation, idempotency.

CREATE TABLE alerts (
  alert_id     bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id    bigint NOT NULL DEFAULT current_tenant_id()
               CONSTRAINT fk_alerts_tenant REFERENCES tenants(tenant_id),
  rule_code    varchar(20)  NOT NULL,
  severity     varchar(10)  NOT NULL
               CONSTRAINT ck_alerts_severity CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
  entity       varchar(30),
  entity_id    varchar(100),
  title        varchar(300) NOT NULL,
  details      jsonb        NOT NULL DEFAULT '{}'::jsonb,
  fingerprint  varchar(200) NOT NULL,   -- what makes a finding "the same finding"; rules dedupe on it
  status       varchar(12)  NOT NULL DEFAULT 'OPEN'
               CONSTRAINT ck_alerts_status CHECK (status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED')),
  created_at   timestamptz  NOT NULL DEFAULT now(),
  updated_at   timestamptz  NOT NULL DEFAULT now(),
  updated_by   varchar(254),
  CONSTRAINT uq_alerts_fingerprint UNIQUE (tenant_id, fingerprint)
);

CREATE INDEX ix_alerts_status ON alerts (tenant_id, status, alert_id DESC);

-- Maker-checker. The CHECK constraint is the four-eyes rule: the database itself refuses a
-- review by the requester, whatever the application does.
CREATE TABLE change_requests (
  change_request_id  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id          bigint NOT NULL DEFAULT current_tenant_id()
                     CONSTRAINT fk_cr_tenant REFERENCES tenants(tenant_id),
  entity             varchar(30)  NOT NULL,
  entity_id          varchar(100) NOT NULL,
  change_type        varchar(30)  NOT NULL,
  payload            jsonb        NOT NULL,
  reason             varchar(500),
  status             varchar(10)  NOT NULL DEFAULT 'PENDING'
                     CONSTRAINT ck_cr_status CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')),
  requested_by_id    bigint       NOT NULL,
  requested_by       varchar(254) NOT NULL,
  requested_at       timestamptz  NOT NULL DEFAULT now(),
  reviewed_by_id     bigint,
  reviewed_by        varchar(254),
  reviewed_at        timestamptz,
  review_note        varchar(500),
  CONSTRAINT ck_cr_four_eyes CHECK (reviewed_by_id IS NULL OR reviewed_by_id <> requested_by_id),
  CONSTRAINT ck_cr_reviewed  CHECK ((status = 'PENDING') = (reviewed_by_id IS NULL)),
  CONSTRAINT fk_cr_requester FOREIGN KEY (tenant_id, requested_by_id) REFERENCES users(tenant_id, user_id),
  CONSTRAINT fk_cr_reviewer  FOREIGN KEY (tenant_id, reviewed_by_id)  REFERENCES users(tenant_id, user_id)
);

CREATE INDEX ix_cr_status ON change_requests (tenant_id, status, change_request_id DESC);
CREATE INDEX ix_cr_entity ON change_requests (tenant_id, entity, entity_id);

-- A decided change request is final.
CREATE FUNCTION change_requests_guard() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF OLD.status <> 'PENDING' THEN
    RAISE EXCEPTION 'Change request % is already %', OLD.change_request_id, OLD.status USING ERRCODE = 'PV030';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_cr_guard BEFORE UPDATE ON change_requests
FOR EACH ROW EXECUTE FUNCTION change_requests_guard();

CREATE TRIGGER trg_a_audit AFTER INSERT OR UPDATE OR DELETE ON change_requests
  FOR EACH ROW EXECUTE FUNCTION audit_capture('change_request', 'change_request_id');

-- ---------------------------------------------------------------------------------------------
-- Webhooks
-- ---------------------------------------------------------------------------------------------
CREATE TABLE webhooks (
  webhook_id   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id    bigint NOT NULL DEFAULT current_tenant_id()
               CONSTRAINT fk_webhooks_tenant REFERENCES tenants(tenant_id),
  url          varchar(500) NOT NULL,
  secret_enc   text         NOT NULL,   -- AES-256-GCM ciphertext; the key is held by the application
  event_types  text[]       NOT NULL DEFAULT ARRAY['*'],
  description  varchar(200),
  is_active    boolean      NOT NULL DEFAULT true,
  created_at   timestamptz  NOT NULL DEFAULT now(),
  CONSTRAINT uq_webhooks_tenant UNIQUE (tenant_id, webhook_id)
);

CREATE TRIGGER trg_a_audit AFTER INSERT OR UPDATE OR DELETE ON webhooks
  FOR EACH ROW EXECUTE FUNCTION audit_capture('webhook', 'webhook_id', 'secret_enc');

CREATE TABLE webhook_deliveries (
  delivery_id       bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id         bigint NOT NULL DEFAULT current_tenant_id(),
  webhook_id        bigint NOT NULL,
  event_id          bigint NOT NULL CONSTRAINT fk_deliveries_event REFERENCES outbox_events(event_id) ON DELETE CASCADE,
  status            varchar(10) NOT NULL DEFAULT 'PENDING'
                    CONSTRAINT ck_deliveries_status CHECK (status IN ('PENDING', 'FAILED', 'SUCCESS', 'DEAD')),
  attempts          integer     NOT NULL DEFAULT 0,
  response_code     integer,
  response_snippet  varchar(500),
  last_error        varchar(1000),
  duration_ms       integer,
  next_attempt_at   timestamptz NOT NULL DEFAULT now(),
  -- Lease: a worker that claims a delivery owns it until this time. If the worker dies, the
  -- lease expires and another worker picks the delivery up (at-least-once delivery).
  locked_until      timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now(),
  delivered_at      timestamptz,
  CONSTRAINT uq_delivery UNIQUE (webhook_id, event_id),
  CONSTRAINT fk_deliveries_webhook FOREIGN KEY (tenant_id, webhook_id)
    REFERENCES webhooks(tenant_id, webhook_id) ON DELETE CASCADE
);

CREATE INDEX ix_deliveries_due ON webhook_deliveries (tenant_id, next_attempt_at)
  WHERE status IN ('PENDING', 'FAILED');
CREATE INDEX ix_deliveries_webhook ON webhook_deliveries (webhook_id, delivery_id DESC);
CREATE INDEX ix_deliveries_event   ON webhook_deliveries (event_id);

-- ---------------------------------------------------------------------------------------------
-- API keys (machine clients). Only SHA-256(secret) is stored.
-- ---------------------------------------------------------------------------------------------
CREATE TABLE api_keys (
  key_id        varchar(16)  PRIMARY KEY,
  tenant_id     bigint       NOT NULL DEFAULT current_tenant_id()
                CONSTRAINT fk_api_keys_tenant REFERENCES tenants(tenant_id),
  name          varchar(100) NOT NULL,
  secret_hash   varchar(64)  NOT NULL,
  scopes        text[]       NOT NULL CONSTRAINT ck_api_keys_scopes CHECK (cardinality(scopes) > 0),
  created_by    varchar(254),
  created_at    timestamptz  NOT NULL DEFAULT now(),
  last_used_at  timestamptz,
  expires_at    timestamptz,
  revoked_at    timestamptz
);

CREATE INDEX ix_api_keys_tenant ON api_keys (tenant_id);

CREATE TRIGGER trg_a_audit AFTER INSERT OR UPDATE OR DELETE ON api_keys
  FOR EACH ROW EXECUTE FUNCTION audit_capture('api_key', 'key_id', 'secret_hash,last_used_at');

-- ---------------------------------------------------------------------------------------------
-- External sources and their events
-- ---------------------------------------------------------------------------------------------
-- A registered upstream system. Capture method and trust level are set here by an administrator
-- and copied onto each event by the database, so a sender cannot claim more trust than it has.
CREATE TABLE sources (
  source_id      bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id      bigint NOT NULL DEFAULT current_tenant_id()
                 CONSTRAINT fk_sources_tenant REFERENCES tenants(tenant_id),
  code           varchar(60)  NOT NULL CONSTRAINT ck_sources_code CHECK (code ~ '^[a-z0-9][a-z0-9._-]{1,59}$'),
  name           varchar(120) NOT NULL,
  capture_method varchar(20)  NOT NULL
                 CONSTRAINT ck_sources_capture CHECK
                 (capture_method IN ('CDC', 'TRIGGER', 'API', 'CSV_IMPORT', 'POLLING', 'MANUAL')),
  trust_level    varchar(10)  NOT NULL
                 CONSTRAINT ck_sources_trust CHECK (trust_level IN ('HIGH', 'MEDIUM', 'LOW')),
  status         varchar(10)  NOT NULL DEFAULT 'ACTIVE'
                 CONSTRAINT ck_sources_status CHECK (status IN ('ACTIVE', 'PAUSED')),
  created_at     timestamptz  NOT NULL DEFAULT now(),
  last_event_at  timestamptz,
  CONSTRAINT uq_sources_code   UNIQUE (tenant_id, code),
  CONSTRAINT uq_sources_tenant UNIQUE (tenant_id, source_id)
);

CREATE TRIGGER trg_a_audit AFTER INSERT OR UPDATE OR DELETE ON sources
  FOR EACH ROW EXECUTE FUNCTION audit_capture('source', 'source_id', 'last_event_at');

-- Every accepted external event. (tenant_id, source_id, source_event_id) is unique, so a retry
-- is recognised by the database (INSERT ... ON CONFLICT DO NOTHING), not by application logic.
CREATE TABLE external_events (
  event_pk         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id        bigint NOT NULL DEFAULT current_tenant_id()
                   CONSTRAINT fk_ext_events_tenant REFERENCES tenants(tenant_id),
  source_id        bigint       NOT NULL,
  source_event_id  varchar(200) NOT NULL,
  event_type       varchar(120) NOT NULL,
  subject          varchar(200),
  entity           varchar(30),
  external_id      varchar(100),
  occurred_at      timestamptz  NOT NULL,
  received_at      timestamptz  NOT NULL DEFAULT now(),
  capture_method   varchar(20)  NOT NULL DEFAULT '',   -- always overwritten from the source
  trust_level      varchar(10)  NOT NULL DEFAULT '',
  payload          jsonb        NOT NULL,
  payload_sha256   varchar(64)  NOT NULL,
  request_id       varchar(64),
  CONSTRAINT fk_ext_events_source FOREIGN KEY (tenant_id, source_id) REFERENCES sources(tenant_id, source_id),
  CONSTRAINT uq_ext_events_id UNIQUE (tenant_id, source_id, source_event_id)
);

-- Serves "latest state of record X" and "history of record X" for reconstruction.
CREATE INDEX ix_ext_events_record ON external_events (tenant_id, source_id, entity, external_id, occurred_at, event_pk);
CREATE INDEX ix_ext_events_recent ON external_events (tenant_id, event_pk DESC);

CREATE FUNCTION external_events_stamp() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  v_source sources%ROWTYPE;
BEGIN
  SELECT * INTO v_source FROM sources WHERE tenant_id = NEW.tenant_id AND source_id = NEW.source_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Unknown source' USING ERRCODE = 'PV010';
  END IF;
  IF v_source.status <> 'ACTIVE' THEN
    RAISE EXCEPTION 'Source is paused: %', v_source.code USING ERRCODE = 'PV011';
  END IF;
  NEW.capture_method := v_source.capture_method;
  NEW.trust_level    := v_source.trust_level;
  NEW.received_at    := now();
  NEW.request_id     := NULLIF(current_setting('app.request_id', true), '');
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_ext_events_stamp BEFORE INSERT ON external_events
FOR EACH ROW EXECUTE FUNCTION external_events_stamp();

CREATE FUNCTION external_events_touch_source() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  UPDATE sources SET last_event_at = NEW.received_at
   WHERE tenant_id = NEW.tenant_id AND source_id = NEW.source_id;
  RETURN NULL;
END;
$$;

CREATE TRIGGER trg_b_touch_source AFTER INSERT ON external_events
FOR EACH ROW EXECUTE FUNCTION external_events_touch_source();

CREATE TRIGGER trg_a_audit AFTER INSERT ON external_events
  FOR EACH ROW EXECUTE FUNCTION audit_capture('external_event', 'event_pk', 'received_at');

CREATE TRIGGER trg_ext_events_immutable BEFORE UPDATE OR DELETE ON external_events
FOR EACH ROW EXECUTE FUNCTION reject_mutation();

-- ---------------------------------------------------------------------------------------------
-- Reconciliation runs (only discrepancies are stored; matched records are counted)
-- ---------------------------------------------------------------------------------------------
CREATE TABLE reconciliations (
  recon_id       bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id      bigint NOT NULL DEFAULT current_tenant_id()
                 CONSTRAINT fk_recon_tenant REFERENCES tenants(tenant_id),
  source_id      bigint       NOT NULL,
  entity         varchar(30)  NOT NULL,
  as_of          timestamptz  NOT NULL,
  complete       boolean      NOT NULL DEFAULT false,
  total_records  integer      NOT NULL,
  matched        integer      NOT NULL,
  mismatched     integer      NOT NULL,
  missing        integer      NOT NULL,
  unexpected     integer      NOT NULL,
  created_by     varchar(254) NOT NULL,
  created_at     timestamptz  NOT NULL DEFAULT now(),
  CONSTRAINT uq_recon_tenant UNIQUE (tenant_id, recon_id),
  CONSTRAINT fk_recon_source FOREIGN KEY (tenant_id, source_id) REFERENCES sources(tenant_id, source_id)
);

CREATE INDEX ix_recon_source ON reconciliations (tenant_id, source_id, recon_id DESC);

CREATE TABLE reconciliation_items (
  item_id      bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  recon_id     bigint NOT NULL,
  tenant_id    bigint NOT NULL DEFAULT current_tenant_id(),
  external_id  varchar(100) NOT NULL,
  outcome      varchar(12)  NOT NULL
               CONSTRAINT ck_recon_outcome CHECK (outcome IN ('MISMATCH', 'MISSING', 'UNEXPECTED')),
  details      jsonb NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT fk_recon_items FOREIGN KEY (tenant_id, recon_id) REFERENCES reconciliations(tenant_id, recon_id)
);

CREATE INDEX ix_recon_items ON reconciliation_items (tenant_id, recon_id);

-- ---------------------------------------------------------------------------------------------
-- Idempotency keys for unsafe API calls (Idempotency-Key header). The key row is written in the
-- same transaction as the work it protects, so "key recorded" and "work done" cannot diverge.
-- ---------------------------------------------------------------------------------------------
CREATE TABLE idempotency_keys (
  tenant_id     bigint       NOT NULL DEFAULT current_tenant_id()
                CONSTRAINT fk_idem_tenant REFERENCES tenants(tenant_id),
  idem_key      varchar(200) NOT NULL,
  endpoint      varchar(120) NOT NULL,
  request_hash  varchar(64)  NOT NULL,
  status_code   integer      NOT NULL,
  response      jsonb        NOT NULL,
  created_at    timestamptz  NOT NULL DEFAULT now(),
  CONSTRAINT pk_idempotency_keys PRIMARY KEY (tenant_id, idem_key)
);

CREATE INDEX ix_idem_created ON idempotency_keys (created_at);
