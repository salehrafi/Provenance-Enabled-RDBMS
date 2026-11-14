-- 0002_01_activity_log: security activity log.
--
-- audit_log answers "how did this record change?". activity_log answers "who did what, from where, and
-- did it work?": sign-ins (including failed ones), every change made through the API, and sensitive
-- reads such as exports. One row per request, written after the response is known.
--
-- Protection
--   * Append-only: the runtime role has SELECT and INSERT only, and a trigger rejects UPDATE, DELETE and
--     TRUNCATE for every role, the table owner included. Removing a row requires a database superuser
--     to disable the trigger first.
--   * Tenant isolated by row-level security like every other tenant table.
--   * Readable in the product only by organization admins (permission activity:read).
--   * Never pruned by housekeeping.

CREATE TABLE activity_log (
  activity_id    bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id      bigint NOT NULL DEFAULT current_tenant_id()
                 CONSTRAINT fk_activity_tenant REFERENCES tenants(tenant_id),
  occurred_at    timestamptz  NOT NULL DEFAULT clock_timestamp(),
  actor          varchar(254) NOT NULL,                 -- email, apikey:<name>, or the attempted email
  actor_user_id  bigint,
  api_key_id     varchar(16),
  action         varchar(120) NOT NULL,                 -- auth.login, auth.login_failed, order.create ...
  method         varchar(10)  NOT NULL,
  route          varchar(300) NOT NULL,                 -- route template, e.g. /api/v1/orders/{order_id}
  path           varchar(500) NOT NULL,                 -- the concrete path that was called
  status_code    integer      NOT NULL,
  outcome        varchar(10)  NOT NULL
                 CONSTRAINT ck_activity_outcome CHECK (outcome IN ('SUCCESS', 'DENIED', 'FAILURE')),
  ip_address     inet,                                  -- client address as seen by the API (see SECURITY.md)
  user_agent     varchar(300),
  request_id     varchar(64),
  duration_ms    integer,
  details        jsonb NOT NULL DEFAULT '{}'::jsonb      -- path parameters and event-specific context; never secrets
);

CREATE INDEX ix_activity_recent ON activity_log (tenant_id, activity_id DESC);
CREATE INDEX ix_activity_time   ON activity_log (tenant_id, occurred_at);
CREATE INDEX ix_activity_actor  ON activity_log (tenant_id, actor, activity_id DESC);
CREATE INDEX ix_activity_ip     ON activity_log USING gist (ip_address inet_ops) WHERE ip_address IS NOT NULL;
CREATE INDEX ix_activity_action ON activity_log (tenant_id, action, activity_id DESC);

CREATE TRIGGER trg_activity_immutable BEFORE UPDATE OR DELETE ON activity_log
FOR EACH ROW EXECUTE FUNCTION reject_mutation();

CREATE TRIGGER trg_activity_no_truncate BEFORE TRUNCATE ON activity_log
FOR EACH STATEMENT EXECUTE FUNCTION reject_mutation();

ALTER TABLE activity_log ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON activity_log
  USING (tenant_id = (SELECT current_tenant_id()))
  WITH CHECK (tenant_id = (SELECT current_tenant_id()));

REVOKE ALL ON activity_log FROM PUBLIC;
GRANT SELECT, INSERT ON activity_log TO prov_app;
