-- 0001_04_security: row-level security, privileged entry points, least-privilege grants.
--
-- Roles
--   prov_owner  owns every object. Used for migrations only. As table owner it is exempt from
--               row-level security, which is what lets the SECURITY DEFINER functions below work.
--   prov_app    the API and the worker. NOSUPERUSER, NOBYPASSRLS. Sees one tenant per transaction.
--
-- Row-level security is the second line of defence, not the first: the application decides which
-- tenant a request belongs to (from a verified token or API key) and tells the database with
-- set_context(). RLS then guarantees that a forgotten WHERE clause, a wrong join or an injected
-- predicate still cannot read or write another tenant's rows. With no context, every policy is
-- false and the role sees nothing.

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'tenants', 'tenant_settings', 'users', 'refresh_tokens',
    'customers', 'products', 'orders', 'order_items', 'payments',
    'outbox_events', 'audit_log', 'audit_chain_head', 'audit_checkpoints',
    'alerts', 'change_requests', 'webhooks', 'webhook_deliveries', 'api_keys',
    'sources', 'external_events', 'reconciliations', 'reconciliation_items', 'idempotency_keys']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    -- No TO clause: the policy applies to every role that is subject to RLS, including any
    -- role added later. (SELECT ...) lets the planner evaluate the tenant once per statement.
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I USING (tenant_id = (SELECT current_tenant_id())) '
      'WITH CHECK (tenant_id = (SELECT current_tenant_id()))', t);
  END LOOP;
END;
$$;

-- ---------------------------------------------------------------------------------------------
-- Privileged entry points. Authentication has to find a user, key or token BEFORE a tenant is
-- known, which row-level security forbids. Each function below does exactly one such lookup by
-- an exact, unguessable or unique key and returns a single row. None of them can list data.
-- search_path is pinned so a caller cannot substitute objects.
-- ---------------------------------------------------------------------------------------------
CREATE FUNCTION auth_user_by_email(p_email text)
RETURNS TABLE (user_id bigint, tenant_id bigint, email varchar, full_name varchar, role varchar,
               is_active boolean, password_hash varchar, token_version integer, tenant_name varchar, tenant_slug varchar, plan varchar)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = prov, pg_temp
AS $$
  SELECT u.user_id, u.tenant_id, u.email, u.full_name, u.role, u.is_active, u.password_hash, u.token_version,
         t.name, t.slug, t.plan
    FROM users u JOIN tenants t ON t.tenant_id = u.tenant_id
   WHERE u.email = lower(p_email)
$$;

CREATE FUNCTION auth_api_key(p_key_id text)
RETURNS TABLE (key_id varchar, tenant_id bigint, name varchar, secret_hash varchar, scopes text[],
               expires_at timestamptz, revoked_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = prov, pg_temp
AS $$
  SELECT k.key_id, k.tenant_id, k.name, k.secret_hash, k.scopes, k.expires_at, k.revoked_at
    FROM api_keys k WHERE k.key_id = p_key_id
$$;

CREATE FUNCTION auth_refresh_token(p_token_hash text)
RETURNS TABLE (token_id bigint, tenant_id bigint, user_id bigint, family_id uuid,
               expires_at timestamptz, used_at timestamptz, revoked_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = prov, pg_temp
AS $$
  SELECT r.token_id, r.tenant_id, r.user_id, r.family_id, r.expires_at, r.used_at, r.revoked_at
    FROM refresh_tokens r WHERE r.token_hash = p_token_hash
$$;

-- Sign-up: creates the organization, its settings, its chain head and its first admin atomically.
CREATE FUNCTION create_organization(p_name text, p_slug text, p_email text, p_full_name text,
                                    p_password_hash text, p_request_id text)
RETURNS TABLE (tenant_id bigint, user_id bigint)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = prov, pg_temp
AS $$
DECLARE
  v_tenant bigint;
  v_user   bigint;
BEGIN
  PERFORM set_config('app.actor', lower(p_email), true),
          set_config('app.request_id', COALESCE(p_request_id, ''), true),
          set_config('app.user_id', '', true),
          set_config('app.change_request_id', '', true);
  INSERT INTO tenants (name, slug) VALUES (p_name, p_slug) RETURNING tenants.tenant_id INTO v_tenant;
  PERFORM set_config('app.tenant_id', v_tenant::text, true);
  INSERT INTO audit_chain_head (tenant_id) VALUES (v_tenant) ON CONFLICT DO NOTHING;
  INSERT INTO tenant_settings (tenant_id) VALUES (v_tenant);
  INSERT INTO users (tenant_id, email, full_name, password_hash, role)
  VALUES (v_tenant, lower(p_email), p_full_name, p_password_hash, 'admin')
  RETURNING users.user_id INTO v_user;
  RETURN QUERY SELECT v_tenant, v_user;
END;
$$;

-- The worker iterates tenants and then works inside each one under row-level security.
CREATE FUNCTION worker_tenants(p_only_pending boolean DEFAULT false)
RETURNS SETOF bigint
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = prov, pg_temp
AS $$
  SELECT t.tenant_id FROM tenants t
   WHERE NOT p_only_pending
      OR EXISTS (SELECT 1 FROM outbox_events o WHERE o.tenant_id = t.tenant_id AND o.dispatched_at IS NULL)
      OR EXISTS (SELECT 1 FROM webhook_deliveries d
                  WHERE d.tenant_id = t.tenant_id AND d.status IN ('PENDING', 'FAILED')
                    AND d.next_attempt_at <= now())
   ORDER BY t.tenant_id
$$;

-- Housekeeping across all tenants. Never touches audit_log, audit_checkpoints or external_events.
CREATE FUNCTION prune_operational_data(p_delivery_days integer DEFAULT 30)
RETURNS TABLE (deliveries bigint, events bigint, idempotency bigint, tokens bigint)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = prov, pg_temp
AS $$
DECLARE
  v_cutoff timestamptz := now() - make_interval(days => GREATEST(p_delivery_days, 1));
BEGIN
  WITH d AS (DELETE FROM webhook_deliveries
              WHERE status IN ('SUCCESS', 'DEAD') AND created_at < v_cutoff RETURNING 1)
  SELECT count(*) INTO deliveries FROM d;

  WITH e AS (DELETE FROM outbox_events o
              WHERE o.dispatched_at < v_cutoff
                AND NOT EXISTS (SELECT 1 FROM webhook_deliveries d WHERE d.event_id = o.event_id)
              RETURNING 1)
  SELECT count(*) INTO events FROM e;

  WITH i AS (DELETE FROM idempotency_keys WHERE created_at < now() - interval '2 days' RETURNING 1)
  SELECT count(*) INTO idempotency FROM i;

  WITH r AS (DELETE FROM refresh_tokens WHERE expires_at < now() - interval '7 days' RETURNING 1)
  SELECT count(*) INTO tokens FROM r;

  RETURN NEXT;
END;
$$;

-- ---------------------------------------------------------------------------------------------
-- Grants. Start from nothing, then add exactly what the API needs.
-- ---------------------------------------------------------------------------------------------
REVOKE ALL ON ALL TABLES    IN SCHEMA prov FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA prov FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA prov REVOKE ALL ON FUNCTIONS FROM PUBLIC;

GRANT USAGE ON SCHEMA prov TO prov_app;

-- Business data
GRANT SELECT, INSERT, UPDATE, DELETE ON customers, products, orders, order_items, payments TO prov_app;
GRANT SELECT ON order_status_transitions TO prov_app;

-- Organization and identity. Tenants are created only through create_organization().
GRANT SELECT ON tenants TO prov_app;
GRANT UPDATE (name) ON tenants TO prov_app;
GRANT SELECT, UPDATE ON tenant_settings TO prov_app;
GRANT SELECT, INSERT, UPDATE ON users TO prov_app;
GRANT SELECT, INSERT, UPDATE ON refresh_tokens TO prov_app;
GRANT SELECT, INSERT, UPDATE ON api_keys TO prov_app;

-- History: the API can read it and nothing else. Rows are written by SECURITY DEFINER triggers.
GRANT SELECT ON audit_log, audit_chain_head TO prov_app;
GRANT SELECT, INSERT ON audit_checkpoints TO prov_app;

-- Outbox: the API appends events and marks them dispatched; it cannot rewrite or delete them.
GRANT SELECT, INSERT ON outbox_events TO prov_app;
GRANT UPDATE (dispatched_at) ON outbox_events TO prov_app;

-- Governance and integration
GRANT SELECT, INSERT, UPDATE ON alerts, change_requests, sources TO prov_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON webhooks TO prov_app;
GRANT SELECT, INSERT, UPDATE ON webhook_deliveries TO prov_app;
GRANT SELECT, INSERT ON external_events, reconciliations, reconciliation_items TO prov_app;
GRANT SELECT, INSERT ON idempotency_keys TO prov_app;

-- Functions. audit_append / audit_seal / audit_capture are deliberately absent.
GRANT EXECUTE ON FUNCTION current_tenant_id() TO prov_app;
GRANT EXECUTE ON FUNCTION set_context(bigint, bigint, text, text) TO prov_app;
GRANT EXECUTE ON FUNCTION set_change_request(bigint) TO prov_app;
GRANT EXECUTE ON FUNCTION audit_preimage(text, bigint, bigint, text, text, text, text, bigint, text, bigint, text, timestamptz, jsonb, jsonb) TO prov_app;
GRANT EXECUTE ON FUNCTION audit_hash(text) TO prov_app;
GRANT EXECUTE ON FUNCTION audit_verify(bigint, integer) TO prov_app;
GRANT EXECUTE ON FUNCTION auth_user_by_email(text) TO prov_app;
GRANT EXECUTE ON FUNCTION auth_api_key(text) TO prov_app;
GRANT EXECUTE ON FUNCTION auth_refresh_token(text) TO prov_app;
GRANT EXECUTE ON FUNCTION create_organization(text, text, text, text, text, text) TO prov_app;
GRANT EXECUTE ON FUNCTION worker_tenants(boolean) TO prov_app;
GRANT EXECUTE ON FUNCTION prune_operational_data(integer) TO prov_app;
-- Trigger functions run with the rights of the statement's role and need EXECUTE.
GRANT EXECUTE ON FUNCTION orders_guard(), order_items_guard(), order_items_recalculate_total(),
                          orders_status_event(), users_keep_one_admin(), change_requests_guard(),
                          external_events_stamp(), external_events_touch_source(),
                          audit_guard(), reject_mutation() TO prov_app;
