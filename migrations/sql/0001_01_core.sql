-- 0001_01_core: request context, organizations, identity, and the built-in commerce ledger.
--
-- Conventions
--   * Everything lives in schema `prov`, owned by role prov_owner. The API connects as prov_app.
--   * Every tenant-owned table has tenant_id NOT NULL DEFAULT current_tenant_id(), so application
--     code never passes a tenant id in an INSERT; row-level security checks it either way.
--   * Composite (tenant_id, id) foreign keys make a cross-tenant reference impossible even for a
--     role that bypasses row-level security.
--   * Timestamps are timestamptz. Money is numeric(12,2), never float.

-- ---------------------------------------------------------------------------------------------
-- Request context. The API calls set_context() as the first statement of every transaction.
-- The values are transaction-local (set_config(..., true)), so they vanish at COMMIT/ROLLBACK and
-- can never leak to the next request that reuses the pooled connection. This is also what makes
-- the design safe behind PgBouncer in transaction-pooling mode.
-- ---------------------------------------------------------------------------------------------
CREATE FUNCTION current_tenant_id() RETURNS bigint
LANGUAGE sql STABLE PARALLEL SAFE
AS $$ SELECT NULLIF(current_setting('app.tenant_id', true), '')::bigint $$;

COMMENT ON FUNCTION current_tenant_id() IS
  'Tenant of the current transaction, or NULL. NULL makes every row-level-security policy false (fail closed).';

CREATE FUNCTION set_context(p_tenant_id bigint, p_user_id bigint, p_actor text, p_request_id text)
RETURNS void
LANGUAGE sql
AS $$
  SELECT set_config('app.tenant_id',         COALESCE(p_tenant_id::text, ''), true),
         set_config('app.user_id',           COALESCE(p_user_id::text, ''),   true),
         set_config('app.actor',             COALESCE(p_actor, ''),           true),
         set_config('app.request_id',        COALESCE(p_request_id, ''),      true),
         set_config('app.change_request_id', '',                              true);
$$;

CREATE FUNCTION set_change_request(p_change_request_id bigint) RETURNS void
LANGUAGE sql
AS $$ SELECT set_config('app.change_request_id', COALESCE(p_change_request_id::text, ''), true) $$;

-- ---------------------------------------------------------------------------------------------
-- Organizations and identity
-- ---------------------------------------------------------------------------------------------
CREATE TABLE tenants (
  tenant_id   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name        varchar(120) NOT NULL CONSTRAINT ck_tenants_name CHECK (length(btrim(name)) >= 2),
  slug        varchar(60)  NOT NULL CONSTRAINT uq_tenants_slug UNIQUE,
  plan        varchar(20)  NOT NULL DEFAULT 'FREE'
              CONSTRAINT ck_tenants_plan CHECK (plan IN ('FREE', 'PRO', 'ENTERPRISE')),
  created_at  timestamptz  NOT NULL DEFAULT now()
);

CREATE TABLE tenant_settings (
  tenant_id                 bigint PRIMARY KEY DEFAULT current_tenant_id()
                            CONSTRAINT fk_settings_tenant REFERENCES tenants(tenant_id),
  currency                  char(3)       NOT NULL DEFAULT 'USD'
                            CONSTRAINT ck_settings_currency CHECK (currency ~ '^[A-Z]{3}$'),
  approval_price_change_pct numeric(6,2)  NOT NULL DEFAULT 20   CHECK (approval_price_change_pct >= 0),
  price_change_alert_pct    numeric(6,2)  NOT NULL DEFAULT 30   CHECK (price_change_alert_pct >= 0),
  discount_alert_pct        numeric(6,2)  NOT NULL DEFAULT 20   CHECK (discount_alert_pct BETWEEN 0 AND 100),
  large_refund_amount       numeric(12,2) NOT NULL DEFAULT 1000 CHECK (large_refund_amount >= 0),
  rapid_change_count        integer       NOT NULL DEFAULT 5    CHECK (rapid_change_count >= 2),
  rapid_change_minutes      integer       NOT NULL DEFAULT 10   CHECK (rapid_change_minutes >= 1)
);

CREATE TABLE users (
  user_id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id            bigint NOT NULL DEFAULT current_tenant_id()
                       CONSTRAINT fk_users_tenant REFERENCES tenants(tenant_id),
  email                varchar(254) NOT NULL CONSTRAINT ck_users_email_lower CHECK (email = lower(email)),
  full_name            varchar(120) NOT NULL,
  password_hash        varchar(255) NOT NULL,
  role                 varchar(10)  NOT NULL DEFAULT 'viewer'
                       CONSTRAINT ck_users_role CHECK (role IN ('admin', 'staff', 'auditor', 'viewer')),
  is_active            boolean      NOT NULL DEFAULT true,
  created_at           timestamptz  NOT NULL DEFAULT now(),
  last_login_at        timestamptz,
  password_changed_at  timestamptz  NOT NULL DEFAULT now(),
  -- Embedded in every access token. Incrementing it (password change, "sign out everywhere",
  -- deactivation) invalidates all access tokens issued before, without comparing clocks.
  token_version        integer      NOT NULL DEFAULT 1,
  -- One account per email across the whole service: login is by email alone.
  CONSTRAINT uq_users_email  UNIQUE (email),
  CONSTRAINT uq_users_tenant UNIQUE (tenant_id, user_id)
);

CREATE INDEX ix_users_tenant ON users (tenant_id);

-- An organization must always keep at least one active admin, whoever makes the change.
-- Deferred to commit so a role swap inside one transaction is allowed.
CREATE FUNCTION users_keep_one_admin() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  -- Serialise concurrent role changes within the organization so two admins cannot demote each other.
  PERFORM 1 FROM tenants WHERE tenant_id = OLD.tenant_id FOR UPDATE;
  IF NOT EXISTS (SELECT 1 FROM users WHERE tenant_id = OLD.tenant_id AND role = 'admin' AND is_active) THEN
    RAISE EXCEPTION 'An organization must keep at least one active admin' USING ERRCODE = 'PV020';
  END IF;
  RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER trg_users_keep_one_admin
AFTER UPDATE OF role, is_active OR DELETE ON users
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
WHEN (OLD.role = 'admin' AND OLD.is_active)
EXECUTE FUNCTION users_keep_one_admin();

-- Refresh tokens are opaque random strings; only their SHA-256 is stored. Each login starts a
-- "family". Using a token rotates it (used_at + replaced_by). Presenting an already-used token
-- means it was stolen or replayed, so the whole family is revoked.
CREATE TABLE refresh_tokens (
  token_id     bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id    bigint NOT NULL DEFAULT current_tenant_id(),
  user_id      bigint NOT NULL,
  family_id    uuid   NOT NULL,
  token_hash   varchar(64) NOT NULL CONSTRAINT uq_refresh_hash UNIQUE,
  issued_at    timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  used_at      timestamptz,
  revoked_at   timestamptz,
  replaced_by  bigint,
  user_agent   varchar(200),
  CONSTRAINT fk_refresh_user FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, user_id) ON DELETE CASCADE
);

CREATE INDEX ix_refresh_user   ON refresh_tokens (tenant_id, user_id);
CREATE INDEX ix_refresh_family ON refresh_tokens (family_id);

-- ---------------------------------------------------------------------------------------------
-- Commerce ledger (the built-in, trigger-captured dataset)
-- ---------------------------------------------------------------------------------------------
CREATE TABLE customers (
  customer_id  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id    bigint NOT NULL DEFAULT current_tenant_id()
               CONSTRAINT fk_customers_tenant REFERENCES tenants(tenant_id),
  name         varchar(120) NOT NULL,
  email        varchar(254) NOT NULL,
  phone        varchar(30),
  created_at   timestamptz  NOT NULL DEFAULT now(),
  CONSTRAINT uq_customers_email  UNIQUE (tenant_id, email),
  CONSTRAINT uq_customers_tenant UNIQUE (tenant_id, customer_id)
);

CREATE TABLE products (
  product_id  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id   bigint NOT NULL DEFAULT current_tenant_id()
              CONSTRAINT fk_products_tenant REFERENCES tenants(tenant_id),
  sku         varchar(40)   NOT NULL,
  name        varchar(120)  NOT NULL,
  price       numeric(12,2) NOT NULL CONSTRAINT ck_products_price CHECK (price >= 0),
  active      boolean       NOT NULL DEFAULT true,
  created_at  timestamptz   NOT NULL DEFAULT now(),
  CONSTRAINT uq_products_sku    UNIQUE (tenant_id, sku),
  CONSTRAINT uq_products_tenant UNIQUE (tenant_id, product_id)
);

CREATE TABLE order_status_transitions (
  from_status varchar(12) NOT NULL,
  to_status   varchar(12) NOT NULL,
  CONSTRAINT pk_order_status_transitions PRIMARY KEY (from_status, to_status)
);

INSERT INTO order_status_transitions (from_status, to_status) VALUES
  ('CREATED',   'PAID'),
  ('CREATED',   'CANCELLED'),
  ('PAID',      'SHIPPED'),
  ('PAID',      'REFUNDED'),
  ('SHIPPED',   'DELIVERED'),
  ('SHIPPED',   'REFUNDED'),
  ('DELIVERED', 'REFUNDED');

CREATE TABLE orders (
  order_id      bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id     bigint NOT NULL DEFAULT current_tenant_id()
                CONSTRAINT fk_orders_tenant REFERENCES tenants(tenant_id),
  customer_id   bigint NOT NULL,
  status        varchar(12) NOT NULL DEFAULT 'CREATED'
                CONSTRAINT ck_orders_status CHECK
                (status IN ('CREATED', 'PAID', 'SHIPPED', 'DELIVERED', 'CANCELLED', 'REFUNDED')),
  total_amount  numeric(12,2) NOT NULL DEFAULT 0 CONSTRAINT ck_orders_total CHECK (total_amount >= 0),
  currency      char(3)       NOT NULL DEFAULT 'USD',
  notes         varchar(500),
  created_at    timestamptz   NOT NULL DEFAULT now(),
  updated_at    timestamptz   NOT NULL DEFAULT now(),
  CONSTRAINT uq_orders_tenant   UNIQUE (tenant_id, order_id),
  CONSTRAINT fk_orders_customer FOREIGN KEY (tenant_id, customer_id) REFERENCES customers(tenant_id, customer_id)
);

CREATE INDEX ix_orders_status   ON orders (tenant_id, status);
CREATE INDEX ix_orders_customer ON orders (tenant_id, customer_id);
CREATE INDEX ix_orders_created  ON orders (tenant_id, created_at);

CREATE TABLE order_items (
  order_id    bigint NOT NULL,
  product_id  bigint NOT NULL,
  tenant_id   bigint NOT NULL DEFAULT current_tenant_id(),
  quantity    numeric(10,2) NOT NULL CONSTRAINT ck_items_qty   CHECK (quantity > 0),
  unit_price  numeric(12,2) NOT NULL CONSTRAINT ck_items_price CHECK (unit_price >= 0),
  line_total  numeric(14,2) GENERATED ALWAYS AS (round(quantity * unit_price, 2)) STORED,
  CONSTRAINT pk_order_items   PRIMARY KEY (order_id, product_id),
  CONSTRAINT fk_items_order   FOREIGN KEY (tenant_id, order_id)   REFERENCES orders(tenant_id, order_id),
  CONSTRAINT fk_items_product FOREIGN KEY (tenant_id, product_id) REFERENCES products(tenant_id, product_id)
);

CREATE INDEX ix_items_product ON order_items (tenant_id, product_id);

CREATE TABLE payments (
  payment_id  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id   bigint NOT NULL DEFAULT current_tenant_id(),
  order_id    bigint NOT NULL,
  amount      numeric(12,2) NOT NULL CONSTRAINT ck_payments_amount CHECK (amount > 0),
  method      varchar(10)   NOT NULL
              CONSTRAINT ck_payments_method CHECK (method IN ('CARD', 'CASH', 'BKASH', 'NAGAD', 'BANK')),
  status      varchar(10)   NOT NULL DEFAULT 'CAPTURED'
              CONSTRAINT ck_payments_status CHECK (status IN ('CAPTURED', 'VOID', 'REFUNDED')),
  reference   varchar(80),
  created_at  timestamptz   NOT NULL DEFAULT now(),
  CONSTRAINT fk_payments_order FOREIGN KEY (tenant_id, order_id) REFERENCES orders(tenant_id, order_id)
);

CREATE INDEX ix_payments_order ON payments (tenant_id, order_id);

-- ---------------------------------------------------------------------------------------------
-- Business rules enforced by the database, so they hold for every client, not only the API.
-- ---------------------------------------------------------------------------------------------
CREATE FUNCTION orders_guard() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.total_amount := 0;  -- derived from order_items; never accepted from the client
    RETURN NEW;
  END IF;
  IF NEW.status <> OLD.status AND NOT EXISTS (
       SELECT 1 FROM order_status_transitions WHERE from_status = OLD.status AND to_status = NEW.status) THEN
    RAISE EXCEPTION 'Invalid order status transition: % -> %', OLD.status, NEW.status USING ERRCODE = 'PV001';
  END IF;
  -- total_amount may only be changed by the order_items trigger (depth 2), never directly.
  IF NEW.total_amount <> OLD.total_amount AND pg_trigger_depth() < 2 THEN
    RAISE EXCEPTION 'total_amount is derived from the order items and cannot be set directly'
      USING ERRCODE = 'PV003';
  END IF;
  IF NEW IS DISTINCT FROM OLD THEN
    NEW.updated_at := now();
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_orders_guard BEFORE INSERT OR UPDATE ON orders
FOR EACH ROW EXECUTE FUNCTION orders_guard();

-- Items can change only while the order is CREATED. Taking the order row lock here serialises
-- concurrent item changes and status changes on one order, so the check cannot race.
CREATE FUNCTION order_items_guard() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  v_order_id bigint := CASE WHEN TG_OP = 'DELETE' THEN OLD.order_id ELSE NEW.order_id END;
  v_status   varchar(12);
BEGIN
  IF TG_OP = 'UPDATE' AND (NEW.order_id <> OLD.order_id OR NEW.product_id <> OLD.product_id) THEN
    RAISE EXCEPTION 'An order item cannot be moved to another order or product' USING ERRCODE = 'PV002';
  END IF;
  SELECT status INTO v_status FROM orders WHERE order_id = v_order_id FOR NO KEY UPDATE;
  IF v_status IS DISTINCT FROM 'CREATED' THEN
    RAISE EXCEPTION 'Order items can only change while the order is CREATED (order is %)',
      COALESCE(v_status, 'missing') USING ERRCODE = 'PV002';
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;

CREATE TRIGGER trg_order_items_guard BEFORE INSERT OR UPDATE OR DELETE ON order_items
FOR EACH ROW EXECUTE FUNCTION order_items_guard();

-- Keeps orders.total_amount equal to the sum of its lines. AFTER ROW triggers see the final
-- state of the statement, so a multi-row statement changes the total once.
CREATE FUNCTION order_items_recalculate_total() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  v_order_id bigint := CASE WHEN TG_OP = 'DELETE' THEN OLD.order_id ELSE NEW.order_id END;
BEGIN
  UPDATE orders
     SET total_amount = (SELECT COALESCE(sum(line_total), 0) FROM order_items WHERE order_id = v_order_id)
   WHERE order_id = v_order_id;
  RETURN NULL;
END;
$$;

-- Trigger names matter: PostgreSQL fires same-event triggers in name order, and the audit
-- trigger (trg_a_audit, created in 0001_02) must record the item before the total it causes.
CREATE TRIGGER trg_b_recalculate_total AFTER INSERT OR UPDATE OR DELETE ON order_items
FOR EACH ROW EXECUTE FUNCTION order_items_recalculate_total();
