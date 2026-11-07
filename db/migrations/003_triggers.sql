-- 003_triggers: provenance capture on every business table + business rules in the DB.
-- No-op updates (old JSON = new JSON) are skipped so the log only holds real changes.

CREATE OR REPLACE TRIGGER trg_audit_customers
AFTER INSERT OR UPDATE OR DELETE ON customers
FOR EACH ROW
DECLARE
  v_old CLOB;
  v_new CLOB;
BEGIN
  IF UPDATING OR DELETING THEN
    SELECT JSON_OBJECT('customer_id' VALUE :OLD.customer_id, 'name' VALUE :OLD.name,
                       'email' VALUE :OLD.email, 'phone' VALUE :OLD.phone RETURNING CLOB)
      INTO v_old FROM dual;
  END IF;
  IF INSERTING OR UPDATING THEN
    SELECT JSON_OBJECT('customer_id' VALUE :NEW.customer_id, 'name' VALUE :NEW.name,
                       'email' VALUE :NEW.email, 'phone' VALUE :NEW.phone RETURNING CLOB)
      INTO v_new FROM dual;
  END IF;
  IF UPDATING AND DBMS_LOB.COMPARE(v_old, v_new) = 0 THEN
    RETURN;
  END IF;
  audit_pkg.log_change(NVL(:NEW.tenant_id, :OLD.tenant_id), 'customer',
                       TO_CHAR(NVL(:NEW.customer_id, :OLD.customer_id)),
                       CASE WHEN INSERTING THEN 'INSERT' WHEN UPDATING THEN 'UPDATE' ELSE 'DELETE' END,
                       v_old, v_new);
END;
/

CREATE OR REPLACE TRIGGER trg_audit_products
AFTER INSERT OR UPDATE OR DELETE ON products
FOR EACH ROW
DECLARE
  v_old CLOB;
  v_new CLOB;
BEGIN
  IF UPDATING OR DELETING THEN
    SELECT JSON_OBJECT('product_id' VALUE :OLD.product_id, 'sku' VALUE :OLD.sku,
                       'name' VALUE :OLD.name, 'price' VALUE :OLD.price,
                       'active_flag' VALUE :OLD.active_flag RETURNING CLOB)
      INTO v_old FROM dual;
  END IF;
  IF INSERTING OR UPDATING THEN
    SELECT JSON_OBJECT('product_id' VALUE :NEW.product_id, 'sku' VALUE :NEW.sku,
                       'name' VALUE :NEW.name, 'price' VALUE :NEW.price,
                       'active_flag' VALUE :NEW.active_flag RETURNING CLOB)
      INTO v_new FROM dual;
  END IF;
  IF UPDATING AND DBMS_LOB.COMPARE(v_old, v_new) = 0 THEN
    RETURN;
  END IF;
  audit_pkg.log_change(NVL(:NEW.tenant_id, :OLD.tenant_id), 'product',
                       TO_CHAR(NVL(:NEW.product_id, :OLD.product_id)),
                       CASE WHEN INSERTING THEN 'INSERT' WHEN UPDATING THEN 'UPDATE' ELSE 'DELETE' END,
                       v_old, v_new);
END;
/

-- Order state machine enforced by the database: any client (API, SQL*Plus, ETL) gets the
-- same rule.
CREATE OR REPLACE TRIGGER trg_orders_status_guard
BEFORE UPDATE OF status ON orders
FOR EACH ROW
DECLARE
  n NUMBER;
BEGIN
  IF :NEW.status <> :OLD.status THEN
    SELECT COUNT(*) INTO n FROM order_status_transitions
     WHERE from_status = :OLD.status AND to_status = :NEW.status;
    IF n = 0 THEN
      RAISE_APPLICATION_ERROR(-20001, 'Invalid order status transition: ' ||
                              :OLD.status || ' -> ' || :NEW.status);
    END IF;
  END IF;
END;
/

CREATE OR REPLACE TRIGGER trg_audit_orders
AFTER INSERT OR UPDATE OR DELETE ON orders
FOR EACH ROW
DECLARE
  v_old     CLOB;
  v_new     CLOB;
  v_payload CLOB;
BEGIN
  IF UPDATING OR DELETING THEN
    SELECT JSON_OBJECT('order_id' VALUE :OLD.order_id, 'customer_id' VALUE :OLD.customer_id,
                       'status' VALUE :OLD.status, 'total_amount' VALUE :OLD.total_amount,
                       'currency' VALUE :OLD.currency, 'notes' VALUE :OLD.notes RETURNING CLOB)
      INTO v_old FROM dual;
  END IF;
  IF INSERTING OR UPDATING THEN
    SELECT JSON_OBJECT('order_id' VALUE :NEW.order_id, 'customer_id' VALUE :NEW.customer_id,
                       'status' VALUE :NEW.status, 'total_amount' VALUE :NEW.total_amount,
                       'currency' VALUE :NEW.currency, 'notes' VALUE :NEW.notes RETURNING CLOB)
      INTO v_new FROM dual;
  END IF;
  IF UPDATING AND DBMS_LOB.COMPARE(v_old, v_new) = 0 THEN
    RETURN;
  END IF;
  audit_pkg.log_change(NVL(:NEW.tenant_id, :OLD.tenant_id), 'order',
                       TO_CHAR(NVL(:NEW.order_id, :OLD.order_id)),
                       CASE WHEN INSERTING THEN 'INSERT' WHEN UPDATING THEN 'UPDATE' ELSE 'DELETE' END,
                       v_old, v_new);
  IF UPDATING AND :NEW.status <> :OLD.status THEN
    SELECT JSON_OBJECT('order_id' VALUE :NEW.order_id, 'from' VALUE :OLD.status,
                       'to' VALUE :NEW.status, 'total_amount' VALUE :NEW.total_amount RETURNING CLOB)
      INTO v_payload FROM dual;
    outbox_pkg.emit(:NEW.tenant_id, 'order.status_changed', 'order', TO_CHAR(:NEW.order_id), v_payload);
  END IF;
END;
/

-- Compound trigger: audit each item row, then recompute the affected order totals once in
-- AFTER STATEMENT. Reading order_items from a plain row-level trigger on order_items raises
-- ORA-04091 (mutating table), which is what the legacy script would have hit.
CREATE OR REPLACE TRIGGER trg_order_items
FOR INSERT OR UPDATE OR DELETE ON order_items
COMPOUND TRIGGER
  TYPE t_ids IS TABLE OF PLS_INTEGER INDEX BY PLS_INTEGER;
  g_ids t_ids;

  BEFORE EACH ROW IS
    v_status orders.status%TYPE;
  BEGIN
    SELECT status INTO v_status FROM orders WHERE order_id = NVL(:NEW.order_id, :OLD.order_id);
    IF v_status <> 'CREATED' THEN
      RAISE_APPLICATION_ERROR(-20002, 'Order items can only change while the order is CREATED (order is '
                              || v_status || ')');
    END IF;
  END BEFORE EACH ROW;

  AFTER EACH ROW IS
    v_old CLOB;
    v_new CLOB;
  BEGIN
    IF UPDATING OR DELETING THEN
      SELECT JSON_OBJECT('order_id' VALUE :OLD.order_id, 'product_id' VALUE :OLD.product_id,
                         'quantity' VALUE :OLD.quantity, 'unit_price' VALUE :OLD.unit_price,
                         'line_total' VALUE ROUND(:OLD.quantity * :OLD.unit_price, 2) RETURNING CLOB)
        INTO v_old FROM dual;
    END IF;
    IF INSERTING OR UPDATING THEN
      SELECT JSON_OBJECT('order_id' VALUE :NEW.order_id, 'product_id' VALUE :NEW.product_id,
                         'quantity' VALUE :NEW.quantity, 'unit_price' VALUE :NEW.unit_price,
                         'line_total' VALUE ROUND(:NEW.quantity * :NEW.unit_price, 2) RETURNING CLOB)
        INTO v_new FROM dual;
    END IF;
    IF NOT (UPDATING AND DBMS_LOB.COMPARE(v_old, v_new) = 0) THEN
      audit_pkg.log_change(NVL(:NEW.tenant_id, :OLD.tenant_id), 'order_item',
                           NVL(:NEW.order_id, :OLD.order_id) || ':' || NVL(:NEW.product_id, :OLD.product_id),
                           CASE WHEN INSERTING THEN 'INSERT' WHEN UPDATING THEN 'UPDATE' ELSE 'DELETE' END,
                           v_old, v_new);
    END IF;
    g_ids(NVL(:NEW.order_id, :OLD.order_id)) := 1;
    IF UPDATING AND :OLD.order_id <> :NEW.order_id THEN
      g_ids(:OLD.order_id) := 1;
    END IF;
  END AFTER EACH ROW;

  AFTER STATEMENT IS
    i PLS_INTEGER;
  BEGIN
    i := g_ids.FIRST;
    WHILE i IS NOT NULL LOOP
      UPDATE orders
         SET total_amount = (SELECT NVL(SUM(ROUND(quantity * unit_price, 2)), 0)
                               FROM order_items WHERE order_id = i),
             updated_at = SYS_EXTRACT_UTC(SYSTIMESTAMP)
       WHERE order_id = i;
      i := g_ids.NEXT(i);
    END LOOP;
    g_ids.DELETE;
  END AFTER STATEMENT;
END trg_order_items;
/

CREATE OR REPLACE TRIGGER trg_audit_payments
AFTER INSERT OR UPDATE OR DELETE ON payments
FOR EACH ROW
DECLARE
  v_old CLOB;
  v_new CLOB;
BEGIN
  IF UPDATING OR DELETING THEN
    SELECT JSON_OBJECT('payment_id' VALUE :OLD.payment_id, 'order_id' VALUE :OLD.order_id,
                       'amount' VALUE :OLD.amount, 'method' VALUE :OLD.method,
                       'status' VALUE :OLD.status, 'reference' VALUE :OLD.reference RETURNING CLOB)
      INTO v_old FROM dual;
  END IF;
  IF INSERTING OR UPDATING THEN
    SELECT JSON_OBJECT('payment_id' VALUE :NEW.payment_id, 'order_id' VALUE :NEW.order_id,
                       'amount' VALUE :NEW.amount, 'method' VALUE :NEW.method,
                       'status' VALUE :NEW.status, 'reference' VALUE :NEW.reference RETURNING CLOB)
      INTO v_new FROM dual;
  END IF;
  IF UPDATING AND DBMS_LOB.COMPARE(v_old, v_new) = 0 THEN
    RETURN;
  END IF;
  audit_pkg.log_change(NVL(:NEW.tenant_id, :OLD.tenant_id), 'payment',
                       TO_CHAR(NVL(:NEW.payment_id, :OLD.payment_id)),
                       CASE WHEN INSERTING THEN 'INSERT' WHEN UPDATING THEN 'UPDATE' ELSE 'DELETE' END,
                       v_old, v_new);
END;
/
