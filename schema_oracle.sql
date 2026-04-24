BEGIN
  FOR t IN (SELECT table_name FROM user_tables WHERE table_name IN (
    'AUDIT_CUSTOMERS','AUDIT_PRODUCTS','AUDIT_ORDERS','AUDIT_ORDER_ITEMS','AUDIT_PAYMENTS',
    'ORDER_ITEMS','PAYMENTS','ORDERS','PRODUCTS','CUSTOMERS')) LOOP
    EXECUTE IMMEDIATE 'DROP TABLE ' || t.table_name || ' CASCADE CONSTRAINTS';
  END LOOP;
  FOR s IN (SELECT sequence_name FROM user_sequences WHERE sequence_name IN (
    'SEQ_CUSTOMERS','SEQ_PRODUCTS','SEQ_ORDERS','SEQ_ORDER_ITEMS','SEQ_PAYMENTS',
    'SEQ_AUDIT_CUSTOMERS','SEQ_AUDIT_PRODUCTS','SEQ_AUDIT_ORDERS',
    'SEQ_AUDIT_ORDER_ITEMS','SEQ_AUDIT_PAYMENTS')) LOOP
    EXECUTE IMMEDIATE 'DROP SEQUENCE ' || s.sequence_name;
  END LOOP;
END;
/

-- Sequences for PK generation
CREATE SEQUENCE seq_customers     START WITH 1 INCREMENT BY 1;
CREATE SEQUENCE seq_products      START WITH 1 INCREMENT BY 1;
CREATE SEQUENCE seq_orders        START WITH 1 INCREMENT BY 1;
CREATE SEQUENCE seq_order_items   START WITH 1 INCREMENT BY 1;
CREATE SEQUENCE seq_payments      START WITH 1 INCREMENT BY 1;

CREATE SEQUENCE seq_audit_customers   START WITH 1     INCREMENT BY 1;
CREATE SEQUENCE seq_audit_products    START WITH 10001 INCREMENT BY 1;
CREATE SEQUENCE seq_audit_orders      START WITH 20001 INCREMENT BY 1;
CREATE SEQUENCE seq_audit_order_items START WITH 30001 INCREMENT BY 1;
CREATE SEQUENCE seq_audit_payments    START WITH 40001 INCREMENT BY 1;

-- Core Tables

CREATE TABLE customers (
  customer_id NUMBER PRIMARY KEY,
  name        VARCHAR2(100) NOT NULL,
  email       VARCHAR2(150) UNIQUE NOT NULL,
  created_at  TIMESTAMP DEFAULT SYSTIMESTAMP
);

CREATE TABLE products (
  product_id  NUMBER PRIMARY KEY,
  name        VARCHAR2(120) NOT NULL,
  price       NUMBER(10,2) NOT NULL CHECK (price >= 0),
  active_flag CHAR(1) DEFAULT 'Y' CHECK (active_flag IN ('Y','N')),
  created_at  TIMESTAMP DEFAULT SYSTIMESTAMP
);

CREATE TABLE orders (
  order_id     NUMBER PRIMARY KEY,
  customer_id  NUMBER NOT NULL REFERENCES customers(customer_id),
  order_date   DATE DEFAULT SYSDATE,
  status       VARCHAR2(20) DEFAULT 'CREATED'
               CHECK (status IN ('CREATED','PAID','SHIPPED','CANCELLED','REFUNDED')),
  total_amount NUMBER(12,2) DEFAULT 0 CHECK (total_amount >= 0)
);

CREATE TABLE order_items (
  order_id   NUMBER NOT NULL REFERENCES orders(order_id) ON DELETE CASCADE,
  product_id NUMBER NOT NULL REFERENCES products(product_id),
  quantity   NUMBER(10,2) NOT NULL CHECK (quantity > 0),
  unit_price NUMBER(10,2) NOT NULL CHECK (unit_price >= 0),
  line_total NUMBER(12,2) GENERATED ALWAYS AS (quantity * unit_price) VIRTUAL,
  CONSTRAINT pk_order_items PRIMARY KEY (order_id, product_id)
);

CREATE TABLE payments (
  payment_id   NUMBER PRIMARY KEY,
  order_id     NUMBER NOT NULL REFERENCES orders(order_id),
  amount       NUMBER(12,2) NOT NULL CHECK (amount > 0),
  payment_date DATE DEFAULT SYSDATE,
  method       VARCHAR2(20) CHECK (method IN ('CARD','CASH','BKASH','NAGAD','BANK')),
  status       VARCHAR2(20) DEFAULT 'CAPTURED'
               CHECK (status IN ('CAPTURED','VOID','REFUNDED'))
);

CREATE INDEX ix_order_items_order ON order_items(order_id);

-- Audit Tables

CREATE TABLE audit_customers (
  audit_id       NUMBER PRIMARY KEY,
  customer_id    NUMBER,
  operation      VARCHAR2(10),
  old_name       VARCHAR2(100),
  new_name       VARCHAR2(100),
  old_email      VARCHAR2(150),
  new_email      VARCHAR2(150),
  actor          VARCHAR2(128),
  operation_time TIMESTAMP DEFAULT SYSTIMESTAMP
);

CREATE TABLE audit_products (
  audit_id       NUMBER PRIMARY KEY,
  product_id     NUMBER,
  operation      VARCHAR2(10),
  old_name       VARCHAR2(120),
  new_name       VARCHAR2(120),
  old_price      NUMBER(10,2),
  new_price      NUMBER(10,2),
  old_active     CHAR(1),
  new_active     CHAR(1),
  actor          VARCHAR2(128),
  operation_time TIMESTAMP DEFAULT SYSTIMESTAMP
);

CREATE TABLE audit_orders (
  audit_id       NUMBER PRIMARY KEY,
  order_id       NUMBER,
  operation      VARCHAR2(10),
  old_status     VARCHAR2(20),
  new_status     VARCHAR2(20),
  old_total      NUMBER(12,2),
  new_total      NUMBER(12,2),
  actor          VARCHAR2(128),
  operation_time TIMESTAMP DEFAULT SYSTIMESTAMP
);

CREATE TABLE audit_order_items (
  audit_id       NUMBER PRIMARY KEY,
  order_id       NUMBER,
  product_id     NUMBER,
  operation      VARCHAR2(10),
  old_quantity   NUMBER(10,2),
  new_quantity   NUMBER(10,2),
  old_price      NUMBER(10,2),
  new_price      NUMBER(10,2),
  actor          VARCHAR2(128),
  operation_time TIMESTAMP DEFAULT SYSTIMESTAMP
);

CREATE TABLE audit_payments (
  audit_id       NUMBER PRIMARY KEY,
  payment_id     NUMBER,
  order_id       NUMBER,
  operation      VARCHAR2(10),
  old_status     VARCHAR2(20),
  new_status     VARCHAR2(20),
  old_amount     NUMBER(12,2),
  new_amount     NUMBER(12,2),
  actor          VARCHAR2(128),
  operation_time TIMESTAMP DEFAULT SYSTIMESTAMP
);

-- Triggers for auto PK on core tables

CREATE OR REPLACE TRIGGER trg_customers_pk
BEFORE INSERT ON customers FOR EACH ROW
BEGIN
  IF :NEW.customer_id IS NULL THEN
    :NEW.customer_id := seq_customers.NEXTVAL;
  END IF;
END;
/

CREATE OR REPLACE TRIGGER trg_products_pk
BEFORE INSERT ON products FOR EACH ROW
BEGIN
  IF :NEW.product_id IS NULL THEN
    :NEW.product_id := seq_products.NEXTVAL;
  END IF;
END;
/

CREATE OR REPLACE TRIGGER trg_orders_pk
BEFORE INSERT ON orders FOR EACH ROW
BEGIN
  IF :NEW.order_id IS NULL THEN
    :NEW.order_id := seq_orders.NEXTVAL;
  END IF;
END;
/

CREATE OR REPLACE TRIGGER trg_payments_pk
BEFORE INSERT ON payments FOR EACH ROW
BEGIN
  IF :NEW.payment_id IS NULL THEN
    :NEW.payment_id := seq_payments.NEXTVAL;
  END IF;
END;
/

-- Helper: recompute order total
CREATE OR REPLACE PROCEDURE recompute_order_total(p_order_id IN NUMBER) AS
BEGIN
  UPDATE orders SET total_amount = (
    SELECT NVL(SUM(quantity * unit_price), 0)
    FROM order_items WHERE order_id = p_order_id
  ) WHERE order_id = p_order_id;
END;
/

-- Audit Triggers

CREATE OR REPLACE TRIGGER trg_audit_customers
AFTER INSERT OR UPDATE OR DELETE ON customers
FOR EACH ROW
BEGIN
  IF INSERTING THEN
    INSERT INTO audit_customers(audit_id,customer_id,operation,new_name,new_email,actor)
    VALUES(seq_audit_customers.NEXTVAL,:NEW.customer_id,'INSERT',:NEW.name,:NEW.email,USER);
  ELSIF UPDATING THEN
    INSERT INTO audit_customers(audit_id,customer_id,operation,old_name,new_name,old_email,new_email,actor)
    VALUES(seq_audit_customers.NEXTVAL,:OLD.customer_id,'UPDATE',:OLD.name,:NEW.name,:OLD.email,:NEW.email,USER);
  ELSIF DELETING THEN
    INSERT INTO audit_customers(audit_id,customer_id,operation,old_name,old_email,actor)
    VALUES(seq_audit_customers.NEXTVAL,:OLD.customer_id,'DELETE',:OLD.name,:OLD.email,USER);
  END IF;
END;
/

CREATE OR REPLACE TRIGGER trg_audit_products
AFTER INSERT OR UPDATE OR DELETE ON products
FOR EACH ROW
BEGIN
  IF INSERTING THEN
    INSERT INTO audit_products(audit_id,product_id,operation,new_name,new_price,new_active,actor)
    VALUES(seq_audit_products.NEXTVAL,:NEW.product_id,'INSERT',:NEW.name,:NEW.price,:NEW.active_flag,USER);
  ELSIF UPDATING THEN
    INSERT INTO audit_products(audit_id,product_id,operation,old_name,new_name,old_price,new_price,old_active,new_active,actor)
    VALUES(seq_audit_products.NEXTVAL,:OLD.product_id,'UPDATE',:OLD.name,:NEW.name,:OLD.price,:NEW.price,:OLD.active_flag,:NEW.active_flag,USER);
  ELSIF DELETING THEN
    INSERT INTO audit_products(audit_id,product_id,operation,old_name,old_price,old_active,actor)
    VALUES(seq_audit_products.NEXTVAL,:OLD.product_id,'DELETE',:OLD.name,:OLD.price,:OLD.active_flag,USER);
  END IF;
END;
/

CREATE OR REPLACE TRIGGER trg_audit_orders
AFTER INSERT OR UPDATE OR DELETE ON orders
FOR EACH ROW
BEGIN
  IF INSERTING THEN
    INSERT INTO audit_orders(audit_id,order_id,operation,new_status,new_total,actor)
    VALUES(seq_audit_orders.NEXTVAL,:NEW.order_id,'INSERT',:NEW.status,:NEW.total_amount,USER);
  ELSIF UPDATING THEN
    INSERT INTO audit_orders(audit_id,order_id,operation,old_status,new_status,old_total,new_total,actor)
    VALUES(seq_audit_orders.NEXTVAL,:OLD.order_id,'UPDATE',:OLD.status,:NEW.status,:OLD.total_amount,:NEW.total_amount,USER);
  ELSIF DELETING THEN
    INSERT INTO audit_orders(audit_id,order_id,operation,old_status,old_total,actor)
    VALUES(seq_audit_orders.NEXTVAL,:OLD.order_id,'DELETE',:OLD.status,:OLD.total_amount,USER);
  END IF;
END;
/

CREATE OR REPLACE TRIGGER trg_audit_order_items
AFTER INSERT OR UPDATE OR DELETE ON order_items
FOR EACH ROW
BEGIN
  IF INSERTING THEN
    INSERT INTO audit_order_items(audit_id,order_id,product_id,operation,new_quantity,new_price,actor)
    VALUES(seq_audit_order_items.NEXTVAL,:NEW.order_id,:NEW.product_id,'INSERT',:NEW.quantity,:NEW.unit_price,USER);
    recompute_order_total(:NEW.order_id);
  ELSIF UPDATING THEN
    INSERT INTO audit_order_items(audit_id,order_id,product_id,operation,old_quantity,new_quantity,old_price,new_price,actor)
    VALUES(seq_audit_order_items.NEXTVAL,:OLD.order_id,:OLD.product_id,'UPDATE',:OLD.quantity,:NEW.quantity,:OLD.unit_price,:NEW.unit_price,USER);
    recompute_order_total(:NEW.order_id);
  ELSIF DELETING THEN
    INSERT INTO audit_order_items(audit_id,order_id,product_id,operation,old_quantity,old_price,actor)
    VALUES(seq_audit_order_items.NEXTVAL,:OLD.order_id,:OLD.product_id,'DELETE',:OLD.quantity,:OLD.unit_price,USER);
    recompute_order_total(:OLD.order_id);
  END IF;
END;
/

CREATE OR REPLACE TRIGGER trg_audit_payments
AFTER INSERT OR UPDATE OR DELETE ON payments
FOR EACH ROW
BEGIN
  IF INSERTING THEN
    INSERT INTO audit_payments(audit_id,payment_id,order_id,operation,new_status,new_amount,actor)
    VALUES(seq_audit_payments.NEXTVAL,:NEW.payment_id,:NEW.order_id,'INSERT',:NEW.status,:NEW.amount,USER);
  ELSIF UPDATING THEN
    INSERT INTO audit_payments(audit_id,payment_id,order_id,operation,old_status,new_status,old_amount,new_amount,actor)
    VALUES(seq_audit_payments.NEXTVAL,:OLD.payment_id,:OLD.order_id,'UPDATE',:OLD.status,:NEW.status,:OLD.amount,:NEW.amount,USER);
  ELSIF DELETING THEN
    INSERT INTO audit_payments(audit_id,payment_id,order_id,operation,old_status,old_amount,actor)
    VALUES(seq_audit_payments.NEXTVAL,:OLD.payment_id,:OLD.order_id,'DELETE',:OLD.status,:OLD.amount,USER);
  END IF;
END;
/

-- Sample Data
INSERT INTO customers(name,email) VALUES('Rafi','rafi@email.com');
INSERT INTO customers(name,email) VALUES('Siyam','siyam@example.com');

INSERT INTO products(name,price) VALUES('Laptop',1000);
INSERT INTO products(name,price) VALUES('Tablet',500);
INSERT INTO products(name,price) VALUES('Headphones',150);
INSERT INTO products(name,price) VALUES('Buds',250);

UPDATE products SET price=1099.99 WHERE name='Laptop';
UPDATE products SET active_flag='N' WHERE name='Tablet';

DECLARE
  v_order_id NUMBER;
BEGIN
  INSERT INTO orders(customer_id,status) VALUES(1,'CREATED') RETURNING order_id INTO v_order_id;
  INSERT INTO order_items(order_id,product_id,quantity,unit_price) VALUES(v_order_id,1,1,1099.99);
  INSERT INTO order_items(order_id,product_id,quantity,unit_price) VALUES(v_order_id,3,2,150);
  UPDATE order_items SET quantity=3 WHERE order_id=v_order_id AND product_id=3;
  INSERT INTO payments(order_id,amount,method,status) VALUES(v_order_id,1549.99,'CARD','CAPTURED');
  recompute_order_total(v_order_id);
  UPDATE orders SET status='PAID' WHERE order_id=v_order_id;
  UPDATE orders SET status='SHIPPED' WHERE order_id=v_order_id;
END;
/

COMMIT;
