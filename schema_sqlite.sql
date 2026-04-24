-- Core Tables
CREATE TABLE IF NOT EXISTS customers (
  customer_id INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT NOT NULL,
  email       TEXT UNIQUE NOT NULL,
  created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS products (
  product_id  INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT NOT NULL,
  price       REAL NOT NULL CHECK (price >= 0),
  active_flag TEXT DEFAULT 'Y' CHECK (active_flag IN ('Y','N')),
  created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS orders (
  order_id     INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_id  INTEGER NOT NULL REFERENCES customers(customer_id),
  order_date   DATE DEFAULT CURRENT_DATE,
  status       TEXT DEFAULT 'CREATED' CHECK (status IN ('CREATED','PAID','SHIPPED','CANCELLED','REFUNDED')),
  total_amount REAL DEFAULT 0 CHECK (total_amount >= 0)
);

CREATE TABLE IF NOT EXISTS order_items (
  order_id   INTEGER NOT NULL REFERENCES orders(order_id),
  product_id INTEGER NOT NULL REFERENCES products(product_id),
  quantity   REAL NOT NULL CHECK (quantity > 0),
  unit_price REAL NOT NULL CHECK (unit_price >= 0),
  PRIMARY KEY (order_id, product_id)
);

CREATE TABLE IF NOT EXISTS payments (
  payment_id   INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id     INTEGER NOT NULL REFERENCES orders(order_id),
  amount       REAL NOT NULL CHECK (amount > 0),
  payment_date DATE DEFAULT CURRENT_DATE,
  method       TEXT CHECK (method IN ('CARD','CASH','BKASH','NAGAD','BANK')),
  status       TEXT DEFAULT 'CAPTURED' CHECK (status IN ('CAPTURED','VOID','REFUNDED'))
);

-- Audit Tables
CREATE TABLE IF NOT EXISTS audit_customers (
  audit_id       INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_id    INTEGER,
  operation      TEXT,
  old_name       TEXT, new_name TEXT,
  old_email      TEXT, new_email TEXT,
  actor          TEXT DEFAULT 'app_user',
  operation_time DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_products (
  audit_id       INTEGER PRIMARY KEY AUTOINCREMENT,
  product_id     INTEGER,
  operation      TEXT,
  old_name       TEXT, new_name TEXT,
  old_price      REAL, new_price REAL,
  old_active     TEXT, new_active TEXT,
  actor          TEXT DEFAULT 'app_user',
  operation_time DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_orders (
  audit_id       INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id       INTEGER,
  operation      TEXT,
  old_status     TEXT, new_status TEXT,
  old_total      REAL, new_total REAL,
  actor          TEXT DEFAULT 'app_user',
  operation_time DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_order_items (
  audit_id       INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id       INTEGER,
  product_id     INTEGER,
  operation      TEXT,
  old_quantity   REAL, new_quantity REAL,
  old_price      REAL, new_price REAL,
  actor          TEXT DEFAULT 'app_user',
  operation_time DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_payments (
  audit_id       INTEGER PRIMARY KEY AUTOINCREMENT,
  payment_id     INTEGER,
  order_id       INTEGER,
  operation      TEXT,
  old_status     TEXT, new_status TEXT,
  old_amount     REAL, new_amount REAL,
  actor          TEXT DEFAULT 'app_user',
  operation_time DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Triggers: Customers
CREATE TRIGGER IF NOT EXISTS trg_audit_customers_insert
AFTER INSERT ON customers FOR EACH ROW
BEGIN
  INSERT INTO audit_customers(customer_id,operation,new_name,new_email)
  VALUES(NEW.customer_id,'INSERT',NEW.name,NEW.email);
END;

CREATE TRIGGER IF NOT EXISTS trg_audit_customers_update
AFTER UPDATE ON customers FOR EACH ROW
BEGIN
  INSERT INTO audit_customers(customer_id,operation,old_name,new_name,old_email,new_email)
  VALUES(OLD.customer_id,'UPDATE',OLD.name,NEW.name,OLD.email,NEW.email);
END;

CREATE TRIGGER IF NOT EXISTS trg_audit_customers_delete
AFTER DELETE ON customers FOR EACH ROW
BEGIN
  INSERT INTO audit_customers(customer_id,operation,old_name,old_email)
  VALUES(OLD.customer_id,'DELETE',OLD.name,OLD.email);
END;

-- Triggers: Products
CREATE TRIGGER IF NOT EXISTS trg_audit_products_insert
AFTER INSERT ON products FOR EACH ROW
BEGIN
  INSERT INTO audit_products(product_id,operation,new_name,new_price,new_active)
  VALUES(NEW.product_id,'INSERT',NEW.name,NEW.price,NEW.active_flag);
END;

CREATE TRIGGER IF NOT EXISTS trg_audit_products_update
AFTER UPDATE ON products FOR EACH ROW
BEGIN
  INSERT INTO audit_products(product_id,operation,old_name,new_name,old_price,new_price,old_active,new_active)
  VALUES(OLD.product_id,'UPDATE',OLD.name,NEW.name,OLD.price,NEW.price,OLD.active_flag,NEW.active_flag);
END;

CREATE TRIGGER IF NOT EXISTS trg_audit_products_delete
AFTER DELETE ON products FOR EACH ROW
BEGIN
  INSERT INTO audit_products(product_id,operation,old_name,old_price,old_active)
  VALUES(OLD.product_id,'DELETE',OLD.name,OLD.price,OLD.active_flag);
END;

-- Triggers: Orders
CREATE TRIGGER IF NOT EXISTS trg_audit_orders_insert
AFTER INSERT ON orders FOR EACH ROW
BEGIN
  INSERT INTO audit_orders(order_id,operation,new_status,new_total)
  VALUES(NEW.order_id,'INSERT',NEW.status,NEW.total_amount);
END;

CREATE TRIGGER IF NOT EXISTS trg_audit_orders_update
AFTER UPDATE ON orders FOR EACH ROW
BEGIN
  INSERT INTO audit_orders(order_id,operation,old_status,new_status,old_total,new_total)
  VALUES(OLD.order_id,'UPDATE',OLD.status,NEW.status,OLD.total_amount,NEW.total_amount);
END;

CREATE TRIGGER IF NOT EXISTS trg_audit_orders_delete
AFTER DELETE ON orders FOR EACH ROW
BEGIN
  INSERT INTO audit_orders(order_id,operation,old_status,old_total)
  VALUES(OLD.order_id,'DELETE',OLD.status,OLD.total_amount);
END;

-- Triggers: Order Items
CREATE TRIGGER IF NOT EXISTS trg_audit_order_items_insert
AFTER INSERT ON order_items FOR EACH ROW
BEGIN
  INSERT INTO audit_order_items(order_id,product_id,operation,new_quantity,new_price)
  VALUES(NEW.order_id,NEW.product_id,'INSERT',NEW.quantity,NEW.unit_price);
  UPDATE orders SET total_amount=(
    SELECT COALESCE(SUM(quantity*unit_price),0) FROM order_items WHERE order_id=NEW.order_id
  ) WHERE order_id=NEW.order_id;
END;

CREATE TRIGGER IF NOT EXISTS trg_audit_order_items_update
AFTER UPDATE ON order_items FOR EACH ROW
BEGIN
  INSERT INTO audit_order_items(order_id,product_id,operation,old_quantity,new_quantity,old_price,new_price)
  VALUES(OLD.order_id,OLD.product_id,'UPDATE',OLD.quantity,NEW.quantity,OLD.unit_price,NEW.unit_price);
  UPDATE orders SET total_amount=(
    SELECT COALESCE(SUM(quantity*unit_price),0) FROM order_items WHERE order_id=NEW.order_id
  ) WHERE order_id=NEW.order_id;
END;

CREATE TRIGGER IF NOT EXISTS trg_audit_order_items_delete
AFTER DELETE ON order_items FOR EACH ROW
BEGIN
  INSERT INTO audit_order_items(order_id,product_id,operation,old_quantity,old_price)
  VALUES(OLD.order_id,OLD.product_id,'DELETE',OLD.quantity,OLD.unit_price);
  UPDATE orders SET total_amount=(
    SELECT COALESCE(SUM(quantity*unit_price),0) FROM order_items WHERE order_id=OLD.order_id
  ) WHERE order_id=OLD.order_id;
END;

-- Triggers: Payments
CREATE TRIGGER IF NOT EXISTS trg_audit_payments_insert
AFTER INSERT ON payments FOR EACH ROW
BEGIN
  INSERT INTO audit_payments(payment_id,order_id,operation,new_status,new_amount)
  VALUES(NEW.payment_id,NEW.order_id,'INSERT',NEW.status,NEW.amount);
END;

CREATE TRIGGER IF NOT EXISTS trg_audit_payments_update
AFTER UPDATE ON payments FOR EACH ROW
BEGIN
  INSERT INTO audit_payments(payment_id,order_id,operation,old_status,new_status,old_amount,new_amount)
  VALUES(OLD.payment_id,OLD.order_id,'UPDATE',OLD.status,NEW.status,OLD.amount,NEW.amount);
END;

CREATE TRIGGER IF NOT EXISTS trg_audit_payments_delete
AFTER DELETE ON payments FOR EACH ROW
BEGIN
  INSERT INTO audit_payments(payment_id,order_id,operation,old_status,old_amount)
  VALUES(OLD.payment_id,OLD.order_id,'DELETE',OLD.status,OLD.amount);
END;

-- Sample Data
INSERT INTO customers(name,email) VALUES('Rafi','rafi@email.com');
INSERT INTO customers(name,email) VALUES('Siyam','siyam@example.com');

INSERT INTO products(name,price) VALUES('Laptop',1000);
INSERT INTO products(name,price) VALUES('Tablet',500);
INSERT INTO products(name,price) VALUES('Headphones',150);
INSERT INTO products(name,price) VALUES('Buds',250);

UPDATE products SET price=1099.99 WHERE name='Laptop';
UPDATE products SET active_flag='N' WHERE name='Tablet';

INSERT INTO orders(customer_id,status) VALUES(1,'CREATED');
INSERT INTO order_items(order_id,product_id,quantity,unit_price) VALUES(1,1,1,1099.99);
INSERT INTO order_items(order_id,product_id,quantity,unit_price) VALUES(1,3,2,150);
UPDATE order_items SET quantity=3 WHERE order_id=1 AND product_id=3;
INSERT INTO payments(order_id,amount,method,status) VALUES(1,1549.99,'CARD','CAPTURED');
UPDATE orders SET status='PAID' WHERE order_id=1;
UPDATE orders SET status='SHIPPED' WHERE order_id=1;
