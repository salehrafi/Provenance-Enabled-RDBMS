-- 002_audit: transactional outbox, tamper-evident audit log (SHA-256 hash chain per tenant).

-- Transactional outbox: events are written in the same transaction as the change that
-- caused them, so an event is never lost and never published for a rolled-back change.
CREATE TABLE outbox_events (
  event_id       NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id      NUMBER NOT NULL,
  event_type     VARCHAR2(60)  NOT NULL,
  entity         VARCHAR2(30),
  entity_id      VARCHAR2(100),
  payload        CLOB CONSTRAINT ck_outbox_json CHECK (payload IS JSON),
  request_id     VARCHAR2(64),
  created_at     TIMESTAMP(6) DEFAULT SYS_EXTRACT_UTC(SYSTIMESTAMP) NOT NULL,
  dispatched_at  TIMESTAMP(6)
)
/

CREATE INDEX ix_outbox_pending ON outbox_events(tenant_id, dispatched_at, event_id)
/

CREATE OR REPLACE PACKAGE outbox_pkg AUTHID DEFINER AS
  PROCEDURE emit(p_tenant_id  IN NUMBER,
                 p_event_type IN VARCHAR2,
                 p_entity     IN VARCHAR2,
                 p_entity_id  IN VARCHAR2,
                 p_payload    IN CLOB);
END outbox_pkg;
/

CREATE OR REPLACE PACKAGE BODY outbox_pkg AS
  PROCEDURE emit(p_tenant_id  IN NUMBER,
                 p_event_type IN VARCHAR2,
                 p_entity     IN VARCHAR2,
                 p_entity_id  IN VARCHAR2,
                 p_payload    IN CLOB) IS
  BEGIN
    INSERT INTO outbox_events (tenant_id, event_type, entity, entity_id, payload, request_id)
    VALUES (p_tenant_id, p_event_type, p_entity, p_entity_id, p_payload,
            SYS_CONTEXT('PROV_CTX', 'REQUEST_ID'));
  END emit;
END outbox_pkg;
/

CREATE TABLE audit_log (
  audit_id           NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id          NUMBER        NOT NULL,
  chain_seq          NUMBER        NOT NULL,
  entity             VARCHAR2(30)  NOT NULL,
  record_pk          VARCHAR2(100) NOT NULL,
  operation          VARCHAR2(6)   NOT NULL
                     CONSTRAINT ck_audit_op CHECK (operation IN ('INSERT', 'UPDATE', 'DELETE')),
  old_values         CLOB CONSTRAINT ck_audit_old_json CHECK (old_values IS JSON),
  new_values         CLOB CONSTRAINT ck_audit_new_json CHECK (new_values IS JSON),
  actor              VARCHAR2(254) NOT NULL,
  actor_user_id      NUMBER,
  request_id         VARCHAR2(64),
  change_request_id  NUMBER,
  db_user            VARCHAR2(128) NOT NULL,
  changed_at         TIMESTAMP(6)  NOT NULL,
  prev_hash          VARCHAR2(64)  NOT NULL,
  row_hash           VARCHAR2(64)  NOT NULL,
  CONSTRAINT uq_audit_chain UNIQUE (tenant_id, chain_seq)
)
/

CREATE INDEX ix_audit_record ON audit_log(tenant_id, entity, record_pk, changed_at)
/

CREATE INDEX ix_audit_request ON audit_log(tenant_id, request_id)
/

CREATE INDEX ix_audit_time ON audit_log(tenant_id, changed_at)
/

-- One row per tenant holding the tip of the hash chain. Writers lock it (SELECT ... FOR
-- UPDATE), which serialises audit writes per tenant and keeps chain_seq gap-free.
CREATE TABLE audit_chain_head (
  tenant_id  NUMBER PRIMARY KEY,
  last_seq   NUMBER       NOT NULL,
  last_hash  VARCHAR2(64) NOT NULL
)
/

CREATE OR REPLACE PACKAGE audit_pkg AUTHID DEFINER AS
  c_genesis CONSTANT VARCHAR2(64) := RPAD('0', 64, '0');

  FUNCTION compute_hash(p_prev      IN VARCHAR2,
                        p_seq       IN NUMBER,
                        p_tenant    IN NUMBER,
                        p_entity    IN VARCHAR2,
                        p_pk        IN VARCHAR2,
                        p_op        IN VARCHAR2,
                        p_actor     IN VARCHAR2,
                        p_actor_id  IN NUMBER,
                        p_req       IN VARCHAR2,
                        p_cr        IN NUMBER,
                        p_db_user   IN VARCHAR2,
                        p_ts        IN TIMESTAMP,
                        p_old       IN CLOB,
                        p_new       IN CLOB) RETURN VARCHAR2;

  PROCEDURE log_change(p_tenant IN NUMBER,
                       p_entity IN VARCHAR2,
                       p_pk     IN VARCHAR2,
                       p_op     IN VARCHAR2,
                       p_old    IN CLOB,
                       p_new    IN CLOB);
END audit_pkg;
/

CREATE OR REPLACE PACKAGE BODY audit_pkg AS
  FUNCTION compute_hash(p_prev      IN VARCHAR2,
                        p_seq       IN NUMBER,
                        p_tenant    IN NUMBER,
                        p_entity    IN VARCHAR2,
                        p_pk        IN VARCHAR2,
                        p_op        IN VARCHAR2,
                        p_actor     IN VARCHAR2,
                        p_actor_id  IN NUMBER,
                        p_req       IN VARCHAR2,
                        p_cr        IN NUMBER,
                        p_db_user   IN VARCHAR2,
                        p_ts        IN TIMESTAMP,
                        p_old       IN CLOB,
                        p_new       IN CLOB) RETURN VARCHAR2 IS
    v CLOB;
  BEGIN
    v := TO_CLOB(p_prev) || '|' || TO_CHAR(p_seq) || '|' || TO_CHAR(p_tenant) || '|' ||
         p_entity || '|' || p_pk || '|' || p_op || '|' || p_actor || '|' ||
         TO_CHAR(p_actor_id) || '|' || p_req || '|' || TO_CHAR(p_cr) || '|' || p_db_user || '|' ||
         TO_CHAR(p_ts, 'YYYY-MM-DD"T"HH24:MI:SS.FF6') || '|';
    IF p_old IS NOT NULL THEN
      DBMS_LOB.APPEND(v, p_old);
    END IF;
    DBMS_LOB.APPEND(v, TO_CLOB('|'));
    IF p_new IS NOT NULL THEN
      DBMS_LOB.APPEND(v, p_new);
    END IF;
    RETURN LOWER(RAWTOHEX(DBMS_CRYPTO.HASH(v, DBMS_CRYPTO.HASH_SH256)));
  END compute_hash;

  PROCEDURE log_change(p_tenant IN NUMBER,
                       p_entity IN VARCHAR2,
                       p_pk     IN VARCHAR2,
                       p_op     IN VARCHAR2,
                       p_old    IN CLOB,
                       p_new    IN CLOB) IS
    v_seq       NUMBER;
    v_prev      VARCHAR2(64);
    v_hash      VARCHAR2(64);
    v_audit_id  NUMBER;
    v_ts        TIMESTAMP(6);
    v_payload   CLOB;
    v_db_user   VARCHAR2(128) := SYS_CONTEXT('USERENV', 'SESSION_USER');
    v_actor     VARCHAR2(254) := NVL(SYS_CONTEXT('PROV_CTX', 'USERNAME'),
                                     'db:' || SYS_CONTEXT('USERENV', 'SESSION_USER'));
    v_actor_id  NUMBER        := TO_NUMBER(SYS_CONTEXT('PROV_CTX', 'USER_ID'));
    v_req       VARCHAR2(64)  := SYS_CONTEXT('PROV_CTX', 'REQUEST_ID');
    v_cr        NUMBER        := TO_NUMBER(SYS_CONTEXT('PROV_CTX', 'CHANGE_REQUEST_ID'));
    v_verb      VARCHAR2(10);
  BEGIN
    BEGIN
      SELECT last_seq, last_hash INTO v_seq, v_prev
        FROM audit_chain_head WHERE tenant_id = p_tenant FOR UPDATE;
    EXCEPTION
      WHEN NO_DATA_FOUND THEN
        BEGIN
          INSERT INTO audit_chain_head (tenant_id, last_seq, last_hash)
          VALUES (p_tenant, 0, c_genesis);
        EXCEPTION
          WHEN DUP_VAL_ON_INDEX THEN NULL;
        END;
        SELECT last_seq, last_hash INTO v_seq, v_prev
          FROM audit_chain_head WHERE tenant_id = p_tenant FOR UPDATE;
    END;

    v_seq := v_seq + 1;
    SELECT SYS_EXTRACT_UTC(SYSTIMESTAMP) INTO v_ts FROM dual;
    v_hash := compute_hash(v_prev, v_seq, p_tenant, p_entity, p_pk, p_op, v_actor, v_actor_id,
                           v_req, v_cr, v_db_user, v_ts, p_old, p_new);

    INSERT INTO audit_log (tenant_id, chain_seq, entity, record_pk, operation, old_values,
                           new_values, actor, actor_user_id, request_id, change_request_id,
                           db_user, changed_at, prev_hash, row_hash)
    VALUES (p_tenant, v_seq, p_entity, p_pk, p_op, p_old, p_new, v_actor, v_actor_id, v_req,
            v_cr, v_db_user, v_ts, v_prev, v_hash)
    RETURNING audit_id INTO v_audit_id;

    UPDATE audit_chain_head SET last_seq = v_seq, last_hash = v_hash WHERE tenant_id = p_tenant;

    v_verb := CASE p_op WHEN 'INSERT' THEN 'created' WHEN 'UPDATE' THEN 'updated' ELSE 'deleted' END;
    SELECT JSON_OBJECT('audit_id'  VALUE v_audit_id,
                       'chain_seq' VALUE v_seq,
                       'entity'    VALUE p_entity,
                       'record_pk' VALUE p_pk,
                       'operation' VALUE p_op,
                       'actor'     VALUE v_actor,
                       'old'       VALUE p_old FORMAT JSON,
                       'new'       VALUE p_new FORMAT JSON
                       RETURNING CLOB)
      INTO v_payload FROM dual;
    outbox_pkg.emit(p_tenant, p_entity || '.' || v_verb, p_entity, p_pk, v_payload);
  END log_change;
END audit_pkg;
/

-- Exposed to the API: verification only. PROV_APP cannot call audit_pkg.log_change, so the
-- API cannot forge audit entries; they are only ever written by triggers.
CREATE OR REPLACE PACKAGE audit_api_pkg AUTHID DEFINER AS
  PROCEDURE verify_chain(p_ok            OUT NUMBER,
                         p_checked       OUT NUMBER,
                         p_first_bad_seq OUT NUMBER,
                         p_reason        OUT VARCHAR2);
END audit_api_pkg;
/

CREATE OR REPLACE PACKAGE BODY audit_api_pkg AS
  PROCEDURE verify_chain(p_ok            OUT NUMBER,
                         p_checked       OUT NUMBER,
                         p_first_bad_seq OUT NUMBER,
                         p_reason        OUT VARCHAR2) IS
    v_tenant    NUMBER := TO_NUMBER(SYS_CONTEXT('PROV_CTX', 'TENANT_ID'));
    v_prev      VARCHAR2(64) := audit_pkg.c_genesis;
    v_expected  NUMBER := 1;
    v_calc      VARCHAR2(64);
    v_head_seq  NUMBER;
    v_head_hash VARCHAR2(64);
  BEGIN
    p_ok := 1;
    p_checked := 0;
    p_first_bad_seq := NULL;
    p_reason := NULL;

    -- Read the head first, then only rows up to it, so concurrent writers cannot cause a
    -- false "tampered" result.
    BEGIN
      SELECT last_seq, last_hash INTO v_head_seq, v_head_hash
        FROM audit_chain_head WHERE tenant_id = v_tenant;
    EXCEPTION
      WHEN NO_DATA_FOUND THEN
        v_head_seq := 0;
        v_head_hash := audit_pkg.c_genesis;
    END;

    FOR r IN (SELECT * FROM audit_log
               WHERE tenant_id = v_tenant AND chain_seq <= v_head_seq
               ORDER BY chain_seq) LOOP
      p_checked := p_checked + 1;
      IF r.chain_seq <> v_expected THEN
        p_ok := 0;
        p_first_bad_seq := v_expected;
        p_reason := 'Record missing: expected chain_seq ' || v_expected || ' but found ' || r.chain_seq;
        RETURN;
      END IF;
      IF r.prev_hash <> v_prev THEN
        p_ok := 0;
        p_first_bad_seq := r.chain_seq;
        p_reason := 'prev_hash does not match the hash of the previous record';
        RETURN;
      END IF;
      v_calc := audit_pkg.compute_hash(r.prev_hash, r.chain_seq, r.tenant_id, r.entity, r.record_pk,
                                       r.operation, r.actor, r.actor_user_id, r.request_id,
                                       r.change_request_id, r.db_user, r.changed_at,
                                       r.old_values, r.new_values);
      IF v_calc <> r.row_hash THEN
        p_ok := 0;
        p_first_bad_seq := r.chain_seq;
        p_reason := 'Record content was modified after it was written (hash mismatch)';
        RETURN;
      END IF;
      v_prev := r.row_hash;
      v_expected := v_expected + 1;
    END LOOP;

    IF v_expected - 1 <> v_head_seq OR v_prev <> v_head_hash THEN
      p_ok := 0;
      p_first_bad_seq := v_expected;
      p_reason := 'Chain head mismatch: records were removed from the end of the log';
    END IF;
  END verify_chain;
END audit_api_pkg;
/

-- Defence in depth: even the schema owner gets an error on UPDATE/DELETE. (Someone with DBA
-- rights could disable this trigger, which is exactly what the hash chain detects.)
CREATE OR REPLACE TRIGGER trg_audit_log_immutable
BEFORE UPDATE OR DELETE ON audit_log
BEGIN
  RAISE_APPLICATION_ERROR(-20901, 'audit_log is append-only');
END;
/
