-- Bootstrap: run as SYSDBA (scripts/setup_db.py pipes this into sqlplus via stdin).
-- Placeholders {{PDB}}, {{OWNER_PASSWORD}}, {{APP_PASSWORD}} are filled in by the script,
-- so passwords never appear on a command line.
--
-- PROV_OWNER : owns tables, triggers, packages, VPD policies.
-- PROV_APP   : runtime user for the API. Gets DML on business tables but only SELECT on
--              audit_log, so the API itself can never rewrite history.
WHENEVER SQLERROR EXIT SQL.SQLCODE
SET SERVEROUTPUT ON FEEDBACK OFF
ALTER SESSION SET CONTAINER = {{PDB}};

DECLARE
  PROCEDURE ensure_user(p_user VARCHAR2, p_pwd VARCHAR2) IS
    n NUMBER;
  BEGIN
    SELECT COUNT(*) INTO n FROM dba_users WHERE username = p_user;
    IF n = 0 THEN
      EXECUTE IMMEDIATE 'CREATE USER ' || p_user || ' IDENTIFIED BY "' || p_pwd ||
                        '" DEFAULT TABLESPACE users QUOTA UNLIMITED ON users';
      DBMS_OUTPUT.PUT_LINE('created user ' || p_user);
    ELSE
      EXECUTE IMMEDIATE 'ALTER USER ' || p_user || ' IDENTIFIED BY "' || p_pwd || '" ACCOUNT UNLOCK';
      DBMS_OUTPUT.PUT_LINE('user ' || p_user || ' exists, password reset');
    END IF;
  END;
BEGIN
  ensure_user('PROV_OWNER', '{{OWNER_PASSWORD}}');
  ensure_user('PROV_APP',   '{{APP_PASSWORD}}');
END;
/

GRANT CREATE SESSION, CREATE TABLE, CREATE SEQUENCE, CREATE PROCEDURE,
      CREATE TRIGGER, CREATE VIEW, CREATE JOB TO prov_owner;
GRANT EXECUTE ON SYS.DBMS_CRYPTO TO prov_owner;
GRANT EXECUTE ON SYS.DBMS_RLS TO prov_owner;
GRANT CREATE SESSION TO prov_app;

-- Session-local application context; only prov_owner.ctx_pkg may write to it.
CREATE OR REPLACE CONTEXT prov_ctx USING prov_owner.ctx_pkg;

EXIT
