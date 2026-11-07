-- Teardown: removes everything this project created. Run as SYSDBA via scripts/teardown_db.py.
WHENEVER SQLERROR EXIT SQL.SQLCODE
SET SERVEROUTPUT ON FEEDBACK OFF
ALTER SESSION SET CONTAINER = {{PDB}};

DECLARE
  n NUMBER;
BEGIN
  FOR u IN (SELECT username FROM dba_users WHERE username IN ('PROV_APP', 'PROV_OWNER')) LOOP
    -- kill lingering sessions so DROP USER does not fail with ORA-01940
    FOR s IN (SELECT sid, serial# AS ser FROM v$session WHERE username = u.username) LOOP
      EXECUTE IMMEDIATE 'ALTER SYSTEM KILL SESSION ''' || s.sid || ',' || s.ser || ''' IMMEDIATE';
    END LOOP;
    EXECUTE IMMEDIATE 'DROP USER ' || u.username || ' CASCADE';
    DBMS_OUTPUT.PUT_LINE('dropped ' || u.username);
  END LOOP;
  SELECT COUNT(*) INTO n FROM dba_context WHERE namespace = 'PROV_CTX';
  IF n > 0 THEN
    EXECUTE IMMEDIATE 'DROP CONTEXT prov_ctx';
    DBMS_OUTPUT.PUT_LINE('dropped context PROV_CTX');
  END IF;
END;
/
EXIT
