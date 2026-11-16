-- Run ONCE as the postgres superuser:
--   sudo -u postgres psql -v pw="'choose-a-strong-password'" -f database/00_create_role_and_database.sql
-- Creates the application role and an empty database owned by it. The role gets no superuser rights.
CREATE ROLE atlas LOGIN PASSWORD :pw NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE DATABASE atlas OWNER atlas;
