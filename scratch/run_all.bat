@echo off
rem -------------------------------------------------------------------
rem  JumpPropTech local development helper
rem -------------------------------------------------------------------
rem Set DB connection environment variables for the PHP process
set DB_HOST=127.0.0.1
set DB_NAME=jumpproptech
set DB_USER=root
set DB_PASS=

rem -------------------------------------------------------------------
rem  1) Create / update the minimal DB schema
rem  (this will run using the env vars we just set)
php -f scratch\setup_db.php

rem -------------------------------------------------------------------
rem  2) Start the PHP built‑in dev server on port 8080
rem  (the server inherits the same env vars, so DB connections work)
php -S 127.0.0.1:8080 -t api
