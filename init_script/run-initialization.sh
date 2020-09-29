#!/bin/sh
set -e

# Debug level 4
exec sudo /usr/sbin/sssd -i -d 4 &

# Wait to be sure that SQL Server came up
sleep 60s

# Run the setup script to create the DB and the schema in the DB
# Note: make sure that your password matches what is in the Dockerfile
/opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P ${MSSQL_SA_PASSWORD} -i /tmp/create_db.sql

# Create stored procedures
/opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P ${MSSQL_SA_PASSWORD} -i /tmp/MaintenanceSolution.sql

# Create sql_agent jobs
/opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P ${MSSQL_SA_PASSWORD} -i /tmp/sql_agent_jobs.sql