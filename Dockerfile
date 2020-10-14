FROM mcr.microsoft.com/mssql/server:2019-latest

# Environment
ENV GOSU_BINARY https://github.com/tianon/gosu/releases/download/1.12/gosu-amd64


# Packages
USER root
RUN apt-get update && \
    apt-get install -y unixodbc-dev krb5-user sssd


# Using gosu to run SQL server as mssql
RUN wget -qO /usr/local/bin/gosu ${GOSU_BINARY} \
 && chmod +x /usr/local/bin/gosu


# Create SQL Agent jobs
WORKDIR /docker-entrypoint-initdb.d
COPY sql_script/MaintenanceSolution.sql MaintenanceSolution.sql
COPY sql_script/sql_agent_jobs.sql sql_agent_jobs.sql


# Init script
WORKDIR /tmp
COPY init_script/entrypoint.sh entrypoint.sh
COPY init_script/run-initialization.sh run-initialization.sh
RUN  chmod +x run-initialization.sh


# Execute SQL server with gosu mssql
CMD ["/bin/bash", "/tmp/entrypoint.sh"]