FROM mcr.microsoft.com/mssql/server:2019-latest

USER root

# Packages
RUN apt-get update && \
    apt-get install -y sudo vim unixodbc-dev krb5-user sssd

# Kerberos and SSSD
COPY krb/krb5.conf /etc/krb5.conf
COPY krb/nsswitch.conf /etc/nsswitch.conf
COPY krb/sssd.conf /etc/sssd/sssd.conf
RUN  chmod 600 /etc/sssd/sssd.conf

# Create needed SSSD directory
RUN mkdir -p /var/lib/sss/db && \
    mkdir -p /var/lib/sss/pipes/private && \
    mkdir -p /var/lib/sss/mc && \
    # Create backup dir
    mkdir /var/opt/mssql/backup

# DB files
WORKDIR /tmp
COPY sql_script/MaintenanceSolution.sql MaintenanceSolution.sql
COPY sql_script/sql_agent_jobs.sql sql_agent_jobs.sql
COPY sql_script/create_db.sql create_db.sql

# Init script
COPY init_script/entrypoint.sh entrypoint.sh
COPY init_script/run-initialization.sh run-initialization.sh
RUN  chmod +x run-initialization.sh

# Run as..
RUN  useradd mssql_s_docker -s /usr/sbin/nologin && \
     chown -R mssql_s_docker /var/opt/mssql && \
     echo "mssql_s_docker ALL=(ALL:ALL) NOPASSWD: /usr/sbin/sssd" >> /etc/sudoers

USER mssql_s_docker

CMD ["/bin/bash", "/tmp/entrypoint.sh"]