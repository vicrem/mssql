#!/bin/bash

# export KRB5_TRACE=/dev/stdout
# export KRB5_CONFIG=/etc/krb5.conf
# export KRB5_KTNAME=/var/opt/mssql/secrets/mssql.keytab
# export KRB5_CLIENT_KTNAME=/var/opt/mssql/secrets/user.keytab

/tmp/run-initialization.sh & \
exec gosu mssql /opt/mssql/bin/sqlservr