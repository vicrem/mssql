#!/bin/bash
set -e


# Mandatory input
[ -z "${KERBEROS_REALM}" ] && echo "KERBEROS_REALM must be defined" && exit 1


# Optional input
[ -z "${LDAP_ENUMERATE}" ] && LDAP_ENUMERATE="False"
[ -z "${LDAP_USER_MEMBEROF}" ] && LDAP_USER_MEMBEROF="memberOf"
[ -z "${LDAP_IGNORE_GROUP_MEMBERS}" ] && LDAP_IGNORE_GROUP_MEMBERS="True"
[ -z "${LDAP_USER_PRINCIPAL}" ] && LDAP_USER_PRINCIPAL="userPrincipalName"
[ -z "${KERBEROS_DNS_DISCOVERY_DOMAIN}" ] && KERBEROS_DNS_DISCOVERY_DOMAIN=${KERBEROS_REALM}



# Put config files in place
cat >/etc/krb5.conf <<EOL
[libdefaults]
rdns = False
forwardable = True
renew_lifetime = 7d
ticket_lifetime = 24h
udp_preference_limit = 0
dns_lookup_realm = True
dns_canonicalize_hostname = True
default_realm = ${KERBEROS_REALM}
default_keytab_name = FILE:${KRB5_KTNAME}
default_client_keytab_name = FILE:${KRB5_CLIENT_KTNAME}

[realms]
${KERBEROS_REALM} = {
}

[domain_realm]
$(echo ${KERBEROS_REALM%%.*} | tr '[:upper:]' '[:lower:]') = ${KERBEROS_REALM}
.$(echo ${KERBEROS_REALM%%.*} | tr '[:upper:]' '[:lower:]') = ${KERBEROS_REALM}
$(echo ${KERBEROS_REALM} | tr '[:upper:]' '[:lower:]') = ${KERBEROS_REALM}
.$(echo ${KERBEROS_REALM} | tr '[:upper:]' '[:lower:]') = ${KERBEROS_REALM}

[capaths]
${KERBEROS_REALM%%.*} = {
    ${KERBEROS_REALM} = ${KERBEROS_REALM#*.}
}
${KERBEROS_REALM} = {
    ${KERBEROS_REALM#*.} = ${KERBEROS_REALM#*.}
}

[plugins]
localauth = {
    module = sssd:/usr/lib/x86_64-linux-gnu/sssd/modules/sssd_krb5_localauth_plugin.so
}
EOL



cat >/etc/sssd/sssd.conf <<EOL
[sssd]
user = sssd
services = nss
config_file_version = 2
domains = ${KERBEROS_REALM}

[domain/${KERBEROS_REALM}]

ad_domain = ${KERBEROS_REALM}

id_provider = ad
access_provider = ad

auth_provider = ad
chpass_provider = ad
subdomains_provider = ad

sudo_provider = none
autofs_provider = none
selinux_provider = none

krb5_realm = ${KERBEROS_REALM}
krb5_keytab = ${KRB5_KTNAME}

dyndns_update = False
cache_credentials = True
use_fully_qualified_names = True
dns_discovery_domain = ${KERBEROS_REALM}
ignore_group_members = ${LDAP_IGNORE_GROUP_MEMBERS}

ldap_id_mapping = True
ldap_group_nesting_level = 0
ldap_account_expire_policy = ad
ldap_force_upper_case_realm = True


[nss]
filter_groups = root
filter_users = root
EOL


cat >/etc/nsswitch.conf <<EOL
passwd:     compat sss
shadow:     compat sss
group:      compat sss

hosts:      files dns myhostname

bootparams: nisplus [NOTFOUND=return] files

ethers:     files
netmasks:   files
networks:   files
protocols:  files
rpc:        files
services:   files sss
netgroup:   nisplus sss
publickey:  nisplus

automount:  files nisplus sss
aliases:    files nisplus
EOL


cat >/etc/ssl/openssl.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
C = SE
ST = Skane
L = Malmo
O = Vicrem
CN = ${HOSTNAME}

[v3_req]
keyUsage = critical, digitalSignature, keyAgreement
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${HOSTNAME}
DNS.2 = ${HOSTNAME%%.*}
EOF


cat >/var/opt/mssql/mssql.conf <<EOF
[network]
forceencryption = 1
tlscert = /etc/ssl/private/cert.pem
tlskey = /etc/ssl/private/cert.key
tlsciphers = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA
tlsprotocols = 1.2
enablekdcfromkrb5conf = true
disablesssd = false
EOF


# Create keytab
if [ "${CREATE_KEYTAB}" = "True" ]; then
    python /tmp/keytab/run.py && \
    chown mssql -R /var/opt/mssql/secrets
fi


# Set permission and run sssd
chmod 600 /etc/sssd/sssd.conf
exec /usr/sbin/sssd -i -d 4 &


# Create TLS cert and set permission
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout /etc/ssl/private/cert.key -out /etc/ssl/private/cert.pem -config /etc/ssl/openssl.cnf -sha256 && \
chown -R mssql /etc/ssl/private/


# Create backup dir
if [ ! -d /var/opt/mssql/backup ]; then
    mkdir /var/opt/mssql/backup
fi


# Wait to be sure that SQL Server is up & running
sleep 30s


# Run sql script
for files in $(ls -d /docker-entrypoint-initdb.d/*); do
    if [[ $files =~ \.sql$ ]]; then
        /opt/mssql-tools/bin/sqlcmd -S localhost,${MSSQL_TCP_PORT} -U sa -P ${MSSQL_SA_PASSWORD} -i $files
    fi
done


# Create login for Admin group
if [ ! -z "${LDAP_ADMIN_GROUP}" ]; then

    for groups in $( echo "${LDAP_ADMIN_GROUP}" | sed 's/,/ /g'); do

cat >/tmp/create_admin_group.sql <<EOF
USE [master]
GO
CREATE LOGIN [${KERBEROS_REALM%%.*}\\${groups}] FROM WINDOWS WITH DEFAULT_DATABASE=[master]
GO
ALTER SERVER ROLE [sysadmin] ADD MEMBER [${KERBEROS_REALM%%.*}\\${groups}]
GO
EOF

        /opt/mssql-tools/bin/sqlcmd -S localhost,${MSSQL_TCP_PORT} -U sa -P ${MSSQL_SA_PASSWORD} -i /tmp/create_admin_group.sql
    done

fi