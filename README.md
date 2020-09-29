# MSSQL with Windows Auth

Contact: victor@vicrem.se

## To do
* Create keytab during build.

* Clean up image
    + Remove unnecessary packages/files/configuration from build.
    + Can sudo be removed(?) or better to use gosu?

* I really dont know if this step is necessary 
    + The server is running with same username (mssql_s_docker) as where I set/create the SPN: 
    + setspn -A MSSQLSvc/mssql.int.vicrem.se:1433 mssql_s_docker -> if it's not broke dont touch it.

* Access the server with a URL/SPN matching the wildcard.. I must use the Virtual IP or the host IP where the container is running - smaller issue :)

## Keytab

```
root@mssql:/tmp# klist -kte /var/opt/mssql/secrets/mssql.keytab
Keytab name: FILE:/var/opt/mssql/secrets/mssql.keytab
KVNO Timestamp         Principal
---- ----------------- --------------------------------------------------------
  11 01/01/70 01:00:00 MSSQLSvc/mssql.int.vicrem.se:1433@VICREM.SE (arcfour-hmac)
  11 01/01/70 01:00:00 MSSQLSvc/docker-vip.vicrem.se:1433@VICREM.SE (arcfour-hmac)
  11 01/01/70 01:00:00 MSSQLSvc/node1.vicrem.se:1433@VICREM.SE (arcfour-hmac)
  11 01/01/70 01:00:00 MSSQLSvc/node2.vicrem.se:1433@VICREM.SE (arcfour-hmac)
  11 01/01/70 01:00:00 MSSQLSvc/node3.vicrem.se:1433:1433@VICREM.SE (arcfour-hmac)
```

## TLS
* openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout cert.key -out cert.pem -config openssl.cfg -sha256

```
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no
[req_distinguished_name]
C = SE
ST = Skane
L = Malmo
O = vicrem.se
CN = "mssql.int.vicrem.se"
[v3_req]
keyUsage = critical, digitalSignature, keyAgreement
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = mssql.int.vicrem.se
DNS.2 = mssql
```

## mssql.conf
```
[network]
forceencryption = 1
tlscert = /var/opt/mssql/ssl/cert.pem
tlskey = /var/opt/mssql/ssl/cert.key
tlsciphers = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA
tlsprotocols = 1.2
kerberoskeytabfile = /var/opt/mssql/secrets/mssql.keytab
enablekdcfromkrb5conf = true
disablesssd = false
privilegedadaccount = mssql_s_docker

```
