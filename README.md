# MSSQL with Windows Auth

Contact: victor@vicrem.se


## Important

* Set "CREATE_KEYTAB" to True if you automatically want to create a keytab - Use it on your own risk!!


## Info

* Creation of SPN will take a while before activated in domain/forest.
    + You may need to redeploy before it works



## Manually create keytab

1) Create a normal AD-user (Example: MSSQLDocker_user)

2) Manually create a Computer Object with User & Computer (Example: MSSQL-DOCKER-COMPUTER)

3) Run in Powershell and press Y to reset computer password

```
ktpass /out mssql.keytab /mapuser MSSQL-DOCKER-COMPUTER$@VICREM.SE /princ MSSQL-DOCKER-COMPUTER$@VICREM.SE /crypto RC4-HMAC-NT /rndpass /ptype KRB5_NT_PRINCIPAL

```

4) Run in Powershell:

* IMPORTANT! Each time ktpass is executed the Kerberos number "kvno" is updated, and all previous keytabs are invalidated. 
    * If you need multiple SPN in same keytab(?)
        + First ktpass command add -setupn
        + Second time add -setupn and -setpass

```
setspn -A MSSQLSvc/mssql.vicrem.se:1433 MSSQLDocker_user

ktpass /princ MSSQLSvc/mssql.vicrem.se:1433@VICREM.SE /mapuser MSSQLDocker_user /pass Password_For_MSSQLDocker_user /crypto RC4-HMAC-NT /ptype KRB5_NT_PRINCIPAL /in mssql.keytab /out mssql.keytab -setupn

```


5) Check SPN

```
PS H:\> setspn -L MSSQLDocker_user
Registered ServicePrincipalNames for CN=MSSQLDocker_user,DC=vicrem,DC=se:
        MSSQLSvc/mssql.vicrem.se:1433
        
``` 


6) Move mssql.keytab to /var/opt/mssql/secrets/ and change permission/owner so running user mssql (not MSSQLDocker_user) can read the keytab


7) Your keytab should look something like this:

```
root@mssql:/tmp# klist -kte /var/opt/mssql/secrets/mssql.keytab

Keytab name: FILE:/var/opt/mssql/secrets/mssql.keytab
KVNO Timestamp         Principal
---- ----------------- --------------------------------------------------------
4 01/01/70 01:00:00 MSSQL-DOCKER-COMPUTER$@VICREM.SE (arcfour-hmac)
7 01/01/70 01:00:00 MSSQLSvc/mssql.vicrem.se:1433@VICREM.SE (arcfour-hmac)

```


8) Test your keytab

```
kinit MSSQL-DOCKER-COMPUTER$ -kt /var/opt/mssql/secrets/mssql.keytab
kinit MSSQLSvc/mssql.vicrem.se:1433 -kt /var/opt/mssql/secrets/mssql.keytab

```

9) If step 8 == ok then create client.keytab else check KVNO number

```
cp /var/opt/mssql/secrets/mssql.keytab /var/opt/mssql/secrets/client.keytab

```


## Debuging kerberos/ldap

10) Add follwing to /var/opt/mssql/logger.ini - or enable env variables in entrypoint.sh

```
[Output:sql]
type=File
filename=/var/opt/mssql/log/pallog.log

[Logger:security.ldap]
level=debug
outputs=sql

[Logger:security.kerberos]
level=debug
outputs=sql

```

## ToDo
* Create Keytab script: 
    + what if only one object exists and the other not? => Need to fix it!
