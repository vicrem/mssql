#!/usr/bin/env python

import os
from krb5.create_object import ldapConnection
from krb5.create_keytab import createKeytab


kvnoList = []


def main(ldapConnSettings, ldapSearchObject):


    ldapInitialized = ldapConnection(ldapConnSettings)

    try:

        for objects in ldapSearchObject.values():

            if isinstance(objects, (list, dict)):

                for adObjectAndFilter in objects:

                    ifObjectFound = ldapInitialized.ldapSearchAdObject(ldapSearchObject['LDAP_BASE_DN'], adObjectAndFilter)

                    ObjectFound = ldapInitialized.ldapCheckAdObject(ldapSearchObject, adObjectAndFilter, ifObjectFound)


                    if ObjectFound == 'objectDoesNotExist':
                        userCreated = ldapInitialized.ldapCreateUserObject(adObjectAndFilter, True)

                        if userCreated:
                            userKvno = ldapInitialized.ldapGetKvnoNumber(ldapSearchObject, adObjectAndFilter)
                            kvnoList.append(userKvno)


                    elif ObjectFound == 'objectExistsWithOutSpn':
                        spnCreated = ldapInitialized.ldapCreateUserObject(adObjectAndFilter, False)

                        if spnCreated:
                            userKvno = ldapInitialized.ldapGetKvnoNumber(ldapSearchObject, adObjectAndFilter)
                            kvnoList.append(userKvno)


                    elif ObjectFound == 'ComputerNotExists':
                        computerCreated = ldapInitialized.ldapCreateComputerObject(adObjectAndFilter[1])

                        if computerCreated:
                            computerKvno = ldapInitialized.ldapGetKvnoNumber(ldapSearchObject, adObjectAndFilter)
                            kvnoList.append(computerKvno)
                    

                    elif not os.path.exists('/var/opt/mssql/secrets/mssql.keytab'):
                        
                        objectKvno = ldapInitialized.ldapGetKvnoNumber(ldapSearchObject, adObjectAndFilter)
                        kvnoList.append(objectKvno)



    except KeyboardInterrupt:
        ldapInitialized.close()



if __name__ == '__main__':

    ldapConnSettings = {
        'LDAP_PROVIDER_URL': os.getenv('LDAP_PROVIDER_URL'),
        'LDAP_CA_CERT_PATH': os.getenv('LDAP_CA_CERT_PATH'),
        'LDAP_BIND_USERNAME': os.getenv('LDAP_BIND_USERNAME'),
        'LDAP_BIND_PASSWORD': os.getenv('LDAP_BIND_PASSWORD'),
    }

    ldapSearchObject = {
        'LDAP_BASE_DN': os.getenv('LDAP_BASE_DN'),
        'LDAP_OBJECT_WITH_FILTER': [
            ['ADUser', os.getenv('LDAP_CREATE_USER'), os.getenv('LDAP_USER_FILER')],
            ['ADComputer', os.getenv('LDAP_CREATE_COMPUTER'), os.getenv('LDAP_COMPUTER_FILTER')]
        ]
    }

    main(ldapConnSettings, ldapSearchObject)
    createKeytab(kvnoList)