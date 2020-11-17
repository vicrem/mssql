#!/usr/bin/env python

import os
from krb5.create_object import ldapConnection
from krb5.create_keytab import createKeytab


createVnoList = []
checkVnoList = []



def getVno(ldapInitialized, ldapSearchObject, adObjectAndFilter):
    
    vno = ldapInitialized.ldapGetVnoNumber(ldapSearchObject, adObjectAndFilter)

    createVnoList.append(vno)




def main(ldapConnSettings, ldapSearchObject, keytabPath):


    ldapInitialized = ldapConnection(ldapConnSettings)

    try:

        for objects in ldapSearchObject.values():


            if isinstance(objects, (list, dict)):


                for adObjectAndFilter in objects:

                    ifObjectFound = ldapInitialized.ldapSearchAdObject(ldapSearchObject['LDAP_BASE_DN'], adObjectAndFilter)

                    objectFound = ldapInitialized.ldapCheckAdObject(ldapSearchObject, adObjectAndFilter, ifObjectFound)



                    if objectFound == 'userObjectDoesNotExist':

                        userCreated = ldapInitialized.ldapCreateUserObject(adObjectAndFilter, createObjectWithAllAttrs=True)

                        if userCreated:

                            getVno(ldapInitialized, ldapSearchObject, adObjectAndFilter)



                    elif objectFound == 'userObjectExistsWithOutSpn':

                        spnCreated = ldapInitialized.ldapCreateUserObject(adObjectAndFilter, createObjectWithAllAttrs=False)

                        if spnCreated:

                            getVno(ldapInitialized, ldapSearchObject, adObjectAndFilter)



                    elif objectFound == 'ComputerNotExists':

                        computerCreated = ldapInitialized.ldapCreateComputerObject(adObjectAndFilter[1])

                        if computerCreated:

                            getVno(ldapInitialized, ldapSearchObject, adObjectAndFilter)
                    


                    elif not os.path.exists(keytabPath['KRB5_KTNAME']):
                        
                        getVno(ldapInitialized, ldapSearchObject, adObjectAndFilter)

                    
                    else:

                        checkVnoList.append(objectFound)




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


    keytabPath = {
        'KRB5_KTNAME': os.getenv('KRB5_KTNAME'),
        'KRB5_CLIENT_KTNAME': os.getenv('KRB5_CLIENT_KTNAME')
    }


    encryptionTypes = {
        23: "rc4-hmac",
        18: "aes256-cts-hmac-sha1-96",
        17: "aes128-cts-hmac-sha1-96",
        16: "des3-cbc-sha1-kd"
    }


    principalType = {
        1: "KRB5_NT_PRINCIPAL",
        2: "KRB5_NT_SRV_INST",
        5: "KRB5_NT_UID"
    }



    main(ldapConnSettings, ldapSearchObject, keytabPath)


    if createVnoList:

        createKeytab(createVnoList, keytabPath, encryptionTypes, principalType)
    
    else:

        createKeytab(checkVnoList, keytabPath, encryptionTypes, principalType)