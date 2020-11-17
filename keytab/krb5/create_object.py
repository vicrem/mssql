#!/usr/bin/env python

import os
import ldap
import ldap.modlist as modlist


class ldapConnection:

    _connection = None


    def __init__(self, ldapConnSettings):

        self.s = ldapConnSettings

        ldapInitialized = self.ldapInitialize(self.s['LDAP_PROVIDER_URL'], self.s['LDAP_CA_CERT_PATH'], self.s['LDAP_BIND_USERNAME'], self.s['LDAP_BIND_PASSWORD'])




    def ldapInitialize(self, ldapProviderUrl, ldapCaCertCath, ldapBindUsername, ldapBindPassword):

        try:

            self._connection = ldap.initialize(ldapProviderUrl)#,trace_level=2)

            self._connection.set_option(ldap.OPT_X_TLS_CACERTFILE, ldapCaCertCath)

            self._connection.set_option(ldap.OPT_REFERRALS, 0)

            self._connection.set_option(ldap.OPT_X_TLS,ldap.OPT_X_TLS_DEMAND)

            self._connection.set_option(ldap.OPT_X_TLS_DEMAND, True)

            self._connection.set_option(ldap.OPT_X_TLS_NEWCTX, ldap.OPT_ON)   


            status = self._connection.simple_bind_s(

                ldapBindUsername,
                ldapBindPassword

            )

            return status


        except ldap.INVALID_CREDENTIALS as err:
            
            raise SystemExit(err)

            
        except ldap.SERVER_DOWN as err:
            
            raise SystemExit(err)




    def ldapSearchAdObject(self, ldapSearchObject, adObjectAndFilter, constructedAttributes=[]):


        checkIfObjectExists = self._connection.search_s(

            ldapSearchObject,
            ldap.SCOPE_SUBTREE,
            adObjectAndFilter[-1] % adObjectAndFilter[1],
            constructedAttributes

        )

        return checkIfObjectExists




    def ldapCheckAdObject(self, ldapSearchObject, adObjectAndFilter, ifObjectFound):


        objectFound = [entry for dn, entry in ifObjectFound if isinstance(entry, dict)]


        if adObjectAndFilter[0] == 'ADUser':

            if not objectFound:

                return 'userObjectDoesNotExist'


            elif not 'servicePrincipalName' in objectFound[0]:

                return 'userObjectExistsWithOutSpn'

                                
            else:

                userVno = self.ldapGetVnoNumber(ldapSearchObject, adObjectAndFilter)

                print('userObjectAlreadyExistsWithSpn with kvno ' + userVno + ', checking if in keytab..')

                return userVno
        

        else:


            if not objectFound:

                return 'ComputerNotExists'

            else:

                computerVno = self.ldapGetVnoNumber(ldapSearchObject, adObjectAndFilter)

                print('ComputerExists with kvno ' + computerVno + ', checking if in keytab..')

                return computerVno




    def ldapCreateUserObject(self, adObjectAndFilter, createObjectWithAllAttrs=''):

        userCreate = adObjectAndFilter[1]


        # Prep object settings
        dn='CN=' + userCreate + ',' +os.getenv('LDAP_USER_DN')
        

        attrs = {}

        if createObjectWithAllAttrs:
            
            attrs['objectclass'] = ['top', 'person', 'organizationalPerson','user']
            attrs['cn'] = userCreate
            attrs['userPrincipalName'] = ''.join([userCreate, os.getenv('LDAP_USER_PRINCIPAL_NAME')])
            attrs['sAMAccountName'] = userCreate
            attrs['givenName'] = userCreate
            attrs['DisplayName'] = userCreate
            attrs['userAccountControl'] = '514'
            attrs['mail'] = ''.join([userCreate, os.getenv('LDAP_USER_PRINCIPAL_NAME')])
            attrs['ou'] = os.getenv('LDAP_USER_DN')
            attrs['servicePrincipalName'] = os.getenv('LDAP_CREATE_SPN')

            # Prep the password
            password = os.getenv('LDAP_CREATE_USER_PASSWORD')
            unicodePass = unicode('\"' + password + '\"', 'iso-8859-1')
            passwordValue = unicodePass.encode('utf-16-le')
            addPass = [(ldap.MOD_REPLACE, 'unicodePwd', [passwordValue])]


            # UserAccountcontrol: http://www.selfadsi.org/ads-attributes/user-userAccountControl.htm
            modAcct = [(ldap.MOD_REPLACE, 'userAccountControl', '66048')]


            # Prep attrs
            ldif = modlist.addModlist(attrs)


            try:

                self._connection.add_s(dn, ldif)

                print('Success, ADUser ' +userCreate+ ' is now created' )


            except ldap.LDAPError, error_message:

                print 'Error adding new user: %s' % error_message

                return False


            try:

                self._connection.modify_s(dn, addPass)

                print('Success, ADUser ' +userCreate+ ' received new passwd' )


            except ldap.LDAPError, error_message:

                print 'Error setting password: %s' % error_message

                return False


            try:

                self._connection.modify_s(dn, modAcct)

                print('Success, ADUser ' +userCreate+ ' is now enabled' )

                return True


            except ldap.LDAPError, error_message:

                print 'Error enabling user: %s' % error_message

                return False


        else:

            ldif = [(ldap.MOD_REPLACE, 'servicePrincipalName', os.getenv('LDAP_CREATE_SPN'))]


            try:

                self._connection.modify_s(dn, ldif)

                print('Success, SPN ' + os.getenv('LDAP_CREATE_SPN') + ' is now set for object ' + userCreate)

                return True


            except ldap.LDAPError, error_message:

                print 'Could not set SPN: %s' % error_message

                return False




    def ldapCreateComputerObject(self, adObjectAndFilter):

        computerCreate = adObjectAndFilter

        # Prep object settings
        dn='CN=' + computerCreate + ',' +os.getenv('LDAP_COMPUTER_DN')
        
        attrs = {}
        attrs['objectclass'] = ['computer']
        attrs['cn'] = computerCreate
        attrs['sAMAccountName'] = ''.join([computerCreate, '$'])
        attrs['userAccountControl'] = '4128'

        # Prep the password
        computerPassword = os.getenv('LDAP_CREATE_COMPUTER_PASSWORD')
        computerUnicodePass = unicode('\"' + computerPassword + '\"', 'iso-8859-1')
        computerPassword_value = computerUnicodePass.encode('utf-16-le')
        computerAddPass = [(ldap.MOD_REPLACE, 'unicodePwd', [computerPassword_value])]

        # Prep attrs
        ldif = modlist.addModlist(attrs)


        try:

            self._connection.add_s(dn, ldif)

            print('Success, ComputerObject ' +computerCreate+ ' is now created' )
            

        except ldap.LDAPError, error_message:

            print 'Error adding new ComputerObject: %s' % error_message

            return False


        try:

            self._connection.modify_s(dn, computerAddPass)

            print('Success, ComputerObject ' +computerCreate+ ' received new passwd' )

            return True
            

        except ldap.LDAPError, error_message:

            print 'Error setting ComputerObject password: %s' % error_message

            return False




    def ldapGetVnoNumber(self, ldapSearchObject, adObjectAndFilter):

        getKvno = self.ldapSearchAdObject(

            ldapSearchObject['LDAP_BASE_DN'], 
            adObjectAndFilter, 
            constructedAttributes=['*','msDs-keyVersionNumber']
            
        )

        msDS = [entry for dn, entry in getKvno if isinstance(entry, dict)]

        for key in msDS:

            return str(key['msDS-KeyVersionNumber']).strip('[]').strip("\'")




    def close(self):
        
        self._connection.unbind_s()