#!/usr/bin/env python

import os
import pexpect
from krb5.create_object import ldapConnection


class createKeytab:


    def __init__(self, kvnoList):

        self.waitKtutil(kvnoList)

        

    def waitKtutil(self, kvnoList, prompt='ktutil: '):

        child = pexpect.spawn('/usr/bin/ktutil -v')

        default_prompt = prompt

        i = child.expect([prompt, default_prompt], timeout=3)

        lines = child.before.strip().split('\n')

        problem = (len(lines) > 1 or  (i == 1))

        if problem:

            print('ktutil error: ' + lines[1])
            return problem
        
        else:

            self.createKeytab(kvnoList, child)




    def createKeytab(self, kvnoList, child):

        spnList = []

        serviceSpn = ''.join([os.getenv('LDAP_CREATE_USER_SPN'), os.getenv('LDAP_USER_PRINCIPAL_NAME').upper()])

        computerSpn = ''.join([os.getenv('LDAP_CREATE_COMPUTER') + '$', os.getenv('LDAP_USER_PRINCIPAL_NAME').upper()])

        spnList.extend((serviceSpn,computerSpn))



        for spn, kvno in zip(spnList, kvnoList):

            child.sendline('addent -password -p %s -k %s -e rc4-hmac' % (spn, kvno))

            child.sendline(os.getenv('LDAP_CREATE_USER_PASSWORD'))
        
        
        child.sendline('write_kt ' + '/var/opt/mssql/secrets/mssql.keytab')
        child.sendline('write_kt ' + '/var/opt/mssql/secrets/client.keytab')
        
        child.sendline('quit')
        child.close() 