#!/usr/bin/env python

import os
import time
import json
import struct
import pexpect


DEBUG = os.getenv('CREATE_KEYTAB_DEBUG')
DEBUG = False



class createKeytab:



    def __init__(self, vnoList, keytabPath, encryptionTypes, principalType):

        for ktPath in keytabPath:

            if os.path.exists(keytabPath[ktPath]):

                keytab = self.getVnoInKeytab(keytabPath[ktPath], encryptionTypes, principalType)

                toDelete = self.checkVnoInKeytab(keytabPath[ktPath], vnoList, keytab)

                if toDelete:
                    
                    print('Vno ' + toDelete[1] + ' is not match with AD, deleting ' + toDelete[0])

                    os.remove(toDelete[0])

                    self.spawnKtutil(keytabPath[ktPath], vnoList)
            
            else:

                self.spawnKtutil(keytabPath[ktPath], vnoList)




    def spawnKtutil(self, keytabPath, vnoList, prompt='ktutil: '):

        ktutilSpawned = pexpect.spawn('/usr/bin/ktutil -v')

        defaultPrompt = prompt

        i = ktutilSpawned.expect([prompt, defaultPrompt], timeout=3)

        lines = ktutilSpawned.before.strip().split('\n')

        problem = (len(lines) > 1 or  (i == 1))


        if not problem:

            self.createKeytab(keytabPath, vnoList, ktutilSpawned)
        
        else:

            print('ktutil error: ' + lines[1])

            return False




    def createKeytab(self, keytabPath, vnoList, ktutilSpawned):

        spnList = []

        serviceSpn = ''.join([os.getenv('LDAP_CREATE_SPN'), os.getenv('LDAP_USER_PRINCIPAL_NAME').upper()])

        computerSpn = ''.join([os.getenv('LDAP_CREATE_COMPUTER') + '$', os.getenv('LDAP_USER_PRINCIPAL_NAME').upper()])

        spnList.extend((serviceSpn,computerSpn))



        for spn, vno in zip(spnList, vnoList):

            ktutilSpawned.sendline('addent -password -p %s -k %s -e rc4-hmac' % (spn, vno))

            ktutilSpawned.sendline(os.getenv('LDAP_CREATE_USER_PASSWORD'))
        

        ktutilSpawned.sendline('write_kt ' + keytabPath)

        print('Creating new keytab ' + keytabPath)
        

        ktutilSpawned.sendline('quit')
        ktutilSpawned.close()




    def getVnoInKeytab(self, keytabPath, encryptionTypes, principalType):

        def debugPrint(*s):
            if DEBUG:
                print(s)

        debugPrint('Keytab: ', keytabPath)

        readKeytab = open(keytabPath, 'rb')
        keytabFile = readKeytab.read()    
        readKeytab.close()

        # Read version
        keytabData = keytabFile
        keytabVersion = int(struct.unpack_from('>H', keytabData)[0])

        debugPrint('Keytab version: ', hex(keytabVersion))

        keytabData = keytabData[2:]
        keytabLength = len(keytabData)

        keytab = list()

        # Process entries
        debugPrint('Starting processing entries.')     

        keytabDone = 0

        while keytabDone < keytabLength:

            debugPrint('==== kte_start')

            keytab.append(dict())
            kte = keytab[-1]
            

            # int32_t size;
            kteLength = int(struct.unpack_from('>i', keytabData)[0])
            keytabData = keytabData[4:]

            debugPrint('kteLengthgth: ', kteLength)

            kte['size'] = kteLength


            # uint16_t num_components;
            keytabComponents = int(struct.unpack_from('>H', keytabData)[0])
            keytabData = keytabData[2:]
            kteDone = 2

            debugPrint('kte_num_components: ', keytabComponents)

            kte['num_components'] = keytabComponents

            # counted_octetString realm;
            realmLength = int(struct.unpack_from('>H', keytabData)[0])
            keytabData = keytabData[2:]
            kteDone += 2
            realmData = keytabData[:realmLength]

            debugPrint('realmLength: ', realmLength)
            debugPrint('realmData: ', realmData)

            keytabData = keytabData[realmLength:]
            kteDone += realmLength

            kte['realm'] = dict()
            kte['realm']['length'] = realmLength
            kte['realm']['data'] = realmData

            kte['components'] = list()

            # counted_octetString components[num_components];
            for kteComponent in range(0, keytabComponents):
                
                kte['components'].append(dict())

                debugPrint('kteComponent_#:', kteComponent)

                kteComponentLength = int(struct.unpack_from('>H', keytabData)[0])

                keytabData = keytabData[2:]
                kteDone += 2

                kteComponentData = keytabData[:kteComponentLength]

                debugPrint('kteComponentLength:', kteComponentLength)
                debugPrint('kteComponentData:', kteComponentData)
                
                kte['components'][kteComponent]['length'] = kteComponentLength
                kte['components'][kteComponent]['data'] = kteComponentData
                
                keytabData = keytabData[kteComponentLength:]
                kteDone += kteComponentLength
            

            # uint32_t nameType;
            nameType = principalType[int(struct.unpack_from('>i', keytabData)[0])]

            debugPrint('nameType: ', nameType)

            keytabData = keytabData[4:]
            kteDone += 4

            kte['nameType'] = nameType


            # uint32_t timestamp;
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(struct.unpack_from('>i', keytabData)[0])))

            debugPrint('timestamp: ', timestamp)

            keytabData = keytabData[4:]
            kteDone += 4

            kte['timestamp'] = timestamp

            # uint8_t vno8;
            vno8 = int(struct.unpack_from('>B', keytabData)[0])

            debugPrint('vno8: ', vno8)

            keytabData = keytabData[1:]
            kteDone += 1

            kte['vno8'] = vno8

            # keyblock key;
            kbtype = encryptionTypes[int(struct.unpack_from('>H', keytabData)[0])]
            keytabData = keytabData[2:]
            kteDone += 2
            kblen = int(struct.unpack_from('>H', keytabData)[0])
            keytabData = keytabData[2:]
            kteDone += 2

            #kbdata = keytabData[:kblen]
            kbdata = [hex(ord(b)) for b in keytabData[:kblen]]

            debugPrint('keyblock_type: ', kbtype)
            debugPrint('keyblock_len: ', kblen)
            debugPrint('keyblock_data: ', kbdata)

            kte['key'] = dict()
            kte['key']['type'] = kbtype
            kte['key']['octetString'] = dict()
            kte['key']['octetString']['length'] = kblen
            #kte['key']['octetString']['data'] = kbdata

            keytabData = keytabData[kblen:]
            kteDone += kblen
                

            if((kteLength - kteDone) >= 4):
                
                debugPrint('Found extra vno.')
                
                vno = int(struct.unpack_from('>i', keytabData)[0])

                debugPrint('vno (overridden): ', vno)

                keytabData = keytabData[4:]
                kteDone += 4

                kte['vno'] = vno

            keytabDone += kteDone
            keytabLength -= 4
            
            debugPrint('==== kteDone')
    

        # Print in json
        #print(json.dumps(keytab, sort_keys=False, indent=4))
        return keytab




    def checkVnoInKeytab(self, keytabPath, vnoList, keytab):    

        ktSpn = list()

        for keys in keytab:

            vno = keys['vno8'] if 'vno8' in keys else 'vno'

            if len(keys["components"]) > 1:

                c = keys["components"][0]["data"] + '/' + keys["components"][1]["data"] + '@' + keys["realm"]["data"]

            else:
                   
                c = keys["components"][0]["data"] + '@' + keys["realm"]["data"]
            
            ktSpn.extend((c, vno))


        i = 1
        for vnoInList in vnoList:

            if int(vnoInList) == ktSpn[i]:
                
                print('Vno: ' + str(ktSpn[i]) + ' in keytab: ' + keytabPath + ' (for object: ' + str(ktSpn[i-1]) + ') match with AD')                  
                    
            else:

                return keytabPath, vnoInList
            
            i += 2