#!/usr/bin/env python

import os
import time
import json
import struct
import pexpect


DEBUG = os.getenv("CREATE_KEYTAB_DEBUG")




class createKeytab:



    def __init__(self, vnoList, keytabPath, encryptionTypes, principalType):

        ktutilSpawned = self.checkVnoInKeytab(vnoList, keytabPath, encryptionTypes, principalType)

        if ktutilSpawned:

            self.createKeytab(vnoList, keytabPath, ktutilSpawned)



        

    def spawnKtutil(self, prompt='ktutil: '):

        ktutilSpawned = pexpect.spawn('/usr/bin/ktutil -v')

        defaultPrompt = prompt

        i = ktutilSpawned.expect([prompt, defaultPrompt], timeout=3)

        lines = ktutilSpawned.before.strip().split('\n')

        problem = (len(lines) > 1 or  (i == 1))


        if not problem:

            return ktutilSpawned
        
        else:

            print('ktutil error: ' + lines[1])

            return False




    def createKeytab(self, vnoList, keytabPath, ktutilSpawned):

        spnList = []

        serviceSpn = ''.join([os.getenv('LDAP_CREATE_SPN'), os.getenv('LDAP_USER_PRINCIPAL_NAME').upper()])

        computerSpn = ''.join([os.getenv('LDAP_CREATE_COMPUTER') + '$', os.getenv('LDAP_USER_PRINCIPAL_NAME').upper()])

        spnList.extend((serviceSpn,computerSpn))



        for spn, vno in zip(spnList, vnoList):

            ktutilSpawned.sendline('addent -password -p %s -k %s -e rc4-hmac' % (spn, vno))

            ktutilSpawned.sendline(os.getenv('LDAP_CREATE_USER_PASSWORD'))
        
        
        for kt in keytabPath:

            ktutilSpawned.sendline('write_kt ' + keytabPath[kt])

            print('Creating new keytab ' + keytabPath[kt])
        

        ktutilSpawned.sendline('quit')
        ktutilSpawned.close()




    def checkVnoInKeytab(self, vnoList, keytabPath, encryptionTypes, principalType):
        

        def dprint(*s):
            if DEBUG:
                print(s)


        for ktPath, vnoInList in zip(sorted(keytabPath, reverse=True), vnoList):

            if os.path.exists(keytabPath[ktPath]):

                dprint("Keytab: ", keytabPath[ktPath])

                readKeytab = open(keytabPath[ktPath], "rb")
                keytabFile = readKeytab.read()    
                readKeytab.close()

                # Read version
                keytabData = keytabFile
                keytabVersion = int(struct.unpack_from(">H", keytabData)[0])
                dprint("Keytab version: ", hex(keytabVersion))
                keytabData = keytabData[2:]
                keytabLength = len(keytabData)

                keytab = list()

                # Process entries
                dprint("Starting processing entries.")        
                keytabDone = 0

                while keytabDone < keytabLength:

                    dprint("==== kte_start")
                    keytab.append(dict())
                    kte = keytab[-1]
                    

                    # int32_t size;
                    kteLength = int(struct.unpack_from(">i", keytabData)[0])
                    keytabData = keytabData[4:]
                    dprint("kteLengthgth: ", kteLength)

                    kte["size"] = kteLength


                    # uint16_t num_components;
                    keytabComponents = int(struct.unpack_from(">H", keytabData)[0])
                    keytabData = keytabData[2:]
                    kteDone = 2

                    dprint("kte_num_components: ", keytabComponents)

                    kte["num_components"] = keytabComponents

                    # counted_octetString realm;
                    realmLength = int(struct.unpack_from(">H", keytabData)[0])
                    keytabData = keytabData[2:]
                    kteDone += 2
                    realmData = keytabData[:realmLength]

                    dprint("realmLength: ", realmLength)
                    dprint("realmData: ", realmData)

                    keytabData = keytabData[realmLength:]
                    kteDone += realmLength

                    kte["realm"] = dict()
                    kte["realm"]["length"] = realmLength
                    kte["realm"]["data"] = realmData

                    kte["components"] = list()

                    # counted_octetString components[num_components];
                    for kteComponent in range(0, keytabComponents):
                        
                        kte["components"].append(dict())

                        dprint("kteComponent_#:", kteComponent)
                        kteComponentLength = int(struct.unpack_from(">H", keytabData)[0])

                        keytabData = keytabData[2:]
                        kteDone += 2

                        kteComponentData = keytabData[:kteComponentLength]
                        dprint("kteComponentLength:", kteComponentLength)
                        dprint("kteComponentData:", kteComponentData)
                        
                        kte["components"][kteComponent]["length"] = kteComponentLength
                        kte["components"][kteComponent]["data"] = kteComponentData
                        
                        keytabData = keytabData[kteComponentLength:]
                        kteDone += kteComponentLength
                    

                    # uint32_t nameType;
                    nameType = principalType[int(struct.unpack_from(">i", keytabData)[0])]
                    dprint("nameType: ", nameType)
                    keytabData = keytabData[4:]
                    kteDone += 4

                    kte["nameType"] = nameType


                    # uint32_t timestamp;
                    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(struct.unpack_from(">i", keytabData)[0])))
                    dprint("timestamp: ", timestamp)
                    keytabData = keytabData[4:]
                    kteDone += 4

                    kte["timestamp"] = timestamp

                    # uint8_t vno8;
                    vno8 = int(struct.unpack_from(">B", keytabData)[0])
                    dprint("vno8: ", vno8)
                    keytabData = keytabData[1:]
                    kteDone += 1

                    kte["vno8"] = vno8

                    # keyblock key;
                    kbtype = encryptionTypes[int(struct.unpack_from(">H", keytabData)[0])]
                    keytabData = keytabData[2:]
                    kteDone += 2
                    kblen = int(struct.unpack_from(">H", keytabData)[0])
                    keytabData = keytabData[2:]
                    kteDone += 2

                    #kbdata = keytabData[:kblen]
                    kbdata = [hex(ord(b)) for b in keytabData[:kblen]]

                    dprint("keyblock_type: ", kbtype)
                    dprint("keyblock_len: ", kblen)
                    dprint("keyblock_data: ", kbdata)

                    kte["key"] = dict()
                    kte["key"]["type"] = kbtype
                    kte["key"]["octetString"] = dict()
                    kte["key"]["octetString"]["length"] = kblen
                    #kte["key"]["octetString"]["data"] = kbdata

                    keytabData = keytabData[kblen:]
                    kteDone += kblen
                        

                    if((kteLength - kteDone) >= 4):
                        
                        dprint("Found extra vno.")
                        
                        vno = int(struct.unpack_from(">i", keytabData)[0])
                        dprint("Vno (overridden): ", vno)
                        keytabData = keytabData[4:]
                        kteDone += 4

                        kte["vno"] = vno

                    keytabDone += kteDone
                    keytabLength -= 4
                    dprint("==== kteDone")
                

                # Debug in json
                # print(json.dumps(keytab, sort_keys=False, indent=4))


                if not int(vnoInList) == vno:

                    for ktRemove in keytabPath:

                        print('Vno ' + str(vnoInList) + ' is not match with AD, deleting ' + keytabPath[ktRemove])
                        os.remove(keytabPath[ktRemove])

                    ktutilSpawned = self.spawnKtutil()

                    return ktutilSpawned
                

                else:

                    for keys in keytab:

                        if len(keys["components"]) > 1:

                            print('Vno: ' + str(keys["vno8"]) + ' in keytab: ' + keytabPath[ktPath] + ' (for object: ' + keys["components"][0]["data"] + '/' + keys["components"][1]["data"] + '@' + keys["realm"]["data"] + ') is matching with AD')

                        else:
                            
                            print('Vno: ' + str(keys["vno8"]) + ' in keytab: ' + keytabPath[ktPath] + '  (for object: ' + keys["components"][0]["data"] + '@' + keys["realm"]["data"] + ') is matching with AD')


            else:

                ktutilSpawned = self.spawnKtutil()

                return ktutilSpawned

                