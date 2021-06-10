#!/usr/bin/env python
# Copyright (c) 2016-2018 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author:
#  Alberto Solino (@agsolino)
#
# Modified by Dirk-jan Mollema (@_dirkjan)
#
# This script loads a TGT or TGS from a file and tries to decrypt it
# with the keys you have to manually put in the source code below.
# If you want to decrypt a TGS you have to change a couple of options too.
# Read the comments :)
#
import argparse
import logging
import os
import sys
import binascii 

from pyasn1.codec.der import decoder, encoder

from impacket import version
from impacket.examples import logger
from impacket.krb5 import constants
from impacket.krb5.asn1 import AP_REQ, AS_REP, TGS_REQ, Authenticator, TGS_REP, seq_set, seq_set_iter, PA_FOR_USER_ENC, \
    Ticket as TicketAsn1, EncTGSRepPart, EncTicketPart, AD_IF_RELEVANT, Ticket as TicketAsn1
from impacket.krb5.crypto import Key, _enctype_table, _HMACMD5, Enctype
from impacket.krb5.kerberosv5 import getKerberosTGT, sendReceive
from impacket.krb5.pac import PACTYPE, PAC_INFO_BUFFER, KERB_VALIDATION_INFO, PAC_CLIENT_INFO_TYPE, PAC_CLIENT_INFO, \
    PAC_SERVER_CHECKSUM, PAC_SIGNATURE_DATA, PAC_PRIVSVR_CHECKSUM, PAC_UPN_DNS_INFO, UPN_DNS_INFO
from impacket.krb5.types import Principal, Ticket
from impacket.krb5.ccache import CCache
from impacket.dcerpc.v5.rpcrt import TypeSerialization1
from impacket.krb5.crypto import Key, _enctype_table, _HMACMD5, Enctype
from impacket.krb5.kerberosv5 import getKerberosTGS
from impacket.krb5.kerberosv5 import getKerberosTGT, sendReceive
from impacket.krb5.types import Principal, KerberosTime, Ticket
from impacket.winregistry import hexdump

class GETST:
    def __init__(self, target, password, domain, options):
        self.__password = password
        self.__user= target
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = None
        self.__options = options
        self.__kdcHost = options.dc_ip
        self.__saveFileName = None

    def saveTicket(self, ticket, sessionKey):
        logging.info('Saving ticket in %s' % (self.__saveFileName + '.ccache'))
        ccache = CCache()

        ccache.fromTGS(ticket, sessionKey, sessionKey)
        ccache.saveFile(self.__saveFileName + '.ccache')

    def printPac(self, data, human=True):
        encTicketPart = decoder.decode(data, asn1Spec=EncTicketPart())[0]
        adIfRelevant = decoder.decode(encTicketPart['authorization-data'][0]['ad-data'], asn1Spec=AD_IF_RELEVANT())[
            0]
        # So here we have the PAC
        pacType = PACTYPE(bytes(adIfRelevant[0]['ad-data']))
        buff = pacType['Buffers']

        for bufferN in range(pacType['cBuffers']):
            infoBuffer = PAC_INFO_BUFFER(buff)
            data = pacType['Buffers'][infoBuffer['Offset']-8:][:infoBuffer['cbBufferSize']]
            if logging.getLogger().level == logging.DEBUG:
                print("TYPE 0x%x" % infoBuffer['ulType'])
            if infoBuffer['ulType'] == 1:
                type1 = TypeSerialization1(data)
                # I'm skipping here 4 bytes with its the ReferentID for the pointer
                newdata = data[len(type1)+4:]
                kerbdata = KERB_VALIDATION_INFO()
                kerbdata.fromString(newdata)
                kerbdata.fromStringReferents(newdata[len(kerbdata.getData()):])
                kerbdata.dump()
                print()
                # # If human is true, print human-friendly version
                # # if not, just do the raw dump
                if human:
                    print()
                    print('Username:', kerbdata['EffectiveName'])
                    print('Domain SID:', kerbdata['LogonDomainId'].formatCanonical())
                    print('UserId:', kerbdata['UserId'])
                    print('PrimaryGroupId', kerbdata['PrimaryGroupId'])
                    print('Member of groups:')
                    for group in kerbdata['GroupIds']:
                        print('  ->   %d (attributes: %d)' % (group['RelativeId'],  group['Attributes']))
                    print('LogonServer: ', kerbdata['LogonServer'])
                    print('LogonDomainName: ', kerbdata['LogonDomainName'])
                    print()
                    print('Extra SIDS:')
                    for sid in kerbdata['ExtraSids']:
                        print('  ->  ', sid['Sid'].formatCanonical())
                    if kerbdata['ResourceGroupDomainSid']:
                        print('Extra domain groups found! Domain SID:')
                        print(kerbdata['ResourceGroupDomainSid'].formatCanonical())
                        print('Relative groups:')
                        for group in kerbdata['ResourceGroupIds']:
                            print('  ->   %d (attributes: %d)' % (group['RelativeId'],  group['Attributes']))
            elif infoBuffer['ulType'] == PAC_CLIENT_INFO_TYPE:
                clientInfo = PAC_CLIENT_INFO(data)
                if logging.getLogger().level == logging.DEBUG:
                    clientInfo.dump()
                    print()
            elif infoBuffer['ulType'] == PAC_SERVER_CHECKSUM:
                signatureData = PAC_SIGNATURE_DATA(data)
                if logging.getLogger().level == logging.DEBUG:
                    signatureData.dump()
                    print()
            elif infoBuffer['ulType'] == PAC_PRIVSVR_CHECKSUM:
                signatureData = PAC_SIGNATURE_DATA(data)
                if logging.getLogger().level == logging.DEBUG:
                    signatureData.dump()
                    print()
            elif infoBuffer['ulType'] == PAC_UPN_DNS_INFO:
                upn = UPN_DNS_INFO(data)
                if logging.getLogger().level == logging.DEBUG:
                    upn.dump()
                    print(data[upn['DnsDomainNameOffset']:])
                    # print
            else:
                hexdump(data)

            if logging.getLogger().level == logging.DEBUG:
                print("#"*80)

            buff = buff[len(infoBuffer):]

    def run(self):

        # Do we have a TGT cached?
        tgt = None
        try:
            ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
            logging.debug("Using Kerberos Cache: %s" % os.getenv('KRB5CCNAME'))
            if options.target_domain:
                if options.via_domain:
                    principal = 'krbtgt/%s@%s' % (options.target_domain.upper(), options.via_domain.upper())
                else:
                    principal = 'krbtgt/%s@%s' % (options.target_domain.upper(), self.__domain.upper())
            else:
                principal = 'krbtgt/%s@%s' % (self.__domain.upper(), self.__domain.upper())
            # For just decoding a TGS, override principal
            # principal = 'cifs/forest-b-server.forest-b.local@FOREST-B.LOCAL'
            creds = ccache.getCredential(principal, False)
            creds.dump()
            if creds is not None:
                # For just decoding a TGS, use toTGS()
                TGT = creds.toTGT()
                tgt, cipher, sessionKey = TGT['KDC_REP'], TGT['cipher'], TGT['sessionKey']
                oldSessionKey = sessionKey
                logging.info('Using TGT from cache')
            else:
                logging.error("No valid credentials found in cache. ")
                return
        except:
            # No cache present
            logging.error("Cache file not valid or not found")
            raise

        print()
        # Print TGT
        # For just decoding a TGS, use TGS_REP()
        decodedTGT = decoder.decode(tgt, asn1Spec = AS_REP())[0]

        # Extract the ticket from the TGT
        ticket = Ticket()
        ticket.from_asn1(decodedTGT['ticket'])

        cipherText = decodedTGT['ticket']['enc-part']['cipher']
        newCipher = _enctype_table[int(decodedTGT['ticket']['enc-part']['etype'])]

        # hash / AES key for the TGT / TGS goes here
        self.__nthash = 'yourkeyhere'
        if self.__nthash != '':
            key = Key(newCipher.enctype, binascii.unhexlify(self.__nthash))

        try:
            # If is was plain U2U, this is the key
            plainText = newCipher.decrypt(key, 2, cipherText)
        except:
            # S4USelf + U2U uses this other key
            plainText = cipher.decrypt(sessionKey, 2, cipherText)

        # Print PAC in human friendly form
        self.printPac(plainText, True)

        # Get TGS and print it
        logging.info('Getting ST for user')
        serverName = Principal(self.__options.spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
        if options.target_domain:
            domain = options.target_domain
        else:
            domain = self.__domain
        print(domain)
        tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, self.__kdcHost, tgt, cipher, sessionKey, clientrealm=self.__domain)
        self.__saveFileName = self.__user


        decodedTGS = decoder.decode(tgs, asn1Spec = TGS_REP())[0]

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('TGS_REP')
            print(decodedTGS.prettyPrint())

        # Get PAC

        cipherText = decodedTGS['ticket']['enc-part']['cipher']

        # Key Usage 2
        # AS-REP Ticket and TGS-REP Ticket (includes tgs session key or
        #  application session key), encrypted with the service key
        #  (section 5.4.2)

        newCipher = _enctype_table[int(decodedTGS['ticket']['enc-part']['etype'])]

        # hash / AES key for the TGT / TGS goes here
        self.__nthash = 'yourkeyhere'
        if self.__nthash != '':
            key = Key(newCipher.enctype, binascii.unhexlify(self.__nthash))

        try:
            # If is was plain U2U, this is the key
            plainText = newCipher.decrypt(key, 2, cipherText)
        except:
            # S4USelf + U2U uses this other key
            plainText = cipher.decrypt(sessionKey, 2, cipherText)

        # Print PAC in human friendly form
        self.printPac(plainText)

        # Save the ticket in case we want to use it later
        self.saveTicket(tgs,oldSessionKey)

if __name__ == '__main__':
    # Init the example's logger theme
    logger.init()
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True, description="Tool to decrypt and dump a PAC from a TGT/TGS"
                                                                " (TGS requires modification) and request an ST"
                                                                " in a different forest. You have to put the correct"
                                                                " trust/service Kerberos keys in the source for decryption"
                                                                " to work")
    parser.add_argument('identity', action='store', help='[domain/]username[:password]')
    parser.add_argument('-spn', action="store", required=True,  help='SPN (service/server) of the target service the '
                                                                     'service ticket will' ' be generated for')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')

    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                       'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-target-domain', action='store', help='Target domain (for cross-trust access)')
    group.add_argument('-via-domain', action='store', help='Domain from which the TGT originates (for cross-trust access)')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)


    import re
    domain, username, password = re.compile('(?:(?:([^/:]*)/)?([^:]*)(?::([^@]*))?)?').match(options.identity).groups(
        '')

    try:
        if domain is None:
            logging.critical('Domain should be specified!')
            sys.exit(1)

        options.k = True

        executer = GETST(username, password, domain, options)
        executer.run()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        print(str(e))
