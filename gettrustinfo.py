#!/usr/bin/env python
#
# Lookup the forest trust info for a domain using a trust key
# Mostly adapted from netview.py and lookupsid.py from impacket
#
# Author:
#  Dirk-jan Mollema (@_dirkjan)
#

import sys
import logging
import argparse
import codecs

from impacket.examples import logger
from impacket import version
from impacket.dcerpc.v5 import transport, lsat, lsad
from impacket.dcerpc.v5.samr import SID_NAME_USE
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import TypeSerialization1, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import epm, nrpc
from binascii import unhexlify
from struct import pack, unpack
class RPCLookup:
    KNOWN_PROTOCOLS = {
        135: {'bindstr': r'ncacn_ip_tcp:%s',           'set_host': False},
        139: {'bindstr': r'ncacn_np:%s[\PIPE\netlogon]', 'set_host': True},
        445: {'bindstr': r'ncacn_np:%s[\PIPE\netlogon]', 'set_host': True},
        }

    def __init__(self, username='', password='', domain='', port = None,
                 hashes = None):

        self.__username = username
        self.__password = password
        self.__port = port
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def dump(self, remoteName, remoteHost):


        stringbinding = epm.hept_map(remoteHost, nrpc.MSRPC_UUID_NRPC, protocol = 'ncacn_ip_tcp')
        logging.info('StringBinding %s'%stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.setRemoteHost(remoteHost)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(nrpc.MSRPC_UUID_NRPC)
        resp = nrpc.hNetrServerReqChallenge(dce, NULL, remoteName + '\x00', b'12345678')
        # resp.dump()
        serverChallenge = resp['ServerChallenge']

        ntHash = unhexlify(self.__nthash)

        self.sessionKey = nrpc.ComputeSessionKeyStrongKey(self.__password, b'12345678', serverChallenge, ntHash)

        self.ppp = nrpc.ComputeNetlogonCredential(b'12345678', self.sessionKey)

        try:
            resp = nrpc.hNetrServerAuthenticate3(dce, NULL, self.__username + '\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.TrustedDnsDomainSecureChannel,remoteName + '\x00',self.ppp, 0x600FFFFF )
            # resp.dump()
        except Exception as e:
            if str(e).find('STATUS_DOWNGRADE_DETECTED') < 0:
                raise

        self.clientStoredCredential = pack('<Q', unpack('<Q',self.ppp)[0] + 10)

        return dce, rpctransport

    def update_authenticator(self, plus=10):
        authenticator = nrpc.NETLOGON_AUTHENTICATOR()
        authenticator['Credential'] = nrpc.ComputeNetlogonCredential(self.clientStoredCredential, self.sessionKey)
        authenticator['Timestamp'] = plus
        return authenticator



# Process command-line arguments.
if __name__ == '__main__':
    # Init the example's logger theme
    logger.init()
    # Explicitly changing the stdout encoding format
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)
    print(version.BANNER)

    parser = argparse.ArgumentParser()

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    # parser.add_argument('maxRid', action='store', default = '4000', nargs='?', help='max Rid to check (default 4000)')

    group = parser.add_argument_group('connection')

    group.add_argument('-target-ip', action='store', metavar="ip address", help='IP Address of the target machine. '
                       'If omitted it will use whatever was specified as target. This is useful when target is the '
                       'NetBIOS name and you cannot resolve it')
    group.add_argument('-port', choices=['135', '139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful when proxying through smbrelayx)')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    import re

    domain, username, password, remoteName = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
        options.target).groups('')

    #In case the password contains '@'
    if '@' in remoteName:
        password = password + '@' + remoteName.rpartition('@')[0]
        remoteName = remoteName.rpartition('@')[2]

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None and options.no_pass is False:
        from getpass import getpass
        password = getpass("Password:")

    if options.target_ip is None:
        options.target_ip = remoteName

    lookup = RPCLookup(username, password, domain, int(options.port), options.hashes)
    dce, rpctransport = lookup.dump(remoteName, options.target_ip)
    request = nrpc.NetrGetForestTrustInformation()
    request['ServerName'] = NULL
    request['ComputerName'] = remoteName + '\x00'
    request['Authenticator'] = lookup.update_authenticator()
    request['ReturnAuthenticator']['Credential'] = b'\x00'*8
    request['ReturnAuthenticator']['Timestamp'] = 0
    request['Flags'] = 0
    try:
        resp = dce.request(request)
        resp.dump()
    except Exception as e:
        if str(e).find('STATUS_NOT_IMPLEMENTED') < 0:
            raise
