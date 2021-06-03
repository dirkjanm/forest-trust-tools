#!/usr/bin/env python
#
# Lookup the Local SID of a computer
# Mostly adapted from netview.py and lookupsid.py from impacket
# Also contains some logic from bloodhound.py
#
# Author:
#  Dirk-jan Mollema (@_dirkjan)
#

import sys
import logging
import argparse
import codecs
from struct import unpack
from impacket.examples.logger import ImpacketFormatter
from impacket import version
from impacket.dcerpc.v5 import transport, lsat, lsad
from impacket.dcerpc.v5.dtypes import NULL, RPC_SID, MAXIMUM_ALLOWED
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.dcerpc.v5.ndr import NULL

class LsaTranslate(object):
    KNOWN_PROTOCOLS = {
        445: {'bindstr': r'ncacn_np:%s[\pipe\lsarpc]', 'set_host': True},
    }

    def __init__(self, username='', password='', domain='', port=None,
                 hashes=None, hostname='', debug=False):

        self.__username = username
        self.__password = password
        self.__port = port
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__hostname = hostname
        self.__debug = debug
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def dump(self, remote_host):

        logging.info('Connecting to LSARPC named pipe at %s', remote_host)

        stringbinding = self.KNOWN_PROTOCOLS[self.__port]['bindstr'] % remote_host
        # logging.info('StringBinding %s'%stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(self.__port)

        if self.KNOWN_PROTOCOLS[self.__port]['set_host']:
            rpctransport.setRemoteHost(remote_host)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

        try:
            self.lookup(rpctransport, remote_host)
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.critical(str(e))
            raise

    def lookup(self, rpctransport, host):
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(lsat.MSRPC_UUID_LSAT)
        logging.info('Bind OK')
        if dce is None:
            logging.warning('Connection failed')
            return

        try:
            resp = lsad.hLsarOpenPolicy2(dce, lsat.POLICY_LOOKUP_NAMES | MAXIMUM_ALLOWED)
        except Exception as e:
            if str(e).find('Broken pipe') >= 0:
                return
            else:
                raise

        policyHandle = resp['PolicyHandle']

        hostname = self.__hostname

        try:
            resp = lsat.hLsarLookupNames3(dce, policyHandle, [hostname], lsat.LSAP_LOOKUP_LEVEL.enumItems.LsapLookupWksta)
        except DCERPCException as e:
            if str(e).find('STATUS_NONE_MAPPED') >= 0:
                logging.warning('HOSTNAME %s lookup failed, return status: STATUS_NONE_MAPPED', hostname)
            elif str(e).find('STATUS_SOME_NOT_MAPPED') >= 0:
                # Not all could be resolved, work with the ones that could
                resp = e.get_packet()
            else:
                raise
        if self.__debug:
            resp.dump()
        try:
            firstsid = resp['TranslatedSids']['Sids'][0]
        except KeyError:
            logging.error('Structure invalid, could not find required information')
        except IndexError:
            logging.error('No SIDs were returned')
        if firstsid['Use'] != 3:
            logging.warning('Unexpected SID use type %s', firstsid['Use'])
        # Construct SID
        print('Found local domain SID: %s' % firstsid['Sid'].formatCanonical())

        dce.disconnect()

        return None


# Process command-line arguments.
def main():
    # Init the example's logger theme
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(ImpacketFormatter())
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.INFO)

    # Explicitly changing the stdout encoding format
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)
    logging.info(version.BANNER)

    parser = argparse.ArgumentParser()

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('hostname', action='store', help='NETBIOS name of host')

    group = parser.add_argument_group('connection')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful when proxying through ntlmrelayx)')
    group.add_argument('-debug', action="store_true", help='Verbose output')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    import re

    domain, username, password, remote_name = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
        options.target).groups('')

    #In case the password contains '@'
    if '@' in remote_name:
        password = password + '@' + remote_name.rpartition('@')[0]
        remote_name = remote_name.rpartition('@')[2]

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None and options.no_pass is False:
        from getpass import getpass
        password = getpass("Password:")


    lookup = LsaTranslate(username, password, domain, int(options.port), options.hashes, options.hostname, options.debug)
    lookup.dump(remote_name)


if __name__ == '__main__':
    main()
