# Forest Trust Tools

These are Proof of Concept tools for playing with forest trusts and cross-realm kerberos tickets.
For `getftST.py` you will need to apply the kerberosv5.patch to your local impacket install (I recommend running this in a virtualenv or pipenv).

Released as part of my blog series on Forest trusts: <https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/>

And part two: <https://dirkjanm.io/active-directory-forest-trusts-part-two-trust-transitivity/>

## getftST.py
Reads a TGT or TGS (TGS requires manual changes in the source code) and decrypts this using the NT hash or Kerberos key you put in the source code. It will print the PAC inside your ticket. Then it will request an ST for the specified SPN, at the DC you specify. It will decrypt this and print the PAC, then store it in a file.

## keytab.py
Contains impacket compatible structures for keytab files. Allows you to write AES/RC4 keys to a keytab file, which can be loaded into Wireshark to automatically decrypt the encrypted parts of Kerberos exchanges. Great for debugging.

## getlocalsid.py
Uses MS-LSAT RPC to query a host for the SID of it's local domain by translating the NETBIOS domain name to a SID.

## gettrustinfo.py
Uses the `NetrGetForestTrustInformation` RPC call with a domain trust account to query the SIDs that are part of a certain forest.

## ftinfo.py
Convert FOREST_TRUST_INFO structs from ADUC or ADSI edit into readable format.

## frida_intercept.py
Frida script to interactively replace a SID of a domain in LSASS when `NetrGetForestTrustInformation` is called.