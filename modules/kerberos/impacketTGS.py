import datetime

import minikerberos.protocol.asn1_structs
from asn1crypto import core
from impacket.krb5 import constants
from impacket.krb5.asn1 import AP_REQ, AS_REP, Authenticator, AuthorizationData, seq_set
from impacket.krb5.constants import ChecksumTypes
from impacket.krb5.crypto import Enctype, Key, _checksum_table
from impacket.krb5.gssapi import CheckSumField
from impacket.krb5.types import KerberosTime, Principal, Ticket
from minikerberos.protocol.mskile import KERB_AD_RESTRICTION_ENTRYS
from minikerberos.protocol.rfc_iakerb import KRB_FINISHED
from pyasn1.codec.der import decoder, encoder

from ..negoex.structs import LSAP_TOKEN_INFO_INTEGRITY, GenerateExtensions, Pack
from .PkinitAsnNew import SPNEGO_PKINIT_AP_REQ


def getKerberosTGS(cipher, sessionKey, tgtResponse, gssAPIChecksumBuffer):
    a = (minikerberos.protocol.asn1_structs.AS_REP(tgtResponse['Kerberos']))
    decodedTGT = decoder.decode(a.dump(), asn1Spec=AS_REP())[0]

    # Extract the ticket from the TGT
    ticket = Ticket() # should be -128 name-type
    ticket.from_asn1(decodedTGT['ticket'])

    apReq = AP_REQ()
    apReq['pvno'] = 5
    apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    opts = list()
    opts.append(constants.KDCOptions.forwarded.value)
    apReq['ap-options'] = constants.encodeFlags(opts)
    seq_set(apReq, 'ticket', ticket.to_asn1)

    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    authenticator['crealm'] = decodedTGT['crealm'].asOctets()

    clientName = Principal()
    clientName.from_asn1(decodedTGT, 'crealm', 'cname')
    
    seq_set(authenticator, 'cname', clientName.components_to_asn1)

    now = datetime.datetime.utcnow()
    authenticator['cusec'] = 2 #now.microsecond
    authenticator['ctime'] = KerberosTime.to_asn1(now)

    authenticator['cksum']['cksumtype'] = 0x8003

    chkField = CheckSumField()
    chkField['Lgth'] = 16

    # GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | GSS_C_EXTENDED_ERROR_FLAG
    #chkField['Flags'] = 16418

    chkField['Flags'] = 16446

    subKey = bytes.fromhex('FB3F5B9CB2E387A5815D57E672978A118C22404938B279BBD4E29E1505CAC2C3')
    checksumtype = _checksum_table[ChecksumTypes.hmac_sha1_96_aes256.value]
    keyServer = Key(Enctype.AES256, subKey)

    kerbFinished = {}
    kerbFinished['gss-mic'] = {'cksumtype': 16,
                               'checksum': checksumtype.checksum(keyServer, 41, bytes.fromhex(gssAPIChecksumBuffer))}

    kerbFinished = KRB_FINISHED(kerbFinished)

    authenticator['cksum']['checksum'] = chkField.getData() + bytes.fromhex(GenerateExtensions(kerbFinished.dump()))
    
    authenticator['subkey']['keytype'] = 18
    authenticator['subkey']['keyvalue'] = subKey
    
    authenticator['seq-number'] = 682437742

    tokenIntegrity = LSAP_TOKEN_INFO_INTEGRITY()
    tokenIntegrity.Flags = 1
    tokenIntegrity.MachineID = bytes.fromhex('7e303fffe6bff25146addca4fbddf1b94f1634178eb4528fb2731c669ca23cde')
    tokenIntegrity.TokenIL = int('2000', 16)

    RESTRICTION_ENTRY = [{'restriction-type': 0, 'restriction': bytes.fromhex(Pack(tokenIntegrity))}]

    KERB_AUTH_DATA_TOKEN_RESTRICTIONS = AuthorizationData()
    KERB_AUTH_DATA_TOKEN_RESTRICTIONS[0]['ad-type'] = 141
    KERB_AUTH_DATA_TOKEN_RESTRICTIONS[0]['ad-data'] = KERB_AD_RESTRICTION_ENTRYS(RESTRICTION_ENTRY).dump()

    # AD_IF_RELEVANT
    authenticator['authorization-data'][0]['ad-type'] = 1
    authenticator['authorization-data'][0]['ad-data'] = encoder.encode(KERB_AUTH_DATA_TOKEN_RESTRICTIONS)

    encodedAuthenticator = encoder.encode(authenticator)

    # Key Usage 7
    # TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes
    # TGS authenticator subkey), encrypted with the TGS session
    # key (Section 5.5.1)

    ## should be key usage 11

    encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, None)

    apReq['authenticator']['etype'] = cipher.enctype
    apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

    apReqNegoEx = {}
    apReqNegoEx['kerberos-v5'] = '1.3.6.1.5.2.7'
    apReqNegoEx['null'] = core.Boolean(True, contents=b'')
    apReqNegoEx['Kerberos'] = minikerberos.protocol.asn1_structs.AP_REQ.load(encoder.encode(apReq))
    apReqNegoEx = SPNEGO_PKINIT_AP_REQ(apReqNegoEx)
    data = (apReqNegoEx.dump().hex())

    return data
    
