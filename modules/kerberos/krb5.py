import datetime
import hashlib

from asn1crypto import algos, cms, core, keys
from asn1crypto.cms import SignedData
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from impacket.krb5.crypto import Enctype, Key, _enctype_table
from minikerberos.protocol.asn1_structs import (
    AS_REQ, KDC_REQ_BODY, EncASRepPart, HostAddress, KDCOptions, KerberosResponse, PrincipalName)
from minikerberos.protocol.constants import PaDataType
from minikerberos.protocol.errors import KerberosError
from minikerberos.protocol.rfc4556 import PA_PK_AS_REP, PA_PK_AS_REQ, AuthPack, KDCDHKeyInfo, PKAuthenticator
from oscrypto.asymmetric import load_private_key, rsa_pkcs1v15_sign
from oscrypto.keys import parse_pkcs12
from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode

from .PkinitAsnNew import SPNEGO_PKINIT_AS_REP, SPNEGO_PKINIT_REP


def sign_authpack_native(data, privkey, certificate, wrap_signed=False):
    """
    Creating PKCS7 blob which contains the following things:
    1. 'data' blob which is an ASN1 encoded "AuthPack" structure
    2. the certificate used to sign the data blob
    3. the singed 'signed_attrs' structure (ASN1) which points to the "data" structure (in point 1)
    """

    da = {'algorithm': algos.DigestAlgorithmId('1.3.14.3.2.26')}

    si = {}
    si['version'] = 'v1'
    si['sid'] = cms.IssuerAndSerialNumber({
        'issuer': certificate.issuer,
        'serial_number': certificate.serial_number,
    })

    si['digest_algorithm'] = algos.DigestAlgorithm(da)
    si['signed_attrs'] = [
        cms.CMSAttribute({'type': 'content_type', 'values': ['1.3.6.1.5.2.3.1']}),
        # indicates that the encap_content_info's authdata struct (marked with OID '1.3.6.1.5.2.3.1' is signed )
        cms.CMSAttribute({'type': 'message_digest', 'values': [hashlib.sha1(data).digest()]}),
        ### hash of the data, the data itself will not be signed, but this block of data will be.
    ]
    si['signature_algorithm'] = algos.SignedDigestAlgorithm({'algorithm': '1.2.840.113549.1.1.1'})
    si['signature'] = rsa_pkcs1v15_sign(privkey, cms.CMSAttributes(si['signed_attrs']).dump(), "sha1")

    ec = {}
    ec['content_type'] = '1.3.6.1.5.2.3.1'
    ec['content'] = data

    sd = {}
    sd['version'] = 'v3'
    sd['digest_algorithms'] = [algos.DigestAlgorithm(da)]  # must have only one
    sd['encap_content_info'] = cms.EncapsulatedContentInfo(ec)
    sd['certificates'] = [certificate]
    sd['signer_infos'] = cms.SignerInfos([cms.SignerInfo(si)])

    if wrap_signed is True:
        ci = {}
        ci['content_type'] = '1.2.840.113549.1.7.2'  # signed data OID
        ci['content'] = cms.SignedData(sd)
        return cms.ContentInfo(ci).dump()

    return cms.SignedData(sd).dump()


def BuildPkinit_pa(req_body, now, diffieHellmanExchange, privKey, cert):
    authenticator = {'cusec': now.microsecond, 'ctime': now.replace(microsecond=0), 'nonce': 0,
                'paChecksum': hashlib.sha1(req_body.dump()).digest()}

    dp = {'p': diffieHellmanExchange.p, 'g': diffieHellmanExchange.g, 'q': 0}

    pka = {'algorithm': '1.2.840.10046.2.1', 'parameters': keys.DomainParameters(dp)}

    spki = {'algorithm': keys.PublicKeyAlgorithm(pka), 'public_key': diffieHellmanExchange.get_public_key()}

    authpack = {'pkAuthenticator': PKAuthenticator(authenticator),
                'clientPublicValue': keys.PublicKeyInfo(spki),
                'clientDHNonce': diffieHellmanExchange.dh_nonce}

    authpack = AuthPack(authpack)
    return sign_authpack_native(authpack.dump(), privKey, cert, wrap_signed=True)


def build_req_body_NegoEx(remoteComputer, cname, now):
    kdc_req_body_data = {}
    kdc_req_body_data['kdc-options'] = KDCOptions({'forwardable', 'renewable', 'canonicalize', 'disable-transited-check'})
    kdc_req_body_data['cname'] = PrincipalName({'name-type': -128, 'name-string': [cname]})
    kdc_req_body_data['realm'] = "WELLKNOWN:PKU2U"
    kdc_req_body_data['sname'] = PrincipalName(
        {'name-type': -128, 'name-string': [remoteComputer]})
    kdc_req_body_data['till'] = (now + datetime.timedelta(days=1)).replace(microsecond=0)
    kdc_req_body_data['rtime'] = (now + datetime.timedelta(days=1)).replace(microsecond=0)
    kdc_req_body_data['nonce'] = 0 #secrets.randbits(31)
    kdc_req_body_data['etype'] = [18, 17, 23, 24, -135]
    kdc_req_body_data['addresses'] = [HostAddress({'addr-type': 20, 'address': b'CLIENT6'})]
    return KDC_REQ_BODY(kdc_req_body_data)


def build_as_req_negoEx(user_cert, cert_pass, remoteComputer, diffieHellmanExchange):
    pfx = open(user_cert, 'rb').read()
    privkeyinfo, certificate, extra_certs = parse_pkcs12(pfx, password=cert_pass.encode())
    privkey = load_private_key(privkeyinfo)
    issuer = certificate.issuer.native['common_name']
    cname = "AzureAD\\" + issuer + "\\" + [i for i in certificate.subject.native['common_name'] if i.startswith('S-1')][0]

    now = datetime.datetime.now(datetime.timezone.utc)

    req_body = build_req_body_NegoEx(remoteComputer, cname, now)

    padata = BuildPkinit_pa(req_body, now, diffieHellmanExchange, privkey, certificate)

    payload = PA_PK_AS_REQ()
    payload['signedAuthPack'] = padata

    pa_data = {'padata-type': PaDataType.PK_AS_REQ.value, 'padata-value': payload.dump()}

    asreq = {'pvno': 5, 'msg-type': 10, 'padata': [pa_data], 'req-body': req_body}

    req = {'kerberos-v5': algos.DigestAlgorithmId('1.3.6.1.5.2.7'), 'null': core.Null(), 'Kerberos': AS_REQ(asreq)}
    req = SPNEGO_PKINIT_REP(req)

    return issuer, req.dump().hex()


def truncate(value, keysize):
    output = b''
    currentNum = 0
    while len(output) < keysize:
        currentDigest = hashlib.sha1(bytes([currentNum]) + value).digest()
        if len(output) + len(currentDigest) > keysize:
            output += currentDigest[:keysize - len(output)]
            break
        output += currentDigest
        currentNum += 1

    return output


def decrypt_pk_dh(data, diffieHellmanExchange):
    try:
        rep = SPNEGO_PKINIT_AS_REP.load(bytes.fromhex(data)).native
    except:
        krb_message = KerberosResponse.load(bytes.fromhex(data))
        raise KerberosError(krb_message)

    relevantPadata = None
    for padata in rep['Kerberos']['padata']:
        if padata['padata-type'] == 17:
            relevantPadata = PA_PK_AS_REP.load(padata['padata-value']).native
            break

    if not relevantPadata:
        raise Exception('No PAdata found with type 17')
    keyinfo = SignedData.load(relevantPadata['dhSignedData']).native['encap_content_info']
    if keyinfo['content_type'] != '1.3.6.1.5.2.3.2':
        raise Exception('Keyinfo content type unexpected value')
    authdata = KDCDHKeyInfo.load(keyinfo['content']).native
    pubkey = int(''.join(['1'] + [str(x) for x in authdata['subjectPublicKey']]), 2)

    pubkey = int.from_bytes(core.BitString(authdata['subjectPublicKey']).dump()[7:], 'big', signed=False)
    shared_key = diffieHellmanExchange.exchange(pubkey)

    server_nonce = relevantPadata['serverDHNonce']
    fullKey = shared_key + diffieHellmanExchange.dh_nonce + server_nonce

    etype = rep['Kerberos']['enc-part']['etype']
    cipher = _enctype_table[etype]
    if etype == Enctype.AES256:
        t_key = truncate(fullKey, 32)
    elif etype == Enctype.AES128:
        t_key = truncate(fullKey, 16)
    elif etype == Enctype.RC4:
        raise NotImplementedError('RC4 key truncation documentation missing. it is different from AES')

    key = Key(cipher.enctype, t_key)
    enc_data = rep['Kerberos']['enc-part']['cipher']
    dec_data = cipher.decrypt(key, 3, enc_data)
    encasrep = EncASRepPart.load(dec_data).native
    cipher = _enctype_table[int(encasrep['key']['keytype'])]
    session_key = Key(cipher.enctype, encasrep['key']['keyvalue'])

    return session_key, cipher, rep
