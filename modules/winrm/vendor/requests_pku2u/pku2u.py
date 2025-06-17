from requests.auth import AuthBase
import base64
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech, SPNEGO_NegTokenResp, ASN1_OID, asn1encode, ASN1_AID
from modules.negoex.helper import NegoExHelper
from urllib.parse import urlparse
from asyauth.protocols.spnegoex.protocol.messages import MESSAGE_TYPE, PKU2U_TOKEN_TYPE, generate_verify, generate_initiator_metadata, generate_init_nego, generate_ap_req, negoexts_parse_bytes
from asyauth.protocols.kerberos.gssapi import get_gssapi
from impacket.krb5 import kerberosv5, gssapi

class HttpPku2uAuth(AuthBase):
    def __init__(self, target, pfx, pfxpass):
        self.helper = NegoExHelper(pfx, pfxpass, urlparse(target).hostname)
        self.pre_token = None
        self.interaction = 1
        self.auth_done = False
        self.gssapi = None
        self.seqno = 0
        return
    
    def generate_token(self):
        if self.interaction == 1:
            # send negoinit
            blob = SPNEGO_NegTokenInit()
            blob['MechTypes'] = [
                TypesMech['NEGOEX - SPNEGO Extended Negotiation Security Mechanism'],
                TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']
            ]
            
            mechToken = self.helper.GenerateNegoExInit()
            blob['MechToken'] = bytes.fromhex(mechToken)

        elif self.interaction == 2:
            # send ap req
            mechToken = self.helper.GenerateNegoExKerberosAs(self.pre_token)
            blob = SPNEGO_NegTokenResp()
            blob['ResponseToken'] = bytes.fromhex(mechToken)

        elif self.interaction == 3:
            blob = SPNEGO_NegTokenResp()
            mechToken = self.helper.GenerateNegoExKerberosAp(self.pre_token)
            blob['ResponseToken'] = bytes.fromhex(mechToken)

        return blob.getData()

    def wrap(self, message): 
        return self.gssapi.GSS_Wrap(message, self.seqno)

    def unwrap(self, message):
        r1,r2 = self.gssapi.GSS_Unwrap(message, self.seqno, direction='init', auth_data=None)
        self.seqno += 1
        return r1,r2

    def setup_gssapi(self, response):
        from minikerberos.protocol.encryption import Enctype, _checksum_table, _enctype_table, Key
        from minikerberos.protocol.asn1_structs import EncAPRepPart

        msgs = negoexts_parse_bytes(response[21:])
        ap_rep = msgs[MESSAGE_TYPE.CHALLENGE].Exchange.inner_token.native
        cipher = _enctype_table[int(ap_rep['enc-part']['etype'])]()
        cipher_text = ap_rep['enc-part']['cipher']
        subkey_key = Key(cipher.enctype, self.helper.session_key.contents)
        temp = cipher.decrypt(subkey_key, 12, cipher_text)
        enc_part = EncAPRepPart.load(temp).native
        cipher = _enctype_table[int(enc_part['subkey']['keytype'])]()
        session_key = Key(cipher.enctype, enc_part['subkey']['keyvalue'])
        self.gssapi = get_gssapi(session_key)
        return

    def __call__(self, r):
        if self.auth_done == False:
            try:
                token = self.generate_token()
                auth_header = "Negotiate " + base64.b64encode(token).decode("ascii")
                r.headers['Authorization'] = auth_header
            except:
                print('[-] failed to login. the target machine might not be Entra-joinned or P2P cert might be expired.')
        return r