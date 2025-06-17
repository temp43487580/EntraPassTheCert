# Kudos:
# Parts of this code was inspired by the following project by @rubin_mor
# https://github.com/morRubin/AzureADJoinedMachinePTC
# 

# TODO: code needs cleanup, it is still in beta
# TODO: add integrity checks and check certificate of the server
# TODO: code currently supports RSA+DH+SHA1 , add support for other mechanisms

import os
from asyauth.common.credentials.kerberos import KerberosCredential
from asyauth.protocols.spnegoex.protocol.messages import MESSAGE_TYPE, negoexts_parse_bytes
from asyauth.protocols.kerberos.gssapi import get_gssapi
from minikerberos.pkinit import PKINIT
from asysocks.unicomm.common.target import UniTarget
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech, SPNEGO_NegTokenResp
from modules.negoex.helper import NegoExHelper

class SPNEGOEXClientNative:
	def __init__(self, credential:KerberosCredential):
		self.credential = credential
		self.target:UniTarget = None
		self.pkinit:PKINIT = self.credential.get_pkinit()
		self.gssapi = None
		self.is_azure = True
		self.helper = NegoExHelper(self.credential.username, self.credential.secret, self.credential.target.ip)
		self._convid = os.urandom(16)
		self._msgctr = 0
		self._asreq = None
		self._krb_finished_data = b''
		self._msgs = b''
		self.session_key_data = None
		self.xxxxx = None
		self.seq = 1
		self.iteractions = 0

	def get_session_key(self):
		return self.session_key.contents

	def get_internal_seq(self):
		return self.seq
		
	async def sign(self, data, message_no, direction = 'init'):
		return self.gssapi.GSS_GetMIC(data, message_no)	
		
	async def encrypt(self, data, message_no):
		return self.gssapi.GSS_Wrap(data, message_no)
		
	async def decrypt(self, data, message_no, direction='init', auth_data=None):		
		return self.gssapi.GSS_Unwrap(data, message_no, direction=direction, auth_data=auth_data)
	
	async def authenticate(self, authData, flags = None, spn = None):
		if self.iteractions == 0:
			self.iteractions += 1
			
			blob = SPNEGO_NegTokenInit()
			blob['MechTypes'] = [
				TypesMech['NEGOEX - SPNEGO Extended Negotiation Security Mechanism'],
                TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']
			]
			
			mechToken = self.helper.GenerateNegoExInit()
			blob['MechToken'] = bytes.fromhex(mechToken)
			return blob.getData(), True, None

		elif self.iteractions == 1:
			self.iteractions += 1
			mechToken = self.helper.GenerateNegoExKerberosAs(authData)
			
			blob = SPNEGO_NegTokenResp()
			blob['ResponseToken'] = bytes.fromhex(mechToken)
			return blob.getData(), True, None
		
		elif self.iteractions == 2:
			self.iteractions += 1
			blob = SPNEGO_NegTokenResp()
			mechToken = self.helper.GenerateNegoExKerberosAp(authData)
			blob['ResponseToken'] = bytes.fromhex(mechToken)
			return blob.getData(), True, None
		
		elif self.iteractions == 3:
			from minikerberos.protocol.encryption import _enctype_table, Key
			from minikerberos.protocol.asn1_structs import EncAPRepPart

			self.iteractions += 1
			msgs = negoexts_parse_bytes(authData[21:])
			self._msgctr += len(msgs)
			ap_rep = msgs[MESSAGE_TYPE.CHALLENGE].Exchange.inner_token.native

			cipher = _enctype_table[int(ap_rep['enc-part']['etype'])]()
			cipher_text = ap_rep['enc-part']['cipher']
			subkey_key = Key(cipher.enctype, self.helper.session_key.contents)
			temp = cipher.decrypt(subkey_key, 12, cipher_text)
			enc_part = EncAPRepPart.load(temp).native
			self.seq = enc_part['seq-number']
			cipher = _enctype_table[int(enc_part['subkey']['keytype'])]()
			self.session_key = Key(cipher.enctype, enc_part['subkey']['keyvalue'])
			self.gssapi = get_gssapi(self.session_key)
			return None, False, None
		else:			
			return None, False, None

