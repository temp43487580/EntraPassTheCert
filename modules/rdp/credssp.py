
from typing import List
from asyauth.common.credentials import UniCredential
from asyauth.common.constants import asyauthProtocol, asyauthSubProtocol
from asyauth.common.subprotocols import SubProtocol
from asyauth.common.subprotocols import SubProtocolNative
from modules.rdp.spnegoex import SPNEGOEXCredential
from modules.rdp.credsspnative import CredSSPClientNative

class CREDSSPCredential(UniCredential):
	def __init__(self, credentials:List[UniCredential] = [], subprotocol:SubProtocol = SubProtocolNative()):
		UniCredential.__init__(self, protocol = asyauthProtocol.CREDSSP, subprotocol=subprotocol)
		self.credentials = credentials

	def build_context(self, *args, **kwargs):
		spnego_cred = SPNEGOEXCredential(self.credentials)
		if self.subprotocol.type == asyauthSubProtocol.NATIVE:
			
			credssp_ctx = CredSSPClientNative(self)
			credssp_ctx.auth_ctx = spnego_cred.build_context()
		else:
			raise Exception('Unsupported subprotocol "%s"' % self.subprotocol)

		return credssp_ctx

