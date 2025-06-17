from typing import List
from asyauth.common.credentials import UniCredential
from asyauth.common.constants import asyauthProtocol, asyauthSubProtocol
from asyauth.common.subprotocols import SubProtocol
from asyauth.common.subprotocols import SubProtocolNative
from modules.rdp.spnegoexnative import SPNEGOEXClientNative

class SPNEGOEXCredential(UniCredential):
	def __init__(self, credentials:List[UniCredential] = [], subprotocol:SubProtocol = SubProtocolNative()):
		UniCredential.__init__(self, protocol = asyauthProtocol.SPNEGOEX, subprotocol=subprotocol)
		self.credentials = credentials
	
	def build_context(self, *args, **kwargs):
		if self.subprotocol.type == asyauthSubProtocol.NATIVE:
			sspi_ctx = SPNEGOEXClientNative(self.credentials[0])
			return sspi_ctx

		else:
			raise Exception('Unsupported subprotocol "%s"' % self.subprotocol)