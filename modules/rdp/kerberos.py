from typing import List
from asyauth.common.credentials import UniCredential
from asyauth.common.constants import asyauthSecret, asyauthProtocol, asyauthSubProtocol
from asyauth.common.subprotocols import SubProtocol
from asyauth.common.subprotocols import SubProtocolNative
from asysocks.unicomm.common.target import UniTarget
from minikerberos.common.creds import KerberosCredential as KCRED
from asyauth.utils.paramprocessor import str_one, int_one, bool_one, int_list

# another hidden import because of oscrypto
#from minikerberos.pkinit import PKINIT

class KerberosCredential(UniCredential):
	def __init__(self, secret, username, domain, stype:asyauthSecret, target:UniTarget = None, altname:str = None, altdomain:str = None, etypes:List[int] = [23,17,18], subprotocol:SubProtocol = SubProtocolNative(), certdata:str = None, keydata:str=None, cross_target:UniTarget = None, cross_realm:str = None):
		UniCredential.__init__(
			self, 
			secret = secret,
			username = username,
			domain = domain,
			stype = stype,			
			protocol = asyauthProtocol.KERBEROS,
			subprotocol = subprotocol)
		
		self.etypes = etypes
		self.altname = altname
		self.altdomain = altdomain
		self.target = target
		self.certdata = certdata #can be file path or cert data
		self.keydata = keydata #can be file path or cert data
		self.cross_target = cross_target #used for cross-domain kerberos
		self.cross_realm = cross_realm #used for cross-domain kerberos

		self.dh_params = {
				'p' : int('00ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff', 16),
				'g' : 2
			}

		if self.stype is asyauthSecret.NT:
			self.stype = asyauthSecret.RC4

		self.sanity_check()
	
	def sanity_check(self):
		if self.domain is None or self.domain == '':
			raise Exception('Kerberos credential must have domain set! %s' % str(self))
		if self.target is None or self.target.dc_ip is None:
			raise Exception('Kerberos credential target must have dc_ip set!')		

	def get_pkinit(self):
		# hidden import
		from minikerberos.pkinit import PKINIT

		if self.stype == asyauthSecret.CERTSTORE:
			return PKINIT.from_windows_certstore(self.settings.pfx12_file, certstore_name = 'MY', cert_serial = None, dh_params = self.dh_params, is_azure = self.is_azure)
		else:
			return PKINIT.from_pfx(self.username, self.secret, dh_params = self.dh_params)

	@staticmethod
	def get_url_params():
		return {
			'altname' : str_one,
			'altdomain' : str_one,
			'etype' : int_list,
			'dc' : str_one, #domain controller IP
			'dcc': str_one, #corss-domain DC IP
			'dns' : str_one,
			'dnsc' : str_one,
			'realmc' : str_one,
			'certdata':str_one,
			'keydata':str_one,
		}

	def get_basetype_and_encoding(self):
		basetype = self.stype
		encoding = 'file'
		if self.stype.name.endswith('B64'):
			basetype = asyauthSecret(self.stype.name[:-3])
			encoding = 'b64'
		elif self.stype.name.endswith('HEX'):
			basetype = asyauthSecret(self.stype.name[:-3])
			encoding = 'hex'
		return basetype, encoding

	def to_ccred(self) -> KCRED:
		basetype, encoding = self.get_basetype_and_encoding()
		if basetype == asyauthSecret.KEYTAB:
			return KCRED.from_keytab(self.secret, self.username, self.domain, encoding=encoding)
		if basetype == asyauthSecret.KIRBI:
			return KCRED.from_kirbi(self.secret, encoding=encoding)
		if basetype == asyauthSecret.CCACHE:
			return KCRED.from_ccache(self.secret, self.username, self.domain, encoding=encoding)
		if basetype == asyauthSecret.PFX:
			return KCRED.from_pfx(self.keydata, self.secret, self.dh_params, self.altname, self.altdomain, encoding=encoding)
		if basetype == asyauthSecret.PFXSTR:
			return KCRED.from_pfx_string(self.keydata, self.secret, self.dh_params, self.altname, self.altdomain)

		res = KCRED()
		res.username = self.username
		res.domain = self.domain

		if self.stype in [asyauthSecret.PASSWORD, asyauthSecret.PW, asyauthSecret.PASS]:
			res.password = self.secret
		elif self.stype in [asyauthSecret.NT, asyauthSecret.RC4]:
			if isinstance(self.secret, str) is True:
				if len(self.secret) != 32:
					raise Exception('Incorrect RC4/NT key! %s' % self.secret)
			elif isinstance(self.secret, bytes):
				if len(self.secret) != 16:
					raise Exception('Incorrect RC4/NT key! %s' % self.secret)
			res.nt_hash = self.secret
			res.kerberos_key_rc4 = self.secret
		elif self.stype == asyauthSecret.AES:
			if isinstance(self.secret, str) is True:
				if len(self.secret) == 32:
					res.kerberos_key_aes_128 = self.secret
				elif len(self.secret) == 64:
					res.kerberos_key_aes_256 = self.secret
				else:
					raise Exception('Incorrect AES key! %s' % self.secret)
			elif isinstance(self.secret, bytes) is True:
				if len(self.secret) == 16:
					res.kerberos_key_aes_128 = self.secret
				elif len(self.secret) == 32:
					res.kerberos_key_aes_256 = self.secret
				else:
					raise Exception('Incorrect AES key! %s' % self.secret)
			else:
				raise Exception('Incorrect AES key! %s' % self.secret)
		elif self.stype == asyauthSecret.DES:
			if isinstance(self.secret, str) is True:
				if len(self.secret) != 16:
					raise Exception('Incorrect DES key! %s' % self.secret)
			elif isinstance(self.secret, bytearray) is True:
				if len(self.secret) != 8:
					raise Exception('Incorrect DES key! %s' % self.secret)
			res.kerberos_key_des = self.secret
		elif self.stype in [asyauthSecret.DES3, asyauthSecret.TDES]:
			if isinstance(self.secret, str) is True:
				if len(self.secret) != 24:
					raise Exception('Incorrect DES3 key! %s' % self.secret)
			elif isinstance(self.secret, bytearray) is True:
				if len(self.secret) != 12:
					raise Exception('Incorrect DES3 key! %s' % self.secret)
			res.kerberos_key_des3 = self.secret
		elif self.stype == asyauthSecret.NONE:
			res.nopreauth = True
		else:
			raise Exception('Missing/unknown stype! %s' % self.stype)

		return res

	def build_context(self, *args, **kwargs):
		if self.subprotocol.type == asyauthSubProtocol.NATIVE:
			from asyauth.protocols.kerberos.client.native import KerberosClientNative
			return KerberosClientNative(self)

		elif self.subprotocol.type == asyauthSubProtocol.SSPI:
			from asyauth.protocols.kerberos.client.sspi import KerberosClientSSPI
			return KerberosClientSSPI(self)

		elif self.subprotocol.type == asyauthSubProtocol.SSPIPROXY:
			from asyauth.protocols.kerberos.client.sspiproxy import KerberosClientSSPIProxy
			return KerberosClientSSPIProxy(self)

		elif self.subprotocol.type == asyauthSubProtocol.WSNET:
			from asyauth.protocols.kerberos.client.wsnet import KerberosClientWSNET
			return KerberosClientWSNET(self)
		elif self.subprotocol.type == asyauthSubProtocol.WSNETDIRECT:
			from asyauth.protocols.kerberos.client.wsnetdirect import KerberosClientWSNETDirect
			return KerberosClientWSNETDirect(self)
		elif self.subprotocol.type == asyauthSubProtocol.CUSTOM:
			return self.subprotocol.factoryobj.build_context(self)
		else:
			raise Exception('Unsupported subprotocol "%s"' % self.subprotocol)

