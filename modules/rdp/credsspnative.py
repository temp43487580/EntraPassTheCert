
import os
import ssl
from hashlib import sha256

from asn1crypto.x509 import Certificate

from asyauth.common.constants import asyauthSecret
from asyauth.protocols.credssp import logger
from asyauth.protocols.spnego.client.native import SPNEGOClientNative
from asyauth.protocols.credssp.messages.asn1_structs import NegoDatas, \
	NegoData, TSRequest, TSRequest, TSPasswordCreds, TSCredentials, \
	TSRemoteGuardCreds, TSRemoteGuardPackageCred, TSCspDataDetail,TSSmartCardCreds

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c

class SSLTunnel:
	#When no certificate is provided, we need to create a SSL tunnel to the server to get the server's public key
	def __init__(self):
		self.ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
		self.ssl_ctx.check_hostname = False
		self.ssl_ctx.verify_mode = ssl.CERT_NONE
		self.ssl_ctx.options |= ssl.OP_NO_COMPRESSION | 0x00000200 | 0x00000800
		self.tls_in_buff = ssl.MemoryBIO()
		self.tls_out_buff = ssl.MemoryBIO()
		self.tls_obj = self.ssl_ctx.wrap_bio(self.tls_in_buff, self.tls_out_buff, server_side=False) # , server_hostname = self.monitor.dst_hostname
		self.handshake_done = False

	def get_peer_certificate(self):
		return self.tls_obj.getpeercert(binary_form=True)

	def data_in(self, data = None):
		if data is not None:
			self.tls_in_buff.write(data)
		
		if self.handshake_done is False:	
			try:
				self.tls_obj.do_handshake()
			except ssl.SSLWantReadError:
				while True:
					client_hello = self.tls_out_buff.read()
					if client_hello != b'':
						#print('DST client_hello %s' % len(client_hello))
						return client_hello
					else:
						break
			except:
				raise
			self.handshake_done = True
		
		buff = b''
		while True:
			try:
				buff += self.tls_obj.read()
			except ssl.SSLWantReadError:
				break
		return buff

	def data_out(self, data:bytes):
		self.tls_obj.write(data)
		
		buff = b''
		while True:
			raw = self.tls_out_buff.read()
			if raw != b'':
				buff += raw
				continue
			break
		return buff


class CredSSPClientNative:
	def __init__(self, credential):
		self.credential = credential
		self.auth_ctx:SPNEGOClientNative = None
		self.cred = None
		self.version = 6
		self.nonce = os.urandom(32)
		self.__internal_auth_continue = True
		self.seqno = 0
		self.__internal_ssl_tunnel = None #CredSSP NEEDS TLS! CredSSP craves TLS!
		self.__pubkey = None
		self.username = None
		self.password= None


	@staticmethod
	def certificate_to_pubkey(certdata):
		# credSSP auth requires knowledge of the server's public key
		cert = Certificate.load(certdata)
		pubkey = cert['tbs_certificate']['subject_public_key_info']['public_key'].contents
		if pubkey[0] == 0x00:
			# padding causes issues
			logger.debug('CredSSP - removing pubkey padding')
			return pubkey[1:]
		logger.debug('CredSSP - pubkey: %s' % pubkey.hex())
		return pubkey
	
	def get_cipher_name(self):
		if self.__internal_ssl_tunnel is None:
			return None
		ciphers = self.__internal_ssl_tunnel.tls_obj.cipher()
		if ciphers is None or len(ciphers) == 0:
			return None
		return ciphers[0]

	def get_extra_info(self):
		return self.auth_ctx.get_extra_info()

	def get_active_credential(self):
		return self.auth_ctx.get_active_credential()
	
	def get_copy(self):
		return self.credential.build_context()

	def get_internal_seq(self):
		return self.seqno

	def get_active_credential(self):
		self.auth_ctx.get_active_credential()
	
	def is_guest(self):
		return self.auth_ctx.is_guest()
	
	def signing_needed(self):
		return self.auth_ctx.signing_needed()
	
	def encryption_needed(self):
		return self.auth_ctx.encryption_needed()

	def get_seq_number(self):
		return self.auth_ctx.get_seq_number()

	async def verify(self, data, signature):
		raise Exception('CredSSP - verify is not supported by the protocol!')

	async def sign(self, data, message_no, direction='init', reset_cipher = False):
		raise Exception('CredSSP - sign is not supported by the protocol!')
		
	async def encrypt(self, data, message_no, *args, **kwargs):
		if self.__internal_ssl_tunnel is None:
			raise Exception('CredSSP - no SSL tunnel available!')
		return self.__internal_ssl_tunnel.data_out(data), None

	async def decrypt(self, data, message_no, *args, **kwargs):
		if self.__internal_ssl_tunnel is None:
			raise Exception('CredSSP - no SSL tunnel available!')
		return self.__internal_ssl_tunnel.data_in(data), None

	def __return(self, data, to_continue, err):
		if self.__internal_ssl_tunnel is not None:
			return self.__internal_ssl_tunnel.data_out(data), to_continue, err
		return data, to_continue, err
	
	async def authenticate(self, token, flags = None, certificate = None, spn = None, remote_credguard = False):
		try:
			# certificate is optional, as the actual usage of this protocol depends on the upper layer
			# In some cases (like RDP) the certificate is provided by the RDP serrver, but this means that CredSSP will not support encryption/decryption in this level
			# In other cases (like WinRM) the certificate is not provided by the upper layer, and CredSSP will need to create an  SSL tunnel itself. In this case support encryption/decryption in this level
			if self.__pubkey is None:
				if certificate is not None:					
					self.__pubkey = CredSSPClientNative.certificate_to_pubkey(certificate)
				elif self.__internal_ssl_tunnel is None:
					print('CredSSP - creating internal SSL tunnel, as no certificate was provided')
					self.__internal_ssl_tunnel = SSLTunnel()
			
			if self.__internal_ssl_tunnel is not None:
				ssldata = self.__internal_ssl_tunnel.data_in(token)
				if self.__internal_ssl_tunnel.handshake_done is True:
					print('CredSSP - SSL tunnel handshake done')
					if self.__pubkey is None:
						self.__pubkey = CredSSPClientNative.certificate_to_pubkey(self.__internal_ssl_tunnel.get_peer_certificate())
					token = ssldata
					if ssldata == b'':
						token = None
				else:
					print('CredSSP - SSL tunnel handshake not done yet')
					return ssldata, True, None
			
			
			if token is None:
				# initial auth
				returndata, self.__internal_auth_continue, err = await self.auth_ctx.authenticate(token, flags = flags, spn = spn)
				if err is not None:
					raise err
					
				negotoken = {
					'negoToken' : returndata
				}
				retoken = {
					'version' : self.version,
					'negoTokens' : NegoDatas([NegoData(negotoken)])
				}
				result = TSRequest(retoken)
				logger.debug('CredSSP - sending initial auth token: %s' % result.native)
				return self.__return(result.dump(), True, None)
			else:
				if self.__internal_auth_continue is True:
					tdata = TSRequest.load(token)
					logger.debug('CredSSP - got token from server: %s' % tdata.native)
					if tdata.native['version'] < self.version:
						logger.debug('[CREDSSP] Server supports version %s which is smaller than our supported version %s' % (tdata.native['version'], self.version))
						self.version = tdata.native['version']
					if tdata.native['negoTokens'] is None:
						raise Exception('PKU2U is not supported by server')
					sspitoken = tdata.native['negoTokens'][0]['negoToken']
					
					try:
						returndata, self.__internal_auth_continue, err = await self.auth_ctx.authenticate(sspitoken, flags = flags, spn = spn)
					except:
						print('[-] failed to login. the target machine might not be Entra-joinned or P2P cert might be expired.')
						raise err
						
					if err is not None:
						raise err
						
					negotoken = {
						'negoToken' : returndata
					}
					retoken = {
						'version' : self.version,
					}
					if returndata is not None:
						
						retoken['negoTokens'] = NegoDatas([NegoData(negotoken)])
					
					
					logger.debug('CredSSP - internal auth continue: %s' % self.__internal_auth_continue)
					if self.__internal_auth_continue is False:
						# self.seqno = self.auth_ctx.get_internal_seq() #spnego might increate a seq number when signing
						self.seqno=0
						if self.version in [5,6]:
							ClientServerHashMagic = b"CredSSP Client-To-Server Binding Hash\x00"
							ClientServerHash = sha256(ClientServerHashMagic + self.nonce + self.__pubkey).digest()
							sealedMessage, signature = await self.auth_ctx.encrypt(ClientServerHash, self.seqno)

							self.seqno += 1
							retoken['pubKeyAuth'] = signature+sealedMessage
							retoken['clientNonce'] = self.nonce
							
						elif self.version in [2,3,4]:
							sealedMessage, signature = await self.auth_ctx.encrypt(self.__pubkey, self.seqno)
							self.seqno += 1
							retoken['pubKeyAuth'] = signature+sealedMessage
							
					
					result = TSRequest(retoken)
					return self.__return(result.dump(), True, None)
				else:
					logger.debug('CredSSP - internal auth finished')
					# sub-level auth protocol finished, now for the other stuff
						
					# waiting for server to reply with the re-encrypted verification string + b'\x01'
					tdata = TSRequest.load(token).native
					if tdata['errorCode'] is not None:
						raise Exception('CredSSP - Server sent an error! Code: %s' % hex(tdata['errorCode'] & (2**32-1)))
					if tdata['pubKeyAuth'] is None:
						raise Exception('Missing pubKeyAuth')
					
					# Verifying server signature
					verification_data, _ = await self.auth_ctx.decrypt(tdata['pubKeyAuth'], 0)
					logger.debug('CredSSP - verification data: %s' % verification_data.hex())
					if self.version in [5,6]:
						ClientServerHashMagic = b"CredSSP Server-To-Client Binding Hash\x00"
						ClientServerHash = sha256(ClientServerHashMagic + self.nonce + self.__pubkey).digest()
						logger.debug('CredSSP - ClientServerHash: %s' % ClientServerHash.hex())
						if verification_data != ClientServerHash:
							raise Exception('CredSSP - Server verification failed!')
					elif self.version in [2,3,4]:
						if verification_data != self.__pubkey:
							raise Exception('CredSSP - Server verification failed!')
					
					# Signatures verified, now we can send the final auth token with the password
					# sending credentials
				
					if remote_credguard is False:
						domain = "AzureAD"

						creds = {
							'domainName' : domain.encode('utf-16-le'),
							'userName'   : self.username.encode('utf-16-le'),
							'password'   : self.password.encode('utf-16-le'),
						}
						
						res = TSPasswordCreds(creds)
						res = TSCredentials({'credType': 1, 'credentials': res.dump()})
						sealedMessage, signature = await self.auth_ctx.encrypt(res.dump(), self.seqno) #seq number must be incremented here..
						self.seqno += 1
						retoken = {
							'version' : self.version,
							'authInfo' : signature+sealedMessage
						}
						result = TSRequest(retoken)
						logger.debug('CredSSP - sending credentials: %s' % result.native)
						return self.__return(result.dump(), False, None)
					else:
						# TODO: implement remote credguard
						print('DO NOT USE THIS! THIS IS NOT IMPLEMENTED YET!')
						credBuffer = b''
						data = {
							'packageName' : 'KERBEROS'.encode('utf-16-le'), #dont forget the encoding!
							'credBuffer' : credBuffer
						}

						remcredguardcreds = TSRemoteGuardCreds({
							'logonCred' : TSRemoteGuardPackageCred(data),
						})

						#print(remcredguardcreds)
						sealedMessage, signature = await self.auth_ctx.encrypt(remcredguardcreds.dump(), self.seqno) #seq number must be incremented here..
						self.seqno += 1
						retoken = {
							'version' : self.version,
							'authInfo' : signature+sealedMessage
						}
						return self.__return(TSRequest(retoken).dump(), False, None)
		except Exception as e:
			return None, None, e