import ctypes
import random
import string

from impacket.krb5.constants import ChecksumTypes
from impacket.krb5.crypto import Enctype, Key, _checksum_table
from impacket.uuid import generate

from .structs import (
    _WST_AUTH_SCHEME_VECTOR, _WST_CHECKSUM, _WST_EXTENSION_VECTOR, _WST_HELLO_MESSAGE, _WST_VERIFY_MESSAGE,
    WST_BYTE_VECTOR, WST_EXCHANGE_MESSAGE, WST_MESSAGE_HEADER, WST_MESSAGE_SIGNATURE, WST_MESSAGE_TYPE, Pack)


def generateRandom(stringLength=32):
    letters = string.ascii_lowercase
    numbers = ''.join(str(i) for i in range(10))
    return ''.join(random.choice(letters + numbers) for i in range(stringLength))

toHex = lambda x: "".join([hex(ord(c))[2:].zfill(2) for c in x])

class Negoex:
    def __init__(self):
        self.conversation_id = generate().hex()
        self.authscheme = '5c33530deaf90d4db2ec4ae3786ec308'
        self.random = generateRandom().encode('utf-8').hex()
        self.negoexHeader = int(toHex("NEGOEXTS"),16)
        PconvId = [int(a+b,16) for a,b in zip(self.conversation_id[0::2],self.conversation_id[1::2])]
        PauthScheme = [int(a + b, 16) for a, b in zip(self.authscheme[0::2], self.authscheme[1::2])]
        Prandom = [int(a + b, 16) for a, b in zip(self.random[0::2], self.random[1::2])]
        self.convId16Byte = (ctypes.c_ubyte * 16)(*PconvId)
        self.authScheme16Byte = (ctypes.c_ubyte * 16)(*PauthScheme)
        self.random32Byte = (ctypes.c_ubyte * 32)(*Prandom)
        self.sequenceNum = 0

    def generateInitiatorNego(self):
        signature = WST_MESSAGE_SIGNATURE(self.negoexHeader)

        # no need to change
        extention = _WST_EXTENSION_VECTOR(0,
                                           0,
                                           0)

        authscheme = _WST_AUTH_SCHEME_VECTOR(96,
                                             1,
                                             0)

        header = WST_MESSAGE_HEADER(signature,
                                    WST_MESSAGE_TYPE.WST_MESSAGE_TYPE_CLIENT_HELLO.value,
                                    0,  # should start as 0
                                    96,
                                    112,  # should be calculated as all initiator nego
                                    self.convId16Byte
                                    )
        
        struct_bytes = ctypes.string_at(ctypes.addressof(header), ctypes.sizeof(header))
        initnego = _WST_HELLO_MESSAGE(header,
                                      self.random32Byte,  # should be generateRandom(),
                                      0,
                                      authscheme,
                                      extention,
                                      self.authScheme16Byte)

        self.sequenceNum += 1
        return Pack(initnego)

    def generateMetaData(self, data):
        signature = WST_MESSAGE_SIGNATURE(self.negoexHeader)

        header2 = WST_MESSAGE_HEADER(signature,
                                     2,
                                     self.sequenceNum,
                                     0,  # change to ctypes.sizeof(header) + 8,
                                     207,  # should be 112,  # should be calculated as all initiator nego
                                     self.convId16Byte
                                     )
        
        exchange2 = WST_BYTE_VECTOR(64,  # should be ctypes.sizeof(header) + 8,
                                    int(len(data) / 2),
                                    0)

        exchangeMsg2 = WST_EXCHANGE_MESSAGE(header2,
                                            self.authScheme16Byte,
                                            exchange2)

        header = WST_MESSAGE_HEADER(signature,
                                    WST_MESSAGE_TYPE.WST_MESSAGE_TYPE_CLIENT_META_DATA.value,
                                    self.sequenceNum,
                                    ctypes.sizeof(header2) + 24,
                                    ctypes.sizeof(exchangeMsg2) + int(len(data) / 2),
                                    self.convId16Byte
                                    )

        exchange = WST_BYTE_VECTOR(ctypes.sizeof(header) + 24,
                                   int(len(data) / 2),
                                   0)

        exchangeMsg = WST_EXCHANGE_MESSAGE(header,
                                           self.authScheme16Byte,
                                           exchange)

        self.sequenceNum += 1
        return Pack(exchangeMsg) + data

    def generateAPRequest(self,data=None):  # same struct as meta data
        signature = WST_MESSAGE_SIGNATURE(self.negoexHeader)

        header2 = WST_MESSAGE_HEADER(signature,
                                     5,
                                     self.sequenceNum,
                                     0,
                                     0,
                                     self.convId16Byte
                                     )
        
        exchange2 = WST_BYTE_VECTOR(64,  # should be ctypes.sizeof(header) + 8,
                                    int(len(data) / 2),
                                    0)

        exchangeMsg2 = WST_EXCHANGE_MESSAGE(header2,
                                            self.authScheme16Byte,
                                            exchange2)

        header = WST_MESSAGE_HEADER(signature,
                                    WST_MESSAGE_TYPE.WST_MESSAGE_TYPE_AP_REQUEST.value,
                                    self.sequenceNum,
                                    ctypes.sizeof(header2) + 24,
                                    ctypes.sizeof(exchangeMsg2) + int(len(data) / 2),
                                    self.convId16Byte
                                    )

        exchange = WST_BYTE_VECTOR(ctypes.sizeof(header) + 24,
                                   int(len(data) / 2),
                                   0)

        ApRequestMsg = WST_EXCHANGE_MESSAGE(header,
                                            self.authScheme16Byte,
                                            exchange)
        self.sequenceNum += 1
        return Pack(ApRequestMsg) + data

    def generateVerify(self, checksumToSend='000000000000000000000001'): # check if correct
        signature = WST_MESSAGE_SIGNATURE(self.negoexHeader)

        header2 = WST_MESSAGE_HEADER(signature,
                                     WST_MESSAGE_TYPE.WST_MESSAGE_TYPE_VERIFY.value,
                                     self.sequenceNum,
                                     0,
                                     0,
                                     self.convId16Byte
                                     )

        checksumvector2 = WST_BYTE_VECTOR(0,
                                          int(len(checksumToSend) / 2),
                                          0)

        checksum2 = _WST_CHECKSUM(0,
                                  1,
                                  16,
                                  checksumvector2)

        verify2 = _WST_VERIFY_MESSAGE(header2,
                                      self.authScheme16Byte,
                                      checksum2)

        header = WST_MESSAGE_HEADER(signature,
                                     WST_MESSAGE_TYPE.WST_MESSAGE_TYPE_VERIFY.value,
                                     self.sequenceNum,
                                     # changed to 80 as the first header and second
                                     80,#ctypes.sizeof(header2) + 24,
                                     int(ctypes.sizeof(verify2) + len(checksumToSend) / 2),
                                     self.convId16Byte
                                     )

        checksumvector = WST_BYTE_VECTOR(ctypes.sizeof(verify2),
                                          int(len(checksumToSend) / 2),
                                          0)

        checksum = _WST_CHECKSUM(ctypes.sizeof(checksum2),
                                  1,
                                  16,
                                  checksumvector)

        verify = _WST_VERIFY_MESSAGE(header,
                                      self.authScheme16Byte,
                                      checksum)

        self.sequenceNum += 1
        return Pack(verify) + checksumToSend

    def negoexInit(self, metaData):
        initNego = self.generateInitiatorNego()
        return initNego + self.generateMetaData(metaData)

    def negoexAsRequest(self, metaData, data):
        # create data from kerberos as request and send to generateAPRequest
        initNego = self.generateInitiatorNego()
        return initNego + self.generateMetaData(metaData) + self.generateAPRequest(data)

    def negoexApRequest(self, data, privData):
        # create data from keberos as normal ap request with data from as response and send it to generateAPRequest
        # create data as checksum of all previous packets to send to generateVerify
        apReq = self.generateAPRequest(data)
        checksumtype = _checksum_table[ChecksumTypes.hmac_sha1_96_aes256.value]
        keyServer = Key(Enctype.AES256, bytes.fromhex('fb3f5b9cb2e387a5815d57e672978a118c22404938b279bbd4e29e1505cac2c3'))
        checksumToSend = checksumtype.checksum(keyServer, 25, bytes.fromhex(privData + apReq)).hex()
        return apReq + self.generateVerify(checksumToSend=checksumToSend)

    def negoexProcess(self):
        return self.generateInitiatorNego() + self.generateMetaData()

    def raiseSequenceNum(self):
        self.sequenceNum += 1
