import ctypes
import random
import string
from enum import Enum

from asn1crypto import core
from minikerberos.protocol.asn1_structs import TAG, PrincipalName


class PAC_CREDENTIAL_INFO(ctypes.Structure):
    _fields_ = [("Version", ctypes.c_uint32),
                ("EncryptionType", ctypes.c_uint32),
                ("SerializedData", ctypes.c_char * 1)
                ]

class PAC_INFO_BUFFER(ctypes.Structure):
    _fields_ = [("ulType", ctypes.c_uint32),
                ("cbBufferSize", ctypes.c_uint32),
                ("Offset", ctypes.c_ulonglong)
                ]

class PACTYPE(ctypes.Structure):
    _fields_ = [("cBuffers", ctypes.c_uint32),
                ("Version", ctypes.c_uint32),
                ("Buffers", PAC_INFO_BUFFER * 1)
                ]

class Extensions(ctypes.BigEndianStructure):
    _fields_ = [("data_type", ctypes.c_int), # 4 byte data type
                ("data_length", ctypes.c_int) # 4 byte data length
                ]

def GenerateExtensions(data):
    extensions = Extensions()
    extensions.data_type = 2
    extensions.data_length = len(data)
    return Pack(extensions) + data.hex()

class LSAP_TOKEN_INFO_INTEGRITY(ctypes.Structure):
    _fields_ = [("Flags", ctypes.c_uint32), # 0 for full token and 1 for UAC
                ("TokenIL", ctypes.c_uint32), # 0 for Untrusted, 1000 low, 2000 medium the high, system and protected process
                ("MachineID", ctypes.c_char * 32) # 32 byte binary random string
                ]

def generateRandom(stringLength=32):
    letters = string.ascii_lowercase
    numbers = ''.join(str(i) for i in range(10))
    return ''.join(random.choice(letters + numbers) for i in range(stringLength))

class WST_MESSAGE_TYPE(Enum):
    WST_MESSAGE_TYPE_CLIENT_HELLO = 0
    WST_MESSAGE_TYPE_SERVER_HELLO = 1
    WST_MESSAGE_TYPE_CLIENT_META_DATA = 2
    WST_MESSAGE_TYPE_SERVER_META_DATA = 3
    WST_MESSAGE_TYPE_CHALLENGE = 4
    WST_MESSAGE_TYPE_AP_REQUEST = 5
    WST_MESSAGE_TYPE_VERIFY = 6
    WST_MESSAGE_TYPE_ALERT = 7

class MessageTypes(Enum):
    INITIATOR_NEGO = 0
    ACCEPTOR_NEGO = 1
    INITIATOR_META_DATA = 2
    ACCEPTOR_META_DATA = 3
    CHALLENGE = 4
    AP_REQUEST = 5
    VERIFY = 6

class _WST_AUTH_SCHEME_VECTOR(ctypes.Structure):
    _fields_ = [("AuthSchemeArrayOffset", ctypes.c_uint32),
                ("AuthSchemeCount", ctypes.c_ushort),
                ("AuthSchemePad", ctypes.c_ushort)
                ]

class _WST_EXTENSION_VECTOR(ctypes.Structure):
    _fields_ = [("ExtensionArrayOffset", ctypes.c_uint32),
                ("ExtensionCount", ctypes.c_ushort),
                ("ExtensionPad", ctypes.c_ushort)
                ]

class WST_MESSAGE_SIGNATURE(ctypes.BigEndianStructure):
    _pack_ = 1
    _fields_ = [("Signature", ctypes.c_ulonglong)
    ]

class WST_BYTE_VECTOR(ctypes.LittleEndianStructure):
    _fields_ = [("ExchangeOffset", ctypes.c_uint32),
                ("ExchangeByteCount", ctypes.c_ushort),
                ("ExchangePad", ctypes.c_ushort)
                ]

class _WST_CHECKSUM(ctypes.Structure):
    _fields_ = [("cbHeaderLength", ctypes.c_uint32),
                ("ChecksumScheme", ctypes.c_uint32),
                ("ChecksumType", ctypes.c_uint32),
                ("ChecksumValue", WST_BYTE_VECTOR)
                ]

class WST_MESSAGE_HEADER(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [("Signature", WST_MESSAGE_SIGNATURE),
                ("MessageType", ctypes.c_int),
                ("SequenceNum", ctypes.c_uint32),
                ("cbHeaderLength", ctypes.c_uint32),
                ("cbMessageLength", ctypes.c_uint32),
                ("ConversationId", ctypes.c_ubyte * 16)
                ]

class WST_EXCHANGE_MESSAGE(ctypes.BigEndianStructure):
    _fields_ = [("Header", WST_MESSAGE_HEADER),
                ("AuthScheme", ctypes.c_ubyte * 16),
                ("Exchange", WST_BYTE_VECTOR)
                ]

class _WST_HELLO_MESSAGE(ctypes.BigEndianStructure):
    _fields_ = [("Header", WST_MESSAGE_HEADER),
                ("Random", ctypes.c_ubyte * 32),
                ("ProtocolVersion", ctypes.c_ulonglong),
                ("AuthSchemes", _WST_AUTH_SCHEME_VECTOR),
                ("Extensions", _WST_EXTENSION_VECTOR),
                ("AuthScheme", ctypes.c_ubyte * 16)
                ]

class _WST_VERIFY_MESSAGE(ctypes.BigEndianStructure):
    _fields_ = [("Header", WST_MESSAGE_HEADER),
                ("AuthScheme", ctypes.c_ubyte * 16),
                ("Checksum", _WST_CHECKSUM)
                ]

class PkAuth(ctypes.Structure):
    _fields_ = [("cusec", ctypes.c_int),
                ("time", ctypes.c_ubyte * 16),
                ("nonce", ctypes.c_int),
                ("pachecksum", ctypes.c_ubyte * 0)
                ]

class SMB2_SESSION_SETUP_RESPONSE(ctypes.Structure):
    _fields_ = [("StructureSize", ctypes.c_ubyte * 2),
                ("SessionFlags", ctypes.c_ubyte * 2),
                ("SecurityBufferOffset", ctypes.c_ubyte * 2),
                ("SecurityBufferLength", ctypes.c_ubyte * 2),
                ("Buffer", ctypes.c_uint32)
                ]

class CertIssuer(core.Sequence):
    _fields = [
        ('1', core.ObjectIdentifier),
        ('Info', core.BMPString)
    ]

class CertIssuers(core.Sequence):
    _fields = [
        ('certIssuer', core.Any, {'tag_type': TAG, 'tag': 0})
    ]

class SetOfCertIssuers(core.SetOf):
    _child_spec = CertIssuer

class SequenceCertIssuers2(core.Sequence):
    _fields = [
        ('certIssuers', SetOfCertIssuers)
    ]

class SequenceCertIssuers(core.Sequence):
    class_ = 2
    method = 0
    tag = 0
    _fields = [
        ('certIssuers', SequenceCertIssuers2)
    ]

class ClientInformation(core.Sequence):
    _fields = [
        ('pku2u', core.GeneralString, {'tag_type': TAG, 'tag': 0}),
        ('information', PrincipalName, {'tag_type': TAG, 'tag': 1})
    ]

class Seq1(core.Sequence):
    _fields = [
        ('1', SequenceCertIssuers)
    ]

class Seq2(core.Sequence):
    _fields = [
        ('2', Seq1)
    ]

class MetaData(core.Sequence):
    _fields = [
        ('SequenceCertIssuers', Seq2, {'tag_type': TAG, 'tag': 0}),
        ('ClientInfo', ClientInformation, {'tag_type': TAG, 'tag': 1})
    ]


def generateMetaDataAsn(remoteComputer, issuer):
    certIssuer = {'1': '2.5.4.3', 'Info': issuer}
    setOfCertIssuers = [certIssuer]
    sequenceCertIssuers = {'certIssuers': setOfCertIssuers}
    seq1 = {'1': SequenceCertIssuers({'certIssuers': SequenceCertIssuers2(sequenceCertIssuers)})}
    seq2 = {'2': seq1}

    clientInformation = {'pku2u': "WELLKNOWN:PKU2U",
        'information': PrincipalName({'name-type': -128, 'name-string': [remoteComputer]})}

    data = {}
    data['ClientInfo'] = ClientInformation(clientInformation)
    data['SequenceCertIssuers'] = Seq2(seq2)

    data = MetaData(data).dump().hex()

    return data


toHex = lambda x: "".join([hex(c)[2:].zfill(2) for c in x])

def Pack(ctype_instance):
    buf = toHex(ctypes.string_at(ctypes.byref(ctype_instance), ctypes.sizeof(ctype_instance)))
    return buf

def Unpack(ctype, buf):
    cstring = ctypes.create_string_buffer(buf)
    ctype_instance = ctypes.cast(ctypes.pointer(cstring), ctypes.POINTER(ctype)).contents
    return ctype_instance

def generateInitiatorNego():
    d = '3bfe3cf76c6d01ea3aff5261bf7d0a4a'
    L = [int(a+b,16) for a,b in zip(d[0::2],d[1::2])] # change from d to CONVERSATION_ID

    guidIn16Bytes = (ctypes.c_ubyte * 16)(*L)


    longnegoex = int(toHex("NEGOEXTS"),16)

    authschem = '5c33530deaf90d4db2ec4ae3786ec308'
    authsc = [int(a + b, 16) for a, b in zip(authschem[0::2], authschem[1::2])]  # change from d to AUTH_SCHEME
    authschemIn16Bytes = (ctypes.c_ubyte * 16)(*authsc)

    ran = 'ffaf0c135369c5075ae3868ec6364dea9615ab5bb22e6c708cf18c133696dd57'
    R = [int(a+b,16) for a,b in zip(ran[0::2],ran[1::2])] # change from d to RANDOM
    randomIn32Bytes = (ctypes.c_ubyte * 32)(*R)

    signature = WST_MESSAGE_SIGNATURE(longnegoex)

    # no need to change
    extenstion = _WST_EXTENSION_VECTOR(0,
                                       0,
                                       0)

    authScheme = _WST_AUTH_SCHEME_VECTOR(96,
                                        1,
                                        0)

    header = WST_MESSAGE_HEADER(signature,
                                0,
                                0, # should start as 0
                                96,
                                112, # should be calculated as all initiator nego
                                guidIn16Bytes
                                )

    initNego = _WST_HELLO_MESSAGE(header,
                                   randomIn32Bytes, # should be generateRandom(),
                                   0,
                                   authScheme,
                                   extenstion,
                                   authschemIn16Bytes)

    return Pack(initNego)


def splitStructs(data, nego):
    # each struct statswith NEGOEXTS
    structs = data.split(bytes("NEGOEXTS", 'utf-8').hex())
    returnStructs = [bytes("NEGOEXTS", 'utf-8').hex() + i for i in structs if i != '']
    # raise sequence number for every struct got
    for struct in structs:
        if struct == '':
            continue
        nego.raiseSequenceNum() 
    for struct in structs:
        if struct == '':
            continue
        if struct.startswith("{0:0{1}x}".format(MessageTypes.CHALLENGE.value, 2)):
            structData = bytes("NEGOEXTS", 'utf-8').hex() + struct
            
            exchange = Unpack(WST_EXCHANGE_MESSAGE, bytes.fromhex(structData))._fields_[2][1]
            # exchange starts from header + authscheme (40 + 16)
            # then we calculate ExchangeByteCount, ExchangeOffset, ExchangePad
            # and then AS response starts
            return structData[(40 + 16 + exchange.ExchangeByteCount.size + exchange.ExchangeOffset.size + exchange.ExchangePad.size) * 2:], returnStructs

def toLitEndian(hexStream):
    lis = [ hexStream[i:i+2] for i in range(0, len(hexStream), 2) ]
    lis.reverse()
    return ''.join(lis) 
