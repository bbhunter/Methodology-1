# External Network Penetration Testing


### Passive External Network Reconnaissance
- Google Dorks (GHDB), bing dorks
- Pastebin
https://github.com/leapsecurity/Pastepwnd
https://github.com/CIRCL/AIL-framework
https://github.com/cvandeplas/pystemon
https://github.com/xme/pastemon
- crt.sh
- https://certstream.calidog.io/
- spiderfoot
https://github.com/smicallef/spiderfoot
- Exposed credentials and leaks (Flare, dehashed, breach-parse)
- Social networks (linkedIn, hunter.io, clearbit, phonebook.cz, Facebook, Company twitter/instagram)
- DNS history
- ASN
- Wayback machine, google cache

### Active External Network Reconnaissance
- masscan
- censys
- shodan
- scans.io
- nmap
- DNS brute force (aiodnsbrute, subLocal)
- Aquatone
- DNS zone transfer
- subdomain takeover

#### User account enumeration
On web app portal

### Exposed services - Protocols
#### HTTP/HTTPS

#### SMTP

#### SNMP
- snmpget
- onesixtyone

```
for i in $(cat onesixtyone/dict.txt); do echo -n "$i : "; snmpget -v 3 -u $i udp6:[IPv6] MIB_TO_FETCH; done
```

#### FTP

#### SSH

#### Databases (MySQL, MSSQL, Oracle, DB2, Postgre, MongoDB...)

### Exposed storages
- AWS S3 buckets
- Azure blob storage
- GCP storage

### Scanning external target
- Nessus, Burp Enterprise, Qualys, nuclei, wpscan, joomscan...
http://www.melcara.com/wp-content/uploads/2017/09/parse_nessus_xml.v24.pl_.zip

### Exploitation

#### RCE
RCE-as-a-feature (Jenkins, Serv-U, etc).

#### Exposed source code or credentials
- .git folder
- Access key, token, secret on github, gitlab, mercurial, code repo solutions...

#### IIS specific checks

#### Web vulnerabilities
- serialization/deserialization

#### Password spray
(o365, Azure, Citrix, RDP, VPN, OWA, etc)

#### 2FA/MFA implementation issues

#### SSL/TLS
- heartbleed
- Shellshock

