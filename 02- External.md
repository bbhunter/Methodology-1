# External Network Penetration Testing

## Reconnaissance
### Passive External Network Reconnaissance
- Google Dorks (GHDB), bing dorks
- Pastebin
https://github.com/carlospolop/Pastos
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
https://bgp.he.net/dns/company.com#_ipinfo

- Wayback machine, google cache

### Active External Network Reconnaissance
- masscan
- censys
- shodan
- scans.io
- DNS brute force (aiodnsbrute, subLocal)
amass, sublist3r
https://0xffsec.com/handbook/information-gathering/subdomain-enumeration/#asn-enumeration

- Aquatone, Eyewitness, Shutter
- DNS zone transfer
- subdomain takeover

#### NMAP
- NSE scripts : 14 categories
  - auth
  - broadcast
  - brute
  - default
  - discovery
  - dos (not recommanded)
  - exploit
  - external
  - fuzzer
  - intrusive
  - malware
  - safe
  - version
  - vuln

Scanning /24 IP range with UDP and TCP scan using SMB NSE script.
```
nmap -sU -sT -p U:137,139,T:22,21,80,443,139,445 --script=smb2-security-mode.nse 192.168.0.10/24
```

#### Recon-NG 
- https://github.com/lanmaster53/recon-ng

### User account enumeration
On web app portal

### Exposed documents - Metadata
- Foca

### Virtual Host
- https://wya.pl/2022/06/16/virtual-hosting-a-well-forgotten-enumeration-technique/

## BGP Hijacking
- [BGP Deep Dive](https://www.youtube.com/watch?v=SVo6cDnQQm0)
- https://www.youtube.com/watch?v=oESNgliRar0
- [Breaking HTTPS with BGP Hijacking](https://www.youtube.com/watch?v=iG5rIqgKuK4)
- Pentest Mag - [BGP Hijacking](https://pentestmag.com/bgp-hijacking-attack/)
- [NIST SP-800-54 - BGP Security](https://www.wired.com/images_blogs/threatlevel/files/nist_on_bgp_security.pdf)
- [Defcon 16 - Stealing the Internet](https://www.youtube.com/watch?v=S0BM6aB90n8)

## Exposed services - Protocols

### HTTP/HTTPS

### SMTP

### DKIM / DMARC / SPF misconfiguration
https://github.com/BishopFox/spoofcheck.git
https://github.com/Mr-Un1k0d3r/SPFAbuse

### SNMP
- snmpget
- onesixtyone

```
for i in $(cat onesixtyone/dict.txt); do echo -n "$i : "; snmpget -v 3 -u $i udp6:[IPv6] MIB_TO_FETCH; done
```

### FTP

### SSH

### Databases (MySQL, MSSQL, Oracle, DB2, Postgre, MongoDB...)

### Exposed storages
- AWS S3 buckets
- Azure blob storage
- GCP storage

### Scanning external target
- Nessus, Burp Enterprise, Qualys, nuclei, wpscan, joomscan...
http://www.melcara.com/wp-content/uploads/2017/09/parse_nessus_xml.v24.pl_.zip








## Exploitation
### RCE
RCE-as-a-feature (Jenkins, Serv-U, etc).
- https://github.com/p0dalirius/Awesome-RCE-techniques

### Exposed source code or credentials
- .git folder
- Access key, token, secret on github, gitlab, mercurial, code repo solutions...
Git / Repo secret parsers

    gitleaks (https://github.com/zricethezav/gitleaks)
    trufflehog (https://github.com/trufflesecurity/truffleHog)
    git-secrets (https://github.com/awslabs/git-secrets)
    shhgit (https://github.com/eth0izzle/shhgit)
    gitrob (https://github.com/michenriksen/gitrob)

### SAP
- https://book.hacktricks.xyz/network-services-pentesting/pentesting-sap
  
### Lync
- https://www.mdsec.co.uk/2017/04/penetration-testing-skype-for-business-exploiting-the-missing-lync/
- https://www.trustedsec.com/blog/attacking-self-hosted-skype-businessmicrosoft-lync-installations/
- https://github.com/mdsecresearch/LyncSniper

### IIS specific checks

### Web vulnerabilities
- serialization/deserialization

### Default Credentials in use


### Open SMTP Relay
- https://www.blackhillsinfosec.com/how-to-test-for-open-mail-relays/

### DNS Zone Transfer


### VPN - IKE Aggressive Mode

## Password spray
(o365, Azure, Citrix, RDP, VPN, OWA, etc)

#### General tool
- https://github.com/knavesec/CredMaster

The following plugins are currently supported:
- OWA - Outlook Web Access
- EWS - Exchange Web Services
- O365 - Office365
- O365Enum - Office365 User Enum (No Authentication Request)
- MSOL - Microsoft Online
- Okta - Okta Authentication Portal
- FortinetVPN - Fortinet VPN Client
- HTTPBrute - Generic HTTP Brute Methods (Basic/Digest/NTLM)
- ADFS - Active Directory Federation Services
- AzureSSO - Azure AD Seamless SSO Endpoint
- GmailEnum - Gmail User Enumeration (No Authentication Request)

#### CheckPoint SSL VPN 
- https://github.com/lutzenfried/checkpointSpray

#### O365
- https://github.com/SecurityRiskAdvisors/msspray
- https://github.com/blacklanternsecurity/TREVORspray

```
 ./trevorspray.py -e emails.txt --passwords "Winter2021!"  --delay 15 --no-current-ip --ssh ubuntu@<IP> ubuntu2@<IP2> -k privkey.pem
 ```

#### OWA
Metasploit module : ```scanner/http/owa_login```

#### Azure
- https://github.com/dafthack/MSOLSpray
- https://github.com/blacklanternsecurity/TREVORspray

### IP rotation
Sometimes during password spraying or brute force attack attacker will need to rotate IP and geolocation to avoid being blocked.

- Burp Extension: IPRotate
- RhinoSecurity Blog : https://rhinosecuritylabs.com/aws/bypassing-ip-based-blocking-aws/
- AWS Keys Setup : https://www.youtube.com/watch?v=_YQLao6p9GM
- Proxycannon https://www.blackhillsinfosec.com/using-burp-proxycannon/
- BHIS blog (https://www.blackhillsinfosec.com/how-to-rotate-your-source-ip-address/)
- Amazon Lambda
- Fireprox

### 2FA/MFA implementation issues
​
[MFASweep](https://github.com/dafthack/MFASweep): Detect MFA for various Microsoft Servers
Credsniper
Re-using valid credentials on alternate services
Mailsniper

- https://infosecwriteups.com/all-about-multi-factor-authentication-security-bypass-f1a95f9b6362
- https://medium.com/proferosec-osm/multi-factor-authentication-in-the-wild-bypass-methods-689f53f0b62b

### SSL/TLS
- heartbleed
- Shellshock



https://www.foregenix.com/blog/know-your-attack-surfaces
