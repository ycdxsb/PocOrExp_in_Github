# Update 2021-04-27
## CVE-2021-27905
 The ReplicationHandler (normally registered at &quot;/replication&quot; under a Solr core) in Apache Solr has a &quot;masterUrl&quot; (also &quot;leaderUrl&quot; alias) parameter that is used to designate another ReplicationHandler on another Solr core to replicate index data into the local core. To prevent a SSRF vulnerability, Solr ought to check these parameters against a similar configuration it uses for the &quot;shards&quot; parameter. Prior to this bug getting fixed, it did not. This problem affects essentially all Solr versions prior to it getting fixed in 8.8.2.

- [https://github.com/W2Ning/Solr-SSRF](https://github.com/W2Ning/Solr-SSRF) :  ![starts](https://img.shields.io/github/stars/W2Ning/Solr-SSRF.svg) ![forks](https://img.shields.io/github/forks/W2Ning/Solr-SSRF.svg)


## CVE-2021-3291
 Zen Cart 1.5.7b allows admins to execute arbitrary OS commands by inspecting an HTML radio input element (within the modules edit page) and inserting a command.

- [https://github.com/ImHades101/CVE-2021-3291](https://github.com/ImHades101/CVE-2021-3291) :  ![starts](https://img.shields.io/github/stars/ImHades101/CVE-2021-3291.svg) ![forks](https://img.shields.io/github/forks/ImHades101/CVE-2021-3291.svg)


## CVE-2021-1732
 Windows Win32k Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-1698.

- [https://github.com/exploitblizzard/Windows-Privilege-Escalation-CVE-2021-1732](https://github.com/exploitblizzard/Windows-Privilege-Escalation-CVE-2021-1732) :  ![starts](https://img.shields.io/github/stars/exploitblizzard/Windows-Privilege-Escalation-CVE-2021-1732.svg) ![forks](https://img.shields.io/github/forks/exploitblizzard/Windows-Privilege-Escalation-CVE-2021-1732.svg)


## CVE-2020-24572
 An issue was discovered in includes/webconsole.php in RaspAP 2.5. With authenticated access, an attacker can use a misconfigured (and virtually unrestricted) web console to attack the underlying OS (Raspberry Pi) running this software, and execute commands on the system (including ones for uploading of files and execution of code).

- [https://github.com/gerbsec/CVE-2020-24572-POC](https://github.com/gerbsec/CVE-2020-24572-POC) :  ![starts](https://img.shields.io/github/stars/gerbsec/CVE-2020-24572-POC.svg) ![forks](https://img.shields.io/github/forks/gerbsec/CVE-2020-24572-POC.svg)


## CVE-2020-3161
 A vulnerability in the web server for Cisco IP Phones could allow an unauthenticated, remote attacker to execute code with root privileges or cause a reload of an affected IP phone, resulting in a denial of service (DoS) condition. The vulnerability is due to a lack of proper input validation of HTTP requests. An attacker could exploit this vulnerability by sending a crafted HTTP request to the web server of a targeted device. A successful exploit could allow the attacker to remotely execute code with root privileges or cause a reload of an affected IP phone, resulting in a DoS condition.

- [https://github.com/uromulouinthehouse/CVE-2020-3161](https://github.com/uromulouinthehouse/CVE-2020-3161) :  ![starts](https://img.shields.io/github/stars/uromulouinthehouse/CVE-2020-3161.svg) ![forks](https://img.shields.io/github/forks/uromulouinthehouse/CVE-2020-3161.svg)


## CVE-2018-8611
 An elevation of privilege vulnerability exists when the Windows kernel fails to properly handle objects in memory, aka &quot;Windows Kernel Elevation of Privilege Vulnerability.&quot; This affects Windows 7, Windows Server 2012 R2, Windows RT 8.1, Windows Server 2008, Windows Server 2019, Windows Server 2012, Windows 8.1, Windows Server 2016, Windows Server 2008 R2, Windows 10, Windows 10 Servers.

- [https://github.com/mavillon/cve-2018-8611](https://github.com/mavillon/cve-2018-8611) :  ![starts](https://img.shields.io/github/stars/mavillon/cve-2018-8611.svg) ![forks](https://img.shields.io/github/forks/mavillon/cve-2018-8611.svg)


## CVE-2018-6389
 In WordPress through 4.9.2, unauthenticated attackers can cause a denial of service (resource consumption) by using the large list of registered .js files (from wp-includes/script-loader.php) to construct a series of requests to load every file many times.

- [https://github.com/Elsfa7-110/CVE-2018-6389](https://github.com/Elsfa7-110/CVE-2018-6389) :  ![starts](https://img.shields.io/github/stars/Elsfa7-110/CVE-2018-6389.svg) ![forks](https://img.shields.io/github/forks/Elsfa7-110/CVE-2018-6389.svg)

