# Update 2023-06-23
## CVE-2023-30347
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/huzefa2212/CVE-2023-30347](https://github.com/huzefa2212/CVE-2023-30347) :  ![starts](https://img.shields.io/github/stars/huzefa2212/CVE-2023-30347.svg) ![forks](https://img.shields.io/github/forks/huzefa2212/CVE-2023-30347.svg)


## CVE-2023-2033
 Type confusion in V8 in Google Chrome prior to 112.0.5615.121 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/gretchenfrage/CVE-2023-2033-analysis](https://github.com/gretchenfrage/CVE-2023-2033-analysis) :  ![starts](https://img.shields.io/github/stars/gretchenfrage/CVE-2023-2033-analysis.svg) ![forks](https://img.shields.io/github/forks/gretchenfrage/CVE-2023-2033-analysis.svg)


## CVE-2022-42475
 A heap-based buffer overflow vulnerability [CWE-122] in FortiOS SSL-VPN 7.2.0 through 7.2.2, 7.0.0 through 7.0.8, 6.4.0 through 6.4.10, 6.2.0 through 6.2.11, 6.0.15 and earlier and FortiProxy SSL-VPN 7.2.0 through 7.2.1, 7.0.7 and earlier may allow a remote unauthenticated attacker to execute arbitrary code or commands via specifically crafted requests.

- [https://github.com/0xhaggis/CVE-2022-42475](https://github.com/0xhaggis/CVE-2022-42475) :  ![starts](https://img.shields.io/github/stars/0xhaggis/CVE-2022-42475.svg) ![forks](https://img.shields.io/github/forks/0xhaggis/CVE-2022-42475.svg)


## CVE-2022-2588
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/konoha279/2022-LPE-UAF](https://github.com/konoha279/2022-LPE-UAF) :  ![starts](https://img.shields.io/github/stars/konoha279/2022-LPE-UAF.svg) ![forks](https://img.shields.io/github/forks/konoha279/2022-LPE-UAF.svg)


## CVE-2021-46704
 In GenieACS 1.2.x before 1.2.8, the UI interface API is vulnerable to unauthenticated OS command injection via the ping host argument (lib/ui/api.ts and lib/ping.ts). The vulnerability arises from insufficient input validation combined with a missing authorization check.

- [https://github.com/Erenlancaster/CVE-2021-46704](https://github.com/Erenlancaster/CVE-2021-46704) :  ![starts](https://img.shields.io/github/stars/Erenlancaster/CVE-2021-46704.svg) ![forks](https://img.shields.io/github/forks/Erenlancaster/CVE-2021-46704.svg)
- [https://github.com/MithatGuner/CVE-2021-46704-POC](https://github.com/MithatGuner/CVE-2021-46704-POC) :  ![starts](https://img.shields.io/github/stars/MithatGuner/CVE-2021-46704-POC.svg) ![forks](https://img.shields.io/github/forks/MithatGuner/CVE-2021-46704-POC.svg)


## CVE-2021-45468
 Imperva Web Application Firewall (WAF) before 2021-12-23 allows remote unauthenticated attackers to use &quot;Content-Encoding: gzip&quot; to evade WAF security controls and send malicious HTTP POST requests to web servers behind the WAF.

- [https://github.com/0xhaggis/Imperva_gzip_bypass](https://github.com/0xhaggis/Imperva_gzip_bypass) :  ![starts](https://img.shields.io/github/stars/0xhaggis/Imperva_gzip_bypass.svg) ![forks](https://img.shields.io/github/forks/0xhaggis/Imperva_gzip_bypass.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/LayarKacaSiber/CVE-2021-41773](https://github.com/LayarKacaSiber/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/LayarKacaSiber/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/LayarKacaSiber/CVE-2021-41773.svg)


## CVE-2021-41277
 Metabase is an open source data analytics platform. In affected versions a security issue has been discovered with the custom GeoJSON map (`admin-&gt;settings-&gt;maps-&gt;custom maps-&gt;add a map`) support and potential local file inclusion (including environment variables). URLs were not validated prior to being loaded. This issue is fixed in a new maintenance release (0.40.5 and 1.40.5), and any subsequent release after that. If you&#8217;re unable to upgrade immediately, you can mitigate this by including rules in your reverse proxy or load balancer or WAF to provide a validation filter before the application.

- [https://github.com/RubXkuB/PoC-Metabase-CVE-2021-41277](https://github.com/RubXkuB/PoC-Metabase-CVE-2021-41277) :  ![starts](https://img.shields.io/github/stars/RubXkuB/PoC-Metabase-CVE-2021-41277.svg) ![forks](https://img.shields.io/github/forks/RubXkuB/PoC-Metabase-CVE-2021-41277.svg)


## CVE-2021-34730
 A vulnerability in the Universal Plug-and-Play (UPnP) service of Cisco Small Business RV110W, RV130, RV130W, and RV215W Routers could allow an unauthenticated, remote attacker to execute arbitrary code or cause an affected device to restart unexpectedly, resulting in a denial of service (DoS) condition. This vulnerability is due to improper validation of incoming UPnP traffic. An attacker could exploit this vulnerability by sending a crafted UPnP request to an affected device. A successful exploit could allow the attacker to execute arbitrary code as the root user on the underlying operating system or cause the device to reload, resulting in a DoS condition. Cisco has not released software updates that address this vulnerability.

- [https://github.com/badmonkey7/CVE-2021-34730](https://github.com/badmonkey7/CVE-2021-34730) :  ![starts](https://img.shields.io/github/stars/badmonkey7/CVE-2021-34730.svg) ![forks](https://img.shields.io/github/forks/badmonkey7/CVE-2021-34730.svg)


## CVE-2021-34473
 Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-31196, CVE-2021-31206.

- [https://github.com/gobysec/Goby](https://github.com/gobysec/Goby) :  ![starts](https://img.shields.io/github/stars/gobysec/Goby.svg) ![forks](https://img.shields.io/github/forks/gobysec/Goby.svg)
- [https://github.com/RaouzRouik/CVE-2021-34473-scanner](https://github.com/RaouzRouik/CVE-2021-34473-scanner) :  ![starts](https://img.shields.io/github/stars/RaouzRouik/CVE-2021-34473-scanner.svg) ![forks](https://img.shields.io/github/forks/RaouzRouik/CVE-2021-34473-scanner.svg)


## CVE-2021-22911
 A improper input sanitization vulnerability exists in Rocket.Chat server 3.11, 3.12 &amp; 3.13 that could lead to unauthenticated NoSQL injection, resulting potentially in RCE.

- [https://github.com/ChrisPritchard/CVE-2021-22911-rust](https://github.com/ChrisPritchard/CVE-2021-22911-rust) :  ![starts](https://img.shields.io/github/stars/ChrisPritchard/CVE-2021-22911-rust.svg) ![forks](https://img.shields.io/github/forks/ChrisPritchard/CVE-2021-22911-rust.svg)


## CVE-2021-3064
 A memory corruption vulnerability exists in Palo Alto Networks GlobalProtect portal and gateway interfaces that enables an unauthenticated network-based attacker to disrupt system processes and potentially execute arbitrary code with root privileges. The attacker must have network access to the GlobalProtect interface to exploit this issue. This issue impacts PAN-OS 8.1 versions earlier than PAN-OS 8.1.17. Prisma Access customers are not impacted by this issue.

- [https://github.com/0xhaggis/CVE-2021-3064](https://github.com/0xhaggis/CVE-2021-3064) :  ![starts](https://img.shields.io/github/stars/0xhaggis/CVE-2021-3064.svg) ![forks](https://img.shields.io/github/forks/0xhaggis/CVE-2021-3064.svg)


## CVE-2021-3036
 An information exposure through log file vulnerability exists in Palo Alto Networks PAN-OS software where secrets in PAN-OS XML API requests are logged in cleartext to the web server logs when the API is used incorrectly. This vulnerability applies only to PAN-OS appliances that are configured to use the PAN-OS XML API and exists only when a client includes a duplicate API parameter in API requests. Logged information includes the cleartext username, password, and API key of the administrator making the PAN-OS XML API request.

- [https://github.com/0xhaggis/CVE-2021-3064](https://github.com/0xhaggis/CVE-2021-3064) :  ![starts](https://img.shields.io/github/stars/0xhaggis/CVE-2021-3064.svg) ![forks](https://img.shields.io/github/forks/0xhaggis/CVE-2021-3064.svg)


## CVE-2019-17662
 ThinVNC 1.0b1 is vulnerable to arbitrary file read, which leads to a compromise of the VNC server. The vulnerability exists even when authentication is turned on during the deployment of the VNC server. The password for authentication is stored in cleartext in a file that can be read via a ../../ThinVnc.ini directory traversal attack vector.

- [https://github.com/medarov411/vnc-lab-cve-2019-17662](https://github.com/medarov411/vnc-lab-cve-2019-17662) :  ![starts](https://img.shields.io/github/stars/medarov411/vnc-lab-cve-2019-17662.svg) ![forks](https://img.shields.io/github/forks/medarov411/vnc-lab-cve-2019-17662.svg)


## CVE-2019-7238
 Sonatype Nexus Repository Manager before 3.15.0 has Incorrect Access Control.

- [https://github.com/jas502n/CVE-2019-7238](https://github.com/jas502n/CVE-2019-7238) :  ![starts](https://img.shields.io/github/stars/jas502n/CVE-2019-7238.svg) ![forks](https://img.shields.io/github/forks/jas502n/CVE-2019-7238.svg)


## CVE-2018-11776
 Apache Struts versions 2.3 to 2.3.34 and 2.5 to 2.5.16 suffer from possible Remote Code Execution when alwaysSelectFullNamespace is true (either by user or a plugin like Convention Plugin) and then: results are used with no namespace and in same time, its upper package have no or wildcard namespace and similar to results, same possibility when using url tag which doesn't have value and action set and in same time, its upper package have no or wildcard namespace.

- [https://github.com/tsong0ku/CVE-2018-11776-FIS](https://github.com/tsong0ku/CVE-2018-11776-FIS) :  ![starts](https://img.shields.io/github/stars/tsong0ku/CVE-2018-11776-FIS.svg) ![forks](https://img.shields.io/github/forks/tsong0ku/CVE-2018-11776-FIS.svg)


## CVE-2016-8025
 SQL injection vulnerability in Intel Security VirusScan Enterprise Linux (VSEL) 2.0.3 (and earlier) allows remote authenticated users to obtain product information via a crafted HTTP request parameter.

- [https://github.com/opsxcq/exploit-CVE-2016-8016-25](https://github.com/opsxcq/exploit-CVE-2016-8016-25) :  ![starts](https://img.shields.io/github/stars/opsxcq/exploit-CVE-2016-8016-25.svg) ![forks](https://img.shields.io/github/forks/opsxcq/exploit-CVE-2016-8016-25.svg)

