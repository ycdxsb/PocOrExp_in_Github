# Update 2023-12-20
## CVE-2023-50164
 An attacker can manipulate file upload params to enable paths traversal and under some circumstances this can lead to uploading a malicious file which can be used to perform Remote Code Execution. Users are recommended to upgrade to versions Struts 2.5.33 or Struts 6.3.0.2 or greater to fix this issue.

- [https://github.com/helsecert/cve-2023-50164](https://github.com/helsecert/cve-2023-50164) :  ![starts](https://img.shields.io/github/stars/helsecert/cve-2023-50164.svg) ![forks](https://img.shields.io/github/forks/helsecert/cve-2023-50164.svg)


## CVE-2023-29484
 In Terminalfour before 8.3.16, misconfigured LDAP users are able to login with an invalid password.

- [https://github.com/SangPenyalang/CVE2023-29484](https://github.com/SangPenyalang/CVE2023-29484) :  ![starts](https://img.shields.io/github/stars/SangPenyalang/CVE2023-29484.svg) ![forks](https://img.shields.io/github/forks/SangPenyalang/CVE2023-29484.svg)


## CVE-2023-28121
 An issue in WooCommerce Payments plugin for WordPress (versions 5.6.1 and lower) allows an unauthenticated attacker to send requests on behalf of an elevated user, like administrator. This allows a remote, unauthenticated attacker to gain admin access on a site that has the affected version of the plugin activated.

- [https://github.com/Jenderal92/WP-CVE-2023-28121](https://github.com/Jenderal92/WP-CVE-2023-28121) :  ![starts](https://img.shields.io/github/stars/Jenderal92/WP-CVE-2023-28121.svg) ![forks](https://img.shields.io/github/forks/Jenderal92/WP-CVE-2023-28121.svg)


## CVE-2023-23752
 An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

- [https://github.com/lainonz/CVE-2023-23752](https://github.com/lainonz/CVE-2023-23752) :  ![starts](https://img.shields.io/github/stars/lainonz/CVE-2023-23752.svg) ![forks](https://img.shields.io/github/forks/lainonz/CVE-2023-23752.svg)


## CVE-2023-6538
 SMU versions prior to 14.8.7825.01 are susceptible to unintended information disclosure, through URL manipulation. Authenticated users in Storage, Server or combined Server+Storage administrative roles are able to access SMU configuration backup, that would normally be barred to those specific administrative roles.

- [https://github.com/Arszilla/CVE-2023-6538](https://github.com/Arszilla/CVE-2023-6538) :  ![starts](https://img.shields.io/github/stars/Arszilla/CVE-2023-6538.svg) ![forks](https://img.shields.io/github/forks/Arszilla/CVE-2023-6538.svg)


## CVE-2023-5808
 SMU versions prior to 14.8.7825.01 are susceptible to unintended information disclosure, through URL manipulation. Authenticated users in a Storage administrative role are able to access HNAS configuration backup and diagnostic data, that would normally be barred to that specific administrative role.

- [https://github.com/Arszilla/CVE-2023-5808](https://github.com/Arszilla/CVE-2023-5808) :  ![starts](https://img.shields.io/github/stars/Arszilla/CVE-2023-5808.svg) ![forks](https://img.shields.io/github/forks/Arszilla/CVE-2023-5808.svg)


## CVE-2023-4863
 Heap buffer overflow in libwebp in Google Chrome prior to 116.0.5845.187 and libwebp 1.3.2 allowed a remote attacker to perform an out of bounds memory write via a crafted HTML page. (Chromium security severity: Critical)

- [https://github.com/caoweiquan322/NotEnough](https://github.com/caoweiquan322/NotEnough) :  ![starts](https://img.shields.io/github/stars/caoweiquan322/NotEnough.svg) ![forks](https://img.shields.io/github/forks/caoweiquan322/NotEnough.svg)


## CVE-2023-3460
 The Ultimate Member WordPress plugin before 2.6.7 does not prevent visitors from creating user accounts with arbitrary capabilities, effectively allowing attackers to create administrator accounts at will. This is actively being exploited in the wild.

- [https://github.com/EmadYaY/CVE-2023-3460](https://github.com/EmadYaY/CVE-2023-3460) :  ![starts](https://img.shields.io/github/stars/EmadYaY/CVE-2023-3460.svg) ![forks](https://img.shields.io/github/forks/EmadYaY/CVE-2023-3460.svg)


## CVE-2023-2732
 The MStore API plugin for WordPress is vulnerable to authentication bypass in versions up to, and including, 3.9.2. This is due to insufficient verification on the user being supplied during the add listing REST API request through the plugin. This makes it possible for unauthenticated attackers to log in as any existing user on the site, such as an administrator, if they have access to the user id.

- [https://github.com/ThatNotEasy/CVE-2023-2732](https://github.com/ThatNotEasy/CVE-2023-2732) :  ![starts](https://img.shields.io/github/stars/ThatNotEasy/CVE-2023-2732.svg) ![forks](https://img.shields.io/github/forks/ThatNotEasy/CVE-2023-2732.svg)


## CVE-2022-41114
 Windows Bind Filter Driver Elevation of Privilege Vulnerability

- [https://github.com/gmh5225/CVE-2022-41114](https://github.com/gmh5225/CVE-2022-41114) :  ![starts](https://img.shields.io/github/stars/gmh5225/CVE-2022-41114.svg) ![forks](https://img.shields.io/github/forks/gmh5225/CVE-2022-41114.svg)


## CVE-2022-3368
 A vulnerability within the Software Updater functionality of Avira Security for Windows allowed an attacker with write access to the filesystem, to escalate his privileges in certain scenarios. The issue was fixed with Avira Security version 1.1.72.30556.

- [https://github.com/Wh04m1001/CVE-2022-3368](https://github.com/Wh04m1001/CVE-2022-3368) :  ![starts](https://img.shields.io/github/stars/Wh04m1001/CVE-2022-3368.svg) ![forks](https://img.shields.io/github/forks/Wh04m1001/CVE-2022-3368.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/LayarKacaSiber/CVE-2021-41773](https://github.com/LayarKacaSiber/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/LayarKacaSiber/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/LayarKacaSiber/CVE-2021-41773.svg)


## CVE-2021-34371
 Neo4j through 3.4.18 (with the shell server enabled) exposes an RMI service that arbitrarily deserializes Java objects, e.g., through setSessionVariable. An attacker can abuse this for remote code execution because there are dependencies with exploitable gadget chains.

- [https://github.com/zwjjustdoit/CVE-2021-34371.jar](https://github.com/zwjjustdoit/CVE-2021-34371.jar) :  ![starts](https://img.shields.io/github/stars/zwjjustdoit/CVE-2021-34371.jar.svg) ![forks](https://img.shields.io/github/forks/zwjjustdoit/CVE-2021-34371.jar.svg)


## CVE-2021-3560
 It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user. This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/curtishoughton/CVE-2021-3560](https://github.com/curtishoughton/CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/curtishoughton/CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/curtishoughton/CVE-2021-3560.svg)


## CVE-2021-3036
 An information exposure through log file vulnerability exists in Palo Alto Networks PAN-OS software where secrets in PAN-OS XML API requests are logged in cleartext to the web server logs when the API is used incorrectly. This vulnerability applies only to PAN-OS appliances that are configured to use the PAN-OS XML API and exists only when a client includes a duplicate API parameter in API requests. Logged information includes the cleartext username, password, and API key of the administrator making the PAN-OS XML API request.

- [https://github.com/0xhaggis/CVE-2021-3064](https://github.com/0xhaggis/CVE-2021-3064) :  ![starts](https://img.shields.io/github/stars/0xhaggis/CVE-2021-3064.svg) ![forks](https://img.shields.io/github/forks/0xhaggis/CVE-2021-3064.svg)


## CVE-2021-1699
 Windows (modem.sys) Information Disclosure Vulnerability

- [https://github.com/waleedassar/CVE-2021-1699](https://github.com/waleedassar/CVE-2021-1699) :  ![starts](https://img.shields.io/github/stars/waleedassar/CVE-2021-1699.svg) ![forks](https://img.shields.io/github/forks/waleedassar/CVE-2021-1699.svg)


## CVE-2020-12124
 A remote command-line injection vulnerability in the /cgi-bin/live_api.cgi endpoint of the WAVLINK WN530H4 M30H4.V5030.190403 allows an attacker to execute arbitrary Linux commands as root without authentication.

- [https://github.com/Scorpion-Security-Labs/CVE-2020-12124](https://github.com/Scorpion-Security-Labs/CVE-2020-12124) :  ![starts](https://img.shields.io/github/stars/Scorpion-Security-Labs/CVE-2020-12124.svg) ![forks](https://img.shields.io/github/forks/Scorpion-Security-Labs/CVE-2020-12124.svg)


## CVE-2020-11651
 An issue was discovered in SaltStack Salt before 2019.2.4 and 3000 before 3000.2. The salt-master process ClearFuncs class does not properly validate method calls. This allows a remote user to access some methods without authentication. These methods can be used to retrieve user tokens from the salt master and/or run arbitrary commands on salt minions.

- [https://github.com/hardsoftsecurity/CVE-2020-11651-PoC](https://github.com/hardsoftsecurity/CVE-2020-11651-PoC) :  ![starts](https://img.shields.io/github/stars/hardsoftsecurity/CVE-2020-11651-PoC.svg) ![forks](https://img.shields.io/github/forks/hardsoftsecurity/CVE-2020-11651-PoC.svg)


## CVE-2019-1040
 A tampering vulnerability exists in Microsoft Windows when a man-in-the-middle attacker is able to successfully bypass the NTLM MIC (Message Integrity Check) protection, aka 'Windows NTLM Tampering Vulnerability'.

- [https://github.com/QAX-A-Team/dcpwn](https://github.com/QAX-A-Team/dcpwn) :  ![starts](https://img.shields.io/github/stars/QAX-A-Team/dcpwn.svg) ![forks](https://img.shields.io/github/forks/QAX-A-Team/dcpwn.svg)


## CVE-2018-19537
 TP-Link Archer C5 devices through V2_160201_US allow remote command execution via shell metacharacters on the wan_dyn_hostname line of a configuration file that is encrypted with the 478DA50BF9E3D2CF key and uploaded through the web GUI by using the web admin account. The default password of admin may be used in some cases.

- [https://github.com/JackDoan/TP-Link-ArcherC5-RCE](https://github.com/JackDoan/TP-Link-ArcherC5-RCE) :  ![starts](https://img.shields.io/github/stars/JackDoan/TP-Link-ArcherC5-RCE.svg) ![forks](https://img.shields.io/github/forks/JackDoan/TP-Link-ArcherC5-RCE.svg)


## CVE-2018-5767
 An issue was discovered on Tenda AC15 V15.03.1.16_multi devices. A remote, unauthenticated attacker can gain remote code execution on the device with a crafted password parameter for the COOKIE header.

- [https://github.com/Scorpion-Security-Labs/CVE-2018-5767-AC9](https://github.com/Scorpion-Security-Labs/CVE-2018-5767-AC9) :  ![starts](https://img.shields.io/github/stars/Scorpion-Security-Labs/CVE-2018-5767-AC9.svg) ![forks](https://img.shields.io/github/forks/Scorpion-Security-Labs/CVE-2018-5767-AC9.svg)


## CVE-2017-18349
 parseObject in Fastjson before 1.2.25, as used in FastjsonEngine in Pippo 1.11.0 and other products, allows remote attackers to execute arbitrary code via a crafted JSON request, as demonstrated by a crafted rmi:// URI in the dataSourceName field of HTTP POST data to the Pippo /json URI, which is mishandled in AjaxApplication.java.

- [https://github.com/h0cksr/Fastjson--CVE-2017-18349-](https://github.com/h0cksr/Fastjson--CVE-2017-18349-) :  ![starts](https://img.shields.io/github/stars/h0cksr/Fastjson--CVE-2017-18349-.svg) ![forks](https://img.shields.io/github/forks/h0cksr/Fastjson--CVE-2017-18349-.svg)


## CVE-2017-7529
 Nginx versions since 0.5.6 up to and including 1.13.2 are vulnerable to integer overflow vulnerability in nginx range filter module resulting into leak of potentially sensitive information triggered by specially crafted request.

- [https://github.com/coolman6942o/-Exploit-CVE-2017-7529](https://github.com/coolman6942o/-Exploit-CVE-2017-7529) :  ![starts](https://img.shields.io/github/stars/coolman6942o/-Exploit-CVE-2017-7529.svg) ![forks](https://img.shields.io/github/forks/coolman6942o/-Exploit-CVE-2017-7529.svg)


## CVE-2012-2122
 sql/password.c in Oracle MySQL 5.1.x before 5.1.63, 5.5.x before 5.5.24, and 5.6.x before 5.6.6, and MariaDB 5.1.x before 5.1.62, 5.2.x before 5.2.12, 5.3.x before 5.3.6, and 5.5.x before 5.5.23, when running in certain environments with certain implementations of the memcmp function, allows remote attackers to bypass authentication by repeatedly authenticating with the same incorrect password, which eventually causes a token comparison to succeed due to an improperly-checked return value.

- [https://github.com/zhangkaibin0921/CVE-2012-2122](https://github.com/zhangkaibin0921/CVE-2012-2122) :  ![starts](https://img.shields.io/github/stars/zhangkaibin0921/CVE-2012-2122.svg) ![forks](https://img.shields.io/github/forks/zhangkaibin0921/CVE-2012-2122.svg)


## CVE-2012-0002
 The Remote Desktop Protocol (RDP) implementation in Microsoft Windows XP SP2 and SP3, Windows Server 2003 SP2, Windows Vista SP2, Windows Server 2008 SP2, R2, and R2 SP1, and Windows 7 Gold and SP1 does not properly process packets in memory, which allows remote attackers to execute arbitrary code by sending crafted RDP packets triggering access to an object that (1) was not properly initialized or (2) is deleted, aka &quot;Remote Desktop Protocol Vulnerability.&quot;

- [https://github.com/zhangkaibin0921/MS12-020-CVE-2012-0002](https://github.com/zhangkaibin0921/MS12-020-CVE-2012-0002) :  ![starts](https://img.shields.io/github/stars/zhangkaibin0921/MS12-020-CVE-2012-0002.svg) ![forks](https://img.shields.io/github/forks/zhangkaibin0921/MS12-020-CVE-2012-0002.svg)


## CVE-2009-1151
 Static code injection vulnerability in setup.php in phpMyAdmin 2.11.x before 2.11.9.5 and 3.x before 3.1.3.1 allows remote attackers to inject arbitrary PHP code into a configuration file via the save action.

- [https://github.com/pagvac/pocs](https://github.com/pagvac/pocs) :  ![starts](https://img.shields.io/github/stars/pagvac/pocs.svg) ![forks](https://img.shields.io/github/forks/pagvac/pocs.svg)

