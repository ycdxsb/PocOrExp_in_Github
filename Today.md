# Update 2021-10-13
## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/0xAlmighty/CVE-2021-41773-PoC](https://github.com/0xAlmighty/CVE-2021-41773-PoC) :  ![starts](https://img.shields.io/github/stars/0xAlmighty/CVE-2021-41773-PoC.svg) ![forks](https://img.shields.io/github/forks/0xAlmighty/CVE-2021-41773-PoC.svg)


## CVE-2021-34486
 Windows Event Tracing Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-26425, CVE-2021-34487.

- [https://github.com/KaLendsi/CVE-2021-34486](https://github.com/KaLendsi/CVE-2021-34486) :  ![starts](https://img.shields.io/github/stars/KaLendsi/CVE-2021-34486.svg) ![forks](https://img.shields.io/github/forks/KaLendsi/CVE-2021-34486.svg)


## CVE-2021-33045
 The identity authentication bypass vulnerability found in some Dahua products during the login process. Attackers can bypass device identity authentication by constructing malicious data packets.

- [https://github.com/dongpohezui/cve-2021-33045](https://github.com/dongpohezui/cve-2021-33045) :  ![starts](https://img.shields.io/github/stars/dongpohezui/cve-2021-33045.svg) ![forks](https://img.shields.io/github/forks/dongpohezui/cve-2021-33045.svg)
- [https://github.com/bp2008/DahuaLoginBypass](https://github.com/bp2008/DahuaLoginBypass) :  ![starts](https://img.shields.io/github/stars/bp2008/DahuaLoginBypass.svg) ![forks](https://img.shields.io/github/forks/bp2008/DahuaLoginBypass.svg)


## CVE-2021-33044
 The identity authentication bypass vulnerability found in some Dahua products during the login process. Attackers can bypass device identity authentication by constructing malicious data packets.

- [https://github.com/bp2008/DahuaLoginBypass](https://github.com/bp2008/DahuaLoginBypass) :  ![starts](https://img.shields.io/github/stars/bp2008/DahuaLoginBypass.svg) ![forks](https://img.shields.io/github/forks/bp2008/DahuaLoginBypass.svg)


## CVE-2021-31796
 An inadequate encryption vulnerability discovered in CyberArk Credential Provider before 12.1 may lead to Information Disclosure. An attacker may realistically have enough information that the number of possible keys (for a credential file) is only one, and the number is usually not higher than 2^36.

- [https://github.com/unmanarc/CACredDecoder](https://github.com/unmanarc/CACredDecoder) :  ![starts](https://img.shields.io/github/stars/unmanarc/CACredDecoder.svg) ![forks](https://img.shields.io/github/forks/unmanarc/CACredDecoder.svg)


## CVE-2021-3129
 Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.

- [https://github.com/hungnt199/CVE-2021-3129_exploit](https://github.com/hungnt199/CVE-2021-3129_exploit) :  ![starts](https://img.shields.io/github/stars/hungnt199/CVE-2021-3129_exploit.svg) ![forks](https://img.shields.io/github/forks/hungnt199/CVE-2021-3129_exploit.svg)


## CVE-2021-1675
 Windows Print Spooler Elevation of Privilege Vulnerability

- [https://github.com/Sirius-RJ/FullstackAcademy-Printernightmare-writeup-2105-E.C.A.R.](https://github.com/Sirius-RJ/FullstackAcademy-Printernightmare-writeup-2105-E.C.A.R.) :  ![starts](https://img.shields.io/github/stars/Sirius-RJ/FullstackAcademy-Printernightmare-writeup-2105-E.C.A.R..svg) ![forks](https://img.shields.io/github/forks/Sirius-RJ/FullstackAcademy-Printernightmare-writeup-2105-E.C.A.R..svg)


## CVE-2019-15858
 admin/includes/class.import.snippet.php in the &quot;Woody ad snippets&quot; plugin before 2.2.5 for WordPress allows unauthenticated options import, as demonstrated by storing an XSS payload for remote code execution.

- [https://github.com/oxctdev/CVE-2019-15858](https://github.com/oxctdev/CVE-2019-15858) :  ![starts](https://img.shields.io/github/stars/oxctdev/CVE-2019-15858.svg) ![forks](https://img.shields.io/github/forks/oxctdev/CVE-2019-15858.svg)


## CVE-2019-9081
 The Illuminate component of Laravel Framework 5.7.x has a deserialization vulnerability that can lead to remote code execution if the content is controllable, related to the __destruct method of the PendingCommand class in PendingCommand.php.

- [https://github.com/hungnt199/CVE-2019-9081_PoC](https://github.com/hungnt199/CVE-2019-9081_PoC) :  ![starts](https://img.shields.io/github/stars/hungnt199/CVE-2019-9081_PoC.svg) ![forks](https://img.shields.io/github/forks/hungnt199/CVE-2019-9081_PoC.svg)


## CVE-2018-12636
 The iThemes Security (better-wp-security) plugin before 7.0.3 for WordPress allows SQL Injection (by attackers with Admin privileges) via the logs page.

- [https://github.com/hungnt199/CVE-2018-12636_exploit](https://github.com/hungnt199/CVE-2018-12636_exploit) :  ![starts](https://img.shields.io/github/stars/hungnt199/CVE-2018-12636_exploit.svg) ![forks](https://img.shields.io/github/forks/hungnt199/CVE-2018-12636_exploit.svg)


## CVE-2018-3810
 Authentication Bypass vulnerability in the Oturia Smart Google Code Inserter plugin before 3.5 for WordPress allows unauthenticated attackers to insert arbitrary JavaScript or HTML code (via the sgcgoogleanalytic parameter) that runs on all pages served by WordPress. The saveGoogleCode() function in smartgooglecode.php does not check if the current request is made by an authorized user, thus allowing any unauthenticated user to successfully update the inserted code.

- [https://github.com/hungnt199/CVE-2018-3810_exploit](https://github.com/hungnt199/CVE-2018-3810_exploit) :  ![starts](https://img.shields.io/github/stars/hungnt199/CVE-2018-3810_exploit.svg) ![forks](https://img.shields.io/github/forks/hungnt199/CVE-2018-3810_exploit.svg)

