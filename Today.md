# Update 2023-05-09
## CVE-2023-23397
 Microsoft Outlook Elevation of Privilege Vulnerability

- [https://github.com/vlad-a-man/CVE-2023-23397](https://github.com/vlad-a-man/CVE-2023-23397) :  ![starts](https://img.shields.io/github/stars/vlad-a-man/CVE-2023-23397.svg) ![forks](https://img.shields.io/github/forks/vlad-a-man/CVE-2023-23397.svg)


## CVE-2023-0386
 A flaw was found in the Linux kernel, where unauthorized access to the execution of the setuid file with capabilities was found in the Linux kernel&#8217;s OverlayFS subsystem in how a user copies a capable file from a nosuid mount into another mount. This uid mapping bug allows a local user to escalate their privileges on the system.

- [https://github.com/CKevens/CVE-2023-0386](https://github.com/CKevens/CVE-2023-0386) :  ![starts](https://img.shields.io/github/stars/CKevens/CVE-2023-0386.svg) ![forks](https://img.shields.io/github/forks/CKevens/CVE-2023-0386.svg)


## CVE-2022-28368
 Dompdf 1.2.1 allows remote code execution via a .php file in the src:url field of an @font-face Cascading Style Sheets (CSS) statement (within an HTML input file).

- [https://github.com/Henryisnotavailable/Dompdf-Exploit-RCE](https://github.com/Henryisnotavailable/Dompdf-Exploit-RCE) :  ![starts](https://img.shields.io/github/stars/Henryisnotavailable/Dompdf-Exploit-RCE.svg) ![forks](https://img.shields.io/github/forks/Henryisnotavailable/Dompdf-Exploit-RCE.svg)


## CVE-2022-21907
 HTTP Protocol Stack Remote Code Execution Vulnerability.

- [https://github.com/Malwareman007/CVE-2022-21907](https://github.com/Malwareman007/CVE-2022-21907) :  ![starts](https://img.shields.io/github/stars/Malwareman007/CVE-2022-21907.svg) ![forks](https://img.shields.io/github/forks/Malwareman007/CVE-2022-21907.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/K3ysTr0K3R/CVE-2021-41773-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2021-41773-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2021-41773-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2021-41773-EXPLOIT.svg)


## CVE-2020-2023
 Kata Containers doesn't restrict containers from accessing the guest's root filesystem device. Malicious containers can exploit this to gain code execution on the guest and masquerade as the kata-agent. This issue affects Kata Containers 1.11 versions earlier than 1.11.1; Kata Containers 1.10 versions earlier than 1.10.5; and Kata Containers 1.9 and earlier versions.

- [https://github.com/ssst0n3/kata-cve-2020-2023-poc](https://github.com/ssst0n3/kata-cve-2020-2023-poc) :  ![starts](https://img.shields.io/github/stars/ssst0n3/kata-cve-2020-2023-poc.svg) ![forks](https://img.shields.io/github/forks/ssst0n3/kata-cve-2020-2023-poc.svg)


## CVE-2020-0601
 A spoofing vulnerability exists in the way Windows CryptoAPI (Crypt32.dll) validates Elliptic Curve Cryptography (ECC) certificates.An attacker could exploit the vulnerability by using a spoofed code-signing certificate to sign a malicious executable, making it appear the file was from a trusted, legitimate source, aka 'Windows CryptoAPI Spoofing Vulnerability'.

- [https://github.com/cimashiro/-Awesome-CVE-2020-0601-](https://github.com/cimashiro/-Awesome-CVE-2020-0601-) :  ![starts](https://img.shields.io/github/stars/cimashiro/-Awesome-CVE-2020-0601-.svg) ![forks](https://img.shields.io/github/forks/cimashiro/-Awesome-CVE-2020-0601-.svg)


## CVE-2019-15107
 An issue was discovered in Webmin &lt;=1.920. The parameter old in password_change.cgi contains a command injection vulnerability.

- [https://github.com/K3ysTr0K3R/CVE-2019-15107-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2019-15107-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2019-15107-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2019-15107-EXPLOIT.svg)


## CVE-2018-12018
 The GetBlockHeadersMsg handler in the LES protocol implementation in Go Ethereum (aka geth) before 1.8.11 may lead to an access violation because of an integer signedness error for the array index, which allows attackers to launch a Denial of Service attack by sending a packet with a -1 query.Skip value. The vulnerable remote node would be crashed by such an attack immediately, aka the EPoD (Ethereum Packet of Death) issue.

- [https://github.com/k3v142/CVE-2018-12018](https://github.com/k3v142/CVE-2018-12018) :  ![starts](https://img.shields.io/github/stars/k3v142/CVE-2018-12018.svg) ![forks](https://img.shields.io/github/forks/k3v142/CVE-2018-12018.svg)


## CVE-2015-8351
 PHP remote file inclusion vulnerability in the Gwolle Guestbook plugin before 1.5.4 for WordPress, when allow_url_include is enabled, allows remote authenticated users to execute arbitrary PHP code via a URL in the abspath parameter to frontend/captcha/ajaxresponse.php.  NOTE: this can also be leveraged to include and execute arbitrary local files via directory traversal sequences regardless of whether allow_url_include is enabled.

- [https://github.com/igruntplay/exploit-CVE-2015-8351](https://github.com/igruntplay/exploit-CVE-2015-8351) :  ![starts](https://img.shields.io/github/stars/igruntplay/exploit-CVE-2015-8351.svg) ![forks](https://img.shields.io/github/forks/igruntplay/exploit-CVE-2015-8351.svg)

