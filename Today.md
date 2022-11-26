# Update 2022-11-26
## CVE-2022-39197
 An XSS (Cross Site Scripting) vulnerability was found in HelpSystems Cobalt Strike through 4.7 that allowed a remote attacker to execute HTML on the Cobalt Strike teamserver. To exploit the vulnerability, one must first inspect a Cobalt Strike payload, and then modify the username field in the payload (or create a new payload with the extracted information and then modify that username field to be malformed).

- [https://github.com/adeljck/CVE-2022-39197](https://github.com/adeljck/CVE-2022-39197) :  ![starts](https://img.shields.io/github/stars/adeljck/CVE-2022-39197.svg) ![forks](https://img.shields.io/github/forks/adeljck/CVE-2022-39197.svg)


## CVE-2022-38374
 A improper neutralization of input during web page generation ('cross-site scripting') in Fortinet FortiADC 7.0.0 - 7.0.2 and 6.2.0 - 6.2.4 allows an attacker to execute unauthorized code or commands via the URL and User fields observed in the traffic and event logviews.

- [https://github.com/azhurtanov/CVE-2022-38374](https://github.com/azhurtanov/CVE-2022-38374) :  ![starts](https://img.shields.io/github/stars/azhurtanov/CVE-2022-38374.svg) ![forks](https://img.shields.io/github/forks/azhurtanov/CVE-2022-38374.svg)


## CVE-2022-26134
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are from 1.3.0 before 7.4.17, from 7.13.0 before 7.13.7, from 7.14.0 before 7.14.3, from 7.15.0 before 7.15.2, from 7.16.0 before 7.16.4, from 7.17.0 before 7.17.4, and from 7.18.0 before 7.18.1.

- [https://github.com/Jhonsonwannaa/CVE_20222_26134](https://github.com/Jhonsonwannaa/CVE_20222_26134) :  ![starts](https://img.shields.io/github/stars/Jhonsonwannaa/CVE_20222_26134.svg) ![forks](https://img.shields.io/github/forks/Jhonsonwannaa/CVE_20222_26134.svg)


## CVE-2022-24637
 Open Web Analytics (OWA) before 1.7.4 allows an unauthenticated remote attacker to obtain sensitive user information, which can be used to gain admin privileges by leveraging cache hashes. This occurs because files generated with '&lt;?php (instead of the intended &quot;&lt;?php sequence) aren't handled by the PHP interpreter.

- [https://github.com/JacobEbben/CVE-2022-24637](https://github.com/JacobEbben/CVE-2022-24637) :  ![starts](https://img.shields.io/github/stars/JacobEbben/CVE-2022-24637.svg) ![forks](https://img.shields.io/github/forks/JacobEbben/CVE-2022-24637.svg)


## CVE-2022-2650
 Improper Restriction of Excessive Authentication Attempts in GitHub repository wger-project/wger prior to 2.2.

- [https://github.com/HackinKraken/CVE-2022-2650](https://github.com/HackinKraken/CVE-2022-2650) :  ![starts](https://img.shields.io/github/stars/HackinKraken/CVE-2022-2650.svg) ![forks](https://img.shields.io/github/forks/HackinKraken/CVE-2022-2650.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/shiomiyan/CVE-2021-41773](https://github.com/shiomiyan/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/shiomiyan/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/shiomiyan/CVE-2021-41773.svg)
- [https://github.com/puckiestyle/CVE-2021-41773](https://github.com/puckiestyle/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-41773.svg)
- [https://github.com/Plunder283/CVE-2021-41773](https://github.com/Plunder283/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Plunder283/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Plunder283/CVE-2021-41773.svg)
- [https://github.com/Evil-d0Zz/CVE-2021-41773-](https://github.com/Evil-d0Zz/CVE-2021-41773-) :  ![starts](https://img.shields.io/github/stars/Evil-d0Zz/CVE-2021-41773-.svg) ![forks](https://img.shields.io/github/forks/Evil-d0Zz/CVE-2021-41773-.svg)


## CVE-2021-40303
 perfex crm 1.10 is vulnerable to Cross Site Scripting (XSS) via /clients/profile.

- [https://github.com/zecopro/CVE-2021-40303](https://github.com/zecopro/CVE-2021-40303) :  ![starts](https://img.shields.io/github/stars/zecopro/CVE-2021-40303.svg) ![forks](https://img.shields.io/github/forks/zecopro/CVE-2021-40303.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/ck00004/CVE-2021-4034](https://github.com/ck00004/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/ck00004/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/ck00004/CVE-2021-4034.svg)
- [https://github.com/evdenis/lsm_bpf_check_argc0](https://github.com/evdenis/lsm_bpf_check_argc0) :  ![starts](https://img.shields.io/github/stars/evdenis/lsm_bpf_check_argc0.svg) ![forks](https://img.shields.io/github/forks/evdenis/lsm_bpf_check_argc0.svg)
- [https://github.com/jpmcb/pwnkit-go](https://github.com/jpmcb/pwnkit-go) :  ![starts](https://img.shields.io/github/stars/jpmcb/pwnkit-go.svg) ![forks](https://img.shields.io/github/forks/jpmcb/pwnkit-go.svg)
- [https://github.com/callrbx/pkexec-lpe-poc](https://github.com/callrbx/pkexec-lpe-poc) :  ![starts](https://img.shields.io/github/stars/callrbx/pkexec-lpe-poc.svg) ![forks](https://img.shields.io/github/forks/callrbx/pkexec-lpe-poc.svg)
- [https://github.com/flux10n/CVE-2021-4034](https://github.com/flux10n/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/flux10n/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/flux10n/CVE-2021-4034.svg)
- [https://github.com/x04000/AutoPwnkit](https://github.com/x04000/AutoPwnkit) :  ![starts](https://img.shields.io/github/stars/x04000/AutoPwnkit.svg) ![forks](https://img.shields.io/github/forks/x04000/AutoPwnkit.svg)
- [https://github.com/0xalwayslucky/log4j-polkit-poc](https://github.com/0xalwayslucky/log4j-polkit-poc) :  ![starts](https://img.shields.io/github/stars/0xalwayslucky/log4j-polkit-poc.svg) ![forks](https://img.shields.io/github/forks/0xalwayslucky/log4j-polkit-poc.svg)
- [https://github.com/defhacks/cve-2021-4034](https://github.com/defhacks/cve-2021-4034) :  ![starts](https://img.shields.io/github/stars/defhacks/cve-2021-4034.svg) ![forks](https://img.shields.io/github/forks/defhacks/cve-2021-4034.svg)


## CVE-2020-1472
 An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC), aka 'Netlogon Elevation of Privilege Vulnerability'.

- [https://github.com/30579096/CVE-2020-1473](https://github.com/30579096/CVE-2020-1473) :  ![starts](https://img.shields.io/github/stars/30579096/CVE-2020-1473.svg) ![forks](https://img.shields.io/github/forks/30579096/CVE-2020-1473.svg)


## CVE-2017-9833
 /cgi-bin/wapopen in BOA Webserver 0.94.14rc21 allows the injection of &quot;../..&quot; using the FILECAMERA variable (sent by GET) to read files with root privileges.

- [https://github.com/anldori/CVE-2017-9833](https://github.com/anldori/CVE-2017-9833) :  ![starts](https://img.shields.io/github/stars/anldori/CVE-2017-9833.svg) ![forks](https://img.shields.io/github/forks/anldori/CVE-2017-9833.svg)

