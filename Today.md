# Update 2022-10-31
## CVE-2022-26134
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are from 1.3.0 before 7.4.17, from 7.13.0 before 7.13.7, from 7.14.0 before 7.14.3, from 7.15.0 before 7.15.2, from 7.16.0 before 7.16.4, from 7.17.0 before 7.17.4, and from 7.18.0 before 7.18.1.

- [https://github.com/itwestend/cve_2022_26134](https://github.com/itwestend/cve_2022_26134) :  ![starts](https://img.shields.io/github/stars/itwestend/cve_2022_26134.svg) ![forks](https://img.shields.io/github/forks/itwestend/cve_2022_26134.svg)


## CVE-2022-21907
 HTTP Protocol Stack Remote Code Execution Vulnerability.

- [https://github.com/Malwareman007/CVE-2022-21907](https://github.com/Malwareman007/CVE-2022-21907) :  ![starts](https://img.shields.io/github/stars/Malwareman007/CVE-2022-21907.svg) ![forks](https://img.shields.io/github/forks/Malwareman007/CVE-2022-21907.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Evil-d0Zz/CVE-2021-41773-](https://github.com/Evil-d0Zz/CVE-2021-41773-) :  ![starts](https://img.shields.io/github/stars/Evil-d0Zz/CVE-2021-41773-.svg) ![forks](https://img.shields.io/github/forks/Evil-d0Zz/CVE-2021-41773-.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/aus-mate/CVE-2021-4034-POC](https://github.com/aus-mate/CVE-2021-4034-POC) :  ![starts](https://img.shields.io/github/stars/aus-mate/CVE-2021-4034-POC.svg) ![forks](https://img.shields.io/github/forks/aus-mate/CVE-2021-4034-POC.svg)
- [https://github.com/JoyGhoshs/CVE-2021-4034](https://github.com/JoyGhoshs/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/JoyGhoshs/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/JoyGhoshs/CVE-2021-4034.svg)


## CVE-2021-3493
 The overlayfs implementation in the linux kernel did not properly validate with respect to user namespaces the setting of file capabilities on files in an underlying file system. Due to the combination of unprivileged user namespaces along with a patch carried in the Ubuntu kernel to allow unprivileged overlay mounts, an attacker could use this to gain elevated privileges.

- [https://github.com/cerodah/overlayFS-CVE-2021-3493](https://github.com/cerodah/overlayFS-CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/cerodah/overlayFS-CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/cerodah/overlayFS-CVE-2021-3493.svg)


## CVE-2018-2628
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.2 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/shaoshore/CVE-2018-2628](https://github.com/shaoshore/CVE-2018-2628) :  ![starts](https://img.shields.io/github/stars/shaoshore/CVE-2018-2628.svg) ![forks](https://img.shields.io/github/forks/shaoshore/CVE-2018-2628.svg)


## CVE-2017-11427
 OneLogin PythonSAML 2.3.0 and earlier may incorrectly utilize the results of XML DOM traversal and canonicalization APIs in such a way that an attacker may be able to manipulate the SAML data without invalidating the cryptographic signature, allowing the attack to potentially bypass authentication to SAML service providers.

- [https://github.com/CHYbeta/CVE-2017-11427-DEMO](https://github.com/CHYbeta/CVE-2017-11427-DEMO) :  ![starts](https://img.shields.io/github/stars/CHYbeta/CVE-2017-11427-DEMO.svg) ![forks](https://img.shields.io/github/forks/CHYbeta/CVE-2017-11427-DEMO.svg)

