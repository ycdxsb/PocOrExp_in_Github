# Update 2022-10-26
## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/west-wind/CVE-2022-42889](https://github.com/west-wind/CVE-2022-42889) :  ![starts](https://img.shields.io/github/stars/west-wind/CVE-2022-42889.svg) ![forks](https://img.shields.io/github/forks/west-wind/CVE-2022-42889.svg)


## CVE-2022-41082
 Microsoft Exchange Server Remote Code Execution Vulnerability.

- [https://github.com/vib3zz/CVE-2022-41082-RCE-POC](https://github.com/vib3zz/CVE-2022-41082-RCE-POC) :  ![starts](https://img.shields.io/github/stars/vib3zz/CVE-2022-41082-RCE-POC.svg) ![forks](https://img.shields.io/github/forks/vib3zz/CVE-2022-41082-RCE-POC.svg)


## CVE-2022-41040
 Microsoft Exchange Server Elevation of Privilege Vulnerability.

- [https://github.com/vib3zz/CVE-2022-41082-RCE-POC](https://github.com/vib3zz/CVE-2022-41082-RCE-POC) :  ![starts](https://img.shields.io/github/stars/vib3zz/CVE-2022-41082-RCE-POC.svg) ![forks](https://img.shields.io/github/forks/vib3zz/CVE-2022-41082-RCE-POC.svg)


## CVE-2022-36804
 Multiple API endpoints in Atlassian Bitbucket Server and Data Center 7.0.0 before version 7.6.17, from version 7.7.0 before version 7.17.10, from version 7.18.0 before version 7.21.4, from version 8.0.0 before version 8.0.3, from version 8.1.0 before version 8.1.3, and from version 8.2.0 before version 8.2.2, and from version 8.3.0 before 8.3.1 allows remote attackers with read permissions to a public or private Bitbucket repository to execute arbitrary code by sending a malicious HTTP request. This vulnerability was reported via our Bug Bounty Program by TheGrandPew.

- [https://github.com/khal4n1/CVE-2022-36804](https://github.com/khal4n1/CVE-2022-36804) :  ![starts](https://img.shields.io/github/stars/khal4n1/CVE-2022-36804.svg) ![forks](https://img.shields.io/github/forks/khal4n1/CVE-2022-36804.svg)


## CVE-2022-36433
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/afine-com/CVE-2022-36433](https://github.com/afine-com/CVE-2022-36433) :  ![starts](https://img.shields.io/github/stars/afine-com/CVE-2022-36433.svg) ![forks](https://img.shields.io/github/forks/afine-com/CVE-2022-36433.svg)


## CVE-2022-36432
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/afine-com/CVE-2022-36432](https://github.com/afine-com/CVE-2022-36432) :  ![starts](https://img.shields.io/github/stars/afine-com/CVE-2022-36432.svg) ![forks](https://img.shields.io/github/forks/afine-com/CVE-2022-36432.svg)


## CVE-2022-35737
 SQLite 1.0.12 through 3.39.x before 3.39.2 sometimes allows an array-bounds overflow if billions of bytes are used in a string argument to a C API.

- [https://github.com/gmh5225/CVE-2022-35737](https://github.com/gmh5225/CVE-2022-35737) :  ![starts](https://img.shields.io/github/stars/gmh5225/CVE-2022-35737.svg) ![forks](https://img.shields.io/github/forks/gmh5225/CVE-2022-35737.svg)


## CVE-2022-35501
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/afine-com/CVE-2022-35501](https://github.com/afine-com/CVE-2022-35501) :  ![starts](https://img.shields.io/github/stars/afine-com/CVE-2022-35501.svg) ![forks](https://img.shields.io/github/forks/afine-com/CVE-2022-35501.svg)


## CVE-2022-35500
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/afine-com/CVE-2022-35500](https://github.com/afine-com/CVE-2022-35500) :  ![starts](https://img.shields.io/github/stars/afine-com/CVE-2022-35500.svg) ![forks](https://img.shields.io/github/forks/afine-com/CVE-2022-35500.svg)


## CVE-2022-32548
 An issue was discovered on certain DrayTek Vigor routers before July 2022 such as the Vigor3910 before 4.3.1.1. /cgi-bin/wlogin.cgi has a buffer overflow via the username or password to the aa or ab field.

- [https://github.com/uisvit/CVE-2022-32548-RCE-MASS](https://github.com/uisvit/CVE-2022-32548-RCE-MASS) :  ![starts](https://img.shields.io/github/stars/uisvit/CVE-2022-32548-RCE-MASS.svg) ![forks](https://img.shields.io/github/forks/uisvit/CVE-2022-32548-RCE-MASS.svg)


## CVE-2022-32223
 Node.js is vulnerable to Hijack Execution Flow: DLL Hijacking under certain conditions on Windows platforms.This vulnerability can be exploited if the victim has the following dependencies on a Windows machine:* OpenSSL has been installed and &#8220;C:\Program Files\Common Files\SSL\openssl.cnf&#8221; exists.Whenever the above conditions are present, `node.exe` will search for `providers.dll` in the current user directory.After that, `node.exe` will try to search for `providers.dll` by the DLL Search Order in Windows.It is possible for an attacker to place the malicious file `providers.dll` under a variety of paths and exploit this vulnerability.

- [https://github.com/ianyong/cve-2022-32223](https://github.com/ianyong/cve-2022-32223) :  ![starts](https://img.shields.io/github/stars/ianyong/cve-2022-32223.svg) ![forks](https://img.shields.io/github/forks/ianyong/cve-2022-32223.svg)


## CVE-2022-26134
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are from 1.3.0 before 7.4.17, from 7.13.0 before 7.13.7, from 7.14.0 before 7.14.3, from 7.15.0 before 7.15.2, from 7.16.0 before 7.16.4, from 7.17.0 before 7.17.4, and from 7.18.0 before 7.18.1.

- [https://github.com/badboy-sft/CVE-2022-26134](https://github.com/badboy-sft/CVE-2022-26134) :  ![starts](https://img.shields.io/github/stars/badboy-sft/CVE-2022-26134.svg) ![forks](https://img.shields.io/github/forks/badboy-sft/CVE-2022-26134.svg)


## CVE-2020-14644
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/cokeBeer/logi](https://github.com/cokeBeer/logi) :  ![starts](https://img.shields.io/github/stars/cokeBeer/logi.svg) ![forks](https://img.shields.io/github/forks/cokeBeer/logi.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/ELIZEUOPAIN/CVE-2019-9053-CMS-Made-Simple-2.2.10---SQL-Injection-Exploit](https://github.com/ELIZEUOPAIN/CVE-2019-9053-CMS-Made-Simple-2.2.10---SQL-Injection-Exploit) :  ![starts](https://img.shields.io/github/stars/ELIZEUOPAIN/CVE-2019-9053-CMS-Made-Simple-2.2.10---SQL-Injection-Exploit.svg) ![forks](https://img.shields.io/github/forks/ELIZEUOPAIN/CVE-2019-9053-CMS-Made-Simple-2.2.10---SQL-Injection-Exploit.svg)


## CVE-2018-8639
 An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka &quot;Win32k Elevation of Privilege Vulnerability.&quot; This affects Windows 7, Windows Server 2012 R2, Windows RT 8.1, Windows Server 2008, Windows Server 2019, Windows Server 2012, Windows 8.1, Windows Server 2016, Windows Server 2008 R2, Windows 10, Windows 10 Servers. This CVE ID is unique from CVE-2018-8641.

- [https://github.com/timwhitez/CVE-2018-8639-EXP](https://github.com/timwhitez/CVE-2018-8639-EXP) :  ![starts](https://img.shields.io/github/stars/timwhitez/CVE-2018-8639-EXP.svg) ![forks](https://img.shields.io/github/forks/timwhitez/CVE-2018-8639-EXP.svg)


## CVE-2018-6066
 Lack of CORS checking by ResourceFetcher/ResourceLoader in Blink in Google Chrome prior to 65.0.3325.146 allowed a remote attacker to leak cross-origin data via a crafted HTML page.

- [https://github.com/DISREL/Ring0VBA](https://github.com/DISREL/Ring0VBA) :  ![starts](https://img.shields.io/github/stars/DISREL/Ring0VBA.svg) ![forks](https://img.shields.io/github/forks/DISREL/Ring0VBA.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/k4u5h41/CVE-2014-0160_Heartbleed](https://github.com/k4u5h41/CVE-2014-0160_Heartbleed) :  ![starts](https://img.shields.io/github/stars/k4u5h41/CVE-2014-0160_Heartbleed.svg) ![forks](https://img.shields.io/github/forks/k4u5h41/CVE-2014-0160_Heartbleed.svg)


## CVE-2007-2447
 The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function, when the &quot;username map script&quot; smb.conf option is enabled, and allows remote authenticated users to execute commands via shell metacharacters involving other MS-RPC functions in the (2) remote printer and (3) file share management.

- [https://github.com/k4u5h41/CVE-2007-2447](https://github.com/k4u5h41/CVE-2007-2447) :  ![starts](https://img.shields.io/github/stars/k4u5h41/CVE-2007-2447.svg) ![forks](https://img.shields.io/github/forks/k4u5h41/CVE-2007-2447.svg)

