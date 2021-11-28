# Update 2021-11-28
## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/TAI-REx/cve-2021-41773-nse](https://github.com/TAI-REx/cve-2021-41773-nse) :  ![starts](https://img.shields.io/github/stars/TAI-REx/cve-2021-41773-nse.svg) ![forks](https://img.shields.io/github/forks/TAI-REx/cve-2021-41773-nse.svg)


## CVE-2021-40865
 An Unsafe Deserialization vulnerability exists in the worker services of the Apache Storm supervisor server allowing pre-auth Remote Code Execution (RCE). Apache Storm 2.2.x users should upgrade to version 2.2.1 or 2.3.0. Apache Storm 2.1.x users should upgrade to version 2.1.1. Apache Storm 1.x users should upgrade to version 1.2.4

- [https://github.com/hktalent/CVE-2021-40865](https://github.com/hktalent/CVE-2021-40865) :  ![starts](https://img.shields.io/github/stars/hktalent/CVE-2021-40865.svg) ![forks](https://img.shields.io/github/forks/hktalent/CVE-2021-40865.svg)


## CVE-2021-24084
 Windows Mobile Device Management Information Disclosure Vulnerability

- [https://github.com/ohnonoyesyes/CVE-2021-24084](https://github.com/ohnonoyesyes/CVE-2021-24084) :  ![starts](https://img.shields.io/github/stars/ohnonoyesyes/CVE-2021-24084.svg) ![forks](https://img.shields.io/github/forks/ohnonoyesyes/CVE-2021-24084.svg)


## CVE-2021-21315
 The System Information Library for Node.JS (npm package &quot;systeminformation&quot;) is an open source collection of functions to retrieve detailed hardware, system and OS information. In systeminformation before version 5.3.1 there is a command injection vulnerability. Problem was fixed in version 5.3.1. As a workaround instead of upgrading, be sure to check or sanitize service parameters that are passed to si.inetLatency(), si.inetChecksite(), si.services(), si.processLoad() ... do only allow strings, reject any arrays. String sanitation works as expected.

- [https://github.com/Anonymous-ghost/AttackWebFrameworkTools](https://github.com/Anonymous-ghost/AttackWebFrameworkTools) :  ![starts](https://img.shields.io/github/stars/Anonymous-ghost/AttackWebFrameworkTools.svg) ![forks](https://img.shields.io/github/forks/Anonymous-ghost/AttackWebFrameworkTools.svg)


## CVE-2021-21042
 Acrobat Reader DC versions 2020.013.20074 (and earlier), 2020.001.30018 (and earlier) and 2017.011.30188 (and earlier) are affected by an Out-of-bounds Read vulnerability that could lead to arbitrary disclosure of information in the memory stack. An attacker could leverage this vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/r1l4-i3pur1l4/CVE-2021-21042](https://github.com/r1l4-i3pur1l4/CVE-2021-21042) :  ![starts](https://img.shields.io/github/stars/r1l4-i3pur1l4/CVE-2021-21042.svg) ![forks](https://img.shields.io/github/forks/r1l4-i3pur1l4/CVE-2021-21042.svg)


## CVE-2020-7247
 smtp_mailaddr in smtp_session.c in OpenSMTPD 6.6, as used in OpenBSD 6.6 and other products, allows remote attackers to execute arbitrary commands as root via a crafted SMTP session, as demonstrated by shell metacharacters in a MAIL FROM field. This affects the &quot;uncommented&quot; default configuration. The issue exists because of an incorrect return value upon failure of input validation.

- [https://github.com/SimonSchoeni/CVE-2020-7247-POC](https://github.com/SimonSchoeni/CVE-2020-7247-POC) :  ![starts](https://img.shields.io/github/stars/SimonSchoeni/CVE-2020-7247-POC.svg) ![forks](https://img.shields.io/github/forks/SimonSchoeni/CVE-2020-7247-POC.svg)


## CVE-2020-0114
 In onCreateSliceProvider of KeyguardSliceProvider.java, there is a possible confused deputy due to a PendingIntent error. This could lead to local escalation of privilege that allows actions performed as the System UI, with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10Android ID: A-147606347

- [https://github.com/Nivaskumark/CVE-2020-0114-frameworks](https://github.com/Nivaskumark/CVE-2020-0114-frameworks) :  ![starts](https://img.shields.io/github/stars/Nivaskumark/CVE-2020-0114-frameworks.svg) ![forks](https://img.shields.io/github/forks/Nivaskumark/CVE-2020-0114-frameworks.svg)
- [https://github.com/Nivaskumark/CVE-2020-0114-frameworks_basegbdgb](https://github.com/Nivaskumark/CVE-2020-0114-frameworks_basegbdgb) :  ![starts](https://img.shields.io/github/stars/Nivaskumark/CVE-2020-0114-frameworks_basegbdgb.svg) ![forks](https://img.shields.io/github/forks/Nivaskumark/CVE-2020-0114-frameworks_basegbdgb.svg)
- [https://github.com/Nivaskumark/CVE-2020-0114-frameworks_base11](https://github.com/Nivaskumark/CVE-2020-0114-frameworks_base11) :  ![starts](https://img.shields.io/github/stars/Nivaskumark/CVE-2020-0114-frameworks_base11.svg) ![forks](https://img.shields.io/github/forks/Nivaskumark/CVE-2020-0114-frameworks_base11.svg)


## CVE-2020-0097
 In various methods of PackageManagerService.java, there is a possible permission bypass due to a missing condition for system apps. This could lead to local escalation of privilege with User privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-9 Android-10Android ID: A-145981139

- [https://github.com/Nivaskumark/CVE-2020-0097-frameworks_base](https://github.com/Nivaskumark/CVE-2020-0097-frameworks_base) :  ![starts](https://img.shields.io/github/stars/Nivaskumark/CVE-2020-0097-frameworks_base.svg) ![forks](https://img.shields.io/github/forks/Nivaskumark/CVE-2020-0097-frameworks_base.svg)

