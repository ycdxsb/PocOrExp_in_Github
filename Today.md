# Update 2023-08-28
## CVE-2023-41080
 URL Redirection to Untrusted Site ('Open Redirect') vulnerability in FORM authentication feature Apache Tomcat.This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.0-M10, from 10.1.0-M1 through 10.0.12, from 9.0.0-M1 through 9.0.79 and from 8.5.0 through 8.5.92. The vulnerability is limited to the ROOT (default) web application.

- [https://github.com/shiomiyan/CVE-2023-41080](https://github.com/shiomiyan/CVE-2023-41080) :  ![starts](https://img.shields.io/github/stars/shiomiyan/CVE-2023-41080.svg) ![forks](https://img.shields.io/github/forks/shiomiyan/CVE-2023-41080.svg)


## CVE-2023-38389
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/codeb0ss/CVE-2023-38389-PoC](https://github.com/codeb0ss/CVE-2023-38389-PoC) :  ![starts](https://img.shields.io/github/stars/codeb0ss/CVE-2023-38389-PoC.svg) ![forks](https://img.shields.io/github/forks/codeb0ss/CVE-2023-38389-PoC.svg)


## CVE-2023-38388
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/codeb0ss/CVE-2023-38388](https://github.com/codeb0ss/CVE-2023-38388) :  ![starts](https://img.shields.io/github/stars/codeb0ss/CVE-2023-38388.svg) ![forks](https://img.shields.io/github/forks/codeb0ss/CVE-2023-38388.svg)


## CVE-2023-21939
 Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Swing). Supported versions that are affected are Oracle Java SE: 8u361, 8u361-perf, 11.0.18, 17.0.6, 20; Oracle GraalVM Enterprise Edition: 20.3.9, 21.3.5 and 22.3.1. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle Java SE, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. CVSS 3.1 Base Score 5.3 (Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N).

- [https://github.com/Y4Sec-Team/CVE-2023-21939](https://github.com/Y4Sec-Team/CVE-2023-21939) :  ![starts](https://img.shields.io/github/stars/Y4Sec-Team/CVE-2023-21939.svg) ![forks](https://img.shields.io/github/forks/Y4Sec-Team/CVE-2023-21939.svg)


## CVE-2023-2648
 A vulnerability was found in Weaver E-Office 9.5. It has been classified as critical. This affects an unknown part of the file /inc/jquery/uploadify/uploadify.php. The manipulation of the argument Filedata leads to unrestricted upload. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-228777 was assigned to this vulnerability. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/bingtangbanli/cve-2023-2523-and-cve-2023-2648](https://github.com/bingtangbanli/cve-2023-2523-and-cve-2023-2648) :  ![starts](https://img.shields.io/github/stars/bingtangbanli/cve-2023-2523-and-cve-2023-2648.svg) ![forks](https://img.shields.io/github/forks/bingtangbanli/cve-2023-2523-and-cve-2023-2648.svg)


## CVE-2023-2523
 A vulnerability was found in Weaver E-Office 9.5. It has been rated as critical. Affected by this issue is some unknown functionality of the file App/Ajax/ajax.php?action=mobile_upload_save. The manipulation of the argument upload_quwan leads to unrestricted upload. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. VDB-228014 is the identifier assigned to this vulnerability. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/bingtangbanli/cve-2023-2523-and-cve-2023-2648](https://github.com/bingtangbanli/cve-2023-2523-and-cve-2023-2648) :  ![starts](https://img.shields.io/github/stars/bingtangbanli/cve-2023-2523-and-cve-2023-2648.svg) ![forks](https://img.shields.io/github/forks/bingtangbanli/cve-2023-2523-and-cve-2023-2648.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/12345qwert123456/CVE-2021-41773](https://github.com/12345qwert123456/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/12345qwert123456/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/12345qwert123456/CVE-2021-41773.svg)


## CVE-2021-39150
 XStream is a simple library to serialize objects to XML and back again. In affected versions this vulnerability may allow a remote attacker to request data from internal resources that are not publicly available only by manipulating the processed input stream with a Java runtime version 14 to 8. No user is affected, who followed the recommendation to setup XStream's security framework with a whitelist limited to the minimal required types. If you rely on XStream's default blacklist of the [Security Framework](https://x-stream.github.io/security.html#framework), you will have to use at least version 1.4.18.

- [https://github.com/zwjjustdoit/Xstream-1.4.17](https://github.com/zwjjustdoit/Xstream-1.4.17) :  ![starts](https://img.shields.io/github/stars/zwjjustdoit/Xstream-1.4.17.svg) ![forks](https://img.shields.io/github/forks/zwjjustdoit/Xstream-1.4.17.svg)


## CVE-2021-3560
 It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user. This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/WinMin/CVE-2021-3560](https://github.com/WinMin/CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/WinMin/CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/WinMin/CVE-2021-3560.svg)
- [https://github.com/n3onhacks/CVE-2021-3560](https://github.com/n3onhacks/CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/n3onhacks/CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/n3onhacks/CVE-2021-3560.svg)


## CVE-2019-3396
 The Widget Connector macro in Atlassian Confluence Server before version 6.6.12 (the fixed version for 6.6.x), from version 6.7.0 before 6.12.3 (the fixed version for 6.12.x), from version 6.13.0 before 6.13.3 (the fixed version for 6.13.x), and from version 6.14.0 before 6.14.2 (the fixed version for 6.14.x), allows remote attackers to achieve path traversal and remote code execution on a Confluence Server or Data Center instance via server-side template injection.

- [https://github.com/quanpt103/CVE-2019-3396](https://github.com/quanpt103/CVE-2019-3396) :  ![starts](https://img.shields.io/github/stars/quanpt103/CVE-2019-3396.svg) ![forks](https://img.shields.io/github/forks/quanpt103/CVE-2019-3396.svg)
- [https://github.com/s1xg0d/CVE-2019-3396](https://github.com/s1xg0d/CVE-2019-3396) :  ![starts](https://img.shields.io/github/stars/s1xg0d/CVE-2019-3396.svg) ![forks](https://img.shields.io/github/forks/s1xg0d/CVE-2019-3396.svg)


## CVE-2017-7921
 An Improper Authentication issue was discovered in Hikvision DS-2CD2xx2F-I Series V5.2.0 build 140721 to V5.4.0 build 160530, DS-2CD2xx0F-I Series V5.2.0 build 140721 to V5.4.0 Build 160401, DS-2CD2xx2FWD Series V5.3.1 build 150410 to V5.4.4 Build 161125, DS-2CD4x2xFWD Series V5.2.0 build 140721 to V5.4.0 Build 160414, DS-2CD4xx5 Series V5.2.0 build 140721 to V5.4.0 Build 160421, DS-2DFx Series V5.2.0 build 140805 to V5.4.5 Build 160928, and DS-2CD63xx Series V5.0.9 build 140305 to V5.3.5 Build 160106 devices. The improper authentication vulnerability occurs when an application does not adequately or correctly authenticate users. This may allow a malicious user to escalate his or her privileges on the system and gain access to sensitive information.

- [https://github.com/fracergu/CVE-2017-7921](https://github.com/fracergu/CVE-2017-7921) :  ![starts](https://img.shields.io/github/stars/fracergu/CVE-2017-7921.svg) ![forks](https://img.shields.io/github/forks/fracergu/CVE-2017-7921.svg)

