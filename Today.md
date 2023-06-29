# Update 2023-06-29
## CVE-2023-35843
 NocoDB through 0.106.0 (or 0.109.1) has a path traversal vulnerability that allows an unauthenticated attacker to access arbitrary files on the server by manipulating the path parameter of the /download route. This vulnerability could allow an attacker to access sensitive files and data on the server, including configuration files, source code, and other sensitive information.

- [https://github.com/Szlein/CVE-2023-35843](https://github.com/Szlein/CVE-2023-35843) :  ![starts](https://img.shields.io/github/stars/Szlein/CVE-2023-35843.svg) ![forks](https://img.shields.io/github/forks/Szlein/CVE-2023-35843.svg)


## CVE-2023-34843
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/rootd4ddy/CVE-2023-34843](https://github.com/rootd4ddy/CVE-2023-34843) :  ![starts](https://img.shields.io/github/stars/rootd4ddy/CVE-2023-34843.svg) ![forks](https://img.shields.io/github/forks/rootd4ddy/CVE-2023-34843.svg)


## CVE-2023-34840
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Xh4H/CVE-2023-34840](https://github.com/Xh4H/CVE-2023-34840) :  ![starts](https://img.shields.io/github/stars/Xh4H/CVE-2023-34840.svg) ![forks](https://img.shields.io/github/forks/Xh4H/CVE-2023-34840.svg)


## CVE-2023-34312
 In Tencent QQ through 9.7.8.29039 and TIM through 3.4.7.22084, QQProtect.exe and QQProtectEngine.dll do not validate pointers from inter-process communication, which leads to a write-what-where condition.

- [https://github.com/vi3t1/qq-tim-elevation](https://github.com/vi3t1/qq-tim-elevation) :  ![starts](https://img.shields.io/github/stars/vi3t1/qq-tim-elevation.svg) ![forks](https://img.shields.io/github/forks/vi3t1/qq-tim-elevation.svg)


## CVE-2023-33617
 An OS Command Injection vulnerability in Parks Fiberlink 210 firmware version V2.1.14_X000 was found via the /boaform/admin/formPing target_addr parameter.

- [https://github.com/hheeyywweellccoommee/CVE-2023-33617-hugnc](https://github.com/hheeyywweellccoommee/CVE-2023-33617-hugnc) :  ![starts](https://img.shields.io/github/stars/hheeyywweellccoommee/CVE-2023-33617-hugnc.svg) ![forks](https://img.shields.io/github/forks/hheeyywweellccoommee/CVE-2023-33617-hugnc.svg)


## CVE-2023-27372
 SPIP before 4.2.1 allows Remote Code Execution via form values in the public area because serialization is mishandled. The fixed versions are 3.2.18, 4.0.10, 4.1.8, and 4.2.1.

- [https://github.com/tucommenceapousser/CVE-2023-27372](https://github.com/tucommenceapousser/CVE-2023-27372) :  ![starts](https://img.shields.io/github/stars/tucommenceapousser/CVE-2023-27372.svg) ![forks](https://img.shields.io/github/forks/tucommenceapousser/CVE-2023-27372.svg)


## CVE-2022-44877
 login/index.php in CWP (aka Control Web Panel or CentOS Web Panel) 7 before 0.9.8.1147 allows remote attackers to execute arbitrary OS commands via shell metacharacters in the login parameter.

- [https://github.com/dkstar11q/CVE-2022-44877](https://github.com/dkstar11q/CVE-2022-44877) :  ![starts](https://img.shields.io/github/stars/dkstar11q/CVE-2022-44877.svg) ![forks](https://img.shields.io/github/forks/dkstar11q/CVE-2022-44877.svg)


## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/gustanini/CVE-2022-42889-Text4Shell-POC](https://github.com/gustanini/CVE-2022-42889-Text4Shell-POC) :  ![starts](https://img.shields.io/github/stars/gustanini/CVE-2022-42889-Text4Shell-POC.svg) ![forks](https://img.shields.io/github/forks/gustanini/CVE-2022-42889-Text4Shell-POC.svg)


## CVE-2022-40684
 An authentication bypass using an alternate path or channel [CWE-288] in Fortinet FortiOS version 7.2.0 through 7.2.1 and 7.0.0 through 7.0.6, FortiProxy version 7.2.0 and version 7.0.0 through 7.0.6 and FortiSwitchManager version 7.2.0 and 7.0.0 allows an unauthenticated atttacker to perform operations on the administrative interface via specially crafted HTTP or HTTPS requests.

- [https://github.com/HAWA771/CVE-2022-40684](https://github.com/HAWA771/CVE-2022-40684) :  ![starts](https://img.shields.io/github/stars/HAWA771/CVE-2022-40684.svg) ![forks](https://img.shields.io/github/forks/HAWA771/CVE-2022-40684.svg)


## CVE-2022-39952
 A external control of file name or path in Fortinet FortiNAC versions 9.4.0, 9.2.0 through 9.2.5, 9.1.0 through 9.1.7, 8.8.0 through 8.8.11, 8.7.0 through 8.7.6, 8.6.0 through 8.6.5, 8.5.0 through 8.5.4, 8.3.7 may allow an unauthenticated attacker to execute unauthorized code or commands via specifically crafted HTTP request.

- [https://github.com/dkstar11q/CVE-2022-39952-better](https://github.com/dkstar11q/CVE-2022-39952-better) :  ![starts](https://img.shields.io/github/stars/dkstar11q/CVE-2022-39952-better.svg) ![forks](https://img.shields.io/github/forks/dkstar11q/CVE-2022-39952-better.svg)


## CVE-2022-36804
 Multiple API endpoints in Atlassian Bitbucket Server and Data Center 7.0.0 before version 7.6.17, from version 7.7.0 before version 7.17.10, from version 7.18.0 before version 7.21.4, from version 8.0.0 before version 8.0.3, from version 8.1.0 before version 8.1.3, and from version 8.2.0 before version 8.2.2, and from version 8.3.0 before 8.3.1 allows remote attackers with read permissions to a public or private Bitbucket repository to execute arbitrary code by sending a malicious HTTP request. This vulnerability was reported via our Bug Bounty Program by TheGrandPew.

- [https://github.com/vj4336/CVE-2022-36804-ReverseShell](https://github.com/vj4336/CVE-2022-36804-ReverseShell) :  ![starts](https://img.shields.io/github/stars/vj4336/CVE-2022-36804-ReverseShell.svg) ![forks](https://img.shields.io/github/forks/vj4336/CVE-2022-36804-ReverseShell.svg)


## CVE-2022-32832
 The issue was addressed with improved memory handling. This issue is fixed in iOS 15.6 and iPadOS 15.6, macOS Big Sur 11.6.8, watchOS 8.7, tvOS 15.6, macOS Monterey 12.5, Security Update 2022-005 Catalina. An app with root privileges may be able to execute arbitrary code with kernel privileges.

- [https://github.com/AkbarTrilaksana/CVE-2022-32832](https://github.com/AkbarTrilaksana/CVE-2022-32832) :  ![starts](https://img.shields.io/github/stars/AkbarTrilaksana/CVE-2022-32832.svg) ![forks](https://img.shields.io/github/forks/AkbarTrilaksana/CVE-2022-32832.svg)


## CVE-2022-31814
 pfSense pfBlockerNG through 2.1.4_26 allows remote attackers to execute arbitrary OS commands as root via shell metacharacters in the HTTP Host header. NOTE: 3.x is unaffected.

- [https://github.com/dkstar11q/CVE-2022-31814](https://github.com/dkstar11q/CVE-2022-31814) :  ![starts](https://img.shields.io/github/stars/dkstar11q/CVE-2022-31814.svg) ![forks](https://img.shields.io/github/forks/dkstar11q/CVE-2022-31814.svg)


## CVE-2022-30525
 A OS command injection vulnerability in the CGI program of Zyxel USG FLEX 100(W) firmware versions 5.00 through 5.21 Patch 1, USG FLEX 200 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 500 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 700 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 50(W) firmware versions 5.10 through 5.21 Patch 1, USG20(W)-VPN firmware versions 5.10 through 5.21 Patch 1, ATP series firmware versions 5.10 through 5.21 Patch 1, VPN series firmware versions 4.60 through 5.21 Patch 1, which could allow an attacker to modify specific files and then execute some OS commands on a vulnerable device.

- [https://github.com/zhefox/CVE-2022-30525-Reverse-Shell](https://github.com/zhefox/CVE-2022-30525-Reverse-Shell) :  ![starts](https://img.shields.io/github/stars/zhefox/CVE-2022-30525-Reverse-Shell.svg) ![forks](https://img.shields.io/github/forks/zhefox/CVE-2022-30525-Reverse-Shell.svg)


## CVE-2022-29464
 Certain WSO2 products allow unrestricted file upload with resultant remote code execution. The attacker must use a /fileupload endpoint with a Content-Disposition directory traversal sequence to reach a directory under the web root, such as a ../../../../repository/deployment/server/webapps directory. This affects WSO2 API Manager 2.2.0 and above through 4.0.0; WSO2 Identity Server 5.2.0 and above through 5.11.0; WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0, and 5.6.0; WSO2 Identity Server as Key Manager 5.3.0 and above through 5.10.0; and WSO2 Enterprise Integrator 6.2.0 and above through 6.6.0.

- [https://github.com/xinghonghaoyue/CVE-2022-29464](https://github.com/xinghonghaoyue/CVE-2022-29464) :  ![starts](https://img.shields.io/github/stars/xinghonghaoyue/CVE-2022-29464.svg) ![forks](https://img.shields.io/github/forks/xinghonghaoyue/CVE-2022-29464.svg)


## CVE-2022-29455
 DOM-based Reflected Cross-Site Scripting (XSS) vulnerability in Elementor's Elementor Website Builder plugin &lt;= 3.5.5 versions.

- [https://github.com/5l1v3r1/CVE-2022-29455](https://github.com/5l1v3r1/CVE-2022-29455) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2022-29455.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2022-29455.svg)


## CVE-2022-29303
 SolarView Compact ver.6.00 was discovered to contain a command injection vulnerability via conf_mail.php.

- [https://github.com/1f3lse/CVE-2022-29303](https://github.com/1f3lse/CVE-2022-29303) :  ![starts](https://img.shields.io/github/stars/1f3lse/CVE-2022-29303.svg) ![forks](https://img.shields.io/github/forks/1f3lse/CVE-2022-29303.svg)


## CVE-2022-27925
 Zimbra Collaboration (aka ZCS) 8.8.15 and 9.0 has mboximport functionality that receives a ZIP archive and extracts files from it. An authenticated user with administrator rights has the ability to upload arbitrary files to the system, leading to directory traversal.

- [https://github.com/lolminerxmrig/CVE-2022-27925-Revshell](https://github.com/lolminerxmrig/CVE-2022-27925-Revshell) :  ![starts](https://img.shields.io/github/stars/lolminerxmrig/CVE-2022-27925-Revshell.svg) ![forks](https://img.shields.io/github/forks/lolminerxmrig/CVE-2022-27925-Revshell.svg)


## CVE-2022-26141
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/5l1v3r1/CVE-2022-26141](https://github.com/5l1v3r1/CVE-2022-26141) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2022-26141.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2022-26141.svg)


## CVE-2022-26134
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are from 1.3.0 before 7.4.17, from 7.13.0 before 7.13.7, from 7.14.0 before 7.14.3, from 7.15.0 before 7.15.2, from 7.16.0 before 7.16.4, from 7.17.0 before 7.17.4, and from 7.18.0 before 7.18.1.

- [https://github.com/5l1v3r1/CVE-2022-26141](https://github.com/5l1v3r1/CVE-2022-26141) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2022-26141.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2022-26141.svg)


## CVE-2022-22960
 VMware Workspace ONE Access, Identity Manager and vRealize Automation contain a privilege escalation vulnerability due to improper permissions in support scripts. A malicious actor with local access can escalate privileges to 'root'.

- [https://github.com/secfb/CVE-2022-22954](https://github.com/secfb/CVE-2022-22954) :  ![starts](https://img.shields.io/github/stars/secfb/CVE-2022-22954.svg) ![forks](https://img.shields.io/github/forks/secfb/CVE-2022-22954.svg)


## CVE-2022-22954
 VMware Workspace ONE Access and Identity Manager contain a remote code execution vulnerability due to server-side template injection. A malicious actor with network access can trigger a server-side template injection that may result in remote code execution.

- [https://github.com/secfb/CVE-2022-22954](https://github.com/secfb/CVE-2022-22954) :  ![starts](https://img.shields.io/github/stars/secfb/CVE-2022-22954.svg) ![forks](https://img.shields.io/github/forks/secfb/CVE-2022-22954.svg)


## CVE-2022-1388
 On F5 BIG-IP 16.1.x versions prior to 16.1.2.2, 15.1.x versions prior to 15.1.5.1, 14.1.x versions prior to 14.1.4.6, 13.1.x versions prior to 13.1.5, and all 12.1.x and 11.6.x versions, undisclosed requests may bypass iControl REST authentication. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

- [https://github.com/li8u99/CVE-2022-1388](https://github.com/li8u99/CVE-2022-1388) :  ![starts](https://img.shields.io/github/stars/li8u99/CVE-2022-1388.svg) ![forks](https://img.shields.io/github/forks/li8u99/CVE-2022-1388.svg)


## CVE-2021-46422
 Telesquare SDT-CW3B1 1.1.0 is affected by an OS command injection vulnerability that allows a remote attacker to execute OS commands without any authentication.

- [https://github.com/5l1v3r1/CVE-2021-46422](https://github.com/5l1v3r1/CVE-2021-46422) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2021-46422.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2021-46422.svg)


## CVE-2021-44852
 An issue was discovered in BS_RCIO64.sys in Biostar RACING GT Evo 2.1.1905.1700. A low-integrity process can open the driver's device object and issue IOCTLs to read or write to arbitrary physical memory locations (or call an arbitrary address), leading to execution of arbitrary code. This is associated with 0x226040, 0x226044, and 0x226000.

- [https://github.com/expFlash/CVE-2021-44852](https://github.com/expFlash/CVE-2021-44852) :  ![starts](https://img.shields.io/github/stars/expFlash/CVE-2021-44852.svg) ![forks](https://img.shields.io/github/forks/expFlash/CVE-2021-44852.svg)


## CVE-2021-41801
 The ReplaceText extension through 1.41 for MediaWiki has Incorrect Access Control. When a user is blocked after submitting a replace job, the job is still run, even if it may be run at a later time (due to the job queue backlog)

- [https://github.com/5l1v3r1/CVE-2021-41801](https://github.com/5l1v3r1/CVE-2021-41801) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2021-41801.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2021-41801.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/shiomiyan/CVE-2021-41773](https://github.com/shiomiyan/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/shiomiyan/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/shiomiyan/CVE-2021-41773.svg)


## CVE-2021-36356
 KRAMER VIAware through August 2021 allows remote attackers to execute arbitrary code because ajaxPages/writeBrowseFilePathAjax.php accepts arbitrary executable pathnames (even though browseSystemFiles.php is no longer reachable via the GUI). NOTE: this issue exists because of an incomplete fix for CVE-2019-17124.

- [https://github.com/info4mationprivate8tools/CVE-2021-35064](https://github.com/info4mationprivate8tools/CVE-2021-35064) :  ![starts](https://img.shields.io/github/stars/info4mationprivate8tools/CVE-2021-35064.svg) ![forks](https://img.shields.io/github/forks/info4mationprivate8tools/CVE-2021-35064.svg)


## CVE-2021-35064
 KramerAV VIAWare, all tested versions, allow privilege escalation through misconfiguration of sudo. Sudoers permits running of multiple dangerous commands, including unzip, systemctl and dpkg.

- [https://github.com/info4mationprivate8tools/CVE-2021-35064](https://github.com/info4mationprivate8tools/CVE-2021-35064) :  ![starts](https://img.shields.io/github/stars/info4mationprivate8tools/CVE-2021-35064.svg) ![forks](https://img.shields.io/github/forks/info4mationprivate8tools/CVE-2021-35064.svg)


## CVE-2021-27965
 The MsIo64.sys driver before 1.1.19.1016 in MSI Dragon Center before 2.0.98.0 has a buffer overflow that allows privilege escalation via a crafted 0x80102040, 0x80102044, 0x80102050, or 0x80102054 IOCTL request.

- [https://github.com/expFlash/CVE-2021-27965](https://github.com/expFlash/CVE-2021-27965) :  ![starts](https://img.shields.io/github/stars/expFlash/CVE-2021-27965.svg) ![forks](https://img.shields.io/github/forks/expFlash/CVE-2021-27965.svg)


## CVE-2021-3438
 A potential buffer overflow in the software drivers for certain HP LaserJet products and Samsung product printers could lead to an escalation of privilege.

- [https://github.com/expFlash/CVE-2021-3438](https://github.com/expFlash/CVE-2021-3438) :  ![starts](https://img.shields.io/github/stars/expFlash/CVE-2021-3438.svg) ![forks](https://img.shields.io/github/forks/expFlash/CVE-2021-3438.svg)


## CVE-2020-17382
 The MSI AmbientLink MsIo64 driver 1.0.0.8 has a Buffer Overflow (0x80102040, 0x80102044, 0x80102050,and 0x80102054).

- [https://github.com/expFlash/CVE-2020-17382](https://github.com/expFlash/CVE-2020-17382) :  ![starts](https://img.shields.io/github/stars/expFlash/CVE-2020-17382.svg) ![forks](https://img.shields.io/github/forks/expFlash/CVE-2020-17382.svg)


## CVE-2019-19492
 FreeSWITCH 1.6.10 through 1.10.1 has a default password in event_socket.conf.xml.

- [https://github.com/hheeyywweellccoommee/CVE-2019-19492-mbprp](https://github.com/hheeyywweellccoommee/CVE-2019-19492-mbprp) :  ![starts](https://img.shields.io/github/stars/hheeyywweellccoommee/CVE-2019-19492-mbprp.svg) ![forks](https://img.shields.io/github/forks/hheeyywweellccoommee/CVE-2019-19492-mbprp.svg)


## CVE-2019-18845
 The MsIo64.sys and MsIo32.sys drivers in Patriot Viper RGB before 1.1 allow local users (including low integrity processes) to read and write to arbitrary memory locations, and consequently gain NT AUTHORITY\SYSTEM privileges, by mapping \Device\PhysicalMemory into the calling process via ZwOpenSection and ZwMapViewOfSection.

- [https://github.com/expFlash/CVE-2019-18845](https://github.com/expFlash/CVE-2019-18845) :  ![starts](https://img.shields.io/github/stars/expFlash/CVE-2019-18845.svg) ![forks](https://img.shields.io/github/forks/expFlash/CVE-2019-18845.svg)


## CVE-2019-1385
 An elevation of privilege vulnerability exists when the Windows AppX Deployment Extensions improperly performs privilege management, resulting in access to system files.To exploit this vulnerability, an authenticated attacker would need to run a specially crafted application to elevate privileges.The security update addresses the vulnerability by correcting how AppX Deployment Extensions manages privileges., aka 'Windows AppX Deployment Extensions Elevation of Privilege Vulnerability'.

- [https://github.com/0x413x4/CVE-2019-1385](https://github.com/0x413x4/CVE-2019-1385) :  ![starts](https://img.shields.io/github/stars/0x413x4/CVE-2019-1385.svg) ![forks](https://img.shields.io/github/forks/0x413x4/CVE-2019-1385.svg)


## CVE-2019-1096
 An information disclosure vulnerability exists when the win32k component improperly provides kernel information, aka 'Win32k Information Disclosure Vulnerability'.

- [https://github.com/CrackerCat/cve-2019-1096-poc](https://github.com/CrackerCat/cve-2019-1096-poc) :  ![starts](https://img.shields.io/github/stars/CrackerCat/cve-2019-1096-poc.svg) ![forks](https://img.shields.io/github/forks/CrackerCat/cve-2019-1096-poc.svg)


## CVE-2019-1083
 A denial of service vulnerability exists when Microsoft Common Object Runtime Library improperly handles web requests, aka '.NET Denial of Service Vulnerability'.

- [https://github.com/stevenseeley/HowCVE-2019-1083Works](https://github.com/stevenseeley/HowCVE-2019-1083Works) :  ![starts](https://img.shields.io/github/stars/stevenseeley/HowCVE-2019-1083Works.svg) ![forks](https://img.shields.io/github/forks/stevenseeley/HowCVE-2019-1083Works.svg)


## CVE-2018-25031
 Swagger UI before 4.1.3 could allow a remote attacker to conduct spoofing attacks. By persuading a victim to open a crafted URL, an attacker could exploit this vulnerability to display remote OpenAPI definitions.

- [https://github.com/mathis2001/CVE-2018-25031](https://github.com/mathis2001/CVE-2018-25031) :  ![starts](https://img.shields.io/github/stars/mathis2001/CVE-2018-25031.svg) ![forks](https://img.shields.io/github/forks/mathis2001/CVE-2018-25031.svg)


## CVE-2018-11235
 In Git before 2.13.7, 2.14.x before 2.14.4, 2.15.x before 2.15.2, 2.16.x before 2.16.4, and 2.17.x before 2.17.1, remote code execution can occur. With a crafted .gitmodules file, a malicious project can execute an arbitrary script on a machine that runs &quot;git clone --recurse-submodules&quot; because submodule &quot;names&quot; are obtained from this file, and then appended to $GIT_DIR/modules, leading to directory traversal with &quot;../&quot; in a name. Finally, post-checkout hooks from a submodule are executed, bypassing the intended design in which hooks are not obtained from a remote server.

- [https://github.com/theerachaich/lab](https://github.com/theerachaich/lab) :  ![starts](https://img.shields.io/github/stars/theerachaich/lab.svg) ![forks](https://img.shields.io/github/forks/theerachaich/lab.svg)


## CVE-2018-3990
 An exploitable pool corruption vulnerability exists in the 0x8200E804 IOCTL handler functionality of WIBU-SYSTEMS WibuKey.sys Version 6.40 (Build 2400). A specially crafted IRP request can cause a buffer overflow, resulting in kernel memory corruption and, potentially, privilege escalation. An attacker can send an IRP request to trigger this vulnerability.

- [https://github.com/expFlash/CVE-2018-3990](https://github.com/expFlash/CVE-2018-3990) :  ![starts](https://img.shields.io/github/stars/expFlash/CVE-2018-3990.svg) ![forks](https://img.shields.io/github/forks/expFlash/CVE-2018-3990.svg)


## CVE-2017-5753
 Systems with microprocessors utilizing speculative execution and branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis.

- [https://github.com/ixtal23/spectreScope](https://github.com/ixtal23/spectreScope) :  ![starts](https://img.shields.io/github/stars/ixtal23/spectreScope.svg) ![forks](https://img.shields.io/github/forks/ixtal23/spectreScope.svg)


## CVE-2015-2291
 (1) IQVW32.sys before 1.3.1.0 and (2) IQVW64.sys before 1.3.1.0 in the Intel Ethernet diagnostics driver for Windows allows local users to cause a denial of service or possibly execute arbitrary code with kernel privileges via a crafted (a) 0x80862013, (b) 0x8086200B, (c) 0x8086200F, or (d) 0x80862007 IOCTL call.

- [https://github.com/expFlash/CVE-2015-2291](https://github.com/expFlash/CVE-2015-2291) :  ![starts](https://img.shields.io/github/stars/expFlash/CVE-2015-2291.svg) ![forks](https://img.shields.io/github/forks/expFlash/CVE-2015-2291.svg)


## CVE-2010-4502
 Integer overflow in KmxSbx.sys 6.2.0.22 in CA Internet Security Suite Plus 2010 allows local users to cause a denial of service (pool corruption) and execute arbitrary code via crafted arguments to the 0x88000080 IOCTL, which triggers a buffer overflow.

- [https://github.com/expFlash/CVE-2010-4502](https://github.com/expFlash/CVE-2010-4502) :  ![starts](https://img.shields.io/github/stars/expFlash/CVE-2010-4502.svg) ![forks](https://img.shields.io/github/forks/expFlash/CVE-2010-4502.svg)


## CVE-2009-4049
 Heap-based buffer overflow in aswRdr.sys (aka the TDI RDR driver) in avast! Home and Professional 4.8.1356.0 allows local users to cause a denial of service (memory corruption) or possibly gain privileges via crafted arguments to IOCTL 0x80002024.

- [https://github.com/expFlash/CVE-2009-4049](https://github.com/expFlash/CVE-2009-4049) :  ![starts](https://img.shields.io/github/stars/expFlash/CVE-2009-4049.svg) ![forks](https://img.shields.io/github/forks/expFlash/CVE-2009-4049.svg)


## CVE-2009-0824
 Elaborate Bytes ElbyCDIO.sys 6.0.2.0 and earlier, as distributed in SlySoft AnyDVD before 6.5.2.6, Virtual CloneDrive 5.4.2.3 and earlier, CloneDVD 2.9.2.0 and earlier, and CloneCD 5.3.1.3 and earlier, uses the METHOD_NEITHER communication method for IOCTLs and does not properly validate a buffer associated with the Irp object, which allows local users to cause a denial of service (system crash) via a crafted IOCTL call.

- [https://github.com/expFlash/CVE-2009-0824](https://github.com/expFlash/CVE-2009-0824) :  ![starts](https://img.shields.io/github/stars/expFlash/CVE-2009-0824.svg) ![forks](https://img.shields.io/github/forks/expFlash/CVE-2009-0824.svg)

