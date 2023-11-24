# Update 2023-11-24
## CVE-2023-49103
 An issue was discovered in ownCloud owncloud/graphapi 0.2.x before 0.2.1 and 0.3.x before 0.3.1. The graphapi app relies on a third-party GetPhpInfo.php library that provides a URL. When this URL is accessed, it reveals the configuration details of the PHP environment (phpinfo). This information includes all the environment variables of the webserver. In containerized deployments, these environment variables may include sensitive data such as the ownCloud admin password, mail server credentials, and license key. Simply disabling the graphapi app does not eliminate the vulnerability. Additionally, phpinfo exposes various other potentially sensitive configuration details that could be exploited by an attacker to gather information about the system. Therefore, even if ownCloud is not running in a containerized environment, this vulnerability should still be a cause for concern. Note that Docker containers from before February 2023 are not vulnerable to the credential disclosure.

- [https://github.com/creacitysec/CVE-2023-49103](https://github.com/creacitysec/CVE-2023-49103) :  ![starts](https://img.shields.io/github/stars/creacitysec/CVE-2023-49103.svg) ![forks](https://img.shields.io/github/forks/creacitysec/CVE-2023-49103.svg)


## CVE-2023-47437
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/herombey/CVE-2023-47437](https://github.com/herombey/CVE-2023-47437) :  ![starts](https://img.shields.io/github/stars/herombey/CVE-2023-47437.svg) ![forks](https://img.shields.io/github/forks/herombey/CVE-2023-47437.svg)


## CVE-2023-47246
 In SysAid On-Premise before 23.3.36, a path traversal vulnerability leads to code execution after an attacker writes a file to the Tomcat webroot, as exploited in the wild in November 2023.

- [https://github.com/rainbowhatrkn/CVE-2023-47246](https://github.com/rainbowhatrkn/CVE-2023-47246) :  ![starts](https://img.shields.io/github/stars/rainbowhatrkn/CVE-2023-47246.svg) ![forks](https://img.shields.io/github/forks/rainbowhatrkn/CVE-2023-47246.svg)
- [https://github.com/tucommenceapousser/CVE-2023-47246](https://github.com/tucommenceapousser/CVE-2023-47246) :  ![starts](https://img.shields.io/github/stars/tucommenceapousser/CVE-2023-47246.svg) ![forks](https://img.shields.io/github/forks/tucommenceapousser/CVE-2023-47246.svg)


## CVE-2023-38646
 Metabase open source before 0.46.6.1 and Metabase Enterprise before 1.46.6.1 allow attackers to execute arbitrary commands on the server, at the server's privilege level. Authentication is not required for exploitation. The other fixed versions are 0.45.4.1, 1.45.4.1, 0.44.7.1, 1.44.7.1, 0.43.7.2, and 1.43.7.2.

- [https://github.com/lazysec0x21/CVE-2023-38646](https://github.com/lazysec0x21/CVE-2023-38646) :  ![starts](https://img.shields.io/github/stars/lazysec0x21/CVE-2023-38646.svg) ![forks](https://img.shields.io/github/forks/lazysec0x21/CVE-2023-38646.svg)


## CVE-2023-36553
 A improper neutralization of special elements used in an os command ('os command injection') in Fortinet FortiSIEM version 5.4.0 and 5.3.0 through 5.3.3 and 5.2.5 through 5.2.8 and 5.2.1 through 5.2.2 and 5.1.0 through 5.1.3 and 5.0.0 through 5.0.1 and 4.10.0 and 4.9.0 and 4.7.2 allows attacker to execute unauthorized code or commands via crafted API requests.

- [https://github.com/kenit7s/CVE-2023-36553-RCE](https://github.com/kenit7s/CVE-2023-36553-RCE) :  ![starts](https://img.shields.io/github/stars/kenit7s/CVE-2023-36553-RCE.svg) ![forks](https://img.shields.io/github/forks/kenit7s/CVE-2023-36553-RCE.svg)


## CVE-2023-35078
 Ivanti Endpoint Manager Mobile (EPMM), formerly MobileIron Core, through 11.10 allows remote attackers to obtain PII, add an administrative account, and change the configuration because of an authentication bypass, as exploited in the wild in July 2023. A patch is available.

- [https://github.com/lazysec0x21/CVE-2023-35078](https://github.com/lazysec0x21/CVE-2023-35078) :  ![starts](https://img.shields.io/github/stars/lazysec0x21/CVE-2023-35078.svg) ![forks](https://img.shields.io/github/forks/lazysec0x21/CVE-2023-35078.svg)


## CVE-2023-28771
 Improper error message handling in Zyxel ZyWALL/USG series firmware versions 4.60 through 4.73, VPN series firmware versions 4.60 through 5.35, USG FLEX series firmware versions 4.60 through 5.35, and ATP series firmware versions 4.60 through 5.35, which could allow an unauthenticated attacker to execute some OS commands remotely by sending crafted packets to an affected device.

- [https://github.com/benjaminhays/CVE-2023-28771-PoC](https://github.com/benjaminhays/CVE-2023-28771-PoC) :  ![starts](https://img.shields.io/github/stars/benjaminhays/CVE-2023-28771-PoC.svg) ![forks](https://img.shields.io/github/forks/benjaminhays/CVE-2023-28771-PoC.svg)


## CVE-2023-24488
 Cross site scripting vulnerability in Citrix ADC and Citrix Gateway in allows and attacker to perform cross site scripting

- [https://github.com/lazysec0x21/CVE-2023-24488](https://github.com/lazysec0x21/CVE-2023-24488) :  ![starts](https://img.shields.io/github/stars/lazysec0x21/CVE-2023-24488.svg) ![forks](https://img.shields.io/github/forks/lazysec0x21/CVE-2023-24488.svg)


## CVE-2023-23583
 Sequence of processor instructions leads to unexpected behavior for some Intel(R) Processors may allow an authenticated user to potentially enable escalation of privilege and/or information disclosure and/or denial of service via local access.

- [https://github.com/Mav3r1ck0x1/CVE-2023-23583-Reptar-](https://github.com/Mav3r1ck0x1/CVE-2023-23583-Reptar-) :  ![starts](https://img.shields.io/github/stars/Mav3r1ck0x1/CVE-2023-23583-Reptar-.svg) ![forks](https://img.shields.io/github/forks/Mav3r1ck0x1/CVE-2023-23583-Reptar-.svg)


## CVE-2023-22855
 Kardex Mlog MCC 5.7.12+0-a203c2a213-master allows remote code execution. It spawns a web interface listening on port 8088. A user-controllable path is handed to a path-concatenation method (Path.Combine from .NET) without proper sanitisation. This yields the possibility of including local files, as well as remote files on SMB shares. If one provides a file with the extension .t4, it is rendered with the .NET templating engine mono/t4, which can execute code.

- [https://github.com/patrickhener/CVE-2023-22855](https://github.com/patrickhener/CVE-2023-22855) :  ![starts](https://img.shields.io/github/stars/patrickhener/CVE-2023-22855.svg) ![forks](https://img.shields.io/github/forks/patrickhener/CVE-2023-22855.svg)


## CVE-2023-4741
 A vulnerability has been found in IBOS OA 4.5.5 and classified as critical. This vulnerability affects unknown code of the file ?r=diary/default/del of the component Delete Logs Handler. The manipulation leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. VDB-238630 is the identifier assigned to this vulnerability. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/wudidike/CVE-2023-4741](https://github.com/wudidike/CVE-2023-4741) :  ![starts](https://img.shields.io/github/stars/wudidike/CVE-2023-4741.svg) ![forks](https://img.shields.io/github/forks/wudidike/CVE-2023-4741.svg)


## CVE-2023-4207
 A use-after-free vulnerability in the Linux kernel's net/sched: cls_fw component can be exploited to achieve local privilege escalation. When fw_change() is called on an existing filter, the whole tcf_result struct is always copied into the new instance of the filter. This causes a problem when updating a filter bound to a class, as tcf_unbind_filter() is always called on the old instance in the success path, decreasing filter_cnt of the still referenced class and allowing it to be deleted, leading to a use-after-free. We recommend upgrading past commit 76e42ae831991c828cffa8c37736ebfb831ad5ec.

- [https://github.com/nidhi7598/linux-4.19.72_net_CVE-2023-4207](https://github.com/nidhi7598/linux-4.19.72_net_CVE-2023-4207) :  ![starts](https://img.shields.io/github/stars/nidhi7598/linux-4.19.72_net_CVE-2023-4207.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/linux-4.19.72_net_CVE-2023-4207.svg)


## CVE-2022-36804
 Multiple API endpoints in Atlassian Bitbucket Server and Data Center 7.0.0 before version 7.6.17, from version 7.7.0 before version 7.17.10, from version 7.18.0 before version 7.21.4, from version 8.0.0 before version 8.0.3, from version 8.1.0 before version 8.1.3, and from version 8.2.0 before version 8.2.2, and from version 8.3.0 before 8.3.1 allows remote attackers with read permissions to a public or private Bitbucket repository to execute arbitrary code by sending a malicious HTTP request. This vulnerability was reported via our Bug Bounty Program by TheGrandPew.

- [https://github.com/benjaminhays/CVE-2022-36804-PoC-Exploit](https://github.com/benjaminhays/CVE-2022-36804-PoC-Exploit) :  ![starts](https://img.shields.io/github/stars/benjaminhays/CVE-2022-36804-PoC-Exploit.svg) ![forks](https://img.shields.io/github/forks/benjaminhays/CVE-2022-36804-PoC-Exploit.svg)


## CVE-2022-1364
 Type confusion in V8 Turbofan in Google Chrome prior to 100.0.4896.127 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/A1Lin/cve-2022-1364](https://github.com/A1Lin/cve-2022-1364) :  ![starts](https://img.shields.io/github/stars/A1Lin/cve-2022-1364.svg) ![forks](https://img.shields.io/github/forks/A1Lin/cve-2022-1364.svg)


## CVE-2019-5418
 There is a File Content Disclosure vulnerability in Action View &lt;5.2.2.1, &lt;5.1.6.2, &lt;5.0.7.2, &lt;4.2.11.1 and v3 where specially crafted accept headers can cause contents of arbitrary files on the target system's filesystem to be exposed.

- [https://github.com/Bad3r/RailroadBandit](https://github.com/Bad3r/RailroadBandit) :  ![starts](https://img.shields.io/github/stars/Bad3r/RailroadBandit.svg) ![forks](https://img.shields.io/github/forks/Bad3r/RailroadBandit.svg)


## CVE-2019-1253
 An elevation of privilege vulnerability exists when the Windows AppX Deployment Server improperly handles junctions.To exploit this vulnerability, an attacker would first have to gain execution on the victim system, aka 'Windows Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-1215, CVE-2019-1278, CVE-2019-1303.

- [https://github.com/padovah4ck/CVE-2019-1253](https://github.com/padovah4ck/CVE-2019-1253) :  ![starts](https://img.shields.io/github/stars/padovah4ck/CVE-2019-1253.svg) ![forks](https://img.shields.io/github/forks/padovah4ck/CVE-2019-1253.svg)
- [https://github.com/likescam/CVE-2019-1253](https://github.com/likescam/CVE-2019-1253) :  ![starts](https://img.shields.io/github/stars/likescam/CVE-2019-1253.svg) ![forks](https://img.shields.io/github/forks/likescam/CVE-2019-1253.svg)


## CVE-2017-8759
 Microsoft .NET Framework 2.0, 3.5, 3.5.1, 4.5.2, 4.6, 4.6.1, 4.6.2 and 4.7 allow an attacker to execute code remotely via a malicious document or application, aka &quot;.NET Framework Remote Code Execution Vulnerability.&quot;

- [https://github.com/adeljck/CVE-2017-8759](https://github.com/adeljck/CVE-2017-8759) :  ![starts](https://img.shields.io/github/stars/adeljck/CVE-2017-8759.svg) ![forks](https://img.shields.io/github/forks/adeljck/CVE-2017-8759.svg)
- [https://github.com/tahisaad6/CVE-2017-8759-Exploit-sample2](https://github.com/tahisaad6/CVE-2017-8759-Exploit-sample2) :  ![starts](https://img.shields.io/github/stars/tahisaad6/CVE-2017-8759-Exploit-sample2.svg) ![forks](https://img.shields.io/github/forks/tahisaad6/CVE-2017-8759-Exploit-sample2.svg)


## CVE-2016-7255
 The kernel-mode drivers in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, and 1607, and Windows Server 2016 allow local users to gain privileges via a crafted application, aka &quot;Win32k Elevation of Privilege Vulnerability.&quot;

- [https://github.com/bbolmin/cve-2016-7255_x86_x64](https://github.com/bbolmin/cve-2016-7255_x86_x64) :  ![starts](https://img.shields.io/github/stars/bbolmin/cve-2016-7255_x86_x64.svg) ![forks](https://img.shields.io/github/forks/bbolmin/cve-2016-7255_x86_x64.svg)


## CVE-2013-6490
 The SIMPLE protocol functionality in Pidgin before 2.10.8 allows remote attackers to have an unspecified impact via a negative Content-Length header, which triggers a buffer overflow.

- [https://github.com/Everdoh/CVE-2013-6490](https://github.com/Everdoh/CVE-2013-6490) :  ![starts](https://img.shields.io/github/stars/Everdoh/CVE-2013-6490.svg) ![forks](https://img.shields.io/github/forks/Everdoh/CVE-2013-6490.svg)

