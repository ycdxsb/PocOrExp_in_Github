# Update 2024-03-29
## CVE-2024-28085
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/skyler-ferrante/CVE-2024-28085](https://github.com/skyler-ferrante/CVE-2024-28085) :  ![starts](https://img.shields.io/github/stars/skyler-ferrante/CVE-2024-28085.svg) ![forks](https://img.shields.io/github/forks/skyler-ferrante/CVE-2024-28085.svg)


## CVE-2024-21899
 An improper authentication vulnerability has been reported to affect several QNAP operating system versions. If exploited, the vulnerability could allow users to compromise the security of the system via a network. We have already fixed the vulnerability in the following versions: QTS 5.1.3.2578 build 20231110 and later QTS 4.5.4.2627 build 20231225 and later QuTS hero h5.1.3.2578 build 20231110 and later QuTS hero h4.5.4.2626 build 20231225 and later QuTScloud c5.1.5.2651 and later

- [https://github.com/Oxdestiny/CVE-2024-21899-RCE-POC](https://github.com/Oxdestiny/CVE-2024-21899-RCE-POC) :  ![starts](https://img.shields.io/github/stars/Oxdestiny/CVE-2024-21899-RCE-POC.svg) ![forks](https://img.shields.io/github/forks/Oxdestiny/CVE-2024-21899-RCE-POC.svg)


## CVE-2024-21762
 A out-of-bounds write in Fortinet FortiOS versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.6, 7.0.0 through 7.0.13, 6.4.0 through 6.4.14, 6.2.0 through 6.2.15, 6.0.0 through 6.0.17, FortiProxy versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.8, 7.0.0 through 7.0.14, 2.0.0 through 2.0.13, 1.2.0 through 1.2.13, 1.1.0 through 1.1.6, 1.0.0 through 1.0.7 allows attacker to execute unauthorized code or commands via specifically crafted requests

- [https://github.com/MrCyberSec/CVE-2024-21762-Fortinet-RCE-ALLWORK](https://github.com/MrCyberSec/CVE-2024-21762-Fortinet-RCE-ALLWORK) :  ![starts](https://img.shields.io/github/stars/MrCyberSec/CVE-2024-21762-Fortinet-RCE-ALLWORK.svg) ![forks](https://img.shields.io/github/forks/MrCyberSec/CVE-2024-21762-Fortinet-RCE-ALLWORK.svg)


## CVE-2024-0519
 Out of bounds memory access in V8 in Google Chrome prior to 120.0.6099.224 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/Oxdestiny/CVE-2024-0519-Chrome-exploit](https://github.com/Oxdestiny/CVE-2024-0519-Chrome-exploit) :  ![starts](https://img.shields.io/github/stars/Oxdestiny/CVE-2024-0519-Chrome-exploit.svg) ![forks](https://img.shields.io/github/forks/Oxdestiny/CVE-2024-0519-Chrome-exploit.svg)


## CVE-2023-3824
 In PHP version 8.0.* before 8.0.30, 8.1.* before 8.1.22, and 8.2.* before 8.2.8, when loading phar file, while reading PHAR directory entries, insufficient length checking may lead to a stack buffer overflow, leading potentially to memory corruption or RCE.

- [https://github.com/NewLockBit/CVE-2023-3824-PHP-to-RCE](https://github.com/NewLockBit/CVE-2023-3824-PHP-to-RCE) :  ![starts](https://img.shields.io/github/stars/NewLockBit/CVE-2023-3824-PHP-to-RCE.svg) ![forks](https://img.shields.io/github/forks/NewLockBit/CVE-2023-3824-PHP-to-RCE.svg)
- [https://github.com/StayBeautiful-collab/CVE-2023-3824-PHP-to-RCE-LockBit-LEAK](https://github.com/StayBeautiful-collab/CVE-2023-3824-PHP-to-RCE-LockBit-LEAK) :  ![starts](https://img.shields.io/github/stars/StayBeautiful-collab/CVE-2023-3824-PHP-to-RCE-LockBit-LEAK.svg) ![forks](https://img.shields.io/github/forks/StayBeautiful-collab/CVE-2023-3824-PHP-to-RCE-LockBit-LEAK.svg)


## CVE-2022-35869
 This vulnerability allows remote attackers to bypass authentication on affected installations of Inductive Automation Ignition 8.1.15 (b2022030114). Authentication is not required to exploit this vulnerability. The specific flaw exists within com.inductiveautomation.ignition.gateway.web.pages. The issue results from the lack of proper authentication prior to access to functionality. An attacker can leverage this vulnerability to bypass authentication on the system. Was ZDI-CAN-17211.

- [https://github.com/at4111/CVE_2022_35869](https://github.com/at4111/CVE_2022_35869) :  ![starts](https://img.shields.io/github/stars/at4111/CVE_2022_35869.svg) ![forks](https://img.shields.io/github/forks/at4111/CVE_2022_35869.svg)


## CVE-2022-21661
 WordPress is a free and open-source content management system written in PHP and paired with a MariaDB database. Due to improper sanitization in WP_Query, there can be cases where SQL injection is possible through plugins or themes that use it in a certain way. This has been patched in WordPress version 5.8.3. Older affected versions are also fixed via security release, that go back till 3.7.37. We strongly recommend that you keep auto-updates enabled. There are no known workarounds for this vulnerability.

- [https://github.com/safe3s/CVE-2022-21661](https://github.com/safe3s/CVE-2022-21661) :  ![starts](https://img.shields.io/github/stars/safe3s/CVE-2022-21661.svg) ![forks](https://img.shields.io/github/forks/safe3s/CVE-2022-21661.svg)


## CVE-2022-20140
 In read_multi_rsp of gatt_sr.cc, there is a possible out of bounds write due to an incorrect bounds check. This could lead to remote escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-12 Android-12LAndroid ID: A-227618988

- [https://github.com/RenukaSelvar/system_bt_aosp10_cve-2022-20140](https://github.com/RenukaSelvar/system_bt_aosp10_cve-2022-20140) :  ![starts](https://img.shields.io/github/stars/RenukaSelvar/system_bt_aosp10_cve-2022-20140.svg) ![forks](https://img.shields.io/github/forks/RenukaSelvar/system_bt_aosp10_cve-2022-20140.svg)


## CVE-2022-1040
 An authentication bypass vulnerability in the User Portal and Webadmin allows a remote attacker to execute code in Sophos Firewall version v18.5 MR3 and older.

- [https://github.com/jackson5sec/CVE-2022-1040](https://github.com/jackson5sec/CVE-2022-1040) :  ![starts](https://img.shields.io/github/stars/jackson5sec/CVE-2022-1040.svg) ![forks](https://img.shields.io/github/forks/jackson5sec/CVE-2022-1040.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `&lt;grafana_host_url&gt;/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/ticofookfook/CVE-2021-43798](https://github.com/ticofookfook/CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/ticofookfook/CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/ticofookfook/CVE-2021-43798.svg)


## CVE-2015-1701
 Win32k.sys in the kernel-mode drivers in Microsoft Windows Server 2003 SP2, Vista SP2, and Server 2008 SP2 allows local users to gain privileges via a crafted application, as exploited in the wild in April 2015, aka &quot;Win32k Elevation of Privilege Vulnerability.&quot;

- [https://github.com/chefphenix25/vuln-rabilit-windows7](https://github.com/chefphenix25/vuln-rabilit-windows7) :  ![starts](https://img.shields.io/github/stars/chefphenix25/vuln-rabilit-windows7.svg) ![forks](https://img.shields.io/github/forks/chefphenix25/vuln-rabilit-windows7.svg)


## CVE-2014-4114
 Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, and Windows RT Gold and 8.1 allow remote attackers to execute arbitrary code via a crafted OLE object in an Office document, as exploited in the wild with a &quot;Sandworm&quot; attack in June through October 2014, aka &quot;Windows OLE Remote Code Execution Vulnerability.&quot;

- [https://github.com/chefphenix25/vuln-rabilit-windows7](https://github.com/chefphenix25/vuln-rabilit-windows7) :  ![starts](https://img.shields.io/github/stars/chefphenix25/vuln-rabilit-windows7.svg) ![forks](https://img.shields.io/github/forks/chefphenix25/vuln-rabilit-windows7.svg)


## CVE-2014-3568
 OpenSSL before 0.9.8zc, 1.0.0 before 1.0.0o, and 1.0.1 before 1.0.1j does not properly enforce the no-ssl3 build option, which allows remote attackers to bypass intended access restrictions via an SSL 3.0 handshake, related to s23_clnt.c and s23_srvr.c.

- [https://github.com/nidhi7598/OPENSSL_1.0.1g_CVE-2014-3568](https://github.com/nidhi7598/OPENSSL_1.0.1g_CVE-2014-3568) :  ![starts](https://img.shields.io/github/stars/nidhi7598/OPENSSL_1.0.1g_CVE-2014-3568.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/OPENSSL_1.0.1g_CVE-2014-3568.svg)


## CVE-2012-0003
 Unspecified vulnerability in winmm.dll in Windows Multimedia Library in Windows Media Player (WMP) in Microsoft Windows XP SP2 and SP3, Server 2003 SP2, Vista SP2, and Server 2008 SP2 allows remote attackers to execute arbitrary code via a crafted MIDI file, aka &quot;MIDI Remote Code Execution Vulnerability.&quot;

- [https://github.com/chefphenix25/vuln-rabilit-windows7](https://github.com/chefphenix25/vuln-rabilit-windows7) :  ![starts](https://img.shields.io/github/stars/chefphenix25/vuln-rabilit-windows7.svg) ![forks](https://img.shields.io/github/forks/chefphenix25/vuln-rabilit-windows7.svg)


## CVE-2010-3333
 Stack-based buffer overflow in Microsoft Office XP SP3, Office 2003 SP3, Office 2007 SP2, Office 2010, Office 2004 and 2008 for Mac, Office for Mac 2011, and Open XML File Format Converter for Mac allows remote attackers to execute arbitrary code via crafted RTF data, aka &quot;RTF Stack Buffer Overflow Vulnerability.&quot;

- [https://github.com/chefphenix25/vuln-rabilit-windows7](https://github.com/chefphenix25/vuln-rabilit-windows7) :  ![starts](https://img.shields.io/github/stars/chefphenix25/vuln-rabilit-windows7.svg) ![forks](https://img.shields.io/github/forks/chefphenix25/vuln-rabilit-windows7.svg)

