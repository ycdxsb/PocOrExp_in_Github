# Update 2023-12-12
## CVE-2023-38831
 RARLAB WinRAR before 6.23 allows attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive. The issue occurs because a ZIP archive may include a benign file (such as an ordinary .JPG file) and also a folder that has the same name as the benign file, and the contents of the folder (which may include executable content) are processed during an attempt to access only the benign file. This was exploited in the wild in April through October 2023.

- [https://github.com/80r1ng/CVE-2023-38831-EXP](https://github.com/80r1ng/CVE-2023-38831-EXP) :  ![starts](https://img.shields.io/github/stars/80r1ng/CVE-2023-38831-EXP.svg) ![forks](https://img.shields.io/github/forks/80r1ng/CVE-2023-38831-EXP.svg)


## CVE-2023-38646
 Metabase open source before 0.46.6.1 and Metabase Enterprise before 1.46.6.1 allow attackers to execute arbitrary commands on the server, at the server's privilege level. Authentication is not required for exploitation. The other fixed versions are 0.45.4.1, 1.45.4.1, 0.44.7.1, 1.44.7.1, 0.43.7.2, and 1.43.7.2.

- [https://github.com/0utl4nder/Another-Metabase-RCE-CVE-2023-38646](https://github.com/0utl4nder/Another-Metabase-RCE-CVE-2023-38646) :  ![starts](https://img.shields.io/github/stars/0utl4nder/Another-Metabase-RCE-CVE-2023-38646.svg) ![forks](https://img.shields.io/github/forks/0utl4nder/Another-Metabase-RCE-CVE-2023-38646.svg)


## CVE-2023-30547
 vm2 is a sandbox that can run untrusted code with whitelisted Node's built-in modules. There exists a vulnerability in exception sanitization of vm2 for versions up to 3.9.16, allowing attackers to raise an unsanitized host exception inside `handleException()` which can be used to escape the sandbox and run arbitrary code in host context. This vulnerability was patched in the release of version `3.9.17` of `vm2`. There are no known workarounds for this vulnerability. Users are advised to upgrade.

- [https://github.com/rvizx/CVE-2023-30547](https://github.com/rvizx/CVE-2023-30547) :  ![starts](https://img.shields.io/github/stars/rvizx/CVE-2023-30547.svg) ![forks](https://img.shields.io/github/forks/rvizx/CVE-2023-30547.svg)


## CVE-2023-23752
 An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

- [https://github.com/raystr-atearedteam/CVE2023-23752](https://github.com/raystr-atearedteam/CVE2023-23752) :  ![starts](https://img.shields.io/github/stars/raystr-atearedteam/CVE2023-23752.svg) ![forks](https://img.shields.io/github/forks/raystr-atearedteam/CVE2023-23752.svg)


## CVE-2023-4911
 A buffer overflow was discovered in the GNU C Library's dynamic loader ld.so while processing the GLIBC_TUNABLES environment variable. This issue could allow a local attacker to use maliciously crafted GLIBC_TUNABLES environment variables when launching binaries with SUID permission to execute code with elevated privileges.

- [https://github.com/snurkeburk/Looney-Tunables](https://github.com/snurkeburk/Looney-Tunables) :  ![starts](https://img.shields.io/github/stars/snurkeburk/Looney-Tunables.svg) ![forks](https://img.shields.io/github/forks/snurkeburk/Looney-Tunables.svg)


## CVE-2022-42475
 A heap-based buffer overflow vulnerability [CWE-122] in FortiOS SSL-VPN 7.2.0 through 7.2.2, 7.0.0 through 7.0.8, 6.4.0 through 6.4.10, 6.2.0 through 6.2.11, 6.0.15 and earlier and FortiProxy SSL-VPN 7.2.0 through 7.2.1, 7.0.7 and earlier may allow a remote unauthenticated attacker to execute arbitrary code or commands via specifically crafted requests.

- [https://github.com/scrt/cve-2022-42475](https://github.com/scrt/cve-2022-42475) :  ![starts](https://img.shields.io/github/stars/scrt/cve-2022-42475.svg) ![forks](https://img.shields.io/github/forks/scrt/cve-2022-42475.svg)


## CVE-2022-41352
 An issue was discovered in Zimbra Collaboration (ZCS) 8.8.15 and 9.0. An attacker can upload arbitrary files through amavis via a cpio loophole (extraction to /opt/zimbra/jetty/webapps/zimbra/public) that can lead to incorrect access to any other user accounts. Zimbra recommends pax over cpio. Also, pax is in the prerequisites of Zimbra on Ubuntu; however, pax is no longer part of a default Red Hat installation after RHEL 6 (or CentOS 6). Once pax is installed, amavis automatically prefers it over cpio.

- [https://github.com/qailanet/cve-2022-41352-zimbra-rce](https://github.com/qailanet/cve-2022-41352-zimbra-rce) :  ![starts](https://img.shields.io/github/stars/qailanet/cve-2022-41352-zimbra-rce.svg) ![forks](https://img.shields.io/github/forks/qailanet/cve-2022-41352-zimbra-rce.svg)
- [https://github.com/lolminerxmrig/cve-2022-41352-zimbra-rce-1](https://github.com/lolminerxmrig/cve-2022-41352-zimbra-rce-1) :  ![starts](https://img.shields.io/github/stars/lolminerxmrig/cve-2022-41352-zimbra-rce-1.svg) ![forks](https://img.shields.io/github/forks/lolminerxmrig/cve-2022-41352-zimbra-rce-1.svg)


## CVE-2022-29464
 Certain WSO2 products allow unrestricted file upload with resultant remote code execution. The attacker must use a /fileupload endpoint with a Content-Disposition directory traversal sequence to reach a directory under the web root, such as a ../../../../repository/deployment/server/webapps directory. This affects WSO2 API Manager 2.2.0 up to 4.0.0, WSO2 Identity Server 5.2.0 up to 5.11.0, WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0 and 5.6.0, WSO2 Identity Server as Key Manager 5.3.0 up to 5.11.0, WSO2 Enterprise Integrator 6.2.0 up to 6.6.0, WSO2 Open Banking AM 1.4.0 up to 2.0.0 and WSO2 Open Banking KM 1.4.0, up to 2.0.0.

- [https://github.com/hev0x/CVE-2022-29464](https://github.com/hev0x/CVE-2022-29464) :  ![starts](https://img.shields.io/github/stars/hev0x/CVE-2022-29464.svg) ![forks](https://img.shields.io/github/forks/hev0x/CVE-2022-29464.svg)


## CVE-2022-26134
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are from 1.3.0 before 7.4.17, from 7.13.0 before 7.13.7, from 7.14.0 before 7.14.3, from 7.15.0 before 7.15.2, from 7.16.0 before 7.16.4, from 7.17.0 before 7.17.4, and from 7.18.0 before 7.18.1.

- [https://github.com/hev0x/CVE-2022-26134](https://github.com/hev0x/CVE-2022-26134) :  ![starts](https://img.shields.io/github/stars/hev0x/CVE-2022-26134.svg) ![forks](https://img.shields.io/github/forks/hev0x/CVE-2022-26134.svg)


## CVE-2022-2414
 Access to external entities when parsing XML documents can lead to XML external entity (XXE) attacks. This flaw allows a remote attacker to potentially retrieve the content of arbitrary files by sending specially crafted HTTP requests.

- [https://github.com/amitlttwo/CVE-2022-2414-Proof-Of-Concept](https://github.com/amitlttwo/CVE-2022-2414-Proof-Of-Concept) :  ![starts](https://img.shields.io/github/stars/amitlttwo/CVE-2022-2414-Proof-Of-Concept.svg) ![forks](https://img.shields.io/github/forks/amitlttwo/CVE-2022-2414-Proof-Of-Concept.svg)


## CVE-2021-31630
 Command Injection in Open PLC Webserver v3 allows remote attackers to execute arbitrary code via the &quot;Hardware Layer Code Box&quot; component on the &quot;/hardware&quot; page of the application.

- [https://github.com/hev0x/CVE-2021-31630-OpenPLC_RCE](https://github.com/hev0x/CVE-2021-31630-OpenPLC_RCE) :  ![starts](https://img.shields.io/github/stars/hev0x/CVE-2021-31630-OpenPLC_RCE.svg) ![forks](https://img.shields.io/github/forks/hev0x/CVE-2021-31630-OpenPLC_RCE.svg)


## CVE-2021-26828
 OpenPLC ScadaBR through 0.9.1 on Linux and through 1.12.4 on Windows allows remote authenticated users to upload and execute arbitrary JSP files via view_edit.shtm.

- [https://github.com/hev0x/CVE-2021-26828_ScadaBR_RCE](https://github.com/hev0x/CVE-2021-26828_ScadaBR_RCE) :  ![starts](https://img.shields.io/github/stars/hev0x/CVE-2021-26828_ScadaBR_RCE.svg) ![forks](https://img.shields.io/github/forks/hev0x/CVE-2021-26828_ScadaBR_RCE.svg)


## CVE-2021-26084
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0 before 7.12.5.

- [https://github.com/hev0x/CVE-2021-26084_Confluence](https://github.com/hev0x/CVE-2021-26084_Confluence) :  ![starts](https://img.shields.io/github/stars/hev0x/CVE-2021-26084_Confluence.svg) ![forks](https://img.shields.io/github/forks/hev0x/CVE-2021-26084_Confluence.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/JoyGhoshs/CVE-2021-4034](https://github.com/JoyGhoshs/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/JoyGhoshs/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/JoyGhoshs/CVE-2021-4034.svg)


## CVE-2021-3560
 It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user. This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/BizarreLove/CVE-2021-3560](https://github.com/BizarreLove/CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/BizarreLove/CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/BizarreLove/CVE-2021-3560.svg)


## CVE-2021-2047
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core Components). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, and 12.2.1.3.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/somatrasss/weblogic2021](https://github.com/somatrasss/weblogic2021) :  ![starts](https://img.shields.io/github/stars/somatrasss/weblogic2021.svg) ![forks](https://img.shields.io/github/forks/somatrasss/weblogic2021.svg)


## CVE-2020-24186
 A Remote Code Execution vulnerability exists in the gVectors wpDiscuz plugin 7.0 through 7.0.4 for WordPress, which allows unauthenticated users to upload any type of file, including PHP files via the wmuUploadFiles AJAX action.

- [https://github.com/hev0x/CVE-2020-24186-WordPress-wpDiscuz-7.0.4-RCE](https://github.com/hev0x/CVE-2020-24186-WordPress-wpDiscuz-7.0.4-RCE) :  ![starts](https://img.shields.io/github/stars/hev0x/CVE-2020-24186-WordPress-wpDiscuz-7.0.4-RCE.svg) ![forks](https://img.shields.io/github/forks/hev0x/CVE-2020-24186-WordPress-wpDiscuz-7.0.4-RCE.svg)


## CVE-2019-12725
 Zeroshell 3.9.0 is prone to a remote command execution vulnerability. Specifically, this issue occurs because the web application mishandles a few HTTP parameters. An unauthenticated attacker can exploit this issue by injecting OS commands inside the vulnerable parameters.

- [https://github.com/hev0x/CVE-2019-12725-Command-Injection](https://github.com/hev0x/CVE-2019-12725-Command-Injection) :  ![starts](https://img.shields.io/github/stars/hev0x/CVE-2019-12725-Command-Injection.svg) ![forks](https://img.shields.io/github/forks/hev0x/CVE-2019-12725-Command-Injection.svg)


## CVE-2019-0808
 An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-0797.

- [https://github.com/ze0r/cve-2019-0808-poc](https://github.com/ze0r/cve-2019-0808-poc) :  ![starts](https://img.shields.io/github/stars/ze0r/cve-2019-0808-poc.svg) ![forks](https://img.shields.io/github/forks/ze0r/cve-2019-0808-poc.svg)


## CVE-2018-19422
 /panel/uploads in Subrion CMS 4.2.1 allows remote attackers to execute arbitrary PHP code via a .pht or .phar file, because the .htaccess file omits these.

- [https://github.com/hev0x/CVE-2018-19422-SubrionCMS-RCE](https://github.com/hev0x/CVE-2018-19422-SubrionCMS-RCE) :  ![starts](https://img.shields.io/github/stars/hev0x/CVE-2018-19422-SubrionCMS-RCE.svg) ![forks](https://img.shields.io/github/forks/hev0x/CVE-2018-19422-SubrionCMS-RCE.svg)


## CVE-2017-16524
 Web Viewer 1.0.0.193 on Samsung SRN-1670D devices suffers from an Unrestricted file upload vulnerability: 'network_ssl_upload.php' allows remote authenticated attackers to upload and execute arbitrary PHP code via a filename with a .php extension, which is then accessed via a direct request to the file in the upload/ directory. To authenticate for this attack, one can obtain web-interface credentials in cleartext by leveraging the existing Local File Read Vulnerability referenced as CVE-2015-8279, which allows remote attackers to read the web-interface credentials via a request for the cslog_export.php?path=/root/php_modules/lighttpd/sbin/userpw URI.

- [https://github.com/realistic-security/CVE-2017-16524](https://github.com/realistic-security/CVE-2017-16524) :  ![starts](https://img.shields.io/github/stars/realistic-security/CVE-2017-16524.svg) ![forks](https://img.shields.io/github/forks/realistic-security/CVE-2017-16524.svg)


## CVE-2009-3103
 Array index error in the SMBv2 protocol implementation in srv2.sys in Microsoft Windows Vista Gold, SP1, and SP2, Windows Server 2008 Gold and SP2, and Windows 7 RC allows remote attackers to execute arbitrary code or cause a denial of service (system crash) via an &amp; (ampersand) character in a Process ID High header field in a NEGOTIATE PROTOCOL REQUEST packet, which triggers an attempted dereference of an out-of-bounds memory location, aka &quot;SMBv2 Negotiation Vulnerability.&quot; NOTE: some of these details are obtained from third party information.

- [https://github.com/sec13b/ms09-050_CVE-2009-3103](https://github.com/sec13b/ms09-050_CVE-2009-3103) :  ![starts](https://img.shields.io/github/stars/sec13b/ms09-050_CVE-2009-3103.svg) ![forks](https://img.shields.io/github/forks/sec13b/ms09-050_CVE-2009-3103.svg)

