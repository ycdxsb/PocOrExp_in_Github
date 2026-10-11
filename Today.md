# Update 2026-10-11
## CVE-2026-107406
  *  NetScaler ADC 13.1-FIPS before13.1-NDcPP 13.1-37.279

- [https://github.com/ApexBreach/CVE-2026-107406-Poc](https://github.com/ApexBreach/CVE-2026-107406-Poc) :  ![starts](https://img.shields.io/github/stars/ApexBreach/CVE-2026-107406-Poc.svg) ![forks](https://img.shields.io/github/forks/ApexBreach/CVE-2026-107406-Poc.svg)
- [https://github.com/techupdate24/citrix-netscaler-rce-cve-2026-107406](https://github.com/techupdate24/citrix-netscaler-rce-cve-2026-107406) :  ![starts](https://img.shields.io/github/stars/techupdate24/citrix-netscaler-rce-cve-2026-107406.svg) ![forks](https://img.shields.io/github/forks/techupdate24/citrix-netscaler-rce-cve-2026-107406.svg)


## CVE-2026-88776
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23  leading to unpredictable or erroneous behavior or Denial of Service

- [https://github.com/Scyrix-LLC/CVE-2026-88776](https://github.com/Scyrix-LLC/CVE-2026-88776) :  ![starts](https://img.shields.io/github/stars/Scyrix-LLC/CVE-2026-88776.svg) ![forks](https://img.shields.io/github/forks/Scyrix-LLC/CVE-2026-88776.svg)


## CVE-2026-84520
 A buffer overflow was addressed with improved size validation. This issue is fixed in macOS Golden Gate 27. A local attacker may be able to cause unexpected system termination or corrupt kernel memory.

- [https://github.com/csrXamfi/CVE-2026-84520](https://github.com/csrXamfi/CVE-2026-84520) :  ![starts](https://img.shields.io/github/stars/csrXamfi/CVE-2026-84520.svg) ![forks](https://img.shields.io/github/forks/csrXamfi/CVE-2026-84520.svg)


## CVE-2026-80428
 ILIAS before versions 9.22, 10.10, and 11.3 contains an unauthenticated PHP object injection vulnerability that allows unauthenticated attackers to execute arbitrary code by injecting serialized objects through the LTI authentication endpoint and triggering deserialization via the Shibboleth back-channel logout endpoint. Attackers can write arbitrary serialized objects into session storage, then exploit an available POP gadget through the logout endpoint's unrestricted deserialization to write attacker-controlled PHP content to a web-accessible path and achieve remote code execution as the web server user.

- [https://github.com/HackfutSecRoot/CVE-2026-80428](https://github.com/HackfutSecRoot/CVE-2026-80428) :  ![starts](https://img.shields.io/github/stars/HackfutSecRoot/CVE-2026-80428.svg) ![forks](https://img.shields.io/github/forks/HackfutSecRoot/CVE-2026-80428.svg)


## CVE-2026-64560
---truncated---

- [https://github.com/sangsheng2026/honor-90gt-mag-an00-root-research](https://github.com/sangsheng2026/honor-90gt-mag-an00-root-research) :  ![starts](https://img.shields.io/github/stars/sangsheng2026/honor-90gt-mag-an00-root-research.svg) ![forks](https://img.shields.io/github/forks/sangsheng2026/honor-90gt-mag-an00-root-research.svg)


## CVE-2026-51994
 mcp-remote versions 0.1.32 through 0.1.38 are vulnerable to Server-Side Request Forgery (SSRF) via the resource_metadata URL extracted from a remote MCP server's WWW-Authenticate header

- [https://github.com/playb0t/mcp-remote-oauth-security](https://github.com/playb0t/mcp-remote-oauth-security) :  ![starts](https://img.shields.io/github/stars/playb0t/mcp-remote-oauth-security.svg) ![forks](https://img.shields.io/github/forks/playb0t/mcp-remote-oauth-security.svg)


## CVE-2026-44963
 A vulnerability allowing remote code execution (RCE) on the Backup Server by an authenticated domain user.

- [https://github.com/jockerjml/CVE-2026-44963-veeam-checker](https://github.com/jockerjml/CVE-2026-44963-veeam-checker) :  ![starts](https://img.shields.io/github/stars/jockerjml/CVE-2026-44963-veeam-checker.svg) ![forks](https://img.shields.io/github/forks/jockerjml/CVE-2026-44963-veeam-checker.svg)


## CVE-2026-28775
 An unauthenticated Remote Code Execution (RCE) vulnerability exists in the SNMP service of International Datacasting Corporation (IDC) SFX Series SuperFlex SatelliteReceiver. The deployment insecurely provisions the `private` SNMP community string with read/write access by default. Because the SNMP agent runs as root, an unauthenticated remote attacker can utilize `NET-SNMP-EXTEND-MIB` directives, abusing the fact that the system runs a vulnerable version of net-snmp pre 5.8, to execute arbitrary operating system commands with root privileges.

- [https://github.com/Udyz/CVE-2026-28775](https://github.com/Udyz/CVE-2026-28775) :  ![starts](https://img.shields.io/github/stars/Udyz/CVE-2026-28775.svg) ![forks](https://img.shields.io/github/forks/Udyz/CVE-2026-28775.svg)


## CVE-2026-24046
 Backstage is an open framework for building developer portals. Multiple Scaffolder actions and archive extraction utilities were vulnerable to symlink-based path traversal attacks. An attacker with access to create and execute Scaffolder templates could exploit symlinks to read arbitrary files via the `debug:log` action by creating a symlink pointing to sensitive files (e.g., `/etc/passwd`, configuration files, secrets); delete arbitrary files via the `fs:delete` action by creating symlinks pointing outside the workspace, and write files outside the workspace via archive extraction (tar/zip) containing malicious symlinks. This affects any Backstage deployment where users can create or execute Scaffolder templates. This vulnerability is fixed in `@backstage/backend-defaults` versions 0.12.2, 0.13.2, 0.14.1, and 0.15.0; `@backstage/plugin-scaffolder-backend` versions 2.2.2, 3.0.2, and 3.1.1; and `@backstage/plugin-scaffolder-node` versions 0.11.2 and 0.12.3. Users should upgrade to these versions or later. Some workarounds are available. Follow the recommendation in the Backstage Threat Model to limit access to creating and updating templates, restrict who can create and execute Scaffolder templates using the permissions framework, audit existing templates for symlink usage, and/or run Backstage in a containerized environment with limited filesystem access.

- [https://github.com/Rem1L/cve-2026-24046-poc](https://github.com/Rem1L/cve-2026-24046-poc) :  ![starts](https://img.shields.io/github/stars/Rem1L/cve-2026-24046-poc.svg) ![forks](https://img.shields.io/github/forks/Rem1L/cve-2026-24046-poc.svg)


## CVE-2026-21589
 This is a vulnerability in Bitbucket Data Center, Confluence Data Center, Jira Service Management Data Center, Jira Software Data Center, Bamboo Data Center. Crowd Data Center, Crucible and Fisheye. This Arbitrary File Access vulnerability allows an unauthenticated attacker to access specific files within the web application root directory in affected versions. Exploitation requires prior knowledge of the target file's exact name and path; this vulnerability does not allow attackers to enumerate or list directory contents. In some configurations, there may be some sensitive files that make this highly severe. This vulnerability allows an unauthenticated remote attacker to access specific files within the web application root directory in affected versions. The vulnerability must be addressed for affected versions of: -- Bitbucket Data Center, introduced in version = 4.6.0, fix versions: 9.4.26, 10.2.8, 10.5.1 -- Confluence Data Center, introduced in version = 5.10.0, fix versions 9.2.26, 10.2.19 -- Crowd Data Center, introduced in version = 2.11.0, fix versions 6.3.7, 7.0.3, 7.1.7, 7.2.4 -- Jira Software Data Center, introduced in version = 7.1.0, fix versions 9.12.40, 10.3.26, 11.3.12 -- Jira Service Management Data Center, introduced in version = 3.1.0, fix versions 5.12.40, 10.3.26, 11.3.12 -- Bamboo Data Center = 7.0.1, fix versions 10.2.24, 12.1.12 -- Crucible, fix versions 4.9.15 -- Fisheye, fix version 4.9.15 -- Exploitation requires prior knowledge of the target file's exact name and path. The vulnerability does not include the capability to enumerate or list directory contents.

- [https://github.com/gotr00t0day/CVE-2026-21589](https://github.com/gotr00t0day/CVE-2026-21589) :  ![starts](https://img.shields.io/github/stars/gotr00t0day/CVE-2026-21589.svg) ![forks](https://img.shields.io/github/forks/gotr00t0day/CVE-2026-21589.svg)


## CVE-2026-9514
 A security vulnerability has been detected in Totolink CA750-PoE 6.2c.510. Impacted is the function setNetworkDiag of the file /cgi-bin/cstecgi.cgi of the component Setting Handler. The manipulation of the argument NetDiagHost/NetDiagPingNum/NetDiagPingSize/NetDiagPingTimeOut/NetDiagTracertHop is directly passed by the attacker/so we can control the NetDiagHost/NetDiagPingNum/NetDiagPingSize/NetDiagPingTimeOut/NetDiagTracertHop leads to os command injection. The attack may be initiated remotely. The exploit has been disclosed publicly and may be used.

- [https://github.com/reputati0n/CVE-2026-95149](https://github.com/reputati0n/CVE-2026-95149) :  ![starts](https://img.shields.io/github/stars/reputati0n/CVE-2026-95149.svg) ![forks](https://img.shields.io/github/forks/reputati0n/CVE-2026-95149.svg)


## CVE-2026-9459
 A security flaw has been discovered in Edimax EW-7438RPn 1.31. This affects the function formConnectionSetting of the file /goform/formConnectionSetting. Performing a manipulation of the argument max_Conn/timeOut results in stack-based buffer overflow. It is possible to initiate the attack remotely. The exploit has been released to the public and may be used for attacks. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/canhieu/CVE-2026-94597-poc](https://github.com/canhieu/CVE-2026-94597-poc) :  ![starts](https://img.shields.io/github/stars/canhieu/CVE-2026-94597-poc.svg) ![forks](https://img.shields.io/github/forks/canhieu/CVE-2026-94597-poc.svg)


## CVE-2026-3143
 The Total Upkeep – WordPress Backup Plugin plus Restore & Migrate by BoldGrid plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'wp_ajax_cli_cancel' function in all versions up to, and including, 1.17.1. This makes it possible for unauthenticated attackers to cancel a pending rollback, potentially preventing a WordPress installation from automatically reverting a failed update.

- [https://github.com/SunL0w/PATCH-CVE-2026-31431-Ubuntu_Debian](https://github.com/SunL0w/PATCH-CVE-2026-31431-Ubuntu_Debian) :  ![starts](https://img.shields.io/github/stars/SunL0w/PATCH-CVE-2026-31431-Ubuntu_Debian.svg) ![forks](https://img.shields.io/github/forks/SunL0w/PATCH-CVE-2026-31431-Ubuntu_Debian.svg)


## CVE-2026-1045
 The Viet contact plugin for WordPress is vulnerable to Stored Cross-Site Scripting via admin settings in all versions up to, and including, 1.3.2 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with administrator-level permissions and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page. This only affects multi-site installations and installations where unfiltered_html has been disabled.

- [https://github.com/AmalJafarzade/CVE-2026-104587](https://github.com/AmalJafarzade/CVE-2026-104587) :  ![starts](https://img.shields.io/github/stars/AmalJafarzade/CVE-2026-104587.svg) ![forks](https://img.shields.io/github/forks/AmalJafarzade/CVE-2026-104587.svg)
- [https://github.com/AmalJafarzade/CVE-2026-104584](https://github.com/AmalJafarzade/CVE-2026-104584) :  ![starts](https://img.shields.io/github/stars/AmalJafarzade/CVE-2026-104584.svg) ![forks](https://img.shields.io/github/forks/AmalJafarzade/CVE-2026-104584.svg)
- [https://github.com/AmalJafarzade/CVE-2026-104585](https://github.com/AmalJafarzade/CVE-2026-104585) :  ![starts](https://img.shields.io/github/stars/AmalJafarzade/CVE-2026-104585.svg) ![forks](https://img.shields.io/github/forks/AmalJafarzade/CVE-2026-104585.svg)
- [https://github.com/AmalJafarzade/CVE-2026-104586](https://github.com/AmalJafarzade/CVE-2026-104586) :  ![starts](https://img.shields.io/github/stars/AmalJafarzade/CVE-2026-104586.svg) ![forks](https://img.shields.io/github/forks/AmalJafarzade/CVE-2026-104586.svg)


## CVE-2025-68613
 n8n is an open source workflow automation platform. Versions starting with 0.211.0 and prior to 1.120.4, 1.121.1, and 1.122.0 contain a critical Remote Code Execution (RCE) vulnerability in their workflow expression evaluation system. Under certain conditions, expressions supplied by authenticated users during workflow configuration may be evaluated in an execution context that is not sufficiently isolated from the underlying runtime. An authenticated attacker could abuse this behavior to execute arbitrary code with the privileges of the n8n process. Successful exploitation may lead to full compromise of the affected instance, including unauthorized access to sensitive data, modification of workflows, and execution of system-level operations. This issue has been fixed in versions 1.120.4, 1.121.1, and 1.122.0. Users are strongly advised to upgrade to a patched version, which introduces additional safeguards to restrict expression evaluation. If upgrading is not immediately possible, administrators should consider the following temporary mitigations: Limit workflow creation and editing permissions to fully trusted users only; and/or deploy n8n in a hardened environment with restricted operating system privileges and network access to reduce the impact of potential exploitation. These workarounds do not fully eliminate the risk and should only be used as short-term measures.

- [https://github.com/RianJuniorSf/Analysis-And-POC-N8N-CVE-2025-68613](https://github.com/RianJuniorSf/Analysis-And-POC-N8N-CVE-2025-68613) :  ![starts](https://img.shields.io/github/stars/RianJuniorSf/Analysis-And-POC-N8N-CVE-2025-68613.svg) ![forks](https://img.shields.io/github/forks/RianJuniorSf/Analysis-And-POC-N8N-CVE-2025-68613.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg)


## CVE-2025-41249
This CVE is published in conjunction with  CVE-2025-41248 https://spring.io/security/cve-2025-41248 .

- [https://github.com/edwin/simulating-cve-2025-41249](https://github.com/edwin/simulating-cve-2025-41249) :  ![starts](https://img.shields.io/github/stars/edwin/simulating-cve-2025-41249.svg) ![forks](https://img.shields.io/github/forks/edwin/simulating-cve-2025-41249.svg)


## CVE-2025-34071
 A remote code execution vulnerability in GFI Kerio Control 9.4.5 allows attackers with administrative access to upload and execute arbitrary code through the firmware upgrade feature. The system upgrade mechanism accepts unsigned .img files, which can be modified to include malicious scripts within the upgrade.sh or disk image components. These modified upgrade images are not validated for authenticity or integrity, and are executed by the system post-upload, enabling root access.

- [https://github.com/cppghoul/CVE-2025-34071](https://github.com/cppghoul/CVE-2025-34071) :  ![starts](https://img.shields.io/github/stars/cppghoul/CVE-2025-34071.svg) ![forks](https://img.shields.io/github/forks/cppghoul/CVE-2025-34071.svg)


## CVE-2025-26466
 A flaw was found in the OpenSSH package. For each ping packet the SSH server receives, a pong packet is allocated in a memory buffer and stored in a queue of packages. It is only freed when the server/client key exchange has finished. A malicious client may keep sending such packages, leading to an uncontrolled increase in memory consumption on the server side. Consequently, the server may become unavailable, resulting in a denial of service attack.

- [https://github.com/K0n9-log/cve-2025-26466-canvas](https://github.com/K0n9-log/cve-2025-26466-canvas) :  ![starts](https://img.shields.io/github/stars/K0n9-log/cve-2025-26466-canvas.svg) ![forks](https://img.shields.io/github/forks/K0n9-log/cve-2025-26466-canvas.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)


## CVE-2025-5518
This issue affects BILGER: before 2.4.6.

- [https://github.com/devianntsec/CVE-2025-55182](https://github.com/devianntsec/CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/devianntsec/CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/devianntsec/CVE-2025-55182.svg)


## CVE-2025-1122
Bypass operating system verification via exploiting the NV_Read functionality during the Challenge-Response process.

- [https://github.com/MCRideable3963/exploit-docs](https://github.com/MCRideable3963/exploit-docs) :  ![starts](https://img.shields.io/github/stars/MCRideable3963/exploit-docs.svg) ![forks](https://img.shields.io/github/forks/MCRideable3963/exploit-docs.svg)


## CVE-2024-36774
 An arbitrary file upload vulnerability in Monstra CMS v3.0.4 allows attackers to execute arbitrary code via uploading a crafted PHP file.

- [https://github.com/PawFV/CVE-2024-36774-Monstra-CMS-RCE-PoC](https://github.com/PawFV/CVE-2024-36774-Monstra-CMS-RCE-PoC) :  ![starts](https://img.shields.io/github/stars/PawFV/CVE-2024-36774-Monstra-CMS-RCE-PoC.svg) ![forks](https://img.shields.io/github/forks/PawFV/CVE-2024-36774-Monstra-CMS-RCE-PoC.svg)


## CVE-2024-28397
 An issue in the component js2py.disable_pyimport() of js2py up to v0.74 allows attackers to execute arbitrary code via a crafted API call.

- [https://github.com/RianJuniorSf/exploit-js2py](https://github.com/RianJuniorSf/exploit-js2py) :  ![starts](https://img.shields.io/github/stars/RianJuniorSf/exploit-js2py.svg) ![forks](https://img.shields.io/github/forks/RianJuniorSf/exploit-js2py.svg)


## CVE-2023-54391
 Proxmox Virtual Environment (VE) 7.0 through 8.0 contains an authentication bypass vulnerability in libpve-access-control before 8.0.4 that allows unauthenticated attackers to authenticate as any existing enabled user without a configured second factor by supplying an arbitrary tfa-challenge value in the API login endpoint. Attackers can send a POST request to the access ticket API endpoint with any value in the tfa-challenge parameter to completely skip password verification, gaining unauthorized access including to the root@pam account. All affected releases are end of life.

- [https://github.com/alexand0www/CVE-2023-54391-RCE](https://github.com/alexand0www/CVE-2023-54391-RCE) :  ![starts](https://img.shields.io/github/stars/alexand0www/CVE-2023-54391-RCE.svg) ![forks](https://img.shields.io/github/forks/alexand0www/CVE-2023-54391-RCE.svg)


## CVE-2022-21812
 Improper access control in the Intel(R) HAXM software before version 7.7.1 may allow an authenticated user to potentially enable escalation of privilege via local access.

- [https://github.com/NeroMinddd/intel-haxm-kernel-reverse-engineering-cve-2022-21812](https://github.com/NeroMinddd/intel-haxm-kernel-reverse-engineering-cve-2022-21812) :  ![starts](https://img.shields.io/github/stars/NeroMinddd/intel-haxm-kernel-reverse-engineering-cve-2022-21812.svg) ![forks](https://img.shields.io/github/forks/NeroMinddd/intel-haxm-kernel-reverse-engineering-cve-2022-21812.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/morgenm/dirtypipe](https://github.com/morgenm/dirtypipe) :  ![starts](https://img.shields.io/github/stars/morgenm/dirtypipe.svg) ![forks](https://img.shields.io/github/forks/morgenm/dirtypipe.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/ashique-thaha/CVE-2021-41773-POC](https://github.com/ashique-thaha/CVE-2021-41773-POC) :  ![starts](https://img.shields.io/github/stars/ashique-thaha/CVE-2021-41773-POC.svg) ![forks](https://img.shields.io/github/forks/ashique-thaha/CVE-2021-41773-POC.svg)
- [https://github.com/0xrogg/CVE-2021-41773](https://github.com/0xrogg/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/0xrogg/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/0xrogg/CVE-2021-41773.svg)


## CVE-2021-26882
 Remote Access API Elevation of Privilege Vulnerability

- [https://github.com/songjianyang/CVE-2021-26882](https://github.com/songjianyang/CVE-2021-26882) :  ![starts](https://img.shields.io/github/stars/songjianyang/CVE-2021-26882.svg) ![forks](https://img.shields.io/github/forks/songjianyang/CVE-2021-26882.svg)


## CVE-2021-26828
 OpenPLC ScadaBR through 0.9.1 on Linux and through 1.12.4 on Windows allows remote authenticated users to upload and execute arbitrary JSP files via view_edit.shtm.

- [https://github.com/h002733/CVE-2021-26828](https://github.com/h002733/CVE-2021-26828) :  ![starts](https://img.shields.io/github/stars/h002733/CVE-2021-26828.svg) ![forks](https://img.shields.io/github/forks/h002733/CVE-2021-26828.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/asd58584388/CVE-2021-44228](https://github.com/asd58584388/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/asd58584388/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/asd58584388/CVE-2021-44228.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/LayarKacaSiber/CVE-2021-41773](https://github.com/LayarKacaSiber/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/LayarKacaSiber/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/LayarKacaSiber/CVE-2021-41773.svg)
- [https://github.com/redspy-sec/CVE-2021-41773](https://github.com/redspy-sec/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/redspy-sec/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/redspy-sec/CVE-2021-41773.svg)


## CVE-2021-1675
 Windows Print Spooler Remote Code Execution Vulnerability

- [https://github.com/cube0x0/CVE-2021-1675](https://github.com/cube0x0/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/cube0x0/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/cube0x0/CVE-2021-1675.svg)
- [https://github.com/calebstewart/CVE-2021-1675](https://github.com/calebstewart/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/calebstewart/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/calebstewart/CVE-2021-1675.svg)
- [https://github.com/BeetleChunks/SpoolSploit](https://github.com/BeetleChunks/SpoolSploit) :  ![starts](https://img.shields.io/github/stars/BeetleChunks/SpoolSploit.svg) ![forks](https://img.shields.io/github/forks/BeetleChunks/SpoolSploit.svg)
- [https://github.com/hlldz/CVE-2021-1675-LPE](https://github.com/hlldz/CVE-2021-1675-LPE) :  ![starts](https://img.shields.io/github/stars/hlldz/CVE-2021-1675-LPE.svg) ![forks](https://img.shields.io/github/forks/hlldz/CVE-2021-1675-LPE.svg)
- [https://github.com/ly4k/PrintNightmare](https://github.com/ly4k/PrintNightmare) :  ![starts](https://img.shields.io/github/stars/ly4k/PrintNightmare.svg) ![forks](https://img.shields.io/github/forks/ly4k/PrintNightmare.svg)
- [https://github.com/LaresLLC/CVE-2021-1675](https://github.com/LaresLLC/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/LaresLLC/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/LaresLLC/CVE-2021-1675.svg)
- [https://github.com/nemo-wq/PrintNightmare-CVE-2021-34527](https://github.com/nemo-wq/PrintNightmare-CVE-2021-34527) :  ![starts](https://img.shields.io/github/stars/nemo-wq/PrintNightmare-CVE-2021-34527.svg) ![forks](https://img.shields.io/github/forks/nemo-wq/PrintNightmare-CVE-2021-34527.svg)
- [https://github.com/mstxq17/CVE-2021-1675_RDL_LPE](https://github.com/mstxq17/CVE-2021-1675_RDL_LPE) :  ![starts](https://img.shields.io/github/stars/mstxq17/CVE-2021-1675_RDL_LPE.svg) ![forks](https://img.shields.io/github/forks/mstxq17/CVE-2021-1675_RDL_LPE.svg)
- [https://github.com/sailay1996/PrintNightmare-LPE](https://github.com/sailay1996/PrintNightmare-LPE) :  ![starts](https://img.shields.io/github/stars/sailay1996/PrintNightmare-LPE.svg) ![forks](https://img.shields.io/github/forks/sailay1996/PrintNightmare-LPE.svg)
- [https://github.com/evilashz/CVE-2021-1675-LPE-EXP](https://github.com/evilashz/CVE-2021-1675-LPE-EXP) :  ![starts](https://img.shields.io/github/stars/evilashz/CVE-2021-1675-LPE-EXP.svg) ![forks](https://img.shields.io/github/forks/evilashz/CVE-2021-1675-LPE-EXP.svg)
- [https://github.com/cybersecurityworks553/CVE-2021-1675_PrintNightMare](https://github.com/cybersecurityworks553/CVE-2021-1675_PrintNightMare) :  ![starts](https://img.shields.io/github/stars/cybersecurityworks553/CVE-2021-1675_PrintNightMare.svg) ![forks](https://img.shields.io/github/forks/cybersecurityworks553/CVE-2021-1675_PrintNightMare.svg)
- [https://github.com/JumpsecLabs/PrintNightmare](https://github.com/JumpsecLabs/PrintNightmare) :  ![starts](https://img.shields.io/github/stars/JumpsecLabs/PrintNightmare.svg) ![forks](https://img.shields.io/github/forks/JumpsecLabs/PrintNightmare.svg)
- [https://github.com/eversinc33/NimNightmare](https://github.com/eversinc33/NimNightmare) :  ![starts](https://img.shields.io/github/stars/eversinc33/NimNightmare.svg) ![forks](https://img.shields.io/github/forks/eversinc33/NimNightmare.svg)
- [https://github.com/k8gege/cve-2021-1675](https://github.com/k8gege/cve-2021-1675) :  ![starts](https://img.shields.io/github/stars/k8gege/cve-2021-1675.svg) ![forks](https://img.shields.io/github/forks/k8gege/cve-2021-1675.svg)
- [https://github.com/Wra7h/SharpPN](https://github.com/Wra7h/SharpPN) :  ![starts](https://img.shields.io/github/stars/Wra7h/SharpPN.svg) ![forks](https://img.shields.io/github/forks/Wra7h/SharpPN.svg)
- [https://github.com/corelight/CVE-2021-1675](https://github.com/corelight/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/corelight/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/corelight/CVE-2021-1675.svg)
- [https://github.com/Leonidus0x10/CVE-2021-1675-SCANNER](https://github.com/Leonidus0x10/CVE-2021-1675-SCANNER) :  ![starts](https://img.shields.io/github/stars/Leonidus0x10/CVE-2021-1675-SCANNER.svg) ![forks](https://img.shields.io/github/forks/Leonidus0x10/CVE-2021-1675-SCANNER.svg)
- [https://github.com/exploitblizzard/PrintNightmare-CVE-2021-1675](https://github.com/exploitblizzard/PrintNightmare-CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/exploitblizzard/PrintNightmare-CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/exploitblizzard/PrintNightmare-CVE-2021-1675.svg)
- [https://github.com/AndrewTrube/CVE-2021-1675](https://github.com/AndrewTrube/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/AndrewTrube/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/AndrewTrube/CVE-2021-1675.svg)
- [https://github.com/hahaleyile/my-CVE-2021-1675](https://github.com/hahaleyile/my-CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/hahaleyile/my-CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/hahaleyile/my-CVE-2021-1675.svg)
- [https://github.com/thomasgeens/CVE-2021-1675](https://github.com/thomasgeens/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/thomasgeens/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/thomasgeens/CVE-2021-1675.svg)
- [https://github.com/Tomparte/PrintNightmare](https://github.com/Tomparte/PrintNightmare) :  ![starts](https://img.shields.io/github/stars/Tomparte/PrintNightmare.svg) ![forks](https://img.shields.io/github/forks/Tomparte/PrintNightmare.svg)
- [https://github.com/kondah/patch-cve-2021-1675](https://github.com/kondah/patch-cve-2021-1675) :  ![starts](https://img.shields.io/github/stars/kondah/patch-cve-2021-1675.svg) ![forks](https://img.shields.io/github/forks/kondah/patch-cve-2021-1675.svg)
- [https://github.com/yu2u/CVE-2021-1675](https://github.com/yu2u/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/yu2u/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/yu2u/CVE-2021-1675.svg)
- [https://github.com/bartimusprimed/CVE-2021-1675-Yara](https://github.com/bartimusprimed/CVE-2021-1675-Yara) :  ![starts](https://img.shields.io/github/stars/bartimusprimed/CVE-2021-1675-Yara.svg) ![forks](https://img.shields.io/github/forks/bartimusprimed/CVE-2021-1675-Yara.svg)
- [https://github.com/TheJoyOfHacking/calebstewart-CVE-2021-1675](https://github.com/TheJoyOfHacking/calebstewart-CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/TheJoyOfHacking/calebstewart-CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/TheJoyOfHacking/calebstewart-CVE-2021-1675.svg)
- [https://github.com/killtr0/CVE-2021-1675-PrintNightmare](https://github.com/killtr0/CVE-2021-1675-PrintNightmare) :  ![starts](https://img.shields.io/github/stars/killtr0/CVE-2021-1675-PrintNightmare.svg) ![forks](https://img.shields.io/github/forks/killtr0/CVE-2021-1675-PrintNightmare.svg)
- [https://github.com/ozergoker/PrintNightmare](https://github.com/ozergoker/PrintNightmare) :  ![starts](https://img.shields.io/github/stars/ozergoker/PrintNightmare.svg) ![forks](https://img.shields.io/github/forks/ozergoker/PrintNightmare.svg)
- [https://github.com/puckiestyle/CVE-2021-1675](https://github.com/puckiestyle/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-1675.svg)
- [https://github.com/OppressionBreedsResistance/CVE-2021-1675-PrintNightmare](https://github.com/OppressionBreedsResistance/CVE-2021-1675-PrintNightmare) :  ![starts](https://img.shields.io/github/stars/OppressionBreedsResistance/CVE-2021-1675-PrintNightmare.svg) ![forks](https://img.shields.io/github/forks/OppressionBreedsResistance/CVE-2021-1675-PrintNightmare.svg)
- [https://github.com/DLL00P/CVE-2021-1675](https://github.com/DLL00P/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/DLL00P/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/DLL00P/CVE-2021-1675.svg)
- [https://github.com/Winter3un/CVE-2021-1675](https://github.com/Winter3un/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/Winter3un/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/Winter3un/CVE-2021-1675.svg)
- [https://github.com/whoami-chmod777/CVE-2021-1675-CVE-2021-34527](https://github.com/whoami-chmod777/CVE-2021-1675-CVE-2021-34527) :  ![starts](https://img.shields.io/github/stars/whoami-chmod777/CVE-2021-1675-CVE-2021-34527.svg) ![forks](https://img.shields.io/github/forks/whoami-chmod777/CVE-2021-1675-CVE-2021-34527.svg)
- [https://github.com/pentagon404uzb/CVE-2021-1675-Local-Privilege-Escalation-CVSS-7.8-](https://github.com/pentagon404uzb/CVE-2021-1675-Local-Privilege-Escalation-CVSS-7.8-) :  ![starts](https://img.shields.io/github/stars/pentagon404uzb/CVE-2021-1675-Local-Privilege-Escalation-CVSS-7.8-.svg) ![forks](https://img.shields.io/github/forks/pentagon404uzb/CVE-2021-1675-Local-Privilege-Escalation-CVSS-7.8-.svg)
- [https://github.com/peckre/PNCVE-Win10-20H2-Exploit](https://github.com/peckre/PNCVE-Win10-20H2-Exploit) :  ![starts](https://img.shields.io/github/stars/peckre/PNCVE-Win10-20H2-Exploit.svg) ![forks](https://img.shields.io/github/forks/peckre/PNCVE-Win10-20H2-Exploit.svg)
- [https://github.com/tanarchytan/CVE-2021-1675](https://github.com/tanarchytan/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/tanarchytan/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/tanarchytan/CVE-2021-1675.svg)
- [https://github.com/zha0/Microsoft-CVE-2021-1675](https://github.com/zha0/Microsoft-CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/zha0/Microsoft-CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/zha0/Microsoft-CVE-2021-1675.svg)
- [https://github.com/initconf/cve-2021-1675-printnightmare](https://github.com/initconf/cve-2021-1675-printnightmare) :  ![starts](https://img.shields.io/github/stars/initconf/cve-2021-1675-printnightmare.svg) ![forks](https://img.shields.io/github/forks/initconf/cve-2021-1675-printnightmare.svg)
- [https://github.com/edsonjt81/CVE-2021-1675](https://github.com/edsonjt81/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/edsonjt81/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/edsonjt81/CVE-2021-1675.svg)
- [https://github.com/HKenzoKimura/CVE-2021-1675](https://github.com/HKenzoKimura/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/HKenzoKimura/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/HKenzoKimura/CVE-2021-1675.svg)
- [https://github.com/000Tonio/cve-2021-1675](https://github.com/000Tonio/cve-2021-1675) :  ![starts](https://img.shields.io/github/stars/000Tonio/cve-2021-1675.svg) ![forks](https://img.shields.io/github/forks/000Tonio/cve-2021-1675.svg)
- [https://github.com/kougyokugentou/CVE-2021-1675](https://github.com/kougyokugentou/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/kougyokugentou/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/kougyokugentou/CVE-2021-1675.svg)
- [https://github.com/ccordeiro/CVE-2021-1675](https://github.com/ccordeiro/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/ccordeiro/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/ccordeiro/CVE-2021-1675.svg)
- [https://github.com/ptter23/CVE-2021-1675](https://github.com/ptter23/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/ptter23/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/ptter23/CVE-2021-1675.svg)
- [https://github.com/thalpius/microsoft-cve-2021-1675](https://github.com/thalpius/microsoft-cve-2021-1675) :  ![starts](https://img.shields.io/github/stars/thalpius/microsoft-cve-2021-1675.svg) ![forks](https://img.shields.io/github/forks/thalpius/microsoft-cve-2021-1675.svg)
- [https://github.com/VelesSecurity/CVE-2021-1675-PrintNightmare-Analysis](https://github.com/VelesSecurity/CVE-2021-1675-PrintNightmare-Analysis) :  ![starts](https://img.shields.io/github/stars/VelesSecurity/CVE-2021-1675-PrintNightmare-Analysis.svg) ![forks](https://img.shields.io/github/forks/VelesSecurity/CVE-2021-1675-PrintNightmare-Analysis.svg)
- [https://github.com/Sp4ceDogy/NPE-CS-V-CVE-2021-1675](https://github.com/Sp4ceDogy/NPE-CS-V-CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/Sp4ceDogy/NPE-CS-V-CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/Sp4ceDogy/NPE-CS-V-CVE-2021-1675.svg)
- [https://github.com/0xSs0rZ/Windows_Exploit](https://github.com/0xSs0rZ/Windows_Exploit) :  ![starts](https://img.shields.io/github/stars/0xSs0rZ/Windows_Exploit.svg) ![forks](https://img.shields.io/github/forks/0xSs0rZ/Windows_Exploit.svg)
- [https://github.com/mrezqi/CVE-2021-1675_CarbonBlack_HuntingQuery](https://github.com/mrezqi/CVE-2021-1675_CarbonBlack_HuntingQuery) :  ![starts](https://img.shields.io/github/stars/mrezqi/CVE-2021-1675_CarbonBlack_HuntingQuery.svg) ![forks](https://img.shields.io/github/forks/mrezqi/CVE-2021-1675_CarbonBlack_HuntingQuery.svg)
- [https://github.com/TheJoyOfHacking/cube0x0-CVE-2021-1675](https://github.com/TheJoyOfHacking/cube0x0-CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/TheJoyOfHacking/cube0x0-CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/TheJoyOfHacking/cube0x0-CVE-2021-1675.svg)
- [https://github.com/whoami-chmod777/CVE-2021-1675---PrintNightmare-LPE-PowerShell-](https://github.com/whoami-chmod777/CVE-2021-1675---PrintNightmare-LPE-PowerShell-) :  ![starts](https://img.shields.io/github/stars/whoami-chmod777/CVE-2021-1675---PrintNightmare-LPE-PowerShell-.svg) ![forks](https://img.shields.io/github/forks/whoami-chmod777/CVE-2021-1675---PrintNightmare-LPE-PowerShell-.svg)
- [https://github.com/galoget/PrintNightmare-CVE-2021-1675-CVE-2021-34527](https://github.com/galoget/PrintNightmare-CVE-2021-1675-CVE-2021-34527) :  ![starts](https://img.shields.io/github/stars/galoget/PrintNightmare-CVE-2021-1675-CVE-2021-34527.svg) ![forks](https://img.shields.io/github/forks/galoget/PrintNightmare-CVE-2021-1675-CVE-2021-34527.svg)
- [https://github.com/r1skkam/PrintNightmare](https://github.com/r1skkam/PrintNightmare) :  ![starts](https://img.shields.io/github/stars/r1skkam/PrintNightmare.svg) ![forks](https://img.shields.io/github/forks/r1skkam/PrintNightmare.svg)
- [https://github.com/fengjixuchui/CVE-2021-34527-1675](https://github.com/fengjixuchui/CVE-2021-34527-1675) :  ![starts](https://img.shields.io/github/stars/fengjixuchui/CVE-2021-34527-1675.svg) ![forks](https://img.shields.io/github/forks/fengjixuchui/CVE-2021-34527-1675.svg)
- [https://github.com/DenizSe/CVE-2021-34527](https://github.com/DenizSe/CVE-2021-34527) :  ![starts](https://img.shields.io/github/stars/DenizSe/CVE-2021-34527.svg) ![forks](https://img.shields.io/github/forks/DenizSe/CVE-2021-34527.svg)
- [https://github.com/Sirius-RJ/FullstackAcademy-Printernightmare-writeup-2105-E.C.A.R.](https://github.com/Sirius-RJ/FullstackAcademy-Printernightmare-writeup-2105-E.C.A.R.) :  ![starts](https://img.shields.io/github/stars/Sirius-RJ/FullstackAcademy-Printernightmare-writeup-2105-E.C.A.R..svg) ![forks](https://img.shields.io/github/forks/Sirius-RJ/FullstackAcademy-Printernightmare-writeup-2105-E.C.A.R..svg)


## CVE-2021-1656
 TPM Device Driver Information Disclosure Vulnerability

- [https://github.com/waleedassar/CVE-2021-1656](https://github.com/waleedassar/CVE-2021-1656) :  ![starts](https://img.shields.io/github/stars/waleedassar/CVE-2021-1656.svg) ![forks](https://img.shields.io/github/forks/waleedassar/CVE-2021-1656.svg)


## CVE-2017-12615
 When running Apache Tomcat 7.0.0 to 7.0.79 on Windows with HTTP PUTs enabled (e.g. via setting the readonly initialisation parameter of the Default to false) it was possible to upload a JSP file to the server via a specially crafted request. This JSP could then be requested and any code it contained would be executed by the server.

- [https://github.com/nouhaila2030/apache-tomcat-security-audit](https://github.com/nouhaila2030/apache-tomcat-security-audit) :  ![starts](https://img.shields.io/github/stars/nouhaila2030/apache-tomcat-security-audit.svg) ![forks](https://img.shields.io/github/forks/nouhaila2030/apache-tomcat-security-audit.svg)


## CVE-2017-5638
 The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.

- [https://github.com/NAIRBS/SC3010-Grp-33](https://github.com/NAIRBS/SC3010-Grp-33) :  ![starts](https://img.shields.io/github/stars/NAIRBS/SC3010-Grp-33.svg) ![forks](https://img.shields.io/github/forks/NAIRBS/SC3010-Grp-33.svg)


## CVE-2013-4547
 nginx 0.8.41 through 1.4.3 and 1.5.x before 1.5.7 allows remote attackers to bypass intended restrictions via an unescaped space character in a URI.

- [https://github.com/CyberCTF/vulhub-nginx-cve-2013-4547](https://github.com/CyberCTF/vulhub-nginx-cve-2013-4547) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-nginx-cve-2013-4547.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-nginx-cve-2013-4547.svg)


## CVE-2012-2122
 sql/password.c in Oracle MySQL 5.1.x before 5.1.63, 5.5.x before 5.5.24, and 5.6.x before 5.6.6, and MariaDB 5.1.x before 5.1.62, 5.2.x before 5.2.12, 5.3.x before 5.3.6, and 5.5.x before 5.5.23, when running in certain environments with certain implementations of the memcmp function, allows remote attackers to bypass authentication by repeatedly authenticating with the same incorrect password, which eventually causes a token comparison to succeed due to an improperly-checked return value.

- [https://github.com/CyberCTF/vulhub-mysql-cve-2012-2122](https://github.com/CyberCTF/vulhub-mysql-cve-2012-2122) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-mysql-cve-2012-2122.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-mysql-cve-2012-2122.svg)


## CVE-2012-1823
 sapi/cgi/cgi_main.c in PHP before 5.3.12 and 5.4.x before 5.4.2, when configured as a CGI script (aka php-cgi), does not properly handle query strings that lack an = (equals sign) character, which allows remote attackers to execute arbitrary code by placing command-line options in the query string, related to lack of skipping a certain php_getopt for the 'd' case.

- [https://github.com/CyberCTF/vulhub-php-cve-2012-1823](https://github.com/CyberCTF/vulhub-php-cve-2012-1823) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-php-cve-2012-1823.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-php-cve-2012-1823.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/Maalfer/CVE-2011-2523-vsftpd-2.3.4-exploit](https://github.com/Maalfer/CVE-2011-2523-vsftpd-2.3.4-exploit) :  ![starts](https://img.shields.io/github/stars/Maalfer/CVE-2011-2523-vsftpd-2.3.4-exploit.svg) ![forks](https://img.shields.io/github/forks/Maalfer/CVE-2011-2523-vsftpd-2.3.4-exploit.svg)


## CVE-2010-2861
 Multiple directory traversal vulnerabilities in the administrator console in Adobe ColdFusion 9.0.1 and earlier allow remote attackers to read arbitrary files via the locale parameter to (1) CFIDE/administrator/settings/mappings.cfm, (2) logging/settings.cfm, (3) datasources/index.cfm, (4) j2eepackaging/editarchive.cfm, and (5) enter.cfm in CFIDE/administrator/.

- [https://github.com/CyberCTF/vulhub-coldfusion-cve-2010-2861](https://github.com/CyberCTF/vulhub-coldfusion-cve-2010-2861) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-coldfusion-cve-2010-2861.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-coldfusion-cve-2010-2861.svg)


## CVE-2007-6750
 The Apache HTTP Server 1.x and 2.x allows remote attackers to cause a denial of service (daemon outage) via partial HTTP requests, as demonstrated by Slowloris, related to the lack of the mod_reqtimeout module in versions before 2.2.15.

- [https://github.com/michou79/noc21220-cybersecurity-assessment](https://github.com/michou79/noc21220-cybersecurity-assessment) :  ![starts](https://img.shields.io/github/stars/michou79/noc21220-cybersecurity-assessment.svg) ![forks](https://img.shields.io/github/forks/michou79/noc21220-cybersecurity-assessment.svg)

