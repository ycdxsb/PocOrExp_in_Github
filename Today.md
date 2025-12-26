# Update 2025-12-26
## CVE-2025-68613
 n8n is an open source workflow automation platform. Versions starting with 0.211.0 and prior to 1.120.4, 1.121.1, and 1.122.0 contain a critical Remote Code Execution (RCE) vulnerability in their workflow expression evaluation system. Under certain conditions, expressions supplied by authenticated users during workflow configuration may be evaluated in an execution context that is not sufficiently isolated from the underlying runtime. An authenticated attacker could abuse this behavior to execute arbitrary code with the privileges of the n8n process. Successful exploitation may lead to full compromise of the affected instance, including unauthorized access to sensitive data, modification of workflows, and execution of system-level operations. This issue has been fixed in versions 1.120.4, 1.121.1, and 1.122.0. Users are strongly advised to upgrade to a patched version, which introduces additional safeguards to restrict expression evaluation. If upgrading is not immediately possible, administrators should consider the following temporary mitigations: Limit workflow creation and editing permissions to fully trusted users only; and/or deploy n8n in a hardened environment with restricted operating system privileges and network access to reduce the impact of potential exploitation. These workarounds do not fully eliminate the risk and should only be used as short-term measures.

- [https://github.com/r4j3sh-com/CVE-2025-68613-n8n-lab](https://github.com/r4j3sh-com/CVE-2025-68613-n8n-lab) :  ![starts](https://img.shields.io/github/stars/r4j3sh-com/CVE-2025-68613-n8n-lab.svg) ![forks](https://img.shields.io/github/forks/r4j3sh-com/CVE-2025-68613-n8n-lab.svg)
- [https://github.com/intelligent-ears/CVE-2025-68613](https://github.com/intelligent-ears/CVE-2025-68613) :  ![starts](https://img.shields.io/github/stars/intelligent-ears/CVE-2025-68613.svg) ![forks](https://img.shields.io/github/forks/intelligent-ears/CVE-2025-68613.svg)
- [https://github.com/secjoker/CVE-2025-68613](https://github.com/secjoker/CVE-2025-68613) :  ![starts](https://img.shields.io/github/stars/secjoker/CVE-2025-68613.svg) ![forks](https://img.shields.io/github/forks/secjoker/CVE-2025-68613.svg)
- [https://github.com/manyaigdtuw/CVE-2025-68613_Scanner](https://github.com/manyaigdtuw/CVE-2025-68613_Scanner) :  ![starts](https://img.shields.io/github/stars/manyaigdtuw/CVE-2025-68613_Scanner.svg) ![forks](https://img.shields.io/github/forks/manyaigdtuw/CVE-2025-68613_Scanner.svg)


## CVE-2025-51471
 Cross-Domain Token Exposure in server.auth.getAuthorizationToken in Ollama 0.6.7 allows remote attackers to steal authentication tokens and bypass access controls via a malicious realm value in a WWW-Authenticate header returned by the /api/pull endpoint.

- [https://github.com/ajtazer/CVE-2025-51471-POC](https://github.com/ajtazer/CVE-2025-51471-POC) :  ![starts](https://img.shields.io/github/stars/ajtazer/CVE-2025-51471-POC.svg) ![forks](https://img.shields.io/github/forks/ajtazer/CVE-2025-51471-POC.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/maronnjapan/claude-create-CVE-2025-29927](https://github.com/maronnjapan/claude-create-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/maronnjapan/claude-create-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/maronnjapan/claude-create-CVE-2025-29927.svg)


## CVE-2025-11833
 The Post SMTP – Complete SMTP Solution with Logs, Alerts, Backup SMTP & Mobile App plugin for WordPress is vulnerable to unauthorized access of data due to a missing capability check on the __construct function in all versions up to, and including, 3.6.0. This makes it possible for unauthenticated attackers to read arbitrary logged emails sent through the Post SMTP plugin, including password reset emails containing password reset links, which can lead to account takeover.

- [https://github.com/halilkirazkaya/CVE-2025-11833](https://github.com/halilkirazkaya/CVE-2025-11833) :  ![starts](https://img.shields.io/github/stars/halilkirazkaya/CVE-2025-11833.svg) ![forks](https://img.shields.io/github/forks/halilkirazkaya/CVE-2025-11833.svg)


## CVE-2025-6394
 A vulnerability was found in code-projects Simple Online Hotel Reservation System 1.0. It has been declared as critical. Affected by this vulnerability is an unknown functionality of the file /add_reserve.php. The manipulation of the argument firstname leads to sql injection. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. Other parameters might be affected as well.

- [https://github.com/alexlee820/CVE-2025-63946-Tencent-PC-Manager-EoP](https://github.com/alexlee820/CVE-2025-63946-Tencent-PC-Manager-EoP) :  ![starts](https://img.shields.io/github/stars/alexlee820/CVE-2025-63946-Tencent-PC-Manager-EoP.svg) ![forks](https://img.shields.io/github/forks/alexlee820/CVE-2025-63946-Tencent-PC-Manager-EoP.svg)


## CVE-2024-57394
 The quarantine - restore function in Qi-ANXIN Tianqing Endpoint Security Management System v10.0 allows user to restore a malicious file to an arbitrary file path. Attackers can write malicious DLL to system path and perform privilege escalation by leveraging Windows DLL hijacking vulnerabilities.

- [https://github.com/cwjchoi01/CVE-2024-57394](https://github.com/cwjchoi01/CVE-2024-57394) :  ![starts](https://img.shields.io/github/stars/cwjchoi01/CVE-2024-57394.svg) ![forks](https://img.shields.io/github/forks/cwjchoi01/CVE-2024-57394.svg)


## CVE-2024-34351
 Next.js is a React framework that can provide building blocks to create web applications. A Server-Side Request Forgery (SSRF) vulnerability was identified in Next.js Server Actions. If the `Host` header is modified, and the below conditions are also met, an attacker may be able to make requests that appear to be originating from the Next.js application server itself. The required conditions are 1) Next.js is running in a self-hosted manner; 2) the Next.js application makes use of Server Actions; and 3) the Server Action performs a redirect to a relative path which starts with a `/`. This vulnerability was fixed in Next.js `14.1.1`.

- [https://github.com/granita112/cve-2024-34351-tester](https://github.com/granita112/cve-2024-34351-tester) :  ![starts](https://img.shields.io/github/stars/granita112/cve-2024-34351-tester.svg) ![forks](https://img.shields.io/github/forks/granita112/cve-2024-34351-tester.svg)


## CVE-2024-5518
 A vulnerability classified as critical has been found in itsourcecode Online Discussion Forum 1.0. This affects an unknown part of the file change_profile_picture.php. The manipulation of the argument image leads to unrestricted upload. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-266589 was assigned to this vulnerability.

- [https://github.com/mallo-m/CVE-2024-55187](https://github.com/mallo-m/CVE-2024-55187) :  ![starts](https://img.shields.io/github/stars/mallo-m/CVE-2024-55187.svg) ![forks](https://img.shields.io/github/forks/mallo-m/CVE-2024-55187.svg)


## CVE-2023-38831
 RARLAB WinRAR before 6.23 allows attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive. The issue occurs because a ZIP archive may include a benign file (such as an ordinary .JPG file) and also a folder that has the same name as the benign file, and the contents of the folder (which may include executable content) are processed during an attempt to access only the benign file. This was exploited in the wild in April through October 2023.

- [https://github.com/ouoxii/Software-Testing-Final-Project](https://github.com/ouoxii/Software-Testing-Final-Project) :  ![starts](https://img.shields.io/github/stars/ouoxii/Software-Testing-Final-Project.svg) ![forks](https://img.shields.io/github/forks/ouoxii/Software-Testing-Final-Project.svg)


## CVE-2023-30253
 Dolibarr before 17.0.1 allows remote code execution by an authenticated user via an uppercase manipulation: ?PHP instead of ?php in injected data.

- [https://github.com/1lkla/POC-exploit-for-Dolibarr](https://github.com/1lkla/POC-exploit-for-Dolibarr) :  ![starts](https://img.shields.io/github/stars/1lkla/POC-exploit-for-Dolibarr.svg) ![forks](https://img.shields.io/github/forks/1lkla/POC-exploit-for-Dolibarr.svg)


## CVE-2023-0669
 Fortra (formerly, HelpSystems) GoAnywhere MFT suffers from a pre-authentication command injection vulnerability in the License Response Servlet due to deserializing an arbitrary attacker-controlled object. This issue was patched in version 7.1.2.

- [https://github.com/zakaria-laouani/cve-2023-0669-simulation](https://github.com/zakaria-laouani/cve-2023-0669-simulation) :  ![starts](https://img.shields.io/github/stars/zakaria-laouani/cve-2023-0669-simulation.svg) ![forks](https://img.shields.io/github/forks/zakaria-laouani/cve-2023-0669-simulation.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/TheLastVvV/CVE-2021-41773](https://github.com/TheLastVvV/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/TheLastVvV/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/TheLastVvV/CVE-2021-41773.svg)
- [https://github.com/faizdotid/CVE-2021-41773](https://github.com/faizdotid/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/faizdotid/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/faizdotid/CVE-2021-41773.svg)
- [https://github.com/Fa1c0n35/CVE-2021-41773](https://github.com/Fa1c0n35/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Fa1c0n35/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Fa1c0n35/CVE-2021-41773.svg)
- [https://github.com/skentagon/CVE-2021-41773](https://github.com/skentagon/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/skentagon/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/skentagon/CVE-2021-41773.svg)


## CVE-2021-2220
 Vulnerability in the PeopleSoft Enterprise SCM eProcurement product of Oracle PeopleSoft (component: Manage Requisition Status). The supported version that is affected is 9.2. Easily exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise PeopleSoft Enterprise SCM eProcurement. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of PeopleSoft Enterprise SCM eProcurement accessible data as well as unauthorized read access to a subset of PeopleSoft Enterprise SCM eProcurement accessible data. CVSS 3.1 Base Score 5.4 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N).

- [https://github.com/nyambiblaise/Walkthrough---Subrion-CMS-Web-Shell-Upload-to-Cron-Based-Privilege-Escalation-CVE-2021-2220-](https://github.com/nyambiblaise/Walkthrough---Subrion-CMS-Web-Shell-Upload-to-Cron-Based-Privilege-Escalation-CVE-2021-2220-) :  ![starts](https://img.shields.io/github/stars/nyambiblaise/Walkthrough---Subrion-CMS-Web-Shell-Upload-to-Cron-Based-Privilege-Escalation-CVE-2021-2220-.svg) ![forks](https://img.shields.io/github/forks/nyambiblaise/Walkthrough---Subrion-CMS-Web-Shell-Upload-to-Cron-Based-Privilege-Escalation-CVE-2021-2220-.svg)


## CVE-2016-15041
 The MainWP Dashboard – The Private WordPress Manager for Multiple Website Maintenance plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the ‘mwp_setup_purchase_username’ parameter in versions up to, and including, 3.1.2 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/Pranjal6955/CVE-2016-15041-testing](https://github.com/Pranjal6955/CVE-2016-15041-testing) :  ![starts](https://img.shields.io/github/stars/Pranjal6955/CVE-2016-15041-testing.svg) ![forks](https://img.shields.io/github/forks/Pranjal6955/CVE-2016-15041-testing.svg)
- [https://github.com/flame-11/CVE-2016-15041-mainwp-dashboard](https://github.com/flame-11/CVE-2016-15041-mainwp-dashboard) :  ![starts](https://img.shields.io/github/stars/flame-11/CVE-2016-15041-mainwp-dashboard.svg) ![forks](https://img.shields.io/github/forks/flame-11/CVE-2016-15041-mainwp-dashboard.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/KlyneZyro/Metasploitable2-VAPT-Report](https://github.com/KlyneZyro/Metasploitable2-VAPT-Report) :  ![starts](https://img.shields.io/github/stars/KlyneZyro/Metasploitable2-VAPT-Report.svg) ![forks](https://img.shields.io/github/forks/KlyneZyro/Metasploitable2-VAPT-Report.svg)


## CVE-2007-2447
 The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function, when the "username map script" smb.conf option is enabled, and allows remote authenticated users to execute commands via shell metacharacters involving other MS-RPC functions in the (2) remote printer and (3) file share management.

- [https://github.com/nulltrace1336/Samba-Exploit-CVE-2007-2447](https://github.com/nulltrace1336/Samba-Exploit-CVE-2007-2447) :  ![starts](https://img.shields.io/github/stars/nulltrace1336/Samba-Exploit-CVE-2007-2447.svg) ![forks](https://img.shields.io/github/forks/nulltrace1336/Samba-Exploit-CVE-2007-2447.svg)


## CVE-2004-2687
 distcc 2.x, as used in XCode 1.5 and others, when not configured to restrict access to the server port, allows remote attackers to execute arbitrary commands via compilation jobs, which are executed by the server without authorization checks.

- [https://github.com/nulltrace1336/Metasploitable-2-Distcc-Exploit-via-Kali-Linux-CVE-2004-2687](https://github.com/nulltrace1336/Metasploitable-2-Distcc-Exploit-via-Kali-Linux-CVE-2004-2687) :  ![starts](https://img.shields.io/github/stars/nulltrace1336/Metasploitable-2-Distcc-Exploit-via-Kali-Linux-CVE-2004-2687.svg) ![forks](https://img.shields.io/github/forks/nulltrace1336/Metasploitable-2-Distcc-Exploit-via-Kali-Linux-CVE-2004-2687.svg)

