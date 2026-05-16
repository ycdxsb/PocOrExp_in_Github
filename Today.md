# Update 2026-05-16
## CVE-2026-45185
 Exim before 4.99.3, in certain GnuTLS configurations, has a remotely reachable use-after-free in the BDAT body parsing path. It is triggered when a client sends a TLS close_notify mid-body during a CHUNKING transfer, followed by a final cleartext byte on the same TCP connection. This can lead to heap corruption. An unauthenticated network attacker exploiting this vulnerability could execute arbitrary code.

- [https://github.com/materaj2/cve-2026-45185-detection-script](https://github.com/materaj2/cve-2026-45185-detection-script) :  ![starts](https://img.shields.io/github/stars/materaj2/cve-2026-45185-detection-script.svg) ![forks](https://img.shields.io/github/forks/materaj2/cve-2026-45185-detection-script.svg)


## CVE-2026-44403
 Wing FTP Server before 8.1.3 contains an authenticated remote code execution vulnerability in the session serialization mechanism that allows authenticated administrators to inject arbitrary Lua code through the domain admin mydirectory field. Attackers can exploit unsafe serialization of session values into Lua source code without proper escaping of closing delimiters, causing the injected code to be executed when the poisoned session is loaded via loadfile().

- [https://github.com/ZemarKhos/CVE-2026-44403-WingFTP-v8.1.2-POC-Exploit](https://github.com/ZemarKhos/CVE-2026-44403-WingFTP-v8.1.2-POC-Exploit) :  ![starts](https://img.shields.io/github/stars/ZemarKhos/CVE-2026-44403-WingFTP-v8.1.2-POC-Exploit.svg) ![forks](https://img.shields.io/github/forks/ZemarKhos/CVE-2026-44403-WingFTP-v8.1.2-POC-Exploit.svg)


## CVE-2026-42945
 NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module. This vulnerability exists when the rewrite directive is followed by a rewrite, if, or set directive and an unnamed Perl-Compatible Regular Expression (PCRE) capture (for example, $1, $2) with a replacement string that includes a question mark (?). An unauthenticated attacker along with conditions beyond its control can exploit this vulnerability by sending crafted HTTP requests. This may cause a heap buffer overflow in the NGINX worker process leading to a restart. Additionally, for systems with Address Space Layout Randomization (ASLR ) disabled, code execution is possible.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/p3Nt3st3r-sTAr/CVE-2026-42945-POC](https://github.com/p3Nt3st3r-sTAr/CVE-2026-42945-POC) :  ![starts](https://img.shields.io/github/stars/p3Nt3st3r-sTAr/CVE-2026-42945-POC.svg) ![forks](https://img.shields.io/github/forks/p3Nt3st3r-sTAr/CVE-2026-42945-POC.svg)
- [https://github.com/friparia/NGINX_RIFT_SCAN_CVE_2026_42945](https://github.com/friparia/NGINX_RIFT_SCAN_CVE_2026_42945) :  ![starts](https://img.shields.io/github/stars/friparia/NGINX_RIFT_SCAN_CVE_2026_42945.svg) ![forks](https://img.shields.io/github/forks/friparia/NGINX_RIFT_SCAN_CVE_2026_42945.svg)
- [https://github.com/cipherspy/CVE-2026-42945-POC](https://github.com/cipherspy/CVE-2026-42945-POC) :  ![starts](https://img.shields.io/github/stars/cipherspy/CVE-2026-42945-POC.svg) ![forks](https://img.shields.io/github/forks/cipherspy/CVE-2026-42945-POC.svg)
- [https://github.com/rheodev/CVE-2026-42945](https://github.com/rheodev/CVE-2026-42945) :  ![starts](https://img.shields.io/github/stars/rheodev/CVE-2026-42945.svg) ![forks](https://img.shields.io/github/forks/rheodev/CVE-2026-42945.svg)
- [https://github.com/realityone/cve-2026-42945-scan](https://github.com/realityone/cve-2026-42945-scan) :  ![starts](https://img.shields.io/github/stars/realityone/cve-2026-42945-scan.svg) ![forks](https://img.shields.io/github/forks/realityone/cve-2026-42945-scan.svg)
- [https://github.com/0xBlackash/CVE-2026-42945](https://github.com/0xBlackash/CVE-2026-42945) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-42945.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-42945.svg)
- [https://github.com/RyosukeDTomita/CVE-2026-42945](https://github.com/RyosukeDTomita/CVE-2026-42945) :  ![starts](https://img.shields.io/github/stars/RyosukeDTomita/CVE-2026-42945.svg) ![forks](https://img.shields.io/github/forks/RyosukeDTomita/CVE-2026-42945.svg)
- [https://github.com/oseasfr/CVE_2026-42945](https://github.com/oseasfr/CVE_2026-42945) :  ![starts](https://img.shields.io/github/stars/oseasfr/CVE_2026-42945.svg) ![forks](https://img.shields.io/github/forks/oseasfr/CVE_2026-42945.svg)
- [https://github.com/nanwinata/nginxrift-CVE-2026-42945](https://github.com/nanwinata/nginxrift-CVE-2026-42945) :  ![starts](https://img.shields.io/github/stars/nanwinata/nginxrift-CVE-2026-42945.svg) ![forks](https://img.shields.io/github/forks/nanwinata/nginxrift-CVE-2026-42945.svg)
- [https://github.com/ChamsBouzaiene/ai-vuln-rediscovery-nginx-cve-2026-42945](https://github.com/ChamsBouzaiene/ai-vuln-rediscovery-nginx-cve-2026-42945) :  ![starts](https://img.shields.io/github/stars/ChamsBouzaiene/ai-vuln-rediscovery-nginx-cve-2026-42945.svg) ![forks](https://img.shields.io/github/forks/ChamsBouzaiene/ai-vuln-rediscovery-nginx-cve-2026-42945.svg)


## CVE-2026-42281
 MagicMirror² is an open source modular smart mirror platform. Prior to 2.36.0, an unauthenticated Server-Side Request Forgery (SSRF) vulnerability in the /cors endpoint allows any remote attacker to force the MagicMirror² server to perform arbitrary HTTP requests to internal networks, cloud metadata services, and localhost services. The endpoint also expands environment variable placeholders (**VAR_NAME**), enabling exfiltration of server-side secrets. This vulnerability is fixed in 2.36.0.

- [https://github.com/Astaruf/CVE-2026-42281](https://github.com/Astaruf/CVE-2026-42281) :  ![starts](https://img.shields.io/github/stars/Astaruf/CVE-2026-42281.svg) ![forks](https://img.shields.io/github/forks/Astaruf/CVE-2026-42281.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/rippsec/CVE-2026-31431-Copy-Fail](https://github.com/rippsec/CVE-2026-31431-Copy-Fail) :  ![starts](https://img.shields.io/github/stars/rippsec/CVE-2026-31431-Copy-Fail.svg) ![forks](https://img.shields.io/github/forks/rippsec/CVE-2026-31431-Copy-Fail.svg)
- [https://github.com/Sebastian294/cve-2026-31431](https://github.com/Sebastian294/cve-2026-31431) :  ![starts](https://img.shields.io/github/stars/Sebastian294/cve-2026-31431.svg) ![forks](https://img.shields.io/github/forks/Sebastian294/cve-2026-31431.svg)


## CVE-2026-24055
 Langfuse is an open source large language model engineering platform. In versions 3.146.0 and below, the /api/public/slack/install endpoint initiates Slack OAuth using a projectId provided by the client without authentication or authorization. The projectId is preserved throughout the OAuth flow, and the callback stores installations based on this untrusted metadata. This allows an attacker to bind their Slack workspace to any project and potentially receive changes to prompts stored in Langfuse Prompt Management. An attacker can replace existing Prompt Slack Automation integrations or pre-register a malicious one, though the latter requires an authenticated user to unknowingly configure it despite visible workspace and channel indicators in the UI. This issue has been fixed in version 3.147.0.

- [https://github.com/imzanggg/CVE-2026-24055-OAuth-Langfuse](https://github.com/imzanggg/CVE-2026-24055-OAuth-Langfuse) :  ![starts](https://img.shields.io/github/stars/imzanggg/CVE-2026-24055-OAuth-Langfuse.svg) ![forks](https://img.shields.io/github/forks/imzanggg/CVE-2026-24055-OAuth-Langfuse.svg)


## CVE-2026-22553
 All versions of InSAT MasterSCADA BUK-TS are susceptible to OS command injection through a field in its MMadmServ web interface. Malicious users that use the vulnerable endpoint are potentially able to cause remote code execution.

- [https://github.com/mbanyamer/CVE-2026-22553-InSAT-MasterSCADA-BUK-TS-MMadmServ](https://github.com/mbanyamer/CVE-2026-22553-InSAT-MasterSCADA-BUK-TS-MMadmServ) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-22553-InSAT-MasterSCADA-BUK-TS-MMadmServ.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-22553-InSAT-MasterSCADA-BUK-TS-MMadmServ.svg)


## CVE-2026-8181
 The Burst Statistics – Privacy-Friendly WordPress Analytics (Google Analytics Alternative) plugin for WordPress is vulnerable to Authentication Bypass in versions 3.4.0 to 3.4.1.1. This is due to incorrect return-value handling in the `is_mainwp_authenticated()` function when validating application passwords from the Authorization header. This makes it possible for unauthenticated attackers, with knowledge of an administrator username, to impersonate that administrator for the duration of the request by supplying any random Basic Authentication password achieving privilege escalation.

- [https://github.com/zycoder0day/CVE-2026-8181](https://github.com/zycoder0day/CVE-2026-8181) :  ![starts](https://img.shields.io/github/stars/zycoder0day/CVE-2026-8181.svg) ![forks](https://img.shields.io/github/forks/zycoder0day/CVE-2026-8181.svg)


## CVE-2026-6145
 The User Registration & Membership plugin for WordPress is vulnerable to Missing Authorization in all versions up to, and including, 5.1.5. This is due to the is_admin_creation_process() method relying solely on the presence of action=createuser in the $_REQUEST superglobal without performing any authentication or capability check. This makes it possible for unauthenticated attackers to bypass the admin approval requirement when registering new accounts via the fallback submission path.

- [https://github.com/Hann1bl3L3ct3r/CVE-2026-6145](https://github.com/Hann1bl3L3ct3r/CVE-2026-6145) :  ![starts](https://img.shields.io/github/stars/Hann1bl3L3ct3r/CVE-2026-6145.svg) ![forks](https://img.shields.io/github/forks/Hann1bl3L3ct3r/CVE-2026-6145.svg)


## CVE-2026-4639
 Vitals ESP developed by Galaxy Software Services has a Incorrect Authorization vulnerability, allowing authenticated remote attackers to perform certain administrative functions, thereby escalating privileges.

- [https://github.com/bradyjmcl/cve-2026-46391](https://github.com/bradyjmcl/cve-2026-46391) :  ![starts](https://img.shields.io/github/stars/bradyjmcl/cve-2026-46391.svg) ![forks](https://img.shields.io/github/forks/bradyjmcl/cve-2026-46391.svg)


## CVE-2026-3533
 The Jupiter X Core plugin for WordPress is vulnerable to limited file uploads due to missing authorization on import_popup_templates() function as well as insufficient file type validation in the upload_files() function in all versions up to, and including, 4.14.1. This makes it possible for Authenticated attackers with Subscriber-level access and above, to upload files with dangerous types that can lead to Remote Code Execution on servers configured to handle .phar files as executable PHP (e.g., Apache+mod_php), or Stored Cross-Site Scripting via .svg, .dfxp, or .xhtml files upload on any server configuration

- [https://github.com/JohannesLks/CVE-2026-35330](https://github.com/JohannesLks/CVE-2026-35330) :  ![starts](https://img.shields.io/github/stars/JohannesLks/CVE-2026-35330.svg) ![forks](https://img.shields.io/github/forks/JohannesLks/CVE-2026-35330.svg)
- [https://github.com/JohannesLks/CVE-2026-35333](https://github.com/JohannesLks/CVE-2026-35333) :  ![starts](https://img.shields.io/github/stars/JohannesLks/CVE-2026-35333.svg) ![forks](https://img.shields.io/github/forks/JohannesLks/CVE-2026-35333.svg)


## CVE-2026-1814
 Rapid7 Nexpose versions 6.4.50 and later are vulnerable to an insufficient entropy issue in the CredentialsKeyStorePassword.generateRandomPassword() method. When updating legacy keystore passwords, the application generates a new password with insufficient length (7-12 characters) and a static prefix 'p', resulting in a weak keyspace. An attacker with access to the nsc.ks file can brute-force this password using consumer-grade hardware to decrypt stored credentials.

- [https://github.com/pbrass/CVE-2026-1814](https://github.com/pbrass/CVE-2026-1814) :  ![starts](https://img.shields.io/github/stars/pbrass/CVE-2026-1814.svg) ![forks](https://img.shields.io/github/forks/pbrass/CVE-2026-1814.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)


## CVE-2025-59287
 Deserialization of untrusted data in Windows Server Update Service allows an unauthorized attacker to execute code over a network.

- [https://github.com/DaddyBigFish/CVE-2025-59287-hawktrace](https://github.com/DaddyBigFish/CVE-2025-59287-hawktrace) :  ![starts](https://img.shields.io/github/stars/DaddyBigFish/CVE-2025-59287-hawktrace.svg) ![forks](https://img.shields.io/github/forks/DaddyBigFish/CVE-2025-59287-hawktrace.svg)


## CVE-2025-30066
 tj-actions changed-files before 46 allows remote attackers to discover secrets by reading actions logs. (The tags v1 through v45.0.7 were affected on 2025-03-14 and 2025-03-15 because they were modified by a threat actor to point at commit 0e58ed8, which contained malicious updateFeatures code.)

- [https://github.com/Super-Vulnerable-Org/compromised-action](https://github.com/Super-Vulnerable-Org/compromised-action) :  ![starts](https://img.shields.io/github/stars/Super-Vulnerable-Org/compromised-action.svg) ![forks](https://img.shields.io/github/forks/Super-Vulnerable-Org/compromised-action.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/s11s11/CVE-2025-29927](https://github.com/s11s11/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/s11s11/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/s11s11/CVE-2025-29927.svg)


## CVE-2024-2997
 A vulnerability was found in Bdtask Multi-Store Inventory Management System up to 20240320. It has been declared as problematic. Affected by this vulnerability is an unknown functionality. The manipulation of the argument Category Name/Model Name/Brand Name/Unit Name leads to cross site scripting. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-258199. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/o9-9/CVE-2024-2997](https://github.com/o9-9/CVE-2024-2997) :  ![starts](https://img.shields.io/github/stars/o9-9/CVE-2024-2997.svg) ![forks](https://img.shields.io/github/forks/o9-9/CVE-2024-2997.svg)


## CVE-2023-23752
 An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

- [https://github.com/Marwan651/Joomla-CMS-Full-Lifecycle-Pentest](https://github.com/Marwan651/Joomla-CMS-Full-Lifecycle-Pentest) :  ![starts](https://img.shields.io/github/stars/Marwan651/Joomla-CMS-Full-Lifecycle-Pentest.svg) ![forks](https://img.shields.io/github/forks/Marwan651/Joomla-CMS-Full-Lifecycle-Pentest.svg)


## CVE-2022-38694
 In BootRom, there is a possible unchecked write address. This could lead to local escalation of privilege with no additional execution privileges needed.

- [https://github.com/Phlegmelm/CRACK12](https://github.com/Phlegmelm/CRACK12) :  ![starts](https://img.shields.io/github/stars/Phlegmelm/CRACK12.svg) ![forks](https://img.shields.io/github/forks/Phlegmelm/CRACK12.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/JIYUN02/cve-2021-41773](https://github.com/JIYUN02/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/JIYUN02/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/JIYUN02/cve-2021-41773.svg)
- [https://github.com/puckiestyle/CVE-2021-41773](https://github.com/puckiestyle/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-41773.svg)
- [https://github.com/AzkOsDev/CVE-2021-41773](https://github.com/AzkOsDev/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/AzkOsDev/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/AzkOsDev/CVE-2021-41773.svg)


## CVE-2020-17103
 Windows Cloud Files Mini Filter Driver Elevation of Privilege Vulnerability

- [https://github.com/Nightmare-Eclipse/MiniPlasma](https://github.com/Nightmare-Eclipse/MiniPlasma) :  ![starts](https://img.shields.io/github/stars/Nightmare-Eclipse/MiniPlasma.svg) ![forks](https://img.shields.io/github/forks/Nightmare-Eclipse/MiniPlasma.svg)
- [https://github.com/0xDimas/MiniPlasma](https://github.com/0xDimas/MiniPlasma) :  ![starts](https://img.shields.io/github/stars/0xDimas/MiniPlasma.svg) ![forks](https://img.shields.io/github/forks/0xDimas/MiniPlasma.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/paulameg/SimpleCTF-THM-Walkthrough](https://github.com/paulameg/SimpleCTF-THM-Walkthrough) :  ![starts](https://img.shields.io/github/stars/paulameg/SimpleCTF-THM-Walkthrough.svg) ![forks](https://img.shields.io/github/forks/paulameg/SimpleCTF-THM-Walkthrough.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka "Dirty COW."

- [https://github.com/maur0amaya/Escalamiento-de-Privilegios-usando-el-Kernel-Exploit-Dirty-Cow](https://github.com/maur0amaya/Escalamiento-de-Privilegios-usando-el-Kernel-Exploit-Dirty-Cow) :  ![starts](https://img.shields.io/github/stars/maur0amaya/Escalamiento-de-Privilegios-usando-el-Kernel-Exploit-Dirty-Cow.svg) ![forks](https://img.shields.io/github/forks/maur0amaya/Escalamiento-de-Privilegios-usando-el-Kernel-Exploit-Dirty-Cow.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/ByteForgeFr/CVE-2011-2523](https://github.com/ByteForgeFr/CVE-2011-2523) :  ![starts](https://img.shields.io/github/stars/ByteForgeFr/CVE-2011-2523.svg) ![forks](https://img.shields.io/github/forks/ByteForgeFr/CVE-2011-2523.svg)

