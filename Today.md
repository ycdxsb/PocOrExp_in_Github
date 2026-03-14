# Update 2026-03-14
## CVE-2026-31816
 Budibase is a low code platform for creating internal tools, workflows, and admin panels. In 3.31.4 and earlier, the Budibase server's authorized() middleware that protects every server-side API endpoint can be completely bypassed by appending a webhook path pattern to the query string of any request. The isWebhookEndpoint() function uses an unanchored regex that tests against ctx.request.url, which in Koa includes the full URL with query parameters. When the regex matches, the authorized() middleware immediately calls return next(), skipping all authentication, authorization, role checks, and CSRF protection. This means a completely unauthenticated, remote attacker can access any server-side API endpoint by simply appending ?/webhooks/trigger (or any webhook pattern variant) to the URL.

- [https://github.com/imjdl/CVE-2026-31816-rshell](https://github.com/imjdl/CVE-2026-31816-rshell) :  ![starts](https://img.shields.io/github/stars/imjdl/CVE-2026-31816-rshell.svg) ![forks](https://img.shields.io/github/forks/imjdl/CVE-2026-31816-rshell.svg)


## CVE-2026-29053
 Ghost is a Node.js content management system. From version 0.7.2 to 6.19.0, specifically crafted malicious themes can execute arbitrary code on the server running Ghost. This issue has been patched in version 6.19.1.

- [https://github.com/rootxran/CVE-2026-29053](https://github.com/rootxran/CVE-2026-29053) :  ![starts](https://img.shields.io/github/stars/rootxran/CVE-2026-29053.svg) ![forks](https://img.shields.io/github/forks/rootxran/CVE-2026-29053.svg)


## CVE-2026-27884
 NetExec is a network execution tool. Prior to version 1.5.1, the module spider_plus improperly creates the output file and folder path when saving files from SMB shares. It does not take into account that it is possible for Linux SMB shares to have path traversal characters such as `../` in them. An attacker can craft a filename in an SMB share that includes these characters, which when spider_plus crawls and downloads, can write or overwrite arbitrary files. The issue is patched in v1.5.1. As a workaround, do not run spider_plus with DOWNLOAD=true against targets.

- [https://github.com/RaynLight/CVE-2026-27884](https://github.com/RaynLight/CVE-2026-27884) :  ![starts](https://img.shields.io/github/stars/RaynLight/CVE-2026-27884.svg) ![forks](https://img.shields.io/github/forks/RaynLight/CVE-2026-27884.svg)


## CVE-2026-21509
 Reliance on untrusted inputs in a security decision in Microsoft Office allows an unauthorized attacker to bypass a security feature locally.

- [https://github.com/DameDode/CVE-2026-21509-POC](https://github.com/DameDode/CVE-2026-21509-POC) :  ![starts](https://img.shields.io/github/stars/DameDode/CVE-2026-21509-POC.svg) ![forks](https://img.shields.io/github/forks/DameDode/CVE-2026-21509-POC.svg)


## CVE-2026-20127
This vulnerability exists because the peering authentication mechanism in an affected system is not working properly. An attacker could exploit this vulnerability by sending crafted requests to an affected system. A successful exploit could allow the attacker to log in to an affected Cisco Catalyst SD-WAN Controller as an internal, high-privileged, non-root&nbsp;user account. Using this account, the attacker could access NETCONF, which would then allow the attacker to manipulate network configuration for the SD-WAN fabric.&nbsp;

- [https://github.com/randeepajayasekara/CVE-2026-20127](https://github.com/randeepajayasekara/CVE-2026-20127) :  ![starts](https://img.shields.io/github/stars/randeepajayasekara/CVE-2026-20127.svg) ![forks](https://img.shields.io/github/forks/randeepajayasekara/CVE-2026-20127.svg)


## CVE-2026-2058
 A flaw has been found in mathurvishal CloudClassroom-PHP-Project up to 5dadec098bfbbf3300d60c3494db3fb95b66e7be. This impacts an unknown function of the file /postquerypublic.php of the component Post Query Details Page. This manipulation of the argument gnamex causes sql injection. The attack is possible to be carried out remotely. The exploit has been published and may be used. This product adopts a rolling release strategy to maintain continuous delivery. Therefore, version details for affected or updated releases cannot be specified. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/carlosalbertotuma/CVE-2026-2058-PoC](https://github.com/carlosalbertotuma/CVE-2026-2058-PoC) :  ![starts](https://img.shields.io/github/stars/carlosalbertotuma/CVE-2026-2058-PoC.svg) ![forks](https://img.shields.io/github/forks/carlosalbertotuma/CVE-2026-2058-PoC.svg)


## CVE-2025-66955
 Local File Inclusion in Contact Plan, E-Mail, SMS and Fax components in Asseco SEE Live 2.0 allows remote authenticated users to access files on the host via "path" parameter in the downloadAttachment and downloadAttachmentFromPath API calls.

- [https://github.com/TheWoodenBench/CVE-2025-66955](https://github.com/TheWoodenBench/CVE-2025-66955) :  ![starts](https://img.shields.io/github/stars/TheWoodenBench/CVE-2025-66955.svg) ![forks](https://img.shields.io/github/forks/TheWoodenBench/CVE-2025-66955.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg)


## CVE-2025-38001
[5] https://lore.kernel.org/netdev/8DuRWwfqjoRDLDmBMlIfbrsZg9Gx50DHJc1ilxsEBNe2D6NMoigR_eIRIG0LOjMc3r10nUUZtArXx4oZBIdUfZQrwjcQhdinnMis_0G7VEk=@willsroot.io/T/#u

- [https://github.com/aexdyhaxor/CVE-2025-38001](https://github.com/aexdyhaxor/CVE-2025-38001) :  ![starts](https://img.shields.io/github/stars/aexdyhaxor/CVE-2025-38001.svg) ![forks](https://img.shields.io/github/forks/aexdyhaxor/CVE-2025-38001.svg)


## CVE-2025-12057
 The WavePlayer WordPress plugin before 3.8.0 does not have authorization in an AJAX action as well as does not validate the file to be copied locally, allowing unauthenticated users to upload arbitrary file on the server and lead to RCE

- [https://github.com/DeadExpl0it/CVE-2025-12057-WordPress-Exploit-PoC](https://github.com/DeadExpl0it/CVE-2025-12057-WordPress-Exploit-PoC) :  ![starts](https://img.shields.io/github/stars/DeadExpl0it/CVE-2025-12057-WordPress-Exploit-PoC.svg) ![forks](https://img.shields.io/github/forks/DeadExpl0it/CVE-2025-12057-WordPress-Exploit-PoC.svg)


## CVE-2025-11391
 The PPOM – Product Addons & Custom Fields for WooCommerce plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the image cropper functionality in all versions up to, and including, 33.0.15. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible. While the vulnerable code is in the free version, this only affected users with the paid version of the software installed and activated.

- [https://github.com/shac1x/CVE-2025-11391](https://github.com/shac1x/CVE-2025-11391) :  ![starts](https://img.shields.io/github/stars/shac1x/CVE-2025-11391.svg) ![forks](https://img.shields.io/github/forks/shac1x/CVE-2025-11391.svg)


## CVE-2025-6972
 Use After Free vulnerability exists in the CATPRODUCT file reading procedure in SOLIDWORKS eDrawings on Release SOLIDWORKS Desktop 2025. This vulnerability could allow an attacker to execute arbitrary code while opening a specially crafted CATPRODUCT file.

- [https://github.com/0xZeroSec/CVE-2025-69727](https://github.com/0xZeroSec/CVE-2025-69727) :  ![starts](https://img.shields.io/github/stars/0xZeroSec/CVE-2025-69727.svg) ![forks](https://img.shields.io/github/forks/0xZeroSec/CVE-2025-69727.svg)


## CVE-2025-6897
 A vulnerability classified as critical was found in D-Link DI-7300G+ 19.12.25A1. Affected by this vulnerability is an unknown functionality of the file httpd_debug.asp. The manipulation of the argument Time leads to os command injection. The exploit has been disclosed to the public and may be used.

- [https://github.com/ChewKeanHo/research-cve-2025-68971](https://github.com/ChewKeanHo/research-cve-2025-68971) :  ![starts](https://img.shields.io/github/stars/ChewKeanHo/research-cve-2025-68971.svg) ![forks](https://img.shields.io/github/forks/ChewKeanHo/research-cve-2025-68971.svg)


## CVE-2025-6389
 The Sneeit Framework plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 8.3 via the sneeit_articles_pagination_callback() function. This is due to the function accepting user input and then passing that through call_user_func(). This makes it possible for unauthenticated attackers to execute code on the server which can be leveraged to inject backdoors or, for example, create new administrative user accounts.

- [https://github.com/shac1x/Blackash-CVE-2025-6389](https://github.com/shac1x/Blackash-CVE-2025-6389) :  ![starts](https://img.shields.io/github/stars/shac1x/Blackash-CVE-2025-6389.svg) ![forks](https://img.shields.io/github/forks/shac1x/Blackash-CVE-2025-6389.svg)


## CVE-2025-5548
 A vulnerability, which was classified as critical, was found in FreeFloat FTP Server 1.0. Affected is an unknown function of the component NOOP Command Handler. The manipulation leads to buffer overflow. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/alanschmidt81/CVE-2025-5548](https://github.com/alanschmidt81/CVE-2025-5548) :  ![starts](https://img.shields.io/github/stars/alanschmidt81/CVE-2025-5548.svg) ![forks](https://img.shields.io/github/forks/alanschmidt81/CVE-2025-5548.svg)


## CVE-2024-32002
 Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.

- [https://github.com/ControlO8/CVE-2024-32002](https://github.com/ControlO8/CVE-2024-32002) :  ![starts](https://img.shields.io/github/stars/ControlO8/CVE-2024-32002.svg) ![forks](https://img.shields.io/github/forks/ControlO8/CVE-2024-32002.svg)
- [https://github.com/ControlO8/CVE-2024-32002-hook](https://github.com/ControlO8/CVE-2024-32002-hook) :  ![starts](https://img.shields.io/github/stars/ControlO8/CVE-2024-32002-hook.svg) ![forks](https://img.shields.io/github/forks/ControlO8/CVE-2024-32002-hook.svg)


## CVE-2024-21762
 A out-of-bounds write in Fortinet FortiOS versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.6, 7.0.0 through 7.0.13, 6.4.0 through 6.4.14, 6.2.0 through 6.2.15, 6.0.0 through 6.0.17, FortiProxy versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.8, 7.0.0 through 7.0.14, 2.0.0 through 2.0.13, 1.2.0 through 1.2.13, 1.1.0 through 1.1.6, 1.0.0 through 1.0.7 allows attacker to execute unauthorized code or commands via specifically crafted requests

- [https://github.com/0x0asif/CVE-2024-21762](https://github.com/0x0asif/CVE-2024-21762) :  ![starts](https://img.shields.io/github/stars/0x0asif/CVE-2024-21762.svg) ![forks](https://img.shields.io/github/forks/0x0asif/CVE-2024-21762.svg)


## CVE-2024-10924
 The Really Simple Security (Free, Pro, and Pro Multisite) plugins for WordPress are vulnerable to authentication bypass in versions 9.0.0 to 9.1.1.1. This is due to improper user check error handling in the two-factor REST API actions with the 'check_login_and_get_user' function. This makes it possible for unauthenticated attackers to log in as any existing user on the site, such as an administrator, when the "Two-Factor Authentication" setting is enabled (disabled by default).

- [https://github.com/Mr-Destroyer/WPGhost](https://github.com/Mr-Destroyer/WPGhost) :  ![starts](https://img.shields.io/github/stars/Mr-Destroyer/WPGhost.svg) ![forks](https://img.shields.io/github/forks/Mr-Destroyer/WPGhost.svg)


## CVE-2024-6387
 A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be able to trigger it by failing to authenticate within a set time period.

- [https://github.com/OHHDamnBRO/Noregressh](https://github.com/OHHDamnBRO/Noregressh) :  ![starts](https://img.shields.io/github/stars/OHHDamnBRO/Noregressh.svg) ![forks](https://img.shields.io/github/forks/OHHDamnBRO/Noregressh.svg)


## CVE-2023-43208
 NextGen Healthcare Mirth Connect before version 4.4.1 is vulnerable to unauthenticated remote code execution. Note that this vulnerability is caused by the incomplete patch of CVE-2023-37679.

- [https://github.com/4nuxd/CVE-2023-43208](https://github.com/4nuxd/CVE-2023-43208) :  ![starts](https://img.shields.io/github/stars/4nuxd/CVE-2023-43208.svg) ![forks](https://img.shields.io/github/forks/4nuxd/CVE-2023-43208.svg)
- [https://github.com/LunaLynx12/cve-2023-43208-poc](https://github.com/LunaLynx12/cve-2023-43208-poc) :  ![starts](https://img.shields.io/github/stars/LunaLynx12/cve-2023-43208-poc.svg) ![forks](https://img.shields.io/github/forks/LunaLynx12/cve-2023-43208-poc.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/zeynepglygt/apache-cve-2021-42013-rce](https://github.com/zeynepglygt/apache-cve-2021-42013-rce) :  ![starts](https://img.shields.io/github/stars/zeynepglygt/apache-cve-2021-42013-rce.svg) ![forks](https://img.shields.io/github/forks/zeynepglygt/apache-cve-2021-42013-rce.svg)


## CVE-2020-2501
 A stack-based buffer overflow vulnerability has been reported to affect QNAP NAS devices running Surveillance Station. If exploited, this vulnerability allows attackers to execute arbitrary code. QNAP have already fixed this vulnerability in the following versions: Surveillance Station 5.1.5.4.3 (and later) for ARM CPU NAS (64bit OS) and x86 CPU NAS (64bit OS) Surveillance Station 5.1.5.3.3 (and later) for ARM CPU NAS (32bit OS) and x86 CPU NAS (32bit OS)

- [https://github.com/Alonzozzz/alonzzzo](https://github.com/Alonzozzz/alonzzzo) :  ![starts](https://img.shields.io/github/stars/Alonzozzz/alonzzzo.svg) ![forks](https://img.shields.io/github/forks/Alonzozzz/alonzzzo.svg)


## CVE-2017-0199
 Microsoft Office 2007 SP3, Microsoft Office 2010 SP2, Microsoft Office 2013 SP1, Microsoft Office 2016, Microsoft Windows Vista SP2, Windows Server 2008 SP2, Windows 7 SP1, Windows 8.1 allow remote attackers to execute arbitrary code via a crafted document, aka "Microsoft Office/WordPad Remote Code Execution Vulnerability w/Windows API."

- [https://github.com/BlackOclock/XLS-to-DBatLoader-or-GuLoader-for-AgentTesla-variant](https://github.com/BlackOclock/XLS-to-DBatLoader-or-GuLoader-for-AgentTesla-variant) :  ![starts](https://img.shields.io/github/stars/BlackOclock/XLS-to-DBatLoader-or-GuLoader-for-AgentTesla-variant.svg) ![forks](https://img.shields.io/github/forks/BlackOclock/XLS-to-DBatLoader-or-GuLoader-for-AgentTesla-variant.svg)

