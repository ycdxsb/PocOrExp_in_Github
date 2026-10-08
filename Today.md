# Update 2026-10-08
## CVE-2026-105221
 The gist RubyGem before 6.1.0 contains an improper certificate validation vulnerability that allows on-path attackers to intercept HTTPS traffic because http_connection in lib/gist.rb sets VERIFY_NONE. Attackers can present any certificate to read or modify GitHub API traffic, stealing OAuth tokens and login credentials to read and modify the victim's gists.

- [https://github.com/abraxas/cve-2026-105221-gist-tls](https://github.com/abraxas/cve-2026-105221-gist-tls) :  ![starts](https://img.shields.io/github/stars/abraxas/cve-2026-105221-gist-tls.svg) ![forks](https://img.shields.io/github/forks/abraxas/cve-2026-105221-gist-tls.svg)


## CVE-2026-105080
 In ConvertX before 0.19.0, converters/calibre.ts does not block recipe files, and instead passes them to the ebook-convert program from Calibre. This affects executable code in a .recipe or .downloaded_recipe file.

- [https://github.com/beyavuz/cve-2026-105080-poc](https://github.com/beyavuz/cve-2026-105080-poc) :  ![starts](https://img.shields.io/github/stars/beyavuz/cve-2026-105080-poc.svg) ![forks](https://img.shields.io/github/forks/beyavuz/cve-2026-105080-poc.svg)


## CVE-2026-104905
 FacturaScripts before version 2026.7 contains a PHP object injection vulnerability in WidgetSelect::processFormData() that allows authenticated attackers to trigger unserialize() on raw POST data without an allowed_classes filter for multiple-select fields. Attackers can submit a serialized XLSXWriter object as the field value to invoke its __destruct() method, deleting arbitrary attacker-specified files such as config.php or backup data, resulting in denial of service and potential application reinstall hijack.

- [https://github.com/wvllxe/CVE-2026-104905-facturascripts-object-injection](https://github.com/wvllxe/CVE-2026-104905-facturascripts-object-injection) :  ![starts](https://img.shields.io/github/stars/wvllxe/CVE-2026-104905-facturascripts-object-injection.svg) ![forks](https://img.shields.io/github/forks/wvllxe/CVE-2026-104905-facturascripts-object-injection.svg)


## CVE-2026-97286
 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in WP Chill Strong Testimonials strong-testimonials allows Stored XSS.This issue affects Strong Testimonials: from n/a through 3.3.11.

- [https://github.com/Rully2212/CVE-2026-97286](https://github.com/Rully2212/CVE-2026-97286) :  ![starts](https://img.shields.io/github/stars/Rully2212/CVE-2026-97286.svg) ![forks](https://img.shields.io/github/forks/Rully2212/CVE-2026-97286.svg)


## CVE-2026-96940
 Weak authorization in Microsoft Exchange Server allows an authenticated attacker to elevate privileges over a network.

- [https://github.com/HORKimhab/CVE-2026-96940](https://github.com/HORKimhab/CVE-2026-96940) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-96940.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-96940.svg)


## CVE-2026-86950
 An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in iOS 26.7.1 and iPadOS 26.7.1, macOS Sequoia 15.8.1, macOS Tahoe 26.7.1. Processing a maliciously crafted file may lead to arbitrary code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 27.

- [https://github.com/34zY/CVE-2026-86950](https://github.com/34zY/CVE-2026-86950) :  ![starts](https://img.shields.io/github/stars/34zY/CVE-2026-86950.svg) ![forks](https://img.shields.io/github/forks/34zY/CVE-2026-86950.svg)


## CVE-2026-74727
calling ovpn_peer_hash_vpn_ip().

- [https://github.com/Kosifuchs/ovpn-kernel-backport](https://github.com/Kosifuchs/ovpn-kernel-backport) :  ![starts](https://img.shields.io/github/stars/Kosifuchs/ovpn-kernel-backport.svg) ![forks](https://img.shields.io/github/forks/Kosifuchs/ovpn-kernel-backport.svg)


## CVE-2026-67401
 A vulnerability in cPanel allows a mail-enabled account to achieve remote code execution as root through SQLi in EmailTrack component

- [https://github.com/hitechcloud-vietnam/CVE-2026-67401](https://github.com/hitechcloud-vietnam/CVE-2026-67401) :  ![starts](https://img.shields.io/github/stars/hitechcloud-vietnam/CVE-2026-67401.svg) ![forks](https://img.shields.io/github/forks/hitechcloud-vietnam/CVE-2026-67401.svg)


## CVE-2026-63277
 LibreOffice Calc can link a cell range to an external data source, and the link is saved in the document. A document could name a Java database driver for such a link to be loaded from a remote location, so opening the document could run Java code from that location. In fixed versions an entry in a Java class path has to be a file URL.

- [https://github.com/HORKimhab/CVE-2026-63277](https://github.com/HORKimhab/CVE-2026-63277) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-63277.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-63277.svg)


## CVE-2026-59265
Until then, users can mitigate this issue by disabling Java runtime integration in the Preferences dialog. This prevents the attack. If this is not possible, or as an extra precaution, you can avoid opening open untrusted files entirely. Once 4.1.17 is released, upgrade to that version to fix the issue.

- [https://github.com/HORKimhab/CVE-2026-59265](https://github.com/HORKimhab/CVE-2026-59265) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-59265.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-59265.svg)


## CVE-2026-57967
Users are recommended to upgrade to version 2.57.0, which fixes the issue.

- [https://github.com/c0dem4sters/CVE-2026-57967](https://github.com/c0dem4sters/CVE-2026-57967) :  ![starts](https://img.shields.io/github/stars/c0dem4sters/CVE-2026-57967.svg) ![forks](https://img.shields.io/github/forks/c0dem4sters/CVE-2026-57967.svg)


## CVE-2026-43805
 A race condition was addressed with improved state handling. This issue is fixed in iOS 26.6 and iPadOS 26.6, macOS Sequoia 15.7.8, macOS Sonoma 14.8.8, macOS Tahoe 26.6, watchOS 26.6. An app may be able to cause unexpected system termination or write kernel memory.

- [https://github.com/WTCYJ/CVE-2026-43805-analysis](https://github.com/WTCYJ/CVE-2026-43805-analysis) :  ![starts](https://img.shields.io/github/stars/WTCYJ/CVE-2026-43805-analysis.svg) ![forks](https://img.shields.io/github/forks/WTCYJ/CVE-2026-43805-analysis.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/linux-tools/VIVO-IQOO-Neo9-Root-Tools](https://github.com/linux-tools/VIVO-IQOO-Neo9-Root-Tools) :  ![starts](https://img.shields.io/github/stars/linux-tools/VIVO-IQOO-Neo9-Root-Tools.svg) ![forks](https://img.shields.io/github/forks/linux-tools/VIVO-IQOO-Neo9-Root-Tools.svg)


## CVE-2026-21589
 This is a vulnerability in Bitbucket Data Center, Confluence Data Center, Jira Service Management Data Center, Jira Software Data Center, Bamboo Data Center. Crowd Data Center, Crucible and Fisheye. This Arbitrary File Access vulnerability allows an unauthenticated attacker to access specific files within the web application root directory in affected versions. Exploitation requires prior knowledge of the target file's exact name and path; this vulnerability does not allow attackers to enumerate or list directory contents. In some configurations, there may be some sensitive files that make this highly severe. This vulnerability allows an unauthenticated remote attacker to access specific files within the web application root directory in affected versions. The vulnerability must be addressed for affected versions of: -- Bitbucket Data Center, introduced in version = 4.6.0, fix versions: 9.4.26, 10.2.8, 10.5.1 -- Confluence Data Center, introduced in version = 5.10.0, fix versions 9.2.26, 10.2.19 -- Crowd Data Center, introduced in version = 2.11.0, fix versions 6.3.7, 7.0.3, 7.1.7, 7.2.4 -- Jira Software Data Center, introduced in version = 7.1.0, fix versions 9.12.40, 10.3.26, 11.3.12 -- Jira Service Management Data Center, introduced in version = 3.1.0, fix versions 5.12.40, 10.3.26, 11.3.12 -- Bamboo Data Center = 7.0.1, fix versions 10.2.24, 12.1.12 -- Crucible, fix versions 4.9.15 -- Fisheye, fix version 4.9.15 -- Exploitation requires prior knowledge of the target file's exact name and path. The vulnerability does not include the capability to enumerate or list directory contents.

- [https://github.com/MarcusProgram/CVE-2026-21589](https://github.com/MarcusProgram/CVE-2026-21589) :  ![starts](https://img.shields.io/github/stars/MarcusProgram/CVE-2026-21589.svg) ![forks](https://img.shields.io/github/forks/MarcusProgram/CVE-2026-21589.svg)
- [https://github.com/watchtowrlabs/watchTowr-vs-Atlassian-CVE-2026-21589](https://github.com/watchtowrlabs/watchTowr-vs-Atlassian-CVE-2026-21589) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/watchTowr-vs-Atlassian-CVE-2026-21589.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/watchTowr-vs-Atlassian-CVE-2026-21589.svg)
- [https://github.com/tc4dy/CVE-2026-21589-PoC-Exploit](https://github.com/tc4dy/CVE-2026-21589-PoC-Exploit) :  ![starts](https://img.shields.io/github/stars/tc4dy/CVE-2026-21589-PoC-Exploit.svg) ![forks](https://img.shields.io/github/forks/tc4dy/CVE-2026-21589-PoC-Exploit.svg)


## CVE-2026-10531
 The AI Share & Summarize WordPress plugin before 2.0.4 does not sanitise and escape some of its shortcode attributes before outputting them in a page, allowing users with the Contributor role and above to perform Stored Cross-Site Scripting attacks.

- [https://github.com/kashishtopi/CVE-2026-105319](https://github.com/kashishtopi/CVE-2026-105319) :  ![starts](https://img.shields.io/github/stars/kashishtopi/CVE-2026-105319.svg) ![forks](https://img.shields.io/github/forks/kashishtopi/CVE-2026-105319.svg)


## CVE-2026-10196
 The Mail Mint – Email Marketing, Newsletter, Email Automation & WooCommerce Emails plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 1.31.0 via deserialization of untrusted input in the 'handle_form_submission' function. This makes it possible for unauthenticated attackers to inject a PHP Object. The additional presence of a POP chain allows attackers to execute code on the server. The vulnerability was partially patched in version 1.23.1.

- [https://github.com/0xCyp1337/CVE-2026-10196](https://github.com/0xCyp1337/CVE-2026-10196) :  ![starts](https://img.shields.io/github/stars/0xCyp1337/CVE-2026-10196.svg) ![forks](https://img.shields.io/github/forks/0xCyp1337/CVE-2026-10196.svg)


## CVE-2026-8206
 The Kirki – Freeform Page Builder, Website Builder & Customizer plugin for WordPress is vulnerable to privilege escalation via account takeover in all versions 6.0.0 to 6.0.6. This is due to the plugin accepting an arbitrary email address when a username is used in the password reset request. This makes it possible for unauthenticated attackers to send a password reset link for any user registered on the site to their own email address.

- [https://github.com/Sanjith1236/CVE-2026-8206-Kirki-Exploit-Analysis](https://github.com/Sanjith1236/CVE-2026-8206-Kirki-Exploit-Analysis) :  ![starts](https://img.shields.io/github/stars/Sanjith1236/CVE-2026-8206-Kirki-Exploit-Analysis.svg) ![forks](https://img.shields.io/github/forks/Sanjith1236/CVE-2026-8206-Kirki-Exploit-Analysis.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/mumaosong/cve-2026-43499-CyberMeowfia](https://github.com/mumaosong/cve-2026-43499-CyberMeowfia) :  ![starts](https://img.shields.io/github/stars/mumaosong/cve-2026-43499-CyberMeowfia.svg) ![forks](https://img.shields.io/github/forks/mumaosong/cve-2026-43499-CyberMeowfia.svg)


## CVE-2026-3888
 Local privilege escalation in snapd on Linux allows local attackers to get root privilege by re-creating snap's private /tmp directory when systemd-tmpfiles is configured to automatically clean up this directory. This issue affects Ubuntu 16.04 LTS, 18.04 LTS, 20.04 LTS, 22.04 LTS, and 24.04 LTS.

- [https://github.com/AlanNewberry/CVE-2026-3888-snap-confine-privilege-escalation](https://github.com/AlanNewberry/CVE-2026-3888-snap-confine-privilege-escalation) :  ![starts](https://img.shields.io/github/stars/AlanNewberry/CVE-2026-3888-snap-confine-privilege-escalation.svg) ![forks](https://img.shields.io/github/forks/AlanNewberry/CVE-2026-3888-snap-confine-privilege-escalation.svg)


## CVE-2025-71384
 Dbit WIFI4 N300 1.0.0 devices allows administrators (from the local Wi-Fi network) to execute OS commands by leveraging a stack-based buffer overflow via the /api/addStaticDHCP comment field,

- [https://github.com/Scorpion-Security-Labs/CVE-2025-71384](https://github.com/Scorpion-Security-Labs/CVE-2025-71384) :  ![starts](https://img.shields.io/github/stars/Scorpion-Security-Labs/CVE-2025-71384.svg) ![forks](https://img.shields.io/github/forks/Scorpion-Security-Labs/CVE-2025-71384.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg)


## CVE-2025-34069
 An authentication bypass vulnerability exists in GFI Kerio Control 9.4.5 due to insecure default proxy configuration and weak access control in the GFIAgent service. The non-transparent proxy on TCP port 3128 can be used to forward unauthenticated requests to internal services such as GFIAgent, bypassing firewall restrictions and exposing internal management endpoints. This enables unauthenticated attackers to access the GFIAgent service on ports 7995 and 7996, retrieve the appliance UUID, and issue administrative requests via the proxy. Exploitation results in full administrative access to the Kerio Control appliance.

- [https://github.com/cppghoul/CVE-2025-34069](https://github.com/cppghoul/CVE-2025-34069) :  ![starts](https://img.shields.io/github/stars/cppghoul/CVE-2025-34069.svg) ![forks](https://img.shields.io/github/forks/cppghoul/CVE-2025-34069.svg)


## CVE-2025-21479
 Memory corruption due to unauthorized command execution in GPU micronode while executing specific sequence of commands.

- [https://github.com/linux-tools/VIVO-IQOO-Neo9-Root-Tools](https://github.com/linux-tools/VIVO-IQOO-Neo9-Root-Tools) :  ![starts](https://img.shields.io/github/stars/linux-tools/VIVO-IQOO-Neo9-Root-Tools.svg) ![forks](https://img.shields.io/github/forks/linux-tools/VIVO-IQOO-Neo9-Root-Tools.svg)
- [https://github.com/Shiho-Patch/linux-tools-vivo_iqoo_neo_9_root_research_on_CVE-2025-21479](https://github.com/Shiho-Patch/linux-tools-vivo_iqoo_neo_9_root_research_on_CVE-2025-21479) :  ![starts](https://img.shields.io/github/stars/Shiho-Patch/linux-tools-vivo_iqoo_neo_9_root_research_on_CVE-2025-21479.svg) ![forks](https://img.shields.io/github/forks/Shiho-Patch/linux-tools-vivo_iqoo_neo_9_root_research_on_CVE-2025-21479.svg)


## CVE-2025-6867
 A vulnerability was found in SourceCodester Simple Company Website 1.0 and classified as critical. This issue affects some unknown processing of the file /admin/services/manage.php. The manipulation of the argument ID leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/richard1026/CVE-2025-6867-reproduction](https://github.com/richard1026/CVE-2025-6867-reproduction) :  ![starts](https://img.shields.io/github/stars/richard1026/CVE-2025-6867-reproduction.svg) ![forks](https://img.shields.io/github/forks/richard1026/CVE-2025-6867-reproduction.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field.svg)


## CVE-2024-21338
 Windows Kernel Elevation of Privilege Vulnerability

- [https://github.com/kikozz/CVE-2024-21338](https://github.com/kikozz/CVE-2024-21338) :  ![starts](https://img.shields.io/github/stars/kikozz/CVE-2024-21338.svg) ![forks](https://img.shields.io/github/forks/kikozz/CVE-2024-21338.svg)


## CVE-2023-5612
 An issue has been discovered in GitLab affecting all versions before 16.6.6, 16.7 prior to 16.7.4, and 16.8 prior to 16.8.1. It was possible to read the user email address via tags feed although the visibility in the user profile has been disabled.

- [https://github.com/ConstantineFedorov/Review.CVE-2023-5612](https://github.com/ConstantineFedorov/Review.CVE-2023-5612) :  ![starts](https://img.shields.io/github/stars/ConstantineFedorov/Review.CVE-2023-5612.svg) ![forks](https://img.shields.io/github/forks/ConstantineFedorov/Review.CVE-2023-5612.svg)


## CVE-2022-0185
 A heap-based buffer overflow flaw was found in the way the legacy_parse_param function in the Filesystem Context functionality of the Linux kernel verified the supplied parameters length. An unprivileged (in case of unprivileged user namespaces enabled, otherwise needs namespaced CAP_SYS_ADMIN privilege) local user able to open a filesystem that does not support the Filesystem Context API (and thus fallbacks to legacy handling) could use this flaw to escalate their privileges on the system.

- [https://github.com/secjuhl/CVE-2022-0185](https://github.com/secjuhl/CVE-2022-0185) :  ![starts](https://img.shields.io/github/stars/secjuhl/CVE-2022-0185.svg) ![forks](https://img.shields.io/github/forks/secjuhl/CVE-2022-0185.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/lmcewen9/cve-2021-42013](https://github.com/lmcewen9/cve-2021-42013) :  ![starts](https://img.shields.io/github/stars/lmcewen9/cve-2021-42013.svg) ![forks](https://img.shields.io/github/forks/lmcewen9/cve-2021-42013.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mightysai1997/cve-2021-41773](https://github.com/mightysai1997/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/mightysai1997/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/cve-2021-41773.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/0xrogg/CVE-2021-41773](https://github.com/0xrogg/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/0xrogg/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/0xrogg/CVE-2021-41773.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via "sudoedit -s" and a command-line argument that ends with a single backslash character.

- [https://github.com/ConstantineFedorov/Review.CVE-2021-3156](https://github.com/ConstantineFedorov/Review.CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/ConstantineFedorov/Review.CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/ConstantineFedorov/Review.CVE-2021-3156.svg)


## CVE-2018-7600
 Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations.

- [https://github.com/Aihikk/DC-1_Vulnhub_Walkthrough](https://github.com/Aihikk/DC-1_Vulnhub_Walkthrough) :  ![starts](https://img.shields.io/github/stars/Aihikk/DC-1_Vulnhub_Walkthrough.svg) ![forks](https://img.shields.io/github/forks/Aihikk/DC-1_Vulnhub_Walkthrough.svg)


## CVE-2017-0199
 Microsoft Office 2007 SP3, Microsoft Office 2010 SP2, Microsoft Office 2013 SP1, Microsoft Office 2016, Microsoft Windows Vista SP2, Windows Server 2008 SP2, Windows 7 SP1, Windows 8.1 allow remote attackers to execute arbitrary code via a crafted document, aka "Microsoft Office/WordPad Remote Code Execution Vulnerability w/Windows API."

- [https://github.com/ahmed-tarek22752/security-vulnerability-in-Microsoft-Office.](https://github.com/ahmed-tarek22752/security-vulnerability-in-Microsoft-Office.) :  ![starts](https://img.shields.io/github/stars/ahmed-tarek22752/security-vulnerability-in-Microsoft-Office..svg) ![forks](https://img.shields.io/github/forks/ahmed-tarek22752/security-vulnerability-in-Microsoft-Office..svg)


## CVE-2015-1328
 The overlayfs implementation in the linux (aka Linux kernel) package before 3.19.0-21.21 in Ubuntu through 15.04 does not properly check permissions for file creation in the upper filesystem directory, which allows local users to obtain root access by leveraging a configuration in which overlayfs is permitted in an arbitrary mount namespace.

- [https://github.com/saqibnet/blackbox-pentesting-infsecos](https://github.com/saqibnet/blackbox-pentesting-infsecos) :  ![starts](https://img.shields.io/github/stars/saqibnet/blackbox-pentesting-infsecos.svg) ![forks](https://img.shields.io/github/forks/saqibnet/blackbox-pentesting-infsecos.svg)


## CVE-2013-3660
 The EPATHOBJ::pprFlattenRec function in win32k.sys in the kernel-mode drivers in Microsoft Windows XP SP2 and SP3, Windows Server 2003 SP2, Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, and Windows Server 2012 does not properly initialize a pointer for the next object in a certain list, which allows local users to obtain write access to the PATHRECORD chain, and consequently gain privileges, by triggering excessive consumption of paged memory and then making many FlattenPath function calls, aka "Win32k Read AV Vulnerability."

- [https://github.com/kikozz/CVE-2013-3660-win32k.sys](https://github.com/kikozz/CVE-2013-3660-win32k.sys) :  ![starts](https://img.shields.io/github/stars/kikozz/CVE-2013-3660-win32k.sys.svg) ![forks](https://img.shields.io/github/forks/kikozz/CVE-2013-3660-win32k.sys.svg)


## CVE-2011-4825
 Static code injection vulnerability in inc/function.base.php in Ajax File and Image Manager before 1.1, as used in tinymce before 1.4.2, phpMyFAQ 2.6 before 2.6.19 and 2.7 before 2.7.1, and possibly other products, allows remote attackers to inject arbitrary PHP code into data.php via crafted parameters.

- [https://github.com/XavLimSG/Zenphoto-1.4.1.4-CVE-2011-4825-RCE](https://github.com/XavLimSG/Zenphoto-1.4.1.4-CVE-2011-4825-RCE) :  ![starts](https://img.shields.io/github/stars/XavLimSG/Zenphoto-1.4.1.4-CVE-2011-4825-RCE.svg) ![forks](https://img.shields.io/github/forks/XavLimSG/Zenphoto-1.4.1.4-CVE-2011-4825-RCE.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/Maalfer/vsftpd-2.3.4-exploit](https://github.com/Maalfer/vsftpd-2.3.4-exploit) :  ![starts](https://img.shields.io/github/stars/Maalfer/vsftpd-2.3.4-exploit.svg) ![forks](https://img.shields.io/github/forks/Maalfer/vsftpd-2.3.4-exploit.svg)


## CVE-2007-2447
 The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function, when the "username map script" smb.conf option is enabled, and allows remote authenticated users to execute commands via shell metacharacters involving other MS-RPC functions in the (2) remote printer and (3) file share management.

- [https://github.com/malredfan/metasploitable2-pentest](https://github.com/malredfan/metasploitable2-pentest) :  ![starts](https://img.shields.io/github/stars/malredfan/metasploitable2-pentest.svg) ![forks](https://img.shields.io/github/forks/malredfan/metasploitable2-pentest.svg)

