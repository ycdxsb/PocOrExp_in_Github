# Update 2026-02-12
## CVE-2026-25961
 SumatraPDF is a multi-format reader for Windows. In 3.5.0 through 3.5.2, SumatraPDF's update mechanism disables TLS hostname verification (INTERNET_FLAG_IGNORE_CERT_CN_INVALID) and executes installers without signature checks. A network attacker with any valid TLS certificate (e.g., Let's Encrypt) can intercept the update check request, inject a malicious installer URL, and achieve arbitrary code execution.

- [https://github.com/mbanyamer/CVE-2026-25961-SumatraPDF-3.5.0---3.5.2-RCE](https://github.com/mbanyamer/CVE-2026-25961-SumatraPDF-3.5.0---3.5.2-RCE) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-25961-SumatraPDF-3.5.0---3.5.2-RCE.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-25961-SumatraPDF-3.5.0---3.5.2-RCE.svg)


## CVE-2026-25939
an authorization bypass vulnerability in the FUXA allows an unauthenticated, remote attacker to create and modify arbitrary schedulers, exposing connected ICS/SCADA environments to follow-on actions. This has been patched in FUXA version 1.2.11.

- [https://github.com/mbanyamer/CVE-2026-25939-SCADA-FUXA-Unauthenticated-Remote-Arbitrary](https://github.com/mbanyamer/CVE-2026-25939-SCADA-FUXA-Unauthenticated-Remote-Arbitrary) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-25939-SCADA-FUXA-Unauthenticated-Remote-Arbitrary.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-25939-SCADA-FUXA-Unauthenticated-Remote-Arbitrary.svg)


## CVE-2026-25807
 ZAI Shell is an autonomous SysOps agent designed to navigate, repair, and secure complex environments. Prior to 9.0.3, the P2P terminal sharing feature (share start) opens a TCP socket on port 5757 without any authentication mechanism. Any remote attacker can connect to this port using a simple socket script. An attacker who connects to a ZAI-Shell P2P session running in --no-ai mode can send arbitrary system commands. If the host user approves the command without reviewing its contents, the command executes directly with the user's privileges, bypassing all Sentinel safety checks. This vulnerability is fixed in 9.0.3.

- [https://github.com/ibrahmsql/CVE-2026-25807-Exploit](https://github.com/ibrahmsql/CVE-2026-25807-Exploit) :  ![starts](https://img.shields.io/github/stars/ibrahmsql/CVE-2026-25807-Exploit.svg) ![forks](https://img.shields.io/github/forks/ibrahmsql/CVE-2026-25807-Exploit.svg)


## CVE-2026-25526
 JinJava is a Java-based template engine based on django template syntax, adapted to render jinja templates. Prior to versions 2.7.6 and 2.8.3, JinJava is vulnerable to arbitrary Java execution via bypass through ForTag. This allows arbitrary Java class instantiation and file access bypassing built-in sandbox restrictions. This issue has been patched in versions 2.7.6 and 2.8.3.

- [https://github.com/av4nth1ka/jinjava-cve-2026-25526-poc](https://github.com/av4nth1ka/jinjava-cve-2026-25526-poc) :  ![starts](https://img.shields.io/github/stars/av4nth1ka/jinjava-cve-2026-25526-poc.svg) ![forks](https://img.shields.io/github/forks/av4nth1ka/jinjava-cve-2026-25526-poc.svg)


## CVE-2026-25251
 This has been moved to the REJECTED state because the information source is under review. If circumstances change, it is possible that this will be moved to the PUBLISHED state at a later date.

- [https://github.com/0verdu/Senate_Surprise](https://github.com/0verdu/Senate_Surprise) :  ![starts](https://img.shields.io/github/stars/0verdu/Senate_Surprise.svg) ![forks](https://img.shields.io/github/forks/0verdu/Senate_Surprise.svg)


## CVE-2026-25053
 n8n is an open source workflow automation platform. Prior to versions 1.123.10 and 2.5.0, vulnerabilities in the Git node allowed authenticated users with permission to create or modify workflows to execute arbitrary system commands or read arbitrary files on the n8n host. This issue has been patched in versions 1.123.10 and 2.5.0.

- [https://github.com/yadhukrishnam/CVE-2026-25053](https://github.com/yadhukrishnam/CVE-2026-25053) :  ![starts](https://img.shields.io/github/stars/yadhukrishnam/CVE-2026-25053.svg) ![forks](https://img.shields.io/github/forks/yadhukrishnam/CVE-2026-25053.svg)


## CVE-2026-24858
 An Authentication Bypass Using an Alternate Path or Channel vulnerability [CWE-288] vulnerability in Fortinet FortiAnalyzer 7.6.0 through 7.6.5, FortiAnalyzer 7.4.0 through 7.4.9, FortiAnalyzer 7.2.0 through 7.2.11, FortiAnalyzer 7.0.0 through 7.0.15, FortiManager 7.6.0 through 7.6.5, FortiManager 7.4.0 through 7.4.9, FortiManager 7.2.0 through 7.2.11, FortiManager 7.0.0 through 7.0.15, FortiOS 7.6.0 through 7.6.5, FortiOS 7.4.0 through 7.4.10, FortiOS 7.2.0 through 7.2.12, FortiOS 7.0.0 through 7.0.18, FortiProxy 7.6.0 through 7.6.4, FortiProxy 7.4.0 through 7.4.12, FortiProxy 7.2.0 through 7.2.15, FortiProxy 7.0.0 through 7.0.22, FortiWeb 8.0.0 through 8.0.3, FortiWeb 7.6.0 through 7.6.6, FortiWeb 7.4.0 through 7.4.11 may allow an attacker with a FortiCloud account and a registered device to log into other devices registered to other accounts, if FortiCloud SSO authentication is enabled on those devices.

- [https://github.com/gagaltotal/cve-2026-24858](https://github.com/gagaltotal/cve-2026-24858) :  ![starts](https://img.shields.io/github/stars/gagaltotal/cve-2026-24858.svg) ![forks](https://img.shields.io/github/forks/gagaltotal/cve-2026-24858.svg)


## CVE-2026-23550
 Incorrect Privilege Assignment vulnerability in Modular DS allows Privilege Escalation.This issue affects Modular DS: from n/a through 2.5.1.

- [https://github.com/epsilonpoint88-glitch/EpSiLoNPoInT-](https://github.com/epsilonpoint88-glitch/EpSiLoNPoInT-) :  ![starts](https://img.shields.io/github/stars/epsilonpoint88-glitch/EpSiLoNPoInT-.svg) ![forks](https://img.shields.io/github/forks/epsilonpoint88-glitch/EpSiLoNPoInT-.svg)


## CVE-2026-21858
 n8n is an open source workflow automation platform. Versions starting with 1.65.0 and below 1.121.0 enable an attacker to access files on the underlying server through execution of certain form-based workflows. A vulnerable workflow could grant access to an unauthenticated remote attacker, resulting in exposure of sensitive information stored on the system and may enable further compromise depending on deployment configuration and workflow usage. This issue is fixed in version 1.121.0.

- [https://github.com/cropnet/Ni8mare](https://github.com/cropnet/Ni8mare) :  ![starts](https://img.shields.io/github/stars/cropnet/Ni8mare.svg) ![forks](https://img.shields.io/github/forks/cropnet/Ni8mare.svg)


## CVE-2026-2113
 A security vulnerability has been detected in yuan1994 tpadmin up to 1.3.12. This affects an unknown part in the library /public/static/admin/lib/webuploader/0.1.5/server/preview.php of the component WebUploader. The manipulation leads to deserialization. The attack is possible to be carried out remotely. The exploit has been disclosed publicly and may be used. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/MaxMnMl/tpadmin-CVE-2026-2113-poc](https://github.com/MaxMnMl/tpadmin-CVE-2026-2113-poc) :  ![starts](https://img.shields.io/github/stars/MaxMnMl/tpadmin-CVE-2026-2113-poc.svg) ![forks](https://img.shields.io/github/forks/MaxMnMl/tpadmin-CVE-2026-2113-poc.svg)


## CVE-2026-1731
 BeyondTrust Remote Support (RS) and certain older versions of Privileged Remote Access (PRA) contain a critical pre-authentication remote code execution vulnerability. By sending specially crafted requests, an unauthenticated remote attacker may be able to execute operating system commands in the context of the site user.

- [https://github.com/z3r0h3ro/CVE-2026-1731-exp](https://github.com/z3r0h3ro/CVE-2026-1731-exp) :  ![starts](https://img.shields.io/github/stars/z3r0h3ro/CVE-2026-1731-exp.svg) ![forks](https://img.shields.io/github/forks/z3r0h3ro/CVE-2026-1731-exp.svg)


## CVE-2026-1529
 A flaw was found in Keycloak. An attacker can exploit this vulnerability by modifying the organization ID and target email within a legitimate invitation token's JSON Web Token (JWT) payload. This lack of cryptographic signature verification allows the attacker to successfully self-register into an unauthorized organization, leading to unauthorized access.

- [https://github.com/ninjazan420/CVE-2026-1529-PoC-keycloak-unauthorized-registration-via-improper-invitation-token-validation](https://github.com/ninjazan420/CVE-2026-1529-PoC-keycloak-unauthorized-registration-via-improper-invitation-token-validation) :  ![starts](https://img.shields.io/github/stars/ninjazan420/CVE-2026-1529-PoC-keycloak-unauthorized-registration-via-improper-invitation-token-validation.svg) ![forks](https://img.shields.io/github/forks/ninjazan420/CVE-2026-1529-PoC-keycloak-unauthorized-registration-via-improper-invitation-token-validation.svg)


## CVE-2025-68645
 A Local File Inclusion (LFI) vulnerability exists in the Webmail Classic UI of Zimbra Collaboration (ZCS) 10.0 and 10.1 because of improper handling of user-supplied request parameters in the RestFilter servlet. An unauthenticated remote attacker can craft requests to the /h/rest endpoint to influence internal request dispatching, allowing inclusion of arbitrary files from the WebRoot directory.

- [https://github.com/faysalferdous/CVE-2025-68645-Exploiting-Zimbra-Webmail-LFI-Vulnerability](https://github.com/faysalferdous/CVE-2025-68645-Exploiting-Zimbra-Webmail-LFI-Vulnerability) :  ![starts](https://img.shields.io/github/stars/faysalferdous/CVE-2025-68645-Exploiting-Zimbra-Webmail-LFI-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/faysalferdous/CVE-2025-68645-Exploiting-Zimbra-Webmail-LFI-Vulnerability.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg)


## CVE-2025-61155
 The GameDriverX64.sys kernel-mode anti-cheat driver (v7.23.4.7 and earlier) contains an access control vulnerability in one of its IOCTL handlers. A user-mode process can open a handle to the driver device and send specially crafted IOCTL requests. These requests are executed in kernel-mode context without proper authentication or access validation, allowing the attacker to terminate arbitrary processes, including critical system and security services, without requiring administrative privileges.

- [https://github.com/I3r1h0n/Sigurd](https://github.com/I3r1h0n/Sigurd) :  ![starts](https://img.shields.io/github/stars/I3r1h0n/Sigurd.svg) ![forks](https://img.shields.io/github/forks/I3r1h0n/Sigurd.svg)


## CVE-2025-54254
 Adobe Experience Manager versions 6.5.23 and earlier are affected by an Improper Restriction of XML External Entity Reference ('XXE') vulnerability that could lead to arbitrary file system read. An attacker could exploit this vulnerability to access sensitive files on the local file system, scope is changed. Exploitation of this issue does not require user interaction.

- [https://github.com/zoomdbz/AEMPWN](https://github.com/zoomdbz/AEMPWN) :  ![starts](https://img.shields.io/github/stars/zoomdbz/AEMPWN.svg) ![forks](https://img.shields.io/github/forks/zoomdbz/AEMPWN.svg)


## CVE-2025-54253
 Adobe Experience Manager versions 6.5.23 and earlier are affected by a Misconfiguration vulnerability that could result in arbitrary code execution. An attacker could leverage this vulnerability to bypass security mechanisms and execute code. Exploitation of this issue does not require user interaction and scope is changed.

- [https://github.com/zoomdbz/AEMPWN](https://github.com/zoomdbz/AEMPWN) :  ![starts](https://img.shields.io/github/stars/zoomdbz/AEMPWN.svg) ![forks](https://img.shields.io/github/forks/zoomdbz/AEMPWN.svg)


## CVE-2025-49132
 Pterodactyl is a free, open-source game server management panel. Prior to version 1.11.11, using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated. With the ability to execute arbitrary code it could be used to gain access to the Panel's server, read credentials from the Panel's config, extract sensitive information from the database, access files of servers managed by the panel, etc. This issue has been patched in version 1.11.11. There are no software workarounds for this vulnerability, but use of an external Web Application Firewall (WAF) could help mitigate this attack.

- [https://github.com/matesz44/CVE-2025-49132](https://github.com/matesz44/CVE-2025-49132) :  ![starts](https://img.shields.io/github/stars/matesz44/CVE-2025-49132.svg) ![forks](https://img.shields.io/github/forks/matesz44/CVE-2025-49132.svg)
- [https://github.com/Ahmedf000/-CVE-2025-49132_Pterodactyl-_HTB-Season-10](https://github.com/Ahmedf000/-CVE-2025-49132_Pterodactyl-_HTB-Season-10) :  ![starts](https://img.shields.io/github/stars/Ahmedf000/-CVE-2025-49132_Pterodactyl-_HTB-Season-10.svg) ![forks](https://img.shields.io/github/forks/Ahmedf000/-CVE-2025-49132_Pterodactyl-_HTB-Season-10.svg)


## CVE-2025-34085
 This CVE ID has been rejected or withdrawn by its CVE Numbering Authority as it is a duplicate of CVE-2020-36847.

- [https://github.com/0xGunrunner/CVE-2025-34085](https://github.com/0xGunrunner/CVE-2025-34085) :  ![starts](https://img.shields.io/github/stars/0xGunrunner/CVE-2025-34085.svg) ![forks](https://img.shields.io/github/forks/0xGunrunner/CVE-2025-34085.svg)


## CVE-2025-29631
 An issue in Gardyn 4 allows a remote attacker execute arbitrary code

- [https://github.com/kristof-mattei/gardyn-hack](https://github.com/kristof-mattei/gardyn-hack) :  ![starts](https://img.shields.io/github/stars/kristof-mattei/gardyn-hack.svg) ![forks](https://img.shields.io/github/forks/kristof-mattei/gardyn-hack.svg)


## CVE-2025-29630
 An issue in Gardyn 4 allows a remote attacker with the corresponding ssh private key can gain remote root access to affected devices

- [https://github.com/kristof-mattei/gardyn-hack](https://github.com/kristof-mattei/gardyn-hack) :  ![starts](https://img.shields.io/github/stars/kristof-mattei/gardyn-hack.svg) ![forks](https://img.shields.io/github/forks/kristof-mattei/gardyn-hack.svg)


## CVE-2025-29629
 An issue in Gardyn 4 allows a remote attacker to obtain sensitive information and execute arbitrary code via the Gardyn Home component

- [https://github.com/kristof-mattei/gardyn-hack](https://github.com/kristof-mattei/gardyn-hack) :  ![starts](https://img.shields.io/github/stars/kristof-mattei/gardyn-hack.svg) ![forks](https://img.shields.io/github/forks/kristof-mattei/gardyn-hack.svg)


## CVE-2025-29628
 An issue in Gardyn 4 allows a remote attacker to obtain sensitive information and execute arbitrary code via a request

- [https://github.com/kristof-mattei/gardyn-hack](https://github.com/kristof-mattei/gardyn-hack) :  ![starts](https://img.shields.io/github/stars/kristof-mattei/gardyn-hack.svg) ![forks](https://img.shields.io/github/forks/kristof-mattei/gardyn-hack.svg)


## CVE-2025-15368
 The SportsPress plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 2.7.26 via shortcodes 'template_name' attribute. This makes it possible for authenticated attackers, with contributor-level and above permissions, to include and execute arbitrary files on the server, allowing the execution of any PHP code in those files. This can be used to bypass access controls, obtain sensitive data, or achieve code execution in cases where php file type can be uploaded and included.

- [https://github.com/kazehere4you/CVE-2025-15368-Exploit](https://github.com/kazehere4you/CVE-2025-15368-Exploit) :  ![starts](https://img.shields.io/github/stars/kazehere4you/CVE-2025-15368-Exploit.svg) ![forks](https://img.shields.io/github/forks/kazehere4you/CVE-2025-15368-Exploit.svg)


## CVE-2025-8088
     from ESET.

- [https://github.com/Ismael-20223/CVE-2025-8088](https://github.com/Ismael-20223/CVE-2025-8088) :  ![starts](https://img.shields.io/github/stars/Ismael-20223/CVE-2025-8088.svg) ![forks](https://img.shields.io/github/forks/Ismael-20223/CVE-2025-8088.svg)


## CVE-2025-6019
 A Local Privilege Escalation (LPE) vulnerability was found in libblockdev. Generally, the "allow_active" setting in Polkit permits a physically present user to take certain actions based on the session type. Due to the way libblockdev interacts with the udisks daemon, an "allow_active" user on a system may be able escalate to full root privileges on the target host. Normally, udisks mounts user-provided filesystem images with security flags like nosuid and nodev to prevent privilege escalation.  However, a local attacker can create a specially crafted XFS image containing a SUID-root shell, then trick udisks into resizing it. This mounts their malicious filesystem with root privileges, allowing them to execute their SUID-root shell and gain complete control of the system.

- [https://github.com/symphony2colour/CVE-2025-6019-udisks-lpe-no-image](https://github.com/symphony2colour/CVE-2025-6019-udisks-lpe-no-image) :  ![starts](https://img.shields.io/github/stars/symphony2colour/CVE-2025-6019-udisks-lpe-no-image.svg) ![forks](https://img.shields.io/github/forks/symphony2colour/CVE-2025-6019-udisks-lpe-no-image.svg)
- [https://github.com/matesz44/CVE-2025-6018-19](https://github.com/matesz44/CVE-2025-6018-19) :  ![starts](https://img.shields.io/github/stars/matesz44/CVE-2025-6018-19.svg) ![forks](https://img.shields.io/github/forks/matesz44/CVE-2025-6018-19.svg)


## CVE-2025-6018
 A Local Privilege Escalation (LPE) vulnerability has been discovered in pam-config within Linux Pluggable Authentication Modules (PAM). This flaw allows an unprivileged local attacker (for example, a user logged in via SSH) to obtain the elevated privileges normally reserved for a physically present, "allow_active" user. The highest risk is that the attacker can then perform all allow_active yes Polkit actions, which are typically restricted to console users, potentially gaining unauthorized control over system configurations, services, or other sensitive operations.

- [https://github.com/matesz44/CVE-2025-6018-19](https://github.com/matesz44/CVE-2025-6018-19) :  ![starts](https://img.shields.io/github/stars/matesz44/CVE-2025-6018-19.svg) ![forks](https://img.shields.io/github/forks/matesz44/CVE-2025-6018-19.svg)


## CVE-2025-5419
 Out of bounds read and write in V8 in Google Chrome prior to 137.0.7151.68 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/Riquelme54322/CVE-2025-5419](https://github.com/Riquelme54322/CVE-2025-5419) :  ![starts](https://img.shields.io/github/stars/Riquelme54322/CVE-2025-5419.svg) ![forks](https://img.shields.io/github/forks/Riquelme54322/CVE-2025-5419.svg)
- [https://github.com/Riquelme54322/riquelme54322.github.io](https://github.com/Riquelme54322/riquelme54322.github.io) :  ![starts](https://img.shields.io/github/stars/Riquelme54322/riquelme54322.github.io.svg) ![forks](https://img.shields.io/github/forks/Riquelme54322/riquelme54322.github.io.svg)


## CVE-2024-45440
 core/authorize.php in Drupal 11.x-dev allows Full Path Disclosure (even when error logging is None) if the value of hash_salt is file_get_contents of a file that does not exist.

- [https://github.com/zoomdbz/CVE-2024-45440](https://github.com/zoomdbz/CVE-2024-45440) :  ![starts](https://img.shields.io/github/stars/zoomdbz/CVE-2024-45440.svg) ![forks](https://img.shields.io/github/forks/zoomdbz/CVE-2024-45440.svg)


## CVE-2024-21413
 Microsoft Outlook Remote Code Execution Vulnerability

- [https://github.com/SallocinAvalcante/lab-SMB-responder-CVE-2024-21413](https://github.com/SallocinAvalcante/lab-SMB-responder-CVE-2024-21413) :  ![starts](https://img.shields.io/github/stars/SallocinAvalcante/lab-SMB-responder-CVE-2024-21413.svg) ![forks](https://img.shields.io/github/forks/SallocinAvalcante/lab-SMB-responder-CVE-2024-21413.svg)


## CVE-2023-38408
 The PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2 has an insufficiently trustworthy search path, leading to remote code execution if an agent is forwarded to an attacker-controlled system. (Code in /usr/lib is not necessarily safe for loading into ssh-agent.) NOTE: this issue exists because of an incomplete fix for CVE-2016-10009.

- [https://github.com/jakovtodorovic/openSSH-agent-forwarding-vulnerability-analysis-CVE-2023-38408](https://github.com/jakovtodorovic/openSSH-agent-forwarding-vulnerability-analysis-CVE-2023-38408) :  ![starts](https://img.shields.io/github/stars/jakovtodorovic/openSSH-agent-forwarding-vulnerability-analysis-CVE-2023-38408.svg) ![forks](https://img.shields.io/github/forks/jakovtodorovic/openSSH-agent-forwarding-vulnerability-analysis-CVE-2023-38408.svg)


## CVE-2022-44136
 Zenario CMS 9.3.57186 is vulnerable to Remote Code Excution (RCE).

- [https://github.com/Ch35h1r3c47/CVE-2022-44136-poc](https://github.com/Ch35h1r3c47/CVE-2022-44136-poc) :  ![starts](https://img.shields.io/github/stars/Ch35h1r3c47/CVE-2022-44136-poc.svg) ![forks](https://img.shields.io/github/forks/Ch35h1r3c47/CVE-2022-44136-poc.svg)


## CVE-2022-38694
 In BootRom, there is a possible unchecked write address. This could lead to local escalation of privilege with no additional execution privileges needed.

- [https://github.com/xbxarchivr/UNISOCUnlocker](https://github.com/xbxarchivr/UNISOCUnlocker) :  ![starts](https://img.shields.io/github/stars/xbxarchivr/UNISOCUnlocker.svg) ![forks](https://img.shields.io/github/forks/xbxarchivr/UNISOCUnlocker.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Taldrid1/cve-2021-41773](https://github.com/Taldrid1/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/Taldrid1/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Taldrid1/cve-2021-41773.svg)

