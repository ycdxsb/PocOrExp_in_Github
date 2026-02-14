# Update 2026-02-14
## CVE-2026-26235
 JUNG Smart Visu Server 1.1.1050 contains a denial of service vulnerability that allows unauthenticated attackers to remotely shutdown or reboot the server. Attackers can send a single POST request to trigger the server reboot without requiring any authentication.

- [https://github.com/mbanyamer/CVE-2026-26235-JUNG-Smart-Visu-Server-Unauthenticated-Reboot-Shutdown](https://github.com/mbanyamer/CVE-2026-26235-JUNG-Smart-Visu-Server-Unauthenticated-Reboot-Shutdown) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-26235-JUNG-Smart-Visu-Server-Unauthenticated-Reboot-Shutdown.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-26235-JUNG-Smart-Visu-Server-Unauthenticated-Reboot-Shutdown.svg)


## CVE-2026-26215
 manga-image-translator version beta-0.3 and prior in shared API mode contains an unsafe deserialization vulnerability that can lead to unauthenticated remote code execution. The FastAPI endpoints /simple_execute/{method} and /execute/{method} deserialize attacker-controlled request bodies using pickle.loads() without validation. Although a nonce-based authorization check is intended to restrict access, the nonce defaults to an empty string and the check is skipped, allowing remote attackers to execute arbitrary code in the server context by sending a crafted pickle payload.

- [https://github.com/mbanyamer/-CVE-2026-26215-manga-image-translator-RCE](https://github.com/mbanyamer/-CVE-2026-26215-manga-image-translator-RCE) :  ![starts](https://img.shields.io/github/stars/mbanyamer/-CVE-2026-26215-manga-image-translator-RCE.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/-CVE-2026-26215-manga-image-translator-RCE.svg)


## CVE-2026-25828
 grub-btrfs through 2026-01-31 (on Arch Linux and derivative distributions) allows initramfs OS command injection because it does not sanitize the $root parameter to resolve_device().

- [https://github.com/cardosource/CVE-2026-25828](https://github.com/cardosource/CVE-2026-25828) :  ![starts](https://img.shields.io/github/stars/cardosource/CVE-2026-25828.svg) ![forks](https://img.shields.io/github/forks/cardosource/CVE-2026-25828.svg)


## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.

- [https://github.com/hyu164/Terrminus-CVE-2026-2406](https://github.com/hyu164/Terrminus-CVE-2026-2406) :  ![starts](https://img.shields.io/github/stars/hyu164/Terrminus-CVE-2026-2406.svg) ![forks](https://img.shields.io/github/forks/hyu164/Terrminus-CVE-2026-2406.svg)


## CVE-2026-23830
 SandboxJS is a JavaScript sandboxing library. Versions prior to 0.8.26 have a sandbox escape vulnerability due to `AsyncFunction` not being isolated in `SandboxFunction`. The library attempts to sandbox code execution by replacing the global `Function` constructor with a safe, sandboxed version (`SandboxFunction`). This is handled in `utils.ts` by mapping `Function` to `sandboxFunction` within a map used for lookups. However, before version 0.8.26, the library did not include mappings for `AsyncFunction`, `GeneratorFunction`, and `AsyncGeneratorFunction`. These constructors are not global properties but can be accessed via the `.constructor` property of an instance (e.g., `(async () = {}).constructor`). In `executor.ts`, property access is handled. When code running inside the sandbox accesses `.constructor` on an async function (which the sandbox allows creating), the `executor` retrieves the property value. Since `AsyncFunction` was not in the safe-replacement map, the `executor` returns the actual native host `AsyncFunction` constructor. Constructors for functions in JavaScript (like `Function`, `AsyncFunction`) create functions that execute in the global scope. By obtaining the host `AsyncFunction` constructor, an attacker can create a new async function that executes entirely outside the sandbox context, bypassing all restrictions and gaining full access to the host environment (Remote Code Execution). Version 0.8.26 patches this vulnerability.

- [https://github.com/Galaxy-sc/CVE-2026-23830-SandBreak](https://github.com/Galaxy-sc/CVE-2026-23830-SandBreak) :  ![starts](https://img.shields.io/github/stars/Galaxy-sc/CVE-2026-23830-SandBreak.svg) ![forks](https://img.shields.io/github/forks/Galaxy-sc/CVE-2026-23830-SandBreak.svg)


## CVE-2026-22153
 An Authentication Bypass by Primary Weakness vulnerability [CWE-305] vulnerability in Fortinet FortiOS 7.6.0 through 7.6.4 may allow an unauthenticated attacker to bypass LDAP authentication of Agentless VPN or FSSO policy, when the remote LDAP server is configured in a specific way.

- [https://github.com/glitchhawks/CVE-2026-22153](https://github.com/glitchhawks/CVE-2026-22153) :  ![starts](https://img.shields.io/github/stars/glitchhawks/CVE-2026-22153.svg) ![forks](https://img.shields.io/github/forks/glitchhawks/CVE-2026-22153.svg)
- [https://github.com/washingtonmaister/CVE-2026-22153-exp](https://github.com/washingtonmaister/CVE-2026-22153-exp) :  ![starts](https://img.shields.io/github/stars/washingtonmaister/CVE-2026-22153-exp.svg) ![forks](https://img.shields.io/github/forks/washingtonmaister/CVE-2026-22153-exp.svg)


## CVE-2026-20841
 Improper neutralization of special elements used in a command ('command injection') in Windows Notepad App allows an unauthorized attacker to execute code locally.

- [https://github.com/patchpoint/CVE-2026-20841](https://github.com/patchpoint/CVE-2026-20841) :  ![starts](https://img.shields.io/github/stars/patchpoint/CVE-2026-20841.svg) ![forks](https://img.shields.io/github/forks/patchpoint/CVE-2026-20841.svg)
- [https://github.com/uky007/CVE-2026-20841_notepad_analysis](https://github.com/uky007/CVE-2026-20841_notepad_analysis) :  ![starts](https://img.shields.io/github/stars/uky007/CVE-2026-20841_notepad_analysis.svg) ![forks](https://img.shields.io/github/forks/uky007/CVE-2026-20841_notepad_analysis.svg)
- [https://github.com/dogukankurnaz/CVE-2026-20841-PoC](https://github.com/dogukankurnaz/CVE-2026-20841-PoC) :  ![starts](https://img.shields.io/github/stars/dogukankurnaz/CVE-2026-20841-PoC.svg) ![forks](https://img.shields.io/github/forks/dogukankurnaz/CVE-2026-20841-PoC.svg)
- [https://github.com/SecureWithUmer/CVE-2026-20841](https://github.com/SecureWithUmer/CVE-2026-20841) :  ![starts](https://img.shields.io/github/stars/SecureWithUmer/CVE-2026-20841.svg) ![forks](https://img.shields.io/github/forks/SecureWithUmer/CVE-2026-20841.svg)
- [https://github.com/atiilla/CVE-2026-20841](https://github.com/atiilla/CVE-2026-20841) :  ![starts](https://img.shields.io/github/stars/atiilla/CVE-2026-20841.svg) ![forks](https://img.shields.io/github/forks/atiilla/CVE-2026-20841.svg)
- [https://github.com/hackfaiz/CVE-2026-20841-PoC](https://github.com/hackfaiz/CVE-2026-20841-PoC) :  ![starts](https://img.shields.io/github/stars/hackfaiz/CVE-2026-20841-PoC.svg) ![forks](https://img.shields.io/github/forks/hackfaiz/CVE-2026-20841-PoC.svg)


## CVE-2026-2249
 METIS DFS devices (versions = oscore 2.1.234-r18) expose a web-based shell at the /console endpoint that does not require authentication. Accessing this endpoint allows a remote attacker to execute arbitrary operating system commands with 'daemon' privileges. This results in the compromise of the software, granting unauthorized access to modify configuration, read and alter sensitive data, or disrupt services.

- [https://github.com/taylorwerno/CVE-2026-2249](https://github.com/taylorwerno/CVE-2026-2249) :  ![starts](https://img.shields.io/github/stars/taylorwerno/CVE-2026-2249.svg) ![forks](https://img.shields.io/github/forks/taylorwerno/CVE-2026-2249.svg)


## CVE-2026-1729
 The AdForest theme for WordPress is vulnerable to authentication bypass in all versions up to, and including, 6.0.12. This is due to the plugin not properly verifying a user's identity prior to authenticating them through the 'sb_login_user_with_otp_fun' function. This makes it possible for unauthenticated attackers to log in as arbitrary users, including administrators.

- [https://github.com/ninjazan420/CVE-2026-1729-PoC-AdForest-WordPress-Authentication-Bypass](https://github.com/ninjazan420/CVE-2026-1729-PoC-AdForest-WordPress-Authentication-Bypass) :  ![starts](https://img.shields.io/github/stars/ninjazan420/CVE-2026-1729-PoC-AdForest-WordPress-Authentication-Bypass.svg) ![forks](https://img.shields.io/github/forks/ninjazan420/CVE-2026-1729-PoC-AdForest-WordPress-Authentication-Bypass.svg)


## CVE-2025-70886
 An issue in halo v.2.22.4 and before allows a remote attacker to cause a denial of service via a crafted payload to the public comment submission endpoint

- [https://github.com/HowieHz/CVE-2025-70886](https://github.com/HowieHz/CVE-2025-70886) :  ![starts](https://img.shields.io/github/stars/HowieHz/CVE-2025-70886.svg) ![forks](https://img.shields.io/github/forks/HowieHz/CVE-2025-70886.svg)


## CVE-2025-69604
 An issue in Shirt Pocket's SuperDuper! 3.11 and earlier allow a local attacker to modify the default task template to install an arbitrary package that can run shell scripts with root privileges and Full Disk Access, thus bypassing macOS privacy controls.

- [https://github.com/graypixel2121/CVE-2025-69604](https://github.com/graypixel2121/CVE-2025-69604) :  ![starts](https://img.shields.io/github/stars/graypixel2121/CVE-2025-69604.svg) ![forks](https://img.shields.io/github/forks/graypixel2121/CVE-2025-69604.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-rsc-webpack](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-rsc-webpack) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-rsc-webpack.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-rsc-webpack.svg)


## CVE-2025-61882
 Vulnerability in the Oracle Concurrent Processing product of Oracle E-Business Suite (component: BI Publisher Integration).  Supported versions that are affected are 12.2.3-12.2.14. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Concurrent Processing.  Successful attacks of this vulnerability can result in takeover of Oracle Concurrent Processing. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/sid-203/Enterprise-Information-Security-Risk-Assessment-Oracle-E-Business-Suite-Case-Study](https://github.com/sid-203/Enterprise-Information-Security-Risk-Assessment-Oracle-E-Business-Suite-Case-Study) :  ![starts](https://img.shields.io/github/stars/sid-203/Enterprise-Information-Security-Risk-Assessment-Oracle-E-Business-Suite-Case-Study.svg) ![forks](https://img.shields.io/github/forks/sid-203/Enterprise-Information-Security-Risk-Assessment-Oracle-E-Business-Suite-Case-Study.svg)


## CVE-2025-59194
 Use of uninitialized resource in Windows Kernel allows an authorized attacker to elevate privileges locally.

- [https://github.com/kawaii-ghost/CVE-2025-59194](https://github.com/kawaii-ghost/CVE-2025-59194) :  ![starts](https://img.shields.io/github/stars/kawaii-ghost/CVE-2025-59194.svg) ![forks](https://img.shields.io/github/forks/kawaii-ghost/CVE-2025-59194.svg)


## CVE-2025-49132
 Pterodactyl is a free, open-source game server management panel. Prior to version 1.11.11, using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated. With the ability to execute arbitrary code it could be used to gain access to the Panel's server, read credentials from the Panel's config, extract sensitive information from the database, access files of servers managed by the panel, etc. This issue has been patched in version 1.11.11. There are no software workarounds for this vulnerability, but use of an external Web Application Firewall (WAF) could help mitigate this attack.

- [https://github.com/xffsec/CVE-2025-49132](https://github.com/xffsec/CVE-2025-49132) :  ![starts](https://img.shields.io/github/stars/xffsec/CVE-2025-49132.svg) ![forks](https://img.shields.io/github/forks/xffsec/CVE-2025-49132.svg)
- [https://github.com/scroollocker/CVE-2025-49132](https://github.com/scroollocker/CVE-2025-49132) :  ![starts](https://img.shields.io/github/stars/scroollocker/CVE-2025-49132.svg) ![forks](https://img.shields.io/github/forks/scroollocker/CVE-2025-49132.svg)
- [https://github.com/thealchimist86/CVE-2025-49132-Pterodactyl-Panel-RCE](https://github.com/thealchimist86/CVE-2025-49132-Pterodactyl-Panel-RCE) :  ![starts](https://img.shields.io/github/stars/thealchimist86/CVE-2025-49132-Pterodactyl-Panel-RCE.svg) ![forks](https://img.shields.io/github/forks/thealchimist86/CVE-2025-49132-Pterodactyl-Panel-RCE.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/Grand-Moomin/Vuln-Next.js-CVE-2025-29927](https://github.com/Grand-Moomin/Vuln-Next.js-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/Grand-Moomin/Vuln-Next.js-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/Grand-Moomin/Vuln-Next.js-CVE-2025-29927.svg)


## CVE-2025-6667
 A vulnerability was found in code-projects Car Rental System 1.0 and classified as critical. Affected by this issue is some unknown functionality of the file /admin/add_cars.php. The manipulation of the argument image leads to unrestricted upload. The attack may be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/cwjchoi01/CVE-2025-66676](https://github.com/cwjchoi01/CVE-2025-66676) :  ![starts](https://img.shields.io/github/stars/cwjchoi01/CVE-2025-66676.svg) ![forks](https://img.shields.io/github/forks/cwjchoi01/CVE-2025-66676.svg)


## CVE-2025-6287
 A vulnerability classified as problematic was found in PHPGurukul COVID19 Testing Management System 1.0. Affected by this vulnerability is an unknown functionality of the file /test-details.php of the component Take Action. The manipulation of the argument remark leads to cross site scripting. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/kinokopio/CVE-2025-62878](https://github.com/kinokopio/CVE-2025-62878) :  ![starts](https://img.shields.io/github/stars/kinokopio/CVE-2025-62878.svg) ![forks](https://img.shields.io/github/forks/kinokopio/CVE-2025-62878.svg)


## CVE-2025-6019
 A Local Privilege Escalation (LPE) vulnerability was found in libblockdev. Generally, the "allow_active" setting in Polkit permits a physically present user to take certain actions based on the session type. Due to the way libblockdev interacts with the udisks daemon, an "allow_active" user on a system may be able escalate to full root privileges on the target host. Normally, udisks mounts user-provided filesystem images with security flags like nosuid and nodev to prevent privilege escalation.  However, a local attacker can create a specially crafted XFS image containing a SUID-root shell, then trick udisks into resizing it. This mounts their malicious filesystem with root privileges, allowing them to execute their SUID-root shell and gain complete control of the system.

- [https://github.com/boboaung1337/CVE-2025-6019](https://github.com/boboaung1337/CVE-2025-6019) :  ![starts](https://img.shields.io/github/stars/boboaung1337/CVE-2025-6019.svg) ![forks](https://img.shields.io/github/forks/boboaung1337/CVE-2025-6019.svg)
- [https://github.com/DesertDemons/CVE-2025-6018-6019](https://github.com/DesertDemons/CVE-2025-6018-6019) :  ![starts](https://img.shields.io/github/stars/DesertDemons/CVE-2025-6018-6019.svg) ![forks](https://img.shields.io/github/forks/DesertDemons/CVE-2025-6018-6019.svg)


## CVE-2025-6018
 A Local Privilege Escalation (LPE) vulnerability has been discovered in pam-config within Linux Pluggable Authentication Modules (PAM). This flaw allows an unprivileged local attacker (for example, a user logged in via SSH) to obtain the elevated privileges normally reserved for a physically present, "allow_active" user. The highest risk is that the attacker can then perform all allow_active yes Polkit actions, which are typically restricted to console users, potentially gaining unauthorized control over system configurations, services, or other sensitive operations.

- [https://github.com/DesertDemons/CVE-2025-6018-6019](https://github.com/DesertDemons/CVE-2025-6018-6019) :  ![starts](https://img.shields.io/github/stars/DesertDemons/CVE-2025-6018-6019.svg) ![forks](https://img.shields.io/github/forks/DesertDemons/CVE-2025-6018-6019.svg)


## CVE-2024-11003
 Qualys discovered that needrestart, before version 3.8, passes unsanitized data to a library (Modules::ScanDeps) which expects safe input. This could allow a local attacker to execute arbitrary shell commands. Please see the related CVE-2024-10224 in Modules::ScanDeps.

- [https://github.com/sychikov/CVE-2024-11003-POC](https://github.com/sychikov/CVE-2024-11003-POC) :  ![starts](https://img.shields.io/github/stars/sychikov/CVE-2024-11003-POC.svg) ![forks](https://img.shields.io/github/forks/sychikov/CVE-2024-11003-POC.svg)


## CVE-2024-0519
 Out of bounds memory access in V8 in Google Chrome prior to 120.0.6099.224 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/dbwlsdnr95/CVE-2024-0519](https://github.com/dbwlsdnr95/CVE-2024-0519) :  ![starts](https://img.shields.io/github/stars/dbwlsdnr95/CVE-2024-0519.svg) ![forks](https://img.shields.io/github/forks/dbwlsdnr95/CVE-2024-0519.svg)


## CVE-2023-35687
 In MtpPropertyValue of MtpProperty.h, there is a possible memory corruption due to a use after free. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/pazhanivel07/frameworks_av_AOSP_10_r33_CVE-2023-35687_CVE-2023-35679](https://github.com/pazhanivel07/frameworks_av_AOSP_10_r33_CVE-2023-35687_CVE-2023-35679) :  ![starts](https://img.shields.io/github/stars/pazhanivel07/frameworks_av_AOSP_10_r33_CVE-2023-35687_CVE-2023-35679.svg) ![forks](https://img.shields.io/github/forks/pazhanivel07/frameworks_av_AOSP_10_r33_CVE-2023-35687_CVE-2023-35679.svg)


## CVE-2023-33962
Version 1.0.1 contains a patch for this issue. To mitigate this vulnerability, the template engine should properly escape special characters, including single quotes. Common practice is to escape `'` as `&#39`. As a workaround, users can avoid this issue by using only double quotes `"` for HTML attributes.

- [https://github.com/shoucheng3/jstachio__jstachio_CVE-2023-33962_1-0-0](https://github.com/shoucheng3/jstachio__jstachio_CVE-2023-33962_1-0-0) :  ![starts](https://img.shields.io/github/stars/shoucheng3/jstachio__jstachio_CVE-2023-33962_1-0-0.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/jstachio__jstachio_CVE-2023-33962_1-0-0.svg)


## CVE-2023-33570
 Bagisto v1.5.1 is vulnerable to Server-Side Template Injection (SSTI).

- [https://github.com/Trangdz/bagisto_ssti_cve_2023_33570](https://github.com/Trangdz/bagisto_ssti_cve_2023_33570) :  ![starts](https://img.shields.io/github/stars/Trangdz/bagisto_ssti_cve_2023_33570.svg) ![forks](https://img.shields.io/github/forks/Trangdz/bagisto_ssti_cve_2023_33570.svg)


## CVE-2023-33404
 An Unrestricted Upload vulnerability, due to insufficient validation on UploadControlled.cs file, in BlogEngine.Net version 3.3.8.0 and earlier allows remote attackers to execute remote code.

- [https://github.com/hacip/CVE-2023-33404](https://github.com/hacip/CVE-2023-33404) :  ![starts](https://img.shields.io/github/stars/hacip/CVE-2023-33404.svg) ![forks](https://img.shields.io/github/forks/hacip/CVE-2023-33404.svg)


## CVE-2023-33177
 Xibo is a content management system (CMS). A path traversal vulnerability exists in the Xibo CMS whereby a specially crafted zip file can be uploaded to the CMS via the layout import function by an authenticated user which would allow creation of files outside of the CMS library directory as the webserver user. This can be used to upload a PHP webshell inside the web root directory and achieve remote code execution as the webserver user. Users should upgrade to version 2.3.17 or 3.3.5, which fix this issue. Customers who host their CMS with Xibo Signage have already received an upgrade or patch to resolve this issue regardless of the CMS version that they are running.

- [https://github.com/complexusprada/Xibo-CMS-Zip-Slip-RCE-Exploit-CVE-2023-33177](https://github.com/complexusprada/Xibo-CMS-Zip-Slip-RCE-Exploit-CVE-2023-33177) :  ![starts](https://img.shields.io/github/stars/complexusprada/Xibo-CMS-Zip-Slip-RCE-Exploit-CVE-2023-33177.svg) ![forks](https://img.shields.io/github/forks/complexusprada/Xibo-CMS-Zip-Slip-RCE-Exploit-CVE-2023-33177.svg)


## CVE-2023-4220
 Unrestricted file upload in big file upload functionality in `/main/inc/lib/javascript/bigupload/inc/bigUpload.php` in Chamilo LMS = v1.11.24 allows unauthenticated attackers to perform stored cross-site scripting attacks and obtain remote code execution via uploading of web shell.

- [https://github.com/Sn0wBaall/CVE-2023-4220-PoC](https://github.com/Sn0wBaall/CVE-2023-4220-PoC) :  ![starts](https://img.shields.io/github/stars/Sn0wBaall/CVE-2023-4220-PoC.svg) ![forks](https://img.shields.io/github/forks/Sn0wBaall/CVE-2023-4220-PoC.svg)


## CVE-2022-30190
Please see the MSRC Blog Entry for important information about steps you can take to protect your system from this vulnerability.

- [https://github.com/imankasthuri/follina-rce-cve-2022-30190](https://github.com/imankasthuri/follina-rce-cve-2022-30190) :  ![starts](https://img.shields.io/github/stars/imankasthuri/follina-rce-cve-2022-30190.svg) ![forks](https://img.shields.io/github/forks/imankasthuri/follina-rce-cve-2022-30190.svg)

