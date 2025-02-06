# Update 2025-02-06
## CVE-2024-47575
 A missing authentication for critical function in FortiManager 7.6.0, FortiManager 7.4.0 through 7.4.4, FortiManager 7.2.0 through 7.2.7, FortiManager 7.0.0 through 7.0.12, FortiManager 6.4.0 through 6.4.14, FortiManager 6.2.0 through 6.2.12, Fortinet FortiManager Cloud 7.4.1 through 7.4.4, FortiManager Cloud 7.2.1 through 7.2.7, FortiManager Cloud 7.0.1 through 7.0.12, FortiManager Cloud 6.4.1 through 6.4.7 allows attacker to execute arbitrary code or commands via specially crafted requests.

- [https://github.com/Raygrants/CVE-2024-47575-POC](https://github.com/Raygrants/CVE-2024-47575-POC) :  ![starts](https://img.shields.io/github/stars/Raygrants/CVE-2024-47575-POC.svg) ![forks](https://img.shields.io/github/forks/Raygrants/CVE-2024-47575-POC.svg)


## CVE-2024-35235
 OpenPrinting CUPS is an open source printing system for Linux and other Unix-like operating systems. In versions 2.4.8 and earlier, when starting the cupsd server with a Listen configuration item pointing to a symbolic link, the cupsd process can be caused to perform an arbitrary chmod of the provided argument, providing world-writable access to the target. Given that cupsd is often running as root, this can result in the change of permission of any user or system files to be world writable. Given the aforementioned Ubuntu AppArmor context, on such systems this vulnerability is limited to those files modifiable by the cupsd process. In that specific case it was found to be possible to turn the configuration of the Listen argument into full control over the cupsd.conf and cups-files.conf configuration files. By later setting the User and Group arguments in cups-files.conf, and printing with a printer configured by PPD with a `FoomaticRIPCommandLine` argument, arbitrary user and group (not root) command execution could be achieved, which can further be used on Ubuntu systems to achieve full root command execution. Commit ff1f8a623e090dee8a8aadf12a6a4b25efac143d contains a patch for the issue.

- [https://github.com/zrax-x/CVE-2024-35235-CVE-2024-5290-exp](https://github.com/zrax-x/CVE-2024-35235-CVE-2024-5290-exp) :  ![starts](https://img.shields.io/github/stars/zrax-x/CVE-2024-35235-CVE-2024-5290-exp.svg) ![forks](https://img.shields.io/github/forks/zrax-x/CVE-2024-35235-CVE-2024-5290-exp.svg)


## CVE-2024-24919
 Potentially allowing an attacker to read certain information on Check Point Security Gateways once connected to the internet and enabled with remote Access VPN or Mobile Access Software Blades. A Security fix that mitigates this vulnerability is available.

- [https://github.com/nullcult/CVE-2024-24919-Exploit](https://github.com/nullcult/CVE-2024-24919-Exploit) :  ![starts](https://img.shields.io/github/stars/nullcult/CVE-2024-24919-Exploit.svg) ![forks](https://img.shields.io/github/forks/nullcult/CVE-2024-24919-Exploit.svg)


## CVE-2024-12542
 The linkID plugin for WordPress is vulnerable to unauthorized access of data due to a missing capability check when including the 'phpinfo' function in all versions up to, and including, 0.1.2. This makes it possible for unauthenticated attackers to read configuration settings and predefined variables on the site's server. The plugin does not need to be activated for the vulnerability to be exploited.

- [https://github.com/Nxploited/CVE-2024-12542-PoC](https://github.com/Nxploited/CVE-2024-12542-PoC) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2024-12542-PoC.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2024-12542-PoC.svg)


## CVE-2024-5761
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: [CVE-2024-5260]. Reason: This candidate is a reservation duplicate of [CVE-2024-5260]. Notes: All CVE users should reference [CVE-ID] instead of this candidate. All references and descriptions in this candidate have been removed to prevent accidental usage.

- [https://github.com/nca785/CVE-2024-57610](https://github.com/nca785/CVE-2024-57610) :  ![starts](https://img.shields.io/github/stars/nca785/CVE-2024-57610.svg) ![forks](https://img.shields.io/github/forks/nca785/CVE-2024-57610.svg)


## CVE-2024-5760
 The Samsung Universal Print Driver for Windows is potentially vulnerable to escalation of privilege allowing the creation of a reverse shell in the tool. This is only applicable for products in the application released or manufactured before 2018.

- [https://github.com/nca785/CVE-2024-57609](https://github.com/nca785/CVE-2024-57609) :  ![starts](https://img.shields.io/github/stars/nca785/CVE-2024-57609.svg) ![forks](https://img.shields.io/github/forks/nca785/CVE-2024-57609.svg)


## CVE-2024-5743
This issue affects Eve Play: through 1.1.42.

- [https://github.com/ahrixia/CVE-2024-57430](https://github.com/ahrixia/CVE-2024-57430) :  ![starts](https://img.shields.io/github/stars/ahrixia/CVE-2024-57430.svg) ![forks](https://img.shields.io/github/forks/ahrixia/CVE-2024-57430.svg)


## CVE-2024-5742
 A vulnerability was found in GNU Nano that allows a possible privilege escalation through an insecure temporary file. If Nano is killed while editing, a file it saves to an emergency file with the permissions of the running user provides a window of opportunity for attackers to escalate privileges through a malicious symlink.

- [https://github.com/ahrixia/CVE-2024-57427](https://github.com/ahrixia/CVE-2024-57427) :  ![starts](https://img.shields.io/github/stars/ahrixia/CVE-2024-57427.svg) ![forks](https://img.shields.io/github/forks/ahrixia/CVE-2024-57427.svg)
- [https://github.com/ahrixia/CVE-2024-57429](https://github.com/ahrixia/CVE-2024-57429) :  ![starts](https://img.shields.io/github/stars/ahrixia/CVE-2024-57429.svg) ![forks](https://img.shields.io/github/forks/ahrixia/CVE-2024-57429.svg)
- [https://github.com/ahrixia/CVE-2024-57428](https://github.com/ahrixia/CVE-2024-57428) :  ![starts](https://img.shields.io/github/stars/ahrixia/CVE-2024-57428.svg) ![forks](https://img.shields.io/github/forks/ahrixia/CVE-2024-57428.svg)


## CVE-2024-5504
 The Rife Elementor Extensions & Templates plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'tag' attribute within the plugin's Writing Effect Headline widget in all versions up to, and including, 1.2.1 due to insufficient input sanitization and output escaping on user supplied attributes. This makes it possible for authenticated attackers, with contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/tcbutler320/CVE-2024-55040-Sensaphone-XSS](https://github.com/tcbutler320/CVE-2024-55040-Sensaphone-XSS) :  ![starts](https://img.shields.io/github/stars/tcbutler320/CVE-2024-55040-Sensaphone-XSS.svg) ![forks](https://img.shields.io/github/forks/tcbutler320/CVE-2024-55040-Sensaphone-XSS.svg)


## CVE-2024-5290
Membership in the netdev group or access to the dbus interface of wpa_supplicant allow an unprivileged user to specify an arbitrary path to a module to be loaded by the wpa_supplicant process; other escalation paths might exist.

- [https://github.com/zrax-x/CVE-2024-35235-CVE-2024-5290-exp](https://github.com/zrax-x/CVE-2024-35235-CVE-2024-5290-exp) :  ![starts](https://img.shields.io/github/stars/zrax-x/CVE-2024-35235-CVE-2024-5290-exp.svg) ![forks](https://img.shields.io/github/forks/zrax-x/CVE-2024-35235-CVE-2024-5290-exp.svg)


## CVE-2024-2961
 The iconv() function in the GNU C Library versions 2.39 and older may overflow the output buffer passed to it by up to 4 bytes when converting strings to the ISO-2022-CN-EXT character set, which may be used to crash an application or overwrite a neighbouring variable.

- [https://github.com/suce0155/CVE-2024-2961_buddyforms_2.7.7](https://github.com/suce0155/CVE-2024-2961_buddyforms_2.7.7) :  ![starts](https://img.shields.io/github/stars/suce0155/CVE-2024-2961_buddyforms_2.7.7.svg) ![forks](https://img.shields.io/github/forks/suce0155/CVE-2024-2961_buddyforms_2.7.7.svg)


## CVE-2023-26136
 Versions of the package tough-cookie before 4.1.3 are vulnerable to Prototype Pollution due to improper handling of Cookies when using CookieJar in rejectPublicSuffixes=false mode. This issue arises from the manner in which the objects are initialized.

- [https://github.com/dani33339/tough-cookie-Seal-Security](https://github.com/dani33339/tough-cookie-Seal-Security) :  ![starts](https://img.shields.io/github/stars/dani33339/tough-cookie-Seal-Security.svg) ![forks](https://img.shields.io/github/forks/dani33339/tough-cookie-Seal-Security.svg)
- [https://github.com/dani33339/tough-cookie-SealSecurity](https://github.com/dani33339/tough-cookie-SealSecurity) :  ![starts](https://img.shields.io/github/stars/dani33339/tough-cookie-SealSecurity.svg) ![forks](https://img.shields.io/github/forks/dani33339/tough-cookie-SealSecurity.svg)


## CVE-2023-2245
 A vulnerability was found in hansunCMS 1.4.3. It has been declared as critical. This vulnerability affects unknown code of the file /ueditor/net/controller.ashx?action=catchimage. The manipulation leads to unrestricted upload. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. VDB-227230 is the identifier assigned to this vulnerability.

- [https://github.com/chihyeonwon/2023-2245](https://github.com/chihyeonwon/2023-2245) :  ![starts](https://img.shields.io/github/stars/chihyeonwon/2023-2245.svg) ![forks](https://img.shields.io/github/forks/chihyeonwon/2023-2245.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/0xc4t/CVE-2021-41773](https://github.com/0xc4t/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/0xc4t/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/0xc4t/CVE-2021-41773.svg)


## CVE-2021-30862
 A validation issue was addressed with improved input sanitization. This issue is fixed in iTunes U 3.8.3. Processing a maliciously crafted URL may lead to arbitrary javascript code execution.

- [https://github.com/Umarovm/CVE-2021-30862](https://github.com/Umarovm/CVE-2021-30862) :  ![starts](https://img.shields.io/github/stars/Umarovm/CVE-2021-30862.svg) ![forks](https://img.shields.io/github/forks/Umarovm/CVE-2021-30862.svg)


## CVE-2018-25031
 Swagger UI 4.1.2 and earlier could allow a remote attacker to conduct spoofing attacks. By persuading a victim to open a crafted URL, an attacker could exploit this vulnerability to display remote OpenAPI definitions. Note: This was originally claimed to be resolved in 4.1.3. However, third parties have indicated this is not resolved in 4.1.3 and even occurs in that version and possibly others.

- [https://github.com/MMAKINGDOM/CVE-2018-25031](https://github.com/MMAKINGDOM/CVE-2018-25031) :  ![starts](https://img.shields.io/github/stars/MMAKINGDOM/CVE-2018-25031.svg) ![forks](https://img.shields.io/github/forks/MMAKINGDOM/CVE-2018-25031.svg)

