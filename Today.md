# Update 2026-06-09
## CVE-2026-42945
 NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module. This vulnerability exists when the rewrite directive is followed by a rewrite, if, or set directive and an unnamed Perl-Compatible Regular Expression (PCRE) capture (for example, $1, $2) with a replacement string that includes a question mark (?). An unauthenticated attacker along with conditions beyond its control can exploit this vulnerability by sending crafted HTTP requests. This may cause a heap buffer overflow in the NGINX worker process leading to a restart. Additionally, attackers can execute code on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/limo57640-crypto/nginx-rift-detector](https://github.com/limo57640-crypto/nginx-rift-detector) :  ![starts](https://img.shields.io/github/stars/limo57640-crypto/nginx-rift-detector.svg) ![forks](https://img.shields.io/github/forks/limo57640-crypto/nginx-rift-detector.svg)


## CVE-2026-41940
 cPanel and WHM versions after 11.40 contain an authentication bypass vulnerability in the login flow that allows unauthenticated remote attackers to gain unauthorized access to the control panel.

- [https://github.com/tc4dy/CVE-2026-41940-PoC-Exploit](https://github.com/tc4dy/CVE-2026-41940-PoC-Exploit) :  ![starts](https://img.shields.io/github/stars/tc4dy/CVE-2026-41940-PoC-Exploit.svg) ![forks](https://img.shields.io/github/forks/tc4dy/CVE-2026-41940-PoC-Exploit.svg)
- [https://github.com/limo57640-crypto/cpanel-cve-41940-detector](https://github.com/limo57640-crypto/cpanel-cve-41940-detector) :  ![starts](https://img.shields.io/github/stars/limo57640-crypto/cpanel-cve-41940-detector.svg) ![forks](https://img.shields.io/github/forks/limo57640-crypto/cpanel-cve-41940-detector.svg)


## CVE-2026-34040
 Moby is an open source container framework. Prior to version 29.3.1, a security vulnerability has been detected that allows attackers to bypass authorization plugins (AuthZ). This issue has been patched in version 29.3.1.

- [https://github.com/m0nk3ygod/CVE-2026-34040-PoC](https://github.com/m0nk3ygod/CVE-2026-34040-PoC) :  ![starts](https://img.shields.io/github/stars/m0nk3ygod/CVE-2026-34040-PoC.svg) ![forks](https://img.shields.io/github/forks/m0nk3ygod/CVE-2026-34040-PoC.svg)


## CVE-2026-23479
 Redis is an in-memory data structure store. In redis-server from 7.2.0 until 8.6.3, the unblock client flow does not handle an error return from `processCommandAndResetClient` when re-executing a blocked command. If a blocked client is evicted during this flow, an authenticated attacker can trigger a use-after-free that may lead to remote code execution. This has been patched in version 8.6.3.

- [https://github.com/daniel30padd/CVE-2026-23479](https://github.com/daniel30padd/CVE-2026-23479) :  ![starts](https://img.shields.io/github/stars/daniel30padd/CVE-2026-23479.svg) ![forks](https://img.shields.io/github/forks/daniel30padd/CVE-2026-23479.svg)


## CVE-2026-10580
 The Hippoo Mobile App for WooCommerce plugin for WordPress is vulnerable to Authentication Bypass leading to Administrator Account Takeover in all versions up to and including 1.9.4. This is due to a logic conflation in HippooPermissions::get_user_permissions(), which returns the same null sentinel for both administrators and unauthenticated visitors — a value that HippooPermissions::has_role_access() unconditionally interprets as full administrator access — causing override_extension_permission_callback() to assign __return_true as the permission callback for every WordPress and WooCommerce REST route cloned under /wc-hippoo/v1/ext/ by HippooControllerWithAuth::re_register_external_routes(), while the block_unauthorized_access() pre-dispatch guard fails to block unauthenticated users for the same reason. This makes it possible for unauthenticated attackers to invoke any core REST endpoint without credentials — most critically, sending a POST request to /wc-hippoo/v1/ext/wp/v2/users/id with a {"password":"new_password"} body to reset the password of any WordPress user, including the site administrator, and gain full administrative control of the site.

- [https://github.com/Polosss/By-Poloss..-..CVE-2026-10580](https://github.com/Polosss/By-Poloss..-..CVE-2026-10580) :  ![starts](https://img.shields.io/github/stars/Polosss/By-Poloss..-..CVE-2026-10580.svg) ![forks](https://img.shields.io/github/forks/Polosss/By-Poloss..-..CVE-2026-10580.svg)


## CVE-2026-9082
This issue affects Drupal core: from 8.9.0 before 10.4.10, from 10.5.0 before 10.5.10, from 10.6.0 before 10.6.9, from 11.0.0 before 11.1.10, from 11.2.0 before 11.2.12, from 11.3.0 before 11.3.10.

- [https://github.com/11romain/CVE-2026-9082](https://github.com/11romain/CVE-2026-9082) :  ![starts](https://img.shields.io/github/stars/11romain/CVE-2026-9082.svg) ![forks](https://img.shields.io/github/forks/11romain/CVE-2026-9082.svg)


## CVE-2026-4480
substitution character without escaping shell meta characters. A remote attacker could exploit this vulnerability by sending a specially crafted print job description that contains unescaped shell characters. This could lead to remote code execution on the affected system.

- [https://github.com/0xBlackash/CVE-2026-4480](https://github.com/0xBlackash/CVE-2026-4480) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-4480.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-4480.svg)
- [https://github.com/robinxiang/CVE-2026-4480](https://github.com/robinxiang/CVE-2026-4480) :  ![starts](https://img.shields.io/github/stars/robinxiang/CVE-2026-4480.svg) ![forks](https://img.shields.io/github/forks/robinxiang/CVE-2026-4480.svg)


## CVE-2026-1492
 The User Registration & Membership – Custom Registration Form Builder, Custom Login Form, User Profile, Content Restriction & Membership Plugin plugin for WordPress is vulnerable to improper privilege management in all versions up to, and including, 5.1.2. This is due to the plugin accepting a user-supplied role during membership registration without properly enforcing a server-side allowlist. This makes it possible for unauthenticated attackers to create administrator accounts by supplying a role value during membership registration.

- [https://github.com/limo57640-crypto/wp-user-registration-vuln-checker](https://github.com/limo57640-crypto/wp-user-registration-vuln-checker) :  ![starts](https://img.shields.io/github/stars/limo57640-crypto/wp-user-registration-vuln-checker.svg) ![forks](https://img.shields.io/github/forks/limo57640-crypto/wp-user-registration-vuln-checker.svg)


## CVE-2026-1151
 A weakness has been identified in technical-laohu mpay up to 1.2.4. The affected element is an unknown function of the component User Center. This manipulation of the argument Nickname causes cross site scripting. The attack may be initiated remotely. The exploit has been made available to the public and could be used for attacks.

- [https://github.com/Xmyronn/CVE-2026-11518-XSS](https://github.com/Xmyronn/CVE-2026-11518-XSS) :  ![starts](https://img.shields.io/github/stars/Xmyronn/CVE-2026-11518-XSS.svg) ![forks](https://img.shields.io/github/forks/Xmyronn/CVE-2026-11518-XSS.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg)


## CVE-2025-57819
 FreePBX is an open-source web-based graphical user interface. FreePBX 15, 16, and 17 endpoints are vulnerable due to insufficiently sanitized user-supplied data allowing unauthenticated access to FreePBX Administrator leading to arbitrary database manipulation and remote code execution. This issue has been patched in endpoint versions 15.0.66, 16.0.89, and 17.0.3.

- [https://github.com/jf-gondim/freepbx-endpoint-sqli-rce](https://github.com/jf-gondim/freepbx-endpoint-sqli-rce) :  ![starts](https://img.shields.io/github/stars/jf-gondim/freepbx-endpoint-sqli-rce.svg) ![forks](https://img.shields.io/github/forks/jf-gondim/freepbx-endpoint-sqli-rce.svg)


## CVE-2024-46671
 An Incorrect User Management vulnerability [CWE-286] in FortiWeb version 7.6.2 and below, version 7.4.6 and below, version 7.2.10 and below, version 7.0.11 and below widgets dashboard may allow an authenticated attacker with at least read-only admin permission to perform operations on the dashboard of other administrators via crafted requests.

- [https://github.com/ixec-lab/fortinet-cve-2024-46671](https://github.com/ixec-lab/fortinet-cve-2024-46671) :  ![starts](https://img.shields.io/github/stars/ixec-lab/fortinet-cve-2024-46671.svg) ![forks](https://img.shields.io/github/forks/ixec-lab/fortinet-cve-2024-46671.svg)


## CVE-2024-29973
The command injection vulnerability in the “setCookie” parameter in Zyxel NAS326 firmware versions before V5.21(AAZF.17)C0 and NAS542 firmware versions before V5.21(ABAG.14)C0 could allow an unauthenticated attacker to execute some operating system (OS) commands by sending a crafted HTTP POST request.

- [https://github.com/intel365/CVE-2024-29973](https://github.com/intel365/CVE-2024-29973) :  ![starts](https://img.shields.io/github/stars/intel365/CVE-2024-29973.svg) ![forks](https://img.shields.io/github/forks/intel365/CVE-2024-29973.svg)


## CVE-2024-24919
 Potentially allowing an attacker to read certain information on Check Point Security Gateways once connected to the internet and enabled with remote Access VPN or Mobile Access Software Blades. A Security fix that mitigates this vulnerability is available.

- [https://github.com/intel365/CVE-2024-24919](https://github.com/intel365/CVE-2024-24919) :  ![starts](https://img.shields.io/github/stars/intel365/CVE-2024-24919.svg) ![forks](https://img.shields.io/github/forks/intel365/CVE-2024-24919.svg)


## CVE-2024-7593
 Incorrect implementation of an authentication algorithm in Ivanti vTM other than versions 22.2R1 or 22.7R2 allows a remote unauthenticated attacker to bypass authentication of the admin panel.

- [https://github.com/intel365/CVE-2024-7593](https://github.com/intel365/CVE-2024-7593) :  ![starts](https://img.shields.io/github/stars/intel365/CVE-2024-7593.svg) ![forks](https://img.shields.io/github/forks/intel365/CVE-2024-7593.svg)


## CVE-2024-2876
 The Email Subscribers by Icegram Express – Email Marketing, Newsletters, Automation for WordPress & WooCommerce plugin for WordPress is vulnerable to SQL Injection via the 'run' function of the 'IG_ES_Subscribers_Query' class in all versions up to, and including, 5.7.14 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/intel365/CVE-2024-2876](https://github.com/intel365/CVE-2024-2876) :  ![starts](https://img.shields.io/github/stars/intel365/CVE-2024-2876.svg) ![forks](https://img.shields.io/github/forks/intel365/CVE-2024-2876.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/im2sinister/CVE-2021-41773](https://github.com/im2sinister/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/im2sinister/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/im2sinister/CVE-2021-41773.svg)


## CVE-2020-17103
 Windows Cloud Files Mini Filter Driver Elevation of Privilege Vulnerability

- [https://github.com/0xBlackash/CVE-2020-17103](https://github.com/0xBlackash/CVE-2020-17103) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2020-17103.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2020-17103.svg)


## CVE-2018-16763
 FUEL CMS 1.4.1 allows PHP Code Evaluation via the pages/select/ filter parameter or the preview/ data parameter. This can lead to Pre-Auth Remote Code Execution.

- [https://github.com/SOME-1HING/CVE-2018-16763](https://github.com/SOME-1HING/CVE-2018-16763) :  ![starts](https://img.shields.io/github/stars/SOME-1HING/CVE-2018-16763.svg) ![forks](https://img.shields.io/github/forks/SOME-1HING/CVE-2018-16763.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock."  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/im2sinister/CVE-2014-6271](https://github.com/im2sinister/CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/im2sinister/CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/im2sinister/CVE-2014-6271.svg)


## CVE-2008-1930
 The cookie authentication method in WordPress 2.5 relies on a hash of a concatenated string containing USERNAME and EXPIRY_TIME, which allows remote attackers to forge cookies by registering a username that results in the same concatenated string, as demonstrated by registering usernames beginning with "admin" to obtain administrator privileges, aka a "cryptographic splicing" issue.  NOTE: this vulnerability exists because of an incomplete fix for CVE-2007-6013.

- [https://github.com/HeisenbergH4X/CVE-2008-1930](https://github.com/HeisenbergH4X/CVE-2008-1930) :  ![starts](https://img.shields.io/github/stars/HeisenbergH4X/CVE-2008-1930.svg) ![forks](https://img.shields.io/github/forks/HeisenbergH4X/CVE-2008-1930.svg)

