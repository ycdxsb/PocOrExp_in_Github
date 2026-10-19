# Update 2026-10-19
## CVE-2026-111823
 Mage OSS through 0.9.80 before 76c4f46 can proceed with session creation upon encountering an unknown OAuth provider.

- [https://github.com/murrez/CVE-2026-111823](https://github.com/murrez/CVE-2026-111823) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-111823.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-111823.svg)


## CVE-2026-104850
 MCP TypeScript SDK is the official TypeScript SDK for Model Context Protocol servers and clients. Starting in version 1.12.0 and prior to versions 1.31.0 and 2.2.0, the SDK's OAuth client support let the MCP server a client connected to decide which authorization server received the client's OAuth credentials. Stored and pre-provisioned credentials were not bound to the authorization server they belong to. A malicious or compromised MCP server could name its own authorization server in its protected resource metadata. Without any user interaction, the client would send that server the `refresh_token` and `client_secret` stored from an earlier sign-in (1.x), or the configured `client_secret` or signed assertion of a bundled non-interactive provider (1.x and 2.x). Only those applications that use the SDK as an MCP client over HTTP with an `authProvider`: your own `OAuthClientProvider`, or the bundled `ClientCredentialsProvider`, `PrivateKeyJwtProvider`, `StaticPrivateKeyJwtProvider` or (2.x) `CrossAppAccessProvider` and that may connect to an MCP server the owners does not fully trust while holding credentials for a legitimate authorization server are affected. `@modelcontextprotocol/sdk` 1.31.0 (1.x) and `@modelcontextprotocol/client` 2.2.0 (2.x) patch the issue. A workaround for those who cannot upgrade is available. 2.0.0 and 2.1.0 already accept `expectedIssuer`. On 1.x, the only workaround is to connect OAuth-enabled clients only to MCP servers you trust.

- [https://github.com/Iceman2050/mcp-oauth-discovery-prober](https://github.com/Iceman2050/mcp-oauth-discovery-prober) :  ![starts](https://img.shields.io/github/stars/Iceman2050/mcp-oauth-discovery-prober.svg) ![forks](https://img.shields.io/github/forks/Iceman2050/mcp-oauth-discovery-prober.svg)


## CVE-2026-104736
 The LearnPress plugin for WordPress is vulnerable to PHP Object Injection in versions up to, and including, 4.4.10 via deserialization of untrusted input from the 'checkout-email' request parameter during the checkout AJAX action. The value is passed through sanitize_text_field(), which does not strip serialized object syntax, then stored in the LearnPress session table and later fed to LP_Helper::maybe_unserialize() → unserialize() (without an allowed_classes restriction) by LP_Session_Handler::get() on subsequent requests. This makes it possible for unauthenticated attackers to inject a PHP Object.

- [https://github.com/BIBILZERODAY/CVE-2026-104736---Proof-of-Concept-PoC-Exploit-Details](https://github.com/BIBILZERODAY/CVE-2026-104736---Proof-of-Concept-PoC-Exploit-Details) :  ![starts](https://img.shields.io/github/stars/BIBILZERODAY/CVE-2026-104736---Proof-of-Concept-PoC-Exploit-Details.svg) ![forks](https://img.shields.io/github/forks/BIBILZERODAY/CVE-2026-104736---Proof-of-Concept-PoC-Exploit-Details.svg)


## CVE-2026-99999
A more complete validation at input is forthcoming, but needs more work.

- [https://github.com/PeronGH/CVE-2026-99999](https://github.com/PeronGH/CVE-2026-99999) :  ![starts](https://img.shields.io/github/stars/PeronGH/CVE-2026-99999.svg) ![forks](https://img.shields.io/github/forks/PeronGH/CVE-2026-99999.svg)
- [https://github.com/Quaerendir/cve-2026-99999-audit](https://github.com/Quaerendir/cve-2026-99999-audit) :  ![starts](https://img.shields.io/github/stars/Quaerendir/cve-2026-99999-audit.svg) ![forks](https://img.shields.io/github/forks/Quaerendir/cve-2026-99999-audit.svg)


## CVE-2026-97229
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 19.2 before 19.2.8, 19.3 before 19.3.5, and 19.4 before 19.4.2 that, under certain conditions, could have allowed an unauthenticated user to execute arbitrary code on the GitLab server via a specially crafted regular expression in a CI/CD configuration, due to insufficient regular expression validation.

- [https://github.com/gandli/cve-2026-97229-lab](https://github.com/gandli/cve-2026-97229-lab) :  ![starts](https://img.shields.io/github/stars/gandli/cve-2026-97229-lab.svg) ![forks](https://img.shields.io/github/forks/gandli/cve-2026-97229-lab.svg)


## CVE-2026-96889
 A flaw was found in librsvg. When processing an SVG document containing nested XML inclusions (Xincludes) with duplicate entity declarations, a use-after-free error can occur. This vulnerability arises because the library incorrectly frees an XML entity that is still in use by the parser. An attacker could potentially exploit this to cause a denial of service or execute arbitrary code.

- [https://github.com/pauleprichna/cybersecurity](https://github.com/pauleprichna/cybersecurity) :  ![starts](https://img.shields.io/github/stars/pauleprichna/cybersecurity.svg) ![forks](https://img.shields.io/github/forks/pauleprichna/cybersecurity.svg)


## CVE-2026-94169
 Improper Control of Generation of Code ('Code Injection') vulnerability in Theme-one The Grid the-grid allows Command Injection.This issue affects The Grid: from n/a through 2.8.1.

- [https://github.com/kize7/CVE-2026-94169](https://github.com/kize7/CVE-2026-94169) :  ![starts](https://img.shields.io/github/stars/kize7/CVE-2026-94169.svg) ![forks](https://img.shields.io/github/forks/kize7/CVE-2026-94169.svg)


## CVE-2026-89282
 The Apache Lounge Windows distribution of Apache HTTP Server build contains an insecure installation directory permissions vulnerability through its default install directory on C:\, which inherits write access for Authenticated Users.

- [https://github.com/dorkerdevil/CVE-2026-89282](https://github.com/dorkerdevil/CVE-2026-89282) :  ![starts](https://img.shields.io/github/stars/dorkerdevil/CVE-2026-89282.svg) ![forks](https://img.shields.io/github/forks/dorkerdevil/CVE-2026-89282.svg)


## CVE-2026-74580
addresses are pushed back through iotlb_access_ok()'s slow path.

- [https://github.com/V01DL1NG/vghost-watch](https://github.com/V01DL1NG/vghost-watch) :  ![starts](https://img.shields.io/github/stars/V01DL1NG/vghost-watch.svg) ![forks](https://img.shields.io/github/forks/V01DL1NG/vghost-watch.svg)


## CVE-2026-67279
 RouterOS SSH enters the connection protocol after a client-requested rekey even though user authentication was never attempted, allowing an unauthenticated client to open a session channel and send an exec request. On affected builds the server dispatches the command, enabling unauthenticated creation, overwrite, and reconstruction of files in the RouterOS managed file namespace, including support files containing configuration and diagnostic data.This issue was fixed in versions: 6.49.21 (Long-term), 7.23.4 (Long-term) and 7.24.2 (Stable)

- [https://github.com/GoldAden/mikrotrick-verifier](https://github.com/GoldAden/mikrotrick-verifier) :  ![starts](https://img.shields.io/github/stars/GoldAden/mikrotrick-verifier.svg) ![forks](https://img.shields.io/github/forks/GoldAden/mikrotrick-verifier.svg)


## CVE-2026-64560
---truncated---

- [https://github.com/ChaYeWuu/prague-CVE-2026-64560-OS4.0](https://github.com/ChaYeWuu/prague-CVE-2026-64560-OS4.0) :  ![starts](https://img.shields.io/github/stars/ChaYeWuu/prague-CVE-2026-64560-OS4.0.svg) ![forks](https://img.shields.io/github/forks/ChaYeWuu/prague-CVE-2026-64560-OS4.0.svg)
- [https://github.com/imkidz0/exploit-CVE-2026-64560](https://github.com/imkidz0/exploit-CVE-2026-64560) :  ![starts](https://img.shields.io/github/stars/imkidz0/exploit-CVE-2026-64560.svg) ![forks](https://img.shields.io/github/forks/imkidz0/exploit-CVE-2026-64560.svg)
- [https://github.com/totsiaw/cve-2026-64560-rmx6699](https://github.com/totsiaw/cve-2026-64560-rmx6699) :  ![starts](https://img.shields.io/github/stars/totsiaw/cve-2026-64560-rmx6699.svg) ![forks](https://img.shields.io/github/forks/totsiaw/cve-2026-64560-rmx6699.svg)
- [https://github.com/maosasagawa/pmx110-cve-2026-64560](https://github.com/maosasagawa/pmx110-cve-2026-64560) :  ![starts](https://img.shields.io/github/stars/maosasagawa/pmx110-cve-2026-64560.svg) ![forks](https://img.shields.io/github/forks/maosasagawa/pmx110-cve-2026-64560.svg)


## CVE-2026-50229
Users are recommended to upgrade to version 11.0.23, 10.1.56 or 9.0.119, which fix the issue.

- [https://github.com/flvzx/CVE-2026-50229](https://github.com/flvzx/CVE-2026-50229) :  ![starts](https://img.shields.io/github/stars/flvzx/CVE-2026-50229.svg) ![forks](https://img.shields.io/github/forks/flvzx/CVE-2026-50229.svg)


## CVE-2026-48907
 A vulnerability in the JCE editor extension for Joomla allows the creation of new editor profiles for unauthenticated users, ultimately resulting in PHP code upload and execution.

- [https://github.com/0xCyp1337/CVE-2026-48907-RCE](https://github.com/0xCyp1337/CVE-2026-48907-RCE) :  ![starts](https://img.shields.io/github/stars/0xCyp1337/CVE-2026-48907-RCE.svg) ![forks](https://img.shields.io/github/forks/0xCyp1337/CVE-2026-48907-RCE.svg)


## CVE-2026-27280
 DNG SDK versions 1.7.1 2471 and earlier are affected by an out-of-bounds write vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/Nehust/CVE-2026-27280](https://github.com/Nehust/CVE-2026-27280) :  ![starts](https://img.shields.io/github/stars/Nehust/CVE-2026-27280.svg) ![forks](https://img.shields.io/github/forks/Nehust/CVE-2026-27280.svg)


## CVE-2026-11143
 Out of bounds read in Extensions in Google Chrome on Linux prior to 149.0.7827.53 allowed an attacker who convinced a user to install a malicious extension to obtain potentially sensitive information from process memory via a crafted Chrome Extension. (Chromium security severity: Medium)

- [https://github.com/ulvigulmaliyev/CVE-2026-111437-Denial-of-Service-Advisory-Technical-Report](https://github.com/ulvigulmaliyev/CVE-2026-111437-Denial-of-Service-Advisory-Technical-Report) :  ![starts](https://img.shields.io/github/stars/ulvigulmaliyev/CVE-2026-111437-Denial-of-Service-Advisory-Technical-Report.svg) ![forks](https://img.shields.io/github/forks/ulvigulmaliyev/CVE-2026-111437-Denial-of-Service-Advisory-Technical-Report.svg)


## CVE-2026-10708
 This vulnerability enables large‑scale data harvesting without requiring app‑specific secrets. A single request to a minimal leaderboard component may return user records containing emails, UUIDs, and custom fields. The combination of wildcard CORS behavior, long‑lived twenty‑day JWTs, and the absence of token revocation allows attackers to gather sensitive personal information from any Adalo application.

- [https://github.com/Primandito/CVE-2026-107083](https://github.com/Primandito/CVE-2026-107083) :  ![starts](https://img.shields.io/github/stars/Primandito/CVE-2026-107083.svg) ![forks](https://img.shields.io/github/forks/Primandito/CVE-2026-107083.svg)
- [https://github.com/Primandito/CVE-2026-107084](https://github.com/Primandito/CVE-2026-107084) :  ![starts](https://img.shields.io/github/stars/Primandito/CVE-2026-107084.svg) ![forks](https://img.shields.io/github/forks/Primandito/CVE-2026-107084.svg)
- [https://github.com/Primandito/CVE-2026-107082](https://github.com/Primandito/CVE-2026-107082) :  ![starts](https://img.shields.io/github/stars/Primandito/CVE-2026-107082.svg) ![forks](https://img.shields.io/github/forks/Primandito/CVE-2026-107082.svg)


## CVE-2026-8933
Due to a flaw in how privilege boundaries or security sandboxes are initialized when the binary runs under limited ambient capabilities, a local, unprivileged attacker can exploit this behavior to bypass intended restrictions and execute arbitrary code. Successful exploitation allows the local user to elevate their privileges to full root authority.

- [https://github.com/songzzzz/CVE-2026-8933](https://github.com/songzzzz/CVE-2026-8933) :  ![starts](https://img.shields.io/github/stars/songzzzz/CVE-2026-8933.svg) ![forks](https://img.shields.io/github/forks/songzzzz/CVE-2026-8933.svg)


## CVE-2026-5399
 The Redux Framework plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the Slider field in User Profile settings in versions up to and including 4.5.13.1. This is due to insufficient input sanitization in the user_meta_save() function (which only sanitizes array values, not scalar values) and improper output escaping in the Redux_Slider::render() method, which outputs slider values into unquoted HTML attributes. The vulnerability also exploits the fact that the clean_default() method only casts values to numeric types when they are empty or out of bounds, allowing malicious strings like '1 tabindex=0 autofocus onfocus=alert(1) x=' to pass validation through PHP's loose type comparison. This makes it possible for authenticated attackers, with Subscriber-level access and above, to inject arbitrary web scripts into their user profile that will execute whenever an Administrator navigates to view the attacker's profile page.

- [https://github.com/SaiTeja-Erukude/CVE-2026-53995-mlflow-path-traversal](https://github.com/SaiTeja-Erukude/CVE-2026-53995-mlflow-path-traversal) :  ![starts](https://img.shields.io/github/stars/SaiTeja-Erukude/CVE-2026-53995-mlflow-path-traversal.svg) ![forks](https://img.shields.io/github/forks/SaiTeja-Erukude/CVE-2026-53995-mlflow-path-traversal.svg)


## CVE-2026-3883
 This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.

- [https://github.com/pawelskokowski/CVE-2026-38838](https://github.com/pawelskokowski/CVE-2026-38838) :  ![starts](https://img.shields.io/github/stars/pawelskokowski/CVE-2026-38838.svg) ![forks](https://img.shields.io/github/forks/pawelskokowski/CVE-2026-38838.svg)


## CVE-2026-3143
 The Total Upkeep – WordPress Backup Plugin plus Restore & Migrate by BoldGrid plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'wp_ajax_cli_cancel' function in all versions up to, and including, 1.17.1. This makes it possible for unauthenticated attackers to cancel a pending rollback, potentially preventing a WordPress installation from automatically reverting a failed update.

- [https://github.com/SunL0w/PATCH-CVE-2026-31431-Ubuntu_Debian](https://github.com/SunL0w/PATCH-CVE-2026-31431-Ubuntu_Debian) :  ![starts](https://img.shields.io/github/stars/SunL0w/PATCH-CVE-2026-31431-Ubuntu_Debian.svg) ![forks](https://img.shields.io/github/forks/SunL0w/PATCH-CVE-2026-31431-Ubuntu_Debian.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)


## CVE-2025-54068
 Livewire is a full-stack framework for Laravel. In Livewire v3 up to and including v3.6.3, a vulnerability allows unauthenticated attackers to achieve remote command execution in specific scenarios. The issue stems from how certain component property updates are hydrated. This vulnerability is unique to Livewire v3 and does not affect prior major versions. Exploitation requires a component to be mounted and configured in a particular way, but does not require authentication or user interaction. This issue has been patched in Livewire v3.6.4. All users are strongly encouraged to upgrade to this version or later as soon as possible. No known workarounds are available.

- [https://github.com/GustavoLopreto/cve-2025-54068-vuln-intel](https://github.com/GustavoLopreto/cve-2025-54068-vuln-intel) :  ![starts](https://img.shields.io/github/stars/GustavoLopreto/cve-2025-54068-vuln-intel.svg) ![forks](https://img.shields.io/github/forks/GustavoLopreto/cve-2025-54068-vuln-intel.svg)


## CVE-2025-49113
 Roundcube Webmail before 1.5.10 and 1.6.x before 1.6.11 allows remote code execution by authenticated users because the _from parameter in a URL is not validated in program/actions/settings/upload.php, leading to PHP Object Deserialization.

- [https://github.com/rank03031/CVE-2025-49113-CTF](https://github.com/rank03031/CVE-2025-49113-CTF) :  ![starts](https://img.shields.io/github/stars/rank03031/CVE-2025-49113-CTF.svg) ![forks](https://img.shields.io/github/forks/rank03031/CVE-2025-49113-CTF.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg)


## CVE-2025-1122
Bypass operating system verification via exploiting the NV_Read functionality during the Challenge-Response process.

- [https://github.com/jenson8161/exploit-docs](https://github.com/jenson8161/exploit-docs) :  ![starts](https://img.shields.io/github/stars/jenson8161/exploit-docs.svg) ![forks](https://img.shields.io/github/forks/jenson8161/exploit-docs.svg)
- [https://github.com/jenson8161/RMASmoke-v2](https://github.com/jenson8161/RMASmoke-v2) :  ![starts](https://img.shields.io/github/stars/jenson8161/RMASmoke-v2.svg) ![forks](https://img.shields.io/github/forks/jenson8161/RMASmoke-v2.svg)


## CVE-2024-38475
Substitutions in server context that use a backreferences or variables as the first segment of the substitution are affected.  Some unsafe RewiteRules will be broken by this change and the rewrite flag "UnsafePrefixStat" can be used to opt back in once ensuring the substitution is appropriately constrained.

- [https://github.com/akabul0us/apache_poc](https://github.com/akabul0us/apache_poc) :  ![starts](https://img.shields.io/github/stars/akabul0us/apache_poc.svg) ![forks](https://img.shields.io/github/forks/akabul0us/apache_poc.svg)


## CVE-2024-32507
 Incorrect Privilege Assignment vulnerability in Hamid Alinia Login with phone number login-with-phone-number.This issue affects Login with phone number: from n/a through = 1.7.16.

- [https://github.com/4minx/CVE-2024-32507](https://github.com/4minx/CVE-2024-32507) :  ![starts](https://img.shields.io/github/stars/4minx/CVE-2024-32507.svg) ![forks](https://img.shields.io/github/forks/4minx/CVE-2024-32507.svg)


## CVE-2023-29357
 Microsoft SharePoint Server Elevation of Privilege Vulnerability

- [https://github.com/Zedocun/Sharepoint-cve-2023-29357-incident-response](https://github.com/Zedocun/Sharepoint-cve-2023-29357-incident-response) :  ![starts](https://img.shields.io/github/stars/Zedocun/Sharepoint-cve-2023-29357-incident-response.svg) ![forks](https://img.shields.io/github/forks/Zedocun/Sharepoint-cve-2023-29357-incident-response.svg)


## CVE-2022-23305
 By design, the JDBCAppender in Log4j 1.2.x accepts an SQL statement as a configuration parameter where the values to be inserted are converters from PatternLayout. The message converter, %m, is likely to always be included. This allows attackers to manipulate the SQL by entering crafted strings into input fields or headers of an application that are logged allowing unintended SQL queries to be executed. Note this issue only affects Log4j 1.x when specifically configured to use the JDBCAppender, which is not the default. Beginning in version 2.0-beta8, the JDBCAppender was re-introduced with proper support for parameterized SQL queries and further customization over the columns written to in logs. Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the previous versions.

- [https://github.com/hoor113/CVE-2022-23305-Demo-and-Whitebox-Report](https://github.com/hoor113/CVE-2022-23305-Demo-and-Whitebox-Report) :  ![starts](https://img.shields.io/github/stars/hoor113/CVE-2022-23305-Demo-and-Whitebox-Report.svg) ![forks](https://img.shields.io/github/forks/hoor113/CVE-2022-23305-Demo-and-Whitebox-Report.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe-](https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe-) :  ![starts](https://img.shields.io/github/stars/Greetdawn/CVE-2022-0847-DirtyPipe-.svg) ![forks](https://img.shields.io/github/forks/Greetdawn/CVE-2022-0847-DirtyPipe-.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/0xrogg/CVE-2021-41773](https://github.com/0xrogg/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/0xrogg/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/0xrogg/CVE-2021-41773.svg)


## CVE-2021-34527
Note that the security updates released on and after July 6, 2021 contain protections for CVE-2021-1675 and the additional remote code execution exploit in the Windows Print Spooler service known as “PrintNightmare”, documented in CVE-2021-34527.

- [https://github.com/s1kh/Vulnerability-Analysis-and-Mitigation](https://github.com/s1kh/Vulnerability-Analysis-and-Mitigation) :  ![starts](https://img.shields.io/github/stars/s1kh/Vulnerability-Analysis-and-Mitigation.svg) ![forks](https://img.shields.io/github/forks/s1kh/Vulnerability-Analysis-and-Mitigation.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/asd58584388/CVE-2021-44228](https://github.com/asd58584388/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/asd58584388/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/asd58584388/CVE-2021-44228.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/mah4nzfr/CVE-2021-41773](https://github.com/mah4nzfr/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/mah4nzfr/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mah4nzfr/CVE-2021-41773.svg)


## CVE-2017-5638
 The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.

- [https://github.com/s1kh/Vulnerability-Analysis-and-Mitigation](https://github.com/s1kh/Vulnerability-Analysis-and-Mitigation) :  ![starts](https://img.shields.io/github/stars/s1kh/Vulnerability-Analysis-and-Mitigation.svg) ![forks](https://img.shields.io/github/forks/s1kh/Vulnerability-Analysis-and-Mitigation.svg)


## CVE-2015-2291
 (1) IQVW32.sys before 1.3.1.0 and (2) IQVW64.sys before 1.3.1.0 in the Intel Ethernet diagnostics driver for Windows allows local users to cause a denial of service or possibly execute arbitrary code with kernel privileges via a crafted (a) 0x80862013, (b) 0x8086200B, (c) 0x8086200F, or (d) 0x80862007 IOCTL call.

- [https://github.com/antoniorauso/NalCaller](https://github.com/antoniorauso/NalCaller) :  ![starts](https://img.shields.io/github/stars/antoniorauso/NalCaller.svg) ![forks](https://img.shields.io/github/forks/antoniorauso/NalCaller.svg)

