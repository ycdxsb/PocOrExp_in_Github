# Update 2026-10-05
## CVE-2026-105030
 Kener 4.0.0 before 4.1.6 contains an information disclosure vulnerability that allows unauthenticated attackers to retrieve hidden or inactive monitor data by querying dashboard API handlers lacking visibility filters. Attackers can supply a known or guessed monitor tag to endpoints such as monitor-bar and monitor-latency-chart to obtain names, descriptions, status, uptime history and latency.

- [https://github.com/asvorg/CVE-2026-105030-poc](https://github.com/asvorg/CVE-2026-105030-poc) :  ![starts](https://img.shields.io/github/stars/asvorg/CVE-2026-105030-poc.svg) ![forks](https://img.shields.io/github/forks/asvorg/CVE-2026-105030-poc.svg)


## CVE-2026-103956
To remediate this issue, users should upgrade to version 1.6.1 or later.

- [https://github.com/abraxas/cve-2026-103956-loom-unauth](https://github.com/abraxas/cve-2026-103956-loom-unauth) :  ![starts](https://img.shields.io/github/stars/abraxas/cve-2026-103956-loom-unauth.svg) ![forks](https://img.shields.io/github/forks/abraxas/cve-2026-103956-loom-unauth.svg)


## CVE-2026-103648
 Path traversal in image-downloader 4.3.0 allows an attacker who can control the download URL to cause downloaded response data to be written outside the configured destination directory.

- [https://github.com/EterNullSec/CVE-2026-103648](https://github.com/EterNullSec/CVE-2026-103648) :  ![starts](https://img.shields.io/github/stars/EterNullSec/CVE-2026-103648.svg) ![forks](https://img.shields.io/github/forks/EterNullSec/CVE-2026-103648.svg)


## CVE-2026-92592
 Craft CMS 4.8.0 through 4.18.5 and 5.0.0 through 5.10.12 sign an authenticated user's attacker-controlled license-shun cookie with the same key and format used to validate signed redirect parameters, because the HMAC signature is not bound to its purpose (Yii's cookieValidationKey is derived from the same Craft securityKey used for signed request parameters). An authenticated, non-administrator user (Control Panel access is not required) can set the cookie via the license-shun endpoint and transplant the signed envelope into the redirect parameter; on a successful login, Craft validates the signature and renders the authenticated bytes as an unsandboxed Twig template, where Twig's map filter accepts a string callback and allows PHP system() to execute arbitrary operating-system commands as the web-server user. Exploitation requires an account using password authentication without active 2FA, the default request configuration, and availability of PHP system(). The issue is fixed in 4.18.6 and 5.10.13.

- [https://github.com/godylockz/CVE-2026-92592](https://github.com/godylockz/CVE-2026-92592) :  ![starts](https://img.shields.io/github/stars/godylockz/CVE-2026-92592.svg) ![forks](https://img.shields.io/github/forks/godylockz/CVE-2026-92592.svg)


## CVE-2026-90970
 GitLab has remediated a vulnerability in the GitLab AI Gateway component affecting all versions of the AI Gateway from 18.1.6 before 19.2.4, 19.3 before 19.3.2, and 19.4 before 19.4.1 that, under certain conditions, could have allowed an authenticated user with Duo Agent Platform access to escape the prompt template sandbox via a specially crafted flow configuration, resulting in arbitrary command execution on the AI Gateway.

- [https://github.com/techupdate24/gitlab-ai-gateway-cve-2026-90970](https://github.com/techupdate24/gitlab-ai-gateway-cve-2026-90970) :  ![starts](https://img.shields.io/github/stars/techupdate24/gitlab-ai-gateway-cve-2026-90970.svg) ![forks](https://img.shields.io/github/forks/techupdate24/gitlab-ai-gateway-cve-2026-90970.svg)


## CVE-2026-72781
 Craft CMS versions = 5.0.0-RC1 before 5.10.7 and = 4.0.0-RC1 before 4.18.3 contain a remote code execution vulnerability in the Twig sandbox mechanism. Because Craft marks the ElementInterface as safe (via the AllowedInSandbox attribute) and the sandbox allowlisting extends to the entire class hierarchy (craft\base\Component up to yii\base\Component), an authenticated attacker with permission to access the control panel can render a malicious Twig template that abuses the yii\base\Component arbitrary function-call gadget to execute arbitrary code, even when the Twig sandbox is enabled via enableTwigSandbox().

- [https://github.com/TRX-0/CVE-2026-72781-craftcms-sandbox-rce](https://github.com/TRX-0/CVE-2026-72781-craftcms-sandbox-rce) :  ![starts](https://img.shields.io/github/stars/TRX-0/CVE-2026-72781-craftcms-sandbox-rce.svg) ![forks](https://img.shields.io/github/forks/TRX-0/CVE-2026-72781-craftcms-sandbox-rce.svg)


## CVE-2026-72778
 Craft CMS versions from 4.0.0-RC1 before 4.18.2 and from 5.0.0-RC1 before 5.10.6 contain an authenticated remote code execution vulnerability in the control panel element-search condition handling. Craft cleanses the outer request-controlled condition array via Component::cleanseConfig(), but Conditions::createCondition() later decodes and merges the JSON string in condition.config without re-running cleanseConfig() on the decoded configuration. Because condition.config is a JSON string during the first cleanse, Yii special config keys such as 'as ...' and 'on ...' can be hidden inside it and, after JSON decoding, are interpreted by Yii as behavior/event configuration during FieldLayout object creation. An attacker with an authenticated control panel session (and a valid CSRF token) can exploit this to execute operating system commands as the PHP/web user.

- [https://github.com/TRX-0/CVE-2026-72778-craftcms-rce](https://github.com/TRX-0/CVE-2026-72778-craftcms-rce) :  ![starts](https://img.shields.io/github/stars/TRX-0/CVE-2026-72778-craftcms-rce.svg) ![forks](https://img.shields.io/github/forks/TRX-0/CVE-2026-72778-craftcms-rce.svg)


## CVE-2026-64638
Discovered and responsibly disclosed by [the team at pwn.ai](https://pwn.ai/).

- [https://github.com/zahidec0de/CVE-2026-12345-poc](https://github.com/zahidec0de/CVE-2026-12345-poc) :  ![starts](https://img.shields.io/github/stars/zahidec0de/CVE-2026-12345-poc.svg) ![forks](https://img.shields.io/github/forks/zahidec0de/CVE-2026-12345-poc.svg)


## CVE-2026-64561
far from ideal; that flaw will be addressed separately.

- [https://github.com/hitechcloud-vietnam/Zapscape](https://github.com/hitechcloud-vietnam/Zapscape) :  ![starts](https://img.shields.io/github/stars/hitechcloud-vietnam/Zapscape.svg) ![forks](https://img.shields.io/github/forks/hitechcloud-vietnam/Zapscape.svg)


## CVE-2026-64560
---truncated---

- [https://github.com/imkidz0/CVE-2026-64560-exploit](https://github.com/imkidz0/CVE-2026-64560-exploit) :  ![starts](https://img.shields.io/github/stars/imkidz0/CVE-2026-64560-exploit.svg) ![forks](https://img.shields.io/github/forks/imkidz0/CVE-2026-64560-exploit.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/hitechcloud-vietnam/wp2shell-PoC](https://github.com/hitechcloud-vietnam/wp2shell-PoC) :  ![starts](https://img.shields.io/github/stars/hitechcloud-vietnam/wp2shell-PoC.svg) ![forks](https://img.shields.io/github/forks/hitechcloud-vietnam/wp2shell-PoC.svg)


## CVE-2026-60137
 WordPress 6.8.x before 6.8.6, 6.9.x before 6.9.5, and 7.0.x before 7.0.2 does not properly sanitise the author__not_in parameter of WP_Query, which could allow SQL Injection when a plugin or theme passes untrusted input to the parameter.

- [https://github.com/hitechcloud-vietnam/wp2shell-PoC](https://github.com/hitechcloud-vietnam/wp2shell-PoC) :  ![starts](https://img.shields.io/github/stars/hitechcloud-vietnam/wp2shell-PoC.svg) ![forks](https://img.shields.io/github/forks/hitechcloud-vietnam/wp2shell-PoC.svg)


## CVE-2026-55794
 Craft CMS is a content management system (CMS). In versions 5.9.0 and above prior to 5.10.0, control panel users with the ability to edit entries can execute unsandboxed Twig code via the HTTP Referrer header, potentially leading to authenticated RCE. The issue happens when a user is saving entries. Strings for a signed redirect URL are being compiled as a Twig template via renderObjectTemplate(), and while a sandboxed alternative already exists (renderSandboxedObjectTemplate()), it is not used in this case. This signed URL can be specified by users, as it is reflected in the “Referer” HTTP request header, which is under attacker control. This issue has been fixed in version 5.10.0.

- [https://github.com/TRX-0/CVE-2026-55794-craftcms-ssti](https://github.com/TRX-0/CVE-2026-55794-craftcms-ssti) :  ![starts](https://img.shields.io/github/stars/TRX-0/CVE-2026-55794-craftcms-ssti.svg) ![forks](https://img.shields.io/github/forks/TRX-0/CVE-2026-55794-craftcms-ssti.svg)


## CVE-2026-48842
 Roundcube Webmail 1.6.x before 1.6.16 and 1.7.x before 1.7.1 has Pre-authentication SQL injection in the virtuser_query plugin via a preg_replace() backslash escape bypass.

- [https://github.com/XsanFlip/POC-CVE-2026-48842](https://github.com/XsanFlip/POC-CVE-2026-48842) :  ![starts](https://img.shields.io/github/stars/XsanFlip/POC-CVE-2026-48842.svg) ![forks](https://img.shields.io/github/forks/XsanFlip/POC-CVE-2026-48842.svg)


## CVE-2026-44011
 Craft CMS is a content management system (CMS). From 4.0.0 to before 4.17.12 and 5.9.18, Craft CMS which contains an input-handling flaw in a Yii object creation path that let any authenticated user inject malicious configuration and execute arbitrary commands on the server. The request-controlled condition field layouts data is converted into a live FieldLayout object without a Component::cleanseConfig() boundary. Because Craft configures models before parent::__construct(), attacker-controlled special config keys can take effect during object creation, and FieldLayout initialization then triggers a same-request event. This vulnerability is fixed in 4.17.12 and 5.9.18.

- [https://github.com/TRX-0/CVE-2026-44011-craftcms-rce](https://github.com/TRX-0/CVE-2026-44011-craftcms-rce) :  ![starts](https://img.shields.io/github/stars/TRX-0/CVE-2026-44011-craftcms-rce.svg) ![forks](https://img.shields.io/github/forks/TRX-0/CVE-2026-44011-craftcms-rce.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/inforcqb/CVE-2026-43499-pja110](https://github.com/inforcqb/CVE-2026-43499-pja110) :  ![starts](https://img.shields.io/github/stars/inforcqb/CVE-2026-43499-pja110.svg) ![forks](https://img.shields.io/github/forks/inforcqb/CVE-2026-43499-pja110.svg)


## CVE-2026-42589
 Gotenberg is a Docker-powered stateless API for PDF files. Prior to 8.31.0, Gotenberg's /forms/pdfengines/metadata/write HTTP endpoint accepts a JSON metadata object and passes its keys directly to ExifTool via the go-exiftool library. No validation is performed on key characters. A \n embedded in a JSON key splits the ExifTool stdin stream into a new argument line, allowing an attacker to inject arbitrary ExifTool flags — including -if, which evaluates Perl expressions. This achieves unauthenticated OS command execution in a single HTTP request. The response is HTTP 200 with a valid PDF, making the attack transparent to basic monitoring. This vulnerability is fixed in 8.31.0.

- [https://github.com/HackfutSecRoot/-GOTENBERG-RCE-CHAIN](https://github.com/HackfutSecRoot/-GOTENBERG-RCE-CHAIN) :  ![starts](https://img.shields.io/github/stars/HackfutSecRoot/-GOTENBERG-RCE-CHAIN.svg) ![forks](https://img.shields.io/github/forks/HackfutSecRoot/-GOTENBERG-RCE-CHAIN.svg)


## CVE-2026-42356
This issue affects Apache HTTP Server: from 2.4.60 through 2.4.68.

- [https://github.com/thankgod4rob/CVEs](https://github.com/thankgod4rob/CVEs) :  ![starts](https://img.shields.io/github/stars/thankgod4rob/CVEs.svg) ![forks](https://img.shields.io/github/forks/thankgod4rob/CVEs.svg)


## CVE-2026-40281
 Gotenberg is a Docker-powered stateless API for PDF files. In versions 8.30.1 and earlier, the metadata write endpoint validates metadata keys for control characters but leaves metadata values unsanitized. A newline character in a metadata value splits the ExifTool stdin line into two separate arguments, allowing injection of arbitrary ExifTool pseudo-tags such as -FileName, -Directory, -SymLink, and -HardLink. This is a bypass of the incomplete key-sanitization fix introduced in v8.30.1. An unauthenticated attacker can rename or move any PDF being processed to an arbitrary path in the container filesystem, overwrite arbitrary files, or create symlinks and hard links at arbitrary paths.

- [https://github.com/HackfutSecRoot/-GOTENBERG-RCE-CHAIN](https://github.com/HackfutSecRoot/-GOTENBERG-RCE-CHAIN) :  ![starts](https://img.shields.io/github/stars/HackfutSecRoot/-GOTENBERG-RCE-CHAIN.svg) ![forks](https://img.shields.io/github/forks/HackfutSecRoot/-GOTENBERG-RCE-CHAIN.svg)


## CVE-2026-39808
 A improper neutralization of special elements used in an os command ('os command injection') vulnerability in Fortinet FortiSandbox 4.4.0 through 4.4.8 may allow attacker to execute unauthorized code or commands via insert attack vector here

- [https://github.com/gotr00t0day/CVE-2026-39808](https://github.com/gotr00t0day/CVE-2026-39808) :  ![starts](https://img.shields.io/github/stars/gotr00t0day/CVE-2026-39808.svg) ![forks](https://img.shields.io/github/forks/gotr00t0day/CVE-2026-39808.svg)


## CVE-2026-34990
 OpenPrinting CUPS is an open source printing system for Linux and other Unix-like operating systems. In versions 2.4.16 and prior, a local unprivileged user can coerce cupsd into authenticating to an attacker-controlled localhost IPP service with a reusable Authorization: Local ... token. That token is enough to drive /admin/ requests on localhost, and the attacker can combine CUPS-Create-Local-Printer with printer-is-shared=true to persist a file:///... queue even though the normal FileDevice policy rejects such URIs. Printing to that queue gives an arbitrary root file overwrite; the PoC below uses that primitive to drop a sudoers fragment and demonstrate root command execution. At time of publication, there are no publicly available patches.

- [https://github.com/TRX-0/CVE-2026-34990-cups-lpe](https://github.com/TRX-0/CVE-2026-34990-cups-lpe) :  ![starts](https://img.shields.io/github/stars/TRX-0/CVE-2026-34990-cups-lpe.svg) ![forks](https://img.shields.io/github/forks/TRX-0/CVE-2026-34990-cups-lpe.svg)


## CVE-2026-33157
 Craft CMS is a content management system (CMS). From version 5.6.0 to before version 5.9.13, a Remote Code Execution (RCE) vulnerability exists in Craft CMS, it can be exploited by any authenticated user with control panel access. This is a bypass of a previous fix. The existing patches add cleanseConfig() to assembleLayoutFromPost() and various FieldsController actions to strip Yii2 behavior/event injection keys ("as" and "on" prefixed keys). However, the fieldLayouts parameter in ElementIndexesController::actionFilterHud() is passed directly to FieldLayout::createFromConfig() without any sanitization, enabling the same behavior injection attack chain. This issue has been patched in version 5.9.13.

- [https://github.com/TRX-0/CVE-2026-33157-craftcms-rce](https://github.com/TRX-0/CVE-2026-33157-craftcms-rce) :  ![starts](https://img.shields.io/github/stars/TRX-0/CVE-2026-33157-craftcms-rce.svg) ![forks](https://img.shields.io/github/forks/TRX-0/CVE-2026-33157-craftcms-rce.svg)


## CVE-2026-31857
 Craft is a content management system (CMS). Prior to 5.9.9 and 4.17.4, a Remote Code Execution vulnerability exists in the Craft CMS 5 conditions system. The BaseElementSelectConditionRule::getElementIds() method passes user-controlled string input through renderObjectTemplate() -- an unsandboxed Twig rendering function with escaping disabled. Any authenticated Control Panel user (including non-admin roles such as Author or Editor) can achieve full RCE by sending a crafted condition rule via standard element listing endpoints. This vulnerability requires no admin privileges, no special permissions beyond basic control panel access, and bypasses all production hardening settings (allowAdminChanges: false, devMode: false, enableTwigSandbox: true). Users should update to the patched 5.9.9 or 4.17.4 release to mitigate the issue.

- [https://github.com/TRX-0/CVE-2026-31857-craftcms-ssti](https://github.com/TRX-0/CVE-2026-31857-craftcms-ssti) :  ![starts](https://img.shields.io/github/stars/TRX-0/CVE-2026-31857-craftcms-ssti.svg) ![forks](https://img.shields.io/github/forks/TRX-0/CVE-2026-31857-craftcms-ssti.svg)


## CVE-2026-27944
 Nginx UI is a web user interface for the Nginx web server. Prior to version 2.3.3, the /api/backup endpoint is accessible without authentication and discloses the encryption keys required to decrypt the backup in the X-Backup-Security response header. This allows an unauthenticated attacker to download a full system backup containing sensitive data (user credentials, session tokens, SSL private keys, Nginx configurations) and decrypt it immediately. This issue has been patched in version 2.3.3.

- [https://github.com/diamorphine666/CVE-2026-27944](https://github.com/diamorphine666/CVE-2026-27944) :  ![starts](https://img.shields.io/github/stars/diamorphine666/CVE-2026-27944.svg) ![forks](https://img.shields.io/github/forks/diamorphine666/CVE-2026-27944.svg)


## CVE-2026-19660
 The Divi Membership plugin for WordPress is vulnerable to Authentication Bypass in all versions up to, and including, 2.3.0. The `process_paypal_callback` function, hooked to the `init` action, accepts a base64-encoded `paypal_param` GET parameter with no IPN validation, no cryptographic signature check, no ownership verification, and no nonce, allowing it to trust an entirely attacker-controlled user ID value that is passed directly to `wp_set_current_user()` and `wp_set_auth_cookie()`. This makes it possible for unauthenticated attackers to log in as any existing WordPress user — including administrators — by supplying an arbitrary user ID in the `paypal_param` GET parameter, resulting in full site takeover. The vulnerability is further compounded by the fact that the PayPal gateway class is instantiated unconditionally regardless of whether PayPal is enabled or configured, ensuring the vulnerable hook is always registered on every front-end request.

- [https://github.com/MRdark-ops/CVE-2026-19660-exploit](https://github.com/MRdark-ops/CVE-2026-19660-exploit) :  ![starts](https://img.shields.io/github/stars/MRdark-ops/CVE-2026-19660-exploit.svg) ![forks](https://img.shields.io/github/forks/MRdark-ops/CVE-2026-19660-exploit.svg)


## CVE-2026-15989
 The Super Forms – Drag & Drop Form Builder plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 6.3.316. This is due to the Register & Login add-on's before_email_success_msg() function whitelisting the client-submitted 'role' key and copying it into the user-data array that is passed directly to wp_insert_user(), without validating the submitted role against the administrator-configured register_user_role, without an allow-list, and without any current_user_can() capability check. This makes it possible for unauthenticated attackers to register a new account with the Administrator role by injecting role=administrator into the data submitted to any published Super Forms registration form (register_login_action='register').

- [https://github.com/antid00t/CVE-2026-15989](https://github.com/antid00t/CVE-2026-15989) :  ![starts](https://img.shields.io/github/stars/antid00t/CVE-2026-15989.svg) ![forks](https://img.shields.io/github/forks/antid00t/CVE-2026-15989.svg)


## CVE-2026-14461
This issue exists in the mtr through version 0.96 and it was fixed in commit 48e1794414d338ce47abc0f27c25ade8788af9c3.

- [https://github.com/sifatnotes/Learn-SecByte-CTF-Labs-Beelzebub-SQLMap-Auth-CVE-2026-14461-Web-to-Root](https://github.com/sifatnotes/Learn-SecByte-CTF-Labs-Beelzebub-SQLMap-Auth-CVE-2026-14461-Web-to-Root) :  ![starts](https://img.shields.io/github/stars/sifatnotes/Learn-SecByte-CTF-Labs-Beelzebub-SQLMap-Auth-CVE-2026-14461-Web-to-Root.svg) ![forks](https://img.shields.io/github/forks/sifatnotes/Learn-SecByte-CTF-Labs-Beelzebub-SQLMap-Auth-CVE-2026-14461-Web-to-Root.svg)


## CVE-2026-14378
 The DevKit Pro plugin for WordPress is vulnerable to Authentication Bypass Leading to Administrator Account Takeover in all versions up to, and including, 2.3.0 This is due to the `revert_switch` handler trusting the attacker-controlled `original_user_id` cookie as the privileged identity: `verify_nonce_and_capability()` incorrectly checks the `manage_options` capability on the user identified by the cookie rather than on the actual requester via `current_user_can()`, while the switch-back form and a valid session-bound nonce are emitted publicly via `wp_footer` to any visitor — including unauthenticated users — whenever that cookie is present. This makes it possible for unauthenticated attackers to set the `original_user_id` cookie to any administrator's user ID, collect the rendered nonce, and POST it back to the `revert_switch` handler, causing `wp_set_auth_cookie()` to be called with the administrator's ID and granting the attacker a full administrator-level authenticated session and complete site takeover.

- [https://github.com/MRdark-ops/CVE-2026-19660-exploit](https://github.com/MRdark-ops/CVE-2026-19660-exploit) :  ![starts](https://img.shields.io/github/stars/MRdark-ops/CVE-2026-19660-exploit.svg) ![forks](https://img.shields.io/github/forks/MRdark-ops/CVE-2026-19660-exploit.svg)


## CVE-2026-12345
 The cleanup of tempfile.TemporaryDirectory is vulnerable to a race condition. An attacker who can modify the tree during cleanup can replace a directory with a symbolic link, causing files outside of the temporary directory to be deleted or have their permissions and file flags reset, with the privileges of the process performing the cleanup. Note that platforms where shutil.rmtree.avoids_symlink_attacks is false, remain affected, and file flags may still be reset outside of the tree on all platforms.

- [https://github.com/zahidec0de/CVE-2026-12345-poc](https://github.com/zahidec0de/CVE-2026-12345-poc) :  ![starts](https://img.shields.io/github/stars/zahidec0de/CVE-2026-12345-poc.svg) ![forks](https://img.shields.io/github/forks/zahidec0de/CVE-2026-12345-poc.svg)


## CVE-2026-9558
 A Server-Side Template Injection (SSTI) vulnerability exists in Mautic's theme engine. The platform renders uploaded Twig templates without a sandbox or strict function restrictions. Authenticated users with permissions to create or upload themes can abuse this to execute arbitrary code on the hosting server (Remote Code Execution) or access restricted system files and configuration settings.

- [https://github.com/Cimihan123/CVE-2026-9558-lab-poc-bundle](https://github.com/Cimihan123/CVE-2026-9558-lab-poc-bundle) :  ![starts](https://img.shields.io/github/stars/Cimihan123/CVE-2026-9558-lab-poc-bundle.svg) ![forks](https://img.shields.io/github/forks/Cimihan123/CVE-2026-9558-lab-poc-bundle.svg)


## CVE-2026-4480
substitution character without escaping shell meta characters. A remote attacker could exploit this vulnerability by sending a specially crafted print job description that contains unescaped shell characters. This could lead to remote code execution on the affected system.

- [https://github.com/saitoken241/CVE-2026-4480-POC](https://github.com/saitoken241/CVE-2026-4480-POC) :  ![starts](https://img.shields.io/github/stars/saitoken241/CVE-2026-4480-POC.svg) ![forks](https://img.shields.io/github/forks/saitoken241/CVE-2026-4480-POC.svg)
- [https://github.com/AlanNewberry/CVE-2026-4480-samba-print-command-injection-rce](https://github.com/AlanNewberry/CVE-2026-4480-samba-print-command-injection-rce) :  ![starts](https://img.shields.io/github/stars/AlanNewberry/CVE-2026-4480-samba-print-command-injection-rce.svg) ![forks](https://img.shields.io/github/forks/AlanNewberry/CVE-2026-4480-samba-print-command-injection-rce.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/233laoliu/mt6985-CVE-2026-43499](https://github.com/233laoliu/mt6985-CVE-2026-43499) :  ![starts](https://img.shields.io/github/stars/233laoliu/mt6985-CVE-2026-43499.svg) ![forks](https://img.shields.io/github/forks/233laoliu/mt6985-CVE-2026-43499.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)


## CVE-2025-60787
 MotionEye v0.43.1b4 and before is vulnerable to OS Command Injection in configuration parameters such as image_file_name. Unsanitized user input is written to Motion configuration files, allowing remote authenticated attackers with admin access to achieve code execution when Motion is restarted.

- [https://github.com/diamorphine666/CVE-2025-60787](https://github.com/diamorphine666/CVE-2025-60787) :  ![starts](https://img.shields.io/github/stars/diamorphine666/CVE-2025-60787.svg) ![forks](https://img.shields.io/github/forks/diamorphine666/CVE-2025-60787.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/giriaryan694-a11y/cve-2025-32433_rce_exploit](https://github.com/giriaryan694-a11y/cve-2025-32433_rce_exploit) :  ![starts](https://img.shields.io/github/stars/giriaryan694-a11y/cve-2025-32433_rce_exploit.svg) ![forks](https://img.shields.io/github/forks/giriaryan694-a11y/cve-2025-32433_rce_exploit.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/Heimd411/CVE-2025-29927-PoC](https://github.com/Heimd411/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/Heimd411/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/Heimd411/CVE-2025-29927-PoC.svg)


## CVE-2025-21065
 Improper input validation in Retail Mode prior to version 5.59.11 allows self attackers to execute privileged commands on their own devices.

- [https://github.com/Pealeap/CVE-2025-21065](https://github.com/Pealeap/CVE-2025-21065) :  ![starts](https://img.shields.io/github/stars/Pealeap/CVE-2025-21065.svg) ![forks](https://img.shields.io/github/forks/Pealeap/CVE-2025-21065.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)


## CVE-2025-2992
 A vulnerability classified as critical was found in Tenda FH1202 1.2.0.14(408). Affected by this vulnerability is an unknown functionality of the file /goform/AdvSetWrlsafeset of the component Web Management Interface. The manipulation leads to improper access controls. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/0xPb1/Next.js-CVE-2025-29927](https://github.com/0xPb1/Next.js-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/0xPb1/Next.js-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/0xPb1/Next.js-CVE-2025-29927.svg)


## CVE-2024-51482
 ZoneMinder is a free, open source closed-circuit television software application. ZoneMinder v1.37.* = 1.37.64 is vulnerable to boolean-based SQL Injection in function of web/ajax/event.php. This is fixed in 1.37.65.

- [https://github.com/diamorphine666/CVE-2024-51482](https://github.com/diamorphine666/CVE-2024-51482) :  ![starts](https://img.shields.io/github/stars/diamorphine666/CVE-2024-51482.svg) ![forks](https://img.shields.io/github/forks/diamorphine666/CVE-2024-51482.svg)


## CVE-2022-0891
 A heap buffer overflow in ExtractImageSection function in tiffcrop.c in libtiff library Version 4.3.0 allows attacker to trigger unsafe or out of bounds memory access via crafted TIFF image file which could result into application crash, potential information disclosure or any other context-dependent impact

- [https://github.com/flavorex0000/libtiff-cve-2022-0891-lab](https://github.com/flavorex0000/libtiff-cve-2022-0891-lab) :  ![starts](https://img.shields.io/github/stars/flavorex0000/libtiff-cve-2022-0891-lab.svg) ![forks](https://img.shields.io/github/forks/flavorex0000/libtiff-cve-2022-0891-lab.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe](https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe) :  ![starts](https://img.shields.io/github/stars/Greetdawn/CVE-2022-0847-DirtyPipe.svg) ![forks](https://img.shields.io/github/forks/Greetdawn/CVE-2022-0847-DirtyPipe.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/Park123r/CVE-2021-41773](https://github.com/Park123r/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Park123r/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Park123r/CVE-2021-41773.svg)


## CVE-2019-8900
 A vulnerability in the SecureROM of some Apple devices can be exploited by an unauthenticated local attacker to execute arbitrary code upon booting those devices. This vulnerability allows arbitrary code to be executed on the device. Exploiting the vulnerability requires physical access to the device: the device must be plugged in to a computer upon booting, and it must be put into Device Firmware Update (DFU) mode. The exploit is not persistent; rebooting the device overrides any changes to the device's software that were made during an exploited session on the device. Additionally, unless an attacker has access to the device's unlock PIN or fingerprint, an attacker cannot gain access to information protected by Apple's Secure Enclave or Touch ID features.

- [https://github.com/Weeabo-Inc/a9pwn](https://github.com/Weeabo-Inc/a9pwn) :  ![starts](https://img.shields.io/github/stars/Weeabo-Inc/a9pwn.svg) ![forks](https://img.shields.io/github/forks/Weeabo-Inc/a9pwn.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock."  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/cyberexpert111/Blind-SSRF-to-Remote-Code-Execution-Shellshock-Professional-Bug-Bounty-Report](https://github.com/cyberexpert111/Blind-SSRF-to-Remote-Code-Execution-Shellshock-Professional-Bug-Bounty-Report) :  ![starts](https://img.shields.io/github/stars/cyberexpert111/Blind-SSRF-to-Remote-Code-Execution-Shellshock-Professional-Bug-Bounty-Report.svg) ![forks](https://img.shields.io/github/forks/cyberexpert111/Blind-SSRF-to-Remote-Code-Execution-Shellshock-Professional-Bug-Bounty-Report.svg)


## CVE-2012-1823
 sapi/cgi/cgi_main.c in PHP before 5.3.12 and 5.4.x before 5.4.2, when configured as a CGI script (aka php-cgi), does not properly handle query strings that lack an = (equals sign) character, which allows remote attackers to execute arbitrary code by placing command-line options in the query string, related to lack of skipping a certain php_getopt for the 'd' case.

- [https://github.com/yilmaz8596/metasploitable-vulnerability-assessment](https://github.com/yilmaz8596/metasploitable-vulnerability-assessment) :  ![starts](https://img.shields.io/github/stars/yilmaz8596/metasploitable-vulnerability-assessment.svg) ![forks](https://img.shields.io/github/forks/yilmaz8596/metasploitable-vulnerability-assessment.svg)


## CVE-2008-0600
 The vmsplice_to_pipe function in Linux kernel 2.6.17 through 2.6.24.1 does not validate a certain userspace pointer before dereference, which allows local users to gain root privileges via crafted arguments in a vmsplice system call, a different vulnerability than CVE-2008-0009 and CVE-2008-0010.

- [https://github.com/yilmaz8596/metasploitable-vulnerability-assessment](https://github.com/yilmaz8596/metasploitable-vulnerability-assessment) :  ![starts](https://img.shields.io/github/stars/yilmaz8596/metasploitable-vulnerability-assessment.svg) ![forks](https://img.shields.io/github/forks/yilmaz8596/metasploitable-vulnerability-assessment.svg)

