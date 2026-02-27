# Update 2026-02-27
## CVE-2026-27639
 Mercator is an open source web application designed to enable mapping of information systems. A stored Cross-Site Scripting (XSS) vulnerability exists in Mercator prior to version 2026.02.22 due to the use of unescaped Blade directives (`{!! !!}`) in display templates. An authenticated user with the User role can inject arbitrary JavaScript payloads into fields such as "contact point" when creating or editing entities. The payload is then executed in the browser of any user who views the affected page, including administrators. Version 2026.02.22 fixes the vulnerability.

- [https://github.com/hadhub/CVE-2026-27639-Mercator-XSS](https://github.com/hadhub/CVE-2026-27639-Mercator-XSS) :  ![starts](https://img.shields.io/github/stars/hadhub/CVE-2026-27639-Mercator-XSS.svg) ![forks](https://img.shields.io/github/forks/hadhub/CVE-2026-27639-Mercator-XSS.svg)


## CVE-2026-27607
 RustFS is a distributed object storage system built in Rust. In versions 1.0.0-alpha.56 through 1.0.0-alpha.82, RustFS does not validate policy conditions in presigned POST uploads (PostObject), allowing attackers to bypass content-length-range, starts-with, and Content-Type constraints. This enables unauthorized file uploads exceeding size limits, uploads to arbitrary object keys, and content-type spoofing, potentially leading to storage exhaustion, unauthorized data access, and security bypasses. Version 1.0.0-alpha.83 fixes the issue.

- [https://github.com/nikeee/CVE-2026-27607](https://github.com/nikeee/CVE-2026-27607) :  ![starts](https://img.shields.io/github/stars/nikeee/CVE-2026-27607.svg) ![forks](https://img.shields.io/github/forks/nikeee/CVE-2026-27607.svg)


## CVE-2026-26717
 An issue in OpenFUN Richie (LMS) in src/richie/apps/courses/api.py. The application used the non-constant time == operator for HMAC signature verification in the sync_course_run_from_request function. This allows remote attackers to forge valid signatures and bypass authentication by measuring response time discrepancies

- [https://github.com/Rickidevs/CVE-2026-26717](https://github.com/Rickidevs/CVE-2026-26717) :  ![starts](https://img.shields.io/github/stars/Rickidevs/CVE-2026-26717.svg) ![forks](https://img.shields.io/github/forks/Rickidevs/CVE-2026-26717.svg)


## CVE-2026-25746
 OpenEMR is a free and open source electronic health records and medical practice management application. Versions prior to 8.0.0 contain a SQL injection vulnerability in prescription that can be exploited by authenticated attackers. The vulnerability exists due to insufficient input validation in the prescription listing functionality. Version 8.0.0 fixes the vulnerability.

- [https://github.com/ChrisSub08/CVE-2026-25746_SqlInjectionVulnerabilityOpenEMR7.0.4](https://github.com/ChrisSub08/CVE-2026-25746_SqlInjectionVulnerabilityOpenEMR7.0.4) :  ![starts](https://img.shields.io/github/stars/ChrisSub08/CVE-2026-25746_SqlInjectionVulnerabilityOpenEMR7.0.4.svg) ![forks](https://img.shields.io/github/forks/ChrisSub08/CVE-2026-25746_SqlInjectionVulnerabilityOpenEMR7.0.4.svg)


## CVE-2026-1357
 The Migration, Backup, Staging – WPvivid Backup & Migration plugin for WordPress is vulnerable to Unauthenticated Arbitrary File Upload in versions up to and including 0.9.123. This is due to improper error handling in the RSA decryption process combined with a lack of path sanitization when writing uploaded files. When the plugin fails to decrypt a session key using openssl_private_decrypt(), it does not terminate execution and instead passes the boolean false value to the phpseclib library's AES cipher initialization. The library treats this false value as a string of null bytes, allowing an attacker to encrypt a malicious payload using a predictable null-byte key. Additionally, the plugin accepts filenames from the decrypted payload without sanitization, enabling directory traversal to escape the protected backup directory. This makes it possible for unauthenticated attackers to upload arbitrary PHP files to publicly accessible directories and achieve Remote Code Execution via the wpvivid_action=send_to_site parameter.

- [https://github.com/rootdirective-sec/CVE-2026-1357-Lab](https://github.com/rootdirective-sec/CVE-2026-1357-Lab) :  ![starts](https://img.shields.io/github/stars/rootdirective-sec/CVE-2026-1357-Lab.svg) ![forks](https://img.shields.io/github/forks/rootdirective-sec/CVE-2026-1357-Lab.svg)


## CVE-2025-69985
 FUXA 1.2.8 and prior contains an Authentication Bypass vulnerability leading to Remote Code Execution (RCE). The vulnerability exists in the server/api/jwt-helper.js middleware, which improperly trusts the HTTP "Referer" header to validate internal requests. A remote unauthenticated attacker can bypass JWT authentication by spoofing the Referer header to match the server's host. Successful exploitation allows the attacker to access the protected /api/runscript endpoint and execute arbitrary Node.js code on the server.

- [https://github.com/joshuavanderpoll/CVE-2025-69985](https://github.com/joshuavanderpoll/CVE-2025-69985) :  ![starts](https://img.shields.io/github/stars/joshuavanderpoll/CVE-2025-69985.svg) ![forks](https://img.shields.io/github/forks/joshuavanderpoll/CVE-2025-69985.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)


## CVE-2025-62878
 A malicious user can manipulate the parameters.pathPattern to create PersistentVolumes in arbitrary locations on the host node, potentially overwriting sensitive files or gaining access to unintended directories.

- [https://github.com/kinokopio/CVE-2025-62878](https://github.com/kinokopio/CVE-2025-62878) :  ![starts](https://img.shields.io/github/stars/kinokopio/CVE-2025-62878.svg) ![forks](https://img.shields.io/github/forks/kinokopio/CVE-2025-62878.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/MammaniNelsonD/React2P4IM0Nshell](https://github.com/MammaniNelsonD/React2P4IM0Nshell) :  ![starts](https://img.shields.io/github/stars/MammaniNelsonD/React2P4IM0Nshell.svg) ![forks](https://img.shields.io/github/forks/MammaniNelsonD/React2P4IM0Nshell.svg)


## CVE-2025-49132
 Pterodactyl is a free, open-source game server management panel. Prior to version 1.11.11, using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated. With the ability to execute arbitrary code it could be used to gain access to the Panel's server, read credentials from the Panel's config, extract sensitive information from the database, access files of servers managed by the panel, etc. This issue has been patched in version 1.11.11. There are no software workarounds for this vulnerability, but use of an external Web Application Firewall (WAF) could help mitigate this attack.

- [https://github.com/revasec/CVE-2025-49132](https://github.com/revasec/CVE-2025-49132) :  ![starts](https://img.shields.io/github/stars/revasec/CVE-2025-49132.svg) ![forks](https://img.shields.io/github/forks/revasec/CVE-2025-49132.svg)


## CVE-2025-40553
 SolarWinds Web Help Desk was found to be susceptible to an untrusted data deserialization vulnerability that could lead to remote code execution, which would allow an attacker to run commands on the host machine. This could be exploited without authentication.

- [https://github.com/watchtowrlabs/watchTowr-vs-SolarWinds-WebHelpDesk-CVE-2025-40552-CVE-2025-40553](https://github.com/watchtowrlabs/watchTowr-vs-SolarWinds-WebHelpDesk-CVE-2025-40552-CVE-2025-40553) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/watchTowr-vs-SolarWinds-WebHelpDesk-CVE-2025-40552-CVE-2025-40553.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/watchTowr-vs-SolarWinds-WebHelpDesk-CVE-2025-40552-CVE-2025-40553.svg)


## CVE-2025-40552
 SolarWinds Web Help Desk was found to be susceptible to an authentication bypass vulnerability that if exploited, would allow a malicious actor to execute actions and methods that should be protected by authentication.

- [https://github.com/watchtowrlabs/watchTowr-vs-SolarWinds-WebHelpDesk-CVE-2025-40552-CVE-2025-40553](https://github.com/watchtowrlabs/watchTowr-vs-SolarWinds-WebHelpDesk-CVE-2025-40552-CVE-2025-40553) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/watchTowr-vs-SolarWinds-WebHelpDesk-CVE-2025-40552-CVE-2025-40553.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/watchTowr-vs-SolarWinds-WebHelpDesk-CVE-2025-40552-CVE-2025-40553.svg)


## CVE-2025-27607
 Python JSON Logger is a JSON Formatter for Python Logging. Between 30 December 2024 and 4 March 2025 Python JSON Logger was vulnerable to RCE through a missing dependency. This occurred because msgspec-python313-pre was deleted by the owner leaving the name open to being claimed by a third party. If the package was claimed, it would allow them RCE on any Python JSON Logger user who installed the development dependencies on Python 3.13 (e.g. pip install python-json-logger[dev]). This issue has been resolved with 3.3.0.

- [https://github.com/Barsug/msgspec-python313-pre](https://github.com/Barsug/msgspec-python313-pre) :  ![starts](https://img.shields.io/github/stars/Barsug/msgspec-python313-pre.svg) ![forks](https://img.shields.io/github/forks/Barsug/msgspec-python313-pre.svg)


## CVE-2025-6841
 A vulnerability has been found in code-projects Product Inventory System 1.0 and classified as critical. This vulnerability affects unknown code of the file /admin/edit_product.php. The manipulation of the argument ID leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/Marshall-Hallenbeck/CVE_2025_68413-4](https://github.com/Marshall-Hallenbeck/CVE_2025_68413-4) :  ![starts](https://img.shields.io/github/stars/Marshall-Hallenbeck/CVE_2025_68413-4.svg) ![forks](https://img.shields.io/github/forks/Marshall-Hallenbeck/CVE_2025_68413-4.svg)


## CVE-2025-1242
 The administrative credentials can be extracted through application API responses, mobile application reverse engineering, and device firmware reverse engineering. The exposure may result in an attacker gaining  full administrative access to the Gardyn IoT Hub exposing connected devices to malicious control.

- [https://github.com/MichaelAdamGroberman/ICSA-26-055-03](https://github.com/MichaelAdamGroberman/ICSA-26-055-03) :  ![starts](https://img.shields.io/github/stars/MichaelAdamGroberman/ICSA-26-055-03.svg) ![forks](https://img.shields.io/github/forks/MichaelAdamGroberman/ICSA-26-055-03.svg)


## CVE-2024-55879
 XWiki Platform is a generic wiki platform. Starting in version 2.3 and prior to versions 15.10.9, 16.3.0, any user with script rights can perform arbitrary remote code execution by adding instances of `XWiki.ConfigurableClass` to any page. This compromises the confidentiality, integrity and availability of the whole XWiki installation. This has been patched in XWiki 15.10.9 and 16.3.0. No known workarounds are available except upgrading.

- [https://github.com/dbwlsdnr95/CVE-2024-55879](https://github.com/dbwlsdnr95/CVE-2024-55879) :  ![starts](https://img.shields.io/github/stars/dbwlsdnr95/CVE-2024-55879.svg) ![forks](https://img.shields.io/github/forks/dbwlsdnr95/CVE-2024-55879.svg)


## CVE-2024-23897
 Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.

- [https://github.com/aldamd/CTF](https://github.com/aldamd/CTF) :  ![starts](https://img.shields.io/github/stars/aldamd/CTF.svg) ![forks](https://img.shields.io/github/forks/aldamd/CTF.svg)


## CVE-2024-23692
 Rejetto HTTP File Server, up to and including version 2.3m, is vulnerable to a template injection vulnerability. This vulnerability allows a remote, unauthenticated attacker to execute arbitrary commands on the affected system by sending a specially crafted HTTP request. As of the CVE assignment date, Rejetto HFS 2.3m is no longer supported.

- [https://github.com/wgetnz/hfs2](https://github.com/wgetnz/hfs2) :  ![starts](https://img.shields.io/github/stars/wgetnz/hfs2.svg) ![forks](https://img.shields.io/github/forks/wgetnz/hfs2.svg)


## CVE-2022-36804
 Multiple API endpoints in Atlassian Bitbucket Server and Data Center 7.0.0 before version 7.6.17, from version 7.7.0 before version 7.17.10, from version 7.18.0 before version 7.21.4, from version 8.0.0 before version 8.0.3, from version 8.1.0 before version 8.1.3, and from version 8.2.0 before version 8.2.2, and from version 8.3.0 before 8.3.1 allows remote attackers with read permissions to a public or private Bitbucket repository to execute arbitrary code by sending a malicious HTTP request. This vulnerability was reported via our Bug Bounty Program by TheGrandPew.

- [https://github.com/DanielHallbro/CVE-2022-36804-Bitbucket-RCE-Analysis](https://github.com/DanielHallbro/CVE-2022-36804-Bitbucket-RCE-Analysis) :  ![starts](https://img.shields.io/github/stars/DanielHallbro/CVE-2022-36804-Bitbucket-RCE-Analysis.svg) ![forks](https://img.shields.io/github/forks/DanielHallbro/CVE-2022-36804-Bitbucket-RCE-Analysis.svg)


## CVE-2022-35411
 rpc.py through 0.6.0 allows Remote Code Execution because an unpickle occurs when the "serializer: pickle" HTTP header is sent. In other words, although JSON (not Pickle) is the default data format, an unauthenticated client can cause the data to be processed with unpickle.

- [https://github.com/Neo-okami/CVE-2022-35411](https://github.com/Neo-okami/CVE-2022-35411) :  ![starts](https://img.shields.io/github/stars/Neo-okami/CVE-2022-35411.svg) ![forks](https://img.shields.io/github/forks/Neo-okami/CVE-2022-35411.svg)


## CVE-2022-26134
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are from 1.3.0 before 7.4.17, from 7.13.0 before 7.13.7, from 7.14.0 before 7.14.3, from 7.15.0 before 7.15.2, from 7.16.0 before 7.16.4, from 7.17.0 before 7.17.4, and from 7.18.0 before 7.18.1.

- [https://github.com/crypt0lith/confluence-ognl-rce](https://github.com/crypt0lith/confluence-ognl-rce) :  ![starts](https://img.shields.io/github/stars/crypt0lith/confluence-ognl-rce.svg) ![forks](https://img.shields.io/github/forks/crypt0lith/confluence-ognl-rce.svg)


## CVE-2022-1471
 SnakeYaml's Constructor() class does not restrict types which can be instantiated during deserialization. Deserializing yaml content provided by an attacker can lead to remote code execution. We recommend using SnakeYaml's SafeConsturctor when parsing untrusted content to restrict deserialization. We recommend upgrading to version 2.0 and beyond.

- [https://github.com/jelee2555/CVE-2022-1471-attacker](https://github.com/jelee2555/CVE-2022-1471-attacker) :  ![starts](https://img.shields.io/github/stars/jelee2555/CVE-2022-1471-attacker.svg) ![forks](https://img.shields.io/github/forks/jelee2555/CVE-2022-1471-attacker.svg)


## CVE-2022-0185
 A heap-based buffer overflow flaw was found in the way the legacy_parse_param function in the Filesystem Context functionality of the Linux kernel verified the supplied parameters length. An unprivileged (in case of unprivileged user namespaces enabled, otherwise needs namespaced CAP_SYS_ADMIN privilege) local user able to open a filesystem that does not support the Filesystem Context API (and thus fallbacks to legacy handling) could use this flaw to escalate their privileges on the system.

- [https://github.com/sandesh9978/CVE-2022-0185-Analysis-and-Exploit](https://github.com/sandesh9978/CVE-2022-0185-Analysis-and-Exploit) :  ![starts](https://img.shields.io/github/stars/sandesh9978/CVE-2022-0185-Analysis-and-Exploit.svg) ![forks](https://img.shields.io/github/forks/sandesh9978/CVE-2022-0185-Analysis-and-Exploit.svg)

