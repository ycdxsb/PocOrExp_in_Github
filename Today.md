# Update 2025-01-26
## CVE-2024-55591
 An Authentication Bypass Using an Alternate Path or Channel vulnerability [CWE-288] affecting FortiOS version 7.0.0 through 7.0.16 and FortiProxy version 7.0.0 through 7.0.19 and 7.2.0 through 7.2.12 allows a remote attacker to gain super-admin privileges via crafted requests to Node.js websocket module.

- [https://github.com/amfg145/Private-CVE-2024-55591.](https://github.com/amfg145/Private-CVE-2024-55591.) :  ![starts](https://img.shields.io/github/stars/amfg145/Private-CVE-2024-55591..svg) ![forks](https://img.shields.io/github/forks/amfg145/Private-CVE-2024-55591..svg)


## CVE-2024-45337
 Applications and libraries which misuse the ServerConfig.PublicKeyCallback callback may be susceptible to an authorization bypass. The documentation for ServerConfig.PublicKeyCallback says that "A call to this function does not guarantee that the key offered is in fact used to authenticate." Specifically, the SSH protocol allows clients to inquire about whether a public key is acceptable before proving control of the corresponding private key. PublicKeyCallback may be called with multiple keys, and the order in which the keys were provided cannot be used to infer which key the client successfully authenticated with, if any. Some applications, which store the key(s) passed to PublicKeyCallback (or derived information) and make security relevant determinations based on it once the connection is established, may make incorrect assumptions. For example, an attacker may send public keys A and B, and then authenticate with A. PublicKeyCallback would be called only twice, first with A and then with B. A vulnerable application may then make authorization decisions based on key B for which the attacker does not actually control the private key. Since this API is widely misused, as a partial mitigation golang.org/x/cry...@v0.31.0 enforces the property that, when successfully authenticating via public key, the last key passed to ServerConfig.PublicKeyCallback will be the key used to authenticate the connection. PublicKeyCallback will now be called multiple times with the same key, if necessary. Note that the client may still not control the last key passed to PublicKeyCallback if the connection is then authenticated with a different method, such as PasswordCallback, KeyboardInteractiveCallback, or NoClientAuth. Users should be using the Extensions field of the Permissions return value from the various authentication callbacks to record data associated with the authentication attempt instead of referencing external state. Once the connection is established the state corresponding to the successful authentication attempt can be retrieved via the ServerConn.Permissions field. Note that some third-party libraries misuse the Permissions type by sharing it across authentication attempts; users of third-party libraries should refer to the relevant projects for guidance.

- [https://github.com/peace-maker/CVE-2024-45337](https://github.com/peace-maker/CVE-2024-45337) :  ![starts](https://img.shields.io/github/stars/peace-maker/CVE-2024-45337.svg) ![forks](https://img.shields.io/github/forks/peace-maker/CVE-2024-45337.svg)


## CVE-2024-41570
 An Unauthenticated Server-Side Request Forgery (SSRF) in demon callback handling in Havoc 2 0.7 allows attackers to send arbitrary network traffic originating from the team server.

- [https://github.com/0xLynk/CVE-2024-41570-POC](https://github.com/0xLynk/CVE-2024-41570-POC) :  ![starts](https://img.shields.io/github/stars/0xLynk/CVE-2024-41570-POC.svg) ![forks](https://img.shields.io/github/forks/0xLynk/CVE-2024-41570-POC.svg)


## CVE-2024-3673
 The Web Directory Free WordPress plugin before 1.7.3 does not validate a parameter before using it in an include(), which could lead to Local File Inclusion issues.

- [https://github.com/Nxploited/CVE-2024-3673](https://github.com/Nxploited/CVE-2024-3673) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2024-3673.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2024-3673.svg)


## CVE-2024-3244
'embedpress_calendar' shortcode in all versions up to, and including, 3.9.14 due to insufficient input sanitization and output escaping on user supplied attributes. This makes it possible for authenticated attackers, with contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/rxerium/CVE-2024-32444](https://github.com/rxerium/CVE-2024-32444) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2024-32444.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2024-32444.svg)


## CVE-2023-6063
 The WP Fastest Cache WordPress plugin before 1.2.2 does not properly sanitise and escape a parameter before using it in a SQL statement, leading to a SQL injection exploitable by unauthenticated users.

- [https://github.com/Eulex0x/CVE-2023-6063](https://github.com/Eulex0x/CVE-2023-6063) :  ![starts](https://img.shields.io/github/stars/Eulex0x/CVE-2023-6063.svg) ![forks](https://img.shields.io/github/forks/Eulex0x/CVE-2023-6063.svg)


## CVE-2023-4220
 Unrestricted file upload in big file upload functionality in `/main/inc/lib/javascript/bigupload/inc/bigUpload.php` in Chamilo LMS = v1.11.24 allows unauthenticated attackers to perform stored cross-site scripting attacks and obtain remote code execution via uploading of web shell.

- [https://github.com/zora-beep/CVE-2023-4220](https://github.com/zora-beep/CVE-2023-4220) :  ![starts](https://img.shields.io/github/stars/zora-beep/CVE-2023-4220.svg) ![forks](https://img.shields.io/github/forks/zora-beep/CVE-2023-4220.svg)


## CVE-2022-40684
 An authentication bypass using an alternate path or channel [CWE-288] in Fortinet FortiOS version 7.2.0 through 7.2.1 and 7.0.0 through 7.0.6, FortiProxy version 7.2.0 and version 7.0.0 through 7.0.6 and FortiSwitchManager version 7.2.0 and 7.0.0 allows an unauthenticated atttacker to perform operations on the administrative interface via specially crafted HTTP or HTTPS requests.

- [https://github.com/niklasmato/fortileak-01-2025-Be](https://github.com/niklasmato/fortileak-01-2025-Be) :  ![starts](https://img.shields.io/github/stars/niklasmato/fortileak-01-2025-Be.svg) ![forks](https://img.shields.io/github/forks/niklasmato/fortileak-01-2025-Be.svg)


## CVE-2022-1609
 The School Management WordPress plugin before 9.9.7 contains an obfuscated backdoor injected in it's license checking code that registers a REST API handler, allowing an unauthenticated attacker to execute arbitrary PHP code on the site.

- [https://github.com/iaaaannn0/cve-2022-1609-exploit](https://github.com/iaaaannn0/cve-2022-1609-exploit) :  ![starts](https://img.shields.io/github/stars/iaaaannn0/cve-2022-1609-exploit.svg) ![forks](https://img.shields.io/github/forks/iaaaannn0/cve-2022-1609-exploit.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/skentagon/CVE-2021-41773](https://github.com/skentagon/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/skentagon/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/skentagon/CVE-2021-41773.svg)

