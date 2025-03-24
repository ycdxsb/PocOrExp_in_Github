# Update 2025-03-24
## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Prior to 14.2.25 and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 14.2.25 and 15.2.3.

- [https://github.com/Ademking/CVE-2025-29927](https://github.com/Ademking/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/Ademking/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/Ademking/CVE-2025-29927.svg)
- [https://github.com/serhalp/test-cve-2025-29927](https://github.com/serhalp/test-cve-2025-29927) :  ![starts](https://img.shields.io/github/stars/serhalp/test-cve-2025-29927.svg) ![forks](https://img.shields.io/github/forks/serhalp/test-cve-2025-29927.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/tonyarris/CVE-2025-24813-PoC](https://github.com/tonyarris/CVE-2025-24813-PoC) :  ![starts](https://img.shields.io/github/stars/tonyarris/CVE-2025-24813-PoC.svg) ![forks](https://img.shields.io/github/forks/tonyarris/CVE-2025-24813-PoC.svg)


## CVE-2025-2624
 A vulnerability was found in westboy CicadasCMS 1.0. It has been rated as critical. Affected by this issue is some unknown functionality of the file /system/cms/content/save. The manipulation of the argument content/fujian/laiyuan leads to sql injection. The attack may be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/Habuon/CVE-2025-26240](https://github.com/Habuon/CVE-2025-26240) :  ![starts](https://img.shields.io/github/stars/Habuon/CVE-2025-26240.svg) ![forks](https://img.shields.io/github/forks/Habuon/CVE-2025-26240.svg)


## CVE-2025-2620
 A vulnerability has been found in D-Link DAP-1620 1.03 and classified as critical. This vulnerability affects the function mod_graph_auth_uri_handler of the file /storage of the component Authentication Handler. The manipulation leads to stack-based buffer overflow. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/Otsmane-Ahmed/CVE-2025-2620-poc](https://github.com/Otsmane-Ahmed/CVE-2025-2620-poc) :  ![starts](https://img.shields.io/github/stars/Otsmane-Ahmed/CVE-2025-2620-poc.svg) ![forks](https://img.shields.io/github/forks/Otsmane-Ahmed/CVE-2025-2620-poc.svg)


## CVE-2025-1316
 Edimax IC-7100 does not properly neutralize requests. An attacker can create specially crafted requests to achieve remote code execution on the device

- [https://github.com/slockit/CVE-2025-1316](https://github.com/slockit/CVE-2025-1316) :  ![starts](https://img.shields.io/github/stars/slockit/CVE-2025-1316.svg) ![forks](https://img.shields.io/github/forks/slockit/CVE-2025-1316.svg)


## CVE-2024-49668
 Unrestricted Upload of File with Dangerous Type vulnerability in Admin Verbalize WP Upload a Web Shell to a Web Server.This issue affects Verbalize WP: from n/a through 1.0.

- [https://github.com/Nxploited/CVE-2024-49668](https://github.com/Nxploited/CVE-2024-49668) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2024-49668.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2024-49668.svg)


## CVE-2024-49653
 Unrestricted Upload of File with Dangerous Type vulnerability in James Eggers Portfolleo portfolleo allows Upload a Web Shell to a Web Server.This issue affects Portfolleo: from n/a through 1.2.

- [https://github.com/Nxploited/CVE-2024-49653](https://github.com/Nxploited/CVE-2024-49653) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2024-49653.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2024-49653.svg)


## CVE-2024-13346
 The Avada | Website Builder For WordPress & WooCommerce theme for WordPress is vulnerable to arbitrary shortcode execution in all versions up to, and including, 7.11.13. This is due to the software allowing users to execute an action that does not properly validate a value before running do_shortcode. This makes it possible for unauthenticated attackers to execute arbitrary shortcodes.

- [https://github.com/tausifzaman/CVE-2024-13346](https://github.com/tausifzaman/CVE-2024-13346) :  ![starts](https://img.shields.io/github/stars/tausifzaman/CVE-2024-13346.svg) ![forks](https://img.shields.io/github/forks/tausifzaman/CVE-2024-13346.svg)


## CVE-2022-23134
 After the initial setup process, some steps of setup.php file are reachable not only by super-administrators, but by unauthenticated users as well. Malicious actor can pass step checks and potentially change the configuration of Zabbix Frontend.

- [https://github.com/TheN00bBuilder/cve-2022-23134-poc-and-writeup](https://github.com/TheN00bBuilder/cve-2022-23134-poc-and-writeup) :  ![starts](https://img.shields.io/github/stars/TheN00bBuilder/cve-2022-23134-poc-and-writeup.svg) ![forks](https://img.shields.io/github/forks/TheN00bBuilder/cve-2022-23134-poc-and-writeup.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Fa1c0n35/CVE-2021-41773](https://github.com/Fa1c0n35/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Fa1c0n35/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Fa1c0n35/CVE-2021-41773.svg)
- [https://github.com/skentagon/CVE-2021-41773](https://github.com/skentagon/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/skentagon/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/skentagon/CVE-2021-41773.svg)

