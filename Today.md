# Update 2025-04-05
## CVE-2025-31864
 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Out the Box Beam me up Scotty – Back to Top Button allows Stored XSS. This issue affects Beam me up Scotty – Back to Top Button: from n/a through 1.0.23.

- [https://github.com/DoTTak/CVE-2025-31864](https://github.com/DoTTak/CVE-2025-31864) :  ![starts](https://img.shields.io/github/stars/DoTTak/CVE-2025-31864.svg) ![forks](https://img.shields.io/github/forks/DoTTak/CVE-2025-31864.svg)


## CVE-2025-30921
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Tribulant Software Newsletters allows SQL Injection. This issue affects Newsletters: from n/a through 4.9.9.7.

- [https://github.com/DoTTak/CVE-2025-30921](https://github.com/DoTTak/CVE-2025-30921) :  ![starts](https://img.shields.io/github/stars/DoTTak/CVE-2025-30921.svg) ![forks](https://img.shields.io/github/forks/DoTTak/CVE-2025-30921.svg)


## CVE-2025-30567
 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability in wp01ru WP01 allows Path Traversal. This issue affects WP01: from n/a through 2.6.2.

- [https://github.com/realcodeb0ss/CVE-2025-30567-PoC](https://github.com/realcodeb0ss/CVE-2025-30567-PoC) :  ![starts](https://img.shields.io/github/stars/realcodeb0ss/CVE-2025-30567-PoC.svg) ![forks](https://img.shields.io/github/forks/realcodeb0ss/CVE-2025-30567-PoC.svg)


## CVE-2025-30208
 Vite, a provider of frontend development tooling, has a vulnerability in versions prior to 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10. `@fs` denies access to files outside of Vite serving allow list. Adding `?raw??` or `?import&raw??` to the URL bypasses this limitation and returns the file content if it exists. This bypass exists because trailing separators such as `?` are removed in several places, but are not accounted for in query string regexes. The contents of arbitrary files can be returned to the browser. Only apps explicitly exposing the Vite dev server to the network (using `--host` or `server.host` config option) are affected. Versions 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10 fix the issue.

- [https://github.com/4m3rr0r/CVE-2025-30208-PoC](https://github.com/4m3rr0r/CVE-2025-30208-PoC) :  ![starts](https://img.shields.io/github/stars/4m3rr0r/CVE-2025-30208-PoC.svg) ![forks](https://img.shields.io/github/forks/4m3rr0r/CVE-2025-30208-PoC.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Prior to 14.2.25 and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 14.2.25 and 15.2.3.

- [https://github.com/fahimalshihab/NextBypass](https://github.com/fahimalshihab/NextBypass) :  ![starts](https://img.shields.io/github/stars/fahimalshihab/NextBypass.svg) ![forks](https://img.shields.io/github/forks/fahimalshihab/NextBypass.svg)


## CVE-2025-24799
 GLPI is a free asset and IT management software package. An unauthenticated user can perform a SQL injection through the inventory endpoint. This vulnerability is fixed in 10.0.18.

- [https://github.com/MuhammadWaseem29/CVE-2025-24799](https://github.com/MuhammadWaseem29/CVE-2025-24799) :  ![starts](https://img.shields.io/github/stars/MuhammadWaseem29/CVE-2025-24799.svg) ![forks](https://img.shields.io/github/forks/MuhammadWaseem29/CVE-2025-24799.svg)


## CVE-2025-22223
you do not have method security annotations on parameterized types or methods, or all method security annotations are attached to target methods

- [https://github.com/1ucky7/cve-2025-22223-demo-1.0.0](https://github.com/1ucky7/cve-2025-22223-demo-1.0.0) :  ![starts](https://img.shields.io/github/stars/1ucky7/cve-2025-22223-demo-1.0.0.svg) ![forks](https://img.shields.io/github/forks/1ucky7/cve-2025-22223-demo-1.0.0.svg)


## CVE-2025-2825
 CrushFTP versions 10.0.0 through 10.8.3 and 11.0.0 through 11.3.0 are affected by a vulnerability in the S3 authorization header processing that allows authentication bypass. Remote and unauthenticated HTTP requests to CrushFTP with known usernames can be used to impersonate a user and conduct actions on their behalf, including administrative actions and data retrieval.

- [https://github.com/WOOOOONG/CVE-2025-2825](https://github.com/WOOOOONG/CVE-2025-2825) :  ![starts](https://img.shields.io/github/stars/WOOOOONG/CVE-2025-2825.svg) ![forks](https://img.shields.io/github/forks/WOOOOONG/CVE-2025-2825.svg)


## CVE-2025-2294
 The Kubio AI Page Builder plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 2.5.1 via thekubio_hybrid_theme_load_template function. This makes it possible for unauthenticated attackers to include and execute arbitrary files on the server, allowing the execution of any PHP code in those files. This can be used to bypass access controls, obtain sensitive data, or achieve code execution in cases where images and other “safe” file types can be uploaded and included.

- [https://github.com/realcodeb0ss/CVE-2025-2294-PoC](https://github.com/realcodeb0ss/CVE-2025-2294-PoC) :  ![starts](https://img.shields.io/github/stars/realcodeb0ss/CVE-2025-2294-PoC.svg) ![forks](https://img.shields.io/github/forks/realcodeb0ss/CVE-2025-2294-PoC.svg)


## CVE-2025-2005
 The Front End Users plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the file uploads field of the registration form in all versions up to, and including, 3.2.32. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/h4ckxel/CVE-2025-2005](https://github.com/h4ckxel/CVE-2025-2005) :  ![starts](https://img.shields.io/github/stars/h4ckxel/CVE-2025-2005.svg) ![forks](https://img.shields.io/github/forks/h4ckxel/CVE-2025-2005.svg)


## CVE-2024-53900
 Mongoose before 8.8.3 can improperly use $where in match, leading to search injection.

- [https://github.com/Gokul-Krishnan-V-R/CVE-2024-53900](https://github.com/Gokul-Krishnan-V-R/CVE-2024-53900) :  ![starts](https://img.shields.io/github/stars/Gokul-Krishnan-V-R/CVE-2024-53900.svg) ![forks](https://img.shields.io/github/forks/Gokul-Krishnan-V-R/CVE-2024-53900.svg)


## CVE-2024-25600
 Improper Control of Generation of Code ('Code Injection') vulnerability in Codeer Limited Bricks Builder allows Code Injection.This issue affects Bricks Builder: from n/a through 1.9.6.

- [https://github.com/cboss43/CVE-2024-25600](https://github.com/cboss43/CVE-2024-25600) :  ![starts](https://img.shields.io/github/stars/cboss43/CVE-2024-25600.svg) ![forks](https://img.shields.io/github/forks/cboss43/CVE-2024-25600.svg)


## CVE-2024-21893
 A server-side request forgery vulnerability in the SAML component of Ivanti Connect Secure (9.x, 22.x) and Ivanti Policy Secure (9.x, 22.x) and Ivanti Neurons for ZTA allows an attacker to access certain restricted resources without authentication.

- [https://github.com/cboss43/CVE-2024-25600](https://github.com/cboss43/CVE-2024-25600) :  ![starts](https://img.shields.io/github/stars/cboss43/CVE-2024-25600.svg) ![forks](https://img.shields.io/github/forks/cboss43/CVE-2024-25600.svg)


## CVE-2024-20931
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core).  Supported versions that are affected are 12.2.1.4.0 and  14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Server.  Successful attacks of this vulnerability can result in  unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).

- [https://github.com/cboss43/CVE-2024-25600](https://github.com/cboss43/CVE-2024-25600) :  ![starts](https://img.shields.io/github/stars/cboss43/CVE-2024-25600.svg) ![forks](https://img.shields.io/github/forks/cboss43/CVE-2024-25600.svg)


## CVE-2024-0204
 Authentication bypass in Fortra's GoAnywhere MFT prior to 7.4.1 allows an unauthorized user to create an admin user via the administration portal.

- [https://github.com/cboss43/CVE-2024-25600](https://github.com/cboss43/CVE-2024-25600) :  ![starts](https://img.shields.io/github/stars/cboss43/CVE-2024-25600.svg) ![forks](https://img.shields.io/github/forks/cboss43/CVE-2024-25600.svg)


## CVE-2023-51467
 The vulnerability permits attackers to circumvent authentication processes, enabling them to remotely execute arbitrary code

- [https://github.com/cboss43/CVE-2024-25600](https://github.com/cboss43/CVE-2024-25600) :  ![starts](https://img.shields.io/github/stars/cboss43/CVE-2024-25600.svg) ![forks](https://img.shields.io/github/forks/cboss43/CVE-2024-25600.svg)


## CVE-2023-46988
 Directory Traversal vulnerability in ONLYOFFICE Document Server v.7.5.0 and before allows a remote attacker to obtain sensitive information via a crafted file upload.

- [https://github.com/mihat2/OnlyOffice-path-traversal](https://github.com/mihat2/OnlyOffice-path-traversal) :  ![starts](https://img.shields.io/github/stars/mihat2/OnlyOffice-path-traversal.svg) ![forks](https://img.shields.io/github/forks/mihat2/OnlyOffice-path-traversal.svg)


## CVE-2022-1388
 On F5 BIG-IP 16.1.x versions prior to 16.1.2.2, 15.1.x versions prior to 15.1.5.1, 14.1.x versions prior to 14.1.4.6, 13.1.x versions prior to 13.1.5, and all 12.1.x and 11.6.x versions, undisclosed requests may bypass iControl REST authentication. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

- [https://github.com/cboss43/CVE-2024-25600](https://github.com/cboss43/CVE-2024-25600) :  ![starts](https://img.shields.io/github/stars/cboss43/CVE-2024-25600.svg) ![forks](https://img.shields.io/github/forks/cboss43/CVE-2024-25600.svg)


## CVE-2021-45232
 In Apache APISIX Dashboard before 2.10.1, the Manager API uses two frameworks and introduces framework `droplet` on the basis of framework `gin`, all APIs and authentication middleware are developed based on framework `droplet`, but some API directly use the interface of framework `gin` thus bypassing the authentication.

- [https://github.com/cboss43/CVE-2024-25600](https://github.com/cboss43/CVE-2024-25600) :  ![starts](https://img.shields.io/github/stars/cboss43/CVE-2024-25600.svg) ![forks](https://img.shields.io/github/forks/cboss43/CVE-2024-25600.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/shiomiyan/CVE-2021-41773](https://github.com/shiomiyan/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/shiomiyan/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/shiomiyan/CVE-2021-41773.svg)
- [https://github.com/puckiestyle/CVE-2021-41773](https://github.com/puckiestyle/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-41773.svg)
- [https://github.com/Plunder283/CVE-2021-41773](https://github.com/Plunder283/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Plunder283/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Plunder283/CVE-2021-41773.svg)


## CVE-2021-38163
 SAP NetWeaver (Visual Composer 7.0 RT) versions - 7.30, 7.31, 7.40, 7.50, without restriction, an attacker authenticated as a non-administrative user can upload a malicious file over a network and trigger its processing, which is capable of running operating system commands with the privilege of the Java Server process. These commands can be used to read or modify any information on the server or shut the server down making it unavailable.

- [https://github.com/purpleteam-ru/CVE-2021-38163](https://github.com/purpleteam-ru/CVE-2021-38163) :  ![starts](https://img.shields.io/github/stars/purpleteam-ru/CVE-2021-38163.svg) ![forks](https://img.shields.io/github/forks/purpleteam-ru/CVE-2021-38163.svg)


## CVE-2018-19422
 /panel/uploads in Subrion CMS 4.2.1 allows remote attackers to execute arbitrary PHP code via a .pht or .phar file, because the .htaccess file omits these.

- [https://github.com/Drew-Alleman/CVE-2018-19422](https://github.com/Drew-Alleman/CVE-2018-19422) :  ![starts](https://img.shields.io/github/stars/Drew-Alleman/CVE-2018-19422.svg) ![forks](https://img.shields.io/github/forks/Drew-Alleman/CVE-2018-19422.svg)


## CVE-2007-6750
 The Apache HTTP Server 1.x and 2.x allows remote attackers to cause a denial of service (daemon outage) via partial HTTP requests, as demonstrated by Slowloris, related to the lack of the mod_reqtimeout module in versions before 2.2.15.

- [https://github.com/Jeanpseven/slowl0ris](https://github.com/Jeanpseven/slowl0ris) :  ![starts](https://img.shields.io/github/stars/Jeanpseven/slowl0ris.svg) ![forks](https://img.shields.io/github/forks/Jeanpseven/slowl0ris.svg)


## CVE-1999-0524
 ICMP information such as (1) netmask and (2) timestamp is allowed from arbitrary hosts.

- [https://github.com/noraj/ChronoLeak](https://github.com/noraj/ChronoLeak) :  ![starts](https://img.shields.io/github/stars/noraj/ChronoLeak.svg) ![forks](https://img.shields.io/github/forks/noraj/ChronoLeak.svg)

