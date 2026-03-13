# Update 2026-03-13
## CVE-2026-32127
 OpenEMR is a free and open source electronic health records and medical practice management application. Prior to 8.0.0.1, OpenEMR contains a SQL injection vulnerability in the ajax graphs library that can be exploited by authenticated attackers. The vulnerability exists due to insufficient input validation in the ajax graphs library. This vulnerability is fixed in 8.0.0.1.

- [https://github.com/ChrisSub08/CVE-2026-32127_SqlInjectionVulnerabilityOpenEMR8.0.0](https://github.com/ChrisSub08/CVE-2026-32127_SqlInjectionVulnerabilityOpenEMR8.0.0) :  ![starts](https://img.shields.io/github/stars/ChrisSub08/CVE-2026-32127_SqlInjectionVulnerabilityOpenEMR8.0.0.svg) ![forks](https://img.shields.io/github/forks/ChrisSub08/CVE-2026-32127_SqlInjectionVulnerabilityOpenEMR8.0.0.svg)


## CVE-2026-31844
 An authenticated SQL Injection vulnerability (CWE-89) exists in the Koha staff interface in the /cgi-bin/koha/suggestion/suggestion.pl endpoint due to improper validation of the displayby parameter used by the GetDistinctValues functionality. A low-privileged staff user can inject arbitrary SQL queries via crafted requests to this parameter, allowing execution of unintended SQL statements and exposure of sensitive database information. Successful exploitation may lead to full compromise of the backend database, including disclosure or modification of stored data.

- [https://github.com/Mothra-1/CVE-2026-31844](https://github.com/Mothra-1/CVE-2026-31844) :  ![starts](https://img.shields.io/github/stars/Mothra-1/CVE-2026-31844.svg) ![forks](https://img.shields.io/github/forks/Mothra-1/CVE-2026-31844.svg)


## CVE-2026-30952
 liquidjs is a Shopify / GitHub Pages compatible template engine in pure JavaScript. Prior to 10.25.0, the layout, render, and include tags allow arbitrary file access via absolute paths (either as string literals or through Liquid variables, the latter require dynamicPartials: true, which is the default). This poses a security risk when malicious users are allowed to control the template content or specify the filepath to be included as a Liquid variable. This vulnerability is fixed in 10.25.0.

- [https://github.com/MorielHarush/CVE-2026-30952-PoC](https://github.com/MorielHarush/CVE-2026-30952-PoC) :  ![starts](https://img.shields.io/github/stars/MorielHarush/CVE-2026-30952-PoC.svg) ![forks](https://img.shields.io/github/forks/MorielHarush/CVE-2026-30952-PoC.svg)


## CVE-2026-30945
 StudioCMS is a server-side-rendered, Astro native, headless content management system. Prior to 0.4.0, the DELETE /studiocms_api/dashboard/api-tokens endpoint allows any authenticated user with editor privileges or above to revoke API tokens belonging to any other user, including admin and owner accounts. The handler accepts tokenID and userID directly from the request payload without verifying token ownership, caller identity, or role hierarchy. This enables targeted denial of service against critical integrations and automations. This vulnerability is fixed in 0.4.0.

- [https://github.com/FilipeGaudard/CVE-2026-30945-PoC](https://github.com/FilipeGaudard/CVE-2026-30945-PoC) :  ![starts](https://img.shields.io/github/stars/FilipeGaudard/CVE-2026-30945-PoC.svg) ![forks](https://img.shields.io/github/forks/FilipeGaudard/CVE-2026-30945-PoC.svg)


## CVE-2026-30944
 StudioCMS is a server-side-rendered, Astro native, headless content management system. Prior to 0.4.0, the /studiocms_api/dashboard/api-tokens endpoint allows any authenticated user (at least Editor) to generate API tokens for any other user, including owner and admin accounts. The endpoint fails to validate whether the requesting user is authorized to create tokens on behalf of the target user ID, resulting in a full privilege escalation. This vulnerability is fixed in 0.4.0.

- [https://github.com/FilipeGaudard/CVE-2026-30944-PoC](https://github.com/FilipeGaudard/CVE-2026-30944-PoC) :  ![starts](https://img.shields.io/github/stars/FilipeGaudard/CVE-2026-30944-PoC.svg) ![forks](https://img.shields.io/github/forks/FilipeGaudard/CVE-2026-30944-PoC.svg)


## CVE-2026-30741
 A remote code execution (RCE) vulnerability in OpenClaw Agent Platform v2026.2.6 allows attackers to execute arbitrary code via a Request-Side prompt injection attack.

- [https://github.com/Named1ess/CVE-2026-30741](https://github.com/Named1ess/CVE-2026-30741) :  ![starts](https://img.shields.io/github/stars/Named1ess/CVE-2026-30741.svg) ![forks](https://img.shields.io/github/forks/Named1ess/CVE-2026-30741.svg)


## CVE-2026-29000
 pac4j-jwt versions prior to 4.5.9, 5.7.9, and 6.3.3 contain an authentication bypass vulnerability in JwtAuthenticator when processing encrypted JWTs that allows remote attackers to forge authentication tokens. Attackers who possess the server's RSA public key can create a JWE-wrapped PlainJWT with arbitrary subject and role claims, bypassing signature verification to authenticate as any user including administrators.

- [https://github.com/rootdirective-sec/CVE-2026-29000-Lab](https://github.com/rootdirective-sec/CVE-2026-29000-Lab) :  ![starts](https://img.shields.io/github/stars/rootdirective-sec/CVE-2026-29000-Lab.svg) ![forks](https://img.shields.io/github/forks/rootdirective-sec/CVE-2026-29000-Lab.svg)


## CVE-2026-27739
 The Angular SSR is a server-rise rendering tool for Angular applications. Versions prior to 21.2.0-rc.1, 21.1.5, 20.3.17, and 19.2.21 have a Server-Side Request Forgery (SSRF) vulnerability in the Angular SSR request handling pipeline. The vulnerability exists because Angular’s internal URL reconstruction logic directly trusts and consumes user-controlled HTTP headers specifically the Host and `X-Forwarded-*` family to determine the application's base origin without any validation of the destination domain. Specifically, the framework didn't have checks for the host domain, path and character sanitization, and port validation. This vulnerability manifests in two primary ways: implicit relative URL resolution and explicit manual construction. When successfully exploited, this vulnerability allows for arbitrary internal request steering. This can lead to credential exfiltration, internal network probing, and a confidentiality breach. In order to be vulnerable, the victim application must use Angular SSR (Server-Side Rendering), the application must perform `HttpClient` requests using relative URLs OR manually construct URLs using the unvalidated `Host` / `X-Forwarded-*` headers using the `REQUEST` object, the application server must be reachable by an attacker who can influence these headers without strict validation from a front-facing proxy, and the infrastructure (Cloud, CDN, or Load Balancer) must not sanitize or validate incoming headers. Versions 21.2.0-rc.1, 21.1.5, 20.3.17, and 19.2.21 contain a patch. Some workarounds are available. Avoid using `req.headers` for URL construction. Instead, use trusted variables for base API paths. Those who cannot upgrade immediately should implement a middleware in their `server.ts` to enforce numeric ports and validated hostnames.

- [https://github.com/bankerke/-CVE-2026-27739-poc](https://github.com/bankerke/-CVE-2026-27739-poc) :  ![starts](https://img.shields.io/github/stars/bankerke/-CVE-2026-27739-poc.svg) ![forks](https://img.shields.io/github/forks/bankerke/-CVE-2026-27739-poc.svg)


## CVE-2026-20131
 Note: If the FMC management interface does not have public internet access, the attack surface that is associated with this vulnerability is reduced.

- [https://github.com/sak110/CVE-2026-20131](https://github.com/sak110/CVE-2026-20131) :  ![starts](https://img.shields.io/github/stars/sak110/CVE-2026-20131.svg) ![forks](https://img.shields.io/github/forks/sak110/CVE-2026-20131.svg)


## CVE-2026-20127
This vulnerability exists because the peering authentication mechanism in an affected system is not working properly. An attacker could exploit this vulnerability by sending crafted requests to an affected system. A successful exploit could allow the attacker to log in to an affected Cisco Catalyst SD-WAN Controller as an internal, high-privileged, non-root&nbsp;user account. Using this account, the attacker could access NETCONF, which would then allow the attacker to manipulate network configuration for the SD-WAN fabric.&nbsp;

- [https://github.com/sfewer-r7/CVE-2026-20127](https://github.com/sfewer-r7/CVE-2026-20127) :  ![starts](https://img.shields.io/github/stars/sfewer-r7/CVE-2026-20127.svg) ![forks](https://img.shields.io/github/forks/sfewer-r7/CVE-2026-20127.svg)


## CVE-2026-3786
 A security flaw has been discovered in EasyCMS up to 1.6. The impacted element is an unknown function of the file /RbacuserAction.class.php of the component Request Parameter Handler. The manipulation of the argument _order results in sql injection. The attack can be launched remotely. The exploit has been released to the public and may be used for attacks. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/snapdowgg/CVE-2026-3786](https://github.com/snapdowgg/CVE-2026-3786) :  ![starts](https://img.shields.io/github/stars/snapdowgg/CVE-2026-3786.svg) ![forks](https://img.shields.io/github/forks/snapdowgg/CVE-2026-3786.svg)


## CVE-2026-3228
 The NextScripts: Social Networks Auto-Poster plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the `[nxs_fbembed]` shortcode in all versions up to, and including, 4.4.6. This is due to insufficient input sanitization and output escaping on the `snapFB` post meta value. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/NULL200OK/CVE-2026-3228](https://github.com/NULL200OK/CVE-2026-3228) :  ![starts](https://img.shields.io/github/stars/NULL200OK/CVE-2026-3228.svg) ![forks](https://img.shields.io/github/forks/NULL200OK/CVE-2026-3228.svg)


## CVE-2026-2754
 Navtor NavBox exposes sensitive configuration and operational data due to missing authentication on HTTP API endpoints. An unauthenticated remote attacker with network access to the device can execute HTTP GET requests to TCP port 8080 to retrieve internal network parameters including ECDIS & OT Information, device identifiers, and service status logs.

- [https://github.com/DeadExpl0it/CVE-2026-27540-WordPress-Exploit-PoC](https://github.com/DeadExpl0it/CVE-2026-27540-WordPress-Exploit-PoC) :  ![starts](https://img.shields.io/github/stars/DeadExpl0it/CVE-2026-27540-WordPress-Exploit-PoC.svg) ![forks](https://img.shields.io/github/forks/DeadExpl0it/CVE-2026-27540-WordPress-Exploit-PoC.svg)


## CVE-2025-70330
 Easy Grade Pro 4.1.0.2 contains a file parsing logic flaw in the handling of proprietary .EGP gradebook files. By modifying specific fields at precise offsets within an otherwise valid .EGP file, an attacker can trigger an out-of-bounds memory read during parsing. This results in an unhandled access violation and application crash, leading to a local denial-of-service condition when the crafted file is opened by a user.

- [https://github.com/TheMalwareGuardian/CVE-2025-70330](https://github.com/TheMalwareGuardian/CVE-2025-70330) :  ![starts](https://img.shields.io/github/stars/TheMalwareGuardian/CVE-2025-70330.svg) ![forks](https://img.shields.io/github/forks/TheMalwareGuardian/CVE-2025-70330.svg)


## CVE-2025-66956
 Insecure Access Control in Contact Plan, E-Mail, SMS and Fax components in Asseco SEE Live 2.0 allows remote attackers to access and execute attachments via a computable URL.

- [https://github.com/TheWoodenBench/CVE-2025-66956](https://github.com/TheWoodenBench/CVE-2025-66956) :  ![starts](https://img.shields.io/github/stars/TheWoodenBench/CVE-2025-66956.svg) ![forks](https://img.shields.io/github/forks/TheWoodenBench/CVE-2025-66956.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg)


## CVE-2025-33073
 Improper access control in Windows SMB allows an authorized attacker to elevate privileges over a network.

- [https://github.com/IyarGross/SMB-CVE-2025-33073](https://github.com/IyarGross/SMB-CVE-2025-33073) :  ![starts](https://img.shields.io/github/stars/IyarGross/SMB-CVE-2025-33073.svg) ![forks](https://img.shields.io/github/forks/IyarGross/SMB-CVE-2025-33073.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/Heimd411/CVE-2025-29927-PoC](https://github.com/Heimd411/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/Heimd411/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/Heimd411/CVE-2025-29927-PoC.svg)


## CVE-2025-27136
 LocalS3 is an Amazon S3 mock service for testing and local development. Prior to version 1.21, the LocalS3 service's bucket creation endpoint is vulnerable to XML External Entity (XXE) injection. When processing the CreateBucketConfiguration XML document during bucket creation, the service's XML parser is configured to resolve external entities. This allows an attacker to declare an external entity that references an internal URL, which the server will then attempt to fetch when parsing the XML. The vulnerability specifically occurs in the location constraint processing, where the XML parser resolves external entities without proper validation or restrictions. When the external entity is resolved, the server makes an HTTP request to the specified URL and includes the response content in the parsed XML document. This vulnerability can be exploited to perform server-side request forgery (SSRF) attacks, allowing an attacker to make requests to internal services or resources that should not be accessible from external networks. The server will include the responses from these internal requests in the resulting bucket configuration, effectively leaking sensitive information. The attacker only needs to be able to send HTTP requests to the LocalS3 service to exploit this vulnerability.

- [https://github.com/ZaidMkh32/CVE-2025-27136-XXE-LocalS3](https://github.com/ZaidMkh32/CVE-2025-27136-XXE-LocalS3) :  ![starts](https://img.shields.io/github/stars/ZaidMkh32/CVE-2025-27136-XXE-LocalS3.svg) ![forks](https://img.shields.io/github/forks/ZaidMkh32/CVE-2025-27136-XXE-LocalS3.svg)


## CVE-2025-5288
 The REST API | Custom API Generator For Cross Platform And Import Export In WP plugin for WordPress is vulnerable to Privilege Escalation due to a missing capability check on the process_handler() function in versions 1.0.0 to 2.0.3. This makes it possible for unauthenticated attackers to POST an arbitrary import_api URL, import specially crafted JSON, and thereby create a new user with full Administrator privileges.

- [https://github.com/Nxploited/CVE-2025-5288](https://github.com/Nxploited/CVE-2025-5288) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-5288.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-5288.svg)


## CVE-2024-21338
 Windows Kernel Elevation of Privilege Vulnerability

- [https://github.com/MistyFir/CVE-2024-21338-Exploit](https://github.com/MistyFir/CVE-2024-21338-Exploit) :  ![starts](https://img.shields.io/github/stars/MistyFir/CVE-2024-21338-Exploit.svg) ![forks](https://img.shields.io/github/forks/MistyFir/CVE-2024-21338-Exploit.svg)


## CVE-2024-3094
Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.

- [https://github.com/michalAshurov/writeup-CVE-2024-3094](https://github.com/michalAshurov/writeup-CVE-2024-3094) :  ![starts](https://img.shields.io/github/stars/michalAshurov/writeup-CVE-2024-3094.svg) ![forks](https://img.shields.io/github/forks/michalAshurov/writeup-CVE-2024-3094.svg)


## CVE-2023-6329
 An authentication bypass vulnerability exists in Control iD iDSecure v4.7.32.0. The login routine used by iDS-Core.dll contains a "passwordCustom" option that allows an unauthenticated attacker to compute valid credentials that can be used to bypass authentication and act as an administrative user.

- [https://github.com/itzvenom/CVE-2023-6329](https://github.com/itzvenom/CVE-2023-6329) :  ![starts](https://img.shields.io/github/stars/itzvenom/CVE-2023-6329.svg) ![forks](https://img.shields.io/github/forks/itzvenom/CVE-2023-6329.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/honypot/CVE-2021-41773](https://github.com/honypot/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/honypot/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/honypot/CVE-2021-41773.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via "sudoedit -s" and a command-line argument that ends with a single backslash character.

- [https://github.com/TheLeopard65/CVE-2021-3156-Baron-Samedit](https://github.com/TheLeopard65/CVE-2021-3156-Baron-Samedit) :  ![starts](https://img.shields.io/github/stars/TheLeopard65/CVE-2021-3156-Baron-Samedit.svg) ![forks](https://img.shields.io/github/forks/TheLeopard65/CVE-2021-3156-Baron-Samedit.svg)


## CVE-2018-7600
 Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations.

- [https://github.com/Meraj1312/cve-2018-7600-drupalgeddon2-lab](https://github.com/Meraj1312/cve-2018-7600-drupalgeddon2-lab) :  ![starts](https://img.shields.io/github/stars/Meraj1312/cve-2018-7600-drupalgeddon2-lab.svg) ![forks](https://img.shields.io/github/forks/Meraj1312/cve-2018-7600-drupalgeddon2-lab.svg)


## CVE-2006-2369
 RealVNC 4.1.1, and other products that use RealVNC such as AdderLink IP and Cisco CallManager, allows remote attackers to bypass authentication via a request in which the client specifies an insecure security type such as "Type 1 - None", which is accepted even if it is not offered by the server, as originally demonstrated using a long password.

- [https://github.com/hacker1337itme/CVE-2006-2369](https://github.com/hacker1337itme/CVE-2006-2369) :  ![starts](https://img.shields.io/github/stars/hacker1337itme/CVE-2006-2369.svg) ![forks](https://img.shields.io/github/forks/hacker1337itme/CVE-2006-2369.svg)

