# Update 2025-04-04
## CVE-2025-31125
 Vite is a frontend tooling framework for javascript. Vite exposes content of non-allowed files using ?inline&import or ?raw?import. Only apps explicitly exposing the Vite dev server to the network (using --host or server.host config option) are affected. This vulnerability is fixed in 6.2.4, 6.1.3, 6.0.13, 5.4.16, and 4.5.11.

- [https://github.com/jackieya/CVE-2025-30208-and-CVE-2025-31125](https://github.com/jackieya/CVE-2025-30208-and-CVE-2025-31125) :  ![starts](https://img.shields.io/github/stars/jackieya/CVE-2025-30208-and-CVE-2025-31125.svg) ![forks](https://img.shields.io/github/forks/jackieya/CVE-2025-30208-and-CVE-2025-31125.svg)


## CVE-2025-30208
 Vite, a provider of frontend development tooling, has a vulnerability in versions prior to 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10. `@fs` denies access to files outside of Vite serving allow list. Adding `?raw??` or `?import&raw??` to the URL bypasses this limitation and returns the file content if it exists. This bypass exists because trailing separators such as `?` are removed in several places, but are not accounted for in query string regexes. The contents of arbitrary files can be returned to the browser. Only apps explicitly exposing the Vite dev server to the network (using `--host` or `server.host` config option) are affected. Versions 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10 fix the issue.

- [https://github.com/jackieya/CVE-2025-30208-and-CVE-2025-31125](https://github.com/jackieya/CVE-2025-30208-and-CVE-2025-31125) :  ![starts](https://img.shields.io/github/stars/jackieya/CVE-2025-30208-and-CVE-2025-31125.svg) ![forks](https://img.shields.io/github/forks/jackieya/CVE-2025-30208-and-CVE-2025-31125.svg)
- [https://github.com/sumeet-darekar/CVE-2025-30208](https://github.com/sumeet-darekar/CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/sumeet-darekar/CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/sumeet-darekar/CVE-2025-30208.svg)
- [https://github.com/0xshaheen/CVE-2025-30208](https://github.com/0xshaheen/CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/0xshaheen/CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/0xshaheen/CVE-2025-30208.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Prior to 14.2.25 and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 14.2.25 and 15.2.3.

- [https://github.com/Gokul-Krishnan-V-R/cve-2025-29927](https://github.com/Gokul-Krishnan-V-R/cve-2025-29927) :  ![starts](https://img.shields.io/github/stars/Gokul-Krishnan-V-R/cve-2025-29927.svg) ![forks](https://img.shields.io/github/forks/Gokul-Krishnan-V-R/cve-2025-29927.svg)
- [https://github.com/Naveen-005/Next.Js-middleware-bypass-vulnerability-CVE-2025-29927](https://github.com/Naveen-005/Next.Js-middleware-bypass-vulnerability-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/Naveen-005/Next.Js-middleware-bypass-vulnerability-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/Naveen-005/Next.Js-middleware-bypass-vulnerability-CVE-2025-29927.svg)


## CVE-2025-2888
 During a snapshot rollback, the client incorrectly caches the timestamp metadata. If the client checks the cache when attempting to perform the next update, the update timestamp validation will fail, preventing the next update until the cache is cleared. Users should upgrade to tough version 0.20.0 or later and ensure any forked or derivative code is patched to incorporate the new fixes.

- [https://github.com/murataydemir/AWS-Tough-Library-Multiple-CVEs](https://github.com/murataydemir/AWS-Tough-Library-Multiple-CVEs) :  ![starts](https://img.shields.io/github/stars/murataydemir/AWS-Tough-Library-Multiple-CVEs.svg) ![forks](https://img.shields.io/github/forks/murataydemir/AWS-Tough-Library-Multiple-CVEs.svg)


## CVE-2025-2887
 During a target rollback, the client fails to detect the rollback for delegated targets. This could cause the client to fetch a target from an incorrect source, altering the target contents. Users should upgrade to tough version 0.20.0 or later and ensure any forked or derivative code is patched to incorporate the new fixes.

- [https://github.com/murataydemir/AWS-Tough-Library-Multiple-CVEs](https://github.com/murataydemir/AWS-Tough-Library-Multiple-CVEs) :  ![starts](https://img.shields.io/github/stars/murataydemir/AWS-Tough-Library-Multiple-CVEs.svg) ![forks](https://img.shields.io/github/forks/murataydemir/AWS-Tough-Library-Multiple-CVEs.svg)


## CVE-2025-2886
 Missing validation of terminating delegation causes the client to continue searching the defined delegation list, even after searching a terminating delegation. This could cause the client to fetch a target from an incorrect source, altering the target contents. Users should upgrade to tough version 0.20.0 or later and ensure any forked or derivative code is patched to incorporate the new fixes.

- [https://github.com/murataydemir/AWS-Tough-Library-Multiple-CVEs](https://github.com/murataydemir/AWS-Tough-Library-Multiple-CVEs) :  ![starts](https://img.shields.io/github/stars/murataydemir/AWS-Tough-Library-Multiple-CVEs.svg) ![forks](https://img.shields.io/github/forks/murataydemir/AWS-Tough-Library-Multiple-CVEs.svg)


## CVE-2025-2885
 Missing validation of the root metatdata version number could allow an actor to supply an arbitrary version number to the client instead of the intended version in the root metadata file, altering the version fetched by the client. Users should upgrade to tough version 0.20.0 or later and ensure any forked or derivative code is patched to incorporate the new fixes.

- [https://github.com/murataydemir/AWS-Tough-Library-Multiple-CVEs](https://github.com/murataydemir/AWS-Tough-Library-Multiple-CVEs) :  ![starts](https://img.shields.io/github/stars/murataydemir/AWS-Tough-Library-Multiple-CVEs.svg) ![forks](https://img.shields.io/github/forks/murataydemir/AWS-Tough-Library-Multiple-CVEs.svg)


## CVE-2025-2005
 The Front End Users plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the file uploads field of the registration form in all versions up to, and including, 3.2.32. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/Nxploited/CVE-2025-2005](https://github.com/Nxploited/CVE-2025-2005) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-2005.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-2005.svg)


## CVE-2025-1219
 In PHP from 8.1.* before 8.1.32, from 8.2.* before 8.2.28, from 8.3.* before 8.3.19, from 8.4.* before 8.4.5, when requesting a HTTP resource using the DOM or SimpleXML extensions, the wrong content-type header is used to determine the charset when the requested resource performs a redirect. This may cause the resulting document to be parsed incorrectly or bypass validations.

- [https://github.com/ediop3SquadALT/ediop3PHP](https://github.com/ediop3SquadALT/ediop3PHP) :  ![starts](https://img.shields.io/github/stars/ediop3SquadALT/ediop3PHP.svg) ![forks](https://img.shields.io/github/forks/ediop3SquadALT/ediop3PHP.svg)


## CVE-2024-8176
 A stack overflow vulnerability exists in the libexpat library due to the way it handles recursive entity expansion in XML documents. When parsing an XML document with deeply nested entity references, libexpat can be forced to recurse indefinitely, exhausting the stack space and causing a crash. This issue could lead to denial of service (DoS) or, in some cases, exploitable memory corruption, depending on the environment and library usage.

- [https://github.com/uthrasri/Expat_2.6.2_CVE-2024-8176](https://github.com/uthrasri/Expat_2.6.2_CVE-2024-8176) :  ![starts](https://img.shields.io/github/stars/uthrasri/Expat_2.6.2_CVE-2024-8176.svg) ![forks](https://img.shields.io/github/forks/uthrasri/Expat_2.6.2_CVE-2024-8176.svg)


## CVE-2024-4220
 Prior to 23.1, an information disclosure vulnerability exists within BeyondInsight which can allow an attacker to enumerate usernames.

- [https://github.com/NotItsSixtyN3in/CVE-2024-422028](https://github.com/NotItsSixtyN3in/CVE-2024-422028) :  ![starts](https://img.shields.io/github/stars/NotItsSixtyN3in/CVE-2024-422028.svg) ![forks](https://img.shields.io/github/forks/NotItsSixtyN3in/CVE-2024-422028.svg)


## CVE-2023-27163
 request-baskets up to v1.2.1 was discovered to contain a Server-Side Request Forgery (SSRF) via the component /api/baskets/{name}. This vulnerability allows attackers to access network resources and sensitive information via a crafted API request.

- [https://github.com/G4sp4rCS/htb-sau-automated](https://github.com/G4sp4rCS/htb-sau-automated) :  ![starts](https://img.shields.io/github/stars/G4sp4rCS/htb-sau-automated.svg) ![forks](https://img.shields.io/github/forks/G4sp4rCS/htb-sau-automated.svg)


## CVE-2022-1227
 A privilege escalation flaw was found in Podman. This flaw allows an attacker to publish a malicious image to a public registry. Once this image is downloaded by a potential victim, the vulnerability is triggered after a user runs the 'podman top' command. This action gives the attacker access to the host filesystem, leading to information disclosure or denial of service.

- [https://github.com/LouisLiuNova/CVE-2022-1227_Exploit](https://github.com/LouisLiuNova/CVE-2022-1227_Exploit) :  ![starts](https://img.shields.io/github/stars/LouisLiuNova/CVE-2022-1227_Exploit.svg) ![forks](https://img.shields.io/github/forks/LouisLiuNova/CVE-2022-1227_Exploit.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/TheLastVvV/CVE-2021-41773](https://github.com/TheLastVvV/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/TheLastVvV/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/TheLastVvV/CVE-2021-41773.svg)
- [https://github.com/vuongnv3389-sec/cve-2021-41773](https://github.com/vuongnv3389-sec/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/vuongnv3389-sec/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/vuongnv3389-sec/cve-2021-41773.svg)
- [https://github.com/Fa1c0n35/CVE-2021-41773](https://github.com/Fa1c0n35/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Fa1c0n35/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Fa1c0n35/CVE-2021-41773.svg)
- [https://github.com/skentagon/CVE-2021-41773](https://github.com/skentagon/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/skentagon/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/skentagon/CVE-2021-41773.svg)


## CVE-2021-21975
 Server Side Request Forgery in vRealize Operations Manager API (CVE-2021-21975) prior to 8.4 may allow a malicious actor with network access to the vRealize Operations Manager API can perform a Server Side Request Forgery attack to steal administrative credentials.

- [https://github.com/murataydemir/CVE-2021-21983](https://github.com/murataydemir/CVE-2021-21983) :  ![starts](https://img.shields.io/github/stars/murataydemir/CVE-2021-21983.svg) ![forks](https://img.shields.io/github/forks/murataydemir/CVE-2021-21983.svg)


## CVE-2020-13942
 It is possible to inject malicious OGNL or MVEL scripts into the /context.json public endpoint. This was partially fixed in 1.5.1 but a new attack vector was found. In Apache Unomi version 1.5.2 scripts are now completely filtered from the input. It is highly recommended to upgrade to the latest available version of the 1.5.x release to fix this problem.

- [https://github.com/corsisechero/CVE-2020-13942byVulHub](https://github.com/corsisechero/CVE-2020-13942byVulHub) :  ![starts](https://img.shields.io/github/stars/corsisechero/CVE-2020-13942byVulHub.svg) ![forks](https://img.shields.io/github/forks/corsisechero/CVE-2020-13942byVulHub.svg)


## CVE-2019-14271
 In Docker 19.03.x before 19.03.1 linked against the GNU C Library (aka glibc), code injection can occur when the nsswitch facility dynamically loads a library inside a chroot that contains the contents of the container.

- [https://github.com/LouisLiuNova/CVE-2019-14271_Exploit](https://github.com/LouisLiuNova/CVE-2019-14271_Exploit) :  ![starts](https://img.shields.io/github/stars/LouisLiuNova/CVE-2019-14271_Exploit.svg) ![forks](https://img.shields.io/github/forks/LouisLiuNova/CVE-2019-14271_Exploit.svg)


## CVE-2019-9193
 In PostgreSQL 9.3 through 11.2, the "COPY TO/FROM PROGRAM" function allows superusers and users in the 'pg_execute_server_program' group to execute arbitrary code in the context of the database's operating system user. This functionality is enabled by default and can be abused to run arbitrary operating system commands on Windows, Linux, and macOS. NOTE: Third parties claim/state this is not an issue because PostgreSQL functionality for ‘COPY TO/FROM PROGRAM’ is acting as intended. References state that in PostgreSQL, a superuser can execute commands as the server user without using the ‘COPY FROM PROGRAM’.

- [https://github.com/corsisechero/CVE-2019-9193byVulHub](https://github.com/corsisechero/CVE-2019-9193byVulHub) :  ![starts](https://img.shields.io/github/stars/corsisechero/CVE-2019-9193byVulHub.svg) ![forks](https://img.shields.io/github/forks/corsisechero/CVE-2019-9193byVulHub.svg)

