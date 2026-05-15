# Update 2026-05-15
## CVE-2026-45321
 On 2026-05-11, between approximately 19:20 and 19:26 UTC, 84 malicious versions across 42 @tanstack/* packages were published to the npm registry. The publishes were authenticated via the legitimate GitHub Actions OIDC trusted-publisher binding for TanStack/router, but the publish workflow itself was not modified. The attacker chained three known vulnerability classes — a pull_request_target "Pwn Request" misconfiguration, GitHub Actions cache poisoning across the fork↔base trust boundary, and runtime memory extraction of the OIDC token from the Actions runner process — to publish credential-stealing malware under a trusted identity. Each affected package received exactly two malicious versions, published a few minutes apart.

- [https://github.com/Yomisana/are-you-get-tanstack-attack](https://github.com/Yomisana/are-you-get-tanstack-attack) :  ![starts](https://img.shields.io/github/stars/Yomisana/are-you-get-tanstack-attack.svg) ![forks](https://img.shields.io/github/forks/Yomisana/are-you-get-tanstack-attack.svg)
- [https://github.com/Intrudify/mini-shai-hulud-scanner](https://github.com/Intrudify/mini-shai-hulud-scanner) :  ![starts](https://img.shields.io/github/stars/Intrudify/mini-shai-hulud-scanner.svg) ![forks](https://img.shields.io/github/forks/Intrudify/mini-shai-hulud-scanner.svg)
- [https://github.com/Breakingcircuitsllc/teampcp_shai_hulud.yar](https://github.com/Breakingcircuitsllc/teampcp_shai_hulud.yar) :  ![starts](https://img.shields.io/github/stars/Breakingcircuitsllc/teampcp_shai_hulud.yar.svg) ![forks](https://img.shields.io/github/forks/Breakingcircuitsllc/teampcp_shai_hulud.yar.svg)


## CVE-2026-44582
 Next.js is a React framework for building full-stack web applications. From 13.4.6 to before 15.5.16 and 16.2.5, React Server Component responses can be vulnerable to cache poisoning in deployments that rely on shared caches with insufficient response partitioning. In affected conditions, collisions in the _rsc cache-busting value can allow an attacker to poison cache entries so users receive the wrong response variant for a given URL. This vulnerability is fixed in 15.5.16 and 16.2.5.

- [https://github.com/dwisiswant0/next-16.2.4-pocs](https://github.com/dwisiswant0/next-16.2.4-pocs) :  ![starts](https://img.shields.io/github/stars/dwisiswant0/next-16.2.4-pocs.svg) ![forks](https://img.shields.io/github/forks/dwisiswant0/next-16.2.4-pocs.svg)


## CVE-2026-44581
 Next.js is a React framework for building full-stack web applications. From 13.4.0 to before 15.5.16 and 16.2.5, App Router applications that rely on CSP nonces can be vulnerable to stored cross-site scripting when deployed behind shared caches. In affected versions, malformed nonce values derived from request headers could be reflected into rendered HTML in an unsafe way, allowing an attacker to poison cached responses and cause script execution for later visitors. This vulnerability is fixed in 15.5.16 and 16.2.5.

- [https://github.com/dwisiswant0/next-16.2.4-pocs](https://github.com/dwisiswant0/next-16.2.4-pocs) :  ![starts](https://img.shields.io/github/stars/dwisiswant0/next-16.2.4-pocs.svg) ![forks](https://img.shields.io/github/forks/dwisiswant0/next-16.2.4-pocs.svg)


## CVE-2026-44580
 Next.js is a React framework for building full-stack web applications. From 13.0.0 to before 15.5.16 and 16.2.5, applications that use beforeInteractive scripts together with untrusted content can be vulnerable to cross-site scripting. In affected versions, serialized script content was not escaped safely before being embedded into the document, which could allow attacker-controlled input to break out of the intended script context and execute arbitrary JavaScript in a visitor's browser. This vulnerability is fixed in 15.5.16 and 16.2.5.

- [https://github.com/dwisiswant0/next-16.2.4-pocs](https://github.com/dwisiswant0/next-16.2.4-pocs) :  ![starts](https://img.shields.io/github/stars/dwisiswant0/next-16.2.4-pocs.svg) ![forks](https://img.shields.io/github/forks/dwisiswant0/next-16.2.4-pocs.svg)


## CVE-2026-44579
 Next.js is a React framework for building full-stack web applications. From  to before 15.5.16 and 16.2.5, applications using Partial Prerendering through the Cache Components feature can be vulnerable to connection exhaustion through crafted POST requests to a server action. In affected configurations, a malicious request can trigger a request-body handling deadlock that leaves connections open for an extended period, consuming file descriptors and server capacity until legitimate users are denied service. This vulnerability is fixed in 15.5.16 and 16.2.5.

- [https://github.com/dwisiswant0/next-16.2.4-pocs](https://github.com/dwisiswant0/next-16.2.4-pocs) :  ![starts](https://img.shields.io/github/stars/dwisiswant0/next-16.2.4-pocs.svg) ![forks](https://img.shields.io/github/forks/dwisiswant0/next-16.2.4-pocs.svg)
- [https://github.com/iamfarzad/fbconsulting_v0_chat](https://github.com/iamfarzad/fbconsulting_v0_chat) :  ![starts](https://img.shields.io/github/stars/iamfarzad/fbconsulting_v0_chat.svg) ![forks](https://img.shields.io/github/forks/iamfarzad/fbconsulting_v0_chat.svg)
- [https://github.com/iamfarzad/fbcounsulting_v2](https://github.com/iamfarzad/fbcounsulting_v2) :  ![starts](https://img.shields.io/github/stars/iamfarzad/fbcounsulting_v2.svg) ![forks](https://img.shields.io/github/forks/iamfarzad/fbcounsulting_v2.svg)


## CVE-2026-44578
 Next.js is a React framework for building full-stack web applications. From 13.4.13 to before 15.5.16 and 16.2.5, self-hosted applications using the built-in Node.js server can be vulnerable to server-side request forgery through crafted WebSocket upgrade requests. An attacker can cause the server to proxy requests to arbitrary internal or external destinations, which may expose internal services or cloud metadata endpoints. Vercel-hosted deployments are not affected. This vulnerability is fixed in 15.5.16 and 16.2.5.

- [https://github.com/dwisiswant0/next-16.2.4-pocs](https://github.com/dwisiswant0/next-16.2.4-pocs) :  ![starts](https://img.shields.io/github/stars/dwisiswant0/next-16.2.4-pocs.svg) ![forks](https://img.shields.io/github/forks/dwisiswant0/next-16.2.4-pocs.svg)
- [https://github.com/panchocosil/verify-ghsa-c4j6-fc7j-m34r](https://github.com/panchocosil/verify-ghsa-c4j6-fc7j-m34r) :  ![starts](https://img.shields.io/github/stars/panchocosil/verify-ghsa-c4j6-fc7j-m34r.svg) ![forks](https://img.shields.io/github/forks/panchocosil/verify-ghsa-c4j6-fc7j-m34r.svg)


## CVE-2026-44577
 Next.js is a React framework for building full-stack web applications. From 10.0.0 to before 15.5.16 and 16.2.5, when self-hosting Next.js with the default image loader, the Image Optimization API fetches local images entirely into memory without enforcing a maximum size limit. An attacker could cause out-of-memory conditions by requesting large local assets from the /_next/image endpoint that match the images.localPatterns configuration (by default, all patterns are allowed). This vulnerability is fixed in 15.5.16 and 16.2.5.

- [https://github.com/dwisiswant0/next-16.2.4-pocs](https://github.com/dwisiswant0/next-16.2.4-pocs) :  ![starts](https://img.shields.io/github/stars/dwisiswant0/next-16.2.4-pocs.svg) ![forks](https://img.shields.io/github/forks/dwisiswant0/next-16.2.4-pocs.svg)


## CVE-2026-44576
 Next.js is a React framework for building full-stack web applications. From 14.2.0 to before 15.5.16 and 16.2.5, applications using React Server Components can be vulnerable to cache poisoning when shared caches do not correctly partition response variants. Under affected conditions, an attacker can cause an RSC response to be served from the original URL and poison shared cache entries so later visitors receive component payloads instead of the expected HTML. This vulnerability is fixed in 15.5.16 and 16.2.5.

- [https://github.com/dwisiswant0/next-16.2.4-pocs](https://github.com/dwisiswant0/next-16.2.4-pocs) :  ![starts](https://img.shields.io/github/stars/dwisiswant0/next-16.2.4-pocs.svg) ![forks](https://img.shields.io/github/forks/dwisiswant0/next-16.2.4-pocs.svg)


## CVE-2026-44575
 Next.js is a React framework for building full-stack web applications. From 15.2.0 to before 15.5.16 and 16.2.5, App Router applications that rely on middleware or proxy-based checks for authorization can allow unauthorized access through transport-specific route variants used for segment prefetching. In affected configurations, specially crafted .rsc and segment-prefetch URLs can resolve to the same page without being matched by the intended middleware rule, which can allow protected content to be reached without the expected authorization check. This vulnerability is fixed in 15.5.16 and 16.2.5.

- [https://github.com/dwisiswant0/next-16.2.4-pocs](https://github.com/dwisiswant0/next-16.2.4-pocs) :  ![starts](https://img.shields.io/github/stars/dwisiswant0/next-16.2.4-pocs.svg) ![forks](https://img.shields.io/github/forks/dwisiswant0/next-16.2.4-pocs.svg)


## CVE-2026-44574
 Next.js is a React framework for building full-stack web applications. From 15.4.0 to before 15.5.16 and 16.2.5, applications that rely on middleware to protect dynamic routes can be vulnerable to authorization bypass. In affected deployments, specially crafted query parameters can alter the dynamic route value seen by the page while leaving the visible path unchanged, which can allow protected content to be rendered without passing the expected middleware check. This vulnerability is fixed in 15.5.16 and 16.2.5.

- [https://github.com/dwisiswant0/next-16.2.4-pocs](https://github.com/dwisiswant0/next-16.2.4-pocs) :  ![starts](https://img.shields.io/github/stars/dwisiswant0/next-16.2.4-pocs.svg) ![forks](https://img.shields.io/github/forks/dwisiswant0/next-16.2.4-pocs.svg)


## CVE-2026-44573
 Next.js is a React framework for building full-stack web applications. From 12.2.0 to before 15.5.16 and 16.2.5, Applications using the Pages Router with i18n configured and middleware/proxy-based authorization can allow unauthorized access to protected page data through locale-less /_next/data/buildId/page.json requests. In affected configurations, middleware does not run for the unprefixed data route, allowing an attacker to retrieve SSR JSON for protected pages without passing the intended authorization checks. This vulnerability is fixed in 15.5.16 and 16.2.5.

- [https://github.com/dwisiswant0/next-16.2.4-pocs](https://github.com/dwisiswant0/next-16.2.4-pocs) :  ![starts](https://img.shields.io/github/stars/dwisiswant0/next-16.2.4-pocs.svg) ![forks](https://img.shields.io/github/forks/dwisiswant0/next-16.2.4-pocs.svg)


## CVE-2026-44572
 Next.js is a React framework for building full-stack web applications. From 12.2.0 to before 15.5.16 and 16.2.5, an external client could send a x-nextjs-data header on a normal request to a path handled by middleware that returns a redirect. When that happened, the middleware/proxy could treat the request as a data request and replace the standard Location redirect header with the internal x-nextjs-redirect header. Browsers do not follow x-nextjs-redirect, so the response became an unusable redirect for normal clients. If the application was deployed behind a CDN or reverse proxy that caches 3xx responses without varying on this header, a single attacker request could poison the cached redirect response for the affected path. Subsequent visitors could then receive a cached redirect response without a Location header, causing a denial of service for that redirect path until the cache entry expired or was purged. This vulnerability is fixed in 15.5.16 and 16.2.5.

- [https://github.com/dwisiswant0/next-16.2.4-pocs](https://github.com/dwisiswant0/next-16.2.4-pocs) :  ![starts](https://img.shields.io/github/stars/dwisiswant0/next-16.2.4-pocs.svg) ![forks](https://img.shields.io/github/forks/dwisiswant0/next-16.2.4-pocs.svg)


## CVE-2026-44277
 A improper access control vulnerability in Fortinet FortiAuthenticator 8.0.2, FortiAuthenticator 8.0.0, FortiAuthenticator 6.6.0 through 6.6.8, FortiAuthenticator 6.5.0 through 6.5.6 may allow attacker to execute unauthorized code or commands via insert attack vector here

- [https://github.com/0xBlackash/CVE-2026-44277](https://github.com/0xBlackash/CVE-2026-44277) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-44277.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-44277.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/FrosterDL/CVE-2026-43284](https://github.com/FrosterDL/CVE-2026-43284) :  ![starts](https://img.shields.io/github/stars/FrosterDL/CVE-2026-43284.svg) ![forks](https://img.shields.io/github/forks/FrosterDL/CVE-2026-43284.svg)
- [https://github.com/ChernStepanov/DirtyFrag-for-dummies](https://github.com/ChernStepanov/DirtyFrag-for-dummies) :  ![starts](https://img.shields.io/github/stars/ChernStepanov/DirtyFrag-for-dummies.svg) ![forks](https://img.shields.io/github/forks/ChernStepanov/DirtyFrag-for-dummies.svg)


## CVE-2026-42945
 NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module. This vulnerability exists when the rewrite directive is followed by a rewrite, if, or set directive and an unnamed Perl-Compatible Regular Expression (PCRE) capture (for example, $1, $2) with a replacement string that includes a question mark (?). An unauthenticated attacker along with conditions beyond its control can exploit this vulnerability by sending crafted HTTP requests. This may cause a heap buffer overflow in the NGINX worker process leading to a restart. Additionally, for systems with Address Space Layout Randomization (ASLR ) disabled, code execution is possible.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/DepthFirstDisclosures/Nginx-Rift](https://github.com/DepthFirstDisclosures/Nginx-Rift) :  ![starts](https://img.shields.io/github/stars/DepthFirstDisclosures/Nginx-Rift.svg) ![forks](https://img.shields.io/github/forks/DepthFirstDisclosures/Nginx-Rift.svg)


## CVE-2026-40369
 Untrusted pointer dereference in Windows Kernel allows an authorized attacker to elevate privileges locally.

- [https://github.com/orinimron123/CVE-2026-40369-EXPLOIT](https://github.com/orinimron123/CVE-2026-40369-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/orinimron123/CVE-2026-40369-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/orinimron123/CVE-2026-40369-EXPLOIT.svg)


## CVE-2026-33626
 LMDeploy is a toolkit for compressing, deploying, and serving large language models. Versions prior to 0.12.3 have a Server-Side Request Forgery (SSRF) vulnerability in LMDeploy's vision-language module. The `load_image()` function in `lmdeploy/vl/utils.py` fetches arbitrary URLs without validating internal/private IP addresses, allowing attackers to access cloud metadata services, internal networks, and sensitive resources. Version 0.12.3 patches the issue.

- [https://github.com/rootdirective-sec/CVE-2026-33626-Lab](https://github.com/rootdirective-sec/CVE-2026-33626-Lab) :  ![starts](https://img.shields.io/github/stars/rootdirective-sec/CVE-2026-33626-Lab.svg) ![forks](https://img.shields.io/github/forks/rootdirective-sec/CVE-2026-33626-Lab.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/gbonacini/CVE-2026-31431](https://github.com/gbonacini/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/gbonacini/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/gbonacini/CVE-2026-31431.svg)


## CVE-2026-31156
 A path injection vulnerability exists in OpenPLC v3 (2c82b0e79c53f8c1f1458eee15fec173400d6e1a) as the binary program compiled from glue_generator.cpp does not perform any validation on the file path parameters passed via the command line. The user-controlled input parameters are directly passed to the underlying file operation functions (fopen/ifstream/ofstream) for file reading and writing. An attacker can exploit this vulnerability by constructing a malicious path to read arbitrary readable files.

- [https://github.com/unicorn-hyh/CVE-2026-31156](https://github.com/unicorn-hyh/CVE-2026-31156) :  ![starts](https://img.shields.io/github/stars/unicorn-hyh/CVE-2026-31156.svg) ![forks](https://img.shields.io/github/forks/unicorn-hyh/CVE-2026-31156.svg)


## CVE-2026-29204
 Insufficient ownership check in `clientarea.php` allows an authenticated client area user to submit requests using another user’s `addonId` without any ownership validation leading to unauthorized access to the victim's account.

- [https://github.com/bogdanrotariu/cve-2026-29204-whmcs-clientarea-addonid](https://github.com/bogdanrotariu/cve-2026-29204-whmcs-clientarea-addonid) :  ![starts](https://img.shields.io/github/stars/bogdanrotariu/cve-2026-29204-whmcs-clientarea-addonid.svg) ![forks](https://img.shields.io/github/forks/bogdanrotariu/cve-2026-29204-whmcs-clientarea-addonid.svg)


## CVE-2026-23918
Users are recommended to upgrade to version 2.4.67, which fixes the issue.

- [https://github.com/Bencodin/CVE-2026-23918-poc](https://github.com/Bencodin/CVE-2026-23918-poc) :  ![starts](https://img.shields.io/github/stars/Bencodin/CVE-2026-23918-poc.svg) ![forks](https://img.shields.io/github/forks/Bencodin/CVE-2026-23918-poc.svg)


## CVE-2026-23870
 A denial of service vulnerability could be triggered by sending specially crafted HTTP requests to server function endpoints, this could lead to server crashes, out-of-memory exceptions or excessive CPU usage; affecting the following packages: react-server-dom-webpack, react-server-dom-parcel, react-server-dom-turbopack (versions 19.0.0 through 19.0.5, 19.1.0 through 19.1.6, and 19.2.0 through 19.2.5).

- [https://github.com/emresandikci/nextjs-cve-2026-23870-checker](https://github.com/emresandikci/nextjs-cve-2026-23870-checker) :  ![starts](https://img.shields.io/github/stars/emresandikci/nextjs-cve-2026-23870-checker.svg) ![forks](https://img.shields.io/github/forks/emresandikci/nextjs-cve-2026-23870-checker.svg)


## CVE-2026-8196
 A flaw has been found in JeecgBoot 3.9.1. The impacted element is an unknown function of the file jeecg-module-system/jeecg-system-biz/src/main/java/org/jeecg/modules/system/controller/LoginController.java of the component mLogin Endpoint. This manipulation causes authorization bypass. The attack is possible to be carried out remotely. The attack is considered to have high complexity. The exploitability is regarded as difficult. The exploit has been published and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/HORKimhab/CVE-2026-8196](https://github.com/HORKimhab/CVE-2026-8196) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-8196.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-8196.svg)


## CVE-2026-4802
 A flaw was found in Cockpit. This vulnerability allows a remote attacker to achieve arbitrary command execution on the host by exploiting unsanitized user-controlled parameters within crafted links in the system logs user interface (UI). An attacker can inject shell metacharacters and command substitutions into these parameters, leading to the execution of arbitrary shell commands on the affected system. This could result in a complete system compromise.

- [https://github.com/hakaioffsec/CVE-2026-4802](https://github.com/hakaioffsec/CVE-2026-4802) :  ![starts](https://img.shields.io/github/stars/hakaioffsec/CVE-2026-4802.svg) ![forks](https://img.shields.io/github/forks/hakaioffsec/CVE-2026-4802.svg)


## CVE-2026-4060
 The Geo Mashup plugin for WordPress is vulnerable to Time-Based SQL Injection via the 'sort' parameter in all versions up to, and including, 1.13.18. This is due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query. The `esc_sql()` function is applied but is ineffective in the `ORDER BY` context because the value is not enclosed in quotes. Additionally, while a `sanitize_sort_arg()` allowlist-based sanitizer was added in version 1.13.18, it is only applied in the AJAX code path (`sanitize_query_args()`) and not in the `render-map.php` or template tag code paths. This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database via a time-based blind approach.

- [https://github.com/ydking0911/CVE-2026-4060-PoC](https://github.com/ydking0911/CVE-2026-4060-PoC) :  ![starts](https://img.shields.io/github/stars/ydking0911/CVE-2026-4060-PoC.svg) ![forks](https://img.shields.io/github/forks/ydking0911/CVE-2026-4060-PoC.svg)


## CVE-2026-2005
 Heap buffer overflow in PostgreSQL pgcrypto allows a ciphertext provider to execute arbitrary code as the operating system user running the database.  Versions before PostgreSQL 18.2, 17.8, 16.12, 15.16, and 14.21 are affected.

- [https://github.com/var77/CVE-2026-2005](https://github.com/var77/CVE-2026-2005) :  ![starts](https://img.shields.io/github/stars/var77/CVE-2026-2005.svg) ![forks](https://img.shields.io/github/forks/var77/CVE-2026-2005.svg)


## CVE-2026-0073
 In adbd_tls_verify_cert of auth.cpp, there is a possible bypass of wireless ADB mutual authentication due to a logic error in the code. This could lead to remote (proximal/adjacent) code execution as the shell user with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/tc4dy/CVE-2026-0073-PoC-Exploit](https://github.com/tc4dy/CVE-2026-0073-PoC-Exploit) :  ![starts](https://img.shields.io/github/stars/tc4dy/CVE-2026-0073-PoC-Exploit.svg) ![forks](https://img.shields.io/github/forks/tc4dy/CVE-2026-0073-PoC-Exploit.svg)


## CVE-2025-67303
 An issue in ComfyUI-Manager prior to version 3.38 allowed remote attackers to potentially manipulate its configuration and critical data. This was due to the application storing its files in an insufficiently protected location that was accessible via the web interface

- [https://github.com/jcaz2378/ComfyUIrce](https://github.com/jcaz2378/ComfyUIrce) :  ![starts](https://img.shields.io/github/stars/jcaz2378/ComfyUIrce.svg) ![forks](https://img.shields.io/github/forks/jcaz2378/ComfyUIrce.svg)


## CVE-2025-49132
 Pterodactyl is a free, open-source game server management panel. Prior to version 1.11.11, using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated. With the ability to execute arbitrary code it could be used to gain access to the Panel's server, read credentials from the Panel's config, extract sensitive information from the database, access files of servers managed by the panel, etc. This issue has been patched in version 1.11.11. There are no software workarounds for this vulnerability, but use of an external Web Application Firewall (WAF) could help mitigate this attack.

- [https://github.com/symphony2colour/HTB-Pterodactyl-RCE-CVE-2025-49132](https://github.com/symphony2colour/HTB-Pterodactyl-RCE-CVE-2025-49132) :  ![starts](https://img.shields.io/github/stars/symphony2colour/HTB-Pterodactyl-RCE-CVE-2025-49132.svg) ![forks](https://img.shields.io/github/forks/symphony2colour/HTB-Pterodactyl-RCE-CVE-2025-49132.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/KaztoRay/CVE-2025-29927-Research](https://github.com/KaztoRay/CVE-2025-29927-Research) :  ![starts](https://img.shields.io/github/stars/KaztoRay/CVE-2025-29927-Research.svg) ![forks](https://img.shields.io/github/forks/KaztoRay/CVE-2025-29927-Research.svg)
- [https://github.com/lucaschanzx/CVE-2025-29927-PoC](https://github.com/lucaschanzx/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/lucaschanzx/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/lucaschanzx/CVE-2025-29927-PoC.svg)


## CVE-2025-29338
 NXP moal.ko Wi-Fi driver 5.1.7.10 FW version from v17.92.1.p149.43 To v17.92.1.p149.157 was discovered to contain a buffer overflow via the mod_para parameter in the woal_init_module_param function.

- [https://github.com/masjadaan/CVE-2025-29338](https://github.com/masjadaan/CVE-2025-29338) :  ![starts](https://img.shields.io/github/stars/masjadaan/CVE-2025-29338.svg) ![forks](https://img.shields.io/github/forks/masjadaan/CVE-2025-29338.svg)


## CVE-2025-26788
 StrongKey FIDO Server before 4.15.1 treats a non-discoverable (namedcredential) flow as a discoverable transaction.

- [https://github.com/jun2e0/CVE-2025-26788](https://github.com/jun2e0/CVE-2025-26788) :  ![starts](https://img.shields.io/github/stars/jun2e0/CVE-2025-26788.svg) ![forks](https://img.shields.io/github/forks/jun2e0/CVE-2025-26788.svg)


## CVE-2024-32019
 Netdata is an open source observability tool. In affected versions the `ndsudo` tool shipped with affected versions of the Netdata Agent allows an attacker to run arbitrary programs with root permissions. The `ndsudo` tool is packaged as a `root`-owned executable with the SUID bit set. It only runs a restricted set of external commands, but its search paths are supplied by the `PATH` environment variable. This allows an attacker to control where `ndsudo` looks for these commands, which may be a path the attacker has write access to. This may lead to local privilege escalation. This vulnerability has been addressed in versions 1.45.3 and 1.45.2-169. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/kikechans/CVE-2024-32019-Netdata-ndsudo-PrivEsc](https://github.com/kikechans/CVE-2024-32019-Netdata-ndsudo-PrivEsc) :  ![starts](https://img.shields.io/github/stars/kikechans/CVE-2024-32019-Netdata-ndsudo-PrivEsc.svg) ![forks](https://img.shields.io/github/forks/kikechans/CVE-2024-32019-Netdata-ndsudo-PrivEsc.svg)


## CVE-2024-2961
 The iconv() function in the GNU C Library versions 2.39 and older may overflow the output buffer passed to it by up to 4 bytes when converting strings to the ISO-2022-CN-EXT character set, which may be used to crash an application or overwrite a neighbouring variable.

- [https://github.com/rcribelar-nucleus/my-cool-demo-php-code](https://github.com/rcribelar-nucleus/my-cool-demo-php-code) :  ![starts](https://img.shields.io/github/stars/rcribelar-nucleus/my-cool-demo-php-code.svg) ![forks](https://img.shields.io/github/forks/rcribelar-nucleus/my-cool-demo-php-code.svg)


## CVE-2023-4863
 Heap buffer overflow in libwebp in Google Chrome prior to 116.0.5845.187 and libwebp 1.3.2 allowed a remote attacker to perform an out of bounds memory write via a crafted HTML page. (Chromium security severity: Critical)

- [https://github.com/pixelotes/lab-cve-2023-4863](https://github.com/pixelotes/lab-cve-2023-4863) :  ![starts](https://img.shields.io/github/stars/pixelotes/lab-cve-2023-4863.svg) ![forks](https://img.shields.io/github/forks/pixelotes/lab-cve-2023-4863.svg)


## CVE-2021-22204
 Improper neutralization of user data in the DjVu file format in ExifTool versions 7.44 and up allows arbitrary code execution when parsing the malicious image

- [https://github.com/TeddyEngel/CVE-2021-22204](https://github.com/TeddyEngel/CVE-2021-22204) :  ![starts](https://img.shields.io/github/stars/TeddyEngel/CVE-2021-22204.svg) ![forks](https://img.shields.io/github/forks/TeddyEngel/CVE-2021-22204.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/Taisa456/network-security-snort](https://github.com/Taisa456/network-security-snort) :  ![starts](https://img.shields.io/github/stars/Taisa456/network-security-snort.svg) ![forks](https://img.shields.io/github/forks/Taisa456/network-security-snort.svg)

