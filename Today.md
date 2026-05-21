# Update 2026-05-21
## CVE-2026-45185
 Exim before 4.99.3, in certain GnuTLS configurations, has a remotely reachable use-after-free in the BDAT body parsing path. It is triggered when a client sends a TLS close_notify mid-body during a CHUNKING transfer, followed by a final cleartext byte on the same TCP connection. This can lead to heap corruption. An unauthenticated network attacker exploiting this vulnerability could execute arbitrary code.

- [https://github.com/MJ-bin/POC_CVE-2026-45185](https://github.com/MJ-bin/POC_CVE-2026-45185) :  ![starts](https://img.shields.io/github/stars/MJ-bin/POC_CVE-2026-45185.svg) ![forks](https://img.shields.io/github/forks/MJ-bin/POC_CVE-2026-45185.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/LucasPDiniz/CVE-2026-43284](https://github.com/LucasPDiniz/CVE-2026-43284) :  ![starts](https://img.shields.io/github/stars/LucasPDiniz/CVE-2026-43284.svg) ![forks](https://img.shields.io/github/forks/LucasPDiniz/CVE-2026-43284.svg)
- [https://github.com/kuniyal08/Dirty-Frag-CVE-2026-43284](https://github.com/kuniyal08/Dirty-Frag-CVE-2026-43284) :  ![starts](https://img.shields.io/github/stars/kuniyal08/Dirty-Frag-CVE-2026-43284.svg) ![forks](https://img.shields.io/github/forks/kuniyal08/Dirty-Frag-CVE-2026-43284.svg)


## CVE-2026-42945
 NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module. This vulnerability exists when the rewrite directive is followed by a rewrite, if, or set directive and an unnamed Perl-Compatible Regular Expression (PCRE) capture (for example, $1, $2) with a replacement string that includes a question mark (?). An unauthenticated attacker along with conditions beyond its control can exploit this vulnerability by sending crafted HTTP requests. This may cause a heap buffer overflow in the NGINX worker process leading to a restart. Additionally, for systems with Address Space Layout Randomization (ASLR ) disabled, code execution is possible.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/RedCrazyGhost/CVE-2026-42945](https://github.com/RedCrazyGhost/CVE-2026-42945) :  ![starts](https://img.shields.io/github/stars/RedCrazyGhost/CVE-2026-42945.svg) ![forks](https://img.shields.io/github/forks/RedCrazyGhost/CVE-2026-42945.svg)
- [https://github.com/gagaltotal/CVE-2026-42945-NGINX-Rift-Scanner](https://github.com/gagaltotal/CVE-2026-42945-NGINX-Rift-Scanner) :  ![starts](https://img.shields.io/github/stars/gagaltotal/CVE-2026-42945-NGINX-Rift-Scanner.svg) ![forks](https://img.shields.io/github/forks/gagaltotal/CVE-2026-42945-NGINX-Rift-Scanner.svg)
- [https://github.com/imSre9/CVE-2026-42945](https://github.com/imSre9/CVE-2026-42945) :  ![starts](https://img.shields.io/github/stars/imSre9/CVE-2026-42945.svg) ![forks](https://img.shields.io/github/forks/imSre9/CVE-2026-42945.svg)
- [https://github.com/fkj-src/fix_nginx_cve_2026_42945](https://github.com/fkj-src/fix_nginx_cve_2026_42945) :  ![starts](https://img.shields.io/github/stars/fkj-src/fix_nginx_cve_2026_42945.svg) ![forks](https://img.shields.io/github/forks/fkj-src/fix_nginx_cve_2026_42945.svg)
- [https://github.com/BarAppTeam/nginx-cve-fix](https://github.com/BarAppTeam/nginx-cve-fix) :  ![starts](https://img.shields.io/github/stars/BarAppTeam/nginx-cve-fix.svg) ![forks](https://img.shields.io/github/forks/BarAppTeam/nginx-cve-fix.svg)


## CVE-2026-42097
The vendor was notified early about this vulnerability, but didn't respond with the details of vulnerability or vulnerable version range. Only version 6.1 (build 167) and below were tested and confirmed as vulnerable, other versions were not tested and might also be vulnerable.

- [https://github.com/br0xpl/sparx_hack](https://github.com/br0xpl/sparx_hack) :  ![starts](https://img.shields.io/github/stars/br0xpl/sparx_hack.svg) ![forks](https://img.shields.io/github/forks/br0xpl/sparx_hack.svg)


## CVE-2026-42096
The vendor was notified early about this vulnerability, but didn't respond with the details of vulnerability or vulnerable version range. Only version 6.1 (build 167) and below were tested and confirmed as vulnerable, other versions were not tested and might also be vulnerable.

- [https://github.com/br0xpl/sparx_hack](https://github.com/br0xpl/sparx_hack) :  ![starts](https://img.shields.io/github/stars/br0xpl/sparx_hack.svg) ![forks](https://img.shields.io/github/forks/br0xpl/sparx_hack.svg)


## CVE-2026-40217
 LiteLLM through 2026-04-08 allows remote attackers to execute arbitrary code via bytecode rewriting at the /guardrails/test_custom_code URI.

- [https://github.com/learner202649/CVE-2026-40217-PoC](https://github.com/learner202649/CVE-2026-40217-PoC) :  ![starts](https://img.shields.io/github/stars/learner202649/CVE-2026-40217-PoC.svg) ![forks](https://img.shields.io/github/forks/learner202649/CVE-2026-40217-PoC.svg)


## CVE-2026-35030
 LiteLLM is a proxy server (AI Gateway) to call LLM APIs in OpenAI (or native) format. Prior to 1.83.0, when JWT authentication is enabled (enable_jwt_auth: true), the OIDC userinfo cache uses token[:20] as the cache key. JWT headers produced by the same signing algorithm generate identical first 20 characters. This configuration option is not enabled by default. Most instances are not affected. An unauthenticated attacker can craft a token whose first 20 characters match a legitimate user's cached token. On cache hit, the attacker inherits the legitimate user's identity and permissions. This affects deployments with JWT/OIDC authentication enabled. Fixed in v1.83.0.

- [https://github.com/learner202649/CVE-2026-35030-PoC](https://github.com/learner202649/CVE-2026-35030-PoC) :  ![starts](https://img.shields.io/github/stars/learner202649/CVE-2026-35030-PoC.svg) ![forks](https://img.shields.io/github/forks/learner202649/CVE-2026-35030-PoC.svg)


## CVE-2026-35029
 LiteLLM is a proxy server (AI Gateway) to call LLM APIs in OpenAI (or native) format. Prior to 1.83.0, the /config/update endpoint does not enforce admin role authorization. A user who is already authenticated into the platform can then use this endpoint to modify proxy configuration and environment variables, register custom pass-through endpoint handlers pointing to attacker-controlled Python code, achieving remote code execution, read arbitrary server files by setting UI_LOGO_PATH and fetching via /get_image, and take over other privileged accounts by overwriting UI_USERNAME and UI_PASSWORD environment variables. Fixed in v1.83.0.

- [https://github.com/learner202649/CVE-2026-35029-PoC](https://github.com/learner202649/CVE-2026-35029-PoC) :  ![starts](https://img.shields.io/github/stars/learner202649/CVE-2026-35029-PoC.svg) ![forks](https://img.shields.io/github/forks/learner202649/CVE-2026-35029-PoC.svg)


## CVE-2026-34486
Users are recommended to upgrade to version 11.0.21, 10.1.54 or 9.0.117, which fix the issue.

- [https://github.com/anonmrc/CVE-2026-34486-e-Tomcat-Tribes](https://github.com/anonmrc/CVE-2026-34486-e-Tomcat-Tribes) :  ![starts](https://img.shields.io/github/stars/anonmrc/CVE-2026-34486-e-Tomcat-Tribes.svg) ![forks](https://img.shields.io/github/forks/anonmrc/CVE-2026-34486-e-Tomcat-Tribes.svg)


## CVE-2026-31635
Reject authenticator lengths that exceed the remaining packet payload.

- [https://github.com/0xBlackash/CVE-2026-31635](https://github.com/0xBlackash/CVE-2026-31635) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-31635.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-31635.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/luotian2/CVE-2026-31431](https://github.com/luotian2/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/luotian2/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/luotian2/CVE-2026-31431.svg)


## CVE-2026-8838
To remediate this issue, users should upgrade to version 2.1.14.

- [https://github.com/Maxime288/CVE-2026-8838-RCE](https://github.com/Maxime288/CVE-2026-8838-RCE) :  ![starts](https://img.shields.io/github/stars/Maxime288/CVE-2026-8838-RCE.svg) ![forks](https://img.shields.io/github/forks/Maxime288/CVE-2026-8838-RCE.svg)


## CVE-2026-4630
 A flaw was found in Keycloak. An authenticated client could exploit an Insecure Direct Object Reference (IDOR) vulnerability in the Authorization Services Protection API endpoint. By knowing or obtaining a resource's unique identifier (UUID) belonging to another Resource Server within the same realm, the client could bypass authorization checks. This allows the client to perform unauthorized GET, PUT, and DELETE operations on resources, leading to information disclosure and potential unauthorized modification or deletion of data.

- [https://github.com/0xBlackash/CVE-2026-46300](https://github.com/0xBlackash/CVE-2026-46300) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-46300.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-46300.svg)
- [https://github.com/Sentebale/CVE-2026-46300](https://github.com/Sentebale/CVE-2026-46300) :  ![starts](https://img.shields.io/github/stars/Sentebale/CVE-2026-46300.svg) ![forks](https://img.shields.io/github/forks/Sentebale/CVE-2026-46300.svg)
- [https://github.com/HORKimhab/CVE-2026-46300](https://github.com/HORKimhab/CVE-2026-46300) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-46300.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-46300.svg)
- [https://github.com/ExploitEoom/CVE-2026-46300](https://github.com/ExploitEoom/CVE-2026-46300) :  ![starts](https://img.shields.io/github/stars/ExploitEoom/CVE-2026-46300.svg) ![forks](https://img.shields.io/github/forks/ExploitEoom/CVE-2026-46300.svg)


## CVE-2026-3674
 A vulnerability was found in Freedom Factory dGEN1 up to 20260221. Affected by this vulnerability is the function FakeAppProvider of the component org.ethosmobile.ethoslauncher. Performing a manipulation results in improper authorization. The attack must be initiated from a local position. The exploit has been made public and could be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/rufflabs/CVE-2026-36748](https://github.com/rufflabs/CVE-2026-36748) :  ![starts](https://img.shields.io/github/stars/rufflabs/CVE-2026-36748.svg) ![forks](https://img.shields.io/github/forks/rufflabs/CVE-2026-36748.svg)


## CVE-2026-3069
 A security vulnerability has been detected in itsourcecode Document Management System 1.0. Affected is an unknown function of the file /edtlbls.php. The manipulation of the argument field1 leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed publicly and may be used.

- [https://github.com/walidriouah/CVE-2026-30691](https://github.com/walidriouah/CVE-2026-30691) :  ![starts](https://img.shields.io/github/stars/walidriouah/CVE-2026-30691.svg) ![forks](https://img.shields.io/github/forks/walidriouah/CVE-2026-30691.svg)


## CVE-2025-60542
 SQL Injection vulnerability in TypeORM before 0.3.26 via crafted request to repository.save or repository.update due to the sqlstring call using stringifyObjects default to false.

- [https://github.com/cavadalizada/typeorm-sqli](https://github.com/cavadalizada/typeorm-sqli) :  ![starts](https://img.shields.io/github/stars/cavadalizada/typeorm-sqli.svg) ![forks](https://img.shields.io/github/forks/cavadalizada/typeorm-sqli.svg)


## CVE-2025-59139
 Hono is a Web application framework that provides support for any JavaScript runtime. In versions prior to 4.9.7, a flaw in the `bodyLimit` middleware could allow bypassing the configured request body size limit when conflicting HTTP headers were present. The middleware previously prioritized the `Content-Length` header even when a `Transfer-Encoding: chunked` header was also included. According to the HTTP specification, `Content-Length` must be ignored in such cases. This discrepancy could allow oversized request bodies to bypass the configured limit. Most standards-compliant runtimes and reverse proxies may reject such malformed requests with `400 Bad Request`, so the practical impact depends on the runtime and deployment environment. If body size limits are used as a safeguard against large or malicious requests, this flaw could allow attackers to send oversized request bodies. The primary risk is denial of service (DoS) due to excessive memory or CPU consumption when handling very large requests. The implementation has been updated to align with the HTTP specification, ensuring that `Transfer-Encoding` takes precedence over `Content-Length`. The issue is fixed in Hono v4.9.7, and all users should upgrade immediately.

- [https://github.com/RoninForge/roninforge-hono](https://github.com/RoninForge/roninforge-hono) :  ![starts](https://img.shields.io/github/stars/RoninForge/roninforge-hono.svg) ![forks](https://img.shields.io/github/forks/RoninForge/roninforge-hono.svg)


## CVE-2025-45809
 SQL Injection vulnerability in BerriAI LiteLLM before 1.81.0 allows attackers to execute arbitrary commands via the key parameter to the "/key/block" and "/key/unblock" API endpoints.

- [https://github.com/learner202649/CVE-2025-45809-PoC](https://github.com/learner202649/CVE-2025-45809-PoC) :  ![starts](https://img.shields.io/github/stars/learner202649/CVE-2025-45809-PoC.svg) ![forks](https://img.shields.io/github/forks/learner202649/CVE-2025-45809-PoC.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/gitgudKrish/cve-2025-29927-nextjs](https://github.com/gitgudKrish/cve-2025-29927-nextjs) :  ![starts](https://img.shields.io/github/stars/gitgudKrish/cve-2025-29927-nextjs.svg) ![forks](https://img.shields.io/github/forks/gitgudKrish/cve-2025-29927-nextjs.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/suil12/CVE-2025-24813_presentation](https://github.com/suil12/CVE-2025-24813_presentation) :  ![starts](https://img.shields.io/github/stars/suil12/CVE-2025-24813_presentation.svg) ![forks](https://img.shields.io/github/forks/suil12/CVE-2025-24813_presentation.svg)


## CVE-2025-7771
 ThrottleStop.sys, a legitimate driver, exposes two IOCTL interfaces that allow arbitrary read and write access to physical memory via the MmMapIoSpace function. This insecure implementation can be exploited by a malicious user-mode application to patch the running Windows kernel and invoke arbitrary kernel functions with ring-0 privileges. The vulnerability enables local attackers to execute arbitrary code in kernel context, resulting in privilege escalation and potential follow-on attacks, such as disabling security software or bypassing kernel-level protections. ThrottleStop.sys version 3.0.0.0 and possibly others are affected. Apply updates per vendor instructions.

- [https://github.com/DeathShotXD/0xKern3lCrush](https://github.com/DeathShotXD/0xKern3lCrush) :  ![starts](https://img.shields.io/github/stars/DeathShotXD/0xKern3lCrush.svg) ![forks](https://img.shields.io/github/forks/DeathShotXD/0xKern3lCrush.svg)


## CVE-2024-41570
 An Unauthenticated Server-Side Request Forgery (SSRF) in demon callback handling in Havoc 2 0.7 allows attackers to send arbitrary network traffic originating from the team server.

- [https://github.com/leo-mitch/CVE-2024-41570-Havoc-C2-RCE](https://github.com/leo-mitch/CVE-2024-41570-Havoc-C2-RCE) :  ![starts](https://img.shields.io/github/stars/leo-mitch/CVE-2024-41570-Havoc-C2-RCE.svg) ![forks](https://img.shields.io/github/forks/leo-mitch/CVE-2024-41570-Havoc-C2-RCE.svg)


## CVE-2024-37054
 Deserialization of untrusted data can occur in versions of the MLflow platform running version 0.9.0 or newer, enabling a maliciously uploaded PyFunc model to run arbitrary code on an end user’s system when interacted with.

- [https://github.com/tristanqtn/CVE-2024-37054](https://github.com/tristanqtn/CVE-2024-37054) :  ![starts](https://img.shields.io/github/stars/tristanqtn/CVE-2024-37054.svg) ![forks](https://img.shields.io/github/forks/tristanqtn/CVE-2024-37054.svg)


## CVE-2024-36420
 Flowise is a drag & drop user interface to build a customized large language model flow. In version 1.4.3 of Flowise, the `/api/v1/openai-assistants-file` endpoint in `index.ts` is vulnerable to arbitrary file read due to lack of sanitization of the `fileName` body parameter. No known patches for this issue are available.

- [https://github.com/fineman999/POC_CVE-2024-36420](https://github.com/fineman999/POC_CVE-2024-36420) :  ![starts](https://img.shields.io/github/stars/fineman999/POC_CVE-2024-36420.svg) ![forks](https://img.shields.io/github/forks/fineman999/POC_CVE-2024-36420.svg)


## CVE-2024-25641
 Cacti provides an operational monitoring and fault management framework. Prior to version 1.2.27, an arbitrary file write vulnerability, exploitable through the "Package Import" feature, allows authenticated users having the "Import Templates" permission to execute arbitrary PHP code on the web server. The vulnerability is located within the `import_package()` function defined into the `/lib/import.php` script. The function blindly trusts the filename and file content provided within the XML data, and writes such files into the Cacti base path (or even outside, since path traversal sequences are not filtered). This can be exploited to write or overwrite arbitrary files on the web server, leading to execution of arbitrary PHP code or other security impacts. Version 1.2.27 contains a patch for this issue.

- [https://github.com/leo-mitch/CVE-2024-25641-RCE-Automated-Exploit-Cacti-1.2.26](https://github.com/leo-mitch/CVE-2024-25641-RCE-Automated-Exploit-Cacti-1.2.26) :  ![starts](https://img.shields.io/github/stars/leo-mitch/CVE-2024-25641-RCE-Automated-Exploit-Cacti-1.2.26.svg) ![forks](https://img.shields.io/github/forks/leo-mitch/CVE-2024-25641-RCE-Automated-Exploit-Cacti-1.2.26.svg)


## CVE-2024-23222
 A type confusion issue was addressed with improved checks. This issue is fixed in Safari 17.3, iOS 15.8.7 and iPadOS 15.8.7, iOS 16.7.5 and iPadOS 16.7.5, iOS 17.3 and iPadOS 17.3, macOS Monterey 12.7.3, macOS Sonoma 14.3, macOS Ventura 13.6.4, tvOS 17.3, visionOS 1.0.2. Processing maliciously crafted web content may lead to arbitrary code execution. This fix associated with the Coruna exploit was shipped in iOS 17.3 on January 22, 2024. This update brings that fix to devices that cannot update to the latest iOS version.

- [https://github.com/Umit-MHL/webkit-cve-2024-23222](https://github.com/Umit-MHL/webkit-cve-2024-23222) :  ![starts](https://img.shields.io/github/stars/Umit-MHL/webkit-cve-2024-23222.svg) ![forks](https://img.shields.io/github/forks/Umit-MHL/webkit-cve-2024-23222.svg)


## CVE-2024-21490
This package is EOL and will not receive any updates to address this issue. Users should migrate to [@angular/core](https://www.npmjs.com/package/@angular/core).

- [https://github.com/RoninForge/roninforge-angularjs-migration](https://github.com/RoninForge/roninforge-angularjs-migration) :  ![starts](https://img.shields.io/github/stars/RoninForge/roninforge-angularjs-migration.svg) ![forks](https://img.shields.io/github/forks/RoninForge/roninforge-angularjs-migration.svg)


## CVE-2024-12886
 An Out-Of-Memory (OOM) vulnerability exists in the `ollama` server version 0.3.14. This vulnerability can be triggered when a malicious API server responds with a gzip bomb HTTP response, leading to the `ollama` server crashing. The vulnerability is present in the `makeRequestWithRetry` and `getAuthorizationToken` functions, which use `io.ReadAll` to read the response body. This can result in excessive memory usage and a Denial of Service (DoS) condition.

- [https://github.com/dannyEndorTest/ollama](https://github.com/dannyEndorTest/ollama) :  ![starts](https://img.shields.io/github/stars/dannyEndorTest/ollama.svg) ![forks](https://img.shields.io/github/forks/dannyEndorTest/ollama.svg)
- [https://github.com/dannyEndorTest/ollama-consumer](https://github.com/dannyEndorTest/ollama-consumer) :  ![starts](https://img.shields.io/github/stars/dannyEndorTest/ollama-consumer.svg) ![forks](https://img.shields.io/github/forks/dannyEndorTest/ollama-consumer.svg)


## CVE-2024-10821
 A Denial of Service (DoS) vulnerability in the multipart request boundary processing mechanism of the Invoke-AI server (version v5.0.1) allows unauthenticated attackers to cause excessive resource consumption. The server fails to handle excessive characters appended to the end of multipart boundaries, leading to an infinite loop and a complete denial of service for all users. The affected endpoint is `/api/v1/images/upload`.

- [https://github.com/dannyEndorTest/invokeai](https://github.com/dannyEndorTest/invokeai) :  ![starts](https://img.shields.io/github/stars/dannyEndorTest/invokeai.svg) ![forks](https://img.shields.io/github/forks/dannyEndorTest/invokeai.svg)
- [https://github.com/dannyEndorTest/invokeai-consumer](https://github.com/dannyEndorTest/invokeai-consumer) :  ![starts](https://img.shields.io/github/stars/dannyEndorTest/invokeai-consumer.svg) ![forks](https://img.shields.io/github/forks/dannyEndorTest/invokeai-consumer.svg)


## CVE-2023-32692
 CodeIgniter is a PHP full-stack web framework. This vulnerability allows attackers to execute arbitrary code when you use Validation Placeholders. The vulnerability exists in the Validation library, and validation methods in the controller and in-model validation are also vulnerable because they use the Validation library internally. This issue is patched in version 4.3.5.

- [https://github.com/mogwailabs/CVE-2023-32692-CodeIgniter4](https://github.com/mogwailabs/CVE-2023-32692-CodeIgniter4) :  ![starts](https://img.shields.io/github/stars/mogwailabs/CVE-2023-32692-CodeIgniter4.svg) ![forks](https://img.shields.io/github/forks/mogwailabs/CVE-2023-32692-CodeIgniter4.svg)


## CVE-2023-29401
 The filename parameter of the Context.FileAttachment function is not properly sanitized. A maliciously crafted filename can cause the Content-Disposition header to be sent with an unexpected filename value or otherwise modify the Content-Disposition header. For example, a filename of "setup.bat&quot;;x=.txt" will be sent as a file named "setup.bat". If the FileAttachment function is called with names provided by an untrusted source, this may permit an attacker to cause a file to be served with a name different than provided. Maliciously crafted attachment file name can modify the Content-Disposition header.

- [https://github.com/dannyEndorTest/gin-vulnerable](https://github.com/dannyEndorTest/gin-vulnerable) :  ![starts](https://img.shields.io/github/stars/dannyEndorTest/gin-vulnerable.svg) ![forks](https://img.shields.io/github/forks/dannyEndorTest/gin-vulnerable.svg)


## CVE-2021-23797
 All versions of package http-server-node are vulnerable to Directory Traversal via use of --path-as-is.

- [https://github.com/dannyEndorTest/http-server-node](https://github.com/dannyEndorTest/http-server-node) :  ![starts](https://img.shields.io/github/stars/dannyEndorTest/http-server-node.svg) ![forks](https://img.shields.io/github/forks/dannyEndorTest/http-server-node.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/jayhutajulu1/PwnKit-CVE-2021-4034](https://github.com/jayhutajulu1/PwnKit-CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/jayhutajulu1/PwnKit-CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/jayhutajulu1/PwnKit-CVE-2021-4034.svg)


## CVE-2020-17103
 Windows Cloud Files Mini Filter Driver Elevation of Privilege Vulnerability

- [https://github.com/AlexLinov/MiniPlasma-Runner](https://github.com/AlexLinov/MiniPlasma-Runner) :  ![starts](https://img.shields.io/github/stars/AlexLinov/MiniPlasma-Runner.svg) ![forks](https://img.shields.io/github/forks/AlexLinov/MiniPlasma-Runner.svg)


## CVE-2020-7602
 node-prompt-here through 1.0.1 allows execution of arbitrary commands. The "runCommand()" is called by "getDevices()" function in file "linux/manager.js", which is required by the "index. process.env.NM_CLI" in the file "linux/manager.js". This function is used to construct the argument of function "execSync()", which can be controlled by users without any sanitization.

- [https://github.com/dannyEndorTest/node-prompt-here](https://github.com/dannyEndorTest/node-prompt-here) :  ![starts](https://img.shields.io/github/stars/dannyEndorTest/node-prompt-here.svg) ![forks](https://img.shields.io/github/forks/dannyEndorTest/node-prompt-here.svg)


## CVE-2019-2725
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Web Services). Supported versions that are affected are 10.3.6.0.0 and 12.1.3.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/peterpeter228/CNTA-2019-0014xCVE-2019-2725](https://github.com/peterpeter228/CNTA-2019-0014xCVE-2019-2725) :  ![starts](https://img.shields.io/github/stars/peterpeter228/CNTA-2019-0014xCVE-2019-2725.svg) ![forks](https://img.shields.io/github/forks/peterpeter228/CNTA-2019-0014xCVE-2019-2725.svg)


## CVE-2017-0143
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0144, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/FernandoTDalcin/thm-blue-writeup](https://github.com/FernandoTDalcin/thm-blue-writeup) :  ![starts](https://img.shields.io/github/stars/FernandoTDalcin/thm-blue-writeup.svg) ![forks](https://img.shields.io/github/forks/FernandoTDalcin/thm-blue-writeup.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka "Dirty COW."

- [https://github.com/SaanviShah30/IoT-Firmware-Reverse-Engineering](https://github.com/SaanviShah30/IoT-Firmware-Reverse-Engineering) :  ![starts](https://img.shields.io/github/stars/SaanviShah30/IoT-Firmware-Reverse-Engineering.svg) ![forks](https://img.shields.io/github/forks/SaanviShah30/IoT-Firmware-Reverse-Engineering.svg)


## CVE-2007-2447
 The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function, when the "username map script" smb.conf option is enabled, and allows remote authenticated users to execute commands via shell metacharacters involving other MS-RPC functions in the (2) remote printer and (3) file share management.

- [https://github.com/Youneskc/SMB-Penetration-Testing-NTLM-Relay-Version-2-](https://github.com/Youneskc/SMB-Penetration-Testing-NTLM-Relay-Version-2-) :  ![starts](https://img.shields.io/github/stars/Youneskc/SMB-Penetration-Testing-NTLM-Relay-Version-2-.svg) ![forks](https://img.shields.io/github/forks/Youneskc/SMB-Penetration-Testing-NTLM-Relay-Version-2-.svg)

