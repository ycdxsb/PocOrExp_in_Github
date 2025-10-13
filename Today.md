# Update 2025-10-13
## CVE-2025-61777
 Flag Forge is a Capture The Flag (CTF) platform. Starting in version 2.0.0 and prior to version 2.3.2, the `/api/admin/badge-templates` (GET) and `/api/admin/badge-templates/create` (POST) endpoints previously allowed access without authentication or authorization. This could have enabled unauthorized users to retrieve all badge templates and sensitive metadata (createdBy, createdAt, updatedAt) and/or create arbitrary badge templates in the database. This could lead to data exposure, database pollution, or abuse of the badge system. The issue has been fixed in FlagForge v2.3.2. GET, POST, UPDATE, and DELETE endpoints now require authentication. Authorization checks ensure only admins can access and modify badge templates. No reliable workarounds are available.

- [https://github.com/0x0w1z/CVE-2025-61777](https://github.com/0x0w1z/CVE-2025-61777) :  ![starts](https://img.shields.io/github/stars/0x0w1z/CVE-2025-61777.svg) ![forks](https://img.shields.io/github/forks/0x0w1z/CVE-2025-61777.svg)


## CVE-2025-61687
 Flowise is a drag & drop user interface to build a customized large language model flow. A file upload vulnerability in version 3.0.7 of FlowiseAI allows authenticated users to upload arbitrary files without proper validation. This enables attackers to persistently store malicious Node.js web shells on the server, potentially leading to Remote Code Execution (RCE). The system fails to validate file extensions, MIME types, or file content during uploads. As a result, malicious scripts such as Node.js-based web shells can be uploaded and stored persistently on the server. These shells expose HTTP endpoints capable of executing arbitrary commands if triggered. The uploaded shell does not automatically execute, but its presence allows future exploitation via administrator error or chained vulnerabilities. This presents a high-severity threat to system integrity and confidentiality. As of time of publication, no known patched versions are available.

- [https://github.com/nltt-br/CVE-2025-58434-CVE-2025-61687-chain-](https://github.com/nltt-br/CVE-2025-58434-CVE-2025-61687-chain-) :  ![starts](https://img.shields.io/github/stars/nltt-br/CVE-2025-58434-CVE-2025-61687-chain-.svg) ![forks](https://img.shields.io/github/forks/nltt-br/CVE-2025-58434-CVE-2025-61687-chain-.svg)


## CVE-2025-59489
 Unity Runtime before 2025-10-02 on Android, Windows, macOS, and Linux allows argument injection that can result in loading of library code from an unintended location. If an application was built with a version of Unity Editor that had the vulnerable Unity Runtime code, then an adversary may be able to execute code on, and exfiltrate confidential information from, the machine on which that application is running. NOTE: product status is provided for Unity Editor because that is the information available from the Supplier. However, updating Unity Editor typically does not address the effects of the vulnerability; instead, it is necessary to rebuild and redeploy all affected applications.

- [https://github.com/taptap/cve-2025-59489](https://github.com/taptap/cve-2025-59489) :  ![starts](https://img.shields.io/github/stars/taptap/cve-2025-59489.svg) ![forks](https://img.shields.io/github/forks/taptap/cve-2025-59489.svg)


## CVE-2025-58434
 Flowise is a drag & drop user interface to build a customized large language model flow. In version 3.0.5 and earlier, the `forgot-password` endpoint in Flowise returns sensitive information including a valid password reset `tempToken` without authentication or verification. This enables any attacker to generate a reset token for arbitrary users and directly reset their password, leading to a complete account takeover (ATO). This vulnerability applies to both the cloud service (`cloud.flowiseai.com`) and self-hosted/local Flowise deployments that expose the same API. Commit 9e178d68873eb876073846433a596590d3d9c863 in version 3.0.6 secures password reset endpoints. Several recommended remediation steps are available. Do not return reset tokens or sensitive account details in API responses. Tokens must only be delivered securely via the registered email channel. Ensure `forgot-password` responds with a generic success message regardless of input, to avoid user enumeration. Require strong validation of the `tempToken` (e.g., single-use, short expiry, tied to request origin, validated against email delivery). Apply the same fixes to both cloud and self-hosted/local deployments. Log and monitor password reset requests for suspicious activity. Consider multi-factor verification for sensitive accounts.

- [https://github.com/nltt-br/CVE-2025-58434-CVE-2025-61687-chain-](https://github.com/nltt-br/CVE-2025-58434-CVE-2025-61687-chain-) :  ![starts](https://img.shields.io/github/stars/nltt-br/CVE-2025-58434-CVE-2025-61687-chain-.svg) ![forks](https://img.shields.io/github/forks/nltt-br/CVE-2025-58434-CVE-2025-61687-chain-.svg)


## CVE-2025-54793
 Astro is a web framework for content-driven websites. In versions 5.2.0 through 5.12.7, there is an Open Redirect vulnerability in the trailing slash redirection logic when handling paths with double slashes. This allows an attacker to redirect users to arbitrary external domains by crafting URLs such as https://mydomain.com//malicious-site.com/. This increases the risk of phishing and other social engineering attacks. This affects sites that use on-demand rendering (SSR) with the Node or Cloudflare adapters. It does not affect static sites, or sites deployed to Netlify or Vercel. This issue is fixed in version 5.12.8. To work around this issue at the network level, block outgoing redirect responses with a Location header value that starts with `//`.

- [https://github.com/Bhuvanesh-Murdoch2005/ict279-cve-2025-54793](https://github.com/Bhuvanesh-Murdoch2005/ict279-cve-2025-54793) :  ![starts](https://img.shields.io/github/stars/Bhuvanesh-Murdoch2005/ict279-cve-2025-54793.svg) ![forks](https://img.shields.io/github/forks/Bhuvanesh-Murdoch2005/ict279-cve-2025-54793.svg)


## CVE-2025-49844
 Redis is an open source, in-memory database that persists on disk. Versions 8.2.1 and below allow an authenticated user to use a specially crafted Lua script to manipulate the garbage collector, trigger a use-after-free and potentially lead to remote code execution. The problem exists in all versions of Redis with Lua scripting. This issue is fixed in version 8.2.2. To workaround this issue without patching the redis-server executable is to prevent users from executing Lua scripts. This can be done using ACL to restrict EVAL and EVALSHA commands.

- [https://github.com/imbas007/CVE-2025-49844-Vulnerability-Scanner](https://github.com/imbas007/CVE-2025-49844-Vulnerability-Scanner) :  ![starts](https://img.shields.io/github/stars/imbas007/CVE-2025-49844-Vulnerability-Scanner.svg) ![forks](https://img.shields.io/github/forks/imbas007/CVE-2025-49844-Vulnerability-Scanner.svg)


## CVE-2025-49132
 Pterodactyl is a free, open-source game server management panel. Prior to version 1.11.11, using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated. With the ability to execute arbitrary code it could be used to gain access to the Panel's server, read credentials from the Panel's config, extract sensitive information from the database, access files of servers managed by the panel, etc. This issue has been patched in version 1.11.11. There are no software workarounds for this vulnerability, but use of an external Web Application Firewall (WAF) could help mitigate this attack.

- [https://github.com/typicalsmc/CVE-2025-49132-PoC](https://github.com/typicalsmc/CVE-2025-49132-PoC) :  ![starts](https://img.shields.io/github/stars/typicalsmc/CVE-2025-49132-PoC.svg) ![forks](https://img.shields.io/github/forks/typicalsmc/CVE-2025-49132-PoC.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/cybershaolin47/CVE-2025-32463_POC](https://github.com/cybershaolin47/CVE-2025-32463_POC) :  ![starts](https://img.shields.io/github/stars/cybershaolin47/CVE-2025-32463_POC.svg) ![forks](https://img.shields.io/github/forks/cybershaolin47/CVE-2025-32463_POC.svg)


## CVE-2025-32421
 Next.js is a React framework for building full-stack web applications. Versions prior to 14.2.24 and 15.1.6 have a race-condition vulnerability. This issue only affects the Pages Router under certain misconfigurations, causing normal endpoints to serve `pageProps` data instead of standard HTML. This issue was patched in versions 15.1.6 and 14.2.24 by stripping the `x-now-route-matches` header from incoming requests. Applications hosted on Vercel's platform are not affected by this issue, as the platform does not cache responses based solely on `200 OK` status without explicit `cache-control` headers. Those who self-host Next.js deployments and are unable to upgrade immediately can mitigate this vulnerability by stripping the `x-now-route-matches` header from all incoming requests at the content development network and setting `cache-control: no-store` for all responses under risk. The maintainers of Next.js strongly recommend only caching responses with explicit cache-control headers.

- [https://github.com/hidesec/CVE-2025-32421](https://github.com/hidesec/CVE-2025-32421) :  ![starts](https://img.shields.io/github/stars/hidesec/CVE-2025-32421.svg) ![forks](https://img.shields.io/github/forks/hidesec/CVE-2025-32421.svg)


## CVE-2025-11371
This issue impacts Gladinet CentreStack and Triofox: All versions prior to and including 16.7.10368.56560

- [https://github.com/callinston/CVE-2025-11371](https://github.com/callinston/CVE-2025-11371) :  ![starts](https://img.shields.io/github/stars/callinston/CVE-2025-11371.svg) ![forks](https://img.shields.io/github/forks/callinston/CVE-2025-11371.svg)


## CVE-2025-10175
 The WP Links Page plugin for WordPress is vulnerable to SQL Injection via the 'id' parameter in all versions up to, and including, 4.9.6 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for authenticated attackers, with Subscriber-level access and above, to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/MooseLoveti/WP-Links-Page-CVE-Report](https://github.com/MooseLoveti/WP-Links-Page-CVE-Report) :  ![starts](https://img.shields.io/github/stars/MooseLoveti/WP-Links-Page-CVE-Report.svg) ![forks](https://img.shields.io/github/forks/MooseLoveti/WP-Links-Page-CVE-Report.svg)


## CVE-2025-9196
 The Trinity Audio – Text to Speech AI audio player to convert content into audio plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, and including, 5.21.0 via the ~/admin/inc/phpinfo.php file that gets created on install. This makes it possible for unauthenticated attackers to extract sensitive data including configuration data.

- [https://github.com/MooseLoveti/Trinity-Audio-CVE-Report](https://github.com/MooseLoveti/Trinity-Audio-CVE-Report) :  ![starts](https://img.shields.io/github/stars/MooseLoveti/Trinity-Audio-CVE-Report.svg) ![forks](https://img.shields.io/github/forks/MooseLoveti/Trinity-Audio-CVE-Report.svg)


## CVE-2024-58239
did some work.

- [https://github.com/khoatran107/cve-2024-58239](https://github.com/khoatran107/cve-2024-58239) :  ![starts](https://img.shields.io/github/stars/khoatran107/cve-2024-58239.svg) ![forks](https://img.shields.io/github/forks/khoatran107/cve-2024-58239.svg)


## CVE-2024-46982
 Next.js is a React framework for building full-stack web applications. By sending a crafted HTTP request, it is possible to poison the cache of a non-dynamic server-side rendered route in the pages router (this does not affect the app router). When this crafted request is sent it could coerce Next.js to cache a route that is meant to not be cached and send a `Cache-Control: s-maxage=1, stale-while-revalidate` header which some upstream CDNs may cache as well. To be potentially affected all of the following must apply: 1. Next.js between 13.5.1 and 14.2.9, 2. Using pages router, & 3. Using non-dynamic server-side rendered routes e.g. `pages/dashboard.tsx` not `pages/blog/[slug].tsx`. This vulnerability was resolved in Next.js v13.5.7, v14.2.10, and later. We recommend upgrading regardless of whether you can reproduce the issue or not. There are no official or recommended workarounds for this issue, we recommend that users patch to a safe version.

- [https://github.com/hidesec/CVE-2025-32421](https://github.com/hidesec/CVE-2025-32421) :  ![starts](https://img.shields.io/github/stars/hidesec/CVE-2025-32421.svg) ![forks](https://img.shields.io/github/forks/hidesec/CVE-2025-32421.svg)


## CVE-2024-44083
 ida64.dll in Hex-Rays IDA Pro through 8.4 crashes when there is a section that has many jumps linked, and the final jump corresponds to the payload from where the actual entry point will be invoked. NOTE: in many use cases, this is an inconvenience but not a security issue.

- [https://github.com/CrackerCat/CVE-2024-44083](https://github.com/CrackerCat/CVE-2024-44083) :  ![starts](https://img.shields.io/github/stars/CrackerCat/CVE-2024-44083.svg) ![forks](https://img.shields.io/github/forks/CrackerCat/CVE-2024-44083.svg)


## CVE-2024-28397
 An issue in the component js2py.disable_pyimport() of js2py up to v0.74 allows attackers to execute arbitrary code via a crafted API call.

- [https://github.com/0xPadme/CVE-2024-28397-Reverse-Shell](https://github.com/0xPadme/CVE-2024-28397-Reverse-Shell) :  ![starts](https://img.shields.io/github/stars/0xPadme/CVE-2024-28397-Reverse-Shell.svg) ![forks](https://img.shields.io/github/forks/0xPadme/CVE-2024-28397-Reverse-Shell.svg)


## CVE-2023-29360
 Microsoft Streaming Service Elevation of Privilege Vulnerability

- [https://github.com/Scottman625/CVE-2023-29360](https://github.com/Scottman625/CVE-2023-29360) :  ![starts](https://img.shields.io/github/stars/Scottman625/CVE-2023-29360.svg) ![forks](https://img.shields.io/github/forks/Scottman625/CVE-2023-29360.svg)


## CVE-2022-37122
 Carel pCOWeb HVAC BACnet Gateway 2.1.0, Firmware: A2.1.0 - B2.1.0, Application Software: 2.15.4A Software v16 13020200 suffers from an unauthenticated arbitrary file disclosure vulnerability. Input passed through the 'file' GET parameter through the 'logdownload.cgi' Bash script is not properly verified before being used to download log files. This can be exploited to disclose the contents of arbitrary and sensitive files via directory traversal attacks.

- [https://github.com/bughuntar/CVE-2022-37122-Exploit](https://github.com/bughuntar/CVE-2022-37122-Exploit) :  ![starts](https://img.shields.io/github/stars/bughuntar/CVE-2022-37122-Exploit.svg) ![forks](https://img.shields.io/github/forks/bughuntar/CVE-2022-37122-Exploit.svg)


## CVE-2022-24992
 A vulnerability in the component process.php of QR Code Generator v5.2.7 allows attackers to perform directory traversal.

- [https://github.com/esistferry/CVE-2022-24992](https://github.com/esistferry/CVE-2022-24992) :  ![starts](https://img.shields.io/github/stars/esistferry/CVE-2022-24992.svg) ![forks](https://img.shields.io/github/forks/esistferry/CVE-2022-24992.svg)


## CVE-2019-5736
 runc through 1.0-rc6, as used in Docker before 18.09.2 and other products, allows attackers to overwrite the host runc binary (and consequently obtain host root access) by leveraging the ability to execute a command as root within one of these types of containers: (1) a new container with an attacker-controlled image, or (2) an existing container, to which the attacker previously had write access, that can be attached with docker exec. This occurs because of file-descriptor mishandling, related to /proc/self/exe.

- [https://github.com/h-wookie/cve-2019-5736-poc](https://github.com/h-wookie/cve-2019-5736-poc) :  ![starts](https://img.shields.io/github/stars/h-wookie/cve-2019-5736-poc.svg) ![forks](https://img.shields.io/github/forks/h-wookie/cve-2019-5736-poc.svg)


## CVE-2017-5941
 An issue was discovered in the node-serialize package 0.0.4 for Node.js. Untrusted data passed into the unserialize() function can be exploited to achieve arbitrary code execution by passing a JavaScript Object with an Immediately Invoked Function Expression (IIFE).

- [https://github.com/cybersploit-tech/RCE-NodeJs](https://github.com/cybersploit-tech/RCE-NodeJs) :  ![starts](https://img.shields.io/github/stars/cybersploit-tech/RCE-NodeJs.svg) ![forks](https://img.shields.io/github/forks/cybersploit-tech/RCE-NodeJs.svg)


## CVE-2012-2982
 file/show.cgi in Webmin 1.590 and earlier allows remote authenticated users to execute arbitrary commands via an invalid character in a pathname, as demonstrated by a | (pipe) character.

- [https://github.com/danielvilaca/PoC_Webmin](https://github.com/danielvilaca/PoC_Webmin) :  ![starts](https://img.shields.io/github/stars/danielvilaca/PoC_Webmin.svg) ![forks](https://img.shields.io/github/forks/danielvilaca/PoC_Webmin.svg)

