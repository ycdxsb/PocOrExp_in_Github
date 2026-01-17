# Update 2026-01-17
## CVE-2026-23550
 Incorrect Privilege Assignment vulnerability in Modular DS allows Privilege Escalation.This issue affects Modular DS: from n/a through 2.5.1.

- [https://github.com/cyberdudebivash/CYBERDUDEBIVASH-Modular-DS-CVE-2026-23550-Detector](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-Modular-DS-CVE-2026-23550-Detector) :  ![starts](https://img.shields.io/github/stars/cyberdudebivash/CYBERDUDEBIVASH-Modular-DS-CVE-2026-23550-Detector.svg) ![forks](https://img.shields.io/github/forks/cyberdudebivash/CYBERDUDEBIVASH-Modular-DS-CVE-2026-23550-Detector.svg)


## CVE-2026-23478
 Cal.com is open-source scheduling software. From 3.1.6 to before 6.0.7, there is a vulnerability in a custom NextAuth JWT callback that allows attackers to gain full authenticated access to any user's account by supplying a target email address via session.update(). This vulnerability is fixed in 6.0.7.

- [https://github.com/Ashwesker/Ashwesker-CVE-2026-23478](https://github.com/Ashwesker/Ashwesker-CVE-2026-23478) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2026-23478.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2026-23478.svg)


## CVE-2026-22686
 Enclave is a secure JavaScript sandbox designed for safe AI agent code execution. Prior to 2.7.0, there is a critical sandbox escape vulnerability in enclave-vm that allows untrusted, sandboxed JavaScript code to execute arbitrary code in the host Node.js runtime. When a tool invocation fails, enclave-vm exposes a host-side Error object to sandboxed code. This Error object retains its host realm prototype chain, which can be traversed to reach the host Function constructor. An attacker can intentionally trigger a host error, then climb the prototype chain. Using the host Function constructor, arbitrary JavaScript can be compiled and executed in the host context, fully bypassing the sandbox and granting access to sensitive resources such as process.env, filesystem, and network. This breaks enclave-vm’s core security guarantee of isolating untrusted code. This vulnerability is fixed in 2.7.0.

- [https://github.com/amusedx/CVE-2026-22686](https://github.com/amusedx/CVE-2026-22686) :  ![starts](https://img.shields.io/github/stars/amusedx/CVE-2026-22686.svg) ![forks](https://img.shields.io/github/forks/amusedx/CVE-2026-22686.svg)


## CVE-2025-67246
 A local information disclosure vulnerability exists in the Ludashi driver before 5.1025 due to a lack of access control in the IOCTL handler. This driver exposes a device interface accessible to a normal user and handles attacker-controlled structures containing the lower 4GB of physical addresses. The handler maps arbitrary physical memory via MmMapIoSpace and copies data back to user mode without verifying the caller's privileges or the target address range. This allows unprivileged users to read arbitrary physical memory, potentially exposing kernel data structures, kernel pointers, security tokens, and other sensitive information. This vulnerability can be further exploited to bypass the Kernel Address Space Layout Rules (KASLR) and achieve local privilege escalation.

- [https://github.com/CDipper/CVE-Publication](https://github.com/CDipper/CVE-Publication) :  ![starts](https://img.shields.io/github/stars/CDipper/CVE-Publication.svg) ![forks](https://img.shields.io/github/forks/CDipper/CVE-Publication.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-transitive](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-transitive) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-transitive.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-transitive.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-rsc-webpack](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-rsc-webpack) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-rsc-webpack.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-rsc-webpack.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg)


## CVE-2025-64516
 GLPI is a free asset and IT management software package. Prior to 10.0.21 and 11.0.3, an unauthorized user can access GLPI documents attached to any item (ticket, asset, ...). If the public FAQ is enabled, this unauthorized access can be performed by an anonymous user. This vulnerability is fixed in 10.0.21 and 11.0.3.

- [https://github.com/lem0naids/CVE-2025-64516-POC](https://github.com/lem0naids/CVE-2025-64516-POC) :  ![starts](https://img.shields.io/github/stars/lem0naids/CVE-2025-64516-POC.svg) ![forks](https://img.shields.io/github/forks/lem0naids/CVE-2025-64516-POC.svg)


## CVE-2025-64155
 An improper neutralization of special elements used in an os command ('os command injection') vulnerability in Fortinet FortiSIEM 7.4.0, FortiSIEM 7.3.0 through 7.3.4, FortiSIEM 7.1.0 through 7.1.8, FortiSIEM 7.0.0 through 7.0.4, FortiSIEM 6.7.0 through 6.7.10 may allow an attacker to execute unauthorized code or commands via  crafted TCP requests.

- [https://github.com/cyberdudebivash/CYBERDUDEBIVASH-FortiSIEM-CVE-2025-64155-Scanner](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-FortiSIEM-CVE-2025-64155-Scanner) :  ![starts](https://img.shields.io/github/stars/cyberdudebivash/CYBERDUDEBIVASH-FortiSIEM-CVE-2025-64155-Scanner.svg) ![forks](https://img.shields.io/github/forks/cyberdudebivash/CYBERDUDEBIVASH-FortiSIEM-CVE-2025-64155-Scanner.svg)


## CVE-2025-61686
 React Router is a router for React. In @react-router/node versions 7.0.0 through 7.9.3, @remix-run/deno prior to version 2.17.2, and @remix-run/node prior to version 2.17.2, if createFileSessionStorage() is being used from @react-router/node (or @remix-run/node/@remix-run/deno in Remix v2) with an unsigned cookie, it is possible for an attacker to cause the session to try to read/write from a location outside the specified session file directory. The success of the attack would depend on the permissions of the web server process to access those files. Read files cannot be returned directly to the attacker. Session file reads would only succeed if the file matched the expected session file format. If the file matched the session file format, the data would be populated into the server side session but not directly returned to the attacker unless the application logic returned specific session information. This issue has been patched in @react-router/node version 7.9.4, @remix-run/deno version 2.17.2, and @remix-run/node version 2.17.2.

- [https://github.com/FlowerWitch/CVE-2025-61686_docker](https://github.com/FlowerWitch/CVE-2025-61686_docker) :  ![starts](https://img.shields.io/github/stars/FlowerWitch/CVE-2025-61686_docker.svg) ![forks](https://img.shields.io/github/forks/FlowerWitch/CVE-2025-61686_docker.svg)


## CVE-2025-61138
 Qlik Sense Enterprise v14.212.13 was discovered to contain an information leak via the /dev-hub/ directory.

- [https://github.com/Israel0x00/poc-qlik](https://github.com/Israel0x00/poc-qlik) :  ![starts](https://img.shields.io/github/stars/Israel0x00/poc-qlik.svg) ![forks](https://img.shields.io/github/forks/Israel0x00/poc-qlik.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/M0onPu15e/next.js-scanner](https://github.com/M0onPu15e/next.js-scanner) :  ![starts](https://img.shields.io/github/stars/M0onPu15e/next.js-scanner.svg) ![forks](https://img.shields.io/github/forks/M0onPu15e/next.js-scanner.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/enochgitgamefied/NextJS-CVE-2025-29927](https://github.com/enochgitgamefied/NextJS-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/enochgitgamefied/NextJS-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/enochgitgamefied/NextJS-CVE-2025-29927.svg)


## CVE-2025-29774
 xml-crypto is an XML digital signature and encryption library for Node.js. An attacker may be able to exploit a vulnerability in versions prior to 6.0.1, 3.2.1, and 2.1.6 to bypass authentication or authorization mechanisms in systems that rely on xml-crypto for verifying signed XML documents. The vulnerability allows an attacker to modify a valid signed XML message in a way that still passes signature verification checks. For example, it could be used to alter critical identity or access control attributes, enabling an attacker with a valid account to escalate privileges or impersonate another user. Users of versions 6.0.0 and prior should upgrade to version 6.0.1 to receive a fix. Those who are still using v2.x or v3.x should upgrade to patched versions 2.1.6 or 3.2.1, respectively.

- [https://github.com/demining/Phantom-Signature-Attack](https://github.com/demining/Phantom-Signature-Attack) :  ![starts](https://img.shields.io/github/stars/demining/Phantom-Signature-Attack.svg) ![forks](https://img.shields.io/github/forks/demining/Phantom-Signature-Attack.svg)


## CVE-2025-24367
 Cacti is an open source performance and fault management framework. An authenticated Cacti user can abuse graph creation and graph template functionality to create arbitrary PHP scripts in the web root of the application, leading to remote code execution on the server. This vulnerability is fixed in 1.2.29.

- [https://github.com/matesz44/CVE-2025-24367](https://github.com/matesz44/CVE-2025-24367) :  ![starts](https://img.shields.io/github/stars/matesz44/CVE-2025-24367.svg) ![forks](https://img.shields.io/github/forks/matesz44/CVE-2025-24367.svg)


## CVE-2025-24132
 The issue was addressed with improved memory handling. This issue is fixed in AirPlay audio SDK 2.7.1, AirPlay video SDK 3.6.0.126, CarPlay Communication Plug-in R18.1. An attacker on the local network may cause an unexpected app termination.

- [https://github.com/TheGamingGallifreyan/Airborne-CVE-2025-24132-Research](https://github.com/TheGamingGallifreyan/Airborne-CVE-2025-24132-Research) :  ![starts](https://img.shields.io/github/stars/TheGamingGallifreyan/Airborne-CVE-2025-24132-Research.svg) ![forks](https://img.shields.io/github/forks/TheGamingGallifreyan/Airborne-CVE-2025-24132-Research.svg)


## CVE-2025-14847
 Mismatched length fields in Zlib compressed protocol headers may allow a read of uninitialized heap memory by an unauthenticated client. This issue affects all MongoDB Server v7.0 prior to 7.0.28 versions, MongoDB Server v8.0 versions prior to 8.0.17, MongoDB Server v8.2 versions prior to 8.2.3, MongoDB Server v6.0 versions prior to 6.0.27, MongoDB Server v5.0 versions prior to 5.0.32, MongoDB Server v4.4 versions prior to 4.4.30, MongoDB Server v4.2 versions greater than or equal to 4.2.0, MongoDB Server v4.0 versions greater than or equal to 4.0.0, and MongoDB Server v3.6 versions greater than or equal to 3.6.0.

- [https://github.com/sakthivel10q/CVE-2025-14847](https://github.com/sakthivel10q/CVE-2025-14847) :  ![starts](https://img.shields.io/github/stars/sakthivel10q/CVE-2025-14847.svg) ![forks](https://img.shields.io/github/forks/sakthivel10q/CVE-2025-14847.svg)
- [https://github.com/sakthivel10q/sakthivel10q.github.io](https://github.com/sakthivel10q/sakthivel10q.github.io) :  ![starts](https://img.shields.io/github/stars/sakthivel10q/sakthivel10q.github.io.svg) ![forks](https://img.shields.io/github/forks/sakthivel10q/sakthivel10q.github.io.svg)


## CVE-2025-14502
 The News and Blog Designer Bundle plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 1.1 via the template parameter. This makes it possible for unauthenticated attackers to include and execute arbitrary .php files on the server, allowing the execution of any PHP code in those files. This can be used to bypass access controls, obtain sensitive data, or achieve code execution in cases where .php file types can be uploaded and included.

- [https://github.com/Kai-One001/WordPress-News-and-Blog-Designer-Bundle-CVE-2025-14502](https://github.com/Kai-One001/WordPress-News-and-Blog-Designer-Bundle-CVE-2025-14502) :  ![starts](https://img.shields.io/github/stars/Kai-One001/WordPress-News-and-Blog-Designer-Bundle-CVE-2025-14502.svg) ![forks](https://img.shields.io/github/forks/Kai-One001/WordPress-News-and-Blog-Designer-Bundle-CVE-2025-14502.svg)


## CVE-2025-7771
 ThrottleStop.sys, a legitimate driver, exposes two IOCTL interfaces that allow arbitrary read and write access to physical memory via the MmMapIoSpace function. This insecure implementation can be exploited by a malicious user-mode application to patch the running Windows kernel and invoke arbitrary kernel functions with ring-0 privileges. The vulnerability enables local attackers to execute arbitrary code in kernel context, resulting in privilege escalation and potential follow-on attacks, such as disabling security software or bypassing kernel-level protections. ThrottleStop.sys version 3.0.0.0 and possibly others are affected. Apply updates per vendor instructions.

- [https://github.com/xM0kht4r/CVE-2025-7771](https://github.com/xM0kht4r/CVE-2025-7771) :  ![starts](https://img.shields.io/github/stars/xM0kht4r/CVE-2025-7771.svg) ![forks](https://img.shields.io/github/forks/xM0kht4r/CVE-2025-7771.svg)


## CVE-2025-3616
 The Greenshift – animation and page builder blocks plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the gspb_make_proxy_api_request() function in versions 11.4 to 11.4.5. This makes it possible for authenticated attackers, with Subscriber-level access and above, to upload arbitrary files on the affected site's server which may make remote code execution possible. The arbitrary file upload was sufficiently patched in 11.4.5, but a capability check was added in 11.4.6 to properly prevent unauthorized limited file uploads.

- [https://github.com/b4d-53ct0r/CVE-2025-3616](https://github.com/b4d-53ct0r/CVE-2025-3616) :  ![starts](https://img.shields.io/github/stars/b4d-53ct0r/CVE-2025-3616.svg) ![forks](https://img.shields.io/github/forks/b4d-53ct0r/CVE-2025-3616.svg)


## CVE-2024-29973
The command injection vulnerability in the “setCookie” parameter in Zyxel NAS326 firmware versions before V5.21(AAZF.17)C0 and NAS542 firmware versions before V5.21(ABAG.14)C0 could allow an unauthenticated attacker to execute some operating system (OS) commands by sending a crafted HTTP POST request.

- [https://github.com/voidbroker/CVE-2024-29973](https://github.com/voidbroker/CVE-2024-29973) :  ![starts](https://img.shields.io/github/stars/voidbroker/CVE-2024-29973.svg) ![forks](https://img.shields.io/github/forks/voidbroker/CVE-2024-29973.svg)


## CVE-2024-24919
 Potentially allowing an attacker to read certain information on Check Point Security Gateways once connected to the internet and enabled with remote Access VPN or Mobile Access Software Blades. A Security fix that mitigates this vulnerability is available.

- [https://github.com/voidbroker/CVE-2024-24919](https://github.com/voidbroker/CVE-2024-24919) :  ![starts](https://img.shields.io/github/stars/voidbroker/CVE-2024-24919.svg) ![forks](https://img.shields.io/github/forks/voidbroker/CVE-2024-24919.svg)


## CVE-2024-7593
 Incorrect implementation of an authentication algorithm in Ivanti vTM other than versions 22.2R1 or 22.7R2 allows a remote unauthenticated attacker to bypass authentication of the admin panel.

- [https://github.com/voidbroker/CVE-2024-7593](https://github.com/voidbroker/CVE-2024-7593) :  ![starts](https://img.shields.io/github/stars/voidbroker/CVE-2024-7593.svg) ![forks](https://img.shields.io/github/forks/voidbroker/CVE-2024-7593.svg)


## CVE-2024-3094
Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.

- [https://github.com/BOSE122/CVE-2024-3094](https://github.com/BOSE122/CVE-2024-3094) :  ![starts](https://img.shields.io/github/stars/BOSE122/CVE-2024-3094.svg) ![forks](https://img.shields.io/github/forks/BOSE122/CVE-2024-3094.svg)


## CVE-2024-2876
 The Email Subscribers by Icegram Express – Email Marketing, Newsletters, Automation for WordPress & WooCommerce plugin for WordPress is vulnerable to SQL Injection via the 'run' function of the 'IG_ES_Subscribers_Query' class in all versions up to, and including, 5.7.14 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/voidbroker/CVE-2024-2876](https://github.com/voidbroker/CVE-2024-2876) :  ![starts](https://img.shields.io/github/stars/voidbroker/CVE-2024-2876.svg) ![forks](https://img.shields.io/github/forks/voidbroker/CVE-2024-2876.svg)


## CVE-2023-31753
 SQL injection vulnerability in diskusi.php in eNdonesia 8.7, allows an attacker to execute arbitrary SQL commands via the "rid=" parameter.

- [https://github.com/KIL0BYT3X/CVE-2023-31753](https://github.com/KIL0BYT3X/CVE-2023-31753) :  ![starts](https://img.shields.io/github/stars/KIL0BYT3X/CVE-2023-31753.svg) ![forks](https://img.shields.io/github/forks/KIL0BYT3X/CVE-2023-31753.svg)


## CVE-2023-27163
 request-baskets up to v1.2.1 was discovered to contain a Server-Side Request Forgery (SSRF) via the component /api/baskets/{name}. This vulnerability allows attackers to access network resources and sensitive information via a crafted API request.

- [https://github.com/lukehebe/CVE-2023-27163-POC](https://github.com/lukehebe/CVE-2023-27163-POC) :  ![starts](https://img.shields.io/github/stars/lukehebe/CVE-2023-27163-POC.svg) ![forks](https://img.shields.io/github/forks/lukehebe/CVE-2023-27163-POC.svg)


## CVE-2023-22515
Atlassian Cloud sites are not affected by this vulnerability. If your Confluence site is accessed via an atlassian.net domain, it is hosted by Atlassian and is not vulnerable to this issue. 

- [https://github.com/dkq-k/CVE-2023-22515](https://github.com/dkq-k/CVE-2023-22515) :  ![starts](https://img.shields.io/github/stars/dkq-k/CVE-2023-22515.svg) ![forks](https://img.shields.io/github/forks/dkq-k/CVE-2023-22515.svg)
- [https://github.com/dkq-k/cve-2023-22515-1](https://github.com/dkq-k/cve-2023-22515-1) :  ![starts](https://img.shields.io/github/stars/dkq-k/cve-2023-22515-1.svg) ![forks](https://img.shields.io/github/forks/dkq-k/cve-2023-22515-1.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Taldrid1/cve-2021-41773](https://github.com/Taldrid1/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/Taldrid1/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Taldrid1/cve-2021-41773.svg)
- [https://github.com/puckiestyle/CVE-2021-41773](https://github.com/puckiestyle/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-41773.svg)
- [https://github.com/JIYUN02/cve-2021-41773](https://github.com/JIYUN02/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/JIYUN02/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/JIYUN02/cve-2021-41773.svg)
- [https://github.com/AzkOsDev/CVE-2021-41773](https://github.com/AzkOsDev/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/AzkOsDev/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/AzkOsDev/CVE-2021-41773.svg)
- [https://github.com/wolf1892/CVE-2021-41773](https://github.com/wolf1892/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/wolf1892/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/wolf1892/CVE-2021-41773.svg)


## CVE-2019-18634
 In Sudo before 1.8.26, if pwfeedback is enabled in /etc/sudoers, users can trigger a stack-based buffer overflow in the privileged sudo process. (pwfeedback is a default setting in Linux Mint and elementary OS; however, it is NOT the default for upstream and many other packages, and would exist only if enabled by an administrator.) The attacker needs to deliver a long string to the stdin of getln() in tgetpass.c.

- [https://github.com/CyrusRazavi/CVE-2019-18634-writeup](https://github.com/CyrusRazavi/CVE-2019-18634-writeup) :  ![starts](https://img.shields.io/github/stars/CyrusRazavi/CVE-2019-18634-writeup.svg) ![forks](https://img.shields.io/github/forks/CyrusRazavi/CVE-2019-18634-writeup.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow "go get" remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/Rezy-Dev/CVE-2018-6574](https://github.com/Rezy-Dev/CVE-2018-6574) :  ![starts](https://img.shields.io/github/stars/Rezy-Dev/CVE-2018-6574.svg) ![forks](https://img.shields.io/github/forks/Rezy-Dev/CVE-2018-6574.svg)


## CVE-2018-4407
 A memory corruption issue was addressed with improved validation. This issue affected versions prior to iOS 12, macOS Mojave 10.14, tvOS 12, watchOS 5.

- [https://github.com/Pa55w0rd/check_icmp_dos](https://github.com/Pa55w0rd/check_icmp_dos) :  ![starts](https://img.shields.io/github/stars/Pa55w0rd/check_icmp_dos.svg) ![forks](https://img.shields.io/github/forks/Pa55w0rd/check_icmp_dos.svg)
- [https://github.com/unixpickle/cve-2018-4407](https://github.com/unixpickle/cve-2018-4407) :  ![starts](https://img.shields.io/github/stars/unixpickle/cve-2018-4407.svg) ![forks](https://img.shields.io/github/forks/unixpickle/cve-2018-4407.svg)
- [https://github.com/r3dxpl0it/CVE-2018-4407](https://github.com/r3dxpl0it/CVE-2018-4407) :  ![starts](https://img.shields.io/github/stars/r3dxpl0it/CVE-2018-4407.svg) ![forks](https://img.shields.io/github/forks/r3dxpl0it/CVE-2018-4407.svg)
- [https://github.com/farisv/AppleDOS](https://github.com/farisv/AppleDOS) :  ![starts](https://img.shields.io/github/stars/farisv/AppleDOS.svg) ![forks](https://img.shields.io/github/forks/farisv/AppleDOS.svg)
- [https://github.com/zteeed/CVE-2018-4407-IOS](https://github.com/zteeed/CVE-2018-4407-IOS) :  ![starts](https://img.shields.io/github/stars/zteeed/CVE-2018-4407-IOS.svg) ![forks](https://img.shields.io/github/forks/zteeed/CVE-2018-4407-IOS.svg)
- [https://github.com/WyAtu/CVE-2018-4407](https://github.com/WyAtu/CVE-2018-4407) :  ![starts](https://img.shields.io/github/stars/WyAtu/CVE-2018-4407.svg) ![forks](https://img.shields.io/github/forks/WyAtu/CVE-2018-4407.svg)
- [https://github.com/SamDecrock/node-cve-2018-4407](https://github.com/SamDecrock/node-cve-2018-4407) :  ![starts](https://img.shields.io/github/stars/SamDecrock/node-cve-2018-4407.svg) ![forks](https://img.shields.io/github/forks/SamDecrock/node-cve-2018-4407.svg)
- [https://github.com/pwnhacker0x18/iOS-Kernel-Crash](https://github.com/pwnhacker0x18/iOS-Kernel-Crash) :  ![starts](https://img.shields.io/github/stars/pwnhacker0x18/iOS-Kernel-Crash.svg) ![forks](https://img.shields.io/github/forks/pwnhacker0x18/iOS-Kernel-Crash.svg)
- [https://github.com/L-codes/my-nse](https://github.com/L-codes/my-nse) :  ![starts](https://img.shields.io/github/stars/L-codes/my-nse.svg) ![forks](https://img.shields.io/github/forks/L-codes/my-nse.svg)
- [https://github.com/anonymouz4/Apple-Remote-Crash-Tool-CVE-2018-4407](https://github.com/anonymouz4/Apple-Remote-Crash-Tool-CVE-2018-4407) :  ![starts](https://img.shields.io/github/stars/anonymouz4/Apple-Remote-Crash-Tool-CVE-2018-4407.svg) ![forks](https://img.shields.io/github/forks/anonymouz4/Apple-Remote-Crash-Tool-CVE-2018-4407.svg)
- [https://github.com/zeng9t/CVE-2018-4407-iOS-exploit](https://github.com/zeng9t/CVE-2018-4407-iOS-exploit) :  ![starts](https://img.shields.io/github/stars/zeng9t/CVE-2018-4407-iOS-exploit.svg) ![forks](https://img.shields.io/github/forks/zeng9t/CVE-2018-4407-iOS-exploit.svg)
- [https://github.com/lucagiovagnoli/CVE-2018-4407](https://github.com/lucagiovagnoli/CVE-2018-4407) :  ![starts](https://img.shields.io/github/stars/lucagiovagnoli/CVE-2018-4407.svg) ![forks](https://img.shields.io/github/forks/lucagiovagnoli/CVE-2018-4407.svg)
- [https://github.com/s2339956/check_icmp_dos-CVE-2018-4407-](https://github.com/s2339956/check_icmp_dos-CVE-2018-4407-) :  ![starts](https://img.shields.io/github/stars/s2339956/check_icmp_dos-CVE-2018-4407-.svg) ![forks](https://img.shields.io/github/forks/s2339956/check_icmp_dos-CVE-2018-4407-.svg)
- [https://github.com/szabo-tibor/CVE-2018-4407](https://github.com/szabo-tibor/CVE-2018-4407) :  ![starts](https://img.shields.io/github/stars/szabo-tibor/CVE-2018-4407.svg) ![forks](https://img.shields.io/github/forks/szabo-tibor/CVE-2018-4407.svg)
- [https://github.com/5431/CVE-2018-4407](https://github.com/5431/CVE-2018-4407) :  ![starts](https://img.shields.io/github/stars/5431/CVE-2018-4407.svg) ![forks](https://img.shields.io/github/forks/5431/CVE-2018-4407.svg)
- [https://github.com/Fans0n-Fan/CVE-2018-4407](https://github.com/Fans0n-Fan/CVE-2018-4407) :  ![starts](https://img.shields.io/github/stars/Fans0n-Fan/CVE-2018-4407.svg) ![forks](https://img.shields.io/github/forks/Fans0n-Fan/CVE-2018-4407.svg)

