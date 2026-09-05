# Update 2026-09-05
## CVE-2026-83548
 A Pre-authentication SSRF vulnerability exists in the SMA1000 Appliance Work Place interface due to an unintended alternate access path. A remote unauthenticated attacker could potentially exploit this vulnerability to gain unauthorized access to sensitive functionality and perform unauthorized operations.

- [https://github.com/xoessie/CVE-2026-83548-SonicWall-SMA1000-Analysis](https://github.com/xoessie/CVE-2026-83548-SonicWall-SMA1000-Analysis) :  ![starts](https://img.shields.io/github/stars/xoessie/CVE-2026-83548-SonicWall-SMA1000-Analysis.svg) ![forks](https://img.shields.io/github/forks/xoessie/CVE-2026-83548-SonicWall-SMA1000-Analysis.svg)


## CVE-2026-82329
 JFrog Artifactory contains an authentication weakness that, under default configuration, may allow an unauthenticated attacker with network access to obtain administrative privileges.

- [https://github.com/0xCyp1337/CVE-2026-82329](https://github.com/0xCyp1337/CVE-2026-82329) :  ![starts](https://img.shields.io/github/stars/0xCyp1337/CVE-2026-82329.svg) ![forks](https://img.shields.io/github/forks/0xCyp1337/CVE-2026-82329.svg)


## CVE-2026-80428
 ILIAS deserialises stored session data for an unauthenticated caller. The Shibboleth back-channel endpoint at components/ILIAS/AuthShibboleth/resources/shib_logout.php runs in a context that ilInitialisation exempts from authentication, and its logout-notification handler locates the session to terminate by reading every live row of the session table and passing each row's stored data to a hand-written parser that calls unserialize without restricting which classes may be constructed. Any serialised object present in any session row is therefore instantiated on behalf of an anonymous request, and object destructors run when those objects are discarded. A serialised object can be placed into a session row without logging in, because the LTI authentication entry point stores request parameters into the session and is reachable on a path the same initialisation code exempts from authentication. A class bundled with the application writes a JSON-encoded structure to a file named by one of its own properties when it is destroyed, which places attacker-controlled content at an attacker-chosen path below the web root and results in code execution as the web server user. Versions 9.22, 10.10 and 11.3 remove the endpoint's logout-notification implementation.

- [https://github.com/Zipkoppie/CVE-2026-80428](https://github.com/Zipkoppie/CVE-2026-80428) :  ![starts](https://img.shields.io/github/stars/Zipkoppie/CVE-2026-80428.svg) ![forks](https://img.shields.io/github/forks/Zipkoppie/CVE-2026-80428.svg)
- [https://github.com/digiprosec/CVE-2026-80428](https://github.com/digiprosec/CVE-2026-80428) :  ![starts](https://img.shields.io/github/stars/digiprosec/CVE-2026-80428.svg) ![forks](https://img.shields.io/github/forks/digiprosec/CVE-2026-80428.svg)


## CVE-2026-78071
 Joomla Extension - digital-peak.com - Authenticated, privileged stored XSS in DP Calendar 7.0.0 - 10.11.2 - Location title is rendered in data attribute without escaping leads to XSS, needs create permission in DPCalendar.

- [https://github.com/toanln-cov/CVE-2026-78071](https://github.com/toanln-cov/CVE-2026-78071) :  ![starts](https://img.shields.io/github/stars/toanln-cov/CVE-2026-78071.svg) ![forks](https://img.shields.io/github/forks/toanln-cov/CVE-2026-78071.svg)


## CVE-2026-78070
 Joomla Extension - digital-peak.com - Authenticated, privileged blind SQL injection in DP Calendar 5.5.0 - 10.11.2 - Saving an article can trigger a blind SQL injection with content plugin, needs update permission for articles.

- [https://github.com/toanln-cov/CVE-2026-78070](https://github.com/toanln-cov/CVE-2026-78070) :  ![starts](https://img.shields.io/github/stars/toanln-cov/CVE-2026-78070.svg) ![forks](https://img.shields.io/github/forks/toanln-cov/CVE-2026-78070.svg)


## CVE-2026-75604
 Next.js is a React framework for building full-stack web applications. From 13.4.0 until 15.5.24 and 16.3.3, Next.js applications using Pages Router or App Router without Cache Components on Windows-hosted servers do not consistently escape backslashes in route segments before constructing incremental-cache paths. In packages/next/src/shared/lib/router/utils/escape-path-delimiters.ts and packages/next/src/server/lib/incremental-cache/file-system-cache.ts, a remote request can supply encoded Windows path separators that traverse outside the intended cache root and expose private build data, including the server-reference-manifest encryption key. Disclosure of that key can enable remote code execution in the affected application. This issue is fixed in versions 15.5.24 and 16.3.3.

- [https://github.com/FORTBRIDGE-UK/cve-2026-75604](https://github.com/FORTBRIDGE-UK/cve-2026-75604) :  ![starts](https://img.shields.io/github/stars/FORTBRIDGE-UK/cve-2026-75604.svg) ![forks](https://img.shields.io/github/forks/FORTBRIDGE-UK/cve-2026-75604.svg)


## CVE-2026-72243
call selinux_socket_connect() when MSG_FASTOPEN is passed.

- [https://github.com/4n4s4zi/tfo-connect-bypass](https://github.com/4n4s4zi/tfo-connect-bypass) :  ![starts](https://img.shields.io/github/stars/4n4s4zi/tfo-connect-bypass.svg) ![forks](https://img.shields.io/github/forks/4n4s4zi/tfo-connect-bypass.svg)


## CVE-2026-65643
 Eval injection in cPanel 11.138.0.0 and earlier allows remote authenticated users to execute arbitrary code as root.

- [https://github.com/tc4dy/CVE-2026-65643-PoC-Toolkit](https://github.com/tc4dy/CVE-2026-65643-PoC-Toolkit) :  ![starts](https://img.shields.io/github/stars/tc4dy/CVE-2026-65643-PoC-Toolkit.svg) ![forks](https://img.shields.io/github/forks/tc4dy/CVE-2026-65643-PoC-Toolkit.svg)


## CVE-2026-65343
 A use after free issue was addressed with improved memory management. This issue is fixed in iOS 26.6.1 and iPadOS 26.6.1, macOS Tahoe 26.6.2. A remote attacker may be able to cause unexpected system termination.

- [https://github.com/AmorCool/iOS26.6-CVE-2026-65343](https://github.com/AmorCool/iOS26.6-CVE-2026-65343) :  ![starts](https://img.shields.io/github/stars/AmorCool/iOS26.6-CVE-2026-65343.svg) ![forks](https://img.shields.io/github/forks/AmorCool/iOS26.6-CVE-2026-65343.svg)


## CVE-2026-64788
 The issue was addressed with improved memory handling. This issue is fixed in iOS 26.6.1 and iPadOS 26.6.1, macOS Tahoe 26.6.2. Processing maliciously crafted web content may lead to memory corruption.

- [https://github.com/AmorCool/iOS26.6-CVE-2026-64788](https://github.com/AmorCool/iOS26.6-CVE-2026-64788) :  ![starts](https://img.shields.io/github/stars/AmorCool/iOS26.6-CVE-2026-64788.svg) ![forks](https://img.shields.io/github/forks/AmorCool/iOS26.6-CVE-2026-64788.svg)


## CVE-2026-62735
 Heap-based buffer overflow in Windows HTTP.sys allows an authorized attacker to elevate privileges locally.

- [https://github.com/HackSpeak/CVE-2026-62735](https://github.com/HackSpeak/CVE-2026-62735) :  ![starts](https://img.shields.io/github/stars/HackSpeak/CVE-2026-62735.svg) ![forks](https://img.shields.io/github/forks/HackSpeak/CVE-2026-62735.svg)


## CVE-2026-59822
 LiteLLM is a proxy server (AI Gateway) to call LLM APIs in OpenAI (or native) format. Prior to 1.84.0, LiteLLM's MCP Streamable HTTP endpoint allowed an unauthenticated attacker to use a fabricated Authorization header to trigger an OAuth2 passthrough fallback path that replaced failed LiteLLM key validation with an empty UserAPIKeyAuth() object, allowing requests to reach MCP tooling without a valid LiteLLM key. This issue is fixed in version 1.84.0.

- [https://github.com/HORKimhab/CVE-2026-59822](https://github.com/HORKimhab/CVE-2026-59822) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-59822.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-59822.svg)


## CVE-2026-56718
 AJCloud AJY IPC firmware prior to version 01.10715.11.37 contains a path traversal vulnerability in the jdbhttpd web service that allows unauthenticated remote attackers to read arbitrary files with root privileges by supplying path traversal sequences in the HTTP request URI. Attackers can send crafted HTTP requests to port 80 without authentication to access sensitive files including cleartext RTSP credentials, Wi-Fi SSID and pre-shared key, device serial number, and cloud binding parameters.

- [https://github.com/hellkkid/CVE-2026-56718](https://github.com/hellkkid/CVE-2026-56718) :  ![starts](https://img.shields.io/github/stars/hellkkid/CVE-2026-56718.svg) ![forks](https://img.shields.io/github/forks/hellkkid/CVE-2026-56718.svg)


## CVE-2026-52810
 Gogs is an open source self-hosted Git service. Prior to 0.14.3, Git smart HTTP authorizes POST …/git-receive-pack using the client-supplied service query string (so ?service=git-upload-pack is evaluated as read access) while routing still runs git receive-pack, allowing push where only read should be allowed. This vulnerability is fixed in 0.14.3.

- [https://github.com/HORKimhab/CVE-2026-52810](https://github.com/HORKimhab/CVE-2026-52810) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-52810.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-52810.svg)


## CVE-2026-47627
 NVIDIA Triton Inference Server for Linux contains a vulnerability where an attacker could cause path traversal. A successful exploit might lead to denial of service.

- [https://github.com/AneKazek/cve-2026-47627](https://github.com/AneKazek/cve-2026-47627) :  ![starts](https://img.shields.io/github/stars/AneKazek/cve-2026-47627.svg) ![forks](https://img.shields.io/github/forks/AneKazek/cve-2026-47627.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/slapah/ghostlock-h8q](https://github.com/slapah/ghostlock-h8q) :  ![starts](https://img.shields.io/github/stars/slapah/ghostlock-h8q.svg) ![forks](https://img.shields.io/github/forks/slapah/ghostlock-h8q.svg)


## CVE-2026-40976
Affected: Spring Boot 4.0.0–4.0.5; upgrade to 4.0.6 or later per vendor advisory.

- [https://github.com/madebyrokit/CVE-2026-40976-POC](https://github.com/madebyrokit/CVE-2026-40976-POC) :  ![starts](https://img.shields.io/github/stars/madebyrokit/CVE-2026-40976-POC.svg) ![forks](https://img.shields.io/github/forks/madebyrokit/CVE-2026-40976-POC.svg)


## CVE-2026-38577
 Insecure hardcoded credentials in the Admin account of Tenda HG21 V4.0.0-260302 allows attackers to gain root access.

- [https://github.com/poxsky/CVE-2026-38577](https://github.com/poxsky/CVE-2026-38577) :  ![starts](https://img.shields.io/github/stars/poxsky/CVE-2026-38577.svg) ![forks](https://img.shields.io/github/forks/poxsky/CVE-2026-38577.svg)


## CVE-2026-20212
This vulnerability exists because TCP ports 43210 and 43211 are accessible in the default Layer 3 (L3) virtual routing and forwarding (VRF). A successful exploit could allow the attacker to connect to an affected device and send crafted input that could be executed as code with&nbsp;root privileges. The exploitation of this vulnerability could also cause the S1HAL process to crash, which could cause the device to reload.

- [https://github.com/HORKimhab/CVE-2026-20212](https://github.com/HORKimhab/CVE-2026-20212) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-20212.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-20212.svg)


## CVE-2026-19949
 The All-in-One WP Migration and Backup plugin for WordPress is vulnerable to SQL Injection via archive restore functionality in all versions up to, and including, 7.109 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query. This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database. This can be leveraged to obtain the ai1wm_secret_key when a site administrator performs an archive restore and achieve remote code execution once able to leverage the ai1wm_secret_key value.

- [https://github.com/HORKimhab/CVE-2026-19949](https://github.com/HORKimhab/CVE-2026-19949) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-19949.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-19949.svg)


## CVE-2026-7874
 IBM Langflow OSS 1.0.0 through 1.10.0 Langflow could allow disclosure of all stored credentials due to the use of a weak and reversible key derivation mechanism for encryption at rest.

- [https://github.com/n0c71v3x/CVE-2026-78745](https://github.com/n0c71v3x/CVE-2026-78745) :  ![starts](https://img.shields.io/github/stars/n0c71v3x/CVE-2026-78745.svg) ![forks](https://img.shields.io/github/forks/n0c71v3x/CVE-2026-78745.svg)


## CVE-2026-5158
 The Post Grid Gutenberg Blocks for News, Magazines, Blog Websites – PostX plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'inputPlaceHolder' parameter in all versions up to, and including, 5.0.13 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/catforgor/CVE-2026-51585](https://github.com/catforgor/CVE-2026-51585) :  ![starts](https://img.shields.io/github/stars/catforgor/CVE-2026-51585.svg) ![forks](https://img.shields.io/github/forks/catforgor/CVE-2026-51585.svg)


## CVE-2026-4813
 A vulnerability in the Lutece Core XSL export management module up to version 7.1.7, which allows authenticated administrators to execute code remotely. The XML/XSLT processing configuration does not enable secure processing mode (FEATURE_SECURE_PROCESSING), allowing Java extension functions to be executed from malicious XSL stylesheets. An attacker with administrator privileges can upload a manipulated XSL transformation file and trigger its execution during user export operations, resulting in the execution of arbitrary code on the server.

- [https://github.com/Trachinus/CVE-2026-4813](https://github.com/Trachinus/CVE-2026-4813) :  ![starts](https://img.shields.io/github/stars/Trachinus/CVE-2026-4813.svg) ![forks](https://img.shields.io/github/forks/Trachinus/CVE-2026-4813.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/CamsShaft/IonStack-S22-cve-2026-43499](https://github.com/CamsShaft/IonStack-S22-cve-2026-43499) :  ![starts](https://img.shields.io/github/stars/CamsShaft/IonStack-S22-cve-2026-43499.svg) ![forks](https://img.shields.io/github/forks/CamsShaft/IonStack-S22-cve-2026-43499.svg)


## CVE-2026-0915
 Calling getnetbyaddr or getnetbyaddr_r with a configured nsswitch.conf that specifies the library's DNS backend for networks and queries for a zero-valued network in the GNU C Library version 2.0 to version 2.42 can leak stack contents to the configured DNS resolver.

- [https://github.com/Terra-Nova83/CVE-2026-0915-json-Patch.-V2.0](https://github.com/Terra-Nova83/CVE-2026-0915-json-Patch.-V2.0) :  ![starts](https://img.shields.io/github/stars/Terra-Nova83/CVE-2026-0915-json-Patch.-V2.0.svg) ![forks](https://img.shields.io/github/forks/Terra-Nova83/CVE-2026-0915-json-Patch.-V2.0.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field.svg)


## CVE-2025-54793
 Astro is a web framework for content-driven websites. In versions 5.2.0 through 5.12.7, there is an Open Redirect vulnerability in the trailing slash redirection logic when handling paths with double slashes. This allows an attacker to redirect users to arbitrary external domains by crafting URLs such as https://mydomain.com//malicious-site.com/. This increases the risk of phishing and other social engineering attacks. This affects sites that use on-demand rendering (SSR) with the Node or Cloudflare adapters. It does not affect static sites, or sites deployed to Netlify or Vercel. This issue is fixed in version 5.12.8. To work around this issue at the network level, block outgoing redirect responses with a Location header value that starts with `//`.

- [https://github.com/bhuvi-labs/ict279-cve-2025-54793](https://github.com/bhuvi-labs/ict279-cve-2025-54793) :  ![starts](https://img.shields.io/github/stars/bhuvi-labs/ict279-cve-2025-54793.svg) ![forks](https://img.shields.io/github/forks/bhuvi-labs/ict279-cve-2025-54793.svg)


## CVE-2025-47928
 Spotipy is a Python library for the Spotify Web API. As of commit 4f5759dbfb4506c7b6280572a4db1aabc1ac778d, using `pull_request_target` on `.github/workflows/integration_tests.yml` followed by the checking out the head.sha of a forked PR can be exploited by attackers, since untrusted code can be executed having full access to secrets (from the base repo). By exploiting the vulnerability is possible to exfiltrate `GITHUB_TOKEN` and secrets `SPOTIPY_CLIENT_ID`,  `SPOTIPY_CLIENT_SECRET`. In particular `GITHUB_TOKEN` which can be used to completely overtake the repo since the token has content write privileges. The `pull_request_target` in GitHub Actions is a major security concern—especially in public repositories—because it executes untrusted code from a PR, but with the context of the base repository, including access to its secrets. Commit 9dfb7177b8d7bb98a5a6014f8e6436812a47576f reverted the change that caused the issue.

- [https://github.com/pvharmo2/gha-lab-2f775f277c](https://github.com/pvharmo2/gha-lab-2f775f277c) :  ![starts](https://img.shields.io/github/stars/pvharmo2/gha-lab-2f775f277c.svg) ![forks](https://img.shields.io/github/forks/pvharmo2/gha-lab-2f775f277c.svg)


## CVE-2025-46820
 phpgt/Dom provides access to modern DOM APIs. Versions of phpgt/Dom prior to 4.1.8 expose the GITHUB_TOKEN in the Dom workflow run artifact. The ci.yml workflow file uses actions/upload-artifact@v4 to upload the build artifact. This artifact is a zip of the current directory, which includes the automatically generated .git/config file containing the run's GITHUB_TOKEN. Seeing as the artifact can be downloaded prior to the end of the workflow, there is a few seconds where an attacker can extract the token from the artifact and use it with the GitHub API to push malicious code or rewrite release commits in your repository. Any downstream user of the repository may be affected, but the token should only be valid for the duration of the workflow run, limiting the time during which exploitation could occur. Version 4.1.8 fixes the issue.

- [https://github.com/pvharmo2/gha-lab-fb6df3d456](https://github.com/pvharmo2/gha-lab-fb6df3d456) :  ![starts](https://img.shields.io/github/stars/pvharmo2/gha-lab-fb6df3d456.svg) ![forks](https://img.shields.io/github/forks/pvharmo2/gha-lab-fb6df3d456.svg)


## CVE-2025-32958
 Adept is a language for general purpose programming. Prior to commit a1a41b7, the remoteBuild.yml workflow file uses actions/upload-artifact@v4 to upload the mac-standalone artifact. This artifact is a zip of the current directory, which includes the automatically generated .git/config file containing the run's GITHUB_TOKEN. Seeing as the artifact can be downloaded prior to the end of the workflow, there is a few seconds where an attacker can extract the token from the artifact and use it with the Github API to push malicious code or rewrite release commits in the AdeptLanguage/Adept repository. This issue has been patched in commit a1a41b7.

- [https://github.com/pvharmo2/gha-lab-b1fe4918c0](https://github.com/pvharmo2/gha-lab-b1fe4918c0) :  ![starts](https://img.shields.io/github/stars/pvharmo2/gha-lab-b1fe4918c0.svg) ![forks](https://img.shields.io/github/forks/pvharmo2/gha-lab-b1fe4918c0.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/all3njk/NextJS_CVE-2025-29927](https://github.com/all3njk/NextJS_CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/all3njk/NextJS_CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/all3njk/NextJS_CVE-2025-29927.svg)
- [https://github.com/enochgitgamefied/NextJS-CVE-2025-29927](https://github.com/enochgitgamefied/NextJS-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/enochgitgamefied/NextJS-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/enochgitgamefied/NextJS-CVE-2025-29927.svg)


## CVE-2025-27840
 Espressif ESP32 chips allow 29 hidden HCI commands, such as 0xFC02 (Write memory).

- [https://github.com/v3ilsm1th/CVE-2025-27840-WIP](https://github.com/v3ilsm1th/CVE-2025-27840-WIP) :  ![starts](https://img.shields.io/github/stars/v3ilsm1th/CVE-2025-27840-WIP.svg) ![forks](https://img.shields.io/github/forks/v3ilsm1th/CVE-2025-27840-WIP.svg)


## CVE-2025-13947
 A flaw was found in WebKitGTK. This vulnerability allows remote, user-assisted information disclosure that can reveal any file the user is permitted to read via abusing the file drag-and-drop mechanism where WebKitGTK does not verify that drag operations originate from outside the browser.

- [https://github.com/sirredbeard/WebKitGTK-DND-Fix](https://github.com/sirredbeard/WebKitGTK-DND-Fix) :  ![starts](https://img.shields.io/github/stars/sirredbeard/WebKitGTK-DND-Fix.svg) ![forks](https://img.shields.io/github/forks/sirredbeard/WebKitGTK-DND-Fix.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg)


## CVE-2025-2992
 A vulnerability classified as critical was found in Tenda FH1202 1.2.0.14(408). Affected by this vulnerability is an unknown functionality of the file /goform/AdvSetWrlsafeset of the component Web Management Interface. The manipulation leads to improper access controls. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/0xPb1/Next.js-CVE-2025-29927](https://github.com/0xPb1/Next.js-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/0xPb1/Next.js-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/0xPb1/Next.js-CVE-2025-29927.svg)
- [https://github.com/lucaschanzx/CVE-2025-29927-PoC](https://github.com/lucaschanzx/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/lucaschanzx/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/lucaschanzx/CVE-2025-29927-PoC.svg)


## CVE-2024-53027
 Transient DOS may occur while processing the country IE.

- [https://github.com/v3ilsm1th/CVE-2024-53027-WIP](https://github.com/v3ilsm1th/CVE-2024-53027-WIP) :  ![starts](https://img.shields.io/github/stars/v3ilsm1th/CVE-2024-53027-WIP.svg) ![forks](https://img.shields.io/github/forks/v3ilsm1th/CVE-2024-53027-WIP.svg)


## CVE-2024-42370
 Litestar is an Asynchronous Server Gateway Interface (ASGI) framework. In versions 2.10.0 and prior, Litestar's `docs-preview.yml` workflow is vulnerable to Environment Variable injection which may lead to secret exfiltration and repository manipulation. This issue grants a malicious actor the permission to write issues, read metadata, and write pull requests. In addition, the `DOCS_PREVIEW_DEPLOY_TOKEN` is exposed to the attacker. Commit 84d351e96aaa2a1338006d6e7221eded161f517b contains a fix for this issue.

- [https://github.com/pvharmo2/gha-lab-ba8e0c4217](https://github.com/pvharmo2/gha-lab-ba8e0c4217) :  ![starts](https://img.shields.io/github/stars/pvharmo2/gha-lab-ba8e0c4217.svg) ![forks](https://img.shields.io/github/forks/pvharmo2/gha-lab-ba8e0c4217.svg)


## CVE-2024-21546
 Versions of the package unisharp/laravel-filemanager before 2.9.1 are vulnerable to Remote Code Execution (RCE) through using a valid mimetype and inserting the . character after the php file extension. This allows the attacker to execute malicious code.

- [https://github.com/digitalsurgn/CVE-2024-21546](https://github.com/digitalsurgn/CVE-2024-21546) :  ![starts](https://img.shields.io/github/stars/digitalsurgn/CVE-2024-21546.svg) ![forks](https://img.shields.io/github/forks/digitalsurgn/CVE-2024-21546.svg)


## CVE-2024-9465
 An SQL injection vulnerability in Palo Alto Networks Expedition allows an unauthenticated attacker to reveal Expedition database contents, such as password hashes, usernames, device configurations, and device API keys. With this, attackers can also create and read arbitrary files on the Expedition system.

- [https://github.com/mustafaakalin/CVE-2024-9465](https://github.com/mustafaakalin/CVE-2024-9465) :  ![starts](https://img.shields.io/github/stars/mustafaakalin/CVE-2024-9465.svg) ![forks](https://img.shields.io/github/forks/mustafaakalin/CVE-2024-9465.svg)


## CVE-2023-54391
 Proxmox Virtual Environment (VE) 7.0 through 8.0 contains an authentication bypass vulnerability in libpve-access-control before 8.0.4 that allows unauthenticated attackers to authenticate as any existing enabled user without a configured second factor by supplying an arbitrary tfa-challenge value in the API login endpoint. Attackers can send a POST request to the access ticket API endpoint with any value in the tfa-challenge parameter to completely skip password verification, gaining unauthorized access including to the root@pam account. All affected releases are end of life.

- [https://github.com/disqualifier/psa-2026-00043-recovery](https://github.com/disqualifier/psa-2026-00043-recovery) :  ![starts](https://img.shields.io/github/stars/disqualifier/psa-2026-00043-recovery.svg) ![forks](https://img.shields.io/github/forks/disqualifier/psa-2026-00043-recovery.svg)


## CVE-2023-45866
 Bluetooth HID Hosts in BlueZ may permit an unauthenticated Peripheral role HID Device to initiate and establish an encrypted connection, and accept HID keyboard reports, potentially permitting injection of HID messages when no user interaction has occurred in the Central role to authorize such access. An example affected package is bluez 5.64-0ubuntu1 in Ubuntu 22.04LTS. NOTE: in some cases, a CVE-2020-0556 mitigation would have already addressed this Bluetooth HID Hosts issue.

- [https://github.com/v3ilsm1th/CVE-2023-45866_WIP](https://github.com/v3ilsm1th/CVE-2023-45866_WIP) :  ![starts](https://img.shields.io/github/stars/v3ilsm1th/CVE-2023-45866_WIP.svg) ![forks](https://img.shields.io/github/forks/v3ilsm1th/CVE-2023-45866_WIP.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mightysai1997/cve-2021-41773](https://github.com/mightysai1997/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/mightysai1997/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/cve-2021-41773.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/Super-Binary/cve-2021-44228](https://github.com/Super-Binary/cve-2021-44228) :  ![starts](https://img.shields.io/github/stars/Super-Binary/cve-2021-44228.svg) ![forks](https://img.shields.io/github/forks/Super-Binary/cve-2021-44228.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/0xrogg/CVE-2021-41773](https://github.com/0xrogg/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/0xrogg/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/0xrogg/CVE-2021-41773.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/lem0n817/CVE-2020-1938-Tomcat-FileRead](https://github.com/lem0n817/CVE-2020-1938-Tomcat-FileRead) :  ![starts](https://img.shields.io/github/stars/lem0n817/CVE-2020-1938-Tomcat-FileRead.svg) ![forks](https://img.shields.io/github/forks/lem0n817/CVE-2020-1938-Tomcat-FileRead.svg)


## CVE-2017-12617
 When running Apache Tomcat versions 9.0.0.M1 to 9.0.0, 8.5.0 to 8.5.22, 8.0.0.RC1 to 8.0.46 and 7.0.0 to 7.0.81 with HTTP PUTs enabled (e.g. via setting the readonly initialisation parameter of the Default servlet to false) it was possible to upload a JSP file to the server via a specially crafted request. This JSP could then be requested and any code it contained would be executed by the server.

- [https://github.com/lem0n817/CVE-2017-12617-POC](https://github.com/lem0n817/CVE-2017-12617-POC) :  ![starts](https://img.shields.io/github/stars/lem0n817/CVE-2017-12617-POC.svg) ![forks](https://img.shields.io/github/forks/lem0n817/CVE-2017-12617-POC.svg)

