# Update 2026-07-19
## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/ZephrFish/wp2shell-scanner](https://github.com/ZephrFish/wp2shell-scanner) :  ![starts](https://img.shields.io/github/stars/ZephrFish/wp2shell-scanner.svg) ![forks](https://img.shields.io/github/forks/ZephrFish/wp2shell-scanner.svg)
- [https://github.com/attackercan/wp2shell-poc2](https://github.com/attackercan/wp2shell-poc2) :  ![starts](https://img.shields.io/github/stars/attackercan/wp2shell-poc2.svg) ![forks](https://img.shields.io/github/forks/attackercan/wp2shell-poc2.svg)
- [https://github.com/zeroc00I/CVE-2026-63030](https://github.com/zeroc00I/CVE-2026-63030) :  ![starts](https://img.shields.io/github/stars/zeroc00I/CVE-2026-63030.svg) ![forks](https://img.shields.io/github/forks/zeroc00I/CVE-2026-63030.svg)
- [https://github.com/Senanfurkan/wordpress-cve-2026-63030](https://github.com/Senanfurkan/wordpress-cve-2026-63030) :  ![starts](https://img.shields.io/github/stars/Senanfurkan/wordpress-cve-2026-63030.svg) ![forks](https://img.shields.io/github/forks/Senanfurkan/wordpress-cve-2026-63030.svg)
- [https://github.com/tcyph3r/wp2shell-cve-2026-63030-root-cause](https://github.com/tcyph3r/wp2shell-cve-2026-63030-root-cause) :  ![starts](https://img.shields.io/github/stars/tcyph3r/wp2shell-cve-2026-63030-root-cause.svg) ![forks](https://img.shields.io/github/forks/tcyph3r/wp2shell-cve-2026-63030-root-cause.svg)
- [https://github.com/47Cid/wp2shell-lab](https://github.com/47Cid/wp2shell-lab) :  ![starts](https://img.shields.io/github/stars/47Cid/wp2shell-lab.svg) ![forks](https://img.shields.io/github/forks/47Cid/wp2shell-lab.svg)
- [https://github.com/dinosn/wp2shell-lab](https://github.com/dinosn/wp2shell-lab) :  ![starts](https://img.shields.io/github/stars/dinosn/wp2shell-lab.svg) ![forks](https://img.shields.io/github/forks/dinosn/wp2shell-lab.svg)


## CVE-2026-60137
 WordPress 6.8.x before 6.8.6, 6.9.x before 6.9.5, and 7.0.x before 7.0.2 does not properly sanitise the author__not_in parameter of WP_Query, which could allow SQL Injection when a plugin or theme passes untrusted input to the parameter.

- [https://github.com/ZephrFish/wp2shell-scanner](https://github.com/ZephrFish/wp2shell-scanner) :  ![starts](https://img.shields.io/github/stars/ZephrFish/wp2shell-scanner.svg) ![forks](https://img.shields.io/github/forks/ZephrFish/wp2shell-scanner.svg)
- [https://github.com/Senanfurkan/wordpress-cve-2026-63030](https://github.com/Senanfurkan/wordpress-cve-2026-63030) :  ![starts](https://img.shields.io/github/stars/Senanfurkan/wordpress-cve-2026-63030.svg) ![forks](https://img.shields.io/github/forks/Senanfurkan/wordpress-cve-2026-63030.svg)


## CVE-2026-52199
 An issue in Generic OEM UZ801_v2.1 4G LTE Router V3.4.3 allows a remote attacker to execute arbitrary code via the sbin/adbd component

- [https://github.com/lamaper/CVE-2026-52199](https://github.com/lamaper/CVE-2026-52199) :  ![starts](https://img.shields.io/github/stars/lamaper/CVE-2026-52199.svg) ![forks](https://img.shields.io/github/forks/lamaper/CVE-2026-52199.svg)


## CVE-2026-51833
 Xenforo 2.3.8 is vulnerable to SSRF. Attackers that have administrator privileges or are able to add/save RSS feeds can enumerate internal services (ports) or expose the original IP address of the server.

- [https://github.com/dennywise/CVE-2026-51833-Public-Disclosure](https://github.com/dennywise/CVE-2026-51833-Public-Disclosure) :  ![starts](https://img.shields.io/github/stars/dennywise/CVE-2026-51833-Public-Disclosure.svg) ![forks](https://img.shields.io/github/forks/dennywise/CVE-2026-51833-Public-Disclosure.svg)


## CVE-2026-50416
 Exposure of sensitive information to an unauthorized actor in Windows Win32K allows an authorized attacker to disclose information locally.

- [https://github.com/karollooool/CVE-2026-50416-writeup-and-poc](https://github.com/karollooool/CVE-2026-50416-writeup-and-poc) :  ![starts](https://img.shields.io/github/stars/karollooool/CVE-2026-50416-writeup-and-poc.svg) ![forks](https://img.shields.io/github/forks/karollooool/CVE-2026-50416-writeup-and-poc.svg)


## CVE-2026-48205
Users are recommended to upgrade to version 4.21.0, which fixes the issue. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.8. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.3. After upgrading, routes that drive DNS operations via the raw header names must use CamelDnsServer / CamelDnsName / CamelDnsDomain / CamelDnsType / CamelDnsClass / CamelDnsTerm instead of the dns.* / term names. For deployments that cannot upgrade immediately, strip the dns.* and term headers from any untrusted ingress before the dns: producer, and set the DNS server and lookup parameters from a trusted source in the route.

- [https://github.com/oscerd/CVE-2026-48205](https://github.com/oscerd/CVE-2026-48205) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-48205.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-48205.svg)


## CVE-2026-48204
Users are recommended to upgrade to version 4.21.0, which fixes the issue. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.8. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.3. After upgrading, routes that drive GridFS operations or metadata via the raw header names must use CamelGridFsOperation / CamelGridFsObjectId / CamelGridFsMetadata / CamelGridFsChunkSize / CamelGridFsFileId instead of the gridfs.* names. For deployments that cannot upgrade immediately, set an explicit operation on the mongodb-gridfs: endpoint so the operation is not taken from a header, and strip the gridfs.* headers from any untrusted ingress before the producer.

- [https://github.com/oscerd/CVE-2026-48204](https://github.com/oscerd/CVE-2026-48204) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-48204.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-48204.svg)


## CVE-2026-48203
Users are recommended to upgrade to version 4.21.0, which fixes the issue. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.8. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.3. After upgrading, routes that set Solr parameters or fields via the raw header prefixes must use CamelSolrParam. / CamelSolrField. instead of SolrParam. / SolrField.. For deployments that cannot upgrade immediately, strip the SolrParam.* and SolrField.* headers from any untrusted ingress before the solr: producer, and set the required Solr parameters and fields from a trusted source in the route.

- [https://github.com/oscerd/CVE-2026-48203](https://github.com/oscerd/CVE-2026-48203) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-48203.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-48203.svg)


## CVE-2026-47777
 Mastodon is a free, open-source social network server based on ActivityPub. In versions there is a missing condition in the check if remote accounts consented to be featured in a remote Collection could lead to attackers bypassing the check and faking consent. An attacker could forge the FeatureAuthorization object that is used to verify consent to be featured in a Collection and thus make it appear as if an account is allowed to be in a Collection when it actually is not. While the FeatureAuthorization must reside on the same domain as the object it is for, a check is missing to make sure said object is actually the same as in the Collection item. This allows an attacker to forge the authorization. Mastodon servers are affected only if running the main branch or nightly builds who have opted into testing the experimental "Collections" feature by setting the environment variable EXPERIMENTAL_FEATURES to a value including collections. This has been patched in version 4.6.0-beta.1.

- [https://github.com/bekwiner/cve-2026-47777](https://github.com/bekwiner/cve-2026-47777) :  ![starts](https://img.shields.io/github/stars/bekwiner/cve-2026-47777.svg) ![forks](https://img.shields.io/github/forks/bekwiner/cve-2026-47777.svg)


## CVE-2026-47323
Users are recommended to upgrade to version 4.19.0, which fixes the issue. If users are on the 4.18.x LTS releases stream, then they are suggested to upgrade to 4.18.2. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.6.

- [https://github.com/oscerd/CVE-2026-47323](https://github.com/oscerd/CVE-2026-47323) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-47323.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-47323.svg)


## CVE-2026-46442
 Flowise is a drag & drop user interface to build a customized large language model flow. Prior to version 3.1.2, POST /api/v1/node-custom-function lacks route-level authorization, allowing any authenticated user or API key to submit arbitrary JavaScript to the Custom JS Function node. When E2B_APIKEY is not configured — the common deployment case — Flowise executes this code inside a NodeVM sandbox. This sandbox can be escaped, allowing an attacker to reach the host process object and execute system commands via child_process. The result is authenticated remote code execution on the Flowise server host. This issue has been patched in version 3.1.2.

- [https://github.com/codeb0ssx/CVE-2026-46442-PoC](https://github.com/codeb0ssx/CVE-2026-46442-PoC) :  ![starts](https://img.shields.io/github/stars/codeb0ssx/CVE-2026-46442-PoC.svg) ![forks](https://img.shields.io/github/forks/codeb0ssx/CVE-2026-46442-PoC.svg)


## CVE-2026-44262
 Scramble generates API documentation for Laravel project. From 0.13.2 to before 0.13.22, when documentation endpoints are publicly accessible and validation rules reference user-controlled input, request supplied data may be evaluated during documentation generation, leading to execution of arbitrary PHP code in the application context. This vulnerability is fixed in 0.13.22.

- [https://github.com/akash-osmsec/CVE-2026-44262-](https://github.com/akash-osmsec/CVE-2026-44262-) :  ![starts](https://img.shields.io/github/stars/akash-osmsec/CVE-2026-44262-.svg) ![forks](https://img.shields.io/github/forks/akash-osmsec/CVE-2026-44262-.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/sorrow404Null/CVE-2026-43499-RMX5200](https://github.com/sorrow404Null/CVE-2026-43499-RMX5200) :  ![starts](https://img.shields.io/github/stars/sorrow404Null/CVE-2026-43499-RMX5200.svg) ![forks](https://img.shields.io/github/forks/sorrow404Null/CVE-2026-43499-RMX5200.svg)
- [https://github.com/MiaPatsune/cve-2026-43499](https://github.com/MiaPatsune/cve-2026-43499) :  ![starts](https://img.shields.io/github/stars/MiaPatsune/cve-2026-43499.svg) ![forks](https://img.shields.io/github/forks/MiaPatsune/cve-2026-43499.svg)
- [https://github.com/justsoman/CyberMeowfia-ace3](https://github.com/justsoman/CyberMeowfia-ace3) :  ![starts](https://img.shields.io/github/stars/justsoman/CyberMeowfia-ace3.svg) ![forks](https://img.shields.io/github/forks/justsoman/CyberMeowfia-ace3.svg)
- [https://github.com/Wtrwx/cve_2026_43499_sm-t878u](https://github.com/Wtrwx/cve_2026_43499_sm-t878u) :  ![starts](https://img.shields.io/github/stars/Wtrwx/cve_2026_43499_sm-t878u.svg) ![forks](https://img.shields.io/github/forks/Wtrwx/cve_2026_43499_sm-t878u.svg)
- [https://github.com/fuukliam/vivo-x-fold6-ghostlock](https://github.com/fuukliam/vivo-x-fold6-ghostlock) :  ![starts](https://img.shields.io/github/stars/fuukliam/vivo-x-fold6-ghostlock.svg) ![forks](https://img.shields.io/github/forks/fuukliam/vivo-x-fold6-ghostlock.svg)


## CVE-2026-43074
Defer the kfree() to an RCU callback to prevent UAF.

- [https://github.com/PeronGH/android-selinux-disabler](https://github.com/PeronGH/android-selinux-disabler) :  ![starts](https://img.shields.io/github/stars/PeronGH/android-selinux-disabler.svg) ![forks](https://img.shields.io/github/forks/PeronGH/android-selinux-disabler.svg)


## CVE-2026-36669
 An unauthenticated arbitrary file upload vulnerability in ck_upload_handler.php in Feng Office 3.11.13.11 allows remote attackers to upload malicious files (such as .html) to the web-accessible /tmp/ directory.

- [https://github.com/firstlax6t/CVE-2026-36669-FengOffice](https://github.com/firstlax6t/CVE-2026-36669-FengOffice) :  ![starts](https://img.shields.io/github/stars/firstlax6t/CVE-2026-36669-FengOffice.svg) ![forks](https://img.shields.io/github/forks/firstlax6t/CVE-2026-36669-FengOffice.svg)


## CVE-2026-33017
 Langflow is a tool for building and deploying AI-powered agents and workflows. In versions prior to 1.9.0, the POST /api/v1/build_public_tmp/{flow_id}/flow endpoint allows building public flows without requiring authentication. When the optional data parameter is supplied, the endpoint uses attacker-controlled flow data (containing arbitrary Python code in node definitions) instead of the stored flow data from the database. This code is passed to exec() with zero sandboxing, resulting in unauthenticated remote code execution. This is distinct from CVE-2025-3248, which fixed /api/v1/validate/code by adding authentication. The build_public_tmp endpoint is designed to be unauthenticated (for public flows) but incorrectly accepts attacker-supplied flow data containing arbitrary executable code. This issue has been fixed in version 1.9.0.

- [https://github.com/Usman0220/CVE-2026-33017-Langflow-RCE](https://github.com/Usman0220/CVE-2026-33017-Langflow-RCE) :  ![starts](https://img.shields.io/github/stars/Usman0220/CVE-2026-33017-Langflow-RCE.svg) ![forks](https://img.shields.io/github/forks/Usman0220/CVE-2026-33017-Langflow-RCE.svg)


## CVE-2026-21445
 Langflow is a tool for building and deploying AI-powered agents and workflows. Prior to version 1.7.0.dev45, multiple critical API endpoints in Langflow are missing authentication controls. The issue allows any unauthenticated user to access sensitive user conversation data, transaction histories, and perform destructive operations including message deletion. This affects endpoints handling personal data and system operations that should require proper authorization. Version 1.7.0.dev45 contains a patch.

- [https://github.com/codeb0ssx/CVE-2026-21445-PoC](https://github.com/codeb0ssx/CVE-2026-21445-PoC) :  ![starts](https://img.shields.io/github/stars/codeb0ssx/CVE-2026-21445-PoC.svg) ![forks](https://img.shields.io/github/forks/codeb0ssx/CVE-2026-21445-PoC.svg)


## CVE-2026-15583
 A confused-deputy flaw in Grafana MCP Server allows an unauthenticated remote attacker to exfiltrate the server's environment-configured Grafana service-account token by supplying a crafted X-Grafana-URL request header. This also enables SSRF against arbitrary internal services, including cloud metadata endpoints.

- [https://github.com/codeb0ssx/CVE-2026-15583-PoC](https://github.com/codeb0ssx/CVE-2026-15583-PoC) :  ![starts](https://img.shields.io/github/stars/codeb0ssx/CVE-2026-15583-PoC.svg) ![forks](https://img.shields.io/github/forks/codeb0ssx/CVE-2026-15583-PoC.svg)


## CVE-2026-15409
 A Server-side request forgery (SSRF) vulnerability has been identified in the SMA1000 Appliance Work Place interface. A remote unauthenticated attacker could potentially cause the appliance to make requests to unintended location.

- [https://github.com/tc4dy/CVE-2026-15409-15410-Framework](https://github.com/tc4dy/CVE-2026-15409-15410-Framework) :  ![starts](https://img.shields.io/github/stars/tc4dy/CVE-2026-15409-15410-Framework.svg) ![forks](https://img.shields.io/github/forks/tc4dy/CVE-2026-15409-15410-Framework.svg)


## CVE-2026-14871
 osTicket versions v1.18.3 and v1.17.7 contain a Broken Object Level Authorization (BOLA) leading to Insecure Direct Object Reference (IDOR) in the AJAX ticket-management subsystem.

- [https://github.com/JFOZ1010/CVE-2026-14871](https://github.com/JFOZ1010/CVE-2026-14871) :  ![starts](https://img.shields.io/github/stars/JFOZ1010/CVE-2026-14871.svg) ![forks](https://img.shields.io/github/forks/JFOZ1010/CVE-2026-14871.svg)


## CVE-2026-14431
 Type Confusion in V8 in Google Chrome prior to 150.0.7871.46 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/jaf0rk/CVE-2026-14431](https://github.com/jaf0rk/CVE-2026-14431) :  ![starts](https://img.shields.io/github/stars/jaf0rk/CVE-2026-14431.svg) ![forks](https://img.shields.io/github/forks/jaf0rk/CVE-2026-14431.svg)


## CVE-2026-9271
 Vulnerability Title

- [https://github.com/CerberusMrXi/WordPress-KeepInMind-CVE-2026-9271-Exploit](https://github.com/CerberusMrXi/WordPress-KeepInMind-CVE-2026-9271-Exploit) :  ![starts](https://img.shields.io/github/stars/CerberusMrXi/WordPress-KeepInMind-CVE-2026-9271-Exploit.svg) ![forks](https://img.shields.io/github/forks/CerberusMrXi/WordPress-KeepInMind-CVE-2026-9271-Exploit.svg)


## CVE-2026-1426
 The Advanced AJAX Product Filters plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 3.1.9.6 via deserialization of untrusted input in the shortcode_check function within the Live Composer compatibility layer. This makes it possible for authenticated attackers, with Author-level access and above, to inject a PHP Object. No known POP chain is present in the vulnerable software, which means this vulnerability has no impact unless another plugin or theme containing a POP chain is installed on the site. If a POP chain is present via an additional plugin or theme installed on the target system, it may allow the attacker to perform actions like delete arbitrary files, retrieve sensitive data, or execute code depending on the POP chain present. Note: This vulnerability requires the Live Composer plugin to also be installed and active.

- [https://github.com/hg0434hongzh0/CVE-2026-14266](https://github.com/hg0434hongzh0/CVE-2026-14266) :  ![starts](https://img.shields.io/github/stars/hg0434hongzh0/CVE-2026-14266.svg) ![forks](https://img.shields.io/github/forks/hg0434hongzh0/CVE-2026-14266.svg)


## CVE-2025-68645
 A Local File Inclusion (LFI) vulnerability exists in the Webmail Classic UI of Zimbra Collaboration (ZCS) 10.0 and 10.1 because of improper handling of user-supplied request parameters in the RestFilter servlet. An unauthenticated remote attacker can craft requests to the /h/rest endpoint to influence internal request dispatching, allowing inclusion of arbitrary files from the WebRoot directory.

- [https://github.com/codeb0ssx/CVE-2025-68645-PoC](https://github.com/codeb0ssx/CVE-2025-68645-PoC) :  ![starts](https://img.shields.io/github/stars/codeb0ssx/CVE-2025-68645-PoC.svg) ![forks](https://img.shields.io/github/forks/codeb0ssx/CVE-2025-68645-PoC.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)


## CVE-2025-60357
 AhnLab EPP Management v1.0.14.32-6249 was discovered to contain a NoSQL injection vulnerability via the eventlog/agentEvent/list endpoint.

- [https://github.com/Nullbyte3117/CVE-2025-60357](https://github.com/Nullbyte3117/CVE-2025-60357) :  ![starts](https://img.shields.io/github/stars/Nullbyte3117/CVE-2025-60357.svg) ![forks](https://img.shields.io/github/forks/Nullbyte3117/CVE-2025-60357.svg)


## CVE-2025-14847
 Mismatched length fields in Zlib compressed protocol headers may allow a read of uninitialized heap memory by an unauthenticated client. This issue affects all MongoDB Server v7.0 prior to 7.0.28 versions, MongoDB Server v8.0 versions prior to 8.0.17, MongoDB Server v8.2 versions prior to 8.2.3, MongoDB Server v6.0 versions prior to 6.0.27, MongoDB Server v5.0 versions prior to 5.0.32, MongoDB Server v4.4 versions prior to 4.4.30, MongoDB Server v4.2 versions greater than or equal to 4.2.0, MongoDB Server v4.0 versions greater than or equal to 4.0.0, and MongoDB Server v3.6 versions greater than or equal to 3.6.0.

- [https://github.com/codeb0ssx/CVE-2025-14847-PoC](https://github.com/codeb0ssx/CVE-2025-14847-PoC) :  ![starts](https://img.shields.io/github/stars/codeb0ssx/CVE-2025-14847-PoC.svg) ![forks](https://img.shields.io/github/forks/codeb0ssx/CVE-2025-14847-PoC.svg)


## CVE-2025-8110
 Improper Symbolic link handling in the PutContents API in Gogs allows Local Execution of Code.

- [https://github.com/Shirouuu/CVE-2025-8110-gogs-poc](https://github.com/Shirouuu/CVE-2025-8110-gogs-poc) :  ![starts](https://img.shields.io/github/stars/Shirouuu/CVE-2025-8110-gogs-poc.svg) ![forks](https://img.shields.io/github/forks/Shirouuu/CVE-2025-8110-gogs-poc.svg)


## CVE-2023-26039
 ZoneMinder is a free, open source Closed-circuit television software application for Linux which supports IP, USB and Analog cameras. Versions prior to 1.36.33 and 1.37.33 contain an OS Command Injection via daemonControl() in (/web/api/app/Controller/HostController.php). Any authenticated user can construct an api command to execute any shell command as the web user. This issue is patched in versions 1.36.33 and 1.37.33.

- [https://github.com/ungabunga-ctf/CVE-2023-26039](https://github.com/ungabunga-ctf/CVE-2023-26039) :  ![starts](https://img.shields.io/github/stars/ungabunga-ctf/CVE-2023-26039.svg) ![forks](https://img.shields.io/github/forks/ungabunga-ctf/CVE-2023-26039.svg)


## CVE-2023-25690
Request splitting/smuggling could result in bypass of access controls in the proxy server, proxying unintended URLs to existing origin servers, and cache poisoning. Users are recommended to update to at least version 2.4.56 of Apache HTTP Server.

- [https://github.com/giordy0424/CVE-2023-25690_lab](https://github.com/giordy0424/CVE-2023-25690_lab) :  ![starts](https://img.shields.io/github/stars/giordy0424/CVE-2023-25690_lab.svg) ![forks](https://img.shields.io/github/forks/giordy0424/CVE-2023-25690_lab.svg)


## CVE-2023-23752
 An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

- [https://github.com/BardLaudian/CVE-2023-23752](https://github.com/BardLaudian/CVE-2023-23752) :  ![starts](https://img.shields.io/github/stars/BardLaudian/CVE-2023-23752.svg) ![forks](https://img.shields.io/github/forks/BardLaudian/CVE-2023-23752.svg)

