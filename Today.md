# Update 2026-01-28
## CVE-2026-24306
 Improper access control in Azure Front Door (AFD) allows an unauthorized attacker to elevate privileges over a network.

- [https://github.com/b1gchoi/CVE-2026-24306](https://github.com/b1gchoi/CVE-2026-24306) :  ![starts](https://img.shields.io/github/stars/b1gchoi/CVE-2026-24306.svg) ![forks](https://img.shields.io/github/forks/b1gchoi/CVE-2026-24306.svg)


## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.

- [https://github.com/Lingzesec/cve-2026-24061-GUI](https://github.com/Lingzesec/cve-2026-24061-GUI) :  ![starts](https://img.shields.io/github/stars/Lingzesec/cve-2026-24061-GUI.svg) ![forks](https://img.shields.io/github/forks/Lingzesec/cve-2026-24061-GUI.svg)
- [https://github.com/XsanFlip/CVE-2026-24061-Scanner](https://github.com/XsanFlip/CVE-2026-24061-Scanner) :  ![starts](https://img.shields.io/github/stars/XsanFlip/CVE-2026-24061-Scanner.svg) ![forks](https://img.shields.io/github/forks/XsanFlip/CVE-2026-24061-Scanner.svg)
- [https://github.com/LucasPDiniz/CVE-2026-24061](https://github.com/LucasPDiniz/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/LucasPDiniz/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/LucasPDiniz/CVE-2026-24061.svg)
- [https://github.com/punitdarji/telnetd-cve-2026-24061](https://github.com/punitdarji/telnetd-cve-2026-24061) :  ![starts](https://img.shields.io/github/stars/punitdarji/telnetd-cve-2026-24061.svg) ![forks](https://img.shields.io/github/forks/punitdarji/telnetd-cve-2026-24061.svg)


## CVE-2026-23760
 SmarterTools SmarterMail versions prior to build 9511 contain an authentication bypass vulnerability in the password reset API. The force-reset-password endpoint permits anonymous requests and fails to verify the existing password or a reset token when resetting system administrator accounts. An unauthenticated attacker can supply a target administrator username and a new password to reset the account, resulting in full administrative compromise of the SmarterMail instance. NOTE: SmarterMail system administrator privileges grant the ability to execute operating system commands via built-in management functionality, effectively providing administrative (SYSTEM or root) access on the underlying host.

- [https://github.com/hilwa24/CVE-2026-23760_SmarterMail-Auth-Bypass-and-RCE](https://github.com/hilwa24/CVE-2026-23760_SmarterMail-Auth-Bypass-and-RCE) :  ![starts](https://img.shields.io/github/stars/hilwa24/CVE-2026-23760_SmarterMail-Auth-Bypass-and-RCE.svg) ![forks](https://img.shields.io/github/forks/hilwa24/CVE-2026-23760_SmarterMail-Auth-Bypass-and-RCE.svg)


## CVE-2026-22686
 Enclave is a secure JavaScript sandbox designed for safe AI agent code execution. Prior to 2.7.0, there is a critical sandbox escape vulnerability in enclave-vm that allows untrusted, sandboxed JavaScript code to execute arbitrary code in the host Node.js runtime. When a tool invocation fails, enclave-vm exposes a host-side Error object to sandboxed code. This Error object retains its host realm prototype chain, which can be traversed to reach the host Function constructor. An attacker can intentionally trigger a host error, then climb the prototype chain. Using the host Function constructor, arbitrary JavaScript can be compiled and executed in the host context, fully bypassing the sandbox and granting access to sensitive resources such as process.env, filesystem, and network. This breaks enclave-vm’s core security guarantee of isolating untrusted code. This vulnerability is fixed in 2.7.0.

- [https://github.com/0x30c4/enclave-vm-CVE-2026-22686](https://github.com/0x30c4/enclave-vm-CVE-2026-22686) :  ![starts](https://img.shields.io/github/stars/0x30c4/enclave-vm-CVE-2026-22686.svg) ![forks](https://img.shields.io/github/forks/0x30c4/enclave-vm-CVE-2026-22686.svg)


## CVE-2026-21962
 Vulnerability in the Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in product of Oracle Fusion Middleware (component: Weblogic Server Proxy Plug-in for Apache HTTP Server, Weblogic Server Proxy Plug-in for IIS).  Supported versions that are affected are 12.2.1.4.0, 14.1.1.0.0 and  14.1.2.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in.  While the vulnerability is in Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in accessible data as well as  unauthorized access to critical data or complete access to all Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in accessible data. Note: Affected version for Weblogic Server Proxy Plug-in for IIS is 12.2.1.4.0 only. CVSS 3.1 Base Score 10.0 (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N).

- [https://github.com/ThumpBo/CVE-2026-21962](https://github.com/ThumpBo/CVE-2026-21962) :  ![starts](https://img.shields.io/github/stars/ThumpBo/CVE-2026-21962.svg) ![forks](https://img.shields.io/github/forks/ThumpBo/CVE-2026-21962.svg)


## CVE-2025-70368
 Worklenz version 2.1.5 contains a Stored Cross-Site Scripting (XSS) vulnerability in the Project Updates feature. An attacker can submit a malicious payload in the Updates text field which is then rendered in the reporting view without proper sanitization. Malicious JavaScript may be executed in a victim's browser when they browse to the page containing the vulnerable field.

- [https://github.com/Stolichnayer/CVE-2025-70368](https://github.com/Stolichnayer/CVE-2025-70368) :  ![starts](https://img.shields.io/github/stars/Stolichnayer/CVE-2025-70368.svg) ![forks](https://img.shields.io/github/forks/Stolichnayer/CVE-2025-70368.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-rsc-webpack](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-rsc-webpack) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-rsc-webpack.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-rsc-webpack.svg)
- [https://github.com/lincemorado97/CVE-2025-55182_CVE-2025-66478](https://github.com/lincemorado97/CVE-2025-55182_CVE-2025-66478) :  ![starts](https://img.shields.io/github/stars/lincemorado97/CVE-2025-55182_CVE-2025-66478.svg) ![forks](https://img.shields.io/github/forks/lincemorado97/CVE-2025-55182_CVE-2025-66478.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/Tiger-Foxx/exploit-react-CVE-2025-55182](https://github.com/Tiger-Foxx/exploit-react-CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/Tiger-Foxx/exploit-react-CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/Tiger-Foxx/exploit-react-CVE-2025-55182.svg)


## CVE-2025-49132
 Pterodactyl is a free, open-source game server management panel. Prior to version 1.11.11, using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated. With the ability to execute arbitrary code it could be used to gain access to the Panel's server, read credentials from the Panel's config, extract sensitive information from the database, access files of servers managed by the panel, etc. This issue has been patched in version 1.11.11. There are no software workarounds for this vulnerability, but use of an external Web Application Firewall (WAF) could help mitigate this attack.

- [https://github.com/0xf3d0rq/CVE-2025-49132](https://github.com/0xf3d0rq/CVE-2025-49132) :  ![starts](https://img.shields.io/github/stars/0xf3d0rq/CVE-2025-49132.svg) ![forks](https://img.shields.io/github/forks/0xf3d0rq/CVE-2025-49132.svg)


## CVE-2025-41243
  *  The actuator endpoints are unsecured.

- [https://github.com/SFN233/CVE-2025-41243-Vulnerability-Lab](https://github.com/SFN233/CVE-2025-41243-Vulnerability-Lab) :  ![starts](https://img.shields.io/github/stars/SFN233/CVE-2025-41243-Vulnerability-Lab.svg) ![forks](https://img.shields.io/github/forks/SFN233/CVE-2025-41243-Vulnerability-Lab.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/Grand-Moomin/Vuln-Next.js-CVE-2025-29927](https://github.com/Grand-Moomin/Vuln-Next.js-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/Grand-Moomin/Vuln-Next.js-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/Grand-Moomin/Vuln-Next.js-CVE-2025-29927.svg)


## CVE-2025-27237
 In Zabbix Agent and Agent 2 on Windows, the OpenSSL configuration file is loaded from a path writable by low-privileged users, allowing malicious modification and potential local privilege escalation by injecting a DLL.

- [https://github.com/HackingLZ/CVE-2025-27237](https://github.com/HackingLZ/CVE-2025-27237) :  ![starts](https://img.shields.io/github/stars/HackingLZ/CVE-2025-27237.svg) ![forks](https://img.shields.io/github/forks/HackingLZ/CVE-2025-27237.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/nohack1212/CVE-2025-24893-](https://github.com/nohack1212/CVE-2025-24893-) :  ![starts](https://img.shields.io/github/stars/nohack1212/CVE-2025-24893-.svg) ![forks](https://img.shields.io/github/forks/nohack1212/CVE-2025-24893-.svg)


## CVE-2025-14855
 The SureForms plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the form field parameters in all versions up to, and including, 2.2.0 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/ch4r0nn/CVE-2025-14855-POC](https://github.com/ch4r0nn/CVE-2025-14855-POC) :  ![starts](https://img.shields.io/github/stars/ch4r0nn/CVE-2025-14855-POC.svg) ![forks](https://img.shields.io/github/forks/ch4r0nn/CVE-2025-14855-POC.svg)


## CVE-2025-13374
 The Kalrav AI Agent plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the kalrav_upload_file AJAX action in all versions up to, and including, 2.3.3. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/d0n601/CVE-2025-13374](https://github.com/d0n601/CVE-2025-13374) :  ![starts](https://img.shields.io/github/stars/d0n601/CVE-2025-13374.svg) ![forks](https://img.shields.io/github/forks/d0n601/CVE-2025-13374.svg)


## CVE-2024-23334
 aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. When using aiohttp as a web server and configuring static routes, it is necessary to specify the root path for static files. Additionally, the option 'follow_symlinks' can be used to determine whether to follow symbolic links outside the static root directory. When 'follow_symlinks' is set to True, there is no validation to check if reading a file is within the root directory. This can lead to directory traversal vulnerabilities, resulting in unauthorized access to arbitrary files on the system, even when symlinks are not present.  Disabling follow_symlinks and using a reverse proxy are encouraged mitigations.  Version 3.9.2 fixes this issue.

- [https://github.com/Sn0wBaall/CVE-2024-23334-PoC](https://github.com/Sn0wBaall/CVE-2024-23334-PoC) :  ![starts](https://img.shields.io/github/stars/Sn0wBaall/CVE-2024-23334-PoC.svg) ![forks](https://img.shields.io/github/forks/Sn0wBaall/CVE-2024-23334-PoC.svg)


## CVE-2024-11467
 Omnissa Horizon Client for macOS contains a Local privilege escalation (LPE) Vulnerability due to a logic flaw. Successful exploitation of this issue may allow attackers with user privileges to escalate their privileges to root on the system where the Horizon Client for macOS is installed.

- [https://github.com/null-event/CVE-2024-11467](https://github.com/null-event/CVE-2024-11467) :  ![starts](https://img.shields.io/github/stars/null-event/CVE-2024-11467.svg) ![forks](https://img.shields.io/github/forks/null-event/CVE-2024-11467.svg)


## CVE-2024-6651
 The WordPress File Upload WordPress plugin before 4.24.8 does not sanitise and escape a parameter before outputting it back in the page, leading to a Reflected Cross-Site Scripting which could be used against high privilege users such as admin

- [https://github.com/yup-Ivan/CVE-2024-6651](https://github.com/yup-Ivan/CVE-2024-6651) :  ![starts](https://img.shields.io/github/stars/yup-Ivan/CVE-2024-6651.svg) ![forks](https://img.shields.io/github/forks/yup-Ivan/CVE-2024-6651.svg)


## CVE-2024-0044
 In createSessionInternal of PackageInstallerService.java, there is a possible run-as any app due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/l1ackerronin/CVE-2024-0044](https://github.com/l1ackerronin/CVE-2024-0044) :  ![starts](https://img.shields.io/github/stars/l1ackerronin/CVE-2024-0044.svg) ![forks](https://img.shields.io/github/forks/l1ackerronin/CVE-2024-0044.svg)


## CVE-2022-47447
 Cross-Site Request Forgery (CSRF) vulnerability in Mathieu Chartier WordPress WP-Advanced-Search plugin = 3.3.8 versions.

- [https://github.com/yup-Ivan/CVE-2022-47447](https://github.com/yup-Ivan/CVE-2022-47447) :  ![starts](https://img.shields.io/github/stars/yup-Ivan/CVE-2022-47447.svg) ![forks](https://img.shields.io/github/forks/yup-Ivan/CVE-2022-47447.svg)


## CVE-2022-25012
 Argus Surveillance DVR v4.0 employs weak password encryption.

- [https://github.com/XK3NF4/CVE-2022-25012](https://github.com/XK3NF4/CVE-2022-25012) :  ![starts](https://img.shields.io/github/stars/XK3NF4/CVE-2022-25012.svg) ![forks](https://img.shields.io/github/forks/XK3NF4/CVE-2022-25012.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `grafana_host_url/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/0xf3d0rq/CVE-2021-43798](https://github.com/0xf3d0rq/CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/0xf3d0rq/CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/0xf3d0rq/CVE-2021-43798.svg)


## CVE-2021-27065
 Microsoft Exchange Server Remote Code Execution Vulnerability

- [https://github.com/SimoesCTT/CTT-ProxyLogon-RCE-v1.0---Convergent-Time-Theory-Enhanced-Microsoft-Exchange-Exploit](https://github.com/SimoesCTT/CTT-ProxyLogon-RCE-v1.0---Convergent-Time-Theory-Enhanced-Microsoft-Exchange-Exploit) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/CTT-ProxyLogon-RCE-v1.0---Convergent-Time-Theory-Enhanced-Microsoft-Exchange-Exploit.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/CTT-ProxyLogon-RCE-v1.0---Convergent-Time-Theory-Enhanced-Microsoft-Exchange-Exploit.svg)


## CVE-2021-26855
 Microsoft Exchange Server Remote Code Execution Vulnerability

- [https://github.com/SimoesCTT/CTT-ProxyLogon-RCE-v1.0---Convergent-Time-Theory-Enhanced-Microsoft-Exchange-Exploit](https://github.com/SimoesCTT/CTT-ProxyLogon-RCE-v1.0---Convergent-Time-Theory-Enhanced-Microsoft-Exchange-Exploit) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/CTT-ProxyLogon-RCE-v1.0---Convergent-Time-Theory-Enhanced-Microsoft-Exchange-Exploit.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/CTT-ProxyLogon-RCE-v1.0---Convergent-Time-Theory-Enhanced-Microsoft-Exchange-Exploit.svg)


## CVE-2020-0096
 In startActivities of ActivityStartController.java, there is a possible escalation of privilege due to a confused deputy. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-8.0 Android-8.1 Android-9Android ID: A-145669109

- [https://github.com/l1ackerronin/CVE-2020-0096-strandhogg-exploit-p0c](https://github.com/l1ackerronin/CVE-2020-0096-strandhogg-exploit-p0c) :  ![starts](https://img.shields.io/github/stars/l1ackerronin/CVE-2020-0096-strandhogg-exploit-p0c.svg) ![forks](https://img.shields.io/github/forks/l1ackerronin/CVE-2020-0096-strandhogg-exploit-p0c.svg)


## CVE-2017-7921
 An Improper Authentication issue was discovered in Hikvision DS-2CD2xx2F-I Series V5.2.0 build 140721 to V5.4.0 build 160530, DS-2CD2xx0F-I Series V5.2.0 build 140721 to V5.4.0 Build 160401, DS-2CD2xx2FWD Series V5.3.1 build 150410 to V5.4.4 Build 161125, DS-2CD4x2xFWD Series V5.2.0 build 140721 to V5.4.0 Build 160414, DS-2CD4xx5 Series V5.2.0 build 140721 to V5.4.0 Build 160421, DS-2DFx Series V5.2.0 build 140805 to V5.4.5 Build 160928, and DS-2CD63xx Series V5.0.9 build 140305 to V5.3.5 Build 160106 devices. The improper authentication vulnerability occurs when an application does not adequately or correctly authenticate users. This may allow a malicious user to escalate his or her privileges on the system and gain access to sensitive information.

- [https://github.com/0xf3d0rq/CVE-2017-7921](https://github.com/0xf3d0rq/CVE-2017-7921) :  ![starts](https://img.shields.io/github/stars/0xf3d0rq/CVE-2017-7921.svg) ![forks](https://img.shields.io/github/forks/0xf3d0rq/CVE-2017-7921.svg)


## CVE-2013-0007
 Microsoft XML Core Services (aka MSXML) 4.0, 5.0, and 6.0 does not properly parse XML content, which allows remote attackers to execute arbitrary code via a crafted web page, aka "MSXML XSLT Vulnerability."

- [https://github.com/jyyjw/msxml4-remediation](https://github.com/jyyjw/msxml4-remediation) :  ![starts](https://img.shields.io/github/stars/jyyjw/msxml4-remediation.svg) ![forks](https://img.shields.io/github/forks/jyyjw/msxml4-remediation.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/tshaq17/vsftpd-2.3.4---Backdoor-Command-Execution](https://github.com/tshaq17/vsftpd-2.3.4---Backdoor-Command-Execution) :  ![starts](https://img.shields.io/github/stars/tshaq17/vsftpd-2.3.4---Backdoor-Command-Execution.svg) ![forks](https://img.shields.io/github/forks/tshaq17/vsftpd-2.3.4---Backdoor-Command-Execution.svg)


## CVE-2009-3103
 Array index error in the SMBv2 protocol implementation in srv2.sys in Microsoft Windows Vista Gold, SP1, and SP2, Windows Server 2008 Gold and SP2, and Windows 7 RC allows remote attackers to execute arbitrary code or cause a denial of service (system crash) via an & (ampersand) character in a Process ID High header field in a NEGOTIATE PROTOCOL REQUEST packet, which triggers an attempted dereference of an out-of-bounds memory location, aka "SMBv2 Negotiation Vulnerability." NOTE: some of these details are obtained from third party information.

- [https://github.com/afifudinmtop/CVE-2009-3103](https://github.com/afifudinmtop/CVE-2009-3103) :  ![starts](https://img.shields.io/github/stars/afifudinmtop/CVE-2009-3103.svg) ![forks](https://img.shields.io/github/forks/afifudinmtop/CVE-2009-3103.svg)

