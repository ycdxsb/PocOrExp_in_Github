# Update 2025-11-29
## CVE-2025-63420
 CrushFTP11 before 11.3.7_57 is vulnerable to stored HTML injection in the CrushFTP Admin Panel (Reports / "Who Created Folder"), enabling persistent HTML execution in admin sessions.

- [https://github.com/hossainshadat/CVE-2025-63420](https://github.com/hossainshadat/CVE-2025-63420) :  ![starts](https://img.shields.io/github/stars/hossainshadat/CVE-2025-63420.svg) ![forks](https://img.shields.io/github/forks/hossainshadat/CVE-2025-63420.svg)


## CVE-2025-63419
 Cross Site Scripting (XSS) vulnerability in CrushFTP 11.3.6_48. The Web-Based Server has a feature where users can share files, the feature reflects the filename to an emailbody field with no sanitations leading to HTML Injection.

- [https://github.com/hossainshadat/CVE-2025-63419](https://github.com/hossainshadat/CVE-2025-63419) :  ![starts](https://img.shields.io/github/stars/hossainshadat/CVE-2025-63419.svg) ![forks](https://img.shields.io/github/forks/hossainshadat/CVE-2025-63419.svg)


## CVE-2025-62593
 Ray is an AI compute engine. Prior to version 2.52.0, developers working with Ray as a development tool can be exploited via a critical RCE vulnerability exploitable via Firefox and Safari. This vulnerability is due to an insufficient guard against browser-based attacks, as the current defense uses the User-Agent header starting with the string "Mozilla" as a defense mechanism. This defense is insufficient as the fetch specification allows the User-Agent header to be modified. Combined with a DNS rebinding attack against the browser, and this vulnerability is exploitable against a developer running Ray who inadvertently visits a malicious website, or is served a malicious advertisement (malvertising). This issue has been patched in version 2.52.0.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-62593](https://github.com/B1ack4sh/Blackash-CVE-2025-62593) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-62593.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-62593.svg)


## CVE-2025-59528
 Flowise is a drag & drop user interface to build a customized large language model flow. In version 3.0.5, Flowise is vulnerable to remote code execution. The CustomMCP node allows users to input configuration settings for connecting to an external MCP server. This node parses the user-provided mcpServerConfig string to build the MCP server configuration. However, during this process, it executes JavaScript code without any security validation. Specifically, inside the convertToValidJSONString function, user input is directly passed to the Function() constructor, which evaluates and executes the input as JavaScript code. Since this runs with full Node.js runtime privileges, it can access dangerous modules such as child_process and fs. This issue has been patched in version 3.0.6.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-59528](https://github.com/B1ack4sh/Blackash-CVE-2025-59528) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-59528.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-59528.svg)


## CVE-2025-58360
 GeoServer is an open source server that allows users to share and edit geospatial data. From version 2.26.0 to before 2.26.2 and before 2.25.6, an XML External Entity (XXE) vulnerability was identified. The application accepts XML input through a specific endpoint /geoserver/wms operation GetMap. However, this input is not sufficiently sanitized or restricted, allowing an attacker to define external entities within the XML request. This issue has been patched in GeoServer 2.25.6, GeoServer 2.26.3, and GeoServer 2.27.0.

- [https://github.com/quyenheu/CVE-2025-58360](https://github.com/quyenheu/CVE-2025-58360) :  ![starts](https://img.shields.io/github/stars/quyenheu/CVE-2025-58360.svg) ![forks](https://img.shields.io/github/forks/quyenheu/CVE-2025-58360.svg)


## CVE-2025-57833
 An issue was discovered in Django 4.2 before 4.2.24, 5.1 before 5.1.12, and 5.2 before 5.2.6. FilteredRelation is subject to SQL injection in column aliases, using a suitably crafted dictionary, with dictionary expansion, as the **kwargs passed QuerySet.annotate() or QuerySet.alias().

- [https://github.com/Gayang2902/CVE-2025-57833](https://github.com/Gayang2902/CVE-2025-57833) :  ![starts](https://img.shields.io/github/stars/Gayang2902/CVE-2025-57833.svg) ![forks](https://img.shields.io/github/forks/Gayang2902/CVE-2025-57833.svg)


## CVE-2025-57310
 A Cross-Site Request Forgery (CSRF) vulnerability in Salmen2/Simple-Faucet-Script v1.07 via crafted POST request to admin.php?p=ads&c=1 allowing attackers to execute arbitrary code.

- [https://github.com/hossainshadat/CVE-2025-57310](https://github.com/hossainshadat/CVE-2025-57310) :  ![starts](https://img.shields.io/github/stars/hossainshadat/CVE-2025-57310.svg) ![forks](https://img.shields.io/github/forks/hossainshadat/CVE-2025-57310.svg)


## CVE-2025-53367
 DjVuLibre is a GPL implementation of DjVu, a web-centric format for distributing documents and images. Prior to version 3.5.29, the MMRDecoder::scanruns method is affected by an OOB-write vulnerability, because it does not check that the xr pointer stays within the bounds of the allocated buffer. This can lead to writes beyond the allocated memory, resulting in a heap corruption condition. An out-of-bounds read with pr is also possible for the same reason. This issue has been patched in version 3.5.29.

- [https://github.com/ThePhykon/CVE-2025-53367-POC](https://github.com/ThePhykon/CVE-2025-53367-POC) :  ![starts](https://img.shields.io/github/stars/ThePhykon/CVE-2025-53367-POC.svg) ![forks](https://img.shields.io/github/forks/ThePhykon/CVE-2025-53367-POC.svg)


## CVE-2025-50433
 An issue was discovered in imonnit.com (2025-04-24) allowing malicious actors to gain escalated privileges via crafted password reset to take over arbitrary user accounts.

- [https://github.com/0xMandor/CVE-2025-50433](https://github.com/0xMandor/CVE-2025-50433) :  ![starts](https://img.shields.io/github/stars/0xMandor/CVE-2025-50433.svg) ![forks](https://img.shields.io/github/forks/0xMandor/CVE-2025-50433.svg)


## CVE-2025-39401
 Unrestricted Upload of File with Dangerous Type vulnerability in mojoomla WPAMS allows Upload a Web Shell to a Web Server.This issue affects WPAMS: from n/a through 44.0 (17-08-2023).

- [https://github.com/Nxploited/CVE-2025-39401](https://github.com/Nxploited/CVE-2025-39401) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-39401.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-39401.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/justjoeyking/CVE-2025-32463](https://github.com/justjoeyking/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/justjoeyking/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/justjoeyking/CVE-2025-32463.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/soltanali0/CVE-2025-32433-Eploit](https://github.com/soltanali0/CVE-2025-32433-Eploit) :  ![starts](https://img.shields.io/github/stars/soltanali0/CVE-2025-32433-Eploit.svg) ![forks](https://img.shields.io/github/forks/soltanali0/CVE-2025-32433-Eploit.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/Grand-Moomin/Vuln-Next.js-CVE-2025-29927](https://github.com/Grand-Moomin/Vuln-Next.js-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/Grand-Moomin/Vuln-Next.js-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/Grand-Moomin/Vuln-Next.js-CVE-2025-29927.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/dr4xp/xwiki-rce](https://github.com/dr4xp/xwiki-rce) :  ![starts](https://img.shields.io/github/stars/dr4xp/xwiki-rce.svg) ![forks](https://img.shields.io/github/forks/dr4xp/xwiki-rce.svg)


## CVE-2025-12735
 The expr-eval library is a JavaScript expression parser and evaluator designed to safely evaluate mathematical expressions with user-defined variables. However, due to insufficient input validation, an attacker can pass a crafted context object or use MEMBER of the context object into the evaluate() function and trigger arbitrary code execution.

- [https://github.com/alecasg555/safe-expr-eval](https://github.com/alecasg555/safe-expr-eval) :  ![starts](https://img.shields.io/github/stars/alecasg555/safe-expr-eval.svg) ![forks](https://img.shields.io/github/forks/alecasg555/safe-expr-eval.svg)


## CVE-2025-8088
     from ESET.

- [https://github.com/4daysday/cve-2025-8088](https://github.com/4daysday/cve-2025-8088) :  ![starts](https://img.shields.io/github/stars/4daysday/cve-2025-8088.svg) ![forks](https://img.shields.io/github/forks/4daysday/cve-2025-8088.svg)


## CVE-2025-6532
 A vulnerability classified as problematic was found in NOYAFA/Xiami LF9 Pro up to 20250611. Affected by this vulnerability is an unknown functionality of the component RTSP Live Video Stream Endpoint. The manipulation leads to improper access controls. The attack can only be initiated within the local network. The exploit has been disclosed to the public and may be used. This dashcam is distributed by multiple resellers and different names.

- [https://github.com/Smarttfoxx/CVE-2025-65320](https://github.com/Smarttfoxx/CVE-2025-65320) :  ![starts](https://img.shields.io/github/stars/Smarttfoxx/CVE-2025-65320.svg) ![forks](https://img.shields.io/github/forks/Smarttfoxx/CVE-2025-65320.svg)


## CVE-2024-43425
 A flaw was found in Moodle. Additional restrictions are required to avoid a remote code execution risk in calculated question types. Note: This requires the capability to add/update questions.

- [https://github.com/voniem12/KTLHPM](https://github.com/voniem12/KTLHPM) :  ![starts](https://img.shields.io/github/stars/voniem12/KTLHPM.svg) ![forks](https://img.shields.io/github/forks/voniem12/KTLHPM.svg)


## CVE-2024-27477
 In Leantime 3.0.6, a Cross-Site Scripting vulnerability exists within the ticket creation and modification functionality, allowing attackers to inject malicious JavaScript code into the title field of tickets (also known as to-dos). This stored XSS vulnerability can be exploited to perform Server-Side Request Forgery (SSRF) attacks.

- [https://github.com/dead1nfluence/Leantime-POC](https://github.com/dead1nfluence/Leantime-POC) :  ![starts](https://img.shields.io/github/stars/dead1nfluence/Leantime-POC.svg) ![forks](https://img.shields.io/github/forks/dead1nfluence/Leantime-POC.svg)


## CVE-2024-27476
 Leantime 3.0.6 is vulnerable to HTML Injection via /dashboard/show#/tickets/newTicket.

- [https://github.com/dead1nfluence/Leantime-POC](https://github.com/dead1nfluence/Leantime-POC) :  ![starts](https://img.shields.io/github/stars/dead1nfluence/Leantime-POC.svg) ![forks](https://img.shields.io/github/forks/dead1nfluence/Leantime-POC.svg)


## CVE-2024-27474
 Leantime 3.0.6 is vulnerable to Cross Site Request Forgery (CSRF). This vulnerability allows malicious actors to perform unauthorized actions on behalf of authenticated users, specifically administrators.

- [https://github.com/dead1nfluence/Leantime-POC](https://github.com/dead1nfluence/Leantime-POC) :  ![starts](https://img.shields.io/github/stars/dead1nfluence/Leantime-POC.svg) ![forks](https://img.shields.io/github/forks/dead1nfluence/Leantime-POC.svg)


## CVE-2024-3661
 DHCP can add routes to a client’s routing table via the classless static route option (121). VPN-based security solutions that rely on routes to redirect traffic can be forced to leak traffic over the physical interface. An attacker on the same local network can read, disrupt, or possibly modify network traffic that was expected to be protected by the VPN.

- [https://github.com/YardenFadida/CVE-2024-3661_Demo](https://github.com/YardenFadida/CVE-2024-3661_Demo) :  ![starts](https://img.shields.io/github/stars/YardenFadida/CVE-2024-3661_Demo.svg) ![forks](https://img.shields.io/github/forks/YardenFadida/CVE-2024-3661_Demo.svg)


## CVE-2023-42793
 In JetBrains TeamCity before 2023.05.4 authentication bypass leading to RCE on TeamCity Server was possible

- [https://github.com/cxdxnt/CVE-2023-42793](https://github.com/cxdxnt/CVE-2023-42793) :  ![starts](https://img.shields.io/github/stars/cxdxnt/CVE-2023-42793.svg) ![forks](https://img.shields.io/github/forks/cxdxnt/CVE-2023-42793.svg)


## CVE-2022-21587
 Vulnerability in the Oracle Web Applications Desktop Integrator product of Oracle E-Business Suite (component: Upload). Supported versions that are affected are 12.2.3-12.2.11. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Web Applications Desktop Integrator. Successful attacks of this vulnerability can result in takeover of Oracle Web Applications Desktop Integrator. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/Ashwesker/Blackash-CVE-2022-21587](https://github.com/Ashwesker/Blackash-CVE-2022-21587) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Blackash-CVE-2022-21587.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Blackash-CVE-2022-21587.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `grafana_host_url/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/f3d0rq/CVE-2021-43798](https://github.com/f3d0rq/CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/f3d0rq/CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/f3d0rq/CVE-2021-43798.svg)


## CVE-2021-43008
 Improper Access Control in Adminer versions 1.12.0 to 4.6.2 (fixed in version 4.6.3) allows an attacker to achieve Arbitrary File Read on the remote server by requesting the Adminer to connect to a remote MySQL database.

- [https://github.com/Bamolitho/adminer_CVE-2021-43008](https://github.com/Bamolitho/adminer_CVE-2021-43008) :  ![starts](https://img.shields.io/github/stars/Bamolitho/adminer_CVE-2021-43008.svg) ![forks](https://img.shields.io/github/forks/Bamolitho/adminer_CVE-2021-43008.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/ch4os443/CVE-2021-41773](https://github.com/ch4os443/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/ch4os443/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/ch4os443/CVE-2021-41773.svg)


## CVE-2020-14883
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows high privileged attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 7.2 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/Ashwesker/Blackash-CVE-2020-14883](https://github.com/Ashwesker/Blackash-CVE-2020-14883) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Blackash-CVE-2020-14883.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Blackash-CVE-2020-14883.svg)


## CVE-2020-14882
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/Ashwesker/Blackash-CVE-2020-14882](https://github.com/Ashwesker/Blackash-CVE-2020-14882) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Blackash-CVE-2020-14882.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Blackash-CVE-2020-14882.svg)


## CVE-2020-5902
 In BIG-IP versions 15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 13.1.0-13.1.3.3, 12.1.0-12.1.5.1, and 11.6.1-11.6.5.1, the Traffic Management User Interface (TMUI), also referred to as the Configuration utility, has a Remote Code Execution (RCE) vulnerability in undisclosed pages.

- [https://github.com/Ashwesker/Blackash-CVE-2020-5902](https://github.com/Ashwesker/Blackash-CVE-2020-5902) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Blackash-CVE-2020-5902.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Blackash-CVE-2020-5902.svg)


## CVE-2020-2551
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: WLS Core Components). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/Ashwesker/Blackash-CVE-2020-2551](https://github.com/Ashwesker/Blackash-CVE-2020-2551) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Blackash-CVE-2020-2551.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Blackash-CVE-2020-2551.svg)


## CVE-2019-11043
 In PHP versions 7.1.x below 7.1.33, 7.2.x below 7.2.24 and 7.3.x below 7.3.11 in certain configurations of FPM setup it is possible to cause FPM module to write past allocated buffers into the space reserved for FCGI protocol data, thus opening the possibility of remote code execution.

- [https://github.com/AndrewMas99/CVE-2019-11043-Vulnerability](https://github.com/AndrewMas99/CVE-2019-11043-Vulnerability) :  ![starts](https://img.shields.io/github/stars/AndrewMas99/CVE-2019-11043-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/AndrewMas99/CVE-2019-11043-Vulnerability.svg)


## CVE-2017-7921
 An Improper Authentication issue was discovered in Hikvision DS-2CD2xx2F-I Series V5.2.0 build 140721 to V5.4.0 build 160530, DS-2CD2xx0F-I Series V5.2.0 build 140721 to V5.4.0 Build 160401, DS-2CD2xx2FWD Series V5.3.1 build 150410 to V5.4.4 Build 161125, DS-2CD4x2xFWD Series V5.2.0 build 140721 to V5.4.0 Build 160414, DS-2CD4xx5 Series V5.2.0 build 140721 to V5.4.0 Build 160421, DS-2DFx Series V5.2.0 build 140805 to V5.4.5 Build 160928, and DS-2CD63xx Series V5.0.9 build 140305 to V5.3.5 Build 160106 devices. The improper authentication vulnerability occurs when an application does not adequately or correctly authenticate users. This may allow a malicious user to escalate his or her privileges on the system and gain access to sensitive information.

- [https://github.com/f3d0rq/CVE-2017-7921](https://github.com/f3d0rq/CVE-2017-7921) :  ![starts](https://img.shields.io/github/stars/f3d0rq/CVE-2017-7921.svg) ![forks](https://img.shields.io/github/forks/f3d0rq/CVE-2017-7921.svg)


## CVE-2017-0144
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/Ashwesker/Blackash-CVE-2017-0144](https://github.com/Ashwesker/Blackash-CVE-2017-0144) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Blackash-CVE-2017-0144.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Blackash-CVE-2017-0144.svg)

