# Update 2025-09-08
## CVE-2025-58443
 FOG is a free open-source cloning/imaging/rescue suite/inventory management system. Versions 1.5.10.1673 and below contain an authentication bypass vulnerability. It is possible for an attacker to perform an unauthenticated DB dump where they could pull a full SQL DB without credentials. A fix is expected to be released 9/15/2025. To address this vulnerability immediately, upgrade to the latest version of either the dev-branch or working-1.6 branch. This will patch the issue for users concerned about immediate exposure. See the FOG Project documentation for step-by-step upgrade instructions: https://docs.fogproject.org/en/latest/install-fog-server#choosing-a-fog-version.

- [https://github.com/casp3r0x0/CVE-2025-58443](https://github.com/casp3r0x0/CVE-2025-58443) :  ![starts](https://img.shields.io/github/stars/casp3r0x0/CVE-2025-58443.svg) ![forks](https://img.shields.io/github/forks/casp3r0x0/CVE-2025-58443.svg)


## CVE-2025-54309
 CrushFTP 10 before 10.8.5 and 11 before 11.3.4_23, when the DMZ proxy feature is not used, mishandles AS2 validation and consequently allows remote attackers to obtain admin access via HTTPS, as exploited in the wild in July 2025.

- [https://github.com/whisperer1290/CVE-2025-54309__Enhanced_exploit](https://github.com/whisperer1290/CVE-2025-54309__Enhanced_exploit) :  ![starts](https://img.shields.io/github/stars/whisperer1290/CVE-2025-54309__Enhanced_exploit.svg) ![forks](https://img.shields.io/github/forks/whisperer1290/CVE-2025-54309__Enhanced_exploit.svg)


## CVE-2025-33073
 Improper access control in Windows SMB allows an authorized attacker to elevate privileges over a network.

- [https://github.com/cve-2025-33073/cve-2025-33073](https://github.com/cve-2025-33073/cve-2025-33073) :  ![starts](https://img.shields.io/github/stars/cve-2025-33073/cve-2025-33073.svg) ![forks](https://img.shields.io/github/forks/cve-2025-33073/cve-2025-33073.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/AventurineJ/CVE-2025-29927-Research](https://github.com/AventurineJ/CVE-2025-29927-Research) :  ![starts](https://img.shields.io/github/stars/AventurineJ/CVE-2025-29927-Research.svg) ![forks](https://img.shields.io/github/forks/AventurineJ/CVE-2025-29927-Research.svg)


## CVE-2025-24204
 The issue was addressed with improved checks. This issue is fixed in macOS Sequoia 15.4. An app may be able to access protected user data.

- [https://github.com/bale170501/decrypted](https://github.com/bale170501/decrypted) :  ![starts](https://img.shields.io/github/stars/bale170501/decrypted.svg) ![forks](https://img.shields.io/github/forks/bale170501/decrypted.svg)


## CVE-2025-10046
 The ELEX WooCommerce Google Shopping (Google Product Feed) plugin for WordPress is vulnerable to SQL Injection via the 'file_to_delete' parameter in all versions up to, and including, 1.4.3 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for authenticated attackers, with Administrator-level access and above, to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/byteReaper77/CVE-2025-10046](https://github.com/byteReaper77/CVE-2025-10046) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-10046.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-10046.svg)


## CVE-2025-8088
     from ESET.

- [https://github.com/cozythrill/CVE-2025-8088](https://github.com/cozythrill/CVE-2025-8088) :  ![starts](https://img.shields.io/github/stars/cozythrill/CVE-2025-8088.svg) ![forks](https://img.shields.io/github/forks/cozythrill/CVE-2025-8088.svg)


## CVE-2025-5238
 The YITH WooCommerce Wishlist plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the ‘id’ parameter in all versions up to, and including, 4.5.0 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/ktr4ck3r/CVE-2025-52389](https://github.com/ktr4ck3r/CVE-2025-52389) :  ![starts](https://img.shields.io/github/stars/ktr4ck3r/CVE-2025-52389.svg) ![forks](https://img.shields.io/github/forks/ktr4ck3r/CVE-2025-52389.svg)


## CVE-2025-1055
 A vulnerability in the K7RKScan.sys driver, part of the K7 Security Anti-Malware suite, allows a local low-privilege user to send crafted IOCTL requests to terminate a wide range of processes running with administrative or system-level privileges, with the exception of those inherently protected by the operating system. This flaw stems from missing access control in the driver's IOCTL handler, enabling unprivileged users to perform privileged actions in kernel space. Successful exploitation can lead to denial of service by disrupting critical services or privileged applications.

- [https://github.com/BlackSnufkin/BYOVD](https://github.com/BlackSnufkin/BYOVD) :  ![starts](https://img.shields.io/github/stars/BlackSnufkin/BYOVD.svg) ![forks](https://img.shields.io/github/forks/BlackSnufkin/BYOVD.svg)


## CVE-2025-0411
The specific flaw exists within the handling of archived files. When extracting files from a crafted archive that bears the Mark-of-the-Web, 7-Zip does not propagate the Mark-of-the-Web to the extracted files. An attacker can leverage this vulnerability to execute arbitrary code in the context of the current user. Was ZDI-CAN-25456.

- [https://github.com/RustMacrosRecoil/7-Zip-CVE-2025-0411-POC](https://github.com/RustMacrosRecoil/7-Zip-CVE-2025-0411-POC) :  ![starts](https://img.shields.io/github/stars/RustMacrosRecoil/7-Zip-CVE-2025-0411-POC.svg) ![forks](https://img.shields.io/github/forks/RustMacrosRecoil/7-Zip-CVE-2025-0411-POC.svg)


## CVE-2025-0011
 Improper removal of sensitive information before storage or transfer in AMD Crash Defender could allow an attacker to obtain kernel address information potentially resulting in loss of confidentiality.

- [https://github.com/binarywarm/kentico-xperience13-AuthBypass-CVE-2025-0011](https://github.com/binarywarm/kentico-xperience13-AuthBypass-CVE-2025-0011) :  ![starts](https://img.shields.io/github/stars/binarywarm/kentico-xperience13-AuthBypass-CVE-2025-0011.svg) ![forks](https://img.shields.io/github/forks/binarywarm/kentico-xperience13-AuthBypass-CVE-2025-0011.svg)


## CVE-2024-28397
 An issue in the component js2py.disable_pyimport() of js2py up to v0.74 allows attackers to execute arbitrary code via a crafted API call.

- [https://github.com/ExtremeUday/Remote-Code-Execution-CVE-2024-28397-pyload-ng-js2py-](https://github.com/ExtremeUday/Remote-Code-Execution-CVE-2024-28397-pyload-ng-js2py-) :  ![starts](https://img.shields.io/github/stars/ExtremeUday/Remote-Code-Execution-CVE-2024-28397-pyload-ng-js2py-.svg) ![forks](https://img.shields.io/github/forks/ExtremeUday/Remote-Code-Execution-CVE-2024-28397-pyload-ng-js2py-.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/mananjain61/PHP-CGI-INTERNAL-RCE](https://github.com/mananjain61/PHP-CGI-INTERNAL-RCE) :  ![starts](https://img.shields.io/github/stars/mananjain61/PHP-CGI-INTERNAL-RCE.svg) ![forks](https://img.shields.io/github/forks/mananjain61/PHP-CGI-INTERNAL-RCE.svg)


## CVE-2023-32315
 Openfire is an XMPP server licensed under the Open Source Apache License. Openfire's administrative console, a web-based application, was found to be vulnerable to a path traversal attack via the setup environment. This permitted an unauthenticated user to use the unauthenticated Openfire Setup Environment in an already configured Openfire environment to access restricted pages in the Openfire Admin Console reserved for administrative users. This vulnerability affects all versions of Openfire that have been released since April 2015, starting with version 3.10.0. The problem has been patched in Openfire release 4.7.5 and 4.6.8, and further improvements will be included in the yet-to-be released first version on the 4.8 branch (which is expected to be version 4.8.0). Users are advised to upgrade. If an Openfire upgrade isn’t available for a specific release, or isn’t quickly actionable, users may see the linked github advisory (GHSA-gw42-f939-fhvm) for mitigation advice.

- [https://github.com/rag-fish/openfire-exploit-suite](https://github.com/rag-fish/openfire-exploit-suite) :  ![starts](https://img.shields.io/github/stars/rag-fish/openfire-exploit-suite.svg) ![forks](https://img.shields.io/github/forks/rag-fish/openfire-exploit-suite.svg)


## CVE-2022-44262
 ff4j 1.8.1 is vulnerable to Remote Code Execution (RCE).

- [https://github.com/shoucheng3/ff4j__ff4j_CVE-2022-44262_1_8_13_fixed](https://github.com/shoucheng3/ff4j__ff4j_CVE-2022-44262_1_8_13_fixed) :  ![starts](https://img.shields.io/github/stars/shoucheng3/ff4j__ff4j_CVE-2022-44262_1_8_13_fixed.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/ff4j__ff4j_CVE-2022-44262_1_8_13_fixed.svg)


## CVE-2022-39299
 Passport-SAML is a SAML 2.0 authentication provider for Passport, the Node.js authentication library. A remote attacker may be able to bypass SAML authentication on a website using passport-saml. A successful attack requires that the attacker is in possession of an arbitrary IDP signed XML element. Depending on the IDP used, fully unauthenticated attacks (e.g without access to a valid user) might also be feasible if generation of a signed message can be triggered. Users should upgrade to passport-saml version 3.2.2 or newer. The issue was also present in the beta releases of `node-saml` before version 4.0.0-beta.5. If you cannot upgrade, disabling SAML authentication may be done as a workaround.

- [https://github.com/AventurineJ/CVE-2022-39299-Research](https://github.com/AventurineJ/CVE-2022-39299-Research) :  ![starts](https://img.shields.io/github/stars/AventurineJ/CVE-2022-39299-Research.svg) ![forks](https://img.shields.io/github/forks/AventurineJ/CVE-2022-39299-Research.svg)


## CVE-2022-3782
 keycloak: path traversal via double URL encoding. A flaw was found in Keycloak, where it does not properly validate URLs included in a redirect. An attacker can use this flaw to construct a malicious request to bypass validation and access other URLs and potentially sensitive information within the domain or possibly conduct further attacks. This flaw affects any client that utilizes a wildcard in the Valid Redirect URIs field.

- [https://github.com/shoucheng3/keycloak__keycloak_CVE-2022-3782_20-0-1](https://github.com/shoucheng3/keycloak__keycloak_CVE-2022-3782_20-0-1) :  ![starts](https://img.shields.io/github/stars/shoucheng3/keycloak__keycloak_CVE-2022-3782_20-0-1.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/keycloak__keycloak_CVE-2022-3782_20-0-1.svg)


## CVE-2022-3602
 A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking. Note that this occurs after certificate chain signature verification and requires either a CA to have signed the malicious certificate or for the application to continue certificate verification despite failure to construct a path to a trusted issuer. An attacker can craft a malicious email address to overflow four attacker-controlled bytes on the stack. This buffer overflow could result in a crash (causing a denial of service) or potentially remote code execution. Many platforms implement stack overflow protections which would mitigate against the risk of remote code execution. The risk may be further mitigated based on stack layout for any given platform/compiler. Pre-announcements of CVE-2022-3602 described this issue as CRITICAL. Further analysis based on some of the mitigating factors described above have led this to be downgraded to HIGH. Users are still encouraged to upgrade to a new version as soon as possible. In a TLS client, this can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server requests client authentication and a malicious client connects. Fixed in OpenSSL 3.0.7 (Affected 3.0.0,3.0.1,3.0.2,3.0.3,3.0.4,3.0.5,3.0.6).

- [https://github.com/NCSC-NL/OpenSSL-2022](https://github.com/NCSC-NL/OpenSSL-2022) :  ![starts](https://img.shields.io/github/stars/NCSC-NL/OpenSSL-2022.svg) ![forks](https://img.shields.io/github/forks/NCSC-NL/OpenSSL-2022.svg)
- [https://github.com/colmmacc/CVE-2022-3602](https://github.com/colmmacc/CVE-2022-3602) :  ![starts](https://img.shields.io/github/stars/colmmacc/CVE-2022-3602.svg) ![forks](https://img.shields.io/github/forks/colmmacc/CVE-2022-3602.svg)
- [https://github.com/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc](https://github.com/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc) :  ![starts](https://img.shields.io/github/stars/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc.svg) ![forks](https://img.shields.io/github/forks/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc.svg)
- [https://github.com/eatscrayon/CVE-2022-3602-poc](https://github.com/eatscrayon/CVE-2022-3602-poc) :  ![starts](https://img.shields.io/github/stars/eatscrayon/CVE-2022-3602-poc.svg) ![forks](https://img.shields.io/github/forks/eatscrayon/CVE-2022-3602-poc.svg)
- [https://github.com/fox-it/spookyssl-pcaps](https://github.com/fox-it/spookyssl-pcaps) :  ![starts](https://img.shields.io/github/stars/fox-it/spookyssl-pcaps.svg) ![forks](https://img.shields.io/github/forks/fox-it/spookyssl-pcaps.svg)
- [https://github.com/Qualys/osslscanwin](https://github.com/Qualys/osslscanwin) :  ![starts](https://img.shields.io/github/stars/Qualys/osslscanwin.svg) ![forks](https://img.shields.io/github/forks/Qualys/osslscanwin.svg)
- [https://github.com/corelight/CVE-2022-3602](https://github.com/corelight/CVE-2022-3602) :  ![starts](https://img.shields.io/github/stars/corelight/CVE-2022-3602.svg) ![forks](https://img.shields.io/github/forks/corelight/CVE-2022-3602.svg)
- [https://github.com/cybersecurityworks553/CVE-2022-3602-and-CVE-2022-3786](https://github.com/cybersecurityworks553/CVE-2022-3602-and-CVE-2022-3786) :  ![starts](https://img.shields.io/github/stars/cybersecurityworks553/CVE-2022-3602-and-CVE-2022-3786.svg) ![forks](https://img.shields.io/github/forks/cybersecurityworks553/CVE-2022-3602-and-CVE-2022-3786.svg)
- [https://github.com/attilaszia/cve-2022-3602](https://github.com/attilaszia/cve-2022-3602) :  ![starts](https://img.shields.io/github/stars/attilaszia/cve-2022-3602.svg) ![forks](https://img.shields.io/github/forks/attilaszia/cve-2022-3602.svg)
- [https://github.com/hi-artem/find-spooky-prismacloud](https://github.com/hi-artem/find-spooky-prismacloud) :  ![starts](https://img.shields.io/github/stars/hi-artem/find-spooky-prismacloud.svg) ![forks](https://img.shields.io/github/forks/hi-artem/find-spooky-prismacloud.svg)
- [https://github.com/alicangnll/SpookySSL-Scanner](https://github.com/alicangnll/SpookySSL-Scanner) :  ![starts](https://img.shields.io/github/stars/alicangnll/SpookySSL-Scanner.svg) ![forks](https://img.shields.io/github/forks/alicangnll/SpookySSL-Scanner.svg)
- [https://github.com/micr0sh0ft/certscare-openssl3-exploit](https://github.com/micr0sh0ft/certscare-openssl3-exploit) :  ![starts](https://img.shields.io/github/stars/micr0sh0ft/certscare-openssl3-exploit.svg) ![forks](https://img.shields.io/github/forks/micr0sh0ft/certscare-openssl3-exploit.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/jxpsx/CVE-2022-0847-DirtyPipe-Exploits](https://github.com/jxpsx/CVE-2022-0847-DirtyPipe-Exploits) :  ![starts](https://img.shields.io/github/stars/jxpsx/CVE-2022-0847-DirtyPipe-Exploits.svg) ![forks](https://img.shields.io/github/forks/jxpsx/CVE-2022-0847-DirtyPipe-Exploits.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/zer0qs/CVE-2021-41773](https://github.com/zer0qs/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/zer0qs/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/zer0qs/CVE-2021-41773.svg)
- [https://github.com/Plunder283/CVE-2021-41773](https://github.com/Plunder283/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Plunder283/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Plunder283/CVE-2021-41773.svg)


## CVE-2020-8570
 Kubernetes Java client libraries in version 10.0.0 and versions prior to 9.0.1 allow writes to paths outside of the current directory when copying multiple files from a remote pod which sends a maliciously crafted archive. This can potentially overwrite any files on the system of the process executing the client code.

- [https://github.com/shoucheng3/kubernetes-client__java_CVE-2020-8570_client-java-parent-9_0_2_fixed](https://github.com/shoucheng3/kubernetes-client__java_CVE-2020-8570_client-java-parent-9_0_2_fixed) :  ![starts](https://img.shields.io/github/stars/shoucheng3/kubernetes-client__java_CVE-2020-8570_client-java-parent-9_0_2_fixed.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/kubernetes-client__java_CVE-2020-8570_client-java-parent-9_0_2_fixed.svg)


## CVE-2019-10219
 A vulnerability was found in Hibernate-Validator. The SafeHtml validator annotation fails to properly sanitize payloads consisting of potentially malicious code in HTML comments and instructions. This vulnerability can result in an XSS attack.

- [https://github.com/shoucheng3/hibernate__hibernate-validator_CVE-2019-10219_6_0_18_Final_fixed](https://github.com/shoucheng3/hibernate__hibernate-validator_CVE-2019-10219_6_0_18_Final_fixed) :  ![starts](https://img.shields.io/github/stars/shoucheng3/hibernate__hibernate-validator_CVE-2019-10219_6_0_18_Final_fixed.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/hibernate__hibernate-validator_CVE-2019-10219_6_0_18_Final_fixed.svg)


## CVE-2019-10077
 A carefully crafted InterWiki link could trigger an XSS vulnerability on Apache JSPWiki 2.9.0 to 2.11.0.M3, which could lead to session hijacking.

- [https://github.com/shoucheng3/apache__jspwiki_CVE-2019-10077_2_11_0_M4_fixed](https://github.com/shoucheng3/apache__jspwiki_CVE-2019-10077_2_11_0_M4_fixed) :  ![starts](https://img.shields.io/github/stars/shoucheng3/apache__jspwiki_CVE-2019-10077_2_11_0_M4_fixed.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/apache__jspwiki_CVE-2019-10077_2_11_0_M4_fixed.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/noob-hacker572/CMS-Made-Simple-2.2.9-CVE-2019-9053](https://github.com/noob-hacker572/CMS-Made-Simple-2.2.9-CVE-2019-9053) :  ![starts](https://img.shields.io/github/stars/noob-hacker572/CMS-Made-Simple-2.2.9-CVE-2019-9053.svg) ![forks](https://img.shields.io/github/forks/noob-hacker572/CMS-Made-Simple-2.2.9-CVE-2019-9053.svg)


## CVE-2018-12542
 In version from 3.0.0 to 3.5.3 of Eclipse Vert.x, the StaticHandler uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize '\' (forward slashes) sequences that can resolve to a location that is outside of that directory when running on Windows Operating Systems.

- [https://github.com/shoucheng3/vert-x3__vertx-web_CVE-2018-12542_3_5_4_fixed](https://github.com/shoucheng3/vert-x3__vertx-web_CVE-2018-12542_3_5_4_fixed) :  ![starts](https://img.shields.io/github/stars/shoucheng3/vert-x3__vertx-web_CVE-2018-12542_3_5_4_fixed.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/vert-x3__vertx-web_CVE-2018-12542_3_5_4_fixed.svg)


## CVE-2018-9159
 In Spark before 2.7.2, a remote attacker can read unintended static files via various representations of absolute or relative pathnames, as demonstrated by file: URLs and directory traversal sequences. NOTE: this product is unrelated to Ignite Realtime Spark.

- [https://github.com/shoucheng3/perwendel__spark_CVE-2018-9159_2_7_2_fixed](https://github.com/shoucheng3/perwendel__spark_CVE-2018-9159_2_7_2_fixed) :  ![starts](https://img.shields.io/github/stars/shoucheng3/perwendel__spark_CVE-2018-9159_2_7_2_fixed.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/perwendel__spark_CVE-2018-9159_2_7_2_fixed.svg)

