# Update 2025-08-22
## CVE-2025-55188
 7-Zip before 25.01 does not always properly handle symbolic links during extraction.

- [https://github.com/rhllsingh/CVE-2025-55188-7z-exploit](https://github.com/rhllsingh/CVE-2025-55188-7z-exploit) :  ![starts](https://img.shields.io/github/stars/rhllsingh/CVE-2025-55188-7z-exploit.svg) ![forks](https://img.shields.io/github/forks/rhllsingh/CVE-2025-55188-7z-exploit.svg)


## CVE-2025-54782
 Nest is a framework for building scalable Node.js server-side applications. In versions 0.2.0 and below, a critical Remote Code Execution (RCE) vulnerability was discovered in the @nestjs/devtools-integration package. When enabled, the package exposes a local development HTTP server with an API endpoint that uses an unsafe JavaScript sandbox (safe-eval-like implementation). Due to improper sandboxing and missing cross-origin protections, any malicious website visited by a developer can execute arbitrary code on their local machine. The package adds HTTP endpoints to a locally running NestJS development server. One of these endpoints, /inspector/graph/interact, accepts JSON input containing a code field and executes the provided code in a Node.js vm.runInNewContext sandbox. This is fixed in version 0.2.1.

- [https://github.com/nitrixog/CVE-2025-54782](https://github.com/nitrixog/CVE-2025-54782) :  ![starts](https://img.shields.io/github/stars/nitrixog/CVE-2025-54782.svg) ![forks](https://img.shields.io/github/forks/nitrixog/CVE-2025-54782.svg)


## CVE-2025-52392
 Soosyze CMS 2.0 allows brute-force login attacks via the /user/login endpoint due to missing rate-limiting and lockout mechanisms. An attacker can repeatedly submit login attempts without restrictions, potentially gaining unauthorized administrative access. This vulnerability corresponds to CWE-307: Improper Restriction of Excessive Authentication Attempts.

- [https://github.com/137f/Soosyze-CMS-2.0---CVE-2025-52392](https://github.com/137f/Soosyze-CMS-2.0---CVE-2025-52392) :  ![starts](https://img.shields.io/github/stars/137f/Soosyze-CMS-2.0---CVE-2025-52392.svg) ![forks](https://img.shields.io/github/forks/137f/Soosyze-CMS-2.0---CVE-2025-52392.svg)


## CVE-2025-48384
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When reading a config value, Git strips any trailing carriage return and line feed (CRLF). When writing a config entry, values with a trailing CR are not quoted, causing the CR to be lost when the config is later read. When initializing a submodule, if the submodule path contains a trailing CR, the altered path is read resulting in the submodule being checked out to an incorrect location. If a symlink exists that points the altered path to the submodule hooks directory, and the submodule contains an executable post-checkout hook, the script may be unintentionally executed after checkout. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.

- [https://github.com/replicatorbot/CVE-2025-48384](https://github.com/replicatorbot/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/replicatorbot/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/replicatorbot/CVE-2025-48384.svg)
- [https://github.com/replicatorbot/CVE-2025-48384-POC](https://github.com/replicatorbot/CVE-2025-48384-POC) :  ![starts](https://img.shields.io/github/stars/replicatorbot/CVE-2025-48384-POC.svg) ![forks](https://img.shields.io/github/forks/replicatorbot/CVE-2025-48384-POC.svg)


## CVE-2025-34036
 An OS command injection vulnerability exists in white-labeled DVRs manufactured by TVT, affecting a custom HTTP service called "Cross Web Server" that listens on TCP ports 81 and 82. The web interface fails to sanitize input in the URI path passed to the language extraction functionality. When the server processes a request to /language/[lang]/index.html, it uses the [lang] input unsafely in a tar extraction command without proper escaping. This allows an unauthenticated remote attacker to inject shell commands and achieve arbitrary command execution as root.

- [https://github.com/Prabhukiran161/cve-2025-34036](https://github.com/Prabhukiran161/cve-2025-34036) :  ![starts](https://img.shields.io/github/stars/Prabhukiran161/cve-2025-34036.svg) ![forks](https://img.shields.io/github/forks/Prabhukiran161/cve-2025-34036.svg)


## CVE-2025-32094
 An issue was discovered in Akamai Ghost, as used for the Akamai CDN platform before 2025-03-26. Under certain circumstances, a client making an HTTP/1.x OPTIONS request with an "Expect: 100-continue" header, and using obsolete line folding, can lead to a discrepancy in how two in-path Akamai servers interpret the request, allowing an attacker to smuggle a second request in the original request body.

- [https://github.com/perplext/echteeteepee](https://github.com/perplext/echteeteepee) :  ![starts](https://img.shields.io/github/stars/perplext/echteeteepee.svg) ![forks](https://img.shields.io/github/forks/perplext/echteeteepee.svg)


## CVE-2025-31324
 SAP NetWeaver Visual Composer Metadata Uploader is not protected with a proper authorization, allowing unauthenticated agent to upload potentially malicious executable binaries that could severely harm the host system. This could significantly affect the confidentiality, integrity, and availability of the targeted system.

- [https://github.com/harshitvarma05/CVE-2025-31324-Exploits](https://github.com/harshitvarma05/CVE-2025-31324-Exploits) :  ![starts](https://img.shields.io/github/stars/harshitvarma05/CVE-2025-31324-Exploits.svg) ![forks](https://img.shields.io/github/forks/harshitvarma05/CVE-2025-31324-Exploits.svg)


## CVE-2025-8088
     from ESET.

- [https://github.com/Syrins/CVE-2025-8088-Winrar-Tool-Gui](https://github.com/Syrins/CVE-2025-8088-Winrar-Tool-Gui) :  ![starts](https://img.shields.io/github/stars/Syrins/CVE-2025-8088-Winrar-Tool-Gui.svg) ![forks](https://img.shields.io/github/forks/Syrins/CVE-2025-8088-Winrar-Tool-Gui.svg)


## CVE-2025-5777
 Insufficient input validation leading to memory overread when the NetScaler is configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server

- [https://github.com/ndr-repo/CVE-2025-5777](https://github.com/ndr-repo/CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/ndr-repo/CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/ndr-repo/CVE-2025-5777.svg)


## CVE-2025-5212
 A vulnerability was found in PHPGurukul Employee Record Management System 1.3. It has been classified as critical. Affected is an unknown function of the file /admin/editempexp.php. The manipulation of the argument emp1name leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/TimTrademark/CVE-2025-52122](https://github.com/TimTrademark/CVE-2025-52122) :  ![starts](https://img.shields.io/github/stars/TimTrademark/CVE-2025-52122.svg) ![forks](https://img.shields.io/github/forks/TimTrademark/CVE-2025-52122.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/Ianthinus/CVE-2024-4577](https://github.com/Ianthinus/CVE-2024-4577) :  ![starts](https://img.shields.io/github/stars/Ianthinus/CVE-2024-4577.svg) ![forks](https://img.shields.io/github/forks/Ianthinus/CVE-2024-4577.svg)


## CVE-2024-3721
 A vulnerability was found in TBK DVR-4104 and DVR-4216 up to 20240412 and classified as critical. This issue affects some unknown processing of the file /device.rsp?opt=sys&cmd=___S_O_S_T_R_E_A_MAX___. The manipulation of the argument mdb/mdc leads to os command injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-260573 was assigned to this vulnerability.

- [https://github.com/qalvynn/CVE-2024-3721---POC](https://github.com/qalvynn/CVE-2024-3721---POC) :  ![starts](https://img.shields.io/github/stars/qalvynn/CVE-2024-3721---POC.svg) ![forks](https://img.shields.io/github/forks/qalvynn/CVE-2024-3721---POC.svg)


## CVE-2023-51770
We recommend users to upgrade Apache DolphinScheduler to version 3.2.1, which fixes the issue.

- [https://github.com/shoucheng3/apache__dolphinscheduler_CVE-2023-51770_3-2-0](https://github.com/shoucheng3/apache__dolphinscheduler_CVE-2023-51770_3-2-0) :  ![starts](https://img.shields.io/github/stars/shoucheng3/apache__dolphinscheduler_CVE-2023-51770_3-2-0.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/apache__dolphinscheduler_CVE-2023-51770_3-2-0.svg)


## CVE-2023-46749
Mitigation: Update to Apache Shiro 1.13.0+ or 2.0.0-alpha-4+, or ensure `blockSemicolon` is enabled (this is the default).

- [https://github.com/shoucheng3/apache__shiro_CVE-2023-46749_1-12-0](https://github.com/shoucheng3/apache__shiro_CVE-2023-46749_1-12-0) :  ![starts](https://img.shields.io/github/stars/shoucheng3/apache__shiro_CVE-2023-46749_1-12-0.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/apache__shiro_CVE-2023-46749_1-12-0.svg)


## CVE-2023-36542
 Apache NiFi 0.0.2 through 1.22.0 include Processors and Controller Services that support HTTP URL references for retrieving drivers, which allows an authenticated and authorized user to configure a location that enables custom code execution. The resolution introduces a new Required Permission for referencing remote resources, restricting configuration of these components to privileged users. The permission prevents unprivileged users from configuring Processors and Controller Services annotated with the new Reference Remote Resources restriction. Upgrading to Apache NiFi 1.23.0 is the recommended mitigation.

- [https://github.com/shoucheng3/asf__nifi_CVE-2023-36542_1-22-0](https://github.com/shoucheng3/asf__nifi_CVE-2023-36542_1-22-0) :  ![starts](https://img.shields.io/github/stars/shoucheng3/asf__nifi_CVE-2023-36542_1-22-0.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/asf__nifi_CVE-2023-36542_1-22-0.svg)


## CVE-2023-31126
 `org.xwiki.commons:xwiki-commons-xml` is an XML library used by the open-source wiki platform XWiki. The HTML sanitizer, introduced in version 14.6-rc-1, allows the injection of arbitrary HTML code and thus cross-site scripting via invalid data attributes. This vulnerability does not affect restricted cleaning in HTMLCleaner as there attributes are cleaned and thus characters like `/` and `` are removed in all attribute names. This problem has been patched in XWiki 14.10.4 and 15.0 RC1 by making sure that data attributes only contain allowed characters. There are no known workarounds apart from upgrading to a version including the fix.

- [https://github.com/shoucheng3/cov-int](https://github.com/shoucheng3/cov-int) :  ![starts](https://img.shields.io/github/stars/shoucheng3/cov-int.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/cov-int.svg)
- [https://github.com/shoucheng3/xwiki__xwiki-commons_CVE-2023-31126_14-10-3](https://github.com/shoucheng3/xwiki__xwiki-commons_CVE-2023-31126_14-10-3) :  ![starts](https://img.shields.io/github/stars/shoucheng3/xwiki__xwiki-commons_CVE-2023-31126_14-10-3.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/xwiki__xwiki-commons_CVE-2023-31126_14-10-3.svg)


## CVE-2023-29528
 XWiki Commons are technical libraries common to several other top level XWiki projects. The "restricted" mode of the HTML cleaner in XWiki, introduced in version 4.2-milestone-1 and massively improved in version 14.6-rc-1, allowed the injection of arbitrary HTML code and thus cross-site scripting via invalid HTML comments. As a consequence, any code relying on this "restricted" mode for security is vulnerable to JavaScript injection ("cross-site scripting"/XSS). When a privileged user with programming rights visits such a comment in XWiki, the malicious JavaScript code is executed in the context of the user session. This allows server-side code execution with programming rights, impacting the confidentiality, integrity and availability of the XWiki instance. This problem has been patched in XWiki 14.10, HTML comments are now removed in restricted mode and a check has been introduced that ensures that comments don't start with ``. There are no known workarounds apart from upgrading to a version including the fix.

- [https://github.com/shoucheng3/xwiki__xwiki-commons_CVE-2023-29528_14-9-rc-1](https://github.com/shoucheng3/xwiki__xwiki-commons_CVE-2023-29528_14-9-rc-1) :  ![starts](https://img.shields.io/github/stars/shoucheng3/xwiki__xwiki-commons_CVE-2023-29528_14-9-rc-1.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/xwiki__xwiki-commons_CVE-2023-29528_14-9-rc-1.svg)


## CVE-2023-29201
 XWiki Commons are technical libraries common to several other top level XWiki projects. The "restricted" mode of the HTML cleaner in XWiki, introduced in version 4.2-milestone-1, only escaped `script` and `style`-tags but neither attributes that can be used to inject scripts nor other dangerous HTML tags like `iframe`. As a consequence, any code relying on this "restricted" mode for security is vulnerable to JavaScript injection ("cross-site scripting"/XSS). When a privileged user with programming rights visits such a comment in XWiki, the malicious JavaScript code is executed in the context of the user session. This allows server-side code execution with programming rights, impacting the confidentiality, integrity and availability of the XWiki instance. This problem has been patched in XWiki 14.6 RC1 with the introduction of a filter with allowed HTML elements and attributes that is enabled in restricted mode. There are no known workarounds apart from upgrading to a version including the fix.

- [https://github.com/shoucheng3/xwiki__xwiki-commons_CVE-2023-29201_14-5](https://github.com/shoucheng3/xwiki__xwiki-commons_CVE-2023-29201_14-5) :  ![starts](https://img.shields.io/github/stars/shoucheng3/xwiki__xwiki-commons_CVE-2023-29201_14-5.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/xwiki__xwiki-commons_CVE-2023-29201_14-5.svg)


## CVE-2022-44262
 ff4j 1.8.1 is vulnerable to Remote Code Execution (RCE).

- [https://github.com/shoucheng3/ff4j__ff4j_CVE-2022-44262_1-8-13](https://github.com/shoucheng3/ff4j__ff4j_CVE-2022-44262_1-8-13) :  ![starts](https://img.shields.io/github/stars/shoucheng3/ff4j__ff4j_CVE-2022-44262_1-8-13.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/ff4j__ff4j_CVE-2022-44262_1-8-13.svg)


## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is "${prefix:name}", where "prefix" is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - "script" - execute expressions using the JVM script execution engine (javax.script) - "dns" - resolve dns records - "url" - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/shoucheng3/asf__commons-text_CVE-2022-42889_1-9](https://github.com/shoucheng3/asf__commons-text_CVE-2022-42889_1-9) :  ![starts](https://img.shields.io/github/stars/shoucheng3/asf__commons-text_CVE-2022-42889_1-9.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/asf__commons-text_CVE-2022-42889_1-9.svg)


## CVE-2022-36007
 Venice is a Clojure inspired sandboxed Lisp dialect with excellent Java interoperability. A partial path traversal issue exists within the functions `load-file` and `load-resource`. These functions can be limited to load files from a list of load paths. Assuming Venice has been configured with the load paths: `[ "/Users/foo/resources" ]` When passing **relative** paths to these two vulnerable functions everything is fine: `(load-resource "test.png")` = loads the file "/Users/foo/resources/test.png" `(load-resource "../resources-alt/test.png")` = rejected, outside the load path When passing **absolute** paths to these two vulnerable functions Venice may return files outside the configured load paths: `(load-resource "/Users/foo/resources/test.png")` = loads the file "/Users/foo/resources/test.png" `(load-resource "/Users/foo/resources-alt/test.png")` = loads the file "/Users/foo/resources-alt/test.png" !!! The latter call suffers from the _Partial Path Traversal_ vulnerability. This issue’s scope is limited to absolute paths whose name prefix matches a load path. E.g. for a load-path `"/Users/foo/resources"`, the actor can cause loading a resource also from `"/Users/foo/resources-alt"`, but not from `"/Users/foo/images"`. Versions of Venice before and including v1.10.17 are affected by this issue. Upgrade to Venice = 1.10.18, if you are on a version  1.10.18. There are currently no known workarounds.

- [https://github.com/shoucheng3/jlangch__venice_CVE-2022-36007_1-10-16](https://github.com/shoucheng3/jlangch__venice_CVE-2022-36007_1-10-16) :  ![starts](https://img.shields.io/github/stars/shoucheng3/jlangch__venice_CVE-2022-36007_1-10-16.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/jlangch__venice_CVE-2022-36007_1-10-16.svg)


## CVE-2022-31195
 DSpace open source software is a repository application which provides durable access to digital resources. In affected versions the ItemImportServiceImpl is vulnerable to a path traversal vulnerability. This means a malicious SAF (simple archive format) package could cause a file/directory to be created anywhere the Tomcat/DSpace user can write to on the server. However, this path traversal vulnerability is only possible by a user with special privileges (either Administrators or someone with command-line access to the server). This vulnerability impacts the XMLUI, JSPUI and command-line. Users are advised to upgrade. As a basic workaround, users may block all access to the following URL paths: If you are using the XMLUI, block all access to /admin/batchimport path (this is the URL of the Admin Batch Import tool). Keep in mind, if your site uses the path "/xmlui", then you'd need to block access to /xmlui/admin/batchimport. If you are using the JSPUI, block all access to /dspace-admin/batchimport path (this is the URL of the Admin Batch Import tool). Keep in mind, if your site uses the path "/jspui", then you'd need to block access to /jspui/dspace-admin/batchimport. Keep in mind, only an Administrative user or a user with command-line access to the server is able to import/upload SAF packages. Therefore, assuming those users do not blindly upload untrusted SAF packages, then it is unlikely your site could be impacted by this vulnerability.

- [https://github.com/shoucheng3/DSpace__DSpace_CVE-2022-31195_5-10](https://github.com/shoucheng3/DSpace__DSpace_CVE-2022-31195_5-10) :  ![starts](https://img.shields.io/github/stars/shoucheng3/DSpace__DSpace_CVE-2022-31195_5-10.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/DSpace__DSpace_CVE-2022-31195_5-10.svg)


## CVE-2022-25175
 Jenkins Pipeline: Multibranch Plugin 706.vd43c65dec013 and earlier uses the same checkout directories for distinct SCMs for the readTrusted step, allowing attackers with Item/Configure permission to invoke arbitrary OS commands on the controller through crafted SCM contents.

- [https://github.com/shoucheng3/jenkinsci__workflow-multibranch-plugin_CVE-2022-25175_706-vd43c65dec013](https://github.com/shoucheng3/jenkinsci__workflow-multibranch-plugin_CVE-2022-25175_706-vd43c65dec013) :  ![starts](https://img.shields.io/github/stars/shoucheng3/jenkinsci__workflow-multibranch-plugin_CVE-2022-25175_706-vd43c65dec013.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/jenkinsci__workflow-multibranch-plugin_CVE-2022-25175_706-vd43c65dec013.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/shoucheng3/spring-projects__spring-framework_CVE-2022-22965_5-2-19-RELEASE](https://github.com/shoucheng3/spring-projects__spring-framework_CVE-2022-22965_5-2-19-RELEASE) :  ![starts](https://img.shields.io/github/stars/shoucheng3/spring-projects__spring-framework_CVE-2022-22965_5-2-19-RELEASE.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/spring-projects__spring-framework_CVE-2022-22965_5-2-19-RELEASE.svg)


## CVE-2022-22947
 In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

- [https://github.com/shoucheng3/spring-cloud__spring-cloud-gateway_CVE-2022-22947_3-0-6](https://github.com/shoucheng3/spring-cloud__spring-cloud-gateway_CVE-2022-22947_3-0-6) :  ![starts](https://img.shields.io/github/stars/shoucheng3/spring-cloud__spring-cloud-gateway_CVE-2022-22947_3-0-6.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/spring-cloud__spring-cloud-gateway_CVE-2022-22947_3-0-6.svg)


## CVE-2022-4944
 A vulnerability, which was classified as problematic, has been found in kalcaddle KodExplorer up to 4.49. Affected by this issue is some unknown functionality. The manipulation leads to cross-site request forgery. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. Upgrading to version 4.50 is able to address this issue. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-227000.

- [https://github.com/brosck/CVE-2022-4944](https://github.com/brosck/CVE-2022-4944) :  ![starts](https://img.shields.io/github/stars/brosck/CVE-2022-4944.svg) ![forks](https://img.shields.io/github/forks/brosck/CVE-2022-4944.svg)


## CVE-2022-2712
 In Eclipse GlassFish versions 5.1.0 to 6.2.5, there is a vulnerability in relative path traversal because it does not filter request path starting with './'. Successful exploitation could allow an remote unauthenticated attacker to access critical data, such as configuration files and deployed application source code.

- [https://github.com/shoucheng3/eclipse-ee4j__glassfish_CVE-2022-2712_6-2-5](https://github.com/shoucheng3/eclipse-ee4j__glassfish_CVE-2022-2712_6-2-5) :  ![starts](https://img.shields.io/github/stars/shoucheng3/eclipse-ee4j__glassfish_CVE-2022-2712_6-2-5.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/eclipse-ee4j__glassfish_CVE-2022-2712_6-2-5.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/muhammad1596/CVE-2022-0847-DirtyPipe-Exploits](https://github.com/muhammad1596/CVE-2022-0847-DirtyPipe-Exploits) :  ![starts](https://img.shields.io/github/stars/muhammad1596/CVE-2022-0847-DirtyPipe-Exploits.svg) ![forks](https://img.shields.io/github/forks/muhammad1596/CVE-2022-0847-DirtyPipe-Exploits.svg)


## CVE-2021-45897
 SuiteCRM before 7.12.3 and 8.x before 8.0.2 allows remote code execution.

- [https://github.com/manuelz120/CVE-2021-45897](https://github.com/manuelz120/CVE-2021-45897) :  ![starts](https://img.shields.io/github/stars/manuelz120/CVE-2021-45897.svg) ![forks](https://img.shields.io/github/forks/manuelz120/CVE-2021-45897.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/JIYUN02/cve-2021-41773](https://github.com/JIYUN02/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/JIYUN02/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/JIYUN02/cve-2021-41773.svg)
- [https://github.com/wolf1892/CVE-2021-41773](https://github.com/wolf1892/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/wolf1892/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/wolf1892/CVE-2021-41773.svg)
- [https://github.com/honypot/CVE-2021-41773](https://github.com/honypot/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/honypot/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/honypot/CVE-2021-41773.svg)
- [https://github.com/zer0qs/CVE-2021-41773](https://github.com/zer0qs/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/zer0qs/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/zer0qs/CVE-2021-41773.svg)


## CVE-2021-41269
 cron-utils is a Java library to define, parse, validate, migrate crons as well as get human readable descriptions for them. In affected versions A template Injection was identified in cron-utils enabling attackers to inject arbitrary Java EL expressions, leading to unauthenticated Remote Code Execution (RCE) vulnerability. Versions up to 9.1.2 are susceptible to this vulnerability. Please note, that only projects using the @Cron annotation to validate untrusted Cron expressions are affected. The issue was patched and a new version was released. Please upgrade to version 9.1.6. There are no known workarounds known.

- [https://github.com/shoucheng3/jmrozanec__cron-utils_CVE-2021-41269_9-1-5](https://github.com/shoucheng3/jmrozanec__cron-utils_CVE-2021-41269_9-1-5) :  ![starts](https://img.shields.io/github/stars/shoucheng3/jmrozanec__cron-utils_CVE-2021-41269_9-1-5.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/jmrozanec__cron-utils_CVE-2021-41269_9-1-5.svg)


## CVE-2021-39623
 In doRead of SimpleDecodingSource.cpp, there is a possible out of bounds write due to an incorrect bounds check. This could lead to remote escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-9Android ID: A-194105348

- [https://github.com/bb33bb/CVE-2021-39623](https://github.com/bb33bb/CVE-2021-39623) :  ![starts](https://img.shields.io/github/stars/bb33bb/CVE-2021-39623.svg) ![forks](https://img.shields.io/github/forks/bb33bb/CVE-2021-39623.svg)


## CVE-2021-32537
 Realtek HAD contains a driver crashed vulnerability which allows local side attackers to send a special string to the kernel driver in a user’s mode. Due to unexpected commands, the kernel driver will cause the system crashed.

- [https://github.com/0vercl0k/CVE-2021-32537](https://github.com/0vercl0k/CVE-2021-32537) :  ![starts](https://img.shields.io/github/stars/0vercl0k/CVE-2021-32537.svg) ![forks](https://img.shields.io/github/forks/0vercl0k/CVE-2021-32537.svg)


## CVE-2021-29447
 Wordpress is an open source CMS. A user with the ability to upload files (like an Author) can exploit an XML parsing issue in the Media Library leading to XXE attacks. This requires WordPress installation to be using PHP 8. Access to internal files is possible in a successful XXE attack. This has been patched in WordPress version 5.7.1, along with the older affected versions via a minor release. We strongly recommend you keep auto-updates enabled.

- [https://github.com/ArtemCyberLab/Project-Project-Chimera-Exploiting-a-Modern-WordPress-XXE-to-Pillage-Secrets-](https://github.com/ArtemCyberLab/Project-Project-Chimera-Exploiting-a-Modern-WordPress-XXE-to-Pillage-Secrets-) :  ![starts](https://img.shields.io/github/stars/ArtemCyberLab/Project-Project-Chimera-Exploiting-a-Modern-WordPress-XXE-to-Pillage-Secrets-.svg) ![forks](https://img.shields.io/github/forks/ArtemCyberLab/Project-Project-Chimera-Exploiting-a-Modern-WordPress-XXE-to-Pillage-Secrets-.svg)


## CVE-2021-3679
 A lack of CPU resource in the Linux kernel tracing module functionality in versions prior to 5.14-rc3 was found in the way user uses trace ring buffer in a specific way. Only privileged local users (with CAP_SYS_ADMIN capability) could use this flaw to starve the resources causing denial of service.

- [https://github.com/aegistudio/RingBufferDetonator](https://github.com/aegistudio/RingBufferDetonator) :  ![starts](https://img.shields.io/github/stars/aegistudio/RingBufferDetonator.svg) ![forks](https://img.shields.io/github/forks/aegistudio/RingBufferDetonator.svg)


## CVE-2021-3317
 KLog Server through 2.4.1 allows authenticated command injection. async.php calls shell_exec() on the original value of the source parameter.

- [https://github.com/Al1ex/CVE-2021-3317](https://github.com/Al1ex/CVE-2021-3317) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2021-3317.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2021-3317.svg)


## CVE-2020-29204
 XXL-JOB 2.2.0 allows Stored XSS (in Add User) to bypass the 20-character limit via xxl-job-admin/src/main/java/com/xxl/job/admin/controller/UserController.java.

- [https://github.com/shoucheng3/xuxueli__xxl-job_CVE-2020-29204_2-2-0](https://github.com/shoucheng3/xuxueli__xxl-job_CVE-2020-29204_2-2-0) :  ![starts](https://img.shields.io/github/stars/shoucheng3/xuxueli__xxl-job_CVE-2020-29204_2-2-0.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/xuxueli__xxl-job_CVE-2020-29204_2-2-0.svg)


## CVE-2020-17519
 A change introduced in Apache Flink 1.11.0 (and released in 1.11.1 and 1.11.2 as well) allows attackers to read any file on the local filesystem of the JobManager through the REST interface of the JobManager process. Access is restricted to files accessible by the JobManager process. All users should upgrade to Flink 1.11.3 or 1.12.0 if their Flink instance(s) are exposed. The issue was fixed in commit b561010b0ee741543c3953306037f00d7a9f0801 from apache/flink:master.

- [https://github.com/shoucheng3/apache__flink_CVE-2020-17519_1-11-2](https://github.com/shoucheng3/apache__flink_CVE-2020-17519_1-11-2) :  ![starts](https://img.shields.io/github/stars/shoucheng3/apache__flink_CVE-2020-17519_1-11-2.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/apache__flink_CVE-2020-17519_1-11-2.svg)


## CVE-2020-5405
 Spring Cloud Config, versions 2.2.x prior to 2.2.2, versions 2.1.x prior to 2.1.7, and older unsupported versions allow applications to serve arbitrary configuration files through the spring-cloud-config-server module. A malicious user, or attacker, can send a request using a specially crafted URL that can lead a directory traversal attack.

- [https://github.com/shoucheng3/spring-cloud__spring-cloud-config_CVE-2020-5405_2-1-6-RELEASE](https://github.com/shoucheng3/spring-cloud__spring-cloud-config_CVE-2020-5405_2-1-6-RELEASE) :  ![starts](https://img.shields.io/github/stars/shoucheng3/spring-cloud__spring-cloud-config_CVE-2020-5405_2-1-6-RELEASE.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/spring-cloud__spring-cloud-config_CVE-2020-5405_2-1-6-RELEASE.svg)


## CVE-2020-2884
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/hktalent/CVE_2020_2546](https://github.com/hktalent/CVE_2020_2546) :  ![starts](https://img.shields.io/github/stars/hktalent/CVE_2020_2546.svg) ![forks](https://img.shields.io/github/forks/hktalent/CVE_2020_2546.svg)


## CVE-2019-0222
 In Apache ActiveMQ 5.0.0 - 5.15.8, unmarshalling corrupt MQTT frame can lead to broker Out of Memory exception making it unresponsive.

- [https://github.com/shoucheng3/apache__activemq_CVE-2019-0222_5-15-8](https://github.com/shoucheng3/apache__activemq_CVE-2019-0222_5-15-8) :  ![starts](https://img.shields.io/github/stars/shoucheng3/apache__activemq_CVE-2019-0222_5-15-8.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/apache__activemq_CVE-2019-0222_5-15-8.svg)


## CVE-2018-7600
 Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations.

- [https://github.com/SyedGhufranRaza/CVE-2018-7600-Remote-Code-Execution](https://github.com/SyedGhufranRaza/CVE-2018-7600-Remote-Code-Execution) :  ![starts](https://img.shields.io/github/stars/SyedGhufranRaza/CVE-2018-7600-Remote-Code-Execution.svg) ![forks](https://img.shields.io/github/forks/SyedGhufranRaza/CVE-2018-7600-Remote-Code-Execution.svg)


## CVE-2016-6662
 Oracle MySQL through 5.5.52, 5.6.x through 5.6.33, and 5.7.x through 5.7.15; MariaDB before 5.5.51, 10.0.x before 10.0.27, and 10.1.x before 10.1.17; and Percona Server before 5.5.51-38.1, 5.6.x before 5.6.32-78.0, and 5.7.x before 5.7.14-7 allow local users to create arbitrary configurations and bypass certain protection mechanisms by setting general_log_file to a my.cnf configuration. NOTE: this can be leveraged to execute arbitrary code with root privileges by setting malloc_lib. NOTE: the affected MySQL version information is from Oracle's October 2016 CPU. Oracle has not commented on third-party claims that the issue was silently patched in MySQL 5.5.52, 5.6.33, and 5.7.15.

- [https://github.com/kanyaars/CVE-2016-6662](https://github.com/kanyaars/CVE-2016-6662) :  ![starts](https://img.shields.io/github/stars/kanyaars/CVE-2016-6662.svg) ![forks](https://img.shields.io/github/forks/kanyaars/CVE-2016-6662.svg)

