# Update 2023-02-18
## CVE-2023-25173
 containerd is an open source container runtime. A bug was found in containerd prior to versions 1.6.18 and 1.5.18 where supplementary groups are not set up properly inside a container. If an attacker has direct access to a container and manipulates their supplementary group access, they may be able to use supplementary group access to bypass primary group restrictions in some cases, potentially gaining access to sensitive information or gaining the ability to execute code in that container. Downstream applications that use the containerd client library may be affected as well. This bug has been fixed in containerd v1.6.18 and v.1.5.18. Users should update to these versions and recreate containers to resolve this issue. Users who rely on a downstream application that uses containerd's client library should check that application for a separate advisory and instructions. As a workaround, ensure that the `&quot;USER $USERNAME&quot;` Dockerfile instruction is not used. Instead, set the container entrypoint to a value similar to `ENTRYPOINT [&quot;su&quot;, &quot;-&quot;, &quot;user&quot;]` to allow `su` to properly set up supplementary groups.

- [https://github.com/Live-Hack-CVE/CVE-2023-25173](https://github.com/Live-Hack-CVE/CVE-2023-25173) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25173.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25173.svg)


## CVE-2023-25153
 containerd is an open source container runtime. Before versions 1.6.18 and 1.5.18, when importing an OCI image, there was no limit on the number of bytes read for certain files. A maliciously crafted image with a large file where a limit was not applied could cause a denial of service. This bug has been fixed in containerd 1.6.18 and 1.5.18. Users should update to these versions to resolve the issue. As a workaround, ensure that only trusted images are used and that only trusted users have permissions to import images.

- [https://github.com/Live-Hack-CVE/CVE-2023-25153](https://github.com/Live-Hack-CVE/CVE-2023-25153) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25153.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25153.svg)


## CVE-2023-25151
 opentelemetry-go-contrib is a collection of extensions for OpenTelemetry-Go. The v0.38.0 release of `go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp` uses the `httpconv.ServerRequest` function to annotate metric measurements for the `http.server.request_content_length`, `http.server.response_content_length`, and `http.server.duration` instruments. The `ServerRequest` function sets the `http.target` attribute value to be the whole request URI (including the query string)[^1]. The metric instruments do not &quot;forget&quot; previous measurement attributes when `cumulative` temporality is used, this means the cardinality of the measurements allocated is directly correlated with the unique URIs handled. If the query string is constantly random, this will result in a constant increase in memory allocation that can be used in a denial-of-service attack. This issue has been addressed in version 0.39.0. Users are advised to upgrade. There are no known workarounds for this issue.

- [https://github.com/Live-Hack-CVE/CVE-2023-25151](https://github.com/Live-Hack-CVE/CVE-2023-25151) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25151.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25151.svg)


## CVE-2023-25150
 Nextcloud office/richdocuments is an office suit for the nextcloud server platform. In affected versions the Collabora integration can be tricked to provide access to any file without proper permission validation. As a result any user with access to Collabora can obtain the content of other users files. It is recommended that the Nextcloud Office App (Collabora Integration) is updated to 7.0.2 (Nextcloud 25), 6.3.2 (Nextcloud 24), 5.0.10 (Nextcloud 23), 4.2.9 (Nextcloud 21-22), or 3.8.7 (Nextcloud 15-20). There are no known workarounds for this issue.

- [https://github.com/Live-Hack-CVE/CVE-2023-25150](https://github.com/Live-Hack-CVE/CVE-2023-25150) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25150.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25150.svg)


## CVE-2023-24814
 TYPO3 is a free and open source Content Management Framework released under the GNU General Public License. In affected versions the TYPO3 core component `GeneralUtility::getIndpEnv()` uses the unfiltered server environment variable `PATH_INFO`, which allows attackers to inject malicious content. In combination with the TypoScript setting `config.absRefPrefix=auto`, attackers can inject malicious HTML code to pages that have not been rendered and cached, yet. As a result, injected values would be cached and delivered to other website visitors (persisted cross-site scripting). Individual code which relies on the resolved value of `GeneralUtility::getIndpEnv('SCRIPT_NAME')` and corresponding usages (as shown below) are vulnerable as well. Additional investigations confirmed that at least Apache web server deployments using CGI (FPM, FCGI/FastCGI, and similar) are affected. However, there still might be the risk that other scenarios like nginx, IIS, or Apache/mod_php are vulnerable. The usage of server environment variable `PATH_INFO` has been removed from corresponding processings in `GeneralUtility::getIndpEnv()`. Besides that, the public property `TypoScriptFrontendController::$absRefPrefix` is encoded for both being used as a URI component and for being used as a prefix in an HTML context. This mitigates the cross-site scripting vulnerability. Users are advised to update to TYPO3 versions 8.7.51 ELTS, 9.5.40 ELTS, 10.4.35 LTS, 11.5.23 LTS and 12.2.0 which fix this problem. For users who are unable to patch in a timely manner the TypoScript setting `config.absRefPrefix` should at least be set to a static path value, instead of using auto - e.g. `config.absRefPrefix=/`. This workaround **does not fix all aspects of the vulnerability**, and is just considered to be an intermediate mitigation to the most prominent manifestation.

- [https://github.com/Live-Hack-CVE/CVE-2023-24814](https://github.com/Live-Hack-CVE/CVE-2023-24814) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24814.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24814.svg)


## CVE-2023-24813
 Dompdf is an HTML to PDF converter written in php. Due to the difference in the attribute parser of Dompdf and php-svg-lib, an attacker can still call arbitrary URLs with arbitrary protocols. Dompdf parses the href attribute of `image` tags and respects `xlink:href` even if `href` is specified. However, php-svg-lib, which is later used to parse the svg file, parses the href attribute. Since `href` is respected if both `xlink:href` and `href` is specified, it's possible to bypass the protection on the Dompdf side by providing an empty `xlink:href` attribute. An attacker can exploit the vulnerability to call arbitrary URLs with arbitrary protocols if they provide an SVG file to the Dompdf. In PHP versions before 8.0.0, it leads to arbitrary unserialize, which will lead, at the very least, to arbitrary file deletion and might lead to remote code execution, depending on available classes. This vulnerability has been addressed in commit `95009ea98` which has been included in release version 2.0.3. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2023-24813](https://github.com/Live-Hack-CVE/CVE-2023-24813) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24813.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24813.svg)


## CVE-2023-24807
 Undici is an HTTP/1.1 client for Node.js. Prior to version 5.19.1, the `Headers.set()` and `Headers.append()` methods are vulnerable to Regular Expression Denial of Service (ReDoS) attacks when untrusted values are passed into the functions. This is due to the inefficient regular expression used to normalize the values in the `headerValueNormalize()` utility function. This vulnerability was patched in v5.19.1. No known workarounds are available.

- [https://github.com/Live-Hack-CVE/CVE-2023-24807](https://github.com/Live-Hack-CVE/CVE-2023-24807) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24807.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24807.svg)


## CVE-2023-24690
 ChurchCRM 4.5.3 and below was discovered to contain a stored cross-site scripting (XSS) vulnerability at /api/public/register/family.

- [https://github.com/Live-Hack-CVE/CVE-2023-24690](https://github.com/Live-Hack-CVE/CVE-2023-24690) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24690.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24690.svg)


## CVE-2023-24485
 Vulnerabilities have been identified that, collectively, allow a standard Windows user to perform operations as SYSTEM on the computer running Citrix Workspace app.

- [https://github.com/Live-Hack-CVE/CVE-2023-24485](https://github.com/Live-Hack-CVE/CVE-2023-24485) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24485.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24485.svg)


## CVE-2023-24484
 A malicious user can cause log files to be written to a directory that they do not have permission to write to.

- [https://github.com/Live-Hack-CVE/CVE-2023-24484](https://github.com/Live-Hack-CVE/CVE-2023-24484) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24484.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24484.svg)


## CVE-2023-24483
 A vulnerability has been identified that, if exploited, could result in a local user elevating their privilege level to NT AUTHORITY\SYSTEM on a Citrix Virtual Apps and Desktops Windows VDA.

- [https://github.com/Live-Hack-CVE/CVE-2023-24483](https://github.com/Live-Hack-CVE/CVE-2023-24483) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24483.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24483.svg)


## CVE-2023-24347
 D-Link N300 WI-FI Router DIR-605L v2.13B01 was discovered to contain a stack overflow via the webpage parameter at /goform/formSetWanDhcpplus.

- [https://github.com/Live-Hack-CVE/CVE-2023-24347](https://github.com/Live-Hack-CVE/CVE-2023-24347) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24347.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24347.svg)


## CVE-2023-24346
 D-Link N300 WI-FI Router DIR-605L v2.13B01 was discovered to contain a stack overflow via the wan_connected parameter at /goform/formEasySetupWizard3.

- [https://github.com/Live-Hack-CVE/CVE-2023-24346](https://github.com/Live-Hack-CVE/CVE-2023-24346) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24346.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24346.svg)


## CVE-2023-24345
 D-Link N300 WI-FI Router DIR-605L v2.13B01 was discovered to contain a stack overflow via the curTime parameter at /goform/formSetWanDhcpplus.

- [https://github.com/Live-Hack-CVE/CVE-2023-24345](https://github.com/Live-Hack-CVE/CVE-2023-24345) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24345.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24345.svg)


## CVE-2023-24344
 D-Link N300 WI-FI Router DIR-605L v2.13B01 was discovered to contain a stack overflow via the webpage parameter at /goform/formWlanGuestSetup.

- [https://github.com/Live-Hack-CVE/CVE-2023-24344](https://github.com/Live-Hack-CVE/CVE-2023-24344) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24344.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24344.svg)


## CVE-2023-24343
 D-Link N300 WI-FI Router DIR-605L v2.13B01 was discovered to contain a stack overflow via the curTime parameter at /goform/formSchedule.

- [https://github.com/Live-Hack-CVE/CVE-2023-24343](https://github.com/Live-Hack-CVE/CVE-2023-24343) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24343.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24343.svg)


## CVE-2023-24238
 TOTOlink A7100RU(V7.4cu.2313_B20191024) was discovered to contain a command injection vulnerability via the city parameter at setting/delStaticDhcpRules.

- [https://github.com/Live-Hack-CVE/CVE-2023-24238](https://github.com/Live-Hack-CVE/CVE-2023-24238) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24238.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24238.svg)


## CVE-2023-24236
 TOTOlink A7100RU(V7.4cu.2313_B20191024) was discovered to contain a command injection vulnerability via the province parameter at setting/delStaticDhcpRules.

- [https://github.com/Live-Hack-CVE/CVE-2023-24236](https://github.com/Live-Hack-CVE/CVE-2023-24236) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24236.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24236.svg)


## CVE-2023-24055
 ** DISPUTED ** KeePass through 2.53 (in a default installation) allows an attacker, who has write access to the XML configuration file, to obtain the cleartext passwords by adding an export trigger. NOTE: the vendor's position is that the password database is not intended to be secure against an attacker who has that level of access to the local PC.

- [https://github.com/poppylarrry/firefox-rce-poc](https://github.com/poppylarrry/firefox-rce-poc) :  ![starts](https://img.shields.io/github/stars/poppylarrry/firefox-rce-poc.svg) ![forks](https://img.shields.io/github/forks/poppylarrry/firefox-rce-poc.svg)


## CVE-2023-23947
 Argo CD is a declarative, GitOps continuous delivery tool for Kubernetes. All Argo CD versions starting with 2.3.0-rc1 and prior to 2.3.17, 2.4.23 2.5.11, and 2.6.2 are vulnerable to an improper authorization bug which allows users who have the ability to update at least one cluster secret to update any cluster secret. The attacker could use this access to escalate privileges (potentially controlling Kubernetes resources) or to break Argo CD functionality (by preventing connections to external clusters). A patch for this vulnerability has been released in Argo CD versions 2.6.2, 2.5.11, 2.4.23, and 2.3.17. Two workarounds are available. Either modify the RBAC configuration to completely revoke all `clusters, update` access, or use the `destinations` and `clusterResourceWhitelist` fields to apply similar restrictions as the `namespaces` and `clusterResources` fields.

- [https://github.com/Live-Hack-CVE/CVE-2023-23947](https://github.com/Live-Hack-CVE/CVE-2023-23947) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23947.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23947.svg)


## CVE-2023-23936
 Undici is an HTTP/1.1 client for Node.js. Starting with version 2.0.0 and prior to version 5.19.1, the undici library does not protect `host` HTTP header from CRLF injection vulnerabilities. This issue is patched in Undici v5.19.1. As a workaround, sanitize the `headers.host` string before passing to undici.

- [https://github.com/Live-Hack-CVE/CVE-2023-23936](https://github.com/Live-Hack-CVE/CVE-2023-23936) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23936.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23936.svg)


## CVE-2023-23931
 cryptography is a package designed to expose cryptographic primitives and recipes to Python developers. In affected versions `Cipher.update_into` would accept Python objects which implement the buffer protocol, but provide only immutable buffers. This would allow immutable objects (such as `bytes`) to be mutated, thus violating fundamental rules of Python and resulting in corrupted output. This now correctly raises an exception. This issue has been present since `update_into` was originally introduced in cryptography 1.8.

- [https://github.com/Live-Hack-CVE/CVE-2023-23931](https://github.com/Live-Hack-CVE/CVE-2023-23931) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23931.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23931.svg)


## CVE-2023-23926
 APOC (Awesome Procedures on Cypher) is an add-on library for Neo4j. An XML External Entity (XXE) vulnerability found in the apoc.import.graphml procedure of APOC core plugin prior to version 5.5.0 in Neo4j graph database. XML External Entity (XXE) injection occurs when the XML parser allows external entities to be resolved. The XML parser used by the apoc.import.graphml procedure was not configured in a secure way and therefore allowed this. External entities can be used to read local files, send HTTP requests, and perform denial-of-service attacks on the application. Abusing the XXE vulnerability enabled assessors to read local files remotely. Although with the level of privileges assessors had this was limited to one-line files. With the ability to write to the database, any file could have been read. Additionally, assessors noted, with local testing, the server could be crashed by passing in improperly formatted XML. The minimum version containing a patch for this vulnerability is 5.5.0. Those who cannot upgrade the library can control the allowlist of the procedures that can be used in your system.

- [https://github.com/Live-Hack-CVE/CVE-2023-23926](https://github.com/Live-Hack-CVE/CVE-2023-23926) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23926.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23926.svg)


## CVE-2023-23752
 An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

- [https://github.com/DanielRuf/CVE-2023-23752](https://github.com/DanielRuf/CVE-2023-23752) :  ![starts](https://img.shields.io/github/stars/DanielRuf/CVE-2023-23752.svg) ![forks](https://img.shields.io/github/forks/DanielRuf/CVE-2023-23752.svg)


## CVE-2023-23558
 In Eternal Terminal 6.2.1, TelemetryService uses fixed paths in /tmp. For example, a local attacker can create /tmp/.sentry-native-etserver with mode 0777 before the etserver process is started. The attacker can choose to read sensitive information from that file, or modify the information in that file.

- [https://github.com/Live-Hack-CVE/CVE-2023-23558](https://github.com/Live-Hack-CVE/CVE-2023-23558) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23558.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23558.svg)


## CVE-2023-22953
 In ExpressionEngine before 7.2.6, remote code execution can be achieved by an authenticated Control Panel user.

- [https://github.com/Live-Hack-CVE/CVE-2023-22953](https://github.com/Live-Hack-CVE/CVE-2023-22953) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22953.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22953.svg)


## CVE-2023-22735
 Zulip is an open-source team collaboration tool. In versions of zulip prior to commit `2f6c5a8` but after commit `04cf68b` users could upload files with arbitrary `Content-Type` which would be served from the Zulip hostname with `Content-Disposition: inline` and no `Content-Security-Policy` header, allowing them to trick other users into executing arbitrary Javascript in the context of the Zulip application. Among other things, this enables session theft. Only deployments which use the S3 storage (not the local-disk storage) are affected, and only deployments which deployed commit 04cf68b45ebb5c03247a0d6453e35ffc175d55da, which has only been in `main`, not any numbered release. Users affected should upgrade from main again to deploy this fix. Switching from S3 storage to the local-disk storage would nominally mitigate this, but is likely more involved than upgrading to the latest `main` which addresses the issue.

- [https://github.com/Live-Hack-CVE/CVE-2023-22735](https://github.com/Live-Hack-CVE/CVE-2023-22735) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22735.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22735.svg)


## CVE-2023-22580
 Due to improper input filtering in the sequalize js library, can malicious queries lead to sensitive information disclosure.

- [https://github.com/Live-Hack-CVE/CVE-2023-22580](https://github.com/Live-Hack-CVE/CVE-2023-22580) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22580.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22580.svg)


## CVE-2023-22579
 Due to improper parameter filtering in the sequalize js library, can a attacker peform injection.

- [https://github.com/Live-Hack-CVE/CVE-2023-22579](https://github.com/Live-Hack-CVE/CVE-2023-22579) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22579.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22579.svg)


## CVE-2023-22578
 Due to improper artibute filtering in the sequalize js library, can a attacker peform SQL injections.

- [https://github.com/Live-Hack-CVE/CVE-2023-22578](https://github.com/Live-Hack-CVE/CVE-2023-22578) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22578.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22578.svg)


## CVE-2023-21753
 Event Tracing for Windows Information Disclosure Vulnerability. This CVE ID is unique from CVE-2023-21536.

- [https://github.com/timpen432/-Wh0Am1001-CVE-2023-21753](https://github.com/timpen432/-Wh0Am1001-CVE-2023-21753) :  ![starts](https://img.shields.io/github/stars/timpen432/-Wh0Am1001-CVE-2023-21753.svg) ![forks](https://img.shields.io/github/forks/timpen432/-Wh0Am1001-CVE-2023-21753.svg)


## CVE-2023-0862
 The NetModule NSRW web administration interface is vulnerable to path traversals, which could lead to arbitrary file uploads and deletion. By uploading malicious files to the web root directory, authenticated users could gain remote command execution with elevated privileges. This issue affects NSRW: from 4.3.0.0 before 4.3.0.119, from 4.4.0.0 before 4.4.0.118, from 4.6.0.0 before 4.6.0.105, from 4.7.0.0 before 4.7.0.103. The issue affects NSRW packaged by Phoenix Contact routers: from 4.6.72.0 before 4.6.72.101, from 4.6.73.0 before 4.6.73.101.

- [https://github.com/Live-Hack-CVE/CVE-2023-0862](https://github.com/Live-Hack-CVE/CVE-2023-0862) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0862.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0862.svg)


## CVE-2023-0861
 NetModule NSRW web administration interface executes an OS command constructed with unsanitized user input. A successful exploit could allow an authenticated user to execute arbitrary commands with elevated privileges. This issue affects NSRW: from 4.3.0.0 before 4.3.0.119, from 4.4.0.0 before 4.4.0.118, from 4.6.0.0 before 4.6.0.105, from 4.7.0.0 before 4.7.0.103. The issue affects NSRW packaged by Phoenix Contact routers: from 4.6.72.0 before 4.6.72.101, from 4.6.73.0 before 4.6.73.101.

- [https://github.com/Live-Hack-CVE/CVE-2023-0861](https://github.com/Live-Hack-CVE/CVE-2023-0861) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0861.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0861.svg)


## CVE-2023-0860
 Improper Restriction of Excessive Authentication Attempts in GitHub repository modoboa/modoboa-installer prior to 2.0.4.

- [https://github.com/0xsu3ks/CVE-2023-0860](https://github.com/0xsu3ks/CVE-2023-0860) :  ![starts](https://img.shields.io/github/stars/0xsu3ks/CVE-2023-0860.svg) ![forks](https://img.shields.io/github/forks/0xsu3ks/CVE-2023-0860.svg)
- [https://github.com/Live-Hack-CVE/CVE-2023-0860](https://github.com/Live-Hack-CVE/CVE-2023-0860) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0860.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0860.svg)


## CVE-2023-0821
 HashiCorp Nomad and Nomad Enterprise 1.2.15 up to 1.3.8, and 1.4.3 jobs using a maliciously compressed artifact stanza source can cause excessive disk usage. Fixed in 1.2.16, 1.3.9, and 1.4.4.

- [https://github.com/Live-Hack-CVE/CVE-2023-0821](https://github.com/Live-Hack-CVE/CVE-2023-0821) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0821.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0821.svg)


## CVE-2023-0771
 SQL Injection in GitHub repository ampache/ampache prior to 5.5.7,develop.

- [https://github.com/Live-Hack-CVE/CVE-2023-0771](https://github.com/Live-Hack-CVE/CVE-2023-0771) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0771.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0771.svg)


## CVE-2023-0751
 When GELI reads a key file from standard input, it does not reuse the key file to initialize multiple providers at once resulting in the second and subsequent devices silently using a NULL key as the user key file. If a user only uses a key file without a user passphrase, the master key is encrypted with an empty key file allowing trivial recovery of the master key.

- [https://github.com/Live-Hack-CVE/CVE-2023-0751](https://github.com/Live-Hack-CVE/CVE-2023-0751) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0751.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0751.svg)


## CVE-2023-0745
 Relative Path Traversal vulnerability in YugaByte, Inc. Yugabyte Managed (PlatformReplicationManager.Java modules) allows Path Traversal. This vulnerability is associated with program files PlatformReplicationManager.Java. This issue affects Yugabyte Managed: from 2.0 through 2.13.

- [https://github.com/Live-Hack-CVE/CVE-2023-0745](https://github.com/Live-Hack-CVE/CVE-2023-0745) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0745.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0745.svg)


## CVE-2023-0705
 Integer overflow in Core in Google Chrome prior to 110.0.5481.77 allowed a remote attacker who had one a race condition to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Low)

- [https://github.com/Live-Hack-CVE/CVE-2023-0705](https://github.com/Live-Hack-CVE/CVE-2023-0705) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0705.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0705.svg)


## CVE-2023-0662
 In PHP 8.0.X before 8.0.28, 8.1.X before 8.1.16 and 8.2.X before 8.2.3, excessive number of parts in HTTP form upload can cause high resource consumption and excessive number of log entries. This can cause denial of service on the affected server by exhausting CPU resources or disk space.

- [https://github.com/Live-Hack-CVE/CVE-2023-0662](https://github.com/Live-Hack-CVE/CVE-2023-0662) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0662.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0662.svg)


## CVE-2023-0574
 Server-Side Request Forgery (SSRF), Improperly Controlled Modification of Dynamically-Determined Object Attributes, Improper Restriction of Excessive Authentication Attempts vulnerability in YugaByte, Inc. Yugabyte Managed allows Accessing Functionality Not Properly Constrained by ACLs, Communication Channel Manipulation, Authentication Abuse.This issue affects Yugabyte Managed: from 2.0 through 2.13.

- [https://github.com/Live-Hack-CVE/CVE-2023-0574](https://github.com/Live-Hack-CVE/CVE-2023-0574) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0574.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0574.svg)


## CVE-2023-0568
 In PHP 8.0.X before 8.0.28, 8.1.X before 8.1.16 and 8.2.X before 8.2.3, core path resolution function allocate buffer one byte too small. When resolving paths with lengths close to system MAXPATHLEN setting, this may lead to the byte after the allocated buffer being overwritten with NUL value, which might lead to unauthorized data access or modification.

- [https://github.com/Live-Hack-CVE/CVE-2023-0568](https://github.com/Live-Hack-CVE/CVE-2023-0568) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0568.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0568.svg)


## CVE-2022-48308
 It was discovered that the sls-logging was not verifying hostnames in TLS certificates due to a misuse of the javax.net.ssl.SSLSocketFactory API. A malicious attacker in a privileged network position could abuse this to perform a man-in-the-middle attack. A successful man-in-the-middle attack would allow them to intercept, read, or modify network communications to and from the affected service.

- [https://github.com/Live-Hack-CVE/CVE-2022-48308](https://github.com/Live-Hack-CVE/CVE-2022-48308) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48308.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48308.svg)


## CVE-2022-48307
 It was discovered that the Magritte-ftp was not verifying hostnames in TLS certificates due to a misuse of the javax.net.ssl.SSLSocketFactory API. A malicious attacker in a privileged network position could abuse this to perform a man-in-the-middle attack. A successful man-in-the-middle attack would allow them to intercept, read, or modify network communications to and from the affected service. In the case of a successful man in the middle attack on magritte-ftp, an attacker would be able to read and modify network traffic such as authentication tokens or raw data entering a Palantir Foundry stack.

- [https://github.com/Live-Hack-CVE/CVE-2022-48307](https://github.com/Live-Hack-CVE/CVE-2022-48307) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48307.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48307.svg)


## CVE-2022-48306
 Improper Validation of Certificate with Host Mismatch vulnerability in Gotham Chat IRC helper of Palantir Gotham allows A malicious attacker in a privileged network position could abuse this to perform a man-in-the-middle attack. A successful man-in-the-middle attack would allow them to intercept, read, or modify network communications to and from the affected service. This issue affects: Palantir Palantir Gotham Chat IRC helper versions prior to 30221005.210011.9242.

- [https://github.com/Live-Hack-CVE/CVE-2022-48306](https://github.com/Live-Hack-CVE/CVE-2022-48306) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48306.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48306.svg)


## CVE-2022-47703
 TIANJIE CPE906-3 is vulnerable to password disclosure. This is present on Software Version WEB5.0_LCD_20200513, Firmware Version MV8.003, and Hardware Version CPF906-V5.0_LCD_20200513.

- [https://github.com/Live-Hack-CVE/CVE-2022-47703](https://github.com/Live-Hack-CVE/CVE-2022-47703) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47703.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47703.svg)


## CVE-2022-47373
 Reflected Cross Site Scripting in Search Functionality of Module Library in Pandora FMS Console v766 and lower. This vulnerability arises on the forget password functionality in which parameter username does not proper input validation/sanitization thus results in executing malicious JavaScript payload.

- [https://github.com/Argonx21/CVE-2022-47373](https://github.com/Argonx21/CVE-2022-47373) :  ![starts](https://img.shields.io/github/stars/Argonx21/CVE-2022-47373.svg) ![forks](https://img.shields.io/github/forks/Argonx21/CVE-2022-47373.svg)


## CVE-2022-45436
 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Artica PFMS Pandora FMS v765 on all platforms, allows Cross-Site Scripting (XSS). As a manager privilege user , create a network map containing name as xss payload. Once created, admin user must click on the edit network maps and XSS payload will be executed, which could be used for stealing admin users cookie value.

- [https://github.com/damodarnaik/CVE-2022-45436](https://github.com/damodarnaik/CVE-2022-45436) :  ![starts](https://img.shields.io/github/stars/damodarnaik/CVE-2022-45436.svg) ![forks](https://img.shields.io/github/forks/damodarnaik/CVE-2022-45436.svg)


## CVE-2022-44666
 Windows Contacts Remote Code Execution Vulnerability.

- [https://github.com/j00sean/CVE-2022-44666](https://github.com/j00sean/CVE-2022-44666) :  ![starts](https://img.shields.io/github/stars/j00sean/CVE-2022-44666.svg) ![forks](https://img.shields.io/github/forks/j00sean/CVE-2022-44666.svg)


## CVE-2022-44556
 Missing parameter type validation in the DRM module. Successful exploitation of this vulnerability may affect availability.

- [https://github.com/Live-Hack-CVE/CVE-2022-44556](https://github.com/Live-Hack-CVE/CVE-2022-44556) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44556.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44556.svg)


## CVE-2022-44299
 SiteServerCMS 7.1.3 sscms has a file read vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-44299](https://github.com/Live-Hack-CVE/CVE-2022-44299) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44299.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44299.svg)


## CVE-2022-43980
 There is a stored cross-site scripting vulnerability in Pandora FMS v765 in the network maps editing functionality. An attacker could modify a network map, including on purpose the name of an XSS payload. Once created, if a user with admin privileges clicks on the edited network maps, the XSS payload will be executed. The exploitation of this vulnerability could allow an atacker to steal the value of the admin users cookie.

- [https://github.com/Argonx21/CVE-2022-43980](https://github.com/Argonx21/CVE-2022-43980) :  ![starts](https://img.shields.io/github/stars/Argonx21/CVE-2022-43980.svg) ![forks](https://img.shields.io/github/forks/Argonx21/CVE-2022-43980.svg)


## CVE-2022-43969
 Ricoh mp_c4504ex devices with firmware 1.06 mishandle credentials.

- [https://github.com/Live-Hack-CVE/CVE-2022-43969](https://github.com/Live-Hack-CVE/CVE-2022-43969) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43969.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43969.svg)


## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/kuckibf/Popular-CVEs](https://github.com/kuckibf/Popular-CVEs) :  ![starts](https://img.shields.io/github/stars/kuckibf/Popular-CVEs.svg) ![forks](https://img.shields.io/github/forks/kuckibf/Popular-CVEs.svg)
- [https://github.com/poppylarrry/firefox-rce-poc](https://github.com/poppylarrry/firefox-rce-poc) :  ![starts](https://img.shields.io/github/stars/poppylarrry/firefox-rce-poc.svg) ![forks](https://img.shields.io/github/forks/poppylarrry/firefox-rce-poc.svg)


## CVE-2022-40080
 Stack overflow vulnerability in Aspire E5-475G 's BIOS firmware, in the FpGui module, a second call to GetVariable services allows local attackers to execute arbitrary code in the UEFI DXE phase and gain escalated privileges.

- [https://github.com/Live-Hack-CVE/CVE-2022-40080](https://github.com/Live-Hack-CVE/CVE-2022-40080) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-40080.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-40080.svg)


## CVE-2022-38731
 Qaelum DOSE 18.08 through 21.1 before 21.2 allows Directory Traversal via the loadimages name parameter. It allows a user to specify an arbitrary location on the server's filesystem from which to load an image. (Only images are displayed to the attacker. All other files are loaded but not displayed.) The Content-Type response header reflects the actual content type of the file being requested. This allows an attacker to enumerate files on the local system. Additionally, remote resources can be requested via a UNC path, allowing an attacker to coerce authentication out from the server to the attackers machine.

- [https://github.com/Live-Hack-CVE/CVE-2022-38731](https://github.com/Live-Hack-CVE/CVE-2022-38731) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38731.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38731.svg)


## CVE-2022-36398
 Uncontrolled search path in the Intel(R) Battery Life Diagnostic Tool software before version 2.2.0 may allow an authenticated user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-36398](https://github.com/Live-Hack-CVE/CVE-2022-36398) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36398.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36398.svg)


## CVE-2022-36278
 Insufficient control flow management in the Intel(R) Battery Life Diagnostic Tool software before version 2.2.0 may allow an authenticated user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-36278](https://github.com/Live-Hack-CVE/CVE-2022-36278) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36278.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36278.svg)


## CVE-2022-33892
 Path traversal in the Intel(R) Quartus Prime Pro and Standard edition software may allow an authenticated user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-33892](https://github.com/Live-Hack-CVE/CVE-2022-33892) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33892.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33892.svg)


## CVE-2022-32570
 Improper authentication in the Intel(R) Quartus Prime Pro and Standard edition software may allow an authenticated user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-32570](https://github.com/Live-Hack-CVE/CVE-2022-32570) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32570.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32570.svg)


## CVE-2022-30539
 Use after free in the BIOS firmware for some Intel(R) Processors may allow a privileged user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-30539](https://github.com/Live-Hack-CVE/CVE-2022-30539) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-30539.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-30539.svg)


## CVE-2022-30531
 Out-of-bounds read in the Intel(R) Iris(R) Xe MAX drivers for Windows before version 100.0.5.1474 may allow a privileged user to potentially enable information disclosure via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-30531](https://github.com/Live-Hack-CVE/CVE-2022-30531) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-30531.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-30531.svg)


## CVE-2022-30530
 Protection mechanism failure in the Intel(R) DSA software before version 22.4.26 may allow an authenticated user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-30530](https://github.com/Live-Hack-CVE/CVE-2022-30530) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-30530.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-30530.svg)


## CVE-2022-30339
 Out-of-bounds read in firmware for the Intel(R) Integrated Sensor Solution before versions 5.4.2.4579v3, 5.4.1.4479 and 5.0.0.4143 may allow a privileged user to potentially enable denial of service via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-30339](https://github.com/Live-Hack-CVE/CVE-2022-30339) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-30339.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-30339.svg)


## CVE-2022-30190
 Microsoft Windows Support Diagnostic Tool (MSDT) Remote Code Execution Vulnerability.

- [https://github.com/poppylarrry/firefox-rce-poc](https://github.com/poppylarrry/firefox-rce-poc) :  ![starts](https://img.shields.io/github/stars/poppylarrry/firefox-rce-poc.svg) ![forks](https://img.shields.io/github/forks/poppylarrry/firefox-rce-poc.svg)


## CVE-2022-27897
 Palantir Gotham versions prior to 3.22.11.2 included an unauthenticated endpoint that would load portions of maliciously crafted zip files to memory. An attacker could repeatedly upload a malicious zip file, which would allow them to exhaust memory resources on the dispatch server.

- [https://github.com/Live-Hack-CVE/CVE-2022-27897](https://github.com/Live-Hack-CVE/CVE-2022-27897) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-27897.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-27897.svg)


## CVE-2022-27892
 Palantir Gotham versions prior to 3.22.11.2 included an unauthenticated endpoint that would have allowed an attacker to exhaust the memory of the Gotham dispatch service.

- [https://github.com/Live-Hack-CVE/CVE-2022-27892](https://github.com/Live-Hack-CVE/CVE-2022-27892) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-27892.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-27892.svg)


## CVE-2022-27891
 Palantir Gotham included an unauthenticated endpoint that listed all active usernames on the stack with an active session. The affected services have been patched and automatically deployed to all Apollo-managed Gotham instances. It is highly recommended that customers upgrade all affected services to the latest version. This issue affects: Palantir Gotham versions prior to 103.30221005.0.

- [https://github.com/Live-Hack-CVE/CVE-2022-27891](https://github.com/Live-Hack-CVE/CVE-2022-27891) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-27891.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-27891.svg)


## CVE-2022-27890
 It was discovered that the sls-logging was not verifying hostnames in TLS certificates due to a misuse of the javax.net.ssl.SSLSocketFactory API. A malicious attacker in a privileged network position could abuse this to perform a man-in-the-middle attack. A successful man-in-the-middle attack would allow them to intercept, read, or modify network communications to and from the affected service. In the case of AtlasDB, the vulnerability was mitigated by other network controls such as two-way TLS when deployed as part of a Palantir platform. Palantir still recommends upgrading to a non-vulnerable version out of an abundance of caution.

- [https://github.com/Live-Hack-CVE/CVE-2022-27890](https://github.com/Live-Hack-CVE/CVE-2022-27890) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-27890.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-27890.svg)


## CVE-2022-26841
 Insufficient control flow management for the Intel(R) SGX SDK software for Linux before version 2.16.100.1 may allow an authenticated user to potentially enable information disclosure via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-26841](https://github.com/Live-Hack-CVE/CVE-2022-26841) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-26841.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-26841.svg)


## CVE-2022-26840
 Improper neutralization in the Intel(R) Quartus Prime Pro and Standard edition software may allow an authenticated user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-26840](https://github.com/Live-Hack-CVE/CVE-2022-26840) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-26840.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-26840.svg)


## CVE-2022-26837
 Improper input validation in the BIOS firmware for some Intel(R) Processors may allow a privileged user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-26837](https://github.com/Live-Hack-CVE/CVE-2022-26837) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-26837.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-26837.svg)


## CVE-2022-26425
 Uncontrolled search path element in the Intel(R) oneAPI Collective Communications Library (oneCCL) before version 2021.6 for Intel(R) oneAPI Base Toolkit may allow an authenticated user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-26425](https://github.com/Live-Hack-CVE/CVE-2022-26425) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-26425.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-26425.svg)


## CVE-2022-26421
 Uncontrolled search path element in the Intel(R) oneAPI DPC++/C++ Compiler Runtime before version 2022.0 may allow an authenticated user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-26421](https://github.com/Live-Hack-CVE/CVE-2022-26421) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-26421.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-26421.svg)


## CVE-2022-26345
 Uncontrolled search path element in the Intel(R) oneAPI Toolkit OpenMP before version 2022.1 may allow an authenticated user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-26345](https://github.com/Live-Hack-CVE/CVE-2022-26345) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-26345.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-26345.svg)


## CVE-2022-26343
 Improper access control in the BIOS firmware for some Intel(R) Processors may allow a privileged user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-26343](https://github.com/Live-Hack-CVE/CVE-2022-26343) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-26343.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-26343.svg)


## CVE-2022-26076
 Uncontrolled search path element in the Intel(R) oneAPI Deep Neural Network (oneDNN) before version 2022.1 may allow an authenticated user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-26076](https://github.com/Live-Hack-CVE/CVE-2022-26076) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-26076.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-26076.svg)


## CVE-2022-26032
 Uncontrolled search path element in the Intel(R) Distribution for Python programming language before version 2022.1 for Intel(R) oneAPI Toolkits may allow an authenticated user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-26032](https://github.com/Live-Hack-CVE/CVE-2022-26032) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-26032.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-26032.svg)


## CVE-2022-25905
 Uncontrolled search path element in the Intel(R) oneAPI Data Analytics Library (oneDAL) before version 2021.5 for Intel(R) oneAPI Base Toolkit may allow an authenticated user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-25905](https://github.com/Live-Hack-CVE/CVE-2022-25905) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-25905.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-25905.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/kuckibf/Popular-CVEs](https://github.com/kuckibf/Popular-CVEs) :  ![starts](https://img.shields.io/github/stars/kuckibf/Popular-CVEs.svg) ![forks](https://img.shields.io/github/forks/kuckibf/Popular-CVEs.svg)


## CVE-2022-21216
 Insufficient granularity of access control in out-of-band management in some Intel(R) Atom and Intel Xeon Scalable Processors may allow a privileged user to potentially enable escalation of privilege via adjacent network access.

- [https://github.com/Live-Hack-CVE/CVE-2022-21216](https://github.com/Live-Hack-CVE/CVE-2022-21216) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-21216.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-21216.svg)


## CVE-2022-4903
 A vulnerability was found in CodenameOne 7.0.70. It has been classified as problematic. Affected is an unknown function. The manipulation leads to use of implicit intent for sensitive communication. It is possible to launch the attack remotely. Upgrading to version 7.0.71 is able to address this issue. The name of the patch is dad49c9ef26a598619fc48d2697151a02987d478. It is recommended to upgrade the affected component. VDB-220470 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-4903](https://github.com/Live-Hack-CVE/CVE-2022-4903) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4903.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4903.svg)


## CVE-2022-3923
 The ActiveCampaign for WooCommerce WordPress plugin through 1.9.6 does not have authorisation check when cleaning up its error logs via an AJAX action, which could allow any authenticated users, such as subscriber to call it and remove error logs.

- [https://github.com/Live-Hack-CVE/CVE-2022-3923](https://github.com/Live-Hack-CVE/CVE-2022-3923) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3923.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3923.svg)


## CVE-2022-3843
 In WAGO Unmanaged Switch (852-111/000-001) in firmware version 01 an undocumented configuration interface without authorization allows an remote attacker to read system information and configure a limited set of parameters.

- [https://github.com/Live-Hack-CVE/CVE-2022-3843](https://github.com/Live-Hack-CVE/CVE-2022-3843) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3843.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3843.svg)


## CVE-2022-3716
 A vulnerability classified as problematic was found in SourceCodester Online Medicine Ordering System 1.0. Affected by this vulnerability is an unknown functionality of the file /omos/admin/?page=user/list. The manipulation of the argument First Name/Middle Name/Last Name leads to cross site scripting. The attack can be launched remotely. The associated identifier of this vulnerability is VDB-212347.

- [https://github.com/Live-Hack-CVE/CVE-2022-3716](https://github.com/Live-Hack-CVE/CVE-2022-3716) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3716.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3716.svg)


## CVE-2022-3568
 The ImageMagick Engine plugin for WordPress is vulnerable to deserialization of untrusted input via the 'cli_path' parameter in versions up to, and including 1.7.5. This makes it possible for unauthenticated users to call files using a PHAR wrapper, granted they can trick a site administrator into performing an action such as clicking on a link, that will deserialize and call arbitrary PHP Objects that can be used to perform a variety of malicious actions granted a POP chain is also present. It also requires that the attacker is successful in uploading a file with the serialized payload.

- [https://github.com/Live-Hack-CVE/CVE-2022-3568](https://github.com/Live-Hack-CVE/CVE-2022-3568) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3568.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3568.svg)


## CVE-2022-3565
 A vulnerability, which was classified as critical, has been found in Linux Kernel. Affected by this issue is the function del_timer of the file drivers/isdn/mISDN/l1oip_core.c of the component Bluetooth. The manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-211088.

- [https://github.com/Live-Hack-CVE/CVE-2022-3565](https://github.com/Live-Hack-CVE/CVE-2022-3565) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3565.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3565.svg)


## CVE-2022-1774
 Exposure of Sensitive Information to an Unauthorized Actor in GitHub repository jgraph/drawio prior to 18.0.7.

- [https://github.com/Live-Hack-CVE/CVE-2022-1774](https://github.com/Live-Hack-CVE/CVE-2022-1774) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1774.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1774.svg)


## CVE-2022-1767
 Server-Side Request Forgery (SSRF) in GitHub repository jgraph/drawio prior to 18.0.7.

- [https://github.com/Live-Hack-CVE/CVE-2022-1767](https://github.com/Live-Hack-CVE/CVE-2022-1767) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1767.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1767.svg)


## CVE-2022-1727
 Improper Input Validation in GitHub repository jgraph/drawio prior to 18.0.6.

- [https://github.com/Live-Hack-CVE/CVE-2022-1727](https://github.com/Live-Hack-CVE/CVE-2022-1727) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1727.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1727.svg)


## CVE-2022-1722
 SSRF in editor's proxy via IPv6 link-local address in GitHub repository jgraph/drawio prior to 18.0.5. SSRF to internal link-local IPv6 addresses

- [https://github.com/Live-Hack-CVE/CVE-2022-1722](https://github.com/Live-Hack-CVE/CVE-2022-1722) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1722.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1722.svg)


## CVE-2022-1721
 Path Traversal in WellKnownServlet in GitHub repository jgraph/drawio prior to 18.0.5. Read local files of the web application.

- [https://github.com/Live-Hack-CVE/CVE-2022-1721](https://github.com/Live-Hack-CVE/CVE-2022-1721) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1721.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1721.svg)


## CVE-2022-1713
 SSRF on /proxy in GitHub repository jgraph/drawio prior to 18.0.4. An attacker can make a request as the server and read its contents. This can lead to a leak of sensitive information.

- [https://github.com/Live-Hack-CVE/CVE-2022-1713](https://github.com/Live-Hack-CVE/CVE-2022-1713) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1713.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1713.svg)


## CVE-2022-1609
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/0xSojalSec/CVE-2022-1609](https://github.com/0xSojalSec/CVE-2022-1609) :  ![starts](https://img.shields.io/github/stars/0xSojalSec/CVE-2022-1609.svg) ![forks](https://img.shields.io/github/forks/0xSojalSec/CVE-2022-1609.svg)


## CVE-2022-0637
 There was an open redirection vulnerability pollbot, which was used in https://pollbot.services.mozilla.com/ and https://pollbot.stage.mozaws.net/ An attacker could have redirected anyone to malicious sites.

- [https://github.com/Live-Hack-CVE/CVE-2022-0637](https://github.com/Live-Hack-CVE/CVE-2022-0637) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-0637.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-0637.svg)


## CVE-2021-45046
 It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in an information leak and remote code execution in some environments and local code execution in all environments. Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7) fix this issue by removing support for message lookup patterns and disabling JNDI functionality by default.

- [https://github.com/kuckibf/Popular-CVEs](https://github.com/kuckibf/Popular-CVEs) :  ![starts](https://img.shields.io/github/stars/kuckibf/Popular-CVEs.svg) ![forks](https://img.shields.io/github/forks/kuckibf/Popular-CVEs.svg)
- [https://github.com/grandDancer/Chrome-CVE-PoC](https://github.com/grandDancer/Chrome-CVE-PoC) :  ![starts](https://img.shields.io/github/stars/grandDancer/Chrome-CVE-PoC.svg) ![forks](https://img.shields.io/github/forks/grandDancer/Chrome-CVE-PoC.svg)


## CVE-2021-43529
 Thunderbird versions prior to 91.3.0 are vulnerable to the heap overflow described in CVE-2021-43527 when processing S/MIME messages. Thunderbird versions 91.3.0 and later will not call the vulnerable code when processing S/MIME messages that contain certificates with DER-encoded DSA or RSA-PSS signatures.

- [https://github.com/Live-Hack-CVE/CVE-2021-43529](https://github.com/Live-Hack-CVE/CVE-2021-43529) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-43529.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-43529.svg)


## CVE-2021-43527
 NSS (Network Security Services) versions prior to 3.73 or 3.68.1 ESR are vulnerable to a heap overflow when handling DER-encoded DSA or RSA-PSS signatures. Applications using NSS for handling signatures encoded within CMS, S/MIME, PKCS \#7, or PKCS \#12 are likely to be impacted. Applications using NSS for certificate validation or other TLS, X.509, OCSP or CRL functionality may be impacted, depending on how they configure NSS. *Note: This vulnerability does NOT impact Mozilla Firefox.* However, email clients and PDF viewers that use NSS for signature verification, such as Thunderbird, LibreOffice, Evolution and Evince are believed to be impacted. This vulnerability affects NSS &lt; 3.73 and NSS &lt; 3.68.1.

- [https://github.com/Live-Hack-CVE/CVE-2021-43529](https://github.com/Live-Hack-CVE/CVE-2021-43529) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-43529.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-43529.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/grandDancer/Chrome-CVE-PoC](https://github.com/grandDancer/Chrome-CVE-PoC) :  ![starts](https://img.shields.io/github/stars/grandDancer/Chrome-CVE-PoC.svg) ![forks](https://img.shields.io/github/forks/grandDancer/Chrome-CVE-PoC.svg)


## CVE-2021-40555
 Cross site scripting (XSS) vulnerability in flatCore-CMS 2.2.15 allows attackers to execute arbitrary code via description field on the new page creation form.

- [https://github.com/Live-Hack-CVE/CVE-2021-40555](https://github.com/Live-Hack-CVE/CVE-2021-40555) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-40555.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-40555.svg)


## CVE-2021-23980
 A mutation XSS affects users calling bleach.clean with all of: svg or math in the allowed tags p or br in allowed tags style, title, noscript, script, textarea, noframes, iframe, or xmp in allowed tags the keyword argument strip_comments=False Note: none of the above tags are in the default allowed tags and strip_comments defaults to True.

- [https://github.com/Live-Hack-CVE/CVE-2021-23980](https://github.com/Live-Hack-CVE/CVE-2021-23980) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-23980.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-23980.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/poppylarrry/firefox-rce-poc](https://github.com/poppylarrry/firefox-rce-poc) :  ![starts](https://img.shields.io/github/stars/poppylarrry/firefox-rce-poc.svg) ![forks](https://img.shields.io/github/forks/poppylarrry/firefox-rce-poc.svg)


## CVE-2021-3639
 A flaw was found in mod_auth_mellon where it does not sanitize logout URLs properly. This issue could be used by an attacker to facilitate phishing attacks by tricking users into visiting a trusted web application URL that redirects to an external and potentially malicious server. The highest threat from this liability is to confidentiality and integrity.

- [https://github.com/Live-Hack-CVE/CVE-2021-3639](https://github.com/Live-Hack-CVE/CVE-2021-3639) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-3639.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-3639.svg)


## CVE-2020-12413
 The Raccoon attack is a timing attack on DHE ciphersuites inherit in the TLS specification. To mitigate this vulnerability, Firefox disabled support for DHE ciphersuites.

- [https://github.com/Live-Hack-CVE/CVE-2020-12413](https://github.com/Live-Hack-CVE/CVE-2020-12413) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-12413.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-12413.svg)


## CVE-2020-9453
 In Epson iProjection v2.30, the driver file EMP_MPAU.sys allows local users to cause a denial of service (BSOD) or possibly have unspecified other impact because of not validating input values from IOCtl 0x9C402406 and IOCtl 0x9C40240A. (0x9C402402 has only a NULL pointer dereference.) This affects \Device\EMPMPAUIO and \DosDevices\EMPMPAU.

- [https://github.com/Live-Hack-CVE/CVE-2020-9453](https://github.com/Live-Hack-CVE/CVE-2020-9453) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-9453.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-9453.svg)


## CVE-2020-6817
 bleach.clean behavior parsing style attributes could result in a regular expression denial of service (ReDoS). Calls to bleach.clean with an allowed tag with an allowed style attribute are vulnerable to ReDoS. For example, bleach.clean(..., attributes={'a': ['style']}).

- [https://github.com/Live-Hack-CVE/CVE-2020-6817](https://github.com/Live-Hack-CVE/CVE-2020-6817) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-6817.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-6817.svg)


## CVE-2020-5245
 Dropwizard-Validation before 1.3.19, and 2.0.2 may allow arbitrary code execution on the host system, with the privileges of the Dropwizard service account, by injecting arbitrary Java Expression Language expressions when using the self-validating feature. The issue has been fixed in dropwizard-validation 1.3.19 and 2.0.2.

- [https://github.com/LycsHub/CVE-2020-5245](https://github.com/LycsHub/CVE-2020-5245) :  ![starts](https://img.shields.io/github/stars/LycsHub/CVE-2020-5245.svg) ![forks](https://img.shields.io/github/forks/LycsHub/CVE-2020-5245.svg)


## CVE-2020-2551
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: WLS Core Components). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/zhzyker/exphub](https://github.com/zhzyker/exphub) :  ![starts](https://img.shields.io/github/stars/zhzyker/exphub.svg) ![forks](https://img.shields.io/github/forks/zhzyker/exphub.svg)
- [https://github.com/Y4er/CVE-2020-2551](https://github.com/Y4er/CVE-2020-2551) :  ![starts](https://img.shields.io/github/stars/Y4er/CVE-2020-2551.svg) ![forks](https://img.shields.io/github/forks/Y4er/CVE-2020-2551.svg)


## CVE-2020-0796
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

- [https://github.com/kuckibf/Popular-CVEs](https://github.com/kuckibf/Popular-CVEs) :  ![starts](https://img.shields.io/github/stars/kuckibf/Popular-CVEs.svg) ![forks](https://img.shields.io/github/forks/kuckibf/Popular-CVEs.svg)
- [https://github.com/poppylarrry/firefox-rce-poc](https://github.com/poppylarrry/firefox-rce-poc) :  ![starts](https://img.shields.io/github/stars/poppylarrry/firefox-rce-poc.svg) ![forks](https://img.shields.io/github/forks/poppylarrry/firefox-rce-poc.svg)


## CVE-2019-17003
 Scanning a QR code that contained a javascript: URL would have resulted in the Javascript being executed.

- [https://github.com/Live-Hack-CVE/CVE-2019-17003](https://github.com/Live-Hack-CVE/CVE-2019-17003) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-17003.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-17003.svg)


## CVE-2018-25009
 A heap-based buffer overflow was found in libwebp in versions before 1.0.1 in GetLE16().

- [https://github.com/Live-Hack-CVE/CVE-2018-25009](https://github.com/Live-Hack-CVE/CVE-2018-25009) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-25009.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-25009.svg)


## CVE-2018-19488
 The WP-jobhunt plugin before version 2.4 for WordPress does not control AJAX requests sent to the cs_reset_pass() function through the admin-ajax.php file, which allows remote unauthenticated attackers to reset the password of a user's account.

- [https://github.com/YOLOP0wn/wp-jobhunt-exploit](https://github.com/YOLOP0wn/wp-jobhunt-exploit) :  ![starts](https://img.shields.io/github/stars/YOLOP0wn/wp-jobhunt-exploit.svg) ![forks](https://img.shields.io/github/forks/YOLOP0wn/wp-jobhunt-exploit.svg)


## CVE-2018-19487
 The WP-jobhunt plugin before version 2.4 for WordPress does not control AJAX requests sent to the cs_employer_ajax_profile() function through the admin-ajax.php file, which allows remote unauthenticated attackers to enumerate information about users.

- [https://github.com/YOLOP0wn/wp-jobhunt-exploit](https://github.com/YOLOP0wn/wp-jobhunt-exploit) :  ![starts](https://img.shields.io/github/stars/YOLOP0wn/wp-jobhunt-exploit.svg) ![forks](https://img.shields.io/github/forks/YOLOP0wn/wp-jobhunt-exploit.svg)


## CVE-2018-18893
 Jinjava before 2.4.6 does not block the getClass method, related to com/hubspot/jinjava/el/ext/JinjavaBeanELResolver.java.

- [https://github.com/LycsHub/CVE-2018-18893](https://github.com/LycsHub/CVE-2018-18893) :  ![starts](https://img.shields.io/github/stars/LycsHub/CVE-2018-18893.svg) ![forks](https://img.shields.io/github/forks/LycsHub/CVE-2018-18893.svg)


## CVE-2018-3912
 On Samsung SmartThings Hub STH-ETH-250 devices with firmware version 0.20.17, the video-core process insecurely extracts the fields from the &quot;shard&quot; table of its SQLite database, leading to a buffer overflow on the stack. The strcpy call overflows the destination buffer, which has a size of 128 bytes. An attacker can send an arbitrarily long &quot;secretKey&quot; value in order to exploit this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2018-3912](https://github.com/Live-Hack-CVE/CVE-2018-3912) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-3912.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-3912.svg)


## CVE-2017-7269
 Buffer overflow in the ScStoragePathFromUrl function in the WebDAV service in Internet Information Services (IIS) 6.0 in Microsoft Windows Server 2003 R2 allows remote attackers to execute arbitrary code via a long header beginning with &quot;If: &lt;http://&quot; in a PROPFIND request, as exploited in the wild in July or August 2016.

- [https://github.com/Therootkitsec/-CVE-2017-7269](https://github.com/Therootkitsec/-CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/Therootkitsec/-CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/Therootkitsec/-CVE-2017-7269.svg)


## CVE-2015-10077
 A vulnerability was found in webbuilders-group silverstripe-kapost-bridge 0.3.3. It has been declared as critical. Affected by this vulnerability is the function index/getPreview of the file code/control/KapostService.php. The manipulation leads to sql injection. The attack can be launched remotely. Upgrading to version 0.4.0 is able to address this issue. The name of the patch is 2e14b0fd0ea35034f90890f364b130fb4645ff35. It is recommended to upgrade the affected component. The associated identifier of this vulnerability is VDB-220471.

- [https://github.com/Live-Hack-CVE/CVE-2015-10077](https://github.com/Live-Hack-CVE/CVE-2015-10077) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10077.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10077.svg)

