# Update 2025-08-21
## CVE-2025-51529
 Incorrect Access Control in the AJAX endpoint functionality in jonkastonka Cookies and Content Security Policy plugin through version 2.29 allows remote attackers to cause a denial of service (database server resource exhaustion) via unlimited database write operations to the wp_ajax_nopriv_cacsp_insert_consent_data endpoint.

- [https://github.com/piotrmaciejbednarski/CVE-2025-51529](https://github.com/piotrmaciejbednarski/CVE-2025-51529) :  ![starts](https://img.shields.io/github/stars/piotrmaciejbednarski/CVE-2025-51529.svg) ![forks](https://img.shields.io/github/forks/piotrmaciejbednarski/CVE-2025-51529.svg)


## CVE-2025-50461
 A deserialization vulnerability exists in Volcengine's verl 3.0.0, specifically in the scripts/model_merger.py script when using the "fsdp" backend. The script calls torch.load() with weights_only=False on user-supplied .pt files, allowing attackers to execute arbitrary code if a maliciously crafted model file is loaded. An attacker can exploit this by convincing a victim to download and place a malicious model file in a local directory with a specific filename pattern. This vulnerability may lead to arbitrary code execution with the privileges of the user running the script.

- [https://github.com/Anchor0221/CVE-2025-50461](https://github.com/Anchor0221/CVE-2025-50461) :  ![starts](https://img.shields.io/github/stars/Anchor0221/CVE-2025-50461.svg) ![forks](https://img.shields.io/github/forks/Anchor0221/CVE-2025-50461.svg)


## CVE-2025-49132
 Pterodactyl is a free, open-source game server management panel. Prior to version 1.11.11, using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated. With the ability to execute arbitrary code it could be used to gain access to the Panel's server, read credentials from the Panel's config, extract sensitive information from the database, access files of servers managed by the panel, etc. This issue has been patched in version 1.11.11. There are no software workarounds for this vulnerability, but use of an external Web Application Firewall (WAF) could help mitigate this attack.

- [https://github.com/pxxdrobits/CVE-2025-49132](https://github.com/pxxdrobits/CVE-2025-49132) :  ![starts](https://img.shields.io/github/stars/pxxdrobits/CVE-2025-49132.svg) ![forks](https://img.shields.io/github/forks/pxxdrobits/CVE-2025-49132.svg)


## CVE-2025-49113
 Roundcube Webmail before 1.5.10 and 1.6.x before 1.6.11 allows remote code execution by authenticated users because the _from parameter in a URL is not validated in program/actions/settings/upload.php, leading to PHP Object Deserialization.

- [https://github.com/SteamPunk424/CVE-2025-49113-Roundcube-RCE-PHP](https://github.com/SteamPunk424/CVE-2025-49113-Roundcube-RCE-PHP) :  ![starts](https://img.shields.io/github/stars/SteamPunk424/CVE-2025-49113-Roundcube-RCE-PHP.svg) ![forks](https://img.shields.io/github/forks/SteamPunk424/CVE-2025-49113-Roundcube-RCE-PHP.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927](https://github.com/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927.svg)


## CVE-2025-8723
 The Cloudflare Image Resizing plugin for WordPress is vulnerable to Remote Code Execution due to missing authentication and insufficient sanitization within its hook_rest_pre_dispatch() method in all versions up to, and including, 1.5.6. This makes it possible for unauthenticated attackers to inject arbitrary PHP into the codebase, achieving remote code execution.

- [https://github.com/Nxploited/CVE-2025-8723](https://github.com/Nxploited/CVE-2025-8723) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-8723.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-8723.svg)


## CVE-2025-5038
 A maliciously crafted X_T file, when parsed through certain Autodesk products, can force a Memory Corruption vulnerability. A malicious actor can leverage this vulnerability to execute arbitrary code in the context of the current process.

- [https://github.com/Abdullah4eb/CVE-2025-50383](https://github.com/Abdullah4eb/CVE-2025-50383) :  ![starts](https://img.shields.io/github/stars/Abdullah4eb/CVE-2025-50383.svg) ![forks](https://img.shields.io/github/forks/Abdullah4eb/CVE-2025-50383.svg)


## CVE-2025-2598
 When the AWS Cloud Development Kit (AWS CDK) Command Line Interface (AWS CDK CLI) is used with a credential plugin which returns an expiration property with the retrieved AWS credentials, the credentials are printed to the console output. To mitigate this issue, users should upgrade to version 2.178.2 or later and ensure any forked or derivative code is patched to incorporate the new fixes.

- [https://github.com/SpongeBob-369/CVE-2025-2598](https://github.com/SpongeBob-369/CVE-2025-2598) :  ![starts](https://img.shields.io/github/stars/SpongeBob-369/CVE-2025-2598.svg) ![forks](https://img.shields.io/github/forks/SpongeBob-369/CVE-2025-2598.svg)


## CVE-2024-53900
 Mongoose before 8.8.3 can improperly use $where in match, leading to search injection.

- [https://github.com/www-spam/CVE-2024-53900](https://github.com/www-spam/CVE-2024-53900) :  ![starts](https://img.shields.io/github/stars/www-spam/CVE-2024-53900.svg) ![forks](https://img.shields.io/github/forks/www-spam/CVE-2024-53900.svg)


## CVE-2024-36042
 Silverpeas before 6.3.5 allows authentication bypass by omitting the Password field to AuthenticationServlet, often providing an unauthenticated user with superadmin access.

- [https://github.com/zaaraZiof0/CVE-2024-36042](https://github.com/zaaraZiof0/CVE-2024-36042) :  ![starts](https://img.shields.io/github/stars/zaaraZiof0/CVE-2024-36042.svg) ![forks](https://img.shields.io/github/forks/zaaraZiof0/CVE-2024-36042.svg)


## CVE-2023-49109
We recommend users to upgrade Apache DolphinScheduler to version 3.2.1, which fixes the issue.

- [https://github.com/shoucheng3/apache__dolphinscheduler_CVE-2023-49109_3-2-0](https://github.com/shoucheng3/apache__dolphinscheduler_CVE-2023-49109_3-2-0) :  ![starts](https://img.shields.io/github/stars/shoucheng3/apache__dolphinscheduler_CVE-2023-49109_3-2-0.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/apache__dolphinscheduler_CVE-2023-49109_3-2-0.svg)


## CVE-2023-41044
 Graylog is a free and open log management platform. A partial path traversal vulnerability exists in Graylog's `Support Bundle` feature. The vulnerability is caused by incorrect user input validation in an HTTP API resource. Graylog's Support Bundle feature allows an attacker with valid Admin role credentials to download or delete files in sibling directories of the support bundle directory. The default `data_dir` in operating system packages (DEB, RPM) is set to `/var/lib/graylog-server`. The data directory for the Support Bundle feature is always `data_dir/support-bundle`. Due to the partial path traversal vulnerability, an attacker with valid Admin role credentials can read or delete files in directories that start with a `/var/lib/graylog-server/support-bundle` directory name. The vulnerability would allow the download or deletion of files in the following example directories: `/var/lib/graylog-server/support-bundle-test` and `/var/lib/graylog-server/support-bundlesdirectory`. For the Graylog Docker images, the `data_dir` is set to `/usr/share/graylog/data` by default. This vulnerability is fixed in Graylog version 5.1.3 and later. Users are advised to upgrade. Users unable to upgrade should block all HTTP requests to the following HTTP API endpoints by using a reverse proxy server in front of Graylog. `GET /api/system/debug/support/bundle/download/{filename}` and `DELETE /api/system/debug/support/bundle/{filename}`.

- [https://github.com/shoucheng3/Graylog2__graylog2-server_CVE-2023-41044_5-1-2](https://github.com/shoucheng3/Graylog2__graylog2-server_CVE-2023-41044_5-1-2) :  ![starts](https://img.shields.io/github/stars/shoucheng3/Graylog2__graylog2-server_CVE-2023-41044_5-1-2.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/Graylog2__graylog2-server_CVE-2023-41044_5-1-2.svg)


## CVE-2023-24057
 HL7 (Health Level 7) FHIR Core Libraries before 5.6.92 allow attackers to extract files into arbitrary directories via directory traversal from a crafted ZIP or TGZ archive (for a prepackaged terminology cache, NPM package, or comparison archive).

- [https://github.com/shoucheng3/hapifhir__org_hl7_fhir_core_CVE-2023-24057_5-6-91](https://github.com/shoucheng3/hapifhir__org_hl7_fhir_core_CVE-2023-24057_5-6-91) :  ![starts](https://img.shields.io/github/stars/shoucheng3/hapifhir__org_hl7_fhir_core_CVE-2023-24057_5-6-91.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/hapifhir__org_hl7_fhir_core_CVE-2023-24057_5-6-91.svg)


## CVE-2022-34662
 When users add resources to the resource center with a relation path will cause path traversal issues and only for logged-in users. You could upgrade to version 3.0.0 or higher

- [https://github.com/shoucheng3/apache__dolphinscheduler_CVE-2022-34662_2-0-9](https://github.com/shoucheng3/apache__dolphinscheduler_CVE-2022-34662_2-0-9) :  ![starts](https://img.shields.io/github/stars/shoucheng3/apache__dolphinscheduler_CVE-2022-34662_2-0-9.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/apache__dolphinscheduler_CVE-2022-34662_2-0-9.svg)


## CVE-2022-28367
 OWASP AntiSamy before 1.6.6 allows XSS via HTML tag smuggling on STYLE content with crafted input. The output serializer does not properly encode the supposed Cascading Style Sheets (CSS) content.

- [https://github.com/shoucheng3/nahsra__antisamy_CVE-2022-28367_1-6-5](https://github.com/shoucheng3/nahsra__antisamy_CVE-2022-28367_1-6-5) :  ![starts](https://img.shields.io/github/stars/shoucheng3/nahsra__antisamy_CVE-2022-28367_1-6-5.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/nahsra__antisamy_CVE-2022-28367_1-6-5.svg)


## CVE-2022-22932
 Apache Karaf obr:* commands and run goal on the karaf-maven-plugin have partial path traversal which allows to break out of expected folder. The risk is low as obr:* commands are not very used and the entry is set by user. This has been fixed in revision: https://gitbox.apache.org/repos/asf?p=karaf.git;h=36a2bc4 https://gitbox.apache.org/repos/asf?p=karaf.git;h=52b70cf Mitigation: Apache Karaf users should upgrade to 4.2.15 or 4.3.6 or later as soon as possible, or use correct path. JIRA Tickets: https://issues.apache.org/jira/browse/KARAF-7326

- [https://github.com/shoucheng3/asf__karaf_CVE-2022-22932_4-3-5](https://github.com/shoucheng3/asf__karaf_CVE-2022-22932_4-3-5) :  ![starts](https://img.shields.io/github/stars/shoucheng3/asf__karaf_CVE-2022-22932_4-3-5.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/asf__karaf_CVE-2022-22932_4-3-5.svg)


## CVE-2022-20617
 Jenkins Docker Commons Plugin 1.17 and earlier does not sanitize the name of an image or a tag, resulting in an OS command execution vulnerability exploitable by attackers with Item/Configure permission or able to control the contents of a previously configured job's SCM repository.

- [https://github.com/shoucheng3/jenkinsci__docker-commons-plugin_CVE-2022-20617_1-17](https://github.com/shoucheng3/jenkinsci__docker-commons-plugin_CVE-2022-20617_1-17) :  ![starts](https://img.shields.io/github/stars/shoucheng3/jenkinsci__docker-commons-plugin_CVE-2022-20617_1-17.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/jenkinsci__docker-commons-plugin_CVE-2022-20617_1-17.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/jxpsx/CVE-2022-0847-DirtyPipe-Exploits](https://github.com/jxpsx/CVE-2022-0847-DirtyPipe-Exploits) :  ![starts](https://img.shields.io/github/stars/jxpsx/CVE-2022-0847-DirtyPipe-Exploits.svg) ![forks](https://img.shields.io/github/forks/jxpsx/CVE-2022-0847-DirtyPipe-Exploits.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/charanvoonna/CVE-2021-41773](https://github.com/charanvoonna/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/charanvoonna/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/charanvoonna/CVE-2021-41773.svg)


## CVE-2019-17640
 In Eclipse Vert.x 3.4.x up to 3.9.4, 4.0.0.milestone1, 4.0.0.milestone2, 4.0.0.milestone3, 4.0.0.milestone4, 4.0.0.milestone5, 4.0.0.Beta1, 4.0.0.Beta2, and 4.0.0.Beta3, StaticHandler doesn't correctly processes back slashes on Windows Operating systems, allowing, escape the webroot folder to the current working directory.

- [https://github.com/shoucheng3/vert-x3__vertx-web_CVE-2019-17640_3-9-3](https://github.com/shoucheng3/vert-x3__vertx-web_CVE-2019-17640_3-9-3) :  ![starts](https://img.shields.io/github/stars/shoucheng3/vert-x3__vertx-web_CVE-2019-17640_3-9-3.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/vert-x3__vertx-web_CVE-2019-17640_3-9-3.svg)


## CVE-2019-10219
 A vulnerability was found in Hibernate-Validator. The SafeHtml validator annotation fails to properly sanitize payloads consisting of potentially malicious code in HTML comments and instructions. This vulnerability can result in an XSS attack.

- [https://github.com/shoucheng3/hibernate__hibernate-validator_CVE-2019-10219_6-0-17-Final](https://github.com/shoucheng3/hibernate__hibernate-validator_CVE-2019-10219_6-0-17-Final) :  ![starts](https://img.shields.io/github/stars/shoucheng3/hibernate__hibernate-validator_CVE-2019-10219_6-0-17-Final.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/hibernate__hibernate-validator_CVE-2019-10219_6-0-17-Final.svg)


## CVE-2018-1002203
 unzipper npm library before 0.8.13 is vulnerable to directory traversal, allowing attackers to write to arbitrary files via a ../ (dot dot slash) in a Zip archive entry that is mishandled during extraction. This vulnerability is also known as 'Zip-Slip'.

- [https://github.com/ossf-cve-benchmark/CVE-2018-1002203](https://github.com/ossf-cve-benchmark/CVE-2018-1002203) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2018-1002203.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2018-1002203.svg)


## CVE-2018-1002200
 plexus-archiver before 3.6.0 is vulnerable to directory traversal, allowing attackers to write to arbitrary files via a ../ (dot dot slash) in an archive entry that is mishandled during extraction. This vulnerability is also known as 'Zip-Slip'.

- [https://github.com/shoucheng3/codehaus-plexus__plexus-archiver_CVE-2018-1002200_3-5](https://github.com/shoucheng3/codehaus-plexus__plexus-archiver_CVE-2018-1002200_3-5) :  ![starts](https://img.shields.io/github/stars/shoucheng3/codehaus-plexus__plexus-archiver_CVE-2018-1002200_3-5.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/codehaus-plexus__plexus-archiver_CVE-2018-1002200_3-5.svg)


## CVE-2018-1000850
 Square Retrofit version versions from (including) 2.0 and 2.5.0 (excluding) contains a Directory Traversal vulnerability in RequestBuilder class, method addPathParameter that can result in By manipulating the URL an attacker could add or delete resources otherwise unavailable to her.. This attack appear to be exploitable via An attacker should have access to an encoded path parameter on POST, PUT or DELETE request.. This vulnerability appears to have been fixed in 2.5.0 and later.

- [https://github.com/shoucheng3/square__retrofit_CVE-2018-1000850_2-4-0](https://github.com/shoucheng3/square__retrofit_CVE-2018-1000850_2-4-0) :  ![starts](https://img.shields.io/github/stars/shoucheng3/square__retrofit_CVE-2018-1000850_2-4-0.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/square__retrofit_CVE-2018-1000850_2-4-0.svg)


## CVE-2018-1000096
 brianleroux tiny-json-http version all versions since commit 9b8e74a232bba4701844e07bcba794173b0238a8 (Oct 29 2016) contains a Missing SSL certificate validation vulnerability in The libraries core functionality is affected. that can result in Exposes the user to man-in-the-middle attacks.

- [https://github.com/ossf-cve-benchmark/CVE-2018-1000096](https://github.com/ossf-cve-benchmark/CVE-2018-1000096) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2018-1000096.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2018-1000096.svg)


## CVE-2018-20834
 A vulnerability was found in node-tar before version 4.4.2 (excluding version 2.2.2). An Arbitrary File Overwrite issue exists when extracting a tarball containing a hardlink to a file that already exists on the system, in conjunction with a later plain file with the same name as the hardlink. This plain file content replaces the existing file content. A patch has been applied to node-tar v2.2.2).

- [https://github.com/ossf-cve-benchmark/CVE-2018-20834](https://github.com/ossf-cve-benchmark/CVE-2018-20834) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2018-20834.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2018-20834.svg)


## CVE-2018-19592
 The "CLink4Service" service is installed with Corsair Link 4.9.7.35 with insecure permissions by default. This allows unprivileged users to take control of the service and execute commands in the context of NT AUTHORITY\SYSTEM, leading to total system takeover, a similar issue to CVE-2018-12441.

- [https://github.com/BradyDonovan/CVE-2018-19592](https://github.com/BradyDonovan/CVE-2018-19592) :  ![starts](https://img.shields.io/github/stars/BradyDonovan/CVE-2018-19592.svg) ![forks](https://img.shields.io/github/forks/BradyDonovan/CVE-2018-19592.svg)


## CVE-2018-19585
 GitLab CE/EE versions 8.18 up to 11.x before 11.3.11, 11.4.x before 11.4.8, and 11.5.x before 11.5.1 have CRLF Injection in Project Mirroring when using the Git protocol.

- [https://github.com/dotPY-hax/gitlab_RCE](https://github.com/dotPY-hax/gitlab_RCE) :  ![starts](https://img.shields.io/github/stars/dotPY-hax/gitlab_RCE.svg) ![forks](https://img.shields.io/github/forks/dotPY-hax/gitlab_RCE.svg)
- [https://github.com/Algafix/gitlab-RCE-11.4.7](https://github.com/Algafix/gitlab-RCE-11.4.7) :  ![starts](https://img.shields.io/github/stars/Algafix/gitlab-RCE-11.4.7.svg) ![forks](https://img.shields.io/github/forks/Algafix/gitlab-RCE-11.4.7.svg)
- [https://github.com/xenophil90/edb-49263-fixed](https://github.com/xenophil90/edb-49263-fixed) :  ![starts](https://img.shields.io/github/stars/xenophil90/edb-49263-fixed.svg) ![forks](https://img.shields.io/github/forks/xenophil90/edb-49263-fixed.svg)


## CVE-2018-19518
 University of Washington IMAP Toolkit 2007f on UNIX, as used in imap_open() in PHP and other products, launches an rsh command (by means of the imap_rimap function in c-client/imap4r1.c and the tcp_aopen function in osdep/unix/tcp_unix.c) without preventing argument injection, which might allow remote attackers to execute arbitrary OS commands if the IMAP server name is untrusted input (e.g., entered by a user of a web application) and if rsh has been replaced by a program with different argument semantics. For example, if rsh is a link to ssh (as seen on Debian and Ubuntu systems), then the attack can use an IMAP server name containing a "-oProxyCommand" argument.

- [https://github.com/houqe/EXP_CVE-2018-19518](https://github.com/houqe/EXP_CVE-2018-19518) :  ![starts](https://img.shields.io/github/stars/houqe/EXP_CVE-2018-19518.svg) ![forks](https://img.shields.io/github/forks/houqe/EXP_CVE-2018-19518.svg)
- [https://github.com/ensimag-security/CVE-2018-19518](https://github.com/ensimag-security/CVE-2018-19518) :  ![starts](https://img.shields.io/github/stars/ensimag-security/CVE-2018-19518.svg) ![forks](https://img.shields.io/github/forks/ensimag-security/CVE-2018-19518.svg)


## CVE-2018-19422
 /panel/uploads in Subrion CMS 4.2.1 allows remote attackers to execute arbitrary PHP code via a .pht or .phar file, because the .htaccess file omits these.

- [https://github.com/hev0x/CVE-2018-19422-SubrionCMS-RCE](https://github.com/hev0x/CVE-2018-19422-SubrionCMS-RCE) :  ![starts](https://img.shields.io/github/stars/hev0x/CVE-2018-19422-SubrionCMS-RCE.svg) ![forks](https://img.shields.io/github/forks/hev0x/CVE-2018-19422-SubrionCMS-RCE.svg)
- [https://github.com/Swammers8/SubrionCMS-4.2.1-File-upload-RCE-auth-](https://github.com/Swammers8/SubrionCMS-4.2.1-File-upload-RCE-auth-) :  ![starts](https://img.shields.io/github/stars/Swammers8/SubrionCMS-4.2.1-File-upload-RCE-auth-.svg) ![forks](https://img.shields.io/github/forks/Swammers8/SubrionCMS-4.2.1-File-upload-RCE-auth-.svg)
- [https://github.com/Drew-Alleman/CVE-2018-19422](https://github.com/Drew-Alleman/CVE-2018-19422) :  ![starts](https://img.shields.io/github/stars/Drew-Alleman/CVE-2018-19422.svg) ![forks](https://img.shields.io/github/forks/Drew-Alleman/CVE-2018-19422.svg)


## CVE-2018-19276
 OpenMRS before 2.24.0 is affected by an Insecure Object Deserialization vulnerability that allows an unauthenticated user to execute arbitrary commands on the targeted system via crafted XML data in a request body.

- [https://github.com/mpgn/CVE-2018-19276](https://github.com/mpgn/CVE-2018-19276) :  ![starts](https://img.shields.io/github/stars/mpgn/CVE-2018-19276.svg) ![forks](https://img.shields.io/github/forks/mpgn/CVE-2018-19276.svg)


## CVE-2018-16460
 A command Injection in ps package versions 1.0.0 for Node.js allowed arbitrary commands to be executed when attacker controls the PID.

- [https://github.com/ossf-cve-benchmark/CVE-2018-16460](https://github.com/ossf-cve-benchmark/CVE-2018-16460) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2018-16460.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2018-16460.svg)


## CVE-2018-16167
 LogonTracer 1.2.0 and earlier allows remote attackers to execute arbitrary OS commands via unspecified vectors.

- [https://github.com/dnr6419/CVE-2018-16167](https://github.com/dnr6419/CVE-2018-16167) :  ![starts](https://img.shields.io/github/stars/dnr6419/CVE-2018-16167.svg) ![forks](https://img.shields.io/github/forks/dnr6419/CVE-2018-16167.svg)


## CVE-2018-14665
 A flaw was found in xorg-x11-server before 1.20.3. An incorrect permission check for -modulepath and -logfile options when starting Xorg. X server allows unprivileged users with the ability to log in to the system via physical console to escalate their privileges and run arbitrary code under root privileges.

- [https://github.com/jas502n/CVE-2018-14665](https://github.com/jas502n/CVE-2018-14665) :  ![starts](https://img.shields.io/github/stars/jas502n/CVE-2018-14665.svg) ![forks](https://img.shields.io/github/forks/jas502n/CVE-2018-14665.svg)
- [https://github.com/bolonobolo/CVE-2018-14665](https://github.com/bolonobolo/CVE-2018-14665) :  ![starts](https://img.shields.io/github/stars/bolonobolo/CVE-2018-14665.svg) ![forks](https://img.shields.io/github/forks/bolonobolo/CVE-2018-14665.svg)


## CVE-2018-14042
 In Bootstrap before 4.1.2, XSS is possible in the data-container property of tooltip.

- [https://github.com/ossf-cve-benchmark/CVE-2018-14042](https://github.com/ossf-cve-benchmark/CVE-2018-14042) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2018-14042.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2018-14042.svg)
- [https://github.com/Snorlyd/https-nj.gov---CVE-2018-14042](https://github.com/Snorlyd/https-nj.gov---CVE-2018-14042) :  ![starts](https://img.shields.io/github/stars/Snorlyd/https-nj.gov---CVE-2018-14042.svg) ![forks](https://img.shields.io/github/forks/Snorlyd/https-nj.gov---CVE-2018-14042.svg)


## CVE-2018-12036
 OWASP Dependency-Check before 3.2.0 allows attackers to write to arbitrary files via a crafted archive that holds directory traversal filenames.

- [https://github.com/shoucheng3/jeremylong__DependencyCheck_CVE-2018-12036_3-1-2](https://github.com/shoucheng3/jeremylong__DependencyCheck_CVE-2018-12036_3-1-2) :  ![starts](https://img.shields.io/github/stars/shoucheng3/jeremylong__DependencyCheck_CVE-2018-12036_3-1-2.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/jeremylong__DependencyCheck_CVE-2018-12036_3-1-2.svg)


## CVE-2018-11770
 From version 1.3.0 onward, Apache Spark's standalone master exposes a REST API for job submission, in addition to the submission mechanism used by spark-submit. In standalone, the config property 'spark.authenticate.secret' establishes a shared secret for authenticating requests to submit jobs via spark-submit. However, the REST API does not use this or any other authentication mechanism, and this is not adequately documented. In this case, a user would be able to run a driver program without authenticating, but not launch executors, using the REST API. This REST API is also used by Mesos, when set up to run in cluster mode (i.e., when also running MesosClusterDispatcher), for job submission. Future versions of Spark will improve documentation on these points, and prohibit setting 'spark.authenticate.secret' when running the REST APIs, to make this clear. Future versions will also disable the REST API by default in the standalone master by changing the default value of 'spark.master.rest.enabled' to 'false'.

- [https://github.com/ivanitlearning/CVE-2018-11770](https://github.com/ivanitlearning/CVE-2018-11770) :  ![starts](https://img.shields.io/github/stars/ivanitlearning/CVE-2018-11770.svg) ![forks](https://img.shields.io/github/forks/ivanitlearning/CVE-2018-11770.svg)


## CVE-2018-11235
 In Git before 2.13.7, 2.14.x before 2.14.4, 2.15.x before 2.15.2, 2.16.x before 2.16.4, and 2.17.x before 2.17.1, remote code execution can occur. With a crafted .gitmodules file, a malicious project can execute an arbitrary script on a machine that runs "git clone --recurse-submodules" because submodule "names" are obtained from this file, and then appended to $GIT_DIR/modules, leading to directory traversal with "../" in a name. Finally, post-checkout hooks from a submodule are executed, bypassing the intended design in which hooks are not obtained from a remote server.

- [https://github.com/Rogdham/CVE-2018-11235](https://github.com/Rogdham/CVE-2018-11235) :  ![starts](https://img.shields.io/github/stars/Rogdham/CVE-2018-11235.svg) ![forks](https://img.shields.io/github/forks/Rogdham/CVE-2018-11235.svg)
- [https://github.com/CHYbeta/CVE-2018-11235-DEMO](https://github.com/CHYbeta/CVE-2018-11235-DEMO) :  ![starts](https://img.shields.io/github/stars/CHYbeta/CVE-2018-11235-DEMO.svg) ![forks](https://img.shields.io/github/forks/CHYbeta/CVE-2018-11235-DEMO.svg)
- [https://github.com/qweraqq/CVE-2018-11235-Git-Submodule-CE](https://github.com/qweraqq/CVE-2018-11235-Git-Submodule-CE) :  ![starts](https://img.shields.io/github/stars/qweraqq/CVE-2018-11235-Git-Submodule-CE.svg) ![forks](https://img.shields.io/github/forks/qweraqq/CVE-2018-11235-Git-Submodule-CE.svg)
- [https://github.com/j4k0m/CVE-2018-11235](https://github.com/j4k0m/CVE-2018-11235) :  ![starts](https://img.shields.io/github/stars/j4k0m/CVE-2018-11235.svg) ![forks](https://img.shields.io/github/forks/j4k0m/CVE-2018-11235.svg)
- [https://github.com/AnonymKing/CVE-2018-11235](https://github.com/AnonymKing/CVE-2018-11235) :  ![starts](https://img.shields.io/github/stars/AnonymKing/CVE-2018-11235.svg) ![forks](https://img.shields.io/github/forks/AnonymKing/CVE-2018-11235.svg)
- [https://github.com/ygouzerh/CVE-2018-11235](https://github.com/ygouzerh/CVE-2018-11235) :  ![starts](https://img.shields.io/github/stars/ygouzerh/CVE-2018-11235.svg) ![forks](https://img.shields.io/github/forks/ygouzerh/CVE-2018-11235.svg)
- [https://github.com/EmaVirgRep/CVE-2018-11235](https://github.com/EmaVirgRep/CVE-2018-11235) :  ![starts](https://img.shields.io/github/stars/EmaVirgRep/CVE-2018-11235.svg) ![forks](https://img.shields.io/github/forks/EmaVirgRep/CVE-2018-11235.svg)
- [https://github.com/dj-thd/cve2018-11235-exploit](https://github.com/dj-thd/cve2018-11235-exploit) :  ![starts](https://img.shields.io/github/stars/dj-thd/cve2018-11235-exploit.svg) ![forks](https://img.shields.io/github/forks/dj-thd/cve2018-11235-exploit.svg)
- [https://github.com/H0K5/clone_and_pwn](https://github.com/H0K5/clone_and_pwn) :  ![starts](https://img.shields.io/github/stars/H0K5/clone_and_pwn.svg) ![forks](https://img.shields.io/github/forks/H0K5/clone_and_pwn.svg)
- [https://github.com/knqyf263/CVE-2018-11235](https://github.com/knqyf263/CVE-2018-11235) :  ![starts](https://img.shields.io/github/stars/knqyf263/CVE-2018-11235.svg) ![forks](https://img.shields.io/github/forks/knqyf263/CVE-2018-11235.svg)
- [https://github.com/moajo/cve_2018_11235](https://github.com/moajo/cve_2018_11235) :  ![starts](https://img.shields.io/github/stars/moajo/cve_2018_11235.svg) ![forks](https://img.shields.io/github/forks/moajo/cve_2018_11235.svg)
- [https://github.com/0rx1/CVE-2018-11235](https://github.com/0rx1/CVE-2018-11235) :  ![starts](https://img.shields.io/github/stars/0rx1/CVE-2018-11235.svg) ![forks](https://img.shields.io/github/forks/0rx1/CVE-2018-11235.svg)
- [https://github.com/Choihosu/cve-2018-11235](https://github.com/Choihosu/cve-2018-11235) :  ![starts](https://img.shields.io/github/stars/Choihosu/cve-2018-11235.svg) ![forks](https://img.shields.io/github/forks/Choihosu/cve-2018-11235.svg)
- [https://github.com/vmotos/CVE-2018-11235](https://github.com/vmotos/CVE-2018-11235) :  ![starts](https://img.shields.io/github/stars/vmotos/CVE-2018-11235.svg) ![forks](https://img.shields.io/github/forks/vmotos/CVE-2018-11235.svg)
- [https://github.com/xElkomy/CVE-2018-11235](https://github.com/xElkomy/CVE-2018-11235) :  ![starts](https://img.shields.io/github/stars/xElkomy/CVE-2018-11235.svg) ![forks](https://img.shields.io/github/forks/xElkomy/CVE-2018-11235.svg)
- [https://github.com/nthuong95/CVE-2018-11235](https://github.com/nthuong95/CVE-2018-11235) :  ![starts](https://img.shields.io/github/stars/nthuong95/CVE-2018-11235.svg) ![forks](https://img.shields.io/github/forks/nthuong95/CVE-2018-11235.svg)
- [https://github.com/theerachaich/lab](https://github.com/theerachaich/lab) :  ![starts](https://img.shields.io/github/stars/theerachaich/lab.svg) ![forks](https://img.shields.io/github/forks/theerachaich/lab.svg)
- [https://github.com/cchang27/CVE-2018-11235-test](https://github.com/cchang27/CVE-2018-11235-test) :  ![starts](https://img.shields.io/github/stars/cchang27/CVE-2018-11235-test.svg) ![forks](https://img.shields.io/github/forks/cchang27/CVE-2018-11235-test.svg)
- [https://github.com/Kiss-sh0t/CVE-2018-11235-poc](https://github.com/Kiss-sh0t/CVE-2018-11235-poc) :  ![starts](https://img.shields.io/github/stars/Kiss-sh0t/CVE-2018-11235-poc.svg) ![forks](https://img.shields.io/github/forks/Kiss-sh0t/CVE-2018-11235-poc.svg)
- [https://github.com/MohamedTarekq/test-CVE-2018-11235](https://github.com/MohamedTarekq/test-CVE-2018-11235) :  ![starts](https://img.shields.io/github/stars/MohamedTarekq/test-CVE-2018-11235.svg) ![forks](https://img.shields.io/github/forks/MohamedTarekq/test-CVE-2018-11235.svg)
- [https://github.com/jongmartinez/CVE-2018-11235-PoC](https://github.com/jongmartinez/CVE-2018-11235-PoC) :  ![starts](https://img.shields.io/github/stars/jongmartinez/CVE-2018-11235-PoC.svg) ![forks](https://img.shields.io/github/forks/jongmartinez/CVE-2018-11235-PoC.svg)
- [https://github.com/twseptian/cve-2018-11235-git-submodule-ce-and-docker-ngrok-configuration](https://github.com/twseptian/cve-2018-11235-git-submodule-ce-and-docker-ngrok-configuration) :  ![starts](https://img.shields.io/github/stars/twseptian/cve-2018-11235-git-submodule-ce-and-docker-ngrok-configuration.svg) ![forks](https://img.shields.io/github/forks/twseptian/cve-2018-11235-git-submodule-ce-and-docker-ngrok-configuration.svg)


## CVE-2018-9159
 In Spark before 2.7.2, a remote attacker can read unintended static files via various representations of absolute or relative pathnames, as demonstrated by file: URLs and directory traversal sequences. NOTE: this product is unrelated to Ignite Realtime Spark.

- [https://github.com/shoucheng3/perwendel__spark_CVE-2018-9159_2-7-1](https://github.com/shoucheng3/perwendel__spark_CVE-2018-9159_2-7-1) :  ![starts](https://img.shields.io/github/stars/shoucheng3/perwendel__spark_CVE-2018-9159_2-7-1.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/perwendel__spark_CVE-2018-9159_2-7-1.svg)


## CVE-2018-8947
 rap2hpoutre Laravel Log Viewer before v0.13.0 relies on Base64 encoding for l, dl, and del requests, which makes it easier for remote attackers to bypass intended access restrictions, as demonstrated by reading arbitrary files via a dl request.

- [https://github.com/scopion/CVE-2018-8947](https://github.com/scopion/CVE-2018-8947) :  ![starts](https://img.shields.io/github/stars/scopion/CVE-2018-8947.svg) ![forks](https://img.shields.io/github/forks/scopion/CVE-2018-8947.svg)


## CVE-2018-7691
 A potential Remote Unauthorized Access in Micro Focus Fortify Software Security Center (SSC), versions 17.10, 17.20, 18.10 this exploitation could allow Remote Unauthorized Access

- [https://github.com/alt3kx/CVE-2018-7691](https://github.com/alt3kx/CVE-2018-7691) :  ![starts](https://img.shields.io/github/stars/alt3kx/CVE-2018-7691.svg) ![forks](https://img.shields.io/github/forks/alt3kx/CVE-2018-7691.svg)


## CVE-2018-7651
 index.js in the ssri module before 5.2.2 for Node.js is prone to a regular expression denial of service vulnerability in strict mode functionality via a long base64 hash string.

- [https://github.com/ossf-cve-benchmark/CVE-2018-7651](https://github.com/ossf-cve-benchmark/CVE-2018-7651) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2018-7651.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2018-7651.svg)


## CVE-2018-6892
 An issue was discovered in CloudMe before 1.11.0. An unauthenticated remote attacker that can connect to the "CloudMe Sync" client application listening on port 8888 can send a malicious payload causing a buffer overflow condition. This will result in an attacker controlling the program's execution flow and allowing arbitrary code execution.

- [https://github.com/latortuga71/CVE-2018-6892-Golang](https://github.com/latortuga71/CVE-2018-6892-Golang) :  ![starts](https://img.shields.io/github/stars/latortuga71/CVE-2018-6892-Golang.svg) ![forks](https://img.shields.io/github/forks/latortuga71/CVE-2018-6892-Golang.svg)
- [https://github.com/manojcode/-Win10-x64-CloudMe-Sync-1.10.9-Buffer-Overflow-SEH-DEP-Bypass](https://github.com/manojcode/-Win10-x64-CloudMe-Sync-1.10.9-Buffer-Overflow-SEH-DEP-Bypass) :  ![starts](https://img.shields.io/github/stars/manojcode/-Win10-x64-CloudMe-Sync-1.10.9-Buffer-Overflow-SEH-DEP-Bypass.svg) ![forks](https://img.shields.io/github/forks/manojcode/-Win10-x64-CloudMe-Sync-1.10.9-Buffer-Overflow-SEH-DEP-Bypass.svg)
- [https://github.com/manojcode/CloudMe-Sync-1.10.9---Buffer-Overflow-SEH-DEP-Bypass](https://github.com/manojcode/CloudMe-Sync-1.10.9---Buffer-Overflow-SEH-DEP-Bypass) :  ![starts](https://img.shields.io/github/stars/manojcode/CloudMe-Sync-1.10.9---Buffer-Overflow-SEH-DEP-Bypass.svg) ![forks](https://img.shields.io/github/forks/manojcode/CloudMe-Sync-1.10.9---Buffer-Overflow-SEH-DEP-Bypass.svg)


## CVE-2018-4878
 A use-after-free vulnerability was discovered in Adobe Flash Player before 28.0.0.161. This vulnerability occurs due to a dangling pointer in the Primetime SDK related to media player handling of listener objects. A successful attack can lead to arbitrary code execution. This was exploited in the wild in January and February 2018.

- [https://github.com/vysecurity/CVE-2018-4878](https://github.com/vysecurity/CVE-2018-4878) :  ![starts](https://img.shields.io/github/stars/vysecurity/CVE-2018-4878.svg) ![forks](https://img.shields.io/github/forks/vysecurity/CVE-2018-4878.svg)
- [https://github.com/mdsecactivebreach/CVE-2018-4878](https://github.com/mdsecactivebreach/CVE-2018-4878) :  ![starts](https://img.shields.io/github/stars/mdsecactivebreach/CVE-2018-4878.svg) ![forks](https://img.shields.io/github/forks/mdsecactivebreach/CVE-2018-4878.svg)
- [https://github.com/SyFi/CVE-2018-4878](https://github.com/SyFi/CVE-2018-4878) :  ![starts](https://img.shields.io/github/stars/SyFi/CVE-2018-4878.svg) ![forks](https://img.shields.io/github/forks/SyFi/CVE-2018-4878.svg)
- [https://github.com/B0fH/CVE-2018-4878](https://github.com/B0fH/CVE-2018-4878) :  ![starts](https://img.shields.io/github/stars/B0fH/CVE-2018-4878.svg) ![forks](https://img.shields.io/github/forks/B0fH/CVE-2018-4878.svg)
- [https://github.com/HuanWoWeiLan/SoftwareSystemSecurity-2019](https://github.com/HuanWoWeiLan/SoftwareSystemSecurity-2019) :  ![starts](https://img.shields.io/github/stars/HuanWoWeiLan/SoftwareSystemSecurity-2019.svg) ![forks](https://img.shields.io/github/forks/HuanWoWeiLan/SoftwareSystemSecurity-2019.svg)
- [https://github.com/ydl555/CVE-2018-4878-](https://github.com/ydl555/CVE-2018-4878-) :  ![starts](https://img.shields.io/github/stars/ydl555/CVE-2018-4878-.svg) ![forks](https://img.shields.io/github/forks/ydl555/CVE-2018-4878-.svg)
- [https://github.com/KathodeN/CVE-2018-4878](https://github.com/KathodeN/CVE-2018-4878) :  ![starts](https://img.shields.io/github/stars/KathodeN/CVE-2018-4878.svg) ![forks](https://img.shields.io/github/forks/KathodeN/CVE-2018-4878.svg)
- [https://github.com/demonsec666/CVE-2018-4878](https://github.com/demonsec666/CVE-2018-4878) :  ![starts](https://img.shields.io/github/stars/demonsec666/CVE-2018-4878.svg) ![forks](https://img.shields.io/github/forks/demonsec666/CVE-2018-4878.svg)
- [https://github.com/ydl555/CVE-2018-4878](https://github.com/ydl555/CVE-2018-4878) :  ![starts](https://img.shields.io/github/stars/ydl555/CVE-2018-4878.svg) ![forks](https://img.shields.io/github/forks/ydl555/CVE-2018-4878.svg)
- [https://github.com/Yable/CVE-2018-4878](https://github.com/Yable/CVE-2018-4878) :  ![starts](https://img.shields.io/github/stars/Yable/CVE-2018-4878.svg) ![forks](https://img.shields.io/github/forks/Yable/CVE-2018-4878.svg)
- [https://github.com/lvyoshino/CVE-2018-4878](https://github.com/lvyoshino/CVE-2018-4878) :  ![starts](https://img.shields.io/github/stars/lvyoshino/CVE-2018-4878.svg) ![forks](https://img.shields.io/github/forks/lvyoshino/CVE-2018-4878.svg)


## CVE-2018-4193
 An issue was discovered in certain Apple products. macOS before 10.13.5 is affected. The issue involves the "Windows Server" component. It allows attackers to execute arbitrary code in a privileged context or cause a denial of service (memory corruption) via a crafted app.

- [https://github.com/Synacktiv-contrib/CVE-2018-4193](https://github.com/Synacktiv-contrib/CVE-2018-4193) :  ![starts](https://img.shields.io/github/stars/Synacktiv-contrib/CVE-2018-4193.svg) ![forks](https://img.shields.io/github/forks/Synacktiv-contrib/CVE-2018-4193.svg)


## CVE-2017-1000487
 Plexus-utils before 3.0.16 is vulnerable to command injection because it does not correctly process the contents of double quoted strings.

- [https://github.com/shoucheng3/codehaus-plexus__plexus-utils_CVE-2017-1000487_3-0-15](https://github.com/shoucheng3/codehaus-plexus__plexus-utils_CVE-2017-1000487_3-0-15) :  ![starts](https://img.shields.io/github/stars/shoucheng3/codehaus-plexus__plexus-utils_CVE-2017-1000487_3-0-15.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/codehaus-plexus__plexus-utils_CVE-2017-1000487_3-0-15.svg)


## CVE-2017-18345
 The Joomanager component through 2.0.0 for Joomla! has an arbitrary file download issue, resulting in exposing the credentials of the database via an index.php?option=com_joomanager&controller=details&task=download&path=configuration.php request.

- [https://github.com/Luth1er/CVE-2017-18345-COM_JOOMANAGER-ARBITRARY-FILE-DOWNLOAD](https://github.com/Luth1er/CVE-2017-18345-COM_JOOMANAGER-ARBITRARY-FILE-DOWNLOAD) :  ![starts](https://img.shields.io/github/stars/Luth1er/CVE-2017-18345-COM_JOOMANAGER-ARBITRARY-FILE-DOWNLOAD.svg) ![forks](https://img.shields.io/github/forks/Luth1er/CVE-2017-18345-COM_JOOMANAGER-ARBITRARY-FILE-DOWNLOAD.svg)


## CVE-2017-14735
 OWASP AntiSamy before 1.5.7 allows XSS via HTML5 entities, as demonstrated by use of &colon; to construct a javascript: URL.

- [https://github.com/shoucheng3/nahsra__antisamy_CVE-2017-14735_1-5-6](https://github.com/shoucheng3/nahsra__antisamy_CVE-2017-14735_1-5-6) :  ![starts](https://img.shields.io/github/stars/shoucheng3/nahsra__antisamy_CVE-2017-14735_1-5-6.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/nahsra__antisamy_CVE-2017-14735_1-5-6.svg)


## CVE-2017-8869
 Buffer overflow in MediaCoder 0.8.48.5888 allows remote attackers to execute arbitrary code via a crafted .m3u file.

- [https://github.com/tankist0x01/CVE-2017-8869](https://github.com/tankist0x01/CVE-2017-8869) :  ![starts](https://img.shields.io/github/stars/tankist0x01/CVE-2017-8869.svg) ![forks](https://img.shields.io/github/forks/tankist0x01/CVE-2017-8869.svg)


## CVE-2017-8798
 Integer signedness error in MiniUPnP MiniUPnPc v1.4.20101221 through v2.0 allows remote attackers to cause a denial of service or possibly have unspecified other impact.

- [https://github.com/tintinweb/pub](https://github.com/tintinweb/pub) :  ![starts](https://img.shields.io/github/stars/tintinweb/pub.svg) ![forks](https://img.shields.io/github/forks/tintinweb/pub.svg)


## CVE-2017-1624
 IBM QRadar 7.3 and 7.3.1 specifies permissions for a security-critical resource in a way that allows that resource to be read or modified by unintended actors. IBM X-Force ID: 133122.

- [https://github.com/AOCorsaire/CVE-2017-16245](https://github.com/AOCorsaire/CVE-2017-16245) :  ![starts](https://img.shields.io/github/stars/AOCorsaire/CVE-2017-16245.svg) ![forks](https://img.shields.io/github/forks/AOCorsaire/CVE-2017-16245.svg)


## CVE-2017-1608
 IBM Rational Quality Manager and IBM Rational Collaborative Lifecycle Management 5.0 through 5.0.2 and 6.0 through 6.0.5 are vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 132928.

- [https://github.com/ossf-cve-benchmark/CVE-2017-16087](https://github.com/ossf-cve-benchmark/CVE-2017-16087) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16087.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16087.svg)


## CVE-2017-1235
 IBM WebSphere MQ 8.0 could allow an authenticated user to cause a premature termination of a client application thread which could potentially cause denial of service. IBM X-Force ID: 123914.

- [https://github.com/11k4r/CVE-2017-1235_exploit](https://github.com/11k4r/CVE-2017-1235_exploit) :  ![starts](https://img.shields.io/github/stars/11k4r/CVE-2017-1235_exploit.svg) ![forks](https://img.shields.io/github/forks/11k4r/CVE-2017-1235_exploit.svg)


## CVE-2017-1079
 DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was in a CNA pool that was not assigned to any issues during 2017. Notes: none

- [https://github.com/n4xh4ck5/CVE-2017-10797](https://github.com/n4xh4ck5/CVE-2017-10797) :  ![starts](https://img.shields.io/github/stars/n4xh4ck5/CVE-2017-10797.svg) ![forks](https://img.shields.io/github/forks/n4xh4ck5/CVE-2017-10797.svg)


## CVE-2015-8543
 The networking implementation in the Linux kernel through 4.3.3, as used in Android and other products, does not validate protocol identifiers for certain protocol families, which allows local users to cause a denial of service (NULL function pointer dereference and system crash) or possibly gain privileges by leveraging CLONE_NEWUSER support to execute a crafted SOCK_RAW application.

- [https://github.com/bittorrent3389/CVE-2015-8543_for_SLE12SP1](https://github.com/bittorrent3389/CVE-2015-8543_for_SLE12SP1) :  ![starts](https://img.shields.io/github/stars/bittorrent3389/CVE-2015-8543_for_SLE12SP1.svg) ![forks](https://img.shields.io/github/forks/bittorrent3389/CVE-2015-8543_for_SLE12SP1.svg)


## CVE-2014-7816
 Directory traversal vulnerability in JBoss Undertow 1.0.x before 1.0.17, 1.1.x before 1.1.0.CR5, and 1.2.x before 1.2.0.Beta3, when running on Windows, allows remote attackers to read arbitrary files via a .. (dot dot) in a resource URI.

- [https://github.com/shoucheng3/undertow-io__undertow_CVE-2014-7816_1-0-16-Final](https://github.com/shoucheng3/undertow-io__undertow_CVE-2014-7816_1-0-16-Final) :  ![starts](https://img.shields.io/github/stars/shoucheng3/undertow-io__undertow_CVE-2014-7816_1-0-16-Final.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/undertow-io__undertow_CVE-2014-7816_1-0-16-Final.svg)


## CVE-2014-4725
 The MailPoet Newsletters (wysija-newsletters) plugin before 2.6.7 for WordPress allows remote attackers to bypass authentication and execute arbitrary PHP code by uploading a crafted theme using wp-admin/admin-post.php and accessing the theme in wp-content/uploads/wysija/themes/mailp/.

- [https://github.com/pwdnx337/CVE-2014-4725](https://github.com/pwdnx337/CVE-2014-4725) :  ![starts](https://img.shields.io/github/stars/pwdnx337/CVE-2014-4725.svg) ![forks](https://img.shields.io/github/forks/pwdnx337/CVE-2014-4725.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/seerat-fatima21/vsftpd-exploit](https://github.com/seerat-fatima21/vsftpd-exploit) :  ![starts](https://img.shields.io/github/stars/seerat-fatima21/vsftpd-exploit.svg) ![forks](https://img.shields.io/github/forks/seerat-fatima21/vsftpd-exploit.svg)

