# Update 2025-08-20
## CVE-2025-55160
 ImageMagick is free and open-source software used for editing and manipulating digital images. Prior to versions 6.9.13-27 and 7.1.2-1, there is undefined behavior (function-type-mismatch) in splay tree cloning callback. This results in a deterministic abort under UBSan (DoS in sanitizer builds), with no crash in a non-sanitized build. This issue has been patched in versions 6.9.13-27 and 7.1.2-1.

- [https://github.com/Yuri08loveElaina/imagemagick-2025-poc](https://github.com/Yuri08loveElaina/imagemagick-2025-poc) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/imagemagick-2025-poc.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/imagemagick-2025-poc.svg)


## CVE-2025-55154
 ImageMagick is free and open-source software used for editing and manipulating digital images. Prior to versions 6.9.13-27 and 7.1.2-1, the magnified size calculations in ReadOneMNGIMage (in coders/png.c) are unsafe and can overflow, leading to memory corruption. This issue has been patched in versions 6.9.13-27 and 7.1.2-1.

- [https://github.com/Yuri08loveElaina/imagemagick-2025-poc](https://github.com/Yuri08loveElaina/imagemagick-2025-poc) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/imagemagick-2025-poc.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/imagemagick-2025-poc.svg)


## CVE-2025-55005
 ImageMagick is free and open-source software used for editing and manipulating digital images. Prior to version 7.1.2-1, when preparing to transform from Log to sRGB colorspaces, the logmap construction fails to handle cases where the reference-black or reference-white value is larger than 1024. This leads to corrupting memory beyond the end of the allocated logmap buffer. This issue has been patched in version 7.1.2-1.

- [https://github.com/Yuri08loveElaina/imagemagick-2025-poc](https://github.com/Yuri08loveElaina/imagemagick-2025-poc) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/imagemagick-2025-poc.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/imagemagick-2025-poc.svg)


## CVE-2025-55004
 ImageMagick is free and open-source software used for editing and manipulating digital images. Prior to version 7.1.2-1, ImageMagick is vulnerable to heap-buffer overflow read around the handling of images with separate alpha channels when performing image magnification in ReadOneMNGIMage. This can likely be used to leak subsequent memory contents into the output image. This issue has been patched in version 7.1.2-1.

- [https://github.com/Yuri08loveElaina/imagemagick-2025-poc](https://github.com/Yuri08loveElaina/imagemagick-2025-poc) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/imagemagick-2025-poc.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/imagemagick-2025-poc.svg)


## CVE-2025-49132
 Pterodactyl is a free, open-source game server management panel. Prior to version 1.11.11, using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated. With the ability to execute arbitrary code it could be used to gain access to the Panel's server, read credentials from the Panel's config, extract sensitive information from the database, access files of servers managed by the panel, etc. This issue has been patched in version 1.11.11. There are no software workarounds for this vulnerability, but use of an external Web Application Firewall (WAF) could help mitigate this attack.

- [https://github.com/GRodolphe/CVE-2025-49132_poc](https://github.com/GRodolphe/CVE-2025-49132_poc) :  ![starts](https://img.shields.io/github/stars/GRodolphe/CVE-2025-49132_poc.svg) ![forks](https://img.shields.io/github/forks/GRodolphe/CVE-2025-49132_poc.svg)


## CVE-2025-49113
 Roundcube Webmail before 1.5.10 and 1.6.x before 1.6.11 allows remote code execution by authenticated users because the _from parameter in a URL is not validated in program/actions/settings/upload.php, leading to PHP Object Deserialization.

- [https://github.com/CyberQuestor-infosec/CVE-2025-49113-Roundcube_1.6.10](https://github.com/CyberQuestor-infosec/CVE-2025-49113-Roundcube_1.6.10) :  ![starts](https://img.shields.io/github/stars/CyberQuestor-infosec/CVE-2025-49113-Roundcube_1.6.10.svg) ![forks](https://img.shields.io/github/forks/CyberQuestor-infosec/CVE-2025-49113-Roundcube_1.6.10.svg)


## CVE-2025-26788
 StrongKey FIDO Server before 4.15.1 treats a non-discoverable (namedcredential) flow as a discoverable transaction.

- [https://github.com/EQSTLab/CVE-2025-26788](https://github.com/EQSTLab/CVE-2025-26788) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2025-26788.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2025-26788.svg)


## CVE-2025-25063
 An XSS issue was discovered in Backdrop CMS 1.28.x before 1.28.5 and 1.29.x before 1.29.3. It does not sufficiently validate uploaded SVG images to ensure they do not contain potentially dangerous SVG tags. SVG images can contain clickable links and executable scripting, and using a crafted SVG, it is possible to execute scripting in the browser when an SVG image is viewed. This issue is mitigated by the attacker needing to be able to upload SVG images, and that Backdrop embeds all uploaded SVG images within &lt;img&gt; tags, which prevents scripting from executing. The SVG must be viewed directly by its URL in order to run any embedded scripting.

- [https://github.com/moften/CVE-2025-8671-MadeYouReset-HTTP-2-DDoS](https://github.com/moften/CVE-2025-8671-MadeYouReset-HTTP-2-DDoS) :  ![starts](https://img.shields.io/github/stars/moften/CVE-2025-8671-MadeYouReset-HTTP-2-DDoS.svg) ![forks](https://img.shields.io/github/forks/moften/CVE-2025-8671-MadeYouReset-HTTP-2-DDoS.svg)


## CVE-2025-8671
 A mismatch caused by client-triggered server-sent stream resets between HTTP/2 specifications and the internal architectures of some HTTP/2 implementations may result in excessive server resource consumption leading to denial-of-service (DoS).  By opening streams and then rapidly triggering the server to reset them—using malformed frames or flow control errors—an attacker can exploit incorrect stream accounting. Streams reset by the server are considered closed at the protocol level, even though backend processing continues. This allows a client to cause the server to handle an unbounded number of concurrent streams on a single connection. This CVE will be updated as affected product details are released.

- [https://github.com/moften/CVE-2025-8671-MadeYouReset-HTTP-2-DDoS](https://github.com/moften/CVE-2025-8671-MadeYouReset-HTTP-2-DDoS) :  ![starts](https://img.shields.io/github/stars/moften/CVE-2025-8671-MadeYouReset-HTTP-2-DDoS.svg) ![forks](https://img.shields.io/github/forks/moften/CVE-2025-8671-MadeYouReset-HTTP-2-DDoS.svg)


## CVE-2025-8517
 A vulnerability was detected in givanz Vvveb 1.0.6.1. Impacted is an unknown function. The manipulation results in session fixiation. The attack can be launched remotely. The exploit is now public and may be used. Upgrading to version 1.0.7 is recommended to address this issue. The patch is identified as d4b1e030066417b77d15b4ac505eed5ae7bf2c5e. You should upgrade the affected component.

- [https://github.com/kwerty138/Session-Fixation-in-Vvveb-CMS-v1.0.6.1](https://github.com/kwerty138/Session-Fixation-in-Vvveb-CMS-v1.0.6.1) :  ![starts](https://img.shields.io/github/stars/kwerty138/Session-Fixation-in-Vvveb-CMS-v1.0.6.1.svg) ![forks](https://img.shields.io/github/forks/kwerty138/Session-Fixation-in-Vvveb-CMS-v1.0.6.1.svg)


## CVE-2025-7771
 ThrottleStop.sys, a legitimate driver, exposes two IOCTL interfaces that allow arbitrary read and write access to physical memory via the MmMapIoSpace function. This insecure implementation can be exploited by a malicious user-mode application to patch the running Windows kernel and invoke arbitrary kernel functions with ring-0 privileges. The vulnerability enables local attackers to execute arbitrary code in kernel context, resulting in privilege escalation and potential follow-on attacks, such as disabling security software or bypassing kernel-level protections. ThrottleStop.sys version 3.0.0.0 and possibly others are affected. Apply updates per vendor instructions.

- [https://github.com/Yuri08loveElaina/CVE-2025-7771](https://github.com/Yuri08loveElaina/CVE-2025-7771) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE-2025-7771.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE-2025-7771.svg)


## CVE-2025-4334
 The Simple User Registration plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 6.3. This is due to insufficient restrictions on user meta values that can be supplied during registration. This makes it possible for unauthenticated attackers to register as an administrator.

- [https://github.com/0xgh057r3c0n/CVE-2025-4334](https://github.com/0xgh057r3c0n/CVE-2025-4334) :  ![starts](https://img.shields.io/github/stars/0xgh057r3c0n/CVE-2025-4334.svg) ![forks](https://img.shields.io/github/forks/0xgh057r3c0n/CVE-2025-4334.svg)


## CVE-2024-28397
 An issue in the component js2py.disable_pyimport() of js2py up to v0.74 allows attackers to execute arbitrary code via a crafted API call.

- [https://github.com/harutomo-jp/CVE-2024-28397-RCE](https://github.com/harutomo-jp/CVE-2024-28397-RCE) :  ![starts](https://img.shields.io/github/stars/harutomo-jp/CVE-2024-28397-RCE.svg) ![forks](https://img.shields.io/github/forks/harutomo-jp/CVE-2024-28397-RCE.svg)


## CVE-2024-0520
 A vulnerability in mlflow/mlflow version 8.2.1 allows for remote code execution due to improper neutralization of special elements used in an OS command ('Command Injection') within the `mlflow.data.http_dataset_source.py` module. Specifically, when loading a dataset from a source URL with an HTTP scheme, the filename extracted from the `Content-Disposition` header or the URL path is used to generate the final file path without proper sanitization. This flaw enables an attacker to control the file path fully by utilizing path traversal or absolute path techniques, such as '../../tmp/poc.txt' or '/tmp/poc.txt', leading to arbitrary file write. Exploiting this vulnerability could allow a malicious user to execute commands on the vulnerable machine, potentially gaining access to data and model information. The issue is fixed in version 2.9.0.

- [https://github.com/chan-068/CVE-2024-0520_try](https://github.com/chan-068/CVE-2024-0520_try) :  ![starts](https://img.shields.io/github/stars/chan-068/CVE-2024-0520_try.svg) ![forks](https://img.shields.io/github/forks/chan-068/CVE-2024-0520_try.svg)


## CVE-2023-35887
This issue affects Apache MINA: from 1.0 before 2.10. Users are recommended to upgrade to 2.10

- [https://github.com/shoucheng3/apache__mina-sshd_CVE-2023-35887_2-9-2](https://github.com/shoucheng3/apache__mina-sshd_CVE-2023-35887_2-9-2) :  ![starts](https://img.shields.io/github/stars/shoucheng3/apache__mina-sshd_CVE-2023-35887_2-9-2.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/apache__mina-sshd_CVE-2023-35887_2-9-2.svg)


## CVE-2023-33962
Version 1.0.1 contains a patch for this issue. To mitigate this vulnerability, the template engine should properly escape special characters, including single quotes. Common practice is to escape `'` as `&#39`. As a workaround, users can avoid this issue by using only double quotes `"` for HTML attributes.

- [https://github.com/shoucheng3/jstachio__jstachio_CVE-2023-33962_1-0-0](https://github.com/shoucheng3/jstachio__jstachio_CVE-2023-33962_1-0-0) :  ![starts](https://img.shields.io/github/stars/shoucheng3/jstachio__jstachio_CVE-2023-33962_1-0-0.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/jstachio__jstachio_CVE-2023-33962_1-0-0.svg)


## CVE-2023-24422
 A sandbox bypass vulnerability involving map constructors in Jenkins Script Security Plugin 1228.vd93135a_2fb_25 and earlier allows attackers with permission to define and run sandboxed scripts, including Pipelines, to bypass the sandbox protection and execute arbitrary code in the context of the Jenkins controller JVM.

- [https://github.com/shoucheng3/jenkinsci__script-security-plugin_CVE-2023-24422_1228.vd93135a_2fb_25](https://github.com/shoucheng3/jenkinsci__script-security-plugin_CVE-2023-24422_1228.vd93135a_2fb_25) :  ![starts](https://img.shields.io/github/stars/shoucheng3/jenkinsci__script-security-plugin_CVE-2023-24422_1228.vd93135a_2fb_25.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/jenkinsci__script-security-plugin_CVE-2023-24422_1228.vd93135a_2fb_25.svg)


## CVE-2023-23752
 An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

- [https://github.com/0xVoodoo/PoCs](https://github.com/0xVoodoo/PoCs) :  ![starts](https://img.shields.io/github/stars/0xVoodoo/PoCs.svg) ![forks](https://img.shields.io/github/forks/0xVoodoo/PoCs.svg)


## CVE-2022-31194
 DSpace open source software is a repository application which provides durable access to digital resources. dspace-jspui is a UI component for DSpace. The JSPUI resumable upload implementations in SubmissionController and FileUploadRequest are vulnerable to multiple path traversal attacks, allowing an attacker to create files/directories anywhere on the server writable by the Tomcat/DSpace user, by modifying some request parameters during submission. This path traversal can only be executed by a user with special privileges (submitter rights). This vulnerability only impacts the JSPUI. Users are advised to upgrade. There are no known workarounds. However, this vulnerability cannot be exploited by an anonymous user or a basic user. The user must first have submitter privileges to at least one Collection and be able to determine how to modify the request parameters to exploit the vulnerability.

- [https://github.com/shoucheng3/DSpace__DSpace_CVE-2022-31194_5-10](https://github.com/shoucheng3/DSpace__DSpace_CVE-2022-31194_5-10) :  ![starts](https://img.shields.io/github/stars/shoucheng3/DSpace__DSpace_CVE-2022-31194_5-10.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/DSpace__DSpace_CVE-2022-31194_5-10.svg)


## CVE-2022-31159
 The AWS SDK for Java enables Java developers to work with Amazon Web Services. A partial-path traversal issue exists within the `downloadDirectory` method in the AWS S3 TransferManager component of the AWS SDK for Java v1 prior to version 1.12.261. Applications using the SDK control the `destinationDirectory` argument, but S3 object keys are determined by the application that uploaded the objects. The `downloadDirectory` method allows the caller to pass a filesystem object in the object key but contained an issue in the validation logic for the key name. A knowledgeable actor could bypass the validation logic by including a UNIX double-dot in the bucket key. Under certain conditions, this could permit them to retrieve a directory from their S3 bucket that is one level up in the filesystem from their working directory. This issue’s scope is limited to directories whose name prefix matches the destinationDirectory. E.g. for destination directory`/tmp/foo`, the actor can cause a download to `/tmp/foo-bar`, but not `/tmp/bar`. If `com.amazonaws.services.s3.transfer.TransferManager::downloadDirectory` is used to download an untrusted buckets contents, the contents of that bucket can be written outside of the intended destination directory. Version 1.12.261 contains a patch for this issue. As a workaround, when calling `com.amazonaws.services.s3.transfer.TransferManager::downloadDirectory`, pass a `KeyFilter` that forbids `S3ObjectSummary` objects that `getKey` method return a string containing the substring `..` .

- [https://github.com/shoucheng3/aws__aws-sdk-java_CVE-2022-31159_1-12-260](https://github.com/shoucheng3/aws__aws-sdk-java_CVE-2022-31159_1-12-260) :  ![starts](https://img.shields.io/github/stars/shoucheng3/aws__aws-sdk-java_CVE-2022-31159_1-12-260.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/aws__aws-sdk-java_CVE-2022-31159_1-12-260.svg)


## CVE-2022-25174
 Jenkins Pipeline: Shared Groovy Libraries Plugin 552.vd9cc05b8a2e1 and earlier uses the same checkout directories for distinct SCMs for Pipeline libraries, allowing attackers with Item/Configure permission to invoke arbitrary OS commands on the controller through crafted SCM contents.

- [https://github.com/shoucheng3/jenkinsci__workflow-cps-global-lib-plugin_CVE-2022-25174_544-vff04fa68714d](https://github.com/shoucheng3/jenkinsci__workflow-cps-global-lib-plugin_CVE-2022-25174_544-vff04fa68714d) :  ![starts](https://img.shields.io/github/stars/shoucheng3/jenkinsci__workflow-cps-global-lib-plugin_CVE-2022-25174_544-vff04fa68714d.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/jenkinsci__workflow-cps-global-lib-plugin_CVE-2022-25174_544-vff04fa68714d.svg)


## CVE-2022-24897
 APIs to evaluate content with Velocity is a package for APIs to evaluate content with Velocity. Starting with version 2.3 and prior to 12.6.7, 12.10.3, and 13.0, the velocity scripts are not properly sandboxed against using the Java File API to perform read or write operations on the filesystem. Writing an attacking script in Velocity requires the Script rights in XWiki so not all users can use it, and it also requires finding an XWiki API which returns a File. The problem has been patched in versions 12.6.7, 12.10.3, and 13.0. There is no easy workaround for fixing this vulnerability other than upgrading and being careful when giving Script rights.

- [https://github.com/shoucheng3/xwiki__xwiki-commons_CVE-2022-24897_12-6-6](https://github.com/shoucheng3/xwiki__xwiki-commons_CVE-2022-24897_12-6-6) :  ![starts](https://img.shields.io/github/stars/shoucheng3/xwiki__xwiki-commons_CVE-2022-24897_12-6-6.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/xwiki__xwiki-commons_CVE-2022-24897_12-6-6.svg)


## CVE-2022-4137
 A reflected cross-site scripting (XSS) vulnerability was found in the 'oob' OAuth endpoint due to incorrect null-byte handling. This issue allows a malicious link to insert an arbitrary URI into a Keycloak error page. This flaw requires a user or administrator to interact with a link in order to be vulnerable. This may compromise user details, allowing it to be changed or collected by an attacker.

- [https://github.com/shoucheng3/keycloak__keycloak_CVE-2022-4137_20-0-3](https://github.com/shoucheng3/keycloak__keycloak_CVE-2022-4137_20-0-3) :  ![starts](https://img.shields.io/github/stars/shoucheng3/keycloak__keycloak_CVE-2022-4137_20-0-3.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/keycloak__keycloak_CVE-2022-4137_20-0-3.svg)


## CVE-2022-1274
 A flaw was found in Keycloak in the execute-actions-email endpoint. This issue allows arbitrary HTML to be injected into emails sent to Keycloak users and can be misused to perform phishing or other attacks against users.

- [https://github.com/shoucheng3/keycloak__keycloak_CVE-2022-1274_20-0-3](https://github.com/shoucheng3/keycloak__keycloak_CVE-2022-1274_20-0-3) :  ![starts](https://img.shields.io/github/stars/shoucheng3/keycloak__keycloak_CVE-2022-1274_20-0-3.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/keycloak__keycloak_CVE-2022-1274_20-0-3.svg)


## CVE-2021-30180
 Apache Dubbo prior to 2.7.9 support Tag routing which will enable a customer to route the request to the right server. These rules are used by the customers when making a request in order to find the right endpoint. When parsing these YAML rules, Dubbo customers may enable calling arbitrary constructors.

- [https://github.com/shoucheng3/apache__dubbo_CVE-2021-30180_2-7-9](https://github.com/shoucheng3/apache__dubbo_CVE-2021-30180_2-7-9) :  ![starts](https://img.shields.io/github/stars/shoucheng3/apache__dubbo_CVE-2021-30180_2-7-9.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/apache__dubbo_CVE-2021-30180_2-7-9.svg)


## CVE-2020-36708
 The following themes for WordPress are vulnerable to Function Injections in versions up to and including Shapely = 1.2.7, NewsMag = 2.4.1, Activello = 1.4.0, Illdy = 2.1.4, Allegiant = 1.2.2, Newspaper X = 1.3.1, Pixova Lite = 2.0.5, Brilliance = 1.2.7, MedZone Lite = 1.2.4, Regina Lite = 2.0.4, Transcend = 1.1.8, Affluent = 1.1.0, Bonkers = 1.0.4, Antreas = 1.0.2, Sparkling = 2.4.8, and NatureMag Lite = 1.0.4. This is due to epsilon_framework_ajax_action. This makes it possible for unauthenticated attackers to call functions and achieve remote code execution.

- [https://github.com/b1g-b33f/CVE-2020-36708](https://github.com/b1g-b33f/CVE-2020-36708) :  ![starts](https://img.shields.io/github/stars/b1g-b33f/CVE-2020-36708.svg) ![forks](https://img.shields.io/github/forks/b1g-b33f/CVE-2020-36708.svg)


## CVE-2019-17573
 By default, Apache CXF creates a /services page containing a listing of the available endpoint names and addresses. This webpage is vulnerable to a reflected Cross-Site Scripting (XSS) attack, which allows a malicious actor to inject javascript into the web page. Please note that the attack exploits a feature which is not typically not present in modern browsers, who remove dot segments before sending the request. However, Mobile applications may be vulnerable.

- [https://github.com/shoucheng3/asf__cxf_CVE-2019-17573_3-2-11](https://github.com/shoucheng3/asf__cxf_CVE-2019-17573_3-2-11) :  ![starts](https://img.shields.io/github/stars/shoucheng3/asf__cxf_CVE-2019-17573_3-2-11.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/asf__cxf_CVE-2019-17573_3-2-11.svg)


## CVE-2019-10078
 A carefully crafted plugin link invocation could trigger an XSS vulnerability on Apache JSPWiki 2.9.0 to 2.11.0.M3, which could lead to session hijacking. Initial reporting indicated ReferredPagesPlugin, but further analysis showed that multiple plugins were vulnerable.

- [https://github.com/shoucheng3/apache__jspwiki_CVE-2019-10078_2-11-0-M3](https://github.com/shoucheng3/apache__jspwiki_CVE-2019-10078_2-11-0-M3) :  ![starts](https://img.shields.io/github/stars/shoucheng3/apache__jspwiki_CVE-2019-10078_2-11-0-M3.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/apache__jspwiki_CVE-2019-10078_2-11-0-M3.svg)


## CVE-2019-10077
 A carefully crafted InterWiki link could trigger an XSS vulnerability on Apache JSPWiki 2.9.0 to 2.11.0.M3, which could lead to session hijacking.

- [https://github.com/shoucheng3/apache__jspwiki_CVE-2019-10077_2-11-0-M3](https://github.com/shoucheng3/apache__jspwiki_CVE-2019-10077_2-11-0-M3) :  ![starts](https://img.shields.io/github/stars/shoucheng3/apache__jspwiki_CVE-2019-10077_2-11-0-M3.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/apache__jspwiki_CVE-2019-10077_2-11-0-M3.svg)


## CVE-2019-5688
 NVIDIA NVFlash, NVUFlash Tool prior to v5.588.0 and GPUModeSwitch Tool prior to 2019-11, NVIDIA kernel mode driver (nvflash.sys, nvflsh32.sys, and nvflsh64.sys) contains a vulnerability in which authenticated users with administrative privileges can gain access to device memory and registers of other devices not managed by NVIDIA, which may lead to escalation of privileges, information disclosure, or denial of service.

- [https://github.com/watsa01/CVE-2019-5688](https://github.com/watsa01/CVE-2019-5688) :  ![starts](https://img.shields.io/github/stars/watsa01/CVE-2019-5688.svg) ![forks](https://img.shields.io/github/forks/watsa01/CVE-2019-5688.svg)


## CVE-2018-1002202
 zip4j before 1.3.3 is vulnerable to directory traversal, allowing attackers to write to arbitrary files via a ../ (dot dot slash) in a Zip archive entry that is mishandled during extraction. This vulnerability is also known as 'Zip-Slip'.

- [https://github.com/shoucheng3/srikanth-lingala__zip4j_CVE-2018-1002202_1-3-2](https://github.com/shoucheng3/srikanth-lingala__zip4j_CVE-2018-1002202_1-3-2) :  ![starts](https://img.shields.io/github/stars/shoucheng3/srikanth-lingala__zip4j_CVE-2018-1002202_1-3-2.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/srikanth-lingala__zip4j_CVE-2018-1002202_1-3-2.svg)


## CVE-2018-1002201
 zt-zip before 1.13 is vulnerable to directory traversal, allowing attackers to write to arbitrary files via a ../ (dot dot slash) in a Zip archive entry that is mishandled during extraction. This vulnerability is also known as 'Zip-Slip'.

- [https://github.com/shoucheng3/zeroturnaround__zt-zip_CVE-2018-1002201_1-12](https://github.com/shoucheng3/zeroturnaround__zt-zip_CVE-2018-1002201_1-12) :  ![starts](https://img.shields.io/github/stars/shoucheng3/zeroturnaround__zt-zip_CVE-2018-1002201_1-12.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/zeroturnaround__zt-zip_CVE-2018-1002201_1-12.svg)


## CVE-2018-17297
 The unzip function in ZipUtil.java in Hutool before 4.1.12 allows remote attackers to overwrite arbitrary files via directory traversal sequences in a filename within a ZIP archive.

- [https://github.com/shoucheng3/dromara__hutool_CVE-2018-17297_4-1-11](https://github.com/shoucheng3/dromara__hutool_CVE-2018-17297_4-1-11) :  ![starts](https://img.shields.io/github/stars/shoucheng3/dromara__hutool_CVE-2018-17297_4-1-11.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/dromara__hutool_CVE-2018-17297_4-1-11.svg)


## CVE-2017-5005
 Stack-based buffer overflow in Quick Heal Internet Security 10.1.0.316 and earlier, Total Security 10.1.0.316 and earlier, and AntiVirus Pro 10.1.0.316 and earlier on OS X allows remote attackers to execute arbitrary code via a crafted LC_UNIXTHREAD.cmdsize field in a Mach-O file that is mishandled during a Security Scan (aka Custom Scan) operation.

- [https://github.com/payatu/QuickHeal](https://github.com/payatu/QuickHeal) :  ![starts](https://img.shields.io/github/stars/payatu/QuickHeal.svg) ![forks](https://img.shields.io/github/forks/payatu/QuickHeal.svg)


## CVE-2016-10006
 In OWASP AntiSamy before 1.5.5, by submitting a specially crafted input (a tag that supports style with active content), you could bypass the library protections and supply executable code. The impact is XSS.

- [https://github.com/shoucheng3/nahsra__antisamy_CVE-2016-10006_1-5-3](https://github.com/shoucheng3/nahsra__antisamy_CVE-2016-10006_1-5-3) :  ![starts](https://img.shields.io/github/stars/shoucheng3/nahsra__antisamy_CVE-2016-10006_1-5-3.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/nahsra__antisamy_CVE-2016-10006_1-5-3.svg)


## CVE-2014-3576
 The processControlCommand function in broker/TransportConnection.java in Apache ActiveMQ before 5.11.0 allows remote attackers to cause a denial of service (shutdown) via a shutdown command.

- [https://github.com/shoucheng3/apache__activemq_CVE-2014-3576_5-10-1](https://github.com/shoucheng3/apache__activemq_CVE-2014-3576_5-10-1) :  ![starts](https://img.shields.io/github/stars/shoucheng3/apache__activemq_CVE-2014-3576_5-10-1.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/apache__activemq_CVE-2014-3576_5-10-1.svg)


## CVE-2013-7285
 Xstream API versions up to 1.4.6 and version 1.4.10, if the security framework has not been initialized, may allow a remote attacker to run arbitrary shell commands by manipulating the processed input stream when unmarshaling XML or any supported format. e.g. JSON.

- [https://github.com/shoucheng3/x-stream__xstream_CVE-2013-7285_1-4-6](https://github.com/shoucheng3/x-stream__xstream_CVE-2013-7285_1-4-6) :  ![starts](https://img.shields.io/github/stars/shoucheng3/x-stream__xstream_CVE-2013-7285_1-4-6.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/x-stream__xstream_CVE-2013-7285_1-4-6.svg)

