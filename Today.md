# Update 2025-11-15
## CVE-2025-64513
 Milvus is an open-source vector database built for generative AI applications. An unauthenticated attacker can exploit a vulnerability in versions prior to 2.4.24, 2.5.21, and 2.6.5 to bypass all authentication mechanisms in the Milvus Proxy component, gaining full administrative access to the Milvus cluster. This grants the attacker the ability to read, modify, or delete data, and to perform privileged administrative operations such as database or collection management. This issue has been fixed in Milvus 2.4.24, 2.5.21, and 2.6.5. If immediate upgrade is not possible, a temporary mitigation can be applied by removing the sourceID header from all incoming requests at the gateway, API gateway, or load balancer level before they reach the Milvus Proxy. This prevents attackers from exploiting the authentication bypass behavior.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-64513](https://github.com/B1ack4sh/Blackash-CVE-2025-64513) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-64513.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-64513.svg)


## CVE-2025-64500
 Symfony is a PHP framework for web and console applications and a set of reusable PHP components. Symfony's HttpFoundation component defines an object-oriented layer for the HTTP specification. Starting in version 2.0.0 and prior to version 5.4.50, 6.4.29, and 7.3.7, the `Request` class improperly interprets some `PATH_INFO` in a way that leads to representing some URLs with a path that doesn't start with a `/`. This can allow bypassing some access control rules that are built with this `/`-prefix assumption. Starting in versions 5.4.50, 6.4.29, and 7.3.7, the `Request` class now ensures that URL paths always start with a `/`.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-64500](https://github.com/B1ack4sh/Blackash-CVE-2025-64500) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-64500.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-64500.svg)


## CVE-2025-60710
 Improper link resolution before file access ('link following') in Host Process for Windows Tasks allows an authorized attacker to elevate privileges locally.

- [https://github.com/mitjakolsek/CVE-2025-60710](https://github.com/mitjakolsek/CVE-2025-60710) :  ![starts](https://img.shields.io/github/stars/mitjakolsek/CVE-2025-60710.svg) ![forks](https://img.shields.io/github/forks/mitjakolsek/CVE-2025-60710.svg)


## CVE-2025-59118
Users are recommended to upgrade to version 24.09.03, which fixes the issue.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-59118](https://github.com/B1ack4sh/Blackash-CVE-2025-59118) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-59118.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-59118.svg)


## CVE-2025-39964
exclusive ownership for writing.

- [https://github.com/n1k0oowang/CVE-2025-39964_EXP](https://github.com/n1k0oowang/CVE-2025-39964_EXP) :  ![starts](https://img.shields.io/github/stars/n1k0oowang/CVE-2025-39964_EXP.svg) ![forks](https://img.shields.io/github/forks/n1k0oowang/CVE-2025-39964_EXP.svg)


## CVE-2025-34299
 Monsta FTP versions 2.11 and earlier contain a vulnerability that allows unauthenticated arbitrary file uploads. This flaw enables attackers to execute arbitrary code by uploading a specially crafted file from a malicious (S)FTP server.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-34299](https://github.com/B1ack4sh/Blackash-CVE-2025-34299) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-34299.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-34299.svg)


## CVE-2025-32434
 PyTorch is a Python package that provides tensor computation with strong GPU acceleration and deep neural networks built on a tape-based autograd system. In version 2.5.1 and prior, a Remote Command Execution (RCE) vulnerability exists in PyTorch when loading a model using torch.load with weights_only=True. This issue has been patched in version 2.6.0.

- [https://github.com/cyhe50/cve-2025-32434-poc](https://github.com/cyhe50/cve-2025-32434-poc) :  ![starts](https://img.shields.io/github/stars/cyhe50/cve-2025-32434-poc.svg) ![forks](https://img.shields.io/github/forks/cyhe50/cve-2025-32434-poc.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/jmbowes/NextSecureScan](https://github.com/jmbowes/NextSecureScan) :  ![starts](https://img.shields.io/github/stars/jmbowes/NextSecureScan.svg) ![forks](https://img.shields.io/github/forks/jmbowes/NextSecureScan.svg)


## CVE-2025-27591
 A privilege escalation vulnerability existed in the Below service prior to v0.9.0 due to the creation of a world-writable directory at /var/log/below. This could have allowed local unprivileged users to escalate to root privileges through symlink attacks that manipulate files such as /etc/shadow.

- [https://github.com/0xDTC/Below-Logger-Symlink-Attack_CVE-2025-27591](https://github.com/0xDTC/Below-Logger-Symlink-Attack_CVE-2025-27591) :  ![starts](https://img.shields.io/github/stars/0xDTC/Below-Logger-Symlink-Attack_CVE-2025-27591.svg) ![forks](https://img.shields.io/github/forks/0xDTC/Below-Logger-Symlink-Attack_CVE-2025-27591.svg)


## CVE-2025-26686
 Sensitive data storage in improperly locked memory in Windows TCP/IP allows an unauthorized attacker to execute code over a network.

- [https://github.com/alifaraj5723/CVE-2025-26686-poc](https://github.com/alifaraj5723/CVE-2025-26686-poc) :  ![starts](https://img.shields.io/github/stars/alifaraj5723/CVE-2025-26686-poc.svg) ![forks](https://img.shields.io/github/forks/alifaraj5723/CVE-2025-26686-poc.svg)


## CVE-2025-20337
This vulnerability is due to insufficient validation of user-supplied input. An attacker could exploit this vulnerability by submitting a crafted API request. A successful exploit could allow the attacker to obtain root privileges on an affected device.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-20337](https://github.com/B1ack4sh/Blackash-CVE-2025-20337) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-20337.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-20337.svg)


## CVE-2025-12480
 Triofox versions prior to 16.7.10368.56560, are vulnerable to an Improper Access Control flaw that allows access to initial setup pages even after setup is complete.

- [https://github.com/velmetrac/CVE-2025-12480](https://github.com/velmetrac/CVE-2025-12480) :  ![starts](https://img.shields.io/github/stars/velmetrac/CVE-2025-12480.svg) ![forks](https://img.shields.io/github/forks/velmetrac/CVE-2025-12480.svg)


## CVE-2025-11493
 The ConnectWise Automate Agent does not fully verify the authenticity of files downloaded from the server, such as updates, dependencies, and integrations. This creates a risk where an on-path attacker could perform a man-in-the-middle attack and substitute malicious files for legitimate ones by impersonating a legitimate server. This risk is mitigated when HTTPS is enforced and is related to CVE-2025-11492.

- [https://github.com/synap5e/connectwise-automate-AiTM-rce](https://github.com/synap5e/connectwise-automate-AiTM-rce) :  ![starts](https://img.shields.io/github/stars/synap5e/connectwise-automate-AiTM-rce.svg) ![forks](https://img.shields.io/github/forks/synap5e/connectwise-automate-AiTM-rce.svg)


## CVE-2025-11492
 In the ConnectWise Automate Agent, communications could be configured to use HTTP instead of HTTPS. In such cases, an on-path threat actor with a man-in-the-middle network position could intercept, modify, or replay agent-server traffic. Additionally, the encryption method used to obfuscate some communications over the HTTP channel is updated in the Automate 2025.9 patch to enforce HTTPS for all agent communications.

- [https://github.com/synap5e/connectwise-automate-AiTM-rce](https://github.com/synap5e/connectwise-automate-AiTM-rce) :  ![starts](https://img.shields.io/github/stars/synap5e/connectwise-automate-AiTM-rce.svg) ![forks](https://img.shields.io/github/forks/synap5e/connectwise-automate-AiTM-rce.svg)


## CVE-2025-9816
 The WP Statistics – The Most Popular Privacy-Friendly Analytics Plugin plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the User-Agent Header in all versions up to, and including, 14.5.4 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/monzaviman/CVE-2025-9816](https://github.com/monzaviman/CVE-2025-9816) :  ![starts](https://img.shields.io/github/stars/monzaviman/CVE-2025-9816.svg) ![forks](https://img.shields.io/github/forks/monzaviman/CVE-2025-9816.svg)


## CVE-2025-8088
     from ESET.

- [https://github.com/WezRyan/CVE-2025-8088](https://github.com/WezRyan/CVE-2025-8088) :  ![starts](https://img.shields.io/github/stars/WezRyan/CVE-2025-8088.svg) ![forks](https://img.shields.io/github/forks/WezRyan/CVE-2025-8088.svg)


## CVE-2025-7771
 ThrottleStop.sys, a legitimate driver, exposes two IOCTL interfaces that allow arbitrary read and write access to physical memory via the MmMapIoSpace function. This insecure implementation can be exploited by a malicious user-mode application to patch the running Windows kernel and invoke arbitrary kernel functions with ring-0 privileges. The vulnerability enables local attackers to execute arbitrary code in kernel context, resulting in privilege escalation and potential follow-on attacks, such as disabling security software or bypassing kernel-level protections. ThrottleStop.sys version 3.0.0.0 and possibly others are affected. Apply updates per vendor instructions.

- [https://github.com/AmrHuss/throttlestop-exploit-rw](https://github.com/AmrHuss/throttlestop-exploit-rw) :  ![starts](https://img.shields.io/github/stars/AmrHuss/throttlestop-exploit-rw.svg) ![forks](https://img.shields.io/github/forks/AmrHuss/throttlestop-exploit-rw.svg)


## CVE-2025-6470
 A vulnerability classified as critical has been found in code-projects Online Bidding System 1.0. Affected is an unknown function of the file /bidlog.php. The manipulation of the argument ID leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/DylanDavis1/CVE-2025-64708](https://github.com/DylanDavis1/CVE-2025-64708) :  ![starts](https://img.shields.io/github/stars/DylanDavis1/CVE-2025-64708.svg) ![forks](https://img.shields.io/github/forks/DylanDavis1/CVE-2025-64708.svg)


## CVE-2024-0044
 In createSessionInternal of PackageInstallerService.java, there is a possible run-as any app due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/HoyoenKim/CVE-2024-0044_PoC](https://github.com/HoyoenKim/CVE-2024-0044_PoC) :  ![starts](https://img.shields.io/github/stars/HoyoenKim/CVE-2024-0044_PoC.svg) ![forks](https://img.shields.io/github/forks/HoyoenKim/CVE-2024-0044_PoC.svg)


## CVE-2023-45992
 A vulnerability in the web-based interface of the RUCKUS Cloudpath product on version 5.12 build 5538 or before to could allow a remote, unauthenticated attacker to execute persistent XSS and CSRF attacks against a user of the admin management interface. A successful attack, combined with a certain admin activity, could allow the attacker to gain full admin privileges on the exploited system.

- [https://github.com/harry935/CVE-2023-45992](https://github.com/harry935/CVE-2023-45992) :  ![starts](https://img.shields.io/github/stars/harry935/CVE-2023-45992.svg) ![forks](https://img.shields.io/github/forks/harry935/CVE-2023-45992.svg)


## CVE-2023-45878
 GibbonEdu Gibbon version 25.0.1 and before allows Arbitrary File Write because rubrics_visualise_saveAjax.phps does not require authentication. The endpoint accepts the img, path, and gibbonPersonID parameters. The img parameter is expected to be a base64 encoded image. If the path parameter is set, the defined path is used as the destination folder, concatenated with the absolute path of the installation directory. The content of the img parameter is base64 decoded and written to the defined file path. This allows creation of PHP files that permit Remote Code Execution (unauthenticated).

- [https://github.com/killercd/CVE-2023-45878](https://github.com/killercd/CVE-2023-45878) :  ![starts](https://img.shields.io/github/stars/killercd/CVE-2023-45878.svg) ![forks](https://img.shields.io/github/forks/killercd/CVE-2023-45878.svg)
- [https://github.com/davidzzo23/CVE-2023-45878](https://github.com/davidzzo23/CVE-2023-45878) :  ![starts](https://img.shields.io/github/stars/davidzzo23/CVE-2023-45878.svg) ![forks](https://img.shields.io/github/forks/davidzzo23/CVE-2023-45878.svg)
- [https://github.com/Can0I0Ever0Enter/CVE-2023-45878](https://github.com/Can0I0Ever0Enter/CVE-2023-45878) :  ![starts](https://img.shields.io/github/stars/Can0I0Ever0Enter/CVE-2023-45878.svg) ![forks](https://img.shields.io/github/forks/Can0I0Ever0Enter/CVE-2023-45878.svg)
- [https://github.com/byt3loss/CVE-2023-45878_to_RCE](https://github.com/byt3loss/CVE-2023-45878_to_RCE) :  ![starts](https://img.shields.io/github/stars/byt3loss/CVE-2023-45878_to_RCE.svg) ![forks](https://img.shields.io/github/forks/byt3loss/CVE-2023-45878_to_RCE.svg)
- [https://github.com/PaulDHaes/CVE-2023-45878-POC](https://github.com/PaulDHaes/CVE-2023-45878-POC) :  ![starts](https://img.shields.io/github/stars/PaulDHaes/CVE-2023-45878-POC.svg) ![forks](https://img.shields.io/github/forks/PaulDHaes/CVE-2023-45878-POC.svg)
- [https://github.com/nrazv/CVE-2023-45878](https://github.com/nrazv/CVE-2023-45878) :  ![starts](https://img.shields.io/github/stars/nrazv/CVE-2023-45878.svg) ![forks](https://img.shields.io/github/forks/nrazv/CVE-2023-45878.svg)
- [https://github.com/dgoorden/CVE-2023-45878](https://github.com/dgoorden/CVE-2023-45878) :  ![starts](https://img.shields.io/github/stars/dgoorden/CVE-2023-45878.svg) ![forks](https://img.shields.io/github/forks/dgoorden/CVE-2023-45878.svg)
- [https://github.com/ulricvbs/gibbonlms-filewrite_rce](https://github.com/ulricvbs/gibbonlms-filewrite_rce) :  ![starts](https://img.shields.io/github/stars/ulricvbs/gibbonlms-filewrite_rce.svg) ![forks](https://img.shields.io/github/forks/ulricvbs/gibbonlms-filewrite_rce.svg)


## CVE-2023-45828
 Missing Authorization vulnerability in RumbleTalk Ltd RumbleTalk Live Group Chat allows Exploiting Incorrectly Configured Access Control Security Levels.This issue affects RumbleTalk Live Group Chat: from n/a through 6.2.5.

- [https://github.com/RandomRobbieBF/CVE-2023-45828](https://github.com/RandomRobbieBF/CVE-2023-45828) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2023-45828.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2023-45828.svg)


## CVE-2023-45612
 In JetBrains Ktor before 2.3.5 default configuration of ContentNegotiation with XML format was vulnerable to XXE

- [https://github.com/aecelen/ktor-xxe-poc](https://github.com/aecelen/ktor-xxe-poc) :  ![starts](https://img.shields.io/github/stars/aecelen/ktor-xxe-poc.svg) ![forks](https://img.shields.io/github/forks/aecelen/ktor-xxe-poc.svg)
- [https://github.com/bbugdigger/ktor-xxe-poc](https://github.com/bbugdigger/ktor-xxe-poc) :  ![starts](https://img.shields.io/github/stars/bbugdigger/ktor-xxe-poc.svg) ![forks](https://img.shields.io/github/forks/bbugdigger/ktor-xxe-poc.svg)
- [https://github.com/clemfavre/cve-2023-45612_exploit](https://github.com/clemfavre/cve-2023-45612_exploit) :  ![starts](https://img.shields.io/github/stars/clemfavre/cve-2023-45612_exploit.svg) ![forks](https://img.shields.io/github/forks/clemfavre/cve-2023-45612_exploit.svg)
- [https://github.com/seraphimi/ktor-xxe](https://github.com/seraphimi/ktor-xxe) :  ![starts](https://img.shields.io/github/stars/seraphimi/ktor-xxe.svg) ![forks](https://img.shields.io/github/forks/seraphimi/ktor-xxe.svg)
- [https://github.com/infernosalex/CVE-2023-45612-PoC](https://github.com/infernosalex/CVE-2023-45612-PoC) :  ![starts](https://img.shields.io/github/stars/infernosalex/CVE-2023-45612-PoC.svg) ![forks](https://img.shields.io/github/forks/infernosalex/CVE-2023-45612-PoC.svg)
- [https://github.com/ksaweryr/CVE-2023-45612-PoC](https://github.com/ksaweryr/CVE-2023-45612-PoC) :  ![starts](https://img.shields.io/github/stars/ksaweryr/CVE-2023-45612-PoC.svg) ![forks](https://img.shields.io/github/forks/ksaweryr/CVE-2023-45612-PoC.svg)
- [https://github.com/stefan-500/ktor-cve-2023-45612-poc](https://github.com/stefan-500/ktor-cve-2023-45612-poc) :  ![starts](https://img.shields.io/github/stars/stefan-500/ktor-cve-2023-45612-poc.svg) ![forks](https://img.shields.io/github/forks/stefan-500/ktor-cve-2023-45612-poc.svg)
- [https://github.com/razvanclaudiu/Ktor-XXE-PoC](https://github.com/razvanclaudiu/Ktor-XXE-PoC) :  ![starts](https://img.shields.io/github/stars/razvanclaudiu/Ktor-XXE-PoC.svg) ![forks](https://img.shields.io/github/forks/razvanclaudiu/Ktor-XXE-PoC.svg)


## CVE-2023-45539
 HAProxy before 2.8.2 accepts # as part of the URI component, which might allow remote attackers to obtain sensitive information or have unspecified other impact upon misinterpretation of a path_end rule, such as routing index.html#.png to a static server.

- [https://github.com/slicingmelon/HAProxy-CVE-2023-45539-PoC](https://github.com/slicingmelon/HAProxy-CVE-2023-45539-PoC) :  ![starts](https://img.shields.io/github/stars/slicingmelon/HAProxy-CVE-2023-45539-PoC.svg) ![forks](https://img.shields.io/github/forks/slicingmelon/HAProxy-CVE-2023-45539-PoC.svg)


## CVE-2023-45184
 IBM i Access Client Solutions 1.1.2 through 1.1.4 and 1.1.4.3 through 1.1.9.3 could allow an attacker to obtain a decryption key due to improper authority checks.  IBM X-Force ID:  268270.

- [https://github.com/afine-com/CVE-2023-45184](https://github.com/afine-com/CVE-2023-45184) :  ![starts](https://img.shields.io/github/stars/afine-com/CVE-2023-45184.svg) ![forks](https://img.shields.io/github/forks/afine-com/CVE-2023-45184.svg)


## CVE-2023-45131
 Discourse is an open source platform for community discussion. New chat messages can be read by making an unauthenticated POST request to MessageBus. This issue is patched in the 3.1.1 stable and 3.2.0.beta2 versions of Discourse. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/ibrahmsql/CVE-2023-45131](https://github.com/ibrahmsql/CVE-2023-45131) :  ![starts](https://img.shields.io/github/stars/ibrahmsql/CVE-2023-45131.svg) ![forks](https://img.shields.io/github/forks/ibrahmsql/CVE-2023-45131.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/xenosf/CS4239-Spring4Shell-POC](https://github.com/xenosf/CS4239-Spring4Shell-POC) :  ![starts](https://img.shields.io/github/stars/xenosf/CS4239-Spring4Shell-POC.svg) ![forks](https://img.shields.io/github/forks/xenosf/CS4239-Spring4Shell-POC.svg)


## CVE-2022-2884
 A vulnerability in GitLab CE/EE affecting all versions from 11.3.4 prior to 15.1.5, 15.2 to 15.2.3, 15.3 to 15.3 to 15.3.1 allows an an authenticated user to achieve remote code execution via the Import from GitHub API endpoint

- [https://github.com/Boydunbarred375/gi-cv](https://github.com/Boydunbarred375/gi-cv) :  ![starts](https://img.shields.io/github/stars/Boydunbarred375/gi-cv.svg) ![forks](https://img.shields.io/github/forks/Boydunbarred375/gi-cv.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/honypot/CVE-2021-41773](https://github.com/honypot/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/honypot/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/honypot/CVE-2021-41773.svg)


## CVE-2020-14144
 The git hook feature in Gitea 1.1.0 through 1.12.5 might allow for authenticated remote code execution in customer environments where the documentation was not understood (e.g., one viewpoint is that the dangerousness of this feature should be documented immediately above the ENABLE_GIT_HOOKS line in the config file). NOTE: The vendor has indicated this is not a vulnerability and states "This is a functionality of the software that is limited to a very limited subset of accounts. If you give someone the privilege to execute arbitrary code on your server, they can execute arbitrary code on your server. We provide very clear warnings to users around this functionality and what it provides.

- [https://github.com/Boydunbarred375/gi-cv](https://github.com/Boydunbarred375/gi-cv) :  ![starts](https://img.shields.io/github/stars/Boydunbarred375/gi-cv.svg) ![forks](https://img.shields.io/github/forks/Boydunbarred375/gi-cv.svg)


## CVE-2019-11932
 A double free vulnerability in the DDGifSlurp function in decoding.c in the android-gif-drawable library before version 1.2.18, as used in WhatsApp for Android before version 2.19.244 and many other Android applications, allows remote attackers to execute arbitrary code or cause a denial of service when the library is used to parse a specially crafted GIF image.

- [https://github.com/OrdaraatSite/https-github.com-awakened171](https://github.com/OrdaraatSite/https-github.com-awakened171) :  ![starts](https://img.shields.io/github/stars/OrdaraatSite/https-github.com-awakened171.svg) ![forks](https://img.shields.io/github/forks/OrdaraatSite/https-github.com-awakened171.svg)


## CVE-2018-1207
 Dell EMC iDRAC7/iDRAC8, versions prior to 2.52.52.52, contain CGI injection vulnerability which could be used to execute remote code. A remote unauthenticated attacker may potentially be able to use CGI variables to execute remote code.

- [https://github.com/hironull/CVE-2018-1207-better](https://github.com/hironull/CVE-2018-1207-better) :  ![starts](https://img.shields.io/github/stars/hironull/CVE-2018-1207-better.svg) ![forks](https://img.shields.io/github/forks/hironull/CVE-2018-1207-better.svg)


## CVE-2016-20012
 OpenSSH through 8.7 allows remote attackers, who have a suspicion that a certain combination of username and public key is known to an SSH server, to test whether this suspicion is correct. This occurs because a challenge is sent only when that combination could be valid for a login session. NOTE: the vendor does not recognize user enumeration as a vulnerability for this product

- [https://github.com/arturo-b-cmu/cve-2016-20012](https://github.com/arturo-b-cmu/cve-2016-20012) :  ![starts](https://img.shields.io/github/stars/arturo-b-cmu/cve-2016-20012.svg) ![forks](https://img.shields.io/github/forks/arturo-b-cmu/cve-2016-20012.svg)

