# Update 2025-03-30
## CVE-2025-30772
 Missing Authorization vulnerability in WPClever WPC Smart Upsell Funnel for WooCommerce allows Privilege Escalation. This issue affects WPC Smart Upsell Funnel for WooCommerce: from n/a through 3.0.4.

- [https://github.com/Nxploited/CVE-2025-30772](https://github.com/Nxploited/CVE-2025-30772) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-30772.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-30772.svg)


## CVE-2025-30208
 Vite, a provider of frontend development tooling, has a vulnerability in versions prior to 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10. `@fs` denies access to files outside of Vite serving allow list. Adding `?raw??` or `?import&raw??` to the URL bypasses this limitation and returns the file content if it exists. This bypass exists because trailing separators such as `?` are removed in several places, but are not accounted for in query string regexes. The contents of arbitrary files can be returned to the browser. Only apps explicitly exposing the Vite dev server to the network (using `--host` or `server.host` config option) are affected. Versions 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10 fix the issue.

- [https://github.com/keklick1337/CVE-2025-30208-ViteVulnScanner](https://github.com/keklick1337/CVE-2025-30208-ViteVulnScanner) :  ![starts](https://img.shields.io/github/stars/keklick1337/CVE-2025-30208-ViteVulnScanner.svg) ![forks](https://img.shields.io/github/forks/keklick1337/CVE-2025-30208-ViteVulnScanner.svg)
- [https://github.com/sadhfdw129/CVE-2025-30208-Vite](https://github.com/sadhfdw129/CVE-2025-30208-Vite) :  ![starts](https://img.shields.io/github/stars/sadhfdw129/CVE-2025-30208-Vite.svg) ![forks](https://img.shields.io/github/forks/sadhfdw129/CVE-2025-30208-Vite.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Prior to 14.2.25 and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 14.2.25 and 15.2.3.

- [https://github.com/0x0Luk/0xMiddleware](https://github.com/0x0Luk/0xMiddleware) :  ![starts](https://img.shields.io/github/stars/0x0Luk/0xMiddleware.svg) ![forks](https://img.shields.io/github/forks/0x0Luk/0xMiddleware.svg)
- [https://github.com/AnonKryptiQuz/NextSploit](https://github.com/AnonKryptiQuz/NextSploit) :  ![starts](https://img.shields.io/github/stars/AnonKryptiQuz/NextSploit.svg) ![forks](https://img.shields.io/github/forks/AnonKryptiQuz/NextSploit.svg)
- [https://github.com/yuzu-juice/CVE-2025-29927_demo](https://github.com/yuzu-juice/CVE-2025-29927_demo) :  ![starts](https://img.shields.io/github/stars/yuzu-juice/CVE-2025-29927_demo.svg) ![forks](https://img.shields.io/github/forks/yuzu-juice/CVE-2025-29927_demo.svg)


## CVE-2025-26909
 Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion') vulnerability in John Darrel Hide My WP Ghost allows PHP Local File Inclusion.This issue affects Hide My WP Ghost: from n/a through 5.4.01.

- [https://github.com/ZeroDayx/CVE-2025-26909](https://github.com/ZeroDayx/CVE-2025-26909) :  ![starts](https://img.shields.io/github/stars/ZeroDayx/CVE-2025-26909.svg) ![forks](https://img.shields.io/github/forks/ZeroDayx/CVE-2025-26909.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/AlperenY-cs/CVE-2025-24813](https://github.com/AlperenY-cs/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/AlperenY-cs/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/AlperenY-cs/CVE-2025-24813.svg)


## CVE-2025-22953
 A SQL injection vulnerability exists in the Epicor HCM 2021 1.9, specifically in the filter parameter of the JsonFetcher.svc endpoint. An attacker can exploit this vulnerability by injecting malicious SQL payloads into the filter parameter, enabling the unauthorized execution of arbitrary SQL commands on the backend database. If certain features (like xp_cmdshell) are enabled, this may lead to remote code execution.

- [https://github.com/maliktawfiq/CVE-2025-22953](https://github.com/maliktawfiq/CVE-2025-22953) :  ![starts](https://img.shields.io/github/stars/maliktawfiq/CVE-2025-22953.svg) ![forks](https://img.shields.io/github/forks/maliktawfiq/CVE-2025-22953.svg)


## CVE-2025-21298
 Windows OLE Remote Code Execution Vulnerability

- [https://github.com/Denyningbow/rtf-ctf-cve-2025-21298](https://github.com/Denyningbow/rtf-ctf-cve-2025-21298) :  ![starts](https://img.shields.io/github/stars/Denyningbow/rtf-ctf-cve-2025-21298.svg) ![forks](https://img.shields.io/github/forks/Denyningbow/rtf-ctf-cve-2025-21298.svg)


## CVE-2025-2901
 A flaw was found in the JBoss EAP Management Console, where a stored Cross-site scripting vulnerability occurs when an application improperly sanitizes user input before storing it in a data store. When this stored data is later included in web pages without adequate sanitization, malicious scripts can execute in the context of users who view these pages, leading to potential data theft, session hijacking, or other malicious activities.

- [https://github.com/b1tm4r/CVE-2025-29015](https://github.com/b1tm4r/CVE-2025-29015) :  ![starts](https://img.shields.io/github/stars/b1tm4r/CVE-2025-29015.svg) ![forks](https://img.shields.io/github/forks/b1tm4r/CVE-2025-29015.svg)
- [https://github.com/b1tm4r/CVE-2025-29017](https://github.com/b1tm4r/CVE-2025-29017) :  ![starts](https://img.shields.io/github/stars/b1tm4r/CVE-2025-29017.svg) ![forks](https://img.shields.io/github/forks/b1tm4r/CVE-2025-29017.svg)
- [https://github.com/b1tm4r/CVE-2025-29018](https://github.com/b1tm4r/CVE-2025-29018) :  ![starts](https://img.shields.io/github/stars/b1tm4r/CVE-2025-29018.svg) ![forks](https://img.shields.io/github/forks/b1tm4r/CVE-2025-29018.svg)


## CVE-2025-2857
*This only affects Firefox on Windows. Other operating systems are unaffected.* This vulnerability affects Firefox  136.0.4, Firefox ESR  128.8.1, and Firefox ESR  115.21.1.

- [https://github.com/RimaRuer/CVE-2025-2857-Exploit](https://github.com/RimaRuer/CVE-2025-2857-Exploit) :  ![starts](https://img.shields.io/github/stars/RimaRuer/CVE-2025-2857-Exploit.svg) ![forks](https://img.shields.io/github/forks/RimaRuer/CVE-2025-2857-Exploit.svg)


## CVE-2025-2783
 Incorrect handle provided in unspecified circumstances in Mojo in Google Chrome on Windows prior to 134.0.6998.177 allowed a remote attacker to perform a sandbox escape via a malicious file. (Chromium security severity: High)

- [https://github.com/bronsoneaver/CVE-2025-2783](https://github.com/bronsoneaver/CVE-2025-2783) :  ![starts](https://img.shields.io/github/stars/bronsoneaver/CVE-2025-2783.svg) ![forks](https://img.shields.io/github/forks/bronsoneaver/CVE-2025-2783.svg)


## CVE-2025-2294
 The Kubio AI Page Builder plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 2.5.1 via thekubio_hybrid_theme_load_template function. This makes it possible for unauthenticated attackers to include and execute arbitrary files on the server, allowing the execution of any PHP code in those files. This can be used to bypass access controls, obtain sensitive data, or achieve code execution in cases where images and other “safe” file types can be uploaded and included.

- [https://github.com/Nxploited/CVE-2025-2294](https://github.com/Nxploited/CVE-2025-2294) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-2294.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-2294.svg)


## CVE-2025-1974
 A security issue was discovered in Kubernetes where under certain conditions, an unauthenticated attacker with access to the pod network can achieve arbitrary code execution in the context of the ingress-nginx controller. This can lead to disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)

- [https://github.com/rjhaikal/POC-IngressNightmare-CVE-2025-1974](https://github.com/rjhaikal/POC-IngressNightmare-CVE-2025-1974) :  ![starts](https://img.shields.io/github/stars/rjhaikal/POC-IngressNightmare-CVE-2025-1974.svg) ![forks](https://img.shields.io/github/forks/rjhaikal/POC-IngressNightmare-CVE-2025-1974.svg)


## CVE-2025-1771
 The Traveler theme for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 3.1.8 via the 'hotel_alone_load_more_post' function 'style' parameter. This makes it possible for unauthenticated attackers to include and execute arbitrary files on the server, allowing the execution of any PHP code in those files. This can be used to bypass access controls, obtain sensitive data, or achieve code execution in cases where php file type can be uploaded and included.

- [https://github.com/realcodeb0ss/CVE-1771-POC](https://github.com/realcodeb0ss/CVE-1771-POC) :  ![starts](https://img.shields.io/github/stars/realcodeb0ss/CVE-1771-POC.svg) ![forks](https://img.shields.io/github/forks/realcodeb0ss/CVE-1771-POC.svg)


## CVE-2025-1653
 The Directory Listings WordPress plugin – uListing plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 2.1.7. This is due to the stm_listing_profile_edit AJAX action not having enough restriction on the user meta that can be updated. This makes it possible for authenticated attackers, with Subscriber-level access and above, to elevate their privileges to that of an administrator.

- [https://github.com/realcodeb0ss/CVE-2025-1653-poc](https://github.com/realcodeb0ss/CVE-2025-1653-poc) :  ![starts](https://img.shields.io/github/stars/realcodeb0ss/CVE-2025-1653-poc.svg) ![forks](https://img.shields.io/github/forks/realcodeb0ss/CVE-2025-1653-poc.svg)


## CVE-2024-23897
 Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.

- [https://github.com/brandonhjh/Jenkins-CVE-2024-23897-Exploit-Demo](https://github.com/brandonhjh/Jenkins-CVE-2024-23897-Exploit-Demo) :  ![starts](https://img.shields.io/github/stars/brandonhjh/Jenkins-CVE-2024-23897-Exploit-Demo.svg) ![forks](https://img.shields.io/github/forks/brandonhjh/Jenkins-CVE-2024-23897-Exploit-Demo.svg)


## CVE-2023-44962
 File Upload vulnerability in Koha Library Software 23.05.04 and before allows a remote attacker to read arbitrary files via the upload-cover-image.pl component.

- [https://github.com/LadyDarwe/Links.a](https://github.com/LadyDarwe/Links.a) :  ![starts](https://img.shields.io/github/stars/LadyDarwe/Links.a.svg) ![forks](https://img.shields.io/github/forks/LadyDarwe/Links.a.svg)


## CVE-2023-42793
 In JetBrains TeamCity before 2023.05.4 authentication bypass leading to RCE on TeamCity Server was possible

- [https://github.com/becrevex/CVE-2023-42793](https://github.com/becrevex/CVE-2023-42793) :  ![starts](https://img.shields.io/github/stars/becrevex/CVE-2023-42793.svg) ![forks](https://img.shields.io/github/forks/becrevex/CVE-2023-42793.svg)


## CVE-2023-7028
 An issue has been discovered in GitLab CE/EE affecting all versions from 16.1 prior to 16.1.6, 16.2 prior to 16.2.9, 16.3 prior to 16.3.7, 16.4 prior to 16.4.5, 16.5 prior to 16.5.6, 16.6 prior to 16.6.4, and 16.7 prior to 16.7.2 in which user account password reset emails could be delivered to an unverified email address.

- [https://github.com/Sornphut/CVE-2023-7028-GitLab](https://github.com/Sornphut/CVE-2023-7028-GitLab) :  ![starts](https://img.shields.io/github/stars/Sornphut/CVE-2023-7028-GitLab.svg) ![forks](https://img.shields.io/github/forks/Sornphut/CVE-2023-7028-GitLab.svg)


## CVE-2023-6241
 Use After Free vulnerability in Arm Ltd Midgard GPU Kernel Driver, Arm Ltd Bifrost GPU Kernel Driver, Arm Ltd Valhall GPU Kernel Driver, Arm Ltd Arm 5th Gen GPU Architecture Kernel Driver allows a local non-privileged user to exploit a software race condition to perform improper memory processing operations. If the system’s memory is carefully prepared by the user, then this in turn cause a use-after-free.This issue affects Midgard GPU Kernel Driver: from r13p0 through r32p0; Bifrost GPU Kernel Driver: from r11p0 through r25p0; Valhall GPU Kernel Driver: from r19p0 through r25p0, from r29p0 through r46p0; Arm 5th Gen GPU Architecture Kernel Driver: from r41p0 through r46p0.

- [https://github.com/SmileTabLabo/CVE-2023-6241](https://github.com/SmileTabLabo/CVE-2023-6241) :  ![starts](https://img.shields.io/github/stars/SmileTabLabo/CVE-2023-6241.svg) ![forks](https://img.shields.io/github/forks/SmileTabLabo/CVE-2023-6241.svg)


## CVE-2022-24706
 In Apache CouchDB prior to 3.2.2, an attacker can access an improperly secured default installation without authenticating and gain admin privileges. The CouchDB documentation has always made recommendations for properly securing an installation, including recommending using a firewall in front of all CouchDB installations.

- [https://github.com/becrevex/CVE-2022-24706](https://github.com/becrevex/CVE-2022-24706) :  ![starts](https://img.shields.io/github/stars/becrevex/CVE-2022-24706.svg) ![forks](https://img.shields.io/github/forks/becrevex/CVE-2022-24706.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/luongchivi/CVE-2021-41773](https://github.com/luongchivi/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/luongchivi/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/luongchivi/CVE-2021-41773.svg)


## CVE-2021-21353
 Pug is an npm package which is a high-performance template engine. In pug before version 3.0.1, if a remote attacker was able to control the `pretty` option of the pug compiler, e.g. if you spread a user provided object such as the query parameters of a request into the pug template inputs, it was possible for them to achieve remote code execution on the node.js backend. This is fixed in version 3.0.1. This advisory applies to multiple pug packages including "pug", "pug-code-gen". pug-code-gen has a backported fix at version 2.0.3. This advisory is not exploitable if there is no way for un-trusted input to be passed to pug as the `pretty` option, e.g. if you compile templates in advance before applying user input to them, you do not need to upgrade.

- [https://github.com/jinsu9758/PUG-RCE-CVE-2021-21353-POC](https://github.com/jinsu9758/PUG-RCE-CVE-2021-21353-POC) :  ![starts](https://img.shields.io/github/stars/jinsu9758/PUG-RCE-CVE-2021-21353-POC.svg) ![forks](https://img.shields.io/github/forks/jinsu9758/PUG-RCE-CVE-2021-21353-POC.svg)


## CVE-2018-16763
 FUEL CMS 1.4.1 allows PHP Code Evaluation via the pages/select/ filter parameter or the preview/ data parameter. This can lead to Pre-Auth Remote Code Execution.

- [https://github.com/andreidiaconescu18/FuelCMS-1.4.1-RCE-for-TryHackMe](https://github.com/andreidiaconescu18/FuelCMS-1.4.1-RCE-for-TryHackMe) :  ![starts](https://img.shields.io/github/stars/andreidiaconescu18/FuelCMS-1.4.1-RCE-for-TryHackMe.svg) ![forks](https://img.shields.io/github/forks/andreidiaconescu18/FuelCMS-1.4.1-RCE-for-TryHackMe.svg)

