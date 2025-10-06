# Update 2025-10-06
## CVE-2025-57819
 FreePBX is an open-source web-based graphical user interface. FreePBX 15, 16, and 17 endpoints are vulnerable due to insufficiently sanitized user-supplied data allowing unauthenticated access to FreePBX Administrator leading to arbitrary database manipulation and remote code execution. This issue has been patched in endpoint versions 15.0.66, 16.0.89, and 17.0.3.

- [https://github.com/JakovBis/CVE-2025-57819_FreePBX-PoC](https://github.com/JakovBis/CVE-2025-57819_FreePBX-PoC) :  ![starts](https://img.shields.io/github/stars/JakovBis/CVE-2025-57819_FreePBX-PoC.svg) ![forks](https://img.shields.io/github/forks/JakovBis/CVE-2025-57819_FreePBX-PoC.svg)


## CVE-2025-39946
an invalid record there's really no way to recover.

- [https://github.com/farazsth98/exploit-CVE-2025-39946](https://github.com/farazsth98/exploit-CVE-2025-39946) :  ![starts](https://img.shields.io/github/stars/farazsth98/exploit-CVE-2025-39946.svg) ![forks](https://img.shields.io/github/forks/farazsth98/exploit-CVE-2025-39946.svg)


## CVE-2025-30208
 Vite, a provider of frontend development tooling, has a vulnerability in versions prior to 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10. `@fs` denies access to files outside of Vite serving allow list. Adding `?raw??` or `?import&raw??` to the URL bypasses this limitation and returns the file content if it exists. This bypass exists because trailing separators such as `?` are removed in several places, but are not accounted for in query string regexes. The contents of arbitrary files can be returned to the browser. Only apps explicitly exposing the Vite dev server to the network (using `--host` or `server.host` config option) are affected. Versions 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10 fix the issue.

- [https://github.com/qodo-dev/CVE-2025-30208](https://github.com/qodo-dev/CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/qodo-dev/CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/qodo-dev/CVE-2025-30208.svg)
- [https://github.com/bugdotexe/CVE-2025-30208](https://github.com/bugdotexe/CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/bugdotexe/CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/bugdotexe/CVE-2025-30208.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/KaztoJun/CVE-2025-29927-Research](https://github.com/KaztoJun/CVE-2025-29927-Research) :  ![starts](https://img.shields.io/github/stars/KaztoJun/CVE-2025-29927-Research.svg) ![forks](https://img.shields.io/github/forks/KaztoJun/CVE-2025-29927-Research.svg)


## CVE-2025-10184
The root cause is a combination of missing permissions for write operations in several content providers (com.android.providers.telephony.PushMessageProvider, com.android.providers.telephony.PushShopProvider, com.android.providers.telephony.ServiceNumberProvider), and a blind SQL injection in the update method of those providers.

- [https://github.com/Webpage-gh/CVE-2025-10184-PoC](https://github.com/Webpage-gh/CVE-2025-10184-PoC) :  ![starts](https://img.shields.io/github/stars/Webpage-gh/CVE-2025-10184-PoC.svg) ![forks](https://img.shields.io/github/forks/Webpage-gh/CVE-2025-10184-PoC.svg)


## CVE-2025-9952
 The Trinity Audio – Text to Speech AI audio player to convert content into audio plugin for WordPress is vulnerable to Reflected Cross-Site Scripting via the 'range-date' parameter in all versions up to, and including, 5.20.2 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that execute if they can successfully trick a user into performing an action such as clicking on a link.

- [https://github.com/MooseLoveti/Trinity-Audio-CVE-Report2](https://github.com/MooseLoveti/Trinity-Audio-CVE-Report2) :  ![starts](https://img.shields.io/github/stars/MooseLoveti/Trinity-Audio-CVE-Report2.svg) ![forks](https://img.shields.io/github/forks/MooseLoveti/Trinity-Audio-CVE-Report2.svg)


## CVE-2025-9886
 The Trinity Audio – Text to Speech AI audio player to convert content into audio plugin for WordPress is vulnerable to Cross-Site Request Forgery in all versions up to, and including, 5.20.2. This is due to missing or incorrect nonce validation in the '/admin/inc/post-management.php' file. This makes it possible for unauthenticated attackers to activate/deactivate posts via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/MooseLoveti/Trinity-Audio-CVE-Report2](https://github.com/MooseLoveti/Trinity-Audio-CVE-Report2) :  ![starts](https://img.shields.io/github/stars/MooseLoveti/Trinity-Audio-CVE-Report2.svg) ![forks](https://img.shields.io/github/forks/MooseLoveti/Trinity-Audio-CVE-Report2.svg)


## CVE-2025-1338
 A vulnerability was found in NUUO Camera up to 20250203. It has been declared as critical. This vulnerability affects the function print_file of the file /handle_config.php. The manipulation of the argument log leads to command injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/jxcaxtc/CVE-2025-1338](https://github.com/jxcaxtc/CVE-2025-1338) :  ![starts](https://img.shields.io/github/stars/jxcaxtc/CVE-2025-1338.svg) ![forks](https://img.shields.io/github/forks/jxcaxtc/CVE-2025-1338.svg)


## CVE-2024-36401
Versions 2.22.6, 2.23.6, 2.24.4, and 2.25.2 contain a patch for the issue. A workaround exists by removing the `gt-complex-x.y.jar` file from the GeoServer where `x.y` is the GeoTools version (e.g., `gt-complex-31.1.jar` if running GeoServer 2.25.1). This will remove the vulnerable code from GeoServer but may break some GeoServer functionality or prevent GeoServer from deploying if the gt-complex module is needed.

- [https://github.com/URJACK2025/CVE-2024-36401](https://github.com/URJACK2025/CVE-2024-36401) :  ![starts](https://img.shields.io/github/stars/URJACK2025/CVE-2024-36401.svg) ![forks](https://img.shields.io/github/forks/URJACK2025/CVE-2024-36401.svg)


## CVE-2024-7627
 The Bit File Manager plugin for WordPress is vulnerable to Remote Code Execution in versions 6.0 to 6.5.5 via the 'checkSyntax' function. This is due to writing a temporary file to a publicly accessible directory before performing file validation. This makes it possible for unauthenticated attackers to execute code on the server if an administrator has allowed Guest User read permissions.

- [https://github.com/lkmn1/CVE-2024-7627](https://github.com/lkmn1/CVE-2024-7627) :  ![starts](https://img.shields.io/github/stars/lkmn1/CVE-2024-7627.svg) ![forks](https://img.shields.io/github/forks/lkmn1/CVE-2024-7627.svg)


## CVE-2022-24348
 Argo CD before 2.1.9 and 2.2.x before 2.2.4 allows directory traversal related to Helm charts because of an error in helmTemplate in repository.go. For example, an attacker may be able to discover credentials stored in a YAML file.

- [https://github.com/jkroepke/CVE-2022-24348-2](https://github.com/jkroepke/CVE-2022-24348-2) :  ![starts](https://img.shields.io/github/stars/jkroepke/CVE-2022-24348-2.svg) ![forks](https://img.shields.io/github/forks/jkroepke/CVE-2022-24348-2.svg)


## CVE-2020-17530
 Forced OGNL evaluation, when evaluated on raw user input in tag attributes, may lead to remote code execution. Affected software : Apache Struts 2.0.0 - Struts 2.5.25.

- [https://github.com/shoucheng3/apache__struts_CVE-2020-17530_2-5-25](https://github.com/shoucheng3/apache__struts_CVE-2020-17530_2-5-25) :  ![starts](https://img.shields.io/github/stars/shoucheng3/apache__struts_CVE-2020-17530_2-5-25.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/apache__struts_CVE-2020-17530_2-5-25.svg)


## CVE-2020-1472
When the second phase of Windows updates become available in Q1 2021, customers will be notified via a revision to this security vulnerability. If you wish to be notified when these updates are released, we recommend that you register for the security notifications mailer to be alerted of content changes to this advisory. See Microsoft Technical Security Notifications.

- [https://github.com/100HnoMeuNome/ZeroLogon-CVE-2020-1472-lab](https://github.com/100HnoMeuNome/ZeroLogon-CVE-2020-1472-lab) :  ![starts](https://img.shields.io/github/stars/100HnoMeuNome/ZeroLogon-CVE-2020-1472-lab.svg) ![forks](https://img.shields.io/github/forks/100HnoMeuNome/ZeroLogon-CVE-2020-1472-lab.svg)


## CVE-2019-0194
 Apache Camel's File is vulnerable to directory traversal. Camel 2.21.0 to 2.21.3, 2.22.0 to 2.22.2, 2.23.0 and the unsupported Camel 2.x (2.19 and earlier) versions may be also affected.

- [https://github.com/shoucheng3/apache__camel_CVE-2019-0194_2-21-44](https://github.com/shoucheng3/apache__camel_CVE-2019-0194_2-21-44) :  ![starts](https://img.shields.io/github/stars/shoucheng3/apache__camel_CVE-2019-0194_2-21-44.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/apache__camel_CVE-2019-0194_2-21-44.svg)


## CVE-2018-17297
 The unzip function in ZipUtil.java in Hutool before 4.1.12 allows remote attackers to overwrite arbitrary files via directory traversal sequences in a filename within a ZIP archive.

- [https://github.com/shoucheng3/dromara__hutool_CVE-2018-17297_4-1-1111](https://github.com/shoucheng3/dromara__hutool_CVE-2018-17297_4-1-1111) :  ![starts](https://img.shields.io/github/stars/shoucheng3/dromara__hutool_CVE-2018-17297_4-1-1111.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/dromara__hutool_CVE-2018-17297_4-1-1111.svg)


## CVE-2017-5618
 GNU screen before 4.5.1 allows local users to modify arbitrary files and consequently gain root privileges by leveraging improper checking of logfile permissions.

- [https://github.com/RXDarkee/CVE-2017-5618-Screen-4.5.0-Root](https://github.com/RXDarkee/CVE-2017-5618-Screen-4.5.0-Root) :  ![starts](https://img.shields.io/github/stars/RXDarkee/CVE-2017-5618-Screen-4.5.0-Root.svg) ![forks](https://img.shields.io/github/forks/RXDarkee/CVE-2017-5618-Screen-4.5.0-Root.svg)

