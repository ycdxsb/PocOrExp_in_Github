# Update 2025-07-01
## CVE-2025-30208
 Vite, a provider of frontend development tooling, has a vulnerability in versions prior to 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10. `@fs` denies access to files outside of Vite serving allow list. Adding `?raw??` or `?import&raw??` to the URL bypasses this limitation and returns the file content if it exists. This bypass exists because trailing separators such as `?` are removed in several places, but are not accounted for in query string regexes. The contents of arbitrary files can be returned to the browser. Only apps explicitly exposing the Vite dev server to the network (using `--host` or `server.host` config option) are affected. Versions 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10 fix the issue.

- [https://github.com/TH-SecForge/CVE-2025-30208](https://github.com/TH-SecForge/CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/TH-SecForge/CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/TH-SecForge/CVE-2025-30208.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/bohmiiidd/CVE-2025-29927-exploit-code-](https://github.com/bohmiiidd/CVE-2025-29927-exploit-code-) :  ![starts](https://img.shields.io/github/stars/bohmiiidd/CVE-2025-29927-exploit-code-.svg) ![forks](https://img.shields.io/github/forks/bohmiiidd/CVE-2025-29927-exploit-code-.svg)


## CVE-2025-6860
 A vulnerability was found in SourceCodester Best Salon Management System 1.0. It has been declared as critical. This vulnerability affects unknown code of the file /panel/staff_commision.php. The manipulation of the argument fromdate/todate leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/byteReaper77/CVE-2025-6860](https://github.com/byteReaper77/CVE-2025-6860) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-6860.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-6860.svg)


## CVE-2025-6218
The specific flaw exists within the handling of file paths within archive files. A crafted file path can cause the process to traverse to unintended directories. An attacker can leverage this vulnerability to execute code in the context of the current user. Was ZDI-CAN-27198.

- [https://github.com/ignis-sec/CVE-2025-6218](https://github.com/ignis-sec/CVE-2025-6218) :  ![starts](https://img.shields.io/github/stars/ignis-sec/CVE-2025-6218.svg) ![forks](https://img.shields.io/github/forks/ignis-sec/CVE-2025-6218.svg)


## CVE-2025-6019
 A Local Privilege Escalation (LPE) vulnerability was found in libblockdev. Generally, the "allow_active" setting in Polkit permits a physically present user to take certain actions based on the session type. Due to the way libblockdev interacts with the udisks daemon, an "allow_active" user on a system may be able escalate to full root privileges on the target host. Normally, udisks mounts user-provided filesystem images with security flags like nosuid and nodev to prevent privilege escalation.  However, a local attacker can create a specially crafted XFS image containing a SUID-root shell, then trick udisks into resizing it. This mounts their malicious filesystem with root privileges, allowing them to execute their SUID-root shell and gain complete control of the system.

- [https://github.com/neko205-mx/CVE-2025-6019_Exploit](https://github.com/neko205-mx/CVE-2025-6019_Exploit) :  ![starts](https://img.shields.io/github/stars/neko205-mx/CVE-2025-6019_Exploit.svg) ![forks](https://img.shields.io/github/forks/neko205-mx/CVE-2025-6019_Exploit.svg)


## CVE-2024-54085
availability.

- [https://github.com/Mr-Zapi/CVE-2024-54085](https://github.com/Mr-Zapi/CVE-2024-54085) :  ![starts](https://img.shields.io/github/stars/Mr-Zapi/CVE-2024-54085.svg) ![forks](https://img.shields.io/github/forks/Mr-Zapi/CVE-2024-54085.svg)


## CVE-2024-43425
 A flaw was found in Moodle. Additional restrictions are required to avoid a remote code execution risk in calculated question types. Note: This requires the capability to add/update questions.

- [https://github.com/aninfosec/CVE-2024-43425-Poc](https://github.com/aninfosec/CVE-2024-43425-Poc) :  ![starts](https://img.shields.io/github/stars/aninfosec/CVE-2024-43425-Poc.svg) ![forks](https://img.shields.io/github/forks/aninfosec/CVE-2024-43425-Poc.svg)


## CVE-2024-4367
 A type check was missing when handling fonts in PDF.js, which would allow arbitrary JavaScript execution in the PDF.js context. This vulnerability affects Firefox  126, Firefox ESR  115.11, and Thunderbird  115.11.

- [https://github.com/pS3ud0RAnD0m/cve-2024-4367-poc](https://github.com/pS3ud0RAnD0m/cve-2024-4367-poc) :  ![starts](https://img.shields.io/github/stars/pS3ud0RAnD0m/cve-2024-4367-poc.svg) ![forks](https://img.shields.io/github/forks/pS3ud0RAnD0m/cve-2024-4367-poc.svg)


## CVE-2022-32250
 net/netfilter/nf_tables_api.c in the Linux kernel through 5.18.1 allows a local user (able to create user/net namespaces) to escalate privileges to root because an incorrect NFT_STATEFUL_EXPR check leads to a use-after-free.

- [https://github.com/g3un/cve-2022-32250](https://github.com/g3un/cve-2022-32250) :  ![starts](https://img.shields.io/github/stars/g3un/cve-2022-32250.svg) ![forks](https://img.shields.io/github/forks/g3un/cve-2022-32250.svg)
- [https://github.com/KuanKuanQAQ/cve-testing](https://github.com/KuanKuanQAQ/cve-testing) :  ![starts](https://img.shields.io/github/stars/KuanKuanQAQ/cve-testing.svg) ![forks](https://img.shields.io/github/forks/KuanKuanQAQ/cve-testing.svg)


## CVE-2022-24785
 Moment.js is a JavaScript date library for parsing, validating, manipulating, and formatting dates. A path traversal vulnerability impacts npm (server) users of Moment.js between versions 1.0.1 and 2.29.1, especially if a user-provided locale string is directly used to switch moment locale. This problem is patched in 2.29.2, and the patch can be applied to all affected versions. As a workaround, sanitize the user-provided locale name before passing it to Moment.js.

- [https://github.com/pS3ud0RAnD0m/cve-2022-24785-poc-lab](https://github.com/pS3ud0RAnD0m/cve-2022-24785-poc-lab) :  ![starts](https://img.shields.io/github/stars/pS3ud0RAnD0m/cve-2022-24785-poc-lab.svg) ![forks](https://img.shields.io/github/forks/pS3ud0RAnD0m/cve-2022-24785-poc-lab.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/ZapcoMan/spring4shell-vulnerable-application](https://github.com/ZapcoMan/spring4shell-vulnerable-application) :  ![starts](https://img.shields.io/github/stars/ZapcoMan/spring4shell-vulnerable-application.svg) ![forks](https://img.shields.io/github/forks/ZapcoMan/spring4shell-vulnerable-application.svg)


## CVE-2020-11984
 Apache HTTP server 2.4.32 to 2.4.44 mod_proxy_uwsgi info disclosure and possible RCE

- [https://github.com/masahiro331/CVE-2020-11984](https://github.com/masahiro331/CVE-2020-11984) :  ![starts](https://img.shields.io/github/stars/masahiro331/CVE-2020-11984.svg) ![forks](https://img.shields.io/github/forks/masahiro331/CVE-2020-11984.svg)


## CVE-2016-0957
 Dispatcher before 4.1.5 in Adobe Experience Manager 5.6.1, 6.0.0, and 6.1.0 does not properly implement a URL filter, which allows remote attackers to bypass dispatcher rules via unspecified vectors.

- [https://github.com/fuckwbored/CVE-2016-0957-payloads](https://github.com/fuckwbored/CVE-2016-0957-payloads) :  ![starts](https://img.shields.io/github/stars/fuckwbored/CVE-2016-0957-payloads.svg) ![forks](https://img.shields.io/github/forks/fuckwbored/CVE-2016-0957-payloads.svg)

