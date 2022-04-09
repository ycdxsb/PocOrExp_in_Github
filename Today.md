# Update 2022-04-09
## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/t3amj3ff/Spring4ShellPoC](https://github.com/t3amj3ff/Spring4ShellPoC) :  ![starts](https://img.shields.io/github/stars/t3amj3ff/Spring4ShellPoC.svg) ![forks](https://img.shields.io/github/forks/t3amj3ff/Spring4ShellPoC.svg)
- [https://github.com/Will-Beninger/CVE-2022-22965_SpringShell](https://github.com/Will-Beninger/CVE-2022-22965_SpringShell) :  ![starts](https://img.shields.io/github/stars/Will-Beninger/CVE-2022-22965_SpringShell.svg) ![forks](https://img.shields.io/github/forks/Will-Beninger/CVE-2022-22965_SpringShell.svg)


## CVE-2022-22947
 In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

- [https://github.com/dbgee/CVE-2022-22947](https://github.com/dbgee/CVE-2022-22947) :  ![starts](https://img.shields.io/github/stars/dbgee/CVE-2022-22947.svg) ![forks](https://img.shields.io/github/forks/dbgee/CVE-2022-22947.svg)


## CVE-2021-46075
 A Privilege Escalation vulnerability exists in Sourcecodester Vehicle Service Management System 1.0. Staff account users can access the admin resources and perform CRUD Operations.

- [https://github.com/plsanu/CVE-2021-46075](https://github.com/plsanu/CVE-2021-46075) :  ![starts](https://img.shields.io/github/stars/plsanu/CVE-2021-46075.svg) ![forks](https://img.shields.io/github/forks/plsanu/CVE-2021-46075.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/Adash7/CVE-2021-42013](https://github.com/Adash7/CVE-2021-42013) :  ![starts](https://img.shields.io/github/stars/Adash7/CVE-2021-42013.svg) ![forks](https://img.shields.io/github/forks/Adash7/CVE-2021-42013.svg)


## CVE-2021-40223
 Rittal CMC PU III Web management (version V3.11.00_2) fails to sanitize user input on several parameters of the configuration (User Configuration dialog, Task Configuration dialog and set logging filter dialog). This allows an attacker to backdoor the device with HTML and browser-interpreted content (such as JavaScript or other client-side scripts). The XSS payload will be triggered when the user accesses some specific sections of the application.

- [https://github.com/asang17/CVE-2021-40223](https://github.com/asang17/CVE-2021-40223) :  ![starts](https://img.shields.io/github/stars/asang17/CVE-2021-40223.svg) ![forks](https://img.shields.io/github/forks/asang17/CVE-2021-40223.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/Ph4nt0mh4x0r/auto-CVE-2021-4034](https://github.com/Ph4nt0mh4x0r/auto-CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Ph4nt0mh4x0r/auto-CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Ph4nt0mh4x0r/auto-CVE-2021-4034.svg)
- [https://github.com/defhacks/cve-2021-4034](https://github.com/defhacks/cve-2021-4034) :  ![starts](https://img.shields.io/github/stars/defhacks/cve-2021-4034.svg) ![forks](https://img.shields.io/github/forks/defhacks/cve-2021-4034.svg)
- [https://github.com/k4u5h41/CVE-2021-4034](https://github.com/k4u5h41/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/k4u5h41/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/k4u5h41/CVE-2021-4034.svg)


## CVE-2021-0520
 In several functions of MemoryFileSystem.cpp and related files, there is a possible use after free due to a race condition. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-11 Android-10Android ID: A-176237595

- [https://github.com/nanopathi/frameworks_av_AOSP10_r33_CVE-2021-0520](https://github.com/nanopathi/frameworks_av_AOSP10_r33_CVE-2021-0520) :  ![starts](https://img.shields.io/github/stars/nanopathi/frameworks_av_AOSP10_r33_CVE-2021-0520.svg) ![forks](https://img.shields.io/github/forks/nanopathi/frameworks_av_AOSP10_r33_CVE-2021-0520.svg)


## CVE-2020-28653
 Zoho ManageEngine OpManager Stable build before 125203 (and Released build before 125233) allows Remote Code Execution via the Smart Update Manager (SUM) servlet.

- [https://github.com/mr-r3bot/ManageEngine-CVE-2020-28653](https://github.com/mr-r3bot/ManageEngine-CVE-2020-28653) :  ![starts](https://img.shields.io/github/stars/mr-r3bot/ManageEngine-CVE-2020-28653.svg) ![forks](https://img.shields.io/github/forks/mr-r3bot/ManageEngine-CVE-2020-28653.svg)


## CVE-2020-5410
 Spring Cloud Config, versions 2.2.x prior to 2.2.3, versions 2.1.x prior to 2.1.9, and older unsupported versions allow applications to serve arbitrary configuration files through the spring-cloud-config-server module. A malicious user, or attacker, can send a request using a specially crafted URL that can lead to a directory traversal attack.

- [https://github.com/Corgizz/SpringCloud](https://github.com/Corgizz/SpringCloud) :  ![starts](https://img.shields.io/github/stars/Corgizz/SpringCloud.svg) ![forks](https://img.shields.io/github/forks/Corgizz/SpringCloud.svg)


## CVE-2019-3799
 Spring Cloud Config, versions 2.1.x prior to 2.1.2, versions 2.0.x prior to 2.0.4, and versions 1.4.x prior to 1.4.6, and older unsupported versions allow applications to serve arbitrary configuration files through the spring-cloud-config-server module. A malicious user, or attacker, can send a request using a specially crafted URL that can lead a directory traversal attack.

- [https://github.com/Corgizz/SpringCloud](https://github.com/Corgizz/SpringCloud) :  ![starts](https://img.shields.io/github/stars/Corgizz/SpringCloud.svg) ![forks](https://img.shields.io/github/forks/Corgizz/SpringCloud.svg)


## CVE-2018-15982
 Flash Player versions 31.0.0.153 and earlier, and 31.0.0.108 and earlier have a use after free vulnerability. Successful exploitation could lead to arbitrary code execution.

- [https://github.com/SyFi/CVE-2018-15982](https://github.com/SyFi/CVE-2018-15982) :  ![starts](https://img.shields.io/github/stars/SyFi/CVE-2018-15982.svg) ![forks](https://img.shields.io/github/forks/SyFi/CVE-2018-15982.svg)
- [https://github.com/JasonLOU/CVE_2018_15982](https://github.com/JasonLOU/CVE_2018_15982) :  ![starts](https://img.shields.io/github/stars/JasonLOU/CVE_2018_15982.svg) ![forks](https://img.shields.io/github/forks/JasonLOU/CVE_2018_15982.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka &quot;Dirty COW.&quot;

- [https://github.com/ArkAngeL43/CVE-2016-5195](https://github.com/ArkAngeL43/CVE-2016-5195) :  ![starts](https://img.shields.io/github/stars/ArkAngeL43/CVE-2016-5195.svg) ![forks](https://img.shields.io/github/forks/ArkAngeL43/CVE-2016-5195.svg)

