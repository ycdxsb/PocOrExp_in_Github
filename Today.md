# Update 2025-04-28
## CVE-2025-32432
 Craft is a flexible, user-friendly CMS for creating custom digital experiences on the web and beyond. Starting from version 3.0.0-RC1 to before 3.9.15, 4.0.0-RC1 to before 4.14.15, and 5.0.0-RC1 to before 5.6.17, Craft is vulnerable to remote code execution. This is a high-impact, low-complexity attack vector. This issue has been patched in versions 3.9.15, 4.14.15, and 5.6.17, and is an additional fix for CVE-2023-41892.

- [https://github.com/Chocapikk/CVE-2025-32432](https://github.com/Chocapikk/CVE-2025-32432) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2025-32432.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2025-32432.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/emadshanab/CVE-2025-29927](https://github.com/emadshanab/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/emadshanab/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/emadshanab/CVE-2025-29927.svg)


## CVE-2025-2294
 The Kubio AI Page Builder plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 2.5.1 via thekubio_hybrid_theme_load_template function. This makes it possible for unauthenticated attackers to include and execute arbitrary files on the server, allowing the execution of any PHP code in those files. This can be used to bypass access controls, obtain sensitive data, or achieve code execution in cases where images and other “safe” file types can be uploaded and included.

- [https://github.com/romanedutov/CVE-2025-2294](https://github.com/romanedutov/CVE-2025-2294) :  ![starts](https://img.shields.io/github/stars/romanedutov/CVE-2025-2294.svg) ![forks](https://img.shields.io/github/forks/romanedutov/CVE-2025-2294.svg)


## CVE-2025-1974
 A security issue was discovered in Kubernetes where under certain conditions, an unauthenticated attacker with access to the pod network can achieve arbitrary code execution in the context of the ingress-nginx controller. This can lead to disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)

- [https://github.com/chhhd/CVE-2025-1974](https://github.com/chhhd/CVE-2025-1974) :  ![starts](https://img.shields.io/github/stars/chhhd/CVE-2025-1974.svg) ![forks](https://img.shields.io/github/forks/chhhd/CVE-2025-1974.svg)


## CVE-2024-31317
 In multiple functions of ZygoteProcess.java, there is a possible way to achieve code execution as any app via WRITE_SECURE_SETTINGS due to unsafe deserialization. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/agg23/cve-2024-31317](https://github.com/agg23/cve-2024-31317) :  ![starts](https://img.shields.io/github/stars/agg23/cve-2024-31317.svg) ![forks](https://img.shields.io/github/forks/agg23/cve-2024-31317.svg)


## CVE-2024-27808
 The issue was addressed with improved memory handling. This issue is fixed in tvOS 17.5, visionOS 1.2, Safari 17.5, iOS 17.5 and iPadOS 17.5, watchOS 10.5, macOS Sonoma 14.5. Processing web content may lead to arbitrary code execution.

- [https://github.com/Leandrobts/CVE-2024-27808.github.io](https://github.com/Leandrobts/CVE-2024-27808.github.io) :  ![starts](https://img.shields.io/github/stars/Leandrobts/CVE-2024-27808.github.io.svg) ![forks](https://img.shields.io/github/forks/Leandrobts/CVE-2024-27808.github.io.svg)


## CVE-2023-39361
 Cacti is an open source operational monitoring and fault management framework. Affected versions are subject to a SQL injection discovered in graph_view.php. Since guest users can access graph_view.php without authentication by default, if guest users are being utilized in an enabled state, there could be the potential for significant damage. Attackers may exploit this vulnerability, and there may be possibilities for actions such as the usurpation of administrative privileges or remote code execution. This issue has been addressed in version 1.2.25. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/ChoDeokCheol/CVE-2023-39361](https://github.com/ChoDeokCheol/CVE-2023-39361) :  ![starts](https://img.shields.io/github/stars/ChoDeokCheol/CVE-2023-39361.svg) ![forks](https://img.shields.io/github/forks/ChoDeokCheol/CVE-2023-39361.svg)


## CVE-2023-1389
 TP-Link Archer AX21 (AX1800) firmware versions before 1.1.4 Build 20230219 contained a command injection vulnerability in the country form of the /cgi-bin/luci;stok=/locale endpoint on the web management interface. Specifically, the country parameter of the write operation was not sanitized before being used in a call to popen(), allowing an unauthenticated attacker to inject commands, which would be run as root, with a simple POST request.

- [https://github.com/ibrahimsql/CVE2023-1389](https://github.com/ibrahimsql/CVE2023-1389) :  ![starts](https://img.shields.io/github/stars/ibrahimsql/CVE2023-1389.svg) ![forks](https://img.shields.io/github/forks/ibrahimsql/CVE2023-1389.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/DanielFEXKEX/CVE-Scanner](https://github.com/DanielFEXKEX/CVE-Scanner) :  ![starts](https://img.shields.io/github/stars/DanielFEXKEX/CVE-Scanner.svg) ![forks](https://img.shields.io/github/forks/DanielFEXKEX/CVE-Scanner.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/cypherlobo/DirtyPipe-BSI](https://github.com/cypherlobo/DirtyPipe-BSI) :  ![starts](https://img.shields.io/github/stars/cypherlobo/DirtyPipe-BSI.svg) ![forks](https://img.shields.io/github/forks/cypherlobo/DirtyPipe-BSI.svg)


## CVE-2021-45046
 It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in an information leak and remote code execution in some environments and local code execution in all environments. Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7) fix this issue by removing support for message lookup patterns and disabling JNDI functionality by default.

- [https://github.com/DanielFEXKEX/CVE-Scanner](https://github.com/DanielFEXKEX/CVE-Scanner) :  ![starts](https://img.shields.io/github/stars/DanielFEXKEX/CVE-Scanner.svg) ![forks](https://img.shields.io/github/forks/DanielFEXKEX/CVE-Scanner.svg)


## CVE-2021-42287
 Active Directory Domain Services Elevation of Privilege Vulnerability

- [https://github.com/DanielFEXKEX/CVE-Scanner](https://github.com/DanielFEXKEX/CVE-Scanner) :  ![starts](https://img.shields.io/github/stars/DanielFEXKEX/CVE-Scanner.svg) ![forks](https://img.shields.io/github/forks/DanielFEXKEX/CVE-Scanner.svg)


## CVE-2021-42278
 Active Directory Domain Services Elevation of Privilege Vulnerability

- [https://github.com/DanielFEXKEX/CVE-Scanner](https://github.com/DanielFEXKEX/CVE-Scanner) :  ![starts](https://img.shields.io/github/stars/DanielFEXKEX/CVE-Scanner.svg) ![forks](https://img.shields.io/github/forks/DanielFEXKEX/CVE-Scanner.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/puckiestyle/CVE-2021-41773](https://github.com/puckiestyle/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-41773.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/DanielFEXKEX/CVE-Scanner](https://github.com/DanielFEXKEX/CVE-Scanner) :  ![starts](https://img.shields.io/github/stars/DanielFEXKEX/CVE-Scanner.svg) ![forks](https://img.shields.io/github/forks/DanielFEXKEX/CVE-Scanner.svg)


## CVE-2020-1362
 An elevation of privilege vulnerability exists in the way that the Windows WalletService handles objects in memory, aka 'Windows WalletService Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-1344, CVE-2020-1369.

- [https://github.com/asdyxcyxc/CVE-2020-1362](https://github.com/asdyxcyxc/CVE-2020-1362) :  ![starts](https://img.shields.io/github/stars/asdyxcyxc/CVE-2020-1362.svg) ![forks](https://img.shields.io/github/forks/asdyxcyxc/CVE-2020-1362.svg)


## CVE-2020-0796
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

- [https://github.com/DanielFEXKEX/CVE-Scanner](https://github.com/DanielFEXKEX/CVE-Scanner) :  ![starts](https://img.shields.io/github/stars/DanielFEXKEX/CVE-Scanner.svg) ![forks](https://img.shields.io/github/forks/DanielFEXKEX/CVE-Scanner.svg)


## CVE-2019-19781
 An issue was discovered in Citrix Application Delivery Controller (ADC) and Gateway 10.5, 11.1, 12.0, 12.1, and 13.0. They allow Directory Traversal.

- [https://github.com/hyunjin0334/CVE-2019-19781](https://github.com/hyunjin0334/CVE-2019-19781) :  ![starts](https://img.shields.io/github/stars/hyunjin0334/CVE-2019-19781.svg) ![forks](https://img.shields.io/github/forks/hyunjin0334/CVE-2019-19781.svg)


## CVE-2018-15133
 In Laravel Framework through 5.5.40 and 5.6.x through 5.6.29, remote code execution might occur as a result of an unserialize call on a potentially untrusted X-XSRF-TOKEN value. This involves the decrypt method in Illuminate/Encryption/Encrypter.php and PendingBroadcast in gadgetchains/Laravel/RCE/3/chain.php in phpggc. The attacker must know the application key, which normally would never occur, but could happen if the attacker previously had privileged access or successfully accomplished a previous attack.

- [https://github.com/yeahhbean/Laravel-CVE-2018-15133](https://github.com/yeahhbean/Laravel-CVE-2018-15133) :  ![starts](https://img.shields.io/github/stars/yeahhbean/Laravel-CVE-2018-15133.svg) ![forks](https://img.shields.io/github/forks/yeahhbean/Laravel-CVE-2018-15133.svg)


## CVE-2018-7600
 Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations.

- [https://github.com/Dowonkwon/drupal-cve-2018-7600-poc](https://github.com/Dowonkwon/drupal-cve-2018-7600-poc) :  ![starts](https://img.shields.io/github/stars/Dowonkwon/drupal-cve-2018-7600-poc.svg) ![forks](https://img.shields.io/github/forks/Dowonkwon/drupal-cve-2018-7600-poc.svg)


## CVE-2017-8386
 git-shell in git before 2.4.12, 2.5.x before 2.5.6, 2.6.x before 2.6.7, 2.7.x before 2.7.5, 2.8.x before 2.8.5, 2.9.x before 2.9.4, 2.10.x before 2.10.3, 2.11.x before 2.11.2, and 2.12.x before 2.12.3 might allow remote authenticated users to gain privileges via a repository name that starts with a - (dash) character.

- [https://github.com/suz1n/WHS3_vulhub](https://github.com/suz1n/WHS3_vulhub) :  ![starts](https://img.shields.io/github/stars/suz1n/WHS3_vulhub.svg) ![forks](https://img.shields.io/github/forks/suz1n/WHS3_vulhub.svg)


## CVE-2017-8291
 Artifex Ghostscript through 2017-04-26 allows -dSAFER bypass and remote command execution via .rsdparams type confusion with a "/OutputFile (%pipe%" substring in a crafted .eps document that is an input to the gs program, as exploited in the wild in April 2017.

- [https://github.com/shun1403/CVE-2017-8291](https://github.com/shun1403/CVE-2017-8291) :  ![starts](https://img.shields.io/github/stars/shun1403/CVE-2017-8291.svg) ![forks](https://img.shields.io/github/forks/shun1403/CVE-2017-8291.svg)
- [https://github.com/shun1403/PIL-CVE-2017-8291-study](https://github.com/shun1403/PIL-CVE-2017-8291-study) :  ![starts](https://img.shields.io/github/stars/shun1403/PIL-CVE-2017-8291-study.svg) ![forks](https://img.shields.io/github/forks/shun1403/PIL-CVE-2017-8291-study.svg)


## CVE-2017-7529
 Nginx versions since 0.5.6 up to and including 1.13.2 are vulnerable to integer overflow vulnerability in nginx range filter module resulting into leak of potentially sensitive information triggered by specially crafted request.

- [https://github.com/portfolio10/nginx](https://github.com/portfolio10/nginx) :  ![starts](https://img.shields.io/github/stars/portfolio10/nginx.svg) ![forks](https://img.shields.io/github/forks/portfolio10/nginx.svg)


## CVE-2015-2797
 Stack-based buffer overflow in AirTies Air 6372, 5760, 5750, 5650TT, 5453, 5444TT, 5443, 5442, 5343, 5342, 5341, and 5021 DSL modems with firmware 1.0.2.0 and earlier allows remote attackers to execute arbitrary code via a long string in the redirect parameter to cgi-bin/login.

- [https://github.com/Bariskizilkaya/CVE-2015-2797-PoC](https://github.com/Bariskizilkaya/CVE-2015-2797-PoC) :  ![starts](https://img.shields.io/github/stars/Bariskizilkaya/CVE-2015-2797-PoC.svg) ![forks](https://img.shields.io/github/forks/Bariskizilkaya/CVE-2015-2797-PoC.svg)


## CVE-2012-2122
 sql/password.c in Oracle MySQL 5.1.x before 5.1.63, 5.5.x before 5.5.24, and 5.6.x before 5.6.6, and MariaDB 5.1.x before 5.1.62, 5.2.x before 5.2.12, 5.3.x before 5.3.6, and 5.5.x before 5.5.23, when running in certain environments with certain implementations of the memcmp function, allows remote attackers to bypass authentication by repeatedly authenticating with the same incorrect password, which eventually causes a token comparison to succeed due to an improperly-checked return value.

- [https://github.com/subinyy/docker_CVE_2012_2122](https://github.com/subinyy/docker_CVE_2012_2122) :  ![starts](https://img.shields.io/github/stars/subinyy/docker_CVE_2012_2122.svg) ![forks](https://img.shields.io/github/forks/subinyy/docker_CVE_2012_2122.svg)


## CVE-2010-1240
 Adobe Reader and Acrobat 9.x before 9.3.3, and 8.x before 8.2.3 on Windows and Mac OS X, do not restrict the contents of one text field in the Launch File warning dialog, which makes it easier for remote attackers to trick users into executing an arbitrary local program that was specified in a PDF document, as demonstrated by a text field that claims that the Open button will enable the user to read an encrypted message.

- [https://github.com/Jasmoon99/Embedded-PDF](https://github.com/Jasmoon99/Embedded-PDF) :  ![starts](https://img.shields.io/github/stars/Jasmoon99/Embedded-PDF.svg) ![forks](https://img.shields.io/github/forks/Jasmoon99/Embedded-PDF.svg)
- [https://github.com/omarothmann/Embedded-Backdoor-Connection](https://github.com/omarothmann/Embedded-Backdoor-Connection) :  ![starts](https://img.shields.io/github/stars/omarothmann/Embedded-Backdoor-Connection.svg) ![forks](https://img.shields.io/github/forks/omarothmann/Embedded-Backdoor-Connection.svg)
- [https://github.com/asepsaepdin/CVE-2010-1240](https://github.com/asepsaepdin/CVE-2010-1240) :  ![starts](https://img.shields.io/github/stars/asepsaepdin/CVE-2010-1240.svg) ![forks](https://img.shields.io/github/forks/asepsaepdin/CVE-2010-1240.svg)

