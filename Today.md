# Update 2025-07-09
## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/MAAYTHM/CVE-2025-32462_32463-Lab](https://github.com/MAAYTHM/CVE-2025-32462_32463-Lab) :  ![starts](https://img.shields.io/github/stars/MAAYTHM/CVE-2025-32462_32463-Lab.svg) ![forks](https://img.shields.io/github/forks/MAAYTHM/CVE-2025-32462_32463-Lab.svg)


## CVE-2025-32462
 Sudo before 1.9.17p1, when used with a sudoers file that specifies a host that is neither the current host nor ALL, allows listed users to execute commands on unintended machines.

- [https://github.com/MAAYTHM/CVE-2025-32462_32463-Lab](https://github.com/MAAYTHM/CVE-2025-32462_32463-Lab) :  ![starts](https://img.shields.io/github/stars/MAAYTHM/CVE-2025-32462_32463-Lab.svg) ![forks](https://img.shields.io/github/forks/MAAYTHM/CVE-2025-32462_32463-Lab.svg)


## CVE-2025-32023
 Redis is an open source, in-memory database that persists on disk. From 2.8 to before 8.0.3, 7.4.5, 7.2.10, and 6.2.19, an authenticated user may use a specially crafted string to trigger a stack/heap out of bounds write on hyperloglog operations, potentially leading to remote code execution. The bug likely affects all Redis versions with hyperloglog operations implemented. This vulnerability is fixed in 8.0.3, 7.4.5, 7.2.10, and 6.2.19. An additional workaround to mitigate the problem without patching the redis-server executable is to prevent users from executing hyperloglog operations. This can be done using ACL to restrict HLL commands.

- [https://github.com/leesh3288/CVE-2025-32023](https://github.com/leesh3288/CVE-2025-32023) :  ![starts](https://img.shields.io/github/stars/leesh3288/CVE-2025-32023.svg) ![forks](https://img.shields.io/github/forks/leesh3288/CVE-2025-32023.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/decyjphr-workspace/CVE-2025-29927](https://github.com/decyjphr-workspace/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/decyjphr-workspace/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/decyjphr-workspace/CVE-2025-29927.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/GongWook/CVE-2025-24813](https://github.com/GongWook/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/GongWook/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/GongWook/CVE-2025-24813.svg)


## CVE-2025-6554
 Type confusion in V8 in Google Chrome prior to 138.0.7204.96 allowed a remote attacker to perform arbitrary read/write via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/PwnToday/CVE-2025-6554](https://github.com/PwnToday/CVE-2025-6554) :  ![starts](https://img.shields.io/github/stars/PwnToday/CVE-2025-6554.svg) ![forks](https://img.shields.io/github/forks/PwnToday/CVE-2025-6554.svg)


## CVE-2025-4870
 A vulnerability classified as critical was found in itsourcecode Restaurant Management System 1.0. This vulnerability affects unknown code of the file /admin/menu_save.php. The manipulation of the argument menu leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/Sq-CC/CVE-2025-48703](https://github.com/Sq-CC/CVE-2025-48703) :  ![starts](https://img.shields.io/github/stars/Sq-CC/CVE-2025-48703.svg) ![forks](https://img.shields.io/github/forks/Sq-CC/CVE-2025-48703.svg)


## CVE-2025-4781
 A vulnerability classified as critical has been found in PHPGurukul Park Ticketing Management System 2.0. Affected is an unknown function of the file /forgot-password.php. The manipulation of the argument email/contactno leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/pevinkumar10/CVE-2025-47812](https://github.com/pevinkumar10/CVE-2025-47812) :  ![starts](https://img.shields.io/github/stars/pevinkumar10/CVE-2025-47812.svg) ![forks](https://img.shields.io/github/forks/pevinkumar10/CVE-2025-47812.svg)


## CVE-2024-51567
 upgrademysqlstatus in databases/views.py in CyberPanel (aka Cyber Panel) before 5b08cd6 allows remote attackers to bypass authentication and execute arbitrary commands via /dataBases/upgrademysqlstatus by bypassing secMiddleware (which is only for a POST request) and using shell metacharacters in the statusfile property, as exploited in the wild in October 2024 by PSAUX. Versions through 2.3.6 and (unpatched) 2.3.7 are affected.

- [https://github.com/ajayalf/CVE-2024-51567](https://github.com/ajayalf/CVE-2024-51567) :  ![starts](https://img.shields.io/github/stars/ajayalf/CVE-2024-51567.svg) ![forks](https://img.shields.io/github/forks/ajayalf/CVE-2024-51567.svg)


## CVE-2024-47773
 Discourse is an open source platform for community discussion. An attacker can make several XHR requests until the cache is poisoned with a response without any preloaded data. This issue only affects anonymous visitors of the site. This problem has been patched in the latest version of Discourse. Users are advised to upgrade. Users unable to upgrade should disable anonymous cache by setting the `DISCOURSE_DISABLE_ANON_CACHE` environment variable to a non-empty value.

- [https://github.com/ibrahmsql/CVE-2024-47773](https://github.com/ibrahmsql/CVE-2024-47773) :  ![starts](https://img.shields.io/github/stars/ibrahmsql/CVE-2024-47773.svg) ![forks](https://img.shields.io/github/forks/ibrahmsql/CVE-2024-47773.svg)


## CVE-2024-9264
 The SQL Expressions experimental feature of Grafana allows for the evaluation of `duckdb` queries containing user input. These queries are insufficiently sanitized before being passed to `duckdb`, leading to a command injection and local file inclusion vulnerability. Any user with the VIEWER or higher permission is capable of executing this attack.  The `duckdb` binary must be present in Grafana's $PATH for this attack to function; by default, this binary is not installed in Grafana distributions.

- [https://github.com/rvizx/CVE-2024-9264](https://github.com/rvizx/CVE-2024-9264) :  ![starts](https://img.shields.io/github/stars/rvizx/CVE-2024-9264.svg) ![forks](https://img.shields.io/github/forks/rvizx/CVE-2024-9264.svg)


## CVE-2024-5243
The specific flaw exists within the handling of DNS names. The issue results from the lack of proper validation of the length of user-supplied data prior to copying it to a buffer. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-22523.

- [https://github.com/dilagluc/CVE_2024_5243](https://github.com/dilagluc/CVE_2024_5243) :  ![starts](https://img.shields.io/github/stars/dilagluc/CVE_2024_5243.svg) ![forks](https://img.shields.io/github/forks/dilagluc/CVE_2024_5243.svg)


## CVE-2021-29427
 In Gradle from version 5.1 and before version 7.0 there is a vulnerability which can lead to information disclosure and/or dependency poisoning. Repository content filtering is a security control Gradle introduced to help users specify what repositories are used to resolve specific dependencies. This feature was introduced in the wake of the "A Confusing Dependency" blog post. In some cases, Gradle may ignore content filters and search all repositories for dependencies. This only occurs when repository content filtering is used from within a `pluginManagement` block in a settings file. This may change how dependencies are resolved for Gradle plugins and build scripts. For builds that are vulnerable, there are two risks: 1) Information disclosure: Gradle could make dependency requests to repositories outside your organization and leak internal package identifiers. 2) Dependency poisoning/Dependency confusion: Gradle could download a malicious binary from a repository outside your organization due to name squatting. For a full example and more details refer to the referenced GitHub Security Advisory. The problem has been patched and released with Gradle 7.0. Users relying on this feature should upgrade their build as soon as possible. As a workaround, users may use a company repository which has the right rules for fetching packages from public repositories, or use project level repository content filtering, inside `buildscript.repositories`. This option is available since Gradle 5.1 when the feature was introduced.

- [https://github.com/arsalanraja987/gradle-cve-2021-29427-demo](https://github.com/arsalanraja987/gradle-cve-2021-29427-demo) :  ![starts](https://img.shields.io/github/stars/arsalanraja987/gradle-cve-2021-29427-demo.svg) ![forks](https://img.shields.io/github/forks/arsalanraja987/gradle-cve-2021-29427-demo.svg)


## CVE-2021-29425
 In Apache Commons IO before 2.7, When invoking the method FileNameUtils.normalize with an improper input string, like "//../foo", or "\\..\foo", the result would be the same value, thus possibly providing access to files in the parent directory, but not further above (thus "limited" path traversal), if the calling code would use the result to construct a path value.

- [https://github.com/arsalanraja987/java-cve-2021-29425-tika-xxe](https://github.com/arsalanraja987/java-cve-2021-29425-tika-xxe) :  ![starts](https://img.shields.io/github/stars/arsalanraja987/java-cve-2021-29425-tika-xxe.svg) ![forks](https://img.shields.io/github/forks/arsalanraja987/java-cve-2021-29425-tika-xxe.svg)


## CVE-2021-27568
 An issue was discovered in netplex json-smart-v1 through 2015-10-23 and json-smart-v2 through 2.4. An exception is thrown from a function, but it is not caught, as demonstrated by NumberFormatException. When it is not caught, it may cause programs using the library to crash or expose sensitive information.

- [https://github.com/arsalanraja987/java-insecure-random-cve-2021-27568](https://github.com/arsalanraja987/java-insecure-random-cve-2021-27568) :  ![starts](https://img.shields.io/github/stars/arsalanraja987/java-insecure-random-cve-2021-27568.svg) ![forks](https://img.shields.io/github/forks/arsalanraja987/java-insecure-random-cve-2021-27568.svg)


## CVE-2021-3560
 It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user. This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/Antoine-MANTIS/POC-Bash-CVE-2021-3560](https://github.com/Antoine-MANTIS/POC-Bash-CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/Antoine-MANTIS/POC-Bash-CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/Antoine-MANTIS/POC-Bash-CVE-2021-3560.svg)


## CVE-2020-9488
 Improper validation of certificate with host mismatch in Apache Log4j SMTP appender. This could allow an SMTPS connection to be intercepted by a man-in-the-middle attack which could leak any log messages sent through that appender. Fixed in Apache Log4j 2.12.3 and 2.13.1

- [https://github.com/arsalanraja987/java-log4j-cve-2020-9488](https://github.com/arsalanraja987/java-log4j-cve-2020-9488) :  ![starts](https://img.shields.io/github/stars/arsalanraja987/java-log4j-cve-2020-9488.svg) ![forks](https://img.shields.io/github/forks/arsalanraja987/java-log4j-cve-2020-9488.svg)


## CVE-2019-10743
 All versions of archiver allow attacker to perform a Zip Slip attack via the "unarchive" functions. It is exploited using a specially crafted zip archive, that holds path traversal filenames. When exploited, a filename in a malicious archive is concatenated to the target extraction directory, which results in the final path ending up outside of the target folder. For instance, a zip may hold a file with a "../../file.exe" location and thus break out of the target folder. If an executable or a configuration file is overwritten with a file containing malicious code, the problem can turn into an arbitrary code execution issue quite easily.

- [https://github.com/albisorua/PoC-CVE-2019-10743](https://github.com/albisorua/PoC-CVE-2019-10743) :  ![starts](https://img.shields.io/github/stars/albisorua/PoC-CVE-2019-10743.svg) ![forks](https://img.shields.io/github/forks/albisorua/PoC-CVE-2019-10743.svg)


## CVE-2018-1002202
 zip4j before 1.3.3 is vulnerable to directory traversal, allowing attackers to write to arbitrary files via a ../ (dot dot slash) in a Zip archive entry that is mishandled during extraction. This vulnerability is also known as 'Zip-Slip'.

- [https://github.com/iris-sast/zip4j](https://github.com/iris-sast/zip4j) :  ![starts](https://img.shields.io/github/stars/iris-sast/zip4j.svg) ![forks](https://img.shields.io/github/forks/iris-sast/zip4j.svg)


## CVE-2018-10933
 A vulnerability was found in libssh's server-side state machine before versions 0.7.6 and 0.8.4. A malicious client could create channels without first performing authentication, resulting in unauthorized access.

- [https://github.com/bidaoui4905/CVE-2018-10933](https://github.com/bidaoui4905/CVE-2018-10933) :  ![starts](https://img.shields.io/github/stars/bidaoui4905/CVE-2018-10933.svg) ![forks](https://img.shields.io/github/forks/bidaoui4905/CVE-2018-10933.svg)

