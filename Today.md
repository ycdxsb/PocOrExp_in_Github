# Update 2022-11-16
## CVE-2022-41082
 Microsoft Exchange Server Remote Code Execution Vulnerability.

- [https://github.com/notareaperbutDR34P3r/http-vuln-CVE-2022-41082](https://github.com/notareaperbutDR34P3r/http-vuln-CVE-2022-41082) :  ![starts](https://img.shields.io/github/stars/notareaperbutDR34P3r/http-vuln-CVE-2022-41082.svg) ![forks](https://img.shields.io/github/forks/notareaperbutDR34P3r/http-vuln-CVE-2022-41082.svg)


## CVE-2022-29464
 Certain WSO2 products allow unrestricted file upload with resultant remote code execution. The attacker must use a /fileupload endpoint with a Content-Disposition directory traversal sequence to reach a directory under the web root, such as a ../../../../repository/deployment/server/webapps directory. This affects WSO2 API Manager 2.2.0 and above through 4.0.0; WSO2 Identity Server 5.2.0 and above through 5.11.0; WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0, and 5.6.0; WSO2 Identity Server as Key Manager 5.3.0 and above through 5.10.0; and WSO2 Enterprise Integrator 6.2.0 and above through 6.6.0.

- [https://github.com/gbrsh/CVE-2022-29464](https://github.com/gbrsh/CVE-2022-29464) :  ![starts](https://img.shields.io/github/stars/gbrsh/CVE-2022-29464.svg) ![forks](https://img.shields.io/github/forks/gbrsh/CVE-2022-29464.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/Azeemering/CVE-2021-44228-DFIR-Notes](https://github.com/Azeemering/CVE-2021-44228-DFIR-Notes) :  ![starts](https://img.shields.io/github/stars/Azeemering/CVE-2021-44228-DFIR-Notes.svg) ![forks](https://img.shields.io/github/forks/Azeemering/CVE-2021-44228-DFIR-Notes.svg)


## CVE-2021-29447
 Wordpress is an open source CMS. A user with the ability to upload files (like an Author) can exploit an XML parsing issue in the Media Library leading to XXE attacks. This requires WordPress installation to be using PHP 8. Access to internal files is possible in a successful XXE attack. This has been patched in WordPress version 5.7.1, along with the older affected versions via a minor release. We strongly recommend you keep auto-updates enabled.

- [https://github.com/thomas-osgood/CVE-2021-29447](https://github.com/thomas-osgood/CVE-2021-29447) :  ![starts](https://img.shields.io/github/stars/thomas-osgood/CVE-2021-29447.svg) ![forks](https://img.shields.io/github/forks/thomas-osgood/CVE-2021-29447.svg)
- [https://github.com/mega8bit/exploit_cve-2021-29447](https://github.com/mega8bit/exploit_cve-2021-29447) :  ![starts](https://img.shields.io/github/stars/mega8bit/exploit_cve-2021-29447.svg) ![forks](https://img.shields.io/github/forks/mega8bit/exploit_cve-2021-29447.svg)


## CVE-2020-9484
 When using Apache Tomcat versions 10.0.0-M1 to 10.0.0-M4, 9.0.0.M1 to 9.0.34, 8.5.0 to 8.5.54 and 7.0.0 to 7.0.103 if a) an attacker is able to control the contents and name of a file on the server; and b) the server is configured to use the PersistenceManager with a FileStore; and c) the PersistenceManager is configured with sessionAttributeValueClassNameFilter=&quot;null&quot; (the default unless a SecurityManager is used) or a sufficiently lax filter to allow the attacker provided object to be deserialized; and d) the attacker knows the relative file path from the storage location used by FileStore to the file the attacker has control over; then, using a specifically crafted request, the attacker will be able to trigger remote code execution via deserialization of the file under their control. Note that all of conditions a) to d) must be true for the attack to succeed.

- [https://github.com/caique-garbim/CVE-2020-9484_Exploit](https://github.com/caique-garbim/CVE-2020-9484_Exploit) :  ![starts](https://img.shields.io/github/stars/caique-garbim/CVE-2020-9484_Exploit.svg) ![forks](https://img.shields.io/github/forks/caique-garbim/CVE-2020-9484_Exploit.svg)


## CVE-2019-13272
 In the Linux kernel before 5.1.17, ptrace_link in kernel/ptrace.c mishandles the recording of the credentials of a process that wants to create a ptrace relationship, which allows local users to obtain root access by leveraging certain scenarios with a parent-child process relationship, where a parent drops privileges and calls execve (potentially allowing control by an attacker). One contributing factor is an object lifetime issue (which can also cause a panic). Another contributing factor is incorrect marking of a ptrace relationship as privileged, which is exploitable through (for example) Polkit's pkexec helper with PTRACE_TRACEME. NOTE: SELinux deny_ptrace might be a usable workaround in some environments.

- [https://github.com/GgKendall/secureCodingDemo](https://github.com/GgKendall/secureCodingDemo) :  ![starts](https://img.shields.io/github/stars/GgKendall/secureCodingDemo.svg) ![forks](https://img.shields.io/github/forks/GgKendall/secureCodingDemo.svg)


## CVE-2019-11043
 In PHP versions 7.1.x below 7.1.33, 7.2.x below 7.2.24 and 7.3.x below 7.3.11 in certain configurations of FPM setup it is possible to cause FPM module to write past allocated buffers into the space reserved for FCGI protocol data, thus opening the possibility of remote code execution.

- [https://github.com/trhacknon/CVE-2019-11043](https://github.com/trhacknon/CVE-2019-11043) :  ![starts](https://img.shields.io/github/stars/trhacknon/CVE-2019-11043.svg) ![forks](https://img.shields.io/github/forks/trhacknon/CVE-2019-11043.svg)


## CVE-2019-9978
 The social-warfare plugin before 3.5.3 for WordPress has stored XSS via the wp-admin/admin-post.php?swp_debug=load_options swp_url parameter, as exploited in the wild in March 2019. This affects Social Warfare and Social Warfare Pro.

- [https://github.com/caique-garbim/CVE-2019-9978_Exploit](https://github.com/caique-garbim/CVE-2019-9978_Exploit) :  ![starts](https://img.shields.io/github/stars/caique-garbim/CVE-2019-9978_Exploit.svg) ![forks](https://img.shields.io/github/forks/caique-garbim/CVE-2019-9978_Exploit.svg)


## CVE-2017-11610
 The XML-RPC server in supervisor before 3.0.1, 3.1.x before 3.1.4, 3.2.x before 3.2.4, and 3.3.x before 3.3.3 allows remote authenticated users to execute arbitrary commands via a crafted XML-RPC request, related to nested supervisord namespace lookups.

- [https://github.com/yaunsky/CVE-2017-11610](https://github.com/yaunsky/CVE-2017-11610) :  ![starts](https://img.shields.io/github/stars/yaunsky/CVE-2017-11610.svg) ![forks](https://img.shields.io/github/forks/yaunsky/CVE-2017-11610.svg)

