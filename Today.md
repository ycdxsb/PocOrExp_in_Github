# Update 2023-04-25
## CVE-2023-21979
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).

- [https://github.com/4ra1n/CVE-2023-21839](https://github.com/4ra1n/CVE-2023-21839) :  ![starts](https://img.shields.io/github/stars/4ra1n/CVE-2023-21839.svg) ![forks](https://img.shields.io/github/forks/4ra1n/CVE-2023-21839.svg)


## CVE-2023-21931
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).

- [https://github.com/4ra1n/CVE-2023-21839](https://github.com/4ra1n/CVE-2023-21839) :  ![starts](https://img.shields.io/github/stars/4ra1n/CVE-2023-21839.svg) ![forks](https://img.shields.io/github/forks/4ra1n/CVE-2023-21839.svg)


## CVE-2022-40799
 Data Integrity Failure in 'Backup Config' in D-Link DNR-322L &lt;= 2.60B15 allows an authenticated attacker to execute OS level commands on the device.

- [https://github.com/rtfmkiesel/CVE-2022-40799](https://github.com/rtfmkiesel/CVE-2022-40799) :  ![starts](https://img.shields.io/github/stars/rtfmkiesel/CVE-2022-40799.svg) ![forks](https://img.shields.io/github/forks/rtfmkiesel/CVE-2022-40799.svg)


## CVE-2022-35914
 /vendor/htmlawed/htmlawed/htmLawedTest.php in the htmlawed module for GLPI through 10.0.2 allows PHP code injection.

- [https://github.com/0xGabe/CVE-2022-35914](https://github.com/0xGabe/CVE-2022-35914) :  ![starts](https://img.shields.io/github/stars/0xGabe/CVE-2022-35914.svg) ![forks](https://img.shields.io/github/forks/0xGabe/CVE-2022-35914.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/zangcc/CVE-2022-22965-rexbb](https://github.com/zangcc/CVE-2022-22965-rexbb) :  ![starts](https://img.shields.io/github/stars/zangcc/CVE-2022-22965-rexbb.svg) ![forks](https://img.shields.io/github/forks/zangcc/CVE-2022-22965-rexbb.svg)
- [https://github.com/Wrin9/CVE-2022-22965](https://github.com/Wrin9/CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/Wrin9/CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/Wrin9/CVE-2022-22965.svg)


## CVE-2022-4450
 The function PEM_read_bio_ex() reads a PEM file from a BIO and parses and decodes the &quot;name&quot; (e.g. &quot;CERTIFICATE&quot;), any header data and the payload data. If the function succeeds then the &quot;name_out&quot;, &quot;header&quot; and &quot;data&quot; arguments are populated with pointers to buffers containing the relevant decoded data. The caller is responsible for freeing those buffers. It is possible to construct a PEM file that results in 0 bytes of payload data. In this case PEM_read_bio_ex() will return a failure code but will populate the header argument with a pointer to a buffer that has already been freed. If the caller also frees this buffer then a double free will occur. This will most likely lead to a crash. This could be exploited by an attacker who has the ability to supply malicious PEM files for parsing to achieve a denial of service attack. The functions PEM_read_bio() and PEM_read() are simple wrappers around PEM_read_bio_ex() and therefore these functions are also directly affected. These functions are also called indirectly by a number of other OpenSSL functions including PEM_X509_INFO_read_bio_ex() and SSL_CTX_use_serverinfo_file() which are also vulnerable. Some OpenSSL internal uses of these functions are not vulnerable because the caller does not free the header argument if PEM_read_bio_ex() returns a failure code. These locations include the PEM_read_bio_TYPE() functions as well as the decoders introduced in OpenSSL 3.0. The OpenSSL asn1parse command line application is also impacted by this issue.

- [https://github.com/nidhi7598/OPENSSL_1.1.1g_G3_CVE-2022-4450](https://github.com/nidhi7598/OPENSSL_1.1.1g_G3_CVE-2022-4450) :  ![starts](https://img.shields.io/github/stars/nidhi7598/OPENSSL_1.1.1g_G3_CVE-2022-4450.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/OPENSSL_1.1.1g_G3_CVE-2022-4450.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/shiomiyan/CVE-2021-41773](https://github.com/shiomiyan/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/shiomiyan/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/shiomiyan/CVE-2021-41773.svg)
- [https://github.com/Plunder283/CVE-2021-41773](https://github.com/Plunder283/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Plunder283/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Plunder283/CVE-2021-41773.svg)


## CVE-2021-29447
 Wordpress is an open source CMS. A user with the ability to upload files (like an Author) can exploit an XML parsing issue in the Media Library leading to XXE attacks. This requires WordPress installation to be using PHP 8. Access to internal files is possible in a successful XXE attack. This has been patched in WordPress version 5.7.1, along with the older affected versions via a minor release. We strongly recommend you keep auto-updates enabled.

- [https://github.com/andyhsu024/CVE-2021-29447](https://github.com/andyhsu024/CVE-2021-29447) :  ![starts](https://img.shields.io/github/stars/andyhsu024/CVE-2021-29447.svg) ![forks](https://img.shields.io/github/forks/andyhsu024/CVE-2021-29447.svg)


## CVE-2021-2175
 Vulnerability in the Database Vault component of Oracle Database Server. Supported versions that are affected are 12.1.0.2, 12.2.0.1, 18c and 19c. Easily exploitable vulnerability allows high privileged attacker having Create Any View, Select Any View privilege with network access via Oracle Net to compromise Database Vault. Successful attacks of this vulnerability can result in unauthorized read access to a subset of Database Vault accessible data. CVSS 3.1 Base Score 2.7 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N).

- [https://github.com/emad-almousa/CVE-2021-2175](https://github.com/emad-almousa/CVE-2021-2175) :  ![starts](https://img.shields.io/github/stars/emad-almousa/CVE-2021-2175.svg) ![forks](https://img.shields.io/github/forks/emad-almousa/CVE-2021-2175.svg)


## CVE-2019-1010298
 Linaro/OP-TEE OP-TEE 3.3.0 and earlier is affected by: Buffer Overflow. The impact is: Code execution in the context of TEE core (kernel). The component is: optee_os. The fixed version is: 3.4.0 and later.

- [https://github.com/RKX1209/CVE-2019-1010298](https://github.com/RKX1209/CVE-2019-1010298) :  ![starts](https://img.shields.io/github/stars/RKX1209/CVE-2019-1010298.svg) ![forks](https://img.shields.io/github/forks/RKX1209/CVE-2019-1010298.svg)


## CVE-2019-13272
 In the Linux kernel before 5.1.17, ptrace_link in kernel/ptrace.c mishandles the recording of the credentials of a process that wants to create a ptrace relationship, which allows local users to obtain root access by leveraging certain scenarios with a parent-child process relationship, where a parent drops privileges and calls execve (potentially allowing control by an attacker). One contributing factor is an object lifetime issue (which can also cause a panic). Another contributing factor is incorrect marking of a ptrace relationship as privileged, which is exploitable through (for example) Polkit's pkexec helper with PTRACE_TRACEME. NOTE: SELinux deny_ptrace might be a usable workaround in some environments.

- [https://github.com/Al1ex/LinuxEelvation](https://github.com/Al1ex/LinuxEelvation) :  ![starts](https://img.shields.io/github/stars/Al1ex/LinuxEelvation.svg) ![forks](https://img.shields.io/github/forks/Al1ex/LinuxEelvation.svg)
- [https://github.com/jas502n/CVE-2019-13272](https://github.com/jas502n/CVE-2019-13272) :  ![starts](https://img.shields.io/github/stars/jas502n/CVE-2019-13272.svg) ![forks](https://img.shields.io/github/forks/jas502n/CVE-2019-13272.svg)
- [https://github.com/oneoy/CVE-2019-13272](https://github.com/oneoy/CVE-2019-13272) :  ![starts](https://img.shields.io/github/stars/oneoy/CVE-2019-13272.svg) ![forks](https://img.shields.io/github/forks/oneoy/CVE-2019-13272.svg)
- [https://github.com/Thathsarani24/CVE2019-13272](https://github.com/Thathsarani24/CVE2019-13272) :  ![starts](https://img.shields.io/github/stars/Thathsarani24/CVE2019-13272.svg) ![forks](https://img.shields.io/github/forks/Thathsarani24/CVE2019-13272.svg)

