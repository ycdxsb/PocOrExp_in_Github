# Update 2022-04-12
## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/CLincat/vulcat](https://github.com/CLincat/vulcat) :  ![starts](https://img.shields.io/github/stars/CLincat/vulcat.svg) ![forks](https://img.shields.io/github/forks/CLincat/vulcat.svg)


## CVE-2021-41560
 OpenCATS through 0.9.6 allows remote attackers to execute arbitrary code by uploading an executable file via lib/FileUtility.php.

- [https://github.com/Nickguitar/RevCAT](https://github.com/Nickguitar/RevCAT) :  ![starts](https://img.shields.io/github/stars/Nickguitar/RevCAT.svg) ![forks](https://img.shields.io/github/forks/Nickguitar/RevCAT.svg)


## CVE-2021-29441
 Nacos is a platform designed for dynamic service discovery and configuration and service management. In Nacos before version 1.4.1, when configured to use authentication (-Dnacos.core.auth.enabled=true) Nacos uses the AuthFilter servlet filter to enforce authentication. This filter has a backdoor that enables Nacos servers to bypass this filter and therefore skip authentication checks. This mechanism relies on the user-agent HTTP header so it can be easily spoofed. This issue may allow any user to carry out any administrative tasks on the Nacos server.

- [https://github.com/CLincat/vulcat](https://github.com/CLincat/vulcat) :  ![starts](https://img.shields.io/github/stars/CLincat/vulcat.svg) ![forks](https://img.shields.io/github/forks/CLincat/vulcat.svg)


## CVE-2021-0507
 In handle_rc_metamsg_cmd of btif_rc.cc, there is a possible out of bounds write due to a missing bounds check. This could lead to remote code execution over Bluetooth with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-11 Android-8.1 Android-9 Android-10Android ID: A-181860042

- [https://github.com/nanopathi/system_bt_AOSP10_r33_CVE-2021-0507](https://github.com/nanopathi/system_bt_AOSP10_r33_CVE-2021-0507) :  ![starts](https://img.shields.io/github/stars/nanopathi/system_bt_AOSP10_r33_CVE-2021-0507.svg) ![forks](https://img.shields.io/github/forks/nanopathi/system_bt_AOSP10_r33_CVE-2021-0507.svg)


## CVE-2020-15999
 Heap buffer overflow in Freetype in Google Chrome prior to 86.0.4240.111 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/maarlo/CVE-2020-15999](https://github.com/maarlo/CVE-2020-15999) :  ![starts](https://img.shields.io/github/stars/maarlo/CVE-2020-15999.svg) ![forks](https://img.shields.io/github/forks/maarlo/CVE-2020-15999.svg)


## CVE-2020-14750
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/CLincat/vulcat](https://github.com/CLincat/vulcat) :  ![starts](https://img.shields.io/github/stars/CLincat/vulcat.svg) ![forks](https://img.shields.io/github/forks/CLincat/vulcat.svg)


## CVE-2020-3580
 Multiple vulnerabilities in the web services interface of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to conduct cross-site scripting (XSS) attacks against a user of the web services interface of an affected device. The vulnerabilities are due to insufficient validation of user-supplied input by the web services interface of an affected device. An attacker could exploit these vulnerabilities by persuading a user of the interface to click a crafted link. A successful exploit could allow the attacker to execute arbitrary script code in the context of the interface or allow the attacker to access sensitive, browser-based information. Note: These vulnerabilities affect only specific AnyConnect and WebVPN configurations. For more information, see the Vulnerable Products section.

- [https://github.com/CLincat/vulcat](https://github.com/CLincat/vulcat) :  ![starts](https://img.shields.io/github/stars/CLincat/vulcat.svg) ![forks](https://img.shields.io/github/forks/CLincat/vulcat.svg)


## CVE-2018-4185
 In iOS before 11.3, tvOS before 11.3, watchOS before 4.3, and macOS before High Sierra 10.13.4, an information disclosure issue existed in the transition of program state. This issue was addressed with improved state handling.

- [https://github.com/Giler2004/bazad1](https://github.com/Giler2004/bazad1) :  ![starts](https://img.shields.io/github/stars/Giler2004/bazad1.svg) ![forks](https://img.shields.io/github/forks/Giler2004/bazad1.svg)


## CVE-2017-12615
 When running Apache Tomcat 7.0.0 to 7.0.79 on Windows with HTTP PUTs enabled (e.g. via setting the readonly initialisation parameter of the Default to false) it was possible to upload a JSP file to the server via a specially crafted request. This JSP could then be requested and any code it contained would be executed by the server.

- [https://github.com/CLincat/vulcat](https://github.com/CLincat/vulcat) :  ![starts](https://img.shields.io/github/stars/CLincat/vulcat.svg) ![forks](https://img.shields.io/github/forks/CLincat/vulcat.svg)


## CVE-2003-0264
 Multiple buffer overflows in SLMail 5.1.0.4420 allows remote attackers to execute arbitrary code via (1) a long EHLO argument to slmail.exe, (2) a long XTRN argument to slmail.exe, (3) a long string to POPPASSWD, or (4) a long password to the POP3 server.

- [https://github.com/vaknin/SLMail5.5](https://github.com/vaknin/SLMail5.5) :  ![starts](https://img.shields.io/github/stars/vaknin/SLMail5.5.svg) ![forks](https://img.shields.io/github/forks/vaknin/SLMail5.5.svg)

