# Update 2023-11-03
## CVE-2023-47184
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/rach1tarora/CVE-2023-47184](https://github.com/rach1tarora/CVE-2023-47184) :  ![starts](https://img.shields.io/github/stars/rach1tarora/CVE-2023-47184.svg) ![forks](https://img.shields.io/github/forks/rach1tarora/CVE-2023-47184.svg)


## CVE-2023-46998
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/soy-oreocato/CVE-2023-46998](https://github.com/soy-oreocato/CVE-2023-46998) :  ![starts](https://img.shields.io/github/stars/soy-oreocato/CVE-2023-46998.svg) ![forks](https://img.shields.io/github/forks/soy-oreocato/CVE-2023-46998.svg)


## CVE-2023-46747
 Undisclosed requests may bypass configuration utility authentication, allowing an attacker with network access to the BIG-IP system through the management port and/or self IP addresses to execute arbitrary system commands. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

- [https://github.com/W01fh4cker/CVE-2023-46747-RCE](https://github.com/W01fh4cker/CVE-2023-46747-RCE) :  ![starts](https://img.shields.io/github/stars/W01fh4cker/CVE-2023-46747-RCE.svg) ![forks](https://img.shields.io/github/forks/W01fh4cker/CVE-2023-46747-RCE.svg)
- [https://github.com/fu2x2000/CVE-2023-46747](https://github.com/fu2x2000/CVE-2023-46747) :  ![starts](https://img.shields.io/github/stars/fu2x2000/CVE-2023-46747.svg) ![forks](https://img.shields.io/github/forks/fu2x2000/CVE-2023-46747.svg)
- [https://github.com/y4v4z/CVE-2023-46747-POC](https://github.com/y4v4z/CVE-2023-46747-POC) :  ![starts](https://img.shields.io/github/stars/y4v4z/CVE-2023-46747-POC.svg) ![forks](https://img.shields.io/github/forks/y4v4z/CVE-2023-46747-POC.svg)
- [https://github.com/maniak-academy/Mitigate-CVE-2023-46747](https://github.com/maniak-academy/Mitigate-CVE-2023-46747) :  ![starts](https://img.shields.io/github/stars/maniak-academy/Mitigate-CVE-2023-46747.svg) ![forks](https://img.shields.io/github/forks/maniak-academy/Mitigate-CVE-2023-46747.svg)
- [https://github.com/bijaysenihang/CVE-2023-46747-Mass-RCE](https://github.com/bijaysenihang/CVE-2023-46747-Mass-RCE) :  ![starts](https://img.shields.io/github/stars/bijaysenihang/CVE-2023-46747-Mass-RCE.svg) ![forks](https://img.shields.io/github/forks/bijaysenihang/CVE-2023-46747-Mass-RCE.svg)


## CVE-2023-46604
 Apache ActiveMQ is vulnerable to Remote Code Execution.The vulnerability may allow a remote attacker with network access to a broker to run arbitrary shell commands by manipulating serialized class types in the OpenWire protocol to cause the broker to instantiate any class on the classpath. Users are recommended to upgrade to version 5.15.16, 5.16.7, 5.17.6, or 5.18.3, which fixes this issue.

- [https://github.com/X1r0z/ActiveMQ-RCE](https://github.com/X1r0z/ActiveMQ-RCE) :  ![starts](https://img.shields.io/github/stars/X1r0z/ActiveMQ-RCE.svg) ![forks](https://img.shields.io/github/forks/X1r0z/ActiveMQ-RCE.svg)


## CVE-2023-38831
 RARLAB WinRAR before 6.23 allows attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive. The issue occurs because a ZIP archive may include a benign file (such as an ordinary .JPG file) and also a folder that has the same name as the benign file, and the contents of the folder (which may include executable content) are processed during an attempt to access only the benign file. This was exploited in the wild in April through October 2023.

- [https://github.com/seyit-sigirci/SideCopy-Exploits-CVE-2023-38831](https://github.com/seyit-sigirci/SideCopy-Exploits-CVE-2023-38831) :  ![starts](https://img.shields.io/github/stars/seyit-sigirci/SideCopy-Exploits-CVE-2023-38831.svg) ![forks](https://img.shields.io/github/forks/seyit-sigirci/SideCopy-Exploits-CVE-2023-38831.svg)


## CVE-2023-28771
 Improper error message handling in Zyxel ZyWALL/USG series firmware versions 4.60 through 4.73, VPN series firmware versions 4.60 through 5.35, USG FLEX series firmware versions 4.60 through 5.35, and ATP series firmware versions 4.60 through 5.35, which could allow an unauthenticated attacker to execute some OS commands remotely by sending crafted packets to an affected device.

- [https://github.com/fed-speak/CVE-2023-28771-PoC](https://github.com/fed-speak/CVE-2023-28771-PoC) :  ![starts](https://img.shields.io/github/stars/fed-speak/CVE-2023-28771-PoC.svg) ![forks](https://img.shields.io/github/forks/fed-speak/CVE-2023-28771-PoC.svg)


## CVE-2023-26049
 Jetty is a java based web server and servlet engine. Nonstandard cookie parsing in Jetty may allow an attacker to smuggle cookies within other cookies, or otherwise perform unintended behavior by tampering with the cookie parsing mechanism. If Jetty sees a cookie VALUE that starts with `&quot;` (double quote), it will continue to read the cookie string until it sees a closing quote -- even if a semicolon is encountered. So, a cookie header such as: `DISPLAY_LANGUAGE=&quot;b; JSESSIONID=1337; c=d&quot;` will be parsed as one cookie, with the name DISPLAY_LANGUAGE and a value of b; JSESSIONID=1337; c=d instead of 3 separate cookies. This has security implications because if, say, JSESSIONID is an HttpOnly cookie, and the DISPLAY_LANGUAGE cookie value is rendered on the page, an attacker can smuggle the JSESSIONID cookie into the DISPLAY_LANGUAGE cookie and thereby exfiltrate it. This is significant when an intermediary is enacting some policy based on cookies, so a smuggled cookie can bypass that policy yet still be seen by the Jetty server or its logging system. This issue has been addressed in versions 9.4.51, 10.0.14, 11.0.14, and 12.0.0.beta0 and users are advised to upgrade. There are no known workarounds for this issue.

- [https://github.com/nidhi7598/jetty-9.4.31_CVE-2023-26049](https://github.com/nidhi7598/jetty-9.4.31_CVE-2023-26049) :  ![starts](https://img.shields.io/github/stars/nidhi7598/jetty-9.4.31_CVE-2023-26049.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/jetty-9.4.31_CVE-2023-26049.svg)


## CVE-2023-26048
 Jetty is a java based web server and servlet engine. In affected versions servlets with multipart support (e.g. annotated with `@MultipartConfig`) that call `HttpServletRequest.getParameter()` or `HttpServletRequest.getParts()` may cause `OutOfMemoryError` when the client sends a multipart request with a part that has a name but no filename and very large content. This happens even with the default settings of `fileSizeThreshold=0` which should stream the whole part content to disk. An attacker client may send a large multipart request and cause the server to throw `OutOfMemoryError`. However, the server may be able to recover after the `OutOfMemoryError` and continue its service -- although it may take some time. This issue has been patched in versions 9.4.51, 10.0.14, and 11.0.14. Users are advised to upgrade. Users unable to upgrade may set the multipart parameter `maxRequestSize` which must be set to a non-negative value, so the whole multipart content is limited (although still read into memory).

- [https://github.com/Trinadh465/jetty_9.4.31_CVE-2023-26048](https://github.com/Trinadh465/jetty_9.4.31_CVE-2023-26048) :  ![starts](https://img.shields.io/github/stars/Trinadh465/jetty_9.4.31_CVE-2023-26048.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/jetty_9.4.31_CVE-2023-26048.svg)


## CVE-2023-5360
 The Royal Elementor Addons and Templates WordPress plugin before 1.3.79 does not properly validate uploaded files, which could allow unauthenticated users to upload arbitrary files, such as PHP and achieve RCE.

- [https://github.com/Chocapikk/CVE-2023-5360](https://github.com/Chocapikk/CVE-2023-5360) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2023-5360.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2023-5360.svg)


## CVE-2022-46166
 Spring boot admins is an open source administrative user interface for management of spring boot applications. All users who run Spring Boot Admin Server, having enabled Notifiers (e.g. Teams-Notifier) and write access to environment variables via UI are affected. Users are advised to upgrade to the most recent releases of Spring Boot Admin 2.6.10 and 2.7.8 to resolve this issue. Users unable to upgrade may disable any notifier or disable write access (POST request) on `/env` actuator endpoint.

- [https://github.com/DickDock/CVE-2022-46166](https://github.com/DickDock/CVE-2022-46166) :  ![starts](https://img.shields.io/github/stars/DickDock/CVE-2022-46166.svg) ![forks](https://img.shields.io/github/forks/DickDock/CVE-2022-46166.svg)


## CVE-2022-46164
 NodeBB is an open source Node.js based forum software. Due to a plain object with a prototype being used in socket.io message handling a specially crafted payload can be used to impersonate other users and takeover accounts. This vulnerability has been patched in version 2.6.1. Users are advised to upgrade. Users unable to upgrade may cherry-pick commit `48d143921753914da45926cca6370a92ed0c46b8` into their codebase to patch the exploit.

- [https://github.com/stephenbradshaw/CVE-2022-46164-poc](https://github.com/stephenbradshaw/CVE-2022-46164-poc) :  ![starts](https://img.shields.io/github/stars/stephenbradshaw/CVE-2022-46164-poc.svg) ![forks](https://img.shields.io/github/forks/stephenbradshaw/CVE-2022-46164-poc.svg)


## CVE-2022-46104
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/NurSec747/CVE-2022-46104---POC](https://github.com/NurSec747/CVE-2022-46104---POC) :  ![starts](https://img.shields.io/github/stars/NurSec747/CVE-2022-46104---POC.svg) ![forks](https://img.shields.io/github/forks/NurSec747/CVE-2022-46104---POC.svg)


## CVE-2022-36804
 Multiple API endpoints in Atlassian Bitbucket Server and Data Center 7.0.0 before version 7.6.17, from version 7.7.0 before version 7.17.10, from version 7.18.0 before version 7.21.4, from version 8.0.0 before version 8.0.3, from version 8.1.0 before version 8.1.3, and from version 8.2.0 before version 8.2.2, and from version 8.3.0 before 8.3.1 allows remote attackers with read permissions to a public or private Bitbucket repository to execute arbitrary code by sending a malicious HTTP request. This vulnerability was reported via our Bug Bounty Program by TheGrandPew.

- [https://github.com/fed-speak/CVE-2022-36804-PoC-Exploit](https://github.com/fed-speak/CVE-2022-36804-PoC-Exploit) :  ![starts](https://img.shields.io/github/stars/fed-speak/CVE-2022-36804-PoC-Exploit.svg) ![forks](https://img.shields.io/github/forks/fed-speak/CVE-2022-36804-PoC-Exploit.svg)


## CVE-2022-30594
 The Linux kernel before 5.17.2 mishandles seccomp permissions. The PTRACE_SEIZE code path allows attackers to bypass intended restrictions on setting the PT_SUSPEND_SECCOMP flag.

- [https://github.com/Lay0us1/linux-4.19.72_CVE-2022-30594](https://github.com/Lay0us1/linux-4.19.72_CVE-2022-30594) :  ![starts](https://img.shields.io/github/stars/Lay0us1/linux-4.19.72_CVE-2022-30594.svg) ![forks](https://img.shields.io/github/forks/Lay0us1/linux-4.19.72_CVE-2022-30594.svg)


## CVE-2021-22205
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 11.9. GitLab was not properly validating image files that were passed to a file parser which resulted in a remote command execution.

- [https://github.com/NukingDragons/gitlab-cve-2021-22205](https://github.com/NukingDragons/gitlab-cve-2021-22205) :  ![starts](https://img.shields.io/github/stars/NukingDragons/gitlab-cve-2021-22205.svg) ![forks](https://img.shields.io/github/forks/NukingDragons/gitlab-cve-2021-22205.svg)


## CVE-2018-7854
 A CWE-248 Uncaught Exception vulnerability exists in all versions of the Modicon M580, Modicon M340, Modicon Quantum, and Modicon Premium which could cause a denial of Service when sending invalid debug parameters to the controller over Modbus.

- [https://github.com/yanissec/CVE-2018-7854](https://github.com/yanissec/CVE-2018-7854) :  ![starts](https://img.shields.io/github/stars/yanissec/CVE-2018-7854.svg) ![forks](https://img.shields.io/github/forks/yanissec/CVE-2018-7854.svg)


## CVE-2014-0224
 OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h does not properly restrict processing of ChangeCipherSpec messages, which allows man-in-the-middle attackers to trigger use of a zero-length master key in certain OpenSSL-to-OpenSSL communications, and consequently hijack sessions or obtain sensitive information, via a crafted TLS handshake, aka the &quot;CCS Injection&quot; vulnerability.

- [https://github.com/nidhi7598/OPENSSL_1.0.1g_CVE-2014-0224](https://github.com/nidhi7598/OPENSSL_1.0.1g_CVE-2014-0224) :  ![starts](https://img.shields.io/github/stars/nidhi7598/OPENSSL_1.0.1g_CVE-2014-0224.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/OPENSSL_1.0.1g_CVE-2014-0224.svg)


## CVE-2010-5298
 Race condition in the ssl3_read_bytes function in s3_pkt.c in OpenSSL through 1.0.1g, when SSL_MODE_RELEASE_BUFFERS is enabled, allows remote attackers to inject data across sessions or cause a denial of service (use-after-free and parsing error) via an SSL connection in a multithreaded environment.

- [https://github.com/nidhi7598/OPENSSL_1.0.1g_CVE-2010-5298](https://github.com/nidhi7598/OPENSSL_1.0.1g_CVE-2010-5298) :  ![starts](https://img.shields.io/github/stars/nidhi7598/OPENSSL_1.0.1g_CVE-2010-5298.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/OPENSSL_1.0.1g_CVE-2010-5298.svg)

