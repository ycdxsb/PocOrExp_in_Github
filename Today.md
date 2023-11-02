# Update 2023-11-02
## CVE-2023-46501
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Cyber-Wo0dy/CVE-2023-46501](https://github.com/Cyber-Wo0dy/CVE-2023-46501) :  ![starts](https://img.shields.io/github/stars/Cyber-Wo0dy/CVE-2023-46501.svg) ![forks](https://img.shields.io/github/forks/Cyber-Wo0dy/CVE-2023-46501.svg)


## CVE-2023-26049
 Jetty is a java based web server and servlet engine. Nonstandard cookie parsing in Jetty may allow an attacker to smuggle cookies within other cookies, or otherwise perform unintended behavior by tampering with the cookie parsing mechanism. If Jetty sees a cookie VALUE that starts with `&quot;` (double quote), it will continue to read the cookie string until it sees a closing quote -- even if a semicolon is encountered. So, a cookie header such as: `DISPLAY_LANGUAGE=&quot;b; JSESSIONID=1337; c=d&quot;` will be parsed as one cookie, with the name DISPLAY_LANGUAGE and a value of b; JSESSIONID=1337; c=d instead of 3 separate cookies. This has security implications because if, say, JSESSIONID is an HttpOnly cookie, and the DISPLAY_LANGUAGE cookie value is rendered on the page, an attacker can smuggle the JSESSIONID cookie into the DISPLAY_LANGUAGE cookie and thereby exfiltrate it. This is significant when an intermediary is enacting some policy based on cookies, so a smuggled cookie can bypass that policy yet still be seen by the Jetty server or its logging system. This issue has been addressed in versions 9.4.51, 10.0.14, 11.0.14, and 12.0.0.beta0 and users are advised to upgrade. There are no known workarounds for this issue.

- [https://github.com/Trinadh465/jetty_9.4.31_CVE-2023-26049](https://github.com/Trinadh465/jetty_9.4.31_CVE-2023-26049) :  ![starts](https://img.shields.io/github/stars/Trinadh465/jetty_9.4.31_CVE-2023-26049.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/jetty_9.4.31_CVE-2023-26049.svg)


## CVE-2023-22518
 All versions of Confluence Data Center and Server are affected by this unexploited vulnerability. There is no impact to confidentiality as an attacker cannot exfiltrate any instance data. Atlassian Cloud sites are not affected by this vulnerability. If your Confluence site is accessed via an atlassian.net domain, it is hosted by Atlassian and is not vulnerable to this issue.

- [https://github.com/ForceFledgling/CVE-2023-22518](https://github.com/ForceFledgling/CVE-2023-22518) :  ![starts](https://img.shields.io/github/stars/ForceFledgling/CVE-2023-22518.svg) ![forks](https://img.shields.io/github/forks/ForceFledgling/CVE-2023-22518.svg)


## CVE-2023-21768
 Windows Ancillary Function Driver for WinSock Elevation of Privilege Vulnerability

- [https://github.com/h1bAna/CVE-2023-21768](https://github.com/h1bAna/CVE-2023-21768) :  ![starts](https://img.shields.io/github/stars/h1bAna/CVE-2023-21768.svg) ![forks](https://img.shields.io/github/forks/h1bAna/CVE-2023-21768.svg)


## CVE-2023-5412
 The Image horizontal reel scroll slideshow plugin for WordPress is vulnerable to SQL Injection via the plugin's shortcode in versions up to, and including, 13.2 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query. This makes it possible for authenticated attackers with subscriber-level and above permissions to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/RandomRobbieBF/CVE-2023-5412](https://github.com/RandomRobbieBF/CVE-2023-5412) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2023-5412.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2023-5412.svg)


## CVE-2022-2048
 In Eclipse Jetty HTTP/2 server implementation, when encountering an invalid HTTP/2 request, the error handling has a bug that can wind up not properly cleaning up the active connections and associated resources. This can lead to a Denial of Service scenario where there are no enough resources left to process good requests.

- [https://github.com/Trinadh465/jetty_9.4.31_CVE-2022-2048](https://github.com/Trinadh465/jetty_9.4.31_CVE-2022-2048) :  ![starts](https://img.shields.io/github/stars/Trinadh465/jetty_9.4.31_CVE-2022-2048.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/jetty_9.4.31_CVE-2022-2048.svg)


## CVE-2021-34428
 For Eclipse Jetty versions &lt;= 9.4.40, &lt;= 10.0.2, &lt;= 11.0.2, if an exception is thrown from the SessionListener#sessionDestroyed() method, then the session ID is not invalidated in the session ID manager. On deployments with clustered sessions and multiple contexts this can result in a session not being invalidated. This can result in an application used on a shared computer being left logged in.

- [https://github.com/Trinadh465/jetty_9.4.31_CVE-2021-34428](https://github.com/Trinadh465/jetty_9.4.31_CVE-2021-34428) :  ![starts](https://img.shields.io/github/stars/Trinadh465/jetty_9.4.31_CVE-2021-34428.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/jetty_9.4.31_CVE-2021-34428.svg)


## CVE-2021-28165
 In Eclipse Jetty 7.2.2 to 9.4.38, 10.0.0.alpha0 to 10.0.1, and 11.0.0.alpha0 to 11.0.1, CPU usage can reach 100% upon receiving a large invalid TLS frame.

- [https://github.com/nidhi7598/jetty-9.4.31_CVE-2021-28165](https://github.com/nidhi7598/jetty-9.4.31_CVE-2021-28165) :  ![starts](https://img.shields.io/github/stars/nidhi7598/jetty-9.4.31_CVE-2021-28165.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/jetty-9.4.31_CVE-2021-28165.svg)


## CVE-2021-28164
 In Eclipse Jetty 9.4.37.v20210219 to 9.4.38.v20210224, the default compliance mode allows requests with URIs that contain %2e or %2e%2e segments to access protected resources within the WEB-INF directory. For example a request to /context/%2e/WEB-INF/web.xml can retrieve the web.xml file. This can reveal sensitive information regarding the implementation of a web application.

- [https://github.com/jammy0903/-jettyCVE-2021-28164-](https://github.com/jammy0903/-jettyCVE-2021-28164-) :  ![starts](https://img.shields.io/github/stars/jammy0903/-jettyCVE-2021-28164-.svg) ![forks](https://img.shields.io/github/forks/jammy0903/-jettyCVE-2021-28164-.svg)


## CVE-2020-9802
 A logic issue was addressed with improved restrictions. This issue is fixed in iOS 13.5 and iPadOS 13.5, tvOS 13.4.5, watchOS 6.2.5, Safari 13.1.1, iTunes 12.10.7 for Windows, iCloud for Windows 11.2, iCloud for Windows 7.19. Processing maliciously crafted web content may lead to arbitrary code execution.

- [https://github.com/khcujw/CVE-2020-9802](https://github.com/khcujw/CVE-2020-9802) :  ![starts](https://img.shields.io/github/stars/khcujw/CVE-2020-9802.svg) ![forks](https://img.shields.io/github/forks/khcujw/CVE-2020-9802.svg)


## CVE-2020-0796
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

- [https://github.com/abdullah098/CVE_2020_0796](https://github.com/abdullah098/CVE_2020_0796) :  ![starts](https://img.shields.io/github/stars/abdullah098/CVE_2020_0796.svg) ![forks](https://img.shields.io/github/forks/abdullah098/CVE_2020_0796.svg)


## CVE-2010-3904
 The rds_page_copy_user function in net/rds/page.c in the Reliable Datagram Sockets (RDS) protocol implementation in the Linux kernel before 2.6.36 does not properly validate addresses obtained from user space, which allows local users to gain privileges via crafted use of the sendmsg and recvmsg system calls.

- [https://github.com/redhatkaty/-cve-2010-3904-report](https://github.com/redhatkaty/-cve-2010-3904-report) :  ![starts](https://img.shields.io/github/stars/redhatkaty/-cve-2010-3904-report.svg) ![forks](https://img.shields.io/github/forks/redhatkaty/-cve-2010-3904-report.svg)

