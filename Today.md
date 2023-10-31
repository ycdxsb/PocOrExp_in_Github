# Update 2023-10-31
## CVE-2023-27524
 Session Validation attacks in Apache Superset versions up to and including 2.0.1. Installations that have not altered the default configured SECRET_KEY according to installation instructions allow for an attacker to authenticate and access unauthorized resources. This does not affect Superset administrators who have changed the default value for SECRET_KEY config.

- [https://github.com/NguyenCongHaiNam/Research-CVE-2023-27524](https://github.com/NguyenCongHaiNam/Research-CVE-2023-27524) :  ![starts](https://img.shields.io/github/stars/NguyenCongHaiNam/Research-CVE-2023-27524.svg) ![forks](https://img.shields.io/github/forks/NguyenCongHaiNam/Research-CVE-2023-27524.svg)


## CVE-2023-22515
 Atlassian has been made aware of an issue reported by a handful of customers where external attackers may have exploited a previously unknown vulnerability in publicly accessible Confluence Data Center and Server instances to create unauthorized Confluence administrator accounts and access Confluence instances. Atlassian Cloud sites are not affected by this vulnerability. If your Confluence site is accessed via an atlassian.net domain, it is hosted by Atlassian and is not vulnerable to this issue.

- [https://github.com/AIex-3/confluence-hack](https://github.com/AIex-3/confluence-hack) :  ![starts](https://img.shields.io/github/stars/AIex-3/confluence-hack.svg) ![forks](https://img.shields.io/github/forks/AIex-3/confluence-hack.svg)


## CVE-2023-4966
 Sensitive information disclosure in NetScaler ADC and NetScaler Gateway when configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) or AAA virtual server.

- [https://github.com/sanjai-AK47/CVE-2023-4966](https://github.com/sanjai-AK47/CVE-2023-4966) :  ![starts](https://img.shields.io/github/stars/sanjai-AK47/CVE-2023-4966.svg) ![forks](https://img.shields.io/github/forks/sanjai-AK47/CVE-2023-4966.svg)


## CVE-2022-31692
 Spring Security, versions 5.7 prior to 5.7.5 and 5.6 prior to 5.6.9 could be susceptible to authorization rules bypass via forward or include dispatcher types. Specifically, an application is vulnerable when all of the following are true: The application expects that Spring Security applies security to forward and include dispatcher types. The application uses the AuthorizationFilter either manually or via the authorizeHttpRequests() method. The application configures the FilterChainProxy to apply to forward and/or include requests (e.g. spring.security.filter.dispatcher-types = request, error, async, forward, include). The application may forward or include the request to a higher privilege-secured endpoint.The application configures Spring Security to apply to every dispatcher type via authorizeHttpRequests().shouldFilterAllDispatcherTypes(true)

- [https://github.com/hotblac/cve-2022-31692](https://github.com/hotblac/cve-2022-31692) :  ![starts](https://img.shields.io/github/stars/hotblac/cve-2022-31692.svg) ![forks](https://img.shields.io/github/forks/hotblac/cve-2022-31692.svg)


## CVE-2021-43226
 Windows Common Log File System Driver Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-43207.

- [https://github.com/Rosayxy/cve-2021-43226PoC](https://github.com/Rosayxy/cve-2021-43226PoC) :  ![starts](https://img.shields.io/github/stars/Rosayxy/cve-2021-43226PoC.svg) ![forks](https://img.shields.io/github/forks/Rosayxy/cve-2021-43226PoC.svg)


## CVE-2021-22880
 The PostgreSQL adapter in Active Record before 6.1.2.1, 6.0.3.5, 5.2.4.5 suffers from a regular expression denial of service (REDoS) vulnerability. Carefully crafted input can cause the input validation in the `money` type of the PostgreSQL adapter in Active Record to spend too much time in a regular expression, resulting in the potential for a DoS attack. This only impacts Rails applications that are using PostgreSQL along with money type columns that take user input.

- [https://github.com/halkichi0308/CVE-2021-22880](https://github.com/halkichi0308/CVE-2021-22880) :  ![starts](https://img.shields.io/github/stars/halkichi0308/CVE-2021-22880.svg) ![forks](https://img.shields.io/github/forks/halkichi0308/CVE-2021-22880.svg)


## CVE-2021-22205
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 11.9. GitLab was not properly validating image files that were passed to a file parser which resulted in a remote command execution.

- [https://github.com/won6c/CVE-2021-22205](https://github.com/won6c/CVE-2021-22205) :  ![starts](https://img.shields.io/github/stars/won6c/CVE-2021-22205.svg) ![forks](https://img.shields.io/github/forks/won6c/CVE-2021-22205.svg)


## CVE-2020-6514
 Inappropriate implementation in WebRTC in Google Chrome prior to 84.0.4147.89 allowed an attacker in a privileged network position to potentially exploit heap corruption via a crafted SCTP stream.

- [https://github.com/R0jhack/CVE-2020-6514](https://github.com/R0jhack/CVE-2020-6514) :  ![starts](https://img.shields.io/github/stars/R0jhack/CVE-2020-6514.svg) ![forks](https://img.shields.io/github/forks/R0jhack/CVE-2020-6514.svg)


## CVE-2018-7852
 A CWE-248: Uncaught Exception vulnerability exists in all versions of the Modicon M580, Modicon M340, Modicon Quantum, and Modicon Premium which could cause denial of service when an invalid private command parameter is sent to the controller over Modbus.

- [https://github.com/yanissec/CVE-2018-7852](https://github.com/yanissec/CVE-2018-7852) :  ![starts](https://img.shields.io/github/stars/yanissec/CVE-2018-7852.svg) ![forks](https://img.shields.io/github/forks/yanissec/CVE-2018-7852.svg)


## CVE-2007-6750
 The Apache HTTP Server 1.x and 2.x allows remote attackers to cause a denial of service (daemon outage) via partial HTTP requests, as demonstrated by Slowloris, related to the lack of the mod_reqtimeout module in versions before 2.2.15.

- [https://github.com/Jeanpseven/slowl0ris](https://github.com/Jeanpseven/slowl0ris) :  ![starts](https://img.shields.io/github/stars/Jeanpseven/slowl0ris.svg) ![forks](https://img.shields.io/github/forks/Jeanpseven/slowl0ris.svg)

