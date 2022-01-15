# Update 2022-01-15
## CVE-2021-45105
 Apache Log4j2 versions 2.0-alpha1 through 2.16.0 (excluding 2.12.3 and 2.3.1) did not protect from uncontrolled recursion from self-referential lookups. This allows an attacker with control over Thread Context Map data to cause a denial of service when a crafted string is interpreted. This issue was fixed in Log4j 2.17.0, 2.12.3, and 2.3.1.

- [https://github.com/andalik/log4j-filescan](https://github.com/andalik/log4j-filescan) :  ![starts](https://img.shields.io/github/stars/andalik/log4j-filescan.svg) ![forks](https://img.shields.io/github/forks/andalik/log4j-filescan.svg)


## CVE-2021-44832
 Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding security fix releases 2.3.2 and 2.12.4) are vulnerable to a remote code execution (RCE) attack when a configuration uses a JDBC Appender with a JNDI LDAP data source URI when an attacker has control of the target LDAP server. This issue is fixed by limiting JNDI data source names to the java protocol in Log4j2 versions 2.17.1, 2.12.4, and 2.3.2.

- [https://github.com/andalik/log4j-filescan](https://github.com/andalik/log4j-filescan) :  ![starts](https://img.shields.io/github/stars/andalik/log4j-filescan.svg) ![forks](https://img.shields.io/github/forks/andalik/log4j-filescan.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `&lt;grafana_host_url&gt;/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/MzzdToT/Grafana_fileread](https://github.com/MzzdToT/Grafana_fileread) :  ![starts](https://img.shields.io/github/stars/MzzdToT/Grafana_fileread.svg) ![forks](https://img.shields.io/github/forks/MzzdToT/Grafana_fileread.svg)


## CVE-2021-35211
 Microsoft discovered a remote code execution (RCE) vulnerability in the SolarWinds Serv-U product utilizing a Remote Memory Escape Vulnerability. If exploited, a threat actor may be able to gain privileged access to the machine hosting Serv-U Only. SolarWinds Serv-U Managed File Transfer and Serv-U Secure FTP for Windows before 15.2.3 HF2 are affected by this vulnerability.

- [https://github.com/BishopFox/CVE-2021-35211](https://github.com/BishopFox/CVE-2021-35211) :  ![starts](https://img.shields.io/github/stars/BishopFox/CVE-2021-35211.svg) ![forks](https://img.shields.io/github/forks/BishopFox/CVE-2021-35211.svg)


## CVE-2021-26856
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/avi8892/CVE-2021-26856](https://github.com/avi8892/CVE-2021-26856) :  ![starts](https://img.shields.io/github/stars/avi8892/CVE-2021-26856.svg) ![forks](https://img.shields.io/github/forks/avi8892/CVE-2021-26856.svg)


## CVE-2021-26084
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0 before 7.12.5.

- [https://github.com/antx-code/CVE-2021-26084](https://github.com/antx-code/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/antx-code/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/antx-code/CVE-2021-26084.svg)


## CVE-2018-16341
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem.  When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/puckiestyle/CVE-2018-16341](https://github.com/puckiestyle/CVE-2018-16341) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2018-16341.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2018-16341.svg)


## CVE-2015-9235
 In jsonwebtoken node module before 4.2.2 it is possible for an attacker to bypass verification when a token digitally signed with an asymmetric key (RS/ES family) of algorithms but instead the attacker send a token digitally signed with a symmetric algorithm (HS* family).

- [https://github.com/aalex954/jwt-key-confusion-poc](https://github.com/aalex954/jwt-key-confusion-poc) :  ![starts](https://img.shields.io/github/stars/aalex954/jwt-key-confusion-poc.svg) ![forks](https://img.shields.io/github/forks/aalex954/jwt-key-confusion-poc.svg)

