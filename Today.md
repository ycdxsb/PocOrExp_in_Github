# Update 2021-07-13
## CVE-2021-34045
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Al1ex/CVE-2021-34045](https://github.com/Al1ex/CVE-2021-34045) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2021-34045.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2021-34045.svg)


## CVE-2021-21985
 The vSphere Client (HTML5) contains a remote code execution vulnerability due to lack of input validation in the Virtual SAN Health Check plug-in which is enabled by default in vCenter Server. A malicious actor with network access to port 443 may exploit this issue to execute commands with unrestricted privileges on the underlying operating system that hosts vCenter Server.

- [https://github.com/aristosMiliaressis/CVE-2021-21985](https://github.com/aristosMiliaressis/CVE-2021-21985) :  ![starts](https://img.shields.io/github/stars/aristosMiliaressis/CVE-2021-21985.svg) ![forks](https://img.shields.io/github/forks/aristosMiliaressis/CVE-2021-21985.svg)


## CVE-2020-24148
 Server-side request forgery (SSRF) in the Import XML and RSS Feeds (import-xml-feed) plugin 2.0.1 for WordPress via the data parameter in a moove_read_xml action.

- [https://github.com/dwisiswant0/CVE-2020-24148](https://github.com/dwisiswant0/CVE-2020-24148) :  ![starts](https://img.shields.io/github/stars/dwisiswant0/CVE-2020-24148.svg) ![forks](https://img.shields.io/github/forks/dwisiswant0/CVE-2020-24148.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/yukiNeko114514/CVE-2020-1938](https://github.com/yukiNeko114514/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/yukiNeko114514/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/yukiNeko114514/CVE-2020-1938.svg)


## CVE-2015-1635
 HTTP.sys in Microsoft Windows 7 SP1, Windows Server 2008 R2 SP1, Windows 8, Windows 8.1, and Windows Server 2012 Gold and R2 allows remote attackers to execute arbitrary code via crafted HTTP requests, aka &quot;HTTP.sys Remote Code Execution Vulnerability.&quot;

- [https://github.com/3hydraking/CVE-2015-1635](https://github.com/3hydraking/CVE-2015-1635) :  ![starts](https://img.shields.io/github/stars/3hydraking/CVE-2015-1635.svg) ![forks](https://img.shields.io/github/forks/3hydraking/CVE-2015-1635.svg)
- [https://github.com/3hydraking/CVE-2015-1635-POC](https://github.com/3hydraking/CVE-2015-1635-POC) :  ![starts](https://img.shields.io/github/stars/3hydraking/CVE-2015-1635-POC.svg) ![forks](https://img.shields.io/github/forks/3hydraking/CVE-2015-1635-POC.svg)

