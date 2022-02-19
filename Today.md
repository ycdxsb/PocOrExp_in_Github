# Update 2022-02-19
## CVE-2022-25258
 An issue was discovered in the Linux kernel before 5.16.10. The USB Gadget subsystem lacks certain validation of interface OS descriptor requests (ones with a large array index and ones associated with NULL function pointer retrieval). Memory corruption might occur.

- [https://github.com/szymonh/d-os-descriptor](https://github.com/szymonh/d-os-descriptor) :  ![starts](https://img.shields.io/github/stars/szymonh/d-os-descriptor.svg) ![forks](https://img.shields.io/github/forks/szymonh/d-os-descriptor.svg)


## CVE-2022-25257
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/RobertDra/CVE-2022-25257](https://github.com/RobertDra/CVE-2022-25257) :  ![starts](https://img.shields.io/github/stars/RobertDra/CVE-2022-25257.svg) ![forks](https://img.shields.io/github/forks/RobertDra/CVE-2022-25257.svg)


## CVE-2022-25256
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/RobertDra/CVE-2022-25256](https://github.com/RobertDra/CVE-2022-25256) :  ![starts](https://img.shields.io/github/stars/RobertDra/CVE-2022-25256.svg) ![forks](https://img.shields.io/github/forks/RobertDra/CVE-2022-25256.svg)


## CVE-2022-23131
 In the case of instances where the SAML SSO authentication is enabled (non-default), session data can be modified by a malicious actor, because a user login stored in the session was not verified. Malicious unauthenticated actor may exploit this issue to escalate privileges and gain admin access to Zabbix Frontend. To perform the attack, SAML authentication is required to be enabled and the actor has to know the username of Zabbix user (or use the guest account, which is disabled by default).

- [https://github.com/qq1549176285/CVE-2022-23131](https://github.com/qq1549176285/CVE-2022-23131) :  ![starts](https://img.shields.io/github/stars/qq1549176285/CVE-2022-23131.svg) ![forks](https://img.shields.io/github/forks/qq1549176285/CVE-2022-23131.svg)


## CVE-2022-22909
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/0z09e/CVE-2022-22909](https://github.com/0z09e/CVE-2022-22909) :  ![starts](https://img.shields.io/github/stars/0z09e/CVE-2022-22909.svg) ![forks](https://img.shields.io/github/forks/0z09e/CVE-2022-22909.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/HackJava/Log4j2](https://github.com/HackJava/Log4j2) :  ![starts](https://img.shields.io/github/stars/HackJava/Log4j2.svg) ![forks](https://img.shields.io/github/forks/HackJava/Log4j2.svg)


## CVE-2020-15778
 ** DISPUTED ** scp in OpenSSH through 8.3p1 allows command injection in the scp.c toremote function, as demonstrated by backtick characters in the destination argument. NOTE: the vendor reportedly has stated that they intentionally omit validation of &quot;anomalous argument transfers&quot; because that could &quot;stand a great chance of breaking existing workflows.&quot;

- [https://github.com/Neko-chanQwQ/CVE-2020-15778-Exploit](https://github.com/Neko-chanQwQ/CVE-2020-15778-Exploit) :  ![starts](https://img.shields.io/github/stars/Neko-chanQwQ/CVE-2020-15778-Exploit.svg) ![forks](https://img.shields.io/github/forks/Neko-chanQwQ/CVE-2020-15778-Exploit.svg)


## CVE-2020-9483
 **Resolved** When use H2/MySQL/TiDB as Apache SkyWalking storage, the metadata query through GraphQL protocol, there is a SQL injection vulnerability, which allows to access unpexcted data. Apache SkyWalking 6.0.0 to 6.6.0, 7.0.0 H2/MySQL/TiDB storage implementations don't use the appropriate way to set SQL parameters.

- [https://github.com/Neko-chanQwQ/CVE-2020-9483](https://github.com/Neko-chanQwQ/CVE-2020-9483) :  ![starts](https://img.shields.io/github/stars/Neko-chanQwQ/CVE-2020-9483.svg) ![forks](https://img.shields.io/github/forks/Neko-chanQwQ/CVE-2020-9483.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/Neko-chanQwQ/CVE-2020-1938](https://github.com/Neko-chanQwQ/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/Neko-chanQwQ/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/Neko-chanQwQ/CVE-2020-1938.svg)


## CVE-2018-9995
 TBK DVR4104 and DVR4216 devices, as well as Novo, CeNova, QSee, Pulnix, XVR 5 in 1, Securus, Night OWL, DVR Login, HVR Login, and MDVR Login, which run re-branded versions of the original TBK DVR4104 and DVR4216 series, allow remote attackers to bypass authentication via a &quot;Cookie: uid=admin&quot; header, as demonstrated by a device.rsp?opt=user&amp;cmd=list request that provides credentials within JSON data in a response.

- [https://github.com/LeQuocKhanh2K/Tool_Exploit_Password_Camera_CVE-2018-9995](https://github.com/LeQuocKhanh2K/Tool_Exploit_Password_Camera_CVE-2018-9995) :  ![starts](https://img.shields.io/github/stars/LeQuocKhanh2K/Tool_Exploit_Password_Camera_CVE-2018-9995.svg) ![forks](https://img.shields.io/github/forks/LeQuocKhanh2K/Tool_Exploit_Password_Camera_CVE-2018-9995.svg)


## CVE-2018-6479
 An issue was discovered on Netwave IP Camera devices. An unauthenticated attacker can crash a device by sending a POST request with a huge body size to the / URI.

- [https://github.com/LeQuocKhanh2K/Tool_Camera_Exploit_Netwave_CVE-2018-6479](https://github.com/LeQuocKhanh2K/Tool_Camera_Exploit_Netwave_CVE-2018-6479) :  ![starts](https://img.shields.io/github/stars/LeQuocKhanh2K/Tool_Camera_Exploit_Netwave_CVE-2018-6479.svg) ![forks](https://img.shields.io/github/forks/LeQuocKhanh2K/Tool_Camera_Exploit_Netwave_CVE-2018-6479.svg)

