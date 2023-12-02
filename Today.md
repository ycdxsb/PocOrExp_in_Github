# Update 2023-12-02
## CVE-2023-48866
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/nitipoom-jar/CVE-2023-48866](https://github.com/nitipoom-jar/CVE-2023-48866) :  ![starts](https://img.shields.io/github/stars/nitipoom-jar/CVE-2023-48866.svg) ![forks](https://img.shields.io/github/forks/nitipoom-jar/CVE-2023-48866.svg)


## CVE-2023-46615
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/RandomRobbieBF/CVE-2023-46615](https://github.com/RandomRobbieBF/CVE-2023-46615) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2023-46615.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2023-46615.svg)


## CVE-2023-31445
 Cassia Access controller before 2.1.1.2203171453, was discovered to have a unprivileged -information disclosure vulnerability that allows read-only users have the ability to enumerate all other users and discover e-mail addresses, phone numbers, and privileges of all other users.

- [https://github.com/Dodge-MPTC/CVE-2023-31445-Unprivileged-Information-Disclosure](https://github.com/Dodge-MPTC/CVE-2023-31445-Unprivileged-Information-Disclosure) :  ![starts](https://img.shields.io/github/stars/Dodge-MPTC/CVE-2023-31445-Unprivileged-Information-Disclosure.svg) ![forks](https://img.shields.io/github/forks/Dodge-MPTC/CVE-2023-31445-Unprivileged-Information-Disclosure.svg)


## CVE-2023-23752
 An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

- [https://github.com/svaltheim/CVE-2023-23752](https://github.com/svaltheim/CVE-2023-23752) :  ![starts](https://img.shields.io/github/stars/svaltheim/CVE-2023-23752.svg) ![forks](https://img.shields.io/github/forks/svaltheim/CVE-2023-23752.svg)
- [https://github.com/r3dston3/CVE-2023-23752](https://github.com/r3dston3/CVE-2023-23752) :  ![starts](https://img.shields.io/github/stars/r3dston3/CVE-2023-23752.svg) ![forks](https://img.shields.io/github/forks/r3dston3/CVE-2023-23752.svg)


## CVE-2022-38691
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/TomKing062/CVE-2022-38691_38692](https://github.com/TomKing062/CVE-2022-38691_38692) :  ![starts](https://img.shields.io/github/stars/TomKing062/CVE-2022-38691_38692.svg) ![forks](https://img.shields.io/github/forks/TomKing062/CVE-2022-38691_38692.svg)


## CVE-2021-1732
 Windows Win32k Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-1698.

- [https://github.com/KaLendsi/CVE-2021-1732-Exploit](https://github.com/KaLendsi/CVE-2021-1732-Exploit) :  ![starts](https://img.shields.io/github/stars/KaLendsi/CVE-2021-1732-Exploit.svg) ![forks](https://img.shields.io/github/forks/KaLendsi/CVE-2021-1732-Exploit.svg)
- [https://github.com/linuxdy/CVE-2021-1732_exp](https://github.com/linuxdy/CVE-2021-1732_exp) :  ![starts](https://img.shields.io/github/stars/linuxdy/CVE-2021-1732_exp.svg) ![forks](https://img.shields.io/github/forks/linuxdy/CVE-2021-1732_exp.svg)
- [https://github.com/jessica0f0116/cve_2022_21882-cve_2021_1732](https://github.com/jessica0f0116/cve_2022_21882-cve_2021_1732) :  ![starts](https://img.shields.io/github/stars/jessica0f0116/cve_2022_21882-cve_2021_1732.svg) ![forks](https://img.shields.io/github/forks/jessica0f0116/cve_2022_21882-cve_2021_1732.svg)
- [https://github.com/YOunGWebER/cve_2021_1732](https://github.com/YOunGWebER/cve_2021_1732) :  ![starts](https://img.shields.io/github/stars/YOunGWebER/cve_2021_1732.svg) ![forks](https://img.shields.io/github/forks/YOunGWebER/cve_2021_1732.svg)


## CVE-2020-25803
 Improper Control of Dynamically-Managed Code Resources vulnerability in Crafter Studio of Crafter CMS allows authenticated developers to execute OS commands via FreeMarker template exposed objects. This issue affects: Crafter Software Crafter CMS 3.0 versions prior to 3.0.27; 3.1 versions prior to 3.1.7.

- [https://github.com/mbadanoiu/CVE-2022-40634](https://github.com/mbadanoiu/CVE-2022-40634) :  ![starts](https://img.shields.io/github/stars/mbadanoiu/CVE-2022-40634.svg) ![forks](https://img.shields.io/github/forks/mbadanoiu/CVE-2022-40634.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/w4fz5uck5/CVE-2020-1938-Clean-Version](https://github.com/w4fz5uck5/CVE-2020-1938-Clean-Version) :  ![starts](https://img.shields.io/github/stars/w4fz5uck5/CVE-2020-1938-Clean-Version.svg) ![forks](https://img.shields.io/github/forks/w4fz5uck5/CVE-2020-1938-Clean-Version.svg)
- [https://github.com/I-Runtime-Error/CVE-2020-1938](https://github.com/I-Runtime-Error/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/I-Runtime-Error/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/I-Runtime-Error/CVE-2020-1938.svg)


## CVE-2019-19652
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/jra89/CVE-2019-19652](https://github.com/jra89/CVE-2019-19652) :  ![starts](https://img.shields.io/github/stars/jra89/CVE-2019-19652.svg) ![forks](https://img.shields.io/github/forks/jra89/CVE-2019-19652.svg)


## CVE-2015-3837
 The OpenSSLX509Certificate class in org/conscrypt/OpenSSLX509Certificate.java in Android before 5.1.1 LMY48I improperly includes certain context data during serialization and deserialization, which allows attackers to execute arbitrary code via an application that sends a crafted Intent, aka internal bug 21437603.

- [https://github.com/itibs/IsildursBane](https://github.com/itibs/IsildursBane) :  ![starts](https://img.shields.io/github/stars/itibs/IsildursBane.svg) ![forks](https://img.shields.io/github/forks/itibs/IsildursBane.svg)


## CVE-2013-5842
 Unspecified vulnerability in Oracle Java SE 7u40 and earlier, Java SE 6u60 and earlier, Java SE 5.0u51 and earlier, and Java SE Embedded 7u40 and earlier allows remote attackers to affect confidentiality, integrity, and availability via unknown vectors related to Libraries, a different vulnerability than CVE-2013-5850.

- [https://github.com/guhe120/CVE-2013-5842](https://github.com/guhe120/CVE-2013-5842) :  ![starts](https://img.shields.io/github/stars/guhe120/CVE-2013-5842.svg) ![forks](https://img.shields.io/github/forks/guhe120/CVE-2013-5842.svg)

