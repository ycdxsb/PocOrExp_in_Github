# Update 2022-12-07
## CVE-2022-44721
 CrowdStrike Falcon 6.44.15806 allows an administrative attacker to uninstall Falcon Sensor, bypassing the intended protection mechanism in which uninstallation requires possessing a one-time token. (The sensor is managed at the kernel level.)

- [https://github.com/gmh5225/CVE-2022-44721-CsFalconUninstaller](https://github.com/gmh5225/CVE-2022-44721-CsFalconUninstaller) :  ![starts](https://img.shields.io/github/stars/gmh5225/CVE-2022-44721-CsFalconUninstaller.svg) ![forks](https://img.shields.io/github/forks/gmh5225/CVE-2022-44721-CsFalconUninstaller.svg)


## CVE-2022-43680
 In libexpat through 2.4.9, there is a use-after free caused by overeager destruction of a shared DTD in XML_ExternalEntityParserCreate in out-of-memory situations.

- [https://github.com/nidhi7598/expat_2.1.0-_CVE-2022-43680](https://github.com/nidhi7598/expat_2.1.0-_CVE-2022-43680) :  ![starts](https://img.shields.io/github/stars/nidhi7598/expat_2.1.0-_CVE-2022-43680.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/expat_2.1.0-_CVE-2022-43680.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/iyamroshan/CVE-2022-22965](https://github.com/iyamroshan/CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/iyamroshan/CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/iyamroshan/CVE-2022-22965.svg)


## CVE-2022-3602
 A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking. Note that this occurs after certificate chain signature verification and requires either a CA to have signed the malicious certificate or for the application to continue certificate verification despite failure to construct a path to a trusted issuer. An attacker can craft a malicious email address to overflow four attacker-controlled bytes on the stack. This buffer overflow could result in a crash (causing a denial of service) or potentially remote code execution. Many platforms implement stack overflow protections which would mitigate against the risk of remote code execution. The risk may be further mitigated based on stack layout for any given platform/compiler. Pre-announcements of CVE-2022-3602 described this issue as CRITICAL. Further analysis based on some of the mitigating factors described above have led this to be downgraded to HIGH. Users are still encouraged to upgrade to a new version as soon as possible. In a TLS client, this can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server requests client authentication and a malicious client connects. Fixed in OpenSSL 3.0.7 (Affected 3.0.0,3.0.1,3.0.2,3.0.3,3.0.4,3.0.5,3.0.6).

- [https://github.com/attilaszia/cve-2022-3602](https://github.com/attilaszia/cve-2022-3602) :  ![starts](https://img.shields.io/github/stars/attilaszia/cve-2022-3602.svg) ![forks](https://img.shields.io/github/forks/attilaszia/cve-2022-3602.svg)


## CVE-2022-2022
 Cross-site Scripting (XSS) - Stored in GitHub repository nocodb/nocodb prior to 0.91.7.

- [https://github.com/sdfbjaksff/CVE-2022-2022](https://github.com/sdfbjaksff/CVE-2022-2022) :  ![starts](https://img.shields.io/github/stars/sdfbjaksff/CVE-2022-2022.svg) ![forks](https://img.shields.io/github/forks/sdfbjaksff/CVE-2022-2022.svg)


## CVE-2021-21380
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. In affected versions of XWiki Platform (and only those with the Ratings API installed), the Rating Script Service expose an API to perform SQL requests without escaping the from and where search arguments. This might lead to an SQL script injection quite easily for any user having Script rights on XWiki. The problem has been patched in XWiki 12.9RC1. The only workaround besides upgrading XWiki would be to uninstall the Ratings API in XWiki from the Extension Manager.

- [https://github.com/advanced-security/codeql-workshop-cve-2021-21380](https://github.com/advanced-security/codeql-workshop-cve-2021-21380) :  ![starts](https://img.shields.io/github/stars/advanced-security/codeql-workshop-cve-2021-21380.svg) ![forks](https://img.shields.io/github/forks/advanced-security/codeql-workshop-cve-2021-21380.svg)


## CVE-2021-3749
 axios is vulnerable to Inefficient Regular Expression Complexity

- [https://github.com/T-Guerrero/axios-redos](https://github.com/T-Guerrero/axios-redos) :  ![starts](https://img.shields.io/github/stars/T-Guerrero/axios-redos.svg) ![forks](https://img.shields.io/github/forks/T-Guerrero/axios-redos.svg)


## CVE-2019-10220
 Linux kernel CIFS implementation, version 4.9.0 is vulnerable to a relative paths injection in directory entry lists.

- [https://github.com/nidhi7598/linux-4.1.15_CVE-2019-10220](https://github.com/nidhi7598/linux-4.1.15_CVE-2019-10220) :  ![starts](https://img.shields.io/github/stars/nidhi7598/linux-4.1.15_CVE-2019-10220.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/linux-4.1.15_CVE-2019-10220.svg)


## CVE-2018-11770
 From version 1.3.0 onward, Apache Spark's standalone master exposes a REST API for job submission, in addition to the submission mechanism used by spark-submit. In standalone, the config property 'spark.authenticate.secret' establishes a shared secret for authenticating requests to submit jobs via spark-submit. However, the REST API does not use this or any other authentication mechanism, and this is not adequately documented. In this case, a user would be able to run a driver program without authenticating, but not launch executors, using the REST API. This REST API is also used by Mesos, when set up to run in cluster mode (i.e., when also running MesosClusterDispatcher), for job submission. Future versions of Spark will improve documentation on these points, and prohibit setting 'spark.authenticate.secret' when running the REST APIs, to make this clear. Future versions will also disable the REST API by default in the standalone master by changing the default value of 'spark.master.rest.enabled' to 'false'.

- [https://github.com/ivanitlearning/CVE-2018-11770](https://github.com/ivanitlearning/CVE-2018-11770) :  ![starts](https://img.shields.io/github/stars/ivanitlearning/CVE-2018-11770.svg) ![forks](https://img.shields.io/github/forks/ivanitlearning/CVE-2018-11770.svg)

