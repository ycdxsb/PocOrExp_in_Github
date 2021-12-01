# Update 2021-12-01
## CVE-2021-40444
 Microsoft MSHTML Remote Code Execution Vulnerability

- [https://github.com/YxZi5/Detection-CVE_2021_40444](https://github.com/YxZi5/Detection-CVE_2021_40444) :  ![starts](https://img.shields.io/github/stars/YxZi5/Detection-CVE_2021_40444.svg) ![forks](https://img.shields.io/github/forks/YxZi5/Detection-CVE_2021_40444.svg)


## CVE-2021-40438
 A crafted request uri-path can cause mod_proxy to forward the request to an origin server choosen by the remote user. This issue affects Apache HTTP Server 2.4.48 and earlier.

- [https://github.com/pisut4152/Sigma-Rule-for-CVE-2021-40438-exploitation-attempt](https://github.com/pisut4152/Sigma-Rule-for-CVE-2021-40438-exploitation-attempt) :  ![starts](https://img.shields.io/github/stars/pisut4152/Sigma-Rule-for-CVE-2021-40438-exploitation-attempt.svg) ![forks](https://img.shields.io/github/forks/pisut4152/Sigma-Rule-for-CVE-2021-40438-exploitation-attempt.svg)


## CVE-2021-32849
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/ohnonoyesyes/CVE-2021-32849](https://github.com/ohnonoyesyes/CVE-2021-32849) :  ![starts](https://img.shields.io/github/stars/ohnonoyesyes/CVE-2021-32849.svg) ![forks](https://img.shields.io/github/forks/ohnonoyesyes/CVE-2021-32849.svg)


## CVE-2020-14882
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/XTeam-Wing/CVE-2020-14882](https://github.com/XTeam-Wing/CVE-2020-14882) :  ![starts](https://img.shields.io/github/stars/XTeam-Wing/CVE-2020-14882.svg) ![forks](https://img.shields.io/github/forks/XTeam-Wing/CVE-2020-14882.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/streghstreek/CVE-2020-1938](https://github.com/streghstreek/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/streghstreek/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/streghstreek/CVE-2020-1938.svg)
- [https://github.com/Hancheng-Lei/Hacking-Vulnerability-CVE-2020-1938-Ghostcat](https://github.com/Hancheng-Lei/Hacking-Vulnerability-CVE-2020-1938-Ghostcat) :  ![starts](https://img.shields.io/github/stars/Hancheng-Lei/Hacking-Vulnerability-CVE-2020-1938-Ghostcat.svg) ![forks](https://img.shields.io/github/forks/Hancheng-Lei/Hacking-Vulnerability-CVE-2020-1938-Ghostcat.svg)


## CVE-2020-0114
 In onCreateSliceProvider of KeyguardSliceProvider.java, there is a possible confused deputy due to a PendingIntent error. This could lead to local escalation of privilege that allows actions performed as the System UI, with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10Android ID: A-147606347

- [https://github.com/Nivaskumark/CVE-2020-0114-frameworks_base_afterfix](https://github.com/Nivaskumark/CVE-2020-0114-frameworks_base_afterfix) :  ![starts](https://img.shields.io/github/stars/Nivaskumark/CVE-2020-0114-frameworks_base_afterfix.svg) ![forks](https://img.shields.io/github/forks/Nivaskumark/CVE-2020-0114-frameworks_base_afterfix.svg)


## CVE-2020-0097
 In various methods of PackageManagerService.java, there is a possible permission bypass due to a missing condition for system apps. This could lead to local escalation of privilege with User privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-9 Android-10Android ID: A-145981139

- [https://github.com/Nivaskumark/CVE-2020-0097-frameworks_base_afterfix](https://github.com/Nivaskumark/CVE-2020-0097-frameworks_base_afterfix) :  ![starts](https://img.shields.io/github/stars/Nivaskumark/CVE-2020-0097-frameworks_base_afterfix.svg) ![forks](https://img.shields.io/github/forks/Nivaskumark/CVE-2020-0097-frameworks_base_afterfix.svg)


## CVE-2020-0074
 In verifyIntentFiltersIfNeeded of PackageManagerService.java, there is a possible settings bypass allowing an app to become the default handler for arbitrary domains. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-11 Android-8.0 Android-8.1 Android-9 Android-10Android ID: A-146204120

- [https://github.com/Nivaskumark/CVE-2020-0074-frameworks_base_after](https://github.com/Nivaskumark/CVE-2020-0074-frameworks_base_after) :  ![starts](https://img.shields.io/github/stars/Nivaskumark/CVE-2020-0074-frameworks_base_after.svg) ![forks](https://img.shields.io/github/forks/Nivaskumark/CVE-2020-0074-frameworks_base_after.svg)


## CVE-2019-11043
 In PHP versions 7.1.x below 7.1.33, 7.2.x below 7.2.24 and 7.3.x below 7.3.11 in certain configurations of FPM setup it is possible to cause FPM module to write past allocated buffers into the space reserved for FCGI protocol data, thus opening the possibility of remote code execution.

- [https://github.com/HxDDD/CVE-PoC](https://github.com/HxDDD/CVE-PoC) :  ![starts](https://img.shields.io/github/stars/HxDDD/CVE-PoC.svg) ![forks](https://img.shields.io/github/forks/HxDDD/CVE-PoC.svg)


## CVE-2018-7600
 Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations.

- [https://github.com/jyo-zi/CVE-2018-7600](https://github.com/jyo-zi/CVE-2018-7600) :  ![starts](https://img.shields.io/github/stars/jyo-zi/CVE-2018-7600.svg) ![forks](https://img.shields.io/github/forks/jyo-zi/CVE-2018-7600.svg)


## CVE-2018-1273
 Spring Data Commons, versions prior to 1.13 to 1.13.10, 2.0 to 2.0.5, and older unsupported versions, contain a property binder vulnerability caused by improper neutralization of special elements. An unauthenticated remote malicious user (or attacker) can supply specially crafted request parameters against Spring Data REST backed HTTP resources or using Spring Data's projection-based request payload binding hat can lead to a remote code execution attack.

- [https://github.com/webr0ck/poc-cve-2018-1273](https://github.com/webr0ck/poc-cve-2018-1273) :  ![starts](https://img.shields.io/github/stars/webr0ck/poc-cve-2018-1273.svg) ![forks](https://img.shields.io/github/forks/webr0ck/poc-cve-2018-1273.svg)


## CVE-2017-12636
 CouchDB administrative users can configure the database server via HTTP(S). Some of the configuration options include paths for operating system-level binaries that are subsequently launched by CouchDB. This allows an admin user in Apache CouchDB before 1.7.0 and 2.x before 2.1.1 to execute arbitrary shell commands as the CouchDB user, including downloading and executing scripts from the public internet.

- [https://github.com/XTeam-Wing/CVE-2017-12636](https://github.com/XTeam-Wing/CVE-2017-12636) :  ![starts](https://img.shields.io/github/stars/XTeam-Wing/CVE-2017-12636.svg) ![forks](https://img.shields.io/github/forks/XTeam-Wing/CVE-2017-12636.svg)


## CVE-2017-2824
 An exploitable code execution vulnerability exists in the trapper command functionality of Zabbix Server 2.4.X. A specially crafted set of packets can cause a command injection resulting in remote code execution. An attacker can make requests from an active Zabbix Proxy to trigger this vulnerability.

- [https://github.com/listenquiet/cve-2017-2824-reverse-shell](https://github.com/listenquiet/cve-2017-2824-reverse-shell) :  ![starts](https://img.shields.io/github/stars/listenquiet/cve-2017-2824-reverse-shell.svg) ![forks](https://img.shields.io/github/forks/listenquiet/cve-2017-2824-reverse-shell.svg)


## CVE-2014-8609
 The addAccount method in src/com/android/settings/accounts/AddAccountSettings.java in the Settings application in Android before 5.0.0 does not properly create a PendingIntent, which allows attackers to use the SYSTEM uid for broadcasting an intent with arbitrary component, action, or category information via a third-party authenticator in a crafted application, aka Bug 17356824.

- [https://github.com/MazX0p/CVE-2014-8609-POC](https://github.com/MazX0p/CVE-2014-8609-POC) :  ![starts](https://img.shields.io/github/stars/MazX0p/CVE-2014-8609-POC.svg) ![forks](https://img.shields.io/github/forks/MazX0p/CVE-2014-8609-POC.svg)

