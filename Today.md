# Update 2023-11-23
## CVE-2023-38408
 The PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2 has an insufficiently trustworthy search path, leading to remote code execution if an agent is forwarded to an attacker-controlled system. (Code in /usr/lib is not necessarily safe for loading into ssh-agent.) NOTE: this issue exists because of an incomplete fix for CVE-2016-10009.

- [https://github.com/snowcra5h/CVE-2023-38408](https://github.com/snowcra5h/CVE-2023-38408) :  ![starts](https://img.shields.io/github/stars/snowcra5h/CVE-2023-38408.svg) ![forks](https://img.shields.io/github/forks/snowcra5h/CVE-2023-38408.svg)


## CVE-2023-36844
 A PHP External Variable Modification vulnerability in J-Web of Juniper Networks Junos OS on EX Series allows an unauthenticated, network-based attacker to control certain, important environment variables. Using a crafted request an attacker is able to modify certain PHP environment variables leading to partial loss of integrity, which may allow chaining to other vulnerabilities. This issue affects Juniper Networks Junos OS on EX Series: * All versions prior to 20.4R3-S9; * 21.1 versions 21.1R1 and later; * 21.2 versions prior to 21.2R3-S7; * 21.3 versions prior to 21.3R3-S5; * 21.4 versions prior to 21.4R3-S5; * 22.1 versions prior to 22.1R3-S4; * 22.2 versions prior to 22.2R3-S2; * 22.3 versions prior to 22.3R3-S1; * 22.4 versions prior to 22.4R2-S2, 22.4R3; * 23.2 versions prior to 23.2R1-S1, 23.2R2.

- [https://github.com/ThatNotEasy/CVE-2023-36844](https://github.com/ThatNotEasy/CVE-2023-36844) :  ![starts](https://img.shields.io/github/stars/ThatNotEasy/CVE-2023-36844.svg) ![forks](https://img.shields.io/github/forks/ThatNotEasy/CVE-2023-36844.svg)


## CVE-2023-34960
 A command injection vulnerability in the wsConvertPpt component of Chamilo v1.11.* up to v1.11.18 allows attackers to execute arbitrary commands via a SOAP API call with a crafted PowerPoint name.

- [https://github.com/ThatNotEasy/CVE-2023-34960](https://github.com/ThatNotEasy/CVE-2023-34960) :  ![starts](https://img.shields.io/github/stars/ThatNotEasy/CVE-2023-34960.svg) ![forks](https://img.shields.io/github/forks/ThatNotEasy/CVE-2023-34960.svg)


## CVE-2023-32571
 Dynamic Linq 1.0.7.10 through 1.2.25 before 1.3.0 allows attackers to execute arbitrary code and commands when untrusted input to methods including Where, Select, OrderBy is parsed.

- [https://github.com/vert16x/CVE-2023-32571-POC](https://github.com/vert16x/CVE-2023-32571-POC) :  ![starts](https://img.shields.io/github/stars/vert16x/CVE-2023-32571-POC.svg) ![forks](https://img.shields.io/github/forks/vert16x/CVE-2023-32571-POC.svg)


## CVE-2023-32315
 Openfire is an XMPP server licensed under the Open Source Apache License. Openfire's administrative console, a web-based application, was found to be vulnerable to a path traversal attack via the setup environment. This permitted an unauthenticated user to use the unauthenticated Openfire Setup Environment in an already configured Openfire environment to access restricted pages in the Openfire Admin Console reserved for administrative users. This vulnerability affects all versions of Openfire that have been released since April 2015, starting with version 3.10.0. The problem has been patched in Openfire release 4.7.5 and 4.6.8, and further improvements will be included in the yet-to-be released first version on the 4.8 branch (which is expected to be version 4.8.0). Users are advised to upgrade. If an Openfire upgrade isn&#8217;t available for a specific release, or isn&#8217;t quickly actionable, users may see the linked github advisory (GHSA-gw42-f939-fhvm) for mitigation advice.

- [https://github.com/ThatNotEasy/CVE-2023-32315](https://github.com/ThatNotEasy/CVE-2023-32315) :  ![starts](https://img.shields.io/github/stars/ThatNotEasy/CVE-2023-32315.svg) ![forks](https://img.shields.io/github/forks/ThatNotEasy/CVE-2023-32315.svg)


## CVE-2023-27524
 Session Validation attacks in Apache Superset versions up to and including 2.0.1. Installations that have not altered the default configured SECRET_KEY according to installation instructions allow for an attacker to authenticate and access unauthorized resources. This does not affect Superset administrators who have changed the default value for SECRET_KEY config.

- [https://github.com/ThatNotEasy/CVE-2023-27524](https://github.com/ThatNotEasy/CVE-2023-27524) :  ![starts](https://img.shields.io/github/stars/ThatNotEasy/CVE-2023-27524.svg) ![forks](https://img.shields.io/github/forks/ThatNotEasy/CVE-2023-27524.svg)


## CVE-2023-27372
 SPIP before 4.2.1 allows Remote Code Execution via form values in the public area because serialization is mishandled. The fixed versions are 3.2.18, 4.0.10, 4.1.8, and 4.2.1.

- [https://github.com/ThatNotEasy/CVE-2023-27372](https://github.com/ThatNotEasy/CVE-2023-27372) :  ![starts](https://img.shields.io/github/stars/ThatNotEasy/CVE-2023-27372.svg) ![forks](https://img.shields.io/github/forks/ThatNotEasy/CVE-2023-27372.svg)


## CVE-2023-27350
 This vulnerability allows remote attackers to bypass authentication on affected installations of PaperCut NG 22.0.5 (Build 63914). Authentication is not required to exploit this vulnerability. The specific flaw exists within the SetupCompleted class. The issue results from improper access control. An attacker can leverage this vulnerability to bypass authentication and execute arbitrary code in the context of SYSTEM. Was ZDI-CAN-18987.

- [https://github.com/ThatNotEasy/CVE-2023-27350](https://github.com/ThatNotEasy/CVE-2023-27350) :  ![starts](https://img.shields.io/github/stars/ThatNotEasy/CVE-2023-27350.svg) ![forks](https://img.shields.io/github/forks/ThatNotEasy/CVE-2023-27350.svg)


## CVE-2023-23752
 An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

- [https://github.com/ThatNotEasy/CVE-2023-23752](https://github.com/ThatNotEasy/CVE-2023-23752) :  ![starts](https://img.shields.io/github/stars/ThatNotEasy/CVE-2023-23752.svg) ![forks](https://img.shields.io/github/forks/ThatNotEasy/CVE-2023-23752.svg)


## CVE-2023-20911
 In addPermission of PermissionManagerServiceImpl.java , there is a possible failure to persist permission settings due to resource exhaustion. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-11 Android-12 Android-12L Android-13Android ID: A-242537498

- [https://github.com/Trinadh465/frameworks_base_AOSP10_r33_CVE-2023-20911](https://github.com/Trinadh465/frameworks_base_AOSP10_r33_CVE-2023-20911) :  ![starts](https://img.shields.io/github/stars/Trinadh465/frameworks_base_AOSP10_r33_CVE-2023-20911.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/frameworks_base_AOSP10_r33_CVE-2023-20911.svg)


## CVE-2023-4622
 A use-after-free vulnerability in the Linux kernel's af_unix component can be exploited to achieve local privilege escalation. The unix_stream_sendpage() function tries to add data to the last skb in the peer's recv queue without locking the queue. Thus there is a race where unix_stream_sendpage() could access an skb locklessly that is being released by garbage collection, resulting in use-after-free. We recommend upgrading past commit 790c2f9d15b594350ae9bca7b236f2b1859de02c.

- [https://github.com/nidhi7598/linux-4.19.72_net_CVE-2023-4622](https://github.com/nidhi7598/linux-4.19.72_net_CVE-2023-4622) :  ![starts](https://img.shields.io/github/stars/nidhi7598/linux-4.19.72_net_CVE-2023-4622.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/linux-4.19.72_net_CVE-2023-4622.svg)


## CVE-2023-3710
 Improper Input Validation vulnerability in Honeywell PM43 on 32 bit, ARM (Printer web page modules) allows Command Injection.This issue affects PM43 versions prior to P10.19.050004. Update to the latest available firmware version of the respective printers to version MR19.5 (e.g. P10.19.050006).

- [https://github.com/vpxuser/CVE-2023-3710-POC](https://github.com/vpxuser/CVE-2023-3710-POC) :  ![starts](https://img.shields.io/github/stars/vpxuser/CVE-2023-3710-POC.svg) ![forks](https://img.shields.io/github/forks/vpxuser/CVE-2023-3710-POC.svg)


## CVE-2023-2732
 The MStore API plugin for WordPress is vulnerable to authentication bypass in versions up to, and including, 3.9.2. This is due to insufficient verification on the user being supplied during the add listing REST API request through the plugin. This makes it possible for unauthenticated attackers to log in as any existing user on the site, such as an administrator, if they have access to the user id.

- [https://github.com/ThatNotEasy/CVE-2023-2732](https://github.com/ThatNotEasy/CVE-2023-2732) :  ![starts](https://img.shields.io/github/stars/ThatNotEasy/CVE-2023-2732.svg) ![forks](https://img.shields.io/github/forks/ThatNotEasy/CVE-2023-2732.svg)


## CVE-2022-30600
 A flaw was found in moodle where logic used to count failed login attempts could result in the account lockout threshold being bypassed.

- [https://github.com/Boonjune/POC-CVE-2022-30600](https://github.com/Boonjune/POC-CVE-2022-30600) :  ![starts](https://img.shields.io/github/stars/Boonjune/POC-CVE-2022-30600.svg) ![forks](https://img.shields.io/github/forks/Boonjune/POC-CVE-2022-30600.svg)


## CVE-2022-29464
 Certain WSO2 products allow unrestricted file upload with resultant remote code execution. The attacker must use a /fileupload endpoint with a Content-Disposition directory traversal sequence to reach a directory under the web root, such as a ../../../../repository/deployment/server/webapps directory. This affects WSO2 API Manager 2.2.0 up to 4.0.0, WSO2 Identity Server 5.2.0 up to 5.11.0, WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0 and 5.6.0, WSO2 Identity Server as Key Manager 5.3.0 up to 5.11.0, WSO2 Enterprise Integrator 6.2.0 up to 6.6.0, WSO2 Open Banking AM 1.4.0 up to 2.0.0 and WSO2 Open Banking KM 1.4.0, up to 2.0.0.

- [https://github.com/ThatNotEasy/CVE-2022-29464](https://github.com/ThatNotEasy/CVE-2022-29464) :  ![starts](https://img.shields.io/github/stars/ThatNotEasy/CVE-2022-29464.svg) ![forks](https://img.shields.io/github/forks/ThatNotEasy/CVE-2022-29464.svg)


## CVE-2022-27413
 Hospital Management System v1.0 was discovered to contain a SQL injection vulnerability via the adminname parameter in admin.php.

- [https://github.com/HH1F/CVE-2022-27413](https://github.com/HH1F/CVE-2022-27413) :  ![starts](https://img.shields.io/github/stars/HH1F/CVE-2022-27413.svg) ![forks](https://img.shields.io/github/forks/HH1F/CVE-2022-27413.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/colincowie/Safer_PoC_CVE-2022-22965](https://github.com/colincowie/Safer_PoC_CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/colincowie/Safer_PoC_CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/colincowie/Safer_PoC_CVE-2022-22965.svg)
- [https://github.com/light-Life/CVE-2022-22965-GUItools](https://github.com/light-Life/CVE-2022-22965-GUItools) :  ![starts](https://img.shields.io/github/stars/light-Life/CVE-2022-22965-GUItools.svg) ![forks](https://img.shields.io/github/forks/light-Life/CVE-2022-22965-GUItools.svg)
- [https://github.com/Qualys/spring4scanwin](https://github.com/Qualys/spring4scanwin) :  ![starts](https://img.shields.io/github/stars/Qualys/spring4scanwin.svg) ![forks](https://img.shields.io/github/forks/Qualys/spring4scanwin.svg)
- [https://github.com/mariomamo/CVE-2022-22965](https://github.com/mariomamo/CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/mariomamo/CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/mariomamo/CVE-2022-22965.svg)
- [https://github.com/netcode/Spring4shell-CVE-2022-22965-POC](https://github.com/netcode/Spring4shell-CVE-2022-22965-POC) :  ![starts](https://img.shields.io/github/stars/netcode/Spring4shell-CVE-2022-22965-POC.svg) ![forks](https://img.shields.io/github/forks/netcode/Spring4shell-CVE-2022-22965-POC.svg)
- [https://github.com/irgoncalves/irule-cve-2022-22965](https://github.com/irgoncalves/irule-cve-2022-22965) :  ![starts](https://img.shields.io/github/stars/irgoncalves/irule-cve-2022-22965.svg) ![forks](https://img.shields.io/github/forks/irgoncalves/irule-cve-2022-22965.svg)
- [https://github.com/bL34cHig0/Telstra-Cybersecurity-Virtual-Experience-](https://github.com/bL34cHig0/Telstra-Cybersecurity-Virtual-Experience-) :  ![starts](https://img.shields.io/github/stars/bL34cHig0/Telstra-Cybersecurity-Virtual-Experience-.svg) ![forks](https://img.shields.io/github/forks/bL34cHig0/Telstra-Cybersecurity-Virtual-Experience-.svg)
- [https://github.com/jakabakos/CVE-2022-22965-Spring4Shell](https://github.com/jakabakos/CVE-2022-22965-Spring4Shell) :  ![starts](https://img.shields.io/github/stars/jakabakos/CVE-2022-22965-Spring4Shell.svg) ![forks](https://img.shields.io/github/forks/jakabakos/CVE-2022-22965-Spring4Shell.svg)
- [https://github.com/mwojterski/cve-2022-22965](https://github.com/mwojterski/cve-2022-22965) :  ![starts](https://img.shields.io/github/stars/mwojterski/cve-2022-22965.svg) ![forks](https://img.shields.io/github/forks/mwojterski/cve-2022-22965.svg)
- [https://github.com/ClemExp/CVE-2022-22965-PoC](https://github.com/ClemExp/CVE-2022-22965-PoC) :  ![starts](https://img.shields.io/github/stars/ClemExp/CVE-2022-22965-PoC.svg) ![forks](https://img.shields.io/github/forks/ClemExp/CVE-2022-22965-PoC.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/future-client/CVE-2021-44228](https://github.com/future-client/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/future-client/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/future-client/CVE-2021-44228.svg)


## CVE-2021-3060
 An OS command injection vulnerability in the Simple Certificate Enrollment Protocol (SCEP) feature of PAN-OS software allows an unauthenticated network-based attacker with specific knowledge of the firewall configuration to execute arbitrary code with root user privileges. The attacker must have network access to the GlobalProtect interfaces to exploit this issue. This issue impacts: PAN-OS 8.1 versions earlier than PAN-OS 8.1.20-h1; PAN-OS 9.0 versions earlier than PAN-OS 9.0.14-h3; PAN-OS 9.1 versions earlier than PAN-OS 9.1.11-h2; PAN-OS 10.0 versions earlier than PAN-OS 10.0.8; PAN-OS 10.1 versions earlier than PAN-OS 10.1.3. Prisma Access customers with Prisma Access 2.1 Preferred and Prisma Access 2.1 Innovation firewalls are impacted by this issue.

- [https://github.com/anmolksachan/CVE-2021-3060](https://github.com/anmolksachan/CVE-2021-3060) :  ![starts](https://img.shields.io/github/stars/anmolksachan/CVE-2021-3060.svg) ![forks](https://img.shields.io/github/forks/anmolksachan/CVE-2021-3060.svg)


## CVE-2021-0481
 In onActivityResult of EditUserPhotoController.java, there is a possible access of unauthorized files due to an unexpected URI handler. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-8.1 Android-9 Android-10 Android-11Android ID: A-172939189

- [https://github.com/ShaikUsaf/packages_apps_settings_AOSP10_r33_CVE-2021-0481](https://github.com/ShaikUsaf/packages_apps_settings_AOSP10_r33_CVE-2021-0481) :  ![starts](https://img.shields.io/github/stars/ShaikUsaf/packages_apps_settings_AOSP10_r33_CVE-2021-0481.svg) ![forks](https://img.shields.io/github/forks/ShaikUsaf/packages_apps_settings_AOSP10_r33_CVE-2021-0481.svg)


## CVE-2020-3580
 Multiple vulnerabilities in the web services interface of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to conduct cross-site scripting (XSS) attacks against a user of the web services interface of an affected device. The vulnerabilities are due to insufficient validation of user-supplied input by the web services interface of an affected device. An attacker could exploit these vulnerabilities by persuading a user of the interface to click a crafted link. A successful exploit could allow the attacker to execute arbitrary script code in the context of the interface or allow the attacker to access sensitive, browser-based information. Note: These vulnerabilities affect only specific AnyConnect and WebVPN configurations. For more information, see the Vulnerable Products section.

- [https://github.com/adarshvs/CVE-2020-3580](https://github.com/adarshvs/CVE-2020-3580) :  ![starts](https://img.shields.io/github/stars/adarshvs/CVE-2020-3580.svg) ![forks](https://img.shields.io/github/forks/adarshvs/CVE-2020-3580.svg)


## CVE-2015-8562
 Joomla! 1.5.x, 2.x, and 3.x before 3.4.6 allow remote attackers to conduct PHP object injection attacks and execute arbitrary PHP code via the HTTP User-Agent header, as exploited in the wild in December 2015.

- [https://github.com/lorenzodegiorgi/setup-cve-2015-8562](https://github.com/lorenzodegiorgi/setup-cve-2015-8562) :  ![starts](https://img.shields.io/github/stars/lorenzodegiorgi/setup-cve-2015-8562.svg) ![forks](https://img.shields.io/github/forks/lorenzodegiorgi/setup-cve-2015-8562.svg)

