# Update 2023-12-29
## CVE-2023-51764
 Postfix through 3.8.4 allows SMTP smuggling unless configured with smtpd_data_restrictions=reject_unauth_pipelining and smtpd_discard_ehlo_keywords=chunking (or certain other options that exist in recent versions). Remote attackers can use a published exploitation technique to inject e-mail messages with a spoofed MAIL FROM address, allowing bypass of an SPF protection mechanism. This occurs because Postfix supports &lt;LF&gt;.&lt;CR&gt;&lt;LF&gt; but some other popular e-mail servers do not. To prevent attack variants (by always disallowing &lt;LF&gt; without &lt;CR&gt;), a different solution is required: the smtpd_forbid_bare_newline=yes option with a Postfix minimum version of 3.5.23, 3.6.13, 3.7.9, 3.8.4, or 3.9.

- [https://github.com/eeenvik1/CVE-2023-51764](https://github.com/eeenvik1/CVE-2023-51764) :  ![starts](https://img.shields.io/github/stars/eeenvik1/CVE-2023-51764.svg) ![forks](https://img.shields.io/github/forks/eeenvik1/CVE-2023-51764.svg)


## CVE-2023-51385
 In ssh in OpenSSH before 9.6, OS command injection might occur if a user name or host name has shell metacharacters, and this name is referenced by an expansion token in certain situations. For example, an untrusted Git repository can have a submodule with shell metacharacters in a user name or host name.

- [https://github.com/zhulin2/testCVE-2023-51385](https://github.com/zhulin2/testCVE-2023-51385) :  ![starts](https://img.shields.io/github/stars/zhulin2/testCVE-2023-51385.svg) ![forks](https://img.shields.io/github/forks/zhulin2/testCVE-2023-51385.svg)
- [https://github.com/jacknickelson/poc-cve-2023-51385](https://github.com/jacknickelson/poc-cve-2023-51385) :  ![starts](https://img.shields.io/github/stars/jacknickelson/poc-cve-2023-51385.svg) ![forks](https://img.shields.io/github/forks/jacknickelson/poc-cve-2023-51385.svg)


## CVE-2023-43481
 An issue in Shenzhen TCL Browser TV Web BrowseHere (aka com.tcl.browser) 6.65.022_dab24cc6_231221_gp allows a remote attacker to execute arbitrary JavaScript code via the com.tcl.browser.portal.browse.activity.BrowsePageActivity component.

- [https://github.com/actuator/com.tcl.browser](https://github.com/actuator/com.tcl.browser) :  ![starts](https://img.shields.io/github/stars/actuator/com.tcl.browser.svg) ![forks](https://img.shields.io/github/forks/actuator/com.tcl.browser.svg)


## CVE-2023-43345
 Cross-site scripting (XSS) vulnerability in opensolution Quick CMS v.6.7 allows a local attacker to execute arbitrary code via a crafted script to the Content - Name parameter in the Pages Menu component.

- [https://github.com/sromanhu/CVE-2023-43345-Quick-CMS-Stored-XSS---Pages-Content](https://github.com/sromanhu/CVE-2023-43345-Quick-CMS-Stored-XSS---Pages-Content) :  ![starts](https://img.shields.io/github/stars/sromanhu/CVE-2023-43345-Quick-CMS-Stored-XSS---Pages-Content.svg) ![forks](https://img.shields.io/github/forks/sromanhu/CVE-2023-43345-Quick-CMS-Stored-XSS---Pages-Content.svg)


## CVE-2023-40121
 In appendEscapedSQLString of DatabaseUtils.java, there is a possible SQL injection due to unsafe deserialization. This could lead to local information disclosure with User execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/nidhi7598/frameworks_base_AOSP10_r33_core_CVE-2023-40121](https://github.com/nidhi7598/frameworks_base_AOSP10_r33_core_CVE-2023-40121) :  ![starts](https://img.shields.io/github/stars/nidhi7598/frameworks_base_AOSP10_r33_core_CVE-2023-40121.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/frameworks_base_AOSP10_r33_core_CVE-2023-40121.svg)
- [https://github.com/hshivhare67/platform_framework_base_AOSP6_r22_CVE-2023-40121](https://github.com/hshivhare67/platform_framework_base_AOSP6_r22_CVE-2023-40121) :  ![starts](https://img.shields.io/github/stars/hshivhare67/platform_framework_base_AOSP6_r22_CVE-2023-40121.svg) ![forks](https://img.shields.io/github/forks/hshivhare67/platform_framework_base_AOSP6_r22_CVE-2023-40121.svg)


## CVE-2023-33565
 ROS2 (Robot Operating System 2) Foxy Fitzroy ROS_VERSION=2 and ROS_PYTHON_VERSION=3 are vulnerable to Denial-of-Service (DoS) attacks. A malicious user potentially exploited the vulnerability remotely and crashed the ROS2 nodes.

- [https://github.com/16yashpatel/CVE-2023-33565](https://github.com/16yashpatel/CVE-2023-33565) :  ![starts](https://img.shields.io/github/stars/16yashpatel/CVE-2023-33565.svg) ![forks](https://img.shields.io/github/forks/16yashpatel/CVE-2023-33565.svg)


## CVE-2023-29017
 vm2 is a sandbox that can run untrusted code with whitelisted Node's built-in modules. Prior to version 3.9.15, vm2 was not properly handling host objects passed to `Error.prepareStackTrace` in case of unhandled async errors. A threat actor could bypass the sandbox protections to gain remote code execution rights on the host running the sandbox. This vulnerability was patched in the release of version 3.9.15 of vm2. There are no known workarounds.

- [https://github.com/passwa11/CVE-2023-29017-reverse-shell](https://github.com/passwa11/CVE-2023-29017-reverse-shell) :  ![starts](https://img.shields.io/github/stars/passwa11/CVE-2023-29017-reverse-shell.svg) ![forks](https://img.shields.io/github/forks/passwa11/CVE-2023-29017-reverse-shell.svg)


## CVE-2023-26035
 ZoneMinder is a free, open source Closed-circuit television software application for Linux which supports IP, USB and Analog cameras. Versions prior to 1.36.33 and 1.37.33 are vulnerable to Unauthenticated Remote Code Execution via Missing Authorization. There are no permissions check on the snapshot action, which expects an id to fetch an existing monitor but can be passed an object to create a new one instead. TriggerOn ends up calling shell_exec using the supplied Id. This issue is fixed in This issue is fixed in versions 1.36.33 and 1.37.33.

- [https://github.com/Faelian/zoneminder_CVE-2023-26035](https://github.com/Faelian/zoneminder_CVE-2023-26035) :  ![starts](https://img.shields.io/github/stars/Faelian/zoneminder_CVE-2023-26035.svg) ![forks](https://img.shields.io/github/forks/Faelian/zoneminder_CVE-2023-26035.svg)


## CVE-2023-25194
 A possible security vulnerability has been identified in Apache Kafka Connect API. This requires access to a Kafka Connect worker, and the ability to create/modify connectors on it with an arbitrary Kafka client SASL JAAS config and a SASL-based security protocol, which has been possible on Kafka Connect clusters since Apache Kafka Connect 2.3.0. When configuring the connector via the Kafka Connect REST API, an authenticated operator can set the `sasl.jaas.config` property for any of the connector's Kafka clients to &quot;com.sun.security.auth.module.JndiLoginModule&quot;, which can be done via the `producer.override.sasl.jaas.config`, `consumer.override.sasl.jaas.config`, or `admin.override.sasl.jaas.config` properties. This will allow the server to connect to the attacker's LDAP server and deserialize the LDAP response, which the attacker can use to execute java deserialization gadget chains on the Kafka connect server. Attacker can cause unrestricted deserialization of untrusted data (or) RCE vulnerability when there are gadgets in the classpath. Since Apache Kafka 3.0.0, users are allowed to specify these properties in connector configurations for Kafka Connect clusters running with out-of-the-box configurations. Before Apache Kafka 3.0.0, users may not specify these properties unless the Kafka Connect cluster has been reconfigured with a connector client override policy that permits them. Since Apache Kafka 3.4.0, we have added a system property (&quot;-Dorg.apache.kafka.disallowed.login.modules&quot;) to disable the problematic login modules usage in SASL JAAS configuration. Also by default &quot;com.sun.security.auth.module.JndiLoginModule&quot; is disabled in Apache Kafka Connect 3.4.0. We advise the Kafka Connect users to validate connector configurations and only allow trusted JNDI configurations. Also examine connector dependencies for vulnerable versions and either upgrade their connectors, upgrading that specific dependency, or removing the connectors as options for remediation. Finally, in addition to leveraging the &quot;org.apache.kafka.disallowed.login.modules&quot; system property, Kafka Connect users can also implement their own connector client config override policy, which can be used to control which Kafka client properties can be overridden directly in a connector config and which cannot.

- [https://github.com/YongYe-Security/CVE-2023-25194](https://github.com/YongYe-Security/CVE-2023-25194) :  ![starts](https://img.shields.io/github/stars/YongYe-Security/CVE-2023-25194.svg) ![forks](https://img.shields.io/github/forks/YongYe-Security/CVE-2023-25194.svg)


## CVE-2023-23397
 Microsoft Outlook Elevation of Privilege Vulnerability

- [https://github.com/ducnorth2712/CVE-2023-23397](https://github.com/ducnorth2712/CVE-2023-23397) :  ![starts](https://img.shields.io/github/stars/ducnorth2712/CVE-2023-23397.svg) ![forks](https://img.shields.io/github/forks/ducnorth2712/CVE-2023-23397.svg)


## CVE-2023-6553
 The Backup Migration plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 1.3.7 via the /includes/backup-heart.php file. This is due to an attacker being able to control the values passed to an include, and subsequently leverage that to achieve remote code execution. This makes it possible for unauthenticated attackers to easily execute code on the server.

- [https://github.com/motikan2010/CVE-2023-6553-PoC](https://github.com/motikan2010/CVE-2023-6553-PoC) :  ![starts](https://img.shields.io/github/stars/motikan2010/CVE-2023-6553-PoC.svg) ![forks](https://img.shields.io/github/forks/motikan2010/CVE-2023-6553-PoC.svg)


## CVE-2023-5360
 The Royal Elementor Addons and Templates WordPress plugin before 1.3.79 does not properly validate uploaded files, which could allow unauthenticated users to upload arbitrary files, such as PHP and achieve RCE.

- [https://github.com/angkerithhack001/CVE-2023-5360-PoC](https://github.com/angkerithhack001/CVE-2023-5360-PoC) :  ![starts](https://img.shields.io/github/stars/angkerithhack001/CVE-2023-5360-PoC.svg) ![forks](https://img.shields.io/github/forks/angkerithhack001/CVE-2023-5360-PoC.svg)


## CVE-2022-45688
 A stack overflow in the XML.toJSONObject component of hutool-json v5.8.10 allows attackers to cause a Denial of Service (DoS) via crafted JSON or XML data.

- [https://github.com/scabench/jsonorg-tp1](https://github.com/scabench/jsonorg-tp1) :  ![starts](https://img.shields.io/github/stars/scabench/jsonorg-tp1.svg) ![forks](https://img.shields.io/github/forks/scabench/jsonorg-tp1.svg)


## CVE-2022-22963
 In Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions, when using routing functionality it is possible for a user to provide a specially crafted SpEL as a routing-expression that may result in remote code execution and access to local resources.

- [https://github.com/xmqaq/CVE-2022-22963](https://github.com/xmqaq/CVE-2022-22963) :  ![starts](https://img.shields.io/github/stars/xmqaq/CVE-2022-22963.svg) ![forks](https://img.shields.io/github/forks/xmqaq/CVE-2022-22963.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `&lt;grafana_host_url&gt;/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/fanygit/Grafana-CVE-2021-43798Exp](https://github.com/fanygit/Grafana-CVE-2021-43798Exp) :  ![starts](https://img.shields.io/github/stars/fanygit/Grafana-CVE-2021-43798Exp.svg) ![forks](https://img.shields.io/github/forks/fanygit/Grafana-CVE-2021-43798Exp.svg)


## CVE-2021-22986
 On BIG-IP versions 16.0.x before 16.0.1.1, 15.1.x before 15.1.2.1, 14.1.x before 14.1.4, 13.1.x before 13.1.3.6, and 12.1.x before 12.1.5.3 amd BIG-IQ 7.1.0.x before 7.1.0.3 and 7.0.0.x before 7.0.0.2, the iControl REST interface has an unauthenticated remote command execution vulnerability. Note: Software versions which have reached End of Software Development (EoSD) are not evaluated.

- [https://github.com/huydung26/CVE-2021-22986](https://github.com/huydung26/CVE-2021-22986) :  ![starts](https://img.shields.io/github/stars/huydung26/CVE-2021-22986.svg) ![forks](https://img.shields.io/github/forks/huydung26/CVE-2021-22986.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/An00bRektn/CVE-2021-4034](https://github.com/An00bRektn/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/An00bRektn/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/An00bRektn/CVE-2021-4034.svg)
- [https://github.com/sofire/polkit-0.96-CVE-2021-4034](https://github.com/sofire/polkit-0.96-CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/sofire/polkit-0.96-CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/sofire/polkit-0.96-CVE-2021-4034.svg)
- [https://github.com/deoxykev/CVE-2021-4034-Rust](https://github.com/deoxykev/CVE-2021-4034-Rust) :  ![starts](https://img.shields.io/github/stars/deoxykev/CVE-2021-4034-Rust.svg) ![forks](https://img.shields.io/github/forks/deoxykev/CVE-2021-4034-Rust.svg)
- [https://github.com/Nosferatuvjr/PwnKit](https://github.com/Nosferatuvjr/PwnKit) :  ![starts](https://img.shields.io/github/stars/Nosferatuvjr/PwnKit.svg) ![forks](https://img.shields.io/github/forks/Nosferatuvjr/PwnKit.svg)
- [https://github.com/0x01-sec/CVE-2021-4034-](https://github.com/0x01-sec/CVE-2021-4034-) :  ![starts](https://img.shields.io/github/stars/0x01-sec/CVE-2021-4034-.svg) ![forks](https://img.shields.io/github/forks/0x01-sec/CVE-2021-4034-.svg)
- [https://github.com/mutur4/CVE-2021-4034](https://github.com/mutur4/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/mutur4/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/mutur4/CVE-2021-4034.svg)


## CVE-2021-2471
 Vulnerability in the MySQL Connectors product of Oracle MySQL (component: Connector/J). Supported versions that are affected are 8.0.26 and prior. Difficult to exploit vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Connectors. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all MySQL Connectors accessible data and unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Connectors. CVSS 3.1 Base Score 5.9 (Confidentiality and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:H).

- [https://github.com/DrunkenShells/CVE-2021-2471](https://github.com/DrunkenShells/CVE-2021-2471) :  ![starts](https://img.shields.io/github/stars/DrunkenShells/CVE-2021-2471.svg) ![forks](https://img.shields.io/github/forks/DrunkenShells/CVE-2021-2471.svg)


## CVE-2020-15780
 An issue was discovered in drivers/acpi/acpi_configfs.c in the Linux kernel before 5.7.7. Injection of malicious ACPI tables via configfs could be used by attackers to bypass lockdown and secure boot restrictions, aka CID-75b0cea7bf30.

- [https://github.com/Annavid/CVE-2020-15780-exploit](https://github.com/Annavid/CVE-2020-15780-exploit) :  ![starts](https://img.shields.io/github/stars/Annavid/CVE-2020-15780-exploit.svg) ![forks](https://img.shields.io/github/forks/Annavid/CVE-2020-15780-exploit.svg)


## CVE-2020-10963
 FrozenNode Laravel-Administrator through 5.0.12 allows unrestricted file upload (and consequently Remote Code Execution) via admin/tips_image/image/file_upload image upload with PHP content within a GIF image that has the .php extension. NOTE: this product is discontinued.

- [https://github.com/scopion/CVE-2020-10963](https://github.com/scopion/CVE-2020-10963) :  ![starts](https://img.shields.io/github/stars/scopion/CVE-2020-10963.svg) ![forks](https://img.shields.io/github/forks/scopion/CVE-2020-10963.svg)


## CVE-2020-9495
 Apache Archiva login service before 2.2.5 is vulnerable to LDAP injection. A attacker is able to retrieve user attribute data from the connected LDAP server by providing special values to the login form. With certain characters it is possible to modify the LDAP filter used to query the LDAP users. By measuring the response time for the login request, arbitrary attribute data can be retrieved from LDAP user objects.

- [https://github.com/ggolawski/CVE-2020-9495](https://github.com/ggolawski/CVE-2020-9495) :  ![starts](https://img.shields.io/github/stars/ggolawski/CVE-2020-9495.svg) ![forks](https://img.shields.io/github/forks/ggolawski/CVE-2020-9495.svg)


## CVE-2018-17552
 SQL Injection in login.php in Naviwebs Navigate CMS 2.8 allows remote attackers to bypass authentication via the navigate-user cookie.

- [https://github.com/kimstars/CVE-2018-17552](https://github.com/kimstars/CVE-2018-17552) :  ![starts](https://img.shields.io/github/stars/kimstars/CVE-2018-17552.svg) ![forks](https://img.shields.io/github/forks/kimstars/CVE-2018-17552.svg)


## CVE-2006-2842
 ** DISP

- [https://github.com/karthi-the-hacker/CVE-2006-2842](https://github.com/karthi-the-hacker/CVE-2006-2842) :  ![starts](https://img.shields.io/github/stars/karthi-the-hacker/CVE-2006-2842.svg) ![forks](https://img.shields.io/github/forks/karthi-the-hacker/CVE-2006-2842.svg)

