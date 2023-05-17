# Update 2023-05-17
## CVE-2023-32243
 Improper Authentication vulnerability in WPDeveloper Essential Addons for Elementor allows Privilege Escalation. This issue affects Essential Addons for Elementor: from 5.4.0 through 5.7.1.

- [https://github.com/RandomRobbieBF/CVE-2023-32243](https://github.com/RandomRobbieBF/CVE-2023-32243) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2023-32243.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2023-32243.svg)


## CVE-2023-32233
 In the Linux kernel through 6.3.1, a use-after-free in Netfilter nf_tables when processing batch requests can be abused to perform arbitrary read and write operations on kernel memory. Unprivileged local users can obtain root privileges. This occurs because anonymous sets are mishandled.

- [https://github.com/Liuk3r/CVE-2023-32233](https://github.com/Liuk3r/CVE-2023-32233) :  ![starts](https://img.shields.io/github/stars/Liuk3r/CVE-2023-32233.svg) ![forks](https://img.shields.io/github/forks/Liuk3r/CVE-2023-32233.svg)
- [https://github.com/PIDAN-HEIDASHUAI/CVE-2023-32233](https://github.com/PIDAN-HEIDASHUAI/CVE-2023-32233) :  ![starts](https://img.shields.io/github/stars/PIDAN-HEIDASHUAI/CVE-2023-32233.svg) ![forks](https://img.shields.io/github/forks/PIDAN-HEIDASHUAI/CVE-2023-32233.svg)


## CVE-2023-32073
 WWBN AVideo is an open source video platform. In versions 12.4 and prior, a command injection vulnerability exists at `plugin/CloneSite/cloneClient.json.php` which allows Remote Code Execution if you CloneSite Plugin. This is a bypass to the fix for CVE-2023-30854, which affects WWBN AVideo up to version 12.3. This issue is patched in commit 1df4af01f80d56ff2c4c43b89d0bac151e7fb6e3.

- [https://github.com/jmrcsnchz/CVE-2023-32073](https://github.com/jmrcsnchz/CVE-2023-32073) :  ![starts](https://img.shields.io/github/stars/jmrcsnchz/CVE-2023-32073.svg) ![forks](https://img.shields.io/github/forks/jmrcsnchz/CVE-2023-32073.svg)


## CVE-2023-28206
 An out-of-bounds write issue was addressed with improved input validation. This issue is fixed in macOS Monterey 12.6.5, iOS 16.4.1 and iPadOS 16.4.1, iOS 15.7.5 and iPadOS 15.7.5, macOS Big Sur 11.7.6, macOS Ventura 13.3.1. An app may be able to execute arbitrary code with kernel privileges. Apple is aware of a report that this issue may have been actively exploited.

- [https://github.com/acceleratortroll/acceleratortroll](https://github.com/acceleratortroll/acceleratortroll) :  ![starts](https://img.shields.io/github/stars/acceleratortroll/acceleratortroll.svg) ![forks](https://img.shields.io/github/forks/acceleratortroll/acceleratortroll.svg)


## CVE-2023-25194
 A possible security vulnerability has been identified in Apache Kafka Connect. This requires access to a Kafka Connect worker, and the ability to create/modify connectors on it with an arbitrary Kafka client SASL JAAS config and a SASL-based security protocol, which has been possible on Kafka Connect clusters since Apache Kafka 2.3.0. When configuring the connector via the Kafka Connect REST API, an authenticated operator can set the `sasl.jaas.config` property for any of the connector's Kafka clients to &quot;com.sun.security.auth.module.JndiLoginModule&quot;, which can be done via the `producer.override.sasl.jaas.config`, `consumer.override.sasl.jaas.config`, or `admin.override.sasl.jaas.config` properties. This will allow the server to connect to the attacker's LDAP server and deserialize the LDAP response, which the attacker can use to execute java deserialization gadget chains on the Kafka connect server. Attacker can cause unrestricted deserialization of untrusted data (or) RCE vulnerability when there are gadgets in the classpath. Since Apache Kafka 3.0.0, users are allowed to specify these properties in connector configurations for Kafka Connect clusters running with out-of-the-box configurations. Before Apache Kafka 3.0.0, users may not specify these properties unless the Kafka Connect cluster has been reconfigured with a connector client override policy that permits them. Since Apache Kafka 3.4.0, we have added a system property (&quot;-Dorg.apache.kafka.disallowed.login.modules&quot;) to disable the problematic login modules usage in SASL JAAS configuration. Also by default &quot;com.sun.security.auth.module.JndiLoginModule&quot; is disabled in Apache Kafka 3.4.0. We advise the Kafka Connect users to validate connector configurations and only allow trusted JNDI configurations. Also examine connector dependencies for vulnerable versions and either upgrade their connectors, upgrading that specific dependency, or removing the connectors as options for remediation. Finally, in addition to leveraging the &quot;org.apache.kafka.disallowed.login.modules&quot; system property, Kafka Connect users can also implement their own connector client config override policy, which can be used to control which Kafka client properties can be overridden directly in a connector config and which cannot.

- [https://github.com/Veraxy00/Flink-Kafka-Vul](https://github.com/Veraxy00/Flink-Kafka-Vul) :  ![starts](https://img.shields.io/github/stars/Veraxy00/Flink-Kafka-Vul.svg) ![forks](https://img.shields.io/github/forks/Veraxy00/Flink-Kafka-Vul.svg)


## CVE-2022-41544
 GetSimple CMS v3.3.16 was discovered to contain a remote code execution (RCE) vulnerability via the edited_file parameter in admin/theme-edit.php.

- [https://github.com/yosef0x01/CVE-2022-41544](https://github.com/yosef0x01/CVE-2022-41544) :  ![starts](https://img.shields.io/github/stars/yosef0x01/CVE-2022-41544.svg) ![forks](https://img.shields.io/github/forks/yosef0x01/CVE-2022-41544.svg)


## CVE-2022-40471
 Remote Code Execution in Clinic's Patient Management System v 1.0 allows Attacker to Upload arbitrary php webshell via profile picture upload functionality in users.php

- [https://github.com/RashidKhanPathan/CVE-2022-40471](https://github.com/RashidKhanPathan/CVE-2022-40471) :  ![starts](https://img.shields.io/github/stars/RashidKhanPathan/CVE-2022-40471.svg) ![forks](https://img.shields.io/github/forks/RashidKhanPathan/CVE-2022-40471.svg)


## CVE-2022-39253
 Git is an open source, scalable, distributed revision control system. Versions prior to 2.30.6, 2.31.5, 2.32.4, 2.33.5, 2.34.5, 2.35.5, 2.36.3, and 2.37.4 are subject to exposure of sensitive information to a malicious actor. When performing a local clone (where the source and target of the clone are on the same volume), Git copies the contents of the source's `$GIT_DIR/objects` directory into the destination by either creating hardlinks to the source contents, or copying them (if hardlinks are disabled via `--no-hardlinks`). A malicious actor could convince a victim to clone a repository with a symbolic link pointing at sensitive information on the victim's machine. This can be done either by having the victim clone a malicious repository on the same machine, or having them clone a malicious repository embedded as a bare repository via a submodule from any source, provided they clone with the `--recurse-submodules` option. Git does not create symbolic links in the `$GIT_DIR/objects` directory. The problem has been patched in the versions published on 2022-10-18, and backported to v2.30.x. Potential workarounds: Avoid cloning untrusted repositories using the `--local` optimization when on a shared machine, either by passing the `--no-local` option to `git clone` or cloning from a URL that uses the `file://` scheme. Alternatively, avoid cloning repositories from untrusted sources with `--recurse-submodules` or run `git config --global protocol.file.allow user`.

- [https://github.com/HiImDarwin/NetworkSecurityFinalProject](https://github.com/HiImDarwin/NetworkSecurityFinalProject) :  ![starts](https://img.shields.io/github/stars/HiImDarwin/NetworkSecurityFinalProject.svg) ![forks](https://img.shields.io/github/forks/HiImDarwin/NetworkSecurityFinalProject.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mightysai1997/CVE-2021-41773-L-](https://github.com/mightysai1997/CVE-2021-41773-L-) :  ![starts](https://img.shields.io/github/stars/mightysai1997/CVE-2021-41773-L-.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/CVE-2021-41773-L-.svg)
- [https://github.com/LayarKacaSiber/CVE-2021-41773](https://github.com/LayarKacaSiber/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/LayarKacaSiber/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/LayarKacaSiber/CVE-2021-41773.svg)
- [https://github.com/MatanelGordon/docker-cve-2021-41773](https://github.com/MatanelGordon/docker-cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/MatanelGordon/docker-cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/MatanelGordon/docker-cve-2021-41773.svg)


## CVE-2021-34473
 Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-31196, CVE-2021-31206.

- [https://github.com/je6k/CVE-2021-34473-Exchange-ProxyShell](https://github.com/je6k/CVE-2021-34473-Exchange-ProxyShell) :  ![starts](https://img.shields.io/github/stars/je6k/CVE-2021-34473-Exchange-ProxyShell.svg) ![forks](https://img.shields.io/github/forks/je6k/CVE-2021-34473-Exchange-ProxyShell.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/laolisafe/CVE-2020-1938](https://github.com/laolisafe/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/laolisafe/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/laolisafe/CVE-2020-1938.svg)
- [https://github.com/YounesTasra-R4z3rSw0rd/CVE-2020-1938](https://github.com/YounesTasra-R4z3rSw0rd/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/YounesTasra-R4z3rSw0rd/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/YounesTasra-R4z3rSw0rd/CVE-2020-1938.svg)
- [https://github.com/einzbernnn/CVE-2020-1938Scan](https://github.com/einzbernnn/CVE-2020-1938Scan) :  ![starts](https://img.shields.io/github/stars/einzbernnn/CVE-2020-1938Scan.svg) ![forks](https://img.shields.io/github/forks/einzbernnn/CVE-2020-1938Scan.svg)


## CVE-2019-1130
 An elevation of privilege vulnerability exists when Windows AppX Deployment Service (AppXSVC) improperly handles hard links, aka 'Windows Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-1129.

- [https://github.com/S3cur3Th1sSh1t/SharpByeBear](https://github.com/S3cur3Th1sSh1t/SharpByeBear) :  ![starts](https://img.shields.io/github/stars/S3cur3Th1sSh1t/SharpByeBear.svg) ![forks](https://img.shields.io/github/forks/S3cur3Th1sSh1t/SharpByeBear.svg)


## CVE-2017-13156
 An elevation of privilege vulnerability in the Android system (art). Product: Android. Versions: 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID A-64211847.

- [https://github.com/ppapadatis/python-janus-vulnerability-scan](https://github.com/ppapadatis/python-janus-vulnerability-scan) :  ![starts](https://img.shields.io/github/stars/ppapadatis/python-janus-vulnerability-scan.svg) ![forks](https://img.shields.io/github/forks/ppapadatis/python-janus-vulnerability-scan.svg)

