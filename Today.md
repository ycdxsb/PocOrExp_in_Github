# Update 2026-07-14
## CVE-2026-46331
offset_valid() against INT_MIN, where negation is undefined.

- [https://github.com/MarwahHadi/CVE-2026-46331-pedit-cow](https://github.com/MarwahHadi/CVE-2026-46331-pedit-cow) :  ![starts](https://img.shields.io/github/stars/MarwahHadi/CVE-2026-46331-pedit-cow.svg) ![forks](https://img.shields.io/github/forks/MarwahHadi/CVE-2026-46331-pedit-cow.svg)


## CVE-2026-43866
Users are recommended to upgrade to version 4.21.0, which fixes the issue. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.8. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.3. After upgrading, JMS ObjectMessage handling is disabled by default in camel-jms, camel-sjms and the JMS-family components (a new objectMessageEnabled option defaults to false at the component and endpoint level), so an incoming ObjectMessage - including a DefaultExchangeHolder payload - is no longer deserialized unless the option is explicitly enabled; only set objectMessageEnabled=true when the consumed JMS destination is fed exclusively by trusted producers. For deployments that cannot upgrade immediately, restrict publish access to the queues and topics consumed by Camel to trusted producers via JMS broker authorization, and do not expose JMS consumers that map ObjectMessage bodies to untrusted networks; a JMS-provider deserialization allow-list does not mitigate this specific bypass because the crafted payload uses only universally-trusted classes.

- [https://github.com/oscerd/CVE-2026-43866](https://github.com/oscerd/CVE-2026-43866) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-43866.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-43866.svg)


## CVE-2026-43865
Users are recommended to upgrade to version 4.21.0, which fixes the issue. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.8. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.3. The fix makes Camel apply a default Hazelcast JavaSerializationFilterConfig (whitelisting the java., javax. and org.apache.camel. class-name prefixes and blacklisting java.net.) to instances it creates from its own default configuration, while leaving any user-supplied Config or HazelcastInstance untouched. For deployments that cannot upgrade immediately, configure a deserialization filter on the Hazelcast instance (Hazelcast JavaSerializationFilterConfig, or the JVM-wide system property -Djdk.serialFilter=!java.net.**;java.**;javax.**;org.apache.camel.**;!*) and enable Hazelcast cluster authentication and TLS to restrict who can reach the cluster.

- [https://github.com/oscerd/CVE-2026-43865](https://github.com/oscerd/CVE-2026-43865) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-43865.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-43865.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/x-spy/CVE-2026-43499-popsicle](https://github.com/x-spy/CVE-2026-43499-popsicle) :  ![starts](https://img.shields.io/github/stars/x-spy/CVE-2026-43499-popsicle.svg) ![forks](https://img.shields.io/github/forks/x-spy/CVE-2026-43499-popsicle.svg)
- [https://github.com/Linuxoid-cn/Mi8E5-Unlocker-by-CVE-2026-43499](https://github.com/Linuxoid-cn/Mi8E5-Unlocker-by-CVE-2026-43499) :  ![starts](https://img.shields.io/github/stars/Linuxoid-cn/Mi8E5-Unlocker-by-CVE-2026-43499.svg) ![forks](https://img.shields.io/github/forks/Linuxoid-cn/Mi8E5-Unlocker-by-CVE-2026-43499.svg)
- [https://github.com/dmcdtc/openvz-cve-patch-2026](https://github.com/dmcdtc/openvz-cve-patch-2026) :  ![starts](https://img.shields.io/github/stars/dmcdtc/openvz-cve-patch-2026.svg) ![forks](https://img.shields.io/github/forks/dmcdtc/openvz-cve-patch-2026.svg)


## CVE-2026-40860
Users are recommended to upgrade to version 4.20.0, which fixes the issue. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.7. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.2.

- [https://github.com/oscerd/CVE-2026-43866](https://github.com/oscerd/CVE-2026-43866) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-43866.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-43866.svg)


## CVE-2026-21055
 Improper export of android application components in Bixby prior to version 4.0.70.8 allows local attackers to execute arbitrary commands with Bixby privilege.

- [https://github.com/Hunt-Benito/samsung-bixby-command-execution-cve-2026-21055-improper-component-export](https://github.com/Hunt-Benito/samsung-bixby-command-execution-cve-2026-21055-improper-component-export) :  ![starts](https://img.shields.io/github/stars/Hunt-Benito/samsung-bixby-command-execution-cve-2026-21055-improper-component-export.svg) ![forks](https://img.shields.io/github/forks/Hunt-Benito/samsung-bixby-command-execution-cve-2026-21055-improper-component-export.svg)


## CVE-2026-20127
This vulnerability exists because the peering authentication mechanism in an affected system is not working properly. An attacker could exploit this vulnerability by sending crafted requests to an affected system. A successful exploit could allow the attacker to log in to an affected Cisco Catalyst SD-WAN Controller as an internal, high-privileged, non-root&nbsp;user account. Using this account, the attacker could access NETCONF, which would then allow the attacker to manipulate network configuration for the SD-WAN fabric.&nbsp;

- [https://github.com/anuththara2007-W/CVE-2026-20127-Exploit-Extension](https://github.com/anuththara2007-W/CVE-2026-20127-Exploit-Extension) :  ![starts](https://img.shields.io/github/stars/anuththara2007-W/CVE-2026-20127-Exploit-Extension.svg) ![forks](https://img.shields.io/github/forks/anuththara2007-W/CVE-2026-20127-Exploit-Extension.svg)


## CVE-2026-4631
 Cockpit's remote login feature passes user-supplied hostnames and usernames from the web interface to the SSH client without validation or sanitization. An attacker with network access to the Cockpit web service can craft a single HTTP request to the login endpoint that injects malicious SSH options or shell commands, achieving code execution on the Cockpit host without valid credentials. The injection occurs during the authentication flow before any credential verification takes place, meaning no login is required to exploit the vulnerability.

- [https://github.com/ExDev994/CVE-2026-4631-cockpit-RCE](https://github.com/ExDev994/CVE-2026-4631-cockpit-RCE) :  ![starts](https://img.shields.io/github/stars/ExDev994/CVE-2026-4631-cockpit-RCE.svg) ![forks](https://img.shields.io/github/forks/ExDev994/CVE-2026-4631-cockpit-RCE.svg)


## CVE-2026-2005
 Heap buffer overflow in PostgreSQL pgcrypto allows a ciphertext provider to execute arbitrary code as the operating system user running the database.  Versions before PostgreSQL 18.2, 17.8, 16.12, 15.16, and 14.21 are affected.

- [https://github.com/M3str3/CVE-2026-2005](https://github.com/M3str3/CVE-2026-2005) :  ![starts](https://img.shields.io/github/stars/M3str3/CVE-2026-2005.svg) ![forks](https://img.shields.io/github/forks/M3str3/CVE-2026-2005.svg)


## CVE-2026-0776
The specific flaw exists within the discord_rpc module. The product loads a file from an unsecured location. An attacker can leverage this vulnerability to escalate privileges and execute arbitrary code in the context of a target user. Was ZDI-CAN-27057.

- [https://github.com/AnhedonicX/CVE-2026-0776](https://github.com/AnhedonicX/CVE-2026-0776) :  ![starts](https://img.shields.io/github/stars/AnhedonicX/CVE-2026-0776.svg) ![forks](https://img.shields.io/github/forks/AnhedonicX/CVE-2026-0776.svg)


## CVE-2025-69212
 OpenSTAManager is an open source management software for technical assistance and invoicing. In 2.9.8 and earlier, a critical OS Command Injection vulnerability exists in the P7M (signed XML) file decoding functionality. An authenticated attacker can upload a ZIP file containing a .p7m file with a malicious filename to execute arbitrary system commands on the server.

- [https://github.com/mmoobbeeiidat-design/Hack-The-Box-Enigma-Findings-Report](https://github.com/mmoobbeeiidat-design/Hack-The-Box-Enigma-Findings-Report) :  ![starts](https://img.shields.io/github/stars/mmoobbeeiidat-design/Hack-The-Box-Enigma-Findings-Report.svg) ![forks](https://img.shields.io/github/forks/mmoobbeeiidat-design/Hack-The-Box-Enigma-Findings-Report.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/yuzuki-ayanami/CVE-2025-24813](https://github.com/yuzuki-ayanami/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/yuzuki-ayanami/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/yuzuki-ayanami/CVE-2025-24813.svg)


## CVE-2025-8110
 Improper Symbolic link handling in the PutContents API in Gogs allows Local Execution of Code.

- [https://github.com/amnsecurity/internal-domain-development-compromise-assessment](https://github.com/amnsecurity/internal-domain-development-compromise-assessment) :  ![starts](https://img.shields.io/github/stars/amnsecurity/internal-domain-development-compromise-assessment.svg) ![forks](https://img.shields.io/github/forks/amnsecurity/internal-domain-development-compromise-assessment.svg)


## CVE-2024-40842
 An issue was addressed with improved validation of environment variables. This issue is fixed in macOS Sequoia 15. An app may be able to access user-sensitive data.

- [https://github.com/dunihiz/Ph-n-t-ch-CVE-2024-40842-XProtectRemediatorDubRobber-Information-Leak-tr-n-macOS](https://github.com/dunihiz/Ph-n-t-ch-CVE-2024-40842-XProtectRemediatorDubRobber-Information-Leak-tr-n-macOS) :  ![starts](https://img.shields.io/github/stars/dunihiz/Ph-n-t-ch-CVE-2024-40842-XProtectRemediatorDubRobber-Information-Leak-tr-n-macOS.svg) ![forks](https://img.shields.io/github/forks/dunihiz/Ph-n-t-ch-CVE-2024-40842-XProtectRemediatorDubRobber-Information-Leak-tr-n-macOS.svg)


## CVE-2023-49002
 An issue in Xenom Technologies (sinous) Phone Dialer-voice Call Dialer v.1.2.5 allows an attacker to bypass intended access restrictions via interaction with com.funprime.calldialer.ui.activities.OutgoingActivity.

- [https://github.com/actuator/com.sinous.voice.dialer](https://github.com/actuator/com.sinous.voice.dialer) :  ![starts](https://img.shields.io/github/stars/actuator/com.sinous.voice.dialer.svg) ![forks](https://img.shields.io/github/forks/actuator/com.sinous.voice.dialer.svg)


## CVE-2023-38146
 Windows Themes Remote Code Execution Vulnerability

- [https://github.com/CH0ico/CVE-2023-38146-Poc](https://github.com/CH0ico/CVE-2023-38146-Poc) :  ![starts](https://img.shields.io/github/stars/CH0ico/CVE-2023-38146-Poc.svg) ![forks](https://img.shields.io/github/forks/CH0ico/CVE-2023-38146-Poc.svg)


## CVE-2023-34468
You are recommended to upgrade to version 1.22.0 or later which fixes this issue.

- [https://github.com/ozcanpng/CVE-2023-34468](https://github.com/ozcanpng/CVE-2023-34468) :  ![starts](https://img.shields.io/github/stars/ozcanpng/CVE-2023-34468.svg) ![forks](https://img.shields.io/github/forks/ozcanpng/CVE-2023-34468.svg)


## CVE-2023-29017
 vm2 is a sandbox that can run untrusted code with whitelisted Node's built-in modules. Prior to version 3.9.15, vm2 was not properly handling host objects passed to `Error.prepareStackTrace` in case of unhandled async errors. A threat actor could bypass the sandbox protections to gain remote code execution rights on the host running the sandbox. This vulnerability was patched in the release of version 3.9.15 of vm2. There are no known workarounds.

- [https://github.com/gunwoo105/Node_CVE-2023-29017](https://github.com/gunwoo105/Node_CVE-2023-29017) :  ![starts](https://img.shields.io/github/stars/gunwoo105/Node_CVE-2023-29017.svg) ![forks](https://img.shields.io/github/forks/gunwoo105/Node_CVE-2023-29017.svg)


## CVE-2023-4911
 A buffer overflow was discovered in the GNU C Library's dynamic loader ld.so while processing the GLIBC_TUNABLES environment variable. This issue could allow a local attacker to use maliciously crafted GLIBC_TUNABLES environment variables when launching binaries with SUID permission to execute code with elevated privileges.

- [https://github.com/baeseungwon1010/CVE-2023-4911](https://github.com/baeseungwon1010/CVE-2023-4911) :  ![starts](https://img.shields.io/github/stars/baeseungwon1010/CVE-2023-4911.svg) ![forks](https://img.shields.io/github/forks/baeseungwon1010/CVE-2023-4911.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/ninthsgrsj-source/vulhub-apache](https://github.com/ninthsgrsj-source/vulhub-apache) :  ![starts](https://img.shields.io/github/stars/ninthsgrsj-source/vulhub-apache.svg) ![forks](https://img.shields.io/github/forks/ninthsgrsj-source/vulhub-apache.svg)


## CVE-2020-14343
 A vulnerability was discovered in the PyYAML library in versions before 5.4, where it is susceptible to arbitrary code execution when it processes untrusted YAML files through the full_load method or with the FullLoader loader. Applications that use the library to process untrusted input may be vulnerable to this flaw. This flaw allows an attacker to execute arbitrary code on the system by abusing the python/object/new constructor. This flaw is due to an incomplete fix for CVE-2020-1747.

- [https://github.com/seal-sec-demo-2/Python-Example](https://github.com/seal-sec-demo-2/Python-Example) :  ![starts](https://img.shields.io/github/stars/seal-sec-demo-2/Python-Example.svg) ![forks](https://img.shields.io/github/forks/seal-sec-demo-2/Python-Example.svg)


## CVE-2019-0232
 When running on Windows with enableCmdLineArguments enabled, the CGI Servlet in Apache Tomcat 9.0.0.M1 to 9.0.17, 8.5.0 to 8.5.39 and 7.0.0 to 7.0.93 is vulnerable to Remote Code Execution due to a bug in the way the JRE passes command line arguments to Windows. The CGI Servlet is disabled by default. The CGI option enableCmdLineArguments is disable by default in Tomcat 9.0.x (and will be disabled by default in all versions in response to this vulnerability). For a detailed explanation of the JRE behaviour, see Markus Wulftange's blog (https://codewhitesec.blogspot.com/2016/02/java-and-command-line-injections-in-windows.html) and this archived MSDN blog (https://web.archive.org/web/20161228144344/https://blogs.msdn.microsoft.com/twistylittlepassagesallalike/2011/04/23/everyone-quotes-command-line-arguments-the-wrong-way/).

- [https://github.com/yuzuki-ayanami/CVE-2019-0232](https://github.com/yuzuki-ayanami/CVE-2019-0232) :  ![starts](https://img.shields.io/github/stars/yuzuki-ayanami/CVE-2019-0232.svg) ![forks](https://img.shields.io/github/forks/yuzuki-ayanami/CVE-2019-0232.svg)


## CVE-2018-16385
 ThinkPHP before 5.1.23 allows SQL Injection via the public/index/index/test/index query string.

- [https://github.com/buzhimingdeaikun/SQL-ThinkPHP-5.0.24-RCE-](https://github.com/buzhimingdeaikun/SQL-ThinkPHP-5.0.24-RCE-) :  ![starts](https://img.shields.io/github/stars/buzhimingdeaikun/SQL-ThinkPHP-5.0.24-RCE-.svg) ![forks](https://img.shields.io/github/forks/buzhimingdeaikun/SQL-ThinkPHP-5.0.24-RCE-.svg)


## CVE-2017-2370
 An issue was discovered in certain Apple products. iOS before 10.2.1 is affected. macOS before 10.12.3 is affected. tvOS before 10.1.1 is affected. watchOS before 3.1.3 is affected. The issue involves the "Kernel" component. It allows attackers to execute arbitrary code in a privileged context or cause a denial of service (buffer overflow) via a crafted app.

- [https://github.com/ldebug/extra_recipe](https://github.com/ldebug/extra_recipe) :  ![starts](https://img.shields.io/github/stars/ldebug/extra_recipe.svg) ![forks](https://img.shields.io/github/forks/ldebug/extra_recipe.svg)

