# Update 2022-02-07
## CVE-2021-45232
 In Apache APISIX Dashboard before 2.10.1, the Manager API uses two frameworks and introduces framework `droplet` on the basis of framework `gin`, all APIs and authentication middleware are developed based on framework `droplet`, but some API directly use the interface of framework `gin` thus bypassing the authentication.

- [https://github.com/Anonymous-ghost/AttackWebFrameworkTools-5.0](https://github.com/Anonymous-ghost/AttackWebFrameworkTools-5.0) :  ![starts](https://img.shields.io/github/stars/Anonymous-ghost/AttackWebFrameworkTools-5.0.svg) ![forks](https://img.shields.io/github/forks/Anonymous-ghost/AttackWebFrameworkTools-5.0.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/Anonymous-ghost/AttackWebFrameworkTools-5.0](https://github.com/Anonymous-ghost/AttackWebFrameworkTools-5.0) :  ![starts](https://img.shields.io/github/stars/Anonymous-ghost/AttackWebFrameworkTools-5.0.svg) ![forks](https://img.shields.io/github/forks/Anonymous-ghost/AttackWebFrameworkTools-5.0.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `&lt;grafana_host_url&gt;/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/Anonymous-ghost/AttackWebFrameworkTools-5.0](https://github.com/Anonymous-ghost/AttackWebFrameworkTools-5.0) :  ![starts](https://img.shields.io/github/stars/Anonymous-ghost/AttackWebFrameworkTools-5.0.svg) ![forks](https://img.shields.io/github/forks/Anonymous-ghost/AttackWebFrameworkTools-5.0.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Anonymous-ghost/AttackWebFrameworkTools-5.0](https://github.com/Anonymous-ghost/AttackWebFrameworkTools-5.0) :  ![starts](https://img.shields.io/github/stars/Anonymous-ghost/AttackWebFrameworkTools-5.0.svg) ![forks](https://img.shields.io/github/forks/Anonymous-ghost/AttackWebFrameworkTools-5.0.svg)


## CVE-2021-37580
 A flaw was found in Apache ShenYu Admin. The incorrect use of JWT in ShenyuAdminBootstrap allows an attacker to bypass authentication. This issue affected Apache ShenYu 2.3.0 and 2.4.0

- [https://github.com/Anonymous-ghost/AttackWebFrameworkTools-5.0](https://github.com/Anonymous-ghost/AttackWebFrameworkTools-5.0) :  ![starts](https://img.shields.io/github/stars/Anonymous-ghost/AttackWebFrameworkTools-5.0.svg) ![forks](https://img.shields.io/github/forks/Anonymous-ghost/AttackWebFrameworkTools-5.0.svg)


## CVE-2021-30461
 A remote code execution issue was discovered in the web UI of VoIPmonitor before 24.61. When the recheck option is used, the user-supplied SPOOLDIR value (which might contain PHP code) is injected into config/configuration.php.

- [https://github.com/Anonymous-ghost/AttackWebFrameworkTools-5.0](https://github.com/Anonymous-ghost/AttackWebFrameworkTools-5.0) :  ![starts](https://img.shields.io/github/stars/Anonymous-ghost/AttackWebFrameworkTools-5.0.svg) ![forks](https://img.shields.io/github/forks/Anonymous-ghost/AttackWebFrameworkTools-5.0.svg)


## CVE-2021-26295
 Apache OFBiz has unsafe deserialization prior to 17.12.06. An unauthenticated attacker can use this vulnerability to successfully take over Apache OFBiz.

- [https://github.com/Anonymous-ghost/AttackWebFrameworkTools-5.0](https://github.com/Anonymous-ghost/AttackWebFrameworkTools-5.0) :  ![starts](https://img.shields.io/github/stars/Anonymous-ghost/AttackWebFrameworkTools-5.0.svg) ![forks](https://img.shields.io/github/forks/Anonymous-ghost/AttackWebFrameworkTools-5.0.svg)


## CVE-2021-26084
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0 before 7.12.5.

- [https://github.com/Anonymous-ghost/AttackWebFrameworkTools-5.0](https://github.com/Anonymous-ghost/AttackWebFrameworkTools-5.0) :  ![starts](https://img.shields.io/github/stars/Anonymous-ghost/AttackWebFrameworkTools-5.0.svg) ![forks](https://img.shields.io/github/forks/Anonymous-ghost/AttackWebFrameworkTools-5.0.svg)


## CVE-2021-22205
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 11.9. GitLab was not properly validating image files that were passed to a file parser which resulted in a remote command execution.

- [https://github.com/Anonymous-ghost/AttackWebFrameworkTools-5.0](https://github.com/Anonymous-ghost/AttackWebFrameworkTools-5.0) :  ![starts](https://img.shields.io/github/stars/Anonymous-ghost/AttackWebFrameworkTools-5.0.svg) ![forks](https://img.shields.io/github/forks/Anonymous-ghost/AttackWebFrameworkTools-5.0.svg)


## CVE-2021-22005
 The vCenter Server contains an arbitrary file upload vulnerability in the Analytics service. A malicious actor with network access to port 443 on vCenter Server may exploit this issue to execute code on vCenter Server by uploading a specially crafted file.

- [https://github.com/Anonymous-ghost/AttackWebFrameworkTools-5.0](https://github.com/Anonymous-ghost/AttackWebFrameworkTools-5.0) :  ![starts](https://img.shields.io/github/stars/Anonymous-ghost/AttackWebFrameworkTools-5.0.svg) ![forks](https://img.shields.io/github/forks/Anonymous-ghost/AttackWebFrameworkTools-5.0.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/Almorabea/pkexec-exploit](https://github.com/Almorabea/pkexec-exploit) :  ![starts](https://img.shields.io/github/stars/Almorabea/pkexec-exploit.svg) ![forks](https://img.shields.io/github/forks/Almorabea/pkexec-exploit.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via &quot;sudoedit -s&quot; and a command-line argument that ends with a single backslash character.

- [https://github.com/unauth401/CVE-2021-3156](https://github.com/unauth401/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/unauth401/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/unauth401/CVE-2021-3156.svg)


## CVE-2020-25078
 An issue was discovered on D-Link DCS-2530L before 1.06.01 Hotfix and DCS-2670L through 2.02 devices. The unauthenticated /config/getuser endpoint allows for remote administrator password disclosure.

- [https://github.com/Anonymous-ghost/AttackWebFrameworkTools-5.0](https://github.com/Anonymous-ghost/AttackWebFrameworkTools-5.0) :  ![starts](https://img.shields.io/github/stars/Anonymous-ghost/AttackWebFrameworkTools-5.0.svg) ![forks](https://img.shields.io/github/forks/Anonymous-ghost/AttackWebFrameworkTools-5.0.svg)

