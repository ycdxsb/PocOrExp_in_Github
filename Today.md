# Update 2023-03-02
## CVE-2022-46166
 Spring boot admins is an open source administrative user interface for management of spring boot applications. All users who run Spring Boot Admin Server, having enabled Notifiers (e.g. Teams-Notifier) and write access to environment variables via UI are affected. Users are advised to upgrade to the most recent releases of Spring Boot Admin 2.6.10 and 2.7.8 to resolve this issue. Users unable to upgrade may disable any notifier or disable write access (POST request) on `/env` actuator endpoint.

- [https://github.com/DickDock/CVE-2022-46166](https://github.com/DickDock/CVE-2022-46166) :  ![starts](https://img.shields.io/github/stars/DickDock/CVE-2022-46166.svg) ![forks](https://img.shields.io/github/forks/DickDock/CVE-2022-46166.svg)


## CVE-2022-24112
 An attacker can abuse the batch-requests plugin to send requests to bypass the IP restriction of Admin API. A default configuration of Apache APISIX (with default API key) is vulnerable to remote code execution. When the admin key was changed or the port of Admin API was changed to a port different from the data panel, the impact is lower. But there is still a risk to bypass the IP restriction of Apache APISIX's data panel. There is a check in the batch-requests plugin which overrides the client IP with its real remote IP. But due to a bug in the code, this check can be bypassed.

- [https://github.com/Acczdy/CVE-2022-24112_POC](https://github.com/Acczdy/CVE-2022-24112_POC) :  ![starts](https://img.shields.io/github/stars/Acczdy/CVE-2022-24112_POC.svg) ![forks](https://img.shields.io/github/forks/Acczdy/CVE-2022-24112_POC.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/pwnwriter/CVE-2022-22965](https://github.com/pwnwriter/CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/pwnwriter/CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/pwnwriter/CVE-2022-22965.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/McSl0vv/CVE-2021-41773](https://github.com/McSl0vv/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/McSl0vv/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/McSl0vv/CVE-2021-41773.svg)
- [https://github.com/12345qwert123456/CVE-2021-41773](https://github.com/12345qwert123456/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/12345qwert123456/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/12345qwert123456/CVE-2021-41773.svg)
- [https://github.com/sixpacksecurity/CVE-2021-41773](https://github.com/sixpacksecurity/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sixpacksecurity/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sixpacksecurity/CVE-2021-41773.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/nel0x/pwnkit-vulnerability](https://github.com/nel0x/pwnkit-vulnerability) :  ![starts](https://img.shields.io/github/stars/nel0x/pwnkit-vulnerability.svg) ![forks](https://img.shields.io/github/forks/nel0x/pwnkit-vulnerability.svg)


## CVE-2021-2047
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core Components). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, and 12.2.1.3.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/somatrasss/weblogic2021](https://github.com/somatrasss/weblogic2021) :  ![starts](https://img.shields.io/github/stars/somatrasss/weblogic2021.svg) ![forks](https://img.shields.io/github/forks/somatrasss/weblogic2021.svg)

