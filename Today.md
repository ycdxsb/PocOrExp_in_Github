# Update 2022-02-24
## CVE-2022-24112
 An attacker can abuse the batch-requests plugin to send requests to bypass the IP restriction of Admin API. A default configuration of Apache APISIX (with default API key) is vulnerable to remote code execution. When the admin key was changed or the port of Admin API was changed to a port different from the data panel, the impact is lower. But there is still a risk to bypass the IP restriction of Apache APISIX's data panel. There is a check in the batch-requests plugin which overrides the client IP with its real remote IP. But due to a bug in the code, this check can be bypassed.

- [https://github.com/Mr-xn/CVE-2022-24112](https://github.com/Mr-xn/CVE-2022-24112) :  ![starts](https://img.shields.io/github/stars/Mr-xn/CVE-2022-24112.svg) ![forks](https://img.shields.io/github/forks/Mr-xn/CVE-2022-24112.svg)
- [https://github.com/Udyz/CVE-2022-24112](https://github.com/Udyz/CVE-2022-24112) :  ![starts](https://img.shields.io/github/stars/Udyz/CVE-2022-24112.svg) ![forks](https://img.shields.io/github/forks/Udyz/CVE-2022-24112.svg)


## CVE-2022-21660
 Gin-vue-admin is a backstage management system based on vue and gin. In versions prior to 2.4.7 low privilege users are able to modify higher privilege users. Authentication is missing on the `setUserInfo` function. Users are advised to update as soon as possible. There are no known workarounds.

- [https://github.com/UzJu/CVE-2022-21660](https://github.com/UzJu/CVE-2022-21660) :  ![starts](https://img.shields.io/github/stars/UzJu/CVE-2022-21660.svg) ![forks](https://img.shields.io/github/forks/UzJu/CVE-2022-21660.svg)


## CVE-2021-45003
 Laundry Booking Management System 1.0 (Latest) and previous versions are affected by a remote code execution (RCE) vulnerability in profile.php through the &quot;image&quot; parameter that can execute a webshell payload.

- [https://github.com/qerogram/BUG_WEB](https://github.com/qerogram/BUG_WEB) :  ![starts](https://img.shields.io/github/stars/qerogram/BUG_WEB.svg) ![forks](https://img.shields.io/github/forks/qerogram/BUG_WEB.svg)


## CVE-2021-36808
 A local attacker could bypass the app password using a race condition in Sophos Secure Workspace for Android before version 9.7.3115.

- [https://github.com/ctuIhu/CVE-2021-36808](https://github.com/ctuIhu/CVE-2021-36808) :  ![starts](https://img.shields.io/github/stars/ctuIhu/CVE-2021-36808.svg) ![forks](https://img.shields.io/github/forks/ctuIhu/CVE-2021-36808.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/Ph4nt0mh4x0r/auto-CVE-2021-4034](https://github.com/Ph4nt0mh4x0r/auto-CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Ph4nt0mh4x0r/auto-CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Ph4nt0mh4x0r/auto-CVE-2021-4034.svg)
- [https://github.com/fireclasher/pwnkit-CVE-2021-4034-](https://github.com/fireclasher/pwnkit-CVE-2021-4034-) :  ![starts](https://img.shields.io/github/stars/fireclasher/pwnkit-CVE-2021-4034-.svg) ![forks](https://img.shields.io/github/forks/fireclasher/pwnkit-CVE-2021-4034-.svg)


## CVE-2021-3310
 Western Digital My Cloud OS 5 devices before 5.10.122 mishandle Symbolic Link Following on SMB and AFP shares. This can lead to code execution and information disclosure (by reading local files).

- [https://github.com/piffd0s/CVE-2021-3310](https://github.com/piffd0s/CVE-2021-3310) :  ![starts](https://img.shields.io/github/stars/piffd0s/CVE-2021-3310.svg) ![forks](https://img.shields.io/github/forks/piffd0s/CVE-2021-3310.svg)


## CVE-2021-3229
 Denial of service in ASUSWRT ASUS RT-AX3000 firmware versions 3.0.0.4.384_10177 and earlier versions allows an attacker to disrupt the use of device setup services via continuous login error.

- [https://github.com/fullbbadda1208/CVE-2021-3229](https://github.com/fullbbadda1208/CVE-2021-3229) :  ![starts](https://img.shields.io/github/stars/fullbbadda1208/CVE-2021-3229.svg) ![forks](https://img.shields.io/github/forks/fullbbadda1208/CVE-2021-3229.svg)


## CVE-2020-6418
 Type confusion in V8 in Google Chrome prior to 80.0.3987.122 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/ulexec/ChromeSHELFLoader](https://github.com/ulexec/ChromeSHELFLoader) :  ![starts](https://img.shields.io/github/stars/ulexec/ChromeSHELFLoader.svg) ![forks](https://img.shields.io/github/forks/ulexec/ChromeSHELFLoader.svg)


## CVE-2020-3452
 A vulnerability in the web services interface of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to conduct directory traversal attacks and read sensitive files on a targeted system. The vulnerability is due to a lack of proper input validation of URLs in HTTP requests processed by an affected device. An attacker could exploit this vulnerability by sending a crafted HTTP request containing directory traversal character sequences to an affected device. A successful exploit could allow the attacker to view arbitrary files within the web services file system on the targeted device. The web services file system is enabled when the affected device is configured with either WebVPN or AnyConnect features. This vulnerability cannot be used to obtain access to ASA or FTD system files or underlying operating system (OS) files.

- [https://github.com/Loneyers/cve-2020-3452](https://github.com/Loneyers/cve-2020-3452) :  ![starts](https://img.shields.io/github/stars/Loneyers/cve-2020-3452.svg) ![forks](https://img.shields.io/github/forks/Loneyers/cve-2020-3452.svg)


## CVE-2016-10956
 The mail-masta plugin 1.0 for WordPress has local file inclusion in count_of_send.php and csvexport.php.

- [https://github.com/p0dalirius/CVE-2016-10956-mail-masta](https://github.com/p0dalirius/CVE-2016-10956-mail-masta) :  ![starts](https://img.shields.io/github/stars/p0dalirius/CVE-2016-10956-mail-masta.svg) ![forks](https://img.shields.io/github/forks/p0dalirius/CVE-2016-10956-mail-masta.svg)


## CVE-2012-2661
 The Active Record component in Ruby on Rails 3.0.x before 3.0.13, 3.1.x before 3.1.5, and 3.2.x before 3.2.4 does not properly implement the passing of request data to a where method in an ActiveRecord class, which allows remote attackers to conduct certain SQL injection attacks via nested query parameters that leverage unintended recursion, a related issue to CVE-2012-2695.

- [https://github.com/Blackyguy/-CVE-2012-2661-ActiveRecord-SQL-injection-](https://github.com/Blackyguy/-CVE-2012-2661-ActiveRecord-SQL-injection-) :  ![starts](https://img.shields.io/github/stars/Blackyguy/-CVE-2012-2661-ActiveRecord-SQL-injection-.svg) ![forks](https://img.shields.io/github/forks/Blackyguy/-CVE-2012-2661-ActiveRecord-SQL-injection-.svg)

