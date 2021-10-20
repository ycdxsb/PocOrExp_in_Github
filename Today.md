# Update 2021-10-20
## CVE-2021-42342
 An issue was discovered in GoAhead 4.x and 5.x before 5.1.5. In the file upload filter, user form variables can be passed to CGI scripts without being prefixed with the CGI prefix. This permits tunneling untrusted environment variables into vulnerable CGI scripts.

- [https://github.com/kimusan/goahead-webserver-pre-5.1.5-RCE-PoC-CVE-2021-42342-](https://github.com/kimusan/goahead-webserver-pre-5.1.5-RCE-PoC-CVE-2021-42342-) :  ![starts](https://img.shields.io/github/stars/kimusan/goahead-webserver-pre-5.1.5-RCE-PoC-CVE-2021-42342-.svg) ![forks](https://img.shields.io/github/forks/kimusan/goahead-webserver-pre-5.1.5-RCE-PoC-CVE-2021-42342-.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/vulf/CVE-2021-41773_42013](https://github.com/vulf/CVE-2021-41773_42013) :  ![starts](https://img.shields.io/github/stars/vulf/CVE-2021-41773_42013.svg) ![forks](https://img.shields.io/github/forks/vulf/CVE-2021-41773_42013.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/vulf/CVE-2021-41773_42013](https://github.com/vulf/CVE-2021-41773_42013) :  ![starts](https://img.shields.io/github/stars/vulf/CVE-2021-41773_42013.svg) ![forks](https://img.shields.io/github/forks/vulf/CVE-2021-41773_42013.svg)


## CVE-2021-36260
 A command injection vulnerability in the web server of some Hikvision product. Due to the insufficient input validation, attacker can exploit the vulnerability to launch a command injection attack by sending some messages with malicious commands.

- [https://github.com/rabbitsafe/CVE-2021-36260](https://github.com/rabbitsafe/CVE-2021-36260) :  ![starts](https://img.shields.io/github/stars/rabbitsafe/CVE-2021-36260.svg) ![forks](https://img.shields.io/github/forks/rabbitsafe/CVE-2021-36260.svg)


## CVE-2021-33044
 The identity authentication bypass vulnerability found in some Dahua products during the login process. Attackers can bypass device identity authentication by constructing malicious data packets.

- [https://github.com/dorkerdevil/CVE-2021-33044](https://github.com/dorkerdevil/CVE-2021-33044) :  ![starts](https://img.shields.io/github/stars/dorkerdevil/CVE-2021-33044.svg) ![forks](https://img.shields.io/github/forks/dorkerdevil/CVE-2021-33044.svg)


## CVE-2021-21234
 spring-boot-actuator-logview in a library that adds a simple logfile viewer as spring boot actuator endpoint. It is maven package &quot;eu.hinsch:spring-boot-actuator-logview&quot;. In spring-boot-actuator-logview before version 0.2.13 there is a directory traversal vulnerability. The nature of this library is to expose a log file directory via admin (spring boot actuator) HTTP endpoints. Both the filename to view and a base folder (relative to the logging folder root) can be specified via request parameters. While the filename parameter was checked to prevent directory traversal exploits (so that `filename=../somefile` would not work), the base folder parameter was not sufficiently checked, so that `filename=somefile&amp;base=../` could access a file outside the logging base directory). The vulnerability has been patched in release 0.2.13. Any users of 0.2.12 should be able to update without any issues as there are no other changes in that release. There is no workaround to fix the vulnerability other than updating or removing the dependency. However, removing read access of the user the application is run with to any directory not required for running the application can limit the impact. Additionally, access to the logview endpoint can be limited by deploying the application behind a reverse proxy.

- [https://github.com/xiaojiangxl/CVE-2021-21234](https://github.com/xiaojiangxl/CVE-2021-21234) :  ![starts](https://img.shields.io/github/stars/xiaojiangxl/CVE-2021-21234.svg) ![forks](https://img.shields.io/github/forks/xiaojiangxl/CVE-2021-21234.svg)


## CVE-2019-6339
 In Drupal Core versions 7.x prior to 7.62, 8.6.x prior to 8.6.6 and 8.5.x prior to 8.5.9; A remote code execution vulnerability exists in PHP's built-in phar stream wrapper when performing file operations on an untrusted phar:// URI. Some Drupal code (core, contrib, and custom) may be performing file operations on insufficiently validated user input, thereby being exposed to this vulnerability. This vulnerability is mitigated by the fact that such code paths typically require access to an administrative permission or an atypical configuration.

- [https://github.com/Vulnmachines/drupal-cve-2019-6339](https://github.com/Vulnmachines/drupal-cve-2019-6339) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/drupal-cve-2019-6339.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/drupal-cve-2019-6339.svg)

