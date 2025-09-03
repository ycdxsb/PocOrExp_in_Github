# Update 2025-09-03
## CVE-2025-57819
 FreePBX is an open-source web-based graphical user interface. FreePBX 15, 16, and 17 endpoints are vulnerable due to insufficiently sanitized user-supplied data allowing unauthenticated access to FreePBX Administrator leading to arbitrary database manipulation and remote code execution. This issue has been patched in endpoint versions 15.0.66, 16.0.89, and 17.0.3.

- [https://github.com/blueisbeautiful/CVE-2025-57819](https://github.com/blueisbeautiful/CVE-2025-57819) :  ![starts](https://img.shields.io/github/stars/blueisbeautiful/CVE-2025-57819.svg) ![forks](https://img.shields.io/github/forks/blueisbeautiful/CVE-2025-57819.svg)


## CVE-2025-34300
 A template injection vulnerability exists in Sawtooth Software’s Lighthouse Studio versions prior to 9.16.14 via the  ciwweb.pl http://ciwweb.pl/  Perl web application. Exploitation allows an unauthenticated attacker can execute arbitrary commands.

- [https://github.com/jisi-001/CVE-2025-34300POC](https://github.com/jisi-001/CVE-2025-34300POC) :  ![starts](https://img.shields.io/github/stars/jisi-001/CVE-2025-34300POC.svg) ![forks](https://img.shields.io/github/forks/jisi-001/CVE-2025-34300POC.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/RUB-NDS/SSH-Strict-Kex-Violations-State-Learning-Artifacts](https://github.com/RUB-NDS/SSH-Strict-Kex-Violations-State-Learning-Artifacts) :  ![starts](https://img.shields.io/github/stars/RUB-NDS/SSH-Strict-Kex-Violations-State-Learning-Artifacts.svg) ![forks](https://img.shields.io/github/forks/RUB-NDS/SSH-Strict-Kex-Violations-State-Learning-Artifacts.svg)


## CVE-2025-27591
 A privilege escalation vulnerability existed in the Below service prior to v0.9.0 due to the creation of a world-writable directory at /var/log/below. This could have allowed local unprivileged users to escalate to root privileges through symlink attacks that manipulate files such as /etc/shadow.

- [https://github.com/danil-koltsov/below-log-race-poc](https://github.com/danil-koltsov/below-log-race-poc) :  ![starts](https://img.shields.io/github/stars/danil-koltsov/below-log-race-poc.svg) ![forks](https://img.shields.io/github/forks/danil-koltsov/below-log-race-poc.svg)


## CVE-2025-27480
 Use after free in Remote Desktop Gateway Service allows an unauthorized attacker to execute code over a network.

- [https://github.com/mrk336/CVE-2025-27480-The-Silent-Gateway-Risk](https://github.com/mrk336/CVE-2025-27480-The-Silent-Gateway-Risk) :  ![starts](https://img.shields.io/github/stars/mrk336/CVE-2025-27480-The-Silent-Gateway-Risk.svg) ![forks](https://img.shields.io/github/forks/mrk336/CVE-2025-27480-The-Silent-Gateway-Risk.svg)


## CVE-2025-5369
 A vulnerability classified as critical has been found in SourceCodester PHP Display Username After Login 1.0. Affected is an unknown function of the file /login.php. The manipulation of the argument Username leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/blueisbeautiful/CVE-2025-53694-to-CVE-2025-53691](https://github.com/blueisbeautiful/CVE-2025-53694-to-CVE-2025-53691) :  ![starts](https://img.shields.io/github/stars/blueisbeautiful/CVE-2025-53694-to-CVE-2025-53691.svg) ![forks](https://img.shields.io/github/forks/blueisbeautiful/CVE-2025-53694-to-CVE-2025-53691.svg)
- [https://github.com/blueisbeautiful/CVE-2025-53694](https://github.com/blueisbeautiful/CVE-2025-53694) :  ![starts](https://img.shields.io/github/stars/blueisbeautiful/CVE-2025-53694.svg) ![forks](https://img.shields.io/github/forks/blueisbeautiful/CVE-2025-53694.svg)
- [https://github.com/blueisbeautiful/CVE-2025-53693](https://github.com/blueisbeautiful/CVE-2025-53693) :  ![starts](https://img.shields.io/github/stars/blueisbeautiful/CVE-2025-53693.svg) ![forks](https://img.shields.io/github/forks/blueisbeautiful/CVE-2025-53693.svg)
- [https://github.com/blueisbeautiful/CVE-2025-53691](https://github.com/blueisbeautiful/CVE-2025-53691) :  ![starts](https://img.shields.io/github/stars/blueisbeautiful/CVE-2025-53691.svg) ![forks](https://img.shields.io/github/forks/blueisbeautiful/CVE-2025-53691.svg)


## CVE-2025-3515
 The Drag and Drop Multiple File Upload for Contact Form 7 plugin for WordPress is vulnerable to arbitrary file uploads due to insufficient file type validation in all versions up to, and including, 1.3.8.9. This makes it possible for unauthenticated attackers to bypass the plugin's blacklist and upload .phar or other dangerous file types on the affected site's server, which may make remote code execution possible on the servers that are configured to handle .phar files as executable PHP scripts, particularly in default Apache+mod_php configurations where the file extension is not strictly validated before being passed to the PHP interpreter.

- [https://github.com/blueisbeautiful/CVE-2025-3515](https://github.com/blueisbeautiful/CVE-2025-3515) :  ![starts](https://img.shields.io/github/stars/blueisbeautiful/CVE-2025-3515.svg) ![forks](https://img.shields.io/github/forks/blueisbeautiful/CVE-2025-3515.svg)


## CVE-2024-36886
---truncated---

- [https://github.com/abubakar-shahid/CVE-2024-36886](https://github.com/abubakar-shahid/CVE-2024-36886) :  ![starts](https://img.shields.io/github/stars/abubakar-shahid/CVE-2024-36886.svg) ![forks](https://img.shields.io/github/forks/abubakar-shahid/CVE-2024-36886.svg)


## CVE-2022-38694
 In BootRom, there is a possible unchecked write address. This could lead to local escalation of privilege with no additional execution privileges needed.

- [https://github.com/Seriousattempts/Bootloader_Unlock_Retroid_Pocket_3Plus](https://github.com/Seriousattempts/Bootloader_Unlock_Retroid_Pocket_3Plus) :  ![starts](https://img.shields.io/github/stars/Seriousattempts/Bootloader_Unlock_Retroid_Pocket_3Plus.svg) ![forks](https://img.shields.io/github/forks/Seriousattempts/Bootloader_Unlock_Retroid_Pocket_3Plus.svg)


## CVE-2022-1592
 Server-Side Request Forgery in scout in GitHub repository clinical-genomics/scout prior to v4.42. An attacker could make the application perform arbitrary requests to fishing steal cookie, request to private area, or lead to xss...

- [https://github.com/AdnanApriliyansyahh/CVE-2022-1592](https://github.com/AdnanApriliyansyahh/CVE-2022-1592) :  ![starts](https://img.shields.io/github/stars/AdnanApriliyansyahh/CVE-2022-1592.svg) ![forks](https://img.shields.io/github/forks/AdnanApriliyansyahh/CVE-2022-1592.svg)


## CVE-2022-1524
 LRM version 2.4 and lower does not implement TLS encryption. A malicious actor can MITM attack sensitive data in-transit, including credentials.

- [https://github.com/mrk336/Hardening-Amazon-IAM-for-Cloud-Engineers](https://github.com/mrk336/Hardening-Amazon-IAM-for-Cloud-Engineers) :  ![starts](https://img.shields.io/github/stars/mrk336/Hardening-Amazon-IAM-for-Cloud-Engineers.svg) ![forks](https://img.shields.io/github/forks/mrk336/Hardening-Amazon-IAM-for-Cloud-Engineers.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/jxpsx/CVE-2022-0847-DirtyPipe-Exploits](https://github.com/jxpsx/CVE-2022-0847-DirtyPipe-Exploits) :  ![starts](https://img.shields.io/github/stars/jxpsx/CVE-2022-0847-DirtyPipe-Exploits.svg) ![forks](https://img.shields.io/github/forks/jxpsx/CVE-2022-0847-DirtyPipe-Exploits.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Fa1c0n35/CVE-2021-41773](https://github.com/Fa1c0n35/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Fa1c0n35/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Fa1c0n35/CVE-2021-41773.svg)
- [https://github.com/skentagon/CVE-2021-41773](https://github.com/skentagon/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/skentagon/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/skentagon/CVE-2021-41773.svg)


## CVE-2021-41617
 sshd in OpenSSH 6.2 through 8.x before 8.8, when certain non-default configurations are used, allows privilege escalation because supplemental groups are not initialized as expected. Helper programs for AuthorizedKeysCommand and AuthorizedPrincipalsCommand may run with privileges associated with group memberships of the sshd process, if the configuration specifies running the command as a different user.

- [https://github.com/AdnanApriliyansyahh/CVE-2021-41617](https://github.com/AdnanApriliyansyahh/CVE-2021-41617) :  ![starts](https://img.shields.io/github/stars/AdnanApriliyansyahh/CVE-2021-41617.svg) ![forks](https://img.shields.io/github/forks/AdnanApriliyansyahh/CVE-2021-41617.svg)


## CVE-2019-10945
 An issue was discovered in Joomla! before 3.9.5. The Media Manager component does not properly sanitize the folder parameter, allowing attackers to act outside the media manager root directory.

- [https://github.com/Snizi/CVE-2019-10945](https://github.com/Snizi/CVE-2019-10945) :  ![starts](https://img.shields.io/github/stars/Snizi/CVE-2019-10945.svg) ![forks](https://img.shields.io/github/forks/Snizi/CVE-2019-10945.svg)


## CVE-2017-9841
 Util/PHP/eval-stdin.php in PHPUnit before 4.8.28 and 5.x before 5.6.3 allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a "?php " substring, as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.

- [https://github.com/Habibullah1101/PHPUnit-GoScan](https://github.com/Habibullah1101/PHPUnit-GoScan) :  ![starts](https://img.shields.io/github/stars/Habibullah1101/PHPUnit-GoScan.svg) ![forks](https://img.shields.io/github/forks/Habibullah1101/PHPUnit-GoScan.svg)

