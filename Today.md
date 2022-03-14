# Update 2022-03-14
## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits](https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits) :  ![starts](https://img.shields.io/github/stars/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.svg) ![forks](https://img.shields.io/github/forks/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.svg)
- [https://github.com/arttnba3/CVE-2022-0847](https://github.com/arttnba3/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/arttnba3/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/arttnba3/CVE-2022-0847.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/thehackersbrain/CVE-2021-41773](https://github.com/thehackersbrain/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/thehackersbrain/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/thehackersbrain/CVE-2021-41773.svg)


## CVE-2021-40449
 Win32k Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-40450, CVE-2021-41357.

- [https://github.com/SamuelTulach/voidmap](https://github.com/SamuelTulach/voidmap) :  ![starts](https://img.shields.io/github/stars/SamuelTulach/voidmap.svg) ![forks](https://img.shields.io/github/forks/SamuelTulach/voidmap.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/hackingyseguridad/CVE-2021-4034](https://github.com/hackingyseguridad/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/hackingyseguridad/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/hackingyseguridad/CVE-2021-4034.svg)
- [https://github.com/J0hnbX/CVE-2021-4034-new](https://github.com/J0hnbX/CVE-2021-4034-new) :  ![starts](https://img.shields.io/github/stars/J0hnbX/CVE-2021-4034-new.svg) ![forks](https://img.shields.io/github/forks/J0hnbX/CVE-2021-4034-new.svg)


## CVE-2018-18925
 Gogs 0.11.66 allows remote code execution because it does not properly validate session IDs, as demonstrated by a &quot;..&quot; session-file forgery in the file session provider in file.go. This is related to session ID handling in the go-macaron/session code for Macaron.

- [https://github.com/j4k0m/CVE-2018-18925](https://github.com/j4k0m/CVE-2018-18925) :  ![starts](https://img.shields.io/github/stars/j4k0m/CVE-2018-18925.svg) ![forks](https://img.shields.io/github/forks/j4k0m/CVE-2018-18925.svg)


## CVE-2018-11235
 In Git before 2.13.7, 2.14.x before 2.14.4, 2.15.x before 2.15.2, 2.16.x before 2.16.4, and 2.17.x before 2.17.1, remote code execution can occur. With a crafted .gitmodules file, a malicious project can execute an arbitrary script on a machine that runs &quot;git clone --recurse-submodules&quot; because submodule &quot;names&quot; are obtained from this file, and then appended to $GIT_DIR/modules, leading to directory traversal with &quot;../&quot; in a name. Finally, post-checkout hooks from a submodule are executed, bypassing the intended design in which hooks are not obtained from a remote server.

- [https://github.com/j4k0m/CVE-2018-11235](https://github.com/j4k0m/CVE-2018-11235) :  ![starts](https://img.shields.io/github/stars/j4k0m/CVE-2018-11235.svg) ![forks](https://img.shields.io/github/forks/j4k0m/CVE-2018-11235.svg)
- [https://github.com/twseptian/cve-2018-11235-git-submodule-ce-and-docker-ngrok-configuration](https://github.com/twseptian/cve-2018-11235-git-submodule-ce-and-docker-ngrok-configuration) :  ![starts](https://img.shields.io/github/stars/twseptian/cve-2018-11235-git-submodule-ce-and-docker-ngrok-configuration.svg) ![forks](https://img.shields.io/github/forks/twseptian/cve-2018-11235-git-submodule-ce-and-docker-ngrok-configuration.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/j4k0m/CVE-2018-6574](https://github.com/j4k0m/CVE-2018-6574) :  ![starts](https://img.shields.io/github/stars/j4k0m/CVE-2018-6574.svg) ![forks](https://img.shields.io/github/forks/j4k0m/CVE-2018-6574.svg)
- [https://github.com/twseptian/cve-2018-6574](https://github.com/twseptian/cve-2018-6574) :  ![starts](https://img.shields.io/github/stars/twseptian/cve-2018-6574.svg) ![forks](https://img.shields.io/github/forks/twseptian/cve-2018-6574.svg)


## CVE-2017-9841
 Util/PHP/eval-stdin.php in PHPUnit before 4.8.28 and 5.x before 5.6.3 allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a &quot;&lt;?php &quot; substring, as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.

- [https://github.com/incogbyte/laravel-phpunit-rce-masscaner](https://github.com/incogbyte/laravel-phpunit-rce-masscaner) :  ![starts](https://img.shields.io/github/stars/incogbyte/laravel-phpunit-rce-masscaner.svg) ![forks](https://img.shields.io/github/forks/incogbyte/laravel-phpunit-rce-masscaner.svg)


## CVE-2016-10033
 The mailSend function in the isMail transport in PHPMailer before 5.2.18 might allow remote attackers to pass extra parameters to the mail command and consequently execute arbitrary code via a \&quot; (backslash double quote) in a crafted Sender property.

- [https://github.com/j4k0m/CVE-2016-10033](https://github.com/j4k0m/CVE-2016-10033) :  ![starts](https://img.shields.io/github/stars/j4k0m/CVE-2016-10033.svg) ![forks](https://img.shields.io/github/forks/j4k0m/CVE-2016-10033.svg)


## CVE-2016-2098
 Action Pack in Ruby on Rails before 3.2.22.2, 4.x before 4.1.14.2, and 4.2.x before 4.2.5.2 allows remote attackers to execute arbitrary Ruby code by leveraging an application's unrestricted use of the render method.

- [https://github.com/j4k0m/CVE-2016-2098](https://github.com/j4k0m/CVE-2016-2098) :  ![starts](https://img.shields.io/github/stars/j4k0m/CVE-2016-2098.svg) ![forks](https://img.shields.io/github/forks/j4k0m/CVE-2016-2098.svg)

