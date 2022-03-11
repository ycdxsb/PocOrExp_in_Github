# Update 2022-03-11
## CVE-2022-24990
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/VVeakee/CVE-2022-24990-POC](https://github.com/VVeakee/CVE-2022-24990-POC) :  ![starts](https://img.shields.io/github/stars/VVeakee/CVE-2022-24990-POC.svg) ![forks](https://img.shields.io/github/forks/VVeakee/CVE-2022-24990-POC.svg)


## CVE-2022-24112
 An attacker can abuse the batch-requests plugin to send requests to bypass the IP restriction of Admin API. A default configuration of Apache APISIX (with default API key) is vulnerable to remote code execution. When the admin key was changed or the port of Admin API was changed to a port different from the data panel, the impact is lower. But there is still a risk to bypass the IP restriction of Apache APISIX's data panel. There is a check in the batch-requests plugin which overrides the client IP with its real remote IP. But due to a bug in the code, this check can be bypassed.

- [https://github.com/Mah1ndra/CVE-2022-24112](https://github.com/Mah1ndra/CVE-2022-24112) :  ![starts](https://img.shields.io/github/stars/Mah1ndra/CVE-2022-24112.svg) ![forks](https://img.shields.io/github/forks/Mah1ndra/CVE-2022-24112.svg)


## CVE-2022-22947
 In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

- [https://github.com/An0th3r/CVE-2022-22947-exp](https://github.com/An0th3r/CVE-2022-22947-exp) :  ![starts](https://img.shields.io/github/stars/An0th3r/CVE-2022-22947-exp.svg) ![forks](https://img.shields.io/github/forks/An0th3r/CVE-2022-22947-exp.svg)


## CVE-2022-22588
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/trevorspiniolas/homekitdos](https://github.com/trevorspiniolas/homekitdos) :  ![starts](https://img.shields.io/github/stars/trevorspiniolas/homekitdos.svg) ![forks](https://img.shields.io/github/forks/trevorspiniolas/homekitdos.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/gyaansastra/CVE-2022-0847](https://github.com/gyaansastra/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/gyaansastra/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/gyaansastra/CVE-2022-0847.svg)
- [https://github.com/pentestblogin/pentestblog-CVE-2022-0847](https://github.com/pentestblogin/pentestblog-CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/pentestblogin/pentestblog-CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/pentestblogin/pentestblog-CVE-2022-0847.svg)
- [https://github.com/edsonjt81/CVE-2022-0847-Linux](https://github.com/edsonjt81/CVE-2022-0847-Linux) :  ![starts](https://img.shields.io/github/stars/edsonjt81/CVE-2022-0847-Linux.svg) ![forks](https://img.shields.io/github/forks/edsonjt81/CVE-2022-0847-Linux.svg)
- [https://github.com/babyshen/CVE-2022-0847](https://github.com/babyshen/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/babyshen/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/babyshen/CVE-2022-0847.svg)
- [https://github.com/T4t4ru/CVE-2022-0847](https://github.com/T4t4ru/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/T4t4ru/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/T4t4ru/CVE-2022-0847.svg)
- [https://github.com/chenaotian/CVE-2022-0847](https://github.com/chenaotian/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/chenaotian/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/chenaotian/CVE-2022-0847.svg)
- [https://github.com/AyoubNajim/cve-2022-0847dirtypipe-exploit](https://github.com/AyoubNajim/cve-2022-0847dirtypipe-exploit) :  ![starts](https://img.shields.io/github/stars/AyoubNajim/cve-2022-0847dirtypipe-exploit.svg) ![forks](https://img.shields.io/github/forks/AyoubNajim/cve-2022-0847dirtypipe-exploit.svg)
- [https://github.com/Mustafa1986/CVE-2022-0847-DirtyPipe-Exploit](https://github.com/Mustafa1986/CVE-2022-0847-DirtyPipe-Exploit) :  ![starts](https://img.shields.io/github/stars/Mustafa1986/CVE-2022-0847-DirtyPipe-Exploit.svg) ![forks](https://img.shields.io/github/forks/Mustafa1986/CVE-2022-0847-DirtyPipe-Exploit.svg)
- [https://github.com/nanaao/Dirtypipe-exploit](https://github.com/nanaao/Dirtypipe-exploit) :  ![starts](https://img.shields.io/github/stars/nanaao/Dirtypipe-exploit.svg) ![forks](https://img.shields.io/github/forks/nanaao/Dirtypipe-exploit.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Hattan-515/POC-CVE-2021-41773](https://github.com/Hattan-515/POC-CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Hattan-515/POC-CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Hattan-515/POC-CVE-2021-41773.svg)
- [https://github.com/sixpacksecurity/CVE-2021-41773](https://github.com/sixpacksecurity/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sixpacksecurity/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sixpacksecurity/CVE-2021-41773.svg)
- [https://github.com/McSl0vv/CVE-2021-41773](https://github.com/McSl0vv/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/McSl0vv/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/McSl0vv/CVE-2021-41773.svg)


## CVE-2021-40870
 An issue was discovered in Aviatrix Controller 6.x before 6.5-1804.1922. Unrestricted upload of a file with a dangerous type is possible, which allows an unauthenticated user to execute arbitrary code via directory traversal.

- [https://github.com/System00-Security/CVE-2021-40870](https://github.com/System00-Security/CVE-2021-40870) :  ![starts](https://img.shields.io/github/stars/System00-Security/CVE-2021-40870.svg) ![forks](https://img.shields.io/github/forks/System00-Security/CVE-2021-40870.svg)


## CVE-2021-26084
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0 before 7.12.5.

- [https://github.com/TheclaMcentire/CVE-2021-26084_Confluence](https://github.com/TheclaMcentire/CVE-2021-26084_Confluence) :  ![starts](https://img.shields.io/github/stars/TheclaMcentire/CVE-2021-26084_Confluence.svg) ![forks](https://img.shields.io/github/forks/TheclaMcentire/CVE-2021-26084_Confluence.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/pengalaman-1t/CVE-2021-4034](https://github.com/pengalaman-1t/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/pengalaman-1t/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/pengalaman-1t/CVE-2021-4034.svg)
- [https://github.com/J0hnbX/CVE-2021-4034-new](https://github.com/J0hnbX/CVE-2021-4034-new) :  ![starts](https://img.shields.io/github/stars/J0hnbX/CVE-2021-4034-new.svg) ![forks](https://img.shields.io/github/forks/J0hnbX/CVE-2021-4034-new.svg)


## CVE-2020-25540
 ThinkAdmin v6 is affected by a directory traversal vulnerability. An unauthorized attacker can read arbitrarily file on a remote server via GET request encode parameter.

- [https://github.com/Rajchowdhury420/ThinkAdmin-CVE-2020-25540](https://github.com/Rajchowdhury420/ThinkAdmin-CVE-2020-25540) :  ![starts](https://img.shields.io/github/stars/Rajchowdhury420/ThinkAdmin-CVE-2020-25540.svg) ![forks](https://img.shields.io/github/forks/Rajchowdhury420/ThinkAdmin-CVE-2020-25540.svg)


## CVE-2019-13272
 In the Linux kernel before 5.1.17, ptrace_link in kernel/ptrace.c mishandles the recording of the credentials of a process that wants to create a ptrace relationship, which allows local users to obtain root access by leveraging certain scenarios with a parent-child process relationship, where a parent drops privileges and calls execve (potentially allowing control by an attacker). One contributing factor is an object lifetime issue (which can also cause a panic). Another contributing factor is incorrect marking of a ptrace relationship as privileged, which is exploitable through (for example) Polkit's pkexec helper with PTRACE_TRACEME. NOTE: SELinux deny_ptrace might be a usable workaround in some environments.

- [https://github.com/babyshen/CVE-2019-13272](https://github.com/babyshen/CVE-2019-13272) :  ![starts](https://img.shields.io/github/stars/babyshen/CVE-2019-13272.svg) ![forks](https://img.shields.io/github/forks/babyshen/CVE-2019-13272.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/purgedemo/CVE-2018-6574](https://github.com/purgedemo/CVE-2018-6574) :  ![starts](https://img.shields.io/github/stars/purgedemo/CVE-2018-6574.svg) ![forks](https://img.shields.io/github/forks/purgedemo/CVE-2018-6574.svg)
- [https://github.com/MohamedTarekq/test-CVE-2018-6574-](https://github.com/MohamedTarekq/test-CVE-2018-6574-) :  ![starts](https://img.shields.io/github/stars/MohamedTarekq/test-CVE-2018-6574-.svg) ![forks](https://img.shields.io/github/forks/MohamedTarekq/test-CVE-2018-6574-.svg)


## CVE-2017-9841
 Util/PHP/eval-stdin.php in PHPUnit before 4.8.28 and 5.x before 5.6.3 allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a &quot;&lt;?php &quot; substring, as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.

- [https://github.com/0xrodt/laravel-phpunit-rce-masscaner](https://github.com/0xrodt/laravel-phpunit-rce-masscaner) :  ![starts](https://img.shields.io/github/stars/0xrodt/laravel-phpunit-rce-masscaner.svg) ![forks](https://img.shields.io/github/forks/0xrodt/laravel-phpunit-rce-masscaner.svg)

