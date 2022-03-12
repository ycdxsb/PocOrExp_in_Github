# Update 2022-03-12
## CVE-2022-24990
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/VVeakee/CVE-2022-24990-EXP](https://github.com/VVeakee/CVE-2022-24990-EXP) :  ![starts](https://img.shields.io/github/stars/VVeakee/CVE-2022-24990-EXP.svg) ![forks](https://img.shields.io/github/forks/VVeakee/CVE-2022-24990-EXP.svg)


## CVE-2022-22947
 In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

- [https://github.com/hh-hunter/cve-2022-22947-docker](https://github.com/hh-hunter/cve-2022-22947-docker) :  ![starts](https://img.shields.io/github/stars/hh-hunter/cve-2022-22947-docker.svg) ![forks](https://img.shields.io/github/forks/hh-hunter/cve-2022-22947-docker.svg)
- [https://github.com/PaoPaoLong-lab/Spring-CVE-2022-22947-](https://github.com/PaoPaoLong-lab/Spring-CVE-2022-22947-) :  ![starts](https://img.shields.io/github/stars/PaoPaoLong-lab/Spring-CVE-2022-22947-.svg) ![forks](https://img.shields.io/github/forks/PaoPaoLong-lab/Spring-CVE-2022-22947-.svg)
- [https://github.com/michaelklaan/CVE-2022-22947-Spring-Cloud](https://github.com/michaelklaan/CVE-2022-22947-Spring-Cloud) :  ![starts](https://img.shields.io/github/stars/michaelklaan/CVE-2022-22947-Spring-Cloud.svg) ![forks](https://img.shields.io/github/forks/michaelklaan/CVE-2022-22947-Spring-Cloud.svg)


## CVE-2022-0853
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/ByteHackr/CVE-2022-0853](https://github.com/ByteHackr/CVE-2022-0853) :  ![starts](https://img.shields.io/github/stars/ByteHackr/CVE-2022-0853.svg) ![forks](https://img.shields.io/github/forks/ByteHackr/CVE-2022-0853.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/terabitSec/dirtyPipe-automaticRoot](https://github.com/terabitSec/dirtyPipe-automaticRoot) :  ![starts](https://img.shields.io/github/stars/terabitSec/dirtyPipe-automaticRoot.svg) ![forks](https://img.shields.io/github/forks/terabitSec/dirtyPipe-automaticRoot.svg)
- [https://github.com/V0WKeep3r/CVE-2022-0847-DirtyPipe-Exploit](https://github.com/V0WKeep3r/CVE-2022-0847-DirtyPipe-Exploit) :  ![starts](https://img.shields.io/github/stars/V0WKeep3r/CVE-2022-0847-DirtyPipe-Exploit.svg) ![forks](https://img.shields.io/github/forks/V0WKeep3r/CVE-2022-0847-DirtyPipe-Exploit.svg)
- [https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe-](https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe-) :  ![starts](https://img.shields.io/github/stars/Greetdawn/CVE-2022-0847-DirtyPipe-.svg) ![forks](https://img.shields.io/github/forks/Greetdawn/CVE-2022-0847-DirtyPipe-.svg)
- [https://github.com/michaelklaan/CVE-2022-0847-Dirty-Pipe](https://github.com/michaelklaan/CVE-2022-0847-Dirty-Pipe) :  ![starts](https://img.shields.io/github/stars/michaelklaan/CVE-2022-0847-Dirty-Pipe.svg) ![forks](https://img.shields.io/github/forks/michaelklaan/CVE-2022-0847-Dirty-Pipe.svg)


## CVE-2021-41277
 Metabase is an open source data analytics platform. In affected versions a security issue has been discovered with the custom GeoJSON map (`admin-&gt;settings-&gt;maps-&gt;custom maps-&gt;add a map`) support and potential local file inclusion (including environment variables). URLs were not validated prior to being loaded. This issue is fixed in a new maintenance release (0.40.5 and 1.40.5), and any subsequent release after that. If you&#8217;re unable to upgrade immediately, you can mitigate this by including rules in your reverse proxy or load balancer or WAF to provide a validation filter before the application.

- [https://github.com/Chen-ling-afk/CVE-2021-41277](https://github.com/Chen-ling-afk/CVE-2021-41277) :  ![starts](https://img.shields.io/github/stars/Chen-ling-afk/CVE-2021-41277.svg) ![forks](https://img.shields.io/github/forks/Chen-ling-afk/CVE-2021-41277.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/Bin4xin/bin4xin.github.io](https://github.com/Bin4xin/bin4xin.github.io) :  ![starts](https://img.shields.io/github/stars/Bin4xin/bin4xin.github.io.svg) ![forks](https://img.shields.io/github/forks/Bin4xin/bin4xin.github.io.svg)


## CVE-2021-3560
 It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user. This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/Bin4xin/bin4xin.github.io](https://github.com/Bin4xin/bin4xin.github.io) :  ![starts](https://img.shields.io/github/stars/Bin4xin/bin4xin.github.io.svg) ![forks](https://img.shields.io/github/forks/Bin4xin/bin4xin.github.io.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via &quot;sudoedit -s&quot; and a command-line argument that ends with a single backslash character.

- [https://github.com/GatoGamer1155/CVE-2021-3156](https://github.com/GatoGamer1155/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/GatoGamer1155/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/GatoGamer1155/CVE-2021-3156.svg)


## CVE-2018-15727
 Grafana 2.x, 3.x, and 4.x before 4.6.4 and 5.x before 5.2.3 allows authentication bypass because an attacker can generate a valid &quot;remember me&quot; cookie knowing only a username of an LDAP or OAuth user.

- [https://github.com/svnsyn/CVE-2018-15727](https://github.com/svnsyn/CVE-2018-15727) :  ![starts](https://img.shields.io/github/stars/svnsyn/CVE-2018-15727.svg) ![forks](https://img.shields.io/github/forks/svnsyn/CVE-2018-15727.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/frarinha/CVE-2018-6574](https://github.com/frarinha/CVE-2018-6574) :  ![starts](https://img.shields.io/github/stars/frarinha/CVE-2018-6574.svg) ![forks](https://img.shields.io/github/forks/frarinha/CVE-2018-6574.svg)


## CVE-2018-1263
 Addresses partial fix in CVE-2018-1261. Pivotal spring-integration-zip, versions prior to 1.0.2, exposes an arbitrary file write vulnerability, that can be achieved using a specially crafted zip archive (affects other archives as well, bzip2, tar, xz, war, cpio, 7z), that holds path traversal filenames. So when the filename gets concatenated to the target extraction directory, the final path ends up outside of the target folder.

- [https://github.com/sakib570/CVE-2018-1263-Demo](https://github.com/sakib570/CVE-2018-1263-Demo) :  ![starts](https://img.shields.io/github/stars/sakib570/CVE-2018-1263-Demo.svg) ![forks](https://img.shields.io/github/forks/sakib570/CVE-2018-1263-Demo.svg)


## CVE-2017-18344
 The timer_create syscall implementation in kernel/time/posix-timers.c in the Linux kernel before 4.14.8 doesn't properly validate the sigevent-&gt;sigev_notify field, which leads to out-of-bounds access in the show_timer function (called when /proc/$PID/timers is read). This allows userspace applications to read arbitrary kernel memory (on a kernel built with CONFIG_POSIX_TIMERS and CONFIG_CHECKPOINT_RESTORE).

- [https://github.com/echo-devim/exploit_linux_kernel4.13](https://github.com/echo-devim/exploit_linux_kernel4.13) :  ![starts](https://img.shields.io/github/stars/echo-devim/exploit_linux_kernel4.13.svg) ![forks](https://img.shields.io/github/forks/echo-devim/exploit_linux_kernel4.13.svg)


## CVE-2017-14954
 The waitid implementation in kernel/exit.c in the Linux kernel through 4.13.4 accesses rusage data structures in unintended cases, which allows local users to obtain sensitive information, and bypass the KASLR protection mechanism, via a crafted system call.

- [https://github.com/echo-devim/exploit_linux_kernel4.13](https://github.com/echo-devim/exploit_linux_kernel4.13) :  ![starts](https://img.shields.io/github/stars/echo-devim/exploit_linux_kernel4.13.svg) ![forks](https://img.shields.io/github/forks/echo-devim/exploit_linux_kernel4.13.svg)


## CVE-2017-5123
 Insufficient data validation in waitid allowed an user to escape sandboxes on Linux.

- [https://github.com/echo-devim/exploit_linux_kernel4.13](https://github.com/echo-devim/exploit_linux_kernel4.13) :  ![starts](https://img.shields.io/github/stars/echo-devim/exploit_linux_kernel4.13.svg) ![forks](https://img.shields.io/github/forks/echo-devim/exploit_linux_kernel4.13.svg)

