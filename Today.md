# Update 2024-08-06
## CVE-2024-32002
 Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.

- [https://github.com/chrisWalker11/running-CVE-2024-32002-locally-for-tesing](https://github.com/chrisWalker11/running-CVE-2024-32002-locally-for-tesing) :  ![starts](https://img.shields.io/github/stars/chrisWalker11/running-CVE-2024-32002-locally-for-tesing.svg) ![forks](https://img.shields.io/github/forks/chrisWalker11/running-CVE-2024-32002-locally-for-tesing.svg)


## CVE-2024-26229
 Windows CSC Service Elevation of Privilege Vulnerability

- [https://github.com/Cracked5pider/eop24-26229](https://github.com/Cracked5pider/eop24-26229) :  ![starts](https://img.shields.io/github/stars/Cracked5pider/eop24-26229.svg) ![forks](https://img.shields.io/github/forks/Cracked5pider/eop24-26229.svg)


## CVE-2024-1112
 Heap-based buffer overflow vulnerability in Resource Hacker, developed by Angus Johnson, affecting version 3.6.0.92. This vulnerability could allow an attacker to execute arbitrary code via a long filename argument.

- [https://github.com/enessakircolak/CVE-2024-1112](https://github.com/enessakircolak/CVE-2024-1112) :  ![starts](https://img.shields.io/github/stars/enessakircolak/CVE-2024-1112.svg) ![forks](https://img.shields.io/github/forks/enessakircolak/CVE-2024-1112.svg)


## CVE-2024-0044
 In createSessionInternal of PackageInstallerService.java, there is a possible run-as any app due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/nexussecelite/EvilDroid](https://github.com/nexussecelite/EvilDroid) :  ![starts](https://img.shields.io/github/stars/nexussecelite/EvilDroid.svg) ![forks](https://img.shields.io/github/forks/nexussecelite/EvilDroid.svg)


## CVE-2023-25813
 Sequelize is a Node.js ORM tool. In versions prior to 6.19.1 a SQL injection exploit exists related to replacements. Parameters which are passed through replacements are not properly escaped which can lead to arbitrary SQL injection depending on the specific queries in use. The issue has been fixed in Sequelize 6.19.1. Users are advised to upgrade. Users unable to upgrade should not use the `replacements` and the `where` option in the same query.

- [https://github.com/White-BAO/CVE-2023-25813](https://github.com/White-BAO/CVE-2023-25813) :  ![starts](https://img.shields.io/github/stars/White-BAO/CVE-2023-25813.svg) ![forks](https://img.shields.io/github/forks/White-BAO/CVE-2023-25813.svg)


## CVE-2023-7028
 An issue has been discovered in GitLab CE/EE affecting all versions from 16.1 prior to 16.1.6, 16.2 prior to 16.2.9, 16.3 prior to 16.3.7, 16.4 prior to 16.4.5, 16.5 prior to 16.5.6, 16.6 prior to 16.6.4, and 16.7 prior to 16.7.2 in which user account password reset emails could be delivered to an unverified email address.

- [https://github.com/googlei1996/CVE-2023-7028](https://github.com/googlei1996/CVE-2023-7028) :  ![starts](https://img.shields.io/github/stars/googlei1996/CVE-2023-7028.svg) ![forks](https://img.shields.io/github/forks/googlei1996/CVE-2023-7028.svg)


## CVE-2020-29661
 A locking issue was discovered in the tty subsystem of the Linux kernel through 5.9.13. drivers/tty/tty_jobctrl.c allows a use-after-free attack against TIOCSPGRP, aka CID-54ffccbf053b.

- [https://github.com/wojkos9/arm-CVE-2020-29661](https://github.com/wojkos9/arm-CVE-2020-29661) :  ![starts](https://img.shields.io/github/stars/wojkos9/arm-CVE-2020-29661.svg) ![forks](https://img.shields.io/github/forks/wojkos9/arm-CVE-2020-29661.svg)


## CVE-2020-0796
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

- [https://github.com/0x25bit/CVE-2020-0796-PoC](https://github.com/0x25bit/CVE-2020-0796-PoC) :  ![starts](https://img.shields.io/github/stars/0x25bit/CVE-2020-0796-PoC.svg) ![forks](https://img.shields.io/github/forks/0x25bit/CVE-2020-0796-PoC.svg)

