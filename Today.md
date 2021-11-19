# Update 2021-11-19
## CVE-2021-37580
 A flaw was found in Apache ShenYu Admin. The incorrect use of JWT in ShenyuAdminBootstrap allows an attacker to bypass authentication. This issue affected Apache ShenYu 2.3.0 and 2.4.0

- [https://github.com/fengwenhua/CVE-2021-37580](https://github.com/fengwenhua/CVE-2021-37580) :  ![starts](https://img.shields.io/github/stars/fengwenhua/CVE-2021-37580.svg) ![forks](https://img.shields.io/github/forks/fengwenhua/CVE-2021-37580.svg)
- [https://github.com/rabbitsafe/CVE-2021-37580](https://github.com/rabbitsafe/CVE-2021-37580) :  ![starts](https://img.shields.io/github/stars/rabbitsafe/CVE-2021-37580.svg) ![forks](https://img.shields.io/github/forks/rabbitsafe/CVE-2021-37580.svg)


## CVE-2020-7740
 This affects all versions of package node-pdf-generator. Due to lack of user input validation and sanitization done to the content given to node-pdf-generator, it is possible for an attacker to craft a url that will be passed to an external server allowing an SSRF attack.

- [https://github.com/CS4239-U6/node-pdf-generator-ssrf](https://github.com/CS4239-U6/node-pdf-generator-ssrf) :  ![starts](https://img.shields.io/github/stars/CS4239-U6/node-pdf-generator-ssrf.svg) ![forks](https://img.shields.io/github/forks/CS4239-U6/node-pdf-generator-ssrf.svg)


## CVE-2019-6249
 An issue was discovered in HuCart v5.7.4. There is a CSRF vulnerability that can add an admin account via /adminsys/index.php?load=admins&amp;act=edit_info&amp;act_type=add.

- [https://github.com/AlphabugX/CVE-2019-6249_Hucart-cms](https://github.com/AlphabugX/CVE-2019-6249_Hucart-cms) :  ![starts](https://img.shields.io/github/stars/AlphabugX/CVE-2019-6249_Hucart-cms.svg) ![forks](https://img.shields.io/github/forks/AlphabugX/CVE-2019-6249_Hucart-cms.svg)


## CVE-2017-17562
 Embedthis GoAhead before 3.6.5 allows remote code execution if CGI is enabled and a CGI program is dynamically linked. This is a result of initializing the environment of forked CGI scripts using untrusted HTTP request parameters in the cgiHandler function in cgi.c. When combined with the glibc dynamic linker, this behaviour can be abused for remote code execution using special parameter names such as LD_PRELOAD. An attacker can POST their shared object payload in the body of the request, and reference it using /proc/self/fd/0.

- [https://github.com/freitzzz/bash-CVE-2017-17562](https://github.com/freitzzz/bash-CVE-2017-17562) :  ![starts](https://img.shields.io/github/stars/freitzzz/bash-CVE-2017-17562.svg) ![forks](https://img.shields.io/github/forks/freitzzz/bash-CVE-2017-17562.svg)


## CVE-2017-16226
 The static-eval module is intended to evaluate statically-analyzable expressions. In affected versions, untrusted user input is able to access the global function constructor, effectively allowing arbitrary code execution.

- [https://github.com/ossf-cve-benchmark/CVE-2017-16226](https://github.com/ossf-cve-benchmark/CVE-2017-16226) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16226.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16226.svg)


## CVE-2013-2171
 The vm_map_lookup function in sys/vm/vm_map.c in the mmap implementation in the kernel in FreeBSD 9.0 through 9.1-RELEASE-p4 does not properly determine whether a task should have write access to a memory location, which allows local users to bypass filesystem write permissions and consequently gain privileges via a crafted application that leverages read permissions, and makes mmap and ptrace system calls.

- [https://github.com/Gabriel-Lima232/FreeBSD-9.0-9.1-Privilege-Escalation](https://github.com/Gabriel-Lima232/FreeBSD-9.0-9.1-Privilege-Escalation) :  ![starts](https://img.shields.io/github/stars/Gabriel-Lima232/FreeBSD-9.0-9.1-Privilege-Escalation.svg) ![forks](https://img.shields.io/github/forks/Gabriel-Lima232/FreeBSD-9.0-9.1-Privilege-Escalation.svg)

