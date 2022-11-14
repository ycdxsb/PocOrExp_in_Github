# Update 2022-11-14
## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/icontempt/CVE-2022-0847](https://github.com/icontempt/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/icontempt/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/icontempt/CVE-2022-0847.svg)


## CVE-2019-9193
 ** DISPUTED ** In PostgreSQL 9.3 through 11.2, the &quot;COPY TO/FROM PROGRAM&quot; function allows superusers and users in the 'pg_execute_server_program' group to execute arbitrary code in the context of the database's operating system user. This functionality is enabled by default and can be abused to run arbitrary operating system commands on Windows, Linux, and macOS. NOTE: Third parties claim/state this is not an issue because PostgreSQL functionality for &#8216;COPY TO/FROM PROGRAM&#8217; is acting as intended. References state that in PostgreSQL, a superuser can execute commands as the server user without using the &#8216;COPY FROM PROGRAM&#8217;.

- [https://github.com/chromanite/CVE-2019-9193-PostgreSQL-9.3-11.7](https://github.com/chromanite/CVE-2019-9193-PostgreSQL-9.3-11.7) :  ![starts](https://img.shields.io/github/stars/chromanite/CVE-2019-9193-PostgreSQL-9.3-11.7.svg) ![forks](https://img.shields.io/github/forks/chromanite/CVE-2019-9193-PostgreSQL-9.3-11.7.svg)


## CVE-2017-16995
 The check_alu_op function in kernel/bpf/verifier.c in the Linux kernel through 4.4 allows local users to cause a denial of service (memory corruption) or possibly have unspecified other impact by leveraging incorrect sign extension.

- [https://github.com/ivilpez/cve-2017-16995.c](https://github.com/ivilpez/cve-2017-16995.c) :  ![starts](https://img.shields.io/github/stars/ivilpez/cve-2017-16995.c.svg) ![forks](https://img.shields.io/github/forks/ivilpez/cve-2017-16995.c.svg)


## CVE-2017-0785
 A information disclosure vulnerability in the Android system (bluetooth). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-63146698.

- [https://github.com/CyberKimathi/Py3-CVE-2017-0785](https://github.com/CyberKimathi/Py3-CVE-2017-0785) :  ![starts](https://img.shields.io/github/stars/CyberKimathi/Py3-CVE-2017-0785.svg) ![forks](https://img.shields.io/github/forks/CyberKimathi/Py3-CVE-2017-0785.svg)

