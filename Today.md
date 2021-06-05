# Update 2021-06-05
## CVE-2021-27965
 The MsIo64.sys driver before 1.1.19.1016 in MSI Dragon Center before 2.0.98.0 has a buffer overflow that allows privilege escalation via a crafted 0x80102040, 0x80102044, 0x80102050, or 0x80102054 IOCTL request.

- [https://github.com/mathisvickie/CVE-2021-27965](https://github.com/mathisvickie/CVE-2021-27965) :  ![starts](https://img.shields.io/github/stars/mathisvickie/CVE-2021-27965.svg) ![forks](https://img.shields.io/github/forks/mathisvickie/CVE-2021-27965.svg)


## CVE-2021-21985
 The vSphere Client (HTML5) contains a remote code execution vulnerability due to lack of input validation in the Virtual SAN Health Check plug-in which is enabled by default in vCenter Server. A malicious actor with network access to port 443 may exploit this issue to execute commands with unrestricted privileges on the underlying operating system that hosts vCenter Server.

- [https://github.com/r0ckysec/CVE-2021-21985](https://github.com/r0ckysec/CVE-2021-21985) :  ![starts](https://img.shields.io/github/stars/r0ckysec/CVE-2021-21985.svg) ![forks](https://img.shields.io/github/forks/r0ckysec/CVE-2021-21985.svg)
- [https://github.com/xnianq/cve-2021-21985_exp](https://github.com/xnianq/cve-2021-21985_exp) :  ![starts](https://img.shields.io/github/stars/xnianq/cve-2021-21985_exp.svg) ![forks](https://img.shields.io/github/forks/xnianq/cve-2021-21985_exp.svg)
- [https://github.com/daedalus/CVE-2021-21985](https://github.com/daedalus/CVE-2021-21985) :  ![starts](https://img.shields.io/github/stars/daedalus/CVE-2021-21985.svg) ![forks](https://img.shields.io/github/forks/daedalus/CVE-2021-21985.svg)


## CVE-2020-24949
 Privilege escalation in PHP-Fusion 9.03.50 downloads/downloads.php allows an authenticated user (not admin) to send a crafted request to the server and perform remote command execution (RCE).

- [https://github.com/r90tpass/CVE-2020-24949](https://github.com/r90tpass/CVE-2020-24949) :  ![starts](https://img.shields.io/github/stars/r90tpass/CVE-2020-24949.svg) ![forks](https://img.shields.io/github/forks/r90tpass/CVE-2020-24949.svg)


## CVE-2020-9484
 When using Apache Tomcat versions 10.0.0-M1 to 10.0.0-M4, 9.0.0.M1 to 9.0.34, 8.5.0 to 8.5.54 and 7.0.0 to 7.0.103 if a) an attacker is able to control the contents and name of a file on the server; and b) the server is configured to use the PersistenceManager with a FileStore; and c) the PersistenceManager is configured with sessionAttributeValueClassNameFilter=&quot;null&quot; (the default unless a SecurityManager is used) or a sufficiently lax filter to allow the attacker provided object to be deserialized; and d) the attacker knows the relative file path from the storage location used by FileStore to the file the attacker has control over; then, using a specifically crafted request, the attacker will be able to trigger remote code execution via deserialization of the file under their control. Note that all of conditions a) to d) must be true for the attack to succeed.

- [https://github.com/DarkRabbit-0/-CVE-2020-9484-](https://github.com/DarkRabbit-0/-CVE-2020-9484-) :  ![starts](https://img.shields.io/github/stars/DarkRabbit-0/-CVE-2020-9484-.svg) ![forks](https://img.shields.io/github/forks/DarkRabbit-0/-CVE-2020-9484-.svg)
- [https://github.com/DarkRabbit-0/-CVE-2020-9484](https://github.com/DarkRabbit-0/-CVE-2020-9484) :  ![starts](https://img.shields.io/github/stars/DarkRabbit-0/-CVE-2020-9484.svg) ![forks](https://img.shields.io/github/forks/DarkRabbit-0/-CVE-2020-9484.svg)


## CVE-2020-7471
 Django 1.11 before 1.11.28, 2.2 before 2.2.10, and 3.0 before 3.0.3 allows SQL Injection if untrusted data is used as a StringAgg delimiter (e.g., in Django applications that offer downloads of data as a series of rows with a user-specified column delimiter). By passing a suitably crafted delimiter to a contrib.postgres.aggregates.StringAgg instance, it was possible to break escaping and inject malicious SQL.

- [https://github.com/huzaifakhan771/CVE-2020-7471-Django](https://github.com/huzaifakhan771/CVE-2020-7471-Django) :  ![starts](https://img.shields.io/github/stars/huzaifakhan771/CVE-2020-7471-Django.svg) ![forks](https://img.shields.io/github/forks/huzaifakhan771/CVE-2020-7471-Django.svg)


## CVE-2019-15947
 In Bitcoin Core 0.18.0, bitcoin-qt stores wallet.dat data unencrypted in memory. Upon a crash, it may dump a core file. If a user were to mishandle a core file, an attacker can reconstruct the user's wallet.dat file, including their private keys, via a grep &quot;6231 0500&quot; command.

- [https://github.com/oxagast/oxasploits](https://github.com/oxagast/oxasploits) :  ![starts](https://img.shields.io/github/stars/oxagast/oxasploits.svg) ![forks](https://img.shields.io/github/forks/oxagast/oxasploits.svg)


## CVE-2019-12881
 i915_gem_userptr_get_pages in drivers/gpu/drm/i915/i915_gem_userptr.c in the Linux kernel 4.15.0 on Ubuntu 18.04.2 allows local users to cause a denial of service (NULL pointer dereference and BUG) or possibly have unspecified other impact via crafted ioctl calls to /dev/dri/card0.

- [https://github.com/oxagast/oxasploits](https://github.com/oxagast/oxasploits) :  ![starts](https://img.shields.io/github/stars/oxagast/oxasploits.svg) ![forks](https://img.shields.io/github/forks/oxagast/oxasploits.svg)


## CVE-2019-9193
 ** DISPUTED ** In PostgreSQL 9.3 through 11.2, the &quot;COPY TO/FROM PROGRAM&quot; function allows superusers and users in the 'pg_execute_server_program' group to execute arbitrary code in the context of the database's operating system user. This functionality is enabled by default and can be abused to run arbitrary operating system commands on Windows, Linux, and macOS. NOTE: Third parties claim/state this is not an issue because PostgreSQL functionality for &#8216;COPY TO/FROM PROGRAM&#8217; is acting as intended. References state that in PostgreSQL, a superuser can execute commands as the server user without using the &#8216;COPY FROM PROGRAM&#8217;.

- [https://github.com/DarkRabbit-0/CVE-2019-9193](https://github.com/DarkRabbit-0/CVE-2019-9193) :  ![starts](https://img.shields.io/github/stars/DarkRabbit-0/CVE-2019-9193.svg) ![forks](https://img.shields.io/github/forks/DarkRabbit-0/CVE-2019-9193.svg)


## CVE-2018-17336
 UDisks 2.8.0 has a format string vulnerability in udisks_log in udiskslogging.c, allowing attackers to obtain sensitive information (stack contents), cause a denial of service (memory corruption), or possibly have unspecified other impact via a malformed filesystem label, as demonstrated by %d or %n substrings.

- [https://github.com/oxagast/oxasploits](https://github.com/oxagast/oxasploits) :  ![starts](https://img.shields.io/github/stars/oxagast/oxasploits.svg) ![forks](https://img.shields.io/github/forks/oxagast/oxasploits.svg)


## CVE-2017-5816
 A Remote Code Execution vulnerability in HPE Intelligent Management Center (iMC) PLAT version 7.3 E0504P04 was found.

- [https://github.com/oxagast/oxasploits](https://github.com/oxagast/oxasploits) :  ![starts](https://img.shields.io/github/stars/oxagast/oxasploits.svg) ![forks](https://img.shields.io/github/forks/oxagast/oxasploits.svg)


## CVE-2016-10401
 ZyXEL PK5001Z devices have zyad5001 as the su password, which makes it easier for remote attackers to obtain root access if a non-root account password is known (or a non-root default account exists within an ISP's deployment of these devices).

- [https://github.com/oxagast/oxasploits](https://github.com/oxagast/oxasploits) :  ![starts](https://img.shields.io/github/stars/oxagast/oxasploits.svg) ![forks](https://img.shields.io/github/forks/oxagast/oxasploits.svg)


## CVE-2010-2626
 index.pl in Miyabi CGI Tools SEO Links 1.02 allows remote attackers to execute arbitrary commands via shell metacharacters in the fn command. NOTE: some of these details are obtained from third party information.

- [https://github.com/oxagast/oxasploits](https://github.com/oxagast/oxasploits) :  ![starts](https://img.shields.io/github/stars/oxagast/oxasploits.svg) ![forks](https://img.shields.io/github/forks/oxagast/oxasploits.svg)


## CVE-2004-1561
 Buffer overflow in Icecast 2.0.1 and earlier allows remote attackers to execute arbitrary code via an HTTP request with a large number of headers.

- [https://github.com/thel1nus/CVE-2004-1561-Notes](https://github.com/thel1nus/CVE-2004-1561-Notes) :  ![starts](https://img.shields.io/github/stars/thel1nus/CVE-2004-1561-Notes.svg) ![forks](https://img.shields.io/github/forks/thel1nus/CVE-2004-1561-Notes.svg)

