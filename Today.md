# Update 2022-09-08
## CVE-2022-35405
 Zoho ManageEngine Password Manager Pro before 12101 and PAM360 before 5510 are vulnerable to unauthenticated remote code execution. (This also affects ManageEngine Access Manager Plus before 4303 with authentication.)

- [https://github.com/viniciuspereiras/CVE-2022-35405](https://github.com/viniciuspereiras/CVE-2022-35405) :  ![starts](https://img.shields.io/github/stars/viniciuspereiras/CVE-2022-35405.svg) ![forks](https://img.shields.io/github/forks/viniciuspereiras/CVE-2022-35405.svg)


## CVE-2022-31299
 Haraj v3.7 was discovered to contain a reflected cross-site scripting (XSS) vulnerability in the User Upgrade Form.

- [https://github.com/bigzooooz/CVE-2022-31299](https://github.com/bigzooooz/CVE-2022-31299) :  ![starts](https://img.shields.io/github/stars/bigzooooz/CVE-2022-31299.svg) ![forks](https://img.shields.io/github/forks/bigzooooz/CVE-2022-31299.svg)


## CVE-2022-20186
 In kbase_mem_alias of mali_kbase_mem_linux.c, there is a possible arbitrary code execution due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-215001024References: N/A

- [https://github.com/SmileTabLabo/CVE-2022-20186_CTXZ](https://github.com/SmileTabLabo/CVE-2022-20186_CTXZ) :  ![starts](https://img.shields.io/github/stars/SmileTabLabo/CVE-2022-20186_CTXZ.svg) ![forks](https://img.shields.io/github/forks/SmileTabLabo/CVE-2022-20186_CTXZ.svg)


## CVE-2022-2639
 An integer coercion error was found in the openvswitch kernel module. Given a sufficiently large number of actions, while copying and reserving memory for a new action of a new flow, the reserve_sfa_size() function does not return -EMSGSIZE as expected, potentially leading to an out-of-bounds write access. This flaw allows a local user to crash or potentially escalate their privileges on the system.

- [https://github.com/avboy1337/CVE-2022-2639-PipeVersion](https://github.com/avboy1337/CVE-2022-2639-PipeVersion) :  ![starts](https://img.shields.io/github/stars/avboy1337/CVE-2022-2639-PipeVersion.svg) ![forks](https://img.shields.io/github/forks/avboy1337/CVE-2022-2639-PipeVersion.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Myhostaaa/CVE-2021-41773](https://github.com/Myhostaaa/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Myhostaaa/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Myhostaaa/CVE-2021-41773.svg)


## CVE-2021-3129
 Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.

- [https://github.com/shadowabi/Laravel-CVE-2021-3129](https://github.com/shadowabi/Laravel-CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/shadowabi/Laravel-CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/shadowabi/Laravel-CVE-2021-3129.svg)


## CVE-2020-7471
 Django 1.11 before 1.11.28, 2.2 before 2.2.10, and 3.0 before 3.0.3 allows SQL Injection if untrusted data is used as a StringAgg delimiter (e.g., in Django applications that offer downloads of data as a series of rows with a user-specified column delimiter). By passing a suitably crafted delimiter to a contrib.postgres.aggregates.StringAgg instance, it was possible to break escaping and inject malicious SQL.

- [https://github.com/Tempuss/CTF_CVE-2020-7471](https://github.com/Tempuss/CTF_CVE-2020-7471) :  ![starts](https://img.shields.io/github/stars/Tempuss/CTF_CVE-2020-7471.svg) ![forks](https://img.shields.io/github/forks/Tempuss/CTF_CVE-2020-7471.svg)


## CVE-2018-1270
 Spring Framework, versions 5.0 prior to 5.0.5 and versions 4.3 prior to 4.3.15 and older unsupported versions, allow applications to expose STOMP over WebSocket endpoints with a simple, in-memory STOMP broker through the spring-messaging module. A malicious user (or attacker) can craft a message to the broker that can lead to a remote code execution attack.

- [https://github.com/tafamace/CVE-2018-1270](https://github.com/tafamace/CVE-2018-1270) :  ![starts](https://img.shields.io/github/stars/tafamace/CVE-2018-1270.svg) ![forks](https://img.shields.io/github/forks/tafamace/CVE-2018-1270.svg)

