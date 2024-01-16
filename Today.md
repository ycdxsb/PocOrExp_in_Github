# Update 2024-01-16
## CVE-2024-21887
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/yoryio/CVE-2023-46805_CVE-2024-21887_Scanner](https://github.com/yoryio/CVE-2023-46805_CVE-2024-21887_Scanner) :  ![starts](https://img.shields.io/github/stars/yoryio/CVE-2023-46805_CVE-2024-21887_Scanner.svg) ![forks](https://img.shields.io/github/forks/yoryio/CVE-2023-46805_CVE-2024-21887_Scanner.svg)
- [https://github.com/oways/ivanti-CVE-2024-21887](https://github.com/oways/ivanti-CVE-2024-21887) :  ![starts](https://img.shields.io/github/stars/oways/ivanti-CVE-2024-21887.svg) ![forks](https://img.shields.io/github/forks/oways/ivanti-CVE-2024-21887.svg)


## CVE-2023-51467
 The vulnerability permits attackers to circumvent authentication processes, enabling them to remotely execute arbitrary code

- [https://github.com/Jake123otte1/BadBizness-CVE-2023-51467](https://github.com/Jake123otte1/BadBizness-CVE-2023-51467) :  ![starts](https://img.shields.io/github/stars/Jake123otte1/BadBizness-CVE-2023-51467.svg) ![forks](https://img.shields.io/github/forks/Jake123otte1/BadBizness-CVE-2023-51467.svg)


## CVE-2023-46805
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/yoryio/CVE-2023-46805_CVE-2024-21887_Scanner](https://github.com/yoryio/CVE-2023-46805_CVE-2024-21887_Scanner) :  ![starts](https://img.shields.io/github/stars/yoryio/CVE-2023-46805_CVE-2024-21887_Scanner.svg) ![forks](https://img.shields.io/github/forks/yoryio/CVE-2023-46805_CVE-2024-21887_Scanner.svg)


## CVE-2023-36000
 A missing authorization check in the MacOS agent configuration endpoint of the Insider Threat Management Server enables an anonymous attacker on an adjacent network to obtain sensitive information. Successful exploitation requires an attacker to first obtain a valid agent authentication token. All versions before 7.14.3 are affected.

- [https://github.com/s3mPr1linux/CVE_2023_360003_POC](https://github.com/s3mPr1linux/CVE_2023_360003_POC) :  ![starts](https://img.shields.io/github/stars/s3mPr1linux/CVE_2023_360003_POC.svg) ![forks](https://img.shields.io/github/forks/s3mPr1linux/CVE_2023_360003_POC.svg)


## CVE-2023-27163
 request-baskets up to v1.2.1 was discovered to contain a Server-Side Request Forgery (SSRF) via the component /api/baskets/{name}. This vulnerability allows attackers to access network resources and sensitive information via a crafted API request.

- [https://github.com/davuXVI/CVE-2023-27163](https://github.com/davuXVI/CVE-2023-27163) :  ![starts](https://img.shields.io/github/stars/davuXVI/CVE-2023-27163.svg) ![forks](https://img.shields.io/github/forks/davuXVI/CVE-2023-27163.svg)


## CVE-2023-4206
 A use-after-free vulnerability in the Linux kernel's net/sched: cls_route component can be exploited to achieve local privilege escalation. When route4_change() is called on an existing filter, the whole tcf_result struct is always copied into the new instance of the filter. This causes a problem when updating a filter bound to a class, as tcf_unbind_filter() is always called on the old instance in the success path, decreasing filter_cnt of the still referenced class and allowing it to be deleted, leading to a use-after-free. We recommend upgrading past commit b80b829e9e2c1b3f7aae34855e04d8f6ecaf13c8.

- [https://github.com/hshivhare67/Kernel_4.1.15_CVE-2023-4206_CVE-2023-4207_CVE-2023-4208](https://github.com/hshivhare67/Kernel_4.1.15_CVE-2023-4206_CVE-2023-4207_CVE-2023-4208) :  ![starts](https://img.shields.io/github/stars/hshivhare67/Kernel_4.1.15_CVE-2023-4206_CVE-2023-4207_CVE-2023-4208.svg) ![forks](https://img.shields.io/github/forks/hshivhare67/Kernel_4.1.15_CVE-2023-4206_CVE-2023-4207_CVE-2023-4208.svg)


## CVE-2022-27925
 Zimbra Collaboration (aka ZCS) 8.8.15 and 9.0 has mboximport functionality that receives a ZIP archive and extracts files from it. An authenticated user with administrator rights has the ability to upload arbitrary files to the system, leading to directory traversal.

- [https://github.com/Josexv1/CVE-2022-27925](https://github.com/Josexv1/CVE-2022-27925) :  ![starts](https://img.shields.io/github/stars/Josexv1/CVE-2022-27925.svg) ![forks](https://img.shields.io/github/forks/Josexv1/CVE-2022-27925.svg)
- [https://github.com/GreyNoise-Intelligence/Zimbra_CVE-2022-37042-_CVE-2022-27925](https://github.com/GreyNoise-Intelligence/Zimbra_CVE-2022-37042-_CVE-2022-27925) :  ![starts](https://img.shields.io/github/stars/GreyNoise-Intelligence/Zimbra_CVE-2022-37042-_CVE-2022-27925.svg) ![forks](https://img.shields.io/github/forks/GreyNoise-Intelligence/Zimbra_CVE-2022-37042-_CVE-2022-27925.svg)


## CVE-2021-45046
 It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in an information leak and remote code execution in some environments and local code execution in all environments. Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7) fix this issue by removing support for message lookup patterns and disabling JNDI functionality by default.

- [https://github.com/alexbakker/log4shell-tools](https://github.com/alexbakker/log4shell-tools) :  ![starts](https://img.shields.io/github/stars/alexbakker/log4shell-tools.svg) ![forks](https://img.shields.io/github/forks/alexbakker/log4shell-tools.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/alexbakker/log4shell-tools](https://github.com/alexbakker/log4shell-tools) :  ![starts](https://img.shields.io/github/stars/alexbakker/log4shell-tools.svg) ![forks](https://img.shields.io/github/forks/alexbakker/log4shell-tools.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/12345qwert123456/CVE-2021-41773](https://github.com/12345qwert123456/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/12345qwert123456/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/12345qwert123456/CVE-2021-41773.svg)


## CVE-2021-4045
 TP-Link Tapo C200 IP camera, on its 1.1.15 firmware version and below, is affected by an unauthenticated RCE vulnerability, present in the uhttpd binary running by default as root. The exploitation of this vulnerability allows an attacker to take full control of the camera.

- [https://github.com/pl4int3xt/CVE-2021-4045](https://github.com/pl4int3xt/CVE-2021-4045) :  ![starts](https://img.shields.io/github/stars/pl4int3xt/CVE-2021-4045.svg) ![forks](https://img.shields.io/github/forks/pl4int3xt/CVE-2021-4045.svg)


## CVE-2021-3129
 Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.

- [https://github.com/Axianke/CVE-2021-3129](https://github.com/Axianke/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/Axianke/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/Axianke/CVE-2021-3129.svg)


## CVE-2020-1350
 A remote code execution vulnerability exists in Windows Domain Name System servers when they fail to properly handle requests, aka 'Windows DNS Server Remote Code Execution Vulnerability'.

- [https://github.com/connormcgarr/CVE-2020-1350](https://github.com/connormcgarr/CVE-2020-1350) :  ![starts](https://img.shields.io/github/stars/connormcgarr/CVE-2020-1350.svg) ![forks](https://img.shields.io/github/forks/connormcgarr/CVE-2020-1350.svg)
- [https://github.com/graph-inc/CVE-2020-1350](https://github.com/graph-inc/CVE-2020-1350) :  ![starts](https://img.shields.io/github/stars/graph-inc/CVE-2020-1350.svg) ![forks](https://img.shields.io/github/forks/graph-inc/CVE-2020-1350.svg)


## CVE-2018-15473
 OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user until after the packet containing the request has been fully parsed, related to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.

- [https://github.com/pyperanger/CVE-2018-15473_exploit](https://github.com/pyperanger/CVE-2018-15473_exploit) :  ![starts](https://img.shields.io/github/stars/pyperanger/CVE-2018-15473_exploit.svg) ![forks](https://img.shields.io/github/forks/pyperanger/CVE-2018-15473_exploit.svg)

