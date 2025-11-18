# Update 2025-11-18
## CVE-2025-64484
 OAuth2-Proxy is an open-source tool that can act as either a standalone reverse proxy or a middleware component integrated into existing reverse proxy or load balancer setups. In versions prior to 7.13.0, all deployments of OAuth2 Proxy in front of applications that normalize underscores to dashes in HTTP headers (e.g., WSGI-based frameworks such as Django, Flask, FastAPI, and PHP applications). Authenticated users can inject underscore variants of X-Forwarded-* headers that bypass the proxy’s filtering logic, potentially escalating privileges in the upstream app. OAuth2 Proxy authentication/authorization itself is not compromised. The problem has been patched with v7.13.0. By default all specified headers will now be normalized, meaning that both capitalization and the use of underscores (_) versus dashes (-) will be ignored when matching headers to be stripped. For example, both `X-Forwarded-For` and `X_Forwarded-for` will now be treated as equivalent and stripped away. For those who have a rational that requires keeping a similar looking header and not stripping it, the maintainers introduced a new configuration field for Headers managed through the AlphaConfig called `InsecureSkipHeaderNormalization`. As a workaround, ensure filtering and processing logic in upstream services don't treat underscores and hyphens in Headers the same way.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-64484](https://github.com/B1ack4sh/Blackash-CVE-2025-64484) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-64484.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-64484.svg)


## CVE-2025-62950
 Cross-Site Request Forgery (CSRF) vulnerability in Wasiliy Strecker / ContestGallery developer Contest Gallery contest-gallery allows Cross Site Request Forgery.This issue affects Contest Gallery: from n/a through = 28.0.0.

- [https://github.com/lorenzocamilli/CVE-2025-62950-PoC](https://github.com/lorenzocamilli/CVE-2025-62950-PoC) :  ![starts](https://img.shields.io/github/stars/lorenzocamilli/CVE-2025-62950-PoC.svg) ![forks](https://img.shields.io/github/forks/lorenzocamilli/CVE-2025-62950-PoC.svg)


## CVE-2025-62220
 Heap-based buffer overflow in Windows Subsystem for Linux GUI allows an unauthorized attacker to execute code over a network.

- [https://github.com/callinston/CVE-2025-62220](https://github.com/callinston/CVE-2025-62220) :  ![starts](https://img.shields.io/github/stars/callinston/CVE-2025-62220.svg) ![forks](https://img.shields.io/github/forks/callinston/CVE-2025-62220.svg)


## CVE-2025-59287
 Deserialization of untrusted data in Windows Server Update Service allows an unauthorized attacker to execute code over a network.

- [https://github.com/M507/CVE-2025-59287-PoC](https://github.com/M507/CVE-2025-59287-PoC) :  ![starts](https://img.shields.io/github/stars/M507/CVE-2025-59287-PoC.svg) ![forks](https://img.shields.io/github/forks/M507/CVE-2025-59287-PoC.svg)


## CVE-2025-48060
 jq is a command-line JSON processor. In versions up to and including 1.7.1, a heap-buffer-overflow is present in function `jv_string_vfmt` in the jq_fuzz_execute harness from oss-fuzz. This crash happens on file jv.c, line 1456 `void* p = malloc(sz);`. As of time of publication, no patched versions are available.

- [https://github.com/leorivass/jq-els-backport-cve-2025-48060](https://github.com/leorivass/jq-els-backport-cve-2025-48060) :  ![starts](https://img.shields.io/github/stars/leorivass/jq-els-backport-cve-2025-48060.svg) ![forks](https://img.shields.io/github/forks/leorivass/jq-els-backport-cve-2025-48060.svg)


## CVE-2025-40019
it's also checked for decryption and in-place encryption.

- [https://github.com/guard-wait/CVE-2025-40019_POC](https://github.com/guard-wait/CVE-2025-40019_POC) :  ![starts](https://img.shields.io/github/stars/guard-wait/CVE-2025-40019_POC.svg) ![forks](https://img.shields.io/github/forks/guard-wait/CVE-2025-40019_POC.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/ankitpandey383/CVE-2025-32463-Sudo-Privilege-Escalation](https://github.com/ankitpandey383/CVE-2025-32463-Sudo-Privilege-Escalation) :  ![starts](https://img.shields.io/github/stars/ankitpandey383/CVE-2025-32463-Sudo-Privilege-Escalation.svg) ![forks](https://img.shields.io/github/forks/ankitpandey383/CVE-2025-32463-Sudo-Privilege-Escalation.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/Grand-Moomin/Vuln-Next.js-CVE-2025-29927](https://github.com/Grand-Moomin/Vuln-Next.js-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/Grand-Moomin/Vuln-Next.js-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/Grand-Moomin/Vuln-Next.js-CVE-2025-29927.svg)
- [https://github.com/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927](https://github.com/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927.svg)


## CVE-2025-21479
 Memory corruption due to unauthorized command execution in GPU micronode while executing specific sequence of commands.

- [https://github.com/sarabpal-dev/cheese-cake](https://github.com/sarabpal-dev/cheese-cake) :  ![starts](https://img.shields.io/github/stars/sarabpal-dev/cheese-cake.svg) ![forks](https://img.shields.io/github/forks/sarabpal-dev/cheese-cake.svg)


## CVE-2025-13188
 A vulnerability was detected in D-Link DIR-816L 2_06_b09_beta. Affected by this vulnerability is the function authenticationcgi_main of the file /authentication.cgi. Performing manipulation of the argument Password results in stack-based buffer overflow. Remote exploitation of the attack is possible. The exploit is now public and may be used. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/degeneration1973/CVE-2025-13188-Exploit](https://github.com/degeneration1973/CVE-2025-13188-Exploit) :  ![starts](https://img.shields.io/github/stars/degeneration1973/CVE-2025-13188-Exploit.svg) ![forks](https://img.shields.io/github/forks/degeneration1973/CVE-2025-13188-Exploit.svg)


## CVE-2025-10720
 The WP Private Content Plus through 3.6.2 provides a global content protection feature that requires a password. However, the access control check is based only on the presence of an unprotected client-side cookie. As a result, an unauthenticated attacker can completely bypass the password protection by manually setting the cookie value in their browser.

- [https://github.com/lorenzocamilli/CVE-2025-62950-PoC](https://github.com/lorenzocamilli/CVE-2025-62950-PoC) :  ![starts](https://img.shields.io/github/stars/lorenzocamilli/CVE-2025-62950-PoC.svg) ![forks](https://img.shields.io/github/forks/lorenzocamilli/CVE-2025-62950-PoC.svg)


## CVE-2025-6085
 The Make Connector plugin for WordPress is vulnerable to arbitrary file uploads due to misconfigured file type validation in the 'upload_media' function in all versions up to, and including, 1.5.10. This makes it possible for authenticated attackers, with Administrator-level access and above, to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/K0n9-log/CVE-2025-60854](https://github.com/K0n9-log/CVE-2025-60854) :  ![starts](https://img.shields.io/github/stars/K0n9-log/CVE-2025-60854.svg) ![forks](https://img.shields.io/github/forks/K0n9-log/CVE-2025-60854.svg)


## CVE-2025-5777
 Insufficient input validation leading to memory overread when the NetScaler is configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server

- [https://github.com/mr-r3b00t/CVE-2025-5777](https://github.com/mr-r3b00t/CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/mr-r3b00t/CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/mr-r3b00t/CVE-2025-5777.svg)


## CVE-2025-5432
 A vulnerability has been found in AssamLook CMS 1.0 and classified as critical. Affected by this vulnerability is an unknown functionality of the file /view_tender.php. The manipulation of the argument ID leads to sql injection. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/saykino/CVE-2025-54320](https://github.com/saykino/CVE-2025-54320) :  ![starts](https://img.shields.io/github/stars/saykino/CVE-2025-54320.svg) ![forks](https://img.shields.io/github/forks/saykino/CVE-2025-54320.svg)
- [https://github.com/saykino/CVE-2025-54321](https://github.com/saykino/CVE-2025-54321) :  ![starts](https://img.shields.io/github/stars/saykino/CVE-2025-54321.svg) ![forks](https://img.shields.io/github/forks/saykino/CVE-2025-54321.svg)


## CVE-2025-4859
 A vulnerability was found in D-Link DAP-2695 120b36r137_ALL_en_20210528. It has been rated as problematic. This issue affects some unknown processing of the file /adv_macbypass.php of the component MAC Bypass Settings Page. The manipulation of the argument f_mac leads to cross site scripting. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. Other parameters might be affected as well. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/rana3333s/CVE-2025-48593](https://github.com/rana3333s/CVE-2025-48593) :  ![starts](https://img.shields.io/github/stars/rana3333s/CVE-2025-48593.svg) ![forks](https://img.shields.io/github/forks/rana3333s/CVE-2025-48593.svg)


## CVE-2024-23828
 Nginx-UI is a web interface to manage Nginx configurations. It is vulnerable to an authenticated arbitrary command execution via CRLF attack when changing the value of test_config_cmd or start_cmd. This vulnerability exists due to an incomplete fix for CVE-2024-22197 and CVE-2024-22198. This vulnerability has been patched in version 2.0.0.beta.12.

- [https://github.com/oxagast/oxasploits](https://github.com/oxagast/oxasploits) :  ![starts](https://img.shields.io/github/stars/oxagast/oxasploits.svg) ![forks](https://img.shields.io/github/forks/oxagast/oxasploits.svg)


## CVE-2024-2873
 A vulnerability was found in wolfSSH's server-side state machine before versions 1.4.17. A malicious client could create channels without first performing user authentication, resulting in unauthorized access.

- [https://github.com/stuxbench/dropbear-cve-2024-2873](https://github.com/stuxbench/dropbear-cve-2024-2873) :  ![starts](https://img.shields.io/github/stars/stuxbench/dropbear-cve-2024-2873.svg) ![forks](https://img.shields.io/github/forks/stuxbench/dropbear-cve-2024-2873.svg)


## CVE-2024-0670
 Privilege escalation in windows agent plugin in Checkmk before 2.2.0p23, 2.1.0p40 and 2.0.0 (EOL) allows local user to escalate privileges

- [https://github.com/elsevar11/CVE-2024-0670-CheckMK-Agent-Local-Privilege-Escalation-Exploit](https://github.com/elsevar11/CVE-2024-0670-CheckMK-Agent-Local-Privilege-Escalation-Exploit) :  ![starts](https://img.shields.io/github/stars/elsevar11/CVE-2024-0670-CheckMK-Agent-Local-Privilege-Escalation-Exploit.svg) ![forks](https://img.shields.io/github/forks/elsevar11/CVE-2024-0670-CheckMK-Agent-Local-Privilege-Escalation-Exploit.svg)
- [https://github.com/magicrc/CVE-2024-0670](https://github.com/magicrc/CVE-2024-0670) :  ![starts](https://img.shields.io/github/stars/magicrc/CVE-2024-0670.svg) ![forks](https://img.shields.io/github/forks/magicrc/CVE-2024-0670.svg)


## CVE-2023-48251
 The vulnerability allows a remote attacker to authenticate to the SSH service with root privileges through a hidden hard-coded account.

- [https://github.com/oxagast/oxasploits](https://github.com/oxagast/oxasploits) :  ![starts](https://img.shields.io/github/stars/oxagast/oxasploits.svg) ![forks](https://img.shields.io/github/forks/oxagast/oxasploits.svg)


## CVE-2023-38941
 django-sspanel v2022.2.2 was discovered to contain a remote command execution (RCE) vulnerability via the component sspanel/admin_view.py - GoodsCreateView._post.

- [https://github.com/oxagast/oxasploits](https://github.com/oxagast/oxasploits) :  ![starts](https://img.shields.io/github/stars/oxagast/oxasploits.svg) ![forks](https://img.shields.io/github/forks/oxagast/oxasploits.svg)


## CVE-2023-2598
 A flaw was found in the fixed buffer registration code for io_uring (io_sqe_buffer_register in io_uring/rsrc.c) in the Linux kernel that allows out-of-bounds access to physical memory beyond the end of the buffer. This flaw enables full local privilege escalation.

- [https://github.com/guard-wait/CVE-2023-2598_EXP](https://github.com/guard-wait/CVE-2023-2598_EXP) :  ![starts](https://img.shields.io/github/stars/guard-wait/CVE-2023-2598_EXP.svg) ![forks](https://img.shields.io/github/forks/guard-wait/CVE-2023-2598_EXP.svg)


## CVE-2022-21587
 Vulnerability in the Oracle Web Applications Desktop Integrator product of Oracle E-Business Suite (component: Upload). Supported versions that are affected are 12.2.3-12.2.11. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Web Applications Desktop Integrator. Successful attacks of this vulnerability can result in takeover of Oracle Web Applications Desktop Integrator. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/merlyn-1/CVE-2022-21587-Oracle-EBS](https://github.com/merlyn-1/CVE-2022-21587-Oracle-EBS) :  ![starts](https://img.shields.io/github/stars/merlyn-1/CVE-2022-21587-Oracle-EBS.svg) ![forks](https://img.shields.io/github/forks/merlyn-1/CVE-2022-21587-Oracle-EBS.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/honeyvig/CVE-2022-0847-DirtyPipe-Exploit](https://github.com/honeyvig/CVE-2022-0847-DirtyPipe-Exploit) :  ![starts](https://img.shields.io/github/stars/honeyvig/CVE-2022-0847-DirtyPipe-Exploit.svg) ![forks](https://img.shields.io/github/forks/honeyvig/CVE-2022-0847-DirtyPipe-Exploit.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/honypot/CVE-2021-41773](https://github.com/honypot/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/honypot/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/honypot/CVE-2021-41773.svg)


## CVE-2021-3560
 It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user. This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/oxagast/oxasploits](https://github.com/oxagast/oxasploits) :  ![starts](https://img.shields.io/github/stars/oxagast/oxasploits.svg) ![forks](https://img.shields.io/github/forks/oxagast/oxasploits.svg)


## CVE-2019-15947
 In Bitcoin Core 0.18.0, bitcoin-qt stores wallet.dat data unencrypted in memory. Upon a crash, it may dump a core file. If a user were to mishandle a core file, an attacker can reconstruct the user's wallet.dat file, including their private keys, via a grep "6231 0500" command.

- [https://github.com/oxagast/oxasploits](https://github.com/oxagast/oxasploits) :  ![starts](https://img.shields.io/github/stars/oxagast/oxasploits.svg) ![forks](https://img.shields.io/github/forks/oxagast/oxasploits.svg)


## CVE-2019-12881
 i915_gem_userptr_get_pages in drivers/gpu/drm/i915/i915_gem_userptr.c in the Linux kernel 4.15.0 on Ubuntu 18.04.2 allows local users to cause a denial of service (NULL pointer dereference and BUG) or possibly have unspecified other impact via crafted ioctl calls to /dev/dri/card0.

- [https://github.com/oxagast/oxasploits](https://github.com/oxagast/oxasploits) :  ![starts](https://img.shields.io/github/stars/oxagast/oxasploits.svg) ![forks](https://img.shields.io/github/forks/oxagast/oxasploits.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/Perseus99999/CVE-2019-9053-working-](https://github.com/Perseus99999/CVE-2019-9053-working-) :  ![starts](https://img.shields.io/github/stars/Perseus99999/CVE-2019-9053-working-.svg) ![forks](https://img.shields.io/github/forks/Perseus99999/CVE-2019-9053-working-.svg)


## CVE-2018-17336
 UDisks 2.8.0 has a format string vulnerability in udisks_log in udiskslogging.c, allowing attackers to obtain sensitive information (stack contents), cause a denial of service (memory corruption), or possibly have unspecified other impact via a malformed filesystem label, as demonstrated by %d or %n substrings.

- [https://github.com/oxagast/oxasploits](https://github.com/oxagast/oxasploits) :  ![starts](https://img.shields.io/github/stars/oxagast/oxasploits.svg) ![forks](https://img.shields.io/github/forks/oxagast/oxasploits.svg)


## CVE-2017-12615
 When running Apache Tomcat 7.0.0 to 7.0.79 on Windows with HTTP PUTs enabled (e.g. via setting the readonly initialisation parameter of the Default to false) it was possible to upload a JSP file to the server via a specially crafted request. This JSP could then be requested and any code it contained would be executed by the server.

- [https://github.com/netw0rk7/CVE-2017-12615-Home-Lab](https://github.com/netw0rk7/CVE-2017-12615-Home-Lab) :  ![starts](https://img.shields.io/github/stars/netw0rk7/CVE-2017-12615-Home-Lab.svg) ![forks](https://img.shields.io/github/forks/netw0rk7/CVE-2017-12615-Home-Lab.svg)


## CVE-2017-5816
 A Remote Code Execution vulnerability in HPE Intelligent Management Center (iMC) PLAT version 7.3 E0504P04 was found.

- [https://github.com/oxagast/oxasploits](https://github.com/oxagast/oxasploits) :  ![starts](https://img.shields.io/github/stars/oxagast/oxasploits.svg) ![forks](https://img.shields.io/github/forks/oxagast/oxasploits.svg)


## CVE-2016-10401
 ZyXEL PK5001Z devices have zyad5001 as the su password, which makes it easier for remote attackers to obtain root access if a non-root account password is known (or a non-root default account exists within an ISP's deployment of these devices).

- [https://github.com/oxagast/oxasploits](https://github.com/oxagast/oxasploits) :  ![starts](https://img.shields.io/github/stars/oxagast/oxasploits.svg) ![forks](https://img.shields.io/github/forks/oxagast/oxasploits.svg)


## CVE-2015-3306
 The mod_copy module in ProFTPD 1.3.5 allows remote attackers to read and write to arbitrary files via the site cpfr and site cpto commands.

- [https://github.com/netw0rk7/CVE-2015-3306-Home-Lab](https://github.com/netw0rk7/CVE-2015-3306-Home-Lab) :  ![starts](https://img.shields.io/github/stars/netw0rk7/CVE-2015-3306-Home-Lab.svg) ![forks](https://img.shields.io/github/forks/netw0rk7/CVE-2015-3306-Home-Lab.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/indrajeetmp11/Heartbleed-PoC-Exploit-Script](https://github.com/indrajeetmp11/Heartbleed-PoC-Exploit-Script) :  ![starts](https://img.shields.io/github/stars/indrajeetmp11/Heartbleed-PoC-Exploit-Script.svg) ![forks](https://img.shields.io/github/forks/indrajeetmp11/Heartbleed-PoC-Exploit-Script.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/avivyap/CVE-2011-2523](https://github.com/avivyap/CVE-2011-2523) :  ![starts](https://img.shields.io/github/stars/avivyap/CVE-2011-2523.svg) ![forks](https://img.shields.io/github/forks/avivyap/CVE-2011-2523.svg)

