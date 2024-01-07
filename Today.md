# Update 2024-01-07
## CVE-2023-51764
 Postfix through 3.8.4 allows SMTP smuggling unless configured with smtpd_data_restrictions=reject_unauth_pipelining and smtpd_discard_ehlo_keywords=chunking (or certain other options that exist in recent versions). Remote attackers can use a published exploitation technique to inject e-mail messages with a spoofed MAIL FROM address, allowing bypass of an SPF protection mechanism. This occurs because Postfix supports &lt;LF&gt;.&lt;CR&gt;&lt;LF&gt; but some other popular e-mail servers do not. To prevent attack variants (by always disallowing &lt;LF&gt; without &lt;CR&gt;), a different solution is required: the smtpd_forbid_bare_newline=yes option with a Postfix minimum version of 3.5.23, 3.6.13, 3.7.9, 3.8.4, or 3.9.

- [https://github.com/Double-q1015/CVE-2023-51764](https://github.com/Double-q1015/CVE-2023-51764) :  ![starts](https://img.shields.io/github/stars/Double-q1015/CVE-2023-51764.svg) ![forks](https://img.shields.io/github/forks/Double-q1015/CVE-2023-51764.svg)


## CVE-2023-51467
 The vulnerability allows attackers to bypass authentication to achieve a simple Server-Side Request Forgery (SSRF)

- [https://github.com/JaneMandy/CVE-2023-51467-Exploit](https://github.com/JaneMandy/CVE-2023-51467-Exploit) :  ![starts](https://img.shields.io/github/stars/JaneMandy/CVE-2023-51467-Exploit.svg) ![forks](https://img.shields.io/github/forks/JaneMandy/CVE-2023-51467-Exploit.svg)


## CVE-2023-40084
 In run of MDnsSdListener.cpp, there is a possible memory corruption due to a use after free. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/Trinadh465/platform_system_netd_AOSP10_r33_CVE-2023-40084](https://github.com/Trinadh465/platform_system_netd_AOSP10_r33_CVE-2023-40084) :  ![starts](https://img.shields.io/github/stars/Trinadh465/platform_system_netd_AOSP10_r33_CVE-2023-40084.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/platform_system_netd_AOSP10_r33_CVE-2023-40084.svg)


## CVE-2021-45067
 Acrobat Reader DC version 21.007.20099 (and earlier), 20.004.30017 (and earlier) and 17.011.30204 (and earlier) are affected by an Access of Memory Location After End of Buffer vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/hacksysteam/CVE-2021-45067](https://github.com/hacksysteam/CVE-2021-45067) :  ![starts](https://img.shields.io/github/stars/hacksysteam/CVE-2021-45067.svg) ![forks](https://img.shields.io/github/forks/hacksysteam/CVE-2021-45067.svg)


## CVE-2021-3490
 The eBPF ALU32 bounds tracking for bitwise ops (AND, OR and XOR) in the Linux kernel did not properly update 32-bit bounds, which could be turned into out of bounds reads and writes in the Linux kernel and therefore, arbitrary code execution. This issue was fixed via commit 049c4e13714e (&quot;bpf: Fix alu32 const subreg bound tracking on bitwise operations&quot;) (v5.13-rc4) and backported to the stable kernels in v5.12.4, v5.11.21, and v5.10.37. The AND/OR issues were introduced by commit 3f50f132d840 (&quot;bpf: Verifier, do explicit ALU32 bounds tracking&quot;) (5.7-rc1) and the XOR variant was introduced by 2921c90d4718 (&quot;bpf:Fix a verifier failure with xor&quot;) ( 5.10-rc1).

- [https://github.com/pivik271/CVE-2021-3490](https://github.com/pivik271/CVE-2021-3490) :  ![starts](https://img.shields.io/github/stars/pivik271/CVE-2021-3490.svg) ![forks](https://img.shields.io/github/forks/pivik271/CVE-2021-3490.svg)


## CVE-2021-3129
 Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.

- [https://github.com/idea-oss/laravel-CVE-2021-3129-EXP](https://github.com/idea-oss/laravel-CVE-2021-3129-EXP) :  ![starts](https://img.shields.io/github/stars/idea-oss/laravel-CVE-2021-3129-EXP.svg) ![forks](https://img.shields.io/github/forks/idea-oss/laravel-CVE-2021-3129-EXP.svg)


## CVE-2020-25272
 In SourceCodester Online Bus Booking System 1.0, there is XSS through the name parameter in book_now.php.

- [https://github.com/Ko-kn3t/CVE-2020-25272](https://github.com/Ko-kn3t/CVE-2020-25272) :  ![starts](https://img.shields.io/github/stars/Ko-kn3t/CVE-2020-25272.svg) ![forks](https://img.shields.io/github/forks/Ko-kn3t/CVE-2020-25272.svg)


## CVE-2018-18778
 ACME mini_httpd before 1.30 lets remote users read arbitrary files.

- [https://github.com/auk0x01/CVE-2018-18778-Scanner](https://github.com/auk0x01/CVE-2018-18778-Scanner) :  ![starts](https://img.shields.io/github/stars/auk0x01/CVE-2018-18778-Scanner.svg) ![forks](https://img.shields.io/github/forks/auk0x01/CVE-2018-18778-Scanner.svg)


## CVE-2017-1000117
 A malicious third-party can give a crafted &quot;ssh://...&quot; URL to an unsuspecting victim, and an attempt to visit the URL can result in any program that exists on the victim's machine being executed. Such a URL could be placed in the .gitmodules file of a malicious project, and an unsuspecting victim could be tricked into running &quot;git clone --recurse-submodules&quot; to trigger the vulnerability.

- [https://github.com/thelastbyte/CVE-2017-1000117](https://github.com/thelastbyte/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/thelastbyte/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/thelastbyte/CVE-2017-1000117.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/BelminD/heartbleed](https://github.com/BelminD/heartbleed) :  ![starts](https://img.shields.io/github/stars/BelminD/heartbleed.svg) ![forks](https://img.shields.io/github/forks/BelminD/heartbleed.svg)
- [https://github.com/siddolo/knockbleed](https://github.com/siddolo/knockbleed) :  ![starts](https://img.shields.io/github/stars/siddolo/knockbleed.svg) ![forks](https://img.shields.io/github/forks/siddolo/knockbleed.svg)
- [https://github.com/iSCInc/heartbleed](https://github.com/iSCInc/heartbleed) :  ![starts](https://img.shields.io/github/stars/iSCInc/heartbleed.svg) ![forks](https://img.shields.io/github/forks/iSCInc/heartbleed.svg)


## CVE-2012-2122
 sql/password.c in Oracle MySQL 5.1.x before 5.1.63, 5.5.x before 5.5.24, and 5.6.x before 5.6.6, and MariaDB 5.1.x before 5.1.62, 5.2.x before 5.2.12, 5.3.x before 5.3.6, and 5.5.x before 5.5.23, when running in certain environments with certain implementations of the memcmp function, allows remote attackers to bypass authentication by repeatedly authenticating with the same incorrect password, which eventually causes a token comparison to succeed due to an improperly-checked return value.

- [https://github.com/Avinza/CVE-2012-2122-scanner](https://github.com/Avinza/CVE-2012-2122-scanner) :  ![starts](https://img.shields.io/github/stars/Avinza/CVE-2012-2122-scanner.svg) ![forks](https://img.shields.io/github/forks/Avinza/CVE-2012-2122-scanner.svg)

