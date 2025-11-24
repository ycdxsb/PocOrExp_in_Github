# Update 2025-11-24
## CVE-2025-48561
 In multiple locations, there is a possible way to access data displayed on the screen due to side channel information disclosure. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/combustible-trojan672/Pixnapping-Attack-on-Android](https://github.com/combustible-trojan672/Pixnapping-Attack-on-Android) :  ![starts](https://img.shields.io/github/stars/combustible-trojan672/Pixnapping-Attack-on-Android.svg) ![forks](https://img.shields.io/github/forks/combustible-trojan672/Pixnapping-Attack-on-Android.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927](https://github.com/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927.svg)


## CVE-2025-26633
 Improper neutralization in Microsoft Management Console allows an unauthorized attacker to bypass a security feature locally.

- [https://github.com/mbanyamer/MSC-EvilTwin-Local-Privilege-Escalation](https://github.com/mbanyamer/MSC-EvilTwin-Local-Privilege-Escalation) :  ![starts](https://img.shields.io/github/stars/mbanyamer/MSC-EvilTwin-Local-Privilege-Escalation.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/MSC-EvilTwin-Local-Privilege-Escalation.svg)


## CVE-2025-11001
The specific flaw exists within the handling of symbolic links in ZIP files. Crafted data in a ZIP file can cause the process to traverse to unintended directories. An attacker can leverage this vulnerability to execute code in the context of a service account. Was ZDI-CAN-26753.

- [https://github.com/ranasen-rat/CVE-2025-11001](https://github.com/ranasen-rat/CVE-2025-11001) :  ![starts](https://img.shields.io/github/stars/ranasen-rat/CVE-2025-11001.svg) ![forks](https://img.shields.io/github/forks/ranasen-rat/CVE-2025-11001.svg)
- [https://github.com/mbanyamer/CVE-2025-11001---7-Zip](https://github.com/mbanyamer/CVE-2025-11001---7-Zip) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2025-11001---7-Zip.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2025-11001---7-Zip.svg)


## CVE-2025-10230
 A flaw was found in Samba, in the front-end WINS hook handling: NetBIOS names from registration packets are passed to a shell without proper validation or escaping. Unsanitized NetBIOS name data from WINS registration packets are inserted into a shell command and executed by the Samba Active Directory Domain Controller’s wins hook, allowing an unauthenticated network attacker to achieve remote command execution as the Samba process.

- [https://github.com/nehkark/CVE-2025-10230](https://github.com/nehkark/CVE-2025-10230) :  ![starts](https://img.shields.io/github/stars/nehkark/CVE-2025-10230.svg) ![forks](https://img.shields.io/github/forks/nehkark/CVE-2025-10230.svg)


## CVE-2024-1071
 The Ultimate Member – User Profile, Registration, Login, Member Directory, Content Restriction & Membership Plugin plugin for WordPress is vulnerable to SQL Injection via the 'sorting' parameter in versions 2.1.3 to 2.8.2 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/dogucyber/WordPress-Exploit-CVE-2024-1071](https://github.com/dogucyber/WordPress-Exploit-CVE-2024-1071) :  ![starts](https://img.shields.io/github/stars/dogucyber/WordPress-Exploit-CVE-2024-1071.svg) ![forks](https://img.shields.io/github/forks/dogucyber/WordPress-Exploit-CVE-2024-1071.svg)


## CVE-2021-43267
 An issue was discovered in net/tipc/crypto.c in the Linux kernel before 5.14.16. The Transparent Inter-Process Communication (TIPC) functionality allows remote attackers to exploit insufficient validation of user-supplied sizes for the MSG_CRYPTO message type.

- [https://github.com/YunchoHang/CVE-2021-43267](https://github.com/YunchoHang/CVE-2021-43267) :  ![starts](https://img.shields.io/github/stars/YunchoHang/CVE-2021-43267.svg) ![forks](https://img.shields.io/github/forks/YunchoHang/CVE-2021-43267.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/ch4os443/CVE-2021-41773](https://github.com/ch4os443/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/ch4os443/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/ch4os443/CVE-2021-41773.svg)
- [https://github.com/RizqiSec/CVE-2021-41773](https://github.com/RizqiSec/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/RizqiSec/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/RizqiSec/CVE-2021-41773.svg)


## CVE-2017-16744
 A path traversal vulnerability in Tridium Niagara AX Versions 3.8 and prior and Niagara 4 systems Versions 4.4 and prior installed on Microsoft Windows Systems can be exploited by leveraging valid platform (administrator) credentials.

- [https://github.com/GainSec/CVE-2017-16744-and-CVE-2017-16748-Tridium-Niagara](https://github.com/GainSec/CVE-2017-16744-and-CVE-2017-16748-Tridium-Niagara) :  ![starts](https://img.shields.io/github/stars/GainSec/CVE-2017-16744-and-CVE-2017-16748-Tridium-Niagara.svg) ![forks](https://img.shields.io/github/forks/GainSec/CVE-2017-16744-and-CVE-2017-16748-Tridium-Niagara.svg)


## CVE-2017-7494
 Samba since version 3.5.0 and before 4.6.4, 4.5.10 and 4.4.14 is vulnerable to remote code execution vulnerability, allowing a malicious client to upload a shared library to a writable share, and then cause the server to load and execute it.

- [https://github.com/FelipeR-UFBA/cve-2017-7494-fixed](https://github.com/FelipeR-UFBA/cve-2017-7494-fixed) :  ![starts](https://img.shields.io/github/stars/FelipeR-UFBA/cve-2017-7494-fixed.svg) ![forks](https://img.shields.io/github/forks/FelipeR-UFBA/cve-2017-7494-fixed.svg)

