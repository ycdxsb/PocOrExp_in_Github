# Update 2025-02-03
## CVE-2025-24118
 The issue was addressed with improved memory handling. This issue is fixed in iPadOS 17.7.4, macOS Sequoia 15.3, macOS Sonoma 14.7.3. An app may be able to cause unexpected system termination or write kernel memory.

- [https://github.com/rawtips/-CVE-2025-24118](https://github.com/rawtips/-CVE-2025-24118) :  ![starts](https://img.shields.io/github/stars/rawtips/-CVE-2025-24118.svg) ![forks](https://img.shields.io/github/forks/rawtips/-CVE-2025-24118.svg)


## CVE-2025-0929
 SQL injection vulnerability in TeamCal Neo, version 3.8.2. This could allow an attacker to retrieve, update and delete all database information by injecting a malicious SQL statement via the ‘abs’ parameter in ‘/teamcal/src/index.php’.

- [https://github.com/McTavishSue/CVE-2025-0929](https://github.com/McTavishSue/CVE-2025-0929) :  ![starts](https://img.shields.io/github/stars/McTavishSue/CVE-2025-0929.svg) ![forks](https://img.shields.io/github/forks/McTavishSue/CVE-2025-0929.svg)


## CVE-2024-57514
 The TP-Link Archer A20 v3 router is vulnerable to Cross-site Scripting (XSS) due to improper handling of directory listing paths in the web interface. When a specially crafted URL is visited, the router's web page renders the directory listing and executes arbitrary JavaScript embedded in the URL. This allows the attacker to inject malicious code into the page, executing JavaScript on the victim's browser, which could then be used for further malicious actions. The vulnerability was identified in the 1.0.6 Build 20231011 rel.85717(5553) version.

- [https://github.com/rvizx/CVE-2024-57514](https://github.com/rvizx/CVE-2024-57514) :  ![starts](https://img.shields.io/github/stars/rvizx/CVE-2024-57514.svg) ![forks](https://img.shields.io/github/forks/rvizx/CVE-2024-57514.svg)


## CVE-2024-39123
 In janeczku Calibre-Web 0.6.0 to 0.6.21, the edit_book_comments function is vulnerable to Cross Site Scripting (XSS) due to improper sanitization performed by the clean_string function. The vulnerability arises from the way the clean_string function handles HTML sanitization.

- [https://github.com/FelinaeBlanc/CVE_2024_39123](https://github.com/FelinaeBlanc/CVE_2024_39123) :  ![starts](https://img.shields.io/github/stars/FelinaeBlanc/CVE_2024_39123.svg) ![forks](https://img.shields.io/github/forks/FelinaeBlanc/CVE_2024_39123.svg)


## CVE-2024-8381
 A potentially exploitable type confusion could be triggered when looking up a property name on an object being used as the `with` environment. This vulnerability affects Firefox  130, Firefox ESR  128.2, Firefox ESR  115.15, Thunderbird  128.2, and Thunderbird  115.15.

- [https://github.com/bjrjk/CVE-2024-8381](https://github.com/bjrjk/CVE-2024-8381) :  ![starts](https://img.shields.io/github/stars/bjrjk/CVE-2024-8381.svg) ![forks](https://img.shields.io/github/forks/bjrjk/CVE-2024-8381.svg)


## CVE-2024-6781
 Path traversal in Calibre = 7.14.0 allow unauthenticated attackers to achieve arbitrary file read.

- [https://github.com/FelinaeBlanc/CVE_2024_6781](https://github.com/FelinaeBlanc/CVE_2024_6781) :  ![starts](https://img.shields.io/github/stars/FelinaeBlanc/CVE_2024_6781.svg) ![forks](https://img.shields.io/github/forks/FelinaeBlanc/CVE_2024_6781.svg)


## CVE-2023-26326
 The BuddyForms WordPress plugin, in versions prior to 2.7.8, was affected by an unauthenticated insecure deserialization issue. An unauthenticated attacker could leverage this issue to call files using a PHAR wrapper that will deserialize the data and call arbitrary PHP Objects that can be used to perform a variety of malicious actions granted a POP chain is also present.

- [https://github.com/omarelshopky/exploit_cve-2023-26326_using_cve-2024-2961](https://github.com/omarelshopky/exploit_cve-2023-26326_using_cve-2024-2961) :  ![starts](https://img.shields.io/github/stars/omarelshopky/exploit_cve-2023-26326_using_cve-2024-2961.svg) ![forks](https://img.shields.io/github/forks/omarelshopky/exploit_cve-2023-26326_using_cve-2024-2961.svg)


## CVE-2023-6546
 A race condition was found in the GSM 0710 tty multiplexor in the Linux kernel. This issue occurs when two threads execute the GSMIOC_SETCONF ioctl on the same tty file descriptor with the gsm line discipline enabled, and can lead to a use-after-free problem on a struct gsm_dlci while restarting the gsm mux. This could allow a local unprivileged user to escalate their privileges on the system.

- [https://github.com/harithlab/CVE-2023-6546](https://github.com/harithlab/CVE-2023-6546) :  ![starts](https://img.shields.io/github/stars/harithlab/CVE-2023-6546.svg) ![forks](https://img.shields.io/github/forks/harithlab/CVE-2023-6546.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Plunder283/CVE-2021-41773](https://github.com/Plunder283/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Plunder283/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Plunder283/CVE-2021-41773.svg)


## CVE-2020-14882
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/Root-Shells/CVE-2020-14882](https://github.com/Root-Shells/CVE-2020-14882) :  ![starts](https://img.shields.io/github/stars/Root-Shells/CVE-2020-14882.svg) ![forks](https://img.shields.io/github/forks/Root-Shells/CVE-2020-14882.svg)

