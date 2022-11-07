# Update 2022-11-07
## CVE-2022-43144
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/mudassiruddin/CVE-2022-43144-Stored-XSS](https://github.com/mudassiruddin/CVE-2022-43144-Stored-XSS) :  ![starts](https://img.shields.io/github/stars/mudassiruddin/CVE-2022-43144-Stored-XSS.svg) ![forks](https://img.shields.io/github/forks/mudassiruddin/CVE-2022-43144-Stored-XSS.svg)


## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/QAInsights/cve-2022-42889-jmeter](https://github.com/QAInsights/cve-2022-42889-jmeter) :  ![starts](https://img.shields.io/github/stars/QAInsights/cve-2022-42889-jmeter.svg) ![forks](https://img.shields.io/github/forks/QAInsights/cve-2022-42889-jmeter.svg)
- [https://github.com/sunnyvale-it/CVE-2022-42889-PoC](https://github.com/sunnyvale-it/CVE-2022-42889-PoC) :  ![starts](https://img.shields.io/github/stars/sunnyvale-it/CVE-2022-42889-PoC.svg) ![forks](https://img.shields.io/github/forks/sunnyvale-it/CVE-2022-42889-PoC.svg)


## CVE-2022-36067
 vm2 is a sandbox that can run untrusted code with whitelisted Node's built-in modules. In versions prior to version 3.9.11, a threat actor can bypass the sandbox protections to gain remote code execution rights on the host running the sandbox. This vulnerability was patched in the release of version 3.9.11 of vm2. There are no known workarounds.

- [https://github.com/Prathamrajgor/Exploit-For-CVE-2022-36067](https://github.com/Prathamrajgor/Exploit-For-CVE-2022-36067) :  ![starts](https://img.shields.io/github/stars/Prathamrajgor/Exploit-For-CVE-2022-36067.svg) ![forks](https://img.shields.io/github/forks/Prathamrajgor/Exploit-For-CVE-2022-36067.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/wolf1892/CVE-2021-41773](https://github.com/wolf1892/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/wolf1892/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/wolf1892/CVE-2021-41773.svg)
- [https://github.com/honypot/CVE-2021-41773](https://github.com/honypot/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/honypot/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/honypot/CVE-2021-41773.svg)
- [https://github.com/hab1b0x/CVE-2021-41773](https://github.com/hab1b0x/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/hab1b0x/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/hab1b0x/CVE-2021-41773.svg)


## CVE-2021-33624
 In kernel/bpf/verifier.c in the Linux kernel before 5.12.13, a branch can be mispredicted (e.g., because of type confusion) and consequently an unprivileged BPF program can read arbitrary memory locations via a side-channel attack, aka CID-9183671af6db.

- [https://github.com/benschlueter/CVE-2021-33624](https://github.com/benschlueter/CVE-2021-33624) :  ![starts](https://img.shields.io/github/stars/benschlueter/CVE-2021-33624.svg) ![forks](https://img.shields.io/github/forks/benschlueter/CVE-2021-33624.svg)


## CVE-2021-29447
 Wordpress is an open source CMS. A user with the ability to upload files (like an Author) can exploit an XML parsing issue in the Media Library leading to XXE attacks. This requires WordPress installation to be using PHP 8. Access to internal files is possible in a successful XXE attack. This has been patched in WordPress version 5.7.1, along with the older affected versions via a minor release. We strongly recommend you keep auto-updates enabled.

- [https://github.com/b-abderrahmane/CVE-2021-29447-POC](https://github.com/b-abderrahmane/CVE-2021-29447-POC) :  ![starts](https://img.shields.io/github/stars/b-abderrahmane/CVE-2021-29447-POC.svg) ![forks](https://img.shields.io/github/forks/b-abderrahmane/CVE-2021-29447-POC.svg)
- [https://github.com/akhils911dev/blind-xxe-controller-CVE-2021-29447](https://github.com/akhils911dev/blind-xxe-controller-CVE-2021-29447) :  ![starts](https://img.shields.io/github/stars/akhils911dev/blind-xxe-controller-CVE-2021-29447.svg) ![forks](https://img.shields.io/github/forks/akhils911dev/blind-xxe-controller-CVE-2021-29447.svg)


## CVE-2021-29155
 An issue was discovered in the Linux kernel through 5.11.x. kernel/bpf/verifier.c performs undesirable out-of-bounds speculation on pointer arithmetic, leading to side-channel attacks that defeat Spectre mitigations and obtain sensitive information from kernel memory. Specifically, for sequences of pointer arithmetic operations, the pointer modification performed by the first operation is not correctly accounted for when restricting subsequent operations.

- [https://github.com/benschlueter/CVE-2021-29155](https://github.com/benschlueter/CVE-2021-29155) :  ![starts](https://img.shields.io/github/stars/benschlueter/CVE-2021-29155.svg) ![forks](https://img.shields.io/github/forks/benschlueter/CVE-2021-29155.svg)


## CVE-2020-8515
 DrayTek Vigor2960 1.3.1_Beta, Vigor3900 1.4.4_Beta, and Vigor300B 1.3.3_Beta, 1.4.2.1_Beta, and 1.4.4_Beta devices allow remote code execution as root (without authentication) via shell metacharacters to the cgi-bin/mainfunction.cgi URI. This issue has been fixed in Vigor3900/2960/300B v1.5.1.

- [https://github.com/trhacknon/CVE-2020-8515](https://github.com/trhacknon/CVE-2020-8515) :  ![starts](https://img.shields.io/github/stars/trhacknon/CVE-2020-8515.svg) ![forks](https://img.shields.io/github/forks/trhacknon/CVE-2020-8515.svg)


## CVE-2018-6389
 In WordPress through 4.9.2, unauthenticated attackers can cause a denial of service (resource consumption) by using the large list of registered .js files (from wp-includes/script-loader.php) to construct a series of requests to load every file many times.

- [https://github.com/m3ssap0/wordpress_cve-2018-6389](https://github.com/m3ssap0/wordpress_cve-2018-6389) :  ![starts](https://img.shields.io/github/stars/m3ssap0/wordpress_cve-2018-6389.svg) ![forks](https://img.shields.io/github/forks/m3ssap0/wordpress_cve-2018-6389.svg)
- [https://github.com/Adelittle/Wordpressz_Dos_CVE_2018_6389](https://github.com/Adelittle/Wordpressz_Dos_CVE_2018_6389) :  ![starts](https://img.shields.io/github/stars/Adelittle/Wordpressz_Dos_CVE_2018_6389.svg) ![forks](https://img.shields.io/github/forks/Adelittle/Wordpressz_Dos_CVE_2018_6389.svg)


## CVE-2017-5674
 A vulnerability in a custom-built GoAhead web server used on Foscam, Vstarcam, and multiple white-label IP camera models allows an attacker to craft a malformed HTTP (&quot;GET system.ini HTTP/1.1\n\n&quot; - note the lack of &quot;/&quot; in the path field of the request) request that will disclose the configuration file with the login password.

- [https://github.com/eR072391/cve-2017-5674](https://github.com/eR072391/cve-2017-5674) :  ![starts](https://img.shields.io/github/stars/eR072391/cve-2017-5674.svg) ![forks](https://img.shields.io/github/forks/eR072391/cve-2017-5674.svg)

