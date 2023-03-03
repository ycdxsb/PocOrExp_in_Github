# Update 2023-03-03
## CVE-2023-23752
 An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

- [https://github.com/keyuan15/CVE-2023-23752](https://github.com/keyuan15/CVE-2023-23752) :  ![starts](https://img.shields.io/github/stars/keyuan15/CVE-2023-23752.svg) ![forks](https://img.shields.io/github/forks/keyuan15/CVE-2023-23752.svg)


## CVE-2023-22490
 Git is a revision control system. Using a specially-crafted repository, Git prior to versions 2.39.2, 2.38.4, 2.37.6, 2.36.5, 2.35.7, 2.34.7, 2.33.7, 2.32.6, 2.31.7, and 2.30.8 can be tricked into using its local clone optimization even when using a non-local transport. Though Git will abort local clones whose source `$GIT_DIR/objects` directory contains symbolic links, the `objects` directory itself may still be a symbolic link. These two may be combined to include arbitrary files based on known paths on the victim's filesystem within the malicious repository's working copy, allowing for data exfiltration in a similar manner as CVE-2022-39253. A fix has been prepared and will appear in v2.39.2 v2.38.4 v2.37.6 v2.36.5 v2.35.7 v2.34.7 v2.33.7 v2.32.6, v2.31.7 and v2.30.8. If upgrading is impractical, two short-term workarounds are available. Avoid cloning repositories from untrusted sources with `--recurse-submodules`. Instead, consider cloning repositories without recursively cloning their submodules, and instead run `git submodule update` at each layer. Before doing so, inspect each new `.gitmodules` file to ensure that it does not contain suspicious module URLs.

- [https://github.com/smash8tap/CVE-2023-22490_PoC](https://github.com/smash8tap/CVE-2023-22490_PoC) :  ![starts](https://img.shields.io/github/stars/smash8tap/CVE-2023-22490_PoC.svg) ![forks](https://img.shields.io/github/forks/smash8tap/CVE-2023-22490_PoC.svg)


## CVE-2022-46689
 A race condition was addressed with additional validation. This issue is fixed in tvOS 16.2, macOS Monterey 12.6.2, macOS Ventura 13.1, macOS Big Sur 11.7.2, iOS 15.7.2 and iPadOS 15.7.2, iOS 16.2 and iPadOS 16.2, watchOS 9.2. An app may be able to execute arbitrary code with kernel privileges.

- [https://github.com/enty8080/MacDirtyCow](https://github.com/enty8080/MacDirtyCow) :  ![starts](https://img.shields.io/github/stars/enty8080/MacDirtyCow.svg) ![forks](https://img.shields.io/github/forks/enty8080/MacDirtyCow.svg)


## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/hotblac/text4shell](https://github.com/hotblac/text4shell) :  ![starts](https://img.shields.io/github/stars/hotblac/text4shell.svg) ![forks](https://img.shields.io/github/forks/hotblac/text4shell.svg)


## CVE-2022-37434
 zlib through 1.2.12 has a heap-based buffer over-read or buffer overflow in inflate in inflate.c via a large gzip header extra field. NOTE: only applications that call inflateGetHeader are affected. Some common applications bundle the affected zlib source code but may be unable to call inflateGetHeader (e.g., see the nodejs/node reference).

- [https://github.com/nidhi7598/external_zlib-1.2.11_AOSP_10_r33_CVE-2022-37434](https://github.com/nidhi7598/external_zlib-1.2.11_AOSP_10_r33_CVE-2022-37434) :  ![starts](https://img.shields.io/github/stars/nidhi7598/external_zlib-1.2.11_AOSP_10_r33_CVE-2022-37434.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/external_zlib-1.2.11_AOSP_10_r33_CVE-2022-37434.svg)


## CVE-2022-31814
 pfSense pfBlockerNG through 2.1.4_26 allows remote attackers to execute arbitrary OS commands as root via shell metacharacters in the HTTP Host header. NOTE: 3.x is unaffected.

- [https://github.com/TheUnknownSoul/CVE-2022-31814](https://github.com/TheUnknownSoul/CVE-2022-31814) :  ![starts](https://img.shields.io/github/stars/TheUnknownSoul/CVE-2022-31814.svg) ![forks](https://img.shields.io/github/forks/TheUnknownSoul/CVE-2022-31814.svg)


## CVE-2022-25845
 The package com.alibaba:fastjson before 1.2.83 are vulnerable to Deserialization of Untrusted Data by bypassing the default autoType shutdown restrictions, which is possible under certain conditions. Exploiting this vulnerability allows attacking remote servers. Workaround: If upgrading is not possible, you can enable [safeMode](https://github.com/alibaba/fastjson/wiki/fastjson_safemode).

- [https://github.com/nerowander/CVE-2022-25845-exploit](https://github.com/nerowander/CVE-2022-25845-exploit) :  ![starts](https://img.shields.io/github/stars/nerowander/CVE-2022-25845-exploit.svg) ![forks](https://img.shields.io/github/forks/nerowander/CVE-2022-25845-exploit.svg)


## CVE-2022-22978
 In Spring Security versions 5.5.6 and 5.6.3 and older unsupported versions, RegexRequestMatcher can easily be misconfigured to be bypassed on some servlet containers. Applications using RegexRequestMatcher with `.` in the regular expression are possibly vulnerable to an authorization bypass

- [https://github.com/umakant76705/CVE-2022-22978](https://github.com/umakant76705/CVE-2022-22978) :  ![starts](https://img.shields.io/github/stars/umakant76705/CVE-2022-22978.svg) ![forks](https://img.shields.io/github/forks/umakant76705/CVE-2022-22978.svg)


## CVE-2022-22718
 Windows Print Spooler Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2022-21997, CVE-2022-21999, CVE-2022-22717.

- [https://github.com/ahmetfurkans/CVE-2022-22718](https://github.com/ahmetfurkans/CVE-2022-22718) :  ![starts](https://img.shields.io/github/stars/ahmetfurkans/CVE-2022-22718.svg) ![forks](https://img.shields.io/github/forks/ahmetfurkans/CVE-2022-22718.svg)


## CVE-2022-0337
 Inappropriate implementation in File System API in Google Chrome on Windows prior to 97.0.4692.71 allowed a remote attacker to obtain potentially sensitive information via a crafted HTML page. (Chrome security severity: High)

- [https://github.com/maldev866/ChExp-CVE-2022-0337-](https://github.com/maldev866/ChExp-CVE-2022-0337-) :  ![starts](https://img.shields.io/github/stars/maldev866/ChExp-CVE-2022-0337-.svg) ![forks](https://img.shields.io/github/forks/maldev866/ChExp-CVE-2022-0337-.svg)


## CVE-2021-3749
 axios is vulnerable to Inefficient Regular Expression Complexity

- [https://github.com/T-Guerrero/axios-redos](https://github.com/T-Guerrero/axios-redos) :  ![starts](https://img.shields.io/github/stars/T-Guerrero/axios-redos.svg) ![forks](https://img.shields.io/github/forks/T-Guerrero/axios-redos.svg)


## CVE-2021-3360
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/tcbutler320/CVE-2021-3360](https://github.com/tcbutler320/CVE-2021-3360) :  ![starts](https://img.shields.io/github/stars/tcbutler320/CVE-2021-3360.svg) ![forks](https://img.shields.io/github/forks/tcbutler320/CVE-2021-3360.svg)


## CVE-2020-2546
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Application Container - JavaEE). Supported versions that are affected are 10.3.6.0.0 and 12.1.3.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/hktalent/CVE_2020_2546](https://github.com/hktalent/CVE_2020_2546) :  ![starts](https://img.shields.io/github/stars/hktalent/CVE_2020_2546.svg) ![forks](https://img.shields.io/github/forks/hktalent/CVE_2020_2546.svg)


## CVE-2017-5638
 The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.

- [https://github.com/mritunjay-k/CVE-2017-5638](https://github.com/mritunjay-k/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/mritunjay-k/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/mritunjay-k/CVE-2017-5638.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka &quot;Dirty COW.&quot;

- [https://github.com/idhyt/androotzf](https://github.com/idhyt/androotzf) :  ![starts](https://img.shields.io/github/stars/idhyt/androotzf.svg) ![forks](https://img.shields.io/github/forks/idhyt/androotzf.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka &quot;ShellShock.&quot;  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/mritunjay-k/CVE-2014-6271](https://github.com/mritunjay-k/CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/mritunjay-k/CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/mritunjay-k/CVE-2014-6271.svg)

