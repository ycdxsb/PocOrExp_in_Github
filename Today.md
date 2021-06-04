# Update 2021-06-04
## CVE-2021-33200
 kernel/bpf/verifier.c in the Linux kernel through 5.12.7 enforces incorrect limits for pointer arithmetic operations, aka CID-bb01a1bba579. This can be abused to perform out-of-bounds reads and writes in kernel memory, leading to local privilege escalation to root. In particular, there is a corner case where the off reg causes a masking direction change, which then results in an incorrect final aux-&gt;alu_limit.

- [https://github.com/JamesGeee/CVE-2021-33200](https://github.com/JamesGeee/CVE-2021-33200) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-33200.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-33200.svg)


## CVE-2021-32625
 Redis is an open source (BSD licensed), in-memory data structure store, used as a database, cache, and message broker. An integer overflow bug in Redis version 6.0 or newer (on 32-bit systems ONLY) can be exploited using the `STRALGO LCS` command to corrupt the heap and potentially result with remote code execution. This is a result of an incomplete fix for CVE-2021-29477 which only addresses the problem on 64-bit systems but fails to do that for 32-bit. 64-bit systems are not affected. The problem is fixed in version 6.2.4 and 6.0.14. An additional workaround to mitigate the problem without patching the `redis-server` executable is to use ACL configuration to prevent clients from using the `STRALGO LCS` command.

- [https://github.com/JamesGeee/CVE-2021-32625](https://github.com/JamesGeee/CVE-2021-32625) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-32625.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-32625.svg)


## CVE-2021-29670
 IBM Jazz Foundation and IBM Engineering products are vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 199408.

- [https://github.com/JamesGeee/CVE-2021-29670](https://github.com/JamesGeee/CVE-2021-29670) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-29670.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-29670.svg)


## CVE-2021-29668
 IBM Jazz Foundation and IBM Engineering products are vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 199406.

- [https://github.com/JamesGeee/CVE-2021-29668](https://github.com/JamesGeee/CVE-2021-29668) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-29668.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-29668.svg)


## CVE-2021-29208
 A remote dom xss, crlf injection vulnerability was discovered in HPE Integrated Lights-Out 4 (iLO 4); HPE SimpliVity 380 Gen9; HPE Integrated Lights-Out 5 (iLO 5) for HPE Gen10 Servers; HPE SimpliVity 380 Gen10; HPE SimpliVity 2600; HPE SimpliVity 380 Gen10 G; HPE SimpliVity 325; HPE SimpliVity 380 Gen10 H version(s): Prior to version 2.78.

- [https://github.com/JamesGeee/CVE-2021-29208](https://github.com/JamesGeee/CVE-2021-29208) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-29208.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-29208.svg)


## CVE-2021-29206
 A remote xss vulnerability was discovered in HPE Integrated Lights-Out 4 (iLO 4); HPE SimpliVity 380 Gen9; HPE Integrated Lights-Out 5 (iLO 5) for HPE Gen10 Servers; HPE SimpliVity 380 Gen10; HPE SimpliVity 2600; HPE SimpliVity 380 Gen10 G; HPE SimpliVity 325; HPE SimpliVity 380 Gen10 H version(s): Prior to version 2.78.

- [https://github.com/JamesGeee/CVE-2021-29206](https://github.com/JamesGeee/CVE-2021-29206) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-29206.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-29206.svg)


## CVE-2021-29205
 A remote xss vulnerability was discovered in HPE Integrated Lights-Out 4 (iLO 4); HPE SimpliVity 380 Gen9; HPE Integrated Lights-Out 5 (iLO 5) for HPE Gen10 Servers; HPE SimpliVity 380 Gen10; HPE SimpliVity 2600; HPE SimpliVity 380 Gen10 G; HPE SimpliVity 325; HPE SimpliVity 380 Gen10 H version(s): Prior to version 2.78.

- [https://github.com/JamesGeee/CVE-2021-29205](https://github.com/JamesGeee/CVE-2021-29205) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-29205.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-29205.svg)


## CVE-2021-29204
 A remote xss vulnerability was discovered in HPE Integrated Lights-Out 4 (iLO 4); HPE SimpliVity 380 Gen9; HPE Integrated Lights-Out 5 (iLO 5) for HPE Gen10 Servers; HPE SimpliVity 380 Gen10; HPE SimpliVity 2600; HPE SimpliVity 380 Gen10 G; HPE SimpliVity 325; HPE SimpliVity 380 Gen10 H version(s): Prior to version 2.78.

- [https://github.com/JamesGeee/CVE-2021-29204](https://github.com/JamesGeee/CVE-2021-29204) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-29204.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-29204.svg)


## CVE-2021-29202
 A local buffer overflow vulnerability was discovered in HPE Integrated Lights-Out 4 (iLO 4); HPE SimpliVity 380 Gen9; HPE Integrated Lights-Out 5 (iLO 5) for HPE Gen10 Servers; HPE SimpliVity 380 Gen10; HPE SimpliVity 2600; HPE SimpliVity 380 Gen10 G; HPE SimpliVity 325; HPE SimpliVity 380 Gen10 H version(s): Prior to version 2.78.

- [https://github.com/JamesGeee/CVE-2021-29202](https://github.com/JamesGeee/CVE-2021-29202) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-29202.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-29202.svg)


## CVE-2021-29201
 A remote xss vulnerability was discovered in HPE Integrated Lights-Out 4 (iLO 4); HPE SimpliVity 380 Gen9; HPE Integrated Lights-Out 5 (iLO 5) for HPE Gen10 Servers; HPE SimpliVity 380 Gen10; HPE SimpliVity 2600; HPE SimpliVity 380 Gen10 G; HPE SimpliVity 325; HPE SimpliVity 380 Gen10 H version(s): Prior to version 2.78.

- [https://github.com/JamesGeee/CVE-2021-29201](https://github.com/JamesGeee/CVE-2021-29201) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-29201.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-29201.svg)


## CVE-2021-28476
 Hyper-V Remote Code Execution Vulnerability

- [https://github.com/bluefrostsecurity/CVE-2021-28476](https://github.com/bluefrostsecurity/CVE-2021-28476) :  ![starts](https://img.shields.io/github/stars/bluefrostsecurity/CVE-2021-28476.svg) ![forks](https://img.shields.io/github/forks/bluefrostsecurity/CVE-2021-28476.svg)


## CVE-2021-20487
 IBM Power9 Self Boot Engine(SBE) could allow a privileged user to inject malicious code and compromise the integrity of the host firmware bypassing the host firmware signature verification process.

- [https://github.com/JamesGeee/CVE-2021-20487](https://github.com/JamesGeee/CVE-2021-20487) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-20487.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-20487.svg)


## CVE-2021-20486
 IBM Cloud Pak for Data 3.0 could allow an authenticated user to obtain sensitive information when installed with additional plugins. IBM X-Force ID: 197668.

- [https://github.com/JamesGeee/CVE-2021-20486](https://github.com/JamesGeee/CVE-2021-20486) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-20486.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-20486.svg)


## CVE-2021-20371
 IBM Jazz Foundation and IBM Engineering products could allow a remote attacker to obtain sensitive information when an error message is returned in the browser. This information could be used in further attacks against the system. IBM X-Force ID: 195516.

- [https://github.com/JamesGeee/CVE-2021-20371](https://github.com/JamesGeee/CVE-2021-20371) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-20371.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-20371.svg)


## CVE-2021-20348
 IBM Jazz Foundation and IBM Engineering products are vulnerable to server-side request forgery (SSRF). This may allow an authenticated attacker to send unauthorized requests from the system, potentially leading to network enumeration or facilitating other attacks. IBM X-ForceID: 194597.

- [https://github.com/JamesGeee/CVE-2021-20348](https://github.com/JamesGeee/CVE-2021-20348) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-20348.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-20348.svg)


## CVE-2021-20347
 IBM Jazz Foundation and IBM Engineering products are vulnerable to server-side request forgery (SSRF). This may allow an authenticated attacker to send unauthorized requests from the system, potentially leading to network enumeration or facilitating other attacks. IBM X-Force ID: 194596.

- [https://github.com/JamesGeee/CVE-2021-20347](https://github.com/JamesGeee/CVE-2021-20347) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-20347.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-20347.svg)


## CVE-2021-20346
 IBM Jazz Foundation and IBM Engineering products are vulnerable to server-side request forgery (SSRF). This may allow an authenticated attacker to send unauthorized requests from the system, potentially leading to network enumeration or facilitating other attacks. IBM X-Force ID: 194595.

- [https://github.com/JamesGeee/CVE-2021-20346](https://github.com/JamesGeee/CVE-2021-20346) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-20346.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-20346.svg)


## CVE-2021-20345
 IBM Jazz Foundation and IBM Engineering products are vulnerable to server-side request forgery (SSRF). This may allow an authenticated attacker to send unauthorized requests from the system, potentially leading to network enumeration or facilitating other attacks. IBM X-Force ID: 194594.

- [https://github.com/JamesGeee/CVE-2021-20345](https://github.com/JamesGeee/CVE-2021-20345) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-20345.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-20345.svg)


## CVE-2021-20343
 IBM Jazz Foundation and IBM Engineering products are vulnerable to server-side request forgery (SSRF). This may allow an authenticated attacker to send unauthorized requests from the system, potentially leading to network enumeration or facilitating other attacks. IBM X-Force ID: 194593.

- [https://github.com/JamesGeee/CVE-2021-20343](https://github.com/JamesGeee/CVE-2021-20343) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-20343.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-20343.svg)


## CVE-2021-20338
 IBM Jazz Foundation and IBM Engineering products are vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 194449.

- [https://github.com/JamesGeee/CVE-2021-20338](https://github.com/JamesGeee/CVE-2021-20338) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-20338.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-20338.svg)


## CVE-2021-20177
 A flaw was found in the Linux kernel's implementation of string matching within a packet. A privileged user (with root or CAP_NET_ADMIN) when inserting iptables rules could insert a rule which can panic the system. Kernel before kernel 5.5-rc1 is affected.

- [https://github.com/JamesGeee/CVE-2021-20177](https://github.com/JamesGeee/CVE-2021-20177) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-20177.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-20177.svg)


## CVE-2020-27833
 A Zip Slip vulnerability was found in the oc binary in openshift-clients where an arbitrary file write is achieved by using a specially crafted raw container image (.tar file) which contains symbolic links. The vulnerability is limited to the command `oc image extract`. If a symbolic link is first created pointing within the tarball, this allows further symbolic links to bypass the existing path check. This flaw allows the tarball to create links outside the tarball's parent directory, allowing for executables or configuration files to be overwritten, resulting in arbitrary code execution. The highest threat from this vulnerability is to confidentiality, integrity, as well as system availability. Versions up to and including openshift-clients-4.7.0-202104250659.p0.git.95881af are affected.

- [https://github.com/JamesGeee/CVE-2020-27833](https://github.com/JamesGeee/CVE-2020-27833) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-27833.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-27833.svg)


## CVE-2020-22023
 A heap-based Buffer Overflow vulnerabililty exists in FFmpeg 4.2 in filter_frame at libavfilter/vf_bitplanenoise.c, which might lead to memory corruption and other potential consequences.

- [https://github.com/JamesGeee/CVE-2020-22023](https://github.com/JamesGeee/CVE-2020-22023) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-22023.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-22023.svg)


## CVE-2020-22022
 A heap-based Buffer Overflow vulnerability exists in FFmpeg 4.2 in filter_frame at libavfilter/vf_fieldorder.c, which might lead to memory corruption and other potential consequences.

- [https://github.com/JamesGeee/CVE-2020-22022](https://github.com/JamesGeee/CVE-2020-22022) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-22022.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-22022.svg)


## CVE-2020-5030
 IBM Jazz Foundation and IBM Engineering products are vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 193737.

- [https://github.com/JamesGeee/CVE-2020-5030](https://github.com/JamesGeee/CVE-2020-5030) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-5030.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-5030.svg)


## CVE-2020-4977
 IBM Engineering Lifecycle Optimization - Publishing is vulnerable to stored cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 192470.

- [https://github.com/JamesGeee/CVE-2020-4977](https://github.com/JamesGeee/CVE-2020-4977) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-4977.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-4977.svg)


## CVE-2020-4732
 IBM Jazz Foundation and IBM Engineering products could allow an authenticated user to obtain sensitive information due to lack of security restrictions. IBM X-Force ID: 188126.

- [https://github.com/JamesGeee/CVE-2020-4732](https://github.com/JamesGeee/CVE-2020-4732) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-4732.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-4732.svg)


## CVE-2020-4520
 IBM Cognos Analytics 11.0 and 11.1 could allow a remote attacker to inject malicious HTML code that when viewed by the authenticated victim would execute the code. IBM X-Force ID: 182395.

- [https://github.com/JamesGeee/CVE-2020-4520](https://github.com/JamesGeee/CVE-2020-4520) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-4520.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-4520.svg)


## CVE-2020-4495
 IBM Jazz Foundation and IBM Engineering products could allow a remote attacker to bypass security restrictions, caused by improper access control. By sending a specially-crafted request to the REST API, an attacker could exploit this vulnerability to bypass access restrictions, and execute arbitrary actions with administrative privileges. IBM X-Force ID: 182114.

- [https://github.com/JamesGeee/CVE-2020-4495](https://github.com/JamesGeee/CVE-2020-4495) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-4495.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-4495.svg)


## CVE-2019-14836
 A vulnerability was found that the 3scale dev portal does not employ mechanisms for protection against login CSRF. An attacker could use this flaw to access unauthorized information or conduct further attacks.

- [https://github.com/JamesGeee/CVE-2019-14836](https://github.com/JamesGeee/CVE-2019-14836) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2019-14836.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2019-14836.svg)


## CVE-2015-7858
 SQL injection vulnerability in Joomla! 3.2 before 3.4.4 allows remote attackers to execute arbitrary SQL commands via unspecified vectors, a different vulnerability than CVE-2015-7297.

- [https://github.com/areaventuno/exploit-joomla](https://github.com/areaventuno/exploit-joomla) :  ![starts](https://img.shields.io/github/stars/areaventuno/exploit-joomla.svg) ![forks](https://img.shields.io/github/forks/areaventuno/exploit-joomla.svg)


## CVE-2015-7857
 SQL injection vulnerability in the getListQuery function in administrator/components/com_contenthistory/models/history.php in Joomla! 3.2 before 3.4.5 allows remote attackers to execute arbitrary SQL commands via the list[select] parameter to index.php.

- [https://github.com/areaventuno/exploit-joomla](https://github.com/areaventuno/exploit-joomla) :  ![starts](https://img.shields.io/github/stars/areaventuno/exploit-joomla.svg) ![forks](https://img.shields.io/github/forks/areaventuno/exploit-joomla.svg)


## CVE-2015-7297
 SQL injection vulnerability in Joomla! 3.2 before 3.4.4 allows remote attackers to execute arbitrary SQL commands via unspecified vectors, a different vulnerability than CVE-2015-7858.

- [https://github.com/areaventuno/exploit-joomla](https://github.com/areaventuno/exploit-joomla) :  ![starts](https://img.shields.io/github/stars/areaventuno/exploit-joomla.svg) ![forks](https://img.shields.io/github/forks/areaventuno/exploit-joomla.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/BelminD/heartbleed](https://github.com/BelminD/heartbleed) :  ![starts](https://img.shields.io/github/stars/BelminD/heartbleed.svg) ![forks](https://img.shields.io/github/forks/BelminD/heartbleed.svg)


## CVE-2006-3392
 Webmin before 1.290 and Usermin before 1.220 calls the simplify_path function before decoding HTML, which allows remote attackers to read arbitrary files, as demonstrated using &quot;..%01&quot; sequences, which bypass the removal of &quot;../&quot; sequences before bytes such as &quot;%01&quot; are removed from the filename.  NOTE: This is a different issue than CVE-2006-3274.

- [https://github.com/oxagast/oxasploits](https://github.com/oxagast/oxasploits) :  ![starts](https://img.shields.io/github/stars/oxagast/oxasploits.svg) ![forks](https://img.shields.io/github/forks/oxagast/oxasploits.svg)

