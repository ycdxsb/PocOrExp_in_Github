# Update 2024-03-27
## CVE-2024-23722
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/alexcote1/CVE-2024-23722-poc](https://github.com/alexcote1/CVE-2024-23722-poc) :  ![starts](https://img.shields.io/github/stars/alexcote1/CVE-2024-23722-poc.svg) ![forks](https://img.shields.io/github/forks/alexcote1/CVE-2024-23722-poc.svg)


## CVE-2023-46604
 The Java OpenWire protocol marshaller is vulnerable to Remote Code Execution. This vulnerability may allow a remote attacker with network access to either a Java-based OpenWire broker or client to run arbitrary shell commands by manipulating serialized class types in the OpenWire protocol to cause either the client or the broker (respectively) to instantiate any class on the classpath. Users are recommended to upgrade both brokers and clients to version 5.15.16, 5.16.7, 5.17.6, or 5.18.3 which fixes this issue.

- [https://github.com/ph-hitachi/CVE-2023-46604](https://github.com/ph-hitachi/CVE-2023-46604) :  ![starts](https://img.shields.io/github/stars/ph-hitachi/CVE-2023-46604.svg) ![forks](https://img.shields.io/github/forks/ph-hitachi/CVE-2023-46604.svg)


## CVE-2023-38831
 RARLAB WinRAR before 6.23 allows attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive. The issue occurs because a ZIP archive may include a benign file (such as an ordinary .JPG file) and also a folder that has the same name as the benign file, and the contents of the folder (which may include executable content) are processed during an attempt to access only the benign file. This was exploited in the wild in April through October 2023.

- [https://github.com/youmulijiang/evil-winrar](https://github.com/youmulijiang/evil-winrar) :  ![starts](https://img.shields.io/github/stars/youmulijiang/evil-winrar.svg) ![forks](https://img.shields.io/github/forks/youmulijiang/evil-winrar.svg)


## CVE-2022-32932
 The issue was addressed with improved memory handling. This issue is fixed in iOS 15.7.1 and iPadOS 15.7.1, iOS 16.1 and iPadOS 16, watchOS 9.1. An app may be able to execute arbitrary code with kernel privileges.

- [https://github.com/ox1111/CVE-2022-32932](https://github.com/ox1111/CVE-2022-32932) :  ![starts](https://img.shields.io/github/stars/ox1111/CVE-2022-32932.svg) ![forks](https://img.shields.io/github/forks/ox1111/CVE-2022-32932.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/vuongnv3389-sec/cve-2021-41773](https://github.com/vuongnv3389-sec/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/vuongnv3389-sec/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/vuongnv3389-sec/cve-2021-41773.svg)
- [https://github.com/skentagon/CVE-2021-41773](https://github.com/skentagon/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/skentagon/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/skentagon/CVE-2021-41773.svg)


## CVE-2020-7961
 Deserialization of Untrusted Data in Liferay Portal prior to 7.2.1 CE GA2 allows remote attackers to execute arbitrary code via JSON web services (JSONWS).

- [https://github.com/NMinhTrung/LIFERAY-CVE-2020-7961](https://github.com/NMinhTrung/LIFERAY-CVE-2020-7961) :  ![starts](https://img.shields.io/github/stars/NMinhTrung/LIFERAY-CVE-2020-7961.svg) ![forks](https://img.shields.io/github/forks/NMinhTrung/LIFERAY-CVE-2020-7961.svg)


## CVE-2019-12550
 WAGO 852-303 before FW06, 852-1305 before FW06, and 852-1505 before FW03 devices contain hardcoded users and passwords that can be used to login via SSH and TELNET.

- [https://github.com/itwizardo/CVE-2019-12550](https://github.com/itwizardo/CVE-2019-12550) :  ![starts](https://img.shields.io/github/stars/itwizardo/CVE-2019-12550.svg) ![forks](https://img.shields.io/github/forks/itwizardo/CVE-2019-12550.svg)


## CVE-2019-0567
 A remote code execution vulnerability exists in the way that the Chakra scripting engine handles objects in memory in Microsoft Edge, aka &quot;Chakra Scripting Engine Memory Corruption Vulnerability.&quot; This affects Microsoft Edge, ChakraCore. This CVE ID is unique from CVE-2019-0539, CVE-2019-0568.

- [https://github.com/ommadawn46/chakra-type-confusions](https://github.com/ommadawn46/chakra-type-confusions) :  ![starts](https://img.shields.io/github/stars/ommadawn46/chakra-type-confusions.svg) ![forks](https://img.shields.io/github/forks/ommadawn46/chakra-type-confusions.svg)


## CVE-2019-0539
 A remote code execution vulnerability exists in the way that the Chakra scripting engine handles objects in memory in Microsoft Edge, aka &quot;Chakra Scripting Engine Memory Corruption Vulnerability.&quot; This affects Microsoft Edge, ChakraCore. This CVE ID is unique from CVE-2019-0567, CVE-2019-0568.

- [https://github.com/ommadawn46/chakra-type-confusions](https://github.com/ommadawn46/chakra-type-confusions) :  ![starts](https://img.shields.io/github/stars/ommadawn46/chakra-type-confusions.svg) ![forks](https://img.shields.io/github/forks/ommadawn46/chakra-type-confusions.svg)


## CVE-2018-8617
 A remote code execution vulnerability exists in the way that the Chakra scripting engine handles objects in memory in Microsoft Edge, aka &quot;Chakra Scripting Engine Memory Corruption Vulnerability.&quot; This affects Microsoft Edge, ChakraCore. This CVE ID is unique from CVE-2018-8583, CVE-2018-8618, CVE-2018-8624, CVE-2018-8629.

- [https://github.com/ommadawn46/chakra-type-confusions](https://github.com/ommadawn46/chakra-type-confusions) :  ![starts](https://img.shields.io/github/stars/ommadawn46/chakra-type-confusions.svg) ![forks](https://img.shields.io/github/forks/ommadawn46/chakra-type-confusions.svg)


## CVE-2016-6304
 Multiple memory leaks in t1_lib.c in OpenSSL before 1.0.1u, 1.0.2 before 1.0.2i, and 1.1.0 before 1.1.0a allow remote attackers to cause a denial of service (memory consumption) via large OCSP Status Request extensions.

- [https://github.com/nidhi7598/OPENSSL_1.0.1g_CVE-2016-6304](https://github.com/nidhi7598/OPENSSL_1.0.1g_CVE-2016-6304) :  ![starts](https://img.shields.io/github/stars/nidhi7598/OPENSSL_1.0.1g_CVE-2016-6304.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/OPENSSL_1.0.1g_CVE-2016-6304.svg)

