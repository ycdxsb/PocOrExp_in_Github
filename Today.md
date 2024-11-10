# Update 2024-11-10
## CVE-2024-21626
 runc is a CLI tool for spawning and running containers on Linux according to the OCI specification. In runc 1.1.11 and earlier, due to an internal file descriptor leak, an attacker could cause a newly-spawned container process (from runc exec) to have a working directory in the host filesystem namespace, allowing for a container escape by giving access to the host filesystem (&quot;attack 2&quot;). The same attack could be used by a malicious image to allow a container process to gain access to the host filesystem through runc run (&quot;attack 1&quot;). Variants of attacks 1 and 2 could be also be used to overwrite semi-arbitrary host binaries, allowing for complete container escapes (&quot;attack 3a&quot; and &quot;attack 3b&quot;). runc 1.1.12 includes patches for this issue.

- [https://github.com/Sk3pper/CVE-2024-21626-old-docker-versions](https://github.com/Sk3pper/CVE-2024-21626-old-docker-versions) :  ![starts](https://img.shields.io/github/stars/Sk3pper/CVE-2024-21626-old-docker-versions.svg) ![forks](https://img.shields.io/github/forks/Sk3pper/CVE-2024-21626-old-docker-versions.svg)


## CVE-2024-5117
 A vulnerability, which was classified as critical, was found in SourceCodester Event Registration System 1.0. This affects an unknown part of the file portal.php. The manipulation of the argument username/password leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-265197 was assigned to this vulnerability.

- [https://github.com/Lakshmirnr/CVE-2024-51179](https://github.com/Lakshmirnr/CVE-2024-51179) :  ![starts](https://img.shields.io/github/stars/Lakshmirnr/CVE-2024-51179.svg) ![forks](https://img.shields.io/github/forks/Lakshmirnr/CVE-2024-51179.svg)


## CVE-2024-5047
 A vulnerability classified as critical has been found in SourceCodester Student Management System 1.0. Affected is an unknown function of the file /student/controller.php. The manipulation of the argument photo leads to unrestricted upload. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-264744.

- [https://github.com/RandomRobbieBF/CVE-2024-50477](https://github.com/RandomRobbieBF/CVE-2024-50477) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-50477.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-50477.svg)


## CVE-2024-5045
 A vulnerability was found in SourceCodester Online Birth Certificate Management System 1.0. It has been declared as problematic. This vulnerability affects unknown code of the file /admin. The manipulation leads to files or directories accessible. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. VDB-264742 is the identifier assigned to this vulnerability.

- [https://github.com/RandomRobbieBF/CVE-2024-50450](https://github.com/RandomRobbieBF/CVE-2024-50450) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-50450.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-50450.svg)


## CVE-2024-5042
 A flaw was found in the Submariner project. Due to unnecessary role-based access control permissions, a privileged attacker can run a malicious container on a node that may allow them to steal service account tokens and further compromise other nodes and potentially the entire cluster.

- [https://github.com/RandomRobbieBF/CVE-2024-50427](https://github.com/RandomRobbieBF/CVE-2024-50427) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-50427.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-50427.svg)


## CVE-2024-2928
 A Local File Inclusion (LFI) vulnerability was identified in mlflow/mlflow, specifically in version 2.9.2, which was fixed in version 2.11.3. This vulnerability arises from the application's failure to properly validate URI fragments for directory traversal sequences such as '../'. An attacker can exploit this flaw by manipulating the fragment part of the URI to read arbitrary files on the local file system, including sensitive files like '/etc/passwd'. The vulnerability is a bypass to a previous patch that only addressed similar manipulation within the URI's query string, highlighting the need for comprehensive validation of all parts of a URI to prevent LFI attacks.

- [https://github.com/nuridincersaygili/CVE-2024-2928](https://github.com/nuridincersaygili/CVE-2024-2928) :  ![starts](https://img.shields.io/github/stars/nuridincersaygili/CVE-2024-2928.svg) ![forks](https://img.shields.io/github/forks/nuridincersaygili/CVE-2024-2928.svg)


## CVE-2024-1047
 The Orbit Fox by ThemeIsle plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the register_reference() function in all versions up to, and including, 2.10.28. This makes it possible for unauthenticated attackers to update the connected API keys.

- [https://github.com/RandomRobbieBF/CVE-2024-10470](https://github.com/RandomRobbieBF/CVE-2024-10470) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-10470.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-10470.svg)


## CVE-2022-41099
 BitLocker Security Feature Bypass Vulnerability

- [https://github.com/rhett-hislop/PatchWinRE](https://github.com/rhett-hislop/PatchWinRE) :  ![starts](https://img.shields.io/github/stars/rhett-hislop/PatchWinRE.svg) ![forks](https://img.shields.io/github/forks/rhett-hislop/PatchWinRE.svg)


## CVE-2021-21401
 Nanopb is a small code-size Protocol Buffers implementation in ansi C. In Nanopb before versions 0.3.9.8 and 0.4.5, decoding a specifically formed message can cause invalid `free()` or `realloc()` calls if the message type contains an `oneof` field, and the `oneof` directly contains both a pointer field and a non-pointer field. If the message data first contains the non-pointer field and then the pointer field, the data of the non-pointer field is incorrectly treated as if it was a pointer value. Such message data rarely occurs in normal messages, but it is a concern when untrusted data is parsed. This has been fixed in versions 0.3.9.8 and 0.4.5. See referenced GitHub Security Advisory for more information including workarounds.

- [https://github.com/uthrasri/CVE-2021-21401_nanopb-c_AOSP10_R33](https://github.com/uthrasri/CVE-2021-21401_nanopb-c_AOSP10_R33) :  ![starts](https://img.shields.io/github/stars/uthrasri/CVE-2021-21401_nanopb-c_AOSP10_R33.svg) ![forks](https://img.shields.io/github/forks/uthrasri/CVE-2021-21401_nanopb-c_AOSP10_R33.svg)


## CVE-2019-12422
 Apache Shiro before 1.4.2, when using the default &quot;remember me&quot; configuration, cookies could be susceptible to a padding attack.

- [https://github.com/BaiHLiu/RuoYI-4.2-Shiro-721-Docker-PoC](https://github.com/BaiHLiu/RuoYI-4.2-Shiro-721-Docker-PoC) :  ![starts](https://img.shields.io/github/stars/BaiHLiu/RuoYI-4.2-Shiro-721-Docker-PoC.svg) ![forks](https://img.shields.io/github/forks/BaiHLiu/RuoYI-4.2-Shiro-721-Docker-PoC.svg)

