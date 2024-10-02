# Update 2024-10-02
## CVE-2024-28987
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/PlayerFridei/CVE-2024-28987](https://github.com/PlayerFridei/CVE-2024-28987) :  ![starts](https://img.shields.io/github/stars/PlayerFridei/CVE-2024-28987.svg) ![forks](https://img.shields.io/github/forks/PlayerFridei/CVE-2024-28987.svg)


## CVE-2024-23897
 Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.

- [https://github.com/verylazytech/CVE-2024-23897](https://github.com/verylazytech/CVE-2024-23897) :  ![starts](https://img.shields.io/github/stars/verylazytech/CVE-2024-23897.svg) ![forks](https://img.shields.io/github/forks/verylazytech/CVE-2024-23897.svg)


## CVE-2024-4127
 A vulnerability was found in Tenda W15E 15.11.0.14. It has been classified as critical. Affected is the function guestWifiRuleRefresh. The manipulation of the argument qosGuestDownstream leads to stack-based buffer overflow. It is possible to launch the attack remotely. VDB-261870 is the identifier assigned to this vulnerability. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/artemy-ccrsky/CVE-2024-41276](https://github.com/artemy-ccrsky/CVE-2024-41276) :  ![starts](https://img.shields.io/github/stars/artemy-ccrsky/CVE-2024-41276.svg) ![forks](https://img.shields.io/github/forks/artemy-ccrsky/CVE-2024-41276.svg)


## CVE-2024-4040
 A server side template injection vulnerability in CrushFTP in all versions before 10.7.1 and 11.1.0 on all platforms allows unauthenticated remote attackers to read files from the filesystem outside of the VFS Sandbox, bypass authentication to gain administrative access, and perform remote code execution on the server.

- [https://github.com/geniuszlyy/GenCrushSSTIExploit](https://github.com/geniuszlyy/GenCrushSSTIExploit) :  ![starts](https://img.shields.io/github/stars/geniuszlyy/GenCrushSSTIExploit.svg) ![forks](https://img.shields.io/github/forks/geniuszlyy/GenCrushSSTIExploit.svg)


## CVE-2023-40404
 A use-after-free issue was addressed with improved memory management. This issue is fixed in macOS Sonoma 14.1. An app may be able to execute arbitrary code with kernel privileges.

- [https://github.com/geniuszlyy/GenEtherExploit](https://github.com/geniuszlyy/GenEtherExploit) :  ![starts](https://img.shields.io/github/stars/geniuszlyy/GenEtherExploit.svg) ![forks](https://img.shields.io/github/forks/geniuszlyy/GenEtherExploit.svg)


## CVE-2023-3390
 A use-after-free vulnerability was found in the Linux kernel's netfilter subsystem in net/netfilter/nf_tables_api.c. Mishandled error handling with NFT_MSG_NEWRULE makes it possible to use a dangling pointer in the same transaction causing a use-after-free vulnerability. This flaw allows a local attacker with user access to cause a privilege escalation issue. We recommend upgrading past commit 1240eb93f0616b21c675416516ff3d74798fdc97.

- [https://github.com/flygonty/CVE-2023-3390_PoC](https://github.com/flygonty/CVE-2023-3390_PoC) :  ![starts](https://img.shields.io/github/stars/flygonty/CVE-2023-3390_PoC.svg) ![forks](https://img.shields.io/github/forks/flygonty/CVE-2023-3390_PoC.svg)


## CVE-2019-14271
 In Docker 19.03.x before 19.03.1 linked against the GNU C Library (aka glibc), code injection can occur when the nsswitch facility dynamically loads a library inside a chroot that contains the contents of the container.

- [https://github.com/HoangLai2k3/CVE_2019_14271](https://github.com/HoangLai2k3/CVE_2019_14271) :  ![starts](https://img.shields.io/github/stars/HoangLai2k3/CVE_2019_14271.svg) ![forks](https://img.shields.io/github/forks/HoangLai2k3/CVE_2019_14271.svg)


## CVE-2019-5736
 runc through 1.0-rc6, as used in Docker before 18.09.2 and other products, allows attackers to overwrite the host runc binary (and consequently obtain host root access) by leveraging the ability to execute a command as root within one of these types of containers: (1) a new container with an attacker-controlled image, or (2) an existing container, to which the attacker previously had write access, that can be attached with docker exec. This occurs because of file-descriptor mishandling, related to /proc/self/exe.

- [https://github.com/HoangLai2k3/CVE_2019_5736](https://github.com/HoangLai2k3/CVE_2019_5736) :  ![starts](https://img.shields.io/github/stars/HoangLai2k3/CVE_2019_5736.svg) ![forks](https://img.shields.io/github/forks/HoangLai2k3/CVE_2019_5736.svg)


## CVE-2015-9238
 secure-compare 3.0.0 and below do not actually compare two strings properly. compare was actually comparing the first argument with itself, meaning the check passed for any two strings of the same length.

- [https://github.com/JamesDarf/wargame-secure_compare](https://github.com/JamesDarf/wargame-secure_compare) :  ![starts](https://img.shields.io/github/stars/JamesDarf/wargame-secure_compare.svg) ![forks](https://img.shields.io/github/forks/JamesDarf/wargame-secure_compare.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/belmind/heartbleed](https://github.com/belmind/heartbleed) :  ![starts](https://img.shields.io/github/stars/belmind/heartbleed.svg) ![forks](https://img.shields.io/github/forks/belmind/heartbleed.svg)


## CVE-2003-0001
 Multiple ethernet Network Interface Card (NIC) device drivers do not pad frames with null bytes, which allows remote attackers to obtain information from previous packets or kernel memory by using malformed packets, as demonstrated by Etherleak.

- [https://github.com/marb08/etherleak-checker](https://github.com/marb08/etherleak-checker) :  ![starts](https://img.shields.io/github/stars/marb08/etherleak-checker.svg) ![forks](https://img.shields.io/github/forks/marb08/etherleak-checker.svg)

