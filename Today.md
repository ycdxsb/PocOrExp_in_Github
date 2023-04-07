# Update 2023-04-07
## CVE-2023-25610
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/PSIRT-REPO/CVE-2023-25610](https://github.com/PSIRT-REPO/CVE-2023-25610) :  ![starts](https://img.shields.io/github/stars/PSIRT-REPO/CVE-2023-25610.svg) ![forks](https://img.shields.io/github/forks/PSIRT-REPO/CVE-2023-25610.svg)


## CVE-2023-22809
 In Sudo before 1.9.12p2, the sudoedit (aka -e) feature mishandles extra arguments passed in the user-provided environment variables (SUDO_EDITOR, VISUAL, and EDITOR), allowing a local attacker to append arbitrary entries to the list of files to process. This can lead to privilege escalation. Affected versions are 1.8.0 through 1.9.12.p1. The problem exists because a user-specified editor may contain a &quot;--&quot; argument that defeats a protection mechanism, e.g., an EDITOR='vim -- /path/to/extra/file' value.

- [https://github.com/CKevens/CVE-2023-22809-sudo-POC](https://github.com/CKevens/CVE-2023-22809-sudo-POC) :  ![starts](https://img.shields.io/github/stars/CKevens/CVE-2023-22809-sudo-POC.svg) ![forks](https://img.shields.io/github/forks/CKevens/CVE-2023-22809-sudo-POC.svg)


## CVE-2023-20943
 In clearApplicationUserData of ActivityManagerService.java, there is a possible way to remove system files due to a path traversal error. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12L Android-13Android ID: A-240267890

- [https://github.com/hshivhare67/platform_frameworks_base_AOSP10_r33_CVE-2023-20943](https://github.com/hshivhare67/platform_frameworks_base_AOSP10_r33_CVE-2023-20943) :  ![starts](https://img.shields.io/github/stars/hshivhare67/platform_frameworks_base_AOSP10_r33_CVE-2023-20943.svg) ![forks](https://img.shields.io/github/forks/hshivhare67/platform_frameworks_base_AOSP10_r33_CVE-2023-20943.svg)


## CVE-2023-20933
 In several functions of MediaCodec.cpp, there is a possible way to corrupt memory due to a use after free. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12L Android-13Android ID: A-245860753

- [https://github.com/hshivhare67/platform_frameworks_av_AOSP10_r33_CVE-2023-20933](https://github.com/hshivhare67/platform_frameworks_av_AOSP10_r33_CVE-2023-20933) :  ![starts](https://img.shields.io/github/stars/hshivhare67/platform_frameworks_av_AOSP10_r33_CVE-2023-20933.svg) ![forks](https://img.shields.io/github/forks/hshivhare67/platform_frameworks_av_AOSP10_r33_CVE-2023-20933.svg)


## CVE-2023-0669
 Fortra (formerly, HelpSystems) GoAnywhere MFT suffers from a pre-authentication command injection vulnerability in the License Response Servlet due to deserializing an arbitrary attacker-controlled object. This issue was patched in version 7.1.2.

- [https://github.com/Avento/CVE-2023-0669](https://github.com/Avento/CVE-2023-0669) :  ![starts](https://img.shields.io/github/stars/Avento/CVE-2023-0669.svg) ![forks](https://img.shields.io/github/forks/Avento/CVE-2023-0669.svg)


## CVE-2022-42896
 There are use-after-free vulnerabilities in the Linux kernel's net/bluetooth/l2cap_core.c's l2cap_connect and l2cap_le_connect_req functions which may allow code execution and leaking kernel memory (respectively) remotely via Bluetooth. A remote attacker could execute code leaking kernel memory via Bluetooth if within proximity of the victim. We recommend upgrading past commit https://www.google.com/url https://github.com/torvalds/linux/commit/711f8c3fb3db61897080468586b970c87c61d9e4 https://www.google.com/url

- [https://github.com/Trinadh465/linux-4.19.72_CVE-2022-42896](https://github.com/Trinadh465/linux-4.19.72_CVE-2022-42896) :  ![starts](https://img.shields.io/github/stars/Trinadh465/linux-4.19.72_CVE-2022-42896.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/linux-4.19.72_CVE-2022-42896.svg)
- [https://github.com/hshivhare67/kernel_v4.19.72_CVE-2022-42896_old](https://github.com/hshivhare67/kernel_v4.19.72_CVE-2022-42896_old) :  ![starts](https://img.shields.io/github/stars/hshivhare67/kernel_v4.19.72_CVE-2022-42896_old.svg) ![forks](https://img.shields.io/github/forks/hshivhare67/kernel_v4.19.72_CVE-2022-42896_old.svg)


## CVE-2022-26265
 Contao Managed Edition v1.5.0 was discovered to contain a remote command execution (RCE) vulnerability via the component php_cli parameter.

- [https://github.com/redteamsecurity2023/CVE-2022-26265](https://github.com/redteamsecurity2023/CVE-2022-26265) :  ![starts](https://img.shields.io/github/stars/redteamsecurity2023/CVE-2022-26265.svg) ![forks](https://img.shields.io/github/forks/redteamsecurity2023/CVE-2022-26265.svg)


## CVE-2021-45960
 In Expat (aka libexpat) before 2.4.3, a left shift by 29 (or more) places in the storeAtts function in xmlparse.c can lead to realloc misbehavior (e.g., allocating too few bytes, or only freeing memory).

- [https://github.com/hshivhare67/external_expat_v2.2.6_CVE-2021-45960](https://github.com/hshivhare67/external_expat_v2.2.6_CVE-2021-45960) :  ![starts](https://img.shields.io/github/stars/hshivhare67/external_expat_v2.2.6_CVE-2021-45960.svg) ![forks](https://img.shields.io/github/forks/hshivhare67/external_expat_v2.2.6_CVE-2021-45960.svg)


## CVE-2021-34496
 Windows GDI Information Disclosure Vulnerability

- [https://github.com/dja2TaqkGEEfA45/CVE-2021-34496](https://github.com/dja2TaqkGEEfA45/CVE-2021-34496) :  ![starts](https://img.shields.io/github/stars/dja2TaqkGEEfA45/CVE-2021-34496.svg) ![forks](https://img.shields.io/github/forks/dja2TaqkGEEfA45/CVE-2021-34496.svg)


## CVE-2021-31290
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/qaisarafridi/cve-2021-31290](https://github.com/qaisarafridi/cve-2021-31290) :  ![starts](https://img.shields.io/github/stars/qaisarafridi/cve-2021-31290.svg) ![forks](https://img.shields.io/github/forks/qaisarafridi/cve-2021-31290.svg)


## CVE-2021-30641
 Apache HTTP Server versions 2.4.39 to 2.4.46 Unexpected matching behavior with 'MergeSlashes OFF'

- [https://github.com/dja2TaqkGEEfA45/CVE-2021-30641](https://github.com/dja2TaqkGEEfA45/CVE-2021-30641) :  ![starts](https://img.shields.io/github/stars/dja2TaqkGEEfA45/CVE-2021-30641.svg) ![forks](https://img.shields.io/github/forks/dja2TaqkGEEfA45/CVE-2021-30641.svg)


## CVE-2021-26691
 In Apache HTTP Server versions 2.4.0 to 2.4.46 a specially crafted SessionHeader sent by an origin server could cause a heap overflow

- [https://github.com/dja2TaqkGEEfA45/CVE-2021-26691](https://github.com/dja2TaqkGEEfA45/CVE-2021-26691) :  ![starts](https://img.shields.io/github/stars/dja2TaqkGEEfA45/CVE-2021-26691.svg) ![forks](https://img.shields.io/github/forks/dja2TaqkGEEfA45/CVE-2021-26691.svg)


## CVE-2021-26690
 Apache HTTP Server versions 2.4.0 to 2.4.46 A specially crafted Cookie header handled by mod_session can cause a NULL pointer dereference and crash, leading to a possible Denial Of Service

- [https://github.com/dja2TaqkGEEfA45/CVE-2021-26690](https://github.com/dja2TaqkGEEfA45/CVE-2021-26690) :  ![starts](https://img.shields.io/github/stars/dja2TaqkGEEfA45/CVE-2021-26690.svg) ![forks](https://img.shields.io/github/forks/dja2TaqkGEEfA45/CVE-2021-26690.svg)


## CVE-2021-3516
 There's a flaw in libxml2's xmllint in versions before 2.9.11. An attacker who is able to submit a crafted file to be processed by xmllint could trigger a use-after-free. The greatest impact of this flaw is to confidentiality, integrity, and availability.

- [https://github.com/dja2TaqkGEEfA45/CVE-2021-3516](https://github.com/dja2TaqkGEEfA45/CVE-2021-3516) :  ![starts](https://img.shields.io/github/stars/dja2TaqkGEEfA45/CVE-2021-3516.svg) ![forks](https://img.shields.io/github/forks/dja2TaqkGEEfA45/CVE-2021-3516.svg)


## CVE-2021-3490
 The eBPF ALU32 bounds tracking for bitwise ops (AND, OR and XOR) in the Linux kernel did not properly update 32-bit bounds, which could be turned into out of bounds reads and writes in the Linux kernel and therefore, arbitrary code execution. This issue was fixed via commit 049c4e13714e (&quot;bpf: Fix alu32 const subreg bound tracking on bitwise operations&quot;) (v5.13-rc4) and backported to the stable kernels in v5.12.4, v5.11.21, and v5.10.37. The AND/OR issues were introduced by commit 3f50f132d840 (&quot;bpf: Verifier, do explicit ALU32 bounds tracking&quot;) (5.7-rc1) and the XOR variant was introduced by 2921c90d4718 (&quot;bpf:Fix a verifier failure with xor&quot;) ( 5.10-rc1).

- [https://github.com/pivik271/CVE-2021-3490](https://github.com/pivik271/CVE-2021-3490) :  ![starts](https://img.shields.io/github/stars/pivik271/CVE-2021-3490.svg) ![forks](https://img.shields.io/github/forks/pivik271/CVE-2021-3490.svg)


## CVE-2021-3129
 Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.

- [https://github.com/qaisarafridi/cve-2021-3129](https://github.com/qaisarafridi/cve-2021-3129) :  ![starts](https://img.shields.io/github/stars/qaisarafridi/cve-2021-3129.svg) ![forks](https://img.shields.io/github/forks/qaisarafridi/cve-2021-3129.svg)


## CVE-2021-2394
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/BabyTeam1024/CVE-2021-2394](https://github.com/BabyTeam1024/CVE-2021-2394) :  ![starts](https://img.shields.io/github/stars/BabyTeam1024/CVE-2021-2394.svg) ![forks](https://img.shields.io/github/forks/BabyTeam1024/CVE-2021-2394.svg)


## CVE-2019-5736
 runc through 1.0-rc6, as used in Docker before 18.09.2 and other products, allows attackers to overwrite the host runc binary (and consequently obtain host root access) by leveraging the ability to execute a command as root within one of these types of containers: (1) a new container with an attacker-controlled image, or (2) an existing container, to which the attacker previously had write access, that can be attached with docker exec. This occurs because of file-descriptor mishandling, related to /proc/self/exe.

- [https://github.com/chosam2/cve-2019-5736-poc](https://github.com/chosam2/cve-2019-5736-poc) :  ![starts](https://img.shields.io/github/stars/chosam2/cve-2019-5736-poc.svg) ![forks](https://img.shields.io/github/forks/chosam2/cve-2019-5736-poc.svg)


## CVE-2019-1322
 An elevation of privilege vulnerability exists when Windows improperly handles authentication requests, aka 'Microsoft Windows Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-1320, CVE-2019-1340.

- [https://github.com/apt69/COMahawk](https://github.com/apt69/COMahawk) :  ![starts](https://img.shields.io/github/stars/apt69/COMahawk.svg) ![forks](https://img.shields.io/github/forks/apt69/COMahawk.svg)


## CVE-2018-14463
 The VRRP parser in tcpdump before 4.9.3 has a buffer over-read in print-vrrp.c:vrrp_print() for VRRP version 2, a different vulnerability than CVE-2019-15167.

- [https://github.com/hshivhare67/platform_external_tcpdump_AOSP10_r33_4.9.2-_CVE-2018-14463](https://github.com/hshivhare67/platform_external_tcpdump_AOSP10_r33_4.9.2-_CVE-2018-14463) :  ![starts](https://img.shields.io/github/stars/hshivhare67/platform_external_tcpdump_AOSP10_r33_4.9.2-_CVE-2018-14463.svg) ![forks](https://img.shields.io/github/forks/hshivhare67/platform_external_tcpdump_AOSP10_r33_4.9.2-_CVE-2018-14463.svg)


## CVE-2016-4631
 ImageIO in Apple iOS before 9.3.3, OS X before 10.11.6, tvOS before 9.2.2, and watchOS before 2.2.2 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted TIFF file.

- [https://github.com/hansnielsen/tiffdisabler](https://github.com/hansnielsen/tiffdisabler) :  ![starts](https://img.shields.io/github/stars/hansnielsen/tiffdisabler.svg) ![forks](https://img.shields.io/github/forks/hansnielsen/tiffdisabler.svg)


## CVE-2015-5864
 IOAudioFamily in Apple OS X before 10.11 allows local users to obtain sensitive kernel memory-layout information via unspecified vectors.

- [https://github.com/jndok/tpwn-bis](https://github.com/jndok/tpwn-bis) :  ![starts](https://img.shields.io/github/stars/jndok/tpwn-bis.svg) ![forks](https://img.shields.io/github/forks/jndok/tpwn-bis.svg)

