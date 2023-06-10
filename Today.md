# Update 2023-06-10
## CVE-2023-34096
 Thruk is a multibackend monitoring webinterface which currently supports Naemon, Icinga, Shinken and Nagios as backends. In versions 3.06 and prior, the file `panorama.pm` is vulnerable to a Path Traversal vulnerability which allows an attacker to upload a file to any folder which has write permissions on the affected system. The parameter location is not filtered, validated or sanitized and it accepts any kind of characters. For a path traversal attack, the only characters required were the dot (`.`) and the slash (`/`). A fix is available in version 3.06.2.

- [https://github.com/galoget/Thruk-CVE-2023-34096](https://github.com/galoget/Thruk-CVE-2023-34096) :  ![starts](https://img.shields.io/github/stars/galoget/Thruk-CVE-2023-34096.svg) ![forks](https://img.shields.io/github/forks/galoget/Thruk-CVE-2023-34096.svg)


## CVE-2023-33253
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Toxich4/CVE-2023-33253](https://github.com/Toxich4/CVE-2023-33253) :  ![starts](https://img.shields.io/github/stars/Toxich4/CVE-2023-33253.svg) ![forks](https://img.shields.io/github/forks/Toxich4/CVE-2023-33253.svg)


## CVE-2023-33246
 For RocketMQ versions 5.1.0 and below, under certain conditions, there is a risk of remote command execution. Several components of RocketMQ, including NameServer, Broker, and Controller, are leaked on the extranet and lack permission verification, an attacker can exploit this vulnerability by using the update configuration function to execute commands as the system users that RocketMQ is running as. Additionally, an attacker can achieve the same effect by forging the RocketMQ protocol content. To prevent these attacks, users are recommended to upgrade to version 5.1.1 or above for using RocketMQ 5.x or 4.9.6 or above for using RocketMQ 4.x .

- [https://github.com/v0ita/rocketMq_RCE](https://github.com/v0ita/rocketMq_RCE) :  ![starts](https://img.shields.io/github/stars/v0ita/rocketMq_RCE.svg) ![forks](https://img.shields.io/github/forks/v0ita/rocketMq_RCE.svg)


## CVE-2023-32353
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/86x/CVE-2023-32353-PoC](https://github.com/86x/CVE-2023-32353-PoC) :  ![starts](https://img.shields.io/github/stars/86x/CVE-2023-32353-PoC.svg) ![forks](https://img.shields.io/github/forks/86x/CVE-2023-32353-PoC.svg)


## CVE-2023-23638
 A deserialization vulnerability existed when dubbo generic invoke, which could lead to malicious code execution. This issue affects Apache Dubbo 2.7.x version 2.7.21 and prior versions; Apache Dubbo 3.0.x version 3.0.13 and prior versions; Apache Dubbo 3.1.x version 3.1.5 and prior versions.

- [https://github.com/CKevens/CVE-2023-23638-Tools](https://github.com/CKevens/CVE-2023-23638-Tools) :  ![starts](https://img.shields.io/github/stars/CKevens/CVE-2023-23638-Tools.svg) ![forks](https://img.shields.io/github/forks/CKevens/CVE-2023-23638-Tools.svg)


## CVE-2023-22809
 In Sudo before 1.9.12p2, the sudoedit (aka -e) feature mishandles extra arguments passed in the user-provided environment variables (SUDO_EDITOR, VISUAL, and EDITOR), allowing a local attacker to append arbitrary entries to the list of files to process. This can lead to privilege escalation. Affected versions are 1.8.0 through 1.9.12.p1. The problem exists because a user-specified editor may contain a &quot;--&quot; argument that defeats a protection mechanism, e.g., an EDITOR='vim -- /path/to/extra/file' value.

- [https://github.com/hello4r1end/patch_CVE-2023-22809](https://github.com/hello4r1end/patch_CVE-2023-22809) :  ![starts](https://img.shields.io/github/stars/hello4r1end/patch_CVE-2023-22809.svg) ![forks](https://img.shields.io/github/forks/hello4r1end/patch_CVE-2023-22809.svg)


## CVE-2023-2033
 Type confusion in V8 in Google Chrome prior to 112.0.5615.121 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/WalccDev/CVE-2023-2033](https://github.com/WalccDev/CVE-2023-2033) :  ![starts](https://img.shields.io/github/stars/WalccDev/CVE-2023-2033.svg) ![forks](https://img.shields.io/github/forks/WalccDev/CVE-2023-2033.svg)


## CVE-2023-1060
 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in YKM YKM CRM allows Reflected XSS.This issue affects YKM CRM: before 23.03.30.

- [https://github.com/b35363/cve-2023-10608-PoC](https://github.com/b35363/cve-2023-10608-PoC) :  ![starts](https://img.shields.io/github/stars/b35363/cve-2023-10608-PoC.svg) ![forks](https://img.shields.io/github/forks/b35363/cve-2023-10608-PoC.svg)


## CVE-2022-25765
 The package pdfkit from 0.0.0 are vulnerable to Command Injection where the URL is not properly sanitized.

- [https://github.com/PurpleWaveIO/CVE-2022-25765-pdfkit-Exploit-Reverse-Shell](https://github.com/PurpleWaveIO/CVE-2022-25765-pdfkit-Exploit-Reverse-Shell) :  ![starts](https://img.shields.io/github/stars/PurpleWaveIO/CVE-2022-25765-pdfkit-Exploit-Reverse-Shell.svg) ![forks](https://img.shields.io/github/forks/PurpleWaveIO/CVE-2022-25765-pdfkit-Exploit-Reverse-Shell.svg)


## CVE-2022-0439
 The Email Subscribers &amp; Newsletters WordPress plugin before 5.3.2 does not correctly escape the `order` and `orderby` parameters to the `ajax_fetch_report_list` action, making it vulnerable to blind SQL injection attacks by users with roles as low as Subscriber. Further, it does not have any CSRF protection in place for the action, allowing an attacker to trick any logged in user to perform the action by clicking a link.

- [https://github.com/RandomRobbieBF/CVE-2022-0439](https://github.com/RandomRobbieBF/CVE-2022-0439) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2022-0439.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2022-0439.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/MatanelGordon/docker-cve-2021-41773](https://github.com/MatanelGordon/docker-cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/MatanelGordon/docker-cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/MatanelGordon/docker-cve-2021-41773.svg)


## CVE-2021-3490
 The eBPF ALU32 bounds tracking for bitwise ops (AND, OR and XOR) in the Linux kernel did not properly update 32-bit bounds, which could be turned into out of bounds reads and writes in the Linux kernel and therefore, arbitrary code execution. This issue was fixed via commit 049c4e13714e (&quot;bpf: Fix alu32 const subreg bound tracking on bitwise operations&quot;) (v5.13-rc4) and backported to the stable kernels in v5.12.4, v5.11.21, and v5.10.37. The AND/OR issues were introduced by commit 3f50f132d840 (&quot;bpf: Verifier, do explicit ALU32 bounds tracking&quot;) (5.7-rc1) and the XOR variant was introduced by 2921c90d4718 (&quot;bpf:Fix a verifier failure with xor&quot;) ( 5.10-rc1).

- [https://github.com/pivik271/CVE-2021-3490](https://github.com/pivik271/CVE-2021-3490) :  ![starts](https://img.shields.io/github/stars/pivik271/CVE-2021-3490.svg) ![forks](https://img.shields.io/github/forks/pivik271/CVE-2021-3490.svg)


## CVE-2021-2047
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core Components). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, and 12.2.1.3.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/somatrasss/weblogic2021](https://github.com/somatrasss/weblogic2021) :  ![starts](https://img.shields.io/github/stars/somatrasss/weblogic2021.svg) ![forks](https://img.shields.io/github/forks/somatrasss/weblogic2021.svg)


## CVE-2019-1041
 An elevation of privilege vulnerability exists when the Windows kernel fails to properly handle objects in memory, aka 'Windows Kernel Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-1065.

- [https://github.com/5l1v3r1/CVE-2019-1041](https://github.com/5l1v3r1/CVE-2019-1041) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2019-1041.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2019-1041.svg)


## CVE-2018-16763
 FUEL CMS 1.4.1 allows PHP Code Evaluation via the pages/select/ filter parameter or the preview/ data parameter. This can lead to Pre-Auth Remote Code Execution.

- [https://github.com/antisecc/CVE-2018-16763](https://github.com/antisecc/CVE-2018-16763) :  ![starts](https://img.shields.io/github/stars/antisecc/CVE-2018-16763.svg) ![forks](https://img.shields.io/github/forks/antisecc/CVE-2018-16763.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/Zeeshan-1234/CVE-2018-6574](https://github.com/Zeeshan-1234/CVE-2018-6574) :  ![starts](https://img.shields.io/github/stars/Zeeshan-1234/CVE-2018-6574.svg) ![forks](https://img.shields.io/github/forks/Zeeshan-1234/CVE-2018-6574.svg)


## CVE-2014-6287
 The findMacroMarker function in parserLib.pas in Rejetto HTTP File Server (aks HFS or HttpFileServer) 2.3x before 2.3c allows remote attackers to execute arbitrary programs via a %00 sequence in a search action.

- [https://github.com/roughiz/cve-2014-6287.py](https://github.com/roughiz/cve-2014-6287.py) :  ![starts](https://img.shields.io/github/stars/roughiz/cve-2014-6287.py.svg) ![forks](https://img.shields.io/github/forks/roughiz/cve-2014-6287.py.svg)

