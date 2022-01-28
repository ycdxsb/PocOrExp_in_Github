# Update 2022-01-28
## CVE-2022-23967
 In TightVNC 1.3.10, there is an integer signedness error and resultant heap-based buffer overflow in InitialiseRFBConnection in rfbproto.c (for the vncviewer component). There is no check on the size given to malloc, e.g., -1 is accepted. This allocates a chunk of size zero, which will give a heap pointer. However, one can send 0xffffffff bytes of data, which can have a DoS impact or lead to remote code execution.

- [https://github.com/MaherAzzouzi/CVE-2022-23967](https://github.com/MaherAzzouzi/CVE-2022-23967) :  ![starts](https://img.shields.io/github/stars/MaherAzzouzi/CVE-2022-23967.svg) ![forks](https://img.shields.io/github/forks/MaherAzzouzi/CVE-2022-23967.svg)


## CVE-2022-22919
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/jdordonezn/CVE-2022-22919](https://github.com/jdordonezn/CVE-2022-22919) :  ![starts](https://img.shields.io/github/stars/jdordonezn/CVE-2022-22919.svg) ![forks](https://img.shields.io/github/forks/jdordonezn/CVE-2022-22919.svg)


## CVE-2022-22828
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/videnlabs/CVE-2022-22828](https://github.com/videnlabs/CVE-2022-22828) :  ![starts](https://img.shields.io/github/stars/videnlabs/CVE-2022-22828.svg) ![forks](https://img.shields.io/github/forks/videnlabs/CVE-2022-22828.svg)


## CVE-2022-21907
 HTTP Protocol Stack Remote Code Execution Vulnerability.

- [https://github.com/corelight/cve-2022-21907](https://github.com/corelight/cve-2022-21907) :  ![starts](https://img.shields.io/github/stars/corelight/cve-2022-21907.svg) ![forks](https://img.shields.io/github/forks/corelight/cve-2022-21907.svg)


## CVE-2022-21882
 Win32k Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2022-21887.

- [https://github.com/KaLendsi/CVE-2022-21882](https://github.com/KaLendsi/CVE-2022-21882) :  ![starts](https://img.shields.io/github/stars/KaLendsi/CVE-2022-21882.svg) ![forks](https://img.shields.io/github/forks/KaLendsi/CVE-2022-21882.svg)


## CVE-2022-0185
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/discordianfish/cve-2022-0185-crash-poc](https://github.com/discordianfish/cve-2022-0185-crash-poc) :  ![starts](https://img.shields.io/github/stars/discordianfish/cve-2022-0185-crash-poc.svg) ![forks](https://img.shields.io/github/forks/discordianfish/cve-2022-0185-crash-poc.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/m96dg/CVE-2021-41773-exercise](https://github.com/m96dg/CVE-2021-41773-exercise) :  ![starts](https://img.shields.io/github/stars/m96dg/CVE-2021-41773-exercise.svg) ![forks](https://img.shields.io/github/forks/m96dg/CVE-2021-41773-exercise.svg)


## CVE-2021-4034
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Al1ex/LinuxEelvation](https://github.com/Al1ex/LinuxEelvation) :  ![starts](https://img.shields.io/github/stars/Al1ex/LinuxEelvation.svg) ![forks](https://img.shields.io/github/forks/Al1ex/LinuxEelvation.svg)
- [https://github.com/ly4k/PwnKit](https://github.com/ly4k/PwnKit) :  ![starts](https://img.shields.io/github/stars/ly4k/PwnKit.svg) ![forks](https://img.shields.io/github/forks/ly4k/PwnKit.svg)
- [https://github.com/zhzyker/CVE-2021-4034](https://github.com/zhzyker/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/zhzyker/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/zhzyker/CVE-2021-4034.svg)
- [https://github.com/c3l3si4n/pwnkit](https://github.com/c3l3si4n/pwnkit) :  ![starts](https://img.shields.io/github/stars/c3l3si4n/pwnkit.svg) ![forks](https://img.shields.io/github/forks/c3l3si4n/pwnkit.svg)
- [https://github.com/PeterGottesman/pwnkit-exploit](https://github.com/PeterGottesman/pwnkit-exploit) :  ![starts](https://img.shields.io/github/stars/PeterGottesman/pwnkit-exploit.svg) ![forks](https://img.shields.io/github/forks/PeterGottesman/pwnkit-exploit.svg)
- [https://github.com/chenaotian/CVE-2021-4034](https://github.com/chenaotian/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/chenaotian/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/chenaotian/CVE-2021-4034.svg)
- [https://github.com/luijait/PwnKit-Exploit](https://github.com/luijait/PwnKit-Exploit) :  ![starts](https://img.shields.io/github/stars/luijait/PwnKit-Exploit.svg) ![forks](https://img.shields.io/github/forks/luijait/PwnKit-Exploit.svg)
- [https://github.com/Anonymous-Family/CVE-2021-4034](https://github.com/Anonymous-Family/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Anonymous-Family/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Anonymous-Family/CVE-2021-4034.svg)
- [https://github.com/dadvlingd/-CVE-2021-4034](https://github.com/dadvlingd/-CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/dadvlingd/-CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/dadvlingd/-CVE-2021-4034.svg)
- [https://github.com/joeammond/CVE-2021-4034](https://github.com/joeammond/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/joeammond/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/joeammond/CVE-2021-4034.svg)
- [https://github.com/kimusan/pkwner](https://github.com/kimusan/pkwner) :  ![starts](https://img.shields.io/github/stars/kimusan/pkwner.svg) ![forks](https://img.shields.io/github/forks/kimusan/pkwner.svg)
- [https://github.com/callrbx/pkexec-lpe-poc](https://github.com/callrbx/pkexec-lpe-poc) :  ![starts](https://img.shields.io/github/stars/callrbx/pkexec-lpe-poc.svg) ![forks](https://img.shields.io/github/forks/callrbx/pkexec-lpe-poc.svg)
- [https://github.com/moldabekov/CVE-2021-4034](https://github.com/moldabekov/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/moldabekov/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/moldabekov/CVE-2021-4034.svg)
- [https://github.com/mike-artemis/cve-2021-4034](https://github.com/mike-artemis/cve-2021-4034) :  ![starts](https://img.shields.io/github/stars/mike-artemis/cve-2021-4034.svg) ![forks](https://img.shields.io/github/forks/mike-artemis/cve-2021-4034.svg)
- [https://github.com/whokilleddb/CVE-2021-4034](https://github.com/whokilleddb/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/whokilleddb/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/whokilleddb/CVE-2021-4034.svg)
- [https://github.com/LukeGix/CVE-2021-4034](https://github.com/LukeGix/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/LukeGix/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/LukeGix/CVE-2021-4034.svg)
- [https://github.com/T3cnokarita/CVE-2021-4034](https://github.com/T3cnokarita/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/T3cnokarita/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/T3cnokarita/CVE-2021-4034.svg)
- [https://github.com/san3ncrypt3d/CVE-2021-4034-POC](https://github.com/san3ncrypt3d/CVE-2021-4034-POC) :  ![starts](https://img.shields.io/github/stars/san3ncrypt3d/CVE-2021-4034-POC.svg) ![forks](https://img.shields.io/github/forks/san3ncrypt3d/CVE-2021-4034-POC.svg)
- [https://github.com/1nf1n17yk1ng/CVE-2021-4034](https://github.com/1nf1n17yk1ng/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/1nf1n17yk1ng/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/1nf1n17yk1ng/CVE-2021-4034.svg)
- [https://github.com/Immersive-Labs-Sec/CVE-2021-4034](https://github.com/Immersive-Labs-Sec/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Immersive-Labs-Sec/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Immersive-Labs-Sec/CVE-2021-4034.svg)
- [https://github.com/aus-mate/CVE-2021-4034-POC](https://github.com/aus-mate/CVE-2021-4034-POC) :  ![starts](https://img.shields.io/github/stars/aus-mate/CVE-2021-4034-POC.svg) ![forks](https://img.shields.io/github/forks/aus-mate/CVE-2021-4034-POC.svg)
- [https://github.com/N1et/CVE-2021-4034](https://github.com/N1et/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/N1et/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/N1et/CVE-2021-4034.svg)
- [https://github.com/sunny0day/CVE-2021-4034](https://github.com/sunny0day/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/sunny0day/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/sunny0day/CVE-2021-4034.svg)
- [https://github.com/vilasboasph/CVE-2021-4034](https://github.com/vilasboasph/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/vilasboasph/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/vilasboasph/CVE-2021-4034.svg)
- [https://github.com/robemmerson/CVE-2021-4034](https://github.com/robemmerson/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/robemmerson/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/robemmerson/CVE-2021-4034.svg)
- [https://github.com/phvilasboas/CVE-2021-4034](https://github.com/phvilasboas/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/phvilasboas/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/phvilasboas/CVE-2021-4034.svg)
- [https://github.com/cd80-ctf/CVE-2021-4034](https://github.com/cd80-ctf/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/cd80-ctf/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/cd80-ctf/CVE-2021-4034.svg)
- [https://github.com/Nero22k/CVE-2021-4034](https://github.com/Nero22k/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Nero22k/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Nero22k/CVE-2021-4034.svg)
- [https://github.com/J0hnbX/CVE-2021-4034-new](https://github.com/J0hnbX/CVE-2021-4034-new) :  ![starts](https://img.shields.io/github/stars/J0hnbX/CVE-2021-4034-new.svg) ![forks](https://img.shields.io/github/forks/J0hnbX/CVE-2021-4034-new.svg)
- [https://github.com/hackingyseguridad/CVE-2021-4034](https://github.com/hackingyseguridad/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/hackingyseguridad/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/hackingyseguridad/CVE-2021-4034.svg)
- [https://github.com/0xBruno/CVE-2021-4034](https://github.com/0xBruno/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/0xBruno/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/0xBruno/CVE-2021-4034.svg)
- [https://github.com/Al1ex/CVE-2021-4034](https://github.com/Al1ex/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2021-4034.svg)
- [https://github.com/jostmart/-CVE-2021-4034](https://github.com/jostmart/-CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/jostmart/-CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/jostmart/-CVE-2021-4034.svg)
- [https://github.com/zcrosman/cve-2021-4034](https://github.com/zcrosman/cve-2021-4034) :  ![starts](https://img.shields.io/github/stars/zcrosman/cve-2021-4034.svg) ![forks](https://img.shields.io/github/forks/zcrosman/cve-2021-4034.svg)
- [https://github.com/binksjar/cve-2021-4034](https://github.com/binksjar/cve-2021-4034) :  ![starts](https://img.shields.io/github/stars/binksjar/cve-2021-4034.svg) ![forks](https://img.shields.io/github/forks/binksjar/cve-2021-4034.svg)
- [https://github.com/azminawwar/CVE-2021-4034](https://github.com/azminawwar/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/azminawwar/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/azminawwar/CVE-2021-4034.svg)
- [https://github.com/fdellwing/CVE-2021-4034](https://github.com/fdellwing/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/fdellwing/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/fdellwing/CVE-2021-4034.svg)
- [https://github.com/xcanwin/CVE-2021-4034-UniontechOS](https://github.com/xcanwin/CVE-2021-4034-UniontechOS) :  ![starts](https://img.shields.io/github/stars/xcanwin/CVE-2021-4034-UniontechOS.svg) ![forks](https://img.shields.io/github/forks/xcanwin/CVE-2021-4034-UniontechOS.svg)
- [https://github.com/nobelh/CVE-2020-4034](https://github.com/nobelh/CVE-2020-4034) :  ![starts](https://img.shields.io/github/stars/nobelh/CVE-2020-4034.svg) ![forks](https://img.shields.io/github/forks/nobelh/CVE-2020-4034.svg)
- [https://github.com/darkerego/pwnkit](https://github.com/darkerego/pwnkit) :  ![starts](https://img.shields.io/github/stars/darkerego/pwnkit.svg) ![forks](https://img.shields.io/github/forks/darkerego/pwnkit.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via &quot;sudoedit -s&quot; and a command-line argument that ends with a single backslash character.

- [https://github.com/chenaotian/CVE-2021-3156](https://github.com/chenaotian/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/chenaotian/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/chenaotian/CVE-2021-3156.svg)


## CVE-2020-28653
 Zoho ManageEngine OpManager Stable build before 125203 (and Released build before 125233) allows Remote Code Execution via the Smart Update Manager (SUM) servlet.

- [https://github.com/tuo4n8/CVE-2020-28653](https://github.com/tuo4n8/CVE-2020-28653) :  ![starts](https://img.shields.io/github/stars/tuo4n8/CVE-2020-28653.svg) ![forks](https://img.shields.io/github/forks/tuo4n8/CVE-2020-28653.svg)


## CVE-2020-4034
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/nobelh/CVE-2020-4034](https://github.com/nobelh/CVE-2020-4034) :  ![starts](https://img.shields.io/github/stars/nobelh/CVE-2020-4034.svg) ![forks](https://img.shields.io/github/forks/nobelh/CVE-2020-4034.svg)


## CVE-2019-18839
 FUDForum 3.0.9 is vulnerable to Stored XSS via the nlogin parameter. This may result in remote code execution. An attacker can use a user account to fully compromise the system using a POST request. When the admin visits the user information, the payload will execute. This will allow for PHP files to be written to the web root, and for code to execute on the remote server.

- [https://github.com/fuzzlove/FUDforum-XSS-RCE](https://github.com/fuzzlove/FUDforum-XSS-RCE) :  ![starts](https://img.shields.io/github/stars/fuzzlove/FUDforum-XSS-RCE.svg) ![forks](https://img.shields.io/github/forks/fuzzlove/FUDforum-XSS-RCE.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/titanous/heartbleeder](https://github.com/titanous/heartbleeder) :  ![starts](https://img.shields.io/github/stars/titanous/heartbleeder.svg) ![forks](https://img.shields.io/github/forks/titanous/heartbleeder.svg)
- [https://github.com/Lekensteyn/pacemaker](https://github.com/Lekensteyn/pacemaker) :  ![starts](https://img.shields.io/github/stars/Lekensteyn/pacemaker.svg) ![forks](https://img.shields.io/github/forks/Lekensteyn/pacemaker.svg)

