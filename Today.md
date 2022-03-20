# Update 2022-03-20
## CVE-2022-27226
 A CSRF issue in /api/crontab on iRZ Mobile Routers through 2022-03-16 allows a threat actor to create a crontab entry in the router administration panel. The cronjob will consequently execute the entry on the threat actor's defined interval, leading to remote code execution, allowing the threat actor to gain filesystem access. In addition, if the router's default credentials aren't rotated or a threat actor discovers valid credentials, remote code execution can be achieved without user interaction.

- [https://github.com/SakuraSamuraii/ez-iRZ](https://github.com/SakuraSamuraii/ez-iRZ) :  ![starts](https://img.shields.io/github/stars/SakuraSamuraii/ez-iRZ.svg) ![forks](https://img.shields.io/github/forks/SakuraSamuraii/ez-iRZ.svg)


## CVE-2022-24990
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/VVeakee/CVE-2022-24990-EXP](https://github.com/VVeakee/CVE-2022-24990-EXP) :  ![starts](https://img.shields.io/github/stars/VVeakee/CVE-2022-24990-EXP.svg) ![forks](https://img.shields.io/github/forks/VVeakee/CVE-2022-24990-EXP.svg)


## CVE-2022-22947
 In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

- [https://github.com/viemsr/spring_cloud_gateway_memshell](https://github.com/viemsr/spring_cloud_gateway_memshell) :  ![starts](https://img.shields.io/github/stars/viemsr/spring_cloud_gateway_memshell.svg) ![forks](https://img.shields.io/github/forks/viemsr/spring_cloud_gateway_memshell.svg)


## CVE-2022-22600
 The issue was addressed with improved permissions logic. This issue is fixed in tvOS 15.4, iOS 15.4 and iPadOS 15.4, macOS Monterey 12.3, watchOS 8.5. A malicious application may be able to bypass certain Privacy preferences.

- [https://github.com/acheong08/MSF-screenrecord-on-MacOS](https://github.com/acheong08/MSF-screenrecord-on-MacOS) :  ![starts](https://img.shields.io/github/stars/acheong08/MSF-screenrecord-on-MacOS.svg) ![forks](https://img.shields.io/github/forks/acheong08/MSF-screenrecord-on-MacOS.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/LudovicPatho/CVE-2022-0847](https://github.com/LudovicPatho/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/LudovicPatho/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/LudovicPatho/CVE-2022-0847.svg)


## CVE-2022-0543
 It was discovered, that redis, a persistent key-value database, due to a packaging issue, is prone to a (Debian-specific) Lua sandbox escape, which could result in remote code execution.

- [https://github.com/Newbee740/REDIS-CVE-2022-0543](https://github.com/Newbee740/REDIS-CVE-2022-0543) :  ![starts](https://img.shields.io/github/stars/Newbee740/REDIS-CVE-2022-0543.svg) ![forks](https://img.shields.io/github/forks/Newbee740/REDIS-CVE-2022-0543.svg)


## CVE-2021-45010
 A Path traversal vulnerability in the file upload functionality in tinyfilemanager.php in Tiny File Manager Project's Tiny File Manager &lt;= 2.4.6 allows remote attackers with valid user accounts to upload malicious PHP files to the webroot and achieve code execution on the target server.

- [https://github.com/febinrev/CVE-2021-45010-TinyFileManager-Exploit](https://github.com/febinrev/CVE-2021-45010-TinyFileManager-Exploit) :  ![starts](https://img.shields.io/github/stars/febinrev/CVE-2021-45010-TinyFileManager-Exploit.svg) ![forks](https://img.shields.io/github/forks/febinrev/CVE-2021-45010-TinyFileManager-Exploit.svg)


## CVE-2021-30955
 A race condition was addressed with improved state handling. This issue is fixed in macOS Monterey 12.1, watchOS 8.3, iOS 15.2 and iPadOS 15.2, tvOS 15.2. A malicious application may be able to execute arbitrary code with kernel privileges.

- [https://github.com/GeoSn0w/Pentagram-exploit-tester](https://github.com/GeoSn0w/Pentagram-exploit-tester) :  ![starts](https://img.shields.io/github/stars/GeoSn0w/Pentagram-exploit-tester.svg) ![forks](https://img.shields.io/github/forks/GeoSn0w/Pentagram-exploit-tester.svg)


## CVE-2021-28476
 Hyper-V Remote Code Execution Vulnerability

- [https://github.com/2273852279qqs/0vercl0k](https://github.com/2273852279qqs/0vercl0k) :  ![starts](https://img.shields.io/github/stars/2273852279qqs/0vercl0k.svg) ![forks](https://img.shields.io/github/forks/2273852279qqs/0vercl0k.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/Ankit-Ojha16/CVE-2021-4034](https://github.com/Ankit-Ojha16/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Ankit-Ojha16/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Ankit-Ojha16/CVE-2021-4034.svg)
- [https://github.com/J0hnbX/CVE-2021-4034-new](https://github.com/J0hnbX/CVE-2021-4034-new) :  ![starts](https://img.shields.io/github/stars/J0hnbX/CVE-2021-4034-new.svg) ![forks](https://img.shields.io/github/forks/J0hnbX/CVE-2021-4034-new.svg)
- [https://github.com/hackingyseguridad/CVE-2021-4034](https://github.com/hackingyseguridad/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/hackingyseguridad/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/hackingyseguridad/CVE-2021-4034.svg)


## CVE-2021-3708
 D-Link router DSL-2750U with firmware vME1.16 or prior versions is vulnerable to OS command injection. An unauthenticated attacker on the local network may exploit this, with CVE-2021-3707, to execute any OS commands on the vulnerable device.

- [https://github.com/HadiMed/DSL-2750U-Full-chain](https://github.com/HadiMed/DSL-2750U-Full-chain) :  ![starts](https://img.shields.io/github/stars/HadiMed/DSL-2750U-Full-chain.svg) ![forks](https://img.shields.io/github/forks/HadiMed/DSL-2750U-Full-chain.svg)


## CVE-2019-2017
 In rw_t2t_handle_tlv_detect_rsp of rw_t2t_ndef.cc, there is a possible out-of-bound write due to a missing bounds check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-7.0 Android-7.1.1 Android-7.1.2 Android-8.0 Android-8.1 Android-9Android ID: A-121035711

- [https://github.com/grmono/CVE2019-2017_POC](https://github.com/grmono/CVE2019-2017_POC) :  ![starts](https://img.shields.io/github/stars/grmono/CVE2019-2017_POC.svg) ![forks](https://img.shields.io/github/forks/grmono/CVE2019-2017_POC.svg)


## CVE-2017-6090
 Unrestricted file upload vulnerability in clients/editclient.php in PhpCollab 2.5.1 and earlier allows remote authenticated users to execute arbitrary code by uploading a file with an executable extension, then accessing it via a direct request to the file in logos_clients/.

- [https://github.com/jlk/exploit-CVE-2017-6090](https://github.com/jlk/exploit-CVE-2017-6090) :  ![starts](https://img.shields.io/github/stars/jlk/exploit-CVE-2017-6090.svg) ![forks](https://img.shields.io/github/forks/jlk/exploit-CVE-2017-6090.svg)


## CVE-2017-0075
 Hyper-V in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows guest OS users to execute arbitrary code on the host OS via a crafted application, aka &quot;Hyper-V Remote Code Execution Vulnerability.&quot; This vulnerability is different from that described in CVE-2017-0109.

- [https://github.com/belyakovvitagmailt/4B5F5F4Bp](https://github.com/belyakovvitagmailt/4B5F5F4Bp) :  ![starts](https://img.shields.io/github/stars/belyakovvitagmailt/4B5F5F4Bp.svg) ![forks](https://img.shields.io/github/forks/belyakovvitagmailt/4B5F5F4Bp.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka &quot;Dirty COW.&quot;

- [https://github.com/vinspiert/scumjrs](https://github.com/vinspiert/scumjrs) :  ![starts](https://img.shields.io/github/stars/vinspiert/scumjrs.svg) ![forks](https://img.shields.io/github/forks/vinspiert/scumjrs.svg)

