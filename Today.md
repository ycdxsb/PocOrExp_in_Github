# Update 2025-08-28
## CVE-2025-57773
 DataEase is an open source business intelligence and data visualization tool. Prior to version 2.10.12, because DB2 parameters are not filtered, a JNDI injection attack can be directly launched. JNDI triggers an AspectJWeaver deserialization attack, writing to various files. This vulnerability requires commons-collections 4.x and aspectjweaver-1.9.22.jar. The vulnerability has been fixed in version 2.10.12.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-57773](https://github.com/B1ack4sh/Blackash-CVE-2025-57773) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-57773.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-57773.svg)


## CVE-2025-33073
 Improper access control in Windows SMB allows an authorized attacker to elevate privileges over a network.

- [https://github.com/matejsmycka/CVE-2025-33073-checker](https://github.com/matejsmycka/CVE-2025-33073-checker) :  ![starts](https://img.shields.io/github/stars/matejsmycka/CVE-2025-33073-checker.svg) ![forks](https://img.shields.io/github/forks/matejsmycka/CVE-2025-33073-checker.svg)


## CVE-2025-26417
 In checkWhetherCallingAppHasAccess of DownloadProvider.java, there is a possible bypass of user consent when opening files in shared storage due to a confused deputy. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/uthrasri/CVE-2025-26417](https://github.com/uthrasri/CVE-2025-26417) :  ![starts](https://img.shields.io/github/stars/uthrasri/CVE-2025-26417.svg) ![forks](https://img.shields.io/github/forks/uthrasri/CVE-2025-26417.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/ibadovulfat/CVE-2025-24893_HackTheBox-Editor-Writeup](https://github.com/ibadovulfat/CVE-2025-24893_HackTheBox-Editor-Writeup) :  ![starts](https://img.shields.io/github/stars/ibadovulfat/CVE-2025-24893_HackTheBox-Editor-Writeup.svg) ![forks](https://img.shields.io/github/forks/ibadovulfat/CVE-2025-24893_HackTheBox-Editor-Writeup.svg)
- [https://github.com/torjan0/xwiki_solrsearch-rce-exploit](https://github.com/torjan0/xwiki_solrsearch-rce-exploit) :  ![starts](https://img.shields.io/github/stars/torjan0/xwiki_solrsearch-rce-exploit.svg) ![forks](https://img.shields.io/github/forks/torjan0/xwiki_solrsearch-rce-exploit.svg)


## CVE-2025-8088
     from ESET.

- [https://github.com/pescada-dev/-CVE-2025-8088](https://github.com/pescada-dev/-CVE-2025-8088) :  ![starts](https://img.shields.io/github/stars/pescada-dev/-CVE-2025-8088.svg) ![forks](https://img.shields.io/github/forks/pescada-dev/-CVE-2025-8088.svg)
- [https://github.com/DeepBlue-dot/CVE-2025-8088-WinRAR-Startup-PoC](https://github.com/DeepBlue-dot/CVE-2025-8088-WinRAR-Startup-PoC) :  ![starts](https://img.shields.io/github/stars/DeepBlue-dot/CVE-2025-8088-WinRAR-Startup-PoC.svg) ![forks](https://img.shields.io/github/forks/DeepBlue-dot/CVE-2025-8088-WinRAR-Startup-PoC.svg)
- [https://github.com/AdityaBhatt3010/CVE-2025-8088-WinRAR-Zero-Day-Path-Traversal](https://github.com/AdityaBhatt3010/CVE-2025-8088-WinRAR-Zero-Day-Path-Traversal) :  ![starts](https://img.shields.io/github/stars/AdityaBhatt3010/CVE-2025-8088-WinRAR-Zero-Day-Path-Traversal.svg) ![forks](https://img.shields.io/github/forks/AdityaBhatt3010/CVE-2025-8088-WinRAR-Zero-Day-Path-Traversal.svg)


## CVE-2024-49740
 In multiple locations, there is a possible crash loop due to resource exhaustion. This could lead to local denial of service with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/SpiralBL0CK/cve2024-49740](https://github.com/SpiralBL0CK/cve2024-49740) :  ![starts](https://img.shields.io/github/stars/SpiralBL0CK/cve2024-49740.svg) ![forks](https://img.shields.io/github/forks/SpiralBL0CK/cve2024-49740.svg)


## CVE-2023-45866
 Bluetooth HID Hosts in BlueZ may permit an unauthenticated Peripheral role HID Device to initiate and establish an encrypted connection, and accept HID keyboard reports, potentially permitting injection of HID messages when no user interaction has occurred in the Central role to authorize such access. An example affected package is bluez 5.64-0ubuntu1 in Ubuntu 22.04LTS. NOTE: in some cases, a CVE-2020-0556 mitigation would have already addressed this Bluetooth HID Hosts issue.

- [https://github.com/Sergeb250/BlueDucky](https://github.com/Sergeb250/BlueDucky) :  ![starts](https://img.shields.io/github/stars/Sergeb250/BlueDucky.svg) ![forks](https://img.shields.io/github/forks/Sergeb250/BlueDucky.svg)


## CVE-2023-45539
 HAProxy before 2.8.2 accepts # as part of the URI component, which might allow remote attackers to obtain sensitive information or have unspecified other impact upon misinterpretation of a path_end rule, such as routing index.html#.png to a static server.

- [https://github.com/slicingmelon/HAProxy-CVE-2023-45539-PoC](https://github.com/slicingmelon/HAProxy-CVE-2023-45539-PoC) :  ![starts](https://img.shields.io/github/stars/slicingmelon/HAProxy-CVE-2023-45539-PoC.svg) ![forks](https://img.shields.io/github/forks/slicingmelon/HAProxy-CVE-2023-45539-PoC.svg)


## CVE-2023-21768
 Windows Ancillary Function Driver for WinSock Elevation of Privilege Vulnerability

- [https://github.com/radoi-teodor/CVE-2023-21768-DSE-Bypass](https://github.com/radoi-teodor/CVE-2023-21768-DSE-Bypass) :  ![starts](https://img.shields.io/github/stars/radoi-teodor/CVE-2023-21768-DSE-Bypass.svg) ![forks](https://img.shields.io/github/forks/radoi-teodor/CVE-2023-21768-DSE-Bypass.svg)


## CVE-2023-21125
 In btif_hh_hsdata_rpt_copy_cb of bta_hh.cc, there is a possible way to corrupt memory due to a use after free. This could lead to local escalation of privilege over Bluetooth with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/761669642/Mahesh-970-CVE-2023-21125_bluedriod_repo](https://github.com/761669642/Mahesh-970-CVE-2023-21125_bluedriod_repo) :  ![starts](https://img.shields.io/github/stars/761669642/Mahesh-970-CVE-2023-21125_bluedriod_repo.svg) ![forks](https://img.shields.io/github/forks/761669642/Mahesh-970-CVE-2023-21125_bluedriod_repo.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/stfnw/Debugging_Dirty_Pipe_CVE-2022-0847](https://github.com/stfnw/Debugging_Dirty_Pipe_CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/stfnw/Debugging_Dirty_Pipe_CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/stfnw/Debugging_Dirty_Pipe_CVE-2022-0847.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/TheLastVvV/CVE-2021-41773](https://github.com/TheLastVvV/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/TheLastVvV/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/TheLastVvV/CVE-2021-41773.svg)
- [https://github.com/vuongnv3389-sec/cve-2021-41773](https://github.com/vuongnv3389-sec/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/vuongnv3389-sec/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/vuongnv3389-sec/cve-2021-41773.svg)
- [https://github.com/Fa1c0n35/CVE-2021-41773](https://github.com/Fa1c0n35/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Fa1c0n35/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Fa1c0n35/CVE-2021-41773.svg)
- [https://github.com/skentagon/CVE-2021-41773](https://github.com/skentagon/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/skentagon/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/skentagon/CVE-2021-41773.svg)


## CVE-2019-11043
 In PHP versions 7.1.x below 7.1.33, 7.2.x below 7.2.24 and 7.3.x below 7.3.11 in certain configurations of FPM setup it is possible to cause FPM module to write past allocated buffers into the space reserved for FCGI protocol data, thus opening the possibility of remote code execution.

- [https://github.com/a1ex-var1amov/ctf-cve-2019-11043](https://github.com/a1ex-var1amov/ctf-cve-2019-11043) :  ![starts](https://img.shields.io/github/stars/a1ex-var1amov/ctf-cve-2019-11043.svg) ![forks](https://img.shields.io/github/forks/a1ex-var1amov/ctf-cve-2019-11043.svg)


## CVE-2018-19323
 The GDrv low-level driver in GIGABYTE APP Center v1.05.21 and earlier, AORUS GRAPHICS ENGINE before 1.57, XTREME GAMING ENGINE before 1.26, and OC GURU II v2.08 exposes functionality to read and write Machine Specific Registers (MSRs).

- [https://github.com/blueisbeautiful/CVE-2018-19323](https://github.com/blueisbeautiful/CVE-2018-19323) :  ![starts](https://img.shields.io/github/stars/blueisbeautiful/CVE-2018-19323.svg) ![forks](https://img.shields.io/github/forks/blueisbeautiful/CVE-2018-19323.svg)


## CVE-2007-2447
 The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function, when the "username map script" smb.conf option is enabled, and allows remote authenticated users to execute commands via shell metacharacters involving other MS-RPC functions in the (2) remote printer and (3) file share management.

- [https://github.com/nika0x38/CVE-2007-2447](https://github.com/nika0x38/CVE-2007-2447) :  ![starts](https://img.shields.io/github/stars/nika0x38/CVE-2007-2447.svg) ![forks](https://img.shields.io/github/forks/nika0x38/CVE-2007-2447.svg)

