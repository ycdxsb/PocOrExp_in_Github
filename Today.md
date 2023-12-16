# Update 2023-12-16
## CVE-2023-49954
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/CVE-2023-49954/CVE-2023-49954.github.io](https://github.com/CVE-2023-49954/CVE-2023-49954.github.io) :  ![starts](https://img.shields.io/github/stars/CVE-2023-49954/CVE-2023-49954.github.io.svg) ![forks](https://img.shields.io/github/forks/CVE-2023-49954/CVE-2023-49954.github.io.svg)


## CVE-2023-49070
 Pre-auth RCE in Apache Ofbiz 18.12.09. It's due to XML-RPC no longer maintained still present. This issue affects Apache OFBiz: before 18.12.10. Users are recommended to upgrade to version 18.12.10

- [https://github.com/abdoghazy2015/ofbiz-CVE-2023-49070-RCE-POC](https://github.com/abdoghazy2015/ofbiz-CVE-2023-49070-RCE-POC) :  ![starts](https://img.shields.io/github/stars/abdoghazy2015/ofbiz-CVE-2023-49070-RCE-POC.svg) ![forks](https://img.shields.io/github/forks/abdoghazy2015/ofbiz-CVE-2023-49070-RCE-POC.svg)


## CVE-2023-22524
 Certain versions of the Atlassian Companion App for MacOS were affected by a remote code execution vulnerability. An attacker could utilize WebSockets to bypass Atlassian Companion&#8217;s blocklist and MacOS Gatekeeper to allow execution of code.

- [https://github.com/ron-imperva/CVE-2023-22524](https://github.com/ron-imperva/CVE-2023-22524) :  ![starts](https://img.shields.io/github/stars/ron-imperva/CVE-2023-22524.svg) ![forks](https://img.shields.io/github/forks/ron-imperva/CVE-2023-22524.svg)
- [https://github.com/imperva/CVE-2023-22524](https://github.com/imperva/CVE-2023-22524) :  ![starts](https://img.shields.io/github/stars/imperva/CVE-2023-22524.svg) ![forks](https://img.shields.io/github/forks/imperva/CVE-2023-22524.svg)


## CVE-2023-4911
 A buffer overflow was discovered in the GNU C Library's dynamic loader ld.so while processing the GLIBC_TUNABLES environment variable. This issue could allow a local attacker to use maliciously crafted GLIBC_TUNABLES environment variables when launching binaries with SUID permission to execute code with elevated privileges.

- [https://github.com/xiaoQ1z/CVE-2023-4911](https://github.com/xiaoQ1z/CVE-2023-4911) :  ![starts](https://img.shields.io/github/stars/xiaoQ1z/CVE-2023-4911.svg) ![forks](https://img.shields.io/github/forks/xiaoQ1z/CVE-2023-4911.svg)


## CVE-2023-4208
 A use-after-free vulnerability in the Linux kernel's net/sched: cls_u32 component can be exploited to achieve local privilege escalation. When u32_change() is called on an existing filter, the whole tcf_result struct is always copied into the new instance of the filter. This causes a problem when updating a filter bound to a class, as tcf_unbind_filter() is always called on the old instance in the success path, decreasing filter_cnt of the still referenced class and allowing it to be deleted, leading to a use-after-free. We recommend upgrading past commit 3044b16e7c6fe5d24b1cdbcf1bd0a9d92d1ebd81.

- [https://github.com/hshivhare67/Kernel_4.1.15_CVE-2023-4206_CVE-2023-4207_CVE-2023-4208](https://github.com/hshivhare67/Kernel_4.1.15_CVE-2023-4206_CVE-2023-4207_CVE-2023-4208) :  ![starts](https://img.shields.io/github/stars/hshivhare67/Kernel_4.1.15_CVE-2023-4206_CVE-2023-4207_CVE-2023-4208.svg) ![forks](https://img.shields.io/github/forks/hshivhare67/Kernel_4.1.15_CVE-2023-4206_CVE-2023-4207_CVE-2023-4208.svg)


## CVE-2023-4207
 A use-after-free vulnerability in the Linux kernel's net/sched: cls_fw component can be exploited to achieve local privilege escalation. When fw_change() is called on an existing filter, the whole tcf_result struct is always copied into the new instance of the filter. This causes a problem when updating a filter bound to a class, as tcf_unbind_filter() is always called on the old instance in the success path, decreasing filter_cnt of the still referenced class and allowing it to be deleted, leading to a use-after-free. We recommend upgrading past commit 76e42ae831991c828cffa8c37736ebfb831ad5ec.

- [https://github.com/hshivhare67/Kernel_4.1.15_CVE-2023-4206_CVE-2023-4207_CVE-2023-4208](https://github.com/hshivhare67/Kernel_4.1.15_CVE-2023-4206_CVE-2023-4207_CVE-2023-4208) :  ![starts](https://img.shields.io/github/stars/hshivhare67/Kernel_4.1.15_CVE-2023-4206_CVE-2023-4207_CVE-2023-4208.svg) ![forks](https://img.shields.io/github/forks/hshivhare67/Kernel_4.1.15_CVE-2023-4206_CVE-2023-4207_CVE-2023-4208.svg)


## CVE-2023-4206
 A use-after-free vulnerability in the Linux kernel's net/sched: cls_route component can be exploited to achieve local privilege escalation. When route4_change() is called on an existing filter, the whole tcf_result struct is always copied into the new instance of the filter. This causes a problem when updating a filter bound to a class, as tcf_unbind_filter() is always called on the old instance in the success path, decreasing filter_cnt of the still referenced class and allowing it to be deleted, leading to a use-after-free. We recommend upgrading past commit b80b829e9e2c1b3f7aae34855e04d8f6ecaf13c8.

- [https://github.com/hshivhare67/Kernel_4.1.15_CVE-2023-4206_CVE-2023-4207_CVE-2023-4208](https://github.com/hshivhare67/Kernel_4.1.15_CVE-2023-4206_CVE-2023-4207_CVE-2023-4208) :  ![starts](https://img.shields.io/github/stars/hshivhare67/Kernel_4.1.15_CVE-2023-4206_CVE-2023-4207_CVE-2023-4208.svg) ![forks](https://img.shields.io/github/forks/hshivhare67/Kernel_4.1.15_CVE-2023-4206_CVE-2023-4207_CVE-2023-4208.svg)


## CVE-2023-3519
 Unauthenticated remote code execution

- [https://github.com/securekomodo/citrixInspector](https://github.com/securekomodo/citrixInspector) :  ![starts](https://img.shields.io/github/stars/securekomodo/citrixInspector.svg) ![forks](https://img.shields.io/github/forks/securekomodo/citrixInspector.svg)


## CVE-2022-3552
 Unrestricted Upload of File with Dangerous Type in GitHub repository boxbilling/boxbilling prior to 0.0.1.

- [https://github.com/kabir0x23/CVE-2022-3552](https://github.com/kabir0x23/CVE-2022-3552) :  ![starts](https://img.shields.io/github/stars/kabir0x23/CVE-2022-3552.svg) ![forks](https://img.shields.io/github/forks/kabir0x23/CVE-2022-3552.svg)


## CVE-2021-26086
 Affected versions of Atlassian Jira Server and Data Center allow remote attackers to read particular files via a path traversal vulnerability in the /WEB-INF/web.xml endpoint. The affected versions are before version 8.5.14, from version 8.6.0 before 8.13.6, and from version 8.14.0 before 8.16.1.

- [https://github.com/Jeromeyoung/CVE-2021-26086](https://github.com/Jeromeyoung/CVE-2021-26086) :  ![starts](https://img.shields.io/github/stars/Jeromeyoung/CVE-2021-26086.svg) ![forks](https://img.shields.io/github/forks/Jeromeyoung/CVE-2021-26086.svg)


## CVE-2021-3656
 A flaw was found in the KVM's AMD code for supporting SVM nested virtualization. The flaw occurs when processing the VMCB (virtual machine control block) provided by the L1 guest to spawn/handle a nested guest (L2). Due to improper validation of the &quot;virt_ext&quot; field, this issue could allow a malicious L1 to disable both VMLOAD/VMSAVE intercepts and VLS (Virtual VMLOAD/VMSAVE) for the L2 guest. As a result, the L2 guest would be allowed to read/write physical pages of the host, resulting in a crash of the entire system, leak of sensitive data or potential guest-to-host escape.

- [https://github.com/rami08448/CVE-2021-3656-Demo](https://github.com/rami08448/CVE-2021-3656-Demo) :  ![starts](https://img.shields.io/github/stars/rami08448/CVE-2021-3656-Demo.svg) ![forks](https://img.shields.io/github/forks/rami08448/CVE-2021-3656-Demo.svg)


## CVE-2021-3560
 It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user. This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/markyu0401/CVE-2021-3560-Polkit-Privilege-Escalation](https://github.com/markyu0401/CVE-2021-3560-Polkit-Privilege-Escalation) :  ![starts](https://img.shields.io/github/stars/markyu0401/CVE-2021-3560-Polkit-Privilege-Escalation.svg) ![forks](https://img.shields.io/github/forks/markyu0401/CVE-2021-3560-Polkit-Privilege-Escalation.svg)


## CVE-2020-27223
 In Eclipse Jetty 9.4.6.v20170531 to 9.4.36.v20210114 (inclusive), 10.0.0, and 11.0.0 when Jetty handles a request containing multiple Accept headers with a large number of &#8220;quality&#8221; (i.e. q) parameters, the server may enter a denial of service (DoS) state due to high CPU usage processing those quality values, resulting in minutes of CPU time exhausted processing those quality values.

- [https://github.com/motikan2010/CVE-2020-27223](https://github.com/motikan2010/CVE-2020-27223) :  ![starts](https://img.shields.io/github/stars/motikan2010/CVE-2020-27223.svg) ![forks](https://img.shields.io/github/forks/motikan2010/CVE-2020-27223.svg)


## CVE-2020-1472
 An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC), aka 'Netlogon Elevation of Privilege Vulnerability'.

- [https://github.com/VoidSec/CVE-2020-1472](https://github.com/VoidSec/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/VoidSec/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/VoidSec/CVE-2020-1472.svg)
- [https://github.com/bb00/zer0dump](https://github.com/bb00/zer0dump) :  ![starts](https://img.shields.io/github/stars/bb00/zer0dump.svg) ![forks](https://img.shields.io/github/forks/bb00/zer0dump.svg)
- [https://github.com/Rvn0xsy/ZeroLogon](https://github.com/Rvn0xsy/ZeroLogon) :  ![starts](https://img.shields.io/github/stars/Rvn0xsy/ZeroLogon.svg) ![forks](https://img.shields.io/github/forks/Rvn0xsy/ZeroLogon.svg)
- [https://github.com/YossiSassi/ZeroLogon-Exploitation-Check](https://github.com/YossiSassi/ZeroLogon-Exploitation-Check) :  ![starts](https://img.shields.io/github/stars/YossiSassi/ZeroLogon-Exploitation-Check.svg) ![forks](https://img.shields.io/github/forks/YossiSassi/ZeroLogon-Exploitation-Check.svg)
- [https://github.com/CPO-EH/CVE-2020-1472_ZeroLogonChecker](https://github.com/CPO-EH/CVE-2020-1472_ZeroLogonChecker) :  ![starts](https://img.shields.io/github/stars/CPO-EH/CVE-2020-1472_ZeroLogonChecker.svg) ![forks](https://img.shields.io/github/forks/CPO-EH/CVE-2020-1472_ZeroLogonChecker.svg)
- [https://github.com/striveben/CVE-2020-1472](https://github.com/striveben/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/striveben/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/striveben/CVE-2020-1472.svg)
- [https://github.com/0xkami/CVE-2020-1472](https://github.com/0xkami/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/0xkami/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/0xkami/CVE-2020-1472.svg)
- [https://github.com/NAXG/CVE-2020-1472](https://github.com/NAXG/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/NAXG/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/NAXG/CVE-2020-1472.svg)
- [https://github.com/Fa1c0n35/CVE-2020-1472](https://github.com/Fa1c0n35/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/Fa1c0n35/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/Fa1c0n35/CVE-2020-1472.svg)
- [https://github.com/hell-moon/ZeroLogon-Exploit](https://github.com/hell-moon/ZeroLogon-Exploit) :  ![starts](https://img.shields.io/github/stars/hell-moon/ZeroLogon-Exploit.svg) ![forks](https://img.shields.io/github/forks/hell-moon/ZeroLogon-Exploit.svg)
- [https://github.com/Tobey123/CVE-2020-1472-visualizer](https://github.com/Tobey123/CVE-2020-1472-visualizer) :  ![starts](https://img.shields.io/github/stars/Tobey123/CVE-2020-1472-visualizer.svg) ![forks](https://img.shields.io/github/forks/Tobey123/CVE-2020-1472-visualizer.svg)
- [https://github.com/likeww/MassZeroLogon](https://github.com/likeww/MassZeroLogon) :  ![starts](https://img.shields.io/github/stars/likeww/MassZeroLogon.svg) ![forks](https://img.shields.io/github/forks/likeww/MassZeroLogon.svg)


## CVE-2019-6340
 Some field types do not properly sanitize data from non-form sources in Drupal 8.5.x before 8.5.11 and Drupal 8.6.x before 8.6.10. This can lead to arbitrary PHP code execution in some cases. A site is only affected by this if one of the following conditions is met: The site has the Drupal 8 core RESTful Web Services (rest) module enabled and allows PATCH or POST requests, or the site has another web services module enabled, like JSON:API in Drupal 8, or Services or RESTful Web Services in Drupal 7. (Note: The Drupal 7 Services module itself does not require an update at this time, but you should apply other contributed updates associated with this advisory if Services is in use.)

- [https://github.com/zhzyker/exphub](https://github.com/zhzyker/exphub) :  ![starts](https://img.shields.io/github/stars/zhzyker/exphub.svg) ![forks](https://img.shields.io/github/forks/zhzyker/exphub.svg)
- [https://github.com/jas502n/CVE-2019-6340](https://github.com/jas502n/CVE-2019-6340) :  ![starts](https://img.shields.io/github/stars/jas502n/CVE-2019-6340.svg) ![forks](https://img.shields.io/github/forks/jas502n/CVE-2019-6340.svg)


## CVE-2017-1000486
 Primetek Primefaces 5.x is vulnerable to a weak encryption flaw resulting in remote code execution

- [https://github.com/LongWayHomie/CVE-2017-1000486](https://github.com/LongWayHomie/CVE-2017-1000486) :  ![starts](https://img.shields.io/github/stars/LongWayHomie/CVE-2017-1000486.svg) ![forks](https://img.shields.io/github/forks/LongWayHomie/CVE-2017-1000486.svg)


## CVE-2017-16995
 The check_alu_op function in kernel/bpf/verifier.c in the Linux kernel through 4.4 allows local users to cause a denial of service (memory corruption) or possibly have unspecified other impact by leveraging incorrect sign extension.

- [https://github.com/ZhiQiAnSecFork/cve-2017-16995](https://github.com/ZhiQiAnSecFork/cve-2017-16995) :  ![starts](https://img.shields.io/github/stars/ZhiQiAnSecFork/cve-2017-16995.svg) ![forks](https://img.shields.io/github/forks/ZhiQiAnSecFork/cve-2017-16995.svg)


## CVE-2012-2012
 HP System Management Homepage (SMH) before 7.1.1 does not have an off autocomplete attribute for unspecified form fields, which makes it easier for remote attackers to obtain access by leveraging an unattended workstation.

- [https://github.com/Ashro-one/CVE-2012-2012](https://github.com/Ashro-one/CVE-2012-2012) :  ![starts](https://img.shields.io/github/stars/Ashro-one/CVE-2012-2012.svg) ![forks](https://img.shields.io/github/forks/Ashro-one/CVE-2012-2012.svg)

