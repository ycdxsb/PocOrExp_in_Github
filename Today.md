# Update 2022-08-04
## CVE-2022-36946
 nfqnl_mangle in net/netfilter/nfnetlink_queue.c in the Linux kernel through 5.18.14 allows remote attackers to cause a denial of service (panic) because, in the case of an nf_queue verdict with a one-byte nfta_payload attribute, an skb_pull can encounter a negative skb-&gt;len.

- [https://github.com/XmasSnowISBACK/CVE-2022-36946](https://github.com/XmasSnowISBACK/CVE-2022-36946) :  ![starts](https://img.shields.io/github/stars/XmasSnowISBACK/CVE-2022-36946.svg) ![forks](https://img.shields.io/github/forks/XmasSnowISBACK/CVE-2022-36946.svg)


## CVE-2022-34918
 An issue was discovered in the Linux kernel through 5.18.9. A type confusion bug in nft_set_elem_init (leading to a buffer overflow) could be used by a local attacker to escalate privileges, a different vulnerability than CVE-2022-32250. (The attacker can obtain root access, but must start with an unprivileged user namespace to obtain CAP_NET_ADMIN access.) This can be fixed in nft_setelem_parse_data in net/netfilter/nf_tables_api.c.

- [https://github.com/veritas501/CVE-2022-34918](https://github.com/veritas501/CVE-2022-34918) :  ![starts](https://img.shields.io/github/stars/veritas501/CVE-2022-34918.svg) ![forks](https://img.shields.io/github/forks/veritas501/CVE-2022-34918.svg)


## CVE-2022-33891
 The Apache Spark UI offers the possibility to enable ACLs via the configuration option spark.acls.enable. With an authentication filter, this checks whether a user has access permissions to view or modify the application. If ACLs are enabled, a code path in HttpSecurityFilter can allow someone to perform impersonation by providing an arbitrary user name. A malicious user might then be able to reach a permission check function that will ultimately build a Unix shell command based on their input, and execute it. This will result in arbitrary shell command execution as the user Spark is currently running as. This affects Apache Spark versions 3.0.3 and earlier, versions 3.1.1 to 3.1.2, and versions 3.2.0 to 3.2.1.

- [https://github.com/XmasSnowISBACK/CVE-2022-33891](https://github.com/XmasSnowISBACK/CVE-2022-33891) :  ![starts](https://img.shields.io/github/stars/XmasSnowISBACK/CVE-2022-33891.svg) ![forks](https://img.shields.io/github/forks/XmasSnowISBACK/CVE-2022-33891.svg)


## CVE-2022-28219
 Cewolf in Zoho ManageEngine ADAudit Plus before 7060 is vulnerable to an unauthenticated XXE attack that leads to Remote Code Execution.

- [https://github.com/aeifkz/CVE-2022-28219-Like](https://github.com/aeifkz/CVE-2022-28219-Like) :  ![starts](https://img.shields.io/github/stars/aeifkz/CVE-2022-28219-Like.svg) ![forks](https://img.shields.io/github/forks/aeifkz/CVE-2022-28219-Like.svg)


## CVE-2022-22947
 In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

- [https://github.com/LY613313/CVE-2022-22947](https://github.com/LY613313/CVE-2022-22947) :  ![starts](https://img.shields.io/github/stars/LY613313/CVE-2022-22947.svg) ![forks](https://img.shields.io/github/forks/LY613313/CVE-2022-22947.svg)


## CVE-2022-21661
 WordPress is a free and open-source content management system written in PHP and paired with a MariaDB database. Due to improper sanitization in WP_Query, there can be cases where SQL injection is possible through plugins or themes that use it in a certain way. This has been patched in WordPress version 5.8.3. Older affected versions are also fixed via security release, that go back till 3.7.37. We strongly recommend that you keep auto-updates enabled. There are no known workarounds for this vulnerability.

- [https://github.com/XmasSnowISBACK/CVE-2022-21661](https://github.com/XmasSnowISBACK/CVE-2022-21661) :  ![starts](https://img.shields.io/github/stars/XmasSnowISBACK/CVE-2022-21661.svg) ![forks](https://img.shields.io/github/forks/XmasSnowISBACK/CVE-2022-21661.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/XmasSnowISBACK/CVE-2022-0847-DirtyPipe-Exploits](https://github.com/XmasSnowISBACK/CVE-2022-0847-DirtyPipe-Exploits) :  ![starts](https://img.shields.io/github/stars/XmasSnowISBACK/CVE-2022-0847-DirtyPipe-Exploits.svg) ![forks](https://img.shields.io/github/forks/XmasSnowISBACK/CVE-2022-0847-DirtyPipe-Exploits.svg)


## CVE-2021-3707
 D-Link router DSL-2750U with firmware vME1.16 or prior versions is vulnerable to unauthorized configuration modification. An unauthenticated attacker on the local network may exploit this, with CVE-2021-3708, to execute any OS commands on the vulnerable device.

- [https://github.com/HadiMed/DSL-2750U-Full-chain](https://github.com/HadiMed/DSL-2750U-Full-chain) :  ![starts](https://img.shields.io/github/stars/HadiMed/DSL-2750U-Full-chain.svg) ![forks](https://img.shields.io/github/forks/HadiMed/DSL-2750U-Full-chain.svg)


## CVE-2021-3122
 CMCAgent in NCR Command Center Agent 16.3 on Aloha POS/BOH servers permits the submission of a runCommand parameter (within an XML document sent to port 8089) that enables the remote, unauthenticated execution of an arbitrary command as SYSTEM, as exploited in the wild in 2020 and/or 2021. NOTE: the vendor's position is that exploitation occurs only on devices with a certain &quot;misconfiguration.&quot;

- [https://github.com/acquiredsecurity/CVE-2021-3122-Details](https://github.com/acquiredsecurity/CVE-2021-3122-Details) :  ![starts](https://img.shields.io/github/stars/acquiredsecurity/CVE-2021-3122-Details.svg) ![forks](https://img.shields.io/github/forks/acquiredsecurity/CVE-2021-3122-Details.svg)


## CVE-2019-10092
 In Apache HTTP Server 2.4.0-2.4.39, a limited cross-site scripting issue was reported affecting the mod_proxy error page. An attacker could cause the link on the error page to be malformed and instead point to a page of their choice. This would only be exploitable where a server was set up with proxying enabled but was misconfigured in such a way that the Proxy Error page was displayed.

- [https://github.com/ro-fes/CVE2019-10092](https://github.com/ro-fes/CVE2019-10092) :  ![starts](https://img.shields.io/github/stars/ro-fes/CVE2019-10092.svg) ![forks](https://img.shields.io/github/forks/ro-fes/CVE2019-10092.svg)


## CVE-2019-6447
 The ES File Explorer File Manager application through 4.1.9.7.4 for Android allows remote attackers to read arbitrary files or execute applications via TCP port 59777 requests on the local Wi-Fi network. This TCP port remains open after the ES application has been launched once, and responds to unauthenticated application/json data over HTTP.

- [https://github.com/vino-theva/CVE-2019-6447](https://github.com/vino-theva/CVE-2019-6447) :  ![starts](https://img.shields.io/github/stars/vino-theva/CVE-2019-6447.svg) ![forks](https://img.shields.io/github/forks/vino-theva/CVE-2019-6447.svg)


## CVE-2018-4185
 In iOS before 11.3, tvOS before 11.3, watchOS before 4.3, and macOS before High Sierra 10.13.4, an information disclosure issue existed in the transition of program state. This issue was addressed with improved state handling.

- [https://github.com/xigexbh/bazad1](https://github.com/xigexbh/bazad1) :  ![starts](https://img.shields.io/github/stars/xigexbh/bazad1.svg) ![forks](https://img.shields.io/github/forks/xigexbh/bazad1.svg)


## CVE-2014-6287
 The findMacroMarker function in parserLib.pas in Rejetto HTTP File Server (aks HFS or HttpFileServer) 2.3x before 2.3c allows remote attackers to execute arbitrary programs via a %00 sequence in a search action.

- [https://github.com/mrintern/thm_steelmountain_CVE-2014-6287](https://github.com/mrintern/thm_steelmountain_CVE-2014-6287) :  ![starts](https://img.shields.io/github/stars/mrintern/thm_steelmountain_CVE-2014-6287.svg) ![forks](https://img.shields.io/github/forks/mrintern/thm_steelmountain_CVE-2014-6287.svg)


## CVE-2010-4221
 Multiple stack-based buffer overflows in the pr_netio_telnet_gets function in netio.c in ProFTPD before 1.3.3c allow remote attackers to execute arbitrary code via vectors involving a TELNET IAC escape character to a (1) FTP or (2) FTPS server.

- [https://github.com/M31MOTH/cve-2010-4221](https://github.com/M31MOTH/cve-2010-4221) :  ![starts](https://img.shields.io/github/stars/M31MOTH/cve-2010-4221.svg) ![forks](https://img.shields.io/github/forks/M31MOTH/cve-2010-4221.svg)


## CVE-2010-3904
 The rds_page_copy_user function in net/rds/page.c in the Reliable Datagram Sockets (RDS) protocol implementation in the Linux kernel before 2.6.36 does not properly validate addresses obtained from user space, which allows local users to gain privileges via crafted use of the sendmsg and recvmsg system calls.

- [https://github.com/redhatkaty/-cve-2010-3904-report](https://github.com/redhatkaty/-cve-2010-3904-report) :  ![starts](https://img.shields.io/github/stars/redhatkaty/-cve-2010-3904-report.svg) ![forks](https://img.shields.io/github/forks/redhatkaty/-cve-2010-3904-report.svg)


## CVE-2010-3332
 Microsoft .NET Framework 1.1 SP1, 2.0 SP1 and SP2, 3.5, 3.5 SP1, 3.5.1, and 4.0, as used for ASP.NET in Microsoft Internet Information Services (IIS), provides detailed error codes during decryption attempts, which allows remote attackers to decrypt and modify encrypted View State (aka __VIEWSTATE) form data, and possibly forge cookies or read application files, via a padding oracle attack, aka &quot;ASP.NET Padding Oracle Vulnerability.&quot;

- [https://github.com/bongbongco/MS10-070](https://github.com/bongbongco/MS10-070) :  ![starts](https://img.shields.io/github/stars/bongbongco/MS10-070.svg) ![forks](https://img.shields.io/github/forks/bongbongco/MS10-070.svg)


## CVE-2009-5147
 DL::dlopen in Ruby 1.8, 1.9.0, 1.9.2, 1.9.3, 2.0.0 before patchlevel 648, and 2.1 before 2.1.8 opens libraries with tainted names.

- [https://github.com/zhangyongbo100/-Ruby-dl-handle.c-CVE-2009-5147-](https://github.com/zhangyongbo100/-Ruby-dl-handle.c-CVE-2009-5147-) :  ![starts](https://img.shields.io/github/stars/zhangyongbo100/-Ruby-dl-handle.c-CVE-2009-5147-.svg) ![forks](https://img.shields.io/github/forks/zhangyongbo100/-Ruby-dl-handle.c-CVE-2009-5147-.svg)


## CVE-2009-1330
 Stack-based buffer overflow in Easy RM to MP3 Converter allows remote attackers to execute arbitrary code via a long filename in a playlist (.pls) file.

- [https://github.com/war4uthor/CVE-2009-1330](https://github.com/war4uthor/CVE-2009-1330) :  ![starts](https://img.shields.io/github/stars/war4uthor/CVE-2009-1330.svg) ![forks](https://img.shields.io/github/forks/war4uthor/CVE-2009-1330.svg)


## CVE-2009-0689
 Array index error in the (1) dtoa implementation in dtoa.c (aka pdtoa.c) and the (2) gdtoa (aka new dtoa) implementation in gdtoa/misc.c in libc, as used in multiple operating systems and products including in FreeBSD 6.4 and 7.2, NetBSD 5.0, OpenBSD 4.5, Mozilla Firefox 3.0.x before 3.0.15 and 3.5.x before 3.5.4, K-Meleon 1.5.3, SeaMonkey 1.1.8, and other products, allows context-dependent attackers to cause a denial of service (application crash) and possibly execute arbitrary code via a large precision value in the format argument to a printf function, which triggers incorrect memory allocation and a heap-based buffer overflow during conversion to a floating-point number.

- [https://github.com/Fullmetal5/str2hax](https://github.com/Fullmetal5/str2hax) :  ![starts](https://img.shields.io/github/stars/Fullmetal5/str2hax.svg) ![forks](https://img.shields.io/github/forks/Fullmetal5/str2hax.svg)


## CVE-2008-0244
 SAP MaxDB 7.6.03 build 007 and earlier allows remote attackers to execute arbitrary commands via &quot;&amp;&amp;&quot; and other shell metacharacters in exec_sdbinfo and other unspecified commands, which are executed when MaxDB invokes cons.exe.

- [https://github.com/gregkcarson/sapmdbret](https://github.com/gregkcarson/sapmdbret) :  ![starts](https://img.shields.io/github/stars/gregkcarson/sapmdbret.svg) ![forks](https://img.shields.io/github/forks/gregkcarson/sapmdbret.svg)

