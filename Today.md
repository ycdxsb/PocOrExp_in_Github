# Update 2022-04-07
## CVE-2022-25636
 net/netfilter/nf_dup_netdev.c in the Linux kernel 5.4 through 5.6.10 allows local users to gain privileges because of a heap out-of-bounds write. This is related to nf_tables_offload.

- [https://github.com/veritas501/CVE-2022-25636-PipeVersion](https://github.com/veritas501/CVE-2022-25636-PipeVersion) :  ![starts](https://img.shields.io/github/stars/veritas501/CVE-2022-25636-PipeVersion.svg) ![forks](https://img.shields.io/github/forks/veritas501/CVE-2022-25636-PipeVersion.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/luoqianlin/CVE-2022-22965](https://github.com/luoqianlin/CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/luoqianlin/CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/luoqianlin/CVE-2022-22965.svg)
- [https://github.com/xnderLAN/CVE-2022-22965](https://github.com/xnderLAN/CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/xnderLAN/CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/xnderLAN/CVE-2022-22965.svg)
- [https://github.com/robiul-awal/CVE-2022-22965](https://github.com/robiul-awal/CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/robiul-awal/CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/robiul-awal/CVE-2022-22965.svg)
- [https://github.com/LudovicPatho/CVE-2022-22965_Spring4Shell](https://github.com/LudovicPatho/CVE-2022-22965_Spring4Shell) :  ![starts](https://img.shields.io/github/stars/LudovicPatho/CVE-2022-22965_Spring4Shell.svg) ![forks](https://img.shields.io/github/forks/LudovicPatho/CVE-2022-22965_Spring4Shell.svg)
- [https://github.com/datawiza-inc/spring-rec-demo](https://github.com/datawiza-inc/spring-rec-demo) :  ![starts](https://img.shields.io/github/stars/datawiza-inc/spring-rec-demo.svg) ![forks](https://img.shields.io/github/forks/datawiza-inc/spring-rec-demo.svg)
- [https://github.com/Snip3R69/spring-shell-vuln](https://github.com/Snip3R69/spring-shell-vuln) :  ![starts](https://img.shields.io/github/stars/Snip3R69/spring-shell-vuln.svg) ![forks](https://img.shields.io/github/forks/Snip3R69/spring-shell-vuln.svg)


## CVE-2022-22963
 In Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions, when using routing functionality it is possible for a user to provide a specially crafted SpEL as a routing-expression that may result in remote code execution and access to local resources.

- [https://github.com/SealPaPaPa/SpringCloudFunction-Research](https://github.com/SealPaPaPa/SpringCloudFunction-Research) :  ![starts](https://img.shields.io/github/stars/SealPaPaPa/SpringCloudFunction-Research.svg) ![forks](https://img.shields.io/github/forks/SealPaPaPa/SpringCloudFunction-Research.svg)


## CVE-2022-22947
 In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

- [https://github.com/aesm1p/CVE-2022-22947-POC-Reproduce](https://github.com/aesm1p/CVE-2022-22947-POC-Reproduce) :  ![starts](https://img.shields.io/github/stars/aesm1p/CVE-2022-22947-POC-Reproduce.svg) ![forks](https://img.shields.io/github/forks/aesm1p/CVE-2022-22947-POC-Reproduce.svg)


## CVE-2022-21882
 Win32k Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2022-21887.

- [https://github.com/Ascotbe/Kernelhub](https://github.com/Ascotbe/Kernelhub) :  ![starts](https://img.shields.io/github/stars/Ascotbe/Kernelhub.svg) ![forks](https://img.shields.io/github/forks/Ascotbe/Kernelhub.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/LudovicPatho/CVE-2022-0847_dirty-pipe](https://github.com/LudovicPatho/CVE-2022-0847_dirty-pipe) :  ![starts](https://img.shields.io/github/stars/LudovicPatho/CVE-2022-0847_dirty-pipe.svg) ![forks](https://img.shields.io/github/forks/LudovicPatho/CVE-2022-0847_dirty-pipe.svg)
- [https://github.com/mhanief/dirtypipe](https://github.com/mhanief/dirtypipe) :  ![starts](https://img.shields.io/github/stars/mhanief/dirtypipe.svg) ![forks](https://img.shields.io/github/forks/mhanief/dirtypipe.svg)


## CVE-2022-0185
 A heap-based buffer overflow flaw was found in the way the legacy_parse_param function in the Filesystem Context functionality of the Linux kernel verified the supplied parameters length. An unprivileged (in case of unprivileged user namespaces enabled, otherwise needs namespaced CAP_SYS_ADMIN privilege) local user able to open a filesystem that does not support the Filesystem Context API (and thus fallbacks to legacy handling) could use this flaw to escalate their privileges on the system.

- [https://github.com/veritas501/CVE-2022-0185-PipeVersion](https://github.com/veritas501/CVE-2022-0185-PipeVersion) :  ![starts](https://img.shields.io/github/stars/veritas501/CVE-2022-0185-PipeVersion.svg) ![forks](https://img.shields.io/github/forks/veritas501/CVE-2022-0185-PipeVersion.svg)


## CVE-2021-38647
 Open Management Infrastructure Remote Code Execution Vulnerability

- [https://github.com/goofsec/omigod](https://github.com/goofsec/omigod) :  ![starts](https://img.shields.io/github/stars/goofsec/omigod.svg) ![forks](https://img.shields.io/github/forks/goofsec/omigod.svg)


## CVE-2021-22555
 A heap out-of-bounds write affecting Linux since v2.6.19-rc1 was discovered in net/netfilter/x_tables.c. This allows an attacker to gain privileges or cause a DoS (via heap memory corruption) through user name space

- [https://github.com/veritas501/CVE-2021-22555-PipeVersion](https://github.com/veritas501/CVE-2021-22555-PipeVersion) :  ![starts](https://img.shields.io/github/stars/veritas501/CVE-2021-22555-PipeVersion.svg) ![forks](https://img.shields.io/github/forks/veritas501/CVE-2021-22555-PipeVersion.svg)


## CVE-2019-1653
 A vulnerability in the web-based management interface of Cisco Small Business RV320 and RV325 Dual Gigabit WAN VPN Routers could allow an unauthenticated, remote attacker to retrieve sensitive information. The vulnerability is due to improper access controls for URLs. An attacker could exploit this vulnerability by connecting to an affected device via HTTP or HTTPS and requesting specific URLs. A successful exploit could allow the attacker to download the router configuration or detailed diagnostic information. Cisco has released firmware updates that address this vulnerability.

- [https://github.com/helGayhub233/CVE-2019-1653](https://github.com/helGayhub233/CVE-2019-1653) :  ![starts](https://img.shields.io/github/stars/helGayhub233/CVE-2019-1653.svg) ![forks](https://img.shields.io/github/forks/helGayhub233/CVE-2019-1653.svg)


## CVE-2016-2569
 Squid 3.x before 3.5.15 and 4.x before 4.0.7 does not properly append data to String objects, which allows remote servers to cause a denial of service (assertion failure and daemon exit) via a long string, as demonstrated by a crafted HTTP Vary header.

- [https://github.com/amit-raut/CVE-2016-2569](https://github.com/amit-raut/CVE-2016-2569) :  ![starts](https://img.shields.io/github/stars/amit-raut/CVE-2016-2569.svg) ![forks](https://img.shields.io/github/forks/amit-raut/CVE-2016-2569.svg)


## CVE-2010-2078
 DataTrack System 3.5 allows remote attackers to list the root directory via a (1) /%u0085/ or (2) /%u00A0/ URI.

- [https://github.com/0bfxgh0st-secondary/UnrealIrcd-3.2.8.1-cve-2010-2075-exploit](https://github.com/0bfxgh0st-secondary/UnrealIrcd-3.2.8.1-cve-2010-2075-exploit) :  ![starts](https://img.shields.io/github/stars/0bfxgh0st-secondary/UnrealIrcd-3.2.8.1-cve-2010-2075-exploit.svg) ![forks](https://img.shields.io/github/forks/0bfxgh0st-secondary/UnrealIrcd-3.2.8.1-cve-2010-2075-exploit.svg)


## CVE-2010-2075
 UnrealIRCd 3.2.8.1, as distributed on certain mirror sites from November 2009 through June 2010, contains an externally introduced modification (Trojan Horse) in the DEBUG3_DOLOG_SYSTEM macro, which allows remote attackers to execute arbitrary commands.

- [https://github.com/0bfxgh0st-secondary/UnrealIrcd-3.2.8.1-cve-2010-2075-exploit](https://github.com/0bfxgh0st-secondary/UnrealIrcd-3.2.8.1-cve-2010-2075-exploit) :  ![starts](https://img.shields.io/github/stars/0bfxgh0st-secondary/UnrealIrcd-3.2.8.1-cve-2010-2075-exploit.svg) ![forks](https://img.shields.io/github/forks/0bfxgh0st-secondary/UnrealIrcd-3.2.8.1-cve-2010-2075-exploit.svg)

