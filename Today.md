# Update 2022-07-30
## CVE-2022-36946
 nfqnl_mangle in net/netfilter/nfnetlink_queue.c in the Linux kernel through 5.18.14 allows remote attackers to cause a denial of service (panic) because, in the case of an nf_queue verdict with a one-byte nfta_payload attribute, an skb_pull can encounter a negative skb-&gt;len.

- [https://github.com/Pwnzer0tt1/CVE-2022-36946](https://github.com/Pwnzer0tt1/CVE-2022-36946) :  ![starts](https://img.shields.io/github/stars/Pwnzer0tt1/CVE-2022-36946.svg) ![forks](https://img.shields.io/github/forks/Pwnzer0tt1/CVE-2022-36946.svg)


## CVE-2022-36408
 PrestaShop 1.6.0.10 through 1.7.x before 1.7.8.7 allows remote attackers to execute arbitrary code, aka a &quot;previously unknown vulnerability chain&quot; related to SQL injection and MySQL Smarty cache storage injection, as exploited in the wild in July 2022.

- [https://github.com/drkbcn/lblfixer_cve_2022_36408](https://github.com/drkbcn/lblfixer_cve_2022_36408) :  ![starts](https://img.shields.io/github/stars/drkbcn/lblfixer_cve_2022_36408.svg) ![forks](https://img.shields.io/github/forks/drkbcn/lblfixer_cve_2022_36408.svg)


## CVE-2022-31181
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/drkbcn/lblfixer_cve_2022_36408](https://github.com/drkbcn/lblfixer_cve_2022_36408) :  ![starts](https://img.shields.io/github/stars/drkbcn/lblfixer_cve_2022_36408.svg) ![forks](https://img.shields.io/github/forks/drkbcn/lblfixer_cve_2022_36408.svg)


## CVE-2022-26138
 The Atlassian Questions For Confluence app for Confluence Server and Data Center creates a Confluence user account in the confluence-users group with the username disabledsystemuser and a hardcoded password. A remote, unauthenticated attacker with knowledge of the hardcoded password could exploit this to log into Confluence and access all content accessible to users in the confluence-users group. This user account is created when installing versions 2.7.34, 2.7.35, and 3.0.2 of the app.

- [https://github.com/Vulnmachines/Confluence-Question-CVE-2022-26138-](https://github.com/Vulnmachines/Confluence-Question-CVE-2022-26138-) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/Confluence-Question-CVE-2022-26138-.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/Confluence-Question-CVE-2022-26138-.svg)


## CVE-2022-21661
 WordPress is a free and open-source content management system written in PHP and paired with a MariaDB database. Due to improper sanitization in WP_Query, there can be cases where SQL injection is possible through plugins or themes that use it in a certain way. This has been patched in WordPress version 5.8.3. Older affected versions are also fixed via security release, that go back till 3.7.37. We strongly recommend that you keep auto-updates enabled. There are no known workarounds for this vulnerability.

- [https://github.com/z92g/CVE-2022-21661](https://github.com/z92g/CVE-2022-21661) :  ![starts](https://img.shields.io/github/stars/z92g/CVE-2022-21661.svg) ![forks](https://img.shields.io/github/forks/z92g/CVE-2022-21661.svg)


## CVE-2022-2022
 Cross-site Scripting (XSS) - Stored in GitHub repository nocodb/nocodb prior to 0.91.7.

- [https://github.com/GREENHAT7/pxplan](https://github.com/GREENHAT7/pxplan) :  ![starts](https://img.shields.io/github/stars/GREENHAT7/pxplan.svg) ![forks](https://img.shields.io/github/forks/GREENHAT7/pxplan.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/theykillmeslowly/CVE-2021-42013](https://github.com/theykillmeslowly/CVE-2021-42013) :  ![starts](https://img.shields.io/github/stars/theykillmeslowly/CVE-2021-42013.svg) ![forks](https://img.shields.io/github/forks/theykillmeslowly/CVE-2021-42013.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via &quot;sudoedit -s&quot; and a command-line argument that ends with a single backslash character.

- [https://github.com/BearCat4/CVE-2021-3156](https://github.com/BearCat4/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/BearCat4/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/BearCat4/CVE-2021-3156.svg)


## CVE-2021-2108
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core Components). The supported version that is affected is 12.1.3.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/somatrasss/weblogic2021](https://github.com/somatrasss/weblogic2021) :  ![starts](https://img.shields.io/github/stars/somatrasss/weblogic2021.svg) ![forks](https://img.shields.io/github/forks/somatrasss/weblogic2021.svg)


## CVE-2019-17625
 There is a stored XSS in Rambox 0.6.9 that can lead to code execution. The XSS is in the name field while adding/editing a service. The problem occurs due to incorrect sanitization of the name field when being processed and stored. This allows a user to craft a payload for Node.js and Electron, such as an exec of OS commands within the onerror attribute of an IMG element.

- [https://github.com/Ekultek/CVE-2019-17625](https://github.com/Ekultek/CVE-2019-17625) :  ![starts](https://img.shields.io/github/stars/Ekultek/CVE-2019-17625.svg) ![forks](https://img.shields.io/github/forks/Ekultek/CVE-2019-17625.svg)


## CVE-2019-7216
 An issue was discovered in FileChucker 4.99e-free-e02. filechucker.cgi has a filter bypass that allows a malicious user to upload any type of file by using % characters within the extension, e.g., file.%ph%p becomes file.php.

- [https://github.com/Ekultek/CVE-2019-7216](https://github.com/Ekultek/CVE-2019-7216) :  ![starts](https://img.shields.io/github/stars/Ekultek/CVE-2019-7216.svg) ![forks](https://img.shields.io/github/forks/Ekultek/CVE-2019-7216.svg)


## CVE-2018-19788
 A flaw was found in PolicyKit (aka polkit) 0.115 that allows a user with a uid greater than INT_MAX to successfully execute any systemctl command.

- [https://github.com/Ekultek/PoC](https://github.com/Ekultek/PoC) :  ![starts](https://img.shields.io/github/stars/Ekultek/PoC.svg) ![forks](https://img.shields.io/github/forks/Ekultek/PoC.svg)


## CVE-2018-11776
 Apache Struts versions 2.3 to 2.3.34 and 2.5 to 2.5.16 suffer from possible Remote Code Execution when alwaysSelectFullNamespace is true (either by user or a plugin like Convention Plugin) and then: results are used with no namespace and in same time, its upper package have no or wildcard namespace and similar to results, same possibility when using url tag which doesn't have value and action set and in same time, its upper package have no or wildcard namespace.

- [https://github.com/Ekultek/Strutter](https://github.com/Ekultek/Strutter) :  ![starts](https://img.shields.io/github/stars/Ekultek/Strutter.svg) ![forks](https://img.shields.io/github/forks/Ekultek/Strutter.svg)


## CVE-2018-10933
 A vulnerability was found in libssh's server-side state machine before versions 0.7.6 and 0.8.4. A malicious client could create channels without first performing authentication, resulting in unauthorized access.

- [https://github.com/EmmanuelCruzL/CVE-2018-10933](https://github.com/EmmanuelCruzL/CVE-2018-10933) :  ![starts](https://img.shields.io/github/stars/EmmanuelCruzL/CVE-2018-10933.svg) ![forks](https://img.shields.io/github/forks/EmmanuelCruzL/CVE-2018-10933.svg)


## CVE-2018-7600
 Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations.

- [https://github.com/anldori/CVE-2018-7600](https://github.com/anldori/CVE-2018-7600) :  ![starts](https://img.shields.io/github/stars/anldori/CVE-2018-7600.svg) ![forks](https://img.shields.io/github/forks/anldori/CVE-2018-7600.svg)


## CVE-2015-1427
 The Groovy scripting engine in Elasticsearch before 1.3.8 and 1.4.x before 1.4.3 allows remote attackers to bypass the sandbox protection mechanism and execute arbitrary shell commands via a crafted script.

- [https://github.com/xpgdgit/CVE-2015-1427](https://github.com/xpgdgit/CVE-2015-1427) :  ![starts](https://img.shields.io/github/stars/xpgdgit/CVE-2015-1427.svg) ![forks](https://img.shields.io/github/forks/xpgdgit/CVE-2015-1427.svg)

