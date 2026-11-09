# Update 2026-11-09
## CVE-2026-123158
 sshd in OpenSSH before 10.6p2 on Linux, when musl libc is used without PAM, lacks a workaround for a password authentication bypass (related to misinterpretation of whether a string is intended to be a password hash). For some configurations of accounts, any password between 256 and 1024 characters succeeds. An example of a platform using musl libc without PAM is Alpine Linux.

- [https://github.com/ashrafzaryouh/CVE-2026-123158](https://github.com/ashrafzaryouh/CVE-2026-123158) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-123158.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-123158.svg)
- [https://github.com/liamromanis101/MaSSHole](https://github.com/liamromanis101/MaSSHole) :  ![starts](https://img.shields.io/github/stars/liamromanis101/MaSSHole.svg) ![forks](https://img.shields.io/github/forks/liamromanis101/MaSSHole.svg)
- [https://github.com/MikeCase/check-sshole](https://github.com/MikeCase/check-sshole) :  ![starts](https://img.shields.io/github/stars/MikeCase/check-sshole.svg) ![forks](https://img.shields.io/github/forks/MikeCase/check-sshole.svg)


## CVE-2026-122675
 Cross-Site Request Forgery (CSRF) vulnerability in Wpmet Wp Social wp-social allows Cross Site Request Forgery.This issue affects Wp Social: from n/a through 3.2.3.

- [https://github.com/Mor-Golan/CVE-2026-122675](https://github.com/Mor-Golan/CVE-2026-122675) :  ![starts](https://img.shields.io/github/stars/Mor-Golan/CVE-2026-122675.svg) ![forks](https://img.shields.io/github/forks/Mor-Golan/CVE-2026-122675.svg)


## CVE-2026-119977
 WordPress Core is vulnerable to Remote Code Execution in versions 4.7 through 7.1.3. This is due to predictable, web-accessible staging paths used during full-package core upgrades. This makes it possible for unauthenticated attackers to execute code on the server during the upgrade window.

- [https://github.com/riabinov/CVE-2026-119977](https://github.com/riabinov/CVE-2026-119977) :  ![starts](https://img.shields.io/github/stars/riabinov/CVE-2026-119977.svg) ![forks](https://img.shields.io/github/forks/riabinov/CVE-2026-119977.svg)


## CVE-2026-117691
 A flaw was found in the SAML HTTP-Redirect binding implementation of Keycloak. The issue occurs because the server processes percent-encoded parameter names (like %53AMLResponse) while the signature verification logic only checks literal parameter names. An attacker can use this discrepancy to provide a crafted, unsigned SAML message that the server processes instead of a legitimately signed one, leading to full account takeover of federated users.

- [https://github.com/foxcornlab/keycloak-saml-scanner](https://github.com/foxcornlab/keycloak-saml-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/keycloak-saml-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/keycloak-saml-scanner.svg)


## CVE-2026-115596
 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in impleCode eCommerce Product Catalog ecommerce-product-catalog allows Reflected XSS.This issue affects eCommerce Product Catalog: from n/a through 3.6.4.

- [https://github.com/Mor-Golan/CVE-2026-115596](https://github.com/Mor-Golan/CVE-2026-115596) :  ![starts](https://img.shields.io/github/stars/Mor-Golan/CVE-2026-115596.svg) ![forks](https://img.shields.io/github/forks/Mor-Golan/CVE-2026-115596.svg)


## CVE-2026-114595
 In EPICS Base release 7.0.10 and prior, an integer overflow in network request processing can cause memory to be allocated with an incorrect size. Subsequent handling of attacker supplied data may result in memory corruption, denial of service, or potential remote code execution.

- [https://github.com/ashrafzaryouh/CVE-2026-114595](https://github.com/ashrafzaryouh/CVE-2026-114595) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-114595.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-114595.svg)


## CVE-2026-112869
 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Noah Hearle We’re Open! opening-hours allows Reflected XSS.This issue affects We’re Open!: from n/a through 2.6.

- [https://github.com/Mor-Golan/CVE-2026-112869](https://github.com/Mor-Golan/CVE-2026-112869) :  ![starts](https://img.shields.io/github/stars/Mor-Golan/CVE-2026-112869.svg) ![forks](https://img.shields.io/github/forks/Mor-Golan/CVE-2026-112869.svg)


## CVE-2026-112222
 Missing Authorization vulnerability in Surfer Surfer surferseo allows Exploiting Incorrectly Configured Access Control Security Levels.This issue affects Surfer: from n/a through 1.8.0.744.

- [https://github.com/Mor-Golan/CVE-2026-112222](https://github.com/Mor-Golan/CVE-2026-112222) :  ![starts](https://img.shields.io/github/stars/Mor-Golan/CVE-2026-112222.svg) ![forks](https://img.shields.io/github/forks/Mor-Golan/CVE-2026-112222.svg)


## CVE-2026-111497
Users need to update any Brotli libraries or binaries between 1.0.3 through 1.2.0 to the latest available version: 1.0.10 or 1.1.1 or 1.2.1.

- [https://github.com/ashrafzaryouh/CVE-2026-111497](https://github.com/ashrafzaryouh/CVE-2026-111497) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-111497.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-111497.svg)


## CVE-2026-110912
 In DragonFly BSD through 6.4.2 before 4bb22ff, the ARP input handlers arpintr() and in_arpinput() (sys/netinet/if_ether.c) do not validate the hardware address length (ar_hln) and protocol address length (ar_pln) fields of incoming ARP packets. in_arpreply() then uses these attacker-controlled values as memcpy lengths when copying from kernel buffers that are only 6 and 4 bytes long, resulting in an out-of-bounds read of kernel heap and stack memory that is copied into the ARP reply sent back to the requester. An unauthenticated attacker on the adjacent network can use a single crafted ARP request to disclose up to roughly 250 bytes of each type of kernel memory, including kernel pointers. This is expected to be fixed in the 6.6 stable release when that is available.

- [https://github.com/ashrafzaryouh/CVE-2026-110912](https://github.com/ashrafzaryouh/CVE-2026-110912) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-110912.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-110912.svg)


## CVE-2026-109618
 PHP uses longjmp() for out-of-memory (OOM) errors to exit the current context and abort handling of the request. Some contexts may not properly account for this scenario and leave request memory in an uninitialized state before performing an allocation. The subsequent request cleanup procedure may read or branch on this memory. Multiple OOM strategies can consistently trigger this condition and lead to remote code execution (RCE).

- [https://github.com/D1se0/php2shell_lab](https://github.com/D1se0/php2shell_lab) :  ![starts](https://img.shields.io/github/stars/D1se0/php2shell_lab.svg) ![forks](https://img.shields.io/github/forks/D1se0/php2shell_lab.svg)


## CVE-2026-106173
 A improper limitation of a pathname to a restricted directory ('path traversal') vulnerability in Fortinet FortiSIEM 7.5.0 may allow attacker to execute unauthorized code or commands via specially crafted packets.

- [https://github.com/ashrafzaryouh/CVE-2026-106173](https://github.com/ashrafzaryouh/CVE-2026-106173) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-106173.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-106173.svg)


## CVE-2026-101767
 Vulnerability in the Oracle Application Object Library product of Oracle E-Business Suite (component: Core).  Supported versions that are affected are 12.2.3-12.2.15. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Application Object Library.  Successful attacks of this vulnerability can result in takeover of Oracle Application Object Library. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/ashrafzaryouh/CVE-2026-101767](https://github.com/ashrafzaryouh/CVE-2026-101767) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-101767.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-101767.svg)


## CVE-2026-98499
such a descriptor trips KASAN before the patch and not after it.

- [https://github.com/woshigenm/CVE-2026-98499](https://github.com/woshigenm/CVE-2026-98499) :  ![starts](https://img.shields.io/github/stars/woshigenm/CVE-2026-98499.svg) ![forks](https://img.shields.io/github/forks/woshigenm/CVE-2026-98499.svg)


## CVE-2026-98432
will be addressed in a separate patch.

- [https://github.com/ashrafzaryouh/CVE-2026-98432](https://github.com/ashrafzaryouh/CVE-2026-98432) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-98432.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-98432.svg)
- [https://github.com/makslanies/cve-2026-98432-mitigation](https://github.com/makslanies/cve-2026-98432-mitigation) :  ![starts](https://img.shields.io/github/stars/makslanies/cve-2026-98432-mitigation.svg) ![forks](https://img.shields.io/github/forks/makslanies/cve-2026-98432-mitigation.svg)
- [https://github.com/one-loner/cve_2026_98432_fix](https://github.com/one-loner/cve_2026_98432_fix) :  ![starts](https://img.shields.io/github/stars/one-loner/cve_2026_98432_fix.svg) ![forks](https://img.shields.io/github/forks/one-loner/cve_2026_98432_fix.svg)
- [https://github.com/zhao-xiaogang/cve_2026_98432_livepatch](https://github.com/zhao-xiaogang/cve_2026_98432_livepatch) :  ![starts](https://img.shields.io/github/stars/zhao-xiaogang/cve_2026_98432_livepatch.svg) ![forks](https://img.shields.io/github/forks/zhao-xiaogang/cve_2026_98432_livepatch.svg)


## CVE-2026-98260
[ tglx: Move the cleanup right after de_thread() ]

- [https://github.com/countryside99/GhostKey](https://github.com/countryside99/GhostKey) :  ![starts](https://img.shields.io/github/stars/countryside99/GhostKey.svg) ![forks](https://img.shields.io/github/forks/countryside99/GhostKey.svg)
- [https://github.com/buihien224/VSOCB-OSS](https://github.com/buihien224/VSOCB-OSS) :  ![starts](https://img.shields.io/github/stars/buihien224/VSOCB-OSS.svg) ![forks](https://img.shields.io/github/forks/buihien224/VSOCB-OSS.svg)


## CVE-2026-97798
 Improper neutralization of argument delimiters in a command ('argument injection') in Windows Error Reporting allows an authorized attacker to elevate privileges locally.

- [https://github.com/ashrafzaryouh/CVE-2026-97798](https://github.com/ashrafzaryouh/CVE-2026-97798) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-97798.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-97798.svg)


## CVE-2026-96838
 Unauthenticated Cross Site Request Forgery (CSRF) in Blacklist Manager &#8211; WooCommerce Anti-Fraud, Blacklist &amp; Checkout Verification = 2.3.1 versions.

- [https://github.com/Mor-Golan/CVE-2026-96838](https://github.com/Mor-Golan/CVE-2026-96838) :  ![starts](https://img.shields.io/github/stars/Mor-Golan/CVE-2026-96838.svg) ![forks](https://img.shields.io/github/forks/Mor-Golan/CVE-2026-96838.svg)
- [https://github.com/Mor-Golan/CVE-2026-96838-wc-blacklist-manager](https://github.com/Mor-Golan/CVE-2026-96838-wc-blacklist-manager) :  ![starts](https://img.shields.io/github/stars/Mor-Golan/CVE-2026-96838-wc-blacklist-manager.svg) ![forks](https://img.shields.io/github/forks/Mor-Golan/CVE-2026-96838-wc-blacklist-manager.svg)


## CVE-2026-95597
 Missing Authorization vulnerability in codemstory 워드프레스 결제 심플페이 pgall-for-woocommerce allows Exploiting Incorrectly Configured Access Control Security Levels.This issue affects 워드프레스 결제 심플페이: from n/a through 5.5.17.

- [https://github.com/Mor-Golan/CVE-2026-95597](https://github.com/Mor-Golan/CVE-2026-95597) :  ![starts](https://img.shields.io/github/stars/Mor-Golan/CVE-2026-95597.svg) ![forks](https://img.shields.io/github/forks/Mor-Golan/CVE-2026-95597.svg)
- [https://github.com/Mor-Golan/CVE-2026-95597-pgall-for-woocommerce](https://github.com/Mor-Golan/CVE-2026-95597-pgall-for-woocommerce) :  ![starts](https://img.shields.io/github/stars/Mor-Golan/CVE-2026-95597-pgall-for-woocommerce.svg) ![forks](https://img.shields.io/github/forks/Mor-Golan/CVE-2026-95597-pgall-for-woocommerce.svg)


## CVE-2026-94641
 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Stiofan UsersWP userswp allows Reflected XSS.This issue affects UsersWP: from n/a through 1.2.73.

- [https://github.com/Mor-Golan/CVE-2026-94641](https://github.com/Mor-Golan/CVE-2026-94641) :  ![starts](https://img.shields.io/github/stars/Mor-Golan/CVE-2026-94641.svg) ![forks](https://img.shields.io/github/forks/Mor-Golan/CVE-2026-94641.svg)


## CVE-2026-94074
 Unauthenticated Broken Access Control in Simply Schedule Appointments = 1.6.12.29 versions.

- [https://github.com/Mor-Golan/CVE-2026-94074](https://github.com/Mor-Golan/CVE-2026-94074) :  ![starts](https://img.shields.io/github/stars/Mor-Golan/CVE-2026-94074.svg) ![forks](https://img.shields.io/github/forks/Mor-Golan/CVE-2026-94074.svg)


## CVE-2026-93485
 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Automattic WordPress wordpress allows DOM-Based XSS.This issue affects WordPress: from n/a through 7.1.

- [https://github.com/ashrafzaryouh/CVE-2026-93485](https://github.com/ashrafzaryouh/CVE-2026-93485) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-93485.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-93485.svg)


## CVE-2026-86950
 An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in iOS 18.7.11 and iPadOS 18.7.11, iOS 26.7.1 and iPadOS 26.7.1, macOS Sequoia 15.8.1, macOS Tahoe 26.7.1. Processing a maliciously crafted file may lead to arbitrary code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 27.

- [https://github.com/ashrafzaryouh/CVE-2026-86950](https://github.com/ashrafzaryouh/CVE-2026-86950) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-86950.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-86950.svg)


## CVE-2026-84411
 The web management service in affected RouterOS versions contains an integer underflow in its HTTP request body handling that is reachable before authentication. This can be leveraged by an unauthenticated network attacker to achieve arbitrary code execution as root, or to cause a denial of service, using a single crafted request.

- [https://github.com/s-b-repo/cve_2026_84411_poc-](https://github.com/s-b-repo/cve_2026_84411_poc-) :  ![starts](https://img.shields.io/github/stars/s-b-repo/cve_2026_84411_poc-.svg) ![forks](https://img.shields.io/github/forks/s-b-repo/cve_2026_84411_poc-.svg)


## CVE-2026-84183
 Incorrect Authorization in the updateLayout simple-method in applications/content/minilang/layout/LayoutEvents.xml in Apache OFBiz 24.09 before 24.09.08 on all platforms allows a remote authenticated attacker holding only OFBTOOLS_VIEW and CONTENTMGR_VIEW to execute arbitrary commands as the OFBiz process user, by using updateLayout's authorization check — which validates only the fixed CONTENT_CREATE operation rather than an update permission on the actual Content record and an independently selected DataResource — to relink an existing RESPONSE-purpose Content record and convert an arbitrary, independently selected DataResource into an OFBIZ_FILE/FTL resource pointed at the OFBiz access log, poisoned via a crafted User-Agent header and evaluated through the normal authenticated showContent route. Users are recommended to upgrade to version 24.09.08, which fixes this issue.

- [https://github.com/Crypto-Cat/apache-ofbiz-2026-pocs](https://github.com/Crypto-Cat/apache-ofbiz-2026-pocs) :  ![starts](https://img.shields.io/github/stars/Crypto-Cat/apache-ofbiz-2026-pocs.svg) ![forks](https://img.shields.io/github/forks/Crypto-Cat/apache-ofbiz-2026-pocs.svg)


## CVE-2026-83844
 Out-of-bounds read in Windows Paint allows an unauthorized attacker to execute code locally.

- [https://github.com/ashrafzaryouh/CVE-2026-83844](https://github.com/ashrafzaryouh/CVE-2026-83844) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-83844.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-83844.svg)
- [https://github.com/LACHHAB-Anas/CVE-2026-83844](https://github.com/LACHHAB-Anas/CVE-2026-83844) :  ![starts](https://img.shields.io/github/stars/LACHHAB-Anas/CVE-2026-83844.svg) ![forks](https://img.shields.io/github/forks/LACHHAB-Anas/CVE-2026-83844.svg)


## CVE-2026-83542
Users are recommended to upgrade to version 24.09.08, which fixes this issue.

- [https://github.com/Crypto-Cat/apache-ofbiz-2026-pocs](https://github.com/Crypto-Cat/apache-ofbiz-2026-pocs) :  ![starts](https://img.shields.io/github/stars/Crypto-Cat/apache-ofbiz-2026-pocs.svg) ![forks](https://img.shields.io/github/forks/Crypto-Cat/apache-ofbiz-2026-pocs.svg)


## CVE-2026-83538
 Missing Authorization in Apache OFBiz 24.09 before 24.09.08 on all platforms allows a remote unauthenticated attacker to disclose internal business records — including organization, employee, product catalog, and product-store data — by requesting several helper endpoints across the Human Resources, Catalog, and Order Manager applications that are configured to skip authentication and perform no permission check before returning the requested record. Users are recommended to upgrade to version 24.09.08, which fixes this issue.

- [https://github.com/Crypto-Cat/apache-ofbiz-2026-pocs](https://github.com/Crypto-Cat/apache-ofbiz-2026-pocs) :  ![starts](https://img.shields.io/github/stars/Crypto-Cat/apache-ofbiz-2026-pocs.svg) ![forks](https://img.shields.io/github/forks/Crypto-Cat/apache-ofbiz-2026-pocs.svg)


## CVE-2026-82894
 Improper Authorization in ContentWorker in Apache OFBiz 24.09 before 24.09.08 on all platforms allows a remote unauthenticated attacker to trigger arbitrary OFBiz service invocation with attacker-controlled parameters, resulting in arbitrary file write, arbitrary file deletion, and server-side request forgery, by requesting the public showHelpPublic view against a Content row whose serviceName field an account holding only CONTENTMGR_CREATE or CONTENTMGR_UPDATE has set to an attacker-chosen service, causing ContentWorker.renderContentAsText to resolve the service to invoke from that persisted, client-writable field and build its parameters directly from the live HTTP request map with no allow-list, no ownership check, and no requirement that the caller be authenticated. Users are recommended to upgrade to version 24.09.08, which fixes this issue.

- [https://github.com/Crypto-Cat/apache-ofbiz-2026-pocs](https://github.com/Crypto-Cat/apache-ofbiz-2026-pocs) :  ![starts](https://img.shields.io/github/stars/Crypto-Cat/apache-ofbiz-2026-pocs.svg) ![forks](https://img.shields.io/github/forks/Crypto-Cat/apache-ofbiz-2026-pocs.svg)


## CVE-2026-81000
other allocation paths.

- [https://github.com/ashrafzaryouh/CVE-2026-81000](https://github.com/ashrafzaryouh/CVE-2026-81000) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-81000.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-81000.svg)


## CVE-2026-80844
errors to the existing AH6 input and output error paths.

- [https://github.com/ashrafzaryouh/CVE-2026-80844](https://github.com/ashrafzaryouh/CVE-2026-80844) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-80844.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-80844.svg)


## CVE-2026-76461
This vulnerability is due to insufficient validation in the email parsing logic. An attacker could exploit this vulnerability by sending a crafted email message that contains malicious SQL statements through an affected device. A successful exploit could allow the attacker to execute arbitrary SQL statements, leading to command execution with root privileges on the underlying operating system.

- [https://github.com/ashrafzaryouh/CVE-2026-76461](https://github.com/ashrafzaryouh/CVE-2026-76461) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-76461.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-76461.svg)


## CVE-2026-74469
to return its existing transport at the limit.

- [https://github.com/ashrafzaryouh/CVE-2026-74469](https://github.com/ashrafzaryouh/CVE-2026-74469) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-74469.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-74469.svg)


## CVE-2026-73578
 Missing authorization enforcement in RequestHandler.renderView in Apache OFBiz 24.09 before 24.09.08 on all platforms allows a remote unauthenticated attacker to bypass the request-map authentication policy for protected views by supplying a crafted _LAST_VIEW_NAME_ value, which is stored as saved-view state in the anonymous session and later rendered without re-applying the original view's authentication requirement, potentially exposing protected views and associated business data. Users are recommended to upgrade to version 24.09.08, which fixes this issue.

- [https://github.com/Crypto-Cat/apache-ofbiz-2026-pocs](https://github.com/Crypto-Cat/apache-ofbiz-2026-pocs) :  ![starts](https://img.shields.io/github/stars/Crypto-Cat/apache-ofbiz-2026-pocs.svg) ![forks](https://img.shields.io/github/forks/Crypto-Cat/apache-ofbiz-2026-pocs.svg)


## CVE-2026-73577
 Incorrect authorization in RequestHandler in Apache OFBiz 24.09 before 24.09.08 on all platforms allows a remote unauthenticated attacker to bypass the authentication requirement of a protected view by appending it as a path suffix to a public request (e.g., /catalog/control/ListLocales/showPortalPage), causing the servlet to authorize the request based on the public path component while rendering the protected suffix view. Users are recommended to upgrade to version 24.09.08, which fixes this issue.

- [https://github.com/Crypto-Cat/apache-ofbiz-2026-pocs](https://github.com/Crypto-Cat/apache-ofbiz-2026-pocs) :  ![starts](https://img.shields.io/github/stars/Crypto-Cat/apache-ofbiz-2026-pocs.svg) ![forks](https://img.shields.io/github/forks/Crypto-Cat/apache-ofbiz-2026-pocs.svg)


## CVE-2026-73570
 A remote code execution vulnerability exists in Zimbra Collaboration (ZCS) before 10.1.20 when the optional zimbra-snmp package is installed and SNMP notifications are enabled. Due to improper sanitization of untrusted input during SNMP notification processing, an unauthenticated attacker can send specially crafted SMTP requests that may result in execution of arbitrary operating system commands as the Zimbra user.

- [https://github.com/ashrafzaryouh/CVE-2026-73570](https://github.com/ashrafzaryouh/CVE-2026-73570) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-73570.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-73570.svg)


## CVE-2026-73296
 Microsoft UFO open-source framework for intelligent automation across devices and platforms. Prior to 3.0.8, create_mobile_data_collection_server and create_mobile_action_server in ufo/client/mcp/http_servers/mobile_mcp_server.py exposed Streamable HTTP MCP services on TCP ports 8020 and 8021 without authentication, allowing an unauthenticated remote attacker to invoke capture_screenshot, get_ui_tree, tap, swipe, type_text, launch_app, press_key, and click_control against an ADB-connected Android device, disclose screen and device data, and modify device state. This issue is fixed in version 3.0.8.

- [https://github.com/ashrafzaryouh/CVE-2026-73296](https://github.com/ashrafzaryouh/CVE-2026-73296) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-73296.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-73296.svg)


## CVE-2026-72898
 Metabase allows a remote, unauthenticated attacker to inject arbitrary SQL via the '/reset_password' database endpoint and gain administrator access to the connected Metabase instance.

- [https://github.com/ashrafzaryouh/CVE-2026-72898](https://github.com/ashrafzaryouh/CVE-2026-72898) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-72898.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-72898.svg)


## CVE-2026-72018
check before the memcpy to reject such requests with -EINVAL.

- [https://github.com/ashrafzaryouh/CVE-2026-72018](https://github.com/ashrafzaryouh/CVE-2026-72018) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-72018.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-72018.svg)


## CVE-2026-68121
relocates the head.

- [https://github.com/ashrafzaryouh/CVE-2026-68121](https://github.com/ashrafzaryouh/CVE-2026-68121) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-68121.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-68121.svg)


## CVE-2026-66066
 Action Pack is a framework for handling and responding to web requests. In versions prior to 7.2.3.2, 8.0.5.1 and 8.1.3.1, Active Storage does not disable libvips operations marked unsafe for untrusted content, allowing a crafted upload to invoke such an operation. Consuming applications are affected when configured to use libvips and accept image uploads from untrusted users. An unauthenticated attacker may exploit this behavior to read arbitrary files accessible to the Rails process, including environment variables and application secrets. Exposure of credentials such as secret_key_base or external-service tokens may enable remote code execution or lateral movement. This issue has been fixed in versions 7.2.3.2, 8.0.5.1 and 8.1.3.1.

- [https://github.com/ashrafzaryouh/CVE-2026-66066](https://github.com/ashrafzaryouh/CVE-2026-66066) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-66066.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-66066.svg)


## CVE-2026-64638
Discovered and responsibly disclosed by [the team at pwn.ai](https://pwn.ai/).

- [https://github.com/ashrafzaryouh/CVE-2026-64638](https://github.com/ashrafzaryouh/CVE-2026-64638) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-64638.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-64638.svg)


## CVE-2026-64600
sequence counter changes across the ILOCK cycle.

- [https://github.com/ashrafzaryouh/CVE-2026-64600](https://github.com/ashrafzaryouh/CVE-2026-64600) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-64600.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-64600.svg)


## CVE-2026-64560
---truncated---

- [https://github.com/000999888111/op13-cve-2026-64560](https://github.com/000999888111/op13-cve-2026-64560) :  ![starts](https://img.shields.io/github/stars/000999888111/op13-cve-2026-64560.svg) ![forks](https://img.shields.io/github/forks/000999888111/op13-cve-2026-64560.svg)


## CVE-2026-64531
ownership and truncates on close failure.

- [https://github.com/ashrafzaryouh/CVE-2026-64531](https://github.com/ashrafzaryouh/CVE-2026-64531) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-64531.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-64531.svg)


## CVE-2026-63292
Users are recommended to upgrade to version 2.4.69, which fixes this issue.

- [https://github.com/ashrafzaryouh/CVE-2026-63292](https://github.com/ashrafzaryouh/CVE-2026-63292) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-63292.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-63292.svg)


## CVE-2026-63072
modules are affected by this CVE.

- [https://github.com/ashrafzaryouh/CVE-2026-63072](https://github.com/ashrafzaryouh/CVE-2026-63072) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-63072.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-63072.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/ashrafzaryouh/CVE-2026-63030](https://github.com/ashrafzaryouh/CVE-2026-63030) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-63030.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-63030.svg)


## CVE-2026-61989
 Unauthenticated Cross Site Scripting (XSS) in Easy Property Listings = 3.5.25 versions.

- [https://github.com/Mor-Golan/CVE-2026-61989](https://github.com/Mor-Golan/CVE-2026-61989) :  ![starts](https://img.shields.io/github/stars/Mor-Golan/CVE-2026-61989.svg) ![forks](https://img.shields.io/github/forks/Mor-Golan/CVE-2026-61989.svg)


## CVE-2026-60206
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core).  Supported versions that are affected are 12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0 and  15.1.1.0.0. Easily exploitable vulnerability allows low privileged attacker with network access via SAML to compromise Oracle WebLogic Server.  While the vulnerability is in Oracle WebLogic Server, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.9 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H).

- [https://github.com/ashrafzaryouh/CVE-2026-60206](https://github.com/ashrafzaryouh/CVE-2026-60206) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-60206.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-60206.svg)


## CVE-2026-60004
 Gitea before 1.27.1 allows remote code execution via the diffpatch API through Git hook installation.

- [https://github.com/ashrafzaryouh/CVE-2026-60004](https://github.com/ashrafzaryouh/CVE-2026-60004) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-60004.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-60004.svg)


## CVE-2026-58138
 Orkes Conductor 3.21.21 before 3.30.2 contains an unauthenticated remote code execution vulnerability that allows remote attackers to execute arbitrary OS commands by submitting inline workflow definitions containing malicious JavaScript or Python expressions to the workflow API endpoint prior to authentication. Attackers can exploit unsandboxed GraalVM evaluators configured with HostAccess.ALL or allowAllAccess(true) through INLINE, LAMBDA, DO_WHILE, and SWITCH task types to invoke arbitrary system commands via Java reflection or direct subprocess calls.

- [https://github.com/ashrafzaryouh/CVE-2026-58138](https://github.com/ashrafzaryouh/CVE-2026-58138) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-58138.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-58138.svg)


## CVE-2026-55450
 Langflow is a tool for building and deploying AI-powered agents and workflows. Prior to 1.9.1, unauthenticated users can upload any amount of data to the server without any limitations. No need for any prior knowledge, only network access to Langflow. This can lead to space exhaustion on the server. In addition, in the response, the absolute path of the uploaded file is reported to the attacker, which is an information leak that can assist in chaining other primitives. This vulnerability is fixed in 1.9.1.

- [https://github.com/ashrafzaryouh/CVE-2026-55450](https://github.com/ashrafzaryouh/CVE-2026-55450) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-55450.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-55450.svg)


## CVE-2026-55200
 libssh2 1.11.1, fixed in commit 97acf3d, contains an out-of-bounds write vulnerability in ssh2_transport_read() that fails to enforce upper bounds on packet_length field. Remote attackers can send crafted SSH packets with excessively large packet_length values to corrupt heap memory and achieve remote code execution.

- [https://github.com/ashrafzaryouh/CVE-2026-55200](https://github.com/ashrafzaryouh/CVE-2026-55200) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-55200.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-55200.svg)


## CVE-2026-54121
 Improper authorization in Active Directory Certificate Services (AD CS) allows an authorized attacker to elevate privileges over a network.

- [https://github.com/ashrafzaryouh/CVE-2026-54121](https://github.com/ashrafzaryouh/CVE-2026-54121) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-54121.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-54121.svg)
- [https://github.com/anubis-update/CVE-2026-54121-Certighost](https://github.com/anubis-update/CVE-2026-54121-Certighost) :  ![starts](https://img.shields.io/github/stars/anubis-update/CVE-2026-54121-Certighost.svg) ![forks](https://img.shields.io/github/forks/anubis-update/CVE-2026-54121-Certighost.svg)


## CVE-2026-53921
 odhcpd is the DHCPv6, DHCPv4, and router-advertisement server used by OpenWrt. Prior to version 25.12, odhcpd's DHCPv6 IA response handler writes past the end of a fixed 512-byte stack buffer (pdbuf) when a single DHCPv6 REQUEST carries enough IA options to nearly exhaust the reply space. Two independent overflow sites exist in the same call chain, both reachable from the network via a single unauthenticated UDP packet. odhcpd runs as root on OpenWrt; embedded targets often lack stack canaries and ASLR, making code execution realistic. This issue has been patched in version 25.12.

- [https://github.com/ashrafzaryouh/CVE-2026-53921](https://github.com/ashrafzaryouh/CVE-2026-53921) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-53921.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-53921.svg)


## CVE-2026-53362
case, remove the MSG_SPLICE_PAGES exception from the negative copy check.

- [https://github.com/sol4ce503/cve-2026-53362-ipv6-frag-escape](https://github.com/sol4ce503/cve-2026-53362-ipv6-frag-escape) :  ![starts](https://img.shields.io/github/stars/sol4ce503/cve-2026-53362-ipv6-frag-escape.svg) ![forks](https://img.shields.io/github/forks/sol4ce503/cve-2026-53362-ipv6-frag-escape.svg)


## CVE-2026-53359
use-after-free.

- [https://github.com/ashrafzaryouh/CVE-2026-53359](https://github.com/ashrafzaryouh/CVE-2026-53359) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-53359.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-53359.svg)


## CVE-2026-50751
 A logic flow weakness in Remote Access and Mobile Access certificate validation in deprecated IKEv1 key exchange allows an unauthenticated remote attacker to bypass user authentication and establish a remote access VPN connection without a valid user password.

- [https://github.com/ashrafzaryouh/CVE-2026-50751](https://github.com/ashrafzaryouh/CVE-2026-50751) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-50751.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-50751.svg)


## CVE-2026-50656
 Microsoft is aware of an elevation of privilege in the Microsoft Malware Protection Engine in Microsoft Defender publicly referred to as &quot;RoguePlanet &quot;.

- [https://github.com/ashrafzaryouh/CVE-2026-50656](https://github.com/ashrafzaryouh/CVE-2026-50656) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-50656.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-50656.svg)


## CVE-2026-48908
 A vulnerability in SP Page Builder for Joomla allows unauthenticated users to upload arbitrary files, ultimately resulting in the upload and execution of PHP code.

- [https://github.com/ashrafzaryouh/CVE-2026-48908](https://github.com/ashrafzaryouh/CVE-2026-48908) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-48908.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-48908.svg)


## CVE-2026-48907
 A vulnerability in the JCE editor extension for Joomla allows the creation of new editor profiles for unauthenticated users, ultimately resulting in PHP code upload and execution.

- [https://github.com/ashrafzaryouh/CVE-2026-48907](https://github.com/ashrafzaryouh/CVE-2026-48907) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-48907.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-48907.svg)


## CVE-2026-47729
 Squid is a caching proxy for the Web. Prior to 7.6, due to an improper validation of syntactic correctness of input in the FTP gateway (src/clients/FtpGateway.cc), Squid is vulnerable to an out-of-bounds read: when a listing entry date in the TypeA or TypeB directory-listing formats is not followed by a filename, parsing was not restricted to the input buffer, so a trusted client accessing a misbehaving FTP server through Squid's gateway feature could read memory from random unrelated transactions. This issue is fixed in version 7.6.

- [https://github.com/ashrafzaryouh/CVE-2026-47729](https://github.com/ashrafzaryouh/CVE-2026-47729) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-47729.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-47729.svg)


## CVE-2026-46817
 Vulnerability in the Oracle Payments product of Oracle E-Business Suite (component: File Transmission).  Supported versions that are affected are 12.2.3-12.2.15. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Payments.  Successful attacks of this vulnerability can result in takeover of Oracle Payments. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/ashrafzaryouh/CVE-2026-46817](https://github.com/ashrafzaryouh/CVE-2026-46817) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-46817.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-46817.svg)


## CVE-2026-46333
set), and require a proper CAP_SYS_PTRACE capability to override.

- [https://github.com/ashrafzaryouh/CVE-2026-46333](https://github.com/ashrafzaryouh/CVE-2026-46333) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-46333.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-46333.svg)


## CVE-2026-46331
offset_valid() against INT_MIN, where negation is undefined.

- [https://github.com/ashrafzaryouh/CVE-2026-46331](https://github.com/ashrafzaryouh/CVE-2026-46331) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-46331.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-46331.svg)


## CVE-2026-46300
bytes into @to's linear data rather than transferring frag descriptors.

- [https://github.com/ashrafzaryouh/CVE-2026-46300](https://github.com/ashrafzaryouh/CVE-2026-46300) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-46300.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-46300.svg)


## CVE-2026-46243
spnego_cred to request the key.

- [https://github.com/ashrafzaryouh/CVE-2026-46243](https://github.com/ashrafzaryouh/CVE-2026-46243) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-46243.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-46243.svg)


## CVE-2026-46242
READ_ONCE(epi-dying) fast-path bailout stays.

- [https://github.com/ashrafzaryouh/CVE-2026-46242](https://github.com/ashrafzaryouh/CVE-2026-46242) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-46242.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-46242.svg)


## CVE-2026-45829
 A pre-authentication, code injection vulnerability in version 1.0.0 or later of the ChromaDB Python project allows an unauthenticated attacker to run arbitrary code on the server by sending a malicious model repository and trust_remote_code set to true in the /api/v2/tenants/{tenant}/databases/{db}/collections endpoint.

- [https://github.com/ashrafzaryouh/CVE-2026-45829](https://github.com/ashrafzaryouh/CVE-2026-45829) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-45829.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-45829.svg)


## CVE-2026-45585
No, if you are using TPM+PIN the vulnerability is not exploitable.

- [https://github.com/ashrafzaryouh/CVE-2026-45585](https://github.com/ashrafzaryouh/CVE-2026-45585) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-45585.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-45585.svg)


## CVE-2026-45447
issue, as the affected code is outside the OpenSSL FIPS module boundary.

- [https://github.com/ashrafzaryouh/CVE-2026-45447](https://github.com/ashrafzaryouh/CVE-2026-45447) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-45447.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-45447.svg)


## CVE-2026-44578
 Next.js is a React framework for building full-stack web applications. From 13.4.13 to before 15.5.16 and 16.2.5, self-hosted applications using the built-in Node.js server can be vulnerable to server-side request forgery through crafted WebSocket upgrade requests. An attacker can cause the server to proxy requests to arbitrary internal or external destinations, which may expose internal services or cloud metadata endpoints. Vercel-hosted deployments are not affected. This vulnerability is fixed in 15.5.16 and 16.2.5.

- [https://github.com/ashrafzaryouh/CVE-2026-44578](https://github.com/ashrafzaryouh/CVE-2026-44578) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-44578.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-44578.svg)


## CVE-2026-44277
 A improper access control vulnerability in Fortinet FortiAuthenticator 8.0.2, FortiAuthenticator 8.0.0, FortiAuthenticator 6.6.0 through 6.6.8, FortiAuthenticator 6.5.0 through 6.5.6, FortiAuthenticator 6.4.0 through 6.4.10 may allow attacker to execute unauthorized code or commands via crafted requests.

- [https://github.com/ashrafzaryouh/CVE-2026-44277](https://github.com/ashrafzaryouh/CVE-2026-44277) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-44277.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-44277.svg)


## CVE-2026-43786
 This issue was addressed with additional entitlement checks. This issue is fixed in macOS Golden Gate 27, macOS Sequoia 15.8, macOS Tahoe 26.7. An app may be able to gain root privileges.

- [https://github.com/ashrafzaryouh/CVE-2026-43786](https://github.com/ashrafzaryouh/CVE-2026-43786) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-43786.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-43786.svg)


## CVE-2026-43503
so segments drawing frags from frag_list members carry the marker.

- [https://github.com/ashrafzaryouh/CVE-2026-43503](https://github.com/ashrafzaryouh/CVE-2026-43503) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-43503.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-43503.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/ashrafzaryouh/CVE-2026-43499](https://github.com/ashrafzaryouh/CVE-2026-43499) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-43499.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-43499.svg)


## CVE-2026-43494
rds_message_zcopy_from_user().

- [https://github.com/ashrafzaryouh/CVE-2026-43494](https://github.com/ashrafzaryouh/CVE-2026-43494) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-43494.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-43494.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/ashrafzaryouh/CVE-2026-43284](https://github.com/ashrafzaryouh/CVE-2026-43284) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-43284.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-43284.svg)
- [https://github.com/noctide/redmi-k50-temp-root](https://github.com/noctide/redmi-k50-temp-root) :  ![starts](https://img.shields.io/github/stars/noctide/redmi-k50-temp-root.svg) ![forks](https://img.shields.io/github/forks/noctide/redmi-k50-temp-root.svg)


## CVE-2026-42945
 NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module. This vulnerability exists when the rewrite directive is followed by a rewrite, if, or set directive and an unnamed Perl-Compatible Regular Expression (PCRE) capture (for example, $1, $2) with a replacement string that includes a question mark (?). An unauthenticated attacker along with conditions beyond its control can exploit this vulnerability by sending crafted HTTP requests. This may cause a heap buffer overflow in the NGINX worker process leading to a restart. Additionally, attackers can execute code on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/ashrafzaryouh/CVE-2026-42945](https://github.com/ashrafzaryouh/CVE-2026-42945) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-42945.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-42945.svg)


## CVE-2026-42569
 phpVMS is a PHP application to run and simulate an airline. Prior to version 7.0.6, a critical vulnerability in phpVMS allowed unauthenticated access to a legacy import feature. This issue has been patched in version 7.0.6.

- [https://github.com/ashrafzaryouh/CVE-2026-42569](https://github.com/ashrafzaryouh/CVE-2026-42569) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-42569.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-42569.svg)


## CVE-2026-42530
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/ashrafzaryouh/CVE-2026-42530](https://github.com/ashrafzaryouh/CVE-2026-42530) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-42530.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-42530.svg)


## CVE-2026-42208
 LiteLLM is a proxy server (AI Gateway) to call LLM APIs in OpenAI (or native) format. From version 1.81.16 to before version 1.83.7, a database query used during proxy API key checks mixed the caller-supplied key value into the query text instead of passing it as a separate parameter. An unauthenticated attacker could send a specially crafted Authorization header to any LLM API route (for example POST /chat/completions) and reach this query through the proxy's error-handling path. An attacker could read data from the proxy's database and may be able to modify it, leading to unauthorised access to the proxy and the credentials it manages. This issue has been patched in version 1.83.7.

- [https://github.com/ashrafzaryouh/CVE-2026-42208](https://github.com/ashrafzaryouh/CVE-2026-42208) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-42208.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-42208.svg)


## CVE-2026-42018
 JFrog Artifactory could return an internal anonymous-user token to an unauthenticated caller when anonymous access is disabled, potentially exposing sensitive resources.

- [https://github.com/dylvie/CVE-2026-42016_CVE-2026-42018](https://github.com/dylvie/CVE-2026-42016_CVE-2026-42018) :  ![starts](https://img.shields.io/github/stars/dylvie/CVE-2026-42016_CVE-2026-42018.svg) ![forks](https://img.shields.io/github/forks/dylvie/CVE-2026-42016_CVE-2026-42018.svg)


## CVE-2026-42016
 JFrog Artifactory (Self Hosted) versions before 7.133.11 are vulnerable to a privilege escalation attack due to a validation check of the token signature/issuer and not the token’s scope.

- [https://github.com/dylvie/CVE-2026-42016_CVE-2026-42018](https://github.com/dylvie/CVE-2026-42016_CVE-2026-42018) :  ![starts](https://img.shields.io/github/stars/dylvie/CVE-2026-42016_CVE-2026-42018.svg) ![forks](https://img.shields.io/github/forks/dylvie/CVE-2026-42016_CVE-2026-42018.svg)


## CVE-2026-41940
 cPanel and WHM versions after 11.40 contain an authentication bypass vulnerability in the login flow that allows unauthenticated remote attackers to gain unauthorized access to the control panel.

- [https://github.com/ashrafzaryouh/CVE-2026-41940](https://github.com/ashrafzaryouh/CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-41940.svg)


## CVE-2026-41651
3. Late flag read at execution time (lines 2273–2277): The scheduler's idle callback reads cached_transaction_flags at dispatch time, not at authorization time. If flags were overwritten between authorization and execution, the backend sees the attacker's flags.

- [https://github.com/ashrafzaryouh/CVE-2026-41651](https://github.com/ashrafzaryouh/CVE-2026-41651) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-41651.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-41651.svg)


## CVE-2026-41462
 ProjeQtor versions 7.0 through 12.4.3 contain an unauthenticated SQL injection vulnerability in the login functionality where the login variable is directly concatenated into a SQL query without parameterization or sanitization. Attackers can inject arbitrary SQL expressions through the username field at the authentication endpoint to create privileged accounts, read sensitive data, and execute operating system commands if the database user has elevated permissions.

- [https://github.com/ashrafzaryouh/CVE-2026-41462](https://github.com/ashrafzaryouh/CVE-2026-41462) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-41462.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-41462.svg)


## CVE-2026-41091
 Improper link resolution before file access ('link following') in Microsoft Defender allows an authorized attacker to elevate privileges locally.

- [https://github.com/ashrafzaryouh/CVE-2026-41091](https://github.com/ashrafzaryouh/CVE-2026-41091) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-41091.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-41091.svg)


## CVE-2026-41089
 Stack-based buffer overflow in Windows Netlogon allows an unauthorized attacker to execute code over a network.

- [https://github.com/ashrafzaryouh/CVE-2026-41089](https://github.com/ashrafzaryouh/CVE-2026-41089) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-41089.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-41089.svg)


## CVE-2026-40487
 Postiz is an AI social media scheduling tool. Prior to version 2.21.6, a file upload validation bypass allows any authenticated user to upload arbitrary HTML, SVG, or other executable file types to the server by spoofing the `Content-Type` header. The uploaded files are then served by nginx with a Content-Type derived from their original extension (`text/html`, `image/svg+xml`), enabling Stored Cross-Site Scripting (XSS) in the context of the application's origin. This can lead to session riding, account takeover, and full compromise of other users' accounts. Version 2.21.6 contains a fix.

- [https://github.com/ashrafzaryouh/CVE-2026-42208](https://github.com/ashrafzaryouh/CVE-2026-42208) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-42208.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-42208.svg)


## CVE-2026-40369
 Heap-based buffer overflow in Windows Kernel allows an authorized attacker to elevate privileges locally.

- [https://github.com/ashrafzaryouh/CVE-2026-40369](https://github.com/ashrafzaryouh/CVE-2026-40369) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-40369.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-40369.svg)


## CVE-2026-40175
 Axios is a promise based HTTP client for the browser and Node.js. Versions prior to 1.15.0 and 0.3.1 are vulnerable to a specific gadget-style attack chain in which prototype pollution in a third-party dependency may be leveraged to inject unsanitized header values into outbound requests. This vulnerability is fixed in 1.15.0 and 0.3.1.

- [https://github.com/ashrafzaryouh/CVE-2026-40175](https://github.com/ashrafzaryouh/CVE-2026-40175) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-40175.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-40175.svg)


## CVE-2026-39987
 marimo is a reactive Python notebook. Prior to 0.23.0, Marimo has a Pre-Auth RCE vulnerability. The terminal WebSocket endpoint /terminal/ws lacks authentication validation, allowing an unauthenticated attacker to obtain a full PTY shell and execute arbitrary system commands. Unlike other WebSocket endpoints (e.g., /ws) that correctly call validate_auth() for authentication, the /terminal/ws endpoint only checks the running mode and platform support before accepting connections, completely skipping authentication verification. This vulnerability is fixed in 0.23.0.

- [https://github.com/ashrafzaryouh/CVE-2026-39987](https://github.com/ashrafzaryouh/CVE-2026-39987) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-39987.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-39987.svg)


## CVE-2026-39813
 A path traversal: '../filedir' vulnerability in Fortinet FortiSandbox 5.0.0 through 5.0.5, FortiSandbox 4.4.0 through 4.4.8 may allow attacker to escalation of privilege via specially crafted HTTP requests.

- [https://github.com/ashrafzaryouh/CVE-2026-39813](https://github.com/ashrafzaryouh/CVE-2026-39813) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-39813.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-39813.svg)


## CVE-2026-39808
 A improper neutralization of special elements used in an os command ('os command injection') vulnerability in Fortinet FortiSandbox 4.4.0 through 4.4.8 may allow attacker to execute unauthorized code or commands via insert attack vector here

- [https://github.com/ashrafzaryouh/CVE-2026-39808](https://github.com/ashrafzaryouh/CVE-2026-39808) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-39808.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-39808.svg)


## CVE-2026-39732
 Unauthenticated SQL Injection in Transliterator = 2.5.13 versions.

- [https://github.com/Mor-Golan/CVE-2026-39732](https://github.com/Mor-Golan/CVE-2026-39732) :  ![starts](https://img.shields.io/github/stars/Mor-Golan/CVE-2026-39732.svg) ![forks](https://img.shields.io/github/forks/Mor-Golan/CVE-2026-39732.svg)


## CVE-2026-35616
 A improper access control vulnerability in Fortinet FortiClientEMS 7.4.5 through 7.4.6 may allow an unauthenticated attacker to execute unauthorized code or commands via crafted requests.

- [https://github.com/ashrafzaryouh/CVE-2026-35616](https://github.com/ashrafzaryouh/CVE-2026-35616) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-35616.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-35616.svg)


## CVE-2026-35273
 Vulnerability in the PeopleSoft Enterprise PeopleTools product of Oracle PeopleSoft (component: Updates Environment Management). Supported versions that are affected are 8.61 and 8.62. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise PeopleSoft Enterprise PeopleTools. Successful attacks of this vulnerability can result in takeover of PeopleSoft Enterprise PeopleTools. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/ashrafzaryouh/CVE-2026-35273](https://github.com/ashrafzaryouh/CVE-2026-35273) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-35273.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-35273.svg)


## CVE-2026-34724
 Zammad is a web based open source helpdesk/customer support system. Prior to 7.0.1, a server-side template injection vulnerability  which leads to RCE via AI Agent exists. Impact is limited to environments where an attacker can control or influence type_enrichment_data (typically high-privilege administrative configuration). This vulnerability is fixed in 7.0.1.

- [https://github.com/ashrafzaryouh/CVE-2026-34724](https://github.com/ashrafzaryouh/CVE-2026-34724) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-34724.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-34724.svg)


## CVE-2026-34197
Users are recommended to upgrade to version 5.19.4 or 6.2.3, which fixes the issue

- [https://github.com/ashrafzaryouh/CVE-2026-34197](https://github.com/ashrafzaryouh/CVE-2026-34197) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-34197.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-34197.svg)


## CVE-2026-34156
 NocoBase is an AI-powered no-code/low-code platform for building business applications and enterprise solutions. Prior to version 2.0.28, NocoBase's Workflow Script Node executes user-supplied JavaScript inside a Node.js vm sandbox with a custom require allowlist (controlled by WORKFLOW_SCRIPT_MODULES env var). However, the console object passed into the sandbox context exposes host-realm WritableWorkerStdio stream objects via console._stdout and console._stderr. An authenticated attacker can traverse the prototype chain to escape the sandbox and achieve Remote Code Execution as root. This issue has been patched in version 2.0.28.

- [https://github.com/ashrafzaryouh/CVE-2026-34156](https://github.com/ashrafzaryouh/CVE-2026-34156) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-34156.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-34156.svg)


## CVE-2026-33825
 Insufficient granularity of access control in Microsoft Defender allows an authorized attacker to elevate privileges locally.

- [https://github.com/ashrafzaryouh/CVE-2026-33825](https://github.com/ashrafzaryouh/CVE-2026-33825) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-33825.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-33825.svg)


## CVE-2026-33017
 Langflow is a tool for building and deploying AI-powered agents and workflows. In versions prior to 1.9.0, the POST /api/v1/build_public_tmp/{flow_id}/flow endpoint allows building public flows without requiring authentication. When the optional data parameter is supplied, the endpoint uses attacker-controlled flow data (containing arbitrary Python code in node definitions) instead of the stored flow data from the database. This code is passed to exec() with zero sandboxing, resulting in unauthenticated remote code execution. This is distinct from CVE-2025-3248, which fixed /api/v1/validate/code by adding authentication. The build_public_tmp endpoint is designed to be unauthenticated (for public flows) but incorrectly accepts attacker-supplied flow data containing arbitrary executable code. This issue has been fixed in version 1.9.0.

- [https://github.com/ashrafzaryouh/CVE-2026-33017](https://github.com/ashrafzaryouh/CVE-2026-33017) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-33017.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-33017.svg)


## CVE-2026-32475
This issue affects Elementor Pro: from n/a through 4.2.1.

- [https://github.com/ashrafzaryouh/CVE-2026-32475](https://github.com/ashrafzaryouh/CVE-2026-32475) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-32475.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-32475.svg)


## CVE-2026-31635
Reject authenticator lengths that exceed the remaining packet payload.

- [https://github.com/ashrafzaryouh/CVE-2026-31635](https://github.com/ashrafzaryouh/CVE-2026-31635) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-31635.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-31635.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/ashrafzaryouh/CVE-2026-31431](https://github.com/ashrafzaryouh/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-31431.svg)


## CVE-2026-31402
correct response on the original request.

- [https://github.com/ashrafzaryouh/CVE-2026-31402](https://github.com/ashrafzaryouh/CVE-2026-31402) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-31402.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-31402.svg)


## CVE-2026-28289
 FreeScout is a free help desk and shared inbox built with PHP's Laravel framework. A patch bypass vulnerability for CVE-2026-27636 in FreeScout 1.8.206 and earlier allows any authenticated user with file upload permissions to achieve Remote Code Execution (RCE) on the server by uploading a malicious .htaccess file using a zero-width space character prefix to bypass the security check. The vulnerability exists in the sanitizeUploadedFileName() function in app/Http/Helper.php. The function contains a Time-of-Check to Time-of-Use (TOCTOU) flaw where the dot-prefix check occurs before sanitization removes invisible characters. This vulnerability is fixed in 1.8.207.

- [https://github.com/ashrafzaryouh/CVE-2026-28289](https://github.com/ashrafzaryouh/CVE-2026-28289) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-28289.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-28289.svg)


## CVE-2026-27876
- 12.4.0 (inclusive) to 12.4.2 (exclusive): 12.4.2 has the fix. 13.0.0 and above also have the fix: no v13 release is affected.

- [https://github.com/ashrafzaryouh/CVE-2026-27876](https://github.com/ashrafzaryouh/CVE-2026-27876) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-27876.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-27876.svg)


## CVE-2026-25769
 Wazuh is a free and open source platform used for threat prevention, detection, and response. Versions 4.0.0 through 4.14.2 have a Remote Code Execution (RCE) vulnerability due to Deserialization of Untrusted Data). All Wazuh deployments using cluster mode (master/worker architecture) and any organization with a compromised worker node (e.g., through initial access, insider threat, or supply chain attack) are impacted. An attacker who gains access to a worker node (through any means) can achieve full RCE on the master node with root privileges. Version 4.14.3 fixes the issue.

- [https://github.com/ashrafzaryouh/CVE-2026-25769](https://github.com/ashrafzaryouh/CVE-2026-25769) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-25769.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-25769.svg)


## CVE-2026-25089
 A improper neutralization of special elements used in an os command ('os command injection') vulnerability in Fortinet FortiSandbox 5.0.0 through 5.0.5, FortiSandbox 4.4.0 through 4.4.8, FortiSandbox 4.2 all versions, FortiSandbox Cloud 5.0.4 through 5.0.5, FortiSandbox PaaS 5.0.4 through 5.0.5 may allow an unauthenticated attacker to execute unauthorized commands via specifically crafted HTTP requests

- [https://github.com/ashrafzaryouh/CVE-2026-25089](https://github.com/ashrafzaryouh/CVE-2026-25089) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-25089.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-25089.svg)


## CVE-2026-25049
 n8n is an open source workflow automation platform. Prior to versions 1.123.17 and 2.5.2, an authenticated user with permission to create or modify workflows could abuse crafted expressions in workflow parameters to trigger unintended system command execution on the host running n8n. This issue has been patched in versions 1.123.17 and 2.5.2.

- [https://github.com/ashrafzaryouh/CVE-2026-25049](https://github.com/ashrafzaryouh/CVE-2026-25049) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-25049.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-25049.svg)


## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.

- [https://github.com/ashrafzaryouh/CVE-2026-24061](https://github.com/ashrafzaryouh/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-24061.svg)


## CVE-2026-23760
 SmarterTools SmarterMail versions prior to build 9511 contain an authentication bypass vulnerability in the password reset API. The force-reset-password endpoint permits anonymous requests and fails to verify the existing password or a reset token when resetting system administrator accounts. An unauthenticated attacker can supply a target administrator username and a new password to reset the account, resulting in full administrative compromise of the SmarterMail instance. NOTE: SmarterMail system administrator privileges grant the ability to execute operating system commands via built-in management functionality, effectively providing administrative (SYSTEM or root) access on the underlying host.

- [https://github.com/msmacu/smartpwn](https://github.com/msmacu/smartpwn) :  ![starts](https://img.shields.io/github/stars/msmacu/smartpwn.svg) ![forks](https://img.shields.io/github/forks/msmacu/smartpwn.svg)


## CVE-2026-23111
skip active elements, process inactive ones.

- [https://github.com/ashrafzaryouh/CVE-2026-23111](https://github.com/ashrafzaryouh/CVE-2026-23111) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-23111.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-23111.svg)


## CVE-2026-22812
 OpenCode is an open source AI coding agent. Prior to 1.0.216, OpenCode automatically starts an unauthenticated HTTP server that allows any local process (or any website via permissive CORS) to execute arbitrary shell commands with the user's privileges. This vulnerability is fixed in 1.0.216.

- [https://github.com/ashrafzaryouh/CVE-2026-22812](https://github.com/ashrafzaryouh/CVE-2026-22812) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-22812.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-22812.svg)


## CVE-2026-22557
 A malicious actor with access to the network could exploit a Path Traversal vulnerability found in the UniFi Network Application to access files on the underlying system that could be manipulated to access an underlying account.

- [https://github.com/ashrafzaryouh/CVE-2026-22557](https://github.com/ashrafzaryouh/CVE-2026-22557) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-22557.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-22557.svg)


## CVE-2026-22241
 The Open eClass platform (formerly known as GUnet eClass) is a complete course management system. Prior to version 4.2, an arbitrary file upload vulnerability in the theme import functionality enables an attacker with administrative privileges to upload arbitrary files on the server's file system. The main cause of the issue is that no validation or sanitization of the file's present inside the zip archive. This leads to remote code execution on the web server. Version 4.2 patches the issue.

- [https://github.com/ashrafzaryouh/CVE-2026-22241](https://github.com/ashrafzaryouh/CVE-2026-22241) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-22241.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-22241.svg)


## CVE-2026-21962
 Vulnerability in the Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in product of Oracle Fusion Middleware (component: Weblogic Server Proxy Plug-in for Apache HTTP Server, Weblogic Server Proxy Plug-in for IIS).  Supported versions that are affected are 12.2.1.4.0, 14.1.1.0.0 and  14.1.2.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in.  While the vulnerability is in Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in accessible data as well as  unauthorized access to critical data or complete access to all Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in accessible data. Note: Affected version for Weblogic Server Proxy Plug-in for IIS is 12.2.1.4.0 only. CVSS 3.1 Base Score 10.0 (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N).

- [https://github.com/ashrafzaryouh/CVE-2026-21962](https://github.com/ashrafzaryouh/CVE-2026-21962) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-21962.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-21962.svg)


## CVE-2026-21858
 n8n is an open source workflow automation platform. Versions starting with 1.65.0 and below 1.121.0 enable an attacker to access files on the underlying server through execution of certain form-based workflows. A vulnerable workflow could grant access to an unauthenticated remote attacker, resulting in exposure of sensitive information stored on the system and may enable further compromise depending on deployment configuration and workflow usage. This issue is fixed in version 1.121.0.

- [https://github.com/ashrafzaryouh/CVE-2026-21858](https://github.com/ashrafzaryouh/CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-21858.svg)


## CVE-2026-21643
 An improper neutralization of special elements used in an sql command ('sql injection') vulnerability in Fortinet FortiClientEMS 7.4.4 may allow an unauthenticated attacker to execute unauthorized code or commands via specifically crafted HTTP requests.

- [https://github.com/ashrafzaryouh/CVE-2026-21643](https://github.com/ashrafzaryouh/CVE-2026-21643) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-21643.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-21643.svg)


## CVE-2026-21589
 This is a vulnerability in Bitbucket Data Center, Confluence Data Center, Jira Service Management Data Center, Jira Software Data Center, Bamboo Data Center. Crowd Data Center, Crucible and Fisheye. This Arbitrary File Access vulnerability allows an unauthenticated attacker to access specific files within the web application root directory in affected versions. Exploitation requires prior knowledge of the target file's exact name and path; this vulnerability does not allow attackers to enumerate or list directory contents. In some configurations, there may be some sensitive files that make this highly severe. This vulnerability allows an unauthenticated remote attacker to access specific files within the web application root directory in affected versions. The vulnerability must be addressed for affected versions of: -- Bitbucket Data Center, introduced in version = 4.6.0, fix versions: 9.4.26, 10.2.8, 10.5.1 -- Confluence Data Center, introduced in version = 5.10.0, fix versions 9.2.26, 10.2.19 -- Crowd Data Center, introduced in version = 2.11.0, fix versions 6.3.7, 7.0.3, 7.1.7, 7.2.4 -- Jira Software Data Center, introduced in version = 7.1.0, fix versions 9.12.40, 10.3.26, 11.3.12 -- Jira Service Management Data Center, introduced in version = 3.1.0, fix versions 5.12.40, 10.3.26, 11.3.12 -- Bamboo Data Center = 7.0.1, fix versions 10.2.24, 12.1.12 -- Crucible, fix versions 4.9.15 -- Fisheye, fix version 4.9.15 -- Exploitation requires prior knowledge of the target file's exact name and path. The vulnerability does not include the capability to enumerate or list directory contents.

- [https://github.com/ashrafzaryouh/CVE-2026-21589](https://github.com/ashrafzaryouh/CVE-2026-21589) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-21589.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-21589.svg)


## CVE-2026-20841
 Improper neutralization of special elements used in a command ('command injection') in Windows Notepad App allows an unauthorized attacker to execute code locally.

- [https://github.com/ashrafzaryouh/CVE-2026-20841](https://github.com/ashrafzaryouh/CVE-2026-20841) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-20841.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-20841.svg)


## CVE-2026-20253
 In Splunk Enterprise 10.2 versions below 10.2.4 and 10 versions below 10.0.7, an unauthenticated user could create or truncate arbitrary files through a PostgreSQL sidecar service endpoint. The vulnerability exists because the PostgreSQL sidecar service endpoint lacks authentication controls, allowing any network-reachable user to invoke file operations without credentials. Splunk Enterprise versions 9.4 and earlier are not affected. If you cannot immediately upgrade to a fixed version, you can mitigate this vulnerability by disabling the PostgreSQL sidecar service.

- [https://github.com/ashrafzaryouh/CVE-2026-20253](https://github.com/ashrafzaryouh/CVE-2026-20253) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-20253.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-20253.svg)


## CVE-2026-20245
Cisco recommends that customers upgrade to the fixed software that is documented in the  that was published on May 14, 2026, and verify the configuration of the edge devices.

- [https://github.com/ashrafzaryouh/CVE-2026-20245](https://github.com/ashrafzaryouh/CVE-2026-20245) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-20245.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-20245.svg)


## CVE-2026-20131
Note: If the FMC management interface does not have public internet access, the attack surface that is associated with this vulnerability is reduced.

- [https://github.com/ashrafzaryouh/CVE-2026-20131](https://github.com/ashrafzaryouh/CVE-2026-20131) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-20131.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-20131.svg)


## CVE-2026-20127
This vulnerability exists because the peering authentication mechanism in an affected system is not working properly. An attacker could exploit this vulnerability by sending crafted requests to an affected system. A successful exploit could allow the attacker to log in to an affected Cisco Catalyst SD-WAN Controller as an internal, high-privileged, non-root&nbsp;user account. Using this account, the attacker could access NETCONF, which would then allow the attacker to manipulate network configuration for the SD-WAN fabric.&nbsp;

- [https://github.com/ashrafzaryouh/CVE-2026-20127](https://github.com/ashrafzaryouh/CVE-2026-20127) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-20127.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-20127.svg)


## CVE-2026-20079
This vulnerability is due to an improper system process that is created at boot time. An attacker could exploit this vulnerability by sending crafted HTTP requests to an affected device. A successful exploit could allow the attacker to execute a variety of scripts and commands that allow&nbsp;root access to the device.&nbsp;

- [https://github.com/ashrafzaryouh/CVE-2026-20079](https://github.com/ashrafzaryouh/CVE-2026-20079) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-20079.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-20079.svg)


## CVE-2026-19868
 An authentication enforcement vulnerability in SonicOS SSLVPN service may allow a user with valid credentials for an alternate authentication method to bypass SAML authentication controls. Successful exploitation may also bypass SAML-enforced multi-factor authentication (MFA).

- [https://github.com/EXEcution-py/CVE-2026-19868](https://github.com/EXEcution-py/CVE-2026-19868) :  ![starts](https://img.shields.io/github/stars/EXEcution-py/CVE-2026-19868.svg) ![forks](https://img.shields.io/github/forks/EXEcution-py/CVE-2026-19868.svg)


## CVE-2026-15409
 A Server-side request forgery (SSRF) vulnerability has been identified in the SMA1000 Appliance Work Place interface. A remote unauthenticated attacker could potentially cause the appliance to make requests to unintended location.

- [https://github.com/ashrafzaryouh/CVE-2026-15409](https://github.com/ashrafzaryouh/CVE-2026-15409) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-15409.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-15409.svg)


## CVE-2026-12485
      memcpy(&reply_buf[36], g_network_config-ip_addr, v3);

- [https://github.com/ashrafzaryouh/CVE-2026-12485](https://github.com/ashrafzaryouh/CVE-2026-12485) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-12485.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-12485.svg)


## CVE-2026-11645
 Out of bounds read and write in V8 in Google Chrome prior to 149.0.7827.103 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/ashrafzaryouh/CVE-2026-11645](https://github.com/ashrafzaryouh/CVE-2026-11645) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-11645.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-11645.svg)


## CVE-2026-11499
 A vulnerability was determined in Tenda HG7, HG9 and HG10 300001138_en_xpon. This affects the function formDOMAINBLK of the file /boaform/formDOMAINBLK. Executing a manipulation of the argument blkDomain can lead to stack-based buffer overflow. The attack may be performed from remote.

- [https://github.com/ashrafzaryouh/CVE-2026-11499](https://github.com/ashrafzaryouh/CVE-2026-11499) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-11499.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-11499.svg)


## CVE-2026-10961
 Use after free in Chrome for iOS in Google Chrome on iOS prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/ashrafzaryouh/CVE-2026-109618](https://github.com/ashrafzaryouh/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-109618.svg)
- [https://github.com/sahmsec/CVE-2026-109618-PHP2SHELL](https://github.com/sahmsec/CVE-2026-109618-PHP2SHELL) :  ![starts](https://img.shields.io/github/stars/sahmsec/CVE-2026-109618-PHP2SHELL.svg) ![forks](https://img.shields.io/github/forks/sahmsec/CVE-2026-109618-PHP2SHELL.svg)
- [https://github.com/LiliNothere/CVE-2026-109618](https://github.com/LiliNothere/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/LiliNothere/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/LiliNothere/CVE-2026-109618.svg)


## CVE-2026-10520
 An OS Command Injection vulnerability in Ivanti Sentry before the R10.5.2, R10.6.2 and R10.7.1 versions allows a remote unauthenticated user to achieve root-level remote code execution

- [https://github.com/ashrafzaryouh/CVE-2026-10520](https://github.com/ashrafzaryouh/CVE-2026-10520) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-10520.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-10520.svg)


## CVE-2026-9082
This issue affects Drupal core: from 8.9.0 before 10.4.10, from 10.5.0 before 10.5.10, from 10.6.0 before 10.6.9, from 11.0.0 before 11.1.10, from 11.2.0 before 11.2.12, from 11.3.0 before 11.3.10.

- [https://github.com/ashrafzaryouh/CVE-2026-9082](https://github.com/ashrafzaryouh/CVE-2026-9082) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-9082.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-9082.svg)


## CVE-2026-8932
the private key.

- [https://github.com/ashrafzaryouh/CVE-2026-8932](https://github.com/ashrafzaryouh/CVE-2026-8932) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-8932.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-8932.svg)


## CVE-2026-8461
This issue affects FFmpeg before version 8.1.2.

- [https://github.com/ashrafzaryouh/CVE-2026-8461](https://github.com/ashrafzaryouh/CVE-2026-8461) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-8461.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-8461.svg)


## CVE-2026-8451
 Insufficient input validation in NetScaler ADC and NetScaler Gateway leading to memory overread if NetScaler ADC or NetScaler Gateway is configured as a SAML IDP

- [https://github.com/ashrafzaryouh/CVE-2026-8451](https://github.com/ashrafzaryouh/CVE-2026-8451) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-8451.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-8451.svg)


## CVE-2026-7574
 Anthropic Claude Desktop Cowork VM image handling (confirmed across v1.1348.0 through v1.2278.0, including v1.1348.0, v1.1617.0, and v1.2278.0) validates only file presence and a version marker string before booting rootfs.img, but does not verify image content integrity at time-of-use. A local attacker with unprivileged code execution as the victim macOS user can modify the VM root filesystem image and have it trusted on subsequent Cowork VM boots, enabling persistent arbitrary code execution in the VM and access to host-mounted directories. The estimated CWE mapping is CWE-353 (Missing Support for Integrity Check).

- [https://github.com/ashrafzaryouh/CVE-2026-7574](https://github.com/ashrafzaryouh/CVE-2026-7574) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-7574.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-7574.svg)


## CVE-2026-6471
 Missing authorization in PostgreSQL logical decoding allows a non-superuser holding REPLICATION privilege to dlopen any file visible to the operating system account running the server, via the choice of logical decoding plugin.  This in turn runs arbitrary code as that account.  Versions before PostgreSQL 18.6, 17.11, 16.15, 15.19, and 14.24 are affected.

- [https://github.com/ashrafzaryouh/CVE-2026-6471](https://github.com/ashrafzaryouh/CVE-2026-6471) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-6471.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-6471.svg)


## CVE-2026-5173
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 16.9.6 before 18.8.9, 18.9 before 18.9.5, and 18.10 before 18.10.3 that could have allowed an authenticated user to invoke unintended server-side methods through websocket connections due to improper access control.

- [https://github.com/ashrafzaryouh/CVE-2026-5173](https://github.com/ashrafzaryouh/CVE-2026-5173) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-5173.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-5173.svg)


## CVE-2026-5027
 The 'POST /api/v2/files' endpoint does not sanitize the 'filename' parameter from the multipart form data, allowing an attacker to write files to arbitrary locations on the filesystem using path traversal sequences ('../').

- [https://github.com/ashrafzaryouh/CVE-2026-5027](https://github.com/ashrafzaryouh/CVE-2026-5027) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-5027.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-5027.svg)


## CVE-2026-4480
substitution character without escaping shell meta characters. A remote attacker could exploit this vulnerability by sending a specially crafted print job description that contains unescaped shell characters. This could lead to remote code execution on the affected system.

- [https://github.com/ashrafzaryouh/CVE-2026-4480](https://github.com/ashrafzaryouh/CVE-2026-4480) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-4480.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-4480.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/a78c7/w25-cve-2026-43499-notes](https://github.com/a78c7/w25-cve-2026-43499-notes) :  ![starts](https://img.shields.io/github/stars/a78c7/w25-cve-2026-43499-notes.svg) ![forks](https://img.shields.io/github/forks/a78c7/w25-cve-2026-43499-notes.svg)
- [https://github.com/AksiSpirit/ghostlock-cve-2026-43499-4.19-k40](https://github.com/AksiSpirit/ghostlock-cve-2026-43499-4.19-k40) :  ![starts](https://img.shields.io/github/stars/AksiSpirit/ghostlock-cve-2026-43499-4.19-k40.svg) ![forks](https://img.shields.io/github/forks/AksiSpirit/ghostlock-cve-2026-43499-4.19-k40.svg)


## CVE-2026-3055
 Insufficient input validation in NetScaler ADC and NetScaler Gateway when configured as a SAML IDP leading to memory overread

- [https://github.com/ashrafzaryouh/CVE-2026-3055](https://github.com/ashrafzaryouh/CVE-2026-3055) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-3055.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-3055.svg)


## CVE-2026-2699
 Customer Managed ShareFile Storage Zones Controller (SZC) allows an unauthenticated attacker to access restricted configuration pages. This leads to changing system configuration and potential remote code execution.

- [https://github.com/ashrafzaryouh/CVE-2026-2699](https://github.com/ashrafzaryouh/CVE-2026-2699) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-2699.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-2699.svg)


## CVE-2026-2115
 A flaw has been found in itsourcecode Society Management System 1.0. This issue affects some unknown processing of the file /admin/delete_expenses.php. This manipulation of the argument expenses_id causes sql injection. It is possible to initiate the attack remotely. The exploit has been published and may be used.

- [https://github.com/UnsignedChad/CVE-2026-21155-SVE-2026-3546](https://github.com/UnsignedChad/CVE-2026-21155-SVE-2026-3546) :  ![starts](https://img.shields.io/github/stars/UnsignedChad/CVE-2026-21155-SVE-2026-3546.svg) ![forks](https://img.shields.io/github/forks/UnsignedChad/CVE-2026-21155-SVE-2026-3546.svg)


## CVE-2026-1357
 The Migration, Backup, Staging – WPvivid Backup & Migration plugin for WordPress is vulnerable to Unauthenticated Arbitrary File Upload in versions up to and including 0.9.123. This is due to improper error handling in the RSA decryption process combined with a lack of path sanitization when writing uploaded files. When the plugin fails to decrypt a session key using openssl_private_decrypt(), it does not terminate execution and instead passes the boolean false value to the phpseclib library's AES cipher initialization. The library treats this false value as a string of null bytes, allowing an attacker to encrypt a malicious payload using a predictable null-byte key. Additionally, the plugin accepts filenames from the decrypted payload without sanitization, enabling directory traversal to escape the protected backup directory. This makes it possible for unauthenticated attackers to upload arbitrary PHP files to publicly accessible directories and achieve Remote Code Execution via the wpvivid_action=send_to_site parameter.

- [https://github.com/ashrafzaryouh/CVE-2026-1357](https://github.com/ashrafzaryouh/CVE-2026-1357) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-1357.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-1357.svg)


## CVE-2026-1170
 A vulnerability was detected in birkir prime up to 0.4.0.beta.0. This issue affects some unknown processing of the file /graphql of the component GraphQL API. Performing a manipulation results in information disclosure. The attack may be initiated remotely. The exploit is now public and may be used. The project was informed of the problem early through an issue report but has not responded yet.

- [https://github.com/CodeStartUp/CVE-2026-117065](https://github.com/CodeStartUp/CVE-2026-117065) :  ![starts](https://img.shields.io/github/stars/CodeStartUp/CVE-2026-117065.svg) ![forks](https://img.shields.io/github/forks/CodeStartUp/CVE-2026-117065.svg)


## CVE-2026-0770
The specific flaw exists within the handling of the exec_globals parameter provided to the validate endpoint. The issue results from the inclusion of a resource from an untrusted control sphere. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-27325.

- [https://github.com/ashrafzaryouh/CVE-2026-0770](https://github.com/ashrafzaryouh/CVE-2026-0770) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-0770.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-0770.svg)


## CVE-2026-0300
Prisma Access, Cloud NGFW and Panorama appliances are not impacted by this vulnerability.

- [https://github.com/ashrafzaryouh/CVE-2026-0300](https://github.com/ashrafzaryouh/CVE-2026-0300) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-0300.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-0300.svg)


## CVE-2026-0257
Panorama and Cloud NGFW are not impacted by these issues.

- [https://github.com/ashrafzaryouh/CVE-2026-0257](https://github.com/ashrafzaryouh/CVE-2026-0257) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-0257.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-0257.svg)


## CVE-2026-0073
 In adbd_tls_verify_cert of auth.cpp, there is a possible bypass of wireless ADB mutual authentication due to a logic error in the code. This could lead to remote (proximal/adjacent) code execution as the shell user with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/ashrafzaryouh/CVE-2026-0073](https://github.com/ashrafzaryouh/CVE-2026-0073) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-0073.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-0073.svg)


## CVE-2025-68645
 A Local File Inclusion (LFI) vulnerability exists in the Webmail Classic UI of Zimbra Collaboration (ZCS) 10.0 and 10.1 because of improper handling of user-supplied request parameters in the RestFilter servlet. An unauthenticated remote attacker can craft requests to the /h/rest endpoint to influence internal request dispatching, allowing inclusion of arbitrary files from the WebRoot directory.

- [https://github.com/ashrafzaryouh/CVE-2025-68645](https://github.com/ashrafzaryouh/CVE-2025-68645) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2025-68645.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2025-68645.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg)


## CVE-2025-64446
 A relative path traversal vulnerability in Fortinet FortiWeb 8.0.0 through 8.0.1, FortiWeb 7.6.0 through 7.6.4, FortiWeb 7.4.0 through 7.4.9, FortiWeb 7.2.0 through 7.2.11, FortiWeb 7.0.0 through 7.0.11 may allow an attacker to execute administrative commands on the system via crafted HTTP or HTTPS requests.

- [https://github.com/ashrafzaryouh/CVE-2025-64446](https://github.com/ashrafzaryouh/CVE-2025-64446) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2025-64446.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2025-64446.svg)


## CVE-2025-54236
 Adobe Commerce versions 2.4.9-alpha2, 2.4.8-p2, 2.4.7-p7, 2.4.6-p12, 2.4.5-p14, 2.4.4-p15 and earlier are affected by an Improper Input Validation vulnerability. A successful attacker can abuse this to achieve session takeover, increasing the confidentiality, and integrity impact to high. Exploitation of this issue does not require user interaction.

- [https://github.com/bigcartenergy/module-sessionreaper-patch](https://github.com/bigcartenergy/module-sessionreaper-patch) :  ![starts](https://img.shields.io/github/stars/bigcartenergy/module-sessionreaper-patch.svg) ![forks](https://img.shields.io/github/forks/bigcartenergy/module-sessionreaper-patch.svg)


## CVE-2025-49844
 Redis is an open source, in-memory database that persists on disk. Versions 8.2.1 and below allow an authenticated user to use a specially crafted Lua script to manipulate the garbage collector, trigger a use-after-free and potentially lead to remote code execution. The problem exists in all versions of Redis with Lua scripting. This issue is fixed in version 8.2.2. To workaround this issue without patching the redis-server executable is to prevent users from executing Lua scripts. This can be done using ACL to restrict EVAL and EVALSHA commands.

- [https://github.com/ashrafzaryouh/CVE-2025-49844](https://github.com/ashrafzaryouh/CVE-2025-49844) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2025-49844.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2025-49844.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/ashrafzaryouh/CVE-2025-32463](https://github.com/ashrafzaryouh/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2025-32463.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/ashrafzaryouh/CVE-2025-32433](https://github.com/ashrafzaryouh/CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2025-32433.svg)


## CVE-2025-31710
 In engineermode service, there is a possible command injection due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed.

- [https://github.com/Little-yellow-duck1206/360-kidwatch-11X-W370-Ghostroot](https://github.com/Little-yellow-duck1206/360-kidwatch-11X-W370-Ghostroot) :  ![starts](https://img.shields.io/github/stars/Little-yellow-duck1206/360-kidwatch-11X-W370-Ghostroot.svg) ![forks](https://img.shields.io/github/forks/Little-yellow-duck1206/360-kidwatch-11X-W370-Ghostroot.svg)


## CVE-2025-31161
 CrushFTP 10 before 10.8.4 and 11 before 11.3.1 allows authentication bypass and takeover of the crushadmin account (unless a DMZ proxy instance is used), as exploited in the wild in March and April 2025, aka "Unauthenticated HTTP(S) port access." A race condition exists in the AWS4-HMAC (compatible with S3) authorization method of the HTTP component of the FTP server. The server first verifies the existence of the user by performing a call to login_user_pass() with no password requirement. This will authenticate the session through the HMAC verification process and up until the server checks for user verification once more. The vulnerability can be further stabilized, eliminating the need for successfully triggering a race condition, by sending a mangled AWS4-HMAC header. By providing only the username and a following slash (/), the server will successfully find a username, which triggers the successful anypass authentication process, but the server will fail to find the expected SignedHeaders entry, resulting in an index-out-of-bounds error that stops the code from reaching the session cleanup. Together, these issues make it trivial to authenticate as any known or guessable user (e.g., crushadmin), and can lead to a full compromise of the system by obtaining an administrative account.

- [https://github.com/ashrafzaryouh/CVE-2025-31161](https://github.com/ashrafzaryouh/CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2025-31161.svg)


## CVE-2025-14847
 Mismatched length fields in Zlib compressed protocol headers may allow a read of uninitialized heap memory by an unauthenticated client. This issue affects all MongoDB Server v7.0 prior to 7.0.28 versions, MongoDB Server v8.0 versions prior to 8.0.17, MongoDB Server v8.2 versions prior to 8.2.3, MongoDB Server v6.0 versions prior to 6.0.27, MongoDB Server v5.0 versions prior to 5.0.32, MongoDB Server v4.4 versions prior to 4.4.30, MongoDB Server v4.2 versions greater than or equal to 4.2.0, MongoDB Server v4.0 versions greater than or equal to 4.0.0, and MongoDB Server v3.6 versions greater than or equal to 3.6.0.

- [https://github.com/ashrafzaryouh/CVE-2025-14847](https://github.com/ashrafzaryouh/CVE-2025-14847) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2025-14847.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2025-14847.svg)


## CVE-2025-13315
 Twonky Server 8.5.2 on Linux and Windows is vulnerable to an access control flaw. An unauthenticated attacker can bypass web service API authentication controls to leak a log file and read the administrator's username and encrypted password.

- [https://github.com/ashrafzaryouh/CVE-2025-13315](https://github.com/ashrafzaryouh/CVE-2025-13315) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2025-13315.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2025-13315.svg)


## CVE-2025-10042
 The Quiz Maker plugin for WordPress is vulnerable to SQL Injection via spoofed IP headers in all versions up to, and including, 6.7.0.56 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database. This is only exploitable in configurations where the server is set up to retrieve the IP from a user-supplied field like `X-Forwarded-For` and limit users by IP is enabled.

- [https://github.com/fumioryoto/Quiz-Maker-SQL-Injection-CVE-2025-10042](https://github.com/fumioryoto/Quiz-Maker-SQL-Injection-CVE-2025-10042) :  ![starts](https://img.shields.io/github/stars/fumioryoto/Quiz-Maker-SQL-Injection-CVE-2025-10042.svg) ![forks](https://img.shields.io/github/forks/fumioryoto/Quiz-Maker-SQL-Injection-CVE-2025-10042.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)


## CVE-2025-5777
 Insufficient input validation leading to memory overread when the NetScaler is configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server

- [https://github.com/ashrafzaryouh/CVE-2025-5777](https://github.com/ashrafzaryouh/CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2025-5777.svg)


## CVE-2025-5518
This issue affects BILGER: before 2.4.6.

- [https://github.com/sangleshubham/React-Security-CVE-2025-55182-Exploit](https://github.com/sangleshubham/React-Security-CVE-2025-55182-Exploit) :  ![starts](https://img.shields.io/github/stars/sangleshubham/React-Security-CVE-2025-55182-Exploit.svg) ![forks](https://img.shields.io/github/forks/sangleshubham/React-Security-CVE-2025-55182-Exploit.svg)


## CVE-2025-2294
 The Kubio AI Page Builder plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 2.5.1 via thekubio_hybrid_theme_load_template function. This makes it possible for unauthenticated attackers to include and execute arbitrary files on the server, allowing the execution of any PHP code in those files. This can be used to bypass access controls, obtain sensitive data, or achieve code execution in cases where images and other “safe” file types can be uploaded and included.

- [https://github.com/fumioryoto/CVE-2025-2294-Kubio-2.5.1-LFi-Checker](https://github.com/fumioryoto/CVE-2025-2294-Kubio-2.5.1-LFi-Checker) :  ![starts](https://img.shields.io/github/stars/fumioryoto/CVE-2025-2294-Kubio-2.5.1-LFi-Checker.svg) ![forks](https://img.shields.io/github/forks/fumioryoto/CVE-2025-2294-Kubio-2.5.1-LFi-Checker.svg)


## CVE-2024-34102
 Adobe Commerce versions 2.4.7, 2.4.6-p5, 2.4.5-p7, 2.4.4-p8 and earlier are affected by an Improper Restriction of XML External Entity Reference ('XXE') vulnerability that could result in arbitrary code execution. An attacker could exploit this vulnerability by sending a crafted XML document that references external entities. Exploitation of this issue does not require user interaction.

- [https://github.com/bigcartenergy/module-cosmicsting-patch](https://github.com/bigcartenergy/module-cosmicsting-patch) :  ![starts](https://img.shields.io/github/stars/bigcartenergy/module-cosmicsting-patch.svg) ![forks](https://img.shields.io/github/forks/bigcartenergy/module-cosmicsting-patch.svg)


## CVE-2024-24919
 Potentially allowing an attacker to read certain information on Check Point Security Gateways once connected to the internet and enabled with remote Access VPN or Mobile Access Software Blades. A Security fix that mitigates this vulnerability is available.

- [https://github.com/khdertaysh1/CVE-2024-24919-PoC](https://github.com/khdertaysh1/CVE-2024-24919-PoC) :  ![starts](https://img.shields.io/github/stars/khdertaysh1/CVE-2024-24919-PoC.svg) ![forks](https://img.shields.io/github/forks/khdertaysh1/CVE-2024-24919-PoC.svg)


## CVE-2024-4367
 A type check was missing when handling fonts in PDF.js, which would allow arbitrary JavaScript execution in the PDF.js context. This vulnerability affects Firefox  126, Firefox ESR  115.11, and Thunderbird  115.11.

- [https://github.com/remiBoudreau/CVE-2024-4367](https://github.com/remiBoudreau/CVE-2024-4367) :  ![starts](https://img.shields.io/github/stars/remiBoudreau/CVE-2024-4367.svg) ![forks](https://img.shields.io/github/forks/remiBoudreau/CVE-2024-4367.svg)


## CVE-2024-3094
Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.

- [https://github.com/ashrafzaryouh/CVE-2024-3094](https://github.com/ashrafzaryouh/CVE-2024-3094) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2024-3094.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2024-3094.svg)


## CVE-2023-48795
 The SSH transport protocol with certain OpenSSH extensions, found in OpenSSH before 9.6 and other products, allows remote attackers to bypass integrity checks such that some packets are omitted (from the extension negotiation message), and a client and server may consequently end up with a connection for which some security features have been downgraded or disabled, aka a Terrapin attack. This occurs because the SSH Binary Packet Protocol (BPP), implemented by these extensions, mishandles the handshake phase and mishandles use of sequence numbers. For example, there is an effective attack against SSH's use of ChaCha20-Poly1305 (and CBC with Encrypt-then-MAC). The bypass occurs in chacha20-poly1305@openssh.com and (if CBC is used) the -etm@openssh.com MAC algorithms. This also affects Maverick Synergy Java SSH API before 3.1.0-SNAPSHOT, Dropbear through 2022.83, Ssh before 5.1.1 in Erlang/OTP, PuTTY before 0.80, AsyncSSH before 2.14.2, golang.org/x/crypto before 0.17.0, libssh before 0.10.6, libssh2 through 1.11.0, Thorn Tech SFTP Gateway before 3.4.6, Tera Term before 5.1, Paramiko before 3.4.0, jsch before 0.2.15, SFTPGo before 2.5.6, Netgate pfSense Plus through 23.09.1, Netgate pfSense CE through 2.7.2, HPN-SSH through 18.2.0, ProFTPD before 1.3.8b (and before 1.3.9rc2), ORYX CycloneSSH before 2.3.4, NetSarang XShell 7 before Build 0144, CrushFTP before 10.6.0, ConnectBot SSH library before 2.2.22, Apache MINA sshd through 2.11.0, sshj through 0.37.0, TinySSH through 20230101, trilead-ssh2 6401, LANCOM LCOS and LANconfig, FileZilla before 3.66.4, Nova before 11.8, PKIX-SSH before 14.4, SecureCRT before 9.4.3, Transmit5 before 5.10.4, Win32-OpenSSH before 9.5.0.0p1-Beta, WinSCP before 6.2.2, Bitvise SSH Server before 9.32, Bitvise SSH Client before 9.33, KiTTY through 0.76.1.13, the net-ssh gem 7.2.0 for Ruby, the mscdex ssh2 module before 1.15.0 for Node.js, the thrussh library before 0.35.1 for Rust, and the Russh crate before 0.40.2 for Rust.

- [https://github.com/fumioryoto/Terrapin-attack](https://github.com/fumioryoto/Terrapin-attack) :  ![starts](https://img.shields.io/github/stars/fumioryoto/Terrapin-attack.svg) ![forks](https://img.shields.io/github/forks/fumioryoto/Terrapin-attack.svg)


## CVE-2023-41974
 A use-after-free issue was addressed with improved memory management. This issue is fixed in iOS 17 and iPadOS 17, iOS 15.8.7 and iPadOS 15.8.7. An app may be able to execute arbitrary code with kernel privileges.

- [https://github.com/kienhho/Solarium](https://github.com/kienhho/Solarium) :  ![starts](https://img.shields.io/github/stars/kienhho/Solarium.svg) ![forks](https://img.shields.io/github/forks/kienhho/Solarium.svg)


## CVE-2023-34468
You are recommended to upgrade to version 1.22.0 or later which fixes this issue.

- [https://github.com/mohammed-moshii/CVE-2023-34468-Apache-NiFi-RCE](https://github.com/mohammed-moshii/CVE-2023-34468-Apache-NiFi-RCE) :  ![starts](https://img.shields.io/github/stars/mohammed-moshii/CVE-2023-34468-Apache-NiFi-RCE.svg) ![forks](https://img.shields.io/github/forks/mohammed-moshii/CVE-2023-34468-Apache-NiFi-RCE.svg)


## CVE-2023-6931
We recommend upgrading past commit 382c27f4ed28f803b1f1473ac2d8db0afc795a1b.

- [https://github.com/koast18/cve-2023-6931-hitv205n](https://github.com/koast18/cve-2023-6931-hitv205n) :  ![starts](https://img.shields.io/github/stars/koast18/cve-2023-6931-hitv205n.svg) ![forks](https://img.shields.io/github/forks/koast18/cve-2023-6931-hitv205n.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/ashrafzaryouh/CVE-2022-22965](https://github.com/ashrafzaryouh/CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2022-22965.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/elbunkerhacker/CVE-2022-0847](https://github.com/elbunkerhacker/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/elbunkerhacker/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/elbunkerhacker/CVE-2022-0847.svg)
- [https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe-](https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe-) :  ![starts](https://img.shields.io/github/stars/Greetdawn/CVE-2022-0847-DirtyPipe-.svg) ![forks](https://img.shields.io/github/forks/Greetdawn/CVE-2022-0847-DirtyPipe-.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/asd58584388/CVE-2021-44228](https://github.com/asd58584388/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/asd58584388/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/asd58584388/CVE-2021-44228.svg)


## CVE-2020-35489
 The contact-form-7 (aka Contact Form 7) plugin before 5.3.2 for WordPress allows Unrestricted File Upload and remote code execution because a filename may contain special characters.

- [https://github.com/elabod1/SOC-wordpress-compromise-report](https://github.com/elabod1/SOC-wordpress-compromise-report) :  ![starts](https://img.shields.io/github/stars/elabod1/SOC-wordpress-compromise-report.svg) ![forks](https://img.shields.io/github/forks/elabod1/SOC-wordpress-compromise-report.svg)


## CVE-2020-17103
 Windows Cloud Files Mini Filter Driver Elevation of Privilege Vulnerability

- [https://github.com/ashrafzaryouh/CVE-2020-17103](https://github.com/ashrafzaryouh/CVE-2020-17103) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2020-17103.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2020-17103.svg)


## CVE-2020-11652
 An issue was discovered in SaltStack Salt before 2019.2.4 and 3000 before 3000.2. The salt-master process ClearFuncs class allows access to some methods that improperly sanitize paths. These methods allow arbitrary directory access to authenticated users.

- [https://github.com/codenamepetrel/salt-cve-2020-11651-poc](https://github.com/codenamepetrel/salt-cve-2020-11651-poc) :  ![starts](https://img.shields.io/github/stars/codenamepetrel/salt-cve-2020-11651-poc.svg) ![forks](https://img.shields.io/github/forks/codenamepetrel/salt-cve-2020-11651-poc.svg)


## CVE-2020-11651
 An issue was discovered in SaltStack Salt before 2019.2.4 and 3000 before 3000.2. The salt-master process ClearFuncs class does not properly validate method calls. This allows a remote user to access some methods without authentication. These methods can be used to retrieve user tokens from the salt master and/or run arbitrary commands on salt minions.

- [https://github.com/codenamepetrel/salt-cve-2020-11651-poc](https://github.com/codenamepetrel/salt-cve-2020-11651-poc) :  ![starts](https://img.shields.io/github/stars/codenamepetrel/salt-cve-2020-11651-poc.svg) ![forks](https://img.shields.io/github/forks/codenamepetrel/salt-cve-2020-11651-poc.svg)


## CVE-2020-5902
 In BIG-IP versions 15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 13.1.0-13.1.3.3, 12.1.0-12.1.5.1, and 11.6.1-11.6.5.1, the Traffic Management User Interface (TMUI), also referred to as the Configuration utility, has a Remote Code Execution (RCE) vulnerability in undisclosed pages.

- [https://github.com/ashrafzaryouh/CVE-2020-5902](https://github.com/ashrafzaryouh/CVE-2020-5902) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2020-5902.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2020-5902.svg)


## CVE-2019-6693
 Use of a hard-coded cryptographic key to cipher sensitive data in FortiOS configuration backup file may allow an attacker with access to the backup file to decipher the sensitive data, via knowledge of the hard-coded key. The aforementioned sensitive data includes users' passwords (except the administrator's password), private keys' passphrases and High Availability password (when set).

- [https://github.com/lureprey/fortidecrypter-CVE-2019-6693](https://github.com/lureprey/fortidecrypter-CVE-2019-6693) :  ![starts](https://img.shields.io/github/stars/lureprey/fortidecrypter-CVE-2019-6693.svg) ![forks](https://img.shields.io/github/forks/lureprey/fortidecrypter-CVE-2019-6693.svg)


## CVE-2018-4878
 A use-after-free vulnerability was discovered in Adobe Flash Player before 28.0.0.161. This vulnerability occurs due to a dangling pointer in the Primetime SDK related to media player handling of listener objects. A successful attack can lead to arbitrary code execution. This was exploited in the wild in January and February 2018.

- [https://github.com/msmacu/cve-2018-4878-adobe-flash-drm-uaf-0day](https://github.com/msmacu/cve-2018-4878-adobe-flash-drm-uaf-0day) :  ![starts](https://img.shields.io/github/stars/msmacu/cve-2018-4878-adobe-flash-drm-uaf-0day.svg) ![forks](https://img.shields.io/github/forks/msmacu/cve-2018-4878-adobe-flash-drm-uaf-0day.svg)


## CVE-2017-0144
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/ashrafzaryouh/CVE-2017-0144](https://github.com/ashrafzaryouh/CVE-2017-0144) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2017-0144.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2017-0144.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock."  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/ashrafzaryouh/CVE-2014-6271](https://github.com/ashrafzaryouh/CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2014-6271.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/ashrafzaryouh/CVE-2014-0160](https://github.com/ashrafzaryouh/CVE-2014-0160) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2014-0160.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2014-0160.svg)

