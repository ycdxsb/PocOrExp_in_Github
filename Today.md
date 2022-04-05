# Update 2022-04-05
## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/FourCoreLabs/spring4shell-exploit-poc](https://github.com/FourCoreLabs/spring4shell-exploit-poc) :  ![starts](https://img.shields.io/github/stars/FourCoreLabs/spring4shell-exploit-poc.svg) ![forks](https://img.shields.io/github/forks/FourCoreLabs/spring4shell-exploit-poc.svg)
- [https://github.com/itsecurityco/CVE-2022-22965](https://github.com/itsecurityco/CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/itsecurityco/CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/itsecurityco/CVE-2022-22965.svg)
- [https://github.com/me2nuk/CVE-2022-22965](https://github.com/me2nuk/CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/me2nuk/CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/me2nuk/CVE-2022-22965.svg)


## CVE-2022-22963
 In Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions, when using routing functionality it is possible for a user to provide a specially crafted SpEL as a routing-expression that may result in remote code execution and access to local resources.

- [https://github.com/twseptian/cve-2022-22963](https://github.com/twseptian/cve-2022-22963) :  ![starts](https://img.shields.io/github/stars/twseptian/cve-2022-22963.svg) ![forks](https://img.shields.io/github/forks/twseptian/cve-2022-22963.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/xnderLAN/CVE-2022-0847](https://github.com/xnderLAN/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/xnderLAN/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/xnderLAN/CVE-2022-0847.svg)


## CVE-2021-43267
 An issue was discovered in net/tipc/crypto.c in the Linux kernel before 5.14.16. The Transparent Inter-Process Communication (TIPC) functionality allows remote attackers to exploit insufficient validation of user-supplied sizes for the MSG_CRYPTO message type.

- [https://github.com/zzhacked/CVE-2021-43267](https://github.com/zzhacked/CVE-2021-43267) :  ![starts](https://img.shields.io/github/stars/zzhacked/CVE-2021-43267.svg) ![forks](https://img.shields.io/github/forks/zzhacked/CVE-2021-43267.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/bernardas/netsec-polygon](https://github.com/bernardas/netsec-polygon) :  ![starts](https://img.shields.io/github/stars/bernardas/netsec-polygon.svg) ![forks](https://img.shields.io/github/forks/bernardas/netsec-polygon.svg)


## CVE-2021-41653
 The PING function on the TP-Link TL-WR840N EU v5 router with firmware through TL-WR840N(EU)_V5_171211 is vulnerable to remote code execution via a crafted payload in an IP address input field.

- [https://github.com/likeww/CVE-2021-41653](https://github.com/likeww/CVE-2021-41653) :  ![starts](https://img.shields.io/github/stars/likeww/CVE-2021-41653.svg) ![forks](https://img.shields.io/github/forks/likeww/CVE-2021-41653.svg)


## CVE-2021-40438
 A crafted request uri-path can cause mod_proxy to forward the request to an origin server choosen by the remote user. This issue affects Apache HTTP Server 2.4.48 and earlier.

- [https://github.com/Kashkovsky/CVE-2021-40438](https://github.com/Kashkovsky/CVE-2021-40438) :  ![starts](https://img.shields.io/github/stars/Kashkovsky/CVE-2021-40438.svg) ![forks](https://img.shields.io/github/forks/Kashkovsky/CVE-2021-40438.svg)


## CVE-2021-36934
 Windows Elevation of Privilege Vulnerability

- [https://github.com/firefart/hivenightmare](https://github.com/firefart/hivenightmare) :  ![starts](https://img.shields.io/github/stars/firefart/hivenightmare.svg) ![forks](https://img.shields.io/github/forks/firefart/hivenightmare.svg)


## CVE-2021-32849
 Gerapy is a distributed crawler management framework. Prior to version 0.9.9, an authenticated user could execute arbitrary commands. This issue is fixed in version 0.9.9. There are no known workarounds.

- [https://github.com/avboy1337/CVE-2021-32849](https://github.com/avboy1337/CVE-2021-32849) :  ![starts](https://img.shields.io/github/stars/avboy1337/CVE-2021-32849.svg) ![forks](https://img.shields.io/github/forks/avboy1337/CVE-2021-32849.svg)


## CVE-2021-32789
 woocommerce-gutenberg-products-block is a feature plugin for WooCommerce Gutenberg Blocks. An SQL injection vulnerability impacts all WooCommerce sites running the WooCommerce Blocks feature plugin between version 2.5.0 and prior to version 2.5.16. Via a carefully crafted URL, an exploit can be executed against the `wc/store/products/collection-data?calculate_attribute_counts[][taxonomy]` endpoint that allows the execution of a read only sql query. There are patches for many versions of this package, starting with version 2.5.16. There are no known workarounds aside from upgrading.

- [https://github.com/andnorack/CVE-2021-32789](https://github.com/andnorack/CVE-2021-32789) :  ![starts](https://img.shields.io/github/stars/andnorack/CVE-2021-32789.svg) ![forks](https://img.shields.io/github/forks/andnorack/CVE-2021-32789.svg)


## CVE-2021-24084
 Windows Mobile Device Management Information Disclosure Vulnerability

- [https://github.com/Jeromeyoung/CVE-2021-24084](https://github.com/Jeromeyoung/CVE-2021-24084) :  ![starts](https://img.shields.io/github/stars/Jeromeyoung/CVE-2021-24084.svg) ![forks](https://img.shields.io/github/forks/Jeromeyoung/CVE-2021-24084.svg)


## CVE-2021-21224
 Type confusion in V8 in Google Chrome prior to 90.0.4430.85 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page.

- [https://github.com/lnfernal/CVE-2021-21224](https://github.com/lnfernal/CVE-2021-21224) :  ![starts](https://img.shields.io/github/stars/lnfernal/CVE-2021-21224.svg) ![forks](https://img.shields.io/github/forks/lnfernal/CVE-2021-21224.svg)


## CVE-2021-20837
 Movable Type 7 r.5002 and earlier (Movable Type 7 Series), Movable Type 6.8.2 and earlier (Movable Type 6 Series), Movable Type Advanced 7 r.5002 and earlier (Movable Type Advanced 7 Series), Movable Type Advanced 6.8.2 and earlier (Movable Type Advanced 6 Series), Movable Type Premium 1.46 and earlier, and Movable Type Premium Advanced 1.46 and earlier allow remote attackers to execute arbitrary OS commands via unspecified vectors. Note that all versions of Movable Type 4.0 or later including unsupported (End-of-Life, EOL) versions are also affected by this vulnerability.

- [https://github.com/avboy1337/CVE-2021-20837](https://github.com/avboy1337/CVE-2021-20837) :  ![starts](https://img.shields.io/github/stars/avboy1337/CVE-2021-20837.svg) ![forks](https://img.shields.io/github/forks/avboy1337/CVE-2021-20837.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/Ph4nt0mh4x0r/auto-CVE-2021-4034](https://github.com/Ph4nt0mh4x0r/auto-CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Ph4nt0mh4x0r/auto-CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Ph4nt0mh4x0r/auto-CVE-2021-4034.svg)


## CVE-2021-3129
 Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.

- [https://github.com/selectarget/laravel-CVE-2021-3129-EXP](https://github.com/selectarget/laravel-CVE-2021-3129-EXP) :  ![starts](https://img.shields.io/github/stars/selectarget/laravel-CVE-2021-3129-EXP.svg) ![forks](https://img.shields.io/github/forks/selectarget/laravel-CVE-2021-3129-EXP.svg)


## CVE-2021-2119
 Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The supported version that is affected is Prior to 6.1.18. Easily exploitable vulnerability allows high privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle VM VirtualBox accessible data. CVSS 3.1 Base Score 6.0 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N).

- [https://github.com/shi10587s/Sauercloude](https://github.com/shi10587s/Sauercloude) :  ![starts](https://img.shields.io/github/stars/shi10587s/Sauercloude.svg) ![forks](https://img.shields.io/github/forks/shi10587s/Sauercloude.svg)


## CVE-2020-0471
 In reassemble_and_dispatch of packet_fragmenter.cc, there is a possible way to inject packets into an encrypted Bluetooth connection due to improper input validation. This could lead to remote escalation of privilege between two Bluetooth devices by a proximal attacker, with no additional execution privileges needed. User interaction is not needed for exploitation. Product: Android; Versions: Android-8.0, Android-8.1, Android-9, Android-10, Android-11; Android ID: A-169327567.

- [https://github.com/nanopathi/system_bt_AOSP10_r33_CVE-2020-0471](https://github.com/nanopathi/system_bt_AOSP10_r33_CVE-2020-0471) :  ![starts](https://img.shields.io/github/stars/nanopathi/system_bt_AOSP10_r33_CVE-2020-0471.svg) ![forks](https://img.shields.io/github/forks/nanopathi/system_bt_AOSP10_r33_CVE-2020-0471.svg)


## CVE-2020-0413
 In gatt_process_read_by_type_rsp of gatt_cl.cc, there is a possible out of bounds read due to a missing bounds check. This could lead to remote information disclosure in the Bluetooth server with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-8.1 Android-9 Android-10 Android-11 Android-8.0Android ID: A-158778659

- [https://github.com/Satheesh575555/system_bt_AOSP10_r33_CVE-2020-0413](https://github.com/Satheesh575555/system_bt_AOSP10_r33_CVE-2020-0413) :  ![starts](https://img.shields.io/github/stars/Satheesh575555/system_bt_AOSP10_r33_CVE-2020-0413.svg) ![forks](https://img.shields.io/github/forks/Satheesh575555/system_bt_AOSP10_r33_CVE-2020-0413.svg)


## CVE-2020-0377
 In gatt_process_read_by_type_rsp of gatt_cl.cc, there is a possible out of bounds read due to a missing bounds check. This could lead to remote information disclosure in the Bluetooth server with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-8.1 Android-9 Android-10 Android-11 Android-8.0Android ID: A-158833854

- [https://github.com/Satheesh575555/system_bt_AOSP10_r33_CVE-2020-0377](https://github.com/Satheesh575555/system_bt_AOSP10_r33_CVE-2020-0377) :  ![starts](https://img.shields.io/github/stars/Satheesh575555/system_bt_AOSP10_r33_CVE-2020-0377.svg) ![forks](https://img.shields.io/github/forks/Satheesh575555/system_bt_AOSP10_r33_CVE-2020-0377.svg)


## CVE-2018-7600
 Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations.

- [https://github.com/firefart/CVE-2018-7600](https://github.com/firefart/CVE-2018-7600) :  ![starts](https://img.shields.io/github/stars/firefart/CVE-2018-7600.svg) ![forks](https://img.shields.io/github/forks/firefart/CVE-2018-7600.svg)
- [https://github.com/persian64/CVE-2018-7600](https://github.com/persian64/CVE-2018-7600) :  ![starts](https://img.shields.io/github/stars/persian64/CVE-2018-7600.svg) ![forks](https://img.shields.io/github/forks/persian64/CVE-2018-7600.svg)


## CVE-2016-1827
 The kernel in Apple iOS before 9.3.2, OS X before 10.11.5, tvOS before 9.2.1, and watchOS before 2.2.1 allows attackers to execute arbitrary code in a privileged context or cause a denial of service (memory corruption) via a crafted app, a different vulnerability than CVE-2016-1828, CVE-2016-1829, and CVE-2016-1830.

- [https://github.com/superMan7912002/bazad3](https://github.com/superMan7912002/bazad3) :  ![starts](https://img.shields.io/github/stars/superMan7912002/bazad3.svg) ![forks](https://img.shields.io/github/forks/superMan7912002/bazad3.svg)

