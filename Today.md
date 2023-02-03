# Update 2023-02-03
## CVE-2023-25012
 The Linux kernel through 6.1.9 has a Use-After-Free in bigben_remove in drivers/hid/hid-bigbenff.c via a crafted USB device because the LED controllers remain registered for too long.

- [https://github.com/Live-Hack-CVE/CVE-2023-25012](https://github.com/Live-Hack-CVE/CVE-2023-25012) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25012.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25012.svg)


## CVE-2023-24977
 Out-of-bounds Read vulnerability in Apache Software Foundation Apache InLong.This issue affects Apache InLong: from 1.1.0 through 1.5.0. Users are advised to upgrade to Apache InLong's latest version or cherry-pick https://github.com/apache/inlong/pull/7214 https://github.com/apache/inlong/pull/7214 to solve it.

- [https://github.com/Live-Hack-CVE/CVE-2023-24977](https://github.com/Live-Hack-CVE/CVE-2023-24977) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24977.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24977.svg)


## CVE-2023-24170
 Tenda AC18 V15.03.05.19 is vulnerable to Buffer Overflow via /goform/fromSetWirelessRepeat.

- [https://github.com/Live-Hack-CVE/CVE-2023-24170](https://github.com/Live-Hack-CVE/CVE-2023-24170) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24170.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24170.svg)


## CVE-2023-24169
 Tenda AC18 V15.03.05.19 is vulnerable to Buffer Overflow via /goform/FUN_0007343c.

- [https://github.com/Live-Hack-CVE/CVE-2023-24169](https://github.com/Live-Hack-CVE/CVE-2023-24169) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24169.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24169.svg)


## CVE-2023-24167
 Tenda AC18 V15.03.05.19 is vulnerable to Buffer Overflow via /goform/add_white_node.

- [https://github.com/Live-Hack-CVE/CVE-2023-24167](https://github.com/Live-Hack-CVE/CVE-2023-24167) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24167.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24167.svg)


## CVE-2023-24166
 Tenda AC18 V15.03.05.19 is vulnerable to Buffer Overflow via /goform/formWifiBasicSet.

- [https://github.com/Live-Hack-CVE/CVE-2023-24166](https://github.com/Live-Hack-CVE/CVE-2023-24166) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24166.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24166.svg)


## CVE-2023-24165
 Tenda AC18 V15.03.05.19 is vulnerable to Buffer Overflow via /goform/initIpAddrInfo.

- [https://github.com/Live-Hack-CVE/CVE-2023-24165](https://github.com/Live-Hack-CVE/CVE-2023-24165) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24165.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24165.svg)


## CVE-2023-24164
 Tenda AC18 V15.03.05.19 is vulnerable to Buffer Overflow via /goform/FUN_000c2318.

- [https://github.com/Live-Hack-CVE/CVE-2023-24164](https://github.com/Live-Hack-CVE/CVE-2023-24164) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24164.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24164.svg)


## CVE-2023-23969
 In Django 3.2 before 3.2.17, 4.0 before 4.0.9, and 4.1 before 4.1.6, the parsed values of Accept-Language headers are cached in order to avoid repetitive parsing. This leads to a potential denial-of-service vector via excessive memory usage if the raw value of Accept-Language headers is very large.

- [https://github.com/Live-Hack-CVE/CVE-2023-23969](https://github.com/Live-Hack-CVE/CVE-2023-23969) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23969.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23969.svg)


## CVE-2023-23924
 Dompdf is an HTML to PDF converter. The URI validation on dompdf 2.0.1 can be bypassed on SVG parsing by passing `&lt;image&gt;` tags with uppercase letters. This may lead to arbitrary object unserialize on PHP &lt; 8, through the `phar` URL wrapper. An attacker can exploit the vulnerability to call arbitrary URL with arbitrary protocols, if they can provide a SVG file to dompdf. In PHP versions before 8.0.0, it leads to arbitrary unserialize, that will lead to the very least to an arbitrary file deletion and even remote code execution, depending on classes that are available.

- [https://github.com/motikan2010/CVE-2023-23924](https://github.com/motikan2010/CVE-2023-23924) :  ![starts](https://img.shields.io/github/stars/motikan2010/CVE-2023-23924.svg) ![forks](https://img.shields.io/github/forks/motikan2010/CVE-2023-23924.svg)


## CVE-2023-23846
 Due to insufficient length validation in the Open5GS GTP library versions prior to versions 2.4.13 and 2.5.7, when parsing extension headers in GPRS tunneling protocol (GPTv1-U) messages, a protocol payload with any extension header length set to zero causes an infinite loop. The affected process becomes immediately unresponsive, resulting in denial of service and excessive resource consumption. CVSS3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:P/RL:O/RC:C

- [https://github.com/Live-Hack-CVE/CVE-2023-23846](https://github.com/Live-Hack-CVE/CVE-2023-23846) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23846.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23846.svg)


## CVE-2023-23751
 An issue was discovered in Joomla! 4.0.0 through 4.2.4. A missing ACL check allows non super-admin users to access com_actionlogs.

- [https://github.com/Live-Hack-CVE/CVE-2023-23751](https://github.com/Live-Hack-CVE/CVE-2023-23751) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23751.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23751.svg)


## CVE-2023-23750
 An issue was discovered in Joomla! 4.0.0 through 4.2.6. A missing token check causes a CSRF vulnerability in the handling of post-installation messages.

- [https://github.com/Live-Hack-CVE/CVE-2023-23750](https://github.com/Live-Hack-CVE/CVE-2023-23750) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23750.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23750.svg)


## CVE-2023-22724
 GLPI is a Free Asset and IT Management Software package. Versions prior to 10.0.6 are subject to Cross-site Scripting via malicious RSS feeds. An Administrator can import a malicious RSS feed that contains Cross Site Scripting (XSS) payloads inside RSS links. Victims who wish to visit an RSS content and click on the link will execute the Javascript. This issue is patched in 10.0.6.

- [https://github.com/Live-Hack-CVE/CVE-2023-22724](https://github.com/Live-Hack-CVE/CVE-2023-22724) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22724.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22724.svg)


## CVE-2023-22722
 GLPI is a Free Asset and IT Management Software package. Versions 9.4.0 and above, prior to 10.0.6 are subject to Cross-site Scripting. An attacker can persuade a victim into opening a URL containing a payload exploiting this vulnerability. After exploited, the attacker can make actions as the victim or exfiltrate session cookies. This issue is patched in version 10.0.6.

- [https://github.com/Live-Hack-CVE/CVE-2023-22722](https://github.com/Live-Hack-CVE/CVE-2023-22722) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22722.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22722.svg)


## CVE-2023-22664
 On BIG-IP versions 17.0.x before 17.0.0.2 and 16.1.x before 16.1.3.3, and BIG-IP SPK starting in version 1.6.0, when a client-side HTTP/2 profile and the HTTP MRF Router option are enabled for a virtual server, undisclosed requests can cause an increase in memory resource utilization. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/Live-Hack-CVE/CVE-2023-22664](https://github.com/Live-Hack-CVE/CVE-2023-22664) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22664.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22664.svg)


## CVE-2023-22657
 On F5OS-A beginning in version 1.2.0 to before 1.3.0 and F5OS-C beginning in version 1.3.0 to before 1.5.0, processing F5OS tenant file names may allow for command injection. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/Live-Hack-CVE/CVE-2023-22657](https://github.com/Live-Hack-CVE/CVE-2023-22657) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22657.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22657.svg)


## CVE-2023-22574
 Dell PowerScale OneFS 9.0.0.x - 9.4.0.x contain an insertion of sensitive information into log file vulnerability in platform API of IPMI module. A low-privileged user with permission to read logs on the cluster could potentially exploit this vulnerability, leading to Information disclosure and denial of service.

- [https://github.com/Live-Hack-CVE/CVE-2023-22574](https://github.com/Live-Hack-CVE/CVE-2023-22574) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22574.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22574.svg)


## CVE-2023-22573
 Dell PowerScale OneFS 9.0.0.x-9.4.0.x contain an insertion of sensitive information into log file vulnerability in cloudpool. A low privileged local attacker could potentially exploit this vulnerability, leading to sensitive information disclosure.

- [https://github.com/Live-Hack-CVE/CVE-2023-22573](https://github.com/Live-Hack-CVE/CVE-2023-22573) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22573.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22573.svg)


## CVE-2023-22501
 An authentication vulnerability was discovered in Jira Service Management Server and Data Center which allows an attacker to impersonate another user and gain access to a Jira Service Management instance under certain circumstances_._ With write access to a User Directory and outgoing email enabled on a Jira Service Management instance, an attacker could gain access to signup tokens sent to users with accounts that have never been logged into. Access to these tokens can be obtained in two cases: * If the attacker is included on Jira issues or requests with these users, or * If the attacker is forwarded or otherwise gains access to emails containing a &#8220;View Request&#8221; link from these users. Bot accounts are particularly susceptible to this scenario. On instances with single sign-on, external customer accounts can be affected in projects where anyone can create their own account.

- [https://github.com/Live-Hack-CVE/CVE-2023-22501](https://github.com/Live-Hack-CVE/CVE-2023-22501) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22501.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22501.svg)


## CVE-2023-22500
 GLPI is a Free Asset and IT Management Software package. Versions 10.0.0 and above, prior to 10.0.6 are vulnerable to Incorrect Authorization. This vulnerability allow unauthorized access to inventory files. Thus, if anonymous access to FAQ is allowed, inventory files are accessbile by unauthenticated users. This issue is patched in version 10.0.6. As a workaround, disable native inventory and delete inventory files from server (default location is `files/_inventory`).

- [https://github.com/Live-Hack-CVE/CVE-2023-22500](https://github.com/Live-Hack-CVE/CVE-2023-22500) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22500.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22500.svg)


## CVE-2023-22422
 On BIG-IP versions 17.0.x before 17.0.0.2 and 16.1.x before 16.1.3.3, when a HTTP profile with the non-default Enforcement options of Enforce HTTP Compliance and Unknown Methods: Reject are configured on a virtual server, undisclosed requests can cause the Traffic Management Microkernel (TMM) to terminate. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/Live-Hack-CVE/CVE-2023-22422](https://github.com/Live-Hack-CVE/CVE-2023-22422) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22422.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22422.svg)


## CVE-2023-22418
 On versions 17.0.x before 17.0.0.2, 16.1.x before 16.1.3.3, 15.1.x before 15.1.7, 14.1.x before 14.1.5.3, and all versions of 13.1.x, an open redirect vulnerability exists on virtual servers enabled with a BIG-IP APM access policy. This vulnerability allows an unauthenticated malicious attacker to build an open redirect URI. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/Live-Hack-CVE/CVE-2023-22418](https://github.com/Live-Hack-CVE/CVE-2023-22418) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22418.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22418.svg)


## CVE-2023-22374
 In BIG-IP starting in versions 17.0.0, 16.1.2.2, 15.1.5.1, 14.1.4.6, and 13.1.5 on their respective branches, a format string vulnerability exists in iControl SOAP that allows an authenticated attacker to crash the iControl SOAP CGI process or, potentially execute arbitrary code. In appliance mode BIG-IP, a successful exploit of this vulnerability can allow the attacker to cross a security boundary. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/Live-Hack-CVE/CVE-2023-22374](https://github.com/Live-Hack-CVE/CVE-2023-22374) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22374.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22374.svg)


## CVE-2023-22358
 In versions beginning with 7.2.2 to before 7.2.3.1, a DLL hijacking vulnerability exists in the BIG-IP Edge Client Windows Installer. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/Live-Hack-CVE/CVE-2023-22358](https://github.com/Live-Hack-CVE/CVE-2023-22358) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22358.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22358.svg)


## CVE-2023-22341
 On version 14.1.x before 14.1.5.3, and all versions of 13.1.x, when the BIG-IP APM system is configured with all the following elements, undisclosed requests may cause the Traffic Management Microkernel (TMM) to terminate: * An OAuth Server that references an OAuth Provider * An OAuth profile with the Authorization Endpoint set to '/' * An access profile that references the above OAuth profile and is associated with an HTTPS virtual server Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/Live-Hack-CVE/CVE-2023-22341](https://github.com/Live-Hack-CVE/CVE-2023-22341) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22341.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22341.svg)


## CVE-2023-22340
 On BIG-IP versions 16.1.x before 16.1.3.3, 15.1.x before 15.1.8, 14.1.x before 14.1.5.3, and all versions of 13.1.x, when a SIP profile is configured on a Message Routing type virtual server, undisclosed traffic can cause TMM to terminate. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/Live-Hack-CVE/CVE-2023-22340](https://github.com/Live-Hack-CVE/CVE-2023-22340) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22340.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22340.svg)


## CVE-2023-22326
 In BIG-IP versions 17.0.x before 17.0.0.2, 16.1.x before 16.1.3.3, 15.1.x before 15.1.8.1, 14.1.x before 14.1.5.3, and all versions of 13.1.x, and all versions of BIG-IQ 8.x and 7.1.x, incorrect permission assignment vulnerabilities exist in the iControl REST and TMOS shell (tmsh) dig command which may allow an authenticated attacker with resource administrator or administrator role privileges to view sensitive information. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/Live-Hack-CVE/CVE-2023-22326](https://github.com/Live-Hack-CVE/CVE-2023-22326) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22326.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22326.svg)


## CVE-2023-22323
 In BIP-IP versions 17.0.x before 17.0.0.2, 16.1.x before 16.1.3.3, 15.1.x before 15.1.8.1, 14.1.x before 14.1.5.3, and all versions of 13.1.x, when OCSP authentication profile is configured on a virtual server, undisclosed requests can cause an increase in CPU resource utilization. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/Live-Hack-CVE/CVE-2023-22323](https://github.com/Live-Hack-CVE/CVE-2023-22323) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22323.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22323.svg)


## CVE-2023-22302
 In BIG-IP versions 17.0.x before 17.0.0.2, and 16.1.x beginning in 16.1.2.2 to before 16.1.3.3, when an HTTP profile is configured on a virtual server and conditions beyond the attacker&#8217;s control exist on the target pool member, undisclosed requests sent to the BIG-IP system can cause the Traffic Management Microkernel (TMM) to terminate. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/Live-Hack-CVE/CVE-2023-22302](https://github.com/Live-Hack-CVE/CVE-2023-22302) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22302.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22302.svg)


## CVE-2023-22283
 On versions beginning in 7.1.5 to before 7.2.3.1, a DLL hijacking vulnerability exists in the BIG-IP Edge Client for Windows. User interaction and administrative privileges are required to exploit this vulnerability because the victim user needs to run the executable on the system and the attacker requires administrative privileges for modifying the files in the trusted search path. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/Live-Hack-CVE/CVE-2023-22283](https://github.com/Live-Hack-CVE/CVE-2023-22283) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22283.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22283.svg)


## CVE-2023-22281
 On versions 17.0.x before 17.0.0.2, 16.1.x before 16.1.3.3, 15.1.x before 15.1.8, 14.1.x before 14.1.5.3, and all versions of 13.1.x, when a BIG-IP AFM NAT policy with a destination NAT rule is configured on a FastL4 virtual server, undisclosed traffic can cause the Traffic Management Microkernel (TMM) to terminate. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/Live-Hack-CVE/CVE-2023-22281](https://github.com/Live-Hack-CVE/CVE-2023-22281) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22281.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22281.svg)


## CVE-2023-20922
 In setMimeGroup of PackageManagerService.java, there is a possible crash loop due to resource exhaustion. This could lead to local denial of service with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-11 Android-12 Android-12L Android-13Android ID: A-237291548

- [https://github.com/Live-Hack-CVE/CVE-2023-20922](https://github.com/Live-Hack-CVE/CVE-2023-20922) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20922.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20922.svg)


## CVE-2023-20921
 In onPackageRemoved of AccessibilityManagerService.java, there is a possibility to automatically grant accessibility services due to a logic error in the code. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12L Android-13Android ID: A-243378132

- [https://github.com/Live-Hack-CVE/CVE-2023-20921](https://github.com/Live-Hack-CVE/CVE-2023-20921) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20921.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20921.svg)


## CVE-2023-20920
 In queue of UsbRequest.java, there is a possible way to corrupt memory due to a use after free. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12L Android-13Android ID: A-204584366

- [https://github.com/Live-Hack-CVE/CVE-2023-20920](https://github.com/Live-Hack-CVE/CVE-2023-20920) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20920.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20920.svg)


## CVE-2023-20919
 In getStringsForPrefix of Settings.java, there is a possible prevention of package uninstallation due to a logic error in the code. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-252663068

- [https://github.com/Live-Hack-CVE/CVE-2023-20919](https://github.com/Live-Hack-CVE/CVE-2023-20919) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20919.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20919.svg)


## CVE-2023-20916
 In getMainActivityLaunchIntent of LauncherAppsService.java, there is a possible way to bypass the restrictions on starting activities from the background due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-12 Android-12LAndroid ID: A-229256049

- [https://github.com/Live-Hack-CVE/CVE-2023-20916](https://github.com/Live-Hack-CVE/CVE-2023-20916) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20916.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20916.svg)


## CVE-2023-20856
 VMware vRealize Operations (vROps) contains a CSRF bypass vulnerability. A malicious user could execute actions on the vROps platform on behalf of the authenticated victim user.

- [https://github.com/Live-Hack-CVE/CVE-2023-20856](https://github.com/Live-Hack-CVE/CVE-2023-20856) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20856.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20856.svg)


## CVE-2023-0619
 The Kraken.io Image Optimizer plugin for WordPress is vulnerable to authorization bypass due to a missing capability check on its AJAX actions in versions up to, and including, 2.6.8. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to reset image optimizations.

- [https://github.com/Live-Hack-CVE/CVE-2023-0619](https://github.com/Live-Hack-CVE/CVE-2023-0619) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0619.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0619.svg)


## CVE-2023-0613
 A vulnerability has been found in TRENDnet TEW-811DRU 1.0.10.0 and classified as critical. Affected by this vulnerability is an unknown functionality of the file /wireless/security.asp of the component httpd. The manipulation leads to memory corruption. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-219937 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2023-0613](https://github.com/Live-Hack-CVE/CVE-2023-0613) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0613.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0613.svg)


## CVE-2023-0612
 A vulnerability, which was classified as critical, was found in TRENDnet TEW-811DRU 1.0.10.0. Affected is an unknown function of the file /wireless/basic.asp of the component httpd. The manipulation leads to buffer overflow. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-219936.

- [https://github.com/Live-Hack-CVE/CVE-2023-0612](https://github.com/Live-Hack-CVE/CVE-2023-0612) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0612.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0612.svg)


## CVE-2023-0611
 A vulnerability, which was classified as critical, has been found in TRENDnet TEW-652BRP 3.04B01. This issue affects some unknown processing of the file get_set.ccp of the component Web Management Interface. The manipulation leads to command injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-219935.

- [https://github.com/Live-Hack-CVE/CVE-2023-0611](https://github.com/Live-Hack-CVE/CVE-2023-0611) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0611.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0611.svg)


## CVE-2023-0610
 Improper Authorization in GitHub repository wallabag/wallabag prior to 2.5.3.

- [https://github.com/Live-Hack-CVE/CVE-2023-0610](https://github.com/Live-Hack-CVE/CVE-2023-0610) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0610.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0610.svg)


## CVE-2023-0609
 Improper Authorization in GitHub repository wallabag/wallabag prior to 2.5.3.

- [https://github.com/Live-Hack-CVE/CVE-2023-0609](https://github.com/Live-Hack-CVE/CVE-2023-0609) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0609.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0609.svg)


## CVE-2023-0608
 Cross-site Scripting (XSS) - DOM in GitHub repository microweber/microweber prior to 1.3.2.

- [https://github.com/Live-Hack-CVE/CVE-2023-0608](https://github.com/Live-Hack-CVE/CVE-2023-0608) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0608.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0608.svg)


## CVE-2023-0607
 Cross-site Scripting (XSS) - Stored in GitHub repository projectsend/projectsend prior to r1606.

- [https://github.com/Live-Hack-CVE/CVE-2023-0607](https://github.com/Live-Hack-CVE/CVE-2023-0607) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0607.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0607.svg)


## CVE-2023-0599
 Rapid7 Metasploit Pro versions 4.21.2 and lower suffer from a stored cross site scripting vulnerability, due to a lack of JavaScript request string sanitization. Using this vulnerability, an authenticated attacker can execute arbitrary HTML and script code in the target browser against another Metasploit Pro user using a specially crafted request. Note that in most deployments, all Metasploit Pro users tend to enjoy privileges equivalent to local administrator.

- [https://github.com/Live-Hack-CVE/CVE-2023-0599](https://github.com/Live-Hack-CVE/CVE-2023-0599) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0599.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0599.svg)


## CVE-2023-0587
 A file upload vulnerability in exists in Trend Micro Apex One server build 11110. Using a malformed Content-Length header in an HTTP PUT message sent to URL /officescan/console/html/cgi/fcgiOfcDDA.exe, an unauthenticated remote attacker can upload arbitrary files to the SampleSubmission directory (i.e., \PCCSRV\TEMP\SampleSubmission) on the server. The attacker can upload a large number of large files to fill up the file system on which the Apex One server is installed.

- [https://github.com/Live-Hack-CVE/CVE-2023-0587](https://github.com/Live-Hack-CVE/CVE-2023-0587) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0587.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0587.svg)


## CVE-2023-0524
 As part of our Security Development Lifecycle, a potential privilege escalation issue was identified internally. This could allow a malicious actor with sufficient permissions to modify environment variables and abuse an impacted plugin in order to escalate privileges. We have resolved the issue and also made several defense-in-depth fixes alongside. While the probability of successful exploitation is low, Tenable is committed to securing our customers&#8217; environments and our products. The updates have been distributed via the Tenable plugin feed in feed serial numbers equal to or greater than #202212212055.

- [https://github.com/Live-Hack-CVE/CVE-2023-0524](https://github.com/Live-Hack-CVE/CVE-2023-0524) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0524.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0524.svg)


## CVE-2023-0454
 OrangeScrum version 2.0.11 allows an authenticated external attacker to delete arbitrary local files from the server. This is possible because the application uses an unsanitized attacker-controlled parameter to construct an internal path.

- [https://github.com/Live-Hack-CVE/CVE-2023-0454](https://github.com/Live-Hack-CVE/CVE-2023-0454) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0454.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0454.svg)


## CVE-2023-0417
 Memory leak in the NFS dissector in Wireshark 4.0.0 to 4.0.2 and 3.6.0 to 3.6.10 and allows denial of service via packet injection or crafted capture file

- [https://github.com/Live-Hack-CVE/CVE-2023-0417](https://github.com/Live-Hack-CVE/CVE-2023-0417) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0417.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0417.svg)


## CVE-2023-0416
 GNW dissector crash in Wireshark 4.0.0 to 4.0.2 and 3.6.0 to 3.6.10 and allows denial of service via packet injection or crafted capture file

- [https://github.com/Live-Hack-CVE/CVE-2023-0416](https://github.com/Live-Hack-CVE/CVE-2023-0416) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0416.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0416.svg)


## CVE-2023-0415
 iSCSI dissector crash in Wireshark 4.0.0 to 4.0.2 and 3.6.0 to 3.6.10 and allows denial of service via packet injection or crafted capture file

- [https://github.com/Live-Hack-CVE/CVE-2023-0415](https://github.com/Live-Hack-CVE/CVE-2023-0415) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0415.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0415.svg)


## CVE-2023-0414
 Crash in the EAP dissector in Wireshark 4.0.0 to 4.0.2 allows denial of service via packet injection or crafted capture file

- [https://github.com/Live-Hack-CVE/CVE-2023-0414](https://github.com/Live-Hack-CVE/CVE-2023-0414) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0414.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0414.svg)


## CVE-2023-0413
 Dissection engine bug in Wireshark 4.0.0 to 4.0.2 and 3.6.0 to 3.6.10 and allows denial of service via packet injection or crafted capture file

- [https://github.com/Live-Hack-CVE/CVE-2023-0413](https://github.com/Live-Hack-CVE/CVE-2023-0413) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0413.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0413.svg)


## CVE-2023-0412
 TIPC dissector crash in Wireshark 4.0.0 to 4.0.2 and 3.6.0 to 3.6.10 and allows denial of service via packet injection or crafted capture file

- [https://github.com/Live-Hack-CVE/CVE-2023-0412](https://github.com/Live-Hack-CVE/CVE-2023-0412) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0412.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0412.svg)


## CVE-2023-0411
 Excessive loops in multiple dissectors in Wireshark 4.0.0 to 4.0.2 and 3.6.0 to 3.6.10 and allows denial of service via packet injection or crafted capture file

- [https://github.com/Live-Hack-CVE/CVE-2023-0411](https://github.com/Live-Hack-CVE/CVE-2023-0411) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0411.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0411.svg)


## CVE-2023-0115
 This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.

- [https://github.com/Live-Hack-CVE/CVE-2023-0115](https://github.com/Live-Hack-CVE/CVE-2023-0115) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0115.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0115.svg)


## CVE-2022-47983
 IBM InfoSphere Information Server 11.7 is vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 243161.

- [https://github.com/Live-Hack-CVE/CVE-2022-47983](https://github.com/Live-Hack-CVE/CVE-2022-47983) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47983.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47983.svg)


## CVE-2022-47872
 maccms10 2021.1000.2000 is vulnerable to Server-side request forgery (SSRF).

- [https://github.com/Live-Hack-CVE/CVE-2022-47872](https://github.com/Live-Hack-CVE/CVE-2022-47872) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47872.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47872.svg)


## CVE-2022-47717
 Last Yard 22.09.8-1 is vulnerable to Cross-origin resource sharing (CORS).

- [https://github.com/Live-Hack-CVE/CVE-2022-47717](https://github.com/Live-Hack-CVE/CVE-2022-47717) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47717.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47717.svg)


## CVE-2022-47715
 In Last Yard 22.09.8-1, the cookie can be stolen via via unencrypted traffic.

- [https://github.com/Live-Hack-CVE/CVE-2022-47715](https://github.com/Live-Hack-CVE/CVE-2022-47715) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47715.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47715.svg)


## CVE-2022-47714
 Last Yard 22.09.8-1 does not enforce HSTS headers

- [https://github.com/Live-Hack-CVE/CVE-2022-47714](https://github.com/Live-Hack-CVE/CVE-2022-47714) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47714.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47714.svg)


## CVE-2022-47073
 A cross-site scripting (XSS) vulnerability in the Create Ticket page of Small CRM v3.0 allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the Subject parameter.

- [https://github.com/Live-Hack-CVE/CVE-2022-47073](https://github.com/Live-Hack-CVE/CVE-2022-47073) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47073.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47073.svg)


## CVE-2022-47003
 A vulnerability in the Remember Me function of Mura CMS before v10.0.580 allows attackers to bypass authentication via a crafted web request.

- [https://github.com/Live-Hack-CVE/CVE-2022-47003](https://github.com/Live-Hack-CVE/CVE-2022-47003) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47003.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47003.svg)


## CVE-2022-47002
 A vulnerability in the Remember Me function of Masa CMS v7.2, 7.3, and 7.4-beta allows attackers to bypass authentication via a crafted web request.

- [https://github.com/Live-Hack-CVE/CVE-2022-47002](https://github.com/Live-Hack-CVE/CVE-2022-47002) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47002.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47002.svg)


## CVE-2022-46934
 kkFileView v4.1.0 was discovered to contain a cross-site scripting (XSS) vulnerability via the url parameter at /controller/OnlinePreviewController.java.

- [https://github.com/Live-Hack-CVE/CVE-2022-46934](https://github.com/Live-Hack-CVE/CVE-2022-46934) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46934.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46934.svg)


## CVE-2022-46756
 Dell VxRail, versions prior to 7.0.410, contain a Container Escape Vulnerability. A local high-privileged attacker could potentially exploit this vulnerability, leading to the execution of arbitrary OS commands on the container's underlying OS. Exploitation may lead to a system take over by an attacker.

- [https://github.com/Live-Hack-CVE/CVE-2022-46756](https://github.com/Live-Hack-CVE/CVE-2022-46756) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46756.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46756.svg)


## CVE-2022-46679
 Dell PowerScale OneFS 8.2.x, 9.0.0.x - 9.4.0.x, contain an insufficient resource pool vulnerability. A remote unauthenticated attacker could potentially exploit this vulnerability, leading to denial of service.

- [https://github.com/Live-Hack-CVE/CVE-2022-46679](https://github.com/Live-Hack-CVE/CVE-2022-46679) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46679.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46679.svg)


## CVE-2022-45783
 An issue was discovered in dotCMS core 4.x through 22.10.2. An authenticated directory traversal vulnerability in the dotCMS API can lead to Remote Code Execution.

- [https://github.com/Live-Hack-CVE/CVE-2022-45783](https://github.com/Live-Hack-CVE/CVE-2022-45783) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45783.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45783.svg)


## CVE-2022-45782
 An issue was discovered in dotCMS core 5.3.8.5 through 5.3.8.15 and 21.03 through 22.10.1. A cryptographically insecure random generation algorithm for password-reset token generation leads to account takeover.

- [https://github.com/Live-Hack-CVE/CVE-2022-45782](https://github.com/Live-Hack-CVE/CVE-2022-45782) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45782.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45782.svg)


## CVE-2022-45389
 A missing permission check in Jenkins XP-Dev Plugin 1.0 and earlier allows unauthenticated attackers to trigger builds of jobs corresponding to an attacker-specified repository.

- [https://github.com/Live-Hack-CVE/CVE-2022-45389](https://github.com/Live-Hack-CVE/CVE-2022-45389) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45389.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45389.svg)


## CVE-2022-45102
 Dell EMC Data Protection Central, versions 19.1 through 19.7, contains a Host Header Injection vulnerability. A remote unauthenticated attacker may potentially exploit this vulnerability by injecting arbitrary \u2018Host\u2019 header values to poison a web cache or trigger redirections.

- [https://github.com/Live-Hack-CVE/CVE-2022-45102](https://github.com/Live-Hack-CVE/CVE-2022-45102) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45102.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45102.svg)


## CVE-2022-45100
 Dell PowerScale OneFS, versions 8.2.x-9.3.x, contains an Improper Certificate Validation vulnerability. An remote unauthenticated attacker could potentially exploit this vulnerability, leading to a full compromise of the system.

- [https://github.com/Live-Hack-CVE/CVE-2022-45100](https://github.com/Live-Hack-CVE/CVE-2022-45100) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45100.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45100.svg)


## CVE-2022-45099
 Dell PowerScale OneFS, versions 8.2.x-9.4.x, contain a weak encoding for a NDMP password. A malicious and privileged local attacker could potentially exploit this vulnerability, leading to a full system compromise

- [https://github.com/Live-Hack-CVE/CVE-2022-45099](https://github.com/Live-Hack-CVE/CVE-2022-45099) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45099.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45099.svg)


## CVE-2022-45098
 Dell PowerScale OneFS, 9.0.0.x-9.4.0.x, contain a cleartext storage of sensitive information vulnerability in S3 component. An authenticated local attacker could potentially exploit this vulnerability, leading to information disclosure.

- [https://github.com/Live-Hack-CVE/CVE-2022-45098](https://github.com/Live-Hack-CVE/CVE-2022-45098) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45098.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45098.svg)


## CVE-2022-44257
 TOTOLINK LR350 V9.3.5u.6369_B20220309 contains a post-authentication buffer overflow via parameter pppoeUser in the setOpModeCfg function.

- [https://github.com/Live-Hack-CVE/CVE-2022-44257](https://github.com/Live-Hack-CVE/CVE-2022-44257) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44257.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44257.svg)


## CVE-2022-43922
 IBM App Connect Enterprise Certified Container 4.1, 4.2, 5.0, 5.1, 5.2, 6.0, 6.1, and 6.2 could disclose sensitive information to an attacker due to a weak hash of an API Key in the configuration. IBM X-Force ID: 241583.

- [https://github.com/Live-Hack-CVE/CVE-2022-43922](https://github.com/Live-Hack-CVE/CVE-2022-43922) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43922.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43922.svg)


## CVE-2022-43920
 IBM Sterling B2B Integrator Standard Edition 6.0.0.0 through 6.1.2.1 could allow an authenticated user to gain privileges in a different group due to an access control vulnerability in the Sftp server adapter. IBM X-Force ID: 241362.

- [https://github.com/Live-Hack-CVE/CVE-2022-43920](https://github.com/Live-Hack-CVE/CVE-2022-43920) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43920.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43920.svg)


## CVE-2022-43917
 IBM WebSphere Application Server 8.5 and 9.0 traditional container uses weaker than expected cryptographic keys that could allow an attacker to decrypt sensitive information. This affects only the containerized version of WebSphere Application Server traditional. IBM X-Force ID: 241045.

- [https://github.com/Live-Hack-CVE/CVE-2022-43917](https://github.com/Live-Hack-CVE/CVE-2022-43917) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43917.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43917.svg)


## CVE-2022-43864
 IBM Business Automation Workflow 22.0.2 could allow a remote attacker to traverse directories on the system. An attacker could send a specially crafted URL request containing &quot;dot dot&quot; sequences (/../) to view arbitrary files on the system. IBM X-Force ID: 239427.

- [https://github.com/Live-Hack-CVE/CVE-2022-43864](https://github.com/Live-Hack-CVE/CVE-2022-43864) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43864.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43864.svg)


## CVE-2022-42384
 This vulnerability allows remote attackers to disclose sensitive information on affected installations of PDF-XChange Editor. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of U3D files. Crafted data in a U3D file can trigger a read past the end of an allocated buffer. An attacker can leverage this in conjunction with other vulnerabilities to execute arbitrary code in the context of the current process. Was ZDI-CAN-18653.

- [https://github.com/Live-Hack-CVE/CVE-2022-42384](https://github.com/Live-Hack-CVE/CVE-2022-42384) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42384.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42384.svg)


## CVE-2022-42383
 This vulnerability allows remote attackers to disclose sensitive information on affected installations of PDF-XChange Editor. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of U3D files. Crafted data in a U3D file can trigger a read past the end of an allocated buffer. An attacker can leverage this in conjunction with other vulnerabilities to execute arbitrary code in the context of the current process. Was ZDI-CAN-18652.

- [https://github.com/Live-Hack-CVE/CVE-2022-42383](https://github.com/Live-Hack-CVE/CVE-2022-42383) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42383.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42383.svg)


## CVE-2022-42382
 This vulnerability allows remote attackers to execute arbitrary code on affected installations of PDF-XChange Editor. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of U3D files. Crafted data in a U3D file can trigger a write past the end of an allocated buffer. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-18651.

- [https://github.com/Live-Hack-CVE/CVE-2022-42382](https://github.com/Live-Hack-CVE/CVE-2022-42382) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42382.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42382.svg)


## CVE-2022-42381
 This vulnerability allows remote attackers to execute arbitrary code on affected installations of PDF-XChange Editor. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of U3D files. Crafted data in a U3D file can trigger a write past the end of an allocated buffer. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-18650.

- [https://github.com/Live-Hack-CVE/CVE-2022-42381](https://github.com/Live-Hack-CVE/CVE-2022-42381) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42381.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42381.svg)


## CVE-2022-42380
 This vulnerability allows remote attackers to execute arbitrary code on affected installations of PDF-XChange Editor. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of U3D files. Crafted data in a U3D file can trigger a write past the end of an allocated buffer. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-18649.

- [https://github.com/Live-Hack-CVE/CVE-2022-42380](https://github.com/Live-Hack-CVE/CVE-2022-42380) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42380.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42380.svg)


## CVE-2022-42378
 This vulnerability allows remote attackers to execute arbitrary code on affected installations of PDF-XChange Editor. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of U3D files. Crafted data in a U3D file can trigger a write past the end of an allocated buffer. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-18631.

- [https://github.com/Live-Hack-CVE/CVE-2022-42378](https://github.com/Live-Hack-CVE/CVE-2022-42378) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42378.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42378.svg)


## CVE-2022-41941
 GLPI is a Free Asset and IT Management Software package. Versions 10.0.0 and above, prior to 10.0.6, are subject to Cross-site Scripting. An administrator may store malicious code in help links. This issue is patched in 10.0.6.

- [https://github.com/Live-Hack-CVE/CVE-2022-41941](https://github.com/Live-Hack-CVE/CVE-2022-41941) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-41941.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-41941.svg)


## CVE-2022-41151
 This vulnerability allows remote attackers to execute arbitrary code on affected installations of PDF-XChange Editor. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of U3D files. Crafted data in a U3D file can trigger a write past the end of an allocated buffer. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-18341.

- [https://github.com/Live-Hack-CVE/CVE-2022-41151](https://github.com/Live-Hack-CVE/CVE-2022-41151) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-41151.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-41151.svg)


## CVE-2022-40036
 An issue was discovered in Rawchen blog-ssm v1.0 allows an attacker to obtain sensitive user information by bypassing permission checks via the /adminGetUserList component.

- [https://github.com/Live-Hack-CVE/CVE-2022-40036](https://github.com/Live-Hack-CVE/CVE-2022-40036) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-40036.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-40036.svg)


## CVE-2022-40035
 File Upload Vulnerability found in Rawchen Blog-ssm v1.0 allowing attackers to execute arbitrary commands and gain escalated privileges via the /uploadFileList component.

- [https://github.com/Live-Hack-CVE/CVE-2022-40035](https://github.com/Live-Hack-CVE/CVE-2022-40035) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-40035.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-40035.svg)


## CVE-2022-37034
 In dotCMS 5.x-22.06, it is possible to call the TempResource multiple times, each time requesting the dotCMS server to download a large file. If done repeatedly, this will result in Tomcat request-thread exhaustion and ultimately a denial of any other requests.

- [https://github.com/Live-Hack-CVE/CVE-2022-37034](https://github.com/Live-Hack-CVE/CVE-2022-37034) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37034.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37034.svg)


## CVE-2022-37033
 In dotCMS 5.x-22.06, TempFileAPI allows a user to create a temporary file based on a passed in URL, while attempting to block any SSRF access to local IP addresses or private subnets. In resolving this URL, the TempFileAPI follows any 302 redirects that the remote URL returns. Because there is no re-validation of the redirect URL, the TempFileAPI can be used to return data from those local/private hosts that should not be accessible remotely.

- [https://github.com/Live-Hack-CVE/CVE-2022-37033](https://github.com/Live-Hack-CVE/CVE-2022-37033) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37033.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37033.svg)


## CVE-2022-36804
 Multiple API endpoints in Atlassian Bitbucket Server and Data Center 7.0.0 before version 7.6.17, from version 7.7.0 before version 7.17.10, from version 7.18.0 before version 7.21.4, from version 8.0.0 before version 8.0.3, from version 8.1.0 before version 8.1.3, and from version 8.2.0 before version 8.2.2, and from version 8.3.0 before 8.3.1 allows remote attackers with read permissions to a public or private Bitbucket repository to execute arbitrary code by sending a malicious HTTP request. This vulnerability was reported via our Bug Bounty Program by TheGrandPew.

- [https://github.com/imbas007/Atlassian-Bitbucket-CVE-2022-36804](https://github.com/imbas007/Atlassian-Bitbucket-CVE-2022-36804) :  ![starts](https://img.shields.io/github/stars/imbas007/Atlassian-Bitbucket-CVE-2022-36804.svg) ![forks](https://img.shields.io/github/forks/imbas007/Atlassian-Bitbucket-CVE-2022-36804.svg)


## CVE-2022-34459
 Dell Command | Update, Dell Update, and Alienware Update versions prior to 4.7 contain a improper verification of cryptographic signature in get applicable driver component. A local malicious user could potentially exploit this vulnerability leading to malicious payload execution.

- [https://github.com/Live-Hack-CVE/CVE-2022-34459](https://github.com/Live-Hack-CVE/CVE-2022-34459) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34459.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34459.svg)


## CVE-2022-34458
 Dell Command | Update, Dell Update, and Alienware Update versions prior to 4.7 contain a Exposure of Sensitive System Information to an Unauthorized Control Sphere vulnerability in download operation component. A local malicious user could potentially exploit this vulnerability leading to the disclosure of confidential data.

- [https://github.com/Live-Hack-CVE/CVE-2022-34458](https://github.com/Live-Hack-CVE/CVE-2022-34458) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34458.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34458.svg)


## CVE-2022-34443
 Dell Rugged Control Center, versions prior to 4.5, contain an Improper Input Validation in the Service EndPoint. A Local Low Privilege attacker could potentially exploit this vulnerability, leading to an Escalation of privileges.

- [https://github.com/Live-Hack-CVE/CVE-2022-34443](https://github.com/Live-Hack-CVE/CVE-2022-34443) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34443.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34443.svg)


## CVE-2022-34403
 Dell BIOS contains a Stack based buffer overflow vulnerability. A local authenticated attacker could potentially exploit this vulnerability by using an SMI to send larger than expected input to a parameter to gain arbitrary code execution in SMRAM.

- [https://github.com/Live-Hack-CVE/CVE-2022-34403](https://github.com/Live-Hack-CVE/CVE-2022-34403) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34403.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34403.svg)


## CVE-2022-34400
 Dell BIOS contains a heap buffer overflow vulnerability. A local attacker with admin privileges could potentially exploit this vulnerability to perform an arbitrary write to SMRAM during SMM.

- [https://github.com/Live-Hack-CVE/CVE-2022-34400](https://github.com/Live-Hack-CVE/CVE-2022-34400) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34400.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34400.svg)


## CVE-2022-34398
 Dell BIOS contains a Time-of-check Time-of-use vulnerability. A local authenticated malicious user could\u00a0potentially exploit this vulnerability by using a specifically timed DMA transaction during an SMI to gain arbitrary code execution on the system.

- [https://github.com/Live-Hack-CVE/CVE-2022-34398](https://github.com/Live-Hack-CVE/CVE-2022-34398) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34398.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34398.svg)


## CVE-2022-34396
 Dell OpenManage Server Administrator (OMSA) version 10.3.0.0 and earlier contains a DLL Injection Vulnerability. A local low privileged authenticated attacker could potentially exploit this vulnerability, leading to the execution of arbitrary executable on the operating system with elevated privileges. Exploitation may lead to a complete system compromise.

- [https://github.com/Live-Hack-CVE/CVE-2022-34396](https://github.com/Live-Hack-CVE/CVE-2022-34396) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34396.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34396.svg)


## CVE-2022-32482
 Dell BIOS contains an improper input validation vulnerability. A local authenticated malicious user with admin privileges may potentially exploit this vulnerability in order to modify a UEFI variable.

- [https://github.com/Live-Hack-CVE/CVE-2022-32482](https://github.com/Live-Hack-CVE/CVE-2022-32482) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32482.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32482.svg)


## CVE-2022-31710
 vRealize Log Insight contains a deserialization vulnerability. An unauthenticated malicious actor can remotely trigger the deserialization of untrusted data which could result in a denial of service.

- [https://github.com/Live-Hack-CVE/CVE-2022-31710](https://github.com/Live-Hack-CVE/CVE-2022-31710) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-31710.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-31710.svg)


## CVE-2022-31706
 The vRealize Log Insight contains a Directory Traversal Vulnerability. An unauthenticated, malicious actor can inject files into the operating system of an impacted appliance which can result in remote code execution.

- [https://github.com/Live-Hack-CVE/CVE-2022-31706](https://github.com/Live-Hack-CVE/CVE-2022-31706) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-31706.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-31706.svg)


## CVE-2022-31704
 The vRealize Log Insight contains a broken access control vulnerability. An unauthenticated malicious actor can remotely inject code into sensitive files of an impacted appliance which can result in remote code execution.

- [https://github.com/Live-Hack-CVE/CVE-2022-31704](https://github.com/Live-Hack-CVE/CVE-2022-31704) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-31704.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-31704.svg)


## CVE-2022-31364
 Cypress : https://www.infineon.com/ Cypress Bluetooth Mesh SDK BSA0107_05.01.00-BX8-AMESH-08 is affected by: Buffer Overflow. The impact is: execute arbitrary code (remote). The component is: affected function is lower_transport_layer_on_seg.  In Cypress Bluetooth Mesh SDK, there is an out-of-bound write vulnerability that can be triggered by sending a series of segmented packets with inconsistent SegN.

- [https://github.com/Live-Hack-CVE/CVE-2022-31364](https://github.com/Live-Hack-CVE/CVE-2022-31364) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-31364.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-31364.svg)


## CVE-2022-31363
 Cypress : https://www.infineon.com/ Cypress Bluetooth Mesh SDK BSA0107_05.01.00-BX8-AMESH-08 is affected by: Buffer Overflow. The impact is: execute arbitrary code (remote). The component is: affected function is pb_transport_handle_frag_.  In Cypress Bluetooth Mesh SDK, there is an out-of-bound write vulnerability that can be triggered during mesh provisioning. Because there is no check for mismatched SegN and TotalLength in Transaction Start PDU.

- [https://github.com/Live-Hack-CVE/CVE-2022-31363](https://github.com/Live-Hack-CVE/CVE-2022-31363) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-31363.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-31363.svg)


## CVE-2022-30904
 In Bestechnic Bluetooth Mesh SDK (BES2300) V1.0, a buffer overflow vulnerability can be triggered during provisioning, because there is no check for the SegN field of the Transaction Start PDU.

- [https://github.com/Live-Hack-CVE/CVE-2022-30904](https://github.com/Live-Hack-CVE/CVE-2022-30904) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-30904.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-30904.svg)


## CVE-2022-29844
 A vulnerability in the FTP service of Western Digital My Cloud OS 5 devices running firmware versions prior to 5.26.119 allows an attacker to read and write arbitrary files. This could lead to a full NAS compromise and would give remote execution capabilities to the attacker.

- [https://github.com/Live-Hack-CVE/CVE-2022-29844](https://github.com/Live-Hack-CVE/CVE-2022-29844) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-29844.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-29844.svg)


## CVE-2022-29843
 A command injection vulnerability in the DDNS service configuration of Western Digital My Cloud OS 5 devices running firmware versions prior to 5.26.119 allows an attacker to execute code in the context of the root user.

- [https://github.com/Live-Hack-CVE/CVE-2022-29843](https://github.com/Live-Hack-CVE/CVE-2022-29843) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-29843.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-29843.svg)


## CVE-2022-27538
 A potential Time-of-Check to Time-of-Use (TOCTOU) vulnerability has been identified in the BIOS for certain HP PC products which may allow arbitrary code execution, denial of service, and information disclosure. HP is releasing BIOS updates to mitigate the potential vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-27538](https://github.com/Live-Hack-CVE/CVE-2022-27538) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-27538.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-27538.svg)


## CVE-2022-27537
 Potential vulnerabilities have been identified in the system BIOS of certain HP PC products, which might allow arbitrary code execution, escalation of privilege, denial of service, and information disclosure. HP is releasing BIOS updates to mitigate these potential vulnerabilities.

- [https://github.com/Live-Hack-CVE/CVE-2022-27537](https://github.com/Live-Hack-CVE/CVE-2022-27537) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-27537.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-27537.svg)


## CVE-2022-27508
 Unauthenticated denial of service

- [https://github.com/Live-Hack-CVE/CVE-2022-27508](https://github.com/Live-Hack-CVE/CVE-2022-27508) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-27508.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-27508.svg)


## CVE-2022-27507
 Authenticated denial of service

- [https://github.com/Live-Hack-CVE/CVE-2022-27507](https://github.com/Live-Hack-CVE/CVE-2022-27507) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-27507.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-27507.svg)


## CVE-2022-25916
 Versions of the package mt7688-wiscan before 0.8.3 are vulnerable to Command Injection due to improper input sanitization in the 'wiscan.scan' function.

- [https://github.com/Live-Hack-CVE/CVE-2022-25916](https://github.com/Live-Hack-CVE/CVE-2022-25916) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-25916.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-25916.svg)


## CVE-2022-25906
 All versions of the package is-http2 are vulnerable to Command Injection due to missing input sanitization or other checks, and sandboxes being employed to the isH2 function.

- [https://github.com/Live-Hack-CVE/CVE-2022-25906](https://github.com/Live-Hack-CVE/CVE-2022-25906) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-25906.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-25906.svg)


## CVE-2022-25350
 All versions of the package puppet-facter are vulnerable to Command Injection via the getFact function due to improper input sanitization.

- [https://github.com/Live-Hack-CVE/CVE-2022-25350](https://github.com/Live-Hack-CVE/CVE-2022-25350) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-25350.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-25350.svg)


## CVE-2022-24324
 A CWE-120: Buffer Copy without Checking Size of Input vulnerability exists that could cause a stack-based buffer overflow potentially leading to remote code execution when an attacker sends a specially crafted message. Affected Products: IGSS Data Server - IGSSdataServer.exe (Versions prior to V15.0.0.22073)

- [https://github.com/Live-Hack-CVE/CVE-2022-24324](https://github.com/Live-Hack-CVE/CVE-2022-24324) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-24324.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-24324.svg)


## CVE-2022-23455
 Potential security vulnerabilities have been identified in HP Support Assistant. These vulnerabilities include privilege escalation, compromise of integrity, allowed communication with untrusted clients, and unauthorized modification of files.

- [https://github.com/Live-Hack-CVE/CVE-2022-23455](https://github.com/Live-Hack-CVE/CVE-2022-23455) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-23455.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-23455.svg)


## CVE-2022-23454
 Potential security vulnerabilities have been identified in HP Support Assistant. These vulnerabilities include privilege escalation, compromise of integrity, allowed communication with untrusted clients, and unauthorized modification of files.

- [https://github.com/Live-Hack-CVE/CVE-2022-23454](https://github.com/Live-Hack-CVE/CVE-2022-23454) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-23454.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-23454.svg)


## CVE-2022-23453
 Potential security vulnerabilities have been identified in HP Support Assistant. These vulnerabilities include privilege escalation, compromise of integrity, allowed communication with untrusted clients, and unauthorized modification of files.

- [https://github.com/Live-Hack-CVE/CVE-2022-23453](https://github.com/Live-Hack-CVE/CVE-2022-23453) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-23453.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-23453.svg)


## CVE-2022-21810
 All versions of the package smartctl are vulnerable to Command Injection via the info method due to improper input sanitization.

- [https://github.com/Live-Hack-CVE/CVE-2022-21810](https://github.com/Live-Hack-CVE/CVE-2022-21810) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-21810.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-21810.svg)


## CVE-2022-21192
 All versions of the package serve-lite are vulnerable to Directory Traversal due to missing input sanitization or other checks and protections employed to the req.url passed as-is to path.join().

- [https://github.com/Live-Hack-CVE/CVE-2022-21192](https://github.com/Live-Hack-CVE/CVE-2022-21192) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-21192.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-21192.svg)


## CVE-2022-4022
 The SVG Support plugin for WordPress defaults to insecure settings in version 2.5 and 2.5.1. SVG files containing malicious javascript are not sanitized. While version 2.5 adds the ability to sanitize image as they are uploaded, the plugin defaults to disable sanitization and does not restrict SVG upload to only administrators. This allows authenticated attackers, with author-level privileges and higher, to upload malicious SVG files that can be embedded in posts and pages by higher privileged users. Additionally, the embedded JavaScript is also triggered on visiting the image URL, which allows an attacker to execute malicious code in browsers visiting that URL.

- [https://github.com/Live-Hack-CVE/CVE-2022-4022](https://github.com/Live-Hack-CVE/CVE-2022-4022) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4022.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4022.svg)


## CVE-2022-4016
 The Booster for WooCommerce WordPress plugin before 5.6.7, Booster Plus for WooCommerce WordPress plugin before 5.6.6, Booster Elite for WooCommerce WordPress plugin before 1.1.8 does not properly check for CSRF when creating and deleting Customer roles, allowing attackers to make logged admins create and delete arbitrary custom roles via CSRF attacks

- [https://github.com/Live-Hack-CVE/CVE-2022-4016](https://github.com/Live-Hack-CVE/CVE-2022-4016) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4016.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4016.svg)


## CVE-2022-3990
 HPSFViewer might allow Escalation of Privilege. This potential vulnerability was remediated on July 29th, 2022. Customers who opted for automatic updates should have already received the remediation.

- [https://github.com/Live-Hack-CVE/CVE-2022-3990](https://github.com/Live-Hack-CVE/CVE-2022-3990) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3990.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3990.svg)


## CVE-2022-3913
 Rapid7 Nexpose and InsightVM versions 6.6.82 through 6.6.177 fail to validate the certificate of the update server when downloading updates. This failure could allow an attacker in a privileged position on the network to provide their own HTTPS endpoint, or intercept communications to the legitimate endpoint. The attacker would need some pre-existing access to at least one node on the network path between the Rapid7-controlled update server and the Nexpose/InsightVM application, and the ability to either spoof the update server's FQDN or redirect legitimate traffic to the attacker's server in order to exploit this vulnerability. Note that even in this scenario, an attacker could not normally replace an update package with a malicious package, since the update process validates a separate, code-signing certificate, distinct from the HTTPS certificate used for communication. This issue was resolved on February 1, 2023 in update 6.6.178 of Nexpose and InsightVM.

- [https://github.com/Live-Hack-CVE/CVE-2022-3913](https://github.com/Live-Hack-CVE/CVE-2022-3913) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3913.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3913.svg)


## CVE-2022-3083
 All versions of Landis+Gyr E850 (ZMQ200) are vulnerable to CWE-784: Reliance on Cookies Without Validation and Integrity. The device's web application navigation depends on the value of the session cookie. The web application could become inaccessible for the user if an attacker changes the cookie values.

- [https://github.com/Live-Hack-CVE/CVE-2022-3083](https://github.com/Live-Hack-CVE/CVE-2022-3083) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3083.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3083.svg)


## CVE-2022-2329
 A CWE-190: Integer Overflow or Wraparound vulnerability exists that could cause heap-based buffer overflow, leading to denial of service and potentially remote code execution when an attacker sends multiple specially crafted messages. Affected Products: IGSS Data Server - IGSSdataServer.exe (Versions prior to V15.0.0.22073)

- [https://github.com/Live-Hack-CVE/CVE-2022-2329](https://github.com/Live-Hack-CVE/CVE-2022-2329) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2329.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2329.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/shiomiyan/CVE-2021-41773](https://github.com/shiomiyan/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/shiomiyan/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/shiomiyan/CVE-2021-41773.svg)
- [https://github.com/puckiestyle/CVE-2021-41773](https://github.com/puckiestyle/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-41773.svg)
- [https://github.com/Plunder283/CVE-2021-41773](https://github.com/Plunder283/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Plunder283/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Plunder283/CVE-2021-41773.svg)


## CVE-2021-3809
 Potential security vulnerabilities have been identified in the BIOS (UEFI Firmware) for certain HP PC products, which might allow arbitrary code execution. HP is releasing firmware updates to mitigate these potential vulnerabilities.

- [https://github.com/Live-Hack-CVE/CVE-2021-3809](https://github.com/Live-Hack-CVE/CVE-2021-3809) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-3809.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-3809.svg)


## CVE-2021-3808
 Potential security vulnerabilities have been identified in the BIOS (UEFI Firmware) for certain HP PC products, which might allow arbitrary code execution. HP is releasing firmware updates to mitigate these potential vulnerabilities.

- [https://github.com/Live-Hack-CVE/CVE-2021-3808](https://github.com/Live-Hack-CVE/CVE-2021-3808) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-3808.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-3808.svg)


## CVE-2021-3701
 A flaw was found in ansible-runner where the default temporary files configuration in ansible-2.0.0 are written to world R/W locations. This flaw allows an attacker to pre-create the directory, resulting in reading private information or forcing ansible-runner to write files as the legitimate user in a place they did not expect. The highest threat from this vulnerability is to confidentiality and integrity.

- [https://github.com/Live-Hack-CVE/CVE-2021-3701](https://github.com/Live-Hack-CVE/CVE-2021-3701) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-3701.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-3701.svg)


## CVE-2021-3478
 There's a flaw in OpenEXR's scanline input file functionality in versions before 3.0.0-beta. An attacker able to submit a crafted file to be processed by OpenEXR could consume excessive system memory. The greatest impact of this flaw is to system availability.

- [https://github.com/Live-Hack-CVE/CVE-2021-3478](https://github.com/Live-Hack-CVE/CVE-2021-3478) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-3478.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-3478.svg)


## CVE-2021-3439
 HP has identified a potential vulnerability in BIOS firmware of some Workstation products. Firmware updates are being released to mitigate these potential vulnerabilities.

- [https://github.com/Live-Hack-CVE/CVE-2021-3439](https://github.com/Live-Hack-CVE/CVE-2021-3439) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-3439.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-3439.svg)


## CVE-2021-2409
 Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The supported version that is affected is Prior to 6.1.24. Easily exploitable vulnerability allows high privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in takeover of Oracle VM VirtualBox. CVSS 3.1 Base Score 8.2 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H).

- [https://github.com/Live-Hack-CVE/CVE-2021-2409](https://github.com/Live-Hack-CVE/CVE-2021-2409) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-2409.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-2409.svg)


## CVE-2021-1732
 Windows Win32k Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-1698.

- [https://github.com/fenalik/CVE-2021-1732](https://github.com/fenalik/CVE-2021-1732) :  ![starts](https://img.shields.io/github/stars/fenalik/CVE-2021-1732.svg) ![forks](https://img.shields.io/github/forks/fenalik/CVE-2021-1732.svg)


## CVE-2020-27955
 Git LFS 2.12.0 allows Remote Code Execution.

- [https://github.com/Kimorea/CVE-2020-27955-LFS](https://github.com/Kimorea/CVE-2020-27955-LFS) :  ![starts](https://img.shields.io/github/stars/Kimorea/CVE-2020-27955-LFS.svg) ![forks](https://img.shields.io/github/forks/Kimorea/CVE-2020-27955-LFS.svg)


## CVE-2020-22662
 In Ruckus R310 10.5.1.0.199, Ruckus R500 10.5.1.0.199, Ruckus R600 10.5.1.0.199, Ruckus T300 10.5.1.0.199, Ruckus T301n 10.5.1.0.199, Ruckus T301s 10.5.1.0.199, SmartCell Gateway 200 (SCG200) before 3.6.2.0.795, SmartZone 100 (SZ-100) before 3.6.2.0.795, SmartZone 300 (SZ300) before 3.6.2.0.795, Virtual SmartZone (vSZ) before 3.6.2.0.795, ZoneDirector 1100 9.10.2.0.130, ZoneDirector 1200 10.2.1.0.218, ZoneDirector 3000 10.2.1.0.218, ZoneDirector 5000 10.0.1.0.151, a vulnerability allows attackers to change and set unauthorized &quot;illegal region code&quot; by remote code Execution command injection which leads to run illegal frequency with maxi output power. Vulnerability allows attacker to create an arbitrary amount of ssid wlans interface per radio which creates overhead over noise (the default max limit is 8 ssid only per radio in solo AP). Vulnerability allows attacker to unlock hidden regions by privilege command injection in WEB GUI.

- [https://github.com/Live-Hack-CVE/CVE-2020-22662](https://github.com/Live-Hack-CVE/CVE-2020-22662) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-22662.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-22662.svg)


## CVE-2020-22661
 In Ruckus R310 10.5.1.0.199, Ruckus R500 10.5.1.0.199, Ruckus R600 10.5.1.0.199, Ruckus T300 10.5.1.0.199, Ruckus T301n 10.5.1.0.199, Ruckus T301s 10.5.1.0.199, SmartCell Gateway 200 (SCG200) before 3.6.2.0.795, SmartZone 100 (SZ-100) before 3.6.2.0.795, SmartZone 300 (SZ300) before 3.6.2.0.795, Virtual SmartZone (vSZ) before 3.6.2.0.795, ZoneDirector 1100 9.10.2.0.130, ZoneDirector 1200 10.2.1.0.218, ZoneDirector 3000 10.2.1.0.218, ZoneDirector 5000 10.0.1.0.151, a vulnerability allows attackers to erase the backup secondary official image and write secondary backup unauthorized image.

- [https://github.com/Live-Hack-CVE/CVE-2020-22661](https://github.com/Live-Hack-CVE/CVE-2020-22661) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-22661.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-22661.svg)


## CVE-2020-22660
 In Ruckus R310 10.5.1.0.199, Ruckus R500 10.5.1.0.199, Ruckus R600 10.5.1.0.199, Ruckus T300 10.5.1.0.199, Ruckus T301n 10.5.1.0.199, Ruckus T301s 10.5.1.0.199, SmartCell Gateway 200 (SCG200) before 3.6.2.0.795, SmartZone 100 (SZ-100) before 3.6.2.0.795, SmartZone 300 (SZ300) before 3.6.2.0.795, Virtual SmartZone (vSZ) before 3.6.2.0.795, ZoneDirector 1100 9.10.2.0.130, ZoneDirector 1200 10.2.1.0.218, ZoneDirector 3000 10.2.1.0.218, ZoneDirector 5000 10.0.1.0.151, a vulnerability allows attackers to force bypass Secure Boot failed attempts and run temporarily the previous Backup image.

- [https://github.com/Live-Hack-CVE/CVE-2020-22660](https://github.com/Live-Hack-CVE/CVE-2020-22660) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-22660.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-22660.svg)


## CVE-2020-22452
 SQL Injection vulnerability in function getTableCreationQuery in CreateAddField.php in phpMyAdmin 5.x before 5.2.0 via the tbl_storage_engine or tbl_collation parameters to tbl_create.php.

- [https://github.com/Live-Hack-CVE/CVE-2020-22452](https://github.com/Live-Hack-CVE/CVE-2020-22452) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-22452.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-22452.svg)


## CVE-2020-22327
 An issue was discovered in HFish 0.5.1. When a payload is inserted where the name is entered, XSS code is triggered when the administrator views the information.

- [https://github.com/Live-Hack-CVE/CVE-2020-22327](https://github.com/Live-Hack-CVE/CVE-2020-22327) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-22327.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-22327.svg)


## CVE-2020-1350
 A remote code execution vulnerability exists in Windows Domain Name System servers when they fail to properly handle requests, aka 'Windows DNS Server Remote Code Execution Vulnerability'.

- [https://github.com/corelight/SIGRed](https://github.com/corelight/SIGRed) :  ![starts](https://img.shields.io/github/stars/corelight/SIGRed.svg) ![forks](https://img.shields.io/github/forks/corelight/SIGRed.svg)


## CVE-2019-19746
 make_arrow in arrow.c in Xfig fig2dev 3.2.7b allows a segmentation fault and out-of-bounds write because of an integer overflow via a large arrow type.

- [https://github.com/Live-Hack-CVE/CVE-2019-19746](https://github.com/Live-Hack-CVE/CVE-2019-19746) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-19746.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-19746.svg)


## CVE-2019-19722
 In Dovecot before 2.3.9.2, an attacker can crash a push-notification driver with a crafted email when push notifications are used, because of a NULL Pointer Dereference. The email must use a group address as either the sender or the recipient.

- [https://github.com/Live-Hack-CVE/CVE-2019-19722](https://github.com/Live-Hack-CVE/CVE-2019-19722) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-19722.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-19722.svg)


## CVE-2019-19649
 Zoho ManageEngine Applications Manager before 13620 allows a remote unauthenticated SQL injection via the SyncEventServlet eventid parameter to the SyncEventServlet.java doGet function.

- [https://github.com/Live-Hack-CVE/CVE-2019-19649](https://github.com/Live-Hack-CVE/CVE-2019-19649) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-19649.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-19649.svg)


## CVE-2019-19648
 In the macho_parse_file functionality in macho/macho.c of YARA 3.11.0, command_size may be inconsistent with the real size. A specially crafted MachO file can cause an out-of-bounds memory access, resulting in Denial of Service (application crash) or potential code execution.

- [https://github.com/Live-Hack-CVE/CVE-2019-19648](https://github.com/Live-Hack-CVE/CVE-2019-19648) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-19648.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-19648.svg)


## CVE-2019-14465
 fmt_mtm_load_song in fmt/mtm.c in Schism Tracker 20190722 has a heap-based buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2019-14465](https://github.com/Live-Hack-CVE/CVE-2019-14465) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-14465.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-14465.svg)


## CVE-2019-14302
 On Ricoh SP C250DN 1.06 devices, a debug port can be used.

- [https://github.com/Live-Hack-CVE/CVE-2019-14302](https://github.com/Live-Hack-CVE/CVE-2019-14302) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-14302.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-14302.svg)


## CVE-2019-14301
 Ricoh SP C250DN 1.06 devices have Incorrect Access Control (issue 1 of 2).

- [https://github.com/Live-Hack-CVE/CVE-2019-14301](https://github.com/Live-Hack-CVE/CVE-2019-14301) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-14301.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-14301.svg)


## CVE-2019-13767
 Use after free in media picker in Google Chrome prior to 79.0.3945.88 allowed a remote attacker who had compromised the renderer process to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2019-13767](https://github.com/Live-Hack-CVE/CVE-2019-13767) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-13767.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-13767.svg)


## CVE-2019-10957
 Geutebruck IP Cameras G-Code(EEC-2xxx), G-Cam(EBC-21xx/EFD-22xx/ETHC-22xx/EWPC-22xx): All versions 1.12.0.25 and prior may allow a remote authenticated attacker with access to event configuration to store malicious code on the server, which could later be triggered by a legitimate user resulting in code execution within the user&#8217;s browser.

- [https://github.com/Live-Hack-CVE/CVE-2019-10957](https://github.com/Live-Hack-CVE/CVE-2019-10957) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-10957.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-10957.svg)


## CVE-2019-9904
 An issue was discovered in lib\cdt\dttree.c in libcdt.a in graphviz 2.40.1. Stack consumption occurs because of recursive agclose calls in lib\cgraph\graph.c in libcgraph.a, related to agfstsubg in lib\cgraph\subg.c.

- [https://github.com/Live-Hack-CVE/CVE-2019-9904](https://github.com/Live-Hack-CVE/CVE-2019-9904) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-9904.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-9904.svg)


## CVE-2019-9193
 ** DISPUTED ** In PostgreSQL 9.3 through 11.2, the &quot;COPY TO/FROM PROGRAM&quot; function allows superusers and users in the 'pg_execute_server_program' group to execute arbitrary code in the context of the database's operating system user. This functionality is enabled by default and can be abused to run arbitrary operating system commands on Windows, Linux, and macOS. NOTE: Third parties claim/state this is not an issue because PostgreSQL functionality for &#8216;COPY TO/FROM PROGRAM&#8217; is acting as intended. References state that in PostgreSQL, a superuser can execute commands as the server user without using the &#8216;COPY FROM PROGRAM&#8217;.

- [https://github.com/paulotrindadec/CVE-2019-9193](https://github.com/paulotrindadec/CVE-2019-9193) :  ![starts](https://img.shields.io/github/stars/paulotrindadec/CVE-2019-9193.svg) ![forks](https://img.shields.io/github/forks/paulotrindadec/CVE-2019-9193.svg)


## CVE-2019-7004
 A Cross-Site Scripting (XSS) vulnerability in the WebUI component of IP Office Application Server could allow unauthorized code execution and potentially disclose sensitive information. All product versions 11.x are affected. Product versions prior to 11.0, including unsupported versions, were not evaluated.

- [https://github.com/Live-Hack-CVE/CVE-2019-7004](https://github.com/Live-Hack-CVE/CVE-2019-7004) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-7004.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-7004.svg)


## CVE-2019-4716
 IBM Planning Analytics 2.0.0 through 2.0.8 is vulnerable to a configuration overwrite that allows an unauthenticated user to login as &quot;admin&quot;, and then execute code as root or SYSTEM via TM1 scripting. IBM X-Force ID: 172094.

- [https://github.com/Live-Hack-CVE/CVE-2019-4716](https://github.com/Live-Hack-CVE/CVE-2019-4716) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-4716.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-4716.svg)


## CVE-2019-1652
 A vulnerability in the web-based management interface of Cisco Small Business RV320 and RV325 Dual Gigabit WAN VPN Routers could allow an authenticated, remote attacker with administrative privileges on an affected device to execute arbitrary commands. The vulnerability is due to improper validation of user-supplied input. An attacker could exploit this vulnerability by sending malicious HTTP POST requests to the web-based management interface of an affected device. A successful exploit could allow the attacker to execute arbitrary commands on the underlying Linux shell as root. Cisco has released firmware updates that address this vulnerability.

- [https://github.com/0x27/CiscoRV320Dump](https://github.com/0x27/CiscoRV320Dump) :  ![starts](https://img.shields.io/github/stars/0x27/CiscoRV320Dump.svg) ![forks](https://img.shields.io/github/forks/0x27/CiscoRV320Dump.svg)


## CVE-2018-3981
 An exploitable out-of-bounds write exists in the TIFF-parsing functionality of Canvas Draw version 5.0.0. An attacker can deliver a TIFF image to trigger this vulnerability and gain code execution.

- [https://github.com/Live-Hack-CVE/CVE-2018-3981](https://github.com/Live-Hack-CVE/CVE-2018-3981) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-3981.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-3981.svg)


## CVE-2018-3967
 An exploitable use-after-free vulnerability exists in the JavaScript engine of Foxit Software's Foxit PDF Reader version 9.1.0.5096. A specially crafted PDF document can trigger a previously freed object in memory to be reused, resulting in arbitrary code execution. An attacker needs to trick the user to open the malicious file to trigger this vulnerability. If the browser plugin extension is enabled, visiting a malicious site can also trigger the vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2018-3967](https://github.com/Live-Hack-CVE/CVE-2018-3967) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-3967.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-3967.svg)


## CVE-2018-3966
 An exploitable use-after-free vulnerability exists in the JavaScript engine of Foxit Software's Foxit PDF Reader version 9.1.0.5096. A specially crafted PDF document can trigger a previously freed object in memory to be reused, resulting in arbitrary code execution. An attacker needs to trick the user to open the malicious file to trigger this vulnerability. If the browser plugin extension is enabled, visiting a malicious site can also trigger the vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2018-3966](https://github.com/Live-Hack-CVE/CVE-2018-3966) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-3966.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-3966.svg)


## CVE-2018-3965
 An exploitable use-after-free vulnerability exists in the JavaScript engine of Foxit Software's Foxit PDF Reader version 9.1.0.5096. A specially crafted PDF document can trigger a previously freed object in memory to be reused, resulting in arbitrary code execution. An attacker needs to trick the user to open the malicious file to trigger this vulnerability. If the browser plugin extension is enabled, visiting a malicious site can also trigger the vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2018-3965](https://github.com/Live-Hack-CVE/CVE-2018-3965) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-3965.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-3965.svg)


## CVE-2018-3964
 An exploitable use-after-free vulnerability exists in the JavaScript engine of Foxit Software's Foxit PDF Reader version 9.1.0.5096. A specially crafted PDF document can trigger a previously freed object in memory to be reused, resulting in arbitrary code execution. An attacker needs to trick the user to open the malicious file to trigger this vulnerability. If the browser plugin extension is enabled, visiting a malicious site can also trigger the vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2018-3964](https://github.com/Live-Hack-CVE/CVE-2018-3964) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-3964.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-3964.svg)


## CVE-2018-3962
 A use-after-free vulnerability exists in the JavaScript engine of Foxit Software's Foxit PDF Reader version 9.1.0.5096. A use-after-free condition can occur when accessing the CreationDate property of the this.info object. An attacker needs to trick the user to open the malicious file to trigger this vulnerability. If the browser plugin extension is enabled, visiting a malicious site can also trigger the vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2018-3962](https://github.com/Live-Hack-CVE/CVE-2018-3962) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-3962.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-3962.svg)


## CVE-2018-3935
 An exploitable code execution vulnerability exists in the UDP network functionality of Yi Home Camera 27US 1.8.7.0D. A specially crafted set of UDP packets can allocate unlimited memory, resulting in denial of service. An attacker can send a set of packets to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2018-3935](https://github.com/Live-Hack-CVE/CVE-2018-3935) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-3935.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-3935.svg)


## CVE-2018-3934
 An exploitable code execution vulnerability exists in the firmware update functionality of Yi Home Camera 27US 1.8.7.0D. A specially crafted set of UDP packets can cause a logic flaw, resulting in an authentication bypass. An attacker can sniff network traffic and send a set of packets to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2018-3934](https://github.com/Live-Hack-CVE/CVE-2018-3934) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-3934.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-3934.svg)


## CVE-2018-3928
 An exploitable code execution vulnerability exists in the firmware update functionality of Yi Home Camera 27US 1.8.7.0D. A specially crafted set of UDP packets can cause a settings change, resulting in denial of service. An attacker can send a set of packets to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2018-3928](https://github.com/Live-Hack-CVE/CVE-2018-3928) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-3928.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-3928.svg)


## CVE-2018-3920
 An exploitable code execution vulnerability exists in the firmware update functionality of the Yi Home Camera 27US 1.8.7.0D. A specially crafted 7-Zip file can cause a CRC collision, resulting in a firmware update and code execution. An attacker can insert an SDcard to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2018-3920](https://github.com/Live-Hack-CVE/CVE-2018-3920) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-3920.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-3920.svg)


## CVE-2018-3910
 An exploitable code execution vulnerability exists in the cloud OTA setup functionality of Yi Home Camera 27US 1.8.7.0D. A specially crafted SSID can cause a command injection, resulting in code execution. An attacker can cause a camera to connect to this SSID to trigger this vulnerability. Alternatively, an attacker can convince a user to connect their camera to this SSID.

- [https://github.com/Live-Hack-CVE/CVE-2018-3910](https://github.com/Live-Hack-CVE/CVE-2018-3910) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-3910.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-3910.svg)


## CVE-2018-3900
 An exploitable code execution vulnerability exists in the QR code scanning functionality of Yi Home Camera 27US 1.8.7.0D. A specially crafted QR Code can cause a buffer overflow, resulting in code execution. An attacker can make the camera scan a QR code to trigger this vulnerability. Alternatively, a user could be convinced to display a QR code from the internet to their camera, which could exploit this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2018-3900](https://github.com/Live-Hack-CVE/CVE-2018-3900) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-3900.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-3900.svg)


## CVE-2018-3899
 An exploitable code execution vulnerability exists in the QR code scanning functionality of Yi Home Camera 27US 1.8.7.0D. A specially crafted QR Code can cause a buffer overflow, resulting in code execution. The trans_info call can overwrite a buffer of size 0x104, which is more than enough to overflow the return address from the password_dst field

- [https://github.com/Live-Hack-CVE/CVE-2018-3899](https://github.com/Live-Hack-CVE/CVE-2018-3899) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-3899.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-3899.svg)


## CVE-2018-3898
 An exploitable code execution vulnerability exists in the QR code scanning functionality of Yi Home Camera 27US 1.8.7.0D. A specially crafted QR Code can cause a buffer overflow, resulting in code execution. The trans_info call can overwrite a buffer of size 0x104, which is more than enough to overflow the return address from the ssid_dst field.

- [https://github.com/Live-Hack-CVE/CVE-2018-3898](https://github.com/Live-Hack-CVE/CVE-2018-3898) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-3898.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-3898.svg)


## CVE-2018-3892
 An exploitable firmware downgrade vulnerability exists in the time syncing functionality of Yi Home Camera 27US 1.8.7.0D. A specially crafted packet can cause a buffer overflow, resulting in code execution. An attacker can intercept and alter network traffic to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2018-3892](https://github.com/Live-Hack-CVE/CVE-2018-3892) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-3892.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-3892.svg)


## CVE-2018-3891
 An exploitable firmware downgrade vulnerability exists in the firmware update functionality of Yi Home Camera 27US 1.8.7.0D. A specially crafted file can cause a logic flaw, resulting in a firmware downgrade. An attacker can insert an SD card to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2018-3891](https://github.com/Live-Hack-CVE/CVE-2018-3891) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-3891.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-3891.svg)


## CVE-2018-3890
 An exploitable code execution vulnerability exists in the firmware update functionality of Yi Home Camera 27US 1.8.7.0D. A specially crafted file can cause a logic flaw and command injection, resulting in code execution. An attacker can insert an SD card to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2018-3890](https://github.com/Live-Hack-CVE/CVE-2018-3890) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-3890.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-3890.svg)


## CVE-2018-3888
 A memory corruption vulnerability exists in the PCX-parsing functionality of Computerinsel Photoline 20.53. A specially crafted PCX image processed via the application can lead to an out-of-bounds write, overwriting arbitrary data. An attacker can deliver a PCX image to trigger this vulnerability and gain code execution.

- [https://github.com/Live-Hack-CVE/CVE-2018-3888](https://github.com/Live-Hack-CVE/CVE-2018-3888) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-3888.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-3888.svg)


## CVE-2018-3887
 A memory corruption vulnerability exists in the PCX-parsing functionality of Computerinsel Photoline 20.53. A specially crafted PCX image processed via the application can lead to an out-of-bounds write, overwriting arbitrary data. An attacker can deliver a PCX image to trigger this vulnerability and gain code execution.

- [https://github.com/Live-Hack-CVE/CVE-2018-3887](https://github.com/Live-Hack-CVE/CVE-2018-3887) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-3887.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-3887.svg)


## CVE-2018-1386
 IBM Tivoli Workload Automation for AIX (IBM Workload Scheduler 8.6, 9.1, 9.2, 9.3, and 9.4) contains directories with improper permissions that could allow a local user to with special access to gain root privileges. IBM X-Force ID: 138208.

- [https://github.com/Live-Hack-CVE/CVE-2018-1386](https://github.com/Live-Hack-CVE/CVE-2018-1386) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-1386.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-1386.svg)


## CVE-2018-1270
 Spring Framework, versions 5.0 prior to 5.0.5 and versions 4.3 prior to 4.3.15 and older unsupported versions, allow applications to expose STOMP over WebSocket endpoints with a simple, in-memory STOMP broker through the spring-messaging module. A malicious user (or attacker) can craft a message to the broker that can lead to a remote code execution attack.

- [https://github.com/CaledoniaProject/CVE-2018-1270](https://github.com/CaledoniaProject/CVE-2018-1270) :  ![starts](https://img.shields.io/github/stars/CaledoniaProject/CVE-2018-1270.svg) ![forks](https://img.shields.io/github/forks/CaledoniaProject/CVE-2018-1270.svg)


## CVE-2018-1111
 A command injection flaw was found in the NetworkManager integration script included in the DHCP client packages in Red Hat Enterprise Linux. A malicious DHCP server, or an attacker on the local network able to spoof DHCP responses, could use this flaw to execute arbitrary commands with root privileges on systems using NetworkManager and configured to obtain network configuration using the DHCP protocol.

- [https://github.com/Live-Hack-CVE/CVE-2018-1111](https://github.com/Live-Hack-CVE/CVE-2018-1111) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-1111.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-1111.svg)


## CVE-2017-1000371
 The offset2lib patch as used by the Linux Kernel contains a vulnerability, if RLIMIT_STACK is set to RLIM_INFINITY and 1 Gigabyte of memory is allocated (the maximum under the 1/4 restriction) then the stack will be grown down to 0x80000000, and as the PIE binary is mapped above 0x80000000 the minimum distance between the end of the PIE binary's read-write segment and the start of the stack becomes small enough that the stack guard page can be jumped over by an attacker. This affects Linux Kernel version 4.11.5. This is a different issue than CVE-2017-1000370 and CVE-2017-1000365. This issue appears to be limited to i386 based systems.

- [https://github.com/Trinadh465/linux-4.1.15_CVE-2017-1000371](https://github.com/Trinadh465/linux-4.1.15_CVE-2017-1000371) :  ![starts](https://img.shields.io/github/stars/Trinadh465/linux-4.1.15_CVE-2017-1000371.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/linux-4.1.15_CVE-2017-1000371.svg)


## CVE-2017-15097
 Privilege escalation flaws were found in the Red Hat initialization scripts of PostgreSQL. An attacker with access to the postgres user account could use these flaws to obtain root access on the server machine.

- [https://github.com/Live-Hack-CVE/CVE-2017-15097](https://github.com/Live-Hack-CVE/CVE-2017-15097) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-15097.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-15097.svg)


## CVE-2017-7488
 A flaw was found where authconfig could configure sssd in a way that treats existing and non-existing logins differently, leaking information on existence of a user. An attacker with physical or network access to the machine could enumerate users via a timing attack.

- [https://github.com/Live-Hack-CVE/CVE-2017-7488](https://github.com/Live-Hack-CVE/CVE-2017-7488) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-7488.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-7488.svg)


## CVE-2016-9922
 CVE-2016-9921 CVE-2016-9922 Qemu: display: cirrus_vga: a divide by zero in cirrus_do_copy

- [https://github.com/Live-Hack-CVE/CVE-2016-9922](https://github.com/Live-Hack-CVE/CVE-2016-9922) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-9922.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-9922.svg)


## CVE-2016-9921
 CVE-2016-9921 CVE-2016-9922 Qemu: display: cirrus_vga: a divide by zero in cirrus_do_copy

- [https://github.com/Live-Hack-CVE/CVE-2016-9922](https://github.com/Live-Hack-CVE/CVE-2016-9922) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-9922.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-9922.svg)


## CVE-2016-3693
 A flaw was found in the provisioning template handling in foreman. An attacker, with permissions to create templates, can cause internal Rails information to be displayed when it is processed, resulting in potentially sensitive information being disclosed.

- [https://github.com/Live-Hack-CVE/CVE-2016-3693](https://github.com/Live-Hack-CVE/CVE-2016-3693) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-3693.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-3693.svg)


## CVE-2016-3107
 It was found that the private key for the node certificate was contained in a world-readable file. A local user could possibly use this flaw to gain access to the private key information in the file.

- [https://github.com/Live-Hack-CVE/CVE-2016-3107](https://github.com/Live-Hack-CVE/CVE-2016-3107) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-3107.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-3107.svg)


## CVE-2015-3248
 It was found that the &quot;/var/lib/openhpi&quot; directory provided by OpenHPI used world-writeable and world-readable permissions. A local user could use this flaw to view, modify, and delete OpenHPI-related data, or even fill up the storage device hosting the /var/lib directory.

- [https://github.com/Live-Hack-CVE/CVE-2015-3248](https://github.com/Live-Hack-CVE/CVE-2015-3248) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-3248.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-3248.svg)


## CVE-2015-3247
 A race condition flaw, leading to a heap-based memory corruption, was found in spice's worker_update_monitors_config() function, which runs under the QEMU-KVM context on the host. A user in a guest could leverage this flaw to crash the host QEMU-KVM process or, possibly, execute arbitrary code with the privileges of the host QEMU-KVM process.

- [https://github.com/Live-Hack-CVE/CVE-2015-3247](https://github.com/Live-Hack-CVE/CVE-2015-3247) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-3247.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-3247.svg)


## CVE-2012-3386
 It was found that the distcheck rule in Automake-generated Makefiles made a directory world-writable when preparing source archives. If a malicious, local user could access this directory, they could execute arbitrary code with the privileges of the user running &quot;make distcheck&quot;.

- [https://github.com/Live-Hack-CVE/CVE-2012-3386](https://github.com/Live-Hack-CVE/CVE-2012-3386) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-3386.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-3386.svg)


## CVE-2012-2386
 CVE-2012-2386 php: Integer overflow leading to heap-buffer overflow in the Phar extension

- [https://github.com/Live-Hack-CVE/CVE-2012-2386](https://github.com/Live-Hack-CVE/CVE-2012-2386) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-2386.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-2386.svg)


## CVE-2011-4127
 CVE-2011-4127 kernel: possible privilege escalation via SG_IO ioctl

- [https://github.com/Live-Hack-CVE/CVE-2011-4127](https://github.com/Live-Hack-CVE/CVE-2011-4127) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2011-4127.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2011-4127.svg)


## CVE-2011-3609
 CVE-2011-3609 JBoss AS: CSRF in the administration console &amp; HTTP management API

- [https://github.com/Live-Hack-CVE/CVE-2011-3609](https://github.com/Live-Hack-CVE/CVE-2011-3609) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2011-3609.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2011-3609.svg)


## CVE-2011-3344
 CVE-2011-3344 Satellite/Spacewalk: XSS on the Lost Password page

- [https://github.com/Live-Hack-CVE/CVE-2011-3344](https://github.com/Live-Hack-CVE/CVE-2011-3344) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2011-3344.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2011-3344.svg)


## CVE-2011-2927
 CVE-2011-2927 Satellite/Spacewalk: XSS flaw in channels search

- [https://github.com/Live-Hack-CVE/CVE-2011-2927](https://github.com/Live-Hack-CVE/CVE-2011-2927) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2011-2927.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2011-2927.svg)


## CVE-2011-2920
 CVE-2011-2920 Satellite: XSS flaw(s) in filter handling

- [https://github.com/Live-Hack-CVE/CVE-2011-2920](https://github.com/Live-Hack-CVE/CVE-2011-2920) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2011-2920.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2011-2920.svg)


## CVE-2011-2487
 A flaw was found in JBoss web services where the services used a weak symmetric encryption protocol, PKCS#1 v1.5. An attacker could use this weakness in chosen-ciphertext attacks to recover the symmetric key and conduct further attacks.

- [https://github.com/Live-Hack-CVE/CVE-2011-2487](https://github.com/Live-Hack-CVE/CVE-2011-2487) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2011-2487.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2011-2487.svg)

