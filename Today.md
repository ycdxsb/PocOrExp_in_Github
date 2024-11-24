# Update 2024-11-24
## CVE-2024-37084
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/XiaomingX/cve-2024-37084-Poc](https://github.com/XiaomingX/cve-2024-37084-Poc) :  ![starts](https://img.shields.io/github/stars/XiaomingX/cve-2024-37084-Poc.svg) ![forks](https://img.shields.io/github/forks/XiaomingX/cve-2024-37084-Poc.svg)


## CVE-2024-36401
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/thestar0/CVE-2024-36401-WoodpeckerPlugin](https://github.com/thestar0/CVE-2024-36401-WoodpeckerPlugin) :  ![starts](https://img.shields.io/github/stars/thestar0/CVE-2024-36401-WoodpeckerPlugin.svg) ![forks](https://img.shields.io/github/forks/thestar0/CVE-2024-36401-WoodpeckerPlugin.svg)
- [https://github.com/XiaomingX/cve-2024-36401-poc](https://github.com/XiaomingX/cve-2024-36401-poc) :  ![starts](https://img.shields.io/github/stars/XiaomingX/cve-2024-36401-poc.svg) ![forks](https://img.shields.io/github/forks/XiaomingX/cve-2024-36401-poc.svg)


## CVE-2024-27130
 A buffer copy without checking size of input vulnerability has been reported to affect several QNAP operating system versions. If exploited, the vulnerability could allow users to execute code via a network. We have already fixed the vulnerability in the following version: QTS 5.1.7.2770 build 20240520 and later QuTS hero h5.1.7.2770 build 20240520 and later

- [https://github.com/XiaomingX/cve-2024-27130-poc](https://github.com/XiaomingX/cve-2024-27130-poc) :  ![starts](https://img.shields.io/github/stars/XiaomingX/cve-2024-27130-poc.svg) ![forks](https://img.shields.io/github/forks/XiaomingX/cve-2024-27130-poc.svg)


## CVE-2024-25641
 Cacti provides an operational monitoring and fault management framework. Prior to version 1.2.27, an arbitrary file write vulnerability, exploitable through the &quot;Package Import&quot; feature, allows authenticated users having the &quot;Import Templates&quot; permission to execute arbitrary PHP code on the web server. The vulnerability is located within the `import_package()` function defined into the `/lib/import.php` script. The function blindly trusts the filename and file content provided within the XML data, and writes such files into the Cacti base path (or even outside, since path traversal sequences are not filtered). This can be exploited to write or overwrite arbitrary files on the web server, leading to execution of arbitrary PHP code or other security impacts. Version 1.2.27 contains a patch for this issue.

- [https://github.com/XiaomingX/cve-2024-25641-poc](https://github.com/XiaomingX/cve-2024-25641-poc) :  ![starts](https://img.shields.io/github/stars/XiaomingX/cve-2024-25641-poc.svg) ![forks](https://img.shields.io/github/forks/XiaomingX/cve-2024-25641-poc.svg)


## CVE-2024-23113
 A use of externally-controlled format string in Fortinet FortiOS versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.6, 7.0.0 through 7.0.13, FortiProxy versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.8, 7.0.0 through 7.0.14, FortiPAM versions 1.2.0, 1.1.0 through 1.1.2, 1.0.0 through 1.0.3, FortiSwitchManager versions 7.2.0 through 7.2.3, 7.0.0 through 7.0.3 allows attacker to execute unauthorized code or commands via specially crafted packets.

- [https://github.com/XiaomingX/cve-2024-23113-exp](https://github.com/XiaomingX/cve-2024-23113-exp) :  ![starts](https://img.shields.io/github/stars/XiaomingX/cve-2024-23113-exp.svg) ![forks](https://img.shields.io/github/forks/XiaomingX/cve-2024-23113-exp.svg)


## CVE-2024-21626
 runc is a CLI tool for spawning and running containers on Linux according to the OCI specification. In runc 1.1.11 and earlier, due to an internal file descriptor leak, an attacker could cause a newly-spawned container process (from runc exec) to have a working directory in the host filesystem namespace, allowing for a container escape by giving access to the host filesystem (&quot;attack 2&quot;). The same attack could be used by a malicious image to allow a container process to gain access to the host filesystem through runc run (&quot;attack 1&quot;). Variants of attacks 1 and 2 could be also be used to overwrite semi-arbitrary host binaries, allowing for complete container escapes (&quot;attack 3a&quot; and &quot;attack 3b&quot;). runc 1.1.12 includes patches for this issue.

- [https://github.com/adaammmeeee/little-joke](https://github.com/adaammmeeee/little-joke) :  ![starts](https://img.shields.io/github/stars/adaammmeeee/little-joke.svg) ![forks](https://img.shields.io/github/forks/adaammmeeee/little-joke.svg)


## CVE-2024-5452
 A remote code execution (RCE) vulnerability exists in the lightning-ai/pytorch-lightning library version 2.2.1 due to improper handling of deserialized user input and mismanagement of dunder attributes by the `deepdiff` library. The library uses `deepdiff.Delta` objects to modify application state based on frontend actions. However, it is possible to bypass the intended restrictions on modifying dunder attributes, allowing an attacker to construct a serialized delta that passes the deserializer whitelist and contains dunder attributes. When processed, this can be exploited to access other modules, classes, and instances, leading to arbitrary attribute write and total RCE on any self-hosted pytorch-lightning application in its default configuration, as the delta endpoint is enabled by default.

- [https://github.com/XiaomingX/cve-2024-5452-poc](https://github.com/XiaomingX/cve-2024-5452-poc) :  ![starts](https://img.shields.io/github/stars/XiaomingX/cve-2024-5452-poc.svg) ![forks](https://img.shields.io/github/forks/XiaomingX/cve-2024-5452-poc.svg)


## CVE-2024-5247
 NETGEAR ProSAFE Network Management System UpLoadServlet Unrestricted File Upload Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of NETGEAR ProSAFE Network Management System. Authentication is required to exploit this vulnerability. The specific flaw exists within the UpLoadServlet class. The issue results from the lack of proper validation of user-supplied data, which can allow the upload of arbitrary files. An attacker can leverage this vulnerability to execute code in the context of SYSTEM. Was ZDI-CAN-22923.

- [https://github.com/ubaii/CVE-2024-52475](https://github.com/ubaii/CVE-2024-52475) :  ![starts](https://img.shields.io/github/stars/ubaii/CVE-2024-52475.svg) ![forks](https://img.shields.io/github/forks/ubaii/CVE-2024-52475.svg)


## CVE-2024-5243
 TP-Link Omada ER605 Buffer Overflow Remote Code Execution Vulnerability. This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of TP-Link Omada ER605 routers. Authentication is not required to exploit this vulnerability. However, devices are vulnerable only if configured to use the Comexe DDNS service. The specific flaw exists within the handling of DNS names. The issue results from the lack of proper validation of the length of user-supplied data prior to copying it to a buffer. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-22523.

- [https://github.com/RandomRobbieBF/CVE-2024-52433](https://github.com/RandomRobbieBF/CVE-2024-52433) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-52433.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-52433.svg)


## CVE-2024-5242
 TP-Link Omada ER605 Stack-based Buffer Overflow Remote Code Execution Vulnerability. This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of TP-Link Omada ER605 routers. Authentication is not required to exploit this vulnerability. However, devices are vulnerable only if configured to use the Comexe DDNS service. The specific flaw exists within the handling of DDNS error codes. The issue results from the lack of proper validation of the length of user-supplied data prior to copying it to a fixed-length stack-based buffer. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-22522.

- [https://github.com/RandomRobbieBF/CVE-2024-52429](https://github.com/RandomRobbieBF/CVE-2024-52429) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-52429.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-52429.svg)


## CVE-2024-4899
 The SEOPress WordPress plugin before 7.8 does not sanitise and escape some of its Post settings, which could allow high privilege users such as contributor to perform Stored Cross-Site Scripting attacks.

- [https://github.com/felmoltor/CVE-2024-48990](https://github.com/felmoltor/CVE-2024-48990) :  ![starts](https://img.shields.io/github/stars/felmoltor/CVE-2024-48990.svg) ![forks](https://img.shields.io/github/forks/felmoltor/CVE-2024-48990.svg)


## CVE-2024-4757
 The Logo Manager For Enamad WordPress plugin through 0.7.0 does not have CSRF check in some places, and is missing sanitisation as well as escaping, which could allow attackers to make logged in admin add Stored XSS payloads via a CSRF attack

- [https://github.com/XiaomingX/cve-2024-47575-exp](https://github.com/XiaomingX/cve-2024-47575-exp) :  ![starts](https://img.shields.io/github/stars/XiaomingX/cve-2024-47575-exp.svg) ![forks](https://img.shields.io/github/forks/XiaomingX/cve-2024-47575-exp.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use &quot;Best-Fit&quot; behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/sug4r-wr41th/CVE-2024-4577](https://github.com/sug4r-wr41th/CVE-2024-4577) :  ![starts](https://img.shields.io/github/stars/sug4r-wr41th/CVE-2024-4577.svg) ![forks](https://img.shields.io/github/forks/sug4r-wr41th/CVE-2024-4577.svg)


## CVE-2024-4551
 The Video Gallery &#8211; YouTube Playlist, Channel Gallery by YotuWP plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 1.3.13 via the display function. This makes it possible for authenticated attackers, with contributor access and higher, to include and execute arbitrary php files on the server, allowing the execution of any PHP code in those files. This can be used to bypass access controls, obtain sensitive data, or achieve code execution in cases where images and other &#8220;safe&#8221; file types can be uploaded and included.

- [https://github.com/XiaomingX/cve-2024-45519-poc](https://github.com/XiaomingX/cve-2024-45519-poc) :  ![starts](https://img.shields.io/github/stars/XiaomingX/cve-2024-45519-poc.svg) ![forks](https://img.shields.io/github/forks/XiaomingX/cve-2024-45519-poc.svg)


## CVE-2024-4543
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/XiaomingX/cve-2024-45436-exp](https://github.com/XiaomingX/cve-2024-45436-exp) :  ![starts](https://img.shields.io/github/stars/XiaomingX/cve-2024-45436-exp.svg) ![forks](https://img.shields.io/github/forks/XiaomingX/cve-2024-45436-exp.svg)


## CVE-2024-4391
 The Happy Addons for Elementor plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the plugin's Event Calendar widget in all versions up to, and including, 3.10.7 due to insufficient input sanitization and output escaping on user supplied attributes. This makes it possible for authenticated attackers, with contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/RandomRobbieBF/CVE-2024-43919](https://github.com/RandomRobbieBF/CVE-2024-43919) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-43919.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-43919.svg)


## CVE-2024-1143
 Central Dogma versions prior to 0.64.1 is vulnerable to Cross-Site Scripting (XSS), which could allow for the leakage of user sessions and subsequent authentication bypass.

- [https://github.com/windz3r0day/CVE-2024-11432](https://github.com/windz3r0day/CVE-2024-11432) :  ![starts](https://img.shields.io/github/stars/windz3r0day/CVE-2024-11432.svg) ![forks](https://img.shields.io/github/forks/windz3r0day/CVE-2024-11432.svg)


## CVE-2024-1142
 Path Traversal in Sonatype IQ Server from version 143 allows remote authenticated attackers to overwrite or delete files via a specially crafted request. Version 171 fixes this issue.

- [https://github.com/windz3r0day/CVE-2024-11428](https://github.com/windz3r0day/CVE-2024-11428) :  ![starts](https://img.shields.io/github/stars/windz3r0day/CVE-2024-11428.svg) ![forks](https://img.shields.io/github/forks/windz3r0day/CVE-2024-11428.svg)


## CVE-2024-1141
 A vulnerability was found in python-glance-store. The issue occurs when the package logs the access_key for the glance-store when the DEBUG log level is enabled.

- [https://github.com/windz3r0day/CVE-2024-11412](https://github.com/windz3r0day/CVE-2024-11412) :  ![starts](https://img.shields.io/github/stars/windz3r0day/CVE-2024-11412.svg) ![forks](https://img.shields.io/github/forks/windz3r0day/CVE-2024-11412.svg)


## CVE-2024-1138
 The FTL Server component of TIBCO Software Inc.'s TIBCO FTL - Enterprise Edition contains a vulnerability that allows a low privileged attacker with network access to execute a privilege escalation on the affected ftlserver. Affected releases are TIBCO Software Inc.'s TIBCO FTL - Enterprise Edition: versions 6.10.1 and below.

- [https://github.com/windz3r0day/CVE-2024-11381](https://github.com/windz3r0day/CVE-2024-11381) :  ![starts](https://img.shields.io/github/stars/windz3r0day/CVE-2024-11381.svg) ![forks](https://img.shields.io/github/forks/windz3r0day/CVE-2024-11381.svg)
- [https://github.com/windz3r0day/CVE-2024-11388](https://github.com/windz3r0day/CVE-2024-11388) :  ![starts](https://img.shields.io/github/stars/windz3r0day/CVE-2024-11388.svg) ![forks](https://img.shields.io/github/forks/windz3r0day/CVE-2024-11388.svg)


## CVE-2024-0012
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/iSee857/CVE-2024-0012-poc](https://github.com/iSee857/CVE-2024-0012-poc) :  ![starts](https://img.shields.io/github/stars/iSee857/CVE-2024-0012-poc.svg) ![forks](https://img.shields.io/github/forks/iSee857/CVE-2024-0012-poc.svg)
- [https://github.com/XiaomingX/cve-2024-0012-poc](https://github.com/XiaomingX/cve-2024-0012-poc) :  ![starts](https://img.shields.io/github/stars/XiaomingX/cve-2024-0012-poc.svg) ![forks](https://img.shields.io/github/forks/XiaomingX/cve-2024-0012-poc.svg)
- [https://github.com/PunitTailor55/Paloalto-CVE-2024-0012](https://github.com/PunitTailor55/Paloalto-CVE-2024-0012) :  ![starts](https://img.shields.io/github/stars/PunitTailor55/Paloalto-CVE-2024-0012.svg) ![forks](https://img.shields.io/github/forks/PunitTailor55/Paloalto-CVE-2024-0012.svg)


## CVE-2023-50685
 An issue in Hipcam Cameras RealServer v.1.0 allows a remote attacker to cause a denial of service via a crafted script to the client_port parameter.

- [https://github.com/MaximilianJungblut/Hipcam-RTSP-Format-Validation-Vulnerability](https://github.com/MaximilianJungblut/Hipcam-RTSP-Format-Validation-Vulnerability) :  ![starts](https://img.shields.io/github/stars/MaximilianJungblut/Hipcam-RTSP-Format-Validation-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/MaximilianJungblut/Hipcam-RTSP-Format-Validation-Vulnerability.svg)


## CVE-2023-42914
 The issue was addressed with improved memory handling. This issue is fixed in macOS Sonoma 14.2, iOS 17.2 and iPadOS 17.2, watchOS 10.2, macOS Ventura 13.6.3, tvOS 17.2, iOS 16.7.3 and iPadOS 16.7.3, macOS Monterey 12.7.2. An app may be able to break out of its sandbox.

- [https://github.com/synacktiv/CVE-2023-32413](https://github.com/synacktiv/CVE-2023-32413) :  ![starts](https://img.shields.io/github/stars/synacktiv/CVE-2023-32413.svg) ![forks](https://img.shields.io/github/forks/synacktiv/CVE-2023-32413.svg)


## CVE-2023-38646
 Metabase open source before 0.46.6.1 and Metabase Enterprise before 1.46.6.1 allow attackers to execute arbitrary commands on the server, at the server's privilege level. Authentication is not required for exploitation. The other fixed versions are 0.45.4.1, 1.45.4.1, 0.44.7.1, 1.44.7.1, 0.43.7.2, and 1.43.7.2.

- [https://github.com/XiaomingX/cve-2023-38646-poc](https://github.com/XiaomingX/cve-2023-38646-poc) :  ![starts](https://img.shields.io/github/stars/XiaomingX/cve-2023-38646-poc.svg) ![forks](https://img.shields.io/github/forks/XiaomingX/cve-2023-38646-poc.svg)


## CVE-2023-32413
 A race condition was addressed with improved state handling. This issue is fixed in watchOS 9.5, tvOS 16.5, macOS Ventura 13.4, iOS 15.7.6 and iPadOS 15.7.6, macOS Big Sur 11.7.7, macOS Monterey 12.6.6, iOS 16.5 and iPadOS 16.5. An app may be able to gain root privileges.

- [https://github.com/synacktiv/CVE-2023-32413](https://github.com/synacktiv/CVE-2023-32413) :  ![starts](https://img.shields.io/github/stars/synacktiv/CVE-2023-32413.svg) ![forks](https://img.shields.io/github/forks/synacktiv/CVE-2023-32413.svg)


## CVE-2023-20198
 Cisco is providing an update for the ongoing investigation into observed exploitation of the web UI feature in Cisco IOS XE Software. We are updating the list of fixed releases and adding the Software Checker. Our investigation has determined that the actors exploited two previously unknown issues. The attacker first exploited CVE-2023-20198 to gain initial access and issued a privilege 15 command to create a local user and password combination. This allowed the user to log in with normal user access. The attacker then exploited another component of the web UI feature, leveraging the new local user to elevate privilege to root and write the implant to the file system. Cisco has assigned CVE-2023-20273 to this issue. CVE-2023-20198 has been assigned a CVSS Score of 10.0. CVE-2023-20273 has been assigned a CVSS Score of 7.2. Both of these CVEs are being tracked by CSCwh87343.

- [https://github.com/XiaomingX/cve-2023-20198-poc](https://github.com/XiaomingX/cve-2023-20198-poc) :  ![starts](https://img.shields.io/github/stars/XiaomingX/cve-2023-20198-poc.svg) ![forks](https://img.shields.io/github/forks/XiaomingX/cve-2023-20198-poc.svg)


## CVE-2022-26134
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are from 1.3.0 before 7.4.17, from 7.13.0 before 7.13.7, from 7.14.0 before 7.14.3, from 7.15.0 before 7.15.2, from 7.16.0 before 7.16.4, from 7.17.0 before 7.17.4, and from 7.18.0 before 7.18.1.

- [https://github.com/XiaomingX/CVE-2022-26134-poc](https://github.com/XiaomingX/CVE-2022-26134-poc) :  ![starts](https://img.shields.io/github/stars/XiaomingX/CVE-2022-26134-poc.svg) ![forks](https://img.shields.io/github/forks/XiaomingX/CVE-2022-26134-poc.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/wolf1892/CVE-2021-41773](https://github.com/wolf1892/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/wolf1892/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/wolf1892/CVE-2021-41773.svg)


## CVE-2021-29442
 Nacos is a platform designed for dynamic service discovery and configuration and service management. In Nacos before version 1.4.1, the ConfigOpsController lets the user perform management operations like querying the database or even wiping it out. While the /data/remove endpoint is properly protected with the @Secured annotation, the /derby endpoint is not protected and can be openly accessed by unauthenticated users. These endpoints are only valid when using embedded storage (derby DB) so this issue should not affect those installations using external storage (e.g. mysql)

- [https://github.com/XiaomingX/cve-2021-29442-Nacos-Derby-rce-exp](https://github.com/XiaomingX/cve-2021-29442-Nacos-Derby-rce-exp) :  ![starts](https://img.shields.io/github/stars/XiaomingX/cve-2021-29442-Nacos-Derby-rce-exp.svg) ![forks](https://img.shields.io/github/forks/XiaomingX/cve-2021-29442-Nacos-Derby-rce-exp.svg)


## CVE-2020-35489
 The contact-form-7 (aka Contact Form 7) plugin before 5.3.2 for WordPress allows Unrestricted File Upload and remote code execution because a filename may contain special characters.

- [https://github.com/g1thubb002/poc-CVE-2020-35489](https://github.com/g1thubb002/poc-CVE-2020-35489) :  ![starts](https://img.shields.io/github/stars/g1thubb002/poc-CVE-2020-35489.svg) ![forks](https://img.shields.io/github/forks/g1thubb002/poc-CVE-2020-35489.svg)


## CVE-2020-2034
 An OS Command Injection vulnerability in the PAN-OS GlobalProtect portal allows an unauthenticated network based attacker to execute arbitrary OS commands with root privileges. An attacker requires some knowledge of the firewall to exploit this issue. This issue can not be exploited if GlobalProtect portal feature is not enabled. This issue impacts PAN-OS 9.1 versions earlier than PAN-OS 9.1.3; PAN-OS 8.1 versions earlier than PAN-OS 8.1.15; PAN-OS 9.0 versions earlier than PAN-OS 9.0.9; all versions of PAN-OS 8.0 and PAN-OS 7.1. Prisma Access services are not impacted by this vulnerability.

- [https://github.com/blackhatethicalhacking/CVE-2020-2034-POC](https://github.com/blackhatethicalhacking/CVE-2020-2034-POC) :  ![starts](https://img.shields.io/github/stars/blackhatethicalhacking/CVE-2020-2034-POC.svg) ![forks](https://img.shields.io/github/forks/blackhatethicalhacking/CVE-2020-2034-POC.svg)


## CVE-2020-2021
 When Security Assertion Markup Language (SAML) authentication is enabled and the 'Validate Identity Provider Certificate' option is disabled (unchecked), improper verification of signatures in PAN-OS SAML authentication enables an unauthenticated network-based attacker to access protected resources. The attacker must have network access to the vulnerable server to exploit this vulnerability. This issue affects PAN-OS 9.1 versions earlier than PAN-OS 9.1.3; PAN-OS 9.0 versions earlier than PAN-OS 9.0.9; PAN-OS 8.1 versions earlier than PAN-OS 8.1.15, and all versions of PAN-OS 8.0 (EOL). This issue does not affect PAN-OS 7.1. This issue cannot be exploited if SAML is not used for authentication. This issue cannot be exploited if the 'Validate Identity Provider Certificate' option is enabled (checked) in the SAML Identity Provider Server Profile. Resources that can be protected by SAML-based single sign-on (SSO) authentication are: GlobalProtect Gateway, GlobalProtect Portal, GlobalProtect Clientless VPN, Authentication and Captive Portal, PAN-OS next-generation firewalls (PA-Series, VM-Series) and Panorama web interfaces, Prisma Access In the case of GlobalProtect Gateways, GlobalProtect Portal, Clientless VPN, Captive Portal, and Prisma Access, an unauthenticated attacker with network access to the affected servers can gain access to protected resources if allowed by configured authentication and Security policies. There is no impact on the integrity and availability of the gateway, portal or VPN server. An attacker cannot inspect or tamper with sessions of regular users. In the worst case, this is a critical severity vulnerability with a CVSS Base Score of 10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N). In the case of PAN-OS and Panorama web interfaces, this issue allows an unauthenticated attacker with network access to the PAN-OS or Panorama web interfaces to log in as an administrator and perform administrative actions. In the worst-case scenario, this is a critical severity vulnerability with a CVSS Base Score of 10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H). If the web interfaces are only accessible to a restricted management network, then the issue is lowered to a CVSS Base Score of 9.6 (CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H). Palo Alto Networks is not aware of any malicious attempts to exploit this vulnerability.

- [https://github.com/mr-r3b00t/CVE-2020-2021](https://github.com/mr-r3b00t/CVE-2020-2021) :  ![starts](https://img.shields.io/github/stars/mr-r3b00t/CVE-2020-2021.svg) ![forks](https://img.shields.io/github/forks/mr-r3b00t/CVE-2020-2021.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/aib0litt/poc-CVE-2020-1938](https://github.com/aib0litt/poc-CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/aib0litt/poc-CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/aib0litt/poc-CVE-2020-1938.svg)


## CVE-2019-25065
 A vulnerability was found in OpenNetAdmin 18.1.1. It has been rated as critical. Affected by this issue is some unknown functionality. The manipulation leads to privilege escalation. The attack may be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/sagisar1/CVE-2019-25065-exploit](https://github.com/sagisar1/CVE-2019-25065-exploit) :  ![starts](https://img.shields.io/github/stars/sagisar1/CVE-2019-25065-exploit.svg) ![forks](https://img.shields.io/github/forks/sagisar1/CVE-2019-25065-exploit.svg)

