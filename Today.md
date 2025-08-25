# Update 2025-08-25
## CVE-2025-52970
 A improper handling of parameters in Fortinet FortiWeb versions 7.6.3 and below, versions 7.4.7 and below, versions 7.2.10 and below, and 7.0.10 and below may allow an unauthenticated remote attacker with non-public information pertaining to the device and targeted user to gain admin privileges on the device via a specially crafted request.

- [https://github.com/Hex00-0x4/FortiWeb-CVE-2025-52970-Authentication-Bypass](https://github.com/Hex00-0x4/FortiWeb-CVE-2025-52970-Authentication-Bypass) :  ![starts](https://img.shields.io/github/stars/Hex00-0x4/FortiWeb-CVE-2025-52970-Authentication-Bypass.svg) ![forks](https://img.shields.io/github/forks/Hex00-0x4/FortiWeb-CVE-2025-52970-Authentication-Bypass.svg)


## CVE-2025-33053
 External control of file name or path in Internet Shortcut Files allows an unauthorized attacker to execute code over a network.

- [https://github.com/4n4s4zi/CVE-2025-33053_PoC](https://github.com/4n4s4zi/CVE-2025-33053_PoC) :  ![starts](https://img.shields.io/github/stars/4n4s4zi/CVE-2025-33053_PoC.svg) ![forks](https://img.shields.io/github/forks/4n4s4zi/CVE-2025-33053_PoC.svg)


## CVE-2025-30406
 Gladinet CentreStack through 16.1.10296.56315 (fixed in 16.4.10315.56368) has a deserialization vulnerability due to the CentreStack portal's hardcoded machineKey use, as exploited in the wild in March 2025. This enables threat actors (who know the machineKey) to serialize a payload for server-side deserialization to achieve remote code execution. NOTE: a CentreStack admin can manually delete the machineKey defined in portal\web.config.

- [https://github.com/threadpoolx/CVE-2025-30406-CentreStack-Triofox-Deserialization-RCE](https://github.com/threadpoolx/CVE-2025-30406-CentreStack-Triofox-Deserialization-RCE) :  ![starts](https://img.shields.io/github/stars/threadpoolx/CVE-2025-30406-CentreStack-Triofox-Deserialization-RCE.svg) ![forks](https://img.shields.io/github/forks/threadpoolx/CVE-2025-30406-CentreStack-Triofox-Deserialization-RCE.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/threadpoolx/CVE-2025-24813-Remote-Code-Execution-in-Apache-Tomcat](https://github.com/threadpoolx/CVE-2025-24813-Remote-Code-Execution-in-Apache-Tomcat) :  ![starts](https://img.shields.io/github/stars/threadpoolx/CVE-2025-24813-Remote-Code-Execution-in-Apache-Tomcat.svg) ![forks](https://img.shields.io/github/forks/threadpoolx/CVE-2025-24813-Remote-Code-Execution-in-Apache-Tomcat.svg)


## CVE-2025-24201
 An out-of-bounds write issue was addressed with improved checks to prevent unauthorized actions. This issue is fixed in visionOS 2.3.2, iOS 18.3.2 and iPadOS 18.3.2, macOS Sequoia 15.3.2, Safari 18.3.1, watchOS 11.4, iPadOS 17.7.6, iOS 16.7.11 and iPadOS 16.7.11, iOS 15.8.4 and iPadOS 15.8.4. Maliciously crafted web content may be able to break out of Web Content sandbox. This is a supplementary fix for an attack that was blocked in iOS 17.2. (Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 17.2.).

- [https://github.com/JGoyd/glass-cage-ios18-cve-2025-24085-cve-2025-24201](https://github.com/JGoyd/glass-cage-ios18-cve-2025-24085-cve-2025-24201) :  ![starts](https://img.shields.io/github/stars/JGoyd/glass-cage-ios18-cve-2025-24085-cve-2025-24201.svg) ![forks](https://img.shields.io/github/forks/JGoyd/glass-cage-ios18-cve-2025-24085-cve-2025-24201.svg)


## CVE-2025-24085
 A use after free issue was addressed with improved memory management. This issue is fixed in visionOS 2.3, iOS 18.3 and iPadOS 18.3, macOS Sequoia 15.3, watchOS 11.3, tvOS 18.3. A malicious application may be able to elevate privileges. Apple is aware of a report that this issue may have been actively exploited against versions of iOS before iOS 17.2.

- [https://github.com/JGoyd/glass-cage-ios18-cve-2025-24085-cve-2025-24201](https://github.com/JGoyd/glass-cage-ios18-cve-2025-24085-cve-2025-24201) :  ![starts](https://img.shields.io/github/stars/JGoyd/glass-cage-ios18-cve-2025-24085-cve-2025-24201.svg) ![forks](https://img.shields.io/github/forks/JGoyd/glass-cage-ios18-cve-2025-24085-cve-2025-24201.svg)


## CVE-2025-8671
 A mismatch caused by client-triggered server-sent stream resets between HTTP/2 specifications and the internal architectures of some HTTP/2 implementations may result in excessive server resource consumption leading to denial-of-service (DoS).  By opening streams and then rapidly triggering the server to reset them—using malformed frames or flow control errors—an attacker can exploit incorrect stream accounting. Streams reset by the server are considered closed at the protocol level, even though backend processing continues. This allows a client to cause the server to handle an unbounded number of concurrent streams on a single connection. This CVE will be updated as affected product details are released.

- [https://github.com/abiyeenzo/CVE-2025-8671](https://github.com/abiyeenzo/CVE-2025-8671) :  ![starts](https://img.shields.io/github/stars/abiyeenzo/CVE-2025-8671.svg) ![forks](https://img.shields.io/github/forks/abiyeenzo/CVE-2025-8671.svg)


## CVE-2025-6713
 An unauthorized user may leverage a specially crafted aggregation pipeline to access data without proper authorization due to improper handling of the $mergeCursors stage in MongoDB Server. This may lead to access to data without further authorisation. This issue affects MongoDB Server MongoDB Server v8.0 versions prior to 8.0.7, MongoDB Server v7.0 versions prior to 7.0.19 and MongoDB Server v6.0 versions prior to 6.0.22

- [https://github.com/c137req/CVE-2025-6713](https://github.com/c137req/CVE-2025-6713) :  ![starts](https://img.shields.io/github/stars/c137req/CVE-2025-6713.svg) ![forks](https://img.shields.io/github/forks/c137req/CVE-2025-6713.svg)


## CVE-2025-4396
 The Relevanssi – A Better Search plugin for WordPress is vulnerable to time-based SQL Injection via the cats and tags query parameters in all versions up to, and including, 4.24.4 (Free) and = 2.27.4 (Premium) due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries to already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/far00t01/CVE-2025-43960](https://github.com/far00t01/CVE-2025-43960) :  ![starts](https://img.shields.io/github/stars/far00t01/CVE-2025-43960.svg) ![forks](https://img.shields.io/github/forks/far00t01/CVE-2025-43960.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/InfoSec-DB/PHPCGIScanner](https://github.com/InfoSec-DB/PHPCGIScanner) :  ![starts](https://img.shields.io/github/stars/InfoSec-DB/PHPCGIScanner.svg) ![forks](https://img.shields.io/github/forks/InfoSec-DB/PHPCGIScanner.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/TheLastVvV/CVE-2021-41773](https://github.com/TheLastVvV/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/TheLastVvV/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/TheLastVvV/CVE-2021-41773.svg)
- [https://github.com/vuongnv3389-sec/cve-2021-41773](https://github.com/vuongnv3389-sec/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/vuongnv3389-sec/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/vuongnv3389-sec/cve-2021-41773.svg)
- [https://github.com/Fa1c0n35/CVE-2021-41773](https://github.com/Fa1c0n35/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Fa1c0n35/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Fa1c0n35/CVE-2021-41773.svg)


## CVE-2021-21345
 XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.16, there is a vulnerability which may allow a remote attacker who has sufficient rights to execute commands of the host only by manipulating the processed input stream. No user is affected, who followed the recommendation to setup XStream's security framework with a whitelist limited to the minimal required types. If you rely on XStream's default blacklist of the Security Framework, you will have to use at least version 1.4.16.

- [https://github.com/shoucheng3/x-stream__xstream_CVE-2021-21345_1-4-15](https://github.com/shoucheng3/x-stream__xstream_CVE-2021-21345_1-4-15) :  ![starts](https://img.shields.io/github/stars/shoucheng3/x-stream__xstream_CVE-2021-21345_1-4-15.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/x-stream__xstream_CVE-2021-21345_1-4-15.svg)


## CVE-2020-26217
 XStream before version 1.4.14 is vulnerable to Remote Code Execution.The vulnerability may allow a remote attacker to run arbitrary shell commands only by manipulating the processed input stream. Only users who rely on blocklists are affected. Anyone using XStream's Security Framework allowlist is not affected. The linked advisory provides code workarounds for users who cannot upgrade. The issue is fixed in version 1.4.14.

- [https://github.com/shoucheng3/x-stream__xstream_CVE-2020-26217_1-4-14-java7](https://github.com/shoucheng3/x-stream__xstream_CVE-2020-26217_1-4-14-java7) :  ![starts](https://img.shields.io/github/stars/shoucheng3/x-stream__xstream_CVE-2020-26217_1-4-14-java7.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/x-stream__xstream_CVE-2020-26217_1-4-14-java7.svg)


## CVE-2014-4725
 The MailPoet Newsletters (wysija-newsletters) plugin before 2.6.7 for WordPress allows remote attackers to bypass authentication and execute arbitrary PHP code by uploading a crafted theme using wp-admin/admin-post.php and accessing the theme in wp-content/uploads/wysija/themes/mailp/.

- [https://github.com/Pwdnx1337/CVE-2014-4725](https://github.com/Pwdnx1337/CVE-2014-4725) :  ![starts](https://img.shields.io/github/stars/Pwdnx1337/CVE-2014-4725.svg) ![forks](https://img.shields.io/github/forks/Pwdnx1337/CVE-2014-4725.svg)

