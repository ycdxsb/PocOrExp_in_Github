# Update 2021-12-02
## CVE-2021-43778
 Barcode is a GLPI plugin for printing barcodes and QR codes. GLPI instances version 2.x prior to version 2.6.1 with the barcode plugin installed are vulnerable to a path traversal vulnerability. This issue was patched in version 2.6.1. As a workaround, delete the `front/send.php` file.

- [https://github.com/AK-blank/CVE-2021-43778](https://github.com/AK-blank/CVE-2021-43778) :  ![starts](https://img.shields.io/github/stars/AK-blank/CVE-2021-43778.svg) ![forks](https://img.shields.io/github/forks/AK-blank/CVE-2021-43778.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/MazX0p/CVE-2021-41773](https://github.com/MazX0p/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/MazX0p/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/MazX0p/CVE-2021-41773.svg)


## CVE-2021-38001
 Type confusion in V8 in Google Chrome prior to 95.0.4638.69 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/maldiohead/TFC-Chrome-v8-bug-CVE-2021-38001-poc](https://github.com/maldiohead/TFC-Chrome-v8-bug-CVE-2021-38001-poc) :  ![starts](https://img.shields.io/github/stars/maldiohead/TFC-Chrome-v8-bug-CVE-2021-38001-poc.svg) ![forks](https://img.shields.io/github/forks/maldiohead/TFC-Chrome-v8-bug-CVE-2021-38001-poc.svg)


## CVE-2021-30807
 A memory corruption issue was addressed with improved memory handling. This issue is fixed in macOS Big Sur 11.5.1, iOS 14.7.1 and iPadOS 14.7.1, watchOS 7.6.1. An application may be able to execute arbitrary code with kernel privileges. Apple is aware of a report that this issue may have been actively exploited.

- [https://github.com/30440r/gex](https://github.com/30440r/gex) :  ![starts](https://img.shields.io/github/stars/30440r/gex.svg) ![forks](https://img.shields.io/github/forks/30440r/gex.svg)


## CVE-2021-25251
 The Trend Micro Security 2020 and 2021 families of consumer products are vulnerable to a code injection vulnerability which could allow an attacker to disable the program's password protection and disable protection. An attacker must already have administrator privileges on the machine to exploit this vulnerability.

- [https://github.com/Parasect-Team/for-trendmciro](https://github.com/Parasect-Team/for-trendmciro) :  ![starts](https://img.shields.io/github/stars/Parasect-Team/for-trendmciro.svg) ![forks](https://img.shields.io/github/forks/Parasect-Team/for-trendmciro.svg)


## CVE-2021-22205
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 11.9. GitLab was not properly validating image files that were passed to a file parser which resulted in a remote command execution.

- [https://github.com/XTeam-Wing/CVE-2021-22205](https://github.com/XTeam-Wing/CVE-2021-22205) :  ![starts](https://img.shields.io/github/stars/XTeam-Wing/CVE-2021-22205.svg) ![forks](https://img.shields.io/github/forks/XTeam-Wing/CVE-2021-22205.svg)


## CVE-2021-21315
 The System Information Library for Node.JS (npm package &quot;systeminformation&quot;) is an open source collection of functions to retrieve detailed hardware, system and OS information. In systeminformation before version 5.3.1 there is a command injection vulnerability. Problem was fixed in version 5.3.1. As a workaround instead of upgrading, be sure to check or sanitize service parameters that are passed to si.inetLatency(), si.inetChecksite(), si.services(), si.processLoad() ... do only allow strings, reject any arrays. String sanitation works as expected.

- [https://github.com/MazX0p/CVE-2021-21315-exploit](https://github.com/MazX0p/CVE-2021-21315-exploit) :  ![starts](https://img.shields.io/github/stars/MazX0p/CVE-2021-21315-exploit.svg) ![forks](https://img.shields.io/github/forks/MazX0p/CVE-2021-21315-exploit.svg)


## CVE-2020-8961
 An issue was discovered in Avira Free-Antivirus before 15.0.2004.1825. The Self-Protection feature does not prohibit a write operation from an external process. Thus, code injection can be used to turn off this feature. After that, one can construct an event that will modify a file at a specific location, and pass this event to the driver, thereby defeating the anti-virus functionality.

- [https://github.com/Parasect-Team/for-avira](https://github.com/Parasect-Team/for-avira) :  ![starts](https://img.shields.io/github/stars/Parasect-Team/for-avira.svg) ![forks](https://img.shields.io/github/forks/Parasect-Team/for-avira.svg)


## CVE-2019-6340
 Some field types do not properly sanitize data from non-form sources in Drupal 8.5.x before 8.5.11 and Drupal 8.6.x before 8.6.10. This can lead to arbitrary PHP code execution in some cases. A site is only affected by this if one of the following conditions is met: The site has the Drupal 8 core RESTful Web Services (rest) module enabled and allows PATCH or POST requests, or the site has another web services module enabled, like JSON:API in Drupal 8, or Services or RESTful Web Services in Drupal 7. (Note: The Drupal 7 Services module itself does not require an update at this time, but you should apply other contributed updates associated with this advisory if Services is in use.)

- [https://github.com/Haruster/Apasys-CVE-2019-6340](https://github.com/Haruster/Apasys-CVE-2019-6340) :  ![starts](https://img.shields.io/github/stars/Haruster/Apasys-CVE-2019-6340.svg) ![forks](https://img.shields.io/github/forks/Haruster/Apasys-CVE-2019-6340.svg)


## CVE-2019-2725
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Web Services). Supported versions that are affected are 10.3.6.0.0 and 12.1.3.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/kerlingcode/CVE-2019-2725](https://github.com/kerlingcode/CVE-2019-2725) :  ![starts](https://img.shields.io/github/stars/kerlingcode/CVE-2019-2725.svg) ![forks](https://img.shields.io/github/forks/kerlingcode/CVE-2019-2725.svg)
- [https://github.com/ianxtianxt/CVE-2019-2725](https://github.com/ianxtianxt/CVE-2019-2725) :  ![starts](https://img.shields.io/github/stars/ianxtianxt/CVE-2019-2725.svg) ![forks](https://img.shields.io/github/forks/ianxtianxt/CVE-2019-2725.svg)
- [https://github.com/1stPeak/CVE-2019-2725-environment](https://github.com/1stPeak/CVE-2019-2725-environment) :  ![starts](https://img.shields.io/github/stars/1stPeak/CVE-2019-2725-environment.svg) ![forks](https://img.shields.io/github/forks/1stPeak/CVE-2019-2725-environment.svg)

