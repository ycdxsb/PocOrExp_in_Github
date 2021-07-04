# Update 2021-07-04
## CVE-2021-35975
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/trump88/CVE-2021-35975](https://github.com/trump88/CVE-2021-35975) :  ![starts](https://img.shields.io/github/stars/trump88/CVE-2021-35975.svg) ![forks](https://img.shields.io/github/forks/trump88/CVE-2021-35975.svg)


## CVE-2021-34527
 Windows Print Spooler Remote Code Execution Vulnerability

- [https://github.com/JohnHammond/CVE-2021-34527](https://github.com/JohnHammond/CVE-2021-34527) :  ![starts](https://img.shields.io/github/stars/JohnHammond/CVE-2021-34527.svg) ![forks](https://img.shields.io/github/forks/JohnHammond/CVE-2021-34527.svg)
- [https://github.com/glshnu/PrintNightmare](https://github.com/glshnu/PrintNightmare) :  ![starts](https://img.shields.io/github/stars/glshnu/PrintNightmare.svg) ![forks](https://img.shields.io/github/forks/glshnu/PrintNightmare.svg)
- [https://github.com/fardinbarashi/Fix-CVE-2021-34527](https://github.com/fardinbarashi/Fix-CVE-2021-34527) :  ![starts](https://img.shields.io/github/stars/fardinbarashi/Fix-CVE-2021-34527.svg) ![forks](https://img.shields.io/github/forks/fardinbarashi/Fix-CVE-2021-34527.svg)
- [https://github.com/DenizSe/CVE-2021-34527](https://github.com/DenizSe/CVE-2021-34527) :  ![starts](https://img.shields.io/github/stars/DenizSe/CVE-2021-34527.svg) ![forks](https://img.shields.io/github/forks/DenizSe/CVE-2021-34527.svg)


## CVE-2021-27850
 A critical unauthenticated remote code execution vulnerability was found all recent versions of Apache Tapestry. The affected versions include 5.4.5, 5.5.0, 5.6.2 and 5.7.0. The vulnerability I have found is a bypass of the fix for CVE-2019-0195. Recap: Before the fix of CVE-2019-0195 it was possible to download arbitrary class files from the classpath by providing a crafted asset file URL. An attacker was able to download the file `AppModule.class` by requesting the URL `http://localhost:8080/assets/something/services/AppModule.class` which contains a HMAC secret key. The fix for that bug was a blacklist filter that checks if the URL ends with `.class`, `.properties` or `.xml`. Bypass: Unfortunately, the blacklist solution can simply be bypassed by appending a `/` at the end of the URL: `http://localhost:8080/assets/something/services/AppModule.class/` The slash is stripped after the blacklist check and the file `AppModule.class` is loaded into the response. This class usually contains the HMAC secret key which is used to sign serialized Java objects. With the knowledge of that key an attacker can sign a Java gadget chain that leads to RCE (e.g. CommonsBeanUtils1 from ysoserial). Solution for this vulnerability: * For Apache Tapestry 5.4.0 to 5.6.1, upgrade to 5.6.2 or later. * For Apache Tapestry 5.7.0, upgrade to 5.7.1 or later.

- [https://github.com/Ovi3/CVE_2021_27850_POC](https://github.com/Ovi3/CVE_2021_27850_POC) :  ![starts](https://img.shields.io/github/stars/Ovi3/CVE_2021_27850_POC.svg) ![forks](https://img.shields.io/github/forks/Ovi3/CVE_2021_27850_POC.svg)


## CVE-2021-3560
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/mr-nO0b/CVE-2021-3560](https://github.com/mr-nO0b/CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/mr-nO0b/CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/mr-nO0b/CVE-2021-3560.svg)
- [https://github.com/iSTARLabs/CVE-2021-3560_PoC](https://github.com/iSTARLabs/CVE-2021-3560_PoC) :  ![starts](https://img.shields.io/github/stars/iSTARLabs/CVE-2021-3560_PoC.svg) ![forks](https://img.shields.io/github/forks/iSTARLabs/CVE-2021-3560_PoC.svg)


## CVE-2021-1675
 Windows Print Spooler Elevation of Privilege Vulnerability

- [https://github.com/thomasgeens/CVE-2021-1675](https://github.com/thomasgeens/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/thomasgeens/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/thomasgeens/CVE-2021-1675.svg)
- [https://github.com/kougyokugentou/CVE-2021-1675](https://github.com/kougyokugentou/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/kougyokugentou/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/kougyokugentou/CVE-2021-1675.svg)
- [https://github.com/initconf/cve-2021-1675-printnightmare](https://github.com/initconf/cve-2021-1675-printnightmare) :  ![starts](https://img.shields.io/github/stars/initconf/cve-2021-1675-printnightmare.svg) ![forks](https://img.shields.io/github/forks/initconf/cve-2021-1675-printnightmare.svg)
- [https://github.com/ptter23/CVE-2021-1675](https://github.com/ptter23/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/ptter23/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/ptter23/CVE-2021-1675.svg)
- [https://github.com/killtr0/CVE-2021-1675-PrintNightmare](https://github.com/killtr0/CVE-2021-1675-PrintNightmare) :  ![starts](https://img.shields.io/github/stars/killtr0/CVE-2021-1675-PrintNightmare.svg) ![forks](https://img.shields.io/github/forks/killtr0/CVE-2021-1675-PrintNightmare.svg)
- [https://github.com/mrezqi/CVE-2021-1675_CarbonBlack_HuntingQuery](https://github.com/mrezqi/CVE-2021-1675_CarbonBlack_HuntingQuery) :  ![starts](https://img.shields.io/github/stars/mrezqi/CVE-2021-1675_CarbonBlack_HuntingQuery.svg) ![forks](https://img.shields.io/github/forks/mrezqi/CVE-2021-1675_CarbonBlack_HuntingQuery.svg)
- [https://github.com/gohrenberg/CVE-2021-1675-Mitigation-For-Systems-That-Need-Spooler](https://github.com/gohrenberg/CVE-2021-1675-Mitigation-For-Systems-That-Need-Spooler) :  ![starts](https://img.shields.io/github/stars/gohrenberg/CVE-2021-1675-Mitigation-For-Systems-That-Need-Spooler.svg) ![forks](https://img.shields.io/github/forks/gohrenberg/CVE-2021-1675-Mitigation-For-Systems-That-Need-Spooler.svg)
- [https://github.com/DenizSe/CVE-2021-34527](https://github.com/DenizSe/CVE-2021-34527) :  ![starts](https://img.shields.io/github/stars/DenizSe/CVE-2021-34527.svg) ![forks](https://img.shields.io/github/forks/DenizSe/CVE-2021-34527.svg)


## CVE-2020-29134
 The TOTVS Fluig platform allows path traversal through the parameter &quot;file = .. /&quot; encoded in base64. This affects all versions Fluig Lake 1.7.0, Fluig 1.6.5 and Fluig 1.6.4

- [https://github.com/lsass-exe/CVE-2020-29134](https://github.com/lsass-exe/CVE-2020-29134) :  ![starts](https://img.shields.io/github/stars/lsass-exe/CVE-2020-29134.svg) ![forks](https://img.shields.io/github/forks/lsass-exe/CVE-2020-29134.svg)


## CVE-2020-14882
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/N0Coriander/CVE-2020-14882-14883](https://github.com/N0Coriander/CVE-2020-14882-14883) :  ![starts](https://img.shields.io/github/stars/N0Coriander/CVE-2020-14882-14883.svg) ![forks](https://img.shields.io/github/forks/N0Coriander/CVE-2020-14882-14883.svg)


## CVE-2020-13886
 Intelbras TIP 200 60.61.75.15, TIP 200 LITE 60.61.75.15, and TIP 300 65.61.75.22 devices allow cgi-bin/cgiServer.exx?page=../ Directory Traversal.

- [https://github.com/lsass-exe/CVE-2020-13886](https://github.com/lsass-exe/CVE-2020-13886) :  ![starts](https://img.shields.io/github/stars/lsass-exe/CVE-2020-13886.svg) ![forks](https://img.shields.io/github/forks/lsass-exe/CVE-2020-13886.svg)


## CVE-2020-0674
 A remote code execution vulnerability exists in the way that the scripting engine handles objects in memory in Internet Explorer, aka 'Scripting Engine Memory Corruption Vulnerability'. This CVE ID is unique from CVE-2020-0673, CVE-2020-0710, CVE-2020-0711, CVE-2020-0712, CVE-2020-0713, CVE-2020-0767.

- [https://github.com/yukiNeko114514/CVE-2020-0674-PoC](https://github.com/yukiNeko114514/CVE-2020-0674-PoC) :  ![starts](https://img.shields.io/github/stars/yukiNeko114514/CVE-2020-0674-PoC.svg) ![forks](https://img.shields.io/github/forks/yukiNeko114514/CVE-2020-0674-PoC.svg)


## CVE-2019-15107
 An issue was discovered in Webmin &lt;=1.920. The parameter old in password_change.cgi contains a command injection vulnerability.

- [https://github.com/whokilleddb/CVE-2019-15107](https://github.com/whokilleddb/CVE-2019-15107) :  ![starts](https://img.shields.io/github/stars/whokilleddb/CVE-2019-15107.svg) ![forks](https://img.shields.io/github/forks/whokilleddb/CVE-2019-15107.svg)


## CVE-2019-6447
 The ES File Explorer File Manager application through 4.1.9.7.4 for Android allows remote attackers to read arbitrary files or execute applications via TCP port 59777 requests on the local Wi-Fi network. This TCP port remains open after the ES application has been launched once, and responds to unauthenticated application/json data over HTTP.

- [https://github.com/sidhawkss/ES-File-Explorer-Vulnerability-on-port-59777](https://github.com/sidhawkss/ES-File-Explorer-Vulnerability-on-port-59777) :  ![starts](https://img.shields.io/github/stars/sidhawkss/ES-File-Explorer-Vulnerability-on-port-59777.svg) ![forks](https://img.shields.io/github/forks/sidhawkss/ES-File-Explorer-Vulnerability-on-port-59777.svg)


## CVE-2018-16323
 ReadXBMImage in coders/xbm.c in ImageMagick before 7.0.8-9 leaves data uninitialized when processing an XBM file that has a negative pixel value. If the affected code is used as a library loaded into a process that includes sensitive information, that information sometimes can be leaked via the image data.

- [https://github.com/ttffdd/XBadManners](https://github.com/ttffdd/XBadManners) :  ![starts](https://img.shields.io/github/stars/ttffdd/XBadManners.svg) ![forks](https://img.shields.io/github/forks/ttffdd/XBadManners.svg)


## CVE-2016-3088
 The Fileserver web application in Apache ActiveMQ 5.x before 5.14.0 allows remote attackers to upload and execute arbitrary files via an HTTP PUT followed by an HTTP MOVE request.

- [https://github.com/MrRobotTnT/CVE-2016-3088](https://github.com/MrRobotTnT/CVE-2016-3088) :  ![starts](https://img.shields.io/github/stars/MrRobotTnT/CVE-2016-3088.svg) ![forks](https://img.shields.io/github/forks/MrRobotTnT/CVE-2016-3088.svg)

