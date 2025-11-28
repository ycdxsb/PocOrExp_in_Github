# Update 2025-11-28
## CVE-2025-65681
 An issue was discovered in Overhang.IO (tutor-open-edx) (overhangio/tutor) 20.0.2 allowing local unauthorized attackers to gain access to sensitive information due to the absence of proper cache-control HTTP headers and client-side session checks.

- [https://github.com/Rivek619/CVE-2025-65681](https://github.com/Rivek619/CVE-2025-65681) :  ![starts](https://img.shields.io/github/stars/Rivek619/CVE-2025-65681.svg) ![forks](https://img.shields.io/github/forks/Rivek619/CVE-2025-65681.svg)


## CVE-2025-65676
 Stored Cross site scripting (XSS) vulnerability in Classroomio LMS 0.1.13 allows authenticated attackers to execute arbitrary code via crafted SVG cover images.

- [https://github.com/Rivek619/CVE-2025-65676](https://github.com/Rivek619/CVE-2025-65676) :  ![starts](https://img.shields.io/github/stars/Rivek619/CVE-2025-65676.svg) ![forks](https://img.shields.io/github/forks/Rivek619/CVE-2025-65676.svg)


## CVE-2025-65675
 Stored Cross site scripting (XSS) vulnerability in Classroomio LMS 0.1.13 allows authenticated attackers to execute arbitrary code via crafted SVG profile pictures.

- [https://github.com/Rivek619/CVE-2025-65675](https://github.com/Rivek619/CVE-2025-65675) :  ![starts](https://img.shields.io/github/stars/Rivek619/CVE-2025-65675.svg) ![forks](https://img.shields.io/github/forks/Rivek619/CVE-2025-65675.svg)


## CVE-2025-65672
 Insecure Direct Object Reference (IDOR) in classroomio 0.1.13 allows unauthorized share and invite access to course settings.

- [https://github.com/Rivek619/CVE-2025-65672](https://github.com/Rivek619/CVE-2025-65672) :  ![starts](https://img.shields.io/github/stars/Rivek619/CVE-2025-65672.svg) ![forks](https://img.shields.io/github/forks/Rivek619/CVE-2025-65672.svg)


## CVE-2025-65670
 An Insecure Direct Object Reference (IDOR) in classroomio 0.1.13 allows students to access sensitive admin/teacher endpoints by manipulating course IDs in URLs, resulting in unauthorized disclosure of sensitive course, admin, and student data. The leak occurs momentarily before the system reverts to a normal state restricting access.

- [https://github.com/Rivek619/CVE-2025-65670](https://github.com/Rivek619/CVE-2025-65670) :  ![starts](https://img.shields.io/github/stars/Rivek619/CVE-2025-65670.svg) ![forks](https://img.shields.io/github/forks/Rivek619/CVE-2025-65670.svg)


## CVE-2025-65669
 An issue was discovered in classroomio 0.1.13. Student accounts are able to delete courses from the Explore page without any authorization or authentication checks, bypassing the expected admin-only deletion restriction.

- [https://github.com/Rivek619/CVE-2025-65669](https://github.com/Rivek619/CVE-2025-65669) :  ![starts](https://img.shields.io/github/stars/Rivek619/CVE-2025-65669.svg) ![forks](https://img.shields.io/github/forks/Rivek619/CVE-2025-65669.svg)


## CVE-2025-62207
 Azure Monitor Elevation of Privilege Vulnerability

- [https://github.com/stankobra853/CVE-2025-62207](https://github.com/stankobra853/CVE-2025-62207) :  ![starts](https://img.shields.io/github/stars/stankobra853/CVE-2025-62207.svg) ![forks](https://img.shields.io/github/forks/stankobra853/CVE-2025-62207.svg)


## CVE-2025-58360
 GeoServer is an open source server that allows users to share and edit geospatial data. From version 2.26.0 to before 2.26.2 and before 2.25.6, an XML External Entity (XXE) vulnerability was identified. The application accepts XML input through a specific endpoint /geoserver/wms operation GetMap. However, this input is not sufficiently sanitized or restricted, allowing an attacker to define external entities within the XML request. This issue has been patched in GeoServer 2.25.6, GeoServer 2.26.3, and GeoServer 2.27.0.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-58360](https://github.com/B1ack4sh/Blackash-CVE-2025-58360) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-58360.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-58360.svg)


## CVE-2025-43300
 An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in iOS 15.8.5 and iPadOS 15.8.5, iOS 16.7.12 and iPadOS 16.7.12. Processing a malicious image file may result in memory corruption. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals.

- [https://github.com/JGoyd/Glass-Cage-iOS18-CVE-2025-24085-CVE-2025-24201](https://github.com/JGoyd/Glass-Cage-iOS18-CVE-2025-24085-CVE-2025-24201) :  ![starts](https://img.shields.io/github/stars/JGoyd/Glass-Cage-iOS18-CVE-2025-24085-CVE-2025-24201.svg) ![forks](https://img.shields.io/github/forks/JGoyd/Glass-Cage-iOS18-CVE-2025-24085-CVE-2025-24201.svg)


## CVE-2025-32421
 Next.js is a React framework for building full-stack web applications. Versions prior to 14.2.24 and 15.1.6 have a race-condition vulnerability. This issue only affects the Pages Router under certain misconfigurations, causing normal endpoints to serve `pageProps` data instead of standard HTML. This issue was patched in versions 15.1.6 and 14.2.24 by stripping the `x-now-route-matches` header from incoming requests. Applications hosted on Vercel's platform are not affected by this issue, as the platform does not cache responses based solely on `200 OK` status without explicit `cache-control` headers. Those who self-host Next.js deployments and are unable to upgrade immediately can mitigate this vulnerability by stripping the `x-now-route-matches` header from all incoming requests at the content development network and setting `cache-control: no-store` for all responses under risk. The maintainers of Next.js strongly recommend only caching responses with explicit cache-control headers.

- [https://github.com/Delfaster/CVE-2025-32421---Race-Condition-Vulnerability---Next.js](https://github.com/Delfaster/CVE-2025-32421---Race-Condition-Vulnerability---Next.js) :  ![starts](https://img.shields.io/github/stars/Delfaster/CVE-2025-32421---Race-Condition-Vulnerability---Next.js.svg) ![forks](https://img.shields.io/github/forks/Delfaster/CVE-2025-32421---Race-Condition-Vulnerability---Next.js.svg)


## CVE-2025-29306
 An issue in FoxCMS v.1.2.5 allows a remote attacker to execute arbitrary code via the case display page in the index.html component.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-29306](https://github.com/B1ack4sh/Blackash-CVE-2025-29306) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-29306.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-29306.svg)


## CVE-2025-10230
 A flaw was found in Samba, in the front-end WINS hook handling: NetBIOS names from registration packets are passed to a shell without proper validation or escaping. Unsanitized NetBIOS name data from WINS registration packets are inserted into a shell command and executed by the Samba Active Directory Domain Controller’s wins hook, allowing an unauthenticated network attacker to achieve remote command execution as the Samba process.

- [https://github.com/marcostolosa/CVE-2025-10230](https://github.com/marcostolosa/CVE-2025-10230) :  ![starts](https://img.shields.io/github/stars/marcostolosa/CVE-2025-10230.svg) ![forks](https://img.shields.io/github/forks/marcostolosa/CVE-2025-10230.svg)


## CVE-2025-8088
     from ESET.

- [https://github.com/h4vier/cve-2025-8088](https://github.com/h4vier/cve-2025-8088) :  ![starts](https://img.shields.io/github/stars/h4vier/cve-2025-8088.svg) ![forks](https://img.shields.io/github/forks/h4vier/cve-2025-8088.svg)


## CVE-2025-2945
This issue affects pgAdmin 4: before 9.2.

- [https://github.com/ExtremeUday/CVE-2025-2945-pgAdmin4-Authenticated-RCE-PoC-](https://github.com/ExtremeUday/CVE-2025-2945-pgAdmin4-Authenticated-RCE-PoC-) :  ![starts](https://img.shields.io/github/stars/ExtremeUday/CVE-2025-2945-pgAdmin4-Authenticated-RCE-PoC-.svg) ![forks](https://img.shields.io/github/forks/ExtremeUday/CVE-2025-2945-pgAdmin4-Authenticated-RCE-PoC-.svg)


## CVE-2023-27532
 Vulnerability in Veeam Backup & Replication component allows encrypted credentials stored in the configuration database to be obtained. This may lead to gaining access to the backup infrastructure hosts.

- [https://github.com/yunus-a1i/veeam-cve-2023-27532-mock](https://github.com/yunus-a1i/veeam-cve-2023-27532-mock) :  ![starts](https://img.shields.io/github/stars/yunus-a1i/veeam-cve-2023-27532-mock.svg) ![forks](https://img.shields.io/github/forks/yunus-a1i/veeam-cve-2023-27532-mock.svg)


## CVE-2023-1189
 A vulnerability was found in WiseCleaner Wise Folder Hider 4.4.3.202. It has been declared as problematic. Affected by this vulnerability is the function 0x222400/0x222404/0x222410 in the library WiseFs64.sys of the component IoControlCode Handler. The manipulation leads to denial of service. An attack has to be approached locally. The exploit has been disclosed to the public and may be used. The identifier VDB-222361 was assigned to this vulnerability.

- [https://github.com/le0s1mba/CVE-2023-1189](https://github.com/le0s1mba/CVE-2023-1189) :  ![starts](https://img.shields.io/github/stars/le0s1mba/CVE-2023-1189.svg) ![forks](https://img.shields.io/github/forks/le0s1mba/CVE-2023-1189.svg)


## CVE-2022-0332
 A flaw was found in Moodle in versions 3.11 to 3.11.4. An SQL injection risk was identified in the h5p activity web service responsible for fetching user attempt data.

- [https://github.com/voniem12/KTLHPM](https://github.com/voniem12/KTLHPM) :  ![starts](https://img.shields.io/github/stars/voniem12/KTLHPM.svg) ![forks](https://img.shields.io/github/forks/voniem12/KTLHPM.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/RizqiSec/CVE-2021-41773](https://github.com/RizqiSec/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/RizqiSec/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/RizqiSec/CVE-2021-41773.svg)


## CVE-2021-36393
 In Moodle, an SQL injection risk was identified in the library fetching a user's recent courses.

- [https://github.com/voniem12/KTLHPM](https://github.com/voniem12/KTLHPM) :  ![starts](https://img.shields.io/github/stars/voniem12/KTLHPM.svg) ![forks](https://img.shields.io/github/forks/voniem12/KTLHPM.svg)


## CVE-2021-21980
 The vSphere Web Client (FLEX/Flash) contains an unauthorized arbitrary file read vulnerability. A malicious actor with network access to port 443 on vCenter Server may exploit this issue to gain access to sensitive information.

- [https://github.com/gui2000guix-ui/cve-2021-21980-mock-server](https://github.com/gui2000guix-ui/cve-2021-21980-mock-server) :  ![starts](https://img.shields.io/github/stars/gui2000guix-ui/cve-2021-21980-mock-server.svg) ![forks](https://img.shields.io/github/forks/gui2000guix-ui/cve-2021-21980-mock-server.svg)
- [https://github.com/pkxk5pr6m2-web/cve-2021-21980-nuclei-poc](https://github.com/pkxk5pr6m2-web/cve-2021-21980-nuclei-poc) :  ![starts](https://img.shields.io/github/stars/pkxk5pr6m2-web/cve-2021-21980-nuclei-poc.svg) ![forks](https://img.shields.io/github/forks/pkxk5pr6m2-web/cve-2021-21980-nuclei-poc.svg)
- [https://github.com/gui2000guix-ui/cve-2021-21980-nuclei-poc](https://github.com/gui2000guix-ui/cve-2021-21980-nuclei-poc) :  ![starts](https://img.shields.io/github/stars/gui2000guix-ui/cve-2021-21980-nuclei-poc.svg) ![forks](https://img.shields.io/github/forks/gui2000guix-ui/cve-2021-21980-nuclei-poc.svg)


## CVE-2020-14343
 A vulnerability was discovered in the PyYAML library in versions before 5.4, where it is susceptible to arbitrary code execution when it processes untrusted YAML files through the full_load method or with the FullLoader loader. Applications that use the library to process untrusted input may be vulnerable to this flaw. This flaw allows an attacker to execute arbitrary code on the system by abusing the python/object/new constructor. This flaw is due to an incomplete fix for CVE-2020-1747.

- [https://github.com/Kairo-one/CVE-2020-14343](https://github.com/Kairo-one/CVE-2020-14343) :  ![starts](https://img.shields.io/github/stars/Kairo-one/CVE-2020-14343.svg) ![forks](https://img.shields.io/github/forks/Kairo-one/CVE-2020-14343.svg)


## CVE-2020-1948
 This vulnerability can affect all Dubbo users stay on version 2.7.6 or lower. An attacker can send RPC requests with unrecognized service name or method name along with some malicious parameter payloads. When the malicious parameter is deserialized, it will execute some malicious code. More details can be found below.

- [https://github.com/richardzhangcmplx/Dubbo-deserialization](https://github.com/richardzhangcmplx/Dubbo-deserialization) :  ![starts](https://img.shields.io/github/stars/richardzhangcmplx/Dubbo-deserialization.svg) ![forks](https://img.shields.io/github/forks/richardzhangcmplx/Dubbo-deserialization.svg)


## CVE-2019-16278
 Directory Traversal in the function http_verify in nostromo nhttpd through 1.9.6 allows an attacker to achieve remote code execution via a crafted HTTP request.

- [https://github.com/andknownmaly/CVE-2019-16278](https://github.com/andknownmaly/CVE-2019-16278) :  ![starts](https://img.shields.io/github/stars/andknownmaly/CVE-2019-16278.svg) ![forks](https://img.shields.io/github/forks/andknownmaly/CVE-2019-16278.svg)


## CVE-2019-15949
 Nagios XI before 5.6.6 allows remote command execution as root. The exploit requires access to the server as the nagios user, or access as the admin user via the web interface. The getprofile.sh script, invoked by downloading a system profile (profile.php?cmd=download), is executed as root via a passwordless sudo entry; the script executes check_plugin, which is owned by the nagios user. A user logged into Nagios XI with permissions to modify plugins, or the nagios user on the server, can modify the check_plugin executable and insert malicious commands to execute as root.

- [https://github.com/0xla1n/Nagios-CVE-2019-15949-RCE-Poc](https://github.com/0xla1n/Nagios-CVE-2019-15949-RCE-Poc) :  ![starts](https://img.shields.io/github/stars/0xla1n/Nagios-CVE-2019-15949-RCE-Poc.svg) ![forks](https://img.shields.io/github/forks/0xla1n/Nagios-CVE-2019-15949-RCE-Poc.svg)


## CVE-2019-7609
 Kibana versions before 5.6.15 and 6.6.1 contain an arbitrary code execution flaw in the Timelion visualizer. An attacker with access to the Timelion application could send a request that will attempt to execute javascript code. This could possibly lead to an attacker executing arbitrary commands with permissions of the Kibana process on the host system.

- [https://github.com/aleister1102/kibana-prototype-pollusion](https://github.com/aleister1102/kibana-prototype-pollusion) :  ![starts](https://img.shields.io/github/stars/aleister1102/kibana-prototype-pollusion.svg) ![forks](https://img.shields.io/github/forks/aleister1102/kibana-prototype-pollusion.svg)


## CVE-2019-2025
 In binder_thread_read of binder.c, there is a possible use-after-free due to improper locking. This could lead to local escalation of privilege in the kernel with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-116855682References: Upstream kernel

- [https://github.com/3kyo0/CVE_2019_2025_EXP](https://github.com/3kyo0/CVE_2019_2025_EXP) :  ![starts](https://img.shields.io/github/stars/3kyo0/CVE_2019_2025_EXP.svg) ![forks](https://img.shields.io/github/forks/3kyo0/CVE_2019_2025_EXP.svg)


## CVE-2017-9841
 Util/PHP/eval-stdin.php in PHPUnit before 4.8.28 and 5.x before 5.6.3 allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a "?php " substring, as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.

- [https://github.com/joelindra/CVE-2017-9841](https://github.com/joelindra/CVE-2017-9841) :  ![starts](https://img.shields.io/github/stars/joelindra/CVE-2017-9841.svg) ![forks](https://img.shields.io/github/forks/joelindra/CVE-2017-9841.svg)


## CVE-2017-7533
 Race condition in the fsnotify implementation in the Linux kernel through 4.12.4 allows local users to gain privileges or cause a denial of service (memory corruption) via a crafted application that leverages simultaneous execution of the inotify_handle_event and vfs_rename functions.

- [https://github.com/woohooook/CVE_2017_7533_EXP](https://github.com/woohooook/CVE_2017_7533_EXP) :  ![starts](https://img.shields.io/github/stars/woohooook/CVE_2017_7533_EXP.svg) ![forks](https://img.shields.io/github/forks/woohooook/CVE_2017_7533_EXP.svg)


## CVE-2017-0199
 Microsoft Office 2007 SP3, Microsoft Office 2010 SP2, Microsoft Office 2013 SP1, Microsoft Office 2016, Microsoft Windows Vista SP2, Windows Server 2008 SP2, Windows 7 SP1, Windows 8.1 allow remote attackers to execute arbitrary code via a crafted document, aka "Microsoft Office/WordPad Remote Code Execution Vulnerability w/Windows API."

- [https://github.com/BlueShield-CyberDefense/Phishing-Analysis](https://github.com/BlueShield-CyberDefense/Phishing-Analysis) :  ![starts](https://img.shields.io/github/stars/BlueShield-CyberDefense/Phishing-Analysis.svg) ![forks](https://img.shields.io/github/forks/BlueShield-CyberDefense/Phishing-Analysis.svg)


## CVE-2016-10204
 SQL injection vulnerability in Zoneminder 1.30 and earlier allows remote attackers to execute arbitrary SQL commands via the limit parameter in a log query request to index.php.

- [https://github.com/0xNullComet/CVE-2016-10204_Webshell](https://github.com/0xNullComet/CVE-2016-10204_Webshell) :  ![starts](https://img.shields.io/github/stars/0xNullComet/CVE-2016-10204_Webshell.svg) ![forks](https://img.shields.io/github/forks/0xNullComet/CVE-2016-10204_Webshell.svg)

