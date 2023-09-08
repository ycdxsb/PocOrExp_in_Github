# Update 2023-09-08
## CVE-2023-38490
 Kirby is a content management system. A vulnerability in versions prior to 3.5.8.3, 3.6.6.3, 3.7.5.2, 3.8.4.1, and 3.9.6 only affects Kirby sites that use the `Xml` data handler (e.g. `Data::decode($string, 'xml')`) or the `Xml::parse()` method in site or plugin code. The Kirby core does not use any of the affected methods. XML External Entities (XXE) is a little used feature in the XML markup language that allows to include data from external files in an XML structure. If the name of the external file can be controlled by an attacker, this becomes a vulnerability that can be abused for various system impacts like the disclosure of internal or confidential data that is stored on the server (arbitrary file disclosure) or to perform network requests on behalf of the server (server-side request forgery, SSRF). Kirby's `Xml::parse()` method used PHP's `LIBXML_NOENT` constant, which enabled the processing of XML external entities during the parsing operation. The `Xml::parse()` method is used in the `Xml` data handler (e.g. `Data::decode($string, 'xml')`). Both the vulnerable method and the data handler are not used in the Kirby core. However they may be used in site or plugin code, e.g. to parse RSS feeds or other XML files. If those files are of an external origin (e.g. uploaded by a user or retrieved from an external URL), attackers may be able to include an external entity in the XML file that will then be processed in the parsing process. Kirby sites that don't use XML parsing in site or plugin code are *not* affected. The problem has been patched in Kirby 3.5.8.3, 3.6.6.3, 3.7.5.2, 3.8.4.1, and 3.9.6. In all of the mentioned releases, the maintainers have removed the `LIBXML_NOENT` constant as processing of external entities is out of scope of the parsing logic. This protects all uses of the method against the described vulnerability.

- [https://github.com/Acceis/exploit-CVE-2023-38490](https://github.com/Acceis/exploit-CVE-2023-38490) :  ![starts](https://img.shields.io/github/stars/Acceis/exploit-CVE-2023-38490.svg) ![forks](https://img.shields.io/github/forks/Acceis/exploit-CVE-2023-38490.svg)


## CVE-2023-37941
 If an attacker gains write access to the Apache Superset metadata database, they could persist a specifically crafted Python object that may lead to remote code execution on Superset's web backend. This vulnerability impacts Apache Superset versions 1.5.0 up to and including 2.1.0.

- [https://github.com/Barroqueiro/CVE-2023-37941](https://github.com/Barroqueiro/CVE-2023-37941) :  ![starts](https://img.shields.io/github/stars/Barroqueiro/CVE-2023-37941.svg) ![forks](https://img.shields.io/github/forks/Barroqueiro/CVE-2023-37941.svg)


## CVE-2023-36123
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/9Bakabaka/CVE-2023-36123](https://github.com/9Bakabaka/CVE-2023-36123) :  ![starts](https://img.shields.io/github/stars/9Bakabaka/CVE-2023-36123.svg) ![forks](https://img.shields.io/github/forks/9Bakabaka/CVE-2023-36123.svg)


## CVE-2023-24078
 Real Time Logic FuguHub v8.1 and earlier was discovered to contain a remote code execution (RCE) vulnerability via the component /FuguHub/cmsdocs/.

- [https://github.com/d2cy/CVEs](https://github.com/d2cy/CVEs) :  ![starts](https://img.shields.io/github/stars/d2cy/CVEs.svg) ![forks](https://img.shields.io/github/forks/d2cy/CVEs.svg)


## CVE-2023-3812
 An out-of-bounds memory access flaw was found in the Linux kernel&#8217;s TUN/TAP device driver functionality in how a user generates a malicious (too big) networking packet when napi frags is enabled. This flaw allows a local user to crash or potentially escalate their privileges on the system.

- [https://github.com/nidhi7598/linux-4.19.72_CVE-2023-3812](https://github.com/nidhi7598/linux-4.19.72_CVE-2023-3812) :  ![starts](https://img.shields.io/github/stars/nidhi7598/linux-4.19.72_CVE-2023-3812.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/linux-4.19.72_CVE-2023-3812.svg)


## CVE-2023-3163
 A vulnerability was found in y_project RuoYi up to 4.7.7. It has been classified as problematic. Affected is the function filterKeyword. The manipulation of the argument value leads to resource consumption. VDB-231090 is the identifier assigned to this vulnerability.

- [https://github.com/George0Papasotiriou/CVE-2023-3163-SQL-Injection-Prevention](https://github.com/George0Papasotiriou/CVE-2023-3163-SQL-Injection-Prevention) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2023-3163-SQL-Injection-Prevention.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2023-3163-SQL-Injection-Prevention.svg)


## CVE-2022-40048
 Flatpress v1.2.1 was discovered to contain a remote code execution (RCE) vulnerability in the Upload File function.

- [https://github.com/d2cy/CVEs](https://github.com/d2cy/CVEs) :  ![starts](https://img.shields.io/github/stars/d2cy/CVEs.svg) ![forks](https://img.shields.io/github/forks/d2cy/CVEs.svg)


## CVE-2022-20133
 In setDiscoverableTimeout of AdapterService.java, there is a possible bypass of user interaction due to a missing permission check. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-206807679

- [https://github.com/nidhi7598/packages_apps_Bluetooth_AOSP_10_r33_CVE-2022-20133](https://github.com/nidhi7598/packages_apps_Bluetooth_AOSP_10_r33_CVE-2022-20133) :  ![starts](https://img.shields.io/github/stars/nidhi7598/packages_apps_Bluetooth_AOSP_10_r33_CVE-2022-20133.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/packages_apps_Bluetooth_AOSP_10_r33_CVE-2022-20133.svg)


## CVE-2022-4510
 A path traversal vulnerability was identified in ReFirm Labs binwalk from version 2.1.2b through 2.3.3 included. By crafting a malicious PFS filesystem file, an attacker can get binwalk's PFS extractor to extract files at arbitrary locations when binwalk is run in extraction mode (-e option). Remote code execution can be achieved by building a PFS filesystem that, upon extraction, would extract a malicious binwalk module into the folder .config/binwalk/plugins. This vulnerability is associated with program files src/binwalk/plugins/unpfs.py. This issue affects binwalk from 2.1.2b through 2.3.3 included.

- [https://github.com/electr0sm0g/CVE-2022-4510](https://github.com/electr0sm0g/CVE-2022-4510) :  ![starts](https://img.shields.io/github/stars/electr0sm0g/CVE-2022-4510.svg) ![forks](https://img.shields.io/github/forks/electr0sm0g/CVE-2022-4510.svg)


## CVE-2022-3452
 A vulnerability was found in SourceCodester Book Store Management System 1.0. It has been declared as problematic. This vulnerability affects unknown code of the file /category.php. The manipulation of the argument category_name leads to cross site scripting. The attack can be initiated remotely. The identifier of this vulnerability is VDB-210436.

- [https://github.com/kenyon-wong/cve-2022-3452](https://github.com/kenyon-wong/cve-2022-3452) :  ![starts](https://img.shields.io/github/stars/kenyon-wong/cve-2022-3452.svg) ![forks](https://img.shields.io/github/forks/kenyon-wong/cve-2022-3452.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/qqdagustian/CVE_2022_0847](https://github.com/qqdagustian/CVE_2022_0847) :  ![starts](https://img.shields.io/github/stars/qqdagustian/CVE_2022_0847.svg) ![forks](https://img.shields.io/github/forks/qqdagustian/CVE_2022_0847.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mightysai1997/CVE-2021-41773-i-](https://github.com/mightysai1997/CVE-2021-41773-i-) :  ![starts](https://img.shields.io/github/stars/mightysai1997/CVE-2021-41773-i-.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/CVE-2021-41773-i-.svg)


## CVE-2021-28476
 Windows Hyper-V Remote Code Execution Vulnerability

- [https://github.com/2273852279qqs/0vercl0k](https://github.com/2273852279qqs/0vercl0k) :  ![starts](https://img.shields.io/github/stars/2273852279qqs/0vercl0k.svg) ![forks](https://img.shields.io/github/forks/2273852279qqs/0vercl0k.svg)


## CVE-2021-3754
 A flaw was found in keycloak where an attacker is able to register himself with the username same as the email ID of any existing user. This may cause trouble in getting password recovery email in case the user forgets the password.

- [https://github.com/7Ragnarok7/CVE-2021-3754](https://github.com/7Ragnarok7/CVE-2021-3754) :  ![starts](https://img.shields.io/github/stars/7Ragnarok7/CVE-2021-3754.svg) ![forks](https://img.shields.io/github/forks/7Ragnarok7/CVE-2021-3754.svg)


## CVE-2019-16759
 vBulletin 5.x through 5.5.4 allows remote command execution via the widgetConfig[code] parameter in an ajax/render/widget_php routestring request.

- [https://github.com/0xdims/CVE-2019-16759](https://github.com/0xdims/CVE-2019-16759) :  ![starts](https://img.shields.io/github/stars/0xdims/CVE-2019-16759.svg) ![forks](https://img.shields.io/github/forks/0xdims/CVE-2019-16759.svg)


## CVE-2018-13382
 An Improper Authorization vulnerability in Fortinet FortiOS 6.0.0 to 6.0.4, 5.6.0 to 5.6.8 and 5.4.1 to 5.4.10 and FortiProxy 2.0.0, 1.2.0 to 1.2.8, 1.1.0 to 1.1.6, 1.0.0 to 1.0.7 under SSL VPN web portal allows an unauthenticated attacker to modify the password of an SSL VPN web portal user via specially crafted HTTP requests

- [https://github.com/tumikoto/Exploit-FortinetMagicBackdoor](https://github.com/tumikoto/Exploit-FortinetMagicBackdoor) :  ![starts](https://img.shields.io/github/stars/tumikoto/Exploit-FortinetMagicBackdoor.svg) ![forks](https://img.shields.io/github/forks/tumikoto/Exploit-FortinetMagicBackdoor.svg)


## CVE-2018-10933
 A vulnerability was found in libssh's server-side state machine before versions 0.7.6 and 0.8.4. A malicious client could create channels without first performing authentication, resulting in unauthorized access.

- [https://github.com/hook-s3c/CVE-2018-10933](https://github.com/hook-s3c/CVE-2018-10933) :  ![starts](https://img.shields.io/github/stars/hook-s3c/CVE-2018-10933.svg) ![forks](https://img.shields.io/github/forks/hook-s3c/CVE-2018-10933.svg)
- [https://github.com/throwawayaccount12312312/precompiled-CVE-2018-10933](https://github.com/throwawayaccount12312312/precompiled-CVE-2018-10933) :  ![starts](https://img.shields.io/github/stars/throwawayaccount12312312/precompiled-CVE-2018-10933.svg) ![forks](https://img.shields.io/github/forks/throwawayaccount12312312/precompiled-CVE-2018-10933.svg)
- [https://github.com/crispy-peppers/Libssh-server-CVE-2018-10933](https://github.com/crispy-peppers/Libssh-server-CVE-2018-10933) :  ![starts](https://img.shields.io/github/stars/crispy-peppers/Libssh-server-CVE-2018-10933.svg) ![forks](https://img.shields.io/github/forks/crispy-peppers/Libssh-server-CVE-2018-10933.svg)


## CVE-2018-2628
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.2 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/shaoshore/CVE-2018-2628](https://github.com/shaoshore/CVE-2018-2628) :  ![starts](https://img.shields.io/github/stars/shaoshore/CVE-2018-2628.svg) ![forks](https://img.shields.io/github/forks/shaoshore/CVE-2018-2628.svg)


## CVE-2017-0541
 A remote code execution vulnerability in sonivox in Mediaserver could enable an attacker using a specially crafted file to cause memory corruption during media file and data processing. This issue is rated as Critical due to the possibility of remote code execution within the context of the Mediaserver process. Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1. Android ID: A-34031018.

- [https://github.com/C0dak/CVE-2017-0541](https://github.com/C0dak/CVE-2017-0541) :  ![starts](https://img.shields.io/github/stars/C0dak/CVE-2017-0541.svg) ![forks](https://img.shields.io/github/forks/C0dak/CVE-2017-0541.svg)


## CVE-2017-0478
 A remote code execution vulnerability in the Framesequence library could enable an attacker using a specially crafted file to execute arbitrary code in the context of an unprivileged process. This issue is rated as High due to the possibility of remote code execution in an application that uses the Framesequence library. Product: Android. Versions: 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1. Android ID: A-33718716.

- [https://github.com/bingghost/CVE-2017-0478](https://github.com/bingghost/CVE-2017-0478) :  ![starts](https://img.shields.io/github/stars/bingghost/CVE-2017-0478.svg) ![forks](https://img.shields.io/github/forks/bingghost/CVE-2017-0478.svg)


## CVE-2017-0199
 Microsoft Office 2007 SP3, Microsoft Office 2010 SP2, Microsoft Office 2013 SP1, Microsoft Office 2016, Microsoft Windows Vista SP2, Windows Server 2008 SP2, Windows 7 SP1, Windows 8.1 allow remote attackers to execute arbitrary code via a crafted document, aka &quot;Microsoft Office/WordPad Remote Code Execution Vulnerability w/Windows API.&quot;

- [https://github.com/kn0wm4d/htattack](https://github.com/kn0wm4d/htattack) :  ![starts](https://img.shields.io/github/stars/kn0wm4d/htattack.svg) ![forks](https://img.shields.io/github/forks/kn0wm4d/htattack.svg)
- [https://github.com/Nacromencer/cve2017-0199-in-python](https://github.com/Nacromencer/cve2017-0199-in-python) :  ![starts](https://img.shields.io/github/stars/Nacromencer/cve2017-0199-in-python.svg) ![forks](https://img.shields.io/github/forks/Nacromencer/cve2017-0199-in-python.svg)

