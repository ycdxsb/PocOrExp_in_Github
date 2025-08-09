# Update 2025-08-09
## CVE-2025-54948
 A vulnerability in Trend Micro Apex One (on-premise) management console could allow a pre-authenticated remote attacker to upload malicious code and execute commands on affected installations.

- [https://github.com/allinsthon/CVE-2025-54948](https://github.com/allinsthon/CVE-2025-54948) :  ![starts](https://img.shields.io/github/stars/allinsthon/CVE-2025-54948.svg) ![forks](https://img.shields.io/github/forks/allinsthon/CVE-2025-54948.svg)


## CVE-2025-54253
 Adobe Experience Manager versions 6.5.23 and earlier are affected by a Misconfiguration vulnerability that could result in arbitrary code execution. An attacker could leverage this vulnerability to bypass security mechanisms and execute code. Exploitation of this issue does not require user interaction and scope is changed.

- [https://github.com/Shivshantp/CVE-2025-54253-Exploit-Demo](https://github.com/Shivshantp/CVE-2025-54253-Exploit-Demo) :  ![starts](https://img.shields.io/github/stars/Shivshantp/CVE-2025-54253-Exploit-Demo.svg) ![forks](https://img.shields.io/github/forks/Shivshantp/CVE-2025-54253-Exploit-Demo.svg)
- [https://github.com/barbaraeivyu/CVE-2025-54253-e](https://github.com/barbaraeivyu/CVE-2025-54253-e) :  ![starts](https://img.shields.io/github/stars/barbaraeivyu/CVE-2025-54253-e.svg) ![forks](https://img.shields.io/github/forks/barbaraeivyu/CVE-2025-54253-e.svg)


## CVE-2025-54135
 Cursor is a code editor built for programming with AI. Cursor allows writing in-workspace files with no user approval in versions below 1.3.9, If the file is a dotfile, editing it requires approval but creating a new one doesn't. Hence, if sensitive MCP files, such as the .cursor/mcp.json file don't already exist in the workspace, an attacker can chain a indirect prompt injection vulnerability to hijack the context to write to the settings file and trigger RCE on the victim without user approval. This is fixed in version 1.3.9.

- [https://github.com/Cbdlll/test-mcp](https://github.com/Cbdlll/test-mcp) :  ![starts](https://img.shields.io/github/stars/Cbdlll/test-mcp.svg) ![forks](https://img.shields.io/github/forks/Cbdlll/test-mcp.svg)


## CVE-2025-53770
Microsoft is preparing and fully testing a comprehensive update to address this vulnerability.  In the meantime, please make sure that the mitigation provided in this CVE documentation is in place so that you are protected from exploitation.

- [https://github.com/Agampreet-Singh/CVE-2025-53770](https://github.com/Agampreet-Singh/CVE-2025-53770) :  ![starts](https://img.shields.io/github/stars/Agampreet-Singh/CVE-2025-53770.svg) ![forks](https://img.shields.io/github/forks/Agampreet-Singh/CVE-2025-53770.svg)


## CVE-2025-51040
 Electrolink FM/DAB/TV Transmitter Web Management System Unauthorized access vulnerability via the /FrameSetCore.html endpoint in Electrolink 500W, 1kW, 2kW Medium DAB Transmitter Web v01.09, v01.08, v01.07, and Display v1.4, v1.2.

- [https://github.com/p0et08/Electrolink-FM-DAB-TV](https://github.com/p0et08/Electrolink-FM-DAB-TV) :  ![starts](https://img.shields.io/github/stars/p0et08/Electrolink-FM-DAB-TV.svg) ![forks](https://img.shields.io/github/forks/p0et08/Electrolink-FM-DAB-TV.svg)


## CVE-2025-50675
 GPMAW 14, a bioinformatics software, has a critical vulnerability related to insecure file permissions in its installation directory. The directory is accessible with full read, write, and execute permissions for all users, allowing unprivileged users to manipulate files within the directory, including executable files like GPMAW3.exe, Fragment.exe, and the uninstaller GPsetup64_17028.exe. An attacker with user-level access can exploit this misconfiguration by replacing or modifying the uninstaller (GPsetup64_17028.exe) with a malicious version. While the application itself runs in the user's context, the uninstaller is typically executed with administrative privileges when an administrator attempts to uninstall the software. By exploiting this flaw, an attacker could gain administrative privileges and execute arbitrary code in the context of the admin, resulting in privilege escalation.

- [https://github.com/LukeSec/CVE-2025-50675-GPMAW-Permissions](https://github.com/LukeSec/CVE-2025-50675-GPMAW-Permissions) :  ![starts](https://img.shields.io/github/stars/LukeSec/CVE-2025-50675-GPMAW-Permissions.svg) ![forks](https://img.shields.io/github/forks/LukeSec/CVE-2025-50675-GPMAW-Permissions.svg)


## CVE-2025-34152
 An unauthenticated OS command injection vulnerability exists in the Shenzhen Aitemi M300 Wi-Fi Repeater (hardware model MT02) via the 'time' parameter of the '/protocol.csp?' endpoint. The input is processed by the internal date '-s' command without rebooting or disrupting HTTP service. Unlike other injection points, this vector allows remote compromise without triggering visible configuration changes.

- [https://github.com/Chocapikk/CVE-2025-34152](https://github.com/Chocapikk/CVE-2025-34152) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2025-34152.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2025-34152.svg)


## CVE-2025-30406
 Gladinet CentreStack through 16.1.10296.56315 (fixed in 16.4.10315.56368) has a deserialization vulnerability due to the CentreStack portal's hardcoded machineKey use, as exploited in the wild in March 2025. This enables threat actors (who know the machineKey) to serialize a payload for server-side deserialization to achieve remote code execution. NOTE: a CentreStack admin can manually delete the machineKey defined in portal\web.config.

- [https://github.com/Gersonaze/CVE-2025-30406](https://github.com/Gersonaze/CVE-2025-30406) :  ![starts](https://img.shields.io/github/stars/Gersonaze/CVE-2025-30406.svg) ![forks](https://img.shields.io/github/forks/Gersonaze/CVE-2025-30406.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/rgvillanueva28/vulnbox-easy-CVE-2025-29927](https://github.com/rgvillanueva28/vulnbox-easy-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/rgvillanueva28/vulnbox-easy-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/rgvillanueva28/vulnbox-easy-CVE-2025-29927.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/mah4nzfr/CVE-2025-24893](https://github.com/mah4nzfr/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/mah4nzfr/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/mah4nzfr/CVE-2025-24893.svg)
- [https://github.com/Th3Gl0w/CVE-2025-24893-POC](https://github.com/Th3Gl0w/CVE-2025-24893-POC) :  ![starts](https://img.shields.io/github/stars/Th3Gl0w/CVE-2025-24893-POC.svg) ![forks](https://img.shields.io/github/forks/Th3Gl0w/CVE-2025-24893-POC.svg)
- [https://github.com/IIIeJlyXaKapToIIIKu/CVE-2025-24893-XWiki-unauthenticated-RCE-via-SolrSearch](https://github.com/IIIeJlyXaKapToIIIKu/CVE-2025-24893-XWiki-unauthenticated-RCE-via-SolrSearch) :  ![starts](https://img.shields.io/github/stars/IIIeJlyXaKapToIIIKu/CVE-2025-24893-XWiki-unauthenticated-RCE-via-SolrSearch.svg) ![forks](https://img.shields.io/github/forks/IIIeJlyXaKapToIIIKu/CVE-2025-24893-XWiki-unauthenticated-RCE-via-SolrSearch.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/Shivshantp/CVE-2025-24813](https://github.com/Shivshantp/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/Shivshantp/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/Shivshantp/CVE-2025-24813.svg)


## CVE-2025-7769
 Tigo Energy's CCA is vulnerable to a command injection vulnerability in the /cgi-bin/mobile_api endpoint when the DEVICE_PING command is called, allowing remote code execution due to improper handling of user input. When used with default credentials, this enables attackers to execute arbitrary commands on the device that could cause potential unauthorized access, service disruption, and data exposure.

- [https://github.com/byteReaper77/CVE-2025-7769](https://github.com/byteReaper77/CVE-2025-7769) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-7769.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-7769.svg)


## CVE-2025-5777
 Insufficient input validation leading to memory overread when the NetScaler is configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server

- [https://github.com/Shivshantp/CVE-2025-5777-TrendMicro-ApexCentral-RCE](https://github.com/Shivshantp/CVE-2025-5777-TrendMicro-ApexCentral-RCE) :  ![starts](https://img.shields.io/github/stars/Shivshantp/CVE-2025-5777-TrendMicro-ApexCentral-RCE.svg) ![forks](https://img.shields.io/github/forks/Shivshantp/CVE-2025-5777-TrendMicro-ApexCentral-RCE.svg)
- [https://github.com/soltanali0/CVE-2025-5777-Exploit](https://github.com/soltanali0/CVE-2025-5777-Exploit) :  ![starts](https://img.shields.io/github/stars/soltanali0/CVE-2025-5777-Exploit.svg) ![forks](https://img.shields.io/github/forks/soltanali0/CVE-2025-5777-Exploit.svg)


## CVE-2025-4126
 The EG-Series plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the plugin's [series] shortcode in all versions up to, and including, 2.1.1 due to insufficient input sanitization and output escaping on user supplied attributes in the shortcode_title function. This makes it possible for authenticated attackers - with contributor-level access and above, on sites with the Classic Editor plugin activated - to inject arbitrary JavaScript code in the titletag attribute that will execute whenever a user access an injected page.

- [https://github.com/Slow-Mist/CVE-2025-4126](https://github.com/Slow-Mist/CVE-2025-4126) :  ![starts](https://img.shields.io/github/stars/Slow-Mist/CVE-2025-4126.svg) ![forks](https://img.shields.io/github/forks/Slow-Mist/CVE-2025-4126.svg)


## CVE-2025-2825
 DO NOT USE THIS CVE RECORD. ConsultIDs: CVE-2025-31161. Reason: This Record is a reservation duplicate of CVE-2025-31161. Notes: All CVE users should reference CVE-2025-31161 instead of this Record. All references and descriptions in this Record have been removed to prevent accidental usage.

- [https://github.com/Shivshantp/CVE-2025-2825-CrushFTP-AuthBypass](https://github.com/Shivshantp/CVE-2025-2825-CrushFTP-AuthBypass) :  ![starts](https://img.shields.io/github/stars/Shivshantp/CVE-2025-2825-CrushFTP-AuthBypass.svg) ![forks](https://img.shields.io/github/forks/Shivshantp/CVE-2025-2825-CrushFTP-AuthBypass.svg)


## CVE-2020-5248
 GLPI before before version 9.4.6 has a vulnerability involving a default encryption key. GLPIKEY is public and is used on every instance. This means anyone can decrypt sensitive data stored using this key. It is possible to change the key before installing GLPI. But on existing instances, data must be reencrypted with the new key. Problem is we can not know which columns or rows in the database are using that; espcially from plugins. Changing the key without updating data would lend in bad password sent from glpi; but storing them again from the UI will work.

- [https://github.com/venomnis/CVE-2020-5248](https://github.com/venomnis/CVE-2020-5248) :  ![starts](https://img.shields.io/github/stars/venomnis/CVE-2020-5248.svg) ![forks](https://img.shields.io/github/forks/venomnis/CVE-2020-5248.svg)


## CVE-2019-18935
 Progress Telerik UI for ASP.NET AJAX through 2019.3.1023 contains a .NET deserialization vulnerability in the RadAsyncUpload function. This is exploitable when the encryption keys are known due to the presence of CVE-2017-11317 or CVE-2017-11357, or other means. Exploitation can result in remote code execution. (As of 2020.1.114, a default setting prevents the exploit. In 2019.3.1023, but not earlier versions, a non-default setting can prevent exploitation.)

- [https://github.com/ekkoo-z/CVE-2019-18935-bypasswaf](https://github.com/ekkoo-z/CVE-2019-18935-bypasswaf) :  ![starts](https://img.shields.io/github/stars/ekkoo-z/CVE-2019-18935-bypasswaf.svg) ![forks](https://img.shields.io/github/forks/ekkoo-z/CVE-2019-18935-bypasswaf.svg)


## CVE-2017-12611
 In Apache Struts 2.0.0 through 2.3.33 and 2.5 through 2.5.10.1, using an unintentional expression in a Freemarker tag instead of string literals can lead to a RCE attack.

- [https://github.com/brianwrf/S2-053-CVE-2017-12611](https://github.com/brianwrf/S2-053-CVE-2017-12611) :  ![starts](https://img.shields.io/github/stars/brianwrf/S2-053-CVE-2017-12611.svg) ![forks](https://img.shields.io/github/forks/brianwrf/S2-053-CVE-2017-12611.svg)


## CVE-2017-9841
 Util/PHP/eval-stdin.php in PHPUnit before 4.8.28 and 5.x before 5.6.3 allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a "?php " substring, as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.

- [https://github.com/joelindra/Argus](https://github.com/joelindra/Argus) :  ![starts](https://img.shields.io/github/stars/joelindra/Argus.svg) ![forks](https://img.shields.io/github/forks/joelindra/Argus.svg)


## CVE-2011-3192
 The byterange filter in the Apache HTTP Server 1.3.x, 2.0.x through 2.0.64, and 2.2.x through 2.2.19 allows remote attackers to cause a denial of service (memory and CPU consumption) via a Range header that expresses multiple overlapping ranges, as exploited in the wild in August 2011, a different vulnerability than CVE-2007-0086.

- [https://github.com/Xinjis/Apache_ByteRange_DoS_cve_2011_3192](https://github.com/Xinjis/Apache_ByteRange_DoS_cve_2011_3192) :  ![starts](https://img.shields.io/github/stars/Xinjis/Apache_ByteRange_DoS_cve_2011_3192.svg) ![forks](https://img.shields.io/github/forks/Xinjis/Apache_ByteRange_DoS_cve_2011_3192.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/As9xm/BrokenDoor-CVE-2011-2523-](https://github.com/As9xm/BrokenDoor-CVE-2011-2523-) :  ![starts](https://img.shields.io/github/stars/As9xm/BrokenDoor-CVE-2011-2523-.svg) ![forks](https://img.shields.io/github/forks/As9xm/BrokenDoor-CVE-2011-2523-.svg)

