# Update 2023-03-05
## CVE-2023-26604
 systemd before 247 does not adequately block local privilege escalation for some Sudo configurations, e.g., plausible sudoers files in which the &quot;systemctl status&quot; command may be executed. Specifically, systemd does not set LESSSECURE to 1, and thus other programs may be launched from the less program. This presents a substantial security risk when running systemctl from Sudo, because less executes as root when the terminal size is too small to show the complete systemctl output.

- [https://github.com/Zenmovie/CVE-2023-26604](https://github.com/Zenmovie/CVE-2023-26604) :  ![starts](https://img.shields.io/github/stars/Zenmovie/CVE-2023-26604.svg) ![forks](https://img.shields.io/github/forks/Zenmovie/CVE-2023-26604.svg)


## CVE-2023-20921
 In onPackageRemoved of AccessibilityManagerService.java, there is a possibility to automatically grant accessibility services due to a logic error in the code. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12L Android-13Android ID: A-243378132

- [https://github.com/nidhi7598/frameworks_base_AOSP_10_r33_CVE-2023-20921](https://github.com/nidhi7598/frameworks_base_AOSP_10_r33_CVE-2023-20921) :  ![starts](https://img.shields.io/github/stars/nidhi7598/frameworks_base_AOSP_10_r33_CVE-2023-20921.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/frameworks_base_AOSP_10_r33_CVE-2023-20921.svg)


## CVE-2023-0050
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/wh-gov/CVE-2023-0050](https://github.com/wh-gov/CVE-2023-0050) :  ![starts](https://img.shields.io/github/stars/wh-gov/CVE-2023-0050.svg) ![forks](https://img.shields.io/github/forks/wh-gov/CVE-2023-0050.svg)


## CVE-2022-39838
 Systematic FIX Adapter (ALFAFX) 2.4.0.25 13/09/2017 allows remote file inclusion via a UNC share pathname, and also allows absolute path traversal to local pathnames.

- [https://github.com/jet-pentest/CVE-2022-39838](https://github.com/jet-pentest/CVE-2022-39838) :  ![starts](https://img.shields.io/github/stars/jet-pentest/CVE-2022-39838.svg) ![forks](https://img.shields.io/github/forks/jet-pentest/CVE-2022-39838.svg)


## CVE-2022-38374
 A improper neutralization of input during web page generation ('cross-site scripting') in Fortinet FortiADC 7.0.0 - 7.0.2 and 6.2.0 - 6.2.4 allows an attacker to execute unauthorized code or commands via the URL and User fields observed in the traffic and event logviews.

- [https://github.com/M4fiaB0y/CVE-2022-38374](https://github.com/M4fiaB0y/CVE-2022-38374) :  ![starts](https://img.shields.io/github/stars/M4fiaB0y/CVE-2022-38374.svg) ![forks](https://img.shields.io/github/forks/M4fiaB0y/CVE-2022-38374.svg)


## CVE-2022-37210
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/AgainstTheLight/CVE-2022-37210](https://github.com/AgainstTheLight/CVE-2022-37210) :  ![starts](https://img.shields.io/github/stars/AgainstTheLight/CVE-2022-37210.svg) ![forks](https://img.shields.io/github/forks/AgainstTheLight/CVE-2022-37210.svg)


## CVE-2022-37209
 JFinal CMS 5.1.0 is affected by: SQL Injection. These interfaces do not use the same component, nor do they have filters, but each uses its own SQL concatenation method, resulting in SQL injection.

- [https://github.com/AgainstTheLight/CVE-2022-37209](https://github.com/AgainstTheLight/CVE-2022-37209) :  ![starts](https://img.shields.io/github/stars/AgainstTheLight/CVE-2022-37209.svg) ![forks](https://img.shields.io/github/forks/AgainstTheLight/CVE-2022-37209.svg)


## CVE-2022-36804
 Multiple API endpoints in Atlassian Bitbucket Server and Data Center 7.0.0 before version 7.6.17, from version 7.7.0 before version 7.17.10, from version 7.18.0 before version 7.21.4, from version 8.0.0 before version 8.0.3, from version 8.1.0 before version 8.1.3, and from version 8.2.0 before version 8.2.2, and from version 8.3.0 before 8.3.1 allows remote attackers with read permissions to a public or private Bitbucket repository to execute arbitrary code by sending a malicious HTTP request. This vulnerability was reported via our Bug Bounty Program by TheGrandPew.

- [https://github.com/JRandomSage/CVE-2022-36804-MASS-RCE](https://github.com/JRandomSage/CVE-2022-36804-MASS-RCE) :  ![starts](https://img.shields.io/github/stars/JRandomSage/CVE-2022-36804-MASS-RCE.svg) ![forks](https://img.shields.io/github/forks/JRandomSage/CVE-2022-36804-MASS-RCE.svg)


## CVE-2022-36539
 WeDayCare B.V Ouderapp before v1.1.22 allows attackers to alter the ID value within intercepted calls to gain access to data of other parents and children.

- [https://github.com/Fopje/CVE-2022-36539](https://github.com/Fopje/CVE-2022-36539) :  ![starts](https://img.shields.io/github/stars/Fopje/CVE-2022-36539.svg) ![forks](https://img.shields.io/github/forks/Fopje/CVE-2022-36539.svg)


## CVE-2022-30524
 There is an invalid memory access in the TextLine class in TextOutputDev.cc in Xpdf 4.0.4 because the text extractor mishandles characters at large y coordinates. It can be triggered by (for example) sending a crafted pdf file to the pdftotext binary, which allows a remote attacker to cause a Denial of Service (Segmentation fault) or possibly have unspecified other impact.

- [https://github.com/rishvic/xpdf-docker](https://github.com/rishvic/xpdf-docker) :  ![starts](https://img.shields.io/github/stars/rishvic/xpdf-docker.svg) ![forks](https://img.shields.io/github/forks/rishvic/xpdf-docker.svg)


## CVE-2022-29464
 Certain WSO2 products allow unrestricted file upload with resultant remote code execution. The attacker must use a /fileupload endpoint with a Content-Disposition directory traversal sequence to reach a directory under the web root, such as a ../../../../repository/deployment/server/webapps directory. This affects WSO2 API Manager 2.2.0 and above through 4.0.0; WSO2 Identity Server 5.2.0 and above through 5.11.0; WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0, and 5.6.0; WSO2 Identity Server as Key Manager 5.3.0 and above through 5.10.0; and WSO2 Enterprise Integrator 6.2.0 and above through 6.6.0.

- [https://github.com/superzerosec/CVE-2022-29464](https://github.com/superzerosec/CVE-2022-29464) :  ![starts](https://img.shields.io/github/stars/superzerosec/CVE-2022-29464.svg) ![forks](https://img.shields.io/github/forks/superzerosec/CVE-2022-29464.svg)
- [https://github.com/axin2019/CVE-2022-29464](https://github.com/axin2019/CVE-2022-29464) :  ![starts](https://img.shields.io/github/stars/axin2019/CVE-2022-29464.svg) ![forks](https://img.shields.io/github/forks/axin2019/CVE-2022-29464.svg)


## CVE-2022-28508
 An XSS issue was discovered in browser_search_plugin.php in MantisBT before 2.25.2. Unescaped output of the return parameter allows an attacker to inject code into a hidden input field.

- [https://github.com/YavuzSahbaz/CVE-2022-28508](https://github.com/YavuzSahbaz/CVE-2022-28508) :  ![starts](https://img.shields.io/github/stars/YavuzSahbaz/CVE-2022-28508.svg) ![forks](https://img.shields.io/github/forks/YavuzSahbaz/CVE-2022-28508.svg)


## CVE-2022-28099
 Poultry Farm Management System v1.0 was discovered to contain a SQL injection vulnerability via the Item parameter at /farm/store.php.

- [https://github.com/IbrahimEkimIsik/CVE-2022-28099](https://github.com/IbrahimEkimIsik/CVE-2022-28099) :  ![starts](https://img.shields.io/github/stars/IbrahimEkimIsik/CVE-2022-28099.svg) ![forks](https://img.shields.io/github/forks/IbrahimEkimIsik/CVE-2022-28099.svg)


## CVE-2022-25236
 xmlparse.c in Expat (aka libexpat) before 2.4.5 allows attackers to insert namespace-separator characters into namespace URIs.

- [https://github.com/Satheesh575555/external_expat_AOSP10_r33_CVE-2022-25236](https://github.com/Satheesh575555/external_expat_AOSP10_r33_CVE-2022-25236) :  ![starts](https://img.shields.io/github/stars/Satheesh575555/external_expat_AOSP10_r33_CVE-2022-25236.svg) ![forks](https://img.shields.io/github/forks/Satheesh575555/external_expat_AOSP10_r33_CVE-2022-25236.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/helsecert/CVE-2022-22965](https://github.com/helsecert/CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/helsecert/CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/helsecert/CVE-2022-22965.svg)
- [https://github.com/Enokiy/spring-RCE-CVE-2022-22965](https://github.com/Enokiy/spring-RCE-CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/Enokiy/spring-RCE-CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/Enokiy/spring-RCE-CVE-2022-22965.svg)


## CVE-2022-22954
 VMware Workspace ONE Access and Identity Manager contain a remote code execution vulnerability due to server-side template injection. A malicious actor with network access can trigger a server-side template injection that may result in remote code execution.

- [https://github.com/nguyenv1nK/CVE-2022-22954](https://github.com/nguyenv1nK/CVE-2022-22954) :  ![starts](https://img.shields.io/github/stars/nguyenv1nK/CVE-2022-22954.svg) ![forks](https://img.shields.io/github/forks/nguyenv1nK/CVE-2022-22954.svg)


## CVE-2022-21984
 Windows DNS Server Remote Code Execution Vulnerability.

- [https://github.com/u201424348/CVE-2022-21984](https://github.com/u201424348/CVE-2022-21984) :  ![starts](https://img.shields.io/github/stars/u201424348/CVE-2022-21984.svg) ![forks](https://img.shields.io/github/forks/u201424348/CVE-2022-21984.svg)


## CVE-2022-21587
 Vulnerability in the Oracle Web Applications Desktop Integrator product of Oracle E-Business Suite (component: Upload). Supported versions that are affected are 12.2.3-12.2.11. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Web Applications Desktop Integrator. Successful attacks of this vulnerability can result in takeover of Oracle Web Applications Desktop Integrator. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/sahabrifki/CVE-2022-21587-Oracle-EBS-](https://github.com/sahabrifki/CVE-2022-21587-Oracle-EBS-) :  ![starts](https://img.shields.io/github/stars/sahabrifki/CVE-2022-21587-Oracle-EBS-.svg) ![forks](https://img.shields.io/github/forks/sahabrifki/CVE-2022-21587-Oracle-EBS-.svg)


## CVE-2022-21449
 Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Libraries). Supported versions that are affected are Oracle Java SE: 17.0.2 and 18; Oracle GraalVM Enterprise Edition: 21.3.1 and 22.0.0.2. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification access to critical data or all Oracle Java SE, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. CVSS 3.1 Base Score 7.5 (Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N).

- [https://github.com/thack1/CVE-2022-21449](https://github.com/thack1/CVE-2022-21449) :  ![starts](https://img.shields.io/github/stars/thack1/CVE-2022-21449.svg) ![forks](https://img.shields.io/github/forks/thack1/CVE-2022-21449.svg)


## CVE-2022-20699
 Multiple vulnerabilities in Cisco Small Business RV160, RV260, RV340, and RV345 Series Routers could allow an attacker to do any of the following: Execute arbitrary code Elevate privileges Execute arbitrary commands Bypass authentication and authorization protections Fetch and run unsigned software Cause denial of service (DoS) For more information about these vulnerabilities, see the Details section of this advisory.

- [https://github.com/puckiestyle/CVE-2022-20699](https://github.com/puckiestyle/CVE-2022-20699) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2022-20699.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2022-20699.svg)


## CVE-2022-20494
 In AutomaticZenRule of AutomaticZenRule.java, there is a possible persistent DoS due to resource exhaustion. This could lead to local denial of service with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12L Android-13Android ID: A-243794204

- [https://github.com/Supersonic/CVE-2022-20494](https://github.com/Supersonic/CVE-2022-20494) :  ![starts](https://img.shields.io/github/stars/Supersonic/CVE-2022-20494.svg) ![forks](https://img.shields.io/github/forks/Supersonic/CVE-2022-20494.svg)


## CVE-2022-20473
 In toLanguageTag of LocaleListCache.cpp, there is a possible out of bounds read due to an incorrect bounds check. This could lead to remote code execution with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12L Android-13Android ID: A-239267173

- [https://github.com/Trinadh465/frameworks_minikin_AOSP10_r33_CVE-2022-20473](https://github.com/Trinadh465/frameworks_minikin_AOSP10_r33_CVE-2022-20473) :  ![starts](https://img.shields.io/github/stars/Trinadh465/frameworks_minikin_AOSP10_r33_CVE-2022-20473.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/frameworks_minikin_AOSP10_r33_CVE-2022-20473.svg)


## CVE-2022-20361
 In btif_dm_auth_cmpl_evt of btif_dm.cc, there is a possible vulnerability in Cross-Transport Key Derivation due to Weakness in Bluetooth Standard. This could lead to remote escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-231161832

- [https://github.com/nidhi7598/system_bt_AOSP_10_r33_CVE-2022-20361](https://github.com/nidhi7598/system_bt_AOSP_10_r33_CVE-2022-20361) :  ![starts](https://img.shields.io/github/stars/nidhi7598/system_bt_AOSP_10_r33_CVE-2022-20361.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/system_bt_AOSP_10_r33_CVE-2022-20361.svg)


## CVE-2022-20347
 In onAttach of ConnectedDeviceDashboardFragment.java, there is a possible permission bypass due to a confused deputy. This could lead to remote escalation of privilege in Bluetooth settings with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-228450811

- [https://github.com/Trinadh465/packages_apps_Settings_AOSP10_r33_CVE-2022-20347](https://github.com/Trinadh465/packages_apps_Settings_AOSP10_r33_CVE-2022-20347) :  ![starts](https://img.shields.io/github/stars/Trinadh465/packages_apps_Settings_AOSP10_r33_CVE-2022-20347.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/packages_apps_Settings_AOSP10_r33_CVE-2022-20347.svg)


## CVE-2022-20344
 In stealReceiveChannel of EventThread.cpp, there is a possible way to interfere with process communication due to a race condition. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-232541124

- [https://github.com/nidhi7598/frameworks_native_AOSP_10_r33_CVE-2022-20344](https://github.com/nidhi7598/frameworks_native_AOSP_10_r33_CVE-2022-20344) :  ![starts](https://img.shields.io/github/stars/nidhi7598/frameworks_native_AOSP_10_r33_CVE-2022-20344.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/frameworks_native_AOSP_10_r33_CVE-2022-20344.svg)


## CVE-2022-1388
 On F5 BIG-IP 16.1.x versions prior to 16.1.2.2, 15.1.x versions prior to 15.1.5.1, 14.1.x versions prior to 14.1.4.6, 13.1.x versions prior to 13.1.5, and all 12.1.x and 11.6.x versions, undisclosed requests may bypass iControl REST authentication. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

- [https://github.com/Osyanina/westone-CVE-2022-1388-scanner](https://github.com/Osyanina/westone-CVE-2022-1388-scanner) :  ![starts](https://img.shields.io/github/stars/Osyanina/westone-CVE-2022-1388-scanner.svg) ![forks](https://img.shields.io/github/forks/Osyanina/westone-CVE-2022-1388-scanner.svg)


## CVE-2021-45105
 Apache Log4j2 versions 2.0-alpha1 through 2.16.0 (excluding 2.12.3 and 2.3.1) did not protect from uncontrolled recursion from self-referential lookups. This allows an attacker with control over Thread Context Map data to cause a denial of service when a crafted string is interpreted. This issue was fixed in Log4j 2.17.0, 2.12.3, and 2.3.1.

- [https://github.com/pravin-pp/log4j2-CVE-2021-45105](https://github.com/pravin-pp/log4j2-CVE-2021-45105) :  ![starts](https://img.shields.io/github/stars/pravin-pp/log4j2-CVE-2021-45105.svg) ![forks](https://img.shields.io/github/forks/pravin-pp/log4j2-CVE-2021-45105.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/corelight/cve-2021-44228](https://github.com/corelight/cve-2021-44228) :  ![starts](https://img.shields.io/github/stars/corelight/cve-2021-44228.svg) ![forks](https://img.shields.io/github/forks/corelight/cve-2021-44228.svg)
- [https://github.com/roxas-tan/CVE-2021-44228](https://github.com/roxas-tan/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/roxas-tan/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/roxas-tan/CVE-2021-44228.svg)


## CVE-2021-44077
 Zoho ManageEngine ServiceDesk Plus before 11306, ServiceDesk Plus MSP before 10530, and SupportCenter Plus before 11014 are vulnerable to unauthenticated remote code execution. This is related to /RestAPI URLs in a servlet, and ImportTechnicians in the Struts configuration.

- [https://github.com/pizza-power/Golang-CVE-2021-44077-POC](https://github.com/pizza-power/Golang-CVE-2021-44077-POC) :  ![starts](https://img.shields.io/github/stars/pizza-power/Golang-CVE-2021-44077-POC.svg) ![forks](https://img.shields.io/github/forks/pizza-power/Golang-CVE-2021-44077-POC.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/anldori/CVE-2021-41773-Scanner](https://github.com/anldori/CVE-2021-41773-Scanner) :  ![starts](https://img.shields.io/github/stars/anldori/CVE-2021-41773-Scanner.svg) ![forks](https://img.shields.io/github/forks/anldori/CVE-2021-41773-Scanner.svg)


## CVE-2021-41078
 Nameko through 2.13.0 can be tricked into performing arbitrary code execution when deserializing the config file.

- [https://github.com/s-index/CVE-2021-41078](https://github.com/s-index/CVE-2021-41078) :  ![starts](https://img.shields.io/github/stars/s-index/CVE-2021-41078.svg) ![forks](https://img.shields.io/github/forks/s-index/CVE-2021-41078.svg)


## CVE-2021-40444
 Microsoft MSHTML Remote Code Execution Vulnerability

- [https://github.com/k8gege/CVE-2021-40444](https://github.com/k8gege/CVE-2021-40444) :  ![starts](https://img.shields.io/github/stars/k8gege/CVE-2021-40444.svg) ![forks](https://img.shields.io/github/forks/k8gege/CVE-2021-40444.svg)
- [https://github.com/LazarusReborn/Docx-Exploit-2021](https://github.com/LazarusReborn/Docx-Exploit-2021) :  ![starts](https://img.shields.io/github/stars/LazarusReborn/Docx-Exploit-2021.svg) ![forks](https://img.shields.io/github/forks/LazarusReborn/Docx-Exploit-2021.svg)
- [https://github.com/khoaduynu/CVE-2021-40444](https://github.com/khoaduynu/CVE-2021-40444) :  ![starts](https://img.shields.io/github/stars/khoaduynu/CVE-2021-40444.svg) ![forks](https://img.shields.io/github/forks/khoaduynu/CVE-2021-40444.svg)
- [https://github.com/factionsypho/TIC4301_Project](https://github.com/factionsypho/TIC4301_Project) :  ![starts](https://img.shields.io/github/stars/factionsypho/TIC4301_Project.svg) ![forks](https://img.shields.io/github/forks/factionsypho/TIC4301_Project.svg)


## CVE-2021-38666
 Remote Desktop Client Remote Code Execution Vulnerability

- [https://github.com/DarkSprings/CVE-2021-38666-poc](https://github.com/DarkSprings/CVE-2021-38666-poc) :  ![starts](https://img.shields.io/github/stars/DarkSprings/CVE-2021-38666-poc.svg) ![forks](https://img.shields.io/github/forks/DarkSprings/CVE-2021-38666-poc.svg)


## CVE-2021-36981
 In the server in SerNet verinice before 1.22.2, insecure Java deserialization allows remote authenticated attackers to execute arbitrary code.

- [https://github.com/0xBrAinsTorM/CVE-2021-36981](https://github.com/0xBrAinsTorM/CVE-2021-36981) :  ![starts](https://img.shields.io/github/stars/0xBrAinsTorM/CVE-2021-36981.svg) ![forks](https://img.shields.io/github/forks/0xBrAinsTorM/CVE-2021-36981.svg)


## CVE-2021-36934
 Windows Elevation of Privilege Vulnerability

- [https://github.com/chron1k/oxide_hive](https://github.com/chron1k/oxide_hive) :  ![starts](https://img.shields.io/github/stars/chron1k/oxide_hive.svg) ![forks](https://img.shields.io/github/forks/chron1k/oxide_hive.svg)


## CVE-2021-23841
 The OpenSSL public API function X509_issuer_and_serial_hash() attempts to create a unique hash value based on the issuer and serial number data contained within an X509 certificate. However it fails to correctly handle any errors that may occur while parsing the issuer field (which might occur if the issuer field is maliciously constructed). This may subsequently result in a NULL pointer deref and a crash leading to a potential denial of service attack. The function X509_issuer_and_serial_hash() is never directly called by OpenSSL itself so applications are only vulnerable if they use this function directly and they use it on certificates that may have been obtained from untrusted sources. OpenSSL versions 1.1.1i and below are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1j. OpenSSL versions 1.0.2x and below are affected by this issue. However OpenSSL 1.0.2 is out of support and no longer receiving public updates. Premium support customers of OpenSSL 1.0.2 should upgrade to 1.0.2y. Other users should upgrade to 1.1.1j. Fixed in OpenSSL 1.1.1j (Affected 1.1.1-1.1.1i). Fixed in OpenSSL 1.0.2y (Affected 1.0.2-1.0.2x).

- [https://github.com/Trinadh465/external_boringssl_openssl_1.1.0g_CVE-2021-23841](https://github.com/Trinadh465/external_boringssl_openssl_1.1.0g_CVE-2021-23841) :  ![starts](https://img.shields.io/github/stars/Trinadh465/external_boringssl_openssl_1.1.0g_CVE-2021-23841.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/external_boringssl_openssl_1.1.0g_CVE-2021-23841.svg)


## CVE-2021-22924
 libcurl keeps previously used connections in a connection pool for subsequenttransfers to reuse, if one of them matches the setup.Due to errors in the logic, the config matching function did not take 'issuercert' into account and it compared the involved paths *case insensitively*,which could lead to libcurl reusing wrong connections.File paths are, or can be, case sensitive on many systems but not all, and caneven vary depending on used file systems.The comparison also didn't include the 'issuer cert' which a transfer can setto qualify how to verify the server certificate.

- [https://github.com/Trinadh465/external_curl_AOSP10_r33_CVE-2021-22924](https://github.com/Trinadh465/external_curl_AOSP10_r33_CVE-2021-22924) :  ![starts](https://img.shields.io/github/stars/Trinadh465/external_curl_AOSP10_r33_CVE-2021-22924.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/external_curl_AOSP10_r33_CVE-2021-22924.svg)


## CVE-2021-21980
 The vSphere Web Client (FLEX/Flash) contains an unauthorized arbitrary file read vulnerability. A malicious actor with network access to port 443 on vCenter Server may exploit this issue to gain access to sensitive information.

- [https://github.com/Osyanina/westone-CVE-2022-1388-scanner](https://github.com/Osyanina/westone-CVE-2022-1388-scanner) :  ![starts](https://img.shields.io/github/stars/Osyanina/westone-CVE-2022-1388-scanner.svg) ![forks](https://img.shields.io/github/forks/Osyanina/westone-CVE-2022-1388-scanner.svg)


## CVE-2021-21234
 spring-boot-actuator-logview in a library that adds a simple logfile viewer as spring boot actuator endpoint. It is maven package &quot;eu.hinsch:spring-boot-actuator-logview&quot;. In spring-boot-actuator-logview before version 0.2.13 there is a directory traversal vulnerability. The nature of this library is to expose a log file directory via admin (spring boot actuator) HTTP endpoints. Both the filename to view and a base folder (relative to the logging folder root) can be specified via request parameters. While the filename parameter was checked to prevent directory traversal exploits (so that `filename=../somefile` would not work), the base folder parameter was not sufficiently checked, so that `filename=somefile&amp;base=../` could access a file outside the logging base directory). The vulnerability has been patched in release 0.2.13. Any users of 0.2.12 should be able to update without any issues as there are no other changes in that release. There is no workaround to fix the vulnerability other than updating or removing the dependency. However, removing read access of the user the application is run with to any directory not required for running the application can limit the impact. Additionally, access to the logview endpoint can be limited by deploying the application behind a reverse proxy.

- [https://github.com/xiaojiangxl/CVE-2021-21234](https://github.com/xiaojiangxl/CVE-2021-21234) :  ![starts](https://img.shields.io/github/stars/xiaojiangxl/CVE-2021-21234.svg) ![forks](https://img.shields.io/github/forks/xiaojiangxl/CVE-2021-21234.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/defhacks/cve-2021-4034](https://github.com/defhacks/cve-2021-4034) :  ![starts](https://img.shields.io/github/stars/defhacks/cve-2021-4034.svg) ![forks](https://img.shields.io/github/forks/defhacks/cve-2021-4034.svg)
- [https://github.com/hahaleyile/CVE-2021-4034](https://github.com/hahaleyile/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/hahaleyile/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/hahaleyile/CVE-2021-4034.svg)
- [https://github.com/jcatala/f_poc_cve-2021-4034](https://github.com/jcatala/f_poc_cve-2021-4034) :  ![starts](https://img.shields.io/github/stars/jcatala/f_poc_cve-2021-4034.svg) ![forks](https://img.shields.io/github/forks/jcatala/f_poc_cve-2021-4034.svg)
- [https://github.com/hohn/codeql-sample-polkit](https://github.com/hohn/codeql-sample-polkit) :  ![starts](https://img.shields.io/github/stars/hohn/codeql-sample-polkit.svg) ![forks](https://img.shields.io/github/forks/hohn/codeql-sample-polkit.svg)


## CVE-2021-3493
 The overlayfs implementation in the linux kernel did not properly validate with respect to user namespaces the setting of file capabilities on files in an underlying file system. Due to the combination of unprivileged user namespaces along with a patch carried in the Ubuntu kernel to allow unprivileged overlay mounts, an attacker could use this to gain elevated privileges.

- [https://github.com/Senz4wa/CVE-2021-3493](https://github.com/Senz4wa/CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/Senz4wa/CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/Senz4wa/CVE-2021-3493.svg)


## CVE-2021-1636
 Microsoft SQL Elevation of Privilege Vulnerability

- [https://github.com/Nate0634034090/bug-free-memory](https://github.com/Nate0634034090/bug-free-memory) :  ![starts](https://img.shields.io/github/stars/Nate0634034090/bug-free-memory.svg) ![forks](https://img.shields.io/github/forks/Nate0634034090/bug-free-memory.svg)


## CVE-2021-0963
 In onCreate of KeyChainActivity.java, there is a possible way to use an app certificate stored in keychain due to a tapjacking/overlay attack. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-9Android ID: A-199754277

- [https://github.com/Trinadh465/packages_apps_KeyChain_AOSP10_r33_CVE-2021-0963](https://github.com/Trinadh465/packages_apps_KeyChain_AOSP10_r33_CVE-2021-0963) :  ![starts](https://img.shields.io/github/stars/Trinadh465/packages_apps_KeyChain_AOSP10_r33_CVE-2021-0963.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/packages_apps_KeyChain_AOSP10_r33_CVE-2021-0963.svg)


## CVE-2021-0511
 In Dex2oat of dex2oat.cc, there is a possible way to inject bytecode into an app due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-9 Android-10 Android-11Android ID: A-178055795

- [https://github.com/Trinadh465/platform_art_AOSP10_r33_CVE-2021-0511](https://github.com/Trinadh465/platform_art_AOSP10_r33_CVE-2021-0511) :  ![starts](https://img.shields.io/github/stars/Trinadh465/platform_art_AOSP10_r33_CVE-2021-0511.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/platform_art_AOSP10_r33_CVE-2021-0511.svg)


## CVE-2021-0326
 In p2p_copy_client_info of p2p.c, there is a possible out of bounds write due to a missing bounds check. This could lead to remote code execution if the target device is performing a Wi-Fi Direct search, with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-8.1 Android-9Android ID: A-172937525

- [https://github.com/ShaikUsaf/external_wpa_supplicant_8_AOSP10_r33CVE-2021-0326](https://github.com/ShaikUsaf/external_wpa_supplicant_8_AOSP10_r33CVE-2021-0326) :  ![starts](https://img.shields.io/github/stars/ShaikUsaf/external_wpa_supplicant_8_AOSP10_r33CVE-2021-0326.svg) ![forks](https://img.shields.io/github/forks/ShaikUsaf/external_wpa_supplicant_8_AOSP10_r33CVE-2021-0326.svg)


## CVE-2020-26527
 An issue was discovered in API/api/Version in Damstra Smart Asset 2020.7. Cross-origin resource sharing trusts random origins by accepting the arbitrary 'Origin: example.com' header and responding with 200 OK and a wildcard 'Access-Control-Allow-Origin: *' header.

- [https://github.com/lukaszstu/SmartAsset-CORS-CVE-2020-26527](https://github.com/lukaszstu/SmartAsset-CORS-CVE-2020-26527) :  ![starts](https://img.shields.io/github/stars/lukaszstu/SmartAsset-CORS-CVE-2020-26527.svg) ![forks](https://img.shields.io/github/forks/lukaszstu/SmartAsset-CORS-CVE-2020-26527.svg)


## CVE-2020-26526
 An issue was discovered in Damstra Smart Asset 2020.7. It is possible to enumerate valid usernames on the login page. The application sends a different server response when the username is invalid than when the username is valid (&quot;Unable to find an APIDomain&quot; versus &quot;Wrong email or password&quot;).

- [https://github.com/lukaszstu/SmartAsset-UE-CVE-2020-26526](https://github.com/lukaszstu/SmartAsset-UE-CVE-2020-26526) :  ![starts](https://img.shields.io/github/stars/lukaszstu/SmartAsset-UE-CVE-2020-26526.svg) ![forks](https://img.shields.io/github/forks/lukaszstu/SmartAsset-UE-CVE-2020-26526.svg)


## CVE-2020-26525
 Damstra Smart Asset 2020.7 has SQL injection via the API/api/Asset originator parameter. This allows forcing the database and server to initiate remote connections to third party DNS servers.

- [https://github.com/lukaszstu/SmartAsset-SQLinj-CVE-2020-26525](https://github.com/lukaszstu/SmartAsset-SQLinj-CVE-2020-26525) :  ![starts](https://img.shields.io/github/stars/lukaszstu/SmartAsset-SQLinj-CVE-2020-26525.svg) ![forks](https://img.shields.io/github/forks/lukaszstu/SmartAsset-SQLinj-CVE-2020-26525.svg)


## CVE-2020-26217
 XStream before version 1.4.14 is vulnerable to Remote Code Execution.The vulnerability may allow a remote attacker to run arbitrary shell commands only by manipulating the processed input stream. Only users who rely on blocklists are affected. Anyone using XStream's Security Framework allowlist is not affected. The linked advisory provides code workarounds for users who cannot upgrade. The issue is fixed in version 1.4.14.

- [https://github.com/novysodope/CVE-2020-26217-XStream-RCE-POC](https://github.com/novysodope/CVE-2020-26217-XStream-RCE-POC) :  ![starts](https://img.shields.io/github/stars/novysodope/CVE-2020-26217-XStream-RCE-POC.svg) ![forks](https://img.shields.io/github/forks/novysodope/CVE-2020-26217-XStream-RCE-POC.svg)


## CVE-2019-11043
 In PHP versions 7.1.x below 7.1.33, 7.2.x below 7.2.24 and 7.3.x below 7.3.11 in certain configurations of FPM setup it is possible to cause FPM module to write past allocated buffers into the space reserved for FCGI protocol data, thus opening the possibility of remote code execution.

- [https://github.com/B1gd0g/CVE-2019-11043](https://github.com/B1gd0g/CVE-2019-11043) :  ![starts](https://img.shields.io/github/stars/B1gd0g/CVE-2019-11043.svg) ![forks](https://img.shields.io/github/forks/B1gd0g/CVE-2019-11043.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/STERN3L/CVE-2019-9053](https://github.com/STERN3L/CVE-2019-9053) :  ![starts](https://img.shields.io/github/stars/STERN3L/CVE-2019-9053.svg) ![forks](https://img.shields.io/github/forks/STERN3L/CVE-2019-9053.svg)


## CVE-2019-2725
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Web Services). Supported versions that are affected are 10.3.6.0.0 and 12.1.3.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/lasensio/cve-2019-2725](https://github.com/lasensio/cve-2019-2725) :  ![starts](https://img.shields.io/github/stars/lasensio/cve-2019-2725.svg) ![forks](https://img.shields.io/github/forks/lasensio/cve-2019-2725.svg)


## CVE-2019-1253
 An elevation of privilege vulnerability exists when the Windows AppX Deployment Server improperly handles junctions.To exploit this vulnerability, an attacker would first have to gain execution on the victim system, aka 'Windows Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-1215, CVE-2019-1278, CVE-2019-1303.

- [https://github.com/rogue-kdc/CVE-2019-1253](https://github.com/rogue-kdc/CVE-2019-1253) :  ![starts](https://img.shields.io/github/stars/rogue-kdc/CVE-2019-1253.svg) ![forks](https://img.shields.io/github/forks/rogue-kdc/CVE-2019-1253.svg)

