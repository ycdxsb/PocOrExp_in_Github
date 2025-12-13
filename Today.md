# Update 2025-12-13
## CVE-2025-66628
 ImageMagick is a software suite to create, edit, compose, or convert bitmap images. In versions 7.1.2-9 and prior, the TIM (PSX TIM) image parser contains a critical integer overflow vulnerability in its ReadTIMImage function (coders/tim.c). The code reads width and height (16-bit values) from the file header and calculates image_size = 2 * width * height without checking for overflow. On 32-bit systems (or where size_t is 32-bit), this calculation can overflow if width and height are large (e.g., 65535), wrapping around to a small value. This results in a small heap allocation via AcquireQuantumMemory and later operations relying on the dimensions can trigger an out of bounds read. This issue is fixed in version 7.1.2-10.

- [https://github.com/Sumitshah00/CVE-2025-66628](https://github.com/Sumitshah00/CVE-2025-66628) :  ![starts](https://img.shields.io/github/stars/Sumitshah00/CVE-2025-66628.svg) ![forks](https://img.shields.io/github/forks/Sumitshah00/CVE-2025-66628.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/l4rm4nd/CVE-2025-55182](https://github.com/l4rm4nd/CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/l4rm4nd/CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/l4rm4nd/CVE-2025-55182.svg)
- [https://github.com/anuththara2007-W/CVE-2025-55182-Exploit-extension](https://github.com/anuththara2007-W/CVE-2025-55182-Exploit-extension) :  ![starts](https://img.shields.io/github/stars/anuththara2007-W/CVE-2025-55182-Exploit-extension.svg) ![forks](https://img.shields.io/github/forks/anuththara2007-W/CVE-2025-55182-Exploit-extension.svg)
- [https://github.com/Code42Cate/nexts-cve-2025-66478-exploit](https://github.com/Code42Cate/nexts-cve-2025-66478-exploit) :  ![starts](https://img.shields.io/github/stars/Code42Cate/nexts-cve-2025-66478-exploit.svg) ![forks](https://img.shields.io/github/forks/Code42Cate/nexts-cve-2025-66478-exploit.svg)
- [https://github.com/changgun-lee/Next.js-RSC-RCE-Scanner-CVE-2025-66478](https://github.com/changgun-lee/Next.js-RSC-RCE-Scanner-CVE-2025-66478) :  ![starts](https://img.shields.io/github/stars/changgun-lee/Next.js-RSC-RCE-Scanner-CVE-2025-66478.svg) ![forks](https://img.shields.io/github/forks/changgun-lee/Next.js-RSC-RCE-Scanner-CVE-2025-66478.svg)


## CVE-2025-66470
 NiceGUI is a Python-based UI framework. Versions 3.3.1 and below are subject to a XSS vulnerability through the ui.interactive_image component of NiceGUI. The component renders SVG content using Vue's v-html directive without any sanitization. This allows attackers to inject malicious HTML or JavaScript via the SVG foreignObject tag whenever the image component is rendered or updated. This is particularly dangerous for dashboards or multi-user applications displaying user-generated content or annotations. This issue is fixed in version 3.4.0.

- [https://github.com/Jmehta10/CVE-2025-66470](https://github.com/Jmehta10/CVE-2025-66470) :  ![starts](https://img.shields.io/github/stars/Jmehta10/CVE-2025-66470.svg) ![forks](https://img.shields.io/github/forks/Jmehta10/CVE-2025-66470.svg)


## CVE-2025-64459
Django would like to thank cyberstan for reporting this issue.

- [https://github.com/ALPYAHYA/CVE-2025-64459-Exploit-PoC](https://github.com/ALPYAHYA/CVE-2025-64459-Exploit-PoC) :  ![starts](https://img.shields.io/github/stars/ALPYAHYA/CVE-2025-64459-Exploit-PoC.svg) ![forks](https://img.shields.io/github/forks/ALPYAHYA/CVE-2025-64459-Exploit-PoC.svg)
- [https://github.com/ALPYAHYA/CVE-2025-64459-Exploit-Fix](https://github.com/ALPYAHYA/CVE-2025-64459-Exploit-Fix) :  ![starts](https://img.shields.io/github/stars/ALPYAHYA/CVE-2025-64459-Exploit-Fix.svg) ![forks](https://img.shields.io/github/forks/ALPYAHYA/CVE-2025-64459-Exploit-Fix.svg)


## CVE-2025-62222
 Improper neutralization of special elements used in a command ('command injection') in Visual Studio Code CoPilot Chat Extension allows an unauthorized attacker to execute code over a network.

- [https://github.com/SadisticNight/PoC-CVE-2025-62222](https://github.com/SadisticNight/PoC-CVE-2025-62222) :  ![starts](https://img.shields.io/github/stars/SadisticNight/PoC-CVE-2025-62222.svg) ![forks](https://img.shields.io/github/forks/SadisticNight/PoC-CVE-2025-62222.svg)


## CVE-2025-60013
 When a user attempts to initialize the rSeries FIPS module using a password with special shell metacharacters, the FIPS hardware security module (HSM) may fail to initialize.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/Mwete404/Scalar-Venom-Attack](https://github.com/Mwete404/Scalar-Venom-Attack) :  ![starts](https://img.shields.io/github/stars/Mwete404/Scalar-Venom-Attack.svg) ![forks](https://img.shields.io/github/forks/Mwete404/Scalar-Venom-Attack.svg)


## CVE-2025-59718
 A improper verification of cryptographic signature vulnerability in Fortinet FortiOS 7.6.0 through 7.6.3, FortiOS 7.4.0 through 7.4.8, FortiOS 7.2.0 through 7.2.11, FortiOS 7.0.0 through 7.0.17, FortiProxy 7.6.0 through 7.6.3, FortiProxy 7.4.0 through 7.4.10, FortiProxy 7.2.0 through 7.2.14, FortiProxy 7.0.0 through 7.0.21, FortiSwitchManager 7.2.0 through 7.2.6, FortiSwitchManager 7.0.0 through 7.0.5 allows an unauthenticated attacker to bypass the FortiCloud SSO login authentication via a crafted SAML response message.

- [https://github.com/Ashwesker/Blackash-CVE-2025-59718](https://github.com/Ashwesker/Blackash-CVE-2025-59718) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Blackash-CVE-2025-59718.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Blackash-CVE-2025-59718.svg)


## CVE-2025-55816
 HotelDruid v3.0.7 and before is vulnerable to Cross Site Scripting (XSS) in the /modifica_app.php file.

- [https://github.com/partywavesec/CVE-2025-55816](https://github.com/partywavesec/CVE-2025-55816) :  ![starts](https://img.shields.io/github/stars/partywavesec/CVE-2025-55816.svg) ![forks](https://img.shields.io/github/forks/partywavesec/CVE-2025-55816.svg)


## CVE-2025-55184
 A pre-authentication denial of service vulnerability exists in React Server Components versions 19.0.0, 19.0.1 19.1.0, 19.1.1, 19.1.2, 19.2.0 and 19.2.1, including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints, which can cause an infinite loop that hangs the server process and may prevent future HTTP requests from being served.

- [https://github.com/ejpir/CVE-2025-55184](https://github.com/ejpir/CVE-2025-55184) :  ![starts](https://img.shields.io/github/stars/ejpir/CVE-2025-55184.svg) ![forks](https://img.shields.io/github/forks/ejpir/CVE-2025-55184.svg)
- [https://github.com/hans362/CVE-2025-55184-poc](https://github.com/hans362/CVE-2025-55184-poc) :  ![starts](https://img.shields.io/github/stars/hans362/CVE-2025-55184-poc.svg) ![forks](https://img.shields.io/github/forks/hans362/CVE-2025-55184-poc.svg)


## CVE-2025-55183
 An information leak vulnerability exists in specific configurations of React Server Components versions 19.0.0, 19.0.1 19.1.0, 19.1.1, 19.1.2, 19.2.0 and 19.2.1, including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. A specifically crafted HTTP request sent to a vulnerable Server Function may unsafely return the source code of any Server Function. Exploitation requires the existence of a Server Function which explicitly or implicitly exposes a stringified argument.

- [https://github.com/Saturate/CVE-2025-55183](https://github.com/Saturate/CVE-2025-55183) :  ![starts](https://img.shields.io/github/stars/Saturate/CVE-2025-55183.svg) ![forks](https://img.shields.io/github/forks/Saturate/CVE-2025-55183.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/Rsatan/Next.js-Exploit-Tool](https://github.com/Rsatan/Next.js-Exploit-Tool) :  ![starts](https://img.shields.io/github/stars/Rsatan/Next.js-Exploit-Tool.svg) ![forks](https://img.shields.io/github/forks/Rsatan/Next.js-Exploit-Tool.svg)
- [https://github.com/SainiONHacks/CVE-2025-55182-Scanner](https://github.com/SainiONHacks/CVE-2025-55182-Scanner) :  ![starts](https://img.shields.io/github/stars/SainiONHacks/CVE-2025-55182-Scanner.svg) ![forks](https://img.shields.io/github/forks/SainiONHacks/CVE-2025-55182-Scanner.svg)
- [https://github.com/yz9yt/React2Shell-CTF](https://github.com/yz9yt/React2Shell-CTF) :  ![starts](https://img.shields.io/github/stars/yz9yt/React2Shell-CTF.svg) ![forks](https://img.shields.io/github/forks/yz9yt/React2Shell-CTF.svg)
- [https://github.com/oscarmine/R2SAE](https://github.com/oscarmine/R2SAE) :  ![starts](https://img.shields.io/github/stars/oscarmine/R2SAE.svg) ![forks](https://img.shields.io/github/forks/oscarmine/R2SAE.svg)
- [https://github.com/VeilVulp/RscScan](https://github.com/VeilVulp/RscScan) :  ![starts](https://img.shields.io/github/stars/VeilVulp/RscScan.svg) ![forks](https://img.shields.io/github/forks/VeilVulp/RscScan.svg)
- [https://github.com/andrei2308/react2shell](https://github.com/andrei2308/react2shell) :  ![starts](https://img.shields.io/github/stars/andrei2308/react2shell.svg) ![forks](https://img.shields.io/github/forks/andrei2308/react2shell.svg)


## CVE-2025-53558
 ZXHN-F660T and ZXHN-F660A provided by ZTE Japan K.K. use a common credential for all installations. With the knowledge of the credential, an attacker may log in to the affected devices.

- [https://github.com/houqe/POC_CVE-2025-53558](https://github.com/houqe/POC_CVE-2025-53558) :  ![starts](https://img.shields.io/github/stars/houqe/POC_CVE-2025-53558.svg) ![forks](https://img.shields.io/github/forks/houqe/POC_CVE-2025-53558.svg)


## CVE-2025-49666
 Heap-based buffer overflow in Windows Kernel allows an authorized attacker to execute code over a network.

- [https://github.com/17patmaks/My-Sigma-Rule-Collection](https://github.com/17patmaks/My-Sigma-Rule-Collection) :  ![starts](https://img.shields.io/github/stars/17patmaks/My-Sigma-Rule-Collection.svg) ![forks](https://img.shields.io/github/forks/17patmaks/My-Sigma-Rule-Collection.svg)


## CVE-2025-34299
 Monsta FTP versions 2.11 and earlier contain a vulnerability that allows unauthenticated arbitrary file uploads. This flaw enables attackers to execute arbitrary code by uploading a specially crafted file from a malicious (S)FTP server.

- [https://github.com/KrE80r/CVE-2025-34299-lab](https://github.com/KrE80r/CVE-2025-34299-lab) :  ![starts](https://img.shields.io/github/stars/KrE80r/CVE-2025-34299-lab.svg) ![forks](https://img.shields.io/github/forks/KrE80r/CVE-2025-34299-lab.svg)


## CVE-2025-23061
 Mongoose before 8.9.5 can improperly use a nested $where filter with a populate() match, leading to search injection. NOTE: this issue exists because of an incomplete fix for CVE-2024-53900.

- [https://github.com/dajneem23/CVE-2025-23061](https://github.com/dajneem23/CVE-2025-23061) :  ![starts](https://img.shields.io/github/stars/dajneem23/CVE-2025-23061.svg) ![forks](https://img.shields.io/github/forks/dajneem23/CVE-2025-23061.svg)


## CVE-2025-13780
 pgAdmin versions up to 9.10 are affected by a Remote Code Execution (RCE) vulnerability that occurs when running in server mode and performing restores from PLAIN-format dump files. This issue allows attackers to inject and execute arbitrary commands on the server hosting pgAdmin, posing a critical risk to the integrity and security of the database management system and underlying data.

- [https://github.com/zeropwn/pgadmin4-9.10-CVE-2025-13780](https://github.com/zeropwn/pgadmin4-9.10-CVE-2025-13780) :  ![starts](https://img.shields.io/github/stars/zeropwn/pgadmin4-9.10-CVE-2025-13780.svg) ![forks](https://img.shields.io/github/forks/zeropwn/pgadmin4-9.10-CVE-2025-13780.svg)


## CVE-2025-13401
 The Autoptimize plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the LCP Image to preload metabox in all versions up to, and including, 3.1.13 due to insufficient input sanitization and output escaping on user-supplied image attributes in the "create_img_preload_tag" function. This makes it possible for authenticated attackers, with contributor level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/ciscocamelo/CVE-2025-13401-XSS-Stored](https://github.com/ciscocamelo/CVE-2025-13401-XSS-Stored) :  ![starts](https://img.shields.io/github/stars/ciscocamelo/CVE-2025-13401-XSS-Stored.svg) ![forks](https://img.shields.io/github/forks/ciscocamelo/CVE-2025-13401-XSS-Stored.svg)


## CVE-2025-12758
 Versions of the package validator before 13.15.22 are vulnerable to Incomplete Filtering of One or More Instances of Special Elements in the isLength() function that does not take into account Unicode variation selectors (\uFE0F, \uFE0E) appearing in a sequence which lead to improper string length calculation. This can lead to an application using isLength for input validation accepting strings significantly longer than intended, resulting in issues like data truncation in databases, buffer overflows in other system components, or denial-of-service.

- [https://github.com/dajneem23/CVE-2025-12758](https://github.com/dajneem23/CVE-2025-12758) :  ![starts](https://img.shields.io/github/stars/dajneem23/CVE-2025-12758.svg) ![forks](https://img.shields.io/github/forks/dajneem23/CVE-2025-12758.svg)


## CVE-2025-12097
 There is a relative path traversal vulnerability in the NI System Web Server that may result in information disclosure.  Successful exploitation requires an attacker to send a specially crafted request to the NI System Web Server, allowing the attacker to read arbitrary files.  This vulnerability existed in the NI System Web Server 2012 and prior versions.  It was fixed in 2013.

- [https://github.com/matejsmycka/PoC-CVE-2025-12097](https://github.com/matejsmycka/PoC-CVE-2025-12097) :  ![starts](https://img.shields.io/github/stars/matejsmycka/PoC-CVE-2025-12097.svg) ![forks](https://img.shields.io/github/forks/matejsmycka/PoC-CVE-2025-12097.svg)


## CVE-2025-8110
 Improper Symbolic link handling in the PutContents API in Gogs allows Local Execution of Code.

- [https://github.com/rxerium/CVE-2025-8110](https://github.com/rxerium/CVE-2025-8110) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-8110.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-8110.svg)
- [https://github.com/Ashwesker/Blackash-CVE-2025-8110](https://github.com/Ashwesker/Blackash-CVE-2025-8110) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Blackash-CVE-2025-8110.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Blackash-CVE-2025-8110.svg)


## CVE-2025-6451
 A vulnerability was found in code-projects Simple Online Hotel Reservation System 1.0. It has been declared as critical. This vulnerability affects unknown code of the file /admin/delete_pending.php. The manipulation of the argument transaction_id leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. It is recommended to apply a patch to fix this issue.

- [https://github.com/lem0naids/CVE-2025-64516-POC](https://github.com/lem0naids/CVE-2025-64516-POC) :  ![starts](https://img.shields.io/github/stars/lem0naids/CVE-2025-64516-POC.svg) ![forks](https://img.shields.io/github/forks/lem0naids/CVE-2025-64516-POC.svg)


## CVE-2025-6019
 A Local Privilege Escalation (LPE) vulnerability was found in libblockdev. Generally, the "allow_active" setting in Polkit permits a physically present user to take certain actions based on the session type. Due to the way libblockdev interacts with the udisks daemon, an "allow_active" user on a system may be able escalate to full root privileges on the target host. Normally, udisks mounts user-provided filesystem images with security flags like nosuid and nodev to prevent privilege escalation.  However, a local attacker can create a specially crafted XFS image containing a SUID-root shell, then trick udisks into resizing it. This mounts their malicious filesystem with root privileges, allowing them to execute their SUID-root shell and gain complete control of the system.

- [https://github.com/robbin0919/CVE-2025-6019](https://github.com/robbin0919/CVE-2025-6019) :  ![starts](https://img.shields.io/github/stars/robbin0919/CVE-2025-6019.svg) ![forks](https://img.shields.io/github/forks/robbin0919/CVE-2025-6019.svg)


## CVE-2024-43425
 A flaw was found in Moodle. Additional restrictions are required to avoid a remote code execution risk in calculated question types. Note: This requires the capability to add/update questions.

- [https://github.com/vuductruong12/KTLHPM](https://github.com/vuductruong12/KTLHPM) :  ![starts](https://img.shields.io/github/stars/vuductruong12/KTLHPM.svg) ![forks](https://img.shields.io/github/forks/vuductruong12/KTLHPM.svg)


## CVE-2024-27956
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in ValvePress Automatic allows SQL Injection.This issue affects Automatic: from n/a through 3.92.0.

- [https://github.com/hitazuranahiro/Valve-Press-CVE-2024-27956-RCE](https://github.com/hitazuranahiro/Valve-Press-CVE-2024-27956-RCE) :  ![starts](https://img.shields.io/github/stars/hitazuranahiro/Valve-Press-CVE-2024-27956-RCE.svg) ![forks](https://img.shields.io/github/forks/hitazuranahiro/Valve-Press-CVE-2024-27956-RCE.svg)


## CVE-2024-7954
 The porte_plume plugin used by SPIP before 4.30-alpha2, 4.2.13, and 4.1.16 is vulnerable to an arbitrary code execution vulnerability. A remote and unauthenticated attacker can execute arbitrary PHP as the SPIP user by sending a crafted HTTP request.

- [https://github.com/ShivanshKuntal/Exploitation-of-a-Remote-Code-Execution-vulnerability--CVE-2024-7954-](https://github.com/ShivanshKuntal/Exploitation-of-a-Remote-Code-Execution-vulnerability--CVE-2024-7954-) :  ![starts](https://img.shields.io/github/stars/ShivanshKuntal/Exploitation-of-a-Remote-Code-Execution-vulnerability--CVE-2024-7954-.svg) ![forks](https://img.shields.io/github/forks/ShivanshKuntal/Exploitation-of-a-Remote-Code-Execution-vulnerability--CVE-2024-7954-.svg)


## CVE-2022-25765
 The package pdfkit from 0.0.0 are vulnerable to Command Injection where the URL is not properly sanitized.

- [https://github.com/lst15/pdfkit-cve-2022-25765](https://github.com/lst15/pdfkit-cve-2022-25765) :  ![starts](https://img.shields.io/github/stars/lst15/pdfkit-cve-2022-25765.svg) ![forks](https://img.shields.io/github/forks/lst15/pdfkit-cve-2022-25765.svg)


## CVE-2022-0332
 A flaw was found in Moodle in versions 3.11 to 3.11.4. An SQL injection risk was identified in the h5p activity web service responsible for fetching user attempt data.

- [https://github.com/vuductruong12/KTLHPM](https://github.com/vuductruong12/KTLHPM) :  ![starts](https://img.shields.io/github/stars/vuductruong12/KTLHPM.svg) ![forks](https://img.shields.io/github/forks/vuductruong12/KTLHPM.svg)


## CVE-2021-36393
 In Moodle, an SQL injection risk was identified in the library fetching a user's recent courses.

- [https://github.com/vuductruong12/KTLHPM](https://github.com/vuductruong12/KTLHPM) :  ![starts](https://img.shields.io/github/stars/vuductruong12/KTLHPM.svg) ![forks](https://img.shields.io/github/forks/vuductruong12/KTLHPM.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/abrewer251/CVE-2020-1938_Ghostcat-PoC](https://github.com/abrewer251/CVE-2020-1938_Ghostcat-PoC) :  ![starts](https://img.shields.io/github/stars/abrewer251/CVE-2020-1938_Ghostcat-PoC.svg) ![forks](https://img.shields.io/github/forks/abrewer251/CVE-2020-1938_Ghostcat-PoC.svg)


## CVE-2020-0014
 It is possible for a malicious application to construct a TYPE_TOAST window manually and make that window clickable. This could lead to a local escalation of privilege with no additional execution privileges needed. User action is needed for exploitation.Product: AndroidVersions: Android-8.0 Android-8.1 Android-9 Android-10Android ID: A-128674520

- [https://github.com/doudoudedi/CVE-2020-0014_Toast](https://github.com/doudoudedi/CVE-2020-0014_Toast) :  ![starts](https://img.shields.io/github/stars/doudoudedi/CVE-2020-0014_Toast.svg) ![forks](https://img.shields.io/github/forks/doudoudedi/CVE-2020-0014_Toast.svg)


## CVE-2019-11043
 In PHP versions 7.1.x below 7.1.33, 7.2.x below 7.2.24 and 7.3.x below 7.3.11 in certain configurations of FPM setup it is possible to cause FPM module to write past allocated buffers into the space reserved for FCGI protocol data, thus opening the possibility of remote code execution.

- [https://github.com/gon905332-jpg/cve-2019-11043.py](https://github.com/gon905332-jpg/cve-2019-11043.py) :  ![starts](https://img.shields.io/github/stars/gon905332-jpg/cve-2019-11043.py.svg) ![forks](https://img.shields.io/github/forks/gon905332-jpg/cve-2019-11043.py.svg)


## CVE-2017-8917
 SQL injection vulnerability in Joomla! 3.7.x before 3.7.1 allows attackers to execute arbitrary SQL commands via unspecified vectors.

- [https://github.com/yayateayayatea/cve-2017-8917](https://github.com/yayateayayatea/cve-2017-8917) :  ![starts](https://img.shields.io/github/stars/yayateayayatea/cve-2017-8917.svg) ![forks](https://img.shields.io/github/forks/yayateayayatea/cve-2017-8917.svg)


## CVE-2014-4725
 The MailPoet Newsletters (wysija-newsletters) plugin before 2.6.7 for WordPress allows remote attackers to bypass authentication and execute arbitrary PHP code by uploading a crafted theme using wp-admin/admin-post.php and accessing the theme in wp-content/uploads/wysija/themes/mailp/.

- [https://github.com/AnotherSec/CVE-2014-4725](https://github.com/AnotherSec/CVE-2014-4725) :  ![starts](https://img.shields.io/github/stars/AnotherSec/CVE-2014-4725.svg) ![forks](https://img.shields.io/github/forks/AnotherSec/CVE-2014-4725.svg)


## CVE-2013-0156
 active_support/core_ext/hash/conversions.rb in Ruby on Rails before 2.3.15, 3.0.x before 3.0.19, 3.1.x before 3.1.10, and 3.2.x before 3.2.11 does not properly restrict casts of string values, which allows remote attackers to conduct object-injection attacks and execute arbitrary code, or cause a denial of service (memory and CPU consumption) involving nested XML entity references, by leveraging Action Pack support for (1) YAML type conversion or (2) Symbol type conversion.

- [https://github.com/7s26simon/CVE-2013-0156](https://github.com/7s26simon/CVE-2013-0156) :  ![starts](https://img.shields.io/github/stars/7s26simon/CVE-2013-0156.svg) ![forks](https://img.shields.io/github/forks/7s26simon/CVE-2013-0156.svg)


## CVE-2009-4623
 Multiple PHP remote file inclusion vulnerabilities in Advanced Comment System 1.0 allow remote attackers to execute arbitrary PHP code via a URL in the ACS_path parameter to (1) index.php and (2) admin.php in advanced_comment_system/. NOTE: this might only be a vulnerability when the administrator has not followed installation instructions in install.php. NOTE: this might be the same as CVE-2020-35598.

- [https://github.com/sammonsempes/CVE-2009-4623](https://github.com/sammonsempes/CVE-2009-4623) :  ![starts](https://img.shields.io/github/stars/sammonsempes/CVE-2009-4623.svg) ![forks](https://img.shields.io/github/forks/sammonsempes/CVE-2009-4623.svg)

