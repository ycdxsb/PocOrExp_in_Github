# Update 2022-12-28
## CVE-2022-45347
 Apache ShardingSphere-Proxy prior to 5.3.0 when using MySQL as database backend didn't cleanup the database session completely after client authentication failed, which allowed an attacker to execute normal commands by constructing a special MySQL client. This vulnerability has been fixed in Apache ShardingSphere 5.3.0.

- [https://github.com/Live-Hack-CVE/CVE-2022-45347](https://github.com/Live-Hack-CVE/CVE-2022-45347) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45347.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45347.svg)


## CVE-2022-45315
 Mikrotik RouterOs before stable v7.6 was discovered to contain an out-of-bounds read in the snmp process. This vulnerability allows attackers to execute arbitrary code via a crafted packet.

- [https://github.com/dianaross20/CVE-2022--45315](https://github.com/dianaross20/CVE-2022--45315) :  ![starts](https://img.shields.io/github/stars/dianaross20/CVE-2022--45315.svg) ![forks](https://img.shields.io/github/forks/dianaross20/CVE-2022--45315.svg)


## CVE-2022-44183
 Tenda AC18 V15.03.05.19 is vulnerable to Buffer Overflow via function formSetWifiGuestBasic.

- [https://github.com/FuHaoPing/CVE-2022-44183](https://github.com/FuHaoPing/CVE-2022-44183) :  ![starts](https://img.shields.io/github/stars/FuHaoPing/CVE-2022-44183.svg) ![forks](https://img.shields.io/github/forks/FuHaoPing/CVE-2022-44183.svg)


## CVE-2022-42898
 PAC parsing in MIT Kerberos 5 (aka krb5) before 1.19.4 and 1.20.x before 1.20.1 has integer overflows that may lead to remote code execution (in KDC, kadmind, or a GSS or Kerberos application server) on 32-bit platforms (which have a resultant heap-based buffer overflow), and cause a denial of service on other platforms. This occurs in krb5_pac_parse in lib/krb5/krb/pac.c. Heimdal before 7.7.1 has &quot;a similar bug.&quot;

- [https://github.com/Live-Hack-CVE/CVE-2022-42898](https://github.com/Live-Hack-CVE/CVE-2022-42898) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42898.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42898.svg)


## CVE-2022-41318
 A buffer over-read was discovered in libntlmauth in Squid 2.5 through 5.6. Due to incorrect integer-overflow protection, the SSPI and SMB authentication helpers are vulnerable to reading unintended memory locations. In some configurations, cleartext credentials from these locations are sent to a client. This is fixed in 5.7.

- [https://github.com/Live-Hack-CVE/CVE-2022-41318](https://github.com/Live-Hack-CVE/CVE-2022-41318) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-41318.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-41318.svg)


## CVE-2022-41317
 An issue was discovered in Squid 4.9 through 4.17 and 5.0.6 through 5.6. Due to inconsistent handling of internal URIs, there can be Exposure of Sensitive Information about clients using the proxy via an HTTPS request to an internal cache manager URL. This is fixed in 5.7.

- [https://github.com/Live-Hack-CVE/CVE-2022-41317](https://github.com/Live-Hack-CVE/CVE-2022-41317) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-41317.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-41317.svg)


## CVE-2022-40005
 Intelbras WiFiber 120AC inMesh before 1-1-220826 allows command injection by authenticated users, as demonstrated by the /boaform/formPing6 and /boaform/formTracert URIs for ping and traceroute.

- [https://github.com/Live-Hack-CVE/CVE-2022-40005](https://github.com/Live-Hack-CVE/CVE-2022-40005) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-40005.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-40005.svg)


## CVE-2022-38665
 Jenkins CollabNet Plugins Plugin 2.0.8 and earlier stores a RabbitMQ password unencrypted in its global configuration file on the Jenkins controller where it can be viewed by users with access to the Jenkins controller file system.

- [https://github.com/Live-Hack-CVE/CVE-2022-38665](https://github.com/Live-Hack-CVE/CVE-2022-38665) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38665.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38665.svg)


## CVE-2022-38664
 Jenkins Job Configuration History Plugin 1165.v8cc9fd1f4597 and earlier does not escape the job name on the System Configuration History page, resulting in a stored cross-site scripting (XSS) vulnerability exploitable by attackers able to configure job names.

- [https://github.com/Live-Hack-CVE/CVE-2022-38664](https://github.com/Live-Hack-CVE/CVE-2022-38664) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38664.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38664.svg)


## CVE-2022-38663
 Jenkins Git Plugin 4.11.4 and earlier does not properly mask (i.e., replace with asterisks) credentials in the build log provided by the Git Username and Password (`gitUsernamePassword`) credentials binding.

- [https://github.com/Live-Hack-CVE/CVE-2022-38663](https://github.com/Live-Hack-CVE/CVE-2022-38663) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38663.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38663.svg)


## CVE-2022-38493
 Rhonabwy 0.9.99 through 1.1.x before 1.1.7 doesn't check the RSA private key length before RSA-OAEP decryption. This allows attackers to cause a Denial of Service via a crafted JWE (JSON Web Encryption) token.

- [https://github.com/Live-Hack-CVE/CVE-2022-38493](https://github.com/Live-Hack-CVE/CVE-2022-38493) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38493.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38493.svg)


## CVE-2022-38463
 ServiceNow through San Diego Patch 4b and Patch 6 allows reflected XSS in the logout functionality.

- [https://github.com/Live-Hack-CVE/CVE-2022-38463](https://github.com/Live-Hack-CVE/CVE-2022-38463) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38463.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38463.svg)


## CVE-2022-38368
 An issue was discovered in Aviatrix Gateway before 6.6.5712 and 6.7.x before 6.7.1376. Because Gateway API functions mishandle authentication, an authenticated VPN user can inject arbitrary commands.

- [https://github.com/Live-Hack-CVE/CVE-2022-38368](https://github.com/Live-Hack-CVE/CVE-2022-38368) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38368.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38368.svg)


## CVE-2022-38362
 Apache Airflow Docker's Provider prior to 3.0.0 shipped with an example DAG that was vulnerable to (authenticated) remote code exploit of code on the Airflow worker host.

- [https://github.com/Live-Hack-CVE/CVE-2022-38362](https://github.com/Live-Hack-CVE/CVE-2022-38362) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38362.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38362.svg)


## CVE-2022-38359
 Cross-site request forgery attacks can be carried out against the Eyes of Network web application, due to an absence of adequate protections. An attacker can, for instance, delete the admin user by directing an authenticated user to the URL https://&lt;target-address&gt;/module/admin_user/index.php?DataTables_Table_0_length=10&amp;user_selected%5B%5D=1&amp;user_mgt_list=delete_user&amp;action=submit by means of a crafted link.

- [https://github.com/Live-Hack-CVE/CVE-2022-38359](https://github.com/Live-Hack-CVE/CVE-2022-38359) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38359.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38359.svg)


## CVE-2022-38358
 Improper neutralization of input during web page generation leaves the Eyes of Network web application vulnerable to cross-site scripting attacks at /module/admin_notifiers/rules.php and /module/report_event/indext.php via the parameters rule_notification, rule_name, and rule_name_old, and at /module/admin_user/add_modify_user.php via the parameters user_name and user_email.

- [https://github.com/Live-Hack-CVE/CVE-2022-38358](https://github.com/Live-Hack-CVE/CVE-2022-38358) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38358.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38358.svg)


## CVE-2022-38357
 Improper neutralization of special elements leaves the Eyes of Network Web application vulnerable to an iFrame injection attack, via the url parameter of /module/module_frame/index.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-38357](https://github.com/Live-Hack-CVE/CVE-2022-38357) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38357.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38357.svg)


## CVE-2022-38238
 XPDF commit ffaf11c was discovered to contain a heap-buffer overflow via DCTStream::lookChar() at /xpdf/Stream.cc.

- [https://github.com/Live-Hack-CVE/CVE-2022-38238](https://github.com/Live-Hack-CVE/CVE-2022-38238) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38238.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38238.svg)


## CVE-2022-38237
 XPDF commit ffaf11c was discovered to contain a heap-buffer overflow via DCTStream::readScan() at /xpdf/Stream.cc.

- [https://github.com/Live-Hack-CVE/CVE-2022-38237](https://github.com/Live-Hack-CVE/CVE-2022-38237) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38237.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38237.svg)


## CVE-2022-38236
 XPDF commit ffaf11c was discovered to contain a global-buffer overflow via Lexer::getObj(Object*) at /xpdf/Lexer.cc.

- [https://github.com/Live-Hack-CVE/CVE-2022-38236](https://github.com/Live-Hack-CVE/CVE-2022-38236) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38236.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38236.svg)


## CVE-2022-38235
 XPDF commit ffaf11c was discovered to contain a segmentation violation via DCTStream::getChar() at /xpdf/Stream.cc.

- [https://github.com/Live-Hack-CVE/CVE-2022-38235](https://github.com/Live-Hack-CVE/CVE-2022-38235) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38235.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38235.svg)


## CVE-2022-38234
 XPDF commit ffaf11c was discovered to contain a segmentation violation via Lexer::getObj(Object*) at /xpdf/Lexer.cc.

- [https://github.com/Live-Hack-CVE/CVE-2022-38234](https://github.com/Live-Hack-CVE/CVE-2022-38234) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38234.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38234.svg)


## CVE-2022-38233
 XPDF commit ffaf11c was discovered to contain a segmentation violation via DCTStream::readMCURow() at /xpdf/Stream.cc.

- [https://github.com/Live-Hack-CVE/CVE-2022-38233](https://github.com/Live-Hack-CVE/CVE-2022-38233) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38233.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38233.svg)


## CVE-2022-38231
 XPDF commit ffaf11c was discovered to contain a heap-buffer overflow via DCTStream::getChar() at /xpdf/Stream.cc.

- [https://github.com/Live-Hack-CVE/CVE-2022-38231](https://github.com/Live-Hack-CVE/CVE-2022-38231) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38231.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38231.svg)


## CVE-2022-38230
 XPDF commit ffaf11c was discovered to contain a floating point exception (FPE) via DCTStream::decodeImage() at /xpdf/Stream.cc.

- [https://github.com/Live-Hack-CVE/CVE-2022-38230](https://github.com/Live-Hack-CVE/CVE-2022-38230) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38230.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38230.svg)


## CVE-2022-38228
 XPDF commit ffaf11c was discovered to contain a heap-buffer overflow via DCTStream::transformDataUnit at /xpdf/Stream.cc.

- [https://github.com/Live-Hack-CVE/CVE-2022-38228](https://github.com/Live-Hack-CVE/CVE-2022-38228) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38228.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38228.svg)


## CVE-2022-38227
 XPDF commit ffaf11c was discovered to contain a stack overflow via __asan_memcpy at asan_interceptors_memintrinsics.cpp.

- [https://github.com/Live-Hack-CVE/CVE-2022-38227](https://github.com/Live-Hack-CVE/CVE-2022-38227) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38227.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38227.svg)


## CVE-2022-38223
 There is an out-of-bounds write in checkType located in etc.c in w3m 0.5.3. It can be triggered by sending a crafted HTML file to the w3m binary. It allows an attacker to cause Denial of Service or possibly have unspecified other impact.

- [https://github.com/Live-Hack-CVE/CVE-2022-38223](https://github.com/Live-Hack-CVE/CVE-2022-38223) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38223.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38223.svg)


## CVE-2022-38221
 A buffer overflow in the FTcpListener thread in The Isle Evrima (the dedicated server on Windows and Linux) 0.9.88.07 before 2022-08-12 allows a remote attacker to crash any server with an accessible RCON port, or possibly execute arbitrary code.

- [https://github.com/Live-Hack-CVE/CVE-2022-38221](https://github.com/Live-Hack-CVE/CVE-2022-38221) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38221.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38221.svg)


## CVE-2022-38216
 An integer overflow exists in Mapbox's closed source gl-native library prior to version 10.6.1, which is bundled with multiple Mapbox products including open source libraries. The overflow is caused by large image height and width values when creating a new Image and allows for out of bounds writes, potentially crashing the Mapbox process.

- [https://github.com/Live-Hack-CVE/CVE-2022-38216](https://github.com/Live-Hack-CVE/CVE-2022-38216) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38216.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38216.svg)


## CVE-2022-38194
 In Esri Portal for ArcGIS versions 10.8.1, a system property is not properly encrypted. This may lead to a local user reading sensitive information from a properties file.

- [https://github.com/Live-Hack-CVE/CVE-2022-38194](https://github.com/Live-Hack-CVE/CVE-2022-38194) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38194.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38194.svg)


## CVE-2022-38192
 A stored Cross Site Scripting (XSS) vulnerability in Esri Portal for ArcGIS may allow a remote, authenticated attacker to pass and store malicious strings via crafted queries which when accessed could potentially execute arbitrary JavaScript code in the user&#8217;s browser.

- [https://github.com/Live-Hack-CVE/CVE-2022-38192](https://github.com/Live-Hack-CVE/CVE-2022-38192) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38192.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38192.svg)


## CVE-2022-38191
 There is an HTML injection issue in Esri Portal for ArcGIS versions 10.9.0 and below which may allow a remote, authenticated attacker to inject HTML into some locations in the home application.

- [https://github.com/Live-Hack-CVE/CVE-2022-38191](https://github.com/Live-Hack-CVE/CVE-2022-38191) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38191.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38191.svg)


## CVE-2022-38190
 A stored Cross Site Scripting (XSS) vulnerability in Esri Portal for ArcGIS configurable apps may allow a remote, unauthenticated attacker to pass and store malicious strings via crafted queries which when accessed could potentially execute arbitrary JavaScript code in the user&#8217;s browser

- [https://github.com/Live-Hack-CVE/CVE-2022-38190](https://github.com/Live-Hack-CVE/CVE-2022-38190) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38190.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38190.svg)


## CVE-2022-38188
 There is a reflected XSS vulnerability in Esri Portal for ArcGIS versions 10.9.1 which may allow a remote attacker able to convince a user to click on a crafted link which could potentially execute arbitrary JavaScript code in the victim&#8217;s browser.

- [https://github.com/Live-Hack-CVE/CVE-2022-38188](https://github.com/Live-Hack-CVE/CVE-2022-38188) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38188.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38188.svg)


## CVE-2022-38187
 Prior to version 10.9.0, the sharing/rest/content/features/analyze endpoint is always accessible to anonymous users, which could allow an unauthenticated attacker to induce Esri Portal for ArcGIS to read arbitrary URLs.

- [https://github.com/Live-Hack-CVE/CVE-2022-38187](https://github.com/Live-Hack-CVE/CVE-2022-38187) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38187.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38187.svg)


## CVE-2022-38186
 There is a reflected XSS vulnerability in Esri Portal for ArcGIS versions 10.8.1 and below which may allow a remote attacker able to convince a user to click on a crafted link which could potentially execute arbitrary JavaScript code in the victim&#8217;s browser.

- [https://github.com/Live-Hack-CVE/CVE-2022-38186](https://github.com/Live-Hack-CVE/CVE-2022-38186) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38186.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38186.svg)


## CVE-2022-38184
 There is an improper access control vulnerability in Portal for ArcGIS versions 10.8.1 and below which could allow a remote, unauthenticated attacker to access an API that may induce Esri Portal for ArcGIS to read arbitrary URLs.

- [https://github.com/Live-Hack-CVE/CVE-2022-38184](https://github.com/Live-Hack-CVE/CVE-2022-38184) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38184.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38184.svg)


## CVE-2022-38172
 ServiceNow through San Diego Patch 3 allows XSS via the name field during creation of a new dashboard for the Performance Analytics dashboard.

- [https://github.com/Live-Hack-CVE/CVE-2022-38172](https://github.com/Live-Hack-CVE/CVE-2022-38172) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38172.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38172.svg)


## CVE-2022-37816
 Tenda AC1206 V15.03.06.23 was discovered to contain a stack overflow via the function fromSetIpMacBind.

- [https://github.com/Live-Hack-CVE/CVE-2022-37816](https://github.com/Live-Hack-CVE/CVE-2022-37816) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37816.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37816.svg)


## CVE-2022-37815
 Tenda AC1206 V15.03.06.23 was discovered to contain a stack overflow via the PPPOEPassword parameter in the function formQuickIndex.

- [https://github.com/Live-Hack-CVE/CVE-2022-37815](https://github.com/Live-Hack-CVE/CVE-2022-37815) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37815.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37815.svg)


## CVE-2022-37814
 Tenda AC1206 V15.03.06.23 was discovered to contain multiple stack overflows via the deviceMac and the device_id parameters in the function addWifiMacFilter.

- [https://github.com/Live-Hack-CVE/CVE-2022-37814](https://github.com/Live-Hack-CVE/CVE-2022-37814) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37814.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37814.svg)


## CVE-2022-37813
 Tenda AC1206 V15.03.06.23 was discovered to contain a stack overflow via the function fromSetSysTime.

- [https://github.com/Live-Hack-CVE/CVE-2022-37813](https://github.com/Live-Hack-CVE/CVE-2022-37813) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37813.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37813.svg)


## CVE-2022-37812
 Tenda AC1206 V15.03.06.23 was discovered to contain a stack overflow via the firewallEn parameter in the function formSetFirewallCfg.

- [https://github.com/Live-Hack-CVE/CVE-2022-37812](https://github.com/Live-Hack-CVE/CVE-2022-37812) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37812.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37812.svg)


## CVE-2022-37811
 Tenda AC1206 V15.03.06.23 was discovered to contain a stack overflow via the startIp parameter in the function formSetPPTPServer.

- [https://github.com/Live-Hack-CVE/CVE-2022-37811](https://github.com/Live-Hack-CVE/CVE-2022-37811) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37811.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37811.svg)


## CVE-2022-37810
 Tenda AC1206 V15.03.06.23 was discovered to contain a command injection vulnerability via the mac parameter in the function formWriteFacMac.

- [https://github.com/Live-Hack-CVE/CVE-2022-37810](https://github.com/Live-Hack-CVE/CVE-2022-37810) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37810.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37810.svg)


## CVE-2022-37809
 Tenda AC1206 V15.03.06.23 was discovered to contain a stack overflow via the speed_dir parameter in the function formSetSpeedWan.

- [https://github.com/Live-Hack-CVE/CVE-2022-37809](https://github.com/Live-Hack-CVE/CVE-2022-37809) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37809.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37809.svg)


## CVE-2022-37808
 Tenda AC1206 V15.03.06.23 was discovered to contain a stack overflow via the index parameter in the function formWifiWpsOOB.

- [https://github.com/Live-Hack-CVE/CVE-2022-37808](https://github.com/Live-Hack-CVE/CVE-2022-37808) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37808.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37808.svg)


## CVE-2022-37807
 Tenda AC1206 V15.03.06.23 was discovered to contain a stack overflow via the function formSetClientState.

- [https://github.com/Live-Hack-CVE/CVE-2022-37807](https://github.com/Live-Hack-CVE/CVE-2022-37807) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37807.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37807.svg)


## CVE-2022-37806
 Tenda AC1206 V15.03.06.23 was discovered to contain a stack overflow via the page parameter in the function fromDhcpListClient.

- [https://github.com/Live-Hack-CVE/CVE-2022-37806](https://github.com/Live-Hack-CVE/CVE-2022-37806) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37806.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37806.svg)


## CVE-2022-37805
 Tenda AC1206 V15.03.06.23 was discovered to contain a stack overflow via the function fromWizardHandle.

- [https://github.com/Live-Hack-CVE/CVE-2022-37805](https://github.com/Live-Hack-CVE/CVE-2022-37805) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37805.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37805.svg)


## CVE-2022-37804
 Tenda AC1206 V15.03.06.23 was discovered to contain a stack overflow via the time parameter in the function saveParentControlInfo.

- [https://github.com/Live-Hack-CVE/CVE-2022-37804](https://github.com/Live-Hack-CVE/CVE-2022-37804) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37804.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37804.svg)


## CVE-2022-37803
 Tenda AC1206 V15.03.06.23 was discovered to contain a stack overflow via the page parameter in the function fromAddressNat.

- [https://github.com/Live-Hack-CVE/CVE-2022-37803](https://github.com/Live-Hack-CVE/CVE-2022-37803) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37803.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37803.svg)


## CVE-2022-37802
 Tenda AC1206 V15.03.06.23 was discovered to contain a stack overflow via the page parameter in the function fromNatStaticSetting.

- [https://github.com/Live-Hack-CVE/CVE-2022-37802](https://github.com/Live-Hack-CVE/CVE-2022-37802) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37802.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37802.svg)


## CVE-2022-37801
 Tenda AC1206 V15.03.06.23 was discovered to contain a stack overflow via the list parameter at the function formSetQosBand.

- [https://github.com/Live-Hack-CVE/CVE-2022-37801](https://github.com/Live-Hack-CVE/CVE-2022-37801) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37801.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37801.svg)


## CVE-2022-37800
 Tenda AC1206 V15.03.06.23 was discovered to contain a stack overflow via the list parameter at the function fromSetRouteStatic.

- [https://github.com/Live-Hack-CVE/CVE-2022-37800](https://github.com/Live-Hack-CVE/CVE-2022-37800) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37800.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37800.svg)


## CVE-2022-37799
 Tenda AC1206 V15.03.06.23 was discovered to contain a stack overflow via the time parameter at the function setSmartPowerManagement.

- [https://github.com/Live-Hack-CVE/CVE-2022-37799](https://github.com/Live-Hack-CVE/CVE-2022-37799) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37799.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37799.svg)


## CVE-2022-37798
 Tenda AC1206 V15.03.06.23 was discovered to contain a stack overflow via the list parameter at the function formSetVirtualSer.

- [https://github.com/Live-Hack-CVE/CVE-2022-37798](https://github.com/Live-Hack-CVE/CVE-2022-37798) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37798.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37798.svg)


## CVE-2022-37781
 fdkaac v1.0.3 was discovered to contain a heap buffer overflow via __interceptor_memcpy.part.46 at /sanitizer_common/sanitizer_common_interceptors.inc.

- [https://github.com/Live-Hack-CVE/CVE-2022-37781](https://github.com/Live-Hack-CVE/CVE-2022-37781) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37781.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37781.svg)


## CVE-2022-37770
 libjpeg commit 281daa9 was discovered to contain a segmentation fault via LineMerger::GetNextLowpassLine at linemerger.cpp. This vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted file.

- [https://github.com/Live-Hack-CVE/CVE-2022-37770](https://github.com/Live-Hack-CVE/CVE-2022-37770) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37770.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37770.svg)


## CVE-2022-37769
 libjpeg commit 281daa9 was discovered to contain a segmentation fault via HuffmanDecoder::Get at huffmandecoder.hpp. This vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted file.

- [https://github.com/Live-Hack-CVE/CVE-2022-37769](https://github.com/Live-Hack-CVE/CVE-2022-37769) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37769.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37769.svg)


## CVE-2022-37768
 libjpeg commit 281daa9 was discovered to contain an infinite loop via the component Frame::ParseTrailer.

- [https://github.com/Live-Hack-CVE/CVE-2022-37768](https://github.com/Live-Hack-CVE/CVE-2022-37768) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37768.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37768.svg)


## CVE-2022-37706
 enlightenment_sys in Enlightenment before 0.25.4 allows local users to gain privileges because it is setuid root, and the system library function mishandles pathnames that begin with a /dev/.. substring.

- [https://github.com/Live-Hack-CVE/CVE-2022-37706](https://github.com/Live-Hack-CVE/CVE-2022-37706) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37706.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37706.svg)


## CVE-2022-37459
 Ampere Altra devices before 1.08g and Ampere Altra Max devices before 2.05a allow attackers to control the predictions for return addresses and potentially hijack code flow to execute arbitrary code via a side-channel attack, aka a &quot;Retbleed&quot; issue.

- [https://github.com/Live-Hack-CVE/CVE-2022-37459](https://github.com/Live-Hack-CVE/CVE-2022-37459) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37459.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37459.svg)


## CVE-2022-37439
 In Splunk Enterprise and Universal Forwarder versions in the following table, indexing a specially crafted ZIP file using the file monitoring input can result in a crash of the application. Attempts to restart the application would result in a crash and would require manually removing the malformed file.

- [https://github.com/Live-Hack-CVE/CVE-2022-37439](https://github.com/Live-Hack-CVE/CVE-2022-37439) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37439.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37439.svg)


## CVE-2022-37438
 In Splunk Enterprise versions in the following table, an authenticated user can craft a dashboard that could potentially leak information (for example, username, email, and real name) about Splunk users, when visited by another user through the drilldown component. The vulnerability requires user access to create and share dashboards using Splunk Web.

- [https://github.com/Live-Hack-CVE/CVE-2022-37438](https://github.com/Live-Hack-CVE/CVE-2022-37438) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37438.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37438.svg)


## CVE-2022-37437
 When using Ingest Actions to configure a destination that resides on Amazon Simple Storage Service (S3) in Splunk Web, TLS certificate validation is not correctly performed and tested for the destination. The vulnerability only affects connections between Splunk Enterprise and an Ingest Actions Destination through Splunk Web and only applies to environments that have configured TLS certificate validation. It does not apply to Destinations configured directly in the outputs.conf configuration file. The vulnerability affects Splunk Enterprise version 9.0.0 and does not affect versions below 9.0.0, including the 8.1.x and 8.2.x versions.

- [https://github.com/Live-Hack-CVE/CVE-2022-37437](https://github.com/Live-Hack-CVE/CVE-2022-37437) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37437.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37437.svg)


## CVE-2022-37423
 Neo4j APOC (Awesome Procedures on Cypher) before 4.3.0.7 and 4.x before 4.4.0.8 allows Directory Traversal to sibling directories via apoc.log.stream.

- [https://github.com/Live-Hack-CVE/CVE-2022-37423](https://github.com/Live-Hack-CVE/CVE-2022-37423) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37423.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37423.svg)


## CVE-2022-37422
 Payara through 5.2022.2 allows directory traversal without authentication. This affects Payara Server, Payara Micro, and Payara Server Embedded.

- [https://github.com/Live-Hack-CVE/CVE-2022-37422](https://github.com/Live-Hack-CVE/CVE-2022-37422) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37422.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37422.svg)


## CVE-2022-37400
 Apache OpenOffice supports the storage of passwords for web connections in the user's configuration database. The stored passwords are encrypted with a single master key provided by the user. A flaw in OpenOffice existed where the required initialization vector for encryption was always the same which weakens the security of the encryption making them vulnerable if an attacker has access to the user's configuration data. This issue affects: Apache OpenOffice versions prior to 4.1.13. Reference: CVE-2022-26306 - LibreOffice

- [https://github.com/Live-Hack-CVE/CVE-2022-37400](https://github.com/Live-Hack-CVE/CVE-2022-37400) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37400.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37400.svg)


## CVE-2022-37397
 An issue was discovered in the YugabyteDB 2.6.1 when using LDAP-based authentication in YCQL with Microsoft&#8217;s Active Directory. When anonymous or unauthenticated LDAP binding is enabled, it allows bypass of authentication with an empty password.

- [https://github.com/Live-Hack-CVE/CVE-2022-37397](https://github.com/Live-Hack-CVE/CVE-2022-37397) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37397.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37397.svg)


## CVE-2022-37393
 Zimbra's sudo configuration permits the zimbra user to execute the zmslapd binary as root with arbitrary parameters. As part of its intended functionality, zmslapd can load a user-defined configuration file, which includes plugins in the form of .so files, which also execute as root.

- [https://github.com/Live-Hack-CVE/CVE-2022-37393](https://github.com/Live-Hack-CVE/CVE-2022-37393) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37393.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37393.svg)


## CVE-2022-37313
 OX App Suite through 7.10.6 allows SSRF because the anti-SSRF protection mechanism only checks the first DNS AA or AAAA record.

- [https://github.com/Live-Hack-CVE/CVE-2022-37313](https://github.com/Live-Hack-CVE/CVE-2022-37313) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37313.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37313.svg)


## CVE-2022-37312
 OX App Suite through 7.10.6 has Uncontrolled Resource Consumption via a large request body containing a redirect URL to the deferrer servlet.

- [https://github.com/Live-Hack-CVE/CVE-2022-37312](https://github.com/Live-Hack-CVE/CVE-2022-37312) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37312.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37312.svg)


## CVE-2022-37311
 OX App Suite through 7.10.6 has Uncontrolled Resource Consumption via a large location request parameter to the redirect servlet.

- [https://github.com/Live-Hack-CVE/CVE-2022-37311](https://github.com/Live-Hack-CVE/CVE-2022-37311) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37311.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37311.svg)


## CVE-2022-37310
 OX App Suite through 7.10.6 allows XSS via a malicious capability to the metrics or help module, as demonstrated by a /#!!&amp;app=io.ox/files&amp;cap= URI.

- [https://github.com/Live-Hack-CVE/CVE-2022-37310](https://github.com/Live-Hack-CVE/CVE-2022-37310) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37310.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37310.svg)


## CVE-2022-37309
 OX App Suite through 7.10.6 allows XSS via script code within a contact that has an e-mail address but lacks a name.

- [https://github.com/Live-Hack-CVE/CVE-2022-37309](https://github.com/Live-Hack-CVE/CVE-2022-37309) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37309.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37309.svg)


## CVE-2022-37308
 OX App Suite through 7.10.6 allows XSS via HTML in text/plain e-mail messages.

- [https://github.com/Live-Hack-CVE/CVE-2022-37308](https://github.com/Live-Hack-CVE/CVE-2022-37308) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37308.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37308.svg)


## CVE-2022-37307
 OX App Suite through 7.10.6 allows XSS via XHTML CDATA for a snippet, as demonstrated by the onerror attribute of an IMG element within an e-mail signature.

- [https://github.com/Live-Hack-CVE/CVE-2022-37307](https://github.com/Live-Hack-CVE/CVE-2022-37307) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37307.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37307.svg)


## CVE-2022-37254
 DolphinPHP 1.5.1 is vulnerable to Cross Site Scripting (XSS) via Background - &gt; System - &gt; system function - &gt; configuration management.

- [https://github.com/Live-Hack-CVE/CVE-2022-37254](https://github.com/Live-Hack-CVE/CVE-2022-37254) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37254.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37254.svg)


## CVE-2022-37245
 MDaemon Technologies SecurityGateway for Email Servers 8.5.2 is vulnerable to Cross Site Scripting (XSS) via the Blacklist endpoint.

- [https://github.com/Live-Hack-CVE/CVE-2022-37245](https://github.com/Live-Hack-CVE/CVE-2022-37245) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37245.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37245.svg)


## CVE-2022-37243
 MDaemon Technologies SecurityGateway for Email Servers 8.5.2 is vulnerable to Cross Site Scripting (XSS) via the whitelist endpoint.

- [https://github.com/Live-Hack-CVE/CVE-2022-37243](https://github.com/Live-Hack-CVE/CVE-2022-37243) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37243.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37243.svg)


## CVE-2022-37241
 MDaemon Technologies SecurityGateway for Email Servers 8.5.2 is vulnerable to Cross Site Scripting (XSS) via the data_leak_list_ajax endpoint.

- [https://github.com/Live-Hack-CVE/CVE-2022-37241](https://github.com/Live-Hack-CVE/CVE-2022-37241) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37241.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37241.svg)


## CVE-2022-37239
 MDaemon Technologies SecurityGateway for Email Servers 8.5.2 is vulnerable to Cross Site Scripting (XSS) via the rulles_list_ajax endpoint.

- [https://github.com/Live-Hack-CVE/CVE-2022-37239](https://github.com/Live-Hack-CVE/CVE-2022-37239) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37239.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37239.svg)


## CVE-2022-37223
 JFinal CMS 5.1.0 is vulnerable to SQL Injection via /jfinal_cms/system/role/list.

- [https://github.com/Live-Hack-CVE/CVE-2022-37223](https://github.com/Live-Hack-CVE/CVE-2022-37223) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37223.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37223.svg)


## CVE-2022-37199
 JFinal CMS 5.1.0 is vulnerable to SQL Injection via /jfinal_cms/system/user/list.

- [https://github.com/Live-Hack-CVE/CVE-2022-37199](https://github.com/Live-Hack-CVE/CVE-2022-37199) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37199.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37199.svg)


## CVE-2022-37175
 Tenda ac15 firmware V15.03.05.18 httpd server has stack buffer overflow in /goform/formWifiBasicSet.

- [https://github.com/Live-Hack-CVE/CVE-2022-37175](https://github.com/Live-Hack-CVE/CVE-2022-37175) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37175.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37175.svg)


## CVE-2022-37153
 An issue was discovered in Artica Proxy 4.30.000000. There is a XSS vulnerability via the password parameter in /fw.login.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-37153](https://github.com/Live-Hack-CVE/CVE-2022-37153) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37153.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37153.svg)


## CVE-2022-37152
 An issue was discovered in Online Diagnostic Lab Management System 1.0, There is a SQL injection vulnerability via &quot;dob&quot; parameter in &quot;/classes/Users.php?f=save_client&quot;

- [https://github.com/Live-Hack-CVE/CVE-2022-37152](https://github.com/Live-Hack-CVE/CVE-2022-37152) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37152.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37152.svg)


## CVE-2022-37151
 There is an unauthorized access vulnerability in Online Diagnostic Lab Management System 1.0.

- [https://github.com/Live-Hack-CVE/CVE-2022-37151](https://github.com/Live-Hack-CVE/CVE-2022-37151) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37151.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37151.svg)


## CVE-2022-37150
 An issue was discovered in Online Diagnostic Lab Management System 1.0. There is a stored XSS vulnerability via firstname, address, middlename, lastname , gender, email, contact parameters.

- [https://github.com/Live-Hack-CVE/CVE-2022-37150](https://github.com/Live-Hack-CVE/CVE-2022-37150) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37150.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37150.svg)


## CVE-2022-37134
 D-link DIR-816 A2_v1.10CNB04.img is vulnerable to Buffer Overflow via /goform/form2Wan.cgi. When wantype is 3, l2tp_usrname will be decrypted by base64, and the result will be stored in v94, which does not check the size of l2tp_usrname, resulting in stack overflow.

- [https://github.com/Live-Hack-CVE/CVE-2022-37134](https://github.com/Live-Hack-CVE/CVE-2022-37134) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37134.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37134.svg)


## CVE-2022-37133
 D-link DIR-816 A2_v1.10CNB04.img reboots the router without authentication via /goform/doReboot. No authentication is required, and reboot is executed when the function returns at the end.

- [https://github.com/Live-Hack-CVE/CVE-2022-37133](https://github.com/Live-Hack-CVE/CVE-2022-37133) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37133.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37133.svg)


## CVE-2022-37113
 Bluecms 1.6 has SQL injection in line 132 of admin/area.php

- [https://github.com/Live-Hack-CVE/CVE-2022-37113](https://github.com/Live-Hack-CVE/CVE-2022-37113) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37113.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37113.svg)


## CVE-2022-37112
 BlueCMS 1.6 has SQL injection in line 55 of admin/model.php

- [https://github.com/Live-Hack-CVE/CVE-2022-37112](https://github.com/Live-Hack-CVE/CVE-2022-37112) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37112.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37112.svg)


## CVE-2022-37111
 BlueCMS 1.6 has SQL injection in line 132 of admin/article.php

- [https://github.com/Live-Hack-CVE/CVE-2022-37111](https://github.com/Live-Hack-CVE/CVE-2022-37111) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37111.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37111.svg)


## CVE-2022-37084
 TOTOLINK A7000R V9.1.0u.6115_B20201022 was discovered to contain a stack overflow via the sPort parameter at the addEffect function.

- [https://github.com/Live-Hack-CVE/CVE-2022-37084](https://github.com/Live-Hack-CVE/CVE-2022-37084) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37084.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37084.svg)


## CVE-2022-37083
 TOTOLINK A7000R V9.1.0u.6115_B20201022 was discovered to contain a command injection vulnerability via the ip parameter at the function setDiagnosisCfg.

- [https://github.com/Live-Hack-CVE/CVE-2022-37083](https://github.com/Live-Hack-CVE/CVE-2022-37083) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37083.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37083.svg)


## CVE-2022-37082
 TOTOLINK A7000R V9.1.0u.6115_B20201022 was discovered to contain a command injection vulnerability via the host_time parameter at the function NTPSyncWithHost.

- [https://github.com/Live-Hack-CVE/CVE-2022-37082](https://github.com/Live-Hack-CVE/CVE-2022-37082) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37082.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37082.svg)


## CVE-2022-37081
 TOTOLINK A7000R V9.1.0u.6115_B20201022 was discovered to contain a command injection vulnerability via the command parameter at setting/setTracerouteCfg.

- [https://github.com/Live-Hack-CVE/CVE-2022-37081](https://github.com/Live-Hack-CVE/CVE-2022-37081) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37081.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37081.svg)


## CVE-2022-37080
 TOTOLINK A7000R V9.1.0u.6115_B20201022 was discovered to contain a stack overflow via the command parameter at setting/setTracerouteCfg.

- [https://github.com/Live-Hack-CVE/CVE-2022-37080](https://github.com/Live-Hack-CVE/CVE-2022-37080) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37080.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37080.svg)


## CVE-2022-37079
 TOTOLINK A7000R V9.1.0u.6115_B20201022 was discovered to contain a command injection vulnerability via the hostName parameter in the function setOpModeCfg.

- [https://github.com/Live-Hack-CVE/CVE-2022-37079](https://github.com/Live-Hack-CVE/CVE-2022-37079) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37079.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37079.svg)


## CVE-2022-37078
 TOTOLINK A7000R V9.1.0u.6115_B20201022 was discovered to contain a command injection vulnerability via the lang parameter at /setting/setLanguageCfg.

- [https://github.com/Live-Hack-CVE/CVE-2022-37078](https://github.com/Live-Hack-CVE/CVE-2022-37078) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37078.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37078.svg)


## CVE-2022-37076
 TOTOLINK A7000R V9.1.0u.6115_B20201022 was discovered to contain a command injection vulnerability via the FileName parameter in the function UploadFirmwareFile.

- [https://github.com/Live-Hack-CVE/CVE-2022-37076](https://github.com/Live-Hack-CVE/CVE-2022-37076) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37076.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37076.svg)


## CVE-2022-37075
 TOTOLink A7000R V9.1.0u.6115_B20201022 was discovered to contain a stack overflow via the ip parameter in the function setDiagnosisCfg.

- [https://github.com/Live-Hack-CVE/CVE-2022-37075](https://github.com/Live-Hack-CVE/CVE-2022-37075) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37075.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37075.svg)


## CVE-2022-37074
 H3C GR-1200W MiniGRW1A0V100R006 was discovered to contain a stack overflow via the function switch_debug_info_set.

- [https://github.com/Live-Hack-CVE/CVE-2022-37074](https://github.com/Live-Hack-CVE/CVE-2022-37074) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37074.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37074.svg)


## CVE-2022-37044
 In Zimbra Collaboration Suite (ZCS) 8.8.15, the URL at /h/search?action accepts parameters called extra, title, and onload that are partially sanitised and lead to reflected XSS that allows executing arbitrary JavaScript on the victim's machine.

- [https://github.com/Live-Hack-CVE/CVE-2022-37044](https://github.com/Live-Hack-CVE/CVE-2022-37044) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37044.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37044.svg)


## CVE-2022-37043
 An issue was discovered in the webmail component in Zimbra Collaboration Suite (ZCS) 8.8.15 and 9.0. When using preauth, CSRF tokens are not checked on some POST endpoints. Thus, when an authenticated user views an attacker-controlled page, a request will be sent to the application that appears to be intended. The CSRF token is omitted from the request, but the request still succeeds.

- [https://github.com/Live-Hack-CVE/CVE-2022-37043](https://github.com/Live-Hack-CVE/CVE-2022-37043) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37043.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37043.svg)


## CVE-2022-37041
 An issue was discovered in ProxyServlet.java in the /proxy servlet in Zimbra Collaboration Suite (ZCS) 8.8.15 and 9.0. The value of the X-Forwarded-Host header overwrites the value of the Host header in proxied requests. The value of X-Forwarded-Host header is not checked against the whitelist of hosts that ZCS is allowed to proxy to (the zimbraProxyAllowedDomains setting).

- [https://github.com/Live-Hack-CVE/CVE-2022-37041](https://github.com/Live-Hack-CVE/CVE-2022-37041) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37041.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37041.svg)


## CVE-2022-37025
 An improper privilege management vulnerability in McAfee Security Scan Plus (MSS+) before 4.1.262.1 could allow a local user to modify a configuration file and perform a LOLBin (Living off the land) attack. This could result in the user gaining elevated permissions and being able to execute arbitrary code due to lack of an integrity check of the configuration file.

- [https://github.com/Live-Hack-CVE/CVE-2022-37025](https://github.com/Live-Hack-CVE/CVE-2022-37025) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37025.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37025.svg)


## CVE-2022-37024
 Zoho ManageEngine OpManager, OpManager Plus, OpManager MSP, Network Configuration Manager, NetFlow Analyzer, and OpUtils before 2022-07-29 through 2022-07-30 ( 125658, 126003, 126105, and 126120) allow authenticated users to make database changes that lead to remote code execution.

- [https://github.com/Live-Hack-CVE/CVE-2022-37024](https://github.com/Live-Hack-CVE/CVE-2022-37024) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37024.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37024.svg)


## CVE-2022-36947
 Unsafe Parsing of a PNG tRNS chunk in FastStone Image Viewer through 7.5 results in a stack buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2022-36947](https://github.com/Live-Hack-CVE/CVE-2022-36947) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36947.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36947.svg)


## CVE-2022-36923
 Zoho ManageEngine OpManager, OpManager Plus, OpManager MSP, Network Configuration Manager, NetFlow Analyzer, Firewall Analyzer, and OpUtils before 2022-07-27 through 2022-07-28 (125657, 126002, 126104, and 126118) allow unauthenticated attackers to obtain a user's API key, and then access external APIs.

- [https://github.com/Live-Hack-CVE/CVE-2022-36923](https://github.com/Live-Hack-CVE/CVE-2022-36923) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36923.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36923.svg)


## CVE-2022-36729
 Library Management System v1.0 was discovered to contain a SQL injection vulnerability via the M_Id parameter at /librarian/del.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-36729](https://github.com/Live-Hack-CVE/CVE-2022-36729) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36729.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36729.svg)


## CVE-2022-36728
 Library Management System v1.0 was discovered to contain a SQL injection vulnerability via the RollNo parameter at /staff/delstu.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-36728](https://github.com/Live-Hack-CVE/CVE-2022-36728) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36728.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36728.svg)


## CVE-2022-36727
 Library Management System v1.0 was discovered to contain a SQL injection vulnerability via the bookId parameter at /staff/delete.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-36727](https://github.com/Live-Hack-CVE/CVE-2022-36727) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36727.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36727.svg)


## CVE-2022-36725
 Library Management System v1.0 was discovered to contain a SQL injection vulnerability via the M_Id parameter at /student/dele.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-36725](https://github.com/Live-Hack-CVE/CVE-2022-36725) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36725.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36725.svg)


## CVE-2022-36722
 Library Management System v1.0 was discovered to contain a SQL injection vulnerability via the title parameter at /librarian/history.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-36722](https://github.com/Live-Hack-CVE/CVE-2022-36722) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36722.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36722.svg)


## CVE-2022-36716
 Library Management System v1.0 was discovered to contain a SQL injection vulnerability via the id parameter at /admin/changestock.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-36716](https://github.com/Live-Hack-CVE/CVE-2022-36716) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36716.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36716.svg)


## CVE-2022-36703
 Ingredients Stock Management System v1.0 was discovered to contain a SQL injection vulnerability via the id parameter at /stocks/manage_stockin.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-36703](https://github.com/Live-Hack-CVE/CVE-2022-36703) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36703.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36703.svg)


## CVE-2022-36701
 Ingredients Stock Management System v1.0 was discovered to contain a SQL injection vulnerability via the id parameter at /items/view_item.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-36701](https://github.com/Live-Hack-CVE/CVE-2022-36701) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36701.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36701.svg)


## CVE-2022-36700
 Ingredients Stock Management System v1.0 was discovered to contain a SQL injection vulnerability via the id parameter at /items/manage_item.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-36700](https://github.com/Live-Hack-CVE/CVE-2022-36700) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36700.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36700.svg)


## CVE-2022-36699
 Ingredients Stock Management System v1.0 was discovered to contain a SQL injection vulnerability via the id parameter at /categories/manage_category.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-36699](https://github.com/Live-Hack-CVE/CVE-2022-36699) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36699.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36699.svg)


## CVE-2022-36698
 Ingredients Stock Management System v1.0 was discovered to contain a SQL injection vulnerability via the id parameter at /categories/view_category.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-36698](https://github.com/Live-Hack-CVE/CVE-2022-36698) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36698.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36698.svg)


## CVE-2022-36693
 Ingredients Stock Management System v1.0 was discovered to contain a SQL injection vulnerability via the id parameter at /classes/Master.php?f=delete_item.

- [https://github.com/Live-Hack-CVE/CVE-2022-36693](https://github.com/Live-Hack-CVE/CVE-2022-36693) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36693.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36693.svg)


## CVE-2022-36692
 Ingredients Stock Management System v1.0 was discovered to contain a SQL injection vulnerability via the id parameter at /classes/Master.php?f=delete_category.

- [https://github.com/Live-Hack-CVE/CVE-2022-36692](https://github.com/Live-Hack-CVE/CVE-2022-36692) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36692.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36692.svg)


## CVE-2022-36683
 Simple Task Scheduling System v1.0 was discovered to contain a SQL injection vulnerability via the id parameter at /classes/Master.php?f=delete_payment.

- [https://github.com/Live-Hack-CVE/CVE-2022-36683](https://github.com/Live-Hack-CVE/CVE-2022-36683) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36683.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36683.svg)


## CVE-2022-36682
 Simple Task Scheduling System v1.0 was discovered to contain a SQL injection vulnerability via the id parameter at /classes/Master.php?f=delete_student.

- [https://github.com/Live-Hack-CVE/CVE-2022-36682](https://github.com/Live-Hack-CVE/CVE-2022-36682) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36682.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36682.svg)


## CVE-2022-36681
 Simple Task Scheduling System v1.0 was discovered to contain a SQL injection vulnerability via the id parameter at /classes/Master.php?f=delete_account.

- [https://github.com/Live-Hack-CVE/CVE-2022-36681](https://github.com/Live-Hack-CVE/CVE-2022-36681) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36681.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36681.svg)


## CVE-2022-36680
 Simple Task Scheduling System v1.0 was discovered to contain a SQL injection vulnerability via the id parameter at /classes/Master.php?f=delete_schedule.

- [https://github.com/Live-Hack-CVE/CVE-2022-36680](https://github.com/Live-Hack-CVE/CVE-2022-36680) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36680.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36680.svg)


## CVE-2022-36679
 Simple Task Scheduling System v1.0 was discovered to contain a SQL injection vulnerability via the id parameter at /admin/?page=user/manage_user.

- [https://github.com/Live-Hack-CVE/CVE-2022-36679](https://github.com/Live-Hack-CVE/CVE-2022-36679) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36679.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36679.svg)


## CVE-2022-36678
 Simple Task Scheduling System v1.0 was discovered to contain a SQL injection vulnerability via the id parameter at /classes/Master.php?f=delete_category.

- [https://github.com/Live-Hack-CVE/CVE-2022-36678](https://github.com/Live-Hack-CVE/CVE-2022-36678) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36678.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36678.svg)


## CVE-2022-36606
 Ywoa before v6.1 was discovered to contain a SQL injection vulnerability via /oa/setup/checkPool?database.

- [https://github.com/Live-Hack-CVE/CVE-2022-36606](https://github.com/Live-Hack-CVE/CVE-2022-36606) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36606.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36606.svg)


## CVE-2022-36605
 Yimioa v6.1 was discovered to contain a SQL injection vulnerability via the orderbyGET parameter.

- [https://github.com/Live-Hack-CVE/CVE-2022-36605](https://github.com/Live-Hack-CVE/CVE-2022-36605) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36605.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36605.svg)


## CVE-2022-36599
 Mingsoft MCMS 5.2.8 was discovered to contain a SQL injection vulnerability in /mdiy/model/delete URI via models Lists.

- [https://github.com/Live-Hack-CVE/CVE-2022-36599](https://github.com/Live-Hack-CVE/CVE-2022-36599) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36599.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36599.svg)


## CVE-2022-36579
 Wellcms 2.2.0 is vulnerable to Cross Site Request Forgery (CSRF).

- [https://github.com/Live-Hack-CVE/CVE-2022-36579](https://github.com/Live-Hack-CVE/CVE-2022-36579) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36579.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36579.svg)


## CVE-2022-36578
 jizhicms v2.3.1 has SQL injection in the background.

- [https://github.com/Live-Hack-CVE/CVE-2022-36578](https://github.com/Live-Hack-CVE/CVE-2022-36578) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36578.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36578.svg)


## CVE-2022-36577
 An issue was discovered in jizhicms v2.3.1. There is a CSRF vulnerability that can add a admin.

- [https://github.com/Live-Hack-CVE/CVE-2022-36577](https://github.com/Live-Hack-CVE/CVE-2022-36577) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36577.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36577.svg)


## CVE-2022-36530
 An issue was discovered in rageframe2 2.6.37. There is a XSS vulnerability in the user agent related parameters of the info.php page.

- [https://github.com/Live-Hack-CVE/CVE-2022-36530](https://github.com/Live-Hack-CVE/CVE-2022-36530) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36530.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36530.svg)


## CVE-2022-36526
 D-Link GO-RT-AC750 GORTAC750_revA_v101b03 &amp; GO-RT-AC750_revB_FWv200b02 is vulnerable to Authentication Bypass via function phpcgi_main in cgibin.

- [https://github.com/Live-Hack-CVE/CVE-2022-36526](https://github.com/Live-Hack-CVE/CVE-2022-36526) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36526.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36526.svg)


## CVE-2022-36525
 D-Link Go-RT-AC750 GORTAC750_revA_v101b03 &amp; GO-RT-AC750_revB_FWv200b02 is vulnerable to Buffer Overflow via authenticationcgi_main.

- [https://github.com/Live-Hack-CVE/CVE-2022-36525](https://github.com/Live-Hack-CVE/CVE-2022-36525) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36525.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36525.svg)


## CVE-2022-36524
 D-Link GO-RT-AC750 GORTAC750_revA_v101b03 &amp; GO-RT-AC750_revB_FWv200b02 is vulnerable to Static Default Credentials via /etc/init0.d/S80telnetd.sh.

- [https://github.com/Live-Hack-CVE/CVE-2022-36524](https://github.com/Live-Hack-CVE/CVE-2022-36524) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36524.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36524.svg)


## CVE-2022-36523
 D-Link Go-RT-AC750 GORTAC750_revA_v101b03 &amp; GO-RT-AC750_revB_FWv200b02 is vulnerable to command injection via /htdocs/upnpinc/gena.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-36523](https://github.com/Live-Hack-CVE/CVE-2022-36523) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36523.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36523.svg)


## CVE-2022-36488
 TOTOLINK N350RT V9.3.5u.6139_B20201216 was discovered to contain a stack overflow via the sPort parameter in the function setIpPortFilterRules.

- [https://github.com/Live-Hack-CVE/CVE-2022-36488](https://github.com/Live-Hack-CVE/CVE-2022-36488) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36488.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36488.svg)


## CVE-2022-36487
 TOTOLINK N350RT V9.3.5u.6139_B20201216 was discovered to contain a command injection vulnerability via the command parameter in the function setTracerouteCfg.

- [https://github.com/Live-Hack-CVE/CVE-2022-36487](https://github.com/Live-Hack-CVE/CVE-2022-36487) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36487.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36487.svg)


## CVE-2022-36486
 TOTOLINK N350RT V9.3.5u.6139_B20201216 was discovered to contain a command injection vulnerability via the FileName parameter in the function UploadFirmwareFile.

- [https://github.com/Live-Hack-CVE/CVE-2022-36486](https://github.com/Live-Hack-CVE/CVE-2022-36486) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36486.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36486.svg)


## CVE-2022-36485
 TOTOLINK N350RT V9.3.5u.6139_B20201216 was discovered to contain a command injection vulnerability via the hostName parameter in the function setOpModeCfg.

- [https://github.com/Live-Hack-CVE/CVE-2022-36485](https://github.com/Live-Hack-CVE/CVE-2022-36485) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36485.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36485.svg)


## CVE-2022-36484
 TOTOLINK N350RT V9.3.5u.6139_B20201216 was discovered to contain a stack overflow via the function setDiagnosisCfg.

- [https://github.com/Live-Hack-CVE/CVE-2022-36484](https://github.com/Live-Hack-CVE/CVE-2022-36484) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36484.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36484.svg)


## CVE-2022-36483
 TOTOLINK N350RT V9.3.5u.6139_B20201216 was discovered to contain a stack overflow via the pppoeUser parameter.

- [https://github.com/Live-Hack-CVE/CVE-2022-36483](https://github.com/Live-Hack-CVE/CVE-2022-36483) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36483.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36483.svg)


## CVE-2022-36482
 TOTOLINK N350RT V9.3.5u.6139_B20201216 was discovered to contain a command injection vulnerability via the lang parameter in the function setLanguageCfg.

- [https://github.com/Live-Hack-CVE/CVE-2022-36482](https://github.com/Live-Hack-CVE/CVE-2022-36482) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36482.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36482.svg)


## CVE-2022-36481
 TOTOLINK N350RT V9.3.5u.6139_B20201216 was discovered to contain a command injection vulnerability via the ip parameter in the function setDiagnosisCfg.

- [https://github.com/Live-Hack-CVE/CVE-2022-36481](https://github.com/Live-Hack-CVE/CVE-2022-36481) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36481.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36481.svg)


## CVE-2022-36480
 TOTOLINK N350RT V9.3.5u.6139_B20201216 was discovered to contain a stack overflow via the command parameter in the function setTracerouteCfg.

- [https://github.com/Live-Hack-CVE/CVE-2022-36480](https://github.com/Live-Hack-CVE/CVE-2022-36480) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36480.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36480.svg)


## CVE-2022-36479
 TOTOLINK N350RT V9.3.5u.6139_B20201216 was discovered to contain a command injection vulnerability via the host_time parameter in the function NTPSyncWithHost.

- [https://github.com/Live-Hack-CVE/CVE-2022-36479](https://github.com/Live-Hack-CVE/CVE-2022-36479) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36479.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36479.svg)


## CVE-2022-36478
 H3C B5 Mini B5MiniV100R005 was discovered to contain a stack overflow via the function Edit_BasicSSID.

- [https://github.com/Live-Hack-CVE/CVE-2022-36478](https://github.com/Live-Hack-CVE/CVE-2022-36478) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36478.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36478.svg)


## CVE-2022-36477
 H3C B5 Mini B5MiniV100R005 was discovered to contain a stack overflow via the function AddWlanMacList.

- [https://github.com/Live-Hack-CVE/CVE-2022-36477](https://github.com/Live-Hack-CVE/CVE-2022-36477) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36477.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36477.svg)


## CVE-2022-36475
 H3C B5 Mini B5MiniV100R005 was discovered to contain a stack overflow via the function AddMacList.

- [https://github.com/Live-Hack-CVE/CVE-2022-36475](https://github.com/Live-Hack-CVE/CVE-2022-36475) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36475.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36475.svg)


## CVE-2022-36474
 H3C B5 Mini B5MiniV100R005 was discovered to contain a stack overflow via the function WlanWpsSet.

- [https://github.com/Live-Hack-CVE/CVE-2022-36474](https://github.com/Live-Hack-CVE/CVE-2022-36474) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36474.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36474.svg)


## CVE-2022-36473
 H3C B5 Mini B5MiniV100R005 was discovered to contain a stack overflow via the function Edit_BasicSSID_5G.

- [https://github.com/Live-Hack-CVE/CVE-2022-36473](https://github.com/Live-Hack-CVE/CVE-2022-36473) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36473.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36473.svg)


## CVE-2022-36472
 H3C B5 Mini B5MiniV100R005 was discovered to contain a stack overflow via the function SetMobileAPInfoById.

- [https://github.com/Live-Hack-CVE/CVE-2022-36472](https://github.com/Live-Hack-CVE/CVE-2022-36472) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36472.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36472.svg)


## CVE-2022-36471
 H3C B5 Mini B5MiniV100R005 was discovered to contain a stack overflow via the function SetMacAccessMode.

- [https://github.com/Live-Hack-CVE/CVE-2022-36471](https://github.com/Live-Hack-CVE/CVE-2022-36471) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36471.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36471.svg)


## CVE-2022-36470
 H3C B5 Mini B5MiniV100R005 was discovered to contain a stack overflow via the function SetAP5GWifiById.

- [https://github.com/Live-Hack-CVE/CVE-2022-36470](https://github.com/Live-Hack-CVE/CVE-2022-36470) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36470.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36470.svg)


## CVE-2022-36469
 H3C B5 Mini B5MiniV100R005 was discovered to contain a stack overflow via the function SetAPWifiorLedInfoById.

- [https://github.com/Live-Hack-CVE/CVE-2022-36469](https://github.com/Live-Hack-CVE/CVE-2022-36469) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36469.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36469.svg)


## CVE-2022-36468
 H3C B5 Mini B5MiniV100R005 was discovered to contain a stack overflow via the function Asp_SetTimingtimeWifiAndLed.

- [https://github.com/Live-Hack-CVE/CVE-2022-36468](https://github.com/Live-Hack-CVE/CVE-2022-36468) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36468.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36468.svg)


## CVE-2022-36467
 H3C B5 Mini B5MiniV100R005 was discovered to contain a stack overflow via the function EditMacList.d.

- [https://github.com/Live-Hack-CVE/CVE-2022-36467](https://github.com/Live-Hack-CVE/CVE-2022-36467) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36467.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36467.svg)


## CVE-2022-36466
 TOTOLINK A3700R V9.1.2u.6134_B20201202 was discovered to contain a stack overflow via the ip parameter in the function setDiagnosisCfg.

- [https://github.com/Live-Hack-CVE/CVE-2022-36466](https://github.com/Live-Hack-CVE/CVE-2022-36466) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36466.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36466.svg)


## CVE-2022-36465
 TOTOLINK A3700R V9.1.2u.6134_B20201202 was discovered to contain a stack overflow via the pppoeUser parameter.

- [https://github.com/Live-Hack-CVE/CVE-2022-36465](https://github.com/Live-Hack-CVE/CVE-2022-36465) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36465.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36465.svg)


## CVE-2022-36464
 TOTOLINK A3700R V9.1.2u.6134_B20201202 was discovered to contain a stack overflow via the sPort parameter in the function setIpPortFilterRules.

- [https://github.com/Live-Hack-CVE/CVE-2022-36464](https://github.com/Live-Hack-CVE/CVE-2022-36464) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36464.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36464.svg)


## CVE-2022-36463
 TOTOLINK A3700R V9.1.2u.6134_B20201202 was discovered to contain a stack overflow via the command parameter in the function setTracerouteCfg.

- [https://github.com/Live-Hack-CVE/CVE-2022-36463](https://github.com/Live-Hack-CVE/CVE-2022-36463) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36463.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36463.svg)


## CVE-2022-36462
 TOTOLINK A3700R V9.1.2u.6134_B20201202 was discovered to contain a stack overflow via the lang parameter in the function setLanguageCfg.

- [https://github.com/Live-Hack-CVE/CVE-2022-36462](https://github.com/Live-Hack-CVE/CVE-2022-36462) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36462.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36462.svg)


## CVE-2022-36461
 TOTOLINK A3700R V9.1.2u.6134_B20201202 was discovered to contain a command injection vulnerability via the hostName parameter in the function setOpModeCfg.

- [https://github.com/Live-Hack-CVE/CVE-2022-36461](https://github.com/Live-Hack-CVE/CVE-2022-36461) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36461.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36461.svg)


## CVE-2022-36460
 TOTOLINK A3700R V9.1.2u.6134_B20201202 was discovered to contain a command injection vulnerability via the FileName parameter in the function UploadFirmwareFile.

- [https://github.com/Live-Hack-CVE/CVE-2022-36460](https://github.com/Live-Hack-CVE/CVE-2022-36460) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36460.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36460.svg)


## CVE-2022-36459
 TOTOLINK A3700R V9.1.2u.6134_B20201202 was discovered to contain a command injection vulnerability via the host_time parameter in the function NTPSyncWithHost.

- [https://github.com/Live-Hack-CVE/CVE-2022-36459](https://github.com/Live-Hack-CVE/CVE-2022-36459) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36459.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36459.svg)


## CVE-2022-36458
 TOTOLINK A3700R V9.1.2u.6134_B20201202 was discovered to contain a command injection vulnerability via the command parameter in the function setTracerouteCfg.

- [https://github.com/Live-Hack-CVE/CVE-2022-36458](https://github.com/Live-Hack-CVE/CVE-2022-36458) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36458.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36458.svg)


## CVE-2022-36456
 TOTOLink A720R V4.1.5cu.532_B20210610 was discovered to contain a command injection vulnerability via the username parameter in /cstecgi.cgi.

- [https://github.com/Live-Hack-CVE/CVE-2022-36456](https://github.com/Live-Hack-CVE/CVE-2022-36456) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36456.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36456.svg)


## CVE-2022-36405
 Authenticated (contributor+) Stored Cross-Site Scripting (XSS) vulnerability in amCharts: Charts and Maps plugin &lt;= 1.4 at WordPress.

- [https://github.com/Live-Hack-CVE/CVE-2022-36405](https://github.com/Live-Hack-CVE/CVE-2022-36405) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36405.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36405.svg)


## CVE-2022-36394
 Authenticated (author+) SQL Injection (SQLi) vulnerability in Contest Gallery plugin &lt;= 17.0.4 at WordPress.

- [https://github.com/Live-Hack-CVE/CVE-2022-36394](https://github.com/Live-Hack-CVE/CVE-2022-36394) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36394.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36394.svg)


## CVE-2022-36389
 Cross-Site Request Forgery (CSRF) vulnerability in WordPlus Better Messages plugin &lt;= 1.9.9.148 at WordPress.

- [https://github.com/Live-Hack-CVE/CVE-2022-36389](https://github.com/Live-Hack-CVE/CVE-2022-36389) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36389.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36389.svg)


## CVE-2022-36381
 OS command injection vulnerability in Nintendo Wi-Fi Network Adaptor WAP-001 All versions allows an attacker with an administrative privilege to execute arbitrary OS commands via unspecified vectors.

- [https://github.com/Live-Hack-CVE/CVE-2022-36381](https://github.com/Live-Hack-CVE/CVE-2022-36381) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36381.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36381.svg)


## CVE-2022-36379
 Cross-Site Request Forgery (CSRF) leading to plugin settings update in YooMoney &#1070;Kassa &#1076;&#1083;&#1103; WooCommerce plugin &lt;= 2.3.0 at WordPress.

- [https://github.com/Live-Hack-CVE/CVE-2022-36379](https://github.com/Live-Hack-CVE/CVE-2022-36379) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36379.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36379.svg)


## CVE-2022-36350
 Stored cross-site scripting vulnerability in PukiWiki versions 1.3.1 to 1.5.3 allows a remote attacker to inject an arbitrary script via unspecified vectors.

- [https://github.com/Live-Hack-CVE/CVE-2022-36350](https://github.com/Live-Hack-CVE/CVE-2022-36350) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36350.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36350.svg)


## CVE-2022-36347
 Authenticated (admin+) Stored Cross-Site Scripting (XSS) vulnerability in Alpine Press Alpine PhotoTile for Pinterest plugin &lt;= 1.3.1 at WordPress.

- [https://github.com/Live-Hack-CVE/CVE-2022-36347](https://github.com/Live-Hack-CVE/CVE-2022-36347) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36347.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36347.svg)


## CVE-2022-36346
 Multiple Cross-Site Request Forgery (CSRF) vulnerabilities in Max Foundry MaxButtons plugin &lt;= 9.2 at WordPress.

- [https://github.com/Live-Hack-CVE/CVE-2022-36346](https://github.com/Live-Hack-CVE/CVE-2022-36346) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36346.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36346.svg)


## CVE-2022-36344
 An unquoted search path vulnerability exists in 'JustSystems JUST Online Update for J-License' bundled with multiple products for corporate users as in Ichitaro through Pro5 and others. Since the affected product starts another program with an unquoted file path, a malicious file may be executed with the privilege of the Windows service if it is placed in a certain path. Affected products are bundled with the following product series: Office and Office Integrated Software, ATOK, Hanako, JUST PDF, Shuriken, Homepage Builder, JUST School, JUST Smile Class, JUST Smile, JUST Frontier, JUST Jump, and Tri-De DetaProtect.

- [https://github.com/Live-Hack-CVE/CVE-2022-36344](https://github.com/Live-Hack-CVE/CVE-2022-36344) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36344.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36344.svg)


## CVE-2022-36341
 Authenticated (subscriber+) plugin settings change leading to Stored Cross-Site Scripting (XSS) vulnerability in Akash soni's AS &#8211; Create Pinterest Pinboard Pages plugin &lt;= 1.0 at WordPress.

- [https://github.com/Live-Hack-CVE/CVE-2022-36341](https://github.com/Live-Hack-CVE/CVE-2022-36341) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36341.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36341.svg)


## CVE-2022-36312
 Airspan AirVelocity 1500 software version 15.18.00.2511 lacks CSRF protections in the eNodeB's web management UI. This issue may affect other AirVelocity and AirSpeed models.

- [https://github.com/Live-Hack-CVE/CVE-2022-36312](https://github.com/Live-Hack-CVE/CVE-2022-36312) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36312.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36312.svg)


## CVE-2022-36311
 Airspan AirVelocity 1500 prior to software version 15.18.00.2511 is vulnerable to injection leading to XSS in the SNMP community field in the eNodeB's web management UI. This issue may affect other AirVelocity and AirSpeed models.

- [https://github.com/Live-Hack-CVE/CVE-2022-36311](https://github.com/Live-Hack-CVE/CVE-2022-36311) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36311.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36311.svg)


## CVE-2022-36310
 Airspan AirVelocity 1500 software prior to version 15.18.00.2511 had NET-SNMP-EXTEND-MIB enabled on its snmpd service, enabling an attacker with SNMP write abilities to execute commands as root on the eNodeB. This issue may affect other AirVelocity and AirSpeed models.

- [https://github.com/Live-Hack-CVE/CVE-2022-36310](https://github.com/Live-Hack-CVE/CVE-2022-36310) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36310.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36310.svg)


## CVE-2022-36309
 Airspan AirVelocity 1500 software versions prior to 15.18.00.2511 have a root command injection vulnerability in the ActiveBank parameter of the recoverySubmit.cgi script running on the eNodeB's web management UI. This issue may affect other AirVelocity and AirSpeed models.

- [https://github.com/Live-Hack-CVE/CVE-2022-36309](https://github.com/Live-Hack-CVE/CVE-2022-36309) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36309.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36309.svg)


## CVE-2022-36308
 Airspan AirVelocity 1500 web management UI displays SNMP credentials in plaintext on software versions older than 15.18.00.2511, and stores SNMPv3 credentials unhashed on the filesystem, enabling anyone with web access to use these credentials to manipulate the eNodeB over SNMP. This issue may affect other AirVelocity and AirSpeed models.

- [https://github.com/Live-Hack-CVE/CVE-2022-36308](https://github.com/Live-Hack-CVE/CVE-2022-36308) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36308.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36308.svg)


## CVE-2022-36307
 The AirVelocity 1500 prints SNMP credentials on its physically accessible serial port during boot. This was fixed in AirVelocity 1500 software version 15.18.00.2511 and may affect other AirVelocity and AirSpeed models.

- [https://github.com/Live-Hack-CVE/CVE-2022-36307](https://github.com/Live-Hack-CVE/CVE-2022-36307) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36307.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36307.svg)


## CVE-2022-36306
 An authenticated attacker can enumerate and download sensitive files, including the eNodeB's web management UI's TLS private key, the web server binary, and the web server configuration file. These vulnerabilities were found in AirVelocity 1500 running software version 9.3.0.01249, were still present in 15.18.00.2511, and may affect other AirVelocity and AirSpeed models.

- [https://github.com/Live-Hack-CVE/CVE-2022-36306](https://github.com/Live-Hack-CVE/CVE-2022-36306) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36306.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36306.svg)


## CVE-2022-36293
 Buffer overflow vulnerability in Nintendo Wi-Fi Network Adaptor WAP-001 All versions allows an attacker with an administrative privilege to execute arbitrary code via unspecified vectors.

- [https://github.com/Live-Hack-CVE/CVE-2022-36293](https://github.com/Live-Hack-CVE/CVE-2022-36293) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36293.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36293.svg)


## CVE-2022-36292
 Cross-Site Request Forgery (CSRF) vulnerabilities in WPChill Gallery PhotoBlocks plugin &lt;= 1.2.6 at WordPress.

- [https://github.com/Live-Hack-CVE/CVE-2022-36292](https://github.com/Live-Hack-CVE/CVE-2022-36292) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36292.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36292.svg)


## CVE-2022-36288
 Multiple Cross-Site Request Forgery (CSRF) vulnerabilities in W3 Eden Download Manager plugin &lt;= 3.2.48 at WordPress.

- [https://github.com/Live-Hack-CVE/CVE-2022-36288](https://github.com/Live-Hack-CVE/CVE-2022-36288) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36288.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36288.svg)


## CVE-2022-36285
 Authenticated Arbitrary File Upload vulnerability in dmitrylitvinov Uploading SVG, WEBP and ICO files plugin &lt;= 1.0.1 at WordPress.

- [https://github.com/Live-Hack-CVE/CVE-2022-36285](https://github.com/Live-Hack-CVE/CVE-2022-36285) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36285.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36285.svg)


## CVE-2022-36282
 Authenticated (editor+) Stored Cross-Site Scripting (XSS) vulnerability in Roman Pronskiy's Search Exclude plugin &lt;= 1.2.6 at WordPress.

- [https://github.com/Live-Hack-CVE/CVE-2022-36282](https://github.com/Live-Hack-CVE/CVE-2022-36282) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36282.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36282.svg)


## CVE-2022-36273
 Tenda AC9 V15.03.2.21_cn is vulnerable to command injection via goform/SetSysTimeCfg.

- [https://github.com/Live-Hack-CVE/CVE-2022-36273](https://github.com/Live-Hack-CVE/CVE-2022-36273) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36273.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36273.svg)


## CVE-2022-36272
 Mingsoft MCMS 5.2.8 was discovered to contain a SQL injection vulnerability in /mdiy/page/verify URI via fieldName parameter.

- [https://github.com/Live-Hack-CVE/CVE-2022-36272](https://github.com/Live-Hack-CVE/CVE-2022-36272) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36272.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36272.svg)


## CVE-2022-36263
 StreamLabs Desktop Application 1.9.0 is vulnerable to Incorrect Access Control via obs64.exe. An attacker can execute arbitrary code via a crafted .exe file.

- [https://github.com/Live-Hack-CVE/CVE-2022-36263](https://github.com/Live-Hack-CVE/CVE-2022-36263) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36263.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36263.svg)


## CVE-2022-36261
 An arbitrary file deletion vulnerability was discovered in taocms 3.0.2, that allows attacker to delete file in server when request url admin.php?action=file&amp;ctrl=del&amp;path=/../../../test.txt

- [https://github.com/Live-Hack-CVE/CVE-2022-36261](https://github.com/Live-Hack-CVE/CVE-2022-36261) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36261.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36261.svg)


## CVE-2022-36251
 Clinic's Patient Management System v1.0 is vulnerable to Cross Site Scripting (XSS) via patients.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-36251](https://github.com/Live-Hack-CVE/CVE-2022-36251) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36251.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36251.svg)


## CVE-2022-36242
 Clinic's Patient Management System v1.0 is vulnerable to SQL Injection via /pms/update_medicine.php?id=.

- [https://github.com/Live-Hack-CVE/CVE-2022-36242](https://github.com/Live-Hack-CVE/CVE-2022-36242) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36242.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36242.svg)


## CVE-2022-36233
 Tenda AC9 V15.03.2.13 is vulnerable to Buffer Overflow via httpd, form_fast_setting_wifi_set. httpd.

- [https://github.com/Live-Hack-CVE/CVE-2022-36233](https://github.com/Live-Hack-CVE/CVE-2022-36233) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36233.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36233.svg)


## CVE-2022-36225
 EyouCMS V1.5.8-UTF8-SP1 is vulnerable to Cross Site Request Forgery (CSRF) via the background, column management function and add.

- [https://github.com/Live-Hack-CVE/CVE-2022-36225](https://github.com/Live-Hack-CVE/CVE-2022-36225) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36225.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36225.svg)


## CVE-2022-36224
 XunRuiCMS V4.5.6 is vulnerable to Cross Site Request Forgery (CSRF).

- [https://github.com/Live-Hack-CVE/CVE-2022-36224](https://github.com/Live-Hack-CVE/CVE-2022-36224) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36224.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36224.svg)


## CVE-2022-36220
 Kiosk breakout (without quit password) in Safe Exam Browser (Windows) &lt;3.4.0, which allows an attacker to achieve code execution via the browsers' print dialog.

- [https://github.com/Live-Hack-CVE/CVE-2022-36220](https://github.com/Live-Hack-CVE/CVE-2022-36220) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36220.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36220.svg)


## CVE-2022-36216
 DedeCMS v5.7.94 - v5.7.97 was discovered to contain a remote code execution vulnerability in member_toadmin.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-36216](https://github.com/Live-Hack-CVE/CVE-2022-36216) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36216.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36216.svg)


## CVE-2022-36215
 DedeBIZ v6 was discovered to contain a remote code execution vulnerability in sys_info.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-36215](https://github.com/Live-Hack-CVE/CVE-2022-36215) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36215.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36215.svg)


## CVE-2022-36198
 Multiple SQL injections detected in Bus Pass Management System 1.0 via buspassms/admin/view-enquiry.php, buspassms/admin/pass-bwdates-reports-details.php, buspassms/admin/changeimage.php, buspassms/admin/search-pass.php, buspassms/admin/edit-category-detail.php, and buspassms/admin/edit-pass-detail.php

- [https://github.com/Live-Hack-CVE/CVE-2022-36198](https://github.com/Live-Hack-CVE/CVE-2022-36198) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36198.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36198.svg)


## CVE-2022-36191
 A heap-buffer-overflow had occurred in function gf_isom_dovi_config_get of isomedia/avc_ext.c:2490, as demonstrated by MP4Box. This vulnerability was fixed in commit fef6242.

- [https://github.com/Live-Hack-CVE/CVE-2022-36191](https://github.com/Live-Hack-CVE/CVE-2022-36191) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36191.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36191.svg)


## CVE-2022-36190
 GPAC mp4box 2.1-DEV-revUNKNOWN-master has a use-after-free vulnerability in function gf_isom_dovi_config_get. This vulnerability was fixed in commit fef6242.

- [https://github.com/Live-Hack-CVE/CVE-2022-36190](https://github.com/Live-Hack-CVE/CVE-2022-36190) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36190.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36190.svg)


## CVE-2022-36186
 A Null Pointer dereference vulnerability exists in GPAC 2.1-DEV-revUNKNOWN-master via the function gf_filter_pid_set_property_full () at filter_core/filter_pid.c:5250,which causes a Denial of Service (DoS). This vulnerability was fixed in commit b43f9d1.

- [https://github.com/Live-Hack-CVE/CVE-2022-36186](https://github.com/Live-Hack-CVE/CVE-2022-36186) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36186.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36186.svg)


## CVE-2022-36171
 MapGIS IGServer 10.5.6.11 is vulnerable to Arbitrary file deletion.

- [https://github.com/Live-Hack-CVE/CVE-2022-36171](https://github.com/Live-Hack-CVE/CVE-2022-36171) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36171.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36171.svg)


## CVE-2022-36170
 MapGIS 10.5 Pro IGServer has hardcoded credentials in the front-end and can lead to escalation of privileges and arbitrary file deletion.

- [https://github.com/Live-Hack-CVE/CVE-2022-36170](https://github.com/Live-Hack-CVE/CVE-2022-36170) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36170.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36170.svg)


## CVE-2022-36157
 XXL-JOB all versions as of 11 July 2022 are vulnerable to Insecure Permissions resulting in the ability to execute admin function with low Privilege account.

- [https://github.com/Live-Hack-CVE/CVE-2022-36157](https://github.com/Live-Hack-CVE/CVE-2022-36157) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36157.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36157.svg)


## CVE-2022-36155
 tifig v0.2.2 was discovered to contain a resource allocation issue via operator new(unsigned long) at asan_new_delete.cpp.

- [https://github.com/Live-Hack-CVE/CVE-2022-36155](https://github.com/Live-Hack-CVE/CVE-2022-36155) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36155.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36155.svg)


## CVE-2022-36153
 tifig v0.2.2 was discovered to contain a segmentation violation via std::vector&lt;unsigned int, std::allocator&lt;unsigned int&gt; &gt;::size() const at /bits/stl_vector.h.

- [https://github.com/Live-Hack-CVE/CVE-2022-36153](https://github.com/Live-Hack-CVE/CVE-2022-36153) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36153.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36153.svg)


## CVE-2022-36152
 tifig v0.2.2 was discovered to contain a memory leak via operator new[](unsigned long) at /asan/asan_new_delete.cpp.

- [https://github.com/Live-Hack-CVE/CVE-2022-36152](https://github.com/Live-Hack-CVE/CVE-2022-36152) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36152.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36152.svg)


## CVE-2022-36151
 tifig v0.2.2 was discovered to contain a segmentation violation via getType() at /common/bbox.cpp.

- [https://github.com/Live-Hack-CVE/CVE-2022-36151](https://github.com/Live-Hack-CVE/CVE-2022-36151) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36151.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36151.svg)


## CVE-2022-36150
 tifig v0.2.2 was discovered to contain a heap-buffer overflow via __asan_memmove at /asan/asan_interceptors_memintrinsics.cpp.

- [https://github.com/Live-Hack-CVE/CVE-2022-36150](https://github.com/Live-Hack-CVE/CVE-2022-36150) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36150.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36150.svg)


## CVE-2022-36149
 tifig v0.2.2 was discovered to contain a heap-use-after-free via temInfoEntry().

- [https://github.com/Live-Hack-CVE/CVE-2022-36149](https://github.com/Live-Hack-CVE/CVE-2022-36149) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36149.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36149.svg)


## CVE-2022-36148
 fdkaac commit 53fe239 was discovered to contain a floating point exception (FPE) via wav_open at /src/wav_reader.c.

- [https://github.com/Live-Hack-CVE/CVE-2022-36148](https://github.com/Live-Hack-CVE/CVE-2022-36148) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36148.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36148.svg)


## CVE-2022-36146
 SWFMill commit 53d7690 was discovered to contain a memory allocation issue via operator new[](unsigned long) at asan_new_delete.cpp.

- [https://github.com/Live-Hack-CVE/CVE-2022-36146](https://github.com/Live-Hack-CVE/CVE-2022-36146) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36146.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36146.svg)


## CVE-2022-36145
 SWFMill commit 53d7690 was discovered to contain a segmentation violation via SWF::Reader::getWord().

- [https://github.com/Live-Hack-CVE/CVE-2022-36145](https://github.com/Live-Hack-CVE/CVE-2022-36145) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36145.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36145.svg)


## CVE-2022-36144
 SWFMill commit 53d7690 was discovered to contain a heap-buffer overflow via base64_encode.

- [https://github.com/Live-Hack-CVE/CVE-2022-36144](https://github.com/Live-Hack-CVE/CVE-2022-36144) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36144.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36144.svg)


## CVE-2022-36143
 SWFMill commit 53d7690 was discovered to contain a heap-buffer overflow via __interceptor_strlen.part at /sanitizer_common/sanitizer_common_interceptors.inc.

- [https://github.com/Live-Hack-CVE/CVE-2022-36143](https://github.com/Live-Hack-CVE/CVE-2022-36143) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36143.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36143.svg)


## CVE-2022-36142
 SWFMill commit 53d7690 was discovered to contain a heap-buffer overflow via SWF::Reader::getU30().

- [https://github.com/Live-Hack-CVE/CVE-2022-36142](https://github.com/Live-Hack-CVE/CVE-2022-36142) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36142.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36142.svg)


## CVE-2022-36141
 SWFMill commit 53d7690 was discovered to contain a segmentation violation via SWF::MethodBody::write(SWF::Writer*, SWF::Context*).

- [https://github.com/Live-Hack-CVE/CVE-2022-36141](https://github.com/Live-Hack-CVE/CVE-2022-36141) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36141.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36141.svg)


## CVE-2022-36140
 SWFMill commit 53d7690 was discovered to contain a segmentation violation via SWF::DeclareFunction2::write(SWF::Writer*, SWF::Context*).

- [https://github.com/Live-Hack-CVE/CVE-2022-36140](https://github.com/Live-Hack-CVE/CVE-2022-36140) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36140.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36140.svg)


## CVE-2022-36139
 SWFMill commit 53d7690 was discovered to contain a heap-buffer overflow via SWF::Writer::writeByte(unsigned char).

- [https://github.com/Live-Hack-CVE/CVE-2022-36139](https://github.com/Live-Hack-CVE/CVE-2022-36139) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36139.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36139.svg)


## CVE-2022-36031
 Directus is a free and open-source data platform for headless content management. The Directus process can be aborted by having an authorized user update the `filename_disk` value to a folder and accessing that file through the `/assets` endpoint. This vulnerability has been patched and release v9.15.0 contains the fix. Users are advised to upgrade. Users unable to upgrade may prevent this problem by making sure no (untrusted) non-admin users have permissions to update the `filename_disk` field on `directus_files`.

- [https://github.com/Live-Hack-CVE/CVE-2022-36031](https://github.com/Live-Hack-CVE/CVE-2022-36031) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36031.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36031.svg)


## CVE-2022-36030
 Project-nexus is a general-purpose blog website framework. Affected versions are subject to SQL injection due to a lack of sensitization of user input. This issue has not yet been patched. Users are advised to restrict user input and to upgrade when a new release becomes available.

- [https://github.com/Live-Hack-CVE/CVE-2022-36030](https://github.com/Live-Hack-CVE/CVE-2022-36030) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36030.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36030.svg)


## CVE-2022-36010
 This library allows strings to be parsed as functions and stored as a specialized component, [`JsonFunctionValue`](https://github.com/oxyno-zeta/react-editable-json-tree/blob/09a0ca97835b0834ad054563e2fddc6f22bc5d8c/src/components/JsonFunctionValue.js). To do this, Javascript's [`eval`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval) function is used to execute strings that begin with &quot;function&quot; as Javascript. This unfortunately could allow arbitrary code to be executed if it exists as a value within the JSON structure being displayed. Given that this component may often be used to display data from arbitrary, untrusted sources, this is extremely dangerous. One important note is that users who have defined a custom [`onSubmitValueParser`](https://github.com/oxyno-zeta/react-editable-json-tree/tree/09a0ca97835b0834ad054563e2fddc6f22bc5d8c#onsubmitvalueparser) callback prop on the [`JsonTree`](https://github.com/oxyno-zeta/react-editable-json-tree/blob/09a0ca97835b0834ad054563e2fddc6f22bc5d8c/src/JsonTree.js) component should be ***unaffected***. This vulnerability exists in the default `onSubmitValueParser` prop which calls [`parse`](https://github.com/oxyno-zeta/react-editable-json-tree/blob/master/src/utils/parse.js#L30). Prop is added to `JsonTree` called `allowFunctionEvaluation`. This prop will be set to `true` in v2.2.2, which allows upgrade without losing backwards-compatibility. In v2.2.2, we switched from using `eval` to using [`Function`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function) to construct anonymous functions. This is better than `eval` for the following reasons: - Arbitrary code should not be able to execute immediately, since the `Function` constructor explicitly *only creates* anonymous functions - Functions are created without local closures, so they only have access to the global scope If you use: - **Version `&lt;2.2.2`**, you must upgrade as soon as possible. - **Version `^2.2.2`**, you must explicitly set `JsonTree`'s `allowFunctionEvaluation` prop to `false` to fully mitigate this vulnerability. - **Version `&gt;=3.0.0`**, `allowFunctionEvaluation` is already set to `false` by default, so no further steps are necessary.

- [https://github.com/Live-Hack-CVE/CVE-2022-36010](https://github.com/Live-Hack-CVE/CVE-2022-36010) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36010.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36010.svg)


## CVE-2022-36009
 gomatrixserverlib is a Go library for matrix protocol federation. Dendrite is a Matrix homeserver written in Go, an alternative to Synapse. The power level parsing within gomatrixserverlib was failing to parse the `&quot;events_default&quot;` key of the `m.room.power_levels` event, defaulting the event default power level to zero in all cases. Power levels are the matrix terminology for user access level. In rooms where the `&quot;events_default&quot;` power level had been changed, this could result in events either being incorrectly authorised or rejected by Dendrite servers. gomatrixserverlib contains a fix as of commit `723fd49` and Dendrite 0.9.3 has been updated accordingly. Matrix rooms where the `&quot;events_default&quot;` power level has not been changed from the default of zero are not vulnerable. Users are advised to upgrade. There are no known workarounds for this issue.

- [https://github.com/Live-Hack-CVE/CVE-2022-36009](https://github.com/Live-Hack-CVE/CVE-2022-36009) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36009.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36009.svg)


## CVE-2022-36008
 Frontier is Substrate's Ethereum compatibility layer. A security issue was discovered affecting parsing of the RPC result of the exit reason in case of EVM reversion. In release build, this would cause the exit reason being incorrectly parsed and returned by RPC. In debug build, this would cause an overflow panic. No action is needed unless you have a bridge node that needs to distinguish different reversion exit reasons and you used RPC for this. There are currently no known workarounds.

- [https://github.com/Live-Hack-CVE/CVE-2022-36008](https://github.com/Live-Hack-CVE/CVE-2022-36008) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36008.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36008.svg)


## CVE-2022-36007
 Venice is a Clojure inspired sandboxed Lisp dialect with excellent Java interoperability. A partial path traversal issue exists within the functions `load-file` and `load-resource`. These functions can be limited to load files from a list of load paths. Assuming Venice has been configured with the load paths: `[ &quot;/Users/foo/resources&quot; ]` When passing **relative** paths to these two vulnerable functions everything is fine: `(load-resource &quot;test.png&quot;)` =&gt; loads the file &quot;/Users/foo/resources/test.png&quot; `(load-resource &quot;../resources-alt/test.png&quot;)` =&gt; rejected, outside the load path When passing **absolute** paths to these two vulnerable functions Venice may return files outside the configured load paths: `(load-resource &quot;/Users/foo/resources/test.png&quot;)` =&gt; loads the file &quot;/Users/foo/resources/test.png&quot; `(load-resource &quot;/Users/foo/resources-alt/test.png&quot;)` =&gt; loads the file &quot;/Users/foo/resources-alt/test.png&quot; !!! The latter call suffers from the _Partial Path Traversal_ vulnerability. This issue&#8217;s scope is limited to absolute paths whose name prefix matches a load path. E.g. for a load-path `&quot;/Users/foo/resources&quot;`, the actor can cause loading a resource also from `&quot;/Users/foo/resources-alt&quot;`, but not from `&quot;/Users/foo/images&quot;`. Versions of Venice before and including v1.10.17 are affected by this issue. Upgrade to Venice &gt;= 1.10.18, if you are on a version &lt; 1.10.18. There are currently no known workarounds.

- [https://github.com/Live-Hack-CVE/CVE-2022-36007](https://github.com/Live-Hack-CVE/CVE-2022-36007) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36007.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36007.svg)


## CVE-2022-36006
 Arvados is an open source platform for managing, processing, and sharing genomic and other large scientific and biomedical data. A remote code execution (RCE) vulnerability in the Arvados Workbench allows authenticated attackers to execute arbitrary code via specially crafted JSON payloads. This exists in all versions up to 2.4.1 and is fixed in 2.4.2. This vulnerability is specific to the Ruby on Rails Workbench application (&#8220;Workbench 1&#8221;). We do not believe any other Arvados components, including the TypesScript browser-based Workbench application (&#8220;Workbench 2&#8221;) or API Server, are vulnerable to this attack. For versions of Arvados earlier than 2.4.2: remove the Ruby-based &quot;Workbench 1&quot; app (&quot;apt-get remove arvados-workbench&quot;) from your installation as a workaround.

- [https://github.com/Live-Hack-CVE/CVE-2022-36006](https://github.com/Live-Hack-CVE/CVE-2022-36006) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36006.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36006.svg)


## CVE-2022-35980
 OpenSearch Security is a plugin for OpenSearch that offers encryption, authentication and authorization. Versions 2.0.0.0 and 2.1.0.0 of the security plugin are affected by an information disclosure vulnerability. Requests to an OpenSearch cluster configured with advanced access control features document level security (DLS), field level security (FLS), and/or field masking will not be filtered when the query's search pattern matches an aliased index. OpenSearch Dashboards creates an alias to `.kibana` by default, so filters with the index pattern of `*` to restrict access to documents or fields will not be applied. This issue allows requests to access sensitive information when customer have acted to restrict access that specific information. OpenSearch 2.2.0, which is compatible with OpenSearch Security 2.2.0.0, contains the fix for this issue. There is no recommended work around.

- [https://github.com/Live-Hack-CVE/CVE-2022-35980](https://github.com/Live-Hack-CVE/CVE-2022-35980) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35980.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35980.svg)


## CVE-2022-35978
 Minetest is a free open-source voxel game engine with easy modding and game creation. In **single player**, a mod can set a global setting that controls the Lua script loaded to display the main menu. The script is then loaded as soon as the game session is exited. The Lua environment the menu runs in is not sandboxed and can directly interfere with the user's system. There are currently no known workarounds.

- [https://github.com/Live-Hack-CVE/CVE-2022-35978](https://github.com/Live-Hack-CVE/CVE-2022-35978) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35978.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35978.svg)


## CVE-2022-35976
 The GitOps Tools Extension for VSCode relies on kubeconfigs in order to communicate with Kubernetes clusters. A specially crafted kubeconfig leads to arbitrary code execution on behalf of the user running VSCode. Users relying on kubeconfigs that are generated or altered by other processes or users are affected by this issue. Please note that the vulnerability is specific to this extension, and the same kubeconfig would not result in arbitrary code execution when used with kubectl. Using only trust-worthy kubeconfigs is a safe mitigation. However, updating to the latest version of the extension is still highly recommended.

- [https://github.com/Live-Hack-CVE/CVE-2022-35976](https://github.com/Live-Hack-CVE/CVE-2022-35976) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35976.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35976.svg)


## CVE-2022-35975
 The GitOps Tools Extension for VSCode can make it easier to manage Flux objects. A specially crafted Flux object may allow for remote code execution in the machine running the extension, in the context of the user that is running VSCode. Users using the VSCode extension to manage clusters that are shared amongst other users are affected by this issue. The only safe mitigation is to update to the latest version of the extension.

- [https://github.com/Live-Hack-CVE/CVE-2022-35975](https://github.com/Live-Hack-CVE/CVE-2022-35975) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35975.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35975.svg)


## CVE-2022-35956
 This Rails gem adds two methods to the ActiveRecord::Base class that allow you to update many records on a single database hit, using a case sql statement for it. Before version 0.1.3 `update_by_case` gem used custom sql strings, and it was not sanitized, making it vulnerable to sql injection. Upgrade to version &gt;= 0.1.3 that uses `Arel` instead to construct the resulting sql statement, with sanitized sql.

- [https://github.com/Live-Hack-CVE/CVE-2022-35956](https://github.com/Live-Hack-CVE/CVE-2022-35956) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35956.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35956.svg)


## CVE-2022-35954
 The GitHub Actions ToolKit provides a set of packages to make creating actions easier. The `core.exportVariable` function uses a well known delimiter that attackers can use to break out of that specific variable and assign values to other arbitrary variables. Workflows that write untrusted values to the `GITHUB_ENV` file may cause the path or other environment variables to be modified without the intention of the workflow or action author. Users should upgrade to `@actions/core v1.9.1`. If you are unable to upgrade the `@actions/core` package, you can modify your action to ensure that any user input does not contain the delimiter `_GitHubActionsFileCommandDelimeter_` before calling `core.exportVariable`.

- [https://github.com/Live-Hack-CVE/CVE-2022-35954](https://github.com/Live-Hack-CVE/CVE-2022-35954) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35954.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35954.svg)


## CVE-2022-35953
 BookWyrm is a social network for tracking your reading, talking about books, writing reviews, and discovering what to read next. Some links in BookWyrm may be vulnerable to tabnabbing, a form of phishing that gives attackers an opportunity to redirect a user to a malicious site. The issue was patched in version 0.4.5.

- [https://github.com/Live-Hack-CVE/CVE-2022-35953](https://github.com/Live-Hack-CVE/CVE-2022-35953) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35953.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35953.svg)


## CVE-2022-35949
 undici is an HTTP/1.1 client, written from scratch for Node.js.`undici` is vulnerable to SSRF (Server-side Request Forgery) when an application takes in **user input** into the `path/pathname` option of `undici.request`. If a user specifies a URL such as `http://127.0.0.1` or `//127.0.0.1` ```js const undici = require(&quot;undici&quot;) undici.request({origin: &quot;http://example.com&quot;, pathname: &quot;//127.0.0.1&quot;}) ``` Instead of processing the request as `http://example.org//127.0.0.1` (or `http://example.org/http://127.0.0.1` when `http://127.0.0.1 is used`), it actually processes the request as `http://127.0.0.1/` and sends it to `http://127.0.0.1`. If a developer passes in user input into `path` parameter of `undici.request`, it can result in an _SSRF_ as they will assume that the hostname cannot change, when in actual fact it can change because the specified path parameter is combined with the base URL. This issue was fixed in `undici@5.8.1`. The best workaround is to validate user input before passing it to the `undici.request` call.

- [https://github.com/Live-Hack-CVE/CVE-2022-35949](https://github.com/Live-Hack-CVE/CVE-2022-35949) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35949.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35949.svg)


## CVE-2022-35943
 Shield is an authentication and authorization framework for CodeIgniter 4. This vulnerability may allow [SameSite Attackers](https://canitakeyoursubdomain.name/) to bypass the [CodeIgniter4 CSRF protection](https://codeigniter4.github.io/userguide/libraries/security.html) mechanism with CodeIgniter Shield. For this attack to succeed, the attacker must have direct (or indirect, e.g., XSS) control over a subdomain site (e.g., `https://a.example.com/`) of the target site (e.g., `http://example.com/`). Upgrade to **CodeIgniter v4.2.3 or later** and **Shield v1.0.0-beta.2 or later**. As a workaround: set `Config\Security::$csrfProtection` to `'session,'`remove old session data right after login (immediately after ID and password match) and regenerate CSRF token right after login (immediately after ID and password match)

- [https://github.com/Live-Hack-CVE/CVE-2022-35943](https://github.com/Live-Hack-CVE/CVE-2022-35943) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35943.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35943.svg)


## CVE-2022-35942
 Improper input validation on the `contains` LoopBack filter may allow for arbitrary SQL injection. When the extended filter property `contains` is permitted to be interpreted by the Postgres connector, it is possible to inject arbitrary SQL which may affect the confidentiality and integrity of data stored on the connected database. A patch was released in version 5.5.1. This affects users who does any of the following: - Connect to the database via the DataSource with `allowExtendedProperties: true` setting OR - Uses the connector's CRUD methods directly OR - Uses the connector's other methods to interpret the LoopBack filter. Users who are unable to upgrade should do the following if applicable: - Remove `allowExtendedProperties: true` DataSource setting - Add `allowExtendedProperties: false` DataSource setting - When passing directly to the connector functions, manually sanitize the user input for the `contains` LoopBack filter beforehand.

- [https://github.com/Live-Hack-CVE/CVE-2022-35942](https://github.com/Live-Hack-CVE/CVE-2022-35942) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35942.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35942.svg)


## CVE-2022-35910
 In Jellyfin before 10.8, stored XSS allows theft of an admin access token.

- [https://github.com/Live-Hack-CVE/CVE-2022-35910](https://github.com/Live-Hack-CVE/CVE-2022-35910) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35910.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35910.svg)


## CVE-2022-35909
 In Jellyfin before 10.8, the /users endpoint has incorrect access control for admin functionality.

- [https://github.com/Live-Hack-CVE/CVE-2022-35909](https://github.com/Live-Hack-CVE/CVE-2022-35909) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35909.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35909.svg)


## CVE-2022-35734
 'Hulu / &#12501;&#12540;&#12523;&#12540;' App for Android from version 3.0.47 to the version prior to 3.1.2 uses a hard-coded API key for an external service. By exploiting this vulnerability, API key for an external service may be obtained by analyzing data in the app.

- [https://github.com/Live-Hack-CVE/CVE-2022-35734](https://github.com/Live-Hack-CVE/CVE-2022-35734) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35734.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35734.svg)


## CVE-2022-35733
 Missing authentication for critical function vulnerability in UNIMO Technology digital video recorders (UDR-JA1004/JA1008/JA1016 firmware versions v1.0.20.13 and earlier, and UDR-JA1016 firmware versions v2.0.20.13 and earlier) allows a remote unauthenticated attacker to execute an arbitrary OS command by sending a specially crafted request to the affected device web interface.

- [https://github.com/Live-Hack-CVE/CVE-2022-35733](https://github.com/Live-Hack-CVE/CVE-2022-35733) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35733.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35733.svg)


## CVE-2022-35726
 Broken Authentication vulnerability in yotuwp Video Gallery plugin &lt;= 1.3.4.5 at WordPress.

- [https://github.com/Live-Hack-CVE/CVE-2022-35726](https://github.com/Live-Hack-CVE/CVE-2022-35726) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35726.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35726.svg)


## CVE-2022-35678
 Adobe Acrobat Reader versions 22.001.20169 (and earlier), 20.005.30362 (and earlier) and 17.012.30249 (and earlier) are affected by an out-of-bounds read vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/Live-Hack-CVE/CVE-2022-35678](https://github.com/Live-Hack-CVE/CVE-2022-35678) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35678.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35678.svg)


## CVE-2022-35671
 Adobe Acrobat Reader versions 22.001.20169 (and earlier), 20.005.30362 (and earlier) and 17.012.30249 (and earlier) are affected by an out-of-bounds read vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/Live-Hack-CVE/CVE-2022-35671](https://github.com/Live-Hack-CVE/CVE-2022-35671) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35671.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35671.svg)


## CVE-2022-35670
 Adobe Acrobat Reader versions 22.001.20169 (and earlier), 20.005.30362 (and earlier) and 17.012.30249 (and earlier) are affected by a Use After Free vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/Live-Hack-CVE/CVE-2022-35670](https://github.com/Live-Hack-CVE/CVE-2022-35670) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35670.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35670.svg)


## CVE-2022-35668
 Adobe Acrobat Reader versions 22.001.20169 (and earlier), 20.005.30362 (and earlier) and 17.012.30249 (and earlier) are affected by an Improper Input Validation vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/Live-Hack-CVE/CVE-2022-35668](https://github.com/Live-Hack-CVE/CVE-2022-35668) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35668.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35668.svg)


## CVE-2022-35667
 Adobe Acrobat Reader versions 22.001.20169 (and earlier), 20.005.30362 (and earlier) and 17.012.30249 (and earlier) are affected by an out-of-bounds write vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/Live-Hack-CVE/CVE-2022-35667](https://github.com/Live-Hack-CVE/CVE-2022-35667) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35667.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35667.svg)


## CVE-2022-35666
 Adobe Acrobat Reader versions 22.001.20169 (and earlier), 20.005.30362 (and earlier) and 17.012.30249 (and earlier) are affected by an Improper Input Validation vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/Live-Hack-CVE/CVE-2022-35666](https://github.com/Live-Hack-CVE/CVE-2022-35666) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35666.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35666.svg)


## CVE-2022-35665
 Adobe Acrobat Reader versions 22.001.20169 (and earlier), 20.005.30362 (and earlier) and 17.012.30249 (and earlier) are affected by a Use After Free vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/Live-Hack-CVE/CVE-2022-35665](https://github.com/Live-Hack-CVE/CVE-2022-35665) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35665.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35665.svg)


## CVE-2022-35656
 Pega Platform from 8.3 to 8.7.3 vulnerability may allow authenticated security administrators to alter CSRF settings directly.

- [https://github.com/Live-Hack-CVE/CVE-2022-35656](https://github.com/Live-Hack-CVE/CVE-2022-35656) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35656.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35656.svg)


## CVE-2022-35655
 Pega Platform from 7.3 to 8.7.3 is affected by an XSS issue due to a misconfiguration of a datapage setting.

- [https://github.com/Live-Hack-CVE/CVE-2022-35655](https://github.com/Live-Hack-CVE/CVE-2022-35655) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35655.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35655.svg)


## CVE-2022-35654
 Pega Platform from 8.5.4 to 8.7.3 is affected by an XSS issue with an unauthenticated user and the redirect parameter.

- [https://github.com/Live-Hack-CVE/CVE-2022-35654](https://github.com/Live-Hack-CVE/CVE-2022-35654) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35654.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35654.svg)


## CVE-2022-35624
 In Nordic nRF5 SDK for Mesh 5.0, a heap overflow vulnerability can be triggered by sending a series of segmented packets with SegO &gt; SegN

- [https://github.com/Live-Hack-CVE/CVE-2022-35624](https://github.com/Live-Hack-CVE/CVE-2022-35624) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35624.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35624.svg)


## CVE-2022-35623
 In Nordic nRF5 SDK for Mesh 5.0, a heap overflow vulnerability can be triggered by sending a series of segmented control packets and access packets with the same SeqAuth

- [https://github.com/Live-Hack-CVE/CVE-2022-35623](https://github.com/Live-Hack-CVE/CVE-2022-35623) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35623.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35623.svg)


## CVE-2022-35606
 A SQL injection vulnerability in CustomerDAO.java in sazanrjb InventoryManagementSystem 1.0 allows attackers to execute arbitrary SQL commands via the parameter 'customerCode.'

- [https://github.com/Live-Hack-CVE/CVE-2022-35606](https://github.com/Live-Hack-CVE/CVE-2022-35606) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35606.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35606.svg)


## CVE-2022-35605
 A SQL injection vulnerability in UserDAO.java in sazanrjb InventoryManagementSystem 1.0 allows attackers to execute arbitrary SQL commands via the parameters such as 'users', 'pass', etc.

- [https://github.com/Live-Hack-CVE/CVE-2022-35605](https://github.com/Live-Hack-CVE/CVE-2022-35605) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35605.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35605.svg)


## CVE-2022-35604
 A SQL injection vulnerability in SupplierDAO.java in sazanrjb InventoryManagementSystem 1.0 allows attackers to execute arbitrary SQL commands via parameter 'searchTxt'.

- [https://github.com/Live-Hack-CVE/CVE-2022-35604](https://github.com/Live-Hack-CVE/CVE-2022-35604) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35604.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35604.svg)


## CVE-2022-35603
 A SQL injection vulnerability in CustomerDAO.java in sazanrjb InventoryManagementSystem 1.0 allows attackers to execute arbitrary SQL commands via parameter searchTxt.

- [https://github.com/Live-Hack-CVE/CVE-2022-35603](https://github.com/Live-Hack-CVE/CVE-2022-35603) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35603.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35603.svg)


## CVE-2022-35602
 A SQL injection vulnerability in UserDAO.java in sazanrjb InventoryManagementSystem 1.0 allows attackers to execute arbitrary SQL commands via parameter user.

- [https://github.com/Live-Hack-CVE/CVE-2022-35602](https://github.com/Live-Hack-CVE/CVE-2022-35602) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35602.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35602.svg)


## CVE-2022-35601
 A SQL injection vulnerability in SupplierDAO.java in sazanrjb InventoryManagementSystem 1.0 allows attackers to execute arbitrary SQL commands via parameter searchTxt.

- [https://github.com/Live-Hack-CVE/CVE-2022-35601](https://github.com/Live-Hack-CVE/CVE-2022-35601) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35601.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35601.svg)


## CVE-2022-35599
 A SQL injection vulnerability in Stocks.java in sazanrjb InventoryManagementSystem 1.0 allows attackers to execute arbitrary SQL commands via parameter productcode.

- [https://github.com/Live-Hack-CVE/CVE-2022-35599](https://github.com/Live-Hack-CVE/CVE-2022-35599) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35599.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35599.svg)


## CVE-2022-35598
 A SQL injection vulnerability in ConnectionFactoryDAO.java in sazanrjb InventoryManagementSystem 1.0 allows attackers to execute arbitrary SQL commands via parameter username.

- [https://github.com/Live-Hack-CVE/CVE-2022-35598](https://github.com/Live-Hack-CVE/CVE-2022-35598) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35598.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35598.svg)


## CVE-2022-35583
 wkhtmlTOpdf 0.12.6 is vulnerable to SSRF which allows an attacker to get initial access into the target's system by injecting iframe tag with initial asset IP address on it's source. This allows the attacker to takeover the whole infrastructure by accessing their internal assets.

- [https://github.com/Live-Hack-CVE/CVE-2022-35583](https://github.com/Live-Hack-CVE/CVE-2022-35583) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35583.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35583.svg)


## CVE-2022-35561
 A stack overflow vulnerability exists in /goform/WifiMacFilterSet in Tenda W6 V1.0.0.9(4122) version, which can be exploited by attackers to cause a denial of service (DoS) via the index parameter.

- [https://github.com/Live-Hack-CVE/CVE-2022-35561](https://github.com/Live-Hack-CVE/CVE-2022-35561) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35561.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35561.svg)


## CVE-2022-35560
 A stack overflow vulnerability exists in /goform/wifiSSIDset in Tenda W6 V1.0.0.9(4122) version, which can be exploited by attackers to cause a denial of service (DoS) via the index parameter.

- [https://github.com/Live-Hack-CVE/CVE-2022-35560](https://github.com/Live-Hack-CVE/CVE-2022-35560) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35560.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35560.svg)


## CVE-2022-35559
 A stack overflow vulnerability exists in /goform/setAutoPing in Tenda W6 V1.0.0.9(4122), which allows an attacker to construct ping1 parameters and ping2 parameters for a stack overflow attack. An attacker can use this vulnerability to execute arbitrary code execution.

- [https://github.com/Live-Hack-CVE/CVE-2022-35559](https://github.com/Live-Hack-CVE/CVE-2022-35559) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35559.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35559.svg)


## CVE-2022-35558
 A stack overflow vulnerability exists in /goform/WifiMacFilterGet in Tenda W6 V1.0.0.9(4122) version, which can be exploited by attackers to cause a denial of service (DoS) via the index parameter.

- [https://github.com/Live-Hack-CVE/CVE-2022-35558](https://github.com/Live-Hack-CVE/CVE-2022-35558) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35558.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35558.svg)


## CVE-2022-35557
 A stack overflow vulnerability exists in /goform/wifiSSIDget in Tenda W6 V1.0.0.9(4122) version, which can be exploited by attackers to cause a denial of service (DoS) via the index parameter.

- [https://github.com/Live-Hack-CVE/CVE-2022-35557](https://github.com/Live-Hack-CVE/CVE-2022-35557) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35557.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35557.svg)


## CVE-2022-35555
 A command injection vulnerability exists in /goform/exeCommand in Tenda W6 V1.0.0.9(4122), which allows attackers to construct cmdinput parameters for arbitrary command execution.

- [https://github.com/Live-Hack-CVE/CVE-2022-35555](https://github.com/Live-Hack-CVE/CVE-2022-35555) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35555.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35555.svg)


## CVE-2022-35554
 Multiple reflected XSS vulnerabilities occur when handling error message of BPC SmartVista version 3.28.0 allowing an attacker to execute javascript code at client side.

- [https://github.com/Live-Hack-CVE/CVE-2022-35554](https://github.com/Live-Hack-CVE/CVE-2022-35554) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35554.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35554.svg)


## CVE-2022-35540
 Hardcoded JWT Secret in AgileConfig &lt;1.6.8 Server allows remote attackers to use the generated JWT token to gain administrator access.

- [https://github.com/Live-Hack-CVE/CVE-2022-35540](https://github.com/Live-Hack-CVE/CVE-2022-35540) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35540.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35540.svg)


## CVE-2022-35516
 DedeCMS v5.7.93 - v5.7.96 was discovered to contain a remote code execution vulnerability in login.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-35516](https://github.com/Live-Hack-CVE/CVE-2022-35516) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35516.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35516.svg)


## CVE-2022-35486
 OTFCC v0.10.4 was discovered to contain a segmentation violation via /release-x64/otfccdump+0x6badae.

- [https://github.com/Live-Hack-CVE/CVE-2022-35486](https://github.com/Live-Hack-CVE/CVE-2022-35486) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35486.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35486.svg)


## CVE-2022-35485
 OTFCC v0.10.4 was discovered to contain a segmentation violation via /release-x64/otfccdump+0x703969.

- [https://github.com/Live-Hack-CVE/CVE-2022-35485](https://github.com/Live-Hack-CVE/CVE-2022-35485) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35485.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35485.svg)


## CVE-2022-35484
 OTFCC v0.10.4 was discovered to contain a segmentation violation via /release-x64/otfccdump+0x6b6a8f.

- [https://github.com/Live-Hack-CVE/CVE-2022-35484](https://github.com/Live-Hack-CVE/CVE-2022-35484) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35484.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35484.svg)


## CVE-2022-35483
 OTFCC v0.10.4 was discovered to contain a segmentation violation via /release-x64/otfccdump+0x5266a8.

- [https://github.com/Live-Hack-CVE/CVE-2022-35483](https://github.com/Live-Hack-CVE/CVE-2022-35483) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35483.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35483.svg)


## CVE-2022-35482
 OTFCC v0.10.4 was discovered to contain a segmentation violation via /release-x64/otfccdump+0x65f724.

- [https://github.com/Live-Hack-CVE/CVE-2022-35482](https://github.com/Live-Hack-CVE/CVE-2022-35482) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35482.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35482.svg)


## CVE-2022-35481
 OTFCC v0.10.4 was discovered to contain a segmentation violation via /multiarch/memmove-vec-unaligned-erms.S.

- [https://github.com/Live-Hack-CVE/CVE-2022-35481](https://github.com/Live-Hack-CVE/CVE-2022-35481) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35481.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35481.svg)


## CVE-2022-35479
 OTFCC v0.10.4 was discovered to contain a segmentation violation via /release-x64/otfccdump+0x4fbbb6.

- [https://github.com/Live-Hack-CVE/CVE-2022-35479](https://github.com/Live-Hack-CVE/CVE-2022-35479) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35479.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35479.svg)


## CVE-2022-35478
 OTFCC v0.10.4 was discovered to contain a segmentation violation via /release-x64/otfccdump+0x6babea.

- [https://github.com/Live-Hack-CVE/CVE-2022-35478](https://github.com/Live-Hack-CVE/CVE-2022-35478) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35478.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35478.svg)


## CVE-2022-35477
 OTFCC v0.10.4 was discovered to contain a segmentation violation via /release-x64/otfccdump+0x4fe954.

- [https://github.com/Live-Hack-CVE/CVE-2022-35477](https://github.com/Live-Hack-CVE/CVE-2022-35477) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35477.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35477.svg)


## CVE-2022-35476
 OTFCC v0.10.4 was discovered to contain a segmentation violation via /release-x64/otfccdump+0x4fbc0b.

- [https://github.com/Live-Hack-CVE/CVE-2022-35476](https://github.com/Live-Hack-CVE/CVE-2022-35476) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35476.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35476.svg)


## CVE-2022-35475
 OTFCC v0.10.4 was discovered to contain a heap-buffer overflow via /release-x64/otfccdump+0x6e41a8.

- [https://github.com/Live-Hack-CVE/CVE-2022-35475](https://github.com/Live-Hack-CVE/CVE-2022-35475) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35475.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35475.svg)


## CVE-2022-35474
 OTFCC v0.10.4 was discovered to contain a heap-buffer overflow via /release-x64/otfccdump+0x6b544e.

- [https://github.com/Live-Hack-CVE/CVE-2022-35474](https://github.com/Live-Hack-CVE/CVE-2022-35474) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35474.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35474.svg)


## CVE-2022-35473
 OTFCC v0.10.4 was discovered to contain a segmentation violation via /release-x64/otfccdump+0x4fe9a7.

- [https://github.com/Live-Hack-CVE/CVE-2022-35473](https://github.com/Live-Hack-CVE/CVE-2022-35473) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35473.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35473.svg)


## CVE-2022-35472
 OTFCC v0.10.4 was discovered to contain a global overflow via /release-x64/otfccdump+0x718693.

- [https://github.com/Live-Hack-CVE/CVE-2022-35472](https://github.com/Live-Hack-CVE/CVE-2022-35472) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35472.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35472.svg)


## CVE-2022-35471
 OTFCC v0.10.4 was discovered to contain a heap-buffer overflow via /release-x64/otfccdump+0x6e41b0.

- [https://github.com/Live-Hack-CVE/CVE-2022-35471](https://github.com/Live-Hack-CVE/CVE-2022-35471) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35471.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35471.svg)


## CVE-2022-35470
 OTFCC v0.10.4 was discovered to contain a heap-buffer overflow via /release-x64/otfccdump+0x65fc97.

- [https://github.com/Live-Hack-CVE/CVE-2022-35470](https://github.com/Live-Hack-CVE/CVE-2022-35470) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35470.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35470.svg)


## CVE-2022-35469
 OTFCC v0.10.4 was discovered to contain a segmentation violation via /x86_64-linux-gnu/libc.so.6+0xbb384.

- [https://github.com/Live-Hack-CVE/CVE-2022-35469](https://github.com/Live-Hack-CVE/CVE-2022-35469) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35469.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35469.svg)


## CVE-2022-35468
 OTFCC v0.10.4 was discovered to contain a heap-buffer overflow via /release-x64/otfccdump+0x6e420d.

- [https://github.com/Live-Hack-CVE/CVE-2022-35468](https://github.com/Live-Hack-CVE/CVE-2022-35468) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35468.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35468.svg)


## CVE-2022-35467
 OTFCC v0.10.4 was discovered to contain a heap-buffer overflow via /release-x64/otfccdump+0x6e41b8.

- [https://github.com/Live-Hack-CVE/CVE-2022-35467](https://github.com/Live-Hack-CVE/CVE-2022-35467) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35467.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35467.svg)


## CVE-2022-35466
 OTFCC v0.10.4 was discovered to contain a heap-buffer overflow via /release-x64/otfccdump+0x6c0473.

- [https://github.com/Live-Hack-CVE/CVE-2022-35466](https://github.com/Live-Hack-CVE/CVE-2022-35466) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35466.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35466.svg)


## CVE-2022-35465
 OTFCC v0.10.4 was discovered to contain a heap-buffer overflow via /release-x64/otfccdump+0x6c0414.

- [https://github.com/Live-Hack-CVE/CVE-2022-35465](https://github.com/Live-Hack-CVE/CVE-2022-35465) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35465.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35465.svg)


## CVE-2022-35464
 OTFCC v0.10.4 was discovered to contain a heap-buffer overflow via /release-x64/otfccdump+0x6171b2.

- [https://github.com/Live-Hack-CVE/CVE-2022-35464](https://github.com/Live-Hack-CVE/CVE-2022-35464) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35464.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35464.svg)


## CVE-2022-35463
 OTFCC v0.10.4 was discovered to contain a heap-buffer overflow via /release-x64/otfccdump+0x6b0478.

- [https://github.com/Live-Hack-CVE/CVE-2022-35463](https://github.com/Live-Hack-CVE/CVE-2022-35463) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35463.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35463.svg)


## CVE-2022-35462
 OTFCC v0.10.4 was discovered to contain a heap-buffer overflow via /release-x64/otfccdump+0x6c0bc3.

- [https://github.com/Live-Hack-CVE/CVE-2022-35462](https://github.com/Live-Hack-CVE/CVE-2022-35462) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35462.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35462.svg)


## CVE-2022-35461
 OTFCC v0.10.4 was discovered to contain a heap-buffer overflow via /release-x64/otfccdump+0x6c0a32.

- [https://github.com/Live-Hack-CVE/CVE-2022-35461](https://github.com/Live-Hack-CVE/CVE-2022-35461) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35461.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35461.svg)


## CVE-2022-35460
 OTFCC v0.10.4 was discovered to contain a heap-buffer overflow via /release-x64/otfccdump+0x61731f.

- [https://github.com/Live-Hack-CVE/CVE-2022-35460](https://github.com/Live-Hack-CVE/CVE-2022-35460) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35460.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35460.svg)


## CVE-2022-35459
 OTFCC v0.10.4 was discovered to contain a heap-buffer overflow via /release-x64/otfccdump+0x6e412a.

- [https://github.com/Live-Hack-CVE/CVE-2022-35459](https://github.com/Live-Hack-CVE/CVE-2022-35459) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35459.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35459.svg)


## CVE-2022-35458
 OTFCC v0.10.4 was discovered to contain a heap-buffer overflow via /release-x64/otfccdump+0x6b05ce.

- [https://github.com/Live-Hack-CVE/CVE-2022-35458](https://github.com/Live-Hack-CVE/CVE-2022-35458) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35458.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35458.svg)


## CVE-2022-35456
 OTFCC v0.10.4 was discovered to contain a heap-buffer overflow via /release-x64/otfccdump+0x617087.

- [https://github.com/Live-Hack-CVE/CVE-2022-35456](https://github.com/Live-Hack-CVE/CVE-2022-35456) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35456.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35456.svg)


## CVE-2022-35455
 OTFCC v0.10.4 was discovered to contain a heap-buffer overflow via /release-x64/otfccdump+0x6b0d63.

- [https://github.com/Live-Hack-CVE/CVE-2022-35455](https://github.com/Live-Hack-CVE/CVE-2022-35455) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35455.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35455.svg)


## CVE-2022-35454
 OTFCC v0.10.4 was discovered to contain a heap-buffer overflow via /release-x64/otfccdump+0x6b05aa.

- [https://github.com/Live-Hack-CVE/CVE-2022-35454](https://github.com/Live-Hack-CVE/CVE-2022-35454) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35454.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35454.svg)


## CVE-2022-35453
 OTFCC v0.10.4 was discovered to contain a heap-buffer overflow via /release-x64/otfccdump+0x6c08a6.

- [https://github.com/Live-Hack-CVE/CVE-2022-35453](https://github.com/Live-Hack-CVE/CVE-2022-35453) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35453.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35453.svg)


## CVE-2022-35452
 OTFCC v0.10.4 was discovered to contain a heap-buffer overflow via /release-x64/otfccdump+0x6b0b2c.

- [https://github.com/Live-Hack-CVE/CVE-2022-35452](https://github.com/Live-Hack-CVE/CVE-2022-35452) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35452.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35452.svg)


## CVE-2022-35451
 OTFCC v0.10.4 was discovered to contain a heap-buffer overflow via /release-x64/otfccdump+0x6b03b5.

- [https://github.com/Live-Hack-CVE/CVE-2022-35451](https://github.com/Live-Hack-CVE/CVE-2022-35451) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35451.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35451.svg)


## CVE-2022-35450
 OTFCC v0.10.4 was discovered to contain a heap-buffer overflow via /release-x64/otfccdump+0x6b84b1.

- [https://github.com/Live-Hack-CVE/CVE-2022-35450](https://github.com/Live-Hack-CVE/CVE-2022-35450) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35450.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35450.svg)


## CVE-2022-35449
 OTFCC v0.10.4 was discovered to contain a heap-buffer overflow via /release-x64/otfccdump+0x6b0466.

- [https://github.com/Live-Hack-CVE/CVE-2022-35449](https://github.com/Live-Hack-CVE/CVE-2022-35449) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35449.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35449.svg)


## CVE-2022-35448
 OTFCC v0.10.4 was discovered to contain a heap-buffer overflow via /release-x64/otfccdump+0x6b55af.

- [https://github.com/Live-Hack-CVE/CVE-2022-35448](https://github.com/Live-Hack-CVE/CVE-2022-35448) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35448.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35448.svg)


## CVE-2022-35447
 OTFCC v0.10.4 was discovered to contain a heap-buffer overflow via /release-x64/otfccdump+0x6b04de.

- [https://github.com/Live-Hack-CVE/CVE-2022-35447](https://github.com/Live-Hack-CVE/CVE-2022-35447) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35447.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35447.svg)


## CVE-2022-35434
 jpeg-quantsmooth before commit 8879454 contained a floating point exception (FPE) via /jpeg-quantsmooth/jpegqs+0x4f5d6c.

- [https://github.com/Live-Hack-CVE/CVE-2022-35434](https://github.com/Live-Hack-CVE/CVE-2022-35434) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35434.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35434.svg)


## CVE-2022-35433
 ffjpeg commit caade60a69633d74100bd3c2528bddee0b6a1291 was discovered to contain a memory leak via /src/jfif.c.

- [https://github.com/Live-Hack-CVE/CVE-2022-35433](https://github.com/Live-Hack-CVE/CVE-2022-35433) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35433.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35433.svg)


## CVE-2022-35242
 Unauthenticated plugin settings change vulnerability in 59sec THE Leads Management System: 59sec LITE plugin &lt;= 3.4.1 at WordPress.

- [https://github.com/Live-Hack-CVE/CVE-2022-35242](https://github.com/Live-Hack-CVE/CVE-2022-35242) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35242.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35242.svg)


## CVE-2022-35239
 The image file management page of SolarView Compact SV-CPT-MC310 Ver.7.23 and earlier, and SV-CPT-MC310F Ver.7.23 and earlier contains an insufficient verification vulnerability when uploading files. If this vulnerability is exploited, arbitrary PHP code may be executed if a remote authenticated attacker uploads a specially crafted PHP file.

- [https://github.com/Live-Hack-CVE/CVE-2022-35239](https://github.com/Live-Hack-CVE/CVE-2022-35239) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35239.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35239.svg)


## CVE-2022-35235
 Authenticated (admin+) Arbitrary File Read vulnerability in XplodedThemes WPide plugin &lt;= 2.6 at WordPress.

- [https://github.com/Live-Hack-CVE/CVE-2022-35235](https://github.com/Live-Hack-CVE/CVE-2022-35235) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35235.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35235.svg)


## CVE-2022-35213
 Ecommerce-CodeIgniter-Bootstrap before commit 56465f was discovered to contain a cross-site scripting (XSS) vulnerability via the function base_url() at /blog/blogpublish.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-35213](https://github.com/Live-Hack-CVE/CVE-2022-35213) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35213.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35213.svg)


## CVE-2022-35212
 osCommerce2 before v2.3.4.1 was discovered to contain a cross-site scripting (XSS) vulnerability via the function tep_db_error().

- [https://github.com/Live-Hack-CVE/CVE-2022-35212](https://github.com/Live-Hack-CVE/CVE-2022-35212) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35212.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35212.svg)


## CVE-2022-35204
 Vitejs Vite before v2.9.13 was discovered to allow attackers to perform a directory traversal via a crafted URL to the victim's service.

- [https://github.com/Live-Hack-CVE/CVE-2022-35204](https://github.com/Live-Hack-CVE/CVE-2022-35204) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35204.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35204.svg)


## CVE-2022-35203
 An access control issue in TrendNet TV-IP572PI v1.0 allows unauthenticated attackers to access sensitive system information.

- [https://github.com/Live-Hack-CVE/CVE-2022-35203](https://github.com/Live-Hack-CVE/CVE-2022-35203) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35203.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35203.svg)


## CVE-2022-35201
 Tenda-AC18 V15.03.05.05 was discovered to contain a remote command execution (RCE) vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-35201](https://github.com/Live-Hack-CVE/CVE-2022-35201) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35201.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35201.svg)


## CVE-2022-35198
 Contract Management System v2.0 contains a weak default password which gives attackers to access database connection information.

- [https://github.com/Live-Hack-CVE/CVE-2022-35198](https://github.com/Live-Hack-CVE/CVE-2022-35198) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35198.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35198.svg)


## CVE-2022-35191
 D-Link Wireless AC1200 Dual Band VDSL ADSL Modem Router DSL-3782 Firmware v1.01 allows unauthenticated attackers to cause a Denial of Service (DoS) via a crafted HTTP connection request.

- [https://github.com/Live-Hack-CVE/CVE-2022-35191](https://github.com/Live-Hack-CVE/CVE-2022-35191) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35191.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35191.svg)


## CVE-2022-35175
 Barangay Management System v1.0 was discovered to contain a SQL injection vulnerability via the hidden_id parameter at /blotter/blotter.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-35175](https://github.com/Live-Hack-CVE/CVE-2022-35175) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35175.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35175.svg)


## CVE-2022-35174
 A stored cross-site scripting (XSS) vulnerability in Kirby's Starterkit v3.7.0.2 allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the Tags field.

- [https://github.com/Live-Hack-CVE/CVE-2022-35174](https://github.com/Live-Hack-CVE/CVE-2022-35174) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35174.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35174.svg)


## CVE-2022-35173
 An issue was discovered in Nginx NJS v0.7.5. The JUMP offset for a break instruction was not set to a correct offset during code generation, leading to a segmentation violation.

- [https://github.com/Live-Hack-CVE/CVE-2022-35173](https://github.com/Live-Hack-CVE/CVE-2022-35173) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35173.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35173.svg)


## CVE-2022-35167
 Printix Cloud Print Management v1.3.1149.0 for Windows was discovered to contain insecure permissions.

- [https://github.com/Live-Hack-CVE/CVE-2022-35167](https://github.com/Live-Hack-CVE/CVE-2022-35167) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35167.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35167.svg)


## CVE-2022-35166
 libjpeg commit 842c7ba was discovered to contain an infinite loop via the component JPEG::ReadInternal.

- [https://github.com/Live-Hack-CVE/CVE-2022-35166](https://github.com/Live-Hack-CVE/CVE-2022-35166) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35166.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35166.svg)


## CVE-2022-35165
 An issue in AP4_SgpdAtom::AP4_SgpdAtom() of Bento4-1.6.0-639 allows attackers to cause a Denial of Service (DoS) via a crafted mp4 input.

- [https://github.com/Live-Hack-CVE/CVE-2022-35165](https://github.com/Live-Hack-CVE/CVE-2022-35165) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35165.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35165.svg)


## CVE-2022-35164
 LibreDWG v0.12.4.4608 &amp; commit f2dea29 was discovered to contain a heap use-after-free via bit_copy_chain.

- [https://github.com/Live-Hack-CVE/CVE-2022-35164](https://github.com/Live-Hack-CVE/CVE-2022-35164) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35164.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35164.svg)


## CVE-2022-35154
 Shopro Mall System v1.3.8 was discovered to contain a SQL injection vulnerability via the value parameter.

- [https://github.com/Live-Hack-CVE/CVE-2022-35154](https://github.com/Live-Hack-CVE/CVE-2022-35154) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35154.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35154.svg)


## CVE-2022-35153
 FusionPBX 5.0.1 was discovered to contain a command injection vulnerability via /fax/fax_send.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-35153](https://github.com/Live-Hack-CVE/CVE-2022-35153) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35153.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35153.svg)


## CVE-2022-35151
 kkFileView v4.1.0 was discovered to contain multiple cross-site scripting (XSS) vulnerabilities via the urls and currentUrl parameters at /controller/OnlinePreviewController.java.

- [https://github.com/Live-Hack-CVE/CVE-2022-35151](https://github.com/Live-Hack-CVE/CVE-2022-35151) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35151.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35151.svg)


## CVE-2022-35150
 Baijicms v4 was discovered to contain an arbitrary file upload vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-35150](https://github.com/Live-Hack-CVE/CVE-2022-35150) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35150.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35150.svg)


## CVE-2022-35148
 maccms10 v2021.1000.1081 to v2022.1000.3031 was discovered to contain a SQL injection vulnerability via the table parameter at database/columns.html.

- [https://github.com/Live-Hack-CVE/CVE-2022-35148](https://github.com/Live-Hack-CVE/CVE-2022-35148) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35148.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35148.svg)


## CVE-2022-35147
 DoraCMS v2.18 and earlier allows attackers to bypass login authentication via a crafted HTTP request.

- [https://github.com/Live-Hack-CVE/CVE-2022-35147](https://github.com/Live-Hack-CVE/CVE-2022-35147) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35147.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35147.svg)


## CVE-2022-35133
 A cross-site scripting (XSS) vulnerability in CherryTree v0.99.30 allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the Name text field when creating a node.

- [https://github.com/Live-Hack-CVE/CVE-2022-35133](https://github.com/Live-Hack-CVE/CVE-2022-35133) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35133.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35133.svg)


## CVE-2022-35122
 An access control issue in Ecowitt GW1100 Series Weather Stations &lt;=GW1100B_v2.1.5 allows unauthenticated attackers to access sensitive information including device and local WiFi passwords.

- [https://github.com/Live-Hack-CVE/CVE-2022-35122](https://github.com/Live-Hack-CVE/CVE-2022-35122) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35122.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35122.svg)


## CVE-2022-35121
 Novel-Plus v3.6.1 was discovered to contain a SQL injection vulnerability via the keyword parameter at /service/impl/BookServiceImpl.java.

- [https://github.com/Live-Hack-CVE/CVE-2022-35121](https://github.com/Live-Hack-CVE/CVE-2022-35121) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35121.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35121.svg)


## CVE-2022-35117
 Clinic's Patient Management System v1.0 was discovered to contain a cross-site scripting (XSS) vulnerability via update_medicine_details.php. This vulnerability allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the Packing text box under the Update Medical Details module.

- [https://github.com/Live-Hack-CVE/CVE-2022-35117](https://github.com/Live-Hack-CVE/CVE-2022-35117) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35117.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35117.svg)


## CVE-2022-35115
 IceWarp WebClient DC2 - Update 2 Build 9 (13.0.2.9) was discovered to contain a SQL injection vulnerability via the search parameter at /webmail/server/webmail.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-35115](https://github.com/Live-Hack-CVE/CVE-2022-35115) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35115.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35115.svg)


## CVE-2022-35114
 SWFTools commit 772e55a2 was discovered to contain a segmentation violation via extractFrame at /readers/swf.c.

- [https://github.com/Live-Hack-CVE/CVE-2022-35114](https://github.com/Live-Hack-CVE/CVE-2022-35114) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35114.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35114.svg)


## CVE-2022-35113
 SWFTools commit 772e55a2 was discovered to contain a heap-buffer overflow via swf_DefineLosslessBitsTagToImage at /modules/swfbits.c.

- [https://github.com/Live-Hack-CVE/CVE-2022-35113](https://github.com/Live-Hack-CVE/CVE-2022-35113) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35113.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35113.svg)


## CVE-2022-35111
 SWFTools commit 772e55a2 was discovered to contain a stack overflow via __sanitizer::StackDepotNode::hash(__sanitizer::StackTrace const&amp;) at /sanitizer_common/sanitizer_stackdepot.cpp.

- [https://github.com/Live-Hack-CVE/CVE-2022-35111](https://github.com/Live-Hack-CVE/CVE-2022-35111) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35111.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35111.svg)


## CVE-2022-35110
 SWFTools commit 772e55a2 was discovered to contain a memory leak via /lib/mem.c.

- [https://github.com/Live-Hack-CVE/CVE-2022-35110](https://github.com/Live-Hack-CVE/CVE-2022-35110) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35110.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35110.svg)


## CVE-2022-35109
 SWFTools commit 772e55a2 was discovered to contain a heap-buffer overflow via draw_stroke at /gfxpoly/stroke.c.

- [https://github.com/Live-Hack-CVE/CVE-2022-35109](https://github.com/Live-Hack-CVE/CVE-2022-35109) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35109.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35109.svg)


## CVE-2022-35108
 SWFTools commit 772e55a2 was discovered to contain a segmentation violation via DCTStream::getChar() at /xpdf/Stream.cc.

- [https://github.com/Live-Hack-CVE/CVE-2022-35108](https://github.com/Live-Hack-CVE/CVE-2022-35108) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35108.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35108.svg)


## CVE-2022-35107
 SWFTools commit 772e55a2 was discovered to contain a stack overflow via vfprintf at /stdio-common/vfprintf.c.

- [https://github.com/Live-Hack-CVE/CVE-2022-35107](https://github.com/Live-Hack-CVE/CVE-2022-35107) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35107.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35107.svg)


## CVE-2022-35106
 SWFTools commit 772e55a2 was discovered to contain a segmentation violation via FoFiTrueType::computeTableChecksum(unsigned char*, int) at /xpdf/FoFiTrueType.cc.

- [https://github.com/Live-Hack-CVE/CVE-2022-35106](https://github.com/Live-Hack-CVE/CVE-2022-35106) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35106.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35106.svg)


## CVE-2022-35105
 SWFTools commit 772e55a2 was discovered to contain a heap-buffer overflow via /bin/png2swf+0x552cea.

- [https://github.com/Live-Hack-CVE/CVE-2022-35105](https://github.com/Live-Hack-CVE/CVE-2022-35105) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35105.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35105.svg)


## CVE-2022-35104
 SWFTools commit 772e55a2 was discovered to contain a heap-buffer overflow via DCTStream::reset() at /xpdf/Stream.cc.

- [https://github.com/Live-Hack-CVE/CVE-2022-35104](https://github.com/Live-Hack-CVE/CVE-2022-35104) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35104.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35104.svg)


## CVE-2022-35101
 SWFTools commit 772e55a2 was discovered to contain a segmentation violation via /multiarch/memset-vec-unaligned-erms.S.

- [https://github.com/Live-Hack-CVE/CVE-2022-35101](https://github.com/Live-Hack-CVE/CVE-2022-35101) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35101.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35101.svg)


## CVE-2022-35100
 SWFTools commit 772e55a2 was discovered to contain a segmentation violation via gfxline_getbbox at /lib/gfxtools.c.

- [https://github.com/Live-Hack-CVE/CVE-2022-35100](https://github.com/Live-Hack-CVE/CVE-2022-35100) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35100.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35100.svg)


## CVE-2022-35013
 PNGDec commit 8abf6be was discovered to contain a FPE via SaveBMP at /linux/main.cpp.

- [https://github.com/Live-Hack-CVE/CVE-2022-35013](https://github.com/Live-Hack-CVE/CVE-2022-35013) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35013.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35013.svg)


## CVE-2022-35012
 PNGDec commit 8abf6be was discovered to contain a heap buffer overflow via SaveBMP at /linux/main.cpp.

- [https://github.com/Live-Hack-CVE/CVE-2022-35012](https://github.com/Live-Hack-CVE/CVE-2022-35012) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35012.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35012.svg)


## CVE-2022-35011
 PNGDec commit 8abf6be was discovered to contain a global buffer overflow via inflate_fast at /src/inffast.c.

- [https://github.com/Live-Hack-CVE/CVE-2022-35011](https://github.com/Live-Hack-CVE/CVE-2022-35011) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35011.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35011.svg)


## CVE-2022-35010
 PNGDec commit 8abf6be was discovered to contain a heap buffer overflow via asan_interceptors_memintrinsics.cpp.

- [https://github.com/Live-Hack-CVE/CVE-2022-35010](https://github.com/Live-Hack-CVE/CVE-2022-35010) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35010.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35010.svg)


## CVE-2022-35009
 PNGDec commit 8abf6be was discovered to contain a memory allocation problem via asan_malloc_linux.cpp.

- [https://github.com/Live-Hack-CVE/CVE-2022-35009](https://github.com/Live-Hack-CVE/CVE-2022-35009) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35009.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35009.svg)


## CVE-2022-35008
 PNGDec commit 8abf6be was discovered to contain a stack overflow via /linux/main.cpp.

- [https://github.com/Live-Hack-CVE/CVE-2022-35008](https://github.com/Live-Hack-CVE/CVE-2022-35008) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35008.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35008.svg)


## CVE-2022-35007
 PNGDec commit 8abf6be was discovered to contain a heap buffer overflow via __interceptor_fwrite.part.57 at sanitizer_common_interceptors.inc.

- [https://github.com/Live-Hack-CVE/CVE-2022-35007](https://github.com/Live-Hack-CVE/CVE-2022-35007) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35007.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35007.svg)


## CVE-2022-35004
 JPEGDEC commit be4843c was discovered to contain a FPE via TIFFSHORT at /src/jpeg.inl.

- [https://github.com/Live-Hack-CVE/CVE-2022-35004](https://github.com/Live-Hack-CVE/CVE-2022-35004) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35004.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35004.svg)


## CVE-2022-35003
 JPEGDEC commit be4843c was discovered to contain a global buffer overflow via ucDitherBuffer at /src/jpeg.inl.

- [https://github.com/Live-Hack-CVE/CVE-2022-35003](https://github.com/Live-Hack-CVE/CVE-2022-35003) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35003.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35003.svg)


## CVE-2022-35002
 JPEGDEC commit be4843c was discovered to contain a segmentation fault via TIFFSHORT at /src/jpeg.inl.

- [https://github.com/Live-Hack-CVE/CVE-2022-35002](https://github.com/Live-Hack-CVE/CVE-2022-35002) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35002.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35002.svg)


## CVE-2022-35000
 JPEGDEC commit be4843c was discovered to contain a segmentation fault via fseek at /libio/fseek.c.

- [https://github.com/Live-Hack-CVE/CVE-2022-35000](https://github.com/Live-Hack-CVE/CVE-2022-35000) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35000.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35000.svg)


## CVE-2022-34999
 JPEGDEC commit be4843c was discovered to contain a FPE via DecodeJPEG at /src/jpeg.inl.

- [https://github.com/Live-Hack-CVE/CVE-2022-34999](https://github.com/Live-Hack-CVE/CVE-2022-34999) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34999.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34999.svg)


## CVE-2022-34998
 JPEGDEC commit be4843c was discovered to contain a global buffer overflow via JPEGDecodeMCU at /src/jpeg.inl.

- [https://github.com/Live-Hack-CVE/CVE-2022-34998](https://github.com/Live-Hack-CVE/CVE-2022-34998) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34998.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34998.svg)


## CVE-2022-34919
 The file upload wizard in Zengenti Contensis Classic before 15.2.1.79 does not correctly check that a user has authenticated. By uploading a crafted aspx file, it is possible to execute arbitrary commands.

- [https://github.com/Live-Hack-CVE/CVE-2022-34919](https://github.com/Live-Hack-CVE/CVE-2022-34919) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34919.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34919.svg)


## CVE-2022-34868
 Authenticated Arbitrary Settings Update vulnerability in YooMoney &#1070;Kassa &#1076;&#1083;&#1103; WooCommerce plugin &lt;= 2.3.0 at WordPress.

- [https://github.com/Live-Hack-CVE/CVE-2022-34868](https://github.com/Live-Hack-CVE/CVE-2022-34868) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34868.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34868.svg)


## CVE-2022-34858
 Authentication Bypass vulnerability in miniOrange OAuth 2.0 client for SSO plugin &lt;= 1.11.3 at WordPress.

- [https://github.com/Live-Hack-CVE/CVE-2022-34858](https://github.com/Live-Hack-CVE/CVE-2022-34858) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34858.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34858.svg)


## CVE-2022-34857
 Reflected Cross-Site Scripting (XSS) vulnerability in smartypants SP Project &amp; Document Manager plugin &lt;= 4.59 at WordPress

- [https://github.com/Live-Hack-CVE/CVE-2022-34857](https://github.com/Live-Hack-CVE/CVE-2022-34857) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34857.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34857.svg)


## CVE-2022-34776
 Tabit - giftcard stealth. Several APIs on the web system display, without authorization, sensitive information such as health statements, previous bills in a specific restaurant, alcohol consumption and smoking habits. Each of the described APIs, has in its URL one or more MongoDB ID which is not so simple to enumerate. However, they each receive a 'tiny URL' in tabits domain, in the form of https://tbit.be/{suffix} with suffix being a 5 character long string containing numbers, lower and upper case letters. It is not so simple to enumerate them all, but really easy to find some that work and lead to a personal endpoint. Furthermore, the redirect URL disclosed the MongoDB IDs discussed above, and we could use them to query other endpoints disclosing more personal information.

- [https://github.com/Live-Hack-CVE/CVE-2022-34776](https://github.com/Live-Hack-CVE/CVE-2022-34776) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34776.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34776.svg)


## CVE-2022-34775
 Tabit - Excessive data exposure. Another endpoint mapped by the tiny url, was one for reservation cancellation, containing the MongoDB ID of the reservation, and organization. This can be used to query the http://tgm-api.tabit.cloud/rsv/management/{reservationId}?organization={orgId} API which returns a lot of data regarding the reservation (OWASP: API3): Name, mail, phone number, the number of visits of the user to this specific restaurant, the money he spent there, the money he spent on alcohol, whether he left a deposit etc. This information can easily be used for a phishing attack.

- [https://github.com/Live-Hack-CVE/CVE-2022-34775](https://github.com/Live-Hack-CVE/CVE-2022-34775) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34775.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34775.svg)


## CVE-2022-34774
 Tabit - Arbitrary account modification. One of the endpoints mapped by the tiny URL, was a page where an adversary can modify personal details, such as email addresses and phone numbers of a specific user in a restaurant's loyalty program. Possibly allowing account takeover (the mail can be used to reset password).

- [https://github.com/Live-Hack-CVE/CVE-2022-34774](https://github.com/Live-Hack-CVE/CVE-2022-34774) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34774.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34774.svg)


## CVE-2022-34773
 Tabit - HTTP Method manipulation. https://bridge.tabit.cloud/configuration/addresses-query - can be POST-ed to add addresses to the DB. This is an example of OWASP:API8 &#8211; Injection.

- [https://github.com/Live-Hack-CVE/CVE-2022-34773](https://github.com/Live-Hack-CVE/CVE-2022-34773) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34773.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34773.svg)


## CVE-2022-34772
 Tabit - password enumeration. Description: Tabit - password enumeration. The passwords for the Tabit system is a 4 digit OTP. One can resend OTP and try logging in indefinitely. Once again, this is an example of OWASP: API4 - Rate limiting.

- [https://github.com/Live-Hack-CVE/CVE-2022-34772](https://github.com/Live-Hack-CVE/CVE-2022-34772) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34772.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34772.svg)


## CVE-2022-34771
 Tabit - arbitrary SMS send on Tabits behalf. The resend OTP API of tabit allows an adversary to send messages on tabits behalf to anyone registered on the system - the API receives the parameters: phone number, and CustomMessage, We can use that API to craft malicious messages to any user of the system. In addition, the API probably has some kind of template injection potential. When entering {{OTP}} in the custom message field it is formatted into an OTP.

- [https://github.com/Live-Hack-CVE/CVE-2022-34771](https://github.com/Live-Hack-CVE/CVE-2022-34771) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34771.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34771.svg)


## CVE-2022-34770
 Tabit - sensitive information disclosure. Several APIs on the web system display, without authorization, sensitive information such as health statements, previous bills in a specific restaurant, alcohol consumption and smoking habits. Each of the described API&#8217;s, has in its URL one or more MongoDB ID which is not so simple to enumerate. However, they each receive a &#8216;tiny URL&#8217; in Tabit&#8217;s domain, in the form of https://tbit.be/{suffix} with suffix being a 5 characters long string containing numbers, lower- and upper-case letters. It is not so simple to enumerate them all, but really easy to find some that work and lead to a personal endpoint. This is both an example of OWASP: API4 - rate limiting and OWASP: API1 - Broken object level authorization. Furthermore, the redirect URL disclosed the MongoDB IDs discussed above, and we could use them to query other endpoints disclosing more personal information. For example: The URL https://tabitisrael.co.il/online-reservations/health-statement?orgId={org_id}&amp;healthStatementId={health_statement_id} is used to invite friends to fill a health statement before attending the restaurant. We can use the health_statement_id to access the https://tgm-api.tabit.cloud/health-statement/{health_statement_id} API which disclose medical information as well as id number.

- [https://github.com/Live-Hack-CVE/CVE-2022-34770](https://github.com/Live-Hack-CVE/CVE-2022-34770) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34770.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34770.svg)


## CVE-2022-34659
 A vulnerability has been identified in Simcenter STAR-CCM+ (All versions only if the Power-on-Demand public license server is used). Affected applications expose user, host and display name of users, when the public license server is used. This could allow an attacker to retrieve this information.

- [https://github.com/Live-Hack-CVE/CVE-2022-34659](https://github.com/Live-Hack-CVE/CVE-2022-34659) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34659.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34659.svg)


## CVE-2022-34658
 Multiple Authenticated (contributor+) Persistent Cross-Site Scripting (XSS) vulnerabilities in W3 Eden Download Manager plugin &lt;= 3.2.48 at WordPress.

- [https://github.com/Live-Hack-CVE/CVE-2022-34658](https://github.com/Live-Hack-CVE/CVE-2022-34658) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34658.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34658.svg)


## CVE-2022-34652
 A sql injection vulnerability exists in the ObjectYPT functionality of WWBN AVideo 11.6 and dev master commit 3f7c0364. A specially-crafted HTTP request can lead to a SQL injection. An attacker can send an HTTP request to trigger this vulnerability.This vulnerability exists in the Live Schedules plugin, allowing an attacker to inject SQL by manipulating the description parameter.

- [https://github.com/Live-Hack-CVE/CVE-2022-34652](https://github.com/Live-Hack-CVE/CVE-2022-34652) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34652.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34652.svg)


## CVE-2022-34648
 Authenticated (author+) Stored Cross-Site Scripting (XSS) vulnerability in dmitrylitvinov Uploading SVG, WEBP and ICO files plugin &lt;= 1.0.1 at WordPress.

- [https://github.com/Live-Hack-CVE/CVE-2022-34648](https://github.com/Live-Hack-CVE/CVE-2022-34648) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34648.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34648.svg)


## CVE-2022-34624
 Mealie1.0.0beta3 does not terminate download tokens after a user logs out, allowing attackers to perform a man-in-the-middle attack via a crafted GET request.

- [https://github.com/Live-Hack-CVE/CVE-2022-34624](https://github.com/Live-Hack-CVE/CVE-2022-34624) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34624.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34624.svg)


## CVE-2022-34623
 Mealie1.0.0beta3 is vulnerable to user enumeration via timing response discrepancy between users and non-users when an invalid password message is displayed during an authentication attempt.

- [https://github.com/Live-Hack-CVE/CVE-2022-34623](https://github.com/Live-Hack-CVE/CVE-2022-34623) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34623.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34623.svg)


## CVE-2022-34621
 Mealie 1.0.0beta3 was discovered to contain an Insecure Direct Object Reference (IDOR) vulnerability which allows attackers to modify user passwords and other attributes via modification of the user_id parameter.

- [https://github.com/Live-Hack-CVE/CVE-2022-34621](https://github.com/Live-Hack-CVE/CVE-2022-34621) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34621.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34621.svg)


## CVE-2022-34615
 Mealie 1.0.0beta3 employs weak password requirements which allows attackers to potentially gain unauthorized access to the application via brute-force attacks.

- [https://github.com/Live-Hack-CVE/CVE-2022-34615](https://github.com/Live-Hack-CVE/CVE-2022-34615) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34615.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34615.svg)


## CVE-2022-34488
 Improper buffer restrictions in the firmware for some Intel(R) NUC Laptop Kits before version BC0076 may allow a privileged user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-34488](https://github.com/Live-Hack-CVE/CVE-2022-34488) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34488.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34488.svg)


## CVE-2022-34486
 Path traversal vulnerability in PukiWiki versions 1.4.5 to 1.5.3 allows a remote authenticated attacker with an administrative privilege to execute a malicious script via unspecified vectors.

- [https://github.com/Live-Hack-CVE/CVE-2022-34486](https://github.com/Live-Hack-CVE/CVE-2022-34486) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34486.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34486.svg)


## CVE-2022-34347
 Cross-Site Request Forgery (CSRF) vulnerability in W3 Eden Download Manager plugin &lt;= 3.2.48 at WordPress.

- [https://github.com/Live-Hack-CVE/CVE-2022-34347](https://github.com/Live-Hack-CVE/CVE-2022-34347) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34347.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34347.svg)


## CVE-2022-34345
 Improper input validation in the firmware for some Intel(R) NUC Laptop Kits before version BC0076 may allow a privileged user to potentially enable escalation of privilege via physical access.

- [https://github.com/Live-Hack-CVE/CVE-2022-34345](https://github.com/Live-Hack-CVE/CVE-2022-34345) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34345.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34345.svg)


## CVE-2022-34294
 totd 1.5.3 uses a fixed UDP source port in upstream queries sent to DNS resolvers. This allows DNS cache poisoning because there is not enough entropy to prevent traffic injection attacks.

- [https://github.com/Live-Hack-CVE/CVE-2022-34294](https://github.com/Live-Hack-CVE/CVE-2022-34294) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34294.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34294.svg)


## CVE-2022-34259
 Adobe Commerce versions 2.4.3-p2 (and earlier), 2.3.7-p3 (and earlier) and 2.4.4 (and earlier) are affected by an Improper Access Control vulnerability that could result in a Security feature bypass. An attacker could leverage this vulnerability to impact the availability of a user's minor feature. Exploitation of this issue does not require user interaction.

- [https://github.com/Live-Hack-CVE/CVE-2022-34259](https://github.com/Live-Hack-CVE/CVE-2022-34259) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34259.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34259.svg)


## CVE-2022-34254
 Adobe Commerce versions 2.4.3-p2 (and earlier), 2.3.7-p3 (and earlier) and 2.4.4 (and earlier) are affected by an Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability that could be abused by an attacker to inject malicious scripts into the vulnerable endpoint. A low privileged attacker could leverage this vulnerability to read local files and to perform Stored XSS. Exploitation of this issue does not require user interaction.

- [https://github.com/Live-Hack-CVE/CVE-2022-34254](https://github.com/Live-Hack-CVE/CVE-2022-34254) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34254.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34254.svg)


## CVE-2022-34253
 Adobe Commerce versions 2.4.3-p2 (and earlier), 2.3.7-p3 (and earlier) and 2.4.4 (and earlier) are affected by an XML Injection vulnerability in the Widgets Module. An attacker with admin privileges can trigger a specially crafted script to achieve remote code execution. Exploitation of this issue does not require user interaction.

- [https://github.com/Live-Hack-CVE/CVE-2022-34253](https://github.com/Live-Hack-CVE/CVE-2022-34253) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34253.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34253.svg)


## CVE-2022-34156
 'Hulu / &#12501;&#12540;&#12523;&#12540;' App for iOS versions prior to 3.0.81 improperly verifies server certificates, which may allow an attacker to eavesdrop on an encrypted communication via a man-in-the-middle attack.

- [https://github.com/Live-Hack-CVE/CVE-2022-34156](https://github.com/Live-Hack-CVE/CVE-2022-34156) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34156.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34156.svg)


## CVE-2022-34149
 Authentication Bypass vulnerability in miniOrange WP OAuth Server plugin &lt;= 3.0.4 at WordPress.

- [https://github.com/Live-Hack-CVE/CVE-2022-34149](https://github.com/Live-Hack-CVE/CVE-2022-34149) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34149.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34149.svg)


## CVE-2022-33994
 The Gutenberg plugin through 13.7.3 for WordPress allows stored XSS by the Contributor role via an SVG document to the &quot;Insert from URL&quot; feature. NOTE: the XSS payload does not execute in the context of the WordPress instance's domain; however, analogous attempts by low-privileged users to reference SVG documents are blocked by some similar products, and this behavioral difference might have security relevance to some WordPress site administrators.

- [https://github.com/Live-Hack-CVE/CVE-2022-33994](https://github.com/Live-Hack-CVE/CVE-2022-33994) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33994.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33994.svg)


## CVE-2022-33993
 Misinterpretation of special domain name characters in DNRD (aka Domain Name Relay Daemon) 2.20.3 leads to cache poisoning because domain names and their associated IP addresses are cached in their misinterpreted form.

- [https://github.com/Live-Hack-CVE/CVE-2022-33993](https://github.com/Live-Hack-CVE/CVE-2022-33993) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33993.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33993.svg)


## CVE-2022-33992
 DNRD (aka Domain Name Relay Daemon) 2.20.3 forwards and caches DNS queries with the CD (aka checking disabled) bit set to 1. This leads to disabling of DNSSEC protection provided by upstream resolvers.

- [https://github.com/Live-Hack-CVE/CVE-2022-33992](https://github.com/Live-Hack-CVE/CVE-2022-33992) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33992.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33992.svg)


## CVE-2022-33991
 dproxy-nexgen (aka dproxy nexgen) forwards and caches DNS queries with the CD (aka checking disabled) bit set to 1. This leads to disabling of DNSSEC protection provided by upstream resolvers.

- [https://github.com/Live-Hack-CVE/CVE-2022-33991](https://github.com/Live-Hack-CVE/CVE-2022-33991) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33991.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33991.svg)


## CVE-2022-33990
 Misinterpretation of special domain name characters in dproxy-nexgen (aka dproxy nexgen) leads to cache poisoning because domain names and their associated IP addresses are cached in their misinterpreted form.

- [https://github.com/Live-Hack-CVE/CVE-2022-33990](https://github.com/Live-Hack-CVE/CVE-2022-33990) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33990.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33990.svg)


## CVE-2022-33989
 dproxy-nexgen (aka dproxy nexgen) uses a static UDP source port (selected randomly only at boot time) in upstream queries sent to DNS resolvers. This allows DNS cache poisoning because there is not enough entropy to prevent traffic injection attacks.

- [https://github.com/Live-Hack-CVE/CVE-2022-33989](https://github.com/Live-Hack-CVE/CVE-2022-33989) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33989.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33989.svg)


## CVE-2022-33988
 dproxy-nexgen (aka dproxy nexgen) re-uses the DNS transaction id (TXID) value from client queries, which allows attackers (able to send queries to the resolver) to conduct DNS cache-poisoning attacks because the TXID value is known to the attacker.

- [https://github.com/Live-Hack-CVE/CVE-2022-33988](https://github.com/Live-Hack-CVE/CVE-2022-33988) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33988.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33988.svg)


## CVE-2022-33939
 CENTUM VP / CS 3000 controller FCS (CP31, CP33, CP345, CP401, and CP451) contains an issue in processing communication packets, which may lead to resource consumption. If this vulnerability is exploited, an attacker may cause a denial of service (DoS) condition in ADL communication by sending a specially crafted packet to the affected product.

- [https://github.com/Live-Hack-CVE/CVE-2022-33939](https://github.com/Live-Hack-CVE/CVE-2022-33939) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33939.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33939.svg)


## CVE-2022-33932
 Dell PowerScale OneFS, versions 9.0.0 up to and including 9.1.0.19, 9.2.1.12, 9.3.0.6, and 9.4.0.2, contain an unprotected primary channel vulnerability. An unauthenticated network malicious attacker may potentially exploit this vulnerability, leading to a denial of filesystem services.

- [https://github.com/Live-Hack-CVE/CVE-2022-33932](https://github.com/Live-Hack-CVE/CVE-2022-33932) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33932.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33932.svg)


## CVE-2022-33916
 OPC UA .NET Standard Reference Server 1.04.368 allows a remote attacker to cause the application to access sensitive information.

- [https://github.com/Live-Hack-CVE/CVE-2022-33916](https://github.com/Live-Hack-CVE/CVE-2022-33916) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33916.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33916.svg)


## CVE-2022-33900
 PHP Object Injection vulnerability in Easy Digital Downloads plugin &lt;= 3.0.1 at WordPress.

- [https://github.com/Live-Hack-CVE/CVE-2022-33900](https://github.com/Live-Hack-CVE/CVE-2022-33900) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33900.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33900.svg)


## CVE-2022-33311
 Browse restriction bypass vulnerability in Address Book of Cybozu Office 10.0.0 to 10.8.5 allows a remote authenticated attacker to obtain the data of Address Book via unspecified vectors.

- [https://github.com/Live-Hack-CVE/CVE-2022-33311](https://github.com/Live-Hack-CVE/CVE-2022-33311) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33311.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33311.svg)


## CVE-2022-33209
 Improper input validation in the firmware for some Intel(R) NUC Laptop Kits before version BC0076 may allow a privileged user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-33209](https://github.com/Live-Hack-CVE/CVE-2022-33209) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33209.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33209.svg)


## CVE-2022-33172
 de.fac2 1.34 allows bypassing the User Presence protection mechanism when there is malware on the victim's PC.

- [https://github.com/Live-Hack-CVE/CVE-2022-33172](https://github.com/Live-Hack-CVE/CVE-2022-33172) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33172.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33172.svg)


## CVE-2022-33151
 Cross-site scripting vulnerability in the specific parameters of Cybozu Office 10.0.0 to 10.8.5 allows remote attackers to inject an arbitrary script via unspecified vectors.

- [https://github.com/Live-Hack-CVE/CVE-2022-33151](https://github.com/Live-Hack-CVE/CVE-2022-33151) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33151.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33151.svg)


## CVE-2022-33149
 A sql injection vulnerability exists in the ObjectYPT functionality of WWBN AVideo 11.6 and dev master commit 3f7c0364. A specially-crafted HTTP request can lead to a SQL injection. An attacker can send an HTTP request to trigger this vulnerability.This vulnerability exists in the CloneSite plugin, allowing an attacker to inject SQL by manipulating the url parameter.

- [https://github.com/Live-Hack-CVE/CVE-2022-33149](https://github.com/Live-Hack-CVE/CVE-2022-33149) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33149.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33149.svg)


## CVE-2022-33148
 A sql injection vulnerability exists in the ObjectYPT functionality of WWBN AVideo 11.6 and dev master commit 3f7c0364. A specially-crafted HTTP request can lead to a SQL injection. An attacker can send an HTTP request to trigger this vulnerability.This vulnerability exists in the Live Schedules plugin, allowing an attacker to inject SQL by manipulating the title parameter.

- [https://github.com/Live-Hack-CVE/CVE-2022-33148](https://github.com/Live-Hack-CVE/CVE-2022-33148) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33148.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33148.svg)


## CVE-2022-33147
 A sql injection vulnerability exists in the ObjectYPT functionality of WWBN AVideo 11.6 and dev master commit 3f7c0364. A specially-crafted HTTP request can lead to a SQL injection. An attacker can send an HTTP request to trigger this vulnerability.This vulnerability exists in the aVideoEncoder functionality which can be used to add new videos, allowing an attacker to inject SQL by manipulating the videoDownloadedLink or duration parameter.

- [https://github.com/Live-Hack-CVE/CVE-2022-33147](https://github.com/Live-Hack-CVE/CVE-2022-33147) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33147.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33147.svg)


## CVE-2022-33142
 Authenticated (subscriber+) Denial Of Service (DoS) vulnerability in WordPlus WordPress Better Messages plugin &lt;= 1.9.10.57 at WordPress.

- [https://github.com/Live-Hack-CVE/CVE-2022-33142](https://github.com/Live-Hack-CVE/CVE-2022-33142) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33142.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33142.svg)


## CVE-2022-32840
 This issue was addressed with improved checks. This issue is fixed in macOS Monterey 12.5, watchOS 8.7, iOS 15.6 and iPadOS 15.6. An app may be able to execute arbitrary code with kernel privileges.

- [https://github.com/Live-Hack-CVE/CVE-2022-32840](https://github.com/Live-Hack-CVE/CVE-2022-32840) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32840.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32840.svg)


## CVE-2022-32810
 The issue was addressed with improved memory handling. This issue is fixed in macOS Monterey 12.5, watchOS 8.7, iOS 15.6 and iPadOS 15.6. An app may be able to execute arbitrary code with kernel privileges.

- [https://github.com/Live-Hack-CVE/CVE-2022-32810](https://github.com/Live-Hack-CVE/CVE-2022-32810) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32810.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32810.svg)


## CVE-2022-32778
 An information disclosure vulnerability exists in the cookie functionality of WWBN AVideo 11.6 and dev master commit 3f7c0364. The session cookie and the pass cookie miss the HttpOnly flag, making them accessible via JavaScript. The session cookie also misses the secure flag, which allows the session cookie to be leaked over non-HTTPS connections. This could allow an attacker to steal the session cookie via crafted HTTP requests.This vulnerability is for the pass cookie, which contains the hashed password and can be leaked via JavaScript.

- [https://github.com/Live-Hack-CVE/CVE-2022-32778](https://github.com/Live-Hack-CVE/CVE-2022-32778) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32778.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32778.svg)


## CVE-2022-32777
 An information disclosure vulnerability exists in the cookie functionality of WWBN AVideo 11.6 and dev master commit 3f7c0364. The session cookie and the pass cookie miss the HttpOnly flag, making them accessible via JavaScript. The session cookie also misses the secure flag, which allows the session cookie to be leaked over non-HTTPS connections. This could allow an attacker to steal the session cookie via crafted HTTP requests.This vulnerabilty is for the session cookie which can be leaked via JavaScript.

- [https://github.com/Live-Hack-CVE/CVE-2022-32777](https://github.com/Live-Hack-CVE/CVE-2022-32777) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32777.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32777.svg)


## CVE-2022-32772
 A cross-site scripting (xss) vulnerability exists in the footer alerts functionality of WWBN AVideo 11.6 and dev master commit 3f7c0364. A specially-crafted HTTP request can lead to arbitrary Javascript execution. An attacker can get an authenticated user to send a crafted HTTP request to trigger this vulnerability.This vulnerability arrises from the &quot;msg&quot; parameter which is inserted into the document with insufficient sanitization.

- [https://github.com/Live-Hack-CVE/CVE-2022-32772](https://github.com/Live-Hack-CVE/CVE-2022-32772) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32772.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32772.svg)


## CVE-2022-32771
 A cross-site scripting (xss) vulnerability exists in the footer alerts functionality of WWBN AVideo 11.6 and dev master commit 3f7c0364. A specially-crafted HTTP request can lead to arbitrary Javascript execution. An attacker can get an authenticated user to send a crafted HTTP request to trigger this vulnerability.This vulnerability arrises from the &quot;success&quot; parameter which is inserted into the document with insufficient sanitization.

- [https://github.com/Live-Hack-CVE/CVE-2022-32771](https://github.com/Live-Hack-CVE/CVE-2022-32771) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32771.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32771.svg)


## CVE-2022-32770
 A cross-site scripting (xss) vulnerability exists in the footer alerts functionality of WWBN AVideo 11.6 and dev master commit 3f7c0364. A specially-crafted HTTP request can lead to arbitrary Javascript execution. An attacker can get an authenticated user to send a crafted HTTP request to trigger this vulnerability.This vulnerability arrises from the &quot;toast&quot; parameter which is inserted into the document with insufficient sanitization.

- [https://github.com/Live-Hack-CVE/CVE-2022-32770](https://github.com/Live-Hack-CVE/CVE-2022-32770) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32770.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32770.svg)


## CVE-2022-32769
 Multiple authentication bypass vulnerabilities exist in the objects id handling functionality of WWBN AVideo 11.6 and dev master commit 3f7c0364. A specially-crafted HTTP request by an authenticated user can lead to unauthorized access and takeover of resources. An attacker can send an HTTP request to trigger this vulnerability.This vulnerability exists in the Playlists plugin, allowing an attacker to bypass authentication by guessing a sequential ID, allowing them to take over the another user's playlists.

- [https://github.com/Live-Hack-CVE/CVE-2022-32769](https://github.com/Live-Hack-CVE/CVE-2022-32769) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32769.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32769.svg)


## CVE-2022-32768
 Multiple authentication bypass vulnerabilities exist in the objects id handling functionality of WWBN AVideo 11.6 and dev master commit 3f7c0364. A specially-crafted HTTP request by an authenticated user can lead to unauthorized access and takeover of resources. An attacker can send an HTTP request to trigger this vulnerability.This vulnerability exists in the Live Schedules plugin, allowing an attacker to bypass authentication by guessing a sequential ID, allowing them to take over the another user's streams.

- [https://github.com/Live-Hack-CVE/CVE-2022-32768](https://github.com/Live-Hack-CVE/CVE-2022-32768) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32768.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32768.svg)


## CVE-2022-32761
 An information disclosure vulnerability exists in the aVideoEncoderReceiveImage functionality of WWBN AVideo 11.6 and dev master commit 3f7c0364. A specially-crafted HTTP request can lead to arbitrary file read. An attacker can send an HTTP request to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-32761](https://github.com/Live-Hack-CVE/CVE-2022-32761) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32761.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32761.svg)


## CVE-2022-32745
 A flaw was found in Samba. Samba AD users can cause the server to access uninitialized data with an LDAP add or modify the request, usually resulting in a segmentation fault.

- [https://github.com/Live-Hack-CVE/CVE-2022-32745](https://github.com/Live-Hack-CVE/CVE-2022-32745) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32745.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32745.svg)


## CVE-2022-32744
 A flaw was found in Samba. The KDC accepts kpasswd requests encrypted with any key known to it. By encrypting forged kpasswd requests with its own key, a user can change other users' passwords, enabling full domain takeover.

- [https://github.com/Live-Hack-CVE/CVE-2022-32744](https://github.com/Live-Hack-CVE/CVE-2022-32744) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32744.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32744.svg)


## CVE-2022-32583
 Operation restriction bypass vulnerability in Scheduler of Cybozu Office 10.0.0 to 10.8.5 allows a remote authenticated attacker to alter the data of Scheduler via unspecified vectors.

- [https://github.com/Live-Hack-CVE/CVE-2022-32583](https://github.com/Live-Hack-CVE/CVE-2022-32583) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32583.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32583.svg)


## CVE-2022-32579
 Improper initialization in the firmware for some Intel(R) NUC Laptop Kits before version BC0076 may allow a privileged user to potentially enable escalation of privilege via physical access.

- [https://github.com/Live-Hack-CVE/CVE-2022-32579](https://github.com/Live-Hack-CVE/CVE-2022-32579) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32579.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32579.svg)


## CVE-2022-32572
 An os command injection vulnerability exists in the aVideoEncoder wget functionality of WWBN AVideo 11.6 and dev master commit 3f7c0364. A specially-crafted HTTP request can lead to arbitrary command execution. An attacker can send an HTTP request to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-32572](https://github.com/Live-Hack-CVE/CVE-2022-32572) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32572.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32572.svg)


## CVE-2022-32544
 Operation restriction bypass vulnerability in Project of Cybozu Office 10.0.0 to 10.8.5 allows a remote authenticated attacker to alter the data of Project via unspecified vectors.

- [https://github.com/Live-Hack-CVE/CVE-2022-32544](https://github.com/Live-Hack-CVE/CVE-2022-32544) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32544.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32544.svg)


## CVE-2022-32480
 Dell PowerScale OneFS, versions 9.0.0, up to and including 9.1.0.19, 9.2.1.12, 9.3.0.6, and 9.4.0.2, contain an insecure default initialization of a resource vulnerability. A remote authenticated attacker may potentially exploit this vulnerability, leading to information disclosure.

- [https://github.com/Live-Hack-CVE/CVE-2022-32480](https://github.com/Live-Hack-CVE/CVE-2022-32480) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32480.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32480.svg)


## CVE-2022-32453
 HTTP header injection vulnerability in Cybozu Office 10.0.0 to 10.8.5 may allow a remote attacker to obtain and/or alter the data of the product via unspecified vectors.

- [https://github.com/Live-Hack-CVE/CVE-2022-32453](https://github.com/Live-Hack-CVE/CVE-2022-32453) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32453.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32453.svg)


## CVE-2022-32283
 Browse restriction bypass vulnerability in Cabinet of Cybozu Office 10.0.0 to 10.8.5 allows a remote authenticated attacker to obtain the data of Cabinet via unspecified vectors.

- [https://github.com/Live-Hack-CVE/CVE-2022-32283](https://github.com/Live-Hack-CVE/CVE-2022-32283) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32283.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32283.svg)


## CVE-2022-32282
 An improper password check exists in the login functionality of WWBN AVideo 11.6 and dev master commit 3f7c0364. An attacker that owns a users' password hash will be able to use it to directly login into the account, leading to increased privileges.

- [https://github.com/Live-Hack-CVE/CVE-2022-32282](https://github.com/Live-Hack-CVE/CVE-2022-32282) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32282.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32282.svg)


## CVE-2022-32148
 Improper exposure of client IP addresses in net/http before Go 1.17.12 and Go 1.18.4 can be triggered by calling httputil.ReverseProxy.ServeHTTP with a Request.Header map containing a nil value for the X-Forwarded-For header, which causes ReverseProxy to set the client IP as the value of the X-Forwarded-For header.

- [https://github.com/Live-Hack-CVE/CVE-2022-32148](https://github.com/Live-Hack-CVE/CVE-2022-32148) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32148.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32148.svg)


## CVE-2022-31813
 Apache HTTP Server 2.4.53 and earlier may not send the X-Forwarded-* headers to the origin server based on client side Connection header hop-by-hop mechanism. This may be used to bypass IP based authentication on the origin server/application.

- [https://github.com/Live-Hack-CVE/CVE-2022-31813](https://github.com/Live-Hack-CVE/CVE-2022-31813) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-31813.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-31813.svg)


## CVE-2022-31469
 OX App Suite through 7.10.6 allows XSS via a deep link, as demonstrated by class=&quot;deep-link-app&quot; for a /#!!&amp;app=%2e./ URI.

- [https://github.com/Live-Hack-CVE/CVE-2022-31469](https://github.com/Live-Hack-CVE/CVE-2022-31469) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-31469.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-31469.svg)


## CVE-2022-31238
 Dell PowerScale OneFS, versions 9.0.0 up to and including 9.1.0.19, 9.2.1.12, 9.3.0.6, and 9.4.0.2, contain a process invoked with sensitive information vulnerability. A CLI user may potentially exploit this vulnerability, leading to information disclosure.

- [https://github.com/Live-Hack-CVE/CVE-2022-31238](https://github.com/Live-Hack-CVE/CVE-2022-31238) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-31238.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-31238.svg)


## CVE-2022-31237
 Dell PowerScale OneFS, versions 9.2.0 up to and including 9.2.1.12 and 9.3.0.5 contain an improper preservation of permissions vulnerability in SyncIQ. A low privileged local attacker may potentially exploit this vulnerability, leading to limited information disclosure.

- [https://github.com/Live-Hack-CVE/CVE-2022-31237](https://github.com/Live-Hack-CVE/CVE-2022-31237) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-31237.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-31237.svg)


## CVE-2022-30693
 Information disclosure vulnerability in the system configuration of Cybozu Office 10.0.0 to 10.8.5 allows a remote attacker to obtain the data of the product via unspecified vectors.

- [https://github.com/Live-Hack-CVE/CVE-2022-30693](https://github.com/Live-Hack-CVE/CVE-2022-30693) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-30693.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-30693.svg)


## CVE-2022-30690
 A cross-site scripting (xss) vulnerability exists in the image403 functionality of WWBN AVideo 11.6 and dev master commit 3f7c0364. A specially-crafted HTTP request can lead to arbitrary Javascript execution. An attacker can get an authenticated user to send a crafted HTTP request to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-30690](https://github.com/Live-Hack-CVE/CVE-2022-30690) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-30690.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-30690.svg)


## CVE-2022-30605
 A privilege escalation vulnerability exists in the session id functionality of WWBN AVideo 11.6 and dev master commit 3f7c0364. A specially-crafted HTTP request can lead to increased privileges. An attacker can get an authenticated user to send a crafted HTTP request to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-30605](https://github.com/Live-Hack-CVE/CVE-2022-30605) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-30605.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-30605.svg)


## CVE-2022-30604
 Cross-site scripting vulnerability in the specific parameters of Cybozu Office 10.0.0 to 10.8.5 allows a remote attacker to inject an arbitrary script via unspecified vectors.

- [https://github.com/Live-Hack-CVE/CVE-2022-30604](https://github.com/Live-Hack-CVE/CVE-2022-30604) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-30604.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-30604.svg)


## CVE-2022-30576
 The Web Console component of TIBCO Software Inc.'s TIBCO Data Science - Workbench, TIBCO Statistica, TIBCO Statistica - Estore Edition, and TIBCO Statistica Trial contains an easily exploitable vulnerability that allows a low privileged attacker with network access to execute Stored Cross Site Scripting (XSS) on the affected system. A successful attack using this vulnerability requires human interaction from a person other than the attacker. Affected releases are TIBCO Software Inc.'s TIBCO Data Science - Workbench: versions 14.0.0 and below, TIBCO Statistica: versions 14.0.0 and below, TIBCO Statistica - Estore Edition: versions 14.0.0 and below, and TIBCO Statistica Trial: versions 14.0.0 and below.

- [https://github.com/Live-Hack-CVE/CVE-2022-30576](https://github.com/Live-Hack-CVE/CVE-2022-30576) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-30576.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-30576.svg)


## CVE-2022-30575
 The Web Console component of TIBCO Software Inc.'s TIBCO Data Science - Workbench, TIBCO Statistica, TIBCO Statistica - Estore Edition, and TIBCO Statistica Trial contains easily exploitable Reflected Cross Site Scripting (XSS) vulnerabilities that allow a low privileged attacker with network access to execute scripts targeting the affected system or the victim's local system. Affected releases are TIBCO Software Inc.'s TIBCO Data Science - Workbench: versions 14.0.0 and below, TIBCO Statistica: versions 14.0.0 and below, TIBCO Statistica - Estore Edition: versions 14.0.0 and below, and TIBCO Statistica Trial: versions 14.0.0 and below.

- [https://github.com/Live-Hack-CVE/CVE-2022-30575](https://github.com/Live-Hack-CVE/CVE-2022-30575) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-30575.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-30575.svg)


## CVE-2022-30556
 Apache HTTP Server 2.4.53 and earlier may return lengths to applications calling r:wsread() that point past the end of the storage allocated for the buffer.

- [https://github.com/Live-Hack-CVE/CVE-2022-30556](https://github.com/Live-Hack-CVE/CVE-2022-30556) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-30556.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-30556.svg)


## CVE-2022-30547
 A directory traversal vulnerability exists in the unzipDirectory functionality of WWBN AVideo 11.6 and dev master commit 3f7c0364. A specially-crafted HTTP request can lead to arbitrary command execution. An attacker can send an HTTP request to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-30547](https://github.com/Live-Hack-CVE/CVE-2022-30547) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-30547.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-30547.svg)


## CVE-2022-30534
 An OS command injection vulnerability exists in the aVideoEncoder chunkfile functionality of WWBN AVideo 11.6 and dev master commit 3f7c0364. A specially-crafted HTTP request can lead to arbitrary command execution. An attacker can send an HTTP request to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-30534](https://github.com/Live-Hack-CVE/CVE-2022-30534) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-30534.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-30534.svg)


## CVE-2022-30532
 In affected versions of Octopus Deploy, there is no logging of changes to artifacts within Octopus Deploy.

- [https://github.com/Live-Hack-CVE/CVE-2022-30532](https://github.com/Live-Hack-CVE/CVE-2022-30532) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-30532.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-30532.svg)


## CVE-2022-30296
 Insufficiently protected credentials in the Intel(R) Datacenter Group Event iOS application, all versions, may allow an unauthenticated user to potentially enable information disclosure via network access.

- [https://github.com/Live-Hack-CVE/CVE-2022-30296](https://github.com/Live-Hack-CVE/CVE-2022-30296) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-30296.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-30296.svg)


## CVE-2022-30264
 The Emerson ROC and FloBoss RTU product lines through 2022-05-02 perform insecure filesystem operations. They utilize the ROC protocol (4000/TCP, 5000/TCP) for communications between a master terminal and RTUs. Opcode 203 of this protocol allows a master terminal to transfer files to and from the flash filesystem and carrying out arbitrary file and directory read, write, and delete operations.

- [https://github.com/Live-Hack-CVE/CVE-2022-30264](https://github.com/Live-Hack-CVE/CVE-2022-30264) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-30264.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-30264.svg)


## CVE-2022-30262
 The Emerson ControlWave 'Next Generation' RTUs through 2022-05-02 mishandle firmware integrity. They utilize the BSAP-IP protocol to transmit firmware updates. Firmware updates are supplied as CAB archive files containing a binary firmware image. In all cases, firmware images were found to have no authentication (in the form of firmware signing) and only relied on insecure checksums for regular integrity checks.

- [https://github.com/Live-Hack-CVE/CVE-2022-30262](https://github.com/Live-Hack-CVE/CVE-2022-30262) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-30262.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-30262.svg)


## CVE-2022-30190
 Microsoft Windows Support Diagnostic Tool (MSDT) Remote Code Execution Vulnerability.

- [https://github.com/dianaross20/Cve-2022-30190](https://github.com/dianaross20/Cve-2022-30190) :  ![starts](https://img.shields.io/github/stars/dianaross20/Cve-2022-30190.svg) ![forks](https://img.shields.io/github/forks/dianaross20/Cve-2022-30190.svg)


## CVE-2022-30036
 MA Lighting grandMA2 Light has a password of root for the root account. NOTE: The vendor's position is that the product was designed for isolated networks. Also, the successor product, grandMA3, is not affected by this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-30036](https://github.com/Live-Hack-CVE/CVE-2022-30036) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-30036.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-30036.svg)


## CVE-2022-29960
 Emerson OpenBSI through 2022-04-29 uses weak cryptography. It is an engineering environment for the ControlWave and Bristol Babcock line of RTUs. DES with hardcoded cryptographic keys is used for protection of certain system credentials, engineering files, and sensitive utilities.

- [https://github.com/Live-Hack-CVE/CVE-2022-29960](https://github.com/Live-Hack-CVE/CVE-2022-29960) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-29960.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-29960.svg)


## CVE-2022-29891
 Browse restriction bypass vulnerability in Custom Ap of Cybozu Office 10.0.0 to 10.8.5 allows a remote authenticated attacker to obtain the data of Custom App via unspecified vectors.

- [https://github.com/Live-Hack-CVE/CVE-2022-29891](https://github.com/Live-Hack-CVE/CVE-2022-29891) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-29891.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-29891.svg)


## CVE-2022-29853
 OX App Suite through 8.2 allows XSS via a certain complex hierarchy that forces use of Show Entire Message for a huge HTML e-mail message.

- [https://github.com/Live-Hack-CVE/CVE-2022-29853](https://github.com/Live-Hack-CVE/CVE-2022-29853) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-29853.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-29853.svg)


## CVE-2022-29852
 OX App Suite through 8.2 allows XSS because BMFreehand10 and image/x-freehand are not blocked.

- [https://github.com/Live-Hack-CVE/CVE-2022-29852](https://github.com/Live-Hack-CVE/CVE-2022-29852) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-29852.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-29852.svg)


## CVE-2022-29805
 A Java Deserialization vulnerability in the Fishbowl Server in Fishbowl Inventory before 2022.4.1 allows remote attackers to execute arbitrary code via a crafted XML payload.

- [https://github.com/Live-Hack-CVE/CVE-2022-29805](https://github.com/Live-Hack-CVE/CVE-2022-29805) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-29805.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-29805.svg)


## CVE-2022-29526
 Go before 1.17.10 and 1.18.x before 1.18.2 has Incorrect Privilege Assignment. When called with a non-zero flags parameter, the Faccessat function could incorrectly report that a file is accessible.

- [https://github.com/Live-Hack-CVE/CVE-2022-29526](https://github.com/Live-Hack-CVE/CVE-2022-29526) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-29526.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-29526.svg)


## CVE-2022-29507
 Insufficiently protected credentials in the Intel(R) Team Blue mobile application in all versions may allow an authenticated user to potentially enable information disclosure via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-29507](https://github.com/Live-Hack-CVE/CVE-2022-29507) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-29507.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-29507.svg)


## CVE-2022-29487
 Cross-site scripting vulnerability in Cybozu Office 10.0.0 to 10.8.5 allows a remote attacker to inject an arbitrary script via unspecified vectors.

- [https://github.com/Live-Hack-CVE/CVE-2022-29487](https://github.com/Live-Hack-CVE/CVE-2022-29487) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-29487.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-29487.svg)


## CVE-2022-29476
 Unauthenticated Stored Cross-Site Scripting (XSS) vulnerability in 8 Degree Themes otification Bar for WordPress plugin &lt;= 1.1.8 at WordPress.

- [https://github.com/Live-Hack-CVE/CVE-2022-29476](https://github.com/Live-Hack-CVE/CVE-2022-29476) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-29476.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-29476.svg)


## CVE-2022-29468
 A cross-site request forgery (CSRF) vulnerability exists in WWBN AVideo 11.6 and dev master commit 3f7c0364. A specially-crafted HTTP request can lead to increased privileges. An attacker can get an authenticated user to send a crafted HTTP request to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-29468](https://github.com/Live-Hack-CVE/CVE-2022-29468) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-29468.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-29468.svg)


## CVE-2022-28883
 A Denial-of-Service (DoS) vulnerability was discovered in F-Secure &amp; WithSecure products whereby the aerdl unpack function crashes. This can lead to a possible scanning engine crash. The exploit can be triggered remotely by an attacker.

- [https://github.com/Live-Hack-CVE/CVE-2022-28883](https://github.com/Live-Hack-CVE/CVE-2022-28883) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28883.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28883.svg)


## CVE-2022-28882
 A Denial-of-Service (DoS) vulnerability was discovered in F-Secure &amp; WithSecure products whereby the aegen.dll will go into an infinite loop when unpacking PE files. This eventually leads to scanning engine crash. The exploit can be triggered remotely by an attacker.

- [https://github.com/Live-Hack-CVE/CVE-2022-28882](https://github.com/Live-Hack-CVE/CVE-2022-28882) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28882.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28882.svg)


## CVE-2022-28858
 Improper buffer restriction in the firmware for some Intel(R) NUC Laptop Kits before version BC0076 may allow a privileged user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-28858](https://github.com/Live-Hack-CVE/CVE-2022-28858) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28858.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28858.svg)


## CVE-2022-28757
 The Zoom Client for Meetings for macOS (Standard and for IT Admin) starting with version 5.7.3 and before 5.11.6 contains a vulnerability in the auto update process. A local low-privileged user could exploit this vulnerability to escalate their privileges to root.

- [https://github.com/Live-Hack-CVE/CVE-2022-28757](https://github.com/Live-Hack-CVE/CVE-2022-28757) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28757.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28757.svg)


## CVE-2022-28756
 The Zoom Client for Meetings for macOS (Standard and for IT Admin) starting with version 5.7.3 and before 5.11.5 contains a vulnerability in the auto update process. A local low-privileged user could exploit this vulnerability to escalate their privileges to root.

- [https://github.com/Live-Hack-CVE/CVE-2022-28756](https://github.com/Live-Hack-CVE/CVE-2022-28756) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28756.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28756.svg)


## CVE-2022-28755
 The Zoom Client for Meetings (for Android, iOS, Linux, macOS, and Windows) before version 5.11.0 are susceptible to a URL parsing vulnerability. If a malicious Zoom meeting URL is opened, the malicious link may direct the user to connect to an arbitrary network address, leading to additional attacks including the potential for remote code execution through launching executables from arbitrary paths.

- [https://github.com/Live-Hack-CVE/CVE-2022-28755](https://github.com/Live-Hack-CVE/CVE-2022-28755) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28755.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28755.svg)


## CVE-2022-28754
 Zoom On-Premise Meeting Connector MMR before version 4.8.129.20220714 contains an improper access control vulnerability. As a result, a malicious actor can join a meeting which they are authorized to join without appearing to the other participants, can admit themselves into the meeting from the waiting room, and can become host and cause other meeting disruptions.

- [https://github.com/Live-Hack-CVE/CVE-2022-28754](https://github.com/Live-Hack-CVE/CVE-2022-28754) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28754.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28754.svg)


## CVE-2022-28753
 Zoom On-Premise Meeting Connector MMR before version 4.8.129.20220714 contains an improper access control vulnerability. As a result, a malicious actor can join a meeting which they are authorized to join without appearing to the other participants, can admit themselves into the meeting from the waiting room, and can become host and cause other meeting disruptions.

- [https://github.com/Live-Hack-CVE/CVE-2022-28753](https://github.com/Live-Hack-CVE/CVE-2022-28753) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28753.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28753.svg)


## CVE-2022-28752
 Zoom Rooms for Conference Rooms for Windows versions before 5.11.0 are susceptible to a Local Privilege Escalation vulnerability. A local low-privileged malicious user could exploit this vulnerability to escalate their privileges to the SYSTEM user.

- [https://github.com/Live-Hack-CVE/CVE-2022-28752](https://github.com/Live-Hack-CVE/CVE-2022-28752) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28752.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28752.svg)


## CVE-2022-28751
 The Zoom Client for Meetings for MacOS (Standard and for IT Admin) before version 5.11.3 contains a vulnerability in the package signature validation during the update process. A local low-privileged user could exploit this vulnerability to escalate their privileges to root.

- [https://github.com/Live-Hack-CVE/CVE-2022-28751](https://github.com/Live-Hack-CVE/CVE-2022-28751) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28751.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28751.svg)


## CVE-2022-28750
 Zoom On-Premise Meeting Connector Zone Controller (ZC) before version 4.8.20220419.112 fails to properly parse STUN error codes, which can result in memory corruption and could allow a malicious actor to crash the application. In versions older than 4.8.12.20211115, this vulnerability could also be leveraged to execute arbitrary code.

- [https://github.com/Live-Hack-CVE/CVE-2022-28750](https://github.com/Live-Hack-CVE/CVE-2022-28750) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28750.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28750.svg)


## CVE-2022-28715
 Cross-site scripting vulnerability in the specific parameters of Cybozu Office 10.0.0 to 10.8.5 allows a remote attacker to inject an arbitrary script via unspecified vectors.

- [https://github.com/Live-Hack-CVE/CVE-2022-28715](https://github.com/Live-Hack-CVE/CVE-2022-28715) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28715.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28715.svg)


## CVE-2022-28712
 A cross-site scripting (xss) vulnerability exists in the videoAddNew functionality of WWBN AVideo 11.6 and dev master commit 3f7c0364. A specially-crafted HTTP request can lead to arbitrary Javascript execution. An attacker can get an authenticated user to send a crafted HTTP request to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-28712](https://github.com/Live-Hack-CVE/CVE-2022-28712) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28712.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28712.svg)


## CVE-2022-28710
 An information disclosure vulnerability exists in the chunkFile functionality of WWBN AVideo 11.6 and dev master commit 3f7c0364. A specially-crafted HTTP request can lead to arbitrary file read. An attacker can send an HTTP request to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-28710](https://github.com/Live-Hack-CVE/CVE-2022-28710) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28710.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28710.svg)


## CVE-2022-28709
 Improper access control in the firmware for some Intel(R) E810 Ethernet Controllers before version 1.6.1.9 may allow a privileged user to potentially enable denial of service via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-28709](https://github.com/Live-Hack-CVE/CVE-2022-28709) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28709.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28709.svg)


## CVE-2022-28696
 Uncontrolled search path in the Intel(R) Distribution for Python before version 2022.0.3 may allow an authenticated user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-28696](https://github.com/Live-Hack-CVE/CVE-2022-28696) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28696.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28696.svg)


## CVE-2022-28681
 This vulnerability allows remote attackers to disclose sensitive information on affected installations of Foxit PDF Reader 11.2.1.53537. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the deletePages method. By performing actions in JavaScript, an attacker can trigger a read past the end of an allocated object. An attacker can leverage this in conjunction with other vulnerabilities to execute arbitrary code in the context of the current process. Was ZDI-CAN-16825.

- [https://github.com/Live-Hack-CVE/CVE-2022-28681](https://github.com/Live-Hack-CVE/CVE-2022-28681) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28681.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28681.svg)


## CVE-2022-28680
 This vulnerability allows remote attackers to execute arbitrary code on affected installations of Foxit PDF Reader 11.2.1.53537. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the handling of Annotation objects. The issue results from the lack of validating the existence of an object prior to performing operations on the object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-16821.

- [https://github.com/Live-Hack-CVE/CVE-2022-28680](https://github.com/Live-Hack-CVE/CVE-2022-28680) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28680.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28680.svg)


## CVE-2022-28679
 This vulnerability allows remote attackers to execute arbitrary code on affected installations of Foxit PDF Reader 11.2.1.53537. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the handling of Annotation objects. The issue results from the lack of validating the existence of an object prior to performing operations on the object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-16861.

- [https://github.com/Live-Hack-CVE/CVE-2022-28679](https://github.com/Live-Hack-CVE/CVE-2022-28679) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28679.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28679.svg)


## CVE-2022-28678
 This vulnerability allows remote attackers to execute arbitrary code on affected installations of Foxit PDF Reader 11.2.1.53537. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the handling of Doc objects. The issue results from the lack of validating the existence of an object prior to performing operations on the object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-16805.

- [https://github.com/Live-Hack-CVE/CVE-2022-28678](https://github.com/Live-Hack-CVE/CVE-2022-28678) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28678.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28678.svg)


## CVE-2022-28670
 This vulnerability allows remote attackers to disclose sensitive information on affected installations of Foxit PDF Reader 11.2.1.53537. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the processing of AcroForms. Crafted data in an AcroForm can trigger a read past the end of an allocated buffer. An attacker can leverage this in conjunction with other vulnerabilities to execute arbitrary code in the context of the current process. Was ZDI-CAN-16523.

- [https://github.com/Live-Hack-CVE/CVE-2022-28670](https://github.com/Live-Hack-CVE/CVE-2022-28670) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28670.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28670.svg)


## CVE-2022-28636
 A potential local arbitrary code execution and a local denial of service (DoS) vulnerability within an isolated process were discovered in HPE Integrated Lights-Out 5 (iLO 5) firmware version(s): Prior to 2.71. An unprivileged user could locally exploit this vulnerability to potentially execute arbitrary code in an isolated process resulting in a complete loss of confidentiality, integrity, and availability within that process. In addition, an unprivileged user could exploit a denial of service (DoS) vulnerability in an isolated process resulting in a complete loss of availability within that process. A successful attack depends on conditions beyond the attackers control. HPE has provided a firmware update to resolve this vulnerability in HPE Integrated Lights-Out 5 (iLO 5).

- [https://github.com/Live-Hack-CVE/CVE-2022-28636](https://github.com/Live-Hack-CVE/CVE-2022-28636) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28636.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28636.svg)


## CVE-2022-28635
 A potential local arbitrary code execution and a local denial of service (DoS) vulnerability within an isolated process were discovered in HPE Integrated Lights-Out 5 (iLO 5) firmware version(s): Prior to 2.71. An unprivileged user could locally exploit this vulnerability to potentially execute arbitrary code in an isolated process resulting in a complete loss of confidentiality, integrity, and availability within that process. In addition, an unprivileged user could exploit a denial of service (DoS) vulnerability in an isolated process resulting in a complete loss of availability within that process. A successful attack depends on conditions beyond the attackers control. HPE has provided a firmware update to resolve this vulnerability in HPE Integrated Lights-Out 5 (iLO 5).

- [https://github.com/Live-Hack-CVE/CVE-2022-28635](https://github.com/Live-Hack-CVE/CVE-2022-28635) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28635.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28635.svg)


## CVE-2022-28634
 A local arbitrary code execution vulnerability was discovered in HPE Integrated Lights-Out 5 (iLO 5) firmware version(s): Prior to 2.71. A highly privileged user could locally exploit this vulnerability to execute arbitrary code resulting in a complete loss of confidentiality, integrity, and availability. HPE has provided a firmware update to resolve this vulnerability in HPE Integrated Lights-Out 5 (iLO 5).

- [https://github.com/Live-Hack-CVE/CVE-2022-28634](https://github.com/Live-Hack-CVE/CVE-2022-28634) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28634.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28634.svg)


## CVE-2022-28633
 A local disclosure of sensitive information and a local unauthorized data modification vulnerability were discovered in HPE Integrated Lights-Out 5 (iLO 5) firmware version(s): Prior to 2.71. An unprivileged user could locally exploit this vulnerability to read and write to the iLO 5 firmware file system resulting in a complete loss of confidentiality and a partial loss of integrity and availability. HPE has provided a firmware update to resolve this vulnerability in HPE Integrated Lights-Out 5 (iLO 5).

- [https://github.com/Live-Hack-CVE/CVE-2022-28633](https://github.com/Live-Hack-CVE/CVE-2022-28633) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28633.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28633.svg)


## CVE-2022-28632
 A potential arbitrary code execution and a denial of service (DoS) vulnerability within an isolated process were discovered in HPE Integrated Lights-Out 5 (iLO 5) firmware version(s): Prior to 2.71. An unprivileged user could exploit this vulnerability in an adjacent network to potentially execute arbitrary code in an isolated process resulting in a complete loss of confidentiality, integrity, and availability within that process. In addition, an unprivileged user could exploit a denial of service (DoS) vulnerability in an isolated process resulting in a complete loss of availability within that process. HPE has provided a firmware update to resolve this vulnerability in HPE Integrated Lights-Out 5 (iLO 5).

- [https://github.com/Live-Hack-CVE/CVE-2022-28632](https://github.com/Live-Hack-CVE/CVE-2022-28632) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28632.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28632.svg)


## CVE-2022-28631
 A potential arbitrary code execution and a denial of service (DoS) vulnerability within an isolated process were discovered in HPE Integrated Lights-Out 5 (iLO 5) firmware version(s): Prior to 2.71. An unprivileged user could exploit this vulnerability in an adjacent network to potentially execute arbitrary code in an isolated process resulting in a complete loss of confidentiality, integrity, and availability within that process. In addition, an unprivileged user could exploit a denial of service (DoS) vulnerability in an isolated process resulting in a complete loss of availability within that process. HPE has provided a firmware update to resolve this vulnerability in HPE Integrated Lights-Out 5 (iLO 5).

- [https://github.com/Live-Hack-CVE/CVE-2022-28631](https://github.com/Live-Hack-CVE/CVE-2022-28631) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28631.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28631.svg)


## CVE-2022-28630
 A local arbitrary code execution vulnerability was discovered in HPE Integrated Lights-Out 5 (iLO 5) firmware version(s): Prior to 2.71. An unprivileged user could locally exploit this vulnerability to execute arbitrary code resulting in a complete loss of confidentiality and integrity, and a partial loss of availability. User interaction is required to exploit this vulnerability. HPE has provided a firmware update to resolve this vulnerability in HPE Integrated Lights-Out 5 (iLO 5).

- [https://github.com/Live-Hack-CVE/CVE-2022-28630](https://github.com/Live-Hack-CVE/CVE-2022-28630) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28630.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28630.svg)


## CVE-2022-28629
 A local arbitrary code execution vulnerability was discovered in HPE Integrated Lights-Out 5 (iLO 5) firmware version(s): Prior to 2.71. A low privileged user could locally exploit this vulnerability to execute arbitrary code resulting in a complete loss of confidentiality, integrity, and availability. HPE has provided a firmware update to resolve this vulnerability in HPE Integrated Lights-Out 5 (iLO 5).

- [https://github.com/Live-Hack-CVE/CVE-2022-28629](https://github.com/Live-Hack-CVE/CVE-2022-28629) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28629.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28629.svg)


## CVE-2022-28628
 A local arbitrary code execution vulnerability was discovered in HPE Integrated Lights-Out 5 (iLO 5) firmware version(s): Prior to 2.71. An unprivileged user could locally exploit this vulnerability to execute arbitrary code resulting in a complete loss of confidentiality, integrity, and availability. HPE has provided a firmware update to resolve this vulnerability in HPE Integrated Lights-Out 5 (iLO 5).

- [https://github.com/Live-Hack-CVE/CVE-2022-28628](https://github.com/Live-Hack-CVE/CVE-2022-28628) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28628.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28628.svg)


## CVE-2022-28627
 A local arbitrary code execution vulnerability was discovered in HPE Integrated Lights-Out 5 (iLO 5) firmware version(s): Prior to 2.71. An unprivileged user could locally exploit this vulnerability to execute arbitrary code resulting in a complete loss of confidentiality, integrity, and availability. HPE has provided a firmware update to resolve this vulnerability in HPE Integrated Lights-Out 5 (iLO 5).

- [https://github.com/Live-Hack-CVE/CVE-2022-28627](https://github.com/Live-Hack-CVE/CVE-2022-28627) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28627.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28627.svg)


## CVE-2022-28626
 A local arbitrary code execution vulnerability was discovered in HPE Integrated Lights-Out 5 (iLO 5) firmware version(s): Prior to 2.71. A highly privileged user could locally exploit this vulnerability to execute arbitrary code resulting in a complete loss of confidentiality, integrity, and availability. HPE has provided a firmware update to resolve this vulnerability in HPE Integrated Lights-Out 5 (iLO 5).

- [https://github.com/Live-Hack-CVE/CVE-2022-28626](https://github.com/Live-Hack-CVE/CVE-2022-28626) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28626.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28626.svg)


## CVE-2022-28615
 Apache HTTP Server 2.4.53 and earlier may crash or disclose information due to a read beyond bounds in ap_strcmp_match() when provided with an extremely large input buffer. While no code distributed with the server can be coerced into such a call, third-party modules or lua scripts that use ap_strcmp_match() may hypothetically be affected.

- [https://github.com/Live-Hack-CVE/CVE-2022-28615](https://github.com/Live-Hack-CVE/CVE-2022-28615) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28615.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28615.svg)


## CVE-2022-28614
 The ap_rwrite() function in Apache HTTP Server 2.4.53 and earlier may read unintended memory if an attacker can cause the server to reflect very large input using ap_rwrite() or ap_rputs(), such as with mod_luas r:puts() function. Modules compiled and distributed separately from Apache HTTP Server that use the 'ap_rputs' function and may pass it a very large (INT_MAX or larger) string must be compiled against current headers to resolve the issue.

- [https://github.com/Live-Hack-CVE/CVE-2022-28614](https://github.com/Live-Hack-CVE/CVE-2022-28614) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28614.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28614.svg)


## CVE-2022-28598
 Frappe ERPNext 12.29.0 is vulnerable to XSS where the software does not neutralize or incorrectly neutralize user-controllable input before it is placed in output that is used as a web page that is served to other users.

- [https://github.com/Live-Hack-CVE/CVE-2022-28598](https://github.com/Live-Hack-CVE/CVE-2022-28598) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28598.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28598.svg)


## CVE-2022-27637
 Reflected cross-site scripting vulnerability in PukiWiki versions 1.5.1 to 1.5.3 allows a remote attacker to inject an arbitrary script via unspecified vectors.

- [https://github.com/Live-Hack-CVE/CVE-2022-27637](https://github.com/Live-Hack-CVE/CVE-2022-27637) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-27637.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-27637.svg)


## CVE-2022-27500
 Incorrect default permissions for the Intel(R) Support Android application before 21.07.40 may allow an authenticated user to potentially enable information disclosure via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-27500](https://github.com/Live-Hack-CVE/CVE-2022-27500) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-27500.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-27500.svg)


## CVE-2022-27493
 Improper initialization in the firmware for some Intel(R) NUC Laptop Kits before version BC0076 may allow a privileged user to potentially enable an escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-27493](https://github.com/Live-Hack-CVE/CVE-2022-27493) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-27493.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-27493.svg)


## CVE-2022-26844
 Insufficiently protected credentials in the installation binaries for Intel(R) SEAPI in all versions may allow an authenticated user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-26844](https://github.com/Live-Hack-CVE/CVE-2022-26844) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-26844.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-26844.svg)


## CVE-2022-26842
 A reflected cross-site scripting (xss) vulnerability exists in the charts tab selection functionality of WWBN AVideo 11.6 and dev master commit 3f7c0364. A specially-crafted HTTP request can lead to arbitrary Javascript execution. An attacker can get an authenticated user to send a crafted HTTP request to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-26842](https://github.com/Live-Hack-CVE/CVE-2022-26842) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-26842.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-26842.svg)


## CVE-2022-26809
 Remote Procedure Call Runtime Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2022-24492, CVE-2022-24528.

- [https://github.com/dianaross20/Cve-2022-26809](https://github.com/dianaross20/Cve-2022-26809) :  ![starts](https://img.shields.io/github/stars/dianaross20/Cve-2022-26809.svg) ![forks](https://img.shields.io/github/forks/dianaross20/Cve-2022-26809.svg)


## CVE-2022-26377
 Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling') vulnerability in mod_proxy_ajp of Apache HTTP Server allows an attacker to smuggle requests to the AJP server it forwards requests to. This issue affects Apache HTTP Server Apache HTTP Server 2.4 version 2.4.53 and prior versions.

- [https://github.com/Live-Hack-CVE/CVE-2022-26377](https://github.com/Live-Hack-CVE/CVE-2022-26377) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-26377.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-26377.svg)


## CVE-2022-26374
 Uncontrolled search path in the installation binaries for Intel(R) SEAPI all versions may allow an authenticated user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-26374](https://github.com/Live-Hack-CVE/CVE-2022-26374) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-26374.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-26374.svg)


## CVE-2022-26364
 x86 pv: Insufficient care with non-coherent mappings T[his CNA information record relates to multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Xen maintains a type reference count for pages, in addition to a regular reference count. This scheme is used to maintain invariants required for Xen's safety, e.g. PV guests may not have direct writeable access to pagetables; updates need auditing by Xen. Unfortunately, Xen's safety logic doesn't account for CPU-induced cache non-coherency; cases where the CPU can cause the content of the cache to be different to the content in main memory. In such cases, Xen's safety logic can incorrectly conclude that the contents of a page is safe.

- [https://github.com/Live-Hack-CVE/CVE-2022-26364](https://github.com/Live-Hack-CVE/CVE-2022-26364) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-26364.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-26364.svg)


## CVE-2022-26363
 x86 pv: Insufficient care with non-coherent mappings T[his CNA information record relates to multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Xen maintains a type reference count for pages, in addition to a regular reference count. This scheme is used to maintain invariants required for Xen's safety, e.g. PV guests may not have direct writeable access to pagetables; updates need auditing by Xen. Unfortunately, Xen's safety logic doesn't account for CPU-induced cache non-coherency; cases where the CPU can cause the content of the cache to be different to the content in main memory. In such cases, Xen's safety logic can incorrectly conclude that the contents of a page is safe.

- [https://github.com/Live-Hack-CVE/CVE-2022-26363](https://github.com/Live-Hack-CVE/CVE-2022-26363) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-26363.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-26363.svg)


## CVE-2022-26362
 x86 pv: Race condition in typeref acquisition Xen maintains a type reference count for pages, in addition to a regular reference count. This scheme is used to maintain invariants required for Xen's safety, e.g. PV guests may not have direct writeable access to pagetables; updates need auditing by Xen. Unfortunately, the logic for acquiring a type reference has a race condition, whereby a safely TLB flush is issued too early and creates a window where the guest can re-establish the read/write mapping before writeability is prohibited.

- [https://github.com/Live-Hack-CVE/CVE-2022-26362](https://github.com/Live-Hack-CVE/CVE-2022-26362) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-26362.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-26362.svg)


## CVE-2022-26344
 Incorrect default permissions in the installation binaries for Intel(R) SEAPI all versions may allow an authenticated user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-26344](https://github.com/Live-Hack-CVE/CVE-2022-26344) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-26344.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-26344.svg)


## CVE-2022-26305
 An Improper Certificate Validation vulnerability in LibreOffice existed where determining if a macro was signed by a trusted author was done by only matching the serial number and issuer string of the used certificate with that of a trusted certificate. This is not sufficient to verify that the macro was actually signed with the certificate. An adversary could therefore create an arbitrary certificate with a serial number and an issuer string identical to a trusted certificate which LibreOffice would present as belonging to the trusted author, potentially leading to the user to execute arbitrary code contained in macros improperly trusted. This issue affects: The Document Foundation LibreOffice 7.2 versions prior to 7.2.7; 7.3 versions prior to 7.3.1.

- [https://github.com/Live-Hack-CVE/CVE-2022-26305](https://github.com/Live-Hack-CVE/CVE-2022-26305) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-26305.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-26305.svg)


## CVE-2022-26061
 A heap-based buffer overflow vulnerability exists in the gif2h5 functionality of HDF5 Group libhdf5 1.10.4. A specially-crafted GIF file can lead to code execution. An attacker can provide a malicious file to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-26061](https://github.com/Live-Hack-CVE/CVE-2022-26061) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-26061.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-26061.svg)


## CVE-2022-26017
 Improper access control in the Intel(R) DSA software for before version 22.2.14 may allow an authenticated user to potentially enable escalation of privilege via adjacent access.

- [https://github.com/Live-Hack-CVE/CVE-2022-26017](https://github.com/Live-Hack-CVE/CVE-2022-26017) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-26017.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-26017.svg)


## CVE-2022-25999
 Uncontrolled search path element in the Intel(R) Enpirion(R) Digital Power Configurator GUI software, all versions may allow an authenticated user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-25999](https://github.com/Live-Hack-CVE/CVE-2022-25999) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-25999.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-25999.svg)


## CVE-2022-25986
 Browse restriction bypass vulnerability in Scheduler of Cybozu Office 10.0.0 to 10.8.5 allows a remote authenticated attacker to obtain the data of Scheduler.

- [https://github.com/Live-Hack-CVE/CVE-2022-25986](https://github.com/Live-Hack-CVE/CVE-2022-25986) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-25986.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-25986.svg)


## CVE-2022-25972
 An out-of-bounds write vulnerability exists in the gif2h5 functionality of HDF5 Group libhdf5 1.10.4. A specially-crafted GIF file can lead to code execution. An attacker can provide a malicious file to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-25972](https://github.com/Live-Hack-CVE/CVE-2022-25972) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-25972.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-25972.svg)


## CVE-2022-25966
 Improper access control in the Intel(R) Edge Insights for Industrial software before version 2.6.1 may allow an authenticated user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-25966](https://github.com/Live-Hack-CVE/CVE-2022-25966) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-25966.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-25966.svg)


## CVE-2022-25942
 An out-of-bounds read vulnerability exists in the gif2h5 functionality of HDF5 Group libhdf5 1.10.4. A specially-crafted GIF file can lead to code execution. An attacker can provide a malicious file to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-25942](https://github.com/Live-Hack-CVE/CVE-2022-25942) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-25942.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-25942.svg)


## CVE-2022-25903
 The package opcua from 0.0.0 are vulnerable to Denial of Service (DoS) via the ExtensionObjects and Variants objects, when it allows unlimited nesting levels, which could result in a stack overflow even if the message size is less than the maximum allowed.

- [https://github.com/Live-Hack-CVE/CVE-2022-25903](https://github.com/Live-Hack-CVE/CVE-2022-25903) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-25903.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-25903.svg)


## CVE-2022-25899
 Authentication bypass for the Open AMT Cloud Toolkit software maintained by Intel(R) before versions 2.0.2 and 2.2.2 may allow an unauthenticated user to potentially enable escalation of privilege via network access.

- [https://github.com/Live-Hack-CVE/CVE-2022-25899](https://github.com/Live-Hack-CVE/CVE-2022-25899) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-25899.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-25899.svg)


## CVE-2022-25888
 The package opcua from 0.0.0 are vulnerable to Denial of Service (DoS) due to a missing limitation on the number of received chunks - per single session or in total for all concurrent sessions. An attacker can exploit this vulnerability by sending an unlimited number of huge chunks (e.g. 2GB each) without sending the Final closing chunk.

- [https://github.com/Live-Hack-CVE/CVE-2022-25888](https://github.com/Live-Hack-CVE/CVE-2022-25888) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-25888.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-25888.svg)


## CVE-2022-25841
 Uncontrolled search path elements in the Intel(R) Datacenter Group Event Android application, all versions, may allow an authenticated user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-25841](https://github.com/Live-Hack-CVE/CVE-2022-25841) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-25841.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-25841.svg)


## CVE-2022-25812
 The Transposh WordPress Translation WordPress plugin before 1.0.8 does not validate its debug settings, which could allow allowing high privilege users such as admin to perform RCE

- [https://github.com/Live-Hack-CVE/CVE-2022-25812](https://github.com/Live-Hack-CVE/CVE-2022-25812) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-25812.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-25812.svg)


## CVE-2022-25811
 The Transposh WordPress Translation WordPress plugin through 1.0.8 does not sanitise and escape the order and orderby parameters before using them in a SQL statement, leading to a SQL injection

- [https://github.com/Live-Hack-CVE/CVE-2022-25811](https://github.com/Live-Hack-CVE/CVE-2022-25811) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-25811.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-25811.svg)


## CVE-2022-25810
 The Transposh WordPress Translation WordPress plugin through 1.0.8 exposes a couple of sensitive actions such has &#8220;tp_reset&#8221; under the Utilities tab (/wp-admin/admin.php?page=tp_utils), which can be used/executed as the lowest-privileged user. Basically all Utilities functionalities are vulnerable this way, which involves resetting configurations and backup/restore operations.

- [https://github.com/Live-Hack-CVE/CVE-2022-25810](https://github.com/Live-Hack-CVE/CVE-2022-25810) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-25810.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-25810.svg)


## CVE-2022-25761
 The package open62541/open62541 before 1.2.5, from 1.3-rc1 and before 1.3.1 are vulnerable to Denial of Service (DoS) due to a missing limitation on the number of received chunks - per single session or in total for all concurrent sessions. An attacker can exploit this vulnerability by sending an unlimited number of huge chunks (e.g. 2GB each) without sending the Final closing chunk.

- [https://github.com/Live-Hack-CVE/CVE-2022-25761](https://github.com/Live-Hack-CVE/CVE-2022-25761) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-25761.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-25761.svg)


## CVE-2022-25302
 All versions of package asneg/opcuastack are vulnerable to Denial of Service (DoS) due to a missing handler for failed casting when unvalidated data is forwarded to boost::get function in OpcUaNodeIdBase.h. Exploiting this vulnerability is possible when sending a specifically crafted OPC UA message with a special encoded NodeId.

- [https://github.com/Live-Hack-CVE/CVE-2022-25302](https://github.com/Live-Hack-CVE/CVE-2022-25302) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-25302.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-25302.svg)


## CVE-2022-25231
 The package node-opcua before 2.74.0 are vulnerable to Denial of Service (DoS) by sending a specifically crafted OPC UA message with a special OPC UA NodeID, when the requested memory allocation exceeds the v8&#8217;s memory limit.

- [https://github.com/Live-Hack-CVE/CVE-2022-25231](https://github.com/Live-Hack-CVE/CVE-2022-25231) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-25231.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-25231.svg)


## CVE-2022-25228
 CandidATS Version 3.0.0 Beta allows an authenticated user to inject SQL queries in '/index.php?m=settings&amp;a=show' via the 'userID' parameter, in '/index.php?m=candidates&amp;a=show' via the 'candidateID', in '/index.php?m=joborders&amp;a=show' via the 'jobOrderID' and '/index.php?m=companies&amp;a=show' via the 'companyID' parameter

- [https://github.com/Live-Hack-CVE/CVE-2022-25228](https://github.com/Live-Hack-CVE/CVE-2022-25228) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-25228.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-25228.svg)


## CVE-2022-24952
 Several denial of service vulnerabilities exist in Eternal Terminal prior to version 6.2.0, including a DoS triggered remotely by an invalid sequence number and a local bug triggered by invalid input sent directly to the IPC socket.

- [https://github.com/Live-Hack-CVE/CVE-2022-24952](https://github.com/Live-Hack-CVE/CVE-2022-24952) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-24952.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-24952.svg)


## CVE-2022-24951
 A race condition exists in Eternal Terminal prior to version 6.2.0 which allows a local attacker to hijack Eternal Terminal's IPC socket, enabling access to Eternal Terminal clients which attempt to connect in the future.

- [https://github.com/Live-Hack-CVE/CVE-2022-24951](https://github.com/Live-Hack-CVE/CVE-2022-24951) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-24951.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-24951.svg)


## CVE-2022-24950
 A race condition exists in Eternal Terminal prior to version 6.2.0 that allows an authenticated attacker to hijack other users' SSH authorization socket, enabling the attacker to login to other systems as the targeted users. The bug is in UserTerminalRouter::getInfoForId().

- [https://github.com/Live-Hack-CVE/CVE-2022-24950](https://github.com/Live-Hack-CVE/CVE-2022-24950) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-24950.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-24950.svg)


## CVE-2022-24949
 A privilege escalation to root exists in Eternal Terminal prior to version 6.2.0. This is due to the combination of a race condition, buffer overflow, and logic bug all in PipeSocketHandler::listen().

- [https://github.com/Live-Hack-CVE/CVE-2022-24949](https://github.com/Live-Hack-CVE/CVE-2022-24949) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-24949.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-24949.svg)


## CVE-2022-24946
 Improper Resource Locking vulnerability in Mitsubishi Electric MELSEC iQ-R Series R12CCPU-V firmware versions &quot;16&quot; and prior, Mitsubishi Electric MELSEC-Q Series Q03UDECPU the first 5 digits of serial No. &quot;24061&quot; and prior, Mitsubishi Electric MELSEC-Q Series Q04/06/10/13/20/26/50/100UDEHCPU the first 5 digits of serial No. &quot;24061&quot; and prior, Mitsubishi Electric MELSEC-Q Series Q03/04/06/13/26UDVCPU the first 5 digits of serial number &quot;24051&quot; and prior, Mitsubishi Electric MELSEC-Q Series Q04/06/13/26UDPVCPU the first 5 digits of serial number &quot;24051&quot; and prior, Mitsubishi Electric MELSEC-Q Series Q12DCCPU-V all versions, Mitsubishi Electric MELSEC-Q Series Q24DHCCPU-V(G) all versions, Mitsubishi Electric MELSEC-Q Series Q24/26DHCCPU-LS all versions, Mitsubishi Electric MELSEC-L series L02/06/26CPU(-P) the first 5 digits of serial number &quot;24051&quot; and prior, Mitsubishi Electric MELSEC-L series L26CPU-(P)BT the first 5 digits of serial number &quot;24051&quot; and prior and Mitsubishi Electric MELIPC Series MI5122-VW firmware versions &quot;05&quot; and prior allows a remote unauthenticated attacker to cause a denial of service (DoS) condition in Ethernet communications by sending specially crafted packets. A system reset of the products is required for recovery.

- [https://github.com/Live-Hack-CVE/CVE-2022-24946](https://github.com/Live-Hack-CVE/CVE-2022-24946) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-24946.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-24946.svg)


## CVE-2022-24381
 All versions of package asneg/opcuastack are vulnerable to Denial of Service (DoS) due to a missing limitation on the number of received chunks - per single session or in total for all concurrent sessions. An attacker can exploit this vulnerability by sending an unlimited number of huge chunks (e.g. 2GB each) without sending the Final closing chunk.

- [https://github.com/Live-Hack-CVE/CVE-2022-24381](https://github.com/Live-Hack-CVE/CVE-2022-24381) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-24381.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-24381.svg)


## CVE-2022-24378
 Improper initialization in the Intel(R) Data Center Manager software before version 4.1 may allow an authenticated user to potentially enable denial of service via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-24378](https://github.com/Live-Hack-CVE/CVE-2022-24378) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-24378.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-24378.svg)


## CVE-2022-24375
 The package node-opcua before 2.74.0 are vulnerable to Denial of Service (DoS) when bypassing the limitations for excessive memory consumption by sending multiple CloseSession requests with the deleteSubscription parameter equal to False.

- [https://github.com/Live-Hack-CVE/CVE-2022-24375](https://github.com/Live-Hack-CVE/CVE-2022-24375) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-24375.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-24375.svg)


## CVE-2022-24298
 All versions of package freeopcua/freeopcua are vulnerable to Denial of Service (DoS) when bypassing the limitations for excessive memory consumption by sending multiple CloseSession requests with the deleteSubscription parameter equal to False.

- [https://github.com/Live-Hack-CVE/CVE-2022-24298](https://github.com/Live-Hack-CVE/CVE-2022-24298) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-24298.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-24298.svg)


## CVE-2022-24130
 xterm through Patch 370, when Sixel support is enabled, allows attackers to trigger a buffer overflow in set_sixel in graphics_sixel.c via crafted text.

- [https://github.com/Live-Hack-CVE/CVE-2022-24130](https://github.com/Live-Hack-CVE/CVE-2022-24130) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-24130.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-24130.svg)


## CVE-2022-24120
 Certain General Electric Renewable Energy products store cleartext credentials in flash memory. This affects iNET and iNET II before 8.3.0.

- [https://github.com/Live-Hack-CVE/CVE-2022-24120](https://github.com/Live-Hack-CVE/CVE-2022-24120) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-24120.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-24120.svg)


## CVE-2022-24119
 Certain General Electric Renewable Energy products have a hidden feature for unauthenticated remote access to the device configuration shell. This affects iNET and iNET II before 8.3.0.

- [https://github.com/Live-Hack-CVE/CVE-2022-24119](https://github.com/Live-Hack-CVE/CVE-2022-24119) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-24119.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-24119.svg)


## CVE-2022-24118
 Certain General Electric Renewable Energy products allow attackers to use a code to trigger a reboot into the factory default configuration. This affects iNET and iNET II before 8.3.0, SD before 6.4.7, TD220X before 2.0.16, and TD220MAX before 1.2.6.

- [https://github.com/Live-Hack-CVE/CVE-2022-24118](https://github.com/Live-Hack-CVE/CVE-2022-24118) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-24118.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-24118.svg)


## CVE-2022-24117
 Certain General Electric Renewable Energy products download firmware without an integrity check. This affects iNET and iNET II before 8.3.0, SD before 6.4.7, TD220X before 2.0.16, and TD220MAX before 1.2.6.

- [https://github.com/Live-Hack-CVE/CVE-2022-24117](https://github.com/Live-Hack-CVE/CVE-2022-24117) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-24117.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-24117.svg)


## CVE-2022-24116
 Certain General Electric Renewable Energy products have inadequate encryption strength. This affects iNET and iNET II before 8.3.0.

- [https://github.com/Live-Hack-CVE/CVE-2022-24116](https://github.com/Live-Hack-CVE/CVE-2022-24116) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-24116.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-24116.svg)


## CVE-2022-23765
 This vulnerability occured by sending a malicious POST request to a specific page while logged in random user from some family of IPTIME NAS. Remote attackers can steal root privileges by changing the password of the root through a POST request.

- [https://github.com/Live-Hack-CVE/CVE-2022-23765](https://github.com/Live-Hack-CVE/CVE-2022-23765) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-23765.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-23765.svg)


## CVE-2022-23764
 The vulnerability causing from insufficient verification procedures for downloaded files during WebCube update. Remote attackers can bypass this verification logic to update both digitally signed and unauthorized files, enabling remote code execution.

- [https://github.com/Live-Hack-CVE/CVE-2022-23764](https://github.com/Live-Hack-CVE/CVE-2022-23764) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-23764.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-23764.svg)


## CVE-2022-23747
 In Sony Xperia series 1, 5, and Pro, an out of bound memory access can occur due to lack of validation of the number of frames being passed during music playback.

- [https://github.com/Live-Hack-CVE/CVE-2022-23747](https://github.com/Live-Hack-CVE/CVE-2022-23747) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-23747.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-23747.svg)


## CVE-2022-23715
 A flaw was discovered in ECE before 3.4.0 that might lead to the disclosure of sensitive information such as user passwords and Elasticsearch keystore settings values in logs such as the audit log or deployment logs in the Logging and Monitoring cluster. The affected APIs are PATCH /api/v1/user and PATCH /deployments/{deployment_id}/elasticsearch/{ref_id}/keystore

- [https://github.com/Live-Hack-CVE/CVE-2022-23715](https://github.com/Live-Hack-CVE/CVE-2022-23715) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-23715.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-23715.svg)


## CVE-2022-23663
 A authenticated remote command injection vulnerability was discovered in Aruba ClearPass Policy Manager version(s): 6.10.4 and below, 6.9.9 and below, 6.8.9-HF2 and below, 6.7.x and below. Aruba has released updates to ClearPass Policy Manager that address this security vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-23663](https://github.com/Live-Hack-CVE/CVE-2022-23663) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-23663.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-23663.svg)


## CVE-2022-23460
 Jsonxx or Json++ is a JSON parser, writer and reader written in C++. In affected versions of jsonxx json parsing may lead to stack exhaustion in an address sanitized (ASAN) build. This issue may lead to Denial of Service if the program using the jsonxx library crashes. This issue exists on the current commit of the jsonxx project and the project itself has been archived. Updates are not expected. Users are advised to find a replacement.

- [https://github.com/Live-Hack-CVE/CVE-2022-23460](https://github.com/Live-Hack-CVE/CVE-2022-23460) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-23460.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-23460.svg)


## CVE-2022-23459
 Jsonxx or Json++ is a JSON parser, writer and reader written in C++. In affected versions of jsonxx use of the Value class may lead to memory corruption via a double free or via a use after free. The value class has a default assignment operator which may be used with pointer types which may point to alterable data where the pointer itself is not updated. This issue exists on the current commit of the jsonxx project. The project itself has been archived and updates are not expected. Users are advised to find a replacement.

- [https://github.com/Live-Hack-CVE/CVE-2022-23459](https://github.com/Live-Hack-CVE/CVE-2022-23459) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-23459.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-23459.svg)


## CVE-2022-23403
 Improper input validation in the Intel(R) Data Center Manager software before version 4.1 may allow an authenticated user to potentially enable denial of service via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-23403](https://github.com/Live-Hack-CVE/CVE-2022-23403) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-23403.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-23403.svg)


## CVE-2022-23277
 Microsoft Exchange Server Remote Code Execution Vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-23277](https://github.com/Live-Hack-CVE/CVE-2022-23277) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-23277.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-23277.svg)


## CVE-2022-23235
 Active IQ Unified Manager for VMware vSphere, Linux, and Microsoft Windows versions prior to 9.10P1 are susceptible to a vulnerability which could allow an attacker to discover cluster, node and Active IQ Unified Manager specific information via AutoSupport telemetry data that is sent even when AutoSupport has been disabled.

- [https://github.com/Live-Hack-CVE/CVE-2022-23235](https://github.com/Live-Hack-CVE/CVE-2022-23235) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-23235.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-23235.svg)


## CVE-2022-23182
 Improper access control in the Intel(R) Data Center Manager software before version 4.1 may allow an unauthenticated user to potentially enable escalation of privilege via adjacent access.

- [https://github.com/Live-Hack-CVE/CVE-2022-23182](https://github.com/Live-Hack-CVE/CVE-2022-23182) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-23182.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-23182.svg)


## CVE-2022-23035
 Insufficient cleanup of passed-through device IRQs The management of IRQs associated with physical devices exposed to x86 HVM guests involves an iterative operation in particular when cleaning up after the guest's use of the device. In the case where an interrupt is not quiescent yet at the time this cleanup gets invoked, the cleanup attempt may be scheduled to be retried. When multiple interrupts are involved, this scheduling of a retry may get erroneously skipped. At the same time pointers may get cleared (resulting in a de-reference of NULL) and freed (resulting in a use-after-free), while other code would continue to assume them to be valid.

- [https://github.com/Live-Hack-CVE/CVE-2022-23035](https://github.com/Live-Hack-CVE/CVE-2022-23035) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-23035.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-23035.svg)


## CVE-2022-23034
 A PV guest could DoS Xen while unmapping a grant To address XSA-380, reference counting was introduced for grant mappings for the case where a PV guest would have the IOMMU enabled. PV guests can request two forms of mappings. When both are in use for any individual mapping, unmapping of such a mapping can be requested in two steps. The reference count for such a mapping would then mistakenly be decremented twice. Underflow of the counters gets detected, resulting in the triggering of a hypervisor bug check.

- [https://github.com/Live-Hack-CVE/CVE-2022-23034](https://github.com/Live-Hack-CVE/CVE-2022-23034) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-23034.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-23034.svg)


## CVE-2022-23033
 arm: guest_physmap_remove_page not removing the p2m mappings The functions to remove one or more entries from a guest p2m pagetable on Arm (p2m_remove_mapping, guest_physmap_remove_page, and p2m_set_entry with mfn set to INVALID_MFN) do not actually clear the pagetable entry if the entry doesn't have the valid bit set. It is possible to have a valid pagetable entry without the valid bit set when a guest operating system uses set/way cache maintenance instructions. For instance, a guest issuing a set/way cache maintenance instruction, then calling the XENMEM_decrease_reservation hypercall to give back memory pages to Xen, might be able to retain access to those pages even after Xen started reusing them for other purposes.

- [https://github.com/Live-Hack-CVE/CVE-2022-23033](https://github.com/Live-Hack-CVE/CVE-2022-23033) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-23033.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-23033.svg)


## CVE-2022-22730
 Improper authentication in the Intel(R) Edge Insights for Industrial software before version 2.6.1 may allow an unauthenticated user to potentially enable escalation of privilege via network access.

- [https://github.com/Live-Hack-CVE/CVE-2022-22730](https://github.com/Live-Hack-CVE/CVE-2022-22730) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-22730.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-22730.svg)


## CVE-2022-22532
 In SAP NetWeaver Application Server Java - versions KRNL64NUC 7.22, 7.22EXT, 7.49, KRNL64UC, 7.22, 7.22EXT, 7.49, 7.53, KERNEL 7.22, 7.49, 7.53, an unauthenticated attacker could submit a crafted HTTP server request which triggers improper shared memory buffer handling. This could allow the malicious payload to be executed and hence execute functions that could be impersonating the victim or even steal the victim's logon session.

- [https://github.com/Live-Hack-CVE/CVE-2022-22532](https://github.com/Live-Hack-CVE/CVE-2022-22532) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-22532.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-22532.svg)


## CVE-2022-22489
 IBM MQ 8.0, (9.0, 9.1, 9.2 LTS), and (9.1 and 9.2 CD) are vulnerable to an XML External Entity Injection (XXE) attack when processing XML data. A remote attacker could exploit this vulnerability to expose sensitive information or consume memory resources. IBM X-Force ID: 226339.

- [https://github.com/Live-Hack-CVE/CVE-2022-22489](https://github.com/Live-Hack-CVE/CVE-2022-22489) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-22489.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-22489.svg)


## CVE-2022-22455
 IBM Security Verify Governance Identity Manager 10.0 virtual appliance component performs an operation at a privilege level that is higher than the minimum level required, which creates new weaknesses or amplifies the consequences of other weaknesses. IBM X-Force ID: 224989.

- [https://github.com/Live-Hack-CVE/CVE-2022-22455](https://github.com/Live-Hack-CVE/CVE-2022-22455) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-22455.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-22455.svg)


## CVE-2022-22411
 IBM Spectrum Scale Data Access Services (DAS) 5.1.3.1 could allow an authenticated user to insert code which could allow the attacker to manipulate cluster resources due to excessive permissions. IBM X-Force ID: 223016.

- [https://github.com/Live-Hack-CVE/CVE-2022-22411](https://github.com/Live-Hack-CVE/CVE-2022-22411) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-22411.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-22411.svg)


## CVE-2022-22021
 Microsoft Edge (Chromium-based) Remote Code Execution Vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-22021](https://github.com/Live-Hack-CVE/CVE-2022-22021) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-22021.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-22021.svg)


## CVE-2022-21907
 HTTP Protocol Stack Remote Code Execution Vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-21907](https://github.com/Live-Hack-CVE/CVE-2022-21907) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-21907.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-21907.svg)


## CVE-2022-21881
 Windows Kernel Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2022-21879.

- [https://github.com/Live-Hack-CVE/CVE-2022-21881](https://github.com/Live-Hack-CVE/CVE-2022-21881) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-21881.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-21881.svg)


## CVE-2022-21812
 Improper access control in the Intel(R) HAXM software before version 7.7.1 may allow an authenticated user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-21812](https://github.com/Live-Hack-CVE/CVE-2022-21812) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-21812.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-21812.svg)


## CVE-2022-21807
 Uncontrolled search path elements in the Intel(R) VTune(TM) Profiler software before version 2022.2.0 may allow an authenticated user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-21807](https://github.com/Live-Hack-CVE/CVE-2022-21807) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-21807.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-21807.svg)


## CVE-2022-21793
 Insufficient control flow management in the Intel(R) Ethernet 500 Series Controller drivers for VMWare before version 1.11.4.0 and in the Intel(R) Ethernet 700 Series Controller drivers for VMWare before version 2.1.5.0 may allow an authenticated user to potentially enable a denial of service via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-21793](https://github.com/Live-Hack-CVE/CVE-2022-21793) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-21793.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-21793.svg)


## CVE-2022-21549
 Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Libraries). Supported versions that are affected are Oracle Java SE: 17.0.3.1; Oracle GraalVM Enterprise Edition: 21.3.2 and 22.1.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle Java SE, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. CVSS 3.1 Base Score 5.3 (Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N).

- [https://github.com/Live-Hack-CVE/CVE-2022-21549](https://github.com/Live-Hack-CVE/CVE-2022-21549) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-21549.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-21549.svg)


## CVE-2022-21541
 Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Hotspot). Supported versions that are affected are Oracle Java SE: 7u343, 8u333, 11.0.15.1, 17.0.3.1, 18.0.1.1; Oracle GraalVM Enterprise Edition: 20.3.6, 21.3.2 and 22.1.0. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification access to critical data or all Oracle Java SE, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. CVSS 3.1 Base Score 5.9 (Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N).

- [https://github.com/Live-Hack-CVE/CVE-2022-21541](https://github.com/Live-Hack-CVE/CVE-2022-21541) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-21541.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-21541.svg)


## CVE-2022-21540
 Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Hotspot). Supported versions that are affected are Oracle Java SE: 7u343, 8u333, 11.0.15.1, 17.0.3.1, 18.0.1.1; Oracle GraalVM Enterprise Edition: 20.3.6, 21.3.2 and 22.1.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized read access to a subset of Oracle Java SE, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. CVSS 3.1 Base Score 5.3 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N).

- [https://github.com/Live-Hack-CVE/CVE-2022-21540](https://github.com/Live-Hack-CVE/CVE-2022-21540) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-21540.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-21540.svg)


## CVE-2022-21240
 Out of bounds read for some Intel(R) PROSet/Wireless WiFi products may allow a privileged user to potentially enable information disclosure via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-21240](https://github.com/Live-Hack-CVE/CVE-2022-21240) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-21240.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-21240.svg)


## CVE-2022-21229
 Improper buffer restrictions for some Intel(R) NUC 9 Extreme Laptop Kit drivers before version 2.2.0.22 may allow an authenticated user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-21229](https://github.com/Live-Hack-CVE/CVE-2022-21229) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-21229.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-21229.svg)


## CVE-2022-21212
 Improper input validation for some Intel(R) PROSet/Wireless WiFi products may allow an unauthenticated user to potentially enable denial of service via adjacent access.

- [https://github.com/Live-Hack-CVE/CVE-2022-21212](https://github.com/Live-Hack-CVE/CVE-2022-21212) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-21212.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-21212.svg)


## CVE-2022-21197
 Improper input validation for some Intel(R) PROSet/Wireless WiFi products may allow an unauthenticated user to potentially enable denial of service via network access.

- [https://github.com/Live-Hack-CVE/CVE-2022-21197](https://github.com/Live-Hack-CVE/CVE-2022-21197) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-21197.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-21197.svg)


## CVE-2022-21181
 Improper input validation for some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi products may allow a privileged user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-21181](https://github.com/Live-Hack-CVE/CVE-2022-21181) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-21181.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-21181.svg)


## CVE-2022-21172
 Out of bounds write for some Intel(R) PROSet/Wireless WiFi products may allow a privileged user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-21172](https://github.com/Live-Hack-CVE/CVE-2022-21172) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-21172.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-21172.svg)


## CVE-2022-21166
 Incomplete cleanup in specific special register write operations for some Intel(R) Processors may allow an authenticated user to potentially enable information disclosure via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-21166](https://github.com/Live-Hack-CVE/CVE-2022-21166) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-21166.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-21166.svg)


## CVE-2022-21160
 Improper buffer restrictions for some Intel(R) PROSet/Wireless WiFi products may allow an unauthenticated user to potentially enable denial of service via network access.

- [https://github.com/Live-Hack-CVE/CVE-2022-21160](https://github.com/Live-Hack-CVE/CVE-2022-21160) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-21160.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-21160.svg)


## CVE-2022-21152
 Improper access control in the Intel(R) Edge Insights for Industrial software before version 2.6.1 may allow an authenticated user to potentially enable information disclosure via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-21152](https://github.com/Live-Hack-CVE/CVE-2022-21152) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-21152.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-21152.svg)


## CVE-2022-21148
 Improper access control in the Intel(R) Edge Insights for Industrial software before version 2.6.1 may allow an authenticated user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-21148](https://github.com/Live-Hack-CVE/CVE-2022-21148) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-21148.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-21148.svg)


## CVE-2022-21140
 Improper access control for some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi products may allow a privileged user to potentially enable information disclosure via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-21140](https://github.com/Live-Hack-CVE/CVE-2022-21140) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-21140.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-21140.svg)


## CVE-2022-21139
 Inadequate encryption strength for some Intel(R) PROSet/Wireless WiFi products may allow an unauthenticated user to potentially enable escalation of privilege via adjacent access.

- [https://github.com/Live-Hack-CVE/CVE-2022-21139](https://github.com/Live-Hack-CVE/CVE-2022-21139) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-21139.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-21139.svg)


## CVE-2022-21125
 Incomplete cleanup of microarchitectural fill buffers on some Intel(R) Processors may allow an authenticated user to potentially enable information disclosure via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-21125](https://github.com/Live-Hack-CVE/CVE-2022-21125) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-21125.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-21125.svg)


## CVE-2022-21123
 Incomplete cleanup of multi-core shared buffers for some Intel(R) Processors may allow an authenticated user to potentially enable information disclosure via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-21123](https://github.com/Live-Hack-CVE/CVE-2022-21123) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-21123.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-21123.svg)


## CVE-2022-20921
 A vulnerability in the API implementation of Cisco ACI Multi-Site Orchestrator (MSO) could allow an authenticated, remote attacker to elevate privileges on an affected device. This vulnerability is due to improper authorization on specific APIs. An attacker could exploit this vulnerability by sending crafted HTTP requests. A successful exploit could allow an attacker who is authenticated with non-Administrator privileges to elevate to Administrator privileges on an affected device.

- [https://github.com/Live-Hack-CVE/CVE-2022-20921](https://github.com/Live-Hack-CVE/CVE-2022-20921) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20921.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20921.svg)


## CVE-2022-20651
 A vulnerability in the logging component of Cisco Adaptive Security Device Manager (ASDM) could allow an authenticated, local attacker to view sensitive information in clear text on an affected system. Cisco ADSM must be deployed in a shared workstation environment for this issue to be exploited. This vulnerability is due to the storage of unencrypted credentials in certain logs. An attacker could exploit this vulnerability by accessing the logs on an affected system. A successful exploit could allow the attacker to view the credentials of other users of the shared device.

- [https://github.com/Live-Hack-CVE/CVE-2022-20651](https://github.com/Live-Hack-CVE/CVE-2022-20651) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20651.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20651.svg)


## CVE-2022-20334
 In Bluetooth, there are possible process crashes due to dereferencing a null pointer. This could lead to remote denial of service with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-178800552

- [https://github.com/Live-Hack-CVE/CVE-2022-20334](https://github.com/Live-Hack-CVE/CVE-2022-20334) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20334.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20334.svg)


## CVE-2022-20333
 In Bluetooth, there is a possible crash due to a missing null check. This could lead to remote denial of service with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-179161657

- [https://github.com/Live-Hack-CVE/CVE-2022-20333](https://github.com/Live-Hack-CVE/CVE-2022-20333) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20333.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20333.svg)


## CVE-2022-20332
 In PackageManager, there is a possible way to determine whether an app is installed, without query permissions, due to side channel information disclosure. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-180019130

- [https://github.com/Live-Hack-CVE/CVE-2022-20332](https://github.com/Live-Hack-CVE/CVE-2022-20332) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20332.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20332.svg)


## CVE-2022-20331
 In the Framework, there is a possible way to enable a work profile without user consent due to a tapjacking/overlay attack. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-181785557

- [https://github.com/Live-Hack-CVE/CVE-2022-20331](https://github.com/Live-Hack-CVE/CVE-2022-20331) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20331.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20331.svg)


## CVE-2022-20330
 In Bluetooth, there is a possible way to connect or disconnect bluetooth devices without user awareness due to a missing permission check. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-181962588

- [https://github.com/Live-Hack-CVE/CVE-2022-20330](https://github.com/Live-Hack-CVE/CVE-2022-20330) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20330.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20330.svg)


## CVE-2022-20329
 In Wifi, there is a possible way to enable Wifi without permissions due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-183410556

- [https://github.com/Live-Hack-CVE/CVE-2022-20329](https://github.com/Live-Hack-CVE/CVE-2022-20329) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20329.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20329.svg)


## CVE-2022-20328
 In PackageManager, there is a possible way to determine whether an app is installed due to a missing permission check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-184948501

- [https://github.com/Live-Hack-CVE/CVE-2022-20328](https://github.com/Live-Hack-CVE/CVE-2022-20328) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20328.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20328.svg)


## CVE-2022-20327
 In Wi-Fi, there is a possible way to retrieve the WiFi SSID without location permissions due to a missing permission check. This could lead to local information disclosure with User execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-185126813

- [https://github.com/Live-Hack-CVE/CVE-2022-20327](https://github.com/Live-Hack-CVE/CVE-2022-20327) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20327.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20327.svg)


## CVE-2022-20326
 In Telephony, there is a possible disclosure of SIM identifiers due to a missing permission check. This could lead to local information disclosure with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-185235527

- [https://github.com/Live-Hack-CVE/CVE-2022-20326](https://github.com/Live-Hack-CVE/CVE-2022-20326) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20326.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20326.svg)


## CVE-2022-20325
 In Media, there is a possible code execution due to a use after free. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-186473060

- [https://github.com/Live-Hack-CVE/CVE-2022-20325](https://github.com/Live-Hack-CVE/CVE-2022-20325) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20325.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20325.svg)


## CVE-2022-20324
 In Framework, there is a possible way to determine whether an app is installed, without query permissions, due to side channel information disclosure. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-187042120

- [https://github.com/Live-Hack-CVE/CVE-2022-20324](https://github.com/Live-Hack-CVE/CVE-2022-20324) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20324.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20324.svg)


## CVE-2022-20323
 In PackageManager, there is a possible package installation disclosure due to a missing permission check. This could lead to local information disclosure with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-187176203

- [https://github.com/Live-Hack-CVE/CVE-2022-20323](https://github.com/Live-Hack-CVE/CVE-2022-20323) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20323.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20323.svg)


## CVE-2022-20322
 In PackageManager, there is a possible installed package disclosure due to a missing permission check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-187176993

- [https://github.com/Live-Hack-CVE/CVE-2022-20322](https://github.com/Live-Hack-CVE/CVE-2022-20322) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20322.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20322.svg)


## CVE-2022-20321
 In Settings, there is a possible way for an application without permissions to read content of WiFi QR codes due to a missing permission check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-187176859

- [https://github.com/Live-Hack-CVE/CVE-2022-20321](https://github.com/Live-Hack-CVE/CVE-2022-20321) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20321.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20321.svg)


## CVE-2022-20320
 In ActivityManager, there is a possible way to determine whether an app is installed, without query permissions, due to side channel information disclosure. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-187956596

- [https://github.com/Live-Hack-CVE/CVE-2022-20320](https://github.com/Live-Hack-CVE/CVE-2022-20320) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20320.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20320.svg)


## CVE-2022-20319
 In DreamServices, there is a possible way to launch arbitrary protected activities due to a confused deputy. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-189574230

- [https://github.com/Live-Hack-CVE/CVE-2022-20319](https://github.com/Live-Hack-CVE/CVE-2022-20319) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20319.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20319.svg)


## CVE-2022-20318
 In PackageInstaller, there is a possible way to determine whether an app is installed, without query permissions, due to side channel information disclosure. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-194694069

- [https://github.com/Live-Hack-CVE/CVE-2022-20318](https://github.com/Live-Hack-CVE/CVE-2022-20318) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20318.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20318.svg)


## CVE-2022-20317
 In SystemUI, there is a possible way to unexpectedly enable the external speaker due to a logic error in the code. This could lead to local information disclosure with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-190199063

- [https://github.com/Live-Hack-CVE/CVE-2022-20317](https://github.com/Live-Hack-CVE/CVE-2022-20317) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20317.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20317.svg)


## CVE-2022-20290
 In Midi, there is a possible way to learn about private midi devices due to a permissions bypass. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-203549963

- [https://github.com/Live-Hack-CVE/CVE-2022-20290](https://github.com/Live-Hack-CVE/CVE-2022-20290) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20290.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20290.svg)


## CVE-2022-20289
 In PackageInstaller, there is a possible way to determine whether an app is installed, without query permissions, due to side channel information disclosure. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-203683960

- [https://github.com/Live-Hack-CVE/CVE-2022-20289](https://github.com/Live-Hack-CVE/CVE-2022-20289) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20289.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20289.svg)


## CVE-2022-20288
 In AppSearchManagerService, there is a possible way to determine whether an app is installed, without query permissions, due to side channel information disclosure. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-204082360

- [https://github.com/Live-Hack-CVE/CVE-2022-20288](https://github.com/Live-Hack-CVE/CVE-2022-20288) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20288.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20288.svg)


## CVE-2022-20287
 In AppSearchManagerService, there is a possible way to determine whether an app is installed, without query permissions, due to side channel information disclosure. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-204082784

- [https://github.com/Live-Hack-CVE/CVE-2022-20287](https://github.com/Live-Hack-CVE/CVE-2022-20287) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20287.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20287.svg)


## CVE-2022-20286
 In Connectivity, there is a possible bypass the restriction of starting activity from background due to a logic error in the code. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-230866011

- [https://github.com/Live-Hack-CVE/CVE-2022-20286](https://github.com/Live-Hack-CVE/CVE-2022-20286) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20286.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20286.svg)


## CVE-2022-20285
 In PackageManager, there is a possible way to determine whether an app is installed, without query permissions, due to side channel information disclosure. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-230868108

- [https://github.com/Live-Hack-CVE/CVE-2022-20285](https://github.com/Live-Hack-CVE/CVE-2022-20285) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20285.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20285.svg)


## CVE-2022-20284
 In Telephony, there is a possible information disclosure due to a missing permission check. This could lead to local information disclosure of phone accounts with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-231986341

- [https://github.com/Live-Hack-CVE/CVE-2022-20284](https://github.com/Live-Hack-CVE/CVE-2022-20284) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20284.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20284.svg)


## CVE-2022-20283
 In Bluetooth, there is a possible out of bounds write due to an integer overflow. This could lead to remote code execution over Bluetooth with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-233069336

- [https://github.com/Live-Hack-CVE/CVE-2022-20283](https://github.com/Live-Hack-CVE/CVE-2022-20283) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20283.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20283.svg)


## CVE-2022-20282
 In AppWidget, there is a possible way to start an activity from the background due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-204083104

- [https://github.com/Live-Hack-CVE/CVE-2022-20282](https://github.com/Live-Hack-CVE/CVE-2022-20282) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20282.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20282.svg)


## CVE-2022-20280
 In MMSProvider, there is a possible read of protected data due to improper input validationSQL injection. This could lead to local information disclosure of sms/mms data with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-204117261

- [https://github.com/Live-Hack-CVE/CVE-2022-20280](https://github.com/Live-Hack-CVE/CVE-2022-20280) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20280.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20280.svg)


## CVE-2022-20273
 In Bluetooth, there is a possible out of bounds read due to a heap buffer overflow. This could lead to remote information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-206478022

- [https://github.com/Live-Hack-CVE/CVE-2022-20273](https://github.com/Live-Hack-CVE/CVE-2022-20273) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20273.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20273.svg)


## CVE-2022-20272
 In PermissionController, there is a possible misunderstanding about the default SMS application's permission set due to misleading text. This could lead to local information disclosure with User privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-207672568

- [https://github.com/Live-Hack-CVE/CVE-2022-20272](https://github.com/Live-Hack-CVE/CVE-2022-20272) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20272.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20272.svg)


## CVE-2022-20271
 In PermissionController, there is a possible way to grant some permissions without user consent due to misleading or insufficient UI. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-207672635

- [https://github.com/Live-Hack-CVE/CVE-2022-20271](https://github.com/Live-Hack-CVE/CVE-2022-20271) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20271.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20271.svg)


## CVE-2022-20269
 In Bluetooth, there is a possible out of bounds write due to an incorrect bounds check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-209062898

- [https://github.com/Live-Hack-CVE/CVE-2022-20269](https://github.com/Live-Hack-CVE/CVE-2022-20269) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20269.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20269.svg)


## CVE-2022-20122
 The PowerVR GPU driver allows unprivileged apps to allocated pinned memory, unpin it (which makes it available to be freed), and continue using the page in GPU calls. No privileges required and this results in kernel memory corruption.Product: AndroidVersions: Android SoCAndroid ID: A-232441339

- [https://github.com/Live-Hack-CVE/CVE-2022-20122](https://github.com/Live-Hack-CVE/CVE-2022-20122) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-20122.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-20122.svg)


## CVE-2022-4741
 A vulnerability was found in docconv up to 1.2.0 and classified as problematic. This issue affects the function ConvertDocx/ConvertODT/ConvertPages/ConvertXML/XMLToText. The manipulation leads to uncontrolled memory allocation. The attack may be initiated remotely. Upgrading to version 1.2.1 is able to address this issue. The name of the patch is 42bcff666855ab978e67a9041d0cdea552f20301. It is recommended to upgrade the affected component. The associated identifier of this vulnerability is VDB-216779.

- [https://github.com/Live-Hack-CVE/CVE-2022-4741](https://github.com/Live-Hack-CVE/CVE-2022-4741) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4741.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4741.svg)


## CVE-2022-4740
 A vulnerability, which was classified as problematic, has been found in kkFileView. Affected by this issue is the function setWatermarkAttribute of the file /picturesPreview. The manipulation leads to cross site scripting. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-216776.

- [https://github.com/Live-Hack-CVE/CVE-2022-4740](https://github.com/Live-Hack-CVE/CVE-2022-4740) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4740.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4740.svg)


## CVE-2022-4739
 A vulnerability classified as critical was found in SourceCodester School Dormitory Management System 1.0. Affected by this vulnerability is an unknown functionality of the component Admin Login. The manipulation leads to sql injection. The attack can be launched remotely. The associated identifier of this vulnerability is VDB-216775.

- [https://github.com/Live-Hack-CVE/CVE-2022-4739](https://github.com/Live-Hack-CVE/CVE-2022-4739) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4739.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4739.svg)


## CVE-2022-4738
 A vulnerability classified as problematic has been found in SourceCodester Blood Bank Management System 1.0. Affected is an unknown function of the file index.php?page=users of the component User Registration Handler. The manipulation of the argument Name leads to cross site scripting. It is possible to launch the attack remotely. VDB-216774 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-4738](https://github.com/Live-Hack-CVE/CVE-2022-4738) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4738.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4738.svg)


## CVE-2022-4737
 A vulnerability was found in SourceCodester Blood Bank Management System 1.0. It has been rated as critical. This issue affects some unknown processing of the file login.php. The manipulation of the argument username/password leads to sql injection. The attack may be initiated remotely. The identifier VDB-216773 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-4737](https://github.com/Live-Hack-CVE/CVE-2022-4737) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4737.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4737.svg)


## CVE-2022-4736
 A vulnerability was found in Venganzas del Pasado and classified as problematic. Affected by this issue is some unknown functionality. The manipulation of the argument the_title leads to cross site scripting. The attack may be launched remotely. The name of the patch is 62339b2ec445692c710b804bdf07aef4bd247ff7. It is recommended to apply a patch to fix this issue. VDB-216770 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-4736](https://github.com/Live-Hack-CVE/CVE-2022-4736) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4736.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4736.svg)


## CVE-2022-4735
 A vulnerability classified as problematic was found in asrashley dash-live. This vulnerability affects the function ready of the file static/js/media.js of the component DOM Node Handler. The manipulation leads to cross site scripting. The attack can be initiated remotely. The name of the patch is 24d01757a5319cc14c4aa1d8b53d1ab24d48e451. It is recommended to apply a patch to fix this issue. VDB-216766 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-4735](https://github.com/Live-Hack-CVE/CVE-2022-4735) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4735.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4735.svg)


## CVE-2022-4731
 A vulnerability, which was classified as problematic, was found in myapnea up to 29.0.x. Affected is an unknown function of the component Title Handler. The manipulation leads to cross site scripting. It is possible to launch the attack remotely. Upgrading to version 29.1.0 is able to address this issue. The name of the patch is 99934258530d761bd5d09809bfa6c14b598f8d18. It is recommended to upgrade the affected component. VDB-216750 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-4731](https://github.com/Live-Hack-CVE/CVE-2022-4731) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4731.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4731.svg)


## CVE-2022-2965
 Improper Restriction of Rendered UI Layers or Frames in GitHub repository notrinos/notrinoserp prior to 0.7.

- [https://github.com/Live-Hack-CVE/CVE-2022-2965](https://github.com/Live-Hack-CVE/CVE-2022-2965) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2965.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2965.svg)


## CVE-2022-2957
 A vulnerability classified as critical was found in SourceCodester Simple and Nice Shopping Cart Script. Affected by this vulnerability is an unknown functionality of the file /mkshop/Men/profile.php. The manipulation of the argument mem_id leads to sql injection. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-207001 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-2957](https://github.com/Live-Hack-CVE/CVE-2022-2957) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2957.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2957.svg)


## CVE-2022-2956
 A vulnerability classified as problematic has been found in ConsoleTVs Noxen. Affected is an unknown function of the file /Noxen-master/users.php. The manipulation of the argument create_user_username with the input &quot;&gt;&lt;script&gt;alert(/xss/)&lt;/script&gt; leads to cross site scripting. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-207000.

- [https://github.com/Live-Hack-CVE/CVE-2022-2956](https://github.com/Live-Hack-CVE/CVE-2022-2956) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2956.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2956.svg)


## CVE-2022-2932
 Cross-site Scripting (XSS) - Reflected in GitHub repository bustle/mobiledoc-kit prior to 0.14.2.

- [https://github.com/Live-Hack-CVE/CVE-2022-2932](https://github.com/Live-Hack-CVE/CVE-2022-2932) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2932.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2932.svg)


## CVE-2022-2930
 Unverified Password Change in GitHub repository octoprint/octoprint prior to 1.8.3.

- [https://github.com/Live-Hack-CVE/CVE-2022-2930](https://github.com/Live-Hack-CVE/CVE-2022-2930) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2930.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2930.svg)


## CVE-2022-2927
 Weak Password Requirements in GitHub repository notrinos/notrinoserp prior to 0.7.

- [https://github.com/Live-Hack-CVE/CVE-2022-2927](https://github.com/Live-Hack-CVE/CVE-2022-2927) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2927.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2927.svg)


## CVE-2022-2921
 Exposure of Private Personal Information to an Unauthorized Actor in GitHub repository notrinos/notrinoserp prior to v0.7. This results in privilege escalation to a system administrator account. An attacker can gain access to protected functionality such as create/update companies, install/update languages, install/activate extensions, install/activate themes and other permissive actions.

- [https://github.com/Live-Hack-CVE/CVE-2022-2921](https://github.com/Live-Hack-CVE/CVE-2022-2921) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2921.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2921.svg)


## CVE-2022-2909
 A vulnerability was found in SourceCodester Simple and Nice Shopping Cart Script. It has been declared as critical. Affected by this vulnerability is an unknown functionality of the file /mkshop/Men/profile.php. The manipulation leads to unrestricted upload. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-206845 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-2909](https://github.com/Live-Hack-CVE/CVE-2022-2909) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2909.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2909.svg)


## CVE-2022-2890
 Cross-site Scripting (XSS) - Stored in GitHub repository yetiforcecompany/yetiforcecrm prior to 6.4.0.

- [https://github.com/Live-Hack-CVE/CVE-2022-2890](https://github.com/Live-Hack-CVE/CVE-2022-2890) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2890.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2890.svg)


## CVE-2022-2886
 A vulnerability, which was classified as critical, was found in Laravel 5.1. Affected is an unknown function. The manipulation leads to deserialization. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-206688.

- [https://github.com/Live-Hack-CVE/CVE-2022-2886](https://github.com/Live-Hack-CVE/CVE-2022-2886) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2886.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2886.svg)


## CVE-2022-2885
 Cross-site Scripting (XSS) - Stored in GitHub repository yetiforcecompany/yetiforcecrm prior to 6.4.0.

- [https://github.com/Live-Hack-CVE/CVE-2022-2885](https://github.com/Live-Hack-CVE/CVE-2022-2885) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2885.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2885.svg)


## CVE-2022-2876
 A vulnerability, which was classified as critical, was found in SourceCodester Student Management System. Affected is an unknown function of the file index.php. The manipulation of the argument id leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. VDB-206634 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-2876](https://github.com/Live-Hack-CVE/CVE-2022-2876) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2876.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2876.svg)


## CVE-2022-2873
 An out-of-bounds memory access flaw was found in the Linux kernel Intel&#8217;s iSMT SMBus host controller driver in the way a user triggers the I2C_SMBUS_BLOCK_DATA (with the ioctl I2C_SMBUS) with malicious input data. This flaw allows a local user to crash the system.

- [https://github.com/Live-Hack-CVE/CVE-2022-2873](https://github.com/Live-Hack-CVE/CVE-2022-2873) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2873.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2873.svg)


## CVE-2022-2871
 Cross-site Scripting (XSS) - Stored in GitHub repository notrinos/notrinoserp prior to 0.7.

- [https://github.com/Live-Hack-CVE/CVE-2022-2871](https://github.com/Live-Hack-CVE/CVE-2022-2871) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2871.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2871.svg)


## CVE-2022-2870
 A vulnerability was found in laravel 5.1 and classified as problematic. This issue affects some unknown processing. The manipulation leads to deserialization. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-206501 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-2870](https://github.com/Live-Hack-CVE/CVE-2022-2870) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2870.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2870.svg)


## CVE-2022-2847
 A vulnerability, which was classified as critical, has been found in SourceCodester Guest Management System. This issue affects some unknown processing of the file /guestmanagement/front.php. The manipulation of the argument rid leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-206489 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-2847](https://github.com/Live-Hack-CVE/CVE-2022-2847) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2847.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2847.svg)


## CVE-2022-2844
 A vulnerability classified as problematic has been found in MotoPress Timetable and Event Schedule up to 1.4.06. This affects an unknown part of the file /wp/?cpmvc_id=1&amp;cpmvc_do_action=mvparse&amp;f=datafeed&amp;calid=1&amp;month_index=1&amp;method=adddetails&amp;id=2 of the component Calendar Handler. The manipulation of the argument Subject/Location/Description leads to cross site scripting. It is possible to initiate the attack remotely. The associated identifier of this vulnerability is VDB-206487.

- [https://github.com/Live-Hack-CVE/CVE-2022-2844](https://github.com/Live-Hack-CVE/CVE-2022-2844) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2844.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2844.svg)


## CVE-2022-2843
 A vulnerability was found in MotoPress Timetable and Event Schedule. It has been rated as problematic. Affected by this issue is some unknown functionality of the file /wp-admin/admin-ajax.php of the component Quick Edit. The manipulation of the argument post_title with the input &lt;img src=x onerror=alert`2`&gt; leads to cross site scripting. The attack may be launched remotely. VDB-206486 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-2843](https://github.com/Live-Hack-CVE/CVE-2022-2843) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2843.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2843.svg)


## CVE-2022-2842
 A vulnerability classified as critical has been found in SourceCodester Gym Management System. This affects an unknown part of the file login.php. The manipulation of the argument user_email leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-206451.

- [https://github.com/Live-Hack-CVE/CVE-2022-2842](https://github.com/Live-Hack-CVE/CVE-2022-2842) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2842.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2842.svg)


## CVE-2022-2841
 A vulnerability was found in CrowdStrike Falcon 6.31.14505.0/6.42.15610. It has been classified as problematic. Affected is the Uninstallation Handler which makes it possible to circumvent and disable the security feature. The manipulation leads to missing authorization. The identifier of this vulnerability is VDB-206880.

- [https://github.com/Live-Hack-CVE/CVE-2022-2841](https://github.com/Live-Hack-CVE/CVE-2022-2841) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2841.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2841.svg)


## CVE-2022-2838
 In Eclipse Sphinx&#8482; before version 0.13.1, Apache Xerces XML Parser was used without disabling processing of referenced external entities allowing the injection of arbitrary definitions which is able to access local files and expose their contents via HTTP requests.

- [https://github.com/Live-Hack-CVE/CVE-2022-2838](https://github.com/Live-Hack-CVE/CVE-2022-2838) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2838.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2838.svg)


## CVE-2022-2833
 Endless Infinite loop in Blender-thumnailing due to logical bugs.

- [https://github.com/Live-Hack-CVE/CVE-2022-2833](https://github.com/Live-Hack-CVE/CVE-2022-2833) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2833.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2833.svg)


## CVE-2022-2829
 Cross-site Scripting (XSS) - Stored in GitHub repository yetiforcecompany/yetiforcecrm prior to 6.4.0.

- [https://github.com/Live-Hack-CVE/CVE-2022-2829](https://github.com/Live-Hack-CVE/CVE-2022-2829) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2829.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2829.svg)


## CVE-2022-2824
 Improper Access Control in GitHub repository openemr/openemr prior to 7.0.0.1.

- [https://github.com/Live-Hack-CVE/CVE-2022-2824](https://github.com/Live-Hack-CVE/CVE-2022-2824) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2824.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2824.svg)


## CVE-2022-2822
 An attacker can freely brute force username and password and can takeover any account. An attacker could easily guess user passwords and gain access to user and administrative accounts.

- [https://github.com/Live-Hack-CVE/CVE-2022-2822](https://github.com/Live-Hack-CVE/CVE-2022-2822) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2822.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2822.svg)


## CVE-2022-2821
 Missing Critical Step in Authentication in GitHub repository namelessmc/nameless prior to v2.0.2.

- [https://github.com/Live-Hack-CVE/CVE-2022-2821](https://github.com/Live-Hack-CVE/CVE-2022-2821) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2821.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2821.svg)


## CVE-2022-2820
 Improper Access Control in GitHub repository namelessmc/nameless prior to v2.0.2.

- [https://github.com/Live-Hack-CVE/CVE-2022-2820](https://github.com/Live-Hack-CVE/CVE-2022-2820) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2820.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2820.svg)


## CVE-2022-2814
 A vulnerability has been found in SourceCodester Simple and Nice Shopping Cart Script and classified as problematic. Affected by this vulnerability is an unknown functionality of the file /mkshope/login.php. The manipulation of the argument msg leads to cross site scripting. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-206401 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-2814](https://github.com/Live-Hack-CVE/CVE-2022-2814) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2814.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2814.svg)


## CVE-2022-2813
 A vulnerability, which was classified as problematic, was found in SourceCodester Guest Management System. Affected is an unknown function. The manipulation leads to cleartext storage of passwords in the database. The identifier of this vulnerability is VDB-206400.

- [https://github.com/Live-Hack-CVE/CVE-2022-2813](https://github.com/Live-Hack-CVE/CVE-2022-2813) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2813.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2813.svg)


## CVE-2022-2812
 A vulnerability classified as critical was found in SourceCodester Guest Management System. This vulnerability affects unknown code of the file index.php. The manipulation of the argument username/pass leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. VDB-206398 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-2812](https://github.com/Live-Hack-CVE/CVE-2022-2812) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2812.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2812.svg)


## CVE-2022-2811
 A vulnerability classified as problematic has been found in SourceCodester Guest Management System. This affects an unknown part of the file myform.php. The manipulation of the argument name leads to cross site scripting. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-206397 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-2811](https://github.com/Live-Hack-CVE/CVE-2022-2811) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2811.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2811.svg)


## CVE-2022-2804
 A vulnerability was found in SourceCodester Zoo Management System. It has been classified as critical. Affected is an unknown function of the file /pages/apply_vacancy.php. The manipulation of the argument filename leads to unrestricted upload. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. VDB-206250 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-2804](https://github.com/Live-Hack-CVE/CVE-2022-2804) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2804.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2804.svg)


## CVE-2022-2803
 A vulnerability was found in SourceCodester Zoo Management System and classified as critical. This issue affects some unknown processing of the file /pages/animals.php. The manipulation of the argument class_id leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-206249 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-2803](https://github.com/Live-Hack-CVE/CVE-2022-2803) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2803.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2803.svg)


## CVE-2022-2802
 A vulnerability has been found in SourceCodester Gas Agency Management System and classified as critical. This vulnerability affects unknown code of the file gasmark/login.php. The manipulation of the argument username leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-206248.

- [https://github.com/Live-Hack-CVE/CVE-2022-2802](https://github.com/Live-Hack-CVE/CVE-2022-2802) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2802.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2802.svg)


## CVE-2022-2801
 A vulnerability, which was classified as critical, was found in SourceCodester Automated Beer Parlour Billing System. This affects an unknown part of the component Login. The manipulation of the argument username leads to sql injection. It is possible to initiate the attack remotely. The associated identifier of this vulnerability is VDB-206247.

- [https://github.com/Live-Hack-CVE/CVE-2022-2801](https://github.com/Live-Hack-CVE/CVE-2022-2801) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2801.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2801.svg)


## CVE-2022-2800
 A vulnerability, which was classified as problematic, has been found in SourceCodester Gym Management System. Affected by this issue is some unknown functionality. The manipulation leads to clickjacking. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. VDB-206246 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-2800](https://github.com/Live-Hack-CVE/CVE-2022-2800) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2800.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2800.svg)


## CVE-2022-2796
 Cross-site Scripting (XSS) - Stored in GitHub repository pimcore/pimcore prior to 10.5.4.

- [https://github.com/Live-Hack-CVE/CVE-2022-2796](https://github.com/Live-Hack-CVE/CVE-2022-2796) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2796.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2796.svg)


## CVE-2022-2793
 Emerson Electric's Proficy Machine Edition Version 9.00 and prior is vulenrable to CWE-353 Missing Support for Integrity Check, and has no authentication or authorization of data packets after establishing a connection for the SRTP protocol.

- [https://github.com/Live-Hack-CVE/CVE-2022-2793](https://github.com/Live-Hack-CVE/CVE-2022-2793) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2793.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2793.svg)


## CVE-2022-2792
 Emerson Electric's Proficy Machine Edition Version 9.00 and prior is vulenrable to CWE-284 Improper Access Control, and stores project data in a directory with improper access control lists.

- [https://github.com/Live-Hack-CVE/CVE-2022-2792](https://github.com/Live-Hack-CVE/CVE-2022-2792) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2792.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2792.svg)


## CVE-2022-2790
 Emerson Electric's Proficy Machine Edition Version 9.00 and prior is vulenrable to CWE-347 Improper Verification of Cryptographic Signature, and does not properly verify compiled logic (PDT files) and data blocks data (BLD/BLK files).

- [https://github.com/Live-Hack-CVE/CVE-2022-2790](https://github.com/Live-Hack-CVE/CVE-2022-2790) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2790.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2790.svg)


## CVE-2022-2789
 Emerson Electric's Proficy Machine Edition Version 9.00 and prior is vulnerable to CWE-345 Insufficient Verification of Data Authenticity, and can display logic that is different than the compiled logic.

- [https://github.com/Live-Hack-CVE/CVE-2022-2789](https://github.com/Live-Hack-CVE/CVE-2022-2789) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2789.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2789.svg)


## CVE-2022-2788
 Emerson Electric's Proficy Machine Edition Version 9.80 and prior is vulnerable to CWE-29 Path Traversal: '\..\Filename', also known as a ZipSlip attack, through an upload procedure which enables attackers to implant a malicious .BLZ file on the PLC. The file can transfer through the engineering station onto Windows in a way that executes the malicious code.

- [https://github.com/Live-Hack-CVE/CVE-2022-2788](https://github.com/Live-Hack-CVE/CVE-2022-2788) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2788.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2788.svg)


## CVE-2022-2779
 A vulnerability classified as critical was found in SourceCodester Gas Agency Management System. Affected by this vulnerability is an unknown functionality of the file /gasmark/assets/myimages/oneWord.php. The manipulation of the argument shell leads to unrestricted upload. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-206173 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-2779](https://github.com/Live-Hack-CVE/CVE-2022-2779) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2779.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2779.svg)


## CVE-2022-2719
 In ImageMagick, a crafted file could trigger an assertion failure when a call to WriteImages was made in MagickWand/operation.c, due to a NULL image list. This could potentially cause a denial of service. This was fixed in upstream ImageMagick version 7.1.0-30.

- [https://github.com/Live-Hack-CVE/CVE-2022-2719](https://github.com/Live-Hack-CVE/CVE-2022-2719) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2719.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2719.svg)


## CVE-2022-2662
 Sequi PortBloque S has a improper authentication issues which may allow an attacker to bypass the authentication process and gain user-level access to the device.

- [https://github.com/Live-Hack-CVE/CVE-2022-2662](https://github.com/Live-Hack-CVE/CVE-2022-2662) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2662.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2662.svg)


## CVE-2022-2661
 Sequi PortBloque S has an improper authorization vulnerability, which may allow a low-privileged user to perform administrative functions using specifically crafted requests.

- [https://github.com/Live-Hack-CVE/CVE-2022-2661](https://github.com/Live-Hack-CVE/CVE-2022-2661) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2661.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2661.svg)


## CVE-2022-2600
 The Auto-hyperlink URLs WordPress plugin through 5.4.1 does not set rel=&quot;noopener noreferer&quot; on generated links, which can lead to Tab Nabbing by giving the target site access to the source tab through the window.opener DOM object.

- [https://github.com/Live-Hack-CVE/CVE-2022-2600](https://github.com/Live-Hack-CVE/CVE-2022-2600) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2600.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2600.svg)


## CVE-2022-2594
 The Advanced Custom Fields WordPress plugin before 5.12.3, Advanced Custom Fields Pro WordPress plugin before 5.12.3 allows unauthenticated users to upload files allowed in a default WP configuration (so PHP is not possible) if there is a frontend form available. This vulnerability was introduced in the 5.0 rewrite and did not exist prior to that release.

- [https://github.com/Live-Hack-CVE/CVE-2022-2594](https://github.com/Live-Hack-CVE/CVE-2022-2594) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2594.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2594.svg)


## CVE-2022-2593
 The Better Search Replace WordPress plugin before 1.4.1 does not properly sanitise and escape table data before inserting it into a SQL query, which could allow high privilege users to perform SQL Injection attacks

- [https://github.com/Live-Hack-CVE/CVE-2022-2593](https://github.com/Live-Hack-CVE/CVE-2022-2593) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2593.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2593.svg)


## CVE-2022-2558
 The Simple Job Board WordPress plugin before 2.10.0 is susceptible to Directory Listing which allows the public listing of uploaded resumes in certain configurations.

- [https://github.com/Live-Hack-CVE/CVE-2022-2558](https://github.com/Live-Hack-CVE/CVE-2022-2558) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2558.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2558.svg)


## CVE-2022-2557
 The Team WordPress plugin before 4.1.2 contains a file which could allow any authenticated users to download arbitrary files from the server via a path traversal vector. Furthermore, the file will also be deleted after its content is returned to the user

- [https://github.com/Live-Hack-CVE/CVE-2022-2557](https://github.com/Live-Hack-CVE/CVE-2022-2557) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2557.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2557.svg)


## CVE-2022-2555
 The Yotpo Reviews for WooCommerce WordPress plugin through 2.0.4 lacks nonce check when updating its settings, which could allow attacker to make a logged in admin change them via a CSRF attack.

- [https://github.com/Live-Hack-CVE/CVE-2022-2555](https://github.com/Live-Hack-CVE/CVE-2022-2555) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2555.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2555.svg)


## CVE-2022-2551
 The Duplicator WordPress plugin before 1.4.7 discloses the url of the a backup to unauthenticated visitors accessing the main installer endpoint of the plugin, if the installer script has been run once by an administrator, allowing download of the full site backup without authenticating.

- [https://github.com/Live-Hack-CVE/CVE-2022-2551](https://github.com/Live-Hack-CVE/CVE-2022-2551) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2551.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2551.svg)


## CVE-2022-2547
 A crafted HTTP packet without a content-type header can create a denial-of-service condition in Softing Secure Integration Server V1.22.

- [https://github.com/Live-Hack-CVE/CVE-2022-2547](https://github.com/Live-Hack-CVE/CVE-2022-2547) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2547.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2547.svg)


## CVE-2022-2544
 The Ninja Job Board WordPress plugin before 1.3.3 does not protect the directory where it stores uploaded resumes, making it vulnerable to unauthenticated Directory Listing which allows the download of uploaded resumes.

- [https://github.com/Live-Hack-CVE/CVE-2022-2544](https://github.com/Live-Hack-CVE/CVE-2022-2544) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2544.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2544.svg)


## CVE-2022-2535
 The SearchWP Live Ajax Search WordPress plugin before 1.6.2 does not ensure that users making a live search are limited to published posts only, allowing unauthenticated users to make a crafted query disclosing private/draft/pending post titles along with their permalink

- [https://github.com/Live-Hack-CVE/CVE-2022-2535](https://github.com/Live-Hack-CVE/CVE-2022-2535) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2535.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2535.svg)


## CVE-2022-2532
 The Feed Them Social WordPress plugin before 3.0.1 does not sanitise and escape a parameter before outputting it back in the page, leading to a Reflected Cross-Site Scripting

- [https://github.com/Live-Hack-CVE/CVE-2022-2532](https://github.com/Live-Hack-CVE/CVE-2022-2532) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2532.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2532.svg)


## CVE-2022-2509
 A vulnerability found in gnutls. This security flaw happens because of a double free error occurs during verification of pkcs7 signatures in gnutls_pkcs7_verify function.

- [https://github.com/Live-Hack-CVE/CVE-2022-2509](https://github.com/Live-Hack-CVE/CVE-2022-2509) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2509.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2509.svg)


## CVE-2022-2503
 Dm-verity is used for extending root-of-trust to root filesystems. LoadPin builds on this property to restrict module/firmware loads to just the trusted root filesystem. Device-mapper table reloads currently allow users with root privileges to switch out the target with an equivalent dm-linear target and bypass verification till reboot. This allows root to bypass LoadPin and can be used to load untrusted and unverified kernel modules and firmware, which implies arbitrary kernel execution and persistence for peripherals that do not verify firmware updates. We recommend upgrading past commit 4caae58406f8ceb741603eee460d79bacca9b1b5

- [https://github.com/Live-Hack-CVE/CVE-2022-2503](https://github.com/Live-Hack-CVE/CVE-2022-2503) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2503.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2503.svg)


## CVE-2022-2481
 Use after free in Views in Google Chrome prior to 103.0.5060.134 allowed a remote attacker who convinced a user to engage in specific user interactions to potentially exploit heap corruption via UI interaction.

- [https://github.com/Live-Hack-CVE/CVE-2022-2481](https://github.com/Live-Hack-CVE/CVE-2022-2481) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2481.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2481.svg)


## CVE-2022-2480
 Use after free in Service Worker API in Google Chrome prior to 103.0.5060.134 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2022-2480](https://github.com/Live-Hack-CVE/CVE-2022-2480) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2480.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2480.svg)


## CVE-2022-2479
 Insufficient validation of untrusted input in File in Google Chrome on Android prior to 103.0.5060.134 allowed an attacker who convinced a user to install a malicious app to obtain potentially sensitive information from internal file directories via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2022-2479](https://github.com/Live-Hack-CVE/CVE-2022-2479) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2479.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2479.svg)


## CVE-2022-2477
 Use after free in Guest View in Google Chrome prior to 103.0.5060.134 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2022-2477](https://github.com/Live-Hack-CVE/CVE-2022-2477) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2477.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2477.svg)


## CVE-2022-2465
 Rockwell Automation ISaGRAF Workbench software versions 6.0 through 6.6.9 are affected by a Deserialization of Untrusted Data vulnerability. ISaGRAF Workbench does not limit the objects that can be deserialized. This vulnerability allows attackers to craft a malicious serialized object that, if opened by a local user in ISaGRAF Workbench, may result in remote code execution. This vulnerability requires user interaction to be successfully exploited.

- [https://github.com/Live-Hack-CVE/CVE-2022-2465](https://github.com/Live-Hack-CVE/CVE-2022-2465) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2465.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2465.svg)


## CVE-2022-2464
 Rockwell Automation ISaGRAF Workbench software versions 6.0 through 6.6.9 are affected by a Path Traversal vulnerability. Crafted malicious files can allow an attacker to traverse the file system when opened by ISaGRAF Workbench. If successfully exploited, an attacker could overwrite existing files and create additional files with the same permissions of the ISaGRAF Workbench software. User interaction is required for this exploit to be successful.

- [https://github.com/Live-Hack-CVE/CVE-2022-2464](https://github.com/Live-Hack-CVE/CVE-2022-2464) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2464.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2464.svg)


## CVE-2022-2463
 Rockwell Automation ISaGRAF Workbench software versions 6.0 through 6.6.9 are affected by a Path Traversal vulnerability. A crafted malicious .7z exchange file may allow an attacker to gain the privileges of the ISaGRAF Workbench software when opened. If the software is running at the SYSTEM level, then the attacker will gain admin level privileges. User interaction is required for this exploit to be successful.

- [https://github.com/Live-Hack-CVE/CVE-2022-2463](https://github.com/Live-Hack-CVE/CVE-2022-2463) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2463.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2463.svg)


## CVE-2022-2407
 The WP phpMyAdmin WordPress plugin before 5.2.0.4 does not escape some of its settings, which could allow high privilege users such as admin to perform Stored Cross-Site Scripting attacks when the unfiltered_html capability is disallowed (for example in multisite setup)

- [https://github.com/Live-Hack-CVE/CVE-2022-2407](https://github.com/Live-Hack-CVE/CVE-2022-2407) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2407.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2407.svg)


## CVE-2022-2392
 The Lana Downloads Manager WordPress plugin before 1.8.0 is affected by an arbitrary file download vulnerability that can be exploited by users with &quot;Contributor&quot; permissions or higher.

- [https://github.com/Live-Hack-CVE/CVE-2022-2392](https://github.com/Live-Hack-CVE/CVE-2022-2392) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2392.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2392.svg)


## CVE-2022-2390
 Apps developed with Google Play Services SDK incorrectly had the mutability flag set to PendingIntents that were passed to the Notification service. As Google Play services SDK is so widely used, this bug affects many applications. For an application affected, this bug will let the attacker, gain the access to all non-exported providers and/or gain the access to other providers the victim has permissions. We recommend upgrading to version 18.0.2 of the Play Service SDK as well as rebuilding and redeploying apps.

- [https://github.com/Live-Hack-CVE/CVE-2022-2390](https://github.com/Live-Hack-CVE/CVE-2022-2390) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2390.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2390.svg)


## CVE-2022-2389
 The Abandoned Cart Recovery for WooCommerce, Follow Up Emails, Newsletter Builder &amp; Marketing Automation By Autonami WordPress plugin before 2.1.2 does not have authorisation and CSRF checks in one of its AJAX action, allowing any authenticated users, such as subscriber to create automations

- [https://github.com/Live-Hack-CVE/CVE-2022-2389](https://github.com/Live-Hack-CVE/CVE-2022-2389) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2389.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2389.svg)


## CVE-2022-2388
 The WP Coder WordPress plugin before 2.5.3 does not have CSRF check in place when deleting code created by the plugin, which could allow attackers to make a logged in admin delete arbitrary ones via a CSRF attack

- [https://github.com/Live-Hack-CVE/CVE-2022-2388](https://github.com/Live-Hack-CVE/CVE-2022-2388) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2388.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2388.svg)


## CVE-2022-2384
 The Digital Publications by Supsystic WordPress plugin before 1.7.4 does not sanitise and escape its settings, allowing high privilege users such as admin to perform cross-Site Scripting attacks even when the unfiltered_html capability is disallowed.

- [https://github.com/Live-Hack-CVE/CVE-2022-2384](https://github.com/Live-Hack-CVE/CVE-2022-2384) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2384.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2384.svg)


## CVE-2022-2383
 The Feed Them Social WordPress plugin before 3.0.1 does not sanitise and escape a parameter before outputting it back in the page, leading to a Reflected Cross-Site Scripting

- [https://github.com/Live-Hack-CVE/CVE-2022-2383](https://github.com/Live-Hack-CVE/CVE-2022-2383) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2383.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2383.svg)


## CVE-2022-2382
 The Product Slider for WooCommerce WordPress plugin before 2.5.7 has flawed CSRF checks and lack authorisation in some of its AJAX actions, allowing any authenticated users, such as subscriber to call them. One in particular could allow them to delete arbitrary blog options.

- [https://github.com/Live-Hack-CVE/CVE-2022-2382](https://github.com/Live-Hack-CVE/CVE-2022-2382) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2382.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2382.svg)


## CVE-2022-2381
 The E Unlocked - Student Result WordPress plugin through 1.0.4 is lacking CSRF and validation when uploading the School logo, which could allow attackers to make a logged in admin upload arbitrary files, such as PHP via a CSRF attack

- [https://github.com/Live-Hack-CVE/CVE-2022-2381](https://github.com/Live-Hack-CVE/CVE-2022-2381) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2381.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2381.svg)


## CVE-2022-2379
 The Easy Student Results WordPress plugin through 2.2.8 lacks authorisation in its REST API, allowing unauthenticated users to retrieve information related to the courses, exams, departments as well as student's grades and PII such as email address, physical address, phone number etc

- [https://github.com/Live-Hack-CVE/CVE-2022-2379](https://github.com/Live-Hack-CVE/CVE-2022-2379) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2379.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2379.svg)


## CVE-2022-2378
 The Easy Student Results WordPress plugin through 2.2.8 does not sanitise and escape a parameter before outputting it back in the page, leading to a Reflected Cross-Site Scripting

- [https://github.com/Live-Hack-CVE/CVE-2022-2378](https://github.com/Live-Hack-CVE/CVE-2022-2378) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2378.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2378.svg)


## CVE-2022-2377
 The Directorist WordPress plugin before 7.3.0 does not have authorisation and CSRF checks in an AJAX action, allowing any authenticated users to send arbitrary emails on behalf of the blog

- [https://github.com/Live-Hack-CVE/CVE-2022-2377](https://github.com/Live-Hack-CVE/CVE-2022-2377) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2377.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2377.svg)


## CVE-2022-2375
 The WP Sticky Button WordPress plugin before 1.4.1 does not have authorisation and CSRF checks when saving its settings, allowing unauthenticated users to update them. Furthermore, due to the lack of escaping in some of them, it could lead to Stored Cross-Site Scripting issues

- [https://github.com/Live-Hack-CVE/CVE-2022-2375](https://github.com/Live-Hack-CVE/CVE-2022-2375) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2375.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2375.svg)


## CVE-2022-2374
 The Simply Schedule Appointments WordPress plugin before 1.5.7.7 does not sanitise and escape some of its settings, which could allow high privilege users such as admin to perform Stored Cross-Site Scripting attacks even when the unfiltered_html capability is disallowed (for example in multisite setup)

- [https://github.com/Live-Hack-CVE/CVE-2022-2374](https://github.com/Live-Hack-CVE/CVE-2022-2374) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2374.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2374.svg)


## CVE-2022-2373
 The Simply Schedule Appointments WordPress plugin before 1.5.7.7 is missing authorisation in a REST endpoint, allowing unauthenticated users to retrieve WordPress users details such as name and email address

- [https://github.com/Live-Hack-CVE/CVE-2022-2373](https://github.com/Live-Hack-CVE/CVE-2022-2373) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2373.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2373.svg)


## CVE-2022-2362
 The Download Manager WordPress plugin before 3.2.50 prioritizes getting a visitor's IP from certain HTTP headers over PHP's REMOTE_ADDR, which makes it possible to bypass IP-based download blocking restrictions.

- [https://github.com/Live-Hack-CVE/CVE-2022-2362](https://github.com/Live-Hack-CVE/CVE-2022-2362) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2362.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2362.svg)


## CVE-2022-2361
 The WP Social Chat WordPress plugin before 6.0.5 does not sanitise and escape some of its settings, which could allow high privilege users such as admin to perform Stored Cross-Site Scripting attacks.

- [https://github.com/Live-Hack-CVE/CVE-2022-2361](https://github.com/Live-Hack-CVE/CVE-2022-2361) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2361.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2361.svg)


## CVE-2022-2354
 The WP-DBManager WordPress plugin before 2.80.8 does not prevent administrators from running arbitrary commands on the server in multisite installations, where only super-administrators should.

- [https://github.com/Live-Hack-CVE/CVE-2022-2354](https://github.com/Live-Hack-CVE/CVE-2022-2354) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2354.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2354.svg)


## CVE-2022-2345
 Use After Free in GitHub repository vim/vim prior to 9.0.0046.

- [https://github.com/Live-Hack-CVE/CVE-2022-2345](https://github.com/Live-Hack-CVE/CVE-2022-2345) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2345.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2345.svg)


## CVE-2022-2343
 Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0044.

- [https://github.com/Live-Hack-CVE/CVE-2022-2343](https://github.com/Live-Hack-CVE/CVE-2022-2343) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2343.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2343.svg)


## CVE-2022-2338
 Softing Secure Integration Server V1.22 is vulnerable to authentication bypass via a machine-in-the-middle attack. The default the administration interface is accessible via plaintext HTTP protocol, facilitating the attack. The HTTP request may contain the session cookie in the request, which may be captured for use in authenticating to the server.

- [https://github.com/Live-Hack-CVE/CVE-2022-2338](https://github.com/Live-Hack-CVE/CVE-2022-2338) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2338.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2338.svg)


## CVE-2022-2337
 A crafted HTTP packet with a missing HTTP URI can create a denial-of-service condition in Softing Secure Integration Server V1.22.

- [https://github.com/Live-Hack-CVE/CVE-2022-2337](https://github.com/Live-Hack-CVE/CVE-2022-2337) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2337.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2337.svg)


## CVE-2022-2336
 Softing Secure Integration Server, edgeConnector, and edgeAggregator software ships with the default administrator credentials as `admin` and password as `admin`. This allows Softing to log in to the server directly to perform administrative functions. Upon installation or upon first login, the application does not ask the user to change the `admin` password. There is no warning or prompt to ask the user to change the default password, and to change the password, many steps are required.

- [https://github.com/Live-Hack-CVE/CVE-2022-2336](https://github.com/Live-Hack-CVE/CVE-2022-2336) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2336.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2336.svg)


## CVE-2022-2335
 A crafted HTTP packet with a -1 content-length header can create a denial-of-service condition in Softing Secure Integration Server V1.22.

- [https://github.com/Live-Hack-CVE/CVE-2022-2335](https://github.com/Live-Hack-CVE/CVE-2022-2335) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2335.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2335.svg)


## CVE-2022-2334
 The application searches for a library dll that is not found. If an attacker can place a dll with this name, then the attacker can leverage it to execute arbitrary code on the targeted Softing Secure Integration Server V1.22.

- [https://github.com/Live-Hack-CVE/CVE-2022-2334](https://github.com/Live-Hack-CVE/CVE-2022-2334) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2334.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2334.svg)


## CVE-2022-2312
 The Student Result or Employee Database WordPress plugin before 1.7.5 does not have CSRF in its AJAX actions, allowing attackers to make logged in user with a role as low as contributor to add/edit and delete students via CSRF attacks. Furthermore, due to the lack of sanitisation and escaping, it could also lead to Stored Cross-Site scripting

- [https://github.com/Live-Hack-CVE/CVE-2022-2312](https://github.com/Live-Hack-CVE/CVE-2022-2312) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2312.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2312.svg)


## CVE-2022-2289
 Use After Free in GitHub repository vim/vim prior to 9.0.

- [https://github.com/Live-Hack-CVE/CVE-2022-2289](https://github.com/Live-Hack-CVE/CVE-2022-2289) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2289.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2289.svg)


## CVE-2022-2286
 Out-of-bounds Read in GitHub repository vim/vim prior to 9.0.

- [https://github.com/Live-Hack-CVE/CVE-2022-2286](https://github.com/Live-Hack-CVE/CVE-2022-2286) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2286.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2286.svg)


## CVE-2022-2284
 Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.

- [https://github.com/Live-Hack-CVE/CVE-2022-2284](https://github.com/Live-Hack-CVE/CVE-2022-2284) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2284.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2284.svg)


## CVE-2022-2276
 The WP Edit Menu WordPress plugin before 1.5.0 does not have authorisation and CSRF in an AJAX action, which could allow unauthenticated attackers to delete arbitrary posts/pages from the blog

- [https://github.com/Live-Hack-CVE/CVE-2022-2276](https://github.com/Live-Hack-CVE/CVE-2022-2276) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2276.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2276.svg)


## CVE-2022-2275
 The WP Edit Menu WordPress plugin before 1.5.0 does not have CSRF in an AJAX action, which could allow attackers to make a logged in admin delete arbitrary posts/pages from the blog via a CSRF attack

- [https://github.com/Live-Hack-CVE/CVE-2022-2275](https://github.com/Live-Hack-CVE/CVE-2022-2275) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2275.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2275.svg)


## CVE-2022-2267
 The Mailchimp for WooCommerce WordPress plugin before 2.7.1 has an AJAX action that allows any logged in users (such as subscriber) to perform a POST request on behalf of the server to the internal network/LAN, the body of the request is also appended to the response so it can be used to scan private network for example

- [https://github.com/Live-Hack-CVE/CVE-2022-2267](https://github.com/Live-Hack-CVE/CVE-2022-2267) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2267.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2267.svg)


## CVE-2022-2261
 The WPIDE WordPress plugin before 3.0 does not sanitize and validate the filename parameter before using it in a require statement in the admin dashboard, leading to a Local File Inclusion issue.

- [https://github.com/Live-Hack-CVE/CVE-2022-2261](https://github.com/Live-Hack-CVE/CVE-2022-2261) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2261.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2261.svg)


## CVE-2022-2257
 Out-of-bounds Read in GitHub repository vim/vim prior to 9.0.

- [https://github.com/Live-Hack-CVE/CVE-2022-2257](https://github.com/Live-Hack-CVE/CVE-2022-2257) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2257.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2257.svg)


## CVE-2022-2234
 An authenticated mySCADA myPRO 8.26.0 user may be able to modify parameters to run commands directly in the operating system.

- [https://github.com/Live-Hack-CVE/CVE-2022-2234](https://github.com/Live-Hack-CVE/CVE-2022-2234) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2234.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2234.svg)


## CVE-2022-2208
 NULL Pointer Dereference in GitHub repository vim/vim prior to 8.2.5163.

- [https://github.com/Live-Hack-CVE/CVE-2022-2208](https://github.com/Live-Hack-CVE/CVE-2022-2208) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2208.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2208.svg)


## CVE-2022-2206
 Out-of-bounds Read in GitHub repository vim/vim prior to 8.2.

- [https://github.com/Live-Hack-CVE/CVE-2022-2206](https://github.com/Live-Hack-CVE/CVE-2022-2206) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2206.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2206.svg)


## CVE-2022-2198
 The WPQA Builder WordPress plugin before 5.7 which is a companion plugin to the Hilmer and Discy , does not check authorization before displaying private messages, allowing any logged in user to read other users private message using the message id, which can easily be brute forced.

- [https://github.com/Live-Hack-CVE/CVE-2022-2198](https://github.com/Live-Hack-CVE/CVE-2022-2198) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2198.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2198.svg)


## CVE-2022-2182
 Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.

- [https://github.com/Live-Hack-CVE/CVE-2022-2182](https://github.com/Live-Hack-CVE/CVE-2022-2182) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2182.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2182.svg)


## CVE-2022-2180
 The GREYD.SUITE WordPress theme does not properly validate uploaded custom font packages, and does not perform any authorization or csrf checks, allowing an unauthenticated attacker to upload arbitrary files including php source files, leading to possible remote code execution (RCE).

- [https://github.com/Live-Hack-CVE/CVE-2022-2180](https://github.com/Live-Hack-CVE/CVE-2022-2180) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2180.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2180.svg)


## CVE-2022-2175
 Buffer Over-read in GitHub repository vim/vim prior to 8.2.

- [https://github.com/Live-Hack-CVE/CVE-2022-2175](https://github.com/Live-Hack-CVE/CVE-2022-2175) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2175.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2175.svg)


## CVE-2022-2172
 The LinkWorth WordPress plugin before 3.3.4 does not implement nonce checks, which could allow attackers to make a logged in admin change settings via a CSRF attack.

- [https://github.com/Live-Hack-CVE/CVE-2022-2172](https://github.com/Live-Hack-CVE/CVE-2022-2172) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2172.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2172.svg)


## CVE-2022-2165
 Insufficient data validation in URL formatting in Google Chrome prior to 103.0.5060.53 allowed a remote attacker to perform domain spoofing via IDN homographs via a crafted domain name.

- [https://github.com/Live-Hack-CVE/CVE-2022-2165](https://github.com/Live-Hack-CVE/CVE-2022-2165) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2165.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2165.svg)


## CVE-2022-2164
 Inappropriate implementation in Extensions API in Google Chrome prior to 103.0.5060.53 allowed an attacker who convinced a user to install a malicious extension to bypass discretionary access control via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2022-2164](https://github.com/Live-Hack-CVE/CVE-2022-2164) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2164.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2164.svg)


## CVE-2022-2162
 Insufficient policy enforcement in File System API in Google Chrome on Windows prior to 103.0.5060.53 allowed a remote attacker to bypass file system access via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2022-2162](https://github.com/Live-Hack-CVE/CVE-2022-2162) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2162.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2162.svg)


## CVE-2022-2116
 The Contact Form DB WordPress plugin before 1.8.0 does not sanitise and escape some parameters before outputting them back in attributes, leading to Reflected Cross-Site Scripting

- [https://github.com/Live-Hack-CVE/CVE-2022-2116](https://github.com/Live-Hack-CVE/CVE-2022-2116) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2116.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2116.svg)


## CVE-2022-2080
 The Sensei LMS WordPress plugin before 4.5.2 does not ensure that the sender of a private message is either the teacher or the original sender, allowing any authenticated user to send messages to arbitrary private conversation via a IDOR attack. Note: Attackers are not able to see responses/messages between the teacher and student

- [https://github.com/Live-Hack-CVE/CVE-2022-2080](https://github.com/Live-Hack-CVE/CVE-2022-2080) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2080.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2080.svg)


## CVE-2022-2075
 In affected versions of Octopus Deploy it is possible to perform a Regex Denial of Service targeting the build information request validation.

- [https://github.com/Live-Hack-CVE/CVE-2022-2075](https://github.com/Live-Hack-CVE/CVE-2022-2075) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2075.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2075.svg)


## CVE-2022-2074
 In affected versions of Octopus Deploy it is possible to perform a Regex Denial of Service using the Variable Project Template.

- [https://github.com/Live-Hack-CVE/CVE-2022-2074](https://github.com/Live-Hack-CVE/CVE-2022-2074) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2074.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2074.svg)


## CVE-2022-2058
 Divide By Zero error in tiffcrop in libtiff 4.4.0 allows attackers to cause a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix is available with commit f3a5e010.

- [https://github.com/Live-Hack-CVE/CVE-2022-2058](https://github.com/Live-Hack-CVE/CVE-2022-2058) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2058.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2058.svg)


## CVE-2022-2049
 In affected versions of Octopus Deploy it is possible to perform a Regex Denial of Service via the package upload function.

- [https://github.com/Live-Hack-CVE/CVE-2022-2049](https://github.com/Live-Hack-CVE/CVE-2022-2049) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2049.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2049.svg)


## CVE-2022-2034
 The Sensei LMS WordPress plugin before 4.5.0 does not have proper permissions set in one of its REST endpoint, allowing unauthenticated users to access private messages sent to teachers

- [https://github.com/Live-Hack-CVE/CVE-2022-2034](https://github.com/Live-Hack-CVE/CVE-2022-2034) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2034.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2034.svg)


## CVE-2022-2031
 A flaw was found in Samba. The security vulnerability occurs when KDC and the kpasswd service share a single account and set of keys, allowing them to decrypt each other's tickets. A user who has been requested to change their password, can exploit this flaw to obtain and use tickets to other services.

- [https://github.com/Live-Hack-CVE/CVE-2022-2031](https://github.com/Live-Hack-CVE/CVE-2022-2031) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2031.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2031.svg)


## CVE-2022-1989
 All CODESYS Visualization versions before V4.2.0.0 generate a login dialog vulnerable to information exposure allowing a remote, unauthenticated attacker to enumerate valid users.

- [https://github.com/Live-Hack-CVE/CVE-2022-1989](https://github.com/Live-Hack-CVE/CVE-2022-1989) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1989.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1989.svg)


## CVE-2022-1932
 The Rezgo Online Booking WordPress plugin before 4.1.8 does not sanitise and escape some parameters before outputting them back in a page, leading to a Reflected Cross-Site Scripting, which can be exploited either via a LFI in an AJAX action, or direct call to the affected file

- [https://github.com/Live-Hack-CVE/CVE-2022-1932](https://github.com/Live-Hack-CVE/CVE-2022-1932) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1932.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1932.svg)


## CVE-2022-1930
 An exponential ReDoS (Regular Expression Denial of Service) can be triggered in the eth-account PyPI package, when an attacker is able to supply arbitrary input to the encode_structured_data method

- [https://github.com/Live-Hack-CVE/CVE-2022-1930](https://github.com/Live-Hack-CVE/CVE-2022-1930) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1930.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1930.svg)


## CVE-2022-1901
 In affected versions of Octopus Deploy it is possible to unmask sensitive variables by using variable preview.

- [https://github.com/Live-Hack-CVE/CVE-2022-1901](https://github.com/Live-Hack-CVE/CVE-2022-1901) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1901.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1901.svg)


## CVE-2022-1796
 Use After Free in GitHub repository vim/vim prior to 8.2.4979.

- [https://github.com/Live-Hack-CVE/CVE-2022-1796](https://github.com/Live-Hack-CVE/CVE-2022-1796) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1796.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1796.svg)


## CVE-2022-1771
 Uncontrolled Recursion in GitHub repository vim/vim prior to 8.2.4975.

- [https://github.com/Live-Hack-CVE/CVE-2022-1771](https://github.com/Live-Hack-CVE/CVE-2022-1771) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1771.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1771.svg)


## CVE-2022-1748
 Softing OPC UA C++ Server SDK, Secure Integration Server, edgeConnector, edgeAggregator, OPC Suite, and uaGate are affected by a NULL pointer dereference vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-1748](https://github.com/Live-Hack-CVE/CVE-2022-1748) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1748.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1748.svg)


## CVE-2022-1665
 A set of pre-production kernel packages of Red Hat Enterprise Linux for IBM Power architecture can be booted by the grub in Secure Boot mode even though it shouldn't. These kernel builds don't have the secure boot lockdown patches applied to it and can bypass the secure boot validations, allowing the attacker to load another non-trusted code.

- [https://github.com/Live-Hack-CVE/CVE-2022-1665](https://github.com/Live-Hack-CVE/CVE-2022-1665) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1665.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1665.svg)


## CVE-2022-1663
 The Stop Spam Comments WordPress plugin through 0.2.1.2 does not properly generate the Javascript access token for preventing abuse of comment section, allowing threat authors to easily collect the value and add it to the request.

- [https://github.com/Live-Hack-CVE/CVE-2022-1663](https://github.com/Live-Hack-CVE/CVE-2022-1663) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1663.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1663.svg)


## CVE-2022-1513
 A potential vulnerability was reported in Lenovo PCManager prior to version 5.0.10.4191 that may allow code execution when visiting a specially crafted website.

- [https://github.com/Live-Hack-CVE/CVE-2022-1513](https://github.com/Live-Hack-CVE/CVE-2022-1513) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1513.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1513.svg)


## CVE-2022-1486
 Type confusion in V8 in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to obtain potentially sensitive information from process memory via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2022-1486](https://github.com/Live-Hack-CVE/CVE-2022-1486) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1486.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1486.svg)


## CVE-2022-1485
 Use after free in File System API in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2022-1485](https://github.com/Live-Hack-CVE/CVE-2022-1485) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1485.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1485.svg)


## CVE-2022-1484
 Heap buffer overflow in Web UI Settings in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2022-1484](https://github.com/Live-Hack-CVE/CVE-2022-1484) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1484.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1484.svg)


## CVE-2022-1483
 Heap buffer overflow in WebGPU in Google Chrome prior to 101.0.4951.41 allowed a remote attacker who had compromised the renderer process to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2022-1483](https://github.com/Live-Hack-CVE/CVE-2022-1483) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1483.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1483.svg)


## CVE-2022-1482
 Inappropriate implementation in WebGL in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2022-1482](https://github.com/Live-Hack-CVE/CVE-2022-1482) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1482.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1482.svg)


## CVE-2022-1481
 Use after free in Sharing in Google Chrome on Mac prior to 101.0.4951.41 allowed a remote attacker who convinced a user to engage in specific user interaction to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2022-1481](https://github.com/Live-Hack-CVE/CVE-2022-1481) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1481.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1481.svg)


## CVE-2022-1479
 Use after free in ANGLE in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2022-1479](https://github.com/Live-Hack-CVE/CVE-2022-1479) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1479.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1479.svg)


## CVE-2022-1478
 Use after free in SwiftShader in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2022-1478](https://github.com/Live-Hack-CVE/CVE-2022-1478) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1478.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1478.svg)


## CVE-2022-1477
 Use after free in Vulkan in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2022-1477](https://github.com/Live-Hack-CVE/CVE-2022-1477) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1477.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1477.svg)


## CVE-2022-1410
 OS Command Injection vulnerability in the db_optimize component of Device42 Asset Management Appliance allows an authenticated attacker to execute remote code on the device. This issue affects: Device42 CMDB version 18.01.00 and prior versions.

- [https://github.com/Live-Hack-CVE/CVE-2022-1410](https://github.com/Live-Hack-CVE/CVE-2022-1410) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1410.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1410.svg)


## CVE-2022-1400
 Use of Hard-coded Cryptographic Key vulnerability in the WebReportsApi.dll of Exago Web Reports, as used in the Device42 Asset Management Appliance, allows an attacker to leak session IDs and elevate privileges. This issue affects: Device42 CMDB versions prior to 18.01.00.

- [https://github.com/Live-Hack-CVE/CVE-2022-1400](https://github.com/Live-Hack-CVE/CVE-2022-1400) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1400.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1400.svg)


## CVE-2022-1399
 An Argument Injection or Modification vulnerability in the &quot;Change Secret&quot; username field as used in the Discovery component of Device42 CMDB allows a local attacker to run arbitrary code on the appliance with root privileges. This issue affects: Device42 CMDB version 18.01.00 and prior versions.

- [https://github.com/Live-Hack-CVE/CVE-2022-1399](https://github.com/Live-Hack-CVE/CVE-2022-1399) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1399.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1399.svg)


## CVE-2022-1373
 The &#8220;restore configuration&#8221; feature of Softing Secure Integration Server V1.22 is vulnerable to a directory traversal vulnerability when processing zip files. An attacker can craft a zip file to load an arbitrary dll and execute code. Using the &quot;restore configuration&quot; feature to upload a zip file containing a path traversal file may cause a file to be created and executed upon touching the disk.

- [https://github.com/Live-Hack-CVE/CVE-2022-1373](https://github.com/Live-Hack-CVE/CVE-2022-1373) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1373.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1373.svg)


## CVE-2022-1364
 Type confusion in V8 Turbofan in Google Chrome prior to 100.0.4896.127 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2022-1364](https://github.com/Live-Hack-CVE/CVE-2022-1364) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1364.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1364.svg)


## CVE-2022-1340
 Cross-site Scripting (XSS) - Stored in GitHub repository yetiforcecompany/yetiforcecrm prior to 6.4.0.

- [https://github.com/Live-Hack-CVE/CVE-2022-1340](https://github.com/Live-Hack-CVE/CVE-2022-1340) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1340.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1340.svg)


## CVE-2022-1322
 The Coming Soon - Under Construction WordPress plugin through 1.1.9 does not sanitize and escape some of its settings, which could allow high-privileged users to perform Cross-Site Scripting attacks even when unfiltered_html is disallowed

- [https://github.com/Live-Hack-CVE/CVE-2022-1322](https://github.com/Live-Hack-CVE/CVE-2022-1322) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1322.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1322.svg)


## CVE-2022-1314
 Type confusion in V8 in Google Chrome prior to 100.0.4896.88 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2022-1314](https://github.com/Live-Hack-CVE/CVE-2022-1314) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1314.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1314.svg)


## CVE-2022-1313
 Use after free in tab groups in Google Chrome prior to 100.0.4896.88 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2022-1313](https://github.com/Live-Hack-CVE/CVE-2022-1313) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1313.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1313.svg)


## CVE-2022-1312
 Use after free in storage in Google Chrome prior to 100.0.4896.88 allowed an attacker who convinced a user to install a malicious extension to potentially perform a sandbox escape via a crafted Chrome Extension.

- [https://github.com/Live-Hack-CVE/CVE-2022-1312](https://github.com/Live-Hack-CVE/CVE-2022-1312) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1312.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1312.svg)


## CVE-2022-1311
 Use after free in shell in Google Chrome on ChromeOS prior to 100.0.4896.88 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2022-1311](https://github.com/Live-Hack-CVE/CVE-2022-1311) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1311.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1311.svg)


## CVE-2022-1310
 Use after free in regular expressions in Google Chrome prior to 100.0.4896.88 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2022-1310](https://github.com/Live-Hack-CVE/CVE-2022-1310) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1310.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1310.svg)


## CVE-2022-1309
 Insufficient policy enforcement in developer tools in Google Chrome prior to 100.0.4896.88 allowed a remote attacker to potentially perform a sandbox escape via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2022-1309](https://github.com/Live-Hack-CVE/CVE-2022-1309) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1309.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1309.svg)


## CVE-2022-1308
 Use after free in BFCache in Google Chrome prior to 100.0.4896.88 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2022-1308](https://github.com/Live-Hack-CVE/CVE-2022-1308) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1308.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1308.svg)


## CVE-2022-1307
 Inappropriate implementation in full screen in Google Chrome on Android prior to 100.0.4896.88 allowed a remote attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2022-1307](https://github.com/Live-Hack-CVE/CVE-2022-1307) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1307.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1307.svg)


## CVE-2022-1306
 Inappropriate implementation in compositing in Google Chrome prior to 100.0.4896.88 allowed a remote attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2022-1306](https://github.com/Live-Hack-CVE/CVE-2022-1306) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1306.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1306.svg)


## CVE-2022-1305
 Use after free in storage in Google Chrome prior to 100.0.4896.88 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2022-1305](https://github.com/Live-Hack-CVE/CVE-2022-1305) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1305.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1305.svg)


## CVE-2022-1251
 The Ask me WordPress theme before 6.8.4 does not perform nonce checks when processing POST requests to the Edit Profile page, allowing an attacker to trick a user to change their profile information by sending a crafted request.

- [https://github.com/Live-Hack-CVE/CVE-2022-1251](https://github.com/Live-Hack-CVE/CVE-2022-1251) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1251.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1251.svg)


## CVE-2022-1232
 Type confusion in V8 in Google Chrome prior to 100.0.4896.75 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2022-1232](https://github.com/Live-Hack-CVE/CVE-2022-1232) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1232.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1232.svg)


## CVE-2022-1160
 heap buffer overflow in get_one_sourceline in GitHub repository vim/vim prior to 8.2.4647.

- [https://github.com/Live-Hack-CVE/CVE-2022-1160](https://github.com/Live-Hack-CVE/CVE-2022-1160) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1160.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1160.svg)


## CVE-2022-1146
 Inappropriate implementation in Resource Timing in Google Chrome prior to 100.0.4896.60 allowed a remote attacker to leak cross-origin data via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2022-1146](https://github.com/Live-Hack-CVE/CVE-2022-1146) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1146.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1146.svg)


## CVE-2022-1145
 Use after free in Extensions in Google Chrome prior to 100.0.4896.60 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via specific user interaction and profile destruction.

- [https://github.com/Live-Hack-CVE/CVE-2022-1145](https://github.com/Live-Hack-CVE/CVE-2022-1145) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1145.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1145.svg)


## CVE-2022-1144
 Use after free in WebUI in Google Chrome prior to 100.0.4896.60 allowed a remote attacker who convinced a user to engage in specific user interaction to potentially exploit heap corruption via specific input into DevTools.

- [https://github.com/Live-Hack-CVE/CVE-2022-1144](https://github.com/Live-Hack-CVE/CVE-2022-1144) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1144.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1144.svg)


## CVE-2022-1143
 Heap buffer overflow in WebUI in Google Chrome prior to 100.0.4896.60 allowed a remote attacker who convinced a user to engage in specific user interaction to potentially exploit heap corruption via specific input into DevTools.

- [https://github.com/Live-Hack-CVE/CVE-2022-1143](https://github.com/Live-Hack-CVE/CVE-2022-1143) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1143.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1143.svg)


## CVE-2022-1142
 Heap buffer overflow in WebUI in Google Chrome prior to 100.0.4896.60 allowed a remote attacker who convinced a user to engage in specific user interaction to potentially exploit heap corruption via specific input into DevTools.

- [https://github.com/Live-Hack-CVE/CVE-2022-1142](https://github.com/Live-Hack-CVE/CVE-2022-1142) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1142.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1142.svg)


## CVE-2022-1141
 Use after free in File Manager in Google Chrome prior to 100.0.4896.60 allowed a remote attacker who convinced a user to engage in specific user interaction to potentially exploit heap corruption via specific user gesture.

- [https://github.com/Live-Hack-CVE/CVE-2022-1141](https://github.com/Live-Hack-CVE/CVE-2022-1141) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1141.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1141.svg)


## CVE-2022-1123
 The Leaflet Maps Marker (Google Maps, OpenStreetMap, Bing Maps) WordPress plugin before 3.12.5 does not properly sanitize some parameters before inserting them into SQL queries. As a result, high privilege users could perform SQL injection attacks.

- [https://github.com/Live-Hack-CVE/CVE-2022-1123](https://github.com/Live-Hack-CVE/CVE-2022-1123) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1123.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1123.svg)


## CVE-2022-1069
 A crafted HTTP packet with a large content-length header can create a denial-of-service condition in Softing Secure Integration Server V1.22.

- [https://github.com/Live-Hack-CVE/CVE-2022-1069](https://github.com/Live-Hack-CVE/CVE-2022-1069) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1069.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1069.svg)


## CVE-2022-1021
 Insecure Storage of Sensitive Information in GitHub repository chatwoot/chatwoot prior to 2.6.0.

- [https://github.com/Live-Hack-CVE/CVE-2022-1021](https://github.com/Live-Hack-CVE/CVE-2022-1021) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-1021.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-1021.svg)


## CVE-2022-0996
 A vulnerability was found in the 389 Directory Server that allows expired passwords to access the database to cause improper authentication.

- [https://github.com/Live-Hack-CVE/CVE-2022-0996](https://github.com/Live-Hack-CVE/CVE-2022-0996) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-0996.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-0996.svg)


## CVE-2022-0542
 Cross-site Scripting (XSS) - DOM in GitHub repository chatwoot/chatwoot prior to 2.7.0.

- [https://github.com/Live-Hack-CVE/CVE-2022-0542](https://github.com/Live-Hack-CVE/CVE-2022-0542) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-0542.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-0542.svg)


## CVE-2022-0446
 The Simple Banner WordPress plugin before 2.12.0 does not properly sanitize its &quot;Simple Banner Text&quot; Settings allowing high privilege users to perform Cross-Site Scripting attacks even when the unfiltered_html capability is disallowed.

- [https://github.com/Live-Hack-CVE/CVE-2022-0446](https://github.com/Live-Hack-CVE/CVE-2022-0446) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-0446.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-0446.svg)


## CVE-2022-0407
 Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.

- [https://github.com/Live-Hack-CVE/CVE-2022-0407](https://github.com/Live-Hack-CVE/CVE-2022-0407) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-0407.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-0407.svg)


## CVE-2022-0393
 Out-of-bounds Read in GitHub repository vim/vim prior to 8.2.

- [https://github.com/Live-Hack-CVE/CVE-2022-0393](https://github.com/Live-Hack-CVE/CVE-2022-0393) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-0393.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-0393.svg)


## CVE-2022-0207
 A race condition was found in vdsm. Functionality to obfuscate sensitive values in log files that may lead to values being stored in clear text.

- [https://github.com/Live-Hack-CVE/CVE-2022-0207](https://github.com/Live-Hack-CVE/CVE-2022-0207) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-0207.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-0207.svg)


## CVE-2022-0168
 A denial of service (DOS) issue was found in the Linux kernel&#8217;s smb2_ioctl_query_info function in the fs/cifs/smb2ops.c Common Internet File System (CIFS) due to an incorrect return from the memdup_user function. This flaw allows a local, privileged (CAP_SYS_ADMIN) attacker to crash the system.

- [https://github.com/Live-Hack-CVE/CVE-2022-0168](https://github.com/Live-Hack-CVE/CVE-2022-0168) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-0168.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-0168.svg)


## CVE-2022-0158
 vim is vulnerable to Heap-based Buffer Overflow

- [https://github.com/Live-Hack-CVE/CVE-2022-0158](https://github.com/Live-Hack-CVE/CVE-2022-0158) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-0158.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-0158.svg)


## CVE-2022-0156
 vim is vulnerable to Use After Free

- [https://github.com/Live-Hack-CVE/CVE-2022-0156](https://github.com/Live-Hack-CVE/CVE-2022-0156) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-0156.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-0156.svg)


## CVE-2022-0084
 A flaw was found in XNIO, specifically in the notifyReadClosed method. The issue revealed this method was logging a message to another expected end. This flaw allows an attacker to send flawed requests to a server, possibly causing log contention-related performance concerns or an unwanted disk fill-up.

- [https://github.com/Live-Hack-CVE/CVE-2022-0084](https://github.com/Live-Hack-CVE/CVE-2022-0084) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-0084.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-0084.svg)


## CVE-2022-0028
 A PAN-OS URL filtering policy misconfiguration could allow a network-based attacker to conduct reflected and amplified TCP denial-of-service (RDoS) attacks. The DoS attack would appear to originate from a Palo Alto Networks PA-Series (hardware), VM-Series (virtual) and CN-Series (container) firewall against an attacker-specified target. To be misused by an external attacker, the firewall configuration must have a URL filtering profile with one or more blocked categories assigned to a source zone that has an external facing interface. This configuration is not typical for URL filtering and, if set, is likely unintended by the administrator. If exploited, this issue would not impact the confidentiality, integrity, or availability of our products. However, the resulting denial-of-service (DoS) attack may help obfuscate the identity of the attacker and implicate the firewall as the source of the attack. We have taken prompt action to address this issue in our PAN-OS software. All software updates for this issue are expected to be released no later than the week of August 15, 2022. This issue does not impact Panorama M-Series or Panorama virtual appliances. This issue has been resolved for all Cloud NGFW and Prisma Access customers and no additional action is required from them.

- [https://github.com/Live-Hack-CVE/CVE-2022-0028](https://github.com/Live-Hack-CVE/CVE-2022-0028) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-0028.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-0028.svg)


## CVE-2022-0002
 Non-transparent sharing of branch predictor within a context in some Intel(R) Processors may allow an authorized user to potentially enable information disclosure via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-0002](https://github.com/Live-Hack-CVE/CVE-2022-0002) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-0002.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-0002.svg)


## CVE-2022-0001
 Non-transparent sharing of branch predictor selectors between contexts in some Intel(R) Processors may allow an authorized user to potentially enable information disclosure via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-0001](https://github.com/Live-Hack-CVE/CVE-2022-0001) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-0001.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-0001.svg)


## CVE-2021-44856
 An issue was discovered in MediaWiki before 1.35.5, 1.36.x before 1.36.3, and 1.37.x before 1.37.1. A title blocked by AbuseFilter can be created via Special:ChangeContentModel due to the mishandling of the EditFilterMergedContent hook return value.

- [https://github.com/Live-Hack-CVE/CVE-2021-44856](https://github.com/Live-Hack-CVE/CVE-2021-44856) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-44856.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-44856.svg)


## CVE-2021-44758
 Heimdal before 7.7.1 allows attackers to cause a NULL pointer dereference in a SPNEGO acceptor via a preferred_mech_type of GSS_C_NO_OID and a nonzero initial_response value to send_accept.

- [https://github.com/Live-Hack-CVE/CVE-2021-44758](https://github.com/Live-Hack-CVE/CVE-2021-44758) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-44758.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-44758.svg)


## CVE-2021-43395
 An issue was discovered in illumos before f859e7171bb5db34321e45585839c6c3200ebb90, OmniOS Community Edition r151038, OpenIndiana Hipster 2021.04, and SmartOS 20210923. A local unprivileged user can cause a deadlock and kernel panic via crafted rename and rmdir calls on tmpfs filesystems. Oracle Solaris 10 and 11 is also affected.

- [https://github.com/Live-Hack-CVE/CVE-2021-43395](https://github.com/Live-Hack-CVE/CVE-2021-43395) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-43395.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-43395.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/azazelm3dj3d/apache-traversal](https://github.com/azazelm3dj3d/apache-traversal) :  ![starts](https://img.shields.io/github/stars/azazelm3dj3d/apache-traversal.svg) ![forks](https://img.shields.io/github/forks/azazelm3dj3d/apache-traversal.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/azazelm3dj3d/apache-traversal](https://github.com/azazelm3dj3d/apache-traversal) :  ![starts](https://img.shields.io/github/stars/azazelm3dj3d/apache-traversal.svg) ![forks](https://img.shields.io/github/forks/azazelm3dj3d/apache-traversal.svg)


## CVE-2021-39369
 In Philips (formerly Carestream) Vue MyVue PACS through 12.2.x.x, the VideoStream function allows Path Traversal by authenticated users to access files stored outside of the web root.

- [https://github.com/Live-Hack-CVE/CVE-2021-39369](https://github.com/Live-Hack-CVE/CVE-2021-39369) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-39369.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-39369.svg)


## CVE-2021-38561
 golang.org/x/text/language in golang.org/x/text before 0.3.7 can panic with an out-of-bounds read during BCP 47 language tag parsing. Index calculation is mishandled. If parsing untrusted user input, this can be used as a vector for a denial-of-service attack.

- [https://github.com/Live-Hack-CVE/CVE-2021-38561](https://github.com/Live-Hack-CVE/CVE-2021-38561) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-38561.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-38561.svg)


## CVE-2021-35954
 fastrack Reflex 2.0 W307S_REFLEX_v90.89 Activity Tracker allows physically proximate attackers to dump the firmware, flash custom malicious firmware, and brick the device via the Serial Wire Debug (SWD) feature.

- [https://github.com/Live-Hack-CVE/CVE-2021-35954](https://github.com/Live-Hack-CVE/CVE-2021-35954) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-35954.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-35954.svg)


## CVE-2021-35953
 fastrack Reflex 2.0 W307S_REFLEX_v90.89 Activity Tracker allows a Remote attacker to cause a Denial of Service (device outage) via crafted choices of the last three bytes of a characteristic value.

- [https://github.com/Live-Hack-CVE/CVE-2021-35953](https://github.com/Live-Hack-CVE/CVE-2021-35953) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-35953.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-35953.svg)


## CVE-2021-35952
 fastrack Reflex 2.0 W307S_REFLEX_v90.89 Activity Tracker allows a Remote attacker to change the time, date, and month via Bluetooth LE Characteristics on handle 0x0017.

- [https://github.com/Live-Hack-CVE/CVE-2021-35952](https://github.com/Live-Hack-CVE/CVE-2021-35952) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-35952.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-35952.svg)


## CVE-2021-35951
 fastrack Reflex 2.0 W307S_REFLEX_v90.89 Activity Tracker allows an Unauthenticated Remote attacker to send a malicious firmware update via BLE and brick the device.

- [https://github.com/Live-Hack-CVE/CVE-2021-35951](https://github.com/Live-Hack-CVE/CVE-2021-35951) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-35951.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-35951.svg)


## CVE-2021-35065
 The glob-parent package before 6.0.1 for Node.js allows ReDoS (regular expression denial of service) attacks against the enclosure regular expression.

- [https://github.com/Live-Hack-CVE/CVE-2021-35065](https://github.com/Live-Hack-CVE/CVE-2021-35065) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-35065.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-35065.svg)


## CVE-2021-30490
 upsMonitor in ViewPower (aka ViewPowerHTML) 1.04-21012 through 1.04-21353 has insecure permissions for the service binary that enable an Authenticated User to modify files, allowing for privilege escalation.

- [https://github.com/Live-Hack-CVE/CVE-2021-30490](https://github.com/Live-Hack-CVE/CVE-2021-30490) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-30490.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-30490.svg)


## CVE-2021-30070
 An issue was discovered in HestiaCP before v1.3.5. Attackers are able to arbitrarily install packages due to values taken from the pgk [] parameter in the update request being transmitted to the operating system's package manager.

- [https://github.com/Live-Hack-CVE/CVE-2021-30070](https://github.com/Live-Hack-CVE/CVE-2021-30070) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-30070.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-30070.svg)


## CVE-2021-26950
 Out of bounds read in firmware for some Intel(R) Wireless Bluetooth(R) and Killer(TM) Bluetooth(R) products before version 22.120 may allow an authenticated user to potentially enable denial of service via local access.

- [https://github.com/Live-Hack-CVE/CVE-2021-26950](https://github.com/Live-Hack-CVE/CVE-2021-26950) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-26950.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-26950.svg)


## CVE-2021-26254
 Out of bounds read for some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi products may allow a privileged user to potentially enable denial of service via local access.

- [https://github.com/Live-Hack-CVE/CVE-2021-26254](https://github.com/Live-Hack-CVE/CVE-2021-26254) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-26254.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-26254.svg)


## CVE-2021-24119
 In Trusted Firmware Mbed TLS 2.24.0, a side-channel vulnerability in base64 PEM file decoding allows system-level (administrator) attackers to obtain information about secret RSA keys via a controlled-channel and side-channel attack on software running in isolated environments that can be single stepped, especially Intel SGX.

- [https://github.com/Live-Hack-CVE/CVE-2021-24119](https://github.com/Live-Hack-CVE/CVE-2021-24119) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-24119.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-24119.svg)


## CVE-2021-23223
 Improper initialization for some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi products may allow a privileged user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2021-23223](https://github.com/Live-Hack-CVE/CVE-2021-23223) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-23223.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-23223.svg)


## CVE-2021-23188
 Improper access control for some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi products may allow an authenticated user to potentially enable information disclosure via local access.

- [https://github.com/Live-Hack-CVE/CVE-2021-23188](https://github.com/Live-Hack-CVE/CVE-2021-23188) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-23188.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-23188.svg)


## CVE-2021-23168
 Out of bounds read for some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi products may allow an unauthenticated user to potentially enable denial of service via adjacent access.

- [https://github.com/Live-Hack-CVE/CVE-2021-23168](https://github.com/Live-Hack-CVE/CVE-2021-23168) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-23168.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-23168.svg)


## CVE-2021-21062
 Acrobat Reader DC versions versions 2020.013.20074 (and earlier), 2020.001.30018 (and earlier) and 2017.011.30188 (and earlier) are affected by a Memory corruption vulnerability when parsing a specially crafted PDF file. An unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/Live-Hack-CVE/CVE-2021-21062](https://github.com/Live-Hack-CVE/CVE-2021-21062) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-21062.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-21062.svg)


## CVE-2021-21059
 Acrobat Reader DC versions versions 2020.013.20074 (and earlier), 2020.001.30018 (and earlier) and 2017.011.30188 (and earlier) are affected by a Memory corruption vulnerability when parsing a specially crafted PDF file. An unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/Live-Hack-CVE/CVE-2021-21059](https://github.com/Live-Hack-CVE/CVE-2021-21059) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-21059.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-21059.svg)


## CVE-2021-21058
 Acrobat Reader DC versions versions 2020.013.20074 (and earlier), 2020.001.30018 (and earlier) and 2017.011.30188 (and earlier) are affected by a Memory corruption vulnerability when parsing a specially crafted PDF file. An unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/Live-Hack-CVE/CVE-2021-21058](https://github.com/Live-Hack-CVE/CVE-2021-21058) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-21058.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-21058.svg)


## CVE-2021-21048
 Adobe Photoshop versions 21.2.4 (and earlier) and 22.1.1 (and earlier) are affected by a Memory Corruption vulnerability when parsing a specially crafted file. An unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file

- [https://github.com/Live-Hack-CVE/CVE-2021-21048](https://github.com/Live-Hack-CVE/CVE-2021-21048) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-21048.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-21048.svg)


## CVE-2021-21046
 Acrobat Reader DC versions versions 2020.013.20074 (and earlier), 2020.001.30018 (and earlier) and 2017.011.30188 (and earlier) are affected by an memory corruption vulnerability. An unauthenticated attacker could leverage this vulnerability to cause an application denial-of-service. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/Live-Hack-CVE/CVE-2021-21046](https://github.com/Live-Hack-CVE/CVE-2021-21046) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-21046.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-21046.svg)


## CVE-2021-21022
 Magento versions 2.4.1 (and earlier), 2.4.0-p1 (and earlier) and 2.3.6 (and earlier) are vulnerable to an insecure direct object reference (IDOR) in the product module. Successful exploitation could lead to unauthorized access to restricted resources.

- [https://github.com/Live-Hack-CVE/CVE-2021-21022](https://github.com/Live-Hack-CVE/CVE-2021-21022) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-21022.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-21022.svg)


## CVE-2021-21012
 Magento versions 2.4.1 (and earlier), 2.4.0-p1 (and earlier) and 2.3.6 (and earlier) are vulnerable to an insecure direct object vulnerability (IDOR) in the checkout module. Successful exploitation could lead to sensitive information disclosure.

- [https://github.com/Live-Hack-CVE/CVE-2021-21012](https://github.com/Live-Hack-CVE/CVE-2021-21012) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-21012.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-21012.svg)


## CVE-2021-4281
 A vulnerability was found in Brave UX for-the-badge and classified as critical. Affected by this issue is some unknown functionality of the file .github/workflows/combine-prs.yml. The manipulation leads to os command injection. The name of the patch is 55b5a234c0fab935df5fb08365bc8fe9c37cf46b. It is recommended to apply a patch to fix this issue. VDB-216842 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2021-4281](https://github.com/Live-Hack-CVE/CVE-2021-4281) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-4281.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-4281.svg)


## CVE-2021-1585
 A vulnerability in the Cisco Adaptive Security Device Manager (ASDM) Launcher could allow an unauthenticated, remote attacker to execute arbitrary code on a user's operating system. This vulnerability is due to a lack of proper signature verification for specific code exchanged between the ASDM and the Launcher. An attacker could exploit this vulnerability by leveraging a man-in-the-middle position on the network to intercept the traffic between the Launcher and the ASDM and then inject arbitrary code. A successful exploit could allow the attacker to execute arbitrary code on the user's operating system with the level of privileges assigned to the ASDM Launcher. A successful exploit may require the attacker to perform a social engineering attack to persuade the user to initiate communication from the Launcher to the ASDM.

- [https://github.com/Live-Hack-CVE/CVE-2021-1585](https://github.com/Live-Hack-CVE/CVE-2021-1585) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-1585.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-1585.svg)


## CVE-2021-0189
 Use of out-of-range pointer offset in the BIOS firmware for some Intel(R) Processors may allow a privileged user to potentially enable aescalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2021-0189](https://github.com/Live-Hack-CVE/CVE-2021-0189) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-0189.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-0189.svg)


## CVE-2021-0159
 Improper input validation in the BIOS authenticated code module for some Intel(R) Processors may allow a privileged user to potentially enable aescalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2021-0159](https://github.com/Live-Hack-CVE/CVE-2021-0159) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-0159.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-0159.svg)


## CVE-2021-0155
 Unchecked return value in the BIOS firmware for some Intel(R) Processors may allow a privileged user to potentially enable information disclosure via local access.

- [https://github.com/Live-Hack-CVE/CVE-2021-0155](https://github.com/Live-Hack-CVE/CVE-2021-0155) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-0155.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-0155.svg)


## CVE-2021-0154
 Improper input validation in the BIOS firmware for some Intel(R) Processors may allow a privileged user to potentially enable aescalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2021-0154](https://github.com/Live-Hack-CVE/CVE-2021-0154) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-0154.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-0154.svg)


## CVE-2021-0153
 Out-of-bounds write in the BIOS firmware for some Intel(R) Processors may allow a privileged user to potentially enable aescalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2021-0153](https://github.com/Live-Hack-CVE/CVE-2021-0153) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-0153.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-0153.svg)


## CVE-2020-28191
 The console in Togglz before 2.9.4 allows CSRF.

- [https://github.com/Live-Hack-CVE/CVE-2020-28191](https://github.com/Live-Hack-CVE/CVE-2020-28191) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-28191.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-28191.svg)


## CVE-2020-24600
 Shilpi CAPExWeb 1.1 allows SQL injection via a servlet/capexweb.cap_sendMail GET request.

- [https://github.com/Live-Hack-CVE/CVE-2020-24600](https://github.com/Live-Hack-CVE/CVE-2020-24600) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-24600.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-24600.svg)


## CVE-2020-12069
 In Pilz PMC programming tool 3.x before 3.5.17 (based on CODESYS Development System), the password-hashing feature requires insufficient computational effort.

- [https://github.com/Live-Hack-CVE/CVE-2020-12069](https://github.com/Live-Hack-CVE/CVE-2020-12069) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-12069.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-12069.svg)


## CVE-2020-12067
 In Pilz PMC programming tool 3.x before 3.5.17 (based on CODESYS Development System), a user's password may be changed by an attacker without knowledge of the current password.

- [https://github.com/Live-Hack-CVE/CVE-2020-12067](https://github.com/Live-Hack-CVE/CVE-2020-12067) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-12067.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-12067.svg)


## CVE-2020-11101
 Sierra Wireless AirLink Mobility Manager (AMM) before 2.17 mishandles sessions and thus an unauthenticated attacker can obtain a login session with administrator privileges.

- [https://github.com/Live-Hack-CVE/CVE-2020-11101](https://github.com/Live-Hack-CVE/CVE-2020-11101) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-11101.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-11101.svg)


## CVE-2020-10650
 A deserialization flaw was discovered in jackson-databind through 2.9.10.4. It could allow an unauthenticated user to perform code execution via ignite-jta or quartz-core: org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup, org.apache.ignite.cache.jta.jndi.CacheJndiTmFactory, and org.quartz.utils.JNDIConnectionProvider.

- [https://github.com/Live-Hack-CVE/CVE-2020-10650](https://github.com/Live-Hack-CVE/CVE-2020-10650) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-10650.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-10650.svg)


## CVE-2019-25085
 A vulnerability was found in GNOME gvdb. It has been classified as critical. This affects the function gvdb_table_write_contents_async of the file gvdb-builder.c. The manipulation leads to use after free. It is possible to initiate the attack remotely. The name of the patch is d83587b2a364eb9a9a53be7e6a708074e252de14. It is recommended to apply a patch to fix this issue. The identifier VDB-216789 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2019-25085](https://github.com/Live-Hack-CVE/CVE-2019-25085) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-25085.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-25085.svg)


## CVE-2019-19705
 Realtek Audio Drivers for Windows, as used on the Lenovo ThinkPad X1 Carbon 20A7, 20A8, 20BS, and 20BT before 6.0.8882.1 and 20KH and 20KG before 6.0.8907.1 (and on many other Lenovo and non-Lenovo products), mishandles DLL preloading.

- [https://github.com/Live-Hack-CVE/CVE-2019-19705](https://github.com/Live-Hack-CVE/CVE-2019-19705) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-19705.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-19705.svg)


## CVE-2019-19030
 Cloud Native Computing Foundation Harbor before 1.10.3 and 2.x before 2.0.1 allows resource enumeration because unauthenticated API calls reveal (via the HTTP status code) whether a resource exists.

- [https://github.com/Live-Hack-CVE/CVE-2019-19030](https://github.com/Live-Hack-CVE/CVE-2019-19030) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-19030.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-19030.svg)


## CVE-2019-18177
 In certain Citrix products, information disclosure can be achieved by an authenticated VPN user when there is a configured SSL VPN endpoint. This affects Citrix ADC and Citrix Gateway 13.0-58.30 and later releases before the CTX276688 update.

- [https://github.com/Live-Hack-CVE/CVE-2019-18177](https://github.com/Live-Hack-CVE/CVE-2019-18177) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-18177.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-18177.svg)


## CVE-2019-14802
 HashiCorp Nomad 0.5.0 through 0.9.4 (fixed in 0.9.5) reveals unintended environment variables to the rendering task during template rendering, aka GHSA-6hv3-7c34-4hx8. This applies to nomad/client/allocrunner/taskrunner/template.

- [https://github.com/Live-Hack-CVE/CVE-2019-14802](https://github.com/Live-Hack-CVE/CVE-2019-14802) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-14802.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-14802.svg)


## CVE-2019-13988
 Sierra Wireless MGOS before 3.15.2 and 4.x before 4.3 allows attackers to read log files via a Direct Request (aka Forced Browsing).

- [https://github.com/Live-Hack-CVE/CVE-2019-13988](https://github.com/Live-Hack-CVE/CVE-2019-13988) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-13988.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-13988.svg)


## CVE-2019-11851
 The ACENet service in Sierra Wireless ALEOS before 4.4.9, 4.5.x through 4.9.x before 4.9.5, and 4.10.x through 4.13.x before 4.14.0 allows remote attackers to execute arbitrary code via a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2019-11851](https://github.com/Live-Hack-CVE/CVE-2019-11851) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-11851.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-11851.svg)


## CVE-2019-9579
 An issue was discovered in Illumos in Nexenta NexentaStor 4.0.5 and 5.1.2, and other products. The SMB server allows an attacker to have unintended access, e.g., an attacker with WRITE_XATTR can change permissions. This occurs because of a combination of three factors: ZFS extended attributes are used to implement NT named streams, the SMB protocol requires implementations to have open handle semantics similar to those of NTFS, and the SMB server passes along certain attribute requests to the underlying object (i.e., they are not considered to be requests that pertain to the named stream).

- [https://github.com/Live-Hack-CVE/CVE-2019-9579](https://github.com/Live-Hack-CVE/CVE-2019-9579) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-9579.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-9579.svg)


## CVE-2019-9011
 In Pilz PMC programming tool 3.x before 3.5.17 (based on CODESYS Development System), an attacker can identify valid usernames.

- [https://github.com/Live-Hack-CVE/CVE-2019-9011](https://github.com/Live-Hack-CVE/CVE-2019-9011) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-9011.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-9011.svg)


## CVE-2018-16135
 The Opera Mini application 47.1.2249.129326 for Android allows remote attackers to spoof the Location Permission dialog via a crafted web site.

- [https://github.com/Live-Hack-CVE/CVE-2018-16135](https://github.com/Live-Hack-CVE/CVE-2018-16135) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-16135.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-16135.svg)


## CVE-2016-20018
 Knex Knex.js through 2.3.0 has a limited SQL injection vulnerability that can be exploited to ignore the WHERE clause of a SQL query.

- [https://github.com/Live-Hack-CVE/CVE-2016-20018](https://github.com/Live-Hack-CVE/CVE-2016-20018) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-20018.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-20018.svg)


## CVE-2016-9054
 An exploitable stack-based buffer overflow vulnerability exists in the querying functionality of Aerospike Database Server 3.10.0.3. A specially crafted packet can cause a stack-based buffer overflow in the function as_sindex__simatch_list_by_set_binid resulting in remote code execution. An attacker can simply connect to the port to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2016-9054](https://github.com/Live-Hack-CVE/CVE-2016-9054) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-9054.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-9054.svg)


## CVE-2016-9048
 Multiple exploitable SQL Injection vulnerabilities exists in ProcessMaker Enterprise Core 3.0.1.7-community. Specially crafted web requests can cause SQL injections. An attacker can send a web request with parameters containing SQL injection attacks to trigger this vulnerability, potentially allowing exfiltration of the database, user credentials and in certain setups access the underlying operating system.

- [https://github.com/Live-Hack-CVE/CVE-2016-9048](https://github.com/Live-Hack-CVE/CVE-2016-9048) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-9048.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-9048.svg)


## CVE-2016-9045
 A code execution vulnerability exists in ProcessMaker Enterprise Core 3.0.1.7-community. A specially crafted web request can cause unsafe deserialization potentially resulting in PHP code being executed. An attacker can send a crafted web parameter to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2016-9045](https://github.com/Live-Hack-CVE/CVE-2016-9045) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-9045.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-9045.svg)


## CVE-2016-9044
 An exploitable command execution vulnerability exists in Information Builders WebFOCUS Business Intelligence Portal 8.1 . A specially crafted web parameter can cause a command injection. An authenticated attacker can send a crafted web request to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2016-9044](https://github.com/Live-Hack-CVE/CVE-2016-9044) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-9044.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-9044.svg)


## CVE-2016-9043
 An out of bound write vulnerability exists in the EMF parsing functionality of CorelDRAW X8 (CdrGfx - Corel Graphics Engine (64-Bit) - 18.1.0.661). A specially crafted EMF file can cause a vulnerability resulting in potential code execution. An attacker can send the victim a specific EMF file to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2016-9043](https://github.com/Live-Hack-CVE/CVE-2016-9043) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-9043.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-9043.svg)


## CVE-2016-9040
 An exploitable denial of service exists in the the Joyent SmartOS OS 20161110T013148Z Hyprlofs file system. The vulnerability is present in the Ioctl system call with the command HYPRLOFSADDENTRIES when used with a 32 bit model. An attacker can cause a buffer to be allocated and never freed. When repeatedly exploit this will result in memory exhaustion, resulting in a full system denial of service.

- [https://github.com/Live-Hack-CVE/CVE-2016-9040](https://github.com/Live-Hack-CVE/CVE-2016-9040) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-9040.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-9040.svg)


## CVE-2016-8732
 Multiple security flaws exists in InvProtectDrv.sys which is a part of Invincea Dell Protected Workspace 5.1.1-22303. Weak restrictions on the driver communication channel and additional insufficient checks allow any application to turn off some of the protection mechanisms provided by the Invincea product.

- [https://github.com/Live-Hack-CVE/CVE-2016-8732](https://github.com/Live-Hack-CVE/CVE-2016-8732) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-8732.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-8732.svg)


## CVE-2016-8731
 Hard-coded FTP credentials (r:r) are included in the Foscam C1 running firmware 1.9.1.12. Knowledge of these credentials would allow remote access to any cameras found on the internet that do not have port 50021 blocked by an intermediate device.

- [https://github.com/Live-Hack-CVE/CVE-2016-8731](https://github.com/Live-Hack-CVE/CVE-2016-8731) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-8731.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-8731.svg)


## CVE-2016-8722
 An exploitable Information Disclosure vulnerability exists in the Web Application functionality of Moxa AWK-3131A Series Industrial IEEE 802.11a/b/g/n wireless AP/bridge/client. Retrieving a specific URL without authentication can reveal sensitive information to an attacker.

- [https://github.com/Live-Hack-CVE/CVE-2016-8722](https://github.com/Live-Hack-CVE/CVE-2016-8722) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-8722.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-8722.svg)


## CVE-2016-8717
 An exploitable Use of Hard-coded Credentials vulnerability exists in the Moxa AWK-3131A Wireless Access Point running firmware 1.1. The device operating system contains an undocumented, privileged (root) account with hard-coded credentials, giving attackers full control of affected devices.

- [https://github.com/Live-Hack-CVE/CVE-2016-8717](https://github.com/Live-Hack-CVE/CVE-2016-8717) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-8717.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-8717.svg)


## CVE-2016-8716
 An exploitable Cleartext Transmission of Password vulnerability exists in the Web Application functionality of Moxa AWK-3131A Wireless Access Point running firmware 1.1. The Change Password functionality of the Web Application transmits the password in cleartext. An attacker capable of intercepting this traffic is able to obtain valid credentials.

- [https://github.com/Live-Hack-CVE/CVE-2016-8716](https://github.com/Live-Hack-CVE/CVE-2016-8716) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-8716.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-8716.svg)


## CVE-2016-8715
 An exploitable heap corruption vulnerability exists in the loadTrailer functionality of Iceni Argus version 6.6.05. A specially crafted PDF file can cause a heap corruption resulting in arbitrary code execution. An attacker can send/provide a malicious PDF file to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2016-8715](https://github.com/Live-Hack-CVE/CVE-2016-8715) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-8715.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-8715.svg)


## CVE-2016-8714
 An exploitable buffer overflow vulnerability exists in the LoadEncoding functionality of the R programming language version 3.3.0. A specially crafted R script can cause a buffer overflow resulting in a memory corruption. An attacker can send a malicious R script to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2016-8714](https://github.com/Live-Hack-CVE/CVE-2016-8714) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-8714.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-8714.svg)


## CVE-2016-6923
 Use-after-free vulnerability in Adobe Flash Player before 18.0.0.375 and 19.x through 23.x before 23.0.0.162 on Windows and OS X and before 11.2.202.635 on Linux allows attackers to execute arbitrary code via unspecified vectors, a different vulnerability than CVE-2016-4272, CVE-2016-4279, CVE-2016-6921, CVE-2016-6925, CVE-2016-6926, CVE-2016-6927, CVE-2016-6929, CVE-2016-6930, CVE-2016-6931, and CVE-2016-6932.

- [https://github.com/Live-Hack-CVE/CVE-2016-6931](https://github.com/Live-Hack-CVE/CVE-2016-6931) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-6931.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-6931.svg)


## CVE-2016-6921
 Use-after-free vulnerability in Adobe Flash Player before 18.0.0.375 and 19.x through 23.x before 23.0.0.162 on Windows and OS X and before 11.2.202.635 on Linux allows attackers to execute arbitrary code via unspecified vectors, a different vulnerability than CVE-2016-4272, CVE-2016-4279, CVE-2016-6923, CVE-2016-6925, CVE-2016-6926, CVE-2016-6927, CVE-2016-6929, CVE-2016-6930, CVE-2016-6931, and CVE-2016-6932.

- [https://github.com/Live-Hack-CVE/CVE-2016-6931](https://github.com/Live-Hack-CVE/CVE-2016-6931) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-6931.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-6931.svg)


## CVE-2016-6191
 Multiple cross-site scripting (XSS) vulnerabilities in the View Raw Source page in the Web Calendar in SOGo before 3.1.3 allow remote attackers to inject arbitrary web script or HTML via the (1) Description, (2) Location, (3) URL, or (4) Title field.

- [https://github.com/Live-Hack-CVE/CVE-2016-6191](https://github.com/Live-Hack-CVE/CVE-2016-6191) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-6191.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-6191.svg)


## CVE-2016-6189
 Incomplete blacklist in SOGo before 2.3.12 and 3.x before 3.1.1 allows remote authenticated users to obtain sensitive information by reading the fields in the (1) ics or (2) XML calendar feeds.

- [https://github.com/Live-Hack-CVE/CVE-2016-6189](https://github.com/Live-Hack-CVE/CVE-2016-6189) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-6189.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-6189.svg)


## CVE-2016-6188
 Memory leak in SOGo 2.3.7 allows remote attackers to cause a denial of service (memory consumption) via a large number of attempts to upload a large attachment, related to temporary files.

- [https://github.com/Live-Hack-CVE/CVE-2016-6188](https://github.com/Live-Hack-CVE/CVE-2016-6188) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-6188.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-6188.svg)


## CVE-2016-4279
 Use-after-free vulnerability in Adobe Flash Player before 18.0.0.375 and 19.x through 23.x before 23.0.0.162 on Windows and OS X and before 11.2.202.635 on Linux allows attackers to execute arbitrary code via unspecified vectors, a different vulnerability than CVE-2016-4272, CVE-2016-6921, CVE-2016-6923, CVE-2016-6925, CVE-2016-6926, CVE-2016-6927, CVE-2016-6929, CVE-2016-6930, CVE-2016-6931, and CVE-2016-6932.

- [https://github.com/Live-Hack-CVE/CVE-2016-6931](https://github.com/Live-Hack-CVE/CVE-2016-6931) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-6931.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-6931.svg)


## CVE-2016-4277
 Adobe Flash Player before 18.0.0.375 and 19.x through 23.x before 23.0.0.162 on Windows and OS X and before 11.2.202.635 on Linux allows attackers to bypass intended access restrictions and obtain sensitive information via unspecified vectors, a different vulnerability than CVE-2016-4271 and CVE-2016-4278.

- [https://github.com/Live-Hack-CVE/CVE-2016-4278](https://github.com/Live-Hack-CVE/CVE-2016-4278) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4278.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4278.svg)


## CVE-2016-4272
 Use-after-free vulnerability in Adobe Flash Player before 18.0.0.375 and 19.x through 23.x before 23.0.0.162 on Windows and OS X and before 11.2.202.635 on Linux allows attackers to execute arbitrary code via unspecified vectors, a different vulnerability than CVE-2016-4279, CVE-2016-6921, CVE-2016-6923, CVE-2016-6925, CVE-2016-6926, CVE-2016-6927, CVE-2016-6929, CVE-2016-6930, CVE-2016-6931, and CVE-2016-6932.

- [https://github.com/Live-Hack-CVE/CVE-2016-6931](https://github.com/Live-Hack-CVE/CVE-2016-6931) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-6931.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-6931.svg)


## CVE-2016-4271
 Adobe Flash Player before 18.0.0.375 and 19.x through 23.x before 23.0.0.162 on Windows and OS X and before 11.2.202.635 on Linux allows attackers to bypass intended access restrictions and obtain sensitive information via unspecified vectors, a different vulnerability than CVE-2016-4277 and CVE-2016-4278, aka a &quot;local-with-filesystem Flash sandbox bypass&quot; issue.

- [https://github.com/Live-Hack-CVE/CVE-2016-4278](https://github.com/Live-Hack-CVE/CVE-2016-4278) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4278.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4278.svg)


## CVE-2016-4163
 Adobe Flash Player before 18.0.0.352 and 19.x through 21.x before 21.0.0.242 on Windows and OS X and before 11.2.202.621 on Linux allows attackers to execute arbitrary code or cause a denial of service (memory corruption) via unspecified vectors, a different vulnerability than CVE-2016-1096, CVE-2016-1098, CVE-2016-1099, CVE-2016-1100, CVE-2016-1102, CVE-2016-1104, CVE-2016-4109, CVE-2016-4111, CVE-2016-4112, CVE-2016-4113, CVE-2016-4114, CVE-2016-4115, CVE-2016-4120, CVE-2016-4160, CVE-2016-4161, and CVE-2016-4162.

- [https://github.com/Live-Hack-CVE/CVE-2016-4163](https://github.com/Live-Hack-CVE/CVE-2016-4163) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4163.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4163.svg)


## CVE-2016-4161
 Adobe Flash Player before 18.0.0.352 and 19.x through 21.x before 21.0.0.242 on Windows and OS X and before 11.2.202.621 on Linux allows attackers to execute arbitrary code or cause a denial of service (memory corruption) via unspecified vectors, a different vulnerability than CVE-2016-1096, CVE-2016-1098, CVE-2016-1099, CVE-2016-1100, CVE-2016-1102, CVE-2016-1104, CVE-2016-4109, CVE-2016-4111, CVE-2016-4112, CVE-2016-4113, CVE-2016-4114, CVE-2016-4115, CVE-2016-4120, CVE-2016-4160, CVE-2016-4162, and CVE-2016-4163.

- [https://github.com/Live-Hack-CVE/CVE-2016-4161](https://github.com/Live-Hack-CVE/CVE-2016-4161) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4161.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4161.svg)


## CVE-2016-4160
 Adobe Flash Player before 18.0.0.352 and 19.x through 21.x before 21.0.0.242 on Windows and OS X and before 11.2.202.621 on Linux allows attackers to execute arbitrary code or cause a denial of service (memory corruption) via unspecified vectors, a different vulnerability than CVE-2016-1096, CVE-2016-1098, CVE-2016-1099, CVE-2016-1100, CVE-2016-1102, CVE-2016-1104, CVE-2016-4109, CVE-2016-4111, CVE-2016-4112, CVE-2016-4113, CVE-2016-4114, CVE-2016-4115, CVE-2016-4120, CVE-2016-4161, CVE-2016-4162, and CVE-2016-4163.

- [https://github.com/Live-Hack-CVE/CVE-2016-4160](https://github.com/Live-Hack-CVE/CVE-2016-4160) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4160.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4160.svg)


## CVE-2016-4120
 Adobe Flash Player before 18.0.0.352 and 19.x through 21.x before 21.0.0.242 on Windows and OS X and before 11.2.202.621 on Linux allows attackers to execute arbitrary code or cause a denial of service (memory corruption) via unspecified vectors, a different vulnerability than CVE-2016-1096, CVE-2016-1098, CVE-2016-1099, CVE-2016-1100, CVE-2016-1102, CVE-2016-1104, CVE-2016-4109, CVE-2016-4111, CVE-2016-4112, CVE-2016-4113, CVE-2016-4114, CVE-2016-4115, CVE-2016-4160, CVE-2016-4161, CVE-2016-4162, and CVE-2016-4163.

- [https://github.com/Live-Hack-CVE/CVE-2016-4120](https://github.com/Live-Hack-CVE/CVE-2016-4120) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4120.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4120.svg)


## CVE-2016-1098
 Unspecified vulnerability in Adobe Flash Player 21.0.0.213 and earlier, as used in the Adobe Flash libraries in Microsoft Internet Explorer 10 and 11 and Microsoft Edge, has unknown impact and attack vectors, a different vulnerability than other CVEs listed in MS16-064.

- [https://github.com/Live-Hack-CVE/CVE-2016-4160](https://github.com/Live-Hack-CVE/CVE-2016-4160) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4160.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4160.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4120](https://github.com/Live-Hack-CVE/CVE-2016-4120) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4120.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4120.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4163](https://github.com/Live-Hack-CVE/CVE-2016-4163) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4163.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4163.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4161](https://github.com/Live-Hack-CVE/CVE-2016-4161) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4161.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4161.svg)


## CVE-2016-1096
 Unspecified vulnerability in Adobe Flash Player 21.0.0.213 and earlier, as used in the Adobe Flash libraries in Microsoft Internet Explorer 10 and 11 and Microsoft Edge, has unknown impact and attack vectors, a different vulnerability than other CVEs listed in MS16-064.

- [https://github.com/Live-Hack-CVE/CVE-2016-4120](https://github.com/Live-Hack-CVE/CVE-2016-4120) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4120.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4120.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4160](https://github.com/Live-Hack-CVE/CVE-2016-4160) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4160.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4160.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4163](https://github.com/Live-Hack-CVE/CVE-2016-4163) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4163.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4163.svg)
- [https://github.com/Live-Hack-CVE/CVE-2016-4161](https://github.com/Live-Hack-CVE/CVE-2016-4161) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-4161.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-4161.svg)


## CVE-2016-1010
 Integer overflow in Adobe Flash Player before 18.0.0.333 and 19.x through 21.x before 21.0.0.182 on Windows and OS X and before 11.2.202.577 on Linux, Adobe AIR before 21.0.0.176, Adobe AIR SDK before 21.0.0.176, and Adobe AIR SDK &amp; Compiler before 21.0.0.176 allows attackers to execute arbitrary code via unspecified vectors, a different vulnerability than CVE-2016-0963 and CVE-2016-0993.

- [https://github.com/Live-Hack-CVE/CVE-2016-1010](https://github.com/Live-Hack-CVE/CVE-2016-1010) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-1010.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-1010.svg)


## CVE-2016-1005
 Adobe Flash Player before 18.0.0.333 and 19.x through 21.x before 21.0.0.182 on Windows and OS X and before 11.2.202.577 on Linux, Adobe AIR before 21.0.0.176, Adobe AIR SDK before 21.0.0.176, and Adobe AIR SDK &amp; Compiler before 21.0.0.176 allow attackers to execute arbitrary code or cause a denial of service (uninitialized pointer dereference and memory corruption) via crafted MPEG-4 data, a different vulnerability than CVE-2016-0960, CVE-2016-0961, CVE-2016-0962, CVE-2016-0986, CVE-2016-0989, CVE-2016-0992, and CVE-2016-1002.

- [https://github.com/Live-Hack-CVE/CVE-2016-1005](https://github.com/Live-Hack-CVE/CVE-2016-1005) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-1005.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-1005.svg)


## CVE-2016-1001
 Heap-based buffer overflow in Adobe Flash Player before 18.0.0.333 and 19.x through 21.x before 21.0.0.182 on Windows and OS X and before 11.2.202.577 on Linux, Adobe AIR before 21.0.0.176, Adobe AIR SDK before 21.0.0.176, and Adobe AIR SDK &amp; Compiler before 21.0.0.176 allows attackers to execute arbitrary code via unspecified vectors.

- [https://github.com/Live-Hack-CVE/CVE-2016-1001](https://github.com/Live-Hack-CVE/CVE-2016-1001) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-1001.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-1001.svg)


## CVE-2016-1000
 Use-after-free vulnerability in Adobe Flash Player before 18.0.0.333 and 19.x through 21.x before 21.0.0.182 on Windows and OS X and before 11.2.202.577 on Linux, Adobe AIR before 21.0.0.176, Adobe AIR SDK before 21.0.0.176, and Adobe AIR SDK &amp; Compiler before 21.0.0.176 allows attackers to execute arbitrary code via unspecified vectors, a different vulnerability than CVE-2016-0987, CVE-2016-0988, CVE-2016-0990, CVE-2016-0991, CVE-2016-0994, CVE-2016-0995, CVE-2016-0996, CVE-2016-0997, CVE-2016-0998, and CVE-2016-0999.

- [https://github.com/Live-Hack-CVE/CVE-2016-1000](https://github.com/Live-Hack-CVE/CVE-2016-1000) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-1000.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-1000.svg)


## CVE-2016-0998
 Use-after-free vulnerability in Adobe Flash Player before 18.0.0.333 and 19.x through 21.x before 21.0.0.182 on Windows and OS X and before 11.2.202.577 on Linux, Adobe AIR before 21.0.0.176, Adobe AIR SDK before 21.0.0.176, and Adobe AIR SDK &amp; Compiler before 21.0.0.176 allows attackers to execute arbitrary code via unspecified vectors, a different vulnerability than CVE-2016-0987, CVE-2016-0988, CVE-2016-0990, CVE-2016-0991, CVE-2016-0994, CVE-2016-0995, CVE-2016-0996, CVE-2016-0997, CVE-2016-0999, and CVE-2016-1000.

- [https://github.com/Live-Hack-CVE/CVE-2016-0998](https://github.com/Live-Hack-CVE/CVE-2016-0998) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-0998.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-0998.svg)


## CVE-2016-0997
 Use-after-free vulnerability in Adobe Flash Player before 18.0.0.333 and 19.x through 21.x before 21.0.0.182 on Windows and OS X and before 11.2.202.577 on Linux, Adobe AIR before 21.0.0.176, Adobe AIR SDK before 21.0.0.176, and Adobe AIR SDK &amp; Compiler before 21.0.0.176 allows attackers to execute arbitrary code via unspecified vectors, a different vulnerability than CVE-2016-0987, CVE-2016-0988, CVE-2016-0990, CVE-2016-0991, CVE-2016-0994, CVE-2016-0995, CVE-2016-0996, CVE-2016-0998, CVE-2016-0999, and CVE-2016-1000.

- [https://github.com/Live-Hack-CVE/CVE-2016-0997](https://github.com/Live-Hack-CVE/CVE-2016-0997) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-0997.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-0997.svg)


## CVE-2016-0996
 Use-after-free vulnerability in the setInterval method in Adobe Flash Player before 18.0.0.333 and 19.x through 21.x before 21.0.0.182 on Windows and OS X and before 11.2.202.577 on Linux, Adobe AIR before 21.0.0.176, Adobe AIR SDK before 21.0.0.176, and Adobe AIR SDK &amp; Compiler before 21.0.0.176 allows attackers to execute arbitrary code via crafted arguments, a different vulnerability than CVE-2016-0987, CVE-2016-0988, CVE-2016-0990, CVE-2016-0991, CVE-2016-0994, CVE-2016-0995, CVE-2016-0997, CVE-2016-0998, CVE-2016-0999, and CVE-2016-1000.

- [https://github.com/Live-Hack-CVE/CVE-2016-0996](https://github.com/Live-Hack-CVE/CVE-2016-0996) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-0996.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-0996.svg)


## CVE-2016-0992
 Adobe Flash Player before 18.0.0.333 and 19.x through 21.x before 21.0.0.182 on Windows and OS X and before 11.2.202.577 on Linux, Adobe AIR before 21.0.0.176, Adobe AIR SDK before 21.0.0.176, and Adobe AIR SDK &amp; Compiler before 21.0.0.176 allow attackers to execute arbitrary code or cause a denial of service (memory corruption) via unspecified vectors, a different vulnerability than CVE-2016-0960, CVE-2016-0961, CVE-2016-0962, CVE-2016-0986, CVE-2016-0989, CVE-2016-1002, and CVE-2016-1005.

- [https://github.com/Live-Hack-CVE/CVE-2016-0992](https://github.com/Live-Hack-CVE/CVE-2016-0992) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-0992.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-0992.svg)


## CVE-2016-0990
 Use-after-free vulnerability in Adobe Flash Player before 18.0.0.333 and 19.x through 21.x before 21.0.0.182 on Windows and OS X and before 11.2.202.577 on Linux, Adobe AIR before 21.0.0.176, Adobe AIR SDK before 21.0.0.176, and Adobe AIR SDK &amp; Compiler before 21.0.0.176 allows attackers to execute arbitrary code via unspecified vectors, a different vulnerability than CVE-2016-0987, CVE-2016-0988, CVE-2016-0991, CVE-2016-0994, CVE-2016-0995, CVE-2016-0996, CVE-2016-0997, CVE-2016-0998, CVE-2016-0999, and CVE-2016-1000.

- [https://github.com/Live-Hack-CVE/CVE-2016-0990](https://github.com/Live-Hack-CVE/CVE-2016-0990) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-0990.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-0990.svg)


## CVE-2016-0986
 Adobe Flash Player before 18.0.0.333 and 19.x through 21.x before 21.0.0.182 on Windows and OS X and before 11.2.202.577 on Linux, Adobe AIR before 21.0.0.176, Adobe AIR SDK before 21.0.0.176, and Adobe AIR SDK &amp; Compiler before 21.0.0.176 allow attackers to execute arbitrary code or cause a denial of service (memory corruption) via unspecified vectors, a different vulnerability than CVE-2016-0960, CVE-2016-0961, CVE-2016-0962, CVE-2016-0989, CVE-2016-0992, CVE-2016-1002, and CVE-2016-1005.

- [https://github.com/Live-Hack-CVE/CVE-2016-0986](https://github.com/Live-Hack-CVE/CVE-2016-0986) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-0986.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-0986.svg)


## CVE-2016-0962
 Adobe Flash Player before 18.0.0.333 and 19.x through 21.x before 21.0.0.182 on Windows and OS X and before 11.2.202.577 on Linux, Adobe AIR before 21.0.0.176, Adobe AIR SDK before 21.0.0.176, and Adobe AIR SDK &amp; Compiler before 21.0.0.176 allow attackers to execute arbitrary code or cause a denial of service (memory corruption) via unspecified vectors, a different vulnerability than CVE-2016-0960, CVE-2016-0961, CVE-2016-0986, CVE-2016-0989, CVE-2016-0992, CVE-2016-1002, and CVE-2016-1005.

- [https://github.com/Live-Hack-CVE/CVE-2016-0962](https://github.com/Live-Hack-CVE/CVE-2016-0962) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-0962.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-0962.svg)


## CVE-2016-0961
 Adobe Flash Player before 18.0.0.333 and 19.x through 21.x before 21.0.0.182 on Windows and OS X and before 11.2.202.577 on Linux, Adobe AIR before 21.0.0.176, Adobe AIR SDK before 21.0.0.176, and Adobe AIR SDK &amp; Compiler before 21.0.0.176 allow attackers to execute arbitrary code or cause a denial of service (memory corruption) via unspecified vectors, a different vulnerability than CVE-2016-0960, CVE-2016-0962, CVE-2016-0986, CVE-2016-0989, CVE-2016-0992, CVE-2016-1002, and CVE-2016-1005.

- [https://github.com/Live-Hack-CVE/CVE-2016-0961](https://github.com/Live-Hack-CVE/CVE-2016-0961) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-0961.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-0961.svg)


## CVE-2016-0960
 Adobe Flash Player before 18.0.0.333 and 19.x through 21.x before 21.0.0.182 on Windows and OS X and before 11.2.202.577 on Linux, Adobe AIR before 21.0.0.176, Adobe AIR SDK before 21.0.0.176, and Adobe AIR SDK &amp; Compiler before 21.0.0.176 allow attackers to execute arbitrary code or cause a denial of service (memory corruption) via unspecified vectors, a different vulnerability than CVE-2016-0961, CVE-2016-0962, CVE-2016-0986, CVE-2016-0989, CVE-2016-0992, CVE-2016-1002, and CVE-2016-1005.

- [https://github.com/Live-Hack-CVE/CVE-2016-0960](https://github.com/Live-Hack-CVE/CVE-2016-0960) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-0960.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-0960.svg)


## CVE-2015-10005
 A vulnerability was found in markdown-it up to 2.x. It has been classified as problematic. Affected is an unknown function of the file lib/common/html_re.js. The manipulation leads to inefficient regular expression complexity. Upgrading to version 3.0.0 is able to address this issue. The name of the patch is 89c8620157d6e38f9872811620d25138fc9d1b0d. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-216852.

- [https://github.com/Live-Hack-CVE/CVE-2015-10005](https://github.com/Live-Hack-CVE/CVE-2015-10005) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10005.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10005.svg)


## CVE-2015-5395
 Cross-site request forgery (CSRF) vulnerability in SOGo before 3.1.0.

- [https://github.com/Live-Hack-CVE/CVE-2015-5395](https://github.com/Live-Hack-CVE/CVE-2015-5395) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-5395.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-5395.svg)


## CVE-2014-9905
 Multiple cross-site scripting (XSS) vulnerabilities in the Web Calendar in SOGo before 2.2.0 allow remote attackers to inject arbitrary web script or HTML via the (1) title of an appointment or (2) contact fields.

- [https://github.com/Live-Hack-CVE/CVE-2014-9905](https://github.com/Live-Hack-CVE/CVE-2014-9905) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-9905.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-9905.svg)


## CVE-2014-8176
 The dtls1_clear_queues function in ssl/d1_lib.c in OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h frees data structures without considering that application data can arrive between a ChangeCipherSpec message and a Finished message, which allows remote DTLS peers to cause a denial of service (memory corruption and application crash) or possibly have unspecified other impact via unexpected application data.

- [https://github.com/Live-Hack-CVE/CVE-2014-8176](https://github.com/Live-Hack-CVE/CVE-2014-8176) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-8176.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-8176.svg)


## CVE-2013-5850
 Unspecified vulnerability in Oracle Java SE 7u40 and earlier, Java SE 6u60 and earlier, Java SE 5.0u51 and earlier, and Java SE Embedded 7u40 and earlier allows remote attackers to affect confidentiality, integrity, and availability via unknown vectors related to Libraries, a different vulnerability than CVE-2013-5842.

- [https://github.com/Live-Hack-CVE/CVE-2013-5842](https://github.com/Live-Hack-CVE/CVE-2013-5842) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2013-5842.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2013-5842.svg)


## CVE-2013-5809
 Unspecified vulnerability in Oracle Java SE 7u40 and earlier, Java SE 6u60 and earlier, Java SE 5.0u51 and earlier, and Java SE Embedded 7u40 and earlier allows remote attackers to affect confidentiality, integrity, and availability via unknown vectors related to 2D, a different vulnerability than CVE-2013-5829.

- [https://github.com/Live-Hack-CVE/CVE-2013-5829](https://github.com/Live-Hack-CVE/CVE-2013-5829) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2013-5829.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2013-5829.svg)


## CVE-2013-0544
 Directory traversal vulnerability in the Administrative Console in IBM WebSphere Application Server (WAS) 6.1 before 6.1.0.47, 7.0 before 7.0.0.29, 8.0 before 8.0.0.6, and 8.5 before 8.5.0.2 on Linux and UNIX allows remote authenticated users to modify data via unspecified vectors.

- [https://github.com/Live-Hack-CVE/CVE-2013-0544](https://github.com/Live-Hack-CVE/CVE-2013-0544) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2013-0544.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2013-0544.svg)


## CVE-2013-0543
 IBM WebSphere Application Server (WAS) 6.1 before 6.1.0.47, 7.0 before 7.0.0.29, 8.0 before 8.0.0.6, and 8.5 before 8.5.0.2 on Linux, Solaris, and HP-UX, when a Local OS registry is used, does not properly validate user accounts, which allows remote attackers to bypass intended access restrictions via unspecified vectors.

- [https://github.com/Live-Hack-CVE/CVE-2013-0543](https://github.com/Live-Hack-CVE/CVE-2013-0543) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2013-0543.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2013-0543.svg)


## CVE-2012-3412
 The sfc (aka Solarflare Solarstorm) driver in the Linux kernel before 3.2.30 allows remote attackers to cause a denial of service (DMA descriptor consumption and network-controller outage) via crafted TCP packets that trigger a small MSS value.

- [https://github.com/Live-Hack-CVE/CVE-2012-3412](https://github.com/Live-Hack-CVE/CVE-2012-3412) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-3412.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-3412.svg)


## CVE-2012-1717
 Unspecified vulnerability in the Java Runtime Environment (JRE) component in Oracle Java SE 7 update 4 and earlier, 6 update 32 and earlier, 5 update 35 and earlier, and 1.4.2_37 and earlier allows local users to affect confidentiality via unknown vectors related to printing on Solaris or Linux.

- [https://github.com/Live-Hack-CVE/CVE-2012-1717](https://github.com/Live-Hack-CVE/CVE-2012-1717) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-1717.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-1717.svg)


## CVE-2012-0777
 The JavaScript API in Adobe Reader and Acrobat 9.x before 9.5.1 and 10.x before 10.1.3 on Mac OS X and Linux allows attackers to execute arbitrary code or cause a denial of service (memory corruption) via unspecified vectors.

- [https://github.com/Live-Hack-CVE/CVE-2012-0777](https://github.com/Live-Hack-CVE/CVE-2012-0777) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-0777.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-0777.svg)


## CVE-2010-4606
 Unspecified vulnerability in the Space Management client in the Hierarchical Storage Management (HSM) component in IBM Tivoli Storage Manager (TSM) 5.4.x before 5.4.3.4, 5.5.x before 5.5.3, 6.1.x before 6.1.4, and 6.2.x before 6.2.2 on Unix and Linux allows remote attackers to execute arbitrary commands via unknown vectors, related to a &quot;script execution vulnerability.&quot;

- [https://github.com/Live-Hack-CVE/CVE-2010-4606](https://github.com/Live-Hack-CVE/CVE-2010-4606) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2010-4606.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2010-4606.svg)


## CVE-2010-4604
 Stack-based buffer overflow in the GeneratePassword function in dsmtca (aka the Trusted Communications Agent or TCA) in the backup-archive client in IBM Tivoli Storage Manager (TSM) 5.3.x before 5.3.6.10, 5.4.x before 5.4.3.4, 5.5.x before 5.5.2.10, and 6.1.x before 6.1.3.1 on Unix and Linux allows local users to gain privileges by specifying a long LANG environment variable, and then sending a request over a pipe.

- [https://github.com/Live-Hack-CVE/CVE-2010-4604](https://github.com/Live-Hack-CVE/CVE-2010-4604) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2010-4604.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2010-4604.svg)


## CVE-2010-4296
 vmware-mount in VMware Workstation 7.x before 7.1.2 build 301548 on Linux, VMware Player 3.1.x before 3.1.2 build 301548 on Linux, VMware Server 2.0.2 on Linux, and VMware Fusion 3.1.x before 3.1.2 build 332101 does not properly load libraries, which allows host OS users to gain privileges via vectors involving shared object files.

- [https://github.com/Live-Hack-CVE/CVE-2010-4296](https://github.com/Live-Hack-CVE/CVE-2010-4296) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2010-4296.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2010-4296.svg)


## CVE-2010-4295
 Race condition in the mounting process in vmware-mount in VMware Workstation 7.x before 7.1.2 build 301548 on Linux, VMware Player 3.1.x before 3.1.2 build 301548 on Linux, VMware Server 2.0.2 on Linux, and VMware Fusion 3.1.x before 3.1.2 build 332101 allows host OS users to gain privileges via vectors involving temporary files.

- [https://github.com/Live-Hack-CVE/CVE-2010-4295](https://github.com/Live-Hack-CVE/CVE-2010-4295) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2010-4295.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2010-4295.svg)


## CVE-2010-1717
 Directory traversal vulnerability in the iF surfALERT (com_if_surfalert) component 1.2 for Joomla! allows remote attackers to read arbitrary files and possibly have unspecified other impact via a .. (dot dot) in the controller parameter to index.php.

- [https://github.com/Live-Hack-CVE/CVE-2010-1717](https://github.com/Live-Hack-CVE/CVE-2010-1717) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2010-1717.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2010-1717.svg)


## CVE-2008-4609
 The TCP implementation in (1) Linux, (2) platforms based on BSD Unix, (3) Microsoft Windows, (4) Cisco products, and probably other operating systems allows remote attackers to cause a denial of service (connection queue exhaustion) via multiple vectors that manipulate information in the TCP state table, as demonstrated by sockstress.

- [https://github.com/Live-Hack-CVE/CVE-2008-4609](https://github.com/Live-Hack-CVE/CVE-2008-4609) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2008-4609.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2008-4609.svg)


## CVE-2006-3240
 Cross-site scripting (XSS) vulnerability in classes/ui.class.php in dotProject 2.0.3 and earlier allows remote attackers to inject arbitrary web script or HTML via the login parameter.

- [https://github.com/Live-Hack-CVE/CVE-2006-3240](https://github.com/Live-Hack-CVE/CVE-2006-3240) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2006-3240.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2006-3240.svg)


## CVE-2003-1562
 sshd in OpenSSH 3.6.1p2 and earlier, when PermitRootLogin is disabled and using PAM keyboard-interactive authentication, does not insert a delay after a root login attempt with the correct password, which makes it easier for remote attackers to use timing differences to determine if the password step of a multi-step authentication is successful, a different vulnerability than CVE-2003-0190.

- [https://github.com/Live-Hack-CVE/CVE-2003-1562](https://github.com/Live-Hack-CVE/CVE-2003-1562) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2003-1562.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2003-1562.svg)


## CVE-2003-0190
 OpenSSH-portable (OpenSSH) 3.6.1p1 and earlier with PAM support enabled immediately sends an error message when a user does not exist, which allows remote attackers to determine valid usernames via a timing attack.

- [https://github.com/Live-Hack-CVE/CVE-2003-0190](https://github.com/Live-Hack-CVE/CVE-2003-0190) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2003-0190.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2003-0190.svg)

