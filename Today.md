# Update 2022-05-01
## CVE-2022-29464
 Certain WSO2 products allow unrestricted file upload with resultant remote code execution. The attacker must use a /fileupload endpoint with a Content-Disposition directory traversal sequence to reach a directory under the web root, such as a ../../../../repository/deployment/server/webapps directory. This affects WSO2 API Manager 2.2.0 and above through 4.0.0; WSO2 Identity Server 5.2.0 and above through 5.11.0; WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0, and 5.6.0; WSO2 Identity Server as Key Manager 5.3.0 and above through 5.10.0; and WSO2 Enterprise Integrator 6.2.0 and above through 6.6.0.

- [https://github.com/superzerosec/CVE-2022-29464](https://github.com/superzerosec/CVE-2022-29464) :  ![starts](https://img.shields.io/github/stars/superzerosec/CVE-2022-29464.svg) ![forks](https://img.shields.io/github/forks/superzerosec/CVE-2022-29464.svg)


## CVE-2022-28508
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/YavuzSahbaz/CVE-2022-28508](https://github.com/YavuzSahbaz/CVE-2022-28508) :  ![starts](https://img.shields.io/github/stars/YavuzSahbaz/CVE-2022-28508.svg) ![forks](https://img.shields.io/github/forks/YavuzSahbaz/CVE-2022-28508.svg)


## CVE-2022-28099
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/IbrahimEkimIsik/CVE-2022-28099](https://github.com/IbrahimEkimIsik/CVE-2022-28099) :  ![starts](https://img.shields.io/github/stars/IbrahimEkimIsik/CVE-2022-28099.svg) ![forks](https://img.shields.io/github/forks/IbrahimEkimIsik/CVE-2022-28099.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/Enokiy/spring-RCE-CVE-2022-22965](https://github.com/Enokiy/spring-RCE-CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/Enokiy/spring-RCE-CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/Enokiy/spring-RCE-CVE-2022-22965.svg)


## CVE-2021-23841
 The OpenSSL public API function X509_issuer_and_serial_hash() attempts to create a unique hash value based on the issuer and serial number data contained within an X509 certificate. However it fails to correctly handle any errors that may occur while parsing the issuer field (which might occur if the issuer field is maliciously constructed). This may subsequently result in a NULL pointer deref and a crash leading to a potential denial of service attack. The function X509_issuer_and_serial_hash() is never directly called by OpenSSL itself so applications are only vulnerable if they use this function directly and they use it on certificates that may have been obtained from untrusted sources. OpenSSL versions 1.1.1i and below are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1j. OpenSSL versions 1.0.2x and below are affected by this issue. However OpenSSL 1.0.2 is out of support and no longer receiving public updates. Premium support customers of OpenSSL 1.0.2 should upgrade to 1.0.2y. Other users should upgrade to 1.1.1j. Fixed in OpenSSL 1.1.1j (Affected 1.1.1-1.1.1i). Fixed in OpenSSL 1.0.2y (Affected 1.0.2-1.0.2x).

- [https://github.com/Trinadh465/external_boringssl_openssl_1.1.0g_CVE-2021-23841](https://github.com/Trinadh465/external_boringssl_openssl_1.1.0g_CVE-2021-23841) :  ![starts](https://img.shields.io/github/stars/Trinadh465/external_boringssl_openssl_1.1.0g_CVE-2021-23841.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/external_boringssl_openssl_1.1.0g_CVE-2021-23841.svg)


## CVE-2021-22924
 libcurl keeps previously used connections in a connection pool for subsequenttransfers to reuse, if one of them matches the setup.Due to errors in the logic, the config matching function did not take 'issuercert' into account and it compared the involved paths *case insensitively*,which could lead to libcurl reusing wrong connections.File paths are, or can be, case sensitive on many systems but not all, and caneven vary depending on used file systems.The comparison also didn't include the 'issuer cert' which a transfer can setto qualify how to verify the server certificate.

- [https://github.com/Trinadh465/external_curl_AOSP10_r33_CVE-2021-22924](https://github.com/Trinadh465/external_curl_AOSP10_r33_CVE-2021-22924) :  ![starts](https://img.shields.io/github/stars/Trinadh465/external_curl_AOSP10_r33_CVE-2021-22924.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/external_curl_AOSP10_r33_CVE-2021-22924.svg)


## CVE-2021-0963
 In onCreate of KeyChainActivity.java, there is a possible way to use an app certificate stored in keychain due to a tapjacking/overlay attack. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-9Android ID: A-199754277

- [https://github.com/Trinadh465/packages_apps_KeyChain_AOSP10_r33_CVE-2021-0963](https://github.com/Trinadh465/packages_apps_KeyChain_AOSP10_r33_CVE-2021-0963) :  ![starts](https://img.shields.io/github/stars/Trinadh465/packages_apps_KeyChain_AOSP10_r33_CVE-2021-0963.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/packages_apps_KeyChain_AOSP10_r33_CVE-2021-0963.svg)


## CVE-2021-0396
 In Builtins::Generate_ArgumentsAdaptorTrampoline of builtins-arm.cc and related files, there is a possible out of bounds write due to an incorrect bounds check. This could lead to remote code execution in an unprivileged process with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-8.1 Android-9 Android-10 Android-11Android ID: A-160610106

- [https://github.com/Satheesh575555/external_v8_AOSP10_r33_CVE-2021-0396](https://github.com/Satheesh575555/external_v8_AOSP10_r33_CVE-2021-0396) :  ![starts](https://img.shields.io/github/stars/Satheesh575555/external_v8_AOSP10_r33_CVE-2021-0396.svg) ![forks](https://img.shields.io/github/forks/Satheesh575555/external_v8_AOSP10_r33_CVE-2021-0396.svg)


## CVE-2021-0393
 In Scanner::LiteralBuffer::NewCapacity of scanner.cc, there is a possible out of bounds write due to an integer overflow. This could lead to remote code execution if an attacker can supply a malicious PAC file, with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-11 Android-8.1 Android-9 Android-10Android ID: A-168041375

- [https://github.com/Trinadh465/external_v8_AOSP10_r33_CVE-2021-0393](https://github.com/Trinadh465/external_v8_AOSP10_r33_CVE-2021-0393) :  ![starts](https://img.shields.io/github/stars/Trinadh465/external_v8_AOSP10_r33_CVE-2021-0393.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/external_v8_AOSP10_r33_CVE-2021-0393.svg)


## CVE-2021-0326
 In p2p_copy_client_info of p2p.c, there is a possible out of bounds write due to a missing bounds check. This could lead to remote code execution if the target device is performing a Wi-Fi Direct search, with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-8.1 Android-9Android ID: A-172937525

- [https://github.com/ShaikUsaf/external_wpa_supplicant_8_AOSP10_r33CVE-2021-0326](https://github.com/ShaikUsaf/external_wpa_supplicant_8_AOSP10_r33CVE-2021-0326) :  ![starts](https://img.shields.io/github/stars/ShaikUsaf/external_wpa_supplicant_8_AOSP10_r33CVE-2021-0326.svg) ![forks](https://img.shields.io/github/forks/ShaikUsaf/external_wpa_supplicant_8_AOSP10_r33CVE-2021-0326.svg)


## CVE-2021-0313
 In isWordBreakAfter of LayoutUtils.cpp, there is a possible way to slow or crash a TextView due to improper input validation. This could lead to remote denial of service with no additional execution privileges needed. User interaction is not needed for exploitation. Product: Android; Versions: Android-9, Android-10, Android-11, Android-8.0, Android-8.1; Android ID: A-170968514.

- [https://github.com/Satheesh575555/frameworks_minikin_AOSP10_r33_CVE-2021-0313](https://github.com/Satheesh575555/frameworks_minikin_AOSP10_r33_CVE-2021-0313) :  ![starts](https://img.shields.io/github/stars/Satheesh575555/frameworks_minikin_AOSP10_r33_CVE-2021-0313.svg) ![forks](https://img.shields.io/github/forks/Satheesh575555/frameworks_minikin_AOSP10_r33_CVE-2021-0313.svg)


## CVE-2020-10220
 An issue was discovered in rConfig through 3.9.4. The web interface is prone to a SQL injection via the commands.inc.php searchColumn parameter.

- [https://github.com/arvind2022/isac_rconfig3.9](https://github.com/arvind2022/isac_rconfig3.9) :  ![starts](https://img.shields.io/github/stars/arvind2022/isac_rconfig3.9.svg) ![forks](https://img.shields.io/github/forks/arvind2022/isac_rconfig3.9.svg)


## CVE-2020-0418
 In getPermissionInfosForGroup of Utils.java, there is a logic error. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10Android ID: A-153879813

- [https://github.com/Trinadh465/packages_apps_PackageInstaller_AOSP10_r33_CVE-2020-0418](https://github.com/Trinadh465/packages_apps_PackageInstaller_AOSP10_r33_CVE-2020-0418) :  ![starts](https://img.shields.io/github/stars/Trinadh465/packages_apps_PackageInstaller_AOSP10_r33_CVE-2020-0418.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/packages_apps_PackageInstaller_AOSP10_r33_CVE-2020-0418.svg)


## CVE-2020-0381
 In Parse_wave of eas_mdls.c, there is a possible out of bounds write due to an integer overflow. This could lead to remote information disclosure in a highly constrained process with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-8.0 Android-8.1 Android-9 Android-10 Android-11Android ID: A-150159669

- [https://github.com/Trinadh465/external_sonivox_AOSP10_r33_CVE-2020-0381](https://github.com/Trinadh465/external_sonivox_AOSP10_r33_CVE-2020-0381) :  ![starts](https://img.shields.io/github/stars/Trinadh465/external_sonivox_AOSP10_r33_CVE-2020-0381.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/external_sonivox_AOSP10_r33_CVE-2020-0381.svg)


## CVE-2020-0240
 In NewFixedDoubleArray of factory.cc, there is a possible out of bounds write due to an integer overflow. This could lead to remote code execution with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-10Android ID: A-150706594

- [https://github.com/ShaikUsaf/external_v8_AOSP10_r33_CVE-2020-0240](https://github.com/ShaikUsaf/external_v8_AOSP10_r33_CVE-2020-0240) :  ![starts](https://img.shields.io/github/stars/ShaikUsaf/external_v8_AOSP10_r33_CVE-2020-0240.svg) ![forks](https://img.shields.io/github/forks/ShaikUsaf/external_v8_AOSP10_r33_CVE-2020-0240.svg)


## CVE-2019-9787
 WordPress before 5.1.1 does not properly filter comment content, leading to Remote Code Execution by unauthenticated users in a default configuration. This occurs because CSRF protection is mishandled, and because Search Engine Optimization of A elements is performed incorrectly, leading to XSS. The XSS results in administrative access, which allows arbitrary changes to .php files. This is related to wp-admin/includes/ajax-actions.php and wp-includes/comment.php.

- [https://github.com/kuangting4231/mitigation-cve-2019-9787](https://github.com/kuangting4231/mitigation-cve-2019-9787) :  ![starts](https://img.shields.io/github/stars/kuangting4231/mitigation-cve-2019-9787.svg) ![forks](https://img.shields.io/github/forks/kuangting4231/mitigation-cve-2019-9787.svg)


## CVE-2018-19422
 /panel/uploads in Subrion CMS 4.2.1 allows remote attackers to execute arbitrary PHP code via a .pht or .phar file, because the .htaccess file omits these.

- [https://github.com/Swammers8/SubrionCMS-4.2.1-File-upload-RCE-auth-](https://github.com/Swammers8/SubrionCMS-4.2.1-File-upload-RCE-auth-) :  ![starts](https://img.shields.io/github/stars/Swammers8/SubrionCMS-4.2.1-File-upload-RCE-auth-.svg) ![forks](https://img.shields.io/github/forks/Swammers8/SubrionCMS-4.2.1-File-upload-RCE-auth-.svg)


## CVE-2018-2019
 IBM Security Identity Manager 6.0.0 Virtual Appliance is vulnerable to a XML External Entity Injection (XXE) attack when processing XML data. A remote attacker could exploit this vulnerability to expose sensitive information or consume memory resources. IBM X-Force ID: 155265.

- [https://github.com/attakercyebr/hack4lx_CVE-2018-2019](https://github.com/attakercyebr/hack4lx_CVE-2018-2019) :  ![starts](https://img.shields.io/github/stars/attakercyebr/hack4lx_CVE-2018-2019.svg) ![forks](https://img.shields.io/github/forks/attakercyebr/hack4lx_CVE-2018-2019.svg)


## CVE-2017-10271
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Security). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.1.0 and 12.2.1.2.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 7.5 (Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H).

- [https://github.com/0xn0ne/weblogicScanner](https://github.com/0xn0ne/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/0xn0ne/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/0xn0ne/weblogicScanner.svg)
- [https://github.com/Yuusuke4/WebLogic_CNVD_C_2019_48814](https://github.com/Yuusuke4/WebLogic_CNVD_C_2019_48814) :  ![starts](https://img.shields.io/github/stars/Yuusuke4/WebLogic_CNVD_C_2019_48814.svg) ![forks](https://img.shields.io/github/forks/Yuusuke4/WebLogic_CNVD_C_2019_48814.svg)

