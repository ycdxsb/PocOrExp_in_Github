# Update 2023-11-27
## CVE-2023-38646
 Metabase open source before 0.46.6.1 and Metabase Enterprise before 1.46.6.1 allow attackers to execute arbitrary commands on the server, at the server's privilege level. Authentication is not required for exploitation. The other fixed versions are 0.45.4.1, 1.45.4.1, 0.44.7.1, 1.44.7.1, 0.43.7.2, and 1.43.7.2.

- [https://github.com/Ego1stoo/CVE-2023-38646](https://github.com/Ego1stoo/CVE-2023-38646) :  ![starts](https://img.shields.io/github/stars/Ego1stoo/CVE-2023-38646.svg) ![forks](https://img.shields.io/github/forks/Ego1stoo/CVE-2023-38646.svg)


## CVE-2023-34468
 The DBCPConnectionPool and HikariCPConnectionPool Controller Services in Apache NiFi 0.0.2 through 1.21.0 allow an authenticated and authorized user to configure a Database URL with the H2 driver that enables custom code execution. The resolution validates the Database URL and rejects H2 JDBC locations. You are recommended to upgrade to version 1.22.0 or later which fixes this issue.

- [https://github.com/mbadanoiu/CVE-2023-34468](https://github.com/mbadanoiu/CVE-2023-34468) :  ![starts](https://img.shields.io/github/stars/mbadanoiu/CVE-2023-34468.svg) ![forks](https://img.shields.io/github/forks/mbadanoiu/CVE-2023-34468.svg)


## CVE-2023-5561
 WordPress does not properly restrict which user fields are searchable via the REST API, allowing unauthenticated attackers to discern the email addresses of users who have published public posts on an affected website via an Oracle style attack

- [https://github.com/justhx0r/CVE-2023-5561](https://github.com/justhx0r/CVE-2023-5561) :  ![starts](https://img.shields.io/github/stars/justhx0r/CVE-2023-5561.svg) ![forks](https://img.shields.io/github/forks/justhx0r/CVE-2023-5561.svg)


## CVE-2023-2650
 Issue summary: Processing some specially crafted ASN.1 object identifiers or data containing them may be very slow. Impact summary: Applications that use OBJ_obj2txt() directly, or use any of the OpenSSL subsystems OCSP, PKCS7/SMIME, CMS, CMP/CRMF or TS with no message size limit may experience notable to very long delays when processing those messages, which may lead to a Denial of Service. An OBJECT IDENTIFIER is composed of a series of numbers - sub-identifiers - most of which have no size limit. OBJ_obj2txt() may be used to translate an ASN.1 OBJECT IDENTIFIER given in DER encoding form (using the OpenSSL type ASN1_OBJECT) to its canonical numeric text form, which are the sub-identifiers of the OBJECT IDENTIFIER in decimal form, separated by periods. When one of the sub-identifiers in the OBJECT IDENTIFIER is very large (these are sizes that are seen as absurdly large, taking up tens or hundreds of KiBs), the translation to a decimal number in text may take a very long time. The time complexity is O(n^2) with 'n' being the size of the sub-identifiers in bytes (*). With OpenSSL 3.0, support to fetch cryptographic algorithms using names / identifiers in string form was introduced. This includes using OBJECT IDENTIFIERs in canonical numeric text form as identifiers for fetching algorithms. Such OBJECT IDENTIFIERs may be received through the ASN.1 structure AlgorithmIdentifier, which is commonly used in multiple protocols to specify what cryptographic algorithm should be used to sign or verify, encrypt or decrypt, or digest passed data. Applications that call OBJ_obj2txt() directly with untrusted data are affected, with any version of OpenSSL. If the use is for the mere purpose of display, the severity is considered low. In OpenSSL 3.0 and newer, this affects the subsystems OCSP, PKCS7/SMIME, CMS, CMP/CRMF or TS. It also impacts anything that processes X.509 certificates, including simple things like verifying its signature. The impact on TLS is relatively low, because all versions of OpenSSL have a 100KiB limit on the peer's certificate chain. Additionally, this only impacts clients, or servers that have explicitly enabled client authentication. In OpenSSL 1.1.1 and 1.0.2, this only affects displaying diverse objects, such as X.509 certificates. This is assumed to not happen in such a way that it would cause a Denial of Service, so these versions are considered not affected by this issue in such a way that it would be cause for concern, and the severity is therefore considered low.

- [https://github.com/hshivhare67/OpenSSL_1.1.1g_CVE-2023-2650](https://github.com/hshivhare67/OpenSSL_1.1.1g_CVE-2023-2650) :  ![starts](https://img.shields.io/github/stars/hshivhare67/OpenSSL_1.1.1g_CVE-2023-2650.svg) ![forks](https://img.shields.io/github/forks/hshivhare67/OpenSSL_1.1.1g_CVE-2023-2650.svg)


## CVE-2021-28165
 In Eclipse Jetty 7.2.2 to 9.4.38, 10.0.0.alpha0 to 10.0.1, and 11.0.0.alpha0 to 11.0.1, CPU usage can reach 100% upon receiving a large invalid TLS frame.

- [https://github.com/uthrasri/CVE-2021-28165](https://github.com/uthrasri/CVE-2021-28165) :  ![starts](https://img.shields.io/github/stars/uthrasri/CVE-2021-28165.svg) ![forks](https://img.shields.io/github/forks/uthrasri/CVE-2021-28165.svg)


## CVE-2021-20253
 A flaw was found in ansible-tower. The default installation is vulnerable to Job Isolation escape allowing an attacker to elevate the privilege from a low privileged user to the awx user from outside the isolated environment. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/mbadanoiu/CVE-2021-20253](https://github.com/mbadanoiu/CVE-2021-20253) :  ![starts](https://img.shields.io/github/stars/mbadanoiu/CVE-2021-20253.svg) ![forks](https://img.shields.io/github/forks/mbadanoiu/CVE-2021-20253.svg)


## CVE-2019-13024
 Centreon 18.x before 18.10.6, 19.x before 19.04.3, and Centreon web before 2.8.29 allows the attacker to execute arbitrary system commands by using the value &quot;init_script&quot;-&quot;Monitoring Engine Binary&quot; in main.get.php to insert a arbitrary command into the database, and execute it by calling the vulnerable page www/include/configuration/configGenerate/xml/generateFiles.php (which passes the inserted value to the database to shell_exec without sanitizing it, allowing one to execute system arbitrary commands).

- [https://github.com/get-get-get-get/Centreon-RCE](https://github.com/get-get-get-get/Centreon-RCE) :  ![starts](https://img.shields.io/github/stars/get-get-get-get/Centreon-RCE.svg) ![forks](https://img.shields.io/github/forks/get-get-get-get/Centreon-RCE.svg)


## CVE-2019-11409
 app/operator_panel/exec.php in the Operator Panel module in FusionPBX 4.4.3 suffers from a command injection vulnerability due to a lack of input validation that allows authenticated non-administrative attackers to execute commands on the host. This can further lead to remote code execution when combined with an XSS vulnerability also present in the FusionPBX Operator Panel module.

- [https://github.com/HoseynHeydari/fusionpbx_rce_vulnerability](https://github.com/HoseynHeydari/fusionpbx_rce_vulnerability) :  ![starts](https://img.shields.io/github/stars/HoseynHeydari/fusionpbx_rce_vulnerability.svg) ![forks](https://img.shields.io/github/forks/HoseynHeydari/fusionpbx_rce_vulnerability.svg)


## CVE-2019-11408
 XSS in app/operator_panel/index_inc.php in the Operator Panel module in FusionPBX 4.4.3 allows remote unauthenticated attackers to inject arbitrary JavaScript characters by placing a phone call using a specially crafted caller ID number. This can further lead to remote code execution by chaining this vulnerability with a command injection vulnerability also present in FusionPBX.

- [https://github.com/HoseynHeydari/fusionpbx_rce_vulnerability](https://github.com/HoseynHeydari/fusionpbx_rce_vulnerability) :  ![starts](https://img.shields.io/github/stars/HoseynHeydari/fusionpbx_rce_vulnerability.svg) ![forks](https://img.shields.io/github/forks/HoseynHeydari/fusionpbx_rce_vulnerability.svg)


## CVE-2003-0282
 Directory traversal vulnerability in UnZip 5.50 allows attackers to overwrite arbitrary files via invalid characters between two . (dot) characters, which are filtered and result in a &quot;..&quot; sequence.

- [https://github.com/theseann/cve-2003-0282](https://github.com/theseann/cve-2003-0282) :  ![starts](https://img.shields.io/github/stars/theseann/cve-2003-0282.svg) ![forks](https://img.shields.io/github/forks/theseann/cve-2003-0282.svg)

