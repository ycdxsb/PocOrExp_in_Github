# Update 2023-04-26
## CVE-2023-28432
 Minio is a Multi-Cloud Object Storage framework. In a cluster deployment starting with RELEASE.2019-12-17T23-16-33Z and prior to RELEASE.2023-03-20T20-16-18Z, MinIO returns all environment variables, including `MINIO_SECRET_KEY` and `MINIO_ROOT_PASSWORD`, resulting in information disclosure. All users of distributed deployment are impacted. All users are advised to upgrade to RELEASE.2023-03-20T20-16-18Z.

- [https://github.com/octosec45/ms-word-rce-0day-poc-2023](https://github.com/octosec45/ms-word-rce-0day-poc-2023) :  ![starts](https://img.shields.io/github/stars/octosec45/ms-word-rce-0day-poc-2023.svg) ![forks](https://img.shields.io/github/forks/octosec45/ms-word-rce-0day-poc-2023.svg)


## CVE-2023-27350
 This vulnerability allows remote attackers to bypass authentication on affected installations of PaperCut NG 22.0.5 (Build 63914). Authentication is not required to exploit this vulnerability. The specific flaw exists within the SetupCompleted class. The issue results from improper access control. An attacker can leverage this vulnerability to bypass authentication and execute arbitrary code in the context of SYSTEM. Was ZDI-CAN-18987.

- [https://github.com/horizon3ai/CVE-2023-27350](https://github.com/horizon3ai/CVE-2023-27350) :  ![starts](https://img.shields.io/github/stars/horizon3ai/CVE-2023-27350.svg) ![forks](https://img.shields.io/github/forks/horizon3ai/CVE-2023-27350.svg)


## CVE-2023-23752
 An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

- [https://github.com/octosec45/ms-word-rce-0day-poc-2023](https://github.com/octosec45/ms-word-rce-0day-poc-2023) :  ![starts](https://img.shields.io/github/stars/octosec45/ms-word-rce-0day-poc-2023.svg) ![forks](https://img.shields.io/github/forks/octosec45/ms-word-rce-0day-poc-2023.svg)


## CVE-2023-22894
 Strapi through 4.5.5 allows attackers (with access to the admin panel) to discover sensitive user details by exploiting the query filter. The attacker can filter users by columns that contain sensitive information and infer a value from API responses. If the attacker has super admin access, then this can be exploited to discover the password hash and password reset token of all users. If the attacker has admin panel access to an account with permission to access the username and email of API users with a lower privileged role (e.g., Editor or Author), then this can be exploited to discover sensitive information for all API users but not other admin accounts.

- [https://github.com/Saboor-Hakimi/CVE-2023-22894](https://github.com/Saboor-Hakimi/CVE-2023-22894) :  ![starts](https://img.shields.io/github/stars/Saboor-Hakimi/CVE-2023-22894.svg) ![forks](https://img.shields.io/github/forks/Saboor-Hakimi/CVE-2023-22894.svg)


## CVE-2023-22809
 In Sudo before 1.9.12p2, the sudoedit (aka -e) feature mishandles extra arguments passed in the user-provided environment variables (SUDO_EDITOR, VISUAL, and EDITOR), allowing a local attacker to append arbitrary entries to the list of files to process. This can lead to privilege escalation. Affected versions are 1.8.0 through 1.9.12.p1. The problem exists because a user-specified editor may contain a &quot;--&quot; argument that defeats a protection mechanism, e.g., an EDITOR='vim -- /path/to/extra/file' value.

- [https://github.com/octosec45/ms-word-rce-0day-poc-2023](https://github.com/octosec45/ms-word-rce-0day-poc-2023) :  ![starts](https://img.shields.io/github/stars/octosec45/ms-word-rce-0day-poc-2023.svg) ![forks](https://img.shields.io/github/forks/octosec45/ms-word-rce-0day-poc-2023.svg)


## CVE-2023-21839
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).

- [https://github.com/octosec45/ms-word-rce-0day-poc-2023](https://github.com/octosec45/ms-word-rce-0day-poc-2023) :  ![starts](https://img.shields.io/github/stars/octosec45/ms-word-rce-0day-poc-2023.svg) ![forks](https://img.shields.io/github/forks/octosec45/ms-word-rce-0day-poc-2023.svg)


## CVE-2023-1671
 A pre-auth command injection vulnerability in the warn-proceed handler of Sophos Web Appliance older than version 4.3.10.4 allows execution of arbitrary code.

- [https://github.com/W01fh4cker/CVE-2023-1671-POC](https://github.com/W01fh4cker/CVE-2023-1671-POC) :  ![starts](https://img.shields.io/github/stars/W01fh4cker/CVE-2023-1671-POC.svg) ![forks](https://img.shields.io/github/forks/W01fh4cker/CVE-2023-1671-POC.svg)


## CVE-2023-0464
 A security vulnerability has been identified in all supported versions of OpenSSL related to the verification of X.509 certificate chains that include policy constraints. Attackers may be able to exploit this vulnerability by creating a malicious certificate chain that triggers exponential use of computational resources, leading to a denial-of-service (DoS) attack on affected systems. Policy processing is disabled by default but can be enabled by passing the `-policy' argument to the command line utilities or by calling the `X509_VERIFY_PARAM_set1_policies()' function.

- [https://github.com/Trinadh465/Openssl_1.1.1g_CVE-2023-0464](https://github.com/Trinadh465/Openssl_1.1.1g_CVE-2023-0464) :  ![starts](https://img.shields.io/github/stars/Trinadh465/Openssl_1.1.1g_CVE-2023-0464.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/Openssl_1.1.1g_CVE-2023-0464.svg)


## CVE-2023-0215
 The public API function BIO_new_NDEF is a helper function used for streaming ASN.1 data via a BIO. It is primarily used internally to OpenSSL to support the SMIME, CMS and PKCS7 streaming capabilities, but may also be called directly by end user applications. The function receives a BIO from the caller, prepends a new BIO_f_asn1 filter BIO onto the front of it to form a BIO chain, and then returns the new head of the BIO chain to the caller. Under certain conditions, for example if a CMS recipient public key is invalid, the new filter BIO is freed and the function returns a NULL result indicating a failure. However, in this case, the BIO chain is not properly cleaned up and the BIO passed by the caller still retains internal pointers to the previously freed filter BIO. If the caller then goes on to call BIO_pop() on the BIO then a use-after-free will occur. This will most likely result in a crash. This scenario occurs directly in the internal function B64_write_ASN1() which may cause BIO_new_NDEF() to be called and will subsequently call BIO_pop() on the BIO. This internal function is in turn called by the public API functions PEM_write_bio_ASN1_stream, PEM_write_bio_CMS_stream, PEM_write_bio_PKCS7_stream, SMIME_write_ASN1, SMIME_write_CMS and SMIME_write_PKCS7. Other public API functions that may be impacted by this include i2d_ASN1_bio_stream, BIO_new_CMS, BIO_new_PKCS7, i2d_CMS_bio_stream and i2d_PKCS7_bio_stream. The OpenSSL cms and smime command line applications are similarly affected.

- [https://github.com/nidhi7598/OPENSSL_1.1.1g_G3_CVE-2023-0215](https://github.com/nidhi7598/OPENSSL_1.1.1g_G3_CVE-2023-0215) :  ![starts](https://img.shields.io/github/stars/nidhi7598/OPENSSL_1.1.1g_G3_CVE-2023-0215.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/OPENSSL_1.1.1g_G3_CVE-2023-0215.svg)


## CVE-2023-0179
 A buffer overflow vulnerability was found in the Netfilter subsystem in the Linux Kernel. This issue could allow the leakage of both stack and heap addresses, and potentially allow Local Privilege Escalation to the root user via arbitrary code execution.

- [https://github.com/puppypete99/discord-rce-exploit-poc-2023-04](https://github.com/puppypete99/discord-rce-exploit-poc-2023-04) :  ![starts](https://img.shields.io/github/stars/puppypete99/discord-rce-exploit-poc-2023-04.svg) ![forks](https://img.shields.io/github/forks/puppypete99/discord-rce-exploit-poc-2023-04.svg)


## CVE-2022-47966
 Multiple Zoho ManageEngine on-premise products, such as ServiceDesk Plus through 14003, allow remote code execution due to use of Apache xmlsec (aka XML Security for Java) 1.4.1, because the xmlsec XSLT features, by design in that version, make the application responsible for certain security protections, and the ManageEngine applications did not provide those protections.

- [https://github.com/puppypete99/discord-rce-exploit-poc-2023-04](https://github.com/puppypete99/discord-rce-exploit-poc-2023-04) :  ![starts](https://img.shields.io/github/stars/puppypete99/discord-rce-exploit-poc-2023-04.svg) ![forks](https://img.shields.io/github/forks/puppypete99/discord-rce-exploit-poc-2023-04.svg)


## CVE-2022-34527
 D-Link DSL-3782 v1.03 and below was discovered to contain a command injection vulnerability via the function byte_4C0160.

- [https://github.com/FzBacon/CVE-2022-34527_D-Link_DSL-3782_Router_command_injection](https://github.com/FzBacon/CVE-2022-34527_D-Link_DSL-3782_Router_command_injection) :  ![starts](https://img.shields.io/github/stars/FzBacon/CVE-2022-34527_D-Link_DSL-3782_Router_command_injection.svg) ![forks](https://img.shields.io/github/forks/FzBacon/CVE-2022-34527_D-Link_DSL-3782_Router_command_injection.svg)


## CVE-2022-33959
 IBM Sterling Order Management 10.0 could allow a user to bypass validation and perform unauthorized actions on behalf of other users. IBM X-Force ID: 229320.

- [https://github.com/gitadvisor/CVE-2022-33959](https://github.com/gitadvisor/CVE-2022-33959) :  ![starts](https://img.shields.io/github/stars/gitadvisor/CVE-2022-33959.svg) ![forks](https://img.shields.io/github/forks/gitadvisor/CVE-2022-33959.svg)


## CVE-2022-22536
 SAP NetWeaver Application Server ABAP, SAP NetWeaver Application Server Java, ABAP Platform, SAP Content Server 7.53 and SAP Web Dispatcher are vulnerable for request smuggling and request concatenation. An unauthenticated attacker can prepend a victim's request with arbitrary data. This way, the attacker can execute functions impersonating the victim or poison intermediary Web caches. A successful attack could result in complete compromise of Confidentiality, Integrity and Availability of the system.

- [https://github.com/puppypete99/discord-rce-exploit-poc-2023-04](https://github.com/puppypete99/discord-rce-exploit-poc-2023-04) :  ![starts](https://img.shields.io/github/stars/puppypete99/discord-rce-exploit-poc-2023-04.svg) ![forks](https://img.shields.io/github/forks/puppypete99/discord-rce-exploit-poc-2023-04.svg)


## CVE-2022-4304
 A timing based side channel exists in the OpenSSL RSA Decryption implementation which could be sufficient to recover a plaintext across a network in a Bleichenbacher style attack. To achieve a successful decryption an attacker would have to be able to send a very large number of trial messages for decryption. The vulnerability affects all RSA padding modes: PKCS#1 v1.5, RSA-OEAP and RSASVE. For example, in a TLS connection, RSA is commonly used by a client to send an encrypted pre-master secret to the server. An attacker that had observed a genuine connection between a client and a server could use this flaw to send trial messages to the server and record the time taken to process them. After a sufficiently large number of messages the attacker could recover the pre-master secret used for the original connection and thus be able to decrypt the application data sent over that connection.

- [https://github.com/Trinadh465/Openssl-1.1.1g_CVE-2022-4304](https://github.com/Trinadh465/Openssl-1.1.1g_CVE-2022-4304) :  ![starts](https://img.shields.io/github/stars/Trinadh465/Openssl-1.1.1g_CVE-2022-4304.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/Openssl-1.1.1g_CVE-2022-4304.svg)


## CVE-2022-2588
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Markakd/CVE-2022-2588](https://github.com/Markakd/CVE-2022-2588) :  ![starts](https://img.shields.io/github/stars/Markakd/CVE-2022-2588.svg) ![forks](https://img.shields.io/github/forks/Markakd/CVE-2022-2588.svg)


## CVE-2022-1609
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/savior-only/CVE-2022-1609](https://github.com/savior-only/CVE-2022-1609) :  ![starts](https://img.shields.io/github/stars/savior-only/CVE-2022-1609.svg) ![forks](https://img.shields.io/github/forks/savior-only/CVE-2022-1609.svg)


## CVE-2021-46461
 njs through 0.7.0, used in NGINX, was discovered to contain an out-of-bounds array access via njs_vmcode_typeof in /src/njs_vmcode.c.

- [https://github.com/puppypete99/discord-rce-exploit-poc-2023-04](https://github.com/puppypete99/discord-rce-exploit-poc-2023-04) :  ![starts](https://img.shields.io/github/stars/puppypete99/discord-rce-exploit-poc-2023-04.svg) ![forks](https://img.shields.io/github/forks/puppypete99/discord-rce-exploit-poc-2023-04.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/LayarKacaSiber/CVE-2021-41773](https://github.com/LayarKacaSiber/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/LayarKacaSiber/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/LayarKacaSiber/CVE-2021-41773.svg)
- [https://github.com/MatanelGordon/docker-cve-2021-41773](https://github.com/MatanelGordon/docker-cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/MatanelGordon/docker-cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/MatanelGordon/docker-cve-2021-41773.svg)


## CVE-2021-26855
 Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-26412, CVE-2021-26854, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065, CVE-2021-27078.

- [https://github.com/iceberg-N/cve-2021-26855](https://github.com/iceberg-N/cve-2021-26855) :  ![starts](https://img.shields.io/github/stars/iceberg-N/cve-2021-26855.svg) ![forks](https://img.shields.io/github/forks/iceberg-N/cve-2021-26855.svg)


## CVE-2021-3166
 An issue was discovered on ASUS DSL-N14U-B1 1.1.2.3_805 devices. An attacker can upload arbitrary file content as a firmware update when the filename Settings_DSL-N14U-B1.trx is used. Once this file is loaded, shutdown measures on a wide range of services are triggered as if it were a real update, resulting in a persistent outage of those services.

- [https://github.com/kaisersource/CVE-2021-3166](https://github.com/kaisersource/CVE-2021-3166) :  ![starts](https://img.shields.io/github/stars/kaisersource/CVE-2021-3166.svg) ![forks](https://img.shields.io/github/forks/kaisersource/CVE-2021-3166.svg)


## CVE-2020-35488
 The fileop module of the NXLog service in NXLog Community Edition 2.10.2150 allows remote attackers to cause a denial of service (daemon crash) via a crafted Syslog payload to the Syslog service. This attack requires a specific configuration. Also, the name of the directory created must use a Syslog field. (For example, on Linux it is not possible to create a .. directory. On Windows, it is not possible to create a CON directory.)

- [https://github.com/GuillaumePetit84/CVE-2020-35488](https://github.com/GuillaumePetit84/CVE-2020-35488) :  ![starts](https://img.shields.io/github/stars/GuillaumePetit84/CVE-2020-35488.svg) ![forks](https://img.shields.io/github/forks/GuillaumePetit84/CVE-2020-35488.svg)


## CVE-2019-9081
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was withdrawn by its CNA. Further investigation showed that it was not a security issue. Notes: none.

- [https://github.com/qafdevsec/CVE-2019-9081_PoC](https://github.com/qafdevsec/CVE-2019-9081_PoC) :  ![starts](https://img.shields.io/github/stars/qafdevsec/CVE-2019-9081_PoC.svg) ![forks](https://img.shields.io/github/forks/qafdevsec/CVE-2019-9081_PoC.svg)


## CVE-2018-1335
 From Apache Tika versions 1.7 to 1.17, clients could send carefully crafted headers to tika-server that could be used to inject commands into the command line of the server running tika-server. This vulnerability only affects those running tika-server on a server that is open to untrusted clients. The mitigation is to upgrade to Tika 1.18.

- [https://github.com/Zebra64/CVE-2018-1335](https://github.com/Zebra64/CVE-2018-1335) :  ![starts](https://img.shields.io/github/stars/Zebra64/CVE-2018-1335.svg) ![forks](https://img.shields.io/github/forks/Zebra64/CVE-2018-1335.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/cbk914/heartbleed-checker](https://github.com/cbk914/heartbleed-checker) :  ![starts](https://img.shields.io/github/stars/cbk914/heartbleed-checker.svg) ![forks](https://img.shields.io/github/forks/cbk914/heartbleed-checker.svg)


## CVE-2010-2075
 UnrealIRCd 3.2.8.1, as distributed on certain mirror sites from November 2009 through June 2010, contains an externally introduced modification (Trojan Horse) in the DEBUG3_DOLOG_SYSTEM macro, which allows remote attackers to execute arbitrary commands.

- [https://github.com/chancej715/UnrealIRCD-3.2.8.1-Backdoor-Command-Execution](https://github.com/chancej715/UnrealIRCD-3.2.8.1-Backdoor-Command-Execution) :  ![starts](https://img.shields.io/github/stars/chancej715/UnrealIRCD-3.2.8.1-Backdoor-Command-Execution.svg) ![forks](https://img.shields.io/github/forks/chancej715/UnrealIRCD-3.2.8.1-Backdoor-Command-Execution.svg)

