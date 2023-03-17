# Update 2023-03-17
## CVE-2023-27587
 ReadtoMyShoe, a web app that lets users upload articles and listen to them later, generates an error message containing sensitive information prior to commit 8533b01. If an error occurs when adding an article, the website shows the user an error message. If the error originates from the Google Cloud TTS request, then it will include the full URL of the request. The request URL contains the Google Cloud API key. This has been patched in commit 8533b01. Upgrading should be accompanied by deleting the current GCP API key and issuing a new one. There are no known workarounds.

- [https://github.com/sec-fx/CVE-2023-27587-PoC](https://github.com/sec-fx/CVE-2023-27587-PoC) :  ![starts](https://img.shields.io/github/stars/sec-fx/CVE-2023-27587-PoC.svg) ![forks](https://img.shields.io/github/forks/sec-fx/CVE-2023-27587-PoC.svg)


## CVE-2023-23924
 Dompdf is an HTML to PDF converter. The URI validation on dompdf 2.0.1 can be bypassed on SVG parsing by passing `&lt;image&gt;` tags with uppercase letters. This may lead to arbitrary object unserialize on PHP &lt; 8, through the `phar` URL wrapper. An attacker can exploit the vulnerability to call arbitrary URL with arbitrary protocols, if they can provide a SVG file to dompdf. In PHP versions before 8.0.0, it leads to arbitrary unserialize, that will lead to the very least to an arbitrary file deletion and even remote code execution, depending on classes that are available.

- [https://github.com/zeverse/CVE-2023-23924-sample](https://github.com/zeverse/CVE-2023-23924-sample) :  ![starts](https://img.shields.io/github/stars/zeverse/CVE-2023-23924-sample.svg) ![forks](https://img.shields.io/github/forks/zeverse/CVE-2023-23924-sample.svg)


## CVE-2023-23397
 Microsoft Outlook Elevation of Privilege Vulnerability

- [https://github.com/sqrtZeroKnowledge/CVE-2023-23397_EXPLOIT_0DAY](https://github.com/sqrtZeroKnowledge/CVE-2023-23397_EXPLOIT_0DAY) :  ![starts](https://img.shields.io/github/stars/sqrtZeroKnowledge/CVE-2023-23397_EXPLOIT_0DAY.svg) ![forks](https://img.shields.io/github/forks/sqrtZeroKnowledge/CVE-2023-23397_EXPLOIT_0DAY.svg)


## CVE-2023-1415
 A vulnerability was found in Simple Art Gallery 1.0. It has been declared as critical. This vulnerability affects the function sliderPicSubmit of the file adminHome.php. The manipulation leads to unrestricted upload. The attack can be initiated remotely. VDB-223126 is the identifier assigned to this vulnerability.

- [https://github.com/0xxtoby/CVE-2023-1415-](https://github.com/0xxtoby/CVE-2023-1415-) :  ![starts](https://img.shields.io/github/stars/0xxtoby/CVE-2023-1415-.svg) ![forks](https://img.shields.io/github/forks/0xxtoby/CVE-2023-1415-.svg)


## CVE-2023-0179
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/H4K6/CVE-2023-0179-PoC](https://github.com/H4K6/CVE-2023-0179-PoC) :  ![starts](https://img.shields.io/github/stars/H4K6/CVE-2023-0179-PoC.svg) ![forks](https://img.shields.io/github/forks/H4K6/CVE-2023-0179-PoC.svg)


## CVE-2022-42475
 A heap-based buffer overflow vulnerability [CWE-122] in FortiOS SSL-VPN 7.2.0 through 7.2.2, 7.0.0 through 7.0.8, 6.4.0 through 6.4.10, 6.2.0 through 6.2.11, 6.0.15 and earlier and FortiProxy SSL-VPN 7.2.0 through 7.2.1, 7.0.7 and earlier may allow a remote unauthenticated attacker to execute arbitrary code or commands via specifically crafted requests.

- [https://github.com/Amir-hy/cve-2022-42475](https://github.com/Amir-hy/cve-2022-42475) :  ![starts](https://img.shields.io/github/stars/Amir-hy/cve-2022-42475.svg) ![forks](https://img.shields.io/github/forks/Amir-hy/cve-2022-42475.svg)


## CVE-2022-30136
 Windows Network File System Remote Code Execution Vulnerability.

- [https://github.com/fortra/CVE-2022-30136](https://github.com/fortra/CVE-2022-30136) :  ![starts](https://img.shields.io/github/stars/fortra/CVE-2022-30136.svg) ![forks](https://img.shields.io/github/forks/fortra/CVE-2022-30136.svg)


## CVE-2022-22947
 In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

- [https://github.com/wallbreak1991/cve-2022-22947](https://github.com/wallbreak1991/cve-2022-22947) :  ![starts](https://img.shields.io/github/stars/wallbreak1991/cve-2022-22947.svg) ![forks](https://img.shields.io/github/forks/wallbreak1991/cve-2022-22947.svg)


## CVE-2022-1026
 Kyocera multifunction printers running vulnerable versions of Net View unintentionally expose sensitive user information, including usernames and passwords, through an insufficiently protected address book export function.

- [https://github.com/ac3lives/kyocera-cve-2022-1026](https://github.com/ac3lives/kyocera-cve-2022-1026) :  ![starts](https://img.shields.io/github/stars/ac3lives/kyocera-cve-2022-1026.svg) ![forks](https://img.shields.io/github/forks/ac3lives/kyocera-cve-2022-1026.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/wolf1892/CVE-2021-41773](https://github.com/wolf1892/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/wolf1892/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/wolf1892/CVE-2021-41773.svg)
- [https://github.com/honypot/CVE-2021-41773](https://github.com/honypot/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/honypot/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/honypot/CVE-2021-41773.svg)


## CVE-2021-21234
 spring-boot-actuator-logview in a library that adds a simple logfile viewer as spring boot actuator endpoint. It is maven package &quot;eu.hinsch:spring-boot-actuator-logview&quot;. In spring-boot-actuator-logview before version 0.2.13 there is a directory traversal vulnerability. The nature of this library is to expose a log file directory via admin (spring boot actuator) HTTP endpoints. Both the filename to view and a base folder (relative to the logging folder root) can be specified via request parameters. While the filename parameter was checked to prevent directory traversal exploits (so that `filename=../somefile` would not work), the base folder parameter was not sufficiently checked, so that `filename=somefile&amp;base=../` could access a file outside the logging base directory). The vulnerability has been patched in release 0.2.13. Any users of 0.2.12 should be able to update without any issues as there are no other changes in that release. There is no workaround to fix the vulnerability other than updating or removing the dependency. However, removing read access of the user the application is run with to any directory not required for running the application can limit the impact. Additionally, access to the logview endpoint can be limited by deploying the application behind a reverse proxy.

- [https://github.com/PwCNO-CTO/CVE-2021-21234](https://github.com/PwCNO-CTO/CVE-2021-21234) :  ![starts](https://img.shields.io/github/stars/PwCNO-CTO/CVE-2021-21234.svg) ![forks](https://img.shields.io/github/forks/PwCNO-CTO/CVE-2021-21234.svg)


## CVE-2021-0399
 In qtaguid_untag of xt_qtaguid.c, there is a possible memory corruption due to a use after free. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-176919394References: Upstream kernel

- [https://github.com/nipund513/Exploiting-UAF-by-Ret2bpf-in-Android-Kernel-CVE-2021-0399-](https://github.com/nipund513/Exploiting-UAF-by-Ret2bpf-in-Android-Kernel-CVE-2021-0399-) :  ![starts](https://img.shields.io/github/stars/nipund513/Exploiting-UAF-by-Ret2bpf-in-Android-Kernel-CVE-2021-0399-.svg) ![forks](https://img.shields.io/github/forks/nipund513/Exploiting-UAF-by-Ret2bpf-in-Android-Kernel-CVE-2021-0399-.svg)


## CVE-2020-7388
 Sage X3 Unauthenticated Remote Command Execution (RCE) as SYSTEM in AdxDSrv.exe component. By editing the client side authentication request, an attacker can bypass credential validation. While exploiting this does require knowledge of the installation path, that information can be learned by exploiting CVE-2020-7387. This issue was fixed in AdxAdmin 93.2.53, which ships with updates for on-premises versions of Sage X3 including Version 9 (components shipped with Syracuse 9.22.7.2 and later), Sage X3 HR &amp; Payroll Version 9 (those components that ship with Syracuse 9.24.1.3), Version 11 (components shipped with Syracuse 11.25.2.6 and later), and Version 12 (components shipped with Syracuse 12.10.2.8 and later) of Sage X3. Other on-premises versions of Sage X3 are unsupported by the vendor.

- [https://github.com/ac3lives/sagex3-cve-2020-7388-poc](https://github.com/ac3lives/sagex3-cve-2020-7388-poc) :  ![starts](https://img.shields.io/github/stars/ac3lives/sagex3-cve-2020-7388-poc.svg) ![forks](https://img.shields.io/github/forks/ac3lives/sagex3-cve-2020-7388-poc.svg)


## CVE-2020-1206
 An information disclosure vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Information Disclosure Vulnerability'.

- [https://github.com/Info-Security-Solution-Kolkata/Smbleed-CVE-2020-1206-Exploit](https://github.com/Info-Security-Solution-Kolkata/Smbleed-CVE-2020-1206-Exploit) :  ![starts](https://img.shields.io/github/stars/Info-Security-Solution-Kolkata/Smbleed-CVE-2020-1206-Exploit.svg) ![forks](https://img.shields.io/github/forks/Info-Security-Solution-Kolkata/Smbleed-CVE-2020-1206-Exploit.svg)


## CVE-2019-14271
 In Docker 19.03.x before 19.03.1 linked against the GNU C Library (aka glibc), code injection can occur when the nsswitch facility dynamically loads a library inside a chroot that contains the contents of the container.

- [https://github.com/iridium-soda/CVE-2019-14271_Exploit](https://github.com/iridium-soda/CVE-2019-14271_Exploit) :  ![starts](https://img.shields.io/github/stars/iridium-soda/CVE-2019-14271_Exploit.svg) ![forks](https://img.shields.io/github/forks/iridium-soda/CVE-2019-14271_Exploit.svg)


## CVE-2018-25032
 zlib before 1.2.12 allows memory corruption when deflating (i.e., when compressing) if the input has many distant matches.

- [https://github.com/Trinadh465/external_zlib_AOSP10_r33_CVE-2018-25032](https://github.com/Trinadh465/external_zlib_AOSP10_r33_CVE-2018-25032) :  ![starts](https://img.shields.io/github/stars/Trinadh465/external_zlib_AOSP10_r33_CVE-2018-25032.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/external_zlib_AOSP10_r33_CVE-2018-25032.svg)


## CVE-2018-0114
 A vulnerability in the Cisco node-jose open source library before 0.11.0 could allow an unauthenticated, remote attacker to re-sign tokens using a key that is embedded within the token. The vulnerability is due to node-jose following the JSON Web Signature (JWS) standard for JSON Web Tokens (JWTs). This standard specifies that a JSON Web Key (JWK) representing a public key can be embedded within the header of a JWS. This public key is then trusted for verification. An attacker could exploit this by forging valid JWS objects by removing the original signature, adding a new public key to the header, and then signing the object using the (attacker-owned) private key associated with the public key embedded in that JWS header.

- [https://github.com/amr9k8/jwt-spoof-tool](https://github.com/amr9k8/jwt-spoof-tool) :  ![starts](https://img.shields.io/github/stars/amr9k8/jwt-spoof-tool.svg) ![forks](https://img.shields.io/github/forks/amr9k8/jwt-spoof-tool.svg)

