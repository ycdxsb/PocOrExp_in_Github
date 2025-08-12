# Update 2025-08-12
## CVE-2025-47178
 Improper neutralization of special elements used in an sql command ('sql injection') in Microsoft Configuration Manager allows an authorized attacker to execute code over an adjacent network.

- [https://github.com/synacktiv/CVE-2025-47178](https://github.com/synacktiv/CVE-2025-47178) :  ![starts](https://img.shields.io/github/stars/synacktiv/CVE-2025-47178.svg) ![forks](https://img.shields.io/github/forks/synacktiv/CVE-2025-47178.svg)


## CVE-2025-1974
 A security issue was discovered in Kubernetes where under certain conditions, an unauthenticated attacker with access to the pod network can achieve arbitrary code execution in the context of the ingress-nginx controller. This can lead to disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)

- [https://github.com/BiiTts/POC-IngressNightmare-CVE-2025-1974](https://github.com/BiiTts/POC-IngressNightmare-CVE-2025-1974) :  ![starts](https://img.shields.io/github/stars/BiiTts/POC-IngressNightmare-CVE-2025-1974.svg) ![forks](https://img.shields.io/github/forks/BiiTts/POC-IngressNightmare-CVE-2025-1974.svg)


## CVE-2024-37388
 An XML External Entity (XXE) vulnerability in the ebookmeta.get_metadata function of lxml before v4.9.1 allows attackers to access sensitive information or cause a Denial of Service (DoS) via crafted XML input.

- [https://github.com/Narsimhareddy28/cve-2024-37388](https://github.com/Narsimhareddy28/cve-2024-37388) :  ![starts](https://img.shields.io/github/stars/Narsimhareddy28/cve-2024-37388.svg) ![forks](https://img.shields.io/github/forks/Narsimhareddy28/cve-2024-37388.svg)


## CVE-2024-31317
 In multiple functions of ZygoteProcess.java, there is a possible way to achieve code execution as any app via WRITE_SECURE_SETTINGS due to unsafe deserialization. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/rifting/Zygotroller](https://github.com/rifting/Zygotroller) :  ![starts](https://img.shields.io/github/stars/rifting/Zygotroller.svg) ![forks](https://img.shields.io/github/forks/rifting/Zygotroller.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/JIYUN02/cve-2021-41773](https://github.com/JIYUN02/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/JIYUN02/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/JIYUN02/cve-2021-41773.svg)


## CVE-2020-2950
 Vulnerability in the Oracle Business Intelligence Enterprise Edition product of Oracle Fusion Middleware (component: Analytics Web General). Supported versions that are affected are 5.5.0.0.0, 11.1.1.9.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Business Intelligence Enterprise Edition. Successful attacks of this vulnerability can result in takeover of Oracle Business Intelligence Enterprise Edition. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/tuo4n8/CVE-2020-2950](https://github.com/tuo4n8/CVE-2020-2950) :  ![starts](https://img.shields.io/github/stars/tuo4n8/CVE-2020-2950.svg) ![forks](https://img.shields.io/github/forks/tuo4n8/CVE-2020-2950.svg)


## CVE-2018-8035
 This vulnerability relates to the user's browser processing of DUCC webpage input data.The javascript comprising Apache UIMA DUCC (= 2.2.2) which runs in the user's browser does not sufficiently filter user supplied inputs, which may result in unintended execution of user supplied javascript code.

- [https://github.com/ossf-cve-benchmark/CVE-2018-8035](https://github.com/ossf-cve-benchmark/CVE-2018-8035) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2018-8035.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2018-8035.svg)


## CVE-2016-10033
 The mailSend function in the isMail transport in PHPMailer before 5.2.18 might allow remote attackers to pass extra parameters to the mail command and consequently execute arbitrary code via a \" (backslash double quote) in a crafted Sender property.

- [https://github.com/alexander47777/CVE-2016-10033](https://github.com/alexander47777/CVE-2016-10033) :  ![starts](https://img.shields.io/github/stars/alexander47777/CVE-2016-10033.svg) ![forks](https://img.shields.io/github/forks/alexander47777/CVE-2016-10033.svg)


## CVE-2015-10141
 An unauthenticated OS command injection vulnerability exists within Xdebug versions 2.5.5 and earlier, a PHP debugging extension developed by Derick Rethans. When remote debugging is enabled, Xdebug listens on port 9000 and accepts debugger protocol commands without authentication. An attacker can send a crafted eval command over this interface to execute arbitrary PHP code, which may invoke system-level functions such as system() or passthru(). This results in full compromise of the host under the privileges of the web server user.

- [https://github.com/D3Ext/CVE-2015-10141](https://github.com/D3Ext/CVE-2015-10141) :  ![starts](https://img.shields.io/github/stars/D3Ext/CVE-2015-10141.svg) ![forks](https://img.shields.io/github/forks/D3Ext/CVE-2015-10141.svg)


## CVE-2015-4133
 Unrestricted file upload vulnerability in admin/scripts/FileUploader/php.php in the ReFlex Gallery plugin before 3.1.4 for WordPress allows remote attackers to execute arbitrary PHP code by uploading a file with a PHP extension, then accessing it via a direct request to the file in uploads/ directory.

- [https://github.com/D3Ext/CVE-2015-4133](https://github.com/D3Ext/CVE-2015-4133) :  ![starts](https://img.shields.io/github/stars/D3Ext/CVE-2015-4133.svg) ![forks](https://img.shields.io/github/forks/D3Ext/CVE-2015-4133.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/BolivarJ/CVE-2011-2523](https://github.com/BolivarJ/CVE-2011-2523) :  ![starts](https://img.shields.io/github/stars/BolivarJ/CVE-2011-2523.svg) ![forks](https://img.shields.io/github/forks/BolivarJ/CVE-2011-2523.svg)

