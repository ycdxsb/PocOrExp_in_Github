# Update 2024-07-20
## CVE-2024-31989
 Argo CD is a declarative, GitOps continuous delivery tool for Kubernetes. It has been discovered that an unprivileged pod in a different namespace on the same cluster could connect to the Redis server on port 6379. Despite having installed the latest version of the VPC CNI plugin on the EKS cluster, it requires manual enablement through configuration to enforce network policies. This raises concerns that many clients might unknowingly have open access to their Redis servers. This vulnerability could lead to Privilege Escalation to the level of cluster controller, or to information leakage, affecting anyone who does not have strict access controls on their Redis instance. This issue has been patched in version(s) 2.8.19, 2.9.15 and 2.10.10.

- [https://github.com/vt0x78/CVE-2024-31989](https://github.com/vt0x78/CVE-2024-31989) :  ![starts](https://img.shields.io/github/stars/vt0x78/CVE-2024-31989.svg) ![forks](https://img.shields.io/github/forks/vt0x78/CVE-2024-31989.svg)


## CVE-2024-22274
 The vCenter Server contains an authenticated remote code execution vulnerability. A malicious actor with administrative privileges on the vCenter appliance shell may exploit this issue to run arbitrary commands on the underlying operating system.

- [https://github.com/Mustafa1986/CVE-2024-22274-RCE](https://github.com/Mustafa1986/CVE-2024-22274-RCE) :  ![starts](https://img.shields.io/github/stars/Mustafa1986/CVE-2024-22274-RCE.svg) ![forks](https://img.shields.io/github/forks/Mustafa1986/CVE-2024-22274-RCE.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use &quot;Best-Fit&quot; behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/nNoSuger/CVE-2024-4577](https://github.com/nNoSuger/CVE-2024-4577) :  ![starts](https://img.shields.io/github/stars/nNoSuger/CVE-2024-4577.svg) ![forks](https://img.shields.io/github/forks/nNoSuger/CVE-2024-4577.svg)


## CVE-2024-4089
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/TAM-K592/CVE-2024-40725-CVE-2024-40898](https://github.com/TAM-K592/CVE-2024-40725-CVE-2024-40898) :  ![starts](https://img.shields.io/github/stars/TAM-K592/CVE-2024-40725-CVE-2024-40898.svg) ![forks](https://img.shields.io/github/forks/TAM-K592/CVE-2024-40725-CVE-2024-40898.svg)


## CVE-2024-4072
 A vulnerability was found in Kashipara Online Furniture Shopping Ecommerce Website 1.0. It has been classified as problematic. Affected is an unknown function of the file search.php. The manipulation of the argument txtSearch leads to cross site scripting. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. VDB-261798 is the identifier assigned to this vulnerability.

- [https://github.com/TAM-K592/CVE-2024-40725-CVE-2024-40898](https://github.com/TAM-K592/CVE-2024-40725-CVE-2024-40898) :  ![starts](https://img.shields.io/github/stars/TAM-K592/CVE-2024-40725-CVE-2024-40898.svg) ![forks](https://img.shields.io/github/forks/TAM-K592/CVE-2024-40725-CVE-2024-40898.svg)


## CVE-2024-1874
 In PHP versions 8.1.* before 8.1.28, 8.2.* before 8.2.18, 8.3.* before 8.3.5, when using proc_open() command with array syntax, due to insufficient escaping, if the arguments of the executed command are controlled by a malicious user, the user can supply arguments that would execute arbitrary commands in Windows shell.

- [https://github.com/Tgcohce/CVE-2024-1874](https://github.com/Tgcohce/CVE-2024-1874) :  ![starts](https://img.shields.io/github/stars/Tgcohce/CVE-2024-1874.svg) ![forks](https://img.shields.io/github/forks/Tgcohce/CVE-2024-1874.svg)


## CVE-2024-0056
 Microsoft.Data.SqlClient and System.Data.SqlClient SQL Data Provider Security Feature Bypass Vulnerability

- [https://github.com/frederickernest/ManInTheMiddle](https://github.com/frederickernest/ManInTheMiddle) :  ![starts](https://img.shields.io/github/stars/frederickernest/ManInTheMiddle.svg) ![forks](https://img.shields.io/github/forks/frederickernest/ManInTheMiddle.svg)


## CVE-2023-22515
 Atlassian has been made aware of an issue reported by a handful of customers where external attackers may have exploited a previously unknown vulnerability in publicly accessible Confluence Data Center and Server instances to create unauthorized Confluence administrator accounts and access Confluence instances. Atlassian Cloud sites are not affected by this vulnerability. If your Confluence site is accessed via an atlassian.net domain, it is hosted by Atlassian and is not vulnerable to this issue.

- [https://github.com/spareack/CVE-2023-22515-NSE](https://github.com/spareack/CVE-2023-22515-NSE) :  ![starts](https://img.shields.io/github/stars/spareack/CVE-2023-22515-NSE.svg) ![forks](https://img.shields.io/github/forks/spareack/CVE-2023-22515-NSE.svg)


## CVE-2023-20872
 VMware Workstation and Fusion contain an out-of-bounds read/write vulnerability in SCSI CD/DVD device emulation.

- [https://github.com/ze0r/vmware-escape-CVE-2023-20872-poc](https://github.com/ze0r/vmware-escape-CVE-2023-20872-poc) :  ![starts](https://img.shields.io/github/stars/ze0r/vmware-escape-CVE-2023-20872-poc.svg) ![forks](https://img.shields.io/github/forks/ze0r/vmware-escape-CVE-2023-20872-poc.svg)


## CVE-2023-3824
 In PHP version 8.0.* before 8.0.30, 8.1.* before 8.1.22, and 8.2.* before 8.2.8, when loading phar file, while reading PHAR directory entries, insufficient length checking may lead to a stack buffer overflow, leading potentially to memory corruption or RCE.

- [https://github.com/m1sn0w/CVE-2023-3824](https://github.com/m1sn0w/CVE-2023-3824) :  ![starts](https://img.shields.io/github/stars/m1sn0w/CVE-2023-3824.svg) ![forks](https://img.shields.io/github/forks/m1sn0w/CVE-2023-3824.svg)


## CVE-2022-30780
 Lighttpd 1.4.56 through 1.4.58 allows a remote attacker to cause a denial of service (CPU consumption from stuck connections) because connection_read_header_more in connections.c has a typo that disrupts use of multiple read operations on large headers.

- [https://github.com/xiw1ll/CVE-2022-30780_Checker](https://github.com/xiw1ll/CVE-2022-30780_Checker) :  ![starts](https://img.shields.io/github/stars/xiw1ll/CVE-2022-30780_Checker.svg) ![forks](https://img.shields.io/github/forks/xiw1ll/CVE-2022-30780_Checker.svg)


## CVE-2022-0155
 follow-redirects is vulnerable to Exposure of Private Personal Information to an Unauthorized Actor

- [https://github.com/coana-tech/CVE-2022-0155-PoC](https://github.com/coana-tech/CVE-2022-0155-PoC) :  ![starts](https://img.shields.io/github/stars/coana-tech/CVE-2022-0155-PoC.svg) ![forks](https://img.shields.io/github/forks/coana-tech/CVE-2022-0155-PoC.svg)


## CVE-2021-21239
 PySAML2 is a pure python implementation of SAML Version 2 Standard. PySAML2 before 6.5.0 has an improper verification of cryptographic signature vulnerability. Users of pysaml2 that use the default CryptoBackendXmlSec1 backend and need to verify signed SAML documents are impacted. PySAML2 does not ensure that a signed SAML document is correctly signed. The default CryptoBackendXmlSec1 backend is using the xmlsec1 binary to verify the signature of signed SAML documents, but by default xmlsec1 accepts any type of key found within the given document. xmlsec1 needs to be configured explicitly to only use only _x509 certificates_ for the verification process of the SAML document signature. This is fixed in PySAML2 6.5.0.

- [https://github.com/RyanBoomer30/CVE-2021-21239-Exploit](https://github.com/RyanBoomer30/CVE-2021-21239-Exploit) :  ![starts](https://img.shields.io/github/stars/RyanBoomer30/CVE-2021-21239-Exploit.svg) ![forks](https://img.shields.io/github/forks/RyanBoomer30/CVE-2021-21239-Exploit.svg)


## CVE-2020-13945
 In Apache APISIX, the user enabled the Admin API and deleted the Admin API access IP restriction rules. Eventually, the default token is allowed to access APISIX management data. This affects versions 1.2, 1.3, 1.4, 1.5.

- [https://github.com/K3ysTr0K3R/CVE-2020-13945-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2020-13945-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2020-13945-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2020-13945-EXPLOIT.svg)


## CVE-2015-1397
 SQL injection vulnerability in the getCsvFile function in the Mage_Adminhtml_Block_Widget_Grid class in Magento Community Edition (CE) 1.9.1.0 and Enterprise Edition (EE) 1.14.1.0 allows remote administrators to execute arbitrary SQL commands via the popularity[field_expr] parameter when the popularity[from] or popularity[to] parameter is set.

- [https://github.com/Wytchwulf/CVE-2015-1397-Magento-Shoplift](https://github.com/Wytchwulf/CVE-2015-1397-Magento-Shoplift) :  ![starts](https://img.shields.io/github/stars/Wytchwulf/CVE-2015-1397-Magento-Shoplift.svg) ![forks](https://img.shields.io/github/forks/Wytchwulf/CVE-2015-1397-Magento-Shoplift.svg)


## CVE-2012-1823
 sapi/cgi/cgi_main.c in PHP before 5.3.12 and 5.4.x before 5.4.2, when configured as a CGI script (aka php-cgi), does not properly handle query strings that lack an = (equals sign) character, which allows remote attackers to execute arbitrary code by placing command-line options in the query string, related to lack of skipping a certain php_getopt for the 'd' case.

- [https://github.com/Fatalityx84/CVE-2012-1823](https://github.com/Fatalityx84/CVE-2012-1823) :  ![starts](https://img.shields.io/github/stars/Fatalityx84/CVE-2012-1823.svg) ![forks](https://img.shields.io/github/forks/Fatalityx84/CVE-2012-1823.svg)

