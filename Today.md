# Update 2023-09-24
## CVE-2023-43326
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/ahrixia/CVE-2023-43326](https://github.com/ahrixia/CVE-2023-43326) :  ![starts](https://img.shields.io/github/stars/ahrixia/CVE-2023-43326.svg) ![forks](https://img.shields.io/github/forks/ahrixia/CVE-2023-43326.svg)


## CVE-2023-43325
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/ahrixia/CVE-2023-43325](https://github.com/ahrixia/CVE-2023-43325) :  ![starts](https://img.shields.io/github/stars/ahrixia/CVE-2023-43325.svg) ![forks](https://img.shields.io/github/forks/ahrixia/CVE-2023-43325.svg)


## CVE-2023-43154
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/ally-petitt/CVE-2023-43154-PoC](https://github.com/ally-petitt/CVE-2023-43154-PoC) :  ![starts](https://img.shields.io/github/stars/ally-petitt/CVE-2023-43154-PoC.svg) ![forks](https://img.shields.io/github/forks/ally-petitt/CVE-2023-43154-PoC.svg)


## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/DimaMend/cve-2022-42889-text4shell](https://github.com/DimaMend/cve-2022-42889-text4shell) :  ![starts](https://img.shields.io/github/stars/DimaMend/cve-2022-42889-text4shell.svg) ![forks](https://img.shields.io/github/forks/DimaMend/cve-2022-42889-text4shell.svg)


## CVE-2022-34753
 A CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') vulnerability exists that could cause remote root exploit when the command is compromised. Affected Products: SpaceLogic C-Bus Home Controller (5200WHC2), formerly known as C-Bus Wiser Homer Controller MK2 (V1.31.460 and prior)

- [https://github.com/K3ysTr0K3R/CVE-2022-34753-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2022-34753-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2022-34753-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2022-34753-EXPLOIT.svg)


## CVE-2022-28113
 An issue in upload.csp of FANTEC GmbH MWiD25-DS Firmware v2.000.030 allows attackers to write files and reset the user passwords without having a valid session cookie.

- [https://github.com/code-byter/CVE-2022-28113](https://github.com/code-byter/CVE-2022-28113) :  ![starts](https://img.shields.io/github/stars/code-byter/CVE-2022-28113.svg) ![forks](https://img.shields.io/github/forks/code-byter/CVE-2022-28113.svg)


## CVE-2022-4510
 A path traversal vulnerability was identified in ReFirm Labs binwalk from version 2.1.2b through 2.3.3 included. By crafting a malicious PFS filesystem file, an attacker can get binwalk's PFS extractor to extract files at arbitrary locations when binwalk is run in extraction mode (-e option). Remote code execution can be achieved by building a PFS filesystem that, upon extraction, would extract a malicious binwalk module into the folder .config/binwalk/plugins. This vulnerability is associated with program files src/binwalk/plugins/unpfs.py. This issue affects binwalk from 2.1.2b through 2.3.3 included.

- [https://github.com/electr0sm0g/CVE-2022-4510](https://github.com/electr0sm0g/CVE-2022-4510) :  ![starts](https://img.shields.io/github/stars/electr0sm0g/CVE-2022-4510.svg) ![forks](https://img.shields.io/github/forks/electr0sm0g/CVE-2022-4510.svg)


## CVE-2021-38149
 index.php/admin/add_user in Chikitsa Patient Management System 2.0.0 allows XSS.

- [https://github.com/jboogie15/CVE-2021-38149](https://github.com/jboogie15/CVE-2021-38149) :  ![starts](https://img.shields.io/github/stars/jboogie15/CVE-2021-38149.svg) ![forks](https://img.shields.io/github/forks/jboogie15/CVE-2021-38149.svg)


## CVE-2021-35464
 ForgeRock AM server before 7.0 has a Java deserialization vulnerability in the jato.pageSession parameter on multiple pages. The exploitation does not require authentication, and remote code execution can be triggered by sending a single crafted /ccversion/* request to the server. The vulnerability exists due to the usage of Sun ONE Application Framework (JATO) found in versions of Java 8 or earlier

- [https://github.com/Y4er/openam-CVE-2021-35464](https://github.com/Y4er/openam-CVE-2021-35464) :  ![starts](https://img.shields.io/github/stars/Y4er/openam-CVE-2021-35464.svg) ![forks](https://img.shields.io/github/forks/Y4er/openam-CVE-2021-35464.svg)


## CVE-2021-3438
 A potential buffer overflow in the software drivers for certain HP LaserJet products and Samsung product printers could lead to an escalation of privilege.

- [https://github.com/CrackerCat/CVE-2021-3438](https://github.com/CrackerCat/CVE-2021-3438) :  ![starts](https://img.shields.io/github/stars/CrackerCat/CVE-2021-3438.svg) ![forks](https://img.shields.io/github/forks/CrackerCat/CVE-2021-3438.svg)


## CVE-2020-35191
 The official drupal docker images before 8.5.10-fpm-alpine (Alpine specific) contain a blank password for a root user. System using the drupal docker container deployed by affected versions of the docker image may allow a remote attacker to achieve root access with a blank password.

- [https://github.com/megadimenex/MegaHiDocker](https://github.com/megadimenex/MegaHiDocker) :  ![starts](https://img.shields.io/github/stars/megadimenex/MegaHiDocker.svg) ![forks](https://img.shields.io/github/forks/megadimenex/MegaHiDocker.svg)


## CVE-2018-1273
 Spring Data Commons, versions prior to 1.13 to 1.13.10, 2.0 to 2.0.5, and older unsupported versions, contain a property binder vulnerability caused by improper neutralization of special elements. An unauthenticated remote malicious user (or attacker) can supply specially crafted request parameters against Spring Data REST backed HTTP resources or using Spring Data's projection-based request payload binding hat can lead to a remote code execution attack.

- [https://github.com/cved-sources/cve-2018-1273](https://github.com/cved-sources/cve-2018-1273) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2018-1273.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2018-1273.svg)


## CVE-2017-8570
 Microsoft Office allows a remote code execution vulnerability due to the way that it handles objects in memory, aka &quot;Microsoft Office Remote Code Execution Vulnerability&quot;. This CVE ID is unique from CVE-2017-0243.

- [https://github.com/temesgeny/ppsx-file-generator](https://github.com/temesgeny/ppsx-file-generator) :  ![starts](https://img.shields.io/github/stars/temesgeny/ppsx-file-generator.svg) ![forks](https://img.shields.io/github/forks/temesgeny/ppsx-file-generator.svg)

