# Update 2021-10-07
## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the expected document root. If files outside of the document root are not protected by &quot;require all denied&quot; these requests can succeed. Additionally this flaw could leak the source of interpreted files like CGI scripts. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions.

- [https://github.com/Vulnmachines/cve-2021-41773](https://github.com/Vulnmachines/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/cve-2021-41773.svg)
- [https://github.com/RyouYoo/CVE-2021-41773](https://github.com/RyouYoo/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/RyouYoo/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/RyouYoo/CVE-2021-41773.svg)
- [https://github.com/ZephrFish/CVE-2021-41773-PoC](https://github.com/ZephrFish/CVE-2021-41773-PoC) :  ![starts](https://img.shields.io/github/stars/ZephrFish/CVE-2021-41773-PoC.svg) ![forks](https://img.shields.io/github/forks/ZephrFish/CVE-2021-41773-PoC.svg)
- [https://github.com/iilegacyyii/PoC-CVE-2021-41773](https://github.com/iilegacyyii/PoC-CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/iilegacyyii/PoC-CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/iilegacyyii/PoC-CVE-2021-41773.svg)
- [https://github.com/numanturle/CVE-2021-41773](https://github.com/numanturle/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/numanturle/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/numanturle/CVE-2021-41773.svg)
- [https://github.com/knqyf263/CVE-2021-41773](https://github.com/knqyf263/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/knqyf263/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/knqyf263/CVE-2021-41773.svg)
- [https://github.com/TishcaTpx/POC-CVE-2021-41773](https://github.com/TishcaTpx/POC-CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/TishcaTpx/POC-CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/TishcaTpx/POC-CVE-2021-41773.svg)
- [https://github.com/lorddemon/CVE-2021-41773-PoC](https://github.com/lorddemon/CVE-2021-41773-PoC) :  ![starts](https://img.shields.io/github/stars/lorddemon/CVE-2021-41773-PoC.svg) ![forks](https://img.shields.io/github/forks/lorddemon/CVE-2021-41773-PoC.svg)
- [https://github.com/masahiro331/CVE-2021-41773](https://github.com/masahiro331/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/masahiro331/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/masahiro331/CVE-2021-41773.svg)
- [https://github.com/habibiefaried/CVE-2021-41773-PoC](https://github.com/habibiefaried/CVE-2021-41773-PoC) :  ![starts](https://img.shields.io/github/stars/habibiefaried/CVE-2021-41773-PoC.svg) ![forks](https://img.shields.io/github/forks/habibiefaried/CVE-2021-41773-PoC.svg)
- [https://github.com/creadpag/CVE-2021-41773-POC](https://github.com/creadpag/CVE-2021-41773-POC) :  ![starts](https://img.shields.io/github/stars/creadpag/CVE-2021-41773-POC.svg) ![forks](https://img.shields.io/github/forks/creadpag/CVE-2021-41773-POC.svg)
- [https://github.com/TishcaTpx/cve-2021-41773-nse](https://github.com/TishcaTpx/cve-2021-41773-nse) :  ![starts](https://img.shields.io/github/stars/TishcaTpx/cve-2021-41773-nse.svg) ![forks](https://img.shields.io/github/forks/TishcaTpx/cve-2021-41773-nse.svg)
- [https://github.com/trungnd51/CVE-2021-41773](https://github.com/trungnd51/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/trungnd51/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/trungnd51/CVE-2021-41773.svg)
- [https://github.com/itsecurityco/CVE-2021-41773](https://github.com/itsecurityco/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/itsecurityco/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/itsecurityco/CVE-2021-41773.svg)
- [https://github.com/lsass-exe/CVE-2021-41773](https://github.com/lsass-exe/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/lsass-exe/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/lsass-exe/CVE-2021-41773.svg)


## CVE-2021-41764
 A cross-site request forgery (CSRF) vulnerability exists in Streama up to and including v1.10.3. The application does not have CSRF checks in place when performing actions such as uploading local files. As a result, attackers could make a logged-in administrator upload arbitrary local files via a CSRF attack and send them to the attacker.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41764](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41764) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41764.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41764.svg)


## CVE-2021-41720
 ** DISPUTED ** A command injection vulnerability in Lodash 4.17.21 allows attackers to achieve arbitrary code execution via the template function. This is a different parameter, method, and version than CVE-2021-23337. NOTE: the vendor's position is that it's the developer's responsibility to ensure that a template does not evaluate code that originates from untrusted input.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41720](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41720) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41720.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41720.svg)


## CVE-2021-41617
 sshd in OpenSSH 6.2 through 8.x before 8.8, when certain non-default configurations are used, allows privilege escalation because supplemental groups are not initialized as expected. Helper programs for AuthorizedKeysCommand and AuthorizedPrincipalsCommand may run with privileges associated with group memberships of the sshd process, if the configuration specifies running the command as a different user.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41617](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41617) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41617.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41617.svg)


## CVE-2021-41588
 In Gradle Enterprise before 2021.1.3, a crafted request can trigger deserialization of arbitrary unsafe Java objects. The attacker must have the encryption and signing keys.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41588](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41588) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41588.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41588.svg)


## CVE-2021-41587
 In Gradle Enterprise before 2021.1.3, an attacker with the ability to perform SSRF attacks can potentially discover credentials for other resources.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41587](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41587) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41587.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41587.svg)


## CVE-2021-41586
 In Gradle Enterprise before 2021.1.3, an attacker with the ability to perform SSRF attacks can potentially reset the system user password.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41586](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41586) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41586.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41586.svg)


## CVE-2021-41584
 Gradle Enterprise before 2021.1.3 can allow unauthorized viewing of a response (information disclosure of possibly sensitive build/configuration details) via a crafted HTTP request with the X-Gradle-Enterprise-Ajax-Request header.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41584](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41584) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41584.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41584.svg)


## CVE-2021-41581
 x509_constraints_parse_mailbox in lib/libcrypto/x509/x509_constraints.c in LibreSSL through 3.4.0 has a stack-based buffer over-read. When the input exceeds DOMAIN_PART_MAX_LEN, the buffer lacks '\0' termination.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41581](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41581) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41581.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41581.svg)


## CVE-2021-41558
 The set_user extension module before 3.0.0 for PostgreSQL allows ProcessUtility_hook bypass via set_config.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41558](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41558) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41558.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41558.svg)


## CVE-2021-41540
 A vulnerability has been identified in Solid Edge SE2021 (All versions &lt; SE2021MP8). The affected application contains a use-after-free vulnerability while parsing OBJ files. An attacker could leverage this vulnerability to execute code in the context of the current process (ZDI-CAN-13776).

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41540](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41540) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41540.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41540.svg)


## CVE-2021-41539
 A vulnerability has been identified in Solid Edge SE2021 (All versions &lt; SE2021MP8). The affected application contains a use-after-free vulnerability while parsing OBJ files. An attacker could leverage this vulnerability to execute code in the context of the current process (ZDI-CAN-13773).

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41539](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41539) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41539.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41539.svg)


## CVE-2021-41538
 A vulnerability has been identified in Solid Edge SE2021 (All versions &lt; SE2021MP8). The affected application is vulnerable to information disclosure by unexpected access to an uninitialized pointer while parsing user-supplied OBJ files. An attacker could leverage this vulnerability to leak information from unexpected memory locations (ZDI-CAN-13770).

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41538](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41538) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41538.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41538.svg)


## CVE-2021-41537
 A vulnerability has been identified in Solid Edge SE2021 (All versions &lt; SE2021MP8). The affected application contains a use-after-free vulnerability while parsing OBJ files. An attacker could leverage this vulnerability to execute code in the context of the current process (ZDI-CAN-13789).

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41537](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41537) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41537.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41537.svg)


## CVE-2021-41536
 A vulnerability has been identified in Solid Edge SE2021 (All versions &lt; SE2021MP8). The affected application contains a use-after-free vulnerability while parsing OBJ files. An attacker could leverage this vulnerability to execute code in the context of the current process (ZDI-CAN-13778).

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41536](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41536) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41536.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41536.svg)


## CVE-2021-41535
 A vulnerability has been identified in Solid Edge SE2021 (All versions &lt; SE2021MP8). The affected application contains a use-after-free vulnerability while parsing OBJ files. An attacker could leverage this vulnerability to execute code in the context of the current process (ZDI-CAN-13771).

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41535](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41535) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41535.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41535.svg)


## CVE-2021-41534
 A vulnerability has been identified in Solid Edge SE2021 (All versions &lt; SE2021MP8). The affected application is vulnerable to an out of bounds read past the end of an allocated buffer when parsing JT files. An attacker could leverage this vulnerability to leak information in the context of the current process (ZDI-CAN-13703).

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41534](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41534) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41534.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41534.svg)


## CVE-2021-41533
 A vulnerability has been identified in Solid Edge SE2021 (All versions &lt; SE2021MP8). The affected application is vulnerable to an out of bounds read past the end of an allocated buffer when parsing JT files. An attacker could leverage this vulnerability to leak information in the context of the current process (ZDI-CAN-13565).

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41533](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41533) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41533.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41533.svg)


## CVE-2021-41525
 An issue related to modification of otherwise restricted files through a locally authenticated attacker exists in FlexNet inventory agent and inventory beacon versions 2020 R2.5 and prior.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41525](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41525) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41525.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41525.svg)


## CVE-2021-41504
 ** UNSUPPORTED WHEN ASSIGNED ** An Elevated Privileges issue exists in D-Link DCS-5000L v1.05 and DCS-932L v2.17 and older. The use of the digest-authentication for the devices command interface may allow further attack vectors that may compromise the cameras configuration and allow malicious users on the LAN to access the device. NOTE: This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41504](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41504) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41504.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41504.svg)


## CVE-2021-41503
 ** UNSUPPORTED WHEN ASSIGNED ** DCS-5000L v1.05 and DCS-932L v2.17 and older are affecged by Incorrect Acess Control. The use of the basic authentication for the devices command interface allows attack vectors that may compromise the cameras configuration and allow malicious users on the LAN to access the device. NOTE: This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41503](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41503) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41503.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41503.svg)


## CVE-2021-41467
 Cross-site scripting (XSS) vulnerability in application/controllers/dropbox.php in JustWriting 1.0.0 and below allow remote attackers to inject arbitrary web script or HTML via the challenge parameter.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41467](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41467) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41467.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41467.svg)


## CVE-2021-41465
 Cross-site scripting (XSS) vulnerability in concrete/elements/collection_theme.php in concrete5-legacy 5.6.4.0 and below allows remote attackers to inject arbitrary web script or HTML via the rel parameter.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41465](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41465) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41465.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41465.svg)


## CVE-2021-41464
 Cross-site scripting (XSS) vulnerability in concrete/elements/collection_add.php in concrete5-legacy 5.6.4.0 and below allows remote attackers to inject arbitrary web script or HTML via the rel parameter.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41464](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41464) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41464.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41464.svg)


## CVE-2021-41463
 Cross-site scripting (XSS) vulnerability in toos/permissions/dialogs/access/entity/types/group_combination.php in concrete5-legacy 5.6.4.0 and below allows remote attackers to inject arbitrary web script or HTML via the cID parameter.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41463](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41463) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41463.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41463.svg)


## CVE-2021-41462
 Cross-site scripting (XSS) vulnerability in concrete/elements/collection_add.php in concrete5-legacy 5.6.4.0 and below allows remote attackers to inject arbitrary web script or HTML via the ctID parameter.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41462](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41462) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41462.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41462.svg)


## CVE-2021-41461
 Cross-site scripting (XSS) vulnerability in concrete/elements/collection_add.php in concrete5-legacy 5.6.4.0 and below allows remote attackers to inject arbitrary web script or HTML via the mode parameter.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41461](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41461) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41461.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41461.svg)


## CVE-2021-41428
 Insecure permissions in Update Manager &lt;= 5.8.0.2300 and DFL &lt;= 12.5.1001.5 in DATEV programs v14.1 allows attacker to escalate privileges via insufficient configuration of service components.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41428](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41428) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41428.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41428.svg)


## CVE-2021-41395
 Teleport before 6.2.12 and 7.x before 7.1.1 allows attackers to control a database connection string, in some situations, via a crafted database name or username.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41395](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41395) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41395.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41395.svg)


## CVE-2021-41394
 Teleport before 4.4.11, 5.x before 5.2.4, 6.x before 6.2.12, and 7.x before 7.1.1 allows alteration of build artifacts in some situations.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41394](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41394) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41394.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41394.svg)


## CVE-2021-41393
 Teleport before 4.4.11, 5.x before 5.2.4, 6.x before 6.2.12, and 7.x before 7.1.1 allows forgery of SSH host certificates in some situations.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41393](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41393) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41393.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41393.svg)


## CVE-2021-41392
 static/main-preload.js in Boost Note through 0.22.0 allows remote command execution. A remote attacker may send a crafted IPC message to the exposed vulnerable ipcRenderer IPC interface, which invokes the dangerous openExternal Electron API.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41392](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41392) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41392.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41392.svg)


## CVE-2021-41391
 In Ericsson ECM before 18.0, it was observed that Security Management Endpoint in User Profile Management Section is vulnerable to stored XSS via a name, leading to session hijacking and full account takeover.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41391](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41391) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41391.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41391.svg)


## CVE-2021-41390
 In Ericsson ECM before 18.0, it was observed that Security Provider Endpoint in the User Profile Management Section is vulnerable to CSV Injection.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41390](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41390) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41390.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41390.svg)


## CVE-2021-41387
 seatd-launch in seatd 0.6.x before 0.6.2 allows privilege escalation because it uses execlp and may be installed setuid root.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41387](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41387) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41387.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41387.svg)


## CVE-2021-41383
 setup.cgi on NETGEAR R6020 1.0.0.48 devices allows an admin to execute arbitrary shell commands via shell metacharacters in the ntp_server field.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41383](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41383) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41383.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41383.svg)


## CVE-2021-41382
 Plastic SCM before 10.0.16.5622 mishandles the WebAdmin server management interface.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41382](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41382) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41382.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41382.svg)


## CVE-2021-41381
 Payara Micro Community 5.2021.6 and below allows Directory Traversal.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41381](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41381) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41381.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41381.svg)


## CVE-2021-41380
 ** DISPUTED ** RealVNC Viewer 6.21.406 allows remote VNC servers to cause a denial of service (application crash) via crafted RFB protocol data. NOTE: It is asserted that this issue requires social engineering a user into connecting to a fake VNC Server. The VNC Viewer application they are using will then hang, until terminated, but no memory leak occurs - the resources are freed once the hung process is terminated and the resource usage is constant during the hang. Only the process that is connected to the fake Server is affected. This is an application bug, not a security issue.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41380](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41380) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41380.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41380.svg)


## CVE-2021-41326
 In MISP before 2.4.148, app/Lib/Export/OpendataExport.php mishandles parameter data that is used in a shell_exec call.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41326](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41326) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41326.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41326.svg)


## CVE-2021-41317
 XSS Hunter Express before 2021-09-17 does not properly enforce authentication requirements for paths.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41317](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41317) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41317.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41317.svg)


## CVE-2021-41316
 The Device42 Main Appliance before 17.05.01 does not sanitize user input in its Nmap Discovery utility. An attacker (with permissions to add or edit jobs run by this utility) can inject an extra argument to overwrite arbitrary files as the root user on the Remote Collector.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41316](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41316) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41316.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41316.svg)


## CVE-2021-41315
 The Device42 Remote Collector before 17.05.01 does not sanitize user input in its SNMP Connectivity utility. This allows an authenticated attacker (with access to the console application) to execute arbitrary OS commands and escalate privileges.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41315](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41315) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41315.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41315.svg)


## CVE-2021-41314
 Certain NETGEAR smart switches are affected by a \n injection in the web UI's password field, which - due to several faulty aspects of the authentication scheme - allows the attacker to create (or overwrite) a file with specific content (e.g., the &quot;2&quot; string). This leads to admin session crafting and therefore gaining full web UI admin privileges by an unauthenticated attacker. This affects GC108P before 1.0.8.2, GC108PP before 1.0.8.2, GS108Tv3 before 7.0.7.2, GS110TPP before 7.0.7.2, GS110TPv3 before 7.0.7.2, GS110TUP before 1.0.5.3, GS308T before 1.0.3.2, GS310TP before 1.0.3.2, GS710TUP before 1.0.5.3, GS716TP before 1.0.4.2, GS716TPP before 1.0.4.2, GS724TPP before 2.0.6.3, GS724TPv2 before 2.0.6.3, GS728TPPv2 before 6.0.8.2, GS728TPv2 before 6.0.8.2, GS750E before 1.0.1.10, GS752TPP before 6.0.8.2, GS752TPv2 before 6.0.8.2, MS510TXM before 1.0.4.2, and MS510TXUP before 1.0.4.2.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41314](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41314) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41314.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41314.svg)


## CVE-2021-41303
 Apache Shiro before 1.8.0, when using Apache Shiro with Spring Boot, a specially crafted HTTP request may cause an authentication bypass. Users should update to Apache Shiro 1.8.0.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41303](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41303) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41303.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41303.svg)


## CVE-2021-41088
 Elvish is a programming language and interactive shell, combined into one package. In versions prior to 0.14.0 Elvish's web UI backend (started by `elvish -web`) hosts an endpoint that allows executing the code sent from the web UI. The backend does not check the origin of requests correctly. As a result, if the user has the web UI backend open and visits a compromised or malicious website, the website can send arbitrary code to the endpoint in localhost. All Elvish releases from 0.14.0 onward no longer include the the web UI, although it is still possible for the user to build a version from source that includes the web UI. The issue can be patched for previous versions by removing the web UI (found in web, pkg/web or pkg/prog/web, depending on the exact version).

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41088](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41088) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41088.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41088.svg)


## CVE-2021-41086
 jsuites is an open source collection of common required javascript web components. In affected versions users are subject to cross site scripting (XSS) attacks via clipboard content. jsuites is vulnerable to DOM based XSS if the user can be tricked into copying _anything_ from a malicious and pasting it into the html editor. This is because a part of the clipboard content is directly written to `innerHTML` allowing for javascript injection and thus XSS. Users are advised to update to version 4.9.11 to resolve.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41086](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41086) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41086.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41086.svg)


## CVE-2021-41083
 Dada Mail is a web-based e-mail list management system. In affected versions a bad actor could give someone a carefully crafted web page via email, SMS, etc, that - when visited, allows them control of the list control panel as if the bad actor was logged in themselves. This includes changing any mailing list password, as well as the Dada Mail Root Password - which could effectively shut out actual list owners of the mailing list and allow the bad actor complete and unfettered control of your mailing list. This vulnerability also affects profile logins. For this vulnerability to work, the target of the bad actor would need to be logged into the list control panel themselves. This CSRF vulnerability in Dada Mail affects all versions of Dada Mail v11.15.1 and below. Although we know of no known CSRF exploits that have happened in the wild, this vulnerability has been confirmed by our testing, and by a third party. Users are advised to update to version 11.16.0.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41083](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41083) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41083.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41083.svg)


## CVE-2021-41082
 Discourse is a platform for community discussion. In affected versions any private message that includes a group had its title and participating user exposed to users that do not have access to the private messages. However, access control for the private messages was not compromised as users were not able to view the posts in the leaked private message despite seeing it in their inbox. The problematic commit was reverted around 32 minutes after it was made. Users are encouraged to upgrade to the latest commit if they are running Discourse against the `tests-passed` branch.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41082](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41082) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41082.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41082.svg)


## CVE-2021-41079
 Apache Tomcat 8.5.0 to 8.5.63, 9.0.0-M1 to 9.0.43 and 10.0.0-M1 to 10.0.2 did not properly validate incoming TLS packets. When Tomcat was configured to use NIO+OpenSSL or NIO2+OpenSSL for TLS, a specially crafted packet could be used to trigger an infinite loop resulting in a denial of service.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41079](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41079) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41079.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41079.svg)


## CVE-2021-41077
 The activation process in Travis CI, for certain 2021-09-03 through 2021-09-10 builds, causes secret data to have unexpected sharing that is not specified by the customer-controlled .travis.yml file. In particular, the desired behavior (if .travis.yml has been created locally by a customer, and added to git) is for a Travis service to perform builds in a way that prevents public access to customer-specific secret environment data such as signing keys, access credentials, and API tokens. However, during the stated 8-day interval, secret data could be revealed to an unauthorized actor who forked a public repository and printed files during a build process.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41077](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41077) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41077.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41077.svg)


## CVE-2021-41073
 loop_rw_iter in fs/io_uring.c in the Linux kernel 5.10 through 5.14.6 allows local users to gain privileges by using IORING_OP_PROVIDE_BUFFERS to trigger a free of a kernel buffer, as demonstrated by using /proc/&lt;pid&gt;/maps for exploitation.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41073](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41073) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41073.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41073.svg)


## CVE-2021-41061
 In RIOT-OS 2021.01, nonce reuse in 802.15.4 encryption in the ieee820154_security component allows attackers to break encryption by triggering reboots.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41061](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41061) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41061.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41061.svg)


## CVE-2021-40981
 ASUS ROG Armoury Crate Lite before 4.2.10 allows local users to gain privileges by placing a Trojan horse file in the publicly writable %PROGRAMDATA%\ASUS\GamingCenterLib directory.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40981](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40981) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40981.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40981.svg)


## CVE-2021-40978
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/nisdn/CVE-2021-40978](https://github.com/nisdn/CVE-2021-40978) :  ![starts](https://img.shields.io/github/stars/nisdn/CVE-2021-40978.svg) ![forks](https://img.shields.io/github/forks/nisdn/CVE-2021-40978.svg)


## CVE-2021-40975
 Cross-site scripting (XSS) vulnerability in application/modules/admin/views/ecommerce/products.php in Ecommerce-CodeIgniter-Bootstrap (Codeigniter 3.1.11, Bootstrap 3.3.7) allows remote attackers to inject arbitrary web script or HTML via the search_title parameter.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40975](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40975) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40975.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40975.svg)


## CVE-2021-40973
 Cross-site scripting (XSS) vulnerability in templates/installer/step-004.inc.php in spotweb 1.5.1 and below allow remote attackers to inject arbitrary web script or HTML via the lastname parameter.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40973](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40973) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40973.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40973.svg)


## CVE-2021-40972
 Cross-site scripting (XSS) vulnerability in templates/installer/step-004.inc.php in spotweb 1.5.1 and below allow remote attackers to inject arbitrary web script or HTML via the mail parameter.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40972](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40972) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40972.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40972.svg)


## CVE-2021-40971
 Cross-site scripting (XSS) vulnerability in templates/installer/step-004.inc.php in spotweb 1.5.1 and below allow remote attackers to inject arbitrary web script or HTML via the newpassword1 parameter.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40971](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40971) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40971.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40971.svg)


## CVE-2021-40970
 Cross-site scripting (XSS) vulnerability in templates/installer/step-004.inc.php in spotweb 1.5.1 and below allow remote attackers to inject arbitrary web script or HTML via the username parameter.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40970](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40970) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40970.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40970.svg)


## CVE-2021-40969
 Cross-site scripting (XSS) vulnerability in templates/installer/step-004.inc.php in spotweb 1.5.1 and below allow remote attackers to inject arbitrary web script or HTML via the firstname parameter.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40969](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40969) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40969.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40969.svg)


## CVE-2021-40968
 Cross-site scripting (XSS) vulnerability in templates/installer/step-004.inc.php in spotweb 1.5.1 and below allow remote attackers to inject arbitrary web script or HTML via the newpassword2 parameter.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40968](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40968) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40968.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40968.svg)


## CVE-2021-40966
 A Stored XSS exists in TinyFileManager All version up to and including 2.4.6 in /tinyfilemanager.php when the server is given a file that contains HTML and javascript in its name. A malicious user can upload a file with a malicious filename containing javascript code and it will run on any user browser when they access the server.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40966](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40966) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40966.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40966.svg)


## CVE-2021-40965
 A Cross-Site Request Forgery (CSRF) vulnerability exists in TinyFileManager all version up to and including 2.4.6 that allows attackers to upload files and run OS commands by inducing the Administrator user to browse a URL controlled by an attacker.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40965](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40965) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40965.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40965.svg)


## CVE-2021-40964
 A Path Traversal vulnerability exists in TinyFileManager all version up to and including 2.4.6 that allows attackers to upload a file (with Admin credentials or with the CSRF vulnerability) with the &quot;fullpath&quot; parameter containing path traversal strings (../ and ..\) in order to escape the server's intended working directory and write malicious files onto any directory on the computer.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40964](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40964) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40964.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40964.svg)


## CVE-2021-40928
 Cross-site scripting (XSS) vulnerability in index.php in FlexTV beta development version allows remote attackers to inject arbitrary web script or HTML via the PHP_SELF parameter.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40928](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40928) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40928.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40928.svg)


## CVE-2021-40927
 Cross-site scripting (XSS) vulnerability in callback.php in Spotify-for-Alfred 0.13.9 and below allows remote attackers to inject arbitrary web script or HTML via the error parameter.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40927](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40927) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40927.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40927.svg)


## CVE-2021-40926
 Cross-site scripting (XSS) vulnerability in demos/demo.mysqli.php in getID3 1.X and v2.0.0-beta allows remote attackers to inject arbitrary web script or HTML via the showtagfiles parameter.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40926](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40926) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40926.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40926.svg)


## CVE-2021-40925
 Cross-site scripting (XSS) vulnerability in dompdf/dompdf/www/demo.php infaveo-helpdesk v1.11.0 and below allow remote attackers to inject arbitrary web script or HTML via the $_SERVER[&quot;PHP_SELF&quot;] parameter.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40925](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40925) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40925.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40925.svg)


## CVE-2021-40924
 Cross-site scripting (XSS) vulnerability in install/index.php in bugs 1.8 and below version allows remote attackers to inject arbitrary web script or HTML via the first_name parameter.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40924](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40924) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40924.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40924.svg)


## CVE-2021-40923
 Cross-site scripting (XSS) vulnerability in install/index.php in bugs 1.8 and below version allows remote attackers to inject arbitrary web script or HTML via the email parameter.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40923](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40923) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40923.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40923.svg)


## CVE-2021-40922
 Cross-site scripting (XSS) vulnerability in install/index.php in bugs 1.8 and below version allows remote attackers to inject arbitrary web script or HTML via the last_name parameter.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40922](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40922) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40922.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40922.svg)


## CVE-2021-40921
 Cross-site scripting (XSS) vulnerability in _contactform.inc.php in Detector 0.8.5 and below version allows remote attackers to inject arbitrary web script or HTML via the cid parameter.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40921](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40921) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40921.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40921.svg)


## CVE-2021-40881
 An issue in the BAT file parameters of PublicCMS v4.0 allows attackers to execute arbitrary code.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40881](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40881) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40881.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40881.svg)


## CVE-2021-40875
 Improper Access Control in Gurock TestRail versions &lt; 7.2.0.3014 resulted in sensitive information exposure. A threat actor can access the /files.md5 file on the client side of a Gurock TestRail application, disclosing a full list of application files and the corresponding file paths. The corresponding file paths can be tested, and in some cases, result in the disclosure of hardcoded credentials, API keys, or other sensitive data.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40875](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40875) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40875.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40875.svg)


## CVE-2021-40868
 In Cloudron 6.2, the returnTo parameter on the login page is vulnerable to Reflected XSS.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40868](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40868) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40868.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40868.svg)


## CVE-2021-40862
 HashiCorp Terraform Enterprise up to v202108-1 contained an API endpoint that erroneously disclosed a sensitive URL to authenticated parties, which could be used for privilege escalation or unauthorized modification of a Terraform configuration. Fixed in v202109-1.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40862](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40862) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40862.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40862.svg)


## CVE-2021-40845
 The web part of Zenitel AlphaCom XE Audio Server through 11.2.3.10, called AlphaWeb XE, does not restrict file upload in the Custom Scripts section at php/index.php. Neither the content nor extension of the uploaded files is checked, allowing execution of PHP code under the /cmd directory.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40845](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40845) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40845.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40845.svg)


## CVE-2021-40825
 nLight ECLYPSE (nECY) system Controllers running software prior to 1.17.21245.754 contain a default key vulnerability. The nECY does not force a change to the key upon the initial configuration of an affected device. nECY system controllers utilize an encrypted channel to secure SensorViewTM configuration and monitoring software and nECY to nECY communications. Impacted devices are at risk of exploitation. A remote attacker with IP access to an impacted device could submit lighting control commands to the nECY by leveraging the default key. A successful attack may result in the attacker gaining the ability to modify lighting conditions or gain the ability to update the software on lighting devices. The impacted key is referred to as the SensorView Password in the nECY nLight Explorer Interface and the Gateway Password in the SensorView application. An attacker cannot authenticate to or modify the configuration or software of the nECY system controller.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40825](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40825) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40825.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40825.svg)


## CVE-2021-40715
 Adobe Premiere Pro version 15.4 (and earlier) is affected by a memory corruption vulnerability due to insecure handling of a malicious .exr file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required in that the victim must open a specially crafted file to exploit this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40715](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40715) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40715.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40715.svg)


## CVE-2021-40714
 Adobe Experience Manager version 6.5.9.0 (and earlier) is affected by a reflected Cross-Site Scripting (XSS) vulnerability via the accesskey parameter. If an attacker is able to convince a victim to visit a URL referencing a vulnerable page, malicious JavaScript content may be executed within the context of the victim's browser

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40714](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40714) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40714.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40714.svg)


## CVE-2021-40713
 Adobe Experience Manager version 6.5.9.0 (and earlier) is affected by a improper certificate validation vulnerability in the cold storage component. If an attacker can achieve a man in the middle when the cold server establishes a new certificate, they would be able to harvest sensitive information.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40713](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40713) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40713.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40713.svg)


## CVE-2021-40712
 Adobe Experience Manager version 6.5.9.0 (and earlier) is affected by a improper input validation vulnerability via the path parameter. An authenticated attacker can send a malformed POST request to achieve server-side denial of service.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40712](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40712) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40712.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40712.svg)


## CVE-2021-40711
 Adobe Experience Manager version 6.5.9.0 (and earlier) is affected by a stored XSS vulnerability when creating Content Fragments. An authenticated attacker can send a malformed POST request to achieve arbitrary code execution. Malicious JavaScript may be executed in a victim&#8217;s browser when they browse to the page containing the vulnerable field.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40711](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40711) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40711.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40711.svg)


## CVE-2021-40710
 Adobe Premiere Pro version 15.4 (and earlier) is affected by a memory corruption vulnerability due to insecure handling of a malicious .svg file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required in that the victim must open a specially crafted file to exploit this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40710](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40710) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40710.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40710.svg)


## CVE-2021-40709
 Adobe Photoshop versions 21.2.11 (and earlier) and 22.5 (and earlier) are affected by a Buffer Overflow vulnerability when parsing a specially crafted SVG file. An unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40709](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40709) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40709.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40709.svg)


## CVE-2021-40708
 Adobe Genuine Service versions 7.3 (and earlier) are affected by a privilege escalation vulnerability in the AGSService installer. An authenticated attacker could leverage this vulnerability to achieve read / write privileges to execute arbitrary code. User interaction is required to abuse this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40708](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40708) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40708.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40708.svg)


## CVE-2021-40703
 Adobe Premiere Elements version 2021.2235820 (and earlier) is affected by a memory corruption vulnerability due to insecure handling of a malicious m4a file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40703](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40703) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40703.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40703.svg)


## CVE-2021-40702
 Adobe Premiere Elements version 2021.2235820 (and earlier) is affected by a memory corruption vulnerability due to insecure handling of a malicious psd file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40702](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40702) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40702.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40702.svg)


## CVE-2021-40701
 Adobe Premiere Elements version 2021.2235820 (and earlier) is affected by a memory corruption vulnerability due to insecure handling of a malicious m4a file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40701](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40701) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40701.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40701.svg)


## CVE-2021-40700
 Adobe Premiere Elements version 2021.2235820 (and earlier) is affected by a memory corruption vulnerability due to insecure handling of a malicious TIFF file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40700](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40700) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40700.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40700.svg)


## CVE-2021-40697
 Adobe Framemaker versions 2019 Update 8 (and earlier) and 2020 Release Update 2 (and earlier) are affected by an out-of-bounds read vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40697](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40697) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40697.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40697.svg)


## CVE-2021-40690
 All versions of Apache Santuario - XML Security for Java prior to 2.2.3 and 2.1.7 are vulnerable to an issue where the &quot;secureValidation&quot; property is not passed correctly when creating a KeyInfo from a KeyInfoReference element. This allows an attacker to abuse an XPath Transform to extract any local .xml files in a RetrievalMethod element.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40690](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40690) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40690.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40690.svg)


## CVE-2021-40674
 An SQL injection vulnerability exists in Wuzhi CMS v4.1.0 via the KeyValue parameter in coreframe/app/order/admin/index.php.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40674](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40674) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40674.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40674.svg)


## CVE-2021-40670
 SQL Injection vulnerability exists in Wuzhi CMS 4.1.0 via the keywords iparameter under the /coreframe/app/order/admin/card.php file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40670](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40670) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40670.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40670.svg)


## CVE-2021-40655
 An informtion disclosure issue exists in D-LINK-DIR-605 B2 Firmware Version : 2.01MT. An attacker can obtain a user name and password by forging a post request to the / getcfg.php page

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40655](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40655) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40655.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40655.svg)


## CVE-2021-40654
 An information disclosure issue exist in D-LINK-DIR-615 B2 2.01mt. An attacker can obtain a user name and password by forging a post request to the / getcfg.php page

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40654](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40654) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40654.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40654.svg)


## CVE-2021-40639
 Improper access control in Jfinal CMS 5.1.0 allows attackers to access sensitive information via /classes/conf/db.properties&amp;config=filemanager.config.js.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40639](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40639) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40639.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40639.svg)


## CVE-2021-40530
 The ElGamal implementation in Crypto++ through 8.5 allows plaintext recovery because, during interaction between two cryptographic libraries, a certain dangerous combination of the prime defined by the receiver's public key, the generator defined by the receiver's public key, and the sender's ephemeral exponents can lead to a cross-configuration attack against OpenPGP.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40530](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40530) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40530.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40530.svg)


## CVE-2021-40516
 WeeChat before 3.2.1 allows remote attackers to cause a denial of service (crash) via a crafted WebSocket frame that trigger an out-of-bounds read in plugins/relay/relay-websocket.c in the Relay plugin.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40516](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40516) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40516.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40516.svg)


## CVE-2021-40490
 A race condition was discovered in ext4_write_inline_data_end in fs/ext4/inline.c in the ext4 subsystem in the Linux kernel through 5.13.13.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40490](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40490) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40490.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40490.svg)


## CVE-2021-40438
 A crafted request uri-path can cause mod_proxy to forward the request to an origin server choosen by the remote user. This issue affects Apache HTTP Server 2.4.48 and earlier.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40438](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40438) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40438.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40438.svg)


## CVE-2021-40357
 A vulnerability has been identified in Teamcenter Active Workspace V4.3 (All versions &lt; V4.3.10), Teamcenter Active Workspace V5.0 (All versions &lt; V5.0.8), Teamcenter Active Workspace V5.1 (All versions &lt; V5.1.5), Teamcenter Active Workspace V5.2 (All versions &lt; V5.2.1). A path traversal vulnerability in the application could allow an attacker to bypass certain restrictions such as direct access to other services within the host.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40357](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40357) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40357.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40357.svg)


## CVE-2021-40356
 A vulnerability has been identified in Teamcenter V12.4 (All versions &lt; V12.4.0.8), Teamcenter V13.0 (All versions &lt; V13.0.0.7), Teamcenter V13.1 (All versions &lt; V13.1.0.5), Teamcenter V13.2 (All versions &lt; 13.2.0.2). The application contains a XML External Entity Injection (XXE) vulnerability. This could allow an attacker to view files on the application server filesystem.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40356](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40356) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40356.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40356.svg)


## CVE-2021-40355
 A vulnerability has been identified in Teamcenter V12.4 (All versions &lt; V12.4.0.8), Teamcenter V13.0 (All versions &lt; V13.0.0.7), Teamcenter V13.1 (All versions &lt; V13.1.0.5), Teamcenter V13.2 (All versions &lt; 13.2.0.2). The affected application contains Insecure Direct Object Reference (IDOR) vulnerability that allows an attacker to use user-supplied input to access objects directly.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40355](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40355) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40355.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40355.svg)


## CVE-2021-40354
 A vulnerability has been identified in Teamcenter V12.4 (All versions &lt; V12.4.0.8), Teamcenter V13.0 (All versions &lt; V13.0.0.7), Teamcenter V13.1 (All versions &lt; V13.1.0.5), Teamcenter V13.2 (All versions &lt; 13.2.0.2). The &quot;surrogate&quot; functionality on the user profile of the application does not perform sufficient access control that could lead to an account takeover. Any profile on the application can perform this attack and access any other user assigned tasks via the &quot;inbox/surrogate tasks&quot;.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40354](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40354) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40354.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40354.svg)


## CVE-2021-40349
 e7d Speed Test (aka speedtest) 0.5.3 allows a path-traversal attack that results in information disclosure via the &quot;GET /..&quot; substring.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40349](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40349) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40349.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40349.svg)


## CVE-2021-40346
 An integer overflow exists in HAProxy 2.0 through 2.5 in htx_add_header that can be exploited to perform an HTTP request smuggling attack, allowing an attacker to bypass all configured http-request HAProxy ACLs and possibly other ACLs.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40346](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40346) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40346.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40346.svg)


## CVE-2021-40310
 OpenSIS Community Edition version 8.0 is affected by a cross-site scripting (XSS) vulnerability in the TakeAttendance.php via the cp_id_miss_attn parameter.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40310](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40310) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40310.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40310.svg)


## CVE-2021-40309
 A SQL injection vulnerability exists in the Take Attendance functionality of OS4Ed's OpenSIS 8.0. allows an attacker to inject their own SQL query. The cp_id_miss_attn parameter from TakeAttendance.php is vulnerable to SQL injection. An attacker can make an authenticated HTTP request as a user with access to &quot;Take Attendance&quot; functionality to trigger this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40309](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40309) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40309.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40309.svg)


## CVE-2021-40238
 A Cross Site Scriptiong (XSS) vulnerability exists in the admin panel in Webuzo &lt; 2.9.0 via an HTTP request to a non-existent page, which is activated by administrators viewing the &quot;Error Log&quot; page. An attacker can leverage this to achieve Unauthenticated Remote Code Execution via the &quot;Cron Jobs&quot; functionality of Webuzo.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40238](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40238) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40238.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40238.svg)


## CVE-2021-40157
 A user may be tricked into opening a malicious FBX file which may exploit an Untrusted Pointer Dereference vulnerability in FBX&#8217;s Review version 1.5.0 and prior causing it to run arbitrary code on the system.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40157](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40157) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40157.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40157.svg)


## CVE-2021-40156
 A maliciously crafted DWG file in Autodesk Navisworks 2019, 2020, 2021, 2022 can be forced to write beyond allocated boundaries when parsing the DWG files. This vulnerability can be exploited to execute arbitrary code.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40156](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40156) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40156.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40156.svg)


## CVE-2021-40155
 A maliciously crafted DWG file in Autodesk Navisworks 2019, 2020, 2021, 2022 can be forced to read beyond allocated boundaries when parsing the DWG files. This vulnerability can be exploited to execute arbitrary code.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40155](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40155) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40155.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40155.svg)


## CVE-2021-40153
 squashfs_opendir in unsquash-1.c in Squashfs-Tools 4.5 stores the filename in the directory entry; this is then used by unsquashfs to create the new file during the unsquash. The filename is not validated for traversal outside of the destination directory, and thus allows writing to locations outside of the destination.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40153](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40153) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40153.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40153.svg)


## CVE-2021-40145
 ** DISPUTED ** gdImageGd2Ptr in gd_gd2.c in the GD Graphics Library (aka LibGD) through 2.3.2 has a double free. NOTE: the vendor's position is &quot;The GD2 image format is a proprietary image format of libgd. It has to be regarded as being obsolete, and should only be used for development and testing purposes.&quot;

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40145](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40145) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40145.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40145.svg)


## CVE-2021-40109
 A SSRF issue was discovered in Concrete CMS through 8.5.5. Users can access forbidden files on their local network. A user with permissions to upload files from external sites can upload a URL that redirects to an internal resource of any file type. The redirect is followed and loads the contents of the file from the redirected-to server. Files of disallowed types can be uploaded.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40109](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40109) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40109.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40109.svg)


## CVE-2021-40108
 An issue was discovered in Concrete CMS through 8.5.5. The Calendar is vulnerable to CSRF. ccm_token is not verified on the ccm/calendar/dialogs/event/add/save endpoint.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40108](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40108) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40108.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40108.svg)


## CVE-2021-40106
 An issue was discovered in Concrete CMS through 8.5.5. There is unauthenticated stored XSS in blog comments via the website field.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40106](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40106) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40106.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40106.svg)


## CVE-2021-40105
 An issue was discovered in Concrete CMS through 8.5.5. There is XSS via Markdown Comments.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40105](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40105) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40105.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40105.svg)


## CVE-2021-40104
 An issue was discovered in Concrete CMS through 8.5.5. There is an SVG sanitizer bypass.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40104](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40104) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40104.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40104.svg)


## CVE-2021-40103
 An issue was discovered in Concrete CMS through 8.5.5. Path Traversal can lead to Arbitrary File Reading and SSRF.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40103](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40103) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40103.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40103.svg)


## CVE-2021-40102
 An issue was discovered in Concrete CMS through 8.5.5. Arbitrary File deletion can occur via PHAR deserialization in is_dir (PHP Object Injection associated with the __wakeup magic method).

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40102](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40102) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40102.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40102.svg)


## CVE-2021-40100
 An issue was discovered in Concrete CMS through 8.5.5. Stored XSS can occur in Conversations when the Active Conversation Editor is set to Rich Text.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40100](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40100) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40100.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40100.svg)


## CVE-2021-40099
 An issue was discovered in Concrete CMS through 8.5.5. Fetching the update json scheme over HTTP leads to remote code execution.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40099](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40099) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40099.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40099.svg)


## CVE-2021-40098
 An issue was discovered in Concrete CMS through 8.5.5. Path Traversal leading to RCE via external form by adding a regular expression.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40098](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40098) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40098.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40098.svg)


## CVE-2021-40097
 An issue was discovered in Concrete CMS through 8.5.5. Authenticated path traversal leads to to remote code execution via uploaded PHP code, related to the bFilename parameter.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40097](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40097) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40097.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40097.svg)


## CVE-2021-40067
 The access controls on the Mobility read-write API improperly validate user access permissions; this API is disabled by default. If the API is manually enabled, attackers with both network access to the API and valid credentials can read and write data to it; regardless of access control group membership settings. This vulnerability is fixed in Mobility v12.14.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40067](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40067) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40067.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40067.svg)


## CVE-2021-40066
 The access controls on the Mobility read-only API improperly validate user access permissions. Attackers with both network access to the API and valid credentials can read data from it; regardless of access control group membership settings. This vulnerability is fixed in Mobility v11.76 and Mobility v12.14.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40066](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-40066) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-40066.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-40066.svg)


## CVE-2021-39865
 Adobe Framemaker versions 2019 Update 8 (and earlier) and 2020 Release Update 2 (and earlier) are affected by an out-of-bounds read vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39865](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39865) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39865.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39865.svg)


## CVE-2021-39862
 Adobe Framemaker versions 2019 Update 8 (and earlier) and 2020 Release Update 2 (and earlier) are affected by an out-of-bounds read vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39862](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39862) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39862.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39862.svg)


## CVE-2021-39828
 Adobe Digital Editions 4.5.11.187646 (and earlier) are affected by a privilege escalation vulnerability in the Digital Editions installer. An authenticated attacker could leverage this vulnerability to escalate privileges. User interaction is required before product installation to abuse this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39828](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39828) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39828.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39828.svg)


## CVE-2021-39827
 Adobe Digital Editions 4.5.11.187646 (and earlier) are affected by an arbitrary file write vulnerability in the Digital Editions installer. An authenticated attacker could leverage this vulnerability to write an arbitrary file to the system. User interaction is required before product installation to abuse this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39827](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39827) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39827.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39827.svg)


## CVE-2021-39826
 Adobe Digital Editions 4.5.11.187646 (and earlier) are affected by an arbitrary command execution vulnerability. An authenticated attacker could leverage this vulnerability to execute arbitrary commands. User interaction is required to abuse this vulnerability in that a user must open a maliciously crafted .epub file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39826](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39826) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39826.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39826.svg)


## CVE-2021-39825
 Photoshop Elements versions 2021 build 19.0 (20210304.m.156367) (and earlier) are affected by an out-of-bounds write vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious TTF file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39825](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39825) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39825.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39825.svg)


## CVE-2021-39824
 Adobe Premiere Elements version 2021.2235820 (and earlier) is affected by a memory corruption vulnerability due to insecure handling of a malicious png file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39824](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39824) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39824.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39824.svg)


## CVE-2021-39823
 Adobe svg-native-viewer 8182d14dfad5d1e10f53ed830328d7d9a3cfa96d and earlier versions are affected by a heap buffer overflow vulnerability due to insecure handling of a malicious .svg file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39823](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39823) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39823.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39823.svg)


## CVE-2021-39821
 Adobe InDesign versions 16.3 (and earlier), and 16.3.1 (and earlier) are affected by an out-of-bounds write vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious TIF file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39821](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39821) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39821.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39821.svg)


## CVE-2021-39819
 Adobe InCopy version 11.1 (and earlier) is affected by a memory corruption vulnerability due to insecure handling of a malicious XML file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39819](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39819) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39819.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39819.svg)


## CVE-2021-39818
 Adobe InCopy version 11.1 (and earlier) is affected by a memory corruption vulnerability due to insecure handling of a malicious TIFF file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39818](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39818) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39818.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39818.svg)


## CVE-2021-39537
 An issue was discovered in ncurses through v6.2-1. _nc_captoinfo in captoinfo.c has a heap-based buffer overflow.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39537](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39537) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39537.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39537.svg)


## CVE-2021-39536
 An issue was discovered in libxsmm through v1.16.1-93. The JIT code has a heap-based buffer overflow.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39536](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39536) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39536.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39536.svg)


## CVE-2021-39535
 An issue was discovered in libxsmm through v1.16.1-93. A NULL pointer dereference exists in JIT code. It allows an attacker to cause Denial of Service.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39535](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39535) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39535.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39535.svg)


## CVE-2021-39534
 An issue was discovered in libslax through v0.22.1. slaxIsCommentStart() in slaxlexer.c has a heap-based buffer overflow.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39534](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39534) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39534.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39534.svg)


## CVE-2021-39533
 An issue was discovered in libslax through v0.22.1. slaxLexer() in slaxlexer.c has a heap-based buffer overflow.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39533](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39533) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39533.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39533.svg)


## CVE-2021-39532
 An issue was discovered in libslax through v0.22.1. A NULL pointer dereference exists in the function slaxLexer() located in slaxlexer.c. It allows an attacker to cause Denial of Service.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39532](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39532) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39532.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39532.svg)


## CVE-2021-39531
 An issue was discovered in libslax through v0.22.1. slaxLexer() in slaxlexer.c has a stack-based buffer overflow.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39531](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39531) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39531.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39531.svg)


## CVE-2021-39514
 An issue was discovered in libjpeg through 2020021. An uncaught floating point exception in the function ACLosslessScan::ParseMCU() located in aclosslessscan.cpp. It allows an attacker to cause Denial of Service.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39514](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39514) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39514.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39514.svg)


## CVE-2021-39404
 MaianAffiliate v1.0 allows an authenticated administrative user to save an XSS to the database.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39404](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39404) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39404.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39404.svg)


## CVE-2021-39402
 MaianAffiliate v.1.0 is suffers from code injection by adding a new product via the admin panel. The injected payload is reflected on the affiliate main page for all authenticated and unauthenticated visitors.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39402](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39402) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39402.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39402.svg)


## CVE-2021-39392
 The management tool in MyLittleBackup up to and including 1.7 allows remote attackers to execute arbitrary code because machineKey is hardcoded (the same for all customers' installations) in web.config, and can be used to send serialized ASP code.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39392](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39392) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39392.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39392.svg)


## CVE-2021-39375
 Philips Healthcare Tasy Electronic Medical Record (EMR) 3.06 allows SQL injection via the WAdvancedFilter/getDimensionItemsByCode FilterValue parameter.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39375](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39375) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39375.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39375.svg)


## CVE-2021-39371
 An XML external entity (XXE) injection in PyWPS before 4.4.5 allows an attacker to view files on the application server filesystem by assigning a path to the entity. OWSLib 0.24.1 may also be affected.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39371](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39371) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39371.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39371.svg)


## CVE-2021-39339
 The Telefication WordPress plugin is vulnerable to Open Proxy and Server-Side Request Forgery via the ~/bypass.php file due to a user-supplied URL request value that gets called by a curl requests. This affects versions up to, and including, 1.8.0.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39339](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39339) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39339.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39339.svg)


## CVE-2021-39327
 The BulletProof Security WordPress plugin is vulnerable to sensitive information disclosure due to a file path disclosure in the publicly accessible ~/db_backup_log.txt file which grants attackers the full path of the site, in addition to the path of database backup files. This affects versions up to, and including, 5.1.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39327](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39327) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39327.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39327.svg)


## CVE-2021-39325
 The OptinMonster WordPress plugin is vulnerable to Reflected Cross-Site Scripting due to insufficient input validation in the load_previews function found in the ~/OMAPI/Output.php file which allows attackers to inject arbitrary web scripts, in versions up to and including 2.6.0.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39325](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39325) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39325.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39325.svg)


## CVE-2021-39307
 PDFTron's WebViewer UI 8.0 or below renders dangerous URLs as hyperlinks in supported documents, including JavaScript URLs, allowing the execution of arbitrary JavaScript code.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39307](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39307) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39307.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39307.svg)


## CVE-2021-39275
 ap_escape_quotes() may write beyond the end of a buffer when given malicious input. No included modules pass untrusted data to these functions, but third-party / external modules may. This issue affects Apache HTTP Server 2.4.48 and earlier.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39275](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39275) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39275.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39275.svg)


## CVE-2021-39271
 OrbiTeam BSCW Classic before 7.4.3 allows authenticated remote code execution (RCE) during archive extraction via attacker-supplied Python code in the class attribute of a .bscw file. This is fixed in 5.0.12, 5.1.10, 5.2.4, 7.3.3, and 7.4.3.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39271](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39271) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39271.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39271.svg)


## CVE-2021-39246
 Tor Browser through 10.5.6 and 11.x through 11.0a4 allows a correlation attack that can compromise the privacy of visits to v2 onion addresses. Exact timestamps of these onion-service visits are logged locally, and an attacker might be able to compare them to timestamp data collected by the destination server (or collected by a rogue site within the Tor network).

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39246](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39246) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39246.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39246.svg)


## CVE-2021-39239
 A vulnerability in XML processing in Apache Jena, in versions up to 4.1.0, may allow an attacker to execute XML External Entities (XXE), including exposing the contents of local files to a remote server.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39239](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39239) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39239.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39239.svg)


## CVE-2021-39230
 Butter is a system usability utility. Due to a kernel error the JPNS kernel is being discontinued. Affected users are recommend to update to the Trinity kernel. There are no workarounds.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39230](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39230) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39230.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39230.svg)


## CVE-2021-39229
 Apprise is an open source library which allows you to send a notification to almost all of the most popular notification services available. In affected versions users who use Apprise granting them access to the IFTTT plugin (which just comes out of the box) are subject to a denial of service attack on an inefficient regular expression. The vulnerable regular expression is [here](https://github.com/caronc/apprise/blob/0007eade20934ddef0aba38b8f1aad980cfff253/apprise/plugins/NotifyIFTTT.py#L356-L359). The problem has been patched in release version 0.9.5.1. Users who are unable to upgrade are advised to remove `apprise/plugins/NotifyIFTTT.py` to eliminate the service.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39229](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39229) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39229.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39229.svg)


## CVE-2021-39228
 Tremor is an event processing system for unstructured data. A vulnerability exists between versions 0.7.2 and 0.11.6. This vulnerability is a memory safety Issue when using `patch` or `merge` on `state` and assign the result back to `state`. In this case, affected versions of Tremor and the tremor-script crate maintains references to memory that might have been freed already. And these memory regions can be accessed by retrieving the `state`, e.g. send it over TCP or HTTP. This requires the Tremor server (or any other program using tremor-script) to execute a tremor-script script that uses the mentioned language construct. The issue has been patched in version 0.11.6 by removing the optimization and always cloning the target expression of a Merge or Patch. If an upgrade is not possible, a possible workaround is to avoid the optimization by introducing a temporary variable and not immediately reassigning to `state`.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39228](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39228) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39228.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39228.svg)


## CVE-2021-39227
 ZRender is a lightweight graphic library providing 2d draw for Apache ECharts. In versions prior to 5.2.1, using `merge` and `clone` helper methods in the `src/core/util.ts` module results in prototype pollution. It affects the popular data visualization library Apache ECharts, which uses and exports these two methods directly. The GitHub Security Advisory page for this vulnerability contains a proof of concept. This issue is patched in ZRender version 5.2.1. One workaround is available: Check if there is `__proto__` in the object keys. Omit it before using it as an parameter in these affected methods. Or in `echarts.util.merge` and `setOption` if project is using ECharts.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39227](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39227) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39227.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39227.svg)


## CVE-2021-39219
 Wasmtime is an open source runtime for WebAssembly &amp; WASI. Wasmtime before version 0.30.0 is affected by a type confusion vulnerability. As a Rust library the `wasmtime` crate clearly marks which functions are safe and which are `unsafe`, guaranteeing that if consumers never use `unsafe` then it should not be possible to have memory unsafety issues in their embeddings of Wasmtime. An issue was discovered in the safe API of `Linker::func_*` APIs. These APIs were previously not sound when one `Engine` was used to create the `Linker` and then a different `Engine` was used to create a `Store` and then the `Linker` was used to instantiate a module into that `Store`. Cross-`Engine` usage of functions is not supported in Wasmtime and this can result in type confusion of function pointers, resulting in being able to safely call a function with the wrong type. Triggering this bug requires using at least two `Engine` values in an embedding and then additionally using two different values with a `Linker` (one at the creation time of the `Linker` and another when instantiating a module with the `Linker`). It's expected that usage of more-than-one `Engine` in an embedding is relatively rare since an `Engine` is intended to be a globally shared resource, so the expectation is that the impact of this issue is relatively small. The fix implemented is to change this behavior to `panic!()` in Rust instead of silently allowing it. Using different `Engine` instances with a `Linker` is a programmer bug that `wasmtime` catches at runtime. This bug has been patched and users should upgrade to Wasmtime version 0.30.0. If you cannot upgrade Wasmtime and are using more than one `Engine` in your embedding it's recommended to instead use only one `Engine` for the entire program if possible. An `Engine` is designed to be a globally shared resource that is suitable to have only one for the lifetime of an entire process. If using multiple `Engine`s is required then code should be audited to ensure that `Linker` is only used with one `Engine`.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39219](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39219) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39219.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39219.svg)


## CVE-2021-39218
 Wasmtime is an open source runtime for WebAssembly &amp; WASI. In Wasmtime from version 0.26.0 and before version 0.30.0 is affected by a memory unsoundness vulnerability. There was an invalid free and out-of-bounds read and write bug when running Wasm that uses `externref`s in Wasmtime. To trigger this bug, Wasmtime needs to be running Wasm that uses `externref`s, the host creates non-null `externrefs`, Wasmtime performs a garbage collection (GC), and there has to be a Wasm frame on the stack that is at a GC safepoint where there are no live references at this safepoint, and there is a safepoint with live references earlier in this frame's function. Under this scenario, Wasmtime would incorrectly use the GC stack map for the safepoint from earlier in the function instead of the empty safepoint. This would result in Wasmtime treating arbitrary stack slots as `externref`s that needed to be rooted for GC. At the *next* GC, it would be determined that nothing was referencing these bogus `externref`s (because nothing could ever reference them, because they are not really `externref`s) and then Wasmtime would deallocate them and run `&lt;ExternRef as Drop&gt;::drop` on them. This results in a free of memory that is not necessarily on the heap (and shouldn't be freed at this moment even if it was), as well as potential out-of-bounds reads and writes. Even though support for `externref`s (via the reference types proposal) is enabled by default, unless you are creating non-null `externref`s in your host code or explicitly triggering GCs, you cannot be affected by this bug. We have reason to believe that the effective impact of this bug is relatively small because usage of `externref` is currently quite rare. This bug has been patched and users should upgrade to Wasmtime version 0.30.0. If you cannot upgrade Wasmtime at this time, you can avoid this bug by disabling the reference types proposal by passing `false` to `wasmtime::Config::wasm_reference_types`.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39218](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39218) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39218.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39218.svg)


## CVE-2021-39216
 Wasmtime is an open source runtime for WebAssembly &amp; WASI. In Wasmtime from version 0.19.0 and before version 0.30.0 there was a use-after-free bug when passing `externref`s from the host to guest Wasm content. To trigger the bug, you have to explicitly pass multiple `externref`s from the host to a Wasm instance at the same time, either by passing multiple `externref`s as arguments from host code to a Wasm function, or returning multiple `externref`s to Wasm from a multi-value return function defined in the host. If you do not have host code that matches one of these shapes, then you are not impacted. If Wasmtime's `VMExternRefActivationsTable` became filled to capacity after passing the first `externref` in, then passing in the second `externref` could trigger a garbage collection. However the first `externref` is not rooted until we pass control to Wasm, and therefore could be reclaimed by the collector if nothing else was holding a reference to it or otherwise keeping it alive. Then, when control was passed to Wasm after the garbage collection, Wasm could use the first `externref`, which at this point has already been freed. We have reason to believe that the effective impact of this bug is relatively small because usage of `externref` is currently quite rare. The bug has been fixed, and users should upgrade to Wasmtime 0.30.0. If you cannot upgrade Wasmtime yet, you can avoid the bug by disabling reference types support in Wasmtime by passing `false` to `wasmtime::Config::wasm_reference_types`.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39216](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39216) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39216.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39216.svg)


## CVE-2021-39215
 Jitsi Meet is an open source video conferencing application. In versions prior to 2.0.5963, a Prosody module allows the use of symmetrical algorithms to validate JSON web tokens. This means that tokens generated by arbitrary sources can be used to gain authorization to protected rooms. This issue is fixed in Jitsi Meet 2.0.5963. There are no known workarounds aside from updating.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39215](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39215) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39215.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39215.svg)


## CVE-2021-39214
 mitmproxy is an interactive, SSL/TLS-capable intercepting proxy. In mitmproxy 7.0.2 and below, a malicious client or server is able to perform HTTP request smuggling attacks through mitmproxy. This means that a malicious client/server could smuggle a request/response through mitmproxy as part of another request/response's HTTP message body. While a smuggled request is still captured as part of another request's body, it does not appear in the request list and does not go through the usual mitmproxy event hooks, where users may have implemented custom access control checks or input sanitization. Unless one uses mitmproxy to protect an HTTP/1 service, no action is required. The vulnerability has been fixed in mitmproxy 7.0.3 and above.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39214](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39214) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39214.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39214.svg)


## CVE-2021-39213
 GLPI is a free Asset and IT management software package. Starting in version 9.1 and prior to version 9.5.6, GLPI with API Rest enabled is vulnerable to API bypass with custom header injection. This issue is fixed in version 9.5.6. One may disable API Rest as a workaround.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39213](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39213) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39213.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39213.svg)


## CVE-2021-39211
 GLPI is a free Asset and IT management software package. Starting in version 9.2 and prior to version 9.5.6, the telemetry endpoint discloses GLPI and server information. This issue is fixed in version 9.5.6. As a workaround, remove the file `ajax/telemetry.php`, which is not needed for usual functions of GLPI.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39211](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39211) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39211.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39211.svg)


## CVE-2021-39210
 GLPI is a free Asset and IT management software package. In versions prior to 9.5.6, the cookie used to store the autologin cookie (when a user uses the &quot;remember me&quot; feature) is accessible by scripts. A malicious plugin that could steal this cookie would be able to use it to autologin. This issue is fixed in version 9.5.6. As a workaround, one may avoid using the &quot;remember me&quot; feature.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39210](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39210) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39210.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39210.svg)


## CVE-2021-39209
 GLPI is a free Asset and IT management software package. In versions prior to 9.5.6, a user who is logged in to GLPI can bypass Cross-Site Request Forgery (CSRF) protection in many places. This could allow a malicious actor to perform many actions on GLPI. This issue is fixed in version 9.5.6. There are no workarounds aside from upgrading.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39209](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39209) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39209.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39209.svg)


## CVE-2021-39208
 SharpCompress is a fully managed C# library to deal with many compression types and formats. Versions prior to 0.29.0 are vulnerable to partial path traversal. SharpCompress recreates a hierarchy of directories under destinationDirectory if ExtractFullPath is set to true in options. In order to prevent extraction outside the destination directory the destinationFileName path is verified to begin with fullDestinationDirectoryPath. However, prior to version 0.29.0, it is not enforced that fullDestinationDirectoryPath ends with slash. If the destinationDirectory is not slash terminated like `/home/user/dir` it is possible to create a file with a name thats begins as the destination directory one level up from the directory, i.e. `/home/user/dir.sh`. Because of the file name and destination directory constraints the arbitrary file creation impact is limited and depends on the use case. This issue is fixed in SharpCompress version 0.29.0.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39208](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39208) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39208.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39208.svg)


## CVE-2021-39206
 Pomerium is an open source identity-aware access proxy. Envoy, which Pomerium is based on, contains two authorization related vulnerabilities CVE-2021-32777 and CVE-2021-32779. This may lead to incorrect routing or authorization policy decisions. With specially crafted requests, incorrect authorization or routing decisions may be made by Pomerium. Pomerium v0.14.8 and v0.15.1 contain an upgraded envoy binary with these vulnerabilities patched. This issue can only be triggered when using path prefix based policy. Removing any such policies should provide mitigation.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39206](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39206) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39206.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39206.svg)


## CVE-2021-39205
 Jitsi Meet is an open source video conferencing application. Versions prior to 2.0.6173 are vulnerable to client-side cross-site scripting via injecting properties into JSON objects that were not properly escaped. There are no known incidents related to this vulnerability being exploited in the wild. This issue is fixed in Jitsi Meet version 2.0.6173. There are no known workarounds aside from upgrading.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39205](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39205) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39205.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39205.svg)


## CVE-2021-39204
 Pomerium is an open source identity-aware access proxy. Envoy, which Pomerium is based on, incorrectly handles resetting of HTTP/2 streams with excessive complexity. This can lead to high CPU utilization when a large number of streams are reset. This can result in a DoS condition. Pomerium versions 0.14.8 and 0.15.1 contain an upgraded envoy binary with this vulnerability patched.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39204](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39204) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39204.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39204.svg)


## CVE-2021-39201
 WordPress is a free and open-source content management system written in PHP and paired with a MySQL or MariaDB database. ### Impact The issue allows an authenticated but low-privileged user (like contributor/author) to execute XSS in the editor. This bypasses the restrictions imposed on users who do not have the permission to post `unfiltered_html`. ### Patches This has been patched in WordPress 5.8, and will be pushed to older versions via minor releases (automatic updates). It's strongly recommended that you keep auto-updates enabled to receive the fix. ### References https://wordpress.org/news/category/releases/ https://hackerone.com/reports/1142140 ### For more information If you have any questions or comments about this advisory: * Open an issue in [HackerOne](https://hackerone.com/wordpress)

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39201](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39201) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39201.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39201.svg)


## CVE-2021-39189
 Pimcore is an open source data &amp; experience management platform. In versions prior to 10.1.3, it is possible to enumerate usernames via the forgot password functionality. This issue is fixed in version 10.1.3. As a workaround, one may apply the available patch manually.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39189](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39189) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39189.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39189.svg)


## CVE-2021-39159
 BinderHub is a kubernetes-based cloud service that allows users to share reproducible interactive computing environments from code repositories. In affected versions a remote code execution vulnerability has been identified in BinderHub, where providing BinderHub with maliciously crafted input could execute code in the BinderHub context, with the potential to egress credentials of the BinderHub deployment, including JupyterHub API tokens, kubernetes service accounts, and docker registry credentials. This may provide the ability to manipulate images and other user created pods in the deployment, with the potential to escalate to the host depending on the underlying kubernetes configuration. Users are advised to update to version 0.2.0-n653. If users are unable to update they may disable the git repo provider by specifying the `BinderHub.repo_providers` as a workaround.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39159](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39159) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39159.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39159.svg)


## CVE-2021-39154
 XStream is a simple library to serialize objects to XML and back again. In affected versions this vulnerability may allow a remote attacker to load and execute arbitrary code from a remote host only by manipulating the processed input stream. No user is affected, who followed the recommendation to setup XStream's security framework with a whitelist limited to the minimal required types. XStream 1.4.18 uses no longer a blacklist by default, since it cannot be secured for general purpose.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39154](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39154) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39154.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39154.svg)


## CVE-2021-39153
 XStream is a simple library to serialize objects to XML and back again. In affected versions this vulnerability may allow a remote attacker to load and execute arbitrary code from a remote host only by manipulating the processed input stream, if using the version out of the box with Java runtime version 14 to 8 or with JavaFX installed. No user is affected, who followed the recommendation to setup XStream's security framework with a whitelist limited to the minimal required types. XStream 1.4.18 uses no longer a blacklist by default, since it cannot be secured for general purpose.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39153](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39153) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39153.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39153.svg)


## CVE-2021-39152
 XStream is a simple library to serialize objects to XML and back again. In affected versions this vulnerability may allow a remote attacker to request data from internal resources that are not publicly available only by manipulating the processed input stream with a Java runtime version 14 to 8. No user is affected, who followed the recommendation to setup XStream's security framework with a whitelist limited to the minimal required types. If you rely on XStream's default blacklist of the [Security Framework](https://x-stream.github.io/security.html#framework), you will have to use at least version 1.4.18.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39152](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39152) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39152.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39152.svg)


## CVE-2021-39151
 XStream is a simple library to serialize objects to XML and back again. In affected versions this vulnerability may allow a remote attacker to load and execute arbitrary code from a remote host only by manipulating the processed input stream. No user is affected, who followed the recommendation to setup XStream's security framework with a whitelist limited to the minimal required types. XStream 1.4.18 uses no longer a blacklist by default, since it cannot be secured for general purpose.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39151](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39151) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39151.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39151.svg)


## CVE-2021-39150
 XStream is a simple library to serialize objects to XML and back again. In affected versions this vulnerability may allow a remote attacker to request data from internal resources that are not publicly available only by manipulating the processed input stream with a Java runtime version 14 to 8. No user is affected, who followed the recommendation to setup XStream's security framework with a whitelist limited to the minimal required types. If you rely on XStream's default blacklist of the [Security Framework](https://x-stream.github.io/security.html#framework), you will have to use at least version 1.4.18.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39150](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39150) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39150.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39150.svg)


## CVE-2021-39149
 XStream is a simple library to serialize objects to XML and back again. In affected versions this vulnerability may allow a remote attacker to load and execute arbitrary code from a remote host only by manipulating the processed input stream. No user is affected, who followed the recommendation to setup XStream's security framework with a whitelist limited to the minimal required types. XStream 1.4.18 uses no longer a blacklist by default, since it cannot be secured for general purpose.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39149](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39149) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39149.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39149.svg)


## CVE-2021-39148
 XStream is a simple library to serialize objects to XML and back again. In affected versions this vulnerability may allow a remote attacker to load and execute arbitrary code from a remote host only by manipulating the processed input stream. No user is affected, who followed the recommendation to setup XStream's security framework with a whitelist limited to the minimal required types. XStream 1.4.18 uses no longer a blacklist by default, since it cannot be secured for general purpose.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39148](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39148) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39148.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39148.svg)


## CVE-2021-39147
 XStream is a simple library to serialize objects to XML and back again. In affected versions this vulnerability may allow a remote attacker to load and execute arbitrary code from a remote host only by manipulating the processed input stream. No user is affected, who followed the recommendation to setup XStream's security framework with a whitelist limited to the minimal required types. XStream 1.4.18 uses no longer a blacklist by default, since it cannot be secured for general purpose.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39147](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39147) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39147.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39147.svg)


## CVE-2021-39146
 XStream is a simple library to serialize objects to XML and back again. In affected versions this vulnerability may allow a remote attacker to load and execute arbitrary code from a remote host only by manipulating the processed input stream. No user is affected, who followed the recommendation to setup XStream's security framework with a whitelist limited to the minimal required types. XStream 1.4.18 uses no longer a blacklist by default, since it cannot be secured for general purpose.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39146](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39146) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39146.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39146.svg)


## CVE-2021-39145
 XStream is a simple library to serialize objects to XML and back again. In affected versions this vulnerability may allow a remote attacker to load and execute arbitrary code from a remote host only by manipulating the processed input stream. No user is affected, who followed the recommendation to setup XStream's security framework with a whitelist limited to the minimal required types. XStream 1.4.18 uses no longer a blacklist by default, since it cannot be secured for general purpose.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39145](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39145) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39145.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39145.svg)


## CVE-2021-39144
 XStream is a simple library to serialize objects to XML and back again. In affected versions this vulnerability may allow a remote attacker has sufficient rights to execute commands of the host only by manipulating the processed input stream. No user is affected, who followed the recommendation to setup XStream's security framework with a whitelist limited to the minimal required types. XStream 1.4.18 uses no longer a blacklist by default, since it cannot be secured for general purpose.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39144](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39144) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39144.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39144.svg)


## CVE-2021-39141
 XStream is a simple library to serialize objects to XML and back again. In affected versions this vulnerability may allow a remote attacker to load and execute arbitrary code from a remote host only by manipulating the processed input stream. No user is affected, who followed the recommendation to setup XStream's security framework with a whitelist limited to the minimal required types. XStream 1.4.18 uses no longer a blacklist by default, since it cannot be secured for general purpose.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39141](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39141) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39141.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39141.svg)


## CVE-2021-39140
 XStream is a simple library to serialize objects to XML and back again. In affected versions this vulnerability may allow a remote attacker to allocate 100% CPU time on the target system depending on CPU type or parallel execution of such a payload resulting in a denial of service only by manipulating the processed input stream. No user is affected, who followed the recommendation to setup XStream's security framework with a whitelist limited to the minimal required types. XStream 1.4.18 uses no longer a blacklist by default, since it cannot be secured for general purpose.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39140](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39140) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39140.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39140.svg)


## CVE-2021-39139
 XStream is a simple library to serialize objects to XML and back again. In affected versions this vulnerability may allow a remote attacker to load and execute arbitrary code from a remote host only by manipulating the processed input stream. A user is only affected if using the version out of the box with JDK 1.7u21 or below. However, this scenario can be adjusted easily to an external Xalan that works regardless of the version of the Java runtime. No user is affected, who followed the recommendation to setup XStream's security framework with a whitelist limited to the minimal required types. XStream 1.4.18 uses no longer a blacklist by default, since it cannot be secured for general purpose.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39139](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39139) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39139.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39139.svg)


## CVE-2021-39138
 Parse Server is an open source backend that can be deployed to any infrastructure that can run Node.js. Developers can use the REST API to signup users and also allow users to login anonymously. Prior to version 4.5.1, when an anonymous user is first signed up using REST, the server creates session incorrectly. Particularly, the `authProvider` field in `_Session` class under `createdWith` shows the user logged in creating a password. If a developer later depends on the `createdWith` field to provide a different level of access between a password user and anonymous user, the server incorrectly classified the session type as being created with a `password`. The server does not currently use `createdWith` to make decisions about internal functions, so if a developer is not using `createdWith` directly, they are not affected. The vulnerability only affects users who depend on `createdWith` by using it directly. The issue is patched in Parse Server version 4.5.1. As a workaround, do not use the `createdWith` Session field to make decisions if one allows anonymous login.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39138](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39138) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39138.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39138.svg)


## CVE-2021-39117
 The AssociateFieldToScreens page in Atlassian Jira Server and Data Center before version 8.18.0 allows remote attackers to inject arbitrary HTML or JavaScript via a Cross-Site Scripting (XSS) vulnerability via the name of a custom field.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39117](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39117) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39117.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39117.svg)


## CVE-2021-39113
 Affected versions of Atlassian Jira Server and Data Center allow anonymous remote attackers to continue to view cached content even after losing permissions, via a Broken Access Control vulnerability in the allowlist feature. The affected versions are before version 8.13.9, and from version 8.14.0 before 8.18.0.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39113](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39113) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39113.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39113.svg)


## CVE-2021-39111
 The Editor plugin in Atlassian Jira Server and Data Center before version 8.5.18, from 8.6.0 before 8.13.10, and from version 8.14.0 before 8.18.2 allows remote attackers to inject arbitrary HTML or JavaScript via a Cross-Site Scripting (XSS) vulnerability in the handling of supplied content such as from a PDF when pasted into a field such as the description field.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39111](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39111) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39111.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39111.svg)


## CVE-2021-38899
 IBM Cloud Pak for Data 2.5 could allow a local user with special privileges to obtain highly sensitive information. IBM X-Force ID: 209575.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38899](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38899) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-38899.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-38899.svg)


## CVE-2021-38877
 IBM Jazz for Service Management 1.1.3.10 is vulnerable to stored cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 208405.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38877](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38877) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-38877.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-38877.svg)


## CVE-2021-38870
 IBM Aspera Cloud is vulnerable to stored cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 208343.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38870](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38870) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-38870.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-38870.svg)


## CVE-2021-38864
 IBM Security Verify Bridge 1.0.5.0 could allow a user to obtain sensitive information due to improper certificate validation. IBM X-Force ID: 208155.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38864](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38864) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-38864.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-38864.svg)


## CVE-2021-38863
 IBM Security Verify Bridge 1.0.5.0 stores user credentials in plain clear text which can be read by a locally authenticated user. IBM X-Force ID: 208154.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38863](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38863) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-38863.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-38863.svg)


## CVE-2021-38714
 In Plib through 1.85, there is an integer overflow vulnerability that could result in arbitrary code execution. The vulnerability is found in ssgLoadTGA() function in src/ssg/ssgLoadTGA.cxx file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38714](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38714) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-38714.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-38714.svg)


## CVE-2021-38675
 A cross-site scripting (XSS) vulnerability has been reported to affect QNAP device running Image2PDF. If exploited, this vulnerability allows remote attackers to inject malicious code. We have already fixed this vulnerability in the following versions of Image2PDF: Image2PDF 2.1.5 ( 2021/08/17 ) and later

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38675](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38675) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-38675.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-38675.svg)


## CVE-2021-38669
 Microsoft Edge (Chromium-based) Tampering Vulnerability

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38669](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38669) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-38669.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-38669.svg)


## CVE-2021-38636
 Windows Redirected Drive Buffering SubSystem Driver Information Disclosure Vulnerability This CVE ID is unique from CVE-2021-36969, CVE-2021-38635.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38635](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38635) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-38635.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-38635.svg)


## CVE-2021-38635
 Windows Redirected Drive Buffering SubSystem Driver Information Disclosure Vulnerability This CVE ID is unique from CVE-2021-36969, CVE-2021-38636.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38635](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38635) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-38635.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-38635.svg)


## CVE-2021-38604
 In librt in the GNU C Library (aka glibc) through 2.34, sysdeps/unix/sysv/linux/mq_notify.c mishandles certain NOTIFY_REMOVED data, leading to a NULL pointer dereference. NOTE: this vulnerability was introduced as a side effect of the CVE-2021-33574 fix.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38604](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38604) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-38604.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-38604.svg)


## CVE-2021-38534
 Certain NETGEAR devices are affected by stored XSS. This affects D3600 before 1.0.0.76, D6000 before 1.0.0.76, D6100 before 1.0.0.60, D6200 before 1.1.00.36, D6220 before 1.0.0.52, D6400 before 1.0.0.86, D7000 before 1.0.1.70, D7000v2 before 1.0.0.53, D8500 before 1.0.3.44, DC112A before 1.0.0.42, DGN2200v4 before 1.0.0.110, DGND2200Bv4 before 1.0.0.109, DM200 before 1.0.0.61, JR6150 before 1.0.1.18, PR2000 before 1.0.0.28, R6020 before 1.0.0.42, R6050 before 1.0.1.18, R6080 before 1.0.0.42, R6220 before 1.1.0.80, R6230 before 1.1.0.80, R6250 before 1.0.4.34, R6260 before 1.1.0.64, R6300v2 before 1.0.4.34, R6400 before 1.0.1.46, R6400v2 before 1.0.2.62, R6700 before 1.0.2.6, R6700v2 before 1.2.0.36, R6700v3 before 1.0.2.62, R6800 before 1.2.0.36, R6900 before 1.0.2.4, R6900P before 1.3.1.64, R6900v2 before 1.2.0.36, R7000 before 1.0.9.60, R7000P before 1.3.1.64, R7100LG before 1.0.0.50, R7300DST before 1.0.0.70, R7450 before 1.2.0.36, R7900 before 1.0.3.8, R7900P before 1.4.1.50, R8000 before 1.0.4.28, R8000P before 1.4.1.50, R8300 before 1.0.2.130, R8500 before 1.0.2.130, WNDR3400v3 before 1.0.1.24, WNR2020 before 1.1.0.62, WNR3500Lv2 before 1.2.0.62, XR450 before 2.3.2.40, and XR500 before 2.3.2.40.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38534](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38534) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-38534.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-38534.svg)


## CVE-2021-38527
 Certain NETGEAR devices are affected by command injection by an unauthenticated attacker. This affects CBR40 before 2.5.0.14, EX6100v2 before 1.0.1.98, EX6150v2 before 1.0.1.98, EX6250 before 1.0.0.132, EX6400 before 1.0.2.158, EX6400v2 before 1.0.0.132, EX6410 before 1.0.0.132, EX6420 before 1.0.0.132, EX7300 before 1.0.2.158, EX7300v2 before 1.0.0.132, EX7320 before 1.0.0.132, EX7700 before 1.0.0.216, EX8000 before 1.0.1.232, R7800 before 1.0.2.78, RBK12 before 2.6.1.44, RBR10 before 2.6.1.44, RBS10 before 2.6.1.44, RBK20 before 2.6.1.38, RBR20 before 2.6.1.36, RBS20 before 2.6.1.38, RBK40 before 2.6.1.38, RBR40 before 2.6.1.36, RBS40 before 2.6.1.38, RBK50 before 2.6.1.40, RBR50 before 2.6.1.40, RBS50 before 2.6.1.40, RBK752 before 3.2.16.6, RBR750 before 3.2.16.6, RBS750 before 3.2.16.6, RBK852 before 3.2.16.6, RBR850 before 3.2.16.6, RBS850 before 3.2.16.6, RBS40V before 2.6.2.4, RBS50Y before 2.6.1.40, RBW30 before 2.6.2.2, and XR500 before 2.3.2.114.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38527](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38527) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-38527.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-38527.svg)


## CVE-2021-38516
 Certain NETGEAR devices are affected by lack of access control at the function level. This affects D6220 before 1.0.0.48, D6400 before 1.0.0.82, D7000v2 before 1.0.0.52, D7800 before 1.0.1.44, D8500 before 1.0.3.43, DC112A before 1.0.0.40, DGN2200v4 before 1.0.0.108, RBK50 before 2.3.0.32, RBR50 before 2.3.0.32, RBS50 before 2.3.0.32, RBK20 before 2.3.0.28, RBR20 before 2.3.0.28, RBS20 before 2.3.0.28, RBK40 before 2.3.0.28, RBR40 before 2.3.0.28, RBS40 before 2.3.0.28, R6020 before 1.0.0.34, R6080 before 1.0.0.34, R6120 before 1.0.0.44, R6220 before 1.1.0.80, R6230 before 1.1.0.80, R6250 before 1.0.4.34, R6260 before 1.1.0.40, R6850 before 1.1.0.40, R6350 before 1.1.0.40, R6400v2 before 1.0.2.62, R6700v3 before 1.0.2.62, R6700v2 before 1.2.0.36, R6800 before 1.2.0.36, R6900v2 before 1.2.0.36, R7000 before 1.0.9.34, R6900P before 1.3.1.44, R7000P before 1.3.1.44, R7100LG before 1.0.0.48, R7200 before 1.2.0.48, R7350 before 1.2.0.48, R7400 before 1.2.0.48, R7450 before 1.2.0.36, AC2100 before 1.2.0.36, AC2400 before 1.2.0.36, AC2600 before 1.2.0.36, R7500v2 before 1.0.3.38, R7800 before 1.0.2.58, R7900 before 1.0.3.8, R7960P before 1.4.1.44, R8000 before 1.0.4.28, R7900P before 1.4.1.30, R8000P before 1.4.1.30, R8900 before 1.0.4.2, R9000 before 1.0.4.2, RAX120 before 1.0.0.74, RBK752 before 3.2.16.6, RBR750 before 3.2.16.6, RBS750 before 3.2.16.6, RBK852 before 3.2.16.6, RBR850 before 3.2.16.6, RBS850 before 3.2.16.6, WNR3500Lv2 before 1.2.0.56, XR450 before 2.3.2.32, and XR500 before 2.3.2.32.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38516](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38516) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-38516.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-38516.svg)


## CVE-2021-38514
 Certain NETGEAR devices are affected by authentication bypass. This affects D3600 before 1.0.0.72, D6000 before 1.0.0.72, D6100 before 1.0.0.63, D6200 before 1.1.00.34, D6220 before 1.0.0.48, D6400 before 1.0.0.86, D7000 before 1.0.1.70, D7000v2 before 1.0.0.52, D7800 before 1.0.1.56, D8500 before 1.0.3.44, DC112A before 1.0.0.42, DGN2200v4 before 1.0.0.108, DGND2200Bv4 before 1.0.0.108, EX2700 before 1.0.1.48, EX3700 before 1.0.0.76, EX3800 before 1.0.0.76, EX6000 before 1.0.0.38, EX6100 before 1.0.2.24, EX6100v2 before 1.0.1.76, EX6120 before 1.0.0.42, EX6130 before 1.0.0.28, EX6150v1 before 1.0.0.42, EX6150v2 before 1.0.1.76, EX6200 before 1.0.3.88, EX6200v2 before 1.0.1.72, EX6400 before 1.0.2.136, EX7000 before 1.0.0.66, EX7300 before 1.0.2.136, EX8000 before 1.0.1.180, RBK50 before 2.1.4.10, RBR50 before 2.1.4.10, RBS50 before 2.1.4.10, RBK40 before 2.1.4.10, RBR40 before 2.1.4.10, RBS40 before 2.1.4.10, RBW30 before 2.2.1.204, PR2000 before 1.0.0.28, R6020 before 1.0.0.38, R6080 before 1.0.0.38, R6050 before 1.0.1.18, JR6150 before 1.0.1.18, R6120 before 1.0.0.46, R6220 before 1.1.0.86, R6250 before 1.0.4.34, R6300v2 before 1.0.4.32, R6400 before 1.0.1.44, R6400v2 before 1.0.2.62, R6700 before 1.0.1.48, R6700v2 before 1.2.0.36, R6800 before 1.2.0.36, R6900v2 before 1.2.0.36, R6900 before 1.0.1.48, R7000 before 1.0.9.34, R6900P before 1.3.1.64, R7000P before 1.3.1.64, R7100LG before 1.0.0.48, R7300DST before 1.0.0.70, R7500v2 before 1.0.3.38, R7800 before 1.0.2.52, R7900 before 1.0.3.8, R8000 before 1.0.4.28, R7900P before 1.4.1.30, R8000P before 1.4.1.30, R8300 before 1.0.2.128, R8500 before 1.0.2.128, R9000 before 1.0.3.10, RBS40V before 2.2.0.58, RBK50V before 2.2.0.58, WN2000RPTv3 before 1.0.1.32, WN2500RPv2 before 1.0.1.54, WN3000RPv3 before 1.0.2.78, WN3100RPv2 before 1.0.0.66, WNDR3400v3 before 1.0.1.22, WNDR3700v4 before 1.0.2.102, WNDR4300v1 before 1.0.2.104, WNDR4300v2 before 1.0.0.56, WNDR4500v3 before 1.0.0.56, WNR2000v5 (R2000) before 1.0.0.66, WNR2020 before 1.1.0.62, WNR2050 before 1.1.0.62, WNR3500Lv2 before 1.2.0.62, and XR500 before 2.3.2.22.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38514](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38514) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-38514.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-38514.svg)


## CVE-2021-38406
 Delta Electronic DOPSoft 2 (Version 2.00.07 and prior) lacks proper validation of user-supplied data when parsing specific project files. This could result in multiple out-of-bounds write instances. An attacker could leverage this vulnerability to execute code in the context of the current process.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38406](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38406) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-38406.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-38406.svg)


## CVE-2021-38404
 Delta Electronic DOPSoft 2 (Version 2.00.07 and prior) lacks proper validation of user-supplied data when parsing specific project files. This could result in a heap-based buffer overflow. An attacker could leverage this vulnerability to execute code in the context of the current process.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38404](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38404) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-38404.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-38404.svg)


## CVE-2021-38402
 Delta Electronic DOPSoft 2 (Version 2.00.07 and prior) lacks proper validation of user-supplied data when parsing specific project files. This could lead to a stack-based buffer overflow while trying to copy to a buffer during font string handling. An attacker could leverage this vulnerability to execute code in the context of the current process.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38402](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38402) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-38402.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-38402.svg)


## CVE-2021-38385
 Tor before 0.3.5.16, 0.4.5.10, and 0.4.6.7 mishandles the relationship between batch-signature verification and single-signature verification, leading to a remote assertion failure, aka TROVE-2021-007.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38385](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38385) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-38385.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-38385.svg)


## CVE-2021-38304
 Improper input validation in the National Instruments NI-PAL driver in versions 20.0.0 and prior may allow a privileged user to potentially enable escalation of privilege via local access.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38304](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38304) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-38304.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-38304.svg)


## CVE-2021-38303
 A SQL injection vulnerability exists in Sureline SUREedge Migrator 7.0.7.29360.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38303](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38303) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-38303.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-38303.svg)


## CVE-2021-38300
 arch/mips/net/bpf_jit.c in the Linux kernel through 5.14.6 can generate undesirable machine code when transforming unprivileged cBPF programs, allowing execution of arbitrary code within the kernel context. This occurs because conditional branches can exceed the 128 KB limit of the MIPS architecture.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38300](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38300) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-38300.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-38300.svg)


## CVE-2021-38176
 Due to improper input sanitization, an authenticated user with certain specific privileges can remotely call NZDT function modules listed in Solution Section to execute manipulated query to gain access to Backend Database. On successful exploitation the threat actor could completely compromise confidentiality, integrity, and availability of the system.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38176](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38176) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-38176.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-38176.svg)


## CVE-2021-38173
 Btrbk before 0.31.2 allows command execution because of the mishandling of remote hosts filtering SSH commands using ssh_filter_btrbk.sh in authorized_keys.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38173](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38173) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-38173.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-38173.svg)


## CVE-2021-38156
 In Nagios XI before 5.8.6, XSS exists in the dashboard page (/dashboards/#) when administrative users attempt to edit a dashboard.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38156](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38156) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-38156.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-38156.svg)


## CVE-2021-38153
 Some components in Apache Kafka use `Arrays.equals` to validate a password or key, which is vulnerable to timing attacks that make brute force attacks for such credentials more likely to be successful. Users should upgrade to 2.8.1 or higher, or 3.0.0 or higher where this vulnerability has been fixed. The affected versions include Apache Kafka 2.0.0, 2.0.1, 2.1.0, 2.1.1, 2.2.0, 2.2.1, 2.2.2, 2.3.0, 2.3.1, 2.4.0, 2.4.1, 2.5.0, 2.5.1, 2.6.0, 2.6.1, 2.6.2, 2.7.0, 2.7.1, and 2.8.0.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38153](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38153) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-38153.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-38153.svg)


## CVE-2021-38124
 Remote Code Execution vulnerability in Micro Focus ArcSight Enterprise Security Manager (ESM) product, affecting versions 7.0.2 through 7.5. The vulnerability could be exploited resulting in remote code execution.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38124](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38124) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-38124.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-38124.svg)


## CVE-2021-38112
 In the Amazon AWS WorkSpaces client 3.0.10 through 3.1.8 on Windows, argument injection in the workspaces:// URI handler can lead to remote code execution because of the Chromium Embedded Framework (CEF) --gpu-launcher argument. This is fixed in 3.1.9.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38112](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38112) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-38112.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-38112.svg)


## CVE-2021-38085
 The Canon TR150 print driver through 3.71.2.10 is vulnerable to a privilege escalation issue. During the add printer process, a local attacker can overwrite CNMurGE.dll and, if timed properly, the overwritten DLL will be loaded into a SYSTEM process resulting in escalation of privileges. This occurs because the driver drops a world-writable DLL into a CanonBJ %PROGRAMDATA% location that gets loaded by printisolationhost (a system process).

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38085](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38085) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-38085.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-38085.svg)


## CVE-2021-37927
 Zoho ManageEngine ADManager Plus version 7110 and prior allows account takeover via SSO.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37927](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37927) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-37927.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-37927.svg)


## CVE-2021-37925
 Zoho ManageEngine ADManager Plus version 7110 and prior has a Post-Auth OS command injection vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37925](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37925) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-37925.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-37925.svg)


## CVE-2021-37913
 The HGiga OAKlouds mobile portal does not filter special characters of the IPv6 Gateway parameter of the network interface card setting page. Remote attackers can use this vulnerability to perform command injection and execute arbitrary commands in the system without logging in.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37913](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37913) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-37913.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-37913.svg)


## CVE-2021-37912
 The HGiga OAKlouds mobile portal does not filter special characters of the Ethernet number parameter of the network interface card setting page. Remote attackers can use this vulnerability to perform command injection and execute arbitrary commands in the system without logging in.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37912](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37912) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-37912.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-37912.svg)


## CVE-2021-37909
 WriteRegistry function in TSSServiSign component does not filter and verify users&#8217; input, remote attackers can rewrite to the registry without permissions thus perform hijack attacks to execute arbitrary code.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37909](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37909) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-37909.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-37909.svg)


## CVE-2021-37761
 Zoho ManageEngine ADManager Plus version 7110 and prior is vulnerable to unrestricted file upload, leading to remote code execution.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37761](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37761) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-37761.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-37761.svg)


## CVE-2021-37750
 The Key Distribution Center (KDC) in MIT Kerberos 5 (aka krb5) before 1.18.5 and 1.19.x before 1.19.3 has a NULL pointer dereference in kdc/do_tgs_req.c via a FAST inner body that lacks a server field.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37750](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37750) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-37750.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-37750.svg)


## CVE-2021-37749
 MapService.svc in Hexagon GeoMedia WebMap 2020 before Update 2 (aka 16.6.2.66) allows blind SQL Injection via the Id (within sourceItems) parameter to the GetMap method.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37749](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37749) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-37749.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-37749.svg)


## CVE-2021-37741
 ManageEngine ADManager Plus before 7111 has Pre-authentication RCE vulnerabilities.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37741](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37741) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-37741.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-37741.svg)


## CVE-2021-37695
 ckeditor is an open source WYSIWYG HTML editor with rich content support. A potential vulnerability has been discovered in CKEditor 4 [Fake Objects](https://ckeditor.com/cke4/addon/fakeobjects) package. The vulnerability allowed to inject malformed Fake Objects HTML, which could result in executing JavaScript code. It affects all users using the CKEditor 4 plugins listed above at version &lt; 4.16.2. The problem has been recognized and patched. The fix will be available in version 4.16.2.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37695](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37695) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-37695.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-37695.svg)


## CVE-2021-37694
 @asyncapi/java-spring-cloud-stream-template generates a Spring Cloud Stream (SCSt) microservice. In versions prior to 0.7.0 arbitrary code injection was possible when an attacker controls the AsyncAPI document. An example is provided in GHSA-xj6r-2jpm-qvxp. There are no mitigations available and all users are advised to update.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37694](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37694) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-37694.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-37694.svg)


## CVE-2021-37608
 Unrestricted Upload of File with Dangerous Type vulnerability in Apache OFBiz allows an attacker to execute remote commands. This issue affects Apache OFBiz version 17.12.07 and prior versions. Upgrade to at least 17.12.08 or apply patches at https://issues.apache.org/jira/browse/OFBIZ-12297.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37608](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37608) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-37608.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-37608.svg)


## CVE-2021-37605
 In the Microchip MiWi v6.5 software stack, there is a possibility of frame counters being being validated / updated prior to message authentication.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37605](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37605) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-37605.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-37605.svg)


## CVE-2021-37576
 arch/powerpc/kvm/book3s_rtas.c in the Linux kernel through 5.13.5 on the powerpc platform allows KVM guest OS users to cause host OS memory corruption via rtas_args.nargs, aka CID-f62f3c20647e.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37576](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37576) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-37576.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-37576.svg)


## CVE-2021-37539
 Zoho ManageEngine ADManager Plus before 7111 is vulnerable to unrestricted file which leads to Remote code execution.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37539](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37539) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-37539.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-37539.svg)


## CVE-2021-37424
 ManageEngine ADSelfService Plus before 6112 is vulnerable to domain user account takeover.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37424](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37424) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-37424.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-37424.svg)


## CVE-2021-37423
 Zoho ManageEngine ADSelfService Plus 6111 and prior is vulnerable to linked applications takeover.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37423](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37423) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-37423.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-37423.svg)


## CVE-2021-37422
 Zoho ManageEngine ADSelfService Plus 6111 and prior is vulnerable to SQL Injection while linking the databases.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37422](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37422) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-37422.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-37422.svg)


## CVE-2021-37420
 ManageEngine ADSelfService Plus before 6112 is vulnerable to mail spoofing.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37420](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37420) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-37420.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-37420.svg)


## CVE-2021-37419
 ManageEngine ADSelfService Plus before 6112 is vulnerable to SSRF.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37419](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37419) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-37419.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-37419.svg)


## CVE-2021-37414
 Zoho ManageEngine DesktopCentral before 10.0.709 allows anyone to get a valid user's APIKEY without authentication.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37414](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37414) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-37414.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-37414.svg)


## CVE-2021-37271
 Cross Site Scripting (XSS) vulnerability exists in UEditor v1.4.3.3, which can be exploited by an attacker to obtain user cookie information.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37271](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37271) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-37271.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-37271.svg)


## CVE-2021-37267
 Cross Site Scripting (XSS) vulnerability exists in all versions of KindEditor, which can be exploited by an attacker to obtain user cookie information.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37267](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37267) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-37267.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-37267.svg)


## CVE-2021-37206
 A vulnerability has been identified in SIPROTEC 5 relays with CPU variants CP050 (All versions &lt; V8.80), SIPROTEC 5 relays with CPU variants CP100 (All versions &lt; V8.80), SIPROTEC 5 relays with CPU variants CP200 (All versions &lt; V8.80), SIPROTEC 5 relays with CPU variants CP300 (All versions &lt; V8.80). Received webpackets are not properly processed. An unauthenticated remote attacker with access to any of the Ethernet interfaces could send specially crafted packets to force a restart of the target device.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37206](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37206) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-37206.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-37206.svg)


## CVE-2021-37203
 A vulnerability has been identified in NX 1980 Series (All versions &lt; V1984), Solid Edge SE2021 (All versions &lt; SE2021MP8). The plmxmlAdapterIFC.dll contains an out-of-bounds read while parsing user supplied IFC files which could result in a read past the end of an allocated buffer. This could allow an attacker to cause a denial-of-service condition or read sensitive information from memory locations.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37203](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37203) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-37203.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-37203.svg)


## CVE-2021-37202
 A vulnerability has been identified in NX 1980 Series (All versions &lt; V1984), Solid Edge SE2021 (All versions &lt; SE2021MP8). The IFC adapter in affected application contains a use-after-free vulnerability that could be triggered while parsing user-supplied IFC files. An attacker could leverage this vulnerability to execute code in the context of the current process.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37202](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-37202) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-37202.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-37202.svg)


## CVE-2021-36983
 replay-sorcery-kms in Replay Sorcery 0.6.0 allows a local attacker to gain root privileges via a symlink attack on /tmp/replay-sorcery or /tmp/replay-sorcery/device.sock.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36983](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36983) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36983.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36983.svg)


## CVE-2021-36969
 Windows Redirected Drive Buffering SubSystem Driver Information Disclosure Vulnerability This CVE ID is unique from CVE-2021-38635, CVE-2021-38636.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38635](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38635) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-38635.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-38635.svg)


## CVE-2021-36934
 Windows Elevation of Privilege Vulnerability

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36934](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36934) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36934.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36934.svg)


## CVE-2021-36931
 Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-36928.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36928](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36928) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36928.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36928.svg)


## CVE-2021-36928
 Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-36931.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36928](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36928) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36928.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36928.svg)


## CVE-2021-36880
 Unauthenticated SQL Injection (SQLi) vulnerability in WordPress uListing plugin (versions &lt;= 2.0.3), vulnerable parameter: custom.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36880](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36880) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36880.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36880.svg)


## CVE-2021-36879
 Unauthenticated Privilege Escalation vulnerability in WordPress uListing plugin (versions &lt;= 2.0.5). Possible if WordPress configuration allows user registration.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36879](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36879) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36879.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36879.svg)


## CVE-2021-36878
 Cross-Site Request Forgery (CSRF) vulnerability in WordPress uListing plugin (versions &lt;= 2.0.5) makes it possible for attackers to update settings.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36878](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36878) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36878.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36878.svg)


## CVE-2021-36877
 Cross-Site Request Forgery (CSRF) vulnerability in WordPress uListing plugin (versions &lt;= 2.0.5) makes it possible for attackers to modify user roles.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36877](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36877) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36877.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36877.svg)


## CVE-2021-36876
 Multiple Cross-Site Request Forgery (CSRF) vulnerabilities in WordPress uListing plugin (versions &lt;= 2.0.5) as it lacks CSRF checks on plugin administration pages.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36876](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36876) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36876.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36876.svg)


## CVE-2021-36875
 Authenticated Reflected Cross-Site Scripting (XSS) vulnerability in WordPress uListing plugin (versions &lt;= 2.0.5). Vulnerable parameters: &amp;filter[id], &amp;filter[user], &amp;filter[expired_date], &amp;filter[created_date], &amp;filter[updated_date].

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36875](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36875) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36875.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36875.svg)


## CVE-2021-36874
 Authenticated Insecure Direct Object References (IDOR) vulnerability in WordPress uListing plugin (versions &lt;= 2.0.5).

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36874](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36874) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36874.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36874.svg)


## CVE-2021-36873
 Authenticated Persistent Cross-Site Scripting (XSS) vulnerability in WordPress iQ Block Country plugin (versions &lt;= 1.2.11). Vulnerable parameter: &amp;blockcountry_blockmessage.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36873](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36873) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36873.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36873.svg)


## CVE-2021-36872
 Authenticated Persistent Cross-Site Scripting (XSS) vulnerability in WordPress Popular Posts plugin (versions &lt;= 5.3.3). Vulnerable at &amp;widget-wpp[2][post_type].

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36872](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36872) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36872.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36872.svg)


## CVE-2021-36871
 Multiple Authenticated Persistent Cross-Site Scripting (XSS) vulnerabilities in WordPress WP Google Maps Pro premium plugin (versions &lt;= 8.1.11). Vulnerable parameters: &amp;wpgmaps_marker_category_name, Value &gt; &amp;attributes[], Name &gt; &amp;attributes[], &amp;icons[], &amp;names[], &amp;description, &amp;link, &amp;title.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36871](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36871) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36871.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36871.svg)


## CVE-2021-36870
 Multiple Authenticated Persistent Cross-Site Scripting (XSS) vulnerabilities in WordPress WP Google Maps plugin (versions &lt;= 8.1.12). Vulnerable parameters: &amp;dataset_name, &amp;wpgmza_gdpr_retention_purpose, &amp;wpgmza_gdpr_company_name, &amp;name #2, &amp;name, &amp;polyname #2, &amp;polyname, &amp;address.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36870](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36870) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36870.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36870.svg)


## CVE-2021-36841
 Authenticated Stored Cross-Site Scripting (XSS) vulnerability in YITH Maintenance Mode (WordPress plugin) versions &lt;= 1.3.7, vulnerable parameter &amp;yith_maintenance_newsletter_submit_label. Possible even when unfiltered HTML is disallowed by WordPress configuration.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36841](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36841) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36841.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36841.svg)


## CVE-2021-36823
 Authenticated Stored Cross-Site Scripting (XSS) vulnerability in WordPress Absolutely Glamorous Custom Admin plugin (versions &lt;= 6.8). Stored XSS possible via unsanitized input fields of the plugin settings, some of the payloads could make the frontend and the backend inaccessible.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36823](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36823) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36823.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36823.svg)


## CVE-2021-36754
 PowerDNS Authoritative Server 4.5.0 before 4.5.1 allows anybody to crash the process by sending a specific query (QTYPE 65535) that causes an out-of-bounds exception.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36754](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36754) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36754.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36754.svg)


## CVE-2021-36749
 In the Druid ingestion system, the InputSource is used for reading data from a certain data source. However, the HTTP InputSource allows authenticated users to read data from other sources than intended, such as the local file system, with the privileges of the Druid server process. This is not an elevation of privilege when users access Druid directly, since Druid also provides the Local InputSource, which allows the same level of access. But it is problematic when users interact with Druid indirectly through an application that allows users to specify the HTTP InputSource, but not the Local InputSource. In this case, users could bypass the application-level restriction by passing a file URL to the HTTP InputSource. This issue was previously mentioned as being fixed in 0.21.0 as per CVE-2021-26920 but was not fixed in 0.21.0 or 0.21.1.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36749](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36749) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36749.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36749.svg)


## CVE-2021-36745
 A vulnerability in Trend Micro ServerProtect for Storage 6.0, ServerProtect for EMC Celerra 5.8, ServerProtect for Network Appliance Filers 5.8, and ServerProtect for Microsoft Windows / Novell Netware 5.8 could allow a remote attacker to bypass authentication on affected installations.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36745](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36745) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36745.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36745.svg)


## CVE-2021-36621
 Sourcecodester Online Covid Vaccination Scheduler System 1.0 is vulnerable to SQL Injection. The username parameter is vulnerable to time-based SQL injection. Upon successful dumping the admin password hash, an attacker can decrypt and obtain the plain-text password. Hence, the attacker could authenticate as Administrator.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36621](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36621) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36621.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36621.svg)


## CVE-2021-36582
 In Kooboo CMS 2.1.1.0, it is possible to upload a remote shell (e.g., aspx) to the server and then call upon it to receive a reverse shell from the victim server. The files are uploaded to /Content/Template/root/reverse-shell.aspx and can be simply triggered by browsing that URL.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36582](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36582) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36582.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36582.svg)


## CVE-2021-36366
 Nagios XI before 5.8.5 incorrectly allows manage_services.sh wildcards.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36366](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36366) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36366.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36366.svg)


## CVE-2021-36365
 Nagios XI before 5.8.5 has Incorrect Permission Assignment for repairmysql.sh.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36365](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36365) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36365.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36365.svg)


## CVE-2021-36364
 Nagios XI before 5.8.5 incorrectly allows backup_xi.sh wildcards.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36364](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36364) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36364.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36364.svg)


## CVE-2021-36363
 Nagios XI before 5.8.5 has Incorrect Permission Assignment for migrate.php.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36363](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36363) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36363.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36363.svg)


## CVE-2021-36359
 OrbiTeam BSCW Classic before 7.4.3 allows exportpdf authenticated remote code execution (RCE) via XML tag injection because reportlab\platypus\paraparser.py (reached via bscw.cgi op=_editfolder.EditFolder) calls eval on attacker-supplied Python code. This is fixed in 5.0.12, 5.1.10, 5.2.4, 7.3.3, and 7.4.3.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36359](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36359) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36359.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36359.svg)


## CVE-2021-36286
 Dell SupportAssist Client Consumer versions 3.9.13.0 and any versions prior to 3.9.13.0 contain an arbitrary file deletion vulnerability that can be exploited by using the Windows feature of NTFS called Symbolic links. Symbolic links can be created by any(non-privileged) user under some object directories, but by themselves are not sufficient to successfully escalate privileges. However, combining them with a different object, such as the NTFS junction point allows for the exploitation. Support assist clean files functionality do not distinguish junction points from the physical folder and proceeds to clean the target of the junction that allows nonprivileged users to create junction points and delete arbitrary files on the system which can be accessed only by the admin.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36286](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36286) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36286.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36286.svg)


## CVE-2021-36285
 Dell BIOS contains an Improper Restriction of Excessive Authentication Attempts vulnerability. A local authenticated malicious administrator could exploit this vulnerability to bypass excessive NVMe password attempt mitigations in order to carry out a brute force attack.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36285](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36285) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36285.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36285.svg)


## CVE-2021-36284
 Dell BIOS contains an Improper Restriction of Excessive Authentication Attempts vulnerability. A local authenticated malicious administrator could exploit this vulnerability to bypass excessive admin password attempt mitigations in order to carry out a brute force attack.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36284](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36284) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36284.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36284.svg)


## CVE-2021-36283
 Dell BIOS contains an improper input validation vulnerability. A local authenticated malicious user may potentially exploit this vulnerability by using an SMI to gain arbitrary code execution in SMRAM.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36283](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36283) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36283.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36283.svg)


## CVE-2021-36219
 An issue was discovered in SKALE sgxwallet 1.58.3. The provided input for ECALL 14 triggers a branch in trustedEcdsaSign that frees a non-initialized pointer from the stack. An attacker can chain multiple enclave calls to prepare a stack that contains a valid address. This address is then freed, resulting in compromised integrity of the enclave. This was resolved after v1.58.3 and not reproducible in sgxwallet v1.77.0.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36219](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36219) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36219.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36219.svg)


## CVE-2021-36218
 An issue was discovered in SKALE sgxwallet 1.58.3. sgx_disp_ippsAES_GCMEncrypt allows an out-of-bounds write, resulting in a segfault and compromised enclave. This issue describes a buffer overflow, which was resolved prior to v1.77.0 and not reproducible in latest sgxwallet v1.77.0

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36218](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36218) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36218.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36218.svg)


## CVE-2021-36217
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2021-3502. Reason: This candidate is a duplicate of CVE-2021-3502. Notes: All CVE users should reference CVE-2021-3502 instead of this candidate. All references and descriptions in this candidate have been removed to prevent accidental usage.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36217](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36217) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36217.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36217.svg)


## CVE-2021-36160
 A carefully crafted request uri-path can cause mod_proxy_uwsgi to read above the allocated memory and crash (DoS). This issue affects Apache HTTP Server versions 2.4.30 to 2.4.48 (inclusive).

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36160](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36160) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36160.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36160.svg)


## CVE-2021-36159
 libfetch before 2021-07-26, as used in apk-tools, xbps, and other products, mishandles numeric strings for the FTP and HTTP protocols. The FTP passive mode implementation allows an out-of-bounds read because strtol is used to parse the relevant numbers into address bytes. It does not check if the line ends prematurely. If it does, the for-loop condition checks for the '\0' terminator one byte too late.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36159](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36159) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36159.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36159.svg)


## CVE-2021-36134
 Out of bounds write vulnerability in the JPEG parsing code of Netop Vision Pro up to and including 9.7.2 allows an adjacent unauthenticated attacker to write to arbitrary memory potentially leading to a Denial of Service (DoS).

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36134](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36134) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36134.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36134.svg)


## CVE-2021-36004
 Adobe InDesign version 16.0 (and earlier) is affected by an Out-of-bounds Write vulnerability in the CoolType library. An unauthenticated attacker could leverage this vulnerability to achieve remote code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36004](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36004) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36004.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36004.svg)


## CVE-2021-35959
 In Plone 5.0 through 5.2.4, Editors are vulnerable to XSS in the folder contents view, if a Contributor has created a folder with a SCRIPT tag in the description field.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35959](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35959) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-35959.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-35959.svg)


## CVE-2021-35945
 Couchbase Server 6.5.x, 6.6.0 through 6.6.2, and 7.0.0, has a Buffer Overflow. A specially crafted network packet sent from an attacker can crash memcached.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35945](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35945) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-35945.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-35945.svg)


## CVE-2021-35944
 Couchbase Server 6.5.x, 6.6.x through 6.6.2, and 7.0.0 has a Buffer Overflow. A specially crafted network packet sent from an attacker can crash memcached.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35944](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35944) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-35944.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-35944.svg)


## CVE-2021-35943
 Couchbase Server 6.5.x and 6.6.x through 6.6.2 has Incorrect Access Control. Externally managed users are not prevented from using an empty password, per RFC4513.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35943](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35943) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-35943.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-35943.svg)


## CVE-2021-35940
 An out-of-bounds array read in the apr_time_exp*() functions was fixed in the Apache Portable Runtime 1.6.3 release (CVE-2017-12613). The fix for this issue was not carried forward to the APR 1.7.x branch, and hence version 1.7.0 regressed compared to 1.6.3 and is vulnerable to the same issue.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35940](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35940) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-35940.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-35940.svg)


## CVE-2021-35479
 Nagios Log Server before 2.1.9 contains Stored XSS in the custom column view for the alert history and audit log function through the affected pp parameter. This affects users who open a crafted link or third-party web page.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35479](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35479) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-35479.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-35479.svg)


## CVE-2021-35478
 Nagios Log Server before 2.1.9 contains Reflected XSS in the dropdown box for the alert history and audit log function. All parameters used for filtering are affected. This affects users who open a crafted link or third-party web page.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35478](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35478) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-35478.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-35478.svg)


## CVE-2021-35205
 NETSCOUT Systems nGeniusONE version 6.3.0 build 1196 allows URL redirection in redirector.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35205](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35205) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-35205.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-35205.svg)


## CVE-2021-35204
 NETSCOUT Systems nGeniusONE 6.3.0 build 1196 allows Reflected Cross-Site Scripting (XSS) in the support endpoint.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35204](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35204) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-35204.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-35204.svg)


## CVE-2021-35203
 NETSCOUT Systems nGeniusONE 6.3.0 build 1196 allows Arbitrary File Read operations via the FDSQueryService endpoint.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35203](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35203) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-35203.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-35203.svg)


## CVE-2021-35202
 NETSCOUT Systems nGeniusONE 6.3.0 build 1196 allows Authorization Bypass (to access an endpoint) in FDSQueryService.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35202](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35202) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-35202.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-35202.svg)


## CVE-2021-35201
 NEI in NETSCOUT nGeniusONE 6.3.0 build 1196 allows XML External Entity (XXE) attacks.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35201](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35201) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-35201.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-35201.svg)


## CVE-2021-35200
 NETSCOUT nGeniusONE 6.3.0 build 1196 allows high-privileged users to achieve Stored Cross-Site Scripting (XSS) in FDSQueryService.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35200](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35200) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-35200.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-35200.svg)


## CVE-2021-35199
 NETSCOUT nGeniusONE 6.3.0 build 1196 and earlier allows Stored Cross-Site Scripting (XSS) in UploadFile.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35199](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35199) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-35199.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-35199.svg)


## CVE-2021-35198
 NETSCOUT nGeniusONE 6.3.0 build 1004 and earlier allows Stored Cross-Site Scripting (XSS) in the Packet Analysis module.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35198](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35198) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-35198.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-35198.svg)


## CVE-2021-35197
 In MediaWiki before 1.31.15, 1.32.x through 1.35.x before 1.35.3, and 1.36.x before 1.36.1, bots have certain unintended API access. When a bot account has a &quot;sitewide block&quot; applied, it is able to still &quot;purge&quot; pages through the MediaWiki Action API (which a &quot;sitewide block&quot; should have prevented).

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35197](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35197) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-35197.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-35197.svg)


## CVE-2021-35028
 A command injection vulnerability in the CGI program of the Zyxel VPN2S firmware version 1.12 could allow an authenticated, local user to execute arbitrary OS commands.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35028](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35028) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-35028.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-35028.svg)


## CVE-2021-35027
 A directory traversal vulnerability in the web server of the Zyxel VPN2S firmware version 1.12 could allow a remote attacker to gain access to sensitive information.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35027](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35027) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-35027.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-35027.svg)


## CVE-2021-34798
 Malformed requests may cause the server to dereference a NULL pointer. This issue affects Apache HTTP Server 2.4.48 and earlier.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34798](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34798) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-34798.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-34798.svg)


## CVE-2021-34723
 A vulnerability in a specific CLI command that is run on Cisco IOS XE SD-WAN Software could allow an authenticated, local attacker to overwrite arbitrary files in the configuration database of an affected device. This vulnerability is due to insufficient validation of specific CLI command parameters. An attacker could exploit this vulnerability by issuing that command with specific parameters. A successful exploit could allow the attacker to overwrite the content of the configuration database and gain root-level access to an affected device.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34723](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34723) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-34723.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-34723.svg)


## CVE-2021-34650
 The eID Easy WordPress plugin is vulnerable to Reflected Cross-Site Scripting via the error parameter found in the ~/admin.php file which allows attackers to inject arbitrary web scripts, in versions up to and including 4.6.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34650](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34650) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-34650.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-34650.svg)


## CVE-2021-34648
 The Ninja Forms WordPress plugin is vulnerable to arbitrary email sending via the trigger_email_action function found in the ~/includes/Routes/Submissions.php file, in versions up to and including 3.5.7. This allows authenticated attackers to send arbitrary emails from the affected server via the /ninja-forms-submissions/email-action REST API which can be used to socially engineer victims.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34648](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34648) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-34648.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-34648.svg)


## CVE-2021-34647
 The Ninja Forms WordPress plugin is vulnerable to sensitive information disclosure via the bulk_export_submissions function found in the ~/includes/Routes/Submissions.php file, in versions up to and including 3.5.7. This allows authenticated attackers to export all Ninja Forms submissions data via the /ninja-forms-submissions/export REST API which can include personally identifiable information.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34647](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34647) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-34647.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-34647.svg)


## CVE-2021-34640
 The Securimage-WP-Fixed WordPress plugin is vulnerable to Reflected Cross-Site Scripting due to the use of $_SERVER['PHP_SELF'] in the ~/securimage-wp.php file which allows attackers to inject arbitrary web scripts, in versions up to and including 3.5.4.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34640](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34640) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-34640.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-34640.svg)


## CVE-2021-34636
 The Countdown and CountUp, WooCommerce Sales Timers WordPress plugin is vulnerable to Cross-Site Request Forgery via the save_theme function found in the ~/includes/admin/coundown_theme_page.php file due to a missing nonce check which allows attackers to inject arbitrary web scripts, in versions up to and including 1.5.7.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34636](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34636) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-34636.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-34636.svg)


## CVE-2021-34576
 In Kaden PICOFLUX Air in all known versions an information exposure through observable discrepancy exists. This may give sensitive information (water consumption without distinct values) to third parties.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34576](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34576) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-34576.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-34576.svg)


## CVE-2021-34573
 In Enbra EWM in Version 1.7.29 together with several tested wireless M-Bus Sensors the events backflow and &quot;no flow&quot; are not reconized or misinterpreted. This may lead to wrong values and missing events.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34573](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34573) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-34573.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-34573.svg)


## CVE-2021-34572
 Enbra EWM 1.7.29 does not check for or detect replay attacks sent by wireless M-Bus Security mode 5 devices. Instead timestamps of the sensor are replaced by the time of the readout even if the data is a replay of earlier data.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34572](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34572) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-34572.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-34572.svg)


## CVE-2021-34571
 Multiple Wireless M-Bus devices by Enbra use Hard-coded Credentials in Security mode 5 without an option to change the encryption key. An adversary can learn all information that is available in Enbra EWM.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34571](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34571) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-34571.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-34571.svg)


## CVE-2021-34570
 Multiple Phoenix Contact PLCnext control devices in versions prior to 2021.0.5 LTS are prone to a DoS attack through special crafted JSON requests.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34570](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34570) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-34570.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-34570.svg)


## CVE-2021-34429
 For Eclipse Jetty versions 9.4.37-9.4.42, 10.0.1-10.0.5 &amp; 11.0.1-11.0.5, URIs can be crafted using some encoded characters to access the content of the WEB-INF directory and/or bypass some security constraints. This is a variation of the vulnerability reported in CVE-2021-28164/GHSA-v7ff-8wcx-gmc5.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34429](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34429) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-34429.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-34429.svg)


## CVE-2021-34428
 For Eclipse Jetty versions &lt;= 9.4.40, &lt;= 10.0.2, &lt;= 11.0.2, if an exception is thrown from the SessionListener#sessionDestroyed() method, then the session ID is not invalidated in the session ID manager. On deployments with clustered sessions and multiple contexts this can result in a session not being invalidated. This can result in an application used on a shared computer being left logged in.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34428](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34428) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-34428.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-34428.svg)


## CVE-2021-34370
 ** DISPUTED ** Accela Civic Platform through 20.1 allows ssoAdapter/logoutAction.do successURL XSS. NOTE: the vendor states &quot;there are configurable security flags and we are unable to reproduce them with the available information.&quot;

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34370](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34370) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-34370.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-34370.svg)


## CVE-2021-34369
 ** DISPUTED ** portlets/contact/ref/refContactDetail.do in Accela Civic Platform through 20.1 allows remote attackers to obtain sensitive information via a modified contactSeqNumber value. NOTE: the vendor states &quot;the information that is being queried is authorized for an authenticated user of that application, so we consider this not applicable.&quot;

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34369](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34369) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-34369.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-34369.svg)


## CVE-2021-34356
 A cross-site scripting (XSS) vulnerability has been reported to affect QNAP device running Photo Station. If exploited, this vulnerability allows remote attackers to inject malicious code. We have already fixed this vulnerability in the following versions of Photo Station: Photo Station 6.0.18 ( 2021/09/01 ) and later

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34356](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34356) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-34356.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-34356.svg)


## CVE-2021-34355
 A cross-site scripting (XSS) vulnerability has been reported to affect QNAP NAS running Photo Station. If exploited, this vulnerability allows remote attackers to inject malicious code. We have already fixed this vulnerability in the following versions of Photo Station: Photo Station 5.4.10 ( 2021/08/19 ) and later Photo Station 5.7.13 ( 2021/08/19 ) and later Photo Station 6.0.18 ( 2021/09/01 ) and later

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34355](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34355) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-34355.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-34355.svg)


## CVE-2021-34354
 A cross-site scripting (XSS) vulnerability has been reported to affect QNAP device running Photo Station. If exploited, this vulnerability allows remote attackers to inject malicious code. We have already fixed this vulnerability in the following versions of Photo Station: Photo Station 6.0.18 ( 2021/09/01 ) and later

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34354](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34354) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-34354.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-34354.svg)


## CVE-2021-34352
 A command injection vulnerability has been reported to affect QNAP device running QVR. If exploited, this vulnerability could allow remote attackers to run arbitrary commands. We have already fixed this vulnerability in the following versions of QVR: QVR 5.1.5 build 20210902 and later

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34352](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34352) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-34352.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-34352.svg)


## CVE-2021-34345
 A stack buffer overflow vulnerability has been reported to affect QNAP device running NVR Storage Expansion. If exploited, this vulnerability allows attackers to execute arbitrary code. We have already fixed this vulnerability in the following versions of NVR Storage Expansion: NVR Storage Expansion 1.0.6 ( 2021/08/03 ) and later

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34345](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34345) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-34345.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-34345.svg)


## CVE-2021-34075
 In Artica Pandora FMS &lt;=754 in the File Manager component, there is sensitive information exposed on the client side which attackers can access.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34075](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34075) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-34075.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-34075.svg)


## CVE-2021-33909
 fs/seq_file.c in the Linux kernel 3.16 through 5.13.x before 5.13.4 does not properly restrict seq buffer allocations, leading to an integer overflow, an Out-of-bounds Write, and escalation to root by an unprivileged user, aka CID-8cae8cd89f05.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33909](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33909) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-33909.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-33909.svg)


## CVE-2021-33904
 ** DISPUTED ** In Accela Civic Platform through 21.1, the security/hostSignon.do parameter servProvCode is vulnerable to XSS. NOTE: The vendor states &quot;there are configurable security flags and we are unable to reproduce them with the available information.&quot;

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33904](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33904) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-33904.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-33904.svg)


## CVE-2021-33829
 A cross-site scripting (XSS) vulnerability in the HTML Data Processor in CKEditor 4 4.14.0 through 4.16.x before 4.16.1 allows remote attackers to inject executable JavaScript code through a crafted comment because --!&gt; is mishandled.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33829](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33829) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-33829.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-33829.svg)


## CVE-2021-33737
 A vulnerability has been identified in SIMATIC CP 343-1 (incl. SIPLUS variants) (All versions), SIMATIC CP 343-1 Advanced (incl. SIPLUS variants) (All versions), SIMATIC CP 343-1 ERPC (All versions), SIMATIC CP 343-1 Lean (incl. SIPLUS variants) (All versions), SIMATIC CP 443-1 (incl. SIPLUS variants) (All versions), SIMATIC CP 443-1 Advanced (incl. SIPLUS variants) (All versions). Sending a specially crafted packet to port 102/tcp of an affected device could cause a Denial-of-Service condition. A restart is needed to restore normal operations.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33737](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33737) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-33737.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-33737.svg)


## CVE-2021-33720
 A vulnerability has been identified in SIPROTEC 5 relays with CPU variants CP050 (All versions &lt; V8.80), SIPROTEC 5 relays with CPU variants CP100 (All versions &lt; V8.80), SIPROTEC 5 relays with CPU variants CP200 (All versions), SIPROTEC 5 relays with CPU variants CP300 (All versions &lt; V8.80). Specially crafted packets sent to port 4443/tcp could cause a Denial-of-Service condition.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33720](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33720) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-33720.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-33720.svg)


## CVE-2021-33719
 A vulnerability has been identified in SIPROTEC 5 relays with CPU variants CP050 (All versions &lt; V8.80), SIPROTEC 5 relays with CPU variants CP100 (All versions &lt; V8.80), SIPROTEC 5 relays with CPU variants CP200 (All versions), SIPROTEC 5 relays with CPU variants CP300 (All versions &lt; V8.80). Specially crafted packets sent to port 4443/tcp could cause a Denial-of-Service condition or potential remote code execution.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33719](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33719) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-33719.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-33719.svg)


## CVE-2021-33705
 The SAP NetWeaver Portal, versions - 7.10, 7.11, 7.20, 7.30, 7.31, 7.40, 7.50, component Iviews Editor contains a Server-Side Request Forgery (SSRF) vulnerability which allows an unauthenticated attacker to craft a malicious URL which when clicked by a user can make any type of request (e.g. POST, GET) to any internal or external server. This can result in the accessing or modification of data accessible from the Portal but will not affect its availability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33705](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33705) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-33705.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-33705.svg)


## CVE-2021-33704
 The Service Layer of SAP Business One, version - 10.0, allows an authenticated attacker to invoke certain functions that would otherwise be restricted to specific users. For an attacker to discover the vulnerable function, no in-depth system knowledge is required. Once exploited via Network stack, the attacker may be able to read, modify or delete restricted data. The impact is that missing authorization can result of abuse of functionality usually restricted to specific users.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33704](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33704) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-33704.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-33704.svg)


## CVE-2021-33701
 DMIS Mobile Plug-In or SAP S/4HANA, versions - DMIS 2011_1_620, 2011_1_640, 2011_1_700, 2011_1_710, 2011_1_730, 710, 2011_1_731, 710, 2011_1_752, 2020, SAPSCORE 125, S4CORE 102, 102, 103, 104, 105, allows an attacker with access to highly privileged account to execute manipulated query in NDZT tool to gain access to Superuser account, leading to SQL Injection vulnerability, that highly impacts systems Confidentiality, Integrity and Availability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33701](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33701) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-33701.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-33701.svg)


## CVE-2021-33700
 SAP Business One, version - 10.0, allows a local attacker with access to the victim's browser under certain circumstances, to login as the victim without knowing his/her password. The attacker could so obtain highly sensitive information which the attacker could use to take substantial control of the vulnerable application.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33700](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33700) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-33700.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-33700.svg)


## CVE-2021-33698
 SAP Business One, version - 10.0, allows an attacker with business authorization to upload any files (including script files) without the proper file format validation.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33698](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33698) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-33698.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-33698.svg)


## CVE-2021-33697
 Under certain conditions, SAP BusinessObjects Business Intelligence Platform (SAPUI5), versions - 420, 430, can allow an unauthenticated attacker to redirect users to a malicious site due to Reverse Tabnabbing vulnerabilities.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33697](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33697) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-33697.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-33697.svg)


## CVE-2021-33696
 SAP BusinessObjects Business Intelligence Platform (Crystal Report), versions - 420, 430, does not sufficiently encode user controlled inputs and therefore an authorized attacker can exploit a XSS vulnerability, leading to non-permanently deface or modify displayed content from a Web site.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33696](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33696) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-33696.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-33696.svg)


## CVE-2021-33695
 Potentially, SAP Cloud Connector, version - 2.0 communication with the backend is accepted without sufficient validation of the certificate.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33695](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33695) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-33695.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-33695.svg)


## CVE-2021-33694
 SAP Cloud Connector, version - 2.0, does not sufficiently encode user-controlled inputs, allowing an attacker with Administrator rights, to include malicious codes that get stored in the database, and when accessed, could be executed in the application, resulting in Stored Cross-Site Scripting.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33694](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33694) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-33694.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-33694.svg)


## CVE-2021-33693
 SAP Cloud Connector, version - 2.0, allows an authenticated administrator to modify a configuration file to inject malicious codes that could potentially lead to OS command execution.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33693](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33693) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-33693.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-33693.svg)


## CVE-2021-33692
 SAP Cloud Connector, version - 2.0, allows the upload of zip files as backup. This backup file can be tricked to inject special elements such as '..' and '/' separators, for attackers to escape outside of the restricted location to access files or directories.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33692](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33692) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-33692.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-33692.svg)


## CVE-2021-33691
 NWDI Notification Service versions - 7.31, 7.40, 7.50, does not sufficiently encode user-controlled inputs, resulting in Cross-Site Scripting (XSS) vulnerability.SAP NetWeaver Development Infrastructure Notification Service allows a threat actor to send crafted scripts to a victim. If the victim has an active session when the crafted script gets executed, the threat actor could compromise information in victims session, and gain access to some sensitive information also.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33691](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33691) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-33691.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-33691.svg)


## CVE-2021-33690
 Server-Side Request Forgery (SSRF) vulnerability has been detected in the SAP NetWeaver Development Infrastructure Component Build Service versions - 7.11, 7.20, 7.30, 7.31, 7.40, 7.50The SAP NetWeaver Development Infrastructure Component Build Service allows a threat actor who has access to the server to perform proxy attacks on server by sending crafted queries. Due to this, the threat actor could completely compromise sensitive data residing on the Server and impact its availability.Note: The impact of this vulnerability depends on whether SAP NetWeaver Development Infrastructure (NWDI) runs on the intranet or internet. The CVSS score reflects the impact considering the worst-case scenario that it runs on the internet.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33690](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33690) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-33690.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-33690.svg)


## CVE-2021-33595
 A address bar spoofing vulnerability was discovered in Safe Browser for iOS. Showing the legitimate URL in the address bar while loading the content from other domain. This makes the user believe that the content is served by a legit domain. A remote attacker can leverage this to perform address bar spoofing attack.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33595](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33595) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-33595.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-33595.svg)


## CVE-2021-33594
 An address bar spoofing vulnerability was discovered in Safe Browser for Android. When user clicks on a specially crafted a malicious URL, it appears like a legitimate one on the address bar, while the content comes from other domain and presented in a window, covering the original content. A remote attacker can leverage this to perform address bar spoofing attack.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33594](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33594) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-33594.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-33594.svg)


## CVE-2021-33574
 The mq_notify function in the GNU C Library (aka glibc) versions 2.32 and 2.33 has a use-after-free. It may use the notification thread attributes object (passed through its struct sigevent parameter) after it has been freed by the caller, leading to a denial of service (application crash) or possibly unspecified other impact.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38604](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-38604) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-38604.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-38604.svg)


## CVE-2021-33560
 Libgcrypt before 1.8.8 and 1.9.x before 1.9.3 mishandles ElGamal encryption because it lacks exponent blinding to address a side-channel attack against mpi_powm, and the window size is not chosen appropriately. This, for example, affects use of ElGamal in OpenPGP.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33560](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33560) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-33560.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-33560.svg)


## CVE-2021-33531
 In Weidmueller Industrial WLAN devices in multiple versions an exploitable use of hard-coded credentials vulnerability exists in multiple iw_* utilities. The device operating system contains an undocumented encryption password, allowing for the creation of custom diagnostic scripts. An attacker can send diagnostic scripts while authenticated as a low privilege user to trigger this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33531](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33531) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-33531.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-33531.svg)


## CVE-2021-33530
 In Weidmueller Industrial WLAN devices in multiple versions an exploitable command injection vulnerability exists in encrypted diagnostic script functionality of the devices. A specially crafted diagnostic script file can cause arbitrary busybox commands to be executed, resulting in remote control over the device. An attacker can send diagnostic while authenticated as a low privilege user to trigger this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33530](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33530) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-33530.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-33530.svg)


## CVE-2021-33529
 In Weidmueller Industrial WLAN devices in multiple versions the usage of hard-coded cryptographic keys within the service agent binary allows for the decryption of captured traffic across the network from or to the device.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33529](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33529) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-33529.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-33529.svg)


## CVE-2021-33528
 In Weidmueller Industrial WLAN devices in multiple versions an exploitable privilege escalation vulnerability exists in the iw_console functionality. A specially crafted menu selection string can cause an escape from the restricted console, resulting in system access as the root user. An attacker can send commands while authenticated as a low privilege user to trigger this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33528](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33528) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-33528.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-33528.svg)


## CVE-2021-33348
 An issue was discovered in JFinal framework v4.9.10 and below. The &quot;set&quot; method of the &quot;Controller&quot; class of jfinal framework is not strictly filtered, which will lead to XSS vulnerabilities in some cases.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33348](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33348) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-33348.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-33348.svg)


## CVE-2021-33193
 A crafted method sent through HTTP/2 will bypass validation and be forwarded by mod_proxy, which can lead to request splitting or cache poisoning. This issue affects Apache HTTP Server 2.4.17 to 2.4.48.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33193](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33193) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-33193.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-33193.svg)


## CVE-2021-33045
 The identity authentication bypass vulnerability found in some Dahua products during the login process. Attackers can bypass device identity authentication by constructing malicious data packets.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33045](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33045) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-33045.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-33045.svg)


## CVE-2021-33044
 The identity authentication bypass vulnerability found in some Dahua products during the login process. Attackers can bypass device identity authentication by constructing malicious data packets.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33044](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33044) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-33044.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-33044.svg)


## CVE-2021-33019
 A stack-based buffer overflow vulnerability in Delta Electronics DOPSoft Version 4.00.11 and prior may be exploited by processing a specially crafted project file, which may allow an attacker to execute arbitrary code.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33019](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33019) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-33019.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-33019.svg)


## CVE-2021-33015
 Cscape (All Versions prior to 9.90 SP5) lacks proper validation of user-supplied data when parsing project files. This could lead to an out-of-bounds write via an uninitialized pointer. An attacker could leverage this vulnerability to execute code in the context of the current process.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33015](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33015) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-33015.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-33015.svg)


## CVE-2021-33007
 A heap-based buffer overflow in Delta Electronics TPEditor: v1.98.06 and prior may be exploited by processing a specially crafted project file. Successful exploitation of this vulnerability may allow an attacker to execute arbitrary code.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33007](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33007) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-33007.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-33007.svg)


## CVE-2021-33003
 Delta Electronics DIAEnergie Version 1.7.5 and prior may allow an attacker to retrieve passwords in cleartext due to a weak hashing algorithm.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33003](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-33003) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-33003.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-33003.svg)


## CVE-2021-32999
 Improper handling of exceptional conditions in SuiteLink server while processing command 0x01

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32999](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32999) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32999.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32999.svg)


## CVE-2021-32995
 Cscape (All Versions prior to 9.90 SP5) lacks proper validation of user-supplied data when parsing project files. This could lead to an out-of-bounds write. An attacker could leverage this vulnerability to execute code in the context of the current process.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32995](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32995) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32995.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32995.svg)


## CVE-2021-32991
 Delta Electronics DIAEnergie Version 1.7.5 and prior is vulnerable to cross-site request forgery, which may allow an attacker to cause a user to carry out an action unintentionally.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32991](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32991) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32991.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32991.svg)


## CVE-2021-32987
 Null pointer dereference in SuiteLink server while processing command 0x0b

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32987](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32987) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32987.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32987.svg)


## CVE-2021-32983
 A Blind SQL injection vulnerability exists in the /DataHandler/Handler_CFG.ashx endpoint of Delta Electronics DIAEnergie Version 1.7.5 and prior. The application does not properly validate the user-controlled value supplied through the parameter keyword before using it as part of an SQL query. A remote, unauthenticated attacker can exploit this issue to execute arbitrary code in the context of NT SERVICE\MSSQLSERVER.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32983](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32983) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32983.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32983.svg)


## CVE-2021-32979
 Null pointer dereference in SuiteLink server while processing commands 0x04/0x0a

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32979](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32979) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32979.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32979.svg)


## CVE-2021-32971
 Null pointer dereference in SuiteLink server while processing command 0x07

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32971](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32971) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32971.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32971.svg)


## CVE-2021-32967
 Delta Electronics DIAEnergie Version 1.7.5 and prior may allow an attacker to add a new administrative user without being authenticated or authorized, which may allow the attacker to log in and use the device with administrative privileges.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32967](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32967) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32967.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32967.svg)


## CVE-2021-32963
 Null pointer dereference in SuiteLink server while processing commands 0x03/0x10

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32963](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32963) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32963.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32963.svg)


## CVE-2021-32959
 Heap-based buffer overflow in SuiteLink server while processing commands 0x05/0x06

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32959](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32959) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32959.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32959.svg)


## CVE-2021-32955
 Delta Electronics DIAEnergie Version 1.7.5 and prior allows unrestricted file uploads, which may allow an attacker to remotely execute code.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32955](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32955) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32955.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32955.svg)


## CVE-2021-32931
 An uninitialized pointer in FATEK Automation FvDesigner, Versions 1.5.88 and prior may be exploited while the application is processing project files, allowing an attacker to craft a special project file that may permit arbitrary code execution.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32931](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32931) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32931.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32931.svg)


## CVE-2021-32839
 sqlparse is a non-validating SQL parser module for Python. In sqlparse versions 0.4.0 and 0.4.1 there is a regular Expression Denial of Service in sqlparse vulnerability. The regular expression may cause exponential backtracking on strings containing many repetitions of '\r\n' in SQL comments. Only the formatting feature that removes comments from SQL statements is affected by this regular expression. As a workaround don't use the sqlformat.format function with keyword strip_comments=True or the --strip-comments command line flag when using the sqlformat command line tool. The issues has been fixed in sqlparse 0.4.2.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32839](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32839) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32839.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32839.svg)


## CVE-2021-32838
 Flask-RESTX (pypi package flask-restx) is a community driven fork of Flask-RESTPlus. Flask-RESTX before version 0.5.1 is vulnerable to ReDoS (Regular Expression Denial of Service) in email_regex. This is fixed in version 0.5.1.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32838](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32838) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32838.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32838.svg)


## CVE-2021-32809
 ckeditor is an open source WYSIWYG HTML editor with rich content support. A potential vulnerability has been discovered in CKEditor 4 [Clipboard](https://ckeditor.com/cke4/addon/clipboard) package. The vulnerability allowed to abuse paste functionality using malformed HTML, which could result in injecting arbitrary HTML into the editor. It affects all users using the CKEditor 4 plugins listed above at version &gt;= 4.5.2. The problem has been recognized and patched. The fix will be available in version 4.16.2.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32809](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32809) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32809.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32809.svg)


## CVE-2021-32808
 ckeditor is an open source WYSIWYG HTML editor with rich content support. A vulnerability has been discovered in the clipboard Widget plugin if used alongside the undo feature. The vulnerability allows a user to abuse undo functionality using malformed widget HTML, which could result in executing JavaScript code. It affects all users using the CKEditor 4 plugins listed above at version &gt;= 4.13.0. The problem has been recognized and patched. The fix will be available in version 4.16.2.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32808](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32808) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32808.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32808.svg)


## CVE-2021-32779
 Envoy is an open source L7 proxy and communication bus designed for large modern service oriented architectures. In affected versions envoy incorrectly handled a URI '#fragment' element as part of the path element. Envoy is configured with an RBAC filter for authorization or similar mechanism with an explicit case of a final &quot;/admin&quot; path element, or is using a negative assertion with final path element of &quot;/admin&quot;. The client sends request to &quot;/app1/admin#foo&quot;. In Envoy prior to 1.18.0, or 1.18.0+ configured with path_normalization=false. Envoy treats fragment as a suffix of the query string when present, or as a suffix of the path when query string is absent, so it evaluates the final path element as &quot;/admin#foo&quot; and mismatches with the configured &quot;/admin&quot; path element. In Envoy 1.18.0+ configured with path_normalization=true. Envoy transforms this to /app1/admin%23foo and mismatches with the configured /admin prefix. The resulting URI is sent to the next server-agent with the offending &quot;#foo&quot; fragment which violates RFC3986 or with the nonsensical &quot;%23foo&quot; text appended. A specifically constructed request with URI containing '#fragment' element delivered by an untrusted client in the presence of path based request authorization resulting in escalation of Privileges when path based request authorization extensions. Envoy versions 1.19.1, 1.18.4, 1.17.4, 1.16.5 contain fixes that removes fragment from URI path in incoming requests.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39206](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39206) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39206.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39206.svg)


## CVE-2021-32778
 Envoy is an open source L7 proxy and communication bus designed for large modern service oriented architectures. In affected versions envoy&#8217;s procedure for resetting a HTTP/2 stream has O(N^2) complexity, leading to high CPU utilization when a large number of streams are reset. Deployments are susceptible to Denial of Service when Envoy is configured with high limit on H/2 concurrent streams. An attacker wishing to exploit this vulnerability would require a client opening and closing a large number of H/2 streams. Envoy versions 1.19.1, 1.18.4, 1.17.4, 1.16.5 contain fixes to reduce time complexity of resetting HTTP/2 streams. As a workaround users may limit the number of simultaneous HTTP/2 dreams for upstream and downstream peers to a low number, i.e. 100.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32778](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32778) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32778.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32778.svg)


## CVE-2021-32777
 Envoy is an open source L7 proxy and communication bus designed for large modern service oriented architectures. In affected versions when ext-authz extension is sending request headers to the external authorization service it must merge multiple value headers according to the HTTP spec. However, only the last header value is sent. This may allow specifically crafted requests to bypass authorization. Attackers may be able to escalate privileges when using ext-authz extension or back end service that uses multiple value headers for authorization. A specifically constructed request may be delivered by an untrusted downstream peer in the presence of ext-authz extension. Envoy versions 1.19.1, 1.18.4, 1.17.4, 1.16.5 contain fixes to the ext-authz extension to correctly merge multiple request header values, when sending request for authorization.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32777](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32777) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32777.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32777.svg)
- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39206](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-39206) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-39206.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-39206.svg)


## CVE-2021-32736
 think-helper defines a set of helper functions for ThinkJS. In versions of think-helper prior to 1.1.3, the software receives input from an upstream component that specifies attributes that are to be initialized or updated in an object, but it does not properly control modifications of attributes of the object prototype. The vulnerability is patched in version 1.1.3.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32736](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32736) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32736.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32736.svg)


## CVE-2021-32610
 In Archive_Tar before 1.4.14, symlinks can refer to targets outside of the extracted archive, a different vulnerability than CVE-2020-36193.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32610](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32610) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32610.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32610.svg)


## CVE-2021-32558
 An issue was discovered in Sangoma Asterisk 13.x before 13.38.3, 16.x before 16.19.1, 17.x before 17.9.4, and 18.x before 18.5.1, and Certified Asterisk before 16.8-cert10. If the IAX2 channel driver receives a packet that contains an unsupported media format, a crash can occur.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32558](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32558) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32558.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32558.svg)


## CVE-2021-32466
 An uncontrolled search path element privilege escalation vulnerability in Trend Micro HouseCall for Home Networks version 5.3.1225 and below could allow an attacker to escalate privileges by placing a custom crafted file in a specific directory to load a malicious library. Please note that an attacker must first obtain the ability to execute low-privileged code on the target system to exploit this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32466](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32466) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32466.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32466.svg)


## CVE-2021-32299
 An issue was discovered in pbrt through 20200627. A stack-buffer-overflow exists in the function pbrt::ParamSet::ParamSet() located in paramset.h. It allows an attacker to cause code Execution.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32299](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32299) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32299.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32299.svg)


## CVE-2021-32298
 An issue was discovered in libiff through 20190123. A global-buffer-overflow exists in the function IFF_errorId located in error.c. It allows an attacker to cause code Execution.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32298](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32298) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32298.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32298.svg)


## CVE-2021-32297
 An issue was discovered in LIEF through 0.11.4. A heap-buffer-overflow exists in the function main located in pe_reader.c. It allows an attacker to cause code Execution.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32297](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32297) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32297.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32297.svg)


## CVE-2021-32294
 An issue was discovered in libgig through 20200507. A heap-buffer-overflow exists in the function RIFF::List::GetSubList located in RIFF.cpp. It allows an attacker to cause code Execution.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32294](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32294) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32294.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32294.svg)


## CVE-2021-32289
 An issue was discovered in heif through through v3.6.2. A NULL pointer dereference exists in the function convertByteStreamToRBSP() located in nalutil.cpp. It allows an attacker to cause Denial of Service.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32289](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32289) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32289.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32289.svg)


## CVE-2021-32288
 An issue was discovered in heif through v3.6.2. A global-buffer-overflow exists in the function HevcDecoderConfigurationRecord::getPicHeight() located in hevcdecoderconfigrecord.cpp. It allows an attacker to cause code Execution.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32288](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32288) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32288.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32288.svg)


## CVE-2021-32287
 An issue was discovered in heif through v3.6.2. A global-buffer-overflow exists in the function HevcDecoderConfigurationRecord::getPicWidth() located in hevcdecoderconfigrecord.cpp. It allows an attacker to cause code Execution.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32287](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32287) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32287.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32287.svg)


## CVE-2021-32286
 An issue was discovered in hcxtools through 6.1.6. A global-buffer-overflow exists in the function pcapngoptionwalk located in hcxpcapngtool.c. It allows an attacker to cause code Execution.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32286](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32286) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32286.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32286.svg)


## CVE-2021-32285
 An issue was discovered in gravity through 0.8.1. A NULL pointer dereference exists in the function list_iterator_next() located in gravity_core.c. It allows an attacker to cause Denial of Service.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32285](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32285) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32285.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32285.svg)


## CVE-2021-32284
 An issue was discovered in gravity through 0.8.1. A NULL pointer dereference exists in the function ircode_register_pop_context_protect() located in gravity_ircode.c. It allows an attacker to cause Denial of Service.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32284](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32284) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32284.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32284.svg)


## CVE-2021-32283
 An issue was discovered in gravity through 0.8.1. A NULL pointer dereference exists in the function gravity_string_to_value() located in gravity_value.c. It allows an attacker to cause Denial of Service.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32283](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32283) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32283.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32283.svg)


## CVE-2021-32282
 An issue was discovered in gravity through 0.8.1. A NULL pointer dereference exists in the function ircode_add_check() located in gravity_ircode.c. It allows an attacker to cause Denial of Service.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32282](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32282) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32282.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32282.svg)


## CVE-2021-32281
 An issue was discovered in gravity through 0.8.1. A heap-buffer-overflow exists in the function gnode_function_add_upvalue located in gravity_ast.c. It allows an attacker to cause code Execution.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32281](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32281) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32281.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32281.svg)


## CVE-2021-32280
 An issue was discovered in fig2dev before 3.2.8.. A NULL pointer dereference exists in the function compute_closed_spline() located in trans_spline.c. It allows an attacker to cause Denial of Service. The fixed version of fig2dev is 3.2.8.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32280](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32280) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32280.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32280.svg)


## CVE-2021-32278
 An issue was discovered in faad2 through 2.10.0. A heap-buffer-overflow exists in the function lt_prediction located in lt_predict.c. It allows an attacker to cause code Execution.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32278](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32278) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32278.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32278.svg)


## CVE-2021-32277
 An issue was discovered in faad2 through 2.10.0. A heap-buffer-overflow exists in the function sbr_qmf_analysis_32 located in sbr_qmf.c. It allows an attacker to cause code Execution.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32277](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32277) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32277.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32277.svg)


## CVE-2021-32276
 An issue was discovered in faad2 through 2.10.0. A NULL pointer dereference exists in the function get_sample() located in output.c. It allows an attacker to cause Denial of Service.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32276](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32276) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32276.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32276.svg)


## CVE-2021-32275
 An issue was discovered in faust through v2.30.5. A NULL pointer dereference exists in the function CosPrim::computeSigOutput() located in cosprim.hh. It allows an attacker to cause Denial of Service.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32275](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32275) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32275.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32275.svg)


## CVE-2021-32274
 An issue was discovered in faad2 through 2.10.0. A heap-buffer-overflow exists in the function sbr_qmf_synthesis_64 located in sbr_qmf.c. It allows an attacker to cause code Execution.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32274](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32274) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32274.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32274.svg)


## CVE-2021-32273
 An issue was discovered in faad2 through 2.10.0. A stack-buffer-overflow exists in the function ftypin located in mp4read.c. It allows an attacker to cause Code Execution.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32273](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32273) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32273.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32273.svg)


## CVE-2021-32272
 An issue was discovered in faad2 before 2.10.0. A heap-buffer-overflow exists in the function stszin located in mp4read.c. It allows an attacker to cause Code Execution.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32272](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32272) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32272.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32272.svg)


## CVE-2021-32271
 An issue was discovered in gpac through 20200801. A stack-buffer-overflow exists in the function DumpRawUIConfig located in odf_dump.c. It allows an attacker to cause code Execution.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32271](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32271) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32271.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32271.svg)


## CVE-2021-32270
 An issue was discovered in gpac through 20200801. A NULL pointer dereference exists in the function vwid_box_del located in box_code_base.c. It allows an attacker to cause Denial of Service.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32270](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32270) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32270.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32270.svg)


## CVE-2021-32269
 An issue was discovered in gpac through 20200801. A NULL pointer dereference exists in the function ilst_item_box_dump located in box_dump.c. It allows an attacker to cause Denial of Service.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32269](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32269) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32269.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32269.svg)


## CVE-2021-32268
 Buffer overflow vulnerability in function gf_fprintf in os_file.c in gpac before 1.0.1 allows attackers to execute arbitrary code. The fixed version is 1.0.1.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32268](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32268) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32268.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32268.svg)


## CVE-2021-32265
 An issue was discovered in Bento4 through v1.6.0-637. A global-buffer-overflow exists in the function AP4_MemoryByteStream::WritePartial() located in Ap4ByteStream.cpp. It allows an attacker to cause code execution or information disclosure.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32265](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32265) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32265.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32265.svg)


## CVE-2021-31989
 A user with permission to log on to the machine hosting the AXIS Device Manager client could under certain conditions extract a memory dump from the built-in Windows Task Manager application. The memory dump may potentially contain credentials of connected Axis devices.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31989](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31989) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-31989.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-31989.svg)


## CVE-2021-31923
 Ping Identity PingAccess before 5.3.3 allows HTTP request smuggling via header manipulation.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31923](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31923) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-31923.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-31923.svg)


## CVE-2021-31891
 A vulnerability has been identified in Desigo CC (All versions with OIS Extension Module), GMA-Manager (All versions with OIS running on Debian 9 or earlier), Operation Scheduler (All versions with OIS running on Debian 9 or earlier), Siveillance Control (All versions with OIS running on Debian 9 or earlier), Siveillance Control Pro (All versions). The affected application incorrectly neutralizes special elements in a specific HTTP GET request which could lead to command injection. An unauthenticated remote attacker could exploit this vulnerability to execute arbitrary code on the system with root privileges.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31891](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31891) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-31891.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-31891.svg)


## CVE-2021-31878
 An issue was discovered in PJSIP in Asterisk before 16.19.1 and before 18.5.1. To exploit, a re-INVITE without SDP must be received after Asterisk has sent a BYE request.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31878](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31878) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-31878.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-31878.svg)


## CVE-2021-31847
 Improper access control vulnerability in the repair process for McAfee Agent for Windows prior to 5.7.4 could allow a local attacker to perform a DLL preloading attack using unsigned DLLs. This would result in elevation of privileges and the ability to execute arbitrary code as the system user, through not correctly protecting a temporary directory used in the repair process and not checking the DLL signature.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31847](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31847) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-31847.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-31847.svg)


## CVE-2021-31845
 A buffer overflow vulnerability in McAfee Data Loss Prevention (DLP) Discover prior to 11.6.100 allows an attacker in the same network as the DLP Discover to execute arbitrary code through placing carefully constructed Ami Pro (.sam) files onto a machine and having DLP Discover scan it, leading to remote code execution with elevated privileges. This is caused by the destination buffer being of fixed size and incorrect checks being made on the source size.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31845](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31845) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-31845.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-31845.svg)


## CVE-2021-31844
 A buffer overflow vulnerability in McAfee Data Loss Prevention (DLP) Endpoint for Windows prior to 11.6.200 allows a local attacker to execute arbitrary code with elevated privileges through placing carefully constructed Ami Pro (.sam) files onto the local system and triggering a DLP Endpoint scan through accessing a file. This is caused by the destination buffer being of fixed size and incorrect checks being made on the source size.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31844](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31844) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-31844.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-31844.svg)


## CVE-2021-31843
 Improper privileges management vulnerability in McAfee Endpoint Security (ENS) Windows prior to 10.7.0 September 2021 Update allows local users to access files which they would otherwise not have access to via manipulating junction links to redirect McAfee folder operations to an unintended location.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31843](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31843) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-31843.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-31843.svg)


## CVE-2021-31842
 XML Entity Expansion injection vulnerability in McAfee Endpoint Security (ENS) for Windows prior to 10.7.0 September 2021 Update allows a local user to initiate high CPU and memory consumption resulting in a Denial of Service attack through carefully editing the EPDeploy.xml file and then executing the setup process.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31842](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31842) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-31842.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-31842.svg)


## CVE-2021-31841
 A DLL sideloading vulnerability in McAfee Agent for Windows prior to 5.7.4 could allow a local user to perform a DLL sideloading attack with an unsigned DLL with a specific name and in a specific location. This would result in the user gaining elevated permissions and the ability to execute arbitrary code as the system user, through not checking the DLL signature.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31841](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31841) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-31841.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-31841.svg)


## CVE-2021-31836
 Improper privilege management vulnerability in maconfig for McAfee Agent for Windows prior to 5.7.4 allows a local user to gain access to sensitive information. The utility was able to be run from any location on the file system and by a low privileged user.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31836](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31836) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-31836.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-31836.svg)


## CVE-2021-31819
 In Halibut versions prior to 4.4.7 there is a deserialisation vulnerability that could allow remote code execution on systems that already trust each other based on certificate verification.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31819](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31819) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-31819.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-31819.svg)


## CVE-2021-31810
 An issue was discovered in Ruby through 2.6.7, 2.7.x through 2.7.3, and 3.x through 3.0.1. A malicious FTP server can use the PASV response to trick Net::FTP into connecting back to a given IP address and port. This potentially makes curl extract information about services that are otherwise private and not disclosed (e.g., the attacker can conduct port scans and service banner extractions).

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31810](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31810) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-31810.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-31810.svg)


## CVE-2021-31799
 In RDoc 3.11 through 6.x before 6.3.1, as distributed with Ruby through 3.0.1, it is possible to execute arbitrary code via | and tags in a filename.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31799](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31799) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-31799.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-31799.svg)


## CVE-2021-31721
 Chevereto before 3.17.1 allows Cross Site Scripting (XSS) via an image title at the image upload stage.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31721](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31721) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-31721.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-31721.svg)


## CVE-2021-31606
 furlongm openvpn-monitor through 1.1.3 allows Authorization Bypass to disconnect arbitrary clients.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31606](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31606) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-31606.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-31606.svg)


## CVE-2021-31605
 furlongm openvpn-monitor through 1.1.3 allows %0a command injection via the OpenVPN management interface socket. This can shut down the server via signal%20SIGTERM.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31605](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31605) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-31605.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-31605.svg)


## CVE-2021-31604
 furlongm openvpn-monitor through 1.1.3 allows CSRF to disconnect an arbitrary client.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31604](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31604) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-31604.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-31604.svg)


## CVE-2021-31535
 LookupCol.c in X.Org X through X11R7.7 and libX11 before 1.7.1 might allow remote attackers to execute arbitrary code. The libX11 XLookupColor request (intended for server-side color lookup) contains a flaw allowing a client to send color-name requests with a name longer than the maximum size allowed by the protocol (and also longer than the maximum packet size for normal-sized packets). The user-controlled data exceeding the maximum size is then interpreted by the server as additional X protocol requests and executed, e.g., to disable X server authorization completely. For example, if the victim encounters malicious terminal control sequences for color codes, then the attacker may be able to take full control of the running graphical session.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31535](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31535) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-31535.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-31535.svg)


## CVE-2021-31506
 This vulnerability allows remote attackers to disclose sensitive information on affected installations of OpenText Brava! Desktop Build 16.6.4.55. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of PDF files. The issue results from the lack of proper validation of user-supplied data, which can result in a read past the end of an allocated data structure. An attacker can leverage this in conjunction with other vulnerabilities to execute arbitrary code in the context of the current process. Was ZDI-CAN-13674.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31506](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-31506) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-31506.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-31506.svg)


## CVE-2021-30860
 An integer overflow was addressed with improved input validation. This issue is fixed in Security Update 2021-005 Catalina, iOS 14.8 and iPadOS 14.8, macOS Big Sur 11.6, watchOS 7.6.2. Processing a maliciously crafted PDF may lead to arbitrary code execution. Apple is aware of a report that this issue may have been actively exploited.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30860](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30860) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30860.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30860.svg)


## CVE-2021-30858
 A use after free issue was addressed with improved memory management. This issue is fixed in iOS 14.8 and iPadOS 14.8, macOS Big Sur 11.6. Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been actively exploited.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30858](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30858) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30858.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30858.svg)


## CVE-2021-30783
 An access issue was addressed with improved access restrictions. This issue is fixed in macOS Big Sur 11.5, Security Update 2021-004 Catalina, Security Update 2021-005 Mojave. A sandboxed process may be able to circumvent sandbox restrictions.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30783](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30783) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30783.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30783.svg)


## CVE-2021-30781
 This issue was addressed with improved checks. This issue is fixed in iOS 14.7, macOS Big Sur 11.5, watchOS 7.6, tvOS 14.7, Security Update 2021-005 Mojave, Security Update 2021-004 Catalina. A local attacker may be able to cause unexpected application termination or arbitrary code execution.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30781](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30781) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30781.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30781.svg)


## CVE-2021-30780
 An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in iOS 14.7, macOS Big Sur 11.5, watchOS 7.6, tvOS 14.7, Security Update 2021-005 Mojave, Security Update 2021-004 Catalina. A malicious application may be able to gain root privileges.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30780](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30780) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30780.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30780.svg)


## CVE-2021-30779
 This issue was addressed with improved checks. This issue is fixed in iOS 14.7, macOS Big Sur 11.5, watchOS 7.6, tvOS 14.7. Processing a maliciously crafted image may lead to arbitrary code execution.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30779](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30779) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30779.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30779.svg)


## CVE-2021-30777
 An injection issue was addressed with improved validation. This issue is fixed in macOS Big Sur 11.5, Security Update 2021-004 Catalina, Security Update 2021-005 Mojave. A malicious application may be able to gain root privileges.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30777](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30777) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30777.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30777.svg)


## CVE-2021-30776
 A logic issue was addressed with improved validation. This issue is fixed in iOS 14.7, macOS Big Sur 11.5, watchOS 7.6, tvOS 14.7, Security Update 2021-004 Catalina. Playing a malicious audio file may lead to an unexpected application termination.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30776](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30776) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30776.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30776.svg)


## CVE-2021-30773
 An issue in code signature validation was addressed with improved checks. This issue is fixed in iOS 14.7, tvOS 14.7, watchOS 7.6. A malicious application may be able to bypass code signing checks.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30773](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30773) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30773.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30773.svg)


## CVE-2021-30768
 A logic issue was addressed with improved validation. This issue is fixed in iOS 14.7, macOS Big Sur 11.5, watchOS 7.6, tvOS 14.7, Security Update 2021-004 Catalina. A sandboxed process may be able to circumvent sandbox restrictions.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30768](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30768) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30768.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30768.svg)


## CVE-2021-30713
 A permissions issue was addressed with improved validation. This issue is fixed in macOS Big Sur 11.4. A malicious application may be able to bypass Privacy preferences. Apple is aware of a report that this issue may have been actively exploited..

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30713](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30713) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30713.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30713.svg)


## CVE-2021-30705
 This issue was addressed with improved checks. This issue is fixed in tvOS 14.6, Security Update 2021-004 Mojave, iOS 14.6 and iPadOS 14.6, Security Update 2021-003 Catalina, macOS Big Sur 11.4, watchOS 7.5. Processing a maliciously crafted ASTC file may disclose memory contents.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30705](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30705) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30705.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30705.svg)


## CVE-2021-30704
 A logic issue was addressed with improved state management. This issue is fixed in tvOS 14.6, Security Update 2021-004 Mojave, iOS 14.6 and iPadOS 14.6, Security Update 2021-003 Catalina, macOS Big Sur 11.4, watchOS 7.5. An application may be able to execute arbitrary code with kernel privileges.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30704](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30704) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30704.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30704.svg)


## CVE-2021-30703
 A double free issue was addressed with improved memory management. This issue is fixed in tvOS 14.6, iOS 14.6 and iPadOS 14.6, Security Update 2021-004 Catalina, Security Update 2021-005 Mojave, macOS Big Sur 11.4, watchOS 7.5. An application may be able to execute arbitrary code with kernel privileges.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30703](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30703) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30703.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30703.svg)


## CVE-2021-30701
 This issue was addressed with improved checks. This issue is fixed in tvOS 14.6, iOS 14.6 and iPadOS 14.6, Security Update 2021-003 Catalina, macOS Big Sur 11.4, watchOS 7.5. Processing a maliciously crafted image may lead to arbitrary code execution.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30701](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30701) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30701.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30701.svg)


## CVE-2021-30700
 This issue was addressed with improved checks. This issue is fixed in macOS Big Sur 11.4, tvOS 14.6, watchOS 7.5, iOS 14.6 and iPadOS 14.6. Processing a maliciously crafted image may lead to disclosure of user information.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30700](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30700) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30700.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30700.svg)


## CVE-2021-30699
 A window management issue was addressed with improved state management. This issue is fixed in iOS 14.6 and iPadOS 14.6. A user may be able to view restricted content from the lockscreen.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30699](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30699) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30699.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30699.svg)


## CVE-2021-30698
 A null pointer dereference was addressed with improved input validation. This issue is fixed in macOS Big Sur 11.4, Safari 14.1.1, iOS 14.6 and iPadOS 14.6. A remote attacker may be able to cause a denial of service.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30698](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30698) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30698.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30698.svg)


## CVE-2021-30697
 A logic issue was addressed with improved state management. This issue is fixed in tvOS 14.6, Security Update 2021-004 Mojave, iOS 14.6 and iPadOS 14.6, Security Update 2021-003 Catalina, macOS Big Sur 11.4, watchOS 7.5. A local user may be able to leak sensitive user information.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30697](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30697) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30697.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30697.svg)


## CVE-2021-30696
 An attacker in a privileged network position may be able to misrepresent application state. This issue is fixed in macOS Big Sur 11.4, Security Update 2021-003 Catalina, Security Update 2021-004 Mojave. A logic issue was addressed with improved state management.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30696](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30696) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30696.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30696.svg)


## CVE-2021-30695
 An out-of-bounds read was addressed with improved bounds checking. This issue is fixed in macOS Big Sur 11.4, Security Update 2021-003 Catalina, Security Update 2021-004 Mojave, iOS 14.6 and iPadOS 14.6. Processing a maliciously crafted USD file may disclose memory contents.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30695](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30695) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30695.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30695.svg)


## CVE-2021-30694
 An information disclosure issue was addressed with improved state management. This issue is fixed in macOS Big Sur 11.4, Security Update 2021-003 Catalina, Security Update 2021-004 Mojave, iOS 14.6 and iPadOS 14.6. Processing a maliciously crafted USD file may disclose memory contents.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30694](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30694) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30694.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30694.svg)


## CVE-2021-30693
 A validation issue was addressed with improved logic. This issue is fixed in macOS Big Sur 11.4, Security Update 2021-003 Catalina, Security Update 2021-004 Mojave, iOS 14.6 and iPadOS 14.6. Processing a maliciously crafted image may lead to arbitrary code execution.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30693](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30693) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30693.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30693.svg)


## CVE-2021-30692
 An information disclosure issue was addressed with improved state management. This issue is fixed in macOS Big Sur 11.4, Security Update 2021-003 Catalina, Security Update 2021-004 Mojave, iOS 14.6 and iPadOS 14.6. Processing a maliciously crafted USD file may disclose memory contents.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30692](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30692) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30692.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30692.svg)


## CVE-2021-30691
 An information disclosure issue was addressed with improved state management. This issue is fixed in macOS Big Sur 11.4, Security Update 2021-003 Catalina, Security Update 2021-004 Mojave, iOS 14.6 and iPadOS 14.6. Processing a maliciously crafted USD file may disclose memory contents.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30691](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30691) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30691.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30691.svg)


## CVE-2021-30690
 Multiple issues in apache were addressed by updating apache to version 2.4.46. This issue is fixed in Security Update 2021-004 Mojave. Multiple issues in apache.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30690](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30690) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30690.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30690.svg)


## CVE-2021-30689
 A logic issue was addressed with improved state management. This issue is fixed in tvOS 14.6, iOS 14.6 and iPadOS 14.6, Safari 14.1.1, macOS Big Sur 11.4, watchOS 7.5. Processing maliciously crafted web content may lead to universal cross site scripting.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30689](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30689) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30689.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30689.svg)


## CVE-2021-30688
 A malicious application may be able to break out of its sandbox. This issue is fixed in macOS Big Sur 11.4, Security Update 2021-003 Catalina. A path handling issue was addressed with improved validation.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30688](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30688) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30688.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30688.svg)


## CVE-2021-30687
 An out-of-bounds read was addressed with improved bounds checking. This issue is fixed in tvOS 14.6, Security Update 2021-004 Mojave, iOS 14.6 and iPadOS 14.6, Security Update 2021-003 Catalina, macOS Big Sur 11.4, watchOS 7.5. Processing a maliciously crafted image may lead to disclosure of user information.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30687](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30687) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30687.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30687.svg)


## CVE-2021-30686
 An out-of-bounds read was addressed with improved bounds checking. This issue is fixed in tvOS 14.6, iOS 14.6 and iPadOS 14.6, Security Update 2021-003 Catalina, macOS Big Sur 11.4, watchOS 7.5. Processing a maliciously crafted audio file may disclose restricted memory.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30686](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30686) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30686.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30686.svg)


## CVE-2021-30684
 A logic issue was addressed with improved state management. This issue is fixed in macOS Big Sur 11.4, Security Update 2021-003 Catalina. A remote attacker may cause an unexpected application termination or arbitrary code execution.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30684](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30684) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30684.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30684.svg)


## CVE-2021-30682
 A logic issue was addressed with improved restrictions. This issue is fixed in tvOS 14.6, iOS 14.6 and iPadOS 14.6, Safari 14.1.1, macOS Big Sur 11.4, watchOS 7.5. A malicious application may be able to leak sensitive user information.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30682](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30682) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30682.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30682.svg)


## CVE-2021-30671
 A validation issue was addressed with improved logic. This issue is fixed in macOS Big Sur 11.4, Security Update 2021-003 Catalina. A malicious application may be able to send unauthorized Apple events to Finder.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30671](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30671) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30671.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30671.svg)


## CVE-2021-30654
 This issue was addressed by removing additional entitlements. This issue is fixed in GarageBand 10.4.3. A local attacker may be able to read sensitive information.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30654](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30654) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30654.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30654.svg)


## CVE-2021-30653
 This issue was addressed with improved checks. This issue is fixed in macOS Big Sur 11.3, iOS 14.5 and iPadOS 14.5, watchOS 7.4, tvOS 14.5. Processing a maliciously crafted image may lead to arbitrary code execution.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30653](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30653) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30653.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30653.svg)


## CVE-2021-30543
 Use after free in Tab Strip in Google Chrome prior to 91.0.4472.77 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30543](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30543) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30543.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30543.svg)


## CVE-2021-30542
 Use after free in Tab Strip in Google Chrome prior to 91.0.4472.77 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30542](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30542) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30542.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30542.svg)


## CVE-2021-30468
 A vulnerability in the JsonMapObjectReaderWriter of Apache CXF allows an attacker to submit malformed JSON to a web service, which results in the thread getting stuck in an infinite loop, consuming CPU indefinitely. This issue affects Apache CXF versions prior to 3.4.4; Apache CXF versions prior to 3.3.11.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30468](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30468) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30468.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30468.svg)


## CVE-2021-30261
 Possible integer and heap overflow due to lack of input command size validation while handling beacon template update command from HLOS in Snapdragon Auto, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon IoT, Snapdragon Mobile, Snapdragon Voice &amp; Music, Snapdragon Wearables

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30261](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30261) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30261.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30261.svg)


## CVE-2021-30137
 Assyst 10 SP7.5 has authenticated XXE leading to SSRF via XML unmarshalling. The application allows users to send JSON or XML data to the server. It was possible to inject malicious XML data through several access points.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30137](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30137) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30137.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30137.svg)


## CVE-2021-30123
 FFmpeg &lt;=4.3 contains a buffer overflow vulnerability in libavcodec through a crafted file that may lead to remote code execution.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30123](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30123) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30123.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30123.svg)


## CVE-2021-30086
 Cross Site Scripting (XSS) vulnerability exists in KindEditor (Chinese versions) 4.1.12, which can be exploited by an attacker to obtain user cookie information.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30086](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-30086) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-30086.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-30086.svg)


## CVE-2021-29965
 A malicious website that causes an HTTP Authentication dialog to be spawned could trick the built-in password manager to suggest passwords for the currently active website instead of the website that triggered the dialog. *This bug only affects Firefox for Android. Other operating systems are unaffected.*. This vulnerability affects Firefox &lt; 89.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29965](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29965) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29965.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29965.svg)


## CVE-2021-29964
 A locally-installed hostile program could send `WM_COPYDATA` messages that Firefox would process incorrectly, leading to an out-of-bounds read. *This bug only affects Firefox on Windows. Other operating systems are unaffected.*. This vulnerability affects Thunderbird &lt; 78.11, Firefox &lt; 89, and Firefox ESR &lt; 78.11.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29964](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29964) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29964.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29964.svg)


## CVE-2021-29961
 When styling and rendering an oversized `&lt;select&gt;` element, Firefox did not apply correct clipping which allowed an attacker to paint over the user interface. This vulnerability affects Firefox &lt; 89.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29961](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29961) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29961.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29961.svg)


## CVE-2021-29956
 OpenPGP secret keys that were imported using Thunderbird version 78.8.1 up to version 78.10.1 were stored unencrypted on the user's local disk. The master password protection was inactive for those keys. Version 78.10.2 will restore the protection mechanism for newly imported keys, and will automatically protect keys that had been imported using affected Thunderbird versions. This vulnerability affects Thunderbird &lt; 78.10.2.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29956](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29956) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29956.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29956.svg)


## CVE-2021-29954
 Proxy functionality built into Hubs Cloud&#8217;s Reticulum software allowed access to internal URLs, including the metadata service. This vulnerability affects Hubs Cloud &lt; mozillareality/reticulum/1.0.1/20210428201255.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29954](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29954) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29954.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29954.svg)


## CVE-2021-29951
 The Mozilla Maintenance Service granted SERVICE_START access to BUILTIN|Users which, in a domain network, grants normal remote users access to start or stop the service. This could be used to prevent the browser update service from operating (if an attacker spammed the 'Stop' command); but also exposed attack surface in the maintenance service. *Note: This issue only affected Windows operating systems older than Win 10 build 1709. Other operating systems are unaffected.*. This vulnerability affects Thunderbird &lt; 78.10.1, Firefox &lt; 87, and Firefox ESR &lt; 78.10.1.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29951](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29951) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29951.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29951.svg)


## CVE-2021-29949
 When loading the shared library that provides the OTR protocol implementation, Thunderbird will initially attempt to open it using a filename that isn't distributed by Thunderbird. If a computer has already been infected with a malicious library of the alternative filename, and the malicious library has been copied to a directory that is contained in the search path for executable libraries, then Thunderbird will load the incorrect library. This vulnerability affects Thunderbird &lt; 78.9.1.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29949](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29949) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29949.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29949.svg)


## CVE-2021-29948
 Signatures are written to disk before and read during verification, which might be subject to a race condition when a malicious local process or user is replacing the file. This vulnerability affects Thunderbird &lt; 78.10.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29948](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29948) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29948.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29948.svg)


## CVE-2021-29945
 The WebAssembly JIT could miscalculate the size of a return type, which could lead to a null read and result in a crash. *Note: This issue only affected x86-32 platforms. Other platforms are unaffected.*. This vulnerability affects Firefox ESR &lt; 78.10, Thunderbird &lt; 78.10, and Firefox &lt; 88.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29945](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29945) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29945.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29945.svg)


## CVE-2021-29905
 IBM Jazz for Service Management 1.1.3.10 and IBM Tivoli Netcool/OMNIbus_GUI is vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 207616.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29905](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29905) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29905.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29905.svg)


## CVE-2021-29904
 IBM Jazz for Service Management 1.1.3.10 and IBM Tivoli Netcool/OMNIbus_GUI displays user credentials in plain clear text which can be read by a local user. IBM X-Force ID: 207610.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29904](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29904) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29904.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29904.svg)


## CVE-2021-29894
 IBM Cloud Pak for Security (CP4S) 1.7.0.0, 1.7.1.0, 1.7.2.0, and 1.8.0.0 uses weaker than expected cryptographic algorithms that could allow an attacker to decrypt highly sensitive information. IBM X-Force ID: 207320.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29894](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29894) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29894.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29894.svg)


## CVE-2021-29856
 IBM Tivoli Netcool/OMNIbus_GUI 8.1.0 could allow an authenticated usre to cause a denial of service through the WebGUI Map Creation page. IBM X-Force ID: 205685.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29856](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29856) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29856.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29856.svg)


## CVE-2021-29842
 IBM WebSphere Application Server 7.0, 8.0, 8.5, 9.0 and Liberty 17.0.0.3 through 21.0.0.9 could allow a remote user to enumerate usernames due to a difference of responses from valid and invalid login attempts. IBM X-Force ID: 205202.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29842](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29842) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29842.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29842.svg)


## CVE-2021-29834
 IBM Business Automation Workflow 18.0.0.0, 18.0.0.1, 18.0.0.2, 19.0.0.1, 19.0.0.2, 19.0.0.3,20.0.0.1, 20.0.0.2, and 21.0.2 and IBM Business Process Manager 8.5 and 8.6 are vulnerable to stored cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 204832.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29834](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29834) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29834.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29834.svg)


## CVE-2021-29833
 IBM Jazz for Service Management 1.1.3.10 and IBM Tivoli Netcool/OMNIbus_GUI is vulnerable to stored cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 204825.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29833](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29833) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29833.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29833.svg)


## CVE-2021-29832
 IBM Jazz for Service Management 1.1.3.10 and IBM Tivoli Netcool/OMNIbus_GUI is vulnerable to stored cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 204824.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29832](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29832) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29832.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29832.svg)


## CVE-2021-29831
 IBM Jazz for Service Management 1.1.3.10 and IBM Tivoli Netcool/OMNIbus_GUI is vulnerable to an XML External Entity Injection (XXE) attack when processing XML data. A remote attacker could exploit this vulnerability to expose sensitive information or consume memory resources. IBM X-Force ID: 204775.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29831](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29831) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29831.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29831.svg)


## CVE-2021-29825
 IBM Db2 for Linux, UNIX and Windows (includes Db2 Connect Server) could disclose sensitive information when using ADMIN_CMD with LOAD or BACKUP. IBM X-Force ID: 204470.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29825](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29825) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29825.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29825.svg)


## CVE-2021-29821
 IBM Jazz for Service Management and IBM Tivoli Netcool/OMNIbus_GUI 8.1.0 is vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 204348.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29821](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29821) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29821.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29821.svg)


## CVE-2021-29820
 IBM Jazz for Service Management and IBM Tivoli Netcool/OMNIbus_GUI 8.1.0 is vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 204347.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29820](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29820) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29820.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29820.svg)


## CVE-2021-29819
 IBM Jazz for Service Management and IBM Tivoli Netcool/OMNIbus_GUI 8.1.0 is vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 204346.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29819](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29819) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29819.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29819.svg)


## CVE-2021-29818
 IBM Jazz for Service Management and IBM Tivoli Netcool/OMNIbus_GUI 8.1.0 is vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 204345.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29818](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29818) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29818.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29818.svg)


## CVE-2021-29817
 IBM Jazz for Service Management and IBM Tivoli Netcool/OMNIbus_GUI 8.1.0 is vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 204343.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29817](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29817) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29817.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29817.svg)


## CVE-2021-29816
 IBM Jazz for Service Management 1.1.3.10 and IBM Tivoli Netcool/OMNIbus_GUI is vulnerable to cross-site request forgery which could allow an attacker to execute malicious and unauthorized actions transmitted from a user that the website trusts. IBM X-Force ID: 204341.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29816](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29816) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29816.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29816.svg)


## CVE-2021-29815
 IBM Jazz for Service Management 1.1.3.10 and IBM Tivoli Netcool/OMNIbus_GUI is vulnerable to stored cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 204340.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29815](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29815) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29815.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29815.svg)


## CVE-2021-29814
 IBM Jazz for Service Management 1.1.3.10 and IBM Tivoli Netcool/OMNIbus_GUI is vulnerable to stored cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 204334.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29814](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29814) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29814.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29814.svg)


## CVE-2021-29813
 IBM Jazz for Service Management 1.1.3.10 and IBM Tivoli Netcool/OMNIbus_GUI is vulnerable to stored cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 204331.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29813](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29813) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29813.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29813.svg)


## CVE-2021-29812
 IBM Jazz for Service Management 1.1.3.10 and IBM Tivoli Netcool/OMNIbus_GUI is vulnerable to stored cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 204330.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29812](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29812) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29812.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29812.svg)


## CVE-2021-29811
 IBM Jazz for Service Management and IBM Tivoli Netcool/OMNIbus_GUI 8.1.0 stores user credentials in plain clear text which can be read by an authenticated admin user. IBM X-Force ID: 204329.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29811](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29811) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29811.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29811.svg)


## CVE-2021-29810
 IBM Jazz for Service Management 1.1.3.10 and IBM Tivoli Netcool/OMNIbus_GUI is vulnerable to stored cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 204279.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29810](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29810) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29810.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29810.svg)


## CVE-2021-29809
 IBM Jazz for Service Management and IBM Tivoli Netcool/OMNIbus_GUI 8.1.0 is vulnerable to stored cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 204270.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29809](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29809) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29809.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29809.svg)


## CVE-2021-29808
 IBM Jazz for Service Management and IBM Tivoli Netcool/OMNIbus_GUI 8.1.0 is vulnerable to stored cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 204269.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29808](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29808) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29808.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29808.svg)


## CVE-2021-29807
 IBM Jazz for Service Management and IBM Tivoli Netcool/OMNIbus_GUI 8.1.0 is vulnerable to stored cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 204265.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29807](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29807) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29807.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29807.svg)


## CVE-2021-29806
 IBM Jazz for Service Management and IBM Tivoli Netcool/OMNIbus_GUI 8.1.0 is vulnerable to stored cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 204264.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29806](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29806) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29806.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29806.svg)


## CVE-2021-29800
 IBM Tivoli Netcool/OMNIbus_GUI and IBM Jazz for Service Management 1.1.3.10 is vulnerable to stored cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29800](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29800) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29800.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29800.svg)


## CVE-2021-29795
 IBM PowerVM Hypervisor FW860, FW930, FW940, and FW950 could allow a local user to create a specially crafted sequence of hypervisor calls from a partition that could crash the system. IBM X-Force ID: 203557.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29795](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29795) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29795.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29795.svg)


## CVE-2021-29773
 IBM Security Guardium 10.6 and 11.3 could allow a remote authenticated attacker to obtain sensitive information or modify user details caused by an insecure direct object vulnerability (IDOR). IBM X-Force ID: 202865.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29773](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29773) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29773.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29773.svg)


## CVE-2021-29763
 IBM Db2 for Linux, UNIX and Windows (includes Db2 Connect Server) 11.1 and 11.5 under very specific conditions, could allow a local user to keep running a procedure that could cause the system to run out of memory.and cause a denial of service. IBM X-Force ID: 202267.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29763](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29763) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29763.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29763.svg)


## CVE-2021-29752
 IBM Db2 11.2 and 11.5 contains an information disclosure vulnerability, exposing remote storage credentials to privileged users under specific conditions. IBM X-Fporce ID: 201780.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29752](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29752) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29752.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29752.svg)


## CVE-2021-29750
 IBM QRadar SIEM 7.3 and 7.4 uses weaker than expected cryptographic algorithms that could allow an attacker to decrypt highly sensitive information. IBM X-Force ID: 201778.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29750](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29750) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29750.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29750.svg)


## CVE-2021-29742
 IBM Security Verify Access Docker 10.0.0 could allow a user to impersonate another user on the system. IBM X-Force ID: 201483.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29742](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29742) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29742.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29742.svg)


## CVE-2021-29699
 IBM Security Verify Access Docker 10.0.0 could allow a remote priviled user to upload arbitrary files with a dangerous file type that could be excuted by an user. IBM X-Force ID: 200600.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29699](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29699) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29699.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29699.svg)


## CVE-2021-29677
 IBM Security Verify (IBM Security Verify Privilege Vault 10.9.66) is vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29677](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29677) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29677.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29677.svg)


## CVE-2021-29676
 IBM Security Verify (IBM Security Verify Privilege Vault 10.9.66) is vulnerable to link injection. By persuading a victim to click on a specially-crafted URL link, a remote attacker could exploit this vulnerability to conduct various attacks against the vulnerable system, including cross-site scripting, cache poisoning or session hijacking

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29676](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29676) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29676.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29676.svg)


## CVE-2021-29484
 Ghost is a Node.js CMS. An unused endpoint added during the development of 4.0.0 has left sites vulnerable to untrusted users gaining access to Ghost Admin. Attackers can gain access by getting logged in users to click a link containing malicious code. Users do not need to enter credentials and may not know they've visited a malicious site. Ghost(Pro) has already been patched. We can find no evidence that the issue was exploited on Ghost(Pro) prior to the patch being added. Self-hosters are impacted if running Ghost a version between 4.0.0 and 4.3.2. Immediate action should be taken to secure your site. The issue has been fixed in 4.3.3, all 4.x sites should upgrade as soon as possible. As the endpoint is unused, the patch simply removes it. As a workaround blocking access to /ghost/preview can also mitigate the issue.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29484](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29484) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29484.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29484.svg)


## CVE-2021-29441
 Nacos is a platform designed for dynamic service discovery and configuration and service management. In Nacos before version 1.4.1, when configured to use authentication (-Dnacos.core.auth.enabled=true) Nacos uses the AuthFilter servlet filter to enforce authentication. This filter has a backdoor that enables Nacos servers to bypass this filter and therefore skip authentication checks. This mechanism relies on the user-agent HTTP header so it can be easily spoofed. This issue may allow any user to carry out any administrative tasks on the Nacos server.

- [https://github.com/hh-hunter/nacos-cve-2021-29441](https://github.com/hh-hunter/nacos-cve-2021-29441) :  ![starts](https://img.shields.io/github/stars/hh-hunter/nacos-cve-2021-29441.svg) ![forks](https://img.shields.io/github/forks/hh-hunter/nacos-cve-2021-29441.svg)


## CVE-2021-29425
 In Apache Commons IO before 2.7, When invoking the method FileNameUtils.normalize with an improper input string, like &quot;//../foo&quot;, or &quot;\\..\foo&quot;, the result would be the same value, thus possibly providing access to files in the parent directory, but not further above (thus &quot;limited&quot; path traversal), if the calling code would use the result to construct a path value.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29425](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-29425) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-29425.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-29425.svg)


## CVE-2021-28966
 In Ruby through 3.0 on Windows, a remote attacker can submit a crafted path when a Web application handles a parameter with TmpDir.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28966](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28966) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28966.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28966.svg)


## CVE-2021-28960
 ManageEngine Desktop Central before build 10.0.683 allows Unauthenticated Remote Code Execution during communication with Notification Server.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28960](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28960) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28960.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28960.svg)


## CVE-2021-28906
 In function read_yin_leaf() in libyang &lt;= v1.0.225, it doesn't check whether the value of retval-&gt;ext[r] is NULL. In some cases, it can be NULL, which leads to the operation of retval-&gt;ext[r]-&gt;flags that results in a crash.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28906](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28906) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28906.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28906.svg)


## CVE-2021-28905
 In function lys_node_free() in libyang &lt;= v1.0.225, it asserts that the value of node-&gt;module can't be NULL. But in some cases, node-&gt;module can be null, which triggers a reachable assertion (CWE-617).

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28905](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28905) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28905.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28905.svg)


## CVE-2021-28904
 In function ext_get_plugin() in libyang &lt;= v1.0.225, it doesn't check whether the value of revision is NULL. If revision is NULL, the operation of strcmp(revision, ext_plugins[u].revision) will lead to a crash.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28904](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28904) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28904.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28904.svg)


## CVE-2021-28903
 A stack overflow in libyang &lt;= v1.0.225 can cause a denial of service through function lyxml_parse_mem(). lyxml_parse_elem() function will be called recursively, which will consume stack space and lead to crash.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28903](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28903) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28903.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28903.svg)


## CVE-2021-28902
 In function read_yin_container() in libyang &lt;= v1.0.225, it doesn't check whether the value of retval-&gt;ext[r] is NULL. In some cases, it can be NULL, which leads to the operation of retval-&gt;ext[r]-&gt;flags that results in a crash.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28902](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28902) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28902.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28902.svg)


## CVE-2021-28901
 Multiple cross-site scripting (XSS) vulnerabilities exist in SITA Software Azur CMS 1.2.3.1 and earlier, which allows remote attackers to inject arbitrary web script or HTML via the (1) NOM_CLI , (2) ADRESSE , (3) ADRESSE2, (4) LOCALITE parameters to /eshop/products/json/aouCustomerAdresse; and the (5) nom_liste parameter to /eshop/products/json/addCustomerFavorite.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28901](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28901) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28901.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28901.svg)


## CVE-2021-28701
 Another race in XENMAPSPACE_grant_table handling Guests are permitted access to certain Xen-owned pages of memory. The majority of such pages remain allocated / associated with a guest for its entire lifetime. Grant table v2 status pages, however, are de-allocated when a guest switches (back) from v2 to v1. Freeing such pages requires that the hypervisor enforce that no parallel request can result in the addition of a mapping of such a page to a guest. That enforcement was missing, allowing guests to retain access to pages that were freed and perhaps re-used for other purposes. Unfortunately, when XSA-379 was being prepared, this similar issue was not noticed.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28701](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28701) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28701.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28701.svg)


## CVE-2021-28700
 xen/arm: No memory limit for dom0less domUs The dom0less feature allows an administrator to create multiple unprivileged domains directly from Xen. Unfortunately, the memory limit from them is not set. This allow a domain to allocate memory beyond what an administrator originally configured.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28700](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28700) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28700.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28700.svg)


## CVE-2021-28699
 inadequate grant-v2 status frames array bounds check The v2 grant table interface separates grant attributes from grant status. That is, when operating in this mode, a guest has two tables. As a result, guests also need to be able to retrieve the addresses that the new status tracking table can be accessed through. For 32-bit guests on x86, translation of requests has to occur because the interface structure layouts commonly differ between 32- and 64-bit. The translation of the request to obtain the frame numbers of the grant status table involves translating the resulting array of frame numbers. Since the space used to carry out the translation is limited, the translation layer tells the core function the capacity of the array within translation space. Unfortunately the core function then only enforces array bounds to be below 8 times the specified value, and would write past the available space if enough frame numbers needed storing.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28699](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28699) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28699.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28699.svg)


## CVE-2021-28698
 long running loops in grant table handling In order to properly monitor resource use, Xen maintains information on the grant mappings a domain may create to map grants offered by other domains. In the process of carrying out certain actions, Xen would iterate over all such entries, including ones which aren't in use anymore and some which may have been created but never used. If the number of entries for a given domain is large enough, this iterating of the entire table may tie up a CPU for too long, starving other domains or causing issues in the hypervisor itself. Note that a domain may map its own grants, i.e. there is no need for multiple domains to be involved here. A pair of &quot;cooperating&quot; guests may, however, cause the effects to be more severe.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28698](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28698) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28698.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28698.svg)


## CVE-2021-28697
 grant table v2 status pages may remain accessible after de-allocation Guest get permitted access to certain Xen-owned pages of memory. The majority of such pages remain allocated / associated with a guest for its entire lifetime. Grant table v2 status pages, however, get de-allocated when a guest switched (back) from v2 to v1. The freeing of such pages requires that the hypervisor know where in the guest these pages were mapped. The hypervisor tracks only one use within guest space, but racing requests from the guest to insert mappings of these pages may result in any of them to become mapped in multiple locations. Upon switching back from v2 to v1, the guest would then retain access to a page that was freed and perhaps re-used for other purposes.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28697](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28697) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28697.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28697.svg)


## CVE-2021-28696
 IOMMU page mapping issues on x86 T[his CNA information record relates to multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Both AMD and Intel allow ACPI tables to specify regions of memory which should be left untranslated, which typically means these addresses should pass the translation phase unaltered. While these are typically device specific ACPI properties, they can also be specified to apply to a range of devices, or even all devices. On all systems with such regions Xen failed to prevent guests from undoing/replacing such mappings (CVE-2021-28694). On AMD systems, where a discontinuous range is specified by firmware, the supposedly-excluded middle range will also be identity-mapped (CVE-2021-28695). Further, on AMD systems, upon de-assigment of a physical device from a guest, the identity mappings would be left in place, allowing a guest continued access to ranges of memory which it shouldn't have access to anymore (CVE-2021-28696).

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28696](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28696) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28696.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28696.svg)
- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28694](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28694) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28694.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28694.svg)
- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28695](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28695) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28695.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28695.svg)


## CVE-2021-28695
 IOMMU page mapping issues on x86 T[his CNA information record relates to multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Both AMD and Intel allow ACPI tables to specify regions of memory which should be left untranslated, which typically means these addresses should pass the translation phase unaltered. While these are typically device specific ACPI properties, they can also be specified to apply to a range of devices, or even all devices. On all systems with such regions Xen failed to prevent guests from undoing/replacing such mappings (CVE-2021-28694). On AMD systems, where a discontinuous range is specified by firmware, the supposedly-excluded middle range will also be identity-mapped (CVE-2021-28695). Further, on AMD systems, upon de-assigment of a physical device from a guest, the identity mappings would be left in place, allowing a guest continued access to ranges of memory which it shouldn't have access to anymore (CVE-2021-28696).

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28695](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28695) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28695.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28695.svg)
- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28696](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28696) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28696.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28696.svg)
- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28694](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28694) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28694.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28694.svg)


## CVE-2021-28694
 IOMMU page mapping issues on x86 T[his CNA information record relates to multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Both AMD and Intel allow ACPI tables to specify regions of memory which should be left untranslated, which typically means these addresses should pass the translation phase unaltered. While these are typically device specific ACPI properties, they can also be specified to apply to a range of devices, or even all devices. On all systems with such regions Xen failed to prevent guests from undoing/replacing such mappings (CVE-2021-28694). On AMD systems, where a discontinuous range is specified by firmware, the supposedly-excluded middle range will also be identity-mapped (CVE-2021-28695). Further, on AMD systems, upon de-assigment of a physical device from a guest, the identity mappings would be left in place, allowing a guest continued access to ranges of memory which it shouldn't have access to anymore (CVE-2021-28696).

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28694](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28694) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28694.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28694.svg)
- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28696](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28696) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28696.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28696.svg)
- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28695](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28695) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28695.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28695.svg)


## CVE-2021-28674
 The node management page in SolarWinds Orion Platform before 2020.2.5 HF1 allows an attacker to create or delete a node (outside of the attacker's perimeter) via an account with write permissions. This occurs because node IDs are predictable (with incrementing numbers) and the access control on Services/NodeManagement.asmx/DeleteObjNow is incorrect. To exploit this, an attacker must be authenticated and must have node management rights associated with at least one valid group on the platform.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28674](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28674) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28674.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28674.svg)


## CVE-2021-28565
 Acrobat Reader DC versions versions 2021.001.20150 (and earlier), 2020.001.30020 (and earlier) and 2017.011.30194 (and earlier) are affected by an Out-of-bounds Read vulnerability in the PDFLibTool component. An unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28565](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28565) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28565.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28565.svg)


## CVE-2021-28564
 Acrobat Reader DC versions versions 2021.001.20150 (and earlier), 2020.001.30020 (and earlier) and 2017.011.30194 (and earlier) are affected by an Out-of-bounds Write vulnerability within the ImageTool component. An unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28564](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28564) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28564.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28564.svg)


## CVE-2021-28561
 Acrobat Reader DC versions versions 2021.001.20150 (and earlier), 2020.001.30020 (and earlier) and 2017.011.30194 (and earlier) are affected by a memory corruption vulnerability. An unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28561](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28561) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28561.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28561.svg)


## CVE-2021-28560
 Acrobat Reader DC versions versions 2021.001.20150 (and earlier), 2020.001.30020 (and earlier) and 2017.011.30194 (and earlier) are affected by a Heap-based Buffer Overflow vulnerability. An unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28560](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28560) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28560.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28560.svg)


## CVE-2021-28559
 Acrobat Reader DC versions versions 2021.001.20150 (and earlier), 2020.001.30020 (and earlier) and 2017.011.30194 (and earlier) are affected by an Information Exposure vulnerability. An unauthenticated attacker could leverage this vulnerability to get access to restricted data stored within global variables and objects.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28559](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28559) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28559.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28559.svg)


## CVE-2021-28553
 Acrobat Reader DC versions versions 2021.001.20150 (and earlier), 2020.001.30020 (and earlier) and 2017.011.30194 (and earlier) are affected by an Use After Free vulnerability. An unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28553](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28553) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28553.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28553.svg)


## CVE-2021-28550
 Acrobat Reader DC versions versions 2021.001.20150 (and earlier), 2020.001.30020 (and earlier) and 2017.011.30194 (and earlier) are affected by a Use After Free vulnerability. An unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28550](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28550) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28550.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28550.svg)


## CVE-2021-28547
 Adobe Creative Cloud Desktop Application for macOS version 5.3 (and earlier) is affected by a privilege escalation vulnerability that could allow a normal user to delete the OOBE directory and get permissions of any directory under the administrator authority.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28547](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28547) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28547.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28547.svg)


## CVE-2021-28169
 For Eclipse Jetty versions &lt;= 9.4.40, &lt;= 10.0.2, &lt;= 11.0.2, it is possible for requests to the ConcatServlet with a doubly encoded path to access protected resources within the WEB-INF directory. For example a request to `/concat?/%2557EB-INF/web.xml` can retrieve the web.xml file. This can reveal sensitive information regarding the implementation of a web application.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28169](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28169) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28169.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28169.svg)


## CVE-2021-28165
 In Eclipse Jetty 7.2.2 to 9.4.38, 10.0.0.alpha0 to 10.0.1, and 11.0.0.alpha0 to 11.0.1, CPU usage can reach 100% upon receiving a large invalid TLS frame.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28165](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28165) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28165.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28165.svg)


## CVE-2021-28164
 In Eclipse Jetty 9.4.37.v20210219 to 9.4.38.v20210224, the default compliance mode allows requests with URIs that contain %2e or %2e%2e segments to access protected resources within the WEB-INF directory. For example a request to /context/%2e/WEB-INF/web.xml can retrieve the web.xml file. This can reveal sensitive information regarding the implementation of a web application.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34429](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-34429) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-34429.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-34429.svg)
- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28164](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28164) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28164.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28164.svg)


## CVE-2021-28163
 In Eclipse Jetty 9.4.32 to 9.4.38, 10.0.0.beta2 to 10.0.1, and 11.0.0.beta2 to 11.0.1, if a user uses a webapps directory that is a symlink, the contents of the webapps directory is deployed as a static webapp, inadvertently serving the webapps themselves and anything else that might be in that directory.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28163](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28163) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28163.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28163.svg)


## CVE-2021-28116
 Squid through 4.14 and 5.x through 5.0.5, in some configurations, allows information disclosure because of an out-of-bounds read in WCCP protocol data. This can be leveraged as part of a chain for remote code execution as nobody.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28116](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-28116) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-28116.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-28116.svg)


## CVE-2021-27913
 The function mt_rand is used to generate session tokens, this function is cryptographically flawed due to its nature being one pseudorandomness, an attacker can take advantage of the cryptographically insecure nature of this function to enumerate session tokens for accounts that are not under his/her control This issue affects: Mautic Mautic versions prior to 3.3.4; versions prior to 4.0.0.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-27913](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-27913) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-27913.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-27913.svg)


## CVE-2021-27912
 Mautic versions before 3.3.4/4.0.0 are vulnerable to an inline JS XSS attack when viewing Mautic assets by utilizing inline JS in the title and adding a broken image URL as a remote asset. This can only be leveraged by an authenticated user with permission to create or edit assets.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-27912](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-27912) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-27912.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-27912.svg)


## CVE-2021-27662
 The KT-1 door controller is susceptible to replay or man-in-the-middle attacks where an attacker can record and replay TCP packets. This issue affects Johnson Controls KT-1 all versions up to and including 3.01

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-27662](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-27662) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-27662.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-27662.svg)


## CVE-2021-27651
 In versions 8.2.1 through 8.5.2 of Pega Infinity, the password reset functionality for local accounts can be used to bypass local authentication checks.

- [https://github.com/oxctdev/CVE-2021-27651](https://github.com/oxctdev/CVE-2021-27651) :  ![starts](https://img.shields.io/github/stars/oxctdev/CVE-2021-27651.svg) ![forks](https://img.shields.io/github/forks/oxctdev/CVE-2021-27651.svg)


## CVE-2021-27578
 Cross Site Scripting vulnerability in markdown interpreter of Apache Zeppelin allows an attacker to inject malicious scripts. This issue affects Apache Zeppelin Apache Zeppelin versions prior to 0.9.0.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-27578](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-27578) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-27578.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-27578.svg)


## CVE-2021-27556
 The Cron job tab in EasyCorp ZenTao 12.5.3 allows remote attackers (who have admin access) to execute arbitrary code by setting the type parameter to System.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-27556](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-27556) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-27556.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-27556.svg)


## CVE-2021-27391
 A vulnerability has been identified in APOGEE MBC (PPC) (P2 Ethernet) (All versions &gt;= V2.6.3), APOGEE MEC (PPC) (P2 Ethernet) (All versions &gt;= V2.6.3), APOGEE PXC Compact (BACnet) (All versions &lt; V3.5.3), APOGEE PXC Compact (P2 Ethernet) (All versions &gt;= V2.8), APOGEE PXC Modular (BACnet) (All versions &lt; V3.5.3), APOGEE PXC Modular (P2 Ethernet) (All versions &gt;= V2.8), TALON TC Compact (BACnet) (All versions &lt; V3.5.3), TALON TC Modular (BACnet) (All versions &lt; V3.5.3). The web server of affected devices lacks proper bounds checking when parsing the Host parameter in HTTP requests, which could lead to a buffer overflow. An unauthenticated remote attacker could exploit this vulnerability to execute arbitrary code on the device with root privileges.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-27391](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-27391) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-27391.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-27391.svg)


## CVE-2021-27341
 OpenSIS Community Edition version &lt;= 7.6 is affected by a local file inclusion vulnerability in DownloadWindow.php via the &quot;filename&quot; parameter.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-27341](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-27341) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-27341.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-27341.svg)


## CVE-2021-27340
 OpenSIS Community Edition version &lt;= 7.6 is affected by a reflected XSS vulnerability in EmailCheck.php via the &quot;opt&quot; parameter.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-27340](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-27340) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-27340.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-27340.svg)


## CVE-2021-27046
 A Memory Corruption vulnerability for PDF files in Autodesk Navisworks 2019, 2020, 2021, 2022 may lead to code execution through maliciously crafted DLL files.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-27046](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-27046) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-27046.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-27046.svg)


## CVE-2021-27045
 A maliciously crafted PDF file in Autodesk Navisworks 2019, 2020, 2021, 2022 can be forced to read beyond allocated boundaries when parsing the PDF file. This vulnerability can be exploited to execute arbitrary code.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-27045](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-27045) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-27045.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-27045.svg)


## CVE-2021-27044
 A Out-Of-Bounds Read/Write Vulnerability in Autodesk FBX Review version 1.4.0 may lead to remote code execution through maliciously crafted DLL files or information disclosure.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-27044](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-27044) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-27044.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-27044.svg)


## CVE-2021-26920
 In the Druid ingestion system, the InputSource is used for reading data from a certain data source. However, the HTTP InputSource allows authenticated users to read data from other sources than intended, such as the local file system, with the privileges of the Druid server process. This is not an elevation of privilege when users access Druid directly, since Druid also provides the Local InputSource, which allows the same level of access. But it is problematic when users interact with Druid indirectly through an application that allows users to specify the HTTP InputSource, but not the Local InputSource. In this case, users could bypass the application-level restriction by passing a file URL to the HTTP InputSource.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36749](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-36749) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-36749.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-36749.svg)


## CVE-2021-26794
 Privilege escalation in 'upload.php' in FrogCMS SentCMS v0.9.5 allows attacker to execute arbitrary code via crafted php file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-26794](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-26794) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-26794.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-26794.svg)


## CVE-2021-26750
 DLL hijacking in Panda Agent &lt;=1.16.11 in Panda Security, S.L.U. Panda Adaptive Defense 360 &lt;= 8.0.17 allows attacker to escalate privileges via maliciously crafted DLL file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-26750](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-26750) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-26750.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-26750.svg)


## CVE-2021-26085
 Affected versions of Atlassian Confluence Server allow remote attackers to view restricted resources via a Pre-Authorization Arbitrary File Read vulnerability in the /s/ endpoint. The affected versions are before version 7.4.10, and from version 7.5.0 before 7.12.3.

- [https://github.com/ColdFusionX/CVE-2021-26085](https://github.com/ColdFusionX/CVE-2021-26085) :  ![starts](https://img.shields.io/github/stars/ColdFusionX/CVE-2021-26085.svg) ![forks](https://img.shields.io/github/forks/ColdFusionX/CVE-2021-26085.svg)


## CVE-2021-26084
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0 before 7.12.5.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-26084](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-26084.svg)


## CVE-2021-25741
 A security issue was discovered in Kubernetes where a user may be able to create a container with subpath volume mounts to access files &amp; directories outside of the volume, including on the host filesystem.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-25741](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-25741) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-25741.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-25741.svg)


## CVE-2021-25740
 A security issue was discovered with Kubernetes that could enable users to send network traffic to locations they would otherwise not have access to via a confused deputy attack.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-25740](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-25740) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-25740.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-25740.svg)


## CVE-2021-25737
 A security issue was discovered in Kubernetes where a user may be able to redirect pod traffic to private networks on a Node. Kubernetes already prevents creation of Endpoint IPs in the localhost or link-local range, but the same validation was not performed on EndpointSlice IPs.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-25737](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-25737) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-25737.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-25737.svg)


## CVE-2021-24741
 The Support Board WordPress plugin before 3.3.4 does not escape multiple POST parameters (such as status_code, department, user_id, conversation_id, conversation_status_code, and recipient_id) before using them in SQL statements, leading to SQL injections which are exploitable by unauthenticated users.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24741](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24741) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24741.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24741.svg)


## CVE-2021-24670
 The CoolClock WordPress plugin before 4.3.5 does not escape some shortcode attributes, allowing users with a role as low as Contributor toperform Stored Cross-Site Scripting attacks

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24670](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24670) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24670.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24670.svg)


## CVE-2021-24667
 A stored cross-site scripting vulnerability has been discovered in : Simply Gallery Blocks with Lightbox (Version &#8211; 2.2.0 &amp; below). The vulnerability exists in the Lightbox functionality where a user with low privileges is allowed to execute arbitrary script code within the context of the application. This vulnerability is due to insufficient validation of image parameters in meta data.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24667](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24667) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24667.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24667.svg)


## CVE-2021-24663
 The Simple Schools Staff Directory WordPress plugin through 1.1 does not validate uploaded logo pictures to ensure that are indeed images, allowing high privilege users such as admin to upload arbitrary file like PHP, leading to RCE

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24663](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24663) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24663.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24663.svg)


## CVE-2021-24661
 The PostX &#8211; Gutenberg Blocks for Post Grid WordPress plugin before 2.4.10, with Saved Templates Addon enabled, allows users with Contributor roles or higher to read password-protected or private post contents the user is otherwise unable to read, given the post ID.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24661](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24661) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24661.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24661.svg)


## CVE-2021-24660
 The PostX &#8211; Gutenberg Blocks for Post Grid WordPress plugin before 2.4.10, with Saved Templates Addon enabled, allows users with a role as low as Contributor to perform Stored Cross-Site Scripting attacks via the plugin's shortcode.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24660](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24660) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24660.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24660.svg)


## CVE-2021-24659
 The PostX &#8211; Gutenberg Blocks for Post Grid WordPress plugin before 2.4.10 allows users with a role as low as Contributor to perform Stored Cross-Site Scripting attacks via the plugin's block.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24659](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24659) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24659.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24659.svg)


## CVE-2021-24657
 The Limit Login Attempts WordPress plugin before 4.0.50 does not escape the IP addresses (which can be controlled by attacker via headers such as X-Forwarded-For) of attempted logins before outputting them in the reports table, leading to an Unauthenticated Stored Cross-Site Scripting issue.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24657](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24657) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24657.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24657.svg)


## CVE-2021-24652
 The PostX &#8211; Gutenberg Blocks for Post Grid WordPress plugin before 2.4.10 performs incorrect checks before allowing any logged in user to perform some ajax based requests, allowing any user to modify, delete or add ultp_options values.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24652](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24652) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24652.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24652.svg)


## CVE-2021-24643
 The WP Map Block WordPress plugin before 1.2.3 does not escape some attributes of the WP Map Block, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attacks

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24643](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24643) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24643.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24643.svg)


## CVE-2021-24640
 The WordPress Slider Block Gutenslider plugin before 5.2.0 does not escape the minWidth attribute of a Gutenburg block, which could allow users with a role as low as contributor to perform Cross-Site Scripting attacks

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24640](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24640) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24640.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24640.svg)


## CVE-2021-24639
 The OMGF WordPress plugin before 4.5.4 does not enforce path validation, authorisation and CSRF checks in the omgf_ajax_empty_dir AJAX action, which allows any authenticated users to delete arbitrary files or folders on the server.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24639](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24639) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24639.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24639.svg)


## CVE-2021-24638
 The OMGF WordPress plugin before 4.5.4 does not escape or validate the handle parameter of the REST API, which allows unauthenticated users to perform path traversal and overwrite arbitrary CSS file with Google Fonts CSS, or download fonts uploaded on Google Fonts website.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24638](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24638) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24638.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24638.svg)


## CVE-2021-24637
 The Google Fonts Typography WordPress plugin before 3.0.3 does not escape and sanitise some of its block settings, allowing users with as role as low as Contributor to perform Stored Cross-Site Scripting attacks via blockType (combined with content), align, color, variant and fontID argument of a Gutenberg block.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24637](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24637) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24637.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24637.svg)


## CVE-2021-24636
 The Print My Blog WordPress Plugin before 3.4.2 does not enforce nonce (CSRF) checks, which allows attackers to make logged in administrators deactivate the Print My Blog plugin and delete all saved data for that plugin by tricking them to open a malicious link

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24636](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24636) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24636.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24636.svg)


## CVE-2021-24635
 The Visual Link Preview WordPress plugin before 2.2.3 does not enforce authorisation on several AJAX actions and has the CSRF nonce displayed for all authenticated users, allowing any authenticated user (such as subscriber) to call them and 1) Get and search through title and content of Draft post, 2) Get title of a password-protected post as well as 3) Upload an image from an URL

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24635](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24635) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24635.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24635.svg)


## CVE-2021-24634
 The Recipe Card Blocks by WPZOOM WordPress plugin before 2.8.3 does not properly sanitise or escape some of the properties of the Recipe Card Block (such as ingredientsLayout, iconSet, steps, ingredients, recipeTitle, or settings), which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attacks.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24634](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24634) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24634.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24634.svg)


## CVE-2021-24633
 The Countdown Block WordPress plugin before 1.1.2 does not have authorisation in the eb_write_block_css AJAX action, which allows any authenticated user, such as Subscriber, to modify post contents displayed to users.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24633](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24633) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24633.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24633.svg)


## CVE-2021-24632
 The Recipe Card Blocks by WPZOOM WordPress plugin before 2.8.1 does not escape the message parameter before outputting it back in the admin dashboard, leading to a Reflected Cross-Site Scripting issue

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24632](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24632) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24632.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24632.svg)


## CVE-2021-24620
 The WordPress Simple Ecommerce Shopping Cart Plugin- Sell products through Paypal plugin through 2.2.5 does not check for the uploaded Downloadable Digital product file, allowing any file, such as PHP to be uploaded by an administrator. Furthermore, as there is no CSRF in place, attackers could also make a logged admin upload a malicious PHP file, which would lead to RCE

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24620](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24620) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24620.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24620.svg)


## CVE-2021-24618
 The Donate With QRCode WordPress plugin before 1.4.5 does not sanitise or escape its QRCode Image setting, which result into a Stored Cross-Site Scripting (XSS). Furthermore, the plugin also does not have any CSRF and capability checks in place when saving such setting, allowing any authenticated user (as low as subscriber), or unauthenticated user via a CSRF vector to update them and perform such attack.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24618](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24618) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24618.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24618.svg)


## CVE-2021-24613
 The Post Views Counter WordPress plugin before 1.3.5 does not sanitise or escape its Post Views Label settings, which could allow high privilege users to perform Cross-Site Scripting attacks in the frontend even when the unfiltered_html capability is disallowed

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24613](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24613) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24613.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24613.svg)


## CVE-2021-24610
 The TranslatePress WordPress plugin before 2.0.9 does not implement a proper sanitisation on the translated strings. The 'trp_sanitize_string' function only removes script tag with a regex, still allowing other HTML tags and attributes to execute javascript, which could lead to authenticated Stored Cross-Site Scripting issues.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24610](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24610) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24610.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24610.svg)


## CVE-2021-24609
 The WP Mapa Politico Espana WordPress plugin before 3.7.0 does not sanitise or escape some of its settings before outputting them in attributes, allowing high privilege users to perform Cross-Site Scripting attacks even when the unfiltered_html is disallowed

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24609](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24609) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24609.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24609.svg)


## CVE-2021-24606
 The Availability Calendar WordPress plugin before 1.2.1 does not escape the category attribute from its shortcode before using it in a SQL statement, leading to a SQL Injection issue, which can be exploited by any user able to add shortcode to posts/pages, such as contributor+

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24606](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24606) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24606.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24606.svg)


## CVE-2021-24604
 The Availability Calendar WordPress plugin before 1.2.2 does not sanitise or escape its Category Names before outputting them in page/post where the associated shortcode is embed, allowing high privilege users to perform Cross-Site Scripting attacks even when the unfiltered_html is disallowed

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24604](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24604) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24604.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24604.svg)


## CVE-2021-24600
 The WP Dialog WordPress plugin through 1.2.5.5 does not sanitise and escape some of its settings before outputting them in pages, allowing high privilege users to perform Cross-Site Scripting attacks even when the unfiltered_html capability is disallowed.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24600](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24600) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24600.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24600.svg)


## CVE-2021-24597
 The You Shang WordPress plugin through 1.0.1 does not escape its qrcode links settings, which result into Stored Cross-Site Scripting issues in frontend posts and the plugins settings page depending on the payload used

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24597](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24597) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24597.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24597.svg)


## CVE-2021-24596
 The youForms for WordPress plugin through 1.0.5 does not sanitise escape the Button Text field of its Templates, allowing high privilege users (editors and admins) to perform Cross-Site Scripting attacks even when the unfiltered_html capability is disallowed

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24596](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24596) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24596.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24596.svg)


## CVE-2021-24587
 The Splash Header WordPress plugin before 1.20.8 doesn't sanitise and escape some of its settings while outputting them in the admin dashboard, leading to an authenticated Stored Cross-Site Scripting issue.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24587](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24587) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24587.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24587.svg)


## CVE-2021-24585
 The Timetable and Event Schedule WordPress plugin before 2.4.0 outputs the Hashed Password, Username and Email Address (along other less sensitive data) of the user related to the Even Head of the Timeslot in the response when requesting the event Timeslot data with a user with the edit_posts capability. Combined with the other Unauthorised Event Timeslot Modification issue (https://wpscan.com/reports/submissions/4699/) where an arbitrary user ID can be set, this could allow low privilege users with the edit_posts capability (such as author) to retrieve sensitive User data by iterating over the user_id

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24585](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24585) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24585.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24585.svg)


## CVE-2021-24584
 The Timetable and Event Schedule WordPress plugin before 2.4.2 does not have proper access control when updating a timeslot, allowing any user with the edit_posts capability (contributor+) to update arbitrary timeslot from any events. Furthermore, no CSRF check is in place as well, allowing such attack to be perform via CSRF against a logged in with such capability. In versions before 2.3.19, the lack of sanitisation and escaping in some of the fields, like the descritption could also lead to Stored XSS issues

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24584](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24584) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24584.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24584.svg)


## CVE-2021-24583
 The Timetable and Event Schedule WordPress plugin before 2.4.2 does not have proper access control when deleting a timeslot, allowing any user with the edit_posts capability (contributor+) to delete arbitrary timeslot from any events. Furthermore, no CSRF check is in place as well, allowing such attack to be performed via CSRF against a logged in with such capability

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24583](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24583) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24583.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24583.svg)


## CVE-2021-24582
 The ThinkTwit WordPress plugin before 1.7.1 did not sanitise or escape its &quot;Consumer key&quot; setting before outputting it its settings page, leading to a Stored Cross-Site Scripting issue.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24582](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24582) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24582.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24582.svg)


## CVE-2021-24569
 The Cookie Notice &amp; Compliance for GDPR / CCPA WordPress plugin before 2.1.2 does not escape the value of its Button Text setting when outputting it in an attribute in the frontend, allowing high privilege users such as admin to perform Cross-Site Scripting even when the unfiltered_html capability is disallowed.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24569](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24569) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24569.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24569.svg)


## CVE-2021-24563
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/V35HR4J/CVE-2021-24563](https://github.com/V35HR4J/CVE-2021-24563) :  ![starts](https://img.shields.io/github/stars/V35HR4J/CVE-2021-24563.svg) ![forks](https://img.shields.io/github/forks/V35HR4J/CVE-2021-24563.svg)


## CVE-2021-24545
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/V35HR4J/CVE-2021-24545](https://github.com/V35HR4J/CVE-2021-24545) :  ![starts](https://img.shields.io/github/stars/V35HR4J/CVE-2021-24545.svg) ![forks](https://img.shields.io/github/forks/V35HR4J/CVE-2021-24545.svg)


## CVE-2021-24530
 The Alojapro Widget WordPress plugin through 1.1.15 doesn't properly sanitise its Custom CSS settings, allowing high privilege users to perform Cross-Site Scripting attacks even when the unfiltered_html capability is disallowed

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24530](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24530) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24530.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24530.svg)


## CVE-2021-24525
 The Shortcodes Ultimate WordPress plugin before 5.10.2 allows users with Contributor roles to perform stored XSS via shortcode attributes. Note: the plugin is inconsistent in its handling of shortcode attributes; some do escape, most don't, and there are even some attributes that are insecure by design (like [su_button]'s onclick attribute).

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24525](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24525) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24525.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24525.svg)


## CVE-2021-24511
 The fetch_product_ajax functionality in the Product Feed on WooCommerce WordPress plugin before 3.3.1.0 uses a `product_id` POST parameter which is not properly sanitised, escaped or validated before inserting to a SQL statement, leading to SQL injection.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24511](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24511) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24511.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24511.svg)


## CVE-2021-24499
 The Workreap WordPress theme before 2.2.2 AJAX actions workreap_award_temp_file_uploader and workreap_temp_file_uploader did not perform nonce checks, or validate that the request is from a valid user in any other way. The endpoints allowed for uploading arbitrary files to the uploads/workreap-temp directory. Uploaded files were neither sanitized nor validated, allowing an unauthenticated visitor to upload executable code such as php scripts.

- [https://github.com/hh-hunter/cve-2021-24499](https://github.com/hh-hunter/cve-2021-24499) :  ![starts](https://img.shields.io/github/stars/hh-hunter/cve-2021-24499.svg) ![forks](https://img.shields.io/github/forks/hh-hunter/cve-2021-24499.svg)


## CVE-2021-24404
 The options.php file of the WP-Board WordPress plugin through 1.1 beta accepts a postid parameter which is not sanitised, escaped or validated before inserting to a SQL statement, leading to SQL injection. This is a time based SQLI and in the same function vulnerable parameter is passed twice so if we pass time as 5 seconds it takes 10 seconds to return since the query ran twice.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24404](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24404) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24404.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24404.svg)


## CVE-2021-24403
 The Orders functionality in the WordPress Page Contact plugin through 1.0 has an order_id parameter which is not sanitised, escaped or validated before inserting to a SQL statement, leading to SQL injection. The feature is available to low privilege users such as contributors

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24403](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24403) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24403.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24403.svg)


## CVE-2021-24402
 The Orders functionality in the WP iCommerce WordPress plugin through 1.1.1 has an `order_id` parameter which is not sanitised, escaped or validated before inserting to a SQL statement, leading to SQL injection. The feature is available to low privilege users such as contributors

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24402](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24402) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24402.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24402.svg)


## CVE-2021-24401
 The Edit domain functionality in the WP Domain Redirect WordPress plugin through 1.0 has an `editid` parameter which is not sanitised, escaped or validated before inserting to a SQL statement, leading to SQL injection.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24401](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24401) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24401.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24401.svg)


## CVE-2021-24400
 The Edit Role functionality in the Display Users WordPress plugin through 2.0.0 had an `id` parameter which is not sanitised, escaped or validated before inserting to a SQL statement, leading to SQL injection.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24400](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24400) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24400.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24400.svg)


## CVE-2021-24399
 The check_order function of The Sorter WordPress plugin through 1.0 uses an `area_id` parameter which is not sanitised, escaped or validated before inserting to a SQL statement, leading to SQL injection.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24399](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24399) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24399.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24399.svg)


## CVE-2021-24398
 The Add new scene functionality in the Responsive 3D Slider WordPress plugin through 1.2 uses an id parameter which is not sanitised, escaped or validated before being inserted to a SQL statement, leading to SQL injection. This is a time based SQLI and in the same function vulnerable parameter is passed twice so if we pass time as 5 seconds it takes 10 seconds to return since the query is ran twice.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24398](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24398) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24398.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24398.svg)


## CVE-2021-24397
 The edit functionality in the MicroCopy WordPress plugin through 1.1.0 makes a get request to fetch the related option. The id parameter used is not sanitised, escaped or validated before inserting to a SQL statement, leading to SQL injection.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24397](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24397) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24397.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24397.svg)


## CVE-2021-24396
 A pageid GET parameter of the GSEOR &#8211; WordPress SEO Plugin WordPress plugin through 1.3 is not sanitised, escaped or validated before inserting to a SQL statement, leading to SQL injection.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24396](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24396) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24396.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24396.svg)


## CVE-2021-24287
 The settings page of the Select All Categories and Taxonomies, Change Checkbox to Radio Buttons WordPress plugin before 1.3.2 did not properly sanitise the tab parameter before outputting it back, leading to a reflected Cross-Site Scripting issue

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24287](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24287) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24287.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24287.svg)


## CVE-2021-24286
 The settings page of the Redirect 404 to parent WordPress plugin before 1.3.1 did not properly sanitise the tab parameter before outputting it back, leading to a reflected Cross-Site Scripting issue

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24286](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24286) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24286.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24286.svg)


## CVE-2021-24276
 The Contact Form by Supsystic WordPress plugin before 1.7.15 did not sanitise the tab parameter of its options page before outputting it in an attribute, leading to a reflected Cross-Site Scripting issue

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24276](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24276) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24276.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24276.svg)


## CVE-2021-24275
 The Popup by Supsystic WordPress plugin before 1.10.5 did not sanitise the tab parameter of its options page before outputting it in an attribute, leading to a reflected Cross-Site Scripting issue

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24275](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24275) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24275.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24275.svg)


## CVE-2021-24274
 The Ultimate Maps by Supsystic WordPress plugin before 1.2.5 did not sanitise the tab parameter of its options page before outputting it in an attribute, leading to a reflected Cross-Site Scripting issue

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24274](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24274) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24274.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24274.svg)


## CVE-2021-24176
 The JH 404 Logger WordPress plugin through 1.1 doesn't sanitise the referer and path of 404 pages, when they are output in the dashboard, which leads to executing arbitrary JavaScript code in the WordPress dashboard.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24176](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-24176) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-24176.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-24176.svg)


## CVE-2021-23444
 This affects the package jointjs before 3.4.2. A type confusion vulnerability can lead to a bypass of CVE-2020-28480 when the user-provided keys used in the path parameter are arrays in the setByPath function.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-23444](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-23444) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-23444.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-23444.svg)


## CVE-2021-23443
 This affects the package edge.js before 5.3.2. A type confusion vulnerability can be used to bypass input sanitization when the input to be rendered is an array (instead of a string or a SafeValue), even if {{ }} are used.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-23443](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-23443) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-23443.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-23443.svg)


## CVE-2021-23442
 This affects all versions of package @cookiex/deep. The global proto object can be polluted using the __proto__ object.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-23442](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-23442) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-23442.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-23442.svg)


## CVE-2021-23441
 All versions of package com.jsoniter:jsoniter are vulnerable to Deserialization of Untrusted Data via malicious JSON strings. This may lead to a Denial of Service, and in certain cases, code execution.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-23441](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-23441) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-23441.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-23441.svg)


## CVE-2021-23434
 This affects the package object-path before 0.11.6. A type confusion vulnerability can lead to a bypass of CVE-2020-15256 when the path components used in the path parameter are arrays. In particular, the condition currentPath === '__proto__' returns false if currentPath is ['__proto__']. This is because the === operator returns always false when the type of the operands is different.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-23434](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-23434) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-23434.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-23434.svg)


## CVE-2021-23420
 This affects the package codeception/codeception from 4.0.0 and before 4.1.22, before 3.1.3. The RunProcess class can be leveraged as a gadget to run arbitrary commands on a system that is deserializing user input without validation.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-23420](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-23420) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-23420.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-23420.svg)


## CVE-2021-23398
 All versions of package react-bootstrap-table are vulnerable to Cross-site Scripting (XSS) via the dataFormat parameter. The problem is triggered when an invalid React element is returned, leading to dangerouslySetInnerHTML being used, which does not sanitize the output.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-23398](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-23398) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-23398.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-23398.svg)


## CVE-2021-23337
 Lodash versions prior to 4.17.21 are vulnerable to Command Injection via the template function.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41720](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-41720) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-41720.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-41720.svg)


## CVE-2021-23054
 On version 16.x before 16.1.0, 15.1.x before 15.1.4, 14.1.x before 14.1.4.4, and all versions of 13.1.x, 12.1.x, and 11.6.x, a reflected cross-site scripting (XSS) vulnerability exists in the resource information page for authenticated users when a full webtop is configured on the BIG-IP APM system. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-23054](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-23054) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-23054.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-23054.svg)


## CVE-2021-23031
 On version 16.0.x before 16.0.1.2, 15.1.x before 15.1.3, 14.1.x before 14.1.4.1, 13.1.x before 13.1.4, 12.1.x before 12.1.6, and 11.6.x before 11.6.5.3, an authenticated user may perform a privilege escalation on the BIG-IP Advanced WAF and ASM Configuration utility. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-23031](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-23031) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-23031.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-23031.svg)


## CVE-2021-23030
 On BIG-IP Advanced WAF and BIG-IP ASM version 16.0.x before 16.0.1.2, 15.1.x before 15.1.3.1, 14.1.x before 14.1.4.3, 13.1.x before 13.1.4.1, and all versions of 12.1.x, when a WebSocket profile is configured on a virtual server, undisclosed requests can cause bd to terminate. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-23030](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-23030) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-23030.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-23030.svg)


## CVE-2021-23027
 On version 16.0.x before 16.0.1.2, 15.1.x before 15.1.3.1, and 14.1.x before 14.1.4.3, a DOM based cross-site scripting (XSS) vulnerability exists in an undisclosed page of the BIG-IP Configuration utility that allows an attacker to execute JavaScript in the context of the currently logged-in user. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-23027](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-23027) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-23027.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-23027.svg)


## CVE-2021-23026
 BIG-IP version 16.0.x before 16.0.1.2, 15.1.x before 15.1.3, 14.1.x before 14.1.4.2, 13.1.x before 13.1.4.1, and all versions of 12.1.x and 11.6.x and all versions of BIG-IQ 8.x, 7.x, and 6.x are vulnerable to cross-site request forgery (CSRF) attacks through iControl SOAP. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-23026](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-23026) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-23026.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-23026.svg)


## CVE-2021-22953
 A CSRF in Concrete CMS version 8.5.5 and below allows an attacker to clone topics which can lead to UI inconvenience, and exhaustion of disk space.Credit for discovery: &quot;Solar Security Research Team&quot;

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22953](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22953) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-22953.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-22953.svg)


## CVE-2021-22952
 A vulnerability found in UniFi Talk application V1.12.3 and earlier permits a malicious actor who has already gained access to a network to subsequently control Talk device(s) assigned to said network if they are not yet adopted. This vulnerability is fixed in UniFi Talk application V1.12.5 and later.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22952](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22952) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-22952.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-22952.svg)


## CVE-2021-22950
 Concrete CMS prior to 8.5.6 had a CSFR vulnerability allowing attachments to comments in the conversation section to be deleted.Credit for discovery: &quot;Solar Security Research Team&quot;

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22950](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22950) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-22950.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-22950.svg)


## CVE-2021-22949
 A CSRF in Concrete CMS version 8.5.5 and below allows an attacker to duplicate files which can lead to UI inconvenience, and exhaustion of disk space.Credit for discovery: &quot;Solar Security CMS Research Team&quot;

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22949](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22949) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-22949.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-22949.svg)


## CVE-2021-22948
 Vulnerability in the generation of session IDs in revive-adserver &lt; 5.3.0, based on the cryptographically insecure uniqid() PHP function. Under some circumstances, an attacker could theoretically be able to brute force session IDs in order to take over a specific account.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22948](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22948) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-22948.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-22948.svg)


## CVE-2021-22939
 If the Node.js https API was used incorrectly and &quot;undefined&quot; was in passed for the &quot;rejectUnauthorized&quot; parameter, no error was returned and connections to servers with an expired certificate would have been accepted.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22939](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22939) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-22939.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-22939.svg)


## CVE-2021-22926
 libcurl-using applications can ask for a specific client certificate to be used in a transfer. This is done with the `CURLOPT_SSLCERT` option (`--cert` with the command line tool).When libcurl is built to use the macOS native TLS library Secure Transport, an application can ask for the client certificate by name or with a file name - using the same option. If the name exists as a file, it will be used instead of by name.If the appliction runs with a current working directory that is writable by other users (like `/tmp`), a malicious user can create a file name with the same name as the app wants to use by name, and thereby trick the application to use the file based cert instead of the one referred to by name making libcurl send the wrong client certificate in the TLS connection handshake.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22926](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22926) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-22926.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-22926.svg)


## CVE-2021-22925
 curl supports the `-t` command line option, known as `CURLOPT_TELNETOPTIONS`in libcurl. This rarely used option is used to send variable=content pairs toTELNET servers.Due to flaw in the option parser for sending `NEW_ENV` variables, libcurlcould be made to pass on uninitialized data from a stack based buffer to theserver. Therefore potentially revealing sensitive internal information to theserver using a clear-text network protocol.This could happen because curl did not call and use sscanf() correctly whenparsing the string provided by the application.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22925](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22925) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-22925.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-22925.svg)


## CVE-2021-22924
 libcurl keeps previously used connections in a connection pool for subsequenttransfers to reuse, if one of them matches the setup.Due to errors in the logic, the config matching function did not take 'issuercert' into account and it compared the involved paths *case insensitively*,which could lead to libcurl reusing wrong connections.File paths are, or can be, case sensitive on many systems but not all, and caneven vary depending on used file systems.The comparison also didn't include the 'issuer cert' which a transfer can setto qualify how to verify the server certificate.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22924](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22924) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-22924.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-22924.svg)


## CVE-2021-22922
 When curl is instructed to download content using the metalink feature, thecontents is verified against a hash provided in the metalink XML file.The metalink XML file points out to the client how to get the same contentfrom a set of different URLs, potentially hosted by different servers and theclient can then download the file from one or several of them. In a serial orparallel manner.If one of the servers hosting the contents has been breached and the contentsof the specific file on that server is replaced with a modified payload, curlshould detect this when the hash of the file mismatches after a completeddownload. It should remove the contents and instead try getting the contentsfrom another URL. This is not done, and instead such a hash mismatch is onlymentioned in text and the potentially malicious content is kept in the file ondisk.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22922](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22922) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-22922.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-22922.svg)


## CVE-2021-22898
 curl 7.7 through 7.76.1 suffers from an information disclosure when the `-t` command line option, known as `CURLOPT_TELNETOPTIONS` in libcurl, is used to send variable=content pairs to TELNET servers. Due to a flaw in the option parser for sending NEW_ENV variables, libcurl could be made to pass on uninitialized data from a stack based buffer to the server, resulting in potentially revealing sensitive internal information to the server using a clear-text network protocol.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22898](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22898) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-22898.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-22898.svg)


## CVE-2021-22869
 An improper access control vulnerability in GitHub Enterprise Server allowed a workflow job to execute in a self-hosted runner group it should not have had access to. This affects customers using self-hosted runner groups for access control. A repository with access to one enterprise runner group could access all of the enterprise runner groups within the organization because of improper authentication checks during the request. This could cause code to be run unintentionally by the incorrect runner group. This vulnerability affected GitHub Enterprise Server versions from 3.0.0 to 3.0.15 and 3.1.0 to 3.1.7 and was fixed in 3.0.16 and 3.1.8 releases.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22869](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22869) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-22869.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-22869.svg)


## CVE-2021-22868
 A path traversal vulnerability was identified in GitHub Enterprise Server that could be exploited when building a GitHub Pages site. User-controlled configuration options used by GitHub Pages were not sufficiently restricted and made it possible to read files on the GitHub Enterprise Server instance. To exploit this vulnerability, an attacker would need permission to create and build a GitHub Pages site on the GitHub Enterprise Server instance. This vulnerability affected all versions of GitHub Enterprise Server prior to 3.1.8 and was fixed in 3.1.8, 3.0.16, and 2.22.22. This vulnerability was reported via the GitHub Bug Bounty program. This is the result of an incomplete fix for CVE-2021-22867.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22868](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22868) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-22868.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-22868.svg)


## CVE-2021-22867
 A path traversal vulnerability was identified in GitHub Enterprise Server that could be exploited when building a GitHub Pages site. User-controlled configuration options used by GitHub Pages were not sufficiently restricted and made it possible to read files on the GitHub Enterprise Server instance. To exploit this vulnerability, an attacker would need permission to create and build a GitHub Pages site on the GitHub Enterprise Server instance. This vulnerability affected all versions of GitHub Enterprise Server prior to 3.1.3 and was fixed in 3.1.3, 3.0.11, and 2.22.17. This vulnerability was reported via the GitHub Bug Bounty program.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22868](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22868) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-22868.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-22868.svg)


## CVE-2021-22699
 Improper Input Validation vulnerability exists in Modicon M241/M251 logic controllers firmware prior to V5.1.9.1 that could cause denial of service when specific crafted requests are sent to the controller over HTTP.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22699](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22699) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-22699.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-22699.svg)


## CVE-2021-22368
 There is a Permission Control Vulnerability in Huawei Smartphone. Successful exploitation of this vulnerability may affect normal use of the device.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22368](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22368) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-22368.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-22368.svg)


## CVE-2021-22367
 There is a Key Management Errors Vulnerability in Huawei Smartphone. Successful exploitation of this vulnerability may lead to authentication bypass.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22367](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22367) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-22367.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-22367.svg)


## CVE-2021-22354
 There is an Information Disclosure Vulnerability in Huawei Smartphone. Successful exploitation of this vulnerability may cause out-of-bounds read.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22354](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22354) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-22354.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-22354.svg)


## CVE-2021-22353
 There is a Memory Buffer Improper Operation Limit Vulnerability in Huawei Smartphone. Successful exploitation of this vulnerability may cause the kernel to restart.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22353](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22353) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-22353.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-22353.svg)


## CVE-2021-22352
 There is a Configuration Defect Vulnerability in Huawei Smartphone. Successful exploitation of this vulnerability may allow attackers to hijack the device and forge UIs to induce users to execute malicious commands.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22352](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22352) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-22352.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-22352.svg)


## CVE-2021-22351
 There is a Credentials Management Errors Vulnerability in Huawei Smartphone. Successful exploitation of this vulnerability may induce users to grant permissions on modifying items in the configuration table,causing system exceptions.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22351](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22351) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-22351.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-22351.svg)


## CVE-2021-22350
 There is a Memory Buffer Improper Operation Limit Vulnerability in Huawei Smartphone. Successful exploitation of this vulnerability may cause the device to crash and restart.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22350](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22350) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-22350.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-22350.svg)


## CVE-2021-22349
 There is an Input Verification Vulnerability in Huawei Smartphone. Successful exploitation of insufficient input verification may cause the system to restart.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22349](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22349) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-22349.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-22349.svg)


## CVE-2021-22348
 There is a Memory Buffer Improper Operation Limit Vulnerability in Huawei Smartphone. Successful exploitation of this vulnerability may cause code to execute.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22348](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22348) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-22348.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-22348.svg)


## CVE-2021-22346
 There is an Improper Permission Management Vulnerability in Huawei Smartphone. Successful exploitation of this vulnerability may lead to the disclosure of user habits.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22346](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22346) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-22346.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-22346.svg)


## CVE-2021-22098
 UAA server versions prior to 75.4.0 are vulnerable to an open redirect vulnerability. A malicious user can exploit the open redirect vulnerability by social engineering leading to take over of victims&#8217; accounts in certain cases along with redirection of UAA users to a malicious sites.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22098](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22098) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-22098.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-22098.svg)


## CVE-2021-22020
 The vCenter Server contains a denial-of-service vulnerability in the Analytics service. Successful exploitation of this issue may allow an attacker to create a denial-of-service condition on vCenter Server.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22020](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22020) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-22020.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-22020.svg)


## CVE-2021-22019
 The vCenter Server contains a denial-of-service vulnerability in VAPI (vCenter API) service. A malicious actor with network access to port 5480 on vCenter Server may exploit this issue by sending a specially crafted jsonrpc message to create a denial of service condition.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22019](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22019) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-22019.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-22019.svg)


## CVE-2021-22018
 The vCenter Server contains an arbitrary file deletion vulnerability in a VMware vSphere Life-cycle Manager plug-in. A malicious actor with network access to port 9087 on vCenter Server may exploit this issue to delete non critical files.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22018](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22018) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-22018.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-22018.svg)


## CVE-2021-22005
 The vCenter Server contains an arbitrary file upload vulnerability in the Analytics service. A malicious actor with network access to port 443 on vCenter Server may exploit this issue to execute code on vCenter Server by uploading a specially crafted file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22005](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-22005) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-22005.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-22005.svg)


## CVE-2021-21993
 The vCenter Server contains an SSRF (Server Side Request Forgery) vulnerability due to improper validation of URLs in vCenter Server Content Library. An authorised user with access to content library may exploit this issue by sending a POST request to vCenter Server leading to information disclosure.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21993](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21993) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21993.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21993.svg)


## CVE-2021-21913
 An information disclosure vulnerability exists in the WiFi Smart Mesh functionality of D-LINK DIR-3040 1.13B03. A specially-crafted network request can lead to command execution. An attacker can connect to the MQTT service to trigger this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21913](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21913) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21913.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21913.svg)


## CVE-2021-21869
 An unsafe deserialization vulnerability exists in the Engine.plugin ProfileInformation ProfileData functionality of CODESYS GmbH CODESYS Development System 3.5.16 and 3.5.17. A specially crafted file can lead to arbitrary command execution. An attacker can provide a malicious file to trigger this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21869](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21869) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21869.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21869.svg)


## CVE-2021-21868
 An unsafe deserialization vulnerability exists in the ObjectManager.plugin Project.get_MissingTypes() functionality of CODESYS GmbH CODESYS Development System 3.5.16 and 3.5.17. A specially crafted file can lead to arbitrary command execution. An attacker can provide a malicious file to trigger this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21868](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21868) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21868.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21868.svg)


## CVE-2021-21867
 An unsafe deserialization vulnerability exists in the ObjectManager.plugin ObjectStream.ProfileByteArray functionality of CODESYS GmbH CODESYS Development System 3.5.16 and 3.5.17. A specially crafted file can lead to arbitrary command execution. An attacker can provide a malicious file to trigger this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21867](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21867) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21867.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21867.svg)


## CVE-2021-21853
 Multiple exploitable integer overflow vulnerabilities exist within the MPEG-4 decoding functionality of the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input can cause an integer overflow due to unchecked addition arithmetic resulting in a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21853](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21853) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21853.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21853.svg)


## CVE-2021-21850
 An exploitable integer overflow vulnerability exists within the MPEG-4 decoding functionality of the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input can cause an integer overflow when the library encounters an atom using the &#8220;trun&#8221; FOURCC code due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21850](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21850) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21850.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21850.svg)


## CVE-2021-21849
 An exploitable integer overflow vulnerability exists within the MPEG-4 decoding functionality of the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input can cause an integer overflow when the library encounters an atom using the &#8220;tfra&#8221; FOURCC code due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21849](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21849) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21849.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21849.svg)


## CVE-2021-21848
 An exploitable integer overflow vulnerability exists within the MPEG-4 decoding functionality of the GPAC Project on Advanced Content library v1.0.1. The library will actually reuse the parser for atoms with the &#8220;stsz&#8221; FOURCC code when parsing atoms that use the &#8220;stz2&#8221; FOURCC code and can cause an integer overflow due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21848](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21848) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21848.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21848.svg)


## CVE-2021-21847
 Multiple exploitable integer overflow vulnerabilities exist within the MPEG-4 decoding functionality of the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input in &#8220;stts&#8221; decoder can cause an integer overflow due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21847](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21847) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21847.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21847.svg)


## CVE-2021-21846
 Multiple exploitable integer overflow vulnerabilities exist within the MPEG-4 decoding functionality of the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input in &#8220;stsz&#8221; decoder can cause an integer overflow due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21846](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21846) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21846.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21846.svg)


## CVE-2021-21845
 Multiple exploitable integer overflow vulnerabilities exist within the MPEG-4 decoding functionality of the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input in &#8220;stsc&#8221; decoder can cause an integer overflow due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21845](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21845) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21845.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21845.svg)


## CVE-2021-21844
 Multiple exploitable integer overflow vulnerabilities exist within the MPEG-4 decoding functionality of the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input when encountering an atom using the &#8220;stco&#8221; FOURCC code, can cause an integer overflow due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21844](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21844) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21844.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21844.svg)


## CVE-2021-21843
 Multiple exploitable integer overflow vulnerabilities exist within the MPEG-4 decoding functionality of the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input can cause an integer overflow due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory corruption. After validating the number of ranges, at [41] the library will multiply the count by the size of the GF_SubsegmentRangeInfo structure. On a 32-bit platform, this multiplication can result in an integer overflow causing the space of the array being allocated to be less than expected. An attacker can convince a user to open a video to trigger this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21843](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21843) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21843.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21843.svg)


## CVE-2021-21842
 An exploitable integer overflow vulnerability exists within the MPEG-4 decoding functionality of the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input can cause an integer overflow when processing an atom using the 'ssix' FOURCC code, due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21842](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21842) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21842.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21842.svg)


## CVE-2021-21841
 An exploitable integer overflow vulnerability exists within the MPEG-4 decoding functionality of the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input when reading an atom using the 'sbgp' FOURCC code can cause an integer overflow due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21841](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21841) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21841.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21841.svg)


## CVE-2021-21840
 An exploitable integer overflow vulnerability exists within the MPEG-4 decoding functionality of the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input used to process an atom using the &#8220;saio&#8221; FOURCC code cause an integer overflow due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21840](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21840) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21840.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21840.svg)


## CVE-2021-21839
 Multiple exploitable integer overflow vulnerabilities exist within the MPEG-4 decoding functionality of the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input can cause an integer overflow due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21839](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21839) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21839.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21839.svg)


## CVE-2021-21838
 Multiple exploitable integer overflow vulnerabilities exist within the MPEG-4 decoding functionality of the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input can cause an integer overflow due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21838](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21838) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21838.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21838.svg)


## CVE-2021-21837
 Multiple exploitable integer overflow vulnerabilities exist within the MPEG-4 decoding functionality of the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input can cause an integer overflow due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21837](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21837) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21837.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21837.svg)


## CVE-2021-21836
 An exploitable integer overflow vulnerability exists within the MPEG-4 decoding functionality of the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input using the &#8220;ctts&#8221; FOURCC code can cause an integer overflow due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21836](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21836) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21836.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21836.svg)


## CVE-2021-21834
 An exploitable integer overflow vulnerability exists within the MPEG-4 decoding functionality of the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input when decoding the atom for the &#8220;co64&#8221; FOURCC can cause an integer overflow due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21834](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21834) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21834.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21834.svg)


## CVE-2021-21798
 An exploitable return of stack variable address vulnerability exists in the JavaScript implementation of Nitro Pro PDF. A specially crafted document can cause a stack variable to go out of scope, resulting in the application dereferencing a stale pointer. This can lead to code execution under the context of the application. An attacker can convince a user to open a document to trigger the vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21798](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21798) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21798.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21798.svg)


## CVE-2021-21742
 There is an information leak vulnerability in the message service app of a ZTE mobile phone. Due to improper parameter settings, attackers could use this vulnerability to obtain some sensitive information of users by accessing specific pages.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21742](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21742) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21742.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21742.svg)


## CVE-2021-21676
 Jenkins requests-plugin Plugin 2.2.7 and earlier does not perform a permission check in an HTTP endpoint, allowing attackers with Overall/Read permission to send test emails to an attacker-specified email address.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21676](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21676) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21676.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21676.svg)


## CVE-2021-21675
 A cross-site request forgery (CSRF) vulnerability in Jenkins requests-plugin Plugin 2.2.12 and earlier allows attackers to create requests and/or have administrators apply pending requests.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21675](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21675) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21675.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21675.svg)


## CVE-2021-21674
 A missing permission check in Jenkins requests-plugin Plugin 2.2.6 and earlier allows attackers with Overall/Read permission to view the list of pending requests.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21674](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21674) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21674.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21674.svg)


## CVE-2021-21673
 Jenkins CAS Plugin 1.6.0 and earlier improperly determines that a redirect URL after login is legitimately pointing to Jenkins, allowing attackers to perform phishing attacks.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21673](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21673) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21673.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21673.svg)


## CVE-2021-21672
 Jenkins Selenium HTML report Plugin 1.0 and earlier does not configure its XML parser to prevent XML external entity (XXE) attacks.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21672](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21672) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21672.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21672.svg)


## CVE-2021-21671
 Jenkins 2.299 and earlier, LTS 2.289.1 and earlier does not invalidate the previous session on login.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21671](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21671) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21671.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21671.svg)


## CVE-2021-21670
 Jenkins 2.299 and earlier, LTS 2.289.1 and earlier allows users to cancel queue items and abort builds of jobs for which they have Item/Cancel permission even when they do not have Item/Read permission.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21670](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21670) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21670.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21670.svg)


## CVE-2021-21574
 Dell BIOSConnect feature contains a buffer overflow vulnerability. An authenticated malicious admin user with local access to the system may potentially exploit this vulnerability to run arbitrary code and bypass UEFI restrictions.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21574](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21574) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21574.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21574.svg)


## CVE-2021-21573
 Dell BIOSConnect feature contains a buffer overflow vulnerability. An authenticated malicious admin user with local access to the system may potentially exploit this vulnerability to run arbitrary code and bypass UEFI restrictions.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21573](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21573) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21573.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21573.svg)


## CVE-2021-21572
 Dell BIOSConnect feature contains a buffer overflow vulnerability. An authenticated malicious admin user with local access to the system may potentially exploit this vulnerability to run arbitrary code and bypass UEFI restrictions.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21572](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21572) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21572.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21572.svg)


## CVE-2021-21570
 Dell NetWorker, versions 18.x and 19.x contain an Information disclosure vulnerability. A NetWorker server user with remote access to NetWorker clients may potentially exploit this vulnerability and gain access to unauthorized information.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21570](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21570) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21570.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21570.svg)


## CVE-2021-21569
 Dell NetWorker, versions 18.x and 19.x contain a Path traversal vulnerability. A NetWorker server user with remote access to NetWorker clients may potentially exploit this vulnerability and gain access to unauthorized information.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21569](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21569) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21569.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21569.svg)


## CVE-2021-21522
 Dell BIOS contains a Credentials Management issue. A local authenticated malicious user may potentially exploit this vulnerability to gain access to sensitive information on an NVMe storage by resetting the BIOS password on the system via the Manageability Interface.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21522](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21522) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21522.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21522.svg)


## CVE-2021-21409
 Netty is an open-source, asynchronous event-driven network application framework for rapid development of maintainable high performance protocol servers &amp; clients. In Netty (io.netty:netty-codec-http2) before version 4.1.61.Final there is a vulnerability that enables request smuggling. The content-length header is not correctly validated if the request only uses a single Http2HeaderFrame with the endStream set to to true. This could lead to request smuggling if the request is proxied to a remote peer and translated to HTTP/1.1. This is a followup of GHSA-wm47-8v5p-wjpj/CVE-2021-21295 which did miss to fix this one case. This was fixed as part of 4.1.61.Final.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21409](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21409) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21409.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21409.svg)


## CVE-2021-21295
 Netty is an open-source, asynchronous event-driven network application framework for rapid development of maintainable high performance protocol servers &amp; clients. In Netty (io.netty:netty-codec-http2) before version 4.1.60.Final there is a vulnerability that enables request smuggling. If a Content-Length header is present in the original HTTP/2 request, the field is not validated by `Http2MultiplexHandler` as it is propagated up. This is fine as long as the request is not proxied through as HTTP/1.1. If the request comes in as an HTTP/2 stream, gets converted into the HTTP/1.1 domain objects (`HttpRequest`, `HttpContent`, etc.) via `Http2StreamFrameToHttpObjectCodec `and then sent up to the child channel's pipeline and proxied through a remote peer as HTTP/1.1 this may result in request smuggling. In a proxy case, users may assume the content-length is validated somehow, which is not the case. If the request is forwarded to a backend channel that is a HTTP/1.1 connection, the Content-Length now has meaning and needs to be checked. An attacker can smuggle requests inside the body as it gets downgraded from HTTP/2 to HTTP/1.1. For an example attack refer to the linked GitHub Advisory. Users are only affected if all of this is true: `HTTP2MultiplexCodec` or `Http2FrameCodec` is used, `Http2StreamFrameToHttpObjectCodec` is used to convert to HTTP/1.1 objects, and these HTTP/1.1 objects are forwarded to another remote peer. This has been patched in 4.1.60.Final As a workaround, the user can do the validation by themselves by implementing a custom `ChannelInboundHandler` that is put in the `ChannelPipeline` behind `Http2StreamFrameToHttpObjectCodec`.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21295](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21295) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21295.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21295.svg)
- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21409](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-21409) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-21409.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-21409.svg)


## CVE-2021-20829
 Cross-site scripting vulnerability due to the inadequate tag sanitization in GROWI versions v4.2.19 and earlier allows remote attackers to execute an arbitrary script on the web browser of the user who accesses a specially crafted page.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20829](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20829) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20829.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20829.svg)


## CVE-2021-20828
 Cross-site scripting vulnerability in Order Status Batch Change Plug-in (for EC-CUBE 3.0 series) all versions allows a remote attacker to inject an arbitrary script via unspecified vectors.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20828](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20828) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20828.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20828.svg)


## CVE-2021-20825
 Cross-site scripting vulnerability in List (order management) item change plug-in (for EC-CUBE 3.0 series) Ver.1.1 and earlier allows a remote attacker to inject an arbitrary script via unspecified vectors.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20825](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20825) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20825.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20825.svg)


## CVE-2021-20815
 Cross-site scripting vulnerability in Edit Boilerplate screen of Movable Type (Movable Type 7 r.4903 and earlier (Movable Type 7 Series), Movable Type 6.8.0 and earlier (Movable Type 6 Series), Movable Type Advanced 7 r.4903 and earlier (Movable Type Advanced 7 Series), Movable Type Premium 1.44 and earlier, and Movable Type Premium Advanced 1.44 and earlier) allows remote attackers to inject arbitrary script or HTML via unspecified vectors.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20815](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20815) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20815.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20815.svg)


## CVE-2021-20814
 Cross-site scripting vulnerability in Setting screen of ContentType Information Widget Plugin of Movable Type (Movable Type 7 r.4903 and earlier (Movable Type 7 Series), Movable Type Advanced 7 r.4903 and earlier (Movable Type Advanced 7 Series), and Movable Type Premium 1.44 and earlier) allows remote attackers to inject arbitrary script or HTML via unspecified vectors.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20814](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20814) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20814.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20814.svg)


## CVE-2021-20813
 Cross-site scripting vulnerability in Edit screen of Content Data of Movable Type (Movable Type 7 r.4903 and earlier (Movable Type 7 Series) and Movable Type Advanced 7 r.4903 and earlier (Movable Type Advanced 7 Series)) allows remote attackers to inject arbitrary script or HTML via unspecified vectors.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20813](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20813) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20813.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20813.svg)


## CVE-2021-20812
 Cross-site scripting vulnerability in Setting screen of Server Sync of Movable Type (Movable Type Advanced 7 r.4903 and earlier (Movable Type Advanced 7 Series) and Movable Type Premium Advanced 1.44 and earlier) allows remote attackers to inject arbitrary script or HTML via unspecified vectors.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20812](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20812) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20812.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20812.svg)


## CVE-2021-20811
 Cross-site scripting vulnerability in List of Assets screen of Movable Type (Movable Type 7 r.4903 and earlier (Movable Type 7 Series), Movable Type 6.8.0 and earlier (Movable Type 6 Series), Movable Type Advanced 7 r.4903 and earlier (Movable Type Advanced 7 Series), Movable Type Premium 1.44 and earlier, and Movable Type Premium Advanced 1.44 and earlier) allows remote attackers to inject arbitrary script or HTML via unspecified vectors.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20811](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20811) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20811.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20811.svg)


## CVE-2021-20810
 Cross-site scripting vulnerability in Website Management screen of Movable Type (Movable Type 7 r.4903 and earlier (Movable Type 7 Series), Movable Type 6.8.0 and earlier (Movable Type 6 Series), Movable Type Advanced 7 r.4903 and earlier (Movable Type Advanced 7 Series), Movable Type Premium 1.44 and earlier, and Movable Type Premium Advanced 1.44 and earlier) allows remote attackers to inject arbitrary script or HTML via unspecified vectors.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20810](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20810) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20810.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20810.svg)


## CVE-2021-20809
 Cross-site scripting vulnerability in Create screens of Entry, Page, and Content Type of Movable Type (Movable Type 7 r.4903 and earlier (Movable Type 7 Series), Movable Type 6.8.0 and earlier (Movable Type 6 Series), Movable Type Advanced 7 r.4903 and earlier (Movable Type Advanced 7 Series), Movable Type Premium 1.44 and earlier, and Movable Type Premium Advanced 1.44 and earlier) allows remote attackers to inject arbitrary script or HTML via unspecified vectors.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20809](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20809) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20809.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20809.svg)


## CVE-2021-20808
 Cross-site scripting vulnerability in Search screen of Movable Type (Movable Type 7 r.4903 and earlier (Movable Type 7 Series), Movable Type 6.8.0 and earlier (Movable Type 6 Series), Movable Type Advanced 7 r.4903 and earlier (Movable Type Advanced 7 Series), Movable Type Premium 1.44 and earlier, and Movable Type Premium Advanced 1.44 and earlier) allows remote attackers to inject arbitrary script or HTML via unspecified vectors.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20808](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20808) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20808.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20808.svg)


## CVE-2021-20793
 Untrusted search path vulnerability in the installer of Sony Audio USB Driver V1.10 and prior and the installer of HAP Music Transfer Ver.1.3.0 and prior allows an attacker to gain privileges and execute arbitrary code via a Trojan horse DLL in an unspecified directory.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20793](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20793) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20793.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20793.svg)


## CVE-2021-20791
 Improper access control vulnerability in RevoWorks Browser 2.1.230 and earlier allows an attacker to bypass access restriction and to exchange unauthorized files between the local environment and the isolated environment or settings of the web browser via unspecified vectors.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20791](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20791) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20791.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20791.svg)


## CVE-2021-20790
 Improper control of program execution vulnerability in RevoWorks Browser 2.1.230 and earlier allows an attacker to execute an arbitrary command or code via unspecified vectors.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20790](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20790) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20790.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20790.svg)


## CVE-2021-20786
 Cross-site request forgery (CSRF) vulnerability in GroupSession (GroupSession Free edition from ver2.2.0 to the version prior to ver5.1.0, GroupSession byCloud from ver3.0.3 to the version prior to ver5.1.0, and GroupSession ZION from ver3.0.3 to the version prior to ver5.1.0) allows a remote attacker to hijack the authentication of administrators via a specially crafted URL.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20786](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20786) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20786.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20786.svg)


## CVE-2021-20746
 Cross-site scripting vulnerability in WordPress Popular Posts 5.3.2 and earlier allows a remote authenticated attacker to inject an arbitrary script via unspecified vectors.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20746](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20746) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20746.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20746.svg)


## CVE-2021-20583
 IBM Security Verify (IBM Security Verify Privilege Vault 10.9.66) could disclose sensitive information through an HTTP GET request by a privileged user due to improper input validation.. IBM X-Force ID: 199396.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20583](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20583) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20583.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20583.svg)


## CVE-2021-20580
 IBM Planning Analytics 2.0 could be vulnerable to cross-site request forgery (CSRF) which could allow an attacker to execute malicious and unauthorized actions transmitted from a user that the website trusts. IBM X-Force ID: 198241.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20580](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20580) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20580.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20580.svg)


## CVE-2021-20578
 IBM Cloud Pak for Security (CP4S) 1.7.0.0, 1.7.1.0, 1.7.2.0, and 1.8.0.0 could allow an attacker to perform unauthorized actions due to improper or missing authentication controls. IBM X-Force ID: 199282.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20578](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20578) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20578.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20578.svg)


## CVE-2021-20563
 IBM Sterling File Gateway 2.2.0.0 through 6.1.0.3 could allow a remote authenciated user to obtain sensitive information. By sending a specially crafted request, the user could disclose a valid filepath on the server which could be used in further attacks against the system. IBM X-Force ID: 199234.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20563](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20563) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20563.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20563.svg)


## CVE-2021-20554
 IBM Sterling Order Management 9.4, 9.5, and 10.0 is vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 199179.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20554](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20554) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20554.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20554.svg)


## CVE-2021-20537
 IBM Security Verify Access Docker 10.0.0 contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data. IBM X-Force ID:198918

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20537](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20537) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20537.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20537.svg)


## CVE-2021-20534
 IBM Security Verify Access Docker 10.0.0 could allow a remote attacker to conduct phishing attacks, using an open redirect attack. By persuading a victim to visit a specially crafted Web site, a remote attacker could exploit this vulnerability to spoof the URL displayed to redirect a user to a malicious Web site that would appear to be trusted. This could allow the attacker to obtain highly sensitive information or conduct further attacks against the victim. IBM X-Force ID: 198814

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20534](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20534) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20534.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20534.svg)


## CVE-2021-20533
 IBM Security Verify Access Docker 10.0.0 could allow a remote authenticated attacker to execute arbitrary commands on the system by sending a specially crafted request. IBM X-Force ID: 198813

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20533](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20533) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20533.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20533.svg)


## CVE-2021-20524
 IBM Security Verify Access Docker 10.0.0 is vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 198661.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20524](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20524) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20524.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20524.svg)


## CVE-2021-20523
 IBM Security Verify Access Docker 10.0.0 could allow a remote attacker to obtain sensitive information when a detailed technical error message is returned in the browser. This information could be used in further attacks against the system. IBM X-Force ID: 198660

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20523](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20523) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20523.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20523.svg)


## CVE-2021-20511
 IBM Security Verify Access Docker 10.0.0 could allow a remote attacker to traverse directories on the system. An attacker could send a specially-crafted URL request containing &quot;dot dot&quot; sequences (/../) to view arbitrary files on the system. IBM X-Force ID: 198300.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20511](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20511) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20511.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20511.svg)


## CVE-2021-20510
 IBM Security Verify Access Docker 10.0.0 stores user credentials in plain clear text which can be read by a local user. IBM X-Force ID: 198299

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20510](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20510) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20510.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20510.svg)


## CVE-2021-20500
 IBM Security Verify Access Docker 10.0.0 could reveal highly sensitive information to a local privileged user. IBM X-Force ID: 197980.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20500](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20500) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20500.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20500.svg)


## CVE-2021-20499
 IBM Security Verify Access Docker 10.0.0 could allow a remote attacker to obtain sensitive information when a detailed technical error message is returned in the browser. This information could be used in further attacks against the system. IBM X-Force ID: 197973

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20499](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20499) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20499.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20499.svg)


## CVE-2021-20498
 IBM Security Verify Access Docker 10.0.0 reveals version information in HTTP requets that could be used in further attacks against the system. IBM X-Force ID: 197972.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20498](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20498) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20498.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20498.svg)


## CVE-2021-20497
 IBM Security Verify Access Docker 10.0.0 uses weaker than expected cryptographic algorithms that could allow an attacker to decrypt highly sensitive information. IBM X-Force ID: 197969

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20497](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20497) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20497.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20497.svg)


## CVE-2021-20496
 IBM Security Verify Access Docker 10.0.0 could allow an authenticated user to bypass input due to improper input validation. IBM X-Force ID: 197966.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20496](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20496) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20496.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20496.svg)


## CVE-2021-20490
 IBM Spectrum Protect Plus 10.1.0 through 10.1.8 could allow a local user to cause a denial of service due to insecure file permission settings. IBM X-Force ID: 197791.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20490](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20490) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20490.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20490.svg)


## CVE-2021-20485
 IBM Sterling File Gateway 2.2.0.0 through 6.1.0.3 could allow a remote attacker to obtain sensitive information when a detailed technical error message is returned in the browser. This information could be used in further attacks against the system. IBM X-Force ID: 197667.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20485](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20485) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20485.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20485.svg)


## CVE-2021-20484
 IBM Sterling File Gateway 2.2.0.0 through 6.1.0.3 is vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 197666.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20484](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20484) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20484.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20484.svg)


## CVE-2021-20477
 IBM Planning Analytics 2.0 is vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 196949.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20477](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20477) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20477.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20477.svg)


## CVE-2021-20435
 IBM Security Verify Bridge 1.0.5.0 does not properly validate a certificate which could allow a local attacker to obtain sensitive information that could aid in further attacks against the system. IBM X-Force ID: 196355.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20435](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20435) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20435.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20435.svg)


## CVE-2021-20434
 IBM Security Verify Bridge 1.0.5.0 stores user credentials in plain clear text which can be read by a local user. IBM X-Force ID: 196346.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20434](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20434) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20434.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20434.svg)


## CVE-2021-20377
 IBM Security Guardium 11.3 could allow a remote attacker to obtain sensitive information when a detailed technical error message is returned in the browser. This information could be used in further attacks against the system. IBM X-Force ID: 195569.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20377](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20377) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20377.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20377.svg)


## CVE-2021-20314
 Stack buffer overflow in libspf2 versions below 1.2.11 when processing certain SPF macros can lead to Denial of service and potentially code execution via malicious crafted SPF explanation messages.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20314](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20314) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20314.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20314.svg)


## CVE-2021-20228
 A flaw was found in the Ansible Engine 2.9.18, where sensitive info is not masked by default and is not protected by the no_log feature when using the sub-option feature of the basic.py module. This flaw allows an attacker to obtain sensitive information. The highest threat from this vulnerability is to confidentiality.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20228](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20228) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20228.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20228.svg)


## CVE-2021-20208
 A flaw was found in cifs-utils in versions before 6.13. A user when mounting a krb5 CIFS file system from within a container can use Kerberos credentials of the host. The highest threat from this vulnerability is to data confidentiality and integrity.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20208](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20208) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20208.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20208.svg)


## CVE-2021-20118
 Nessus Agent 8.3.0 and earlier was found to contain a local privilege escalation vulnerability which could allow an authenticated, local administrator to run specific executables on the Nessus Agent host. This is different than CVE-2021-20117.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20118](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20118) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20118.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20118.svg)
- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20117](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20117) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20117.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20117.svg)


## CVE-2021-20117
 Nessus Agent 8.3.0 and earlier was found to contain a local privilege escalation vulnerability which could allow an authenticated, local administrator to run specific executables on the Nessus Agent host. This is different than CVE-2021-20118.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20118](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20118) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20118.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20118.svg)
- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20117](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-20117) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-20117.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-20117.svg)


## CVE-2021-3830
 btcpayserver is vulnerable to Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3830](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3830) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3830.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3830.svg)


## CVE-2021-3828
 nltk is vulnerable to Inefficient Regular Expression Complexity

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3828](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3828) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3828.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3828.svg)


## CVE-2021-3824
 OpenVPN Access Server 2.9.0 through 2.9.4 allow remote attackers to inject arbitrary web script or HTML via the web login page URL.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3824](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3824) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3824.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3824.svg)


## CVE-2021-3822
 jsoneditor is vulnerable to Inefficient Regular Expression Complexity

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3822](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3822) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3822.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3822.svg)


## CVE-2021-3820
 inflect is vulnerable to Inefficient Regular Expression Complexity

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3820](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3820) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3820.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3820.svg)


## CVE-2021-3819
 firefly-iii is vulnerable to Cross-Site Request Forgery (CSRF)

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3819](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3819) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3819.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3819.svg)


## CVE-2021-3818
 grav is vulnerable to Reliance on Cookies without Validation and Integrity Checking

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3818](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3818) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3818.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3818.svg)


## CVE-2021-3812
 adminlte is vulnerable to Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3812](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3812) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3812.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3812.svg)


## CVE-2021-3811
 adminlte is vulnerable to Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3811](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3811) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3811.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3811.svg)


## CVE-2021-3810
 code-server is vulnerable to Inefficient Regular Expression Complexity

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3810](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3810) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3810.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3810.svg)


## CVE-2021-3807
 ansi-regex is vulnerable to Inefficient Regular Expression Complexity

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3807](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3807) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3807.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3807.svg)


## CVE-2021-3806
 A path traversal vulnerability on Pardus Software Center's &quot;extractArchive&quot; function could allow anyone on the same network to do a man-in-the-middle and write files on the system.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3806](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3806) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3806.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3806.svg)


## CVE-2021-3805
 object-path is vulnerable to Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3805](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3805) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3805.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3805.svg)


## CVE-2021-3804
 taro is vulnerable to Inefficient Regular Expression Complexity

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3804](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3804) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3804.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3804.svg)


## CVE-2021-3803
 nth-check is vulnerable to Inefficient Regular Expression Complexity

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3803](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3803) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3803.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3803.svg)


## CVE-2021-3801
 prism is vulnerable to Inefficient Regular Expression Complexity

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3801](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3801) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3801.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3801.svg)


## CVE-2021-3799
 grav-plugin-admin is vulnerable to Improper Restriction of Rendered UI Layers or Frames

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3799](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3799) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3799.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3799.svg)


## CVE-2021-3797
 hestiacp is vulnerable to Use of Wrong Operator in String Comparison

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3797](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3797) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3797.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3797.svg)


## CVE-2021-3796
 vim is vulnerable to Use After Free

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3796](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3796) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3796.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3796.svg)


## CVE-2021-3795
 semver-regex is vulnerable to Inefficient Regular Expression Complexity

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3795](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3795) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3795.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3795.svg)


## CVE-2021-3794
 vuelidate is vulnerable to Inefficient Regular Expression Complexity

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3794](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3794) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3794.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3794.svg)


## CVE-2021-3778
 vim is vulnerable to Heap-based Buffer Overflow

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3778](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3778) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3778.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3778.svg)


## CVE-2021-3770
 vim is vulnerable to Heap-based Buffer Overflow

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3770](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3770) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3770.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3770.svg)


## CVE-2021-3747
 The MacOS version of Multipass, version 1.7.0, fixed in 1.7.2, accidentally installed the application directory with incorrect owner.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3747](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3747) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3747.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3747.svg)


## CVE-2021-3713
 An out-of-bounds write flaw was found in the UAS (USB Attached SCSI) device emulation of QEMU in versions prior to 6.2.0-rc0. The device uses the guest supplied stream number unchecked, which can lead to out-of-bounds access to the UASDevice-&gt;data3 and UASDevice-&gt;status3 fields. A malicious guest user could use this flaw to crash QEMU or potentially achieve code execution with the privileges of the QEMU process on the host.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3713](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3713) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3713.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3713.svg)


## CVE-2021-3712
 ASN.1 strings are represented internally within OpenSSL as an ASN1_STRING structure which contains a buffer holding the string data and a field holding the buffer length. This contrasts with normal C strings which are repesented as a buffer for the string data which is terminated with a NUL (0) byte. Although not a strict requirement, ASN.1 strings that are parsed using OpenSSL's own &quot;d2i&quot; functions (and other similar parsing functions) as well as any string whose value has been set with the ASN1_STRING_set() function will additionally NUL terminate the byte array in the ASN1_STRING structure. However, it is possible for applications to directly construct valid ASN1_STRING structures which do not NUL terminate the byte array by directly setting the &quot;data&quot; and &quot;length&quot; fields in the ASN1_STRING array. This can also happen by using the ASN1_STRING_set0() function. Numerous OpenSSL functions that print ASN.1 data have been found to assume that the ASN1_STRING byte array will be NUL terminated, even though this is not guaranteed for strings that have been directly constructed. Where an application requests an ASN.1 structure to be printed, and where that ASN.1 structure contains ASN1_STRINGs that have been directly constructed by the application without NUL terminating the &quot;data&quot; field, then a read buffer overrun can occur. The same thing can also occur during name constraints processing of certificates (for example if a certificate has been directly constructed by the application instead of loading it via the OpenSSL parsing functions, and the certificate contains non NUL terminated ASN1_STRING structures). It can also occur in the X509_get1_email(), X509_REQ_get1_email() and X509_get1_ocsp() functions. If a malicious actor can cause an application to directly construct an ASN1_STRING and then process it through one of the affected OpenSSL functions then this issue could be hit. This might result in a crash (causing a Denial of Service attack). It could also result in the disclosure of private memory contents (such as private keys, or sensitive plaintext). Fixed in OpenSSL 1.1.1l (Affected 1.1.1-1.1.1k). Fixed in OpenSSL 1.0.2za (Affected 1.0.2-1.0.2y).

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3712](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3712) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3712.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3712.svg)


## CVE-2021-3682
 A flaw was found in the USB redirector device emulation of QEMU in versions prior to 6.1.0-rc2. It occurs when dropping packets during a bulk transfer from a SPICE client due to the packet queue being full. A malicious SPICE client could use this flaw to make QEMU call free() with faked heap chunk metadata, resulting in a crash of QEMU or potential code execution with the privileges of the QEMU process on the host.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3682](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3682) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3682.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3682.svg)


## CVE-2021-3673
 A vulnerability was found in Radare2 in version 5.3.1. Improper input validation when reading a crafted LE binary can lead to resource exhaustion and DoS.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3673](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3673) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3673.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3673.svg)


## CVE-2021-3634
 A flaw has been found in libssh in versions prior to 0.9.6. The SSH protocol keeps track of two shared secrets during the lifetime of the session. One of them is called secret_hash and the other session_id. Initially, both of them are the same, but after key re-exchange, previous session_id is kept and used as an input to new secret_hash. Historically, both of these buffers had shared length variable, which worked as long as these buffers were same. But the key re-exchange operation can also change the key exchange method, which can be based on hash of different size, eventually creating &quot;secret_hash&quot; of different size than the session_id has. This becomes an issue when the session_id memory is zeroed or when it is used again during second key re-exchange.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3634](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3634) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3634.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3634.svg)


## CVE-2021-3628
 OpenKM Community Edition in its 6.3.10 version is vulnerable to authenticated Cross-site scripting (XSS). A remote attacker could exploit this vulnerability by injecting arbitrary code via de uuid parameter.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3628](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3628) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3628.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3628.svg)


## CVE-2021-3626
 The Windows version of Multipass before 1.7.0 allowed any local process to connect to the localhost TCP control socket to perform mounts from the operating system to a guest, allowing for privilege escalation.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3626](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3626) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3626.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3626.svg)


## CVE-2021-3561
 An Out of Bounds flaw was found fig2dev version 3.2.8a. A flawed bounds check in read_objects() could allow an attacker to provide a crafted malicious input causing the application to either crash or in some cases cause memory corruption. The highest threat from this vulnerability is to integrity as well as system availability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3561](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3561) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3561.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3561.svg)


## CVE-2021-3546
 A flaw was found in vhost-user-gpu of QEMU in versions up to and including 6.0. An out-of-bounds write vulnerability can allow a malicious guest to crash the QEMU process on the host resulting in a denial of service or potentially execute arbitrary code on the host with the privileges of the QEMU process. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3546](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3546) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3546.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3546.svg)


## CVE-2021-3545
 An information disclosure vulnerability was found in the virtio vhost-user GPU device (vhost-user-gpu) of QEMU in versions up to and including 6.0. The flaw exists in virgl_cmd_get_capset_info() in contrib/vhost-user-gpu/virgl.c and could occur due to the read of uninitialized memory. A malicious guest could exploit this issue to leak memory from the host.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3545](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3545) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3545.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3545.svg)


## CVE-2021-3544
 Several memory leaks were found in the virtio vhost-user GPU device (vhost-user-gpu) of QEMU in versions up to and including 6.0. They exist in contrib/vhost-user-gpu/vhost-user-gpu.c and contrib/vhost-user-gpu/virgl.c due to improper release of memory (i.e., free) after effective lifetime.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3544](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3544) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3544.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3544.svg)


## CVE-2021-3050
 An OS command injection vulnerability in the Palo Alto Networks PAN-OS web interface enables an authenticated administrator to execute arbitrary OS commands to escalate privileges. This issue impacts: PAN-OS 9.0 version 9.0.10 through PAN-OS 9.0.14; PAN-OS 9.1 version 9.1.4 through PAN-OS 9.1.10; PAN-OS 10.0 version 10.0.7 and earlier PAN-OS 10.0 versions; PAN-OS 10.1 version 10.1.0 through PAN-OS 10.1.1. Prisma Access firewalls and firewalls running PAN-OS 8.1 versions are not impacted by this issue.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3050](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3050) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3050.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3050.svg)


## CVE-2021-3048
 Certain invalid URL entries contained in an External Dynamic List (EDL) cause the Device Server daemon (devsrvr) to stop responding. This condition causes subsequent commits on the firewall to fail and prevents administrators from performing commits and configuration changes even though the firewall remains otherwise functional. If the firewall then restarts, it results in a denial-of-service (DoS) condition and the firewall stops processing traffic. This issue impacts: PAN-OS 9.0 versions earlier than PAN-OS 9.0.14; PAN-OS 9.1 versions earlier than PAN-OS 9.1.9; PAN-OS 10.0 versions earlier than PAN-OS 10.0.5. PAN-OS 8.1 and PAN-OS 10.1 versions are not impacted.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3048](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3048) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3048.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3048.svg)


## CVE-2021-3047
 A cryptographically weak pseudo-random number generator (PRNG) is used during authentication to the Palo Alto Networks PAN-OS web interface. This enables an authenticated attacker, with the capability to observe their own authentication secrets over a long duration on the PAN-OS appliance, to impersonate another authenticated web interface administrator's session. This issue impacts: PAN-OS 8.1 versions earlier than PAN-OS 8.1.19; PAN-OS 9.0 versions earlier than PAN-OS 9.0.14; PAN-OS 9.1 versions earlier than PAN-OS 9.1.10; PAN-OS 10.0 versions earlier than PAN-OS 10.0.4. PAN-OS 10.1 versions are not impacted.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3047](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3047) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3047.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3047.svg)


## CVE-2021-3046
 An improper authentication vulnerability exists in Palo Alto Networks PAN-OS software that enables a SAML authenticated attacker to impersonate any other user in the GlobalProtect Portal and GlobalProtect Gateway when they are configured to use SAML authentication. This issue impacts: PAN-OS 8.1 versions earlier than PAN-OS 8.1.19; PAN-OS 9.0 versions earlier than PAN-OS 9.0.14; PAN-OS 9.1 versions earlier than PAN-OS 9.1.9; PAN-OS 10.0 versions earlier than PAN-OS 10.0.5. PAN-OS 10.1 versions are not impacted.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3046](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3046) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3046.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3046.svg)


## CVE-2021-3045
 An OS command argument injection vulnerability in the Palo Alto Networks PAN-OS web interface enables an authenticated administrator to read any arbitrary file from the file system. This issue impacts: PAN-OS 8.1 versions earlier than PAN-OS 8.1.19; PAN-OS 9.0 versions earlier than PAN-OS 9.0.14; PAN-OS 9.1 versions earlier than PAN-OS 9.1.10. PAN-OS 10.0 and later versions are not impacted.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3045](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-3045) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-3045.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-3045.svg)


## CVE-2021-2464
 Vulnerability in Oracle Linux (component: OSwatcher). Supported versions that are affected are 7 and 8. Easily exploitable vulnerability allows low privileged attacker with logon to the infrastructure where Oracle Linux executes to compromise Oracle Linux. Successful attacks of this vulnerability can result in takeover of Oracle Linux. CVSS 3.1 Base Score 7.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-2464](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-2464) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-2464.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-2464.svg)


## CVE-2021-1976
 A use after free can occur due to improper validation of P2P device address in PD Request frame in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Voice &amp; Music, Snapdragon Wearables, Snapdragon Wired Infrastructure and Networking

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1976](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1976) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-1976.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-1976.svg)


## CVE-2021-1947
 Use-after-free vulnerability in kernel graphics driver because of storing an invalid pointer in Snapdragon Compute, Snapdragon Connectivity, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Wearables, Snapdragon Wired Infrastructure and Networking

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1947](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1947) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-1947.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-1947.svg)


## CVE-2021-1939
 Null pointer dereference occurs due to improper validation when the preemption feature enablement is toggled in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Wearables

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1939](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1939) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-1939.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-1939.svg)


## CVE-2021-1885
 An out-of-bounds read was addressed with improved bounds checking. This issue is fixed in macOS Big Sur 11.3, iOS 14.5 and iPadOS 14.5, watchOS 7.4, tvOS 14.5. Processing a maliciously crafted image may lead to arbitrary code execution.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1885](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1885) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-1885.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-1885.svg)


## CVE-2021-1881
 An out-of-bounds read was addressed with improved input validation. This issue is fixed in Security Update 2021-002 Catalina, Security Update 2021-003 Mojave, iOS 14.5 and iPadOS 14.5, watchOS 7.4, tvOS 14.5, macOS Big Sur 11.3. Processing a maliciously crafted font file may lead to arbitrary code execution.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1881](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1881) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-1881.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-1881.svg)


## CVE-2021-1858
 Processing a maliciously crafted image may lead to arbitrary code execution. This issue is fixed in Security Update 2021-002 Catalina, iOS 14.5 and iPadOS 14.5, watchOS 7.4, tvOS 14.5, macOS Big Sur 11.3. An out-of-bounds write issue was addressed with improved bounds checking.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1858](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1858) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-1858.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-1858.svg)


## CVE-2021-1833
 This issue was addressed with improved checks. This issue is fixed in iOS 14.5 and iPadOS 14.5. An application may be able to gain elevated privileges.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1833](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1833) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-1833.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-1833.svg)


## CVE-2021-1832
 Copied files may not have the expected file permissions. This issue is fixed in Security Update 2021-002 Catalina, iOS 14.5 and iPadOS 14.5, watchOS 7.4, tvOS 14.5, macOS Big Sur 11.3. The issue was addressed with improved permissions logic.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1832](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1832) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-1832.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-1832.svg)


## CVE-2021-1831
 The issue was addressed with improved permissions logic. This issue is fixed in iOS 14.5 and iPadOS 14.5. An application may allow shortcuts to access restricted files.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1831](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1831) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-1831.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-1831.svg)


## CVE-2021-1830
 An out-of-bounds read was addressed with improved input validation. This issue is fixed in iOS 14.5 and iPadOS 14.5. A local user may be able to read kernel memory.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1830](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1830) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-1830.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-1830.svg)


## CVE-2021-1829
 A type confusion issue was addressed with improved state handling. This issue is fixed in macOS Big Sur 11.3. An application may be able to execute arbitrary code with kernel privileges.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1829](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1829) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-1829.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-1829.svg)


## CVE-2021-1810
 A logic issue was addressed with improved state management. This issue is fixed in macOS Big Sur 11.3, Security Update 2021-002 Catalina. A malicious application may bypass Gatekeeper checks.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1810](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1810) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-1810.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-1810.svg)


## CVE-2021-1675
 Windows Print Spooler Elevation of Privilege Vulnerability

- [https://github.com/OppressionBreedsResistance/CVE-2021-1675-PrintNightmare](https://github.com/OppressionBreedsResistance/CVE-2021-1675-PrintNightmare) :  ![starts](https://img.shields.io/github/stars/OppressionBreedsResistance/CVE-2021-1675-PrintNightmare.svg) ![forks](https://img.shields.io/github/forks/OppressionBreedsResistance/CVE-2021-1675-PrintNightmare.svg)


## CVE-2021-1622
 A vulnerability in the Common Open Policy Service (COPS) of Cisco IOS XE Software for Cisco cBR-8 Converged Broadband Routers could allow an unauthenticated, remote attacker to cause resource exhaustion, resulting in a denial of service (DoS) condition. This vulnerability is due to a deadlock condition in the code when processing COPS packets under certain conditions. An attacker could exploit this vulnerability by sending COPS packets with high burst rates to an affected device. A successful exploit could allow the attacker to cause the CPU to consume excessive resources, which prevents other control plane processes from obtaining resources and results in a DoS.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1622](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1622) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-1622.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-1622.svg)


## CVE-2021-1615
 A vulnerability in the packet processing functionality of Cisco Embedded Wireless Controller (EWC) Software for Catalyst Access Points (APs) could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected AP. This vulnerability is due to insufficient buffer allocation. An attacker could exploit this vulnerability by sending crafted traffic to an affected device. A successful exploit could allow the attacker to exhaust available resources and cause a DoS condition on an affected AP, as well as a DoS condition for client traffic traversing the AP.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1615](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1615) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-1615.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-1615.svg)


## CVE-2021-1612
 A vulnerability in the Cisco IOS XE SD-WAN Software CLI could allow an authenticated, local attacker to overwrite arbitrary files on the local system. This vulnerability is due to improper access controls on files within the local file system. An attacker could exploit this vulnerability by placing a symbolic link in a specific location on the local file system. A successful exploit could allow the attacker to overwrite arbitrary files on an affected device.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1612](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1612) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-1612.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-1612.svg)


## CVE-2021-1592
 A vulnerability in the way Cisco UCS Manager software handles SSH sessions could allow an authenticated, remote attacker to cause a denial of service (DoS) condition on an affected device. This vulnerability is due to improper resource management for established SSH sessions. An attacker could exploit this vulnerability by opening a significant number of SSH sessions on an affected device. A successful exploit could allow the attacker to cause a crash and restart of internal Cisco UCS Manager software processes and a temporary loss of access to the Cisco UCS Manager CLI and web UI. Note: The attacker must have valid user credentials to authenticate to the affected device.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1592](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1592) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-1592.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-1592.svg)


## CVE-2021-1591
 A vulnerability in the EtherChannel port subscription logic of Cisco Nexus 9500 Series Switches could allow an unauthenticated, remote attacker to bypass access control list (ACL) rules that are configured on an affected device. This vulnerability is due to oversubscription of resources that occurs when applying ACLs to port channel interfaces. An attacker could exploit this vulnerability by attempting to access network resources that are protected by the ACL. A successful exploit could allow the attacker to access network resources that would be protected by the ACL that was applied on the port channel interface.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1591](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1591) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-1591.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-1591.svg)


## CVE-2021-1590
 A vulnerability in the implementation of the system login block-for command for Cisco NX-OS Software could allow an unauthenticated, remote attacker to cause a login process to unexpectedly restart, causing a denial of service (DoS) condition. This vulnerability is due to a logic error in the implementation of the system login block-for command when an attack is detected and acted upon. An attacker could exploit this vulnerability by performing a brute-force login attack on an affected device. A successful exploit could allow the attacker to cause a login process to reload, which could result in a delay during authentication to the affected device.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1590](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1590) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-1590.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-1590.svg)


## CVE-2021-1589
 A vulnerability in the disaster recovery feature of Cisco SD-WAN vManage Software could allow an authenticated, remote attacker to gain unauthorized access to user credentials. This vulnerability exists because access to API endpoints is not properly restricted. An attacker could exploit this vulnerability by sending a request to an API endpoint. A successful exploit could allow the attacker to gain unauthorized access to administrative credentials that could be used in further attacks.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1589](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1589) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-1589.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-1589.svg)


## CVE-2021-1588
 A vulnerability in the MPLS Operation, Administration, and Maintenance (OAM) feature of Cisco NX-OS Software could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected device. This vulnerability is due to improper input validation when an affected device is processing an MPLS echo-request or echo-reply packet. An attacker could exploit this vulnerability by sending malicious MPLS echo-request or echo-reply packets to an interface that is enabled for MPLS forwarding on the affected device. A successful exploit could allow the attacker to cause the MPLS OAM process to crash and restart multiple times, causing the affected device to reload and resulting in a DoS condition.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1588](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1588) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-1588.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-1588.svg)


## CVE-2021-1546
 A vulnerability in the CLI of Cisco SD-WAN Software could allow an authenticated, local attacker to access sensitive information. This vulnerability is due to improper protections on file access through the CLI. An attacker could exploit this vulnerability by running a CLI command that targets an arbitrary file on the local system. A successful exploit could allow the attacker to return portions of an arbitrary file, possibly resulting in the disclosure of sensitive information.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1546](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1546) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-1546.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-1546.svg)


## CVE-2021-1419
 A vulnerability in the SSH management feature of multiple Cisco Access Points (APs) platforms could allow a local, authenticated user to modify files on the affected device and possibly gain escalated privileges. The vulnerability is due to improper checking on file operations within the SSH management interface. A network administrator user could exploit this vulnerability by accessing an affected device through SSH management to make a configuration change. A successful exploit could allow the attacker to gain privileges equivalent to the root user.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1419](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1419) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-1419.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-1419.svg)


## CVE-2021-1075
 NVIDIA Windows GPU Display Driver for Windows, all versions, contains a vulnerability in the kernel mode layer (nvlddmkm.sys) handler for DxgkDdiEscape where the program dereferences a pointer that contains a location for memory that is no longer valid, which may lead to code execution, denial of service, or escalation of privileges. Attacker does not have any control over the information and may conduct limited data modification.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1075](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-1075) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-1075.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-1075.svg)


## CVE-2021-0660
 In ccu, there is a possible out of bounds read due to incorrect error handling. This could lead to information disclosure with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS05827145; Issue ID: ALPS05827145.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0660](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0660) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-0660.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-0660.svg)


## CVE-2021-0612
 In m4u, there is a possible memory corruption due to a use after free. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS05403499; Issue ID: ALPS05425834.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0612](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0612) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-0612.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-0612.svg)


## CVE-2021-0611
 In m4u, there is a possible memory corruption due to a use after free. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS05403499; Issue ID: ALPS05425810.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0611](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0611) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-0611.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-0611.svg)


## CVE-2021-0610
 In memory management driver, there is a possible memory corruption due to an integer overflow. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS05403499; Issue ID: ALPS05411456.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0610](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0610) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-0610.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-0610.svg)


## CVE-2021-0425
 In memory management driver, there is a possible side channel information disclosure. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS05403499; Issue ID: ALPS05400059.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0425](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0425) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-0425.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-0425.svg)


## CVE-2021-0424
 In memory management driver, there is a possible system crash due to a missing bounds check. This could lead to local denial of service with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS05403499; Issue ID: ALPS05393787.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0424](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0424) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-0424.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-0424.svg)


## CVE-2021-0423
 In memory management driver, there is a possible information disclosure due to uninitialized data. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS05403499; Issue ID: ALPS05385714.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0423](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0423) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-0423.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-0423.svg)


## CVE-2021-0422
 In memory management driver, there is a possible system crash due to a missing bounds check. This could lead to local denial of service with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS05403499; Issue ID: ALPS05381071.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0422](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0422) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-0422.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-0422.svg)


## CVE-2021-0129
 Improper access control in BlueZ may allow an authenticated user to potentially enable information disclosure via adjacent access.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0129](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0129) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-0129.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-0129.svg)


## CVE-2021-0114
 Insecure default variable initialization for the Intel BSSA DFT feature may allow a privileged user to potentially enable an escalation of privilege via local access.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0114](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0114) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-0114.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-0114.svg)


## CVE-2021-0062
 Improper input validation in some Intel(R) Graphics Drivers before version 27.20.100.8935 may allow an authenticated user to potentially enable escalation of privilege via local access.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0062](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0062) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-0062.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-0062.svg)


## CVE-2021-0061
 Improper initialization in some Intel(R) Graphics Driver before version 27.20.100.9030 may allow an authenticated user to potentially enable escalation of privilege via local access.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0061](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0061) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-0061.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-0061.svg)


## CVE-2021-0012
 Use after free in some Intel(R) Graphics Driver before version 27.20.100.8336, 15.45.33.5164, and 15.40.47.5166 may allow an authenticated user to potentially enable denial of service via local access.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0012](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0012) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-0012.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-0012.svg)


## CVE-2021-0009
 Out-of-bounds read in the firmware for Intel(R) Ethernet Adapters 800 Series Controllers and associated adapters before version 1.5.3.0 may allow an unauthenticated user to potentially enable denial of service via adjacent access.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0009](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0009) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-0009.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-0009.svg)


## CVE-2021-0008
 Uncontrolled resource consumption in firmware for Intel(R) Ethernet Adapters 800 Series Controllers and associated adapters before version 1.5.3.0 may allow privileged user to potentially enable denial of service via local access.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0008](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0008) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-0008.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-0008.svg)


## CVE-2021-0007
 Uncaught exception in firmware for Intel(R) Ethernet Adapters 800 Series Controllers and associated adapters before version 1.5.1.0 may allow a privileged attacker to potentially enable denial of service via local access.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0007](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0007) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-0007.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-0007.svg)


## CVE-2021-0006
 Improper conditions check in firmware for Intel(R) Ethernet Adapters 800 Series Controllers and associated adapters before version 1.5.4.0 may allow a privileged user to potentially enable denial of service via local access.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0006](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0006) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-0006.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-0006.svg)


## CVE-2021-0002
 Improper conditions check in some Intel(R) Ethernet Controllers 800 series Linux drivers before version 1.4.11 may allow an authenticated user to potentially enable information disclosure or denial of service via local access.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0002](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-0002) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-0002.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-0002.svg)


## CVE-2020-36281
 Leptonica before 1.80.0 allows a heap-based buffer over-read in pixFewColorsOctcubeQuantMixed in colorquant1.c.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-36281](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-36281) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-36281.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-36281.svg)


## CVE-2020-36280
 Leptonica before 1.80.0 allows a heap-based buffer over-read in pixReadFromTiffStream, related to tiffio.c.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-36280](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-36280) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-36280.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-36280.svg)


## CVE-2020-36279
 Leptonica before 1.80.0 allows a heap-based buffer over-read in rasteropGeneralLow, related to adaptmap_reg.c and adaptmap.c.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-36279](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-36279) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-36279.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-36279.svg)


## CVE-2020-36278
 Leptonica before 1.80.0 allows a heap-based buffer over-read in findNextBorderPixel in ccbord.c.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-36278](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-36278) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-36278.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-36278.svg)


## CVE-2020-36277
 Leptonica before 1.80.0 allows a denial of service (application crash) via an incorrect left shift in pixConvert2To8 in pixconv.c.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-36277](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-36277) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-36277.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-36277.svg)


## CVE-2020-36193
 Tar.php in Archive_Tar through 1.4.11 allows write operations with Directory Traversal due to inadequate checking of symbolic links, a related issue to CVE-2020-28948.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32610](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-32610) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-32610.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-32610.svg)


## CVE-2020-28589
 An improper array index validation vulnerability exists in the LoadObj functionality of tinyobjloader v2.0-rc1 and tinyobjloader development commit 79d4421. A specially crafted file could lead to code execution. An attacker can provide a malicious file to trigger this vulnerability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-28589](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-28589) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-28589.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-28589.svg)


## CVE-2020-28480
 The package jointjs before 3.3.0 are vulnerable to Prototype Pollution via util.setByPath (https://resources.jointjs.com/docs/jointjs/v3.2/joint.htmlutil.setByPath). The path used the access the object's key and set the value is not properly sanitized, leading to a Prototype Pollution.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-23444](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-23444) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-23444.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-23444.svg)


## CVE-2020-28220
 A CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer vulnerability exists in Modicon M258 Firmware (All versions prior to V5.0.4.11) and SoMachine/SoMachine Motion software (All versions), that could cause a buffer overflow when the length of a file transferred to the webserver is not verified.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-28220](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-28220) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-28220.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-28220.svg)


## CVE-2020-28214
 A CWE-760: Use of a One-Way Hash with a Predictable Salt vulnerability exists in Modicon M221 (all references, all versions), that could allow an attacker to pre-compute the hash value using dictionary attack technique such as rainbow tables, effectively disabling the protection that an unpredictable salt would provide.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-28214](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-28214) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-28214.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-28214.svg)


## CVE-2020-28020
 Exim 4 before 4.92 allows Integer Overflow to Buffer Overflow, in which an unauthenticated remote attacker can execute arbitrary code by leveraging the mishandling of continuation lines during header-length restriction.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-28020](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-28020) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-28020.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-28020.svg)


## CVE-2020-27942
 A logic issue was addressed with improved state management. This issue is fixed in Security Update 2021-002 Catalina, Security Update 2021-003 Mojave. Processing a maliciously crafted font file may lead to arbitrary code execution.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-27942](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-27942) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-27942.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-27942.svg)


## CVE-2020-27339
 In the kernel in Insyde InsydeH2O 5.x, certain SMM drivers did not correctly validate the CommBuffer and CommBufferSize parameters, allowing callers to corrupt either the firmware or the OS memory. The fixed versions for this issue in the AhciBusDxe, IdeBusDxe, NvmExpressDxe, SdHostDriverDxe, and SdMmcDeviceDxe drivers are 05.16.25, 05.26.25, 05.35.25, 05.43.25, and 05.51.25 (for Kernel 5.1 through 5.5).

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-27339](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-27339) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-27339.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-27339.svg)


## CVE-2020-27153
 In BlueZ before 5.55, a double free was found in the gatttool disconnect_cb() routine from shared/att.c. A remote attacker could potentially cause a denial of service or code execution, during service discovery, due to a redundant disconnect MGMT event.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-27153](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-27153) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-27153.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-27153.svg)


## CVE-2020-26558
 Bluetooth LE and BR/EDR secure pairing in Bluetooth Core Specification 2.1 through 5.2 may permit a nearby man-in-the-middle attacker to identify the Passkey used during pairing (in the Passkey authentication procedure) by reflection of the public key and the authentication evidence of the initiating device, potentially permitting this attacker to complete authenticated pairing with the responding device using the correct Passkey for the pairing session. The attack methodology determines the Passkey value one bit at a time.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-26558](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-26558) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-26558.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-26558.svg)


## CVE-2020-26556
 Mesh Provisioning in the Bluetooth Mesh profile 1.0 and 1.0.1 may permit a nearby device, able to conduct a successful brute-force attack on an insufficiently random AuthValue before the provisioning procedure times out, to complete authentication by leveraging Malleable Commitment.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-26556](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-26556) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-26556.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-26556.svg)


## CVE-2020-26301
 ssh2 is client and server modules written in pure JavaScript for node.js. In ssh2 before version 1.4.0 there is a command injection vulnerability. The issue only exists on Windows. This issue may lead to remote code execution if a client of the library calls the vulnerable method with untrusted input. This is fixed in version 1.4.0.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-26301](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-26301) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-26301.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-26301.svg)


## CVE-2020-26181
 Dell EMC Isilon OneFS versions 8.1 and later and Dell EMC PowerScale OneFS version 9.0.0 contain a privilege escalation vulnerability on a SmartLock Compliance mode cluster. The compadmin user connecting using ISI PRIV LOGIN SSH or ISI PRIV LOGIN CONSOLE can elevate privileges to the root user if they have ISI PRIV HARDENING privileges.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-26181](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-26181) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-26181.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-26181.svg)


## CVE-2020-25901
 Host Header Injection in Spiceworks 7.5.7.0 allowing the attacker to render arbitrary links that point to a malicious website with poisoned Host header webpages.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-25901](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-25901) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-25901.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-25901.svg)


## CVE-2020-25649
 A flaw was found in FasterXML Jackson Databind, where it did not have entity expansion secured properly. This flaw allows vulnerability to XML external entity (XXE) attacks. The highest threat from this vulnerability is data integrity.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-25649](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-25649) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-25649.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-25649.svg)


## CVE-2020-24574
 The client (aka GalaxyClientService.exe) in GOG GALAXY through 2.0.41 (as of 12:58 AM Eastern, 9/26/21) allows local privilege escalation from any authenticated user to SYSTEM by instructing the Windows service to execute arbitrary commands. This occurs because the attacker can inject a DLL into GalaxyClient.exe, defeating the TCP-based &quot;trusted client&quot; protection mechanism.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-24574](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-24574) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-24574.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-24574.svg)


## CVE-2020-24512
 Observable timing discrepancy in some Intel(R) Processors may allow an authenticated user to potentially enable information disclosure via local access.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-24512](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-24512) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-24512.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-24512.svg)


## CVE-2020-24511
 Improper isolation of shared resources in some Intel(R) Processors may allow an authenticated user to potentially enable information disclosure via local access.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-24511](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-24511) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-24511.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-24511.svg)


## CVE-2020-24327
 Server Side Request Forgery (SSRF) vulnerability exists in Discourse 2.3.2 and 2.6 via the email function. When writing an email in an editor, you can upload pictures of remote websites.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-24327](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-24327) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-24327.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-24327.svg)


## CVE-2020-23659
 WebPort-v1.19.17121 is affected by Cross Site Scripting (XSS) on the &quot;connections&quot; feature.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-23659](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-23659) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-23659.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-23659.svg)


## CVE-2020-23481
 CMS Made Simple 2.2.14 was discovered to contain a cross-site scripting (XSS) vulnerability which allows attackers to execute arbitrary web scripts or HTML via a crafted payload in the Field Definition text field.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-23481](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-23481) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-23481.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-23481.svg)


## CVE-2020-23478
 Leo Editor v6.2.1 was discovered to contain a regular expression denial of service (ReDoS) vulnerability in the component plugins/importers/dart.py.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-23478](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-23478) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-23478.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-23478.svg)


## CVE-2020-23273
 Heap-buffer overflow in the randomize_iparp function in edit_packet.c. of Tcpreplay v4.3.2 allows attackers to cause a denial of service (DOS) via a crafted pcap.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-23273](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-23273) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-23273.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-23273.svg)


## CVE-2020-23269
 An issue was discovered in gpac 0.8.0. The stbl_GetSampleSize function in isomedia/stbl_read.c has a heap-based buffer overflow which can lead to a denial of service (DOS) via a crafted media file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-23269](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-23269) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-23269.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-23269.svg)


## CVE-2020-23267
 An issue was discovered in gpac 0.8.0. The gf_hinter_track_process function in isom_hinter_track_process.c has a heap-based buffer overflow which can lead to a denial of service (DOS) via a crafted media file

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-23267](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-23267) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-23267.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-23267.svg)


## CVE-2020-23266
 An issue was discovered in gpac 0.8.0. The OD_ReadUTF8String function in odf_code.c has a heap-based buffer overflow which can lead to a denial of service (DOS) via a crafted media file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-23266](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-23266) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-23266.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-23266.svg)


## CVE-2020-21936
 An issue in HNAP1/GetMultipleHNAPs of Motorola CX2 router CX 1.0.2 Build 20190508 Rel.97360n allows attackers to access the components GetStationSettings, GetWebsiteFilterSettings and GetNetworkSettings without authentication.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21936](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21936) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21936.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21936.svg)


## CVE-2020-21913
 International Components for Unicode (ICU-20850) v66.1 was discovered to contain a use after free bug in the pkg_createWithAssemblyCode function in the file tools/pkgdata/pkgdata.cpp.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21913](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21913) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21913.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21913.svg)


## CVE-2020-21787
 CRMEB 3.1.0+ is vulnerable to File Upload Getshell via /crmeb/crmeb/services/UploadService.php.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21787](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21787) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21787.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21787.svg)


## CVE-2020-21784
 phpwcms 1.9.13 is vulnerable to Code Injection via /phpwcms/setup/setup.php.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21784](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21784) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21784.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21784.svg)


## CVE-2020-21676
 A stack-based buffer overflow in the genpstrx_text() component in genpstricks.c of fig2dev 3.2.7b allows attackers to cause a denial of service (DOS) via converting a xfig file into pstricks format.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21676](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21676) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21676.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21676.svg)


## CVE-2020-21675
 A stack-based buffer overflow in the genptk_text component in genptk.c of fig2dev 3.2.7b allows attackers to cause a denial of service (DOS) via converting a xfig file into ptk format.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21675](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21675) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21675.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21675.svg)


## CVE-2020-21606
 libde265 v1.0.4 contains a heap buffer overflow fault in the put_epel_16_fallback function, which can be exploited via a crafted a file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21606](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21606) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21606.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21606.svg)


## CVE-2020-21605
 libde265 v1.0.4 contains a segmentation fault in the apply_sao_internal function, which can be exploited via a crafted a file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21605](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21605) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21605.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21605.svg)


## CVE-2020-21604
 libde265 v1.0.4 contains a heap buffer overflow fault in the _mm_loadl_epi64 function, which can be exploited via a crafted a file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21604](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21604) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21604.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21604.svg)


## CVE-2020-21603
 libde265 v1.0.4 contains a heap buffer overflow in the put_qpel_0_0_fallback_16 function, which can be exploited via a crafted a file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21603](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21603) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21603.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21603.svg)


## CVE-2020-21602
 libde265 v1.0.4 contains a heap buffer overflow in the put_weighted_bipred_16_fallback function, which can be exploited via a crafted a file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21602](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21602) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21602.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21602.svg)


## CVE-2020-21601
 libde265 v1.0.4 contains a stack buffer overflow in the put_qpel_fallback function, which can be exploited via a crafted a file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21601](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21601) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21601.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21601.svg)


## CVE-2020-21600
 libde265 v1.0.4 contains a heap buffer overflow in the put_weighted_pred_avg_16_fallback function, which can be exploited via a crafted a file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21600](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21600) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21600.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21600.svg)


## CVE-2020-21599
 libde265 v1.0.4 contains a heap buffer overflow in the de265_image::available_zscan function, which can be exploited via a crafted a file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21599](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21599) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21599.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21599.svg)


## CVE-2020-21598
 libde265 v1.0.4 contains a heap buffer overflow in the ff_hevc_put_unweighted_pred_8_sse function, which can be exploited via a crafted a file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21598](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21598) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21598.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21598.svg)


## CVE-2020-21597
 libde265 v1.0.4 contains a heap buffer overflow in the mc_chroma function, which can be exploited via a crafted a file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21597](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21597) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21597.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21597.svg)


## CVE-2020-21596
 libde265 v1.0.4 contains a global buffer overflow in the decode_CABAC_bit function, which can be exploited via a crafted a file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21596](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21596) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21596.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21596.svg)


## CVE-2020-21595
 libde265 v1.0.4 contains a heap buffer overflow in the mc_luma function, which can be exploited via a crafted a file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21595](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21595) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21595.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21595.svg)


## CVE-2020-21594
 libde265 v1.0.4 contains a heap buffer overflow in the put_epel_hv_fallback function, which can be exploited via a crafted a file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21594](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21594) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21594.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21594.svg)


## CVE-2020-21564
 An issue was discovered in Pluck CMS 4.7.10-dev2 and 4.7.11. There is a file upload vulnerability that can cause a remote command execution via admin.php?action=files.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21564](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21564) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21564.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21564.svg)


## CVE-2020-21548
 Libsixel 1.8.3 contains a heap-based buffer overflow in the sixel_encode_highcolor function in tosixel.c.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21548](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21548) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21548.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21548.svg)


## CVE-2020-21547
 Libsixel 1.8.2 contains a heap-based buffer overflow in the dither_func_fs function in tosixel.c.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21547](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21547) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21547.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21547.svg)


## CVE-2020-21535
 fig2dev 3.2.7b contains a segmentation fault in the gencgm_start function in gencgm.c.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21535](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21535) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21535.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21535.svg)


## CVE-2020-21534
 fig2dev 3.2.7b contains a global buffer overflow in the get_line function in read.c.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21534](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21534) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21534.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21534.svg)


## CVE-2020-21533
 fig2dev 3.2.7b contains a stack buffer overflow in the read_textobject function in read.c.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21533](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21533) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21533.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21533.svg)


## CVE-2020-21532
 fig2dev 3.2.7b contains a global buffer overflow in the setfigfont function in genepic.c.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21532](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21532) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21532.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21532.svg)


## CVE-2020-21531
 fig2dev 3.2.7b contains a global buffer overflow in the conv_pattern_index function in gencgm.c.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21531](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21531) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21531.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21531.svg)


## CVE-2020-21530
 fig2dev 3.2.7b contains a segmentation fault in the read_objects function in read.c.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21530](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21530) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21530.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21530.svg)


## CVE-2020-21529
 fig2dev 3.2.7b contains a stack buffer overflow in the bezier_spline function in genepic.c.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21529](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21529) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21529.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21529.svg)


## CVE-2020-21483
 An arbitrary file upload vulnerability in Jizhicms v1.5 allows attackers to execute arbitrary code via a crafted .jpg file which is later changed to a PHP file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21483](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21483) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21483.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21483.svg)


## CVE-2020-21482
 A cross-site scripting (XSS) vulnerability in RGCMS v1.06 allows attackers to obtain the administrator's cookie via a crafted payload in the Name field under the Message Board module

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21482](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21482) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21482.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21482.svg)


## CVE-2020-21481
 An arbitrary file upload vulnerability in RGCMS v1.06 allows attackers to execute arbitrary code via a crafted .txt file which is later changed to a PHP file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21481](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21481) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21481.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21481.svg)


## CVE-2020-21480
 An arbitrary file write vulnerability in RGCMS v1.06 allows attackers to execute arbitrary code via a crafted PHP file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21480](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21480) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21480.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21480.svg)


## CVE-2020-21468
 ** DISPUTED ** A segmentation fault in the redis-server component of Redis 5.0.7 leads to a denial of service (DOS). NOTE: the vendor cannot reproduce this issue in a released version, such as 5.0.7.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21468](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21468) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21468.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21468.svg)


## CVE-2020-21322
 An arbitrary file upload vulnerability in Feehi CMS v2.0.8 and below allows attackers to execute arbitrary code via a crafted PHP file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21322](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21322) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21322.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21322.svg)


## CVE-2020-21321
 emlog v6.0 contains a Cross-Site Request Forgery (CSRF) via /admin/link.php?action=addlink, which allows attackers to arbitrarily add articles.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21321](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21321) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21321.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21321.svg)


## CVE-2020-21125
 An arbitrary file creation vulnerability in UReport 2.2.9 allows attackers to execute arbitrary code.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21125](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21125) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21125.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21125.svg)


## CVE-2020-21124
 UReport 2.2.9 allows attackers to execute arbitrary code due to a lack of access control to the designer page.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21124](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21124) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21124.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21124.svg)


## CVE-2020-21122
 UReport v2.2.9 contains a Server-Side Request Forgery (SSRF) in the designer page which allows attackers to detect intranet device ports.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21122](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21122) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21122.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21122.svg)


## CVE-2020-21121
 Pligg CMS 2.0.2 contains a time-based SQL injection vulnerability via the $recordIDValue parameter in the admin_update_module_widgets.php file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21121](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-21121) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-21121.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-21121.svg)


## CVE-2020-20902
 A CWE-125: Out-of-bounds read vulnerability exists in long_term_filter function in g729postfilter.c in FFmpeg 4.2.1 during computation of the denominator of pseudo-normalized correlation R'(0), that could result in disclosure of information.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20902](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20902) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-20902.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-20902.svg)


## CVE-2020-20799
 JeeCMS 1.0.1 contains a stored cross-site scripting (XSS) vulnerability which allows attackers to execute arbitrary web scripts or HTML via a crafted payload in the commentText parameter.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20799](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20799) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-20799.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-20799.svg)


## CVE-2020-20797
 FlameCMS 3.3.5 contains a time-based blind SQL injection vulnerability in /account/register.php.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20797](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20797) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-20797.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-20797.svg)


## CVE-2020-20796
 FlameCMS 3.3.5 contains a SQL injection vulnerability in /master/article.php via the &quot;Id&quot; parameter.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20796](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20796) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-20796.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-20796.svg)


## CVE-2020-20781
 A stored cross-site scripting (XSS) vulnerability in /ucms/index.php?do=list_edit of UCMS 1.4.7 allows attackers to execute arbitrary web scripts or HTML via a crafted payload in the title, key words, description or content text fields.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20781](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20781) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-20781.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-20781.svg)


## CVE-2020-20696
 A cross-site scripting (XSS) vulnerability in /admin/content/post of GilaCMS v1.11.4 allows attackers to execute arbitrary web scripts or HTML via a crafted payload in the Tags field.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20696](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20696) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-20696.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-20696.svg)


## CVE-2020-20695
 A stored cross-site scripting (XSS) vulnerability in GilaCMS v1.11.4 allows attackers to execute arbitrary web scripts or HTML via a crafted SVG file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20695](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20695) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-20695.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-20695.svg)


## CVE-2020-20693
 A Cross-Site Request Forgery (CSRF) in GilaCMS v1.11.4 allows authenticated attackers to arbitrarily add administrator accounts.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20693](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20693) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-20693.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-20693.svg)


## CVE-2020-20692
 GilaCMS v1.11.4 was discovered to contain a SQL injection vulnerability via the $_GET parameter in /src/core/controllers/cm.php.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20692](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20692) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-20692.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-20692.svg)


## CVE-2020-20665
 rudp v0.6 was discovered to contain a memory leak in the component main.c.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20665](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20665) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-20665.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-20665.svg)


## CVE-2020-20664
 libiec_iccp_mod v1.5 contains a segmentation violation in the component server_example1.c.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20664](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20664) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-20664.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-20664.svg)


## CVE-2020-20663
 libiec_iccp_mod v1.5 contains a heap-buffer-overflow in the component mms_client_connection.c.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20663](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20663) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-20663.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-20663.svg)


## CVE-2020-20662
 libiec_iccp_mod v1.5 contains a heap-buffer-overflow in the component mms_client_example1.c.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20662](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20662) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-20662.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-20662.svg)


## CVE-2020-20514
 A Cross-Site Request Forgery (CSRF) in Maccms v10 via admin.php/admin/admin/del/ids/&lt;id&gt;.html allows authenticated attackers to delete all users.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20514](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20514) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-20514.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-20514.svg)


## CVE-2020-20508
 Shopkit v2.7 contains a reflective cross-site scripting (XSS) vulnerability in the /account/register component, which allows attackers to hijack user credentials via a crafted payload in the E-Mail text field.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20508](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20508) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-20508.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-20508.svg)


## CVE-2020-20131
 LaraCMS v1.0.1 contains a stored cross-site scripting (XSS) vulnerability which allows atackers to execute arbitrary web scripts or HTML via a crafted payload in the page management module.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20131](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20131) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-20131.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-20131.svg)


## CVE-2020-20129
 LaraCMS v1.0.1 contains a stored cross-site scripting (XSS) vulnerability which allows attackers to execute arbitrary web scripts or HTML via a crafted payload in the content editor.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20129](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20129) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-20129.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-20129.svg)


## CVE-2020-20128
 LaraCMS v1.0.1 transmits sensitive information in cleartext which can be intercepted by attackers.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20128](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-20128) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-20128.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-20128.svg)


## CVE-2020-19951
 A cross-site request forgery (CSRF) in /controller/pay.class.php of YzmCMS v5.5 allows attackers to access sensitive components of the application.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-19951](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-19951) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-19951.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-19951.svg)


## CVE-2020-19950
 A cross-site scripting (XSS) vulnerability in the /banner/add.html component of YzmCMS v5.3 allows attackers to execute arbitrary web scripts or HTML.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-19950](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-19950) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-19950.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-19950.svg)


## CVE-2020-19949
 A cross-site scripting (XSS) vulnerability in the /link/add.html component of YzmCMS v5.3 allows attackers to execute arbitrary web scripts or HTML.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-19949](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-19949) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-19949.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-19949.svg)


## CVE-2020-19915
 Cross Site Scripting (XSS vulnerability exists in WUZHI CMS 4.1.0 via the mailbox username in index.php.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-19915](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-19915) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-19915.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-19915.svg)


## CVE-2020-19822
 A remote code execution (RCE) vulnerability in template_user.php of ZZCMS version 2018 allows attackers to execute arbitrary PHP code via the &quot;ml&quot; and &quot;title&quot; parameters.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-19822](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-19822) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-19822.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-19822.svg)


## CVE-2020-19554
 Cross Site Scripting (XSS) vulnerability exists in ManageEngine OPManager &lt;=12.5.174 when the API key contains an XML-based XSS payload.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-19554](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-19554) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-19554.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-19554.svg)


## CVE-2020-19553
 Cross Site Scripting (XSS) vlnerability exists in WUZHI CMS up to and including 4.1.0 in the config function in coreframe/app/attachment/libs/class/ckditor.class.php.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-19553](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-19553) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-19553.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-19553.svg)


## CVE-2020-19551
 Blacklist bypass issue exists in WUZHI CMS up to and including 4.1.0 in common.func.php, which when uploaded can cause remote code executiong.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-19551](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-19551) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-19551.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-19551.svg)


## CVE-2020-19144
 Buffer Overflow in LibTiff v4.0.10 allows attackers to cause a denial of service via the 'in _TIFFmemcpy' funtion in the component 'tif_unix.c'.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-19144](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-19144) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-19144.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-19144.svg)


## CVE-2020-19143
 Buffer Overflow in LibTiff v4.0.10 allows attackers to cause a denial of service via the &quot;TIFFVGetField&quot; funtion in the component 'libtiff/tif_dir.c'.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-19143](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-19143) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-19143.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-19143.svg)


## CVE-2020-18913
 EARCLINK ESPCMS-P8 was discovered to contain a SQL injection vulnerability in the espcms_web/Search.php component via the attr_array parameter. This vulnerability allows attackers to access sensitive database information.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-18913](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-18913) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-18913.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-18913.svg)


## CVE-2020-18685
 Floodlight through 1.2 has poor input validation in checkFlow in StaticFlowEntryPusherResource.java because of unchecked prerequisites related to TCP or UDP ports, or group or table IDs.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-18685](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-18685) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-18685.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-18685.svg)


## CVE-2020-18683
 Floodlight through 1.2 has poor input validation in checkFlow in StaticFlowEntryPusherResource.java because of undefined fields mishandling.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-18683](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-18683) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-18683.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-18683.svg)


## CVE-2020-15744
 Stack-based Buffer Overflow vulnerability in the ONVIF server component of Victure PC420 smart camera allows an attacker to execute remote code on the target device. This issue affects: Victure PC420 firmware version 1.2.2 and prior versions.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-15744](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-15744) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-15744.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-15744.svg)


## CVE-2020-15705
 GRUB2 fails to validate kernel signature when booted directly without shim, allowing secure boot to be bypassed. This only affects systems where the kernel signing certificate has been imported directly into the secure boot database and the GRUB image is booted directly without the use of shim. This issue affects GRUB2 version 2.04 and prior versions.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-15705](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-15705) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-15705.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-15705.svg)


## CVE-2020-15256
 A prototype pollution vulnerability has been found in `object-path` &lt;= 0.11.4 affecting the `set()` method. The vulnerability is limited to the `includeInheritedProps` mode (if version &gt;= 0.11.0 is used), which has to be explicitly enabled by creating a new instance of `object-path` and setting the option `includeInheritedProps: true`, or by using the default `withInheritedProps` instance. The default operating mode is not affected by the vulnerability if version &gt;= 0.11.0 is used. Any usage of `set()` in versions &lt; 0.11.0 is vulnerable. The issue is fixed in object-path version 0.11.5 As a workaround, don't use the `includeInheritedProps: true` options or the `withInheritedProps` instance if using a version &gt;= 0.11.0.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-23434](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-23434) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-23434.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-23434.svg)


## CVE-2020-15250
 In JUnit4 from version 4.7 and before 4.13.1, the test rule TemporaryFolder contains a local information disclosure vulnerability. On Unix like systems, the system's temporary directory is shared between all users on that system. Because of this, when files and directories are written into this directory they are, by default, readable by other users on that same system. This vulnerability does not allow other users to overwrite the contents of these directories or files. This is purely an information disclosure vulnerability. This vulnerability impacts you if the JUnit tests write sensitive information, like API keys or passwords, into the temporary folder, and the JUnit tests execute in an environment where the OS has other untrusted users. Because certain JDK file system APIs were only added in JDK 1.7, this this fix is dependent upon the version of the JDK you are using. For Java 1.7 and higher users: this vulnerability is fixed in 4.13.1. For Java 1.6 and lower users: no patch is available, you must use the workaround below. If you are unable to patch, or are stuck running on Java 1.6, specifying the `java.io.tmpdir` system environment variable to a directory that is exclusively owned by the executing user will fix this vulnerability. For more information, including an example of vulnerable code, see the referenced GitHub Security Advisory.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-15250](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-15250) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-15250.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-15250.svg)


## CVE-2020-14410
 SDL (Simple DirectMedia Layer) through 2.0.12 has a heap-based buffer over-read in Blit_3or4_to_3or4__inversed_rgb in video/SDL_blit_N.c via a crafted .BMP file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-14410](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-14410) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-14410.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-14410.svg)


## CVE-2020-14409
 SDL (Simple DirectMedia Layer) through 2.0.12 has an Integer Overflow (and resultant SDL_memcpy heap corruption) in SDL_BlitCopy in video/SDL_blit_copy.c via a crafted .BMP file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-14409](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-14409) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-14409.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-14409.svg)


## CVE-2020-14386
 A flaw was found in the Linux kernel before 5.9-rc4. Memory corruption can be exploited to gain root privileges from unprivileged processes. The highest threat from this vulnerability is to data confidentiality and integrity.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-14386](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-14386) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-14386.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-14386.svg)


## CVE-2020-14365
 A flaw was found in the Ansible Engine, in ansible-engine 2.8.x before 2.8.15 and ansible-engine 2.9.x before 2.9.13, when installing packages using the dnf module. GPG signatures are ignored during installation even when disable_gpg_check is set to False, which is the default behavior. This flaw leads to malicious packages being installed on the system and arbitrary code executed via package installation scripts. The highest threat from this vulnerability is to integrity and system availability.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-14365](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-14365) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-14365.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-14365.svg)


## CVE-2020-14343
 A vulnerability was discovered in the PyYAML library in versions before 5.4, where it is susceptible to arbitrary code execution when it processes untrusted YAML files through the full_load method or with the FullLoader loader. Applications that use the library to process untrusted input may be vulnerable to this flaw. This flaw allows an attacker to execute arbitrary code on the system by abusing the python/object/new constructor. This flaw is due to an incomplete fix for CVE-2020-1747.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-14343](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-14343) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-14343.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-14343.svg)


## CVE-2020-14332
 A flaw was found in the Ansible Engine when using module_args. Tasks executed with check mode (--check-mode) do not properly neutralize sensitive data exposed in the event data. This flaw allows unauthorized users to read this data. The highest threat from this vulnerability is to confidentiality.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-14332](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-14332) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-14332.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-14332.svg)


## CVE-2020-14330
 An Improper Output Neutralization for Logs flaw was found in Ansible when using the uri module, where sensitive data is exposed to content and json output. This flaw allows an attacker to access the logs or outputs of performed tasks to read keys used in playbooks from other users within the uri module. The highest threat from this vulnerability is to data confidentiality.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-14330](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-14330) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-14330.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-14330.svg)


## CVE-2020-14311
 There is an issue with grub2 before version 2.06 while handling symlink on ext filesystems. A filesystem containing a symbolic link with an inode size of UINT32_MAX causes an arithmetic overflow leading to a zero-sized memory allocation with subsequent heap-based buffer overflow.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-14311](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-14311) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-14311.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-14311.svg)


## CVE-2020-14308
 In grub2 versions before 2.06 the grub memory allocator doesn't check for possible arithmetic overflows on the requested allocation size. This leads the function to return invalid memory allocations which can be further used to cause possible integrity, confidentiality and availability impacts during the boot process.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-14308](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-14308) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-14308.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-14308.svg)


## CVE-2020-14124
 There is a buffer overflow in librsa.so called by getwifipwdurl interface, resulting in code execution on Xiaomi router AX3600 with ROM version =rom&lt; 1.1.12.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-14124](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-14124) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-14124.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-14124.svg)


## CVE-2020-14119
 There is command injection in the addMeshNode interface of xqnetwork.lua, which leads to command execution under administrator authority on Xiaomi router AX3600 with rom versionrom&lt; 1.1.12

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-14119](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-14119) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-14119.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-14119.svg)


## CVE-2020-13959
 The default error page for VelocityView in Apache Velocity Tools prior to 3.1 reflects back the vm file that was entered as part of the URL. An attacker can set an XSS payload file as this vm file in the URL which results in this payload being executed. XSS vulnerabilities allow attackers to execute arbitrary JavaScript in the context of the attacked website and the attacked user. This can be abused to steal session cookies, perform requests in the name of the victim or for phishing attacks.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-13959](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-13959) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-13959.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-13959.svg)


## CVE-2020-13949
 In Apache Thrift 0.9.3 to 0.13.0, malicious RPC clients could send short messages which would result in a large memory allocation, potentially leading to denial of service.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-13949](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-13949) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-13949.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-13949.svg)


## CVE-2020-13936
 An attacker that is able to modify Velocity templates may execute arbitrary Java code or run arbitrary system commands with the same privileges as the account running the Servlet container. This applies to applications that allow untrusted users to upload/modify velocity templates running Apache Velocity Engine versions up to 2.2.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-13936](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-13936) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-13936.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-13936.svg)


## CVE-2020-13929
 Authentication bypass vulnerability in Apache Zeppelin allows an attacker to bypass Zeppelin authentication mechanism to act as another user. This issue affects Apache Zeppelin Apache Zeppelin version 0.9.0 and prior versions.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-13929](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-13929) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-13929.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-13929.svg)


## CVE-2020-12083
 An elevated privileges issue related to Spring MVC calls impacts Code Insight v7.x releases up to and including 2020 R1 (7.11.0-64).

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-12083](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-12083) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-12083.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-12083.svg)


## CVE-2020-12082
 A stored cross-site scripting issue impacts certain areas of the Web UI for Code Insight v7.x releases up to and including 2020 R1 (7.11.0-64).

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-12082](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-12082) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-12082.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-12082.svg)


## CVE-2020-12080
 A Denial of Service vulnerability has been identified in FlexNet Publisher's lmadmin.exe version 11.16.6. A certain message protocol can be exploited to cause lmadmin to crash.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-12080](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-12080) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-12080.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-12080.svg)


## CVE-2020-10729
 A flaw was found in the use of insufficiently random values in Ansible. Two random password lookups of the same length generate the equal value as the template caching action for the same file since no re-evaluation happens. The highest threat from this vulnerability would be that all passwords are exposed at once for the file. This flaw affects Ansible Engine versions before 2.9.6.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-10729](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-10729) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-10729.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-10729.svg)


## CVE-2020-10685
 A flaw was found in Ansible Engine affecting Ansible Engine versions 2.7.x before 2.7.17 and 2.8.x before 2.8.11 and 2.9.x before 2.9.7 as well as Ansible Tower before and including versions 3.4.5 and 3.5.5 and 3.6.3 when using modules which decrypts vault files such as assemble, script, unarchive, win_copy, aws_s3 or copy modules. The temporary directory is created in /tmp leaves the s ts unencrypted. On Operating Systems which /tmp is not a tmpfs but part of the root partition, the directory is only cleared on boot and the decryp emains when the host is switched off. The system will be vulnerable when the system is not running. So decrypted data must be cleared as soon as possible and the data which normally is encrypted ble.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-10685](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-10685) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-10685.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-10685.svg)


## CVE-2020-10684
 A flaw was found in Ansible Engine, all versions 2.7.x, 2.8.x and 2.9.x prior to 2.7.17, 2.8.9 and 2.9.6 respectively, when using ansible_facts as a subkey of itself and promoting it to a variable when inject is enabled, overwriting the ansible_facts after the clean. An attacker could take advantage of this by altering the ansible_facts, such as ansible_hosts, users and any other key data which would lead into privilege escalation or code injection.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-10684](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-10684) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-10684.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-10684.svg)


## CVE-2020-9760
 An issue was discovered in WeeChat before 2.7.1 (0.3.4 to 2.7 are affected). When a new IRC message 005 is received with longer nick prefixes, a buffer overflow and possibly a crash can happen when a new mode is set for a nick.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-9760](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-9760) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-9760.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-9760.svg)


## CVE-2020-9759
 A Vulnerability of LG Electronic web OS TV Emulator could allow an attacker to escalate privileges and overwrite certain files. This vulnerability is due to wrong environment setting. An attacker could exploit this vulnerability through crafted configuration files and executable files.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-9759](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-9759) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-9759.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-9759.svg)


## CVE-2020-9281
 A cross-site scripting (XSS) vulnerability in the HTML Data Processor for CKEditor 4.0 before 4.14 allows remote attackers to inject arbitrary web script through a crafted &quot;protected&quot; comment (with the cke_protected syntax).

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-9281](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-9281) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-9281.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-9281.svg)


## CVE-2020-8955
 irc_mode_channel_update in plugins/irc/irc-mode.c in WeeChat through 2.7 allows remote attackers to cause a denial of service (buffer overflow and application crash) or possibly have unspecified other impact via a malformed IRC message 324 (channel mode).

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-8955](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-8955) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-8955.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-8955.svg)


## CVE-2020-8561
 A security issue was discovered in Kubernetes where actors that control the responses of MutatingWebhookConfiguration or ValidatingWebhookConfiguration requests are able to redirect kube-apiserver requests to private networks of the apiserver. If that user can view kube-apiserver logs when the log level is set to 10, they can view the redirected responses and headers in the logs.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-8561](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-8561) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-8561.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-8561.svg)


## CVE-2020-7566
 A CWE-334: Small Space of Random Values vulnerability exists in Modicon M221 (all references, all versions) that could allow the attacker to break the encryption keys when the attacker has captured the traffic between EcoStruxure Machine - Basic software and Modicon M221 controller.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-7566](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-7566) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-7566.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-7566.svg)


## CVE-2020-7565
 A CWE-326: Inadequate Encryption Strength vulnerability exists in Modicon M221 (all references, all versions) that could allow the attacker to break the encryption key when the attacker has captured the traffic between EcoStruxure Machine - Basic software and Modicon M221 controller.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-7565](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-7565) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-7565.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-7565.svg)


## CVE-2020-7524
 Out-of-bounds Write vulnerability exists in Modicon M218 Logic Controller (V5.0.0.7 and prior) which could cause Denial of Service when sending specific crafted IPV4 packet to the controller: Sending a specific IPv4 protocol package to Schneider Electric Modicon M218 Logic Controller can cause IPv4 devices to go down. The device does not work properly and must be powered back on to return to normal.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-7524](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-7524) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-7524.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-7524.svg)


## CVE-2020-5398
 In Spring Framework, versions 5.2.x prior to 5.2.3, versions 5.1.x prior to 5.1.13, and versions 5.0.x prior to 5.0.16, an application is vulnerable to a reflected file download (RFD) attack when it sets a &quot;Content-Disposition&quot; header in the response where the filename attribute is derived from user supplied input.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-5398](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-5398) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-5398.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-5398.svg)


## CVE-2020-4944
 IBM UrbanCode Deploy (UCD) 7.0.3.0, 7.0.4.0, 7.0.5.3, 7.0.5.4, 7.1.0.0, 7.1.1.0, 7.1.1.1, and 7.1.1.2, stores keystore passwords in plain text after a manual edit, which can be read by a local user. IBM X-Force ID: 191944.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-4944](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-4944) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-4944.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-4944.svg)


## CVE-2020-4941
 IBM Edge 4.2 could reveal sensitive version information about the server from error pages that could aid an attacker in further attacks against the system. IBM X-Force ID: 191941.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-4941](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-4941) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-4941.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-4941.svg)


## CVE-2020-4809
 IBM Edge 4.2 allows web pages to be stored locally which can be read by another user on the system. IBM X-Force ID: 189633.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-4809](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-4809) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-4809.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-4809.svg)


## CVE-2020-4805
 IBM Edge 4.2 allows web pages to be stored locally which can be read by another user on the system. IBM X-Force ID: 189539.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-4805](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-4805) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-4805.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-4805.svg)


## CVE-2020-4803
 IBM Edge 4.2 allows web pages to be stored locally which can be read by another user on the system. IBM X-Force ID: 189535.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-4803](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-4803) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-4803.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-4803.svg)


## CVE-2020-4690
 IBM Security Guardium 11.3 contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data. IBM X-Force ID: 186697.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-4690](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-4690) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-4690.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-4690.svg)


## CVE-2020-3960
 VMware ESXi (6.7 before ESXi670-202006401-SG and 6.5 before ESXi650-202005401-SG), Workstation (15.x before 15.5.5), and Fusion (11.x before 11.5.5) contain an out-of-bounds read vulnerability in NVMe functionality. A malicious actor with local non-administrative access to a virtual machine with a virtual NVMe controller present may be able to read privileged information contained in physical memory.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3960](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3960) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3960.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3960.svg)


## CVE-2020-3477
 A vulnerability in the CLI parser of Cisco IOS Software and Cisco IOS XE Software could allow an authenticated, local attacker to access files from the flash: filesystem. The vulnerability is due to insufficient application of restrictions during the execution of a specific command. An attacker could exploit this vulnerability by using a specific command at the command line. A successful exploit could allow the attacker to obtain read-only access to files that are located on the flash: filesystem that otherwise might not have been accessible.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3477](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3477) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3477.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3477.svg)


## CVE-2020-3475
 Multiple vulnerabilities in the web management framework of Cisco IOS XE Software could allow an authenticated, remote attacker with read-only privileges to gain unauthorized read access to sensitive data or cause the web management software to hang or crash, resulting in a denial of service (DoS) condition. For more information about these vulnerabilities, see the Details section of this advisory.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3475](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3475) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3475.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3475.svg)


## CVE-2020-3472
 A vulnerability in the contacts feature of Cisco Webex Meetings could allow an authenticated, remote attacker with a legitimate user account to access sensitive information. The vulnerability is due to improper access restrictions on users who are added within user contacts. An attacker on one Webex Meetings site could exploit this vulnerability by sending specially crafted requests to the Webex Meetings site. A successful exploit could allow the attacker to view the details of users on another Webex site, including user names and email addresses.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3472](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3472) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3472.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3472.svg)


## CVE-2020-3471
 A vulnerability in Cisco Webex Meetings and Cisco Webex Meetings Server could allow an unauthenticated, remote attacker to maintain bidirectional audio despite being expelled from an active Webex session. The vulnerability is due to a synchronization issue between meeting and media services on a vulnerable Webex site. An attacker could exploit this vulnerability by sending crafted requests to a vulnerable Cisco Webex Meetings or Cisco Webex Meetings Server site. A successful exploit could allow the attacker to maintain the audio connection of a Webex session despite being expelled.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3471](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3471) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3471.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3471.svg)


## CVE-2020-3470
 Multiple vulnerabilities in the API subsystem of Cisco Integrated Management Controller (IMC) could allow an unauthenticated, remote attacker to execute arbitrary code with root privileges. The vulnerabilities are due to improper boundary checks for certain user-supplied input. An attacker could exploit these vulnerabilities by sending a crafted HTTP request to the API subsystem of an affected system. When this request is processed, an exploitable buffer overflow condition may occur. A successful exploit could allow the attacker to execute arbitrary code with root privileges on the underlying operating system (OS).

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3470](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3470) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3470.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3470.svg)


## CVE-2020-3465
 A vulnerability in Cisco IOS XE Software could allow an unauthenticated, adjacent attacker to cause a device to reload. The vulnerability is due to incorrect handling of certain valid, but not typical, Ethernet frames. An attacker could exploit this vulnerability by sending the Ethernet frames onto the Ethernet segment. A successful exploit could allow the attacker to cause the device to reload, resulting in a denial of service (DoS) condition.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3465](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3465) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3465.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3465.svg)


## CVE-2020-3453
 Multiple vulnerabilities in the web-based management interface of Cisco Small Business RV340 Series Routers could allow an authenticated, remote attacker with administrative credentials to execute arbitrary commands on the underlying operating system (OS) as a restricted user. For more information about these vulnerabilities, see the Details section of this advisory.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3453](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3453) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3453.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3453.svg)


## CVE-2020-3452
 A vulnerability in the web services interface of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to conduct directory traversal attacks and read sensitive files on a targeted system. The vulnerability is due to a lack of proper input validation of URLs in HTTP requests processed by an affected device. An attacker could exploit this vulnerability by sending a crafted HTTP request containing directory traversal character sequences to an affected device. A successful exploit could allow the attacker to view arbitrary files within the web services file system on the targeted device. The web services file system is enabled when the affected device is configured with either WebVPN or AnyConnect features. This vulnerability cannot be used to obtain access to ASA or FTD system files or underlying operating system (OS) files.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3452](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3452) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3452.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3452.svg)


## CVE-2020-3451
 Multiple vulnerabilities in the web-based management interface of Cisco Small Business RV340 Series Routers could allow an authenticated, remote attacker with administrative credentials to execute arbitrary commands on the underlying operating system (OS) as a restricted user. For more information about these vulnerabilities, see the Details section of this advisory.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3451](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3451) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3451.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3451.svg)


## CVE-2020-3444
 A vulnerability in the packet filtering features of Cisco SD-WAN Software could allow an unauthenticated, remote attacker to bypass L3 and L4 traffic filters. The vulnerability is due to improper traffic filtering conditions on an affected device. An attacker could exploit this vulnerability by crafting a malicious TCP packet with specific characteristics and sending it to a targeted device. A successful exploit could allow the attacker to bypass the L3 and L4 traffic filters and inject an arbitrary packet into the network.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3444](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3444) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3444.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3444.svg)


## CVE-2020-3441
 A vulnerability in Cisco Webex Meetings and Cisco Webex Meetings Server could allow an unauthenticated, remote attacker to view sensitive information from the meeting room lobby. This vulnerability is due to insufficient protection of sensitive participant information. An attacker could exploit this vulnerability by browsing the Webex roster. A successful exploit could allow the attacker to gather information about other Webex participants, such as email address and IP address, while waiting in the lobby.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3441](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3441) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3441.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3441.svg)


## CVE-2020-3435
 A vulnerability in the interprocess communication (IPC) channel of Cisco AnyConnect Secure Mobility Client for Windows could allow an authenticated, local attacker to overwrite VPN profiles on an affected device. To exploit this vulnerability, the attacker would need to have valid credentials on the Windows system. The vulnerability is due to insufficient validation of user-supplied input. An attacker could exploit this vulnerability by sending a crafted IPC message to the AnyConnect process on an affected device. A successful exploit could allow the attacker to modify VPN profile files. To exploit this vulnerability, the attacker would need to have valid credentials on the Windows system.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3435](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3435) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3435.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3435.svg)


## CVE-2020-3434
 A vulnerability in the interprocess communication (IPC) channel of Cisco AnyConnect Secure Mobility Client for Windows could allow an authenticated, local attacker to cause a denial of service (DoS) condition on an affected device. To exploit this vulnerability, the attacker would need to have valid credentials on the Windows system. The vulnerability is due to insufficient validation of user-supplied input. An attacker could exploit this vulnerability by sending a crafted IPC message to the AnyConnect process on an affected device. A successful exploit could allow the attacker to stop the AnyConnect process, causing a DoS condition on the device. To exploit this vulnerability, the attacker would need to have valid credentials on the Windows system.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3434](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3434) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3434.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3434.svg)


## CVE-2020-3429
 A vulnerability in the WPA2 and WPA3 security implementation of Cisco IOS XE Wireless Controller Software for the Cisco Catalyst 9000 Family could allow an unauthenticated, adjacent attacker to cause denial of service (DoS) condition on an affected device. The vulnerability is due to incorrect packet processing during the WPA2 and WPA3 authentication handshake when configured for dot1x or pre-shared key (PSK) authentication key management (AKM) with 802.11r BSS Fast Transition (FT) enabled. An attacker could exploit this vulnerability by sending a crafted authentication packet to an affected device. A successful exploit could cause an affected device to reload, resulting in a DoS condition.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3429](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3429) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3429.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3429.svg)


## CVE-2020-3426
 A vulnerability in the implementation of the Low Power, Wide Area (LPWA) subsystem of Cisco IOS Software for Cisco 800 Series Industrial Integrated Services Routers (Industrial ISRs) and Cisco 1000 Series Connected Grid Routers (CGR1000) could allow an unauthenticated, remote attacker to gain unauthorized read access to sensitive data or cause a denial of service (DoS) condition. The vulnerability is due to a lack of input and validation checking mechanisms for virtual-LPWA (VLPWA) protocol modem messages. An attacker could exploit this vulnerability by supplying crafted packets to an affected device. A successful exploit could allow the attacker to gain unauthorized read access to sensitive data or cause the VLPWA interface of the affected device to shut down, resulting in DoS condition.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3426](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3426) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3426.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3426.svg)


## CVE-2020-3398
 A vulnerability in the Border Gateway Protocol (BGP) Multicast VPN (MVPN) implementation of Cisco NX-OS Software could allow an unauthenticated, remote attacker to cause a BGP session to repeatedly reset, causing a partial denial of service (DoS) condition due to the BGP session being down. The vulnerability is due to incorrect parsing of a specific type of BGP MVPN update message. An attacker could exploit this vulnerability by sending this BGP MVPN update message to a targeted device. A successful exploit could allow the attacker to cause the BGP peer connections to reset, which could lead to BGP route instability and impact traffic. The incoming BGP MVPN update message is valid but is parsed incorrectly by the NX-OS device, which could send a corrupted BGP update to the configured BGP peer. Note: The Cisco implementation of BGP accepts incoming BGP traffic from only explicitly configured peers. To exploit this vulnerability, an attacker must send a specific BGP MVPN update message over an established TCP connection that appears to come from a trusted BGP peer. To do so, the attacker must obtain information about the BGP peers in the trusted network of the affected system.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3398](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3398) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3398.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3398.svg)


## CVE-2020-3391
 A vulnerability in Cisco Digital Network Architecture (DNA) Center could allow an authenticated, remote attacker to view sensitive information in clear text. The vulnerability is due to insecure storage of certain unencrypted credentials on an affected device. An attacker could exploit this vulnerability by viewing the network device configuration and obtaining credentials that they may not normally have access to. A successful exploit could allow the attacker to use those credentials to discover and manage network devices.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3391](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3391) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3391.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3391.svg)


## CVE-2020-3387
 A vulnerability in Cisco SD-WAN vManage Software could allow an authenticated, remote attacker to execute code with root privileges on an affected system. The vulnerability is due to insufficient input sanitization during user authentication processing. An attacker could exploit this vulnerability by sending a crafted response to the Cisco SD-WAN vManage Software. A successful exploit could allow the attacker to access the software and execute commands they should not be authorized to execute.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3387](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3387) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3387.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3387.svg)


## CVE-2020-3383
 A vulnerability in the archive utility of Cisco Data Center Network Manager (DCNM) could allow an authenticated, remote attacker to conduct directory traversal attacks on an affected device. The vulnerability is due to a lack of proper input validation of paths that are embedded within archive files. An attacker could exploit this vulnerability by sending a crafted request to an affected device. A successful exploit could allow the attacker to write arbitrary files in the system with the privileges of the logged-in user.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3383](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3383) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3383.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3383.svg)


## CVE-2020-3379
 A vulnerability in Cisco SD-WAN Solution Software could allow an authenticated, local attacker to elevate privileges to Administrator on the underlying operating system. The vulnerability is due to insufficient input validation. An attacker could exploit this vulnerability by sending a crafted request to an affected system. A successful exploit could allow the attacker to gain administrative privileges.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3379](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3379) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3379.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3379.svg)


## CVE-2020-3307
 A vulnerability in the web UI of Cisco Firepower Management Center (FMC) Software could allow an unauthenticated, remote attacker to write arbitrary entries to the log file on an affected device. The vulnerability is due to insufficient input validation. An attacker could exploit this vulnerability by sending a crafted HTTP request to an affected device. A successful exploit could allow the attacker to send incorrect information to the system log on the affected system.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3307](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3307) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3307.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3307.svg)


## CVE-2020-3304
 A vulnerability in the web interface of Cisco Adaptive Security Appliance (ASA) Software and Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to cause an affected device to reload unexpectedly, resulting in a denial of service (DoS) condition. The vulnerability is due to a lack of proper input validation of HTTP requests. An attacker could exploit this vulnerability by sending a crafted HTTP request to an affected device. An exploit could allow the attacker to cause a DoS condition. Note: This vulnerability applies to IP Version 4 (IPv4) and IP Version 6 (IPv6) HTTP traffic.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3304](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3304) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3304.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3304.svg)


## CVE-2020-3283
 A vulnerability in the Secure Sockets Layer (SSL)/Transport Layer Security (TLS) handler of Cisco Firepower Threat Defense (FTD) Software when running on the Cisco Firepower 1000 Series platform could allow an unauthenticated, remote attacker to trigger a denial of service (DoS) condition on an affected device. The vulnerability is due to a communication error between internal functions. An attacker could exploit this vulnerability by sending a crafted SSL/TLS message to an affected device. A successful exploit could allow the attacker to cause a buffer underrun, which leads to a crash. The crash causes the affected device to reload.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3283](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3283) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3283.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3283.svg)


## CVE-2020-3272
 A vulnerability in the DHCP server of Cisco Prime Network Registrar could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected device. The vulnerability is due to insufficient input validation of incoming DHCP traffic. An attacker could exploit this vulnerability by sending a crafted DHCP request to an affected device. A successful exploit could allow the attacker to cause a restart of the DHCP server process, causing a DoS condition.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3272](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3272) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3272.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3272.svg)


## CVE-2020-3263
 A vulnerability in Cisco Webex Meetings Desktop App could allow an unauthenticated, remote attacker to execute programs on an affected end-user system. The vulnerability is due to improper validation of input that is supplied to application URLs. The attacker could exploit this vulnerability by persuading a user to follow a malicious URL. A successful exploit could allow the attacker to cause the application to execute other programs that are already present on the end-user system. If malicious files are planted on the system or on an accessible network file path, the attacker could execute arbitrary code on the affected system.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3263](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3263) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3263.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3263.svg)


## CVE-2020-3259
 A vulnerability in the web services interface of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to retrieve memory contents on an affected device, which could lead to the disclosure of confidential information. The vulnerability is due to a buffer tracking issue when the software parses invalid URLs that are requested from the web services interface. An attacker could exploit this vulnerability by sending a crafted GET request to the web services interface. A successful exploit could allow the attacker to retrieve memory contents, which could lead to the disclosure of confidential information. Note: This vulnerability affects only specific AnyConnect and WebVPN configurations. For more information, see the Vulnerable Products section.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3259](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3259) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3259.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3259.svg)


## CVE-2020-3244
 A vulnerability in the Enhanced Charging Service (ECS) functionality of Cisco ASR 5000 Series Aggregation Services Routers could allow an unauthenticated, remote attacker to bypass the traffic classification rules on an affected device. The vulnerability is due to insufficient input validation of user traffic going through an affected device. An attacker could exploit this vulnerability by sending a malformed HTTP request to an affected device. A successful exploit could allow the attacker to bypass the traffic classification rules and potentially avoid being charged for traffic consumption.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3244](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3244) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3244.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3244.svg)


## CVE-2020-3242
 A vulnerability in the REST API of Cisco UCS Director could allow an authenticated, remote attacker with administrative privileges to obtain confidential information from an affected device. The vulnerability exists because confidential information is returned as part of an API response. An attacker could exploit this vulnerability by sending a crafted request to the API. A successful exploit could allow the attacker to obtain the API key of another user, which would allow the attacker to impersonate the account of that user on the affected device. To exploit this vulnerability, the attacker must have administrative privileges on the device.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3242](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3242) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3242.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3242.svg)


## CVE-2020-3238
 A vulnerability in the Cisco Application Framework component of the Cisco IOx application environment could allow an authenticated, remote attacker to write or modify arbitrary files in the virtual instance that is running on the affected device. The vulnerability is due to insufficient input validation of user-supplied application packages. An attacker who can upload a malicious package within Cisco IOx could exploit the vulnerability to modify arbitrary files. The impacts of a successful exploit are limited to the scope of the virtual instance and do not affect the device that is hosting Cisco IOx.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3238](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3238) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3238.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3238.svg)


## CVE-2020-3235
 A vulnerability in the Simple Network Management Protocol (SNMP) subsystem of Cisco IOS Software and Cisco IOS XE Software on Catalyst 4500 Series Switches could allow an authenticated, remote attacker to cause a denial of service (DoS) condition. The vulnerability is due to insufficient input validation when the software processes specific SNMP object identifiers. An attacker could exploit this vulnerability by sending a crafted SNMP packet to an affected device. A successful exploit could allow the attacker to cause the affected device to reload, resulting in a DoS condition. Note: To exploit this vulnerability by using SNMPv2c or earlier, the attacker must know the SNMP read-only community string for an affected system. To exploit this vulnerability by using SNMPv3, the attacker must know the user credentials for the affected system.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3235](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3235) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3235.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3235.svg)


## CVE-2020-3230
 A vulnerability in the Internet Key Exchange Version 2 (IKEv2) implementation in Cisco IOS Software and Cisco IOS XE Software could allow an unauthenticated, remote attacker to prevent IKEv2 from establishing new security associations. The vulnerability is due to incorrect handling of crafted IKEv2 SA-Init packets. An attacker could exploit this vulnerability by sending crafted IKEv2 SA-Init packets to the affected device. An exploit could allow the attacker to cause the affected device to reach the maximum incoming negotiation limits and prevent further IKEv2 security associations from being formed.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3230](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3230) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3230.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3230.svg)


## CVE-2020-3228
 A vulnerability in Security Group Tag Exchange Protocol (SXP) in Cisco IOS Software, Cisco IOS XE Software, and Cisco NX-OS Software could allow an unauthenticated, remote attacker to cause the affected device to reload, resulting in a denial of service (DoS) condition. The vulnerability exists because crafted SXP packets are mishandled. An attacker could exploit this vulnerability by sending specifically crafted SXP packets to the affected device. A successful exploit could allow the attacker to cause the affected device to reload, resulting in a DoS condition.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3228](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3228) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3228.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3228.svg)


## CVE-2020-3226
 A vulnerability in the Session Initiation Protocol (SIP) library of Cisco IOS Software and Cisco IOS XE Software could allow an unauthenticated, remote attacker to trigger a reload of an affected device, resulting in a denial of service (DoS) condition. The vulnerability is due to insufficient sanity checks on received SIP messages. An attacker could exploit this vulnerability by sending crafted SIP messages to an affected device. A successful exploit could allow the attacker to cause the affected device to reload, resulting in a denial of service condition.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3226](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3226) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3226.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3226.svg)


## CVE-2020-3225
 Multiple vulnerabilities in the implementation of the Common Industrial Protocol (CIP) feature of Cisco IOS Software and Cisco IOS XE Software could allow an unauthenticated, remote attacker to cause an affected device to reload, resulting in a denial of service (DoS) condition. The vulnerabilities are due to insufficient input processing of CIP traffic. An attacker could exploit these vulnerabilities by sending crafted CIP traffic to be processed by an affected device. A successful exploit could allow the attacker to cause the affected device to reload, resulting in a DoS condition.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3225](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3225) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3225.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3225.svg)


## CVE-2020-3221
 A vulnerability in the Flexible NetFlow Version 9 packet processor of Cisco IOS XE Software for Cisco Catalyst 9800 Series Wireless Controllers could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected device. The vulnerability is due to improper validation of parameters in a Flexible NetFlow Version 9 record. An attacker could exploit this vulnerability by sending a malformed Flexible NetFlow Version 9 packet to the Control and Provisioning of Wireless Access Points (CAPWAP) data port of an affected device. An exploit could allow the attacker to trigger an infinite loop, resulting in a process crash that would cause a reload of the device.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3221](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3221) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3221.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3221.svg)


## CVE-2020-3219
 A vulnerability in the web UI of Cisco IOS XE Software could allow an authenticated, remote attacker to inject and execute arbitrary commands with administrative privileges on the underlying operating system of an affected device. The vulnerability is due to insufficient validation of user-supplied input to the web UI. An attacker could exploit this vulnerability by submitting crafted input to the web UI. A successful exploit could allow an attacker to execute arbitrary commands with administrative privileges on an affected device.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3219](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3219) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3219.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3219.svg)


## CVE-2020-3218
 A vulnerability in the web UI of Cisco IOS XE Software could allow an authenticated, remote attacker with administrative privileges to execute arbitrary code with root privileges on the underlying Linux shell. The vulnerability is due to improper validation of user-supplied input. An attacker could exploit this vulnerability by first creating a malicious file on the affected device itself and then uploading a second malicious file to the device. A successful exploit could allow the attacker to execute arbitrary code with root privileges or bypass licensing requirements on the device.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3218](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3218) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3218.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3218.svg)


## CVE-2020-3217
 A vulnerability in the Topology Discovery Service of Cisco One Platform Kit (onePK) in Cisco IOS Software, Cisco IOS XE Software, Cisco IOS XR Software, and Cisco NX-OS Software could allow an unauthenticated, adjacent attacker to execute arbitrary code or cause a denial of service (DoS) condition on an affected device. The vulnerability is due to insufficient length restrictions when the onePK Topology Discovery Service parses Cisco Discovery Protocol messages. An attacker could exploit this vulnerability by sending a malicious Cisco Discovery Protocol message to an affected device. An exploit could allow the attacker to cause a stack overflow, which could allow the attacker to execute arbitrary code with administrative privileges, or to cause a process crash, which could result in a reload of the device and cause a DoS condition.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3217](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3217) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3217.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3217.svg)


## CVE-2020-3214
 A vulnerability in Cisco IOS XE Software could allow an authenticated, local attacker to escalate their privileges to a user with root-level privileges. The vulnerability is due to insufficient validation of user-supplied content. This vulnerability could allow an attacker to load malicious software onto an affected device.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3214](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3214) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3214.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3214.svg)


## CVE-2020-3206
 A vulnerability in the handling of IEEE 802.11w Protected Management Frames (PMFs) of Cisco Catalyst 9800 Series Wireless Controllers that are running Cisco IOS XE Software could allow an unauthenticated, adjacent attacker to terminate a valid user connection to an affected device. The vulnerability exists because the affected software does not properly validate 802.11w disassociation and deauthentication PMFs that it receives. An attacker could exploit this vulnerability by sending a spoofed 802.11w PMF from a valid, authenticated client on a network adjacent to an affected device. A successful exploit could allow the attacker to terminate a single valid user connection to the affected device.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3206](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3206) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3206.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3206.svg)


## CVE-2020-3204
 A vulnerability in the Tool Command Language (Tcl) interpreter of Cisco IOS Software and Cisco IOS XE Software could allow an authenticated, local attacker with privileged EXEC credentials to execute arbitrary code on the underlying operating system (OS) with root privileges. The vulnerability is due to insufficient input validation of data passed to the Tcl interpreter. An attacker could exploit this vulnerability by loading malicious Tcl code on an affected device. A successful exploit could allow the attacker to cause memory corruption or execute the code with root privileges on the underlying OS of the affected device.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3204](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-3204) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-3204.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-3204.svg)


## CVE-2020-1753
 A security flaw was found in Ansible Engine, all Ansible 2.7.x versions prior to 2.7.17, all Ansible 2.8.x versions prior to 2.8.11 and all Ansible 2.9.x versions prior to 2.9.7, when managing kubernetes using the k8s module. Sensitive parameters such as passwords and tokens are passed to kubectl from the command line, not using an environment variable or an input configuration file. This will disclose passwords and tokens from process list and no_log directive from debug module would not have any effect making these secrets being disclosed on stdout and log files.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-1753](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-1753) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-1753.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-1753.svg)


## CVE-2020-1747
 A vulnerability was discovered in the PyYAML library in versions before 5.3.1, where it is susceptible to arbitrary code execution when it processes untrusted YAML files through the full_load method or with the FullLoader loader. Applications that use the library to process untrusted input may be vulnerable to this flaw. An attacker could use this flaw to execute arbitrary code on the system by abusing the python/object/new constructor.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-14343](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-14343) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-14343.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-14343.svg)


## CVE-2020-1746
 A flaw was found in the Ansible Engine affecting Ansible Engine versions 2.7.x before 2.7.17 and 2.8.x before 2.8.11 and 2.9.x before 2.9.7 as well as Ansible Tower before and including versions 3.4.5 and 3.5.5 and 3.6.3 when the ldap_attr and ldap_entry community modules are used. The issue discloses the LDAP bind password to stdout or a log file if a playbook task is written using the bind_pw in the parameters field. The highest threat from this vulnerability is data confidentiality.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-1746](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-1746) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-1746.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-1746.svg)


## CVE-2020-1740
 A flaw was found in Ansible Engine when using Ansible Vault for editing encrypted files. When a user executes &quot;ansible-vault edit&quot;, another user on the same computer can read the old and new secret, as it is created in a temporary file with mkstemp and the returned file descriptor is closed and the method write_data is called to write the existing secret in the file. This method will delete the file before recreating it insecurely. All versions in 2.7.x, 2.8.x and 2.9.x branches are believed to be vulnerable.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-1740](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-1740) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-1740.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-1740.svg)


## CVE-2020-1739
 A flaw was found in Ansible 2.7.16 and prior, 2.8.8 and prior, and 2.9.5 and prior when a password is set with the argument &quot;password&quot; of svn module, it is used on svn command line, disclosing to other users within the same node. An attacker could take advantage by reading the cmdline file from that particular PID on the procfs.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-1739](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-1739) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-1739.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-1739.svg)


## CVE-2020-1735
 A flaw was found in the Ansible Engine when the fetch module is used. An attacker could intercept the module, inject a new path, and then choose a new destination path on the controller node. All versions in 2.7.x, 2.8.x and 2.9.x branches are believed to be vulnerable.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-1735](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-1735) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-1735.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-1735.svg)


## CVE-2020-1733
 A race condition flaw was found in Ansible Engine 2.7.17 and prior, 2.8.9 and prior, 2.9.6 and prior when running a playbook with an unprivileged become user. When Ansible needs to run a module with become user, the temporary directory is created in /var/tmp. This directory is created with &quot;umask 77 &amp;&amp; mkdir -p &lt;dir&gt;&quot;; this operation does not fail if the directory already exists and is owned by another user. An attacker could take advantage to gain control of the become user as the target directory can be retrieved by iterating '/proc/&lt;pid&gt;/cmdline'.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-1733](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-1733) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-1733.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-1733.svg)


## CVE-2020-1416
 An elevation of privilege vulnerability exists in Visual Studio and Visual Studio Code when they load software dependencies, aka 'Visual Studio and Visual Studio Code Elevation of Privilege Vulnerability'.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-1416](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2020-1416) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2020-1416.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2020-1416.svg)


## CVE-2019-25052
 In Linaro OP-TEE before 3.7.0, by using inconsistent or malformed data, it is possible to call update and final cryptographic functions directly, causing a crash that could leak sensitive information.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-25052](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-25052) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2019-25052.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2019-25052.svg)


## CVE-2019-19797
 read_colordef in read.c in Xfig fig2dev 3.2.7b has an out-of-bounds write.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-19797](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-19797) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2019-19797.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2019-19797.svg)


## CVE-2019-18413
 In TypeStack class-validator 0.10.2, validate() input validation can be bypassed because certain internal attributes can be overwritten via a conflicting name. Even though there is an optional forbidUnknownValues parameter that can be used to reduce the risk of this bypass, this option is not documented and thus most developers configure input validation in the vulnerable default manner. With this vulnerability, attackers can launch SQL Injection or XSS attacks by injecting arbitrary malicious input. NOTE: a software maintainer agrees with the &quot;is not documented&quot; finding but suggests that much of the responsibility for the risk lies in a different product.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-18413](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-18413) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2019-18413.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2019-18413.svg)


## CVE-2019-17571
 Included in Log4j 1.2 is a SocketServer class that is vulnerable to deserialization of untrusted data which can be exploited to remotely execute arbitrary code when combined with a deserialization gadget when listening to untrusted network traffic for log data. This affects Log4j versions up to 1.2 up to 1.2.17.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-17571](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-17571) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2019-17571.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2019-17571.svg)


## CVE-2019-17495
 A Cascading Style Sheets (CSS) injection vulnerability in Swagger UI before 3.23.11 allows attackers to use the Relative Path Overwrite (RPO) technique to perform CSS-based input field value exfiltration, such as exfiltration of a CSRF token value. In other words, this product intentionally allows the embedding of untrusted JSON data from remote servers, but it was not previously known that &lt;style&gt;@import within the JSON data was a functional attack method.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-17495](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-17495) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2019-17495.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2019-17495.svg)


## CVE-2019-15107
 An issue was discovered in Webmin &lt;=1.920. The parameter old in password_change.cgi contains a command injection vulnerability.

- [https://github.com/hacknotes/CVE-2019-15107-Exploit](https://github.com/hacknotes/CVE-2019-15107-Exploit) :  ![starts](https://img.shields.io/github/stars/hacknotes/CVE-2019-15107-Exploit.svg) ![forks](https://img.shields.io/github/forks/hacknotes/CVE-2019-15107-Exploit.svg)


## CVE-2019-14904
 A flaw was found in the solaris_zone module from the Ansible Community modules. When setting the name for the zone on the Solaris host, the zone name is checked by listing the process with the 'ps' bare command on the remote machine. An attacker could take advantage of this flaw by crafting the name of the zone and executing arbitrary commands in the remote host. Ansible Engine 2.7.15, 2.8.7, and 2.9.2 as well as previous versions are affected.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-14904](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-14904) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2019-14904.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2019-14904.svg)


## CVE-2019-14864
 Ansible, versions 2.9.x before 2.9.1, 2.8.x before 2.8.7 and Ansible versions 2.7.x before 2.7.15, is not respecting the flag no_log set it to True when Sumologic and Splunk callback plugins are used send tasks results events to collectors. This would discloses and collects any sensitive data.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-14864](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-14864) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2019-14864.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2019-14864.svg)


## CVE-2019-14846
 In Ansible, all Ansible Engine versions up to ansible-engine 2.8.5, ansible-engine 2.7.13, ansible-engine 2.6.19, were logging at the DEBUG level which lead to a disclosure of credentials if a plugin used a library that logged credentials at the DEBUG level. This flaw does not affect Ansible modules, as those are executed in a separate process.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-14846](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-14846) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2019-14846.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2019-14846.svg)


## CVE-2019-12840
 In Webmin through 1.910, any user authorized to the &quot;Package Updates&quot; module can execute arbitrary commands with root privileges via the data parameter to update.cgi.

- [https://github.com/WizzzStark/CVE-2019-12840.py](https://github.com/WizzzStark/CVE-2019-12840.py) :  ![starts](https://img.shields.io/github/stars/WizzzStark/CVE-2019-12840.py.svg) ![forks](https://img.shields.io/github/forks/WizzzStark/CVE-2019-12840.py.svg)


## CVE-2019-12823
 Craft CMS before 3.1.31 does not properly filter XML feeds and thus allowing XSS.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-12823](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-12823) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2019-12823.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2019-12823.svg)


## CVE-2019-11831
 The PharStreamWrapper (aka phar-stream-wrapper) package 2.x before 2.1.1 and 3.x before 3.1.1 for TYPO3 does not prevent directory traversal, which allows attackers to bypass a deserialization protection mechanism, as demonstrated by a phar:///path/bad.phar/../good.phar URL.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-11831](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-11831) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2019-11831.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2019-11831.svg)


## CVE-2019-11595
 In uBlock before 0.9.5.15, the $rewrite filter option allows filter-list maintainers to run arbitrary code in a client-side session when a web service loads a script for execution using XMLHttpRequest or Fetch, and the script origin has an open redirect.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-11595](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-11595) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2019-11595.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2019-11595.svg)


## CVE-2019-11358
 jQuery before 3.4.0, as used in Drupal, Backdrop CMS, and other products, mishandles jQuery.extend(true, {}, ...) because of Object.prototype pollution. If an unsanitized source object contained an enumerable __proto__ property, it could extend the native Object.prototype.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-11358](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-11358) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2019-11358.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2019-11358.svg)


## CVE-2019-10953
 ABB, Phoenix Contact, Schneider Electric, Siemens, WAGO - Programmable Logic Controllers, multiple versions. Researchers have found some controllers are susceptible to a denial-of-service attack due to a flood of network packets.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-10953](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-10953) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2019-10953.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2019-10953.svg)


## CVE-2019-10911
 In Symfony before 2.7.51, 2.8.x before 2.8.50, 3.x before 3.4.26, 4.x before 4.1.12, and 4.2.x before 4.2.7, a vulnerability would allow an attacker to authenticate as a privileged user on sites with user registration and remember me login functionality enabled. This is related to symfony/security.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-10911](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-10911) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2019-10911.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2019-10911.svg)


## CVE-2019-10910
 In Symfony before 2.7.51, 2.8.x before 2.8.50, 3.x before 3.4.26, 4.x before 4.1.12, and 4.2.x before 4.2.7, when service ids allow user input, this could allow for SQL Injection and remote code execution. This is related to symfony/dependency-injection.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-10910](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-10910) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2019-10910.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2019-10910.svg)


## CVE-2019-10206
 ansible-playbook -k and ansible cli tools, all versions 2.8.x before 2.8.4, all 2.7.x before 2.7.13 and all 2.6.x before 2.6.19, prompt passwords by expanding them from templates as they could contain special characters. Passwords should be wrapped to prevent templates trigger and exposing them.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-10206](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-10206) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2019-10206.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2019-10206.svg)


## CVE-2019-10181
 It was found that in icedtea-web up to and including 1.7.2 and 1.8.2 executable code could be injected in a JAR file without compromising the signature verification. An attacker could use this flaw to inject code in a trusted JAR. The code would be executed inside the sandbox.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-10181](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-10181) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2019-10181.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2019-10181.svg)


## CVE-2019-10172
 A flaw was found in org.codehaus.jackson:jackson-mapper-asl:1.9.x libraries. XML external entity vulnerabilities similar CVE-2016-3720 also affects codehaus jackson-mapper-asl libraries but in different classes.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-10172](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-10172) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2019-10172.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2019-10172.svg)


## CVE-2019-10156
 A flaw was discovered in the way Ansible templating was implemented in versions before 2.6.18, 2.7.12 and 2.8.2, causing the possibility of information disclosure through unexpected variable substitution. By taking advantage of unintended variable substitution the content of any variable may be disclosed.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-10156](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-10156) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2019-10156.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2019-10156.svg)


## CVE-2019-10095
 bash command injection vulnerability in Apache Zeppelin allows an attacker to inject system commands into Spark interpreter settings. This issue affects Apache Zeppelin Apache Zeppelin version 0.9.0 and prior versions.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-10095](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-10095) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2019-10095.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2019-10095.svg)


## CVE-2019-0227
 A Server Side Request Forgery (SSRF) vulnerability affected the Apache Axis 1.4 distribution that was last released in 2006. Security and bug commits commits continue in the projects Axis 1.x Subversion repository, legacy users are encouraged to build from source. The successor to Axis 1.x is Axis2, the latest version is 1.7.9 and is not vulnerable to this issue.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-0227](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-0227) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2019-0227.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2019-0227.svg)


## CVE-2019-0205
 In Apache Thrift all versions up to and including 0.12.0, a server or client may run into an endless loop when feed with specific input data. Because the issue had already been partially fixed in version 0.11.0, depending on the installed version it affects only certain language bindings.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-0205](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-0205) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2019-0205.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2019-0205.svg)


## CVE-2018-9995
 TBK DVR4104 and DVR4216 devices, as well as Novo, CeNova, QSee, Pulnix, XVR 5 in 1, Securus, Night OWL, DVR Login, HVR Login, and MDVR Login, which run re-branded versions of the original TBK DVR4104 and DVR4216 series, allow remote attackers to bypass authentication via a &quot;Cookie: uid=admin&quot; header, as demonstrated by a device.rsp?opt=user&amp;cmd=list request that provides credentials within JSON data in a response.

- [https://github.com/yatcode/HTC](https://github.com/yatcode/HTC) :  ![starts](https://img.shields.io/github/stars/yatcode/HTC.svg) ![forks](https://img.shields.io/github/forks/yatcode/HTC.svg)


## CVE-2017-16119
 Fresh is a module used by the Express.js framework for HTTP response freshness testing. It is vulnerable to a regular expression denial of service when it is passed specially crafted input to parse. This causes the event loop to be blocked causing a denial of service condition.

- [https://github.com/ossf-cve-benchmark/CVE-2017-16119](https://github.com/ossf-cve-benchmark/CVE-2017-16119) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16119.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16119.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka &quot;ShellShock.&quot;  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/0bfxgh0st/ShellShock](https://github.com/0bfxgh0st/ShellShock) :  ![starts](https://img.shields.io/github/stars/0bfxgh0st/ShellShock.svg) ![forks](https://img.shields.io/github/forks/0bfxgh0st/ShellShock.svg)


## CVE-2014-2815
 Microsoft OneNote 2007 SP3 allows remote attackers to execute arbitrary code via a crafted OneNote file that triggers creation of an executable file in a startup folder, aka &quot;OneNote Remote Code Execution Vulnerability.&quot;

- [https://github.com/Edubr2020/CABTrap_OneNote2007](https://github.com/Edubr2020/CABTrap_OneNote2007) :  ![starts](https://img.shields.io/github/stars/Edubr2020/CABTrap_OneNote2007.svg) ![forks](https://img.shields.io/github/forks/Edubr2020/CABTrap_OneNote2007.svg)

