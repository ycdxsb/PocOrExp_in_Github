# Update 2025-03-22
## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/n0n-zer0/Spring-Boot-Tomcat-CVE-2025-24813](https://github.com/n0n-zer0/Spring-Boot-Tomcat-CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/n0n-zer0/Spring-Boot-Tomcat-CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/n0n-zer0/Spring-Boot-Tomcat-CVE-2025-24813.svg)


## CVE-2025-2476
 Use after free in Lens in Google Chrome prior to 134.0.6998.117 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Critical)

- [https://github.com/McTavishSue/CVE-2025-2476](https://github.com/McTavishSue/CVE-2025-2476) :  ![starts](https://img.shields.io/github/stars/McTavishSue/CVE-2025-2476.svg) ![forks](https://img.shields.io/github/forks/McTavishSue/CVE-2025-2476.svg)


## CVE-2024-48591
 Inflectra SpiraTeam 7.2.00 is vulnerable to Cross Site Scripting (XSS). A specially crafted SVG file can be uploaded that will render and execute JavaScript upon direct viewing.

- [https://github.com/GCatt-AS/CVE-2024-48591](https://github.com/GCatt-AS/CVE-2024-48591) :  ![starts](https://img.shields.io/github/stars/GCatt-AS/CVE-2024-48591.svg) ![forks](https://img.shields.io/github/forks/GCatt-AS/CVE-2024-48591.svg)


## CVE-2024-48590
 Inflectra SpiraTeam 7.2.00 is vulnerable to Server-Side Request Forgery (SSRF) via the NewsReaderService. This allows an attacker to escalate privileges and obtain sensitive information.

- [https://github.com/GCatt-AS/CVE-2024-48590](https://github.com/GCatt-AS/CVE-2024-48590) :  ![starts](https://img.shields.io/github/stars/GCatt-AS/CVE-2024-48590.svg) ![forks](https://img.shields.io/github/forks/GCatt-AS/CVE-2024-48590.svg)


## CVE-2024-46981
 Redis is an open source, in-memory database that persists on disk. An authenticated user may use a specially crafted Lua script to manipulate the garbage collector and potentially lead to remote code execution. The problem is fixed in 7.4.2, 7.2.7, and 6.2.17. An additional workaround to mitigate the problem without patching the redis-server executable is to prevent users from executing Lua scripts. This can be done using ACL to restrict EVAL and EVALSHA commands.

- [https://github.com/publicqi/CVE-2024-46981](https://github.com/publicqi/CVE-2024-46981) :  ![starts](https://img.shields.io/github/stars/publicqi/CVE-2024-46981.svg) ![forks](https://img.shields.io/github/forks/publicqi/CVE-2024-46981.svg)


## CVE-2024-32962
 xml-crypto is an xml digital signature and encryption library for Node.js. In affected versions the default configuration does not check authorization of the signer, it only checks the validity of the signature per section 3.2.2 of the w3 xmldsig-core-20080610 spec. As such, without additional validation steps, the default configuration allows a malicious actor to re-sign an XML document, place the certificate in a `KeyInfo /` element, and pass `xml-crypto` default validation checks. As a result `xml-crypto` trusts by default any certificate provided via digitally signed XML document's `KeyInfo /`. `xml-crypto` prefers to use any certificate provided via digitally signed XML document's `KeyInfo /` even if library was configured to use specific certificate (`publicCert`) for signature verification purposes.  An attacker can spoof signature verification by modifying XML document and replacing existing signature with signature generated with malicious private key (created by attacker) and by attaching that private key's certificate to `KeyInfo /` element. This vulnerability is combination of changes introduced to `4.0.0` on pull request 301 / commit `c2b83f98` and has been addressed in version 6.0.0 with pull request 445 / commit `21201723d`. Users are advised to upgrade. Users unable to upgrade may either check the certificate extracted via `getCertFromKeyInfo` against trusted certificates before accepting the results of the validation or set `xml-crypto's getCertFromKeyInfo` to `() = undefined` forcing `xml-crypto` to use an explicitly configured `publicCert` or `privateKey` for signature verification.

- [https://github.com/absholi7ly/Poc-CVE-2024-32962-xml-crypto](https://github.com/absholi7ly/Poc-CVE-2024-32962-xml-crypto) :  ![starts](https://img.shields.io/github/stars/absholi7ly/Poc-CVE-2024-32962-xml-crypto.svg) ![forks](https://img.shields.io/github/forks/absholi7ly/Poc-CVE-2024-32962-xml-crypto.svg)


## CVE-2023-45878
 GibbonEdu Gibbon version 25.0.1 and before allows Arbitrary File Write because rubrics_visualise_saveAjax.phps does not require authentication. The endpoint accepts the img, path, and gibbonPersonID parameters. The img parameter is expected to be a base64 encoded image. If the path parameter is set, the defined path is used as the destination folder, concatenated with the absolute path of the installation directory. The content of the img parameter is base64 decoded and written to the defined file path. This allows creation of PHP files that permit Remote Code Execution (unauthenticated).

- [https://github.com/killercd/CVE-2023-45878](https://github.com/killercd/CVE-2023-45878) :  ![starts](https://img.shields.io/github/stars/killercd/CVE-2023-45878.svg) ![forks](https://img.shields.io/github/forks/killercd/CVE-2023-45878.svg)
- [https://github.com/PaulDHaes/CVE-2023-45878-POC](https://github.com/PaulDHaes/CVE-2023-45878-POC) :  ![starts](https://img.shields.io/github/stars/PaulDHaes/CVE-2023-45878-POC.svg) ![forks](https://img.shields.io/github/forks/PaulDHaes/CVE-2023-45878-POC.svg)


## CVE-2022-38181
 The Arm Mali GPU kernel driver allows unprivileged users to access freed memory because GPU memory operations are mishandled. This affects Bifrost r0p0 through r38p1, and r39p0; Valhall r19p0 through r38p1, and r39p0; and Midgard r4p0 through r32p0.

- [https://github.com/Bariskizilkaya/CVE_2022_38181-Mali-SAMSUNG-S6-Lite-Tablet](https://github.com/Bariskizilkaya/CVE_2022_38181-Mali-SAMSUNG-S6-Lite-Tablet) :  ![starts](https://img.shields.io/github/stars/Bariskizilkaya/CVE_2022_38181-Mali-SAMSUNG-S6-Lite-Tablet.svg) ![forks](https://img.shields.io/github/forks/Bariskizilkaya/CVE_2022_38181-Mali-SAMSUNG-S6-Lite-Tablet.svg)


## CVE-2022-30190
Please see the MSRC Blog Entry for important information about steps you can take to protect your system from this vulnerability.

- [https://github.com/JotaQC/CVE-2022-30190_Temporary_Fix](https://github.com/JotaQC/CVE-2022-30190_Temporary_Fix) :  ![starts](https://img.shields.io/github/stars/JotaQC/CVE-2022-30190_Temporary_Fix.svg) ![forks](https://img.shields.io/github/forks/JotaQC/CVE-2022-30190_Temporary_Fix.svg)
- [https://github.com/JotaQC/CVE-2022-30190_Temporary_Fix_Source_Code](https://github.com/JotaQC/CVE-2022-30190_Temporary_Fix_Source_Code) :  ![starts](https://img.shields.io/github/stars/JotaQC/CVE-2022-30190_Temporary_Fix_Source_Code.svg) ![forks](https://img.shields.io/github/forks/JotaQC/CVE-2022-30190_Temporary_Fix_Source_Code.svg)


## CVE-2016-10924
 The ebook-download plugin before 1.2 for WordPress has directory traversal.

- [https://github.com/808ale/cve-2016-10924-POC](https://github.com/808ale/cve-2016-10924-POC) :  ![starts](https://img.shields.io/github/stars/808ale/cve-2016-10924-POC.svg) ![forks](https://img.shields.io/github/forks/808ale/cve-2016-10924-POC.svg)

