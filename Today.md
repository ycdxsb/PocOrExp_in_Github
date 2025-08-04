# Update 2025-08-04
## CVE-2025-53770
Microsoft is preparing and fully testing a comprehensive update to address this vulnerability.  In the meantime, please make sure that the mitigation provided in this CVE documentation is in place so that you are protected from exploitation.

- [https://github.com/harryhaxor/CVE-2025-53770-SharePoint-Deserialization-RCE-PoC](https://github.com/harryhaxor/CVE-2025-53770-SharePoint-Deserialization-RCE-PoC) :  ![starts](https://img.shields.io/github/stars/harryhaxor/CVE-2025-53770-SharePoint-Deserialization-RCE-PoC.svg) ![forks](https://img.shields.io/github/forks/harryhaxor/CVE-2025-53770-SharePoint-Deserialization-RCE-PoC.svg)


## CVE-2025-48384
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When reading a config value, Git strips any trailing carriage return and line feed (CRLF). When writing a config entry, values with a trailing CR are not quoted, causing the CR to be lost when the config is later read. When initializing a submodule, if the submodule path contains a trailing CR, the altered path is read resulting in the submodule being checked out to an incorrect location. If a symlink exists that points the altered path to the submodule hooks directory, and the submodule contains an executable post-checkout hook, the script may be unintentionally executed after checkout. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.

- [https://github.com/fluoworite/CVE-2025-48384](https://github.com/fluoworite/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/fluoworite/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/fluoworite/CVE-2025-48384.svg)
- [https://github.com/fluoworite/CVE-2025-48384_sub](https://github.com/fluoworite/CVE-2025-48384_sub) :  ![starts](https://img.shields.io/github/stars/fluoworite/CVE-2025-48384_sub.svg) ![forks](https://img.shields.io/github/forks/fluoworite/CVE-2025-48384_sub.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/Dlodlos/CVE-2025-32463-lab](https://github.com/Dlodlos/CVE-2025-32463-lab) :  ![starts](https://img.shields.io/github/stars/Dlodlos/CVE-2025-32463-lab.svg) ![forks](https://img.shields.io/github/forks/Dlodlos/CVE-2025-32463-lab.svg)


## CVE-2025-32462
 Sudo before 1.9.17p1, when used with a sudoers file that specifies a host that is neither the current host nor ALL, allows listed users to execute commands on unintended machines.

- [https://github.com/Dlodlos/CVE-2025-32463-lab](https://github.com/Dlodlos/CVE-2025-32463-lab) :  ![starts](https://img.shields.io/github/stars/Dlodlos/CVE-2025-32463-lab.svg) ![forks](https://img.shields.io/github/forks/Dlodlos/CVE-2025-32463-lab.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/nopgadget/CVE-2025-24893](https://github.com/nopgadget/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/nopgadget/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/nopgadget/CVE-2025-24893.svg)
- [https://github.com/Kai7788/CVE-2025-24893-RCE-PoC](https://github.com/Kai7788/CVE-2025-24893-RCE-PoC) :  ![starts](https://img.shields.io/github/stars/Kai7788/CVE-2025-24893-RCE-PoC.svg) ![forks](https://img.shields.io/github/forks/Kai7788/CVE-2025-24893-RCE-PoC.svg)


## CVE-2025-7847
 The AI Engine plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the rest_simpleFileUpload() function in versions 2.9.3 and 2.9.4. This makes it possible for authenticated attackers, with Subscriber-level access and above, to upload arbitrary files on the affected site's server when the REST API is enabled, which may make remote code execution possible.

- [https://github.com/EricArdiansa/CVE-2025-7847-POC](https://github.com/EricArdiansa/CVE-2025-7847-POC) :  ![starts](https://img.shields.io/github/stars/EricArdiansa/CVE-2025-7847-POC.svg) ![forks](https://img.shields.io/github/forks/EricArdiansa/CVE-2025-7847-POC.svg)


## CVE-2025-5394
 The Alone – Charity Multipurpose Non-profit WordPress Theme theme for WordPress is vulnerable to arbitrary file uploads due to a missing capability check on the alone_import_pack_install_plugin() function in all versions up to, and including, 7.8.3. This makes it possible for unauthenticated attackers to upload zip files containing webshells disguised as plugins from remote locations to achieve remote code execution.

- [https://github.com/Yucaerin/CVE-2025-5394](https://github.com/Yucaerin/CVE-2025-5394) :  ![starts](https://img.shields.io/github/stars/Yucaerin/CVE-2025-5394.svg) ![forks](https://img.shields.io/github/forks/Yucaerin/CVE-2025-5394.svg)
- [https://github.com/Nxploited/CVE-2025-5394](https://github.com/Nxploited/CVE-2025-5394) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-5394.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-5394.svg)


## CVE-2025-4606
 The Sala - Startup & SaaS WordPress Theme theme for WordPress is vulnerable to privilege escalation via account takeover in all versions up to, and including, 1.1.4. This is due to the theme not properly validating a user's identity prior to updating their details like password. This makes it possible for unauthenticated attackers to change arbitrary user's passwords, including administrators, and leverage that to gain access to their account.

- [https://github.com/Yucaerin/CVE-2025-4606](https://github.com/Yucaerin/CVE-2025-4606) :  ![starts](https://img.shields.io/github/stars/Yucaerin/CVE-2025-4606.svg) ![forks](https://img.shields.io/github/forks/Yucaerin/CVE-2025-4606.svg)


## CVE-2024-43425
 A flaw was found in Moodle. Additional restrictions are required to avoid a remote code execution risk in calculated question types. Note: This requires the capability to add/update questions.

- [https://github.com/aayush256-sys/Moodle-authenticated-RCE](https://github.com/aayush256-sys/Moodle-authenticated-RCE) :  ![starts](https://img.shields.io/github/stars/aayush256-sys/Moodle-authenticated-RCE.svg) ![forks](https://img.shields.io/github/forks/aayush256-sys/Moodle-authenticated-RCE.svg)


## CVE-2024-21626
 runc is a CLI tool for spawning and running containers on Linux according to the OCI specification. In runc 1.1.11 and earlier, due to an internal file descriptor leak, an attacker could cause a newly-spawned container process (from runc exec) to have a working directory in the host filesystem namespace, allowing for a container escape by giving access to the host filesystem ("attack 2"). The same attack could be used by a malicious image to allow a container process to gain access to the host filesystem through runc run ("attack 1"). Variants of attacks 1 and 2 could be also be used to overwrite semi-arbitrary host binaries, allowing for complete container escapes ("attack 3a" and "attack 3b"). runc 1.1.12 includes patches for this issue.

- [https://github.com/R4mbb/CVE-2024-21626-PoC](https://github.com/R4mbb/CVE-2024-21626-PoC) :  ![starts](https://img.shields.io/github/stars/R4mbb/CVE-2024-21626-PoC.svg) ![forks](https://img.shields.io/github/forks/R4mbb/CVE-2024-21626-PoC.svg)


## CVE-2023-45878
 GibbonEdu Gibbon version 25.0.1 and before allows Arbitrary File Write because rubrics_visualise_saveAjax.phps does not require authentication. The endpoint accepts the img, path, and gibbonPersonID parameters. The img parameter is expected to be a base64 encoded image. If the path parameter is set, the defined path is used as the destination folder, concatenated with the absolute path of the installation directory. The content of the img parameter is base64 decoded and written to the defined file path. This allows creation of PHP files that permit Remote Code Execution (unauthenticated).

- [https://github.com/byt3loss/CVE-2023-45878_to_RCE](https://github.com/byt3loss/CVE-2023-45878_to_RCE) :  ![starts](https://img.shields.io/github/stars/byt3loss/CVE-2023-45878_to_RCE.svg) ![forks](https://img.shields.io/github/forks/byt3loss/CVE-2023-45878_to_RCE.svg)


## CVE-2021-21239
 PySAML2 is a pure python implementation of SAML Version 2 Standard. PySAML2 before 6.5.0 has an improper verification of cryptographic signature vulnerability. Users of pysaml2 that use the default CryptoBackendXmlSec1 backend and need to verify signed SAML documents are impacted. PySAML2 does not ensure that a signed SAML document is correctly signed. The default CryptoBackendXmlSec1 backend is using the xmlsec1 binary to verify the signature of signed SAML documents, but by default xmlsec1 accepts any type of key found within the given document. xmlsec1 needs to be configured explicitly to only use only _x509 certificates_ for the verification process of the SAML document signature. This is fixed in PySAML2 6.5.0.

- [https://github.com/GrantBirki/redash-vulnerable](https://github.com/GrantBirki/redash-vulnerable) :  ![starts](https://img.shields.io/github/stars/GrantBirki/redash-vulnerable.svg) ![forks](https://img.shields.io/github/forks/GrantBirki/redash-vulnerable.svg)


## CVE-2020-7934
 In LifeRay Portal CE 7.1.0 through 7.2.1 GA2, the First Name, Middle Name, and Last Name fields for user accounts in MyAccountPortlet are all vulnerable to a persistent XSS issue. Any user can modify these fields with a particular XSS payload, and it will be stored in the database. The payload will then be rendered when a user utilizes the search feature to search for other users (i.e., if a user with modified fields occurs in the search results). This issue was fixed in Liferay Portal CE version 7.3.0 GA1.

- [https://github.com/giardinas-dev/audit-xss-cve-2020-7934](https://github.com/giardinas-dev/audit-xss-cve-2020-7934) :  ![starts](https://img.shields.io/github/stars/giardinas-dev/audit-xss-cve-2020-7934.svg) ![forks](https://img.shields.io/github/forks/giardinas-dev/audit-xss-cve-2020-7934.svg)


## CVE-2019-0567
 A remote code execution vulnerability exists in the way that the Chakra scripting engine handles objects in memory in Microsoft Edge, aka "Chakra Scripting Engine Memory Corruption Vulnerability." This affects Microsoft Edge, ChakraCore. This CVE ID is unique from CVE-2019-0539, CVE-2019-0568.

- [https://github.com/kai6u/TriBell_Edge_SandBox_Escape](https://github.com/kai6u/TriBell_Edge_SandBox_Escape) :  ![starts](https://img.shields.io/github/stars/kai6u/TriBell_Edge_SandBox_Escape.svg) ![forks](https://img.shields.io/github/forks/kai6u/TriBell_Edge_SandBox_Escape.svg)


## CVE-2019-0555
 An elevation of privilege vulnerability exists in the Microsoft XmlDocument class that could allow an attacker to escape from the AppContainer sandbox in the browser, aka "Microsoft XmlDocument Elevation of Privilege Vulnerability." This affects Windows Server 2012 R2, Windows RT 8.1, Windows Server 2012, Windows Server 2019, Windows Server 2016, Windows 8.1, Windows 10, Windows 10 Servers.

- [https://github.com/kai6u/TriBell_Edge_SandBox_Escape](https://github.com/kai6u/TriBell_Edge_SandBox_Escape) :  ![starts](https://img.shields.io/github/stars/kai6u/TriBell_Edge_SandBox_Escape.svg) ![forks](https://img.shields.io/github/forks/kai6u/TriBell_Edge_SandBox_Escape.svg)

