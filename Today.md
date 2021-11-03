# Update 2021-11-03
## CVE-2021-42694
 An issue was discovered in the character definitions of the Unicode Specification through 14.0. The specification allows an adversary to produce source code identifiers such as function names using homoglyphs that render visually identical to a target identifier. Adversaries can leverage this to inject code via adversarial identifier definitions in upstream software dependencies invoked deceptively in downstream software.

- [https://github.com/hffaust/CVE-2021-42574_and_CVE-2021-42694](https://github.com/hffaust/CVE-2021-42574_and_CVE-2021-42694) :  ![starts](https://img.shields.io/github/stars/hffaust/CVE-2021-42574_and_CVE-2021-42694.svg) ![forks](https://img.shields.io/github/forks/hffaust/CVE-2021-42574_and_CVE-2021-42694.svg)


## CVE-2021-42574
 An issue was discovered in the Bidirectional Algorithm in the Unicode Specification through 14.0. It permits the visual reordering of characters via control sequences, which can be used to craft source code that renders different logic than the logical ordering of tokens ingested by compilers and interpreters. Adversaries can leverage this to encode source code for compilers accepting Unicode such that targeted vulnerabilities are introduced invisibly to human reviewers.

- [https://github.com/shiomiyan/CVE-2021-42574](https://github.com/shiomiyan/CVE-2021-42574) :  ![starts](https://img.shields.io/github/stars/shiomiyan/CVE-2021-42574.svg) ![forks](https://img.shields.io/github/forks/shiomiyan/CVE-2021-42574.svg)
- [https://github.com/hffaust/CVE-2021-42574_and_CVE-2021-42694](https://github.com/hffaust/CVE-2021-42574_and_CVE-2021-42694) :  ![starts](https://img.shields.io/github/stars/hffaust/CVE-2021-42574_and_CVE-2021-42694.svg) ![forks](https://img.shields.io/github/forks/hffaust/CVE-2021-42574_and_CVE-2021-42694.svg)


## CVE-2021-42327
 dp_link_settings_write in drivers/gpu/drm/amd/display/amdgpu_dm/amdgpu_dm_debugfs.c in the Linux kernel through 5.14.14 allows a heap-based buffer overflow by an attacker who can write a string to the AMD GPU display drivers debug filesystem. There are no checks on size within parse_write_buffer_into_params when it uses the size of copy_from_user to copy a userspace buffer into a 40-byte heap buffer.

- [https://github.com/docfate111/CVE-2021-42327](https://github.com/docfate111/CVE-2021-42327) :  ![starts](https://img.shields.io/github/stars/docfate111/CVE-2021-42327.svg) ![forks](https://img.shields.io/github/forks/docfate111/CVE-2021-42327.svg)


## CVE-2021-27514
 EyesOfNetwork 5.3-10 uses an integer of between 8 and 10 digits for the session ID, which might be leveraged for brute-force authentication bypass (such as in CVE-2021-27513 exploitation).

- [https://github.com/ArianeBlow/CVE-2021-27513-CVE-2021-27514](https://github.com/ArianeBlow/CVE-2021-27513-CVE-2021-27514) :  ![starts](https://img.shields.io/github/stars/ArianeBlow/CVE-2021-27513-CVE-2021-27514.svg) ![forks](https://img.shields.io/github/forks/ArianeBlow/CVE-2021-27513-CVE-2021-27514.svg)


## CVE-2021-27513
 The module admin_ITSM in EyesOfNetwork 5.3-10 allows remote authenticated users to upload arbitrary .xml.php files because it relies on &quot;le filtre userside.&quot;

- [https://github.com/ArianeBlow/CVE-2021-27513-CVE-2021-27514](https://github.com/ArianeBlow/CVE-2021-27513-CVE-2021-27514) :  ![starts](https://img.shields.io/github/stars/ArianeBlow/CVE-2021-27513-CVE-2021-27514.svg) ![forks](https://img.shields.io/github/forks/ArianeBlow/CVE-2021-27513-CVE-2021-27514.svg)


## CVE-2021-26814
 Wazuh API in Wazuh from 4.0.0 to 4.0.3 allows authenticated users to execute arbitrary code with administrative privileges via /manager/files URI. An authenticated user to the service may exploit incomplete input validation on the /manager/files API to inject arbitrary code within the API service script.

- [https://github.com/paolorabbito/Internet-Security-Project---CVE-2021-26814](https://github.com/paolorabbito/Internet-Security-Project---CVE-2021-26814) :  ![starts](https://img.shields.io/github/stars/paolorabbito/Internet-Security-Project---CVE-2021-26814.svg) ![forks](https://img.shields.io/github/forks/paolorabbito/Internet-Security-Project---CVE-2021-26814.svg)


## CVE-2021-25646
 Apache Druid includes the ability to execute user-provided JavaScript code embedded in various types of requests. This functionality is intended for use in high-trust environments, and is disabled by default. However, in Druid 0.20.0 and earlier, it is possible for an authenticated user to send a specially-crafted request that forces Druid to run user-provided JavaScript code for that request, regardless of server configuration. This can be leveraged to execute code on the target machine with the privileges of the Druid server process.

- [https://github.com/Vulnmachines/Apache-Druid-CVE-2021-25646](https://github.com/Vulnmachines/Apache-Druid-CVE-2021-25646) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/Apache-Druid-CVE-2021-25646.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/Apache-Druid-CVE-2021-25646.svg)


## CVE-2021-22205
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 11.9. GitLab was not properly validating image files that were passed to a file parser which resulted in a remote command execution.

- [https://github.com/shang159/CVE-2021-22205-getshell](https://github.com/shang159/CVE-2021-22205-getshell) :  ![starts](https://img.shields.io/github/stars/shang159/CVE-2021-22205-getshell.svg) ![forks](https://img.shields.io/github/forks/shang159/CVE-2021-22205-getshell.svg)
- [https://github.com/AkBanner/CVE-2021-22205](https://github.com/AkBanner/CVE-2021-22205) :  ![starts](https://img.shields.io/github/stars/AkBanner/CVE-2021-22205.svg) ![forks](https://img.shields.io/github/forks/AkBanner/CVE-2021-22205.svg)
- [https://github.com/Qclover/Gitlab_RCE_CVE_2021_22205](https://github.com/Qclover/Gitlab_RCE_CVE_2021_22205) :  ![starts](https://img.shields.io/github/stars/Qclover/Gitlab_RCE_CVE_2021_22205.svg) ![forks](https://img.shields.io/github/forks/Qclover/Gitlab_RCE_CVE_2021_22205.svg)


## CVE-2021-20837
 Movable Type 7 r.5002 and earlier (Movable Type 7 Series), Movable Type 6.8.2 and earlier (Movable Type 6 Series), Movable Type Advanced 7 r.5002 and earlier (Movable Type Advanced 7 Series), Movable Type Advanced 6.8.2 and earlier (Movable Type Advanced 6 Series), Movable Type Premium 1.46 and earlier, and Movable Type Premium Advanced 1.46 and earlier allow remote attackers to execute arbitrary OS commands via unspecified vectors. Note that all versions of Movable Type 4.0 or later including unsupported (End-of-Life, EOL) versions are also affected by this vulnerability.

- [https://github.com/Cosemz/CVE-2021-20837](https://github.com/Cosemz/CVE-2021-20837) :  ![starts](https://img.shields.io/github/stars/Cosemz/CVE-2021-20837.svg) ![forks](https://img.shields.io/github/forks/Cosemz/CVE-2021-20837.svg)


## CVE-2021-3441
 A potential security vulnerability has been identified for the HP OfficeJet 7110 Wide Format ePrinter that enables Cross-Site Scripting (XSS).

- [https://github.com/tcbutler320/CVE-2021-3441-check](https://github.com/tcbutler320/CVE-2021-3441-check) :  ![starts](https://img.shields.io/github/stars/tcbutler320/CVE-2021-3441-check.svg) ![forks](https://img.shields.io/github/forks/tcbutler320/CVE-2021-3441-check.svg)


## CVE-2019-17570
 An untrusted deserialization was found in the org.apache.xmlrpc.parser.XmlRpcResponseParser:addResult method of Apache XML-RPC (aka ws-xmlrpc) library. A malicious XML-RPC server could target a XML-RPC client causing it to execute arbitrary code. Apache XML-RPC is no longer maintained and this issue will not be fixed.

- [https://github.com/fbeasts/xmlrpc-common-deserialization](https://github.com/fbeasts/xmlrpc-common-deserialization) :  ![starts](https://img.shields.io/github/stars/fbeasts/xmlrpc-common-deserialization.svg) ![forks](https://img.shields.io/github/forks/fbeasts/xmlrpc-common-deserialization.svg)


## CVE-2015-1635
 HTTP.sys in Microsoft Windows 7 SP1, Windows Server 2008 R2 SP1, Windows 8, Windows 8.1, and Windows Server 2012 Gold and R2 allows remote attackers to execute arbitrary code via crafted HTTP requests, aka &quot;HTTP.sys Remote Code Execution Vulnerability.&quot;

- [https://github.com/limkokholefork/CVE-2015-1635](https://github.com/limkokholefork/CVE-2015-1635) :  ![starts](https://img.shields.io/github/stars/limkokholefork/CVE-2015-1635.svg) ![forks](https://img.shields.io/github/forks/limkokholefork/CVE-2015-1635.svg)


## CVE-2015-0235
 Heap-based buffer overflow in the __nss_hostname_digits_dots function in glibc 2.2, and other 2.x versions before 2.18, allows context-dependent attackers to execute arbitrary code via vectors related to the (1) gethostbyname or (2) gethostbyname2 function, aka &quot;GHOST.&quot;

- [https://github.com/limkokholefork/GHOSTCHECK-cve-2015-0235](https://github.com/limkokholefork/GHOSTCHECK-cve-2015-0235) :  ![starts](https://img.shields.io/github/stars/limkokholefork/GHOSTCHECK-cve-2015-0235.svg) ![forks](https://img.shields.io/github/forks/limkokholefork/GHOSTCHECK-cve-2015-0235.svg)


## CVE-2011-3192
 The byterange filter in the Apache HTTP Server 1.3.x, 2.0.x through 2.0.64, and 2.2.x through 2.2.19 allows remote attackers to cause a denial of service (memory and CPU consumption) via a Range header that expresses multiple overlapping ranges, as exploited in the wild in August 2011, a different vulnerability than CVE-2007-0086.

- [https://github.com/limkokholefork/CVE-2011-3192](https://github.com/limkokholefork/CVE-2011-3192) :  ![starts](https://img.shields.io/github/stars/limkokholefork/CVE-2011-3192.svg) ![forks](https://img.shields.io/github/forks/limkokholefork/CVE-2011-3192.svg)

