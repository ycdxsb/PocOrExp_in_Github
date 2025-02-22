# Update 2025-02-22
## CVE-2025-25968
 DDSN Interactive cm3 Acora CMS version 10.1.1 contains an improper access control vulnerability. An editor-privileged user can access sensitive information, such as system administrator credentials, by force browsing the endpoint and exploiting the 'file' parameter. By referencing specific files (e.g., cm3.xml), attackers can bypass access controls, leading to account takeover and potential privilege escalation.

- [https://github.com/padayali-JD/CVE-2025-25968](https://github.com/padayali-JD/CVE-2025-25968) :  ![starts](https://img.shields.io/github/stars/padayali-JD/CVE-2025-25968.svg) ![forks](https://img.shields.io/github/forks/padayali-JD/CVE-2025-25968.svg)


## CVE-2025-24971
 DumpDrop is a stupid simple file upload application that provides an interface for dragging and dropping files. An OS Command Injection vulnerability was discovered in the DumbDrop application, `/upload/init` endpoint. This vulnerability could allow an attacker to execute arbitrary code remotely when the **Apprise Notification** enabled. This issue has been addressed in commit `4ff8469d` and all users are advised to patch. There are no known workarounds for this vulnerability.

- [https://github.com/be4zad/CVE-2025-24971](https://github.com/be4zad/CVE-2025-24971) :  ![starts](https://img.shields.io/github/stars/be4zad/CVE-2025-24971.svg) ![forks](https://img.shields.io/github/forks/be4zad/CVE-2025-24971.svg)


## CVE-2025-24016
 Wazuh is a free and open source platform used for threat prevention, detection, and response. Starting in version 4.4.0 and prior to version 4.9.1, an unsafe deserialization vulnerability allows for remote code execution on Wazuh servers. DistributedAPI parameters are a serialized as JSON and deserialized using `as_wazuh_object` (in `framework/wazuh/core/cluster/common.py`). If an attacker manages to inject an unsanitized dictionary in DAPI request/response, they can forge an unhandled exception (`__unhandled_exc__`) to evaluate arbitrary python code. The vulnerability can be triggered by anybody with API access (compromised dashboard or Wazuh servers in the cluster) or, in certain configurations, even by a compromised agent. Version 4.9.1 contains a fix.

- [https://github.com/MuhammadWaseem29/CVE-2025-24016](https://github.com/MuhammadWaseem29/CVE-2025-24016) :  ![starts](https://img.shields.io/github/stars/MuhammadWaseem29/CVE-2025-24016.svg) ![forks](https://img.shields.io/github/forks/MuhammadWaseem29/CVE-2025-24016.svg)


## CVE-2025-21420
 Windows Disk Cleanup Tool Elevation of Privilege Vulnerability

- [https://github.com/toxy4ny/edge-maradeur](https://github.com/toxy4ny/edge-maradeur) :  ![starts](https://img.shields.io/github/stars/toxy4ny/edge-maradeur.svg) ![forks](https://img.shields.io/github/forks/toxy4ny/edge-maradeur.svg)


## CVE-2025-21401
 Microsoft Edge (Chromium-based) Security Feature Bypass Vulnerability

- [https://github.com/toxy4ny/edge-maradeur](https://github.com/toxy4ny/edge-maradeur) :  ![starts](https://img.shields.io/github/stars/toxy4ny/edge-maradeur.svg) ![forks](https://img.shields.io/github/forks/toxy4ny/edge-maradeur.svg)


## CVE-2024-57401
 SQL Injection vulnerability in Uniclare Student portal v.2 and before allows a remote attacker to execute arbitrary code via the Forgot Password function.

- [https://github.com/aksingh82/CVE-2024-57401](https://github.com/aksingh82/CVE-2024-57401) :  ![starts](https://img.shields.io/github/stars/aksingh82/CVE-2024-57401.svg) ![forks](https://img.shields.io/github/forks/aksingh82/CVE-2024-57401.svg)


## CVE-2024-55457
 MasterSAM Star Gate 11 is vulnerable to directory traversal via /adama/adama/downloadService. An attacker can exploit this vulnerability by manipulating the file parameter to access arbitrary files on the server, potentially exposing sensitive information.

- [https://github.com/h13nh04ng/CVE-2024-55457-PoC](https://github.com/h13nh04ng/CVE-2024-55457-PoC) :  ![starts](https://img.shields.io/github/stars/h13nh04ng/CVE-2024-55457-PoC.svg) ![forks](https://img.shields.io/github/forks/h13nh04ng/CVE-2024-55457-PoC.svg)


## CVE-2024-43768
 In skia_alloc_func of SkDeflate.cpp, there is a possible out of bounds write due to an integer overflow. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/Mahesh-970/CVE-2024-43768](https://github.com/Mahesh-970/CVE-2024-43768) :  ![starts](https://img.shields.io/github/stars/Mahesh-970/CVE-2024-43768.svg) ![forks](https://img.shields.io/github/forks/Mahesh-970/CVE-2024-43768.svg)


## CVE-2024-43097
 In resizeToAtLeast of SkRegion.cpp, there is a possible out of bounds write due to an integer overflow. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/Mahesh-970/CVE-2024-43097](https://github.com/Mahesh-970/CVE-2024-43097) :  ![starts](https://img.shields.io/github/stars/Mahesh-970/CVE-2024-43097.svg) ![forks](https://img.shields.io/github/forks/Mahesh-970/CVE-2024-43097.svg)


## CVE-2024-23346
 Pymatgen (Python Materials Genomics) is an open-source Python library for materials analysis. A critical security vulnerability exists in the `JonesFaithfulTransformation.from_transformation_str()` method within the `pymatgen` library prior to version 2024.2.20. This method insecurely utilizes `eval()` for processing input, enabling execution of arbitrary code when parsing untrusted input. Version 2024.2.20 fixes this issue.

- [https://github.com/Sanity-Archive/CVE-2024-23346](https://github.com/Sanity-Archive/CVE-2024-23346) :  ![starts](https://img.shields.io/github/stars/Sanity-Archive/CVE-2024-23346.svg) ![forks](https://img.shields.io/github/forks/Sanity-Archive/CVE-2024-23346.svg)


## CVE-2024-13489
 The LTL Freight Quotes – Old Dominion Edition plugin for WordPress is vulnerable to SQL Injection via the 'edit_id' and 'dropship_edit_id' parameters in all versions up to, and including, 4.2.10 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/RandomRobbieBF/CVE-2024-13489](https://github.com/RandomRobbieBF/CVE-2024-13489) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-13489.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-13489.svg)


## CVE-2024-13488
 The LTL Freight Quotes – Estes Edition plugin for WordPress is vulnerable to SQL Injection via the 'dropship_edit_id' and 'edit_id' parameters in all versions up to, and including, 3.3.7 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/RandomRobbieBF/CVE-2024-13488](https://github.com/RandomRobbieBF/CVE-2024-13488) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-13488.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-13488.svg)


## CVE-2024-13485
 The LTL Freight Quotes – ABF Freight Edition plugin for WordPress is vulnerable to SQL Injection via the 'edit_id' and 'dropship_edit_id' parameters in all versions up to, and including, 3.3.7 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/RandomRobbieBF/CVE-2024-13485](https://github.com/RandomRobbieBF/CVE-2024-13485) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-13485.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-13485.svg)


## CVE-2024-13483
 The LTL Freight Quotes – SAIA Edition plugin for WordPress is vulnerable to SQL Injection via the 'edit_id' and 'dropship_edit_id' parameters in all versions up to, and including, 2.2.10 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/RandomRobbieBF/CVE-2024-13483](https://github.com/RandomRobbieBF/CVE-2024-13483) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-13483.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-13483.svg)


## CVE-2024-13481
 The LTL Freight Quotes – R+L Carriers Edition plugin for WordPress is vulnerable to SQL Injection via the 'edit_id' and 'dropship_edit_id' parameters in all versions up to, and including, 3.3.4 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/RandomRobbieBF/CVE-2024-13481](https://github.com/RandomRobbieBF/CVE-2024-13481) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-13481.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-13481.svg)


## CVE-2024-13479
 The LTL Freight Quotes – SEFL Edition plugin for WordPress is vulnerable to SQL Injection via the 'dropship_edit_id' and 'edit_id' parameters in all versions up to, and including, 3.2.4 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/RandomRobbieBF/CVE-2024-13479](https://github.com/RandomRobbieBF/CVE-2024-13479) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-13479.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-13479.svg)


## CVE-2024-13478
 The LTL Freight Quotes – TForce Edition plugin for WordPress is vulnerable to SQL Injection via the 'dropship_edit_id' and 'edit_id' parameters in all versions up to, and including, 3.6.4 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/RandomRobbieBF/CVE-2024-13478](https://github.com/RandomRobbieBF/CVE-2024-13478) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-13478.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-13478.svg)


## CVE-2024-3273
 ** UNSUPPORTED WHEN ASSIGNED ** A vulnerability, which was classified as critical, was found in D-Link DNS-320L, DNS-325, DNS-327L and DNS-340L up to 20240403. Affected is an unknown function of the file /cgi-bin/nas_sharing.cgi of the component HTTP GET Request Handler. The manipulation of the argument system leads to command injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-259284. NOTE: This vulnerability only affects products that are no longer supported by the maintainer. NOTE: Vendor was contacted early and confirmed immediately that the product is end-of-life. It should be retired and replaced.

- [https://github.com/GSTEINF/CVE-2024-3273](https://github.com/GSTEINF/CVE-2024-3273) :  ![starts](https://img.shields.io/github/stars/GSTEINF/CVE-2024-3273.svg) ![forks](https://img.shields.io/github/forks/GSTEINF/CVE-2024-3273.svg)


## CVE-2024-2961
 The iconv() function in the GNU C Library versions 2.39 and older may overflow the output buffer passed to it by up to 4 bytes when converting strings to the ISO-2022-CN-EXT character set, which may be used to crash an application or overwrite a neighbouring variable.

- [https://github.com/regantemudo/PHP-file-read-to-RCE-CVE-2024-2961-](https://github.com/regantemudo/PHP-file-read-to-RCE-CVE-2024-2961-) :  ![starts](https://img.shields.io/github/stars/regantemudo/PHP-file-read-to-RCE-CVE-2024-2961-.svg) ![forks](https://img.shields.io/github/forks/regantemudo/PHP-file-read-to-RCE-CVE-2024-2961-.svg)


## CVE-2024-1651
This is possible because the application is vulnerable to insecure deserialization.

- [https://github.com/killukeren/cve-2024-1651](https://github.com/killukeren/cve-2024-1651) :  ![starts](https://img.shields.io/github/stars/killukeren/cve-2024-1651.svg) ![forks](https://img.shields.io/github/forks/killukeren/cve-2024-1651.svg)


## CVE-2023-4220
 Unrestricted file upload in big file upload functionality in `/main/inc/lib/javascript/bigupload/inc/bigUpload.php` in Chamilo LMS = v1.11.24 allows unauthenticated attackers to perform stored cross-site scripting attacks and obtain remote code execution via uploading of web shell.

- [https://github.com/N1ghtfallXxX/CVE-2023-4220](https://github.com/N1ghtfallXxX/CVE-2023-4220) :  ![starts](https://img.shields.io/github/stars/N1ghtfallXxX/CVE-2023-4220.svg) ![forks](https://img.shields.io/github/forks/N1ghtfallXxX/CVE-2023-4220.svg)

