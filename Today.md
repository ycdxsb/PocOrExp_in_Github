# Update 2026-07-18
## CVE-2026-58457
 Shenzhen Aitemi M300 Wi-Fi Repeater (hardware model MT02) contains an unauthenticated OS command injection vulnerability that allows network-adjacent attackers to execute arbitrary shell commands by injecting unsanitized input through the smacfilter_conf handler in the commuos web backend. Attackers can append semicolon-delimited payloads to the name, enable, or mac GET parameters, which are passed without sanitization into sprintf() to build uci shell commands executed via doSystemCmdComlib(), granting full root-level control of the device.

- [https://github.com/J4ck3LSyN-Gen2/CVE-2026-58457](https://github.com/J4ck3LSyN-Gen2/CVE-2026-58457) :  ![starts](https://img.shields.io/github/stars/J4ck3LSyN-Gen2/CVE-2026-58457.svg) ![forks](https://img.shields.io/github/forks/J4ck3LSyN-Gen2/CVE-2026-58457.svg)


## CVE-2026-57821
 A SQL Injection vulnerability exists in Apache Fineract's Office Search API (GET /api/v1/offices) in versions up to and including 1.14.0. The orderBy request parameter is concatenated into a SQL query without sufficient validation, allowing an authenticated user with permission to view offices to inject arbitrary SQL via a crafted orderBy value. This is a bypass of the ColumnValidator fix introduced for CVE-2024-32838, which does not detect bare subqueries in the ORDER BY position. This can be leveraged to perform time-based blind SQL injection for data exfiltration. Because the injected query blocks the database connection for its full duration, concurrent exploitation can exhaust the application's database connection pool, resulting in denial of service for other users. Users are recommended to upgrade to a version containing the fix.

- [https://github.com/tc4dy/CVE-2026-57821-PoC-Exploit](https://github.com/tc4dy/CVE-2026-57821-PoC-Exploit) :  ![starts](https://img.shields.io/github/stars/tc4dy/CVE-2026-57821-PoC-Exploit.svg) ![forks](https://img.shields.io/github/forks/tc4dy/CVE-2026-57821-PoC-Exploit.svg)


## CVE-2026-54992
 Heap-based buffer overflow in Windows Message Queuing Queue Manager allows an unauthorized attacker to execute code locally.

- [https://github.com/DavidCarliez/CVE-2026-54992-PoC](https://github.com/DavidCarliez/CVE-2026-54992-PoC) :  ![starts](https://img.shields.io/github/stars/DavidCarliez/CVE-2026-54992-PoC.svg) ![forks](https://img.shields.io/github/forks/DavidCarliez/CVE-2026-54992-PoC.svg)


## CVE-2026-53359
use-after-free.

- [https://github.com/x024n/kvm-kernelcare-januscape](https://github.com/x024n/kvm-kernelcare-januscape) :  ![starts](https://img.shields.io/github/stars/x024n/kvm-kernelcare-januscape.svg) ![forks](https://img.shields.io/github/forks/x024n/kvm-kernelcare-januscape.svg)


## CVE-2026-50369
 Use after free in Windows Remote Desktop Services allows an authorized attacker to elevate privileges over a network.

- [https://github.com/syxlox/CVE-2026-50369](https://github.com/syxlox/CVE-2026-50369) :  ![starts](https://img.shields.io/github/stars/syxlox/CVE-2026-50369.svg) ![forks](https://img.shields.io/github/forks/syxlox/CVE-2026-50369.svg)


## CVE-2026-50343
 Improper privilege management in Microsoft Install Service allows an authorized attacker to elevate privileges locally.

- [https://github.com/Rat5ak/CVE-2026-50343-InstallService-EoP](https://github.com/Rat5ak/CVE-2026-50343-InstallService-EoP) :  ![starts](https://img.shields.io/github/stars/Rat5ak/CVE-2026-50343-InstallService-EoP.svg) ![forks](https://img.shields.io/github/forks/Rat5ak/CVE-2026-50343-InstallService-EoP.svg)


## CVE-2026-50011
 Netty is a network application framework for development of protocol servers and clients. Prior to versions 4.1.135.Final and 4.2.15.Final, RedisArrayAggregator pre-allocates ArrayList with initial capacity equal to the RESP array element count declared in an array header. That count is taken from the wire before the corresponding child messages exist. A small malicious header can claim a huge initial capacity. Versions 4.1.135.Final and 4.2.15.Final patch the issue.

- [https://github.com/bibotai/secveri-cve-2026-50011-positive](https://github.com/bibotai/secveri-cve-2026-50011-positive) :  ![starts](https://img.shields.io/github/stars/bibotai/secveri-cve-2026-50011-positive.svg) ![forks](https://img.shields.io/github/forks/bibotai/secveri-cve-2026-50011-positive.svg)
- [https://github.com/bibotai/secveri-cve-2026-50011-negative](https://github.com/bibotai/secveri-cve-2026-50011-negative) :  ![starts](https://img.shields.io/github/stars/bibotai/secveri-cve-2026-50011-negative.svg) ![forks](https://img.shields.io/github/forks/bibotai/secveri-cve-2026-50011-negative.svg)


## CVE-2026-47729
 Squid is a caching proxy for the Web. Prior to 7.6, due to an improper validation of syntactic correctness of input in the FTP gateway (src/clients/FtpGateway.cc), Squid is vulnerable to an out-of-bounds read: when a listing entry date in the TypeA or TypeB directory-listing formats is not followed by a filename, parsing was not restricted to the input buffer, so a trusted client accessing a misbehaving FTP server through Squid's gateway feature could read memory from random unrelated transactions. This issue is fixed in version 7.6.

- [https://github.com/0xBlackash/CVE-2026-47729](https://github.com/0xBlackash/CVE-2026-47729) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-47729.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-47729.svg)


## CVE-2026-46726
Users are recommended to upgrade to version 4.21.0, which fixes the issue. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.8. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.3. The fix makes the affected consumers apply a HeaderFilterStrategy that filters the Camel header namespace case-insensitively on inbound mapping, so externally-supplied Camel* / camel* headers are no longer copied into the Exchange. For deployments that cannot upgrade immediately, strip the Camel control headers from the inbound message before they reach any downstream producer (for example removeHeaders('Camel*') and removeHeaders('camel*') at the start of the route), require authentication on the WebSocket endpoint, and avoid bridging an untrusted consumer directly into an HTTP producer whose target URI can be driven from message headers.

- [https://github.com/oscerd/CVE-2026-46726](https://github.com/oscerd/CVE-2026-46726) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-46726.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-46726.svg)


## CVE-2026-46592
Users are recommended to upgrade to version 4.21.0, which fixes the issue. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.8. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.3. After upgrading, the operation-selection headers are named CamelCxfOperationName / CamelCxfOperationNamespace and are filtered at transport boundaries; see the 4.21 upgrade guide for the cross-transport carrier-header pattern. For deployments that cannot upgrade immediately, do not select the CXF operation from untrusted input: strip the operationName and operationNamespace headers from any untrusted ingress before the cxf: producer and set the operation from a trusted source in the route.

- [https://github.com/oscerd/CVE-2026-46592](https://github.com/oscerd/CVE-2026-46592) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-46592.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-46592.svg)


## CVE-2026-44596
 Yamcs is a mission control framework. Prior to 5.12.7, the authentication endpoint POST /auth/token in yamcs-core, handled by yamcs-core/src/main/java/org/yamcs/http/auth/AuthHandler.java, lacked any rate limiting, account lockout, or failed-attempt throttling, so an unauthenticated remote attacker could perform unlimited password-guessing attempts against any user account, significantly increasing the risk of successful brute-force attacks. This issue is fixed in versions 5.12.7 and 5.13.0.

- [https://github.com/ex-cal1bur/CVE-2026-44596](https://github.com/ex-cal1bur/CVE-2026-44596) :  ![starts](https://img.shields.io/github/stars/ex-cal1bur/CVE-2026-44596.svg) ![forks](https://img.shields.io/github/forks/ex-cal1bur/CVE-2026-44596.svg)


## CVE-2026-44595
 Yamcs is a mission control framework. Prior to 5.12.7, the IAM API endpoints listUsers, getUser, listGroups, and getGroup in yamcs-core did not enforce the required SystemPrivilege.ControlAccess check in yamcs-core/src/main/java/org/yamcs/http/api/IamApi.java, so any authenticated user, even one with low or no privileges, could enumerate all user accounts in the system including their usernames, superuser status, and group memberships. This issue is fixed in versions 5.12.7 and 5.13.0.

- [https://github.com/ex-cal1bur/CVE-2026-44595](https://github.com/ex-cal1bur/CVE-2026-44595) :  ![starts](https://img.shields.io/github/stars/ex-cal1bur/CVE-2026-44595.svg) ![forks](https://img.shields.io/github/forks/ex-cal1bur/CVE-2026-44595.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/BuSung-dev/CVE-2026-43499-S25U](https://github.com/BuSung-dev/CVE-2026-43499-S25U) :  ![starts](https://img.shields.io/github/stars/BuSung-dev/CVE-2026-43499-S25U.svg) ![forks](https://img.shields.io/github/forks/BuSung-dev/CVE-2026-43499-S25U.svg)
- [https://github.com/ayyy7128/CVE-2026-43499-jinghu](https://github.com/ayyy7128/CVE-2026-43499-jinghu) :  ![starts](https://img.shields.io/github/stars/ayyy7128/CVE-2026-43499-jinghu.svg) ![forks](https://img.shields.io/github/forks/ayyy7128/CVE-2026-43499-jinghu.svg)
- [https://github.com/2932796375github/CVE-2026-43499_OPPO-MT6835](https://github.com/2932796375github/CVE-2026-43499_OPPO-MT6835) :  ![starts](https://img.shields.io/github/stars/2932796375github/CVE-2026-43499_OPPO-MT6835.svg) ![forks](https://img.shields.io/github/forks/2932796375github/CVE-2026-43499_OPPO-MT6835.svg)
- [https://github.com/DistrictBlauw/CyberMeowfia-ace3](https://github.com/DistrictBlauw/CyberMeowfia-ace3) :  ![starts](https://img.shields.io/github/stars/DistrictBlauw/CyberMeowfia-ace3.svg) ![forks](https://img.shields.io/github/forks/DistrictBlauw/CyberMeowfia-ace3.svg)
- [https://github.com/SlightNeko/ghostlock-rothko](https://github.com/SlightNeko/ghostlock-rothko) :  ![starts](https://img.shields.io/github/stars/SlightNeko/ghostlock-rothko.svg) ![forks](https://img.shields.io/github/forks/SlightNeko/ghostlock-rothko.svg)


## CVE-2026-43494
rds_message_zcopy_from_user().

- [https://github.com/jayhutajulu1/CVE-2026-43494-PinTheft-PoC](https://github.com/jayhutajulu1/CVE-2026-43494-PinTheft-PoC) :  ![starts](https://img.shields.io/github/stars/jayhutajulu1/CVE-2026-43494-PinTheft-PoC.svg) ![forks](https://img.shields.io/github/forks/jayhutajulu1/CVE-2026-43494-PinTheft-PoC.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/jayhutajulu1/CVE-2026-43284-DirtyFrag-PoC](https://github.com/jayhutajulu1/CVE-2026-43284-DirtyFrag-PoC) :  ![starts](https://img.shields.io/github/stars/jayhutajulu1/CVE-2026-43284-DirtyFrag-PoC.svg) ![forks](https://img.shields.io/github/forks/jayhutajulu1/CVE-2026-43284-DirtyFrag-PoC.svg)


## CVE-2026-42533
 Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/0xCyberstan/CVE-2026-42533-Config-Scanner](https://github.com/0xCyberstan/CVE-2026-42533-Config-Scanner) :  ![starts](https://img.shields.io/github/stars/0xCyberstan/CVE-2026-42533-Config-Scanner.svg) ![forks](https://img.shields.io/github/forks/0xCyberstan/CVE-2026-42533-Config-Scanner.svg)


## CVE-2026-40083
 Cacti is an open source performance and fault management framework. Versions 1.2.30 and prior have SQL Injection through unsanitized unserialize+implode in managers.php.  At line 756 of managers.php, the application assigns $selected_items by calling cacti_unserialize(stripslashes(gnrv('selected_graphs_array'))). The  cacti_unserialize() function calls unserialize() with allowed_classes set to false, which prevents object injection but still allows arbitrary string  arrays to be deserialized. Then, at lines 760 to 766, the deserialized array values are passed directly into db_execute('DELETE FROM snmpagent_managers  WHERE id IN (' . implode(',', $selected_items) . ')'), where they are imploded into the SQL statement without any integer validation, resulting in SQL  Injection when using SNMP agent management permissions. This issue has been fixed in version 1.2.31.

- [https://github.com/hakaioffsec/CVE-2026-40083](https://github.com/hakaioffsec/CVE-2026-40083) :  ![starts](https://img.shields.io/github/stars/hakaioffsec/CVE-2026-40083.svg) ![forks](https://img.shields.io/github/forks/hakaioffsec/CVE-2026-40083.svg)


## CVE-2026-36425
 An issue in OPSWAT AppRemover Driver (ardrv.sys) v2017.10.02.1551 and earlier in IOCTL handler 0x2420031. Any local user can open the device and send process termination requests without privilege validation.

- [https://github.com/redteamfortress/CVE-2026-36425](https://github.com/redteamfortress/CVE-2026-36425) :  ![starts](https://img.shields.io/github/stars/redteamfortress/CVE-2026-36425.svg) ![forks](https://img.shields.io/github/forks/redteamfortress/CVE-2026-36425.svg)


## CVE-2026-34197
Users are recommended to upgrade to version 5.19.4 or 6.2.3, which fixes the issue

- [https://github.com/K3ysTr0K3R/CVE-2026-34197](https://github.com/K3ysTr0K3R/CVE-2026-34197) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2026-34197.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2026-34197.svg)


## CVE-2026-33634
 Trivy is a security scanner. On March 19, 2026, a threat actor used compromised credentials to publish a malicious Trivy v0.69.4 release, force-push 76 of 77 version tags in `aquasecurity/trivy-action` to credential-stealing malware, and replace all 7 tags in `aquasecurity/setup-trivy` with malicious commits. This incident is a continuation of the supply chain attack that began in late February 2026. Following the initial disclosure on March 1, credential rotation was performed but was not atomic (not all credentials were revoked simultaneously). The attacker could have use a valid token to exfiltrate newly rotated secrets during the rotation window (which lasted a few days). This could have allowed the attacker to retain access and execute the March 19 attack. Affected components include the `aquasecurity/trivy` Go / Container image version 0.69.4, the `aquasecurity/trivy-action` GitHub Action versions 0.0.1 – 0.34.2 (76/77), and the`aquasecurity/setup-trivy` GitHub Action versions 0.2.0 – 0.2.6, prior to the recreation of 0.2.6 with a safe commit. Known safe versions include versions 0.69.2 and 0.69.3 of the Trivy binary, version 0.35.0 of trivy-action, and version 0.2.6 of setup-trivy. Additionally, take other mitigations to ensure the safety of secrets. If there is any possibility that a compromised version ran in one's environment, all secrets accessible to affected pipelines must be treated as exposed and rotated immediately. Check whether one's organization pulled or executed Trivy v0.69.4 from any source. Remove any affected artifacts immediately. Review all workflows using `aquasecurity/trivy-action` or `aquasecurity/setup-trivy`. Those who referenced a version tag rather than a full commit SHA should check workflow run logs from March 19–20, 2026 for signs of compromise. Look for repositories named `tpcp-docs` in one's GitHub organization. The presence of such a repository may indicate that the fallback exfiltration mechanism was triggered and secrets were successfully stolen. Pin GitHub Actions to full, immutable commit SHA hashes, don't use mutable version tags.

- [https://github.com/dfs333/trivysupplychainanalysis](https://github.com/dfs333/trivysupplychainanalysis) :  ![starts](https://img.shields.io/github/stars/dfs333/trivysupplychainanalysis.svg) ![forks](https://img.shields.io/github/forks/dfs333/trivysupplychainanalysis.svg)


## CVE-2026-33017
 Langflow is a tool for building and deploying AI-powered agents and workflows. In versions prior to 1.9.0, the POST /api/v1/build_public_tmp/{flow_id}/flow endpoint allows building public flows without requiring authentication. When the optional data parameter is supplied, the endpoint uses attacker-controlled flow data (containing arbitrary Python code in node definitions) instead of the stored flow data from the database. This code is passed to exec() with zero sandboxing, resulting in unauthenticated remote code execution. This is distinct from CVE-2025-3248, which fixed /api/v1/validate/code by adding authentication. The build_public_tmp endpoint is designed to be unauthenticated (for public flows) but incorrectly accepts attacker-supplied flow data containing arbitrary executable code. This issue has been fixed in version 1.9.0.

- [https://github.com/Industri4l-H3ll-Xpl0it3rs/CVE-2026-33017-Langflow-RCE](https://github.com/Industri4l-H3ll-Xpl0it3rs/CVE-2026-33017-Langflow-RCE) :  ![starts](https://img.shields.io/github/stars/Industri4l-H3ll-Xpl0it3rs/CVE-2026-33017-Langflow-RCE.svg) ![forks](https://img.shields.io/github/forks/Industri4l-H3ll-Xpl0it3rs/CVE-2026-33017-Langflow-RCE.svg)


## CVE-2026-25993
path / request_path values—derived from the url_key stored in the database—into SQL statements via string concatenation and passes them to execute(). As a result, if a malicious string is stored in url_key , subsequent event processing modifies and executes the SQL statement, leading to a second-order SQL injection. Patched from v2.1.1.

- [https://github.com/MoxitPanchal/EverShop-Lab-CVE-2026-25993](https://github.com/MoxitPanchal/EverShop-Lab-CVE-2026-25993) :  ![starts](https://img.shields.io/github/stars/MoxitPanchal/EverShop-Lab-CVE-2026-25993.svg) ![forks](https://img.shields.io/github/forks/MoxitPanchal/EverShop-Lab-CVE-2026-25993.svg)


## CVE-2026-21955
 Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core).  Supported versions that are affected are 7.1.14 and  7.2.4. Easily exploitable vulnerability allows high privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox.  While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in takeover of Oracle VM VirtualBox. CVSS 3.1 Base Score 8.2 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H).

- [https://github.com/minq0x1412/CVE-2026-21955](https://github.com/minq0x1412/CVE-2026-21955) :  ![starts](https://img.shields.io/github/stars/minq0x1412/CVE-2026-21955.svg) ![forks](https://img.shields.io/github/forks/minq0x1412/CVE-2026-21955.svg)


## CVE-2026-21385
 Memory corruption while using alignments for memory allocation.

- [https://github.com/DaRkZ2012/qualcomm-vulnerability-scanner](https://github.com/DaRkZ2012/qualcomm-vulnerability-scanner) :  ![starts](https://img.shields.io/github/stars/DaRkZ2012/qualcomm-vulnerability-scanner.svg) ![forks](https://img.shields.io/github/forks/DaRkZ2012/qualcomm-vulnerability-scanner.svg)


## CVE-2026-20896
 Gitea Docker image versions up to and including 1.26.2 use REVERSE_PROXY_TRUSTED_PROXIES=* by default, allowing any source IP to impersonate a user when reverse-proxy authentication headers such as X-WEBAUTH-USER are enabled.

- [https://github.com/XaocZenon/CVE-2026-20896](https://github.com/XaocZenon/CVE-2026-20896) :  ![starts](https://img.shields.io/github/stars/XaocZenon/CVE-2026-20896.svg) ![forks](https://img.shields.io/github/forks/XaocZenon/CVE-2026-20896.svg)


## CVE-2026-20833
 Use of a broken or risky cryptographic algorithm in Windows Kerberos allows an authorized attacker to disclose information locally.

- [https://github.com/AlMarWorld/KerberosAudit-PS](https://github.com/AlMarWorld/KerberosAudit-PS) :  ![starts](https://img.shields.io/github/stars/AlMarWorld/KerberosAudit-PS.svg) ![forks](https://img.shields.io/github/forks/AlMarWorld/KerberosAudit-PS.svg)


## CVE-2026-15410
 Post-authentication improper control of generation of code ('Code Injection') vulnerability has been identified in the SMA1000 Appliance Management Console (AMC) which in specific conditions could potentially enable a remote authenticated attacker as administrator to execute arbitrary OS commands.

- [https://github.com/MrRawBit/SonicWall-SMA1000-Zero-Day-IoC-Check](https://github.com/MrRawBit/SonicWall-SMA1000-Zero-Day-IoC-Check) :  ![starts](https://img.shields.io/github/stars/MrRawBit/SonicWall-SMA1000-Zero-Day-IoC-Check.svg) ![forks](https://img.shields.io/github/forks/MrRawBit/SonicWall-SMA1000-Zero-Day-IoC-Check.svg)


## CVE-2026-15409
 A Server-side request forgery (SSRF) vulnerability has been identified in the SMA1000 Appliance Work Place interface. A remote unauthenticated attacker could potentially cause the appliance to make requests to unintended location.

- [https://github.com/MrRawBit/SonicWall-SMA1000-Zero-Day-IoC-Check](https://github.com/MrRawBit/SonicWall-SMA1000-Zero-Day-IoC-Check) :  ![starts](https://img.shields.io/github/stars/MrRawBit/SonicWall-SMA1000-Zero-Day-IoC-Check.svg) ![forks](https://img.shields.io/github/forks/MrRawBit/SonicWall-SMA1000-Zero-Day-IoC-Check.svg)


## CVE-2026-14894
 The Super Forms – Drag & Drop Form Builder plugin for WordPress is vulnerable to Arbitrary File Upload in all versions up to, and including, 6.3.313 via the submit_form function. This is due to missing file type validation and the absence of any capability check on the submit_form nopriv AJAX handler, whose only barrier is a session nonce freely obtainable by unauthenticated visitors via a separate nopriv endpoint. This makes it possible for unauthenticated attackers to upload files that may be executable, which makes remote code execution possible. The nonce requirement is trivially bypassed because the super_create_nonce nopriv AJAX action allows any unauthenticated visitor to mint a valid sf_nonce and session cookie in a single prior request, reducing exploitation to two unauthenticated HTTP requests.

- [https://github.com/shinthink/CVE-2026-14894](https://github.com/shinthink/CVE-2026-14894) :  ![starts](https://img.shields.io/github/stars/shinthink/CVE-2026-14894.svg) ![forks](https://img.shields.io/github/forks/shinthink/CVE-2026-14894.svg)


## CVE-2026-13585
Security Update for ASUS System Control Interface  ' section on the ASUS Security Advisory for more information.

- [https://github.com/416rehman/asus-bsitf-0-day-poc](https://github.com/416rehman/asus-bsitf-0-day-poc) :  ![starts](https://img.shields.io/github/stars/416rehman/asus-bsitf-0-day-poc.svg) ![forks](https://img.shields.io/github/forks/416rehman/asus-bsitf-0-day-poc.svg)


## CVE-2026-13001
 The Podlove Podcast Publisher plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'podlove_handle_cache_files' function in all versions up to, and including, 4.5.1. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/sadb98523-eng/CVE-2026-13001](https://github.com/sadb98523-eng/CVE-2026-13001) :  ![starts](https://img.shields.io/github/stars/sadb98523-eng/CVE-2026-13001.svg) ![forks](https://img.shields.io/github/forks/sadb98523-eng/CVE-2026-13001.svg)


## CVE-2026-8838
To remediate this issue, users should upgrade to version 2.1.14.

- [https://github.com/Sana-404/CVE-2026-8838-Mitigation-and-Detection](https://github.com/Sana-404/CVE-2026-8838-Mitigation-and-Detection) :  ![starts](https://img.shields.io/github/stars/Sana-404/CVE-2026-8838-Mitigation-and-Detection.svg) ![forks](https://img.shields.io/github/forks/Sana-404/CVE-2026-8838-Mitigation-and-Detection.svg)


## CVE-2026-8388
 Incorrect boundary conditions in the JavaScript Engine: JIT component. This vulnerability was fixed in Firefox 150.0.3, Firefox ESR 115.36, Firefox ESR 140.11, and Thunderbird 140.11.

- [https://github.com/Sana-404/CVE-2026-8388-Mitigation-and-Detection](https://github.com/Sana-404/CVE-2026-8388-Mitigation-and-Detection) :  ![starts](https://img.shields.io/github/stars/Sana-404/CVE-2026-8388-Mitigation-and-Detection.svg) ![forks](https://img.shields.io/github/forks/Sana-404/CVE-2026-8388-Mitigation-and-Detection.svg)


## CVE-2026-5715
 The Voyage Plus plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'class' attribute of the 'post-content' shortcode in all versions up to, and including, 1.0.6 due to insufficient input sanitization and output escaping on user supplied attributes. This makes it possible for authenticated attackers, with contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/babyshen/CVE-2026-57155](https://github.com/babyshen/CVE-2026-57155) :  ![starts](https://img.shields.io/github/stars/babyshen/CVE-2026-57155.svg) ![forks](https://img.shields.io/github/forks/babyshen/CVE-2026-57155.svg)


## CVE-2026-5557
 A vulnerability was detected in badlogic pi-mono up to 0.58.4. This issue affects some unknown processing of the file packages/mom/src/slack.ts of the component pi-mom Slack Bot. The manipulation results in authentication bypass using alternate channel. The attack can be executed remotely. The exploit is now public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/Ch4120N/CVE-2026-55579](https://github.com/Ch4120N/CVE-2026-55579) :  ![starts](https://img.shields.io/github/stars/Ch4120N/CVE-2026-55579.svg) ![forks](https://img.shields.io/github/forks/Ch4120N/CVE-2026-55579.svg)


## CVE-2026-3180
 The Contest Gallery – Upload & Vote Photos, Media, Sell with PayPal & Stripe plugin for WordPress is vulnerable to blind SQL Injection via the ‘cgLostPasswordEmail’ and the ’cgl_mail’ parameter in all versions up to, and including, 28.1.4 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database. The vulnerability's ’cgLostPasswordEmail’ parameter was patched in version 28.1.4, and the ’cgl_mail’ parameter was patched in version 28.1.5.

- [https://github.com/CerberusMrXi/WP-Contest-Gallery-28.1.4-Exploit](https://github.com/CerberusMrXi/WP-Contest-Gallery-28.1.4-Exploit) :  ![starts](https://img.shields.io/github/stars/CerberusMrXi/WP-Contest-Gallery-28.1.4-Exploit.svg) ![forks](https://img.shields.io/github/forks/CerberusMrXi/WP-Contest-Gallery-28.1.4-Exploit.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg)


## CVE-2025-54793
 Astro is a web framework for content-driven websites. In versions 5.2.0 through 5.12.7, there is an Open Redirect vulnerability in the trailing slash redirection logic when handling paths with double slashes. This allows an attacker to redirect users to arbitrary external domains by crafting URLs such as https://mydomain.com//malicious-site.com/. This increases the risk of phishing and other social engineering attacks. This affects sites that use on-demand rendering (SSR) with the Node or Cloudflare adapters. It does not affect static sites, or sites deployed to Netlify or Vercel. This issue is fixed in version 5.12.8. To work around this issue at the network level, block outgoing redirect responses with a Location header value that starts with `//`.

- [https://github.com/xxisem9090/xi-sem.github.io](https://github.com/xxisem9090/xi-sem.github.io) :  ![starts](https://img.shields.io/github/stars/xxisem9090/xi-sem.github.io.svg) ![forks](https://img.shields.io/github/forks/xxisem9090/xi-sem.github.io.svg)


## CVE-2025-8110
 Improper Symbolic link handling in the PutContents API in Gogs allows Local Execution of Code.

- [https://github.com/Xdezen/CVE-2025-8110](https://github.com/Xdezen/CVE-2025-8110) :  ![starts](https://img.shields.io/github/stars/Xdezen/CVE-2025-8110.svg) ![forks](https://img.shields.io/github/forks/Xdezen/CVE-2025-8110.svg)


## CVE-2025-5878
 A vulnerability was found in ESAPI esapi-java-legacy and classified as problematic. This issue affects the interface Encoder.encodeForSQL of the SQL Injection Defense. An attack leads to an improper neutralization of special elements. The attack may be initiated remotely and an exploit has been disclosed to the public. The project was contacted early about this issue and handled it with an exceptional level of professionalism. Upgrading to version 2.7.0.0 is able to address this issue. Commit ID f75ac2c2647a81d2cfbdc9c899f8719c240ed512 is disabling the feature by default and any attempt to use it will trigger a warning. And commit ID e2322914304d9b1c52523ff24be495b7832f6a56 is updating the misleading Java class documentation to warn about the risks.

- [https://github.com/fantasy-fql/ESAPI-SQLinjection-CVE-2025-5878-Exploit](https://github.com/fantasy-fql/ESAPI-SQLinjection-CVE-2025-5878-Exploit) :  ![starts](https://img.shields.io/github/stars/fantasy-fql/ESAPI-SQLinjection-CVE-2025-5878-Exploit.svg) ![forks](https://img.shields.io/github/forks/fantasy-fql/ESAPI-SQLinjection-CVE-2025-5878-Exploit.svg)


## CVE-2024-53104
uvc_parse_streaming.

- [https://github.com/runtimeverification/kernel-c-to-rust-spike](https://github.com/runtimeverification/kernel-c-to-rust-spike) :  ![starts](https://img.shields.io/github/stars/runtimeverification/kernel-c-to-rust-spike.svg) ![forks](https://img.shields.io/github/forks/runtimeverification/kernel-c-to-rust-spike.svg)


## CVE-2024-25600
 Improper Control of Generation of Code ('Code Injection') vulnerability in Codeer Limited Bricks Builder allows Code Injection.This issue affects Bricks Builder: from n/a through 1.9.6.

- [https://github.com/CerberusMrXi/WP-Bricks-Exploit-CVE-2024-25600](https://github.com/CerberusMrXi/WP-Bricks-Exploit-CVE-2024-25600) :  ![starts](https://img.shields.io/github/stars/CerberusMrXi/WP-Bricks-Exploit-CVE-2024-25600.svg) ![forks](https://img.shields.io/github/forks/CerberusMrXi/WP-Bricks-Exploit-CVE-2024-25600.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/BLACK-ARCHIVERS/CVE-2024-4577](https://github.com/BLACK-ARCHIVERS/CVE-2024-4577) :  ![starts](https://img.shields.io/github/stars/BLACK-ARCHIVERS/CVE-2024-4577.svg) ![forks](https://img.shields.io/github/forks/BLACK-ARCHIVERS/CVE-2024-4577.svg)

