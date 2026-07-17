# Update 2026-07-17
## CVE-2026-59827
 Metabase is an open-source business intelligence and embedded analytics tool. Prior to 1.58.15, 1.59.12, 1.60.6.3, and 1.61.1.4, Metabase instances with an H2 database connection, including the default sample database, deserialize arbitrary Java objects returned in H2 native query result columns of type OTHER without validation, allowing an authenticated user who can run native H2 queries to execute code on the Metabase server. This issue is fixed in versions 1.58.15, 1.59.12, 1.60.6.3, and 1.61.1.4.

- [https://github.com/c0gnit00/CVE-2026-59827](https://github.com/c0gnit00/CVE-2026-59827) :  ![starts](https://img.shields.io/github/stars/c0gnit00/CVE-2026-59827.svg) ![forks](https://img.shields.io/github/forks/c0gnit00/CVE-2026-59827.svg)


## CVE-2026-58635
 Improper neutralization of special elements used in a command ('command injection') in Windows Narrator Braille allows an authorized attacker to elevate privileges locally.

- [https://github.com/DavidCarliez/CVE-2026-58635-PoC](https://github.com/DavidCarliez/CVE-2026-58635-PoC) :  ![starts](https://img.shields.io/github/stars/DavidCarliez/CVE-2026-58635-PoC.svg) ![forks](https://img.shields.io/github/forks/DavidCarliez/CVE-2026-58635-PoC.svg)


## CVE-2026-58138
 Orkes Conductor 3.21.21 before 3.30.2 contains an unauthenticated remote code execution vulnerability that allows remote attackers to execute arbitrary OS commands by submitting inline workflow definitions containing malicious JavaScript or Python expressions to the workflow API endpoint prior to authentication. Attackers can exploit unsandboxed GraalVM evaluators configured with HostAccess.ALL or allowAllAccess(true) through INLINE, LAMBDA, DO_WHILE, and SWITCH task types to invoke arbitrary system commands via Java reflection or direct subprocess calls.

- [https://github.com/Ch4120N/CVE-2026-58138](https://github.com/Ch4120N/CVE-2026-58138) :  ![starts](https://img.shields.io/github/stars/Ch4120N/CVE-2026-58138.svg) ![forks](https://img.shields.io/github/forks/Ch4120N/CVE-2026-58138.svg)
- [https://github.com/seqra/cve-2026-58138](https://github.com/seqra/cve-2026-58138) :  ![starts](https://img.shields.io/github/stars/seqra/cve-2026-58138.svg) ![forks](https://img.shields.io/github/forks/seqra/cve-2026-58138.svg)


## CVE-2026-57239
 The user-controllable executable files will be directly executed by high-privilege processes, allowing low-privilege users to have the opportunity to elevate their privileges to NT AUTHORITY\SYSTEM.

- [https://github.com/Paradoxis/CVE-2026-57239](https://github.com/Paradoxis/CVE-2026-57239) :  ![starts](https://img.shields.io/github/stars/Paradoxis/CVE-2026-57239.svg) ![forks](https://img.shields.io/github/forks/Paradoxis/CVE-2026-57239.svg)


## CVE-2026-56164
 Missing authentication for critical function in Microsoft Office SharePoint allows an unauthorized attacker to elevate privileges over a network.

- [https://github.com/sentinel-aidefense/CVE-2026-56164-EXP](https://github.com/sentinel-aidefense/CVE-2026-56164-EXP) :  ![starts](https://img.shields.io/github/stars/sentinel-aidefense/CVE-2026-56164-EXP.svg) ![forks](https://img.shields.io/github/forks/sentinel-aidefense/CVE-2026-56164-EXP.svg)


## CVE-2026-53359
use-after-free.

- [https://github.com/ndouglas-cloudsmith/CVE-2026-53359](https://github.com/ndouglas-cloudsmith/CVE-2026-53359) :  ![starts](https://img.shields.io/github/stars/ndouglas-cloudsmith/CVE-2026-53359.svg) ![forks](https://img.shields.io/github/forks/ndouglas-cloudsmith/CVE-2026-53359.svg)
- [https://github.com/x024n/almalinux-januscape-mitigation](https://github.com/x024n/almalinux-januscape-mitigation) :  ![starts](https://img.shields.io/github/stars/x024n/almalinux-januscape-mitigation.svg) ![forks](https://img.shields.io/github/forks/x024n/almalinux-januscape-mitigation.svg)


## CVE-2026-50657
 Exposure of private personal information to an unauthorized actor in Microsoft Defender allows an authorized attacker to disclose information locally.

- [https://github.com/NeseOS-Corp/CVE-2026-50657](https://github.com/NeseOS-Corp/CVE-2026-50657) :  ![starts](https://img.shields.io/github/stars/NeseOS-Corp/CVE-2026-50657.svg) ![forks](https://img.shields.io/github/forks/NeseOS-Corp/CVE-2026-50657.svg)


## CVE-2026-49352
 9Router is an AI router & token saver. From 0.2.21 until 0.4.44, 9Router used the hardcoded fallback JWT secret 9router-default-secret-change-me in src/app/api/auth/login/route.js, src/middleware.js, and later src/lib/auth/dashboardSession.js, allowing attackers to forge an auth_token cookie when JWT_SECRET was unset. This issue is fixed in version 0.4.44

- [https://github.com/covepseng/cve-2026-49352-poc](https://github.com/covepseng/cve-2026-49352-poc) :  ![starts](https://img.shields.io/github/stars/covepseng/cve-2026-49352-poc.svg) ![forks](https://img.shields.io/github/forks/covepseng/cve-2026-49352-poc.svg)


## CVE-2026-48909
 SP LMS (com_splms)  4.1.4 by JoomShaper deserializes user-controlled cookie data without validation, enabling an unauthenticated remote attacker to execute arbitrary code on the server.

- [https://github.com/CerberusMrXi/CVE-2026-48909-Joomla-SP-Exploit](https://github.com/CerberusMrXi/CVE-2026-48909-Joomla-SP-Exploit) :  ![starts](https://img.shields.io/github/stars/CerberusMrXi/CVE-2026-48909-Joomla-SP-Exploit.svg) ![forks](https://img.shields.io/github/forks/CerberusMrXi/CVE-2026-48909-Joomla-SP-Exploit.svg)


## CVE-2026-48282
 ColdFusion versions 2025.9, 2023.20 and earlier are affected by an Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability that could lead to arbitrary code execution in the context of the current user. Exploitation of this issue does not require user interaction. Scope is changed.

- [https://github.com/arpit-bansal15/cve-2026-48282-pentest-lab](https://github.com/arpit-bansal15/cve-2026-48282-pentest-lab) :  ![starts](https://img.shields.io/github/stars/arpit-bansal15/cve-2026-48282-pentest-lab.svg) ![forks](https://img.shields.io/github/forks/arpit-bansal15/cve-2026-48282-pentest-lab.svg)


## CVE-2026-46591
Users are recommended to upgrade to version 4.21.0, which fixes the issue. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.8. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.3. For deployments that cannot upgrade immediately, do not populate the CamelNeo4jMatchProperties map from untrusted input: validate or allow-list the property names (for example against ^[A-Za-z_][A-Za-z0-9_]*$) before the Neo4j producer, and ensure that any consumer feeding such a route filters inbound Camel* / camel* headers so the match header cannot be supplied by an external sender.

- [https://github.com/oscerd/CVE-2026-46591](https://github.com/oscerd/CVE-2026-46591) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-46591.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-46591.svg)


## CVE-2026-46590
Users are recommended to upgrade to version 4.21.0, which fixes the issue. If users are on the 4.18.x LTS releases stream, then they are suggested to upgrade to 4.18.3. For deployments that cannot upgrade immediately, restrict write access to the key backend so that only the application's own identity can write the camel-pqc secrets (least-privilege HashiCorp Vault policies and secretsmanager:PutSecretValue IAM), and keep the PQC key material in a backend separate from any data that less-trusted principals can write.

- [https://github.com/oscerd/CVE-2026-46590](https://github.com/oscerd/CVE-2026-46590) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-46590.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-46590.svg)


## CVE-2026-46588
Users are recommended to upgrade to version 4.14.8, 4.18.3, 4.21.0, which fixes the issue.

- [https://github.com/oscerd/CVE-2026-46588](https://github.com/oscerd/CVE-2026-46588) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-46588.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-46588.svg)


## CVE-2026-46587
Users are recommended to upgrade to version 4.14.8, 4.18.3, 4.21.0, which fixes the issue.

- [https://github.com/oscerd/CVE-2026-46587](https://github.com/oscerd/CVE-2026-46587) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-46587.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-46587.svg)


## CVE-2026-46585
Users are recommended to upgrade to version 4.21.0, which fixes the issue. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.8. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.3. After upgrading, routes that set the query via the raw header name must use CamelLuceneQuery (and CamelLuceneReturnLuceneDocs) instead of QUERY / RETURN_LUCENE_DOCS. For deployments that cannot upgrade immediately, strip the attacker-controllable headers before the Lucene producer and set the query from a trusted source (for example removeHeader('QUERY') and removeHeader('RETURN_LUCENE_DOCS'), then setHeader('QUERY', constant(...)) at the start of the route).

- [https://github.com/oscerd/CVE-2026-46585](https://github.com/oscerd/CVE-2026-46585) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-46585.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-46585.svg)


## CVE-2026-45806
 Penpot is an open-source design tool for design and code collaboration. Prior to 2.15.0, Penpot's remote image import passed the user-controlled url from frontend/src/app/main/data/workspace/media.cljs into the backend RPC method :create-file-media-object-from-url in backend/src/app/rpc/commands/media.clj, where media/download-image in backend/src/app/media.clj used the shared HTTP client without destination filtering, allowing an authenticated file editor to reach internal-only endpoints. This issue is fixed in version 2.15.0.

- [https://github.com/0xmrma/CVE-2026-45806](https://github.com/0xmrma/CVE-2026-45806) :  ![starts](https://img.shields.io/github/stars/0xmrma/CVE-2026-45806.svg) ![forks](https://img.shields.io/github/forks/0xmrma/CVE-2026-45806.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/Colorful-glassblock/duchamp-root](https://github.com/Colorful-glassblock/duchamp-root) :  ![starts](https://img.shields.io/github/stars/Colorful-glassblock/duchamp-root.svg) ![forks](https://img.shields.io/github/forks/Colorful-glassblock/duchamp-root.svg)
- [https://github.com/onesmiledx/CVE-2026-43499](https://github.com/onesmiledx/CVE-2026-43499) :  ![starts](https://img.shields.io/github/stars/onesmiledx/CVE-2026-43499.svg) ![forks](https://img.shields.io/github/forks/onesmiledx/CVE-2026-43499.svg)
- [https://github.com/qianmo-xw/CVE-2026-43499-popsicle](https://github.com/qianmo-xw/CVE-2026-43499-popsicle) :  ![starts](https://img.shields.io/github/stars/qianmo-xw/CVE-2026-43499-popsicle.svg) ![forks](https://img.shields.io/github/forks/qianmo-xw/CVE-2026-43499-popsicle.svg)
- [https://github.com/ctnBobong32/CVE-2026-43499-so-build](https://github.com/ctnBobong32/CVE-2026-43499-so-build) :  ![starts](https://img.shields.io/github/stars/ctnBobong32/CVE-2026-43499-so-build.svg) ![forks](https://img.shields.io/github/forks/ctnBobong32/CVE-2026-43499-so-build.svg)
- [https://github.com/Cxyofficial/x200-cve-2026-43499](https://github.com/Cxyofficial/x200-cve-2026-43499) :  ![starts](https://img.shields.io/github/stars/Cxyofficial/x200-cve-2026-43499.svg) ![forks](https://img.shields.io/github/forks/Cxyofficial/x200-cve-2026-43499.svg)
- [https://github.com/ctnBobong32/auto_extract_offsets](https://github.com/ctnBobong32/auto_extract_offsets) :  ![starts](https://img.shields.io/github/stars/ctnBobong32/auto_extract_offsets.svg) ![forks](https://img.shields.io/github/forks/ctnBobong32/auto_extract_offsets.svg)
- [https://github.com/HYCQAQ/Logitech-G-Cloud-GhostLock-CVE-2026-43499](https://github.com/HYCQAQ/Logitech-G-Cloud-GhostLock-CVE-2026-43499) :  ![starts](https://img.shields.io/github/stars/HYCQAQ/Logitech-G-Cloud-GhostLock-CVE-2026-43499.svg) ![forks](https://img.shields.io/github/forks/HYCQAQ/Logitech-G-Cloud-GhostLock-CVE-2026-43499.svg)


## CVE-2026-42533
 Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/0xCyberstan/CVE-2026-42533-Scanner](https://github.com/0xCyberstan/CVE-2026-42533-Scanner) :  ![starts](https://img.shields.io/github/stars/0xCyberstan/CVE-2026-42533-Scanner.svg) ![forks](https://img.shields.io/github/forks/0xCyberstan/CVE-2026-42533-Scanner.svg)


## CVE-2026-40048
Users are recommended to upgrade to version 4.20.0, which fixes the issue by replacing java.io.ObjectInputStream-based key and metadata storage with standard PKCS#8 (private key) / X.509 SubjectPublicKeyInfo (public key) Base64 JSON encoding. For users on the 4.18.x LTS releases stream, upgrade to 4.18.2.

- [https://github.com/oscerd/CVE-2026-46590](https://github.com/oscerd/CVE-2026-46590) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-46590.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-46590.svg)


## CVE-2026-36590
 An issue in EMQ NanoMQ v.0.24.9 allows a remote attacker to cause a denial of service via the nni_qos_db_set function in broker_tcp.c component

- [https://github.com/MoXie25/NanoMQ-Memory-Leak-Research](https://github.com/MoXie25/NanoMQ-Memory-Leak-Research) :  ![starts](https://img.shields.io/github/stars/MoXie25/NanoMQ-Memory-Leak-Research.svg) ![forks](https://img.shields.io/github/forks/MoXie25/NanoMQ-Memory-Leak-Research.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/TheMalwareGuardian/CVE-2026-31431](https://github.com/TheMalwareGuardian/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/TheMalwareGuardian/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/TheMalwareGuardian/CVE-2026-31431.svg)


## CVE-2026-27944
 Nginx UI is a web user interface for the Nginx web server. Prior to version 2.3.3, the /api/backup endpoint is accessible without authentication and discloses the encryption keys required to decrypt the backup in the X-Backup-Security response header. This allows an unauthenticated attacker to download a full system backup containing sensitive data (user credentials, session tokens, SSL private keys, Nginx configurations) and decrypt it immediately. This issue has been patched in version 2.3.3.

- [https://github.com/Cosm3No1de/HTB-Snapped-Writeup](https://github.com/Cosm3No1de/HTB-Snapped-Writeup) :  ![starts](https://img.shields.io/github/stars/Cosm3No1de/HTB-Snapped-Writeup.svg) ![forks](https://img.shields.io/github/forks/Cosm3No1de/HTB-Snapped-Writeup.svg)


## CVE-2026-27483
 MindsDB is a platform for building artificial intelligence from enterprise data. Prior to version 25.9.1.1, there is a path traversal vulnerability in Mindsdb's /api/files interface, which an authenticated attacker can exploit to achieve remote command execution. The vulnerability exists in the "Upload File" module, which corresponds to the API endpoint /api/files. Since the multipart file upload does not perform security checks on the uploaded file path, an attacker can perform path traversal by using `../` sequences in the filename field. The file write operation occurs before calling clear_filename and save_file, meaning there is no filtering of filenames or file types, allowing arbitrary content to be written to any path on the server. Version 25.9.1.1 patches the issue.

- [https://github.com/nabhan-mohy/cve-2026-27483-lab](https://github.com/nabhan-mohy/cve-2026-27483-lab) :  ![starts](https://img.shields.io/github/stars/nabhan-mohy/cve-2026-27483-lab.svg) ![forks](https://img.shields.io/github/forks/nabhan-mohy/cve-2026-27483-lab.svg)


## CVE-2026-26719
 Cross Site Scripting vulnerability in xxl-job-admin v.3.0.0 allows a remote attacker to execute arbitrary code via a crafted HTTP GET request containing a malicious script

- [https://github.com/Ibrahim-Sartawi/CVE-2026-26719](https://github.com/Ibrahim-Sartawi/CVE-2026-26719) :  ![starts](https://img.shields.io/github/stars/Ibrahim-Sartawi/CVE-2026-26719.svg) ![forks](https://img.shields.io/github/forks/Ibrahim-Sartawi/CVE-2026-26719.svg)


## CVE-2026-26718
 A Cross-Site Request Forgery (CSRF) vulnerability exists in the xxl-job-admin web application v.3.0.0 that allows an attacker to perform unauthorized modifications to Glue IDE shell scripts. The affected endpoint lacks proper CSRF token validation and accepts arbitrary HTTP methods via a permissive request mapping

- [https://github.com/Ibrahim-Sartawi/CVE-2026-26718](https://github.com/Ibrahim-Sartawi/CVE-2026-26718) :  ![starts](https://img.shields.io/github/stars/Ibrahim-Sartawi/CVE-2026-26718.svg) ![forks](https://img.shields.io/github/forks/Ibrahim-Sartawi/CVE-2026-26718.svg)


## CVE-2026-25541
 Bytes is a utility library for working with bytes. From version 1.2.1 to before 1.11.1, Bytes is vulnerable to integer overflow in BytesMut::reserve. In the unique reclaim path of BytesMut::reserve, if the condition "v_capacity = new_cap + offset" uses an unchecked addition. When new_cap + offset overflows usize in release builds, this condition may incorrectly pass, causing self.cap to be set to a value that exceeds the actual allocated capacity. Subsequent APIs such as spare_capacity_mut() then trust this corrupted cap value and may create out-of-bounds slices, leading to UB. This behavior is observable in release builds (integer overflow wraps), whereas debug builds panic due to overflow checks. This issue has been patched in version 1.11.1.

- [https://github.com/trajanOx/cve-2026-25541-fuel-analysis](https://github.com/trajanOx/cve-2026-25541-fuel-analysis) :  ![starts](https://img.shields.io/github/stars/trajanOx/cve-2026-25541-fuel-analysis.svg) ![forks](https://img.shields.io/github/forks/trajanOx/cve-2026-25541-fuel-analysis.svg)


## CVE-2026-21048
 Out-of-bounds write in parsing DNG format in libimagecodec.media.quram.so prior to SMR Jul-2026 Release 1 allows remote attackers to write out-of-bounds memory.

- [https://github.com/Filipemendonca1978/CVE-2026-21045_and_CVE-2026-21048](https://github.com/Filipemendonca1978/CVE-2026-21045_and_CVE-2026-21048) :  ![starts](https://img.shields.io/github/stars/Filipemendonca1978/CVE-2026-21045_and_CVE-2026-21048.svg) ![forks](https://img.shields.io/github/forks/Filipemendonca1978/CVE-2026-21045_and_CVE-2026-21048.svg)


## CVE-2026-21045
 Out-of-bounds write in parsing TIFF format in libimagecodec.media.quram.so prior to SMR Jul-2026 Release 1 allows remote attackers to write out-of-bounds memory.

- [https://github.com/Filipemendonca1978/CVE-2026-21045_and_CVE-2026-21048](https://github.com/Filipemendonca1978/CVE-2026-21045_and_CVE-2026-21048) :  ![starts](https://img.shields.io/github/stars/Filipemendonca1978/CVE-2026-21045_and_CVE-2026-21048.svg) ![forks](https://img.shields.io/github/forks/Filipemendonca1978/CVE-2026-21045_and_CVE-2026-21048.svg)


## CVE-2026-15410
 Post-authentication improper control of generation of code ('Code Injection') vulnerability has been identified in the SMA1000 Appliance Management Console (AMC) which in specific conditions could potentially enable a remote authenticated attacker as administrator to execute arbitrary OS commands.

- [https://github.com/HORKimhab/CVE-2026-15410](https://github.com/HORKimhab/CVE-2026-15410) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-15410.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-15410.svg)


## CVE-2026-15409
 A Server-side request forgery (SSRF) vulnerability has been identified in the SMA1000 Appliance Work Place interface. A remote unauthenticated attacker could potentially cause the appliance to make requests to unintended location.

- [https://github.com/remmons-r7/rapid7-CVE-2026-15409](https://github.com/remmons-r7/rapid7-CVE-2026-15409) :  ![starts](https://img.shields.io/github/stars/remmons-r7/rapid7-CVE-2026-15409.svg) ![forks](https://img.shields.io/github/forks/remmons-r7/rapid7-CVE-2026-15409.svg)
- [https://github.com/0xBlackash/CVE-2026-15409](https://github.com/0xBlackash/CVE-2026-15409) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-15409.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-15409.svg)
- [https://github.com/HORKimhab/CVE-2026-15409](https://github.com/HORKimhab/CVE-2026-15409) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-15409.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-15409.svg)


## CVE-2026-14961
 Pegatron `Tdelo64.sys` exposes a privileged device interface, `\\.\TdeIo`, that fails to properly restrict access to sensitive IOCTL functionality. The driver's IOCTL dispatcher does not validate caller privileges or verify user-supplied kernel memory addresses before performing memory operations. By sending crafted requests to IOCTL, a local attacker can achieve arbitrary kernel memory read and write operations, leading to privilege escalation to `NT AUTHORITY\SYSTEM`, security product bypass, credential theft, or complete system compromise.

- [https://github.com/FzRsLLaSheR/CVE-2026-14960-CVE-2026-14961](https://github.com/FzRsLLaSheR/CVE-2026-14960-CVE-2026-14961) :  ![starts](https://img.shields.io/github/stars/FzRsLLaSheR/CVE-2026-14960-CVE-2026-14961.svg) ![forks](https://img.shields.io/github/forks/FzRsLLaSheR/CVE-2026-14960-CVE-2026-14961.svg)


## CVE-2026-14960
 Pegatron `Tdelo64.sys` improperly exposes privileged hardware access functionality through the `\\.\TdeIo` device interface. IOCTL handlers including `TDE_IOCTL_INDEXIO_READ` and `TDE_IOCTL_INDEXIO_WRITE` permit unprivileged user-mode callers to perform arbitrary hardware I/O port reads and writes without authorization checks. A local attacker can abuse this functionality to manipulate hardware registers, tamper with firmware-related interfaces, cause system instability, or establish persistent low-level compromise.

- [https://github.com/FzRsLLaSheR/CVE-2026-14960-CVE-2026-14961](https://github.com/FzRsLLaSheR/CVE-2026-14960-CVE-2026-14961) :  ![starts](https://img.shields.io/github/stars/FzRsLLaSheR/CVE-2026-14960-CVE-2026-14961.svg) ![forks](https://img.shields.io/github/forks/FzRsLLaSheR/CVE-2026-14960-CVE-2026-14961.svg)


## CVE-2026-13001
 The Podlove Podcast Publisher plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'podlove_handle_cache_files' function in all versions up to, and including, 4.5.1. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/Raimu0x19/CVE-2026-13001](https://github.com/Raimu0x19/CVE-2026-13001) :  ![starts](https://img.shields.io/github/stars/Raimu0x19/CVE-2026-13001.svg) ![forks](https://img.shields.io/github/forks/Raimu0x19/CVE-2026-13001.svg)
- [https://github.com/shinthink/CVE-2026-13001](https://github.com/shinthink/CVE-2026-13001) :  ![starts](https://img.shields.io/github/stars/shinthink/CVE-2026-13001.svg) ![forks](https://img.shields.io/github/forks/shinthink/CVE-2026-13001.svg)


## CVE-2026-11989
 The Bit integrations – Form Integration, Webhook, Spreadsheets, CRM, LMS & Email Automation plugin for WordPress is vulnerable to Server-Side Request Forgery in all versions up to, and including, 2.8.7 via the upload_attachment. This makes it possible for unauthenticated attackers to make web requests to arbitrary locations originating from the web application and can be used to query and modify information from internal services. Exploitation requires a form integration to be configured with a field mapped to a WooCommerce product image, product gallery, downloadable files, or Google Contacts attachment field, which is a default use case for these integrations.

- [https://github.com/repo-ranger21/security-portfolio-chris-peterson](https://github.com/repo-ranger21/security-portfolio-chris-peterson) :  ![starts](https://img.shields.io/github/stars/repo-ranger21/security-portfolio-chris-peterson.svg) ![forks](https://img.shields.io/github/forks/repo-ranger21/security-portfolio-chris-peterson.svg)


## CVE-2026-11395
 The CF7 to Webhook plugin for WordPress is vulnerable to Server-Side Request Forgery in all versions up to, and including, 5.0.0 via the pull_the_trigger. This makes it possible for unauthenticated attackers to make web requests to arbitrary locations originating from the web application and can be used to query and modify information from internal services. Exploitation requires that the admin-configured webhook URL contains a Contact Form 7 field placeholder in the host segment of the URL, and that the affected form is publicly accessible.

- [https://github.com/repo-ranger21/security-portfolio-chris-peterson](https://github.com/repo-ranger21/security-portfolio-chris-peterson) :  ![starts](https://img.shields.io/github/stars/repo-ranger21/security-portfolio-chris-peterson.svg) ![forks](https://img.shields.io/github/forks/repo-ranger21/security-portfolio-chris-peterson.svg)


## CVE-2026-3891
 The Pix for WooCommerce plugin for WordPress is vulnerable to arbitrary file uploads due to missing capability check and missing file type validation in the 'lkn_pix_for_woocommerce_c6_save_settings' function in all versions up to, and including, 1.5.0. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/shinthink/CVE-2026-3891](https://github.com/shinthink/CVE-2026-3891) :  ![starts](https://img.shields.io/github/stars/shinthink/CVE-2026-3891.svg) ![forks](https://img.shields.io/github/forks/shinthink/CVE-2026-3891.svg)
- [https://github.com/m4sh-wacker/CVE-2026-3891-Pix-for-WooCommerce-Plugin-Exploit](https://github.com/m4sh-wacker/CVE-2026-3891-Pix-for-WooCommerce-Plugin-Exploit) :  ![starts](https://img.shields.io/github/stars/m4sh-wacker/CVE-2026-3891-Pix-for-WooCommerce-Plugin-Exploit.svg) ![forks](https://img.shields.io/github/forks/m4sh-wacker/CVE-2026-3891-Pix-for-WooCommerce-Plugin-Exploit.svg)


## CVE-2026-3888
 Local privilege escalation in snapd on Linux allows local attackers to get root privilege by re-creating snap's private /tmp directory when systemd-tmpfiles is configured to automatically clean up this directory. This issue affects Ubuntu 16.04 LTS, 18.04 LTS, 20.04 LTS, 22.04 LTS, and 24.04 LTS.

- [https://github.com/Cosm3No1de/HTB-Snapped-Writeup](https://github.com/Cosm3No1de/HTB-Snapped-Writeup) :  ![starts](https://img.shields.io/github/stars/Cosm3No1de/HTB-Snapped-Writeup.svg) ![forks](https://img.shields.io/github/forks/Cosm3No1de/HTB-Snapped-Writeup.svg)


## CVE-2026-3780
 The application's installer runs with elevated privileges but resolves system executables and DLLs using untrusted search paths that can include user-writable directories, allowing a local attacker to place malicious binaries with the same names and have them loaded or executed instead of the legitimate system files, resulting in local privilege escalation.

- [https://github.com/Paradoxis/CVE-2026-57239](https://github.com/Paradoxis/CVE-2026-57239) :  ![starts](https://img.shields.io/github/stars/Paradoxis/CVE-2026-57239.svg) ![forks](https://img.shields.io/github/forks/Paradoxis/CVE-2026-57239.svg)


## CVE-2026-3775
 The application's update service, when checking for updates, loads certain system libraries from a search path that includes directories writable by low‑privileged users and is not strictly restricted to trusted system locations. Because these libraries may be resolved and loaded from user‑writable locations, a local attacker can place a malicious library there and have it loaded with SYSTEM privileges, resulting in local privilege escalation and arbitrary code execution.

- [https://github.com/Paradoxis/CVE-2026-57239](https://github.com/Paradoxis/CVE-2026-57239) :  ![starts](https://img.shields.io/github/stars/Paradoxis/CVE-2026-57239.svg) ![forks](https://img.shields.io/github/forks/Paradoxis/CVE-2026-57239.svg)


## CVE-2026-1487
 The LatePoint – Calendar Booking Plugin for Appointments and Events plugin for WordPress is vulnerable to SQL Injection via the JSON Import in all versions up to, and including, 5.2.7 due to insufficient validation on the user-supplied JSON data.  This makes it possible for authenticated attackers, with Administrator-level access and above, to execute arbitrary SQL queries on the database that can be used to extract information via time-based techniques, drop tables, or modify data.

- [https://github.com/JFOZ1010/CVE-2026-14871](https://github.com/JFOZ1010/CVE-2026-14871) :  ![starts](https://img.shields.io/github/stars/JFOZ1010/CVE-2026-14871.svg) ![forks](https://img.shields.io/github/forks/JFOZ1010/CVE-2026-14871.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry.svg)


## CVE-2025-32044
 A flaw has been identified in Moodle where, on certain sites, unauthenticated users could retrieve sensitive user data—including names, contact information, and hashed passwords—via stack traces returned by specific API calls. Sites with PHP configured with zend.exception_ignore_args = 1 in the php.ini file are not affected by this vulnerability.

- [https://github.com/shinthink/CVE-2025-32044](https://github.com/shinthink/CVE-2025-32044) :  ![starts](https://img.shields.io/github/stars/shinthink/CVE-2025-32044.svg) ![forks](https://img.shields.io/github/forks/shinthink/CVE-2025-32044.svg)


## CVE-2025-21333
 Windows Hyper-V NT Kernel Integration VSP Elevation of Privilege Vulnerability

- [https://github.com/uname1able/CVE-2025-21333](https://github.com/uname1able/CVE-2025-21333) :  ![starts](https://img.shields.io/github/stars/uname1able/CVE-2025-21333.svg) ![forks](https://img.shields.io/github/forks/uname1able/CVE-2025-21333.svg)


## CVE-2025-6035
 A flaw was found in GIMP. An integer overflow vulnerability exists in the GIMP "Despeckle"  plug-in. The issue occurs due to unchecked multiplication of image dimensions, such as width, height, and bytes-per-pixel (img_bpp), which can result in allocating insufficient memory and subsequently performing out-of-bounds writes. This issue could lead to heap corruption, a potential denial of service (DoS), or arbitrary code execution in certain scenarios.

- [https://github.com/Nullbyte3117/CVE-2025-60357](https://github.com/Nullbyte3117/CVE-2025-60357) :  ![starts](https://img.shields.io/github/stars/Nullbyte3117/CVE-2025-60357.svg) ![forks](https://img.shields.io/github/forks/Nullbyte3117/CVE-2025-60357.svg)


## CVE-2024-40432
 A lack of input validation in Realtek SD card reader driver before 10.0.26100.21374 through the implementation of the IOCTL_SFFDISK_DEVICE_COMMAND control of the SD card reader driver allows a privileged attacker to crash the OS.

- [https://github.com/HORKimhab/CVE-2022-25477](https://github.com/HORKimhab/CVE-2022-25477) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2022-25477.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2022-25477.svg)


## CVE-2024-40431
 A lack of input validation in Realtek SD card reader driver before 10.0.26100.21374 through the implementation of the IOCTL_SCSI_PASS_THROUGH control of the SD card reader driver allows an attacker to write to predictable kernel memory locations, even as a low-privileged user.

- [https://github.com/HORKimhab/CVE-2022-25477](https://github.com/HORKimhab/CVE-2022-25477) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2022-25477.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2022-25477.svg)


## CVE-2024-6387
 A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be able to trigger it by failing to authenticate within a set time period.

- [https://github.com/m0n3ef/regreSSHion-Checker](https://github.com/m0n3ef/regreSSHion-Checker) :  ![starts](https://img.shields.io/github/stars/m0n3ef/regreSSHion-Checker.svg) ![forks](https://img.shields.io/github/forks/m0n3ef/regreSSHion-Checker.svg)


## CVE-2024-5082
This issue affects Nexus Repository 2 OSS/Pro versions up to and including 2.15.1.

- [https://github.com/h4mr3r/CVE-2024-5082](https://github.com/h4mr3r/CVE-2024-5082) :  ![starts](https://img.shields.io/github/stars/h4mr3r/CVE-2024-5082.svg) ![forks](https://img.shields.io/github/forks/h4mr3r/CVE-2024-5082.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/Kanak-CypherX/cve-2024-4577-lab](https://github.com/Kanak-CypherX/cve-2024-4577-lab) :  ![starts](https://img.shields.io/github/stars/Kanak-CypherX/cve-2024-4577-lab.svg) ![forks](https://img.shields.io/github/forks/Kanak-CypherX/cve-2024-4577-lab.svg)


## CVE-2022-25480
 Vulnerability in Realtek RtsPer driver for PCIe Card Reader (RtsPer.sys) before 10.0.22000.21355 and Realtek RtsUer driver for USB Card Reader (RtsUer.sys) before 10.0.22000.31274 allows writing to kernel memory beyond the SystemBuffer of the IRP.

- [https://github.com/HORKimhab/CVE-2022-25477](https://github.com/HORKimhab/CVE-2022-25477) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2022-25477.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2022-25477.svg)


## CVE-2022-25479
 Vulnerability in Realtek RtsPer driver for PCIe Card Reader (RtsPer.sys) before 10.0.22000.21355 and Realtek RtsUer driver for USB Card Reader (RtsUer.sys) before 10.0.22000.31274 allows for the leakage of kernel memory from both the stack and the heap.

- [https://github.com/HORKimhab/CVE-2022-25477](https://github.com/HORKimhab/CVE-2022-25477) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2022-25477.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2022-25477.svg)


## CVE-2022-25478
 Vulnerability in Realtek RtsPer driver for PCIe Card Reader (RtsPer.sys) before 10.0.22000.21355 and Realtek RtsUer driver for USB Card Reader (RtsUer.sys) before 10.0.22000.31274 provides read and write access to the PCI configuration space of the device.

- [https://github.com/HORKimhab/CVE-2022-25477](https://github.com/HORKimhab/CVE-2022-25477) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2022-25477.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2022-25477.svg)


## CVE-2022-25477
 Vulnerability in Realtek RtsPer driver for PCIe Card Reader (RtsPer.sys) before 10.0.22000.21355 and Realtek RtsUer driver for USB Card Reader (RtsUer.sys) before 10.0.22000.31274 leaks driver logs that contain addresses of kernel mode objects, weakening KASLR.

- [https://github.com/HORKimhab/CVE-2022-25477](https://github.com/HORKimhab/CVE-2022-25477) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2022-25477.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2022-25477.svg)


## CVE-2022-2547
 A crafted HTTP packet without a content-type header can create a denial-of-service condition in Softing Secure Integration Server V1.22.

- [https://github.com/HORKimhab/CVE-2022-25476](https://github.com/HORKimhab/CVE-2022-25476) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2022-25476.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2022-25476.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via "sudoedit -s" and a command-line argument that ends with a single backslash character.

- [https://github.com/IJBaig/CVE-2021-3156](https://github.com/IJBaig/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/IJBaig/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/IJBaig/CVE-2021-3156.svg)

