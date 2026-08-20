# Update 2026-08-20
## CVE-2026-74970
 Site isolation issue in the Graphics component. This vulnerability was fixed in Firefox 154, Firefox ESR 153.1, Thunderbird 154, and Thunderbird 153.1.

- [https://github.com/defineid/Trespasser](https://github.com/defineid/Trespasser) :  ![starts](https://img.shields.io/github/stars/defineid/Trespasser.svg) ![forks](https://img.shields.io/github/forks/defineid/Trespasser.svg)


## CVE-2026-74945
 Information disclosure in the Graphics: Text component. This vulnerability was fixed in Firefox 154, Firefox ESR 115.39, Firefox ESR 140.14, Firefox ESR 153.1, Thunderbird 154, Thunderbird 140.14, and Thunderbird 153.1.

- [https://github.com/defineid/Palimpsest](https://github.com/defineid/Palimpsest) :  ![starts](https://img.shields.io/github/stars/defineid/Palimpsest.svg) ![forks](https://img.shields.io/github/forks/defineid/Palimpsest.svg)


## CVE-2026-74943
 Use-after-free in the Graphics: ImageLib component. This vulnerability was fixed in Firefox 154, Firefox ESR 115.39, Firefox ESR 140.14, Firefox ESR 153.1, Thunderbird 154, Thunderbird 140.14, and Thunderbird 153.1.

- [https://github.com/defineid/Revenant](https://github.com/defineid/Revenant) :  ![starts](https://img.shields.io/github/stars/defineid/Revenant.svg) ![forks](https://img.shields.io/github/forks/defineid/Revenant.svg)


## CVE-2026-73292
 Semaphore UI is a web interface for managing DevOps tools. Prior to 2.18.21, the /api/users/{id}/password endpoint accepts a cross-site request using the authenticated user's semaphore session cookie without CSRF protection or current-password confirmation, allowing an unauthenticated attacker to change an administrator's or another user's password after user interaction. This issue is fixed in version 2.18.21.

- [https://github.com/CamilleGR/CVE-2026-73292](https://github.com/CamilleGR/CVE-2026-73292) :  ![starts](https://img.shields.io/github/stars/CamilleGR/CVE-2026-73292.svg) ![forks](https://img.shields.io/github/forks/CamilleGR/CVE-2026-73292.svg)


## CVE-2026-69414
We are working to provide a high quality security update that addresses this vulnerability. We will provide information in this CVE when the update is available.

- [https://github.com/1neptune/ShieldBreak](https://github.com/1neptune/ShieldBreak) :  ![starts](https://img.shields.io/github/stars/1neptune/ShieldBreak.svg) ![forks](https://img.shields.io/github/forks/1neptune/ShieldBreak.svg)


## CVE-2026-67846
 Berkeley Out-of-Order Machine (BOOM) commit 5223e44cfeb26f41380057a2eb4d651197475f69 contains a potential incorrect privilege assignment issue in the v3 and v4 NBDTLB implementations. The raw mstatus.SUM value participates in the read and write permission logic without an explicit local satp.MODE validity check at the use site

- [https://github.com/duan528/CVE-2026-67846-BOOM-NBDTLB](https://github.com/duan528/CVE-2026-67846-BOOM-NBDTLB) :  ![starts](https://img.shields.io/github/stars/duan528/CVE-2026-67846-BOOM-NBDTLB.svg) ![forks](https://img.shields.io/github/forks/duan528/CVE-2026-67846-BOOM-NBDTLB.svg)


## CVE-2026-66804
 Improper access control in Windows Cross Device Service allows an authorized attacker to elevate privileges locally.

- [https://github.com/CypherHippie/CVE-2026-66804](https://github.com/CypherHippie/CVE-2026-66804) :  ![starts](https://img.shields.io/github/stars/CypherHippie/CVE-2026-66804.svg) ![forks](https://img.shields.io/github/forks/CypherHippie/CVE-2026-66804.svg)


## CVE-2026-65400
 An authentication issue was addressed with improved state management. This issue is fixed in macOS Sequoia 15.7.9, macOS Sonoma 14.8.9, macOS Tahoe 26.6.1. An attacker on the network may be able to authenticate to Screen Sharing without valid credentials.

- [https://github.com/HORKimhab/CVE-2026-65400](https://github.com/HORKimhab/CVE-2026-65400) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-65400.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-65400.svg)


## CVE-2026-64849
 MLflow is an open source AI engineering platform for agents, large language models, and machine learning models. Prior to 3.15.0, the unauthenticated POST /api/2.0/mlflow/webhooks/{id}/test endpoint calls _validate_webhook_url() in mlflow/utils/validation.py only for the original URL while mlflow/webhooks/delivery.py follows redirects and re-resolves the hostname without pinning the validated address, allowing attackers to reach internal or cloud metadata services and receive response_status and response_body. This issue is fixed in version 3.15.0.

- [https://github.com/codeb0ssx/CVE-2026-64849-PoC](https://github.com/codeb0ssx/CVE-2026-64849-PoC) :  ![starts](https://img.shields.io/github/stars/codeb0ssx/CVE-2026-64849-PoC.svg) ![forks](https://img.shields.io/github/forks/codeb0ssx/CVE-2026-64849-PoC.svg)


## CVE-2026-64638
Discovered and responsibly disclosed by [the team at pwn.ai](https://pwn.ai/).

- [https://github.com/kaleth4/CVE-2026-64638](https://github.com/kaleth4/CVE-2026-64638) :  ![starts](https://img.shields.io/github/stars/kaleth4/CVE-2026-64638.svg) ![forks](https://img.shields.io/github/forks/kaleth4/CVE-2026-64638.svg)


## CVE-2026-50142
 libheif is a HEIF and AVIF file format decoder and encoder. From 1.19.0 until 1.23.0, a crafted HEIF sequence accepted by heif_context_read_from_memory() with the msf1 sequence brand can cause unbounded heap allocation. In libheif/sequences/seq_boxes.cc, Box_stsz::parse() applies max_sequence_frames only to variable-size samples, so fixed-size mode accepts an attacker-controlled sample_count without a bound. In libheif/sequences/track.cc, Track::load() also adds current_sample_idx and samples_per_chunk in 32-bit arithmetic, allowing the consistency check to be bypassed by wraparound. The resulting values reach the Chunk::Chunk() allocation path, which can consume gigabytes of memory and crash or stall the process through memory exhaustion. This issue is fixed in version 1.23.0.

- [https://github.com/MuhammedHussein17/libheif-cve-2026-50142](https://github.com/MuhammedHussein17/libheif-cve-2026-50142) :  ![starts](https://img.shields.io/github/stars/MuhammedHussein17/libheif-cve-2026-50142.svg) ![forks](https://img.shields.io/github/forks/MuhammedHussein17/libheif-cve-2026-50142.svg)


## CVE-2026-44848
 Portainer Community Edition is a lightweight service delivery platform for containerized applications that can be used to manage Docker, Swarm, Kubernetes and ACI environments. From 2.33.0 to before 2.33.8, 2.39.2, and 2.41.0, The Docker plugin management endpoints (/plugins/*) were not registered with a handler, so standard users with endpoint access could call privileged plugin operations — including installing and enabling plugins — directly against the underlying Docker daemon. The vulnerability is exposed when a non-admin Portainer user (Standard User role, or any role granted endpoint-level access) has been given access to a Docker endpoint via Portainer RBAC. This vulnerability is fixed in 2.33.8, 2.39.2, and 2.41.0.

- [https://github.com/Boreas37/CVE-2026-44848-PoC](https://github.com/Boreas37/CVE-2026-44848-PoC) :  ![starts](https://img.shields.io/github/stars/Boreas37/CVE-2026-44848-PoC.svg) ![forks](https://img.shields.io/github/forks/Boreas37/CVE-2026-44848-PoC.svg)


## CVE-2026-44578
 Next.js is a React framework for building full-stack web applications. From 13.4.13 to before 15.5.16 and 16.2.5, self-hosted applications using the built-in Node.js server can be vulnerable to server-side request forgery through crafted WebSocket upgrade requests. An attacker can cause the server to proxy requests to arbitrary internal or external destinations, which may expose internal services or cloud metadata endpoints. Vercel-hosted deployments are not affected. This vulnerability is fixed in 15.5.16 and 16.2.5.

- [https://github.com/lxxexxbxx/CVE-2026-44578](https://github.com/lxxexxbxx/CVE-2026-44578) :  ![starts](https://img.shields.io/github/stars/lxxexxbxx/CVE-2026-44578.svg) ![forks](https://img.shields.io/github/forks/lxxexxbxx/CVE-2026-44578.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/gitchw/ghostlock-cve-2026-43499](https://github.com/gitchw/ghostlock-cve-2026-43499) :  ![starts](https://img.shields.io/github/stars/gitchw/ghostlock-cve-2026-43499.svg) ![forks](https://img.shields.io/github/forks/gitchw/ghostlock-cve-2026-43499.svg)


## CVE-2026-32128
 FastGPT is an AI Agent building platform. In 4.14.7 and earlier, FastGPT's Python Sandbox (fastgpt-sandbox) includes guardrails intended to prevent file writes (static detection + seccomp). These guardrails are bypassable by remapping stdout (fd 1) to an arbitrary writable file descriptor using fcntl. After remapping, writing via sys.stdout.write() still satisfies the seccomp rule write(fd==1), enabling arbitrary file creation/overwrite inside the sandbox container despite the intended no file writes restriction.

- [https://github.com/qianlijaingshan/fastgpt-sandbox-audit](https://github.com/qianlijaingshan/fastgpt-sandbox-audit) :  ![starts](https://img.shields.io/github/stars/qianlijaingshan/fastgpt-sandbox-audit.svg) ![forks](https://img.shields.io/github/forks/qianlijaingshan/fastgpt-sandbox-audit.svg)


## CVE-2026-19598
 The Pods – Custom Content Types and Fields plugin for WordPress is vulnerable to Privilege Escalation via Authorization Bypass in all versions up to, and including, 3.3.9. The vulnerability exists because the pods_admin AJAX router funnels every access check — including the method allowlist, nonce verification, login enforcement, and capability gate — through pods_error(), which under the JSON meta-box-loader compatibility path only writes failures to the PHP error log and returns false instead of terminating the request, rendering all guards ineffective.  This makes it possible for unauthenticated attackers to escalate their privileges to Administrator or overwrite the password of any user account, including the site owner's, enabling complete site takeover, or perform another administrator action.

- [https://github.com/ksotaria1337/CVE-2026-19598](https://github.com/ksotaria1337/CVE-2026-19598) :  ![starts](https://img.shields.io/github/stars/ksotaria1337/CVE-2026-19598.svg) ![forks](https://img.shields.io/github/forks/ksotaria1337/CVE-2026-19598.svg)


## CVE-2026-19501
 CSV export functionality in Brainstorm Force SureForms version, = 2.1.1, fails to neutralize spreadsheet formula characters in user-controlled form field names before generating CSV exports, which allows a remote attacker to execute spreadsheet formulas on an administrator's workstation when the exported CSV file is opened in a vulnerable spreadsheet application.

- [https://github.com/typedefabcd1234ntd/CVE-2026-19501-poc](https://github.com/typedefabcd1234ntd/CVE-2026-19501-poc) :  ![starts](https://img.shields.io/github/stars/typedefabcd1234ntd/CVE-2026-19501-poc.svg) ![forks](https://img.shields.io/github/forks/typedefabcd1234ntd/CVE-2026-19501-poc.svg)


## CVE-2026-19500
 The Entries component in Brainstorm Force SureForms version, less than 2.1.3, does not enforce adequate limits on user-controlled form fields or submitted content during processing and rendering, which allows a remote attacker to exhaust server resources, prevent administrators from accessing the Entries interface, and trigger HTTP 500 errors via crafted form submissions.

- [https://github.com/typedefabcd1234ntd/CVE-2026-19500-poc](https://github.com/typedefabcd1234ntd/CVE-2026-19500-poc) :  ![starts](https://img.shields.io/github/stars/typedefabcd1234ntd/CVE-2026-19500-poc.svg) ![forks](https://img.shields.io/github/forks/typedefabcd1234ntd/CVE-2026-19500-poc.svg)


## CVE-2026-19478
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 18.2 before 18.11.11, 19.0 before 19.0.8, 19.1 before 19.1.6, and 19.2 before 19.2.4 that under certain conditions could allow an unauthenticated user to remotely modify or delete public projects and user data via a GraphQL directive.

- [https://github.com/davkharrr/CVE-2026-19478-PoC](https://github.com/davkharrr/CVE-2026-19478-PoC) :  ![starts](https://img.shields.io/github/stars/davkharrr/CVE-2026-19478-PoC.svg) ![forks](https://img.shields.io/github/forks/davkharrr/CVE-2026-19478-PoC.svg)


## CVE-2026-17106
 The tar extraction routines in moby/go-archive (Unpack, UnpackLayer, Untar/UntarUncompressed, and the ApplyLayer helpers) do not confine filesystem operations to the destination directory. The extractor decides where each archive entry lands using lexical string checks and then performs the filesystem operation on a path that is resolved by the OS, so links introduced by the archive can be followed out of the destination directory. An attacker who controls the contents of an archive can create or overwrite files at arbitrary paths writable by the extracting process.

- [https://github.com/masasron/CopyEscape-CVE-2026-17106](https://github.com/masasron/CopyEscape-CVE-2026-17106) :  ![starts](https://img.shields.io/github/stars/masasron/CopyEscape-CVE-2026-17106.svg) ![forks](https://img.shields.io/github/forks/masasron/CopyEscape-CVE-2026-17106.svg)
- [https://github.com/HackSpeak/CVE-2026-17106](https://github.com/HackSpeak/CVE-2026-17106) :  ![starts](https://img.shields.io/github/stars/HackSpeak/CVE-2026-17106.svg) ![forks](https://img.shields.io/github/forks/HackSpeak/CVE-2026-17106.svg)
- [https://github.com/686f6c61/POC-CopyEscape-CVE-2026-17106](https://github.com/686f6c61/POC-CopyEscape-CVE-2026-17106) :  ![starts](https://img.shields.io/github/stars/686f6c61/POC-CopyEscape-CVE-2026-17106.svg) ![forks](https://img.shields.io/github/forks/686f6c61/POC-CopyEscape-CVE-2026-17106.svg)


## CVE-2026-15748
 The Forminator Forms plugin for WordPress is vulnerable to Arbitrary File Upload in all versions up to, and including, 1.56.1 via the handle_file_upload function. This is due to insufficient file type validation in handle_file_upload, where the dangerous-extension blocklist performs exact-key matching that is bypassed by pipe-alternative MIME type keys, combined with a public submission handler that trusts attacker-controlled upload field configuration injected via a forged Select field value. This makes it possible for unauthenticated attackers to upload files that may be executable, which makes remote code execution possible.

- [https://github.com/yora1928/cve-2026-15748](https://github.com/yora1928/cve-2026-15748) :  ![starts](https://img.shields.io/github/stars/yora1928/cve-2026-15748.svg) ![forks](https://img.shields.io/github/forks/yora1928/cve-2026-15748.svg)
- [https://github.com/HORKimhab/CVE-2026-15826-CVE-2026-15748](https://github.com/HORKimhab/CVE-2026-15826-CVE-2026-15748) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-15826-CVE-2026-15748.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-15826-CVE-2026-15748.svg)


## CVE-2026-14669
 Heap buffer overflow in PostgreSQL to_char(timestamptz) allows the party choosing the timezone to execute arbitrary code as the operating system user running the database, via a long POSIX timezone abbreviation.  Versions before PostgreSQL 18.5, 17.11, 16.15, 15.19, and 14.24 are affected.

- [https://github.com/HackSpeak/CVE-2026-14669](https://github.com/HackSpeak/CVE-2026-14669) :  ![starts](https://img.shields.io/github/stars/HackSpeak/CVE-2026-14669.svg) ![forks](https://img.shields.io/github/forks/HackSpeak/CVE-2026-14669.svg)


## CVE-2026-9158
 In Eclipse 4diac FORTE versions 3.0.0 to 3.1.0, a specially crafted DELETE connection command to the management interface can lead to a dangling pointer. This allows subsequent commands to access freed memory (use-after-free).

- [https://github.com/Klaurx/CVE_2026_9158](https://github.com/Klaurx/CVE_2026_9158) :  ![starts](https://img.shields.io/github/stars/Klaurx/CVE_2026_9158.svg) ![forks](https://img.shields.io/github/forks/Klaurx/CVE_2026_9158.svg)


## CVE-2025-69848
 NetBox is an open-source infrastructure resource modeling and IP address management platform. A reflected cross-site scripting (XSS) vulnerability exists in versions 2.11.0 through 3.7.x in the ProtectedError handling logic, where object names are included in HTML error messages without proper escaping. This allows user-controlled content to be rendered in the web interface when a delete operation fails due to protected relationships, potentially enabling execution of arbitrary client-side code in the context of a privileged user.

- [https://github.com/alkimcoskun/CVE-2025-69848-security-advisories](https://github.com/alkimcoskun/CVE-2025-69848-security-advisories) :  ![starts](https://img.shields.io/github/stars/alkimcoskun/CVE-2025-69848-security-advisories.svg) ![forks](https://img.shields.io/github/forks/alkimcoskun/CVE-2025-69848-security-advisories.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg)


## CVE-2025-62593
 Ray is an AI compute engine. Prior to version 2.52.0, developers working with Ray as a development tool can be exploited via a critical RCE vulnerability exploitable via Firefox and Safari. This vulnerability is due to an insufficient guard against browser-based attacks, as the current defense uses the User-Agent header starting with the string "Mozilla" as a defense mechanism. This defense is insufficient as the fetch specification allows the User-Agent header to be modified. Combined with a DNS rebinding attack against the browser, and this vulnerability is exploitable against a developer running Ray who inadvertently visits a malicious website, or is served a malicious advertisement (malvertising). This issue has been patched in version 2.52.0.

- [https://github.com/Boreas37/CVE-2025-62593-PoC](https://github.com/Boreas37/CVE-2025-62593-PoC) :  ![starts](https://img.shields.io/github/stars/Boreas37/CVE-2025-62593-PoC.svg) ![forks](https://img.shields.io/github/forks/Boreas37/CVE-2025-62593-PoC.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg)


## CVE-2025-5880
 A vulnerability has been found in Whistle 2.9.98 and classified as problematic. This vulnerability affects unknown code of the file /cgi-bin/sessions/get-temp-file. The manipulation of the argument filename leads to path traversal. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/AC8999/CVE-2025-5880](https://github.com/AC8999/CVE-2025-5880) :  ![starts](https://img.shields.io/github/stars/AC8999/CVE-2025-5880.svg) ![forks](https://img.shields.io/github/forks/AC8999/CVE-2025-5880.svg)


## CVE-2025-3248
code.

- [https://github.com/GraySignal/CVE-2025-3248](https://github.com/GraySignal/CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/GraySignal/CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/GraySignal/CVE-2025-3248.svg)


## CVE-2024-50803
 The mediapool feature of the Redaxo Core CMS application v 5.17.1 is vulnerable to Cross Site Scripting(XSS) which allows a remote attacker to escalate privileges

- [https://github.com/GraySignal/CVE-2024-50803-Redaxo](https://github.com/GraySignal/CVE-2024-50803-Redaxo) :  ![starts](https://img.shields.io/github/stars/GraySignal/CVE-2024-50803-Redaxo.svg) ![forks](https://img.shields.io/github/forks/GraySignal/CVE-2024-50803-Redaxo.svg)


## CVE-2024-38856
Unauthenticated endpoints could allow execution of screen rendering code of screens if some preconditions are met (such as when the screen definitions don't explicitly check user's permissions because they rely on the configuration of their endpoints).

- [https://github.com/GraySignal/CVE-2024-38856-ApacheOfBiz](https://github.com/GraySignal/CVE-2024-38856-ApacheOfBiz) :  ![starts](https://img.shields.io/github/stars/GraySignal/CVE-2024-38856-ApacheOfBiz.svg) ![forks](https://img.shields.io/github/forks/GraySignal/CVE-2024-38856-ApacheOfBiz.svg)


## CVE-2024-28995
 SolarWinds Serv-U was susceptible to a directory transversal vulnerability that would allow access to read sensitive files on the host machine.

- [https://github.com/GraySignal/CVE-2024-28995-SolarWinds-Serv-U](https://github.com/GraySignal/CVE-2024-28995-SolarWinds-Serv-U) :  ![starts](https://img.shields.io/github/stars/GraySignal/CVE-2024-28995-SolarWinds-Serv-U.svg) ![forks](https://img.shields.io/github/forks/GraySignal/CVE-2024-28995-SolarWinds-Serv-U.svg)


## CVE-2024-24919
 Potentially allowing an attacker to read certain information on Check Point Security Gateways once connected to the internet and enabled with remote Access VPN or Mobile Access Software Blades. A Security fix that mitigates this vulnerability is available.

- [https://github.com/GraySignal/CVE-2024-24919-Check-Point-Remote-Access-VPN](https://github.com/GraySignal/CVE-2024-24919-Check-Point-Remote-Access-VPN) :  ![starts](https://img.shields.io/github/stars/GraySignal/CVE-2024-24919-Check-Point-Remote-Access-VPN.svg) ![forks](https://img.shields.io/github/forks/GraySignal/CVE-2024-24919-Check-Point-Remote-Access-VPN.svg)


## CVE-2024-23897
 Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.

- [https://github.com/GraySignal/CVE-2024-23897-Jenkins-Arbitrary-Read-File-Vulnerability](https://github.com/GraySignal/CVE-2024-23897-Jenkins-Arbitrary-Read-File-Vulnerability) :  ![starts](https://img.shields.io/github/stars/GraySignal/CVE-2024-23897-Jenkins-Arbitrary-Read-File-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/GraySignal/CVE-2024-23897-Jenkins-Arbitrary-Read-File-Vulnerability.svg)


## CVE-2024-20767
 ColdFusion versions 2023.6, 2021.12 and earlier are affected by an Improper Access Control vulnerability that could result in arbitrary file system read. An attacker could leverage this vulnerability to access or modify restricted files. Exploitation of this issue does not require user interaction. Exploitation of this issue requires the admin panel be exposed to the internet.

- [https://github.com/GraySignal/CVE-2024-20767-Adobe-ColdFusion](https://github.com/GraySignal/CVE-2024-20767-Adobe-ColdFusion) :  ![starts](https://img.shields.io/github/stars/GraySignal/CVE-2024-20767-Adobe-ColdFusion.svg) ![forks](https://img.shields.io/github/forks/GraySignal/CVE-2024-20767-Adobe-ColdFusion.svg)


## CVE-2024-4956
 Path Traversal in Sonatype Nexus Repository 3 allows an unauthenticated attacker to read system files. Fixed in version 3.68.1.

- [https://github.com/GraySignal/CVE-2024-4956-Sonatype-Nexus-Repository-Manager](https://github.com/GraySignal/CVE-2024-4956-Sonatype-Nexus-Repository-Manager) :  ![starts](https://img.shields.io/github/stars/GraySignal/CVE-2024-4956-Sonatype-Nexus-Repository-Manager.svg) ![forks](https://img.shields.io/github/forks/GraySignal/CVE-2024-4956-Sonatype-Nexus-Repository-Manager.svg)


## CVE-2024-4879
 ServiceNow has addressed an input validation vulnerability that was identified in Vancouver and Washington DC Now Platform releases. This vulnerability could enable an unauthenticated user to remotely execute code within the context of the Now Platform. ServiceNow applied an update to hosted instances, and ServiceNow released the update to our partners and self-hosted customers. Listed below are the patches and hot fixes that address the vulnerability. If you have not done so already, we recommend applying security patches relevant to your instance as soon as possible.

- [https://github.com/GraySignal/CVE-2024-4879-ServiceNow](https://github.com/GraySignal/CVE-2024-4879-ServiceNow) :  ![starts](https://img.shields.io/github/stars/GraySignal/CVE-2024-4879-ServiceNow.svg) ![forks](https://img.shields.io/github/forks/GraySignal/CVE-2024-4879-ServiceNow.svg)


## CVE-2024-4040
 A server side template injection vulnerability in CrushFTP in all versions before 10.7.1 and 11.1.0 on all platforms allows unauthenticated remote attackers to read files from the filesystem outside of the VFS Sandbox, bypass authentication to gain administrative access, and perform remote code execution on the server.

- [https://github.com/GraySignal/CVE-2024-4040-CrushFTP-server](https://github.com/GraySignal/CVE-2024-4040-CrushFTP-server) :  ![starts](https://img.shields.io/github/stars/GraySignal/CVE-2024-4040-CrushFTP-server.svg) ![forks](https://img.shields.io/github/forks/GraySignal/CVE-2024-4040-CrushFTP-server.svg)


## CVE-2024-4027
 A flaw was found in Undertow. Servlets using a method that calls HttpServletRequestImpl.getParameterNames() can cause an OutOfMemoryError when the client sends a request with large parameter names. This issue can be exploited by an unauthorized user to cause a remote denial-of-service (DoS) attack.

- [https://github.com/burjoy/CVE-2024-40275_Scanner](https://github.com/burjoy/CVE-2024-40275_Scanner) :  ![starts](https://img.shields.io/github/stars/burjoy/CVE-2024-40275_Scanner.svg) ![forks](https://img.shields.io/github/forks/burjoy/CVE-2024-40275_Scanner.svg)


## CVE-2023-51467
 The vulnerability permits attackers to circumvent authentication processes, enabling them to remotely execute arbitrary code

- [https://github.com/GraySignal/Apache-OFBiz-Auth-Bypass-and-RCE-Exploit-CVE-2023-49070-CVE-2023-51467](https://github.com/GraySignal/Apache-OFBiz-Auth-Bypass-and-RCE-Exploit-CVE-2023-49070-CVE-2023-51467) :  ![starts](https://img.shields.io/github/stars/GraySignal/Apache-OFBiz-Auth-Bypass-and-RCE-Exploit-CVE-2023-49070-CVE-2023-51467.svg) ![forks](https://img.shields.io/github/forks/GraySignal/Apache-OFBiz-Auth-Bypass-and-RCE-Exploit-CVE-2023-49070-CVE-2023-51467.svg)


## CVE-2023-49070
Users are recommended to upgrade to version 18.12.10

- [https://github.com/GraySignal/Apache-OFBiz-Auth-Bypass-and-RCE-Exploit-CVE-2023-49070-CVE-2023-51467](https://github.com/GraySignal/Apache-OFBiz-Auth-Bypass-and-RCE-Exploit-CVE-2023-49070-CVE-2023-51467) :  ![starts](https://img.shields.io/github/stars/GraySignal/Apache-OFBiz-Auth-Bypass-and-RCE-Exploit-CVE-2023-49070-CVE-2023-51467.svg) ![forks](https://img.shields.io/github/forks/GraySignal/Apache-OFBiz-Auth-Bypass-and-RCE-Exploit-CVE-2023-49070-CVE-2023-51467.svg)


## CVE-2023-44487
 The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.

- [https://github.com/imabee101/CVE-2023-44487](https://github.com/imabee101/CVE-2023-44487) :  ![starts](https://img.shields.io/github/stars/imabee101/CVE-2023-44487.svg) ![forks](https://img.shields.io/github/forks/imabee101/CVE-2023-44487.svg)


## CVE-2022-38694
 In BootRom, there is a possible unchecked write address. This could lead to local escalation of privilege with no additional execution privileges needed.

- [https://github.com/xun404/spd_dump-macos](https://github.com/xun404/spd_dump-macos) :  ![starts](https://img.shields.io/github/stars/xun404/spd_dump-macos.svg) ![forks](https://img.shields.io/github/forks/xun404/spd_dump-macos.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/gaganhm3018-art/CVE-2022-0847-Dirty-Pipe-](https://github.com/gaganhm3018-art/CVE-2022-0847-Dirty-Pipe-) :  ![starts](https://img.shields.io/github/stars/gaganhm3018-art/CVE-2022-0847-Dirty-Pipe-.svg) ![forks](https://img.shields.io/github/forks/gaganhm3018-art/CVE-2022-0847-Dirty-Pipe-.svg)


## CVE-2021-43716
 Verification Bypass vulnerability exists in EPSON 150075647YWWV110 EasyMP Network Updater Ver.1.20. The Epson projector can be updated by encrypted firmware through USB.

- [https://github.com/dpfkdlemtp/epson-eh-tw5350-advisories](https://github.com/dpfkdlemtp/epson-eh-tw5350-advisories) :  ![starts](https://img.shields.io/github/stars/dpfkdlemtp/epson-eh-tw5350-advisories.svg) ![forks](https://img.shields.io/github/forks/dpfkdlemtp/epson-eh-tw5350-advisories.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/asd58584388/CVE-2021-44228](https://github.com/asd58584388/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/asd58584388/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/asd58584388/CVE-2021-44228.svg)
- [https://github.com/Super-Binary/cve-2021-44228](https://github.com/Super-Binary/cve-2021-44228) :  ![starts](https://img.shields.io/github/stars/Super-Binary/cve-2021-44228.svg) ![forks](https://img.shields.io/github/forks/Super-Binary/cve-2021-44228.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/TheLastVvV/CVE-2021-41773](https://github.com/TheLastVvV/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/TheLastVvV/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/TheLastVvV/CVE-2021-41773.svg)
- [https://github.com/faizdotid/CVE-2021-41773](https://github.com/faizdotid/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/faizdotid/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/faizdotid/CVE-2021-41773.svg)


## CVE-2021-1675
 Windows Print Spooler Remote Code Execution Vulnerability

- [https://github.com/VelesSecurity/CVE-2021-1675-PrintNightmare-Analysis](https://github.com/VelesSecurity/CVE-2021-1675-PrintNightmare-Analysis) :  ![starts](https://img.shields.io/github/stars/VelesSecurity/CVE-2021-1675-PrintNightmare-Analysis.svg) ![forks](https://img.shields.io/github/forks/VelesSecurity/CVE-2021-1675-PrintNightmare-Analysis.svg)


## CVE-2020-14882
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/VelesSecurity/CVE-2020-14882-WebLogic-Analysis](https://github.com/VelesSecurity/CVE-2020-14882-WebLogic-Analysis) :  ![starts](https://img.shields.io/github/stars/VelesSecurity/CVE-2020-14882-WebLogic-Analysis.svg) ![forks](https://img.shields.io/github/forks/VelesSecurity/CVE-2020-14882-WebLogic-Analysis.svg)


## CVE-2018-1058
 A flaw was found in the way Postgresql allowed a user to modify the behavior of a query for other users. An attacker with a user account could use this flaw to execute code with the permissions of superuser in the database. Versions 9.3 through 10 are affected.

- [https://github.com/mthamil107/DB_Audit_Research](https://github.com/mthamil107/DB_Audit_Research) :  ![starts](https://img.shields.io/github/stars/mthamil107/DB_Audit_Research.svg) ![forks](https://img.shields.io/github/forks/mthamil107/DB_Audit_Research.svg)


## CVE-2015-1805
 The (1) pipe_read and (2) pipe_write implementations in fs/pipe.c in the Linux kernel before 3.16 do not properly consider the side effects of failed __copy_to_user_inatomic and __copy_from_user_inatomic calls, which allows local users to cause a denial of service (system crash) or possibly gain privileges via a crafted application, aka an "I/O vector array overrun."

- [https://github.com/valentineus/hp-slate7-root-kit](https://github.com/valentineus/hp-slate7-root-kit) :  ![starts](https://img.shields.io/github/stars/valentineus/hp-slate7-root-kit.svg) ![forks](https://img.shields.io/github/forks/valentineus/hp-slate7-root-kit.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/IhsSpotlight/HeartBleed-CVE-2014-0160--SCRIPTS-python3](https://github.com/IhsSpotlight/HeartBleed-CVE-2014-0160--SCRIPTS-python3) :  ![starts](https://img.shields.io/github/stars/IhsSpotlight/HeartBleed-CVE-2014-0160--SCRIPTS-python3.svg) ![forks](https://img.shields.io/github/forks/IhsSpotlight/HeartBleed-CVE-2014-0160--SCRIPTS-python3.svg)

