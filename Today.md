# Update 2026-08-07
## CVE-2026-71211
 MLflow's AI Gateway accepts an auth_config.api_base value when creating a gateway secret (mlflow/server/handlers.py, _create_gateway_secret) with no validation of scheme, host, or IP range; the value is stored verbatim. The gateway proxy endpoint (mlflow/server/gateway_api.py, raw_proxy) subsequently issues an HTTP request to that stored api_base plus a caller-supplied path and returns the full response body. MLflow's existing SSRF guard, _validate_webhook_url (which blocks non-global and metadata IPs), is never invoked anywhere in this gateway secret/proxy code path. The CreateGatewaySecret action additionally has no entry in the permission-validator map, so it requires only basic authentication rather than any specific scope, meaning any authenticated user — including read-only accounts — can create a secret pointing at an internal address and reach it via the proxy endpoint, potentially exposing cloud-instance IAM credentials via metadata services. This is related to CVE-2026-4035, which addresses a distinct mechanism in the same gateway-secret feature (server-side $ENV_VAR resolution inside the api_key field leaking credentials to the configured upstream); the finding here is an independent missing-validation gap in the api_base destination itself, unaffected by that fix.

- [https://github.com/Abdivasiyev2008/CVE-2026-71211-exploit](https://github.com/Abdivasiyev2008/CVE-2026-71211-exploit) :  ![starts](https://img.shields.io/github/stars/Abdivasiyev2008/CVE-2026-71211-exploit.svg) ![forks](https://img.shields.io/github/forks/Abdivasiyev2008/CVE-2026-71211-exploit.svg)


## CVE-2026-65058
 Trezor Safe 3, Safe 5, and Safe 7 firmware contains a confirmation-binding flaw in the Ethereum sign_tx / sign_tx_eip1559 flow. For contract interactions, the device confirms only the initial calldata chunk while the signature commits to the full streamed calldata. An attacker could present calldata to a victim then supply a different tail that changes the signed transaction. Fixed in 70c9b0c.

- [https://github.com/helper-beeps/trezor-cve-2026-65058](https://github.com/helper-beeps/trezor-cve-2026-65058) :  ![starts](https://img.shields.io/github/stars/helper-beeps/trezor-cve-2026-65058.svg) ![forks](https://img.shields.io/github/forks/helper-beeps/trezor-cve-2026-65058.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/AnggaTechI/CVE-2026-63030](https://github.com/AnggaTechI/CVE-2026-63030) :  ![starts](https://img.shields.io/github/stars/AnggaTechI/CVE-2026-63030.svg) ![forks](https://img.shields.io/github/forks/AnggaTechI/CVE-2026-63030.svg)
- [https://github.com/minwunn/wp2shell-CVE-2026-63030](https://github.com/minwunn/wp2shell-CVE-2026-63030) :  ![starts](https://img.shields.io/github/stars/minwunn/wp2shell-CVE-2026-63030.svg) ![forks](https://img.shields.io/github/forks/minwunn/wp2shell-CVE-2026-63030.svg)
- [https://github.com/sowarma/wp2shell-PoC](https://github.com/sowarma/wp2shell-PoC) :  ![starts](https://img.shields.io/github/stars/sowarma/wp2shell-PoC.svg) ![forks](https://img.shields.io/github/forks/sowarma/wp2shell-PoC.svg)


## CVE-2026-60137
 WordPress 6.8.x before 6.8.6, 6.9.x before 6.9.5, and 7.0.x before 7.0.2 does not properly sanitise the author__not_in parameter of WP_Query, which could allow SQL Injection when a plugin or theme passes untrusted input to the parameter.

- [https://github.com/sowarma/wp2shell-PoC](https://github.com/sowarma/wp2shell-PoC) :  ![starts](https://img.shields.io/github/stars/sowarma/wp2shell-PoC.svg) ![forks](https://img.shields.io/github/forks/sowarma/wp2shell-PoC.svg)


## CVE-2026-59650
 In Bouncy Castle for Java before 1.85, MTI/A0 DH agreement exponentiates unvalidated peer value. This issue also affects Bouncy Castle for Java LTS before 2.73.12.

- [https://github.com/xiaoqiMikko/bc-check](https://github.com/xiaoqiMikko/bc-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/bc-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/bc-check.svg)


## CVE-2026-59638
 In Bouncy Castle for Java before 1.85, JSSE hostname verifier CN-fallback enabled by default despite documented opt-in. This issue also affects Bouncy Castle for Java LTS before 2.73.12, and Bouncy Castle for Java FIPS (BC-FJA) before bctls-fips 1.0.24 (1.0.X series), 2.0.24 (2.0.X series) and 2.1.24 (2.1.X series).

- [https://github.com/xiaoqiMikko/bc-check](https://github.com/xiaoqiMikko/bc-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/bc-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/bc-check.svg)


## CVE-2026-58062
 In Bouncy Castle for Java before 1.85, Stapled OCSP response accepted without binding to the checked certificate. This issue also affects Bouncy Castle for Java LTS before 2.73.12, and Bouncy Castle for Java FIPS (BC-FJA) before bc-fips 2.0.2 (2.0.X series) and 2.1.3 (2.1.X series).

- [https://github.com/xiaoqiMikko/bc-check](https://github.com/xiaoqiMikko/bc-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/bc-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/bc-check.svg)


## CVE-2026-55276
Users are recommended to upgrade to version 11.0.23, 10.1.56 or 9.0.119 which fixes the issue.

- [https://github.com/xiaoqiMikko/tomcat-check](https://github.com/xiaoqiMikko/tomcat-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/tomcat-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/tomcat-check.svg)


## CVE-2026-50130
 Pi-hole is a DNS sinkhole that protects devices from unwanted content without installing any client-side software. From 6.0 to 6.4.2, a user with code execution as the unprivileged pihole user can escalate to root by replacing /etc/pihole/logrotate. The replacement is laundered to root:root ownership by pihole-FTL-prestart.sh and then parsed as root by the daily pihole flush cron, executing firstaction shell as uid 0. This issue is fixed in version 6.4.3.

- [https://github.com/linnemanlabs/advisories](https://github.com/linnemanlabs/advisories) :  ![starts](https://img.shields.io/github/stars/linnemanlabs/advisories.svg) ![forks](https://img.shields.io/github/forks/linnemanlabs/advisories.svg)


## CVE-2026-44024
 Fluentd collects events from various data sources and writes them to files, RDBMS, NoSQL, IaaS, SaaS, Hadoop and so on. Prior to 1.19.3, Fluentd allows dynamically constructing file paths using the ${tag} placeholder, and insufficient validation of ${tag} in file configurations such as the path parameter of the out_file plugin allows attackers sending untrusted tags containing path traversal characters to write or overwrite arbitrary files and potentially achieve remote code execution. This issue is fixed in version 1.19.3.

- [https://github.com/0xdak/CVE-2026-44024_exploit](https://github.com/0xdak/CVE-2026-44024_exploit) :  ![starts](https://img.shields.io/github/stars/0xdak/CVE-2026-44024_exploit.svg) ![forks](https://img.shields.io/github/forks/0xdak/CVE-2026-44024_exploit.svg)


## CVE-2026-43500
page_pool RX, GRO).  The OOM/trace handling already in place is reused.

- [https://github.com/millikanjohnl-blip/dirtyfrag-detection-rules](https://github.com/millikanjohnl-blip/dirtyfrag-detection-rules) :  ![starts](https://img.shields.io/github/stars/millikanjohnl-blip/dirtyfrag-detection-rules.svg) ![forks](https://img.shields.io/github/forks/millikanjohnl-blip/dirtyfrag-detection-rules.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/millikanjohnl-blip/dirtyfrag-detection-rules](https://github.com/millikanjohnl-blip/dirtyfrag-detection-rules) :  ![starts](https://img.shields.io/github/stars/millikanjohnl-blip/dirtyfrag-detection-rules.svg) ![forks](https://img.shields.io/github/forks/millikanjohnl-blip/dirtyfrag-detection-rules.svg)


## CVE-2026-42533
 Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/0xCyberstan/CVE-2026-42533-POC](https://github.com/0xCyberstan/CVE-2026-42533-POC) :  ![starts](https://img.shields.io/github/stars/0xCyberstan/CVE-2026-42533-POC.svg) ![forks](https://img.shields.io/github/forks/0xCyberstan/CVE-2026-42533-POC.svg)


## CVE-2026-40982
Spring Cloud Config 3.1.x: affected from 3.1.0 through 3.1.13 (inclusive); upgrade to 3.1.14 or greater (Enterprise Support Only). Spring Cloud Config 4.1.x: affected from 4.1.0 through 4.1.9 (inclusive); upgrade to 4.1.10 or greater (Enterprise Support Only). Spring Cloud Config 4.2.x: affected from 4.2.0 through 4.2.6 (inclusive); upgrade to 4.2.7 or greater (Enterprise Support Only). Spring Cloud Config 4.3.x: affected from 4.3.0 through 4.3.2 (inclusive); upgrade to 4.3.3 or greater. Spring Cloud Config 5.0.x: affected from 5.0.0 through 5.0.2 (inclusive); upgrade to 5.0.3 or greater.

- [https://github.com/xiaoqiMikko/scc-check](https://github.com/xiaoqiMikko/scc-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/scc-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/scc-check.svg)


## CVE-2026-34990
 OpenPrinting CUPS is an open source printing system for Linux and other Unix-like operating systems. In versions 2.4.16 and prior, a local unprivileged user can coerce cupsd into authenticating to an attacker-controlled localhost IPP service with a reusable Authorization: Local ... token. That token is enough to drive /admin/ requests on localhost, and the attacker can combine CUPS-Create-Local-Printer with printer-is-shared=true to persist a file:///... queue even though the normal FileDevice policy rejects such URIs. Printing to that queue gives an arbitrary root file overwrite; the PoC below uses that primitive to drop a sudoers fragment and demonstrate root command execution. At time of publication, there are no publicly available patches.

- [https://github.com/HORKimhab/CVE-2026-34990](https://github.com/HORKimhab/CVE-2026-34990) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-34990.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-34990.svg)


## CVE-2026-34980
 OpenPrinting CUPS is an open source printing system for Linux and other Unix-like operating systems. In versions 2.4.16 and prior, in a network-exposed cupsd with a shared target queue, an unauthorized client can send a Print-Job to that shared PostScript queue without authentication. The server accepts a page-border value supplied as textWithoutLanguage, preserves an embedded newline through option escaping and reparse, and then reparses the resulting second-line PPD: text as a trusted scheduler control record. A follow-up raw print job can therefore make the server execute an attacker-chosen existing binary such as /usr/bin/vim as lp. At time of publication, there are no publicly available patches.

- [https://github.com/HORKimhab/CVE-2026-34980](https://github.com/HORKimhab/CVE-2026-34980) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-34980.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-34980.svg)


## CVE-2026-33017
 Langflow is a tool for building and deploying AI-powered agents and workflows. In versions prior to 1.9.0, the POST /api/v1/build_public_tmp/{flow_id}/flow endpoint allows building public flows without requiring authentication. When the optional data parameter is supplied, the endpoint uses attacker-controlled flow data (containing arbitrary Python code in node definitions) instead of the stored flow data from the database. This code is passed to exec() with zero sandboxing, resulting in unauthenticated remote code execution. This is distinct from CVE-2025-3248, which fixed /api/v1/validate/code by adding authentication. The build_public_tmp endpoint is designed to be unauthenticated (for public flows) but incorrectly accepts attacker-supplied flow data containing arbitrary executable code. This issue has been fixed in version 1.9.0.

- [https://github.com/TatoSec/CVE-2026-33017-Langflop](https://github.com/TatoSec/CVE-2026-33017-Langflop) :  ![starts](https://img.shields.io/github/stars/TatoSec/CVE-2026-33017-Langflop.svg) ![forks](https://img.shields.io/github/forks/TatoSec/CVE-2026-33017-Langflop.svg)


## CVE-2026-28372
 telnetd in GNU inetutils through 2.7 allows privilege escalation that can be exploited by abusing systemd service credentials support added to the login(1) implementation of util-linux in release 2.40. This is related to client control over the CREDENTIALS_DIRECTORY environment variable, and requires an unprivileged local user to create a login.noauth file.

- [https://github.com/SafeBreach-Labs/ForgottenButNotGone](https://github.com/SafeBreach-Labs/ForgottenButNotGone) :  ![starts](https://img.shields.io/github/stars/SafeBreach-Labs/ForgottenButNotGone.svg) ![forks](https://img.shields.io/github/forks/SafeBreach-Labs/ForgottenButNotGone.svg)


## CVE-2026-27912
 Improper authorization in Windows Kerberos allows an authorized attacker to elevate privileges over an adjacent network.

- [https://github.com/Semperis-Community/ResetNightmare](https://github.com/Semperis-Community/ResetNightmare) :  ![starts](https://img.shields.io/github/stars/Semperis-Community/ResetNightmare.svg) ![forks](https://img.shields.io/github/forks/Semperis-Community/ResetNightmare.svg)


## CVE-2026-23489
 Fields is a GLPI plugin that allows users to add custom fields on GLPI items forms. Prior to version 1.23.3, it is possible to execute arbitrary PHP code from users that are allowed to create dropdowns. This issue has been patched in version 1.23.3.

- [https://github.com/eorll-lgtm/poc-CVE-2026-23489](https://github.com/eorll-lgtm/poc-CVE-2026-23489) :  ![starts](https://img.shields.io/github/stars/eorll-lgtm/poc-CVE-2026-23489.svg) ![forks](https://img.shields.io/github/forks/eorll-lgtm/poc-CVE-2026-23489.svg)


## CVE-2026-23010
---truncated---

- [https://github.com/George0Papasotiriou/CVE-2026-23010-CCSDS-Telecommand-Replay-Without-Sequence-Number](https://github.com/George0Papasotiriou/CVE-2026-23010-CCSDS-Telecommand-Replay-Without-Sequence-Number) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-23010-CCSDS-Telecommand-Replay-Without-Sequence-Number.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-23010-CCSDS-Telecommand-Replay-Without-Sequence-Number.svg)


## CVE-2026-23009
then it is up to the class driver to ensure endpoint is properly set up.

- [https://github.com/George0Papasotiriou/CVE-2026-23009-DICOM-Network-Image-Injection-Without-Authentication](https://github.com/George0Papasotiriou/CVE-2026-23009-DICOM-Network-Image-Injection-Without-Authentication) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-23009-DICOM-Network-Image-Injection-Without-Authentication.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-23009-DICOM-Network-Image-Injection-Without-Authentication.svg)


## CVE-2026-23008
the driver causing a black screen.

- [https://github.com/George0Papasotiriou/CVE-2026-23008-Solidity-Assembly-Return-Data-Size-Confusion](https://github.com/George0Papasotiriou/CVE-2026-23008-Solidity-Assembly-Return-Data-Size-Confusion) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-23008-Solidity-Assembly-Return-Data-Size-Confusion.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-23008-Solidity-Assembly-Return-Data-Size-Confusion.svg)


## CVE-2026-23007
metadata is larger than just the PI tuple.

- [https://github.com/George0Papasotiriou/CVE-2026-23007-Serverless-Cold-Start-Memory-Remanence-Data-Leakage-](https://github.com/George0Papasotiriou/CVE-2026-23007-Serverless-Cold-Start-Memory-Remanence-Data-Leakage-) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-23007-Serverless-Cold-Start-Memory-Remanence-Data-Leakage-.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-23007-Serverless-Cold-Start-Memory-Remanence-Data-Leakage-.svg)


## CVE-2026-23006
"adcx140_priv".

- [https://github.com/George0Papasotiriou/CVE-2026-23006-Kyber-Ciphertext-Length-Side-Channel](https://github.com/George0Papasotiriou/CVE-2026-23006-Kyber-Ciphertext-Length-Side-Channel) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-23006-Kyber-Ciphertext-Length-Side-Channel.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-23006-Kyber-Ciphertext-Length-Side-Channel.svg)


## CVE-2026-23005
---truncated---

- [https://github.com/George0Papasotiriou/CVE-2026-23005-Matter-Commissioning-Code-Brute-Force-Without-Rate-Limit](https://github.com/George0Papasotiriou/CVE-2026-23005-Matter-Commissioning-Code-Brute-Force-Without-Rate-Limit) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-23005-Matter-Commissioning-Code-Brute-Force-Without-Rate-Limit.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-23005-Matter-Commissioning-Code-Brute-Force-Without-Rate-Limit.svg)


## CVE-2026-23004
---truncated---

- [https://github.com/George0Papasotiriou/CVE-2026-23004-Automotive-UDS-Authentication-Bypass-via-Replay-Attack](https://github.com/George0Papasotiriou/CVE-2026-23004-Automotive-UDS-Authentication-Bypass-via-Replay-Attack) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-23004-Automotive-UDS-Authentication-Bypass-via-Replay-Attack.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-23004-Automotive-UDS-Authentication-Bypass-via-Replay-Attack.svg)


## CVE-2026-23003
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 10/25/2025

- [https://github.com/George0Papasotiriou/CVE-2026-23003-Cross-Chain-Bridge-Message-Forging-via-Missing-Origin-Chain-ID](https://github.com/George0Papasotiriou/CVE-2026-23003-Cross-Chain-Bridge-Message-Forging-via-Missing-Origin-Chain-ID) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-23003-Cross-Chain-Bridge-Message-Forging-via-Missing-Origin-Chain-ID.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-23003-Cross-Chain-Bridge-Message-Forging-via-Missing-Origin-Chain-ID.svg)


## CVE-2026-23002
buildid code.

- [https://github.com/George0Papasotiriou/CVE-2026-23002-5G-NAS-Message-Buffer-Overflow-in-gNodeB](https://github.com/George0Papasotiriou/CVE-2026-23002-5G-NAS-Message-Buffer-Overflow-in-gNodeB) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-23002-5G-NAS-Message-Buffer-Overflow-in-gNodeB.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-23002-5G-NAS-Message-Buffer-Overflow-in-gNodeB.svg)


## CVE-2026-23001
https: //lore.kernel.org/netdev/695fb1e8.050a0220.1c677c.039f.GAE@google.com/T/#u

- [https://github.com/George0Papasotiriou/CVE-2026-23001-Hugging-Face-Transformers-Model-Deserialization-Arbitrary-Code-via-Pickle-](https://github.com/George0Papasotiriou/CVE-2026-23001-Hugging-Face-Transformers-Model-Deserialization-Arbitrary-Code-via-Pickle-) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-23001-Hugging-Face-Transformers-Model-Deserialization-Arbitrary-Code-via-Pickle-.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-23001-Hugging-Face-Transformers-Model-Deserialization-Arbitrary-Code-via-Pickle-.svg)


## CVE-2026-20200
This vulnerability is due to improper validation of user-supplied input. An attacker could exploit this vulnerability by entering crafted inputs to the web-based management interface of the affected software. A successful exploit could allow the attacker to execute arbitrary commands on the underlying operating system as the root user.&nbsp;

- [https://github.com/NSIDE-ATTACK-LOGIC/CIMCown](https://github.com/NSIDE-ATTACK-LOGIC/CIMCown) :  ![starts](https://img.shields.io/github/stars/NSIDE-ATTACK-LOGIC/CIMCown.svg) ![forks](https://img.shields.io/github/forks/NSIDE-ATTACK-LOGIC/CIMCown.svg)


## CVE-2026-18577
 An incomplete patch for CVE-2026-18556 allows for authentication bypass and account takeover in N-central Versions through 2026.3.1

- [https://github.com/CreamyG31337/ncentral-compromise-ioc-triage](https://github.com/CreamyG31337/ncentral-compromise-ioc-triage) :  ![starts](https://img.shields.io/github/stars/CreamyG31337/ncentral-compromise-ioc-triage.svg) ![forks](https://img.shields.io/github/forks/CreamyG31337/ncentral-compromise-ioc-triage.svg)


## CVE-2026-18556
This issue affects N-central: through 2026.1.

- [https://github.com/CreamyG31337/ncentral-compromise-ioc-triage](https://github.com/CreamyG31337/ncentral-compromise-ioc-triage) :  ![starts](https://img.shields.io/github/stars/CreamyG31337/ncentral-compromise-ioc-triage.svg) ![forks](https://img.shields.io/github/forks/CreamyG31337/ncentral-compromise-ioc-triage.svg)


## CVE-2026-17583
Thermo Fisher Applied Biosystems Genetic Analyzers are vulnerable because .fsa/.hid output files can be edited. An attacker could tamper with these files, altering DNA data and resulting in inaccurate DNA test outcomes.

- [https://github.com/HORKimhab/CVE-2026-17583](https://github.com/HORKimhab/CVE-2026-17583) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-17583.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-17583.svg)


## CVE-2026-17532
 The Seraphinite Accelerator plugin for WordPress is vulnerable to Reflected Cross-Site Scripting via the 'seraph_accel_prep' parameter in versions up to, and including, 2.29.15. This is due to the CacheExtractPreparePageParams() function using PHP's loose inequality operator (!=) to compare the expected HMAC string against the JSON-decoded 'nonce' value — supplying the JSON boolean true causes any non-empty HMAC string to compare as loosely equal, bypassing the signature check — combined with insufficient output escaping in the _CbContentFinishSkip() function, which concatenates the attacker-controlled 'selfTest' field directly into the HTML response body. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that execute if they can successfully trick a user into performing an action such as clicking on a specially crafted link.

- [https://github.com/kalhoralireza/CVE-2026-17532](https://github.com/kalhoralireza/CVE-2026-17532) :  ![starts](https://img.shields.io/github/stars/kalhoralireza/CVE-2026-17532.svg) ![forks](https://img.shields.io/github/forks/kalhoralireza/CVE-2026-17532.svg)


## CVE-2026-16723
 A remote code execution (RCE) vulnerability exists in fastjson 1.2.68 through 1.2.83. This vulnerability is exploitable under fastjson's stock default configuration — no AutoType enablement required, no classpath gadget required.

- [https://github.com/learner330/fastjson-cve-2026-16723](https://github.com/learner330/fastjson-cve-2026-16723) :  ![starts](https://img.shields.io/github/stars/learner330/fastjson-cve-2026-16723.svg) ![forks](https://img.shields.io/github/forks/learner330/fastjson-cve-2026-16723.svg)


## CVE-2026-15430
lsass.exe, and terminate PPL-protected security processes.

- [https://github.com/BlackSnufkin/AxHunter](https://github.com/BlackSnufkin/AxHunter) :  ![starts](https://img.shields.io/github/stars/BlackSnufkin/AxHunter.svg) ![forks](https://img.shields.io/github/forks/BlackSnufkin/AxHunter.svg)


## CVE-2026-13934
 Insufficient validation of untrusted input in Dawn in Google Chrome on Android prior to 150.0.7871.47 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/ArtWide/cve-2026-13934](https://github.com/ArtWide/cve-2026-13934) :  ![starts](https://img.shields.io/github/stars/ArtWide/cve-2026-13934.svg) ![forks](https://img.shields.io/github/forks/ArtWide/cve-2026-13934.svg)


## CVE-2026-9198
 IBM Langflow OSS 1.0.0 through 1.10.0 allows unauthenticated attackers to chain /api/v1/auto_login (mints SUPERUSER tokens to any network caller) with /api/v1/validate/code (executes user code via exec()) to achieve full RCE on default Langflow deployments

- [https://github.com/rmhowe425/PoC-CVE-2026-9198](https://github.com/rmhowe425/PoC-CVE-2026-9198) :  ![starts](https://img.shields.io/github/stars/rmhowe425/PoC-CVE-2026-9198.svg) ![forks](https://img.shields.io/github/forks/rmhowe425/PoC-CVE-2026-9198.svg)


## CVE-2026-8763
 In Bouncy Castle for Java before 1.85, Name Constraints bypass via trailing dot in rfc822Name and URI. This issue also affects Bouncy Castle for Java LTS before 2.73.12, and Bouncy Castle for Java FIPS (BC-FJA) before bc-fips 1.0.2.7 (1.0.X series), 2.0.2 (2.0.X series) and 2.1.3 (2.1.X series).

- [https://github.com/xiaoqiMikko/bc-check](https://github.com/xiaoqiMikko/bc-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/bc-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/bc-check.svg)


## CVE-2026-8149
This issue affects BC-LTS: from 2.73.0 before 2.73.11; BC-FJA: from 2.1.0 before 2.1.3.

- [https://github.com/xiaoqiMikko/bc-check](https://github.com/xiaoqiMikko/bc-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/bc-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/bc-check.svg)


## CVE-2026-6800
 The FastBots plugin for WordPress is vulnerable to Stored Cross-Site Scripting via admin settings in all versions up to, and including, 1.0.12 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with administrator-level permissions and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page. This only affects multi-site installations and installations where unfiltered_html has been disabled.

- [https://github.com/xuwu-xuwu/CVE-2026-68004](https://github.com/xuwu-xuwu/CVE-2026-68004) :  ![starts](https://img.shields.io/github/stars/xuwu-xuwu/CVE-2026-68004.svg) ![forks](https://img.shields.io/github/forks/xuwu-xuwu/CVE-2026-68004.svg)


## CVE-2026-5027
 The 'POST /api/v2/files' endpoint does not sanitize the 'filename' parameter from the multipart form data, allowing an attacker to write files to arbitrary locations on the filesystem using path traversal sequences ('../').

- [https://github.com/HORKimhab/CVE-2026-5027](https://github.com/HORKimhab/CVE-2026-5027) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-5027.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-5027.svg)


## CVE-2026-4480
substitution character without escaping shell meta characters. A remote attacker could exploit this vulnerability by sending a specially crafted print job description that contains unescaped shell characters. This could lead to remote code execution on the affected system.

- [https://github.com/SafeBreach-Labs/ForgottenButNotGone](https://github.com/SafeBreach-Labs/ForgottenButNotGone) :  ![starts](https://img.shields.io/github/stars/SafeBreach-Labs/ForgottenButNotGone.svg) ![forks](https://img.shields.io/github/forks/SafeBreach-Labs/ForgottenButNotGone.svg)


## CVE-2026-4408
 A flaw was found in Samba. A remote attacker can exploit a misconfiguration in Samba file servers and classic domain controllers that use the "check password script" feature. If this script is configured with the %u substitution character, the client-controlled username is passed without proper escaping of shell meta-characters. This vulnerability allows an attacker to achieve remote command execution on the affected system. This issue primarily affects non-standard configurations where the "check password script" is used with %u and the samba-dcerpcd service is started as a system service.

- [https://github.com/SafeBreach-Labs/ForgottenButNotGone](https://github.com/SafeBreach-Labs/ForgottenButNotGone) :  ![starts](https://img.shields.io/github/stars/SafeBreach-Labs/ForgottenButNotGone.svg) ![forks](https://img.shields.io/github/forks/SafeBreach-Labs/ForgottenButNotGone.svg)


## CVE-2026-0092
 In Package Manager, there is a possible device lock controller bypass due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/Majorjayyy1/CVE-2026-0092](https://github.com/Majorjayyy1/CVE-2026-0092) :  ![starts](https://img.shields.io/github/stars/Majorjayyy1/CVE-2026-0092.svg) ![forks](https://img.shields.io/github/forks/Majorjayyy1/CVE-2026-0092.svg)


## CVE-2025-70962
 Zosi C519M V4.2.8.823C01450BA is vulnerable to Incorrect Access Control. The application contains hardcoded credentials in the RTSP authentication mechanism. An attacker with network access can use the unchangeable default credentials to access the RTSP video stream, resulting in unauthorized viewing of camera footage.

- [https://github.com/namaek2/CVE-2025-70962](https://github.com/namaek2/CVE-2025-70962) :  ![starts](https://img.shields.io/github/stars/namaek2/CVE-2025-70962.svg) ![forks](https://img.shields.io/github/forks/namaek2/CVE-2025-70962.svg)


## CVE-2025-66390
 In Microsoft Azure API Management through 2025-10-17, when self-service signup (username/password Basic Authentication) is enabled in Tenant A, an attacker can reuse the registration flow by changing the hostname or tenant identifier to Tenant B, even when Tenant B has signup disabled at the UI level. In other words, disabling signup in the UI does not disable the underlying API endpoint (which still accepts cross-tenant requests based on the Host header). NOTE: The supplier states that they evaluated the report and determined it did not cross a security boundary (i.e., the observed behavior was a configuration/state issue rather than an exploitable product vulnerability affecting tenant isolation). NOTE: The supplier evaluated this report and determined that it did not cross a security boundary (i.e., the observed behavior was a configuration/state issue rather than an exploitable product vulnerability affecting tenant isolation).

- [https://github.com/dz-y/Azure-APIM-Dev-Portal-Signup-Bypass](https://github.com/dz-y/Azure-APIM-Dev-Portal-Signup-Bypass) :  ![starts](https://img.shields.io/github/stars/dz-y/Azure-APIM-Dev-Portal-Signup-Bypass.svg) ![forks](https://img.shields.io/github/forks/dz-y/Azure-APIM-Dev-Portal-Signup-Bypass.svg)


## CVE-2025-32432
 Craft is a flexible, user-friendly CMS for creating custom digital experiences on the web and beyond. Starting from version 3.0.0-RC1 to before 3.9.15, 4.0.0-RC1 to before 4.14.15, and 5.0.0-RC1 to before 5.6.17, Craft is vulnerable to remote code execution. This is a high-impact, low-complexity attack vector. This issue has been patched in versions 3.9.15, 4.14.15, and 5.6.17, and is an additional fix for CVE-2023-41892.

- [https://github.com/PsyGuy007-sys/craftcms-cve-2025-32432-rce](https://github.com/PsyGuy007-sys/craftcms-cve-2025-32432-rce) :  ![starts](https://img.shields.io/github/stars/PsyGuy007-sys/craftcms-cve-2025-32432-rce.svg) ![forks](https://img.shields.io/github/forks/PsyGuy007-sys/craftcms-cve-2025-32432-rce.svg)


## CVE-2025-32375
 BentoML is a Python library for building online serving systems optimized for AI apps and model inference. Prior to 1.4.8, there was an insecure deserialization in BentoML's runner server. By setting specific headers and parameters in the POST request, it is possible to execute any unauthorized arbitrary code on the server, which will grant the attackers to have the initial access and information disclosure on the server. This vulnerability is fixed in 1.4.8.

- [https://github.com/SevdaKhidirova/CVE-2025-32375-PoC](https://github.com/SevdaKhidirova/CVE-2025-32375-PoC) :  ![starts](https://img.shields.io/github/stars/SevdaKhidirova/CVE-2025-32375-PoC.svg) ![forks](https://img.shields.io/github/forks/SevdaKhidirova/CVE-2025-32375-PoC.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/NamelessSaint8/CVE-2025-24813-POC](https://github.com/NamelessSaint8/CVE-2025-24813-POC) :  ![starts](https://img.shields.io/github/stars/NamelessSaint8/CVE-2025-24813-POC.svg) ![forks](https://img.shields.io/github/forks/NamelessSaint8/CVE-2025-24813-POC.svg)


## CVE-2025-8110
 Improper Symbolic link handling in the PutContents API in Gogs allows Local Execution of Code.

- [https://github.com/9xh4kv/CVE-2025-8110](https://github.com/9xh4kv/CVE-2025-8110) :  ![starts](https://img.shields.io/github/stars/9xh4kv/CVE-2025-8110.svg) ![forks](https://img.shields.io/github/forks/9xh4kv/CVE-2025-8110.svg)


## CVE-2025-3037
 A vulnerability has been found in yzk2356911358 StudentServlet-JSP cc0cdce25fbe43b6c58b60a77a2c85f52d2102f5/d4d7a0643f1dae908a4831206f2714b21820f991 and classified as problematic. This vulnerability affects unknown code. The manipulation leads to cross-site request forgery. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. Continious delivery with rolling releases is used by this product. Therefore, no version details of affected nor updated releases are available.

- [https://github.com/jackfromeast/CVE-2025-30374](https://github.com/jackfromeast/CVE-2025-30374) :  ![starts](https://img.shields.io/github/stars/jackfromeast/CVE-2025-30374.svg) ![forks](https://img.shields.io/github/forks/jackfromeast/CVE-2025-30374.svg)


## CVE-2024-2961
 The iconv() function in the GNU C Library versions 2.39 and older may overflow the output buffer passed to it by up to 4 bytes when converting strings to the ISO-2022-CN-EXT character set, which may be used to crash an application or overwrite a neighbouring variable.

- [https://github.com/HORKimhab/CVE-2022-31626-CVE-2024-2961-CVE-2019-6977](https://github.com/HORKimhab/CVE-2022-31626-CVE-2024-2961-CVE-2019-6977) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2022-31626-CVE-2024-2961-CVE-2019-6977.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2022-31626-CVE-2024-2961-CVE-2019-6977.svg)

