# Update 2026-09-08
## CVE-2026-82222
This issue affects GiveWP: from n/a through 4.16.7.1.

- [https://github.com/0xCyp1337/CVE-2026-82222-MassExploit](https://github.com/0xCyp1337/CVE-2026-82222-MassExploit) :  ![starts](https://img.shields.io/github/stars/0xCyp1337/CVE-2026-82222-MassExploit.svg) ![forks](https://img.shields.io/github/forks/0xCyp1337/CVE-2026-82222-MassExploit.svg)


## CVE-2026-67276
 RouterOS does not compare the complete RSA public key when matching an SSH authentication request to an authorized user key, checking the key type and modulus but omitting the exponent. Because signature verification uses the client-supplied key, an attacker knowing an authorized RSA modulus can supply a key with exponent one, forge a valid signature, and open an SSH command channel as the target user without the private key.This issue was fixed in versions: 6.49.21 (Long-term), 7.23.4 (Long-term) and 7.24.2 (Stable)

- [https://github.com/dinosn/mikrotrick-poc](https://github.com/dinosn/mikrotrick-poc) :  ![starts](https://img.shields.io/github/stars/dinosn/mikrotrick-poc.svg) ![forks](https://img.shields.io/github/forks/dinosn/mikrotrick-poc.svg)


## CVE-2026-64849
 MLflow is an open source AI engineering platform for agents, large language models, and machine learning models. Prior to 3.15.0, the unauthenticated POST /api/2.0/mlflow/webhooks/{id}/test endpoint calls _validate_webhook_url() in mlflow/utils/validation.py only for the original URL while mlflow/webhooks/delivery.py follows redirects and re-resolves the hostname without pinning the validated address, allowing attackers to reach internal or cloud metadata services and receive response_status and response_body. This issue is fixed in version 3.15.0.

- [https://github.com/isaca0315/CVE-2026-64849-poc-lab](https://github.com/isaca0315/CVE-2026-64849-poc-lab) :  ![starts](https://img.shields.io/github/stars/isaca0315/CVE-2026-64849-poc-lab.svg) ![forks](https://img.shields.io/github/forks/isaca0315/CVE-2026-64849-poc-lab.svg)


## CVE-2026-49777
This issue affects Product Slider Pro for WooCommerce: from n/a before 3.5.4.

- [https://github.com/katranSefa/CVE-2026-49777](https://github.com/katranSefa/CVE-2026-49777) :  ![starts](https://img.shields.io/github/stars/katranSefa/CVE-2026-49777.svg) ![forks](https://img.shields.io/github/forks/katranSefa/CVE-2026-49777.svg)


## CVE-2026-44578
 Next.js is a React framework for building full-stack web applications. From 13.4.13 to before 15.5.16 and 16.2.5, self-hosted applications using the built-in Node.js server can be vulnerable to server-side request forgery through crafted WebSocket upgrade requests. An attacker can cause the server to proxy requests to arbitrary internal or external destinations, which may expose internal services or cloud metadata endpoints. Vercel-hosted deployments are not affected. This vulnerability is fixed in 15.5.16 and 16.2.5.

- [https://github.com/isaca0315/CVE-2026-44578-next-js-ssrf](https://github.com/isaca0315/CVE-2026-44578-next-js-ssrf) :  ![starts](https://img.shields.io/github/stars/isaca0315/CVE-2026-44578-next-js-ssrf.svg) ![forks](https://img.shields.io/github/forks/isaca0315/CVE-2026-44578-next-js-ssrf.svg)


## CVE-2026-44402
 Voltronic Power SNMP Web Pro 1.1 contains an unauthenticated remote code execution vulnerability in the upload.cgi firmware update endpoint that allows remote attackers to execute arbitrary commands as root by uploading a crafted tar archive without valid credentials. Attackers can supply a malicious tar archive containing arbitrary executable files that are extracted to a privileged directory and executed as root, achieving full system compromise.

- [https://github.com/0xCyp1337/CVE-2026-44402](https://github.com/0xCyp1337/CVE-2026-44402) :  ![starts](https://img.shields.io/github/stars/0xCyp1337/CVE-2026-44402.svg) ![forks](https://img.shields.io/github/forks/0xCyp1337/CVE-2026-44402.svg)


## CVE-2026-44246
 nnU-Net is a semantic segmentation framework that automatically adapts its pipeline to a dataset. Prior to 2.4.1, the nnU-Net Issue Triage workflow in .github/workflows/issue-triage.yml is vulnerable to Agentic Workflow Injection. The workflow sets allowed_non_write_users: ${{ github.event.issue.user.login }}, which means any logged-in GitHub user who opens an issue can reach this agentic workflow with attacker-controlled content. Untrusted issue title and body content are embedded directly into the prompt of anthropics/claude-code-action, and the workflow then runs a command-capable Claude agent with permission to comment on and relabel the current issue via gh. Because this workflow is triggered automatically on issues.opened, an external attacker can submit a crafted issue that steers the agent beyond its intended issue-triage purpose and influences authenticated issue actions. This vulnerability is fixed in 2.4.1.

- [https://github.com/pvharmo2/gha-lab-733c168b88](https://github.com/pvharmo2/gha-lab-733c168b88) :  ![starts](https://img.shields.io/github/stars/pvharmo2/gha-lab-733c168b88.svg) ![forks](https://img.shields.io/github/forks/pvharmo2/gha-lab-733c168b88.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/dorlow/hazel-cve-2026-43499](https://github.com/dorlow/hazel-cve-2026-43499) :  ![starts](https://img.shields.io/github/stars/dorlow/hazel-cve-2026-43499.svg) ![forks](https://img.shields.io/github/forks/dorlow/hazel-cve-2026-43499.svg)


## CVE-2026-42559
 RMCP is an official Rust SDK for the Model Context Protocol. Prior to version 1.4.0, the rmcp crate's Streamable HTTP server transport (crates/rmcp/src/transport/streamable_http_server/) did not validate the incoming Host header. This allowed a malicious public website, via a DNS rebinding attack, to send authenticated requests to an MCP server running on the victim's loopback or private-network interface. This vulnerability is fixed in 1.4.0.

- [https://github.com/joaovicdev/CVE-2026-42559](https://github.com/joaovicdev/CVE-2026-42559) :  ![starts](https://img.shields.io/github/stars/joaovicdev/CVE-2026-42559.svg) ![forks](https://img.shields.io/github/forks/joaovicdev/CVE-2026-42559.svg)


## CVE-2026-42298
 Postiz is an AI social media scheduling tool. Prior to commit da44801, a "Pwn Request" vulnerability in the Build and Publish PR Docker Image workflow (.github/workflows/pr-docker-build.yml) allows any unauthenticated user to execute arbitrary code during the Docker build process and exfiltrate a highly privileged GITHUB_TOKEN (write-all permissions). This can be achieved simply by opening a Pull Request from a fork with a maliciously modified Dockerfile.dev. This issue has been patched via commit da44801.

- [https://github.com/pvharmo2/gha-lab-677752506e](https://github.com/pvharmo2/gha-lab-677752506e) :  ![starts](https://img.shields.io/github/stars/pvharmo2/gha-lab-677752506e.svg) ![forks](https://img.shields.io/github/forks/pvharmo2/gha-lab-677752506e.svg)


## CVE-2026-41414
 Skim is a fuzzy finder designed to through files, lines, and commands. The generate-files job in .github/workflows/pr.yml checks out attacker-controlled fork code and executes it via cargo run, with access to SKIM_RS_BOT_PRIVATE_KEY and GITHUB_TOKEN (contents:write). No gates prevent exploitation - any GitHub user can trigger this by opening a pull request from a fork. This vulnerability is fixed with commit bf63404ad51985b00ed304690ba9d477860a5a75.

- [https://github.com/pvharmo2/gha-lab-456dd8a245](https://github.com/pvharmo2/gha-lab-456dd8a245) :  ![starts](https://img.shields.io/github/stars/pvharmo2/gha-lab-456dd8a245.svg) ![forks](https://img.shields.io/github/forks/pvharmo2/gha-lab-456dd8a245.svg)


## CVE-2026-41249
 CoreShop is a Pimcore enhanced eCommerce solution. In versions 5.0.1 through 5.1.0-beta.1,, the GitHub Actions workflow (`.github/workflows/static.yml`) uses the `pull_request_target` trigger but dangerously checks out the unverified code from the pull request head (`ref: ${{ github.event.pull_request.head.ref }}`). Subsequently, it executes a script (`bin/console`) from this untrusted checkout. This allows any external attacker to achieve Remote Code Execution (RCE) on the GitHub Actions runner simply by submitting a malicious Pull Request. Also known as a "Pwn Request" vulnerability. As of time of publication, `pull_request_target` is still in the file.

- [https://github.com/pvharmo2/gha-lab-5bce203f66](https://github.com/pvharmo2/gha-lab-5bce203f66) :  ![starts](https://img.shields.io/github/stars/pvharmo2/gha-lab-5bce203f66.svg) ![forks](https://img.shields.io/github/forks/pvharmo2/gha-lab-5bce203f66.svg)


## CVE-2026-39866
 Lawnchair is a free, open-source home app for Android. Prior to commit fcba413f55dd47f8a3921445252849126c6266b2, command injection in release_update.yml workflow dispatch input allows arbitrary code execution. Commit fcba413f55dd47f8a3921445252849126c6266b2 patches the issue.

- [https://github.com/pvharmo2/gha-lab-360f77d0d4](https://github.com/pvharmo2/gha-lab-360f77d0d4) :  ![starts](https://img.shields.io/github/stars/pvharmo2/gha-lab-360f77d0d4.svg) ![forks](https://img.shields.io/github/forks/pvharmo2/gha-lab-360f77d0d4.svg)


## CVE-2026-19949
 The All-in-One WP Migration and Backup plugin for WordPress is vulnerable to SQL Injection via archive restore functionality in all versions up to, and including, 7.109 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query. This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database. This can be leveraged to obtain the ai1wm_secret_key when a site administrator performs an archive restore and achieve remote code execution once able to leverage the ai1wm_secret_key value.

- [https://github.com/katranSefa/CVE-2026-19949](https://github.com/katranSefa/CVE-2026-19949) :  ![starts](https://img.shields.io/github/stars/katranSefa/CVE-2026-19949.svg) ![forks](https://img.shields.io/github/forks/katranSefa/CVE-2026-19949.svg)


## CVE-2026-18963
 A flaw was found in the reset-credentials flow of the keycloak-services component, which is the core engine for identity and access management in Red Hat Build of Keycloak. The issue allows an unauthenticated attacker to force the password reset process for any user without needing to click the required email verification link. This can result in the attacker gaining full control over target user accounts by directly setting new credentials.

- [https://github.com/ynsmroztas/KeySniper](https://github.com/ynsmroztas/KeySniper) :  ![starts](https://img.shields.io/github/stars/ynsmroztas/KeySniper.svg) ![forks](https://img.shields.io/github/forks/ynsmroztas/KeySniper.svg)


## CVE-2026-6279
 The Avada Builder (fusion-builder) plugin for WordPress is vulnerable to Unauthenticated Remote Code Execution via PHP Function Injection in versions up to and including 3.15.2. This is due to the `wp_conditional_tags` case in `Fusion_Builder_Conditional_Render_Helper::get_value()` passing attacker-controlled values from a base64-decoded JSON blob directly to `call_user_func()` without any allowlist validation. This is exploitable by unauthenticated attackers through the `fusion_get_widget_markup` AJAX endpoint, which is registered for non-privileged (unauthenticated) users via `wp_ajax_nopriv_fusion_get_widget_markup`. The endpoint is protected only by a nonce (`fusion_load_nonce`), but this nonce is generated for user ID 0 and is deterministically exposed in the JavaScript output of any public-facing page containing a Post Cards (`[fusion_post_cards]`) or Table of Contents (`[fusion_table_of_contents]`) element. This makes it possible for unauthenticated attackers to execute arbitrary code on affected sites.

- [https://github.com/katranSefa/CVE-2026-6279](https://github.com/katranSefa/CVE-2026-6279) :  ![starts](https://img.shields.io/github/stars/katranSefa/CVE-2026-6279.svg) ![forks](https://img.shields.io/github/forks/katranSefa/CVE-2026-6279.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/pimpamebanihah/cve-2026-43499-app.so](https://github.com/pimpamebanihah/cve-2026-43499-app.so) :  ![starts](https://img.shields.io/github/stars/pimpamebanihah/cve-2026-43499-app.so.svg) ![forks](https://img.shields.io/github/forks/pimpamebanihah/cve-2026-43499-app.so.svg)


## CVE-2025-57819
 FreePBX is an open-source web-based graphical user interface. FreePBX 15, 16, and 17 endpoints are vulnerable due to insufficiently sanitized user-supplied data allowing unauthenticated access to FreePBX Administrator leading to arbitrary database manipulation and remote code execution. This issue has been patched in endpoint versions 15.0.66, 16.0.89, and 17.0.3.

- [https://github.com/r3vpwnx/CVE-2025-57819](https://github.com/r3vpwnx/CVE-2025-57819) :  ![starts](https://img.shields.io/github/stars/r3vpwnx/CVE-2025-57819.svg) ![forks](https://img.shields.io/github/forks/r3vpwnx/CVE-2025-57819.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/EthanEvans92/CVE-2025-32463](https://github.com/EthanEvans92/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/EthanEvans92/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/EthanEvans92/CVE-2025-32463.svg)


## CVE-2025-31324
 SAP NetWeaver Visual Composer Metadata Uploader is not protected with a proper authorization, allowing unauthenticated agent to upload potentially malicious executable binaries that could severely harm the host system. This could significantly affect the confidentiality, integrity, and availability of the targeted system.

- [https://github.com/HKenzoKimura/CVE-2025-31324](https://github.com/HKenzoKimura/CVE-2025-31324) :  ![starts](https://img.shields.io/github/stars/HKenzoKimura/CVE-2025-31324.svg) ![forks](https://img.shields.io/github/forks/HKenzoKimura/CVE-2025-31324.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/all3njk/NextJS_CVE-2025-29927](https://github.com/all3njk/NextJS_CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/all3njk/NextJS_CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/all3njk/NextJS_CVE-2025-29927.svg)


## CVE-2025-13407
 The Gravity Forms WordPress plugin before 2.9.23.1 does not properly prevent users from uploading dangerous files through its chunked upload functionality, allowing attackers to upload PHP files to affected sites and achieve Remote Code Execution, granted they can discover or enumerate the upload path.

- [https://github.com/katranSefa/CVE--2025-13407](https://github.com/katranSefa/CVE--2025-13407) :  ![starts](https://img.shields.io/github/stars/katranSefa/CVE--2025-13407.svg) ![forks](https://img.shields.io/github/forks/katranSefa/CVE--2025-13407.svg)


## CVE-2025-2992
 A vulnerability classified as critical was found in Tenda FH1202 1.2.0.14(408). Affected by this vulnerability is an unknown functionality of the file /goform/AdvSetWrlsafeset of the component Web Management Interface. The manipulation leads to improper access controls. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/Heimd411/CVE-2025-29927-PoC](https://github.com/Heimd411/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/Heimd411/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/Heimd411/CVE-2025-29927-PoC.svg)


## CVE-2024-38063
 Windows TCP/IP Remote Code Execution Vulnerability

- [https://github.com/hibaNITT/CVE-2024-38063](https://github.com/hibaNITT/CVE-2024-38063) :  ![starts](https://img.shields.io/github/stars/hibaNITT/CVE-2024-38063.svg) ![forks](https://img.shields.io/github/forks/hibaNITT/CVE-2024-38063.svg)
- [https://github.com/Mayank637-pixel/CVE-2024-38063](https://github.com/Mayank637-pixel/CVE-2024-38063) :  ![starts](https://img.shields.io/github/stars/Mayank637-pixel/CVE-2024-38063.svg) ![forks](https://img.shields.io/github/forks/Mayank637-pixel/CVE-2024-38063.svg)


## CVE-2024-29973
The command injection vulnerability in the “setCookie” parameter in Zyxel NAS326 firmware versions before V5.21(AAZF.17)C0 and NAS542 firmware versions before V5.21(ABAG.14)C0 could allow an unauthenticated attacker to execute some operating system (OS) commands by sending a crafted HTTP POST request.

- [https://github.com/aerchy/CVE-2024-29973](https://github.com/aerchy/CVE-2024-29973) :  ![starts](https://img.shields.io/github/stars/aerchy/CVE-2024-29973.svg) ![forks](https://img.shields.io/github/forks/aerchy/CVE-2024-29973.svg)


## CVE-2024-7804
 This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.

- [https://github.com/joaovicdev/CVE-2024-7804](https://github.com/joaovicdev/CVE-2024-7804) :  ![starts](https://img.shields.io/github/stars/joaovicdev/CVE-2024-7804.svg) ![forks](https://img.shields.io/github/forks/joaovicdev/CVE-2024-7804.svg)


## CVE-2024-7593
 Incorrect implementation of an authentication algorithm in Ivanti vTM other than versions 22.2R1 or 22.7R2 allows a remote unauthenticated attacker to bypass authentication of the admin panel.

- [https://github.com/aerchy/CVE-2024-7593](https://github.com/aerchy/CVE-2024-7593) :  ![starts](https://img.shields.io/github/stars/aerchy/CVE-2024-7593.svg) ![forks](https://img.shields.io/github/forks/aerchy/CVE-2024-7593.svg)


## CVE-2024-2876
 The Email Subscribers by Icegram Express – Email Marketing, Newsletters, Automation for WordPress & WooCommerce plugin for WordPress is vulnerable to SQL Injection via the 'run' function of the 'IG_ES_Subscribers_Query' class in all versions up to, and including, 5.7.14 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/aerchy/CVE-2024-2876](https://github.com/aerchy/CVE-2024-2876) :  ![starts](https://img.shields.io/github/stars/aerchy/CVE-2024-2876.svg) ![forks](https://img.shields.io/github/forks/aerchy/CVE-2024-2876.svg)


## CVE-2023-7028
 An issue has been discovered in GitLab CE/EE affecting all versions from 16.1 prior to 16.1.6, 16.2 prior to 16.2.9, 16.3 prior to 16.3.7, 16.4 prior to 16.4.5, 16.5 prior to 16.5.6, 16.6 prior to 16.6.4, and 16.7 prior to 16.7.2 in which user account password reset emails could be delivered to an unverified email address.

- [https://github.com/FearThePLOTO/GitLab-CVE-2023-7028](https://github.com/FearThePLOTO/GitLab-CVE-2023-7028) :  ![starts](https://img.shields.io/github/stars/FearThePLOTO/GitLab-CVE-2023-7028.svg) ![forks](https://img.shields.io/github/forks/FearThePLOTO/GitLab-CVE-2023-7028.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe](https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe) :  ![starts](https://img.shields.io/github/stars/Greetdawn/CVE-2022-0847-DirtyPipe.svg) ![forks](https://img.shields.io/github/forks/Greetdawn/CVE-2022-0847-DirtyPipe.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/asd58584388/CVE-2021-44228](https://github.com/asd58584388/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/asd58584388/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/asd58584388/CVE-2021-44228.svg)


## CVE-2021-1675
 Windows Print Spooler Remote Code Execution Vulnerability

- [https://github.com/HKenzoKimura/CVE-2021-1675](https://github.com/HKenzoKimura/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/HKenzoKimura/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/HKenzoKimura/CVE-2021-1675.svg)


## CVE-2004-1235
 Race condition in the (1) load_elf_library and (2) binfmt_aout function calls for uselib in Linux kernel 2.4 through 2.429-rc2 and 2.6 through 2.6.10 allows local users to execute arbitrary code by manipulating the VMA descriptor.

- [https://github.com/0b0111100/2004](https://github.com/0b0111100/2004) :  ![starts](https://img.shields.io/github/stars/0b0111100/2004.svg) ![forks](https://img.shields.io/github/forks/0b0111100/2004.svg)


## CVE-2004-0077
 The do_mremap function for the mremap system call in Linux 2.2 to 2.2.25, 2.4 to 2.4.24, and 2.6 to 2.6.2, does not properly check the return value from the do_munmap function when the maximum number of VMA descriptors is exceeded, which allows local users to gain root privileges, a different vulnerability than CAN-2003-0985.

- [https://github.com/0b0111100/2004](https://github.com/0b0111100/2004) :  ![starts](https://img.shields.io/github/stars/0b0111100/2004.svg) ![forks](https://img.shields.io/github/forks/0b0111100/2004.svg)

