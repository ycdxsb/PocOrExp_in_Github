# Update 2026-09-21
## CVE-2026-93659
 Concrete CMS Community Store before 2.7.8 renders customer-supplied order fields without HTML escaping in checkout and admin views. Unauthenticated attackers can store script payloads in billing name, email, or phone fields that execute in authenticated manager sessions to create rogue accounts or exfiltrate data.

- [https://github.com/prince325/CVE-2026-93659-writeup](https://github.com/prince325/CVE-2026-93659-writeup) :  ![starts](https://img.shields.io/github/stars/prince325/CVE-2026-93659-writeup.svg) ![forks](https://img.shields.io/github/forks/prince325/CVE-2026-93659-writeup.svg)


## CVE-2026-92229
 The The Forminator Forms – Contact Form, Payment Form & Custom Form Builder plugin for WordPress is vulnerable to arbitrary shortcode execution in all versions up to, and including, 1.57.2. This is due to the software allowing users to execute an action that does not properly validate a value before running do_shortcode. This makes it possible for unauthenticated attackers to execute arbitrary shortcodes.

- [https://github.com/murrez/CVE-2026-92229](https://github.com/murrez/CVE-2026-92229) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-92229.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-92229.svg)


## CVE-2026-89274
 The WP Recipe Maker plugin for WordPress is vulnerable to Arbitrary Shortcode Execution in all versions up to, and including, 10.8.1. The vulnerability exists because `WPRM_Metadata::sanitize_metadata()` recursively calls `do_shortcode()` on every scalar field of the recipe's structured metadata array — including the `reviewBody` field, which is populated verbatim from the `comment_content` of approved `wprm-comment-rating` comments — without sanitizing or stripping shortcode tokens before execution; the subsequent `wp_strip_all_tags()` and `strip_shortcodes()` calls operate only on the output string after execution has already fully occurred, providing no protection against server-side shortcode invocation. This makes it possible for unauthenticated attackers to execute arbitrary registered WordPress shortcodes server-side on every recipe page render, causing shortcode output — such as attachment captions, private post fields, or other data exposed by installed shortcodes — to be embedded in the page's JSON-LD `reviewBody` metadata and disclosed to all visitors who load the recipe page. Successful exploitation requires the attacker's rated comment to pass the site's comment approval threshold, either via auto-approval or moderator action, before the injected shortcode begins executing on page loads.

- [https://github.com/murrez/CVE-2026-89274](https://github.com/murrez/CVE-2026-89274) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-89274.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-89274.svg)


## CVE-2026-85721
 The AsyncHttpClient (AHC) library allows Java applications to easily execute HTTP requests and asynchronously process HTTP responses. From 2.0.0 until 2.16.1 and 3.0.12, automatic response decompression on the HTTP/1.1 path uses ChannelManager.newHttpContentDecompressor() to install Http1ContentDecompressor without a cumulative output-size limit. A hostile or compromised server, or an attacker who can alter a response in transit, can send a small gzip, deflate, or snappy response that expands across chunks until the client exhausts its heap and raises OutOfMemoryError; brotli and zstd are also affected when their optional codecs are present. In versions 3.0.8 through 3.0.10, the HTTP/2 decompressor is also unbounded, so switching protocols does not mitigate the issue on those releases. A limit applied to each decode call is insufficient because the response can be delivered as many small chunks, so the fixed implementation tracks total decompressed bytes for the whole response. This issue is fixed in versions 2.16.1 and 3.0.12.

- [https://github.com/xiaoqiMikko/async-http-client-check](https://github.com/xiaoqiMikko/async-http-client-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/async-http-client-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/async-http-client-check.svg)


## CVE-2026-84434
 The Gravity Forms plugin for WordPress is vulnerable to Arbitrary File Upload in all versions up to, and including, 3.1.0.4 via the upload_file function. This is due to a mismatch between the field validation pipeline and the file persistence pipeline, where hidden file upload fields bypass extension validation and a rejected file's intact upload state is later passed to upload_file() without re-validation. This makes it possible for unauthenticated attackers to upload files that may be executable, which makes remote code execution possible. Exploitation requires the targeted form to contain a File Upload field with its Visibility set to 'Hidden'; the vulnerability is reachable by unauthenticated attackers on any publicly accessible form meeting this condition.

- [https://github.com/murrez/CVE-2026-84434](https://github.com/murrez/CVE-2026-84434) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-84434.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-84434.svg)


## CVE-2026-81648
 The CryptoPayment Gateway WordPress plugin from 1.2.1 to 1.2.2 does not apply an authorization check on one of its AJAX endpoints, allowing unauthenticated users to invoke administrative operations, including deleting arbitrary files on the server, overwriting the payment gateway configuration and recovering stored wallet credentials in cleartext.

- [https://github.com/abraxas/CVE-2026-81648](https://github.com/abraxas/CVE-2026-81648) :  ![starts](https://img.shields.io/github/stars/abraxas/CVE-2026-81648.svg) ![forks](https://img.shields.io/github/forks/abraxas/CVE-2026-81648.svg)


## CVE-2026-81294
 Unauthenticated Privilege Escalation in Authorizer = 3.15.1 versions.

- [https://github.com/abraxas/CVE-2026-81294](https://github.com/abraxas/CVE-2026-81294) :  ![starts](https://img.shields.io/github/stars/abraxas/CVE-2026-81294.svg) ![forks](https://img.shields.io/github/forks/abraxas/CVE-2026-81294.svg)


## CVE-2026-81000
other allocation paths.

- [https://github.com/0xBlackash/CVE-2026-81000](https://github.com/0xBlackash/CVE-2026-81000) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-81000.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-81000.svg)


## CVE-2026-80844
errors to the existing AH6 input and output error paths.

- [https://github.com/0xBlackash/CVE-2026-80844](https://github.com/0xBlackash/CVE-2026-80844) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-80844.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-80844.svg)


## CVE-2026-79752
 CakePHP is a rapid development framework for PHP. Prior to 4.5.12, 4.6.5, 5.1.9, 5.2.14, and 5.3.7, FunctionsBuilder::cast, FunctionsBuilder::extract, FunctionsBuilder::datePart, and FunctionsBuilder::dateAdd in src/Database/FunctionsBuilder.php accept user-controlled dataType, part, or unit values and incorporate them into generated SQL as unescaped structural fragments. An application that passes untrusted input to these parameters can permit SQL injection with confidentiality, integrity, and availability impact according to the database connection's privileges. This issue is fixed in versions 4.5.12, 4.6.5, 5.1.9, 5.2.14, and 5.3.7.

- [https://github.com/abraxas/CVE-2026-79752](https://github.com/abraxas/CVE-2026-79752) :  ![starts](https://img.shields.io/github/stars/abraxas/CVE-2026-79752.svg) ![forks](https://img.shields.io/github/forks/abraxas/CVE-2026-79752.svg)


## CVE-2026-78159
 The The Events Calendar plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 6.17.3 via the parse_array function. This is due to insufficient validation of the widget 'classes' map, allowing a plain-array payload to bypass the is_safe_widget_instance() object check and reach the callable-invocation sink in Element_Classes::parse_array(). This makes it possible for unauthenticated attackers to execute code on the server. Exploitation requires that the targeted site has comments enabled on tribe_events posts and that at least one comment containing a crafted wp:legacy-widget block has been submitted, as the attack chain is triggered when do_blocks() processes the single-event HTML including the comment area.

- [https://github.com/abraxas/CVE-2026-78159](https://github.com/abraxas/CVE-2026-78159) :  ![starts](https://img.shields.io/github/stars/abraxas/CVE-2026-78159.svg) ![forks](https://img.shields.io/github/forks/abraxas/CVE-2026-78159.svg)


## CVE-2026-77635
 CakePHP is a rapid development framework for PHP. Prior to versions 5.1.10, 5.2.15, and 5.3.7 on their respective release lines, FunctionsBuilder::jsonValue() with PostgresDriver is vulnerable to SQL injection when user-controlled data is supplied to the jsonPath parameter. This issue is fixed in versions 5.1.10, 5.2.15, and 5.3.7.

- [https://github.com/abraxas/CVE-2026-77635](https://github.com/abraxas/CVE-2026-77635) :  ![starts](https://img.shields.io/github/stars/abraxas/CVE-2026-77635.svg) ![forks](https://img.shields.io/github/forks/abraxas/CVE-2026-77635.svg)


## CVE-2026-75816
 The Frontend Admin by DynamiApps plugin for WordPress is vulnerable to Authentication Bypass to Account Takeover in all versions up to, and including, 3.29.12. This is due to the pre_update_value function lacking any capability or ownership check, and ActionPost::conditions_logic() short-circuiting its current_user_can('edit_post') authorization gate whenever the post ID is non-numeric — such as the string user_1 — allowing unauthenticated form submissions to be routed to arbitrary user records without restriction. This makes it possible for unauthenticated attackers to overwrite any user's registered email address, including an administrator's, and then leverage WordPress's native password-reset flow to fully take over the targeted account.

- [https://github.com/abraxas/CVE-2026-75816](https://github.com/abraxas/CVE-2026-75816) :  ![starts](https://img.shields.io/github/stars/abraxas/CVE-2026-75816.svg) ![forks](https://img.shields.io/github/forks/abraxas/CVE-2026-75816.svg)


## CVE-2026-75157
 Apache Airflow's asset queued-events DELETE endpoints checked the caller's Dag-axis permission with `READ` instead of `EDIT`. Any authenticated user who could read a Dag could therefore delete that Dag's queued asset events, silently suppressing asset-triggered scheduling for it — a state-changing action gated on a read-only permission. Deployments are affected whenever asset-triggered scheduling is in use and Dag read access is granted more widely than Dag edit access, which is the normal RBAC arrangement; no special configuration is required. Upgrade to apache-airflow 3.3.2 or later.

- [https://github.com/licitrasimone/cve-2026-75157-poc](https://github.com/licitrasimone/cve-2026-75157-poc) :  ![starts](https://img.shields.io/github/stars/licitrasimone/cve-2026-75157-poc.svg) ![forks](https://img.shields.io/github/forks/licitrasimone/cve-2026-75157-poc.svg)


## CVE-2026-74469
to return its existing transport at the limit.

- [https://github.com/0xBlackash/CVE-2026-74469](https://github.com/0xBlackash/CVE-2026-74469) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-74469.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-74469.svg)


## CVE-2026-68121
relocates the head.

- [https://github.com/0xBlackash/CVE-2026-68121](https://github.com/0xBlackash/CVE-2026-68121) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-68121.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-68121.svg)


## CVE-2026-65647
 Improper symlink resolution before file access in Plesk allows remote authenticated users to execute arbitrary code as root.

- [https://github.com/boomerangBS/CVE-2026-65647-PoC](https://github.com/boomerangBS/CVE-2026-65647-PoC) :  ![starts](https://img.shields.io/github/stars/boomerangBS/CVE-2026-65647-PoC.svg) ![forks](https://img.shields.io/github/forks/boomerangBS/CVE-2026-65647-PoC.svg)


## CVE-2026-65616
 Incorrect authorization validation in refresh token signature allows non-admin users to obtain a signed JFrog administrator token.

- [https://github.com/alixiacf/hpim-training-lab](https://github.com/alixiacf/hpim-training-lab) :  ![starts](https://img.shields.io/github/stars/alixiacf/hpim-training-lab.svg) ![forks](https://img.shields.io/github/forks/alixiacf/hpim-training-lab.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/DeAurity/ghost-hoock](https://github.com/DeAurity/ghost-hoock) :  ![starts](https://img.shields.io/github/stars/DeAurity/ghost-hoock.svg) ![forks](https://img.shields.io/github/forks/DeAurity/ghost-hoock.svg)


## CVE-2026-33439
 Open Access Management (OpenAM) is an access management solution. Prior to 16.0.6, OpenIdentityPlatform OpenAM is vulnerable to pre-authentication Remote Code Execution (RCE) via unsafe Java deserialization of the jato.clientSession HTTP parameter. This bypasses the WhitelistObjectInputStream mitigation that was applied to the jato.pageSession parameter after CVE-2021-35464. An unauthenticated attacker can achieve arbitrary command execution on the server by sending a crafted serialized Java object as the jato.clientSession GET/POST parameter to any JATO ViewBean endpoint whose JSP contains jato:form tags (e.g., the Password Reset pages). This vulnerability is fixed in 16.0.6.

- [https://github.com/JonasChen0103/CVE-2026-33439-PoC](https://github.com/JonasChen0103/CVE-2026-33439-PoC) :  ![starts](https://img.shields.io/github/stars/JonasChen0103/CVE-2026-33439-PoC.svg) ![forks](https://img.shields.io/github/forks/JonasChen0103/CVE-2026-33439-PoC.svg)


## CVE-2026-33017
 Langflow is a tool for building and deploying AI-powered agents and workflows. In versions prior to 1.9.0, the POST /api/v1/build_public_tmp/{flow_id}/flow endpoint allows building public flows without requiring authentication. When the optional data parameter is supplied, the endpoint uses attacker-controlled flow data (containing arbitrary Python code in node definitions) instead of the stored flow data from the database. This code is passed to exec() with zero sandboxing, resulting in unauthenticated remote code execution. This is distinct from CVE-2025-3248, which fixed /api/v1/validate/code by adding authentication. The build_public_tmp endpoint is designed to be unauthenticated (for public flows) but incorrectly accepts attacker-supplied flow data containing arbitrary executable code. This issue has been fixed in version 1.9.0.

- [https://github.com/arensballiu/CVE-2026-33017-langflow-rce](https://github.com/arensballiu/CVE-2026-33017-langflow-rce) :  ![starts](https://img.shields.io/github/stars/arensballiu/CVE-2026-33017-langflow-rce.svg) ![forks](https://img.shields.io/github/forks/arensballiu/CVE-2026-33017-langflow-rce.svg)


## CVE-2026-19952
 The Frontend Admin by DynamiApps plugin for WordPress is vulnerable to arbitrary file deletion due to insufficient file path validation in the move_folders function in all versions up to, and including, 3.29.12. This makes it possible for unauthenticated attackers to delete arbitrary files on the server, which can easily lead to remote code execution when the right file is deleted (such as wp-config.php). This is exploitable without authentication when a form is configured with public visibility (who_can_see='all'), as the required nonce is publicly obtainable from the rendered form.

- [https://github.com/abraxas/CVE-2026-19952](https://github.com/abraxas/CVE-2026-19952) :  ![starts](https://img.shields.io/github/stars/abraxas/CVE-2026-19952.svg) ![forks](https://img.shields.io/github/forks/abraxas/CVE-2026-19952.svg)


## CVE-2026-18937
 The Broken Link Checker WordPress plugin before 2.4.12 does not limit which query variables it accepts from user input on sites using plain permalinks, allowing unauthenticated users to overwrite arbitrary PHP global variables, and to execute arbitrary code on the server when a classic (non-block)  is active.

- [https://github.com/abraxas/CVE-2026-18937](https://github.com/abraxas/CVE-2026-18937) :  ![starts](https://img.shields.io/github/stars/abraxas/CVE-2026-18937.svg) ![forks](https://img.shields.io/github/forks/abraxas/CVE-2026-18937.svg)


## CVE-2026-13447
 The Mstore Api plugin for WordPress is vulnerable to Authentication Bypass via JWT Forgery in versions up to, and including, 4.20.0 This is due to missing cryptographic signature verification in the FirebasePhoneAuthHelper::verify_id_token() function, which decodes and validates Firebase ID token claims (alg, kid, aud, iss) but never calls openssl_verify() or any equivalent to validate the JWT signature against Google's actual public key certificates. This makes it possible for unauthenticated attackers to forge a Firebase Phone Auth JWT signed with a self-generated RSA key pair and impersonate any phone number, resulting in unauthorized access to existing WordPress accounts or creation of new arbitrary accounts.

- [https://github.com/abraxas/CVE-2026-13447](https://github.com/abraxas/CVE-2026-13447) :  ![starts](https://img.shields.io/github/stars/abraxas/CVE-2026-13447.svg) ![forks](https://img.shields.io/github/forks/abraxas/CVE-2026-13447.svg)


## CVE-2026-9403
 A vulnerability was determined in Edimax BR-6675nD 1.12. The impacted element is the function formWlSiteSurvey of the file /goform/formWlSiteSurvey of the component POST Request Handler. This manipulation of the argument selSSID causes buffer overflow. The attack may be initiated remotely. The exploit has been publicly disclosed and may be utilized. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/djzzlim/CVE-2026-94036](https://github.com/djzzlim/CVE-2026-94036) :  ![starts](https://img.shields.io/github/stars/djzzlim/CVE-2026-94036.svg) ![forks](https://img.shields.io/github/forks/djzzlim/CVE-2026-94036.svg)


## CVE-2026-6295
 The WP Optimizer plugin for WordPress is vulnerable to SQL Injection via the 's' parameter in all versions up to and including 2.5.0. This is due to an unsafe subquery-detection branch in the Query::parse_key_compare_field() method that, when the user-supplied value matches the regex ^[(\s]*SELECT\s+, wraps the value in parentheses and embeds it directly into the SQL string without any escaping or quoting. While the normal LIKE code path correctly uses esc_sql($wpdb-esc_like(...)) and wraps the value in single quotes, this branch completely bypasses those protections. Because the attack payload (SELECT ...) contains no single quotes, WordPress's wp_magic_quotes() provides no protection. This makes it possible for authenticated attackers with administrator-level access to inject arbitrary SQL subqueries — including time-based blind payloads — that can be used to extract sensitive information from the database.

- [https://github.com/0Linear/CVE-2026-62958](https://github.com/0Linear/CVE-2026-62958) :  ![starts](https://img.shields.io/github/stars/0Linear/CVE-2026-62958.svg) ![forks](https://img.shields.io/github/forks/0Linear/CVE-2026-62958.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/anksgls-sj/-Help-vivo-Y200i-5.10.218-GKI-CVE-2026-43499-stack-reclaim-reaches-0x300-need-0x318](https://github.com/anksgls-sj/-Help-vivo-Y200i-5.10.218-GKI-CVE-2026-43499-stack-reclaim-reaches-0x300-need-0x318) :  ![starts](https://img.shields.io/github/stars/anksgls-sj/-Help-vivo-Y200i-5.10.218-GKI-CVE-2026-43499-stack-reclaim-reaches-0x300-need-0x318.svg) ![forks](https://img.shields.io/github/forks/anksgls-sj/-Help-vivo-Y200i-5.10.218-GKI-CVE-2026-43499-stack-reclaim-reaches-0x300-need-0x318.svg)


## CVE-2026-3143
 The Total Upkeep – WordPress Backup Plugin plus Restore & Migrate by BoldGrid plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'wp_ajax_cli_cancel' function in all versions up to, and including, 1.17.1. This makes it possible for unauthenticated attackers to cancel a pending rollback, potentially preventing a WordPress installation from automatically reverting a failed update.

- [https://github.com/AvPrince26/copy-fail-CVE-2026-31431-Python-Golfing](https://github.com/AvPrince26/copy-fail-CVE-2026-31431-Python-Golfing) :  ![starts](https://img.shields.io/github/stars/AvPrince26/copy-fail-CVE-2026-31431-Python-Golfing.svg) ![forks](https://img.shields.io/github/forks/AvPrince26/copy-fail-CVE-2026-31431-Python-Golfing.svg)


## CVE-2025-68613
 n8n is an open source workflow automation platform. Versions starting with 0.211.0 and prior to 1.120.4, 1.121.1, and 1.122.0 contain a critical Remote Code Execution (RCE) vulnerability in their workflow expression evaluation system. Under certain conditions, expressions supplied by authenticated users during workflow configuration may be evaluated in an execution context that is not sufficiently isolated from the underlying runtime. An authenticated attacker could abuse this behavior to execute arbitrary code with the privileges of the n8n process. Successful exploitation may lead to full compromise of the affected instance, including unauthorized access to sensitive data, modification of workflows, and execution of system-level operations. This issue has been fixed in versions 1.120.4, 1.121.1, and 1.122.0. Users are strongly advised to upgrade to a patched version, which introduces additional safeguards to restrict expression evaluation. If upgrading is not immediately possible, administrators should consider the following temporary mitigations: Limit workflow creation and editing permissions to fully trusted users only; and/or deploy n8n in a hardened environment with restricted operating system privileges and network access to reduce the impact of potential exploitation. These workarounds do not fully eliminate the risk and should only be used as short-term measures.

- [https://github.com/releaseown/Analysis-And-POC-N8N-CVE-2025-68613](https://github.com/releaseown/Analysis-And-POC-N8N-CVE-2025-68613) :  ![starts](https://img.shields.io/github/stars/releaseown/Analysis-And-POC-N8N-CVE-2025-68613.svg) ![forks](https://img.shields.io/github/forks/releaseown/Analysis-And-POC-N8N-CVE-2025-68613.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)


## CVE-2025-59528
 Flowise is a drag & drop user interface to build a customized large language model flow. In version 3.0.5, Flowise is vulnerable to remote code execution. The CustomMCP node allows users to input configuration settings for connecting to an external MCP server. This node parses the user-provided mcpServerConfig string to build the MCP server configuration. However, during this process, it executes JavaScript code without any security validation. Specifically, inside the convertToValidJSONString function, user input is directly passed to the Function() constructor, which evaluates and executes the input as JavaScript code. Since this runs with full Node.js runtime privileges, it can access dangerous modules such as child_process and fs. This issue has been patched in version 3.0.6.

- [https://github.com/arensballiu/Flowise-RCE-CVE-2025-59528](https://github.com/arensballiu/Flowise-RCE-CVE-2025-59528) :  ![starts](https://img.shields.io/github/stars/arensballiu/Flowise-RCE-CVE-2025-59528.svg) ![forks](https://img.shields.io/github/forks/arensballiu/Flowise-RCE-CVE-2025-59528.svg)


## CVE-2025-58434
 Flowise is a drag & drop user interface to build a customized large language model flow. In version 3.0.5 and earlier, the `forgot-password` endpoint in Flowise returns sensitive information including a valid password reset `tempToken` without authentication or verification. This enables any attacker to generate a reset token for arbitrary users and directly reset their password, leading to a complete account takeover (ATO). This vulnerability applies to both the cloud service (`cloud.flowiseai.com`) and self-hosted/local Flowise deployments that expose the same API. Commit 9e178d68873eb876073846433a596590d3d9c863 in version 3.0.6 secures password reset endpoints. Several recommended remediation steps are available. Do not return reset tokens or sensitive account details in API responses. Tokens must only be delivered securely via the registered email channel. Ensure `forgot-password` responds with a generic success message regardless of input, to avoid user enumeration. Require strong validation of the `tempToken` (e.g., single-use, short expiry, tied to request origin, validated against email delivery). Apply the same fixes to both cloud and self-hosted/local deployments. Log and monitor password reset requests for suspicious activity. Consider multi-factor verification for sensitive accounts.

- [https://github.com/arensballiu/Flowise-CVE-2025-58434-PasswordReset](https://github.com/arensballiu/Flowise-CVE-2025-58434-PasswordReset) :  ![starts](https://img.shields.io/github/stars/arensballiu/Flowise-CVE-2025-58434-PasswordReset.svg) ![forks](https://img.shields.io/github/forks/arensballiu/Flowise-CVE-2025-58434-PasswordReset.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg)


## CVE-2024-57521
 SQL Injection vulnerability in RuoYi v.4.7.9 and before allows a remote attacker to execute arbitrary code via the createTable function in SqlUtil.java.

- [https://github.com/xs2024770/CVE-2024-57521-RuoYi-SQLi](https://github.com/xs2024770/CVE-2024-57521-RuoYi-SQLi) :  ![starts](https://img.shields.io/github/stars/xs2024770/CVE-2024-57521-RuoYi-SQLi.svg) ![forks](https://img.shields.io/github/forks/xs2024770/CVE-2024-57521-RuoYi-SQLi.svg)


## CVE-2024-37054
 Deserialization of untrusted data can occur in versions of the MLflow platform running version 0.9.0 or newer, enabling a maliciously uploaded PyFunc model to run arbitrary code on an end user’s system when interacted with.

- [https://github.com/ClearLotus-git/CVE-2024-37054-PoC](https://github.com/ClearLotus-git/CVE-2024-37054-PoC) :  ![starts](https://img.shields.io/github/stars/ClearLotus-git/CVE-2024-37054-PoC.svg) ![forks](https://img.shields.io/github/forks/ClearLotus-git/CVE-2024-37054-PoC.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/pmihsan/Dirty-Pipe-CVE-2022-0847](https://github.com/pmihsan/Dirty-Pipe-CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/pmihsan/Dirty-Pipe-CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/pmihsan/Dirty-Pipe-CVE-2022-0847.svg)


## CVE-2021-44790
 A carefully crafted request body can cause a buffer overflow in the mod_lua multipart parser (r:parsebody() called from Lua scripts). The Apache httpd team is not aware of an exploit for the vulnerabilty though it might be possible to craft one. This issue affects Apache HTTP Server 2.4.51 and earlier.

- [https://github.com/MohammadAliMehri/cve-2021-44790-lab](https://github.com/MohammadAliMehri/cve-2021-44790-lab) :  ![starts](https://img.shields.io/github/stars/MohammadAliMehri/cve-2021-44790-lab.svg) ![forks](https://img.shields.io/github/forks/MohammadAliMehri/cve-2021-44790-lab.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `grafana_host_url/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/elsanose01/CVE-2021-43798-Grafana-path-traversal-tester](https://github.com/elsanose01/CVE-2021-43798-Grafana-path-traversal-tester) :  ![starts](https://img.shields.io/github/stars/elsanose01/CVE-2021-43798-Grafana-path-traversal-tester.svg) ![forks](https://img.shields.io/github/forks/elsanose01/CVE-2021-43798-Grafana-path-traversal-tester.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mightysai1997/cve-2021-41773](https://github.com/mightysai1997/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/mightysai1997/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/cve-2021-41773.svg)
- [https://github.com/r0otk3r/CVE-2021-41773](https://github.com/r0otk3r/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/r0otk3r/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/r0otk3r/CVE-2021-41773.svg)
- [https://github.com/Mahfujurjust/CVE-2021-41773](https://github.com/Mahfujurjust/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Mahfujurjust/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Mahfujurjust/CVE-2021-41773.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/Phineas09/CVE-2021-44228](https://github.com/Phineas09/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/Phineas09/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/Phineas09/CVE-2021-44228.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/0xrogg/CVE-2021-41773](https://github.com/0xrogg/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/0xrogg/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/0xrogg/CVE-2021-41773.svg)
- [https://github.com/LayarKacaSiber/CVE-2021-41773](https://github.com/LayarKacaSiber/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/LayarKacaSiber/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/LayarKacaSiber/CVE-2021-41773.svg)
- [https://github.com/redspy-sec/CVE-2021-41773](https://github.com/redspy-sec/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/redspy-sec/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/redspy-sec/CVE-2021-41773.svg)
- [https://github.com/ch4os443/CVE-2021-41773](https://github.com/ch4os443/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/ch4os443/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/ch4os443/CVE-2021-41773.svg)


## CVE-2020-14343
 A vulnerability was discovered in the PyYAML library in versions before 5.4, where it is susceptible to arbitrary code execution when it processes untrusted YAML files through the full_load method or with the FullLoader loader. Applications that use the library to process untrusted input may be vulnerable to this flaw. This flaw allows an attacker to execute arbitrary code on the system by abusing the python/object/new constructor. This flaw is due to an incomplete fix for CVE-2020-1747.

- [https://github.com/saina15/cve-2020-14343-lab](https://github.com/saina15/cve-2020-14343-lab) :  ![starts](https://img.shields.io/github/stars/saina15/cve-2020-14343-lab.svg) ![forks](https://img.shields.io/github/forks/saina15/cve-2020-14343-lab.svg)

