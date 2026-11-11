# Update 2026-11-11
## CVE-2026-124576
 A security flaw has been discovered in BeikeShop up to 2.0.0.31. Impacted is the function OrderRepo::getOrderByNumber of the file beike/Repositories/OrderRepo.php of the component Guest Order Lookup. Performing a manipulation of the argument order_number results in enforcement of behavioral workflow. The attack can be initiated remotely. Upgrading to version 2.0.0.32 is recommended to address this issue. The patch is named 6cf25f8c15d27d1ff14a848faf645c94d20ba5f1. It is recommended to upgrade the affected component.

- [https://github.com/capivara-research/CVE-2026-124576](https://github.com/capivara-research/CVE-2026-124576) :  ![starts](https://img.shields.io/github/stars/capivara-research/CVE-2026-124576.svg) ![forks](https://img.shields.io/github/forks/capivara-research/CVE-2026-124576.svg)


## CVE-2026-124552
 Webmin through 2.670 contains a stored cross-site scripting vulnerability in the Shorewall and Shorewall6 modules' list.cgi, which renders table fields and COMMENT lines unescaped. Authenticated users with table edit permission can store JavaScript via savecmt.cgi or table entries that executes when other users, including root, view the list page.

- [https://github.com/googlesky/CVE-2026-124552](https://github.com/googlesky/CVE-2026-124552) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-124552.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-124552.svg)


## CVE-2026-124450
 OpenEMR before 8.3.0 contains a broken access control and path traversal vulnerability in the fax/sms module disposeDocument action via an unvalidated file_path parameter. Authenticated low-privilege users can read sqlconf.php to recover database credentials and write arbitrary files as the web user, enabling remote code execution.

- [https://github.com/Nxploited/CVE-2026-124450](https://github.com/Nxploited/CVE-2026-124450) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2026-124450.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2026-124450.svg)


## CVE-2026-123753
 Server-Side Request Forgery (SSRF) vulnerability in Apache Axis2/Java. An unauthenticated caller could supply a non-anonymous WS-Addressing wsa:ReplyTo or wsa:FaultTo address, and Axis2 would open a connection to that address to deliver the response or fault, allowing requests to internal hosts and delivery of response content to a host of the caller's choosing. From 2.0.2, decoupled responses are refused unless allowNonAnonymousResponseEndpoints is enabled, and enabled endpoints are restricted by scheme and screened at both the header-parsing and transport-selection layers. This issue affects Apache Axis2/Java: through 2.0.1. Users are recommended to upgrade to version 2.0.2, which fixes the issue.

- [https://github.com/googlesky/CVE-2026-123753](https://github.com/googlesky/CVE-2026-123753) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-123753.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-123753.svg)


## CVE-2026-123491
 Craft CMS 4.0.0 before 4.18.9 and 5.0.0 before 5.11.2 contains an SQL injection vulnerability in GraphQL eager-loading: arguments on eager-loadable nodes absent from the public schema are copied into EagerLoadPlan criteria without cleansing. Unauthenticated attackers can supply a parenthesized select argument to inject SQL expressions and read arbitrary database content, including password hashes and session tokens.

- [https://github.com/foxcornlab/craft-cms-scanner](https://github.com/foxcornlab/craft-cms-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/craft-cms-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/craft-cms-scanner.svg)


## CVE-2026-123490
 Craft CMS from 5.8.17 before 5.11.2 contains a privilege escalation vulnerability because getOwners() applies caller criteria without cleansing the query configuration. Authenticated control panel users can invoke attacker-selected static PHP callables via crafted criteria to promote every account to administrator.

- [https://github.com/foxcornlab/craft-cms-scanner](https://github.com/foxcornlab/craft-cms-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/craft-cms-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/craft-cms-scanner.svg)


## CVE-2026-123489
 Craft CMS 4.0.0 before 4.18.9 and 5.0.0 before 5.11.2 contains a blind SQL injection vulnerability because the sandbox-exposed getNext() and getPrev() methods pass arbitrary criteria arrays to Craft::configure() without removing SQL-bearing properties such as orderBy and where. Authenticated control panel users can supply a crafted elementIds value, rendered as a sandboxed template, to obtain a conditional SQL oracle under the Craft database account.

- [https://github.com/foxcornlab/craft-cms-scanner](https://github.com/foxcornlab/craft-cms-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/craft-cms-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/craft-cms-scanner.svg)


## CVE-2026-123488
 Craft CMS 4.0.0 before 4.18.9 and 5.0.0 before 5.11.2 contains an unauthenticated SQL injection vulnerability in the element search endpoint because the attribute parameter is concatenated into the query unsanitized and emulated PDO prepares allow stacked statements. Remote attackers can read and write the database, setting the admin flag or overwriting password hashes in the users table to gain administrator access.

- [https://github.com/ashrafzaryouh/CVE-2026-123488](https://github.com/ashrafzaryouh/CVE-2026-123488) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-123488.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-123488.svg)
- [https://github.com/foxcornlab/craft-cms-scanner](https://github.com/foxcornlab/craft-cms-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/craft-cms-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/craft-cms-scanner.svg)


## CVE-2026-123158
 sshd in OpenSSH before 10.6p2 on Linux, when musl libc is used without PAM, lacks a workaround for a password authentication bypass (related to misinterpretation of whether a string is intended to be a password hash). For some configurations of accounts, any password between 256 and 1024 characters succeeds. An example of a platform using musl libc without PAM is Alpine Linux.

- [https://github.com/D1se0/CVE-2026-123158](https://github.com/D1se0/CVE-2026-123158) :  ![starts](https://img.shields.io/github/stars/D1se0/CVE-2026-123158.svg) ![forks](https://img.shields.io/github/forks/D1se0/CVE-2026-123158.svg)
- [https://github.com/aciddust/CVE-2026-123158-LAB](https://github.com/aciddust/CVE-2026-123158-LAB) :  ![starts](https://img.shields.io/github/stars/aciddust/CVE-2026-123158-LAB.svg) ![forks](https://img.shields.io/github/forks/aciddust/CVE-2026-123158-LAB.svg)
- [https://github.com/Iperez95-ot/sshole-lab](https://github.com/Iperez95-ot/sshole-lab) :  ![starts](https://img.shields.io/github/stars/Iperez95-ot/sshole-lab.svg) ![forks](https://img.shields.io/github/forks/Iperez95-ot/sshole-lab.svg)


## CVE-2026-122056
 A flaw was found in OpenSCAP. A heap-based buffer overflow can occur when processing a specially crafted Extensible Configuration Checklist Description Format (XCCDF) document using the sds-compose option. An attacker could exploit this vulnerability to corrupt memory, resulting in an application crash and a Denial of Service (DoS).

- [https://github.com/D7EAD/CVE-2026-122056](https://github.com/D7EAD/CVE-2026-122056) :  ![starts](https://img.shields.io/github/stars/D7EAD/CVE-2026-122056.svg) ![forks](https://img.shields.io/github/forks/D7EAD/CVE-2026-122056.svg)


## CVE-2026-119200
 Nuxt is an open-source web development framework for Vue.js. From 4.6.0 until 4.6.3, Nuxt resolves literal or percent-encoded dot segments before rendering a page while Nitro routing, server/middleware checks, and server route rules evaluate the unresolved path. A request such as /%2e/admin can therefore render app/pages/admin.vue and its server-rendered data while checks keyed to /admin, redirects, or per-route security headers do not apply. API handlers, appMiddleware, Nuxt 3, and Nuxt 4.0.0 through 4.5.x are not affected, and exploitation requires a client that sends dot segments without browser normalization. This issue is fixed in version 4.6.3.

- [https://github.com/federiconbaez/cortex9-nuxt-dot-segment-middleware-bypass-model](https://github.com/federiconbaez/cortex9-nuxt-dot-segment-middleware-bypass-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-nuxt-dot-segment-middleware-bypass-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-nuxt-dot-segment-middleware-bypass-model.svg)


## CVE-2026-118669
 OAuthLib is an implementation of the OAuth request-signing logic for Python 3.6+. Prior to 4.0.0, the client_credentials and Resource Owner Password Credentials token grant handlers can authenticate request.client as one confidential client while retaining an attacker-supplied request.client_id for validate_grant_type and validate_scopes. A lower-privilege authenticated client can therefore cause grant and scope authorization to use another client's identity when an application validator relies on the documented client_id argument, potentially issuing tokens with unauthorized grants or scopes. Validators that authorize exclusively from request.client may not be affected. This issue is fixed in version 4.0.0.

- [https://github.com/federiconbaez/cortex9-oauthlib-token-grant-client-id-confusion-model](https://github.com/federiconbaez/cortex9-oauthlib-token-grant-client-id-confusion-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-oauthlib-token-grant-client-id-confusion-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-oauthlib-token-grant-client-id-confusion-model.svg)


## CVE-2026-118650
 Echo is a Go web framework. Prior to 4.16.0 and 5.4.0, a globally mounted middleware.Static instance can interpret an encoded request path differently from Echo's router because the router matches the still-encoded path while the static handler uses the decoded URL.Path. The advisory demonstrates an encoded slash resolving to a file under the static root through the global static middleware, but the source is internally inconsistent about whether a route or group guard protects the corresponding literal path in that global-mount configuration. This issue is fixed in 4.16.0 and 5.4.0.

- [https://github.com/federiconbaez/cortex9-echo-static-encoded-segment-bypass-model](https://github.com/federiconbaez/cortex9-echo-static-encoded-segment-bypass-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-echo-static-encoded-segment-bypass-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-echo-static-encoded-segment-bypass-model.svg)


## CVE-2026-118378
 Tabularis before 0.28.0 contains an SQL injection vulnerability in its SQLite driver that allows MCP clients to execute stacked statements by supplying a crafted table_name to the describe_table tool. Attackers, including AI agents steered by untrusted content, can close the quoted PRAGMA argument and append statements to read, modify, or drop SQLite data, bypassing read-only mode and write approval.

- [https://github.com/squeeze440/CVE-2026-118378-tabularis-PoC](https://github.com/squeeze440/CVE-2026-118378-tabularis-PoC) :  ![starts](https://img.shields.io/github/stars/squeeze440/CVE-2026-118378-tabularis-PoC.svg) ![forks](https://img.shields.io/github/forks/squeeze440/CVE-2026-118378-tabularis-PoC.svg)


## CVE-2026-116580
 Seroval facilitates JavaScript value stringification, including complex structures beyond JSON.stringify capabilities. Prior to 1.6.8, fromJSON rebuilds an AsyncIteratorFactoryInstance by calling source.on(listener) without requiring source to be a genuine internal stream. With untrusted Seroval input and an application plugin that returns a callable value or an object exposing an on method, a crafted node can reuse an identifier so the deserializer invokes the plugin-produced value. This is an incomplete-fix variant of CVE-2026-59940. The resulting confidentiality, integrity, or availability impact depends on the behavior exposed by the application plugin. This issue is fixed in version 1.6.8.

- [https://github.com/federiconbaez/cortex9-seroval-node-id-type-confusion-model](https://github.com/federiconbaez/cortex9-seroval-node-id-type-confusion-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-seroval-node-id-type-confusion-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-seroval-node-id-type-confusion-model.svg)


## CVE-2026-116567
 FreeSWITCH is a Software Defined Telecom Stack enabling the digital transformation from proprietary telecom switches to a software implementation that runs on any commodity hardware. Prior to 1.11.2, rtmp_handle_control() rendered an RTMP user-control message into a 200-byte stack buffer using an unbounded sprintf loop controlled by the wire message length. A body of roughly 70 bytes or more overflowed the stack before any RTMP login, because the handshake authenticates neither side. The flaw affects deployments that build and load mod_rtmp, which is disabled in the stock build and configuration but commonly exposes a listener on TCP port 1935 when enabled. One unauthenticated message can crash FreeSWITCH and end every active call; the constrained ASCII hex output has not yielded control-flow hijacking. This issue is fixed in version 1.11.2.

- [https://github.com/carterlasalle/CVE-2026-116567](https://github.com/carterlasalle/CVE-2026-116567) :  ![starts](https://img.shields.io/github/stars/carterlasalle/CVE-2026-116567.svg) ![forks](https://img.shields.io/github/forks/carterlasalle/CVE-2026-116567.svg)


## CVE-2026-115878
 Stanza is a Stanford NLP Python library for tokenization, sentence segmentation, NER, and parsing of many human languages. From 1.14.0 until 1.15.0, loading an attacker-supplied lemmatizer checkpoint can execute arbitrary code because stanza/models/lemma/trainer.py stores pos_dict as gzip-compressed pickle bytes and Trainer.load passes the decompressed stream to unrestricted pickle.loads. The outer torch.load call uses weights_only=True, but the nested bytes are treated as a primitive and are not inspected by that allowlist. The path is reachable during pipeline construction through a caller-influenced lemma_model_path, before inference begins. This issue is fixed in version 1.15.0.

- [https://github.com/federiconbaez/cortex9-stanza-lemma-pickle-to-json-model](https://github.com/federiconbaez/cortex9-stanza-lemma-pickle-to-json-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-stanza-lemma-pickle-to-json-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-stanza-lemma-pickle-to-json-model.svg)


## CVE-2026-114140
 The nbconvert tool, jupyter nbconvert, converts Jupyter notebooks to various other formats via Jinja templates. From 5.4.0 until 7.17.2, ExtractOutputPreprocessor in nbconvert/preprocessors/extractoutput.py joins the attacker-controlled cell output metadata filename to output_files_dir without limiting the result to the intended directory. When a victim converts a malicious notebook with the markdown, LaTeX, reStructuredText, or AsciiDoc exporter, path traversal in the output filename can write attacker-controlled output data to arbitrary locations accessible to the victim. Running the notebook cell again replaces the malicious output metadata, but merely converting the supplied notebook does not. This issue is fixed in version 7.17.2.

- [https://github.com/federiconbaez/cortex9-nbconvert-output-filename-traversal-model](https://github.com/federiconbaez/cortex9-nbconvert-output-filename-traversal-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-nbconvert-output-filename-traversal-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-nbconvert-output-filename-traversal-model.svg)


## CVE-2026-112936
 filelock is a platform-independent file lock for Python. From 3.20.4 until 4.0.9, ReadWriteLock and AsyncReadWriteLock versions from 3.20.4 resolve the lock path and pass it to SQLite without rejecting a final symbolic link, allowing another local user who can create names in the lock directory to redirect database creation and locking or split mutual exclusion between targets. This issue is fixed in version 4.0.9.

- [https://github.com/federiconbaez/cortex9-filelock-sqlite-symlink-follow-model](https://github.com/federiconbaez/cortex9-filelock-sqlite-symlink-follow-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-filelock-sqlite-symlink-follow-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-filelock-sqlite-symlink-follow-model.svg)


## CVE-2026-112900
 Pillow is a Python imaging library. From 2.6.0 until 13.0.0, Pillow is vulnerable to argument injection when invoking Ghostscript for EPS input. EpsImagePlugin.Ghostscript passes a caller-controlled input filename after -f without converting it to a safe absolute path, so a name beginning with a hyphen can be interpreted as a Ghostscript option. An attacker who controls the filename can inject Ghostscript arguments. Arbitrary command execution specifically requires a leading @ argument-file filename and control of the referenced text file containing additional Ghostscript arguments; the reported chain reproduces with the default -dSAFER invocation. This issue is fixed in version 13.0.0.

- [https://github.com/federiconbaez/cortex9-pillow-ghostscript-argv-injection-model](https://github.com/federiconbaez/cortex9-pillow-ghostscript-argv-injection-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-pillow-ghostscript-argv-injection-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-pillow-ghostscript-argv-injection-model.svg)


## CVE-2026-110634
 git-diff before 2.0.7 contains an OS command injection vulnerability that allows attackers to execute shell commands by supplying crafted strings to the gitDiff API. Attackers who control a diffed document string can embed $(cmd) or backtick substitutions that shelljs.exec evaluates, running commands with Node.js process privileges.

- [https://github.com/federiconbaez/cortex9-git-diff-shell-hash-object-injection-model](https://github.com/federiconbaez/cortex9-git-diff-shell-hash-object-injection-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-git-diff-shell-hash-object-injection-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-git-diff-shell-hash-object-injection-model.svg)


## CVE-2026-109618
 PHP uses longjmp() for out-of-memory (OOM) errors to exit the current context and abort handling of the request. Some contexts may not properly account for this scenario and leave request memory in an uninitialized state before performing an allocation. The subsequent request cleanup procedure may read or branch on this memory. Multiple OOM strategies can consistently trigger this condition and lead to remote code execution (RCE).

- [https://github.com/revonnet/php-fix](https://github.com/revonnet/php-fix) :  ![starts](https://img.shields.io/github/stars/revonnet/php-fix.svg) ![forks](https://img.shields.io/github/forks/revonnet/php-fix.svg)


## CVE-2026-109372
 ZITADEL 4.x before 4.19.2 and 3.x through 3.4.15 contains an authentication bypass in the SAML identity-provider intent callback, which verifies the assertion signature using the provider named in the request URL but resolves the user from the login intent without checking they match. Attackers with organization-administrator permission can register a SAML provider with their own signing key to obtain authenticated sessions as any user linked to another SAML provider on the instance, including in other organizations.

- [https://github.com/federiconbaez/cortex9-zitadel-saml-idp-intent-mismatch-model](https://github.com/federiconbaez/cortex9-zitadel-saml-idp-intent-mismatch-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-zitadel-saml-idp-intent-mismatch-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-zitadel-saml-idp-intent-mismatch-model.svg)


## CVE-2026-108360
 PhpSpreadsheet is a pure PHP library for reading and writing spreadsheet files. Prior to 1.30.7, 2.1.19, 2.4.8, 3.10.8, and 5.10.0, Worksheet\Drawing::setPath validates only the initial external-image URL with setIsWhitelisted when setAllowExternalImages is enabled. The HTTP stream context permits PHP to follow a redirect without applying the callback to the redirected URL, so a permitted image host can redirect the server to an internal address and cause a blind GET request. The response body is not returned to the attacker because the reader validates the downloaded content as an image and removes the temporary file, but internal GET-driven endpoints, network reachability, and cloud metadata endpoints may be reached. This issue is fixed in versions 1.30.7, 2.1.19, 2.4.8, 3.10.8, and 5.10.0.

- [https://github.com/federiconbaez/cortex9-phpspreadsheet-redirect-whitelist-ssrf-model](https://github.com/federiconbaez/cortex9-phpspreadsheet-redirect-whitelist-ssrf-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-phpspreadsheet-redirect-whitelist-ssrf-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-phpspreadsheet-redirect-whitelist-ssrf-model.svg)


## CVE-2026-107720
 fast-jwt provides fast JSON Web Token (JWT) implementation. Prior to 6.3.1, fast-jwt createVerifier accepts an unsigned JWT when key is an empty string or null and algorithms is a non-empty allowlist. Falsy synchronous keys bypass prepareKeyOrSecret, allowedAlgorithms remains active, hasKey is false, and the empty signature avoids the verifySignature gate. An attacker can therefore submit a token containing arbitrary claims without possessing a signing key, resulting in authentication or authorization bypass. Claim validators still run, and non-empty keys, an empty key without algorithms, and the async key resolver path do not have this behavior. This issue is fixed in version 6.3.1.

- [https://github.com/federiconbaez/cortex9-fastjwt-empty-key-unsigned-accept-model](https://github.com/federiconbaez/cortex9-fastjwt-empty-key-unsigned-accept-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-fastjwt-empty-key-unsigned-accept-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-fastjwt-empty-key-unsigned-accept-model.svg)


## CVE-2026-106451
 yawkat LZ4 Java provides LZ4 compression for Java. From 1.7.0 until 1.11.4, net.jpountz.util.Native.load() uses File.createTempFile to create an exclusive temporary .lck file but derives the native-library path by removing the suffix, then FileOutputStream opens that predictable path without exclusive creation, allowing another local user with access to the same shared temporary directory to create or replace the library file before System.load() uses it. Successful exploitation depends on shared-directory permissions, host protections, and winning the race, and can execute native code as the victim; hardened systems may instead cause library loading to fail and fall back to Java implementations. Configurations using a system library, a private java.io.tmpdir, or Java-only implementations are not affected. This issue is fixed in version 1.11.4.

- [https://github.com/federiconbaez/cortex9-lz4java-tmp-native-lib-predictable-name-model](https://github.com/federiconbaez/cortex9-lz4java-tmp-native-lib-predictable-name-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-lz4java-tmp-native-lib-predictable-name-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-lz4java-tmp-native-lib-predictable-name-model.svg)


## CVE-2026-104851
 fsspec is a specification and Python implementation framework for filesystem interfaces. From 0.9.0 until 2026.6.0, fsspec.implementations.reference.ReferenceFileSystem evaluates fields from Kerchunk reference JSON documents through unrestricted jinja2.Template(...).render(...) calls in _process_references1._render_jinja, _process_templates, and _process_gen in fsspec/implementations/reference.py. A document supplied inline or fetched from an attacker-controlled URL can provide template expressions that execute Python code when the reference filesystem is opened, including through consumers such as xarray, before referenced data is read. The _process_gen path is reached whenever a document includes a gen array, while the other paths depend on template-related options and values. This issue is fixed in version 2026.6.0.

- [https://github.com/federiconbaez/cortex9-fsspec-reference-jinja-ssti-model](https://github.com/federiconbaez/cortex9-fsspec-reference-jinja-ssti-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-fsspec-reference-jinja-ssti-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-fsspec-reference-jinja-ssti-model.svg)


## CVE-2026-102422
 shell-quote's `quote()` function emits a `{ comment }` token as `#` followed by its text, which comments out the rest of the shell line, including the opening quote of any later string token. A line terminator (\n, \r, U+2028, U+2029) in that later string therefore ends the comment, and the rest of the string is parsed as shell input: `quote(['echo', 'ok', { comment: 'x' }, 'a\nid;#'])` runs `id` in sh, bash, dash, ksh and zsh. `parse()` emits a comment token for a `#` in the middle of a word (for example `http://example.com/#frag`), so callers that combine `parse()` output with another untrusted string, such as `quote(parse(untrustedCommand).concat(untrustedArg))`, are affected. The fix for CVE-2026-9277 rejected line terminators in the comment's own text, but not in the tokens after it. Fixed in 1.11.0: `quote()` throws a `TypeError` when a string after a `{ comment }` token contains a line terminator.

- [https://github.com/federiconbaez/cortex9-shell-quote-comment-line-terminator-model](https://github.com/federiconbaez/cortex9-shell-quote-comment-line-terminator-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-shell-quote-comment-line-terminator-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-shell-quote-comment-line-terminator-model.svg)


## CVE-2026-102268
 PyJWT is a Python implementation of JSON Web Token standards. Prior to 2.14.0, is_pem_format in jwt/utils.py is affected because is_pem_format does not recognize every PEM representation accepted by the cryptography loader. This occurs when an application mixes HMAC and asymmetric algorithms and supplies a mutated public-key PEM as raw key bytes. As a result, HMACAlgorithm.prepare_key treats the unrecognized asymmetric public key as an HMAC secret. Consequently, an attacker who knows the public key can forge authenticated HMAC tokens. This issue is fixed in version 2.14.0.

- [https://github.com/federiconbaez/cortex9-pyjwt-pem-detection-alg-confusion-model](https://github.com/federiconbaez/cortex9-pyjwt-pem-detection-alg-confusion-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-pyjwt-pem-detection-alg-confusion-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-pyjwt-pem-detection-alg-confusion-model.svg)


## CVE-2026-98432
will be addressed in a separate patch.

- [https://github.com/rootagi/CVE-2026-98432](https://github.com/rootagi/CVE-2026-98432) :  ![starts](https://img.shields.io/github/stars/rootagi/CVE-2026-98432.svg) ![forks](https://img.shields.io/github/forks/rootagi/CVE-2026-98432.svg)
- [https://github.com/nnssh/CVE-2026-98432_poc](https://github.com/nnssh/CVE-2026-98432_poc) :  ![starts](https://img.shields.io/github/stars/nnssh/CVE-2026-98432_poc.svg) ![forks](https://img.shields.io/github/forks/nnssh/CVE-2026-98432_poc.svg)
- [https://github.com/jackykeung/CVE-2026-98432-Verified-Attack](https://github.com/jackykeung/CVE-2026-98432-Verified-Attack) :  ![starts](https://img.shields.io/github/stars/jackykeung/CVE-2026-98432-Verified-Attack.svg) ![forks](https://img.shields.io/github/forks/jackykeung/CVE-2026-98432-Verified-Attack.svg)
- [https://github.com/sam00/CVE-2026-98432-POC-Exploit](https://github.com/sam00/CVE-2026-98432-POC-Exploit) :  ![starts](https://img.shields.io/github/stars/sam00/CVE-2026-98432-POC-Exploit.svg) ![forks](https://img.shields.io/github/forks/sam00/CVE-2026-98432-POC-Exploit.svg)


## CVE-2026-98260
[ tglx: Move the cleanup right after de_thread() ]

- [https://github.com/cuteaplane/opd2051example](https://github.com/cuteaplane/opd2051example) :  ![starts](https://img.shields.io/github/stars/cuteaplane/opd2051example.svg) ![forks](https://img.shields.io/github/forks/cuteaplane/opd2051example.svg)
- [https://github.com/arkylin/CVE-2026-98260-Asteroids](https://github.com/arkylin/CVE-2026-98260-Asteroids) :  ![starts](https://img.shields.io/github/stars/arkylin/CVE-2026-98260-Asteroids.svg) ![forks](https://img.shields.io/github/forks/arkylin/CVE-2026-98260-Asteroids.svg)


## CVE-2026-96889
 A flaw was found in librsvg. When processing an SVG document containing nested XML inclusions (Xincludes) with duplicate entity declarations, a use-after-free error can occur. This vulnerability arises because the library incorrectly frees an XML entity that is still in use by the parser. An attacker could potentially exploit this to cause a denial of service or execute arbitrary code.

- [https://github.com/anishadhikari02/cve-2026-96889-payload](https://github.com/anishadhikari02/cve-2026-96889-payload) :  ![starts](https://img.shields.io/github/stars/anishadhikari02/cve-2026-96889-payload.svg) ![forks](https://img.shields.io/github/forks/anishadhikari02/cve-2026-96889-payload.svg)


## CVE-2026-96760
 Authlib (v1.7.2 and below) contains a signature verification bypass vulnerability. The JsonWebSignature.deserialize_json() method accepts a JSON Serialization JWS object and returns the payload as successfully verified without checking for a signature and without requiring a cryptographic key.

- [https://github.com/federiconbaez/cortex9-authlib-jws-json-empty-signatures-model](https://github.com/federiconbaez/cortex9-authlib-jws-json-empty-signatures-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-authlib-jws-json-empty-signatures-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-authlib-jws-json-empty-signatures-model.svg)


## CVE-2026-94434
This issue affects Pardus Boot Repair: from 1.0.8 before 1.0.9.

- [https://github.com/ozcanpng/CVE-2026-94434](https://github.com/ozcanpng/CVE-2026-94434) :  ![starts](https://img.shields.io/github/stars/ozcanpng/CVE-2026-94434.svg) ![forks](https://img.shields.io/github/forks/ozcanpng/CVE-2026-94434.svg)


## CVE-2026-93399
 The Bookly plugin for WordPress is vulnerable to Insecure Direct Object Reference in versions up to, and including, 28.2 via the 'bookly_get_form_id', 'bookly_render_complete', 'bookly_add_to_calendar' and 'bookly_rollback_order' AJAX actions. This is due to the 'bookly_get_form_id' handler blindly storing the attacker-controlled 'order_id' from the submitted form_data into a new booking session, which the 'bookly_render_complete' handler then trusts to look up and return the corresponding Order's secret token without verifying that the current session created that order. This makes it possible for unauthenticated attackers to enumerate sequential order IDs, disclose other customers' order tokens, retrieve calendar/appointment information via 'bookly_add_to_calendar' and permanently delete arbitrary non-completed bookings via 'bookly_rollback_order', which cascade-deletes the customer_appointment and (when no other customers are attached) the underlying appointment.

- [https://github.com/josemour88/CVE-2026-93399](https://github.com/josemour88/CVE-2026-93399) :  ![starts](https://img.shields.io/github/stars/josemour88/CVE-2026-93399.svg) ![forks](https://img.shields.io/github/forks/josemour88/CVE-2026-93399.svg)


## CVE-2026-92606
This issue affects Pardus MyComputer: from 0.8.0 before 0.8.1.

- [https://github.com/ozcanpng/CVE-2026-92606](https://github.com/ozcanpng/CVE-2026-92606) :  ![starts](https://img.shields.io/github/stars/ozcanpng/CVE-2026-92606.svg) ![forks](https://img.shields.io/github/forks/ozcanpng/CVE-2026-92606.svg)


## CVE-2026-92080
This issue affects pardus-boot-repair: from 1.0.8 before 1.1.0.

- [https://github.com/ozcanpng/CVE-2026-92080](https://github.com/ozcanpng/CVE-2026-92080) :  ![starts](https://img.shields.io/github/stars/ozcanpng/CVE-2026-92080.svg) ![forks](https://img.shields.io/github/forks/ozcanpng/CVE-2026-92080.svg)


## CVE-2026-84380
 HTTPX2 is a next generation HTTP client for Python. Prior to 2.11.0, Request._prepare() in src/httpx2/httpx2/_models.py can add a body-derived Content-Length header to a request that already contains a caller-supplied Transfer-Encoding header because its setdefault() processing checks each default header independently rather than treating the two framing headers as mutually exclusive. Fixed-size byte, JSON, form, and known-length multipart bodies can therefore be serialized over HTTP/1.1 with both headers, allowing request smuggling or connection desynchronization when downstream intermediaries disagree about which framing header takes precedence. This issue is fixed in version 2.11.0.

- [https://github.com/federiconbaez/cortex9-httpx2-cl-te-framing-conflict-model](https://github.com/federiconbaez/cortex9-httpx2-cl-te-framing-conflict-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-httpx2-cl-te-framing-conflict-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-httpx2-cl-te-framing-conflict-model.svg)


## CVE-2026-83844
 Out-of-bounds read in Windows Paint allows an unauthorized attacker to execute code locally.

- [https://github.com/HackingLZ/CVE-2026-83844-public](https://github.com/HackingLZ/CVE-2026-83844-public) :  ![starts](https://img.shields.io/github/stars/HackingLZ/CVE-2026-83844-public.svg) ![forks](https://img.shields.io/github/forks/HackingLZ/CVE-2026-83844-public.svg)


## CVE-2026-83681
 Weak authentication in Microsoft PowerToys allows an authorized attacker to perform tampering locally.

- [https://github.com/2alf/CarbonBlue](https://github.com/2alf/CarbonBlue) :  ![starts](https://img.shields.io/github/stars/2alf/CarbonBlue.svg) ![forks](https://img.shields.io/github/forks/2alf/CarbonBlue.svg)


## CVE-2026-79657
 NLTK versions before 3.10.3 contain a remote code execution vulnerability in allowlisted pickle loaders that trust entire module namespaces instead of specific safe callables. Attackers can craft malicious pickle payloads invoking dangerous in-namespace functions like ReppTokenizer._execute and numpy.f2py.crackfortran.myeval through pickle REDUCE to execute arbitrary commands during model or tokenizer artifact loading.

- [https://github.com/federiconbaez/cortex9-nltk-pickle-allowlist-prefix-model](https://github.com/federiconbaez/cortex9-nltk-pickle-allowlist-prefix-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-nltk-pickle-allowlist-prefix-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-nltk-pickle-allowlist-prefix-model.svg)


## CVE-2026-75037
 Polkit Authentication Based on UnixProcessSubject / Peer PID in LACT on Linux allows an Authentication Bypass. This issue affects LACT through 0.10.0. Fixed by commit d0478fe42c2219454e272f96b1cbd29ab37ee566.

- [https://github.com/federiconbaez/cortex9-lact-polkit-pid-subject-bypass-model](https://github.com/federiconbaez/cortex9-lact-polkit-pid-subject-bypass-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-lact-polkit-pid-subject-bypass-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-lact-polkit-pid-subject-bypass-model.svg)


## CVE-2026-73858
 Solspace Freeform plugin for Craft CMS 5.x is a super flexible form-building tool. From 5.0.0 through 5.10.13, submitted values from public Freeform forms can be evaluated by the isolated Twig renderer when rendered into HTML attributes. An unauthenticated attacker can place Twig expressions in submitted field values, including value attributes, and receive evaluated PHP, operating-system, or Craft filesystem-path constants in the form response. The isolated context was not shown to expose Craft globals, environment variables, credentials, arbitrary files, or code execution, so the confirmed impact is limited server and environment information disclosure and possible rendering errors. This issue is fixed in version 5.10.14.

- [https://github.com/federiconbaez/cortex9-freeform-attribute-twig-render-model](https://github.com/federiconbaez/cortex9-freeform-attribute-twig-render-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-freeform-attribute-twig-render-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-freeform-attribute-twig-render-model.svg)


## CVE-2026-73802
 Gitea Runner passes workflow-controlled container options into Docker job container configuration while privileged mode is disabled. Host namespace settings, expanded capabilities, and security profile overrides can remain effective despite Privileged being forced false. A workflow author able to run jobs on an affected Docker-backed runner can use these options to access host namespaces and execute commands as root on the runner host, bypassing the intended container isolation.

- [https://github.com/sn0x-sharma/Gitea2shell-Sandbox-Escape-to-Host-RCE](https://github.com/sn0x-sharma/Gitea2shell-Sandbox-Escape-to-Host-RCE) :  ![starts](https://img.shields.io/github/stars/sn0x-sharma/Gitea2shell-Sandbox-Escape-to-Host-RCE.svg) ![forks](https://img.shields.io/github/forks/sn0x-sharma/Gitea2shell-Sandbox-Escape-to-Host-RCE.svg)


## CVE-2026-72422
mutex which is safe on this send path (it already performs network I/O).

- [https://github.com/federiconbaez/cortex9-ksmbd-preauth-info-race-model](https://github.com/federiconbaez/cortex9-ksmbd-preauth-info-race-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-ksmbd-preauth-info-race-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-ksmbd-preauth-info-race-model.svg)


## CVE-2026-65600
 Traefik versions = v2.11.51, = v3.6.0 = v3.6.22, and = v3.7.0 = v3.7.6 contain an authentication bypass via path traversal in the ReplacePathRegex middleware. When ReplacePathRegex is configured with a regex that captures user-controlled path segments without a mandatory path separator (e.g. regex "^/api(.*)", replacement "/$1"), the middleware forwards the replaced path to the backend without validating that it matches its normalized form. An unauthenticated remote attacker can send a crafted request (e.g. GET /api../admin) that produces an un-normalized path such as /../admin, which a backend that normalizes paths resolves to a protected route, bypassing authentication middleware. Fixed in v2.11.52, v3.6.23, and v3.7.7.

- [https://github.com/federiconbaez/cortex9-traefik-replacepathregex-normalization-model](https://github.com/federiconbaez/cortex9-traefik-replacepathregex-normalization-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-traefik-replacepathregex-normalization-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-traefik-replacepathregex-normalization-model.svg)


## CVE-2026-64849
 MLflow is an open source AI engineering platform for agents, large language models, and machine learning models. Starting in 3.3.0 and prior to 3.15.0, the unauthenticated POST /api/2.0/mlflow/webhooks/{id}/test endpoint calls _validate_webhook_url() in mlflow/utils/validation.py only for the original URL while mlflow/webhooks/delivery.py follows redirects and re-resolves the hostname without pinning the validated address, allowing attackers to reach internal or cloud metadata services and receive response_status and response_body. This issue is fixed in version 3.15.0.

- [https://github.com/federiconbaez/cortex9-mlflow-webhook-dns-rebinding-toctou-model](https://github.com/federiconbaez/cortex9-mlflow-webhook-dns-rebinding-toctou-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-mlflow-webhook-dns-rebinding-toctou-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-mlflow-webhook-dns-rebinding-toctou-model.svg)


## CVE-2026-63686
Users are recommended to upgrade to version 2.4.69, which fixes this issue.

- [https://github.com/duruton/CVE-2026-63686-Dalton-Tim-](https://github.com/duruton/CVE-2026-63686-Dalton-Tim-) :  ![starts](https://img.shields.io/github/stars/duruton/CVE-2026-63686-Dalton-Tim-.svg) ![forks](https://img.shields.io/github/forks/duruton/CVE-2026-63686-Dalton-Tim-.svg)


## CVE-2026-62367
 Vikunja is an open-source self-hosted task management platform. In versions 1.0.0 through 2.3.0, when an administrator enables the per-provider `emailfallback` option on an OpenID Connect provider, Vikunja links an SSO login to a pre-existing local (username+password) account using only the `email` claim from the IdP. The fallback never checks an `email_verified` (or Microsoft `xms_edov`) signal and never requires the matched account's password. An attacker who can obtain a token from the configured issuer carrying a victim's email logs in as that victim with a full session, with no consent or interaction from the victim. Version 2.4.0 fixes the issue.

- [https://github.com/federiconbaez/cortex9-vikunja-oidc-email-verified-linking-model](https://github.com/federiconbaez/cortex9-vikunja-oidc-email-verified-linking-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-vikunja-oidc-email-verified-linking-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-vikunja-oidc-email-verified-linking-model.svg)


## CVE-2026-58882
 In decodeWapPdu of WapPushOverSms.java, there is a possible out of bounds read due to an integer overflow. This could lead to a remote denial of service with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/uzairdeveloper223/Defib](https://github.com/uzairdeveloper223/Defib) :  ![starts](https://img.shields.io/github/stars/uzairdeveloper223/Defib.svg) ![forks](https://img.shields.io/github/forks/uzairdeveloper223/Defib.svg)


## CVE-2026-57845
 Hugging Face Datasets through 5.1.0 contains an insecure deserialization vulnerability that allows attackers to execute arbitrary Python code by crafting a malicious pickle file loaded through the deprecated pandas packaged builder. Attackers can supply a pickle-backed dataset that is processed by Pandas._generate_tables via pandas.read_pickle() without validation, so when a victim calls datasets.load_dataset("pandas", data_files=...), the embedded __reduce__ payload executes code with the victim process's privileges.

- [https://github.com/Sun-Wukhan/pickle-sentry](https://github.com/Sun-Wukhan/pickle-sentry) :  ![starts](https://img.shields.io/github/stars/Sun-Wukhan/pickle-sentry.svg) ![forks](https://img.shields.io/github/forks/Sun-Wukhan/pickle-sentry.svg)


## CVE-2026-56712
 Replicate Cog through 0.23.1 contains a server-side request forgery vulnerability that allows attackers to cause the Cog process to make server-side HTTP requests by submitting prediction inputs with attacker-controlled URLs that are not validated against the resolved destination host or IP before fetching. Attackers can supply malicious URLs or exploit HTTP redirects in cog.File and cog.Path predictor inputs to force requests to internal addresses, potentially exposing sensitive internal services or credentials.

- [https://github.com/SaiTeja-Erukude/CVE-2026-56712-cog-ssrf](https://github.com/SaiTeja-Erukude/CVE-2026-56712-cog-ssrf) :  ![starts](https://img.shields.io/github/stars/SaiTeja-Erukude/CVE-2026-56712-cog-ssrf.svg) ![forks](https://img.shields.io/github/forks/SaiTeja-Erukude/CVE-2026-56712-cog-ssrf.svg)


## CVE-2026-55797
 Argo CD is a declarative, GitOps continuous delivery tool for Kubernetes. From 2.11.0 until 3.3.15, 3.4.10, 3.5.4, and 3.6.0-rc2, the Argo CD repo-server is vulnerable to command injection when it clones, tests, or fetches an SSH Git repository configured with a proxy URL. The proxy host and port are embedded in an SSH ProxyCommand that is executed through a shell without neutralizing shell metacharacters. A user who can create or update a repository or repository credential template can supply a crafted proxy host to execute commands in the repo-server and access its Git, Helm, and OCI credentials. This issue is fixed in versions 3.3.15, 3.4.10, 3.5.4, and 3.6.0-rc2.

- [https://github.com/federiconbaez/cortex9-argocd-git-ssh-proxy-url-injection-model](https://github.com/federiconbaez/cortex9-argocd-git-ssh-proxy-url-injection-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-argocd-git-ssh-proxy-url-injection-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-argocd-git-ssh-proxy-url-injection-model.svg)


## CVE-2026-54017
 Open WebUI is a self-hosted artificial intelligence platform designed to operate entirely offline. Prior to 0.9.6, the terminal-server reverse proxy in `backend/open_webui/routers/terminals.py` does not fully confine the user-controlled `path` segment before forwarding it to an admin-configured terminal server. An authenticated user who has been granted access to a terminal server can craft `path` values containing encoded `../` traversal sequences that escape the intended path (or policy) scope on that server, reaching unintended endpoints and files on the terminal-server host. Where the terminal server fans requests out to internal services, this also gives SSRF-style reach into those services. This is a separate code path from the `/api/v1/retrieval/process/web` SSRF (GHSA-c6xv-rcvw-v685), with its own input. Two distinct vectors are consolidated here: first, raw path forwarding / single-encoded traversal (original report); and second, a bypass of the subsequently-added `_sanitize_proxy_path` mitigation using double-encoded dots (`%252e%252e`). The attacker-controlled input is the request `path`, supplied by the non-admin user, not anything an administrator configures, so this is not an admin-trust / Rule-9 situation. Version 0.9.6 fixes the issue.

- [https://github.com/federiconbaez/cortex9-open-webui-proxy-multidecode-traversal-model](https://github.com/federiconbaez/cortex9-open-webui-proxy-multidecode-traversal-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-open-webui-proxy-multidecode-traversal-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-open-webui-proxy-multidecode-traversal-model.svg)


## CVE-2026-39883
 OpenTelemetry-Go is the Go implementation of OpenTelemetry. From 1.15.0 to 1.42.0, the fix for CVE-2026-24051 changed the Darwin ioreg command to use an absolute path but left the BSD kenv command using a bare name, allowing the same PATH hijacking attack on BSD and Solaris platforms. This vulnerability is fixed in 1.43.0.

- [https://github.com/NinjaShadowBoy/SSI-cve-39883-lab](https://github.com/NinjaShadowBoy/SSI-cve-39883-lab) :  ![starts](https://img.shields.io/github/stars/NinjaShadowBoy/SSI-cve-39883-lab.svg) ![forks](https://img.shields.io/github/forks/NinjaShadowBoy/SSI-cve-39883-lab.svg)


## CVE-2026-33050
 GeoNode is a geospatial content management system, a platform for the management and publication of geospatial data. Prior to 5.1.0, a crafted vector file layer name supplied during upload allows a low-privileged remote user to inject shell syntax and execute arbitrary operating-system commands on the GeoNode server. This issue is fixed in version 5.1.0.

- [https://github.com/federiconbaez/cortex9-geonode-layer-name-command-injection-model](https://github.com/federiconbaez/cortex9-geonode-layer-name-command-injection-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-geonode-layer-name-command-injection-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-geonode-layer-name-command-injection-model.svg)


## CVE-2026-31864
 JumpServer is an open source bastion host and an operation and maintenance security audit system. a Server-Side Template Injection (SSTI) vulnerability exists in JumpServer's Applet and VirtualApp upload functionality. This vulnerability can only be exploited by users with administrative privileges (Application Applet Management or Virtual Application Management permissions). Attackers can exploit this vulnerability to execute arbitrary code within the JumpServer Core container. The vulnerability arises from unsafe use of Jinja2 template rendering when processing user-uploaded YAML configuration files. When a user uploads an Applet or VirtualApp ZIP package, the manifest.yml file is rendered through Jinja2 without sandbox restrictions, allowing template injection attacks.

- [https://github.com/federiconbaez/cortex9-jumpserver-yaml-jinja-sandbox-model](https://github.com/federiconbaez/cortex9-jumpserver-yaml-jinja-sandbox-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-jumpserver-yaml-jinja-sandbox-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-jumpserver-yaml-jinja-sandbox-model.svg)


## CVE-2026-26189
 Trivy Action runs Trivy as GitHub action to scan a Docker container image for vulnerabilities. A command injection vulnerability exists in `aquasecurity/trivy-action` versions 0.31.0 through 0.33.1 due to improper handling of action inputs when exporting environment variables. The action writes `export VAR=input` lines to `trivy_envs.txt` based on user-supplied inputs and subsequently sources this file in `entrypoint.sh`. Because input values are written without appropriate shell escaping, attacker-controlled input containing shell metacharacters (e.g., `$(...)`, backticks, or other command substitution syntax) may be evaluated during the sourcing process. This can result in arbitrary command execution within the GitHub Actions runner context. Version 0.34.0 contains a patch for this issue. The vulnerability is exploitable when a consuming workflow passes attacker-controlled data into any action input that is written to `trivy_envs.txt`. Access to user input is required by the malicious actor. Workflows that do not pass attacker-controlled data into `trivy-action` inputs, workflows that upgrade to a patched version that properly escapes shell values or eliminates the `source ./trivy_envs.txt` pattern, and workflows where user input is not accessible are not affected.

- [https://github.com/federiconbaez/cortex9-trivy-action-envfile-source-injection-model](https://github.com/federiconbaez/cortex9-trivy-action-envfile-source-injection-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-trivy-action-envfile-source-injection-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-trivy-action-envfile-source-injection-model.svg)


## CVE-2026-23813
 A vulnerability has been identified in the web-based management interface of AOS-CX switches that could potentially allow an unauthenticated remote actor to circumvent existing authentication controls. In some cases this could enable resetting the admin password.

- [https://github.com/cyberaeonic/security-research](https://github.com/cyberaeonic/security-research) :  ![starts](https://img.shields.io/github/stars/cyberaeonic/security-research.svg) ![forks](https://img.shields.io/github/forks/cyberaeonic/security-research.svg)


## CVE-2026-19553
isn't supplied.

- [https://github.com/Tharsh2003/INF2005-ACW3-PythonSSL](https://github.com/Tharsh2003/INF2005-ACW3-PythonSSL) :  ![starts](https://img.shields.io/github/stars/Tharsh2003/INF2005-ACW3-PythonSSL.svg) ![forks](https://img.shields.io/github/forks/Tharsh2003/INF2005-ACW3-PythonSSL.svg)


## CVE-2026-11800
 A flaw was found in Keycloak. This JWT algorithm confusion vulnerability in the JWT Authorization Grant flow allows an attacker with valid client credentials to bypass signature verification. By forging an assertion, the attacker can create unauthorized access tokens. This enables the attacker to impersonate any federated user linked to the affected Identity Provider, leading to unauthorized access and potential privilege escalation.

- [https://github.com/federiconbaez/cortex9-keycloak-jwt-grant-alg-confusion-model](https://github.com/federiconbaez/cortex9-keycloak-jwt-grant-alg-confusion-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-keycloak-jwt-grant-alg-confusion-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-keycloak-jwt-grant-alg-confusion-model.svg)


## CVE-2026-10961
 Use after free in Chrome for iOS in Google Chrome on iOS prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/Ya0h4cker/CVE-2026-109618-and-CVE-2026-109619](https://github.com/Ya0h4cker/CVE-2026-109618-and-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/Ya0h4cker/CVE-2026-109618-and-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/Ya0h4cker/CVE-2026-109618-and-CVE-2026-109619.svg)
- [https://github.com/TheMursalin/CVE-2026-109618](https://github.com/TheMursalin/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/TheMursalin/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/TheMursalin/CVE-2026-109618.svg)
- [https://github.com/santihabib/CVE-2026-109619](https://github.com/santihabib/CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/santihabib/CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/santihabib/CVE-2026-109619.svg)


## CVE-2026-4961
 A vulnerability was identified in Tenda AC6 15.03.05.16. Affected by this vulnerability is the function formQuickIndex of the file /goform/QuickIndex of the component POST Request Handler. The manipulation of the argument PPPOEPassword leads to stack-based buffer overflow. The attack is possible to be carried out remotely. The exploit is publicly available and might be used.

- [https://github.com/lufeng78/tenda-ac6-cve-2026-4961-patch](https://github.com/lufeng78/tenda-ac6-cve-2026-4961-patch) :  ![starts](https://img.shields.io/github/stars/lufeng78/tenda-ac6-cve-2026-4961-patch.svg) ![forks](https://img.shields.io/github/forks/lufeng78/tenda-ac6-cve-2026-4961-patch.svg)


## CVE-2026-3143
 The Total Upkeep – WordPress Backup Plugin plus Restore & Migrate by BoldGrid plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'wp_ajax_cli_cancel' function in all versions up to, and including, 1.17.1. This makes it possible for unauthenticated attackers to cancel a pending rollback, potentially preventing a WordPress installation from automatically reverting a failed update.

- [https://github.com/danimrtzp/CVE-2026-31431-REVSHELL](https://github.com/danimrtzp/CVE-2026-31431-REVSHELL) :  ![starts](https://img.shields.io/github/stars/danimrtzp/CVE-2026-31431-REVSHELL.svg) ![forks](https://img.shields.io/github/forks/danimrtzp/CVE-2026-31431-REVSHELL.svg)


## CVE-2026-2835
As a workaround, users can reject certain requests with an error in the request filter logic in order to stop processing bytes on the connection and disable downstream connection reuse. The user should reject any non-HTTP/1.1 request, or a request that has invalid Content-Length, multiple Transfer-Encoding headers, or Transfer-Encoding header that is not an exact “chunked” string match.

- [https://github.com/federiconbaez/cortex9-pingora-http10-te-smuggling-model](https://github.com/federiconbaez/cortex9-pingora-http10-te-smuggling-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-pingora-http10-te-smuggling-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-pingora-http10-te-smuggling-model.svg)


## CVE-2026-1096
 The Best-wp-google-map plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'latitude' and 'longitudinal' parameters of the 'google_map_view' shortcode in all versions up to, and including, 2.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/debugactiveprocess/CVE-2026-109618](https://github.com/debugactiveprocess/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/debugactiveprocess/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/debugactiveprocess/CVE-2026-109618.svg)
- [https://github.com/skydwn/CVE-2026-109618](https://github.com/skydwn/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/skydwn/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/skydwn/CVE-2026-109618.svg)
- [https://github.com/zhaoboy9692/CVE-2026-109618_](https://github.com/zhaoboy9692/CVE-2026-109618_) :  ![starts](https://img.shields.io/github/stars/zhaoboy9692/CVE-2026-109618_.svg) ![forks](https://img.shields.io/github/forks/zhaoboy9692/CVE-2026-109618_.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg)


## CVE-2025-62023
 Improper Control of Generation of Code ('Code Injection') vulnerability in Cristián Lávaque s2Member s2member.This issue affects s2Member: from n/a through 250905.

- [https://github.com/josemour88/CVE-2025-62023](https://github.com/josemour88/CVE-2025-62023) :  ![starts](https://img.shields.io/github/stars/josemour88/CVE-2025-62023.svg) ![forks](https://img.shields.io/github/forks/josemour88/CVE-2025-62023.svg)


## CVE-2025-27840
 Espressif ESP32 chips allow 29 hidden HCI commands, such as 0xFC02 (Write memory).

- [https://github.com/h4r-m0n1e/CVE-2025-27840-WIP](https://github.com/h4r-m0n1e/CVE-2025-27840-WIP) :  ![starts](https://img.shields.io/github/stars/h4r-m0n1e/CVE-2025-27840-WIP.svg) ![forks](https://img.shields.io/github/forks/h4r-m0n1e/CVE-2025-27840-WIP.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)


## CVE-2025-4609
 Incorrect handle provided in unspecified circumstances in Mojo in Google Chrome on Windows prior to 136.0.7103.113 allowed a remote attacker to potentially perform a sandbox escape via a malicious file. (Chromium security severity: High)

- [https://github.com/nek-3231/cve-2025-4609-mojo-poc](https://github.com/nek-3231/cve-2025-4609-mojo-poc) :  ![starts](https://img.shields.io/github/stars/nek-3231/cve-2025-4609-mojo-poc.svg) ![forks](https://img.shields.io/github/forks/nek-3231/cve-2025-4609-mojo-poc.svg)


## CVE-2024-53027
 Transient DOS may occur while processing the country IE.

- [https://github.com/h4r-m0n1e/CVE-2024-53027-WIP](https://github.com/h4r-m0n1e/CVE-2024-53027-WIP) :  ![starts](https://img.shields.io/github/stars/h4r-m0n1e/CVE-2024-53027-WIP.svg) ![forks](https://img.shields.io/github/forks/h4r-m0n1e/CVE-2024-53027-WIP.svg)


## CVE-2024-51482
 ZoneMinder is a free, open source closed-circuit television software application. ZoneMinder v1.37.* = 1.37.64 is vulnerable to boolean-based SQL Injection in function of web/ajax/event.php. This is fixed in 1.37.65.

- [https://github.com/ehl0707/CVE-2024-51482-ZoneMinder-CCTV-HTB-Reliable-EXP](https://github.com/ehl0707/CVE-2024-51482-ZoneMinder-CCTV-HTB-Reliable-EXP) :  ![starts](https://img.shields.io/github/stars/ehl0707/CVE-2024-51482-ZoneMinder-CCTV-HTB-Reliable-EXP.svg) ![forks](https://img.shields.io/github/forks/ehl0707/CVE-2024-51482-ZoneMinder-CCTV-HTB-Reliable-EXP.svg)


## CVE-2024-44068
 An issue was discovered in the m2m scaler driver in Samsung Mobile Processor and Wearable Processor Exynos 9820, 9825, 980, 990, 850,and W920. A Use-After-Free in the mobile processor leads to privilege escalation.

- [https://github.com/privacyportalUK/PP-Root](https://github.com/privacyportalUK/PP-Root) :  ![starts](https://img.shields.io/github/stars/privacyportalUK/PP-Root.svg) ![forks](https://img.shields.io/github/forks/privacyportalUK/PP-Root.svg)


## CVE-2024-38063
 Windows TCP/IP Remote Code Execution Vulnerability

- [https://github.com/omarbabba779xx/ethical-hacking-tp5-vulnerability-analysis-nmap-nse](https://github.com/omarbabba779xx/ethical-hacking-tp5-vulnerability-analysis-nmap-nse) :  ![starts](https://img.shields.io/github/stars/omarbabba779xx/ethical-hacking-tp5-vulnerability-analysis-nmap-nse.svg) ![forks](https://img.shields.io/github/forks/omarbabba779xx/ethical-hacking-tp5-vulnerability-analysis-nmap-nse.svg)


## CVE-2024-26229
 Windows CSC Service Elevation of Privilege Vulnerability

- [https://github.com/Cracked5pider/eop24-26229](https://github.com/Cracked5pider/eop24-26229) :  ![starts](https://img.shields.io/github/stars/Cracked5pider/eop24-26229.svg) ![forks](https://img.shields.io/github/forks/Cracked5pider/eop24-26229.svg)


## CVE-2023-45866
 Bluetooth HID Hosts in BlueZ may permit an unauthenticated Peripheral role HID Device to initiate and establish an encrypted connection, and accept HID keyboard reports, potentially permitting injection of HID messages when no user interaction has occurred in the Central role to authorize such access. An example affected package is bluez 5.64-0ubuntu1 in Ubuntu 22.04LTS. NOTE: in some cases, a CVE-2020-0556 mitigation would have already addressed this Bluetooth HID Hosts issue.

- [https://github.com/h4r-m0n1e/CVE-2023-45866_WIP](https://github.com/h4r-m0n1e/CVE-2023-45866_WIP) :  ![starts](https://img.shields.io/github/stars/h4r-m0n1e/CVE-2023-45866_WIP.svg) ![forks](https://img.shields.io/github/forks/h4r-m0n1e/CVE-2023-45866_WIP.svg)


## CVE-2023-36845
  *  23.2 versions prior to 23.2R1-S1, 23.2R2.

- [https://github.com/cxb2523/ccfb-pointwise-20261109-010-cve-2023-36845-scanner](https://github.com/cxb2523/ccfb-pointwise-20261109-010-cve-2023-36845-scanner) :  ![starts](https://img.shields.io/github/stars/cxb2523/ccfb-pointwise-20261109-010-cve-2023-36845-scanner.svg) ![forks](https://img.shields.io/github/forks/cxb2523/ccfb-pointwise-20261109-010-cve-2023-36845-scanner.svg)


## CVE-2023-33107
 Memory corruption in Graphics Linux while assigning shared virtual memory region during IOCTL call.

- [https://github.com/markutell/CVE-2023-33107-SO51A](https://github.com/markutell/CVE-2023-33107-SO51A) :  ![starts](https://img.shields.io/github/stars/markutell/CVE-2023-33107-SO51A.svg) ![forks](https://img.shields.io/github/forks/markutell/CVE-2023-33107-SO51A.svg)


## CVE-2023-6241
 Use After Free vulnerability in Arm Ltd Midgard GPU Kernel Driver, Arm Ltd Bifrost GPU Kernel Driver, Arm Ltd Valhall GPU Kernel Driver, Arm Ltd Arm 5th Gen GPU Architecture Kernel Driver allows a local non-privileged user to exploit a software race condition to perform improper memory processing operations. If the system’s memory is carefully prepared by the user, then this in turn cause a use-after-free.This issue affects Midgard GPU Kernel Driver: from r13p0 through r32p0; Bifrost GPU Kernel Driver: from r11p0 through r25p0; Valhall GPU Kernel Driver: from r19p0 through r25p0, from r29p0 through r46p0; Arm 5th Gen GPU Architecture Kernel Driver: from r41p0 through r46p0.

- [https://github.com/R0rt1z2/CVE-2023-6241-JM](https://github.com/R0rt1z2/CVE-2023-6241-JM) :  ![starts](https://img.shields.io/github/stars/R0rt1z2/CVE-2023-6241-JM.svg) ![forks](https://img.shields.io/github/forks/R0rt1z2/CVE-2023-6241-JM.svg)


## CVE-2023-4863
 Heap buffer overflow in libwebp in Google Chrome prior to 116.0.5845.187 and libwebp 1.3.2 allowed a remote attacker to perform an out of bounds memory write via a crafted HTML page. (Chromium security severity: Critical)

- [https://github.com/federiconbaez/cortex9-libwebp-huffman-table-sizing-model](https://github.com/federiconbaez/cortex9-libwebp-huffman-table-sizing-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-libwebp-huffman-table-sizing-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-libwebp-huffman-table-sizing-model.svg)


## CVE-2023-0286
over a network.

- [https://github.com/federiconbaez/cortex9-openssl-x400-generalname-type-confusion-model](https://github.com/federiconbaez/cortex9-openssl-x400-generalname-type-confusion-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-openssl-x400-generalname-type-confusion-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-openssl-x400-generalname-type-confusion-model.svg)


## CVE-2022-28986
 LMS Doctor Simple 2 Factor Authentication Plugin For Moodle Affected: 2021072900 has an Insecure direct object references (IDOR) vulnerability, which allows remote attackers to update sensitive records such as email, password and phone number of other user accounts.

- [https://github.com/FlaviuPopescu/CVE-2022-28986](https://github.com/FlaviuPopescu/CVE-2022-28986) :  ![starts](https://img.shields.io/github/stars/FlaviuPopescu/CVE-2022-28986.svg) ![forks](https://img.shields.io/github/forks/FlaviuPopescu/CVE-2022-28986.svg)


## CVE-2022-28601
 A Two-Factor Authentication (2FA) bypass vulnerability in "Simple 2FA Plugin for Moodle" by LMS Doctor allows remote attackers to overwrite the phone number used for confirmation via the profile.php file. Therefore, allowing them to bypass the phone verification mechanism.

- [https://github.com/FlaviuPopescu/CVE-2022-28601](https://github.com/FlaviuPopescu/CVE-2022-28601) :  ![starts](https://img.shields.io/github/stars/FlaviuPopescu/CVE-2022-28601.svg) ![forks](https://img.shields.io/github/forks/FlaviuPopescu/CVE-2022-28601.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/Super-Binary/cve-2021-44228](https://github.com/Super-Binary/cve-2021-44228) :  ![starts](https://img.shields.io/github/stars/Super-Binary/cve-2021-44228.svg) ![forks](https://img.shields.io/github/forks/Super-Binary/cve-2021-44228.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/ch4os443/CVE-2021-41773](https://github.com/ch4os443/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/ch4os443/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/ch4os443/CVE-2021-41773.svg)


## CVE-2021-3711
 In order to decrypt SM2 encrypted data an application is expected to call the API function EVP_PKEY_decrypt(). Typically an application will call this function twice. The first time, on entry, the "out" parameter can be NULL and, on exit, the "outlen" parameter is populated with the buffer size required to hold the decrypted plaintext. The application can then allocate a sufficiently sized buffer and call EVP_PKEY_decrypt() again, but this time passing a non-NULL value for the "out" parameter. A bug in the implementation of the SM2 decryption code means that the calculation of the buffer size required to hold the plaintext returned by the first call to EVP_PKEY_decrypt() can be smaller than the actual size required by the second call. This can lead to a buffer overflow when EVP_PKEY_decrypt() is called by the application a second time with a buffer that is too small. A malicious attacker who is able present SM2 content for decryption to an application could cause attacker chosen data to overflow the buffer by up to a maximum of 62 bytes altering the contents of other data held after the buffer, possibly changing application behaviour or causing the application to crash. The location of the buffer is application dependent but is typically heap allocated. Fixed in OpenSSL 1.1.1l (Affected 1.1.1-1.1.1k).

- [https://github.com/federiconbaez/cortex9-openssl-sm2-plaintext-size-model](https://github.com/federiconbaez/cortex9-openssl-sm2-plaintext-size-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-openssl-sm2-plaintext-size-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-openssl-sm2-plaintext-size-model.svg)


## CVE-2020-8927
 A buffer overflow exists in the Brotli library versions prior to 1.0.8 where an attacker controlling the input length of a "one-shot" decompression request to a script can trigger a crash, which happens when copying over chunks of data larger than 2 GiB. It is recommended to update your Brotli library to 1.0.8 or later. If one cannot update, we recommend to use the "streaming" API as opposed to the "one-shot" API, and impose chunk size limits.

- [https://github.com/federiconbaez/cortex9-brotli-uncompressed-copy-narrowing-model](https://github.com/federiconbaez/cortex9-brotli-uncompressed-copy-narrowing-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-brotli-uncompressed-copy-narrowing-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-brotli-uncompressed-copy-narrowing-model.svg)


## CVE-2019-2215
 A use-after-free in binder.c allows an elevation of privilege from an application to the Linux Kernel. No user interaction is required to exploit this vulnerability, however exploitation does require either the installation of a malicious local application or a separate vulnerability in a network facing application.Product: AndroidAndroid ID: A-141720095

- [https://github.com/WJNKAC/CVE-2019-2215-vivo-Y66i](https://github.com/WJNKAC/CVE-2019-2215-vivo-Y66i) :  ![starts](https://img.shields.io/github/stars/WJNKAC/CVE-2019-2215-vivo-Y66i.svg) ![forks](https://img.shields.io/github/forks/WJNKAC/CVE-2019-2215-vivo-Y66i.svg)


## CVE-2019-1926
 Multiple vulnerabilities in Cisco Webex Network Recording Player for Microsoft Windows and Cisco Webex Player for Microsoft Windows could allow an attacker to execute arbitrary code on an affected system. The vulnerabilities exist because the affected software improperly validates Advanced Recording Format (ARF) and Webex Recording Format (WRF) files. An attacker could exploit these vulnerabilities by sending a user a malicious ARF or WRF file through a link or email attachment and persuading the user to open the file with the affected software on the local system. A successful exploit could allow the attacker to execute arbitrary code on the affected system with the privileges of the targeted user.

- [https://github.com/harry1080/CVE-2019-19268](https://github.com/harry1080/CVE-2019-19268) :  ![starts](https://img.shields.io/github/stars/harry1080/CVE-2019-19268.svg) ![forks](https://img.shields.io/github/forks/harry1080/CVE-2019-19268.svg)


## CVE-2016-1834
 Heap-based buffer overflow in the xmlStrncat function in libxml2 before 2.9.4, as used in Apple iOS before 9.3.2, OS X before 10.11.5, tvOS before 9.2.1, and watchOS before 2.2.1, allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted XML document.

- [https://github.com/federiconbaez/cortex9-libxml2-strncat-length-wrap-model](https://github.com/federiconbaez/cortex9-libxml2-strncat-length-wrap-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-libxml2-strncat-length-wrap-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-libxml2-strncat-length-wrap-model.svg)


## CVE-2015-7547
 Multiple stack-based buffer overflows in the (1) send_dg and (2) send_vc functions in the libresolv library in the GNU C Library (aka glibc or libc6) before 2.23 allow remote attackers to cause a denial of service (crash) or possibly execute arbitrary code via a crafted DNS response that triggers a call to the getaddrinfo function with the AF_UNSPEC or AF_INET6 address family, related to performing "dual A/AAAA DNS queries" and the libnss_dns.so.2 NSS module.

- [https://github.com/federiconbaez/cortex9-glibc-getaddrinfo-dual-buffer-state-model](https://github.com/federiconbaez/cortex9-glibc-getaddrinfo-dual-buffer-state-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-glibc-getaddrinfo-dual-buffer-state-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-glibc-getaddrinfo-dual-buffer-state-model.svg)


## CVE-2012-0694
 SugarCRM CE = 6.3.1 contains scripts that use "unserialize()" with user controlled input which allows remote attackers to execute arbitrary PHP code.

- [https://github.com/marinovharisan/CVE-2012-0694-SugarCRM-PoC](https://github.com/marinovharisan/CVE-2012-0694-SugarCRM-PoC) :  ![starts](https://img.shields.io/github/stars/marinovharisan/CVE-2012-0694-SugarCRM-PoC.svg) ![forks](https://img.shields.io/github/forks/marinovharisan/CVE-2012-0694-SugarCRM-PoC.svg)

