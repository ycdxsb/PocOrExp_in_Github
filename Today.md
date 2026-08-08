# Update 2026-08-08
## CVE-2026-70559
 Dinky's SysConfigController.getAll() handler for GET /api/sysConfig/getAll carries a method-level @SaIgnore annotation that short-circuits the class-level @SaCheckLogin, so the Sa-Token interceptor lets the request through with no session or role check. Any remote unauthenticated caller who can reach the Dinky HTTP port (8888 by default) receives the full live system configuration (54 entries on a stock v1.2.5 install) with one parameterless GET. Only one credential field (sys.maven.settings.repositoryPassword) has a desensitization handler wired; the other credential-bearing fields (sys.env.settings.dinkyToken, sys.ldap.settings.userPassword, sys.resource.settings.oss.accessKey and secretKey, and sys.dolphinscheduler.settings.token) return in cleartext. A bare install leaks the shipped defaults, including the hardcoded dinkyToken efda1551-7958-4e0f-80a8-dfd107df3e38 and minioadmin/minioadmin OSS keys; once an operator configures LDAP, object storage, or DolphinScheduler through the Settings Center, those live third-party credentials leak from the same endpoint. Because dinkyToken is the sole gate on the sibling POST /download/uploadFromRsByLocal arbitrary file write, this disclosure defeats token rotation as a mitigation for that vulnerability. Affects Dinky v1.2.5 (the current release, 2025-11-05) and the development branch (dev HEAD 63b5a5a), where the affected code is byte-identical.

- [https://github.com/codeb0ssx/CVE-2026-70559-PoC](https://github.com/codeb0ssx/CVE-2026-70559-PoC) :  ![starts](https://img.shields.io/github/stars/codeb0ssx/CVE-2026-70559-PoC.svg) ![forks](https://img.shields.io/github/forks/codeb0ssx/CVE-2026-70559-PoC.svg)


## CVE-2026-70553
 MaxSite CMS contains a remote code execution vulnerability that allows unauthenticated attackers to inject arbitrary PHP code into the application configuration file by submitting crafted POST requests to the install endpoint after installation is complete. Attackers can supply a malicious db_dbprefix value containing a single quote to break out of a PHP string literal in application/config/database.php, appending attacker-controlled PHP statements that are executed by the web server on every subsequent request, resulting in persistent unauthenticated remote code execution as the web-server process user.

- [https://github.com/woshidashabi1126/CVE-2026-70553-PoC](https://github.com/woshidashabi1126/CVE-2026-70553-PoC) :  ![starts](https://img.shields.io/github/stars/woshidashabi1126/CVE-2026-70553-PoC.svg) ![forks](https://img.shields.io/github/forks/woshidashabi1126/CVE-2026-70553-PoC.svg)


## CVE-2026-69098
 kotaemon through 0.12.0 contains an insecure deserialization vulnerability in the check_connection endpoint that allows unauthenticated attackers to instantiate arbitrary Python classes by supplying crafted YAML/JSON input with a __type__ field. Attackers can exploit this to override the __type__ field with subprocess.check_output and arbitrary arguments, achieving remote code execution with application process privileges.

- [https://github.com/0xdak/CVE-2026-69098_exploit](https://github.com/0xdak/CVE-2026-69098_exploit) :  ![starts](https://img.shields.io/github/stars/0xdak/CVE-2026-69098_exploit.svg) ![forks](https://img.shields.io/github/forks/0xdak/CVE-2026-69098_exploit.svg)


## CVE-2026-67689
 SQL Injection vulnerability in FineAdmin V1.0 allows a remote attacker to execute arbitrary code via the `field` and `order` parameters in paginated list endpoints

- [https://github.com/qflksheep/CVE-2026-67689-FineAdmin.Mvc-vulnerability](https://github.com/qflksheep/CVE-2026-67689-FineAdmin.Mvc-vulnerability) :  ![starts](https://img.shields.io/github/stars/qflksheep/CVE-2026-67689-FineAdmin.Mvc-vulnerability.svg) ![forks](https://img.shields.io/github/forks/qflksheep/CVE-2026-67689-FineAdmin.Mvc-vulnerability.svg)


## CVE-2026-67687
 Insecure Permissions vulnerability in ics-park v.2.0 allows a remote attacker to escalate privileges via the /system/role/save endpoint in RoleController.java and system/user/update endpoint in UserController.java

- [https://github.com/qflksheep/CVE-2026-67687-ICS-Park-Smart-Park-Management-System-v2.0](https://github.com/qflksheep/CVE-2026-67687-ICS-Park-Smart-Park-Management-System-v2.0) :  ![starts](https://img.shields.io/github/stars/qflksheep/CVE-2026-67687-ICS-Park-Smart-Park-Management-System-v2.0.svg) ![forks](https://img.shields.io/github/forks/qflksheep/CVE-2026-67687-ICS-Park-Smart-Park-Management-System-v2.0.svg)


## CVE-2026-67598
 Emlog Pro through 2.6.23 contains a disabled TLS certificate validation vulnerability in include/service/ai.php that allows network-adjacent attackers to intercept outbound HTTPS requests to configured LLM providers by presenting arbitrary TLS certificates, as CURLOPT_SSL_VERIFYPEER and CURLOPT_SSL_VERIFYHOST are unconditionally disabled across sendStream(), sendImageRequest(), send(), and fetchSearchHtml() with no option to re-enable verification. Attackers can perform man-in-the-middle interception to extract Authorization Bearer API keys from every AI request and inject crafted AI responses that may be acted upon by the tool-call execution pipeline, including the query_database and update_config tool handlers.

- [https://github.com/IlhomjonR/CVE-2026-67598](https://github.com/IlhomjonR/CVE-2026-67598) :  ![starts](https://img.shields.io/github/stars/IlhomjonR/CVE-2026-67598.svg) ![forks](https://img.shields.io/github/forks/IlhomjonR/CVE-2026-67598.svg)


## CVE-2026-65058
 Trezor Safe 3, Safe 5, and Safe 7 firmware contains a confirmation-binding flaw in the Ethereum sign_tx / sign_tx_eip1559 flow. For contract interactions, the device confirms only the initial calldata chunk while the signature commits to the full streamed calldata. An attacker could present calldata to a victim then supply a different tail that changes the signed transaction. Fixed in 70c9b0c.

- [https://github.com/iktok90-design/trezor-cve-2026-65058](https://github.com/iktok90-design/trezor-cve-2026-65058) :  ![starts](https://img.shields.io/github/stars/iktok90-design/trezor-cve-2026-65058.svg) ![forks](https://img.shields.io/github/forks/iktok90-design/trezor-cve-2026-65058.svg)


## CVE-2026-64633
 A vulnerability allowing remote unauthenticated code execution on the agent host.

- [https://github.com/tfawnies/CVE-2026-64633](https://github.com/tfawnies/CVE-2026-64633) :  ![starts](https://img.shields.io/github/stars/tfawnies/CVE-2026-64633.svg) ![forks](https://img.shields.io/github/forks/tfawnies/CVE-2026-64633.svg)


## CVE-2026-59083
Users are recommended to upgrade to version 11.0.24, 10.1.57 or 9.0.120, which fix the issue.

- [https://github.com/xiaoqiMikko/tomcat-check](https://github.com/xiaoqiMikko/tomcat-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/tomcat-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/tomcat-check.svg)


## CVE-2026-58048
 Improper preservation of SQL mode when renaming databases in  cPanel allows execution of SQL in root context.

- [https://github.com/tc4dy/CVE-2026-58048-PoC-Exploit](https://github.com/tc4dy/CVE-2026-58048-PoC-Exploit) :  ![starts](https://img.shields.io/github/stars/tc4dy/CVE-2026-58048-PoC-Exploit.svg) ![forks](https://img.shields.io/github/forks/tc4dy/CVE-2026-58048-PoC-Exploit.svg)


## CVE-2026-57827
 Joomla Extension - rsjoomla.com - Unauthenticated file upload in RSFiles component  1.17.12 - The Joomla extension RSFiles is vulnerable to an unauthenticated arbitrary file upload that allows uploading executable files and leads to full RCE.

- [https://github.com/jjkk123123/CVE-2026-57827](https://github.com/jjkk123123/CVE-2026-57827) :  ![starts](https://img.shields.io/github/stars/jjkk123123/CVE-2026-57827.svg) ![forks](https://img.shields.io/github/forks/jjkk123123/CVE-2026-57827.svg)


## CVE-2026-56164
 Missing authentication for critical function in Microsoft Office SharePoint allows an unauthorized attacker to elevate privileges over a network.

- [https://github.com/sam00/POC-CVE-2026-56164-exploit](https://github.com/sam00/POC-CVE-2026-56164-exploit) :  ![starts](https://img.shields.io/github/stars/sam00/POC-CVE-2026-56164-exploit.svg) ![forks](https://img.shields.io/github/forks/sam00/POC-CVE-2026-56164-exploit.svg)


## CVE-2026-56130
Upgrade to version 3.0.0 or later, which fixes the issue.

- [https://github.com/xiaoqiMikko/shiro-check](https://github.com/xiaoqiMikko/shiro-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/shiro-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/shiro-check.svg)


## CVE-2026-56091
Upgrade to version 3.0.0 or later, which fixes the issue.

- [https://github.com/xiaoqiMikko/shiro-check](https://github.com/xiaoqiMikko/shiro-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/shiro-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/shiro-check.svg)


## CVE-2026-54518
 jackson-databind contains the general-purpose data-binding functionality and tree-model for Jackson Data Processor. From 2.21.0 until 2.21.4 and 3.1.4, UnwrappedPropertyHandler.processUnwrappedCreatorProperties() replays buffered JSON into creator parameters but never consults prop.visibleInView(activeView). The normal property-based creator path gates creator properties on the active view, but this unwrapped-creator replay path bypasses that check, so a constructor parameter annotated with both @JsonView(AdminView.class) and @JsonUnwrapped is populated from attacker JSON even when a more restrictive view is active. This vulnerability is fixed in 2.21.4 and 3.1.4.

- [https://github.com/xiaoqiMikko/jackson-check](https://github.com/xiaoqiMikko/jackson-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/jackson-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/jackson-check.svg)


## CVE-2026-54517
 jackson-databind contains the general-purpose data-binding functionality and tree-model for Jackson Data Processor. From 2.21.0 until 2.21.4 and 3.1.4, in BeanDeserializer._deserializeUsingPropertyBased, the active-view (@JsonView) filter was applied only to creator properties; the regular property-buffering branch performed no prop.visibleInView(activeView) check. A change making SetterlessProperty.isMerging() return true routed setterless Collection/Map properties through this unguarded path, so a setterless collection annotated with a restricted @JsonView is populated from attacker JSON even when the active view excludes it. This vulnerability is fixed in 2.21.4 and 3.1.4.

- [https://github.com/xiaoqiMikko/jackson-check](https://github.com/xiaoqiMikko/jackson-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/jackson-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/jackson-check.svg)


## CVE-2026-54516
 jackson-databind contains the general-purpose data-binding functionality and tree-model for Jackson Data Processor. From 2.21.0 until 2.21.4 and 3.1.4, POJOPropertiesCollector._renameProperties() allows a property with @JsonProperty("renamed") on the getter and @JsonIgnore on the setter to be renamed rather than dropped. With MapperFeature.INFER_PROPERTY_MUTATORS enabled (default), the private backing field is retained; during deserialization BeanDeserializerFactory.addBeanProps() sees hasField()==true, builds a FieldProperty, and makes the backing field writable. An attacker supplying the renamed JSON key writes the backing field directly, bypassing the @JsonIgnore on the setter. This vulnerability is fixed in 3.1.4.

- [https://github.com/xiaoqiMikko/jackson-check](https://github.com/xiaoqiMikko/jackson-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/jackson-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/jackson-check.svg)


## CVE-2026-54515
 jackson-databind contains the general-purpose data-binding functionality and tree-model for Jackson Data Processor. From 2.8.0 until 2.18.9, 2.21.5, and 3.1.4, in BeanDeserializerBase.createContextual(), per-property @JsonIgnoreProperties exclusions are applied by _handleByNameInclusion(), producing a contextual deserializer whose BeanPropertyMap has the ignored properties removed. The subsequent per-property case-insensitivity block (triggered by @JsonFormat(ACCEPT_CASE_INSENSITIVE_PROPERTIES)) rebuilds from this._beanProperties (the original, unfiltered map) instead of contextual._beanProperties, then overwrites the filtered map — restoring every property _handleByNameInclusion had just removed. The ignored property becomes writable again. This vulnerability is fixed in 2.18.9, 2.21.5, and 3.1.4.

- [https://github.com/xiaoqiMikko/jackson-check](https://github.com/xiaoqiMikko/jackson-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/jackson-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/jackson-check.svg)


## CVE-2026-54514
 jackson-databind contains the general-purpose data-binding functionality and tree-model for Jackson Data Processor. From 2.0.0 until 2.18.8, 2.21.4, and 3.1.4, JDKFromStringDeserializer constructed InetSocketAddress with new InetSocketAddress(host, port), which performs eager DNS name resolution for hostname inputs at deserialization time. An application that binds untrusted JSON into a type containing an InetSocketAddress field issues an attacker-chosen DNS query during readValue, before any application-level validation or connect logic. The fix uses InetSocketAddress.createUnresolved(host, port), deferring DNS to an explicit connect. This vulnerability is fixed in 2.18.8, 2.21.4, and 3.1.4.

- [https://github.com/xiaoqiMikko/jackson-check](https://github.com/xiaoqiMikko/jackson-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/jackson-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/jackson-check.svg)


## CVE-2026-54513
 jackson-databind contains the general-purpose data-binding functionality and tree-model for Jackson Data Processor. From 2.10.0 until 2.18.8, 2.21.4, and 3.1.4, BasicPolymorphicTypeValidator.Builder.allowIfSubTypeIsArray() allowlists any array type based only on clazz.isArray(), without validating the array's component (element) type against the configured allowlist. A PTV built with allowIfSubTypeIsArray() plus an explicit concrete-type allowlist therefore still permits EvilType[] even though EvilType is not allowlisted. When Jackson deserializes the elements and no per-element type IDs are present, it instantiates the component type directly with no further PTV check, bypassing the allowlist. This vulnerability is fixed in 2.18.8, 2.21.4, and 3.1.4.

- [https://github.com/xiaoqiMikko/jackson-check](https://github.com/xiaoqiMikko/jackson-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/jackson-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/jackson-check.svg)


## CVE-2026-54512
 jackson-databind contains the general-purpose data-binding functionality and tree-model for Jackson Data Processor. From 2.10.0 until 2.18.8, 2.21.4, and 3.1.4, jackson-databind's PolymorphicTypeValidator (PTV) is the primary safety mechanism guarding polymorphic deserialization. When polymorphic typing is enabled and a type identifier contains generic parameters (i.e. the type ID string contains ), DatabindContext._resolveAndValidateGeneric() validates only the raw container class name (the substring before ) against the configured PTV. If the container type is approved, the method parses the full canonical type string via TypeFactory.constructFromCanonical() and returns the fully parameterized type without ever validating the nested type arguments against the PTV. The nested type arguments are then resolved, instantiated, and populated as beans during deserialization. An attacker who controls the type ID can therefore place a denied class as a generic type parameter of an allowed container — for example java.util.ArrayListcom.evil.Gadget when only java.util.ArrayList is allow-listed. The container passes the PTV check; com.evil.Gadget is loaded via Class.forName(name, true, loader), instantiated, and its properties are set from attacker-controlled JSON. This completely bypasses an explicitly configured PTV allow-list. This vulnerability is fixed in 2.18.8, 2.21.4, and 3.1.4.

- [https://github.com/xiaoqiMikko/jackson-check](https://github.com/xiaoqiMikko/jackson-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/jackson-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/jackson-check.svg)


## CVE-2026-53404
Users are recommended to upgrade to version 11.0.23, 10.1.56 or 9.0.119, which fix the issue.

- [https://github.com/xiaoqiMikko/tomcat-check](https://github.com/xiaoqiMikko/tomcat-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/tomcat-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/tomcat-check.svg)


## CVE-2026-50522
 Deserialization of untrusted data in Microsoft Office SharePoint allows an unauthorized attacker to execute code over a network.

- [https://github.com/WismanSec/sharepoint-2026-poc](https://github.com/WismanSec/sharepoint-2026-poc) :  ![starts](https://img.shields.io/github/stars/WismanSec/sharepoint-2026-poc.svg) ![forks](https://img.shields.io/github/forks/WismanSec/sharepoint-2026-poc.svg)


## CVE-2026-50193
 jackson-databind contains the general-purpose data-binding functionality and tree-model for Jackson Data Processor. From 2.13.0 until 2.14.0, a potential Denial-of-Service exists when attacker sends deeply nested JSON if (and only if) the service reads deeply nested (1000s of levels) JSON as JsonNode (ObjectMapper.readTree()) and writes out same (or modifided) node using JsonNode.toString(). This can consume significant amount of resources with concurrent relatively small requests (1000 nested arrays is 2kB). This vulnerability is fixed in 2.14.0.

- [https://github.com/xiaoqiMikko/jackson-check](https://github.com/xiaoqiMikko/jackson-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/jackson-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/jackson-check.svg)


## CVE-2026-49268
Upgrade to Apache Shiro 2.2.1 or 3.0.0-alpha-2 or later, which fixes the issue.

- [https://github.com/xiaoqiMikko/shiro-check](https://github.com/xiaoqiMikko/shiro-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/shiro-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/shiro-check.svg)


## CVE-2026-43632
 llama.cpp builds b7492 through the latest b9060 contains a use-after-free vulnerability in llama-server affecting six tokenization endpoints (/tokenize, /detokenize, /infill, /apply-template, /rerank, and /anthropic/count_tokens) that bypass the task queue and access ctx_server.vocab directly on HTTP worker threads. Attackers can exploit a time-of-check-time-of-use race condition where the main thread destroys and frees vocab after the synchronization lock is released but before the handler finishes using it, causing a crash or potential code execution when --sleep-idle-seconds is configured.

- [https://github.com/Vladimir-tokarev-cyera/llama-cpp-security-patches](https://github.com/Vladimir-tokarev-cyera/llama-cpp-security-patches) :  ![starts](https://img.shields.io/github/stars/Vladimir-tokarev-cyera/llama-cpp-security-patches.svg) ![forks](https://img.shields.io/github/forks/Vladimir-tokarev-cyera/llama-cpp-security-patches.svg)


## CVE-2026-43512
Users are recommended to upgrade to version 11.0.22, 10.1.55 or 9.0.118 which fix the issue.

- [https://github.com/xiaoqiMikko/tomcat-check](https://github.com/xiaoqiMikko/tomcat-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/tomcat-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/tomcat-check.svg)


## CVE-2026-41293
Users are recommended to upgrade to version [FIXED_VERSION], which fixes the issue.

- [https://github.com/xiaoqiMikko/tomcat-check](https://github.com/xiaoqiMikko/tomcat-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/tomcat-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/tomcat-check.svg)


## CVE-2026-39987
 marimo is a reactive Python notebook. Prior to 0.23.0, Marimo has a Pre-Auth RCE vulnerability. The terminal WebSocket endpoint /terminal/ws lacks authentication validation, allowing an unauthenticated attacker to obtain a full PTY shell and execute arbitrary system commands. Unlike other WebSocket endpoints (e.g., /ws) that correctly call validate_auth() for authentication, the /terminal/ws endpoint only checks the running mode and platform support before accepting connections, completely skipping authentication verification. This vulnerability is fixed in 0.23.0.

- [https://github.com/alreadyClosed/CVE-2026-39987](https://github.com/alreadyClosed/CVE-2026-39987) :  ![starts](https://img.shields.io/github/stars/alreadyClosed/CVE-2026-39987.svg) ![forks](https://img.shields.io/github/forks/alreadyClosed/CVE-2026-39987.svg)


## CVE-2026-25243
 Redis is an in-memory data structure store. In versions of redis-server up to 8.6.3, the RESTORE command does not properly validate serialized values. An authenticated attacker with permission to execute RESTORE can supply a crafted serialized payload that triggers invalid memory access and may lead to remote code execution. A workaround is to restrict access to the RESTORE command with ACL rules. This is patched in version 8.6.3.

- [https://github.com/captain-woof/CVE-2026-25243](https://github.com/captain-woof/CVE-2026-25243) :  ![starts](https://img.shields.io/github/stars/captain-woof/CVE-2026-25243.svg) ![forks](https://img.shields.io/github/forks/captain-woof/CVE-2026-25243.svg)


## CVE-2026-18649
 A flaw was found in the GStreamer gst-plugins-good package. The rtph264depay and rtph265depay RTP depayloader elements do not enforce a maximum size limit on the reassembly buffer used during fragmented RTP packet processing. A remote, unauthenticated attacker can send a continuous stream of RTP fragments without ever transmitting an end-of-fragment marker, causing the reassembly buffer to grow without bound until process memory is exhausted. This results in a denial of service through process termination.

- [https://github.com/0xSemizzz/CVE-2026-18649](https://github.com/0xSemizzz/CVE-2026-18649) :  ![starts](https://img.shields.io/github/stars/0xSemizzz/CVE-2026-18649.svg) ![forks](https://img.shields.io/github/forks/0xSemizzz/CVE-2026-18649.svg)


## CVE-2026-17543
 Improper escaping of backslashes in attacker-provided parameters would allow for trivial SQL injection in PHP versions from 8.2.* before 8.2.33, from 8.3.* before 8.3.33, from 8.4.* before 8.4.24, and from 8.5.* before 8.5.9.

- [https://github.com/Hunt-Benito/e-is-for-exploit-cve-2026-17543-php-pgsql-sql-injection-backslash-breakout](https://github.com/Hunt-Benito/e-is-for-exploit-cve-2026-17543-php-pgsql-sql-injection-backslash-breakout) :  ![starts](https://img.shields.io/github/stars/Hunt-Benito/e-is-for-exploit-cve-2026-17543-php-pgsql-sql-injection-backslash-breakout.svg) ![forks](https://img.shields.io/github/forks/Hunt-Benito/e-is-for-exploit-cve-2026-17543-php-pgsql-sql-injection-backslash-breakout.svg)


## CVE-2026-11961
 The User Registration & Membership  WordPress plugin before 5.2.3 does not validate that the membership tier submitted during public registration is one of the tiers allowed by the registration form before assigning that tier's associated user role, allowing unauthenticated users to register into an arbitrary published membership tier and obtain its role — up to administrator when such a tier exists.

- [https://github.com/JohenLastGen-JLG/CVE-2026-11961](https://github.com/JohenLastGen-JLG/CVE-2026-11961) :  ![starts](https://img.shields.io/github/stars/JohenLastGen-JLG/CVE-2026-11961.svg) ![forks](https://img.shields.io/github/forks/JohenLastGen-JLG/CVE-2026-11961.svg)


## CVE-2026-7867
 A flaw was found in udisks2. A local attacker with an active console session can exploit insufficient authorization checking on the 'as-user' option in the org.freedesktop.UDisks2.Filesystem.Mount() D-Bus method. This allows the attacker to spoof the 'as-user' parameter, mounting filesystems on behalf of arbitrary users, including privileged accounts. This can lead to local privilege escalation through mount point injection and manipulation of the mount namespace visible to privileged users.

- [https://github.com/azqzazq1/CVE-2026-7867-disk2root](https://github.com/azqzazq1/CVE-2026-7867-disk2root) :  ![starts](https://img.shields.io/github/stars/azqzazq1/CVE-2026-7867-disk2root.svg) ![forks](https://img.shields.io/github/forks/azqzazq1/CVE-2026-7867-disk2root.svg)


## CVE-2026-5977
 A weakness has been identified in Totolink A7100RU 7.4cu.2313_b20191024. This impacts the function setWiFiBasicCfg of the file /cgi-bin/cstecgi.cgi of the component CGI Handler. Executing a manipulation of the argument wifiOff can lead to os command injection. It is possible to launch the attack remotely. The exploit has been made available to the public and could be used for attacks.

- [https://github.com/FlowerWitch/CVE-2026-59774_docker](https://github.com/FlowerWitch/CVE-2026-59774_docker) :  ![starts](https://img.shields.io/github/stars/FlowerWitch/CVE-2026-59774_docker.svg) ![forks](https://img.shields.io/github/forks/FlowerWitch/CVE-2026-59774_docker.svg)


## CVE-2026-5288
 Use after free in WebView in Google Chrome on Android prior to 146.0.7680.178 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/v3s9er/CVE-2026-52886](https://github.com/v3s9er/CVE-2026-52886) :  ![starts](https://img.shields.io/github/stars/v3s9er/CVE-2026-52886.svg) ![forks](https://img.shields.io/github/forks/v3s9er/CVE-2026-52886.svg)


## CVE-2026-3805
a data pointer pointing into already freed memory.

- [https://github.com/Crypte1/CVE-2026-38053---Remove-PPL](https://github.com/Crypte1/CVE-2026-38053---Remove-PPL) :  ![starts](https://img.shields.io/github/stars/Crypte1/CVE-2026-38053---Remove-PPL.svg) ![forks](https://img.shields.io/github/forks/Crypte1/CVE-2026-38053---Remove-PPL.svg)


## CVE-2026-3609
Note: KVE 2023-5589 (https://krcert.or.kr) was initially issued for version 10.0.10011.16384, but the vulnerability was not fully remediated and remains in version 2023.12.7.78.

- [https://github.com/BlackSnufkin/AxHunter](https://github.com/BlackSnufkin/AxHunter) :  ![starts](https://img.shields.io/github/stars/BlackSnufkin/AxHunter.svg) ![forks](https://img.shields.io/github/forks/BlackSnufkin/AxHunter.svg)


## CVE-2026-0300
Prisma Access, Cloud NGFW and Panorama appliances are not impacted by this vulnerability.

- [https://github.com/sam00/POC-CVE-2026-0300-exploit](https://github.com/sam00/POC-CVE-2026-0300-exploit) :  ![starts](https://img.shields.io/github/stars/sam00/POC-CVE-2026-0300-exploit.svg) ![forks](https://img.shields.io/github/forks/sam00/POC-CVE-2026-0300-exploit.svg)


## CVE-2026-0163
 In multiple functions of vpu_ioctl.c, there is a possible use after free due to a use after free. This could lead to remote escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/sentinel-aidefense/CVE-2026-0163-EXP](https://github.com/sentinel-aidefense/CVE-2026-0163-EXP) :  ![starts](https://img.shields.io/github/stars/sentinel-aidefense/CVE-2026-0163-EXP.svg) ![forks](https://img.shields.io/github/forks/sentinel-aidefense/CVE-2026-0163-EXP.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry.svg)


## CVE-2025-52464
 Meshtastic is an open source mesh networking solution. In versions from 2.5.0 to before 2.6.11, the flashing procedure of several hardware vendors was resulting in duplicated public/private keys. Additionally, the Meshtastic was failing to properly initialize the internal randomness pool on some platforms, leading to possible low-entropy key generation. When users with an affected key pair sent Direct Messages, those message could be captured and decrypted by an attacker that has compiled the list of compromised keys. This issue has been patched in version 2.6.11 where key generation is delayed til the first time the LoRa region is set, along with warning users when a compromised key is detected. Version 2.6.12 furthers this patch by automatically wiping known compromised keys when found. A workaround to this vulnerability involves users doing a complete device wipe to remove vendor-cloned keys.

- [https://github.com/msdmehdipour/meshtastic-cve-2025-52464-poc](https://github.com/msdmehdipour/meshtastic-cve-2025-52464-poc) :  ![starts](https://img.shields.io/github/stars/msdmehdipour/meshtastic-cve-2025-52464-poc.svg) ![forks](https://img.shields.io/github/forks/msdmehdipour/meshtastic-cve-2025-52464-poc.svg)


## CVE-2025-46811
 A Missing Authorization vulnerability in SUSE Linux Manager allows anyone with the ability to connect to port 443 of SUSE Manager is able to run any command as root on any client. This issue affects Container suse/manager/5.0/x86_64/server:5.0.5.7.30.1: from ? before 5.0.27-150600.3.33.1; Image SLES15-SP4-Manager-Server-4-3-BYOS: from ? before 4.3.87-150400.3.110.2; Image SLES15-SP4-Manager-Server-4-3-BYOS-Azure: from ? before 4.3.87-150400.3.110.2; Image SLES15-SP4-Manager-Server-4-3-BYOS-EC2: from ? before 4.3.87-150400.3.110.2; Image SLES15-SP4-Manager-Server-4-3-BYOS-GCE: from ? before 4.3.87-150400.3.110.2; SUSE Manager Server Module 4.3: from ? before 4.3.87-150400.3.110.2.

- [https://github.com/szachovy/CVE-2025-46811-challenge](https://github.com/szachovy/CVE-2025-46811-challenge) :  ![starts](https://img.shields.io/github/stars/szachovy/CVE-2025-46811-challenge.svg) ![forks](https://img.shields.io/github/forks/szachovy/CVE-2025-46811-challenge.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/0xPb1/Next.js-CVE-2025-29927](https://github.com/0xPb1/Next.js-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/0xPb1/Next.js-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/0xPb1/Next.js-CVE-2025-29927.svg)


## CVE-2025-8045
 Use After Free vulnerability in Arm Ltd Valhall GPU Kernel Driver, Arm Ltd Arm 5th Gen GPU Architecture Kernel Driver allows a local non-privileged user process to perform improper GPU processing operations to gain access to already freed memory.This issue affects Valhall GPU Kernel Driver: from r53p0 through r54p1; Arm 5th Gen GPU Architecture Kernel Driver: from r53p0 through r54p1.

- [https://github.com/kuzeyardabulut/CVE-2025-8045](https://github.com/kuzeyardabulut/CVE-2025-8045) :  ![starts](https://img.shields.io/github/stars/kuzeyardabulut/CVE-2025-8045.svg) ![forks](https://img.shields.io/github/forks/kuzeyardabulut/CVE-2025-8045.svg)


## CVE-2024-39024
 In Packetfence 13.2.0, the WebGui interface setting allows authenticated remote code execution.

- [https://github.com/ly1g3/packetfence-CVE-2024-39024](https://github.com/ly1g3/packetfence-CVE-2024-39024) :  ![starts](https://img.shields.io/github/stars/ly1g3/packetfence-CVE-2024-39024.svg) ![forks](https://img.shields.io/github/forks/ly1g3/packetfence-CVE-2024-39024.svg)


## CVE-2024-6387
 A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be able to trigger it by failing to authenticate within a set time period.

- [https://github.com/hasan8babiker/CVE-2024-6387](https://github.com/hasan8babiker/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/hasan8babiker/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/hasan8babiker/CVE-2024-6387.svg)


## CVE-2024-2421
 LenelS2 NetBox access control and event monitoring system was discovered to contain an unauthenticated RCE in versions prior to and including 5.6.1, which allows an attacker to execute malicious commands with elevated permissions.

- [https://github.com/ha6ker-hu/CVE-2024-24210](https://github.com/ha6ker-hu/CVE-2024-24210) :  ![starts](https://img.shields.io/github/stars/ha6ker-hu/CVE-2024-24210.svg) ![forks](https://img.shields.io/github/forks/ha6ker-hu/CVE-2024-24210.svg)


## CVE-2024-1086
We recommend upgrading past commit f342de4e2f33e0e39165d8639387aa6c19dff660.

- [https://github.com/dopaminauta/onetwoseven-writeup](https://github.com/dopaminauta/onetwoseven-writeup) :  ![starts](https://img.shields.io/github/stars/dopaminauta/onetwoseven-writeup.svg) ![forks](https://img.shields.io/github/forks/dopaminauta/onetwoseven-writeup.svg)

