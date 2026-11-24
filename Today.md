# Update 2026-11-24
## CVE-2026-134758
 Wfuzz through 3.1.1 contains a stored cross-site scripting vulnerability that allows malicious target servers to inject script by returning crafted links written unescaped into HTML reports. When the links script and html printer are used, attacker-supplied href values close the unquoted anchor tag and execute JavaScript when the operator opens the report.

- [https://github.com/VulnSVNC/CVE-2026-134758](https://github.com/VulnSVNC/CVE-2026-134758) :  ![starts](https://img.shields.io/github/stars/VulnSVNC/CVE-2026-134758.svg) ![forks](https://img.shields.io/github/forks/VulnSVNC/CVE-2026-134758.svg)


## CVE-2026-134753
 dsniff through 2.5a2 contains an integer underflow in decode_sniffer() in decode_sniffer.c that allows unauthenticated remote attackers to write past the global obuf buffer. Attackers can send a UDP datagram to port 2001 on a monitored segment with a 4096-byte string, disabling base64_pton bounds checks to corrupt memory and crash dsniff.

- [https://github.com/LLCForge/CVE-2026-134753](https://github.com/LLCForge/CVE-2026-134753) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-134753.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-134753.svg)
- [https://github.com/VulnSVNC/CVE-2026-134753](https://github.com/VulnSVNC/CVE-2026-134753) :  ![starts](https://img.shields.io/github/stars/VulnSVNC/CVE-2026-134753.svg) ![forks](https://img.shields.io/github/forks/VulnSVNC/CVE-2026-134753.svg)


## CVE-2026-134704
 OpenShot Video Editor (openshot-qt) through 4.1.1 contains an unsafe deserialization vulnerability in ProjectDataStore.load() and read_legacy_project_file() that passes non-JSON project files to pickle.load() without restriction. Attackers can trick users into opening a crafted .osp project file containing a pickle __reduce__ gadget to execute code with the user's privileges.

- [https://github.com/LLCForge/CVE-2026-134704](https://github.com/LLCForge/CVE-2026-134704) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-134704.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-134704.svg)


## CVE-2026-134694
 Gammapy through 2.1 contains a code injection vulnerability in WcsGeom.from_header() that passes the WCSSHAPE FITS header card to eval(). Attackers can supply a crafted .fits file with a Python expression in WCSSHAPE, executing code as the user who loads it via Map.read().

- [https://github.com/LLCForge/CVE-2026-134694](https://github.com/LLCForge/CVE-2026-134694) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-134694.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-134694.svg)


## CVE-2026-134679
 WeddingShare through 1.8.2 contains a missing authorization vulnerability in the anonymous MediaViewerController.GalleryItem action that allows unauthenticated attackers to retrieve item upload paths without the gallery secret key. Attackers can enumerate sequential integer item ids to learn paths and uploader names, then download photos and videos from key-protected galleries served as static files.

- [https://github.com/LLCForge/CVE-2026-134679](https://github.com/LLCForge/CVE-2026-134679) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-134679.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-134679.svg)


## CVE-2026-134654
 Mailflare before 48957fb contains a host header injection vulnerability in the password-reset request handler that allows unauthenticated attackers to poison reset links when APP_URL is unset. Attackers can submit a reset request for a victim's email with a malicious Host header, capturing the single-use token when the victim clicks the link to take over the account.

- [https://github.com/LLCForge/CVE-2026-134654](https://github.com/LLCForge/CVE-2026-134654) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-134654.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-134654.svg)


## CVE-2026-134623
 A flaw has been found in Microweber up to 2.0.20. This impacts the function UserManager::make_logged of the file src/MicroweberPackages/App/Http/Controllers/ApiController.php of the component Generic API Dispatcher. This manipulation causes improper access controls. Remote exploitation of the attack is possible. The exploit has been published and may be used. Upgrading to version 2.0.21 will fix this issue. Patch name: e639d26e61b989b100f8b6f6bb78c0cecca79b99. You should upgrade the affected component.

- [https://github.com/LLCForge/CVE-2026-134623](https://github.com/LLCForge/CVE-2026-134623) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-134623.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-134623.svg)
- [https://github.com/SumitNayak1337/CVE-2026-134623](https://github.com/SumitNayak1337/CVE-2026-134623) :  ![starts](https://img.shields.io/github/stars/SumitNayak1337/CVE-2026-134623.svg) ![forks](https://img.shields.io/github/forks/SumitNayak1337/CVE-2026-134623.svg)


## CVE-2026-134543
 A flaw has been found in jprocms up to 1.7.7. Affected is the function StrUtil.format of the component Database Backup Module. Executing a manipulation of the argument host/port/username/password/dbName can lead to os command injection. The attack can be launched remotely. The exploit has been published and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/LLCForge/CVE-2026-134543](https://github.com/LLCForge/CVE-2026-134543) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-134543.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-134543.svg)


## CVE-2026-134541
 A vulnerability was detected in Surya2Developer Online Shopping System 1.0. This impacts an unknown function of the file product.php of the component GET Parameter Handler. Performing a manipulation of the argument p results in sql injection. The attack can be initiated remotely. The exploit is now public and may be used. The project was informed of the problem early through an issue report but has not responded yet.

- [https://github.com/LLCForge/CVE-2026-134541](https://github.com/LLCForge/CVE-2026-134541) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-134541.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-134541.svg)


## CVE-2026-133528
 BeamNG.drive before 0.40.6 contains an out-of-bounds write vulnerability because JIT-compiled LuaJIT traces omit FFI array bounds checks, letting untrusted Lua escape the sandbox. Attackers supplying a malicious mod can JIT-compile an FFI store loop, write out of range using a tostring() address leak, re-enable ffi.load, and run commands as the game user.

- [https://github.com/drbloop2000/BeamNG-Drive-RCE](https://github.com/drbloop2000/BeamNG-Drive-RCE) :  ![starts](https://img.shields.io/github/stars/drbloop2000/BeamNG-Drive-RCE.svg) ![forks](https://img.shields.io/github/forks/drbloop2000/BeamNG-Drive-RCE.svg)


## CVE-2026-133169
 modified eCommerce Shopsoftware through 3.3.0 contains a stored cross-site scripting vulnerability that allows authenticated administrators to inject scripts via the unsanitized products_model field. Attackers with product editing permission can store JavaScript that executes in browsers of other administrators, storefront visitors, and customers viewing carts and order history.

- [https://github.com/capivara-research/CVE-2026-133169](https://github.com/capivara-research/CVE-2026-133169) :  ![starts](https://img.shields.io/github/stars/capivara-research/CVE-2026-133169.svg) ![forks](https://img.shields.io/github/forks/capivara-research/CVE-2026-133169.svg)


## CVE-2026-133112
 modified eCommerce Shopsoftware through 3.3.0 contains a cross-site request forgery vulnerability in gv_send.php because the action=process step never validates a CSRF token via check_secure_form(). Attackers can host an auto-submitting form that makes a logged-in customer send their gift voucher balance to an attacker-controlled email address for redemption.

- [https://github.com/capivara-research/CVE-2026-133112](https://github.com/capivara-research/CVE-2026-133112) :  ![starts](https://img.shields.io/github/stars/capivara-research/CVE-2026-133112.svg) ![forks](https://img.shields.io/github/forks/capivara-research/CVE-2026-133112.svg)


## CVE-2026-132825
 Ruby before 3.3.14, 3.4.13, and 4.0.10 has a heap-based buffer overflow during case conversion. One byte can be written outside a buffer for, for example, ISO-8859-1 or Windows-1252.

- [https://github.com/0xBlackash/CVE-2026-132825](https://github.com/0xBlackash/CVE-2026-132825) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-132825.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-132825.svg)


## CVE-2026-132252
 A vulnerability was found in October CMS up to 4.4.6. This affects the function validateExternalImageHost of the file modules/system/classes/resizeimages/ValidatesExternalImages.php of the component Image Resizer. Performing a manipulation of the argument url results in server-side request forgery. The attack may be initiated remotely. The complexity of an attack is rather high. The exploitability is reported as difficult. The exploit has been made public and could be used. Upgrading to version 4.4.7 mitigates this issue. The patch is named f6372867006c03141944e7b57396a726eb02acf0. You should upgrade the affected component.

- [https://github.com/capivara-research/CVE-2026-132252](https://github.com/capivara-research/CVE-2026-132252) :  ![starts](https://img.shields.io/github/stars/capivara-research/CVE-2026-132252.svg) ![forks](https://img.shields.io/github/forks/capivara-research/CVE-2026-132252.svg)


## CVE-2026-132147
and fixed query parameters. Crafted query parameters could cause version.cgi to output any lines of the target file which contained spaces.

- [https://github.com/ly1g3/debian-bts-CVE-2026-132147](https://github.com/ly1g3/debian-bts-CVE-2026-132147) :  ![starts](https://img.shields.io/github/stars/ly1g3/debian-bts-CVE-2026-132147.svg) ![forks](https://img.shields.io/github/forks/ly1g3/debian-bts-CVE-2026-132147.svg)


## CVE-2026-130007
 k8s-mcp-server manages Kubernetes clusters through the Model Context Protocol. Prior to 1.1.0, SERVER_MODE defaults to SSE, with the listener on 0.0.0.0:8080, but main.go creates the SSE server without an authentication option or context function. The GET /sse handler creates a sessionId that is only a correlation value, and the POST /message handler accepts a loadable sessionId without an authorization or Origin check before dispatching tools/call; consequently, any client able to reach the port can enumerate and invoke registered Kubernetes tools without credentials. Read-only mode is disabled by default, leaving write-capable Kubernetes tools available to run with the server's configured cluster privileges. This issue is fixed in version 1.1.0.

- [https://github.com/googlesky/CVE-2026-130007](https://github.com/googlesky/CVE-2026-130007) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-130007.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-130007.svg)


## CVE-2026-129307
 eml_parser serves as a python module for parsing eml files and returning various information found in the e-mail as well as computed information. In 3.0.3 and earlier, eml_parser.routing.parserouting() in eml_parser/routing.py builds a regular expression with multiple greedy capture groups and appends the npdate date literal extracted from a normalized copy of an attacker-controlled Received header, then searches that expression against the original unnormalized line. A formatting difference can make the trailing literal impossible to match, causing exhaustive backtracking across the greedy groups at each start position. The unsliced Received-header path is invoked by decode_email, decode_email_bytes, and parse_email, so one small unauthenticated message can pin a parser worker and create sustained queue backlog. This issue is fixed in version 3.0.4.

- [https://github.com/googlesky/CVE-2026-129307](https://github.com/googlesky/CVE-2026-129307) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-129307.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-129307.svg)


## CVE-2026-129304
 Guard Core is an API security core engine for the FastAPI-Guard, FlaskAPI Guard, and DjAPI Guard adapters. From 1.0.0 until 3.13.0, _extract_from_forwarded_header() in guard_core/utils.py returns the selected X-Forwarded-For entry without validating that it is an IP address. In deployments configured with trusted_proxies where the selected entry is attacker-controlled, the arbitrary client_ip string reaches BehaviorTracker in guard_core/handlers/behavior_handler.py and is interpolated into Redis key names and blocking KEYS glob patterns. Glob metacharacters can cause one request to count other clients' behavior events, embedded separators can disturb key parsing, and rotating identities can create unbounded keys while repeatedly scanning the shared Redis keyspace. A non-IP identity can also reach a ban action and cause an uncaught validation error. This issue is fixed in version 3.13.0.

- [https://github.com/googlesky/CVE-2026-129304](https://github.com/googlesky/CVE-2026-129304) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-129304.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-129304.svg)


## CVE-2026-129303
 Guard Core is an API security core engine for the FastAPI-Guard, FlaskAPI Guard, and DjAPI Guard adapters. From 1.0.0 until 3.13.0, ContentPreprocessor.preprocess() in guard_core/detection_engine/preprocessor.py collapses all whitespace before built-in pattern matching in the default enhanced mode. This removes carriage returns and newlines required by the http_split and newline-anchored cmd_injection detectors in guard_core/handlers/suspatterns_handler.py, making those detectors unable to match. Framework-decoded CRLF can therefore pass through Guard Core unflagged while the downstream application still receives the raw newline-bearing value. Direct security impact requires a downstream stack or application that persists or re-emits the value into a CRLF-tolerant response or command context. This issue is fixed in version 3.13.0.

- [https://github.com/googlesky/CVE-2026-129303](https://github.com/googlesky/CVE-2026-129303) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-129303.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-129303.svg)


## CVE-2026-129302
 Guard Core is an API security core engine for the FastAPI-Guard, FlaskAPI Guard, and DjAPI Guard adapters. From 3.5.0 until 3.13.0, built-in penetration-detection patterns in guard_core/handlers/suspatterns_handler.py execute through a direct pattern.search(content) call instead of the timeout-protected create_safe_matcher() path used for custom patterns. The built-in template-injection detector contains an unbounded expression with quadratic behavior when scanning repeated opening braces. Because penetration detection and enhanced mode are enabled by a stock SecurityConfig, an unauthenticated request can block the shared asyncio event loop, affecting all application endpoints. The triggering input does not produce a detection match, so the request can complete without incrementing ban counters or being recorded as suspicious. This issue is fixed in version 3.13.0.

- [https://github.com/googlesky/CVE-2026-129302](https://github.com/googlesky/CVE-2026-129302) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-129302.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-129302.svg)


## CVE-2026-129234
 NLTK (Natural Language Toolkit) is a suite of open source Python modules, data sets, and tutorials supporting research and development in Natural Language Processing. Prior to 3.10.4, Prover9Parent.config_prover9 and Mace accept a relative binary_location and pass it to find_binary as path_to_bin, disabling the bare-name absolute-path guard. A local attacker who can plant prover9 or mace4 in the resolved working directory can cause subprocess.Popen to execute that binary with the invoking user's privileges. This issue is fixed in version 3.10.4.

- [https://github.com/googlesky/CVE-2026-129234](https://github.com/googlesky/CVE-2026-129234) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-129234.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-129234.svg)


## CVE-2026-129233
 NLTK (Natural Language Toolkit) is a suite of open source Python modules, data sets, and tutorials supporting research and development in Natural Language Processing. From 3.10.0 until 3.10.4, StreamBackedCorpusView performs os.stat on a caller-supplied plain string path during construction before pathsec containment is enforced. The PathPointer branch used by in-tree corpus readers is validated, so exploitation requires application code to pass an attacker-influenced string directly to the public constructor. That string can identify an out-of-root path and disclose its existence, size, and modification time even though opening the file would be rejected. This issue is fixed in version 3.10.4.

- [https://github.com/googlesky/CVE-2026-129233](https://github.com/googlesky/CVE-2026-129233) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-129233.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-129233.svg)


## CVE-2026-129232
 NLTK (Natural Language Toolkit) is a suite of open source Python modules, data sets, and tutorials supporting research and development in Natural Language Processing. Prior to 3.10.4, XMLCorpusView.read_block rebuilds the full root-to-node context path with "/".join(context) for every start tag while searching for a matching element. Deeply nested attacker-influenced corpus XML therefore causes quadratic pure-Python work and can pin a processing worker, resulting in denial of service. This issue is fixed in version 3.10.4.

- [https://github.com/googlesky/CVE-2026-129232](https://github.com/googlesky/CVE-2026-129232) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-129232.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-129232.svg)


## CVE-2026-129231
 NLTK (Natural Language Toolkit) is a suite of open source Python modules, data sets, and tutorials supporting research and development in Natural Language Processing. Prior to 3.10.4, SeekableUnicodeStreamReader.readline appends each new block to a growing character buffer and reruns splitlines over the entire buffer on every iteration. An attacker-controlled corpus file containing one very long unterminated line therefore causes quadratic CPU consumption in line-oriented corpus readers and can deny service. This issue is fixed in version 3.10.4.

- [https://github.com/googlesky/CVE-2026-129231](https://github.com/googlesky/CVE-2026-129231) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-129231.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-129231.svg)


## CVE-2026-129230
 NLTK (Natural Language Toolkit) is a suite of open source Python modules, data sets, and tutorials supporting research and development in Natural Language Processing. Prior to 3.10.4, WordNet Synset.max_depth, min_depth, hypernym_paths, and hypernym_distances recursively follow attacker-controlled corpus pointers without a visited-node set or depth cap. A cyclic or excessively deep hypernym graph can raise RecursionError and terminate traversal APIs and similarity operations that depend on them. This issue is fixed in version 3.10.4.

- [https://github.com/googlesky/CVE-2026-129230](https://github.com/googlesky/CVE-2026-129230) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-129230.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-129230.svg)


## CVE-2026-129229
 NLTK (Natural Language Toolkit) is a suite of open source Python modules, data sets, and tutorials supporting research and development in Natural Language Processing. From 3.10.0 until 3.10.4, TokenSearcher.findall and Text.findall accept caller-controlled regular expressions with an unbounded number of capturing groups throughout the affected range. Starting in 3.10.3, nltk.redos.compile and RegexpTokenizer expose the same compile-time vector. The third-party regex engine compiles group-dense patterns with roughly quadratic cost before the match-time timeout begins, allowing a small unauthenticated request to exhaust CPU and deny service. This issue is fixed in version 3.10.4.

- [https://github.com/googlesky/CVE-2026-129229](https://github.com/googlesky/CVE-2026-129229) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-129229.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-129229.svg)


## CVE-2026-129228
 NLTK (Natural Language Toolkit) is a suite of open source Python modules, data sets, and tutorials supporting research and development in Natural Language Processing. Prior to 3.10.4, ToolboxSettings.parse builds a deeply nested attacker-controlled settings tree iteratively, but the later public helpers to_settings_string, remove_blanks, add_default_fields, sort_fields, and add_blank_lines recursively traverse that tree without a depth bound. Invoking any of those helpers on input nested beyond the interpreter recursion limit can raise RecursionError and abort the operation or request worker. This issue is fixed in version 3.10.4.

- [https://github.com/googlesky/CVE-2026-129228](https://github.com/googlesky/CVE-2026-129228) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-129228.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-129228.svg)


## CVE-2026-129227
 NLTK (Natural Language Toolkit) is a suite of open source Python modules, data sets, and tutorials supporting research and development in Natural Language Processing. Prior to 3.10.4, Tree.fromlist recursively converts nested Python list input into Tree objects without enforcing a maximum tree depth. An attacker-controlled list nested beyond the interpreter recursion limit can raise RecursionError and terminate the current parse operation or request worker. This issue is fixed in version 3.10.4.

- [https://github.com/googlesky/CVE-2026-129227](https://github.com/googlesky/CVE-2026-129227) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-129227.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-129227.svg)


## CVE-2026-129226
 NLTK (Natural Language Toolkit) is a suite of open source Python modules, data sets, and tutorials supporting research and development in Natural Language Processing. Prior to 3.10.4, the semantic-logic read_type parser recursively processes both halves of nested complex type strings without applying LogicParser.MAX_PARSE_DEPTH. An attacker-controlled type string or signature with excessive nesting can raise RecursionError through Type.fromstring or type-checking entry points and abort the current worker. This issue is fixed in version 3.10.4.

- [https://github.com/googlesky/CVE-2026-129226](https://github.com/googlesky/CVE-2026-129226) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-129226.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-129226.svg)


## CVE-2026-129225
 NLTK (Natural Language Toolkit) is a suite of open source Python modules, data sets, and tutorials supporting research and development in Natural Language Processing. In 3.10.3 and earlier, DependencyGraph._tree and triples recurse once per dependency edge without a depth bound, and get_cycle_path also lacks a visited-set termination guard. A deeply chained or cyclic attacker-controlled CoNLL or Malt-TAB dependency structure can raise RecursionError and abort a parse worker. This issue is fixed in version 3.10.4.

- [https://github.com/googlesky/CVE-2026-129225](https://github.com/googlesky/CVE-2026-129225) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-129225.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-129225.svg)


## CVE-2026-129224
 NLTK (Natural Language Toolkit) is a suite of open source Python modules, data sets, and tutorials supporting research and development in Natural Language Processing. Prior to 3.10.4, the CCG lexicon parser's matchBrackets and augParseCategory functions recursively process nested parenthesized categories without a depth bound. An attacker-controlled lexicon string with excessive nesting can raise RecursionError through nltk.ccg.lexicon.fromstring and terminate the parse operation or request worker. This issue is fixed in version 3.10.4.

- [https://github.com/googlesky/CVE-2026-129224](https://github.com/googlesky/CVE-2026-129224) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-129224.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-129224.svg)


## CVE-2026-128135
 NLTK (Natural Language Toolkit) is a suite of open source Python modules, data sets, and tutorials supporting research and development in Natural Language Processing. From 3.9.4 to 3.10.3, NLTK ZIP package extraction can write through an existing in-root hardlink whose other link points outside the NLTK data root. A local attacker who can prepare the extraction target can cause a package member write to overwrite an out-of-root file, violating the pathsec containment boundary and affecting integrity and availability. This issues is fixed in version 3.10.4.

- [https://github.com/googlesky/CVE-2026-128135](https://github.com/googlesky/CVE-2026-128135) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-128135.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-128135.svg)


## CVE-2026-126714
This issue affects PHP versions before 8.2.36, 8.3.* before 8.3.37, 8.4.* before 8.4.28 and 8.5.* before 8.5.13.

- [https://github.com/vperetti/phpbackports](https://github.com/vperetti/phpbackports) :  ![starts](https://img.shields.io/github/stars/vperetti/phpbackports.svg) ![forks](https://img.shields.io/github/forks/vperetti/phpbackports.svg)
- [https://github.com/0xBlackash/CVE-2026-126714](https://github.com/0xBlackash/CVE-2026-126714) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-126714.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-126714.svg)


## CVE-2026-125396
 Ghostscript before 10.08.0 contains a -dSAFER bypass vulnerability in the .putgstringcopy procedure in gs_fonts.ps, which calls the privileged .forceput operator without checking operand types. Attackers can supply crafted PostScript or PDF documents that trigger a type error, recover .forceput via a custom error handler, and cause a use-after-free across save/restore to execute arbitrary code.

- [https://github.com/9bie/CVE-2026-125396-bomb](https://github.com/9bie/CVE-2026-125396-bomb) :  ![starts](https://img.shields.io/github/stars/9bie/CVE-2026-125396-bomb.svg) ![forks](https://img.shields.io/github/forks/9bie/CVE-2026-125396-bomb.svg)
- [https://github.com/dinosn/upload2shell-poc-generator](https://github.com/dinosn/upload2shell-poc-generator) :  ![starts](https://img.shields.io/github/stars/dinosn/upload2shell-poc-generator.svg) ![forks](https://img.shields.io/github/forks/dinosn/upload2shell-poc-generator.svg)
- [https://github.com/Mahgal/upload2shell-check](https://github.com/Mahgal/upload2shell-check) :  ![starts](https://img.shields.io/github/stars/Mahgal/upload2shell-check.svg) ![forks](https://img.shields.io/github/forks/Mahgal/upload2shell-check.svg)
- [https://github.com/0xBlackash/CVE-2026-125396](https://github.com/0xBlackash/CVE-2026-125396) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-125396.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-125396.svg)
- [https://github.com/evenomn/CVE-2026-125396-upload2shell](https://github.com/evenomn/CVE-2026-125396-upload2shell) :  ![starts](https://img.shields.io/github/stars/evenomn/CVE-2026-125396-upload2shell.svg) ![forks](https://img.shields.io/github/forks/evenomn/CVE-2026-125396-upload2shell.svg)


## CVE-2026-125350
 Use after free in XML in Google Chrome prior to 157.0.8103.50 allowed a remote attacker to execute arbitrary code inside the sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/0xBlackash/CVE-2026-125350](https://github.com/0xBlackash/CVE-2026-125350) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-125350.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-125350.svg)


## CVE-2026-123890
Telco Cloud Platform 3.0, 4.x, 5.0.x, 5.1.x, 5.2 and Telco Cloud Infrastructure 3.0 are also affected (see KB463116).

- [https://github.com/PARTSI14/armory-castle-vcenter-detections](https://github.com/PARTSI14/armory-castle-vcenter-detections) :  ![starts](https://img.shields.io/github/stars/PARTSI14/armory-castle-vcenter-detections.svg) ![forks](https://img.shields.io/github/forks/PARTSI14/armory-castle-vcenter-detections.svg)


## CVE-2026-123488
 Craft CMS 4.0.0 before 4.18.9 and 5.0.0 before 5.11.2 contains an unauthenticated SQL injection vulnerability in the element search endpoint because the attribute parameter is concatenated into the query unsanitized and emulated PDO prepares allow stacked statements. Remote attackers can read and write the database, setting the admin flag or overwriting password hashes in the users table to gain administrator access.

- [https://github.com/0xBlackash/CVE-2026-123488](https://github.com/0xBlackash/CVE-2026-123488) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-123488.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-123488.svg)


## CVE-2026-123158
 sshd in OpenSSH before 10.6p2 on Linux, when musl libc is used without PAM, lacks a workaround for a password authentication bypass (related to misinterpretation of whether a string is intended to be a password hash). For some configurations of accounts, any password between 256 and 1024 characters succeeds. An example of a platform using musl libc without PAM is Alpine Linux.

- [https://github.com/0xBlackash/CVE-2026-123158](https://github.com/0xBlackash/CVE-2026-123158) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-123158.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-123158.svg)
- [https://github.com/0xsyr0/CVE-2026-123158-POC](https://github.com/0xsyr0/CVE-2026-123158-POC) :  ![starts](https://img.shields.io/github/stars/0xsyr0/CVE-2026-123158-POC.svg) ![forks](https://img.shields.io/github/forks/0xsyr0/CVE-2026-123158-POC.svg)


## CVE-2026-123007
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/0xBlackash/CVE-2026-123007](https://github.com/0xBlackash/CVE-2026-123007) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-123007.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-123007.svg)
- [https://github.com/VABISMO/nginx2root](https://github.com/VABISMO/nginx2root) :  ![starts](https://img.shields.io/github/stars/VABISMO/nginx2root.svg) ![forks](https://img.shields.io/github/forks/VABISMO/nginx2root.svg)


## CVE-2026-121716
 fzf is a command-line fuzzy finder. Prior to 0.74.5, bin/fzf-tmux validates separately supplied layout sizes but does not validate attached -l and -u layout values before Bash arithmetic expansion, allowing command substitution in a crafted operand to execute as the invoking user during option parsing. The same validation failure lets space-bearing popup geometry options -x, -y, -w, -h, and -p reach an unquoted tmux popup option string and inject additional tmux flags. Exploitation requires less-trusted project configuration, a wrapper, or a plugin to supply the poisoned value and requires the victim to invoke fzf-tmux; normal values are usually trusted, and the script has been superseded by built-in tmux options. This issue is fixed in version 0.74.5.

- [https://github.com/googlesky/CVE-2026-121716](https://github.com/googlesky/CVE-2026-121716) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-121716.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-121716.svg)


## CVE-2026-121529
 A origin validation error vulnerability in Fortinet FortiClientMac 7.4.0 through 7.4.7, FortiClientWindows 7.4.0 through 7.4.7, FortiClientWindows 7.2.0 through 7.2.14, FortiClientWindowsPAM 7.4.7, FortiClientWindowsPAM 7.2.14 may allow an unauthorized remote attacker to execute unauthorized code or commands. Successful exploitation requires interaction with the victim.

- [https://github.com/0xBlackash/CVE-2026-121529](https://github.com/0xBlackash/CVE-2026-121529) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-121529.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-121529.svg)


## CVE-2026-120984
 A flaw was found in the Keycloak server's client management component. When a client is created or imported with authorization services enabled, the system fails to properly clear an internal session attribute used during the setup process. This allows an authenticated attacker with client management permissions to bypass security controls and upload a malicious JavaScript policy, which is then executed on the server when an authorization request is made. Successful exploitation could allow the attacker to run arbitrary code on the server, potentially compromising the entire system.

- [https://github.com/youssefmohamed552/KeyCloak-CVE-2026-120984-poc](https://github.com/youssefmohamed552/KeyCloak-CVE-2026-120984-poc) :  ![starts](https://img.shields.io/github/stars/youssefmohamed552/KeyCloak-CVE-2026-120984-poc.svg) ![forks](https://img.shields.io/github/forks/youssefmohamed552/KeyCloak-CVE-2026-120984-poc.svg)


## CVE-2026-120343
 A flaw has been found in mathurvishal CloudClassroom-PHP-Project. The impacted element is an unknown function of the file manageassessment2.php. This manipulation of the argument ExamName/Q1/Q2/Q3/Q4/Q5 causes cross site scripting. The attack is possible to be carried out remotely. The exploit has been published and may be used. This product adopts a rolling release strategy to maintain continuous delivery. Therefore, version details for affected or updated releases cannot be specified. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/capivara-research/CVE-2026-120343](https://github.com/capivara-research/CVE-2026-120343) :  ![starts](https://img.shields.io/github/stars/capivara-research/CVE-2026-120343.svg) ![forks](https://img.shields.io/github/forks/capivara-research/CVE-2026-120343.svg)


## CVE-2026-116779
 FreeSWITCH is a Software Defined Telecom Stack enabling the digital transformation from proprietary telecom switches to a software implementation that runs on any commodity hardware. Prior to 1.11.3, sofia_presence_handle_sip_i_message() split the To user of an inbound SIP MESSAGE on a plus sign and treated the left side as a chat protocol selector. Selecting the api chat proto reached switch_api_execute(), allowing a peer whose MESSAGE was accepted to run FreeSWITCH API commands, including operating-system command sinks, with the daemon's privileges. Inbound chat is enabled on the stock internal and external profiles, and any authenticated profile account is sufficient; stock directory users without password material can also remove that barrier in affected configurations. The flaw permits configuration and credential disclosure, arbitrary call control, and command execution, and exploitation has been observed in the wild. This issue is fixed in version 1.11.3.

- [https://github.com/0xBlackash/CVE-2026-116779](https://github.com/0xBlackash/CVE-2026-116779) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-116779.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-116779.svg)


## CVE-2026-115563
 The Model Context Protocol Python SDK is the official Python SDK for Model Context Protocol servers and clients. From 1.9.1 until 1.30.0 and 2.2.0, OAuth client support in mcp.client.auth can send credentials to an authorization server chosen by an untrusted MCP server. ClientCredentialsOAuthProvider and PrivateKeyJWTOAuthProvider cannot identify the authorization server that owns their credentials. Affected HTTP clients using those providers, OAuthClientProvider, or the deprecated 1.x RFC7523OAuthClientProvider can disclose a client_secret, authorization code, PKCE code_verifier, or signed client assertion. MCP servers, stdio clients, and clients that attach their own tokens or headers are not affected. Interactive OAuthClientProvider use requires a person to start sign-in, while the unattended providers do not. For ClientCredentialsOAuthProvider and PrivateKeyJWTOAuthProvider, callers must configure issuer= after upgrading because omission still follows the MCP server's advertised authorization server, and the deprecated RFC7523OAuthClientProvider must be replaced because it has no issuer option. A stored client registration without an issuer remains unbound after upgrading, so stored OAuth client information must be cleared once to register again or a manually pre-registered record must be updated with its issuer. This issue is fixed in versions 1.30.0 and 2.2.0.

- [https://github.com/googlesky/CVE-2026-115563](https://github.com/googlesky/CVE-2026-115563) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-115563.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-115563.svg)


## CVE-2026-114938
 Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Compiler).  Supported versions that are affected are Oracle Java SE: 8u511b33-perf, 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3; Oracle GraalVM for JDK: 17.0.21.0.3 and  21.0.13.0.3; Oracle GraalVM Enterprise Edition: 21.3.20.0.3. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in takeover of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition. Note: This vulnerability can only be exploited by supplying data to APIs in the specified Component without using Untrusted Java Web Start applications or Untrusted Java applets, such as through a web service. CVSS 3.1 Base Score 8.1 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/0xBlackash/CVE-2026-114938](https://github.com/0xBlackash/CVE-2026-114938) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-114938.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-114938.svg)
- [https://github.com/adjscent/CVE-2026-114938-POC](https://github.com/adjscent/CVE-2026-114938-POC) :  ![starts](https://img.shields.io/github/stars/adjscent/CVE-2026-114938-POC.svg) ![forks](https://img.shields.io/github/forks/adjscent/CVE-2026-114938-POC.svg)


## CVE-2026-114728
 Roundcube Webmail before 1.6.20 and 1.7.x before 1.7.5 is affected by a remote content blocking bypass in the handling of FuncIRI attributes. rcube_washtml detected the CSS url() token with a pattern that enumerated only some of its escaped spellings, so values using other CSS escape sequences, for example \000075rl( or u\72 l(, were not recognized and remote content was loaded from an HTML message without the user's consent. Upstream fixed this in the commit “Fix remote content blocking bypass via CSS escapes in FuncIRI attributes (again)”, which resolves CSS escapes before matching and also inspects the `to`, `from` and `by` attributes.

- [https://github.com/Neo-XeD/CVE-2026-114728](https://github.com/Neo-XeD/CVE-2026-114728) :  ![starts](https://img.shields.io/github/stars/Neo-XeD/CVE-2026-114728.svg) ![forks](https://img.shields.io/github/forks/Neo-XeD/CVE-2026-114728.svg)


## CVE-2026-114595
 In EPICS Base release 7.0.10 and prior, an integer overflow in network request processing can cause memory to be allocated with an incorrect size. Subsequent handling of attacker supplied data may result in memory corruption, denial of service, or potential remote code execution.

- [https://github.com/0xBlackash/CVE-2026-114595](https://github.com/0xBlackash/CVE-2026-114595) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-114595.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-114595.svg)


## CVE-2026-112020
 LodePNG through 20261006 contains a heap out-of-bounds read vulnerability in lodepng::getFilterTypesInterlaced() in lodepng_util.cpp that lacks bounds checks on decompressed IDAT data. Attackers can supply a crafted interlaced PNG declaring a raster larger than its IDAT stream to disclose adjacent heap memory or crash applications.

- [https://github.com/coboliqcom/lodepng-hardened](https://github.com/coboliqcom/lodepng-hardened) :  ![starts](https://img.shields.io/github/stars/coboliqcom/lodepng-hardened.svg) ![forks](https://img.shields.io/github/forks/coboliqcom/lodepng-hardened.svg)


## CVE-2026-111497
Users need to update any Brotli libraries or binaries between 1.0.3 through 1.2.0 to the latest available version: 1.0.10 or 1.1.1 or 1.2.1.

- [https://github.com/0xBlackash/CVE-2026-111497](https://github.com/0xBlackash/CVE-2026-111497) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-111497.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-111497.svg)


## CVE-2026-110912
 In DragonFly BSD through 6.4.2 before 4bb22ff, the ARP input handlers arpintr() and in_arpinput() (sys/netinet/if_ether.c) do not validate the hardware address length (ar_hln) and protocol address length (ar_pln) fields of incoming ARP packets. in_arpreply() then uses these attacker-controlled values as memcpy lengths when copying from kernel buffers that are only 6 and 4 bytes long, resulting in an out-of-bounds read of kernel heap and stack memory that is copied into the ARP reply sent back to the requester. An unauthenticated attacker on the adjacent network can use a single crafted ARP request to disclose up to roughly 250 bytes of each type of kernel memory, including kernel pointers. This is expected to be fixed in the 6.6 stable release when that is available.

- [https://github.com/0xBlackash/CVE-2026-110912](https://github.com/0xBlackash/CVE-2026-110912) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-110912.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-110912.svg)


## CVE-2026-109619
 PHP has various global state that temporarily points into request memory. In some scenarios, global state may not be correctly reset, or may be repopulated after being reset. The global state may then refer to request memory even after it has been freed. Subsequent requests may read or branch on this stale state before it is fully initialized. Multiple strategies can trigger this condition and produce remote code execution (RCE).

- [https://github.com/xaviware/go-php2shell-scanner-CVE-2026-109618-CVE-2026-109619](https://github.com/xaviware/go-php2shell-scanner-CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/xaviware/go-php2shell-scanner-CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/xaviware/go-php2shell-scanner-CVE-2026-109618-CVE-2026-109619.svg)


## CVE-2026-109618
 PHP uses longjmp() for out-of-memory (OOM) errors to exit the current context and abort handling of the request. Some contexts may not properly account for this scenario and leave request memory in an uninitialized state before performing an allocation. The subsequent request cleanup procedure may read or branch on this memory. Multiple OOM strategies can consistently trigger this condition and lead to remote code execution (RCE).

- [https://github.com/vperetti/phpbackports](https://github.com/vperetti/phpbackports) :  ![starts](https://img.shields.io/github/stars/vperetti/phpbackports.svg) ![forks](https://img.shields.io/github/forks/vperetti/phpbackports.svg)


## CVE-2026-107853
 tiny-secp256k1 is a tiny secp256k1 native/JS wrapper. From 2.1.0 until 2.2.5 for tiny-secp256k1 and from 2.2.2 until 2.2.5 for @bitcoin-js/tiny-secp256k1-asmjs, the three-argument xOnlyPointAddTweakCheck path ignores the backend failure return from xOnlyPointAddTweak when a tweak produces the point at infinity. The shared X_ONLY_PUBLIC_KEY_INPUT buffer then still contains the original point, so a caller-controlled resultToCheck equal to that point can make the stale-buffer comparison return true even though no tweaked key exists. Protocols that rely on this helper to validate caller-controlled internal keys, tweaks, and comparison values can accept an invalid derived key. This issue is fixed in version 2.2.5.

- [https://github.com/googlesky/CVE-2026-107853](https://github.com/googlesky/CVE-2026-107853) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-107853.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-107853.svg)


## CVE-2026-106173
 A improper limitation of a pathname to a restricted directory ('path traversal') vulnerability in Fortinet FortiSIEM 7.5.0, FortiSIEM 7.4 all versions, FortiSIEM 7.3 all versions, FortiSIEM 7.2 all versions, FortiSIEM 7.1 all versions, FortiSIEM 7.0 all versions may allow attacker to execute unauthorized code or commands via specially crafted packets.

- [https://github.com/0xBlackash/CVE-2026-106173](https://github.com/0xBlackash/CVE-2026-106173) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-106173.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-106173.svg)


## CVE-2026-104099
 Fabio is an HTTP(S) and TCP router for deploying applications managed by consul. Prior to 1.7.3, route/table.go selects targets using raw req.URL.Path, while proxy/http_proxy.go applies per-route ACL and basic-auth checks to the selected target and forwards the raw path to the origin. Dot-segment, encoded-dot, or repeated-slash variants can fall through to a less restrictive route that reaches the same backend; the backend then normalizes the path and serves the protected resource without the configured access controls. A less restrictive fallback route must reach the same backend; without one, the request returns 404. This issue is fixed in version 1.7.3.

- [https://github.com/abraxas/cve-2026-104099-fabio-path-acl-bypass](https://github.com/abraxas/cve-2026-104099-fabio-path-acl-bypass) :  ![starts](https://img.shields.io/github/stars/abraxas/cve-2026-104099-fabio-path-acl-bypass.svg) ![forks](https://img.shields.io/github/forks/abraxas/cve-2026-104099-fabio-path-acl-bypass.svg)


## CVE-2026-102697
 Ollama versions 0.14.0 before 0.31.2 contain an incorrect authorization vulnerability in the experimental agent mode Bash tool approval mechanism that fails to properly parse shell syntax. Attackers who can influence model output through prompt injection can execute additional shell commands by appending control operators like semicolons or logical operators to approved commands, bypassing the session approval requirement.

- [https://github.com/akinerkisa/llamasmuggle-cve-2026-102697](https://github.com/akinerkisa/llamasmuggle-cve-2026-102697) :  ![starts](https://img.shields.io/github/stars/akinerkisa/llamasmuggle-cve-2026-102697.svg) ![forks](https://img.shields.io/github/forks/akinerkisa/llamasmuggle-cve-2026-102697.svg)


## CVE-2026-101767
 Vulnerability in the Oracle Application Object Library product of Oracle E-Business Suite (component: Core).  Supported versions that are affected are 12.2.3-12.2.15. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Application Object Library.  Successful attacks of this vulnerability can result in takeover of Oracle Application Object Library. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/0xBlackash/CVE-2026-101767](https://github.com/0xBlackash/CVE-2026-101767) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-101767.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-101767.svg)


## CVE-2026-99491
desynchronization.

- [https://github.com/woshigenm/CVE-2026-99491-FANXIAOCHAO](https://github.com/woshigenm/CVE-2026-99491-FANXIAOCHAO) :  ![starts](https://img.shields.io/github/stars/woshigenm/CVE-2026-99491-FANXIAOCHAO.svg) ![forks](https://img.shields.io/github/forks/woshigenm/CVE-2026-99491-FANXIAOCHAO.svg)
- [https://github.com/FatBrother1/hapt-99491](https://github.com/FatBrother1/hapt-99491) :  ![starts](https://img.shields.io/github/stars/FatBrother1/hapt-99491.svg) ![forks](https://img.shields.io/github/forks/FatBrother1/hapt-99491.svg)


## CVE-2026-99312
CR0.PG must be '0').

- [https://github.com/Quaerendir/cve-2026-99312-audit](https://github.com/Quaerendir/cve-2026-99312-audit) :  ![starts](https://img.shields.io/github/stars/Quaerendir/cve-2026-99312-audit.svg) ![forks](https://img.shields.io/github/forks/Quaerendir/cve-2026-99312-audit.svg)


## CVE-2026-98432
will be addressed in a separate patch.

- [https://github.com/0xBlackash/CVE-2026-98432](https://github.com/0xBlackash/CVE-2026-98432) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-98432.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-98432.svg)


## CVE-2026-98260
[ tglx: Move the cleanup right after de_thread() ]

- [https://github.com/okk30721-cell/cve-2026-98260-ksu](https://github.com/okk30721-cell/cve-2026-98260-ksu) :  ![starts](https://img.shields.io/github/stars/okk30721-cell/cve-2026-98260-ksu.svg) ![forks](https://img.shields.io/github/forks/okk30721-cell/cve-2026-98260-ksu.svg)
- [https://github.com/mumaosong/cve-2026-98260-app](https://github.com/mumaosong/cve-2026-98260-app) :  ![starts](https://img.shields.io/github/stars/mumaosong/cve-2026-98260-app.svg) ![forks](https://img.shields.io/github/forks/mumaosong/cve-2026-98260-app.svg)
- [https://github.com/pjnssb/CVE-2026-98260-GhostKey](https://github.com/pjnssb/CVE-2026-98260-GhostKey) :  ![starts](https://img.shields.io/github/stars/pjnssb/CVE-2026-98260-GhostKey.svg) ![forks](https://img.shields.io/github/forks/pjnssb/CVE-2026-98260-GhostKey.svg)


## CVE-2026-97798
 Improper neutralization of argument delimiters in a command ('argument injection') in Windows Error Reporting allows an authorized attacker to elevate privileges locally.

- [https://github.com/0xBlackash/CVE-2026-97798](https://github.com/0xBlackash/CVE-2026-97798) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-97798.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-97798.svg)


## CVE-2026-97699
 Mistune is a Python Markdown parser with renderers and plugins. Prior to 3.3.4, inline image parsing sends nested ![ openers through precedence_scan because the no_link_before and _label_contains_link linearization guards are gated by not is_image. In src/mistune/inline_parser.py, each outer image opener can therefore search the remaining image body, while max_image_depth does not apply because the failed scans do not produce image tokens. Rendering untrusted Markdown with the default HTML renderer and no plugins can perform quadratic CPU work and keep a worker at 100 percent utilization. This issue is fixed in version 3.3.4.

- [https://github.com/googlesky/CVE-2026-97699](https://github.com/googlesky/CVE-2026-97699) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-97699.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-97699.svg)


## CVE-2026-97698
 Mistune is a Python Markdown parser with renderers and plugins. Prior to 3.3.4, parse_link_href performs an unbounded parenthesis-balancing scan to the end of the document for each unmatched opening parenthesis reached through an empty [] link label. In src/mistune/helpers.py and src/mistune/inline_parser.py, the empty label bypasses no_close_bracket_before, and no_link_before advances only past the short label, so successive [] ( candidates repeatedly scan the remaining document. Rendering untrusted Markdown with the default HTML renderer and no plugins can perform quadratic CPU work and keep a worker at 100 percent utilization. This issue is fixed in version 3.3.4.

- [https://github.com/googlesky/CVE-2026-97698](https://github.com/googlesky/CVE-2026-97698) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-97698.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-97698.svg)


## CVE-2026-93485
 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Automattic WordPress wordpress allows DOM-Based XSS.This issue affects WordPress: from n/a through 7.1.

- [https://github.com/0xBlackash/CVE-2026-93485](https://github.com/0xBlackash/CVE-2026-93485) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-93485.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-93485.svg)


## CVE-2026-86950
 An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in iOS 18.7.11 and iPadOS 18.7.11, iOS 26.7.1 and iPadOS 26.7.1, macOS Sequoia 15.8.1, macOS Tahoe 26.7.1. Processing a maliciously crafted file may lead to arbitrary code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 27.

- [https://github.com/0xBlackash/CVE-2026-86950](https://github.com/0xBlackash/CVE-2026-86950) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-86950.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-86950.svg)


## CVE-2026-83844
 Out-of-bounds read in Windows Paint allows an unauthorized attacker to execute code locally.

- [https://github.com/0xBlackash/CVE-2026-83844](https://github.com/0xBlackash/CVE-2026-83844) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-83844.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-83844.svg)


## CVE-2026-81000
other allocation paths.

- [https://github.com/0xBlackash/CVE-2026-81000](https://github.com/0xBlackash/CVE-2026-81000) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-81000.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-81000.svg)


## CVE-2026-80844
errors to the existing AH6 input and output error paths.

- [https://github.com/0xBlackash/CVE-2026-80844](https://github.com/0xBlackash/CVE-2026-80844) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-80844.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-80844.svg)


## CVE-2026-76466
Note: Cisco Expressway Series refers to Cisco Expressway Core (Expressway-C) devices and Cisco Expressway Edge (Expressway-E) devices.

- [https://github.com/foxcornlab/cisco-expressway-scanner](https://github.com/foxcornlab/cisco-expressway-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/cisco-expressway-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/cisco-expressway-scanner.svg)


## CVE-2026-76461
This vulnerability is due to insufficient validation in the email parsing logic. An attacker could exploit this vulnerability by sending a crafted email message that contains malicious SQL statements through an affected device. A successful exploit could allow the attacker to execute arbitrary SQL statements, leading to command execution with root privileges on the underlying operating system.

- [https://github.com/0xBlackash/CVE-2026-76461](https://github.com/0xBlackash/CVE-2026-76461) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-76461.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-76461.svg)


## CVE-2026-74469
to return its existing transport at the limit.

- [https://github.com/0xBlackash/CVE-2026-74469](https://github.com/0xBlackash/CVE-2026-74469) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-74469.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-74469.svg)


## CVE-2026-73570
 A remote code execution vulnerability exists in Zimbra Collaboration (ZCS) before 10.1.20 when the optional zimbra-snmp package is installed and SNMP notifications are enabled. Due to improper sanitization of untrusted input during SNMP notification processing, an unauthenticated attacker can send specially crafted SMTP requests that may result in execution of arbitrary operating system commands as the Zimbra user.

- [https://github.com/0xBlackash/CVE-2026-73570](https://github.com/0xBlackash/CVE-2026-73570) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-73570.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-73570.svg)


## CVE-2026-73296
 Microsoft UFO open-source framework for intelligent automation across devices and platforms. Prior to 3.0.8, create_mobile_data_collection_server and create_mobile_action_server in ufo/client/mcp/http_servers/mobile_mcp_server.py exposed Streamable HTTP MCP services on TCP ports 8020 and 8021 without authentication, allowing an unauthenticated remote attacker to invoke capture_screenshot, get_ui_tree, tap, swipe, type_text, launch_app, press_key, and click_control against an ADB-connected Android device, disclose screen and device data, and modify device state. This issue is fixed in version 3.0.8.

- [https://github.com/0xBlackash/CVE-2026-73296](https://github.com/0xBlackash/CVE-2026-73296) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-73296.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-73296.svg)


## CVE-2026-72898
 Metabase allows a remote, unauthenticated attacker to inject arbitrary SQL via the '/reset_password' database endpoint and gain administrator access to the connected Metabase instance.

- [https://github.com/0xBlackash/CVE-2026-72898](https://github.com/0xBlackash/CVE-2026-72898) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-72898.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-72898.svg)


## CVE-2026-72018
check before the memcpy to reject such requests with -EINVAL.

- [https://github.com/0xBlackash/CVE-2026-72018](https://github.com/0xBlackash/CVE-2026-72018) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-72018.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-72018.svg)


## CVE-2026-69451
 Use after free in Windows Management Instrumentation allows an authorized attacker to elevate privileges over a network.

- [https://github.com/CreeperMPG/PasswordToolCVE](https://github.com/CreeperMPG/PasswordToolCVE) :  ![starts](https://img.shields.io/github/stars/CreeperMPG/PasswordToolCVE.svg) ![forks](https://img.shields.io/github/forks/CreeperMPG/PasswordToolCVE.svg)


## CVE-2026-68387
[mkl: use Closes tag instead of Link]

- [https://github.com/cybuildguild/CVE-2026-68387](https://github.com/cybuildguild/CVE-2026-68387) :  ![starts](https://img.shields.io/github/stars/cybuildguild/CVE-2026-68387.svg) ![forks](https://img.shields.io/github/forks/cybuildguild/CVE-2026-68387.svg)


## CVE-2026-68121
relocates the head.

- [https://github.com/0xBlackash/CVE-2026-68121](https://github.com/0xBlackash/CVE-2026-68121) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-68121.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-68121.svg)


## CVE-2026-66066
 Action Pack is a framework for handling and responding to web requests. In versions prior to 7.2.3.2, 8.0.5.1 and 8.1.3.1, Active Storage does not disable libvips operations marked unsafe for untrusted content, allowing a crafted upload to invoke such an operation. Consuming applications are affected when configured to use libvips and accept image uploads from untrusted users. An unauthenticated attacker may exploit this behavior to read arbitrary files accessible to the Rails process, including environment variables and application secrets. Exposure of credentials such as secret_key_base or external-service tokens may enable remote code execution or lateral movement. This issue has been fixed in versions 7.2.3.2, 8.0.5.1 and 8.1.3.1.

- [https://github.com/0xBlackash/CVE-2026-66066](https://github.com/0xBlackash/CVE-2026-66066) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-66066.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-66066.svg)


## CVE-2026-64638
Discovered and responsibly disclosed by [the team at pwn.ai](https://pwn.ai/).

- [https://github.com/0xBlackash/CVE-2026-64638](https://github.com/0xBlackash/CVE-2026-64638) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-64638.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-64638.svg)


## CVE-2026-64600
sequence counter changes across the ILOCK cycle.

- [https://github.com/0xBlackash/CVE-2026-64600](https://github.com/0xBlackash/CVE-2026-64600) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-64600.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-64600.svg)


## CVE-2026-64531
ownership and truncates on close failure.

- [https://github.com/0xBlackash/CVE-2026-64531](https://github.com/0xBlackash/CVE-2026-64531) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-64531.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-64531.svg)


## CVE-2026-63292
Users are recommended to upgrade to version 2.4.69, which fixes this issue.

- [https://github.com/0xBlackash/CVE-2026-63292](https://github.com/0xBlackash/CVE-2026-63292) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-63292.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-63292.svg)


## CVE-2026-63072
modules are affected by this CVE.

- [https://github.com/0xBlackash/CVE-2026-63072](https://github.com/0xBlackash/CVE-2026-63072) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-63072.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-63072.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/0xBlackash/CVE-2026-63030](https://github.com/0xBlackash/CVE-2026-63030) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-63030.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-63030.svg)


## CVE-2026-60206
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core).  Supported versions that are affected are 12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0 and  15.1.1.0.0. Easily exploitable vulnerability allows low privileged attacker with network access via SAML to compromise Oracle WebLogic Server.  While the vulnerability is in Oracle WebLogic Server, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.9 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H).

- [https://github.com/0xBlackash/CVE-2026-60206](https://github.com/0xBlackash/CVE-2026-60206) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-60206.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-60206.svg)


## CVE-2026-60004
 Gitea before 1.27.1 allows remote code execution via the diffpatch API through Git hook installation.

- [https://github.com/0xBlackash/CVE-2026-60004](https://github.com/0xBlackash/CVE-2026-60004) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-60004.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-60004.svg)


## CVE-2026-59924
 Mistune is a Python Markdown parser with renderers and plugins. Prior to 3.3.0, Include.parse() joins and normalizes user-supplied include paths without verifying that the result remains within the intended markdown directory, allowing crafted include paths to access files outside that directory when markdown files are processed using md.read(). This issue is fixed in version 3.3.0.

- [https://github.com/0x5t4l1n/CVE-2026-59924](https://github.com/0x5t4l1n/CVE-2026-59924) :  ![starts](https://img.shields.io/github/stars/0x5t4l1n/CVE-2026-59924.svg) ![forks](https://img.shields.io/github/forks/0x5t4l1n/CVE-2026-59924.svg)


## CVE-2026-58210
 NATS Server is a high-performance server for NATS.io, the cloud and edge native messaging system. Prior to 2.14.3 and 2.12.12, an unauthenticated MQTT client could cause the server to retain large incomplete MQTT CONNECT packets before authentication completed, consuming server memory while the parser waited for the advertised MQTT packet length. This issue is fixed in versions 2.14.3 and 2.12.12.

- [https://github.com/googlesky/CVE-2026-58210](https://github.com/googlesky/CVE-2026-58210) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-58210.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-58210.svg)


## CVE-2026-58209
 NATS Server is a high-performance server for NATS.io, the cloud and edge native messaging system. Prior to 2.14.3 and 2.12.12, MQTT retained message delivery and QoS1+ durable replay could deliver messages whose original topics matched a subscriber configured subscribe deny rule because these delivery paths did not consistently recheck the concrete original topic before sending the MQTT PUBLISH to the subscriber. This issue is fixed in versions 2.14.3 and 2.12.12.

- [https://github.com/googlesky/CVE-2026-58209](https://github.com/googlesky/CVE-2026-58209) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-58209.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-58209.svg)


## CVE-2026-58208
 NATS Server is a high-performance server for NATS.io, the cloud and edge native messaging system. Prior to 2.14.3 and 2.12.12, a WebSocket listener could route requests for the MQTT-over-WebSocket path into MQTT handling even when MQTT was not configured, allowing an unauthenticated client with access to the WebSocket listener to reach uninitialized MQTT state and crash the server process. This issue is fixed in versions 2.14.3 and 2.12.12.

- [https://github.com/googlesky/CVE-2026-58208](https://github.com/googlesky/CVE-2026-58208) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-58208.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-58208.svg)


## CVE-2026-58138
 Orkes Conductor 3.21.21 before 3.30.2 contains an unauthenticated remote code execution vulnerability that allows remote attackers to execute arbitrary OS commands by submitting inline workflow definitions containing malicious JavaScript or Python expressions to the workflow API endpoint prior to authentication. Attackers can exploit unsandboxed GraalVM evaluators configured with HostAccess.ALL or allowAllAccess(true) through INLINE, LAMBDA, DO_WHILE, and SWITCH task types to invoke arbitrary system commands via Java reflection or direct subprocess calls.

- [https://github.com/0xBlackash/CVE-2026-58138](https://github.com/0xBlackash/CVE-2026-58138) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-58138.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-58138.svg)


## CVE-2026-55450
 Langflow is a tool for building and deploying AI-powered agents and workflows. Prior to 1.9.1, unauthenticated users can upload any amount of data to the server without any limitations. No need for any prior knowledge, only network access to Langflow. This can lead to space exhaustion on the server. In addition, in the response, the absolute path of the uploaded file is reported to the attacker, which is an information leak that can assist in chaining other primitives. This vulnerability is fixed in 1.9.1.

- [https://github.com/0xBlackash/CVE-2026-55450](https://github.com/0xBlackash/CVE-2026-55450) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-55450.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-55450.svg)


## CVE-2026-55200
 libssh2 1.11.1, fixed in commit 97acf3d, contains an out-of-bounds write vulnerability in ssh2_transport_read() that fails to enforce upper bounds on packet_length field. Remote attackers can send crafted SSH packets with excessively large packet_length values to corrupt heap memory and achieve remote code execution.

- [https://github.com/0xBlackash/CVE-2026-55200](https://github.com/0xBlackash/CVE-2026-55200) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-55200.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-55200.svg)


## CVE-2026-55062
 uniget is a universal installer and updater for (container) tools. Prior to 0.27.6, the hooks edit command in cmd/uniget/hooks.go concatenates an unvalidated hook filename with the selected hooks directory, allowing parent-directory components to escape that directory. The resulting path is passed to the configured editor, which can access or modify files outside the hooks directory with the privileges of the uniget process account. This issue is fixed in version 0.27.6.

- [https://github.com/0x5t4l1n/CVE-2026-55062](https://github.com/0x5t4l1n/CVE-2026-55062) :  ![starts](https://img.shields.io/github/stars/0x5t4l1n/CVE-2026-55062.svg) ![forks](https://img.shields.io/github/forks/0x5t4l1n/CVE-2026-55062.svg)


## CVE-2026-55061
 uniget is a universal installer and updater for (container) tools. Prior to 0.27.6, the hooks edit command in cmd/uniget/hooks.go parses UNIGET_EDITOR or EDITOR with strings.Split(editor, " ") and passes every space-delimited suffix as an argument to the selected editor executable. An attacker who can influence the editor environment and cause hook editing can supply unexpected editor arguments, potentially causing unintended actions with the privileges of the uniget process account. Go os/exec does not evaluate shell operators in these arguments, so the advisory's wrapper demonstration establishes argument delivery but does not establish shell command interpretation. This issue is fixed in version 0.27.6.

- [https://github.com/0x5t4l1n/CVE-2026-55061](https://github.com/0x5t4l1n/CVE-2026-55061) :  ![starts](https://img.shields.io/github/stars/0x5t4l1n/CVE-2026-55061.svg) ![forks](https://img.shields.io/github/forks/0x5t4l1n/CVE-2026-55061.svg)


## CVE-2026-54121
 Improper authorization in Active Directory Certificate Services (AD CS) allows an authorized attacker to elevate privileges over a network.

- [https://github.com/0xBlackash/CVE-2026-54121](https://github.com/0xBlackash/CVE-2026-54121) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-54121.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-54121.svg)


## CVE-2026-53921
 odhcpd is the DHCPv6, DHCPv4, and router-advertisement server used by OpenWrt. Prior to version 25.12, odhcpd's DHCPv6 IA response handler writes past the end of a fixed 512-byte stack buffer (pdbuf) when a single DHCPv6 REQUEST carries enough IA options to nearly exhaust the reply space. Two independent overflow sites exist in the same call chain, both reachable from the network via a single unauthenticated UDP packet. odhcpd runs as root on OpenWrt; embedded targets often lack stack canaries and ASLR, making code execution realistic. This issue has been patched in version 25.12.

- [https://github.com/0xBlackash/CVE-2026-53921](https://github.com/0xBlackash/CVE-2026-53921) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-53921.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-53921.svg)


## CVE-2026-53359
use-after-free.

- [https://github.com/0xBlackash/CVE-2026-53359](https://github.com/0xBlackash/CVE-2026-53359) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-53359.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-53359.svg)


## CVE-2026-50751
 A logic flow weakness in Remote Access and Mobile Access certificate validation in deprecated IKEv1 key exchange allows an unauthenticated remote attacker to bypass user authentication and establish a remote access VPN connection without a valid user password.

- [https://github.com/0xBlackash/CVE-2026-50751](https://github.com/0xBlackash/CVE-2026-50751) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-50751.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-50751.svg)


## CVE-2026-50656
 Microsoft is aware of an elevation of privilege in the Microsoft Malware Protection Engine in Microsoft Defender publicly referred to as &quot;RoguePlanet &quot;.

- [https://github.com/0xBlackash/CVE-2026-50656](https://github.com/0xBlackash/CVE-2026-50656) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-50656.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-50656.svg)


## CVE-2026-48908
 A vulnerability in SP Page Builder for Joomla allows unauthenticated users to upload arbitrary files, ultimately resulting in the upload and execution of PHP code.

- [https://github.com/0xBlackash/CVE-2026-48908](https://github.com/0xBlackash/CVE-2026-48908) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-48908.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-48908.svg)


## CVE-2026-48907
 A vulnerability in the JCE editor extension for Joomla allows the creation of new editor profiles for unauthenticated users, ultimately resulting in PHP code upload and execution.

- [https://github.com/0xBlackash/CVE-2026-48907](https://github.com/0xBlackash/CVE-2026-48907) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-48907.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-48907.svg)


## CVE-2026-47884
Spring Framework 5.2.25.RELEASE and earlier

- [https://github.com/AabyssZG/SpringBoot-Scan](https://github.com/AabyssZG/SpringBoot-Scan) :  ![starts](https://img.shields.io/github/stars/AabyssZG/SpringBoot-Scan.svg) ![forks](https://img.shields.io/github/forks/AabyssZG/SpringBoot-Scan.svg)


## CVE-2026-47729
 Squid is a caching proxy for the Web. Prior to 7.6, due to an improper validation of syntactic correctness of input in the FTP gateway (src/clients/FtpGateway.cc), Squid is vulnerable to an out-of-bounds read: when a listing entry date in the TypeA or TypeB directory-listing formats is not followed by a filename, parsing was not restricted to the input buffer, so a trusted client accessing a misbehaving FTP server through Squid's gateway feature could read memory from random unrelated transactions. This issue is fixed in version 7.6.

- [https://github.com/0xBlackash/CVE-2026-47729](https://github.com/0xBlackash/CVE-2026-47729) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-47729.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-47729.svg)


## CVE-2026-46817
 Vulnerability in the Oracle Payments product of Oracle E-Business Suite (component: File Transmission).  Supported versions that are affected are 12.2.3-12.2.15. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Payments.  Successful attacks of this vulnerability can result in takeover of Oracle Payments. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/0xBlackash/CVE-2026-46817](https://github.com/0xBlackash/CVE-2026-46817) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-46817.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-46817.svg)


## CVE-2026-46333
set), and require a proper CAP_SYS_PTRACE capability to override.

- [https://github.com/0xBlackash/CVE-2026-46333](https://github.com/0xBlackash/CVE-2026-46333) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-46333.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-46333.svg)


## CVE-2026-46331
offset_valid() against INT_MIN, where negation is undefined.

- [https://github.com/0xBlackash/CVE-2026-46331](https://github.com/0xBlackash/CVE-2026-46331) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-46331.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-46331.svg)


## CVE-2026-46300
bytes into @to's linear data rather than transferring frag descriptors.

- [https://github.com/0xBlackash/CVE-2026-46300](https://github.com/0xBlackash/CVE-2026-46300) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-46300.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-46300.svg)


## CVE-2026-46243
spnego_cred to request the key.

- [https://github.com/0xBlackash/CVE-2026-46243](https://github.com/0xBlackash/CVE-2026-46243) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-46243.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-46243.svg)


## CVE-2026-46242
READ_ONCE(epi-dying) fast-path bailout stays.

- [https://github.com/0xBlackash/CVE-2026-46242](https://github.com/0xBlackash/CVE-2026-46242) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-46242.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-46242.svg)


## CVE-2026-45829
 A pre-authentication, code injection vulnerability in version 1.0.0 or later of the ChromaDB Python project allows an unauthenticated attacker to run arbitrary code on the server by sending a malicious model repository and trust_remote_code set to true in the /api/v2/tenants/{tenant}/databases/{db}/collections endpoint.

- [https://github.com/0xBlackash/CVE-2026-45829](https://github.com/0xBlackash/CVE-2026-45829) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-45829.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-45829.svg)


## CVE-2026-45585
No, if you are using TPM+PIN the vulnerability is not exploitable.

- [https://github.com/0xBlackash/CVE-2026-45585](https://github.com/0xBlackash/CVE-2026-45585) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-45585.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-45585.svg)


## CVE-2026-45447
issue, as the affected code is outside the OpenSSL FIPS module boundary.

- [https://github.com/0xBlackash/CVE-2026-45447](https://github.com/0xBlackash/CVE-2026-45447) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-45447.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-45447.svg)


## CVE-2026-45152
 uniget is a universal installer and updater for (container) tools. Prior to 0.27.1, a command injection vulnerability exists in uniget due to unsafe execution of the check field from metadata files using /bin/bash -c. Because the check field is loaded directly from untrusted JSON metadata without validation or sanitization, an attacker can craft malicious metadata that executes arbitrary shell commands on the victim’s system when common uniget operations such as describe, install, update, or inspect are performed. This vulnerability can lead to arbitrary code execution with the privileges of the user running uniget. This vulnerability is fixed in 0.27.1.

- [https://github.com/0x5t4l1n/CVE-2026-45152](https://github.com/0x5t4l1n/CVE-2026-45152) :  ![starts](https://img.shields.io/github/stars/0x5t4l1n/CVE-2026-45152.svg) ![forks](https://img.shields.io/github/forks/0x5t4l1n/CVE-2026-45152.svg)


## CVE-2026-44578
 Next.js is a React framework for building full-stack web applications. From 13.4.13 to before 15.5.16 and 16.2.5, self-hosted applications using the built-in Node.js server can be vulnerable to server-side request forgery through crafted WebSocket upgrade requests. An attacker can cause the server to proxy requests to arbitrary internal or external destinations, which may expose internal services or cloud metadata endpoints. Vercel-hosted deployments are not affected. This vulnerability is fixed in 15.5.16 and 16.2.5.

- [https://github.com/0xBlackash/CVE-2026-44578](https://github.com/0xBlackash/CVE-2026-44578) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-44578.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-44578.svg)


## CVE-2026-44277
 A improper access control vulnerability in Fortinet FortiAuthenticator 8.0.2, FortiAuthenticator 8.0.0, FortiAuthenticator 6.6.0 through 6.6.8, FortiAuthenticator 6.5.0 through 6.5.6, FortiAuthenticator 6.4.0 through 6.4.10 may allow attacker to execute unauthorized code or commands via crafted requests.

- [https://github.com/0xBlackash/CVE-2026-44277](https://github.com/0xBlackash/CVE-2026-44277) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-44277.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-44277.svg)


## CVE-2026-43786
 This issue was addressed with additional entitlement checks. This issue is fixed in macOS Golden Gate 27, macOS Sequoia 15.8, macOS Tahoe 26.7. An app may be able to gain root privileges.

- [https://github.com/0xBlackash/CVE-2026-43786](https://github.com/0xBlackash/CVE-2026-43786) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-43786.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-43786.svg)


## CVE-2026-43503
so segments drawing frags from frag_list members carry the marker.

- [https://github.com/0xBlackash/CVE-2026-43503](https://github.com/0xBlackash/CVE-2026-43503) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-43503.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-43503.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/0xBlackash/CVE-2026-43499](https://github.com/0xBlackash/CVE-2026-43499) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-43499.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-43499.svg)
- [https://github.com/YUE546/IQOO-neo7-ghostlock-43499](https://github.com/YUE546/IQOO-neo7-ghostlock-43499) :  ![starts](https://img.shields.io/github/stars/YUE546/IQOO-neo7-ghostlock-43499.svg) ![forks](https://img.shields.io/github/forks/YUE546/IQOO-neo7-ghostlock-43499.svg)


## CVE-2026-43494
rds_message_zcopy_from_user().

- [https://github.com/0xBlackash/CVE-2026-43494](https://github.com/0xBlackash/CVE-2026-43494) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-43494.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-43494.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/0xBlackash/CVE-2026-43284](https://github.com/0xBlackash/CVE-2026-43284) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-43284.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-43284.svg)


## CVE-2026-42945
 NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module. This vulnerability exists when the rewrite directive is followed by a rewrite, if, or set directive and an unnamed Perl-Compatible Regular Expression (PCRE) capture (for example, $1, $2) with a replacement string that includes a question mark (?). An unauthenticated attacker along with conditions beyond its control can exploit this vulnerability by sending crafted HTTP requests. This may cause a heap buffer overflow in the NGINX worker process leading to a restart. Additionally, attackers can execute code on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/0xBlackash/CVE-2026-42945](https://github.com/0xBlackash/CVE-2026-42945) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-42945.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-42945.svg)


## CVE-2026-42569
 phpVMS is a PHP application to run and simulate an airline. Prior to version 7.0.6, a critical vulnerability in phpVMS allowed unauthenticated access to a legacy import feature. This issue has been patched in version 7.0.6.

- [https://github.com/0xBlackash/CVE-2026-42569](https://github.com/0xBlackash/CVE-2026-42569) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-42569.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-42569.svg)


## CVE-2026-42530
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/0xBlackash/CVE-2026-42530](https://github.com/0xBlackash/CVE-2026-42530) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-42530.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-42530.svg)


## CVE-2026-42290
 protobufjs-cli is the command line add-on for protobuf.js. Prior to 1.2.1 and 2.0.2, pbts invoked JSDoc by building a shell command string from input file paths and executing it through child_process.exec. File paths containing shell metacharacters could therefore be interpreted by the shell instead of being passed to JSDoc as plain arguments. This vulnerability is fixed in 1.2.1 and 2.0.2.

- [https://github.com/0x5t4l1n/CVE-2026-42290](https://github.com/0x5t4l1n/CVE-2026-42290) :  ![starts](https://img.shields.io/github/stars/0x5t4l1n/CVE-2026-42290.svg) ![forks](https://img.shields.io/github/forks/0x5t4l1n/CVE-2026-42290.svg)


## CVE-2026-42208
 LiteLLM is a proxy server (AI Gateway) to call LLM APIs in OpenAI (or native) format. From version 1.81.16 to before version 1.83.7, a database query used during proxy API key checks mixed the caller-supplied key value into the query text instead of passing it as a separate parameter. An unauthenticated attacker could send a specially crafted Authorization header to any LLM API route (for example POST /chat/completions) and reach this query through the proxy's error-handling path. An attacker could read data from the proxy's database and may be able to modify it, leading to unauthorised access to the proxy and the credentials it manages. This issue has been patched in version 1.83.7.

- [https://github.com/0xBlackash/CVE-2026-42208](https://github.com/0xBlackash/CVE-2026-42208) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-42208.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-42208.svg)


## CVE-2026-41940
 cPanel and WHM versions after 11.40 contain an authentication bypass vulnerability in the login flow that allows unauthenticated remote attackers to gain unauthorized access to the control panel.

- [https://github.com/0xBlackash/CVE-2026-41940](https://github.com/0xBlackash/CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-41940.svg)


## CVE-2026-41651
3. Late flag read at execution time (lines 2273–2277): The scheduler's idle callback reads cached_transaction_flags at dispatch time, not at authorization time. If flags were overwritten between authorization and execution, the backend sees the attacker's flags.

- [https://github.com/0xBlackash/CVE-2026-41651](https://github.com/0xBlackash/CVE-2026-41651) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-41651.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-41651.svg)


## CVE-2026-41462
 ProjeQtor versions 7.0 through 12.4.3 contain an unauthenticated SQL injection vulnerability in the login functionality where the login variable is directly concatenated into a SQL query without parameterization or sanitization. Attackers can inject arbitrary SQL expressions through the username field at the authentication endpoint to create privileged accounts, read sensitive data, and execute operating system commands if the database user has elevated permissions.

- [https://github.com/0xBlackash/CVE-2026-41462](https://github.com/0xBlackash/CVE-2026-41462) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-41462.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-41462.svg)


## CVE-2026-41091
 Improper link resolution before file access ('link following') in Microsoft Defender allows an authorized attacker to elevate privileges locally.

- [https://github.com/0xBlackash/CVE-2026-41091](https://github.com/0xBlackash/CVE-2026-41091) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-41091.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-41091.svg)


## CVE-2026-41089
 Stack-based buffer overflow in Windows Netlogon allows an unauthorized attacker to execute code over a network.

- [https://github.com/0xBlackash/CVE-2026-41089](https://github.com/0xBlackash/CVE-2026-41089) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-41089.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-41089.svg)


## CVE-2026-41039
Successful exploitation of this vulnerability could allow the attacker to access sensitive information, including internal endpoints, scripts and directories on the targeted device.

- [https://github.com/0x5t4l1n/CVE-2026-41039](https://github.com/0x5t4l1n/CVE-2026-41039) :  ![starts](https://img.shields.io/github/stars/0x5t4l1n/CVE-2026-41039.svg) ![forks](https://img.shields.io/github/forks/0x5t4l1n/CVE-2026-41039.svg)


## CVE-2026-41037
 This vulnerability exists in Quantum Networks router due to missing rate limiting and CAPTCHA protection for failed login attempts in the web-based management interface. An attacker on the same network could exploit this vulnerability by performing brute force attacks against administrative credentials, leading to unauthorized access with root privileges on the targeted device.

- [https://github.com/0x5t4l1n/CVE-2026-41037](https://github.com/0x5t4l1n/CVE-2026-41037) :  ![starts](https://img.shields.io/github/stars/0x5t4l1n/CVE-2026-41037.svg) ![forks](https://img.shields.io/github/forks/0x5t4l1n/CVE-2026-41037.svg)


## CVE-2026-40487
 Postiz is an AI social media scheduling tool. Prior to version 2.21.6, a file upload validation bypass allows any authenticated user to upload arbitrary HTML, SVG, or other executable file types to the server by spoofing the `Content-Type` header. The uploaded files are then served by nginx with a Content-Type derived from their original extension (`text/html`, `image/svg+xml`), enabling Stored Cross-Site Scripting (XSS) in the context of the application's origin. This can lead to session riding, account takeover, and full compromise of other users' accounts. Version 2.21.6 contains a fix.

- [https://github.com/0xBlackash/CVE-2026-42208](https://github.com/0xBlackash/CVE-2026-42208) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-42208.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-42208.svg)


## CVE-2026-40369
 Heap-based buffer overflow in Windows Kernel allows an authorized attacker to elevate privileges locally.

- [https://github.com/0xBlackash/CVE-2026-40369](https://github.com/0xBlackash/CVE-2026-40369) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-40369.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-40369.svg)


## CVE-2026-40175
 Axios is a promise based HTTP client for the browser and Node.js. Versions prior to 1.15.0 and 0.3.1 are vulnerable to a specific gadget-style attack chain in which prototype pollution in a third-party dependency may be leveraged to inject unsanitized header values into outbound requests. This vulnerability is fixed in 1.15.0 and 0.3.1.

- [https://github.com/0xBlackash/CVE-2026-40175](https://github.com/0xBlackash/CVE-2026-40175) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-40175.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-40175.svg)


## CVE-2026-39987
 marimo is a reactive Python notebook. Prior to 0.23.0, Marimo has a Pre-Auth RCE vulnerability. The terminal WebSocket endpoint /terminal/ws lacks authentication validation, allowing an unauthenticated attacker to obtain a full PTY shell and execute arbitrary system commands. Unlike other WebSocket endpoints (e.g., /ws) that correctly call validate_auth() for authentication, the /terminal/ws endpoint only checks the running mode and platform support before accepting connections, completely skipping authentication verification. This vulnerability is fixed in 0.23.0.

- [https://github.com/0xBlackash/CVE-2026-39987](https://github.com/0xBlackash/CVE-2026-39987) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-39987.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-39987.svg)


## CVE-2026-39813
 A path traversal: '../filedir' vulnerability in Fortinet FortiSandbox 5.0.0 through 5.0.5, FortiSandbox 4.4.0 through 4.4.8 may allow attacker to escalation of privilege via specially crafted HTTP requests.

- [https://github.com/0xBlackash/CVE-2026-39813](https://github.com/0xBlackash/CVE-2026-39813) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-39813.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-39813.svg)


## CVE-2026-39808
 A improper neutralization of special elements used in an os command ('os command injection') vulnerability in Fortinet FortiSandbox 4.4.0 through 4.4.8 may allow attacker to execute unauthorized code or commands via insert attack vector here

- [https://github.com/0xBlackash/CVE-2026-39808](https://github.com/0xBlackash/CVE-2026-39808) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-39808.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-39808.svg)


## CVE-2026-35616
 A improper access control vulnerability in Fortinet FortiClientEMS 7.4.5 through 7.4.6 may allow an unauthenticated attacker to execute unauthorized code or commands via crafted requests.

- [https://github.com/0xBlackash/CVE-2026-35616](https://github.com/0xBlackash/CVE-2026-35616) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-35616.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-35616.svg)


## CVE-2026-35273
 Vulnerability in the PeopleSoft Enterprise PeopleTools product of Oracle PeopleSoft (component: Updates Environment Management). Supported versions that are affected are 8.61 and 8.62. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise PeopleSoft Enterprise PeopleTools. Successful attacks of this vulnerability can result in takeover of PeopleSoft Enterprise PeopleTools. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/0xBlackash/CVE-2026-35273](https://github.com/0xBlackash/CVE-2026-35273) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-35273.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-35273.svg)


## CVE-2026-34724
 Zammad is a web based open source helpdesk/customer support system. Prior to 7.0.1, a server-side template injection vulnerability  which leads to RCE via AI Agent exists. Impact is limited to environments where an attacker can control or influence type_enrichment_data (typically high-privilege administrative configuration). This vulnerability is fixed in 7.0.1.

- [https://github.com/0xBlackash/CVE-2026-34724](https://github.com/0xBlackash/CVE-2026-34724) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-34724.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-34724.svg)


## CVE-2026-34197
Users are recommended to upgrade to version 5.19.4 or 6.2.3, which fixes the issue

- [https://github.com/0xBlackash/CVE-2026-34197](https://github.com/0xBlackash/CVE-2026-34197) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-34197.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-34197.svg)


## CVE-2026-34156
 NocoBase is an AI-powered no-code/low-code platform for building business applications and enterprise solutions. Prior to version 2.0.28, NocoBase's Workflow Script Node executes user-supplied JavaScript inside a Node.js vm sandbox with a custom require allowlist (controlled by WORKFLOW_SCRIPT_MODULES env var). However, the console object passed into the sandbox context exposes host-realm WritableWorkerStdio stream objects via console._stdout and console._stderr. An authenticated attacker can traverse the prototype chain to escape the sandbox and achieve Remote Code Execution as root. This issue has been patched in version 2.0.28.

- [https://github.com/0xBlackash/CVE-2026-34156](https://github.com/0xBlackash/CVE-2026-34156) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-34156.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-34156.svg)


## CVE-2026-33825
 Insufficient granularity of access control in Microsoft Defender allows an authorized attacker to elevate privileges locally.

- [https://github.com/0xBlackash/CVE-2026-33825](https://github.com/0xBlackash/CVE-2026-33825) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-33825.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-33825.svg)


## CVE-2026-33017
 Langflow is a tool for building and deploying AI-powered agents and workflows. In versions prior to 1.9.0, the POST /api/v1/build_public_tmp/{flow_id}/flow endpoint allows building public flows without requiring authentication. When the optional data parameter is supplied, the endpoint uses attacker-controlled flow data (containing arbitrary Python code in node definitions) instead of the stored flow data from the database. This code is passed to exec() with zero sandboxing, resulting in unauthenticated remote code execution. This is distinct from CVE-2025-3248, which fixed /api/v1/validate/code by adding authentication. The build_public_tmp endpoint is designed to be unauthenticated (for public flows) but incorrectly accepts attacker-supplied flow data containing arbitrary executable code. This issue has been fixed in version 1.9.0.

- [https://github.com/0xBlackash/CVE-2026-33017](https://github.com/0xBlackash/CVE-2026-33017) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-33017.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-33017.svg)


## CVE-2026-32475
This issue affects Elementor Pro: from n/a through 4.2.1.

- [https://github.com/0xBlackash/CVE-2026-32475](https://github.com/0xBlackash/CVE-2026-32475) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-32475.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-32475.svg)


## CVE-2026-31635
Reject authenticator lengths that exceed the remaining packet payload.

- [https://github.com/0xBlackash/CVE-2026-31635](https://github.com/0xBlackash/CVE-2026-31635) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-31635.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-31635.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/0xBlackash/CVE-2026-31431](https://github.com/0xBlackash/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-31431.svg)
- [https://github.com/JnamerZ/CopyFail-CVE-2026-31431](https://github.com/JnamerZ/CopyFail-CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/JnamerZ/CopyFail-CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/JnamerZ/CopyFail-CVE-2026-31431.svg)


## CVE-2026-31402
correct response on the original request.

- [https://github.com/0xBlackash/CVE-2026-31402](https://github.com/0xBlackash/CVE-2026-31402) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-31402.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-31402.svg)


## CVE-2026-29905
 Kirby CMS through 5.1.4 allows an authenticated user with 'Editor' permissions to cause a persistent Denial of Service (DoS) via a malformed image upload. The application fails to properly validate the return value of the PHP getimagesize() function. When the system attempts to process this file for metadata or thumbnail generation, it triggers a fatal TypeError.

- [https://github.com/0x5t4l1n/CVE-2026-29905](https://github.com/0x5t4l1n/CVE-2026-29905) :  ![starts](https://img.shields.io/github/stars/0x5t4l1n/CVE-2026-29905.svg) ![forks](https://img.shields.io/github/forks/0x5t4l1n/CVE-2026-29905.svg)


## CVE-2026-28289
 FreeScout is a free help desk and shared inbox built with PHP's Laravel framework. A patch bypass vulnerability for CVE-2026-27636 in FreeScout 1.8.206 and earlier allows any authenticated user with file upload permissions to achieve Remote Code Execution (RCE) on the server by uploading a malicious .htaccess file using a zero-width space character prefix to bypass the security check. The vulnerability exists in the sanitizeUploadedFileName() function in app/Http/Helper.php. The function contains a Time-of-Check to Time-of-Use (TOCTOU) flaw where the dot-prefix check occurs before sanitization removes invisible characters. This vulnerability is fixed in 1.8.207.

- [https://github.com/0xBlackash/CVE-2026-28289](https://github.com/0xBlackash/CVE-2026-28289) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-28289.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-28289.svg)


## CVE-2026-27876
- 12.4.0 (inclusive) to 12.4.2 (exclusive): 12.4.2 has the fix. 13.0.0 and above also have the fix: no v13 release is affected.

- [https://github.com/0xBlackash/CVE-2026-27876](https://github.com/0xBlackash/CVE-2026-27876) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-27876.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-27876.svg)


## CVE-2026-25769
 Wazuh is a free and open source platform used for threat prevention, detection, and response. Versions 4.0.0 through 4.14.2 have a Remote Code Execution (RCE) vulnerability due to Deserialization of Untrusted Data). All Wazuh deployments using cluster mode (master/worker architecture) and any organization with a compromised worker node (e.g., through initial access, insider threat, or supply chain attack) are impacted. An attacker who gains access to a worker node (through any means) can achieve full RCE on the master node with root privileges. Version 4.14.3 fixes the issue.

- [https://github.com/0xBlackash/CVE-2026-25769](https://github.com/0xBlackash/CVE-2026-25769) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-25769.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-25769.svg)


## CVE-2026-25089
 A improper neutralization of special elements used in an os command ('os command injection') vulnerability in Fortinet FortiSandbox 5.0.0 through 5.0.5, FortiSandbox 4.4.0 through 4.4.8, FortiSandbox 4.2 all versions, FortiSandbox Cloud 5.0.4 through 5.0.5, FortiSandbox PaaS 5.0.4 through 5.0.5 may allow an unauthenticated attacker to execute unauthorized commands via specifically crafted HTTP requests

- [https://github.com/0xBlackash/CVE-2026-25089](https://github.com/0xBlackash/CVE-2026-25089) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-25089.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-25089.svg)


## CVE-2026-25049
 n8n is an open source workflow automation platform. Prior to versions 1.123.17 and 2.5.2, an authenticated user with permission to create or modify workflows could abuse crafted expressions in workflow parameters to trigger unintended system command execution on the host running n8n. This issue has been patched in versions 1.123.17 and 2.5.2.

- [https://github.com/0xBlackash/CVE-2026-25049](https://github.com/0xBlackash/CVE-2026-25049) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-25049.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-25049.svg)


## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.

- [https://github.com/0xBlackash/CVE-2026-24061](https://github.com/0xBlackash/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-24061.svg)


## CVE-2026-23111
skip active elements, process inactive ones.

- [https://github.com/0xBlackash/CVE-2026-23111](https://github.com/0xBlackash/CVE-2026-23111) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-23111.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-23111.svg)


## CVE-2026-22812
 OpenCode is an open source AI coding agent. Prior to 1.0.216, OpenCode automatically starts an unauthenticated HTTP server that allows any local process (or any website via permissive CORS) to execute arbitrary shell commands with the user's privileges. This vulnerability is fixed in 1.0.216.

- [https://github.com/0xBlackash/CVE-2026-22812](https://github.com/0xBlackash/CVE-2026-22812) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-22812.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-22812.svg)


## CVE-2026-22557
 A malicious actor with access to the network could exploit a Path Traversal vulnerability found in the UniFi Network Application to access files on the underlying system that could be manipulated to access an underlying account.

- [https://github.com/0xBlackash/CVE-2026-22557](https://github.com/0xBlackash/CVE-2026-22557) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-22557.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-22557.svg)


## CVE-2026-22241
 The Open eClass platform (formerly known as GUnet eClass) is a complete course management system. Prior to version 4.2, an arbitrary file upload vulnerability in the theme import functionality enables an attacker with administrative privileges to upload arbitrary files on the server's file system. The main cause of the issue is that no validation or sanitization of the file's present inside the zip archive. This leads to remote code execution on the web server. Version 4.2 patches the issue.

- [https://github.com/0xBlackash/CVE-2026-22241](https://github.com/0xBlackash/CVE-2026-22241) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-22241.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-22241.svg)


## CVE-2026-21962
 Vulnerability in the Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in product of Oracle Fusion Middleware (component: Weblogic Server Proxy Plug-in for Apache HTTP Server, Weblogic Server Proxy Plug-in for IIS).  Supported versions that are affected are 12.2.1.4.0, 14.1.1.0.0 and  14.1.2.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in.  While the vulnerability is in Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in accessible data as well as  unauthorized access to critical data or complete access to all Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in accessible data. Note: Affected version for Weblogic Server Proxy Plug-in for IIS is 12.2.1.4.0 only. CVSS 3.1 Base Score 10.0 (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N).

- [https://github.com/0xBlackash/CVE-2026-21962](https://github.com/0xBlackash/CVE-2026-21962) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-21962.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-21962.svg)


## CVE-2026-21858
 n8n is an open source workflow automation platform. Versions starting with 1.65.0 and below 1.121.0 enable an attacker to access files on the underlying server through execution of certain form-based workflows. A vulnerable workflow could grant access to an unauthenticated remote attacker, resulting in exposure of sensitive information stored on the system and may enable further compromise depending on deployment configuration and workflow usage. This issue is fixed in version 1.121.0.

- [https://github.com/0xBlackash/CVE-2026-21858](https://github.com/0xBlackash/CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-21858.svg)


## CVE-2026-21643
 An improper neutralization of special elements used in an sql command ('sql injection') vulnerability in Fortinet FortiClientEMS 7.4.4 may allow an unauthenticated attacker to execute unauthorized code or commands via specifically crafted HTTP requests.

- [https://github.com/0xBlackash/CVE-2026-21643](https://github.com/0xBlackash/CVE-2026-21643) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-21643.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-21643.svg)


## CVE-2026-21589
 This is a vulnerability in Bitbucket Data Center, Confluence Data Center, Jira Service Management Data Center, Jira Software Data Center, Bamboo Data Center. Crowd Data Center, Crucible and Fisheye. This Arbitrary File Access vulnerability allows an unauthenticated attacker to access specific files within the web application root directory in affected versions. Exploitation requires prior knowledge of the target file's exact name and path; this vulnerability does not allow attackers to enumerate or list directory contents. In some configurations, there may be some sensitive files that make this highly severe. This vulnerability allows an unauthenticated remote attacker to access specific files within the web application root directory in affected versions. The vulnerability must be addressed for affected versions of: -- Bitbucket Data Center, introduced in version = 4.6.0, fix versions: 9.4.26, 10.2.8, 10.5.1 -- Confluence Data Center, introduced in version = 5.10.0, fix versions 9.2.26, 10.2.19 -- Crowd Data Center, introduced in version = 2.11.0, fix versions 6.3.7, 7.0.3, 7.1.7, 7.2.4 -- Jira Software Data Center, introduced in version = 7.1.0, fix versions 9.12.40, 10.3.26, 11.3.12 -- Jira Service Management Data Center, introduced in version = 3.1.0, fix versions 5.12.40, 10.3.26, 11.3.12 -- Bamboo Data Center = 7.0.1, fix versions 10.2.24, 12.1.12 -- Crucible, fix versions 4.9.15 -- Fisheye, fix version 4.9.15 -- Exploitation requires prior knowledge of the target file's exact name and path. The vulnerability does not include the capability to enumerate or list directory contents.

- [https://github.com/0xBlackash/CVE-2026-21589](https://github.com/0xBlackash/CVE-2026-21589) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-21589.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-21589.svg)


## CVE-2026-20841
 Improper neutralization of special elements used in a command ('command injection') in Windows Notepad App allows an unauthorized attacker to execute code locally.

- [https://github.com/0xBlackash/CVE-2026-20841](https://github.com/0xBlackash/CVE-2026-20841) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-20841.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-20841.svg)


## CVE-2026-20253
 In Splunk Enterprise 10.2 versions below 10.2.4 and 10 versions below 10.0.7, an unauthenticated user could create or truncate arbitrary files through a PostgreSQL sidecar service endpoint. The vulnerability exists because the PostgreSQL sidecar service endpoint lacks authentication controls, allowing any network-reachable user to invoke file operations without credentials. Splunk Enterprise versions 9.4 and earlier are not affected. If you cannot immediately upgrade to a fixed version, you can mitigate this vulnerability by disabling the PostgreSQL sidecar service.

- [https://github.com/0xBlackash/CVE-2026-20253](https://github.com/0xBlackash/CVE-2026-20253) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-20253.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-20253.svg)


## CVE-2026-20245
Cisco recommends that customers upgrade to the fixed software that is documented in the  that was published on May 14, 2026, and verify the configuration of the edge devices.

- [https://github.com/0xBlackash/CVE-2026-20245](https://github.com/0xBlackash/CVE-2026-20245) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-20245.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-20245.svg)


## CVE-2026-20131
Note: If the FMC management interface does not have public internet access, the attack surface that is associated with this vulnerability is reduced.

- [https://github.com/0xBlackash/CVE-2026-20131](https://github.com/0xBlackash/CVE-2026-20131) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-20131.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-20131.svg)


## CVE-2026-20127
This vulnerability exists because the peering authentication mechanism in an affected system is not working properly. An attacker could exploit this vulnerability by sending crafted requests to an affected system. A successful exploit could allow the attacker to log in to an affected Cisco Catalyst SD-WAN Controller as an internal, high-privileged, non-root&nbsp;user account. Using this account, the attacker could access NETCONF, which would then allow the attacker to manipulate network configuration for the SD-WAN fabric.&nbsp;

- [https://github.com/0xBlackash/CVE-2026-20127](https://github.com/0xBlackash/CVE-2026-20127) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-20127.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-20127.svg)


## CVE-2026-20079
This vulnerability is due to an improper system process that is created at boot time. An attacker could exploit this vulnerability by sending crafted HTTP requests to an affected device. A successful exploit could allow the attacker to execute a variety of scripts and commands that allow&nbsp;root access to the device.&nbsp;

- [https://github.com/0xBlackash/CVE-2026-20079](https://github.com/0xBlackash/CVE-2026-20079) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-20079.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-20079.svg)


## CVE-2026-19412
Successful exploitation of this vulnerability could allow the attacker to gain unauthorized administrative access and perform privileged operations on the targeted device.

- [https://github.com/0x5t4l1n/CVE-2026-19412](https://github.com/0x5t4l1n/CVE-2026-19412) :  ![starts](https://img.shields.io/github/stars/0x5t4l1n/CVE-2026-19412.svg) ![forks](https://img.shields.io/github/forks/0x5t4l1n/CVE-2026-19412.svg)


## CVE-2026-15409
 A Server-side request forgery (SSRF) vulnerability has been identified in the SMA1000 Appliance Work Place interface. A remote unauthenticated attacker could potentially cause the appliance to make requests to unintended location.

- [https://github.com/0xBlackash/CVE-2026-15409](https://github.com/0xBlackash/CVE-2026-15409) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-15409.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-15409.svg)


## CVE-2026-12485
      memcpy(&reply_buf[36], g_network_config-ip_addr, v3);

- [https://github.com/0xBlackash/CVE-2026-12485](https://github.com/0xBlackash/CVE-2026-12485) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-12485.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-12485.svg)


## CVE-2026-11742
The fix wraps both peek implementations with k_spin_lock/k_spin_unlock on the queue lock, making the read-and-dereference atomic with respect to the concurrent unlink-and-free and bringing peek into line with the rest of the queue's locking discipline.

- [https://github.com/0x5t4l1n/CVE-2026-117425](https://github.com/0x5t4l1n/CVE-2026-117425) :  ![starts](https://img.shields.io/github/stars/0x5t4l1n/CVE-2026-117425.svg) ![forks](https://img.shields.io/github/forks/0x5t4l1n/CVE-2026-117425.svg)


## CVE-2026-11645
 Out of bounds read and write in V8 in Google Chrome prior to 149.0.7827.103 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/0xBlackash/CVE-2026-11645](https://github.com/0xBlackash/CVE-2026-11645) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-11645.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-11645.svg)


## CVE-2026-11499
 A vulnerability was determined in Tenda HG7, HG9 and HG10 300001138_en_xpon. This affects the function formDOMAINBLK of the file /boaform/formDOMAINBLK. Executing a manipulation of the argument blkDomain can lead to stack-based buffer overflow. The attack may be performed from remote.

- [https://github.com/0xBlackash/CVE-2026-11499](https://github.com/0xBlackash/CVE-2026-11499) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-11499.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-11499.svg)


## CVE-2026-10961
 Use after free in Chrome for iOS in Google Chrome on iOS prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/0xBlackash/CVE-2026-109618](https://github.com/0xBlackash/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-109618.svg)
- [https://github.com/Aron-2005/CVE-2026-109618-PoC](https://github.com/Aron-2005/CVE-2026-109618-PoC) :  ![starts](https://img.shields.io/github/stars/Aron-2005/CVE-2026-109618-PoC.svg) ![forks](https://img.shields.io/github/forks/Aron-2005/CVE-2026-109618-PoC.svg)


## CVE-2026-10520
 An OS Command Injection vulnerability in Ivanti Sentry before the R10.5.2, R10.6.2 and R10.7.1 versions allows a remote unauthenticated user to achieve root-level remote code execution

- [https://github.com/0xBlackash/CVE-2026-10520](https://github.com/0xBlackash/CVE-2026-10520) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-10520.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-10520.svg)


## CVE-2026-9506
Successful exploitation of this vulnerability could allow an attacker to read arbitrary sensitive files on the targeted system.

- [https://github.com/0x5t4l1n/CVE-2026-9506](https://github.com/0x5t4l1n/CVE-2026-9506) :  ![starts](https://img.shields.io/github/stars/0x5t4l1n/CVE-2026-9506.svg) ![forks](https://img.shields.io/github/forks/0x5t4l1n/CVE-2026-9506.svg)


## CVE-2026-9082
This issue affects Drupal core: from 8.9.0 before 10.4.10, from 10.5.0 before 10.5.10, from 10.6.0 before 10.6.9, from 11.0.0 before 11.1.10, from 11.2.0 before 11.2.12, from 11.3.0 before 11.3.10.

- [https://github.com/0xBlackash/CVE-2026-9082](https://github.com/0xBlackash/CVE-2026-9082) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-9082.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-9082.svg)


## CVE-2026-8932
the private key.

- [https://github.com/0xBlackash/CVE-2026-8932](https://github.com/0xBlackash/CVE-2026-8932) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-8932.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-8932.svg)


## CVE-2026-8461
This issue affects FFmpeg before version 8.1.2.

- [https://github.com/0xBlackash/CVE-2026-8461](https://github.com/0xBlackash/CVE-2026-8461) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-8461.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-8461.svg)


## CVE-2026-8451
 Insufficient input validation in NetScaler ADC and NetScaler Gateway leading to memory overread if NetScaler ADC or NetScaler Gateway is configured as a SAML IDP

- [https://github.com/0xBlackash/CVE-2026-8451](https://github.com/0xBlackash/CVE-2026-8451) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-8451.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-8451.svg)


## CVE-2026-7574
 Anthropic Claude Desktop Cowork VM image handling (confirmed across v1.1348.0 through v1.2278.0, including v1.1348.0, v1.1617.0, and v1.2278.0) validates only file presence and a version marker string before booting rootfs.img, but does not verify image content integrity at time-of-use. A local attacker with unprivileged code execution as the victim macOS user can modify the VM root filesystem image and have it trusted on subsequent Cowork VM boots, enabling persistent arbitrary code execution in the VM and access to host-mounted directories. The estimated CWE mapping is CWE-353 (Missing Support for Integrity Check).

- [https://github.com/0xBlackash/CVE-2026-7574](https://github.com/0xBlackash/CVE-2026-7574) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-7574.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-7574.svg)


## CVE-2026-6471
 Missing authorization in PostgreSQL logical decoding allows a non-superuser holding REPLICATION privilege to dlopen any file visible to the operating system account running the server, via the choice of logical decoding plugin.  This in turn runs arbitrary code as that account.  Versions before PostgreSQL 18.6, 17.11, 16.15, 15.19, and 14.24 are affected.

- [https://github.com/0xBlackash/CVE-2026-6471](https://github.com/0xBlackash/CVE-2026-6471) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-6471.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-6471.svg)


## CVE-2026-5173
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 16.9.6 before 18.8.9, 18.9 before 18.9.5, and 18.10 before 18.10.3 that could have allowed an authenticated user to invoke unintended server-side methods through websocket connections due to improper access control.

- [https://github.com/0xBlackash/CVE-2026-5173](https://github.com/0xBlackash/CVE-2026-5173) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-5173.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-5173.svg)


## CVE-2026-5027
 The 'POST /api/v2/files' endpoint does not sanitize the 'filename' parameter from the multipart form data, allowing an attacker to write files to arbitrary locations on the filesystem using path traversal sequences ('../').

- [https://github.com/0xBlackash/CVE-2026-5027](https://github.com/0xBlackash/CVE-2026-5027) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-5027.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-5027.svg)


## CVE-2026-4480
substitution character without escaping shell meta characters. A remote attacker could exploit this vulnerability by sending a specially crafted print job description that contains unescaped shell characters. This could lead to remote code execution on the affected system.

- [https://github.com/0xBlackash/CVE-2026-4480](https://github.com/0xBlackash/CVE-2026-4480) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-4480.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-4480.svg)


## CVE-2026-3143
 The Total Upkeep – WordPress Backup Plugin plus Restore & Migrate by BoldGrid plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'wp_ajax_cli_cancel' function in all versions up to, and including, 1.17.1. This makes it possible for unauthenticated attackers to cancel a pending rollback, potentially preventing a WordPress installation from automatically reverting a failed update.

- [https://github.com/erlangparasu/mitigate_cve_2026_31431-sh](https://github.com/erlangparasu/mitigate_cve_2026_31431-sh) :  ![starts](https://img.shields.io/github/stars/erlangparasu/mitigate_cve_2026_31431-sh.svg) ![forks](https://img.shields.io/github/forks/erlangparasu/mitigate_cve_2026_31431-sh.svg)


## CVE-2026-3055
 Insufficient input validation in NetScaler ADC and NetScaler Gateway when configured as a SAML IDP leading to memory overread

- [https://github.com/0xBlackash/CVE-2026-3055](https://github.com/0xBlackash/CVE-2026-3055) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-3055.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-3055.svg)


## CVE-2026-3008
information or crash the application.

- [https://github.com/0x5t4l1n/CVE-2026-30081](https://github.com/0x5t4l1n/CVE-2026-30081) :  ![starts](https://img.shields.io/github/stars/0x5t4l1n/CVE-2026-30081.svg) ![forks](https://img.shields.io/github/forks/0x5t4l1n/CVE-2026-30081.svg)


## CVE-2026-2699
 Customer Managed ShareFile Storage Zones Controller (SZC) allows an unauthenticated attacker to access restricted configuration pages. This leads to changing system configuration and potential remote code execution.

- [https://github.com/0xBlackash/CVE-2026-2699](https://github.com/0xBlackash/CVE-2026-2699) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-2699.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-2699.svg)


## CVE-2026-1357
 The Migration, Backup, Staging – WPvivid Backup & Migration plugin for WordPress is vulnerable to Unauthenticated Arbitrary File Upload in versions up to and including 0.9.123. This is due to improper error handling in the RSA decryption process combined with a lack of path sanitization when writing uploaded files. When the plugin fails to decrypt a session key using openssl_private_decrypt(), it does not terminate execution and instead passes the boolean false value to the phpseclib library's AES cipher initialization. The library treats this false value as a string of null bytes, allowing an attacker to encrypt a malicious payload using a predictable null-byte key. Additionally, the plugin accepts filenames from the decrypted payload without sanitization, enabling directory traversal to escape the protected backup directory. This makes it possible for unauthenticated attackers to upload arbitrary PHP files to publicly accessible directories and achieve Remote Code Execution via the wpvivid_action=send_to_site parameter.

- [https://github.com/0xBlackash/CVE-2026-1357](https://github.com/0xBlackash/CVE-2026-1357) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-1357.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-1357.svg)


## CVE-2026-1096
 The Best-wp-google-map plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'latitude' and 'longitudinal' parameters of the 'google_map_view' shortcode in all versions up to, and including, 2.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/TheMursalin/CVE-2026-109618](https://github.com/TheMursalin/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/TheMursalin/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/TheMursalin/CVE-2026-109618.svg)


## CVE-2026-0770
The specific flaw exists within the handling of the exec_globals parameter provided to the validate endpoint. The issue results from the inclusion of a resource from an untrusted control sphere. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-27325.

- [https://github.com/0xBlackash/CVE-2026-0770](https://github.com/0xBlackash/CVE-2026-0770) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-0770.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-0770.svg)


## CVE-2026-0300
Prisma Access, Cloud NGFW and Panorama appliances are not impacted by this vulnerability.

- [https://github.com/0xBlackash/CVE-2026-0300](https://github.com/0xBlackash/CVE-2026-0300) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-0300.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-0300.svg)


## CVE-2026-0257
Panorama and Cloud NGFW are not impacted by these issues.

- [https://github.com/0xBlackash/CVE-2026-0257](https://github.com/0xBlackash/CVE-2026-0257) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-0257.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-0257.svg)


## CVE-2026-0073
 In adbd_tls_verify_cert of auth.cpp, there is a possible bypass of wireless ADB mutual authentication due to a logic error in the code. This could lead to remote (proximal/adjacent) code execution as the shell user with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/0xBlackash/CVE-2026-0073](https://github.com/0xBlackash/CVE-2026-0073) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-0073.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-0073.svg)


## CVE-2025-68645
 A Local File Inclusion (LFI) vulnerability exists in the Webmail Classic UI of Zimbra Collaboration (ZCS) 10.0 and 10.1 because of improper handling of user-supplied request parameters in the RestFilter servlet. An unauthenticated remote attacker can craft requests to the /h/rest endpoint to influence internal request dispatching, allowing inclusion of arbitrary files from the WebRoot directory.

- [https://github.com/0xBlackash/CVE-2025-68645](https://github.com/0xBlackash/CVE-2025-68645) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2025-68645.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2025-68645.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg)


## CVE-2025-64446
 A relative path traversal vulnerability in Fortinet FortiWeb 8.0.0 through 8.0.1, FortiWeb 7.6.0 through 7.6.4, FortiWeb 7.4.0 through 7.4.9, FortiWeb 7.2.0 through 7.2.11, FortiWeb 7.0.0 through 7.0.11 may allow an attacker to execute administrative commands on the system via crafted HTTP or HTTPS requests.

- [https://github.com/0xBlackash/CVE-2025-64446](https://github.com/0xBlackash/CVE-2025-64446) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2025-64446.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2025-64446.svg)


## CVE-2025-49844
 Redis is an open source, in-memory database that persists on disk. Versions 8.2.1 and below allow an authenticated user to use a specially crafted Lua script to manipulate the garbage collector, trigger a use-after-free and potentially lead to remote code execution. The problem exists in all versions of Redis with Lua scripting. This issue is fixed in version 8.2.2. To workaround this issue without patching the redis-server executable is to prevent users from executing Lua scripts. This can be done using ACL to restrict EVAL and EVALSHA commands.

- [https://github.com/0xBlackash/CVE-2025-49844](https://github.com/0xBlackash/CVE-2025-49844) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2025-49844.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2025-49844.svg)


## CVE-2025-48757
 An insufficient database Row-Level Security policy in Lovable through 2025-04-15 allows remote unauthenticated attackers to read or write to arbitrary database tables of generated sites. NOTE: this is disputed by the Supplier because each individual customer of the Lovable platform accepts a responsibility over protecting the data of their application.

- [https://github.com/zColdWater/vibeshield-cli](https://github.com/zColdWater/vibeshield-cli) :  ![starts](https://img.shields.io/github/stars/zColdWater/vibeshield-cli.svg) ![forks](https://img.shields.io/github/forks/zColdWater/vibeshield-cli.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/0xBlackash/CVE-2025-32463](https://github.com/0xBlackash/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2025-32463.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/0xBlackash/CVE-2025-32433](https://github.com/0xBlackash/CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2025-32433.svg)
- [https://github.com/javakhir018/jenkins-erlang-otp-cve-2025-32433](https://github.com/javakhir018/jenkins-erlang-otp-cve-2025-32433) :  ![starts](https://img.shields.io/github/stars/javakhir018/jenkins-erlang-otp-cve-2025-32433.svg) ![forks](https://img.shields.io/github/forks/javakhir018/jenkins-erlang-otp-cve-2025-32433.svg)


## CVE-2025-31161
 CrushFTP 10 before 10.8.4 and 11 before 11.3.1 allows authentication bypass and takeover of the crushadmin account (unless a DMZ proxy instance is used), as exploited in the wild in March and April 2025, aka "Unauthenticated HTTP(S) port access." A race condition exists in the AWS4-HMAC (compatible with S3) authorization method of the HTTP component of the FTP server. The server first verifies the existence of the user by performing a call to login_user_pass() with no password requirement. This will authenticate the session through the HMAC verification process and up until the server checks for user verification once more. The vulnerability can be further stabilized, eliminating the need for successfully triggering a race condition, by sending a mangled AWS4-HMAC header. By providing only the username and a following slash (/), the server will successfully find a username, which triggers the successful anypass authentication process, but the server will fail to find the expected SignedHeaders entry, resulting in an index-out-of-bounds error that stops the code from reaching the session cleanup. Together, these issues make it trivial to authenticate as any known or guessable user (e.g., crushadmin), and can lead to a full compromise of the system by obtaining an administrative account.

- [https://github.com/0xBlackash/CVE-2025-31161](https://github.com/0xBlackash/CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2025-31161.svg)


## CVE-2025-31133
 runc is a CLI tool for spawning and running containers according to the OCI specification. In versions 1.2.7 and below, 1.3.0-rc.1 through 1.3.1, 1.4.0-rc.1 and 1.4.0-rc.2 files, runc would not perform sufficient verification that the source of the bind-mount (i.e., the container's /dev/null) was actually a real /dev/null inode when using the container's /dev/null to mask. This exposes two methods of attack:  an arbitrary mount gadget, leading to host information disclosure, host denial of service, container escape, or a bypassing of maskedPaths. This issue is fixed in versions 1.2.8, 1.3.3 and 1.4.0-rc.3.

- [https://github.com/ritvikindupuri/EscapeArmed](https://github.com/ritvikindupuri/EscapeArmed) :  ![starts](https://img.shields.io/github/stars/ritvikindupuri/EscapeArmed.svg) ![forks](https://img.shields.io/github/forks/ritvikindupuri/EscapeArmed.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/AabyssZG/SpringBoot-Scan](https://github.com/AabyssZG/SpringBoot-Scan) :  ![starts](https://img.shields.io/github/stars/AabyssZG/SpringBoot-Scan.svg) ![forks](https://img.shields.io/github/forks/AabyssZG/SpringBoot-Scan.svg)


## CVE-2025-23266
 NVIDIA Container Toolkit for all platforms contains a vulnerability in some hooks used to initialize the container, where an attacker could execute arbitrary code with elevated permissions. A successful exploit of this vulnerability might lead to escalation of privileges, data tampering, information disclosure, and denial of service.

- [https://github.com/ritvikindupuri/EscapeArmed](https://github.com/ritvikindupuri/EscapeArmed) :  ![starts](https://img.shields.io/github/stars/ritvikindupuri/EscapeArmed.svg) ![forks](https://img.shields.io/github/forks/ritvikindupuri/EscapeArmed.svg)


## CVE-2025-22235
  *  Your application does not handle requests to /null or this path does not need protection

- [https://github.com/AabyssZG/SpringBoot-Scan](https://github.com/AabyssZG/SpringBoot-Scan) :  ![starts](https://img.shields.io/github/stars/AabyssZG/SpringBoot-Scan.svg) ![forks](https://img.shields.io/github/forks/AabyssZG/SpringBoot-Scan.svg)


## CVE-2025-14847
 Mismatched length fields in Zlib compressed protocol headers may allow a read of uninitialized heap memory by an unauthenticated client. This issue affects all MongoDB Server v7.0 prior to 7.0.28 versions, MongoDB Server v8.0 versions prior to 8.0.17, MongoDB Server v8.2 versions prior to 8.2.3, MongoDB Server v6.0 versions prior to 6.0.27, MongoDB Server v5.0 versions prior to 5.0.32, MongoDB Server v4.4 versions prior to 4.4.30, MongoDB Server v4.2 versions greater than or equal to 4.2.0, MongoDB Server v4.0 versions greater than or equal to 4.0.0, and MongoDB Server v3.6 versions greater than or equal to 3.6.0.

- [https://github.com/0xBlackash/CVE-2025-14847](https://github.com/0xBlackash/CVE-2025-14847) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2025-14847.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2025-14847.svg)


## CVE-2025-13315
 Twonky Server 8.5.2 on Linux and Windows is vulnerable to an access control flaw. An unauthenticated attacker can bypass web service API authentication controls to leak a log file and read the administrator's username and encrypted password.

- [https://github.com/0xBlackash/CVE-2025-13315](https://github.com/0xBlackash/CVE-2025-13315) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2025-13315.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2025-13315.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-build-metadata](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-build-metadata) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-build-metadata.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-build-metadata.svg)


## CVE-2025-5777
 Insufficient input validation leading to memory overread when the NetScaler is configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server

- [https://github.com/0xBlackash/CVE-2025-5777](https://github.com/0xBlackash/CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2025-5777.svg)


## CVE-2024-31317
 In multiple functions of ZygoteProcess.java, there is a possible way to achieve code execution as any app via WRITE_SECURE_SETTINGS due to unsafe deserialization. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/ddtftx1/xiaodu-qinghe-v20-security-audit](https://github.com/ddtftx1/xiaodu-qinghe-v20-security-audit) :  ![starts](https://img.shields.io/github/stars/ddtftx1/xiaodu-qinghe-v20-security-audit.svg) ![forks](https://img.shields.io/github/forks/ddtftx1/xiaodu-qinghe-v20-security-audit.svg)


## CVE-2024-30804
 An issue discovered in the DeviceIoControl component in ASUS Fan_Xpert before v.10013 allows an attacker to execute arbitrary code via crafted IOCTL requests.

- [https://github.com/ekfkawl/CVE-2024-30804](https://github.com/ekfkawl/CVE-2024-30804) :  ![starts](https://img.shields.io/github/stars/ekfkawl/CVE-2024-30804.svg) ![forks](https://img.shields.io/github/forks/ekfkawl/CVE-2024-30804.svg)


## CVE-2024-3094
Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.

- [https://github.com/0xBlackash/CVE-2024-3094](https://github.com/0xBlackash/CVE-2024-3094) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2024-3094.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2024-3094.svg)


## CVE-2023-44487
 The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.

- [https://github.com/TAVARDT-Canada/http2-kernel-dos-resilience-checker-ca](https://github.com/TAVARDT-Canada/http2-kernel-dos-resilience-checker-ca) :  ![starts](https://img.shields.io/github/stars/TAVARDT-Canada/http2-kernel-dos-resilience-checker-ca.svg) ![forks](https://img.shields.io/github/forks/TAVARDT-Canada/http2-kernel-dos-resilience-checker-ca.svg)
- [https://github.com/TAVARDT-Australia/http2-kernel-dos-resilience-checker-au](https://github.com/TAVARDT-Australia/http2-kernel-dos-resilience-checker-au) :  ![starts](https://img.shields.io/github/stars/TAVARDT-Australia/http2-kernel-dos-resilience-checker-au.svg) ![forks](https://img.shields.io/github/forks/TAVARDT-Australia/http2-kernel-dos-resilience-checker-au.svg)
- [https://github.com/TAVARDT-France/http2-kernel-dos-resilience-checker-fr](https://github.com/TAVARDT-France/http2-kernel-dos-resilience-checker-fr) :  ![starts](https://img.shields.io/github/stars/TAVARDT-France/http2-kernel-dos-resilience-checker-fr.svg) ![forks](https://img.shields.io/github/forks/TAVARDT-France/http2-kernel-dos-resilience-checker-fr.svg)
- [https://github.com/TAVARDT-New-Zealand/http2-kernel-dos-resilience-checker-nz](https://github.com/TAVARDT-New-Zealand/http2-kernel-dos-resilience-checker-nz) :  ![starts](https://img.shields.io/github/stars/TAVARDT-New-Zealand/http2-kernel-dos-resilience-checker-nz.svg) ![forks](https://img.shields.io/github/forks/TAVARDT-New-Zealand/http2-kernel-dos-resilience-checker-nz.svg)
- [https://github.com/TAVARDT-UK/http2-kernel-dos-resilience-checker-uk](https://github.com/TAVARDT-UK/http2-kernel-dos-resilience-checker-uk) :  ![starts](https://img.shields.io/github/stars/TAVARDT-UK/http2-kernel-dos-resilience-checker-uk.svg) ![forks](https://img.shields.io/github/forks/TAVARDT-UK/http2-kernel-dos-resilience-checker-uk.svg)
- [https://github.com/TAVARDT-USA/http2-kernel-dos-resilience-checker-us](https://github.com/TAVARDT-USA/http2-kernel-dos-resilience-checker-us) :  ![starts](https://img.shields.io/github/stars/TAVARDT-USA/http2-kernel-dos-resilience-checker-us.svg) ![forks](https://img.shields.io/github/forks/TAVARDT-USA/http2-kernel-dos-resilience-checker-us.svg)
- [https://github.com/TAVARDT-Italia/http2-kernel-dos-resilience-checker-it](https://github.com/TAVARDT-Italia/http2-kernel-dos-resilience-checker-it) :  ![starts](https://img.shields.io/github/stars/TAVARDT-Italia/http2-kernel-dos-resilience-checker-it.svg) ![forks](https://img.shields.io/github/forks/TAVARDT-Italia/http2-kernel-dos-resilience-checker-it.svg)
- [https://github.com/TAVARDT-Brasil/http2-kernel-dos-resilience-checker-br](https://github.com/TAVARDT-Brasil/http2-kernel-dos-resilience-checker-br) :  ![starts](https://img.shields.io/github/stars/TAVARDT-Brasil/http2-kernel-dos-resilience-checker-br.svg) ![forks](https://img.shields.io/github/forks/TAVARDT-Brasil/http2-kernel-dos-resilience-checker-br.svg)
- [https://github.com/TAVARDT-Mexico/http2-kernel-dos-resilience-checker-mx](https://github.com/TAVARDT-Mexico/http2-kernel-dos-resilience-checker-mx) :  ![starts](https://img.shields.io/github/stars/TAVARDT-Mexico/http2-kernel-dos-resilience-checker-mx.svg) ![forks](https://img.shields.io/github/forks/TAVARDT-Mexico/http2-kernel-dos-resilience-checker-mx.svg)
- [https://github.com/TAVARDT-Portugal/http2-kernel-dos-resilience-checker-pt](https://github.com/TAVARDT-Portugal/http2-kernel-dos-resilience-checker-pt) :  ![starts](https://img.shields.io/github/stars/TAVARDT-Portugal/http2-kernel-dos-resilience-checker-pt.svg) ![forks](https://img.shields.io/github/forks/TAVARDT-Portugal/http2-kernel-dos-resilience-checker-pt.svg)
- [https://github.com/TAVARDT-Espana/http2-kernel-dos-resilience-checker-es](https://github.com/TAVARDT-Espana/http2-kernel-dos-resilience-checker-es) :  ![starts](https://img.shields.io/github/stars/TAVARDT-Espana/http2-kernel-dos-resilience-checker-es.svg) ![forks](https://img.shields.io/github/forks/TAVARDT-Espana/http2-kernel-dos-resilience-checker-es.svg)


## CVE-2022-38694
 In BootRom, there is a possible unchecked write address. This could lead to local escalation of privilege with no additional execution privileges needed.

- [https://github.com/DazBot13-boopt/sc9863a-flash-free](https://github.com/DazBot13-boopt/sc9863a-flash-free) :  ![starts](https://img.shields.io/github/stars/DazBot13-boopt/sc9863a-flash-free.svg) ![forks](https://img.shields.io/github/forks/DazBot13-boopt/sc9863a-flash-free.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/0xBlackash/CVE-2022-22965](https://github.com/0xBlackash/CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2022-22965.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/LucasPDiniz/CVE-2021-44228](https://github.com/LucasPDiniz/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/LucasPDiniz/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/LucasPDiniz/CVE-2021-44228.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/xMohamed0/CVE-2021-41773](https://github.com/xMohamed0/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/xMohamed0/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/xMohamed0/CVE-2021-41773.svg)
- [https://github.com/sixpacksecurity/CVE-2021-41773](https://github.com/sixpacksecurity/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sixpacksecurity/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sixpacksecurity/CVE-2021-41773.svg)


## CVE-2020-17103
 Windows Cloud Files Mini Filter Driver Elevation of Privilege Vulnerability

- [https://github.com/0xBlackash/CVE-2020-17103](https://github.com/0xBlackash/CVE-2020-17103) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2020-17103.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2020-17103.svg)


## CVE-2020-5902
 In BIG-IP versions 15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 13.1.0-13.1.3.3, 12.1.0-12.1.5.1, and 11.6.1-11.6.5.1, the Traffic Management User Interface (TMUI), also referred to as the Configuration utility, has a Remote Code Execution (RCE) vulnerability in undisclosed pages.

- [https://github.com/0xBlackash/CVE-2020-5902](https://github.com/0xBlackash/CVE-2020-5902) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2020-5902.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2020-5902.svg)


## CVE-2019-20446
 In xml.rs in GNOME librsvg before 2.46.2, a crafted SVG file with nested patterns can cause denial of service when passed to the library for processing. The attacker constructs pattern elements so that the number of final rendered objects grows exponentially.

- [https://github.com/googlesky/CVE-2026-132275](https://github.com/googlesky/CVE-2026-132275) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-132275.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-132275.svg)


## CVE-2019-2215
 A use-after-free in binder.c allows an elevation of privilege from an application to the Linux Kernel. No user interaction is required to exploit this vulnerability, however exploitation does require either the installation of a malicious local application or a separate vulnerability in a network facing application.Product: AndroidAndroid ID: A-141720095

- [https://github.com/RxinnotRstar/CVE-2019-2215-ForMIpad4-NEW-GUI](https://github.com/RxinnotRstar/CVE-2019-2215-ForMIpad4-NEW-GUI) :  ![starts](https://img.shields.io/github/stars/RxinnotRstar/CVE-2019-2215-ForMIpad4-NEW-GUI.svg) ![forks](https://img.shields.io/github/forks/RxinnotRstar/CVE-2019-2215-ForMIpad4-NEW-GUI.svg)


## CVE-2017-2636
 Race condition in drivers/tty/n_hdlc.c in the Linux kernel through 4.10.1 allows local users to gain privileges or cause a denial of service (double free) by setting the HDLC line discipline.

- [https://github.com/OYMMYO/n_hdlc-cve-2017-2636](https://github.com/OYMMYO/n_hdlc-cve-2017-2636) :  ![starts](https://img.shields.io/github/stars/OYMMYO/n_hdlc-cve-2017-2636.svg) ![forks](https://img.shields.io/github/forks/OYMMYO/n_hdlc-cve-2017-2636.svg)


## CVE-2017-0144
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/0xBlackash/CVE-2017-0144](https://github.com/0xBlackash/CVE-2017-0144) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2017-0144.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2017-0144.svg)


## CVE-2014-6287
 The findMacroMarker function in parserLib.pas in Rejetto HTTP File Server (aks HFS or HttpFileServer) 2.3x before 2.3c allows remote attackers to execute arbitrary programs via a %00 sequence in a search action.

- [https://github.com/xyzzklk/HFS_Strike](https://github.com/xyzzklk/HFS_Strike) :  ![starts](https://img.shields.io/github/stars/xyzzklk/HFS_Strike.svg) ![forks](https://img.shields.io/github/forks/xyzzklk/HFS_Strike.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock."  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/0xBlackash/CVE-2014-6271](https://github.com/0xBlackash/CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2014-6271.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/0xBlackash/CVE-2014-0160](https://github.com/0xBlackash/CVE-2014-0160) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2014-0160.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2014-0160.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/SelimcanG/security-home-lab](https://github.com/SelimcanG/security-home-lab) :  ![starts](https://img.shields.io/github/stars/SelimcanG/security-home-lab.svg) ![forks](https://img.shields.io/github/forks/SelimcanG/security-home-lab.svg)

