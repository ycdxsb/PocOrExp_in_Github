# Update 2026-10-27
## CVE-2026-116191
 Rclone before 1.75.2 contains a path traversal vulnerability in serve webdav that allows unauthenticated attackers to write above the served root by sending an unvalidated '..' path component. Attackers can send MKCOL /.. to plant a VFS node, then PUT, MOVE, COPY, or MKCOL to create, overwrite, or delete files belonging to other tenants.

- [https://github.com/asvorg/CVE-2026-116191-poc](https://github.com/asvorg/CVE-2026-116191-poc) :  ![starts](https://img.shields.io/github/stars/asvorg/CVE-2026-116191-poc.svg) ![forks](https://img.shields.io/github/forks/asvorg/CVE-2026-116191-poc.svg)


## CVE-2026-112900
 Pillow is a Python imaging library. From 2.6.0 until 13.0.0, Pillow is vulnerable to argument injection when invoking Ghostscript for EPS input. EpsImagePlugin.Ghostscript passes a caller-controlled input filename after -f without converting it to a safe absolute path, so a name beginning with a hyphen can be interpreted as a Ghostscript option. An attacker who controls the filename can inject Ghostscript arguments. Arbitrary command execution specifically requires a leading @ argument-file filename and control of the referenced text file containing additional Ghostscript arguments; the reported chain reproduces with the default -dSAFER invocation. This issue is fixed in version 13.0.0.

- [https://github.com/kavin-jindal/CVE-2026-112900-PoC](https://github.com/kavin-jindal/CVE-2026-112900-PoC) :  ![starts](https://img.shields.io/github/stars/kavin-jindal/CVE-2026-112900-PoC.svg) ![forks](https://img.shields.io/github/forks/kavin-jindal/CVE-2026-112900-PoC.svg)


## CVE-2026-112866
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in WPFactory Product Filter by WBW woo-product-filter allows Blind SQL Injection.This issue affects Product Filter by WBW: from n/a through 3.4.6.

- [https://github.com/Hassham1/CVE-2026-112866-woo-product-filter-sqli-poc](https://github.com/Hassham1/CVE-2026-112866-woo-product-filter-sqli-poc) :  ![starts](https://img.shields.io/github/stars/Hassham1/CVE-2026-112866-woo-product-filter-sqli-poc.svg) ![forks](https://img.shields.io/github/forks/Hassham1/CVE-2026-112866-woo-product-filter-sqli-poc.svg)


## CVE-2026-111497
Users need to update any Brotli libraries or binaries between 1.0.3 through 1.2.0 to the latest available version: 1.0.10 or 1.1.1 or 1.2.1.

- [https://github.com/assetnote/node2shell-scanner](https://github.com/assetnote/node2shell-scanner) :  ![starts](https://img.shields.io/github/stars/assetnote/node2shell-scanner.svg) ![forks](https://img.shields.io/github/forks/assetnote/node2shell-scanner.svg)
- [https://github.com/Hika-sec/http2shell-CVE-2026-111497](https://github.com/Hika-sec/http2shell-CVE-2026-111497) :  ![starts](https://img.shields.io/github/stars/Hika-sec/http2shell-CVE-2026-111497.svg) ![forks](https://img.shields.io/github/forks/Hika-sec/http2shell-CVE-2026-111497.svg)
- [https://github.com/emirwtz/CVE-2026-111497](https://github.com/emirwtz/CVE-2026-111497) :  ![starts](https://img.shields.io/github/stars/emirwtz/CVE-2026-111497.svg) ![forks](https://img.shields.io/github/forks/emirwtz/CVE-2026-111497.svg)
- [https://github.com/GlobularOne/HTTP2Shell-PoC](https://github.com/GlobularOne/HTTP2Shell-PoC) :  ![starts](https://img.shields.io/github/stars/GlobularOne/HTTP2Shell-PoC.svg) ![forks](https://img.shields.io/github/forks/GlobularOne/HTTP2Shell-PoC.svg)
- [https://github.com/tani2shell/node2shell-lab](https://github.com/tani2shell/node2shell-lab) :  ![starts](https://img.shields.io/github/stars/tani2shell/node2shell-lab.svg) ![forks](https://img.shields.io/github/forks/tani2shell/node2shell-lab.svg)
- [https://github.com/SYM01/cve-2026-111497](https://github.com/SYM01/cve-2026-111497) :  ![starts](https://img.shields.io/github/stars/SYM01/cve-2026-111497.svg) ![forks](https://img.shields.io/github/forks/SYM01/cve-2026-111497.svg)
- [https://github.com/tikarammardi/CVE-2026-111497](https://github.com/tikarammardi/CVE-2026-111497) :  ![starts](https://img.shields.io/github/stars/tikarammardi/CVE-2026-111497.svg) ![forks](https://img.shields.io/github/forks/tikarammardi/CVE-2026-111497.svg)
- [https://github.com/lushinshang/cve-2026-111497-http2shell-guide](https://github.com/lushinshang/cve-2026-111497-http2shell-guide) :  ![starts](https://img.shields.io/github/stars/lushinshang/cve-2026-111497-http2shell-guide.svg) ![forks](https://img.shields.io/github/forks/lushinshang/cve-2026-111497-http2shell-guide.svg)
- [https://github.com/apaonum/brotli-cve-check](https://github.com/apaonum/brotli-cve-check) :  ![starts](https://img.shields.io/github/stars/apaonum/brotli-cve-check.svg) ![forks](https://img.shields.io/github/forks/apaonum/brotli-cve-check.svg)
- [https://github.com/fbuff-tools/http2shell-checker](https://github.com/fbuff-tools/http2shell-checker) :  ![starts](https://img.shields.io/github/stars/fbuff-tools/http2shell-checker.svg) ![forks](https://img.shields.io/github/forks/fbuff-tools/http2shell-checker.svg)


## CVE-2026-109619
 PHP has various global state that temporarily points into request memory. In some scenarios, global state may not be correctly reset, or may be repopulated after being reset. The global state may then refer to request memory even after it has been freed. Subsequent requests may read or branch on this stale state before it is fully initialized. Multiple strategies can trigger this condition and produce remote code execution (RCE).

- [https://github.com/akamor2800/php-5.4-cve-2026-php2shell-patch](https://github.com/akamor2800/php-5.4-cve-2026-php2shell-patch) :  ![starts](https://img.shields.io/github/stars/akamor2800/php-5.4-cve-2026-php2shell-patch.svg) ![forks](https://img.shields.io/github/forks/akamor2800/php-5.4-cve-2026-php2shell-patch.svg)
- [https://github.com/Ademking/php2shell-migration](https://github.com/Ademking/php2shell-migration) :  ![starts](https://img.shields.io/github/stars/Ademking/php2shell-migration.svg) ![forks](https://img.shields.io/github/forks/Ademking/php2shell-migration.svg)
- [https://github.com/tani2shell/php2shell-lab](https://github.com/tani2shell/php2shell-lab) :  ![starts](https://img.shields.io/github/stars/tani2shell/php2shell-lab.svg) ![forks](https://img.shields.io/github/forks/tani2shell/php2shell-lab.svg)
- [https://github.com/BRANDEFENSE/php2shell-defense-kit](https://github.com/BRANDEFENSE/php2shell-defense-kit) :  ![starts](https://img.shields.io/github/stars/BRANDEFENSE/php2shell-defense-kit.svg) ![forks](https://img.shields.io/github/forks/BRANDEFENSE/php2shell-defense-kit.svg)
- [https://github.com/bashclub/php2shell-forensic-check](https://github.com/bashclub/php2shell-forensic-check) :  ![starts](https://img.shields.io/github/stars/bashclub/php2shell-forensic-check.svg) ![forks](https://img.shields.io/github/forks/bashclub/php2shell-forensic-check.svg)
- [https://github.com/codiobert/runcloud-php2shell-patch](https://github.com/codiobert/runcloud-php2shell-patch) :  ![starts](https://img.shields.io/github/stars/codiobert/runcloud-php2shell-patch.svg) ![forks](https://img.shields.io/github/forks/codiobert/runcloud-php2shell-patch.svg)


## CVE-2026-109618
 PHP uses longjmp() for out-of-memory (OOM) errors to exit the current context and abort handling of the request. Some contexts may not properly account for this scenario and leave request memory in an uninitialized state before performing an allocation. The subsequent request cleanup procedure may read or branch on this memory. Multiple OOM strategies can consistently trigger this condition and lead to remote code execution (RCE).

- [https://github.com/0x1c1101/CVE-2026-109618-PoC](https://github.com/0x1c1101/CVE-2026-109618-PoC) :  ![starts](https://img.shields.io/github/stars/0x1c1101/CVE-2026-109618-PoC.svg) ![forks](https://img.shields.io/github/forks/0x1c1101/CVE-2026-109618-PoC.svg)
- [https://github.com/akamor2800/php-5.4-cve-2026-php2shell-patch](https://github.com/akamor2800/php-5.4-cve-2026-php2shell-patch) :  ![starts](https://img.shields.io/github/stars/akamor2800/php-5.4-cve-2026-php2shell-patch.svg) ![forks](https://img.shields.io/github/forks/akamor2800/php-5.4-cve-2026-php2shell-patch.svg)
- [https://github.com/Ademking/php2shell-migration](https://github.com/Ademking/php2shell-migration) :  ![starts](https://img.shields.io/github/stars/Ademking/php2shell-migration.svg) ![forks](https://img.shields.io/github/forks/Ademking/php2shell-migration.svg)
- [https://github.com/tani2shell/php2shell-lab](https://github.com/tani2shell/php2shell-lab) :  ![starts](https://img.shields.io/github/stars/tani2shell/php2shell-lab.svg) ![forks](https://img.shields.io/github/forks/tani2shell/php2shell-lab.svg)
- [https://github.com/deconstruction/EOLphp-php2shell-patches](https://github.com/deconstruction/EOLphp-php2shell-patches) :  ![starts](https://img.shields.io/github/stars/deconstruction/EOLphp-php2shell-patches.svg) ![forks](https://img.shields.io/github/forks/deconstruction/EOLphp-php2shell-patches.svg)
- [https://github.com/andreysheva/php2shell-doctor](https://github.com/andreysheva/php2shell-doctor) :  ![starts](https://img.shields.io/github/stars/andreysheva/php2shell-doctor.svg) ![forks](https://img.shields.io/github/forks/andreysheva/php2shell-doctor.svg)
- [https://github.com/Taz1920/PHP-Canarywall](https://github.com/Taz1920/PHP-Canarywall) :  ![starts](https://img.shields.io/github/stars/Taz1920/PHP-Canarywall.svg) ![forks](https://img.shields.io/github/forks/Taz1920/PHP-Canarywall.svg)
- [https://github.com/BRANDEFENSE/php2shell-defense-kit](https://github.com/BRANDEFENSE/php2shell-defense-kit) :  ![starts](https://img.shields.io/github/stars/BRANDEFENSE/php2shell-defense-kit.svg) ![forks](https://img.shields.io/github/forks/BRANDEFENSE/php2shell-defense-kit.svg)
- [https://github.com/RuanSerraAzul/CVE-2026-109618-POC](https://github.com/RuanSerraAzul/CVE-2026-109618-POC) :  ![starts](https://img.shields.io/github/stars/RuanSerraAzul/CVE-2026-109618-POC.svg) ![forks](https://img.shields.io/github/forks/RuanSerraAzul/CVE-2026-109618-POC.svg)


## CVE-2026-109378
 SPIP before 4.4.18 contains a server-side request forgery vulnerability in recuperer_url() in ecrire/inc/distant.php that follows up to 10 redirects without re-validating targets with valider_url_distante(). Authenticated attackers can supply a remote URL, such as a syndicated site feed or remote document, that redirects to internal or link-local addresses including cloud metadata endpoints.

- [https://github.com/ka3n1x/spip-cve-2026](https://github.com/ka3n1x/spip-cve-2026) :  ![starts](https://img.shields.io/github/stars/ka3n1x/spip-cve-2026.svg) ![forks](https://img.shields.io/github/forks/ka3n1x/spip-cve-2026.svg)


## CVE-2026-106173
 A improper limitation of a pathname to a restricted directory ('path traversal') vulnerability in Fortinet FortiSIEM 7.5.0 may allow attacker to execute unauthorized code or commands via specially crafted packets.

- [https://github.com/Ghost-Bx1/Fortinet-Exploits-CVE-2026-39808-106173-107656](https://github.com/Ghost-Bx1/Fortinet-Exploits-CVE-2026-39808-106173-107656) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/Fortinet-Exploits-CVE-2026-39808-106173-107656.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/Fortinet-Exploits-CVE-2026-39808-106173-107656.svg)


## CVE-2026-99999
A more complete validation at input is forthcoming, but needs more work.

- [https://github.com/unixreaper/CVE-2026-99999-Research](https://github.com/unixreaper/CVE-2026-99999-Research) :  ![starts](https://img.shields.io/github/stars/unixreaper/CVE-2026-99999-Research.svg) ![forks](https://img.shields.io/github/forks/unixreaper/CVE-2026-99999-Research.svg)


## CVE-2026-98260
[ tglx: Move the cleanup right after de_thread() ]

- [https://github.com/zsw125/o3root](https://github.com/zsw125/o3root) :  ![starts](https://img.shields.io/github/stars/zsw125/o3root.svg) ![forks](https://img.shields.io/github/forks/zsw125/o3root.svg)
- [https://github.com/janewas/cve-2026-98260-vivo-gki-research](https://github.com/janewas/cve-2026-98260-vivo-gki-research) :  ![starts](https://img.shields.io/github/stars/janewas/cve-2026-98260-vivo-gki-research.svg) ![forks](https://img.shields.io/github/forks/janewas/cve-2026-98260-vivo-gki-research.svg)


## CVE-2026-86950
 An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in iOS 26.7.1 and iPadOS 26.7.1, macOS Sequoia 15.8.1, macOS Tahoe 26.7.1. Processing a maliciously crafted file may lead to arbitrary code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 27.

- [https://github.com/DeAurity/CVE-2026-86950-POC](https://github.com/DeAurity/CVE-2026-86950-POC) :  ![starts](https://img.shields.io/github/stars/DeAurity/CVE-2026-86950-POC.svg) ![forks](https://img.shields.io/github/forks/DeAurity/CVE-2026-86950-POC.svg)


## CVE-2026-86426
 LibreNMS before 26.8.0 contains an authentication bypass vulnerability in the REST API that allows unauthenticated attackers to access protected endpoints by sending numeric values instead of string tokens. Attackers can exploit MySQL type coercion by sending small integers like 0 through 9 to match token hashes, gaining access to API functionality including device credentials and administrative features that enable remote code execution through alert templates.

- [https://github.com/Guila95/CVE-2026-86426](https://github.com/Guila95/CVE-2026-86426) :  ![starts](https://img.shields.io/github/stars/Guila95/CVE-2026-86426.svg) ![forks](https://img.shields.io/github/forks/Guila95/CVE-2026-86426.svg)


## CVE-2026-83548
 A Pre-authentication SSRF vulnerability exists in the SMA1000 Appliance Work Place interface due to an unintended alternate access path. A remote unauthenticated attacker could potentially exploit this vulnerability to gain unauthorized access to sensitive functionality and perform unauthorized operations.

- [https://github.com/maxprog-svg/CVE-2026-83548](https://github.com/maxprog-svg/CVE-2026-83548) :  ![starts](https://img.shields.io/github/stars/maxprog-svg/CVE-2026-83548.svg) ![forks](https://img.shields.io/github/forks/maxprog-svg/CVE-2026-83548.svg)


## CVE-2026-74580
addresses are pushed back through iotlb_access_ok()'s slow path.

- [https://github.com/YounesHfa/CVE-2026-74580](https://github.com/YounesHfa/CVE-2026-74580) :  ![starts](https://img.shields.io/github/stars/YounesHfa/CVE-2026-74580.svg) ![forks](https://img.shields.io/github/forks/YounesHfa/CVE-2026-74580.svg)


## CVE-2026-72714
 Rocq Prover does not restore the universe graph's copy of the universe checking flag when a module that locally disabled the check is closed. Local Unset Universe Checking inside a module is expected to last only until the module ends, and the global flag is restored, but the universe graph keeps its own copy which is left disabled. The two views then disagree: Test Universe Checking reports the check as enabled while the kernel continues to accept universe-inconsistent terms. With the constraint between two universes no longer enforced, Hurkens' paradox applies and yields a proof of False, from which any proposition follows. The proof uses no axioms, plugins or unsafe features once the module has closed, and Print Assumptions reports it as closed under the global context, so neither the assumption audit nor the flag query reflects the actual kernel state. No fix is available.

- [https://github.com/endrazine/rocq-cve-poc-22287](https://github.com/endrazine/rocq-cve-poc-22287) :  ![starts](https://img.shields.io/github/stars/endrazine/rocq-cve-poc-22287.svg) ![forks](https://img.shields.io/github/forks/endrazine/rocq-cve-poc-22287.svg)


## CVE-2026-72711
 The Lean 4 kernel does not check that the body of an opaque declaration is closed. environment::add_opaque omits the check_no_metavar_no_fvar call that the definition and theorem paths perform, so a value containing a free variable that is absent from the local context is not rejected outright. A metaprogram can first cause the kernel to create a temporary local of type False and record its type in the type checker's inference cache, then restore the local context while that cache entry persists on the same type checker instance, and finally submit an opaque declaration whose value is the now-unbound variable. The cache lookup answers before the branch that would test membership of the local context, so the kernel infers the cached type and admits an opaque constant of type False, from which any proposition follows. The declaration is accepted through the ordinary checked path at maximum kernel checking, without sorry, unsafeCast, debug.skipKernelTC, addDeclWithoutChecking, foreign code or a modified .olean file, and the result carries no axioms. Fixed in 4.32.2 by adding the missing closure check.

- [https://github.com/endrazine/lean-cve-poc-14484](https://github.com/endrazine/lean-cve-poc-14484) :  ![starts](https://img.shields.io/github/stars/endrazine/lean-cve-poc-14484.svg) ![forks](https://img.shields.io/github/forks/endrazine/lean-cve-poc-14484.svg)


## CVE-2026-72708
 SPIP before 4.4.18 contains an unauthenticated blind SQL injection vulnerability in the SQL escaping layer that allows unauthenticated attackers to inject arbitrary SQL by supplying a crafted annee parameter value matching a word character followed by an open parenthesis, which bypasses escaping for date-type columns across MySQL, SQLite, and PostgreSQL backends. Attackers can exploit the always-present sitemap.xml.html template's annee criterion to embed unescaped time-based or boolean payloads into database queries, enabling extraction of arbitrary database content including the alea_ephemere secret used to sign SPIP action nonces.

- [https://github.com/ka3n1x/spip-cve-2026](https://github.com/ka3n1x/spip-cve-2026) :  ![starts](https://img.shields.io/github/stars/ka3n1x/spip-cve-2026.svg) ![forks](https://img.shields.io/github/forks/ka3n1x/spip-cve-2026.svg)


## CVE-2026-72705
 The guard checker in Rocq Prover does not follow recursive calls made through a fixpoint's own arguments. A fixpoint may pass itself as a higher-order argument to a second fixpoint, which then applies it to a value that is not a subterm of the structural argument. Passing the recursive function to a plain definition is rejected because the checker unfolds the definition and observes the call, but passing it to a fixpoint is accepted because higher-order recursive calls through fixpoint arguments are not tracked. This admits a type that is definitionally equal to its own negation, so self-application produces False in purely definitional code, without tactics, axioms, plugins or unsafe flags, and Print Assumptions reports the result as closed under the global context. Fixed in Rocq 9.2.0.

- [https://github.com/endrazine/rocq-cve-poc-21683](https://github.com/endrazine/rocq-cve-poc-21683) :  ![starts](https://img.shields.io/github/stars/endrazine/rocq-cve-poc-21683.svg) ![forks](https://img.shields.io/github/forks/endrazine/rocq-cve-poc-21683.svg)


## CVE-2026-72704
 The guard checker in Rocq Prover does not recheck the recursive tree representation of an inductive type parameter after that parameter has been changed by transport. A fixpoint may apply a rewrite along an equality between types to its recursive argument, which the guard checker accepts because the inductive type is preserved, while the recursive tree recorded for the parameter is altered. A second fixpoint that calls the first inherits the altered recursive tree without verification, so a call that is not structurally decreasing is accepted as terminating. The resulting non-terminating definition proves that a natural number equals its own successor and therefore False, from which any proposition follows. The demonstration uses two axioms that follow from univalence and are consistent with the calculus of inductive constructions, so the contradiction comes from the guard check rather than from the assumptions. A fix is proposed but not merged.

- [https://github.com/endrazine/rocq-cve-poc-22024](https://github.com/endrazine/rocq-cve-poc-22024) :  ![starts](https://img.shields.io/github/stars/endrazine/rocq-cve-poc-22024.svg) ![forks](https://img.shields.io/github/forks/endrazine/rocq-cve-poc-22024.svg)


## CVE-2026-72703
 The guard checker in Rocq Prover treats a parameter of a nested mutual fixpoint as uniform without examining calls between the different bodies of that fixpoint. find_uniform_parameters in kernel/inductive.ml inspects only self-recursive calls, so when no body calls itself the function concludes that every parameter is uniform. A parameter that grows through a cross-call from one body to another therefore keeps the subterm specification it inherited from the enclosing fixpoint, and a recursive call guarded by that specification is accepted although the argument is not structurally smaller. A non-terminating definition is admitted as structurally decreasing, which yields a term whose value equals its own successor and so a proof of False, from which any proposition follows. The proof requires no axioms, plugins or unsafe flags and Print Assumptions reports it as closed under the global context. Introduced in Coq 8.20 and fixed in Rocq 9.2.0.

- [https://github.com/endrazine/rocq-cve-poc-21682](https://github.com/endrazine/rocq-cve-poc-21682) :  ![starts](https://img.shields.io/github/stars/endrazine/rocq-cve-poc-21682.svg) ![forks](https://img.shields.io/github/forks/endrazine/rocq-cve-poc-21682.svg)


## CVE-2026-64849
 MLflow is an open source AI engineering platform for agents, large language models, and machine learning models. Starting in 3.3.0 and prior to 3.15.0, the unauthenticated POST /api/2.0/mlflow/webhooks/{id}/test endpoint calls _validate_webhook_url() in mlflow/utils/validation.py only for the original URL while mlflow/webhooks/delivery.py follows redirects and re-resolves the hostname without pinning the validated address, allowing attackers to reach internal or cloud metadata services and receive response_status and response_body. This issue is fixed in version 3.15.0.

- [https://github.com/maxprog-svg/CVE-2026-64849](https://github.com/maxprog-svg/CVE-2026-64849) :  ![starts](https://img.shields.io/github/stars/maxprog-svg/CVE-2026-64849.svg) ![forks](https://img.shields.io/github/forks/maxprog-svg/CVE-2026-64849.svg)


## CVE-2026-64560
---truncated---

- [https://github.com/wanwuzhishi/ksu-root](https://github.com/wanwuzhishi/ksu-root) :  ![starts](https://img.shields.io/github/stars/wanwuzhishi/ksu-root.svg) ![forks](https://img.shields.io/github/forks/wanwuzhishi/ksu-root.svg)


## CVE-2026-59248
This issue affects cowlib: from 2.0.0 before 2.19.0.

- [https://github.com/DarynOngera/bug-free-broccoli](https://github.com/DarynOngera/bug-free-broccoli) :  ![starts](https://img.shields.io/github/stars/DarynOngera/bug-free-broccoli.svg) ![forks](https://img.shields.io/github/forks/DarynOngera/bug-free-broccoli.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/tusharpandey13/ghostlock-somalia](https://github.com/tusharpandey13/ghostlock-somalia) :  ![starts](https://img.shields.io/github/stars/tusharpandey13/ghostlock-somalia.svg) ![forks](https://img.shields.io/github/forks/tusharpandey13/ghostlock-somalia.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/yameteeee-kudasaiiiiiii90/DFRoot](https://github.com/yameteeee-kudasaiiiiiii90/DFRoot) :  ![starts](https://img.shields.io/github/stars/yameteeee-kudasaiiiiiii90/DFRoot.svg) ![forks](https://img.shields.io/github/forks/yameteeee-kudasaiiiiiii90/DFRoot.svg)


## CVE-2026-39808
 A improper neutralization of special elements used in an os command ('os command injection') vulnerability in Fortinet FortiSandbox 4.4.0 through 4.4.8 may allow attacker to execute unauthorized code or commands via insert attack vector here

- [https://github.com/Ghost-Bx1/Fortinet-Exploits-CVE-2026-39808-106173-107656](https://github.com/Ghost-Bx1/Fortinet-Exploits-CVE-2026-39808-106173-107656) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/Fortinet-Exploits-CVE-2026-39808-106173-107656.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/Fortinet-Exploits-CVE-2026-39808-106173-107656.svg)


## CVE-2026-25262
 Memory corruption while processing a crafted ELF file in the Primary Bootloader.

- [https://github.com/Starry2233/cve-2026-25262-poc](https://github.com/Starry2233/cve-2026-25262-poc) :  ![starts](https://img.shields.io/github/stars/Starry2233/cve-2026-25262-poc.svg) ![forks](https://img.shields.io/github/forks/Starry2233/cve-2026-25262-poc.svg)


## CVE-2026-21627
 The vulnerability was rooted in how the Tassos Framework plugin handled specific AJAX requests through Joomla’s com_ajax entry point. Under certain conditions, internal framework functionality could be invoked without proper restriction.

- [https://github.com/SAIM28826/CVE-2026-21627](https://github.com/SAIM28826/CVE-2026-21627) :  ![starts](https://img.shields.io/github/stars/SAIM28826/CVE-2026-21627.svg) ![forks](https://img.shields.io/github/forks/SAIM28826/CVE-2026-21627.svg)


## CVE-2026-14440
David Osipov (ORCID: https://orcid.org/0009-0005-2713-9242), independent researcher

- [https://github.com/Ghost-Bx1/Cloudflare-Exploits-CVE-2026-14440-CVE-2026-3125-CVE-2025-0651](https://github.com/Ghost-Bx1/Cloudflare-Exploits-CVE-2026-14440-CVE-2026-3125-CVE-2025-0651) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/Cloudflare-Exploits-CVE-2026-14440-CVE-2026-3125-CVE-2025-0651.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/Cloudflare-Exploits-CVE-2026-14440-CVE-2026-3125-CVE-2025-0651.svg)


## CVE-2026-11610
in schema.c only.

- [https://github.com/ohackercego/CVE-2026-116105](https://github.com/ohackercego/CVE-2026-116105) :  ![starts](https://img.shields.io/github/stars/ohackercego/CVE-2026-116105.svg) ![forks](https://img.shields.io/github/forks/ohackercego/CVE-2026-116105.svg)
- [https://github.com/ohackercego/CVE-2026-116106](https://github.com/ohackercego/CVE-2026-116106) :  ![starts](https://img.shields.io/github/stars/ohackercego/CVE-2026-116106.svg) ![forks](https://img.shields.io/github/forks/ohackercego/CVE-2026-116106.svg)


## CVE-2026-11556
 A security flaw has been discovered in Tenda F451 1.0.0.7/1.0.0.9. Impacted is the function formWriteFacMac of the file /goform/WriteFacMac of the component Web Management Interface. Performing a manipulation of the argument mac results in os command injection. Remote exploitation of the attack is possible. The exploit has been released to the public and may be used for attacks.

- [https://github.com/renzi25031469/CVE-2026-115560](https://github.com/renzi25031469/CVE-2026-115560) :  ![starts](https://img.shields.io/github/stars/renzi25031469/CVE-2026-115560.svg) ![forks](https://img.shields.io/github/forks/renzi25031469/CVE-2026-115560.svg)
- [https://github.com/al4n4n/CVE-2026-115560](https://github.com/al4n4n/CVE-2026-115560) :  ![starts](https://img.shields.io/github/stars/al4n4n/CVE-2026-115560.svg) ![forks](https://img.shields.io/github/forks/al4n4n/CVE-2026-115560.svg)


## CVE-2026-11232
 Inappropriate implementation in TabGroups in Google Chrome prior to 149.0.7827.53 allowed a remote attacker to perform UI spoofing via malicious network traffic. (Chromium security severity: Low)

- [https://github.com/j0xh-sec/CVE-2026-112325](https://github.com/j0xh-sec/CVE-2026-112325) :  ![starts](https://img.shields.io/github/stars/j0xh-sec/CVE-2026-112325.svg) ![forks](https://img.shields.io/github/forks/j0xh-sec/CVE-2026-112325.svg)


## CVE-2026-10961
 Use after free in Chrome for iOS in Google Chrome on iOS prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/pruiz/php-CVE-2026-109618](https://github.com/pruiz/php-CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/pruiz/php-CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/pruiz/php-CVE-2026-109618.svg)
- [https://github.com/Chr1s-T/php2shell-cve-2026-109618](https://github.com/Chr1s-T/php2shell-cve-2026-109618) :  ![starts](https://img.shields.io/github/stars/Chr1s-T/php2shell-cve-2026-109618.svg) ![forks](https://img.shields.io/github/forks/Chr1s-T/php2shell-cve-2026-109618.svg)
- [https://github.com/SamJUK/php2shell-check-cve-2026-109618](https://github.com/SamJUK/php2shell-check-cve-2026-109618) :  ![starts](https://img.shields.io/github/stars/SamJUK/php2shell-check-cve-2026-109618.svg) ![forks](https://img.shields.io/github/forks/SamJUK/php2shell-check-cve-2026-109618.svg)
- [https://github.com/lzz0403/CVE-2026-109618-PHP2Shell-poc](https://github.com/lzz0403/CVE-2026-109618-PHP2Shell-poc) :  ![starts](https://img.shields.io/github/stars/lzz0403/CVE-2026-109618-PHP2Shell-poc.svg) ![forks](https://img.shields.io/github/forks/lzz0403/CVE-2026-109618-PHP2Shell-poc.svg)
- [https://github.com/pattingbabies/php2shell-CVE-2026-109618-109619](https://github.com/pattingbabies/php2shell-CVE-2026-109618-109619) :  ![starts](https://img.shields.io/github/stars/pattingbabies/php2shell-CVE-2026-109618-109619.svg) ![forks](https://img.shields.io/github/forks/pattingbabies/php2shell-CVE-2026-109618-109619.svg)
- [https://github.com/lucasbarros097/PHP2Shell__CVE-2026-109618__CVE2026-109619](https://github.com/lucasbarros097/PHP2Shell__CVE-2026-109618__CVE2026-109619) :  ![starts](https://img.shields.io/github/stars/lucasbarros097/PHP2Shell__CVE-2026-109618__CVE2026-109619.svg) ![forks](https://img.shields.io/github/forks/lucasbarros097/PHP2Shell__CVE-2026-109618__CVE2026-109619.svg)
- [https://github.com/GOLF2546/PHP2Shell-CVE-2026-109618-CVE-2026-109619](https://github.com/GOLF2546/PHP2Shell-CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/GOLF2546/PHP2Shell-CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/GOLF2546/PHP2Shell-CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/jeffschafer/Bigfix-PHP-Vulnerability-Scanner-Content-CVE-2026-109618-CVE-2026-109619](https://github.com/jeffschafer/Bigfix-PHP-Vulnerability-Scanner-Content-CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/jeffschafer/Bigfix-PHP-Vulnerability-Scanner-Content-CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/jeffschafer/Bigfix-PHP-Vulnerability-Scanner-Content-CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/delvin-45/php2shell-CVE-2026-109618-CVE-2026-109619-PoC](https://github.com/delvin-45/php2shell-CVE-2026-109618-CVE-2026-109619-PoC) :  ![starts](https://img.shields.io/github/stars/delvin-45/php2shell-CVE-2026-109618-CVE-2026-109619-PoC.svg) ![forks](https://img.shields.io/github/forks/delvin-45/php2shell-CVE-2026-109618-CVE-2026-109619-PoC.svg)


## CVE-2026-10678
The vulnerable code was introduced when the I2C+GPIO target binding was added and shipped in Zephyr v4.3.0 and v4.4.0. The fix defers allocation to the first data byte with a NULL check, treats a missing length as a zero-sized packet rejected by libmctp, and moves the bounds check before the store.

- [https://github.com/tanuj8124/CVE-2026-106781](https://github.com/tanuj8124/CVE-2026-106781) :  ![starts](https://img.shields.io/github/stars/tanuj8124/CVE-2026-106781.svg) ![forks](https://img.shields.io/github/forks/tanuj8124/CVE-2026-106781.svg)


## CVE-2026-3125
Additionally, Cloudflare Workers with Assets and Cloudflare Pages suffer from a similar vulnerability. Assets stored under /cdn-cgi/ paths are not publicly accessible under normal conditions. However, using the same backslash bypass (/cdn-cgi\... instead of /cdn-cgi/...), these assets become publicly accessible. This could be used to retrieve private data. For example, Open Next projects store incremental cache data under /cdn-cgi/_next_cache, which could be exposed via this bypass.

- [https://github.com/Ghost-Bx1/Cloudflare-Exploits-CVE-2026-14440-CVE-2026-3125-CVE-2025-0651](https://github.com/Ghost-Bx1/Cloudflare-Exploits-CVE-2026-14440-CVE-2026-3125-CVE-2025-0651) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/Cloudflare-Exploits-CVE-2026-14440-CVE-2026-3125-CVE-2025-0651.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/Cloudflare-Exploits-CVE-2026-14440-CVE-2026-3125-CVE-2025-0651.svg)


## CVE-2026-2113
 A security vulnerability has been detected in yuan1994 tpadmin up to 1.3.12. This affects an unknown part in the library /public/static/admin/lib/webuploader/0.1.5/server/preview.php of the component WebUploader. The manipulation leads to deserialization. The attack is possible to be carried out remotely. The exploit has been disclosed publicly and may be used. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/yora1928/cve_2026_2113](https://github.com/yora1928/cve_2026_2113) :  ![starts](https://img.shields.io/github/stars/yora1928/cve_2026_2113.svg) ![forks](https://img.shields.io/github/forks/yora1928/cve_2026_2113.svg)


## CVE-2026-1096
 The Best-wp-google-map plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'latitude' and 'longitudinal' parameters of the 'google_map_view' shortcode in all versions up to, and including, 2.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/tuanhoma/CVE-2026-109618](https://github.com/tuanhoma/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/tuanhoma/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/tuanhoma/CVE-2026-109618.svg)


## CVE-2026-0073
 In adbd_tls_verify_cert of auth.cpp, there is a possible bypass of wireless ADB mutual authentication due to a logic error in the code. This could lead to remote (proximal/adjacent) code execution as the shell user with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/umarrehmansiddiqui/CVE-2026-0073](https://github.com/umarrehmansiddiqui/CVE-2026-0073) :  ![starts](https://img.shields.io/github/stars/umarrehmansiddiqui/CVE-2026-0073.svg) ![forks](https://img.shields.io/github/forks/umarrehmansiddiqui/CVE-2026-0073.svg)
- [https://github.com/xqi1337/CVE-2026-0073-Android-ADBD-bypass-POC](https://github.com/xqi1337/CVE-2026-0073-Android-ADBD-bypass-POC) :  ![starts](https://img.shields.io/github/stars/xqi1337/CVE-2026-0073-Android-ADBD-bypass-POC.svg) ![forks](https://img.shields.io/github/forks/xqi1337/CVE-2026-0073-Android-ADBD-bypass-POC.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg)


## CVE-2025-26326
 A vulnerability was identified in the NVDA Remote (version 2.6.4) and Tele NVDA Remote (version 2025.3.3) remote connection add-ons, which allows an attacker to obtain total control of the remote system by guessing a weak password. The problem occurs because these add-ons accept any password entered by the user and do not have an additional authentication or computer verification mechanism. Tests indicate that more than 1,000 systems use easy-to-guess passwords, many with less than 4 to 6 characters, including common sequences. This allows brute force attacks or trial-and-error attempts by malicious invaders. The vulnerability can be exploited by a remote attacker who knows or can guess the password used in the connection. As a result, the attacker gains complete access to the affected system and can execute commands, modify files, and compromise user security.

- [https://github.com/ohackercego/CVE-2025-26326](https://github.com/ohackercego/CVE-2025-26326) :  ![starts](https://img.shields.io/github/stars/ohackercego/CVE-2025-26326.svg) ![forks](https://img.shields.io/github/forks/ohackercego/CVE-2025-26326.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg)


## CVE-2025-0651
This issue affects WARP: before 2024.12.492.0.

- [https://github.com/Ghost-Bx1/Cloudflare-Exploits-CVE-2026-14440-CVE-2026-3125-CVE-2025-0651](https://github.com/Ghost-Bx1/Cloudflare-Exploits-CVE-2026-14440-CVE-2026-3125-CVE-2025-0651) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/Cloudflare-Exploits-CVE-2026-14440-CVE-2026-3125-CVE-2025-0651.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/Cloudflare-Exploits-CVE-2026-14440-CVE-2026-3125-CVE-2025-0651.svg)


## CVE-2024-51482
 ZoneMinder is a free, open source closed-circuit television software application. ZoneMinder v1.37.* = 1.37.64 is vulnerable to boolean-based SQL Injection in function of web/ajax/event.php. This is fixed in 1.37.65.

- [https://github.com/Ravi-lk/CVE-2024-51482-ZoneMinder-SQL-Injection-POC](https://github.com/Ravi-lk/CVE-2024-51482-ZoneMinder-SQL-Injection-POC) :  ![starts](https://img.shields.io/github/stars/Ravi-lk/CVE-2024-51482-ZoneMinder-SQL-Injection-POC.svg) ![forks](https://img.shields.io/github/forks/Ravi-lk/CVE-2024-51482-ZoneMinder-SQL-Injection-POC.svg)


## CVE-2024-45409
 The Ruby SAML library is for implementing the client side of a SAML authorization. Ruby-SAML in = 12.2 and 1.13.0 = 1.16.0 does not properly verify the signature of the SAML Response. An unauthenticated attacker with access to any signed saml document (by the IdP) can thus forge a SAML Response/Assertion with arbitrary contents. This would allow the attacker to log in as arbitrary user within the vulnerable system. This vulnerability is fixed in 1.17.0 and 1.12.3.

- [https://github.com/barkotenicholas/CVE-2024-45409](https://github.com/barkotenicholas/CVE-2024-45409) :  ![starts](https://img.shields.io/github/stars/barkotenicholas/CVE-2024-45409.svg) ![forks](https://img.shields.io/github/forks/barkotenicholas/CVE-2024-45409.svg)


## CVE-2024-21762
 A out-of-bounds write vulnerability in Fortinet FortiOS 7.4.0 through 7.4.2, FortiOS 7.2.0 through 7.2.6, FortiOS 7.0.0 through 7.0.13, FortiOS 6.4.0 through 6.4.14, FortiOS 6.2.0 through 6.2.15, FortiOS 6.0 all versions, FortiProxy 7.4.0 through 7.4.2, FortiProxy 7.2.0 through 7.2.8, FortiProxy 7.0.0 through 7.0.14, FortiProxy 2.0.0 through 2.0.13, FortiProxy 01.02 all versions, FortiProxy 1.2 all versions, FortiProxy 01.01 all versions, FortiProxy 1.1 all versions, FortiProxy 01.00 all versions allows attacker to execute unauthorized code or commands via specifically crafted requests

- [https://github.com/izancxg/CVE-2024-21762-Safe-Check](https://github.com/izancxg/CVE-2024-21762-Safe-Check) :  ![starts](https://img.shields.io/github/stars/izancxg/CVE-2024-21762-Safe-Check.svg) ![forks](https://img.shields.io/github/forks/izancxg/CVE-2024-21762-Safe-Check.svg)


## CVE-2024-6387
 A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be able to trigger it by failing to authenticate within a set time period.

- [https://github.com/ohackercego/CVE-2024-6387-how-to-fix](https://github.com/ohackercego/CVE-2024-6387-how-to-fix) :  ![starts](https://img.shields.io/github/stars/ohackercego/CVE-2024-6387-how-to-fix.svg) ![forks](https://img.shields.io/github/forks/ohackercego/CVE-2024-6387-how-to-fix.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/CyberDefenderAI/AI-Threat-Detection-PHP-CGI-Vulnerabilities](https://github.com/CyberDefenderAI/AI-Threat-Detection-PHP-CGI-Vulnerabilities) :  ![starts](https://img.shields.io/github/stars/CyberDefenderAI/AI-Threat-Detection-PHP-CGI-Vulnerabilities.svg) ![forks](https://img.shields.io/github/forks/CyberDefenderAI/AI-Threat-Detection-PHP-CGI-Vulnerabilities.svg)


## CVE-2023-48795
 The SSH transport protocol with certain OpenSSH extensions, found in OpenSSH before 9.6 and other products, allows remote attackers to bypass integrity checks such that some packets are omitted (from the extension negotiation message), and a client and server may consequently end up with a connection for which some security features have been downgraded or disabled, aka a Terrapin attack. This occurs because the SSH Binary Packet Protocol (BPP), implemented by these extensions, mishandles the handshake phase and mishandles use of sequence numbers. For example, there is an effective attack against SSH's use of ChaCha20-Poly1305 (and CBC with Encrypt-then-MAC). The bypass occurs in chacha20-poly1305@openssh.com and (if CBC is used) the -etm@openssh.com MAC algorithms. This also affects Maverick Synergy Java SSH API before 3.1.0-SNAPSHOT, Dropbear through 2022.83, Ssh before 5.1.1 in Erlang/OTP, PuTTY before 0.80, AsyncSSH before 2.14.2, golang.org/x/crypto before 0.17.0, libssh before 0.10.6, libssh2 through 1.11.0, Thorn Tech SFTP Gateway before 3.4.6, Tera Term before 5.1, Paramiko before 3.4.0, jsch before 0.2.15, SFTPGo before 2.5.6, Netgate pfSense Plus through 23.09.1, Netgate pfSense CE through 2.7.2, HPN-SSH through 18.2.0, ProFTPD before 1.3.8b (and before 1.3.9rc2), ORYX CycloneSSH before 2.3.4, NetSarang XShell 7 before Build 0144, CrushFTP before 10.6.0, ConnectBot SSH library before 2.2.22, Apache MINA sshd through 2.11.0, sshj through 0.37.0, TinySSH through 20230101, trilead-ssh2 6401, LANCOM LCOS and LANconfig, FileZilla before 3.66.4, Nova before 11.8, PKIX-SSH before 14.4, SecureCRT before 9.4.3, Transmit5 before 5.10.4, Win32-OpenSSH before 9.5.0.0p1-Beta, WinSCP before 6.2.2, Bitvise SSH Server before 9.32, Bitvise SSH Client before 9.33, KiTTY through 0.76.1.13, the net-ssh gem 7.2.0 for Ruby, the mscdex ssh2 module before 1.15.0 for Node.js, the thrussh library before 0.35.1 for Rust, and the Russh crate before 0.40.2 for Rust.

- [https://github.com/breaksek/CVE-2023-48795](https://github.com/breaksek/CVE-2023-48795) :  ![starts](https://img.shields.io/github/stars/breaksek/CVE-2023-48795.svg) ![forks](https://img.shields.io/github/forks/breaksek/CVE-2023-48795.svg)


## CVE-2023-21839
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core).  Supported versions that are affected are 12.2.1.3.0, 12.2.1.4.0 and  14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Server.  Successful attacks of this vulnerability can result in  unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).

- [https://github.com/daybreak-kits/simple-scanner](https://github.com/daybreak-kits/simple-scanner) :  ![starts](https://img.shields.io/github/stars/daybreak-kits/simple-scanner.svg) ![forks](https://img.shields.io/github/forks/daybreak-kits/simple-scanner.svg)


## CVE-2023-21752
 Windows Backup Service Elevation of Privilege Vulnerability

- [https://github.com/SamDHarrison/Compiled-CVE-2023-21752](https://github.com/SamDHarrison/Compiled-CVE-2023-21752) :  ![starts](https://img.shields.io/github/stars/SamDHarrison/Compiled-CVE-2023-21752.svg) ![forks](https://img.shields.io/github/forks/SamDHarrison/Compiled-CVE-2023-21752.svg)


## CVE-2021-23410
 DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was withdrawn by its CNA. Further investigation showed that it was not a security issue. Notes: none

- [https://github.com/risvensehiraxt/msgpack-CVE-2021-23410-test.hpp](https://github.com/risvensehiraxt/msgpack-CVE-2021-23410-test.hpp) :  ![starts](https://img.shields.io/github/stars/risvensehiraxt/msgpack-CVE-2021-23410-test.hpp.svg) ![forks](https://img.shields.io/github/forks/risvensehiraxt/msgpack-CVE-2021-23410-test.hpp.svg)


## CVE-2021-22205
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 11.9. GitLab was not properly validating image files that were passed to a file parser which resulted in a remote command execution.

- [https://github.com/daybreak-kits/simple-scanner](https://github.com/daybreak-kits/simple-scanner) :  ![starts](https://img.shields.io/github/stars/daybreak-kits/simple-scanner.svg) ![forks](https://img.shields.io/github/forks/daybreak-kits/simple-scanner.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/asd58584388/CVE-2021-44228](https://github.com/asd58584388/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/asd58584388/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/asd58584388/CVE-2021-44228.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/sixpacksecurity/CVE-2021-41773](https://github.com/sixpacksecurity/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sixpacksecurity/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sixpacksecurity/CVE-2021-41773.svg)


## CVE-2020-37268
 Print Assumptions does not report that a definition was produced while universe checking was disabled when that definition reaches the caller through Parameter Inline in a module type. Applying a functor inlines the body of the parameter, and the inlining drops the record that the term was built under Unset Universe Checking, so the resulting constant carries no trace of the unsafe operation. A module implementation can therefore prove False using a universe inconsistency, expose it through an inlined parameter, and have Print Assumptions report the dependent proof as closed under the global context. Because Print Assumptions is the in-process audit used to confirm that a development rests on no unexpected assumptions, a dependency built this way passes that audit while proving arbitrary propositions. The standalone checker coqchk does reject the resulting compiled file. The project records this in dev/doc/critical-bugs.md under non-fixed bugs and rates the risk as moderate when coqchk is not used.

- [https://github.com/endrazine/rocq-cve-poc-12155](https://github.com/endrazine/rocq-cve-poc-12155) :  ![starts](https://img.shields.io/github/stars/endrazine/rocq-cve-poc-12155.svg) ![forks](https://img.shields.io/github/forks/endrazine/rocq-cve-poc-12155.svg)


## CVE-2020-25213
 The File Manager (wp-file-manager) plugin before 6.9 for WordPress allows remote attackers to upload and execute arbitrary PHP code because it renames an unsafe example elFinder connector file to have the .php extension. This, for example, allows attackers to run the elFinder upload (or mkfile and put) command to write PHP code into the wp-content/plugins/wp-file-manager/lib/files/ directory. This was exploited in the wild in August and September 2020.

- [https://github.com/rigby721/CEV-2020-25213_wp-file-manger_exploit](https://github.com/rigby721/CEV-2020-25213_wp-file-manger_exploit) :  ![starts](https://img.shields.io/github/stars/rigby721/CEV-2020-25213_wp-file-manger_exploit.svg) ![forks](https://img.shields.io/github/forks/rigby721/CEV-2020-25213_wp-file-manger_exploit.svg)


## CVE-2020-14883
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows high privileged attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 7.2 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/daybreak-kits/weblogicScanner](https://github.com/daybreak-kits/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/daybreak-kits/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/daybreak-kits/weblogicScanner.svg)


## CVE-2020-14882
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/daybreak-kits/weblogicScanner](https://github.com/daybreak-kits/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/daybreak-kits/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/daybreak-kits/weblogicScanner.svg)


## CVE-2020-14750
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/daybreak-kits/weblogicScanner](https://github.com/daybreak-kits/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/daybreak-kits/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/daybreak-kits/weblogicScanner.svg)


## CVE-2020-2883
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/daybreak-kits/weblogicScanner](https://github.com/daybreak-kits/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/daybreak-kits/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/daybreak-kits/weblogicScanner.svg)


## CVE-2020-2555
 Vulnerability in the Oracle Coherence product of Oracle Fusion Middleware (component: Caching,CacheStore,Invocation). Supported versions that are affected are 3.7.1.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle Coherence. Successful attacks of this vulnerability can result in takeover of Oracle Coherence. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/daybreak-kits/weblogicScanner](https://github.com/daybreak-kits/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/daybreak-kits/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/daybreak-kits/weblogicScanner.svg)


## CVE-2020-2551
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: WLS Core Components). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/daybreak-kits/weblogicScanner](https://github.com/daybreak-kits/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/daybreak-kits/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/daybreak-kits/weblogicScanner.svg)


## CVE-2019-2890
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Web Services). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0 and 12.2.1.3.0. Easily exploitable vulnerability allows high privileged attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 7.2 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/daybreak-kits/weblogicScanner](https://github.com/daybreak-kits/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/daybreak-kits/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/daybreak-kits/weblogicScanner.svg)


## CVE-2019-2888
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: EJB Container). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0 and 12.2.1.3.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized read access to a subset of Oracle WebLogic Server accessible data. CVSS 3.0 Base Score 5.3 (Confidentiality impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N).

- [https://github.com/daybreak-kits/weblogicScanner](https://github.com/daybreak-kits/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/daybreak-kits/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/daybreak-kits/weblogicScanner.svg)


## CVE-2019-2729
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Web Services). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0 and 12.2.1.3.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/daybreak-kits/weblogicScanner](https://github.com/daybreak-kits/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/daybreak-kits/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/daybreak-kits/weblogicScanner.svg)


## CVE-2019-2725
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Web Services). Supported versions that are affected are 10.3.6.0.0 and 12.1.3.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/daybreak-kits/weblogicScanner](https://github.com/daybreak-kits/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/daybreak-kits/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/daybreak-kits/weblogicScanner.svg)


## CVE-2019-2618
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0 and 12.2.1.3.0. Easily exploitable vulnerability allows high privileged attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data as well as unauthorized update, insert or delete access to some of Oracle WebLogic Server accessible data. CVSS 3.0 Base Score 5.5 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:N).

- [https://github.com/daybreak-kits/weblogicScanner](https://github.com/daybreak-kits/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/daybreak-kits/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/daybreak-kits/weblogicScanner.svg)


## CVE-2018-20062
 An issue was discovered in NoneCms V1.3. thinkphp/library/think/App.php allows remote attackers to execute arbitrary PHP code via crafted use of the filter parameter, as demonstrated by the s=index/\think\Request/input&filter=phpinfo&data=1 query string.

- [https://github.com/0xRar/ThinkPHP5_RCE](https://github.com/0xRar/ThinkPHP5_RCE) :  ![starts](https://img.shields.io/github/stars/0xRar/ThinkPHP5_RCE.svg) ![forks](https://img.shields.io/github/forks/0xRar/ThinkPHP5_RCE.svg)


## CVE-2018-3252
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/daybreak-kits/weblogicScanner](https://github.com/daybreak-kits/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/daybreak-kits/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/daybreak-kits/weblogicScanner.svg)


## CVE-2018-3245
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/daybreak-kits/weblogicScanner](https://github.com/daybreak-kits/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/daybreak-kits/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/daybreak-kits/weblogicScanner.svg)


## CVE-2018-3191
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/daybreak-kits/weblogicScanner](https://github.com/daybreak-kits/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/daybreak-kits/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/daybreak-kits/weblogicScanner.svg)


## CVE-2018-2894
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS - Web Services). Supported versions that are affected are 12.1.3.0, 12.2.1.2 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/daybreak-kits/weblogicScanner](https://github.com/daybreak-kits/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/daybreak-kits/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/daybreak-kits/weblogicScanner.svg)


## CVE-2018-2893
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.2 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/daybreak-kits/weblogicScanner](https://github.com/daybreak-kits/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/daybreak-kits/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/daybreak-kits/weblogicScanner.svg)


## CVE-2018-2628
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.2 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/daybreak-kits/weblogicScanner](https://github.com/daybreak-kits/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/daybreak-kits/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/daybreak-kits/weblogicScanner.svg)


## CVE-2017-1000028
 Oracle, GlassFish Server Open Source Edition 4.1 is vulnerable to both authenticated and unauthenticated Directory Traversal vulnerability, that can be exploited by issuing a specially crafted HTTP GET request.

- [https://github.com/skl233/hdu-is-work1](https://github.com/skl233/hdu-is-work1) :  ![starts](https://img.shields.io/github/stars/skl233/hdu-is-work1.svg) ![forks](https://img.shields.io/github/forks/skl233/hdu-is-work1.svg)


## CVE-2017-10271
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Security). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.1.0 and 12.2.1.2.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 7.5 (Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H).

- [https://github.com/daybreak-kits/weblogicScanner](https://github.com/daybreak-kits/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/daybreak-kits/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/daybreak-kits/weblogicScanner.svg)


## CVE-2017-5689
 An unprivileged network attacker could gain system privileges to provisioned Intel manageability SKUs: Intel Active Management Technology (AMT) and Intel Standard Manageability (ISM). An unprivileged local attacker could provision manageability features gaining unprivileged network or local system privileges on Intel manageability SKUs: Intel Active Management Technology (AMT), Intel Standard Manageability (ISM), and Intel Small Business Technology (SBT).

- [https://github.com/aix567/C-A-S](https://github.com/aix567/C-A-S) :  ![starts](https://img.shields.io/github/stars/aix567/C-A-S.svg) ![forks](https://img.shields.io/github/forks/aix567/C-A-S.svg)


## CVE-2017-3506
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Web Services). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.0, 12.2.1.1 and 12.2.1.2. Difficult to exploit vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification access to critical data or all Oracle WebLogic Server accessible data as well as unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.0 Base Score 7.4 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N).

- [https://github.com/daybreak-kits/weblogicScanner](https://github.com/daybreak-kits/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/daybreak-kits/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/daybreak-kits/weblogicScanner.svg)


## CVE-2017-3248
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.0 and 12.2.1.1. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS v3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).

- [https://github.com/daybreak-kits/weblogicScanner](https://github.com/daybreak-kits/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/daybreak-kits/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/daybreak-kits/weblogicScanner.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka "Dirty COW."

- [https://github.com/cbry-96/Dirty-Cow-Ubuntu-Server-16.04.1](https://github.com/cbry-96/Dirty-Cow-Ubuntu-Server-16.04.1) :  ![starts](https://img.shields.io/github/stars/cbry-96/Dirty-Cow-Ubuntu-Server-16.04.1.svg) ![forks](https://img.shields.io/github/forks/cbry-96/Dirty-Cow-Ubuntu-Server-16.04.1.svg)


## CVE-2016-3510
 Unspecified vulnerability in the Oracle WebLogic Server component in Oracle Fusion Middleware 10.3.6.0, 12.1.3.0, and 12.2.1.0 allows remote attackers to affect confidentiality, integrity, and availability via vectors related to WLS Core Components, a different vulnerability than CVE-2016-3586.

- [https://github.com/daybreak-kits/weblogicScanner](https://github.com/daybreak-kits/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/daybreak-kits/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/daybreak-kits/weblogicScanner.svg)


## CVE-2016-0638
 Unspecified vulnerability in the Oracle WebLogic Server component in Oracle Fusion Middleware 10.3.6, 12.1.2, 12.1.3, and 12.2.1 allows remote attackers to affect confidentiality, integrity, and availability via vectors related to Java Messaging Service.

- [https://github.com/daybreak-kits/weblogicScanner](https://github.com/daybreak-kits/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/daybreak-kits/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/daybreak-kits/weblogicScanner.svg)


## CVE-2015-1805
 The (1) pipe_read and (2) pipe_write implementations in fs/pipe.c in the Linux kernel before 3.16 do not properly consider the side effects of failed __copy_to_user_inatomic and __copy_from_user_inatomic calls, which allows local users to cause a denial of service (system crash) or possibly gain privileges via a crafted application, aka an "I/O vector array overrun."

- [https://github.com/cjn304/Root-My-Galaxy-S4](https://github.com/cjn304/Root-My-Galaxy-S4) :  ![starts](https://img.shields.io/github/stars/cjn304/Root-My-Galaxy-S4.svg) ![forks](https://img.shields.io/github/forks/cjn304/Root-My-Galaxy-S4.svg)


## CVE-2014-4210
 Unspecified vulnerability in the Oracle WebLogic Server component in Oracle Fusion Middleware 10.0.2.0 and 10.3.6.0 allows remote attackers to affect confidentiality via vectors related to WLS - Web Services.

- [https://github.com/daybreak-kits/weblogicScanner](https://github.com/daybreak-kits/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/daybreak-kits/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/daybreak-kits/weblogicScanner.svg)

