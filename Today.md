# Update 2026-11-21
## CVE-2026-133305
 sqlmap before 1.10.11.89 contains a credential exposure vulnerability that allows attackers to capture user-supplied Cookie and Authorization headers by redirecting requests to another host. Attackers controlling the scanned target or abusing an open redirect can make RedirectHandler.http_error_302 forward session cookies or bearer tokens to an attacker-controlled host.

- [https://github.com/VulnSVNC/CVE-2026-133305](https://github.com/VulnSVNC/CVE-2026-133305) :  ![starts](https://img.shields.io/github/stars/VulnSVNC/CVE-2026-133305.svg) ![forks](https://img.shields.io/github/forks/VulnSVNC/CVE-2026-133305.svg)


## CVE-2026-133274
 THC-Hydra through 9.7 contains a stack buffer overflow vulnerability in analyze_server_response() of hydra-http-form.c that allows malicious HTTP servers to corrupt memory via crafted Set-Cookie headers. Attackers can send a Set-Cookie header with an extra leading space followed by a repeated cookie name, causing a negative strncpy length that overflows tmpcookie and crashes Hydra.

- [https://github.com/VulnSVNC/CVE-2026-133274](https://github.com/VulnSVNC/CVE-2026-133274) :  ![starts](https://img.shields.io/github/stars/VulnSVNC/CVE-2026-133274.svg) ![forks](https://img.shields.io/github/forks/VulnSVNC/CVE-2026-133274.svg)


## CVE-2026-133235
 Tandoor Recipes before 2.7.4 contains a server-side request forgery vulnerability that allows space admins to reach internal hosts because Nextcloud.get_client builds WebDAV clients from Storage.url without calling safe_request. Attackers can create a NEXTCLOUD storage via POST /api/storage/ pointing at internal hosts, import a file, then call GET /api/get_recipe_file/id/ to read internal service or cloud metadata responses.

- [https://github.com/LLCForge/CVE-2026-133235](https://github.com/LLCForge/CVE-2026-133235) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-133235.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-133235.svg)


## CVE-2026-133234
 Stoatchat before 0.16.5 contains an unbounded JXL image decoding vulnerability in revolt_files decode_image that allows unauthenticated attackers to exhaust memory via the january /proxy endpoint. Attackers can request a small hosted JXL file declaring 12000x12000 pixels through /proxy to trigger huge allocations, OOM-killing january and denying proxy and embed service.

- [https://github.com/LLCForge/CVE-2026-133234](https://github.com/LLCForge/CVE-2026-133234) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-133234.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-133234.svg)


## CVE-2026-133185
 Goproxy before 1.9.4 contains a weak key generation vulnerability in NewCounterEncryptorRandFromKey that derives RSA and Ed25519 leaf certificate private keys from public data due to misuse of hash.Sum. Attackers with the CA certificate and one observed leaf certificate can regenerate that host's leaf private key and impersonate the host to clients trusting the proxy CA.

- [https://github.com/LLCForge/CVE-2026-133185](https://github.com/LLCForge/CVE-2026-133185) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-133185.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-133185.svg)


## CVE-2026-133173
 WatchAlert 2.0.0 through 3.9.20 contains an insecure direct object reference vulnerability in the /api/w8t/datasource/dataSourceGet endpoint that lets authenticated users read other tenants' datasources because lookups omit tenant_id filtering. Tenant members with datasource view permission can request another tenant's datasource ID to obtain basic auth passwords, AWS and Alibaba Cloud keys, and Kubernetes kubeconfigs.

- [https://github.com/LLCForge/CVE-2026-133173](https://github.com/LLCForge/CVE-2026-133173) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-133173.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-133173.svg)


## CVE-2026-133172
 Cozy Cloud cozy-stack 1.6.62 before 1.6.69 contains an authorization bypass vulnerability in the shared-drive move handler that allows authenticated users to access other instances' files. Attackers owning a shared drive can name another instance's domain and any directory ID as the move source to copy and delete the victim's file tree.

- [https://github.com/LLCForge/CVE-2026-133172](https://github.com/LLCForge/CVE-2026-133172) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-133172.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-133172.svg)


## CVE-2026-133168
 OFFIS DCMTK 3.7.1 contains a heap buffer overflow vulnerability in togglePlanarConfiguration8 and togglePlanarConfiguration16 in djcodece.cc, which compute row offsets using rows instead of columns. Attackers can supply a crafted color-by-plane DICOM image with more rows than columns that is compressed with the true-lossless JPEG codec to corrupt heap memory, causing crashes and potentially code execution.

- [https://github.com/LLCForge/CVE-2026-133168](https://github.com/LLCForge/CVE-2026-133168) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-133168.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-133168.svg)


## CVE-2026-133117
 WebToffee Product Feed before 2.4.4 for WordPress contains a use of hard-coded cryptographic key vulnerability that allows unauthenticated attackers to bypass the URL-cron signature check by computing a valid hash using the publicly known constant salt embedded in the plugin source. Attackers can send forged GET requests with attacker-controlled parameters to the unauthenticated init-hooked endpoint to repeatedly trigger product-feed generation, causing CPU/database resource exhaustion and overwriting of the generated feed file.

- [https://github.com/LLCForge/CVE-2026-133117](https://github.com/LLCForge/CVE-2026-133117) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-133117.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-133117.svg)


## CVE-2026-133114
 Caddy – WooCommerce Side Cart & Free Shipping Bar plugin for WordPress 3.0.0 before 3.2.1 contains a missing authorization vulnerability in the saved-items/add REST endpoint that exposes non-public product data. Authenticated attackers with Subscriber-level access can enumerate product_id values to read names, prices, images and stock status of private, draft, hidden and password-protected products.

- [https://github.com/LLCForge/CVE-2026-133114](https://github.com/LLCForge/CVE-2026-133114) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-133114.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-133114.svg)


## CVE-2026-133113
 Gogs through 0.14.4 contains an authorization bypass vulnerability that allows collaborators with write access to push to protected branches by merging pull requests. Because MergePullRequest skips branch protection checks and PullRequest.Merge omits hook environment variables, attackers can merge commits into branches restricted to allowlisted users.

- [https://github.com/LLCForge/CVE-2026-133113](https://github.com/LLCForge/CVE-2026-133113) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-133113.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-133113.svg)


## CVE-2026-132825
 Ruby before 3.3.14, 3.4.13, and 4.0.10 has a heap-based buffer overflow during case conversion. One byte can be written outside a buffer for, for example, ISO-8859-1 or Windows-1252.

- [https://github.com/evenomn/CVE-2026-132825](https://github.com/evenomn/CVE-2026-132825) :  ![starts](https://img.shields.io/github/stars/evenomn/CVE-2026-132825.svg) ![forks](https://img.shields.io/github/forks/evenomn/CVE-2026-132825.svg)
- [https://github.com/scadastrangelove/ruby2shell](https://github.com/scadastrangelove/ruby2shell) :  ![starts](https://img.shields.io/github/stars/scadastrangelove/ruby2shell.svg) ![forks](https://img.shields.io/github/forks/scadastrangelove/ruby2shell.svg)


## CVE-2026-132252
 A vulnerability was found in October CMS up to 4.4.6. This affects the function validateExternalImageHost of the file modules/system/classes/resizeimages/ValidatesExternalImages.php of the component Image Resizer. Performing a manipulation of the argument url results in server-side request forgery. The attack may be initiated remotely. The complexity of an attack is rather high. The exploitability is reported as difficult. The exploit has been made public and could be used. Upgrading to version 4.4.7 mitigates this issue. The patch is named f6372867006c03141944e7b57396a726eb02acf0. You should upgrade the affected component.

- [https://github.com/googlesky/CVE-2026-132252](https://github.com/googlesky/CVE-2026-132252) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-132252.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-132252.svg)


## CVE-2026-130648
 WWBN AVideo from 6.5 contains a stored cross-site scripting vulnerability that allows users with upload permission to inject script by submitting a javascript: scheme videoLink for embed videos. The unvalidated URL is rendered into an iframe src in videoEmbeded.php and PlayerSkins.php, executing for viewers including administrators and enabling creation of new administrator accounts.

- [https://github.com/LLCForge/CVE-2026-130648](https://github.com/LLCForge/CVE-2026-130648) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-130648.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-130648.svg)


## CVE-2026-129987
 Dokploy is a free, self-hostable Platform as a Service (PaaS). Prior to 0.31.1, the database password validation used by the MySQL, PostgreSQL, MariaDB, MongoDB, and Redis change-password procedures permits backticks, and the procedures interpolate attacker-controlled passwords into Bash command strings. An authenticated user who can update a database password can trigger command substitution before the database command runs, resulting in arbitrary operating-system command execution with the Dokploy process privileges, which are typically root. This issue is fixed in version 0.31.1.

- [https://github.com/evenomn/CVE-2026-129987](https://github.com/evenomn/CVE-2026-129987) :  ![starts](https://img.shields.io/github/stars/evenomn/CVE-2026-129987.svg) ![forks](https://img.shields.io/github/forks/evenomn/CVE-2026-129987.svg)


## CVE-2026-129496
This issue affects PHP versions before 8.2.36, 8.3.* before 8.3.37, 8.4.* before 8.4.28 and 8.5.* before 8.5.13.

- [https://github.com/abraxas/php-tzcache-rce](https://github.com/abraxas/php-tzcache-rce) :  ![starts](https://img.shields.io/github/stars/abraxas/php-tzcache-rce.svg) ![forks](https://img.shields.io/github/forks/abraxas/php-tzcache-rce.svg)


## CVE-2026-129289
This issue affects PHP versions before 8.2.36, 8.3.* before 8.3.37, 8.4.* before 8.4.28 and 8.5.* before 8.5.13.

- [https://github.com/HOSTED-POWER/php_uploadprogress_guard](https://github.com/HOSTED-POWER/php_uploadprogress_guard) :  ![starts](https://img.shields.io/github/stars/HOSTED-POWER/php_uploadprogress_guard.svg) ![forks](https://img.shields.io/github/forks/HOSTED-POWER/php_uploadprogress_guard.svg)


## CVE-2026-128134
 NLTK (Natural Language Toolkit) is a suite of open source Python modules, data sets, and tutorials supporting research and development in Natural Language Processing. Prior to 3.10.4, nltk.parse.dependencygraph.dot2img resolves the Graphviz dot executable through PATH but invokes the resulting absolute executable without routing through spawn_trusted, so resolve_trusted_executable ownership and writability validation and safe_env loader environment scrubbing do not run. A local low-privileged attacker who can write to a directory on a POSIX victim's PATH can plant or replace dot, and code executes as the victim when dot2img is called directly or DependencyGraph.repr_svg renders a graph. The current-working-directory-only bare-name vector is blocked and is not this vulnerability; this issue is the residual writable absolute PATH element bypass after CVE-2026-78680. This issue is fixed in version 3.10.4.

- [https://github.com/LLCForge/CVE-2026-128134](https://github.com/LLCForge/CVE-2026-128134) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-128134.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-128134.svg)


## CVE-2026-126714
This issue affects PHP versions before 8.2.36, 8.3.* before 8.3.37, 8.4.* before 8.4.28 and 8.5.* before 8.5.13.

- [https://github.com/HOSTED-POWER/php_uploadprogress_guard](https://github.com/HOSTED-POWER/php_uploadprogress_guard) :  ![starts](https://img.shields.io/github/stars/HOSTED-POWER/php_uploadprogress_guard.svg) ![forks](https://img.shields.io/github/forks/HOSTED-POWER/php_uploadprogress_guard.svg)
- [https://github.com/alvm/php2shell-eol-backport](https://github.com/alvm/php2shell-eol-backport) :  ![starts](https://img.shields.io/github/stars/alvm/php2shell-eol-backport.svg) ![forks](https://img.shields.io/github/forks/alvm/php2shell-eol-backport.svg)


## CVE-2026-124194
 Product ui does not warn user of unsafe actions in Microsoft Office Outlook allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/raktabhdutta/NTLM-HashLeak-Attack-Detection-or-Outlook-NTLM-HashLeak-CVE-2026-124194](https://github.com/raktabhdutta/NTLM-HashLeak-Attack-Detection-or-Outlook-NTLM-HashLeak-CVE-2026-124194) :  ![starts](https://img.shields.io/github/stars/raktabhdutta/NTLM-HashLeak-Attack-Detection-or-Outlook-NTLM-HashLeak-CVE-2026-124194.svg) ![forks](https://img.shields.io/github/forks/raktabhdutta/NTLM-HashLeak-Attack-Detection-or-Outlook-NTLM-HashLeak-CVE-2026-124194.svg)


## CVE-2026-123890
Telco Cloud Platform 3.0, 4.x, 5.0.x, 5.1.x, 5.2 and Telco Cloud Infrastructure 3.0 are also affected (see KB463116).

- [https://github.com/Quaerendir/check-cve-2026-123890](https://github.com/Quaerendir/check-cve-2026-123890) :  ![starts](https://img.shields.io/github/stars/Quaerendir/check-cve-2026-123890.svg) ![forks](https://img.shields.io/github/forks/Quaerendir/check-cve-2026-123890.svg)
- [https://github.com/Cyber-BansalAI/vmware-vcenter-2026](https://github.com/Cyber-BansalAI/vmware-vcenter-2026) :  ![starts](https://img.shields.io/github/stars/Cyber-BansalAI/vmware-vcenter-2026.svg) ![forks](https://img.shields.io/github/forks/Cyber-BansalAI/vmware-vcenter-2026.svg)


## CVE-2026-123634
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/HOSTED-POWER/nginx2root-patches](https://github.com/HOSTED-POWER/nginx2root-patches) :  ![starts](https://img.shields.io/github/stars/HOSTED-POWER/nginx2root-patches.svg) ![forks](https://img.shields.io/github/forks/HOSTED-POWER/nginx2root-patches.svg)
- [https://github.com/foxcornlab/nginx-scanner](https://github.com/foxcornlab/nginx-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/nginx-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/nginx-scanner.svg)
- [https://github.com/maizarrahman/nginx_cve_2026_audit](https://github.com/maizarrahman/nginx_cve_2026_audit) :  ![starts](https://img.shields.io/github/stars/maizarrahman/nginx_cve_2026_audit.svg) ![forks](https://img.shields.io/github/forks/maizarrahman/nginx_cve_2026_audit.svg)
- [https://github.com/ramenaru/nginx2root-playground](https://github.com/ramenaru/nginx2root-playground) :  ![starts](https://img.shields.io/github/stars/ramenaru/nginx2root-playground.svg) ![forks](https://img.shields.io/github/forks/ramenaru/nginx2root-playground.svg)


## CVE-2026-123633
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/HOSTED-POWER/nginx2root-patches](https://github.com/HOSTED-POWER/nginx2root-patches) :  ![starts](https://img.shields.io/github/stars/HOSTED-POWER/nginx2root-patches.svg) ![forks](https://img.shields.io/github/forks/HOSTED-POWER/nginx2root-patches.svg)
- [https://github.com/Mahgal/nginx-http2-rce-check](https://github.com/Mahgal/nginx-http2-rce-check) :  ![starts](https://img.shields.io/github/stars/Mahgal/nginx-http2-rce-check.svg) ![forks](https://img.shields.io/github/forks/Mahgal/nginx-http2-rce-check.svg)
- [https://github.com/foxcornlab/nginx-scanner](https://github.com/foxcornlab/nginx-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/nginx-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/nginx-scanner.svg)
- [https://github.com/0xsaju/nginx-exploits](https://github.com/0xsaju/nginx-exploits) :  ![starts](https://img.shields.io/github/stars/0xsaju/nginx-exploits.svg) ![forks](https://img.shields.io/github/forks/0xsaju/nginx-exploits.svg)
- [https://github.com/maizarrahman/nginx_cve_2026_audit](https://github.com/maizarrahman/nginx_cve_2026_audit) :  ![starts](https://img.shields.io/github/stars/maizarrahman/nginx_cve_2026_audit.svg) ![forks](https://img.shields.io/github/forks/maizarrahman/nginx_cve_2026_audit.svg)
- [https://github.com/githubcdr/nginx-ingress-controller](https://github.com/githubcdr/nginx-ingress-controller) :  ![starts](https://img.shields.io/github/stars/githubcdr/nginx-ingress-controller.svg) ![forks](https://img.shields.io/github/forks/githubcdr/nginx-ingress-controller.svg)
- [https://github.com/im0xfay/CVE-2026-123007](https://github.com/im0xfay/CVE-2026-123007) :  ![starts](https://img.shields.io/github/stars/im0xfay/CVE-2026-123007.svg) ![forks](https://img.shields.io/github/forks/im0xfay/CVE-2026-123007.svg)
- [https://github.com/ramenaru/nginx2root-playground](https://github.com/ramenaru/nginx2root-playground) :  ![starts](https://img.shields.io/github/stars/ramenaru/nginx2root-playground.svg) ![forks](https://img.shields.io/github/forks/ramenaru/nginx2root-playground.svg)


## CVE-2026-123007
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/HOSTED-POWER/nginx2root-patches](https://github.com/HOSTED-POWER/nginx2root-patches) :  ![starts](https://img.shields.io/github/stars/HOSTED-POWER/nginx2root-patches.svg) ![forks](https://img.shields.io/github/forks/HOSTED-POWER/nginx2root-patches.svg)
- [https://github.com/0xcypher110/nginx2root_lab](https://github.com/0xcypher110/nginx2root_lab) :  ![starts](https://img.shields.io/github/stars/0xcypher110/nginx2root_lab.svg) ![forks](https://img.shields.io/github/forks/0xcypher110/nginx2root_lab.svg)
- [https://github.com/akarkode/nginx-http2-cve-2026-123007-lab](https://github.com/akarkode/nginx-http2-cve-2026-123007-lab) :  ![starts](https://img.shields.io/github/stars/akarkode/nginx-http2-cve-2026-123007-lab.svg) ![forks](https://img.shields.io/github/forks/akarkode/nginx-http2-cve-2026-123007-lab.svg)
- [https://github.com/Mahgal/nginx-http2-rce-check](https://github.com/Mahgal/nginx-http2-rce-check) :  ![starts](https://img.shields.io/github/stars/Mahgal/nginx-http2-rce-check.svg) ![forks](https://img.shields.io/github/forks/Mahgal/nginx-http2-rce-check.svg)
- [https://github.com/foxcornlab/nginx-scanner](https://github.com/foxcornlab/nginx-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/nginx-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/nginx-scanner.svg)
- [https://github.com/DeFexNN/defex-ngnix](https://github.com/DeFexNN/defex-ngnix) :  ![starts](https://img.shields.io/github/stars/DeFexNN/defex-ngnix.svg) ![forks](https://img.shields.io/github/forks/DeFexNN/defex-ngnix.svg)
- [https://github.com/0xnrg/CVE-2026-123007](https://github.com/0xnrg/CVE-2026-123007) :  ![starts](https://img.shields.io/github/stars/0xnrg/CVE-2026-123007.svg) ![forks](https://img.shields.io/github/forks/0xnrg/CVE-2026-123007.svg)
- [https://github.com/im0xfay/CVE-2026-123007](https://github.com/im0xfay/CVE-2026-123007) :  ![starts](https://img.shields.io/github/stars/im0xfay/CVE-2026-123007.svg) ![forks](https://img.shields.io/github/forks/im0xfay/CVE-2026-123007.svg)
- [https://github.com/materaj2/cve-2026-123007-scanner](https://github.com/materaj2/cve-2026-123007-scanner) :  ![starts](https://img.shields.io/github/stars/materaj2/cve-2026-123007-scanner.svg) ![forks](https://img.shields.io/github/forks/materaj2/cve-2026-123007-scanner.svg)
- [https://github.com/yusif-v/cve-2026-123007-poc](https://github.com/yusif-v/cve-2026-123007-poc) :  ![starts](https://img.shields.io/github/stars/yusif-v/cve-2026-123007-poc.svg) ![forks](https://img.shields.io/github/forks/yusif-v/cve-2026-123007-poc.svg)
- [https://github.com/eh-amish/nginx2root--CVE-2026-123007](https://github.com/eh-amish/nginx2root--CVE-2026-123007) :  ![starts](https://img.shields.io/github/stars/eh-amish/nginx2root--CVE-2026-123007.svg) ![forks](https://img.shields.io/github/forks/eh-amish/nginx2root--CVE-2026-123007.svg)
- [https://github.com/aduli198/CVE-2026-123007_nginx2root](https://github.com/aduli198/CVE-2026-123007_nginx2root) :  ![starts](https://img.shields.io/github/stars/aduli198/CVE-2026-123007_nginx2root.svg) ![forks](https://img.shields.io/github/forks/aduli198/CVE-2026-123007_nginx2root.svg)
- [https://github.com/MazeResearch/nginx-h2-probe](https://github.com/MazeResearch/nginx-h2-probe) :  ![starts](https://img.shields.io/github/stars/MazeResearch/nginx-h2-probe.svg) ![forks](https://img.shields.io/github/forks/MazeResearch/nginx-h2-probe.svg)
- [https://github.com/0xsaju/nginx-exploits](https://github.com/0xsaju/nginx-exploits) :  ![starts](https://img.shields.io/github/stars/0xsaju/nginx-exploits.svg) ![forks](https://img.shields.io/github/forks/0xsaju/nginx-exploits.svg)
- [https://github.com/jenic/nginx2root-ioc-scan](https://github.com/jenic/nginx2root-ioc-scan) :  ![starts](https://img.shields.io/github/stars/jenic/nginx2root-ioc-scan.svg) ![forks](https://img.shields.io/github/forks/jenic/nginx2root-ioc-scan.svg)
- [https://github.com/SamJUK/nginx2root-check](https://github.com/SamJUK/nginx2root-check) :  ![starts](https://img.shields.io/github/stars/SamJUK/nginx2root-check.svg) ![forks](https://img.shields.io/github/forks/SamJUK/nginx2root-check.svg)
- [https://github.com/githubcdr/nginx-ingress-controller](https://github.com/githubcdr/nginx-ingress-controller) :  ![starts](https://img.shields.io/github/stars/githubcdr/nginx-ingress-controller.svg) ![forks](https://img.shields.io/github/forks/githubcdr/nginx-ingress-controller.svg)
- [https://github.com/c0re-i5/intbug-lab](https://github.com/c0re-i5/intbug-lab) :  ![starts](https://img.shields.io/github/stars/c0re-i5/intbug-lab.svg) ![forks](https://img.shields.io/github/forks/c0re-i5/intbug-lab.svg)
- [https://github.com/maizarrahman/nginx_cve_2026_audit](https://github.com/maizarrahman/nginx_cve_2026_audit) :  ![starts](https://img.shields.io/github/stars/maizarrahman/nginx_cve_2026_audit.svg) ![forks](https://img.shields.io/github/forks/maizarrahman/nginx_cve_2026_audit.svg)
- [https://github.com/josueportillo/nginx2root-scanner](https://github.com/josueportillo/nginx2root-scanner) :  ![starts](https://img.shields.io/github/stars/josueportillo/nginx2root-scanner.svg) ![forks](https://img.shields.io/github/forks/josueportillo/nginx2root-scanner.svg)
- [https://github.com/ramenaru/nginx2root-playground](https://github.com/ramenaru/nginx2root-playground) :  ![starts](https://img.shields.io/github/stars/ramenaru/nginx2root-playground.svg) ![forks](https://img.shields.io/github/forks/ramenaru/nginx2root-playground.svg)


## CVE-2026-121810
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/HOSTED-POWER/nginx2root-patches](https://github.com/HOSTED-POWER/nginx2root-patches) :  ![starts](https://img.shields.io/github/stars/HOSTED-POWER/nginx2root-patches.svg) ![forks](https://img.shields.io/github/forks/HOSTED-POWER/nginx2root-patches.svg)
- [https://github.com/foxcornlab/nginx-scanner](https://github.com/foxcornlab/nginx-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/nginx-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/nginx-scanner.svg)
- [https://github.com/maizarrahman/nginx_cve_2026_audit](https://github.com/maizarrahman/nginx_cve_2026_audit) :  ![starts](https://img.shields.io/github/stars/maizarrahman/nginx_cve_2026_audit.svg) ![forks](https://img.shields.io/github/forks/maizarrahman/nginx_cve_2026_audit.svg)
- [https://github.com/ramenaru/nginx2root-playground](https://github.com/ramenaru/nginx2root-playground) :  ![starts](https://img.shields.io/github/stars/ramenaru/nginx2root-playground.svg) ![forks](https://img.shields.io/github/forks/ramenaru/nginx2root-playground.svg)


## CVE-2026-119073
 The Live Composer  WordPress plugin before 2.1.23 does not escape a pagination setting supplied through its post-listing module shortcodes before outputting it in an HTML attribute, allowing users with the Contributor role and above to perform Stored Cross-Site Scripting attacks.

- [https://github.com/Shashi552/CVE-2026-119073-PoC](https://github.com/Shashi552/CVE-2026-119073-PoC) :  ![starts](https://img.shields.io/github/stars/Shashi552/CVE-2026-119073-PoC.svg) ![forks](https://img.shields.io/github/forks/Shashi552/CVE-2026-119073-PoC.svg)


## CVE-2026-118899
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/foxcornlab/nginx-scanner](https://github.com/foxcornlab/nginx-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/nginx-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/nginx-scanner.svg)


## CVE-2026-116448
 Dell PowerStore SDNAS contains an OS Command Injection vulnerability that could allow an attacker with internal network access to execute arbitrary commands as root on the NAS node.

- [https://github.com/LLCForge/CVE-2026-116448](https://github.com/LLCForge/CVE-2026-116448) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-116448.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-116448.svg)


## CVE-2026-116442
 Dell PowerStore SDNAS contains an authentication-bypass-by-replay vulnerability in the NAS NDMP service that could allow a network attacker to gain backup and restore control of the appliance.

- [https://github.com/LLCForge/CVE-2026-116442](https://github.com/LLCForge/CVE-2026-116442) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-116442.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-116442.svg)


## CVE-2026-115560
This issue affects PHP versions before 8.2.36, 8.3.* before 8.3.37, 8.4.* before 8.4.28 and 8.5.* before 8.5.13.

- [https://github.com/syhunt/php2shell-protection](https://github.com/syhunt/php2shell-protection) :  ![starts](https://img.shields.io/github/stars/syhunt/php2shell-protection.svg) ![forks](https://img.shields.io/github/forks/syhunt/php2shell-protection.svg)
- [https://github.com/murrez/php2shell](https://github.com/murrez/php2shell) :  ![starts](https://img.shields.io/github/stars/murrez/php2shell.svg) ![forks](https://img.shields.io/github/forks/murrez/php2shell.svg)
- [https://github.com/PasqualePillitteri/php2shell-hardening](https://github.com/PasqualePillitteri/php2shell-hardening) :  ![starts](https://img.shields.io/github/stars/PasqualePillitteri/php2shell-hardening.svg) ![forks](https://img.shields.io/github/forks/PasqualePillitteri/php2shell-hardening.svg)
- [https://github.com/sykeops/CVE-2026-115560](https://github.com/sykeops/CVE-2026-115560) :  ![starts](https://img.shields.io/github/stars/sykeops/CVE-2026-115560.svg) ![forks](https://img.shields.io/github/forks/sykeops/CVE-2026-115560.svg)
- [https://github.com/KtebhTeam/php2shell](https://github.com/KtebhTeam/php2shell) :  ![starts](https://img.shields.io/github/stars/KtebhTeam/php2shell.svg) ![forks](https://img.shields.io/github/forks/KtebhTeam/php2shell.svg)
- [https://github.com/googlesky/CVE-2026-115560](https://github.com/googlesky/CVE-2026-115560) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-115560.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-115560.svg)
- [https://github.com/slabbdev/php-cve-2026-115560-kit](https://github.com/slabbdev/php-cve-2026-115560-kit) :  ![starts](https://img.shields.io/github/stars/slabbdev/php-cve-2026-115560-kit.svg) ![forks](https://img.shields.io/github/forks/slabbdev/php-cve-2026-115560-kit.svg)
- [https://github.com/prnjlksingh/php-cve-2026-115560-demo](https://github.com/prnjlksingh/php-cve-2026-115560-demo) :  ![starts](https://img.shields.io/github/stars/prnjlksingh/php-cve-2026-115560-demo.svg) ![forks](https://img.shields.io/github/forks/prnjlksingh/php-cve-2026-115560-demo.svg)
- [https://github.com/Pr0fEs0r-X/PHP2SHELL-Checker-v-1.0-CVE-2026-115560-](https://github.com/Pr0fEs0r-X/PHP2SHELL-Checker-v-1.0-CVE-2026-115560-) :  ![starts](https://img.shields.io/github/stars/Pr0fEs0r-X/PHP2SHELL-Checker-v-1.0-CVE-2026-115560-.svg) ![forks](https://img.shields.io/github/forks/Pr0fEs0r-X/PHP2SHELL-Checker-v-1.0-CVE-2026-115560-.svg)
- [https://github.com/SirjanSingh/php2shell-check](https://github.com/SirjanSingh/php2shell-check) :  ![starts](https://img.shields.io/github/stars/SirjanSingh/php2shell-check.svg) ![forks](https://img.shields.io/github/forks/SirjanSingh/php2shell-check.svg)
- [https://github.com/ivst/CVE-2026-115560](https://github.com/ivst/CVE-2026-115560) :  ![starts](https://img.shields.io/github/stars/ivst/CVE-2026-115560.svg) ![forks](https://img.shields.io/github/forks/ivst/CVE-2026-115560.svg)
- [https://github.com/basesixtythree/B63-POC-CVE-2026-115560](https://github.com/basesixtythree/B63-POC-CVE-2026-115560) :  ![starts](https://img.shields.io/github/stars/basesixtythree/B63-POC-CVE-2026-115560.svg) ![forks](https://img.shields.io/github/forks/basesixtythree/B63-POC-CVE-2026-115560.svg)
- [https://github.com/Pr0fEs0r-X/PHP2SHELL-Checker-v-2.0-CVE-2026-115560-](https://github.com/Pr0fEs0r-X/PHP2SHELL-Checker-v-2.0-CVE-2026-115560-) :  ![starts](https://img.shields.io/github/stars/Pr0fEs0r-X/PHP2SHELL-Checker-v-2.0-CVE-2026-115560-.svg) ![forks](https://img.shields.io/github/forks/Pr0fEs0r-X/PHP2SHELL-Checker-v-2.0-CVE-2026-115560-.svg)
- [https://github.com/JoshRob297/php2shell-research](https://github.com/JoshRob297/php2shell-research) :  ![starts](https://img.shields.io/github/stars/JoshRob297/php2shell-research.svg) ![forks](https://img.shields.io/github/forks/JoshRob297/php2shell-research.svg)
- [https://github.com/CyberRick-AI/php2shell-check](https://github.com/CyberRick-AI/php2shell-check) :  ![starts](https://img.shields.io/github/stars/CyberRick-AI/php2shell-check.svg) ![forks](https://img.shields.io/github/forks/CyberRick-AI/php2shell-check.svg)
- [https://github.com/Leviticus-Triage/php2shell-unchained](https://github.com/Leviticus-Triage/php2shell-unchained) :  ![starts](https://img.shields.io/github/stars/Leviticus-Triage/php2shell-unchained.svg) ![forks](https://img.shields.io/github/forks/Leviticus-Triage/php2shell-unchained.svg)
- [https://github.com/esskslifetech/php-secure-patch](https://github.com/esskslifetech/php-secure-patch) :  ![starts](https://img.shields.io/github/stars/esskslifetech/php-secure-patch.svg) ![forks](https://img.shields.io/github/forks/esskslifetech/php-secure-patch.svg)
- [https://github.com/renzi25031469/CVE-2026-115560](https://github.com/renzi25031469/CVE-2026-115560) :  ![starts](https://img.shields.io/github/stars/renzi25031469/CVE-2026-115560.svg) ![forks](https://img.shields.io/github/forks/renzi25031469/CVE-2026-115560.svg)
- [https://github.com/LLCForge/CVE-2026-115560](https://github.com/LLCForge/CVE-2026-115560) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-115560.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-115560.svg)
- [https://github.com/al4n4n/CVE-2026-115560](https://github.com/al4n4n/CVE-2026-115560) :  ![starts](https://img.shields.io/github/stars/al4n4n/CVE-2026-115560.svg) ![forks](https://img.shields.io/github/forks/al4n4n/CVE-2026-115560.svg)
- [https://github.com/yora1928/cve_2026_115560_by_yora](https://github.com/yora1928/cve_2026_115560_by_yora) :  ![starts](https://img.shields.io/github/stars/yora1928/cve_2026_115560_by_yora.svg) ![forks](https://img.shields.io/github/forks/yora1928/cve_2026_115560_by_yora.svg)
- [https://github.com/Pr0fEs0r-X/PHP-CVE-2026-115560-Cheker-v-1.0](https://github.com/Pr0fEs0r-X/PHP-CVE-2026-115560-Cheker-v-1.0) :  ![starts](https://img.shields.io/github/stars/Pr0fEs0r-X/PHP-CVE-2026-115560-Cheker-v-1.0.svg) ![forks](https://img.shields.io/github/forks/Pr0fEs0r-X/PHP-CVE-2026-115560-Cheker-v-1.0.svg)
- [https://github.com/Suman99pro/php2shell-check](https://github.com/Suman99pro/php2shell-check) :  ![starts](https://img.shields.io/github/stars/Suman99pro/php2shell-check.svg) ![forks](https://img.shields.io/github/forks/Suman99pro/php2shell-check.svg)
- [https://github.com/PVY-Smit/php2shell-defender](https://github.com/PVY-Smit/php2shell-defender) :  ![starts](https://img.shields.io/github/stars/PVY-Smit/php2shell-defender.svg) ![forks](https://img.shields.io/github/forks/PVY-Smit/php2shell-defender.svg)
- [https://github.com/mamarce/php-vulns-discovered-23-10-2026](https://github.com/mamarce/php-vulns-discovered-23-10-2026) :  ![starts](https://img.shields.io/github/stars/mamarce/php-vulns-discovered-23-10-2026.svg) ![forks](https://img.shields.io/github/forks/mamarce/php-vulns-discovered-23-10-2026.svg)
- [https://github.com/JAvito-GC/php2shell-check](https://github.com/JAvito-GC/php2shell-check) :  ![starts](https://img.shields.io/github/stars/JAvito-GC/php2shell-check.svg) ![forks](https://img.shields.io/github/forks/JAvito-GC/php2shell-check.svg)
- [https://github.com/Nguemoue/project2026_20261023_php_rce_guard](https://github.com/Nguemoue/project2026_20261023_php_rce_guard) :  ![starts](https://img.shields.io/github/stars/Nguemoue/project2026_20261023_php_rce_guard.svg) ![forks](https://img.shields.io/github/forks/Nguemoue/project2026_20261023_php_rce_guard.svg)
- [https://github.com/GarphenGate/php2shell-defender-toolkit](https://github.com/GarphenGate/php2shell-defender-toolkit) :  ![starts](https://img.shields.io/github/stars/GarphenGate/php2shell-defender-toolkit.svg) ![forks](https://img.shields.io/github/forks/GarphenGate/php2shell-defender-toolkit.svg)
- [https://github.com/avego/php2shell](https://github.com/avego/php2shell) :  ![starts](https://img.shields.io/github/stars/avego/php2shell.svg) ![forks](https://img.shields.io/github/forks/avego/php2shell.svg)


## CVE-2026-114952
 Vulnerability in the MySQL Server, MySQL Cluster product of Oracle MySQL (component: Client programs).  Supported versions that are affected are MySQL Server: 8.4.0-8.4.13, 9.7.0-9.7.4, 26.10; MySQL Cluster: 8.0.0-8.0.50, 8.4.0-8.4.13, 9.7.0-9.7.4 and  26.10. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise MySQL Server, MySQL Cluster.  Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all MySQL Server, MySQL Cluster accessible data as well as  unauthorized access to critical data or complete access to all MySQL Server, MySQL Cluster accessible data. CVSS 3.1 Base Score 9.1 (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N).

- [https://github.com/Quaerendir/cve-2026-114952-mysql-audit](https://github.com/Quaerendir/cve-2026-114952-mysql-audit) :  ![starts](https://img.shields.io/github/stars/Quaerendir/cve-2026-114952-mysql-audit.svg) ![forks](https://img.shields.io/github/forks/Quaerendir/cve-2026-114952-mysql-audit.svg)


## CVE-2026-114938
 Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Compiler).  Supported versions that are affected are Oracle Java SE: 8u511b33-perf, 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3; Oracle GraalVM for JDK: 17.0.21.0.3 and  21.0.13.0.3; Oracle GraalVM Enterprise Edition: 21.3.20.0.3. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in takeover of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition. Note: This vulnerability can only be exploited by supplying data to APIs in the specified Component without using Untrusted Java Web Start applications or Untrusted Java applets, such as through a web service. CVSS 3.1 Base Score 8.1 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/tc4dy/CVE-2026-114938-Toolkit](https://github.com/tc4dy/CVE-2026-114938-Toolkit) :  ![starts](https://img.shields.io/github/stars/tc4dy/CVE-2026-114938-Toolkit.svg) ![forks](https://img.shields.io/github/forks/tc4dy/CVE-2026-114938-Toolkit.svg)
- [https://github.com/MazeResearch/java4shell-check](https://github.com/MazeResearch/java4shell-check) :  ![starts](https://img.shields.io/github/stars/MazeResearch/java4shell-check.svg) ![forks](https://img.shields.io/github/forks/MazeResearch/java4shell-check.svg)
- [https://github.com/alt3kx/CVE-2026-114938](https://github.com/alt3kx/CVE-2026-114938) :  ![starts](https://img.shields.io/github/stars/alt3kx/CVE-2026-114938.svg) ![forks](https://img.shields.io/github/forks/alt3kx/CVE-2026-114938.svg)
- [https://github.com/uxokpro1234/Java4Shell-CVE-2026-114938-Defender](https://github.com/uxokpro1234/Java4Shell-CVE-2026-114938-Defender) :  ![starts](https://img.shields.io/github/stars/uxokpro1234/Java4Shell-CVE-2026-114938-Defender.svg) ![forks](https://img.shields.io/github/forks/uxokpro1234/Java4Shell-CVE-2026-114938-Defender.svg)
- [https://github.com/shivabalaj/CVE-2026-114938](https://github.com/shivabalaj/CVE-2026-114938) :  ![starts](https://img.shields.io/github/stars/shivabalaj/CVE-2026-114938.svg) ![forks](https://img.shields.io/github/forks/shivabalaj/CVE-2026-114938.svg)
- [https://github.com/gbuyssens/CVE-2026-114938](https://github.com/gbuyssens/CVE-2026-114938) :  ![starts](https://img.shields.io/github/stars/gbuyssens/CVE-2026-114938.svg) ![forks](https://img.shields.io/github/forks/gbuyssens/CVE-2026-114938.svg)
- [https://github.com/gbuyssens/CVE-2026-114938-Check](https://github.com/gbuyssens/CVE-2026-114938-Check) :  ![starts](https://img.shields.io/github/stars/gbuyssens/CVE-2026-114938-Check.svg) ![forks](https://img.shields.io/github/forks/gbuyssens/CVE-2026-114938-Check.svg)
- [https://github.com/kjry8sb/java4shell_CVE-2026-114938](https://github.com/kjry8sb/java4shell_CVE-2026-114938) :  ![starts](https://img.shields.io/github/stars/kjry8sb/java4shell_CVE-2026-114938.svg) ![forks](https://img.shields.io/github/forks/kjry8sb/java4shell_CVE-2026-114938.svg)
- [https://github.com/Jerczey/java4shell-ansible-detection](https://github.com/Jerczey/java4shell-ansible-detection) :  ![starts](https://img.shields.io/github/stars/Jerczey/java4shell-ansible-detection.svg) ![forks](https://img.shields.io/github/forks/Jerczey/java4shell-ansible-detection.svg)
- [https://github.com/Bluefire-Redteam-Cybersecurity/bluefire-java4shell-guard](https://github.com/Bluefire-Redteam-Cybersecurity/bluefire-java4shell-guard) :  ![starts](https://img.shields.io/github/stars/Bluefire-Redteam-Cybersecurity/bluefire-java4shell-guard.svg) ![forks](https://img.shields.io/github/forks/Bluefire-Redteam-Cybersecurity/bluefire-java4shell-guard.svg)
- [https://github.com/rzkyp/java4shell-lab](https://github.com/rzkyp/java4shell-lab) :  ![starts](https://img.shields.io/github/stars/rzkyp/java4shell-lab.svg) ![forks](https://img.shields.io/github/forks/rzkyp/java4shell-lab.svg)
- [https://github.com/FoxKyong/java4shell-checks](https://github.com/FoxKyong/java4shell-checks) :  ![starts](https://img.shields.io/github/stars/FoxKyong/java4shell-checks.svg) ![forks](https://img.shields.io/github/forks/FoxKyong/java4shell-checks.svg)
- [https://github.com/bh679/mcjavasafetycheck-mc](https://github.com/bh679/mcjavasafetycheck-mc) :  ![starts](https://img.shields.io/github/stars/bh679/mcjavasafetycheck-mc.svg) ![forks](https://img.shields.io/github/forks/bh679/mcjavasafetycheck-mc.svg)


## CVE-2026-113425
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/HOSTED-POWER/nginx2root-patches](https://github.com/HOSTED-POWER/nginx2root-patches) :  ![starts](https://img.shields.io/github/stars/HOSTED-POWER/nginx2root-patches.svg) ![forks](https://img.shields.io/github/forks/HOSTED-POWER/nginx2root-patches.svg)
- [https://github.com/foxcornlab/nginx-scanner](https://github.com/foxcornlab/nginx-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/nginx-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/nginx-scanner.svg)
- [https://github.com/maizarrahman/nginx_cve_2026_audit](https://github.com/maizarrahman/nginx_cve_2026_audit) :  ![starts](https://img.shields.io/github/stars/maizarrahman/nginx_cve_2026_audit.svg) ![forks](https://img.shields.io/github/forks/maizarrahman/nginx_cve_2026_audit.svg)
- [https://github.com/ramenaru/nginx2root-playground](https://github.com/ramenaru/nginx2root-playground) :  ![starts](https://img.shields.io/github/stars/ramenaru/nginx2root-playground.svg) ![forks](https://img.shields.io/github/forks/ramenaru/nginx2root-playground.svg)


## CVE-2026-112477
 A race condition was addressed with improved locking. This issue is fixed in iOS 26.7.2 and iPadOS 26.7.2, iOS 27.2 and iPadOS 27.2, macOS Golden Gate 27.2, macOS Sequoia 15.8.2, macOS Tahoe 26.7.2, tvOS 27.2, visionOS 27.2, watchOS 27.2. An app may be able to cause unexpected system termination or corrupt kernel memory.

- [https://github.com/Rust505/CVE-2026-112477](https://github.com/Rust505/CVE-2026-112477) :  ![starts](https://img.shields.io/github/stars/Rust505/CVE-2026-112477.svg) ![forks](https://img.shields.io/github/forks/Rust505/CVE-2026-112477.svg)


## CVE-2026-110486
 In Eclipse Mosquitto versions 2.1 through 2.1.2, a listener configured with `protocol websockets` mishandles empty WebSocket data frames. `net__read_ws()` in `lib/net_ws.c` returns the number of framing bytes consumed (the 4 masking-key bytes) for a data frame with a zero-length payload, without writing any bytes to the caller’s buffer. The MQTT packet reader in `packet__read_single()` (`lib/packet_mosq.c`) trusts that return value as a payload byte count. A remote client can therefore advance the read position over an uninitialised heap allocation, causing the broker to process and forward uninitialised heap memory (information disclosure, including heap and libc pointers), and can underflow the unsigned `to_process` counter so that subsequent attacker-controlled frame data is written past the end of the allocation (heap out-of-bounds write). The out-of-bounds write is reachable from the CONNECT packet before any authentication check, so an unauthenticated client can corrupt the heap and crash the broker even when `allow_anonymous false` is set. Combining the disclosure and the write allows remote code execution as the broker’s user by any client able to establish a session.

- [https://github.com/googlesky/CVE-2026-110486](https://github.com/googlesky/CVE-2026-110486) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-110486.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-110486.svg)


## CVE-2026-109619
 PHP has various global state that temporarily points into request memory. In some scenarios, global state may not be correctly reset, or may be repopulated after being reset. The global state may then refer to request memory even after it has been freed. Subsequent requests may read or branch on this stale state before it is fully initialized. Multiple strategies can trigger this condition and produce remote code execution (RCE).

- [https://github.com/xbuddhi/php2shell-fix](https://github.com/xbuddhi/php2shell-fix) :  ![starts](https://img.shields.io/github/stars/xbuddhi/php2shell-fix.svg) ![forks](https://img.shields.io/github/forks/xbuddhi/php2shell-fix.svg)
- [https://github.com/xaviware/go-php2shell-scanner-CVE-2026-109618-CVE-2026-109619](https://github.com/xaviware/go-php2shell-scanner-CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/xaviware/go-php2shell-scanner-CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/xaviware/go-php2shell-scanner-CVE-2026-109618-CVE-2026-109619.svg)


## CVE-2026-98432
will be addressed in a separate patch.

- [https://github.com/lwmacct/261119-cve-2026-98432](https://github.com/lwmacct/261119-cve-2026-98432) :  ![starts](https://img.shields.io/github/stars/lwmacct/261119-cve-2026-98432.svg) ![forks](https://img.shields.io/github/forks/lwmacct/261119-cve-2026-98432.svg)


## CVE-2026-97798
 Improper neutralization of argument delimiters in a command ('argument injection') in Windows Error Reporting allows an authorized attacker to elevate privileges locally.

- [https://github.com/noname2kz/LPE_CVE-2026-97798_Research](https://github.com/noname2kz/LPE_CVE-2026-97798_Research) :  ![starts](https://img.shields.io/github/stars/noname2kz/LPE_CVE-2026-97798_Research.svg) ![forks](https://img.shields.io/github/forks/noname2kz/LPE_CVE-2026-97798_Research.svg)


## CVE-2026-93295
The vulnerability requires the ability to submit the events/contact form (or any other endpoint that forwards user input into background job arguments). No special timing or race condition is required; the attack is deterministic once the crafted parameters are accepted. The impact is full remote code execution in the context of the MISP web server process, allowing data exfiltration, persistence, and lateral movement within the host.

- [https://github.com/CXu0630/CVE-2026-93295_MISP_RCE_Proof-of-Concept](https://github.com/CXu0630/CVE-2026-93295_MISP_RCE_Proof-of-Concept) :  ![starts](https://img.shields.io/github/stars/CXu0630/CVE-2026-93295_MISP_RCE_Proof-of-Concept.svg) ![forks](https://img.shields.io/github/forks/CXu0630/CVE-2026-93295_MISP_RCE_Proof-of-Concept.svg)


## CVE-2026-90436
As Axis 1 has been EOL we recommend you migrate to a different SOAP engine, such as Apache Axis 2/Java. Alternatively you could use a build of Axis with the patch from https://github.com/apache/axis-axis1-java/commit/41f3b4e8d04e310ca81f86b92630ab2c11d608bd applied. The Apache Axis project does not expect to create an Axis 1.x release fixing this problem.

- [https://github.com/evenomn/CVE-2026-90436](https://github.com/evenomn/CVE-2026-90436) :  ![starts](https://img.shields.io/github/stars/evenomn/CVE-2026-90436.svg) ![forks](https://img.shields.io/github/forks/evenomn/CVE-2026-90436.svg)


## CVE-2026-75521
 Miren Runtime provides the runtime component for the Miren application platform. Prior to 0.11.1, the QUIC/HTTP3 RPC server on the default port 8443 uses tls.RequestClientCert and does not verify that presented certificates chain to the configured cluster certificate authority. The RPC authenticators derive a caller identity from PeerCertificates[0].Subject.CommonName without requiring a non-empty VerifiedChains value, and certificate identities bypass all RBAC checks. A network attacker who can reach the listener can present a self-signed certificate with an issuer distinguished name matching the public cluster CA subject and gain cluster superuser access, allowing disclosure, modification, or disruption of applications, sandboxes, disks, credentials, and other managed resources. This issue is fixed in version 0.11.1.

- [https://github.com/LLCForge/CVE-2026-75521](https://github.com/LLCForge/CVE-2026-75521) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-75521.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-75521.svg)


## CVE-2026-73504
 cassandra-jdbc-wrapper provides a JDBC-compliant API over the Java driver for Apache Cassandra. Prior to 4.16.4 and 5.0.2, DriverUtil.toStringWithoutSensitiveValues() and DriverUtil.redactSensitiveValuesInJdbcUrl() redact the password property but not the equally sensitive token property used for DataStax Astra and other token-based authentication. When DEBUG logging is enabled, SessionHolder passes connection properties and JDBC URLs containing token through these helpers, causing the live token to be written in plaintext when connections are acquired or released. An attacker who can read those logs can use the token to access Cassandra data and operations authorized to that credential. This issue is fixed in versions 4.16.4 and 5.0.2.

- [https://github.com/googlesky/CVE-2026-73504](https://github.com/googlesky/CVE-2026-73504) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-73504.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-73504.svg)


## CVE-2026-71481
 ALTCHA PHP is a lightweight PHP library for creating and verifying ALTCHA challenges. From 2.0.0 until 2.0.3, the verifySolution method skips HMAC signature verification when a challenge payload omits the signature field, even when hmacSignatureSecret is configured. An attacker can remove the signature, supply attacker-selected low-difficulty challenge parameters, solve the resulting proof of work, and submit a payload that verifies successfully, bypassing the CAPTCHA control. This issue is fixed in version 2.0.3.

- [https://github.com/LLCForge/CVE-2026-71481](https://github.com/LLCForge/CVE-2026-71481) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-71481.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-71481.svg)


## CVE-2026-69158
 Atomic Server is an open source headless CMS and real-time database. Prior to 0.40.3, unauthenticated requests to /bookmark can supply a url that server/src/plugins/bookmark.rs passes through fetch_data to fetch_body. Endpoint dispatch in lib/src/db.rs invokes the handler before check_read, and lib/src/client/helpers.rs previously checked only that the URL began with HTTP, without restricting loopback, private, link-local, DNS-rebinding, or redirect targets. The handler reflects fetched content in returned resource fields, making this a full-response server-side request forgery that can expose internal services and plain-GET cloud metadata. The short request timeout limits slow targets, and metadata services requiring a separate token request are outside the demonstrated GET-only path. This issue is fixed in version 0.40.3.

- [https://github.com/LLCForge/CVE-2026-69158](https://github.com/LLCForge/CVE-2026-69158) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-69158.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-69158.svg)


## CVE-2026-69157
 Atomic Server is an open source headless CMS and real-time database. From 0.29.0 to 0.40.2, Atomic Server provisions a well-known /setup invite with write enabled, the Drive root as its target, and usagesLeft set to one. construct_invite_redirect in server/src/plugins/invite.rs discards the redeemer identity, so an unauthenticated request containing an attacker-controlled public-key can create a new Agent and grant it write access to the entire Drive. On a fresh, unclaimed deployment, this permits reading, modifying, or deleting resources, changing permissions, and creating or altering Agents. No complete fixed version was verified as of this review.

- [https://github.com/LLCForge/CVE-2026-69157](https://github.com/LLCForge/CVE-2026-69157) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-69157.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-69157.svg)


## CVE-2026-69156
 Atomic Server is an open source headless CMS and real-time database. From 0.30.0 until 0.40.3, the Commit application path in lib/src/commit.rs allows an authenticated Agent to assign the server-managed internalId property to an owned resource without character validation. The /download handler in server/src/handlers/download.rs passes that value to filesystem path construction and NamedFile::open without sanitization, containment validation, or a File-class check, so traversal or absolute paths can read files available to the server process. Reading the server configuration can expose the root Agent private key and allow root impersonation with full read, write, and delete access to server data. This issue is fixed in version 0.40.3.

- [https://github.com/LLCForge/CVE-2026-69156](https://github.com/LLCForge/CVE-2026-69156) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-69156.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-69156.svg)


## CVE-2026-63219
 GeoNetwork is a catalog application to manage spatially referenced resources. Prior to versions 4.4.12 and 4.2.17, the API endpoint for creating a new formatter via file upload is unprotected and allows the upload of external uncontrolled files. An unauthenticated attacker can upload arbitrary `.xsl` or `.zip` formatter files to the server.  An unauthenticated attacker can write arbitrary files into the GeoNetwork formatter directory. On its own this constitutes unauthorized write access to server storage. The issue is patched in GeoNetwork versions 4.4.12 and 4.2.17.

- [https://github.com/BridgerAlderson/GeoNetwork-PreAuth-RCE-PoC](https://github.com/BridgerAlderson/GeoNetwork-PreAuth-RCE-PoC) :  ![starts](https://img.shields.io/github/stars/BridgerAlderson/GeoNetwork-PreAuth-RCE-PoC.svg) ![forks](https://img.shields.io/github/forks/BridgerAlderson/GeoNetwork-PreAuth-RCE-PoC.svg)
- [https://github.com/Fckroun/CVE-2026-63219-POC](https://github.com/Fckroun/CVE-2026-63219-POC) :  ![starts](https://img.shields.io/github/stars/Fckroun/CVE-2026-63219-POC.svg) ![forks](https://img.shields.io/github/forks/Fckroun/CVE-2026-63219-POC.svg)


## CVE-2026-63129
 mssql-mcp-core is the shared library that powers MSSQL MCP servers. Prior to core and server 0.6.0 and reader and writer 0.5.0, multiple database tools interpolate caller-controlled identifiers and predicates into T-SQL batches passed to Request.query() while parameterizing only data values. update_data, delete_data, insert_data, execute_transaction, create_table, create_index, and drop_table accept unsafe tableName, column, index, schema, or free-form whereClause input, while reader-tier list_databases interpolates stateFilter without runtime allowlist enforcement. Row-count and preview queries execute before confirmUpdate or confirmDelete, allowing malicious arguments to bypass confirmation and maxRows controls and execute stacked DDL or DML, read or destroy data, and potentially run operating-system commands when the SQL login is privileged and xp_cmdshell is enabled. This issue is fixed in core and server version 0.6.0 and reader and writer version 0.5.0.

- [https://github.com/LLCForge/CVE-2026-63129](https://github.com/LLCForge/CVE-2026-63129) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-63129.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-63129.svg)


## CVE-2026-58400
`java.lang.Runtime.exec()` or `java.lang.ProcessBuilder` directly, achieving arbitrary command execution as the GeoNetwork process user. A user with sufficient privileges to upload a formatter can deliver a `.xsl` file containing Java extension call that execute arbitrary OS commands with the privileges of the GeoNetwork process. The issue is patched in GeoNetwork versions 4.4.12 and 4.2.17.

- [https://github.com/BridgerAlderson/GeoNetwork-PreAuth-RCE-PoC](https://github.com/BridgerAlderson/GeoNetwork-PreAuth-RCE-PoC) :  ![starts](https://img.shields.io/github/stars/BridgerAlderson/GeoNetwork-PreAuth-RCE-PoC.svg) ![forks](https://img.shields.io/github/forks/BridgerAlderson/GeoNetwork-PreAuth-RCE-PoC.svg)


## CVE-2026-48500
 Filament is a collection of full-stack components for accelerated Laravel development. From 3.0.0 until 3.3.52, 4.11.5, and 5.6.5, any schema can contain a file upload form field, so Filament applies Livewire's WithFileUploads trait to the Livewire component the schema is embedded in. However, some schemas, such as the panel login form, do not require file uploads, and exposing unauthenticated temporary file uploads on these components is not an acceptable risk. On these components, an unauthenticated attacker could upload arbitrary files to the application's temporary storage, which could be abused to exhaust disk space or inflate storage costs. This vulnerability is fixed in 3.3.52, 4.11.5, and 5.6.5.

- [https://github.com/inj4ct0r/CVE-2026-48500](https://github.com/inj4ct0r/CVE-2026-48500) :  ![starts](https://img.shields.io/github/stars/inj4ct0r/CVE-2026-48500.svg) ![forks](https://img.shields.io/github/forks/inj4ct0r/CVE-2026-48500.svg)


## CVE-2026-41875
This issue was fixed in a patch to version 6.7 published on 09.11.2026, deployments without this patch are still vulnerable

- [https://github.com/KarolCzubernat/CVE-2026-41875-EXPLOIT-QuickCart-one-click-Account-Takeover](https://github.com/KarolCzubernat/CVE-2026-41875-EXPLOIT-QuickCart-one-click-Account-Takeover) :  ![starts](https://img.shields.io/github/stars/KarolCzubernat/CVE-2026-41875-EXPLOIT-QuickCart-one-click-Account-Takeover.svg) ![forks](https://img.shields.io/github/forks/KarolCzubernat/CVE-2026-41875-EXPLOIT-QuickCart-one-click-Account-Takeover.svg)


## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.

- [https://github.com/anxs3c/CVE-2026-24061-GNU-InetUtils-telnetd](https://github.com/anxs3c/CVE-2026-24061-GNU-InetUtils-telnetd) :  ![starts](https://img.shields.io/github/stars/anxs3c/CVE-2026-24061-GNU-InetUtils-telnetd.svg) ![forks](https://img.shields.io/github/forks/anxs3c/CVE-2026-24061-GNU-InetUtils-telnetd.svg)


## CVE-2026-13181
 In Progress® Telerik® UI for AJAX prior to v2026.2.708, forged upload metadata can influence AsyncUploadTypeName processing and trigger unsafe attacker-controlled type resolution, enabling remote code execution in affected deployments.

- [https://github.com/kjry8sb/CVE-2026-13181](https://github.com/kjry8sb/CVE-2026-13181) :  ![starts](https://img.shields.io/github/stars/kjry8sb/CVE-2026-13181.svg) ![forks](https://img.shields.io/github/forks/kjry8sb/CVE-2026-13181.svg)


## CVE-2026-12844
Any caller of pairwise() whose block returns, for a single pair, more than four times the longer input array's length writes past the buffer and corrupts the heap.

- [https://github.com/langz337/CVE-2026-128442](https://github.com/langz337/CVE-2026-128442) :  ![starts](https://img.shields.io/github/stars/langz337/CVE-2026-128442.svg) ![forks](https://img.shields.io/github/forks/langz337/CVE-2026-128442.svg)


## CVE-2026-10961
 Use after free in Chrome for iOS in Google Chrome on iOS prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/cloudducoeur/ansible-playbook-CVE-2026-109618](https://github.com/cloudducoeur/ansible-playbook-CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/cloudducoeur/ansible-playbook-CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/cloudducoeur/ansible-playbook-CVE-2026-109618.svg)
- [https://github.com/debugactiveprocess/CVE-2026-109618](https://github.com/debugactiveprocess/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/debugactiveprocess/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/debugactiveprocess/CVE-2026-109618.svg)


## CVE-2026-1300
 The Responsive Header plugin for WordPress is vulnerable to Stored Cross-Site Scripting via multiple plugin settings parameters in all versions up to, and including, 1.0 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with administrator-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page. This only affects multi-site installations and installations where unfiltered_html has been disabled.

- [https://github.com/LLCForge/CVE-2026-130001](https://github.com/LLCForge/CVE-2026-130001) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-130001.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-130001.svg)


## CVE-2026-1096
 The Best-wp-google-map plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'latitude' and 'longitudinal' parameters of the 'google_map_view' shortcode in all versions up to, and including, 2.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/skydwn/CVE-2026-109618](https://github.com/skydwn/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/skydwn/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/skydwn/CVE-2026-109618.svg)


## CVE-2025-57819
 FreePBX is an open-source web-based graphical user interface. FreePBX 15, 16, and 17 endpoints are vulnerable due to insufficiently sanitized user-supplied data allowing unauthenticated access to FreePBX Administrator leading to arbitrary database manipulation and remote code execution. This issue has been patched in endpoint versions 15.0.66, 16.0.89, and 17.0.3.

- [https://github.com/SamWang8891/CVE-2025-57819-poc](https://github.com/SamWang8891/CVE-2025-57819-poc) :  ![starts](https://img.shields.io/github/stars/SamWang8891/CVE-2025-57819-poc.svg) ![forks](https://img.shields.io/github/forks/SamWang8891/CVE-2025-57819-poc.svg)


## CVE-2025-36911
 In key-based pairing, there is a possible ID due to a logic error in the code. This could lead to remote (proximal/adjacent) information disclosure of user's conversations and location with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/jvitor211/TheyListen](https://github.com/jvitor211/TheyListen) :  ![starts](https://img.shields.io/github/stars/jvitor211/TheyListen.svg) ![forks](https://img.shields.io/github/forks/jvitor211/TheyListen.svg)


## CVE-2025-30208
 Vite, a provider of frontend development tooling, has a vulnerability in versions prior to 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10. `@fs` denies access to files outside of Vite serving allow list. Adding `?raw??` or `?import&raw??` to the URL bypasses this limitation and returns the file content if it exists. This bypass exists because trailing separators such as `?` are removed in several places, but are not accounted for in query string regexes. The contents of arbitrary files can be returned to the browser. Only apps explicitly exposing the Vite dev server to the network (using `--host` or `server.host` config option) are affected. Versions 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10 fix the issue.

- [https://github.com/Lusensec/CVE-2025-30208](https://github.com/Lusensec/CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/Lusensec/CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/Lusensec/CVE-2025-30208.svg)


## CVE-2025-24983
 Use after free in Windows Win32 Kernel Subsystem allows an authorized attacker to elevate privileges locally.

- [https://github.com/sote-CJ/CVE-2025-24983-1Day](https://github.com/sote-CJ/CVE-2025-24983-1Day) :  ![starts](https://img.shields.io/github/stars/sote-CJ/CVE-2025-24983-1Day.svg) ![forks](https://img.shields.io/github/forks/sote-CJ/CVE-2025-24983-1Day.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/anxs3c/editor_machine_writeup](https://github.com/anxs3c/editor_machine_writeup) :  ![starts](https://img.shields.io/github/stars/anxs3c/editor_machine_writeup.svg) ![forks](https://img.shields.io/github/forks/anxs3c/editor_machine_writeup.svg)


## CVE-2025-8110
 Improper Symbolic link handling in the PutContents API in Gogs allows Local Execution of Code.

- [https://github.com/anxs3c/GhostlinkWriteup](https://github.com/anxs3c/GhostlinkWriteup) :  ![starts](https://img.shields.io/github/stars/anxs3c/GhostlinkWriteup.svg) ![forks](https://img.shields.io/github/forks/anxs3c/GhostlinkWriteup.svg)


## CVE-2024-4367
 A type check was missing when handling fonts in PDF.js, which would allow arbitrary JavaScript execution in the PDF.js context. This vulnerability affects Firefox  126, Firefox ESR  115.11, and Thunderbird  115.11.

- [https://github.com/toobunbo/CVE-2024-4367](https://github.com/toobunbo/CVE-2024-4367) :  ![starts](https://img.shields.io/github/stars/toobunbo/CVE-2024-4367.svg) ![forks](https://img.shields.io/github/forks/toobunbo/CVE-2024-4367.svg)


## CVE-2023-46604
which fixes this issue.

- [https://github.com/Bhavya2-4/Detection-rules-SOC](https://github.com/Bhavya2-4/Detection-rules-SOC) :  ![starts](https://img.shields.io/github/stars/Bhavya2-4/Detection-rules-SOC.svg) ![forks](https://img.shields.io/github/forks/Bhavya2-4/Detection-rules-SOC.svg)


## CVE-2023-0386
 A flaw was found in the Linux kernel, where unauthorized access to the execution of the setuid file with capabilities was found in the Linux kernel’s OverlayFS subsystem in how a user copies a capable file from a nosuid mount into another mount. This uid mapping bug allows a local user to escalate their privileges on the system.

- [https://github.com/anxs3c/TwoMillion-Machine-Writeup](https://github.com/anxs3c/TwoMillion-Machine-Writeup) :  ![starts](https://img.shields.io/github/stars/anxs3c/TwoMillion-Machine-Writeup.svg) ![forks](https://img.shields.io/github/forks/anxs3c/TwoMillion-Machine-Writeup.svg)


## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is "${prefix:name}", where "prefix" is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - "script" - execute expressions using the JVM script execution engine (javax.script) - "dns" - resolve dns records - "url" - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/adikelty/commons-text-cve-2022-42889](https://github.com/adikelty/commons-text-cve-2022-42889) :  ![starts](https://img.shields.io/github/stars/adikelty/commons-text-cve-2022-42889.svg) ![forks](https://img.shields.io/github/forks/adikelty/commons-text-cve-2022-42889.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/Park123r/CVE-2021-41773](https://github.com/Park123r/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Park123r/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Park123r/CVE-2021-41773.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via "sudoedit -s" and a command-line argument that ends with a single backslash character.

- [https://github.com/tkien207/CVE-2021-3156](https://github.com/tkien207/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/tkien207/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/tkien207/CVE-2021-3156.svg)


## CVE-2020-24986
 Concrete5 up to and including 8.5.2 allows Unrestricted Upload of File with Dangerous Type such as a .php file via File Manager. It is possible to modify site configuration to upload the PHP file and execute arbitrary commands.

- [https://github.com/Rickert155/CVE-2020-24986-Exploit](https://github.com/Rickert155/CVE-2020-24986-Exploit) :  ![starts](https://img.shields.io/github/stars/Rickert155/CVE-2020-24986-Exploit.svg) ![forks](https://img.shields.io/github/forks/Rickert155/CVE-2020-24986-Exploit.svg)


## CVE-2019-7609
 Kibana versions before 5.6.15 and 6.6.1 contain an arbitrary code execution flaw in the Timelion visualizer. An attacker with access to the Timelion application could send a request that will attempt to execute javascript code. This could possibly lead to an attacker executing arbitrary commands with permissions of the Kibana process on the host system.

- [https://github.com/kaali0001/CVE-2019-7609](https://github.com/kaali0001/CVE-2019-7609) :  ![starts](https://img.shields.io/github/stars/kaali0001/CVE-2019-7609.svg) ![forks](https://img.shields.io/github/forks/kaali0001/CVE-2019-7609.svg)


## CVE-2018-16763
 FUEL CMS 1.4.1 allows PHP Code Evaluation via the pages/select/ filter parameter or the preview/ data parameter. This can lead to Pre-Auth Remote Code Execution.

- [https://github.com/fantasmakm4/LAB-008-IGNITE](https://github.com/fantasmakm4/LAB-008-IGNITE) :  ![starts](https://img.shields.io/github/stars/fantasmakm4/LAB-008-IGNITE.svg) ![forks](https://img.shields.io/github/forks/fantasmakm4/LAB-008-IGNITE.svg)


## CVE-2015-2025
 IBM WebSphere eXtreme Scale 7.1.0 before 7.1.0.3 and 7.1.1 before 7.1.1.1 does not set the secure flag for the session cookie in an https session, which makes it easier for remote attackers to capture this cookie by intercepting its transmission within an http session.

- [https://github.com/Ethanpr05/cve-2015-2025-analisis](https://github.com/Ethanpr05/cve-2015-2025-analisis) :  ![starts](https://img.shields.io/github/stars/Ethanpr05/cve-2015-2025-analisis.svg) ![forks](https://img.shields.io/github/forks/Ethanpr05/cve-2015-2025-analisis.svg)


## CVE-2013-2028
 The ngx_http_parse_chunked function in http/ngx_http_parse.c in nginx 1.3.9 through 1.4.0 allows remote attackers to cause a denial of service (crash) and execute arbitrary code via a chunked Transfer-Encoding request with a large chunk size, which triggers an integer signedness error and a stack-based buffer overflow.

- [https://github.com/XiXinping/367-nginx-chunked-size](https://github.com/XiXinping/367-nginx-chunked-size) :  ![starts](https://img.shields.io/github/stars/XiXinping/367-nginx-chunked-size.svg) ![forks](https://img.shields.io/github/forks/XiXinping/367-nginx-chunked-size.svg)

