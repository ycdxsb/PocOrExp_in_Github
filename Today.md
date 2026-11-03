# Update 2026-11-03
## CVE-2026-120232
 A vulnerability was identified in Horizon DataSys Reboot Restore Standard up to 13.2. The impacted element is the function sub_23908 in the library shield.sys of the component Kernel Driver. Such manipulation leads to memory corruption. The attack can only be performed from a local environment. The exploit is publicly available and might be used. A fix is planned for the upcoming release.

- [https://github.com/Element2023H/CVE-2026-120232](https://github.com/Element2023H/CVE-2026-120232) :  ![starts](https://img.shields.io/github/stars/Element2023H/CVE-2026-120232.svg) ![forks](https://img.shields.io/github/forks/Element2023H/CVE-2026-120232.svg)


## CVE-2026-120218
 A flaw has been found in Typemill up to 2.26.0. The impacted element is the function ControllerApiImage::saveImage of the file system/typemill/Models/SvgSanitizer.php. Executing a manipulation can lead to cross site scripting. The attack may be performed from remote. The exploit has been published and may be used. Upgrading to version 2.27.0 is sufficient to resolve this issue. This patch is called 9ca43c4a7b6764c5a6ac11a2ccc099b036ee3cef. It is recommended to upgrade the affected component.

- [https://github.com/capivara-research/CVE-2026-120218](https://github.com/capivara-research/CVE-2026-120218) :  ![starts](https://img.shields.io/github/stars/capivara-research/CVE-2026-120218.svg) ![forks](https://img.shields.io/github/forks/capivara-research/CVE-2026-120218.svg)


## CVE-2026-118764
 minimatch is a minimal matching utility for converting glob expressions into JavaScript RegExp objects. Prior to 11.0.1, src/index.ts implements firstPhasePreProcess() so that, at optimizationLevel 2 or higher, it repeatedly expands attacker-controlled **/.. pattern segments inside a fixpoint loop, allowing generated globParts entries to be processed and expanded again. secondPhasePreProcess() then compares the expanded entries pairwise, so a short malicious glob can cause excessive CPU and memory consumption during pattern compilation. This issue is fixed in version 11.0.1.

- [https://github.com/b1nv0id/CVE-2026-118764](https://github.com/b1nv0id/CVE-2026-118764) :  ![starts](https://img.shields.io/github/stars/b1nv0id/CVE-2026-118764.svg) ![forks](https://img.shields.io/github/forks/b1nv0id/CVE-2026-118764.svg)


## CVE-2026-116512
 The Project Manager – AI Powered Project Management, Task Management, Kanban Board & Time Tracker plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 4.1.1 via the 'id' parameter parameter. This is due to unsanitized 'id' parameter value concatenated directly into the pipe-delimited validation rule string, which is then split and each token invoked as a dynamic PHP function with no allowlist check. This makes it possible for unauthenticated attackers to execute code on the server. This is exploitable by unauthenticated attackers because WordPress core executes the route argument's validate_callback inside WP_REST_Server::dispatch() before the route's permission_callback is invoked, meaning the Project_Manage_Capability authorization gate is never reached on the vulnerable code path.

- [https://github.com/BabyMushr00w/CVE-2026-116512](https://github.com/BabyMushr00w/CVE-2026-116512) :  ![starts](https://img.shields.io/github/stars/BabyMushr00w/CVE-2026-116512.svg) ![forks](https://img.shields.io/github/forks/BabyMushr00w/CVE-2026-116512.svg)


## CVE-2026-116296
 The API routes for releases, release assets, milestones and repository labels did not reject changes to archived repositories. A user with write access to an archived repository, or a holder of such a user's write-scoped token, could replace or delete release assets while keeping their download URLs, delete releases and tags, and create, edit or delete milestones and labels of a repository that is meant to be read-only. Changing requests on these routes now return 423 Locked for archived repositories.

- [https://github.com/thalewalan/CVE-2026-116296](https://github.com/thalewalan/CVE-2026-116296) :  ![starts](https://img.shields.io/github/stars/thalewalan/CVE-2026-116296.svg) ![forks](https://img.shields.io/github/forks/thalewalan/CVE-2026-116296.svg)


## CVE-2026-115965
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in BuddyPress BuddyPress buddypress allows Blind SQL Injection.This issue affects BuddyPress: from n/a through 14.5.2.

- [https://github.com/4m3rr0r/CVE-2026-115965](https://github.com/4m3rr0r/CVE-2026-115965) :  ![starts](https://img.shields.io/github/stars/4m3rr0r/CVE-2026-115965.svg) ![forks](https://img.shields.io/github/forks/4m3rr0r/CVE-2026-115965.svg)


## CVE-2026-114509
 Laravel is a web application framework. Prior to 12.68.0 and 13.29.0, TokenGuard configured as a standard token-based API guard does not reject a crafted non-string credential. Under affected MySQL or MariaDB configurations, the authentication lookup can match an unintended existing user, allowing an unauthenticated attacker to bypass authentication and take over an account on routes protected by TokenGuard. This issue is fixed in versions 12.68.0 and 13.29.0.

- [https://github.com/nextmend/laravel-type-juggling-auth-bypass](https://github.com/nextmend/laravel-type-juggling-auth-bypass) :  ![starts](https://img.shields.io/github/stars/nextmend/laravel-type-juggling-auth-bypass.svg) ![forks](https://img.shields.io/github/forks/nextmend/laravel-type-juggling-auth-bypass.svg)


## CVE-2026-112816
 Improper certificate validation in the HTTPS listener in Canonical LXD 4.0.14, 5.0.10, 5.21.8, 6.9 before 4.0.15, 5.0.11, 5.21.9, 6.10.1 allows an unauthenticated attacker to authenticate as any trusted client and gain full access to the cluster and managed virtual machines via a crafted certificate chain.

- [https://github.com/MrNarsus/cve-2026-112816-poc](https://github.com/MrNarsus/cve-2026-112816-poc) :  ![starts](https://img.shields.io/github/stars/MrNarsus/cve-2026-112816-poc.svg) ![forks](https://img.shields.io/github/forks/MrNarsus/cve-2026-112816-poc.svg)


## CVE-2026-111497
Users need to update any Brotli libraries or binaries between 1.0.3 through 1.2.0 to the latest available version: 1.0.10 or 1.1.1 or 1.2.1.

- [https://github.com/mehmet-emir-eroglu/NODE2SHELL](https://github.com/mehmet-emir-eroglu/NODE2SHELL) :  ![starts](https://img.shields.io/github/stars/mehmet-emir-eroglu/NODE2SHELL.svg) ![forks](https://img.shields.io/github/forks/mehmet-emir-eroglu/NODE2SHELL.svg)
- [https://github.com/esskslifetech/PROTECTION2Shell](https://github.com/esskslifetech/PROTECTION2Shell) :  ![starts](https://img.shields.io/github/stars/esskslifetech/PROTECTION2Shell.svg) ![forks](https://img.shields.io/github/forks/esskslifetech/PROTECTION2Shell.svg)
- [https://github.com/Sable-Research/brotli-decoder-overflow](https://github.com/Sable-Research/brotli-decoder-overflow) :  ![starts](https://img.shields.io/github/stars/Sable-Research/brotli-decoder-overflow.svg) ![forks](https://img.shields.io/github/forks/Sable-Research/brotli-decoder-overflow.svg)


## CVE-2026-109619
 PHP has various global state that temporarily points into request memory. In some scenarios, global state may not be correctly reset, or may be repopulated after being reset. The global state may then refer to request memory even after it has been freed. Subsequent requests may read or branch on this stale state before it is fully initialized. Multiple strategies can trigger this condition and produce remote code execution (RCE).

- [https://github.com/alvm/php2shell-eol-backport](https://github.com/alvm/php2shell-eol-backport) :  ![starts](https://img.shields.io/github/stars/alvm/php2shell-eol-backport.svg) ![forks](https://img.shields.io/github/forks/alvm/php2shell-eol-backport.svg)


## CVE-2026-107406
  *  NetScaler ADC 13.1-FIPS before13.1-NDcPP 13.1-37.279

- [https://github.com/maxprog-svg/CVE-2026-107406](https://github.com/maxprog-svg/CVE-2026-107406) :  ![starts](https://img.shields.io/github/stars/maxprog-svg/CVE-2026-107406.svg) ![forks](https://img.shields.io/github/forks/maxprog-svg/CVE-2026-107406.svg)


## CVE-2026-105192
 LMCache multiprocess mode, also called distributed mode, opens an unauthenticated ZeroMQ ROUTER so worker processes can register and share KV cache blocks. Messages on that socket are msgpack. Extension code 1 is passed to DeviceIPCWrapper.Deserialize, which calls pickle.loads, while the server is still decoding request arguments and before the handler runs. A single unauthenticated ZMQ DEALER message to the transport port (default 5555) therefore executes code as the user the LMCache process runs as. Official container images run that process as root. The transport binds to localhost unless the operator sets a routable address with --host, which is how multi-node deployments let peers connect. The decode path shipped in v0.3.9 and is present through v0.5.5, including the v0.5.6 release candidates. v0.5.6, published on 2026-10-14, removes pickle.loads from this path.

- [https://github.com/basesixtythree/B63-POC-CVE-2026-105192](https://github.com/basesixtythree/B63-POC-CVE-2026-105192) :  ![starts](https://img.shields.io/github/stars/basesixtythree/B63-POC-CVE-2026-105192.svg) ![forks](https://img.shields.io/github/forks/basesixtythree/B63-POC-CVE-2026-105192.svg)


## CVE-2026-98432
will be addressed in a separate patch.

- [https://github.com/AronWang001/linux-cve-2026-98432-fix](https://github.com/AronWang001/linux-cve-2026-98432-fix) :  ![starts](https://img.shields.io/github/stars/AronWang001/linux-cve-2026-98432-fix.svg) ![forks](https://img.shields.io/github/forks/AronWang001/linux-cve-2026-98432-fix.svg)
- [https://github.com/al4n4n/CVE-2026-98432](https://github.com/al4n4n/CVE-2026-98432) :  ![starts](https://img.shields.io/github/stars/al4n4n/CVE-2026-98432.svg) ![forks](https://img.shields.io/github/forks/al4n4n/CVE-2026-98432.svg)
- [https://github.com/Mervent/cve-2026-98432](https://github.com/Mervent/cve-2026-98432) :  ![starts](https://img.shields.io/github/stars/Mervent/cve-2026-98432.svg) ![forks](https://img.shields.io/github/forks/Mervent/cve-2026-98432.svg)
- [https://github.com/jamilbk/drop-ipv4-opt](https://github.com/jamilbk/drop-ipv4-opt) :  ![starts](https://img.shields.io/github/stars/jamilbk/drop-ipv4-opt.svg) ![forks](https://img.shields.io/github/forks/jamilbk/drop-ipv4-opt.svg)
- [https://github.com/fetus-hina/cve-2026-98432-mitigation-rpm](https://github.com/fetus-hina/cve-2026-98432-mitigation-rpm) :  ![starts](https://img.shields.io/github/stars/fetus-hina/cve-2026-98432-mitigation-rpm.svg) ![forks](https://img.shields.io/github/forks/fetus-hina/cve-2026-98432-mitigation-rpm.svg)
- [https://github.com/Ghost-Bx1/cve-2026-98432-linux-tcp-uaf](https://github.com/Ghost-Bx1/cve-2026-98432-linux-tcp-uaf) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/cve-2026-98432-linux-tcp-uaf.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/cve-2026-98432-linux-tcp-uaf.svg)
- [https://github.com/uvian/xboard-core](https://github.com/uvian/xboard-core) :  ![starts](https://img.shields.io/github/stars/uvian/xboard-core.svg) ![forks](https://img.shields.io/github/forks/uvian/xboard-core.svg)


## CVE-2026-98260
[ tglx: Move the cleanup right after de_thread() ]

- [https://github.com/sabuweis/GhostLock-CVE-2026-98260](https://github.com/sabuweis/GhostLock-CVE-2026-98260) :  ![starts](https://img.shields.io/github/stars/sabuweis/GhostLock-CVE-2026-98260.svg) ![forks](https://img.shields.io/github/forks/sabuweis/GhostLock-CVE-2026-98260.svg)
- [https://github.com/yoro1836/SamTimer](https://github.com/yoro1836/SamTimer) :  ![starts](https://img.shields.io/github/stars/yoro1836/SamTimer.svg) ![forks](https://img.shields.io/github/forks/yoro1836/SamTimer.svg)
- [https://github.com/cuteaplane/CVE-2026-98260-for-OPD2501](https://github.com/cuteaplane/CVE-2026-98260-for-OPD2501) :  ![starts](https://img.shields.io/github/stars/cuteaplane/CVE-2026-98260-for-OPD2501.svg) ![forks](https://img.shields.io/github/forks/cuteaplane/CVE-2026-98260-for-OPD2501.svg)
- [https://github.com/LinXing0926/CVE-2026-98260-iQOO-Neo9-Pro-Root](https://github.com/LinXing0926/CVE-2026-98260-iQOO-Neo9-Pro-Root) :  ![starts](https://img.shields.io/github/stars/LinXing0926/CVE-2026-98260-iQOO-Neo9-Pro-Root.svg) ![forks](https://img.shields.io/github/forks/LinXing0926/CVE-2026-98260-iQOO-Neo9-Pro-Root.svg)


## CVE-2026-98258
code to make progress and remove it from the list.

- [https://github.com/imkidz0/poc-CVE-2026-98258](https://github.com/imkidz0/poc-CVE-2026-98258) :  ![starts](https://img.shields.io/github/stars/imkidz0/poc-CVE-2026-98258.svg) ![forks](https://img.shields.io/github/forks/imkidz0/poc-CVE-2026-98258.svg)


## CVE-2026-88773
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1-37.279 and NDcPP; Gateway: before 14.1-73.37 FIPS and before 13.1-64.23.

- [https://github.com/Fyyre/CVE-2026-88773](https://github.com/Fyyre/CVE-2026-88773) :  ![starts](https://img.shields.io/github/stars/Fyyre/CVE-2026-88773.svg) ![forks](https://img.shields.io/github/forks/Fyyre/CVE-2026-88773.svg)


## CVE-2026-86962
 A double free issue was addressed with improved memory management. This issue is fixed in iOS 26.7 and iPadOS 26.7, iOS 27 and iPadOS 27, macOS Golden Gate 27, macOS Sequoia 15.8, macOS Tahoe 26.7, tvOS 27, visionOS 27, watchOS 27. An app may be able to cause unexpected system termination.

- [https://github.com/bobmarleyfaruk9/CVE-2026-86962](https://github.com/bobmarleyfaruk9/CVE-2026-86962) :  ![starts](https://img.shields.io/github/stars/bobmarleyfaruk9/CVE-2026-86962.svg) ![forks](https://img.shields.io/github/forks/bobmarleyfaruk9/CVE-2026-86962.svg)


## CVE-2026-84295
 Improper authentication in Progress Software WS_FTP Server versions prior to 2024.0.6 and 2025.0.3 on Windows could allow an unauthenticated remote attacker to access sensitive information, including administrative credentials.

- [https://github.com/foxcornlab/wsftp-server-scanner](https://github.com/foxcornlab/wsftp-server-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/wsftp-server-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/wsftp-server-scanner.svg)


## CVE-2026-63765
 Chatwoot before 4.16.0 contains an authentication bypass vulnerability in the direct uploads controller that allows unauthenticated attackers to create arbitrary ActiveStorage blobs in any tenant account. Attackers can exploit missing authentication checks to resolve any account and conversation, then obtain signed PUT URLs to write arbitrary data to the application's storage backend.

- [https://github.com/n3chik/CVE-2026-63765](https://github.com/n3chik/CVE-2026-63765) :  ![starts](https://img.shields.io/github/stars/n3chik/CVE-2026-63765.svg) ![forks](https://img.shields.io/github/forks/n3chik/CVE-2026-63765.svg)


## CVE-2026-60004
 Gitea before 1.27.1 allows remote code execution via the diffpatch API through Git hook installation.

- [https://github.com/basesixtythree/B63-POC-CVE-2026-60004](https://github.com/basesixtythree/B63-POC-CVE-2026-60004) :  ![starts](https://img.shields.io/github/stars/basesixtythree/B63-POC-CVE-2026-60004.svg) ![forks](https://img.shields.io/github/forks/basesixtythree/B63-POC-CVE-2026-60004.svg)


## CVE-2026-43715
 A use-after-free issue was addressed with improved memory management. This issue is fixed in Safari 26.5.2, iOS 26.5.2 and iPadOS 26.5.2, iOS 26.7 and iPadOS 26.7, macOS Tahoe 26.5.2, tvOS 26.6, visionOS 26.6, watchOS 26.6. Processing maliciously crafted web content may lead to memory corruption.

- [https://github.com/Jmesmykil/SWITCH2-WEBKIT-JAILBREAK](https://github.com/Jmesmykil/SWITCH2-WEBKIT-JAILBREAK) :  ![starts](https://img.shields.io/github/stars/Jmesmykil/SWITCH2-WEBKIT-JAILBREAK.svg) ![forks](https://img.shields.io/github/forks/Jmesmykil/SWITCH2-WEBKIT-JAILBREAK.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/Escosis/V2463A-LPE](https://github.com/Escosis/V2463A-LPE) :  ![starts](https://img.shields.io/github/stars/Escosis/V2463A-LPE.svg) ![forks](https://img.shields.io/github/forks/Escosis/V2463A-LPE.svg)


## CVE-2026-19971
 A flaw has been found in LB-Link WR1210M 1.0.3. This impacts the function main of the file /www/cgi-bin/backup.cgi of the component Backup Endpoint. This manipulation causes missing authentication. The attack is only possible within the local network. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/tianlansedexiaoniu/CVE-2026-19971_guest](https://github.com/tianlansedexiaoniu/CVE-2026-19971_guest) :  ![starts](https://img.shields.io/github/stars/tianlansedexiaoniu/CVE-2026-19971_guest.svg) ![forks](https://img.shields.io/github/forks/tianlansedexiaoniu/CVE-2026-19971_guest.svg)


## CVE-2026-11677
 Race in Network in Google Chrome on Mac prior to 149.0.7827.103 allowed a remote attacker who had compromised the network process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/majidrahimi5020-lgtm/Poc-exploit-for-CVE-2026-116779-FreeSWITCH-](https://github.com/majidrahimi5020-lgtm/Poc-exploit-for-CVE-2026-116779-FreeSWITCH-) :  ![starts](https://img.shields.io/github/stars/majidrahimi5020-lgtm/Poc-exploit-for-CVE-2026-116779-FreeSWITCH-.svg) ![forks](https://img.shields.io/github/forks/majidrahimi5020-lgtm/Poc-exploit-for-CVE-2026-116779-FreeSWITCH-.svg)


## CVE-2026-11652
 Use after free in Extensions in Google Chrome prior to 149.0.7827.103 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/4m3rr0r/CVE-2026-116521-poc](https://github.com/4m3rr0r/CVE-2026-116521-poc) :  ![starts](https://img.shields.io/github/stars/4m3rr0r/CVE-2026-116521-poc.svg) ![forks](https://img.shields.io/github/forks/4m3rr0r/CVE-2026-116521-poc.svg)


## CVE-2026-10961
 Use after free in Chrome for iOS in Google Chrome on iOS prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/syrex1013/CVE-2026-109619](https://github.com/syrex1013/CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/syrex1013/CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/syrex1013/CVE-2026-109619.svg)


## CVE-2026-9151
network security, and service availability.

- [https://github.com/hcbt/CVE-2026-9151](https://github.com/hcbt/CVE-2026-9151) :  ![starts](https://img.shields.io/github/stars/hcbt/CVE-2026-9151.svg) ![forks](https://img.shields.io/github/forks/hcbt/CVE-2026-9151.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/lkeld/CVE-2026-43499-poc](https://github.com/lkeld/CVE-2026-43499-poc) :  ![starts](https://img.shields.io/github/stars/lkeld/CVE-2026-43499-poc.svg) ![forks](https://img.shields.io/github/forks/lkeld/CVE-2026-43499-poc.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/sodiptabadiabanurea/ntu-se6013-nextjs-auth-bypass](https://github.com/sodiptabadiabanurea/ntu-se6013-nextjs-auth-bypass) :  ![starts](https://img.shields.io/github/stars/sodiptabadiabanurea/ntu-se6013-nextjs-auth-bypass.svg) ![forks](https://img.shields.io/github/forks/sodiptabadiabanurea/ntu-se6013-nextjs-auth-bypass.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)


## CVE-2025-2992
 A vulnerability classified as critical was found in Tenda FH1202 1.2.0.14(408). Affected by this vulnerability is an unknown functionality of the file /goform/AdvSetWrlsafeset of the component Web Management Interface. The manipulation leads to improper access controls. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/amitlttwo/Next.JS-CVE-2025-29927](https://github.com/amitlttwo/Next.JS-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/amitlttwo/Next.JS-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/amitlttwo/Next.JS-CVE-2025-29927.svg)
- [https://github.com/Ghost-Bx1/cve-2025-29927-nextjs-middleware-bypass](https://github.com/Ghost-Bx1/cve-2025-29927-nextjs-middleware-bypass) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/cve-2025-29927-nextjs-middleware-bypass.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/cve-2025-29927-nextjs-middleware-bypass.svg)


## CVE-2025-1974
 A security issue was discovered in Kubernetes where under certain conditions, an unauthenticated attacker with access to the pod network can achieve arbitrary code execution in the context of the ingress-nginx controller. This can lead to disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)

- [https://github.com/Ghost-Bx1/cve-2025-1974-ingress-nginx-rce](https://github.com/Ghost-Bx1/cve-2025-1974-ingress-nginx-rce) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/cve-2025-1974-ingress-nginx-rce.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/cve-2025-1974-ingress-nginx-rce.svg)


## CVE-2024-57521
 SQL Injection vulnerability in RuoYi v.4.7.9 and before allows a remote attacker to execute arbitrary code via the createTable function in SqlUtil.java.

- [https://github.com/cipher-xs/CVE-2024-57521-RuoYi-SQLi](https://github.com/cipher-xs/CVE-2024-57521-RuoYi-SQLi) :  ![starts](https://img.shields.io/github/stars/cipher-xs/CVE-2024-57521-RuoYi-SQLi.svg) ![forks](https://img.shields.io/github/forks/cipher-xs/CVE-2024-57521-RuoYi-SQLi.svg)


## CVE-2024-48990
 Qualys discovered that needrestart, before version 3.8, allows local attackers to execute arbitrary code as root by tricking needrestart into running the Python interpreter with an attacker-controlled PYTHONPATH environment variable.

- [https://github.com/nekr0ff/needrestart-sudo-escalate-cve-2024-48990](https://github.com/nekr0ff/needrestart-sudo-escalate-cve-2024-48990) :  ![starts](https://img.shields.io/github/stars/nekr0ff/needrestart-sudo-escalate-cve-2024-48990.svg) ![forks](https://img.shields.io/github/forks/nekr0ff/needrestart-sudo-escalate-cve-2024-48990.svg)


## CVE-2024-4890
 A blind SQL injection vulnerability exists in the berriai/litellm application, specifically within the '/team/update' process. The vulnerability arises due to the improper handling of the 'user_id' parameter in the raw SQL query used for deleting users. An attacker can exploit this vulnerability by injecting malicious SQL commands through the 'user_id' parameter, leading to potential unauthorized access to sensitive information such as API keys, user information, and tokens stored in the database. The affected version is 1.27.14.

- [https://github.com/nekr0ff/needrestart-sudo-escalate-cve-2024-48990](https://github.com/nekr0ff/needrestart-sudo-escalate-cve-2024-48990) :  ![starts](https://img.shields.io/github/stars/nekr0ff/needrestart-sudo-escalate-cve-2024-48990.svg) ![forks](https://img.shields.io/github/forks/nekr0ff/needrestart-sudo-escalate-cve-2024-48990.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/esskslifetech/PROTECTION2Shell](https://github.com/esskslifetech/PROTECTION2Shell) :  ![starts](https://img.shields.io/github/stars/esskslifetech/PROTECTION2Shell.svg) ![forks](https://img.shields.io/github/forks/esskslifetech/PROTECTION2Shell.svg)


## CVE-2024-3094
Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.

- [https://github.com/mcpmark-eval-liuhezi/security-digest-modern-classics](https://github.com/mcpmark-eval-liuhezi/security-digest-modern-classics) :  ![starts](https://img.shields.io/github/stars/mcpmark-eval-liuhezi/security-digest-modern-classics.svg) ![forks](https://img.shields.io/github/forks/mcpmark-eval-liuhezi/security-digest-modern-classics.svg)


## CVE-2023-37474
 Copyparty is a portable file server. Versions prior to 1.8.2 are subject to a path traversal vulnerability detected in the `.cpr` subfolder. The Path Traversal attack technique allows an attacker access to files, directories, and commands that reside outside the web document root directory. This issue has been addressed in commit `043e3c7d` which has been included in release 1.8.2. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/0D00-0721-0/hdu-is-work1-copyparty-cve-2023-37474](https://github.com/0D00-0721-0/hdu-is-work1-copyparty-cve-2023-37474) :  ![starts](https://img.shields.io/github/stars/0D00-0721-0/hdu-is-work1-copyparty-cve-2023-37474.svg) ![forks](https://img.shields.io/github/forks/0D00-0721-0/hdu-is-work1-copyparty-cve-2023-37474.svg)


## CVE-2023-30861
This happens because vulnerable versions of Flask only set the `Vary: Cookie` header when the session is accessed or modified, not when it is refreshed (re-sent to update the expiration) without being accessed or modified. This issue has been fixed in versions 2.3.2 and 2.2.5.

- [https://github.com/elisapresciutti/CVE-2023-30861-flask-lab](https://github.com/elisapresciutti/CVE-2023-30861-flask-lab) :  ![starts](https://img.shields.io/github/stars/elisapresciutti/CVE-2023-30861-flask-lab.svg) ![forks](https://img.shields.io/github/forks/elisapresciutti/CVE-2023-30861-flask-lab.svg)


## CVE-2023-30856
 eDEX-UI is a science fiction terminal emulator. Versions 2.2.8 and prior are vulnerable to cross-site websocket hijacking. When running eDEX-UI and browsing the web, a malicious website can connect to eDEX's internal terminal control websocket, and send arbitrary commands to the shell. The project has been archived since 2021, and as of time of publication there are no plans to patch this issue and release a new version. Some workarounds are available, including shutting down eDEX-UI when browsing the web and ensuring the eDEX terminal runs with lowest possible privileges.

- [https://github.com/zpf2234/edex-afterlife](https://github.com/zpf2234/edex-afterlife) :  ![starts](https://img.shields.io/github/stars/zpf2234/edex-afterlife.svg) ![forks](https://img.shields.io/github/forks/zpf2234/edex-afterlife.svg)


## CVE-2022-36532
 Bolt CMS contains a vulnerability in version 5.1.12 and below that allows an authenticated user with the ROLE_EDITOR privileges to upload and rename a malicious file to achieve remote code execution.

- [https://github.com/wLuC45/wLuC45-CVE-2022-36532](https://github.com/wLuC45/wLuC45-CVE-2022-36532) :  ![starts](https://img.shields.io/github/stars/wLuC45/wLuC45-CVE-2022-36532.svg) ![forks](https://img.shields.io/github/forks/wLuC45/wLuC45-CVE-2022-36532.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `grafana_host_url/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/str1keboo/CVE-2021-43798](https://github.com/str1keboo/CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/str1keboo/CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/str1keboo/CVE-2021-43798.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/LayarKacaSiber/CVE-2021-41773](https://github.com/LayarKacaSiber/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/LayarKacaSiber/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/LayarKacaSiber/CVE-2021-41773.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/0xrogg/CVE-2021-41773](https://github.com/0xrogg/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/0xrogg/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/0xrogg/CVE-2021-41773.svg)
- [https://github.com/sixpacksecurity/CVE-2021-41773](https://github.com/sixpacksecurity/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sixpacksecurity/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sixpacksecurity/CVE-2021-41773.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock."  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/mcpmark-eval-liuhezi/security-digest-modern-classics](https://github.com/mcpmark-eval-liuhezi/security-digest-modern-classics) :  ![starts](https://img.shields.io/github/stars/mcpmark-eval-liuhezi/security-digest-modern-classics.svg) ![forks](https://img.shields.io/github/forks/mcpmark-eval-liuhezi/security-digest-modern-classics.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/mcpmark-eval-liuhezi/security-digest-modern-classics](https://github.com/mcpmark-eval-liuhezi/security-digest-modern-classics) :  ![starts](https://img.shields.io/github/stars/mcpmark-eval-liuhezi/security-digest-modern-classics.svg) ![forks](https://img.shields.io/github/forks/mcpmark-eval-liuhezi/security-digest-modern-classics.svg)

