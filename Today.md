# Update 2026-08-25
## CVE-2026-78122
 docker-socket-proxy fails to properly gate read endpoints in the /containers Docker API namespace when the CONTAINERS environment variable is set. Attackers can use GET requests to /containers/{id}/archive, /containers/{id}/export, /containers/{id}/logs, and /containers/{id}/top to read arbitrary files and download entire container filesystems as tar archives.

- [https://github.com/Legendile7/CVE-2026-78122-POC](https://github.com/Legendile7/CVE-2026-78122-POC) :  ![starts](https://img.shields.io/github/stars/Legendile7/CVE-2026-78122-POC.svg) ![forks](https://img.shields.io/github/forks/Legendile7/CVE-2026-78122-POC.svg)


## CVE-2026-66917
 Joomla Extension - joomgalleryfriends.net - Stored XSS in JoomGallery  4.4.0 - An authenticated, privileged can store an XSS payload in any image causing JS execution in every visitor's browser.

- [https://github.com/toanln-cov/CVE-2026-66917](https://github.com/toanln-cov/CVE-2026-66917) :  ![starts](https://img.shields.io/github/stars/toanln-cov/CVE-2026-66917.svg) ![forks](https://img.shields.io/github/forks/toanln-cov/CVE-2026-66917.svg)


## CVE-2026-66916
 Joomla Extension - joomgalleryfriends.net - Password-Protected Category Bypass via JSON Format in JoomGallery  4.4.0- An unauthenticated access control bypass exists in JoomGallery's category JSON view. When a gallery category is protected with a password, the HTML view correctly enforces the password gate - but the JSON view ( format=json ) skips this check entirely.

- [https://github.com/toanln-cov/CVE-2026-66916](https://github.com/toanln-cov/CVE-2026-66916) :  ![starts](https://img.shields.io/github/stars/toanln-cov/CVE-2026-66916.svg) ![forks](https://img.shields.io/github/forks/toanln-cov/CVE-2026-66916.svg)


## CVE-2026-64560
---truncated---

- [https://github.com/xx2901318208/ghostlock-cve-2026-64560](https://github.com/xx2901318208/ghostlock-cve-2026-64560) :  ![starts](https://img.shields.io/github/stars/xx2901318208/ghostlock-cve-2026-64560.svg) ![forks](https://img.shields.io/github/forks/xx2901318208/ghostlock-cve-2026-64560.svg)


## CVE-2026-45316
 Open WebUI is a self-hosted artificial intelligence platform designed to operate entirely offline. Prior to 0.9.3, the POST /api/v1/notes/{id}/pin endpoint performs a write operation (toggling the is_pinned field) but only checks for read permission. Users with read-only access to a shared note can pin/unpin it, which is a state-modifying action that should require write permission. This vulnerability is fixed in 0.9.3.

- [https://github.com/arian-gogani/enforcement-coverage](https://github.com/arian-gogani/enforcement-coverage) :  ![starts](https://img.shields.io/github/stars/arian-gogani/enforcement-coverage.svg) ![forks](https://img.shields.io/github/forks/arian-gogani/enforcement-coverage.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/sarabpal-dev/IonStack-S22U](https://github.com/sarabpal-dev/IonStack-S22U) :  ![starts](https://img.shields.io/github/stars/sarabpal-dev/IonStack-S22U.svg) ![forks](https://img.shields.io/github/forks/sarabpal-dev/IonStack-S22U.svg)
- [https://github.com/XingChenRS/CyberMeowfiaNS](https://github.com/XingChenRS/CyberMeowfiaNS) :  ![starts](https://img.shields.io/github/stars/XingChenRS/CyberMeowfiaNS.svg) ![forks](https://img.shields.io/github/forks/XingChenRS/CyberMeowfiaNS.svg)
- [https://github.com/yakidango-official/GhostLock-H80GT](https://github.com/yakidango-official/GhostLock-H80GT) :  ![starts](https://img.shields.io/github/stars/yakidango-official/GhostLock-H80GT.svg) ![forks](https://img.shields.io/github/forks/yakidango-official/GhostLock-H80GT.svg)


## CVE-2026-23744
 MCPJam inspector is the local-first development platform for MCP servers. Versions 1.4.2 and earlier are vulnerable to remote code execution (RCE) vulnerability, which allows an attacker to send a crafted HTTP request that triggers the installation of an MCP server, leading to RCE. Since MCPJam inspector by default listens on 0.0.0.0 instead of 127.0.0.1, an attacker can trigger the RCE remotely via a simple HTTP request. Version 1.4.3 contains a patch.

- [https://github.com/itsC1SCO/mcpjam-to-root](https://github.com/itsC1SCO/mcpjam-to-root) :  ![starts](https://img.shields.io/github/stars/itsC1SCO/mcpjam-to-root.svg) ![forks](https://img.shields.io/github/forks/itsC1SCO/mcpjam-to-root.svg)


## CVE-2026-19681
 An authenticated command injection vulnerability exists in Security Center related to file upload processing. An attacker could exploit this issue by uploading a specially crafted file, potentially resulting in arbitrary command execution on the underlying operating system.

- [https://github.com/h00die/poc_cve_2026_19681](https://github.com/h00die/poc_cve_2026_19681) :  ![starts](https://img.shields.io/github/stars/h00die/poc_cve_2026_19681.svg) ![forks](https://img.shields.io/github/forks/h00die/poc_cve_2026_19681.svg)


## CVE-2026-19650
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 18.2 before 18.11.11, 19.0 before 19.0.8, 19.1 before 19.1.6, and 19.2 before 19.2.4 that under certain conditions could have allowed an unauthenticated user to execute mutations via GET requests due to improper request validation in GraphQL multiplex query handling.

- [https://github.com/dinosn/gitlab-cve-2026-19478-lab](https://github.com/dinosn/gitlab-cve-2026-19478-lab) :  ![starts](https://img.shields.io/github/stars/dinosn/gitlab-cve-2026-19478-lab.svg) ![forks](https://img.shields.io/github/forks/dinosn/gitlab-cve-2026-19478-lab.svg)


## CVE-2026-19478
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 18.2 before 18.11.11, 19.0 before 19.0.8, 19.1 before 19.1.6, and 19.2 before 19.2.4 that under certain conditions could allow an unauthenticated user to remotely modify or delete public projects and user data via a GraphQL directive.

- [https://github.com/dinosn/gitlab-cve-2026-19478-lab](https://github.com/dinosn/gitlab-cve-2026-19478-lab) :  ![starts](https://img.shields.io/github/stars/dinosn/gitlab-cve-2026-19478-lab.svg) ![forks](https://img.shields.io/github/forks/dinosn/gitlab-cve-2026-19478-lab.svg)


## CVE-2026-15718
 We are aware that exploit code for this is public however we are not aware of any attacks in the wild abusing this flaw. This vulnerability was fixed in Firefox 152.0.6, Firefox ESR 140.13, and Thunderbird 140.13.

- [https://github.com/SneakyNachos/CVE-2026-15718-who-put-ptrs-in-my-wasm](https://github.com/SneakyNachos/CVE-2026-15718-who-put-ptrs-in-my-wasm) :  ![starts](https://img.shields.io/github/stars/SneakyNachos/CVE-2026-15718-who-put-ptrs-in-my-wasm.svg) ![forks](https://img.shields.io/github/forks/SneakyNachos/CVE-2026-15718-who-put-ptrs-in-my-wasm.svg)


## CVE-2026-10053
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 18.8 before 19.0.6, 19.1 before 19.1.4, and 19.2 before 19.2.2 that under certain conditions could have allowed an authenticated user to achieve remote code execution due to a path traversal vulnerability in the package registry.

- [https://github.com/dinosn/CVE-2026-10053-lab](https://github.com/dinosn/CVE-2026-10053-lab) :  ![starts](https://img.shields.io/github/stars/dinosn/CVE-2026-10053-lab.svg) ![forks](https://img.shields.io/github/forks/dinosn/CVE-2026-10053-lab.svg)


## CVE-2026-9198
 IBM Langflow OSS 1.0.0 through 1.10.0 allows unauthenticated attackers to chain /api/v1/auto_login (mints SUPERUSER tokens to any network caller) with /api/v1/validate/code (executes user code via exec()) to achieve full RCE on default Langflow deployments

- [https://github.com/chessalekin/cve-2026-9198_exploit](https://github.com/chessalekin/cve-2026-9198_exploit) :  ![starts](https://img.shields.io/github/stars/chessalekin/cve-2026-9198_exploit.svg) ![forks](https://img.shields.io/github/forks/chessalekin/cve-2026-9198_exploit.svg)


## CVE-2026-3437
 An improper restriction of operations within the bounds of a memory buffer vulnerability in Portwell Engineering Toolkits version 4.8.2 could allow a local authenticated attacker to read and write to arbitrary memory via the Portwell Engineering Toolkits driver. Successful exploitation of this vulnerability could result in escalation of privileges or cause a denial-of-service condition.

- [https://github.com/tihomirocrew/cve-2026-3437](https://github.com/tihomirocrew/cve-2026-3437) :  ![starts](https://img.shields.io/github/stars/tihomirocrew/cve-2026-3437.svg) ![forks](https://img.shields.io/github/forks/tihomirocrew/cve-2026-3437.svg)


## CVE-2026-0013
 In setupLayout of PickActivity.java, there is a possible way to start any activity as a DocumentsUI app due to a confused deputy. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/XiaoBaiLovesStirring/cve-2026-0013-poc](https://github.com/XiaoBaiLovesStirring/cve-2026-0013-poc) :  ![starts](https://img.shields.io/github/stars/XiaoBaiLovesStirring/cve-2026-0013-poc.svg) ![forks](https://img.shields.io/github/forks/XiaoBaiLovesStirring/cve-2026-0013-poc.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/Heimd411/CVE-2025-29927-PoC](https://github.com/Heimd411/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/Heimd411/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/Heimd411/CVE-2025-29927-PoC.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg)


## CVE-2025-2992
 A vulnerability classified as critical was found in Tenda FH1202 1.2.0.14(408). Affected by this vulnerability is an unknown functionality of the file /goform/AdvSetWrlsafeset of the component Web Management Interface. The manipulation leads to improper access controls. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/0xPb1/Next.js-CVE-2025-29927](https://github.com/0xPb1/Next.js-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/0xPb1/Next.js-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/0xPb1/Next.js-CVE-2025-29927.svg)


## CVE-2024-9264
 The SQL Expressions experimental feature of Grafana allows for the evaluation of `duckdb` queries containing user input. These queries are insufficiently sanitized before being passed to `duckdb`, leading to a command injection and local file inclusion vulnerability. Any user with the VIEWER or higher permission is capable of executing this attack.  The `duckdb` binary must be present in Grafana's $PATH for this attack to function; by default, this binary is not installed in Grafana distributions.

- [https://github.com/barun121/CVE-2024-9264-in-Grafana-11.x](https://github.com/barun121/CVE-2024-9264-in-Grafana-11.x) :  ![starts](https://img.shields.io/github/stars/barun121/CVE-2024-9264-in-Grafana-11.x.svg) ![forks](https://img.shields.io/github/forks/barun121/CVE-2024-9264-in-Grafana-11.x.svg)


## CVE-2023-44487
 The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.

- [https://github.com/ramonzx6/rapid-reset-check](https://github.com/ramonzx6/rapid-reset-check) :  ![starts](https://img.shields.io/github/stars/ramonzx6/rapid-reset-check.svg) ![forks](https://img.shields.io/github/forks/ramonzx6/rapid-reset-check.svg)


## CVE-2022-41352
 An issue was discovered in Zimbra Collaboration (ZCS) 8.8.15 and 9.0. An attacker can upload arbitrary files through amavis via a cpio loophole (extraction to /opt/zimbra/jetty/webapps/zimbra/public) that can lead to incorrect access to any other user accounts. Zimbra recommends pax over cpio. Also, pax is in the prerequisites of Zimbra on Ubuntu; however, pax is no longer part of a default Red Hat installation after RHEL 6 (or CentOS 6). Once pax is installed, amavis automatically prefers it over cpio.

- [https://github.com/dafrax/cve-2022-41352-zimbra-rce](https://github.com/dafrax/cve-2022-41352-zimbra-rce) :  ![starts](https://img.shields.io/github/stars/dafrax/cve-2022-41352-zimbra-rce.svg) ![forks](https://img.shields.io/github/forks/dafrax/cve-2022-41352-zimbra-rce.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/pmihsan/Dirty-Pipe-CVE-2022-0847](https://github.com/pmihsan/Dirty-Pipe-CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/pmihsan/Dirty-Pipe-CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/pmihsan/Dirty-Pipe-CVE-2022-0847.svg)
- [https://github.com/gaganhm3018-art/CVE-2022-0847-Dirty-Pipe-](https://github.com/gaganhm3018-art/CVE-2022-0847-Dirty-Pipe-) :  ![starts](https://img.shields.io/github/stars/gaganhm3018-art/CVE-2022-0847-Dirty-Pipe-.svg) ![forks](https://img.shields.io/github/forks/gaganhm3018-art/CVE-2022-0847-Dirty-Pipe-.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/dbgee/CVE-2021-44228](https://github.com/dbgee/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/dbgee/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/dbgee/CVE-2021-44228.svg)
- [https://github.com/IAmNewbieZ/CVE-2021-44228](https://github.com/IAmNewbieZ/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/IAmNewbieZ/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/IAmNewbieZ/CVE-2021-44228.svg)


## CVE-2020-6418
 Type confusion in V8 in Google Chrome prior to 80.0.3987.122 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/a-mansilla/CVE-2020-6418](https://github.com/a-mansilla/CVE-2020-6418) :  ![starts](https://img.shields.io/github/stars/a-mansilla/CVE-2020-6418.svg) ![forks](https://img.shields.io/github/forks/a-mansilla/CVE-2020-6418.svg)


## CVE-2020-5504
 In phpMyAdmin 4 before 4.9.4 and 5 before 5.0.1, SQL injection exists in the user accounts page. A malicious user could inject custom SQL in place of their own username when creating queries to this page. An attacker must have a valid MySQL account to access the server.

- [https://github.com/CerberusMrXi/phpMyAdmin-CVE-2020-5504-Exploit](https://github.com/CerberusMrXi/phpMyAdmin-CVE-2020-5504-Exploit) :  ![starts](https://img.shields.io/github/stars/CerberusMrXi/phpMyAdmin-CVE-2020-5504-Exploit.svg) ![forks](https://img.shields.io/github/forks/CerberusMrXi/phpMyAdmin-CVE-2020-5504-Exploit.svg)

