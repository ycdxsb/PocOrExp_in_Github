## CVE-2026-22804
 Termix is a web-based server management platform with SSH terminal, tunneling, and file editing capabilities. From 1.7.0 to 1.9.0, Stored Cross-Site Scripting (XSS) vulnerability exists in the Termix File Manager component. The application fails to sanitize SVG file content before rendering it. This allows an attacker who has compromised a managed SSH server to plant a malicious file, which, when previewed by the Termix user, executes arbitrary JavaScript in the context of the application. The vulnerability is located in src/ui/desktop/apps/file-manager/components/FileViewer.tsx. This vulnerability is fixed in 1.10.0.



- [https://github.com/ThemeHackers/CVE-2026-22804](https://github.com/ThemeHackers/CVE-2026-22804) :  ![starts](https://img.shields.io/github/stars/ThemeHackers/CVE-2026-22804.svg) ![forks](https://img.shields.io/github/forks/ThemeHackers/CVE-2026-22804.svg)

## CVE-2026-22241
 The Open eClass platform (formerly known as GUnet eClass) is a complete course management system. Prior to version 4.2, an arbitrary file upload vulnerability in the theme import functionality enables an attacker with administrative privileges to upload arbitrary files on the server's file system. The main cause of the issue is that no validation or sanitization of the file's present inside the zip archive. This leads to remote code execution on the web server. Version 4.2 patches the issue.



- [https://github.com/Ashifcoder/CVE-2026-22241](https://github.com/Ashifcoder/CVE-2026-22241) :  ![starts](https://img.shields.io/github/stars/Ashifcoder/CVE-2026-22241.svg) ![forks](https://img.shields.io/github/forks/Ashifcoder/CVE-2026-22241.svg)

## CVE-2026-21877
 n8n is an open source workflow automation platform. In versions 0.121.2 and below, an authenticated attacker may be able to execute malicious code using the n8n service. This could result in full compromise and can impact both self-hosted and n8n Cloud instances. This issue is fixed in version 1.121.3. Administrators can reduce exposure by disabling the Git node and limiting access for untrusted users, but upgrading to the latest version is recommended.



- [https://github.com/Ashwesker/Ashwesker-CVE-2026-21877](https://github.com/Ashwesker/Ashwesker-CVE-2026-21877) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2026-21877.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2026-21877.svg)

## CVE-2026-21876
 The OWASP core rule set (CRS) is a set of generic attack detection rules for use with compatible web application firewalls. Prior to versions 4.22.0 and 3.3.8, the current rule 922110 has a bug when processing multipart requests with multiple parts. When the first rule in a chain iterates over a collection (like `MULTIPART_PART_HEADERS`), the capture variables (`TX:0`, `TX:1`) get overwritten with each iteration. Only the last captured value is available to the chained rule, which means malicious charsets in earlier parts can be missed if a later part has a legitimate charset. Versions 4.22.0 and 3.3.8 patch the issue.



- [https://github.com/daytriftnewgen/CVE-2026-21876](https://github.com/daytriftnewgen/CVE-2026-21876) :  ![starts](https://img.shields.io/github/stars/daytriftnewgen/CVE-2026-21876.svg) ![forks](https://img.shields.io/github/forks/daytriftnewgen/CVE-2026-21876.svg)

## CVE-2026-21858
 n8n is an open source workflow automation platform. Versions starting with 1.65.0 and below 1.121.0 enable an attacker to access files on the underlying server through execution of certain form-based workflows. A vulnerable workflow could grant access to an unauthenticated remote attacker, resulting in exposure of sensitive information stored on the system and may enable further compromise depending on deployment configuration and workflow usage. This issue is fixed in version 1.121.0.



- [https://github.com/Chocapikk/CVE-2026-21858](https://github.com/Chocapikk/CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2026-21858.svg)

- [https://github.com/Ashwesker/Ashwesker-CVE-2026-21858](https://github.com/Ashwesker/Ashwesker-CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2026-21858.svg)

- [https://github.com/eduardorossi84/CVE-2026-21858-POC](https://github.com/eduardorossi84/CVE-2026-21858-POC) :  ![starts](https://img.shields.io/github/stars/eduardorossi84/CVE-2026-21858-POC.svg) ![forks](https://img.shields.io/github/forks/eduardorossi84/CVE-2026-21858-POC.svg)

- [https://github.com/cropnet/ni8mare-scanner](https://github.com/cropnet/ni8mare-scanner) :  ![starts](https://img.shields.io/github/stars/cropnet/ni8mare-scanner.svg) ![forks](https://img.shields.io/github/forks/cropnet/ni8mare-scanner.svg)

## CVE-2026-21451
 Bagisto is an open source laravel eCommerce platform. A stored Cross-Site Scripting (XSS) vulnerability exists in Bagisto prior to version 2.3.10 within the CMS page editor. Although the platform normally attempts to sanitize `script` tags, the filtering can be bypassed by manipulating the raw HTTP POST request before submission. As a result, arbitrary JavaScript can be stored in the CMS content and executed whenever the page is viewed or edited. This exposes administrators to a high-severity risk, including complete account takeover, backend hijacking, and malicious script execution. Version 2.3.10 fixes the issue.



- [https://github.com/Ashwesker/Ashwesker-CVE-2026-21451](https://github.com/Ashwesker/Ashwesker-CVE-2026-21451) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2026-21451.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2026-21451.svg)

## CVE-2026-21450
 Bagisto is an open source laravel eCommerce platform. Versions prior to 2.3.10 are vulnerable to server-side template injection via type parameter, which can lead to remote code execution or another exploitation. Version 2.3.10 fixes the issue.



- [https://github.com/Ashwesker/Ashwesker-CVE-2026-21450](https://github.com/Ashwesker/Ashwesker-CVE-2026-21450) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2026-21450.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2026-21450.svg)

## CVE-2026-21445
 Langflow is a tool for building and deploying AI-powered agents and workflows. Prior to version 1.7.0.dev45, multiple critical API endpoints in Langflow are missing authentication controls. The issue allows any unauthenticated user to access sensitive user conversation data, transaction histories, and perform destructive operations including message deletion. This affects endpoints handling personal data and system operations that should require proper authorization. Version 1.7.0.dev45 contains a patch.



- [https://github.com/chinaxploiter/CVE-2026-21445-PoC](https://github.com/chinaxploiter/CVE-2026-21445-PoC) :  ![starts](https://img.shields.io/github/stars/chinaxploiter/CVE-2026-21445-PoC.svg) ![forks](https://img.shields.io/github/forks/chinaxploiter/CVE-2026-21445-PoC.svg)

## CVE-2026-21440
 AdonisJS is a TypeScript-first web framework. A Path Traversal vulnerability in AdonisJS multipart file handling may allow a remote attacker to write arbitrary files to arbitrary locations on the server filesystem. This impacts @adonisjs/bodyparser through version 10.1.1 and 11.x prerelease versions prior to 11.0.0-next.6. This issue has been patched in @adonisjs/bodyparser versions 10.1.2 and 11.0.0-next.6.



- [https://github.com/Ashwesker/Ashwesker-CVE-2026-21440](https://github.com/Ashwesker/Ashwesker-CVE-2026-21440) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2026-21440.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2026-21440.svg)

- [https://github.com/k0nnect/cve-2026-21440-writeup-poc](https://github.com/k0nnect/cve-2026-21440-writeup-poc) :  ![starts](https://img.shields.io/github/stars/k0nnect/cve-2026-21440-writeup-poc.svg) ![forks](https://img.shields.io/github/forks/k0nnect/cve-2026-21440-writeup-poc.svg)

- [https://github.com/you-ssef9/CVE-2026-21440](https://github.com/you-ssef9/CVE-2026-21440) :  ![starts](https://img.shields.io/github/stars/you-ssef9/CVE-2026-21440.svg) ![forks](https://img.shields.io/github/forks/you-ssef9/CVE-2026-21440.svg)

## CVE-2026-21437
 eopkg is a Solus package manager implemented in python3. In versions prior to 4.4.0, a malicious package could include files that are not tracked by `eopkg`. This requires the installation of a package from a malicious or compromised source. Files in such packages would not be shown by `lseopkg` and related tools. The issue has been fixed in v4.4.0. Users only installing packages from the Solus repositories are not affected.



- [https://github.com/osmancanvural/CVE-2026-21437](https://github.com/osmancanvural/CVE-2026-21437) :  ![starts](https://img.shields.io/github/stars/osmancanvural/CVE-2026-21437.svg) ![forks](https://img.shields.io/github/forks/osmancanvural/CVE-2026-21437.svg)

## CVE-2026-21436
 eopkg is a Solus package manager implemented in python3. In versions prior to 4.4.0, a malicious package could escape the directory set by `--destdir`. This requires the installation of a package from a malicious or compromised source. Files in such packages would not be installed in the path given by `--destdir`, but on a different location on the host. The issue has been fixed in v4.4.0. Users only installing packages from the Solus repositories are not affected.



- [https://github.com/osmancanvural/CVE-2026-21436](https://github.com/osmancanvural/CVE-2026-21436) :  ![starts](https://img.shields.io/github/stars/osmancanvural/CVE-2026-21436.svg) ![forks](https://img.shields.io/github/forks/osmancanvural/CVE-2026-21436.svg)

## CVE-2026-20856
 Improper input validation in Windows Server Update Service allows an unauthorized attacker to execute code over a network.



- [https://github.com/b1gchoi/poc-CVE-2026-20856](https://github.com/b1gchoi/poc-CVE-2026-20856) :  ![starts](https://img.shields.io/github/stars/b1gchoi/poc-CVE-2026-20856.svg) ![forks](https://img.shields.io/github/forks/b1gchoi/poc-CVE-2026-20856.svg)

## CVE-2026-20805
 Exposure of sensitive information to an unauthorized actor in Desktop Windows Manager allows an authorized attacker to disclose information locally.



- [https://github.com/fevar54/CVE-2026-20805-POC](https://github.com/fevar54/CVE-2026-20805-POC) :  ![starts](https://img.shields.io/github/stars/fevar54/CVE-2026-20805-POC.svg) ![forks](https://img.shields.io/github/forks/fevar54/CVE-2026-20805-POC.svg)

## CVE-2026-0842
 A flaw has been found in Flycatcher Toys smART Sketcher up to 2.0. This affects an unknown part of the component Bluetooth Low Energy Interface. This manipulation causes missing authentication. The attack can only be done within the local network. The exploit has been published and may be used. The vendor was contacted early about this disclosure but did not respond in any way.



- [https://github.com/davidrxchester/smart-sketcher-upload](https://github.com/davidrxchester/smart-sketcher-upload) :  ![starts](https://img.shields.io/github/stars/davidrxchester/smart-sketcher-upload.svg) ![forks](https://img.shields.io/github/forks/davidrxchester/smart-sketcher-upload.svg)

## CVE-2026-0628
 Insufficient policy enforcement in WebView tag in Google Chrome prior to 143.0.7499.192 allowed an attacker who convinced a user to install a malicious extension to inject scripts or HTML into a privileged page via a crafted Chrome Extension. (Chromium security severity: High)



- [https://github.com/fevar54/CVE-2026-0628-POC](https://github.com/fevar54/CVE-2026-0628-POC) :  ![starts](https://img.shields.io/github/stars/fevar54/CVE-2026-0628-POC.svg) ![forks](https://img.shields.io/github/forks/fevar54/CVE-2026-0628-POC.svg)

## CVE-2026-0547
 A vulnerability was found in PHPGurukul Online Course Registration up to 3.1. This issue affects some unknown processing of the file /admin/edit-student-profile.php of the component Student Registration Page. The manipulation of the argument photo results in unrestricted upload. The attack may be launched remotely. The exploit has been made public and could be used.



- [https://github.com/rsecroot/CVE-2026-0547](https://github.com/rsecroot/CVE-2026-0547) :  ![starts](https://img.shields.io/github/stars/rsecroot/CVE-2026-0547.svg) ![forks](https://img.shields.io/github/forks/rsecroot/CVE-2026-0547.svg)
