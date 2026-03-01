# Update 2026-03-01
## CVE-2026-28372
 telnetd in GNU inetutils through 2.7 allows privilege escalation that can be exploited by abusing systemd service credentials support added to the login(1) implementation of util-linux in release 2.40. This is related to client control over the CREDENTIALS_DIRECTORY environment variable, and requires an unprivileged local user to create a login.noauth file.

- [https://github.com/mbanyamer/CVE-2026-28372-GNU-inetutils-telnetd-Privilege-Escalation](https://github.com/mbanyamer/CVE-2026-28372-GNU-inetutils-telnetd-Privilege-Escalation) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-28372-GNU-inetutils-telnetd-Privilege-Escalation.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-28372-GNU-inetutils-telnetd-Privilege-Escalation.svg)


## CVE-2026-28207
 Zen C is a systems programming language that compiles to human-readable GNU C/C11. Prior to version 0.4.2, a command injection vulnerability (CWE-78) in the Zen C compiler allows local attackers to execute arbitrary shell commands by providing a specially crafted output filename via the `-o` command-line argument. The vulnerability existed in the `main` application logic (specifically in `src/main.c`), where the compiler constructed a shell command string to invoke the backend C compiler. This command string was built by concatenating various arguments, including the user-controlled output filename, and was subsequently executed using the `system()` function. Because `system()` invokes a shell to parse and execute the command, shell metacharacters within the output filename were interpreted by the shell, leading to arbitrary command execution. An attacker who can influence the command-line arguments passed to the `zc` compiler (like through a build script or a CI/CD pipeline configuration) can execute arbitrary commands with the privileges of the user running the compiler. The vulnerability has been fixed in version 0.4.2 by removing `system()` calls, implementing `ArgList`, and internal argument handling. Users are advised to update to Zen C version v0.4.2 or later.

- [https://github.com/F0ndueSav0yarde/CVE-2026-28207](https://github.com/F0ndueSav0yarde/CVE-2026-28207) :  ![starts](https://img.shields.io/github/stars/F0ndueSav0yarde/CVE-2026-28207.svg) ![forks](https://img.shields.io/github/forks/F0ndueSav0yarde/CVE-2026-28207.svg)


## CVE-2026-21852
 Claude Code is an agentic coding tool. Prior to version 2.0.65, vulnerability in Claude Code's project-load flow allowed malicious repositories to exfiltrate data including Anthropic API keys before users confirmed trust. An attacker-controlled repository could include a settings file that sets ANTHROPIC_BASE_URL to an attacker-controlled endpoint and when the repository was opened, Claude Code would read the configuration and immediately issue API requests before showing the trust prompt, potentially leaking the user's API keys. Users on standard Claude Code auto-update have received this fix already. Users performing manual updates are advised to update to version 2.0.65, which contains a patch, or to the latest version.

- [https://github.com/atiilla/CVE-2026-21852-PoC](https://github.com/atiilla/CVE-2026-21852-PoC) :  ![starts](https://img.shields.io/github/stars/atiilla/CVE-2026-21852-PoC.svg) ![forks](https://img.shields.io/github/forks/atiilla/CVE-2026-21852-PoC.svg)
- [https://github.com/M0broot/CVE-Archive](https://github.com/M0broot/CVE-Archive) :  ![starts](https://img.shields.io/github/stars/M0broot/CVE-Archive.svg) ![forks](https://img.shields.io/github/forks/M0broot/CVE-Archive.svg)


## CVE-2026-2672
 A security flaw has been discovered in Tsinghua Unigroup Electronic Archives System 3.2.210802(62532). Affected by this vulnerability is the function Download of the file /Search/Subject/downLoad. Performing a manipulation of the argument path results in path traversal. The attack is possible to be carried out remotely. The exploit has been released to the public and may be used for attacks. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/dillonkirsch/CVE-2026-26720-Twenty-RCE](https://github.com/dillonkirsch/CVE-2026-26720-Twenty-RCE) :  ![starts](https://img.shields.io/github/stars/dillonkirsch/CVE-2026-26720-Twenty-RCE.svg) ![forks](https://img.shields.io/github/forks/dillonkirsch/CVE-2026-26720-Twenty-RCE.svg)


## CVE-2026-2472
 Stored Cross-Site Scripting (XSS) in the _genai/_evals_visualization component of Google Cloud Vertex AI SDK (google-cloud-aiplatform) versions from 1.98.0 up to (but not including) 1.131.0 allows an unauthenticated remote attacker to execute arbitrary JavaScript in a victim's Jupyter or Colab environment via injecting script escape sequences into model evaluation results or dataset JSON data.

- [https://github.com/JoshuaProvoste/CVE-2026-2472-Vertex-AI-SDK-Google-Cloud](https://github.com/JoshuaProvoste/CVE-2026-2472-Vertex-AI-SDK-Google-Cloud) :  ![starts](https://img.shields.io/github/stars/JoshuaProvoste/CVE-2026-2472-Vertex-AI-SDK-Google-Cloud.svg) ![forks](https://img.shields.io/github/forks/JoshuaProvoste/CVE-2026-2472-Vertex-AI-SDK-Google-Cloud.svg)


## CVE-2026-1581
 The wpForo Forum plugin for WordPress is vulnerable to time-based SQL Injection via the 'wpfob' parameter in all versions up to, and including, 2.4.14 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query. This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/rootdirective-sec/CVE-2026-1581-Analysis-Lab](https://github.com/rootdirective-sec/CVE-2026-1581-Analysis-Lab) :  ![starts](https://img.shields.io/github/stars/rootdirective-sec/CVE-2026-1581-Analysis-Lab.svg) ![forks](https://img.shields.io/github/forks/rootdirective-sec/CVE-2026-1581-Analysis-Lab.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/alptexans/RSC-Detect-CVE-2025-55182](https://github.com/alptexans/RSC-Detect-CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/alptexans/RSC-Detect-CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/alptexans/RSC-Detect-CVE-2025-55182.svg)
- [https://github.com/Dh4v4l8/CVE-2025-55182-poc-tool](https://github.com/Dh4v4l8/CVE-2025-55182-poc-tool) :  ![starts](https://img.shields.io/github/stars/Dh4v4l8/CVE-2025-55182-poc-tool.svg) ![forks](https://img.shields.io/github/forks/Dh4v4l8/CVE-2025-55182-poc-tool.svg)


## CVE-2025-39459
 Incorrect Privilege Assignment vulnerability in Contempo Themes Real Estate 7 allows Privilege Escalation.This issue affects Real Estate 7: from n/a through 3.5.2.

- [https://github.com/Dit-Developers/CVE-2025-39459](https://github.com/Dit-Developers/CVE-2025-39459) :  ![starts](https://img.shields.io/github/stars/Dit-Developers/CVE-2025-39459.svg) ![forks](https://img.shields.io/github/forks/Dit-Developers/CVE-2025-39459.svg)


## CVE-2025-1302
This is caused by an incomplete fix for [CVE-2024-21534](https://security.snyk.io/vuln/SNYK-JS-JSONPATHPLUS-7945884).

- [https://github.com/dbwlsdnr95/CVE-2025-1302](https://github.com/dbwlsdnr95/CVE-2025-1302) :  ![starts](https://img.shields.io/github/stars/dbwlsdnr95/CVE-2025-1302.svg) ![forks](https://img.shields.io/github/forks/dbwlsdnr95/CVE-2025-1302.svg)


## CVE-2025-1242
 The administrative credentials can be extracted through application API responses, mobile application reverse engineering, and device firmware reverse engineering. The exposure may result in an attacker gaining  full administrative access to the Gardyn IoT Hub exposing connected devices to malicious control.

- [https://github.com/MichaelAdamGroberman/CVE-2025-1242](https://github.com/MichaelAdamGroberman/CVE-2025-1242) :  ![starts](https://img.shields.io/github/stars/MichaelAdamGroberman/CVE-2025-1242.svg) ![forks](https://img.shields.io/github/forks/MichaelAdamGroberman/CVE-2025-1242.svg)


## CVE-2025-1068
 There is an untrusted search path vulnerability in Esri ArcGIS AllSource 1.2 and 1.3 that may allow a low privileged attacker with write privileges to the local file system to introduce a malicious executable to the filesystem. When the victim performs a specific action using ArcGIS AllSource, the file could execute and run malicious commands under the context of the victim. This issue is corrected in ArcGIS AllSource 1.2.1 and 1.3.1.

- [https://github.com/MichaelAdamGroberman/CVE-2025-10681](https://github.com/MichaelAdamGroberman/CVE-2025-10681) :  ![starts](https://img.shields.io/github/stars/MichaelAdamGroberman/CVE-2025-10681.svg) ![forks](https://img.shields.io/github/forks/MichaelAdamGroberman/CVE-2025-10681.svg)


## CVE-2024-52940
 AnyDesk through 8.1.0 on Windows, when Allow Direct Connections is enabled, inadvertently exposes a public IP address within network traffic. The attacker must know the victim's AnyDesk ID.

- [https://github.com/ebrasha/abdal-anydesk-remote-ip-detector](https://github.com/ebrasha/abdal-anydesk-remote-ip-detector) :  ![starts](https://img.shields.io/github/stars/ebrasha/abdal-anydesk-remote-ip-detector.svg) ![forks](https://img.shields.io/github/forks/ebrasha/abdal-anydesk-remote-ip-detector.svg)
- [https://github.com/MKultra6969/AnySniff](https://github.com/MKultra6969/AnySniff) :  ![starts](https://img.shields.io/github/stars/MKultra6969/AnySniff.svg) ![forks](https://img.shields.io/github/forks/MKultra6969/AnySniff.svg)


## CVE-2024-35250
 Windows Kernel-Mode Driver Elevation of Privilege Vulnerability

- [https://github.com/xvalegendary/HVCIPwned](https://github.com/xvalegendary/HVCIPwned) :  ![starts](https://img.shields.io/github/stars/xvalegendary/HVCIPwned.svg) ![forks](https://img.shields.io/github/forks/xvalegendary/HVCIPwned.svg)


## CVE-2023-46229
 LangChain before 0.0.317 allows SSRF via document_loaders/recursive_url_loader.py because crawling can proceed from an external server to an internal server.

- [https://github.com/JarvisDing-sdu/Yasa-CVE-2023-46229](https://github.com/JarvisDing-sdu/Yasa-CVE-2023-46229) :  ![starts](https://img.shields.io/github/stars/JarvisDing-sdu/Yasa-CVE-2023-46229.svg) ![forks](https://img.shields.io/github/forks/JarvisDing-sdu/Yasa-CVE-2023-46229.svg)


## CVE-2022-42475
 A heap-based buffer overflow vulnerability [CWE-122] in FortiOS SSL-VPN 7.2.0 through 7.2.2, 7.0.0 through 7.0.8, 6.4.0 through 6.4.10, 6.2.0 through 6.2.11, 6.0.15 and earlier  and FortiProxy SSL-VPN 7.2.0 through 7.2.1, 7.0.7 and earlier may allow a remote unauthenticated attacker to execute arbitrary code or commands via specifically crafted requests.

- [https://github.com/ArthurHendrich/CVE-2022-42475-POC](https://github.com/ArthurHendrich/CVE-2022-42475-POC) :  ![starts](https://img.shields.io/github/stars/ArthurHendrich/CVE-2022-42475-POC.svg) ![forks](https://img.shields.io/github/forks/ArthurHendrich/CVE-2022-42475-POC.svg)


## CVE-2022-30190
Please see the MSRC Blog Entry for important information about steps you can take to protect your system from this vulnerability.

- [https://github.com/bcarrulo/Lab-CVE-2022-30190](https://github.com/bcarrulo/Lab-CVE-2022-30190) :  ![starts](https://img.shields.io/github/stars/bcarrulo/Lab-CVE-2022-30190.svg) ![forks](https://img.shields.io/github/forks/bcarrulo/Lab-CVE-2022-30190.svg)

