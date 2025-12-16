# Update 2025-12-16
## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/hidden-investigations/react2shell-scanner](https://github.com/hidden-investigations/react2shell-scanner) :  ![starts](https://img.shields.io/github/stars/hidden-investigations/react2shell-scanner.svg) ![forks](https://img.shields.io/github/forks/hidden-investigations/react2shell-scanner.svg)
- [https://github.com/ProwlSec/React2Shell](https://github.com/ProwlSec/React2Shell) :  ![starts](https://img.shields.io/github/stars/ProwlSec/React2Shell.svg) ![forks](https://img.shields.io/github/forks/ProwlSec/React2Shell.svg)


## CVE-2025-66039
 FreePBX Endpoint Manager is a module for managing telephony endpoints in FreePBX systems. Versions are vulnerable to authentication bypass when the authentication type is set to "webserver." When providing an Authorization header with an arbitrary value, a session is associated with the target user regardless of valid credentials. This issue is fixed in versions 16.0.44 and 17.0.23.

- [https://github.com/BimBoxH4/CVE-2025-66039_CVE-2025-61675_CVE-2025-61678_reePBX](https://github.com/BimBoxH4/CVE-2025-66039_CVE-2025-61675_CVE-2025-61678_reePBX) :  ![starts](https://img.shields.io/github/stars/BimBoxH4/CVE-2025-66039_CVE-2025-61675_CVE-2025-61678_reePBX.svg) ![forks](https://img.shields.io/github/forks/BimBoxH4/CVE-2025-66039_CVE-2025-61675_CVE-2025-61678_reePBX.svg)


## CVE-2025-64720
 LIBPNG is a reference library for use in applications that read, create, and manipulate PNG (Portable Network Graphics) raster image files. From version 1.6.0 to before 1.6.51, an out-of-bounds read vulnerability exists in png_image_read_composite when processing palette images with PNG_FLAG_OPTIMIZE_ALPHA enabled. The palette compositing code in png_init_read_transformations incorrectly applies background compositing during premultiplication, violating the invariant component ≤ alpha × 257 required by the simplified PNG API. This issue has been patched in version 1.6.51.

- [https://github.com/dantsco/CVE-2025-64720-PoC](https://github.com/dantsco/CVE-2025-64720-PoC) :  ![starts](https://img.shields.io/github/stars/dantsco/CVE-2025-64720-PoC.svg) ![forks](https://img.shields.io/github/forks/dantsco/CVE-2025-64720-PoC.svg)


## CVE-2025-61678
 FreePBX Endpoint Manager is a module for managing telephony endpoints in FreePBX systems. In versions prior to 16.0.92 for FreePBX 16 and versions prior to 17.0.6 for FreePBX 17, the Endpoint Manager module contains an authenticated arbitrary file upload vulnerability affecting the fwbrand parameter. The fwbrand parameter allows an attacker to change the file path. Combined, these issues can result in a webshell being uploaded. Authentication with a known username is required to exploit this vulnerability. Successful exploitation allows authenticated users to upload arbitrary files to attacker-controlled paths on the server, potentially leading to remote code execution. This issue has been patched in version 16.0.92 for FreePBX 16 and version 17.0.6 for FreePBX 17.

- [https://github.com/BimBoxH4/CVE-2025-66039_CVE-2025-61675_CVE-2025-61678_reePBX](https://github.com/BimBoxH4/CVE-2025-66039_CVE-2025-61675_CVE-2025-61678_reePBX) :  ![starts](https://img.shields.io/github/stars/BimBoxH4/CVE-2025-66039_CVE-2025-61675_CVE-2025-61678_reePBX.svg) ![forks](https://img.shields.io/github/forks/BimBoxH4/CVE-2025-66039_CVE-2025-61675_CVE-2025-61678_reePBX.svg)


## CVE-2025-61675
 FreePBX Endpoint Manager is a module for managing telephony endpoints in FreePBX systems. In versions prior to 16.0.92 for FreePBX 16 and versions prior to 17.0.6 for FreePBX 17, the Endpoint Manager module contains authenticated SQL injection vulnerabilities affecting multiple parameters in the basestation, model, firmware, and custom extension configuration functionality areas. Authentication with a known username is required to exploit these vulnerabilities. Successful exploitation allows authenticated users to execute arbitrary SQL queries against the database, potentially enabling access to sensitive data or modification of database contents. This issue has been patched in version 16.0.92 for FreePBX 16 and version 17.0.6 for FreePBX 17.

- [https://github.com/BimBoxH4/CVE-2025-66039_CVE-2025-61675_CVE-2025-61678_reePBX](https://github.com/BimBoxH4/CVE-2025-66039_CVE-2025-61675_CVE-2025-61678_reePBX) :  ![starts](https://img.shields.io/github/stars/BimBoxH4/CVE-2025-66039_CVE-2025-61675_CVE-2025-61678_reePBX.svg) ![forks](https://img.shields.io/github/forks/BimBoxH4/CVE-2025-66039_CVE-2025-61675_CVE-2025-61678_reePBX.svg)


## CVE-2025-55184
 A pre-authentication denial of service vulnerability exists in React Server Components versions 19.0.0, 19.0.1 19.1.0, 19.1.1, 19.1.2, 19.2.0 and 19.2.1, including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints, which can cause an infinite loop that hangs the server process and may prevent future HTTP requests from being served.

- [https://github.com/cybertechajju/CVE-2025-55184-POC-Expolit](https://github.com/cybertechajju/CVE-2025-55184-POC-Expolit) :  ![starts](https://img.shields.io/github/stars/cybertechajju/CVE-2025-55184-POC-Expolit.svg) ![forks](https://img.shields.io/github/forks/cybertechajju/CVE-2025-55184-POC-Expolit.svg)
- [https://github.com/KingHacker353/CVE-2025-55184](https://github.com/KingHacker353/CVE-2025-55184) :  ![starts](https://img.shields.io/github/stars/KingHacker353/CVE-2025-55184.svg) ![forks](https://img.shields.io/github/forks/KingHacker353/CVE-2025-55184.svg)
- [https://github.com/EvtDanya/rsc-vulnerabilities](https://github.com/EvtDanya/rsc-vulnerabilities) :  ![starts](https://img.shields.io/github/stars/EvtDanya/rsc-vulnerabilities.svg) ![forks](https://img.shields.io/github/forks/EvtDanya/rsc-vulnerabilities.svg)


## CVE-2025-55183
 An information leak vulnerability exists in specific configurations of React Server Components versions 19.0.0, 19.0.1 19.1.0, 19.1.1, 19.1.2, 19.2.0 and 19.2.1, including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. A specifically crafted HTTP request sent to a vulnerable Server Function may unsafely return the source code of any Server Function. Exploitation requires the existence of a Server Function which explicitly or implicitly exposes a stringified argument.

- [https://github.com/EvtDanya/rsc-vulnerabilities](https://github.com/EvtDanya/rsc-vulnerabilities) :  ![starts](https://img.shields.io/github/stars/EvtDanya/rsc-vulnerabilities.svg) ![forks](https://img.shields.io/github/forks/EvtDanya/rsc-vulnerabilities.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/MoLeft/React2Shell-Toolbox](https://github.com/MoLeft/React2Shell-Toolbox) :  ![starts](https://img.shields.io/github/stars/MoLeft/React2Shell-Toolbox.svg) ![forks](https://img.shields.io/github/forks/MoLeft/React2Shell-Toolbox.svg)
- [https://github.com/Dh4v4l8/CVE-2025-55182-poc-tool](https://github.com/Dh4v4l8/CVE-2025-55182-poc-tool) :  ![starts](https://img.shields.io/github/stars/Dh4v4l8/CVE-2025-55182-poc-tool.svg) ![forks](https://img.shields.io/github/forks/Dh4v4l8/CVE-2025-55182-poc-tool.svg)
- [https://github.com/raivenLockdown/RCE_React2Shell_ButCooler-SomeUselessUsefulThingsLMAO-](https://github.com/raivenLockdown/RCE_React2Shell_ButCooler-SomeUselessUsefulThingsLMAO-) :  ![starts](https://img.shields.io/github/stars/raivenLockdown/RCE_React2Shell_ButCooler-SomeUselessUsefulThingsLMAO-.svg) ![forks](https://img.shields.io/github/forks/raivenLockdown/RCE_React2Shell_ButCooler-SomeUselessUsefulThingsLMAO-.svg)


## CVE-2025-48384
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When reading a config value, Git strips any trailing carriage return and line feed (CRLF). When writing a config entry, values with a trailing CR are not quoted, causing the CR to be lost when the config is later read. When initializing a submodule, if the submodule path contains a trailing CR, the altered path is read resulting in the submodule being checked out to an incorrect location. If a symlink exists that points the altered path to the submodule hooks directory, and the submodule contains an executable post-checkout hook, the script may be unintentionally executed after checkout. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.

- [https://github.com/vignesh21-git/CVE-2025-48384](https://github.com/vignesh21-git/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/vignesh21-git/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/vignesh21-git/CVE-2025-48384.svg)
- [https://github.com/vignesh21-git/CVE-2025-48384-submodule](https://github.com/vignesh21-git/CVE-2025-48384-submodule) :  ![starts](https://img.shields.io/github/stars/vignesh21-git/CVE-2025-48384-submodule.svg) ![forks](https://img.shields.io/github/forks/vignesh21-git/CVE-2025-48384-submodule.svg)


## CVE-2025-32434
 PyTorch is a Python package that provides tensor computation with strong GPU acceleration and deep neural networks built on a tape-based autograd system. In version 2.5.1 and prior, a Remote Command Execution (RCE) vulnerability exists in PyTorch when loading a model using torch.load with weights_only=True. This issue has been patched in version 2.6.0.

- [https://github.com/Cheval-Paresseux/cve_2025_32434](https://github.com/Cheval-Paresseux/cve_2025_32434) :  ![starts](https://img.shields.io/github/stars/Cheval-Paresseux/cve_2025_32434.svg) ![forks](https://img.shields.io/github/forks/Cheval-Paresseux/cve_2025_32434.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/enochgitgamefied/NextJS-CVE-2025-29927](https://github.com/enochgitgamefied/NextJS-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/enochgitgamefied/NextJS-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/enochgitgamefied/NextJS-CVE-2025-29927.svg)
- [https://github.com/jmbowes/NextSecureScan](https://github.com/jmbowes/NextSecureScan) :  ![starts](https://img.shields.io/github/stars/jmbowes/NextSecureScan.svg) ![forks](https://img.shields.io/github/forks/jmbowes/NextSecureScan.svg)


## CVE-2025-24367
 Cacti is an open source performance and fault management framework. An authenticated Cacti user can abuse graph creation and graph template functionality to create arbitrary PHP scripts in the web root of the application, leading to remote code execution on the server. This vulnerability is fixed in 1.2.29.

- [https://github.com/SoftAndoWetto/CVE-2025-24367-PoC-Cacti](https://github.com/SoftAndoWetto/CVE-2025-24367-PoC-Cacti) :  ![starts](https://img.shields.io/github/stars/SoftAndoWetto/CVE-2025-24367-PoC-Cacti.svg) ![forks](https://img.shields.io/github/forks/SoftAndoWetto/CVE-2025-24367-PoC-Cacti.svg)


## CVE-2025-14174
 Out of bounds memory access in ANGLE in Google Chrome on Mac prior to 143.0.7499.110 allowed a remote attacker to perform out of bounds memory access via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/Terrasue/CVE-2025-14174-Exploit](https://github.com/Terrasue/CVE-2025-14174-Exploit) :  ![starts](https://img.shields.io/github/stars/Terrasue/CVE-2025-14174-Exploit.svg) ![forks](https://img.shields.io/github/forks/Terrasue/CVE-2025-14174-Exploit.svg)


## CVE-2025-9074
This can lead to execution of a wide range of privileged commands to the engine API, including controlling other containers, creating new ones, managing images etc. In some circumstances (e.g. Docker Desktop for Windows with WSL backend) it also allows mounting the host drive with the same privileges as the user running Docker Desktop.

- [https://github.com/fsoc-ghost-0x/CVE-2025-9074_DAEMON_KILLER](https://github.com/fsoc-ghost-0x/CVE-2025-9074_DAEMON_KILLER) :  ![starts](https://img.shields.io/github/stars/fsoc-ghost-0x/CVE-2025-9074_DAEMON_KILLER.svg) ![forks](https://img.shields.io/github/forks/fsoc-ghost-0x/CVE-2025-9074_DAEMON_KILLER.svg)


## CVE-2025-6019
 A Local Privilege Escalation (LPE) vulnerability was found in libblockdev. Generally, the "allow_active" setting in Polkit permits a physically present user to take certain actions based on the session type. Due to the way libblockdev interacts with the udisks daemon, an "allow_active" user on a system may be able escalate to full root privileges on the target host. Normally, udisks mounts user-provided filesystem images with security flags like nosuid and nodev to prevent privilege escalation.  However, a local attacker can create a specially crafted XFS image containing a SUID-root shell, then trick udisks into resizing it. This mounts their malicious filesystem with root privileges, allowing them to execute their SUID-root shell and gain complete control of the system.

- [https://github.com/phamdinhquy2512/CVE-2025-6019-Exploitation](https://github.com/phamdinhquy2512/CVE-2025-6019-Exploitation) :  ![starts](https://img.shields.io/github/stars/phamdinhquy2512/CVE-2025-6019-Exploitation.svg) ![forks](https://img.shields.io/github/forks/phamdinhquy2512/CVE-2025-6019-Exploitation.svg)


## CVE-2024-24590
 Deserialization of untrusted data can occur in versions 0.17.0 to 1.14.2 of the client SDK of Allegro AI’s ClearML platform, enabling a maliciously uploaded artifact to run arbitrary code on an end user’s system when interacted with.

- [https://github.com/xffsec/CVE-2024-24590-ClearML-RCE-Exploit](https://github.com/xffsec/CVE-2024-24590-ClearML-RCE-Exploit) :  ![starts](https://img.shields.io/github/stars/xffsec/CVE-2024-24590-ClearML-RCE-Exploit.svg) ![forks](https://img.shields.io/github/forks/xffsec/CVE-2024-24590-ClearML-RCE-Exploit.svg)


## CVE-2024-12227
 A vulnerability, which was classified as problematic, was found in MSI Dragon Center up to 2.0.146.0. This affects the function MmUnMapIoSpace in the library NTIOLib_X64.sys of the component IOCTL Handler. The manipulation leads to null pointer dereference. It is possible to launch the attack on the local host. Upgrading to version 2.0.148.0 is able to address this issue. It is recommended to upgrade the affected component.

- [https://github.com/HI0U/POC-CVE-2024-12227](https://github.com/HI0U/POC-CVE-2024-12227) :  ![starts](https://img.shields.io/github/stars/HI0U/POC-CVE-2024-12227.svg) ![forks](https://img.shields.io/github/forks/HI0U/POC-CVE-2024-12227.svg)


## CVE-2023-44487
 The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.

- [https://github.com/tpirate/cve-2023-44487-POC](https://github.com/tpirate/cve-2023-44487-POC) :  ![starts](https://img.shields.io/github/stars/tpirate/cve-2023-44487-POC.svg) ![forks](https://img.shields.io/github/forks/tpirate/cve-2023-44487-POC.svg)


## CVE-2021-4107
 yetiforcecrm is vulnerable to Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

- [https://github.com/dillonkirsch/CVE-2021-41074](https://github.com/dillonkirsch/CVE-2021-41074) :  ![starts](https://img.shields.io/github/stars/dillonkirsch/CVE-2021-41074.svg) ![forks](https://img.shields.io/github/forks/dillonkirsch/CVE-2021-41074.svg)

