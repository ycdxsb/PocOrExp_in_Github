# Update 2026-10-10
## CVE-2026-107406
  *  NetScaler ADC 13.1-FIPS before13.1-NDcPP 13.1-37.279

- [https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker](https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker) :  ![starts](https://img.shields.io/github/stars/ThomasPoppelgaard/netscaler-ctx697096-checker.svg) ![forks](https://img.shields.io/github/forks/ThomasPoppelgaard/netscaler-ctx697096-checker.svg)


## CVE-2026-105192
 LMCache multiprocess mode, also called distributed mode, opens an unauthenticated ZeroMQ ROUTER so worker processes can register and share KV cache blocks. Messages on that socket are msgpack. Extension code 1 is passed to DeviceIPCWrapper.Deserialize, which calls pickle.loads, while the server is still decoding request arguments and before the handler runs. A single unauthenticated ZMQ DEALER message to the transport port (default 5555) therefore executes code as the user the LMCache process runs as. Official container images run that process as root. The transport binds to localhost unless the operator sets a routable address with --host, which is how multi-node deployments let peers connect.

- [https://github.com/rxsklife/CVE-2026-105192](https://github.com/rxsklife/CVE-2026-105192) :  ![starts](https://img.shields.io/github/stars/rxsklife/CVE-2026-105192.svg) ![forks](https://img.shields.io/github/forks/rxsklife/CVE-2026-105192.svg)


## CVE-2026-92555
This issue affects AKINSOFT WOLVOX Control Panel: from 26.02.25 before 26.02.26.

- [https://github.com/Enay-Project/CVE-2026-92555](https://github.com/Enay-Project/CVE-2026-92555) :  ![starts](https://img.shields.io/github/stars/Enay-Project/CVE-2026-92555.svg) ![forks](https://img.shields.io/github/forks/Enay-Project/CVE-2026-92555.svg)


## CVE-2026-91940
 crawl4ai before 0.9.3 contains an arbitrary file write vulnerability in PDFContentScrapingStrategy where the _filter_untrusted_fields function fails to validate untrusted configuration fields. Attackers can submit crafted config bodies with malicious image_save_dir paths to write attacker-controlled bytes into any directory accessible to the service account.

- [https://github.com/BiiTts/CVE-2026-91940-crawl4ai-Arbitrary-File-Write](https://github.com/BiiTts/CVE-2026-91940-crawl4ai-Arbitrary-File-Write) :  ![starts](https://img.shields.io/github/stars/BiiTts/CVE-2026-91940-crawl4ai-Arbitrary-File-Write.svg) ![forks](https://img.shields.io/github/forks/BiiTts/CVE-2026-91940-crawl4ai-Arbitrary-File-Write.svg)


## CVE-2026-84411
 The web management service in affected RouterOS versions contains an integer underflow in its HTTP request body handling that is reachable before authentication. This can be leveraged by an unauthenticated network attacker to achieve arbitrary code execution as root, or to cause a denial of service, using a single crafted request.

- [https://github.com/gagaltotal/CVE-2026-mikrotik-poc](https://github.com/gagaltotal/CVE-2026-mikrotik-poc) :  ![starts](https://img.shields.io/github/stars/gagaltotal/CVE-2026-mikrotik-poc.svg) ![forks](https://img.shields.io/github/forks/gagaltotal/CVE-2026-mikrotik-poc.svg)


## CVE-2026-67279
 RouterOS SSH enters the connection protocol after a client-requested rekey even though user authentication was never attempted, allowing an unauthenticated client to open a session channel and send an exec request. On affected builds the server dispatches the command, enabling unauthenticated creation, overwrite, and reconstruction of files in the RouterOS managed file namespace, including support files containing configuration and diagnostic data.This issue was fixed in versions: 6.49.21 (Long-term), 7.23.4 (Long-term) and 7.24.2 (Stable)

- [https://github.com/shmaki4/CVE-2026-67279-Mikrotik-6.42-POC](https://github.com/shmaki4/CVE-2026-67279-Mikrotik-6.42-POC) :  ![starts](https://img.shields.io/github/stars/shmaki4/CVE-2026-67279-Mikrotik-6.42-POC.svg) ![forks](https://img.shields.io/github/forks/shmaki4/CVE-2026-67279-Mikrotik-6.42-POC.svg)


## CVE-2026-61424
 Joomla Extension - dj-extensions.com - Unauthenticated arbitrary file upload in DJ-Classifieds  3.11.2 - The Joomla extension DJ-Classifieds is vulnerable to an unauthenticated file upload, leading to full RCE.

- [https://github.com/theendofabbys/CVE-2026-61424](https://github.com/theendofabbys/CVE-2026-61424) :  ![starts](https://img.shields.io/github/stars/theendofabbys/CVE-2026-61424.svg) ![forks](https://img.shields.io/github/forks/theendofabbys/CVE-2026-61424.svg)


## CVE-2026-56291
 Joomla Extension - balbooa.com - Unauthenticated file upload in Balbooa Forms extension  2.4.1 - The Joomla extension Balbooa Forms is vulnerable to an unauthenticated arbitrary file upload that allows uploading executable files and leads to full RCE.

- [https://github.com/theendofabbys/CVE-2026-56291](https://github.com/theendofabbys/CVE-2026-56291) :  ![starts](https://img.shields.io/github/stars/theendofabbys/CVE-2026-56291.svg) ![forks](https://img.shields.io/github/forks/theendofabbys/CVE-2026-56291.svg)


## CVE-2026-55450
 Langflow is a tool for building and deploying AI-powered agents and workflows. Prior to 1.9.1, unauthenticated users can upload any amount of data to the server without any limitations. No need for any prior knowledge, only network access to Langflow. This can lead to space exhaustion on the server. In addition, in the response, the absolute path of the uploaded file is reported to the attacker, which is an information leak that can assist in chaining other primitives. This vulnerability is fixed in 1.9.1.

- [https://github.com/0xBlackash/CVE-2026-55450](https://github.com/0xBlackash/CVE-2026-55450) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-55450.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-55450.svg)


## CVE-2026-50055
 A policy-enforcement flaw in Zimbra Collaboration Suite allows an authenticated user to bypass disabled mail forwarding by using a Sieve notify action to send copies of email content and headers to an arbitrary address.

- [https://github.com/HORKimhab/CVE-2026-50055](https://github.com/HORKimhab/CVE-2026-50055) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-50055.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-50055.svg)


## CVE-2026-49881
 In serviceClassExists of InCallController.java, there is a possible arbitrary code execution due to a logic error in the code. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/Lewason/mhl-off-hook-writeup](https://github.com/Lewason/mhl-off-hook-writeup) :  ![starts](https://img.shields.io/github/stars/Lewason/mhl-off-hook-writeup.svg) ![forks](https://img.shields.io/github/forks/Lewason/mhl-off-hook-writeup.svg)


## CVE-2026-49049
 The Helix3 plugin for Joomla exposes an ajax handler task, that allows unauthenticated attackers to delete arbitrary files, write arbitrary JSON files and update template parameters.

- [https://github.com/theendofabbys/CVE-2026-49049](https://github.com/theendofabbys/CVE-2026-49049) :  ![starts](https://img.shields.io/github/stars/theendofabbys/CVE-2026-49049.svg) ![forks](https://img.shields.io/github/forks/theendofabbys/CVE-2026-49049.svg)


## CVE-2026-48908
 A vulnerability in SP Page Builder for Joomla allows unauthenticated users to upload arbitrary files, ultimately resulting in the upload and execution of PHP code.

- [https://github.com/theendofabbys/CVE-2026-48908](https://github.com/theendofabbys/CVE-2026-48908) :  ![starts](https://img.shields.io/github/stars/theendofabbys/CVE-2026-48908.svg) ![forks](https://img.shields.io/github/forks/theendofabbys/CVE-2026-48908.svg)


## CVE-2026-48907
 A vulnerability in the JCE editor extension for Joomla allows the creation of new editor profiles for unauthenticated users, ultimately resulting in PHP code upload and execution.

- [https://github.com/theendofabbys/CVE-2026-48907](https://github.com/theendofabbys/CVE-2026-48907) :  ![starts](https://img.shields.io/github/stars/theendofabbys/CVE-2026-48907.svg) ![forks](https://img.shields.io/github/forks/theendofabbys/CVE-2026-48907.svg)


## CVE-2026-46300
bytes into @to's linear data rather than transferring frag descriptors.

- [https://github.com/porcumarcooo/THM-CVE-2026-46300-Fragnesia-Exploit](https://github.com/porcumarcooo/THM-CVE-2026-46300-Fragnesia-Exploit) :  ![starts](https://img.shields.io/github/stars/porcumarcooo/THM-CVE-2026-46300-Fragnesia-Exploit.svg) ![forks](https://img.shields.io/github/forks/porcumarcooo/THM-CVE-2026-46300-Fragnesia-Exploit.svg)


## CVE-2026-46242
READ_ONCE(epi-dying) fast-path bailout stays.

- [https://github.com/villager1314/CVE-2026-46242-Analysis](https://github.com/villager1314/CVE-2026-46242-Analysis) :  ![starts](https://img.shields.io/github/stars/villager1314/CVE-2026-46242-Analysis.svg) ![forks](https://img.shields.io/github/forks/villager1314/CVE-2026-46242-Analysis.svg)


## CVE-2026-42945
 NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module. This vulnerability exists when the rewrite directive is followed by a rewrite, if, or set directive and an unnamed Perl-Compatible Regular Expression (PCRE) capture (for example, $1, $2) with a replacement string that includes a question mark (?). An unauthenticated attacker along with conditions beyond its control can exploit this vulnerability by sending crafted HTTP requests. This may cause a heap buffer overflow in the NGINX worker process leading to a restart. Additionally, attackers can execute code on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/porcumarcooo/THM-CVE-2026-42945-Nginx-Rift-Exploit](https://github.com/porcumarcooo/THM-CVE-2026-42945-Nginx-Rift-Exploit) :  ![starts](https://img.shields.io/github/stars/porcumarcooo/THM-CVE-2026-42945-Nginx-Rift-Exploit.svg) ![forks](https://img.shields.io/github/forks/porcumarcooo/THM-CVE-2026-42945-Nginx-Rift-Exploit.svg)


## CVE-2026-31857
 Craft is a content management system (CMS). Prior to 5.9.9 and 4.17.4, a Remote Code Execution vulnerability exists in the Craft CMS 5 conditions system. The BaseElementSelectConditionRule::getElementIds() method passes user-controlled string input through renderObjectTemplate() -- an unsandboxed Twig rendering function with escaping disabled. Any authenticated Control Panel user (including non-admin roles such as Author or Editor) can achieve full RCE by sending a crafted condition rule via standard element listing endpoints. This vulnerability requires no admin privileges, no special permissions beyond basic control panel access, and bypasses all production hardening settings (allowAdminChanges: false, devMode: false, enableTwigSandbox: true). Users should update to the patched 5.9.9 or 4.17.4 release to mitigate the issue.

- [https://github.com/kaizoku73/CVE-2026-31857-PoC](https://github.com/kaizoku73/CVE-2026-31857-PoC) :  ![starts](https://img.shields.io/github/stars/kaizoku73/CVE-2026-31857-PoC.svg) ![forks](https://img.shields.io/github/forks/kaizoku73/CVE-2026-31857-PoC.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/abdullaabdullazade/CVE-2026-31431](https://github.com/abdullaabdullazade/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/abdullaabdullazade/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/abdullaabdullazade/CVE-2026-31431.svg)


## CVE-2026-21589
 This is a vulnerability in Bitbucket Data Center, Confluence Data Center, Jira Service Management Data Center, Jira Software Data Center, Bamboo Data Center. Crowd Data Center, Crucible and Fisheye. This Arbitrary File Access vulnerability allows an unauthenticated attacker to access specific files within the web application root directory in affected versions. Exploitation requires prior knowledge of the target file's exact name and path; this vulnerability does not allow attackers to enumerate or list directory contents. In some configurations, there may be some sensitive files that make this highly severe. This vulnerability allows an unauthenticated remote attacker to access specific files within the web application root directory in affected versions. The vulnerability must be addressed for affected versions of: -- Bitbucket Data Center, introduced in version = 4.6.0, fix versions: 9.4.26, 10.2.8, 10.5.1 -- Confluence Data Center, introduced in version = 5.10.0, fix versions 9.2.26, 10.2.19 -- Crowd Data Center, introduced in version = 2.11.0, fix versions 6.3.7, 7.0.3, 7.1.7, 7.2.4 -- Jira Software Data Center, introduced in version = 7.1.0, fix versions 9.12.40, 10.3.26, 11.3.12 -- Jira Service Management Data Center, introduced in version = 3.1.0, fix versions 5.12.40, 10.3.26, 11.3.12 -- Bamboo Data Center = 7.0.1, fix versions 10.2.24, 12.1.12 -- Crucible, fix versions 4.9.15 -- Fisheye, fix version 4.9.15 -- Exploitation requires prior knowledge of the target file's exact name and path. The vulnerability does not include the capability to enumerate or list directory contents.

- [https://github.com/murrez/CVE-2026-21589](https://github.com/murrez/CVE-2026-21589) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-21589.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-21589.svg)
- [https://github.com/renzi25031469/CVE-2026-21589](https://github.com/renzi25031469/CVE-2026-21589) :  ![starts](https://img.shields.io/github/stars/renzi25031469/CVE-2026-21589.svg) ![forks](https://img.shields.io/github/forks/renzi25031469/CVE-2026-21589.svg)
- [https://github.com/rxsklife/CVE-2026-21589](https://github.com/rxsklife/CVE-2026-21589) :  ![starts](https://img.shields.io/github/stars/rxsklife/CVE-2026-21589.svg) ![forks](https://img.shields.io/github/forks/rxsklife/CVE-2026-21589.svg)


## CVE-2026-18963
 A flaw was found in the reset-credentials flow of the keycloak-services component, which is the core engine for identity and access management in Red Hat Build of Keycloak. The issue allows an unauthenticated attacker to force the password reset process for any user without needing to click the required email verification link. This can result in the attacker gaining full control over target user accounts by directly setting new credentials.

- [https://github.com/SonOfABot/-CVE-2026-18963-POC](https://github.com/SonOfABot/-CVE-2026-18963-POC) :  ![starts](https://img.shields.io/github/stars/SonOfABot/-CVE-2026-18963-POC.svg) ![forks](https://img.shields.io/github/forks/SonOfABot/-CVE-2026-18963-POC.svg)
- [https://github.com/hardeep-sudo/Keycloak-CVE-2026-18963-Exploit](https://github.com/hardeep-sudo/Keycloak-CVE-2026-18963-Exploit) :  ![starts](https://img.shields.io/github/stars/hardeep-sudo/Keycloak-CVE-2026-18963-Exploit.svg) ![forks](https://img.shields.io/github/forks/hardeep-sudo/Keycloak-CVE-2026-18963-Exploit.svg)


## CVE-2026-11318
 Deskin through 3.3.4.3 contains a privilege escalation vulnerability in the com.deskin.service.installer XPC service that allows local unprivileged attackers to execute arbitrary installer packages as root by connecting to the root-owned service without authentication. Attackers can invoke the privileged installer method to run an attacker-supplied installer, achieving full root compromise of the macOS host.

- [https://github.com/Cr0wld3r/CVE-2026-11318](https://github.com/Cr0wld3r/CVE-2026-11318) :  ![starts](https://img.shields.io/github/stars/Cr0wld3r/CVE-2026-11318.svg) ![forks](https://img.shields.io/github/forks/Cr0wld3r/CVE-2026-11318.svg)


## CVE-2026-10726
 Cato Windows SDP Client before version 6.12.6 contains an arbitrary file disclosure vulnerability. A low-privileged local user can cause the Windows service, running as Local System, to read and disclose arbitrary local files due to improper file path validation and missing TLS certificate enforcement.

- [https://github.com/yuwkaaa/CVE-2026-107268](https://github.com/yuwkaaa/CVE-2026-107268) :  ![starts](https://img.shields.io/github/stars/yuwkaaa/CVE-2026-107268.svg) ![forks](https://img.shields.io/github/forks/yuwkaaa/CVE-2026-107268.svg)


## CVE-2026-10661
 A vulnerability has been found in ahujasid blender-mcp up to 7636d13bded82eca58eb93c3f4cd8708dfdfbe8b. Impacted is the function Open of the file src/blender_mcp/server.py. The manipulation of the argument input_image_url leads to injection. Remote exploitation of the attack is possible. The exploit has been disclosed to the public and may be used. This product follows a rolling release approach for continuous delivery, so version details for affected or updated releases are not provided. The identifier of the patch is 5b37be25242e73dc4cf1328974d30458b9e5d67e. To fix this issue, it is recommended to deploy a patch.

- [https://github.com/KevineCharles/CVE-2026-106610-miniorange-otp-ato](https://github.com/KevineCharles/CVE-2026-106610-miniorange-otp-ato) :  ![starts](https://img.shields.io/github/stars/KevineCharles/CVE-2026-106610-miniorange-otp-ato.svg) ![forks](https://img.shields.io/github/forks/KevineCharles/CVE-2026-106610-miniorange-otp-ato.svg)


## CVE-2026-5430
Successful exploitation of this vulnerability may result in unauthorized access to the system, including the potential compromise of administrative accounts and full account takeover. The CVSS score is adjusted to 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) in single-tenant deployments, reflecting that the impact is contained within a single security authority boundary.

- [https://github.com/getdrive/wso2_cve-2026-5430_lab](https://github.com/getdrive/wso2_cve-2026-5430_lab) :  ![starts](https://img.shields.io/github/stars/getdrive/wso2_cve-2026-5430_lab.svg) ![forks](https://img.shields.io/github/forks/getdrive/wso2_cve-2026-5430_lab.svg)


## CVE-2026-3143
 The Total Upkeep – WordPress Backup Plugin plus Restore & Migrate by BoldGrid plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'wp_ajax_cli_cancel' function in all versions up to, and including, 1.17.1. This makes it possible for unauthenticated attackers to cancel a pending rollback, potentially preventing a WordPress installation from automatically reverting a failed update.

- [https://github.com/sec17br/CVE-2026-31431-Copy-Fail](https://github.com/sec17br/CVE-2026-31431-Copy-Fail) :  ![starts](https://img.shields.io/github/stars/sec17br/CVE-2026-31431-Copy-Fail.svg) ![forks](https://img.shields.io/github/forks/sec17br/CVE-2026-31431-Copy-Fail.svg)


## CVE-2025-68664
 LangChain is a framework for building agents and LLM-powered applications. Prior to versions 0.3.81 and 1.2.5, a serialization injection vulnerability exists in LangChain's dumps() and dumpd() functions. The functions do not escape dictionaries with 'lc' keys when serializing free-form dictionaries. The 'lc' key is used internally by LangChain to mark serialized objects. When user-controlled data contains this key structure, it is treated as a legitimate LangChain object during deserialization rather than plain user data. This issue has been patched in versions 0.3.81 and 1.2.5.

- [https://github.com/t-sorger/cve-2025-68664-langgrinch](https://github.com/t-sorger/cve-2025-68664-langgrinch) :  ![starts](https://img.shields.io/github/stars/t-sorger/cve-2025-68664-langgrinch.svg) ![forks](https://img.shields.io/github/forks/t-sorger/cve-2025-68664-langgrinch.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)


## CVE-2025-62215
 Concurrent execution using shared resource with improper synchronization ('race condition') in Windows Kernel allows an authorized attacker to elevate privileges locally.

- [https://github.com/Hu2ie/CVE-2025-62215-Windows-Kernel---Elevation-of-Privilege](https://github.com/Hu2ie/CVE-2025-62215-Windows-Kernel---Elevation-of-Privilege) :  ![starts](https://img.shields.io/github/stars/Hu2ie/CVE-2025-62215-Windows-Kernel---Elevation-of-Privilege.svg) ![forks](https://img.shields.io/github/forks/Hu2ie/CVE-2025-62215-Windows-Kernel---Elevation-of-Privilege.svg)


## CVE-2025-57819
 FreePBX is an open-source web-based graphical user interface. FreePBX 15, 16, and 17 endpoints are vulnerable due to insufficiently sanitized user-supplied data allowing unauthenticated access to FreePBX Administrator leading to arbitrary database manipulation and remote code execution. This issue has been patched in endpoint versions 15.0.66, 16.0.89, and 17.0.3.

- [https://github.com/foxcornlab/freepbx-rce-detector](https://github.com/foxcornlab/freepbx-rce-detector) :  ![starts](https://img.shields.io/github/stars/foxcornlab/freepbx-rce-detector.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/freepbx-rce-detector.svg)


## CVE-2025-45737
 An issue in NetEase (Hangzhou) Network Co., Ltd NeacSafe64 Driver before v1.0.0.8 allows attackers to escalate privileges via sending crafted IOCTL commands to the NeacSafe64.sys component.

- [https://github.com/LanBaiCode/CVE-2025-45737](https://github.com/LanBaiCode/CVE-2025-45737) :  ![starts](https://img.shields.io/github/stars/LanBaiCode/CVE-2025-45737.svg) ![forks](https://img.shields.io/github/forks/LanBaiCode/CVE-2025-45737.svg)


## CVE-2025-21479
 Memory corruption due to unauthorized command execution in GPU micronode while executing specific sequence of commands.

- [https://github.com/Type010/cheese-app](https://github.com/Type010/cheese-app) :  ![starts](https://img.shields.io/github/stars/Type010/cheese-app.svg) ![forks](https://img.shields.io/github/forks/Type010/cheese-app.svg)


## CVE-2025-9974
 The unified WEBUI application of the ONT/Beacon device contains an input handling flaw that allows authenticated users to trigger unintended system-level command execution. Due to insufficient validation of user-supplied data, a low-privileged authenticated attacker may be able to execute arbitrary commands on the underlying ONT/Beacon operating system, potentially impacting the confidentiality, integrity, and availability of the device.

- [https://github.com/xxs-2/Beacon10-Getshell](https://github.com/xxs-2/Beacon10-Getshell) :  ![starts](https://img.shields.io/github/stars/xxs-2/Beacon10-Getshell.svg) ![forks](https://img.shields.io/github/forks/xxs-2/Beacon10-Getshell.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg)


## CVE-2025-1122
Bypass operating system verification via exploiting the NV_Read functionality during the Challenge-Response process.

- [https://github.com/IsolatedAnarchy/RMASmoke-v2](https://github.com/IsolatedAnarchy/RMASmoke-v2) :  ![starts](https://img.shields.io/github/stars/IsolatedAnarchy/RMASmoke-v2.svg) ![forks](https://img.shields.io/github/forks/IsolatedAnarchy/RMASmoke-v2.svg)


## CVE-2024-28752
 A SSRF vulnerability using the Aegis DataBinding in versions of Apache CXF before 4.0.4, 3.6.3 and 3.5.8 allows an attacker to perform SSRF style attacks on webservices that take at least one parameter of any type. Users of other data bindings (including the default databinding) are not impacted.

- [https://github.com/CyberCTF/vulhub-apache-cxf-cve-2024-28752](https://github.com/CyberCTF/vulhub-apache-cxf-cve-2024-28752) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-apache-cxf-cve-2024-28752.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-apache-cxf-cve-2024-28752.svg)


## CVE-2024-23897
 Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.

- [https://github.com/CyberCTF/vulhub-jenkins-cve-2024-23897](https://github.com/CyberCTF/vulhub-jenkins-cve-2024-23897) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-jenkins-cve-2024-23897.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-jenkins-cve-2024-23897.svg)


## CVE-2023-54391
 Proxmox Virtual Environment (VE) 7.0 through 8.0 contains an authentication bypass vulnerability in libpve-access-control before 8.0.4 that allows unauthenticated attackers to authenticate as any existing enabled user without a configured second factor by supplying an arbitrary tfa-challenge value in the API login endpoint. Attackers can send a POST request to the access ticket API endpoint with any value in the tfa-challenge parameter to completely skip password verification, gaining unauthorized access including to the root@pam account. All affected releases are end of life.

- [https://github.com/alexandrov666/CVE-2023-54391-RCE](https://github.com/alexandrov666/CVE-2023-54391-RCE) :  ![starts](https://img.shields.io/github/stars/alexandrov666/CVE-2023-54391-RCE.svg) ![forks](https://img.shields.io/github/forks/alexandrov666/CVE-2023-54391-RCE.svg)


## CVE-2023-51467
 The vulnerability permits attackers to circumvent authentication processes, enabling them to remotely execute arbitrary code

- [https://github.com/CyberCTF/vulhub-ofbiz-cve-2023-51467](https://github.com/CyberCTF/vulhub-ofbiz-cve-2023-51467) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-ofbiz-cve-2023-51467.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-ofbiz-cve-2023-51467.svg)


## CVE-2023-46604
which fixes this issue.

- [https://github.com/CyberCTF/vulhub-activemq-cve-2023-46604](https://github.com/CyberCTF/vulhub-activemq-cve-2023-46604) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-activemq-cve-2023-46604.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-activemq-cve-2023-46604.svg)


## CVE-2023-32315
 Openfire is an XMPP server licensed under the Open Source Apache License. Openfire's administrative console, a web-based application, was found to be vulnerable to a path traversal attack via the setup environment. This permitted an unauthenticated user to use the unauthenticated Openfire Setup Environment in an already configured Openfire environment to access restricted pages in the Openfire Admin Console reserved for administrative users. This vulnerability affects all versions of Openfire that have been released since April 2015, starting with version 3.10.0. The problem has been patched in Openfire release 4.7.5 and 4.6.8, and further improvements will be included in the yet-to-be released first version on the 4.8 branch (which is expected to be version 4.8.0). Users are advised to upgrade. If an Openfire upgrade isn’t available for a specific release, or isn’t quickly actionable, users may see the linked github advisory (GHSA-gw42-f939-fhvm) for mitigation advice.

- [https://github.com/CyberCTF/vulhub-openfire-cve-2023-32315](https://github.com/CyberCTF/vulhub-openfire-cve-2023-32315) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-openfire-cve-2023-32315.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-openfire-cve-2023-32315.svg)


## CVE-2023-27524
Alternatively you can set it with `SUPERSET_SECRET_KEY` environment variable.

- [https://github.com/CyberCTF/vulhub-superset-cve-2023-27524](https://github.com/CyberCTF/vulhub-superset-cve-2023-27524) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-superset-cve-2023-27524.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-superset-cve-2023-27524.svg)


## CVE-2023-23752
 An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

- [https://github.com/CyberCTF/vulhub-joomla-cve-2023-23752](https://github.com/CyberCTF/vulhub-joomla-cve-2023-23752) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-joomla-cve-2023-23752.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-joomla-cve-2023-23752.svg)


## CVE-2022-46169
This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/CyberCTF/vulhub-cacti-cve-2022-46169](https://github.com/CyberCTF/vulhub-cacti-cve-2022-46169) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-cacti-cve-2022-46169.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-cacti-cve-2022-46169.svg)


## CVE-2022-44268
 ImageMagick 7.1.0-49 is vulnerable to Information Disclosure. When it parses a PNG image (e.g., for resize), the resulting image could have embedded the content of an arbitrary. file (if the magick binary has permissions to read it).

- [https://github.com/CyberCTF/vulhub-imagemagick-cve-2022-44268](https://github.com/CyberCTF/vulhub-imagemagick-cve-2022-44268) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-imagemagick-cve-2022-44268.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-imagemagick-cve-2022-44268.svg)


## CVE-2022-34265
 An issue was discovered in Django 3.2 before 3.2.14 and 4.0 before 4.0.6. The Trunc() and Extract() database functions are subject to SQL injection if untrusted data is used as a kind/lookup_name value. Applications that constrain the lookup name and kind choice to a known safe list are unaffected.

- [https://github.com/CyberCTF/vulhub-django-cve-2022-34265](https://github.com/CyberCTF/vulhub-django-cve-2022-34265) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-django-cve-2022-34265.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-django-cve-2022-34265.svg)


## CVE-2022-23221
 H2 Console before 2.1.210 allows remote attackers to execute arbitrary code via a jdbc:h2:mem JDBC URL containing the IGNORE_UNKNOWN_SETTINGS=TRUE;FORBID_CREATION=FALSE;INIT=RUNSCRIPT substring, a different vulnerability than CVE-2021-42392.

- [https://github.com/CyberCTF/vulhub-h2database-cve-2022-23221](https://github.com/CyberCTF/vulhub-h2database-cve-2022-23221) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-h2database-cve-2022-23221.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-h2database-cve-2022-23221.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/CyberCTF/vulhub-spring-cve-2022-22965](https://github.com/CyberCTF/vulhub-spring-cve-2022-22965) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-spring-cve-2022-22965.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-spring-cve-2022-22965.svg)


## CVE-2022-22963
 In Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions, when using routing functionality it is possible for a user to provide a specially crafted SpEL as a routing-expression that may result in remote code execution and access to local resources.

- [https://github.com/CyberCTF/vulhub-spring-cve-2022-22963](https://github.com/CyberCTF/vulhub-spring-cve-2022-22963) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-spring-cve-2022-22963.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-spring-cve-2022-22963.svg)


## CVE-2022-22947
 In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

- [https://github.com/CyberCTF/vulhub-spring-cve-2022-22947](https://github.com/CyberCTF/vulhub-spring-cve-2022-22947) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-spring-cve-2022-22947.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-spring-cve-2022-22947.svg)


## CVE-2022-2296
 Use after free in Chrome OS Shell in Google Chrome on Chrome OS prior to 103.0.5060.114 allowed a remote attacker who convinced a user to engage in specific user interactions to potentially exploit heap corruption via direct UI interactions.

- [https://github.com/Shakur1314/CVE-2022-22965-Spring4Shell-Security-Operations-Analysis](https://github.com/Shakur1314/CVE-2022-22965-Spring4Shell-Security-Operations-Analysis) :  ![starts](https://img.shields.io/github/stars/Shakur1314/CVE-2022-22965-Spring4Shell-Security-Operations-Analysis.svg) ![forks](https://img.shields.io/github/forks/Shakur1314/CVE-2022-22965-Spring4Shell-Security-Operations-Analysis.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe-](https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe-) :  ![starts](https://img.shields.io/github/stars/Greetdawn/CVE-2022-0847-DirtyPipe-.svg) ![forks](https://img.shields.io/github/forks/Greetdawn/CVE-2022-0847-DirtyPipe-.svg)
- [https://github.com/pmihsan/Dirty-Pipe-CVE-2022-0847](https://github.com/pmihsan/Dirty-Pipe-CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/pmihsan/Dirty-Pipe-CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/pmihsan/Dirty-Pipe-CVE-2022-0847.svg)


## CVE-2022-0543
 It was discovered, that redis, a persistent key-value database, due to a packaging issue, is prone to a (Debian-specific) Lua sandbox escape, which could result in remote code execution.

- [https://github.com/CyberCTF/vulhub-redis-cve-2022-0543](https://github.com/CyberCTF/vulhub-redis-cve-2022-0543) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-redis-cve-2022-0543.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-redis-cve-2022-0543.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `grafana_host_url/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/CyberCTF/vulhub-grafana-cve-2021-43798](https://github.com/CyberCTF/vulhub-grafana-cve-2021-43798) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-grafana-cve-2021-43798.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-grafana-cve-2021-43798.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/CyberCTF/vulhub-httpd-cve-2021-42013](https://github.com/CyberCTF/vulhub-httpd-cve-2021-42013) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-httpd-cve-2021-42013.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-httpd-cve-2021-42013.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/LordX404/CVE_2021-41773](https://github.com/LordX404/CVE_2021-41773) :  ![starts](https://img.shields.io/github/stars/LordX404/CVE_2021-41773.svg) ![forks](https://img.shields.io/github/forks/LordX404/CVE_2021-41773.svg)


## CVE-2021-39214
 mitmproxy is an interactive, SSL/TLS-capable intercepting proxy. In mitmproxy 7.0.2 and below, a malicious client or server is able to perform HTTP request smuggling attacks through mitmproxy. This means that a malicious client/server could smuggle a request/response through mitmproxy as part of another request/response's HTTP message body. While a smuggled request is still captured as part of another request's body, it does not appear in the request list and does not go through the usual mitmproxy event hooks, where users may have implemented custom access control checks or input sanitization. Unless one uses mitmproxy to protect an HTTP/1 service, no action is required. The vulnerability has been fixed in mitmproxy 7.0.3 and above.

- [https://github.com/CyberCTF/secdevlabs-golden-hat](https://github.com/CyberCTF/secdevlabs-golden-hat) :  ![starts](https://img.shields.io/github/stars/CyberCTF/secdevlabs-golden-hat.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/secdevlabs-golden-hat.svg)


## CVE-2021-30535
 Double free in ICU in Google Chrome prior to 91.0.4472.77 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/califio/icu4x-crubit-demo](https://github.com/califio/icu4x-crubit-demo) :  ![starts](https://img.shields.io/github/stars/califio/icu4x-crubit-demo.svg) ![forks](https://img.shields.io/github/forks/califio/icu4x-crubit-demo.svg)


## CVE-2021-29441
 Nacos is a platform designed for dynamic service discovery and configuration and service management. In Nacos before version 1.4.1, when configured to use authentication (-Dnacos.core.auth.enabled=true) Nacos uses the AuthFilter servlet filter to enforce authentication. This filter has a backdoor that enables Nacos servers to bypass this filter and therefore skip authentication checks. This mechanism relies on the user-agent HTTP header so it can be easily spoofed. This issue may allow any user to carry out any administrative tasks on the Nacos server.

- [https://github.com/CyberCTF/vulhub-nacos-cve-2021-29441](https://github.com/CyberCTF/vulhub-nacos-cve-2021-29441) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-nacos-cve-2021-29441.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-nacos-cve-2021-29441.svg)


## CVE-2021-28164
 In Eclipse Jetty 9.4.37.v20210219 to 9.4.38.v20210224, the default compliance mode allows requests with URIs that contain %2e or %2e%2e segments to access protected resources within the WEB-INF directory. For example a request to /context/%2e/WEB-INF/web.xml can retrieve the web.xml file. This can reveal sensitive information regarding the implementation of a web application.

- [https://github.com/CyberCTF/vulhub-jetty-cve-2021-28164](https://github.com/CyberCTF/vulhub-jetty-cve-2021-28164) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-jetty-cve-2021-28164.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-jetty-cve-2021-28164.svg)


## CVE-2021-25646
 Apache Druid includes the ability to execute user-provided JavaScript code embedded in various types of requests. This functionality is intended for use in high-trust environments, and is disabled by default. However, in Druid 0.20.0 and earlier, it is possible for an authenticated user to send a specially-crafted request that forces Druid to run user-provided JavaScript code for that request, regardless of server configuration. This can be leveraged to execute code on the target machine with the privileges of the Druid server process.

- [https://github.com/CyberCTF/vulhub-apache-druid-cve-2021-25646](https://github.com/CyberCTF/vulhub-apache-druid-cve-2021-25646) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-apache-druid-cve-2021-25646.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-apache-druid-cve-2021-25646.svg)


## CVE-2021-22205
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 11.9. GitLab was not properly validating image files that were passed to a file parser which resulted in a remote command execution.

- [https://github.com/CyberCTF/vulhub-gitlab-cve-2021-22205](https://github.com/CyberCTF/vulhub-gitlab-cve-2021-22205) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-gitlab-cve-2021-22205.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-gitlab-cve-2021-22205.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/Super-Binary/cve-2021-44228](https://github.com/Super-Binary/cve-2021-44228) :  ![starts](https://img.shields.io/github/stars/Super-Binary/cve-2021-44228.svg) ![forks](https://img.shields.io/github/forks/Super-Binary/cve-2021-44228.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/0xrogg/CVE-2021-41773](https://github.com/0xrogg/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/0xrogg/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/0xrogg/CVE-2021-41773.svg)


## CVE-2021-3129
 Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.

- [https://github.com/CyberCTF/vulhub-laravel-cve-2021-3129](https://github.com/CyberCTF/vulhub-laravel-cve-2021-3129) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-laravel-cve-2021-3129.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-laravel-cve-2021-3129.svg)


## CVE-2020-35476
 A remote code execution vulnerability occurs in OpenTSDB through 2.4.0 via command injection in the yrange parameter. The yrange value is written to a gnuplot file in the /tmp directory. This file is then executed via the mygnuplot.sh shell script. (tsd/GraphHandler.java attempted to prevent command injections by blocking backticks but this is insufficient.)

- [https://github.com/CyberCTF/vulhub-opentsdb-cve-2020-35476](https://github.com/CyberCTF/vulhub-opentsdb-cve-2020-35476) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-opentsdb-cve-2020-35476.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-opentsdb-cve-2020-35476.svg)


## CVE-2020-17519
 A change introduced in Apache Flink 1.11.0 (and released in 1.11.1 and 1.11.2 as well) allows attackers to read any file on the local filesystem of the JobManager through the REST interface of the JobManager process. Access is restricted to files accessible by the JobManager process. All users should upgrade to Flink 1.11.3 or 1.12.0 if their Flink instance(s) are exposed. The issue was fixed in commit b561010b0ee741543c3953306037f00d7a9f0801 from apache/flink:master.

- [https://github.com/CyberCTF/vulhub-flink-cve-2020-17519](https://github.com/CyberCTF/vulhub-flink-cve-2020-17519) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-flink-cve-2020-17519.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-flink-cve-2020-17519.svg)


## CVE-2020-14883
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows high privileged attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 7.2 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/CyberCTF/vulhub-weblogic-cve-2020-14882](https://github.com/CyberCTF/vulhub-weblogic-cve-2020-14882) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-weblogic-cve-2020-14882.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-weblogic-cve-2020-14882.svg)


## CVE-2020-14882
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/CyberCTF/vulhub-weblogic-cve-2020-14882](https://github.com/CyberCTF/vulhub-weblogic-cve-2020-14882) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-weblogic-cve-2020-14882.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-weblogic-cve-2020-14882.svg)


## CVE-2020-13945
 In Apache APISIX, the user enabled the Admin API and deleted the Admin API access IP restriction rules. Eventually, the default token is allowed to access APISIX management data. This affects versions 1.2, 1.3, 1.4, 1.5.

- [https://github.com/CyberCTF/vulhub-apisix-cve-2020-13945](https://github.com/CyberCTF/vulhub-apisix-cve-2020-13945) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-apisix-cve-2020-13945.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-apisix-cve-2020-13945.svg)


## CVE-2020-13942
 It is possible to inject malicious OGNL or MVEL scripts into the /context.json public endpoint. This was partially fixed in 1.5.1 but a new attack vector was found. In Apache Unomi version 1.5.2 scripts are now completely filtered from the input. It is highly recommended to upgrade to the latest available version of the 1.5.x release to fix this problem.

- [https://github.com/CyberCTF/vulhub-unomi-cve-2020-13942](https://github.com/CyberCTF/vulhub-unomi-cve-2020-13942) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-unomi-cve-2020-13942.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-unomi-cve-2020-13942.svg)


## CVE-2020-11651
 An issue was discovered in SaltStack Salt before 2019.2.4 and 3000 before 3000.2. The salt-master process ClearFuncs class does not properly validate method calls. This allows a remote user to access some methods without authentication. These methods can be used to retrieve user tokens from the salt master and/or run arbitrary commands on salt minions.

- [https://github.com/CyberCTF/vulhub-saltstack-cve-2020-11651](https://github.com/CyberCTF/vulhub-saltstack-cve-2020-11651) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-saltstack-cve-2020-11651.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-saltstack-cve-2020-11651.svg)


## CVE-2020-7247
 smtp_mailaddr in smtp_session.c in OpenSMTPD 6.6, as used in OpenBSD 6.6 and other products, allows remote attackers to execute arbitrary commands as root via a crafted SMTP session, as demonstrated by shell metacharacters in a MAIL FROM field. This affects the "uncommented" default configuration. The issue exists because of an incorrect return value upon failure of input validation.

- [https://github.com/CyberCTF/vulhub-opensmtpd-cve-2020-7247](https://github.com/CyberCTF/vulhub-opensmtpd-cve-2020-7247) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-opensmtpd-cve-2020-7247.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-opensmtpd-cve-2020-7247.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/CyberCTF/vulhub-tomcat-cve-2020-1938](https://github.com/CyberCTF/vulhub-tomcat-cve-2020-1938) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-tomcat-cve-2020-1938.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-tomcat-cve-2020-1938.svg)


## CVE-2019-20933
 InfluxDB before 1.7.6 has an authentication bypass vulnerability in the authenticate function in services/httpd/handler.go because a JWT token may have an empty SharedSecret (aka shared secret).

- [https://github.com/CyberCTF/vulhub-influxdb-cve-2019-20933](https://github.com/CyberCTF/vulhub-influxdb-cve-2019-20933) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-influxdb-cve-2019-20933.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-influxdb-cve-2019-20933.svg)


## CVE-2019-17564
 Unsafe deserialization occurs within a Dubbo application which has HTTP remoting enabled. An attacker may submit a POST request with a Java object in it to completely compromise a Provider instance of Apache Dubbo, if this instance enables HTTP. This issue affected Apache Dubbo 2.7.0 to 2.7.4, 2.6.0 to 2.6.7, and all 2.5.x versions.

- [https://github.com/CyberCTF/vulhub-dubbo-cve-2019-17564](https://github.com/CyberCTF/vulhub-dubbo-cve-2019-17564) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-dubbo-cve-2019-17564.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-dubbo-cve-2019-17564.svg)


## CVE-2019-17558
 Apache Solr 5.0.0 to Apache Solr 8.3.1 are vulnerable to a Remote Code Execution through the VelocityResponseWriter. A Velocity template can be provided through Velocity templates in a configset `velocity/` directory or as a parameter. A user defined configset could contain renderable, potentially malicious, templates. Parameter provided templates are disabled by default, but can be enabled by setting `params.resource.loader.enabled` by defining a response writer with that setting set to `true`. Defining a response writer requires configuration API access. Solr 8.4 removed the params resource loader entirely, and only enables the configset-provided template rendering when the configset is `trusted` (has been uploaded by an authenticated user).

- [https://github.com/CyberCTF/vulhub-solr-cve-2019-17558](https://github.com/CyberCTF/vulhub-solr-cve-2019-17558) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-solr-cve-2019-17558.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-solr-cve-2019-17558.svg)


## CVE-2019-15107
 An issue was discovered in Webmin =1.920. The parameter old in password_change.cgi contains a command injection vulnerability.

- [https://github.com/CyberCTF/vulhub-webmin-cve-2019-15107](https://github.com/CyberCTF/vulhub-webmin-cve-2019-15107) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-webmin-cve-2019-15107.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-webmin-cve-2019-15107.svg)


## CVE-2019-11043
 In PHP versions 7.1.x below 7.1.33, 7.2.x below 7.2.24 and 7.3.x below 7.3.11 in certain configurations of FPM setup it is possible to cause FPM module to write past allocated buffers into the space reserved for FCGI protocol data, thus opening the possibility of remote code execution.

- [https://github.com/CyberCTF/vulhub-php-cve-2019-11043](https://github.com/CyberCTF/vulhub-php-cve-2019-11043) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-php-cve-2019-11043.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-php-cve-2019-11043.svg)


## CVE-2019-10758
 mongo-express before 0.54.0 is vulnerable to Remote Code Execution via endpoints that uses the `toBSON` method. A misuse of the `vm` dependency to perform `exec` commands in a non-safe environment.

- [https://github.com/CyberCTF/vulhub-mongo-express-cve-2019-10758](https://github.com/CyberCTF/vulhub-mongo-express-cve-2019-10758) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-mongo-express-cve-2019-10758.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-mongo-express-cve-2019-10758.svg)


## CVE-2019-9193
 In PostgreSQL 9.3 through 11.2, the "COPY TO/FROM PROGRAM" function allows superusers and users in the 'pg_execute_server_program' group to execute arbitrary code in the context of the database's operating system user. This functionality is enabled by default and can be abused to run arbitrary operating system commands on Windows, Linux, and macOS. NOTE: Third parties claim/state this is not an issue because PostgreSQL functionality for ‘COPY TO/FROM PROGRAM’ is acting as intended. References state that in PostgreSQL, a superuser can execute commands as the server user without using the ‘COPY FROM PROGRAM’.

- [https://github.com/CyberCTF/vulhub-postgres-cve-2019-9193](https://github.com/CyberCTF/vulhub-postgres-cve-2019-9193) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-postgres-cve-2019-9193.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-postgres-cve-2019-9193.svg)


## CVE-2019-7609
 Kibana versions before 5.6.15 and 6.6.1 contain an arbitrary code execution flaw in the Timelion visualizer. An attacker with access to the Timelion application could send a request that will attempt to execute javascript code. This could possibly lead to an attacker executing arbitrary commands with permissions of the Kibana process on the host system.

- [https://github.com/CyberCTF/vulhub-kibana-cve-2019-7609](https://github.com/CyberCTF/vulhub-kibana-cve-2019-7609) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-kibana-cve-2019-7609.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-kibana-cve-2019-7609.svg)


## CVE-2019-7238
 Sonatype Nexus Repository Manager before 3.15.0 has Incorrect Access Control.

- [https://github.com/CyberCTF/vulhub-nexus-cve-2019-7238](https://github.com/CyberCTF/vulhub-nexus-cve-2019-7238) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-nexus-cve-2019-7238.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-nexus-cve-2019-7238.svg)


## CVE-2019-5418
 There is a File Content Disclosure vulnerability in Action View 5.2.2.1, 5.1.6.2, 5.0.7.2, 4.2.11.1 and v3 where specially crafted accept headers can cause contents of arbitrary files on the target system's filesystem to be exposed.

- [https://github.com/CyberCTF/vulhub-rails-cve-2019-5418](https://github.com/CyberCTF/vulhub-rails-cve-2019-5418) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-rails-cve-2019-5418.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-rails-cve-2019-5418.svg)


## CVE-2018-1000861
 A code execution vulnerability exists in the Stapler web framework used by Jenkins 2.153 and earlier, LTS 2.138.3 and earlier in stapler/core/src/main/java/org/kohsuke/stapler/MetaClass.java that allows attackers to invoke some methods on Java objects by accessing crafted URLs that were not intended to be invoked this way.

- [https://github.com/CyberCTF/vulhub-jenkins-cve-2018-1000861](https://github.com/CyberCTF/vulhub-jenkins-cve-2018-1000861) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-jenkins-cve-2018-1000861.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-jenkins-cve-2018-1000861.svg)


## CVE-2018-16509
 An issue was discovered in Artifex Ghostscript before 9.24. Incorrect "restoration of privilege" checking during handling of /invalidaccess exceptions could be used by attackers able to supply crafted PostScript to execute code using the "pipe" instruction.

- [https://github.com/CyberCTF/vulhub-ghostscript-cve-2018-16509](https://github.com/CyberCTF/vulhub-ghostscript-cve-2018-16509) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-ghostscript-cve-2018-16509.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-ghostscript-cve-2018-16509.svg)


## CVE-2018-15473
 OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user until after the packet containing the request has been fully parsed, related to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.

- [https://github.com/CyberCTF/vulhub-openssh-cve-2018-15473](https://github.com/CyberCTF/vulhub-openssh-cve-2018-15473) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-openssh-cve-2018-15473.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-openssh-cve-2018-15473.svg)


## CVE-2018-12613
 An issue was discovered in phpMyAdmin 4.8.x before 4.8.2, in which an attacker can include (view and potentially execute) files on the server. The vulnerability comes from a portion of code where pages are redirected and loaded within phpMyAdmin, and an improper test for whitelisted pages. An attacker must be authenticated, except in the "$cfg['AllowArbitraryServer'] = true" case (where an attacker can specify any host he/she is already in control of, and execute arbitrary code on phpMyAdmin) and the "$cfg['ServerDefault'] = 0" case (which bypasses the login requirement and runs the vulnerable code without any authentication).

- [https://github.com/CyberCTF/vulhub-phpmyadmin-cve-2018-12613](https://github.com/CyberCTF/vulhub-phpmyadmin-cve-2018-12613) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-phpmyadmin-cve-2018-12613.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-phpmyadmin-cve-2018-12613.svg)


## CVE-2018-10933
 A vulnerability was found in libssh's server-side state machine before versions 0.7.6 and 0.8.4. A malicious client could create channels without first performing authentication, resulting in unauthorized access.

- [https://github.com/CyberCTF/vulhub-libssh-cve-2018-10933](https://github.com/CyberCTF/vulhub-libssh-cve-2018-10933) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-libssh-cve-2018-10933.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-libssh-cve-2018-10933.svg)


## CVE-2018-8715
 The Embedthis HTTP library, and Appweb versions before 7.0.3, have a logic flaw related to the authCondition function in http/httpLib.c. With a forged HTTP request, it is possible to bypass authentication for the form and digest login types.

- [https://github.com/CyberCTF/vulhub-appweb-cve-2018-8715](https://github.com/CyberCTF/vulhub-appweb-cve-2018-8715) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-appweb-cve-2018-8715.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-appweb-cve-2018-8715.svg)


## CVE-2018-7600
 Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations.

- [https://github.com/CyberCTF/vulhub-drupal-cve-2018-7600](https://github.com/CyberCTF/vulhub-drupal-cve-2018-7600) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-drupal-cve-2018-7600.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-drupal-cve-2018-7600.svg)


## CVE-2018-7490
 uWSGI before 2.0.17 mishandles a DOCUMENT_ROOT check during use of the --php-docroot option, allowing directory traversal.

- [https://github.com/CyberCTF/vulhub-uwsgi-cve-2018-7490](https://github.com/CyberCTF/vulhub-uwsgi-cve-2018-7490) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-uwsgi-cve-2018-7490.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-uwsgi-cve-2018-7490.svg)


## CVE-2018-3760
 There is an information leak vulnerability in Sprockets. Versions Affected: 4.0.0.beta7 and lower, 3.7.1 and lower, 2.12.4 and lower. Specially crafted requests can be used to access files that exists on the filesystem that is outside an application's root directory, when the Sprockets server is used in production. All users running an affected release should either upgrade or use one of the work arounds immediately.

- [https://github.com/CyberCTF/vulhub-rails-cve-2018-3760](https://github.com/CyberCTF/vulhub-rails-cve-2018-3760) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-rails-cve-2018-3760.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-rails-cve-2018-3760.svg)


## CVE-2018-1297
 When using Distributed Test only (RMI based), Apache JMeter 2.x and 3.x uses an unsecured RMI connection. This could allow an attacker to get Access to JMeterEngine and send unauthorized code.

- [https://github.com/CyberCTF/vulhub-jmeter-cve-2018-1297](https://github.com/CyberCTF/vulhub-jmeter-cve-2018-1297) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-jmeter-cve-2018-1297.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-jmeter-cve-2018-1297.svg)


## CVE-2018-1273
 Spring Data Commons, versions prior to 1.13 to 1.13.10, 2.0 to 2.0.5, and older unsupported versions, contain a property binder vulnerability caused by improper neutralization of special elements. An unauthenticated remote malicious user (or attacker) can supply specially crafted request parameters against Spring Data REST backed HTTP resources or using Spring Data's projection-based request payload binding hat can lead to a remote code execution attack.

- [https://github.com/CyberCTF/vulhub-spring-cve-2018-1273](https://github.com/CyberCTF/vulhub-spring-cve-2018-1273) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-spring-cve-2018-1273.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-spring-cve-2018-1273.svg)


## CVE-2017-1000028
 Oracle, GlassFish Server Open Source Edition 4.1 is vulnerable to both authenticated and unauthenticated Directory Traversal vulnerability, that can be exploited by issuing a specially crafted HTTP GET request.

- [https://github.com/CyberCTF/vulhub-glassfish-cve-2017-1000028](https://github.com/CyberCTF/vulhub-glassfish-cve-2017-1000028) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-glassfish-cve-2017-1000028.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-glassfish-cve-2017-1000028.svg)


## CVE-2017-15715
 In Apache httpd 2.4.0 to 2.4.29, the expression specified in FilesMatch could match '$' to a newline character in a malicious filename, rather than matching only the end of the filename. This could be exploited in environments where uploads of some files are are externally blocked, but only by matching the trailing portion of the filename.

- [https://github.com/CyberCTF/vulhub-httpd-cve-2017-15715](https://github.com/CyberCTF/vulhub-httpd-cve-2017-15715) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-httpd-cve-2017-15715.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-httpd-cve-2017-15715.svg)


## CVE-2017-14849
 Node.js 8.5.0 before 8.6.0 allows remote attackers to access unintended files, because a change to ".." handling was incompatible with the pathname validation used by unspecified community modules.

- [https://github.com/CyberCTF/vulhub-node-cve-2017-14849](https://github.com/CyberCTF/vulhub-node-cve-2017-14849) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-node-cve-2017-14849.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-node-cve-2017-14849.svg)


## CVE-2017-12635
 Due to differences in the Erlang-based JSON parser and JavaScript-based JSON parser, it is possible in Apache CouchDB before 1.7.0 and 2.x before 2.1.1 to submit _users documents with duplicate keys for 'roles' used for access control within the database, including the special case '_admin' role, that denotes administrative users. In combination with CVE-2017-12636 (Remote Code Execution), this can be used to give non-admin users access to arbitrary shell commands on the server as the database system user. The JSON parser differences result in behaviour that if two 'roles' keys are available in the JSON, the second one will be used for authorising the document write, but the first 'roles' key is used for subsequent authorization for the newly created user. By design, users can not assign themselves roles. The vulnerability allows non-admin users to give themselves admin privileges.

- [https://github.com/CyberCTF/vulhub-couchdb-cve-2017-12635](https://github.com/CyberCTF/vulhub-couchdb-cve-2017-12635) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-couchdb-cve-2017-12635.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-couchdb-cve-2017-12635.svg)


## CVE-2017-12629
 Remote code execution occurs in Apache Solr before 7.1 with Apache Lucene before 7.1 by exploiting XXE in conjunction with use of a Config API add-listener command to reach the RunExecutableListener class. Elasticsearch, although it uses Lucene, is NOT vulnerable to this. Note that the XML external entity expansion vulnerability occurs in the XML Query Parser which is available, by default, for any query request with parameters deftype=xmlparser and can be exploited to upload malicious data to the /upload request handler or as Blind XXE using ftp wrapper in order to read arbitrary local files from the Solr server. Note also that the second vulnerability relates to remote code execution using the RunExecutableListener available on all affected versions of Solr.

- [https://github.com/CyberCTF/vulhub-solr-cve-2017-12629-rce](https://github.com/CyberCTF/vulhub-solr-cve-2017-12629-rce) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-solr-cve-2017-12629-rce.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-solr-cve-2017-12629-rce.svg)


## CVE-2017-12615
 When running Apache Tomcat 7.0.0 to 7.0.79 on Windows with HTTP PUTs enabled (e.g. via setting the readonly initialisation parameter of the Default to false) it was possible to upload a JSP file to the server via a specially crafted request. This JSP could then be requested and any code it contained would be executed by the server.

- [https://github.com/CyberCTF/vulhub-tomcat-cve-2017-12615](https://github.com/CyberCTF/vulhub-tomcat-cve-2017-12615) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-tomcat-cve-2017-12615.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-tomcat-cve-2017-12615.svg)


## CVE-2017-12149
 In Jboss Application Server as shipped with Red Hat Enterprise Application Platform 5.2, it was found that the doFilter method in the ReadOnlyAccessFilter of the HTTP Invoker does not restrict classes for which it performs deserialization and thus allowing an attacker to execute arbitrary code via crafted serialized data.

- [https://github.com/CyberCTF/vulhub-jboss-cve-2017-12149](https://github.com/CyberCTF/vulhub-jboss-cve-2017-12149) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-jboss-cve-2017-12149.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-jboss-cve-2017-12149.svg)


## CVE-2017-11610
 The XML-RPC server in supervisor before 3.0.1, 3.1.x before 3.1.4, 3.2.x before 3.2.4, and 3.3.x before 3.3.3 allows remote authenticated users to execute arbitrary commands via a crafted XML-RPC request, related to nested supervisord namespace lookups.

- [https://github.com/CyberCTF/vulhub-supervisor-cve-2017-11610](https://github.com/CyberCTF/vulhub-supervisor-cve-2017-11610) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-supervisor-cve-2017-11610.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-supervisor-cve-2017-11610.svg)


## CVE-2017-10271
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Security). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.1.0 and 12.2.1.2.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 7.5 (Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H).

- [https://github.com/CyberCTF/vulhub-weblogic-cve-2017-10271](https://github.com/CyberCTF/vulhub-weblogic-cve-2017-10271) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-weblogic-cve-2017-10271.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-weblogic-cve-2017-10271.svg)


## CVE-2017-9841
 Util/PHP/eval-stdin.php in PHPUnit before 4.8.28 and 5.x before 5.6.3 allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a "?php " substring, as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.

- [https://github.com/CyberCTF/vulhub-phpunit-cve-2017-9841](https://github.com/CyberCTF/vulhub-phpunit-cve-2017-9841) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-phpunit-cve-2017-9841.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-phpunit-cve-2017-9841.svg)


## CVE-2017-7529
 Nginx versions since 0.5.6 up to and including 1.13.2 are vulnerable to integer overflow vulnerability in nginx range filter module resulting into leak of potentially sensitive information triggered by specially crafted request.

- [https://github.com/CyberCTF/vulhub-nginx-cve-2017-7529](https://github.com/CyberCTF/vulhub-nginx-cve-2017-7529) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-nginx-cve-2017-7529.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-nginx-cve-2017-7529.svg)


## CVE-2017-7494
 Samba since version 3.5.0 and before 4.6.4, 4.5.10 and 4.4.14 is vulnerable to remote code execution vulnerability, allowing a malicious client to upload a shared library to a writable share, and then cause the server to load and execute it.

- [https://github.com/CyberCTF/vulhub-samba-cve-2017-7494](https://github.com/CyberCTF/vulhub-samba-cve-2017-7494) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-samba-cve-2017-7494.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-samba-cve-2017-7494.svg)


## CVE-2016-10134
 SQL injection vulnerability in Zabbix before 2.2.14 and 3.0 before 3.0.4 allows remote attackers to execute arbitrary SQL commands via the toggle_ids array parameter in latest.php.

- [https://github.com/CyberCTF/vulhub-zabbix-cve-2016-10134](https://github.com/CyberCTF/vulhub-zabbix-cve-2016-10134) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-zabbix-cve-2016-10134.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-zabbix-cve-2016-10134.svg)


## CVE-2016-4977
 When processing authorization requests using the whitelabel views in Spring Security OAuth 2.0.0 to 2.0.9 and 1.0.0 to 1.0.5, the response_type parameter value was executed as Spring SpEL which enabled a malicious user to trigger remote code execution via the crafting of the value for response_type.

- [https://github.com/CyberCTF/vulhub-spring-cve-2016-4977](https://github.com/CyberCTF/vulhub-spring-cve-2016-4977) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-spring-cve-2016-4977.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-spring-cve-2016-4977.svg)


## CVE-2016-4437
 Apache Shiro before 1.2.5, when a cipher key has not been configured for the "remember me" feature, allows remote attackers to execute arbitrary code or bypass intended access restrictions via an unspecified request parameter.

- [https://github.com/CyberCTF/vulhub-shiro-cve-2016-4437](https://github.com/CyberCTF/vulhub-shiro-cve-2016-4437) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-shiro-cve-2016-4437.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-shiro-cve-2016-4437.svg)


## CVE-2016-3714
 The (1) EPHEMERAL, (2) HTTPS, (3) MVG, (4) MSL, (5) TEXT, (6) SHOW, (7) WIN, and (8) PLT coders in ImageMagick before 6.9.3-10 and 7.x before 7.0.1-1 allow remote attackers to execute arbitrary code via shell metacharacters in a crafted image, aka "ImageTragick."

- [https://github.com/CyberCTF/vulhub-imagemagick-cve-2016-3714](https://github.com/CyberCTF/vulhub-imagemagick-cve-2016-3714) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-imagemagick-cve-2016-3714.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-imagemagick-cve-2016-3714.svg)


## CVE-2016-3088
 The Fileserver web application in Apache ActiveMQ 5.x before 5.14.0 allows remote attackers to upload and execute arbitrary files via an HTTP PUT followed by an HTTP MOVE request.

- [https://github.com/CyberCTF/vulhub-activemq-cve-2016-3088](https://github.com/CyberCTF/vulhub-activemq-cve-2016-3088) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-activemq-cve-2016-3088.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-activemq-cve-2016-3088.svg)


## CVE-2015-1427
 The Groovy scripting engine in Elasticsearch before 1.3.8 and 1.4.x before 1.4.3 allows remote attackers to bypass the sandbox protection mechanism and execute arbitrary shell commands via a crafted script.

- [https://github.com/CyberCTF/vulhub-elasticsearch-cve-2015-1427](https://github.com/CyberCTF/vulhub-elasticsearch-cve-2015-1427) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-elasticsearch-cve-2015-1427.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-elasticsearch-cve-2015-1427.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock."  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/CyberCTF/vulhub-bash-cve-2014-6271](https://github.com/CyberCTF/vulhub-bash-cve-2014-6271) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-bash-cve-2014-6271.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-bash-cve-2014-6271.svg)


## CVE-2014-3704
 The expandArguments function in the database abstraction API in Drupal core 7.x before 7.32 does not properly construct prepared statements, which allows remote attackers to conduct SQL injection attacks via an array containing crafted keys.

- [https://github.com/CyberCTF/vulhub-drupal-cve-2014-3704](https://github.com/CyberCTF/vulhub-drupal-cve-2014-3704) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-drupal-cve-2014-3704.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-drupal-cve-2014-3704.svg)


## CVE-2014-3120
 The default configuration in Elasticsearch before 1.2 enables dynamic scripting, which allows remote attackers to execute arbitrary MVEL expressions and Java code via the source parameter to _search.  NOTE: this only violates the vendor's intended security policy if the user does not run Elasticsearch in its own independent virtual machine.

- [https://github.com/CyberCTF/vulhub-elasticsearch-cve-2014-3120](https://github.com/CyberCTF/vulhub-elasticsearch-cve-2014-3120) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-elasticsearch-cve-2014-3120.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-elasticsearch-cve-2014-3120.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/CyberCTF/vulhub-openssl-cve-2014-0160](https://github.com/CyberCTF/vulhub-openssl-cve-2014-0160) :  ![starts](https://img.shields.io/github/stars/CyberCTF/vulhub-openssl-cve-2014-0160.svg) ![forks](https://img.shields.io/github/forks/CyberCTF/vulhub-openssl-cve-2014-0160.svg)

