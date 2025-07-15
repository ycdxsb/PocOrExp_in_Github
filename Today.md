# Update 2025-07-15
## CVE-2025-49113
 Roundcube Webmail before 1.5.10 and 1.6.x before 1.6.11 allows remote code execution by authenticated users because the _from parameter in a URL is not validated in program/actions/settings/upload.php, leading to PHP Object Deserialization.

- [https://github.com/hackmelocal/HML-CVE-2025-49113](https://github.com/hackmelocal/HML-CVE-2025-49113) :  ![starts](https://img.shields.io/github/stars/hackmelocal/HML-CVE-2025-49113.svg) ![forks](https://img.shields.io/github/forks/hackmelocal/HML-CVE-2025-49113.svg)


## CVE-2025-47981
 Heap-based buffer overflow in Windows SPNEGO Extended Negotiation allows an unauthorized attacker to execute code over a network.

- [https://github.com/barbaraogmgf/CVE-2025-47981-POC](https://github.com/barbaraogmgf/CVE-2025-47981-POC) :  ![starts](https://img.shields.io/github/stars/barbaraogmgf/CVE-2025-47981-POC.svg) ![forks](https://img.shields.io/github/forks/barbaraogmgf/CVE-2025-47981-POC.svg)


## CVE-2025-34085
 An unrestricted file upload vulnerability in the WordPress Simple File List plugin prior to version 4.2.3 allows unauthenticated remote attackers to achieve remote code execution. The plugin's upload endpoint (ee-upload-engine.php) restricts file uploads based on extension, but lacks proper validation after file renaming. An attacker can first upload a PHP payload disguised as a .png file, then use the plugin’s ee-file-engine.php rename functionality to change the extension to .php. This bypasses upload restrictions and results in the uploaded payload being executable on the server.

- [https://github.com/ill-deed/CVE-2025-34085-Multi-target](https://github.com/ill-deed/CVE-2025-34085-Multi-target) :  ![starts](https://img.shields.io/github/stars/ill-deed/CVE-2025-34085-Multi-target.svg) ![forks](https://img.shields.io/github/forks/ill-deed/CVE-2025-34085-Multi-target.svg)


## CVE-2025-31125
 Vite is a frontend tooling framework for javascript. Vite exposes content of non-allowed files using ?inline&import or ?raw?import. Only apps explicitly exposing the Vite dev server to the network (using --host or server.host config option) are affected. This vulnerability is fixed in 6.2.4, 6.1.3, 6.0.13, 5.4.16, and 4.5.11.

- [https://github.com/harshgupptaa/Path-Transversal-CVE-2025-31125-](https://github.com/harshgupptaa/Path-Transversal-CVE-2025-31125-) :  ![starts](https://img.shields.io/github/stars/harshgupptaa/Path-Transversal-CVE-2025-31125-.svg) ![forks](https://img.shields.io/github/forks/harshgupptaa/Path-Transversal-CVE-2025-31125-.svg)


## CVE-2025-27591
 A privilege escalation vulnerability existed in the Below service prior to v0.9.0 due to the creation of a world-writable directory at /var/log/below. This could have allowed local unprivileged users to escalate to root privileges through symlink attacks that manipulate files such as /etc/shadow.

- [https://github.com/BridgerAlderson/CVE-2025-27591-PoC](https://github.com/BridgerAlderson/CVE-2025-27591-PoC) :  ![starts](https://img.shields.io/github/stars/BridgerAlderson/CVE-2025-27591-PoC.svg) ![forks](https://img.shields.io/github/forks/BridgerAlderson/CVE-2025-27591-PoC.svg)


## CVE-2025-24016
 Wazuh is a free and open source platform used for threat prevention, detection, and response. Starting in version 4.4.0 and prior to version 4.9.1, an unsafe deserialization vulnerability allows for remote code execution on Wazuh servers. DistributedAPI parameters are a serialized as JSON and deserialized using `as_wazuh_object` (in `framework/wazuh/core/cluster/common.py`). If an attacker manages to inject an unsanitized dictionary in DAPI request/response, they can forge an unhandled exception (`__unhandled_exc__`) to evaluate arbitrary python code. The vulnerability can be triggered by anybody with API access (compromised dashboard or Wazuh servers in the cluster) or, in certain configurations, even by a compromised agent. Version 4.9.1 contains a fix.

- [https://github.com/guinea-offensive-security/Wazuh-RCE](https://github.com/guinea-offensive-security/Wazuh-RCE) :  ![starts](https://img.shields.io/github/stars/guinea-offensive-security/Wazuh-RCE.svg) ![forks](https://img.shields.io/github/forks/guinea-offensive-security/Wazuh-RCE.svg)


## CVE-2025-22457
 A stack-based buffer overflow in Ivanti Connect Secure before version 22.7R2.6, Ivanti Policy Secure before version 22.7R1.4, and Ivanti ZTA Gateways before version 22.8R2.2 allows a remote unauthenticated attacker to achieve remote code execution.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-22457](https://github.com/B1ack4sh/Blackash-CVE-2025-22457) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-22457.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-22457.svg)


## CVE-2025-6058
 The WPBookit plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the image_upload_handle() function hooked via the 'add_booking_type' route in all versions up to, and including, 1.0.4. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/JayVillain/Scan-CVE-2025-6058](https://github.com/JayVillain/Scan-CVE-2025-6058) :  ![starts](https://img.shields.io/github/stars/JayVillain/Scan-CVE-2025-6058.svg) ![forks](https://img.shields.io/github/forks/JayVillain/Scan-CVE-2025-6058.svg)


## CVE-2025-4593
 The WP Register Profile With Shortcode plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, and including, 3.6.2 via the 'rp_user_data' shortcode. This makes it possible for authenticated attackers, with Contributor-level access and above, to extract sensitive data from user meta like hashed passwords, usernames, and more.

- [https://github.com/karenucqki/CVE-2025-4593](https://github.com/karenucqki/CVE-2025-4593) :  ![starts](https://img.shields.io/github/stars/karenucqki/CVE-2025-4593.svg) ![forks](https://img.shields.io/github/forks/karenucqki/CVE-2025-4593.svg)


## CVE-2023-30258
 Command Injection vulnerability in MagnusSolution magnusbilling 6.x and 7.x allows remote attackers to run arbitrary commands via unauthenticated HTTP request.

- [https://github.com/AdityaBhatt3010/TryHackMe-Room-Walkthrough-Billing](https://github.com/AdityaBhatt3010/TryHackMe-Room-Walkthrough-Billing) :  ![starts](https://img.shields.io/github/stars/AdityaBhatt3010/TryHackMe-Room-Walkthrough-Billing.svg) ![forks](https://img.shields.io/github/forks/AdityaBhatt3010/TryHackMe-Room-Walkthrough-Billing.svg)


## CVE-2022-46689
 A race condition was addressed with additional validation. This issue is fixed in tvOS 16.2, macOS Monterey 12.6.2, macOS Ventura 13.1, macOS Big Sur 11.7.2, iOS 15.7.2 and iPadOS 15.7.2, iOS 16.2 and iPadOS 16.2, watchOS 9.2. An app may be able to execute arbitrary code with kernel privileges.

- [https://github.com/daviszhto/overwrite](https://github.com/daviszhto/overwrite) :  ![starts](https://img.shields.io/github/stars/daviszhto/overwrite.svg) ![forks](https://img.shields.io/github/forks/daviszhto/overwrite.svg)


## CVE-2022-30190
Please see the MSRC Blog Entry for important information about steps you can take to protect your system from this vulnerability.

- [https://github.com/cyberdashy/CVE-2022-30190](https://github.com/cyberdashy/CVE-2022-30190) :  ![starts](https://img.shields.io/github/stars/cyberdashy/CVE-2022-30190.svg) ![forks](https://img.shields.io/github/forks/cyberdashy/CVE-2022-30190.svg)


## CVE-2020-35848
 Agentejo Cockpit before 0.11.2 allows NoSQL injection via the Controller/Auth.php newpassword function.

- [https://github.com/sabbu143s/CVE_2020_35848](https://github.com/sabbu143s/CVE_2020_35848) :  ![starts](https://img.shields.io/github/stars/sabbu143s/CVE_2020_35848.svg) ![forks](https://img.shields.io/github/forks/sabbu143s/CVE_2020_35848.svg)


## CVE-2017-0143
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0144, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/basimnawaz6/EternalBlue-Lab](https://github.com/basimnawaz6/EternalBlue-Lab) :  ![starts](https://img.shields.io/github/stars/basimnawaz6/EternalBlue-Lab.svg) ![forks](https://img.shields.io/github/forks/basimnawaz6/EternalBlue-Lab.svg)

