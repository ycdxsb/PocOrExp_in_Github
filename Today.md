# Update 2025-12-12
## CVE-2025-67494
 ZITADEL is an open-source identity infrastructure tool. Versions 4.7.0 and below are vulnerable to an unauthenticated, full-read SSRF vulnerability. The ZITADEL Login UI (V2) treats the x-zitadel-forward-host header as a trusted fallback for all deployments, including self-hosted instances. This allows an unauthenticated attacker to force the server to make HTTP requests to arbitrary domains, such as internal addresses, and read the responses, enabling data exfiltration and bypassing network-segmentation controls. This issue is fixed in version 4.7.1.

- [https://github.com/Chocapikk/CVE-2025-67494](https://github.com/Chocapikk/CVE-2025-67494) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2025-67494.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2025-67494.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/kOaDT/poc-cve-2025-55182](https://github.com/kOaDT/poc-cve-2025-55182) :  ![starts](https://img.shields.io/github/stars/kOaDT/poc-cve-2025-55182.svg) ![forks](https://img.shields.io/github/forks/kOaDT/poc-cve-2025-55182.svg)
- [https://github.com/Saad-Ayady/react2shellNSE](https://github.com/Saad-Ayady/react2shellNSE) :  ![starts](https://img.shields.io/github/stars/Saad-Ayady/react2shellNSE.svg) ![forks](https://img.shields.io/github/forks/Saad-Ayady/react2shellNSE.svg)
- [https://github.com/rix4uni/CVE-2025-55182](https://github.com/rix4uni/CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/rix4uni/CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/rix4uni/CVE-2025-55182.svg)


## CVE-2025-65964
 n8n is an open source workflow automation platform. Versions 0.123.1 through 1.119.1 do not have adequate protections to prevent RCE through the project's pre-commit hooks. The Add Config operation allows workflows to set arbitrary Git configuration values, including core.hooksPath, which can point to a malicious Git hook that executes arbitrary commands on the n8n host during subsequent Git operations. Exploitation requires the ability to create or modify an n8n workflow using the Git node. This issue is fixed in version 1.119.2. Workarounds include excluding the Git Node (Docs) and avoiding cloning or interacting with untrusted repositories using the Git Node.

- [https://github.com/Geekby/n8n-CVE-2025-65964](https://github.com/Geekby/n8n-CVE-2025-65964) :  ![starts](https://img.shields.io/github/stars/Geekby/n8n-CVE-2025-65964.svg) ![forks](https://img.shields.io/github/forks/Geekby/n8n-CVE-2025-65964.svg)
- [https://github.com/Ashwesker/Blackash-CVE-2025-65964](https://github.com/Ashwesker/Blackash-CVE-2025-65964) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Blackash-CVE-2025-65964.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Blackash-CVE-2025-65964.svg)


## CVE-2025-65754
 Cross Site Scripting vulnerability in Algernon v1.17.4 allows attackers to execute arbitrary code via injecting a crafted payload into a filename.

- [https://github.com/Bnyt7/CVE-2025-65754](https://github.com/Bnyt7/CVE-2025-65754) :  ![starts](https://img.shields.io/github/stars/Bnyt7/CVE-2025-65754.svg) ![forks](https://img.shields.io/github/forks/Bnyt7/CVE-2025-65754.svg)


## CVE-2025-64113
 Emby Server is a user-installable home media server. Versions below 4.9.1.81 allow an attacker to gain full administrative access to an Emby Server (for Emby Server administration, not at the OS level). Other than network access, no specific preconditions need to be fulfilled for a server to be vulnerable. This issue is fixed in version 4.9.1.81.

- [https://github.com/Ashwesker/Blackash-CVE-2025-64113](https://github.com/Ashwesker/Blackash-CVE-2025-64113) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Blackash-CVE-2025-64113.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Blackash-CVE-2025-64113.svg)


## CVE-2025-63895
 An issue in the Bluetooth firmware of JXL 9 Inch Car Android Double Din Player Android v12.0 allows attackers to cause a Denial of Service (DoS) via sending a crafted Link Manager Protocol (LMP) packet.

- [https://github.com/thorat-shubham/JXL_Infotainment_CVE-2025-63895](https://github.com/thorat-shubham/JXL_Infotainment_CVE-2025-63895) :  ![starts](https://img.shields.io/github/stars/thorat-shubham/JXL_Infotainment_CVE-2025-63895.svg) ![forks](https://img.shields.io/github/forks/thorat-shubham/JXL_Infotainment_CVE-2025-63895.svg)


## CVE-2025-61229
 An issue in Shirt Pocket's SuperDuper! 3.10 and earlier allow a local attacker to modify the default task template to execute an arbitrary preflight script with root privileges and Full Disk Access, thus bypassing macOS privacy controls.

- [https://github.com/graypixel2121/CVE-2025-61229](https://github.com/graypixel2121/CVE-2025-61229) :  ![starts](https://img.shields.io/github/stars/graypixel2121/CVE-2025-61229.svg) ![forks](https://img.shields.io/github/forks/graypixel2121/CVE-2025-61229.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/BeichenDream/CVE-2025-55182-GodzillaMemoryShell](https://github.com/BeichenDream/CVE-2025-55182-GodzillaMemoryShell) :  ![starts](https://img.shields.io/github/stars/BeichenDream/CVE-2025-55182-GodzillaMemoryShell.svg) ![forks](https://img.shields.io/github/forks/BeichenDream/CVE-2025-55182-GodzillaMemoryShell.svg)
- [https://github.com/theori-io/reactguard](https://github.com/theori-io/reactguard) :  ![starts](https://img.shields.io/github/stars/theori-io/reactguard.svg) ![forks](https://img.shields.io/github/forks/theori-io/reactguard.svg)
- [https://github.com/alsaut1/react2shell-lab](https://github.com/alsaut1/react2shell-lab) :  ![starts](https://img.shields.io/github/stars/alsaut1/react2shell-lab.svg) ![forks](https://img.shields.io/github/forks/alsaut1/react2shell-lab.svg)
- [https://github.com/CirqueiraDev/MassExploit-CVE-2025-55182](https://github.com/CirqueiraDev/MassExploit-CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/CirqueiraDev/MassExploit-CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/CirqueiraDev/MassExploit-CVE-2025-55182.svg)
- [https://github.com/Syrins/CVE-2025-55182-React2Shell-RCE](https://github.com/Syrins/CVE-2025-55182-React2Shell-RCE) :  ![starts](https://img.shields.io/github/stars/Syrins/CVE-2025-55182-React2Shell-RCE.svg) ![forks](https://img.shields.io/github/forks/Syrins/CVE-2025-55182-React2Shell-RCE.svg)
- [https://github.com/onlylovetx/CVE-2025-55182-CVE-2025-66478-Exploit-GUI](https://github.com/onlylovetx/CVE-2025-55182-CVE-2025-66478-Exploit-GUI) :  ![starts](https://img.shields.io/github/stars/onlylovetx/CVE-2025-55182-CVE-2025-66478-Exploit-GUI.svg) ![forks](https://img.shields.io/github/forks/onlylovetx/CVE-2025-55182-CVE-2025-66478-Exploit-GUI.svg)
- [https://github.com/Security-Phoenix-demo/react2shell-scanner-rce-react-next-CVE-2025-55182-CVE-2025-66478](https://github.com/Security-Phoenix-demo/react2shell-scanner-rce-react-next-CVE-2025-55182-CVE-2025-66478) :  ![starts](https://img.shields.io/github/stars/Security-Phoenix-demo/react2shell-scanner-rce-react-next-CVE-2025-55182-CVE-2025-66478.svg) ![forks](https://img.shields.io/github/forks/Security-Phoenix-demo/react2shell-scanner-rce-react-next-CVE-2025-55182-CVE-2025-66478.svg)
- [https://github.com/enesbuyuk/react2shell-security-tool](https://github.com/enesbuyuk/react2shell-security-tool) :  ![starts](https://img.shields.io/github/stars/enesbuyuk/react2shell-security-tool.svg) ![forks](https://img.shields.io/github/forks/enesbuyuk/react2shell-security-tool.svg)
- [https://github.com/hlsitechio/shellockolm](https://github.com/hlsitechio/shellockolm) :  ![starts](https://img.shields.io/github/stars/hlsitechio/shellockolm.svg) ![forks](https://img.shields.io/github/forks/hlsitechio/shellockolm.svg)


## CVE-2025-53772
 Deserialization of untrusted data in Web Deploy allows an authorized attacker to execute code over a network.

- [https://github.com/sailay1996/CVE-2025-53772](https://github.com/sailay1996/CVE-2025-53772) :  ![starts](https://img.shields.io/github/stars/sailay1996/CVE-2025-53772.svg) ![forks](https://img.shields.io/github/forks/sailay1996/CVE-2025-53772.svg)


## CVE-2025-33073
 Improper access control in Windows SMB allows an authorized attacker to elevate privileges over a network.

- [https://github.com/Iddygodwin/CVE-2025-33073](https://github.com/Iddygodwin/CVE-2025-33073) :  ![starts](https://img.shields.io/github/stars/Iddygodwin/CVE-2025-33073.svg) ![forks](https://img.shields.io/github/forks/Iddygodwin/CVE-2025-33073.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/moften/CVE-2025-29927_Next.js_Auth_Bypass](https://github.com/moften/CVE-2025-29927_Next.js_Auth_Bypass) :  ![starts](https://img.shields.io/github/stars/moften/CVE-2025-29927_Next.js_Auth_Bypass.svg) ![forks](https://img.shields.io/github/forks/moften/CVE-2025-29927_Next.js_Auth_Bypass.svg)
- [https://github.com/w3shinew/CVE-2025-29927](https://github.com/w3shinew/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/w3shinew/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/w3shinew/CVE-2025-29927.svg)
- [https://github.com/Grand-Moomin/Vuln-Next.js-CVE-2025-29927](https://github.com/Grand-Moomin/Vuln-Next.js-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/Grand-Moomin/Vuln-Next.js-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/Grand-Moomin/Vuln-Next.js-CVE-2025-29927.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/gunyakit/CVE-2025-24813-PoC-exploit](https://github.com/gunyakit/CVE-2025-24813-PoC-exploit) :  ![starts](https://img.shields.io/github/stars/gunyakit/CVE-2025-24813-PoC-exploit.svg) ![forks](https://img.shields.io/github/forks/gunyakit/CVE-2025-24813-PoC-exploit.svg)


## CVE-2025-24071
 Exposure of sensitive information to an unauthorized actor in Windows File Explorer allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/WhiteDominion/CVE-2025-24054_CVE-2025-24071-PoC](https://github.com/WhiteDominion/CVE-2025-24054_CVE-2025-24071-PoC) :  ![starts](https://img.shields.io/github/stars/WhiteDominion/CVE-2025-24054_CVE-2025-24071-PoC.svg) ![forks](https://img.shields.io/github/forks/WhiteDominion/CVE-2025-24054_CVE-2025-24071-PoC.svg)


## CVE-2025-24054
 External control of file name or path in Windows NTLM allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/WhiteDominion/CVE-2025-24054_CVE-2025-24071-PoC](https://github.com/WhiteDominion/CVE-2025-24054_CVE-2025-24071-PoC) :  ![starts](https://img.shields.io/github/stars/WhiteDominion/CVE-2025-24054_CVE-2025-24071-PoC.svg) ![forks](https://img.shields.io/github/forks/WhiteDominion/CVE-2025-24054_CVE-2025-24071-PoC.svg)


## CVE-2025-13339
 The Hippoo Mobile App for WooCommerce plugin for WordPress is vulnerable to Path Traversal in all versions up to, and including, 1.7.1 via the template_redirect() function. This makes it possible for unauthenticated attackers to read the contents of arbitrary files on the server, which can contain sensitive information.

- [https://github.com/MooseLoveti/Hippoo-Mobile-App-For-WooCommerce-CVE-Report](https://github.com/MooseLoveti/Hippoo-Mobile-App-For-WooCommerce-CVE-Report) :  ![starts](https://img.shields.io/github/stars/MooseLoveti/Hippoo-Mobile-App-For-WooCommerce-CVE-Report.svg) ![forks](https://img.shields.io/github/forks/MooseLoveti/Hippoo-Mobile-App-For-WooCommerce-CVE-Report.svg)


## CVE-2025-9074
This can lead to execution of a wide range of privileged commands to the engine API, including controlling other containers, creating new ones, managing images etc. In some circumstances (e.g. Docker Desktop for Windows with WSL backend) it also allows mounting the host drive with the same privileges as the user running Docker Desktop.

- [https://github.com/3rendil/CVE-2025-9074-POC](https://github.com/3rendil/CVE-2025-9074-POC) :  ![starts](https://img.shields.io/github/stars/3rendil/CVE-2025-9074-POC.svg) ![forks](https://img.shields.io/github/forks/3rendil/CVE-2025-9074-POC.svg)
- [https://github.com/pppxo/CVE-2025-9074-PoC-Bash](https://github.com/pppxo/CVE-2025-9074-PoC-Bash) :  ![starts](https://img.shields.io/github/stars/pppxo/CVE-2025-9074-PoC-Bash.svg) ![forks](https://img.shields.io/github/forks/pppxo/CVE-2025-9074-PoC-Bash.svg)


## CVE-2025-8061
 A potential insufficient access control vulnerability was reported in the Lenovo Dispatcher 3.0 and Dispatcher 3.1 drivers used by some Lenovo consumer notebooks that could allow an authenticated local user to execute code with elevated privileges. The Lenovo Dispatcher 3.2 driver is not affected. This vulnerability does not affect systems when the Windows feature Core Isolation Memory Integrity is enabled. Lenovo systems preloaded with Windows 11 have this feature enabled by default.

- [https://github.com/spawn451/CVE-2025-8061-Exploit](https://github.com/spawn451/CVE-2025-8061-Exploit) :  ![starts](https://img.shields.io/github/stars/spawn451/CVE-2025-8061-Exploit.svg) ![forks](https://img.shields.io/github/forks/spawn451/CVE-2025-8061-Exploit.svg)


## CVE-2025-6574
 The Service Finder Bookings plugin for WordPress is vulnerable to privilege escalation via account takeover in all versions up to, and excluding, 6.1. This is due to the plugin not properly validating a user's identity prior to updating their details like email. This makes it possible for authenticated attackers, with subscriber-level access and above, to change arbitrary user's email addresses, including administrators, and leverage that to reset the user's password and gain access to their account.

- [https://github.com/CBx216/CVE-2025-65742-Newgen-OmniDocs-LDAP-BFLA](https://github.com/CBx216/CVE-2025-65742-Newgen-OmniDocs-LDAP-BFLA) :  ![starts](https://img.shields.io/github/stars/CBx216/CVE-2025-65742-Newgen-OmniDocs-LDAP-BFLA.svg) ![forks](https://img.shields.io/github/forks/CBx216/CVE-2025-65742-Newgen-OmniDocs-LDAP-BFLA.svg)


## CVE-2025-6389
 The Sneeit Framework plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 8.3 via the sneeit_articles_pagination_callback() function. This is due to the function accepting user input and then passing that through call_user_func(). This makes it possible for unauthenticated attackers to execute code on the server which can be leveraged to inject backdoors or, for example, create new administrative user accounts.

- [https://github.com/itsismarcos/SneeitScanner-CVE-2025-6389](https://github.com/itsismarcos/SneeitScanner-CVE-2025-6389) :  ![starts](https://img.shields.io/github/stars/itsismarcos/SneeitScanner-CVE-2025-6389.svg) ![forks](https://img.shields.io/github/forks/itsismarcos/SneeitScanner-CVE-2025-6389.svg)


## CVE-2025-5746
 The Drag and Drop Multiple File Upload (Pro) - WooCommerce plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the dnd_upload_cf7_upload_chunks() function in version 5.0 - 5.0.5 (when bundled with the PrintSpace theme) and all versions up to, and including, 1.7.1 (in the standalone version). This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible. The execution of PHP is disabled via a .htaccess file but is still possible in certain server configurations.

- [https://github.com/aljoharasubaie/CVE-2025-57462](https://github.com/aljoharasubaie/CVE-2025-57462) :  ![starts](https://img.shields.io/github/stars/aljoharasubaie/CVE-2025-57462.svg) ![forks](https://img.shields.io/github/forks/aljoharasubaie/CVE-2025-57462.svg)
- [https://github.com/aljoharasubaie/CVE-2025-57460](https://github.com/aljoharasubaie/CVE-2025-57460) :  ![starts](https://img.shields.io/github/stars/aljoharasubaie/CVE-2025-57460.svg) ![forks](https://img.shields.io/github/forks/aljoharasubaie/CVE-2025-57460.svg)


## CVE-2025-5745
 The strncmp implementation optimized for the Power10 processor in the GNU C Library version 2.40 and later writes to vector registers v20 to v31 without saving contents from the caller (those registers are defined as non-volatile registers by the powerpc64le ABI), resulting in overwriting of its contents and potentially altering control flow of the caller, or leaking the input strings to the function to other parts of the program.

- [https://github.com/aljoharasubaie/CVE-2025-57459](https://github.com/aljoharasubaie/CVE-2025-57459) :  ![starts](https://img.shields.io/github/stars/aljoharasubaie/CVE-2025-57459.svg) ![forks](https://img.shields.io/github/forks/aljoharasubaie/CVE-2025-57459.svg)


## CVE-2025-5544
 A vulnerability was found in aaluoxiang oa_system up to 5b445a6227b51cee287bd0c7c33ed94b801a82a5. It has been rated as problematic. Affected by this issue is the function image of the file src/main/java/cn/gson/oasys/controller/user/UserpanelController.java. The manipulation leads to path traversal. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. Continious delivery with rolling releases is used by this product. Therefore, no version details of affected nor updated releases are available.

- [https://github.com/xhh1h/CVE-2025-55449](https://github.com/xhh1h/CVE-2025-55449) :  ![starts](https://img.shields.io/github/stars/xhh1h/CVE-2025-55449.svg) ![forks](https://img.shields.io/github/forks/xhh1h/CVE-2025-55449.svg)


## CVE-2025-4917
 A vulnerability classified as critical has been found in PHPGurukul Auto Taxi Stand Management System 1.0. Affected is an unknown function of the file /admin/new-autoortaxi-entry-form.php. The manipulation of the argument drivername leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. Other parameters might be affected as well.

- [https://github.com/ArbitaryMannn/cve-2025-49173-macos-mavericks-10.9-local-root-privesc-auth-services](https://github.com/ArbitaryMannn/cve-2025-49173-macos-mavericks-10.9-local-root-privesc-auth-services) :  ![starts](https://img.shields.io/github/stars/ArbitaryMannn/cve-2025-49173-macos-mavericks-10.9-local-root-privesc-auth-services.svg) ![forks](https://img.shields.io/github/forks/ArbitaryMannn/cve-2025-49173-macos-mavericks-10.9-local-root-privesc-auth-services.svg)


## CVE-2025-3248
code.

- [https://github.com/b0ySie7e/CVE-2025-3248-POC](https://github.com/b0ySie7e/CVE-2025-3248-POC) :  ![starts](https://img.shields.io/github/stars/b0ySie7e/CVE-2025-3248-POC.svg) ![forks](https://img.shields.io/github/forks/b0ySie7e/CVE-2025-3248-POC.svg)


## CVE-2025-1974
 A security issue was discovered in Kubernetes where under certain conditions, an unauthenticated attacker with access to the pod network can achieve arbitrary code execution in the context of the ingress-nginx controller. This can lead to disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)

- [https://github.com/gunyakit/CVE-2025-1974-PoC-exploit](https://github.com/gunyakit/CVE-2025-1974-PoC-exploit) :  ![starts](https://img.shields.io/github/stars/gunyakit/CVE-2025-1974-PoC-exploit.svg) ![forks](https://img.shields.io/github/forks/gunyakit/CVE-2025-1974-PoC-exploit.svg)


## CVE-2024-5518
 A vulnerability classified as critical has been found in itsourcecode Online Discussion Forum 1.0. This affects an unknown part of the file change_profile_picture.php. The manipulation of the argument image leads to unrestricted upload. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-266589 was assigned to this vulnerability.

- [https://github.com/MernJsb/CVE-2024-55182](https://github.com/MernJsb/CVE-2024-55182) :  ![starts](https://img.shields.io/github/stars/MernJsb/CVE-2024-55182.svg) ![forks](https://img.shields.io/github/forks/MernJsb/CVE-2024-55182.svg)


## CVE-2023-27524
Alternatively you can set it with `SUPERSET_SECRET_KEY` environment variable.

- [https://github.com/tardc/CVE-2023-27524](https://github.com/tardc/CVE-2023-27524) :  ![starts](https://img.shields.io/github/stars/tardc/CVE-2023-27524.svg) ![forks](https://img.shields.io/github/forks/tardc/CVE-2023-27524.svg)


## CVE-2021-20086
 Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution') in jquery-bbq 1.2.1 allows a malicious user to inject properties into Object.prototype.

- [https://github.com/1337rokudenashi/Odoo-Apps-XSS-via-Prototype-Pollution](https://github.com/1337rokudenashi/Odoo-Apps-XSS-via-Prototype-Pollution) :  ![starts](https://img.shields.io/github/stars/1337rokudenashi/Odoo-Apps-XSS-via-Prototype-Pollution.svg) ![forks](https://img.shields.io/github/forks/1337rokudenashi/Odoo-Apps-XSS-via-Prototype-Pollution.svg)


## CVE-2021-4045
 TP-Link Tapo C200 IP camera, on its 1.1.15 firmware version and below, is affected by an unauthenticated RCE vulnerability, present in the uhttpd binary running by default as root. The exploitation of this vulnerability allows an attacker to take full control of the camera.

- [https://github.com/234329a423853/CVE-2021-4045](https://github.com/234329a423853/CVE-2021-4045) :  ![starts](https://img.shields.io/github/stars/234329a423853/CVE-2021-4045.svg) ![forks](https://img.shields.io/github/forks/234329a423853/CVE-2021-4045.svg)


## CVE-2018-1160
 Netatalk before 3.1.12 is vulnerable to an out of bounds write in dsi_opensess.c. This is due to lack of bounds checking on attacker controlled data. A remote unauthenticated attacker can leverage this vulnerability to achieve arbitrary code execution.

- [https://github.com/meir0222/CVE-2018-1160](https://github.com/meir0222/CVE-2018-1160) :  ![starts](https://img.shields.io/github/stars/meir0222/CVE-2018-1160.svg) ![forks](https://img.shields.io/github/forks/meir0222/CVE-2018-1160.svg)

