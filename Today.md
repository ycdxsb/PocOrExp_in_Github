# Update 2026-06-01
## CVE-2026-43500
page_pool RX, GRO).  The OOM/trace handling already in place is reused.

- [https://github.com/K3ysTr0K3R/CVE-2026-43284-CVE-2026-43500-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2026-43284-CVE-2026-43500-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2026-43284-CVE-2026-43500-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2026-43284-CVE-2026-43500-EXPLOIT.svg)


## CVE-2026-43494
rds_message_zcopy_from_user().

- [https://github.com/letsr00t/CVE-2026-43494-PinTheft-PoC](https://github.com/letsr00t/CVE-2026-43494-PinTheft-PoC) :  ![starts](https://img.shields.io/github/stars/letsr00t/CVE-2026-43494-PinTheft-PoC.svg) ![forks](https://img.shields.io/github/forks/letsr00t/CVE-2026-43494-PinTheft-PoC.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/K3ysTr0K3R/CVE-2026-43284-CVE-2026-43500-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2026-43284-CVE-2026-43500-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2026-43284-CVE-2026-43500-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2026-43284-CVE-2026-43500-EXPLOIT.svg)


## CVE-2026-42589
 Gotenberg is a Docker-powered stateless API for PDF files. Prior to 8.31.0, Gotenberg's /forms/pdfengines/metadata/write HTTP endpoint accepts a JSON metadata object and passes its keys directly to ExifTool via the go-exiftool library. No validation is performed on key characters. A \n embedded in a JSON key splits the ExifTool stdin stream into a new argument line, allowing an attacker to inject arbitrary ExifTool flags — including -if, which evaluates Perl expressions. This achieves unauthenticated OS command execution in a single HTTP request. The response is HTTP 200 with a valid PDF, making the attack transparent to basic monitoring. This vulnerability is fixed in 8.31.0.

- [https://github.com/fineman999/POC_CVE-2026-42589](https://github.com/fineman999/POC_CVE-2026-42589) :  ![starts](https://img.shields.io/github/stars/fineman999/POC_CVE-2026-42589.svg) ![forks](https://img.shields.io/github/forks/fineman999/POC_CVE-2026-42589.svg)


## CVE-2026-42208
 LiteLLM is a proxy server (AI Gateway) to call LLM APIs in OpenAI (or native) format. From version 1.81.16 to before version 1.83.7, a database query used during proxy API key checks mixed the caller-supplied key value into the query text instead of passing it as a separate parameter. An unauthenticated attacker could send a specially crafted Authorization header to any LLM API route (for example POST /chat/completions) and reach this query through the proxy's error-handling path. An attacker could read data from the proxy's database and may be able to modify it, leading to unauthorised access to the proxy and the credentials it manages. This issue has been patched in version 1.83.7.

- [https://github.com/HAERIN-L/poc_cve-2026-42208](https://github.com/HAERIN-L/poc_cve-2026-42208) :  ![starts](https://img.shields.io/github/stars/HAERIN-L/poc_cve-2026-42208.svg) ![forks](https://img.shields.io/github/forks/HAERIN-L/poc_cve-2026-42208.svg)


## CVE-2026-40369
 Untrusted pointer dereference in Windows Kernel allows an authorized attacker to elevate privileges locally.

- [https://github.com/Joe1sn/CVE_2026_40369](https://github.com/Joe1sn/CVE_2026_40369) :  ![starts](https://img.shields.io/github/stars/Joe1sn/CVE_2026_40369.svg) ![forks](https://img.shields.io/github/forks/Joe1sn/CVE_2026_40369.svg)


## CVE-2026-39987
 marimo is a reactive Python notebook. Prior to 0.23.0, Marimo has a Pre-Auth RCE vulnerability. The terminal WebSocket endpoint /terminal/ws lacks authentication validation, allowing an unauthenticated attacker to obtain a full PTY shell and execute arbitrary system commands. Unlike other WebSocket endpoints (e.g., /ws) that correctly call validate_auth() for authentication, the /terminal/ws endpoint only checks the running mode and platform support before accepting connections, completely skipping authentication verification. This vulnerability is fixed in 0.23.0.

- [https://github.com/HORKimhab/CVE-2026-39987](https://github.com/HORKimhab/CVE-2026-39987) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-39987.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-39987.svg)


## CVE-2026-29000
 pac4j-jwt versions prior to 4.5.9, 5.7.9, and 6.3.3 contain an authentication bypass vulnerability in JwtAuthenticator when processing encrypted JWTs that allows remote attackers to forge authentication tokens. Attackers who possess the server's RSA public key can create a JWE-wrapped PlainJWT with arbitrary subject and role claims, bypassing signature verification to authenticate as any user including administrators.

- [https://github.com/c0gnit00/CVE-2026-29000](https://github.com/c0gnit00/CVE-2026-29000) :  ![starts](https://img.shields.io/github/stars/c0gnit00/CVE-2026-29000.svg) ![forks](https://img.shields.io/github/forks/c0gnit00/CVE-2026-29000.svg)


## CVE-2026-26111
 Integer overflow or wraparound in Windows Routing and Remote Access Service (RRAS) allows an authorized attacker to execute code over a network.

- [https://github.com/Dhananjayasj/RRAS-VULNERABILITY-CVE-2026-25172-CVE-2026-25173-CVE-2026--26111](https://github.com/Dhananjayasj/RRAS-VULNERABILITY-CVE-2026-25172-CVE-2026-25173-CVE-2026--26111) :  ![starts](https://img.shields.io/github/stars/Dhananjayasj/RRAS-VULNERABILITY-CVE-2026-25172-CVE-2026-25173-CVE-2026--26111.svg) ![forks](https://img.shields.io/github/forks/Dhananjayasj/RRAS-VULNERABILITY-CVE-2026-25172-CVE-2026-25173-CVE-2026--26111.svg)


## CVE-2026-25173
 Integer overflow or wraparound in Windows Routing and Remote Access Service (RRAS) allows an authorized attacker to execute code over a network.

- [https://github.com/Dhananjayasj/RRAS-VULNERABILITY-CVE-2026-25172-CVE-2026-25173-CVE-2026--26111](https://github.com/Dhananjayasj/RRAS-VULNERABILITY-CVE-2026-25172-CVE-2026-25173-CVE-2026--26111) :  ![starts](https://img.shields.io/github/stars/Dhananjayasj/RRAS-VULNERABILITY-CVE-2026-25172-CVE-2026-25173-CVE-2026--26111.svg) ![forks](https://img.shields.io/github/forks/Dhananjayasj/RRAS-VULNERABILITY-CVE-2026-25172-CVE-2026-25173-CVE-2026--26111.svg)


## CVE-2026-25172
 Integer overflow or wraparound in Windows Routing and Remote Access Service (RRAS) allows an authorized attacker to execute code over a network.

- [https://github.com/Dhananjayasj/RRAS-VULNERABILITY-CVE-2026-25172-CVE-2026-25173-CVE-2026--26111](https://github.com/Dhananjayasj/RRAS-VULNERABILITY-CVE-2026-25172-CVE-2026-25173-CVE-2026--26111) :  ![starts](https://img.shields.io/github/stars/Dhananjayasj/RRAS-VULNERABILITY-CVE-2026-25172-CVE-2026-25173-CVE-2026--26111.svg) ![forks](https://img.shields.io/github/forks/Dhananjayasj/RRAS-VULNERABILITY-CVE-2026-25172-CVE-2026-25173-CVE-2026--26111.svg)


## CVE-2026-23744
 MCPJam inspector is the local-first development platform for MCP servers. Versions 1.4.2 and earlier are vulnerable to remote code execution (RCE) vulnerability, which allows an attacker to send a crafted HTTP request that triggers the installation of an MCP server, leading to RCE. Since MCPJam inspector by default listens on 0.0.0.0 instead of 127.0.0.1, an attacker can trigger the RCE remotely via a simple HTTP request. Version 1.4.3 contains a patch.

- [https://github.com/w3nch/CVE-2026-23744](https://github.com/w3nch/CVE-2026-23744) :  ![starts](https://img.shields.io/github/stars/w3nch/CVE-2026-23744.svg) ![forks](https://img.shields.io/github/forks/w3nch/CVE-2026-23744.svg)
- [https://github.com/SuriyaBoon/DevHub-HackTheBox-ss11](https://github.com/SuriyaBoon/DevHub-HackTheBox-ss11) :  ![starts](https://img.shields.io/github/stars/SuriyaBoon/DevHub-HackTheBox-ss11.svg) ![forks](https://img.shields.io/github/forks/SuriyaBoon/DevHub-HackTheBox-ss11.svg)


## CVE-2026-10110
 A vulnerability was detected in code-projects Student Details Management System 1.0. This affects an unknown function of the file /index.php. Performing a manipulation of the argument roll results in sql injection. The attack is possible to be carried out remotely. The exploit is now public and may be used.

- [https://github.com/Xmyronn/CVE-2026-10110-SQLi](https://github.com/Xmyronn/CVE-2026-10110-SQLi) :  ![starts](https://img.shields.io/github/stars/Xmyronn/CVE-2026-10110-SQLi.svg) ![forks](https://img.shields.io/github/forks/Xmyronn/CVE-2026-10110-SQLi.svg)


## CVE-2026-8732
 The WP Maps Pro plugin for WordPress is vulnerable to Privilege Escalation via Administrator Account Creation in all versions up to, and including, 6.1.0. This is due to the wpgmp_temp_access_ajax AJAX action being registered with wp_ajax_nopriv_ and protected only by a nonce check using the fc-call-nonce nonce, which is publicly embedded into every frontend page via wp_localize_script as the nonce field of the wpgmp_local JavaScript object, rendering the check ineffective as an access control mechanism. This makes it possible for unauthenticated attackers to invoke the wpgmp_temp_access_support handler with check_temp=false, which unconditionally creates a new WordPress user with the hardcoded role of administrator via wp_insert_user() and returns a magic login URL that, when visited, calls wp_set_auth_cookie() to fully authenticate the attacker as the newly created administrator, resulting in complete site takeover.

- [https://github.com/Jenderal92/CVE-2026-8732](https://github.com/Jenderal92/CVE-2026-8732) :  ![starts](https://img.shields.io/github/stars/Jenderal92/CVE-2026-8732.svg) ![forks](https://img.shields.io/github/forks/Jenderal92/CVE-2026-8732.svg)
- [https://github.com/xShadow-Here/CVE-2026-8732](https://github.com/xShadow-Here/CVE-2026-8732) :  ![starts](https://img.shields.io/github/stars/xShadow-Here/CVE-2026-8732.svg) ![forks](https://img.shields.io/github/forks/xShadow-Here/CVE-2026-8732.svg)


## CVE-2026-7465
 The Spectra Gutenberg Blocks – Website Builder for the Block Editor plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 2.19.25. This makes it possible for authenticated attackers, with Contributor-level access and above, to execute code on the server. Exploitation requires a two-block payload embedded in post content: the first block registers a fake uagb/-prefixed block type with an attacker-specified render_callback, and the second block of the same fake type triggers invocation of that callback via call_user_func() during sequential block rendering in the same page request.

- [https://github.com/endangcamon/CVE-2026-7465-POC](https://github.com/endangcamon/CVE-2026-7465-POC) :  ![starts](https://img.shields.io/github/stars/endangcamon/CVE-2026-7465-POC.svg) ![forks](https://img.shields.io/github/forks/endangcamon/CVE-2026-7465-POC.svg)


## CVE-2026-7392
 A vulnerability has been found in SourceCodester Pharmacy Sales and Inventory System 1.0. This impacts the function delete_supplier of the file /ajax.php?action=delete_supplier. Such manipulation of the argument ID leads to sql injection. The attack can be executed remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/microwaveabi/pharmacy-sqli-CVE-2026-7392](https://github.com/microwaveabi/pharmacy-sqli-CVE-2026-7392) :  ![starts](https://img.shields.io/github/stars/microwaveabi/pharmacy-sqli-CVE-2026-7392.svg) ![forks](https://img.shields.io/github/forks/microwaveabi/pharmacy-sqli-CVE-2026-7392.svg)


## CVE-2026-4893
 An information disclosure vulnerability in dnsmasq allows remote attackers to bypass source checks via a crafted DNS packet with RFC 7871 client subnet information.

- [https://github.com/lottiedeyan/CVE20264893poc](https://github.com/lottiedeyan/CVE20264893poc) :  ![starts](https://img.shields.io/github/stars/lottiedeyan/CVE20264893poc.svg) ![forks](https://img.shields.io/github/forks/lottiedeyan/CVE20264893poc.svg)


## CVE-2026-4877
 A security flaw has been discovered in itsourcecode Payroll Management System up to 1.0. This affects an unknown function of the file /index.php. Performing a manipulation of the argument page results in cross site scripting. It is possible to initiate the attack remotely. The exploit has been released to the public and may be used for attacks.

- [https://github.com/XK3NF4/CVE-2026-48778](https://github.com/XK3NF4/CVE-2026-48778) :  ![starts](https://img.shields.io/github/stars/XK3NF4/CVE-2026-48778.svg) ![forks](https://img.shields.io/github/forks/XK3NF4/CVE-2026-48778.svg)
- [https://github.com/kavin-jindal/CVE-2026-48778-PoC](https://github.com/kavin-jindal/CVE-2026-48778-PoC) :  ![starts](https://img.shields.io/github/stars/kavin-jindal/CVE-2026-48778-PoC.svg) ![forks](https://img.shields.io/github/forks/kavin-jindal/CVE-2026-48778-PoC.svg)


## CVE-2026-4406
 The Gravity Forms plugin for WordPress is vulnerable to Reflected Cross-Site Scripting via the `form_ids` parameter in the `gform_get_config` AJAX action in all versions up to, and including, 2.9.30. This is due to the `GFCommon::send_json()` method outputting JSON-encoded data wrapped in HTML comment delimiters using `echo` and `wp_die()`, which serves the response with a `Content-Type: text/html` header instead of `application/json`. The `wp_json_encode()` function does not HTML-encode angle brackets within JSON string values, allowing injected HTML/script tags in `form_ids` array values to be parsed and executed by the browser. The required `config_nonce` is generated with `wp_create_nonce('gform_config_ajax')` and is publicly embedded on every page that renders a Gravity Forms form, making it identical for all unauthenticated visitors within the same 12-hour nonce tick. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that execute if they can successfully trick a user into performing an action such as clicking on a link. This vulnerability cannot be exploited against users who are authenticated on the target system, but could be used to alter the target page.

- [https://github.com/Hann1bl3L3ct3r/CVE-2026-4406](https://github.com/Hann1bl3L3ct3r/CVE-2026-4406) :  ![starts](https://img.shields.io/github/stars/Hann1bl3L3ct3r/CVE-2026-4406.svg) ![forks](https://img.shields.io/github/forks/Hann1bl3L3ct3r/CVE-2026-4406.svg)


## CVE-2026-0257
Panorama and Cloud NGFW are not impacted by these issues.

- [https://github.com/0xBlackash/CVE-2026-0257](https://github.com/0xBlackash/CVE-2026-0257) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-0257.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-0257.svg)
- [https://github.com/HORKimhab/CVE-2026-0257](https://github.com/HORKimhab/CVE-2026-0257) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-0257.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-0257.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-overrides](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-overrides) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-overrides.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-overrides.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-rsc-webpack](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-rsc-webpack) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-rsc-webpack.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-rsc-webpack.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-transitive](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-transitive) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-transitive.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-transitive.svg)


## CVE-2025-10162
 The Admin and Customer Messages After Order for WooCommerce: OrderConvo WordPress plugin before 14 does not validate the path of files to be downloaded, which could allow unauthenticated attacker to read/download arbitrary files via a path traversal attack

- [https://github.com/diamorphine666/CVE-2025-10162-Exploit](https://github.com/diamorphine666/CVE-2025-10162-Exploit) :  ![starts](https://img.shields.io/github/stars/diamorphine666/CVE-2025-10162-Exploit.svg) ![forks](https://img.shields.io/github/forks/diamorphine666/CVE-2025-10162-Exploit.svg)


## CVE-2025-9485
 The OAuth Single Sign On – SSO (OAuth Client) plugin for WordPress is vulnerable to Improper Verification of Cryptographic Signature in versions up to, and including, 6.26.12. This is due to the plugin performing unsafe JWT token processing without verification or validation in the `get_resource_owner_from_id_token` function. This makes it possible for unauthenticated attackers to bypass authentication and gain access to any existing user account - including administrators in certain configurations - or to create arbitrary subscriber-level accounts.

- [https://github.com/ItsSunshineXD/CVE-2025-9485-PoC](https://github.com/ItsSunshineXD/CVE-2025-9485-PoC) :  ![starts](https://img.shields.io/github/stars/ItsSunshineXD/CVE-2025-9485-PoC.svg) ![forks](https://img.shields.io/github/forks/ItsSunshineXD/CVE-2025-9485-PoC.svg)


## CVE-2025-9074
This can lead to execution of a wide range of privileged commands to the engine API, including controlling other containers, creating new ones, managing images etc. In some circumstances (e.g. Docker Desktop for Windows with WSL backend) it also allows mounting the host drive with the same privileges as the user running Docker Desktop.

- [https://github.com/c0gnit00/CVE-2025-9074](https://github.com/c0gnit00/CVE-2025-9074) :  ![starts](https://img.shields.io/github/stars/c0gnit00/CVE-2025-9074.svg) ![forks](https://img.shields.io/github/forks/c0gnit00/CVE-2025-9074.svg)


## CVE-2025-5947
 The Service Finder Bookings plugin for WordPress is vulnerable to privilege escalation via authentication bypass in all versions up to, and including, 6.0. This is due to the plugin not properly validating a user's cookie value prior to logging them in through the service_finder_switch_back() function. This makes it possible for unauthenticated attackers to login as any user including admins.

- [https://github.com/xxconi/CVE-2025-5947](https://github.com/xxconi/CVE-2025-5947) :  ![starts](https://img.shields.io/github/stars/xxconi/CVE-2025-5947.svg) ![forks](https://img.shields.io/github/forks/xxconi/CVE-2025-5947.svg)


## CVE-2024-36401
Versions 2.22.6, 2.23.6, 2.24.4, and 2.25.2 contain a patch for the issue. A workaround exists by removing the `gt-complex-x.y.jar` file from the GeoServer where `x.y` is the GeoTools version (e.g., `gt-complex-31.1.jar` if running GeoServer 2.25.1). This will remove the vulnerable code from GeoServer but may break some GeoServer functionality or prevent GeoServer from deploying if the gt-complex module is needed.

- [https://github.com/Delt-A/CVE-2024-36401-poc](https://github.com/Delt-A/CVE-2024-36401-poc) :  ![starts](https://img.shields.io/github/stars/Delt-A/CVE-2024-36401-poc.svg) ![forks](https://img.shields.io/github/forks/Delt-A/CVE-2024-36401-poc.svg)


## CVE-2024-6387
 A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be able to trigger it by failing to authenticate within a set time period.

- [https://github.com/oseasfr/Scanner_CVE_OpenSSH](https://github.com/oseasfr/Scanner_CVE_OpenSSH) :  ![starts](https://img.shields.io/github/stars/oseasfr/Scanner_CVE_OpenSSH.svg) ![forks](https://img.shields.io/github/forks/oseasfr/Scanner_CVE_OpenSSH.svg)


## CVE-2024-3400
Cloud NGFW, Panorama appliances, and Prisma Access are not impacted by this vulnerability.

- [https://github.com/Nikki-the-Parcel/Global-Protect_VPN_Vuln](https://github.com/Nikki-the-Parcel/Global-Protect_VPN_Vuln) :  ![starts](https://img.shields.io/github/stars/Nikki-the-Parcel/Global-Protect_VPN_Vuln.svg) ![forks](https://img.shields.io/github/forks/Nikki-the-Parcel/Global-Protect_VPN_Vuln.svg)


## CVE-2023-48795
 The SSH transport protocol with certain OpenSSH extensions, found in OpenSSH before 9.6 and other products, allows remote attackers to bypass integrity checks such that some packets are omitted (from the extension negotiation message), and a client and server may consequently end up with a connection for which some security features have been downgraded or disabled, aka a Terrapin attack. This occurs because the SSH Binary Packet Protocol (BPP), implemented by these extensions, mishandles the handshake phase and mishandles use of sequence numbers. For example, there is an effective attack against SSH's use of ChaCha20-Poly1305 (and CBC with Encrypt-then-MAC). The bypass occurs in chacha20-poly1305@openssh.com and (if CBC is used) the -etm@openssh.com MAC algorithms. This also affects Maverick Synergy Java SSH API before 3.1.0-SNAPSHOT, Dropbear through 2022.83, Ssh before 5.1.1 in Erlang/OTP, PuTTY before 0.80, AsyncSSH before 2.14.2, golang.org/x/crypto before 0.17.0, libssh before 0.10.6, libssh2 through 1.11.0, Thorn Tech SFTP Gateway before 3.4.6, Tera Term before 5.1, Paramiko before 3.4.0, jsch before 0.2.15, SFTPGo before 2.5.6, Netgate pfSense Plus through 23.09.1, Netgate pfSense CE through 2.7.2, HPN-SSH through 18.2.0, ProFTPD before 1.3.8b (and before 1.3.9rc2), ORYX CycloneSSH before 2.3.4, NetSarang XShell 7 before Build 0144, CrushFTP before 10.6.0, ConnectBot SSH library before 2.2.22, Apache MINA sshd through 2.11.0, sshj through 0.37.0, TinySSH through 20230101, trilead-ssh2 6401, LANCOM LCOS and LANconfig, FileZilla before 3.66.4, Nova before 11.8, PKIX-SSH before 14.4, SecureCRT before 9.4.3, Transmit5 before 5.10.4, Win32-OpenSSH before 9.5.0.0p1-Beta, WinSCP before 6.2.2, Bitvise SSH Server before 9.32, Bitvise SSH Client before 9.33, KiTTY through 0.76.1.13, the net-ssh gem 7.2.0 for Ruby, the mscdex ssh2 module before 1.15.0 for Node.js, the thrussh library before 0.35.1 for Rust, and the Russh crate before 0.40.2 for Rust.

- [https://github.com/oseasfr/Scanner_CVE_OpenSSH](https://github.com/oseasfr/Scanner_CVE_OpenSSH) :  ![starts](https://img.shields.io/github/stars/oseasfr/Scanner_CVE_OpenSSH.svg) ![forks](https://img.shields.io/github/forks/oseasfr/Scanner_CVE_OpenSSH.svg)


## CVE-2023-27350
 This vulnerability allows remote attackers to bypass authentication on affected installations of PaperCut NG 22.0.5 (Build 63914). Authentication is not required to exploit this vulnerability. The specific flaw exists within the SetupCompleted class. The issue results from improper access control. An attacker can leverage this vulnerability to bypass authentication and execute arbitrary code in the context of SYSTEM. Was ZDI-CAN-18987.

- [https://github.com/joaoaugustom/PaperCut-Authentication_Bypass_and_RCE](https://github.com/joaoaugustom/PaperCut-Authentication_Bypass_and_RCE) :  ![starts](https://img.shields.io/github/stars/joaoaugustom/PaperCut-Authentication_Bypass_and_RCE.svg) ![forks](https://img.shields.io/github/forks/joaoaugustom/PaperCut-Authentication_Bypass_and_RCE.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `grafana_host_url/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/STK-Security/Grafana-Password-Decryptor](https://github.com/STK-Security/Grafana-Password-Decryptor) :  ![starts](https://img.shields.io/github/stars/STK-Security/Grafana-Password-Decryptor.svg) ![forks](https://img.shields.io/github/forks/STK-Security/Grafana-Password-Decryptor.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/Jeanback1/CVE-2019-9053-exploit](https://github.com/Jeanback1/CVE-2019-9053-exploit) :  ![starts](https://img.shields.io/github/stars/Jeanback1/CVE-2019-9053-exploit.svg) ![forks](https://img.shields.io/github/forks/Jeanback1/CVE-2019-9053-exploit.svg)


## CVE-2016-10924
 The ebook-download plugin before 1.2 for WordPress has directory traversal.

- [https://github.com/rvzsec/CVE-2016-10924](https://github.com/rvzsec/CVE-2016-10924) :  ![starts](https://img.shields.io/github/stars/rvzsec/CVE-2016-10924.svg) ![forks](https://img.shields.io/github/forks/rvzsec/CVE-2016-10924.svg)


## CVE-2014-3120
 The default configuration in Elasticsearch before 1.2 enables dynamic scripting, which allows remote attackers to execute arbitrary MVEL expressions and Java code via the source parameter to _search.  NOTE: this only violates the vendor's intended security policy if the user does not run Elasticsearch in its own independent virtual machine.

- [https://github.com/Dungsocool/CVE-2014-3120](https://github.com/Dungsocool/CVE-2014-3120) :  ![starts](https://img.shields.io/github/stars/Dungsocool/CVE-2014-3120.svg) ![forks](https://img.shields.io/github/forks/Dungsocool/CVE-2014-3120.svg)


## CVE-2007-4560
 clamav-milter in ClamAV before 0.91.2, when run in black hole mode, allows remote attackers to execute arbitrary commands via shell metacharacters that are used in a certain popen call, involving the "recipient field of sendmail."

- [https://github.com/STK-Security/sendmail-clamav-exploit-CVE-2007-4560](https://github.com/STK-Security/sendmail-clamav-exploit-CVE-2007-4560) :  ![starts](https://img.shields.io/github/stars/STK-Security/sendmail-clamav-exploit-CVE-2007-4560.svg) ![forks](https://img.shields.io/github/forks/STK-Security/sendmail-clamav-exploit-CVE-2007-4560.svg)

