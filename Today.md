# Update 2025-11-12
## CVE-2025-64495
 Open WebUI is a self-hosted artificial intelligence platform designed to operate entirely offline. In versions 0.6.34 and below, the functionality that inserts custom prompts into the chat window is vulnerable to DOM XSS when 'Insert Prompt as Rich Text' is enabled, since the prompt body is assigned to the DOM sink .innerHtml without sanitisation. Any user with permissions to create prompts can abuse this to plant a payload that could be triggered by other users if they run the corresponding / command to insert the prompt. This issue is fixed in version 0.6.35.

- [https://github.com/AlphabugX/CVE-2025-64495-POC](https://github.com/AlphabugX/CVE-2025-64495-POC) :  ![starts](https://img.shields.io/github/stars/AlphabugX/CVE-2025-64495-POC.svg) ![forks](https://img.shields.io/github/forks/AlphabugX/CVE-2025-64495-POC.svg)
- [https://github.com/B1ack4sh/Blackash-CVE-2025-64495](https://github.com/B1ack4sh/Blackash-CVE-2025-64495) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-64495.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-64495.svg)


## CVE-2025-64459
Django would like to thank cyberstan for reporting this issue.

- [https://github.com/nunpa/CVE-2025-64459](https://github.com/nunpa/CVE-2025-64459) :  ![starts](https://img.shields.io/github/stars/nunpa/CVE-2025-64459.svg) ![forks](https://img.shields.io/github/forks/nunpa/CVE-2025-64459.svg)


## CVE-2025-63296
 KERUI K259 5MP Wi-Fi / Tuya Smart Security Camera firmware v33.53.87 contains a code execution vulnerability in its boot/update logic: during startup /usr/sbin/anyka_service.sh scans mounted TF/SD cards and, if /mnt/update.nor.sh is present, copies it to /tmp/net.sh and executes it as root.

- [https://github.com/t4e-3/CVE-2025-63296](https://github.com/t4e-3/CVE-2025-63296) :  ![starts](https://img.shields.io/github/stars/t4e-3/CVE-2025-63296.svg) ![forks](https://img.shields.io/github/forks/t4e-3/CVE-2025-63296.svg)


## CVE-2025-61932
 Lanscope Endpoint Manager (On-Premises) (Client program (MR) and Detection agent (DA)) improperly verifies the origin of incoming requests, allowing an attacker to execute arbitrary code by sending specially crafted packets.

- [https://github.com/godfatherofexps/CVE-2025-61932-PoC](https://github.com/godfatherofexps/CVE-2025-61932-PoC) :  ![starts](https://img.shields.io/github/stars/godfatherofexps/CVE-2025-61932-PoC.svg) ![forks](https://img.shields.io/github/forks/godfatherofexps/CVE-2025-61932-PoC.svg)


## CVE-2025-59287
 Deserialization of untrusted data in Windows Server Update Service allows an unauthorized attacker to execute code over a network.

- [https://github.com/N3k0t-dev/PoC-CVE-collection](https://github.com/N3k0t-dev/PoC-CVE-collection) :  ![starts](https://img.shields.io/github/stars/N3k0t-dev/PoC-CVE-collection.svg) ![forks](https://img.shields.io/github/forks/N3k0t-dev/PoC-CVE-collection.svg)


## CVE-2025-56503
 An issue in Sublime HQ Pty Ltd Sublime Text 4 4200 allows authenticated attackers with low-level privileges to escalate privileges to Administrator via replacing the uninstall file with a crafted binary in the installation folder.

- [https://github.com/secxplorers/CVE-2025-56503](https://github.com/secxplorers/CVE-2025-56503) :  ![starts](https://img.shields.io/github/stars/secxplorers/CVE-2025-56503.svg) ![forks](https://img.shields.io/github/forks/secxplorers/CVE-2025-56503.svg)


## CVE-2025-52881
 runc is a CLI tool for spawning and running containers according to the OCI specification. In versions 1.2.7, 1.3.2 and 1.4.0-rc.2, an attacker can trick runc into misdirecting writes to /proc to other procfs files through the use of a racing container with shared mounts (we have also verified this attack is possible to exploit using a standard Dockerfile with docker buildx build as that also permits triggering parallel execution of containers with custom shared mounts configured). This redirect could be through symbolic links in a tmpfs or theoretically other methods such as regular bind-mounts. While similar, the mitigation applied for the related CVE, CVE-2019-19921, was fairly limited and effectively only caused runc to verify that when LSM labels are written they are actually procfs files. This issue is fixed in versions 1.2.8, 1.3.3, and 1.4.0-rc.3.

- [https://github.com/omne-earth/arca](https://github.com/omne-earth/arca) :  ![starts](https://img.shields.io/github/stars/omne-earth/arca.svg) ![forks](https://img.shields.io/github/forks/omne-earth/arca.svg)


## CVE-2025-52565
 runc is a CLI tool for spawning and running containers according to the OCI specification. Versions 1.0.0-rc3 through 1.2.7, 1.3.0-rc.1 through 1.3.2, and 1.4.0-rc.1 through 1.4.0-rc.2, due to insufficient checks when bind-mounting `/dev/pts/$n` to `/dev/console` inside the container, an attacker can trick runc into bind-mounting paths which would normally be made read-only or be masked onto a path that the attacker can write to. This attack is very similar in concept and application to CVE-2025-31133, except that it attacks a similar vulnerability in a different target (namely, the bind-mount of `/dev/pts/$n` to `/dev/console` as configured for all containers that allocate a console). This happens after `pivot_root(2)`, so this cannot be used to write to host files directly -- however, as with CVE-2025-31133, this can load to denial of service of the host or a container breakout by providing the attacker with a writable copy of `/proc/sysrq-trigger` or `/proc/sys/kernel/core_pattern` (respectively). This issue is fixed in versions 1.2.8, 1.3.3 and 1.4.0-rc.3.

- [https://github.com/omne-earth/arca](https://github.com/omne-earth/arca) :  ![starts](https://img.shields.io/github/stars/omne-earth/arca.svg) ![forks](https://img.shields.io/github/forks/omne-earth/arca.svg)


## CVE-2025-34299
 Monsta FTP versions 2.11 and earlier contain a vulnerability that allows unauthenticated arbitrary file uploads. This flaw enables attackers to execute arbitrary code by uploading a specially crafted file from a malicious (S)FTP server.

- [https://github.com/crondenice/CVE-2025-34299](https://github.com/crondenice/CVE-2025-34299) :  ![starts](https://img.shields.io/github/stars/crondenice/CVE-2025-34299.svg) ![forks](https://img.shields.io/github/forks/crondenice/CVE-2025-34299.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/Ghstxz/CVE-2025-32463](https://github.com/Ghstxz/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/Ghstxz/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/Ghstxz/CVE-2025-32463.svg)


## CVE-2025-31133
 runc is a CLI tool for spawning and running containers according to the OCI specification. In versions 1.2.7 and below, 1.3.0-rc.1 through 1.3.1, 1.4.0-rc.1 and 1.4.0-rc.2 files, runc would not perform sufficient verification that the source of the bind-mount (i.e., the container's /dev/null) was actually a real /dev/null inode when using the container's /dev/null to mask. This exposes two methods of attack:  an arbitrary mount gadget, leading to host information disclosure, host denial of service, container escape, or a bypassing of maskedPaths. This issue is fixed in versions 1.2.8, 1.3.3 and 1.4.0-rc.3.

- [https://github.com/omne-earth/arca](https://github.com/omne-earth/arca) :  ![starts](https://img.shields.io/github/stars/omne-earth/arca.svg) ![forks](https://img.shields.io/github/forks/omne-earth/arca.svg)


## CVE-2025-12428
 Type Confusion in V8 in Google Chrome prior to 142.0.7444.59 allowed a remote attacker to perform arbitrary read/write via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/dexterm300/cve-2025-12428-exploit-poc](https://github.com/dexterm300/cve-2025-12428-exploit-poc) :  ![starts](https://img.shields.io/github/stars/dexterm300/cve-2025-12428-exploit-poc.svg) ![forks](https://img.shields.io/github/forks/dexterm300/cve-2025-12428-exploit-poc.svg)


## CVE-2025-11953
 The Metro Development Server, which is opened by the React Native Community CLI, binds to external interfaces by default. The server exposes an endpoint that is vulnerable to OS command injection. This allows unauthenticated network attackers to send a POST request to the server and run arbitrary executables. On Windows, the attackers can also execute arbitrary shell commands with fully controlled arguments.

- [https://github.com/N3k0t-dev/PoC-CVE-collection](https://github.com/N3k0t-dev/PoC-CVE-collection) :  ![starts](https://img.shields.io/github/stars/N3k0t-dev/PoC-CVE-collection.svg) ![forks](https://img.shields.io/github/forks/N3k0t-dev/PoC-CVE-collection.svg)


## CVE-2025-8941
 A flaw was found in linux-pam. The pam_namespace module may improperly handle user-controlled paths, allowing local users to exploit symlink attacks and race conditions to elevate their privileges to root. This CVE provides a "complete" fix for CVE-2025-6020.

- [https://github.com/N3k0t-dev/PoC-CVE-collection](https://github.com/N3k0t-dev/PoC-CVE-collection) :  ![starts](https://img.shields.io/github/stars/N3k0t-dev/PoC-CVE-collection.svg) ![forks](https://img.shields.io/github/forks/N3k0t-dev/PoC-CVE-collection.svg)


## CVE-2025-8760
 A vulnerability was identified in INSTAR 2K+ and 4K 3.11.1 Build 1124. This affects the function base64_decode of the component fcgi_server. The manipulation of the argument Authorization leads to buffer overflow. It is possible to initiate the attack remotely.

- [https://github.com/born0monday/CVE-2025-8760](https://github.com/born0monday/CVE-2025-8760) :  ![starts](https://img.shields.io/github/stars/born0monday/CVE-2025-8760.svg) ![forks](https://img.shields.io/github/forks/born0monday/CVE-2025-8760.svg)


## CVE-2025-8088
     from ESET.

- [https://github.com/kredscript/cve-2025-8088](https://github.com/kredscript/cve-2025-8088) :  ![starts](https://img.shields.io/github/stars/kredscript/cve-2025-8088.svg) ![forks](https://img.shields.io/github/forks/kredscript/cve-2025-8088.svg)


## CVE-2025-6440
 The WooCommerce Designer Pro plugin for WordPress, used by the Pricom - Printing Company & Design Services WordPress theme, is vulnerable to arbitrary file uploads due to missing file type validation in the 'wcdp_save_canvas_design_ajax' function in all versions up to, and including, 1.9.26. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/Nxploited/CVE-2025-6440](https://github.com/Nxploited/CVE-2025-6440) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-6440.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-6440.svg)


## CVE-2025-6341
 A vulnerability classified as problematic was found in code-projects School Fees Payment System 1.0. This vulnerability affects unknown code. The manipulation leads to cross-site request forgery. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/MMAKINGDOM/CVE-2025-63419](https://github.com/MMAKINGDOM/CVE-2025-63419) :  ![starts](https://img.shields.io/github/stars/MMAKINGDOM/CVE-2025-63419.svg) ![forks](https://img.shields.io/github/forks/MMAKINGDOM/CVE-2025-63419.svg)


## CVE-2025-1974
 A security issue was discovered in Kubernetes where under certain conditions, an unauthenticated attacker with access to the pod network can achieve arbitrary code execution in the context of the ingress-nginx controller. This can lead to disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)

- [https://github.com/I3r1h0n/IngressNightterror](https://github.com/I3r1h0n/IngressNightterror) :  ![starts](https://img.shields.io/github/stars/I3r1h0n/IngressNightterror.svg) ![forks](https://img.shields.io/github/forks/I3r1h0n/IngressNightterror.svg)


## CVE-2024-49138
 Windows Common Log File System Driver Elevation of Privilege Vulnerability

- [https://github.com/Bridg3Ops/SOC335-CVE-2024-49138-Exploitation-Detected](https://github.com/Bridg3Ops/SOC335-CVE-2024-49138-Exploitation-Detected) :  ![starts](https://img.shields.io/github/stars/Bridg3Ops/SOC335-CVE-2024-49138-Exploitation-Detected.svg) ![forks](https://img.shields.io/github/forks/Bridg3Ops/SOC335-CVE-2024-49138-Exploitation-Detected.svg)


## CVE-2024-48910
 DOMPurify is a DOM-only, super-fast, uber-tolerant XSS sanitizer for HTML, MathML and SVG. DOMPurify was vulnerable to prototype pollution. This vulnerability is fixed in 2.4.2.

- [https://github.com/Mitchellzhou1/CVE-2024-48910-PoC](https://github.com/Mitchellzhou1/CVE-2024-48910-PoC) :  ![starts](https://img.shields.io/github/stars/Mitchellzhou1/CVE-2024-48910-PoC.svg) ![forks](https://img.shields.io/github/forks/Mitchellzhou1/CVE-2024-48910-PoC.svg)


## CVE-2023-51444
 GeoServer is an open source software server written in Java that allows users to share and edit geospatial data. An arbitrary file upload vulnerability exists in versions prior to 2.23.4 and 2.24.1 that enables an authenticated administrator with permissions to modify coverage stores through the REST Coverage Store API to upload arbitrary file contents to arbitrary file locations which can lead to remote code execution. Coverage stores that are configured using relative paths use a GeoServer Resource implementation that has validation to prevent path traversal but coverage stores that are configured using absolute paths use a different Resource implementation that does not prevent path traversal. This vulnerability can lead to executing arbitrary code. An administrator with limited privileges could also potentially exploit this to overwrite GeoServer security files and obtain full administrator privileges. Versions 2.23.4 and 2.24.1 contain a fix for this issue.

- [https://github.com/iPlayForSG/CVE-2023-51444](https://github.com/iPlayForSG/CVE-2023-51444) :  ![starts](https://img.shields.io/github/stars/iPlayForSG/CVE-2023-51444.svg) ![forks](https://img.shields.io/github/forks/iPlayForSG/CVE-2023-51444.svg)


## CVE-2022-35869
 This vulnerability allows remote attackers to bypass authentication on affected installations of Inductive Automation Ignition 8.1.15 (b2022030114). Authentication is not required to exploit this vulnerability. The specific flaw exists within com.inductiveautomation.ignition.gateway.web.pages. The issue results from the lack of proper authentication prior to access to functionality. An attacker can leverage this vulnerability to bypass authentication on the system. Was ZDI-CAN-17211.

- [https://github.com/aschoiloa1890/CVE_2022_35869](https://github.com/aschoiloa1890/CVE_2022_35869) :  ![starts](https://img.shields.io/github/stars/aschoiloa1890/CVE_2022_35869.svg) ![forks](https://img.shields.io/github/forks/aschoiloa1890/CVE_2022_35869.svg)


## CVE-2022-4361
 Keycloak, an open-source identity and access management solution, has a cross-site scripting (XSS) vulnerability in the SAML or OIDC providers. The vulnerability can allow an attacker to execute malicious scripts by setting the AssertionConsumerServiceURL value or the redirect_uri.

- [https://github.com/faccimatteo/CVE-2022-4361](https://github.com/faccimatteo/CVE-2022-4361) :  ![starts](https://img.shields.io/github/stars/faccimatteo/CVE-2022-4361.svg) ![forks](https://img.shields.io/github/forks/faccimatteo/CVE-2022-4361.svg)


## CVE-2021-4449
 The ZoomSounds plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'savepng.php' file in versions up to, and including, 5.96. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/0xmoner/CVE-2021-4449](https://github.com/0xmoner/CVE-2021-4449) :  ![starts](https://img.shields.io/github/stars/0xmoner/CVE-2021-4449.svg) ![forks](https://img.shields.io/github/forks/0xmoner/CVE-2021-4449.svg)


## CVE-2018-14324
 The demo feature in Oracle GlassFish Open Source Edition 5.0 has TCP port 7676 open by default with a password of admin for the admin account. This allows remote attackers to obtain potentially sensitive information, perform database operations, or manipulate the demo via a JMX RMI session, aka a "jmx_rmi remote monitoring and control problem." NOTE: this is not an Oracle supported product.

- [https://github.com/matejsmycka/CVE-2018-14324-Exploit](https://github.com/matejsmycka/CVE-2018-14324-Exploit) :  ![starts](https://img.shields.io/github/stars/matejsmycka/CVE-2018-14324-Exploit.svg) ![forks](https://img.shields.io/github/forks/matejsmycka/CVE-2018-14324-Exploit.svg)


## CVE-2016-10204
 SQL injection vulnerability in Zoneminder 1.30 and earlier allows remote attackers to execute arbitrary SQL commands via the limit parameter in a log query request to index.php.

- [https://github.com/dc-333-666/CVE-2016-10204_Webshell](https://github.com/dc-333-666/CVE-2016-10204_Webshell) :  ![starts](https://img.shields.io/github/stars/dc-333-666/CVE-2016-10204_Webshell.svg) ![forks](https://img.shields.io/github/forks/dc-333-666/CVE-2016-10204_Webshell.svg)


## CVE-2016-0777
 The resend_bytes function in roaming_common.c in the client in OpenSSH 5.x, 6.x, and 7.x before 7.1p2 allows remote servers to obtain sensitive information from process memory by requesting transmission of an entire buffer, as demonstrated by reading a private key.

- [https://github.com/Abdirisaq-ali-aynab/openssh-vulnerability-assessment](https://github.com/Abdirisaq-ali-aynab/openssh-vulnerability-assessment) :  ![starts](https://img.shields.io/github/stars/Abdirisaq-ali-aynab/openssh-vulnerability-assessment.svg) ![forks](https://img.shields.io/github/forks/Abdirisaq-ali-aynab/openssh-vulnerability-assessment.svg)


## CVE-2015-5600
 The kbdint_next_device function in auth2-chall.c in sshd in OpenSSH through 6.9 does not properly restrict the processing of keyboard-interactive devices within a single connection, which makes it easier for remote attackers to conduct brute-force attacks or cause a denial of service (CPU consumption) via a long and duplicative list in the ssh -oKbdInteractiveDevices option, as demonstrated by a modified client that provides a different password for each pam element on this list.

- [https://github.com/Abdirisaq-ali-aynab/openssh-vulnerability-assessment](https://github.com/Abdirisaq-ali-aynab/openssh-vulnerability-assessment) :  ![starts](https://img.shields.io/github/stars/Abdirisaq-ali-aynab/openssh-vulnerability-assessment.svg) ![forks](https://img.shields.io/github/forks/Abdirisaq-ali-aynab/openssh-vulnerability-assessment.svg)

