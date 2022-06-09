## CVE-2009-5147
 DL::dlopen in Ruby 1.8, 1.9.0, 1.9.2, 1.9.3, 2.0.0 before patchlevel 648, and 2.1 before 2.1.8 opens libraries with tainted names.



- [https://github.com/vpereira/CVE-2009-5147](https://github.com/vpereira/CVE-2009-5147) :  ![starts](https://img.shields.io/github/stars/vpereira/CVE-2009-5147.svg) ![forks](https://img.shields.io/github/forks/vpereira/CVE-2009-5147.svg)

- [https://github.com/zhangyongbo100/-Ruby-dl-handle.c-CVE-2009-5147-](https://github.com/zhangyongbo100/-Ruby-dl-handle.c-CVE-2009-5147-) :  ![starts](https://img.shields.io/github/stars/zhangyongbo100/-Ruby-dl-handle.c-CVE-2009-5147-.svg) ![forks](https://img.shields.io/github/forks/zhangyongbo100/-Ruby-dl-handle.c-CVE-2009-5147-.svg)

## CVE-2009-4660
 Stack-based buffer overflow in the AntServer Module (AntServer.exe) in BigAnt IM Server 2.50 allows remote attackers to execute arbitrary code via a long GET request to TCP port 6660.



- [https://github.com/war4uthor/CVE-2009-4660](https://github.com/war4uthor/CVE-2009-4660) :  ![starts](https://img.shields.io/github/stars/war4uthor/CVE-2009-4660.svg) ![forks](https://img.shields.io/github/forks/war4uthor/CVE-2009-4660.svg)

## CVE-2009-4140
 Unrestricted file upload vulnerability in ofc_upload_image.php in Open Flash Chart v2 Beta 1 through v2 Lug Wyrm Charmer, as used in Piwik 0.2.35 through 0.4.3, Woopra Analytics Plugin before 1.4.3.2, and possibly other products, when register_globals is enabled, allows remote authenticated users to execute arbitrary code by uploading a file with an executable extension through the name parameter with the code in the HTTP_RAW_POST_DATA parameter, then accessing it via a direct request to the file in tmp-upload-images/.



- [https://github.com/Alexeyan/CVE-2009-4137](https://github.com/Alexeyan/CVE-2009-4137) :  ![starts](https://img.shields.io/github/stars/Alexeyan/CVE-2009-4137.svg) ![forks](https://img.shields.io/github/forks/Alexeyan/CVE-2009-4137.svg)

## CVE-2009-4137
 The loadContentFromCookie function in core/Cookie.php in Piwik before 0.5 does not validate strings obtained from cookies before calling the unserialize function, which allows remote attackers to execute arbitrary code or upload arbitrary files via vectors related to the __destruct function in the Piwik_Config class; php://filter URIs; the __destruct functions in Zend Framework, as demonstrated by the Zend_Log destructor; the shutdown functions in Zend Framework, as demonstrated by the Zend_Log_Writer_Mail class; the render function in the Piwik_View class; Smarty templates; and the _eval function in Smarty.



- [https://github.com/Alexeyan/CVE-2009-4137](https://github.com/Alexeyan/CVE-2009-4137) :  ![starts](https://img.shields.io/github/stars/Alexeyan/CVE-2009-4137.svg) ![forks](https://img.shields.io/github/forks/Alexeyan/CVE-2009-4137.svg)

## CVE-2009-4118
 The StartServiceCtrlDispatcher function in the cvpnd service (cvpnd.exe) in Cisco VPN client for Windows before 5.0.06.0100 does not properly handle an ERROR_FAILED_SERVICE_CONTROLLER_CONNECT error, which allows local users to cause a denial of service (service crash and VPN connection loss) via a manual start of cvpnd.exe while the cvpnd service is running.



- [https://github.com/alt3kx/CVE-2009-4118](https://github.com/alt3kx/CVE-2009-4118) :  ![starts](https://img.shields.io/github/stars/alt3kx/CVE-2009-4118.svg) ![forks](https://img.shields.io/github/forks/alt3kx/CVE-2009-4118.svg)

## CVE-2009-4092
 Cross-site request forgery (CSRF) vulnerability in user.php in Simplog 0.9.3.2, and possibly earlier, allows remote attackers to hijack the authentication of administrators and users for requests that change passwords.



- [https://github.com/xiaoyu-iid/Simplog-Exploit](https://github.com/xiaoyu-iid/Simplog-Exploit) :  ![starts](https://img.shields.io/github/stars/xiaoyu-iid/Simplog-Exploit.svg) ![forks](https://img.shields.io/github/forks/xiaoyu-iid/Simplog-Exploit.svg)

## CVE-2009-3555
 The TLS protocol, and the SSL protocol 3.0 and possibly earlier, as used in Microsoft Internet Information Services (IIS) 7.0, mod_ssl in the Apache HTTP Server 2.2.14 and earlier, OpenSSL before 0.9.8l, GnuTLS 2.8.5 and earlier, Mozilla Network Security Services (NSS) 3.12.4 and earlier, multiple Cisco products, and other products, does not properly associate renegotiation handshakes with an existing connection, which allows man-in-the-middle attackers to insert data into HTTPS sessions, and possibly other types of sessions protected by TLS or SSL, by sending an unauthenticated request that is processed retroactively by a server in a post-renegotiation context, related to a &quot;plaintext injection&quot; attack, aka the &quot;Project Mogul&quot; issue.



- [https://github.com/johnwchadwick/cve-2009-3555-test-server](https://github.com/johnwchadwick/cve-2009-3555-test-server) :  ![starts](https://img.shields.io/github/stars/johnwchadwick/cve-2009-3555-test-server.svg) ![forks](https://img.shields.io/github/forks/johnwchadwick/cve-2009-3555-test-server.svg)

## CVE-2009-3548
 The Windows installer for Apache Tomcat 6.0.0 through 6.0.20, 5.5.0 through 5.5.28, and possibly earlier versions uses a blank default password for the administrative user, which allows remote attackers to gain privileges.



- [https://github.com/cocomelonc/vulnexipy](https://github.com/cocomelonc/vulnexipy) :  ![starts](https://img.shields.io/github/stars/cocomelonc/vulnexipy.svg) ![forks](https://img.shields.io/github/forks/cocomelonc/vulnexipy.svg)

## CVE-2009-3103
 Array index error in the SMBv2 protocol implementation in srv2.sys in Microsoft Windows Vista Gold, SP1, and SP2, Windows Server 2008 Gold and SP2, and Windows 7 RC allows remote attackers to execute arbitrary code or cause a denial of service (system crash) via an &amp; (ampersand) character in a Process ID High header field in a NEGOTIATE PROTOCOL REQUEST packet, which triggers an attempted dereference of an out-of-bounds memory location, aka &quot;SMBv2 Negotiation Vulnerability.&quot; NOTE: some of these details are obtained from third party information.



- [https://github.com/sooklalad/ms09050](https://github.com/sooklalad/ms09050) :  ![starts](https://img.shields.io/github/stars/sooklalad/ms09050.svg) ![forks](https://img.shields.io/github/forks/sooklalad/ms09050.svg)

## CVE-2009-2698
 The udp_sendmsg function in the UDP implementation in (1) net/ipv4/udp.c and (2) net/ipv6/udp.c in the Linux kernel before 2.6.19 allows local users to gain privileges or cause a denial of service (NULL pointer dereference and system crash) via vectors involving the MSG_MORE flag and a UDP socket.



- [https://github.com/xiaoxiaoleo/CVE-2009-2698](https://github.com/xiaoxiaoleo/CVE-2009-2698) :  ![starts](https://img.shields.io/github/stars/xiaoxiaoleo/CVE-2009-2698.svg) ![forks](https://img.shields.io/github/forks/xiaoxiaoleo/CVE-2009-2698.svg)

## CVE-2009-2692
 The Linux kernel 2.6.0 through 2.6.30.4, and 2.4.4 through 2.4.37.4, does not initialize all function pointers for socket operations in proto_ops structures, which allows local users to trigger a NULL pointer dereference and gain privileges by using mmap to map page zero, placing arbitrary code on this page, and then invoking an unavailable operation, as demonstrated by the sendpage operation (sock_sendpage function) on a PF_PPPOX socket.



- [https://github.com/jdvalentini/CVE-2009-2692](https://github.com/jdvalentini/CVE-2009-2692) :  ![starts](https://img.shields.io/github/stars/jdvalentini/CVE-2009-2692.svg) ![forks](https://img.shields.io/github/forks/jdvalentini/CVE-2009-2692.svg)

## CVE-2009-2585
 SQL injection vulnerability in index.php in Mlffat 2.2 allows remote attackers to execute arbitrary SQL commands via a member cookie in an account editprofile action, a different vector than CVE-2009-1731.



- [https://github.com/n4xh4ck5/CVE2009-2585_HP_Power_Manager_BoF](https://github.com/n4xh4ck5/CVE2009-2585_HP_Power_Manager_BoF) :  ![starts](https://img.shields.io/github/stars/n4xh4ck5/CVE2009-2585_HP_Power_Manager_BoF.svg) ![forks](https://img.shields.io/github/forks/n4xh4ck5/CVE2009-2585_HP_Power_Manager_BoF.svg)

## CVE-2009-2265
 Multiple directory traversal vulnerabilities in FCKeditor before 2.6.4.1 allow remote attackers to create executable files in arbitrary directories via directory traversal sequences in the input to unspecified connector modules, as exploited in the wild for remote code execution in July 2009, related to the file browser and the editor/filemanager/connectors/ directory.



- [https://github.com/zaphoxx/zaphoxx-coldfusion](https://github.com/zaphoxx/zaphoxx-coldfusion) :  ![starts](https://img.shields.io/github/stars/zaphoxx/zaphoxx-coldfusion.svg) ![forks](https://img.shields.io/github/forks/zaphoxx/zaphoxx-coldfusion.svg)

- [https://github.com/0xkasra/CVE-2009-2265](https://github.com/0xkasra/CVE-2009-2265) :  ![starts](https://img.shields.io/github/stars/0xkasra/CVE-2009-2265.svg) ![forks](https://img.shields.io/github/forks/0xkasra/CVE-2009-2265.svg)

- [https://github.com/0zvxr/CVE-2009-2265](https://github.com/0zvxr/CVE-2009-2265) :  ![starts](https://img.shields.io/github/stars/0zvxr/CVE-2009-2265.svg) ![forks](https://img.shields.io/github/forks/0zvxr/CVE-2009-2265.svg)

- [https://github.com/k4u5h41/CVE-2009-2265](https://github.com/k4u5h41/CVE-2009-2265) :  ![starts](https://img.shields.io/github/stars/k4u5h41/CVE-2009-2265.svg) ![forks](https://img.shields.io/github/forks/k4u5h41/CVE-2009-2265.svg)

## CVE-2009-1904
 The BigDecimal library in Ruby 1.8.6 before p369 and 1.8.7 before p173 allows context-dependent attackers to cause a denial of service (application crash) via a string argument that represents a large number, as demonstrated by an attempted conversion to the Float data type.



- [https://github.com/NZKoz/bigdecimal-segfault-fix](https://github.com/NZKoz/bigdecimal-segfault-fix) :  ![starts](https://img.shields.io/github/stars/NZKoz/bigdecimal-segfault-fix.svg) ![forks](https://img.shields.io/github/forks/NZKoz/bigdecimal-segfault-fix.svg)

## CVE-2009-1437
 Stack-based buffer overflow in PortableApps CoolPlayer Portable (aka CoolPlayer+ Portable) 2.19.6 and earlier allows remote attackers to execute arbitrary code via a long string in a malformed playlist (.m3u) file. NOTE: this may overlap CVE-2008-3408.



- [https://github.com/HanseSecure/CVE-2009-1437](https://github.com/HanseSecure/CVE-2009-1437) :  ![starts](https://img.shields.io/github/stars/HanseSecure/CVE-2009-1437.svg) ![forks](https://img.shields.io/github/forks/HanseSecure/CVE-2009-1437.svg)

## CVE-2009-1330
 Stack-based buffer overflow in Easy RM to MP3 Converter allows remote attackers to execute arbitrary code via a long filename in a playlist (.pls) file.



- [https://github.com/war4uthor/CVE-2009-1330](https://github.com/war4uthor/CVE-2009-1330) :  ![starts](https://img.shields.io/github/stars/war4uthor/CVE-2009-1330.svg) ![forks](https://img.shields.io/github/forks/war4uthor/CVE-2009-1330.svg)

- [https://github.com/adenkiewicz/CVE-2009-1330](https://github.com/adenkiewicz/CVE-2009-1330) :  ![starts](https://img.shields.io/github/stars/adenkiewicz/CVE-2009-1330.svg) ![forks](https://img.shields.io/github/forks/adenkiewicz/CVE-2009-1330.svg)

- [https://github.com/exploitwritter/CVE-2009-1330_EasyRMToMp3Converter](https://github.com/exploitwritter/CVE-2009-1330_EasyRMToMp3Converter) :  ![starts](https://img.shields.io/github/stars/exploitwritter/CVE-2009-1330_EasyRMToMp3Converter.svg) ![forks](https://img.shields.io/github/forks/exploitwritter/CVE-2009-1330_EasyRMToMp3Converter.svg)

## CVE-2009-1324
 Stack-based buffer overflow in Mini-stream ASX to MP3 Converter 3.0.0.7 allows remote attackers to execute arbitrary code via a long URI in a playlist (.m3u) file.



- [https://github.com/war4uthor/CVE-2009-1324](https://github.com/war4uthor/CVE-2009-1324) :  ![starts](https://img.shields.io/github/stars/war4uthor/CVE-2009-1324.svg) ![forks](https://img.shields.io/github/forks/war4uthor/CVE-2009-1324.svg)

## CVE-2009-1244
 Unspecified vulnerability in the virtual machine display function in VMware Workstation 6.5.1 and earlier; VMware Player 2.5.1 and earlier; VMware ACE 2.5.1 and earlier; VMware Server 1.x before 1.0.9 build 156507 and 2.x before 2.0.1 build 156745; VMware Fusion before 2.0.4 build 159196; VMware ESXi 3.5; and VMware ESX 3.0.2, 3.0.3, and 3.5 allows guest OS users to execute arbitrary code on the host OS via unknown vectors, a different vulnerability than CVE-2008-4916.



- [https://github.com/piotrbania/vmware_exploit_pack_CVE-2009-1244](https://github.com/piotrbania/vmware_exploit_pack_CVE-2009-1244) :  ![starts](https://img.shields.io/github/stars/piotrbania/vmware_exploit_pack_CVE-2009-1244.svg) ![forks](https://img.shields.io/github/forks/piotrbania/vmware_exploit_pack_CVE-2009-1244.svg)

## CVE-2009-1151
 Static code injection vulnerability in setup.php in phpMyAdmin 2.11.x before 2.11.9.5 and 3.x before 3.1.3.1 allows remote attackers to inject arbitrary PHP code into a configuration file via the save action.



- [https://github.com/pagvac/pocs](https://github.com/pagvac/pocs) :  ![starts](https://img.shields.io/github/stars/pagvac/pocs.svg) ![forks](https://img.shields.io/github/forks/pagvac/pocs.svg)

## CVE-2009-0689
 Array index error in the (1) dtoa implementation in dtoa.c (aka pdtoa.c) and the (2) gdtoa (aka new dtoa) implementation in gdtoa/misc.c in libc, as used in multiple operating systems and products including in FreeBSD 6.4 and 7.2, NetBSD 5.0, OpenBSD 4.5, Mozilla Firefox 3.0.x before 3.0.15 and 3.5.x before 3.5.4, K-Meleon 1.5.3, SeaMonkey 1.1.8, and other products, allows context-dependent attackers to cause a denial of service (application crash) and possibly execute arbitrary code via a large precision value in the format argument to a printf function, which triggers incorrect memory allocation and a heap-based buffer overflow during conversion to a floating-point number.



- [https://github.com/Fullmetal5/str2hax](https://github.com/Fullmetal5/str2hax) :  ![starts](https://img.shields.io/github/stars/Fullmetal5/str2hax.svg) ![forks](https://img.shields.io/github/forks/Fullmetal5/str2hax.svg)

## CVE-2009-0473
 Open redirect vulnerability in the web interface in the Rockwell Automation ControlLogix 1756-ENBT/A EtherNet/IP Bridge Module allows remote attackers to redirect users to arbitrary web sites and conduct phishing attacks via unspecified vectors.



- [https://github.com/akbarq/CVE-2009-0473-check](https://github.com/akbarq/CVE-2009-0473-check) :  ![starts](https://img.shields.io/github/stars/akbarq/CVE-2009-0473-check.svg) ![forks](https://img.shields.io/github/forks/akbarq/CVE-2009-0473-check.svg)

## CVE-2009-0229
 The Windows Printing Service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP2, Vista Gold, SP1, and SP2, and Server 2008 SP2 allows local users to read arbitrary files via a crafted separator page, aka &quot;Print Spooler Read File Vulnerability.&quot;



- [https://github.com/zveriu/CVE-2009-0229-PoC](https://github.com/zveriu/CVE-2009-0229-PoC) :  ![starts](https://img.shields.io/github/stars/zveriu/CVE-2009-0229-PoC.svg) ![forks](https://img.shields.io/github/forks/zveriu/CVE-2009-0229-PoC.svg)

## CVE-2009-0182
 Buffer overflow in VUPlayer 2.49 and earlier allows user-assisted attackers to execute arbitrary code via a long URL in a File line in a .pls file, as demonstrated by an http URL on a File1 line.



- [https://github.com/nobodyatall648/CVE-2009-0182](https://github.com/nobodyatall648/CVE-2009-0182) :  ![starts](https://img.shields.io/github/stars/nobodyatall648/CVE-2009-0182.svg) ![forks](https://img.shields.io/github/forks/nobodyatall648/CVE-2009-0182.svg)
