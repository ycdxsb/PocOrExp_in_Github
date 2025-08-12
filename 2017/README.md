## CVE-2017-1000499
 phpMyAdmin versions 4.7.x (prior to 4.7.6.1/4.7.7) are vulnerable to a CSRF weakness. By deceiving a user to click on a crafted URL, it is possible to perform harmful database operations such as deleting records, dropping/truncating tables etc.



- [https://github.com/Villaquiranm/5MMISSI-CVE-2017-1000499](https://github.com/Villaquiranm/5MMISSI-CVE-2017-1000499) :  ![starts](https://img.shields.io/github/stars/Villaquiranm/5MMISSI-CVE-2017-1000499.svg) ![forks](https://img.shields.io/github/forks/Villaquiranm/5MMISSI-CVE-2017-1000499.svg)

## CVE-2017-1000427
 marked version 0.3.6 and earlier is vulnerable to an XSS attack in the data: URI parser.



- [https://github.com/ossf-cve-benchmark/CVE-2017-1000427](https://github.com/ossf-cve-benchmark/CVE-2017-1000427) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-1000427.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-1000427.svg)

## CVE-2017-1000353
 Jenkins versions 2.56 and earlier as well as 2.46.1 LTS and earlier are vulnerable to an unauthenticated remote code execution. An unauthenticated remote code execution vulnerability allowed attackers to transfer a serialized Java `SignedObject` object to the Jenkins CLI, that would be deserialized using a new `ObjectInputStream`, bypassing the existing blacklist-based protection mechanism. We're fixing this issue by adding `SignedObject` to the blacklist. We're also backporting the new HTTP CLI protocol from Jenkins 2.54 to LTS 2.46.2, and deprecating the remoting-based (i.e. Java serialization) CLI protocol, disabling it by default.



- [https://github.com/vulhub/CVE-2017-1000353](https://github.com/vulhub/CVE-2017-1000353) :  ![starts](https://img.shields.io/github/stars/vulhub/CVE-2017-1000353.svg) ![forks](https://img.shields.io/github/forks/vulhub/CVE-2017-1000353.svg)

- [https://github.com/r00t4dm/Jenkins-CVE-2017-1000353](https://github.com/r00t4dm/Jenkins-CVE-2017-1000353) :  ![starts](https://img.shields.io/github/stars/r00t4dm/Jenkins-CVE-2017-1000353.svg) ![forks](https://img.shields.io/github/forks/r00t4dm/Jenkins-CVE-2017-1000353.svg)

## CVE-2017-1000253
 Linux distributions that have not patched their long-term kernels with https://git.kernel.org/linus/a87938b2e246b81b4fb713edb371a9fa3c5c3c86 (committed on April 14, 2015). This kernel vulnerability was fixed in April 2015 by commit a87938b2e246b81b4fb713edb371a9fa3c5c3c86 (backported to Linux 3.10.77 in May 2015), but it was not recognized as a security threat. With CONFIG_ARCH_BINFMT_ELF_RANDOMIZE_PIE enabled, and a normal top-down address allocation strategy, load_elf_binary() will attempt to map a PIE binary into an address range immediately below mm-mmap_base. Unfortunately, load_elf_ binary() does not take account of the need to allocate sufficient space for the entire binary which means that, while the first PT_LOAD segment is mapped below mm-mmap_base, the subsequent PT_LOAD segment(s) end up being mapped above mm-mmap_base into the are that is supposed to be the "gap" between the stack and the binary.



- [https://github.com/RicterZ/PIE-Stack-Clash-CVE-2017-1000253](https://github.com/RicterZ/PIE-Stack-Clash-CVE-2017-1000253) :  ![starts](https://img.shields.io/github/stars/RicterZ/PIE-Stack-Clash-CVE-2017-1000253.svg) ![forks](https://img.shields.io/github/forks/RicterZ/PIE-Stack-Clash-CVE-2017-1000253.svg)

- [https://github.com/sxlmnwb/CVE-2017-1000253](https://github.com/sxlmnwb/CVE-2017-1000253) :  ![starts](https://img.shields.io/github/stars/sxlmnwb/CVE-2017-1000253.svg) ![forks](https://img.shields.io/github/forks/sxlmnwb/CVE-2017-1000253.svg)

## CVE-2017-1000028
 Oracle, GlassFish Server Open Source Edition 4.1 is vulnerable to both authenticated and unauthenticated Directory Traversal vulnerability, that can be exploited by issuing a specially crafted HTTP GET request.



- [https://github.com/NeonNOXX/CVE-2017-1000028](https://github.com/NeonNOXX/CVE-2017-1000028) :  ![starts](https://img.shields.io/github/stars/NeonNOXX/CVE-2017-1000028.svg) ![forks](https://img.shields.io/github/forks/NeonNOXX/CVE-2017-1000028.svg)

## CVE-2017-1000006
 Plotly, Inc. plotly.js versions prior to 1.16.0 are vulnerable to an XSS issue.



- [https://github.com/ossf-cve-benchmark/CVE-2017-1000006](https://github.com/ossf-cve-benchmark/CVE-2017-1000006) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-1000006.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-1000006.svg)

## CVE-2017-18635
 An XSS vulnerability was discovered in noVNC before 0.6.2 in which the remote VNC server could inject arbitrary HTML into the noVNC web page via the messages propagated to the status field, such as the VNC server name.



- [https://github.com/ShielderSec/CVE-2017-18635](https://github.com/ShielderSec/CVE-2017-18635) :  ![starts](https://img.shields.io/github/stars/ShielderSec/CVE-2017-18635.svg) ![forks](https://img.shields.io/github/forks/ShielderSec/CVE-2017-18635.svg)

- [https://github.com/ossf-cve-benchmark/CVE-2017-18635](https://github.com/ossf-cve-benchmark/CVE-2017-18635) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-18635.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-18635.svg)

## CVE-2017-18214
 The moment module before 2.19.3 for Node.js is prone to a regular expression denial of service via a crafted date string, a different vulnerability than CVE-2016-4055.



- [https://github.com/ossf-cve-benchmark/CVE-2017-18214](https://github.com/ossf-cve-benchmark/CVE-2017-18214) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-18214.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-18214.svg)

## CVE-2017-18016
 Parity Browser 1.6.10 and earlier allows remote attackers to bypass the Same Origin Policy and obtain sensitive information by requesting other websites via the Parity web proxy engine (reusing the current website's token, which is not bound to an origin).



- [https://github.com/tintinweb/pub](https://github.com/tintinweb/pub) :  ![starts](https://img.shields.io/github/stars/tintinweb/pub.svg) ![forks](https://img.shields.io/github/forks/tintinweb/pub.svg)

## CVE-2017-17562
 Embedthis GoAhead before 3.6.5 allows remote code execution if CGI is enabled and a CGI program is dynamically linked. This is a result of initializing the environment of forked CGI scripts using untrusted HTTP request parameters in the cgiHandler function in cgi.c. When combined with the glibc dynamic linker, this behaviour can be abused for remote code execution using special parameter names such as LD_PRELOAD. An attacker can POST their shared object payload in the body of the request, and reference it using /proc/self/fd/0.



- [https://github.com/ivanitlearning/CVE-2017-17562](https://github.com/ivanitlearning/CVE-2017-17562) :  ![starts](https://img.shields.io/github/stars/ivanitlearning/CVE-2017-17562.svg) ![forks](https://img.shields.io/github/forks/ivanitlearning/CVE-2017-17562.svg)

- [https://github.com/nu11pointer/goahead-rce-exploit](https://github.com/nu11pointer/goahead-rce-exploit) :  ![starts](https://img.shields.io/github/stars/nu11pointer/goahead-rce-exploit.svg) ![forks](https://img.shields.io/github/forks/nu11pointer/goahead-rce-exploit.svg)

- [https://github.com/1337g/CVE-2017-17562](https://github.com/1337g/CVE-2017-17562) :  ![starts](https://img.shields.io/github/stars/1337g/CVE-2017-17562.svg) ![forks](https://img.shields.io/github/forks/1337g/CVE-2017-17562.svg)

- [https://github.com/joaomagfreitas/bash-CVE-2017-17562](https://github.com/joaomagfreitas/bash-CVE-2017-17562) :  ![starts](https://img.shields.io/github/stars/joaomagfreitas/bash-CVE-2017-17562.svg) ![forks](https://img.shields.io/github/forks/joaomagfreitas/bash-CVE-2017-17562.svg)

- [https://github.com/crispy-peppers/Goahead-CVE-2017-17562](https://github.com/crispy-peppers/Goahead-CVE-2017-17562) :  ![starts](https://img.shields.io/github/stars/crispy-peppers/Goahead-CVE-2017-17562.svg) ![forks](https://img.shields.io/github/forks/crispy-peppers/Goahead-CVE-2017-17562.svg)

- [https://github.com/cyberharsh/GoAhead-cve---2017--17562](https://github.com/cyberharsh/GoAhead-cve---2017--17562) :  ![starts](https://img.shields.io/github/stars/cyberharsh/GoAhead-cve---2017--17562.svg) ![forks](https://img.shields.io/github/forks/cyberharsh/GoAhead-cve---2017--17562.svg)

## CVE-2017-17099
 There exists an unauthenticated SEH based Buffer Overflow vulnerability in the HTTP server of Flexense SyncBreeze Enterprise v10.1.16. When sending a GET request with an excessive length, it is possible for a malicious user to overwrite the SEH record and execute a payload that would run under the Windows SYSTEM account.



- [https://github.com/wetw0rk/Exploit-Development](https://github.com/wetw0rk/Exploit-Development) :  ![starts](https://img.shields.io/github/stars/wetw0rk/Exploit-Development.svg) ![forks](https://img.shields.io/github/forks/wetw0rk/Exploit-Development.svg)

## CVE-2017-16943
 The receive_msg function in receive.c in the SMTP daemon in Exim 4.88 and 4.89 allows remote attackers to execute arbitrary code or cause a denial of service (use-after-free) via vectors involving BDAT commands.



- [https://github.com/beraphin/CVE-2017-16943](https://github.com/beraphin/CVE-2017-16943) :  ![starts](https://img.shields.io/github/stars/beraphin/CVE-2017-16943.svg) ![forks](https://img.shields.io/github/forks/beraphin/CVE-2017-16943.svg)

## CVE-2017-16939
 The XFRM dump policy implementation in net/xfrm/xfrm_user.c in the Linux kernel before 4.13.11 allows local users to gain privileges or cause a denial of service (use-after-free) via a crafted SO_RCVBUF setsockopt system call in conjunction with XFRM_MSG_GETPOLICY Netlink messages.



- [https://github.com/Al1ex/LinuxEelvation](https://github.com/Al1ex/LinuxEelvation) :  ![starts](https://img.shields.io/github/stars/Al1ex/LinuxEelvation.svg) ![forks](https://img.shields.io/github/forks/Al1ex/LinuxEelvation.svg)

## CVE-2017-16930
 The remote management interface on the Claymore Dual GPU miner 10.1 allows an unauthenticated remote attacker to execute arbitrary code due to a stack-based buffer overflow in the request handler. This can be exploited via a long API request that is mishandled during logging.



- [https://github.com/tintinweb/pub](https://github.com/tintinweb/pub) :  ![starts](https://img.shields.io/github/stars/tintinweb/pub.svg) ![forks](https://img.shields.io/github/forks/tintinweb/pub.svg)

## CVE-2017-16806
 The Process function in RemoteTaskServer/WebServer/HttpServer.cs in Ulterius before 1.9.5.0 allows HTTP server directory traversal.



- [https://github.com/rickoooooo/ulteriusExploit](https://github.com/rickoooooo/ulteriusExploit) :  ![starts](https://img.shields.io/github/stars/rickoooooo/ulteriusExploit.svg) ![forks](https://img.shields.io/github/forks/rickoooooo/ulteriusExploit.svg)

## CVE-2017-16695
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem.  When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/Jewel591/Privilege-Escalation](https://github.com/Jewel591/Privilege-Escalation) :  ![starts](https://img.shields.io/github/stars/Jewel591/Privilege-Escalation.svg) ![forks](https://img.shields.io/github/forks/Jewel591/Privilege-Escalation.svg)

## CVE-2017-16524
 Web Viewer 1.0.0.193 on Samsung SRN-1670D devices suffers from an Unrestricted file upload vulnerability: 'network_ssl_upload.php' allows remote authenticated attackers to upload and execute arbitrary PHP code via a filename with a .php extension, which is then accessed via a direct request to the file in the upload/ directory. To authenticate for this attack, one can obtain web-interface credentials in cleartext by leveraging the existing Local File Read Vulnerability referenced as CVE-2015-8279, which allows remote attackers to read the web-interface credentials via a request for the cslog_export.php?path=/root/php_modules/lighttpd/sbin/userpw URI.



- [https://github.com/realistic-security/CVE-2017-16524](https://github.com/realistic-security/CVE-2017-16524) :  ![starts](https://img.shields.io/github/stars/realistic-security/CVE-2017-16524.svg) ![forks](https://img.shields.io/github/forks/realistic-security/CVE-2017-16524.svg)

## CVE-2017-16245
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem.  When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/AOCorsaire/CVE-2017-16245](https://github.com/AOCorsaire/CVE-2017-16245) :  ![starts](https://img.shields.io/github/stars/AOCorsaire/CVE-2017-16245.svg) ![forks](https://img.shields.io/github/forks/AOCorsaire/CVE-2017-16245.svg)

## CVE-2017-16137
 The debug module is vulnerable to regular expression denial of service when untrusted user input is passed into the o formatter. It takes around 50k characters to block for 2 seconds making this a low severity issue.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16137](https://github.com/ossf-cve-benchmark/CVE-2017-16137) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16137.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16137.svg)

## CVE-2017-16114
 The marked module is vulnerable to a regular expression denial of service. Based on the information published in the public issue, 1k characters can block for around 6 seconds.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16114](https://github.com/ossf-cve-benchmark/CVE-2017-16114) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16114.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16114.svg)

## CVE-2017-16107
 pooledwebsocket is vulnerable to a directory traversal issue, giving an attacker access to the filesystem by placing "../" in the url.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16107](https://github.com/ossf-cve-benchmark/CVE-2017-16107) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16107.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16107.svg)

## CVE-2017-16098
 charset 1.0.0 and below are vulnerable to regular expression denial of service. Input of around 50k characters is required for a slow down of around 2 seconds. Unless node was compiled using the -DHTTP_MAX_HEADER_SIZE= option the default header max length is 80kb, so the impact of the ReDoS is relatively low.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16098](https://github.com/ossf-cve-benchmark/CVE-2017-16098) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16098.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16098.svg)

## CVE-2017-16087
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem.  When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16087](https://github.com/ossf-cve-benchmark/CVE-2017-16087) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16087.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16087.svg)

## CVE-2017-16082
 A remote code execution vulnerability was found within the pg module when the remote database or query specifies a specially crafted column name. There are 2 likely scenarios in which one would likely be vulnerable. 1) Executing unsafe, user-supplied sql which contains a malicious column name. 2) Connecting to an untrusted database and executing a query which returns results where any of the column names are malicious.



- [https://github.com/nulldreams/CVE-2017-16082](https://github.com/nulldreams/CVE-2017-16082) :  ![starts](https://img.shields.io/github/stars/nulldreams/CVE-2017-16082.svg) ![forks](https://img.shields.io/github/forks/nulldreams/CVE-2017-16082.svg)

- [https://github.com/ossf-cve-benchmark/CVE-2017-16082](https://github.com/ossf-cve-benchmark/CVE-2017-16082) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16082.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16082.svg)

## CVE-2017-16043
 Shout is an IRC client. Because the `/topic` command in messages is unescaped, attackers have the ability to inject HTML scripts that will run in the victim's browser. Affects shout =0.44.0 =0.49.3.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16043](https://github.com/ossf-cve-benchmark/CVE-2017-16043) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16043.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16043.svg)

## CVE-2017-16042
 Growl adds growl notification support to nodejs. Growl before 1.10.2 does not properly sanitize input before passing it to exec, allowing for arbitrary command execution.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16042](https://github.com/ossf-cve-benchmark/CVE-2017-16042) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16042.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16042.svg)

## CVE-2017-16034
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem.  When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16034](https://github.com/ossf-cve-benchmark/CVE-2017-16034) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16034.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16034.svg)

## CVE-2017-16014
 Http-proxy is a proxying library. Because of the way errors are handled in versions before 0.7.0, an attacker that forces an error can crash the server, causing a denial of service.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16014](https://github.com/ossf-cve-benchmark/CVE-2017-16014) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16014.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16014.svg)

## CVE-2017-16011
 DO NOT USE THIS CANDIDATE NUMBER.  ConsultIDs: CVE-2012-6708.  Reason: This candidate is a duplicate of CVE-2012-6708.  Notes: All CVE users should reference CVE-2012-6708 instead of this candidate.  All references and descriptions in this candidate have been removed to prevent accidental usage



- [https://github.com/ossf-cve-benchmark/CVE-2017-16011](https://github.com/ossf-cve-benchmark/CVE-2017-16011) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16011.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16011.svg)

## CVE-2017-16006
 Remarkable is a markdown parser. In versions 1.6.2 and lower, remarkable allows the use of `data:` URIs in links and can therefore execute javascript.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16006](https://github.com/ossf-cve-benchmark/CVE-2017-16006) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16006.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16006.svg)

## CVE-2017-15689
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem.  When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/hidog123/Codiad-CVE-2018-14009](https://github.com/hidog123/Codiad-CVE-2018-14009) :  ![starts](https://img.shields.io/github/stars/hidog123/Codiad-CVE-2018-14009.svg) ![forks](https://img.shields.io/github/forks/hidog123/Codiad-CVE-2018-14009.svg)

## CVE-2017-15120
 An issue has been found in the parsing of authoritative answers in PowerDNS Recursor before 4.0.8, leading to a NULL pointer dereference when parsing a specially crafted answer containing a CNAME of a different class than IN. An unauthenticated remote attacker could cause a denial of service.



- [https://github.com/shutingrz/CVE-2017-15120_PoC](https://github.com/shutingrz/CVE-2017-15120_PoC) :  ![starts](https://img.shields.io/github/stars/shutingrz/CVE-2017-15120_PoC.svg) ![forks](https://img.shields.io/github/forks/shutingrz/CVE-2017-15120_PoC.svg)

## CVE-2017-15010
 A ReDoS (regular expression denial of service) flaw was found in the tough-cookie module before 2.3.3 for Node.js. An attacker that is able to make an HTTP request using a specially crafted cookie may cause the application to consume an excessive amount of CPU.



- [https://github.com/ossf-cve-benchmark/CVE-2017-15010](https://github.com/ossf-cve-benchmark/CVE-2017-15010) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-15010.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-15010.svg)

## CVE-2017-14719
 Before version 4.8.2, WordPress was vulnerable to a directory traversal attack during unzip operations in the ZipArchive and PclZip components.



- [https://github.com/PalmTreeForest/CodePath_Week_7-8](https://github.com/PalmTreeForest/CodePath_Week_7-8) :  ![starts](https://img.shields.io/github/stars/PalmTreeForest/CodePath_Week_7-8.svg) ![forks](https://img.shields.io/github/forks/PalmTreeForest/CodePath_Week_7-8.svg)

## CVE-2017-14105
 HiveManager Classic through 8.1r1 allows arbitrary JSP code execution by modifying a backup archive before a restore, because the restore feature does not validate pathnames within the archive. An authenticated, local attacker - even restricted as a tenant - can add a jsp at HiveManager/tomcat/webapps/hm/domains/$yourtenant/maps (it will be exposed at the web interface).



- [https://github.com/theguly/CVE-2017-14105](https://github.com/theguly/CVE-2017-14105) :  ![starts](https://img.shields.io/github/stars/theguly/CVE-2017-14105.svg) ![forks](https://img.shields.io/github/forks/theguly/CVE-2017-14105.svg)

## CVE-2017-13872
 An issue was discovered in certain Apple products. macOS High Sierra before Security Update 2017-001 is affected. The issue involves the "Directory Utility" component. It allows attackers to obtain administrator access without a password via certain interactions involving entry of the root user name.



- [https://github.com/giovannidispoto/CVE-2017-13872-Patch](https://github.com/giovannidispoto/CVE-2017-13872-Patch) :  ![starts](https://img.shields.io/github/stars/giovannidispoto/CVE-2017-13872-Patch.svg) ![forks](https://img.shields.io/github/forks/giovannidispoto/CVE-2017-13872-Patch.svg)

## CVE-2017-13868
 An issue was discovered in certain Apple products. iOS before 11.2 is affected. macOS before 10.13.2 is affected. tvOS before 11.2 is affected. watchOS before 4.2 is affected. The issue involves the "Kernel" component. It allows attackers to bypass intended memory-read restrictions via a crafted app.



- [https://github.com/bazad/ctl_ctloutput-leak](https://github.com/bazad/ctl_ctloutput-leak) :  ![starts](https://img.shields.io/github/stars/bazad/ctl_ctloutput-leak.svg) ![forks](https://img.shields.io/github/forks/bazad/ctl_ctloutput-leak.svg)

## CVE-2017-13286
 In writeToParcel and readFromParcel of OutputConfiguration.java, there is a permission bypass due to mismatched serialization. This could lead to a local escalation of privilege where the user can start an activity with system privileges, with no additional execution privileges needed. User interaction is not needed for exploitation. Product: Android. Versions: 8.0, 8.1. Android ID: A-69683251.



- [https://github.com/UmVfX1BvaW50/CVE-2017-13286](https://github.com/UmVfX1BvaW50/CVE-2017-13286) :  ![starts](https://img.shields.io/github/stars/UmVfX1BvaW50/CVE-2017-13286.svg) ![forks](https://img.shields.io/github/forks/UmVfX1BvaW50/CVE-2017-13286.svg)

## CVE-2017-12945
 Insufficient validation of user-supplied input for the Solstice Pod before 2.8.4 networking configuration enables authenticated attackers to execute arbitrary commands as root.



- [https://github.com/aress31/cve-2017-12945](https://github.com/aress31/cve-2017-12945) :  ![starts](https://img.shields.io/github/stars/aress31/cve-2017-12945.svg) ![forks](https://img.shields.io/github/forks/aress31/cve-2017-12945.svg)

## CVE-2017-12943
 D-Link DIR-600 Rev Bx devices with v2.x firmware allow remote attackers to read passwords via a model/__show_info.php?REQUIRE_FILE= absolute path traversal attack, as demonstrated by discovering the admin password.



- [https://github.com/aymankhalfatni/D-Link](https://github.com/aymankhalfatni/D-Link) :  ![starts](https://img.shields.io/github/stars/aymankhalfatni/D-Link.svg) ![forks](https://img.shields.io/github/forks/aymankhalfatni/D-Link.svg)

- [https://github.com/d4rk30/CVE-2017-12943](https://github.com/d4rk30/CVE-2017-12943) :  ![starts](https://img.shields.io/github/stars/d4rk30/CVE-2017-12943.svg) ![forks](https://img.shields.io/github/forks/d4rk30/CVE-2017-12943.svg)

## CVE-2017-12792
 Multiple cross-site request forgery (CSRF) vulnerabilities in NexusPHP 1.5 allow remote attackers to hijack the authentication of administrators for requests that conduct cross-site scripting (XSS) attacks via the (1) linkname, (2) url, or (3) title parameter in an add action to linksmanage.php.



- [https://github.com/ZZS2017/cve-2017-12792](https://github.com/ZZS2017/cve-2017-12792) :  ![starts](https://img.shields.io/github/stars/ZZS2017/cve-2017-12792.svg) ![forks](https://img.shields.io/github/forks/ZZS2017/cve-2017-12792.svg)

## CVE-2017-12629
 Remote code execution occurs in Apache Solr before 7.1 with Apache Lucene before 7.1 by exploiting XXE in conjunction with use of a Config API add-listener command to reach the RunExecutableListener class. Elasticsearch, although it uses Lucene, is NOT vulnerable to this. Note that the XML external entity expansion vulnerability occurs in the XML Query Parser which is available, by default, for any query request with parameters deftype=xmlparser and can be exploited to upload malicious data to the /upload request handler or as Blind XXE using ftp wrapper in order to read arbitrary local files from the Solr server. Note also that the second vulnerability relates to remote code execution using the RunExecutableListener available on all affected versions of Solr.



- [https://github.com/Imanfeng/Apache-Solr-RCE](https://github.com/Imanfeng/Apache-Solr-RCE) :  ![starts](https://img.shields.io/github/stars/Imanfeng/Apache-Solr-RCE.svg) ![forks](https://img.shields.io/github/forks/Imanfeng/Apache-Solr-RCE.svg)

- [https://github.com/tdwyer/PoC_CVE-2017-3164_CVE-2017-1262](https://github.com/tdwyer/PoC_CVE-2017-3164_CVE-2017-1262) :  ![starts](https://img.shields.io/github/stars/tdwyer/PoC_CVE-2017-3164_CVE-2017-1262.svg) ![forks](https://img.shields.io/github/forks/tdwyer/PoC_CVE-2017-3164_CVE-2017-1262.svg)

- [https://github.com/captain-woof/cve-2017-12629](https://github.com/captain-woof/cve-2017-12629) :  ![starts](https://img.shields.io/github/stars/captain-woof/cve-2017-12629.svg) ![forks](https://img.shields.io/github/forks/captain-woof/cve-2017-12629.svg)

## CVE-2017-12615
 When running Apache Tomcat 7.0.0 to 7.0.79 on Windows with HTTP PUTs enabled (e.g. via setting the readonly initialisation parameter of the Default to false) it was possible to upload a JSP file to the server via a specially crafted request. This JSP could then be requested and any code it contained would be executed by the server.



- [https://github.com/lizhianyuguangming/TomcatScanPro](https://github.com/lizhianyuguangming/TomcatScanPro) :  ![starts](https://img.shields.io/github/stars/lizhianyuguangming/TomcatScanPro.svg) ![forks](https://img.shields.io/github/forks/lizhianyuguangming/TomcatScanPro.svg)

- [https://github.com/tpt11fb/AttackTomcat](https://github.com/tpt11fb/AttackTomcat) :  ![starts](https://img.shields.io/github/stars/tpt11fb/AttackTomcat.svg) ![forks](https://img.shields.io/github/forks/tpt11fb/AttackTomcat.svg)

- [https://github.com/breaktoprotect/CVE-2017-12615](https://github.com/breaktoprotect/CVE-2017-12615) :  ![starts](https://img.shields.io/github/stars/breaktoprotect/CVE-2017-12615.svg) ![forks](https://img.shields.io/github/forks/breaktoprotect/CVE-2017-12615.svg)

- [https://github.com/mefulton/cve-2017-12615](https://github.com/mefulton/cve-2017-12615) :  ![starts](https://img.shields.io/github/stars/mefulton/cve-2017-12615.svg) ![forks](https://img.shields.io/github/forks/mefulton/cve-2017-12615.svg)

- [https://github.com/xiaokp7/Tomcat_PUT_GUI_EXP](https://github.com/xiaokp7/Tomcat_PUT_GUI_EXP) :  ![starts](https://img.shields.io/github/stars/xiaokp7/Tomcat_PUT_GUI_EXP.svg) ![forks](https://img.shields.io/github/forks/xiaokp7/Tomcat_PUT_GUI_EXP.svg)

- [https://github.com/zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717](https://github.com/zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717) :  ![starts](https://img.shields.io/github/stars/zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717.svg) ![forks](https://img.shields.io/github/forks/zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717.svg)

- [https://github.com/1337g/CVE-2017-12615](https://github.com/1337g/CVE-2017-12615) :  ![starts](https://img.shields.io/github/stars/1337g/CVE-2017-12615.svg) ![forks](https://img.shields.io/github/forks/1337g/CVE-2017-12615.svg)

- [https://github.com/wsg00d/cve-2017-12615](https://github.com/wsg00d/cve-2017-12615) :  ![starts](https://img.shields.io/github/stars/wsg00d/cve-2017-12615.svg) ![forks](https://img.shields.io/github/forks/wsg00d/cve-2017-12615.svg)

- [https://github.com/BeyondCy/CVE-2017-12615](https://github.com/BeyondCy/CVE-2017-12615) :  ![starts](https://img.shields.io/github/stars/BeyondCy/CVE-2017-12615.svg) ![forks](https://img.shields.io/github/forks/BeyondCy/CVE-2017-12615.svg)

- [https://github.com/ianxtianxt/CVE-2017-12615](https://github.com/ianxtianxt/CVE-2017-12615) :  ![starts](https://img.shields.io/github/stars/ianxtianxt/CVE-2017-12615.svg) ![forks](https://img.shields.io/github/forks/ianxtianxt/CVE-2017-12615.svg)

- [https://github.com/w0x68y/CVE-2017-12615-EXP](https://github.com/w0x68y/CVE-2017-12615-EXP) :  ![starts](https://img.shields.io/github/stars/w0x68y/CVE-2017-12615-EXP.svg) ![forks](https://img.shields.io/github/forks/w0x68y/CVE-2017-12615-EXP.svg)

- [https://github.com/cved-sources/cve-2017-12615](https://github.com/cved-sources/cve-2017-12615) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2017-12615.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2017-12615.svg)

- [https://github.com/Shellkeys/CVE-2017-12615](https://github.com/Shellkeys/CVE-2017-12615) :  ![starts](https://img.shields.io/github/stars/Shellkeys/CVE-2017-12615.svg) ![forks](https://img.shields.io/github/forks/Shellkeys/CVE-2017-12615.svg)

- [https://github.com/cyberharsh/Tomcat-CVE-2017-12615](https://github.com/cyberharsh/Tomcat-CVE-2017-12615) :  ![starts](https://img.shields.io/github/stars/cyberharsh/Tomcat-CVE-2017-12615.svg) ![forks](https://img.shields.io/github/forks/cyberharsh/Tomcat-CVE-2017-12615.svg)

- [https://github.com/wudidwo/CVE-2017-12615-poc](https://github.com/wudidwo/CVE-2017-12615-poc) :  ![starts](https://img.shields.io/github/stars/wudidwo/CVE-2017-12615-poc.svg) ![forks](https://img.shields.io/github/forks/wudidwo/CVE-2017-12615-poc.svg)

- [https://github.com/edyekomu/CVE-2017-12615-PoC](https://github.com/edyekomu/CVE-2017-12615-PoC) :  ![starts](https://img.shields.io/github/stars/edyekomu/CVE-2017-12615-PoC.svg) ![forks](https://img.shields.io/github/forks/edyekomu/CVE-2017-12615-PoC.svg)

## CVE-2017-12611
 In Apache Struts 2.0.0 through 2.3.33 and 2.5 through 2.5.10.1, using an unintentional expression in a Freemarker tag instead of string literals can lead to a RCE attack.



- [https://github.com/brianwrf/S2-053-CVE-2017-12611](https://github.com/brianwrf/S2-053-CVE-2017-12611) :  ![starts](https://img.shields.io/github/stars/brianwrf/S2-053-CVE-2017-12611.svg) ![forks](https://img.shields.io/github/forks/brianwrf/S2-053-CVE-2017-12611.svg)

## CVE-2017-12542
 A authentication bypass and execution of code vulnerability in HPE Integrated Lights-out 4 (iLO 4) version prior to 2.53 was found.



- [https://github.com/skelsec/CVE-2017-12542](https://github.com/skelsec/CVE-2017-12542) :  ![starts](https://img.shields.io/github/stars/skelsec/CVE-2017-12542.svg) ![forks](https://img.shields.io/github/forks/skelsec/CVE-2017-12542.svg)

- [https://github.com/sk1dish/ilo4-rce-vuln-scanner](https://github.com/sk1dish/ilo4-rce-vuln-scanner) :  ![starts](https://img.shields.io/github/stars/sk1dish/ilo4-rce-vuln-scanner.svg) ![forks](https://img.shields.io/github/forks/sk1dish/ilo4-rce-vuln-scanner.svg)

## CVE-2017-11907
 Internet Explorer in Microsoft Windows 7 SP1, Windows Server 2008 and R2 SP1, Windows 8.1 and Windows RT 8.1, Windows Server 2012 and R2, Windows 10 Gold, 1511, 1607, 1703, 1709, and Windows Server 2016 allows an attacker to gain the same user rights as the current user, due to how Internet Explorer handles objects in memory, aka "Scripting Engine Memory Corruption Vulnerability". This CVE ID is unique from CVE-2017-11886, CVE-2017-11889, CVE-2017-11890, CVE-2017-11893, CVE-2017-11894, CVE-2017-11895, CVE-2017-11901, CVE-2017-11903, CVE-2017-11905, CVE-2017-11905, CVE-2017-11908, CVE-2017-11909, CVE-2017-11910, CVE-2017-11911, CVE-2017-11912, CVE-2017-11913, CVE-2017-11914, CVE-2017-11916, CVE-2017-11918, and CVE-2017-11930.



- [https://github.com/AV1080p/CVE-2017-11907](https://github.com/AV1080p/CVE-2017-11907) :  ![starts](https://img.shields.io/github/stars/AV1080p/CVE-2017-11907.svg) ![forks](https://img.shields.io/github/forks/AV1080p/CVE-2017-11907.svg)

## CVE-2017-11519
 passwd_recovery.lua on the TP-Link Archer C9(UN)_V2_160517 allows an attacker to reset the admin password by leveraging a predictable random number generator seed. This is fixed in C9(UN)_V2_170511.



- [https://github.com/vakzz/tplink-CVE-2017-11519](https://github.com/vakzz/tplink-CVE-2017-11519) :  ![starts](https://img.shields.io/github/stars/vakzz/tplink-CVE-2017-11519.svg) ![forks](https://img.shields.io/github/forks/vakzz/tplink-CVE-2017-11519.svg)

## CVE-2017-11503
 PHPMailer 5.2.23 has XSS in the "From Email Address" and "To Email Address" fields of code_generator.php.



- [https://github.com/wizardafric/download](https://github.com/wizardafric/download) :  ![starts](https://img.shields.io/github/stars/wizardafric/download.svg) ![forks](https://img.shields.io/github/forks/wizardafric/download.svg)

## CVE-2017-11366
 components/filemanager/class.filemanager.php in Codiad before 2.8.4 is vulnerable to remote command execution because shell commands can be embedded in parameter values, as demonstrated by search_file_type.



- [https://github.com/hidog123/Codiad-CVE-2018-14009](https://github.com/hidog123/Codiad-CVE-2018-14009) :  ![starts](https://img.shields.io/github/stars/hidog123/Codiad-CVE-2018-14009.svg) ![forks](https://img.shields.io/github/forks/hidog123/Codiad-CVE-2018-14009.svg)

## CVE-2017-11176
 The mq_notify function in the Linux kernel through 4.11.9 does not set the sock pointer to NULL upon entry into the retry logic. During a user-space close of a Netlink socket, it allows attackers to cause a denial of service (use-after-free) or possibly have unspecified other impact.



- [https://github.com/lexfo/cve-2017-11176](https://github.com/lexfo/cve-2017-11176) :  ![starts](https://img.shields.io/github/stars/lexfo/cve-2017-11176.svg) ![forks](https://img.shields.io/github/forks/lexfo/cve-2017-11176.svg)

- [https://github.com/c3r34lk1ll3r/CVE-2017-11176](https://github.com/c3r34lk1ll3r/CVE-2017-11176) :  ![starts](https://img.shields.io/github/stars/c3r34lk1ll3r/CVE-2017-11176.svg) ![forks](https://img.shields.io/github/forks/c3r34lk1ll3r/CVE-2017-11176.svg)

- [https://github.com/Sama-Ayman-Mokhtar/CVE-2017-11176](https://github.com/Sama-Ayman-Mokhtar/CVE-2017-11176) :  ![starts](https://img.shields.io/github/stars/Sama-Ayman-Mokhtar/CVE-2017-11176.svg) ![forks](https://img.shields.io/github/forks/Sama-Ayman-Mokhtar/CVE-2017-11176.svg)

- [https://github.com/leonardo1101/cve-2017-11176](https://github.com/leonardo1101/cve-2017-11176) :  ![starts](https://img.shields.io/github/stars/leonardo1101/cve-2017-11176.svg) ![forks](https://img.shields.io/github/forks/leonardo1101/cve-2017-11176.svg)

- [https://github.com/Yanoro/CVE-2017-11176](https://github.com/Yanoro/CVE-2017-11176) :  ![starts](https://img.shields.io/github/stars/Yanoro/CVE-2017-11176.svg) ![forks](https://img.shields.io/github/forks/Yanoro/CVE-2017-11176.svg)

- [https://github.com/DoubleMice/cve-2017-11176](https://github.com/DoubleMice/cve-2017-11176) :  ![starts](https://img.shields.io/github/stars/DoubleMice/cve-2017-11176.svg) ![forks](https://img.shields.io/github/forks/DoubleMice/cve-2017-11176.svg)

## CVE-2017-11165
 dataTaker DT80 dEX 1.50.012 allows remote attackers to obtain sensitive credential and configuration information via a direct request for the /services/getFile.cmd?userfile=config.xml URI.



- [https://github.com/xymbiot-solution/CVE-2017-11165](https://github.com/xymbiot-solution/CVE-2017-11165) :  ![starts](https://img.shields.io/github/stars/xymbiot-solution/CVE-2017-11165.svg) ![forks](https://img.shields.io/github/forks/xymbiot-solution/CVE-2017-11165.svg)

## CVE-2017-11104
 Knot DNS before 2.4.5 and 2.5.x before 2.5.2 contains a flaw within the TSIG protocol implementation that would allow an attacker with a valid key name and algorithm to bypass TSIG authentication if no additional ACL restrictions are set, because of an improper TSIG validity period check.



- [https://github.com/saaph/CVE-2017-3143](https://github.com/saaph/CVE-2017-3143) :  ![starts](https://img.shields.io/github/stars/saaph/CVE-2017-3143.svg) ![forks](https://img.shields.io/github/forks/saaph/CVE-2017-3143.svg)

## CVE-2017-10797
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem.  When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/n4xh4ck5/CVE-2017-10797](https://github.com/n4xh4ck5/CVE-2017-10797) :  ![starts](https://img.shields.io/github/stars/n4xh4ck5/CVE-2017-10797.svg) ![forks](https://img.shields.io/github/forks/n4xh4ck5/CVE-2017-10797.svg)

## CVE-2017-10617
 The ifmap service that comes bundled with Contrail has an XML External Entity (XXE) vulnerability that may allow an attacker to retrieve sensitive system files. Affected releases are Juniper Networks Contrail 2.2 prior to 2.21.4; 3.0 prior to 3.0.3.4; 3.1 prior to 3.1.4.0; 3.2 prior to 3.2.5.0. CVE-2017-10616 and CVE-2017-10617 can be chained together and have a combined CVSSv3 score of 5.8 (AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N).



- [https://github.com/gteissier/CVE-2017-10617](https://github.com/gteissier/CVE-2017-10617) :  ![starts](https://img.shields.io/github/stars/gteissier/CVE-2017-10617.svg) ![forks](https://img.shields.io/github/forks/gteissier/CVE-2017-10617.svg)

## CVE-2017-10417
 Vulnerability in the Oracle Advanced Outbound Telephony component of Oracle E-Business Suite (subcomponent: Setup and Configuration). Supported versions that are affected are 12.2.3, 12.2.4, 12.2.5, 12.2.6 and 12.2.7. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Advanced Outbound Telephony. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle Advanced Outbound Telephony, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle Advanced Outbound Telephony accessible data as well as unauthorized update, insert or delete access to some of Oracle Advanced Outbound Telephony accessible data. CVSS 3.0 Base Score 8.2 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N).



- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)

## CVE-2017-10416
 Vulnerability in the Oracle Advanced Outbound Telephony component of Oracle E-Business Suite (subcomponent: Setup and Configuration). Supported versions that are affected are 12.2.3, 12.2.4, 12.2.5, 12.2.6 and 12.2.7. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Advanced Outbound Telephony. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle Advanced Outbound Telephony, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle Advanced Outbound Telephony accessible data as well as unauthorized update, insert or delete access to some of Oracle Advanced Outbound Telephony accessible data. CVSS 3.0 Base Score 8.2 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N).



- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)

## CVE-2017-10271
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Security). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.1.0 and 12.2.1.2.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 7.5 (Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H).



- [https://github.com/0xn0ne/weblogicScanner](https://github.com/0xn0ne/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/0xn0ne/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/0xn0ne/weblogicScanner.svg)

- [https://github.com/shack2/javaserializetools](https://github.com/shack2/javaserializetools) :  ![starts](https://img.shields.io/github/stars/shack2/javaserializetools.svg) ![forks](https://img.shields.io/github/forks/shack2/javaserializetools.svg)

- [https://github.com/c0mmand3rOpSec/CVE-2017-10271](https://github.com/c0mmand3rOpSec/CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/c0mmand3rOpSec/CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/c0mmand3rOpSec/CVE-2017-10271.svg)

- [https://github.com/kkirsche/CVE-2017-10271](https://github.com/kkirsche/CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/kkirsche/CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/kkirsche/CVE-2017-10271.svg)

- [https://github.com/7kbstorm/WebLogic_CNVD_C2019_48814](https://github.com/7kbstorm/WebLogic_CNVD_C2019_48814) :  ![starts](https://img.shields.io/github/stars/7kbstorm/WebLogic_CNVD_C2019_48814.svg) ![forks](https://img.shields.io/github/forks/7kbstorm/WebLogic_CNVD_C2019_48814.svg)

- [https://github.com/SkyBlueEternal/CNVD-C-2019-48814-CNNVD-201904-961](https://github.com/SkyBlueEternal/CNVD-C-2019-48814-CNNVD-201904-961) :  ![starts](https://img.shields.io/github/stars/SkyBlueEternal/CNVD-C-2019-48814-CNNVD-201904-961.svg) ![forks](https://img.shields.io/github/forks/SkyBlueEternal/CNVD-C-2019-48814-CNNVD-201904-961.svg)

- [https://github.com/1337g/CVE-2017-10271](https://github.com/1337g/CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/1337g/CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/1337g/CVE-2017-10271.svg)

- [https://github.com/Cymmetria/weblogic_honeypot](https://github.com/Cymmetria/weblogic_honeypot) :  ![starts](https://img.shields.io/github/stars/Cymmetria/weblogic_honeypot.svg) ![forks](https://img.shields.io/github/forks/Cymmetria/weblogic_honeypot.svg)

- [https://github.com/Luffin/CVE-2017-10271](https://github.com/Luffin/CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/Luffin/CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/Luffin/CVE-2017-10271.svg)

- [https://github.com/s3xy/CVE-2017-10271](https://github.com/s3xy/CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/s3xy/CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/s3xy/CVE-2017-10271.svg)

- [https://github.com/bigsizeme/weblogic-XMLDecoder](https://github.com/bigsizeme/weblogic-XMLDecoder) :  ![starts](https://img.shields.io/github/stars/bigsizeme/weblogic-XMLDecoder.svg) ![forks](https://img.shields.io/github/forks/bigsizeme/weblogic-XMLDecoder.svg)

- [https://github.com/ETOCheney/JavaDeserialization](https://github.com/ETOCheney/JavaDeserialization) :  ![starts](https://img.shields.io/github/stars/ETOCheney/JavaDeserialization.svg) ![forks](https://img.shields.io/github/forks/ETOCheney/JavaDeserialization.svg)

- [https://github.com/SuperHacker-liuan/cve-2017-10271-poc](https://github.com/SuperHacker-liuan/cve-2017-10271-poc) :  ![starts](https://img.shields.io/github/stars/SuperHacker-liuan/cve-2017-10271-poc.svg) ![forks](https://img.shields.io/github/forks/SuperHacker-liuan/cve-2017-10271-poc.svg)

- [https://github.com/pssss/CVE-2017-10271](https://github.com/pssss/CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/pssss/CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/pssss/CVE-2017-10271.svg)

- [https://github.com/kbsec/Weblogic_Wsat_RCE](https://github.com/kbsec/Weblogic_Wsat_RCE) :  ![starts](https://img.shields.io/github/stars/kbsec/Weblogic_Wsat_RCE.svg) ![forks](https://img.shields.io/github/forks/kbsec/Weblogic_Wsat_RCE.svg)

- [https://github.com/ZH3FENG/PoCs-Weblogic_2017_10271](https://github.com/ZH3FENG/PoCs-Weblogic_2017_10271) :  ![starts](https://img.shields.io/github/stars/ZH3FENG/PoCs-Weblogic_2017_10271.svg) ![forks](https://img.shields.io/github/forks/ZH3FENG/PoCs-Weblogic_2017_10271.svg)

- [https://github.com/cjjduck/weblogic_wls_wsat_rce](https://github.com/cjjduck/weblogic_wls_wsat_rce) :  ![starts](https://img.shields.io/github/stars/cjjduck/weblogic_wls_wsat_rce.svg) ![forks](https://img.shields.io/github/forks/cjjduck/weblogic_wls_wsat_rce.svg)

- [https://github.com/pizza-power/weblogic-CVE-2019-2729-POC](https://github.com/pizza-power/weblogic-CVE-2019-2729-POC) :  ![starts](https://img.shields.io/github/stars/pizza-power/weblogic-CVE-2019-2729-POC.svg) ![forks](https://img.shields.io/github/forks/pizza-power/weblogic-CVE-2019-2729-POC.svg)

- [https://github.com/Al1ex/CVE-2017-10271](https://github.com/Al1ex/CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2017-10271.svg)

- [https://github.com/ianxtianxt/-CVE-2017-10271-](https://github.com/ianxtianxt/-CVE-2017-10271-) :  ![starts](https://img.shields.io/github/stars/ianxtianxt/-CVE-2017-10271-.svg) ![forks](https://img.shields.io/github/forks/ianxtianxt/-CVE-2017-10271-.svg)

- [https://github.com/rambleZzz/weblogic_CVE_2017_10271](https://github.com/rambleZzz/weblogic_CVE_2017_10271) :  ![starts](https://img.shields.io/github/stars/rambleZzz/weblogic_CVE_2017_10271.svg) ![forks](https://img.shields.io/github/forks/rambleZzz/weblogic_CVE_2017_10271.svg)

- [https://github.com/XHSecurity/Oracle-WebLogic-CVE-2017-10271](https://github.com/XHSecurity/Oracle-WebLogic-CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/XHSecurity/Oracle-WebLogic-CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/XHSecurity/Oracle-WebLogic-CVE-2017-10271.svg)

- [https://github.com/JackyTsuuuy/weblogic_wls_rce_poc-exp](https://github.com/JackyTsuuuy/weblogic_wls_rce_poc-exp) :  ![starts](https://img.shields.io/github/stars/JackyTsuuuy/weblogic_wls_rce_poc-exp.svg) ![forks](https://img.shields.io/github/forks/JackyTsuuuy/weblogic_wls_rce_poc-exp.svg)

- [https://github.com/lonehand/Oracle-WebLogic-CVE-2017-10271-master](https://github.com/lonehand/Oracle-WebLogic-CVE-2017-10271-master) :  ![starts](https://img.shields.io/github/stars/lonehand/Oracle-WebLogic-CVE-2017-10271-master.svg) ![forks](https://img.shields.io/github/forks/lonehand/Oracle-WebLogic-CVE-2017-10271-master.svg)

- [https://github.com/Yuusuke4/WebLogic_CNVD_C_2019_48814](https://github.com/Yuusuke4/WebLogic_CNVD_C_2019_48814) :  ![starts](https://img.shields.io/github/stars/Yuusuke4/WebLogic_CNVD_C_2019_48814.svg) ![forks](https://img.shields.io/github/forks/Yuusuke4/WebLogic_CNVD_C_2019_48814.svg)

- [https://github.com/peterpeter228/Oracle-WebLogic-CVE-2017-10271](https://github.com/peterpeter228/Oracle-WebLogic-CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/peterpeter228/Oracle-WebLogic-CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/peterpeter228/Oracle-WebLogic-CVE-2017-10271.svg)

- [https://github.com/testwc/CVE-2017-10271](https://github.com/testwc/CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/testwc/CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/testwc/CVE-2017-10271.svg)

- [https://github.com/cved-sources/cve-2017-10271](https://github.com/cved-sources/cve-2017-10271) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2017-10271.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2017-10271.svg)

- [https://github.com/r4b3rt/CVE-2017-10271](https://github.com/r4b3rt/CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/r4b3rt/CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/r4b3rt/CVE-2017-10271.svg)

- [https://github.com/KKsdall/7kbstormq](https://github.com/KKsdall/7kbstormq) :  ![starts](https://img.shields.io/github/stars/KKsdall/7kbstormq.svg) ![forks](https://img.shields.io/github/forks/KKsdall/7kbstormq.svg)

## CVE-2017-9830
 Remote Code Execution is possible in Code42 CrashPlan 5.4.x via the org.apache.commons.ssl.rmi.DateRMI Java class, because (upon instantiation) it creates an RMI server that listens on a TCP port and deserializes objects sent by TCP clients.



- [https://github.com/securifera/CVE-2017-9830](https://github.com/securifera/CVE-2017-9830) :  ![starts](https://img.shields.io/github/stars/securifera/CVE-2017-9830.svg) ![forks](https://img.shields.io/github/forks/securifera/CVE-2017-9830.svg)

## CVE-2017-9627
 An Uncontrolled Resource Consumption issue was discovered in Schneider Electric Wonderware ArchestrA Logger, versions 2017.426.2307.1 and prior. The uncontrolled resource consumption vulnerability could allow an attacker to exhaust the memory resources of the machine, causing a denial of service.



- [https://github.com/USSCltd/aaLogger](https://github.com/USSCltd/aaLogger) :  ![starts](https://img.shields.io/github/stars/USSCltd/aaLogger.svg) ![forks](https://img.shields.io/github/forks/USSCltd/aaLogger.svg)

## CVE-2017-9609
 Cross-site scripting (XSS) vulnerability in Blackcat CMS 1.2 allows remote authenticated users to inject arbitrary web script or HTML via the map_language parameter to backend/pages/lang_settings.php.



- [https://github.com/faizzaidi/Blackcat-cms-v1.2-xss-POC-by-Provensec-llc](https://github.com/faizzaidi/Blackcat-cms-v1.2-xss-POC-by-Provensec-llc) :  ![starts](https://img.shields.io/github/stars/faizzaidi/Blackcat-cms-v1.2-xss-POC-by-Provensec-llc.svg) ![forks](https://img.shields.io/github/forks/faizzaidi/Blackcat-cms-v1.2-xss-POC-by-Provensec-llc.svg)

## CVE-2017-9097
 In Anti-Web through 3.8.7, as used on NetBiter FGW200 devices through 3.21.2, WS100 devices through 3.30.5, EC150 devices through 1.40.0, WS200 devices through 3.30.4, EC250 devices through 1.40.0, and other products, an LFI vulnerability allows a remote attacker to read or modify files through a path traversal technique, as demonstrated by reading the password file, or using the template parameter to cgi-bin/write.cgi to write to an arbitrary file.



- [https://github.com/MDudek-ICS/AntiWeb_testing-Suite](https://github.com/MDudek-ICS/AntiWeb_testing-Suite) :  ![starts](https://img.shields.io/github/stars/MDudek-ICS/AntiWeb_testing-Suite.svg) ![forks](https://img.shields.io/github/forks/MDudek-ICS/AntiWeb_testing-Suite.svg)

## CVE-2017-9077
 The tcp_v6_syn_recv_sock function in net/ipv6/tcp_ipv6.c in the Linux kernel through 4.11.1 mishandles inheritance, which allows local users to cause a denial of service or possibly have unspecified other impact via crafted system calls, a related issue to CVE-2017-8890.



- [https://github.com/idhyt/androotzf](https://github.com/idhyt/androotzf) :  ![starts](https://img.shields.io/github/stars/idhyt/androotzf.svg) ![forks](https://img.shields.io/github/forks/idhyt/androotzf.svg)

## CVE-2017-8917
 SQL injection vulnerability in Joomla! 3.7.x before 3.7.1 allows attackers to execute arbitrary SQL commands via unspecified vectors.



- [https://github.com/stefanlucas/Exploit-Joomla](https://github.com/stefanlucas/Exploit-Joomla) :  ![starts](https://img.shields.io/github/stars/stefanlucas/Exploit-Joomla.svg) ![forks](https://img.shields.io/github/forks/stefanlucas/Exploit-Joomla.svg)

- [https://github.com/brianwrf/Joomla3.7-SQLi-CVE-2017-8917](https://github.com/brianwrf/Joomla3.7-SQLi-CVE-2017-8917) :  ![starts](https://img.shields.io/github/stars/brianwrf/Joomla3.7-SQLi-CVE-2017-8917.svg) ![forks](https://img.shields.io/github/forks/brianwrf/Joomla3.7-SQLi-CVE-2017-8917.svg)

- [https://github.com/AkuCyberSec/CVE-2017-8917-Joomla-370-SQL-Injection](https://github.com/AkuCyberSec/CVE-2017-8917-Joomla-370-SQL-Injection) :  ![starts](https://img.shields.io/github/stars/AkuCyberSec/CVE-2017-8917-Joomla-370-SQL-Injection.svg) ![forks](https://img.shields.io/github/forks/AkuCyberSec/CVE-2017-8917-Joomla-370-SQL-Injection.svg)

- [https://github.com/xcalts/CVE-2017-8917](https://github.com/xcalts/CVE-2017-8917) :  ![starts](https://img.shields.io/github/stars/xcalts/CVE-2017-8917.svg) ![forks](https://img.shields.io/github/forks/xcalts/CVE-2017-8917.svg)

- [https://github.com/gmohlamo/CVE-2017-8917](https://github.com/gmohlamo/CVE-2017-8917) :  ![starts](https://img.shields.io/github/stars/gmohlamo/CVE-2017-8917.svg) ![forks](https://img.shields.io/github/forks/gmohlamo/CVE-2017-8917.svg)

- [https://github.com/cved-sources/cve-2017-8917](https://github.com/cved-sources/cve-2017-8917) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2017-8917.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2017-8917.svg)

- [https://github.com/Siopy/CVE-2017-8917](https://github.com/Siopy/CVE-2017-8917) :  ![starts](https://img.shields.io/github/stars/Siopy/CVE-2017-8917.svg) ![forks](https://img.shields.io/github/forks/Siopy/CVE-2017-8917.svg)

- [https://github.com/BaptisteContreras/CVE-2017-8917-Joomla](https://github.com/BaptisteContreras/CVE-2017-8917-Joomla) :  ![starts](https://img.shields.io/github/stars/BaptisteContreras/CVE-2017-8917-Joomla.svg) ![forks](https://img.shields.io/github/forks/BaptisteContreras/CVE-2017-8917-Joomla.svg)

- [https://github.com/ionutbaltariu/joomla_CVE-2017-8917](https://github.com/ionutbaltariu/joomla_CVE-2017-8917) :  ![starts](https://img.shields.io/github/stars/ionutbaltariu/joomla_CVE-2017-8917.svg) ![forks](https://img.shields.io/github/forks/ionutbaltariu/joomla_CVE-2017-8917.svg)

- [https://github.com/gloliveira1701/Joomblah](https://github.com/gloliveira1701/Joomblah) :  ![starts](https://img.shields.io/github/stars/gloliveira1701/Joomblah.svg) ![forks](https://img.shields.io/github/forks/gloliveira1701/Joomblah.svg)

## CVE-2017-8809
 api.php in MediaWiki before 1.27.4, 1.28.x before 1.28.3, and 1.29.x before 1.29.2 has a Reflected File Download vulnerability.



- [https://github.com/motikan2010/CVE-2017-8809_MediaWiki_RFD](https://github.com/motikan2010/CVE-2017-8809_MediaWiki_RFD) :  ![starts](https://img.shields.io/github/stars/motikan2010/CVE-2017-8809_MediaWiki_RFD.svg) ![forks](https://img.shields.io/github/forks/motikan2010/CVE-2017-8809_MediaWiki_RFD.svg)

## CVE-2017-8802
 Cross-site scripting (XSS) vulnerability in Zimbra Collaboration Suite (aka ZCS) before 8.8.0 Beta2 might allow remote attackers to inject arbitrary web script or HTML via vectors related to the "Show Snippet" functionality.



- [https://github.com/ozzi-/Zimbra-CVE-2017-8802-Hotifx](https://github.com/ozzi-/Zimbra-CVE-2017-8802-Hotifx) :  ![starts](https://img.shields.io/github/stars/ozzi-/Zimbra-CVE-2017-8802-Hotifx.svg) ![forks](https://img.shields.io/github/forks/ozzi-/Zimbra-CVE-2017-8802-Hotifx.svg)

## CVE-2017-8798
 Integer signedness error in MiniUPnP MiniUPnPc v1.4.20101221 through v2.0 allows remote attackers to cause a denial of service or possibly have unspecified other impact.



- [https://github.com/tintinweb/pub](https://github.com/tintinweb/pub) :  ![starts](https://img.shields.io/github/stars/tintinweb/pub.svg) ![forks](https://img.shields.io/github/forks/tintinweb/pub.svg)

## CVE-2017-8759
 Microsoft .NET Framework 2.0, 3.5, 3.5.1, 4.5.2, 4.6, 4.6.1, 4.6.2 and 4.7 allow an attacker to execute code remotely via a malicious document or application, aka ".NET Framework Remote Code Execution Vulnerability."



- [https://github.com/bhdresh/CVE-2017-8759](https://github.com/bhdresh/CVE-2017-8759) :  ![starts](https://img.shields.io/github/stars/bhdresh/CVE-2017-8759.svg) ![forks](https://img.shields.io/github/forks/bhdresh/CVE-2017-8759.svg)

- [https://github.com/Voulnet/CVE-2017-8759-Exploit-sample](https://github.com/Voulnet/CVE-2017-8759-Exploit-sample) :  ![starts](https://img.shields.io/github/stars/Voulnet/CVE-2017-8759-Exploit-sample.svg) ![forks](https://img.shields.io/github/forks/Voulnet/CVE-2017-8759-Exploit-sample.svg)

- [https://github.com/vysecurity/CVE-2017-8759](https://github.com/vysecurity/CVE-2017-8759) :  ![starts](https://img.shields.io/github/stars/vysecurity/CVE-2017-8759.svg) ![forks](https://img.shields.io/github/forks/vysecurity/CVE-2017-8759.svg)

- [https://github.com/nccgroup/CVE-2017-8759](https://github.com/nccgroup/CVE-2017-8759) :  ![starts](https://img.shields.io/github/stars/nccgroup/CVE-2017-8759.svg) ![forks](https://img.shields.io/github/forks/nccgroup/CVE-2017-8759.svg)

- [https://github.com/JonasUliana/CVE-2017-8759](https://github.com/JonasUliana/CVE-2017-8759) :  ![starts](https://img.shields.io/github/stars/JonasUliana/CVE-2017-8759.svg) ![forks](https://img.shields.io/github/forks/JonasUliana/CVE-2017-8759.svg)

- [https://github.com/jacobsoo/RTF-Cleaner](https://github.com/jacobsoo/RTF-Cleaner) :  ![starts](https://img.shields.io/github/stars/jacobsoo/RTF-Cleaner.svg) ![forks](https://img.shields.io/github/forks/jacobsoo/RTF-Cleaner.svg)

- [https://github.com/ashr/CVE-2017-8759-exploits](https://github.com/ashr/CVE-2017-8759-exploits) :  ![starts](https://img.shields.io/github/stars/ashr/CVE-2017-8759-exploits.svg) ![forks](https://img.shields.io/github/forks/ashr/CVE-2017-8759-exploits.svg)

- [https://github.com/homjxi0e/CVE-2017-8759_-SOAP_WSDL](https://github.com/homjxi0e/CVE-2017-8759_-SOAP_WSDL) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-8759_-SOAP_WSDL.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-8759_-SOAP_WSDL.svg)

- [https://github.com/BasuCert/CVE-2017-8759](https://github.com/BasuCert/CVE-2017-8759) :  ![starts](https://img.shields.io/github/stars/BasuCert/CVE-2017-8759.svg) ![forks](https://img.shields.io/github/forks/BasuCert/CVE-2017-8759.svg)

- [https://github.com/sythass/CVE-2017-8759](https://github.com/sythass/CVE-2017-8759) :  ![starts](https://img.shields.io/github/stars/sythass/CVE-2017-8759.svg) ![forks](https://img.shields.io/github/forks/sythass/CVE-2017-8759.svg)

- [https://github.com/ChaitanyaHaritash/CVE-2017-8759](https://github.com/ChaitanyaHaritash/CVE-2017-8759) :  ![starts](https://img.shields.io/github/stars/ChaitanyaHaritash/CVE-2017-8759.svg) ![forks](https://img.shields.io/github/forks/ChaitanyaHaritash/CVE-2017-8759.svg)

- [https://github.com/zhengkook/CVE-2017-8759](https://github.com/zhengkook/CVE-2017-8759) :  ![starts](https://img.shields.io/github/stars/zhengkook/CVE-2017-8759.svg) ![forks](https://img.shields.io/github/forks/zhengkook/CVE-2017-8759.svg)

- [https://github.com/adeljck/CVE-2017-8759](https://github.com/adeljck/CVE-2017-8759) :  ![starts](https://img.shields.io/github/stars/adeljck/CVE-2017-8759.svg) ![forks](https://img.shields.io/github/forks/adeljck/CVE-2017-8759.svg)

- [https://github.com/Winter3un/cve_2017_8759](https://github.com/Winter3un/cve_2017_8759) :  ![starts](https://img.shields.io/github/stars/Winter3un/cve_2017_8759.svg) ![forks](https://img.shields.io/github/forks/Winter3un/cve_2017_8759.svg)

- [https://github.com/l0n3rs/CVE-2017-8759](https://github.com/l0n3rs/CVE-2017-8759) :  ![starts](https://img.shields.io/github/stars/l0n3rs/CVE-2017-8759.svg) ![forks](https://img.shields.io/github/forks/l0n3rs/CVE-2017-8759.svg)

- [https://github.com/smashinu/CVE-2017-8759Expoit](https://github.com/smashinu/CVE-2017-8759Expoit) :  ![starts](https://img.shields.io/github/stars/smashinu/CVE-2017-8759Expoit.svg) ![forks](https://img.shields.io/github/forks/smashinu/CVE-2017-8759Expoit.svg)

- [https://github.com/tahisaad6/CVE-2017-8759-Exploit-sample2](https://github.com/tahisaad6/CVE-2017-8759-Exploit-sample2) :  ![starts](https://img.shields.io/github/stars/tahisaad6/CVE-2017-8759-Exploit-sample2.svg) ![forks](https://img.shields.io/github/forks/tahisaad6/CVE-2017-8759-Exploit-sample2.svg)

- [https://github.com/GayashanM/OHTS](https://github.com/GayashanM/OHTS) :  ![starts](https://img.shields.io/github/stars/GayashanM/OHTS.svg) ![forks](https://img.shields.io/github/forks/GayashanM/OHTS.svg)

- [https://github.com/varunsaru/SNP](https://github.com/varunsaru/SNP) :  ![starts](https://img.shields.io/github/stars/varunsaru/SNP.svg) ![forks](https://img.shields.io/github/forks/varunsaru/SNP.svg)

- [https://github.com/chefphenix25/vuln-rabilit-windows7](https://github.com/chefphenix25/vuln-rabilit-windows7) :  ![starts](https://img.shields.io/github/stars/chefphenix25/vuln-rabilit-windows7.svg) ![forks](https://img.shields.io/github/forks/chefphenix25/vuln-rabilit-windows7.svg)

## CVE-2017-8570
 Microsoft Office allows a remote code execution vulnerability due to the way that it handles objects in memory, aka "Microsoft Office Remote Code Execution Vulnerability". This CVE ID is unique from CVE-2017-0243.



- [https://github.com/rxwx/CVE-2017-8570](https://github.com/rxwx/CVE-2017-8570) :  ![starts](https://img.shields.io/github/stars/rxwx/CVE-2017-8570.svg) ![forks](https://img.shields.io/github/forks/rxwx/CVE-2017-8570.svg)

- [https://github.com/temesgeny/ppsx-file-generator](https://github.com/temesgeny/ppsx-file-generator) :  ![starts](https://img.shields.io/github/stars/temesgeny/ppsx-file-generator.svg) ![forks](https://img.shields.io/github/forks/temesgeny/ppsx-file-generator.svg)

- [https://github.com/SwordSheath/CVE-2017-8570](https://github.com/SwordSheath/CVE-2017-8570) :  ![starts](https://img.shields.io/github/stars/SwordSheath/CVE-2017-8570.svg) ![forks](https://img.shields.io/github/forks/SwordSheath/CVE-2017-8570.svg)

- [https://github.com/Drac0nids/CVE-2017-8570](https://github.com/Drac0nids/CVE-2017-8570) :  ![starts](https://img.shields.io/github/stars/Drac0nids/CVE-2017-8570.svg) ![forks](https://img.shields.io/github/forks/Drac0nids/CVE-2017-8570.svg)

- [https://github.com/erfze/CVE-2017-8570](https://github.com/erfze/CVE-2017-8570) :  ![starts](https://img.shields.io/github/stars/erfze/CVE-2017-8570.svg) ![forks](https://img.shields.io/github/forks/erfze/CVE-2017-8570.svg)

- [https://github.com/MaxSecurity/Office-CVE-2017-8570](https://github.com/MaxSecurity/Office-CVE-2017-8570) :  ![starts](https://img.shields.io/github/stars/MaxSecurity/Office-CVE-2017-8570.svg) ![forks](https://img.shields.io/github/forks/MaxSecurity/Office-CVE-2017-8570.svg)

- [https://github.com/sasqwatch/CVE-2017-8570](https://github.com/sasqwatch/CVE-2017-8570) :  ![starts](https://img.shields.io/github/stars/sasqwatch/CVE-2017-8570.svg) ![forks](https://img.shields.io/github/forks/sasqwatch/CVE-2017-8570.svg)

- [https://github.com/erfze/CVE-2017-0261](https://github.com/erfze/CVE-2017-0261) :  ![starts](https://img.shields.io/github/stars/erfze/CVE-2017-0261.svg) ![forks](https://img.shields.io/github/forks/erfze/CVE-2017-0261.svg)

## CVE-2017-8543
 Microsoft Windows XP SP3, Windows XP x64 XP2, Windows Server 2003 SP2, Windows Vista, Windows 7 SP1, Windows Server 2008 SP2 and R2 SP1, Windows 8, Windows 8.1 and Windows RT 8.1, Windows Server 2012 and R2, Windows 10 Gold, 1511, 1607, and 1703, and Windows Server 2016 allow an attacker to take control of the affected system when Windows Search fails to handle objects in memory, aka "Windows Search Remote Code Execution Vulnerability".



- [https://github.com/americanhanko/windows-security-cve-2017-8543](https://github.com/americanhanko/windows-security-cve-2017-8543) :  ![starts](https://img.shields.io/github/stars/americanhanko/windows-security-cve-2017-8543.svg) ![forks](https://img.shields.io/github/forks/americanhanko/windows-security-cve-2017-8543.svg)

## CVE-2017-8486
 Microsoft Windows 7 SP1, Windows Server 2008 SP2 and R2 SP1, Windows 8.1 and Windows RT 8.1, Windows Server 2012 and R2, Windows 10 Gold, 1511, 1607, 1703, and Windows Server 2016 allows an information disclosure due to the way it handles objects in memory, aka "Win32k Information Disclosure Vulnerability".



- [https://github.com/doudouhala/CVE-2017-8464-exp-generator](https://github.com/doudouhala/CVE-2017-8464-exp-generator) :  ![starts](https://img.shields.io/github/stars/doudouhala/CVE-2017-8464-exp-generator.svg) ![forks](https://img.shields.io/github/forks/doudouhala/CVE-2017-8464-exp-generator.svg)

## CVE-2017-8464
 Windows Shell in Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, 1703, and Windows Server 2016 allows local users or remote attackers to execute arbitrary code via a crafted .LNK file, which is not properly handled during icon display in Windows Explorer or any other application that parses the icon of the shortcut. aka "LNK Remote Code Execution Vulnerability."



- [https://github.com/3gstudent/CVE-2017-8464-EXP](https://github.com/3gstudent/CVE-2017-8464-EXP) :  ![starts](https://img.shields.io/github/stars/3gstudent/CVE-2017-8464-EXP.svg) ![forks](https://img.shields.io/github/forks/3gstudent/CVE-2017-8464-EXP.svg)

- [https://github.com/doudouhala/CVE-2017-8464-exp-generator](https://github.com/doudouhala/CVE-2017-8464-exp-generator) :  ![starts](https://img.shields.io/github/stars/doudouhala/CVE-2017-8464-exp-generator.svg) ![forks](https://img.shields.io/github/forks/doudouhala/CVE-2017-8464-exp-generator.svg)

- [https://github.com/TrG-1999/DetectPacket-CVE-2017-8464](https://github.com/TrG-1999/DetectPacket-CVE-2017-8464) :  ![starts](https://img.shields.io/github/stars/TrG-1999/DetectPacket-CVE-2017-8464.svg) ![forks](https://img.shields.io/github/forks/TrG-1999/DetectPacket-CVE-2017-8464.svg)

- [https://github.com/Elm0D/CVE-2017-8464](https://github.com/Elm0D/CVE-2017-8464) :  ![starts](https://img.shields.io/github/stars/Elm0D/CVE-2017-8464.svg) ![forks](https://img.shields.io/github/forks/Elm0D/CVE-2017-8464.svg)

- [https://github.com/xssfile/CVE-2017-8464-EXP](https://github.com/xssfile/CVE-2017-8464-EXP) :  ![starts](https://img.shields.io/github/stars/xssfile/CVE-2017-8464-EXP.svg) ![forks](https://img.shields.io/github/forks/xssfile/CVE-2017-8464-EXP.svg)

- [https://github.com/X-Vector/usbhijacking](https://github.com/X-Vector/usbhijacking) :  ![starts](https://img.shields.io/github/stars/X-Vector/usbhijacking.svg) ![forks](https://img.shields.io/github/forks/X-Vector/usbhijacking.svg)

- [https://github.com/TieuLong21Prosper/Detect-CVE-2017-8464](https://github.com/TieuLong21Prosper/Detect-CVE-2017-8464) :  ![starts](https://img.shields.io/github/stars/TieuLong21Prosper/Detect-CVE-2017-8464.svg) ![forks](https://img.shields.io/github/forks/TieuLong21Prosper/Detect-CVE-2017-8464.svg)

- [https://github.com/tuankiethkt020/Phat-hien-CVE-2017-8464](https://github.com/tuankiethkt020/Phat-hien-CVE-2017-8464) :  ![starts](https://img.shields.io/github/stars/tuankiethkt020/Phat-hien-CVE-2017-8464.svg) ![forks](https://img.shields.io/github/forks/tuankiethkt020/Phat-hien-CVE-2017-8464.svg)

## CVE-2017-8386
 git-shell in git before 2.4.12, 2.5.x before 2.5.6, 2.6.x before 2.6.7, 2.7.x before 2.7.5, 2.8.x before 2.8.5, 2.9.x before 2.9.4, 2.10.x before 2.10.3, 2.11.x before 2.11.2, and 2.12.x before 2.12.3 might allow remote authenticated users to gain privileges via a repository name that starts with a - (dash) character.



- [https://github.com/suz1n/WHS3_vulhub](https://github.com/suz1n/WHS3_vulhub) :  ![starts](https://img.shields.io/github/stars/suz1n/WHS3_vulhub.svg) ![forks](https://img.shields.io/github/forks/suz1n/WHS3_vulhub.svg)

## CVE-2017-8056
 WatchGuard Fireware v11.12.1 and earlier mishandles requests referring to an XML External Entity (XXE), in the XML-RPC agent. This causes the Firebox wgagent process to crash. This process crash ends all authenticated sessions to the Firebox, including management connections, and prevents new authenticated sessions until the process has recovered. The Firebox may also experience an overall degradation in performance while the wgagent process recovers. An attacker could continuously send XML-RPC requests that contain references to external entities to perform a limited Denial of Service (DoS) attack against an affected Firebox.



- [https://github.com/itzexploit/CVE-2017-8056](https://github.com/itzexploit/CVE-2017-8056) :  ![starts](https://img.shields.io/github/stars/itzexploit/CVE-2017-8056.svg) ![forks](https://img.shields.io/github/forks/itzexploit/CVE-2017-8056.svg)

## CVE-2017-7921
 An Improper Authentication issue was discovered in Hikvision DS-2CD2xx2F-I Series V5.2.0 build 140721 to V5.4.0 build 160530, DS-2CD2xx0F-I Series V5.2.0 build 140721 to V5.4.0 Build 160401, DS-2CD2xx2FWD Series V5.3.1 build 150410 to V5.4.4 Build 161125, DS-2CD4x2xFWD Series V5.2.0 build 140721 to V5.4.0 Build 160414, DS-2CD4xx5 Series V5.2.0 build 140721 to V5.4.0 Build 160421, DS-2DFx Series V5.2.0 build 140805 to V5.4.5 Build 160928, and DS-2CD63xx Series V5.0.9 build 140305 to V5.3.5 Build 160106 devices. The improper authentication vulnerability occurs when an application does not adequately or correctly authenticate users. This may allow a malicious user to escalate his or her privileges on the system and gain access to sensitive information.



- [https://github.com/jorhelp/Ingram](https://github.com/jorhelp/Ingram) :  ![starts](https://img.shields.io/github/stars/jorhelp/Ingram.svg) ![forks](https://img.shields.io/github/forks/jorhelp/Ingram.svg)

- [https://github.com/chrisjd20/hikvision_CVE-2017-7921_auth_bypass_config_decryptor](https://github.com/chrisjd20/hikvision_CVE-2017-7921_auth_bypass_config_decryptor) :  ![starts](https://img.shields.io/github/stars/chrisjd20/hikvision_CVE-2017-7921_auth_bypass_config_decryptor.svg) ![forks](https://img.shields.io/github/forks/chrisjd20/hikvision_CVE-2017-7921_auth_bypass_config_decryptor.svg)

- [https://github.com/JrDw0/CVE-2017-7921-EXP](https://github.com/JrDw0/CVE-2017-7921-EXP) :  ![starts](https://img.shields.io/github/stars/JrDw0/CVE-2017-7921-EXP.svg) ![forks](https://img.shields.io/github/forks/JrDw0/CVE-2017-7921-EXP.svg)

- [https://github.com/BurnyMcDull/CVE-2017-7921](https://github.com/BurnyMcDull/CVE-2017-7921) :  ![starts](https://img.shields.io/github/stars/BurnyMcDull/CVE-2017-7921.svg) ![forks](https://img.shields.io/github/forks/BurnyMcDull/CVE-2017-7921.svg)

- [https://github.com/K3ysTr0K3R/CVE-2017-7921-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2017-7921-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2017-7921-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2017-7921-EXPLOIT.svg)

- [https://github.com/MisakaMikato/cve-2017-7921-golang](https://github.com/MisakaMikato/cve-2017-7921-golang) :  ![starts](https://img.shields.io/github/stars/MisakaMikato/cve-2017-7921-golang.svg) ![forks](https://img.shields.io/github/forks/MisakaMikato/cve-2017-7921-golang.svg)

- [https://github.com/201646613/CVE-2017-7921](https://github.com/201646613/CVE-2017-7921) :  ![starts](https://img.shields.io/github/stars/201646613/CVE-2017-7921.svg) ![forks](https://img.shields.io/github/forks/201646613/CVE-2017-7921.svg)

- [https://github.com/kooroshsanaei/HikVision-CVE-2017-7921](https://github.com/kooroshsanaei/HikVision-CVE-2017-7921) :  ![starts](https://img.shields.io/github/stars/kooroshsanaei/HikVision-CVE-2017-7921.svg) ![forks](https://img.shields.io/github/forks/kooroshsanaei/HikVision-CVE-2017-7921.svg)

- [https://github.com/yousouf-Tasfin/cve-2017-7921-Mass-Exploit](https://github.com/yousouf-Tasfin/cve-2017-7921-Mass-Exploit) :  ![starts](https://img.shields.io/github/stars/yousouf-Tasfin/cve-2017-7921-Mass-Exploit.svg) ![forks](https://img.shields.io/github/forks/yousouf-Tasfin/cve-2017-7921-Mass-Exploit.svg)

- [https://github.com/D2550/CVE_2017_7921_EXP](https://github.com/D2550/CVE_2017_7921_EXP) :  ![starts](https://img.shields.io/github/stars/D2550/CVE_2017_7921_EXP.svg) ![forks](https://img.shields.io/github/forks/D2550/CVE_2017_7921_EXP.svg)

- [https://github.com/aengussong/hikvision_probe](https://github.com/aengussong/hikvision_probe) :  ![starts](https://img.shields.io/github/stars/aengussong/hikvision_probe.svg) ![forks](https://img.shields.io/github/forks/aengussong/hikvision_probe.svg)

- [https://github.com/krypton612/hikivision](https://github.com/krypton612/hikivision) :  ![starts](https://img.shields.io/github/stars/krypton612/hikivision.svg) ![forks](https://img.shields.io/github/forks/krypton612/hikivision.svg)

- [https://github.com/GabrielAvls/CVE-2017-7921](https://github.com/GabrielAvls/CVE-2017-7921) :  ![starts](https://img.shields.io/github/stars/GabrielAvls/CVE-2017-7921.svg) ![forks](https://img.shields.io/github/forks/GabrielAvls/CVE-2017-7921.svg)

- [https://github.com/b3pwn3d/CVE-2017-7921](https://github.com/b3pwn3d/CVE-2017-7921) :  ![starts](https://img.shields.io/github/stars/b3pwn3d/CVE-2017-7921.svg) ![forks](https://img.shields.io/github/forks/b3pwn3d/CVE-2017-7921.svg)

- [https://github.com/inj3ction/CVE-2017-7921-EXP](https://github.com/inj3ction/CVE-2017-7921-EXP) :  ![starts](https://img.shields.io/github/stars/inj3ction/CVE-2017-7921-EXP.svg) ![forks](https://img.shields.io/github/forks/inj3ction/CVE-2017-7921-EXP.svg)

- [https://github.com/initon/Hikvision---CVE-2017-7921](https://github.com/initon/Hikvision---CVE-2017-7921) :  ![starts](https://img.shields.io/github/stars/initon/Hikvision---CVE-2017-7921.svg) ![forks](https://img.shields.io/github/forks/initon/Hikvision---CVE-2017-7921.svg)

- [https://github.com/p4tq/hikvision_CVE-2017-7921_auth_bypass_config_decryptor](https://github.com/p4tq/hikvision_CVE-2017-7921_auth_bypass_config_decryptor) :  ![starts](https://img.shields.io/github/stars/p4tq/hikvision_CVE-2017-7921_auth_bypass_config_decryptor.svg) ![forks](https://img.shields.io/github/forks/p4tq/hikvision_CVE-2017-7921_auth_bypass_config_decryptor.svg)

- [https://github.com/AnonkiGroup/AnonHik](https://github.com/AnonkiGroup/AnonHik) :  ![starts](https://img.shields.io/github/stars/AnonkiGroup/AnonHik.svg) ![forks](https://img.shields.io/github/forks/AnonkiGroup/AnonHik.svg)

## CVE-2017-7529
 Nginx versions since 0.5.6 up to and including 1.13.2 are vulnerable to integer overflow vulnerability in nginx range filter module resulting into leak of potentially sensitive information triggered by specially crafted request.



- [https://github.com/en0f/CVE-2017-7529_PoC](https://github.com/en0f/CVE-2017-7529_PoC) :  ![starts](https://img.shields.io/github/stars/en0f/CVE-2017-7529_PoC.svg) ![forks](https://img.shields.io/github/forks/en0f/CVE-2017-7529_PoC.svg)

- [https://github.com/liusec/CVE-2017-7529](https://github.com/liusec/CVE-2017-7529) :  ![starts](https://img.shields.io/github/stars/liusec/CVE-2017-7529.svg) ![forks](https://img.shields.io/github/forks/liusec/CVE-2017-7529.svg)

- [https://github.com/gemboxteam/exploit-nginx-1.10.3](https://github.com/gemboxteam/exploit-nginx-1.10.3) :  ![starts](https://img.shields.io/github/stars/gemboxteam/exploit-nginx-1.10.3.svg) ![forks](https://img.shields.io/github/forks/gemboxteam/exploit-nginx-1.10.3.svg)

- [https://github.com/Shehzadcyber/CVE-2017-7529](https://github.com/Shehzadcyber/CVE-2017-7529) :  ![starts](https://img.shields.io/github/stars/Shehzadcyber/CVE-2017-7529.svg) ![forks](https://img.shields.io/github/forks/Shehzadcyber/CVE-2017-7529.svg)

- [https://github.com/MaxSecurity/CVE-2017-7529-POC](https://github.com/MaxSecurity/CVE-2017-7529-POC) :  ![starts](https://img.shields.io/github/stars/MaxSecurity/CVE-2017-7529-POC.svg) ![forks](https://img.shields.io/github/forks/MaxSecurity/CVE-2017-7529-POC.svg)

- [https://github.com/cyberharsh/nginx-CVE-2017-7529](https://github.com/cyberharsh/nginx-CVE-2017-7529) :  ![starts](https://img.shields.io/github/stars/cyberharsh/nginx-CVE-2017-7529.svg) ![forks](https://img.shields.io/github/forks/cyberharsh/nginx-CVE-2017-7529.svg)

- [https://github.com/mo3zj/Nginx-Remote-Integer-Overflow-Vulnerability](https://github.com/mo3zj/Nginx-Remote-Integer-Overflow-Vulnerability) :  ![starts](https://img.shields.io/github/stars/mo3zj/Nginx-Remote-Integer-Overflow-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/mo3zj/Nginx-Remote-Integer-Overflow-Vulnerability.svg)

- [https://github.com/SirEagIe/CVE-2017-7529](https://github.com/SirEagIe/CVE-2017-7529) :  ![starts](https://img.shields.io/github/stars/SirEagIe/CVE-2017-7529.svg) ![forks](https://img.shields.io/github/forks/SirEagIe/CVE-2017-7529.svg)

- [https://github.com/portfolio10/nginx](https://github.com/portfolio10/nginx) :  ![starts](https://img.shields.io/github/stars/portfolio10/nginx.svg) ![forks](https://img.shields.io/github/forks/portfolio10/nginx.svg)

- [https://github.com/cved-sources/cve-2017-7529](https://github.com/cved-sources/cve-2017-7529) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2017-7529.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2017-7529.svg)

- [https://github.com/Fenil2511/CVE-2017-7529-POC](https://github.com/Fenil2511/CVE-2017-7529-POC) :  ![starts](https://img.shields.io/github/stars/Fenil2511/CVE-2017-7529-POC.svg) ![forks](https://img.shields.io/github/forks/Fenil2511/CVE-2017-7529-POC.svg)

- [https://github.com/CalebFIN/EXP-CVE-2017-75](https://github.com/CalebFIN/EXP-CVE-2017-75) :  ![starts](https://img.shields.io/github/stars/CalebFIN/EXP-CVE-2017-75.svg) ![forks](https://img.shields.io/github/forks/CalebFIN/EXP-CVE-2017-75.svg)

- [https://github.com/cyberk1w1/CVE-2017-7529](https://github.com/cyberk1w1/CVE-2017-7529) :  ![starts](https://img.shields.io/github/stars/cyberk1w1/CVE-2017-7529.svg) ![forks](https://img.shields.io/github/forks/cyberk1w1/CVE-2017-7529.svg)

- [https://github.com/youngmin0104/CVE-2017-7529-](https://github.com/youngmin0104/CVE-2017-7529-) :  ![starts](https://img.shields.io/github/stars/youngmin0104/CVE-2017-7529-.svg) ![forks](https://img.shields.io/github/forks/youngmin0104/CVE-2017-7529-.svg)

- [https://github.com/coolman6942o/-Exploit-CVE-2017-7529](https://github.com/coolman6942o/-Exploit-CVE-2017-7529) :  ![starts](https://img.shields.io/github/stars/coolman6942o/-Exploit-CVE-2017-7529.svg) ![forks](https://img.shields.io/github/forks/coolman6942o/-Exploit-CVE-2017-7529.svg)

- [https://github.com/daehee/nginx-overflow](https://github.com/daehee/nginx-overflow) :  ![starts](https://img.shields.io/github/stars/daehee/nginx-overflow.svg) ![forks](https://img.shields.io/github/forks/daehee/nginx-overflow.svg)

- [https://github.com/fardeen-ahmed/Remote-Integer-Overflow-Vulnerability](https://github.com/fardeen-ahmed/Remote-Integer-Overflow-Vulnerability) :  ![starts](https://img.shields.io/github/stars/fardeen-ahmed/Remote-Integer-Overflow-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/fardeen-ahmed/Remote-Integer-Overflow-Vulnerability.svg)

- [https://github.com/fu2x2000/CVE-2017-7529-Nginx---Remote-Integer-Overflow-Exploit](https://github.com/fu2x2000/CVE-2017-7529-Nginx---Remote-Integer-Overflow-Exploit) :  ![starts](https://img.shields.io/github/stars/fu2x2000/CVE-2017-7529-Nginx---Remote-Integer-Overflow-Exploit.svg) ![forks](https://img.shields.io/github/forks/fu2x2000/CVE-2017-7529-Nginx---Remote-Integer-Overflow-Exploit.svg)

- [https://github.com/devansh3008/Cve_Finder_2017-7529](https://github.com/devansh3008/Cve_Finder_2017-7529) :  ![starts](https://img.shields.io/github/stars/devansh3008/Cve_Finder_2017-7529.svg) ![forks](https://img.shields.io/github/forks/devansh3008/Cve_Finder_2017-7529.svg)

## CVE-2017-7376
 Buffer overflow in libxml2 allows remote attackers to execute arbitrary code by leveraging an incorrect limit for port values when handling redirects.



- [https://github.com/brahmstaedt/libxml2-exploit](https://github.com/brahmstaedt/libxml2-exploit) :  ![starts](https://img.shields.io/github/stars/brahmstaedt/libxml2-exploit.svg) ![forks](https://img.shields.io/github/forks/brahmstaedt/libxml2-exploit.svg)

## CVE-2017-7374
 Use-after-free vulnerability in fs/crypto/ in the Linux kernel before 4.10.7 allows local users to cause a denial of service (NULL pointer dereference) or possibly gain privileges by revoking keyring keys being used for ext4, f2fs, or ubifs encryption, causing cryptographic transform objects to be freed prematurely.



- [https://github.com/ww9210/cve-2017-7374](https://github.com/ww9210/cve-2017-7374) :  ![starts](https://img.shields.io/github/stars/ww9210/cve-2017-7374.svg) ![forks](https://img.shields.io/github/forks/ww9210/cve-2017-7374.svg)

## CVE-2017-7358
 In LightDM through 1.22.0, a directory traversal issue in debian/guest-account.sh allows local attackers to own arbitrary directory path locations and escalate privileges to root when the guest user logs out.



- [https://github.com/JonPichel/CVE-2017-7358](https://github.com/JonPichel/CVE-2017-7358) :  ![starts](https://img.shields.io/github/stars/JonPichel/CVE-2017-7358.svg) ![forks](https://img.shields.io/github/forks/JonPichel/CVE-2017-7358.svg)

## CVE-2017-7038
 A DOMParser XSS issue was discovered in certain Apple products. iOS before 10.3.3 is affected. Safari before 10.1.2 is affected. tvOS before 10.2.2 is affected. The issue involves the "WebKit" component.



- [https://github.com/ansjdnakjdnajkd/CVE-2017-7038](https://github.com/ansjdnakjdnajkd/CVE-2017-7038) :  ![starts](https://img.shields.io/github/stars/ansjdnakjdnajkd/CVE-2017-7038.svg) ![forks](https://img.shields.io/github/forks/ansjdnakjdnajkd/CVE-2017-7038.svg)

## CVE-2017-6950
 SAP GUI 7.2 through 7.5 allows remote attackers to bypass intended security policy restrictions and execute arbitrary code via a crafted ABAP code, aka SAP Security Note 2407616.



- [https://github.com/vah13/SAP_ransomware](https://github.com/vah13/SAP_ransomware) :  ![starts](https://img.shields.io/github/stars/vah13/SAP_ransomware.svg) ![forks](https://img.shields.io/github/forks/vah13/SAP_ransomware.svg)

## CVE-2017-6913
 Cross-site scripting (XSS) vulnerability in the Open-Xchange webmail before 7.6.3-rev28 allows remote attackers to inject arbitrary web script or HTML via the event attribute in a time tag.



- [https://github.com/gquere/CVE-2017-6913](https://github.com/gquere/CVE-2017-6913) :  ![starts](https://img.shields.io/github/stars/gquere/CVE-2017-6913.svg) ![forks](https://img.shields.io/github/forks/gquere/CVE-2017-6913.svg)

## CVE-2017-6736
 The Simple Network Management Protocol (SNMP) subsystem of Cisco IOS and IOS XE Software contains multiple vulnerabilities that could allow an authenticated, remote attacker to remotely execute code on an affected system or cause an affected system to reload. An attacker could exploit these vulnerabilities by sending a crafted SNMP packet to an affected system via IPv4 or IPv6. Only traffic directed to an affected system can be used to exploit these vulnerabilities.
 The vulnerabilities are due to a buffer overflow condition in the SNMP subsystem of the affected software. The vulnerabilities affect all versions of SNMP - Versions 1, 2c, and 3. To exploit these vulnerabilities via SNMP Version 2c or earlier, the attacker must know the SNMP read-only community string for the affected system. To exploit these vulnerabilities via SNMP Version 3, the attacker must have user credentials for the affected system. A successful exploit could allow the attacker to execute arbitrary code and obtain full control of the affected system or cause the affected system to reload.
 Customers are advised to apply the workaround as contained in the Workarounds section below. Fixed software information is available via the Cisco IOS Software Checker. All devices that have enabled SNMP and have not explicitly excluded the affected MIBs or OIDs should be considered vulnerable.
   There are workarounds that address these vulnerabilities.



- [https://github.com/garnetsunset/CiscoIOSSNMPToolkit](https://github.com/garnetsunset/CiscoIOSSNMPToolkit) :  ![starts](https://img.shields.io/github/stars/garnetsunset/CiscoIOSSNMPToolkit.svg) ![forks](https://img.shields.io/github/forks/garnetsunset/CiscoIOSSNMPToolkit.svg)

- [https://github.com/garnetsunset/CiscoSpectreTakeover](https://github.com/garnetsunset/CiscoSpectreTakeover) :  ![starts](https://img.shields.io/github/stars/garnetsunset/CiscoSpectreTakeover.svg) ![forks](https://img.shields.io/github/forks/garnetsunset/CiscoSpectreTakeover.svg)

## CVE-2017-6558
 iball Baton 150M iB-WRA150N v1 00000001 1.2.6 build 110401 Rel.47776n devices are prone to an authentication bypass vulnerability that allows remote attackers to view and modify administrative router settings by reading the HTML source code of the password.cgi file.



- [https://github.com/GemGeorge/iBall-UTStar-CVEChecker](https://github.com/GemGeorge/iBall-UTStar-CVEChecker) :  ![starts](https://img.shields.io/github/stars/GemGeorge/iBall-UTStar-CVEChecker.svg) ![forks](https://img.shields.io/github/forks/GemGeorge/iBall-UTStar-CVEChecker.svg)

## CVE-2017-5871
 Odoo Version = 8.0-20160726 and Version 9 is affected by: CWE-601: Open redirection. The impact is: obtain sensitive information (remote).



- [https://github.com/1337rokudenashi/CVE-2017-5871](https://github.com/1337rokudenashi/CVE-2017-5871) :  ![starts](https://img.shields.io/github/stars/1337rokudenashi/CVE-2017-5871.svg) ![forks](https://img.shields.io/github/forks/1337rokudenashi/CVE-2017-5871.svg)

## CVE-2017-5792
 A Remote Code Execution vulnerability in HPE Intelligent Management Center (iMC) PLAT version 7.3 E0504P2 was found.



- [https://github.com/scanfsec/HPE-iMC-7.3-RMI-Java-Deserialization](https://github.com/scanfsec/HPE-iMC-7.3-RMI-Java-Deserialization) :  ![starts](https://img.shields.io/github/stars/scanfsec/HPE-iMC-7.3-RMI-Java-Deserialization.svg) ![forks](https://img.shields.io/github/forks/scanfsec/HPE-iMC-7.3-RMI-Java-Deserialization.svg)

## CVE-2017-5753
 Systems with microprocessors utilizing speculative execution and branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis.



- [https://github.com/speed47/spectre-meltdown-checker](https://github.com/speed47/spectre-meltdown-checker) :  ![starts](https://img.shields.io/github/stars/speed47/spectre-meltdown-checker.svg) ![forks](https://img.shields.io/github/forks/speed47/spectre-meltdown-checker.svg)

- [https://github.com/nsacyber/Hardware-and-Firmware-Security-Guidance](https://github.com/nsacyber/Hardware-and-Firmware-Security-Guidance) :  ![starts](https://img.shields.io/github/stars/nsacyber/Hardware-and-Firmware-Security-Guidance.svg) ![forks](https://img.shields.io/github/forks/nsacyber/Hardware-and-Firmware-Security-Guidance.svg)

- [https://github.com/Eugnis/spectre-attack](https://github.com/Eugnis/spectre-attack) :  ![starts](https://img.shields.io/github/stars/Eugnis/spectre-attack.svg) ![forks](https://img.shields.io/github/forks/Eugnis/spectre-attack.svg)

- [https://github.com/mathse/meltdown-spectre-bios-list](https://github.com/mathse/meltdown-spectre-bios-list) :  ![starts](https://img.shields.io/github/stars/mathse/meltdown-spectre-bios-list.svg) ![forks](https://img.shields.io/github/forks/mathse/meltdown-spectre-bios-list.svg)

- [https://github.com/00052/spectre-attack-example](https://github.com/00052/spectre-attack-example) :  ![starts](https://img.shields.io/github/stars/00052/spectre-attack-example.svg) ![forks](https://img.shields.io/github/forks/00052/spectre-attack-example.svg)

- [https://github.com/neuhalje/presentation_meltdown_spectre](https://github.com/neuhalje/presentation_meltdown_spectre) :  ![starts](https://img.shields.io/github/stars/neuhalje/presentation_meltdown_spectre.svg) ![forks](https://img.shields.io/github/forks/neuhalje/presentation_meltdown_spectre.svg)

- [https://github.com/ixtal23/spectreScope](https://github.com/ixtal23/spectreScope) :  ![starts](https://img.shields.io/github/stars/ixtal23/spectreScope.svg) ![forks](https://img.shields.io/github/forks/ixtal23/spectreScope.svg)

- [https://github.com/garnetsunset/CiscoSpectreTakeover](https://github.com/garnetsunset/CiscoSpectreTakeover) :  ![starts](https://img.shields.io/github/stars/garnetsunset/CiscoSpectreTakeover.svg) ![forks](https://img.shields.io/github/forks/garnetsunset/CiscoSpectreTakeover.svg)

- [https://github.com/EdwardOwusuAdjei/Spectre-PoC](https://github.com/EdwardOwusuAdjei/Spectre-PoC) :  ![starts](https://img.shields.io/github/stars/EdwardOwusuAdjei/Spectre-PoC.svg) ![forks](https://img.shields.io/github/forks/EdwardOwusuAdjei/Spectre-PoC.svg)

- [https://github.com/gonoph/ansible-meltdown-spectre](https://github.com/gonoph/ansible-meltdown-spectre) :  ![starts](https://img.shields.io/github/stars/gonoph/ansible-meltdown-spectre.svg) ![forks](https://img.shields.io/github/forks/gonoph/ansible-meltdown-spectre.svg)

- [https://github.com/miglen/Awesome-Meltdown-Spectre](https://github.com/miglen/Awesome-Meltdown-Spectre) :  ![starts](https://img.shields.io/github/stars/miglen/Awesome-Meltdown-Spectre.svg) ![forks](https://img.shields.io/github/forks/miglen/Awesome-Meltdown-Spectre.svg)

- [https://github.com/albertleecn/cve-2017-5753](https://github.com/albertleecn/cve-2017-5753) :  ![starts](https://img.shields.io/github/stars/albertleecn/cve-2017-5753.svg) ![forks](https://img.shields.io/github/forks/albertleecn/cve-2017-5753.svg)

- [https://github.com/pedrolucasoliva/spectre-attack-demo](https://github.com/pedrolucasoliva/spectre-attack-demo) :  ![starts](https://img.shields.io/github/stars/pedrolucasoliva/spectre-attack-demo.svg) ![forks](https://img.shields.io/github/forks/pedrolucasoliva/spectre-attack-demo.svg)

- [https://github.com/sachinthaBS/Spectre-Vulnerability-CVE-2017-5753-](https://github.com/sachinthaBS/Spectre-Vulnerability-CVE-2017-5753-) :  ![starts](https://img.shields.io/github/stars/sachinthaBS/Spectre-Vulnerability-CVE-2017-5753-.svg) ![forks](https://img.shields.io/github/forks/sachinthaBS/Spectre-Vulnerability-CVE-2017-5753-.svg)

- [https://github.com/GregAskew/SpeculativeExecutionAssessment](https://github.com/GregAskew/SpeculativeExecutionAssessment) :  ![starts](https://img.shields.io/github/stars/GregAskew/SpeculativeExecutionAssessment.svg) ![forks](https://img.shields.io/github/forks/GregAskew/SpeculativeExecutionAssessment.svg)

## CVE-2017-5638
 The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.



- [https://github.com/mazen160/struts-pwn](https://github.com/mazen160/struts-pwn) :  ![starts](https://img.shields.io/github/stars/mazen160/struts-pwn.svg) ![forks](https://img.shields.io/github/forks/mazen160/struts-pwn.svg)

- [https://github.com/Flyteas/Struts2-045-Exp](https://github.com/Flyteas/Struts2-045-Exp) :  ![starts](https://img.shields.io/github/stars/Flyteas/Struts2-045-Exp.svg) ![forks](https://img.shields.io/github/forks/Flyteas/Struts2-045-Exp.svg)

- [https://github.com/Z-0ne/ScanS2-045-Nmap](https://github.com/Z-0ne/ScanS2-045-Nmap) :  ![starts](https://img.shields.io/github/stars/Z-0ne/ScanS2-045-Nmap.svg) ![forks](https://img.shields.io/github/forks/Z-0ne/ScanS2-045-Nmap.svg)

- [https://github.com/mthbernardes/strutszeiro](https://github.com/mthbernardes/strutszeiro) :  ![starts](https://img.shields.io/github/stars/mthbernardes/strutszeiro.svg) ![forks](https://img.shields.io/github/forks/mthbernardes/strutszeiro.svg)

- [https://github.com/immunio/apache-struts2-CVE-2017-5638](https://github.com/immunio/apache-struts2-CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/immunio/apache-struts2-CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/immunio/apache-struts2-CVE-2017-5638.svg)

- [https://github.com/shawnmckinney/remote-code-execution-sample](https://github.com/shawnmckinney/remote-code-execution-sample) :  ![starts](https://img.shields.io/github/stars/shawnmckinney/remote-code-execution-sample.svg) ![forks](https://img.shields.io/github/forks/shawnmckinney/remote-code-execution-sample.svg)

- [https://github.com/jas502n/S2-045-EXP-POC-TOOLS](https://github.com/jas502n/S2-045-EXP-POC-TOOLS) :  ![starts](https://img.shields.io/github/stars/jas502n/S2-045-EXP-POC-TOOLS.svg) ![forks](https://img.shields.io/github/forks/jas502n/S2-045-EXP-POC-TOOLS.svg)

- [https://github.com/PolarisLab/S2-045](https://github.com/PolarisLab/S2-045) :  ![starts](https://img.shields.io/github/stars/PolarisLab/S2-045.svg) ![forks](https://img.shields.io/github/forks/PolarisLab/S2-045.svg)

- [https://github.com/jas502n/st2-046-poc](https://github.com/jas502n/st2-046-poc) :  ![starts](https://img.shields.io/github/stars/jas502n/st2-046-poc.svg) ![forks](https://img.shields.io/github/forks/jas502n/st2-046-poc.svg)

- [https://github.com/xsscx/cve-2017-5638](https://github.com/xsscx/cve-2017-5638) :  ![starts](https://img.shields.io/github/stars/xsscx/cve-2017-5638.svg) ![forks](https://img.shields.io/github/forks/xsscx/cve-2017-5638.svg)

- [https://github.com/ret2jazzy/Struts-Apache-ExploitPack](https://github.com/ret2jazzy/Struts-Apache-ExploitPack) :  ![starts](https://img.shields.io/github/stars/ret2jazzy/Struts-Apache-ExploitPack.svg) ![forks](https://img.shields.io/github/forks/ret2jazzy/Struts-Apache-ExploitPack.svg)

- [https://github.com/win3zz/CVE-2017-5638](https://github.com/win3zz/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/win3zz/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/win3zz/CVE-2017-5638.svg)

- [https://github.com/jrrdev/cve-2017-5638](https://github.com/jrrdev/cve-2017-5638) :  ![starts](https://img.shields.io/github/stars/jrrdev/cve-2017-5638.svg) ![forks](https://img.shields.io/github/forks/jrrdev/cve-2017-5638.svg)

- [https://github.com/sUbc0ol/Apache-Struts2-RCE-Exploit-v2-CVE-2017-5638](https://github.com/sUbc0ol/Apache-Struts2-RCE-Exploit-v2-CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/sUbc0ol/Apache-Struts2-RCE-Exploit-v2-CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/sUbc0ol/Apache-Struts2-RCE-Exploit-v2-CVE-2017-5638.svg)

- [https://github.com/Iletee/struts2-rce](https://github.com/Iletee/struts2-rce) :  ![starts](https://img.shields.io/github/stars/Iletee/struts2-rce.svg) ![forks](https://img.shields.io/github/forks/Iletee/struts2-rce.svg)

- [https://github.com/tahmed11/strutsy](https://github.com/tahmed11/strutsy) :  ![starts](https://img.shields.io/github/stars/tahmed11/strutsy.svg) ![forks](https://img.shields.io/github/forks/tahmed11/strutsy.svg)

- [https://github.com/initconf/CVE-2017-5638_struts](https://github.com/initconf/CVE-2017-5638_struts) :  ![starts](https://img.shields.io/github/stars/initconf/CVE-2017-5638_struts.svg) ![forks](https://img.shields.io/github/forks/initconf/CVE-2017-5638_struts.svg)

- [https://github.com/payatu/CVE-2017-5638](https://github.com/payatu/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/payatu/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/payatu/CVE-2017-5638.svg)

- [https://github.com/0x00-0x00/CVE-2017-5638](https://github.com/0x00-0x00/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/0x00-0x00/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/0x00-0x00/CVE-2017-5638.svg)

- [https://github.com/R4v3nBl4ck/Apache-Struts-2-CVE-2017-5638-Exploit-](https://github.com/R4v3nBl4ck/Apache-Struts-2-CVE-2017-5638-Exploit-) :  ![starts](https://img.shields.io/github/stars/R4v3nBl4ck/Apache-Struts-2-CVE-2017-5638-Exploit-.svg) ![forks](https://img.shields.io/github/forks/R4v3nBl4ck/Apache-Struts-2-CVE-2017-5638-Exploit-.svg)

- [https://github.com/evolvesecurity/vuln-struts2-vm](https://github.com/evolvesecurity/vuln-struts2-vm) :  ![starts](https://img.shields.io/github/stars/evolvesecurity/vuln-struts2-vm.svg) ![forks](https://img.shields.io/github/forks/evolvesecurity/vuln-struts2-vm.svg)

- [https://github.com/falcon-lnhg/StrutsShell](https://github.com/falcon-lnhg/StrutsShell) :  ![starts](https://img.shields.io/github/stars/falcon-lnhg/StrutsShell.svg) ![forks](https://img.shields.io/github/forks/falcon-lnhg/StrutsShell.svg)

- [https://github.com/lolwaleet/ExpStruts](https://github.com/lolwaleet/ExpStruts) :  ![starts](https://img.shields.io/github/stars/lolwaleet/ExpStruts.svg) ![forks](https://img.shields.io/github/forks/lolwaleet/ExpStruts.svg)

- [https://github.com/un4ckn0wl3z/CVE-2017-5638](https://github.com/un4ckn0wl3z/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/un4ckn0wl3z/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/un4ckn0wl3z/CVE-2017-5638.svg)

- [https://github.com/Greynad/struts2-jakarta-inject](https://github.com/Greynad/struts2-jakarta-inject) :  ![starts](https://img.shields.io/github/stars/Greynad/struts2-jakarta-inject.svg) ![forks](https://img.shields.io/github/forks/Greynad/struts2-jakarta-inject.svg)

- [https://github.com/opt9/Strutscli](https://github.com/opt9/Strutscli) :  ![starts](https://img.shields.io/github/stars/opt9/Strutscli.svg) ![forks](https://img.shields.io/github/forks/opt9/Strutscli.svg)

- [https://github.com/aljazceru/CVE-2017-5638-Apache-Struts2](https://github.com/aljazceru/CVE-2017-5638-Apache-Struts2) :  ![starts](https://img.shields.io/github/stars/aljazceru/CVE-2017-5638-Apache-Struts2.svg) ![forks](https://img.shields.io/github/forks/aljazceru/CVE-2017-5638-Apache-Struts2.svg)

- [https://github.com/opt9/Strutshock](https://github.com/opt9/Strutshock) :  ![starts](https://img.shields.io/github/stars/opt9/Strutshock.svg) ![forks](https://img.shields.io/github/forks/opt9/Strutshock.svg)

- [https://github.com/andypitcher/check_struts](https://github.com/andypitcher/check_struts) :  ![starts](https://img.shields.io/github/stars/andypitcher/check_struts.svg) ![forks](https://img.shields.io/github/forks/andypitcher/check_struts.svg)

- [https://github.com/Nithylesh/web-application-firewall-](https://github.com/Nithylesh/web-application-firewall-) :  ![starts](https://img.shields.io/github/stars/Nithylesh/web-application-firewall-.svg) ![forks](https://img.shields.io/github/forks/Nithylesh/web-application-firewall-.svg)

- [https://github.com/paralelo14/CVE_2017_5638](https://github.com/paralelo14/CVE_2017_5638) :  ![starts](https://img.shields.io/github/stars/paralelo14/CVE_2017_5638.svg) ![forks](https://img.shields.io/github/forks/paralelo14/CVE_2017_5638.svg)

- [https://github.com/oktavianto/CVE-2017-5638-Apache-Struts2](https://github.com/oktavianto/CVE-2017-5638-Apache-Struts2) :  ![starts](https://img.shields.io/github/stars/oktavianto/CVE-2017-5638-Apache-Struts2.svg) ![forks](https://img.shields.io/github/forks/oktavianto/CVE-2017-5638-Apache-Struts2.svg)

- [https://github.com/riyazwalikar/struts-rce-cve-2017-5638](https://github.com/riyazwalikar/struts-rce-cve-2017-5638) :  ![starts](https://img.shields.io/github/stars/riyazwalikar/struts-rce-cve-2017-5638.svg) ![forks](https://img.shields.io/github/forks/riyazwalikar/struts-rce-cve-2017-5638.svg)

- [https://github.com/ggolawski/struts-rce](https://github.com/ggolawski/struts-rce) :  ![starts](https://img.shields.io/github/stars/ggolawski/struts-rce.svg) ![forks](https://img.shields.io/github/forks/ggolawski/struts-rce.svg)

- [https://github.com/sighup1/cybersecurity-struts2](https://github.com/sighup1/cybersecurity-struts2) :  ![starts](https://img.shields.io/github/stars/sighup1/cybersecurity-struts2.svg) ![forks](https://img.shields.io/github/forks/sighup1/cybersecurity-struts2.svg)

- [https://github.com/haxerr9/CVE-2017-5638](https://github.com/haxerr9/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/haxerr9/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/haxerr9/CVE-2017-5638.svg)

- [https://github.com/jongmartinez/CVE-2017-5638](https://github.com/jongmartinez/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/jongmartinez/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/jongmartinez/CVE-2017-5638.svg)

- [https://github.com/jptr218/struts_hack](https://github.com/jptr218/struts_hack) :  ![starts](https://img.shields.io/github/stars/jptr218/struts_hack.svg) ![forks](https://img.shields.io/github/forks/jptr218/struts_hack.svg)

- [https://github.com/m3ssap0/struts2_cve-2017-5638](https://github.com/m3ssap0/struts2_cve-2017-5638) :  ![starts](https://img.shields.io/github/stars/m3ssap0/struts2_cve-2017-5638.svg) ![forks](https://img.shields.io/github/forks/m3ssap0/struts2_cve-2017-5638.svg)

- [https://github.com/kloutkake/CVE-2017-5638-PoC](https://github.com/kloutkake/CVE-2017-5638-PoC) :  ![starts](https://img.shields.io/github/stars/kloutkake/CVE-2017-5638-PoC.svg) ![forks](https://img.shields.io/github/forks/kloutkake/CVE-2017-5638-PoC.svg)

- [https://github.com/ludy-dev/XworkStruts-RCE](https://github.com/ludy-dev/XworkStruts-RCE) :  ![starts](https://img.shields.io/github/stars/ludy-dev/XworkStruts-RCE.svg) ![forks](https://img.shields.io/github/forks/ludy-dev/XworkStruts-RCE.svg)

- [https://github.com/sUbc0ol/Apache-Struts-CVE-2017-5638-RCE-Mass-Scanner](https://github.com/sUbc0ol/Apache-Struts-CVE-2017-5638-RCE-Mass-Scanner) :  ![starts](https://img.shields.io/github/stars/sUbc0ol/Apache-Struts-CVE-2017-5638-RCE-Mass-Scanner.svg) ![forks](https://img.shields.io/github/forks/sUbc0ol/Apache-Struts-CVE-2017-5638-RCE-Mass-Scanner.svg)

- [https://github.com/KarzsGHR/S2-046_S2-045_POC](https://github.com/KarzsGHR/S2-046_S2-045_POC) :  ![starts](https://img.shields.io/github/stars/KarzsGHR/S2-046_S2-045_POC.svg) ![forks](https://img.shields.io/github/forks/KarzsGHR/S2-046_S2-045_POC.svg)

- [https://github.com/jpacora/Struts2Shell](https://github.com/jpacora/Struts2Shell) :  ![starts](https://img.shields.io/github/stars/jpacora/Struts2Shell.svg) ![forks](https://img.shields.io/github/forks/jpacora/Struts2Shell.svg)

- [https://github.com/mike-williams/Struts2Vuln](https://github.com/mike-williams/Struts2Vuln) :  ![starts](https://img.shields.io/github/stars/mike-williams/Struts2Vuln.svg) ![forks](https://img.shields.io/github/forks/mike-williams/Struts2Vuln.svg)

- [https://github.com/Masahiro-Yamada/OgnlContentTypeRejectorValve](https://github.com/Masahiro-Yamada/OgnlContentTypeRejectorValve) :  ![starts](https://img.shields.io/github/stars/Masahiro-Yamada/OgnlContentTypeRejectorValve.svg) ![forks](https://img.shields.io/github/forks/Masahiro-Yamada/OgnlContentTypeRejectorValve.svg)

- [https://github.com/gh0st27/Struts2Scanner](https://github.com/gh0st27/Struts2Scanner) :  ![starts](https://img.shields.io/github/stars/gh0st27/Struts2Scanner.svg) ![forks](https://img.shields.io/github/forks/gh0st27/Struts2Scanner.svg)

- [https://github.com/gsfish/S2-Reaper](https://github.com/gsfish/S2-Reaper) :  ![starts](https://img.shields.io/github/stars/gsfish/S2-Reaper.svg) ![forks](https://img.shields.io/github/forks/gsfish/S2-Reaper.svg)

- [https://github.com/SpiderMate/Stutsfi](https://github.com/SpiderMate/Stutsfi) :  ![starts](https://img.shields.io/github/stars/SpiderMate/Stutsfi.svg) ![forks](https://img.shields.io/github/forks/SpiderMate/Stutsfi.svg)

- [https://github.com/Aasron/Struts2-045-Exp](https://github.com/Aasron/Struts2-045-Exp) :  ![starts](https://img.shields.io/github/stars/Aasron/Struts2-045-Exp.svg) ![forks](https://img.shields.io/github/forks/Aasron/Struts2-045-Exp.svg)

- [https://github.com/colorblindpentester/CVE-2017-5638](https://github.com/colorblindpentester/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/colorblindpentester/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/colorblindpentester/CVE-2017-5638.svg)

- [https://github.com/AndreasKl/CVE-2017-5638](https://github.com/AndreasKl/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/AndreasKl/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/AndreasKl/CVE-2017-5638.svg)

- [https://github.com/eeehit/CVE-2017-5638](https://github.com/eeehit/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/eeehit/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/eeehit/CVE-2017-5638.svg)

- [https://github.com/Badbird3/CVE-2017-5638](https://github.com/Badbird3/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/Badbird3/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/Badbird3/CVE-2017-5638.svg)

- [https://github.com/random-robbie/CVE-2017-5638](https://github.com/random-robbie/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/random-robbie/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/random-robbie/CVE-2017-5638.svg)

- [https://github.com/QHxDr-dz/CVE-2017-5638](https://github.com/QHxDr-dz/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/QHxDr-dz/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/QHxDr-dz/CVE-2017-5638.svg)

- [https://github.com/homjxi0e/CVE-2017-5638](https://github.com/homjxi0e/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-5638.svg)

- [https://github.com/Tankirat/CVE-2017-5638](https://github.com/Tankirat/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/Tankirat/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/Tankirat/CVE-2017-5638.svg)

- [https://github.com/jrrombaldo/CVE-2017-5638](https://github.com/jrrombaldo/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/jrrombaldo/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/jrrombaldo/CVE-2017-5638.svg)

- [https://github.com/injcristianrojas/cve-2017-5638](https://github.com/injcristianrojas/cve-2017-5638) :  ![starts](https://img.shields.io/github/stars/injcristianrojas/cve-2017-5638.svg) ![forks](https://img.shields.io/github/forks/injcristianrojas/cve-2017-5638.svg)

- [https://github.com/mritunjay-k/CVE-2017-5638](https://github.com/mritunjay-k/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/mritunjay-k/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/mritunjay-k/CVE-2017-5638.svg)

- [https://github.com/bhagdave/CVE-2017-5638](https://github.com/bhagdave/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/bhagdave/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/bhagdave/CVE-2017-5638.svg)

- [https://github.com/readloud/CVE-2017-5638](https://github.com/readloud/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/readloud/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/readloud/CVE-2017-5638.svg)

- [https://github.com/toothbrushsoapflannelbiscuits/cve-2017-5638](https://github.com/toothbrushsoapflannelbiscuits/cve-2017-5638) :  ![starts](https://img.shields.io/github/stars/toothbrushsoapflannelbiscuits/cve-2017-5638.svg) ![forks](https://img.shields.io/github/forks/toothbrushsoapflannelbiscuits/cve-2017-5638.svg)

- [https://github.com/mcassano/cve-2017-5638](https://github.com/mcassano/cve-2017-5638) :  ![starts](https://img.shields.io/github/stars/mcassano/cve-2017-5638.svg) ![forks](https://img.shields.io/github/forks/mcassano/cve-2017-5638.svg)

- [https://github.com/bongbongco/cve-2017-5638](https://github.com/bongbongco/cve-2017-5638) :  ![starts](https://img.shields.io/github/stars/bongbongco/cve-2017-5638.svg) ![forks](https://img.shields.io/github/forks/bongbongco/cve-2017-5638.svg)

- [https://github.com/Xhendos/CVE-2017-5638](https://github.com/Xhendos/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/Xhendos/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/Xhendos/CVE-2017-5638.svg)

- [https://github.com/mfdev-solution/Exploit-CVE-2017-5638](https://github.com/mfdev-solution/Exploit-CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/mfdev-solution/Exploit-CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/mfdev-solution/Exploit-CVE-2017-5638.svg)

- [https://github.com/cafnet/apache-struts-v2-CVE-2017-5638](https://github.com/cafnet/apache-struts-v2-CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/cafnet/apache-struts-v2-CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/cafnet/apache-struts-v2-CVE-2017-5638.svg)

- [https://github.com/Xernary/CVE-2017-5638-POC](https://github.com/Xernary/CVE-2017-5638-POC) :  ![starts](https://img.shields.io/github/stars/Xernary/CVE-2017-5638-POC.svg) ![forks](https://img.shields.io/github/forks/Xernary/CVE-2017-5638-POC.svg)

- [https://github.com/sonatype-workshops/struts2-rce](https://github.com/sonatype-workshops/struts2-rce) :  ![starts](https://img.shields.io/github/stars/sonatype-workshops/struts2-rce.svg) ![forks](https://img.shields.io/github/forks/sonatype-workshops/struts2-rce.svg)

- [https://github.com/leandrocamposcardoso/CVE-2017-5638-Mass-Exploit](https://github.com/leandrocamposcardoso/CVE-2017-5638-Mass-Exploit) :  ![starts](https://img.shields.io/github/stars/leandrocamposcardoso/CVE-2017-5638-Mass-Exploit.svg) ![forks](https://img.shields.io/github/forks/leandrocamposcardoso/CVE-2017-5638-Mass-Exploit.svg)

- [https://github.com/invisiblethreat/strutser](https://github.com/invisiblethreat/strutser) :  ![starts](https://img.shields.io/github/stars/invisiblethreat/strutser.svg) ![forks](https://img.shields.io/github/forks/invisiblethreat/strutser.svg)

- [https://github.com/joidiego/Detection-struts-cve-2017-5638-detector](https://github.com/joidiego/Detection-struts-cve-2017-5638-detector) :  ![starts](https://img.shields.io/github/stars/joidiego/Detection-struts-cve-2017-5638-detector.svg) ![forks](https://img.shields.io/github/forks/joidiego/Detection-struts-cve-2017-5638-detector.svg)

- [https://github.com/c002/Apache-Struts](https://github.com/c002/Apache-Struts) :  ![starts](https://img.shields.io/github/stars/c002/Apache-Struts.svg) ![forks](https://img.shields.io/github/forks/c002/Apache-Struts.svg)

- [https://github.com/sjitech/test_struts2_vulnerability_CVE-2017-5638](https://github.com/sjitech/test_struts2_vulnerability_CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/sjitech/test_struts2_vulnerability_CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/sjitech/test_struts2_vulnerability_CVE-2017-5638.svg)

- [https://github.com/FredBrave/CVE-2017-5638-ApacheStruts2.3.5](https://github.com/FredBrave/CVE-2017-5638-ApacheStruts2.3.5) :  ![starts](https://img.shields.io/github/stars/FredBrave/CVE-2017-5638-ApacheStruts2.3.5.svg) ![forks](https://img.shields.io/github/forks/FredBrave/CVE-2017-5638-ApacheStruts2.3.5.svg)

- [https://github.com/TamiiLambrado/Apache-Struts-CVE-2017-5638-RCE-Mass-Scanner](https://github.com/TamiiLambrado/Apache-Struts-CVE-2017-5638-RCE-Mass-Scanner) :  ![starts](https://img.shields.io/github/stars/TamiiLambrado/Apache-Struts-CVE-2017-5638-RCE-Mass-Scanner.svg) ![forks](https://img.shields.io/github/forks/TamiiLambrado/Apache-Struts-CVE-2017-5638-RCE-Mass-Scanner.svg)

- [https://github.com/testpilot031/vulnerability_struts-2.3.31](https://github.com/testpilot031/vulnerability_struts-2.3.31) :  ![starts](https://img.shields.io/github/stars/testpilot031/vulnerability_struts-2.3.31.svg) ![forks](https://img.shields.io/github/forks/testpilot031/vulnerability_struts-2.3.31.svg)

- [https://github.com/xeroxis-xs/Computer-Security-Apache-Struts-Vulnerability](https://github.com/xeroxis-xs/Computer-Security-Apache-Struts-Vulnerability) :  ![starts](https://img.shields.io/github/stars/xeroxis-xs/Computer-Security-Apache-Struts-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/xeroxis-xs/Computer-Security-Apache-Struts-Vulnerability.svg)

- [https://github.com/donaldashdown/Common-Vulnerability-and-Exploit](https://github.com/donaldashdown/Common-Vulnerability-and-Exploit) :  ![starts](https://img.shields.io/github/stars/donaldashdown/Common-Vulnerability-and-Exploit.svg) ![forks](https://img.shields.io/github/forks/donaldashdown/Common-Vulnerability-and-Exploit.svg)

- [https://github.com/andrewkroh/auditbeat-apache-struts-demo](https://github.com/andrewkroh/auditbeat-apache-struts-demo) :  ![starts](https://img.shields.io/github/stars/andrewkroh/auditbeat-apache-struts-demo.svg) ![forks](https://img.shields.io/github/forks/andrewkroh/auditbeat-apache-struts-demo.svg)

## CVE-2017-5521
 An issue was discovered on NETGEAR R8500, R8300, R7000, R6400, R7300, R7100LG, R6300v2, WNDR3400v3, WNR3500Lv2, R6250, R6700, R6900, and R8000 devices. They are prone to password disclosure via simple crafted requests to the web management server. The bug is exploitable remotely if the remote management option is set, and can also be exploited given access to the router over LAN or WLAN. When trying to access the web panel, a user is asked to authenticate; if the authentication is canceled and password recovery is not enabled, the user is redirected to a page that exposes a password recovery token. If a user supplies the correct token to the page /passwordrecovered.cgi?id=TOKEN (and password recovery is not enabled), they will receive the admin password for the router. If password recovery is set the exploit will fail, as it will ask the user for the recovery questions that were previously set when enabling that feature. This is persistent (even after disabling the recovery option, the exploit will fail) because the router will ask for the security questions.



- [https://github.com/lilloX/routerPWN](https://github.com/lilloX/routerPWN) :  ![starts](https://img.shields.io/github/stars/lilloX/routerPWN.svg) ![forks](https://img.shields.io/github/forks/lilloX/routerPWN.svg)

## CVE-2017-5005
 Stack-based buffer overflow in Quick Heal Internet Security 10.1.0.316 and earlier, Total Security 10.1.0.316 and earlier, and AntiVirus Pro 10.1.0.316 and earlier on OS X allows remote attackers to execute arbitrary code via a crafted LC_UNIXTHREAD.cmdsize field in a Mach-O file that is mishandled during a Security Scan (aka Custom Scan) operation.



- [https://github.com/payatu/QuickHeal](https://github.com/payatu/QuickHeal) :  ![starts](https://img.shields.io/github/stars/payatu/QuickHeal.svg) ![forks](https://img.shields.io/github/forks/payatu/QuickHeal.svg)

## CVE-2017-3248
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.0 and 12.2.1.1. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS v3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).



- [https://github.com/0xn0ne/weblogicScanner](https://github.com/0xn0ne/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/0xn0ne/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/0xn0ne/weblogicScanner.svg)

- [https://github.com/ianxtianxt/CVE-2017-3248](https://github.com/ianxtianxt/CVE-2017-3248) :  ![starts](https://img.shields.io/github/stars/ianxtianxt/CVE-2017-3248.svg) ![forks](https://img.shields.io/github/forks/ianxtianxt/CVE-2017-3248.svg)

- [https://github.com/BabyTeam1024/CVE-2017-3248](https://github.com/BabyTeam1024/CVE-2017-3248) :  ![starts](https://img.shields.io/github/stars/BabyTeam1024/CVE-2017-3248.svg) ![forks](https://img.shields.io/github/forks/BabyTeam1024/CVE-2017-3248.svg)

## CVE-2017-2388
 An issue was discovered in certain Apple products. macOS before 10.12.4 is affected. The issue involves the "IOFireWireFamily" component. It allows attackers to cause a denial of service (NULL pointer dereference) via a crafted app.



- [https://github.com/bazad/IOFireWireFamily-null-deref](https://github.com/bazad/IOFireWireFamily-null-deref) :  ![starts](https://img.shields.io/github/stars/bazad/IOFireWireFamily-null-deref.svg) ![forks](https://img.shields.io/github/forks/bazad/IOFireWireFamily-null-deref.svg)

## CVE-2017-0807
 An elevation of privilege vulnerability in the Android framework (ui framework). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2. Android ID: A-35056974.



- [https://github.com/kpatsakis/PoC_CVE-2017-0807](https://github.com/kpatsakis/PoC_CVE-2017-0807) :  ![starts](https://img.shields.io/github/stars/kpatsakis/PoC_CVE-2017-0807.svg) ![forks](https://img.shields.io/github/forks/kpatsakis/PoC_CVE-2017-0807.svg)

## CVE-2017-0785
 A information disclosure vulnerability in the Android system (bluetooth). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-63146698.



- [https://github.com/ojasookert/CVE-2017-0785](https://github.com/ojasookert/CVE-2017-0785) :  ![starts](https://img.shields.io/github/stars/ojasookert/CVE-2017-0785.svg) ![forks](https://img.shields.io/github/forks/ojasookert/CVE-2017-0785.svg)

- [https://github.com/Alfa100001/-CVE-2017-0785-BlueBorne-PoC](https://github.com/Alfa100001/-CVE-2017-0785-BlueBorne-PoC) :  ![starts](https://img.shields.io/github/stars/Alfa100001/-CVE-2017-0785-BlueBorne-PoC.svg) ![forks](https://img.shields.io/github/forks/Alfa100001/-CVE-2017-0785-BlueBorne-PoC.svg)

- [https://github.com/pieterbork/blueborne](https://github.com/pieterbork/blueborne) :  ![starts](https://img.shields.io/github/stars/pieterbork/blueborne.svg) ![forks](https://img.shields.io/github/forks/pieterbork/blueborne.svg)

- [https://github.com/henrychoi7/Bluepwn](https://github.com/henrychoi7/Bluepwn) :  ![starts](https://img.shields.io/github/stars/henrychoi7/Bluepwn.svg) ![forks](https://img.shields.io/github/forks/henrychoi7/Bluepwn.svg)

- [https://github.com/CrackSoft900/Blue-Borne](https://github.com/CrackSoft900/Blue-Borne) :  ![starts](https://img.shields.io/github/stars/CrackSoft900/Blue-Borne.svg) ![forks](https://img.shields.io/github/forks/CrackSoft900/Blue-Borne.svg)

- [https://github.com/Hackerscript/BlueBorne-CVE-2017-0785](https://github.com/Hackerscript/BlueBorne-CVE-2017-0785) :  ![starts](https://img.shields.io/github/stars/Hackerscript/BlueBorne-CVE-2017-0785.svg) ![forks](https://img.shields.io/github/forks/Hackerscript/BlueBorne-CVE-2017-0785.svg)

- [https://github.com/CyberKimathi/Py3-CVE-2017-0785](https://github.com/CyberKimathi/Py3-CVE-2017-0785) :  ![starts](https://img.shields.io/github/stars/CyberKimathi/Py3-CVE-2017-0785.svg) ![forks](https://img.shields.io/github/forks/CyberKimathi/Py3-CVE-2017-0785.svg)

- [https://github.com/RavSS/Bluetooth-Crash-CVE-2017-0785](https://github.com/RavSS/Bluetooth-Crash-CVE-2017-0785) :  ![starts](https://img.shields.io/github/stars/RavSS/Bluetooth-Crash-CVE-2017-0785.svg) ![forks](https://img.shields.io/github/forks/RavSS/Bluetooth-Crash-CVE-2017-0785.svg)

- [https://github.com/MasterCode112/Upgraded_BlueBourne-CVE-2017-0785-](https://github.com/MasterCode112/Upgraded_BlueBourne-CVE-2017-0785-) :  ![starts](https://img.shields.io/github/stars/MasterCode112/Upgraded_BlueBourne-CVE-2017-0785-.svg) ![forks](https://img.shields.io/github/forks/MasterCode112/Upgraded_BlueBourne-CVE-2017-0785-.svg)

- [https://github.com/CarlosDelRosario7/sploit-bX](https://github.com/CarlosDelRosario7/sploit-bX) :  ![starts](https://img.shields.io/github/stars/CarlosDelRosario7/sploit-bX.svg) ![forks](https://img.shields.io/github/forks/CarlosDelRosario7/sploit-bX.svg)

- [https://github.com/sh4rknado/BlueBorn](https://github.com/sh4rknado/BlueBorn) :  ![starts](https://img.shields.io/github/stars/sh4rknado/BlueBorn.svg) ![forks](https://img.shields.io/github/forks/sh4rknado/BlueBorn.svg)

- [https://github.com/aymankhalfatni/CVE-2017-0785](https://github.com/aymankhalfatni/CVE-2017-0785) :  ![starts](https://img.shields.io/github/stars/aymankhalfatni/CVE-2017-0785.svg) ![forks](https://img.shields.io/github/forks/aymankhalfatni/CVE-2017-0785.svg)

- [https://github.com/Joanmei/CVE-2017-0785](https://github.com/Joanmei/CVE-2017-0785) :  ![starts](https://img.shields.io/github/stars/Joanmei/CVE-2017-0785.svg) ![forks](https://img.shields.io/github/forks/Joanmei/CVE-2017-0785.svg)

- [https://github.com/sigbitsadmin/diff](https://github.com/sigbitsadmin/diff) :  ![starts](https://img.shields.io/github/stars/sigbitsadmin/diff.svg) ![forks](https://img.shields.io/github/forks/sigbitsadmin/diff.svg)

## CVE-2017-0781
 A remote code execution vulnerability in the Android system (bluetooth). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-63146105.



- [https://github.com/ojasookert/CVE-2017-0781](https://github.com/ojasookert/CVE-2017-0781) :  ![starts](https://img.shields.io/github/stars/ojasookert/CVE-2017-0781.svg) ![forks](https://img.shields.io/github/forks/ojasookert/CVE-2017-0781.svg)

- [https://github.com/CrackSoft900/Blue-Borne](https://github.com/CrackSoft900/Blue-Borne) :  ![starts](https://img.shields.io/github/stars/CrackSoft900/Blue-Borne.svg) ![forks](https://img.shields.io/github/forks/CrackSoft900/Blue-Borne.svg)

- [https://github.com/X3eRo0/android712-blueborne](https://github.com/X3eRo0/android712-blueborne) :  ![starts](https://img.shields.io/github/stars/X3eRo0/android712-blueborne.svg) ![forks](https://img.shields.io/github/forks/X3eRo0/android712-blueborne.svg)

- [https://github.com/DamianSuess/Learn.BlueJam](https://github.com/DamianSuess/Learn.BlueJam) :  ![starts](https://img.shields.io/github/stars/DamianSuess/Learn.BlueJam.svg) ![forks](https://img.shields.io/github/forks/DamianSuess/Learn.BlueJam.svg)

- [https://github.com/CarlosDelRosario7/sploit-bX](https://github.com/CarlosDelRosario7/sploit-bX) :  ![starts](https://img.shields.io/github/stars/CarlosDelRosario7/sploit-bX.svg) ![forks](https://img.shields.io/github/forks/CarlosDelRosario7/sploit-bX.svg)

- [https://github.com/mjancek/BlueborneDetection](https://github.com/mjancek/BlueborneDetection) :  ![starts](https://img.shields.io/github/stars/mjancek/BlueborneDetection.svg) ![forks](https://img.shields.io/github/forks/mjancek/BlueborneDetection.svg)

## CVE-2017-0564
 An elevation of privilege vulnerability in the kernel ION subsystem could enable a local malicious application to execute arbitrary code within the context of the kernel. This issue is rated as Critical due to the possibility of a local permanent device compromise, which may require reflashing the operating system to repair the device. Product: Android. Versions: Kernel-3.10, Kernel-3.18. Android ID: A-34276203.



- [https://github.com/guoygang/CVE-2017-0564-ION-PoC](https://github.com/guoygang/CVE-2017-0564-ION-PoC) :  ![starts](https://img.shields.io/github/stars/guoygang/CVE-2017-0564-ION-PoC.svg) ![forks](https://img.shields.io/github/forks/guoygang/CVE-2017-0564-ION-PoC.svg)

## CVE-2017-0358
 Jann Horn of Google Project Zero discovered that NTFS-3G, a read-write NTFS driver for FUSE, does not scrub the environment before executing modprobe with elevated privileges. A local user can take advantage of this flaw for local root privilege escalation.



- [https://github.com/Wangsafz/cve-2017-0358.sh](https://github.com/Wangsafz/cve-2017-0358.sh) :  ![starts](https://img.shields.io/github/stars/Wangsafz/cve-2017-0358.sh.svg) ![forks](https://img.shields.io/github/forks/Wangsafz/cve-2017-0358.sh.svg)

## CVE-2017-0213
 Windows COM Aggregate Marshaler in Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, and 1703, and Windows Server 2016 allows an elevation privilege vulnerability when an attacker runs a specially crafted application, aka "Windows COM Elevation of Privilege Vulnerability". This CVE ID is unique from CVE-2017-0214.



- [https://github.com/zcgonvh/CVE-2017-0213](https://github.com/zcgonvh/CVE-2017-0213) :  ![starts](https://img.shields.io/github/stars/zcgonvh/CVE-2017-0213.svg) ![forks](https://img.shields.io/github/forks/zcgonvh/CVE-2017-0213.svg)

- [https://github.com/eonrickity/CVE-2017-0213](https://github.com/eonrickity/CVE-2017-0213) :  ![starts](https://img.shields.io/github/stars/eonrickity/CVE-2017-0213.svg) ![forks](https://img.shields.io/github/forks/eonrickity/CVE-2017-0213.svg)

- [https://github.com/jbooz1/CVE-2017-0213](https://github.com/jbooz1/CVE-2017-0213) :  ![starts](https://img.shields.io/github/stars/jbooz1/CVE-2017-0213.svg) ![forks](https://img.shields.io/github/forks/jbooz1/CVE-2017-0213.svg)

- [https://github.com/shaheemirza/CVE-2017-0213-](https://github.com/shaheemirza/CVE-2017-0213-) :  ![starts](https://img.shields.io/github/stars/shaheemirza/CVE-2017-0213-.svg) ![forks](https://img.shields.io/github/forks/shaheemirza/CVE-2017-0213-.svg)

- [https://github.com/billa3283/CVE-2017-0213](https://github.com/billa3283/CVE-2017-0213) :  ![starts](https://img.shields.io/github/stars/billa3283/CVE-2017-0213.svg) ![forks](https://img.shields.io/github/forks/billa3283/CVE-2017-0213.svg)

- [https://github.com/Anonymous-Family/CVE-2017-0213](https://github.com/Anonymous-Family/CVE-2017-0213) :  ![starts](https://img.shields.io/github/stars/Anonymous-Family/CVE-2017-0213.svg) ![forks](https://img.shields.io/github/forks/Anonymous-Family/CVE-2017-0213.svg)

- [https://github.com/likekabin/CVE-2017-0213](https://github.com/likekabin/CVE-2017-0213) :  ![starts](https://img.shields.io/github/stars/likekabin/CVE-2017-0213.svg) ![forks](https://img.shields.io/github/forks/likekabin/CVE-2017-0213.svg)

## CVE-2017-0204
 Microsoft Outlook 2007 SP3, Microsoft Outlook 2010 SP2, Microsoft Outlook 2013 SP1, and Microsoft Outlook 2016 allow remote attackers to bypass the Office Protected View via a specially crafted document, aka "Microsoft Office Security Feature Bypass Vulnerability."



- [https://github.com/ryhanson/CVE-2017-0204](https://github.com/ryhanson/CVE-2017-0204) :  ![starts](https://img.shields.io/github/stars/ryhanson/CVE-2017-0204.svg) ![forks](https://img.shields.io/github/forks/ryhanson/CVE-2017-0204.svg)

## CVE-2017-0148
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0144, CVE-2017-0145, and CVE-2017-0146.



- [https://github.com/HakaKali/CVE-2017-0148](https://github.com/HakaKali/CVE-2017-0148) :  ![starts](https://img.shields.io/github/stars/HakaKali/CVE-2017-0148.svg) ![forks](https://img.shields.io/github/forks/HakaKali/CVE-2017-0148.svg)

## CVE-2017-0147
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to obtain sensitive information from process memory via a crafted packets, aka "Windows SMB Information Disclosure Vulnerability."



- [https://github.com/RobertoLeonFR-ES/Exploit-Win32.CVE-2017-0147.A](https://github.com/RobertoLeonFR-ES/Exploit-Win32.CVE-2017-0147.A) :  ![starts](https://img.shields.io/github/stars/RobertoLeonFR-ES/Exploit-Win32.CVE-2017-0147.A.svg) ![forks](https://img.shields.io/github/forks/RobertoLeonFR-ES/Exploit-Win32.CVE-2017-0147.A.svg)

## CVE-2017-0089
 Uniscribe in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, and Windows 7 SP1 allows remote attackers to execute arbitrary code via a crafted web site, aka "Uniscribe Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0072, CVE-2017-0083, CVE-2017-0084, CVE-2017-0086, CVE-2017-0087, CVE-2017-0088, and CVE-2017-0090.



- [https://github.com/rainhawk13/Added-Pentest-Ground-to-vulnerable-websites-for-training](https://github.com/rainhawk13/Added-Pentest-Ground-to-vulnerable-websites-for-training) :  ![starts](https://img.shields.io/github/stars/rainhawk13/Added-Pentest-Ground-to-vulnerable-websites-for-training.svg) ![forks](https://img.shields.io/github/forks/rainhawk13/Added-Pentest-Ground-to-vulnerable-websites-for-training.svg)

## CVE-2017-0038
 gdi32.dll in Graphics Device Interface (GDI) in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, and Windows 10 Gold, 1511, and 1607 allows remote attackers to obtain sensitive information from process heap memory via a crafted EMF file, as demonstrated by an EMR_SETDIBITSTODEVICE record with modified Device Independent Bitmap (DIB) dimensions. NOTE: this vulnerability exists because of an incomplete fix for CVE-2016-3216, CVE-2016-3219, and/or CVE-2016-3220.



- [https://github.com/k0keoyo/CVE-2017-0038-EXP-C-JS](https://github.com/k0keoyo/CVE-2017-0038-EXP-C-JS) :  ![starts](https://img.shields.io/github/stars/k0keoyo/CVE-2017-0038-EXP-C-JS.svg) ![forks](https://img.shields.io/github/forks/k0keoyo/CVE-2017-0038-EXP-C-JS.svg)

## CVE-2017-0037
 Microsoft Internet Explorer 10 and 11 and Microsoft Edge have a type confusion issue in the Layout::MultiColumnBoxBuilder::HandleColumnBreakOnColumnSpanningElement function in mshtml.dll, which allows remote attackers to execute arbitrary code via vectors involving a crafted Cascading Style Sheets (CSS) token sequence and crafted JavaScript code that operates on a TH element.



- [https://github.com/chattopadhyaykittu/CVE-2017-0037](https://github.com/chattopadhyaykittu/CVE-2017-0037) :  ![starts](https://img.shields.io/github/stars/chattopadhyaykittu/CVE-2017-0037.svg) ![forks](https://img.shields.io/github/forks/chattopadhyaykittu/CVE-2017-0037.svg)
