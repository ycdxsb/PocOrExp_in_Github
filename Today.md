# Update 2025-06-03
## CVE-2024-9465
 An SQL injection vulnerability in Palo Alto Networks Expedition allows an unauthenticated attacker to reveal Expedition database contents, such as password hashes, usernames, device configurations, and device API keys. With this, attackers can also create and read arbitrary files on the Expedition system.

- [https://github.com/Qlng/CVE-2024-9465](https://github.com/Qlng/CVE-2024-9465) :  ![starts](https://img.shields.io/github/stars/Qlng/CVE-2024-9465.svg) ![forks](https://img.shields.io/github/forks/Qlng/CVE-2024-9465.svg)


## CVE-2023-25690
Request splitting/smuggling could result in bypass of access controls in the proxy server, proxying unintended URLs to existing origin servers, and cache poisoning. Users are recommended to update to at least version 2.4.56 of Apache HTTP Server.

- [https://github.com/oOCyginXOo/CVE-2023-25690-POC](https://github.com/oOCyginXOo/CVE-2023-25690-POC) :  ![starts](https://img.shields.io/github/stars/oOCyginXOo/CVE-2023-25690-POC.svg) ![forks](https://img.shields.io/github/forks/oOCyginXOo/CVE-2023-25690-POC.svg)


## CVE-2019-19781
 An issue was discovered in Citrix Application Delivery Controller (ADC) and Gateway 10.5, 11.1, 12.0, 12.1, and 13.0. They allow Directory Traversal.

- [https://github.com/awesome-security/citrixmash_scanner](https://github.com/awesome-security/citrixmash_scanner) :  ![starts](https://img.shields.io/github/stars/awesome-security/citrixmash_scanner.svg) ![forks](https://img.shields.io/github/forks/awesome-security/citrixmash_scanner.svg)


## CVE-2019-9193
 In PostgreSQL 9.3 through 11.2, the "COPY TO/FROM PROGRAM" function allows superusers and users in the 'pg_execute_server_program' group to execute arbitrary code in the context of the database's operating system user. This functionality is enabled by default and can be abused to run arbitrary operating system commands on Windows, Linux, and macOS. NOTE: Third parties claim/state this is not an issue because PostgreSQL functionality for ‘COPY TO/FROM PROGRAM’ is acting as intended. References state that in PostgreSQL, a superuser can execute commands as the server user without using the ‘COPY FROM PROGRAM’.

- [https://github.com/jhnhnck/CVE-2019-9193](https://github.com/jhnhnck/CVE-2019-9193) :  ![starts](https://img.shields.io/github/stars/jhnhnck/CVE-2019-9193.svg) ![forks](https://img.shields.io/github/forks/jhnhnck/CVE-2019-9193.svg)


## CVE-2018-9995
 TBK DVR4104 and DVR4216 devices, as well as Novo, CeNova, QSee, Pulnix, XVR 5 in 1, Securus, Night OWL, DVR Login, HVR Login, and MDVR Login, which run re-branded versions of the original TBK DVR4104 and DVR4216 series, allow remote attackers to bypass authentication via a "Cookie: uid=admin" header, as demonstrated by a device.rsp?opt=user&cmd=list request that provides credentials within JSON data in a response.

- [https://github.com/its-anya/DVR_Credential_Scanner](https://github.com/its-anya/DVR_Credential_Scanner) :  ![starts](https://img.shields.io/github/stars/its-anya/DVR_Credential_Scanner.svg) ![forks](https://img.shields.io/github/forks/its-anya/DVR_Credential_Scanner.svg)


## CVE-2017-5689
 An unprivileged network attacker could gain system privileges to provisioned Intel manageability SKUs: Intel Active Management Technology (AMT) and Intel Standard Manageability (ISM). An unprivileged local attacker could provision manageability features gaining unprivileged network or local system privileges on Intel manageability SKUs: Intel Active Management Technology (AMT), Intel Standard Manageability (ISM), and Intel Small Business Technology (SBT).

- [https://github.com/MlSebrell/amthoneypot](https://github.com/MlSebrell/amthoneypot) :  ![starts](https://img.shields.io/github/stars/MlSebrell/amthoneypot.svg) ![forks](https://img.shields.io/github/forks/MlSebrell/amthoneypot.svg)


## CVE-2015-7858
 SQL injection vulnerability in Joomla! 3.2 before 3.4.4 allows remote attackers to execute arbitrary SQL commands via unspecified vectors, a different vulnerability than CVE-2015-7297.

- [https://github.com/CCrashBandicot/ContentHistory](https://github.com/CCrashBandicot/ContentHistory) :  ![starts](https://img.shields.io/github/stars/CCrashBandicot/ContentHistory.svg) ![forks](https://img.shields.io/github/forks/CCrashBandicot/ContentHistory.svg)
- [https://github.com/areaventuno/exploit-joomla](https://github.com/areaventuno/exploit-joomla) :  ![starts](https://img.shields.io/github/stars/areaventuno/exploit-joomla.svg) ![forks](https://img.shields.io/github/forks/areaventuno/exploit-joomla.svg)


## CVE-2015-7857
 SQL injection vulnerability in the getListQuery function in administrator/components/com_contenthistory/models/history.php in Joomla! 3.2 before 3.4.5 allows remote attackers to execute arbitrary SQL commands via the list[select] parameter to index.php.

- [https://github.com/CCrashBandicot/ContentHistory](https://github.com/CCrashBandicot/ContentHistory) :  ![starts](https://img.shields.io/github/stars/CCrashBandicot/ContentHistory.svg) ![forks](https://img.shields.io/github/forks/CCrashBandicot/ContentHistory.svg)
- [https://github.com/areaventuno/exploit-joomla](https://github.com/areaventuno/exploit-joomla) :  ![starts](https://img.shields.io/github/stars/areaventuno/exploit-joomla.svg) ![forks](https://img.shields.io/github/forks/areaventuno/exploit-joomla.svg)


## CVE-2015-7756
 The encryption implementation in Juniper ScreenOS 6.2.0r15 through 6.2.0r18, 6.3.0r12 before 6.3.0r12b, 6.3.0r13 before 6.3.0r13b, 6.3.0r14 before 6.3.0r14b, 6.3.0r15 before 6.3.0r15b, 6.3.0r16 before 6.3.0r16b, 6.3.0r17 before 6.3.0r17b, 6.3.0r18 before 6.3.0r18b, 6.3.0r19 before 6.3.0r19b, and 6.3.0r20 before 6.3.0r21 makes it easier for remote attackers to discover the plaintext content of VPN sessions by sniffing the network for ciphertext data and conducting an unspecified decryption attack.

- [https://github.com/hdm/juniper-cve-2015-7755](https://github.com/hdm/juniper-cve-2015-7755) :  ![starts](https://img.shields.io/github/stars/hdm/juniper-cve-2015-7755.svg) ![forks](https://img.shields.io/github/forks/hdm/juniper-cve-2015-7755.svg)


## CVE-2015-7755
 Juniper ScreenOS 6.2.0r15 through 6.2.0r18, 6.3.0r12 before 6.3.0r12b, 6.3.0r13 before 6.3.0r13b, 6.3.0r14 before 6.3.0r14b, 6.3.0r15 before 6.3.0r15b, 6.3.0r16 before 6.3.0r16b, 6.3.0r17 before 6.3.0r17b, 6.3.0r18 before 6.3.0r18b, 6.3.0r19 before 6.3.0r19b, and 6.3.0r20 before 6.3.0r21 allows remote attackers to obtain administrative access by entering an unspecified password during a (1) SSH or (2) TELNET session.

- [https://github.com/hdm/juniper-cve-2015-7755](https://github.com/hdm/juniper-cve-2015-7755) :  ![starts](https://img.shields.io/github/stars/hdm/juniper-cve-2015-7755.svg) ![forks](https://img.shields.io/github/forks/hdm/juniper-cve-2015-7755.svg)
- [https://github.com/cinno/CVE-2015-7755-POC](https://github.com/cinno/CVE-2015-7755-POC) :  ![starts](https://img.shields.io/github/stars/cinno/CVE-2015-7755-POC.svg) ![forks](https://img.shields.io/github/forks/cinno/CVE-2015-7755-POC.svg)


## CVE-2015-7576
 The http_basic_authenticate_with method in actionpack/lib/action_controller/metal/http_authentication.rb in the Basic Authentication implementation in Action Controller in Ruby on Rails before 3.2.22.1, 4.0.x and 4.1.x before 4.1.14.1, 4.2.x before 4.2.5.1, and 5.x before 5.0.0.beta1.1 does not use a constant-time algorithm for verifying credentials, which makes it easier for remote attackers to bypass authentication by measuring timing differences.

- [https://github.com/yield-c/CVE2015-7576](https://github.com/yield-c/CVE2015-7576) :  ![starts](https://img.shields.io/github/stars/yield-c/CVE2015-7576.svg) ![forks](https://img.shields.io/github/forks/yield-c/CVE2015-7576.svg)


## CVE-2015-7547
 Multiple stack-based buffer overflows in the (1) send_dg and (2) send_vc functions in the libresolv library in the GNU C Library (aka glibc or libc6) before 2.23 allow remote attackers to cause a denial of service (crash) or possibly execute arbitrary code via a crafted DNS response that triggers a call to the getaddrinfo function with the AF_UNSPEC or AF_INET6 address family, related to performing "dual A/AAAA DNS queries" and the libnss_dns.so.2 NSS module.

- [https://github.com/fjserna/CVE-2015-7547](https://github.com/fjserna/CVE-2015-7547) :  ![starts](https://img.shields.io/github/stars/fjserna/CVE-2015-7547.svg) ![forks](https://img.shields.io/github/forks/fjserna/CVE-2015-7547.svg)
- [https://github.com/eSentire/cve-2015-7547-public](https://github.com/eSentire/cve-2015-7547-public) :  ![starts](https://img.shields.io/github/stars/eSentire/cve-2015-7547-public.svg) ![forks](https://img.shields.io/github/forks/eSentire/cve-2015-7547-public.svg)
- [https://github.com/jgajek/cve-2015-7547](https://github.com/jgajek/cve-2015-7547) :  ![starts](https://img.shields.io/github/stars/jgajek/cve-2015-7547.svg) ![forks](https://img.shields.io/github/forks/jgajek/cve-2015-7547.svg)
- [https://github.com/cakuzo/CVE-2015-7547](https://github.com/cakuzo/CVE-2015-7547) :  ![starts](https://img.shields.io/github/stars/cakuzo/CVE-2015-7547.svg) ![forks](https://img.shields.io/github/forks/cakuzo/CVE-2015-7547.svg)
- [https://github.com/t0r0t0r0/CVE-2015-7547](https://github.com/t0r0t0r0/CVE-2015-7547) :  ![starts](https://img.shields.io/github/stars/t0r0t0r0/CVE-2015-7547.svg) ![forks](https://img.shields.io/github/forks/t0r0t0r0/CVE-2015-7547.svg)
- [https://github.com/Stick-U235/CVE-2015-7547-Research](https://github.com/Stick-U235/CVE-2015-7547-Research) :  ![starts](https://img.shields.io/github/stars/Stick-U235/CVE-2015-7547-Research.svg) ![forks](https://img.shields.io/github/forks/Stick-U235/CVE-2015-7547-Research.svg)
- [https://github.com/Amilaperera12/Glibc-Vulnerability-Exploit-CVE-2015-7547](https://github.com/Amilaperera12/Glibc-Vulnerability-Exploit-CVE-2015-7547) :  ![starts](https://img.shields.io/github/stars/Amilaperera12/Glibc-Vulnerability-Exploit-CVE-2015-7547.svg) ![forks](https://img.shields.io/github/forks/Amilaperera12/Glibc-Vulnerability-Exploit-CVE-2015-7547.svg)
- [https://github.com/babykillerblack/CVE-2015-7547](https://github.com/babykillerblack/CVE-2015-7547) :  ![starts](https://img.shields.io/github/stars/babykillerblack/CVE-2015-7547.svg) ![forks](https://img.shields.io/github/forks/babykillerblack/CVE-2015-7547.svg)
- [https://github.com/miracle03/CVE-2015-7547-master](https://github.com/miracle03/CVE-2015-7547-master) :  ![starts](https://img.shields.io/github/stars/miracle03/CVE-2015-7547-master.svg) ![forks](https://img.shields.io/github/forks/miracle03/CVE-2015-7547-master.svg)
- [https://github.com/bluebluelan/CVE-2015-7547-proj-master](https://github.com/bluebluelan/CVE-2015-7547-proj-master) :  ![starts](https://img.shields.io/github/stars/bluebluelan/CVE-2015-7547-proj-master.svg) ![forks](https://img.shields.io/github/forks/bluebluelan/CVE-2015-7547-proj-master.svg)
- [https://github.com/rexifiles/rex-sec-glibc](https://github.com/rexifiles/rex-sec-glibc) :  ![starts](https://img.shields.io/github/stars/rexifiles/rex-sec-glibc.svg) ![forks](https://img.shields.io/github/forks/rexifiles/rex-sec-glibc.svg)


## CVE-2015-7545
 The (1) git-remote-ext and (2) unspecified other remote helper programs in Git before 2.3.10, 2.4.x before 2.4.10, 2.5.x before 2.5.4, and 2.6.x before 2.6.1 do not properly restrict the allowed protocols, which might allow remote attackers to execute arbitrary code via a URL in a (a) .gitmodules file or (b) unknown other sources in a submodule.

- [https://github.com/avuserow/bug-free-chainsaw](https://github.com/avuserow/bug-free-chainsaw) :  ![starts](https://img.shields.io/github/stars/avuserow/bug-free-chainsaw.svg) ![forks](https://img.shields.io/github/forks/avuserow/bug-free-chainsaw.svg)


## CVE-2015-7501
 Red Hat JBoss A-MQ 6.x; BPM Suite (BPMS) 6.x; BRMS 6.x and 5.x; Data Grid (JDG) 6.x; Data Virtualization (JDV) 6.x and 5.x; Enterprise Application Platform 6.x, 5.x, and 4.3.x; Fuse 6.x; Fuse Service Works (FSW) 6.x; Operations Network (JBoss ON) 3.x; Portal 6.x; SOA Platform (SOA-P) 5.x; Web Server (JWS) 3.x; Red Hat OpenShift/xPAAS 3.x; and Red Hat Subscription Asset Manager 1.3 allow remote attackers to execute arbitrary commands via a crafted serialized Java object, related to the Apache Commons Collections (ACC) library.

- [https://github.com/ianxtianxt/CVE-2015-7501](https://github.com/ianxtianxt/CVE-2015-7501) :  ![starts](https://img.shields.io/github/stars/ianxtianxt/CVE-2015-7501.svg) ![forks](https://img.shields.io/github/forks/ianxtianxt/CVE-2015-7501.svg)


## CVE-2015-7297
 SQL injection vulnerability in Joomla! 3.2 before 3.4.4 allows remote attackers to execute arbitrary SQL commands via unspecified vectors, a different vulnerability than CVE-2015-7858.

- [https://github.com/CCrashBandicot/ContentHistory](https://github.com/CCrashBandicot/ContentHistory) :  ![starts](https://img.shields.io/github/stars/CCrashBandicot/ContentHistory.svg) ![forks](https://img.shields.io/github/forks/CCrashBandicot/ContentHistory.svg)
- [https://github.com/Cappricio-Securities/CVE-2015-7297](https://github.com/Cappricio-Securities/CVE-2015-7297) :  ![starts](https://img.shields.io/github/stars/Cappricio-Securities/CVE-2015-7297.svg) ![forks](https://img.shields.io/github/forks/Cappricio-Securities/CVE-2015-7297.svg)
- [https://github.com/areaventuno/exploit-joomla](https://github.com/areaventuno/exploit-joomla) :  ![starts](https://img.shields.io/github/stars/areaventuno/exploit-joomla.svg) ![forks](https://img.shields.io/github/forks/areaventuno/exploit-joomla.svg)


## CVE-2015-7214
 Mozilla Firefox before 43.0 and Firefox ESR 38.x before 38.5 allow remote attackers to bypass the Same Origin Policy via data: and view-source: URIs.

- [https://github.com/llamakko/CVE-2015-7214](https://github.com/llamakko/CVE-2015-7214) :  ![starts](https://img.shields.io/github/stars/llamakko/CVE-2015-7214.svg) ![forks](https://img.shields.io/github/forks/llamakko/CVE-2015-7214.svg)


## CVE-2015-4870
 Unspecified vulnerability in Oracle MySQL Server 5.5.45 and earlier, and 5.6.26 and earlier, allows remote authenticated users to affect availability via unknown vectors related to Server : Parser.

- [https://github.com/OsandaMalith/CVE-2015-4870](https://github.com/OsandaMalith/CVE-2015-4870) :  ![starts](https://img.shields.io/github/stars/OsandaMalith/CVE-2015-4870.svg) ![forks](https://img.shields.io/github/forks/OsandaMalith/CVE-2015-4870.svg)


## CVE-2015-4133
 Unrestricted file upload vulnerability in admin/scripts/FileUploader/php.php in the ReFlex Gallery plugin before 3.1.4 for WordPress allows remote attackers to execute arbitrary PHP code by uploading a file with a PHP extension, then accessing it via a direct request to the file in uploads/ directory.

- [https://github.com/sug4r-wr41th/CVE-2015-4133](https://github.com/sug4r-wr41th/CVE-2015-4133) :  ![starts](https://img.shields.io/github/stars/sug4r-wr41th/CVE-2015-4133.svg) ![forks](https://img.shields.io/github/forks/sug4r-wr41th/CVE-2015-4133.svg)


## CVE-2015-4000
 The TLS protocol 1.2 and earlier, when a DHE_EXPORT ciphersuite is enabled on a server but not on a client, does not properly convey a DHE_EXPORT choice, which allows man-in-the-middle attackers to conduct cipher-downgrade attacks by rewriting a ClientHello with DHE replaced by DHE_EXPORT and then rewriting a ServerHello with DHE_EXPORT replaced by DHE, aka the "Logjam" issue.

- [https://github.com/fatlan/HAProxy-Keepalived-Sec-HighLoads](https://github.com/fatlan/HAProxy-Keepalived-Sec-HighLoads) :  ![starts](https://img.shields.io/github/stars/fatlan/HAProxy-Keepalived-Sec-HighLoads.svg) ![forks](https://img.shields.io/github/forks/fatlan/HAProxy-Keepalived-Sec-HighLoads.svg)
- [https://github.com/anthophilee/A2SV--SSL-VUL-Scan](https://github.com/anthophilee/A2SV--SSL-VUL-Scan) :  ![starts](https://img.shields.io/github/stars/anthophilee/A2SV--SSL-VUL-Scan.svg) ![forks](https://img.shields.io/github/forks/anthophilee/A2SV--SSL-VUL-Scan.svg)


## CVE-2011-0762
 The vsf_filename_passes_filter function in ls.c in vsftpd before 2.3.3 allows remote authenticated users to cause a denial of service (CPU consumption and process slot exhaustion) via crafted glob expressions in STAT commands in multiple FTP sessions, a different vulnerability than CVE-2010-2632.

- [https://github.com/AndreyFreitax/CVE-2011-0762](https://github.com/AndreyFreitax/CVE-2011-0762) :  ![starts](https://img.shields.io/github/stars/AndreyFreitax/CVE-2011-0762.svg) ![forks](https://img.shields.io/github/forks/AndreyFreitax/CVE-2011-0762.svg)

