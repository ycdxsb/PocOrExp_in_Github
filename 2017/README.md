## CVE-2017-20165
 A vulnerability classified as problematic has been found in debug-js debug up to 3.0.x. This affects the function useColors of the file src/node.js. The manipulation of the argument str leads to inefficient regular expression complexity. Upgrading to version 3.1.0 is able to address this issue. The identifier of the patch is c38a0166c266a679c8de012d4eaccec3f944e685. It is recommended to upgrade the affected component. The identifier VDB-217665 was assigned to this vulnerability.



- [https://github.com/fastify/send](https://github.com/fastify/send) :  ![starts](https://img.shields.io/github/stars/fastify/send.svg) ![forks](https://img.shields.io/github/forks/fastify/send.svg)

## CVE-2017-18635
 An XSS vulnerability was discovered in noVNC before 0.6.2 in which the remote VNC server could inject arbitrary HTML into the noVNC web page via the messages propagated to the status field, such as the VNC server name.



- [https://github.com/ShielderSec/CVE-2017-18635](https://github.com/ShielderSec/CVE-2017-18635) :  ![starts](https://img.shields.io/github/stars/ShielderSec/CVE-2017-18635.svg) ![forks](https://img.shields.io/github/forks/ShielderSec/CVE-2017-18635.svg)

- [https://github.com/ossf-cve-benchmark/CVE-2017-18635](https://github.com/ossf-cve-benchmark/CVE-2017-18635) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-18635.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-18635.svg)

## CVE-2017-18486
 Jitbit Helpdesk before 9.0.3 allows remote attackers to escalate privileges because of mishandling of the User/AutoLogin userHash parameter. By inspecting the token value provided in a password reset link, a user can leverage a weak PRNG to recover the shared secret used by the server for remote authentication. The shared secret can be used to escalate privileges by forging new tokens for any user. These tokens can be used to automatically log in as the affected user.



- [https://github.com/Kc57/JitBit_Helpdesk_Auth_Bypass](https://github.com/Kc57/JitBit_Helpdesk_Auth_Bypass) :  ![starts](https://img.shields.io/github/stars/Kc57/JitBit_Helpdesk_Auth_Bypass.svg) ![forks](https://img.shields.io/github/forks/Kc57/JitBit_Helpdesk_Auth_Bypass.svg)

## CVE-2017-18355
 Installed packages are exposed by node_modules in Rendertron 1.0.0, allowing remote attackers to read absolute paths on the server by examining the &quot;_where&quot; attribute of package.json files.



- [https://github.com/ossf-cve-benchmark/CVE-2017-18355](https://github.com/ossf-cve-benchmark/CVE-2017-18355) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-18355.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-18355.svg)

## CVE-2017-18354
 Rendertron 1.0.0 allows for alternative protocols such as 'file://' introducing a Local File Inclusion (LFI) bug where arbitrary files can be read by a remote attacker.



- [https://github.com/ossf-cve-benchmark/CVE-2017-18354](https://github.com/ossf-cve-benchmark/CVE-2017-18354) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-18354.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-18354.svg)

## CVE-2017-18353
 Rendertron 1.0.0 includes an _ah/stop route to shutdown the Chrome instance responsible for serving render requests to all users. Visiting this route with a GET request allows any unauthorized remote attacker to disable the core service of the application.



- [https://github.com/ossf-cve-benchmark/CVE-2017-18353](https://github.com/ossf-cve-benchmark/CVE-2017-18353) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-18353.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-18353.svg)

## CVE-2017-18047
 Buffer Overflow in the FTP client in LabF nfsAxe 3.7 allows remote FTP servers to execute arbitrary code via a long reply.



- [https://github.com/wetw0rk/Exploit-Development](https://github.com/wetw0rk/Exploit-Development) :  ![starts](https://img.shields.io/github/stars/wetw0rk/Exploit-Development.svg) ![forks](https://img.shields.io/github/forks/wetw0rk/Exploit-Development.svg)

## CVE-2017-18044
 A Command Injection issue was discovered in ContentStore/Base/CVDataPipe.dll in Commvault before v11 SP6. A certain message parsing function inside the Commvault service does not properly validate the input of an incoming string before passing it to CreateProcess. As a result, a specially crafted message can inject commands that will be executed on the target operating system. Exploitation of this vulnerability does not require authentication and can lead to SYSTEM level privilege on any system running the cvd daemon. This is a different vulnerability than CVE-2017-3195.



- [https://github.com/securifera/CVE-2017-18044-Exploit](https://github.com/securifera/CVE-2017-18044-Exploit) :  ![starts](https://img.shields.io/github/stars/securifera/CVE-2017-18044-Exploit.svg) ![forks](https://img.shields.io/github/forks/securifera/CVE-2017-18044-Exploit.svg)

## CVE-2017-18019
 In K7 Total Security before 15.1.0.305, user-controlled input to the K7Sentry device is not sufficiently sanitized: the user-controlled input can be used to compare an arbitrary memory address with a fixed value, which in turn can be used to read the contents of arbitrary memory. Similarly, the product crashes upon a \\.\K7Sentry DeviceIoControl call with an invalid kernel pointer.



- [https://github.com/SpiralBL0CK/CVE-2017-18019](https://github.com/SpiralBL0CK/CVE-2017-18019) :  ![starts](https://img.shields.io/github/stars/SpiralBL0CK/CVE-2017-18019.svg) ![forks](https://img.shields.io/github/forks/SpiralBL0CK/CVE-2017-18019.svg)

## CVE-2017-17917
 ** DISPUTED ** SQL injection vulnerability in the 'where' method in Ruby on Rails 5.1.4 and earlier allows remote attackers to execute arbitrary SQL commands via the 'id' parameter. NOTE: The vendor disputes this issue because the documentation states that this method is not intended for use with untrusted input.



- [https://github.com/matiasarenhard/rails-cve-2017-17917](https://github.com/matiasarenhard/rails-cve-2017-17917) :  ![starts](https://img.shields.io/github/stars/matiasarenhard/rails-cve-2017-17917.svg) ![forks](https://img.shields.io/github/forks/matiasarenhard/rails-cve-2017-17917.svg)

## CVE-2017-17736
 Kentico 9.0 before 9.0.51 and 10.0 before 10.0.48 allows remote attackers to obtain Global Administrator access by visiting CMSInstall/install.aspx and then navigating to the CMS Administration Dashboard.



- [https://github.com/0xSojalSec/Nuclei-TemplatesNuclei-Templates-CVE-2017-17736](https://github.com/0xSojalSec/Nuclei-TemplatesNuclei-Templates-CVE-2017-17736) :  ![starts](https://img.shields.io/github/stars/0xSojalSec/Nuclei-TemplatesNuclei-Templates-CVE-2017-17736.svg) ![forks](https://img.shields.io/github/forks/0xSojalSec/Nuclei-TemplatesNuclei-Templates-CVE-2017-17736.svg)

## CVE-2017-17309
 Huawei HG255s-10 V100R001C163B025SP02 has a path traversal vulnerability due to insufficient validation of the received HTTP requests, a remote attacker may access the local files on the device without authentication.



- [https://github.com/exploit-labs/huawei_hg255s_exploit](https://github.com/exploit-labs/huawei_hg255s_exploit) :  ![starts](https://img.shields.io/github/stars/exploit-labs/huawei_hg255s_exploit.svg) ![forks](https://img.shields.io/github/forks/exploit-labs/huawei_hg255s_exploit.svg)

## CVE-2017-17099
 There exists an unauthenticated SEH based Buffer Overflow vulnerability in the HTTP server of Flexense SyncBreeze Enterprise v10.1.16. When sending a GET request with an excessive length, it is possible for a malicious user to overwrite the SEH record and execute a payload that would run under the Windows SYSTEM account.



- [https://github.com/wetw0rk/Exploit-Development](https://github.com/wetw0rk/Exploit-Development) :  ![starts](https://img.shields.io/github/stars/wetw0rk/Exploit-Development.svg) ![forks](https://img.shields.io/github/forks/wetw0rk/Exploit-Development.svg)

## CVE-2017-17058
 ** DISPUTED ** The WooCommerce plugin through 3.x for WordPress has a Directory Traversal Vulnerability via a /wp-content/plugins/woocommerce/templates/emails/plain/ URI, which accesses a parent directory. NOTE: a software maintainer indicates that Directory Traversal is not possible because all of the template files have &quot;if (!defined('ABSPATH')) {exit;}&quot; code.



- [https://github.com/fu2x2000/CVE-2017-17058-woo_exploit](https://github.com/fu2x2000/CVE-2017-17058-woo_exploit) :  ![starts](https://img.shields.io/github/stars/fu2x2000/CVE-2017-17058-woo_exploit.svg) ![forks](https://img.shields.io/github/forks/fu2x2000/CVE-2017-17058-woo_exploit.svg)

## CVE-2017-16997
 elf/dl-load.c in the GNU C Library (aka glibc or libc6) 2.19 through 2.26 mishandles RPATH and RUNPATH containing $ORIGIN for a privileged (setuid or AT_SECURE) program, which allows local users to gain privileges via a Trojan horse library in the current working directory, related to the fillin_rpath and decompose_rpath functions. This is associated with misinterpretion of an empty RPATH/RUNPATH token as the &quot;./&quot; directory. NOTE: this configuration of RPATH/RUNPATH for a privileged program is apparently very uncommon; most likely, no such program is shipped with any common Linux distribution.



- [https://github.com/Xiami2012/CVE-2017-16997-poc](https://github.com/Xiami2012/CVE-2017-16997-poc) :  ![starts](https://img.shields.io/github/stars/Xiami2012/CVE-2017-16997-poc.svg) ![forks](https://img.shields.io/github/forks/Xiami2012/CVE-2017-16997-poc.svg)

## CVE-2017-16994
 The walk_hugetlb_range function in mm/pagewalk.c in the Linux kernel before 4.14.2 mishandles holes in hugetlb ranges, which allows local users to obtain sensitive information from uninitialized kernel memory via crafted use of the mincore() system call.



- [https://github.com/jedai47/CVE-2017-16994](https://github.com/jedai47/CVE-2017-16994) :  ![starts](https://img.shields.io/github/stars/jedai47/CVE-2017-16994.svg) ![forks](https://img.shields.io/github/forks/jedai47/CVE-2017-16994.svg)

## CVE-2017-16930
 The remote management interface on the Claymore Dual GPU miner 10.1 allows an unauthenticated remote attacker to execute arbitrary code due to a stack-based buffer overflow in the request handler. This can be exploited via a long API request that is mishandled during logging.



- [https://github.com/tintinweb/pub](https://github.com/tintinweb/pub) :  ![starts](https://img.shields.io/github/stars/tintinweb/pub.svg) ![forks](https://img.shields.io/github/forks/tintinweb/pub.svg)

## CVE-2017-16877
 ZEIT Next.js before 2.4.1 has directory traversal under the /_next and /static request namespace, allowing attackers to obtain sensitive information.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16877](https://github.com/ossf-cve-benchmark/CVE-2017-16877) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16877.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16877.svg)

## CVE-2017-16806
 The Process function in RemoteTaskServer/WebServer/HttpServer.cs in Ulterius before 1.9.5.0 allows HTTP server directory traversal.



- [https://github.com/rickoooooo/ulteriusExploit](https://github.com/rickoooooo/ulteriusExploit) :  ![starts](https://img.shields.io/github/stars/rickoooooo/ulteriusExploit.svg) ![forks](https://img.shields.io/github/forks/rickoooooo/ulteriusExploit.svg)

## CVE-2017-16748
 An attacker can log into the local Niagara platform (Niagara AX Framework Versions 3.8 and prior or Niagara 4 Framework Versions 4.4 and prior) using a disabled account name and a blank password, granting the attacker administrator access to the Niagara system.



- [https://github.com/GainSec/CVE-2017-16744-and-CVE-2017-16748-Tridium-Niagara](https://github.com/GainSec/CVE-2017-16744-and-CVE-2017-16748-Tridium-Niagara) :  ![starts](https://img.shields.io/github/stars/GainSec/CVE-2017-16744-and-CVE-2017-16748-Tridium-Niagara.svg) ![forks](https://img.shields.io/github/forks/GainSec/CVE-2017-16744-and-CVE-2017-16748-Tridium-Niagara.svg)

## CVE-2017-16651
 Roundcube Webmail before 1.1.10, 1.2.x before 1.2.7, and 1.3.x before 1.3.3 allows unauthorized access to arbitrary files on the host's filesystem, including configuration files, as exploited in the wild in November 2017. The attacker must be able to authenticate at the target system with a valid username/password as the attack requires an active session. The issue is related to file-based attachment plugins and _task=settings&amp;_action=upload-display&amp;_from=timezone requests.



- [https://github.com/starnightcyber/Exploit-Database-For-Webmail](https://github.com/starnightcyber/Exploit-Database-For-Webmail) :  ![starts](https://img.shields.io/github/stars/starnightcyber/Exploit-Database-For-Webmail.svg) ![forks](https://img.shields.io/github/forks/starnightcyber/Exploit-Database-For-Webmail.svg)

- [https://github.com/ropbear/CVE-2017-16651](https://github.com/ropbear/CVE-2017-16651) :  ![starts](https://img.shields.io/github/stars/ropbear/CVE-2017-16651.svg) ![forks](https://img.shields.io/github/forks/ropbear/CVE-2017-16651.svg)

- [https://github.com/sephiroth950911/CVE-2017-16651-Exploit](https://github.com/sephiroth950911/CVE-2017-16651-Exploit) :  ![starts](https://img.shields.io/github/stars/sephiroth950911/CVE-2017-16651-Exploit.svg) ![forks](https://img.shields.io/github/forks/sephiroth950911/CVE-2017-16651-Exploit.svg)

## CVE-2017-16541
 Tor Browser before 7.0.9 on macOS and Linux allows remote attackers to bypass the intended anonymity feature and discover a client IP address via vectors involving a crafted web site that leverages file:// mishandling in Firefox, aka TorMoil. NOTE: Tails is unaffected.



- [https://github.com/Ethan-Chen-uwo/A-breif-introduction-of-CVE-2017-16541](https://github.com/Ethan-Chen-uwo/A-breif-introduction-of-CVE-2017-16541) :  ![starts](https://img.shields.io/github/stars/Ethan-Chen-uwo/A-breif-introduction-of-CVE-2017-16541.svg) ![forks](https://img.shields.io/github/forks/Ethan-Chen-uwo/A-breif-introduction-of-CVE-2017-16541.svg)

## CVE-2017-16524
 Web Viewer 1.0.0.193 on Samsung SRN-1670D devices suffers from an Unrestricted file upload vulnerability: 'network_ssl_upload.php' allows remote authenticated attackers to upload and execute arbitrary PHP code via a filename with a .php extension, which is then accessed via a direct request to the file in the upload/ directory. To authenticate for this attack, one can obtain web-interface credentials in cleartext by leveraging the existing Local File Read Vulnerability referenced as CVE-2015-8279, which allows remote attackers to read the web-interface credentials via a request for the cslog_export.php?path=/root/php_modules/lighttpd/sbin/userpw URI.



- [https://github.com/realistic-security/CVE-2017-16524](https://github.com/realistic-security/CVE-2017-16524) :  ![starts](https://img.shields.io/github/stars/realistic-security/CVE-2017-16524.svg) ![forks](https://img.shields.io/github/forks/realistic-security/CVE-2017-16524.svg)

## CVE-2017-16137
 The debug module is vulnerable to regular expression denial of service when untrusted user input is passed into the o formatter. It takes around 50k characters to block for 2 seconds making this a low severity issue.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16137](https://github.com/ossf-cve-benchmark/CVE-2017-16137) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16137.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16137.svg)

## CVE-2017-16119
 Fresh is a module used by the Express.js framework for HTTP response freshness testing. It is vulnerable to a regular expression denial of service when it is passed specially crafted input to parse. This causes the event loop to be blocked causing a denial of service condition.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16119](https://github.com/ossf-cve-benchmark/CVE-2017-16119) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16119.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16119.svg)

## CVE-2017-16030
 Useragent is used to parse useragent headers. It uses several regular expressions to accomplish this. An attacker could edit their own headers, creating an arbitrarily long useragent string, causing the event loop and server to block. This affects Useragent 2.1.12 and earlier.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16030](https://github.com/ossf-cve-benchmark/CVE-2017-16030) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16030.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16030.svg)

## CVE-2017-16014
 Http-proxy is a proxying library. Because of the way errors are handled in versions before 0.7.0, an attacker that forces an error can crash the server, causing a denial of service.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16014](https://github.com/ossf-cve-benchmark/CVE-2017-16014) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16014.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16014.svg)

## CVE-2017-16011
 ** RE



- [https://github.com/ossf-cve-benchmark/CVE-2017-16011](https://github.com/ossf-cve-benchmark/CVE-2017-16011) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16011.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16011.svg)

## CVE-2017-15120
 An issue has been found in the parsing of authoritative answers in PowerDNS Recursor before 4.0.8, leading to a NULL pointer dereference when parsing a specially crafted answer containing a CNAME of a different class than IN. An unauthenticated remote attacker could cause a denial of service.



- [https://github.com/shutingrz/CVE-2017-15120_PoC](https://github.com/shutingrz/CVE-2017-15120_PoC) :  ![starts](https://img.shields.io/github/stars/shutingrz/CVE-2017-15120_PoC.svg) ![forks](https://img.shields.io/github/forks/shutingrz/CVE-2017-15120_PoC.svg)

## CVE-2017-14980
 Buffer overflow in Sync Breeze Enterprise 10.0.28 allows remote attackers to have unspecified impact via a long username parameter to /login.



- [https://github.com/TheDarthMole/CVE-2017-14980](https://github.com/TheDarthMole/CVE-2017-14980) :  ![starts](https://img.shields.io/github/stars/TheDarthMole/CVE-2017-14980.svg) ![forks](https://img.shields.io/github/forks/TheDarthMole/CVE-2017-14980.svg)

## CVE-2017-9999
 ** RE



- [https://github.com/homjxi0e/CVE-2017-9999_bypassing_General_Firefox](https://github.com/homjxi0e/CVE-2017-9999_bypassing_General_Firefox) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-9999_bypassing_General_Firefox.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-9999_bypassing_General_Firefox.svg)

## CVE-2017-9947
 A vulnerability has been identified in Siemens APOGEE PXC and TALON TC BACnet Automation Controllers in all versions &lt;V3.5. A directory traversal vulnerability could allow a remote attacker with network access to the integrated web server (80/tcp and 443/tcp) to obtain information on the structure of the file system of the affected devices.



- [https://github.com/RoseSecurity/APOLOGEE](https://github.com/RoseSecurity/APOLOGEE) :  ![starts](https://img.shields.io/github/stars/RoseSecurity/APOLOGEE.svg) ![forks](https://img.shields.io/github/forks/RoseSecurity/APOLOGEE.svg)

## CVE-2017-9934
 Missing CSRF token checks and improper input validation in Joomla! CMS 1.7.3 through 3.7.2 lead to an XSS vulnerability.



- [https://github.com/xyringe/CVE-2017-9934](https://github.com/xyringe/CVE-2017-9934) :  ![starts](https://img.shields.io/github/stars/xyringe/CVE-2017-9934.svg) ![forks](https://img.shields.io/github/forks/xyringe/CVE-2017-9934.svg)

## CVE-2017-9841
 Util/PHP/eval-stdin.php in PHPUnit before 4.8.28 and 5.x before 5.6.3 allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a &quot;&lt;?php &quot; substring, as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.



- [https://github.com/RandomRobbieBF/phpunit-brute](https://github.com/RandomRobbieBF/phpunit-brute) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/phpunit-brute.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/phpunit-brute.svg)

- [https://github.com/incogbyte/laravel-phpunit-rce-masscaner](https://github.com/incogbyte/laravel-phpunit-rce-masscaner) :  ![starts](https://img.shields.io/github/stars/incogbyte/laravel-phpunit-rce-masscaner.svg) ![forks](https://img.shields.io/github/forks/incogbyte/laravel-phpunit-rce-masscaner.svg)

- [https://github.com/ludy-dev/PHPUnit_eval-stdin_RCE](https://github.com/ludy-dev/PHPUnit_eval-stdin_RCE) :  ![starts](https://img.shields.io/github/stars/ludy-dev/PHPUnit_eval-stdin_RCE.svg) ![forks](https://img.shields.io/github/forks/ludy-dev/PHPUnit_eval-stdin_RCE.svg)

- [https://github.com/MadExploits/PHPunit-Exploit](https://github.com/MadExploits/PHPunit-Exploit) :  ![starts](https://img.shields.io/github/stars/MadExploits/PHPunit-Exploit.svg) ![forks](https://img.shields.io/github/forks/MadExploits/PHPunit-Exploit.svg)

- [https://github.com/Chocapikk/CVE-2017-9841](https://github.com/Chocapikk/CVE-2017-9841) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2017-9841.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2017-9841.svg)

- [https://github.com/MrG3P5/CVE-2017-9841](https://github.com/MrG3P5/CVE-2017-9841) :  ![starts](https://img.shields.io/github/stars/MrG3P5/CVE-2017-9841.svg) ![forks](https://img.shields.io/github/forks/MrG3P5/CVE-2017-9841.svg)

- [https://github.com/akr3ch/CVE-2017-9841](https://github.com/akr3ch/CVE-2017-9841) :  ![starts](https://img.shields.io/github/stars/akr3ch/CVE-2017-9841.svg) ![forks](https://img.shields.io/github/forks/akr3ch/CVE-2017-9841.svg)

- [https://github.com/p1ckzi/CVE-2017-9841](https://github.com/p1ckzi/CVE-2017-9841) :  ![starts](https://img.shields.io/github/stars/p1ckzi/CVE-2017-9841.svg) ![forks](https://img.shields.io/github/forks/p1ckzi/CVE-2017-9841.svg)

- [https://github.com/dream434/CVE-2017-9841-](https://github.com/dream434/CVE-2017-9841-) :  ![starts](https://img.shields.io/github/stars/dream434/CVE-2017-9841-.svg) ![forks](https://img.shields.io/github/forks/dream434/CVE-2017-9841-.svg)

- [https://github.com/mbrasile/CVE-2017-9841](https://github.com/mbrasile/CVE-2017-9841) :  ![starts](https://img.shields.io/github/stars/mbrasile/CVE-2017-9841.svg) ![forks](https://img.shields.io/github/forks/mbrasile/CVE-2017-9841.svg)

- [https://github.com/jax7sec/CVE-2017-9841](https://github.com/jax7sec/CVE-2017-9841) :  ![starts](https://img.shields.io/github/stars/jax7sec/CVE-2017-9841.svg) ![forks](https://img.shields.io/github/forks/jax7sec/CVE-2017-9841.svg)

- [https://github.com/cyberharsh/Php-unit-CVE-2017-9841](https://github.com/cyberharsh/Php-unit-CVE-2017-9841) :  ![starts](https://img.shields.io/github/stars/cyberharsh/Php-unit-CVE-2017-9841.svg) ![forks](https://img.shields.io/github/forks/cyberharsh/Php-unit-CVE-2017-9841.svg)

- [https://github.com/mileticluka1/eval-stdin](https://github.com/mileticluka1/eval-stdin) :  ![starts](https://img.shields.io/github/stars/mileticluka1/eval-stdin.svg) ![forks](https://img.shields.io/github/forks/mileticluka1/eval-stdin.svg)

## CVE-2017-9833
 ** DISPUTED ** /cgi-bin/wapopen in Boa 0.94.14rc21 allows the injection of &quot;../..&quot; using the FILECAMERA variable (sent by GET) to read files with root privileges. NOTE: multiple third parties report that this is a system-integrator issue (e.g., a vulnerability on one type of camera) because Boa does not include any wapopen program or any code to read a FILECAMERA variable.



- [https://github.com/anldori/CVE-2017-9833](https://github.com/anldori/CVE-2017-9833) :  ![starts](https://img.shields.io/github/stars/anldori/CVE-2017-9833.svg) ![forks](https://img.shields.io/github/forks/anldori/CVE-2017-9833.svg)

## CVE-2017-9830
 Remote Code Execution is possible in Code42 CrashPlan 5.4.x via the org.apache.commons.ssl.rmi.DateRMI Java class, because (upon instantiation) it creates an RMI server that listens on a TCP port and deserializes objects sent by TCP clients.



- [https://github.com/securifera/CVE-2017-9830](https://github.com/securifera/CVE-2017-9830) :  ![starts](https://img.shields.io/github/stars/securifera/CVE-2017-9830.svg) ![forks](https://img.shields.io/github/forks/securifera/CVE-2017-9830.svg)

## CVE-2017-9822
 DNN (aka DotNetNuke) before 9.1.1 has Remote Code Execution via a cookie, aka &quot;2017-08 (Critical) Possible remote code execution on DNN sites.&quot;



- [https://github.com/murataydemir/CVE-2017-9822](https://github.com/murataydemir/CVE-2017-9822) :  ![starts](https://img.shields.io/github/stars/murataydemir/CVE-2017-9822.svg) ![forks](https://img.shields.io/github/forks/murataydemir/CVE-2017-9822.svg)

## CVE-2017-9805
 The REST Plugin in Apache Struts 2.1.1 through 2.3.x before 2.3.34 and 2.5.x before 2.5.13 uses an XStreamHandler with an instance of XStream for deserialization without any type filtering, which can lead to Remote Code Execution when deserializing XML payloads.



- [https://github.com/mazen160/struts-pwn_CVE-2017-9805](https://github.com/mazen160/struts-pwn_CVE-2017-9805) :  ![starts](https://img.shields.io/github/stars/mazen160/struts-pwn_CVE-2017-9805.svg) ![forks](https://img.shields.io/github/forks/mazen160/struts-pwn_CVE-2017-9805.svg)

- [https://github.com/luc10/struts-rce-cve-2017-9805](https://github.com/luc10/struts-rce-cve-2017-9805) :  ![starts](https://img.shields.io/github/stars/luc10/struts-rce-cve-2017-9805.svg) ![forks](https://img.shields.io/github/forks/luc10/struts-rce-cve-2017-9805.svg)

- [https://github.com/chrisjd20/cve-2017-9805.py](https://github.com/chrisjd20/cve-2017-9805.py) :  ![starts](https://img.shields.io/github/stars/chrisjd20/cve-2017-9805.py.svg) ![forks](https://img.shields.io/github/forks/chrisjd20/cve-2017-9805.py.svg)

- [https://github.com/0x00-0x00/-CVE-2017-9805](https://github.com/0x00-0x00/-CVE-2017-9805) :  ![starts](https://img.shields.io/github/stars/0x00-0x00/-CVE-2017-9805.svg) ![forks](https://img.shields.io/github/forks/0x00-0x00/-CVE-2017-9805.svg)

- [https://github.com/Lone-Ranger/apache-struts-pwn_CVE-2017-9805](https://github.com/Lone-Ranger/apache-struts-pwn_CVE-2017-9805) :  ![starts](https://img.shields.io/github/stars/Lone-Ranger/apache-struts-pwn_CVE-2017-9805.svg) ![forks](https://img.shields.io/github/forks/Lone-Ranger/apache-struts-pwn_CVE-2017-9805.svg)

- [https://github.com/Shakun8/CVE-2017-9805](https://github.com/Shakun8/CVE-2017-9805) :  ![starts](https://img.shields.io/github/stars/Shakun8/CVE-2017-9805.svg) ![forks](https://img.shields.io/github/forks/Shakun8/CVE-2017-9805.svg)

- [https://github.com/hahwul/struts2-rce-cve-2017-9805-ruby](https://github.com/hahwul/struts2-rce-cve-2017-9805-ruby) :  ![starts](https://img.shields.io/github/stars/hahwul/struts2-rce-cve-2017-9805-ruby.svg) ![forks](https://img.shields.io/github/forks/hahwul/struts2-rce-cve-2017-9805-ruby.svg)

- [https://github.com/0xd3vil/CVE-2017-9805-Exploit](https://github.com/0xd3vil/CVE-2017-9805-Exploit) :  ![starts](https://img.shields.io/github/stars/0xd3vil/CVE-2017-9805-Exploit.svg) ![forks](https://img.shields.io/github/forks/0xd3vil/CVE-2017-9805-Exploit.svg)

- [https://github.com/BeyondCy/S2-052](https://github.com/BeyondCy/S2-052) :  ![starts](https://img.shields.io/github/stars/BeyondCy/S2-052.svg) ![forks](https://img.shields.io/github/forks/BeyondCy/S2-052.svg)

- [https://github.com/jongmartinez/-CVE-2017-9805-](https://github.com/jongmartinez/-CVE-2017-9805-) :  ![starts](https://img.shields.io/github/stars/jongmartinez/-CVE-2017-9805-.svg) ![forks](https://img.shields.io/github/forks/jongmartinez/-CVE-2017-9805-.svg)

- [https://github.com/UbuntuStrike/struts_rest_rce_fuzz-CVE-2017-9805-](https://github.com/UbuntuStrike/struts_rest_rce_fuzz-CVE-2017-9805-) :  ![starts](https://img.shields.io/github/stars/UbuntuStrike/struts_rest_rce_fuzz-CVE-2017-9805-.svg) ![forks](https://img.shields.io/github/forks/UbuntuStrike/struts_rest_rce_fuzz-CVE-2017-9805-.svg)

- [https://github.com/z3bd/CVE-2017-9805](https://github.com/z3bd/CVE-2017-9805) :  ![starts](https://img.shields.io/github/stars/z3bd/CVE-2017-9805.svg) ![forks](https://img.shields.io/github/forks/z3bd/CVE-2017-9805.svg)

- [https://github.com/wifido/CVE-2017-9805-Exploit](https://github.com/wifido/CVE-2017-9805-Exploit) :  ![starts](https://img.shields.io/github/stars/wifido/CVE-2017-9805-Exploit.svg) ![forks](https://img.shields.io/github/forks/wifido/CVE-2017-9805-Exploit.svg)

- [https://github.com/rvermeulen/apache-struts-cve-2017-9805](https://github.com/rvermeulen/apache-struts-cve-2017-9805) :  ![starts](https://img.shields.io/github/stars/rvermeulen/apache-struts-cve-2017-9805.svg) ![forks](https://img.shields.io/github/forks/rvermeulen/apache-struts-cve-2017-9805.svg)

- [https://github.com/sujithvaddi/apache_struts_cve_2017_9805](https://github.com/sujithvaddi/apache_struts_cve_2017_9805) :  ![starts](https://img.shields.io/github/stars/sujithvaddi/apache_struts_cve_2017_9805.svg) ![forks](https://img.shields.io/github/forks/sujithvaddi/apache_struts_cve_2017_9805.svg)

- [https://github.com/AvishkaSenadheera/CVE-2017-9805---Documentation---IT19143378](https://github.com/AvishkaSenadheera/CVE-2017-9805---Documentation---IT19143378) :  ![starts](https://img.shields.io/github/stars/AvishkaSenadheera/CVE-2017-9805---Documentation---IT19143378.svg) ![forks](https://img.shields.io/github/forks/AvishkaSenadheera/CVE-2017-9805---Documentation---IT19143378.svg)

- [https://github.com/UbuntuStrike/CVE-2017-9805-Apache-Struts-Fuzz-N-Sploit](https://github.com/UbuntuStrike/CVE-2017-9805-Apache-Struts-Fuzz-N-Sploit) :  ![starts](https://img.shields.io/github/stars/UbuntuStrike/CVE-2017-9805-Apache-Struts-Fuzz-N-Sploit.svg) ![forks](https://img.shields.io/github/forks/UbuntuStrike/CVE-2017-9805-Apache-Struts-Fuzz-N-Sploit.svg)

## CVE-2017-9798
 Apache httpd allows remote attackers to read secret data from process memory if the Limit directive can be set in a user's .htaccess file, or if httpd.conf has certain misconfigurations, aka Optionsbleed. This affects the Apache HTTP Server through 2.2.34 and 2.4.x through 2.4.27. The attacker sends an unauthenticated OPTIONS HTTP request when attempting to read secret data. This is a use-after-free issue and thus secret data is not always sent, and the specific data depends on many factors including configuration. Exploitation with .htaccess can be blocked with a patch to the ap_limit_section function in server/core.c.



- [https://github.com/brokensound77/OptionsBleed-POC-Scanner](https://github.com/brokensound77/OptionsBleed-POC-Scanner) :  ![starts](https://img.shields.io/github/stars/brokensound77/OptionsBleed-POC-Scanner.svg) ![forks](https://img.shields.io/github/forks/brokensound77/OptionsBleed-POC-Scanner.svg)

- [https://github.com/nitrado/CVE-2017-9798](https://github.com/nitrado/CVE-2017-9798) :  ![starts](https://img.shields.io/github/stars/nitrado/CVE-2017-9798.svg) ![forks](https://img.shields.io/github/forks/nitrado/CVE-2017-9798.svg)

- [https://github.com/pabloec20/optionsbleed](https://github.com/pabloec20/optionsbleed) :  ![starts](https://img.shields.io/github/stars/pabloec20/optionsbleed.svg) ![forks](https://img.shields.io/github/forks/pabloec20/optionsbleed.svg)

- [https://github.com/l0n3rs/CVE-2017-9798](https://github.com/l0n3rs/CVE-2017-9798) :  ![starts](https://img.shields.io/github/stars/l0n3rs/CVE-2017-9798.svg) ![forks](https://img.shields.io/github/forks/l0n3rs/CVE-2017-9798.svg)

## CVE-2017-9791
 The Struts 1 plugin in Apache Struts 2.1.x and 2.3.x might allow remote code execution via a malicious field value passed in a raw message to the ActionMessage.



- [https://github.com/dragoneeg/Struts2-048](https://github.com/dragoneeg/Struts2-048) :  ![starts](https://img.shields.io/github/stars/dragoneeg/Struts2-048.svg) ![forks](https://img.shields.io/github/forks/dragoneeg/Struts2-048.svg)

- [https://github.com/IanSmith123/s2-048](https://github.com/IanSmith123/s2-048) :  ![starts](https://img.shields.io/github/stars/IanSmith123/s2-048.svg) ![forks](https://img.shields.io/github/forks/IanSmith123/s2-048.svg)

- [https://github.com/gh0st27/Struts2Scanner](https://github.com/gh0st27/Struts2Scanner) :  ![starts](https://img.shields.io/github/stars/gh0st27/Struts2Scanner.svg) ![forks](https://img.shields.io/github/forks/gh0st27/Struts2Scanner.svg)

- [https://github.com/xfer0/CVE-2017-9791](https://github.com/xfer0/CVE-2017-9791) :  ![starts](https://img.shields.io/github/stars/xfer0/CVE-2017-9791.svg) ![forks](https://img.shields.io/github/forks/xfer0/CVE-2017-9791.svg)

## CVE-2017-9779
 OCaml compiler allows attackers to have unspecified impact via unknown vectors, a similar issue to CVE-2017-9772 &quot;but with much less impact.&quot;



- [https://github.com/homjxi0e/CVE-2017-9779](https://github.com/homjxi0e/CVE-2017-9779) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-9779.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-9779.svg)

## CVE-2017-9769
 A specially crafted IOCTL can be issued to the rzpnk.sys driver in Razer Synapse 2.20.15.1104 that is forwarded to ZwOpenProcess allowing a handle to be opened to an arbitrary process.



- [https://github.com/kkent030315/CVE-2017-9769](https://github.com/kkent030315/CVE-2017-9769) :  ![starts](https://img.shields.io/github/stars/kkent030315/CVE-2017-9769.svg) ![forks](https://img.shields.io/github/forks/kkent030315/CVE-2017-9769.svg)

## CVE-2017-9757
 IPFire 2.19 has a Remote Command Injection vulnerability in ids.cgi via the OINKCODE parameter, which is mishandled by a shell. This can be exploited directly by authenticated users, or through CSRF.



- [https://github.com/peterleiva/CVE-2017-9757](https://github.com/peterleiva/CVE-2017-9757) :  ![starts](https://img.shields.io/github/stars/peterleiva/CVE-2017-9757.svg) ![forks](https://img.shields.io/github/forks/peterleiva/CVE-2017-9757.svg)

## CVE-2017-9631
 A Null Pointer Dereference issue was discovered in Schneider Electric Wonderware ArchestrA Logger, versions 2017.426.2307.1 and prior. The null pointer dereference vulnerability could allow an attacker to crash the logger process, causing a denial of service for logging and log-viewing (applications that use the Wonderware ArchestrA Logger continue to run when the Wonderware ArchestrA Logger service is unavailable).



- [https://github.com/USSCltd/aaLogger](https://github.com/USSCltd/aaLogger) :  ![starts](https://img.shields.io/github/stars/USSCltd/aaLogger.svg) ![forks](https://img.shields.io/github/forks/USSCltd/aaLogger.svg)

## CVE-2017-9629
 A Stack-Based Buffer Overflow issue was discovered in Schneider Electric Wonderware ArchestrA Logger, versions 2017.426.2307.1 and prior. The stack-based buffer overflow vulnerability has been identified, which may allow a remote attacker to execute arbitrary code in the context of a highly privileged account.



- [https://github.com/USSCltd/aaLogger](https://github.com/USSCltd/aaLogger) :  ![starts](https://img.shields.io/github/stars/USSCltd/aaLogger.svg) ![forks](https://img.shields.io/github/forks/USSCltd/aaLogger.svg)

## CVE-2017-9627
 An Uncontrolled Resource Consumption issue was discovered in Schneider Electric Wonderware ArchestrA Logger, versions 2017.426.2307.1 and prior. The uncontrolled resource consumption vulnerability could allow an attacker to exhaust the memory resources of the machine, causing a denial of service.



- [https://github.com/USSCltd/aaLogger](https://github.com/USSCltd/aaLogger) :  ![starts](https://img.shields.io/github/stars/USSCltd/aaLogger.svg) ![forks](https://img.shields.io/github/forks/USSCltd/aaLogger.svg)

## CVE-2017-9609
 Cross-site scripting (XSS) vulnerability in Blackcat CMS 1.2 allows remote authenticated users to inject arbitrary web script or HTML via the map_language parameter to backend/pages/lang_settings.php.



- [https://github.com/faizzaidi/Blackcat-cms-v1.2-xss-POC-by-Provensec-llc](https://github.com/faizzaidi/Blackcat-cms-v1.2-xss-POC-by-Provensec-llc) :  ![starts](https://img.shields.io/github/stars/faizzaidi/Blackcat-cms-v1.2-xss-POC-by-Provensec-llc.svg) ![forks](https://img.shields.io/github/forks/faizzaidi/Blackcat-cms-v1.2-xss-POC-by-Provensec-llc.svg)

## CVE-2017-9608
 The dnxhd decoder in FFmpeg before 3.2.6, and 3.3.x before 3.3.3 allows remote attackers to cause a denial of service (NULL pointer dereference) via a crafted mov file.



- [https://github.com/LaCinquette/practice-22-23](https://github.com/LaCinquette/practice-22-23) :  ![starts](https://img.shields.io/github/stars/LaCinquette/practice-22-23.svg) ![forks](https://img.shields.io/github/forks/LaCinquette/practice-22-23.svg)

## CVE-2017-9606
 Infotecs ViPNet Client and Coordinator before 4.3.2-42442 allow local users to gain privileges by placing a Trojan horse ViPNet update file in the update folder. The attack succeeds because of incorrect folder permissions in conjunction with a lack of integrity and authenticity checks.



- [https://github.com/Houl777/CVE-2017-9606](https://github.com/Houl777/CVE-2017-9606) :  ![starts](https://img.shields.io/github/stars/Houl777/CVE-2017-9606.svg) ![forks](https://img.shields.io/github/forks/Houl777/CVE-2017-9606.svg)

## CVE-2017-9554
 An information exposure vulnerability in forget_passwd.cgi in Synology DiskStation Manager (DSM) before 6.1.3-15152 allows remote attackers to enumerate valid usernames via unspecified vectors.



- [https://github.com/rfcl/Synology-DiskStation-User-Enumeration-CVE-2017-9554-](https://github.com/rfcl/Synology-DiskStation-User-Enumeration-CVE-2017-9554-) :  ![starts](https://img.shields.io/github/stars/rfcl/Synology-DiskStation-User-Enumeration-CVE-2017-9554-.svg) ![forks](https://img.shields.io/github/forks/rfcl/Synology-DiskStation-User-Enumeration-CVE-2017-9554-.svg)

- [https://github.com/Ez0-yf/CVE-2017-9554-Exploit-Tool](https://github.com/Ez0-yf/CVE-2017-9554-Exploit-Tool) :  ![starts](https://img.shields.io/github/stars/Ez0-yf/CVE-2017-9554-Exploit-Tool.svg) ![forks](https://img.shields.io/github/forks/Ez0-yf/CVE-2017-9554-Exploit-Tool.svg)

## CVE-2017-9544
 There is a remote stack-based buffer overflow (SEH) in register.ghp in EFS Software Easy Chat Server versions 2.0 to 3.1. By sending an overly long username string to registresult.htm for registering the user, an attacker may be able to execute arbitrary code.



- [https://github.com/adenkiewicz/CVE-2017-9544](https://github.com/adenkiewicz/CVE-2017-9544) :  ![starts](https://img.shields.io/github/stars/adenkiewicz/CVE-2017-9544.svg) ![forks](https://img.shields.io/github/forks/adenkiewicz/CVE-2017-9544.svg)

## CVE-2017-9506
 The IconUriServlet of the Atlassian OAuth Plugin from version 1.3.0 before version 1.9.12 and from version 2.0.0 before version 2.0.4 allows remote attackers to access the content of internal network resources and/or perform an XSS attack via Server Side Request Forgery (SSRF).



- [https://github.com/random-robbie/Jira-Scan](https://github.com/random-robbie/Jira-Scan) :  ![starts](https://img.shields.io/github/stars/random-robbie/Jira-Scan.svg) ![forks](https://img.shields.io/github/forks/random-robbie/Jira-Scan.svg)

- [https://github.com/labsbots/CVE-2017-9506](https://github.com/labsbots/CVE-2017-9506) :  ![starts](https://img.shields.io/github/stars/labsbots/CVE-2017-9506.svg) ![forks](https://img.shields.io/github/forks/labsbots/CVE-2017-9506.svg)

- [https://github.com/pwn1sher/jira-ssrf](https://github.com/pwn1sher/jira-ssrf) :  ![starts](https://img.shields.io/github/stars/pwn1sher/jira-ssrf.svg) ![forks](https://img.shields.io/github/forks/pwn1sher/jira-ssrf.svg)

## CVE-2017-9476
 The Comcast firmware on Cisco DPC3939 (firmware version dpc3939-P20-18-v303r20421733-160420a-CMCST); Cisco DPC3939 (firmware version dpc3939-P20-18-v303r20421746-170221a-CMCST); and Arris TG1682G (eMTA&amp;DOCSIS version 10.0.132.SIP.PC20.CT, software version TG1682_2.2p7s2_PROD_sey) devices makes it easy for remote attackers to determine the hidden SSID and passphrase for a Home Security Wi-Fi network.



- [https://github.com/wiire-a/CVE-2017-9476](https://github.com/wiire-a/CVE-2017-9476) :  ![starts](https://img.shields.io/github/stars/wiire-a/CVE-2017-9476.svg) ![forks](https://img.shields.io/github/forks/wiire-a/CVE-2017-9476.svg)

## CVE-2017-9430
 Stack-based buffer overflow in dnstracer through 1.9 allows attackers to cause a denial of service (application crash) or possibly have unspecified other impact via a command line with a long name argument that is mishandled in a strcpy call for argv[0]. An example threat model is a web application that launches dnstracer with an untrusted name string.



- [https://github.com/j0lama/Dnstracer-1.9-Fix](https://github.com/j0lama/Dnstracer-1.9-Fix) :  ![starts](https://img.shields.io/github/stars/j0lama/Dnstracer-1.9-Fix.svg) ![forks](https://img.shields.io/github/forks/j0lama/Dnstracer-1.9-Fix.svg)

- [https://github.com/homjxi0e/CVE-2017-9430](https://github.com/homjxi0e/CVE-2017-9430) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-9430.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-9430.svg)

## CVE-2017-9417
 Broadcom BCM43xx Wi-Fi chips allow remote attackers to execute arbitrary code via unspecified vectors, aka the &quot;Broadpwn&quot; issue.



- [https://github.com/mailinneberg/Broadpwn](https://github.com/mailinneberg/Broadpwn) :  ![starts](https://img.shields.io/github/stars/mailinneberg/Broadpwn.svg) ![forks](https://img.shields.io/github/forks/mailinneberg/Broadpwn.svg)

## CVE-2017-9248
 Telerik.Web.UI.dll in Progress Telerik UI for ASP.NET AJAX before R2 2017 SP1 and Sitefinity before 10.0.6412.0 does not properly protect Telerik.Web.UI.DialogParametersEncryptionKey or the MachineKey, which makes it easier for remote attackers to defeat cryptographic protection mechanisms, leading to a MachineKey leak, arbitrary file uploads or downloads, XSS, or ASP.NET ViewState compromise.



- [https://github.com/bao7uo/dp_crypto](https://github.com/bao7uo/dp_crypto) :  ![starts](https://img.shields.io/github/stars/bao7uo/dp_crypto.svg) ![forks](https://img.shields.io/github/forks/bao7uo/dp_crypto.svg)

- [https://github.com/capt-meelo/Telewreck](https://github.com/capt-meelo/Telewreck) :  ![starts](https://img.shields.io/github/stars/capt-meelo/Telewreck.svg) ![forks](https://img.shields.io/github/forks/capt-meelo/Telewreck.svg)

- [https://github.com/blacklanternsecurity/dp_cryptomg](https://github.com/blacklanternsecurity/dp_cryptomg) :  ![starts](https://img.shields.io/github/stars/blacklanternsecurity/dp_cryptomg.svg) ![forks](https://img.shields.io/github/forks/blacklanternsecurity/dp_cryptomg.svg)

- [https://github.com/hlong12042/CVE-2017-9248](https://github.com/hlong12042/CVE-2017-9248) :  ![starts](https://img.shields.io/github/stars/hlong12042/CVE-2017-9248.svg) ![forks](https://img.shields.io/github/forks/hlong12042/CVE-2017-9248.svg)

- [https://github.com/ictnamanh/CVE-2017-9248](https://github.com/ictnamanh/CVE-2017-9248) :  ![starts](https://img.shields.io/github/stars/ictnamanh/CVE-2017-9248.svg) ![forks](https://img.shields.io/github/forks/ictnamanh/CVE-2017-9248.svg)

- [https://github.com/cehamod/UI_CVE-2017-9248](https://github.com/cehamod/UI_CVE-2017-9248) :  ![starts](https://img.shields.io/github/stars/cehamod/UI_CVE-2017-9248.svg) ![forks](https://img.shields.io/github/forks/cehamod/UI_CVE-2017-9248.svg)

- [https://github.com/oldboysonnt/dp](https://github.com/oldboysonnt/dp) :  ![starts](https://img.shields.io/github/stars/oldboysonnt/dp.svg) ![forks](https://img.shields.io/github/forks/oldboysonnt/dp.svg)

## CVE-2017-9101
 import.php (aka the Phonebook import feature) in PlaySMS 1.4 allows remote code execution via vectors involving the User-Agent HTTP header and PHP code in the name of a file.



- [https://github.com/jasperla/CVE-2017-9101](https://github.com/jasperla/CVE-2017-9101) :  ![starts](https://img.shields.io/github/stars/jasperla/CVE-2017-9101.svg) ![forks](https://img.shields.io/github/forks/jasperla/CVE-2017-9101.svg)

## CVE-2017-9097
 In Anti-Web through 3.8.7, as used on NetBiter FGW200 devices through 3.21.2, WS100 devices through 3.30.5, EC150 devices through 1.40.0, WS200 devices through 3.30.4, EC250 devices through 1.40.0, and other products, an LFI vulnerability allows a remote attacker to read or modify files through a path traversal technique, as demonstrated by reading the password file, or using the template parameter to cgi-bin/write.cgi to write to an arbitrary file.



- [https://github.com/MDudek-ICS/AntiWeb_testing-Suite](https://github.com/MDudek-ICS/AntiWeb_testing-Suite) :  ![starts](https://img.shields.io/github/stars/MDudek-ICS/AntiWeb_testing-Suite.svg) ![forks](https://img.shields.io/github/forks/MDudek-ICS/AntiWeb_testing-Suite.svg)

## CVE-2017-9096
 The XML parsers in iText before 5.5.12 and 7.x before 7.0.3 do not disable external entities, which might allow remote attackers to conduct XML external entity (XXE) attacks via a crafted PDF.



- [https://github.com/jakabakos/CVE-2017-9096-iText-XXE](https://github.com/jakabakos/CVE-2017-9096-iText-XXE) :  ![starts](https://img.shields.io/github/stars/jakabakos/CVE-2017-9096-iText-XXE.svg) ![forks](https://img.shields.io/github/forks/jakabakos/CVE-2017-9096-iText-XXE.svg)

## CVE-2017-9077
 The tcp_v6_syn_recv_sock function in net/ipv6/tcp_ipv6.c in the Linux kernel through 4.11.1 mishandles inheritance, which allows local users to cause a denial of service or possibly have unspecified other impact via crafted system calls, a related issue to CVE-2017-8890.



- [https://github.com/idhyt/androotzf](https://github.com/idhyt/androotzf) :  ![starts](https://img.shields.io/github/stars/idhyt/androotzf.svg) ![forks](https://img.shields.io/github/forks/idhyt/androotzf.svg)

## CVE-2017-8917
 SQL injection vulnerability in Joomla! 3.7.x before 3.7.1 allows attackers to execute arbitrary SQL commands via unspecified vectors.



- [https://github.com/stefanlucas/Exploit-Joomla](https://github.com/stefanlucas/Exploit-Joomla) :  ![starts](https://img.shields.io/github/stars/stefanlucas/Exploit-Joomla.svg) ![forks](https://img.shields.io/github/forks/stefanlucas/Exploit-Joomla.svg)

- [https://github.com/brianwrf/Joomla3.7-SQLi-CVE-2017-8917](https://github.com/brianwrf/Joomla3.7-SQLi-CVE-2017-8917) :  ![starts](https://img.shields.io/github/stars/brianwrf/Joomla3.7-SQLi-CVE-2017-8917.svg) ![forks](https://img.shields.io/github/forks/brianwrf/Joomla3.7-SQLi-CVE-2017-8917.svg)

- [https://github.com/AkuCyberSec/CVE-2017-8917-Joomla-370-SQL-Injection](https://github.com/AkuCyberSec/CVE-2017-8917-Joomla-370-SQL-Injection) :  ![starts](https://img.shields.io/github/stars/AkuCyberSec/CVE-2017-8917-Joomla-370-SQL-Injection.svg) ![forks](https://img.shields.io/github/forks/AkuCyberSec/CVE-2017-8917-Joomla-370-SQL-Injection.svg)

- [https://github.com/gmohlamo/CVE-2017-8917](https://github.com/gmohlamo/CVE-2017-8917) :  ![starts](https://img.shields.io/github/stars/gmohlamo/CVE-2017-8917.svg) ![forks](https://img.shields.io/github/forks/gmohlamo/CVE-2017-8917.svg)

- [https://github.com/cved-sources/cve-2017-8917](https://github.com/cved-sources/cve-2017-8917) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2017-8917.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2017-8917.svg)

- [https://github.com/Siopy/CVE-2017-8917](https://github.com/Siopy/CVE-2017-8917) :  ![starts](https://img.shields.io/github/stars/Siopy/CVE-2017-8917.svg) ![forks](https://img.shields.io/github/forks/Siopy/CVE-2017-8917.svg)

- [https://github.com/BaptisteContreras/CVE-2017-8917-Joomla](https://github.com/BaptisteContreras/CVE-2017-8917-Joomla) :  ![starts](https://img.shields.io/github/stars/BaptisteContreras/CVE-2017-8917-Joomla.svg) ![forks](https://img.shields.io/github/forks/BaptisteContreras/CVE-2017-8917-Joomla.svg)

- [https://github.com/ionutbaltariu/joomla_CVE-2017-8917](https://github.com/ionutbaltariu/joomla_CVE-2017-8917) :  ![starts](https://img.shields.io/github/stars/ionutbaltariu/joomla_CVE-2017-8917.svg) ![forks](https://img.shields.io/github/forks/ionutbaltariu/joomla_CVE-2017-8917.svg)

- [https://github.com/gloliveira1701/Joomblah](https://github.com/gloliveira1701/Joomblah) :  ![starts](https://img.shields.io/github/stars/gloliveira1701/Joomblah.svg) ![forks](https://img.shields.io/github/forks/gloliveira1701/Joomblah.svg)

## CVE-2017-8890
 The inet_csk_clone_lock function in net/ipv4/inet_connection_sock.c in the Linux kernel through 4.10.15 allows attackers to cause a denial of service (double free) or possibly have unspecified other impact by leveraging use of the accept system call.



- [https://github.com/idhyt/androotzf](https://github.com/idhyt/androotzf) :  ![starts](https://img.shields.io/github/stars/idhyt/androotzf.svg) ![forks](https://img.shields.io/github/forks/idhyt/androotzf.svg)

- [https://github.com/thinkycx/CVE-2017-8890](https://github.com/thinkycx/CVE-2017-8890) :  ![starts](https://img.shields.io/github/stars/thinkycx/CVE-2017-8890.svg) ![forks](https://img.shields.io/github/forks/thinkycx/CVE-2017-8890.svg)

- [https://github.com/beraphin/CVE-2017-8890](https://github.com/beraphin/CVE-2017-8890) :  ![starts](https://img.shields.io/github/stars/beraphin/CVE-2017-8890.svg) ![forks](https://img.shields.io/github/forks/beraphin/CVE-2017-8890.svg)

- [https://github.com/7043mcgeep/cve-2017-8890-msf](https://github.com/7043mcgeep/cve-2017-8890-msf) :  ![starts](https://img.shields.io/github/stars/7043mcgeep/cve-2017-8890-msf.svg) ![forks](https://img.shields.io/github/forks/7043mcgeep/cve-2017-8890-msf.svg)

## CVE-2017-8809
 api.php in MediaWiki before 1.27.4, 1.28.x before 1.28.3, and 1.29.x before 1.29.2 has a Reflected File Download vulnerability.



- [https://github.com/motikan2010/CVE-2017-8809_MediaWiki_RFD](https://github.com/motikan2010/CVE-2017-8809_MediaWiki_RFD) :  ![starts](https://img.shields.io/github/stars/motikan2010/CVE-2017-8809_MediaWiki_RFD.svg) ![forks](https://img.shields.io/github/forks/motikan2010/CVE-2017-8809_MediaWiki_RFD.svg)

## CVE-2017-8802
 Cross-site scripting (XSS) vulnerability in Zimbra Collaboration Suite (aka ZCS) before 8.8.0 Beta2 might allow remote attackers to inject arbitrary web script or HTML via vectors related to the &quot;Show Snippet&quot; functionality.



- [https://github.com/ozzi-/Zimbra-CVE-2017-8802-Hotifx](https://github.com/ozzi-/Zimbra-CVE-2017-8802-Hotifx) :  ![starts](https://img.shields.io/github/stars/ozzi-/Zimbra-CVE-2017-8802-Hotifx.svg) ![forks](https://img.shields.io/github/forks/ozzi-/Zimbra-CVE-2017-8802-Hotifx.svg)

## CVE-2017-8798
 Integer signedness error in MiniUPnP MiniUPnPc v1.4.20101221 through v2.0 allows remote attackers to cause a denial of service or possibly have unspecified other impact.



- [https://github.com/tintinweb/pub](https://github.com/tintinweb/pub) :  ![starts](https://img.shields.io/github/stars/tintinweb/pub.svg) ![forks](https://img.shields.io/github/forks/tintinweb/pub.svg)

## CVE-2017-8779
 rpcbind through 0.2.4, LIBTIRPC through 1.0.1 and 1.0.2-rc through 1.0.2-rc3, and NTIRPC through 1.4.3 do not consider the maximum RPC data size during memory allocation for XDR strings, which allows remote attackers to cause a denial of service (memory consumption with no subsequent free) via a crafted UDP packet to port 111, aka rpcbomb.



- [https://github.com/drbothen/GO-RPCBOMB](https://github.com/drbothen/GO-RPCBOMB) :  ![starts](https://img.shields.io/github/stars/drbothen/GO-RPCBOMB.svg) ![forks](https://img.shields.io/github/forks/drbothen/GO-RPCBOMB.svg)

## CVE-2017-8760
 An issue was discovered on Accellion FTA devices before FTA_9_12_180. There is XSS in courier/1000@/index.html with the auth_params parameter. The device tries to use internal WAF filters to stop specific XSS Vulnerabilities. However, these can be bypassed by using some modifications to the payloads, e.g., URL encoding.



- [https://github.com/Voraka/cve-2017-8760](https://github.com/Voraka/cve-2017-8760) :  ![starts](https://img.shields.io/github/stars/Voraka/cve-2017-8760.svg) ![forks](https://img.shields.io/github/forks/Voraka/cve-2017-8760.svg)

## CVE-2017-8759
 Microsoft .NET Framework 2.0, 3.5, 3.5.1, 4.5.2, 4.6, 4.6.1, 4.6.2 and 4.7 allow an attacker to execute code remotely via a malicious document or application, aka &quot;.NET Framework Remote Code Execution Vulnerability.&quot;



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

- [https://github.com/Winter3un/cve_2017_8759](https://github.com/Winter3un/cve_2017_8759) :  ![starts](https://img.shields.io/github/stars/Winter3un/cve_2017_8759.svg) ![forks](https://img.shields.io/github/forks/Winter3un/cve_2017_8759.svg)

- [https://github.com/l0n3rs/CVE-2017-8759](https://github.com/l0n3rs/CVE-2017-8759) :  ![starts](https://img.shields.io/github/stars/l0n3rs/CVE-2017-8759.svg) ![forks](https://img.shields.io/github/forks/l0n3rs/CVE-2017-8759.svg)

- [https://github.com/adeljck/CVE-2017-8759](https://github.com/adeljck/CVE-2017-8759) :  ![starts](https://img.shields.io/github/stars/adeljck/CVE-2017-8759.svg) ![forks](https://img.shields.io/github/forks/adeljck/CVE-2017-8759.svg)

- [https://github.com/smashinu/CVE-2017-8759Expoit](https://github.com/smashinu/CVE-2017-8759Expoit) :  ![starts](https://img.shields.io/github/stars/smashinu/CVE-2017-8759Expoit.svg) ![forks](https://img.shields.io/github/forks/smashinu/CVE-2017-8759Expoit.svg)

- [https://github.com/tahisaad6/CVE-2017-8759-Exploit-sample2](https://github.com/tahisaad6/CVE-2017-8759-Exploit-sample2) :  ![starts](https://img.shields.io/github/stars/tahisaad6/CVE-2017-8759-Exploit-sample2.svg) ![forks](https://img.shields.io/github/forks/tahisaad6/CVE-2017-8759-Exploit-sample2.svg)

- [https://github.com/GayashanM/OHTS](https://github.com/GayashanM/OHTS) :  ![starts](https://img.shields.io/github/stars/GayashanM/OHTS.svg) ![forks](https://img.shields.io/github/forks/GayashanM/OHTS.svg)

- [https://github.com/varunsaru/SNP](https://github.com/varunsaru/SNP) :  ![starts](https://img.shields.io/github/stars/varunsaru/SNP.svg) ![forks](https://img.shields.io/github/forks/varunsaru/SNP.svg)

- [https://github.com/chefphenix25/vuln-rabilit-windows7](https://github.com/chefphenix25/vuln-rabilit-windows7) :  ![starts](https://img.shields.io/github/stars/chefphenix25/vuln-rabilit-windows7.svg) ![forks](https://img.shields.io/github/forks/chefphenix25/vuln-rabilit-windows7.svg)

## CVE-2017-8641
 Microsoft browsers in Microsoft Windows 7 SP1, Windows Server 2008 R2 SP1, Windows 8.1 and Windows RT 8.1, Windows Server 2012 and R2, Windows 10 Gold, 1511, 1607, 1703, and Windows Server 2016 allow an attacker to execute arbitrary code in the context of the current user due to the way that Microsoft browser JavaScript engines render when handling objects in memory, aka &quot;Scripting Engine Memory Corruption Vulnerability&quot;. This CVE ID is unique from CVE-2017-8634, CVE-2017-8635, CVE-2017-8636, CVE-2017-8638, CVE-2017-8639, CVE-2017-8640, CVE-2017-8645, CVE-2017-8646, CVE-2017-8647, CVE-2017-8655, CVE-2017-8656, CVE-2017-8657, CVE-2017-8670, CVE-2017-8671, CVE-2017-8672, and CVE-2017-8674.



- [https://github.com/homjxi0e/CVE-2017-8641_chakra_Js_GlobalObject](https://github.com/homjxi0e/CVE-2017-8641_chakra_Js_GlobalObject) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-8641_chakra_Js_GlobalObject.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-8641_chakra_Js_GlobalObject.svg)

## CVE-2017-8625
 Internet Explorer in Windows 10 Gold, 1511, 1607, 1703, and Windows Server 2016 allows an attacker to bypass Device Guard User Mode Code Integrity (UMCI) policies due to Internet Explorer failing to validate UMCI policies, aka &quot;Internet Explorer Security Feature Bypass Vulnerability&quot;.



- [https://github.com/homjxi0e/CVE-2017-8625_Bypass_UMCI](https://github.com/homjxi0e/CVE-2017-8625_Bypass_UMCI) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-8625_Bypass_UMCI.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-8625_Bypass_UMCI.svg)

## CVE-2017-8570
 Microsoft Office allows a remote code execution vulnerability due to the way that it handles objects in memory, aka &quot;Microsoft Office Remote Code Execution Vulnerability&quot;. This CVE ID is unique from CVE-2017-0243.



- [https://github.com/rxwx/CVE-2017-8570](https://github.com/rxwx/CVE-2017-8570) :  ![starts](https://img.shields.io/github/stars/rxwx/CVE-2017-8570.svg) ![forks](https://img.shields.io/github/forks/rxwx/CVE-2017-8570.svg)

- [https://github.com/temesgeny/ppsx-file-generator](https://github.com/temesgeny/ppsx-file-generator) :  ![starts](https://img.shields.io/github/stars/temesgeny/ppsx-file-generator.svg) ![forks](https://img.shields.io/github/forks/temesgeny/ppsx-file-generator.svg)

- [https://github.com/SwordSheath/CVE-2017-8570](https://github.com/SwordSheath/CVE-2017-8570) :  ![starts](https://img.shields.io/github/stars/SwordSheath/CVE-2017-8570.svg) ![forks](https://img.shields.io/github/forks/SwordSheath/CVE-2017-8570.svg)

- [https://github.com/Drac0nids/CVE-2017-8570](https://github.com/Drac0nids/CVE-2017-8570) :  ![starts](https://img.shields.io/github/stars/Drac0nids/CVE-2017-8570.svg) ![forks](https://img.shields.io/github/forks/Drac0nids/CVE-2017-8570.svg)

- [https://github.com/erfze/CVE-2017-8570](https://github.com/erfze/CVE-2017-8570) :  ![starts](https://img.shields.io/github/stars/erfze/CVE-2017-8570.svg) ![forks](https://img.shields.io/github/forks/erfze/CVE-2017-8570.svg)

- [https://github.com/MaxSecurity/Office-CVE-2017-8570](https://github.com/MaxSecurity/Office-CVE-2017-8570) :  ![starts](https://img.shields.io/github/stars/MaxSecurity/Office-CVE-2017-8570.svg) ![forks](https://img.shields.io/github/forks/MaxSecurity/Office-CVE-2017-8570.svg)

- [https://github.com/sasqwatch/CVE-2017-8570](https://github.com/sasqwatch/CVE-2017-8570) :  ![starts](https://img.shields.io/github/stars/sasqwatch/CVE-2017-8570.svg) ![forks](https://img.shields.io/github/forks/sasqwatch/CVE-2017-8570.svg)

- [https://github.com/erfze/CVE-2017-0261](https://github.com/erfze/CVE-2017-0261) :  ![starts](https://img.shields.io/github/stars/erfze/CVE-2017-0261.svg) ![forks](https://img.shields.io/github/forks/erfze/CVE-2017-0261.svg)

## CVE-2017-8543
 Microsoft Windows XP SP3, Windows XP x64 XP2, Windows Server 2003 SP2, Windows Vista, Windows 7 SP1, Windows Server 2008 SP2 and R2 SP1, Windows 8, Windows 8.1 and Windows RT 8.1, Windows Server 2012 and R2, Windows 10 Gold, 1511, 1607, and 1703, and Windows Server 2016 allow an attacker to take control of the affected system when Windows Search fails to handle objects in memory, aka &quot;Windows Search Remote Code Execution Vulnerability&quot;.



- [https://github.com/americanhanko/windows-security-cve-2017-8543](https://github.com/americanhanko/windows-security-cve-2017-8543) :  ![starts](https://img.shields.io/github/stars/americanhanko/windows-security-cve-2017-8543.svg) ![forks](https://img.shields.io/github/forks/americanhanko/windows-security-cve-2017-8543.svg)

## CVE-2017-8529
 Internet Explorer in Microsoft Windows 7 SP1, Windows Server 2008 R2 SP1, Windows 8.1 and Windows RT 8.1, and Windows Server 2012 and R2 allow an attacker to detect specific files on the user's computer when affected Microsoft scripting engines do not properly handle objects in memory, aka &quot;Microsoft Browser Information Disclosure Vulnerability&quot;.



- [https://github.com/sfitpro/cve-2017-8529](https://github.com/sfitpro/cve-2017-8529) :  ![starts](https://img.shields.io/github/stars/sfitpro/cve-2017-8529.svg) ![forks](https://img.shields.io/github/forks/sfitpro/cve-2017-8529.svg)

- [https://github.com/kaddirov/windows2016fixCVE-2017-8529](https://github.com/kaddirov/windows2016fixCVE-2017-8529) :  ![starts](https://img.shields.io/github/stars/kaddirov/windows2016fixCVE-2017-8529.svg) ![forks](https://img.shields.io/github/forks/kaddirov/windows2016fixCVE-2017-8529.svg)

## CVE-2017-8486
 Microsoft Windows 7 SP1, Windows Server 2008 SP2 and R2 SP1, Windows 8.1 and Windows RT 8.1, Windows Server 2012 and R2, Windows 10 Gold, 1511, 1607, 1703, and Windows Server 2016 allows an information disclosure due to the way it handles objects in memory, aka &quot;Win32k Information Disclosure Vulnerability&quot;.



- [https://github.com/doudouhala/CVE-2017-8464-exp-generator](https://github.com/doudouhala/CVE-2017-8464-exp-generator) :  ![starts](https://img.shields.io/github/stars/doudouhala/CVE-2017-8464-exp-generator.svg) ![forks](https://img.shields.io/github/forks/doudouhala/CVE-2017-8464-exp-generator.svg)

## CVE-2017-8465
 Microsoft Windows 8.1 and Windows RT 8.1, Windows Server 2012 R2, Windows 10 Gold, 1511, 1607, and 1703, and Windows Server 2016 allow an attacker to run processes in an elevated context when the Windows kernel improperly handles objects in memory, aka &quot;Win32k Elevation of Privilege Vulnerability.&quot; This CVE ID is unique from CVE-2017-8468.



- [https://github.com/nghiadt1098/CVE-2017-8465](https://github.com/nghiadt1098/CVE-2017-8465) :  ![starts](https://img.shields.io/github/stars/nghiadt1098/CVE-2017-8465.svg) ![forks](https://img.shields.io/github/forks/nghiadt1098/CVE-2017-8465.svg)

## CVE-2017-8464
 Windows Shell in Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, 1703, and Windows Server 2016 allows local users or remote attackers to execute arbitrary code via a crafted .LNK file, which is not properly handled during icon display in Windows Explorer or any other application that parses the icon of the shortcut. aka &quot;LNK Remote Code Execution Vulnerability.&quot;



- [https://github.com/3gstudent/CVE-2017-8464-EXP](https://github.com/3gstudent/CVE-2017-8464-EXP) :  ![starts](https://img.shields.io/github/stars/3gstudent/CVE-2017-8464-EXP.svg) ![forks](https://img.shields.io/github/forks/3gstudent/CVE-2017-8464-EXP.svg)

- [https://github.com/doudouhala/CVE-2017-8464-exp-generator](https://github.com/doudouhala/CVE-2017-8464-exp-generator) :  ![starts](https://img.shields.io/github/stars/doudouhala/CVE-2017-8464-exp-generator.svg) ![forks](https://img.shields.io/github/forks/doudouhala/CVE-2017-8464-exp-generator.svg)

- [https://github.com/TrG-1999/DetectPacket-CVE-2017-8464](https://github.com/TrG-1999/DetectPacket-CVE-2017-8464) :  ![starts](https://img.shields.io/github/stars/TrG-1999/DetectPacket-CVE-2017-8464.svg) ![forks](https://img.shields.io/github/forks/TrG-1999/DetectPacket-CVE-2017-8464.svg)

- [https://github.com/Elm0D/CVE-2017-8464](https://github.com/Elm0D/CVE-2017-8464) :  ![starts](https://img.shields.io/github/stars/Elm0D/CVE-2017-8464.svg) ![forks](https://img.shields.io/github/forks/Elm0D/CVE-2017-8464.svg)

- [https://github.com/xssfile/CVE-2017-8464-EXP](https://github.com/xssfile/CVE-2017-8464-EXP) :  ![starts](https://img.shields.io/github/stars/xssfile/CVE-2017-8464-EXP.svg) ![forks](https://img.shields.io/github/forks/xssfile/CVE-2017-8464-EXP.svg)

- [https://github.com/X-Vector/usbhijacking](https://github.com/X-Vector/usbhijacking) :  ![starts](https://img.shields.io/github/stars/X-Vector/usbhijacking.svg) ![forks](https://img.shields.io/github/forks/X-Vector/usbhijacking.svg)

- [https://github.com/TieuLong21Prosper/Detect-CVE-2017-8464](https://github.com/TieuLong21Prosper/Detect-CVE-2017-8464) :  ![starts](https://img.shields.io/github/stars/TieuLong21Prosper/Detect-CVE-2017-8464.svg) ![forks](https://img.shields.io/github/forks/TieuLong21Prosper/Detect-CVE-2017-8464.svg)

- [https://github.com/tuankiethkt020/Phat-hien-CVE-2017-8464](https://github.com/tuankiethkt020/Phat-hien-CVE-2017-8464) :  ![starts](https://img.shields.io/github/stars/tuankiethkt020/Phat-hien-CVE-2017-8464.svg) ![forks](https://img.shields.io/github/forks/tuankiethkt020/Phat-hien-CVE-2017-8464.svg)

## CVE-2017-8382
 admidio 3.2.8 has CSRF in adm_program/modules/members/members_function.php with an impact of deleting arbitrary user accounts.



- [https://github.com/faizzaidi/Admidio-3.2.8-CSRF-POC-by-Provensec-llc](https://github.com/faizzaidi/Admidio-3.2.8-CSRF-POC-by-Provensec-llc) :  ![starts](https://img.shields.io/github/stars/faizzaidi/Admidio-3.2.8-CSRF-POC-by-Provensec-llc.svg) ![forks](https://img.shields.io/github/forks/faizzaidi/Admidio-3.2.8-CSRF-POC-by-Provensec-llc.svg)

## CVE-2017-8367
 Buffer overflow in Ether Software Easy MOV Converter 1.4.24, Easy DVD Creator, Easy MPEG/AVI/DIVX/WMV/RM to DVD, Easy Avi/Divx/Xvid to DVD Burner, Easy MPEG to DVD Burner, Easy WMV/ASF/ASX to DVD Burner, Easy RM RMVB to DVD Burner, Easy CD DVD Copy, MP3/AVI/MPEG/WMV/RM to Audio CD Burner, MP3/WAV/OGG/WMA/AC3 to CD Burner, MP3 WAV to CD Burner, My Video Converter, Easy AVI DivX Converter, Easy Video to iPod Converter, Easy Video to PSP Converter, Easy Video to 3GP Converter, Easy Video to MP4 Converter, and Easy Video to iPod/MP4/PSP/3GP Converter allows local attackers to cause a denial of service (SEH overwrite) or possibly have unspecified other impact via a long username.



- [https://github.com/rnnsz/CVE-2017-8367](https://github.com/rnnsz/CVE-2017-8367) :  ![starts](https://img.shields.io/github/stars/rnnsz/CVE-2017-8367.svg) ![forks](https://img.shields.io/github/forks/rnnsz/CVE-2017-8367.svg)

## CVE-2017-8295
 WordPress through 4.7.4 relies on the Host HTTP header for a password-reset e-mail message, which makes it easier for remote attackers to reset arbitrary passwords by making a crafted wp-login.php?action=lostpassword request and then arranging for this message to bounce or be resent, leading to transmission of the reset key to a mailbox on an attacker-controlled SMTP server. This is related to problematic use of the SERVER_NAME variable in wp-includes/pluggable.php in conjunction with the PHP mail function. Exploitation is not achievable in all cases because it requires at least one of the following: (1) the attacker can prevent the victim from receiving any e-mail messages for an extended period of time (such as 5 days), (2) the victim's e-mail system sends an autoresponse containing the original message, or (3) the victim manually composes a reply containing the original message.



- [https://github.com/cyberheartmi9/CVE-2017-8295](https://github.com/cyberheartmi9/CVE-2017-8295) :  ![starts](https://img.shields.io/github/stars/cyberheartmi9/CVE-2017-8295.svg) ![forks](https://img.shields.io/github/forks/cyberheartmi9/CVE-2017-8295.svg)

- [https://github.com/alash3al/wp-allowed-hosts](https://github.com/alash3al/wp-allowed-hosts) :  ![starts](https://img.shields.io/github/stars/alash3al/wp-allowed-hosts.svg) ![forks](https://img.shields.io/github/forks/alash3al/wp-allowed-hosts.svg)

- [https://github.com/homjxi0e/CVE-2017-8295-WordPress-4.7.4---Unauthorized-Password-Reset](https://github.com/homjxi0e/CVE-2017-8295-WordPress-4.7.4---Unauthorized-Password-Reset) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-8295-WordPress-4.7.4---Unauthorized-Password-Reset.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-8295-WordPress-4.7.4---Unauthorized-Password-Reset.svg)

## CVE-2017-8225
 On Wireless IP Camera (P2P) WIFICAM devices, access to .ini files (containing credentials) is not correctly checked. An attacker can bypass authentication by providing an empty loginuse parameter and an empty loginpas parameter in the URI.



- [https://github.com/K3ysTr0K3R/CVE-2017-8225-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2017-8225-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2017-8225-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2017-8225-EXPLOIT.svg)

- [https://github.com/kienquoc102/CVE-2017-8225](https://github.com/kienquoc102/CVE-2017-8225) :  ![starts](https://img.shields.io/github/stars/kienquoc102/CVE-2017-8225.svg) ![forks](https://img.shields.io/github/forks/kienquoc102/CVE-2017-8225.svg)

## CVE-2017-8046
 Malicious PATCH requests submitted to servers using Spring Data REST versions prior to 2.6.9 (Ingalls SR9), versions prior to 3.0.1 (Kay SR1) and Spring Boot versions prior to 1.5.9, 2.0 M6 can use specially crafted JSON data to run arbitrary Java code.



- [https://github.com/m3ssap0/spring-break_cve-2017-8046](https://github.com/m3ssap0/spring-break_cve-2017-8046) :  ![starts](https://img.shields.io/github/stars/m3ssap0/spring-break_cve-2017-8046.svg) ![forks](https://img.shields.io/github/forks/m3ssap0/spring-break_cve-2017-8046.svg)

- [https://github.com/m3ssap0/SpringBreakVulnerableApp](https://github.com/m3ssap0/SpringBreakVulnerableApp) :  ![starts](https://img.shields.io/github/stars/m3ssap0/SpringBreakVulnerableApp.svg) ![forks](https://img.shields.io/github/forks/m3ssap0/SpringBreakVulnerableApp.svg)

- [https://github.com/Soontao/CVE-2017-8046-DEMO](https://github.com/Soontao/CVE-2017-8046-DEMO) :  ![starts](https://img.shields.io/github/stars/Soontao/CVE-2017-8046-DEMO.svg) ![forks](https://img.shields.io/github/forks/Soontao/CVE-2017-8046-DEMO.svg)

- [https://github.com/cved-sources/cve-2017-8046](https://github.com/cved-sources/cve-2017-8046) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2017-8046.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2017-8046.svg)

- [https://github.com/FixYourFace/SpringBreakPoC](https://github.com/FixYourFace/SpringBreakPoC) :  ![starts](https://img.shields.io/github/stars/FixYourFace/SpringBreakPoC.svg) ![forks](https://img.shields.io/github/forks/FixYourFace/SpringBreakPoC.svg)

- [https://github.com/jkutner/spring-break-cve-2017-8046](https://github.com/jkutner/spring-break-cve-2017-8046) :  ![starts](https://img.shields.io/github/stars/jkutner/spring-break-cve-2017-8046.svg) ![forks](https://img.shields.io/github/forks/jkutner/spring-break-cve-2017-8046.svg)

- [https://github.com/sj/spring-data-rest-CVE-2017-8046](https://github.com/sj/spring-data-rest-CVE-2017-8046) :  ![starts](https://img.shields.io/github/stars/sj/spring-data-rest-CVE-2017-8046.svg) ![forks](https://img.shields.io/github/forks/sj/spring-data-rest-CVE-2017-8046.svg)

- [https://github.com/guanjivip/CVE-2017-8046](https://github.com/guanjivip/CVE-2017-8046) :  ![starts](https://img.shields.io/github/stars/guanjivip/CVE-2017-8046.svg) ![forks](https://img.shields.io/github/forks/guanjivip/CVE-2017-8046.svg)

- [https://github.com/bkhablenko/CVE-2017-8046](https://github.com/bkhablenko/CVE-2017-8046) :  ![starts](https://img.shields.io/github/stars/bkhablenko/CVE-2017-8046.svg) ![forks](https://img.shields.io/github/forks/bkhablenko/CVE-2017-8046.svg)

- [https://github.com/jsotiro/VulnerableSpringDataRest](https://github.com/jsotiro/VulnerableSpringDataRest) :  ![starts](https://img.shields.io/github/stars/jsotiro/VulnerableSpringDataRest.svg) ![forks](https://img.shields.io/github/forks/jsotiro/VulnerableSpringDataRest.svg)

## CVE-2017-7998
 Multiple cross-site scripting (XSS) vulnerabilities in Gespage before 7.4.9 allow remote attackers to inject arbitrary web script or HTML via the (1) printer name when adding a printer in the admin panel or (2) username parameter to webapp/users/user_reg.jsp.



- [https://github.com/homjxi0e/CVE-2017-7998](https://github.com/homjxi0e/CVE-2017-7998) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-7998.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-7998.svg)

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

- [https://github.com/D2550/CVE_2017_7921_EXP](https://github.com/D2550/CVE_2017_7921_EXP) :  ![starts](https://img.shields.io/github/stars/D2550/CVE_2017_7921_EXP.svg) ![forks](https://img.shields.io/github/forks/D2550/CVE_2017_7921_EXP.svg)

- [https://github.com/yousouf-Tasfin/cve-2017-7921-Mass-Exploit](https://github.com/yousouf-Tasfin/cve-2017-7921-Mass-Exploit) :  ![starts](https://img.shields.io/github/stars/yousouf-Tasfin/cve-2017-7921-Mass-Exploit.svg) ![forks](https://img.shields.io/github/forks/yousouf-Tasfin/cve-2017-7921-Mass-Exploit.svg)

- [https://github.com/krypton612/hikivision](https://github.com/krypton612/hikivision) :  ![starts](https://img.shields.io/github/stars/krypton612/hikivision.svg) ![forks](https://img.shields.io/github/forks/krypton612/hikivision.svg)

- [https://github.com/b3pwn3d/CVE-2017-7921](https://github.com/b3pwn3d/CVE-2017-7921) :  ![starts](https://img.shields.io/github/stars/b3pwn3d/CVE-2017-7921.svg) ![forks](https://img.shields.io/github/forks/b3pwn3d/CVE-2017-7921.svg)

- [https://github.com/fracergu/CVE-2017-7921](https://github.com/fracergu/CVE-2017-7921) :  ![starts](https://img.shields.io/github/stars/fracergu/CVE-2017-7921.svg) ![forks](https://img.shields.io/github/forks/fracergu/CVE-2017-7921.svg)

- [https://github.com/inj3ction/CVE-2017-7921-EXP](https://github.com/inj3ction/CVE-2017-7921-EXP) :  ![starts](https://img.shields.io/github/stars/inj3ction/CVE-2017-7921-EXP.svg) ![forks](https://img.shields.io/github/forks/inj3ction/CVE-2017-7921-EXP.svg)

- [https://github.com/p4tq/hikvision_CVE-2017-7921_auth_bypass_config_decryptor](https://github.com/p4tq/hikvision_CVE-2017-7921_auth_bypass_config_decryptor) :  ![starts](https://img.shields.io/github/stars/p4tq/hikvision_CVE-2017-7921_auth_bypass_config_decryptor.svg) ![forks](https://img.shields.io/github/forks/p4tq/hikvision_CVE-2017-7921_auth_bypass_config_decryptor.svg)

- [https://github.com/AnonkiGroup/AnonHik](https://github.com/AnonkiGroup/AnonHik) :  ![starts](https://img.shields.io/github/stars/AnonkiGroup/AnonHik.svg) ![forks](https://img.shields.io/github/forks/AnonkiGroup/AnonHik.svg)

## CVE-2017-7912
 Hanwha Techwin SRN-4000, SRN-4000 firmware versions prior to SRN4000_v2.16_170401, A specially crafted http request and response could allow an attacker to gain access to the device management page with admin privileges without proper authentication.



- [https://github.com/homjxi0e/CVE-2017-7912_Sneak](https://github.com/homjxi0e/CVE-2017-7912_Sneak) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-7912_Sneak.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-7912_Sneak.svg)

## CVE-2017-7679
 In Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26, mod_mime can read one byte past the end of a buffer when sending a malicious Content-Type response header.



- [https://github.com/snknritr/CVE-2017-7679-in-python](https://github.com/snknritr/CVE-2017-7679-in-python) :  ![starts](https://img.shields.io/github/stars/snknritr/CVE-2017-7679-in-python.svg) ![forks](https://img.shields.io/github/forks/snknritr/CVE-2017-7679-in-python.svg)

## CVE-2017-7651
 In Eclipse Mosquitto 1.4.14, a user can shutdown the Mosquitto server simply by filling the RAM memory with a lot of connections with large payload. This can be done without authentications if occur in connection phase of MQTT protocol.



- [https://github.com/mukkul007/MqttAttack](https://github.com/mukkul007/MqttAttack) :  ![starts](https://img.shields.io/github/stars/mukkul007/MqttAttack.svg) ![forks](https://img.shields.io/github/forks/mukkul007/MqttAttack.svg)

- [https://github.com/St3v3nsS/CVE-2017-7651](https://github.com/St3v3nsS/CVE-2017-7651) :  ![starts](https://img.shields.io/github/stars/St3v3nsS/CVE-2017-7651.svg) ![forks](https://img.shields.io/github/forks/St3v3nsS/CVE-2017-7651.svg)

## CVE-2017-7648
 Foscam networked devices use the same hardcoded SSL private key across different customers' installations, which allows remote attackers to defeat cryptographic protection mechanisms by leveraging knowledge of this key from another installation.



- [https://github.com/notmot/CVE-2017-7648.](https://github.com/notmot/CVE-2017-7648.) :  ![starts](https://img.shields.io/github/stars/notmot/CVE-2017-7648..svg) ![forks](https://img.shields.io/github/forks/notmot/CVE-2017-7648..svg)

## CVE-2017-7533
 Race condition in the fsnotify implementation in the Linux kernel through 4.12.4 allows local users to gain privileges or cause a denial of service (memory corruption) via a crafted application that leverages simultaneous execution of the inotify_handle_event and vfs_rename functions.



- [https://github.com/jltxgcy/CVE_2017_7533_EXP](https://github.com/jltxgcy/CVE_2017_7533_EXP) :  ![starts](https://img.shields.io/github/stars/jltxgcy/CVE_2017_7533_EXP.svg) ![forks](https://img.shields.io/github/forks/jltxgcy/CVE_2017_7533_EXP.svg)

## CVE-2017-7529
 Nginx versions since 0.5.6 up to and including 1.13.2 are vulnerable to integer overflow vulnerability in nginx range filter module resulting into leak of potentially sensitive information triggered by specially crafted request.



- [https://github.com/en0f/CVE-2017-7529_PoC](https://github.com/en0f/CVE-2017-7529_PoC) :  ![starts](https://img.shields.io/github/stars/en0f/CVE-2017-7529_PoC.svg) ![forks](https://img.shields.io/github/forks/en0f/CVE-2017-7529_PoC.svg)

- [https://github.com/liusec/CVE-2017-7529](https://github.com/liusec/CVE-2017-7529) :  ![starts](https://img.shields.io/github/stars/liusec/CVE-2017-7529.svg) ![forks](https://img.shields.io/github/forks/liusec/CVE-2017-7529.svg)

- [https://github.com/gemboxteam/exploit-nginx-1.10.3](https://github.com/gemboxteam/exploit-nginx-1.10.3) :  ![starts](https://img.shields.io/github/stars/gemboxteam/exploit-nginx-1.10.3.svg) ![forks](https://img.shields.io/github/forks/gemboxteam/exploit-nginx-1.10.3.svg)

- [https://github.com/Shehzadcyber/CVE-2017-7529](https://github.com/Shehzadcyber/CVE-2017-7529) :  ![starts](https://img.shields.io/github/stars/Shehzadcyber/CVE-2017-7529.svg) ![forks](https://img.shields.io/github/forks/Shehzadcyber/CVE-2017-7529.svg)

- [https://github.com/MaxSecurity/CVE-2017-7529-POC](https://github.com/MaxSecurity/CVE-2017-7529-POC) :  ![starts](https://img.shields.io/github/stars/MaxSecurity/CVE-2017-7529-POC.svg) ![forks](https://img.shields.io/github/forks/MaxSecurity/CVE-2017-7529-POC.svg)

- [https://github.com/mo3zj/Nginx-Remote-Integer-Overflow-Vulnerability](https://github.com/mo3zj/Nginx-Remote-Integer-Overflow-Vulnerability) :  ![starts](https://img.shields.io/github/stars/mo3zj/Nginx-Remote-Integer-Overflow-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/mo3zj/Nginx-Remote-Integer-Overflow-Vulnerability.svg)

- [https://github.com/cyberharsh/nginx-CVE-2017-7529](https://github.com/cyberharsh/nginx-CVE-2017-7529) :  ![starts](https://img.shields.io/github/stars/cyberharsh/nginx-CVE-2017-7529.svg) ![forks](https://img.shields.io/github/forks/cyberharsh/nginx-CVE-2017-7529.svg)

- [https://github.com/cved-sources/cve-2017-7529](https://github.com/cved-sources/cve-2017-7529) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2017-7529.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2017-7529.svg)

- [https://github.com/cyberk1w1/CVE-2017-7529](https://github.com/cyberk1w1/CVE-2017-7529) :  ![starts](https://img.shields.io/github/stars/cyberk1w1/CVE-2017-7529.svg) ![forks](https://img.shields.io/github/forks/cyberk1w1/CVE-2017-7529.svg)

- [https://github.com/CalebFIN/EXP-CVE-2017-75](https://github.com/CalebFIN/EXP-CVE-2017-75) :  ![starts](https://img.shields.io/github/stars/CalebFIN/EXP-CVE-2017-75.svg) ![forks](https://img.shields.io/github/forks/CalebFIN/EXP-CVE-2017-75.svg)

- [https://github.com/SirEagIe/CVE-2017-7529](https://github.com/SirEagIe/CVE-2017-7529) :  ![starts](https://img.shields.io/github/stars/SirEagIe/CVE-2017-7529.svg) ![forks](https://img.shields.io/github/forks/SirEagIe/CVE-2017-7529.svg)

- [https://github.com/coolman6942o/-Exploit-CVE-2017-7529](https://github.com/coolman6942o/-Exploit-CVE-2017-7529) :  ![starts](https://img.shields.io/github/stars/coolman6942o/-Exploit-CVE-2017-7529.svg) ![forks](https://img.shields.io/github/forks/coolman6942o/-Exploit-CVE-2017-7529.svg)

- [https://github.com/daehee/nginx-overflow](https://github.com/daehee/nginx-overflow) :  ![starts](https://img.shields.io/github/stars/daehee/nginx-overflow.svg) ![forks](https://img.shields.io/github/forks/daehee/nginx-overflow.svg)

- [https://github.com/fu2x2000/CVE-2017-7529-Nginx---Remote-Integer-Overflow-Exploit](https://github.com/fu2x2000/CVE-2017-7529-Nginx---Remote-Integer-Overflow-Exploit) :  ![starts](https://img.shields.io/github/stars/fu2x2000/CVE-2017-7529-Nginx---Remote-Integer-Overflow-Exploit.svg) ![forks](https://img.shields.io/github/forks/fu2x2000/CVE-2017-7529-Nginx---Remote-Integer-Overflow-Exploit.svg)

- [https://github.com/fardeen-ahmed/Remote-Integer-Overflow-Vulnerability](https://github.com/fardeen-ahmed/Remote-Integer-Overflow-Vulnerability) :  ![starts](https://img.shields.io/github/stars/fardeen-ahmed/Remote-Integer-Overflow-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/fardeen-ahmed/Remote-Integer-Overflow-Vulnerability.svg)

- [https://github.com/devansh3008/Cve_Finder_2017-7529](https://github.com/devansh3008/Cve_Finder_2017-7529) :  ![starts](https://img.shields.io/github/stars/devansh3008/Cve_Finder_2017-7529.svg) ![forks](https://img.shields.io/github/forks/devansh3008/Cve_Finder_2017-7529.svg)

## CVE-2017-7525
 A deserialization flaw was discovered in the jackson-databind, versions before 2.6.7.1, 2.7.9.1 and 2.8.9, which could allow an unauthenticated user to perform code execution by sending the maliciously crafted input to the readValue method of the ObjectMapper.



- [https://github.com/SecureSkyTechnology/study-struts2-s2-054_055-jackson-cve-2017-7525_cve-2017-15095](https://github.com/SecureSkyTechnology/study-struts2-s2-054_055-jackson-cve-2017-7525_cve-2017-15095) :  ![starts](https://img.shields.io/github/stars/SecureSkyTechnology/study-struts2-s2-054_055-jackson-cve-2017-7525_cve-2017-15095.svg) ![forks](https://img.shields.io/github/forks/SecureSkyTechnology/study-struts2-s2-054_055-jackson-cve-2017-7525_cve-2017-15095.svg)

- [https://github.com/JavanXD/Demo-Exploit-Jackson-RCE](https://github.com/JavanXD/Demo-Exploit-Jackson-RCE) :  ![starts](https://img.shields.io/github/stars/JavanXD/Demo-Exploit-Jackson-RCE.svg) ![forks](https://img.shields.io/github/forks/JavanXD/Demo-Exploit-Jackson-RCE.svg)

- [https://github.com/Ingenuity-Fainting-Goats/CVE-2017-7525-Jackson-Deserialization-Lab](https://github.com/Ingenuity-Fainting-Goats/CVE-2017-7525-Jackson-Deserialization-Lab) :  ![starts](https://img.shields.io/github/stars/Ingenuity-Fainting-Goats/CVE-2017-7525-Jackson-Deserialization-Lab.svg) ![forks](https://img.shields.io/github/forks/Ingenuity-Fainting-Goats/CVE-2017-7525-Jackson-Deserialization-Lab.svg)

- [https://github.com/Dannners/jackson-deserialization-2017-7525](https://github.com/Dannners/jackson-deserialization-2017-7525) :  ![starts](https://img.shields.io/github/stars/Dannners/jackson-deserialization-2017-7525.svg) ![forks](https://img.shields.io/github/forks/Dannners/jackson-deserialization-2017-7525.svg)

- [https://github.com/Nazicc/S2-055](https://github.com/Nazicc/S2-055) :  ![starts](https://img.shields.io/github/stars/Nazicc/S2-055.svg) ![forks](https://img.shields.io/github/forks/Nazicc/S2-055.svg)

- [https://github.com/BassinD/jackson-RCE](https://github.com/BassinD/jackson-RCE) :  ![starts](https://img.shields.io/github/stars/BassinD/jackson-RCE.svg) ![forks](https://img.shields.io/github/forks/BassinD/jackson-RCE.svg)

## CVE-2017-7504
 HTTPServerILServlet.java in JMS over HTTP Invocation Layer of the JbossMQ implementation, which is enabled by default in Red Hat Jboss Application Server &lt;= Jboss 4.X does not restrict the classes for which it performs deserialization, which allows remote attackers to execute arbitrary code via crafted serialized data.



- [https://github.com/wudidwo/CVE-2017-7504-poc](https://github.com/wudidwo/CVE-2017-7504-poc) :  ![starts](https://img.shields.io/github/stars/wudidwo/CVE-2017-7504-poc.svg) ![forks](https://img.shields.io/github/forks/wudidwo/CVE-2017-7504-poc.svg)

## CVE-2017-7494
 Samba since version 3.5.0 and before 4.6.4, 4.5.10 and 4.4.14 is vulnerable to remote code execution vulnerability, allowing a malicious client to upload a shared library to a writable share, and then cause the server to load and execute it.



- [https://github.com/opsxcq/exploit-CVE-2017-7494](https://github.com/opsxcq/exploit-CVE-2017-7494) :  ![starts](https://img.shields.io/github/stars/opsxcq/exploit-CVE-2017-7494.svg) ![forks](https://img.shields.io/github/forks/opsxcq/exploit-CVE-2017-7494.svg)

- [https://github.com/joxeankoret/CVE-2017-7494](https://github.com/joxeankoret/CVE-2017-7494) :  ![starts](https://img.shields.io/github/stars/joxeankoret/CVE-2017-7494.svg) ![forks](https://img.shields.io/github/forks/joxeankoret/CVE-2017-7494.svg)

- [https://github.com/betab0t/cve-2017-7494](https://github.com/betab0t/cve-2017-7494) :  ![starts](https://img.shields.io/github/stars/betab0t/cve-2017-7494.svg) ![forks](https://img.shields.io/github/forks/betab0t/cve-2017-7494.svg)

- [https://github.com/Waffles-2/SambaCry](https://github.com/Waffles-2/SambaCry) :  ![starts](https://img.shields.io/github/stars/Waffles-2/SambaCry.svg) ![forks](https://img.shields.io/github/forks/Waffles-2/SambaCry.svg)

- [https://github.com/brianwrf/SambaHunter](https://github.com/brianwrf/SambaHunter) :  ![starts](https://img.shields.io/github/stars/brianwrf/SambaHunter.svg) ![forks](https://img.shields.io/github/forks/brianwrf/SambaHunter.svg)

- [https://github.com/0xm4ud/noSAMBAnoCRY-CVE-2017-7494](https://github.com/0xm4ud/noSAMBAnoCRY-CVE-2017-7494) :  ![starts](https://img.shields.io/github/stars/0xm4ud/noSAMBAnoCRY-CVE-2017-7494.svg) ![forks](https://img.shields.io/github/forks/0xm4ud/noSAMBAnoCRY-CVE-2017-7494.svg)

- [https://github.com/d3fudd/CVE-2017-7494_SambaCry](https://github.com/d3fudd/CVE-2017-7494_SambaCry) :  ![starts](https://img.shields.io/github/stars/d3fudd/CVE-2017-7494_SambaCry.svg) ![forks](https://img.shields.io/github/forks/d3fudd/CVE-2017-7494_SambaCry.svg)

- [https://github.com/I-Rinka/BIT-EternalBlue-for-macOS_Linux](https://github.com/I-Rinka/BIT-EternalBlue-for-macOS_Linux) :  ![starts](https://img.shields.io/github/stars/I-Rinka/BIT-EternalBlue-for-macOS_Linux.svg) ![forks](https://img.shields.io/github/forks/I-Rinka/BIT-EternalBlue-for-macOS_Linux.svg)

- [https://github.com/00mjk/exploit-CVE-2017-7494](https://github.com/00mjk/exploit-CVE-2017-7494) :  ![starts](https://img.shields.io/github/stars/00mjk/exploit-CVE-2017-7494.svg) ![forks](https://img.shields.io/github/forks/00mjk/exploit-CVE-2017-7494.svg)

- [https://github.com/Zer0d0y/Samba-CVE-2017-7494](https://github.com/Zer0d0y/Samba-CVE-2017-7494) :  ![starts](https://img.shields.io/github/stars/Zer0d0y/Samba-CVE-2017-7494.svg) ![forks](https://img.shields.io/github/forks/Zer0d0y/Samba-CVE-2017-7494.svg)

- [https://github.com/homjxi0e/CVE-2017-7494](https://github.com/homjxi0e/CVE-2017-7494) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-7494.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-7494.svg)

- [https://github.com/gunsan92/CVE2017-7494_quicktest](https://github.com/gunsan92/CVE2017-7494_quicktest) :  ![starts](https://img.shields.io/github/stars/gunsan92/CVE2017-7494_quicktest.svg) ![forks](https://img.shields.io/github/forks/gunsan92/CVE2017-7494_quicktest.svg)

- [https://github.com/cved-sources/cve-2017-7494](https://github.com/cved-sources/cve-2017-7494) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2017-7494.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2017-7494.svg)

- [https://github.com/incredible1yu/CVE-2017-7494](https://github.com/incredible1yu/CVE-2017-7494) :  ![starts](https://img.shields.io/github/stars/incredible1yu/CVE-2017-7494.svg) ![forks](https://img.shields.io/github/forks/incredible1yu/CVE-2017-7494.svg)

- [https://github.com/john-80/cve-2017-7494](https://github.com/john-80/cve-2017-7494) :  ![starts](https://img.shields.io/github/stars/john-80/cve-2017-7494.svg) ![forks](https://img.shields.io/github/forks/john-80/cve-2017-7494.svg)

- [https://github.com/NhutMinh2801/CVE_2017_7494](https://github.com/NhutMinh2801/CVE_2017_7494) :  ![starts](https://img.shields.io/github/stars/NhutMinh2801/CVE_2017_7494.svg) ![forks](https://img.shields.io/github/forks/NhutMinh2801/CVE_2017_7494.svg)

- [https://github.com/Hansindu-M/CVE-2017-7494_IT19115344](https://github.com/Hansindu-M/CVE-2017-7494_IT19115344) :  ![starts](https://img.shields.io/github/stars/Hansindu-M/CVE-2017-7494_IT19115344.svg) ![forks](https://img.shields.io/github/forks/Hansindu-M/CVE-2017-7494_IT19115344.svg)

- [https://github.com/adjaliya/-CVE-2017-7494-Samba-Exploit-POC](https://github.com/adjaliya/-CVE-2017-7494-Samba-Exploit-POC) :  ![starts](https://img.shields.io/github/stars/adjaliya/-CVE-2017-7494-Samba-Exploit-POC.svg) ![forks](https://img.shields.io/github/forks/adjaliya/-CVE-2017-7494-Samba-Exploit-POC.svg)

## CVE-2017-7472
 The KEYS subsystem in the Linux kernel before 4.10.13 allows local users to cause a denial of service (memory consumption) via a series of KEY_REQKEY_DEFL_THREAD_KEYRING keyctl_set_reqkey_keyring calls.



- [https://github.com/homjxi0e/CVE-2017-7472](https://github.com/homjxi0e/CVE-2017-7472) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-7472.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-7472.svg)

## CVE-2017-7410
 Multiple SQL injection vulnerabilities in account/signup.php and account/signup2.php in WebsiteBaker 2.10.0 and earlier allow remote attackers to execute arbitrary SQL commands via the (1) username, (2) display_name parameter.



- [https://github.com/ashangp923/CVE-2017-7410](https://github.com/ashangp923/CVE-2017-7410) :  ![starts](https://img.shields.io/github/stars/ashangp923/CVE-2017-7410.svg) ![forks](https://img.shields.io/github/forks/ashangp923/CVE-2017-7410.svg)

## CVE-2017-7376
 Buffer overflow in libxml2 allows remote attackers to execute arbitrary code by leveraging an incorrect limit for port values when handling redirects.



- [https://github.com/brahmstaedt/libxml2-exploit](https://github.com/brahmstaedt/libxml2-exploit) :  ![starts](https://img.shields.io/github/stars/brahmstaedt/libxml2-exploit.svg) ![forks](https://img.shields.io/github/forks/brahmstaedt/libxml2-exploit.svg)

## CVE-2017-7374
 Use-after-free vulnerability in fs/crypto/ in the Linux kernel before 4.10.7 allows local users to cause a denial of service (NULL pointer dereference) or possibly gain privileges by revoking keyring keys being used for ext4, f2fs, or ubifs encryption, causing cryptographic transform objects to be freed prematurely.



- [https://github.com/ww9210/cve-2017-7374](https://github.com/ww9210/cve-2017-7374) :  ![starts](https://img.shields.io/github/stars/ww9210/cve-2017-7374.svg) ![forks](https://img.shields.io/github/forks/ww9210/cve-2017-7374.svg)

## CVE-2017-7358
 In LightDM through 1.22.0, a directory traversal issue in debian/guest-account.sh allows local attackers to own arbitrary directory path locations and escalate privileges to root when the guest user logs out.



- [https://github.com/JonPichel/CVE-2017-7358](https://github.com/JonPichel/CVE-2017-7358) :  ![starts](https://img.shields.io/github/stars/JonPichel/CVE-2017-7358.svg) ![forks](https://img.shields.io/github/forks/JonPichel/CVE-2017-7358.svg)

## CVE-2017-7308
 The packet_set_ring function in net/packet/af_packet.c in the Linux kernel through 4.10.6 does not properly validate certain block-size data, which allows local users to cause a denial of service (integer signedness error and out-of-bounds write), or gain privileges (if the CAP_NET_RAW capability is held), via crafted system calls.



- [https://github.com/anldori/CVE-2017-7308](https://github.com/anldori/CVE-2017-7308) :  ![starts](https://img.shields.io/github/stars/anldori/CVE-2017-7308.svg) ![forks](https://img.shields.io/github/forks/anldori/CVE-2017-7308.svg)

## CVE-2017-7269
 Buffer overflow in the ScStoragePathFromUrl function in the WebDAV service in Internet Information Services (IIS) 6.0 in Microsoft Windows Server 2003 R2 allows remote attackers to execute arbitrary code via a long header beginning with &quot;If: &lt;http://&quot; in a PROPFIND request, as exploited in the wild in July or August 2016.



- [https://github.com/zcgonvh/cve-2017-7269](https://github.com/zcgonvh/cve-2017-7269) :  ![starts](https://img.shields.io/github/stars/zcgonvh/cve-2017-7269.svg) ![forks](https://img.shields.io/github/forks/zcgonvh/cve-2017-7269.svg)

- [https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269](https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/g0rx/iis6-exploit-2017-CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/g0rx/iis6-exploit-2017-CVE-2017-7269.svg)

- [https://github.com/zcgonvh/cve-2017-7269-tool](https://github.com/zcgonvh/cve-2017-7269-tool) :  ![starts](https://img.shields.io/github/stars/zcgonvh/cve-2017-7269-tool.svg) ![forks](https://img.shields.io/github/forks/zcgonvh/cve-2017-7269-tool.svg)

- [https://github.com/lcatro/CVE-2017-7269-Echo-PoC](https://github.com/lcatro/CVE-2017-7269-Echo-PoC) :  ![starts](https://img.shields.io/github/stars/lcatro/CVE-2017-7269-Echo-PoC.svg) ![forks](https://img.shields.io/github/forks/lcatro/CVE-2017-7269-Echo-PoC.svg)

- [https://github.com/eliuha/webdav_exploit](https://github.com/eliuha/webdav_exploit) :  ![starts](https://img.shields.io/github/stars/eliuha/webdav_exploit.svg) ![forks](https://img.shields.io/github/forks/eliuha/webdav_exploit.svg)

- [https://github.com/Al1ex/CVE-2017-7269](https://github.com/Al1ex/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2017-7269.svg)

- [https://github.com/slimpagey/IIS_6.0_WebDAV_Ruby](https://github.com/slimpagey/IIS_6.0_WebDAV_Ruby) :  ![starts](https://img.shields.io/github/stars/slimpagey/IIS_6.0_WebDAV_Ruby.svg) ![forks](https://img.shields.io/github/forks/slimpagey/IIS_6.0_WebDAV_Ruby.svg)

- [https://github.com/n3rdh4x0r/CVE-2017-7269](https://github.com/n3rdh4x0r/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/n3rdh4x0r/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/n3rdh4x0r/CVE-2017-7269.svg)

- [https://github.com/geniuszlyy/CVE-2017-7269](https://github.com/geniuszlyy/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/geniuszlyy/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/geniuszlyy/CVE-2017-7269.svg)

- [https://github.com/caicai1355/CVE-2017-7269-exploit](https://github.com/caicai1355/CVE-2017-7269-exploit) :  ![starts](https://img.shields.io/github/stars/caicai1355/CVE-2017-7269-exploit.svg) ![forks](https://img.shields.io/github/forks/caicai1355/CVE-2017-7269-exploit.svg)

- [https://github.com/xiaovpn/CVE-2017-7269](https://github.com/xiaovpn/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/xiaovpn/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/xiaovpn/CVE-2017-7269.svg)

- [https://github.com/denchief1/CVE-2017-7269](https://github.com/denchief1/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/denchief1/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/denchief1/CVE-2017-7269.svg)

- [https://github.com/VanishedPeople/CVE-2017-7269](https://github.com/VanishedPeople/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/VanishedPeople/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/VanishedPeople/CVE-2017-7269.svg)

- [https://github.com/Cappricio-Securities/CVE-2017-7269](https://github.com/Cappricio-Securities/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/Cappricio-Securities/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/Cappricio-Securities/CVE-2017-7269.svg)

- [https://github.com/denchief1/CVE-2017-7269_Python3](https://github.com/denchief1/CVE-2017-7269_Python3) :  ![starts](https://img.shields.io/github/stars/denchief1/CVE-2017-7269_Python3.svg) ![forks](https://img.shields.io/github/forks/denchief1/CVE-2017-7269_Python3.svg)

- [https://github.com/mirrorblack/CVE-2017-7269](https://github.com/mirrorblack/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/mirrorblack/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/mirrorblack/CVE-2017-7269.svg)

- [https://github.com/AxthonyV/CVE-2017-7269](https://github.com/AxthonyV/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/AxthonyV/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/AxthonyV/CVE-2017-7269.svg)

- [https://github.com/homjxi0e/cve-2017-7269](https://github.com/homjxi0e/cve-2017-7269) :  ![starts](https://img.shields.io/github/stars/homjxi0e/cve-2017-7269.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/cve-2017-7269.svg)

- [https://github.com/M1a0rz/CVE-2017-7269](https://github.com/M1a0rz/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/M1a0rz/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/M1a0rz/CVE-2017-7269.svg)

- [https://github.com/ThanHuuTuan/CVE-2017-7269](https://github.com/ThanHuuTuan/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/ThanHuuTuan/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/ThanHuuTuan/CVE-2017-7269.svg)

- [https://github.com/whiteHat001/cve-2017-7269picture](https://github.com/whiteHat001/cve-2017-7269picture) :  ![starts](https://img.shields.io/github/stars/whiteHat001/cve-2017-7269picture.svg) ![forks](https://img.shields.io/github/forks/whiteHat001/cve-2017-7269picture.svg)

## CVE-2017-7188
 Zurmo 3.1.1 Stable allows a Cross-Site Scripting (XSS) attack with a base64-encoded SCRIPT element within a data: URL in the returnUrl parameter to default/toggleCollapse.



- [https://github.com/faizzaidi/Zurmo-Stable-3.1.1-XSS-By-Provensec-LLC](https://github.com/faizzaidi/Zurmo-Stable-3.1.1-XSS-By-Provensec-LLC) :  ![starts](https://img.shields.io/github/stars/faizzaidi/Zurmo-Stable-3.1.1-XSS-By-Provensec-LLC.svg) ![forks](https://img.shields.io/github/forks/faizzaidi/Zurmo-Stable-3.1.1-XSS-By-Provensec-LLC.svg)

## CVE-2017-7184
 The xfrm_replay_verify_len function in net/xfrm/xfrm_user.c in the Linux kernel through 4.10.6 does not validate certain size data after an XFRM_MSG_NEWAE update, which allows local users to obtain root privileges or cause a denial of service (heap-based out-of-bounds access) by leveraging the CAP_NET_ADMIN capability, as demonstrated during a Pwn2Own competition at CanSecWest 2017 for the Ubuntu 16.10 linux-image-* package 4.8.0.41.52.



- [https://github.com/rockl/cve-2017-7184](https://github.com/rockl/cve-2017-7184) :  ![starts](https://img.shields.io/github/stars/rockl/cve-2017-7184.svg) ![forks](https://img.shields.io/github/forks/rockl/cve-2017-7184.svg)

- [https://github.com/rockl/cve-2017-7184-bak](https://github.com/rockl/cve-2017-7184-bak) :  ![starts](https://img.shields.io/github/stars/rockl/cve-2017-7184-bak.svg) ![forks](https://img.shields.io/github/forks/rockl/cve-2017-7184-bak.svg)

## CVE-2017-7173
 An issue was discovered in certain Apple products. macOS before 10.13.2 is affected. The issue involves the &quot;Kernel&quot; component. It allows attackers to bypass intended memory-read restrictions via a crafted app.



- [https://github.com/bazad/sysctl_coalition_get_pid_list-dos](https://github.com/bazad/sysctl_coalition_get_pid_list-dos) :  ![starts](https://img.shields.io/github/stars/bazad/sysctl_coalition_get_pid_list-dos.svg) ![forks](https://img.shields.io/github/forks/bazad/sysctl_coalition_get_pid_list-dos.svg)

## CVE-2017-7092
 An issue was discovered in certain Apple products. iOS before 11 is affected. Safari before 11 is affected. iCloud before 7.0 on Windows is affected. iTunes before 12.7 on Windows is affected. tvOS before 11 is affected. The issue involves the &quot;WebKit&quot; component. It allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption and application crash) via a crafted web site.



- [https://github.com/xuechiyaobai/CVE-2017-7092-PoC](https://github.com/xuechiyaobai/CVE-2017-7092-PoC) :  ![starts](https://img.shields.io/github/stars/xuechiyaobai/CVE-2017-7092-PoC.svg) ![forks](https://img.shields.io/github/forks/xuechiyaobai/CVE-2017-7092-PoC.svg)

## CVE-2017-7089
 An issue was discovered in certain Apple products. iOS before 11 is affected. Safari before 11 is affected. iCloud before 7.0 on Windows is affected. The issue involves the &quot;WebKit&quot; component. It allows remote attackers to conduct Universal XSS (UXSS) attacks via a crafted web site that is mishandled during parent-tab processing.



- [https://github.com/Bo0oM/CVE-2017-7089](https://github.com/Bo0oM/CVE-2017-7089) :  ![starts](https://img.shields.io/github/stars/Bo0oM/CVE-2017-7089.svg) ![forks](https://img.shields.io/github/forks/Bo0oM/CVE-2017-7089.svg)

- [https://github.com/aymankhalfatni/Safari_Mac](https://github.com/aymankhalfatni/Safari_Mac) :  ![starts](https://img.shields.io/github/stars/aymankhalfatni/Safari_Mac.svg) ![forks](https://img.shields.io/github/forks/aymankhalfatni/Safari_Mac.svg)

## CVE-2017-7047
 An issue was discovered in certain Apple products. iOS before 10.3.3 is affected. macOS before 10.12.6 is affected. tvOS before 10.2.2 is affected. watchOS before 3.2.3 is affected. The issue involves the &quot;libxpc&quot; component. It allows attackers to execute arbitrary code in a privileged context or cause a denial of service (memory corruption) via a crafted app.



- [https://github.com/JosephShenton/Triple_Fetch-Kernel-Creds](https://github.com/JosephShenton/Triple_Fetch-Kernel-Creds) :  ![starts](https://img.shields.io/github/stars/JosephShenton/Triple_Fetch-Kernel-Creds.svg) ![forks](https://img.shields.io/github/forks/JosephShenton/Triple_Fetch-Kernel-Creds.svg)

- [https://github.com/q1f3/Triple_fetch](https://github.com/q1f3/Triple_fetch) :  ![starts](https://img.shields.io/github/stars/q1f3/Triple_fetch.svg) ![forks](https://img.shields.io/github/forks/q1f3/Triple_fetch.svg)

## CVE-2017-7038
 A DOMParser XSS issue was discovered in certain Apple products. iOS before 10.3.3 is affected. Safari before 10.1.2 is affected. tvOS before 10.2.2 is affected. The issue involves the &quot;WebKit&quot; component.



- [https://github.com/ansjdnakjdnajkd/CVE-2017-7038](https://github.com/ansjdnakjdnajkd/CVE-2017-7038) :  ![starts](https://img.shields.io/github/stars/ansjdnakjdnajkd/CVE-2017-7038.svg) ![forks](https://img.shields.io/github/forks/ansjdnakjdnajkd/CVE-2017-7038.svg)

## CVE-2017-6971
 AlienVault USM and OSSIM before 5.3.7 and NfSen before 1.3.8 allow remote authenticated users to execute arbitrary commands in a privileged context, or launch a reverse shell, via vectors involving the PHP session ID and the NfSen PHP code, aka AlienVault ID ENG-104862.



- [https://github.com/patrickfreed/nfsen-exploit](https://github.com/patrickfreed/nfsen-exploit) :  ![starts](https://img.shields.io/github/stars/patrickfreed/nfsen-exploit.svg) ![forks](https://img.shields.io/github/forks/patrickfreed/nfsen-exploit.svg)

- [https://github.com/KeyStrOke95/nfsen_1.3.7_CVE-2017-6971](https://github.com/KeyStrOke95/nfsen_1.3.7_CVE-2017-6971) :  ![starts](https://img.shields.io/github/stars/KeyStrOke95/nfsen_1.3.7_CVE-2017-6971.svg) ![forks](https://img.shields.io/github/forks/KeyStrOke95/nfsen_1.3.7_CVE-2017-6971.svg)

## CVE-2017-6950
 SAP GUI 7.2 through 7.5 allows remote attackers to bypass intended security policy restrictions and execute arbitrary code via a crafted ABAP code, aka SAP Security Note 2407616.



- [https://github.com/vah13/SAP_ransomware](https://github.com/vah13/SAP_ransomware) :  ![starts](https://img.shields.io/github/stars/vah13/SAP_ransomware.svg) ![forks](https://img.shields.io/github/forks/vah13/SAP_ransomware.svg)

## CVE-2017-6913
 Cross-site scripting (XSS) vulnerability in the Open-Xchange webmail before 7.6.3-rev28 allows remote attackers to inject arbitrary web script or HTML via the event attribute in a time tag.



- [https://github.com/gquere/CVE-2017-6913](https://github.com/gquere/CVE-2017-6913) :  ![starts](https://img.shields.io/github/stars/gquere/CVE-2017-6913.svg) ![forks](https://img.shields.io/github/forks/gquere/CVE-2017-6913.svg)

## CVE-2017-6736
 The Simple Network Management Protocol (SNMP) subsystem of Cisco IOS 12.0 through 12.4 and 15.0 through 15.6 and IOS XE 2.2 through 3.17 contains multiple vulnerabilities that could allow an authenticated, remote attacker to remotely execute code on an affected system or cause an affected system to reload. An attacker could exploit these vulnerabilities by sending a crafted SNMP packet to an affected system via IPv4 or IPv6. Only traffic directed to an affected system can be used to exploit these vulnerabilities. The vulnerabilities are due to a buffer overflow condition in the SNMP subsystem of the affected software. The vulnerabilities affect all versions of SNMP: Versions 1, 2c, and 3. To exploit these vulnerabilities via SNMP Version 2c or earlier, the attacker must know the SNMP read-only community string for the affected system. To exploit these vulnerabilities via SNMP Version 3, the attacker must have user credentials for the affected system. All devices that have enabled SNMP and have not explicitly excluded the affected MIBs or OIDs should be considered vulnerable. Cisco Bug IDs: CSCve57697.



- [https://github.com/GarnetSunset/CiscoIOSSNMPToolkit](https://github.com/GarnetSunset/CiscoIOSSNMPToolkit) :  ![starts](https://img.shields.io/github/stars/GarnetSunset/CiscoIOSSNMPToolkit.svg) ![forks](https://img.shields.io/github/forks/GarnetSunset/CiscoIOSSNMPToolkit.svg)

- [https://github.com/GarnetSunset/CiscoSpectreTakeover](https://github.com/GarnetSunset/CiscoSpectreTakeover) :  ![starts](https://img.shields.io/github/stars/GarnetSunset/CiscoSpectreTakeover.svg) ![forks](https://img.shields.io/github/forks/GarnetSunset/CiscoSpectreTakeover.svg)

## CVE-2017-6640
 A vulnerability in Cisco Prime Data Center Network Manager (DCNM) Software could allow an unauthenticated, remote attacker to log in to the administrative console of a DCNM server by using an account that has a default, static password. The account could be granted root- or system-level privileges. The vulnerability exists because the affected software has a default user account that has a default, static password. The user account is created automatically when the software is installed. An attacker could exploit this vulnerability by connecting remotely to an affected system and logging in to the affected software by using the credentials for this default user account. A successful exploit could allow the attacker to use this default user account to log in to the affected software and gain access to the administrative console of a DCNM server. This vulnerability affects Cisco Prime Data Center Network Manager (DCNM) Software releases prior to Release 10.2(1) for Microsoft Windows, Linux, and Virtual Appliance platforms. Cisco Bug IDs: CSCvd95346.



- [https://github.com/hemp3l/CVE-2017-6640-POC](https://github.com/hemp3l/CVE-2017-6640-POC) :  ![starts](https://img.shields.io/github/stars/hemp3l/CVE-2017-6640-POC.svg) ![forks](https://img.shields.io/github/forks/hemp3l/CVE-2017-6640-POC.svg)

## CVE-2017-6558
 iball Baton 150M iB-WRA150N v1 00000001 1.2.6 build 110401 Rel.47776n devices are prone to an authentication bypass vulnerability that allows remote attackers to view and modify administrative router settings by reading the HTML source code of the password.cgi file.



- [https://github.com/GemGeorge/iBall-UTStar-CVEChecker](https://github.com/GemGeorge/iBall-UTStar-CVEChecker) :  ![starts](https://img.shields.io/github/stars/GemGeorge/iBall-UTStar-CVEChecker.svg) ![forks](https://img.shields.io/github/forks/GemGeorge/iBall-UTStar-CVEChecker.svg)

## CVE-2017-6516
 A Local Privilege Escalation Vulnerability in MagniComp's Sysinfo before 10-H64 for Linux and UNIX platforms could allow a local attacker to gain elevated privileges. Parts of SysInfo require setuid-to-root access in order to access restricted system files and make restricted kernel calls. This access could be exploited by a local attacker to gain a root shell prompt using the right combination of environment variables and command line arguments.



- [https://github.com/Rubytox/CVE-2017-6516-mcsiwrapper-](https://github.com/Rubytox/CVE-2017-6516-mcsiwrapper-) :  ![starts](https://img.shields.io/github/stars/Rubytox/CVE-2017-6516-mcsiwrapper-.svg) ![forks](https://img.shields.io/github/forks/Rubytox/CVE-2017-6516-mcsiwrapper-.svg)

## CVE-2017-6370
 TYPO3 7.6.15 sends an http request to an index.php?loginProvider URI in cases with an https Referer, which allows remote attackers to obtain sensitive cleartext information by sniffing the network and reading the userident and username fields.



- [https://github.com/faizzaidi/TYPO3-v7.6.15-Unencrypted-Login-Request](https://github.com/faizzaidi/TYPO3-v7.6.15-Unencrypted-Login-Request) :  ![starts](https://img.shields.io/github/stars/faizzaidi/TYPO3-v7.6.15-Unencrypted-Login-Request.svg) ![forks](https://img.shields.io/github/forks/faizzaidi/TYPO3-v7.6.15-Unencrypted-Login-Request.svg)

## CVE-2017-6206
 D-Link DGS-1510-28XMP, DGS-1510-28X, DGS-1510-52X, DGS-1510-52, DGS-1510-28P, DGS-1510-28, and DGS-1510-20 Websmart devices with firmware before 1.31.B003 allow attackers to conduct Unauthenticated Information Disclosure attacks via unspecified vectors.



- [https://github.com/varangamin/CVE-2017-6206](https://github.com/varangamin/CVE-2017-6206) :  ![starts](https://img.shields.io/github/stars/varangamin/CVE-2017-6206.svg) ![forks](https://img.shields.io/github/forks/varangamin/CVE-2017-6206.svg)

## CVE-2017-6090
 Unrestricted file upload vulnerability in clients/editclient.php in PhpCollab 2.5.1 and earlier allows remote authenticated users to execute arbitrary code by uploading a file with an executable extension, then accessing it via a direct request to the file in logos_clients/.



- [https://github.com/jlk/exploit-CVE-2017-6090](https://github.com/jlk/exploit-CVE-2017-6090) :  ![starts](https://img.shields.io/github/stars/jlk/exploit-CVE-2017-6090.svg) ![forks](https://img.shields.io/github/forks/jlk/exploit-CVE-2017-6090.svg)

## CVE-2017-6079
 The HTTP web-management application on Edgewater Networks Edgemarc appliances has a hidden page that allows for user-defined commands such as specific iptables routes, etc., to be set. You can use this page as a web shell essentially to execute commands, though you get no feedback client-side from the web application: if the command is valid, it executes. An example is the wget command. The page that allows this has been confirmed in firmware as old as 2006.



- [https://github.com/MostafaSoliman/CVE-2017-6079-Blind-Command-Injection-In-Edgewater-Edgemarc-Devices-Exploit](https://github.com/MostafaSoliman/CVE-2017-6079-Blind-Command-Injection-In-Edgewater-Edgemarc-Devices-Exploit) :  ![starts](https://img.shields.io/github/stars/MostafaSoliman/CVE-2017-6079-Blind-Command-Injection-In-Edgewater-Edgemarc-Devices-Exploit.svg) ![forks](https://img.shields.io/github/forks/MostafaSoliman/CVE-2017-6079-Blind-Command-Injection-In-Edgewater-Edgemarc-Devices-Exploit.svg)

## CVE-2017-6074
 The dccp_rcv_state_process function in net/dccp/input.c in the Linux kernel through 4.9.11 mishandles DCCP_PKT_REQUEST packet data structures in the LISTEN state, which allows local users to obtain root privileges or cause a denial of service (double free) via an application that makes an IPV6_RECVPKTINFO setsockopt system call.



- [https://github.com/BimsaraMalinda/Linux-Kernel-4.4.0-Ubuntu---DCCP-Double-Free-Privilege-Escalation-CVE-2017-6074](https://github.com/BimsaraMalinda/Linux-Kernel-4.4.0-Ubuntu---DCCP-Double-Free-Privilege-Escalation-CVE-2017-6074) :  ![starts](https://img.shields.io/github/stars/BimsaraMalinda/Linux-Kernel-4.4.0-Ubuntu---DCCP-Double-Free-Privilege-Escalation-CVE-2017-6074.svg) ![forks](https://img.shields.io/github/forks/BimsaraMalinda/Linux-Kernel-4.4.0-Ubuntu---DCCP-Double-Free-Privilege-Escalation-CVE-2017-6074.svg)

- [https://github.com/toanthang1842002/CVE-2017-6074](https://github.com/toanthang1842002/CVE-2017-6074) :  ![starts](https://img.shields.io/github/stars/toanthang1842002/CVE-2017-6074.svg) ![forks](https://img.shields.io/github/forks/toanthang1842002/CVE-2017-6074.svg)

## CVE-2017-6008
 A kernel pool overflow in the driver hitmanpro37.sys in Sophos SurfRight HitmanPro before 3.7.20 Build 286 (included in the HitmanPro.Alert solution and Sophos Clean) allows local users to escalate privileges via a malformed IOCTL call.



- [https://github.com/cbayet/Exploit-CVE-2017-6008](https://github.com/cbayet/Exploit-CVE-2017-6008) :  ![starts](https://img.shields.io/github/stars/cbayet/Exploit-CVE-2017-6008.svg) ![forks](https://img.shields.io/github/forks/cbayet/Exploit-CVE-2017-6008.svg)

## CVE-2017-5954
 An issue was discovered in the serialize-to-js package 0.5.0 for Node.js. Untrusted data passed into the deserialize() function can be exploited to achieve arbitrary code execution by passing a JavaScript Object with an Immediately Invoked Function Expression (IIFE).



- [https://github.com/ossf-cve-benchmark/CVE-2017-5954](https://github.com/ossf-cve-benchmark/CVE-2017-5954) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-5954.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-5954.svg)

## CVE-2017-5941
 An issue was discovered in the node-serialize package 0.0.4 for Node.js. Untrusted data passed into the unserialize() function can be exploited to achieve arbitrary code execution by passing a JavaScript Object with an Immediately Invoked Function Expression (IIFE).



- [https://github.com/rodolfomarianocy/nodeserial](https://github.com/rodolfomarianocy/nodeserial) :  ![starts](https://img.shields.io/github/stars/rodolfomarianocy/nodeserial.svg) ![forks](https://img.shields.io/github/forks/rodolfomarianocy/nodeserial.svg)

- [https://github.com/uartu0/nodejshell](https://github.com/uartu0/nodejshell) :  ![starts](https://img.shields.io/github/stars/uartu0/nodejshell.svg) ![forks](https://img.shields.io/github/forks/uartu0/nodejshell.svg)

- [https://github.com/Cr4zyD14m0nd137/Lab-for-cve-2018-15133](https://github.com/Cr4zyD14m0nd137/Lab-for-cve-2018-15133) :  ![starts](https://img.shields.io/github/stars/Cr4zyD14m0nd137/Lab-for-cve-2018-15133.svg) ![forks](https://img.shields.io/github/forks/Cr4zyD14m0nd137/Lab-for-cve-2018-15133.svg)

- [https://github.com/turnernator1/Node.js-CVE-2017-5941](https://github.com/turnernator1/Node.js-CVE-2017-5941) :  ![starts](https://img.shields.io/github/stars/turnernator1/Node.js-CVE-2017-5941.svg) ![forks](https://img.shields.io/github/forks/turnernator1/Node.js-CVE-2017-5941.svg)

- [https://github.com/Frivolous-scholar/CVE-2017-5941-NodeJS-RCE](https://github.com/Frivolous-scholar/CVE-2017-5941-NodeJS-RCE) :  ![starts](https://img.shields.io/github/stars/Frivolous-scholar/CVE-2017-5941-NodeJS-RCE.svg) ![forks](https://img.shields.io/github/forks/Frivolous-scholar/CVE-2017-5941-NodeJS-RCE.svg)

## CVE-2017-5816
 A Remote Code Execution vulnerability in HPE Intelligent Management Center (iMC) PLAT version 7.3 E0504P04 was found.



- [https://github.com/oxagast/oxasploits](https://github.com/oxagast/oxasploits) :  ![starts](https://img.shields.io/github/stars/oxagast/oxasploits.svg) ![forks](https://img.shields.io/github/forks/oxagast/oxasploits.svg)

## CVE-2017-5792
 A Remote Code Execution vulnerability in HPE Intelligent Management Center (iMC) PLAT version 7.3 E0504P2 was found.



- [https://github.com/scanfsec/HPE-iMC-7.3-RMI-Java-Deserialization](https://github.com/scanfsec/HPE-iMC-7.3-RMI-Java-Deserialization) :  ![starts](https://img.shields.io/github/stars/scanfsec/HPE-iMC-7.3-RMI-Java-Deserialization.svg) ![forks](https://img.shields.io/github/forks/scanfsec/HPE-iMC-7.3-RMI-Java-Deserialization.svg)

## CVE-2017-5754
 Systems with microprocessors utilizing speculative execution and indirect branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis of the data cache.



- [https://github.com/speed47/spectre-meltdown-checker](https://github.com/speed47/spectre-meltdown-checker) :  ![starts](https://img.shields.io/github/stars/speed47/spectre-meltdown-checker.svg) ![forks](https://img.shields.io/github/forks/speed47/spectre-meltdown-checker.svg)

- [https://github.com/nsacyber/Hardware-and-Firmware-Security-Guidance](https://github.com/nsacyber/Hardware-and-Firmware-Security-Guidance) :  ![starts](https://img.shields.io/github/stars/nsacyber/Hardware-and-Firmware-Security-Guidance.svg) ![forks](https://img.shields.io/github/forks/nsacyber/Hardware-and-Firmware-Security-Guidance.svg)

- [https://github.com/ionescu007/SpecuCheck](https://github.com/ionescu007/SpecuCheck) :  ![starts](https://img.shields.io/github/stars/ionescu007/SpecuCheck.svg) ![forks](https://img.shields.io/github/forks/ionescu007/SpecuCheck.svg)

- [https://github.com/raphaelsc/Am-I-affected-by-Meltdown](https://github.com/raphaelsc/Am-I-affected-by-Meltdown) :  ![starts](https://img.shields.io/github/stars/raphaelsc/Am-I-affected-by-Meltdown.svg) ![forks](https://img.shields.io/github/forks/raphaelsc/Am-I-affected-by-Meltdown.svg)

- [https://github.com/Viralmaniar/In-Spectre-Meltdown](https://github.com/Viralmaniar/In-Spectre-Meltdown) :  ![starts](https://img.shields.io/github/stars/Viralmaniar/In-Spectre-Meltdown.svg) ![forks](https://img.shields.io/github/forks/Viralmaniar/In-Spectre-Meltdown.svg)

- [https://github.com/mathse/meltdown-spectre-bios-list](https://github.com/mathse/meltdown-spectre-bios-list) :  ![starts](https://img.shields.io/github/stars/mathse/meltdown-spectre-bios-list.svg) ![forks](https://img.shields.io/github/forks/mathse/meltdown-spectre-bios-list.svg)

- [https://github.com/neuhalje/presentation_meltdown_spectre](https://github.com/neuhalje/presentation_meltdown_spectre) :  ![starts](https://img.shields.io/github/stars/neuhalje/presentation_meltdown_spectre.svg) ![forks](https://img.shields.io/github/forks/neuhalje/presentation_meltdown_spectre.svg)

- [https://github.com/jarmouz/spectre_meltdown](https://github.com/jarmouz/spectre_meltdown) :  ![starts](https://img.shields.io/github/stars/jarmouz/spectre_meltdown.svg) ![forks](https://img.shields.io/github/forks/jarmouz/spectre_meltdown.svg)

- [https://github.com/gonoph/ansible-meltdown-spectre](https://github.com/gonoph/ansible-meltdown-spectre) :  ![starts](https://img.shields.io/github/stars/gonoph/ansible-meltdown-spectre.svg) ![forks](https://img.shields.io/github/forks/gonoph/ansible-meltdown-spectre.svg)

- [https://github.com/zzado/Meltdown](https://github.com/zzado/Meltdown) :  ![starts](https://img.shields.io/github/stars/zzado/Meltdown.svg) ![forks](https://img.shields.io/github/forks/zzado/Meltdown.svg)

- [https://github.com/miglen/Awesome-Meltdown-Spectre](https://github.com/miglen/Awesome-Meltdown-Spectre) :  ![starts](https://img.shields.io/github/stars/miglen/Awesome-Meltdown-Spectre.svg) ![forks](https://img.shields.io/github/forks/miglen/Awesome-Meltdown-Spectre.svg)

- [https://github.com/jdmulloy/meltdown-aws-scanner](https://github.com/jdmulloy/meltdown-aws-scanner) :  ![starts](https://img.shields.io/github/stars/jdmulloy/meltdown-aws-scanner.svg) ![forks](https://img.shields.io/github/forks/jdmulloy/meltdown-aws-scanner.svg)

- [https://github.com/speecyy/Am-I-affected-by-Meltdown](https://github.com/speecyy/Am-I-affected-by-Meltdown) :  ![starts](https://img.shields.io/github/stars/speecyy/Am-I-affected-by-Meltdown.svg) ![forks](https://img.shields.io/github/forks/speecyy/Am-I-affected-by-Meltdown.svg)

- [https://github.com/GregAskew/SpeculativeExecutionAssessment](https://github.com/GregAskew/SpeculativeExecutionAssessment) :  ![starts](https://img.shields.io/github/stars/GregAskew/SpeculativeExecutionAssessment.svg) ![forks](https://img.shields.io/github/forks/GregAskew/SpeculativeExecutionAssessment.svg)

- [https://github.com/kevincoakley/puppet-spectre_meltdown](https://github.com/kevincoakley/puppet-spectre_meltdown) :  ![starts](https://img.shields.io/github/stars/kevincoakley/puppet-spectre_meltdown.svg) ![forks](https://img.shields.io/github/forks/kevincoakley/puppet-spectre_meltdown.svg)

## CVE-2017-5753
 Systems with microprocessors utilizing speculative execution and branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis.



- [https://github.com/speed47/spectre-meltdown-checker](https://github.com/speed47/spectre-meltdown-checker) :  ![starts](https://img.shields.io/github/stars/speed47/spectre-meltdown-checker.svg) ![forks](https://img.shields.io/github/forks/speed47/spectre-meltdown-checker.svg)

- [https://github.com/nsacyber/Hardware-and-Firmware-Security-Guidance](https://github.com/nsacyber/Hardware-and-Firmware-Security-Guidance) :  ![starts](https://img.shields.io/github/stars/nsacyber/Hardware-and-Firmware-Security-Guidance.svg) ![forks](https://img.shields.io/github/forks/nsacyber/Hardware-and-Firmware-Security-Guidance.svg)

- [https://github.com/Eugnis/spectre-attack](https://github.com/Eugnis/spectre-attack) :  ![starts](https://img.shields.io/github/stars/Eugnis/spectre-attack.svg) ![forks](https://img.shields.io/github/forks/Eugnis/spectre-attack.svg)

- [https://github.com/mathse/meltdown-spectre-bios-list](https://github.com/mathse/meltdown-spectre-bios-list) :  ![starts](https://img.shields.io/github/stars/mathse/meltdown-spectre-bios-list.svg) ![forks](https://img.shields.io/github/forks/mathse/meltdown-spectre-bios-list.svg)

- [https://github.com/00052/spectre-attack-example](https://github.com/00052/spectre-attack-example) :  ![starts](https://img.shields.io/github/stars/00052/spectre-attack-example.svg) ![forks](https://img.shields.io/github/forks/00052/spectre-attack-example.svg)

- [https://github.com/neuhalje/presentation_meltdown_spectre](https://github.com/neuhalje/presentation_meltdown_spectre) :  ![starts](https://img.shields.io/github/stars/neuhalje/presentation_meltdown_spectre.svg) ![forks](https://img.shields.io/github/forks/neuhalje/presentation_meltdown_spectre.svg)

- [https://github.com/ixtal23/spectreScope](https://github.com/ixtal23/spectreScope) :  ![starts](https://img.shields.io/github/stars/ixtal23/spectreScope.svg) ![forks](https://img.shields.io/github/forks/ixtal23/spectreScope.svg)

- [https://github.com/GarnetSunset/CiscoSpectreTakeover](https://github.com/GarnetSunset/CiscoSpectreTakeover) :  ![starts](https://img.shields.io/github/stars/GarnetSunset/CiscoSpectreTakeover.svg) ![forks](https://img.shields.io/github/forks/GarnetSunset/CiscoSpectreTakeover.svg)

- [https://github.com/EdwardOwusuAdjei/Spectre-PoC](https://github.com/EdwardOwusuAdjei/Spectre-PoC) :  ![starts](https://img.shields.io/github/stars/EdwardOwusuAdjei/Spectre-PoC.svg) ![forks](https://img.shields.io/github/forks/EdwardOwusuAdjei/Spectre-PoC.svg)

- [https://github.com/gonoph/ansible-meltdown-spectre](https://github.com/gonoph/ansible-meltdown-spectre) :  ![starts](https://img.shields.io/github/stars/gonoph/ansible-meltdown-spectre.svg) ![forks](https://img.shields.io/github/forks/gonoph/ansible-meltdown-spectre.svg)

- [https://github.com/miglen/Awesome-Meltdown-Spectre](https://github.com/miglen/Awesome-Meltdown-Spectre) :  ![starts](https://img.shields.io/github/stars/miglen/Awesome-Meltdown-Spectre.svg) ![forks](https://img.shields.io/github/forks/miglen/Awesome-Meltdown-Spectre.svg)

- [https://github.com/albertleecn/cve-2017-5753](https://github.com/albertleecn/cve-2017-5753) :  ![starts](https://img.shields.io/github/stars/albertleecn/cve-2017-5753.svg) ![forks](https://img.shields.io/github/forks/albertleecn/cve-2017-5753.svg)

- [https://github.com/pedrolucasoliva/spectre-attack-demo](https://github.com/pedrolucasoliva/spectre-attack-demo) :  ![starts](https://img.shields.io/github/stars/pedrolucasoliva/spectre-attack-demo.svg) ![forks](https://img.shields.io/github/forks/pedrolucasoliva/spectre-attack-demo.svg)

- [https://github.com/sachinthaBS/Spectre-Vulnerability-CVE-2017-5753-](https://github.com/sachinthaBS/Spectre-Vulnerability-CVE-2017-5753-) :  ![starts](https://img.shields.io/github/stars/sachinthaBS/Spectre-Vulnerability-CVE-2017-5753-.svg) ![forks](https://img.shields.io/github/forks/sachinthaBS/Spectre-Vulnerability-CVE-2017-5753-.svg)

- [https://github.com/GregAskew/SpeculativeExecutionAssessment](https://github.com/GregAskew/SpeculativeExecutionAssessment) :  ![starts](https://img.shields.io/github/stars/GregAskew/SpeculativeExecutionAssessment.svg) ![forks](https://img.shields.io/github/forks/GregAskew/SpeculativeExecutionAssessment.svg)

## CVE-2017-5721
 Insufficient input validation in system firmware for Intel NUC7i3BNK, NUC7i3BNH, NUC7i5BNK, NUC7i5BNH, NUC7i7BNH versions BN0049 and below allows local attackers to execute arbitrary code via manipulation of memory.



- [https://github.com/embedi/smm_usbrt_poc](https://github.com/embedi/smm_usbrt_poc) :  ![starts](https://img.shields.io/github/stars/embedi/smm_usbrt_poc.svg) ![forks](https://img.shields.io/github/forks/embedi/smm_usbrt_poc.svg)

## CVE-2017-5715
 Systems with microprocessors utilizing speculative execution and indirect branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis.



- [https://github.com/speed47/spectre-meltdown-checker](https://github.com/speed47/spectre-meltdown-checker) :  ![starts](https://img.shields.io/github/stars/speed47/spectre-meltdown-checker.svg) ![forks](https://img.shields.io/github/forks/speed47/spectre-meltdown-checker.svg)

- [https://github.com/nsacyber/Hardware-and-Firmware-Security-Guidance](https://github.com/nsacyber/Hardware-and-Firmware-Security-Guidance) :  ![starts](https://img.shields.io/github/stars/nsacyber/Hardware-and-Firmware-Security-Guidance.svg) ![forks](https://img.shields.io/github/forks/nsacyber/Hardware-and-Firmware-Security-Guidance.svg)

- [https://github.com/Eugnis/spectre-attack](https://github.com/Eugnis/spectre-attack) :  ![starts](https://img.shields.io/github/stars/Eugnis/spectre-attack.svg) ![forks](https://img.shields.io/github/forks/Eugnis/spectre-attack.svg)

- [https://github.com/ionescu007/SpecuCheck](https://github.com/ionescu007/SpecuCheck) :  ![starts](https://img.shields.io/github/stars/ionescu007/SpecuCheck.svg) ![forks](https://img.shields.io/github/forks/ionescu007/SpecuCheck.svg)

- [https://github.com/Viralmaniar/In-Spectre-Meltdown](https://github.com/Viralmaniar/In-Spectre-Meltdown) :  ![starts](https://img.shields.io/github/stars/Viralmaniar/In-Spectre-Meltdown.svg) ![forks](https://img.shields.io/github/forks/Viralmaniar/In-Spectre-Meltdown.svg)

- [https://github.com/opsxcq/exploit-cve-2017-5715](https://github.com/opsxcq/exploit-cve-2017-5715) :  ![starts](https://img.shields.io/github/stars/opsxcq/exploit-cve-2017-5715.svg) ![forks](https://img.shields.io/github/forks/opsxcq/exploit-cve-2017-5715.svg)

- [https://github.com/mathse/meltdown-spectre-bios-list](https://github.com/mathse/meltdown-spectre-bios-list) :  ![starts](https://img.shields.io/github/stars/mathse/meltdown-spectre-bios-list.svg) ![forks](https://img.shields.io/github/forks/mathse/meltdown-spectre-bios-list.svg)

- [https://github.com/00052/spectre-attack-example](https://github.com/00052/spectre-attack-example) :  ![starts](https://img.shields.io/github/stars/00052/spectre-attack-example.svg) ![forks](https://img.shields.io/github/forks/00052/spectre-attack-example.svg)

- [https://github.com/neuhalje/presentation_meltdown_spectre](https://github.com/neuhalje/presentation_meltdown_spectre) :  ![starts](https://img.shields.io/github/stars/neuhalje/presentation_meltdown_spectre.svg) ![forks](https://img.shields.io/github/forks/neuhalje/presentation_meltdown_spectre.svg)

- [https://github.com/ixtal23/spectreScope](https://github.com/ixtal23/spectreScope) :  ![starts](https://img.shields.io/github/stars/ixtal23/spectreScope.svg) ![forks](https://img.shields.io/github/forks/ixtal23/spectreScope.svg)

- [https://github.com/jarmouz/spectre_meltdown](https://github.com/jarmouz/spectre_meltdown) :  ![starts](https://img.shields.io/github/stars/jarmouz/spectre_meltdown.svg) ![forks](https://img.shields.io/github/forks/jarmouz/spectre_meltdown.svg)

- [https://github.com/GarnetSunset/CiscoSpectreTakeover](https://github.com/GarnetSunset/CiscoSpectreTakeover) :  ![starts](https://img.shields.io/github/stars/GarnetSunset/CiscoSpectreTakeover.svg) ![forks](https://img.shields.io/github/forks/GarnetSunset/CiscoSpectreTakeover.svg)

- [https://github.com/EdwardOwusuAdjei/Spectre-PoC](https://github.com/EdwardOwusuAdjei/Spectre-PoC) :  ![starts](https://img.shields.io/github/stars/EdwardOwusuAdjei/Spectre-PoC.svg) ![forks](https://img.shields.io/github/forks/EdwardOwusuAdjei/Spectre-PoC.svg)

- [https://github.com/gonoph/ansible-meltdown-spectre](https://github.com/gonoph/ansible-meltdown-spectre) :  ![starts](https://img.shields.io/github/stars/gonoph/ansible-meltdown-spectre.svg) ![forks](https://img.shields.io/github/forks/gonoph/ansible-meltdown-spectre.svg)

- [https://github.com/miglen/Awesome-Meltdown-Spectre](https://github.com/miglen/Awesome-Meltdown-Spectre) :  ![starts](https://img.shields.io/github/stars/miglen/Awesome-Meltdown-Spectre.svg) ![forks](https://img.shields.io/github/forks/miglen/Awesome-Meltdown-Spectre.svg)

- [https://github.com/pedrolucasoliva/spectre-attack-demo](https://github.com/pedrolucasoliva/spectre-attack-demo) :  ![starts](https://img.shields.io/github/stars/pedrolucasoliva/spectre-attack-demo.svg) ![forks](https://img.shields.io/github/forks/pedrolucasoliva/spectre-attack-demo.svg)

- [https://github.com/GalloLuigi/Analisi-CVE-2017-5715](https://github.com/GalloLuigi/Analisi-CVE-2017-5715) :  ![starts](https://img.shields.io/github/stars/GalloLuigi/Analisi-CVE-2017-5715.svg) ![forks](https://img.shields.io/github/forks/GalloLuigi/Analisi-CVE-2017-5715.svg)

- [https://github.com/GregAskew/SpeculativeExecutionAssessment](https://github.com/GregAskew/SpeculativeExecutionAssessment) :  ![starts](https://img.shields.io/github/stars/GregAskew/SpeculativeExecutionAssessment.svg) ![forks](https://img.shields.io/github/forks/GregAskew/SpeculativeExecutionAssessment.svg)

- [https://github.com/dmo2118/retpoline-audit](https://github.com/dmo2118/retpoline-audit) :  ![starts](https://img.shields.io/github/stars/dmo2118/retpoline-audit.svg) ![forks](https://img.shields.io/github/forks/dmo2118/retpoline-audit.svg)

- [https://github.com/kevincoakley/puppet-spectre_meltdown](https://github.com/kevincoakley/puppet-spectre_meltdown) :  ![starts](https://img.shields.io/github/stars/kevincoakley/puppet-spectre_meltdown.svg) ![forks](https://img.shields.io/github/forks/kevincoakley/puppet-spectre_meltdown.svg)

## CVE-2017-5693
 Firmware in the Intel Puma 5, 6, and 7 Series might experience resource depletion or timeout, which allows a network attacker to create a denial of service via crafted network traffic.



- [https://github.com/LunNova/Puma6Fail](https://github.com/LunNova/Puma6Fail) :  ![starts](https://img.shields.io/github/stars/LunNova/Puma6Fail.svg) ![forks](https://img.shields.io/github/forks/LunNova/Puma6Fail.svg)

## CVE-2017-5689
 An unprivileged network attacker could gain system privileges to provisioned Intel manageability SKUs: Intel Active Management Technology (AMT) and Intel Standard Manageability (ISM). An unprivileged local attacker could provision manageability features gaining unprivileged network or local system privileges on Intel manageability SKUs: Intel Active Management Technology (AMT), Intel Standard Manageability (ISM), and Intel Small Business Technology (SBT).



- [https://github.com/bartblaze/Disable-Intel-AMT](https://github.com/bartblaze/Disable-Intel-AMT) :  ![starts](https://img.shields.io/github/stars/bartblaze/Disable-Intel-AMT.svg) ![forks](https://img.shields.io/github/forks/bartblaze/Disable-Intel-AMT.svg)

- [https://github.com/embedi/amt_auth_bypass_poc](https://github.com/embedi/amt_auth_bypass_poc) :  ![starts](https://img.shields.io/github/stars/embedi/amt_auth_bypass_poc.svg) ![forks](https://img.shields.io/github/forks/embedi/amt_auth_bypass_poc.svg)

- [https://github.com/CerberusSecurity/CVE-2017-5689](https://github.com/CerberusSecurity/CVE-2017-5689) :  ![starts](https://img.shields.io/github/stars/CerberusSecurity/CVE-2017-5689.svg) ![forks](https://img.shields.io/github/forks/CerberusSecurity/CVE-2017-5689.svg)

- [https://github.com/haxrob/amthoneypot](https://github.com/haxrob/amthoneypot) :  ![starts](https://img.shields.io/github/stars/haxrob/amthoneypot.svg) ![forks](https://img.shields.io/github/forks/haxrob/amthoneypot.svg)

- [https://github.com/Bijaye/intel_amt_bypass](https://github.com/Bijaye/intel_amt_bypass) :  ![starts](https://img.shields.io/github/stars/Bijaye/intel_amt_bypass.svg) ![forks](https://img.shields.io/github/forks/Bijaye/intel_amt_bypass.svg)

- [https://github.com/baonq-me/cve2017-5689](https://github.com/baonq-me/cve2017-5689) :  ![starts](https://img.shields.io/github/stars/baonq-me/cve2017-5689.svg) ![forks](https://img.shields.io/github/forks/baonq-me/cve2017-5689.svg)

- [https://github.com/TheWay-hue/CVE-2017-5689-Checker](https://github.com/TheWay-hue/CVE-2017-5689-Checker) :  ![starts](https://img.shields.io/github/stars/TheWay-hue/CVE-2017-5689-Checker.svg) ![forks](https://img.shields.io/github/forks/TheWay-hue/CVE-2017-5689-Checker.svg)

## CVE-2017-5645
 In Apache Log4j 2.x before 2.8.2, when using the TCP socket server or UDP socket server to receive serialized log events from another application, a specially crafted binary payload can be sent that, when deserialized, can execute arbitrary code.



- [https://github.com/pimps/CVE-2017-5645](https://github.com/pimps/CVE-2017-5645) :  ![starts](https://img.shields.io/github/stars/pimps/CVE-2017-5645.svg) ![forks](https://img.shields.io/github/forks/pimps/CVE-2017-5645.svg)

- [https://github.com/HynekPetrak/log4shell-finder](https://github.com/HynekPetrak/log4shell-finder) :  ![starts](https://img.shields.io/github/stars/HynekPetrak/log4shell-finder.svg) ![forks](https://img.shields.io/github/forks/HynekPetrak/log4shell-finder.svg)

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

- [https://github.com/xsscx/cve-2017-5638](https://github.com/xsscx/cve-2017-5638) :  ![starts](https://img.shields.io/github/stars/xsscx/cve-2017-5638.svg) ![forks](https://img.shields.io/github/forks/xsscx/cve-2017-5638.svg)

- [https://github.com/ret2jazzy/Struts-Apache-ExploitPack](https://github.com/ret2jazzy/Struts-Apache-ExploitPack) :  ![starts](https://img.shields.io/github/stars/ret2jazzy/Struts-Apache-ExploitPack.svg) ![forks](https://img.shields.io/github/forks/ret2jazzy/Struts-Apache-ExploitPack.svg)

- [https://github.com/jrrdev/cve-2017-5638](https://github.com/jrrdev/cve-2017-5638) :  ![starts](https://img.shields.io/github/stars/jrrdev/cve-2017-5638.svg) ![forks](https://img.shields.io/github/forks/jrrdev/cve-2017-5638.svg)

- [https://github.com/win3zz/CVE-2017-5638](https://github.com/win3zz/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/win3zz/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/win3zz/CVE-2017-5638.svg)

- [https://github.com/sUbc0ol/Apache-Struts2-RCE-Exploit-v2-CVE-2017-5638](https://github.com/sUbc0ol/Apache-Struts2-RCE-Exploit-v2-CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/sUbc0ol/Apache-Struts2-RCE-Exploit-v2-CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/sUbc0ol/Apache-Struts2-RCE-Exploit-v2-CVE-2017-5638.svg)

- [https://github.com/tahmed11/strutsy](https://github.com/tahmed11/strutsy) :  ![starts](https://img.shields.io/github/stars/tahmed11/strutsy.svg) ![forks](https://img.shields.io/github/forks/tahmed11/strutsy.svg)

- [https://github.com/Iletee/struts2-rce](https://github.com/Iletee/struts2-rce) :  ![starts](https://img.shields.io/github/stars/Iletee/struts2-rce.svg) ![forks](https://img.shields.io/github/forks/Iletee/struts2-rce.svg)

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

- [https://github.com/paralelo14/CVE_2017_5638](https://github.com/paralelo14/CVE_2017_5638) :  ![starts](https://img.shields.io/github/stars/paralelo14/CVE_2017_5638.svg) ![forks](https://img.shields.io/github/forks/paralelo14/CVE_2017_5638.svg)

- [https://github.com/oktavianto/CVE-2017-5638-Apache-Struts2](https://github.com/oktavianto/CVE-2017-5638-Apache-Struts2) :  ![starts](https://img.shields.io/github/stars/oktavianto/CVE-2017-5638-Apache-Struts2.svg) ![forks](https://img.shields.io/github/forks/oktavianto/CVE-2017-5638-Apache-Struts2.svg)

- [https://github.com/riyazwalikar/struts-rce-cve-2017-5638](https://github.com/riyazwalikar/struts-rce-cve-2017-5638) :  ![starts](https://img.shields.io/github/stars/riyazwalikar/struts-rce-cve-2017-5638.svg) ![forks](https://img.shields.io/github/forks/riyazwalikar/struts-rce-cve-2017-5638.svg)

- [https://github.com/ggolawski/struts-rce](https://github.com/ggolawski/struts-rce) :  ![starts](https://img.shields.io/github/stars/ggolawski/struts-rce.svg) ![forks](https://img.shields.io/github/forks/ggolawski/struts-rce.svg)

- [https://github.com/sighup1/cybersecurity-struts2](https://github.com/sighup1/cybersecurity-struts2) :  ![starts](https://img.shields.io/github/stars/sighup1/cybersecurity-struts2.svg) ![forks](https://img.shields.io/github/forks/sighup1/cybersecurity-struts2.svg)

- [https://github.com/lizhi16/CVE-2017-5638](https://github.com/lizhi16/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/lizhi16/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/lizhi16/CVE-2017-5638.svg)

- [https://github.com/jongmartinez/CVE-2017-5638](https://github.com/jongmartinez/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/jongmartinez/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/jongmartinez/CVE-2017-5638.svg)

- [https://github.com/0xConstant/CVE-2017-5638](https://github.com/0xConstant/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/0xConstant/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/0xConstant/CVE-2017-5638.svg)

- [https://github.com/jptr218/struts_hack](https://github.com/jptr218/struts_hack) :  ![starts](https://img.shields.io/github/stars/jptr218/struts_hack.svg) ![forks](https://img.shields.io/github/forks/jptr218/struts_hack.svg)

- [https://github.com/m3ssap0/struts2_cve-2017-5638](https://github.com/m3ssap0/struts2_cve-2017-5638) :  ![starts](https://img.shields.io/github/stars/m3ssap0/struts2_cve-2017-5638.svg) ![forks](https://img.shields.io/github/forks/m3ssap0/struts2_cve-2017-5638.svg)

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

- [https://github.com/eeehit/CVE-2017-5638](https://github.com/eeehit/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/eeehit/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/eeehit/CVE-2017-5638.svg)

- [https://github.com/AndreasKl/CVE-2017-5638](https://github.com/AndreasKl/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/AndreasKl/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/AndreasKl/CVE-2017-5638.svg)

- [https://github.com/Badbird3/CVE-2017-5638](https://github.com/Badbird3/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/Badbird3/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/Badbird3/CVE-2017-5638.svg)

- [https://github.com/readloud/CVE-2017-5638](https://github.com/readloud/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/readloud/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/readloud/CVE-2017-5638.svg)

- [https://github.com/Xhendos/CVE-2017-5638](https://github.com/Xhendos/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/Xhendos/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/Xhendos/CVE-2017-5638.svg)

- [https://github.com/bongbongco/cve-2017-5638](https://github.com/bongbongco/cve-2017-5638) :  ![starts](https://img.shields.io/github/stars/bongbongco/cve-2017-5638.svg) ![forks](https://img.shields.io/github/forks/bongbongco/cve-2017-5638.svg)

- [https://github.com/colorblindpentester/CVE-2017-5638](https://github.com/colorblindpentester/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/colorblindpentester/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/colorblindpentester/CVE-2017-5638.svg)

- [https://github.com/mritunjay-k/CVE-2017-5638](https://github.com/mritunjay-k/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/mritunjay-k/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/mritunjay-k/CVE-2017-5638.svg)

- [https://github.com/random-robbie/CVE-2017-5638](https://github.com/random-robbie/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/random-robbie/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/random-robbie/CVE-2017-5638.svg)

- [https://github.com/bhagdave/CVE-2017-5638](https://github.com/bhagdave/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/bhagdave/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/bhagdave/CVE-2017-5638.svg)

- [https://github.com/Tankirat/CVE-2017-5638](https://github.com/Tankirat/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/Tankirat/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/Tankirat/CVE-2017-5638.svg)

- [https://github.com/jrrombaldo/CVE-2017-5638](https://github.com/jrrombaldo/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/jrrombaldo/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/jrrombaldo/CVE-2017-5638.svg)

- [https://github.com/injcristianrojas/cve-2017-5638](https://github.com/injcristianrojas/cve-2017-5638) :  ![starts](https://img.shields.io/github/stars/injcristianrojas/cve-2017-5638.svg) ![forks](https://img.shields.io/github/forks/injcristianrojas/cve-2017-5638.svg)

- [https://github.com/mcassano/cve-2017-5638](https://github.com/mcassano/cve-2017-5638) :  ![starts](https://img.shields.io/github/stars/mcassano/cve-2017-5638.svg) ![forks](https://img.shields.io/github/forks/mcassano/cve-2017-5638.svg)

- [https://github.com/homjxi0e/CVE-2017-5638](https://github.com/homjxi0e/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-5638.svg)

- [https://github.com/mfdev-solution/Exploit-CVE-2017-5638](https://github.com/mfdev-solution/Exploit-CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/mfdev-solution/Exploit-CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/mfdev-solution/Exploit-CVE-2017-5638.svg)

- [https://github.com/cafnet/apache-struts-v2-CVE-2017-5638](https://github.com/cafnet/apache-struts-v2-CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/cafnet/apache-struts-v2-CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/cafnet/apache-struts-v2-CVE-2017-5638.svg)

- [https://github.com/sonatype-workshops/struts2-rce](https://github.com/sonatype-workshops/struts2-rce) :  ![starts](https://img.shields.io/github/stars/sonatype-workshops/struts2-rce.svg) ![forks](https://img.shields.io/github/forks/sonatype-workshops/struts2-rce.svg)

- [https://github.com/leandrocamposcardoso/CVE-2017-5638-Mass-Exploit](https://github.com/leandrocamposcardoso/CVE-2017-5638-Mass-Exploit) :  ![starts](https://img.shields.io/github/stars/leandrocamposcardoso/CVE-2017-5638-Mass-Exploit.svg) ![forks](https://img.shields.io/github/forks/leandrocamposcardoso/CVE-2017-5638-Mass-Exploit.svg)

- [https://github.com/kloutkake/CVE-2017-5638-PoC](https://github.com/kloutkake/CVE-2017-5638-PoC) :  ![starts](https://img.shields.io/github/stars/kloutkake/CVE-2017-5638-PoC.svg) ![forks](https://img.shields.io/github/forks/kloutkake/CVE-2017-5638-PoC.svg)

- [https://github.com/invisiblethreat/strutser](https://github.com/invisiblethreat/strutser) :  ![starts](https://img.shields.io/github/stars/invisiblethreat/strutser.svg) ![forks](https://img.shields.io/github/forks/invisiblethreat/strutser.svg)

- [https://github.com/sjitech/test_struts2_vulnerability_CVE-2017-5638](https://github.com/sjitech/test_struts2_vulnerability_CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/sjitech/test_struts2_vulnerability_CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/sjitech/test_struts2_vulnerability_CVE-2017-5638.svg)

- [https://github.com/c002/Apache-Struts](https://github.com/c002/Apache-Struts) :  ![starts](https://img.shields.io/github/stars/c002/Apache-Struts.svg) ![forks](https://img.shields.io/github/forks/c002/Apache-Struts.svg)

- [https://github.com/FredBrave/CVE-2017-5638-ApacheStruts2.3.5](https://github.com/FredBrave/CVE-2017-5638-ApacheStruts2.3.5) :  ![starts](https://img.shields.io/github/stars/FredBrave/CVE-2017-5638-ApacheStruts2.3.5.svg) ![forks](https://img.shields.io/github/forks/FredBrave/CVE-2017-5638-ApacheStruts2.3.5.svg)

- [https://github.com/TamiiLambrado/Apache-Struts-CVE-2017-5638-RCE-Mass-Scanner](https://github.com/TamiiLambrado/Apache-Struts-CVE-2017-5638-RCE-Mass-Scanner) :  ![starts](https://img.shields.io/github/stars/TamiiLambrado/Apache-Struts-CVE-2017-5638-RCE-Mass-Scanner.svg) ![forks](https://img.shields.io/github/forks/TamiiLambrado/Apache-Struts-CVE-2017-5638-RCE-Mass-Scanner.svg)

- [https://github.com/testpilot031/vulnerability_struts-2.3.31](https://github.com/testpilot031/vulnerability_struts-2.3.31) :  ![starts](https://img.shields.io/github/stars/testpilot031/vulnerability_struts-2.3.31.svg) ![forks](https://img.shields.io/github/forks/testpilot031/vulnerability_struts-2.3.31.svg)

- [https://github.com/xeroxis-xs/Computer-Security-Apache-Struts-Vulnerability](https://github.com/xeroxis-xs/Computer-Security-Apache-Struts-Vulnerability) :  ![starts](https://img.shields.io/github/stars/xeroxis-xs/Computer-Security-Apache-Struts-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/xeroxis-xs/Computer-Security-Apache-Struts-Vulnerability.svg)

- [https://github.com/Nithylesh/web-application-firewall-](https://github.com/Nithylesh/web-application-firewall-) :  ![starts](https://img.shields.io/github/stars/Nithylesh/web-application-firewall-.svg) ![forks](https://img.shields.io/github/forks/Nithylesh/web-application-firewall-.svg)

- [https://github.com/donaldashdown/Common-Vulnerability-and-Exploit](https://github.com/donaldashdown/Common-Vulnerability-and-Exploit) :  ![starts](https://img.shields.io/github/stars/donaldashdown/Common-Vulnerability-and-Exploit.svg) ![forks](https://img.shields.io/github/forks/donaldashdown/Common-Vulnerability-and-Exploit.svg)

- [https://github.com/andrewkroh/auditbeat-apache-struts-demo](https://github.com/andrewkroh/auditbeat-apache-struts-demo) :  ![starts](https://img.shields.io/github/stars/andrewkroh/auditbeat-apache-struts-demo.svg) ![forks](https://img.shields.io/github/forks/andrewkroh/auditbeat-apache-struts-demo.svg)

## CVE-2017-5633
 Multiple cross-site request forgery (CSRF) vulnerabilities on the D-Link DI-524 Wireless Router with firmware 9.01 allow remote attackers to (1) change the admin password, (2) reboot the device, or (3) possibly have unspecified other impact via crafted requests to CGI programs.



- [https://github.com/cardangi/Exploit-CVE-2017-5633](https://github.com/cardangi/Exploit-CVE-2017-5633) :  ![starts](https://img.shields.io/github/stars/cardangi/Exploit-CVE-2017-5633.svg) ![forks](https://img.shields.io/github/forks/cardangi/Exploit-CVE-2017-5633.svg)

## CVE-2017-5521
 An issue was discovered on NETGEAR R8500, R8300, R7000, R6400, R7300, R7100LG, R6300v2, WNDR3400v3, WNR3500Lv2, R6250, R6700, R6900, and R8000 devices. They are prone to password disclosure via simple crafted requests to the web management server. The bug is exploitable remotely if the remote management option is set, and can also be exploited given access to the router over LAN or WLAN. When trying to access the web panel, a user is asked to authenticate; if the authentication is canceled and password recovery is not enabled, the user is redirected to a page that exposes a password recovery token. If a user supplies the correct token to the page /passwordrecovered.cgi?id=TOKEN (and password recovery is not enabled), they will receive the admin password for the router. If password recovery is set the exploit will fail, as it will ask the user for the recovery questions that were previously set when enabling that feature. This is persistent (even after disabling the recovery option, the exploit will fail) because the router will ask for the security questions.



- [https://github.com/lilloX/routerPWN](https://github.com/lilloX/routerPWN) :  ![starts](https://img.shields.io/github/stars/lilloX/routerPWN.svg) ![forks](https://img.shields.io/github/forks/lilloX/routerPWN.svg)

## CVE-2017-5487
 wp-includes/rest-api/endpoints/class-wp-rest-users-controller.php in the REST API implementation in WordPress 4.7 before 4.7.1 does not properly restrict listings of post authors, which allows remote attackers to obtain sensitive information via a wp-json/wp/v2/users request.



- [https://github.com/K3ysTr0K3R/CVE-2017-5487-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2017-5487-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2017-5487-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2017-5487-EXPLOIT.svg)

- [https://github.com/anx0ing/Wordpress_Brute](https://github.com/anx0ing/Wordpress_Brute) :  ![starts](https://img.shields.io/github/stars/anx0ing/Wordpress_Brute.svg) ![forks](https://img.shields.io/github/forks/anx0ing/Wordpress_Brute.svg)

- [https://github.com/patilkr/wp-CVE-2017-5487-exploit](https://github.com/patilkr/wp-CVE-2017-5487-exploit) :  ![starts](https://img.shields.io/github/stars/patilkr/wp-CVE-2017-5487-exploit.svg) ![forks](https://img.shields.io/github/forks/patilkr/wp-CVE-2017-5487-exploit.svg)

- [https://github.com/GeunSam2/CVE-2017-5487](https://github.com/GeunSam2/CVE-2017-5487) :  ![starts](https://img.shields.io/github/stars/GeunSam2/CVE-2017-5487.svg) ![forks](https://img.shields.io/github/forks/GeunSam2/CVE-2017-5487.svg)

- [https://github.com/teambugsbunny/wpUsersScan](https://github.com/teambugsbunny/wpUsersScan) :  ![starts](https://img.shields.io/github/stars/teambugsbunny/wpUsersScan.svg) ![forks](https://img.shields.io/github/forks/teambugsbunny/wpUsersScan.svg)

- [https://github.com/dream434/CVE-2017-5487](https://github.com/dream434/CVE-2017-5487) :  ![starts](https://img.shields.io/github/stars/dream434/CVE-2017-5487.svg) ![forks](https://img.shields.io/github/forks/dream434/CVE-2017-5487.svg)

- [https://github.com/SeasonLeague/CVE-2017-5487](https://github.com/SeasonLeague/CVE-2017-5487) :  ![starts](https://img.shields.io/github/stars/SeasonLeague/CVE-2017-5487.svg) ![forks](https://img.shields.io/github/forks/SeasonLeague/CVE-2017-5487.svg)

- [https://github.com/zkhalidul/GrabberWP-CVE-2017-5487](https://github.com/zkhalidul/GrabberWP-CVE-2017-5487) :  ![starts](https://img.shields.io/github/stars/zkhalidul/GrabberWP-CVE-2017-5487.svg) ![forks](https://img.shields.io/github/forks/zkhalidul/GrabberWP-CVE-2017-5487.svg)

- [https://github.com/Ravindu-Priyankara/CVE-2017-5487-vulnerability-on-NSBM](https://github.com/Ravindu-Priyankara/CVE-2017-5487-vulnerability-on-NSBM) :  ![starts](https://img.shields.io/github/stars/Ravindu-Priyankara/CVE-2017-5487-vulnerability-on-NSBM.svg) ![forks](https://img.shields.io/github/forks/Ravindu-Priyankara/CVE-2017-5487-vulnerability-on-NSBM.svg)

- [https://github.com/R3K1NG/wpUsersScan](https://github.com/R3K1NG/wpUsersScan) :  ![starts](https://img.shields.io/github/stars/R3K1NG/wpUsersScan.svg) ![forks](https://img.shields.io/github/forks/R3K1NG/wpUsersScan.svg)

## CVE-2017-5415
 An attack can use a blob URL and script to spoof an arbitrary addressbar URL prefaced by &quot;blob:&quot; as the protocol, leading to user confusion and further spoofing attacks. This vulnerability affects Firefox &lt; 52.



- [https://github.com/649/CVE-2017-5415](https://github.com/649/CVE-2017-5415) :  ![starts](https://img.shields.io/github/stars/649/CVE-2017-5415.svg) ![forks](https://img.shields.io/github/forks/649/CVE-2017-5415.svg)

## CVE-2017-5223
 An issue was discovered in PHPMailer before 5.2.22. PHPMailer's msgHTML method applies transformations to an HTML document to make it usable as an email message body. One of the transformations is to convert relative image URLs into attachments using a script-provided base directory. If no base directory is provided, it resolves to /, meaning that relative image URLs get treated as absolute local file paths and added as attachments. To form a remote vulnerability, the msgHTML method must be called, passed an unfiltered, user-supplied HTML document, and must not set a base directory.



- [https://github.com/cscli/CVE-2017-5223](https://github.com/cscli/CVE-2017-5223) :  ![starts](https://img.shields.io/github/stars/cscli/CVE-2017-5223.svg) ![forks](https://img.shields.io/github/forks/cscli/CVE-2017-5223.svg)

## CVE-2017-5124
 Incorrect application of sandboxing in Blink in Google Chrome prior to 62.0.3202.62 allowed a remote attacker to inject arbitrary scripts or HTML (UXSS) via a crafted MHTML page.



- [https://github.com/Bo0oM/CVE-2017-5124](https://github.com/Bo0oM/CVE-2017-5124) :  ![starts](https://img.shields.io/github/stars/Bo0oM/CVE-2017-5124.svg) ![forks](https://img.shields.io/github/forks/Bo0oM/CVE-2017-5124.svg)

## CVE-2017-5123
 Insufficient data validation in waitid allowed an user to escape sandboxes on Linux.



- [https://github.com/c3r34lk1ll3r/CVE-2017-5123](https://github.com/c3r34lk1ll3r/CVE-2017-5123) :  ![starts](https://img.shields.io/github/stars/c3r34lk1ll3r/CVE-2017-5123.svg) ![forks](https://img.shields.io/github/forks/c3r34lk1ll3r/CVE-2017-5123.svg)

- [https://github.com/0x5068656e6f6c/CVE-2017-5123](https://github.com/0x5068656e6f6c/CVE-2017-5123) :  ![starts](https://img.shields.io/github/stars/0x5068656e6f6c/CVE-2017-5123.svg) ![forks](https://img.shields.io/github/forks/0x5068656e6f6c/CVE-2017-5123.svg)

- [https://github.com/Synacktiv-contrib/exploiting-cve-2017-5123](https://github.com/Synacktiv-contrib/exploiting-cve-2017-5123) :  ![starts](https://img.shields.io/github/stars/Synacktiv-contrib/exploiting-cve-2017-5123.svg) ![forks](https://img.shields.io/github/forks/Synacktiv-contrib/exploiting-cve-2017-5123.svg)

- [https://github.com/FloatingGuy/CVE-2017-5123](https://github.com/FloatingGuy/CVE-2017-5123) :  ![starts](https://img.shields.io/github/stars/FloatingGuy/CVE-2017-5123.svg) ![forks](https://img.shields.io/github/forks/FloatingGuy/CVE-2017-5123.svg)

- [https://github.com/echo-devim/exploit_linux_kernel4.13](https://github.com/echo-devim/exploit_linux_kernel4.13) :  ![starts](https://img.shields.io/github/stars/echo-devim/exploit_linux_kernel4.13.svg) ![forks](https://img.shields.io/github/forks/echo-devim/exploit_linux_kernel4.13.svg)

- [https://github.com/teawater/CVE-2017-5123](https://github.com/teawater/CVE-2017-5123) :  ![starts](https://img.shields.io/github/stars/teawater/CVE-2017-5123.svg) ![forks](https://img.shields.io/github/forks/teawater/CVE-2017-5123.svg)

- [https://github.com/h1bAna/CVE-2017-5123](https://github.com/h1bAna/CVE-2017-5123) :  ![starts](https://img.shields.io/github/stars/h1bAna/CVE-2017-5123.svg) ![forks](https://img.shields.io/github/forks/h1bAna/CVE-2017-5123.svg)

## CVE-2017-5007
 Blink in Google Chrome prior to 56.0.2924.76 for Linux, Windows and Mac, and 56.0.2924.87 for Android, incorrectly handled the sequence of events when closing a page, which allowed a remote attacker to inject arbitrary scripts or HTML (UXSS) via a crafted HTML page.



- [https://github.com/Ang-YC/CVE-2017-5007](https://github.com/Ang-YC/CVE-2017-5007) :  ![starts](https://img.shields.io/github/stars/Ang-YC/CVE-2017-5007.svg) ![forks](https://img.shields.io/github/forks/Ang-YC/CVE-2017-5007.svg)

## CVE-2017-5005
 Stack-based buffer overflow in Quick Heal Internet Security 10.1.0.316 and earlier, Total Security 10.1.0.316 and earlier, and AntiVirus Pro 10.1.0.316 and earlier on OS X allows remote attackers to execute arbitrary code via a crafted LC_UNIXTHREAD.cmdsize field in a Mach-O file that is mishandled during a Security Scan (aka Custom Scan) operation.



- [https://github.com/payatu/QuickHeal](https://github.com/payatu/QuickHeal) :  ![starts](https://img.shields.io/github/stars/payatu/QuickHeal.svg) ![forks](https://img.shields.io/github/forks/payatu/QuickHeal.svg)

## CVE-2017-4971
 An issue was discovered in Pivotal Spring Web Flow through 2.4.4. Applications that do not change the value of the MvcViewFactoryCreator useSpringBinding property which is disabled by default (i.e., set to 'false') can be vulnerable to malicious EL expressions in view states that process form submissions but do not have a sub-element to declare explicit data binding property mappings.



- [https://github.com/cved-sources/cve-2017-4971](https://github.com/cved-sources/cve-2017-4971) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2017-4971.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2017-4971.svg)

## CVE-2017-4878
 ** RE



- [https://github.com/brianwrf/CVE-2017-4878-Samples](https://github.com/brianwrf/CVE-2017-4878-Samples) :  ![starts](https://img.shields.io/github/stars/brianwrf/CVE-2017-4878-Samples.svg) ![forks](https://img.shields.io/github/forks/brianwrf/CVE-2017-4878-Samples.svg)

## CVE-2017-4490
 ** RE



- [https://github.com/homjxi0e/CVE-2017-4490-](https://github.com/homjxi0e/CVE-2017-4490-) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-4490-.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-4490-.svg)

- [https://github.com/homjxi0e/CVE-2017-4490-install-Script-Python-in-Terminal-](https://github.com/homjxi0e/CVE-2017-4490-install-Script-Python-in-Terminal-) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-4490-install-Script-Python-in-Terminal-.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-4490-install-Script-Python-in-Terminal-.svg)

## CVE-2017-3881
 A vulnerability in the Cisco Cluster Management Protocol (CMP) processing code in Cisco IOS and Cisco IOS XE Software could allow an unauthenticated, remote attacker to cause a reload of an affected device or remotely execute code with elevated privileges. The Cluster Management Protocol utilizes Telnet internally as a signaling and command protocol between cluster members. The vulnerability is due to the combination of two factors: (1) the failure to restrict the use of CMP-specific Telnet options only to internal, local communications between cluster members and instead accept and process such options over any Telnet connection to an affected device; and (2) the incorrect processing of malformed CMP-specific Telnet options. An attacker could exploit this vulnerability by sending malformed CMP-specific Telnet options while establishing a Telnet session with an affected Cisco device configured to accept Telnet connections. An exploit could allow an attacker to execute arbitrary code and obtain full control of the device or cause a reload of the affected device. This affects Catalyst switches, Embedded Service 2020 switches, Enhanced Layer 2 EtherSwitch Service Module, Enhanced Layer 2/3 EtherSwitch Service Module, Gigabit Ethernet Switch Module (CGESM) for HP, IE Industrial Ethernet switches, ME 4924-10GE switch, RF Gateway 10, and SM-X Layer 2/3 EtherSwitch Service Module. Cisco Bug IDs: CSCvd48893.



- [https://github.com/artkond/cisco-rce](https://github.com/artkond/cisco-rce) :  ![starts](https://img.shields.io/github/stars/artkond/cisco-rce.svg) ![forks](https://img.shields.io/github/forks/artkond/cisco-rce.svg)

- [https://github.com/homjxi0e/CVE-2017-3881-exploit-cisco-](https://github.com/homjxi0e/CVE-2017-3881-exploit-cisco-) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-3881-exploit-cisco-.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-3881-exploit-cisco-.svg)

- [https://github.com/1337g/CVE-2017-3881](https://github.com/1337g/CVE-2017-3881) :  ![starts](https://img.shields.io/github/stars/1337g/CVE-2017-3881.svg) ![forks](https://img.shields.io/github/forks/1337g/CVE-2017-3881.svg)

- [https://github.com/mzakyz666/PoC-CVE-2017-3881](https://github.com/mzakyz666/PoC-CVE-2017-3881) :  ![starts](https://img.shields.io/github/stars/mzakyz666/PoC-CVE-2017-3881.svg) ![forks](https://img.shields.io/github/forks/mzakyz666/PoC-CVE-2017-3881.svg)

- [https://github.com/homjxi0e/CVE-2017-3881-Cisco](https://github.com/homjxi0e/CVE-2017-3881-Cisco) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-3881-Cisco.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-3881-Cisco.svg)

## CVE-2017-3730
 In OpenSSL 1.1.0 before 1.1.0d, if a malicious server supplies bad parameters for a DHE or ECDHE key exchange then this can result in the client attempting to dereference a NULL pointer leading to a client crash. This could be exploited in a Denial of Service attack.



- [https://github.com/olivierh59500/CVE-2017-3730](https://github.com/olivierh59500/CVE-2017-3730) :  ![starts](https://img.shields.io/github/stars/olivierh59500/CVE-2017-3730.svg) ![forks](https://img.shields.io/github/forks/olivierh59500/CVE-2017-3730.svg)

## CVE-2017-3599
 Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server: Pluggable Auth). Supported versions that are affected are 5.6.35 and earlier and 5.7.17 and earlier. Easily &quot;exploitable&quot; vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.0 Base Score 7.5 (Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H). NOTE: the previous information is from the April 2017 CPU. Oracle has not commented on third-party claims that this issue is an integer overflow in sql/auth/sql_authentication.cc which allows remote attackers to cause a denial of service via a crafted authentication packet.



- [https://github.com/SECFORCE/CVE-2017-3599](https://github.com/SECFORCE/CVE-2017-3599) :  ![starts](https://img.shields.io/github/stars/SECFORCE/CVE-2017-3599.svg) ![forks](https://img.shields.io/github/forks/SECFORCE/CVE-2017-3599.svg)

- [https://github.com/jptr218/mysql_dos](https://github.com/jptr218/mysql_dos) :  ![starts](https://img.shields.io/github/stars/jptr218/mysql_dos.svg) ![forks](https://img.shields.io/github/forks/jptr218/mysql_dos.svg)

## CVE-2017-3506
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Web Services). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.0, 12.2.1.1 and 12.2.1.2. Difficult to exploit vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification access to critical data or all Oracle WebLogic Server accessible data as well as unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.0 Base Score 7.4 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N).



- [https://github.com/0xn0ne/weblogicScanner](https://github.com/0xn0ne/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/0xn0ne/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/0xn0ne/weblogicScanner.svg)

- [https://github.com/Al1ex/CVE-2017-3506](https://github.com/Al1ex/CVE-2017-3506) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2017-3506.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2017-3506.svg)

- [https://github.com/ianxtianxt/CVE-2017-3506](https://github.com/ianxtianxt/CVE-2017-3506) :  ![starts](https://img.shields.io/github/stars/ianxtianxt/CVE-2017-3506.svg) ![forks](https://img.shields.io/github/forks/ianxtianxt/CVE-2017-3506.svg)

## CVE-2017-3248
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.0 and 12.2.1.1. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS v3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).



- [https://github.com/0xn0ne/weblogicScanner](https://github.com/0xn0ne/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/0xn0ne/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/0xn0ne/weblogicScanner.svg)

- [https://github.com/ianxtianxt/CVE-2017-3248](https://github.com/ianxtianxt/CVE-2017-3248) :  ![starts](https://img.shields.io/github/stars/ianxtianxt/CVE-2017-3248.svg) ![forks](https://img.shields.io/github/forks/ianxtianxt/CVE-2017-3248.svg)

- [https://github.com/BabyTeam1024/CVE-2017-3248](https://github.com/BabyTeam1024/CVE-2017-3248) :  ![starts](https://img.shields.io/github/stars/BabyTeam1024/CVE-2017-3248.svg) ![forks](https://img.shields.io/github/forks/BabyTeam1024/CVE-2017-3248.svg)

## CVE-2017-3241
 Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent: RMI). Supported versions that are affected are Java SE: 6u131, 7u121 and 8u112; Java SE Embedded: 8u111; JRockit: R28.3.12. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Java SE, Java SE Embedded, JRockit. While the vulnerability is in Java SE, Java SE Embedded, JRockit, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in takeover of Java SE, Java SE Embedded, JRockit. Note: This vulnerability can only be exploited by supplying data to APIs in the specified Component without using Untrusted Java Web Start applications or Untrusted Java applets, such as through a web service. CVSS v3.0 Base Score 9.0 (Confidentiality, Integrity and Availability impacts).



- [https://github.com/xfei3/CVE-2017-3241-POC](https://github.com/xfei3/CVE-2017-3241-POC) :  ![starts](https://img.shields.io/github/stars/xfei3/CVE-2017-3241-POC.svg) ![forks](https://img.shields.io/github/forks/xfei3/CVE-2017-3241-POC.svg)

- [https://github.com/scopion/CVE-2017-3241](https://github.com/scopion/CVE-2017-3241) :  ![starts](https://img.shields.io/github/stars/scopion/CVE-2017-3241.svg) ![forks](https://img.shields.io/github/forks/scopion/CVE-2017-3241.svg)

## CVE-2017-3164
 Server Side Request Forgery in Apache Solr, versions 1.3 until 7.6 (inclusive). Since the &quot;shards&quot; parameter does not have a corresponding whitelist mechanism, a remote attacker with access to the server could make Solr perform an HTTP GET request to any reachable URL.



- [https://github.com/tdwyer/PoC_CVE-2017-3164_CVE-2017-1262](https://github.com/tdwyer/PoC_CVE-2017-3164_CVE-2017-1262) :  ![starts](https://img.shields.io/github/stars/tdwyer/PoC_CVE-2017-3164_CVE-2017-1262.svg) ![forks](https://img.shields.io/github/forks/tdwyer/PoC_CVE-2017-3164_CVE-2017-1262.svg)

## CVE-2017-3143
 An attacker who is able to send and receive messages to an authoritative DNS server and who has knowledge of a valid TSIG key name for the zone and service being targeted may be able to manipulate BIND into accepting an unauthorized dynamic update. Affects BIND 9.4.0-&gt;9.8.8, 9.9.0-&gt;9.9.10-P1, 9.10.0-&gt;9.10.5-P1, 9.11.0-&gt;9.11.1-P1, 9.9.3-S1-&gt;9.9.10-S2, 9.10.5-S1-&gt;9.10.5-S2.



- [https://github.com/saaph/CVE-2017-3143](https://github.com/saaph/CVE-2017-3143) :  ![starts](https://img.shields.io/github/stars/saaph/CVE-2017-3143.svg) ![forks](https://img.shields.io/github/forks/saaph/CVE-2017-3143.svg)

## CVE-2017-3078
 Adobe Flash Player versions 25.0.0.171 and earlier have an exploitable memory corruption vulnerability in the Adobe Texture Format (ATF) module. Successful exploitation could lead to arbitrary code execution.



- [https://github.com/homjxi0e/CVE-2017-3078](https://github.com/homjxi0e/CVE-2017-3078) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-3078.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-3078.svg)

## CVE-2017-3066
 Adobe ColdFusion 2016 Update 3 and earlier, ColdFusion 11 update 11 and earlier, ColdFusion 10 Update 22 and earlier have a Java deserialization vulnerability in the Apache BlazeDS library. Successful exploitation could lead to arbitrary code execution.



- [https://github.com/codewhitesec/ColdFusionPwn](https://github.com/codewhitesec/ColdFusionPwn) :  ![starts](https://img.shields.io/github/stars/codewhitesec/ColdFusionPwn.svg) ![forks](https://img.shields.io/github/forks/codewhitesec/ColdFusionPwn.svg)

- [https://github.com/cucadili/CVE-2017-3066](https://github.com/cucadili/CVE-2017-3066) :  ![starts](https://img.shields.io/github/stars/cucadili/CVE-2017-3066.svg) ![forks](https://img.shields.io/github/forks/cucadili/CVE-2017-3066.svg)

## CVE-2017-3000
 Adobe Flash Player versions 24.0.0.221 and earlier have a vulnerability in the random number generator used for constant blinding. Successful exploitation could lead to information disclosure.



- [https://github.com/dangokyo/CVE-2017-3000](https://github.com/dangokyo/CVE-2017-3000) :  ![starts](https://img.shields.io/github/stars/dangokyo/CVE-2017-3000.svg) ![forks](https://img.shields.io/github/forks/dangokyo/CVE-2017-3000.svg)

## CVE-2017-2903
 An exploitable integer overflow exists in the DPX loading functionality of the Blender open-source 3d creation suite version 2.78c. A specially crafted '.cin' file can cause an integer overflow resulting in a buffer overflow which can allow for code execution under the context of the application. An attacker can convince a user to use the file as an asset via the sequencer in order to trigger this vulnerability.



- [https://github.com/SpiralBL0CK/dpx_work_CVE-2017-2903](https://github.com/SpiralBL0CK/dpx_work_CVE-2017-2903) :  ![starts](https://img.shields.io/github/stars/SpiralBL0CK/dpx_work_CVE-2017-2903.svg) ![forks](https://img.shields.io/github/forks/SpiralBL0CK/dpx_work_CVE-2017-2903.svg)

## CVE-2017-2824
 An exploitable code execution vulnerability exists in the trapper command functionality of Zabbix Server 2.4.X. A specially crafted set of packets can cause a command injection resulting in remote code execution. An attacker can make requests from an active Zabbix Proxy to trigger this vulnerability.



- [https://github.com/listenquiet/cve-2017-2824-reverse-shell](https://github.com/listenquiet/cve-2017-2824-reverse-shell) :  ![starts](https://img.shields.io/github/stars/listenquiet/cve-2017-2824-reverse-shell.svg) ![forks](https://img.shields.io/github/forks/listenquiet/cve-2017-2824-reverse-shell.svg)

## CVE-2017-2793
 An exploitable heap corruption vulnerability exists in the UnCompressUnicode functionality of Antenna House DMC HTMLFilter used by MarkLogic 8.0-6. A specially crafted xls file can cause a heap corruption resulting in arbitrary code execution. An attacker can send/provide malicious XLS file to trigger this vulnerability.



- [https://github.com/sUbc0ol/Detection-for-CVE-2017-2793](https://github.com/sUbc0ol/Detection-for-CVE-2017-2793) :  ![starts](https://img.shields.io/github/stars/sUbc0ol/Detection-for-CVE-2017-2793.svg) ![forks](https://img.shields.io/github/forks/sUbc0ol/Detection-for-CVE-2017-2793.svg)

## CVE-2017-2751
 A BIOS password extraction vulnerability has been reported on certain consumer notebooks with firmware F.22 and others. The BIOS password was stored in CMOS in a way that allowed it to be extracted. This applies to consumer notebooks launched in early 2014.



- [https://github.com/BaderSZ/CVE-2017-2751](https://github.com/BaderSZ/CVE-2017-2751) :  ![starts](https://img.shields.io/github/stars/BaderSZ/CVE-2017-2751.svg) ![forks](https://img.shields.io/github/forks/BaderSZ/CVE-2017-2751.svg)

## CVE-2017-2741
 A potential security vulnerability has been identified with HP PageWide Printers, HP OfficeJet Pro Printers, with firmware before 1708D. This vulnerability could potentially be exploited to execute arbitrary code.



- [https://github.com/dopheide-esnet/zeek-jetdirect](https://github.com/dopheide-esnet/zeek-jetdirect) :  ![starts](https://img.shields.io/github/stars/dopheide-esnet/zeek-jetdirect.svg) ![forks](https://img.shields.io/github/forks/dopheide-esnet/zeek-jetdirect.svg)

## CVE-2017-2671
 The ping_unhash function in net/ipv4/ping.c in the Linux kernel through 4.10.8 is too late in obtaining a certain lock and consequently cannot ensure that disconnect function calls are safe, which allows local users to cause a denial of service (panic) by leveraging access to the protocol value of IPPROTO_ICMP in a socket system call.



- [https://github.com/homjxi0e/CVE-2017-2671](https://github.com/homjxi0e/CVE-2017-2671) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-2671.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-2671.svg)

## CVE-2017-2666
 It was discovered in Undertow that the code that parsed the HTTP request line permitted invalid characters. This could be exploited, in conjunction with a proxy that also permitted the invalid characters but with a different interpretation, to inject data into the HTTP response. By manipulating the HTTP response the attacker could poison a web-cache, perform an XSS attack, or obtain sensitive information from requests other than their own.



- [https://github.com/tafamace/CVE-2017-2666](https://github.com/tafamace/CVE-2017-2666) :  ![starts](https://img.shields.io/github/stars/tafamace/CVE-2017-2666.svg) ![forks](https://img.shields.io/github/forks/tafamace/CVE-2017-2666.svg)

## CVE-2017-2636
 Race condition in drivers/tty/n_hdlc.c in the Linux kernel through 4.10.1 allows local users to gain privileges or cause a denial of service (double free) by setting the HDLC line discipline.



- [https://github.com/alexzorin/cve-2017-2636-el](https://github.com/alexzorin/cve-2017-2636-el) :  ![starts](https://img.shields.io/github/stars/alexzorin/cve-2017-2636-el.svg) ![forks](https://img.shields.io/github/forks/alexzorin/cve-2017-2636-el.svg)

## CVE-2017-2388
 An issue was discovered in certain Apple products. macOS before 10.12.4 is affected. The issue involves the &quot;IOFireWireFamily&quot; component. It allows attackers to cause a denial of service (NULL pointer dereference) via a crafted app.



- [https://github.com/bazad/IOFireWireFamily-null-deref](https://github.com/bazad/IOFireWireFamily-null-deref) :  ![starts](https://img.shields.io/github/stars/bazad/IOFireWireFamily-null-deref.svg) ![forks](https://img.shields.io/github/forks/bazad/IOFireWireFamily-null-deref.svg)

## CVE-2017-2370
 An issue was discovered in certain Apple products. iOS before 10.2.1 is affected. macOS before 10.12.3 is affected. tvOS before 10.1.1 is affected. watchOS before 3.1.3 is affected. The issue involves the &quot;Kernel&quot; component. It allows attackers to execute arbitrary code in a privileged context or cause a denial of service (buffer overflow) via a crafted app.



- [https://github.com/Peterpan0927/CVE-2017-2370](https://github.com/Peterpan0927/CVE-2017-2370) :  ![starts](https://img.shields.io/github/stars/Peterpan0927/CVE-2017-2370.svg) ![forks](https://img.shields.io/github/forks/Peterpan0927/CVE-2017-2370.svg)

- [https://github.com/Rootkitsmm-zz/extra_recipe-iOS-10.2](https://github.com/Rootkitsmm-zz/extra_recipe-iOS-10.2) :  ![starts](https://img.shields.io/github/stars/Rootkitsmm-zz/extra_recipe-iOS-10.2.svg) ![forks](https://img.shields.io/github/forks/Rootkitsmm-zz/extra_recipe-iOS-10.2.svg)

- [https://github.com/JackBro/extra_recipe](https://github.com/JackBro/extra_recipe) :  ![starts](https://img.shields.io/github/stars/JackBro/extra_recipe.svg) ![forks](https://img.shields.io/github/forks/JackBro/extra_recipe.svg)

- [https://github.com/maximehip/extra_recipe](https://github.com/maximehip/extra_recipe) :  ![starts](https://img.shields.io/github/stars/maximehip/extra_recipe.svg) ![forks](https://img.shields.io/github/forks/maximehip/extra_recipe.svg)

## CVE-2017-2368
 An issue was discovered in certain Apple products. iOS before 10.2.1 is affected. The issue involves the &quot;Contacts&quot; component. It allows remote attackers to cause a denial of service (application crash) via a crafted contact card.



- [https://github.com/vincedes3/CVE-2017-2368](https://github.com/vincedes3/CVE-2017-2368) :  ![starts](https://img.shields.io/github/stars/vincedes3/CVE-2017-2368.svg) ![forks](https://img.shields.io/github/forks/vincedes3/CVE-2017-2368.svg)

## CVE-2017-2027
 ** RE



- [https://github.com/ghhubin/weblogic_cve2017-20271](https://github.com/ghhubin/weblogic_cve2017-20271) :  ![starts](https://img.shields.io/github/stars/ghhubin/weblogic_cve2017-20271.svg) ![forks](https://img.shields.io/github/forks/ghhubin/weblogic_cve2017-20271.svg)

## CVE-2017-0541
 A remote code execution vulnerability in sonivox in Mediaserver could enable an attacker using a specially crafted file to cause memory corruption during media file and data processing. This issue is rated as Critical due to the possibility of remote code execution within the context of the Mediaserver process. Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1. Android ID: A-34031018.



- [https://github.com/C0dak/CVE-2017-0541](https://github.com/C0dak/CVE-2017-0541) :  ![starts](https://img.shields.io/github/stars/C0dak/CVE-2017-0541.svg) ![forks](https://img.shields.io/github/forks/C0dak/CVE-2017-0541.svg)
