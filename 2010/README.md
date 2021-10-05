## CVE-2010-5230
 Multiple untrusted search path vulnerabilities in MicroStation 7.1 allow local users to gain privileges via a Trojan horse (1) mptools.dll, (2) baseman.dll, (3) wintab32.dll, or (4) wintab.dll file in the current working directory, as demonstrated by a directory that contains a .hln or .rdl file.  NOTE: some of these details are obtained from third party information.



- [https://github.com/otofoto/CVE-2010-5230](https://github.com/otofoto/CVE-2010-5230) :  ![starts](https://img.shields.io/github/stars/otofoto/CVE-2010-5230.svg) ![forks](https://img.shields.io/github/forks/otofoto/CVE-2010-5230.svg)

## CVE-2010-4804
 The Android browser in Android before 2.3.4 allows remote attackers to obtain SD card contents via crafted content:// URIs, related to (1) BrowserActivity.java and (2) BrowserSettings.java in com/android/browser/.



- [https://github.com/thomascannon/android-cve-2010-4804](https://github.com/thomascannon/android-cve-2010-4804) :  ![starts](https://img.shields.io/github/stars/thomascannon/android-cve-2010-4804.svg) ![forks](https://img.shields.io/github/forks/thomascannon/android-cve-2010-4804.svg)

## CVE-2010-4756
 The glob implementation in the GNU C Library (aka glibc or libc6) allows remote authenticated users to cause a denial of service (CPU and memory consumption) via crafted glob expressions that do not match any pathnames, as demonstrated by glob expressions in STAT commands to an FTP daemon, a different vulnerability than CVE-2010-2632.



- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2010-4756](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2010-4756) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2010-4756.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2010-4756.svg)

## CVE-2010-4669
 The Neighbor Discovery (ND) protocol implementation in the IPv6 stack in Microsoft Windows XP, Windows Server 2003, Windows Vista, Windows Server 2008, and Windows 7 allows remote attackers to cause a denial of service (CPU consumption and system hang) by sending many Router Advertisement (RA) messages with different source addresses, as demonstrated by the flood_router6 program in the thc-ipv6 package.



- [https://github.com/quinn-samuel-perry/CVE-2010-4669](https://github.com/quinn-samuel-perry/CVE-2010-4669) :  ![starts](https://img.shields.io/github/stars/quinn-samuel-perry/CVE-2010-4669.svg) ![forks](https://img.shields.io/github/forks/quinn-samuel-perry/CVE-2010-4669.svg)

## CVE-2010-4476
 The Double.parseDouble method in Java Runtime Environment (JRE) in Oracle Java SE and Java for Business 6 Update 23 and earlier, 5.0 Update 27 and earlier, and 1.4.2_29 and earlier, as used in OpenJDK, Apache, JBossweb, and other products, allows remote attackers to cause a denial of service via a crafted string that triggers an infinite loop of estimations during conversion to a double-precision binary floating-point number, as demonstrated using 2.2250738585072012e-308.



- [https://github.com/grzegorzblaszczyk/CVE-2010-4476-check](https://github.com/grzegorzblaszczyk/CVE-2010-4476-check) :  ![starts](https://img.shields.io/github/stars/grzegorzblaszczyk/CVE-2010-4476-check.svg) ![forks](https://img.shields.io/github/forks/grzegorzblaszczyk/CVE-2010-4476-check.svg)

## CVE-2010-4258
 The do_exit function in kernel/exit.c in the Linux kernel before 2.6.36.2 does not properly handle a KERNEL_DS get_fs value, which allows local users to bypass intended access_ok restrictions, overwrite arbitrary kernel memory locations, and gain privileges by leveraging a (1) BUG, (2) NULL pointer dereference, or (3) page fault, as demonstrated by vectors involving the clear_child_tid feature and the splice system call.



- [https://github.com/johnreginald/CVE-2010-4258](https://github.com/johnreginald/CVE-2010-4258) :  ![starts](https://img.shields.io/github/stars/johnreginald/CVE-2010-4258.svg) ![forks](https://img.shields.io/github/forks/johnreginald/CVE-2010-4258.svg)

## CVE-2010-4221
 Multiple stack-based buffer overflows in the pr_netio_telnet_gets function in netio.c in ProFTPD before 1.3.3c allow remote attackers to execute arbitrary code via vectors involving a TELNET IAC escape character to a (1) FTP or (2) FTPS server.



- [https://github.com/M31MOTH/cve-2010-4221](https://github.com/M31MOTH/cve-2010-4221) :  ![starts](https://img.shields.io/github/stars/M31MOTH/cve-2010-4221.svg) ![forks](https://img.shields.io/github/forks/M31MOTH/cve-2010-4221.svg)

## CVE-2010-3971
 Use-after-free vulnerability in the CSharedStyleSheet::Notify function in the Cascading Style Sheets (CSS) parser in mshtml.dll, as used in Microsoft Internet Explorer 6 through 8 and other products, allows remote attackers to execute arbitrary code or cause a denial of service (application crash) via a self-referential @import rule in a stylesheet, aka &quot;CSS Memory Corruption Vulnerability.&quot;



- [https://github.com/nektra/CVE-2010-3971-hotpatch](https://github.com/nektra/CVE-2010-3971-hotpatch) :  ![starts](https://img.shields.io/github/stars/nektra/CVE-2010-3971-hotpatch.svg) ![forks](https://img.shields.io/github/forks/nektra/CVE-2010-3971-hotpatch.svg)

## CVE-2010-3904
 The rds_page_copy_user function in net/rds/page.c in the Reliable Datagram Sockets (RDS) protocol implementation in the Linux kernel before 2.6.36 does not properly validate addresses obtained from user space, which allows local users to gain privileges via crafted use of the sendmsg and recvmsg system calls.



- [https://github.com/redhatkaty/-cve-2010-3904-report](https://github.com/redhatkaty/-cve-2010-3904-report) :  ![starts](https://img.shields.io/github/stars/redhatkaty/-cve-2010-3904-report.svg) ![forks](https://img.shields.io/github/forks/redhatkaty/-cve-2010-3904-report.svg)

## CVE-2010-3847
 elf/dl-load.c in ld.so in the GNU C Library (aka glibc or libc6) through 2.11.2, and 2.12.x through 2.12.1, does not properly handle a value of $ORIGIN for the LD_AUDIT environment variable, which allows local users to gain privileges via a crafted dynamic shared object (DSO) located in an arbitrary directory.



- [https://github.com/magisterquis/cve-2010-3847](https://github.com/magisterquis/cve-2010-3847) :  ![starts](https://img.shields.io/github/stars/magisterquis/cve-2010-3847.svg) ![forks](https://img.shields.io/github/forks/magisterquis/cve-2010-3847.svg)

## CVE-2010-3600
 Unspecified vulnerability in the Client System Analyzer component in Oracle Database Server 11.1.0.7 and 11.2.0.1 and Enterprise Manager Grid Control 10.2.0.5 allows remote attackers to affect confidentiality, integrity, and availability via unknown vectors. NOTE: the previous information was obtained from the January 2011 CPU.  Oracle has not commented on claims from a reliable third party coordinator that this issue involves an exposed JSP script that accepts XML uploads in conjunction with NULL bytes in an unspecified parameter that allow execution of arbitrary code.



- [https://github.com/LAITRUNGMINHDUC/CVE-2010-3600-PythonHackOracle11gR2](https://github.com/LAITRUNGMINHDUC/CVE-2010-3600-PythonHackOracle11gR2) :  ![starts](https://img.shields.io/github/stars/LAITRUNGMINHDUC/CVE-2010-3600-PythonHackOracle11gR2.svg) ![forks](https://img.shields.io/github/forks/LAITRUNGMINHDUC/CVE-2010-3600-PythonHackOracle11gR2.svg)

## CVE-2010-3490
 Directory traversal vulnerability in page.recordings.php in the System Recordings component in the configuration interface in FreePBX 2.8.0 and earlier allows remote authenticated administrators to create arbitrary files via a .. (dot dot) in the usersnum parameter to admin/config.php, as demonstrated by creating a .php file under the web root.



- [https://github.com/moayadalmalat/CVE-2010-3490](https://github.com/moayadalmalat/CVE-2010-3490) :  ![starts](https://img.shields.io/github/stars/moayadalmalat/CVE-2010-3490.svg) ![forks](https://img.shields.io/github/forks/moayadalmalat/CVE-2010-3490.svg)

## CVE-2010-3437
 Integer signedness error in the pkt_find_dev_from_minor function in drivers/block/pktcdvd.c in the Linux kernel before 2.6.36-rc6 allows local users to obtain sensitive information from kernel memory or cause a denial of service (invalid pointer dereference and system crash) via a crafted index value in a PKT_CTRL_CMD_STATUS ioctl call.



- [https://github.com/huang-emily/CVE-2010-3437](https://github.com/huang-emily/CVE-2010-3437) :  ![starts](https://img.shields.io/github/stars/huang-emily/CVE-2010-3437.svg) ![forks](https://img.shields.io/github/forks/huang-emily/CVE-2010-3437.svg)

## CVE-2010-3333
 Stack-based buffer overflow in Microsoft Office XP SP3, Office 2003 SP3, Office 2007 SP2, Office 2010, Office 2004 and 2008 for Mac, Office for Mac 2011, and Open XML File Format Converter for Mac allows remote attackers to execute arbitrary code via crafted RTF data, aka &quot;RTF Stack Buffer Overflow Vulnerability.&quot;



- [https://github.com/whiteHat001/cve-2010-3333](https://github.com/whiteHat001/cve-2010-3333) :  ![starts](https://img.shields.io/github/stars/whiteHat001/cve-2010-3333.svg) ![forks](https://img.shields.io/github/forks/whiteHat001/cve-2010-3333.svg)

## CVE-2010-3332
 Microsoft .NET Framework 1.1 SP1, 2.0 SP1 and SP2, 3.5, 3.5 SP1, 3.5.1, and 4.0, as used for ASP.NET in Microsoft Internet Information Services (IIS), provides detailed error codes during decryption attempts, which allows remote attackers to decrypt and modify encrypted View State (aka __VIEWSTATE) form data, and possibly forge cookies or read application files, via a padding oracle attack, aka &quot;ASP.NET Padding Oracle Vulnerability.&quot;



- [https://github.com/bongbongco/MS10-070](https://github.com/bongbongco/MS10-070) :  ![starts](https://img.shields.io/github/stars/bongbongco/MS10-070.svg) ![forks](https://img.shields.io/github/forks/bongbongco/MS10-070.svg)

## CVE-2010-3301
 The IA32 system call emulation functionality in arch/x86/ia32/ia32entry.S in the Linux kernel before 2.6.36-rc4-git2 on the x86_64 platform does not zero extend the %eax register after the 32-bit entry path to ptrace is used, which allows local users to gain privileges by triggering an out-of-bounds access to the system call table using the %rax register.  NOTE: this vulnerability exists because of a CVE-2007-4573 regression.



- [https://github.com/n0lann/CVE2010-3301_compiled](https://github.com/n0lann/CVE2010-3301_compiled) :  ![starts](https://img.shields.io/github/stars/n0lann/CVE2010-3301_compiled.svg) ![forks](https://img.shields.io/github/forks/n0lann/CVE2010-3301_compiled.svg)

## CVE-2010-2632
 Unspecified vulnerability in the FTP Server in Oracle Solaris 8, 9, 10, and 11 Express allows remote attackers to affect availability. NOTE: the previous information was obtained from the January 2011 CPU. Oracle has not commented on claims from a reliable researcher that this is an issue in the glob implementation in libc that allows remote authenticated users to cause a denial of service (CPU and memory consumption) via crafted glob expressions that do not match any pathnames.



- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2010-4756](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2010-4756) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2010-4756.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2010-4756.svg)

## CVE-2010-2626
 index.pl in Miyabi CGI Tools SEO Links 1.02 allows remote attackers to execute arbitrary commands via shell metacharacters in the fn command. NOTE: some of these details are obtained from third party information.



- [https://github.com/oxagast/oxasploits](https://github.com/oxagast/oxasploits) :  ![starts](https://img.shields.io/github/stars/oxagast/oxasploits.svg) ![forks](https://img.shields.io/github/forks/oxagast/oxasploits.svg)

## CVE-2010-2333
 LiteSpeed Technologies LiteSpeed Web Server 4.0.x before 4.0.15 allows remote attackers to read the source code of scripts via an HTTP request with a null byte followed by a .txt file extension.



- [https://github.com/aforakjackson/cve2010-2333](https://github.com/aforakjackson/cve2010-2333) :  ![starts](https://img.shields.io/github/stars/aforakjackson/cve2010-2333.svg) ![forks](https://img.shields.io/github/forks/aforakjackson/cve2010-2333.svg)

## CVE-2010-2078
 DataTrack System 3.5 allows remote attackers to list the root directory via a (1) /%u0085/ or (2) /%u00A0/ URI.



- [https://github.com/0bfxgh0st/UnrealIrcd-3.2.8.1-cve-2010-2075-exploit](https://github.com/0bfxgh0st/UnrealIrcd-3.2.8.1-cve-2010-2075-exploit) :  ![starts](https://img.shields.io/github/stars/0bfxgh0st/UnrealIrcd-3.2.8.1-cve-2010-2075-exploit.svg) ![forks](https://img.shields.io/github/forks/0bfxgh0st/UnrealIrcd-3.2.8.1-cve-2010-2075-exploit.svg)

## CVE-2010-2075
 UnrealIRCd 3.2.8.1, as distributed on certain mirror sites from November 2009 through June 2010, contains an externally introduced modification (Trojan Horse) in the DEBUG3_DOLOG_SYSTEM macro, which allows remote attackers to execute arbitrary commands.



- [https://github.com/XorgX304/UnrealIRCd-3.2.8.1-RCE](https://github.com/XorgX304/UnrealIRCd-3.2.8.1-RCE) :  ![starts](https://img.shields.io/github/stars/XorgX304/UnrealIRCd-3.2.8.1-RCE.svg) ![forks](https://img.shields.io/github/forks/XorgX304/UnrealIRCd-3.2.8.1-RCE.svg)

- [https://github.com/0bfxgh0st/UnrealIrcd-3.2.8.1-cve-2010-2075-exploit](https://github.com/0bfxgh0st/UnrealIrcd-3.2.8.1-cve-2010-2075-exploit) :  ![starts](https://img.shields.io/github/stars/0bfxgh0st/UnrealIrcd-3.2.8.1-cve-2010-2075-exploit.svg) ![forks](https://img.shields.io/github/forks/0bfxgh0st/UnrealIrcd-3.2.8.1-cve-2010-2075-exploit.svg)

## CVE-2010-1411
 Multiple integer overflows in the Fax3SetupState function in tif_fax3.c in the FAX3 decoder in LibTIFF before 3.9.3, as used in ImageIO in Apple Mac OS X 10.5.8 and Mac OS X 10.6 before 10.6.4, allow remote attackers to execute arbitrary code or cause a denial of service (application crash) via a crafted TIFF file that triggers a heap-based buffer overflow.



- [https://github.com/MAVProxyUser/httpfuzz-robomiller](https://github.com/MAVProxyUser/httpfuzz-robomiller) :  ![starts](https://img.shields.io/github/stars/MAVProxyUser/httpfuzz-robomiller.svg) ![forks](https://img.shields.io/github/forks/MAVProxyUser/httpfuzz-robomiller.svg)

## CVE-2010-1240
 Adobe Reader and Acrobat 9.x before 9.3.3, and 8.x before 8.2.3 on Windows and Mac OS X, do not restrict the contents of one text field in the Launch File warning dialog, which makes it easier for remote attackers to trick users into executing an arbitrary local program that was specified in a PDF document, as demonstrated by a text field that claims that the Open button will enable the user to read an encrypted message.



- [https://github.com/Jasmoon99/Embedded-PDF](https://github.com/Jasmoon99/Embedded-PDF) :  ![starts](https://img.shields.io/github/stars/Jasmoon99/Embedded-PDF.svg) ![forks](https://img.shields.io/github/forks/Jasmoon99/Embedded-PDF.svg)

## CVE-2010-1205
 Buffer overflow in pngpread.c in libpng before 1.2.44 and 1.4.x before 1.4.3, as used in progressive applications, might allow remote attackers to execute arbitrary code via a PNG image that triggers an additional data row.



- [https://github.com/mk219533/CVE-2010-1205](https://github.com/mk219533/CVE-2010-1205) :  ![starts](https://img.shields.io/github/stars/mk219533/CVE-2010-1205.svg) ![forks](https://img.shields.io/github/forks/mk219533/CVE-2010-1205.svg)

## CVE-2010-0738
 The JMX-Console web application in JBossAs in Red Hat JBoss Enterprise Application Platform (aka JBoss EAP or JBEAP) 4.2 before 4.2.0.CP09 and 4.3 before 4.3.0.CP08 performs access control only for the GET and POST methods, which allows remote attackers to send requests to this application's GET handler by using a different method.



- [https://github.com/ChristianPapathanasiou/jboss-autopwn](https://github.com/ChristianPapathanasiou/jboss-autopwn) :  ![starts](https://img.shields.io/github/stars/ChristianPapathanasiou/jboss-autopwn.svg) ![forks](https://img.shields.io/github/forks/ChristianPapathanasiou/jboss-autopwn.svg)

- [https://github.com/gitcollect/jboss-autopwn](https://github.com/gitcollect/jboss-autopwn) :  ![starts](https://img.shields.io/github/stars/gitcollect/jboss-autopwn.svg) ![forks](https://img.shields.io/github/forks/gitcollect/jboss-autopwn.svg)

## CVE-2010-0426
 sudo 1.6.x before 1.6.9p21 and 1.7.x before 1.7.2p4, when a pseudo-command is enabled, permits a match between the name of the pseudo-command and the name of an executable file in an arbitrary directory, which allows local users to gain privileges via a crafted executable file, as demonstrated by a file named sudoedit in a user's home directory.



- [https://github.com/t0kx/privesc-CVE-2010-0426](https://github.com/t0kx/privesc-CVE-2010-0426) :  ![starts](https://img.shields.io/github/stars/t0kx/privesc-CVE-2010-0426.svg) ![forks](https://img.shields.io/github/forks/t0kx/privesc-CVE-2010-0426.svg)

- [https://github.com/cved-sources/cve-2010-0426](https://github.com/cved-sources/cve-2010-0426) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2010-0426.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2010-0426.svg)
