# Update 2022-08-12
## CVE-2022-25313
 In Expat (aka libexpat) before 2.4.5, an attacker can trigger stack exhaustion in build_model via a large nesting depth in the DTD element.

- [https://github.com/ShaikUsaf/external_expact_AOSP10_r33_CVE-2022-25313](https://github.com/ShaikUsaf/external_expact_AOSP10_r33_CVE-2022-25313) :  ![starts](https://img.shields.io/github/stars/ShaikUsaf/external_expact_AOSP10_r33_CVE-2022-25313.svg) ![forks](https://img.shields.io/github/forks/ShaikUsaf/external_expact_AOSP10_r33_CVE-2022-25313.svg)


## CVE-2022-21894
 Secure Boot Security Feature Bypass Vulnerability.

- [https://github.com/Wack0/CVE-2022-21894](https://github.com/Wack0/CVE-2022-21894) :  ![starts](https://img.shields.io/github/stars/Wack0/CVE-2022-21894.svg) ![forks](https://img.shields.io/github/forks/Wack0/CVE-2022-21894.svg)


## CVE-2022-20866
 A vulnerability in the handling of RSA keys on devices running Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to retrieve an RSA private key. This vulnerability is due to a logic error when the RSA key is stored in memory on a hardware platform that performs hardware-based cryptography. An attacker could exploit this vulnerability by using a Lenstra side-channel attack against the targeted device. A successful exploit could allow the attacker to retrieve the RSA private key. The following conditions may be observed on an affected device: This vulnerability will apply to approximately 5 percent of the RSA keys on a device that is running a vulnerable release of Cisco ASA Software or Cisco FTD Software; not all RSA keys are expected to be affected due to mathematical calculations applied to the RSA key. The RSA key could be valid but have specific characteristics that make it vulnerable to the potential leak of the RSA private key. If an attacker obtains the RSA private key, they could use the key to impersonate a device that is running Cisco ASA Software or Cisco FTD Software or to decrypt the device traffic. See the Indicators of Compromise section for more information on the detection of this type of RSA key. The RSA key could be malformed and invalid. A malformed RSA key is not functional, and a TLS client connection to a device that is running Cisco ASA Software or Cisco FTD Software that uses the malformed RSA key will result in a TLS signature failure, which means a vulnerable software release created an invalid RSA signature that failed verification. If an attacker obtains the RSA private key, they could use the key to impersonate a device that is running Cisco ASA Software or Cisco FTD Software or to decrypt the device traffic.

- [https://github.com/CiscoPSIRT/CVE-2022-20866](https://github.com/CiscoPSIRT/CVE-2022-20866) :  ![starts](https://img.shields.io/github/stars/CiscoPSIRT/CVE-2022-20866.svg) ![forks](https://img.shields.io/github/forks/CiscoPSIRT/CVE-2022-20866.svg)


## CVE-2022-1040
 An authentication bypass vulnerability in the User Portal and Webadmin allows a remote attacker to execute code in Sophos Firewall version v18.5 MR3 and older.

- [https://github.com/APTIRAN/CVE-2022-1040](https://github.com/APTIRAN/CVE-2022-1040) :  ![starts](https://img.shields.io/github/stars/APTIRAN/CVE-2022-1040.svg) ![forks](https://img.shields.io/github/forks/APTIRAN/CVE-2022-1040.svg)


## CVE-2021-44852
 An issue was discovered in BS_RCIO64.sys in Biostar RACING GT Evo 2.1.1905.1700. A low-integrity process can open the driver's device object and issue IOCTLs to read or write to arbitrary physical memory locations (or call an arbitrary address), leading to execution of arbitrary code. This is associated with 0x226040, 0x226044, and 0x226000.

- [https://github.com/Exploitables/CVE-2021-44852](https://github.com/Exploitables/CVE-2021-44852) :  ![starts](https://img.shields.io/github/stars/Exploitables/CVE-2021-44852.svg) ![forks](https://img.shields.io/github/forks/Exploitables/CVE-2021-44852.svg)


## CVE-2021-40865
 An Unsafe Deserialization vulnerability exists in the worker services of the Apache Storm supervisor server allowing pre-auth Remote Code Execution (RCE). Apache Storm 2.2.x users should upgrade to version 2.2.1 or 2.3.0. Apache Storm 2.1.x users should upgrade to version 2.1.1. Apache Storm 1.x users should upgrade to version 1.2.4

- [https://github.com/hktalent/CVE-2021-40865](https://github.com/hktalent/CVE-2021-40865) :  ![starts](https://img.shields.io/github/stars/hktalent/CVE-2021-40865.svg) ![forks](https://img.shields.io/github/forks/hktalent/CVE-2021-40865.svg)


## CVE-2021-25837
 Cosmos Network Ethermint &lt;= v0.4.0 is affected by cache lifecycle inconsistency in the EVM module. Due to the inconsistency between the Storage caching cycle and the Tx processing cycle, Storage changes caused by a failed transaction are improperly reserved in memory. Although the bad storage cache data will be discarded at EndBlock, it is still valid in the current block, which enables many possible attacks such as an &quot;arbitrary mint token&quot;.

- [https://github.com/iczc/Ethermint-CVE-2021-25837](https://github.com/iczc/Ethermint-CVE-2021-25837) :  ![starts](https://img.shields.io/github/stars/iczc/Ethermint-CVE-2021-25837.svg) ![forks](https://img.shields.io/github/forks/iczc/Ethermint-CVE-2021-25837.svg)


## CVE-2021-4154
 A use-after-free flaw was found in cgroup1_parse_param in kernel/cgroup/cgroup-v1.c in the Linux kernel's cgroup v1 parser. A local attacker with a user privilege could cause a privilege escalation by exploiting the fsconfig syscall parameter leading to a container breakout and a denial of service on the system.

- [https://github.com/Markakd/CVE-2021-4154](https://github.com/Markakd/CVE-2021-4154) :  ![starts](https://img.shields.io/github/stars/Markakd/CVE-2021-4154.svg) ![forks](https://img.shields.io/github/forks/Markakd/CVE-2021-4154.svg)


## CVE-2021-2022
 Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are affected are 5.6.50 and prior, 5.7.32 and prior and 8.0.22 and prior. Difficult to exploit vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.4 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H).

- [https://github.com/team-v-2022/Cosine-Percentage-Calculation](https://github.com/team-v-2022/Cosine-Percentage-Calculation) :  ![starts](https://img.shields.io/github/stars/team-v-2022/Cosine-Percentage-Calculation.svg) ![forks](https://img.shields.io/github/forks/team-v-2022/Cosine-Percentage-Calculation.svg)


## CVE-2019-19781
 An issue was discovered in Citrix Application Delivery Controller (ADC) and Gateway 10.5, 11.1, 12.0, 12.1, and 13.0. They allow Directory Traversal.

- [https://github.com/robhax/CVE-2019-19781](https://github.com/robhax/CVE-2019-19781) :  ![starts](https://img.shields.io/github/stars/robhax/CVE-2019-19781.svg) ![forks](https://img.shields.io/github/forks/robhax/CVE-2019-19781.svg)
- [https://github.com/robhax/citrixmash_scanner](https://github.com/robhax/citrixmash_scanner) :  ![starts](https://img.shields.io/github/stars/robhax/citrixmash_scanner.svg) ![forks](https://img.shields.io/github/forks/robhax/citrixmash_scanner.svg)
- [https://github.com/robhax/citrix-honeypot](https://github.com/robhax/citrix-honeypot) :  ![starts](https://img.shields.io/github/stars/robhax/citrix-honeypot.svg) ![forks](https://img.shields.io/github/forks/robhax/citrix-honeypot.svg)


## CVE-2018-15727
 Grafana 2.x, 3.x, and 4.x before 4.6.4 and 5.x before 5.2.3 allows authentication bypass because an attacker can generate a valid &quot;remember me&quot; cookie knowing only a username of an LDAP or OAuth user.

- [https://github.com/u238/grafana-CVE-2018-15727](https://github.com/u238/grafana-CVE-2018-15727) :  ![starts](https://img.shields.io/github/stars/u238/grafana-CVE-2018-15727.svg) ![forks](https://img.shields.io/github/forks/u238/grafana-CVE-2018-15727.svg)


## CVE-2017-13156
 An elevation of privilege vulnerability in the Android system (art). Product: Android. Versions: 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID A-64211847.

- [https://github.com/xyzAsian/Janus-CVE-2017-13156](https://github.com/xyzAsian/Janus-CVE-2017-13156) :  ![starts](https://img.shields.io/github/stars/xyzAsian/Janus-CVE-2017-13156.svg) ![forks](https://img.shields.io/github/forks/xyzAsian/Janus-CVE-2017-13156.svg)
- [https://github.com/giacomoferretti/janus-toolkit](https://github.com/giacomoferretti/janus-toolkit) :  ![starts](https://img.shields.io/github/stars/giacomoferretti/janus-toolkit.svg) ![forks](https://img.shields.io/github/forks/giacomoferretti/janus-toolkit.svg)


## CVE-2017-11882
 Microsoft Office 2007 Service Pack 3, Microsoft Office 2010 Service Pack 2, Microsoft Office 2013 Service Pack 1, and Microsoft Office 2016 allow an attacker to run arbitrary code in the context of the current user by failing to properly handle objects in memory, aka &quot;Microsoft Office Memory Corruption Vulnerability&quot;. This CVE ID is unique from CVE-2017-11884.

- [https://github.com/Ridter/CVE-2017-11882](https://github.com/Ridter/CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/Ridter/CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/Ridter/CVE-2017-11882.svg)
- [https://github.com/likescam/CVE-2018-0802_CVE-2017-11882](https://github.com/likescam/CVE-2018-0802_CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/likescam/CVE-2018-0802_CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/likescam/CVE-2018-0802_CVE-2017-11882.svg)
- [https://github.com/Retr0-code/SignHere](https://github.com/Retr0-code/SignHere) :  ![starts](https://img.shields.io/github/stars/Retr0-code/SignHere.svg) ![forks](https://img.shields.io/github/forks/Retr0-code/SignHere.svg)
- [https://github.com/ChaitanyaHaritash/CVE-2017-11882](https://github.com/ChaitanyaHaritash/CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/ChaitanyaHaritash/CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/ChaitanyaHaritash/CVE-2017-11882.svg)
- [https://github.com/5l1v3r1/rtfkit](https://github.com/5l1v3r1/rtfkit) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/rtfkit.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/rtfkit.svg)


## CVE-2017-11317
 Telerik.Web.UI in Progress Telerik UI for ASP.NET AJAX before R1 2017 and R2 before R2 2017 SP2 uses weak RadAsyncUpload encryption, which allows remote attackers to perform arbitrary file uploads or execute arbitrary code.

- [https://github.com/bao7uo/RAU_crypto](https://github.com/bao7uo/RAU_crypto) :  ![starts](https://img.shields.io/github/stars/bao7uo/RAU_crypto.svg) ![forks](https://img.shields.io/github/forks/bao7uo/RAU_crypto.svg)


## CVE-2017-8464
 Windows Shell in Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, 1703, and Windows Server 2016 allows local users or remote attackers to execute arbitrary code via a crafted .LNK file, which is not properly handled during icon display in Windows Explorer or any other application that parses the icon of the shortcut. aka &quot;LNK Remote Code Execution Vulnerability.&quot;

- [https://github.com/TrG-1999/DetectPacket-CVE-2017-8464](https://github.com/TrG-1999/DetectPacket-CVE-2017-8464) :  ![starts](https://img.shields.io/github/stars/TrG-1999/DetectPacket-CVE-2017-8464.svg) ![forks](https://img.shields.io/github/forks/TrG-1999/DetectPacket-CVE-2017-8464.svg)


## CVE-2017-8295
 WordPress through 4.7.4 relies on the Host HTTP header for a password-reset e-mail message, which makes it easier for remote attackers to reset arbitrary passwords by making a crafted wp-login.php?action=lostpassword request and then arranging for this message to bounce or be resent, leading to transmission of the reset key to a mailbox on an attacker-controlled SMTP server. This is related to problematic use of the SERVER_NAME variable in wp-includes/pluggable.php in conjunction with the PHP mail function. Exploitation is not achievable in all cases because it requires at least one of the following: (1) the attacker can prevent the victim from receiving any e-mail messages for an extended period of time (such as 5 days), (2) the victim's e-mail system sends an autoresponse containing the original message, or (3) the victim manually composes a reply containing the original message.

- [https://github.com/cyberheartmi9/CVE-2017-8295](https://github.com/cyberheartmi9/CVE-2017-8295) :  ![starts](https://img.shields.io/github/stars/cyberheartmi9/CVE-2017-8295.svg) ![forks](https://img.shields.io/github/forks/cyberheartmi9/CVE-2017-8295.svg)


## CVE-2017-7529
 Nginx versions since 0.5.6 up to and including 1.13.2 are vulnerable to integer overflow vulnerability in nginx range filter module resulting into leak of potentially sensitive information triggered by specially crafted request.

- [https://github.com/liusec/CVE-2017-7529](https://github.com/liusec/CVE-2017-7529) :  ![starts](https://img.shields.io/github/stars/liusec/CVE-2017-7529.svg) ![forks](https://img.shields.io/github/forks/liusec/CVE-2017-7529.svg)


## CVE-2017-5689
 An unprivileged network attacker could gain system privileges to provisioned Intel manageability SKUs: Intel Active Management Technology (AMT) and Intel Standard Manageability (ISM). An unprivileged local attacker could provision manageability features gaining unprivileged network or local system privileges on Intel manageability SKUs: Intel Active Management Technology (AMT), Intel Standard Manageability (ISM), and Intel Small Business Technology (SBT).

- [https://github.com/robhax/amthoneypot](https://github.com/robhax/amthoneypot) :  ![starts](https://img.shields.io/github/stars/robhax/amthoneypot.svg) ![forks](https://img.shields.io/github/forks/robhax/amthoneypot.svg)


## CVE-2015-4852
 The WLS Security component in Oracle WebLogic Server 10.3.6.0, 12.1.2.0, 12.1.3.0, and 12.2.1.0 allows remote attackers to execute arbitrary commands via a crafted serialized Java object in T3 protocol traffic to TCP port 7001, related to oracle_common/modules/com.bea.core.apache.commons.collections.jar. NOTE: the scope of this CVE is limited to the WebLogic Server product.

- [https://github.com/AndersonSingh/serialization-vulnerability-scanner](https://github.com/AndersonSingh/serialization-vulnerability-scanner) :  ![starts](https://img.shields.io/github/stars/AndersonSingh/serialization-vulnerability-scanner.svg) ![forks](https://img.shields.io/github/forks/AndersonSingh/serialization-vulnerability-scanner.svg)


## CVE-2014-3341
 The SNMP module in Cisco NX-OS 7.0(3)N1(1) and earlier on Nexus 5000 and 6000 devices provides different error messages for invalid requests depending on whether the VLAN ID exists, which allows remote attackers to enumerate VLANs via a series of requests, aka Bug ID CSCup85616.

- [https://github.com/ehabhussein/snmpvlan](https://github.com/ehabhussein/snmpvlan) :  ![starts](https://img.shields.io/github/stars/ehabhussein/snmpvlan.svg) ![forks](https://img.shields.io/github/forks/ehabhussein/snmpvlan.svg)


## CVE-2014-0196
 The n_tty_write function in drivers/tty/n_tty.c in the Linux kernel through 3.14.3 does not properly manage tty driver access in the &quot;LECHO &amp; !OPOST&quot; case, which allows local users to cause a denial of service (memory corruption and system crash) or gain privileges by triggering a race condition involving read and write operations with long strings.

- [https://github.com/tempbottle/CVE-2014-0196](https://github.com/tempbottle/CVE-2014-0196) :  ![starts](https://img.shields.io/github/stars/tempbottle/CVE-2014-0196.svg) ![forks](https://img.shields.io/github/forks/tempbottle/CVE-2014-0196.svg)
- [https://github.com/SunRain/CVE-2014-0196](https://github.com/SunRain/CVE-2014-0196) :  ![starts](https://img.shields.io/github/stars/SunRain/CVE-2014-0196.svg) ![forks](https://img.shields.io/github/forks/SunRain/CVE-2014-0196.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/sensepost/heartbleed-poc](https://github.com/sensepost/heartbleed-poc) :  ![starts](https://img.shields.io/github/stars/sensepost/heartbleed-poc.svg) ![forks](https://img.shields.io/github/forks/sensepost/heartbleed-poc.svg)


## CVE-2013-2765
 The ModSecurity module before 2.7.4 for the Apache HTTP Server allows remote attackers to cause a denial of service (NULL pointer dereference, process crash, and disk consumption) via a POST request with a large body and a crafted Content-Type header.

- [https://github.com/yjaaidi/exploits](https://github.com/yjaaidi/exploits) :  ![starts](https://img.shields.io/github/stars/yjaaidi/exploits.svg) ![forks](https://img.shields.io/github/forks/yjaaidi/exploits.svg)


## CVE-2011-3389
 The SSL protocol, as used in certain configurations in Microsoft Windows and Microsoft Internet Explorer, Mozilla Firefox, Google Chrome, Opera, and other products, encrypts data by using CBC mode with chained initialization vectors, which allows man-in-the-middle attackers to obtain plaintext HTTP headers via a blockwise chosen-boundary attack (BCBA) on an HTTPS session, in conjunction with JavaScript code that uses (1) the HTML5 WebSocket API, (2) the Java URLConnection API, or (3) the Silverlight WebClient API, aka a &quot;BEAST&quot; attack.

- [https://github.com/mpgn/BEAST-PoC](https://github.com/mpgn/BEAST-PoC) :  ![starts](https://img.shields.io/github/stars/mpgn/BEAST-PoC.svg) ![forks](https://img.shields.io/github/forks/mpgn/BEAST-PoC.svg)

