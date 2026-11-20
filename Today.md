# Update 2026-11-20
## CVE-2026-131873
 Gargoyle 2023.1 through 2026.1.1 contains a stack-based buffer overflow vulnerability in the bundled Plus interpreter's ReadAction() function in terps/plus/loaddatabase.c, which never bounds-checks the index into the 1024-entry conditions array. Attackers can supply a crafted or truncated .plus game file with unterminated action conditions to write file-controlled values past the array and crash the player.

- [https://github.com/googlesky/CVE-2026-131873](https://github.com/googlesky/CVE-2026-131873) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-131873.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-131873.svg)


## CVE-2026-131852
 OwnTracks Recorder before 1.0.5 contains a format string vulnerability in json_response() and related output functions that allows unauthenticated attackers to execute code by storing a malicious tid value. Attackers can publish locations via POST /pub or MQTT with printf specifiers in tid, then read them back through GET /api/0/last to leak addresses and write memory.

- [https://github.com/googlesky/CVE-2026-131852](https://github.com/googlesky/CVE-2026-131852) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-131852.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-131852.svg)


## CVE-2026-131850
 ILIAS 11.0 before 11.6 contains an sql injection vulnerability in RegistrationCodeRepository::getCodesData() that concatenates unvalidated sort fields into an ORDER BY clause. Authenticated users with read access to the Authentication and Registration administration node can supply SQL expressions as the sort parameter to extract database contents via boolean-based inference.

- [https://github.com/murrez/CVE-2026-131850](https://github.com/murrez/CVE-2026-131850) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-131850.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-131850.svg)


## CVE-2026-131842
 Poppler pdfdetach 24.03.0 through 26.11.0 contains a path traversal vulnerability in utils/pdfdetach.cc that allows attackers to write files outside the output directory by bypassing a string-prefix containment check. Attackers can craft PDFs with embedded file names containing '..' sequences or absolute paths, so -saveall or -savefile extraction creates or overwrites files with the invoking user's privileges.

- [https://github.com/googlesky/CVE-2026-131842](https://github.com/googlesky/CVE-2026-131842) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-131842.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-131842.svg)


## CVE-2026-130587
 OpenFunction through 1.2.0 contains a privilege escalation vulnerability that allows namespace tenants to create privileged host-access pods by supplying unrestricted PodSpec templates in Function and Serving resources. Attackers with only Function or Serving create permissions can set privileged, hostNetwork, hostPID, or hostPath fields to mount the worker node's root filesystem and escalate to node access.

- [https://github.com/googlesky/CVE-2026-130587](https://github.com/googlesky/CVE-2026-130587) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-130587.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-130587.svg)


## CVE-2026-129448
Users who cannot upgrade right away should set "enabledForExtensions" to "false" in WEB-INF/web.xml, or remove the "/roller-services/xmlrpc" servlet mapping, and restart Roller. Disabling XML-RPC in the administration UI is not enough, because older versions deserialize the request before checking that setting.

- [https://github.com/Yanixos/APACHE-CVE-2026-129448](https://github.com/Yanixos/APACHE-CVE-2026-129448) :  ![starts](https://img.shields.io/github/stars/Yanixos/APACHE-CVE-2026-129448.svg) ![forks](https://img.shields.io/github/forks/Yanixos/APACHE-CVE-2026-129448.svg)


## CVE-2026-127222
 SGLang through 0.5.23, fixed in commit 7b5fb39, contains a missing authorization vulnerability in the POST /load_lora_adapter_from_tensors HTTP endpoint, which lacks the @auth_level(AuthLevel.ADMIN_OPTIONAL) decorator applied to its sibling admin endpoints, allowing unauthenticated network-reachable attackers to invoke it without an API key. Attackers can load a LoRA adapter from attacker-supplied serialized tensors to manipulate the served model, and when combined with a separately documented deserialization bypass, achieve unauthenticated remote code execution as root.

- [https://github.com/rahulreddykarne/CVE-2026-127222-sglang](https://github.com/rahulreddykarne/CVE-2026-127222-sglang) :  ![starts](https://img.shields.io/github/stars/rahulreddykarne/CVE-2026-127222-sglang.svg) ![forks](https://img.shields.io/github/forks/rahulreddykarne/CVE-2026-127222-sglang.svg)


## CVE-2026-126979
The specific flaw exists within the HomeKit Accessory Protocol service, which listens on TCP port 8080 by default. When parsing pairing requests, the process does not properly validate user-supplied data, which can result in an integer underflow before writing to memory. An attacker can leverage this vulnerability to execute code in the context of the device. Was ZDI-CAN-28332.

- [https://github.com/LLCForge/CVE-2026-126978](https://github.com/LLCForge/CVE-2026-126978) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-126978.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-126978.svg)


## CVE-2026-126978
The specific flaw exists within the HomeKit Accessory Protocol service, which listens on TCP port 8080 by default. When parsing pairing requests, the process does not properly validate the length of user-supplied data prior to copying it to a fixed-length, heap-based buffer. An attacker can leverage this vulnerability to execute code in the context of the device. Was ZDI-CAN-28434.

- [https://github.com/LLCForge/CVE-2026-126978](https://github.com/LLCForge/CVE-2026-126978) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-126978.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-126978.svg)


## CVE-2026-126967
The specific flaw exists within the FileStorageController class. The issue results from the lack of proper validation of a user-supplied path prior to using it in file operations. An attacker can leverage this vulnerability to execute code in the context of SYSTEM. Was ZDI-CAN-30742.

- [https://github.com/LLCForge/CVE-2026-126967](https://github.com/LLCForge/CVE-2026-126967) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-126967.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-126967.svg)


## CVE-2026-125350
 Use after free in XML in Google Chrome prior to 157.0.8103.50 allowed a remote attacker to execute arbitrary code inside the sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/LLCForge/CVE-2026-125350](https://github.com/LLCForge/CVE-2026-125350) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-125350.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-125350.svg)


## CVE-2026-125283
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/LLCForge/CVE-2026-125283](https://github.com/LLCForge/CVE-2026-125283) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-125283.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-125283.svg)


## CVE-2026-124990
 The Masteriyo LMS – LMS Course Builder, Quizzes & Certificates plugin for WordPress is vulnerable to PHP Object Injection in versions up to, and including, 3.5.1 via deserialization of untrusted input in the course importer. The set_post_metas() method  calls maybe_unserialize() on attacker-controlled postmeta string values parsed from the uploaded JSON import file. This makes it possible for unauthenticated attackers to inject arbitrary PHP Objects. Exploitation by unauthenticated attackers requires that the site has enable_instructor_registration=true AND enable_guest_checkout=true AND at least one purchasable course exists. Install.php sets enable_instructor_registration=false on fresh installs, so this is a non-default configuration. On a default installation, where that is not configured, the vulnerability requires attackers with author-level access and above.

- [https://github.com/im0xfay/CVE-2026-124990](https://github.com/im0xfay/CVE-2026-124990) :  ![starts](https://img.shields.io/github/stars/im0xfay/CVE-2026-124990.svg) ![forks](https://img.shields.io/github/forks/im0xfay/CVE-2026-124990.svg)


## CVE-2026-124194
 Product ui does not warn user of unsafe actions in Microsoft Office Outlook allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/LLCForge/CVE-2026-124194](https://github.com/LLCForge/CVE-2026-124194) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-124194.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-124194.svg)


## CVE-2026-124024
When converting from UCS-4, these encoders may encounter a combining base such as U+00E6 and jump ahead by 4 bytes to check the next UCS-4 code point.  The check for end of buffer however does not account for this, which may result in a buffer overread if the following code point has less than 4 bytes remaining.  Exploitation of this bug not only requires attacker control of input and encoding, but also strict control over layout of the input in memory.

- [https://github.com/D7EAD/CVE-2026-124024](https://github.com/D7EAD/CVE-2026-124024) :  ![starts](https://img.shields.io/github/stars/D7EAD/CVE-2026-124024.svg) ![forks](https://img.shields.io/github/forks/D7EAD/CVE-2026-124024.svg)


## CVE-2026-123640
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/LLCForge/CVE-2026-123640](https://github.com/LLCForge/CVE-2026-123640) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-123640.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-123640.svg)


## CVE-2026-123634
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/LLCForge/CVE-2026-123634](https://github.com/LLCForge/CVE-2026-123634) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-123634.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-123634.svg)


## CVE-2026-123633
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/LLCForge/CVE-2026-123633](https://github.com/LLCForge/CVE-2026-123633) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-123633.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-123633.svg)
- [https://github.com/Quaerendir/cve-2026-123633-123007-nginx-audit](https://github.com/Quaerendir/cve-2026-123633-123007-nginx-audit) :  ![starts](https://img.shields.io/github/stars/Quaerendir/cve-2026-123633-123007-nginx-audit.svg) ![forks](https://img.shields.io/github/forks/Quaerendir/cve-2026-123633-123007-nginx-audit.svg)
- [https://github.com/Ghost-Bx1/nginx-exploits](https://github.com/Ghost-Bx1/nginx-exploits) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/nginx-exploits.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/nginx-exploits.svg)
- [https://github.com/LLCForge/CVE-2026-123640](https://github.com/LLCForge/CVE-2026-123640) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-123640.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-123640.svg)


## CVE-2026-123158
 sshd in OpenSSH before 10.6p2 on Linux, when musl libc is used without PAM, lacks a workaround for a password authentication bypass (related to misinterpretation of whether a string is intended to be a password hash). For some configurations of accounts, any password between 256 and 1024 characters succeeds. An example of a platform using musl libc without PAM is Alpine Linux.

- [https://github.com/gotr00t0day/CVE-2026-123158](https://github.com/gotr00t0day/CVE-2026-123158) :  ![starts](https://img.shields.io/github/stars/gotr00t0day/CVE-2026-123158.svg) ![forks](https://img.shields.io/github/forks/gotr00t0day/CVE-2026-123158.svg)
- [https://github.com/Cheats121/sshole-CVE-2026-123158](https://github.com/Cheats121/sshole-CVE-2026-123158) :  ![starts](https://img.shields.io/github/stars/Cheats121/sshole-CVE-2026-123158.svg) ![forks](https://img.shields.io/github/forks/Cheats121/sshole-CVE-2026-123158.svg)
- [https://github.com/VardonBorin/Exploring_CVE-2026-123158](https://github.com/VardonBorin/Exploring_CVE-2026-123158) :  ![starts](https://img.shields.io/github/stars/VardonBorin/Exploring_CVE-2026-123158.svg) ![forks](https://img.shields.io/github/forks/VardonBorin/Exploring_CVE-2026-123158.svg)


## CVE-2026-123007
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/sfewer-r7/CVE-2026-123007](https://github.com/sfewer-r7/CVE-2026-123007) :  ![starts](https://img.shields.io/github/stars/sfewer-r7/CVE-2026-123007.svg) ![forks](https://img.shields.io/github/forks/sfewer-r7/CVE-2026-123007.svg)
- [https://github.com/LLCForge/CVE-2026-123007](https://github.com/LLCForge/CVE-2026-123007) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-123007.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-123007.svg)
- [https://github.com/ashrafzaryouh/CVE-2026-123007](https://github.com/ashrafzaryouh/CVE-2026-123007) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-123007.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-123007.svg)
- [https://github.com/suominen/CVE-2026-123007](https://github.com/suominen/CVE-2026-123007) :  ![starts](https://img.shields.io/github/stars/suominen/CVE-2026-123007.svg) ![forks](https://img.shields.io/github/forks/suominen/CVE-2026-123007.svg)
- [https://github.com/arkrwn/NGINX2Root-CVE-2026-123007](https://github.com/arkrwn/NGINX2Root-CVE-2026-123007) :  ![starts](https://img.shields.io/github/stars/arkrwn/NGINX2Root-CVE-2026-123007.svg) ![forks](https://img.shields.io/github/forks/arkrwn/NGINX2Root-CVE-2026-123007.svg)
- [https://github.com/Ghost-Bx1/nginx-exploits](https://github.com/Ghost-Bx1/nginx-exploits) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/nginx-exploits.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/nginx-exploits.svg)
- [https://github.com/Quaerendir/cve-2026-123633-123007-nginx-audit](https://github.com/Quaerendir/cve-2026-123633-123007-nginx-audit) :  ![starts](https://img.shields.io/github/stars/Quaerendir/cve-2026-123633-123007-nginx-audit.svg) ![forks](https://img.shields.io/github/forks/Quaerendir/cve-2026-123633-123007-nginx-audit.svg)
- [https://github.com/WormW/nginx2root-rce-lab](https://github.com/WormW/nginx2root-rce-lab) :  ![starts](https://img.shields.io/github/stars/WormW/nginx2root-rce-lab.svg) ![forks](https://img.shields.io/github/forks/WormW/nginx2root-rce-lab.svg)
- [https://github.com/The-DevOps-Daily/nginx2root-check](https://github.com/The-DevOps-Daily/nginx2root-check) :  ![starts](https://img.shields.io/github/stars/The-DevOps-Daily/nginx2root-check.svg) ![forks](https://img.shields.io/github/forks/The-DevOps-Daily/nginx2root-check.svg)
- [https://github.com/rogersouzak8s/nginx-http2-check](https://github.com/rogersouzak8s/nginx-http2-check) :  ![starts](https://img.shields.io/github/stars/rogersouzak8s/nginx-http2-check.svg) ![forks](https://img.shields.io/github/forks/rogersouzak8s/nginx-http2-check.svg)
- [https://github.com/TimTheBeastNL/nginx2root](https://github.com/TimTheBeastNL/nginx2root) :  ![starts](https://img.shields.io/github/stars/TimTheBeastNL/nginx2root.svg) ![forks](https://img.shields.io/github/forks/TimTheBeastNL/nginx2root.svg)


## CVE-2026-121994
 A stack buffer overflow in the GDB client's remote protocol handler allows an attacker-controlled debug target to execute arbitrary code in the GDB process. The vulnerability exists in fetch_register_using_p, which decodes a stub's register reply into an alloca-sized buffer without bounding writes by the register width.

- [https://github.com/DeeBumG/CVE-2026-121994-POC](https://github.com/DeeBumG/CVE-2026-121994-POC) :  ![starts](https://img.shields.io/github/stars/DeeBumG/CVE-2026-121994-POC.svg) ![forks](https://img.shields.io/github/forks/DeeBumG/CVE-2026-121994-POC.svg)


## CVE-2026-121810
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/LLCForge/CVE-2026-121810](https://github.com/LLCForge/CVE-2026-121810) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-121810.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-121810.svg)


## CVE-2026-121720
 OpenVPN 2.4.0 through 2.6.23 and 2.7_alpha1 through 2.7.8 on Windows allows local authenticated users to execute arbitrary code via a privileged service using user-controlled environment variables.

- [https://github.com/refiaa/CVE-2026-121720](https://github.com/refiaa/CVE-2026-121720) :  ![starts](https://img.shields.io/github/stars/refiaa/CVE-2026-121720.svg) ![forks](https://img.shields.io/github/forks/refiaa/CVE-2026-121720.svg)


## CVE-2026-120993
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/LLCForge/CVE-2026-120993](https://github.com/LLCForge/CVE-2026-120993) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-120993.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-120993.svg)


## CVE-2026-120967
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/LLCForge/CVE-2026-120967](https://github.com/LLCForge/CVE-2026-120967) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-120967.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-120967.svg)


## CVE-2026-119958
 Out-of-bounds write in Windows LDAP - Lightweight Directory Access Protocol allows an unauthorized attacker to execute code over a network.

- [https://github.com/LLCForge/CVE-2026-119958](https://github.com/LLCForge/CVE-2026-119958) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-119958.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-119958.svg)


## CVE-2026-118899
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/LLCForge/CVE-2026-118899](https://github.com/LLCForge/CVE-2026-118899) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-118899.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-118899.svg)


## CVE-2026-116289
 Gitea did not reject personal access tokens restricted to public resources (`public-only`) on the organization Actions runner registration-token endpoint, and the runner registered with the resulting token was not limited to public repositories. Holding only such a token with `write:organization` that belongs to an owner of a public organization, an attacker could register an organization-level runner and receive jobs of the organization's private repositories that have Actions enabled, including the workflow content, Actions secrets and variables, and a task token with access to the private repository. The issue widens what the restricted token can reach; it gives nothing beyond what the owner's full account can already do.

- [https://github.com/afsharid/gitea-cve-2026-116289-detection](https://github.com/afsharid/gitea-cve-2026-116289-detection) :  ![starts](https://img.shields.io/github/stars/afsharid/gitea-cve-2026-116289-detection.svg) ![forks](https://img.shields.io/github/forks/afsharid/gitea-cve-2026-116289-detection.svg)


## CVE-2026-115732
 Incorrect authorization in the certificate-name matching of trapperkeeper-authorization, as used by Puppet Server, in the affected products, allows a client that holds a CA-signed certificate whose name extends or shortens an authorized hostname to be authorized as that host. This enables impersonation of other nodes and, in Puppet Enterprise, access to certificate-authority administration and remote command execution on managed nodes. Exploitation requires a certificate with a colliding name, which the certificate authority issues by approval or autosign.

- [https://github.com/foxcornlab/puppet-enterprise-scanner](https://github.com/foxcornlab/puppet-enterprise-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/puppet-enterprise-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/puppet-enterprise-scanner.svg)


## CVE-2026-115731
 Deserialization of untrusted data in the report-processing code of Puppet, as used by Puppet Server, in the affected releases, allows a client that holds any CA-signed agent certificate to execute arbitrary code on the Puppet Server as its service user by submitting a report containing a crafted rich-data type via PUT request. Where the certificate authority autosigns requests without strong verification, an unauthenticated network attacker can obtain such a certificate.

- [https://github.com/foxcornlab/puppet-enterprise-scanner](https://github.com/foxcornlab/puppet-enterprise-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/puppet-enterprise-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/puppet-enterprise-scanner.svg)


## CVE-2026-114938
 Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Compiler).  Supported versions that are affected are Oracle Java SE: 8u511b33-perf, 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3; Oracle GraalVM for JDK: 17.0.21.0.3 and  21.0.13.0.3; Oracle GraalVM Enterprise Edition: 21.3.20.0.3. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in takeover of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition. Note: This vulnerability can only be exploited by supplying data to APIs in the specified Component without using Untrusted Java Web Start applications or Untrusted Java applets, such as through a web service. CVSS 3.1 Base Score 8.1 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/Dungsocool/CVE-2026-114938](https://github.com/Dungsocool/CVE-2026-114938) :  ![starts](https://img.shields.io/github/stars/Dungsocool/CVE-2026-114938.svg) ![forks](https://img.shields.io/github/forks/Dungsocool/CVE-2026-114938.svg)
- [https://github.com/Ghost-Bx1/java-exploits](https://github.com/Ghost-Bx1/java-exploits) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/java-exploits.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/java-exploits.svg)
- [https://github.com/zake1god/java2shell](https://github.com/zake1god/java2shell) :  ![starts](https://img.shields.io/github/stars/zake1god/java2shell.svg) ![forks](https://img.shields.io/github/forks/zake1god/java2shell.svg)
- [https://github.com/oflavioc/detect4shell](https://github.com/oflavioc/detect4shell) :  ![starts](https://img.shields.io/github/stars/oflavioc/detect4shell.svg) ![forks](https://img.shields.io/github/forks/oflavioc/detect4shell.svg)
- [https://github.com/boundaryx/cloudrasp-java4shell](https://github.com/boundaryx/cloudrasp-java4shell) :  ![starts](https://img.shields.io/github/stars/boundaryx/cloudrasp-java4shell.svg) ![forks](https://img.shields.io/github/forks/boundaryx/cloudrasp-java4shell.svg)
- [https://github.com/DistributedIT/cve2026-114938-java4shell-check](https://github.com/DistributedIT/cve2026-114938-java4shell-check) :  ![starts](https://img.shields.io/github/stars/DistributedIT/cve2026-114938-java4shell-check.svg) ![forks](https://img.shields.io/github/forks/DistributedIT/cve2026-114938-java4shell-check.svg)
- [https://github.com/arkrwn/PoC-CVE-2026-114938-CrashLeak](https://github.com/arkrwn/PoC-CVE-2026-114938-CrashLeak) :  ![starts](https://img.shields.io/github/stars/arkrwn/PoC-CVE-2026-114938-CrashLeak.svg) ![forks](https://img.shields.io/github/forks/arkrwn/PoC-CVE-2026-114938-CrashLeak.svg)
- [https://github.com/TahuCryptsi/poc-cve-2026-114938-java4shell-base64-oob](https://github.com/TahuCryptsi/poc-cve-2026-114938-java4shell-base64-oob) :  ![starts](https://img.shields.io/github/stars/TahuCryptsi/poc-cve-2026-114938-java4shell-base64-oob.svg) ![forks](https://img.shields.io/github/forks/TahuCryptsi/poc-cve-2026-114938-java4shell-base64-oob.svg)
- [https://github.com/avoliomattia/CVE-2026-114938](https://github.com/avoliomattia/CVE-2026-114938) :  ![starts](https://img.shields.io/github/stars/avoliomattia/CVE-2026-114938.svg) ![forks](https://img.shields.io/github/forks/avoliomattia/CVE-2026-114938.svg)
- [https://github.com/pathcosmos/CVE-2026-114938](https://github.com/pathcosmos/CVE-2026-114938) :  ![starts](https://img.shields.io/github/stars/pathcosmos/CVE-2026-114938.svg) ![forks](https://img.shields.io/github/forks/pathcosmos/CVE-2026-114938.svg)
- [https://github.com/hsmiranda/cve_2026_114938](https://github.com/hsmiranda/cve_2026_114938) :  ![starts](https://img.shields.io/github/stars/hsmiranda/cve_2026_114938.svg) ![forks](https://img.shields.io/github/forks/hsmiranda/cve_2026_114938.svg)
- [https://github.com/AngelicIndustries/Java4ShellFix](https://github.com/AngelicIndustries/Java4ShellFix) :  ![starts](https://img.shields.io/github/stars/AngelicIndustries/Java4ShellFix.svg) ![forks](https://img.shields.io/github/forks/AngelicIndustries/Java4ShellFix.svg)
- [https://github.com/alequinterok/CVE-2026-114938](https://github.com/alequinterok/CVE-2026-114938) :  ![starts](https://img.shields.io/github/stars/alequinterok/CVE-2026-114938.svg) ![forks](https://img.shields.io/github/forks/alequinterok/CVE-2026-114938.svg)
- [https://github.com/LLCForge/CVE-2026-114938](https://github.com/LLCForge/CVE-2026-114938) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-114938.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-114938.svg)
- [https://github.com/zulloper/cve-2026-114938-spring-poc](https://github.com/zulloper/cve-2026-114938-spring-poc) :  ![starts](https://img.shields.io/github/stars/zulloper/cve-2026-114938-spring-poc.svg) ![forks](https://img.shields.io/github/forks/zulloper/cve-2026-114938-spring-poc.svg)
- [https://github.com/XanDuri/java4shell-check](https://github.com/XanDuri/java4shell-check) :  ![starts](https://img.shields.io/github/stars/XanDuri/java4shell-check.svg) ![forks](https://img.shields.io/github/forks/XanDuri/java4shell-check.svg)
- [https://github.com/yora1928/CVE-2026-114938_by_yora1928](https://github.com/yora1928/CVE-2026-114938_by_yora1928) :  ![starts](https://img.shields.io/github/stars/yora1928/CVE-2026-114938_by_yora1928.svg) ![forks](https://img.shields.io/github/forks/yora1928/CVE-2026-114938_by_yora1928.svg)
- [https://github.com/jiparis/java4shell](https://github.com/jiparis/java4shell) :  ![starts](https://img.shields.io/github/stars/jiparis/java4shell.svg) ![forks](https://img.shields.io/github/forks/jiparis/java4shell.svg)
- [https://github.com/ubitquity/cve-2026-114938-java4shell-remediation](https://github.com/ubitquity/cve-2026-114938-java4shell-remediation) :  ![starts](https://img.shields.io/github/stars/ubitquity/cve-2026-114938-java4shell-remediation.svg) ![forks](https://img.shields.io/github/forks/ubitquity/cve-2026-114938-java4shell-remediation.svg)
- [https://github.com/Quaerendir/cve-2026-114938-java4shell-audit](https://github.com/Quaerendir/cve-2026-114938-java4shell-audit) :  ![starts](https://img.shields.io/github/stars/Quaerendir/cve-2026-114938-java4shell-audit.svg) ![forks](https://img.shields.io/github/forks/Quaerendir/cve-2026-114938-java4shell-audit.svg)
- [https://github.com/douglasmun/CVE-2026-114938_Java4Shell_lab](https://github.com/douglasmun/CVE-2026-114938_Java4Shell_lab) :  ![starts](https://img.shields.io/github/stars/douglasmun/CVE-2026-114938_Java4Shell_lab.svg) ![forks](https://img.shields.io/github/forks/douglasmun/CVE-2026-114938_Java4Shell_lab.svg)
- [https://github.com/afe038/audit-java4shell](https://github.com/afe038/audit-java4shell) :  ![starts](https://img.shields.io/github/stars/afe038/audit-java4shell.svg) ![forks](https://img.shields.io/github/forks/afe038/audit-java4shell.svg)
- [https://github.com/klapertart/Java4Shell-CVE-2026-114938-Summary](https://github.com/klapertart/Java4Shell-CVE-2026-114938-Summary) :  ![starts](https://img.shields.io/github/stars/klapertart/Java4Shell-CVE-2026-114938-Summary.svg) ![forks](https://img.shields.io/github/forks/klapertart/Java4Shell-CVE-2026-114938-Summary.svg)
- [https://github.com/akamai/CVE-2026-114938-java4shell-validation-mitigation](https://github.com/akamai/CVE-2026-114938-java4shell-validation-mitigation) :  ![starts](https://img.shields.io/github/stars/akamai/CVE-2026-114938-java4shell-validation-mitigation.svg) ![forks](https://img.shields.io/github/forks/akamai/CVE-2026-114938-java4shell-validation-mitigation.svg)
- [https://github.com/sam00/Java4Shell-CVE-2026-114938-PoC](https://github.com/sam00/Java4Shell-CVE-2026-114938-PoC) :  ![starts](https://img.shields.io/github/stars/sam00/Java4Shell-CVE-2026-114938-PoC.svg) ![forks](https://img.shields.io/github/forks/sam00/Java4Shell-CVE-2026-114938-PoC.svg)
- [https://github.com/Ademking/java4shell](https://github.com/Ademking/java4shell) :  ![starts](https://img.shields.io/github/stars/Ademking/java4shell.svg) ![forks](https://img.shields.io/github/forks/Ademking/java4shell.svg)
- [https://github.com/AdeelAhmedKhan/spring-boot-corretto-patched](https://github.com/AdeelAhmedKhan/spring-boot-corretto-patched) :  ![starts](https://img.shields.io/github/stars/AdeelAhmedKhan/spring-boot-corretto-patched.svg) ![forks](https://img.shields.io/github/forks/AdeelAhmedKhan/spring-boot-corretto-patched.svg)
- [https://github.com/OmarXtream/Java4Shell-Checker](https://github.com/OmarXtream/Java4Shell-Checker) :  ![starts](https://img.shields.io/github/stars/OmarXtream/Java4Shell-Checker.svg) ![forks](https://img.shields.io/github/forks/OmarXtream/Java4Shell-Checker.svg)
- [https://github.com/Certbn/CVE-2026-114938-OpenJDK-HotSpot-AVX-512-Base64-Java4Shell-](https://github.com/Certbn/CVE-2026-114938-OpenJDK-HotSpot-AVX-512-Base64-Java4Shell-) :  ![starts](https://img.shields.io/github/stars/Certbn/CVE-2026-114938-OpenJDK-HotSpot-AVX-512-Base64-Java4Shell-.svg) ![forks](https://img.shields.io/github/forks/Certbn/CVE-2026-114938-OpenJDK-HotSpot-AVX-512-Base64-Java4Shell-.svg)
- [https://github.com/simonliska/java4shell-k8s-scanner](https://github.com/simonliska/java4shell-k8s-scanner) :  ![starts](https://img.shields.io/github/stars/simonliska/java4shell-k8s-scanner.svg) ![forks](https://img.shields.io/github/forks/simonliska/java4shell-k8s-scanner.svg)
- [https://github.com/CypherSecurity/java4shell-detection](https://github.com/CypherSecurity/java4shell-detection) :  ![starts](https://img.shields.io/github/stars/CypherSecurity/java4shell-detection.svg) ![forks](https://img.shields.io/github/forks/CypherSecurity/java4shell-detection.svg)
- [https://github.com/WaveShift/ZenithJvmFlagGuard](https://github.com/WaveShift/ZenithJvmFlagGuard) :  ![starts](https://img.shields.io/github/stars/WaveShift/ZenithJvmFlagGuard.svg) ![forks](https://img.shields.io/github/forks/WaveShift/ZenithJvmFlagGuard.svg)
- [https://github.com/bkirkware/j4s-checker](https://github.com/bkirkware/j4s-checker) :  ![starts](https://img.shields.io/github/stars/bkirkware/j4s-checker.svg) ![forks](https://img.shields.io/github/forks/bkirkware/j4s-checker.svg)
- [https://github.com/carlosnetto/Java4Shell](https://github.com/carlosnetto/Java4Shell) :  ![starts](https://img.shields.io/github/stars/carlosnetto/Java4Shell.svg) ![forks](https://img.shields.io/github/forks/carlosnetto/Java4Shell.svg)
- [https://github.com/eduxcode/java4shell-lab](https://github.com/eduxcode/java4shell-lab) :  ![starts](https://img.shields.io/github/stars/eduxcode/java4shell-lab.svg) ![forks](https://img.shields.io/github/forks/eduxcode/java4shell-lab.svg)
- [https://github.com/mylesagnew/java2shell-detection](https://github.com/mylesagnew/java2shell-detection) :  ![starts](https://img.shields.io/github/stars/mylesagnew/java2shell-detection.svg) ![forks](https://img.shields.io/github/forks/mylesagnew/java2shell-detection.svg)
- [https://github.com/chandrapati/csw-java-workloads](https://github.com/chandrapati/csw-java-workloads) :  ![starts](https://img.shields.io/github/stars/chandrapati/csw-java-workloads.svg) ![forks](https://img.shields.io/github/forks/chandrapati/csw-java-workloads.svg)
- [https://github.com/jsik22/java4shell-detection](https://github.com/jsik22/java4shell-detection) :  ![starts](https://img.shields.io/github/stars/jsik22/java4shell-detection.svg) ![forks](https://img.shields.io/github/forks/jsik22/java4shell-detection.svg)
- [https://github.com/FebusAI/java4shell-poc](https://github.com/FebusAI/java4shell-poc) :  ![starts](https://img.shields.io/github/stars/FebusAI/java4shell-poc.svg) ![forks](https://img.shields.io/github/forks/FebusAI/java4shell-poc.svg)
- [https://github.com/fumioryoto/java4shell-poc](https://github.com/fumioryoto/java4shell-poc) :  ![starts](https://img.shields.io/github/stars/fumioryoto/java4shell-poc.svg) ![forks](https://img.shields.io/github/forks/fumioryoto/java4shell-poc.svg)
- [https://github.com/tobiastillstam/Scan-Java4Shell](https://github.com/tobiastillstam/Scan-Java4Shell) :  ![starts](https://img.shields.io/github/stars/tobiastillstam/Scan-Java4Shell.svg) ![forks](https://img.shields.io/github/forks/tobiastillstam/Scan-Java4Shell.svg)
- [https://github.com/nu0l/Java4Shell-LocalScanner](https://github.com/nu0l/Java4Shell-LocalScanner) :  ![starts](https://img.shields.io/github/stars/nu0l/Java4Shell-LocalScanner.svg) ![forks](https://img.shields.io/github/forks/nu0l/Java4Shell-LocalScanner.svg)
- [https://github.com/rogersouzak8s/java4shell-check](https://github.com/rogersouzak8s/java4shell-check) :  ![starts](https://img.shields.io/github/stars/rogersouzak8s/java4shell-check.svg) ![forks](https://img.shields.io/github/forks/rogersouzak8s/java4shell-check.svg)
- [https://github.com/Mahgal/java4shell-check](https://github.com/Mahgal/java4shell-check) :  ![starts](https://img.shields.io/github/stars/Mahgal/java4shell-check.svg) ![forks](https://img.shields.io/github/forks/Mahgal/java4shell-check.svg)
- [https://github.com/Nextron-Labs/thor-plugin-jvm-crash-cluster](https://github.com/Nextron-Labs/thor-plugin-jvm-crash-cluster) :  ![starts](https://img.shields.io/github/stars/Nextron-Labs/thor-plugin-jvm-crash-cluster.svg) ![forks](https://img.shields.io/github/forks/Nextron-Labs/thor-plugin-jvm-crash-cluster.svg)
- [https://github.com/darkfibr/yara-java4shell](https://github.com/darkfibr/yara-java4shell) :  ![starts](https://img.shields.io/github/stars/darkfibr/yara-java4shell.svg) ![forks](https://img.shields.io/github/forks/darkfibr/yara-java4shell.svg)
- [https://github.com/ionsec/java4shell-detector](https://github.com/ionsec/java4shell-detector) :  ![starts](https://img.shields.io/github/stars/ionsec/java4shell-detector.svg) ![forks](https://img.shields.io/github/forks/ionsec/java4shell-detector.svg)
- [https://github.com/techdevfun/java4shell](https://github.com/techdevfun/java4shell) :  ![starts](https://img.shields.io/github/stars/techdevfun/java4shell.svg) ![forks](https://img.shields.io/github/forks/techdevfun/java4shell.svg)
- [https://github.com/zejunyang/java4shell-rce](https://github.com/zejunyang/java4shell-rce) :  ![starts](https://img.shields.io/github/stars/zejunyang/java4shell-rce.svg) ![forks](https://img.shields.io/github/forks/zejunyang/java4shell-rce.svg)
- [https://github.com/cm-suzuki-ryo/aws-waf-java4shell-base64-guard](https://github.com/cm-suzuki-ryo/aws-waf-java4shell-base64-guard) :  ![starts](https://img.shields.io/github/stars/cm-suzuki-ryo/aws-waf-java4shell-base64-guard.svg) ![forks](https://img.shields.io/github/forks/cm-suzuki-ryo/aws-waf-java4shell-base64-guard.svg)
- [https://github.com/chjwoo7/java4shell](https://github.com/chjwoo7/java4shell) :  ![starts](https://img.shields.io/github/stars/chjwoo7/java4shell.svg) ![forks](https://img.shields.io/github/forks/chjwoo7/java4shell.svg)
- [https://github.com/securibee/java4shell-tenable-skill](https://github.com/securibee/java4shell-tenable-skill) :  ![starts](https://img.shields.io/github/stars/securibee/java4shell-tenable-skill.svg) ![forks](https://img.shields.io/github/forks/securibee/java4shell-tenable-skill.svg)


## CVE-2026-114202
Security Update for ASUS Control Center Express Agent  ' section on the ASUS Security Advisory for more information.

- [https://github.com/LLCForge/CVE-2026-114202](https://github.com/LLCForge/CVE-2026-114202) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-114202.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-114202.svg)


## CVE-2026-113425
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/LLCForge/CVE-2026-113425](https://github.com/LLCForge/CVE-2026-113425) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-113425.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-113425.svg)


## CVE-2026-112611
 An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in iOS 26.7.2 and iPadOS 26.7.2, iOS 27.2 and iPadOS 27.2, macOS Sequoia 15.8.2, macOS Tahoe 26.7.2. Processing a maliciously crafted PDF file may lead to memory corruption.

- [https://github.com/SKVLENT/CVE-2026-112611](https://github.com/SKVLENT/CVE-2026-112611) :  ![starts](https://img.shields.io/github/stars/SKVLENT/CVE-2026-112611.svg) ![forks](https://img.shields.io/github/forks/SKVLENT/CVE-2026-112611.svg)


## CVE-2026-111825
 The Event Tickets with Ticket Scanner plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'code' parameter in all versions up to, and including, 3.3.1 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page. The payload persists through WooCommerce session data into order-item metadata and executes when rendered in the ticket scanner interface.

- [https://github.com/jacobbabula/CVE-2026-111825](https://github.com/jacobbabula/CVE-2026-111825) :  ![starts](https://img.shields.io/github/stars/jacobbabula/CVE-2026-111825.svg) ![forks](https://img.shields.io/github/forks/jacobbabula/CVE-2026-111825.svg)


## CVE-2026-109619
 PHP has various global state that temporarily points into request memory. In some scenarios, global state may not be correctly reset, or may be repopulated after being reset. The global state may then refer to request memory even after it has been freed. Subsequent requests may read or branch on this stale state before it is fully initialized. Multiple strategies can trigger this condition and produce remote code execution (RCE).

- [https://github.com/twili8/php2shell-poc](https://github.com/twili8/php2shell-poc) :  ![starts](https://img.shields.io/github/stars/twili8/php2shell-poc.svg) ![forks](https://img.shields.io/github/forks/twili8/php2shell-poc.svg)


## CVE-2026-109618
 PHP uses longjmp() for out-of-memory (OOM) errors to exit the current context and abort handling of the request. Some contexts may not properly account for this scenario and leave request memory in an uninitialized state before performing an allocation. The subsequent request cleanup procedure may read or branch on this memory. Multiple OOM strategies can consistently trigger this condition and lead to remote code execution (RCE).

- [https://github.com/twili8/php2shell-poc](https://github.com/twili8/php2shell-poc) :  ![starts](https://img.shields.io/github/stars/twili8/php2shell-poc.svg) ![forks](https://img.shields.io/github/forks/twili8/php2shell-poc.svg)
- [https://github.com/Galeax/PHP2Shell-Mitigations](https://github.com/Galeax/PHP2Shell-Mitigations) :  ![starts](https://img.shields.io/github/stars/Galeax/PHP2Shell-Mitigations.svg) ![forks](https://img.shields.io/github/forks/Galeax/PHP2Shell-Mitigations.svg)
- [https://github.com/Andrew2142/php73-backport](https://github.com/Andrew2142/php73-backport) :  ![starts](https://img.shields.io/github/stars/Andrew2142/php73-backport.svg) ![forks](https://img.shields.io/github/forks/Andrew2142/php73-backport.svg)
- [https://github.com/alvm/php2shell-eol-backport](https://github.com/alvm/php2shell-eol-backport) :  ![starts](https://img.shields.io/github/stars/alvm/php2shell-eol-backport.svg) ![forks](https://img.shields.io/github/forks/alvm/php2shell-eol-backport.svg)


## CVE-2026-108474
 In JetBrains Exposed before 1.5.1 sQL injection was possible via unescaped string arguments of several SQL functions

- [https://github.com/DeeBumG/CVE-2026-108474-POC](https://github.com/DeeBumG/CVE-2026-108474-POC) :  ![starts](https://img.shields.io/github/stars/DeeBumG/CVE-2026-108474-POC.svg) ![forks](https://img.shields.io/github/forks/DeeBumG/CVE-2026-108474-POC.svg)


## CVE-2026-106152
 In Progress® Telerik® Report Server prior to version 12.3.26.1110, an external control of a system configuration setting vulnerability allows an unauthenticated remote attacker to influence the server address used by Report Server when generating links and notifications. With user interaction, this can lead to disclosure of sensitive information and account takeover.

- [https://github.com/fumioryoto/CVE-2026-106152](https://github.com/fumioryoto/CVE-2026-106152) :  ![starts](https://img.shields.io/github/stars/fumioryoto/CVE-2026-106152.svg) ![forks](https://img.shields.io/github/forks/fumioryoto/CVE-2026-106152.svg)


## CVE-2026-100397
 Rucio is a scientific data management framework. From 1.14.0 until 35.9.1, 38.6.1, 40.4.2, and 41.1.1, validate_auth_token in lib/rucio/core/authentication.py does not distinguish short-lived SSH challenge nonces from authentication tokens stored in the same token table. An unauthenticated attacker can request /auth/ssh_challenge_token for an arbitrary account by supplying X-Rucio-Account, then present the returned X-Rucio-SSH-Challenge-Token as X-Rucio-Auth-Token to authenticate to other API endpoints as that account, including an administrative account. This issue is fixed in versions 35.9.1, 38.6.1, 40.4.2, and 41.1.1.

- [https://github.com/LLCForge/CVE-2026-100397](https://github.com/LLCForge/CVE-2026-100397) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-100397.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-100397.svg)


## CVE-2026-98432
will be addressed in a separate patch.

- [https://github.com/hardenedlinux/linux-rce-poc](https://github.com/hardenedlinux/linux-rce-poc) :  ![starts](https://img.shields.io/github/stars/hardenedlinux/linux-rce-poc.svg) ![forks](https://img.shields.io/github/forks/hardenedlinux/linux-rce-poc.svg)
- [https://github.com/mrjoshuap-hq/ansible-ezcve](https://github.com/mrjoshuap-hq/ansible-ezcve) :  ![starts](https://img.shields.io/github/stars/mrjoshuap-hq/ansible-ezcve.svg) ![forks](https://img.shields.io/github/forks/mrjoshuap-hq/ansible-ezcve.svg)


## CVE-2026-98260
[ tglx: Move the cleanup right after de_thread() ]

- [https://github.com/tiamo1990/CVE-2026-98260](https://github.com/tiamo1990/CVE-2026-98260) :  ![starts](https://img.shields.io/github/stars/tiamo1990/CVE-2026-98260.svg) ![forks](https://img.shields.io/github/forks/tiamo1990/CVE-2026-98260.svg)


## CVE-2026-92182
The specific flaw exists within the XMLRPC endpoint. The issue results from incorrect authorization prior to allowing access to functionality. An attacker can leverage this vulnerability to execute code within the context of the root. Was ZDI-CAN-32353.

- [https://github.com/LLCForge/CVE-2026-92182](https://github.com/LLCForge/CVE-2026-92182) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-92182.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-92182.svg)


## CVE-2026-78006
 The The Events Calendar plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 6.17.4 via the is_safe_widget_instance function. This is due to insufficient protection in is_safe_widget_instance, which can be bypassed because PHP fires magic methods during its pre-parse, combined with enable_rendering_widget_copied() forging a valid wp_hash integrity attribute before unserialize() is reached. This makes it possible for unauthenticated attackers to execute code on the server. This is exploitable without authentication or approval because the plugin's V2 single-event template runs do_blocks() over buffered comment HTML, and WordPress returns a moderation-hash URL that allows an unauthenticated commenter to immediately view their own pending comment, delivering the injected block markup to the vulnerable code path before any moderation occurs. This does require comments to be enabled and visible on events.

- [https://github.com/rismabadog-svg/CVE-2026-78006-POC](https://github.com/rismabadog-svg/CVE-2026-78006-POC) :  ![starts](https://img.shields.io/github/stars/rismabadog-svg/CVE-2026-78006-POC.svg) ![forks](https://img.shields.io/github/forks/rismabadog-svg/CVE-2026-78006-POC.svg)


## CVE-2026-71961
 Cudy WR3000 2.0 running firmware before 2.5.24 contains an OS command injection vulnerability that allows authenticated attackers to execute arbitrary OS commands with root privileges by sending unsanitized input through the mesh MQTT command interface. The sync_command binary forwards unsanitized input directly to a shell execution sink in command.lua, enabling attackers with access to the MQTT broker to exploit the default-enabled command execution path to achieve full root-level system compromise.

- [https://github.com/ShibbityShwab/cudy-wr3000v2-cve](https://github.com/ShibbityShwab/cudy-wr3000v2-cve) :  ![starts](https://img.shields.io/github/stars/ShibbityShwab/cudy-wr3000v2-cve.svg) ![forks](https://img.shields.io/github/forks/ShibbityShwab/cudy-wr3000v2-cve.svg)


## CVE-2026-71960
 Cudy WR3000 2.0 running firmware before 2.5.24 contains a hard-coded JWT HMAC signing secret vulnerability in the Mosquitto MQTT broker's authentication plugin that allows unauthenticated attackers to forge valid JWT tokens by extracting the secret from the firmware image. Attackers can use the extracted secret to craft arbitrary JWT tokens and authenticate to the MQTT broker without legitimate credentials, gaining unauthorized access to the device's mesh networking interface.

- [https://github.com/ShibbityShwab/cudy-wr3000v2-cve](https://github.com/ShibbityShwab/cudy-wr3000v2-cve) :  ![starts](https://img.shields.io/github/stars/ShibbityShwab/cudy-wr3000v2-cve.svg) ![forks](https://img.shields.io/github/forks/ShibbityShwab/cudy-wr3000v2-cve.svg)


## CVE-2026-63219
 GeoNetwork is a catalog application to manage spatially referenced resources. Prior to versions 4.4.12 and 4.2.17, the API endpoint for creating a new formatter via file upload is unprotected and allows the upload of external uncontrolled files. An unauthenticated attacker can upload arbitrary `.xsl` or `.zip` formatter files to the server.  An unauthenticated attacker can write arbitrary files into the GeoNetwork formatter directory. On its own this constitutes unauthorized write access to server storage. The issue is patched in GeoNetwork versions 4.4.12 and 4.2.17.

- [https://github.com/gzzcoo/GeoNetwork-UnauthenticatedRCE](https://github.com/gzzcoo/GeoNetwork-UnauthenticatedRCE) :  ![starts](https://img.shields.io/github/stars/gzzcoo/GeoNetwork-UnauthenticatedRCE.svg) ![forks](https://img.shields.io/github/forks/gzzcoo/GeoNetwork-UnauthenticatedRCE.svg)


## CVE-2026-61584
 Chamilo LMS is an open-source learning management system. Prior to 1.11.40, main/inc/ajax/record_audio_rtc.ajax.php concatenates the user-controlled audio_dir parameter with the course document root and passes the result to recursive directory creation without path normalization. An authenticated course user can select directory paths outside the intended course storage tree wherever the web-server account has permission to create directories. The resulting filesystem changes can interfere with application layout or support a separate file-write or code-execution chain, although this endpoint alone is not shown to write attacker-selected file content outside the course tree. This issue is fixed in version 1.11.40.

- [https://github.com/HORKimhab/CVE-Chamilo-LMS](https://github.com/HORKimhab/CVE-Chamilo-LMS) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-Chamilo-LMS.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-Chamilo-LMS.svg)


## CVE-2026-61583
 Chamilo LMS is an open-source learning management system. Prior to 1.11.40, main/dropbox/dropbox_functions.inc.php accepts a literal .htaccess filename in the course dropbox and stores it in a directory served by Apache, where the file can alter handler behavior under the required AllowOverride All configuration. Any authenticated course participant can upload .htaccess and then upload a PHP payload disguised as a .gif, resulting in code execution as the web-server user when the dropbox tool is enabled. This can expose or modify the Chamilo installation, course content, and database credentials. This issue is fixed in version 1.11.40.

- [https://github.com/HORKimhab/CVE-Chamilo-LMS](https://github.com/HORKimhab/CVE-Chamilo-LMS) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-Chamilo-LMS.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-Chamilo-LMS.svg)


## CVE-2026-61582
 Chamilo LMS is an open-source learning management system. Prior to 1.11.40, main/inc/ajax/user_manager.ajax.php exposes the update_users action without an authorization check and stores attacker-controlled firstname, lastname, and email values without HTML sanitization. An unauthenticated attacker can modify another user's profile fields, and the stored content executes when user_portal.php, the administrative user listing, user information, social profile, course participant list, or message-composer recipient header renders the modified account. Targeting an administrator account can expose administrator-session data or permit actions in that session. This issue is fixed in version 1.11.40.

- [https://github.com/HORKimhab/CVE-Chamilo-LMS](https://github.com/HORKimhab/CVE-Chamilo-LMS) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-Chamilo-LMS.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-Chamilo-LMS.svg)


## CVE-2026-61578
 Chamilo LMS is an open-source learning management system. Prior to 1.11.40 on the 1.11 release line and in 2.0.0, plugin/cleandeletedfiles/src/ajax.php and public/plugin/CleanDeletedFiles/src/ajax.php pass the request path parameter and list parameter directly to unlink without canonicalization, filename validation, or confinement to the plugin's scanned directories. An authenticated administrator can delete arbitrary files writable by the web server; a cross-site request forgery against an administrator session can reach the same operation. Deleting application source, uploaded content, cache, or configuration files can cause data loss and denial of service. This issue is fixed in version 1.11.40 on the 1.11 release line. No fixed 2.0 release is established as of this review.

- [https://github.com/HORKimhab/CVE-Chamilo-LMS](https://github.com/HORKimhab/CVE-Chamilo-LMS) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-Chamilo-LMS.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-Chamilo-LMS.svg)


## CVE-2026-58400
`java.lang.Runtime.exec()` or `java.lang.ProcessBuilder` directly, achieving arbitrary command execution as the GeoNetwork process user. A user with sufficient privileges to upload a formatter can deliver a `.xsl` file containing Java extension call that execute arbitrary OS commands with the privileges of the GeoNetwork process. The issue is patched in GeoNetwork versions 4.4.12 and 4.2.17.

- [https://github.com/gzzcoo/GeoNetwork-UnauthenticatedRCE](https://github.com/gzzcoo/GeoNetwork-UnauthenticatedRCE) :  ![starts](https://img.shields.io/github/stars/gzzcoo/GeoNetwork-UnauthenticatedRCE.svg) ![forks](https://img.shields.io/github/forks/gzzcoo/GeoNetwork-UnauthenticatedRCE.svg)


## CVE-2026-48728
 The GLPI Inventory Plugin handles network discovery, inventory, software deployment, and data collection for GLPI agents. Prior to 1.6.8, the /b/deploy, /b/collect, and /b/esx agent API endpoints do not authenticate requests before processing Deploy, Collect, and ESX task operations. An unauthenticated remote attacker can enumerate jobs and manipulate their status through these endpoints, disclosing job information and interfering with task processing. This issue is fixed in version 1.6.8.

- [https://github.com/Crypto-Cat/apache-ofbiz-2026-pocs](https://github.com/Crypto-Cat/apache-ofbiz-2026-pocs) :  ![starts](https://img.shields.io/github/stars/Crypto-Cat/apache-ofbiz-2026-pocs.svg) ![forks](https://img.shields.io/github/forks/Crypto-Cat/apache-ofbiz-2026-pocs.svg)


## CVE-2026-47884
Spring Framework 5.2.25.RELEASE and earlier

- [https://github.com/LLCForge/CVE-2026-47884](https://github.com/LLCForge/CVE-2026-47884) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-47884.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-47884.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/Gr-1m/CVE-2026-31431](https://github.com/Gr-1m/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/Gr-1m/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/Gr-1m/CVE-2026-31431.svg)


## CVE-2026-30502
 A Cross-Site Scripting (XSS) vulnerability in OpenKM v6.3.12 allows attackers to execute arbitrary Javascript in the context of the user's browser via a crafted input injected into the Content parameter.

- [https://github.com/dharmstm/CVE-2026-30502-OpenKM-6.3.12-Reflected-XSS](https://github.com/dharmstm/CVE-2026-30502-OpenKM-6.3.12-Reflected-XSS) :  ![starts](https://img.shields.io/github/stars/dharmstm/CVE-2026-30502-OpenKM-6.3.12-Reflected-XSS.svg) ![forks](https://img.shields.io/github/forks/dharmstm/CVE-2026-30502-OpenKM-6.3.12-Reflected-XSS.svg)


## CVE-2026-24708
 An issue was discovered in OpenStack Nova before 30.2.2, 31 before 31.2.1, and 32 before 32.1.1. By writing a malicious QCOW header to a root or ephemeral disk and then triggering a resize, a user may convince Nova's Flat image backend to call qemu-img without a format restriction, resulting in an unsafe image resize operation that could destroy data on the host system. Only compute nodes using the Flat image backend (usually configured with use_cow_images=False) are affected.

- [https://github.com/ahmed-stg/cve-2026-24708-lab](https://github.com/ahmed-stg/cve-2026-24708-lab) :  ![starts](https://img.shields.io/github/stars/ahmed-stg/cve-2026-24708-lab.svg) ![forks](https://img.shields.io/github/forks/ahmed-stg/cve-2026-24708-lab.svg)


## CVE-2026-19773
The specific flaw exists within the parsing of HTTP/2 HPACK path header. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated buffer. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-31036.

- [https://github.com/firmdura/meta-firmdura-kirkstone](https://github.com/firmdura/meta-firmdura-kirkstone) :  ![starts](https://img.shields.io/github/stars/firmdura/meta-firmdura-kirkstone.svg) ![forks](https://img.shields.io/github/forks/firmdura/meta-firmdura-kirkstone.svg)


## CVE-2026-10961
 Use after free in Chrome for iOS in Google Chrome on iOS prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/lzz0403/CVE-2026-109618-PHP2Shell-poc](https://github.com/lzz0403/CVE-2026-109618-PHP2Shell-poc) :  ![starts](https://img.shields.io/github/stars/lzz0403/CVE-2026-109618-PHP2Shell-poc.svg) ![forks](https://img.shields.io/github/forks/lzz0403/CVE-2026-109618-PHP2Shell-poc.svg)
- [https://github.com/xaviware/go-php2shell-scanner-CVE-2026-109618-CVE-2026-109619](https://github.com/xaviware/go-php2shell-scanner-CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/xaviware/go-php2shell-scanner-CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/xaviware/go-php2shell-scanner-CVE-2026-109618-CVE-2026-109619.svg)


## CVE-2026-9526
 A vulnerability was found in itsourcecode Electronic Judging System 1.0. This vulnerability affects unknown code of the file /admin/edit_team.php. The manipulation of the argument num_id results in sql injection. The attack may be launched remotely. The exploit has been made public and could be used.

- [https://github.com/netuseradministrator/CVE-2026-95267](https://github.com/netuseradministrator/CVE-2026-95267) :  ![starts](https://img.shields.io/github/stars/netuseradministrator/CVE-2026-95267.svg) ![forks](https://img.shields.io/github/forks/netuseradministrator/CVE-2026-95267.svg)


## CVE-2026-3143
 The Total Upkeep – WordPress Backup Plugin plus Restore & Migrate by BoldGrid plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'wp_ajax_cli_cancel' function in all versions up to, and including, 1.17.1. This makes it possible for unauthenticated attackers to cancel a pending rollback, potentially preventing a WordPress installation from automatically reverting a failed update.

- [https://github.com/JnamerZ/CopyFail-CVE-2026-31431](https://github.com/JnamerZ/CopyFail-CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/JnamerZ/CopyFail-CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/JnamerZ/CopyFail-CVE-2026-31431.svg)


## CVE-2026-1096
 The Best-wp-google-map plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'latitude' and 'longitudinal' parameters of the 'google_map_view' shortcode in all versions up to, and including, 2.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/santihabib/CVE-2026-109619](https://github.com/santihabib/CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/santihabib/CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/santihabib/CVE-2026-109619.svg)


## CVE-2025-57819
 FreePBX is an open-source web-based graphical user interface. FreePBX 15, 16, and 17 endpoints are vulnerable due to insufficiently sanitized user-supplied data allowing unauthenticated access to FreePBX Administrator leading to arbitrary database manipulation and remote code execution. This issue has been patched in endpoint versions 15.0.66, 16.0.89, and 17.0.3.

- [https://github.com/alinaclark672377250/SQL-Injection-and-RCE_CVE-2025-57819](https://github.com/alinaclark672377250/SQL-Injection-and-RCE_CVE-2025-57819) :  ![starts](https://img.shields.io/github/stars/alinaclark672377250/SQL-Injection-and-RCE_CVE-2025-57819.svg) ![forks](https://img.shields.io/github/forks/alinaclark672377250/SQL-Injection-and-RCE_CVE-2025-57819.svg)


## CVE-2025-32462
 Sudo before 1.9.17p1, when used with a sudoers file that specifies a host that is neither the current host nor ALL, allows listed users to execute commands on unintended machines.

- [https://github.com/ceraz02/cve-2025-32462-analysis](https://github.com/ceraz02/cve-2025-32462-analysis) :  ![starts](https://img.shields.io/github/stars/ceraz02/cve-2025-32462-analysis.svg) ![forks](https://img.shields.io/github/forks/ceraz02/cve-2025-32462-analysis.svg)


## CVE-2025-31125
 Vite is a frontend tooling framework for javascript. Vite exposes content of non-allowed files using ?inline&import or ?raw?import. Only apps explicitly exposing the Vite dev server to the network (using --host or server.host config option) are affected. This vulnerability is fixed in 6.2.4, 6.1.3, 6.0.13, 5.4.16, and 4.5.11.

- [https://github.com/alinaclark672377250/Vitejs-exploit](https://github.com/alinaclark672377250/Vitejs-exploit) :  ![starts](https://img.shields.io/github/stars/alinaclark672377250/Vitejs-exploit.svg) ![forks](https://img.shields.io/github/forks/alinaclark672377250/Vitejs-exploit.svg)


## CVE-2025-6561
 Certain hybrid DVR models ((HBF-09KD and HBF-16NK)) from Hunt Electronic have an Exposure of Sensitive Information vulnerability, allowing unauthenticated remote attackers to directly access a system configuration file and obtain plaintext administrator credentials.

- [https://github.com/redline1736/CVE-2025-65616](https://github.com/redline1736/CVE-2025-65616) :  ![starts](https://img.shields.io/github/stars/redline1736/CVE-2025-65616.svg) ![forks](https://img.shields.io/github/forks/redline1736/CVE-2025-65616.svg)


## CVE-2025-3248
code.

- [https://github.com/A5omics/exposecheck](https://github.com/A5omics/exposecheck) :  ![starts](https://img.shields.io/github/stars/A5omics/exposecheck.svg) ![forks](https://img.shields.io/github/forks/A5omics/exposecheck.svg)


## CVE-2024-50849
 A Stored Cross-Site Scripting (XSS) vulnerability in the "Rules" functionality of WorldServer v11.8.2 allows a remote authenticated attacker to execute arbitrary JavaScript code.

- [https://github.com/SN4K3N/CVE-2024-50849](https://github.com/SN4K3N/CVE-2024-50849) :  ![starts](https://img.shields.io/github/stars/SN4K3N/CVE-2024-50849.svg) ![forks](https://img.shields.io/github/forks/SN4K3N/CVE-2024-50849.svg)


## CVE-2024-50848
 An XML External Entity (XXE) vulnerability in the Import object and Translation Memory import functionalities of WorldServer v11.8.2 to access sensitive information and execute arbitrary commands via supplying a crafted .tmx file.

- [https://github.com/SN4K3N/CVE-2024-50848](https://github.com/SN4K3N/CVE-2024-50848) :  ![starts](https://img.shields.io/github/stars/SN4K3N/CVE-2024-50848.svg) ![forks](https://img.shields.io/github/forks/SN4K3N/CVE-2024-50848.svg)


## CVE-2024-21626
 runc is a CLI tool for spawning and running containers on Linux according to the OCI specification. In runc 1.1.11 and earlier, due to an internal file descriptor leak, an attacker could cause a newly-spawned container process (from runc exec) to have a working directory in the host filesystem namespace, allowing for a container escape by giving access to the host filesystem ("attack 2"). The same attack could be used by a malicious image to allow a container process to gain access to the host filesystem through runc run ("attack 1"). Variants of attacks 1 and 2 could be also be used to overwrite semi-arbitrary host binaries, allowing for complete container escapes ("attack 3a" and "attack 3b"). runc 1.1.12 includes patches for this issue.

- [https://github.com/n3d-d3v/Multi-Tenant-FaaS-Security-Lab-CVE-2024-21626](https://github.com/n3d-d3v/Multi-Tenant-FaaS-Security-Lab-CVE-2024-21626) :  ![starts](https://img.shields.io/github/stars/n3d-d3v/Multi-Tenant-FaaS-Security-Lab-CVE-2024-21626.svg) ![forks](https://img.shields.io/github/forks/n3d-d3v/Multi-Tenant-FaaS-Security-Lab-CVE-2024-21626.svg)


## CVE-2024-2887
 Type Confusion in WebAssembly in Google Chrome prior to 123.0.6312.86 allowed a remote attacker to execute arbitrary code via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/J-Delsinne/samsung-tizen9-root](https://github.com/J-Delsinne/samsung-tizen9-root) :  ![starts](https://img.shields.io/github/stars/J-Delsinne/samsung-tizen9-root.svg) ![forks](https://img.shields.io/github/forks/J-Delsinne/samsung-tizen9-root.svg)


## CVE-2022-46337
and 8.

- [https://github.com/intersoftdatalabs-in/derby](https://github.com/intersoftdatalabs-in/derby) :  ![starts](https://img.shields.io/github/stars/intersoftdatalabs-in/derby.svg) ![forks](https://img.shields.io/github/forks/intersoftdatalabs-in/derby.svg)


## CVE-2022-38694
 In BootRom, there is a possible unchecked write address. This could lead to local escalation of privilege with no additional execution privileges needed.

- [https://github.com/sriramsrangan/itel-a05s-a663lc](https://github.com/sriramsrangan/itel-a05s-a663lc) :  ![starts](https://img.shields.io/github/stars/sriramsrangan/itel-a05s-a663lc.svg) ![forks](https://img.shields.io/github/forks/sriramsrangan/itel-a05s-a663lc.svg)


## CVE-2022-36449
 An issue was discovered in the Arm Mali GPU Kernel Driver. A non-privileged user can make improper GPU processing operations to gain access to already freed memory, write a limited amount outside of buffer bounds, or to disclose details of memory mappings. This affects Midgard r4p0 through r32p0, Bifrost r0p0 through r38p0 and r39p0 before r38p1, and Valhall r19p0 through r38p0 and r39p0 before r38p1.

- [https://github.com/MootComb/cve-2022-36449-mali](https://github.com/MootComb/cve-2022-36449-mali) :  ![starts](https://img.shields.io/github/stars/MootComb/cve-2022-36449-mali.svg) ![forks](https://img.shields.io/github/forks/MootComb/cve-2022-36449-mali.svg)


## CVE-2022-0995
 An out-of-bounds (OOB) memory write flaw was found in the Linux kernel’s watch_queue event notification subsystem. This flaw can overwrite parts of the kernel state, potentially allowing a local user to gain privileged access or cause a denial of service on the system.

- [https://github.com/Calculusdetective/Page_Jack_pwn](https://github.com/Calculusdetective/Page_Jack_pwn) :  ![starts](https://img.shields.io/github/stars/Calculusdetective/Page_Jack_pwn.svg) ![forks](https://img.shields.io/github/forks/Calculusdetective/Page_Jack_pwn.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `grafana_host_url/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/Wobomba/grafana-decrypt](https://github.com/Wobomba/grafana-decrypt) :  ![starts](https://img.shields.io/github/stars/Wobomba/grafana-decrypt.svg) ![forks](https://img.shields.io/github/forks/Wobomba/grafana-decrypt.svg)


## CVE-2021-26102
 A relative path traversal vulnerability (CWE-23) in FortiWAN version 4.5.7 and below, 4.4 all versions may allow a remote non-authenticated attacker to delete files on the system by sending a crafted POST request. In particular, deleting specific configuration files will reset the Admin password to its default value.

- [https://github.com/SleepyCofe/CVE-2021-26102](https://github.com/SleepyCofe/CVE-2021-26102) :  ![starts](https://img.shields.io/github/stars/SleepyCofe/CVE-2021-26102.svg) ![forks](https://img.shields.io/github/forks/SleepyCofe/CVE-2021-26102.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/LayarKacaSiber/CVE-2021-41773](https://github.com/LayarKacaSiber/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/LayarKacaSiber/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/LayarKacaSiber/CVE-2021-41773.svg)
- [https://github.com/redspy-sec/CVE-2021-41773](https://github.com/redspy-sec/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/redspy-sec/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/redspy-sec/CVE-2021-41773.svg)


## CVE-2020-14979
 The WinRing0.sys and WinRing0x64.sys drivers 1.2.0 in EVGA Precision X1 through 1.0.6 allow local users, including low integrity processes, to read and write to arbitrary memory locations. This allows any user to gain NT AUTHORITY\SYSTEM privileges by mapping \Device\PhysicalMemory into the calling process.

- [https://github.com/Skynet-Marwen/trafficmonitor-pawnio-fix](https://github.com/Skynet-Marwen/trafficmonitor-pawnio-fix) :  ![starts](https://img.shields.io/github/stars/Skynet-Marwen/trafficmonitor-pawnio-fix.svg) ![forks](https://img.shields.io/github/forks/Skynet-Marwen/trafficmonitor-pawnio-fix.svg)


## CVE-2019-2215
 A use-after-free in binder.c allows an elevation of privilege from an application to the Linux Kernel. No user interaction is required to exploit this vulnerability, however exploitation does require either the installation of a malicious local application or a separate vulnerability in a network facing application.Product: AndroidAndroid ID: A-141720095

- [https://github.com/neohob/odinroot](https://github.com/neohob/odinroot) :  ![starts](https://img.shields.io/github/stars/neohob/odinroot.svg) ![forks](https://img.shields.io/github/forks/neohob/odinroot.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/gigirahamaa/heartbleed-project-](https://github.com/gigirahamaa/heartbleed-project-) :  ![starts](https://img.shields.io/github/stars/gigirahamaa/heartbleed-project-.svg) ![forks](https://img.shields.io/github/forks/gigirahamaa/heartbleed-project-.svg)

