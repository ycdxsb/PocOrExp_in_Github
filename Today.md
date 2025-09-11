# Update 2025-09-11
## CVE-2025-58180
 OctoPrint provides a web interface for controlling consumer 3D printers. OctoPrint versions up until and including 1.11.2 contain a vulnerability that allows an authenticated attacker to upload a file under a specially crafted filename that will allow arbitrary command execution if said filename becomes included in a command defined in a system event handler and said event gets triggered. If no event handlers executing system commands with uploaded filenames as parameters have been configured, this vulnerability does not have an impact. The vulnerability is patched in version 1.11.3. As a workaround, OctoPrint administrators who have event handlers configured that include any kind of filename based placeholders should disable those by setting their `enabled` property to `False` or unchecking the "Enabled" checkbox in the GUI based Event Manager. Alternatively, OctoPrint administrators should set `feature.enforceReallyUniversalFilenames` to `true` in `config.yaml` and restart OctoPrint, then vet the existing uploads and make sure to delete any suspicious looking files. As always, OctoPrint administrators are advised to not expose OctoPrint on hostile networks like the public internet, and to vet who has access to their instance.

- [https://github.com/prabhatverma47/CVE-2025-58180](https://github.com/prabhatverma47/CVE-2025-58180) :  ![starts](https://img.shields.io/github/stars/prabhatverma47/CVE-2025-58180.svg) ![forks](https://img.shields.io/github/forks/prabhatverma47/CVE-2025-58180.svg)


## CVE-2025-57833
 An issue was discovered in Django 4.2 before 4.2.24, 5.1 before 5.1.12, and 5.2 before 5.2.6. FilteredRelation is subject to SQL injection in column aliases, using a suitably crafted dictionary, with dictionary expansion, as the **kwargs passed QuerySet.annotate() or QuerySet.alias().

- [https://github.com/loic-houchi/Django-faille-CVE-2025-57833_test](https://github.com/loic-houchi/Django-faille-CVE-2025-57833_test) :  ![starts](https://img.shields.io/github/stars/loic-houchi/Django-faille-CVE-2025-57833_test.svg) ![forks](https://img.shields.io/github/forks/loic-houchi/Django-faille-CVE-2025-57833_test.svg)


## CVE-2025-52915
 K7RKScan.sys 23.0.0.10, part of the K7 Security Anti-Malware suite, allows an admin-privileged user to send crafted IOCTL requests to terminate processes that are protected through a third-party implementation. This is caused by insufficient caller validation in the driver's IOCTL handler, enabling unauthorized processes to perform those actions in kernel space. Successful exploitation can lead to denial of service by disrupting critical third-party services or applications.

- [https://github.com/BlackSnufkin/BYOVD](https://github.com/BlackSnufkin/BYOVD) :  ![starts](https://img.shields.io/github/stars/BlackSnufkin/BYOVD.svg) ![forks](https://img.shields.io/github/forks/BlackSnufkin/BYOVD.svg)
- [https://github.com/diego-tella/CVE-2025-1055-poc](https://github.com/diego-tella/CVE-2025-1055-poc) :  ![starts](https://img.shields.io/github/stars/diego-tella/CVE-2025-1055-poc.svg) ![forks](https://img.shields.io/github/forks/diego-tella/CVE-2025-1055-poc.svg)


## CVE-2025-48384
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When reading a config value, Git strips any trailing carriage return and line feed (CRLF). When writing a config entry, values with a trailing CR are not quoted, causing the CR to be lost when the config is later read. When initializing a submodule, if the submodule path contains a trailing CR, the altered path is read resulting in the submodule being checked out to an incorrect location. If a symlink exists that points the altered path to the submodule hooks directory, and the submodule contains an executable post-checkout hook, the script may be unintentionally executed after checkout. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.

- [https://github.com/EdwardYeIntrix/CVE-2025-48384-Scanner](https://github.com/EdwardYeIntrix/CVE-2025-48384-Scanner) :  ![starts](https://img.shields.io/github/stars/EdwardYeIntrix/CVE-2025-48384-Scanner.svg) ![forks](https://img.shields.io/github/forks/EdwardYeIntrix/CVE-2025-48384-Scanner.svg)


## CVE-2025-8889
 The Compress & Upload WordPress plugin before 1.0.5 does not properly validate uploaded files, allowing high privilege users such as admin to upload arbitrary files on the server even when they should not be allowed to (for example in multisite setup)

- [https://github.com/siberkampus/CVE-2025-8889](https://github.com/siberkampus/CVE-2025-8889) :  ![starts](https://img.shields.io/github/stars/siberkampus/CVE-2025-8889.svg) ![forks](https://img.shields.io/github/forks/siberkampus/CVE-2025-8889.svg)


## CVE-2025-8088
     from ESET.

- [https://github.com/SANJOY007/WinRAR-2025](https://github.com/SANJOY007/WinRAR-2025) :  ![starts](https://img.shields.io/github/stars/SANJOY007/WinRAR-2025.svg) ![forks](https://img.shields.io/github/forks/SANJOY007/WinRAR-2025.svg)


## CVE-2025-5752
 The Vertical scroll image slideshow gallery plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the ‘width’ parameter in all versions up to, and including, 11.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/onurcangnc/CVE-2025-57520-Stored-XSS-in-Decap-CMS-3.8.3-](https://github.com/onurcangnc/CVE-2025-57520-Stored-XSS-in-Decap-CMS-3.8.3-) :  ![starts](https://img.shields.io/github/stars/onurcangnc/CVE-2025-57520-Stored-XSS-in-Decap-CMS-3.8.3-.svg) ![forks](https://img.shields.io/github/forks/onurcangnc/CVE-2025-57520-Stored-XSS-in-Decap-CMS-3.8.3-.svg)


## CVE-2025-5739
 A vulnerability classified as critical has been found in TOTOLINK X15 1.0.0-B20230714.1105. This affects an unknown part of the file /boafrm/formSaveConfig of the component HTTP POST Request Handler. The manipulation of the argument submit-url leads to buffer overflow. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/meisterlos/CVE-2025-57392](https://github.com/meisterlos/CVE-2025-57392) :  ![starts](https://img.shields.io/github/stars/meisterlos/CVE-2025-57392.svg) ![forks](https://img.shields.io/github/forks/meisterlos/CVE-2025-57392.svg)


## CVE-2025-5095
password change to proceed without verifying the request's legitimacy.

- [https://github.com/TeteuXD2/CVE-2025-5095-POC](https://github.com/TeteuXD2/CVE-2025-5095-POC) :  ![starts](https://img.shields.io/github/stars/TeteuXD2/CVE-2025-5095-POC.svg) ![forks](https://img.shields.io/github/forks/TeteuXD2/CVE-2025-5095-POC.svg)


## CVE-2024-28397
 An issue in the component js2py.disable_pyimport() of js2py up to v0.74 allows attackers to execute arbitrary code via a crafted API call.

- [https://github.com/naclapor/CVE-2024-28397](https://github.com/naclapor/CVE-2024-28397) :  ![starts](https://img.shields.io/github/stars/naclapor/CVE-2024-28397.svg) ![forks](https://img.shields.io/github/forks/naclapor/CVE-2024-28397.svg)


## CVE-2023-36845
  *  23.2 versions prior to 23.2R1-S1, 23.2R2.

- [https://github.com/P4x1s/ansible-cve-2023-36845](https://github.com/P4x1s/ansible-cve-2023-36845) :  ![starts](https://img.shields.io/github/stars/P4x1s/ansible-cve-2023-36845.svg) ![forks](https://img.shields.io/github/forks/P4x1s/ansible-cve-2023-36845.svg)


## CVE-2023-33829
 A stored cross-site scripting (XSS) vulnerability in Cloudogu GmbH SCM Manager v1.2 to v1.60 allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the Description text field.

- [https://github.com/P4x1s/CVE-2023-33829-POC](https://github.com/P4x1s/CVE-2023-33829-POC) :  ![starts](https://img.shields.io/github/stars/P4x1s/CVE-2023-33829-POC.svg) ![forks](https://img.shields.io/github/forks/P4x1s/CVE-2023-33829-POC.svg)


## CVE-2023-33246
To prevent these attacks, users are recommended to upgrade to version 5.1.1 or above for using RocketMQ 5.x or 4.9.6 or above for using RocketMQ 4.x .

- [https://github.com/P4x1s/CVE-2023-33246](https://github.com/P4x1s/CVE-2023-33246) :  ![starts](https://img.shields.io/github/stars/P4x1s/CVE-2023-33246.svg) ![forks](https://img.shields.io/github/forks/P4x1s/CVE-2023-33246.svg)


## CVE-2023-29923
 PowerJob V4.3.1 is vulnerable to Insecure Permissions. via the list job interface.

- [https://github.com/P4x1s/CVE-2023-29923-Scan](https://github.com/P4x1s/CVE-2023-29923-Scan) :  ![starts](https://img.shields.io/github/stars/P4x1s/CVE-2023-29923-Scan.svg) ![forks](https://img.shields.io/github/forks/P4x1s/CVE-2023-29923-Scan.svg)


## CVE-2023-29922
 PowerJob V4.3.1 is vulnerable to Incorrect Access Control via the create user/save interface.

- [https://github.com/P4x1s/CVE-2023-29923-Scan](https://github.com/P4x1s/CVE-2023-29923-Scan) :  ![starts](https://img.shields.io/github/stars/P4x1s/CVE-2023-29923-Scan.svg) ![forks](https://img.shields.io/github/forks/P4x1s/CVE-2023-29923-Scan.svg)


## CVE-2023-22809
 In Sudo before 1.9.12p2, the sudoedit (aka -e) feature mishandles extra arguments passed in the user-provided environment variables (SUDO_EDITOR, VISUAL, and EDITOR), allowing a local attacker to append arbitrary entries to the list of files to process. This can lead to privilege escalation. Affected versions are 1.8.0 through 1.9.12.p1. The problem exists because a user-specified editor may contain a "--" argument that defeats a protection mechanism, e.g., an EDITOR='vim -- /path/to/extra/file' value.

- [https://github.com/P4x1s/CVE-2023-22809-sudo-POC](https://github.com/P4x1s/CVE-2023-22809-sudo-POC) :  ![starts](https://img.shields.io/github/stars/P4x1s/CVE-2023-22809-sudo-POC.svg) ![forks](https://img.shields.io/github/forks/P4x1s/CVE-2023-22809-sudo-POC.svg)


## CVE-2023-21768
 Windows Ancillary Function Driver for WinSock Elevation of Privilege Vulnerability

- [https://github.com/P4x1s/CVE-2023-21768-POC](https://github.com/P4x1s/CVE-2023-21768-POC) :  ![starts](https://img.shields.io/github/stars/P4x1s/CVE-2023-21768-POC.svg) ![forks](https://img.shields.io/github/forks/P4x1s/CVE-2023-21768-POC.svg)


## CVE-2023-21716
 Microsoft Word Remote Code Execution Vulnerability

- [https://github.com/P4x1s/CVE-2023-21716-POC](https://github.com/P4x1s/CVE-2023-21716-POC) :  ![starts](https://img.shields.io/github/stars/P4x1s/CVE-2023-21716-POC.svg) ![forks](https://img.shields.io/github/forks/P4x1s/CVE-2023-21716-POC.svg)


## CVE-2022-42475
 A heap-based buffer overflow vulnerability [CWE-122] in FortiOS SSL-VPN 7.2.0 through 7.2.2, 7.0.0 through 7.0.8, 6.4.0 through 6.4.10, 6.2.0 through 6.2.11, 6.0.15 and earlier  and FortiProxy SSL-VPN 7.2.0 through 7.2.1, 7.0.7 and earlier may allow a remote unauthenticated attacker to execute arbitrary code or commands via specifically crafted requests.

- [https://github.com/P4x1s/CVE-2022-42475-RCE-POC](https://github.com/P4x1s/CVE-2022-42475-RCE-POC) :  ![starts](https://img.shields.io/github/stars/P4x1s/CVE-2022-42475-RCE-POC.svg) ![forks](https://img.shields.io/github/forks/P4x1s/CVE-2022-42475-RCE-POC.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/cypherlobo/DirtyPipe-BSI](https://github.com/cypherlobo/DirtyPipe-BSI) :  ![starts](https://img.shields.io/github/stars/cypherlobo/DirtyPipe-BSI.svg) ![forks](https://img.shields.io/github/forks/cypherlobo/DirtyPipe-BSI.svg)


## CVE-2021-41278
 Functions SDK for EdgeX is meant to provide all the plumbing necessary for developers to get started in processing/transforming/exporting data out of the EdgeX IoT platform. In affected versions broken encryption in app-functions-sdk “AES” transform in EdgeX Foundry releases prior to Jakarta allows attackers to decrypt messages via unspecified vectors. The app-functions-sdk exports an “aes” transform that user scripts can optionally call to encrypt data in the processing pipeline. No decrypt function is provided. Encryption is not enabled by default, but if used, the level of protection may be less than the user may expects due to a broken implementation. Version v2.1.0 (EdgeX Foundry Jakarta release and later) of app-functions-sdk-go/v2 deprecates the “aes” transform and provides an improved “aes256” transform in its place. The broken implementation will remain in a deprecated state until it is removed in the next EdgeX major release to avoid breakage of existing software that depends on the broken implementation. As the broken transform is a library function that is not invoked by default, users who do not use the AES transform in their processing pipelines are unaffected. Those that are affected are urged to upgrade to the Jakarta EdgeX release and modify processing pipelines to use the new "aes256" transform.

- [https://github.com/FDlucifer/CVE-2021-41278](https://github.com/FDlucifer/CVE-2021-41278) :  ![starts](https://img.shields.io/github/stars/FDlucifer/CVE-2021-41278.svg) ![forks](https://img.shields.io/github/forks/FDlucifer/CVE-2021-41278.svg)


## CVE-2021-22210
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 13.2. When querying the repository branches through API, GitLab was ignoring a query parameter and returning a considerable amount of results.

- [https://github.com/Jeromeyoung/CVE-2021-22210](https://github.com/Jeromeyoung/CVE-2021-22210) :  ![starts](https://img.shields.io/github/stars/Jeromeyoung/CVE-2021-22210.svg) ![forks](https://img.shields.io/github/forks/Jeromeyoung/CVE-2021-22210.svg)


## CVE-2021-22205
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 11.9. GitLab was not properly validating image files that were passed to a file parser which resulted in a remote command execution.

- [https://github.com/Jeromeyoung/CVE-2021-22210](https://github.com/Jeromeyoung/CVE-2021-22210) :  ![starts](https://img.shields.io/github/stars/Jeromeyoung/CVE-2021-22210.svg) ![forks](https://img.shields.io/github/forks/Jeromeyoung/CVE-2021-22210.svg)


## CVE-2019-13272
 In the Linux kernel before 5.1.17, ptrace_link in kernel/ptrace.c mishandles the recording of the credentials of a process that wants to create a ptrace relationship, which allows local users to obtain root access by leveraging certain scenarios with a parent-child process relationship, where a parent drops privileges and calls execve (potentially allowing control by an attacker). One contributing factor is an object lifetime issue (which can also cause a panic). Another contributing factor is incorrect marking of a ptrace relationship as privileged, which is exploitable through (for example) Polkit's pkexec helper with PTRACE_TRACEME. NOTE: SELinux deny_ptrace might be a usable workaround in some environments.

- [https://github.com/Chinmay1743/ptrace-vuln](https://github.com/Chinmay1743/ptrace-vuln) :  ![starts](https://img.shields.io/github/stars/Chinmay1743/ptrace-vuln.svg) ![forks](https://img.shields.io/github/forks/Chinmay1743/ptrace-vuln.svg)


## CVE-2019-12102
 Kentico 11 through 12 lets attackers upload and explore files without authentication via the cmsmodules/medialibrary/formcontrols/liveselectors/insertimageormedia/tabs_media.aspx URI. NOTE: The vendor disputes the report because the researcher did not configure the media library permissions correctly. The vendor states that by default all users can read/modify/upload files, and it’s up to the administrator to decide who should have access to the media library and set the permissions accordingly. See the vendor documentation in the references for more information

- [https://github.com/Egi08/CVE-2019-12102-Scanner](https://github.com/Egi08/CVE-2019-12102-Scanner) :  ![starts](https://img.shields.io/github/stars/Egi08/CVE-2019-12102-Scanner.svg) ![forks](https://img.shields.io/github/forks/Egi08/CVE-2019-12102-Scanner.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/Slayerma/-CVE-2019-9053](https://github.com/Slayerma/-CVE-2019-9053) :  ![starts](https://img.shields.io/github/stars/Slayerma/-CVE-2019-9053.svg) ![forks](https://img.shields.io/github/forks/Slayerma/-CVE-2019-9053.svg)


## CVE-2018-15473
 OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user until after the packet containing the request has been fully parsed, related to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.

- [https://github.com/Alph4Sec/ssh_enum_py](https://github.com/Alph4Sec/ssh_enum_py) :  ![starts](https://img.shields.io/github/stars/Alph4Sec/ssh_enum_py.svg) ![forks](https://img.shields.io/github/forks/Alph4Sec/ssh_enum_py.svg)


## CVE-2018-5764
 The parse_arguments function in options.c in rsyncd in rsync before 3.1.3 does not prevent multiple --protect-args uses, which allows remote attackers to bypass an argument-sanitization protection mechanism.

- [https://github.com/waleedadam360-web/SyncShield](https://github.com/waleedadam360-web/SyncShield) :  ![starts](https://img.shields.io/github/stars/waleedadam360-web/SyncShield.svg) ![forks](https://img.shields.io/github/forks/waleedadam360-web/SyncShield.svg)


## CVE-2017-15944
 Palo Alto Networks PAN-OS before 6.1.19, 7.0.x before 7.0.19, 7.1.x before 7.1.14, and 8.0.x before 8.0.6 allows remote attackers to execute arbitrary code via vectors involving the management interface.

- [https://github.com/P4x1s/PaloAlto_EXP](https://github.com/P4x1s/PaloAlto_EXP) :  ![starts](https://img.shields.io/github/stars/P4x1s/PaloAlto_EXP.svg) ![forks](https://img.shields.io/github/forks/P4x1s/PaloAlto_EXP.svg)

