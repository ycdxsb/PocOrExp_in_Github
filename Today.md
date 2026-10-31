# Update 2026-10-31
## CVE-2026-115889
 Wasmtime is a runtime for WebAssembly. Prior to 36.0.19 and 43.0.0, the Cranelift compiler backend bit-packs SSA value indices in a way that can silently overflow in release builds when compiling a sufficiently large or specially crafted Wasm function with many SSA values. The overflow can make Cranelift reference incorrect IR values, causing arbitrary miscompilation, type confusion, and other attacker-controlled effects that may escape the Wasm sandbox on any architecture using the default Cranelift backend. This issue is fixed in versions 36.0.19 and 43.0.0.

- [https://github.com/mehmet-emir-eroglu/CVE-2026-115889](https://github.com/mehmet-emir-eroglu/CVE-2026-115889) :  ![starts](https://img.shields.io/github/stars/mehmet-emir-eroglu/CVE-2026-115889.svg) ![forks](https://img.shields.io/github/forks/mehmet-emir-eroglu/CVE-2026-115889.svg)


## CVE-2026-114625
Hosted, including Dedicated, versions of VCO were impacted and have already been patched.

- [https://github.com/mehmet-emir-eroglu/CVE-2026-114625](https://github.com/mehmet-emir-eroglu/CVE-2026-114625) :  ![starts](https://img.shields.io/github/stars/mehmet-emir-eroglu/CVE-2026-114625.svg) ![forks](https://img.shields.io/github/forks/mehmet-emir-eroglu/CVE-2026-114625.svg)


## CVE-2026-114595
 In EPICS Base release 7.0.10 and prior, an integer overflow in network request processing can cause memory to be allocated with an incorrect size. Subsequent handling of attacker supplied data may result in memory corruption, denial of service, or potential remote code execution.

- [https://github.com/0xredash/CVE-2026-114595](https://github.com/0xredash/CVE-2026-114595) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-114595.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-114595.svg)


## CVE-2026-114509
 Laravel is a web application framework. Prior to 12.68.0 and 13.29.0, TokenGuard configured as a standard token-based API guard does not reject a crafted non-string credential. Under affected MySQL or MariaDB configurations, the authentication lookup can match an unintended existing user, allowing an unauthenticated attacker to bypass authentication and take over an account on routes protected by TokenGuard. This issue is fixed in versions 12.68.0 and 13.29.0.

- [https://github.com/mehmet-emir-eroglu/CVE-2026-114509](https://github.com/mehmet-emir-eroglu/CVE-2026-114509) :  ![starts](https://img.shields.io/github/stars/mehmet-emir-eroglu/CVE-2026-114509.svg) ![forks](https://img.shields.io/github/forks/mehmet-emir-eroglu/CVE-2026-114509.svg)


## CVE-2026-114148
 Incorrect default permissions in ASP.NET Core allows an authorized attacker to elevate privileges locally.

- [https://github.com/Ghost-Bx1/DotNet-Tarball-CVE-2026-114148](https://github.com/Ghost-Bx1/DotNet-Tarball-CVE-2026-114148) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/DotNet-Tarball-CVE-2026-114148.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/DotNet-Tarball-CVE-2026-114148.svg)


## CVE-2026-113870
 MongoDB Compass improperly escapes certain BSON values when converting a stored view’s aggregation pipeline into editable source. When a user connects to a MongoDB deployment containing a specially crafted view and opens that view for editing, the values can cause arbitrary code to execute with the privileges of the user running Compass.

- [https://github.com/mehmet-emir-eroglu/CVE-2026-113870](https://github.com/mehmet-emir-eroglu/CVE-2026-113870) :  ![starts](https://img.shields.io/github/stars/mehmet-emir-eroglu/CVE-2026-113870.svg) ![forks](https://img.shields.io/github/forks/mehmet-emir-eroglu/CVE-2026-113870.svg)


## CVE-2026-113792
 pypdf is a free and open-source pure-python PDF library. Prior to 6.20.1, calling PdfWriter.find_outline_item on a crafted PDF with a cyclic outline hierarchy can enter an infinite loop and block the current process. This issue is fixed in version 6.20.1.

- [https://github.com/8hw3/pillow-uaf-research](https://github.com/8hw3/pillow-uaf-research) :  ![starts](https://img.shields.io/github/stars/8hw3/pillow-uaf-research.svg) ![forks](https://img.shields.io/github/forks/8hw3/pillow-uaf-research.svg)


## CVE-2026-112621
 An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in Safari 27.2, iOS 26.7.2 and iPadOS 26.7.2, iOS 27.2 and iPadOS 27.2, macOS Golden Gate 27.2, visionOS 27.2. Processing a maliciously crafted image may result in memory corruption.

- [https://github.com/Xplo8E/CVE-2026-112621-oob-write-poc](https://github.com/Xplo8E/CVE-2026-112621-oob-write-poc) :  ![starts](https://img.shields.io/github/stars/Xplo8E/CVE-2026-112621-oob-write-poc.svg) ![forks](https://img.shields.io/github/forks/Xplo8E/CVE-2026-112621-oob-write-poc.svg)
- [https://github.com/794pn2s6fh-hub/CVE-2026-112621-](https://github.com/794pn2s6fh-hub/CVE-2026-112621-) :  ![starts](https://img.shields.io/github/stars/794pn2s6fh-hub/CVE-2026-112621-.svg) ![forks](https://img.shields.io/github/forks/794pn2s6fh-hub/CVE-2026-112621-.svg)
- [https://github.com/Allen-ux-dev/cve-2026-112621-test](https://github.com/Allen-ux-dev/cve-2026-112621-test) :  ![starts](https://img.shields.io/github/stars/Allen-ux-dev/cve-2026-112621-test.svg) ![forks](https://img.shields.io/github/forks/Allen-ux-dev/cve-2026-112621-test.svg)


## CVE-2026-112396
 Pillow is a Python imaging library. From 11.3.0 until 13.0.0, Pillow has a heap use-after-free when libtiff rejects a tag while encoding TIFF data to an in-memory buffer. When an application saves attacker-influenced TIFF tags to BytesIO, libtiff can reject a tag during encoding in ImagingLibTiffEncode; the error path then frees the output buffer without closing or clearing the TIFF handle, and later cleanup flushes through the write callback into freed memory, which can crash the process and may enable code execution. This issue is fixed in version 13.0.0.

- [https://github.com/8hw3/pillow-uaf-research](https://github.com/8hw3/pillow-uaf-research) :  ![starts](https://img.shields.io/github/stars/8hw3/pillow-uaf-research.svg) ![forks](https://img.shields.io/github/forks/8hw3/pillow-uaf-research.svg)


## CVE-2026-111497
Users need to update any Brotli libraries or binaries between 1.0.3 through 1.2.0 to the latest available version: 1.0.10 or 1.1.1 or 1.2.1.

- [https://github.com/CompleteTech-Security/node2shell-check](https://github.com/CompleteTech-Security/node2shell-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/node2shell-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/node2shell-check.svg)
- [https://github.com/CompleteTech-Security/http2shell-check](https://github.com/CompleteTech-Security/http2shell-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/http2shell-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/http2shell-check.svg)
- [https://github.com/0xredash/CVE-2026-111497](https://github.com/0xredash/CVE-2026-111497) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-111497.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-111497.svg)
- [https://github.com/Sumit0x00/node2shell](https://github.com/Sumit0x00/node2shell) :  ![starts](https://img.shields.io/github/stars/Sumit0x00/node2shell.svg) ![forks](https://img.shields.io/github/forks/Sumit0x00/node2shell.svg)
- [https://github.com/fieldse/brotli-node2shell-check](https://github.com/fieldse/brotli-node2shell-check) :  ![starts](https://img.shields.io/github/stars/fieldse/brotli-node2shell-check.svg) ![forks](https://img.shields.io/github/forks/fieldse/brotli-node2shell-check.svg)
- [https://github.com/mehmet-emir-eroglu/CVE-2026-111497](https://github.com/mehmet-emir-eroglu/CVE-2026-111497) :  ![starts](https://img.shields.io/github/stars/mehmet-emir-eroglu/CVE-2026-111497.svg) ![forks](https://img.shields.io/github/forks/mehmet-emir-eroglu/CVE-2026-111497.svg)
- [https://github.com/RedSideSecurity/node2shell](https://github.com/RedSideSecurity/node2shell) :  ![starts](https://img.shields.io/github/stars/RedSideSecurity/node2shell.svg) ![forks](https://img.shields.io/github/forks/RedSideSecurity/node2shell.svg)
- [https://github.com/timosar/woff2shell](https://github.com/timosar/woff2shell) :  ![starts](https://img.shields.io/github/stars/timosar/woff2shell.svg) ![forks](https://img.shields.io/github/forks/timosar/woff2shell.svg)
- [https://github.com/foxcornlab/node2shell-inventory-scanner](https://github.com/foxcornlab/node2shell-inventory-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/node2shell-inventory-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/node2shell-inventory-scanner.svg)
- [https://github.com/sakai-sktech/brotli-check](https://github.com/sakai-sktech/brotli-check) :  ![starts](https://img.shields.io/github/stars/sakai-sktech/brotli-check.svg) ![forks](https://img.shields.io/github/forks/sakai-sktech/brotli-check.svg)


## CVE-2026-110912
 In DragonFly BSD through 6.4.2 before 4bb22ff, the ARP input handlers arpintr() and in_arpinput() (sys/netinet/if_ether.c) do not validate the hardware address length (ar_hln) and protocol address length (ar_pln) fields of incoming ARP packets. in_arpreply() then uses these attacker-controlled values as memcpy lengths when copying from kernel buffers that are only 6 and 4 bytes long, resulting in an out-of-bounds read of kernel heap and stack memory that is copied into the ARP reply sent back to the requester. An unauthenticated attacker on the adjacent network can use a single crafted ARP request to disclose up to roughly 250 bytes of each type of kernel memory, including kernel pointers. This is expected to be fixed in the 6.6 stable release when that is available.

- [https://github.com/0xredash/CVE-2026-110912](https://github.com/0xredash/CVE-2026-110912) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-110912.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-110912.svg)


## CVE-2026-110447
 Collabora Online Built-in CODE Server before 26.4.303 (richdocumentscode), a Nextcloud app, allows remote code execution, as exploited in the wild in September and October 2026, a different vulnerability than CVE-2025-66208. This is an OS command injection in proxy.php when the CODE server isn't running (e.g., the product was recently restarted). The vulnerability is not present in standalone Collabora Online servers; only this deployment with CODE Server is affected.

- [https://github.com/CyRouteWolf/cve-2026-110447-poc](https://github.com/CyRouteWolf/cve-2026-110447-poc) :  ![starts](https://img.shields.io/github/stars/CyRouteWolf/cve-2026-110447-poc.svg) ![forks](https://img.shields.io/github/forks/CyRouteWolf/cve-2026-110447-poc.svg)


## CVE-2026-110311
 Creating a draft release through the API returned an `assets` list that was built from a release without an ID, which matched every attachment that was not linked to a release. A user who could create a draft release in a repository therefore received the metadata (file name, UUID, upload time, size and download count) of issue and comment attachments of repositories they could not read, and of abandoned uploads.

- [https://github.com/akiraraikou36-hub/cve-2026-110311-gitea-lab](https://github.com/akiraraikou36-hub/cve-2026-110311-gitea-lab) :  ![starts](https://img.shields.io/github/stars/akiraraikou36-hub/cve-2026-110311-gitea-lab.svg) ![forks](https://img.shields.io/github/forks/akiraraikou36-hub/cve-2026-110311-gitea-lab.svg)


## CVE-2026-110264
 An issue has been discovered in GitLab CE/EE affecting all versions from 7.0 before 18.11.13, 19.0 before 19.0.10, 19.1 before 19.1.9, 19.2 before 19.2.9, 19.3 before 19.3.6, 19.4 before 19.4.3, and 19.5 before 19.5.1 that, under certain conditions, could have allowed an unauthenticated user to execute arbitrary code on the GitLab server due to integer overflow when compiling a specially crafted regular expression.

- [https://github.com/mehmet-emir-eroglu/CVE-2026-110264](https://github.com/mehmet-emir-eroglu/CVE-2026-110264) :  ![starts](https://img.shields.io/github/stars/mehmet-emir-eroglu/CVE-2026-110264.svg) ![forks](https://img.shields.io/github/forks/mehmet-emir-eroglu/CVE-2026-110264.svg)
- [https://github.com/murat-levi/gitlab-rce-toolkit](https://github.com/murat-levi/gitlab-rce-toolkit) :  ![starts](https://img.shields.io/github/stars/murat-levi/gitlab-rce-toolkit.svg) ![forks](https://img.shields.io/github/forks/murat-levi/gitlab-rce-toolkit.svg)


## CVE-2026-110200
 IBM Langflow OSS 1.0.0 through 1.12.4 could allow a remote authenticated attacker to obtain sensitive information due to cleartext storage of sensitive information.

- [https://github.com/rmhowe425/POC-CVE-2026-110200](https://github.com/rmhowe425/POC-CVE-2026-110200) :  ![starts](https://img.shields.io/github/stars/rmhowe425/POC-CVE-2026-110200.svg) ![forks](https://img.shields.io/github/forks/rmhowe425/POC-CVE-2026-110200.svg)


## CVE-2026-110063
 Improper link resolution before file access ('link following') in VM Inspector for Azure Virtual Machines allows an unauthorized attacker to elevate privileges over a network.

- [https://github.com/mehmet-emir-eroglu/CVE-2026-110063](https://github.com/mehmet-emir-eroglu/CVE-2026-110063) :  ![starts](https://img.shields.io/github/stars/mehmet-emir-eroglu/CVE-2026-110063.svg) ![forks](https://img.shields.io/github/forks/mehmet-emir-eroglu/CVE-2026-110063.svg)


## CVE-2026-109722
 JIT miscompilation in the JavaScript Engine: JIT component. This vulnerability was fixed in Firefox 158, Firefox ESR 115.43, Firefox ESR 153.5, Thunderbird 158, and Thunderbird 153.5.

- [https://github.com/Scyrix-LLC/CVE-2026-109722](https://github.com/Scyrix-LLC/CVE-2026-109722) :  ![starts](https://img.shields.io/github/stars/Scyrix-LLC/CVE-2026-109722.svg) ![forks](https://img.shields.io/github/forks/Scyrix-LLC/CVE-2026-109722.svg)


## CVE-2026-109619
 PHP has various global state that temporarily points into request memory. In some scenarios, global state may not be correctly reset, or may be repopulated after being reset. The global state may then refer to request memory even after it has been freed. Subsequent requests may read or branch on this stale state before it is fully initialized. Multiple strategies can trigger this condition and produce remote code execution (RCE).

- [https://github.com/CompleteTech-Security/php2shell-check](https://github.com/CompleteTech-Security/php2shell-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/php2shell-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/php2shell-check.svg)
- [https://github.com/mym0us3r/PHP2Shell-Detection-with-Wazuh](https://github.com/mym0us3r/PHP2Shell-Detection-with-Wazuh) :  ![starts](https://img.shields.io/github/stars/mym0us3r/PHP2Shell-Detection-with-Wazuh.svg) ![forks](https://img.shields.io/github/forks/mym0us3r/PHP2Shell-Detection-with-Wazuh.svg)
- [https://github.com/EQSTLab/CVE-2026-109619](https://github.com/EQSTLab/CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2026-109619.svg)


## CVE-2026-109618
 PHP uses longjmp() for out-of-memory (OOM) errors to exit the current context and abort handling of the request. Some contexts may not properly account for this scenario and leave request memory in an uninitialized state before performing an allocation. The subsequent request cleanup procedure may read or branch on this memory. Multiple OOM strategies can consistently trigger this condition and lead to remote code execution (RCE).

- [https://github.com/CompleteTech-Security/php2shell-check](https://github.com/CompleteTech-Security/php2shell-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/php2shell-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/php2shell-check.svg)
- [https://github.com/cseelhoff-ms/php2shell-hunting-pack](https://github.com/cseelhoff-ms/php2shell-hunting-pack) :  ![starts](https://img.shields.io/github/stars/cseelhoff-ms/php2shell-hunting-pack.svg) ![forks](https://img.shields.io/github/forks/cseelhoff-ms/php2shell-hunting-pack.svg)
- [https://github.com/seppegadeyne/php2shell-runcloud-builds](https://github.com/seppegadeyne/php2shell-runcloud-builds) :  ![starts](https://img.shields.io/github/stars/seppegadeyne/php2shell-runcloud-builds.svg) ![forks](https://img.shields.io/github/forks/seppegadeyne/php2shell-runcloud-builds.svg)


## CVE-2026-107329
 IBM Langflow OSS 1.0.0 through 1.12.4 could allow a remote authenticated attacker to execute arbitrary code due to improper control of code generation.

- [https://github.com/rmhowe425/POC-CVE-2026-107329](https://github.com/rmhowe425/POC-CVE-2026-107329) :  ![starts](https://img.shields.io/github/stars/rmhowe425/POC-CVE-2026-107329.svg) ![forks](https://img.shields.io/github/forks/rmhowe425/POC-CVE-2026-107329.svg)


## CVE-2026-107328
 IBM Langflow OSS 1.0.0 through 1.12.4 could allow a remote authenticated attacker to execute arbitrary code due to improper neutralization of code in eval/exec.

- [https://github.com/rmhowe425/POC-CVE-2026-107328](https://github.com/rmhowe425/POC-CVE-2026-107328) :  ![starts](https://img.shields.io/github/stars/rmhowe425/POC-CVE-2026-107328.svg) ![forks](https://img.shields.io/github/forks/rmhowe425/POC-CVE-2026-107328.svg)


## CVE-2026-107327
 IBM Langflow OSS 1.0.0 through 1.12.4 could allow a remote authenticated attacker to execute arbitrary code due to missing authorization.

- [https://github.com/rmhowe425/POC-CVE-2026-107327](https://github.com/rmhowe425/POC-CVE-2026-107327) :  ![starts](https://img.shields.io/github/stars/rmhowe425/POC-CVE-2026-107327.svg) ![forks](https://img.shields.io/github/forks/rmhowe425/POC-CVE-2026-107327.svg)


## CVE-2026-106173
 A improper limitation of a pathname to a restricted directory ('path traversal') vulnerability in Fortinet FortiSIEM 7.5.0 may allow attacker to execute unauthorized code or commands via specially crafted packets.

- [https://github.com/0xredash/CVE-2026-106173](https://github.com/0xredash/CVE-2026-106173) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-106173.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-106173.svg)


## CVE-2026-106074
This vulnerability affects Node.js **26.x**, **24.x**, and **22.x**.

- [https://github.com/CompleteTech-Security/node-cve-2026-106074-check](https://github.com/CompleteTech-Security/node-cve-2026-106074-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/node-cve-2026-106074-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/node-cve-2026-106074-check.svg)


## CVE-2026-106073
This vulnerability affects Node.js **26.x**, **24.x**, and **22.x**.

- [https://github.com/CompleteTech-Security/node-cve-2026-106073-check](https://github.com/CompleteTech-Security/node-cve-2026-106073-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/node-cve-2026-106073-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/node-cve-2026-106073-check.svg)


## CVE-2026-106072
This vulnerability affects Node.js **26.x**, **24.x**, and **22.x**.

- [https://github.com/CompleteTech-Security/node-cve-2026-106072-check](https://github.com/CompleteTech-Security/node-cve-2026-106072-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/node-cve-2026-106072-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/node-cve-2026-106072-check.svg)


## CVE-2026-106071
This vulnerability affects Node.js **26.x**.

- [https://github.com/CompleteTech-Security/node-cve-2026-106071-check](https://github.com/CompleteTech-Security/node-cve-2026-106071-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/node-cve-2026-106071-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/node-cve-2026-106071-check.svg)


## CVE-2026-106070
This vulnerability affects Node.js **26.x**.

- [https://github.com/CompleteTech-Security/node-cve-2026-106070-check](https://github.com/CompleteTech-Security/node-cve-2026-106070-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/node-cve-2026-106070-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/node-cve-2026-106070-check.svg)


## CVE-2026-106069
This vulnerability affects Node.js **26.x**, **24.x**, and **22.x**.

- [https://github.com/CompleteTech-Security/node-cve-2026-106069-check](https://github.com/CompleteTech-Security/node-cve-2026-106069-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/node-cve-2026-106069-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/node-cve-2026-106069-check.svg)


## CVE-2026-105483
This vulnerability affects Node.js **26.x** and **24.x**.

- [https://github.com/CompleteTech-Security/node-cve-2026-105483-check](https://github.com/CompleteTech-Security/node-cve-2026-105483-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/node-cve-2026-105483-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/node-cve-2026-105483-check.svg)


## CVE-2026-105482
This vulnerability affects Node.js 26.x, 24.x, and 22.x.

- [https://github.com/CompleteTech-Security/node-cve-2026-105482-check](https://github.com/CompleteTech-Security/node-cve-2026-105482-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/node-cve-2026-105482-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/node-cve-2026-105482-check.svg)


## CVE-2026-105481
This vulnerability affects Node.js **26.x**, **24.x**, and **22.x**.

- [https://github.com/CompleteTech-Security/node-cve-2026-105481-check](https://github.com/CompleteTech-Security/node-cve-2026-105481-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/node-cve-2026-105481-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/node-cve-2026-105481-check.svg)


## CVE-2026-105445
 An Incorrect Privilege Assignment vulnerability in Docker Hub's account-to-organization conversion feature allowed an authenticated attacker to reassign a personal access token (PAT) they controlled to another Docker Hub user without rotating or revoking the token secret. The unchanged PAT then authenticated to the registry as the recipient and could pull, push, or delete images, within its scopes, in repositories accessible to that user, including organization repositories.

- [https://github.com/CompleteTech-Security/docker-hub-ghostpat-check](https://github.com/CompleteTech-Security/docker-hub-ghostpat-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/docker-hub-ghostpat-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/docker-hub-ghostpat-check.svg)


## CVE-2026-105014
 Improper neutralization of special elements used in a command ('command injection') in Azure Pipelines allows an unauthorized attacker to execute code over a network.

- [https://github.com/mehmet-emir-eroglu/CVE-2026-105014](https://github.com/mehmet-emir-eroglu/CVE-2026-105014) :  ![starts](https://img.shields.io/github/stars/mehmet-emir-eroglu/CVE-2026-105014.svg) ![forks](https://img.shields.io/github/forks/mehmet-emir-eroglu/CVE-2026-105014.svg)


## CVE-2026-104935
 Authentication bypass by spoofing in ICS before version 25.1.3.0 allows a remote unauthenticated attacker to execute arbitrary commands. This does not impact ICS version 22.7R2.14 or prior.

- [https://github.com/CompleteTech-Security/ivanti-connect-secure-cve-2026-104935-check](https://github.com/CompleteTech-Security/ivanti-connect-secure-cve-2026-104935-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/ivanti-connect-secure-cve-2026-104935-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/ivanti-connect-secure-cve-2026-104935-check.svg)


## CVE-2026-104849
 Tinypool is a minimal Node.js worker thread pool implementation. Prior to 2.1.2, Tinypool reads filename from a caller-supplied options object in pool.run(task, options) without requiring an own property, so a polluted Object.prototype.filename can replace the intended worker module. Applications are affected only when they pass their own second-argument options object to pool.run(); calls without that argument use the trusted default options object. An attacker who can first pollute the prototype can cause the worker pool to load attacker-selected JavaScript and can read or modify task data with the host process's privileges. This issue is fixed in version 2.1.2.

- [https://github.com/CompleteTech-Security/tinypool-options-rce-check](https://github.com/CompleteTech-Security/tinypool-options-rce-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/tinypool-options-rce-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/tinypool-options-rce-check.svg)


## CVE-2026-104286
 An improper limitation of a pathname to a restricted directory ('path traversal') vulnerability in Fortinet FortiMail 8.0.0 through 8.0.1, FortiMail 7.6.0 through 7.6.6, FortiMail 7.4.0 through 7.4.8, FortiMail 7.2.0 through 7.2.9, FortiMail 7.0 all versions may allow an unauthenticated attacker to write arbitrary files on the underlying system via crafted HTTP or HTTPS requests.

- [https://github.com/maxprog-svg/CVE-2026-104286](https://github.com/maxprog-svg/CVE-2026-104286) :  ![starts](https://img.shields.io/github/stars/maxprog-svg/CVE-2026-104286.svg) ![forks](https://img.shields.io/github/forks/maxprog-svg/CVE-2026-104286.svg)
- [https://github.com/CompleteTech-Security/fortimail-cve-2026-104286-check](https://github.com/CompleteTech-Security/fortimail-cve-2026-104286-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/fortimail-cve-2026-104286-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/fortimail-cve-2026-104286-check.svg)


## CVE-2026-102826
 simple-git, an interface for running git commands in any node.js application, enables applications to execute Git operations from JavaScript. Prior to 4.0.0, the default blockUnsafeOperationsPlugin does not completely reject configuration includes supplied through customArgs to git.clone(). The missing include.path classification permits Git to load an attacker-controlled configuration file, and the initial remediation does not cover includeIf.condition.path, allowing the same file-loading primitive through a conditional include. A loaded configuration can set an executable Git option such as core.sshCommand, which Git invokes during the clone operation with the privileges of the Node.js process. Exploitation requires the application to pass attacker-influenced custom arguments and requires an attacker-controlled file that the process can read. This issue is fixed in 4.0.0.

- [https://github.com/CompleteTech-Security/simple-git-rce-check](https://github.com/CompleteTech-Security/simple-git-rce-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/simple-git-rce-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/simple-git-rce-check.svg)


## CVE-2026-102764
 The vulnerability exists within internal components of BeyondTrust’s Remote Support product. The components did not adequately validate the origin of the messages it received. Under the right conditions, this could allow an attacker to perform file operations on the appliance.

- [https://github.com/CompleteTech-Security/beyondtrust-remote-support-cve-2026-102764-check](https://github.com/CompleteTech-Security/beyondtrust-remote-support-cve-2026-102764-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/beyondtrust-remote-support-cve-2026-102764-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/beyondtrust-remote-support-cve-2026-102764-check.svg)


## CVE-2026-102258
 Post-authentication Stored Cross-Site Scripting (XSS) vulnerability has been identified in the SMA1000 Appliance Management Console (AMC) which in specific conditions could potentially enable a remote authenticated attacker as administrator to store and potentially execute arbitrary JavaScript code in the Appliance Management Console (AMC).

- [https://github.com/CompleteTech-Security/sonicwall-sma1000-cve-2026-102258-check](https://github.com/CompleteTech-Security/sonicwall-sma1000-cve-2026-102258-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/sonicwall-sma1000-cve-2026-102258-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/sonicwall-sma1000-cve-2026-102258-check.svg)


## CVE-2026-102257
 A Zip Slip vulnerability in the in the SMA1000 Appliance Management Console (AMC) interface allows an attacker to extract files outside the intended destination directory using a specially crafted archive, resulting in remote code execution.

- [https://github.com/CompleteTech-Security/sonicwall-sma1000-cve-2026-102257-check](https://github.com/CompleteTech-Security/sonicwall-sma1000-cve-2026-102257-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/sonicwall-sma1000-cve-2026-102257-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/sonicwall-sma1000-cve-2026-102257-check.svg)


## CVE-2026-102256
 Post-authentication Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') vulnerability has been identified in the SMA1000 appliance which in specific conditions could potentially enable a remote authenticated attacker as administrator to execute arbitrary OS commands, resulting in remote code execution.

- [https://github.com/CompleteTech-Security/sonicwall-sma1000-cve-2026-102256-check](https://github.com/CompleteTech-Security/sonicwall-sma1000-cve-2026-102256-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/sonicwall-sma1000-cve-2026-102256-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/sonicwall-sma1000-cve-2026-102256-check.svg)


## CVE-2026-102255
 A Pre-authentication SSRF vulnerability exists in the SMA1000 Appliance Work Place interface due to an unintended alternate access path. By abusing this path, a remote unauthenticated attacker could potentially exploit this vulnerability to direct the appliance to issue requests on their behalf and reach internal functionality and perform unauthorized operations.

- [https://github.com/CompleteTech-Security/sonicwall-sma1000-cve-2026-102255-check](https://github.com/CompleteTech-Security/sonicwall-sma1000-cve-2026-102255-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/sonicwall-sma1000-cve-2026-102255-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/sonicwall-sma1000-cve-2026-102255-check.svg)


## CVE-2026-101767
 Vulnerability in the Oracle Application Object Library product of Oracle E-Business Suite (component: Core).  Supported versions that are affected are 12.2.3-12.2.15. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Application Object Library.  Successful attacks of this vulnerability can result in takeover of Oracle Application Object Library. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/0xredash/CVE-2026-101767](https://github.com/0xredash/CVE-2026-101767) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-101767.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-101767.svg)


## CVE-2026-101259
Users are recommended to upgrade to version 4.23.0, which fixes the issue. If users are on the 4.22.x releases stream, then they are suggested to upgrade to 4.22.2. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.5. The 4.14.x releases stream and earlier, and the 4.15.x to 4.17.x and 4.19.x to 4.21.x release lines, reached end of life before this issue was resolved and will not receive a fix, so deployments on them must move to a supported release. The upgrade is enough on its own: the new muteException consumer option defaults to true on all three fixed release lines, so the error response carries no payload without any configuration change. For deployments that cannot upgrade immediately, make sure the response can always be built once the route has completed: convert the body to byte[] or String as the last step of each route that consumes from a coap endpoint, for example with convertBodyTo, give the CamelCoapMaxAge and CamelCoapETag headers only values of their own types, and add an onException handler that marks the failure as handled and sets the response body explicitly, so that a conversion failure is raised and replaced inside the route rather than in the consumer.

- [https://github.com/oscerd/CVE-2026-101259](https://github.com/oscerd/CVE-2026-101259) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-101259.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-101259.svg)


## CVE-2026-99999
A more complete validation at input is forthcoming, but needs more work.

- [https://github.com/nsrg-fmlorg/kpatch-cve-2026-98432](https://github.com/nsrg-fmlorg/kpatch-cve-2026-98432) :  ![starts](https://img.shields.io/github/stars/nsrg-fmlorg/kpatch-cve-2026-98432.svg) ![forks](https://img.shields.io/github/forks/nsrg-fmlorg/kpatch-cve-2026-98432.svg)


## CVE-2026-98432
will be addressed in a separate patch.

- [https://github.com/axisops/CVE-2026-98432](https://github.com/axisops/CVE-2026-98432) :  ![starts](https://img.shields.io/github/stars/axisops/CVE-2026-98432.svg) ![forks](https://img.shields.io/github/forks/axisops/CVE-2026-98432.svg)
- [https://github.com/mahdi-salmanzade/CVE-2026-98432](https://github.com/mahdi-salmanzade/CVE-2026-98432) :  ![starts](https://img.shields.io/github/stars/mahdi-salmanzade/CVE-2026-98432.svg) ![forks](https://img.shields.io/github/forks/mahdi-salmanzade/CVE-2026-98432.svg)
- [https://github.com/H1z3-br0/CVE-2026-98432](https://github.com/H1z3-br0/CVE-2026-98432) :  ![starts](https://img.shields.io/github/stars/H1z3-br0/CVE-2026-98432.svg) ![forks](https://img.shields.io/github/forks/H1z3-br0/CVE-2026-98432.svg)
- [https://github.com/suominen/CVE-2026-98432](https://github.com/suominen/CVE-2026-98432) :  ![starts](https://img.shields.io/github/stars/suominen/CVE-2026-98432.svg) ![forks](https://img.shields.io/github/forks/suominen/CVE-2026-98432.svg)
- [https://github.com/typhoon1217/cve-2026-98432-mitigation](https://github.com/typhoon1217/cve-2026-98432-mitigation) :  ![starts](https://img.shields.io/github/stars/typhoon1217/cve-2026-98432-mitigation.svg) ![forks](https://img.shields.io/github/forks/typhoon1217/cve-2026-98432-mitigation.svg)
- [https://github.com/paulwouters/block_cve_2026_98432](https://github.com/paulwouters/block_cve_2026_98432) :  ![starts](https://img.shields.io/github/stars/paulwouters/block_cve_2026_98432.svg) ![forks](https://img.shields.io/github/forks/paulwouters/block_cve_2026_98432.svg)
- [https://github.com/Quaerendir/cve-2026-98432-audit](https://github.com/Quaerendir/cve-2026-98432-audit) :  ![starts](https://img.shields.io/github/stars/Quaerendir/cve-2026-98432-audit.svg) ![forks](https://img.shields.io/github/forks/Quaerendir/cve-2026-98432-audit.svg)
- [https://github.com/nsrg-fmlorg/kpatch-cve-2026-98432](https://github.com/nsrg-fmlorg/kpatch-cve-2026-98432) :  ![starts](https://img.shields.io/github/stars/nsrg-fmlorg/kpatch-cve-2026-98432.svg) ![forks](https://img.shields.io/github/forks/nsrg-fmlorg/kpatch-cve-2026-98432.svg)
- [https://github.com/techtaek77/ubuntu-tcp-guide](https://github.com/techtaek77/ubuntu-tcp-guide) :  ![starts](https://img.shields.io/github/stars/techtaek77/ubuntu-tcp-guide.svg) ![forks](https://img.shields.io/github/forks/techtaek77/ubuntu-tcp-guide.svg)
- [https://github.com/maxigentr/netviser-linux-security-auditor](https://github.com/maxigentr/netviser-linux-security-auditor) :  ![starts](https://img.shields.io/github/stars/maxigentr/netviser-linux-security-auditor.svg) ![forks](https://img.shields.io/github/forks/maxigentr/netviser-linux-security-auditor.svg)


## CVE-2026-98260
[ tglx: Move the cleanup right after de_thread() ]

- [https://github.com/Yunnijian/OnePlus16-Jailbreak](https://github.com/Yunnijian/OnePlus16-Jailbreak) :  ![starts](https://img.shields.io/github/stars/Yunnijian/OnePlus16-Jailbreak.svg) ![forks](https://img.shields.io/github/forks/Yunnijian/OnePlus16-Jailbreak.svg)
- [https://github.com/simayang01/CVE-2026-98260-vivo-x-fold6-poc](https://github.com/simayang01/CVE-2026-98260-vivo-x-fold6-poc) :  ![starts](https://img.shields.io/github/stars/simayang01/CVE-2026-98260-vivo-x-fold6-poc.svg) ![forks](https://img.shields.io/github/forks/simayang01/CVE-2026-98260-vivo-x-fold6-poc.svg)
- [https://github.com/Feiman55/CVE-2026-98260-GhostKey](https://github.com/Feiman55/CVE-2026-98260-GhostKey) :  ![starts](https://img.shields.io/github/stars/Feiman55/CVE-2026-98260-GhostKey.svg) ![forks](https://img.shields.io/github/forks/Feiman55/CVE-2026-98260-GhostKey.svg)
- [https://github.com/AzirX1337/CVE-2026-98260-PMX110-Root618-Jailbreak](https://github.com/AzirX1337/CVE-2026-98260-PMX110-Root618-Jailbreak) :  ![starts](https://img.shields.io/github/stars/AzirX1337/CVE-2026-98260-PMX110-Root618-Jailbreak.svg) ![forks](https://img.shields.io/github/forks/AzirX1337/CVE-2026-98260-PMX110-Root618-Jailbreak.svg)
- [https://github.com/quyicheng03-boop/CVE-2026-98260-dada-android](https://github.com/quyicheng03-boop/CVE-2026-98260-dada-android) :  ![starts](https://img.shields.io/github/stars/quyicheng03-boop/CVE-2026-98260-dada-android.svg) ![forks](https://img.shields.io/github/forks/quyicheng03-boop/CVE-2026-98260-dada-android.svg)


## CVE-2026-97798
 Improper neutralization of argument delimiters in a command ('argument injection') in Windows Error Reporting allows an authorized attacker to elevate privileges locally.

- [https://github.com/j0wii/CVE-2026-97798_LPE_Windows](https://github.com/j0wii/CVE-2026-97798_LPE_Windows) :  ![starts](https://img.shields.io/github/stars/j0wii/CVE-2026-97798_LPE_Windows.svg) ![forks](https://img.shields.io/github/forks/j0wii/CVE-2026-97798_LPE_Windows.svg)


## CVE-2026-97785
 Improper authentication in AAD App Proxy allows an unauthorized attacker to elevate privileges over a network.

- [https://github.com/mehmet-emir-eroglu/CVE-2026-97785](https://github.com/mehmet-emir-eroglu/CVE-2026-97785) :  ![starts](https://img.shields.io/github/stars/mehmet-emir-eroglu/CVE-2026-97785.svg) ![forks](https://img.shields.io/github/forks/mehmet-emir-eroglu/CVE-2026-97785.svg)


## CVE-2026-97631
and Availability.

- [https://github.com/RayanZiani/Bootjack](https://github.com/RayanZiani/Bootjack) :  ![starts](https://img.shields.io/github/stars/RayanZiani/Bootjack.svg) ![forks](https://img.shields.io/github/forks/RayanZiani/Bootjack.svg)


## CVE-2026-97555
   allocated 884-byte region [ffff8881a5e25000, ffff8881a5e25374)

- [https://github.com/woshigenm/CVE-2026-97555](https://github.com/woshigenm/CVE-2026-97555) :  ![starts](https://img.shields.io/github/stars/woshigenm/CVE-2026-97555.svg) ![forks](https://img.shields.io/github/forks/woshigenm/CVE-2026-97555.svg)


## CVE-2026-97229
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 19.2 before 19.2.8, 19.3 before 19.3.5, and 19.4 before 19.4.2 that, under certain conditions, could have allowed an unauthenticated user to execute arbitrary code on the GitLab server via a specially crafted regular expression in a CI/CD configuration, due to insufficient regular expression validation.

- [https://github.com/murat-levi/gitlab-rce-toolkit](https://github.com/murat-levi/gitlab-rce-toolkit) :  ![starts](https://img.shields.io/github/stars/murat-levi/gitlab-rce-toolkit.svg) ![forks](https://img.shields.io/github/forks/murat-levi/gitlab-rce-toolkit.svg)


## CVE-2026-96889
 A flaw was found in librsvg. When processing an SVG document containing nested XML inclusions (Xincludes) with duplicate entity declarations, a use-after-free error can occur. This vulnerability arises because the library incorrectly frees an XML entity that is still in use by the parser. An attacker could potentially exploit this to cause a denial of service or execute arbitrary code.

- [https://github.com/CompleteTech-Security/sharp-vectorfreed-check](https://github.com/CompleteTech-Security/sharp-vectorfreed-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/sharp-vectorfreed-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/sharp-vectorfreed-check.svg)


## CVE-2026-95664
Users are recommended to upgrade to version 4.23.0, which fixes the issue. If users are on the 4.22.x releases stream, then they are suggested to upgrade to 4.22.2. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.5. The 4.8.x to 4.17.x and 4.19.x to 4.21.x release lines reached end of life before this issue was resolved and will not receive a fix, so deployments on them must move to a supported release. After upgrading, a key or bucket name supplied through a message header is used literally, so a route that put an unevaluated Simple expression in the CamelAwsS3Key or CamelAwsS3OverrideBucketName header must evaluate it in the route instead, for example with setHeader and simple(), or configure it as the keyName or bucketName option of the endpoint. For deployments that cannot upgrade immediately, do not let a key derived from an object name or from other untrusted message content reach an aws2-s3 producer unchecked: in routes that pass exchanges from an aws2-s3 consumer to an aws2-s3 producer, either remove the CamelAwsS3Key header before the producer with removeHeader(“CamelAwsS3Key”), so that the keyName configured on the endpoint is used, or reject exchanges whose CamelAwsS3Key header contains ${ or $simple{. Configuring keyName alone is not a workaround, because the header takes precedence over it. As defence in depth, allow only trusted principals to write to buckets that Camel routes consume.

- [https://github.com/oscerd/CVE-2026-95664](https://github.com/oscerd/CVE-2026-95664) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-95664.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-95664.svg)


## CVE-2026-95663
Users are recommended to upgrade to version 4.23.0, which fixes the issue. If users are on the 4.22.x releases stream, then they are suggested to upgrade to 4.22.2. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.5. The 4.16.x, 4.17.x and 4.19.x to 4.21.x release lines reached end of life before this issue was resolved and will not receive a fix, so deployments on them must move to a supported release. For deployments that cannot upgrade immediately, set introspectionCacheEnabled=false on the KeycloakSecurityPolicy, so that every request is checked against the introspection endpoint, which reports an expired token as inactive, at the cost of one introspection call per request. Lowering introspectionCacheTtl only narrows the window and does not close it.

- [https://github.com/oscerd/CVE-2026-95663](https://github.com/oscerd/CVE-2026-95663) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-95663.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-95663.svg)


## CVE-2026-95629
Users are recommended to upgrade to version 4.23.0, which fixes the issue. If users are on the 4.22.x releases stream, then they are suggested to upgrade to 4.22.2. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.5. The fix adds an outputBaseDirectory endpoint option that is unset by default, so after upgrading, set it on every docling endpoint whose CamelDoclingOutputFilePath header can carry a value influenced from outside the deployment; without it the header is normalized but can still name any directory. The 4.15.x to 4.17.x and 4.19.x to 4.21.x release lines reached end of life before this issue was resolved and will not receive a fix, so deployments on them must move to a supported release. For deployments that cannot upgrade immediately, do not build the CamelDoclingOutputFilePath header from values that originate outside the deployment, remove that header from messages that arrive from outside before they reach a docling endpoint, and make sure that consumers which map incoming message headers drop the Camel header namespace, so that only the route itself chooses the output directory.

- [https://github.com/oscerd/CVE-2026-95629](https://github.com/oscerd/CVE-2026-95629) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-95629.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-95629.svg)


## CVE-2026-95628
Users are recommended to upgrade to version 4.23.0, which fixes the issue. If users are on the 4.22.x releases stream, then they are suggested to upgrade to 4.22.2. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.5. The 4.15.x to 4.17.x and 4.19.x to 4.21.x release lines reached end of life before this issue was resolved and will not receive a fix, so deployments on them must move to a supported release. For deployments that cannot upgrade immediately, do not build the CamelDoclingCustomArguments header from values that originate outside the deployment, remove that header from messages that arrive from outside before they reach a docling endpoint, and make sure that consumers which map incoming message headers drop the Camel header namespace, so that only the route itself chooses the custom arguments.

- [https://github.com/oscerd/CVE-2026-95628](https://github.com/oscerd/CVE-2026-95628) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-95628.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-95628.svg)


## CVE-2026-94386
Users are recommended to upgrade to version 4.23.0, which fixes the issue. If users are on the 4.22.x releases stream, then they are suggested to upgrade to 4.22.2. The 4.19.x to 4.21.x release lines reached end of life before this issue was resolved and will not receive a fix, so deployments on them must move to a supported release. For deployments that cannot upgrade immediately, disable token caching on every OAuth profile that shares a token endpoint and client ID with another profile, by setting camel.oauth.NAME.cache-tokens=false for a named profile or camel.oauth.cache-tokens=false for the default one, so that each resolution requests a token with that profile’s own scope and client secret, at the cost of a token request on every resolution. Alternatively, register a separate client at the identity provider for each profile that needs a different scope or client secret, so that no two such profiles share a client ID.

- [https://github.com/oscerd/CVE-2026-94386](https://github.com/oscerd/CVE-2026-94386) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-94386.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-94386.svg)


## CVE-2026-94300
This issue affects BIND 9 versions 9.11.0 through 9.18.50, 9.20.0 through 9.20.29, 9.21.0 through 9.21.26, 9.11.3-S1 through 9.18.50-S1, and 9.20.9-S1 through 9.20.29-S1.

- [https://github.com/mehmet-emir-eroglu/CVE-2026-94300](https://github.com/mehmet-emir-eroglu/CVE-2026-94300) :  ![starts](https://img.shields.io/github/stars/mehmet-emir-eroglu/CVE-2026-94300.svg) ![forks](https://img.shields.io/github/forks/mehmet-emir-eroglu/CVE-2026-94300.svg)


## CVE-2026-93680
 IBM Langflow OSS 1.0.0 through 1.12.8 could allow a remote attacker to bypass security restrictions due to improper authentication.

- [https://github.com/rmhowe425/POC-CVE-2026-93680](https://github.com/rmhowe425/POC-CVE-2026-93680) :  ![starts](https://img.shields.io/github/stars/rmhowe425/POC-CVE-2026-93680.svg) ![forks](https://img.shields.io/github/forks/rmhowe425/POC-CVE-2026-93680.svg)


## CVE-2026-93485
 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Automattic WordPress wordpress allows DOM-Based XSS.This issue affects WordPress: from n/a through 7.1.

- [https://github.com/0xredash/CVE-2026-93485](https://github.com/0xredash/CVE-2026-93485) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-93485.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-93485.svg)


## CVE-2026-92935
 vm2 is a sandbox for running untrusted Node.js code. In versions = 3.11.4 and = 3.11.6, the NodeVM constructor computes `hasRealRequireConfig` with `typeof requireOpts === 'object' && requireOpts !== null`, so an array-shaped `require` value (for example `require: []`) satisfies the guard that is meant to reject nesting without an explicit require configuration. `makeResolverFromLegacyOptions()` then destructures the array into undefined option fields and returns a resolver containing only `NESTING_OVERRIDE.vm2`. As a result, an attacker who can supply JavaScript executed by a NodeVM configured with truthy `nesting` and an array-shaped `require` (e.g. `new NodeVM({nesting: true, require: []})`) can require the host `vm2` module, create an inner NodeVM with an attacker-chosen builtin allowlist (such as `child_process`), and execute arbitrary commands with the privileges of the host Node.js process, escaping the sandbox. Outer builtin restrictions do not constrain the attacker-created inner NodeVM. This issue is fixed in vm2 3.11.7.

- [https://github.com/CompleteTech-Security/vm2-nesting-check](https://github.com/CompleteTech-Security/vm2-nesting-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/vm2-nesting-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/vm2-nesting-check.svg)


## CVE-2026-92424
 The Content Egg  WordPress plugin before 11.9.0 does not verify that a user running its bulk content-import feature is authorized for the import preset they select, and switches to the preset author's identity before creating the resulting post, allowing users with contributor-level access and above to store arbitrary web scripts unfiltered under a privileged user's account, executing in the context of anyone who later views that content.

- [https://github.com/aymencdm/cve-2026-92424-content-egg-stored-xss-](https://github.com/aymencdm/cve-2026-92424-content-egg-stored-xss-) :  ![starts](https://img.shields.io/github/stars/aymencdm/cve-2026-92424-content-egg-stored-xss-.svg) ![forks](https://img.shields.io/github/forks/aymencdm/cve-2026-92424-content-egg-stored-xss-.svg)


## CVE-2026-91403
 Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: JSSE).  Supported versions that are affected are Oracle Java SE: 8u511, 8u511-perf, 11.0.33, 17.0.21, 21.0.13, 25.0.5, 27.0.1; Oracle GraalVM for JDK: 17.0.21 and  21.0.13; Oracle GraalVM Enterprise Edition: 21.3.20. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data as well as  unauthorized access to critical data or complete access to all Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability can be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. This vulnerability also applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. CVSS 3.1 Base Score 9.1 (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N).

- [https://github.com/mehmet-emir-eroglu/CVE-2026-91403](https://github.com/mehmet-emir-eroglu/CVE-2026-91403) :  ![starts](https://img.shields.io/github/stars/mehmet-emir-eroglu/CVE-2026-91403.svg) ![forks](https://img.shields.io/github/forks/mehmet-emir-eroglu/CVE-2026-91403.svg)


## CVE-2026-90885
Users are recommended to upgrade to version 4.23.0, which fixes the issue. If users are on the 4.22.x releases stream, then they are suggested to upgrade to 4.22.2. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.5. The 4.14.x releases stream and earlier, as well as the 4.15.x to 4.17.x and 4.19.x to 4.21.x release lines, reached end of life before this issue was resolved and will not receive a fix, so deployments on them must move to a supported release. For deployments that cannot upgrade immediately, do not evaluate XQuery over a message body that is already a javax.xml.transform.Source when that body carries XML from an untrusted sender, or set the configuration option of the xquery endpoint or language to a Saxon Configuration whose parse options refuse a DOCTYPE declaration and disable external entities and external DTD loading, which is what the fixed releases now apply by default.

- [https://github.com/oscerd/CVE-2026-90885](https://github.com/oscerd/CVE-2026-90885) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-90885.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-90885.svg)


## CVE-2026-89035
 MikroTik RouterOS through 7.24.5 contains a session token replay vulnerability in the WebFig interface that allows attackers to bypass authentication by replaying captured session tokens across new ECDH sessions. The makeSessionKey function in libucrypto.so generates tokens using fixed salts without incorporating channel-specific or session-specific input, and the user service validates tokens against the login store without verifying channel context, enabling stolen tokens to grant persistent administrative access until the token store is explicitly cleared. This vulnerability extends the impact of CVE-2025-61481, which identified the underlying transport-layer exposure without a corresponding fix.

- [https://github.com/mehmet-emir-eroglu/CVE-2026-89035](https://github.com/mehmet-emir-eroglu/CVE-2026-89035) :  ![starts](https://img.shields.io/github/stars/mehmet-emir-eroglu/CVE-2026-89035.svg) ![forks](https://img.shields.io/github/forks/mehmet-emir-eroglu/CVE-2026-89035.svg)


## CVE-2026-88804
 An unauthenticated update of public UI settings could be used by remote attackers to execute a stored cross-site scripting attack in the Rancher UI, in SUSE Rancher 2.15 before 2.15.2, 2.14 before 2.14.6, 2.13 before 2.13.10, 2.12 before 2.12.14 and 2.11 before 2.11.18.

- [https://github.com/R0gfall/CVE-2026-88804](https://github.com/R0gfall/CVE-2026-88804) :  ![starts](https://img.shields.io/github/stars/R0gfall/CVE-2026-88804.svg) ![forks](https://img.shields.io/github/forks/R0gfall/CVE-2026-88804.svg)


## CVE-2026-88778
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23.

- [https://github.com/CompleteTech-Security/netscaler-cve-2026-88778-check](https://github.com/CompleteTech-Security/netscaler-cve-2026-88778-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/netscaler-cve-2026-88778-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/netscaler-cve-2026-88778-check.svg)


## CVE-2026-88777
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23  leading to unpredictable or erroneous behavior or Denial of Service

- [https://github.com/CompleteTech-Security/netscaler-cve-2026-88777-check](https://github.com/CompleteTech-Security/netscaler-cve-2026-88777-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/netscaler-cve-2026-88777-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/netscaler-cve-2026-88777-check.svg)


## CVE-2026-88776
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23  leading to unpredictable or erroneous behavior or Denial of Service

- [https://github.com/CompleteTech-Security/netscaler-cve-2026-88776-check](https://github.com/CompleteTech-Security/netscaler-cve-2026-88776-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/netscaler-cve-2026-88776-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/netscaler-cve-2026-88776-check.svg)


## CVE-2026-88775
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23 leading Memory overflow vulnerability leading to unpredictable or erroneous behavior or Denial of Service

- [https://github.com/CompleteTech-Security/netscaler-cve-2026-88775-check](https://github.com/CompleteTech-Security/netscaler-cve-2026-88775-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/netscaler-cve-2026-88775-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/netscaler-cve-2026-88775-check.svg)


## CVE-2026-88774
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23 leading to a feature policy bypass due to improper HTTP URL based expression usage.

- [https://github.com/CompleteTech-Security/netscaler-cve-2026-88774-check](https://github.com/CompleteTech-Security/netscaler-cve-2026-88774-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/netscaler-cve-2026-88774-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/netscaler-cve-2026-88774-check.svg)


## CVE-2026-88773
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1-37.279 and NDcPP; Gateway: before 14.1-73.37 FIPS and before 13.1-64.23.

- [https://github.com/CompleteTech-Security/netscaler-cve-2026-88773-check](https://github.com/CompleteTech-Security/netscaler-cve-2026-88773-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/netscaler-cve-2026-88773-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/netscaler-cve-2026-88773-check.svg)


## CVE-2026-88772
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23 leading to Remote Code Execution or Denial of Service

- [https://github.com/CompleteTech-Security/netscaler-pitscaler-cve-2026-88772-check](https://github.com/CompleteTech-Security/netscaler-pitscaler-cve-2026-88772-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/netscaler-pitscaler-cve-2026-88772-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/netscaler-pitscaler-cve-2026-88772-check.svg)


## CVE-2026-88771
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23 leading to an unauthenticated attacker to execute arbitrary commands.

- [https://github.com/CompleteTech-Security/netscaler-pitscaler-cve-2026-88771-check](https://github.com/CompleteTech-Security/netscaler-pitscaler-cve-2026-88771-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/netscaler-pitscaler-cve-2026-88771-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/netscaler-pitscaler-cve-2026-88771-check.svg)


## CVE-2026-86950
 An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in iOS 18.7.11 and iPadOS 18.7.11, iOS 26.7.1 and iPadOS 26.7.1, macOS Sequoia 15.8.1, macOS Tahoe 26.7.1. Processing a maliciously crafted file may lead to arbitrary code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 27.

- [https://github.com/0xredash/CVE-2026-86950](https://github.com/0xredash/CVE-2026-86950) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-86950.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-86950.svg)


## CVE-2026-83938
 Missing authentication for critical function in Azure Kubernetes Configuration Service allows an unauthorized attacker to elevate privileges over a network.

- [https://github.com/mehmet-emir-eroglu/CVE-2026-83938](https://github.com/mehmet-emir-eroglu/CVE-2026-83938) :  ![starts](https://img.shields.io/github/stars/mehmet-emir-eroglu/CVE-2026-83938.svg) ![forks](https://img.shields.io/github/forks/mehmet-emir-eroglu/CVE-2026-83938.svg)


## CVE-2026-81000
other allocation paths.

- [https://github.com/0xredash/CVE-2026-81000](https://github.com/0xredash/CVE-2026-81000) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-81000.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-81000.svg)


## CVE-2026-80844
errors to the existing AH6 input and output error paths.

- [https://github.com/0xredash/CVE-2026-80844](https://github.com/0xredash/CVE-2026-80844) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-80844.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-80844.svg)


## CVE-2026-76475
The vulnerabilities tracked by CVE-2026-76475 are related to issues concerning improper neutralization of input during web page generation that are grouped under the Common Weakness Enumeration (CWE) Base CWE-79.

- [https://github.com/mehmet-emir-eroglu/CVE-2026-76475](https://github.com/mehmet-emir-eroglu/CVE-2026-76475) :  ![starts](https://img.shields.io/github/stars/mehmet-emir-eroglu/CVE-2026-76475.svg) ![forks](https://img.shields.io/github/forks/mehmet-emir-eroglu/CVE-2026-76475.svg)


## CVE-2026-76474
The vulnerabilities tracked by CVE-2026-76474 are related to issues concerning improper authentication that are grouped under the Common Weakness Enumeration (CWE) Class CWE-287.

- [https://github.com/mehmet-emir-eroglu/CVE-2026-76474](https://github.com/mehmet-emir-eroglu/CVE-2026-76474) :  ![starts](https://img.shields.io/github/stars/mehmet-emir-eroglu/CVE-2026-76474.svg) ![forks](https://img.shields.io/github/forks/mehmet-emir-eroglu/CVE-2026-76474.svg)


## CVE-2026-76473
The vulnerabilities tracked by CVE-2026-76473 are related to issues concerning improper neutralization of special elements in output used by a downstream component that are grouped under the Common Weakness Enumeration (CWE) Class CWE-74.

- [https://github.com/mehmet-emir-eroglu/CVE-2026-76473](https://github.com/mehmet-emir-eroglu/CVE-2026-76473) :  ![starts](https://img.shields.io/github/stars/mehmet-emir-eroglu/CVE-2026-76473.svg) ![forks](https://img.shields.io/github/forks/mehmet-emir-eroglu/CVE-2026-76473.svg)


## CVE-2026-76466
Note: Cisco Expressway Series refers to Cisco Expressway Core (Expressway-C) devices and Cisco Expressway Edge (Expressway-E) devices.

- [https://github.com/mehmet-emir-eroglu/CVE-2026-76466](https://github.com/mehmet-emir-eroglu/CVE-2026-76466) :  ![starts](https://img.shields.io/github/stars/mehmet-emir-eroglu/CVE-2026-76466.svg) ![forks](https://img.shields.io/github/forks/mehmet-emir-eroglu/CVE-2026-76466.svg)


## CVE-2026-76461
This vulnerability is due to insufficient validation in the email parsing logic. An attacker could exploit this vulnerability by sending a crafted email message that contains malicious SQL statements through an affected device. A successful exploit could allow the attacker to execute arbitrary SQL statements, leading to command execution with root privileges on the underlying operating system.

- [https://github.com/0xredash/CVE-2026-76461](https://github.com/0xredash/CVE-2026-76461) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-76461.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-76461.svg)


## CVE-2026-74469
to return its existing transport at the limit.

- [https://github.com/0xredash/CVE-2026-74469](https://github.com/0xredash/CVE-2026-74469) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-74469.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-74469.svg)


## CVE-2026-73570
 A remote code execution vulnerability exists in Zimbra Collaboration (ZCS) before 10.1.20 when the optional zimbra-snmp package is installed and SNMP notifications are enabled. Due to improper sanitization of untrusted input during SNMP notification processing, an unauthenticated attacker can send specially crafted SMTP requests that may result in execution of arbitrary operating system commands as the Zimbra user.

- [https://github.com/0xredash/CVE-2026-73570](https://github.com/0xredash/CVE-2026-73570) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-73570.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-73570.svg)


## CVE-2026-73296
 Microsoft UFO open-source framework for intelligent automation across devices and platforms. Prior to 3.0.8, create_mobile_data_collection_server and create_mobile_action_server in ufo/client/mcp/http_servers/mobile_mcp_server.py exposed Streamable HTTP MCP services on TCP ports 8020 and 8021 without authentication, allowing an unauthenticated remote attacker to invoke capture_screenshot, get_ui_tree, tap, swipe, type_text, launch_app, press_key, and click_control against an ADB-connected Android device, disclose screen and device data, and modify device state. This issue is fixed in version 3.0.8.

- [https://github.com/0xredash/CVE-2026-73296](https://github.com/0xredash/CVE-2026-73296) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-73296.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-73296.svg)


## CVE-2026-72898
 Metabase allows a remote, unauthenticated attacker to inject arbitrary SQL via the '/reset_password' database endpoint and gain administrator access to the connected Metabase instance.

- [https://github.com/0xredash/CVE-2026-72898](https://github.com/0xredash/CVE-2026-72898) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-72898.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-72898.svg)


## CVE-2026-72018
check before the memcpy to reject such requests with -EINVAL.

- [https://github.com/0xredash/CVE-2026-72018](https://github.com/0xredash/CVE-2026-72018) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-72018.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-72018.svg)


## CVE-2026-71569
Users are recommended to upgrade to version 4.23.0, which fixes the issue. If users are on the 4.22.x releases stream, then they are suggested to upgrade to 4.22.2. The 4.21.x release line reached end of life before this issue was resolved and will not receive a fix, so deployments on it must move to a supported release. Both the literal and the resolved path now classify the address from its raw bytes with one shared classifier, which recognises fc00::/7 and the shared address space 100.64.0.0/10, as well as IPv4-compatible, NAT64 (64:ff9b::/96) and 6to4 (2002::/16) addresses whose embedded IPv4 address is not globally routable. For deployments that cannot upgrade immediately, place authentication in front of the A2A push notification configuration path so that the webhook URL does not arrive from an untrusted caller, and deny egress from the Camel process to fc00::/7 at the network level; where the deployment has no need of IPv6, starting the JVM with -Djava.net.preferIPv4Stack=true removes the address class the gap turns on. Note that allowLocalWebhookUrls=false is already the default and does not by itself close the gap.

- [https://github.com/oscerd/CVE-2026-71569](https://github.com/oscerd/CVE-2026-71569) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-71569.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-71569.svg)


## CVE-2026-71195
 In OpenStack Manila before 23.0.1, multiple Manila API operations on public shares do not verify that the caller owns the share. The API controllers authorize operations against the caller's own project context, then load a foreign public share without re-authorizing against the share's actual owner. This affects the following operations: allow_access: grant data-plane read/write access to another tenant's share; deny_access: revoke the owner's existing access rules; update_access: escalate access level (e.g., ro to rw); create_share_backup: exfiltrate share data via a backup created under the attacker's project; soft_delete: move a foreign share to the recycle bin; restore: interfere with the owner's deletion workflow; export location metadata: create, update, and delete metadata on foreign export locations; access rule listing: disclose IPs, usernames, and CephFS keys. Any authenticated project member can exploit these operations on any public share. The share UUID is visible since the share is public.

- [https://github.com/mehmet-emir-eroglu/CVE-2026-71195](https://github.com/mehmet-emir-eroglu/CVE-2026-71195) :  ![starts](https://img.shields.io/github/stars/mehmet-emir-eroglu/CVE-2026-71195.svg) ![forks](https://img.shields.io/github/forks/mehmet-emir-eroglu/CVE-2026-71195.svg)


## CVE-2026-69254
 Flowise is a drag & drop user interface to build a customized large language model flow. Prior to 3.1.3, executeJavaScriptCode() accepted caller-provided nodeVMOptions and merged them over the default NodeVM security settings in packages/components/src/utils.ts. An authenticated attacker reaching packages/server/src/routes/node-custom-functions/index.ts could run a custom function that imported flowise-components/dist/src/utils.js, called executeJavaScriptCode() again with nodeVMOptions.require.builtin set to allow all built-in modules, and then required child_process to execute arbitrary system commands as root on the Flowise server. This issue is fixed in version 3.1.3.

- [https://github.com/CompleteTech-Security/flowise-cve-2026-69254-check](https://github.com/CompleteTech-Security/flowise-cve-2026-69254-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/flowise-cve-2026-69254-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/flowise-cve-2026-69254-check.svg)


## CVE-2026-68121
relocates the head.

- [https://github.com/0xredash/CVE-2026-68121](https://github.com/0xredash/CVE-2026-68121) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-68121.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-68121.svg)


## CVE-2026-66066
 Action Pack is a framework for handling and responding to web requests. In versions prior to 7.2.3.2, 8.0.5.1 and 8.1.3.1, Active Storage does not disable libvips operations marked unsafe for untrusted content, allowing a crafted upload to invoke such an operation. Consuming applications are affected when configured to use libvips and accept image uploads from untrusted users. An unauthenticated attacker may exploit this behavior to read arbitrary files accessible to the Rails process, including environment variables and application secrets. Exposure of credentials such as secret_key_base or external-service tokens may enable remote code execution or lateral movement. This issue has been fixed in versions 7.2.3.2, 8.0.5.1 and 8.1.3.1.

- [https://github.com/0xredash/CVE-2026-66066](https://github.com/0xredash/CVE-2026-66066) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-66066.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-66066.svg)


## CVE-2026-64638
Discovered and responsibly disclosed by [the team at pwn.ai](https://pwn.ai/).

- [https://github.com/0xredash/CVE-2026-64638](https://github.com/0xredash/CVE-2026-64638) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-64638.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-64638.svg)


## CVE-2026-64600
sequence counter changes across the ILOCK cycle.

- [https://github.com/0xredash/CVE-2026-64600](https://github.com/0xredash/CVE-2026-64600) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-64600.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-64600.svg)


## CVE-2026-64531
ownership and truncates on close failure.

- [https://github.com/0xredash/CVE-2026-64531](https://github.com/0xredash/CVE-2026-64531) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-64531.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-64531.svg)


## CVE-2026-63292
Users are recommended to upgrade to version 2.4.69, which fixes this issue.

- [https://github.com/0xredash/CVE-2026-63292](https://github.com/0xredash/CVE-2026-63292) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-63292.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-63292.svg)


## CVE-2026-63072
modules are affected by this CVE.

- [https://github.com/0xredash/CVE-2026-63072](https://github.com/0xredash/CVE-2026-63072) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-63072.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-63072.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/0xredash/CVE-2026-63030](https://github.com/0xredash/CVE-2026-63030) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-63030.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-63030.svg)


## CVE-2026-60206
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core).  Supported versions that are affected are 12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0 and  15.1.1.0.0. Easily exploitable vulnerability allows low privileged attacker with network access via SAML to compromise Oracle WebLogic Server.  While the vulnerability is in Oracle WebLogic Server, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.9 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H).

- [https://github.com/0xredash/CVE-2026-60206](https://github.com/0xredash/CVE-2026-60206) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-60206.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-60206.svg)


## CVE-2026-60004
 Gitea before 1.27.1 allows remote code execution via the diffpatch API through Git hook installation.

- [https://github.com/0xredash/CVE-2026-60004](https://github.com/0xredash/CVE-2026-60004) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-60004.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-60004.svg)


## CVE-2026-58138
 Orkes Conductor 3.21.21 before 3.30.2 contains an unauthenticated remote code execution vulnerability that allows remote attackers to execute arbitrary OS commands by submitting inline workflow definitions containing malicious JavaScript or Python expressions to the workflow API endpoint prior to authentication. Attackers can exploit unsandboxed GraalVM evaluators configured with HostAccess.ALL or allowAllAccess(true) through INLINE, LAMBDA, DO_WHILE, and SWITCH task types to invoke arbitrary system commands via Java reflection or direct subprocess calls.

- [https://github.com/0xredash/CVE-2026-58138](https://github.com/0xredash/CVE-2026-58138) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-58138.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-58138.svg)


## CVE-2026-58045
This vulnerability affects Node.js **22.x**, **24.x**, and **26.x**.

- [https://github.com/CompleteTech-Security/node-cve-2026-58045-check](https://github.com/CompleteTech-Security/node-cve-2026-58045-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/node-cve-2026-58045-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/node-cve-2026-58045-check.svg)


## CVE-2026-58044
This vulnerability affects all supported release lines: **Node.js 22**, **Node.js 24**, and **Node.js 26**.

- [https://github.com/CompleteTech-Security/node-cve-2026-58044-check](https://github.com/CompleteTech-Security/node-cve-2026-58044-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/node-cve-2026-58044-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/node-cve-2026-58044-check.svg)


## CVE-2026-58043
This vulnerability affects Node.js **main**, **22.x**, **24.x**, and **26.x**.

- [https://github.com/CompleteTech-Security/node-cve-2026-58043-check](https://github.com/CompleteTech-Security/node-cve-2026-58043-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/node-cve-2026-58043-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/node-cve-2026-58043-check.svg)


## CVE-2026-58042
This vulnerability affects Node.js **26.x**, **24.x**, and **22.x**.

- [https://github.com/CompleteTech-Security/node-cve-2026-58042-check](https://github.com/CompleteTech-Security/node-cve-2026-58042-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/node-cve-2026-58042-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/node-cve-2026-58042-check.svg)


## CVE-2026-58041
This vulnerability affects Node.js **22.x**, **24.x**, and **26.x**.

- [https://github.com/CompleteTech-Security/node-cve-2026-58041-check](https://github.com/CompleteTech-Security/node-cve-2026-58041-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/node-cve-2026-58041-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/node-cve-2026-58041-check.svg)


## CVE-2026-58040
This vulnerability affects Node.js **22.x**, **24.x**, and **26.x**.

- [https://github.com/CompleteTech-Security/node-cve-2026-58040-check](https://github.com/CompleteTech-Security/node-cve-2026-58040-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/node-cve-2026-58040-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/node-cve-2026-58040-check.svg)


## CVE-2026-58039
This vulnerability affects Node.js **22.x**, **24.x**, and **26.x**.

- [https://github.com/CompleteTech-Security/node-cve-2026-58039-check](https://github.com/CompleteTech-Security/node-cve-2026-58039-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/node-cve-2026-58039-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/node-cve-2026-58039-check.svg)


## CVE-2026-56850
This vulnerability affects Node.js **26.x**, **24.x**, and **22.x**.

- [https://github.com/CompleteTech-Security/node-cve-2026-56850-check](https://github.com/CompleteTech-Security/node-cve-2026-56850-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/node-cve-2026-56850-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/node-cve-2026-56850-check.svg)


## CVE-2026-56848
This vulnerability affects Node.js **26.x**, **24.x**, and **22.x**.

- [https://github.com/CompleteTech-Security/node-cve-2026-56848-check](https://github.com/CompleteTech-Security/node-cve-2026-56848-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/node-cve-2026-56848-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/node-cve-2026-56848-check.svg)


## CVE-2026-56847
This vulnerability affects Node.js **22.x**, **24.x**, and **26.x**.

- [https://github.com/CompleteTech-Security/node-cve-2026-56847-check](https://github.com/CompleteTech-Security/node-cve-2026-56847-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/node-cve-2026-56847-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/node-cve-2026-56847-check.svg)


## CVE-2026-56846
This vulnerability affects Node.js **24.x** and **22.x**.

- [https://github.com/CompleteTech-Security/node-cve-2026-56846-check](https://github.com/CompleteTech-Security/node-cve-2026-56846-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/node-cve-2026-56846-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/node-cve-2026-56846-check.svg)


## CVE-2026-56190
 Use of uninitialized resource in Windows RDP allows an unauthorized attacker to execute code over a network.

- [https://github.com/Udyz/RDPBleed](https://github.com/Udyz/RDPBleed) :  ![starts](https://img.shields.io/github/stars/Udyz/RDPBleed.svg) ![forks](https://img.shields.io/github/forks/Udyz/RDPBleed.svg)


## CVE-2026-55450
 Langflow is a tool for building and deploying AI-powered agents and workflows. Prior to 1.9.1, unauthenticated users can upload any amount of data to the server without any limitations. No need for any prior knowledge, only network access to Langflow. This can lead to space exhaustion on the server. In addition, in the response, the absolute path of the uploaded file is reported to the attacker, which is an information leak that can assist in chaining other primitives. This vulnerability is fixed in 1.9.1.

- [https://github.com/0xredash/CVE-2026-55450](https://github.com/0xredash/CVE-2026-55450) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-55450.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-55450.svg)


## CVE-2026-55200
 libssh2 1.11.1, fixed in commit 97acf3d, contains an out-of-bounds write vulnerability in ssh2_transport_read() that fails to enforce upper bounds on packet_length field. Remote attackers can send crafted SSH packets with excessively large packet_length values to corrupt heap memory and achieve remote code execution.

- [https://github.com/0xredash/CVE-2026-55200](https://github.com/0xredash/CVE-2026-55200) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-55200.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-55200.svg)


## CVE-2026-54121
 Improper authorization in Active Directory Certificate Services (AD CS) allows an authorized attacker to elevate privileges over a network.

- [https://github.com/0xredash/CVE-2026-54121](https://github.com/0xredash/CVE-2026-54121) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-54121.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-54121.svg)


## CVE-2026-53921
 odhcpd is the DHCPv6, DHCPv4, and router-advertisement server used by OpenWrt. Prior to version 25.12, odhcpd's DHCPv6 IA response handler writes past the end of a fixed 512-byte stack buffer (pdbuf) when a single DHCPv6 REQUEST carries enough IA options to nearly exhaust the reply space. Two independent overflow sites exist in the same call chain, both reachable from the network via a single unauthenticated UDP packet. odhcpd runs as root on OpenWrt; embedded targets often lack stack canaries and ASLR, making code execution realistic. This issue has been patched in version 25.12.

- [https://github.com/0xredash/CVE-2026-53921](https://github.com/0xredash/CVE-2026-53921) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-53921.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-53921.svg)
- [https://github.com/mehmet-emir-eroglu/CVE-2026-53921](https://github.com/mehmet-emir-eroglu/CVE-2026-53921) :  ![starts](https://img.shields.io/github/stars/mehmet-emir-eroglu/CVE-2026-53921.svg) ![forks](https://img.shields.io/github/forks/mehmet-emir-eroglu/CVE-2026-53921.svg)


## CVE-2026-53359
use-after-free.

- [https://github.com/0xredash/CVE-2026-53359](https://github.com/0xredash/CVE-2026-53359) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-53359.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-53359.svg)


## CVE-2026-50751
 A logic flow weakness in Remote Access and Mobile Access certificate validation in deprecated IKEv1 key exchange allows an unauthenticated remote attacker to bypass user authentication and establish a remote access VPN connection without a valid user password.

- [https://github.com/0xredash/CVE-2026-50751](https://github.com/0xredash/CVE-2026-50751) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-50751.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-50751.svg)


## CVE-2026-50656
 Microsoft is aware of an elevation of privilege in the Microsoft Malware Protection Engine in Microsoft Defender publicly referred to as &quot;RoguePlanet &quot;.

- [https://github.com/0xredash/CVE-2026-50656](https://github.com/0xredash/CVE-2026-50656) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-50656.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-50656.svg)


## CVE-2026-50053
 A request attribute override vulnerability in Zimbra Collaboration Suite (ZCS) allows unauthenticated requests to /h/* to populate servlet attributes intended for trusted internal dispatch. RestFilter copies URL parameters specifying an authentication token, target account, target item and dispatch state into the request attributes consumed by the Classic Web Client. Combined with CVE-2026-10632 on ZCS 10.1.16, this allows an attacker to supply their own valid token and document identifiers and execute JavaScript in another user's signed-in browser session. ZCS 10.1.17 blocks that XSS chain by changing the document renderer, but retains the request attribute override.

- [https://github.com/mehmet-emir-eroglu/CVE-2026-50053](https://github.com/mehmet-emir-eroglu/CVE-2026-50053) :  ![starts](https://img.shields.io/github/stars/mehmet-emir-eroglu/CVE-2026-50053.svg) ![forks](https://img.shields.io/github/forks/mehmet-emir-eroglu/CVE-2026-50053.svg)


## CVE-2026-48908
 A vulnerability in SP Page Builder for Joomla allows unauthenticated users to upload arbitrary files, ultimately resulting in the upload and execution of PHP code.

- [https://github.com/0xredash/CVE-2026-48908](https://github.com/0xredash/CVE-2026-48908) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-48908.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-48908.svg)


## CVE-2026-48907
 A vulnerability in the JCE editor extension for Joomla allows the creation of new editor profiles for unauthenticated users, ultimately resulting in PHP code upload and execution.

- [https://github.com/0xredash/CVE-2026-48907](https://github.com/0xredash/CVE-2026-48907) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-48907.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-48907.svg)
- [https://github.com/CoNistical/CVE-2026-48907](https://github.com/CoNistical/CVE-2026-48907) :  ![starts](https://img.shields.io/github/stars/CoNistical/CVE-2026-48907.svg) ![forks](https://img.shields.io/github/forks/CoNistical/CVE-2026-48907.svg)


## CVE-2026-47729
 Squid is a caching proxy for the Web. Prior to 7.6, due to an improper validation of syntactic correctness of input in the FTP gateway (src/clients/FtpGateway.cc), Squid is vulnerable to an out-of-bounds read: when a listing entry date in the TypeA or TypeB directory-listing formats is not followed by a filename, parsing was not restricted to the input buffer, so a trusted client accessing a misbehaving FTP server through Squid's gateway feature could read memory from random unrelated transactions. This issue is fixed in version 7.6.

- [https://github.com/0xredash/CVE-2026-47729](https://github.com/0xredash/CVE-2026-47729) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-47729.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-47729.svg)


## CVE-2026-46817
 Vulnerability in the Oracle Payments product of Oracle E-Business Suite (component: File Transmission).  Supported versions that are affected are 12.2.3-12.2.15. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Payments.  Successful attacks of this vulnerability can result in takeover of Oracle Payments. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/0xredash/CVE-2026-46817](https://github.com/0xredash/CVE-2026-46817) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-46817.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-46817.svg)


## CVE-2026-46333
set), and require a proper CAP_SYS_PTRACE capability to override.

- [https://github.com/0xredash/CVE-2026-46333](https://github.com/0xredash/CVE-2026-46333) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-46333.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-46333.svg)


## CVE-2026-46331
offset_valid() against INT_MIN, where negation is undefined.

- [https://github.com/0xredash/CVE-2026-46331](https://github.com/0xredash/CVE-2026-46331) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-46331.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-46331.svg)


## CVE-2026-46300
bytes into @to's linear data rather than transferring frag descriptors.

- [https://github.com/0xredash/CVE-2026-46300](https://github.com/0xredash/CVE-2026-46300) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-46300.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-46300.svg)


## CVE-2026-46243
spnego_cred to request the key.

- [https://github.com/0xredash/CVE-2026-46243](https://github.com/0xredash/CVE-2026-46243) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-46243.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-46243.svg)


## CVE-2026-46242
READ_ONCE(epi-dying) fast-path bailout stays.

- [https://github.com/0xredash/CVE-2026-46242](https://github.com/0xredash/CVE-2026-46242) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-46242.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-46242.svg)


## CVE-2026-45829
 A pre-authentication, code injection vulnerability in version 1.0.0 or later of the ChromaDB Python project allows an unauthenticated attacker to run arbitrary code on the server by sending a malicious model repository and trust_remote_code set to true in the /api/v2/tenants/{tenant}/databases/{db}/collections endpoint.

- [https://github.com/0xredash/CVE-2026-45829](https://github.com/0xredash/CVE-2026-45829) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-45829.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-45829.svg)


## CVE-2026-45585
No, if you are using TPM+PIN the vulnerability is not exploitable.

- [https://github.com/0xredash/CVE-2026-45585](https://github.com/0xredash/CVE-2026-45585) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-45585.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-45585.svg)


## CVE-2026-45447
issue, as the affected code is outside the OpenSSL FIPS module boundary.

- [https://github.com/0xredash/CVE-2026-45447](https://github.com/0xredash/CVE-2026-45447) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-45447.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-45447.svg)


## CVE-2026-44578
 Next.js is a React framework for building full-stack web applications. From 13.4.13 to before 15.5.16 and 16.2.5, self-hosted applications using the built-in Node.js server can be vulnerable to server-side request forgery through crafted WebSocket upgrade requests. An attacker can cause the server to proxy requests to arbitrary internal or external destinations, which may expose internal services or cloud metadata endpoints. Vercel-hosted deployments are not affected. This vulnerability is fixed in 15.5.16 and 16.2.5.

- [https://github.com/0xredash/CVE-2026-44578](https://github.com/0xredash/CVE-2026-44578) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-44578.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-44578.svg)


## CVE-2026-44277
 A improper access control vulnerability in Fortinet FortiAuthenticator 8.0.2, FortiAuthenticator 8.0.0, FortiAuthenticator 6.6.0 through 6.6.8, FortiAuthenticator 6.5.0 through 6.5.6 may allow attacker to execute unauthorized code or commands via crafted requests.

- [https://github.com/0xredash/CVE-2026-44277](https://github.com/0xredash/CVE-2026-44277) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-44277.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-44277.svg)


## CVE-2026-43786
 This issue was addressed with additional entitlement checks. This issue is fixed in macOS Golden Gate 27, macOS Sequoia 15.8, macOS Tahoe 26.7. An app may be able to gain root privileges.

- [https://github.com/0xredash/CVE-2026-43786](https://github.com/0xredash/CVE-2026-43786) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-43786.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-43786.svg)


## CVE-2026-43664
 This issue was addressed with improved data protection. This issue is fixed in iOS 26.7 and iPadOS 26.7, iOS 27 and iPadOS 27, macOS Golden Gate 27, macOS Sequoia 15.8, macOS Tahoe 26.7, tvOS 27, watchOS 27. An app may be able to access sensitive user data.

- [https://github.com/speedyfriend433/CVE-2026-43664](https://github.com/speedyfriend433/CVE-2026-43664) :  ![starts](https://img.shields.io/github/stars/speedyfriend433/CVE-2026-43664.svg) ![forks](https://img.shields.io/github/forks/speedyfriend433/CVE-2026-43664.svg)


## CVE-2026-43503
so segments drawing frags from frag_list members carry the marker.

- [https://github.com/0xredash/CVE-2026-43503](https://github.com/0xredash/CVE-2026-43503) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-43503.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-43503.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/pubglite55/findn2-ksu-chain](https://github.com/pubglite55/findn2-ksu-chain) :  ![starts](https://img.shields.io/github/stars/pubglite55/findn2-ksu-chain.svg) ![forks](https://img.shields.io/github/forks/pubglite55/findn2-ksu-chain.svg)
- [https://github.com/0xredash/CVE-2026-43499](https://github.com/0xredash/CVE-2026-43499) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-43499.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-43499.svg)


## CVE-2026-43494
rds_message_zcopy_from_user().

- [https://github.com/0xredash/CVE-2026-43494](https://github.com/0xredash/CVE-2026-43494) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-43494.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-43494.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/0xredash/CVE-2026-43284](https://github.com/0xredash/CVE-2026-43284) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-43284.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-43284.svg)


## CVE-2026-42945
 NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module. This vulnerability exists when the rewrite directive is followed by a rewrite, if, or set directive and an unnamed Perl-Compatible Regular Expression (PCRE) capture (for example, $1, $2) with a replacement string that includes a question mark (?). An unauthenticated attacker along with conditions beyond its control can exploit this vulnerability by sending crafted HTTP requests. This may cause a heap buffer overflow in the NGINX worker process leading to a restart. Additionally, attackers can execute code on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/0xredash/CVE-2026-42945](https://github.com/0xredash/CVE-2026-42945) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-42945.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-42945.svg)
- [https://github.com/richard-rodriguez26/CVE-2026-42945](https://github.com/richard-rodriguez26/CVE-2026-42945) :  ![starts](https://img.shields.io/github/stars/richard-rodriguez26/CVE-2026-42945.svg) ![forks](https://img.shields.io/github/forks/richard-rodriguez26/CVE-2026-42945.svg)
- [https://github.com/ChaskarVinit/nginx-rift-cve-2026-42945-lab](https://github.com/ChaskarVinit/nginx-rift-cve-2026-42945-lab) :  ![starts](https://img.shields.io/github/stars/ChaskarVinit/nginx-rift-cve-2026-42945-lab.svg) ![forks](https://img.shields.io/github/forks/ChaskarVinit/nginx-rift-cve-2026-42945-lab.svg)


## CVE-2026-42569
 phpVMS is a PHP application to run and simulate an airline. Prior to version 7.0.6, a critical vulnerability in phpVMS allowed unauthenticated access to a legacy import feature. This issue has been patched in version 7.0.6.

- [https://github.com/0xredash/CVE-2026-42569](https://github.com/0xredash/CVE-2026-42569) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-42569.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-42569.svg)


## CVE-2026-42533
 Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/0xh3y3/cve-2026-42533](https://github.com/0xh3y3/cve-2026-42533) :  ![starts](https://img.shields.io/github/stars/0xh3y3/cve-2026-42533.svg) ![forks](https://img.shields.io/github/forks/0xh3y3/cve-2026-42533.svg)


## CVE-2026-42530
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/0xredash/CVE-2026-42530](https://github.com/0xredash/CVE-2026-42530) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-42530.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-42530.svg)


## CVE-2026-42208
 LiteLLM is a proxy server (AI Gateway) to call LLM APIs in OpenAI (or native) format. From version 1.81.16 to before version 1.83.7, a database query used during proxy API key checks mixed the caller-supplied key value into the query text instead of passing it as a separate parameter. An unauthenticated attacker could send a specially crafted Authorization header to any LLM API route (for example POST /chat/completions) and reach this query through the proxy's error-handling path. An attacker could read data from the proxy's database and may be able to modify it, leading to unauthorised access to the proxy and the credentials it manages. This issue has been patched in version 1.83.7.

- [https://github.com/0xredash/CVE-2026-42208](https://github.com/0xredash/CVE-2026-42208) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-42208.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-42208.svg)


## CVE-2026-41940
 cPanel and WHM versions after 11.40 contain an authentication bypass vulnerability in the login flow that allows unauthenticated remote attackers to gain unauthorized access to the control panel.

- [https://github.com/0xredash/CVE-2026-41940](https://github.com/0xredash/CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-41940.svg)
- [https://github.com/ylerpeek/CVE-2026-41940-PoC-3](https://github.com/ylerpeek/CVE-2026-41940-PoC-3) :  ![starts](https://img.shields.io/github/stars/ylerpeek/CVE-2026-41940-PoC-3.svg) ![forks](https://img.shields.io/github/forks/ylerpeek/CVE-2026-41940-PoC-3.svg)


## CVE-2026-41651
3. Late flag read at execution time (lines 2273–2277): The scheduler's idle callback reads cached_transaction_flags at dispatch time, not at authorization time. If flags were overwritten between authorization and execution, the backend sees the attacker's flags.

- [https://github.com/0xredash/CVE-2026-41651](https://github.com/0xredash/CVE-2026-41651) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-41651.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-41651.svg)


## CVE-2026-41462
 ProjeQtor versions 7.0 through 12.4.3 contain an unauthenticated SQL injection vulnerability in the login functionality where the login variable is directly concatenated into a SQL query without parameterization or sanitization. Attackers can inject arbitrary SQL expressions through the username field at the authentication endpoint to create privileged accounts, read sensitive data, and execute operating system commands if the database user has elevated permissions.

- [https://github.com/0xredash/CVE-2026-41462](https://github.com/0xredash/CVE-2026-41462) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-41462.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-41462.svg)


## CVE-2026-41091
 Improper link resolution before file access ('link following') in Microsoft Defender allows an authorized attacker to elevate privileges locally.

- [https://github.com/0xredash/CVE-2026-41091](https://github.com/0xredash/CVE-2026-41091) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-41091.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-41091.svg)


## CVE-2026-41089
 Stack-based buffer overflow in Windows Netlogon allows an unauthorized attacker to execute code over a network.

- [https://github.com/0xredash/CVE-2026-41089](https://github.com/0xredash/CVE-2026-41089) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-41089.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-41089.svg)


## CVE-2026-40487
 Postiz is an AI social media scheduling tool. Prior to version 2.21.6, a file upload validation bypass allows any authenticated user to upload arbitrary HTML, SVG, or other executable file types to the server by spoofing the `Content-Type` header. The uploaded files are then served by nginx with a Content-Type derived from their original extension (`text/html`, `image/svg+xml`), enabling Stored Cross-Site Scripting (XSS) in the context of the application's origin. This can lead to session riding, account takeover, and full compromise of other users' accounts. Version 2.21.6 contains a fix.

- [https://github.com/0xredash/CVE-2026-42208](https://github.com/0xredash/CVE-2026-42208) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-42208.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-42208.svg)


## CVE-2026-40369
 Heap-based buffer overflow in Windows Kernel allows an authorized attacker to elevate privileges locally.

- [https://github.com/0xredash/CVE-2026-40369](https://github.com/0xredash/CVE-2026-40369) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-40369.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-40369.svg)


## CVE-2026-40175
 Axios is a promise based HTTP client for the browser and Node.js. Versions prior to 1.15.0 and 0.3.1 are vulnerable to a specific gadget-style attack chain in which prototype pollution in a third-party dependency may be leveraged to inject unsanitized header values into outbound requests. This vulnerability is fixed in 1.15.0 and 0.3.1.

- [https://github.com/0xredash/CVE-2026-40175](https://github.com/0xredash/CVE-2026-40175) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-40175.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-40175.svg)


## CVE-2026-40047
Users are recommended to upgrade to a release that contains the CAMEL-23212 fix. On the mainline the fix is included from Apache Camel 4.19.0 (and later releases such as 4.20.0). For users on the 4.18.x LTS releases stream, upgrade to 4.18.3. The fix replaces the denylist with a strict allowlist of recognized `docling` CLI flags (rejecting any unrecognized flag, and rejecting producer-managed flags such as the output-directory flags), defensively rejects shell metacharacters in argument values, and normalizes path-like values with Path.normalize() before validating them so that traversal sequences which bypass a literal `../` check are detected. As defence in depth, route authors should avoid mapping untrusted message content into the `CamelDoclingCustomArguments` header and the path-bearing headers, and should strip Camel-internal headers from messages that arrive from untrusted producers.

- [https://github.com/oscerd/CVE-2026-95628](https://github.com/oscerd/CVE-2026-95628) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-95628.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-95628.svg)


## CVE-2026-39987
 marimo is a reactive Python notebook. Prior to 0.23.0, Marimo has a Pre-Auth RCE vulnerability. The terminal WebSocket endpoint /terminal/ws lacks authentication validation, allowing an unauthenticated attacker to obtain a full PTY shell and execute arbitrary system commands. Unlike other WebSocket endpoints (e.g., /ws) that correctly call validate_auth() for authentication, the /terminal/ws endpoint only checks the running mode and platform support before accepting connections, completely skipping authentication verification. This vulnerability is fixed in 0.23.0.

- [https://github.com/0xredash/CVE-2026-39987](https://github.com/0xredash/CVE-2026-39987) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-39987.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-39987.svg)


## CVE-2026-39813
 A path traversal: '../filedir' vulnerability in Fortinet FortiSandbox 5.0.0 through 5.0.5, FortiSandbox 4.4.0 through 4.4.8 may allow attacker to escalation of privilege via specially crafted HTTP requests.

- [https://github.com/0xredash/CVE-2026-39813](https://github.com/0xredash/CVE-2026-39813) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-39813.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-39813.svg)


## CVE-2026-39808
 A improper neutralization of special elements used in an os command ('os command injection') vulnerability in Fortinet FortiSandbox 4.4.0 through 4.4.8 may allow attacker to execute unauthorized code or commands via insert attack vector here

- [https://github.com/0xredash/CVE-2026-39808](https://github.com/0xredash/CVE-2026-39808) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-39808.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-39808.svg)


## CVE-2026-35616
 A improper access control vulnerability in Fortinet FortiClientEMS 7.4.5 through 7.4.6 may allow an unauthenticated attacker to execute unauthorized code or commands via crafted requests.

- [https://github.com/0xredash/CVE-2026-35616](https://github.com/0xredash/CVE-2026-35616) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-35616.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-35616.svg)


## CVE-2026-35273
 Vulnerability in the PeopleSoft Enterprise PeopleTools product of Oracle PeopleSoft (component: Updates Environment Management). Supported versions that are affected are 8.61 and 8.62. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise PeopleSoft Enterprise PeopleTools. Successful attacks of this vulnerability can result in takeover of PeopleSoft Enterprise PeopleTools. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/0xredash/CVE-2026-35273](https://github.com/0xredash/CVE-2026-35273) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-35273.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-35273.svg)


## CVE-2026-34724
 Zammad is a web based open source helpdesk/customer support system. Prior to 7.0.1, a server-side template injection vulnerability  which leads to RCE via AI Agent exists. Impact is limited to environments where an attacker can control or influence type_enrichment_data (typically high-privilege administrative configuration). This vulnerability is fixed in 7.0.1.

- [https://github.com/0xredash/CVE-2026-34724](https://github.com/0xredash/CVE-2026-34724) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-34724.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-34724.svg)


## CVE-2026-34197
Users are recommended to upgrade to version 5.19.4 or 6.2.3, which fixes the issue

- [https://github.com/0xredash/CVE-2026-34197](https://github.com/0xredash/CVE-2026-34197) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-34197.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-34197.svg)


## CVE-2026-34156
 NocoBase is an AI-powered no-code/low-code platform for building business applications and enterprise solutions. Prior to version 2.0.28, NocoBase's Workflow Script Node executes user-supplied JavaScript inside a Node.js vm sandbox with a custom require allowlist (controlled by WORKFLOW_SCRIPT_MODULES env var). However, the console object passed into the sandbox context exposes host-realm WritableWorkerStdio stream objects via console._stdout and console._stderr. An authenticated attacker can traverse the prototype chain to escape the sandbox and achieve Remote Code Execution as root. This issue has been patched in version 2.0.28.

- [https://github.com/0xredash/CVE-2026-34156](https://github.com/0xredash/CVE-2026-34156) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-34156.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-34156.svg)


## CVE-2026-33825
 Insufficient granularity of access control in Microsoft Defender allows an authorized attacker to elevate privileges locally.

- [https://github.com/0xredash/CVE-2026-33825](https://github.com/0xredash/CVE-2026-33825) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-33825.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-33825.svg)


## CVE-2026-33439
 Open Access Management (OpenAM) is an access management solution. Prior to 16.0.6, OpenIdentityPlatform OpenAM is vulnerable to pre-authentication Remote Code Execution (RCE) via unsafe Java deserialization of the jato.clientSession HTTP parameter. This bypasses the WhitelistObjectInputStream mitigation that was applied to the jato.pageSession parameter after CVE-2021-35464. An unauthenticated attacker can achieve arbitrary command execution on the server by sending a crafted serialized Java object as the jato.clientSession GET/POST parameter to any JATO ViewBean endpoint whose JSP contains jato:form tags (e.g., the Password Reset pages). This vulnerability is fixed in 16.0.6.

- [https://github.com/TeoVMP/CVE-2026-33439](https://github.com/TeoVMP/CVE-2026-33439) :  ![starts](https://img.shields.io/github/stars/TeoVMP/CVE-2026-33439.svg) ![forks](https://img.shields.io/github/forks/TeoVMP/CVE-2026-33439.svg)


## CVE-2026-33017
 Langflow is a tool for building and deploying AI-powered agents and workflows. In versions prior to 1.9.0, the POST /api/v1/build_public_tmp/{flow_id}/flow endpoint allows building public flows without requiring authentication. When the optional data parameter is supplied, the endpoint uses attacker-controlled flow data (containing arbitrary Python code in node definitions) instead of the stored flow data from the database. This code is passed to exec() with zero sandboxing, resulting in unauthenticated remote code execution. This is distinct from CVE-2025-3248, which fixed /api/v1/validate/code by adding authentication. The build_public_tmp endpoint is designed to be unauthenticated (for public flows) but incorrectly accepts attacker-supplied flow data containing arbitrary executable code. This issue has been fixed in version 1.9.0.

- [https://github.com/0xredash/CVE-2026-33017](https://github.com/0xredash/CVE-2026-33017) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-33017.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-33017.svg)


## CVE-2026-32475
This issue affects Elementor Pro: from n/a through 4.2.1.

- [https://github.com/0xredash/CVE-2026-32475](https://github.com/0xredash/CVE-2026-32475) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-32475.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-32475.svg)


## CVE-2026-31635
Reject authenticator lengths that exceed the remaining packet payload.

- [https://github.com/0xredash/CVE-2026-31635](https://github.com/0xredash/CVE-2026-31635) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-31635.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-31635.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/0xredash/CVE-2026-31431](https://github.com/0xredash/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-31431.svg)


## CVE-2026-31402
correct response on the original request.

- [https://github.com/0xredash/CVE-2026-31402](https://github.com/0xredash/CVE-2026-31402) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-31402.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-31402.svg)


## CVE-2026-28289
 FreeScout is a free help desk and shared inbox built with PHP's Laravel framework. A patch bypass vulnerability for CVE-2026-27636 in FreeScout 1.8.206 and earlier allows any authenticated user with file upload permissions to achieve Remote Code Execution (RCE) on the server by uploading a malicious .htaccess file using a zero-width space character prefix to bypass the security check. The vulnerability exists in the sanitizeUploadedFileName() function in app/Http/Helper.php. The function contains a Time-of-Check to Time-of-Use (TOCTOU) flaw where the dot-prefix check occurs before sanitization removes invisible characters. This vulnerability is fixed in 1.8.207.

- [https://github.com/0xredash/CVE-2026-28289](https://github.com/0xredash/CVE-2026-28289) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-28289.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-28289.svg)


## CVE-2026-27876
- 12.4.0 (inclusive) to 12.4.2 (exclusive): 12.4.2 has the fix. 13.0.0 and above also have the fix: no v13 release is affected.

- [https://github.com/0xredash/CVE-2026-27876](https://github.com/0xredash/CVE-2026-27876) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-27876.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-27876.svg)


## CVE-2026-26081
 HAProxy Community Edition 3.0 through 3.3 before 3.3.3 lacks a length check for the NEW_TOKEN format. HAProxy Enterprise and ALOHA are also affected.

- [https://github.com/Zeerg/haproxy-quic-cves-2026](https://github.com/Zeerg/haproxy-quic-cves-2026) :  ![starts](https://img.shields.io/github/stars/Zeerg/haproxy-quic-cves-2026.svg) ![forks](https://img.shields.io/github/forks/Zeerg/haproxy-quic-cves-2026.svg)


## CVE-2026-26080
 HAProxy Community Edition 3.2.x through 3.3.x before 3.3.3 can enter a loop or crash because varint is mishandled. HAProxy Enterprise and ALOHA are also affected.

- [https://github.com/Zeerg/haproxy-quic-cves-2026](https://github.com/Zeerg/haproxy-quic-cves-2026) :  ![starts](https://img.shields.io/github/stars/Zeerg/haproxy-quic-cves-2026.svg) ![forks](https://img.shields.io/github/forks/Zeerg/haproxy-quic-cves-2026.svg)


## CVE-2026-26026
 GLPI is a free asset and IT management software package. From 11.0.0 to before 11.0.6, template injection by an administrator lead to RCE. This vulnerability is fixed in 11.0.6.

- [https://github.com/PeaMatNgu/CVE-2026-26026-GLPI](https://github.com/PeaMatNgu/CVE-2026-26026-GLPI) :  ![starts](https://img.shields.io/github/stars/PeaMatNgu/CVE-2026-26026-GLPI.svg) ![forks](https://img.shields.io/github/forks/PeaMatNgu/CVE-2026-26026-GLPI.svg)


## CVE-2026-25769
 Wazuh is a free and open source platform used for threat prevention, detection, and response. Versions 4.0.0 through 4.14.2 have a Remote Code Execution (RCE) vulnerability due to Deserialization of Untrusted Data). All Wazuh deployments using cluster mode (master/worker architecture) and any organization with a compromised worker node (e.g., through initial access, insider threat, or supply chain attack) are impacted. An attacker who gains access to a worker node (through any means) can achieve full RCE on the master node with root privileges. Version 4.14.3 fixes the issue.

- [https://github.com/0xredash/CVE-2026-25769](https://github.com/0xredash/CVE-2026-25769) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-25769.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-25769.svg)


## CVE-2026-25089
 A improper neutralization of special elements used in an os command ('os command injection') vulnerability in Fortinet FortiSandbox 5.0.0 through 5.0.5, FortiSandbox 4.4.0 through 4.4.8, FortiSandbox 4.2 all versions, FortiSandbox Cloud 5.0.4 through 5.0.5, FortiSandbox PaaS 5.0.4 through 5.0.5 may allow an unauthenticated attacker to execute unauthorized commands via specifically crafted HTTP requests

- [https://github.com/0xredash/CVE-2026-25089](https://github.com/0xredash/CVE-2026-25089) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-25089.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-25089.svg)


## CVE-2026-25049
 n8n is an open source workflow automation platform. Prior to versions 1.123.17 and 2.5.2, an authenticated user with permission to create or modify workflows could abuse crafted expressions in workflow parameters to trigger unintended system command execution on the host running n8n. This issue has been patched in versions 1.123.17 and 2.5.2.

- [https://github.com/0xredash/CVE-2026-25049](https://github.com/0xredash/CVE-2026-25049) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-25049.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-25049.svg)


## CVE-2026-24090
 Cryptographic issue while processing partition table entries allows unauthorized modification of boot flow.

- [https://github.com/wnduddld0513/Lenovo-Qcom-RPMB-PoC](https://github.com/wnduddld0513/Lenovo-Qcom-RPMB-PoC) :  ![starts](https://img.shields.io/github/stars/wnduddld0513/Lenovo-Qcom-RPMB-PoC.svg) ![forks](https://img.shields.io/github/forks/wnduddld0513/Lenovo-Qcom-RPMB-PoC.svg)


## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.

- [https://github.com/0xredash/CVE-2026-24061](https://github.com/0xredash/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-24061.svg)


## CVE-2026-23111
skip active elements, process inactive ones.

- [https://github.com/0xredash/CVE-2026-23111](https://github.com/0xredash/CVE-2026-23111) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-23111.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-23111.svg)


## CVE-2026-22812
 OpenCode is an open source AI coding agent. Prior to 1.0.216, OpenCode automatically starts an unauthenticated HTTP server that allows any local process (or any website via permissive CORS) to execute arbitrary shell commands with the user's privileges. This vulnerability is fixed in 1.0.216.

- [https://github.com/0xredash/CVE-2026-22812](https://github.com/0xredash/CVE-2026-22812) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-22812.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-22812.svg)


## CVE-2026-22557
 A malicious actor with access to the network could exploit a Path Traversal vulnerability found in the UniFi Network Application to access files on the underlying system that could be manipulated to access an underlying account.

- [https://github.com/0xredash/CVE-2026-22557](https://github.com/0xredash/CVE-2026-22557) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-22557.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-22557.svg)


## CVE-2026-22241
 The Open eClass platform (formerly known as GUnet eClass) is a complete course management system. Prior to version 4.2, an arbitrary file upload vulnerability in the theme import functionality enables an attacker with administrative privileges to upload arbitrary files on the server's file system. The main cause of the issue is that no validation or sanitization of the file's present inside the zip archive. This leads to remote code execution on the web server. Version 4.2 patches the issue.

- [https://github.com/0xredash/CVE-2026-22241](https://github.com/0xredash/CVE-2026-22241) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-22241.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-22241.svg)


## CVE-2026-21962
 Vulnerability in the Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in product of Oracle Fusion Middleware (component: Weblogic Server Proxy Plug-in for Apache HTTP Server, Weblogic Server Proxy Plug-in for IIS).  Supported versions that are affected are 12.2.1.4.0, 14.1.1.0.0 and  14.1.2.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in.  While the vulnerability is in Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in accessible data as well as  unauthorized access to critical data or complete access to all Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in accessible data. Note: Affected version for Weblogic Server Proxy Plug-in for IIS is 12.2.1.4.0 only. CVSS 3.1 Base Score 10.0 (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N).

- [https://github.com/0xredash/CVE-2026-21962](https://github.com/0xredash/CVE-2026-21962) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-21962.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-21962.svg)


## CVE-2026-21858
 n8n is an open source workflow automation platform. Versions starting with 1.65.0 and below 1.121.0 enable an attacker to access files on the underlying server through execution of certain form-based workflows. A vulnerable workflow could grant access to an unauthenticated remote attacker, resulting in exposure of sensitive information stored on the system and may enable further compromise depending on deployment configuration and workflow usage. This issue is fixed in version 1.121.0.

- [https://github.com/0xredash/CVE-2026-21858](https://github.com/0xredash/CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-21858.svg)


## CVE-2026-21643
 An improper neutralization of special elements used in an sql command ('sql injection') vulnerability in Fortinet FortiClientEMS 7.4.4 may allow an unauthenticated attacker to execute unauthorized code or commands via specifically crafted HTTP requests.

- [https://github.com/0xredash/CVE-2026-21643](https://github.com/0xredash/CVE-2026-21643) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-21643.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-21643.svg)


## CVE-2026-21589
 This is a vulnerability in Bitbucket Data Center, Confluence Data Center, Jira Service Management Data Center, Jira Software Data Center, Bamboo Data Center. Crowd Data Center, Crucible and Fisheye. This Arbitrary File Access vulnerability allows an unauthenticated attacker to access specific files within the web application root directory in affected versions. Exploitation requires prior knowledge of the target file's exact name and path; this vulnerability does not allow attackers to enumerate or list directory contents. In some configurations, there may be some sensitive files that make this highly severe. This vulnerability allows an unauthenticated remote attacker to access specific files within the web application root directory in affected versions. The vulnerability must be addressed for affected versions of: -- Bitbucket Data Center, introduced in version = 4.6.0, fix versions: 9.4.26, 10.2.8, 10.5.1 -- Confluence Data Center, introduced in version = 5.10.0, fix versions 9.2.26, 10.2.19 -- Crowd Data Center, introduced in version = 2.11.0, fix versions 6.3.7, 7.0.3, 7.1.7, 7.2.4 -- Jira Software Data Center, introduced in version = 7.1.0, fix versions 9.12.40, 10.3.26, 11.3.12 -- Jira Service Management Data Center, introduced in version = 3.1.0, fix versions 5.12.40, 10.3.26, 11.3.12 -- Bamboo Data Center = 7.0.1, fix versions 10.2.24, 12.1.12 -- Crucible, fix versions 4.9.15 -- Fisheye, fix version 4.9.15 -- Exploitation requires prior knowledge of the target file's exact name and path. The vulnerability does not include the capability to enumerate or list directory contents.

- [https://github.com/0xredash/CVE-2026-21589](https://github.com/0xredash/CVE-2026-21589) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-21589.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-21589.svg)
- [https://github.com/CompleteTech-Security/atlassian-cve-2026-21589-check](https://github.com/CompleteTech-Security/atlassian-cve-2026-21589-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/atlassian-cve-2026-21589-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/atlassian-cve-2026-21589-check.svg)


## CVE-2026-20841
 Improper neutralization of special elements used in a command ('command injection') in Windows Notepad App allows an unauthorized attacker to execute code locally.

- [https://github.com/0xredash/CVE-2026-20841](https://github.com/0xredash/CVE-2026-20841) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-20841.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-20841.svg)


## CVE-2026-20700
 A memory corruption issue was addressed with improved state management. This issue is fixed in iOS 26.3 and iPadOS 26.3, macOS Tahoe 26.3, tvOS 26.3, visionOS 26.3, watchOS 26.3. An attacker with memory write capability may be able to execute arbitrary code. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 26. CVE-2025-14174 and CVE-2025-43529 were also issued in response to this report.

- [https://github.com/nicnac599/tr4mpass](https://github.com/nicnac599/tr4mpass) :  ![starts](https://img.shields.io/github/stars/nicnac599/tr4mpass.svg) ![forks](https://img.shields.io/github/forks/nicnac599/tr4mpass.svg)


## CVE-2026-20253
 In Splunk Enterprise 10.2 versions below 10.2.4 and 10 versions below 10.0.7, an unauthenticated user could create or truncate arbitrary files through a PostgreSQL sidecar service endpoint. The vulnerability exists because the PostgreSQL sidecar service endpoint lacks authentication controls, allowing any network-reachable user to invoke file operations without credentials. Splunk Enterprise versions 9.4 and earlier are not affected. If you cannot immediately upgrade to a fixed version, you can mitigate this vulnerability by disabling the PostgreSQL sidecar service.

- [https://github.com/0xredash/CVE-2026-20253](https://github.com/0xredash/CVE-2026-20253) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-20253.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-20253.svg)


## CVE-2026-20245
Cisco recommends that customers upgrade to the fixed software that is documented in the  that was published on May 14, 2026, and verify the configuration of the edge devices.

- [https://github.com/0xredash/CVE-2026-20245](https://github.com/0xredash/CVE-2026-20245) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-20245.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-20245.svg)


## CVE-2026-20131
Note: If the FMC management interface does not have public internet access, the attack surface that is associated with this vulnerability is reduced.

- [https://github.com/0xredash/CVE-2026-20131](https://github.com/0xredash/CVE-2026-20131) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-20131.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-20131.svg)


## CVE-2026-20127
This vulnerability exists because the peering authentication mechanism in an affected system is not working properly. An attacker could exploit this vulnerability by sending crafted requests to an affected system. A successful exploit could allow the attacker to log in to an affected Cisco Catalyst SD-WAN Controller as an internal, high-privileged, non-root&nbsp;user account. Using this account, the attacker could access NETCONF, which would then allow the attacker to manipulate network configuration for the SD-WAN fabric.&nbsp;

- [https://github.com/0xredash/CVE-2026-20127](https://github.com/0xredash/CVE-2026-20127) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-20127.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-20127.svg)


## CVE-2026-20079
This vulnerability is due to an improper system process that is created at boot time. An attacker could exploit this vulnerability by sending crafted HTTP requests to an affected device. A successful exploit could allow the attacker to execute a variety of scripts and commands that allow&nbsp;root access to the device.&nbsp;

- [https://github.com/0xredash/CVE-2026-20079](https://github.com/0xredash/CVE-2026-20079) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-20079.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-20079.svg)


## CVE-2026-19490
This issue affects ADC: from 14.1 through 73.32 and from 13.1 through 63.21; Gateway: from 14.1 through 73.32 and from 13.1 through 63.21.

- [https://github.com/CompleteTech-Security/netscaler-cve-2026-19490-check](https://github.com/CompleteTech-Security/netscaler-cve-2026-19490-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/netscaler-cve-2026-19490-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/netscaler-cve-2026-19490-check.svg)


## CVE-2026-19489
This issue affects ADC: from 14.1 through 73.32 and from 13.1 through 63.21; Gateway: from 14.1 through 73.32 and from 13.1 through 63.21.

- [https://github.com/CompleteTech-Security/netscaler-cve-2026-19489-check](https://github.com/CompleteTech-Security/netscaler-cve-2026-19489-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/netscaler-cve-2026-19489-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/netscaler-cve-2026-19489-check.svg)


## CVE-2026-17106
 The tar extraction routines in moby/go-archive (Unpack, UnpackLayer, Untar/UntarUncompressed, and the ApplyLayer helpers) do not confine filesystem operations to the destination directory. The extractor decides where each archive entry lands using lexical string checks and then performs the filesystem operation on a path that is resolved by the OS, so links introduced by the archive can be followed out of the destination directory. An attacker who controls the contents of an archive can create or overwrite files at arbitrary paths writable by the extracting process.

- [https://github.com/CompleteTech-Security/copyescape-check](https://github.com/CompleteTech-Security/copyescape-check) :  ![starts](https://img.shields.io/github/stars/CompleteTech-Security/copyescape-check.svg) ![forks](https://img.shields.io/github/forks/CompleteTech-Security/copyescape-check.svg)


## CVE-2026-15723
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 10.1 before 19.3.6, 19.4 before 19.4.3, and 19.5 before 19.5.1 that, when OmniAuth SAML and LDAP auto-linking were both enabled, an authenticated user could have taken over an existing LDAP-backed account without any interaction from the targeted user, due to improper input sanitization in the LDAP email lookup path used during OmniAuth identity linking.

- [https://github.com/mehmet-emir-eroglu/CVE-2026-15723](https://github.com/mehmet-emir-eroglu/CVE-2026-15723) :  ![starts](https://img.shields.io/github/stars/mehmet-emir-eroglu/CVE-2026-15723.svg) ![forks](https://img.shields.io/github/forks/mehmet-emir-eroglu/CVE-2026-15723.svg)


## CVE-2026-15409
 A Server-side request forgery (SSRF) vulnerability has been identified in the SMA1000 Appliance Work Place interface. A remote unauthenticated attacker could potentially cause the appliance to make requests to unintended location.

- [https://github.com/0xredash/CVE-2026-15409](https://github.com/0xredash/CVE-2026-15409) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-15409.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-15409.svg)


## CVE-2026-12485
      memcpy(&reply_buf[36], g_network_config-ip_addr, v3);

- [https://github.com/0xredash/CVE-2026-12485](https://github.com/0xredash/CVE-2026-12485) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-12485.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-12485.svg)


## CVE-2026-11645
 Out of bounds read and write in V8 in Google Chrome prior to 149.0.7827.103 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/0xredash/CVE-2026-11645](https://github.com/0xredash/CVE-2026-11645) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-11645.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-11645.svg)


## CVE-2026-11592
 The Email Subscribers & Newsletters – Email Marketing, Post Notifications & Newsletter Plugin for WordPress plugin for WordPress is vulnerable to authorization bypass in all versions up to, and including, 5.9.27. This is due to the plugin not properly verifying that a user is authorized to perform an action. This makes it possible for authenticated attackers, with contributor-level access and above, to overwrite plugin mail settings (from name and from email address), create audience lists, insert arbitrary contacts into those lists, create and overwrite newsletter broadcasts and post notifications, add workflows, and queue and dispatch mass email to arbitrary recipients.

- [https://github.com/aymencdm/CVE-2026-115926-free5gc-bsf-missing-auth](https://github.com/aymencdm/CVE-2026-115926-free5gc-bsf-missing-auth) :  ![starts](https://img.shields.io/github/stars/aymencdm/CVE-2026-115926-free5gc-bsf-missing-auth.svg) ![forks](https://img.shields.io/github/forks/aymencdm/CVE-2026-115926-free5gc-bsf-missing-auth.svg)
- [https://github.com/aymencdm/CVE-2026-115925-free5gc-root-ca-key-exposure](https://github.com/aymencdm/CVE-2026-115925-free5gc-root-ca-key-exposure) :  ![starts](https://img.shields.io/github/stars/aymencdm/CVE-2026-115925-free5gc-root-ca-key-exposure.svg) ![forks](https://img.shields.io/github/forks/aymencdm/CVE-2026-115925-free5gc-root-ca-key-exposure.svg)


## CVE-2026-11499
 A vulnerability was determined in Tenda HG7, HG9 and HG10 300001138_en_xpon. This affects the function formDOMAINBLK of the file /boaform/formDOMAINBLK. Executing a manipulation of the argument blkDomain can lead to stack-based buffer overflow. The attack may be performed from remote.

- [https://github.com/0xredash/CVE-2026-11499](https://github.com/0xredash/CVE-2026-11499) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-11499.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-11499.svg)


## CVE-2026-11244
 Insufficient validation of untrusted input in WebAuthentication in Google Chrome prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to bypass same origin policy via a crafted HTML page. (Chromium security severity: Low)

- [https://github.com/Mas0nShi/CVE-2026-112445](https://github.com/Mas0nShi/CVE-2026-112445) :  ![starts](https://img.shields.io/github/stars/Mas0nShi/CVE-2026-112445.svg) ![forks](https://img.shields.io/github/forks/Mas0nShi/CVE-2026-112445.svg)


## CVE-2026-10961
 Use after free in Chrome for iOS in Google Chrome on iOS prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/fahise/cve-2026-109618-cve-2026-109619-poc](https://github.com/fahise/cve-2026-109618-cve-2026-109619-poc) :  ![starts](https://img.shields.io/github/stars/fahise/cve-2026-109618-cve-2026-109619-poc.svg) ![forks](https://img.shields.io/github/forks/fahise/cve-2026-109618-cve-2026-109619-poc.svg)
- [https://github.com/0xredash/CVE-2026-109618](https://github.com/0xredash/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-109618.svg)


## CVE-2026-10795
 The UpdraftPlus: WP Backup & Migration Plugin plugin for WordPress is vulnerable to Authentication Bypass in all versions up to, and including, 1.26.4 via the UpdraftPlus_Remote_Communications_V2::wp_loaded function. This is due to insufficient validation of the remote communications message format, where signature verification can be bypassed and unchecked decryption return values collapse to a predictable all-zero encryption key. This makes it possible for unauthenticated attackers to forge arbitrary RPC commands and run them as the connected administrator, such as uploading and activating a malicious plugin, which ultimately leads to remote code execution.

- [https://github.com/NilsZimmermann/wordpress-ushort-redirect-cleaner](https://github.com/NilsZimmermann/wordpress-ushort-redirect-cleaner) :  ![starts](https://img.shields.io/github/stars/NilsZimmermann/wordpress-ushort-redirect-cleaner.svg) ![forks](https://img.shields.io/github/forks/NilsZimmermann/wordpress-ushort-redirect-cleaner.svg)


## CVE-2026-10520
 An OS Command Injection vulnerability in Ivanti Sentry before the R10.5.2, R10.6.2 and R10.7.1 versions allows a remote unauthenticated user to achieve root-level remote code execution

- [https://github.com/0xredash/CVE-2026-10520](https://github.com/0xredash/CVE-2026-10520) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-10520.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-10520.svg)


## CVE-2026-9082
This issue affects Drupal core: from 8.9.0 before 10.4.10, from 10.5.0 before 10.5.10, from 10.6.0 before 10.6.9, from 11.0.0 before 11.1.10, from 11.2.0 before 11.2.12, from 11.3.0 before 11.3.10.

- [https://github.com/0xredash/CVE-2026-9082](https://github.com/0xredash/CVE-2026-9082) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-9082.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-9082.svg)


## CVE-2026-8932
the private key.

- [https://github.com/0xredash/CVE-2026-8932](https://github.com/0xredash/CVE-2026-8932) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-8932.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-8932.svg)


## CVE-2026-8461
This issue affects FFmpeg before version 8.1.2.

- [https://github.com/0xredash/CVE-2026-8461](https://github.com/0xredash/CVE-2026-8461) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-8461.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-8461.svg)


## CVE-2026-8451
 Insufficient input validation in NetScaler ADC and NetScaler Gateway leading to memory overread if NetScaler ADC or NetScaler Gateway is configured as a SAML IDP

- [https://github.com/0xredash/CVE-2026-8451](https://github.com/0xredash/CVE-2026-8451) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-8451.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-8451.svg)


## CVE-2026-7574
 Anthropic Claude Desktop Cowork VM image handling (confirmed across v1.1348.0 through v1.2278.0, including v1.1348.0, v1.1617.0, and v1.2278.0) validates only file presence and a version marker string before booting rootfs.img, but does not verify image content integrity at time-of-use. A local attacker with unprivileged code execution as the victim macOS user can modify the VM root filesystem image and have it trusted on subsequent Cowork VM boots, enabling persistent arbitrary code execution in the VM and access to host-mounted directories. The estimated CWE mapping is CWE-353 (Missing Support for Integrity Check).

- [https://github.com/0xredash/CVE-2026-7574](https://github.com/0xredash/CVE-2026-7574) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-7574.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-7574.svg)


## CVE-2026-6471
 Missing authorization in PostgreSQL logical decoding allows a non-superuser holding REPLICATION privilege to dlopen any file visible to the operating system account running the server, via the choice of logical decoding plugin.  This in turn runs arbitrary code as that account.  Versions before PostgreSQL 18.6, 17.11, 16.15, 15.19, and 14.24 are affected.

- [https://github.com/0xredash/CVE-2026-6471](https://github.com/0xredash/CVE-2026-6471) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-6471.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-6471.svg)


## CVE-2026-5173
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 16.9.6 before 18.8.9, 18.9 before 18.9.5, and 18.10 before 18.10.3 that could have allowed an authenticated user to invoke unintended server-side methods through websocket connections due to improper access control.

- [https://github.com/0xredash/CVE-2026-5173](https://github.com/0xredash/CVE-2026-5173) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-5173.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-5173.svg)


## CVE-2026-5054
The specific flaw exists within the handling of command line parameters. The issue results from the lack of proper validation of a user-supplied path prior to using it in file operations. An attacker can leverage this vulnerability to escalate privileges and execute arbitrary code in the context of root. Was ZDI-CAN-28630.

- [https://github.com/do4choo/CVE-2026-5054_NoMachine_LPE](https://github.com/do4choo/CVE-2026-5054_NoMachine_LPE) :  ![starts](https://img.shields.io/github/stars/do4choo/CVE-2026-5054_NoMachine_LPE.svg) ![forks](https://img.shields.io/github/forks/do4choo/CVE-2026-5054_NoMachine_LPE.svg)


## CVE-2026-5053
The specific flaw exists within the handling of environment variables. The issue results from the lack of proper validation of a user-supplied path prior to using it in file operations. An attacker can leverage this vulnerability to delete files in the context of root. Was ZDI-CAN-28644.

- [https://github.com/do4choo/CVE-2026-5053_NoMachine_LPE](https://github.com/do4choo/CVE-2026-5053_NoMachine_LPE) :  ![starts](https://img.shields.io/github/stars/do4choo/CVE-2026-5053_NoMachine_LPE.svg) ![forks](https://img.shields.io/github/forks/do4choo/CVE-2026-5053_NoMachine_LPE.svg)


## CVE-2026-5027
 The 'POST /api/v2/files' endpoint does not sanitize the 'filename' parameter from the multipart form data, allowing an attacker to write files to arbitrary locations on the filesystem using path traversal sequences ('../').

- [https://github.com/0xredash/CVE-2026-5027](https://github.com/0xredash/CVE-2026-5027) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-5027.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-5027.svg)


## CVE-2026-4480
substitution character without escaping shell meta characters. A remote attacker could exploit this vulnerability by sending a specially crafted print job description that contains unescaped shell characters. This could lead to remote code execution on the affected system.

- [https://github.com/0xredash/CVE-2026-4480](https://github.com/0xredash/CVE-2026-4480) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-4480.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-4480.svg)


## CVE-2026-3055
 Insufficient input validation in NetScaler ADC and NetScaler Gateway when configured as a SAML IDP leading to memory overread

- [https://github.com/0xredash/CVE-2026-3055](https://github.com/0xredash/CVE-2026-3055) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-3055.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-3055.svg)


## CVE-2026-2699
 Customer Managed ShareFile Storage Zones Controller (SZC) allows an unauthenticated attacker to access restricted configuration pages. This leads to changing system configuration and potential remote code execution.

- [https://github.com/0xredash/CVE-2026-2699](https://github.com/0xredash/CVE-2026-2699) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-2699.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-2699.svg)


## CVE-2026-1357
 The Migration, Backup, Staging – WPvivid Backup & Migration plugin for WordPress is vulnerable to Unauthenticated Arbitrary File Upload in versions up to and including 0.9.123. This is due to improper error handling in the RSA decryption process combined with a lack of path sanitization when writing uploaded files. When the plugin fails to decrypt a session key using openssl_private_decrypt(), it does not terminate execution and instead passes the boolean false value to the phpseclib library's AES cipher initialization. The library treats this false value as a string of null bytes, allowing an attacker to encrypt a malicious payload using a predictable null-byte key. Additionally, the plugin accepts filenames from the decrypted payload without sanitization, enabling directory traversal to escape the protected backup directory. This makes it possible for unauthenticated attackers to upload arbitrary PHP files to publicly accessible directories and achieve Remote Code Execution via the wpvivid_action=send_to_site parameter.

- [https://github.com/0xredash/CVE-2026-1357](https://github.com/0xredash/CVE-2026-1357) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-1357.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-1357.svg)


## CVE-2026-0770
The specific flaw exists within the handling of the exec_globals parameter provided to the validate endpoint. The issue results from the inclusion of a resource from an untrusted control sphere. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-27325.

- [https://github.com/0xredash/CVE-2026-0770](https://github.com/0xredash/CVE-2026-0770) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-0770.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-0770.svg)


## CVE-2026-0300
Prisma Access, Cloud NGFW and Panorama appliances are not impacted by this vulnerability.

- [https://github.com/0xredash/CVE-2026-0300](https://github.com/0xredash/CVE-2026-0300) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-0300.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-0300.svg)


## CVE-2026-0257
Panorama and Cloud NGFW are not impacted by these issues.

- [https://github.com/0xredash/CVE-2026-0257](https://github.com/0xredash/CVE-2026-0257) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-0257.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-0257.svg)


## CVE-2026-0073
 In adbd_tls_verify_cert of auth.cpp, there is a possible bypass of wireless ADB mutual authentication due to a logic error in the code. This could lead to remote (proximal/adjacent) code execution as the shell user with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/0xredash/CVE-2026-0073](https://github.com/0xredash/CVE-2026-0073) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2026-0073.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2026-0073.svg)


## CVE-2025-68645
 A Local File Inclusion (LFI) vulnerability exists in the Webmail Classic UI of Zimbra Collaboration (ZCS) 10.0 and 10.1 because of improper handling of user-supplied request parameters in the RestFilter servlet. An unauthenticated remote attacker can craft requests to the /h/rest endpoint to influence internal request dispatching, allowing inclusion of arbitrary files from the WebRoot directory.

- [https://github.com/0xredash/CVE-2025-68645](https://github.com/0xredash/CVE-2025-68645) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2025-68645.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2025-68645.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)


## CVE-2025-64446
 A relative path traversal vulnerability in Fortinet FortiWeb 8.0.0 through 8.0.1, FortiWeb 7.6.0 through 7.6.4, FortiWeb 7.4.0 through 7.4.9, FortiWeb 7.2.0 through 7.2.11, FortiWeb 7.0.0 through 7.0.11 may allow an attacker to execute administrative commands on the system via crafted HTTP or HTTPS requests.

- [https://github.com/0xredash/CVE-2025-64446](https://github.com/0xredash/CVE-2025-64446) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2025-64446.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2025-64446.svg)


## CVE-2025-49844
 Redis is an open source, in-memory database that persists on disk. Versions 8.2.1 and below allow an authenticated user to use a specially crafted Lua script to manipulate the garbage collector, trigger a use-after-free and potentially lead to remote code execution. The problem exists in all versions of Redis with Lua scripting. This issue is fixed in version 8.2.2. To workaround this issue without patching the redis-server executable is to prevent users from executing Lua scripts. This can be done using ACL to restrict EVAL and EVALSHA commands.

- [https://github.com/0xredash/CVE-2025-49844](https://github.com/0xredash/CVE-2025-49844) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2025-49844.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2025-49844.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/0xredash/CVE-2025-32463](https://github.com/0xredash/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2025-32463.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/0xredash/CVE-2025-32433](https://github.com/0xredash/CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2025-32433.svg)


## CVE-2025-31161
 CrushFTP 10 before 10.8.4 and 11 before 11.3.1 allows authentication bypass and takeover of the crushadmin account (unless a DMZ proxy instance is used), as exploited in the wild in March and April 2025, aka "Unauthenticated HTTP(S) port access." A race condition exists in the AWS4-HMAC (compatible with S3) authorization method of the HTTP component of the FTP server. The server first verifies the existence of the user by performing a call to login_user_pass() with no password requirement. This will authenticate the session through the HMAC verification process and up until the server checks for user verification once more. The vulnerability can be further stabilized, eliminating the need for successfully triggering a race condition, by sending a mangled AWS4-HMAC header. By providing only the username and a following slash (/), the server will successfully find a username, which triggers the successful anypass authentication process, but the server will fail to find the expected SignedHeaders entry, resulting in an index-out-of-bounds error that stops the code from reaching the session cleanup. Together, these issues make it trivial to authenticate as any known or guessable user (e.g., crushadmin), and can lead to a full compromise of the system by obtaining an administrative account.

- [https://github.com/0xredash/CVE-2025-31161](https://github.com/0xredash/CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2025-31161.svg)


## CVE-2025-14847
 Mismatched length fields in Zlib compressed protocol headers may allow a read of uninitialized heap memory by an unauthenticated client. This issue affects all MongoDB Server v7.0 prior to 7.0.28 versions, MongoDB Server v8.0 versions prior to 8.0.17, MongoDB Server v8.2 versions prior to 8.2.3, MongoDB Server v6.0 versions prior to 6.0.27, MongoDB Server v5.0 versions prior to 5.0.32, MongoDB Server v4.4 versions prior to 4.4.30, MongoDB Server v4.2 versions greater than or equal to 4.2.0, MongoDB Server v4.0 versions greater than or equal to 4.0.0, and MongoDB Server v3.6 versions greater than or equal to 3.6.0.

- [https://github.com/0xredash/CVE-2025-14847](https://github.com/0xredash/CVE-2025-14847) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2025-14847.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2025-14847.svg)


## CVE-2025-13315
 Twonky Server 8.5.2 on Linux and Windows is vulnerable to an access control flaw. An unauthenticated attacker can bypass web service API authentication controls to leak a log file and read the administrator's username and encrypted password.

- [https://github.com/0xredash/CVE-2025-13315](https://github.com/0xredash/CVE-2025-13315) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2025-13315.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2025-13315.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg)


## CVE-2025-5777
 Insufficient input validation leading to memory overread when the NetScaler is configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server

- [https://github.com/0xredash/CVE-2025-5777](https://github.com/0xredash/CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2025-5777.svg)


## CVE-2025-4960
These rights can be requested and granted by the authorization daemon to any local user, regardless of privilege level. As a result, an attacker can exploit the vulnerable service to perform privileged operations such as executing arbitrary commands or installing system components without requiring administrative credentials.

- [https://github.com/CarlosG13/CVE-2025-4960](https://github.com/CarlosG13/CVE-2025-4960) :  ![starts](https://img.shields.io/github/stars/CarlosG13/CVE-2025-4960.svg) ![forks](https://img.shields.io/github/forks/CarlosG13/CVE-2025-4960.svg)


## CVE-2024-50986
 An issue in Clementine v.1.3.1 allows a local attacker to execute arbitrary code via a crafted DLL file.

- [https://github.com/riftsandroses/CVE-2024-50986](https://github.com/riftsandroses/CVE-2024-50986) :  ![starts](https://img.shields.io/github/stars/riftsandroses/CVE-2024-50986.svg) ![forks](https://img.shields.io/github/forks/riftsandroses/CVE-2024-50986.svg)


## CVE-2024-49328
 Authentication Bypass Using an Alternate Path or Channel vulnerability in vivek2tamrakar WP REST API FNS rest-api-fns allows Authentication Bypass.This issue affects WP REST API FNS: from n/a through = 1.0.0.

- [https://github.com/RandomRobbieBF/CVE-2024-49328](https://github.com/RandomRobbieBF/CVE-2024-49328) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-49328.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-49328.svg)
- [https://github.com/Nxploited/CVE-2024-49328-exploit](https://github.com/Nxploited/CVE-2024-49328-exploit) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2024-49328-exploit.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2024-49328-exploit.svg)


## CVE-2024-43630
 Windows Kernel Elevation of Privilege Vulnerability

- [https://github.com/QuasarBinary/CVE-2024-43630-POC](https://github.com/QuasarBinary/CVE-2024-43630-POC) :  ![starts](https://img.shields.io/github/stars/QuasarBinary/CVE-2024-43630-POC.svg) ![forks](https://img.shields.io/github/forks/QuasarBinary/CVE-2024-43630-POC.svg)


## CVE-2024-43583
 Winlogon Elevation of Privilege Vulnerability

- [https://github.com/Kvngtheta/CVE-2024-43583-PoC](https://github.com/Kvngtheta/CVE-2024-43583-PoC) :  ![starts](https://img.shields.io/github/stars/Kvngtheta/CVE-2024-43583-PoC.svg) ![forks](https://img.shields.io/github/forks/Kvngtheta/CVE-2024-43583-PoC.svg)


## CVE-2024-43570
 Windows Kernel Elevation of Privilege Vulnerability

- [https://github.com/jayesther/KTM_POCS](https://github.com/jayesther/KTM_POCS) :  ![starts](https://img.shields.io/github/stars/jayesther/KTM_POCS.svg) ![forks](https://img.shields.io/github/forks/jayesther/KTM_POCS.svg)


## CVE-2024-43425
 A flaw was found in Moodle. Additional restrictions are required to avoid a remote code execution risk in calculated question types. Note: This requires the capability to add/update questions.

- [https://github.com/RedTeamPentesting/moodle-rce-calculatedquestions](https://github.com/RedTeamPentesting/moodle-rce-calculatedquestions) :  ![starts](https://img.shields.io/github/stars/RedTeamPentesting/moodle-rce-calculatedquestions.svg) ![forks](https://img.shields.io/github/forks/RedTeamPentesting/moodle-rce-calculatedquestions.svg)
- [https://github.com/Snizi/Moodle-CVE-2024-43425-Exploit](https://github.com/Snizi/Moodle-CVE-2024-43425-Exploit) :  ![starts](https://img.shields.io/github/stars/Snizi/Moodle-CVE-2024-43425-Exploit.svg) ![forks](https://img.shields.io/github/forks/Snizi/Moodle-CVE-2024-43425-Exploit.svg)
- [https://github.com/kazuya256/Moodle-authenticated-RCE](https://github.com/kazuya256/Moodle-authenticated-RCE) :  ![starts](https://img.shields.io/github/stars/kazuya256/Moodle-authenticated-RCE.svg) ![forks](https://img.shields.io/github/forks/kazuya256/Moodle-authenticated-RCE.svg)
- [https://github.com/Tnot123/cve-2024-43425](https://github.com/Tnot123/cve-2024-43425) :  ![starts](https://img.shields.io/github/stars/Tnot123/cve-2024-43425.svg) ![forks](https://img.shields.io/github/forks/Tnot123/cve-2024-43425.svg)
- [https://github.com/aninfosec/CVE-2024-43425-Poc](https://github.com/aninfosec/CVE-2024-43425-Poc) :  ![starts](https://img.shields.io/github/stars/aninfosec/CVE-2024-43425-Poc.svg) ![forks](https://img.shields.io/github/forks/aninfosec/CVE-2024-43425-Poc.svg)
- [https://github.com/vuductruong12/KTLHPM](https://github.com/vuductruong12/KTLHPM) :  ![starts](https://img.shields.io/github/stars/vuductruong12/KTLHPM.svg) ![forks](https://img.shields.io/github/forks/vuductruong12/KTLHPM.svg)


## CVE-2024-43416
 GLPI is a free asset and IT management software package. Starting in version 0.80 and prior to version 10.0.17, an unauthenticated user can use an application endpoint to check if an email address corresponds to a valid GLPI user. Version 10.0.17 fixes the issue.

- [https://github.com/0xmupa/CVE-2024-43416-PoC](https://github.com/0xmupa/CVE-2024-43416-PoC) :  ![starts](https://img.shields.io/github/stars/0xmupa/CVE-2024-43416-PoC.svg) ![forks](https://img.shields.io/github/forks/0xmupa/CVE-2024-43416-PoC.svg)


## CVE-2024-43400
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. It is possible for a user without Script or Programming rights to craft a URL pointing to a page with arbitrary JavaScript. This requires social engineer to trick a user to follow the URL. This has been patched in XWiki 14.10.21, 15.5.5, 15.10.6 and 16.0.0.

- [https://github.com/rain321654/CVE-2024-43400](https://github.com/rain321654/CVE-2024-43400) :  ![starts](https://img.shields.io/github/stars/rain321654/CVE-2024-43400.svg) ![forks](https://img.shields.io/github/forks/rain321654/CVE-2024-43400.svg)
- [https://github.com/rain321654/yasa-cve-2024-43400-main1](https://github.com/rain321654/yasa-cve-2024-43400-main1) :  ![starts](https://img.shields.io/github/stars/rain321654/yasa-cve-2024-43400-main1.svg) ![forks](https://img.shields.io/github/forks/rain321654/yasa-cve-2024-43400-main1.svg)


## CVE-2024-43093
 In shouldHideDocument of ExternalStorageProvider.java, there is a possible bypass of a file path filter designed to prevent access to sensitive directories due to  incorrect unicode normalization. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.

- [https://github.com/xiaoxiaoyu78/gki-unicode-fix](https://github.com/xiaoxiaoyu78/gki-unicode-fix) :  ![starts](https://img.shields.io/github/stars/xiaoxiaoyu78/gki-unicode-fix.svg) ![forks](https://img.shields.io/github/forks/xiaoxiaoyu78/gki-unicode-fix.svg)


## CVE-2024-36886
---truncated---

- [https://github.com/abubakar-shahid/CVE-2024-36886](https://github.com/abubakar-shahid/CVE-2024-36886) :  ![starts](https://img.shields.io/github/stars/abubakar-shahid/CVE-2024-36886.svg) ![forks](https://img.shields.io/github/forks/abubakar-shahid/CVE-2024-36886.svg)


## CVE-2024-32136
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Xenioushk BWL Advanced FAQ Manager.This issue affects BWL Advanced FAQ Manager: from n/a through 2.0.3.

- [https://github.com/xbz0n/CVE-2024-32136](https://github.com/xbz0n/CVE-2024-32136) :  ![starts](https://img.shields.io/github/stars/xbz0n/CVE-2024-32136.svg) ![forks](https://img.shields.io/github/forks/xbz0n/CVE-2024-32136.svg)


## CVE-2024-31851
 A path traversal vulnerability exists in the Java version of CData Sync  23.4.8843 when running using the embedded Jetty server, which could allow an unauthenticated remote attacker to gain access to sensitive information and perform limited actions.

- [https://github.com/Stuub/CVE-2024-31848-PoC](https://github.com/Stuub/CVE-2024-31848-PoC) :  ![starts](https://img.shields.io/github/stars/Stuub/CVE-2024-31848-PoC.svg) ![forks](https://img.shields.io/github/forks/Stuub/CVE-2024-31848-PoC.svg)


## CVE-2024-31850
 A path traversal vulnerability exists in the Java version of CData Arc  23.4.8839 when running using the embedded Jetty server, which could allow an unauthenticated remote attacker to gain access to sensitive information and perform limited actions.

- [https://github.com/Stuub/CVE-2024-31848-PoC](https://github.com/Stuub/CVE-2024-31848-PoC) :  ![starts](https://img.shields.io/github/stars/Stuub/CVE-2024-31848-PoC.svg) ![forks](https://img.shields.io/github/forks/Stuub/CVE-2024-31848-PoC.svg)


## CVE-2024-31849
 A path traversal vulnerability exists in the Java version of CData Connect  23.4.8846 when running using the embedded Jetty server, which could allow an unauthenticated remote attacker to gain complete administrative access to the application.

- [https://github.com/Stuub/CVE-2024-31848-PoC](https://github.com/Stuub/CVE-2024-31848-PoC) :  ![starts](https://img.shields.io/github/stars/Stuub/CVE-2024-31848-PoC.svg) ![forks](https://img.shields.io/github/forks/Stuub/CVE-2024-31848-PoC.svg)


## CVE-2024-31848
 A path traversal vulnerability exists in the Java version of CData API Server  23.4.8844 when running using the embedded Jetty server, which could allow an unauthenticated remote attacker to gain complete administrative access to the application.

- [https://github.com/Stuub/CVE-2024-31848-PoC](https://github.com/Stuub/CVE-2024-31848-PoC) :  ![starts](https://img.shields.io/github/stars/Stuub/CVE-2024-31848-PoC.svg) ![forks](https://img.shields.io/github/forks/Stuub/CVE-2024-31848-PoC.svg)


## CVE-2024-31777
 File Upload vulnerability in openeclass v.3.15 and before allows an attacker to execute arbitrary code via a crafted file to the certbadge.php endpoint.

- [https://github.com/FreySolarEye/Exploit-CVE-2024-31777](https://github.com/FreySolarEye/Exploit-CVE-2024-31777) :  ![starts](https://img.shields.io/github/stars/FreySolarEye/Exploit-CVE-2024-31777.svg) ![forks](https://img.shields.io/github/forks/FreySolarEye/Exploit-CVE-2024-31777.svg)


## CVE-2024-31771
 Insecure Permission vulnerability in TotalAV v.6.0.740 allows a local attacker to escalate privileges via a crafted file

- [https://github.com/restdone/CVE-2024-31771](https://github.com/restdone/CVE-2024-31771) :  ![starts](https://img.shields.io/github/stars/restdone/CVE-2024-31771.svg) ![forks](https://img.shields.io/github/forks/restdone/CVE-2024-31771.svg)


## CVE-2024-30896
 InfluxDB OSS 2.x through 2.7.11 stores the administrative operator token under the default organization which allows authorized users with read access to the authorization resource of the default organization to retrieve the operator token. InfluxDB OSS 1.x, Enterprise, Cloud, Cloud Dedicated and Clustered are not affected. NOTE: The researcher states that InfluxDB allows allAccess administrators to retrieve all raw tokens via an "influx auth ls" command. The supplier indicates that the organizations feature is operating as intended and that users may choose to add users to non-default organizations. A future release of InfluxDB 2.x will remove the ability to retrieve tokens from the API. The supplier has stated that InfluxDB 2.8.0 has addressed this issue.

- [https://github.com/XenoM0rph97/CVE-2024-30896](https://github.com/XenoM0rph97/CVE-2024-30896) :  ![starts](https://img.shields.io/github/stars/XenoM0rph97/CVE-2024-30896.svg) ![forks](https://img.shields.io/github/forks/XenoM0rph97/CVE-2024-30896.svg)


## CVE-2024-28397
 An issue in the component js2py.disable_pyimport() of js2py up to v0.74 allows attackers to execute arbitrary code via a crafted API call.

- [https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape](https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape) :  ![starts](https://img.shields.io/github/stars/Marven11/CVE-2024-28397-js2py-Sandbox-Escape.svg) ![forks](https://img.shields.io/github/forks/Marven11/CVE-2024-28397-js2py-Sandbox-Escape.svg)
- [https://github.com/naclapor/CVE-2024-28397](https://github.com/naclapor/CVE-2024-28397) :  ![starts](https://img.shields.io/github/stars/naclapor/CVE-2024-28397.svg) ![forks](https://img.shields.io/github/forks/naclapor/CVE-2024-28397.svg)
- [https://github.com/GhostOverflow/CVE-2024-28397-command-execution-poc](https://github.com/GhostOverflow/CVE-2024-28397-command-execution-poc) :  ![starts](https://img.shields.io/github/stars/GhostOverflow/CVE-2024-28397-command-execution-poc.svg) ![forks](https://img.shields.io/github/forks/GhostOverflow/CVE-2024-28397-command-execution-poc.svg)
- [https://github.com/L1337Xi/CVE-2024-28397-Exploit-Automation](https://github.com/L1337Xi/CVE-2024-28397-Exploit-Automation) :  ![starts](https://img.shields.io/github/stars/L1337Xi/CVE-2024-28397-Exploit-Automation.svg) ![forks](https://img.shields.io/github/forks/L1337Xi/CVE-2024-28397-Exploit-Automation.svg)
- [https://github.com/xeloxa/CVE-2024-28397-Js2Py-RCE-Exploit](https://github.com/xeloxa/CVE-2024-28397-Js2Py-RCE-Exploit) :  ![starts](https://img.shields.io/github/stars/xeloxa/CVE-2024-28397-Js2Py-RCE-Exploit.svg) ![forks](https://img.shields.io/github/forks/xeloxa/CVE-2024-28397-Js2Py-RCE-Exploit.svg)
- [https://github.com/somisec/CVE-2024-28397-Reverse-Shell](https://github.com/somisec/CVE-2024-28397-Reverse-Shell) :  ![starts](https://img.shields.io/github/stars/somisec/CVE-2024-28397-Reverse-Shell.svg) ![forks](https://img.shields.io/github/forks/somisec/CVE-2024-28397-Reverse-Shell.svg)
- [https://github.com/harutomo-jp/CVE-2024-28397-RCE](https://github.com/harutomo-jp/CVE-2024-28397-RCE) :  ![starts](https://img.shields.io/github/stars/harutomo-jp/CVE-2024-28397-RCE.svg) ![forks](https://img.shields.io/github/forks/harutomo-jp/CVE-2024-28397-RCE.svg)
- [https://github.com/Naved124/CVE-2024-28397-js2py-Sandbox-Escape](https://github.com/Naved124/CVE-2024-28397-js2py-Sandbox-Escape) :  ![starts](https://img.shields.io/github/stars/Naved124/CVE-2024-28397-js2py-Sandbox-Escape.svg) ![forks](https://img.shields.io/github/forks/Naved124/CVE-2024-28397-js2py-Sandbox-Escape.svg)
- [https://github.com/RianJuniorSf/exploit-js2py](https://github.com/RianJuniorSf/exploit-js2py) :  ![starts](https://img.shields.io/github/stars/RianJuniorSf/exploit-js2py.svg) ![forks](https://img.shields.io/github/forks/RianJuniorSf/exploit-js2py.svg)
- [https://github.com/vitaciminIPI/CVE-2024-28397-RCE](https://github.com/vitaciminIPI/CVE-2024-28397-RCE) :  ![starts](https://img.shields.io/github/stars/vitaciminIPI/CVE-2024-28397-RCE.svg) ![forks](https://img.shields.io/github/forks/vitaciminIPI/CVE-2024-28397-RCE.svg)
- [https://github.com/3z-p0wn/CVE-2024-28397-exploit](https://github.com/3z-p0wn/CVE-2024-28397-exploit) :  ![starts](https://img.shields.io/github/stars/3z-p0wn/CVE-2024-28397-exploit.svg) ![forks](https://img.shields.io/github/forks/3z-p0wn/CVE-2024-28397-exploit.svg)
- [https://github.com/kyl0-ST12/CVE_2024_28397---js2py-RCE](https://github.com/kyl0-ST12/CVE_2024_28397---js2py-RCE) :  ![starts](https://img.shields.io/github/stars/kyl0-ST12/CVE_2024_28397---js2py-RCE.svg) ![forks](https://img.shields.io/github/forks/kyl0-ST12/CVE_2024_28397---js2py-RCE.svg)
- [https://github.com/y0naldez/CVE-2024-28397-Js2Py-RCE](https://github.com/y0naldez/CVE-2024-28397-Js2Py-RCE) :  ![starts](https://img.shields.io/github/stars/y0naldez/CVE-2024-28397-Js2Py-RCE.svg) ![forks](https://img.shields.io/github/forks/y0naldez/CVE-2024-28397-Js2Py-RCE.svg)
- [https://github.com/D3ltaFormation/CVE-2024-28397-Js2Py-RCE](https://github.com/D3ltaFormation/CVE-2024-28397-Js2Py-RCE) :  ![starts](https://img.shields.io/github/stars/D3ltaFormation/CVE-2024-28397-Js2Py-RCE.svg) ![forks](https://img.shields.io/github/forks/D3ltaFormation/CVE-2024-28397-Js2Py-RCE.svg)
- [https://github.com/CYBER-WARRIOR-SEC/CVE-2024-28397-js2py-Sandbox-Escape](https://github.com/CYBER-WARRIOR-SEC/CVE-2024-28397-js2py-Sandbox-Escape) :  ![starts](https://img.shields.io/github/stars/CYBER-WARRIOR-SEC/CVE-2024-28397-js2py-Sandbox-Escape.svg) ![forks](https://img.shields.io/github/forks/CYBER-WARRIOR-SEC/CVE-2024-28397-js2py-Sandbox-Escape.svg)
- [https://github.com/0xDTC/js2py-Sandbox-Escape-CVE-2024-28397-RCE](https://github.com/0xDTC/js2py-Sandbox-Escape-CVE-2024-28397-RCE) :  ![starts](https://img.shields.io/github/stars/0xDTC/js2py-Sandbox-Escape-CVE-2024-28397-RCE.svg) ![forks](https://img.shields.io/github/forks/0xDTC/js2py-Sandbox-Escape-CVE-2024-28397-RCE.svg)
- [https://github.com/Udayveer17/Remote-Code-Execution-CVE-2024-28397-pyload-ng-js2py-](https://github.com/Udayveer17/Remote-Code-Execution-CVE-2024-28397-pyload-ng-js2py-) :  ![starts](https://img.shields.io/github/stars/Udayveer17/Remote-Code-Execution-CVE-2024-28397-pyload-ng-js2py-.svg) ![forks](https://img.shields.io/github/forks/Udayveer17/Remote-Code-Execution-CVE-2024-28397-pyload-ng-js2py-.svg)


## CVE-2024-28182
 nghttp2 is an implementation of the Hypertext Transfer Protocol version 2 in C. The nghttp2 library prior to version 1.61.0 keeps reading the unbounded number of HTTP/2 CONTINUATION frames even after a stream is reset to keep HPACK context in sync.  This causes excessive CPU usage to decode HPACK stream. nghttp2 v1.61.0 mitigates this vulnerability by limiting the number of CONTINUATION frames it accepts per stream. There is no workaround for this vulnerability.

- [https://github.com/lockness-Ko/CVE-2024-27316](https://github.com/lockness-Ko/CVE-2024-27316) :  ![starts](https://img.shields.io/github/stars/lockness-Ko/CVE-2024-27316.svg) ![forks](https://img.shields.io/github/forks/lockness-Ko/CVE-2024-27316.svg)


## CVE-2024-27983
 An attacker can make the Node.js HTTP/2 server completely unavailable by sending a small amount of HTTP/2 frames packets with a few HTTP/2 frames inside. It is possible to leave some data in nghttp2 memory after reset when headers with HTTP/2 CONTINUATION frame are sent to the server and then a TCP connection is abruptly closed by the client triggering the Http2Session destructor while header frames are still being processed (and stored in memory) causing a race condition.

- [https://github.com/lirantal/CVE-2024-27983-nodejs-http2](https://github.com/lirantal/CVE-2024-27983-nodejs-http2) :  ![starts](https://img.shields.io/github/stars/lirantal/CVE-2024-27983-nodejs-http2.svg) ![forks](https://img.shields.io/github/forks/lirantal/CVE-2024-27983-nodejs-http2.svg)


## CVE-2024-27674
 Macro Expert through 4.9.4 allows BUILTIN\Users:(OI)(CI)(M) access to the "%PROGRAMFILES(X86)%\GrassSoft\Macro Expert" folder and thus an unprivileged user can escalate to SYSTEM by replacing the MacroService.exe binary.

- [https://github.com/Alaatk/CVE-2024-27674](https://github.com/Alaatk/CVE-2024-27674) :  ![starts](https://img.shields.io/github/stars/Alaatk/CVE-2024-27674.svg) ![forks](https://img.shields.io/github/forks/Alaatk/CVE-2024-27674.svg)


## CVE-2024-27673
 DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was withdrawn by its CNA. Further investigation showed that it was not a security issue. Notes: none.

- [https://github.com/Alaatk/CVE-2024-27673](https://github.com/Alaatk/CVE-2024-27673) :  ![starts](https://img.shields.io/github/stars/Alaatk/CVE-2024-27673.svg) ![forks](https://img.shields.io/github/forks/Alaatk/CVE-2024-27673.svg)


## CVE-2024-27665
 Unifiedtransform v2.X is vulnerable to Stored Cross-Site Scripting (XSS) via file upload feature in Syllabus module.

- [https://github.com/Thirukrishnan/CVE-2024-27665](https://github.com/Thirukrishnan/CVE-2024-27665) :  ![starts](https://img.shields.io/github/stars/Thirukrishnan/CVE-2024-27665.svg) ![forks](https://img.shields.io/github/forks/Thirukrishnan/CVE-2024-27665.svg)


## CVE-2024-27632
 An issue in GNU Savane v.3.12 and before allows a remote attacker to escalate privileges via the form_id in the form_header() function.

- [https://github.com/ally-petitt/CVE-2024-27632](https://github.com/ally-petitt/CVE-2024-27632) :  ![starts](https://img.shields.io/github/stars/ally-petitt/CVE-2024-27632.svg) ![forks](https://img.shields.io/github/forks/ally-petitt/CVE-2024-27632.svg)


## CVE-2024-27631
 Cross Site Request Forgery vulnerability in GNU Savane v.3.12 and before allows a remote attacker to escalate privileges via siteadmin/usergroup.php

- [https://github.com/ally-petitt/CVE-2024-27631](https://github.com/ally-petitt/CVE-2024-27631) :  ![starts](https://img.shields.io/github/stars/ally-petitt/CVE-2024-27631.svg) ![forks](https://img.shields.io/github/forks/ally-petitt/CVE-2024-27631.svg)


## CVE-2024-27130
QuTS hero h5.1.7.2770 build 20240520 and later

- [https://github.com/watchtowrlabs/CVE-2024-27130](https://github.com/watchtowrlabs/CVE-2024-27130) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/CVE-2024-27130.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/CVE-2024-27130.svg)


## CVE-2024-26574
 Insecure Permissions vulnerability in Wondershare Filmora v.13.0.51 allows a local attacker to execute arbitrary code via a crafted script to the WSNativePushService.exe

- [https://github.com/Alaatk/CVE-2024-26574](https://github.com/Alaatk/CVE-2024-26574) :  ![starts](https://img.shields.io/github/stars/Alaatk/CVE-2024-26574.svg) ![forks](https://img.shields.io/github/forks/Alaatk/CVE-2024-26574.svg)


## CVE-2024-23897
 Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.

- [https://github.com/foreverlanterns/secure-api-cve-2024-23897](https://github.com/foreverlanterns/secure-api-cve-2024-23897) :  ![starts](https://img.shields.io/github/stars/foreverlanterns/secure-api-cve-2024-23897.svg) ![forks](https://img.shields.io/github/forks/foreverlanterns/secure-api-cve-2024-23897.svg)


## CVE-2024-23738
 An issue in Postman version 10.22 and before on macOS allows a remote attacker to execute arbitrary code via the RunAsNode and enableNodeClilnspectArguments settings. NOTE: the vendor states "we dispute the report's accuracy ... the configuration does not enable remote code execution.."

- [https://github.com/giovannipajeu1/CVE-2024-23738](https://github.com/giovannipajeu1/CVE-2024-23738) :  ![starts](https://img.shields.io/github/stars/giovannipajeu1/CVE-2024-23738.svg) ![forks](https://img.shields.io/github/forks/giovannipajeu1/CVE-2024-23738.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/kokilyadm/waffers](https://github.com/kokilyadm/waffers) :  ![starts](https://img.shields.io/github/stars/kokilyadm/waffers.svg) ![forks](https://img.shields.io/github/forks/kokilyadm/waffers.svg)


## CVE-2024-4358
 In Progress Telerik Report Server, version 2024 Q1 (10.0.24.305) or earlier, on IIS, an unauthenticated attacker can gain access to Telerik Report Server restricted functionality via an authentication bypass vulnerability.

- [https://github.com/sinsinology/CVE-2024-4358](https://github.com/sinsinology/CVE-2024-4358) :  ![starts](https://img.shields.io/github/stars/sinsinology/CVE-2024-4358.svg) ![forks](https://img.shields.io/github/forks/sinsinology/CVE-2024-4358.svg)
- [https://github.com/Sk1dr0wz/CVE-2024-4358_Mass_Exploit](https://github.com/Sk1dr0wz/CVE-2024-4358_Mass_Exploit) :  ![starts](https://img.shields.io/github/stars/Sk1dr0wz/CVE-2024-4358_Mass_Exploit.svg) ![forks](https://img.shields.io/github/forks/Sk1dr0wz/CVE-2024-4358_Mass_Exploit.svg)
- [https://github.com/verylazytech/CVE-2024-4358](https://github.com/verylazytech/CVE-2024-4358) :  ![starts](https://img.shields.io/github/stars/verylazytech/CVE-2024-4358.svg) ![forks](https://img.shields.io/github/forks/verylazytech/CVE-2024-4358.svg)
- [https://github.com/RevoltSecurities/CVE-2024-4358](https://github.com/RevoltSecurities/CVE-2024-4358) :  ![starts](https://img.shields.io/github/stars/RevoltSecurities/CVE-2024-4358.svg) ![forks](https://img.shields.io/github/forks/RevoltSecurities/CVE-2024-4358.svg)
- [https://github.com/gh-ost00/CVE-2024-4358](https://github.com/gh-ost00/CVE-2024-4358) :  ![starts](https://img.shields.io/github/stars/gh-ost00/CVE-2024-4358.svg) ![forks](https://img.shields.io/github/forks/gh-ost00/CVE-2024-4358.svg)
- [https://github.com/Harydhk7/CVE-2024-4358](https://github.com/Harydhk7/CVE-2024-4358) :  ![starts](https://img.shields.io/github/stars/Harydhk7/CVE-2024-4358.svg) ![forks](https://img.shields.io/github/forks/Harydhk7/CVE-2024-4358.svg)


## CVE-2024-4320
 A remote code execution (RCE) vulnerability exists in the '/install_extension' endpoint of the parisneo/lollms-webui application, specifically within the `@router.post("/install_extension")` route handler. The vulnerability arises due to improper handling of the `name` parameter in the `ExtensionBuilder().build_extension()` method, which allows for local file inclusion (LFI) leading to arbitrary code execution. An attacker can exploit this vulnerability by crafting a malicious `name` parameter that causes the server to load and execute a `__init__.py` file from an arbitrary location, such as the upload directory for discussions. This vulnerability affects the latest version of parisneo/lollms-webui and can lead to remote code execution without requiring user interaction, especially when the application is exposed to an external endpoint or operated in headless mode.

- [https://github.com/bolkv/CVE-2024-4320](https://github.com/bolkv/CVE-2024-4320) :  ![starts](https://img.shields.io/github/stars/bolkv/CVE-2024-4320.svg) ![forks](https://img.shields.io/github/forks/bolkv/CVE-2024-4320.svg)


## CVE-2024-4295
 The Email Subscribers by Icegram Express plugin for WordPress is vulnerable to SQL Injection via the ‘hash’ parameter in all versions up to, and including, 5.7.20 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/TgHook/CVE-2024-4295-Poc](https://github.com/TgHook/CVE-2024-4295-Poc) :  ![starts](https://img.shields.io/github/stars/TgHook/CVE-2024-4295-Poc.svg) ![forks](https://img.shields.io/github/forks/TgHook/CVE-2024-4295-Poc.svg)
- [https://github.com/cve-2024/CVE-2024-4295-Poc](https://github.com/cve-2024/CVE-2024-4295-Poc) :  ![starts](https://img.shields.io/github/stars/cve-2024/CVE-2024-4295-Poc.svg) ![forks](https://img.shields.io/github/forks/cve-2024/CVE-2024-4295-Poc.svg)


## CVE-2024-3690
 A vulnerability classified as critical was found in PHPGurukul Small CRM 3.0. Affected by this vulnerability is an unknown functionality of the component Change Password Handler. The manipulation leads to sql injection. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-260479.

- [https://github.com/taeseongk/CVE-2024-3690](https://github.com/taeseongk/CVE-2024-3690) :  ![starts](https://img.shields.io/github/stars/taeseongk/CVE-2024-3690.svg) ![forks](https://img.shields.io/github/forks/taeseongk/CVE-2024-3690.svg)


## CVE-2024-3177
 A security issue was discovered in Kubernetes where users may be able to launch containers that bypass the mountable secrets policy enforced by the ServiceAccount admission plugin when using containers, init containers, and ephemeral containers with the envFrom field populated. The policy ensures pods running with a service account may only reference secrets specified in the service account’s secrets field. Kubernetes clusters are only affected if the ServiceAccount admission plugin and the kubernetes.io/enforce-mountable-secrets annotation are used together with containers, init containers, and ephemeral containers with the envFrom field populated.

- [https://github.com/Cgv-Dev/Metasploit-Module-TFM](https://github.com/Cgv-Dev/Metasploit-Module-TFM) :  ![starts](https://img.shields.io/github/stars/Cgv-Dev/Metasploit-Module-TFM.svg) ![forks](https://img.shields.io/github/forks/Cgv-Dev/Metasploit-Module-TFM.svg)


## CVE-2024-3094
Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.

- [https://github.com/0xredash/CVE-2024-3094](https://github.com/0xredash/CVE-2024-3094) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2024-3094.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2024-3094.svg)


## CVE-2024-2961
 The iconv() function in the GNU C Library versions 2.39 and older may overflow the output buffer passed to it by up to 4 bytes when converting strings to the ISO-2022-CN-EXT character set, which may be used to crash an application or overwrite a neighbouring variable.

- [https://github.com/kokilyadm/waffers](https://github.com/kokilyadm/waffers) :  ![starts](https://img.shields.io/github/stars/kokilyadm/waffers.svg) ![forks](https://img.shields.io/github/forks/kokilyadm/waffers.svg)


## CVE-2023-27524
Alternatively you can set it with `SUPERSET_SECRET_KEY` environment variable.

- [https://github.com/sifatnotes/secbyte-cve-exploitation-real-world-vulnerabilities-red-teaming-ctf-labs](https://github.com/sifatnotes/secbyte-cve-exploitation-real-world-vulnerabilities-red-teaming-ctf-labs) :  ![starts](https://img.shields.io/github/stars/sifatnotes/secbyte-cve-exploitation-real-world-vulnerabilities-red-teaming-ctf-labs.svg) ![forks](https://img.shields.io/github/forks/sifatnotes/secbyte-cve-exploitation-real-world-vulnerabilities-red-teaming-ctf-labs.svg)


## CVE-2023-7356
the service UUID is Basic Audio Announcement Service UUID.

- [https://github.com/mehmet-emir-eroglu/CVE-2023-7356](https://github.com/mehmet-emir-eroglu/CVE-2023-7356) :  ![starts](https://img.shields.io/github/stars/mehmet-emir-eroglu/CVE-2023-7356.svg) ![forks](https://img.shields.io/github/forks/mehmet-emir-eroglu/CVE-2023-7356.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/0xredash/CVE-2022-22965](https://github.com/0xredash/CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2022-22965.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/osungjinwoo/CVE-2022-0847-Dirty-Pipe](https://github.com/osungjinwoo/CVE-2022-0847-Dirty-Pipe) :  ![starts](https://img.shields.io/github/stars/osungjinwoo/CVE-2022-0847-Dirty-Pipe.svg) ![forks](https://img.shields.io/github/forks/osungjinwoo/CVE-2022-0847-Dirty-Pipe.svg)


## CVE-2021-40444
UPDATE September 14, 2021: Microsoft has released security updates to address this vulnerability. Please see the Security Updates table for the applicable update for your system. We recommend that you install these updates immediately. Please see the FAQ for important information about which updates are applicable to your system.

- [https://github.com/m4madturk/CVE-2021-40444](https://github.com/m4madturk/CVE-2021-40444) :  ![starts](https://img.shields.io/github/stars/m4madturk/CVE-2021-40444.svg) ![forks](https://img.shields.io/github/forks/m4madturk/CVE-2021-40444.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/Super-Binary/cve-2021-44228](https://github.com/Super-Binary/cve-2021-44228) :  ![starts](https://img.shields.io/github/stars/Super-Binary/cve-2021-44228.svg) ![forks](https://img.shields.io/github/forks/Super-Binary/cve-2021-44228.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/zer0qs/CVE-2021-41773](https://github.com/zer0qs/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/zer0qs/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/zer0qs/CVE-2021-41773.svg)
- [https://github.com/gunzf0x/CVE-2021-41773](https://github.com/gunzf0x/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/gunzf0x/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/gunzf0x/CVE-2021-41773.svg)
- [https://github.com/sotiak/CVE-2021-41773](https://github.com/sotiak/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sotiak/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sotiak/CVE-2021-41773.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/jscamposx/hack](https://github.com/jscamposx/hack) :  ![starts](https://img.shields.io/github/stars/jscamposx/hack.svg) ![forks](https://img.shields.io/github/forks/jscamposx/hack.svg)


## CVE-2020-17103
 Windows Cloud Files Mini Filter Driver Elevation of Privilege Vulnerability

- [https://github.com/0xredash/CVE-2020-17103](https://github.com/0xredash/CVE-2020-17103) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2020-17103.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2020-17103.svg)


## CVE-2020-5902
 In BIG-IP versions 15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 13.1.0-13.1.3.3, 12.1.0-12.1.5.1, and 11.6.1-11.6.5.1, the Traffic Management User Interface (TMUI), also referred to as the Configuration utility, has a Remote Code Execution (RCE) vulnerability in undisclosed pages.

- [https://github.com/0xredash/CVE-2020-5902](https://github.com/0xredash/CVE-2020-5902) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2020-5902.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2020-5902.svg)


## CVE-2019-18980
 On Signify Philips Taolight Smart Wi-Fi Wiz Connected LED Bulb 9290022656 devices, an unprotected API lets remote users control the bulb's operation. Anyone can turn the bulb on or off, or change its color or brightness remotely. There is no authentication or encryption to use the control API. The only requirement is that the attacker have network access to the bulb.

- [https://github.com/anmolksachan/wiz-bulb-tool](https://github.com/anmolksachan/wiz-bulb-tool) :  ![starts](https://img.shields.io/github/stars/anmolksachan/wiz-bulb-tool.svg) ![forks](https://img.shields.io/github/forks/anmolksachan/wiz-bulb-tool.svg)


## CVE-2018-17463
 Incorrect side effect annotation in V8 in Google Chrome prior to 70.0.3538.64 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page.

- [https://github.com/bianchiSLR/cve-2018-17463-lab](https://github.com/bianchiSLR/cve-2018-17463-lab) :  ![starts](https://img.shields.io/github/stars/bianchiSLR/cve-2018-17463-lab.svg) ![forks](https://img.shields.io/github/forks/bianchiSLR/cve-2018-17463-lab.svg)


## CVE-2017-11882
 Microsoft Office 2007 Service Pack 3, Microsoft Office 2010 Service Pack 2, Microsoft Office 2013 Service Pack 1, and Microsoft Office 2016 allow an attacker to run arbitrary code in the context of the current user by failing to properly handle objects in memory, aka "Microsoft Office Memory Corruption Vulnerability". This CVE ID is unique from CVE-2017-11884.

- [https://github.com/wunmi-commits/phishing-analysis-thm](https://github.com/wunmi-commits/phishing-analysis-thm) :  ![starts](https://img.shields.io/github/stars/wunmi-commits/phishing-analysis-thm.svg) ![forks](https://img.shields.io/github/forks/wunmi-commits/phishing-analysis-thm.svg)


## CVE-2017-0144
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/0xredash/CVE-2017-0144](https://github.com/0xredash/CVE-2017-0144) :  ![starts](https://img.shields.io/github/stars/0xredash/CVE-2017-0144.svg) ![forks](https://img.shields.io/github/forks/0xredash/CVE-2017-0144.svg)


## CVE-2016-3427
 Unspecified vulnerability in Oracle Java SE 6u113, 7u99, and 8u77; Java SE Embedded 8u77; and JRockit R28.3.9 allows remote attackers to affect confidentiality, integrity, and availability via vectors related to JMX.

- [https://github.com/qtc-de/beanshooter](https://github.com/qtc-de/beanshooter) :  ![starts](https://img.shields.io/github/stars/qtc-de/beanshooter.svg) ![forks](https://img.shields.io/github/forks/qtc-de/beanshooter.svg)


## CVE-2014-7921
 mediaserver in Android 4.0.3 through 5.x before 5.1 allows attackers to gain privileges.  NOTE: This is a different vulnerability than CVE-2014-7920.

- [https://github.com/laginimaineb/cve-2014-7920-7921](https://github.com/laginimaineb/cve-2014-7920-7921) :  ![starts](https://img.shields.io/github/stars/laginimaineb/cve-2014-7920-7921.svg) ![forks](https://img.shields.io/github/forks/laginimaineb/cve-2014-7920-7921.svg)


## CVE-2014-7920
 mediaserver in Android 2.2 through 5.x before 5.1 allows attackers to gain privileges.  NOTE: This is a different vulnerability than CVE-2014-7921.

- [https://github.com/laginimaineb/cve-2014-7920-7921](https://github.com/laginimaineb/cve-2014-7920-7921) :  ![starts](https://img.shields.io/github/stars/laginimaineb/cve-2014-7920-7921.svg) ![forks](https://img.shields.io/github/forks/laginimaineb/cve-2014-7920-7921.svg)
- [https://github.com/Vinc3nt4H/cve-2014-7920-7921_update](https://github.com/Vinc3nt4H/cve-2014-7920-7921_update) :  ![starts](https://img.shields.io/github/stars/Vinc3nt4H/cve-2014-7920-7921_update.svg) ![forks](https://img.shields.io/github/forks/Vinc3nt4H/cve-2014-7920-7921_update.svg)


## CVE-2014-2324
 Multiple directory traversal vulnerabilities in (1) mod_evhost and (2) mod_simple_vhost in lighttpd before 1.4.35 allow remote attackers to read arbitrary files via a .. (dot dot) in the host name, related to request_check_hostname.

- [https://github.com/sp4c30x1/uc_httpd_exploit](https://github.com/sp4c30x1/uc_httpd_exploit) :  ![starts](https://img.shields.io/github/stars/sp4c30x1/uc_httpd_exploit.svg) ![forks](https://img.shields.io/github/forks/sp4c30x1/uc_httpd_exploit.svg)


## CVE-2013-1690
 Mozilla Firefox before 22.0, Firefox ESR 17.x before 17.0.7, Thunderbird before 17.0.7, and Thunderbird ESR 17.x before 17.0.7 do not properly handle onreadystatechange events in conjunction with page reloading, which allows remote attackers to cause a denial of service (application crash) or possibly execute arbitrary code via a crafted web site that triggers an attempt to execute data at an unmapped memory location.

- [https://github.com/Diamond975-py/FBI-Tor-Exploit-CVE-2013-1690](https://github.com/Diamond975-py/FBI-Tor-Exploit-CVE-2013-1690) :  ![starts](https://img.shields.io/github/stars/Diamond975-py/FBI-Tor-Exploit-CVE-2013-1690.svg) ![forks](https://img.shields.io/github/forks/Diamond975-py/FBI-Tor-Exploit-CVE-2013-1690.svg)

