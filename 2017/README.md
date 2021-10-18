## CVE-2017-1002101
 In Kubernetes versions 1.3.x, 1.4.x, 1.5.x, 1.6.x and prior to versions 1.7.14, 1.8.9 and 1.9.4 containers using subpath volume mounts with any volume type (including non-privileged pods, subject to file permissions) can access files/directories outside of the volume, including the host's filesystem.



- [https://github.com/bgeesaman/subpath-exploit](https://github.com/bgeesaman/subpath-exploit) :  ![starts](https://img.shields.io/github/stars/bgeesaman/subpath-exploit.svg) ![forks](https://img.shields.io/github/forks/bgeesaman/subpath-exploit.svg)

## CVE-2017-1001004
 typed-function before 0.10.6 had an arbitrary code execution in the JavaScript engine. Creating a typed function with JavaScript code in the name could result arbitrary execution.



- [https://github.com/ossf-cve-benchmark/CVE-2017-1001004](https://github.com/ossf-cve-benchmark/CVE-2017-1001004) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-1001004.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-1001004.svg)

## CVE-2017-1000499
 phpMyAdmin versions 4.7.x (prior to 4.7.6.1/4.7.7) are vulnerable to a CSRF weakness. By deceiving a user to click on a crafted URL, it is possible to perform harmful database operations such as deleting records, dropping/truncating tables etc.



- [https://github.com/Villaquiranm/5MMISSI-CVE-2017-1000499](https://github.com/Villaquiranm/5MMISSI-CVE-2017-1000499) :  ![starts](https://img.shields.io/github/stars/Villaquiranm/5MMISSI-CVE-2017-1000499.svg) ![forks](https://img.shields.io/github/forks/Villaquiranm/5MMISSI-CVE-2017-1000499.svg)

## CVE-2017-1000486
 Primetek Primefaces 5.x is vulnerable to a weak encryption flaw resulting in remote code execution



- [https://github.com/pimps/CVE-2017-1000486](https://github.com/pimps/CVE-2017-1000486) :  ![starts](https://img.shields.io/github/stars/pimps/CVE-2017-1000486.svg) ![forks](https://img.shields.io/github/forks/pimps/CVE-2017-1000486.svg)

- [https://github.com/mogwailabs/CVE-2017-1000486](https://github.com/mogwailabs/CVE-2017-1000486) :  ![starts](https://img.shields.io/github/stars/mogwailabs/CVE-2017-1000486.svg) ![forks](https://img.shields.io/github/forks/mogwailabs/CVE-2017-1000486.svg)

- [https://github.com/cved-sources/cve-2017-1000486](https://github.com/cved-sources/cve-2017-1000486) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2017-1000486.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2017-1000486.svg)

- [https://github.com/Pastea/CVE-2017-1000486](https://github.com/Pastea/CVE-2017-1000486) :  ![starts](https://img.shields.io/github/stars/Pastea/CVE-2017-1000486.svg) ![forks](https://img.shields.io/github/forks/Pastea/CVE-2017-1000486.svg)

## CVE-2017-1000475
 FreeSSHd 1.3.1 version is vulnerable to an Unquoted Path Service allowing local users to launch processes with elevated privileges.



- [https://github.com/lajarajorge/CVE-2017-1000475](https://github.com/lajarajorge/CVE-2017-1000475) :  ![starts](https://img.shields.io/github/stars/lajarajorge/CVE-2017-1000475.svg) ![forks](https://img.shields.io/github/forks/lajarajorge/CVE-2017-1000475.svg)

## CVE-2017-1000427
 marked version 0.3.6 and earlier is vulnerable to an XSS attack in the data: URI parser.



- [https://github.com/ossf-cve-benchmark/CVE-2017-1000427](https://github.com/ossf-cve-benchmark/CVE-2017-1000427) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-1000427.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-1000427.svg)

## CVE-2017-1000405
 The Linux Kernel versions 2.6.38 through 4.14 have a problematic use of pmd_mkdirty() in the touch_pmd() function inside the THP implementation. touch_pmd() can be reached by get_user_pages(). In such case, the pmd will become dirty. This scenario breaks the new can_follow_write_pmd()'s logic - pmd can become dirty without going through a COW cycle. This bug is not as severe as the original &quot;Dirty cow&quot; because an ext4 file (or any other regular file) cannot be mapped using THP. Nevertheless, it does allow us to overwrite read-only huge pages. For example, the zero huge page and sealed shmem files can be overwritten (since their mapping can be populated using THP). Note that after the first write page-fault to the zero page, it will be replaced with a new fresh (and zeroed) thp.



- [https://github.com/bindecy/HugeDirtyCowPOC](https://github.com/bindecy/HugeDirtyCowPOC) :  ![starts](https://img.shields.io/github/stars/bindecy/HugeDirtyCowPOC.svg) ![forks](https://img.shields.io/github/forks/bindecy/HugeDirtyCowPOC.svg)

## CVE-2017-1000367
 Todd Miller's sudo version 1.8.20 and earlier is vulnerable to an input validation (embedded spaces) in the get_process_ttyname() function resulting in information disclosure and command execution.



- [https://github.com/Al1ex/LinuxEelvation](https://github.com/Al1ex/LinuxEelvation) :  ![starts](https://img.shields.io/github/stars/Al1ex/LinuxEelvation.svg) ![forks](https://img.shields.io/github/forks/Al1ex/LinuxEelvation.svg)

- [https://github.com/c0d3z3r0/sudo-CVE-2017-1000367](https://github.com/c0d3z3r0/sudo-CVE-2017-1000367) :  ![starts](https://img.shields.io/github/stars/c0d3z3r0/sudo-CVE-2017-1000367.svg) ![forks](https://img.shields.io/github/forks/c0d3z3r0/sudo-CVE-2017-1000367.svg)

- [https://github.com/pucerpocok/sudo_exploit](https://github.com/pucerpocok/sudo_exploit) :  ![starts](https://img.shields.io/github/stars/pucerpocok/sudo_exploit.svg) ![forks](https://img.shields.io/github/forks/pucerpocok/sudo_exploit.svg)

- [https://github.com/homjxi0e/CVE-2017-1000367](https://github.com/homjxi0e/CVE-2017-1000367) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-1000367.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-1000367.svg)

## CVE-2017-1000353
 Jenkins versions 2.56 and earlier as well as 2.46.1 LTS and earlier are vulnerable to an unauthenticated remote code execution. An unauthenticated remote code execution vulnerability allowed attackers to transfer a serialized Java `SignedObject` object to the Jenkins CLI, that would be deserialized using a new `ObjectInputStream`, bypassing the existing blacklist-based protection mechanism. We're fixing this issue by adding `SignedObject` to the blacklist. We're also backporting the new HTTP CLI protocol from Jenkins 2.54 to LTS 2.46.2, and deprecating the remoting-based (i.e. Java serialization) CLI protocol, disabling it by default.



- [https://github.com/vulhub/CVE-2017-1000353](https://github.com/vulhub/CVE-2017-1000353) :  ![starts](https://img.shields.io/github/stars/vulhub/CVE-2017-1000353.svg) ![forks](https://img.shields.io/github/forks/vulhub/CVE-2017-1000353.svg)

## CVE-2017-1000253
 Linux distributions that have not patched their long-term kernels with https://git.kernel.org/linus/a87938b2e246b81b4fb713edb371a9fa3c5c3c86 (committed on April 14, 2015). This kernel vulnerability was fixed in April 2015 by commit a87938b2e246b81b4fb713edb371a9fa3c5c3c86 (backported to Linux 3.10.77 in May 2015), but it was not recognized as a security threat. With CONFIG_ARCH_BINFMT_ELF_RANDOMIZE_PIE enabled, and a normal top-down address allocation strategy, load_elf_binary() will attempt to map a PIE binary into an address range immediately below mm-&gt;mmap_base. Unfortunately, load_elf_ binary() does not take account of the need to allocate sufficient space for the entire binary which means that, while the first PT_LOAD segment is mapped below mm-&gt;mmap_base, the subsequent PT_LOAD segment(s) end up being mapped above mm-&gt;mmap_base into the are that is supposed to be the &quot;gap&quot; between the stack and the binary.



- [https://github.com/RicterZ/PIE-Stack-Clash-CVE-2017-1000253](https://github.com/RicterZ/PIE-Stack-Clash-CVE-2017-1000253) :  ![starts](https://img.shields.io/github/stars/RicterZ/PIE-Stack-Clash-CVE-2017-1000253.svg) ![forks](https://img.shields.io/github/forks/RicterZ/PIE-Stack-Clash-CVE-2017-1000253.svg)

## CVE-2017-1000251
 The native Bluetooth stack in the Linux Kernel (BlueZ), starting at the Linux kernel version 2.6.32 and up to and including 4.13.1, are vulnerable to a stack overflow vulnerability in the processing of L2CAP configuration responses resulting in Remote code execution in kernel space.



- [https://github.com/hayzamjs/Blueborne-CVE-2017-1000251](https://github.com/hayzamjs/Blueborne-CVE-2017-1000251) :  ![starts](https://img.shields.io/github/stars/hayzamjs/Blueborne-CVE-2017-1000251.svg) ![forks](https://img.shields.io/github/forks/hayzamjs/Blueborne-CVE-2017-1000251.svg)

- [https://github.com/marcinguy/blueborne-CVE-2017-1000251](https://github.com/marcinguy/blueborne-CVE-2017-1000251) :  ![starts](https://img.shields.io/github/stars/marcinguy/blueborne-CVE-2017-1000251.svg) ![forks](https://img.shields.io/github/forks/marcinguy/blueborne-CVE-2017-1000251.svg)

- [https://github.com/own2pwn/blueborne-CVE-2017-1000251-POC](https://github.com/own2pwn/blueborne-CVE-2017-1000251-POC) :  ![starts](https://img.shields.io/github/stars/own2pwn/blueborne-CVE-2017-1000251-POC.svg) ![forks](https://img.shields.io/github/forks/own2pwn/blueborne-CVE-2017-1000251-POC.svg)

- [https://github.com/CrackSoft900/Blue-Borne](https://github.com/CrackSoft900/Blue-Borne) :  ![starts](https://img.shields.io/github/stars/CrackSoft900/Blue-Borne.svg) ![forks](https://img.shields.io/github/forks/CrackSoft900/Blue-Borne.svg)

- [https://github.com/tlatkdgus1/blueborne-CVE-2017-1000251](https://github.com/tlatkdgus1/blueborne-CVE-2017-1000251) :  ![starts](https://img.shields.io/github/stars/tlatkdgus1/blueborne-CVE-2017-1000251.svg) ![forks](https://img.shields.io/github/forks/tlatkdgus1/blueborne-CVE-2017-1000251.svg)

## CVE-2017-1000250
 All versions of the SDP server in BlueZ 5.46 and earlier are vulnerable to an information disclosure vulnerability which allows remote attackers to obtain sensitive information from the bluetoothd process memory. This vulnerability lies in the processing of SDP search attribute requests.



- [https://github.com/AxelRoudaut/THC_BlueBorne](https://github.com/AxelRoudaut/THC_BlueBorne) :  ![starts](https://img.shields.io/github/stars/AxelRoudaut/THC_BlueBorne.svg) ![forks](https://img.shields.io/github/forks/AxelRoudaut/THC_BlueBorne.svg)

- [https://github.com/olav-st/CVE-2017-1000250-PoC](https://github.com/olav-st/CVE-2017-1000250-PoC) :  ![starts](https://img.shields.io/github/stars/olav-st/CVE-2017-1000250-PoC.svg) ![forks](https://img.shields.io/github/forks/olav-st/CVE-2017-1000250-PoC.svg)

## CVE-2017-1000219
 npm/KyleRoss windows-cpu all versions vulnerable to command injection resulting in code execution as Node.js user



- [https://github.com/ossf-cve-benchmark/CVE-2017-1000219](https://github.com/ossf-cve-benchmark/CVE-2017-1000219) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-1000219.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-1000219.svg)

## CVE-2017-1000170
 jqueryFileTree 2.1.5 and older Directory Traversal



- [https://github.com/Nickguitar/Jquery-File-Tree-1.6.6-Path-Traversal](https://github.com/Nickguitar/Jquery-File-Tree-1.6.6-Path-Traversal) :  ![starts](https://img.shields.io/github/stars/Nickguitar/Jquery-File-Tree-1.6.6-Path-Traversal.svg) ![forks](https://img.shields.io/github/forks/Nickguitar/Jquery-File-Tree-1.6.6-Path-Traversal.svg)

## CVE-2017-1000117
 A malicious third-party can give a crafted &quot;ssh://...&quot; URL to an unsuspecting victim, and an attempt to visit the URL can result in any program that exists on the victim's machine being executed. Such a URL could be placed in the .gitmodules file of a malicious project, and an unsuspecting victim could be tricked into running &quot;git clone --recurse-submodules&quot; to trigger the vulnerability.



- [https://github.com/greymd/CVE-2017-1000117](https://github.com/greymd/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/greymd/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/greymd/CVE-2017-1000117.svg)

- [https://github.com/Manouchehri/CVE-2017-1000117](https://github.com/Manouchehri/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/Manouchehri/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/Manouchehri/CVE-2017-1000117.svg)

- [https://github.com/timwr/CVE-2017-1000117](https://github.com/timwr/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/timwr/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/timwr/CVE-2017-1000117.svg)

- [https://github.com/VulApps/CVE-2017-1000117](https://github.com/VulApps/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/VulApps/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/VulApps/CVE-2017-1000117.svg)

- [https://github.com/ieee0824/CVE-2017-1000117](https://github.com/ieee0824/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/ieee0824/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/ieee0824/CVE-2017-1000117.svg)

- [https://github.com/nkoneko/CVE-2017-1000117](https://github.com/nkoneko/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/nkoneko/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/nkoneko/CVE-2017-1000117.svg)

- [https://github.com/AnonymKing/CVE-2017-1000117](https://github.com/AnonymKing/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/AnonymKing/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/AnonymKing/CVE-2017-1000117.svg)

- [https://github.com/sasairc/CVE-2017-1000117_wasawasa](https://github.com/sasairc/CVE-2017-1000117_wasawasa) :  ![starts](https://img.shields.io/github/stars/sasairc/CVE-2017-1000117_wasawasa.svg) ![forks](https://img.shields.io/github/forks/sasairc/CVE-2017-1000117_wasawasa.svg)

- [https://github.com/rootclay/CVE-2017-1000117](https://github.com/rootclay/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/rootclay/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/rootclay/CVE-2017-1000117.svg)

- [https://github.com/cved-sources/cve-2017-1000117](https://github.com/cved-sources/cve-2017-1000117) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2017-1000117.svg)

- [https://github.com/chenzhuo0618/test](https://github.com/chenzhuo0618/test) :  ![starts](https://img.shields.io/github/stars/chenzhuo0618/test.svg) ![forks](https://img.shields.io/github/forks/chenzhuo0618/test.svg)

- [https://github.com/ieee0824/CVE-2017-1000117-sl](https://github.com/ieee0824/CVE-2017-1000117-sl) :  ![starts](https://img.shields.io/github/stars/ieee0824/CVE-2017-1000117-sl.svg) ![forks](https://img.shields.io/github/forks/ieee0824/CVE-2017-1000117-sl.svg)

- [https://github.com/alilangtest/CVE-2017-1000117](https://github.com/alilangtest/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/alilangtest/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/alilangtest/CVE-2017-1000117.svg)

- [https://github.com/Shadow5523/CVE-2017-1000117-test](https://github.com/Shadow5523/CVE-2017-1000117-test) :  ![starts](https://img.shields.io/github/stars/Shadow5523/CVE-2017-1000117-test.svg) ![forks](https://img.shields.io/github/forks/Shadow5523/CVE-2017-1000117-test.svg)

- [https://github.com/takehaya/CVE-2017-1000117](https://github.com/takehaya/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/takehaya/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/takehaya/CVE-2017-1000117.svg)

- [https://github.com/siling2017/CVE-2017-1000117](https://github.com/siling2017/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/siling2017/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/siling2017/CVE-2017-1000117.svg)

- [https://github.com/thelastbyte/CVE-2017-1000117](https://github.com/thelastbyte/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/thelastbyte/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/thelastbyte/CVE-2017-1000117.svg)

- [https://github.com/Q2h1Cg/CVE-2017-1000117](https://github.com/Q2h1Cg/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/Q2h1Cg/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/Q2h1Cg/CVE-2017-1000117.svg)

- [https://github.com/Jerry-zhuang/CVE-2017-1000117](https://github.com/Jerry-zhuang/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/Jerry-zhuang/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/Jerry-zhuang/CVE-2017-1000117.svg)

- [https://github.com/leezp/CVE-2017-1000117](https://github.com/leezp/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/leezp/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/leezp/CVE-2017-1000117.svg)

- [https://github.com/ikmski/CVE-2017-1000117](https://github.com/ikmski/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/ikmski/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/ikmski/CVE-2017-1000117.svg)

- [https://github.com/shogo82148/Fix-CVE-2017-1000117](https://github.com/shogo82148/Fix-CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/shogo82148/Fix-CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/shogo82148/Fix-CVE-2017-1000117.svg)

- [https://github.com/bells17/CVE-2017-1000117](https://github.com/bells17/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/bells17/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/bells17/CVE-2017-1000117.svg)

- [https://github.com/GrahamMThomas/test-git-vuln_CVE-2017-1000117](https://github.com/GrahamMThomas/test-git-vuln_CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/GrahamMThomas/test-git-vuln_CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/GrahamMThomas/test-git-vuln_CVE-2017-1000117.svg)

## CVE-2017-1000112
 Linux kernel: Exploitable memory corruption due to UFO to non-UFO path switch. When building a UFO packet with MSG_MORE __ip_append_data() calls ip_ufo_append_data() to append. However in between two send() calls, the append path can be switched from UFO to non-UFO one, which leads to a memory corruption. In case UFO packet lengths exceeds MTU, copy = maxfraglen - skb-&gt;len becomes negative on the non-UFO path and the branch to allocate new skb is taken. This triggers fragmentation and computation of fraggap = skb_prev-&gt;len - maxfraglen. Fraggap can exceed MTU, causing copy = datalen - transhdrlen - fraggap to become negative. Subsequently skb_copy_and_csum_bits() writes out-of-bounds. A similar issue is present in IPv6 code. The bug was introduced in e89e9cf539a2 (&quot;[IPv4/IPv6]: UFO Scatter-gather approach&quot;) on Oct 18 2005.



- [https://github.com/Al1ex/LinuxEelvation](https://github.com/Al1ex/LinuxEelvation) :  ![starts](https://img.shields.io/github/stars/Al1ex/LinuxEelvation.svg) ![forks](https://img.shields.io/github/forks/Al1ex/LinuxEelvation.svg)

- [https://github.com/ol0273st-s/CVE-2017-1000112-Adpated](https://github.com/ol0273st-s/CVE-2017-1000112-Adpated) :  ![starts](https://img.shields.io/github/stars/ol0273st-s/CVE-2017-1000112-Adpated.svg) ![forks](https://img.shields.io/github/forks/ol0273st-s/CVE-2017-1000112-Adpated.svg)

- [https://github.com/IT19083124/SNP-Assignment](https://github.com/IT19083124/SNP-Assignment) :  ![starts](https://img.shields.io/github/stars/IT19083124/SNP-Assignment.svg) ![forks](https://img.shields.io/github/forks/IT19083124/SNP-Assignment.svg)

- [https://github.com/hikame/docker_escape_pwn](https://github.com/hikame/docker_escape_pwn) :  ![starts](https://img.shields.io/github/stars/hikame/docker_escape_pwn.svg) ![forks](https://img.shields.io/github/forks/hikame/docker_escape_pwn.svg)

## CVE-2017-1000083
 backend/comics/comics-document.c (aka the comic book backend) in GNOME Evince before 3.24.1 allows remote attackers to execute arbitrary commands via a .cbt file that is a TAR archive containing a filename beginning with a &quot;--&quot; command-line option substring, as demonstrated by a --checkpoint-action=exec=bash at the beginning of the filename.



- [https://github.com/matlink/evince-cve-2017-1000083](https://github.com/matlink/evince-cve-2017-1000083) :  ![starts](https://img.shields.io/github/stars/matlink/evince-cve-2017-1000083.svg) ![forks](https://img.shields.io/github/forks/matlink/evince-cve-2017-1000083.svg)

- [https://github.com/matlink/cve-2017-1000083-atril-nautilus](https://github.com/matlink/cve-2017-1000083-atril-nautilus) :  ![starts](https://img.shields.io/github/stars/matlink/cve-2017-1000083-atril-nautilus.svg) ![forks](https://img.shields.io/github/forks/matlink/cve-2017-1000083-atril-nautilus.svg)

## CVE-2017-1000006
 Plotly, Inc. plotly.js versions prior to 1.16.0 are vulnerable to an XSS issue.



- [https://github.com/ossf-cve-benchmark/CVE-2017-1000006](https://github.com/ossf-cve-benchmark/CVE-2017-1000006) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-1000006.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-1000006.svg)

## CVE-2017-1000000
 ** RE



- [https://github.com/smythtech/DWF-CVE-2017-1000000](https://github.com/smythtech/DWF-CVE-2017-1000000) :  ![starts](https://img.shields.io/github/stars/smythtech/DWF-CVE-2017-1000000.svg) ![forks](https://img.shields.io/github/forks/smythtech/DWF-CVE-2017-1000000.svg)

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

## CVE-2017-18352
 Error reporting within Rendertron 1.0.0 allows reflected Cross Site Scripting (XSS) from invalid URLs.



- [https://github.com/ossf-cve-benchmark/CVE-2017-18352](https://github.com/ossf-cve-benchmark/CVE-2017-18352) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-18352.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-18352.svg)

## CVE-2017-18345
 The Joomanager component through 2.0.0 for Joomla! has an arbitrary file download issue, resulting in exposing the credentials of the database via an index.php?option=com_joomanager&amp;controller=details&amp;task=download&amp;path=configuration.php request.



- [https://github.com/Luth1er/CVE-2017-18345-COM_JOOMANAGER-ARBITRARY-FILE-DOWNLOAD](https://github.com/Luth1er/CVE-2017-18345-COM_JOOMANAGER-ARBITRARY-FILE-DOWNLOAD) :  ![starts](https://img.shields.io/github/stars/Luth1er/CVE-2017-18345-COM_JOOMANAGER-ARBITRARY-FILE-DOWNLOAD.svg) ![forks](https://img.shields.io/github/forks/Luth1er/CVE-2017-18345-COM_JOOMANAGER-ARBITRARY-FILE-DOWNLOAD.svg)

## CVE-2017-18344
 The timer_create syscall implementation in kernel/time/posix-timers.c in the Linux kernel before 4.14.8 doesn't properly validate the sigevent-&gt;sigev_notify field, which leads to out-of-bounds access in the show_timer function (called when /proc/$PID/timers is read). This allows userspace applications to read arbitrary kernel memory (on a kernel built with CONFIG_POSIX_TIMERS and CONFIG_CHECKPOINT_RESTORE).



- [https://github.com/hikame/docker_escape_pwn](https://github.com/hikame/docker_escape_pwn) :  ![starts](https://img.shields.io/github/stars/hikame/docker_escape_pwn.svg) ![forks](https://img.shields.io/github/forks/hikame/docker_escape_pwn.svg)

## CVE-2017-18214
 The moment module before 2.19.3 for Node.js is prone to a regular expression denial of service via a crafted date string, a different vulnerability than CVE-2016-4055.



- [https://github.com/ossf-cve-benchmark/CVE-2017-18214](https://github.com/ossf-cve-benchmark/CVE-2017-18214) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-18214.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-18214.svg)

## CVE-2017-18077
 index.js in brace-expansion before 1.1.7 is vulnerable to Regular Expression Denial of Service (ReDoS) attacks, as demonstrated by an expand argument containing many comma characters.



- [https://github.com/ossf-cve-benchmark/CVE-2017-18077](https://github.com/ossf-cve-benchmark/CVE-2017-18077) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-18077.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-18077.svg)

## CVE-2017-18047
 Buffer Overflow in the FTP client in LabF nfsAxe 3.7 allows remote FTP servers to execute arbitrary code via a long reply.



- [https://github.com/wetw0rk/Exploit-Development](https://github.com/wetw0rk/Exploit-Development) :  ![starts](https://img.shields.io/github/stars/wetw0rk/Exploit-Development.svg) ![forks](https://img.shields.io/github/forks/wetw0rk/Exploit-Development.svg)

## CVE-2017-18044
 A Command Injection issue was discovered in ContentStore/Base/CVDataPipe.dll in Commvault before v11 SP6. A certain message parsing function inside the Commvault service does not properly validate the input of an incoming string before passing it to CreateProcess. As a result, a specially crafted message can inject commands that will be executed on the target operating system. Exploitation of this vulnerability does not require authentication and can lead to SYSTEM level privilege on any system running the cvd daemon. This is a different vulnerability than CVE-2017-3195.



- [https://github.com/securifera/CVE-2017-18044-Exploit](https://github.com/securifera/CVE-2017-18044-Exploit) :  ![starts](https://img.shields.io/github/stars/securifera/CVE-2017-18044-Exploit.svg) ![forks](https://img.shields.io/github/forks/securifera/CVE-2017-18044-Exploit.svg)

## CVE-2017-18016
 Parity Browser 1.6.10 and earlier allows remote attackers to bypass the Same Origin Policy and obtain sensitive information by requesting other websites via the Parity web proxy engine (reusing the current website's token, which is not bound to an origin).



- [https://github.com/tintinweb/pub](https://github.com/tintinweb/pub) :  ![starts](https://img.shields.io/github/stars/tintinweb/pub.svg) ![forks](https://img.shields.io/github/forks/tintinweb/pub.svg)

## CVE-2017-17692
 Samsung Internet Browser 5.4.02.3 allows remote attackers to bypass the Same Origin Policy and obtain sensitive information via crafted JavaScript code that redirects to a child tab and rewrites the innerHTML property.



- [https://github.com/lr3800/CVE-2017-17692](https://github.com/lr3800/CVE-2017-17692) :  ![starts](https://img.shields.io/github/stars/lr3800/CVE-2017-17692.svg) ![forks](https://img.shields.io/github/forks/lr3800/CVE-2017-17692.svg)

## CVE-2017-17562
 Embedthis GoAhead before 3.6.5 allows remote code execution if CGI is enabled and a CGI program is dynamically linked. This is a result of initializing the environment of forked CGI scripts using untrusted HTTP request parameters in the cgiHandler function in cgi.c. When combined with the glibc dynamic linker, this behaviour can be abused for remote code execution using special parameter names such as LD_PRELOAD. An attacker can POST their shared object payload in the body of the request, and reference it using /proc/self/fd/0.



- [https://github.com/ivanitlearning/CVE-2017-17562](https://github.com/ivanitlearning/CVE-2017-17562) :  ![starts](https://img.shields.io/github/stars/ivanitlearning/CVE-2017-17562.svg) ![forks](https://img.shields.io/github/forks/ivanitlearning/CVE-2017-17562.svg)

- [https://github.com/1337g/CVE-2017-17562](https://github.com/1337g/CVE-2017-17562) :  ![starts](https://img.shields.io/github/stars/1337g/CVE-2017-17562.svg) ![forks](https://img.shields.io/github/forks/1337g/CVE-2017-17562.svg)

- [https://github.com/crispy-peppers/Goahead-CVE-2017-17562](https://github.com/crispy-peppers/Goahead-CVE-2017-17562) :  ![starts](https://img.shields.io/github/stars/crispy-peppers/Goahead-CVE-2017-17562.svg) ![forks](https://img.shields.io/github/forks/crispy-peppers/Goahead-CVE-2017-17562.svg)

- [https://github.com/cyberharsh/GoAhead-cve---2017--17562](https://github.com/cyberharsh/GoAhead-cve---2017--17562) :  ![starts](https://img.shields.io/github/stars/cyberharsh/GoAhead-cve---2017--17562.svg) ![forks](https://img.shields.io/github/forks/cyberharsh/GoAhead-cve---2017--17562.svg)

## CVE-2017-17485
 FasterXML jackson-databind through 2.8.10 and 2.9.x through 2.9.3 allows unauthenticated remote code execution because of an incomplete fix for the CVE-2017-7525 deserialization flaw. This is exploitable by sending maliciously crafted JSON input to the readValue method of the ObjectMapper, bypassing a blacklist that is ineffective if the Spring libraries are available in the classpath.



- [https://github.com/maxbitcoin/Jackson-CVE-2017-17485](https://github.com/maxbitcoin/Jackson-CVE-2017-17485) :  ![starts](https://img.shields.io/github/stars/maxbitcoin/Jackson-CVE-2017-17485.svg) ![forks](https://img.shields.io/github/forks/maxbitcoin/Jackson-CVE-2017-17485.svg)

- [https://github.com/Al1ex/CVE-2017-17485](https://github.com/Al1ex/CVE-2017-17485) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2017-17485.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2017-17485.svg)

- [https://github.com/x7iaob/cve-2017-17485](https://github.com/x7iaob/cve-2017-17485) :  ![starts](https://img.shields.io/github/stars/x7iaob/cve-2017-17485.svg) ![forks](https://img.shields.io/github/forks/x7iaob/cve-2017-17485.svg)

- [https://github.com/tafamace/CVE-2017-17485](https://github.com/tafamace/CVE-2017-17485) :  ![starts](https://img.shields.io/github/stars/tafamace/CVE-2017-17485.svg) ![forks](https://img.shields.io/github/forks/tafamace/CVE-2017-17485.svg)

## CVE-2017-17461
 ** RE



- [https://github.com/ossf-cve-benchmark/CVE-2017-17461](https://github.com/ossf-cve-benchmark/CVE-2017-17461) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-17461.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-17461.svg)

## CVE-2017-17309
 Huawei HG255s-10 V100R001C163B025SP02 has a path traversal vulnerability due to insufficient validation of the received HTTP requests, a remote attacker may access the local files on the device without authentication.



- [https://github.com/exploit-labs/huawei_hg255s_exploit](https://github.com/exploit-labs/huawei_hg255s_exploit) :  ![starts](https://img.shields.io/github/stars/exploit-labs/huawei_hg255s_exploit.svg) ![forks](https://img.shields.io/github/forks/exploit-labs/huawei_hg255s_exploit.svg)

## CVE-2017-17275
 ** RE



- [https://github.com/kd992102/CVE-2017-17275](https://github.com/kd992102/CVE-2017-17275) :  ![starts](https://img.shields.io/github/stars/kd992102/CVE-2017-17275.svg) ![forks](https://img.shields.io/github/forks/kd992102/CVE-2017-17275.svg)

## CVE-2017-17215
 Huawei HG532 with some customized versions has a remote code execution vulnerability. An authenticated attacker could send malicious packets to port 37215 to launch attacks. Successful exploit could lead to the remote execution of arbitrary code.



- [https://github.com/1337g/CVE-2017-17215](https://github.com/1337g/CVE-2017-17215) :  ![starts](https://img.shields.io/github/stars/1337g/CVE-2017-17215.svg) ![forks](https://img.shields.io/github/forks/1337g/CVE-2017-17215.svg)

- [https://github.com/wilfred-wulbou/HG532d-RCE-Exploit](https://github.com/wilfred-wulbou/HG532d-RCE-Exploit) :  ![starts](https://img.shields.io/github/stars/wilfred-wulbou/HG532d-RCE-Exploit.svg) ![forks](https://img.shields.io/github/forks/wilfred-wulbou/HG532d-RCE-Exploit.svg)

- [https://github.com/kd992102/CVE-2017-17275](https://github.com/kd992102/CVE-2017-17275) :  ![starts](https://img.shields.io/github/stars/kd992102/CVE-2017-17275.svg) ![forks](https://img.shields.io/github/forks/kd992102/CVE-2017-17275.svg)

## CVE-2017-17099
 There exists an unauthenticated SEH based Buffer Overflow vulnerability in the HTTP server of Flexense SyncBreeze Enterprise v10.1.16. When sending a GET request with an excessive length, it is possible for a malicious user to overwrite the SEH record and execute a payload that would run under the Windows SYSTEM account.



- [https://github.com/wetw0rk/Exploit-Development](https://github.com/wetw0rk/Exploit-Development) :  ![starts](https://img.shields.io/github/stars/wetw0rk/Exploit-Development.svg) ![forks](https://img.shields.io/github/forks/wetw0rk/Exploit-Development.svg)

## CVE-2017-17058
 ** DISPUTED ** The WooCommerce plugin through 3.x for WordPress has a Directory Traversal Vulnerability via a /wp-content/plugins/woocommerce/templates/emails/plain/ URI, which accesses a parent directory. NOTE: a software maintainer indicates that Directory Traversal is not possible because all of the template files have &quot;if (!defined('ABSPATH')) {exit;}&quot; code.



- [https://github.com/fu2x2000/CVE-2017-17058-woo_exploit](https://github.com/fu2x2000/CVE-2017-17058-woo_exploit) :  ![starts](https://img.shields.io/github/stars/fu2x2000/CVE-2017-17058-woo_exploit.svg) ![forks](https://img.shields.io/github/forks/fu2x2000/CVE-2017-17058-woo_exploit.svg)

## CVE-2017-16997
 elf/dl-load.c in the GNU C Library (aka glibc or libc6) 2.19 through 2.26 mishandles RPATH and RUNPATH containing $ORIGIN for a privileged (setuid or AT_SECURE) program, which allows local users to gain privileges via a Trojan horse library in the current working directory, related to the fillin_rpath and decompose_rpath functions. This is associated with misinterpretion of an empty RPATH/RUNPATH token as the &quot;./&quot; directory. NOTE: this configuration of RPATH/RUNPATH for a privileged program is apparently very uncommon; most likely, no such program is shipped with any common Linux distribution.



- [https://github.com/Xiami2012/CVE-2017-16997-poc](https://github.com/Xiami2012/CVE-2017-16997-poc) :  ![starts](https://img.shields.io/github/stars/Xiami2012/CVE-2017-16997-poc.svg) ![forks](https://img.shields.io/github/forks/Xiami2012/CVE-2017-16997-poc.svg)

## CVE-2017-16995
 The check_alu_op function in kernel/bpf/verifier.c in the Linux kernel through 4.4 allows local users to cause a denial of service (memory corruption) or possibly have unspecified other impact by leveraging incorrect sign extension.



- [https://github.com/Al1ex/LinuxEelvation](https://github.com/Al1ex/LinuxEelvation) :  ![starts](https://img.shields.io/github/stars/Al1ex/LinuxEelvation.svg) ![forks](https://img.shields.io/github/forks/Al1ex/LinuxEelvation.svg)

- [https://github.com/Al1ex/CVE-2017-16995](https://github.com/Al1ex/CVE-2017-16995) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2017-16995.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2017-16995.svg)

- [https://github.com/dangokyo/CVE_2017_16995](https://github.com/dangokyo/CVE_2017_16995) :  ![starts](https://img.shields.io/github/stars/dangokyo/CVE_2017_16995.svg) ![forks](https://img.shields.io/github/forks/dangokyo/CVE_2017_16995.svg)

- [https://github.com/ph4ntonn/CVE-2017-16995](https://github.com/ph4ntonn/CVE-2017-16995) :  ![starts](https://img.shields.io/github/stars/ph4ntonn/CVE-2017-16995.svg) ![forks](https://img.shields.io/github/forks/ph4ntonn/CVE-2017-16995.svg)

- [https://github.com/vnik5287/CVE-2017-16995](https://github.com/vnik5287/CVE-2017-16995) :  ![starts](https://img.shields.io/github/stars/vnik5287/CVE-2017-16995.svg) ![forks](https://img.shields.io/github/forks/vnik5287/CVE-2017-16995.svg)

- [https://github.com/littlebin404/CVE-2017-16995](https://github.com/littlebin404/CVE-2017-16995) :  ![starts](https://img.shields.io/github/stars/littlebin404/CVE-2017-16995.svg) ![forks](https://img.shields.io/github/forks/littlebin404/CVE-2017-16995.svg)

- [https://github.com/C0dak/CVE-2017-16995](https://github.com/C0dak/CVE-2017-16995) :  ![starts](https://img.shields.io/github/stars/C0dak/CVE-2017-16995.svg) ![forks](https://img.shields.io/github/forks/C0dak/CVE-2017-16995.svg)

- [https://github.com/gugronnier/CVE-2017-16995](https://github.com/gugronnier/CVE-2017-16995) :  ![starts](https://img.shields.io/github/stars/gugronnier/CVE-2017-16995.svg) ![forks](https://img.shields.io/github/forks/gugronnier/CVE-2017-16995.svg)

- [https://github.com/senyuuri/cve-2017-16995](https://github.com/senyuuri/cve-2017-16995) :  ![starts](https://img.shields.io/github/stars/senyuuri/cve-2017-16995.svg) ![forks](https://img.shields.io/github/forks/senyuuri/cve-2017-16995.svg)

- [https://github.com/Lumindu/CVE-2017-16995-Linux-Kernel---BPF-Sign-Extension-Local-Privilege-Escalation-](https://github.com/Lumindu/CVE-2017-16995-Linux-Kernel---BPF-Sign-Extension-Local-Privilege-Escalation-) :  ![starts](https://img.shields.io/github/stars/Lumindu/CVE-2017-16995-Linux-Kernel---BPF-Sign-Extension-Local-Privilege-Escalation-.svg) ![forks](https://img.shields.io/github/forks/Lumindu/CVE-2017-16995-Linux-Kernel---BPF-Sign-Extension-Local-Privilege-Escalation-.svg)

## CVE-2017-16943
 The receive_msg function in receive.c in the SMTP daemon in Exim 4.88 and 4.89 allows remote attackers to execute arbitrary code or cause a denial of service (use-after-free) via vectors involving BDAT commands.



- [https://github.com/beraphin/CVE-2017-16943](https://github.com/beraphin/CVE-2017-16943) :  ![starts](https://img.shields.io/github/stars/beraphin/CVE-2017-16943.svg) ![forks](https://img.shields.io/github/forks/beraphin/CVE-2017-16943.svg)

## CVE-2017-16939
 The XFRM dump policy implementation in net/xfrm/xfrm_user.c in the Linux kernel before 4.13.11 allows local users to gain privileges or cause a denial of service (use-after-free) via a crafted SO_RCVBUF setsockopt system call in conjunction with XFRM_MSG_GETPOLICY Netlink messages.



- [https://github.com/Al1ex/LinuxEelvation](https://github.com/Al1ex/LinuxEelvation) :  ![starts](https://img.shields.io/github/stars/Al1ex/LinuxEelvation.svg) ![forks](https://img.shields.io/github/forks/Al1ex/LinuxEelvation.svg)

## CVE-2017-16930
 The remote management interface on the Claymore Dual GPU miner 10.1 allows an unauthenticated remote attacker to execute arbitrary code due to a stack-based buffer overflow in the request handler. This can be exploited via a long API request that is mishandled during logging.



- [https://github.com/tintinweb/pub](https://github.com/tintinweb/pub) :  ![starts](https://img.shields.io/github/stars/tintinweb/pub.svg) ![forks](https://img.shields.io/github/forks/tintinweb/pub.svg)

## CVE-2017-16929
 The remote management interface on the Claymore Dual GPU miner 10.1 is vulnerable to an authenticated directory traversal vulnerability exploited by issuing a specially crafted request, allowing a remote attacker to read/write arbitrary files. This can be exploited via ../ sequences in the pathname to miner_file or miner_getfile.



- [https://github.com/tintinweb/pub](https://github.com/tintinweb/pub) :  ![starts](https://img.shields.io/github/stars/tintinweb/pub.svg) ![forks](https://img.shields.io/github/forks/tintinweb/pub.svg)

## CVE-2017-16894
 In Laravel framework through 5.5.21, remote attackers can obtain sensitive information (such as externally usable passwords) via a direct request for the /.env URI. NOTE: this CVE is only about Laravel framework's writeNewEnvironmentFileWith function in src/Illuminate/Foundation/Console/KeyGenerateCommand.php, which uses file_put_contents without restricting the .env permissions. The .env filename is not used exclusively by Laravel framework.



- [https://github.com/ahacker15/CVE-2017-16894](https://github.com/ahacker15/CVE-2017-16894) :  ![starts](https://img.shields.io/github/stars/ahacker15/CVE-2017-16894.svg) ![forks](https://img.shields.io/github/forks/ahacker15/CVE-2017-16894.svg)

- [https://github.com/H3dI/ENV-Mass-Exploit](https://github.com/H3dI/ENV-Mass-Exploit) :  ![starts](https://img.shields.io/github/stars/H3dI/ENV-Mass-Exploit.svg) ![forks](https://img.shields.io/github/forks/H3dI/ENV-Mass-Exploit.svg)

- [https://github.com/LuanDevecchi/CVE201716894](https://github.com/LuanDevecchi/CVE201716894) :  ![starts](https://img.shields.io/github/stars/LuanDevecchi/CVE201716894.svg) ![forks](https://img.shields.io/github/forks/LuanDevecchi/CVE201716894.svg)

## CVE-2017-16877
 ZEIT Next.js before 2.4.1 has directory traversal under the /_next and /static request namespace, allowing attackers to obtain sensitive information.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16877](https://github.com/ossf-cve-benchmark/CVE-2017-16877) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16877.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16877.svg)

## CVE-2017-16806
 The Process function in RemoteTaskServer/WebServer/HttpServer.cs in Ulterius before 1.9.5.0 allows HTTP server directory traversal.



- [https://github.com/rickoooooo/ulteriusExploit](https://github.com/rickoooooo/ulteriusExploit) :  ![starts](https://img.shields.io/github/stars/rickoooooo/ulteriusExploit.svg) ![forks](https://img.shields.io/github/forks/rickoooooo/ulteriusExploit.svg)

## CVE-2017-16778
 An access control weakness in the DTMF tone receiver of Fermax Outdoor Panel allows physical attackers to inject a Dual-Tone-Multi-Frequency (DTMF) tone to invoke an access grant that would allow physical access to a restricted floor/level. By design, only a residential unit owner may allow such an access grant. However, due to incorrect access control, an attacker could inject it via the speaker unit to perform an access grant to gain unauthorized access, as demonstrated by a loud DTMF tone representing '1' and a long '#' (697 Hz and 1209 Hz, followed by 941 Hz and 1477 Hz).



- [https://github.com/breaktoprotect/CVE-2017-16778-Intercom-DTMF-Injection](https://github.com/breaktoprotect/CVE-2017-16778-Intercom-DTMF-Injection) :  ![starts](https://img.shields.io/github/stars/breaktoprotect/CVE-2017-16778-Intercom-DTMF-Injection.svg) ![forks](https://img.shields.io/github/forks/breaktoprotect/CVE-2017-16778-Intercom-DTMF-Injection.svg)

## CVE-2017-16748
 An attacker can log into the local Niagara platform (Niagara AX Framework Versions 3.8 and prior or Niagara 4 Framework Versions 4.4 and prior) using a disabled account name and a blank password, granting the attacker administrator access to the Niagara system.



- [https://github.com/GainSec/CVE-2017-16744-and-CVE-2017-16748-Tridium-Niagara](https://github.com/GainSec/CVE-2017-16744-and-CVE-2017-16748-Tridium-Niagara) :  ![starts](https://img.shields.io/github/stars/GainSec/CVE-2017-16744-and-CVE-2017-16748-Tridium-Niagara.svg) ![forks](https://img.shields.io/github/forks/GainSec/CVE-2017-16744-and-CVE-2017-16748-Tridium-Niagara.svg)

## CVE-2017-16744
 A path traversal vulnerability in Tridium Niagara AX Versions 3.8 and prior and Niagara 4 systems Versions 4.4 and prior installed on Microsoft Windows Systems can be exploited by leveraging valid platform (administrator) credentials.



- [https://github.com/GainSec/CVE-2017-16744-and-CVE-2017-16748-Tridium-Niagara](https://github.com/GainSec/CVE-2017-16744-and-CVE-2017-16748-Tridium-Niagara) :  ![starts](https://img.shields.io/github/stars/GainSec/CVE-2017-16744-and-CVE-2017-16748-Tridium-Niagara.svg) ![forks](https://img.shields.io/github/forks/GainSec/CVE-2017-16744-and-CVE-2017-16748-Tridium-Niagara.svg)

## CVE-2017-16695
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem.  When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/Jewel591/Privilege-Escalation](https://github.com/Jewel591/Privilege-Escalation) :  ![starts](https://img.shields.io/github/stars/Jewel591/Privilege-Escalation.svg) ![forks](https://img.shields.io/github/forks/Jewel591/Privilege-Escalation.svg)

## CVE-2017-16651
 Roundcube Webmail before 1.1.10, 1.2.x before 1.2.7, and 1.3.x before 1.3.3 allows unauthorized access to arbitrary files on the host's filesystem, including configuration files, as exploited in the wild in November 2017. The attacker must be able to authenticate at the target system with a valid username/password as the attack requires an active session. The issue is related to file-based attachment plugins and _task=settings&amp;_action=upload-display&amp;_from=timezone requests.



- [https://github.com/starnightcyber/Exploit-Database-For-Webmail](https://github.com/starnightcyber/Exploit-Database-For-Webmail) :  ![starts](https://img.shields.io/github/stars/starnightcyber/Exploit-Database-For-Webmail.svg) ![forks](https://img.shields.io/github/forks/starnightcyber/Exploit-Database-For-Webmail.svg)

- [https://github.com/stonepresto/CVE-2017-16651](https://github.com/stonepresto/CVE-2017-16651) :  ![starts](https://img.shields.io/github/stars/stonepresto/CVE-2017-16651.svg) ![forks](https://img.shields.io/github/forks/stonepresto/CVE-2017-16651.svg)

## CVE-2017-16568
 Cross-site scripting (XSS) vulnerability in Logitech Media Server 7.9.0 allows remote attackers to inject arbitrary web script or HTML via a radio URL.



- [https://github.com/dewankpant/CVE-2017-16568](https://github.com/dewankpant/CVE-2017-16568) :  ![starts](https://img.shields.io/github/stars/dewankpant/CVE-2017-16568.svg) ![forks](https://img.shields.io/github/forks/dewankpant/CVE-2017-16568.svg)

## CVE-2017-16567
 Cross-site scripting (XSS) vulnerability in Logitech Media Server 7.9.0 allows remote attackers to inject arbitrary web script or HTML via a &quot;favorite.&quot;



- [https://github.com/dewankpant/CVE-2017-16567](https://github.com/dewankpant/CVE-2017-16567) :  ![starts](https://img.shields.io/github/stars/dewankpant/CVE-2017-16567.svg) ![forks](https://img.shields.io/github/forks/dewankpant/CVE-2017-16567.svg)

## CVE-2017-16541
 Tor Browser before 7.0.9 on macOS and Linux allows remote attackers to bypass the intended anonymity feature and discover a client IP address via vectors involving a crafted web site that leverages file:// mishandling in Firefox, aka TorMoil. NOTE: Tails is unaffected.



- [https://github.com/Ethan-Chen-uwo/A-breif-introduction-of-CVE-2017-16541](https://github.com/Ethan-Chen-uwo/A-breif-introduction-of-CVE-2017-16541) :  ![starts](https://img.shields.io/github/stars/Ethan-Chen-uwo/A-breif-introduction-of-CVE-2017-16541.svg) ![forks](https://img.shields.io/github/forks/Ethan-Chen-uwo/A-breif-introduction-of-CVE-2017-16541.svg)

## CVE-2017-16524
 Web Viewer 1.0.0.193 on Samsung SRN-1670D devices suffers from an Unrestricted file upload vulnerability: 'network_ssl_upload.php' allows remote authenticated attackers to upload and execute arbitrary PHP code via a filename with a .php extension, which is then accessed via a direct request to the file in the upload/ directory. To authenticate for this attack, one can obtain web-interface credentials in cleartext by leveraging the existing Local File Read Vulnerability referenced as CVE-2015-8279, which allows remote attackers to read the web-interface credentials via a request for the cslog_export.php?path=/root/php_modules/lighttpd/sbin/userpw URI.



- [https://github.com/realistic-security/CVE-2017-16524](https://github.com/realistic-security/CVE-2017-16524) :  ![starts](https://img.shields.io/github/stars/realistic-security/CVE-2017-16524.svg) ![forks](https://img.shields.io/github/forks/realistic-security/CVE-2017-16524.svg)

## CVE-2017-16245
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem.  When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/AOCorsaire/CVE-2017-16245](https://github.com/AOCorsaire/CVE-2017-16245) :  ![starts](https://img.shields.io/github/stars/AOCorsaire/CVE-2017-16245.svg) ![forks](https://img.shields.io/github/forks/AOCorsaire/CVE-2017-16245.svg)

## CVE-2017-16226
 The static-eval module is intended to evaluate statically-analyzable expressions. In affected versions, untrusted user input is able to access the global function constructor, effectively allowing arbitrary code execution.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16226](https://github.com/ossf-cve-benchmark/CVE-2017-16226) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16226.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16226.svg)

## CVE-2017-16224
 st is a module for serving static files. An attacker is able to craft a request that results in an HTTP 301 (redirect) to an entirely different domain. A request for: http://some.server.com//nodesecurity.org/%2e%2e would result in a 301 to //nodesecurity.org/%2e%2e which most browsers treat as a proper redirect as // is translated into the current schema being used. Mitigating factor: In order for this to work, st must be serving from the root of a server (/) rather than the typical sub directory (/static/) and the redirect URL will end with some form of URL encoded .. (&quot;%2e%2e&quot;, &quot;%2e.&quot;, &quot;.%2e&quot;).



- [https://github.com/ossf-cve-benchmark/CVE-2017-16224](https://github.com/ossf-cve-benchmark/CVE-2017-16224) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16224.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16224.svg)

## CVE-2017-16138
 The mime module &lt; 1.4.1, 2.0.1, 2.0.2 is vulnerable to regular expression denial of service when a mime lookup is performed on untrusted user input.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16138](https://github.com/ossf-cve-benchmark/CVE-2017-16138) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16138.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16138.svg)

## CVE-2017-16137
 The debug module is vulnerable to regular expression denial of service when untrusted user input is passed into the o formatter. It takes around 50k characters to block for 2 seconds making this a low severity issue.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16137](https://github.com/ossf-cve-benchmark/CVE-2017-16137) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16137.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16137.svg)

## CVE-2017-16136
 method-override is a module used by the Express.js framework to let you use HTTP verbs such as PUT or DELETE in places where the client doesn't support it. method-override is vulnerable to a regular expression denial of service vulnerability when specially crafted input is passed in to be parsed via the X-HTTP-Method-Override header.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16136](https://github.com/ossf-cve-benchmark/CVE-2017-16136) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16136.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16136.svg)

## CVE-2017-16119
 Fresh is a module used by the Express.js framework for HTTP response freshness testing. It is vulnerable to a regular expression denial of service when it is passed specially crafted input to parse. This causes the event loop to be blocked causing a denial of service condition.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16119](https://github.com/ossf-cve-benchmark/CVE-2017-16119) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16119.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16119.svg)

## CVE-2017-16118
 The forwarded module is used by the Express.js framework to handle the X-Forwarded-For header. It is vulnerable to a regular expression denial of service when it's passed specially crafted input to parse. This causes the event loop to be blocked causing a denial of service condition.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16118](https://github.com/ossf-cve-benchmark/CVE-2017-16118) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16118.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16118.svg)

## CVE-2017-16117
 slug is a module to slugify strings, even if they contain unicode. slug is vulnerable to regular expression denial of service is specially crafted untrusted input is passed as input. About 50k characters can block the event loop for 2 seconds.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16117](https://github.com/ossf-cve-benchmark/CVE-2017-16117) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16117.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16117.svg)

## CVE-2017-16114
 The marked module is vulnerable to a regular expression denial of service. Based on the information published in the public issue, 1k characters can block for around 6 seconds.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16114](https://github.com/ossf-cve-benchmark/CVE-2017-16114) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16114.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16114.svg)

## CVE-2017-16107
 pooledwebsocket is vulnerable to a directory traversal issue, giving an attacker access to the filesystem by placing &quot;../&quot; in the url.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16107](https://github.com/ossf-cve-benchmark/CVE-2017-16107) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16107.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16107.svg)

## CVE-2017-16100
 dns-sync is a sync/blocking dns resolver. If untrusted user input is allowed into the resolve() method then command injection is possible.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16100](https://github.com/ossf-cve-benchmark/CVE-2017-16100) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16100.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16100.svg)

## CVE-2017-16098
 charset 1.0.0 and below are vulnerable to regular expression denial of service. Input of around 50k characters is required for a slow down of around 2 seconds. Unless node was compiled using the -DHTTP_MAX_HEADER_SIZE= option the default header max length is 80kb, so the impact of the ReDoS is relatively low.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16098](https://github.com/ossf-cve-benchmark/CVE-2017-16098) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16098.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16098.svg)

## CVE-2017-16088
 The safe-eval module describes itself as a safer version of eval. By accessing the object constructors, un-sanitized user input can access the entire standard library and effectively break out of the sandbox.



- [https://github.com/Flyy-yu/CVE-2017-16088](https://github.com/Flyy-yu/CVE-2017-16088) :  ![starts](https://img.shields.io/github/stars/Flyy-yu/CVE-2017-16088.svg) ![forks](https://img.shields.io/github/forks/Flyy-yu/CVE-2017-16088.svg)

## CVE-2017-16087
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem.  When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16087](https://github.com/ossf-cve-benchmark/CVE-2017-16087) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16087.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16087.svg)

## CVE-2017-16084
 list-n-stream is a server for static files to list and stream local videos. list-n-stream v0.0.10 or lower is vulnerable to a directory traversal issue, giving an attacker access to the filesystem by placing &quot;../&quot; in the url.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16084](https://github.com/ossf-cve-benchmark/CVE-2017-16084) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16084.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16084.svg)

## CVE-2017-16083
 node-simple-router is a minimalistic router for Node. node-simple-router is vulnerable to a directory traversal issue, giving an attacker access to the filesystem by placing &quot;../&quot; in the URL.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16083](https://github.com/ossf-cve-benchmark/CVE-2017-16083) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16083.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16083.svg)

## CVE-2017-16082
 A remote code execution vulnerability was found within the pg module when the remote database or query specifies a specially crafted column name. There are 2 likely scenarios in which one would likely be vulnerable. 1) Executing unsafe, user-supplied sql which contains a malicious column name. 2) Connecting to an untrusted database and executing a query which returns results where any of the column names are malicious.



- [https://github.com/nulldreams/CVE-2017-16082](https://github.com/nulldreams/CVE-2017-16082) :  ![starts](https://img.shields.io/github/stars/nulldreams/CVE-2017-16082.svg) ![forks](https://img.shields.io/github/forks/nulldreams/CVE-2017-16082.svg)

- [https://github.com/ossf-cve-benchmark/CVE-2017-16082](https://github.com/ossf-cve-benchmark/CVE-2017-16082) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16082.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16082.svg)

## CVE-2017-16043
 Shout is an IRC client. Because the `/topic` command in messages is unescaped, attackers have the ability to inject HTML scripts that will run in the victim's browser. Affects shout &gt;=0.44.0 &lt;=0.49.3.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16043](https://github.com/ossf-cve-benchmark/CVE-2017-16043) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16043.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16043.svg)

## CVE-2017-16042
 Growl adds growl notification support to nodejs. Growl before 1.10.2 does not properly sanitize input before passing it to exec, allowing for arbitrary command execution.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16042](https://github.com/ossf-cve-benchmark/CVE-2017-16042) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16042.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16042.svg)

## CVE-2017-16034
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem.  When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16034](https://github.com/ossf-cve-benchmark/CVE-2017-16034) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16034.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16034.svg)

## CVE-2017-16031
 Socket.io is a realtime application framework that provides communication via websockets. Because socket.io 0.9.6 and earlier depends on `Math.random()` to create socket IDs, the IDs are predictable. An attacker is able to guess the socket ID and gain access to socket.io servers, potentially obtaining sensitive information.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16031](https://github.com/ossf-cve-benchmark/CVE-2017-16031) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16031.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16031.svg)

## CVE-2017-16030
 Useragent is used to parse useragent headers. It uses several regular expressions to accomplish this. An attacker could edit their own headers, creating an arbitrarily long useragent string, causing the event loop and server to block. This affects Useragent 2.1.12 and earlier.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16030](https://github.com/ossf-cve-benchmark/CVE-2017-16030) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16030.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16030.svg)

## CVE-2017-16029
 hostr is a simple web server that serves up the contents of the current directory. There is a directory traversal vulnerability in hostr 2.3.5 and earlier that allows an attacker to read files outside the current directory by sending `../` in the url path for GET requests.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16029](https://github.com/ossf-cve-benchmark/CVE-2017-16029) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16029.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16029.svg)

## CVE-2017-16028
 react-native-meteor-oauth is a library for Oauth2 login to a Meteor server in React Native. The oauth Random Token is generated using a non-cryptographically strong RNG (Math.random()).



- [https://github.com/ossf-cve-benchmark/CVE-2017-16028](https://github.com/ossf-cve-benchmark/CVE-2017-16028) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16028.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16028.svg)

## CVE-2017-16026
 Request is an http client. If a request is made using ```multipart```, and the body type is a ```number```, then the specified number of non-zero memory is passed in the body. This affects Request &gt;=2.2.6 &lt;2.47.0 || &gt;2.51.0 &lt;=2.67.0.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16026](https://github.com/ossf-cve-benchmark/CVE-2017-16026) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16026.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16026.svg)

## CVE-2017-16023
 Decamelize is used to convert a dash/dot/underscore/space separated string to camelCase. Decamelize 1.1.0 through 1.1.1 uses regular expressions to evaluate a string and takes unescaped separator values, which can be used to create a denial of service attack.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16023](https://github.com/ossf-cve-benchmark/CVE-2017-16023) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16023.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16023.svg)

## CVE-2017-16018
 Restify is a framework for building REST APIs. Restify &gt;=2.0.0 &lt;=4.0.4 using URL encoded script tags in a non-existent URL, an attacker can get script to run in some browsers.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16018](https://github.com/ossf-cve-benchmark/CVE-2017-16018) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16018.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16018.svg)

## CVE-2017-16014
 Http-proxy is a proxying library. Because of the way errors are handled in versions before 0.7.0, an attacker that forces an error can crash the server, causing a denial of service.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16014](https://github.com/ossf-cve-benchmark/CVE-2017-16014) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16014.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16014.svg)

## CVE-2017-16011
 ** RE



- [https://github.com/ossf-cve-benchmark/CVE-2017-16011](https://github.com/ossf-cve-benchmark/CVE-2017-16011) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16011.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16011.svg)

## CVE-2017-16006
 Remarkable is a markdown parser. In versions 1.6.2 and lower, remarkable allows the use of `data:` URIs in links and can therefore execute javascript.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16006](https://github.com/ossf-cve-benchmark/CVE-2017-16006) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16006.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16006.svg)

## CVE-2017-16003
 windows-build-tools is a module for installing C++ Build Tools for Windows using npm. windows-build-tools versions below 1.0.0 download resources over HTTP, which leaves it vulnerable to MITM attacks. It may be possible to cause remote code execution (RCE) by swapping out the requested resources with an attacker controlled copy if the attacker is on the network or positioned in between the user and the remote server.



- [https://github.com/ossf-cve-benchmark/CVE-2017-16003](https://github.com/ossf-cve-benchmark/CVE-2017-16003) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16003.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16003.svg)

## CVE-2017-15950
 Flexense SyncBreeze Enterprise version 10.1.16 is vulnerable to a buffer overflow that can be exploited for arbitrary code execution. The flaw is triggered by providing a long input into the &quot;Destination directory&quot; field, either within an XML document or through use of passive mode.



- [https://github.com/rnnsz/CVE-2017-15950](https://github.com/rnnsz/CVE-2017-15950) :  ![starts](https://img.shields.io/github/stars/rnnsz/CVE-2017-15950.svg) ![forks](https://img.shields.io/github/forks/rnnsz/CVE-2017-15950.svg)

## CVE-2017-15944
 Palo Alto Networks PAN-OS before 6.1.19, 7.0.x before 7.0.19, 7.1.x before 7.1.14, and 8.0.x before 8.0.6 allows remote attackers to execute arbitrary code via vectors involving the management interface.



- [https://github.com/surajraghuvanshi/PaloAltoRceDetectionAndExploit](https://github.com/surajraghuvanshi/PaloAltoRceDetectionAndExploit) :  ![starts](https://img.shields.io/github/stars/surajraghuvanshi/PaloAltoRceDetectionAndExploit.svg) ![forks](https://img.shields.io/github/forks/surajraghuvanshi/PaloAltoRceDetectionAndExploit.svg)

- [https://github.com/xxnbyy/CVE-2017-15944-POC](https://github.com/xxnbyy/CVE-2017-15944-POC) :  ![starts](https://img.shields.io/github/stars/xxnbyy/CVE-2017-15944-POC.svg) ![forks](https://img.shields.io/github/forks/xxnbyy/CVE-2017-15944-POC.svg)

- [https://github.com/yukar1z0e/CVE-2017-15944](https://github.com/yukar1z0e/CVE-2017-15944) :  ![starts](https://img.shields.io/github/stars/yukar1z0e/CVE-2017-15944.svg) ![forks](https://img.shields.io/github/forks/yukar1z0e/CVE-2017-15944.svg)

## CVE-2017-15715
 In Apache httpd 2.4.0 to 2.4.29, the expression specified in &lt;FilesMatch&gt; could match '$' to a newline character in a malicious filename, rather than matching only the end of the filename. This could be exploited in environments where uploads of some files are are externally blocked, but only by matching the trailing portion of the filename.



- [https://github.com/whisp1830/CVE-2017-15715](https://github.com/whisp1830/CVE-2017-15715) :  ![starts](https://img.shields.io/github/stars/whisp1830/CVE-2017-15715.svg) ![forks](https://img.shields.io/github/forks/whisp1830/CVE-2017-15715.svg)

## CVE-2017-15708
 In Apache Synapse, by default no authentication is required for Java Remote Method Invocation (RMI). So Apache Synapse 3.0.1 or all previous releases (3.0.0, 2.1.0, 2.0.0, 1.2, 1.1.2, 1.1.1) allows remote code execution attacks that can be performed by injecting specially crafted serialized objects. And the presence of Apache Commons Collections 3.2.1 (commons-collections-3.2.1.jar) or previous versions in Synapse distribution makes this exploitable. To mitigate the issue, we need to limit RMI access to trusted users only. Further upgrading to 3.0.1 version will eliminate the risk of having said Commons Collection version. In Synapse 3.0.1, Commons Collection has been updated to 3.2.2 version.



- [https://github.com/HuSoul/CVE-2017-15708](https://github.com/HuSoul/CVE-2017-15708) :  ![starts](https://img.shields.io/github/stars/HuSoul/CVE-2017-15708.svg) ![forks](https://img.shields.io/github/forks/HuSoul/CVE-2017-15708.svg)

## CVE-2017-15394
 Insufficient Policy Enforcement in Extensions in Google Chrome prior to 62.0.3202.62 allowed a remote attacker to perform domain spoofing in permission dialogs via IDN homographs in a crafted Chrome Extension.



- [https://github.com/sudosammy/CVE-2017-15394](https://github.com/sudosammy/CVE-2017-15394) :  ![starts](https://img.shields.io/github/stars/sudosammy/CVE-2017-15394.svg) ![forks](https://img.shields.io/github/forks/sudosammy/CVE-2017-15394.svg)

## CVE-2017-15361
 The Infineon RSA library 1.02.013 in Infineon Trusted Platform Module (TPM) firmware, such as versions before 0000000000000422 - 4.34, before 000000000000062b - 6.43, and before 0000000000008521 - 133.33, mishandles RSA key generation, which makes it easier for attackers to defeat various cryptographic protection mechanisms via targeted attacks, aka ROCA. Examples of affected technologies include BitLocker with TPM 1.2, YubiKey 4 (before 4.3.5) PGP key generation, and the Cached User Data encryption feature in Chrome OS.



- [https://github.com/nsacyber/Detect-CVE-2017-15361-TPM](https://github.com/nsacyber/Detect-CVE-2017-15361-TPM) :  ![starts](https://img.shields.io/github/stars/nsacyber/Detect-CVE-2017-15361-TPM.svg) ![forks](https://img.shields.io/github/forks/nsacyber/Detect-CVE-2017-15361-TPM.svg)

- [https://github.com/brunoproduit/roca](https://github.com/brunoproduit/roca) :  ![starts](https://img.shields.io/github/stars/brunoproduit/roca.svg) ![forks](https://img.shields.io/github/forks/brunoproduit/roca.svg)

- [https://github.com/titanous/rocacheck](https://github.com/titanous/rocacheck) :  ![starts](https://img.shields.io/github/stars/titanous/rocacheck.svg) ![forks](https://img.shields.io/github/forks/titanous/rocacheck.svg)

- [https://github.com/0xxon/zeek-plugin-roca](https://github.com/0xxon/zeek-plugin-roca) :  ![starts](https://img.shields.io/github/stars/0xxon/zeek-plugin-roca.svg) ![forks](https://img.shields.io/github/forks/0xxon/zeek-plugin-roca.svg)

- [https://github.com/lva/Infineon-CVE-2017-15361](https://github.com/lva/Infineon-CVE-2017-15361) :  ![starts](https://img.shields.io/github/stars/lva/Infineon-CVE-2017-15361.svg) ![forks](https://img.shields.io/github/forks/lva/Infineon-CVE-2017-15361.svg)

- [https://github.com/Elbarbons/Attacco-ROCA-sulla-vulnerabilita-CVE-2017-15361](https://github.com/Elbarbons/Attacco-ROCA-sulla-vulnerabilita-CVE-2017-15361) :  ![starts](https://img.shields.io/github/stars/Elbarbons/Attacco-ROCA-sulla-vulnerabilita-CVE-2017-15361.svg) ![forks](https://img.shields.io/github/forks/Elbarbons/Attacco-ROCA-sulla-vulnerabilita-CVE-2017-15361.svg)

- [https://github.com/0xxon/roca](https://github.com/0xxon/roca) :  ![starts](https://img.shields.io/github/stars/0xxon/roca.svg) ![forks](https://img.shields.io/github/forks/0xxon/roca.svg)

- [https://github.com/jnpuskar/RocaCmTest](https://github.com/jnpuskar/RocaCmTest) :  ![starts](https://img.shields.io/github/stars/jnpuskar/RocaCmTest.svg) ![forks](https://img.shields.io/github/forks/jnpuskar/RocaCmTest.svg)

## CVE-2017-15303
 In CPUID CPU-Z before 1.43, there is an arbitrary memory write that results directly in elevation of privileges, because any program running on the local machine (while CPU-Z is running) can issue an ioctl 0x9C402430 call to the kernel-mode driver (e.g., cpuz141_x64.sys for version 1.41).



- [https://github.com/hfiref0x/Stryker](https://github.com/hfiref0x/Stryker) :  ![starts](https://img.shields.io/github/stars/hfiref0x/Stryker.svg) ![forks](https://img.shields.io/github/forks/hfiref0x/Stryker.svg)

## CVE-2017-15277
 ReadGIFImage in coders/gif.c in ImageMagick 7.0.6-1 and GraphicsMagick 1.3.26 leaves the palette uninitialized when processing a GIF file that has neither a global nor local palette. If the affected product is used as a library loaded into a process that operates on interesting data, this data sometimes can be leaked via the uninitialized palette.



- [https://github.com/tacticthreat/ImageMagick-CVE-2017-15277](https://github.com/tacticthreat/ImageMagick-CVE-2017-15277) :  ![starts](https://img.shields.io/github/stars/tacticthreat/ImageMagick-CVE-2017-15277.svg) ![forks](https://img.shields.io/github/forks/tacticthreat/ImageMagick-CVE-2017-15277.svg)

## CVE-2017-15120
 An issue has been found in the parsing of authoritative answers in PowerDNS Recursor before 4.0.8, leading to a NULL pointer dereference when parsing a specially crafted answer containing a CNAME of a different class than IN. An unauthenticated remote attacker could cause a denial of service.



- [https://github.com/shutingrz/CVE-2017-15120_PoC](https://github.com/shutingrz/CVE-2017-15120_PoC) :  ![starts](https://img.shields.io/github/stars/shutingrz/CVE-2017-15120_PoC.svg) ![forks](https://img.shields.io/github/forks/shutingrz/CVE-2017-15120_PoC.svg)

## CVE-2017-15095
 A deserialization flaw was discovered in the jackson-databind in versions before 2.8.10 and 2.9.1, which could allow an unauthenticated user to perform code execution by sending the maliciously crafted input to the readValue method of the ObjectMapper. This issue extends the previous flaw CVE-2017-7525 by blacklisting more classes that could be used maliciously.



- [https://github.com/SecureSkyTechnology/study-struts2-s2-054_055-jackson-cve-2017-7525_cve-2017-15095](https://github.com/SecureSkyTechnology/study-struts2-s2-054_055-jackson-cve-2017-7525_cve-2017-15095) :  ![starts](https://img.shields.io/github/stars/SecureSkyTechnology/study-struts2-s2-054_055-jackson-cve-2017-7525_cve-2017-15095.svg) ![forks](https://img.shields.io/github/forks/SecureSkyTechnology/study-struts2-s2-054_055-jackson-cve-2017-7525_cve-2017-15095.svg)

## CVE-2017-15010
 A ReDoS (regular expression denial of service) flaw was found in the tough-cookie module before 2.3.3 for Node.js. An attacker that is able to make an HTTP request using a specially crafted cookie may cause the application to consume an excessive amount of CPU.



- [https://github.com/ossf-cve-benchmark/CVE-2017-15010](https://github.com/ossf-cve-benchmark/CVE-2017-15010) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-15010.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-15010.svg)

## CVE-2017-14948
 Certain D-Link products are affected by: Buffer Overflow. This affects DIR-880L 1.08B04 and DIR-895 L/R 1.13b03. The impact is: execute arbitrary code (remote). The component is: htdocs/fileaccess.cgi. The attack vector is: A crafted HTTP request handled by fileacces.cgi could allow an attacker to mount a ROP attack: if the HTTP header field CONTENT_TYPE starts with ''boundary=' followed by more than 256 characters, a buffer overflow would be triggered, potentially causing code execution.



- [https://github.com/badnack/d_link_880_bug](https://github.com/badnack/d_link_880_bug) :  ![starts](https://img.shields.io/github/stars/badnack/d_link_880_bug.svg) ![forks](https://img.shields.io/github/forks/badnack/d_link_880_bug.svg)

## CVE-2017-14719
 Before version 4.8.2, WordPress was vulnerable to a directory traversal attack during unzip operations in the ZipArchive and PclZip components.



- [https://github.com/PalmTreeForest/CodePath_Week_7-8](https://github.com/PalmTreeForest/CodePath_Week_7-8) :  ![starts](https://img.shields.io/github/stars/PalmTreeForest/CodePath_Week_7-8.svg) ![forks](https://img.shields.io/github/forks/PalmTreeForest/CodePath_Week_7-8.svg)

## CVE-2017-14494
 dnsmasq before 2.78, when configured as a relay, allows remote attackers to obtain sensitive memory information via vectors involving handling DHCPv6 forwarded requests.



- [https://github.com/raw-packet/raw-packet](https://github.com/raw-packet/raw-packet) :  ![starts](https://img.shields.io/github/stars/raw-packet/raw-packet.svg) ![forks](https://img.shields.io/github/forks/raw-packet/raw-packet.svg)

## CVE-2017-14493
 Stack-based buffer overflow in dnsmasq before 2.78 allows remote attackers to cause a denial of service (crash) or execute arbitrary code via a crafted DHCPv6 request.



- [https://github.com/raw-packet/raw-packet](https://github.com/raw-packet/raw-packet) :  ![starts](https://img.shields.io/github/stars/raw-packet/raw-packet.svg) ![forks](https://img.shields.io/github/forks/raw-packet/raw-packet.svg)

- [https://github.com/pupiles/bof-dnsmasq-cve-2017-14493](https://github.com/pupiles/bof-dnsmasq-cve-2017-14493) :  ![starts](https://img.shields.io/github/stars/pupiles/bof-dnsmasq-cve-2017-14493.svg) ![forks](https://img.shields.io/github/forks/pupiles/bof-dnsmasq-cve-2017-14493.svg)

## CVE-2017-14491
 Heap-based buffer overflow in dnsmasq before 2.78 allows remote attackers to cause a denial of service (crash) or execute arbitrary code via a crafted DNS response.



- [https://github.com/skyformat99/dnsmasq-2.4.1-fix-CVE-2017-14491](https://github.com/skyformat99/dnsmasq-2.4.1-fix-CVE-2017-14491) :  ![starts](https://img.shields.io/github/stars/skyformat99/dnsmasq-2.4.1-fix-CVE-2017-14491.svg) ![forks](https://img.shields.io/github/forks/skyformat99/dnsmasq-2.4.1-fix-CVE-2017-14491.svg)

## CVE-2017-14322
 The function in charge to check whether the user is already logged in init.php in Interspire Email Marketer (IEM) prior to 6.1.6 allows remote attackers to bypass authentication and obtain administrative access by using the IEM_CookieLogin cookie with a specially crafted value.



- [https://github.com/joesmithjaffa/CVE-2017-14322](https://github.com/joesmithjaffa/CVE-2017-14322) :  ![starts](https://img.shields.io/github/stars/joesmithjaffa/CVE-2017-14322.svg) ![forks](https://img.shields.io/github/forks/joesmithjaffa/CVE-2017-14322.svg)

## CVE-2017-14263
 Honeywell NVR devices allow remote attackers to create a user account in the admin group by leveraging access to a guest account to obtain a session ID, and then sending that session ID in a userManager.addUser request to the /RPC2 URI. The attacker can login to the device with that new user account to fully control the device.



- [https://github.com/zzz66686/CVE-2017-14263](https://github.com/zzz66686/CVE-2017-14263) :  ![starts](https://img.shields.io/github/stars/zzz66686/CVE-2017-14263.svg) ![forks](https://img.shields.io/github/forks/zzz66686/CVE-2017-14263.svg)

## CVE-2017-14262
 On Samsung NVR devices, remote attackers can read the MD5 password hash of the 'admin' account via certain szUserName JSON data to cgi-bin/main-cgi, and login to the device with that hash in the szUserPasswd parameter.



- [https://github.com/zzz66686/CVE-2017-14262](https://github.com/zzz66686/CVE-2017-14262) :  ![starts](https://img.shields.io/github/stars/zzz66686/CVE-2017-14262.svg) ![forks](https://img.shields.io/github/forks/zzz66686/CVE-2017-14262.svg)

## CVE-2017-14244
 An authentication bypass vulnerability on iBall Baton ADSL2+ Home Router FW_iB-LR7011A_1.0.2 devices potentially allows attackers to directly access administrative router settings by crafting URLs with a .cgi extension, as demonstrated by /info.cgi and /password.cgi.



- [https://github.com/GemGeorge/iBall-UTStar-CVEChecker](https://github.com/GemGeorge/iBall-UTStar-CVEChecker) :  ![starts](https://img.shields.io/github/stars/GemGeorge/iBall-UTStar-CVEChecker.svg) ![forks](https://img.shields.io/github/forks/GemGeorge/iBall-UTStar-CVEChecker.svg)

## CVE-2017-14243
 An authentication bypass vulnerability on UTStar WA3002G4 ADSL Broadband Modem WA3002G4-0021.01 devices allows attackers to directly access administrative settings and obtain cleartext credentials from HTML source, as demonstrated by info.cgi, upload.cgi, backupsettings.cgi, pppoe.cgi, resetrouter.cgi, and password.cgi.



- [https://github.com/GemGeorge/iBall-UTStar-CVEChecker](https://github.com/GemGeorge/iBall-UTStar-CVEChecker) :  ![starts](https://img.shields.io/github/stars/GemGeorge/iBall-UTStar-CVEChecker.svg) ![forks](https://img.shields.io/github/forks/GemGeorge/iBall-UTStar-CVEChecker.svg)

## CVE-2017-14105
 HiveManager Classic through 8.1r1 allows arbitrary JSP code execution by modifying a backup archive before a restore, because the restore feature does not validate pathnames within the archive. An authenticated, local attacker - even restricted as a tenant - can add a jsp at HiveManager/tomcat/webapps/hm/domains/$yourtenant/maps (it will be exposed at the web interface).



- [https://github.com/theguly/CVE-2017-14105](https://github.com/theguly/CVE-2017-14105) :  ![starts](https://img.shields.io/github/stars/theguly/CVE-2017-14105.svg) ![forks](https://img.shields.io/github/forks/theguly/CVE-2017-14105.svg)

## CVE-2017-13872
 An issue was discovered in certain Apple products. macOS High Sierra before Security Update 2017-001 is affected. The issue involves the &quot;Directory Utility&quot; component. It allows attackers to obtain administrator access without a password via certain interactions involving entry of the root user name.



- [https://github.com/giovannidispoto/CVE-2017-13872-Patch](https://github.com/giovannidispoto/CVE-2017-13872-Patch) :  ![starts](https://img.shields.io/github/stars/giovannidispoto/CVE-2017-13872-Patch.svg) ![forks](https://img.shields.io/github/forks/giovannidispoto/CVE-2017-13872-Patch.svg)

## CVE-2017-13868
 An issue was discovered in certain Apple products. iOS before 11.2 is affected. macOS before 10.13.2 is affected. tvOS before 11.2 is affected. watchOS before 4.2 is affected. The issue involves the &quot;Kernel&quot; component. It allows attackers to bypass intended memory-read restrictions via a crafted app.



- [https://github.com/bazad/ctl_ctloutput-leak](https://github.com/bazad/ctl_ctloutput-leak) :  ![starts](https://img.shields.io/github/stars/bazad/ctl_ctloutput-leak.svg) ![forks](https://img.shields.io/github/forks/bazad/ctl_ctloutput-leak.svg)

## CVE-2017-13672
 QEMU (aka Quick Emulator), when built with the VGA display emulator support, allows local guest OS privileged users to cause a denial of service (out-of-bounds read and QEMU process crash) via vectors involving display update.



- [https://github.com/DavidBuchanan314/CVE-2017-13672](https://github.com/DavidBuchanan314/CVE-2017-13672) :  ![starts](https://img.shields.io/github/stars/DavidBuchanan314/CVE-2017-13672.svg) ![forks](https://img.shields.io/github/forks/DavidBuchanan314/CVE-2017-13672.svg)

## CVE-2017-13253
 In CryptoPlugin::decrypt of CryptoPlugin.cpp, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation. Product: Android. Versions: 8.0, 8.1. Android ID: A-71389378.



- [https://github.com/tamirzb/CVE-2017-13253](https://github.com/tamirzb/CVE-2017-13253) :  ![starts](https://img.shields.io/github/stars/tamirzb/CVE-2017-13253.svg) ![forks](https://img.shields.io/github/forks/tamirzb/CVE-2017-13253.svg)

## CVE-2017-13208
 In receive_packet of libnetutils/packet.c, there is a possible out-of-bounds write due to a missing bounds check on the DHCP response. This could lead to remote code execution as a privileged process with no additional execution privileges needed. User interaction is not needed for exploitation. Product: Android. Versions: 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0, 8.1. Android ID: A-67474440.



- [https://github.com/tintinweb/pub](https://github.com/tintinweb/pub) :  ![starts](https://img.shields.io/github/stars/tintinweb/pub.svg) ![forks](https://img.shields.io/github/forks/tintinweb/pub.svg)

- [https://github.com/idanshechter/CVE-2017-13208-Scanner](https://github.com/idanshechter/CVE-2017-13208-Scanner) :  ![starts](https://img.shields.io/github/stars/idanshechter/CVE-2017-13208-Scanner.svg) ![forks](https://img.shields.io/github/forks/idanshechter/CVE-2017-13208-Scanner.svg)

## CVE-2017-13156
 An elevation of privilege vulnerability in the Android system (art). Product: Android. Versions: 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID A-64211847.



- [https://github.com/xyzAsian/Janus-CVE-2017-13156](https://github.com/xyzAsian/Janus-CVE-2017-13156) :  ![starts](https://img.shields.io/github/stars/xyzAsian/Janus-CVE-2017-13156.svg) ![forks](https://img.shields.io/github/forks/xyzAsian/Janus-CVE-2017-13156.svg)

- [https://github.com/giacomoferretti/janus-toolkit](https://github.com/giacomoferretti/janus-toolkit) :  ![starts](https://img.shields.io/github/stars/giacomoferretti/janus-toolkit.svg) ![forks](https://img.shields.io/github/forks/giacomoferretti/janus-toolkit.svg)

- [https://github.com/ari5ti/Janus-Vulnerability-CVE-2017-13156-Exploit-with-POC](https://github.com/ari5ti/Janus-Vulnerability-CVE-2017-13156-Exploit-with-POC) :  ![starts](https://img.shields.io/github/stars/ari5ti/Janus-Vulnerability-CVE-2017-13156-Exploit-with-POC.svg) ![forks](https://img.shields.io/github/forks/ari5ti/Janus-Vulnerability-CVE-2017-13156-Exploit-with-POC.svg)

- [https://github.com/tea9/CVE-2017-13156-Janus](https://github.com/tea9/CVE-2017-13156-Janus) :  ![starts](https://img.shields.io/github/stars/tea9/CVE-2017-13156-Janus.svg) ![forks](https://img.shields.io/github/forks/tea9/CVE-2017-13156-Janus.svg)

- [https://github.com/caxmd/CVE-2017-13156](https://github.com/caxmd/CVE-2017-13156) :  ![starts](https://img.shields.io/github/stars/caxmd/CVE-2017-13156.svg) ![forks](https://img.shields.io/github/forks/caxmd/CVE-2017-13156.svg)

## CVE-2017-13089
 The http.c:skip_short_body() function is called in some circumstances, such as when processing redirects. When the response is sent chunked in wget before 1.19.2, the chunk parser uses strtol() to read each chunk's length, but doesn't check that the chunk length is a non-negative number. The code then tries to skip the chunk in pieces of 512 bytes by using the MIN() macro, but ends up passing the negative chunk length to connect.c:fd_read(). As fd_read() takes an int argument, the high 32 bits of the chunk length are discarded, leaving fd_read() with a completely attacker controlled length argument.



- [https://github.com/mzeyong/CVE-2017-13089](https://github.com/mzeyong/CVE-2017-13089) :  ![starts](https://img.shields.io/github/stars/mzeyong/CVE-2017-13089.svg) ![forks](https://img.shields.io/github/forks/mzeyong/CVE-2017-13089.svg)

- [https://github.com/r1b/CVE-2017-13089](https://github.com/r1b/CVE-2017-13089) :  ![starts](https://img.shields.io/github/stars/r1b/CVE-2017-13089.svg) ![forks](https://img.shields.io/github/forks/r1b/CVE-2017-13089.svg)

## CVE-2017-12945
 Insufficient validation of user-supplied input for the Solstice Pod before 2.8.4 networking configuration enables authenticated attackers to execute arbitrary commands as root.



- [https://github.com/aress31/cve-2017-12945](https://github.com/aress31/cve-2017-12945) :  ![starts](https://img.shields.io/github/stars/aress31/cve-2017-12945.svg) ![forks](https://img.shields.io/github/forks/aress31/cve-2017-12945.svg)

## CVE-2017-12943
 D-Link DIR-600 Rev Bx devices with v2.x firmware allow remote attackers to read passwords via a model/__show_info.php?REQUIRE_FILE= absolute path traversal attack, as demonstrated by discovering the admin password.



- [https://github.com/aymankhalfatni/D-Link](https://github.com/aymankhalfatni/D-Link) :  ![starts](https://img.shields.io/github/stars/aymankhalfatni/D-Link.svg) ![forks](https://img.shields.io/github/forks/aymankhalfatni/D-Link.svg)

## CVE-2017-12852
 The numpy.pad function in Numpy 1.13.1 and older versions is missing input validation. An empty list or ndarray will stick into an infinite loop, which can allow attackers to cause a DoS attack.



- [https://github.com/BT123/numpy-1.13.1](https://github.com/BT123/numpy-1.13.1) :  ![starts](https://img.shields.io/github/stars/BT123/numpy-1.13.1.svg) ![forks](https://img.shields.io/github/forks/BT123/numpy-1.13.1.svg)

## CVE-2017-12842
 Bitcoin Core before 0.14 allows an attacker to create an ostensibly valid SPV proof for a payment to a victim who uses an SPV wallet, even if that payment did not actually occur. Completing the attack would cost more than a million dollars, and is relevant mainly only in situations where an autonomous system relies solely on an SPV proof for transactions of a greater dollar amount.



- [https://github.com/nondejus/CVE-2017-12842](https://github.com/nondejus/CVE-2017-12842) :  ![starts](https://img.shields.io/github/stars/nondejus/CVE-2017-12842.svg) ![forks](https://img.shields.io/github/forks/nondejus/CVE-2017-12842.svg)

## CVE-2017-12792
 Multiple cross-site request forgery (CSRF) vulnerabilities in NexusPHP 1.5 allow remote attackers to hijack the authentication of administrators for requests that conduct cross-site scripting (XSS) attacks via the (1) linkname, (2) url, or (3) title parameter in an add action to linksmanage.php.



- [https://github.com/ZZS2017/cve-2017-12792](https://github.com/ZZS2017/cve-2017-12792) :  ![starts](https://img.shields.io/github/stars/ZZS2017/cve-2017-12792.svg) ![forks](https://img.shields.io/github/forks/ZZS2017/cve-2017-12792.svg)

## CVE-2017-12717
 An Uncontrolled Search Path Element issue was discovered in Advantech WebAccess versions prior to V8.2_20170817. A maliciously crafted dll file placed earlier in the search path may allow an attacker to execute code within the context of the application.



- [https://github.com/zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717](https://github.com/zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717) :  ![starts](https://img.shields.io/github/stars/zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717.svg) ![forks](https://img.shields.io/github/forks/zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717.svg)

## CVE-2017-12636
 CouchDB administrative users can configure the database server via HTTP(S). Some of the configuration options include paths for operating system-level binaries that are subsequently launched by CouchDB. This allows an admin user in Apache CouchDB before 1.7.0 and 2.x before 2.1.1 to execute arbitrary shell commands as the CouchDB user, including downloading and executing scripts from the public internet.



- [https://github.com/RedTeamWing/CVE-2017-12636](https://github.com/RedTeamWing/CVE-2017-12636) :  ![starts](https://img.shields.io/github/stars/RedTeamWing/CVE-2017-12636.svg) ![forks](https://img.shields.io/github/forks/RedTeamWing/CVE-2017-12636.svg)

- [https://github.com/moayadalmalat/CVE-2017-12636](https://github.com/moayadalmalat/CVE-2017-12636) :  ![starts](https://img.shields.io/github/stars/moayadalmalat/CVE-2017-12636.svg) ![forks](https://img.shields.io/github/forks/moayadalmalat/CVE-2017-12636.svg)

## CVE-2017-12635
 Due to differences in the Erlang-based JSON parser and JavaScript-based JSON parser, it is possible in Apache CouchDB before 1.7.0 and 2.x before 2.1.1 to submit _users documents with duplicate keys for 'roles' used for access control within the database, including the special case '_admin' role, that denotes administrative users. In combination with CVE-2017-12636 (Remote Code Execution), this can be used to give non-admin users access to arbitrary shell commands on the server as the database system user. The JSON parser differences result in behaviour that if two 'roles' keys are available in the JSON, the second one will be used for authorising the document write, but the first 'roles' key is used for subsequent authorization for the newly created user. By design, users can not assign themselves roles. The vulnerability allows non-admin users to give themselves admin privileges.



- [https://github.com/assalielmehdi/CVE-2017-12635](https://github.com/assalielmehdi/CVE-2017-12635) :  ![starts](https://img.shields.io/github/stars/assalielmehdi/CVE-2017-12635.svg) ![forks](https://img.shields.io/github/forks/assalielmehdi/CVE-2017-12635.svg)

- [https://github.com/cyberharsh/Apache-couchdb-CVE-2017-12635](https://github.com/cyberharsh/Apache-couchdb-CVE-2017-12635) :  ![starts](https://img.shields.io/github/stars/cyberharsh/Apache-couchdb-CVE-2017-12635.svg) ![forks](https://img.shields.io/github/forks/cyberharsh/Apache-couchdb-CVE-2017-12635.svg)

## CVE-2017-12629
 Remote code execution occurs in Apache Solr before 7.1 with Apache Lucene before 7.1 by exploiting XXE in conjunction with use of a Config API add-listener command to reach the RunExecutableListener class. Elasticsearch, although it uses Lucene, is NOT vulnerable to this. Note that the XML external entity expansion vulnerability occurs in the XML Query Parser which is available, by default, for any query request with parameters deftype=xmlparser and can be exploited to upload malicious data to the /upload request handler or as Blind XXE using ftp wrapper in order to read arbitrary local files from the Solr server. Note also that the second vulnerability relates to remote code execution using the RunExecutableListener available on all affected versions of Solr.



- [https://github.com/Imanfeng/Apache-Solr-RCE](https://github.com/Imanfeng/Apache-Solr-RCE) :  ![starts](https://img.shields.io/github/stars/Imanfeng/Apache-Solr-RCE.svg) ![forks](https://img.shields.io/github/forks/Imanfeng/Apache-Solr-RCE.svg)

## CVE-2017-12624
 Apache CXF supports sending and receiving attachments via either the JAX-WS or JAX-RS specifications. It is possible to craft a message attachment header that could lead to a Denial of Service (DoS) attack on a CXF web service provider. Both JAX-WS and JAX-RS services are vulnerable to this attack. From Apache CXF 3.2.1 and 3.1.14, message attachment headers that are greater than 300 characters will be rejected by default. This value is configurable via the property &quot;attachment-max-header-size&quot;.



- [https://github.com/tafamace/CVE-2017-12624](https://github.com/tafamace/CVE-2017-12624) :  ![starts](https://img.shields.io/github/stars/tafamace/CVE-2017-12624.svg) ![forks](https://img.shields.io/github/forks/tafamace/CVE-2017-12624.svg)

## CVE-2017-12617
 When running Apache Tomcat versions 9.0.0.M1 to 9.0.0, 8.5.0 to 8.5.22, 8.0.0.RC1 to 8.0.46 and 7.0.0 to 7.0.81 with HTTP PUTs enabled (e.g. via setting the readonly initialisation parameter of the Default servlet to false) it was possible to upload a JSP file to the server via a specially crafted request. This JSP could then be requested and any code it contained would be executed by the server.



- [https://github.com/cyberheartmi9/CVE-2017-12617](https://github.com/cyberheartmi9/CVE-2017-12617) :  ![starts](https://img.shields.io/github/stars/cyberheartmi9/CVE-2017-12617.svg) ![forks](https://img.shields.io/github/forks/cyberheartmi9/CVE-2017-12617.svg)

- [https://github.com/zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717](https://github.com/zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717) :  ![starts](https://img.shields.io/github/stars/zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717.svg) ![forks](https://img.shields.io/github/forks/zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717.svg)

- [https://github.com/ygouzerh/CVE-2017-12617](https://github.com/ygouzerh/CVE-2017-12617) :  ![starts](https://img.shields.io/github/stars/ygouzerh/CVE-2017-12617.svg) ![forks](https://img.shields.io/github/forks/ygouzerh/CVE-2017-12617.svg)

- [https://github.com/jptr218/tc_hack](https://github.com/jptr218/tc_hack) :  ![starts](https://img.shields.io/github/stars/jptr218/tc_hack.svg) ![forks](https://img.shields.io/github/forks/jptr218/tc_hack.svg)

- [https://github.com/qiantu88/CVE-2017-12617](https://github.com/qiantu88/CVE-2017-12617) :  ![starts](https://img.shields.io/github/stars/qiantu88/CVE-2017-12617.svg) ![forks](https://img.shields.io/github/forks/qiantu88/CVE-2017-12617.svg)

- [https://github.com/devcoinfet/CVE-2017-12617](https://github.com/devcoinfet/CVE-2017-12617) :  ![starts](https://img.shields.io/github/stars/devcoinfet/CVE-2017-12617.svg) ![forks](https://img.shields.io/github/forks/devcoinfet/CVE-2017-12617.svg)

- [https://github.com/tyranteye666/tomcat-cve-2017-12617](https://github.com/tyranteye666/tomcat-cve-2017-12617) :  ![starts](https://img.shields.io/github/stars/tyranteye666/tomcat-cve-2017-12617.svg) ![forks](https://img.shields.io/github/forks/tyranteye666/tomcat-cve-2017-12617.svg)

## CVE-2017-12615
 When running Apache Tomcat 7.0.0 to 7.0.79 on Windows with HTTP PUTs enabled (e.g. via setting the readonly initialisation parameter of the Default to false) it was possible to upload a JSP file to the server via a specially crafted request. This JSP could then be requested and any code it contained would be executed by the server.



- [https://github.com/breaktoprotect/CVE-2017-12615](https://github.com/breaktoprotect/CVE-2017-12615) :  ![starts](https://img.shields.io/github/stars/breaktoprotect/CVE-2017-12615.svg) ![forks](https://img.shields.io/github/forks/breaktoprotect/CVE-2017-12615.svg)

- [https://github.com/mefulton/cve-2017-12615](https://github.com/mefulton/cve-2017-12615) :  ![starts](https://img.shields.io/github/stars/mefulton/cve-2017-12615.svg) ![forks](https://img.shields.io/github/forks/mefulton/cve-2017-12615.svg)

- [https://github.com/zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717](https://github.com/zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717) :  ![starts](https://img.shields.io/github/stars/zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717.svg) ![forks](https://img.shields.io/github/forks/zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717.svg)

- [https://github.com/wsg00d/cve-2017-12615](https://github.com/wsg00d/cve-2017-12615) :  ![starts](https://img.shields.io/github/stars/wsg00d/cve-2017-12615.svg) ![forks](https://img.shields.io/github/forks/wsg00d/cve-2017-12615.svg)

- [https://github.com/ianxtianxt/CVE-2017-12615](https://github.com/ianxtianxt/CVE-2017-12615) :  ![starts](https://img.shields.io/github/stars/ianxtianxt/CVE-2017-12615.svg) ![forks](https://img.shields.io/github/forks/ianxtianxt/CVE-2017-12615.svg)

- [https://github.com/1337g/CVE-2017-12615](https://github.com/1337g/CVE-2017-12615) :  ![starts](https://img.shields.io/github/stars/1337g/CVE-2017-12615.svg) ![forks](https://img.shields.io/github/forks/1337g/CVE-2017-12615.svg)

- [https://github.com/cved-sources/cve-2017-12615](https://github.com/cved-sources/cve-2017-12615) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2017-12615.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2017-12615.svg)

- [https://github.com/cyberharsh/Tomcat-CVE-2017-12615](https://github.com/cyberharsh/Tomcat-CVE-2017-12615) :  ![starts](https://img.shields.io/github/stars/cyberharsh/Tomcat-CVE-2017-12615.svg) ![forks](https://img.shields.io/github/forks/cyberharsh/Tomcat-CVE-2017-12615.svg)

- [https://github.com/BeyondCy/CVE-2017-12615](https://github.com/BeyondCy/CVE-2017-12615) :  ![starts](https://img.shields.io/github/stars/BeyondCy/CVE-2017-12615.svg) ![forks](https://img.shields.io/github/forks/BeyondCy/CVE-2017-12615.svg)

- [https://github.com/gardenWhy/CVE-2017-12615-EXP](https://github.com/gardenWhy/CVE-2017-12615-EXP) :  ![starts](https://img.shields.io/github/stars/gardenWhy/CVE-2017-12615-EXP.svg) ![forks](https://img.shields.io/github/forks/gardenWhy/CVE-2017-12615-EXP.svg)

- [https://github.com/Shellkeys/CVE-2017-12615](https://github.com/Shellkeys/CVE-2017-12615) :  ![starts](https://img.shields.io/github/stars/Shellkeys/CVE-2017-12615.svg) ![forks](https://img.shields.io/github/forks/Shellkeys/CVE-2017-12615.svg)

## CVE-2017-12611
 In Apache Struts 2.0.0 through 2.3.33 and 2.5 through 2.5.10.1, using an unintentional expression in a Freemarker tag instead of string literals can lead to a RCE attack.



- [https://github.com/brianwrf/S2-053-CVE-2017-12611](https://github.com/brianwrf/S2-053-CVE-2017-12611) :  ![starts](https://img.shields.io/github/stars/brianwrf/S2-053-CVE-2017-12611.svg) ![forks](https://img.shields.io/github/forks/brianwrf/S2-053-CVE-2017-12611.svg)

## CVE-2017-12542
 A authentication bypass and execution of code vulnerability in HPE Integrated Lights-out 4 (iLO 4) version prior to 2.53 was found.



- [https://github.com/skelsec/CVE-2017-12542](https://github.com/skelsec/CVE-2017-12542) :  ![starts](https://img.shields.io/github/stars/skelsec/CVE-2017-12542.svg) ![forks](https://img.shields.io/github/forks/skelsec/CVE-2017-12542.svg)

- [https://github.com/sk1dish/ilo4-rce-vuln-scanner](https://github.com/sk1dish/ilo4-rce-vuln-scanner) :  ![starts](https://img.shields.io/github/stars/sk1dish/ilo4-rce-vuln-scanner.svg) ![forks](https://img.shields.io/github/forks/sk1dish/ilo4-rce-vuln-scanner.svg)

## CVE-2017-12426
 GitLab Community Edition (CE) and Enterprise Edition (EE) before 8.17.8, 9.0.x before 9.0.13, 9.1.x before 9.1.10, 9.2.x before 9.2.10, 9.3.x before 9.3.10, and 9.4.x before 9.4.4 might allow remote attackers to execute arbitrary code via a crafted SSH URL in a project import.



- [https://github.com/sm-paul-schuette/CVE-2017-12426](https://github.com/sm-paul-schuette/CVE-2017-12426) :  ![starts](https://img.shields.io/github/stars/sm-paul-schuette/CVE-2017-12426.svg) ![forks](https://img.shields.io/github/forks/sm-paul-schuette/CVE-2017-12426.svg)

## CVE-2017-12149
 In Jboss Application Server as shipped with Red Hat Enterprise Application Platform 5.2, it was found that the doFilter method in the ReadOnlyAccessFilter of the HTTP Invoker does not restrict classes for which it performs deserialization and thus allowing an attacker to execute arbitrary code via crafted serialized data.



- [https://github.com/yunxu1/jboss-_CVE-2017-12149](https://github.com/yunxu1/jboss-_CVE-2017-12149) :  ![starts](https://img.shields.io/github/stars/yunxu1/jboss-_CVE-2017-12149.svg) ![forks](https://img.shields.io/github/forks/yunxu1/jboss-_CVE-2017-12149.svg)

- [https://github.com/sevck/CVE-2017-12149](https://github.com/sevck/CVE-2017-12149) :  ![starts](https://img.shields.io/github/stars/sevck/CVE-2017-12149.svg) ![forks](https://img.shields.io/github/forks/sevck/CVE-2017-12149.svg)

- [https://github.com/1337g/CVE-2017-12149](https://github.com/1337g/CVE-2017-12149) :  ![starts](https://img.shields.io/github/stars/1337g/CVE-2017-12149.svg) ![forks](https://img.shields.io/github/forks/1337g/CVE-2017-12149.svg)

- [https://github.com/jreppiks/CVE-2017-12149](https://github.com/jreppiks/CVE-2017-12149) :  ![starts](https://img.shields.io/github/stars/jreppiks/CVE-2017-12149.svg) ![forks](https://img.shields.io/github/forks/jreppiks/CVE-2017-12149.svg)

- [https://github.com/Xcatolin/jboss-deserialization](https://github.com/Xcatolin/jboss-deserialization) :  ![starts](https://img.shields.io/github/stars/Xcatolin/jboss-deserialization.svg) ![forks](https://img.shields.io/github/forks/Xcatolin/jboss-deserialization.svg)

## CVE-2017-11907
 Internet Explorer in Microsoft Windows 7 SP1, Windows Server 2008 and R2 SP1, Windows 8.1 and Windows RT 8.1, Windows Server 2012 and R2, Windows 10 Gold, 1511, 1607, 1703, 1709, and Windows Server 2016 allows an attacker to gain the same user rights as the current user, due to how Internet Explorer handles objects in memory, aka &quot;Scripting Engine Memory Corruption Vulnerability&quot;. This CVE ID is unique from CVE-2017-11886, CVE-2017-11889, CVE-2017-11890, CVE-2017-11893, CVE-2017-11894, CVE-2017-11895, CVE-2017-11901, CVE-2017-11903, CVE-2017-11905, CVE-2017-11905, CVE-2017-11908, CVE-2017-11909, CVE-2017-11910, CVE-2017-11911, CVE-2017-11912, CVE-2017-11913, CVE-2017-11914, CVE-2017-11916, CVE-2017-11918, and CVE-2017-11930.



- [https://github.com/AV1080p/CVE-2017-11907](https://github.com/AV1080p/CVE-2017-11907) :  ![starts](https://img.shields.io/github/stars/AV1080p/CVE-2017-11907.svg) ![forks](https://img.shields.io/github/forks/AV1080p/CVE-2017-11907.svg)

## CVE-2017-11882
 Microsoft Office 2007 Service Pack 3, Microsoft Office 2010 Service Pack 2, Microsoft Office 2013 Service Pack 1, and Microsoft Office 2016 allow an attacker to run arbitrary code in the context of the current user by failing to properly handle objects in memory, aka &quot;Microsoft Office Memory Corruption Vulnerability&quot;. This CVE ID is unique from CVE-2017-11884.



- [https://github.com/Ridter/CVE-2017-11882](https://github.com/Ridter/CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/Ridter/CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/Ridter/CVE-2017-11882.svg)

- [https://github.com/embedi/CVE-2017-11882](https://github.com/embedi/CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/embedi/CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/embedi/CVE-2017-11882.svg)

- [https://github.com/unamer/CVE-2017-11882](https://github.com/unamer/CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/unamer/CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/unamer/CVE-2017-11882.svg)

- [https://github.com/rxwx/CVE-2018-0802](https://github.com/rxwx/CVE-2018-0802) :  ![starts](https://img.shields.io/github/stars/rxwx/CVE-2018-0802.svg) ![forks](https://img.shields.io/github/forks/rxwx/CVE-2018-0802.svg)

- [https://github.com/Ridter/RTF_11882_0802](https://github.com/Ridter/RTF_11882_0802) :  ![starts](https://img.shields.io/github/stars/Ridter/RTF_11882_0802.svg) ![forks](https://img.shields.io/github/forks/Ridter/RTF_11882_0802.svg)

- [https://github.com/0x09AL/CVE-2017-11882-metasploit](https://github.com/0x09AL/CVE-2017-11882-metasploit) :  ![starts](https://img.shields.io/github/stars/0x09AL/CVE-2017-11882-metasploit.svg) ![forks](https://img.shields.io/github/forks/0x09AL/CVE-2017-11882-metasploit.svg)

- [https://github.com/starnightcyber/CVE-2017-11882](https://github.com/starnightcyber/CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/starnightcyber/CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/starnightcyber/CVE-2017-11882.svg)

- [https://github.com/BlackMathIT/2017-11882_Generator](https://github.com/BlackMathIT/2017-11882_Generator) :  ![starts](https://img.shields.io/github/stars/BlackMathIT/2017-11882_Generator.svg) ![forks](https://img.shields.io/github/forks/BlackMathIT/2017-11882_Generator.svg)

- [https://github.com/likescam/CVE-2018-0802_CVE-2017-11882](https://github.com/likescam/CVE-2018-0802_CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/likescam/CVE-2018-0802_CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/likescam/CVE-2018-0802_CVE-2017-11882.svg)

- [https://github.com/dcsync/rtfkit](https://github.com/dcsync/rtfkit) :  ![starts](https://img.shields.io/github/stars/dcsync/rtfkit.svg) ![forks](https://img.shields.io/github/forks/dcsync/rtfkit.svg)

- [https://github.com/littlebin404/CVE-2017-11882](https://github.com/littlebin404/CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/littlebin404/CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/littlebin404/CVE-2017-11882.svg)

- [https://github.com/Retr0-code/SignHere](https://github.com/Retr0-code/SignHere) :  ![starts](https://img.shields.io/github/stars/Retr0-code/SignHere.svg) ![forks](https://img.shields.io/github/forks/Retr0-code/SignHere.svg)

- [https://github.com/zhouat/cve-2017-11882](https://github.com/zhouat/cve-2017-11882) :  ![starts](https://img.shields.io/github/stars/zhouat/cve-2017-11882.svg) ![forks](https://img.shields.io/github/forks/zhouat/cve-2017-11882.svg)

- [https://github.com/ChaitanyaHaritash/CVE-2017-11882](https://github.com/ChaitanyaHaritash/CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/ChaitanyaHaritash/CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/ChaitanyaHaritash/CVE-2017-11882.svg)

- [https://github.com/ekgg/Overflow-Demo-CVE-2017-11882](https://github.com/ekgg/Overflow-Demo-CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/ekgg/Overflow-Demo-CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/ekgg/Overflow-Demo-CVE-2017-11882.svg)

- [https://github.com/R0fM1a/IDB_Share](https://github.com/R0fM1a/IDB_Share) :  ![starts](https://img.shields.io/github/stars/R0fM1a/IDB_Share.svg) ![forks](https://img.shields.io/github/forks/R0fM1a/IDB_Share.svg)

- [https://github.com/Shadowshusky/CVE-2017-11882-](https://github.com/Shadowshusky/CVE-2017-11882-) :  ![starts](https://img.shields.io/github/stars/Shadowshusky/CVE-2017-11882-.svg) ![forks](https://img.shields.io/github/forks/Shadowshusky/CVE-2017-11882-.svg)

- [https://github.com/bloomer1016/CVE-2017-11882-Possible-Remcos-Malspam](https://github.com/bloomer1016/CVE-2017-11882-Possible-Remcos-Malspam) :  ![starts](https://img.shields.io/github/stars/bloomer1016/CVE-2017-11882-Possible-Remcos-Malspam.svg) ![forks](https://img.shields.io/github/forks/bloomer1016/CVE-2017-11882-Possible-Remcos-Malspam.svg)

- [https://github.com/letiencong96/CVE_2017_11882](https://github.com/letiencong96/CVE_2017_11882) :  ![starts](https://img.shields.io/github/stars/letiencong96/CVE_2017_11882.svg) ![forks](https://img.shields.io/github/forks/letiencong96/CVE_2017_11882.svg)

- [https://github.com/HZachev/ABC](https://github.com/HZachev/ABC) :  ![starts](https://img.shields.io/github/stars/HZachev/ABC.svg) ![forks](https://img.shields.io/github/forks/HZachev/ABC.svg)

- [https://github.com/CSC-pentest/cve-2017-11882](https://github.com/CSC-pentest/cve-2017-11882) :  ![starts](https://img.shields.io/github/stars/CSC-pentest/cve-2017-11882.svg) ![forks](https://img.shields.io/github/forks/CSC-pentest/cve-2017-11882.svg)

- [https://github.com/j0lama/CVE-2017-11882](https://github.com/j0lama/CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/j0lama/CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/j0lama/CVE-2017-11882.svg)

- [https://github.com/likescam/CVE-2017-11882](https://github.com/likescam/CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/likescam/CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/likescam/CVE-2017-11882.svg)

- [https://github.com/chanbin/CVE-2017-11882](https://github.com/chanbin/CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/chanbin/CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/chanbin/CVE-2017-11882.svg)

- [https://github.com/HaoJame/CVE-2017-11882](https://github.com/HaoJame/CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/HaoJame/CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/HaoJame/CVE-2017-11882.svg)

- [https://github.com/ActorExpose/CVE-2017-11882](https://github.com/ActorExpose/CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/ActorExpose/CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/ActorExpose/CVE-2017-11882.svg)

- [https://github.com/Grey-Li/CVE-2017-11882](https://github.com/Grey-Li/CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/Grey-Li/CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/Grey-Li/CVE-2017-11882.svg)

- [https://github.com/legendsec/CVE-2017-11882-for-Kali](https://github.com/legendsec/CVE-2017-11882-for-Kali) :  ![starts](https://img.shields.io/github/stars/legendsec/CVE-2017-11882-for-Kali.svg) ![forks](https://img.shields.io/github/forks/legendsec/CVE-2017-11882-for-Kali.svg)

- [https://github.com/qy1202/https-github.com-Ridter-CVE-2017-11882-](https://github.com/qy1202/https-github.com-Ridter-CVE-2017-11882-) :  ![starts](https://img.shields.io/github/stars/qy1202/https-github.com-Ridter-CVE-2017-11882-.svg) ![forks](https://img.shields.io/github/forks/qy1202/https-github.com-Ridter-CVE-2017-11882-.svg)

## CVE-2017-11826
 Microsoft Office 2010, SharePoint Enterprise Server 2010, SharePoint Server 2010, Web Applications, Office Web Apps Server 2010 and 2013, Word Viewer, Word 2007, 2010, 2013 and 2016, Word Automation Services, and Office Online Server allow remote code execution when the software fails to properly handle objects in memory.



- [https://github.com/thatskriptkid/CVE-2017-11826](https://github.com/thatskriptkid/CVE-2017-11826) :  ![starts](https://img.shields.io/github/stars/thatskriptkid/CVE-2017-11826.svg) ![forks](https://img.shields.io/github/forks/thatskriptkid/CVE-2017-11826.svg)

- [https://github.com/9aylas/DDE-MS_WORD-Exploit_Detector](https://github.com/9aylas/DDE-MS_WORD-Exploit_Detector) :  ![starts](https://img.shields.io/github/stars/9aylas/DDE-MS_WORD-Exploit_Detector.svg) ![forks](https://img.shields.io/github/forks/9aylas/DDE-MS_WORD-Exploit_Detector.svg)

## CVE-2017-11816
 The Microsoft Windows Graphics Device Interface (GDI) on Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, and 1703, and Windows Server 2016 allows an information disclosure vulnerability in the way it handles objects in memory, aka &quot;Windows GDI Information Disclosure Vulnerability&quot;.



- [https://github.com/lr3800/CVE-2017-11816](https://github.com/lr3800/CVE-2017-11816) :  ![starts](https://img.shields.io/github/stars/lr3800/CVE-2017-11816.svg) ![forks](https://img.shields.io/github/forks/lr3800/CVE-2017-11816.svg)

## CVE-2017-11783
 Microsoft Windows 8.1, Windows Server 2012 R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, and 1703, and Windows Server 2016 allows an elevation of privilege vulnerability in the way it handles calls to Advanced Local Procedure Call (ALPC), aka &quot;Windows Elevation of Privilege Vulnerability&quot;.



- [https://github.com/Sheisback/CVE-2017-11783](https://github.com/Sheisback/CVE-2017-11783) :  ![starts](https://img.shields.io/github/stars/Sheisback/CVE-2017-11783.svg) ![forks](https://img.shields.io/github/forks/Sheisback/CVE-2017-11783.svg)

## CVE-2017-11774
 Microsoft Outlook 2010 SP2, Outlook 2013 SP1 and RT SP1, and Outlook 2016 allow an attacker to execute arbitrary commands, due to how Microsoft Office handles objects in memory, aka &quot;Microsoft Outlook Security Feature Bypass Vulnerability.&quot;



- [https://github.com/devcoinfet/SniperRoost](https://github.com/devcoinfet/SniperRoost) :  ![starts](https://img.shields.io/github/stars/devcoinfet/SniperRoost.svg) ![forks](https://img.shields.io/github/forks/devcoinfet/SniperRoost.svg)

## CVE-2017-11611
 Wolf CMS 0.8.3.1 allows Cross-Site Scripting (XSS) attacks. The vulnerability exists due to insufficient sanitization of the file name in a &quot;create-file-popup&quot; action, and the directory name in a &quot;create-directory-popup&quot; action, in the HTTP POST method to the &quot;/plugin/file_manager/&quot; script (aka an /admin/plugin/file_manager/browse// URI).



- [https://github.com/faizzaidi/Wolfcms-v0.8.3.1-xss-POC-by-Provensec-llc](https://github.com/faizzaidi/Wolfcms-v0.8.3.1-xss-POC-by-Provensec-llc) :  ![starts](https://img.shields.io/github/stars/faizzaidi/Wolfcms-v0.8.3.1-xss-POC-by-Provensec-llc.svg) ![forks](https://img.shields.io/github/forks/faizzaidi/Wolfcms-v0.8.3.1-xss-POC-by-Provensec-llc.svg)

## CVE-2017-11610
 The XML-RPC server in supervisor before 3.0.1, 3.1.x before 3.1.4, 3.2.x before 3.2.4, and 3.3.x before 3.3.3 allows remote authenticated users to execute arbitrary commands via a crafted XML-RPC request, related to nested supervisord namespace lookups.



- [https://github.com/yaunsky/CVE-2017-11610](https://github.com/yaunsky/CVE-2017-11610) :  ![starts](https://img.shields.io/github/stars/yaunsky/CVE-2017-11610.svg) ![forks](https://img.shields.io/github/forks/yaunsky/CVE-2017-11610.svg)

- [https://github.com/ivanitlearning/CVE-2017-11610](https://github.com/ivanitlearning/CVE-2017-11610) :  ![starts](https://img.shields.io/github/stars/ivanitlearning/CVE-2017-11610.svg) ![forks](https://img.shields.io/github/forks/ivanitlearning/CVE-2017-11610.svg)

## CVE-2017-11519
 passwd_recovery.lua on the TP-Link Archer C9(UN)_V2_160517 allows an attacker to reset the admin password by leveraging a predictable random number generator seed. This is fixed in C9(UN)_V2_170511.



- [https://github.com/vakzz/tplink-CVE-2017-11519](https://github.com/vakzz/tplink-CVE-2017-11519) :  ![starts](https://img.shields.io/github/stars/vakzz/tplink-CVE-2017-11519.svg) ![forks](https://img.shields.io/github/forks/vakzz/tplink-CVE-2017-11519.svg)

## CVE-2017-11503
 PHPMailer 5.2.23 has XSS in the &quot;From Email Address&quot; and &quot;To Email Address&quot; fields of code_generator.php.



- [https://github.com/wizardafric/download](https://github.com/wizardafric/download) :  ![starts](https://img.shields.io/github/stars/wizardafric/download.svg) ![forks](https://img.shields.io/github/forks/wizardafric/download.svg)

## CVE-2017-11427
 OneLogin PythonSAML 2.3.0 and earlier may incorrectly utilize the results of XML DOM traversal and canonicalization APIs in such a way that an attacker may be able to manipulate the SAML data without invalidating the cryptographic signature, allowing the attack to potentially bypass authentication to SAML service providers.



- [https://github.com/CHYbeta/CVE-2017-11427-DEMO](https://github.com/CHYbeta/CVE-2017-11427-DEMO) :  ![starts](https://img.shields.io/github/stars/CHYbeta/CVE-2017-11427-DEMO.svg) ![forks](https://img.shields.io/github/forks/CHYbeta/CVE-2017-11427-DEMO.svg)

## CVE-2017-11357
 Progress Telerik UI for ASP.NET AJAX before R2 2017 SP2 does not properly restrict user input to RadAsyncUpload, which allows remote attackers to perform arbitrary file uploads or execute arbitrary code.



- [https://github.com/bao7uo/RAU_crypto](https://github.com/bao7uo/RAU_crypto) :  ![starts](https://img.shields.io/github/stars/bao7uo/RAU_crypto.svg) ![forks](https://img.shields.io/github/forks/bao7uo/RAU_crypto.svg)

## CVE-2017-11317
 Telerik.Web.UI in Progress Telerik UI for ASP.NET AJAX before R1 2017 and R2 before R2 2017 SP2 uses weak RadAsyncUpload encryption, which allows remote attackers to perform arbitrary file uploads or execute arbitrary code.



- [https://github.com/bao7uo/RAU_crypto](https://github.com/bao7uo/RAU_crypto) :  ![starts](https://img.shields.io/github/stars/bao7uo/RAU_crypto.svg) ![forks](https://img.shields.io/github/forks/bao7uo/RAU_crypto.svg)

## CVE-2017-11176
 The mq_notify function in the Linux kernel through 4.11.9 does not set the sock pointer to NULL upon entry into the retry logic. During a user-space close of a Netlink socket, it allows attackers to cause a denial of service (use-after-free) or possibly have unspecified other impact.



- [https://github.com/lexfo/cve-2017-11176](https://github.com/lexfo/cve-2017-11176) :  ![starts](https://img.shields.io/github/stars/lexfo/cve-2017-11176.svg) ![forks](https://img.shields.io/github/forks/lexfo/cve-2017-11176.svg)

- [https://github.com/c3r34lk1ll3r/CVE-2017-11176](https://github.com/c3r34lk1ll3r/CVE-2017-11176) :  ![starts](https://img.shields.io/github/stars/c3r34lk1ll3r/CVE-2017-11176.svg) ![forks](https://img.shields.io/github/forks/c3r34lk1ll3r/CVE-2017-11176.svg)

- [https://github.com/DoubleMice/cve-2017-11176](https://github.com/DoubleMice/cve-2017-11176) :  ![starts](https://img.shields.io/github/stars/DoubleMice/cve-2017-11176.svg) ![forks](https://img.shields.io/github/forks/DoubleMice/cve-2017-11176.svg)

- [https://github.com/leonardo1101/cve-2017-11176](https://github.com/leonardo1101/cve-2017-11176) :  ![starts](https://img.shields.io/github/stars/leonardo1101/cve-2017-11176.svg) ![forks](https://img.shields.io/github/forks/leonardo1101/cve-2017-11176.svg)

- [https://github.com/applemasterz17/CVE-2017-11176](https://github.com/applemasterz17/CVE-2017-11176) :  ![starts](https://img.shields.io/github/stars/applemasterz17/CVE-2017-11176.svg) ![forks](https://img.shields.io/github/forks/applemasterz17/CVE-2017-11176.svg)

- [https://github.com/HckEX/CVE-2017-11176](https://github.com/HckEX/CVE-2017-11176) :  ![starts](https://img.shields.io/github/stars/HckEX/CVE-2017-11176.svg) ![forks](https://img.shields.io/github/forks/HckEX/CVE-2017-11176.svg)

## CVE-2017-11104
 Knot DNS before 2.4.5 and 2.5.x before 2.5.2 contains a flaw within the TSIG protocol implementation that would allow an attacker with a valid key name and algorithm to bypass TSIG authentication if no additional ACL restrictions are set, because of an improper TSIG validity period check.



- [https://github.com/saaph/CVE-2017-3143](https://github.com/saaph/CVE-2017-3143) :  ![starts](https://img.shields.io/github/stars/saaph/CVE-2017-3143.svg) ![forks](https://img.shields.io/github/forks/saaph/CVE-2017-3143.svg)

## CVE-2017-10952
 This vulnerability allows remote attackers to execute arbitrary code on vulnerable installations of Foxit Reader 8.2.0.2051. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the saveAs JavaScript function. The issue results from the lack of proper validation of user-supplied data, which can lead to writing arbitrary files into attacker controlled locations. An attacker can leverage this vulnerability to execute code under the context of the current process. Was ZDI-CAN-4518.



- [https://github.com/afbase/CVE-2017-10952](https://github.com/afbase/CVE-2017-10952) :  ![starts](https://img.shields.io/github/stars/afbase/CVE-2017-10952.svg) ![forks](https://img.shields.io/github/forks/afbase/CVE-2017-10952.svg)

## CVE-2017-10910
 MQTT.js 2.x.x prior to 2.15.0 issue in handling PUBLISH tickets may lead to an attacker causing a denial-of-service condition.



- [https://github.com/ossf-cve-benchmark/CVE-2017-10910](https://github.com/ossf-cve-benchmark/CVE-2017-10910) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-10910.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-10910.svg)

## CVE-2017-10797
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem.  When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/n4xh4ck5/CVE-2017-10797](https://github.com/n4xh4ck5/CVE-2017-10797) :  ![starts](https://img.shields.io/github/stars/n4xh4ck5/CVE-2017-10797.svg) ![forks](https://img.shields.io/github/forks/n4xh4ck5/CVE-2017-10797.svg)

## CVE-2017-10661
 Race condition in fs/timerfd.c in the Linux kernel before 4.10.15 allows local users to gain privileges or cause a denial of service (list corruption or use-after-free) via simultaneous file-descriptor operations that leverage improper might_cancel queueing.



- [https://github.com/GeneBlue/CVE-2017-10661_POC](https://github.com/GeneBlue/CVE-2017-10661_POC) :  ![starts](https://img.shields.io/github/stars/GeneBlue/CVE-2017-10661_POC.svg) ![forks](https://img.shields.io/github/forks/GeneBlue/CVE-2017-10661_POC.svg)

## CVE-2017-10617
 The ifmap service that comes bundled with Contrail has an XML External Entity (XXE) vulnerability that may allow an attacker to retrieve sensitive system files. Affected releases are Juniper Networks Contrail 2.2 prior to 2.21.4; 3.0 prior to 3.0.3.4; 3.1 prior to 3.1.4.0; 3.2 prior to 3.2.5.0. CVE-2017-10616 and CVE-2017-10617 can be chained together and have a combined CVSSv3 score of 5.8 (AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N).



- [https://github.com/gteissier/CVE-2017-10617](https://github.com/gteissier/CVE-2017-10617) :  ![starts](https://img.shields.io/github/stars/gteissier/CVE-2017-10617.svg) ![forks](https://img.shields.io/github/forks/gteissier/CVE-2017-10617.svg)

## CVE-2017-10616
 The ifmap service that comes bundled with Juniper Networks Contrail releases uses hard coded credentials. Affected releases are Contrail releases 2.2 prior to 2.21.4; 3.0 prior to 3.0.3.4; 3.1 prior to 3.1.4.0; 3.2 prior to 3.2.5.0. CVE-2017-10616 and CVE-2017-10617 can be chained together and have a combined CVSSv3 score of 5.8 (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N).



- [https://github.com/gteissier/CVE-2017-10617](https://github.com/gteissier/CVE-2017-10617) :  ![starts](https://img.shields.io/github/stars/gteissier/CVE-2017-10617.svg) ![forks](https://img.shields.io/github/forks/gteissier/CVE-2017-10617.svg)

## CVE-2017-10417
 Vulnerability in the Oracle Advanced Outbound Telephony component of Oracle E-Business Suite (subcomponent: Setup and Configuration). Supported versions that are affected are 12.2.3, 12.2.4, 12.2.5, 12.2.6 and 12.2.7. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Advanced Outbound Telephony. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle Advanced Outbound Telephony, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle Advanced Outbound Telephony accessible data as well as unauthorized update, insert or delete access to some of Oracle Advanced Outbound Telephony accessible data. CVSS 3.0 Base Score 8.2 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N).



- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)

## CVE-2017-10416
 Vulnerability in the Oracle Advanced Outbound Telephony component of Oracle E-Business Suite (subcomponent: Setup and Configuration). Supported versions that are affected are 12.2.3, 12.2.4, 12.2.5, 12.2.6 and 12.2.7. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Advanced Outbound Telephony. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle Advanced Outbound Telephony, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle Advanced Outbound Telephony accessible data as well as unauthorized update, insert or delete access to some of Oracle Advanced Outbound Telephony accessible data. CVSS 3.0 Base Score 8.2 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N).



- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)

## CVE-2017-10415
 Vulnerability in the Oracle iSupport component of Oracle E-Business Suite (subcomponent: Others). Supported versions that are affected are 12.1.1, 12.1.2, 12.1.3, 12.2.3, 12.2.4, 12.2.5, 12.2.6 and 12.2.7. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle iSupport. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle iSupport, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle iSupport accessible data as well as unauthorized update, insert or delete access to some of Oracle iSupport accessible data. CVSS 3.0 Base Score 8.2 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N).



- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)

## CVE-2017-10414
 Vulnerability in the Oracle iStore component of Oracle E-Business Suite (subcomponent: Checkout and Order Placement). Supported versions that are affected are 12.1.1, 12.1.2, 12.1.3, 12.2.3, 12.2.4, 12.2.5, 12.2.6 and 12.2.7. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle iStore. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle iStore, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle iStore accessible data as well as unauthorized update, insert or delete access to some of Oracle iStore accessible data. CVSS 3.0 Base Score 8.2 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N).



- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)

## CVE-2017-10413
 Vulnerability in the Oracle Mobile Field Service component of Oracle E-Business Suite (subcomponent: Multiplatform Based on HTML5). Supported versions that are affected are 12.1.1, 12.1.2, 12.1.3, 12.2.3, 12.2.4, 12.2.5, 12.2.6 and 12.2.7. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Mobile Field Service. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle Mobile Field Service, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle Mobile Field Service accessible data as well as unauthorized update, insert or delete access to some of Oracle Mobile Field Service accessible data. CVSS 3.0 Base Score 8.2 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N).



- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)

## CVE-2017-10412
 Vulnerability in the Oracle Knowledge Management component of Oracle E-Business Suite (subcomponent: User Interface). Supported versions that are affected are 12.1.1, 12.1.2, 12.1.3, 12.2.3, 12.2.4, 12.2.5, 12.2.6 and 12.2.7. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Knowledge Management. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle Knowledge Management, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle Knowledge Management accessible data as well as unauthorized update, insert or delete access to some of Oracle Knowledge Management accessible data. CVSS 3.0 Base Score 8.2 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N).



- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)

## CVE-2017-10411
 Vulnerability in the Oracle Knowledge Management component of Oracle E-Business Suite (subcomponent: User Interface). Supported versions that are affected are 12.1.1, 12.1.2, 12.1.3, 12.2.3, 12.2.4, 12.2.5, 12.2.6 and 12.2.7. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Knowledge Management. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle Knowledge Management, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle Knowledge Management accessible data as well as unauthorized update, insert or delete access to some of Oracle Knowledge Management accessible data. CVSS 3.0 Base Score 8.2 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N).



- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)

## CVE-2017-10410
 Vulnerability in the Oracle Knowledge Management component of Oracle E-Business Suite (subcomponent: Search). Supported versions that are affected are 12.1.1, 12.1.2, 12.1.3, 12.2.3, 12.2.4, 12.2.5, 12.2.6 and 12.2.7. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Knowledge Management. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle Knowledge Management, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle Knowledge Management accessible data as well as unauthorized update, insert or delete access to some of Oracle Knowledge Management accessible data. CVSS 3.0 Base Score 8.2 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N).



- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)

## CVE-2017-10409
 Vulnerability in the Oracle iStore component of Oracle E-Business Suite (subcomponent: Merchant UI). Supported versions that are affected are 12.1.1, 12.1.2, 12.1.3, 12.2.3, 12.2.4, 12.2.5, 12.2.6 and 12.2.7. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle iStore. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle iStore, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle iStore accessible data as well as unauthorized update, insert or delete access to some of Oracle iStore accessible data. CVSS 3.0 Base Score 8.2 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N).



- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)

## CVE-2017-10366
 Vulnerability in the PeopleSoft Enterprise PT PeopleTools component of Oracle PeopleSoft Products (subcomponent: Performance Monitor). Supported versions that are affected are 8.54, 8.55 and 8.56. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise PeopleSoft Enterprise PT PeopleTools. Successful attacks of this vulnerability can result in takeover of PeopleSoft Enterprise PT PeopleTools. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).



- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)

- [https://github.com/blazeinfosec/CVE-2017-10366_peoplesoft](https://github.com/blazeinfosec/CVE-2017-10366_peoplesoft) :  ![starts](https://img.shields.io/github/stars/blazeinfosec/CVE-2017-10366_peoplesoft.svg) ![forks](https://img.shields.io/github/forks/blazeinfosec/CVE-2017-10366_peoplesoft.svg)

## CVE-2017-10352
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS - Web Services). The supported version that is affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.1.0, 12.2.1.2.0 and 12.2.1.3.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. While the vulnerability is in Oracle WebLogic Server, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle WebLogic Server as well as unauthorized update, insert or delete access to some of Oracle WebLogic Server accessible data and unauthorized read access to a subset of Oracle WebLogic Server accessible data. CVSS 3.0 Base Score 9.9 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:H).



- [https://github.com/bigsizeme/weblogic-XMLDecoder](https://github.com/bigsizeme/weblogic-XMLDecoder) :  ![starts](https://img.shields.io/github/stars/bigsizeme/weblogic-XMLDecoder.svg) ![forks](https://img.shields.io/github/forks/bigsizeme/weblogic-XMLDecoder.svg)

## CVE-2017-10271
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Security). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.1.0 and 12.2.1.2.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 7.5 (Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H).



- [https://github.com/0xn0ne/weblogicScanner](https://github.com/0xn0ne/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/0xn0ne/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/0xn0ne/weblogicScanner.svg)

- [https://github.com/shack2/javaserializetools](https://github.com/shack2/javaserializetools) :  ![starts](https://img.shields.io/github/stars/shack2/javaserializetools.svg) ![forks](https://img.shields.io/github/forks/shack2/javaserializetools.svg)

- [https://github.com/c0mmand3rOpSec/CVE-2017-10271](https://github.com/c0mmand3rOpSec/CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/c0mmand3rOpSec/CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/c0mmand3rOpSec/CVE-2017-10271.svg)

- [https://github.com/kkirsche/CVE-2017-10271](https://github.com/kkirsche/CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/kkirsche/CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/kkirsche/CVE-2017-10271.svg)

- [https://github.com/7kbstorm/WebLogic_CNVD_C2019_48814](https://github.com/7kbstorm/WebLogic_CNVD_C2019_48814) :  ![starts](https://img.shields.io/github/stars/7kbstorm/WebLogic_CNVD_C2019_48814.svg) ![forks](https://img.shields.io/github/forks/7kbstorm/WebLogic_CNVD_C2019_48814.svg)

- [https://github.com/SkyBlueEternal/CNVD-C-2019-48814-CNNVD-201904-961](https://github.com/SkyBlueEternal/CNVD-C-2019-48814-CNNVD-201904-961) :  ![starts](https://img.shields.io/github/stars/SkyBlueEternal/CNVD-C-2019-48814-CNNVD-201904-961.svg) ![forks](https://img.shields.io/github/forks/SkyBlueEternal/CNVD-C-2019-48814-CNNVD-201904-961.svg)

- [https://github.com/1337g/CVE-2017-10271](https://github.com/1337g/CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/1337g/CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/1337g/CVE-2017-10271.svg)

- [https://github.com/Luffin/CVE-2017-10271](https://github.com/Luffin/CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/Luffin/CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/Luffin/CVE-2017-10271.svg)

- [https://github.com/s3xy/CVE-2017-10271](https://github.com/s3xy/CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/s3xy/CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/s3xy/CVE-2017-10271.svg)

- [https://github.com/Cymmetria/weblogic_honeypot](https://github.com/Cymmetria/weblogic_honeypot) :  ![starts](https://img.shields.io/github/stars/Cymmetria/weblogic_honeypot.svg) ![forks](https://img.shields.io/github/forks/Cymmetria/weblogic_honeypot.svg)

- [https://github.com/bigsizeme/weblogic-XMLDecoder](https://github.com/bigsizeme/weblogic-XMLDecoder) :  ![starts](https://img.shields.io/github/stars/bigsizeme/weblogic-XMLDecoder.svg) ![forks](https://img.shields.io/github/forks/bigsizeme/weblogic-XMLDecoder.svg)

- [https://github.com/ETOCheney/JavaDeserialization](https://github.com/ETOCheney/JavaDeserialization) :  ![starts](https://img.shields.io/github/stars/ETOCheney/JavaDeserialization.svg) ![forks](https://img.shields.io/github/forks/ETOCheney/JavaDeserialization.svg)

- [https://github.com/SuperHacker-liuan/cve-2017-10271-poc](https://github.com/SuperHacker-liuan/cve-2017-10271-poc) :  ![starts](https://img.shields.io/github/stars/SuperHacker-liuan/cve-2017-10271-poc.svg) ![forks](https://img.shields.io/github/forks/SuperHacker-liuan/cve-2017-10271-poc.svg)

- [https://github.com/pssss/CVE-2017-10271](https://github.com/pssss/CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/pssss/CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/pssss/CVE-2017-10271.svg)

- [https://github.com/kbsec/Weblogic_Wsat_RCE](https://github.com/kbsec/Weblogic_Wsat_RCE) :  ![starts](https://img.shields.io/github/stars/kbsec/Weblogic_Wsat_RCE.svg) ![forks](https://img.shields.io/github/forks/kbsec/Weblogic_Wsat_RCE.svg)

- [https://github.com/ianxtianxt/-CVE-2017-10271-](https://github.com/ianxtianxt/-CVE-2017-10271-) :  ![starts](https://img.shields.io/github/stars/ianxtianxt/-CVE-2017-10271-.svg) ![forks](https://img.shields.io/github/forks/ianxtianxt/-CVE-2017-10271-.svg)

- [https://github.com/ZH3FENG/PoCs-Weblogic_2017_10271](https://github.com/ZH3FENG/PoCs-Weblogic_2017_10271) :  ![starts](https://img.shields.io/github/stars/ZH3FENG/PoCs-Weblogic_2017_10271.svg) ![forks](https://img.shields.io/github/forks/ZH3FENG/PoCs-Weblogic_2017_10271.svg)

- [https://github.com/cjjduck/weblogic_wls_wsat_rce](https://github.com/cjjduck/weblogic_wls_wsat_rce) :  ![starts](https://img.shields.io/github/stars/cjjduck/weblogic_wls_wsat_rce.svg) ![forks](https://img.shields.io/github/forks/cjjduck/weblogic_wls_wsat_rce.svg)

- [https://github.com/nhwuxiaojun/CVE-2017-10271](https://github.com/nhwuxiaojun/CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/nhwuxiaojun/CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/nhwuxiaojun/CVE-2017-10271.svg)

- [https://github.com/s0wr0b1ndef/Oracle-WebLogic-WLS-WSAT](https://github.com/s0wr0b1ndef/Oracle-WebLogic-WLS-WSAT) :  ![starts](https://img.shields.io/github/stars/s0wr0b1ndef/Oracle-WebLogic-WLS-WSAT.svg) ![forks](https://img.shields.io/github/forks/s0wr0b1ndef/Oracle-WebLogic-WLS-WSAT.svg)

- [https://github.com/XHSecurity/Oracle-WebLogic-CVE-2017-10271](https://github.com/XHSecurity/Oracle-WebLogic-CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/XHSecurity/Oracle-WebLogic-CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/XHSecurity/Oracle-WebLogic-CVE-2017-10271.svg)

- [https://github.com/JackyTsuuuy/weblogic_wls_rce_poc-exp](https://github.com/JackyTsuuuy/weblogic_wls_rce_poc-exp) :  ![starts](https://img.shields.io/github/stars/JackyTsuuuy/weblogic_wls_rce_poc-exp.svg) ![forks](https://img.shields.io/github/forks/JackyTsuuuy/weblogic_wls_rce_poc-exp.svg)

- [https://github.com/bmcculley/CVE-2017-10271](https://github.com/bmcculley/CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/bmcculley/CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/bmcculley/CVE-2017-10271.svg)

- [https://github.com/lonehand/Oracle-WebLogic-CVE-2017-10271-master](https://github.com/lonehand/Oracle-WebLogic-CVE-2017-10271-master) :  ![starts](https://img.shields.io/github/stars/lonehand/Oracle-WebLogic-CVE-2017-10271-master.svg) ![forks](https://img.shields.io/github/forks/lonehand/Oracle-WebLogic-CVE-2017-10271-master.svg)

- [https://github.com/Yuusuke4/WebLogic_CNVD_C_2019_48814](https://github.com/Yuusuke4/WebLogic_CNVD_C_2019_48814) :  ![starts](https://img.shields.io/github/stars/Yuusuke4/WebLogic_CNVD_C_2019_48814.svg) ![forks](https://img.shields.io/github/forks/Yuusuke4/WebLogic_CNVD_C_2019_48814.svg)

- [https://github.com/pizza-power/weblogic-CVE-2019-2729-POC](https://github.com/pizza-power/weblogic-CVE-2019-2729-POC) :  ![starts](https://img.shields.io/github/stars/pizza-power/weblogic-CVE-2019-2729-POC.svg) ![forks](https://img.shields.io/github/forks/pizza-power/weblogic-CVE-2019-2729-POC.svg)

- [https://github.com/peterpeter228/Oracle-WebLogic-CVE-2017-10271](https://github.com/peterpeter228/Oracle-WebLogic-CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/peterpeter228/Oracle-WebLogic-CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/peterpeter228/Oracle-WebLogic-CVE-2017-10271.svg)

- [https://github.com/testwc/CVE-2017-10271](https://github.com/testwc/CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/testwc/CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/testwc/CVE-2017-10271.svg)

- [https://github.com/Al1ex/CVE-2017-10271](https://github.com/Al1ex/CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2017-10271.svg)

- [https://github.com/cved-sources/cve-2017-10271](https://github.com/cved-sources/cve-2017-10271) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2017-10271.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2017-10271.svg)

- [https://github.com/rambleZzz/weblogic_CVE_2017_10271](https://github.com/rambleZzz/weblogic_CVE_2017_10271) :  ![starts](https://img.shields.io/github/stars/rambleZzz/weblogic_CVE_2017_10271.svg) ![forks](https://img.shields.io/github/forks/rambleZzz/weblogic_CVE_2017_10271.svg)

## CVE-2017-10235
 Vulnerability in the Oracle VM VirtualBox component of Oracle Virtualization (subcomponent: Core). The supported version that is affected is Prior to 5.1.24. Easily exploitable vulnerability allows high privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle VM VirtualBox as well as unauthorized update, insert or delete access to some of Oracle VM VirtualBox accessible data. CVSS 3.0 Base Score 6.7 (Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:L/A:H).



- [https://github.com/fundacion-sadosky/vbox_cve_2017_10235](https://github.com/fundacion-sadosky/vbox_cve_2017_10235) :  ![starts](https://img.shields.io/github/stars/fundacion-sadosky/vbox_cve_2017_10235.svg) ![forks](https://img.shields.io/github/forks/fundacion-sadosky/vbox_cve_2017_10235.svg)

## CVE-2017-10148
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.1 and 12.2.1.2. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. While the vulnerability is in Oracle WebLogic Server, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle WebLogic Server accessible data. CVSS 3.0 Base Score 5.8 (Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N). NOTE: the previous information is from the July 2017 CPU. Oracle has not commented on third-party claims that this issue allows remote attackers to inject special data into log files via a crafted T3 request.



- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)

## CVE-2017-10147
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.1 and 12.2.1.2. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. While the vulnerability is in Oracle WebLogic Server, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle WebLogic Server. CVSS 3.0 Base Score 8.6 (Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H). NOTE: the previous information is from the July 2017 CPU. Oracle has not commented on third-party claims that this issue exists in the migrate functionality in the WebLogic/cluster/singleton/ServerMigrationCoordinator class and allows remote attackers to shutdown the server via a crafted T3 request.



- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)

## CVE-2017-9999
 ** RE



- [https://github.com/homjxi0e/CVE-2017-9999_bypassing_General_Firefox](https://github.com/homjxi0e/CVE-2017-9999_bypassing_General_Firefox) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-9999_bypassing_General_Firefox.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-9999_bypassing_General_Firefox.svg)

## CVE-2017-9934
 Missing CSRF token checks and improper input validation in Joomla! CMS 1.7.3 through 3.7.2 lead to an XSS vulnerability.



- [https://github.com/xyringe/CVE-2017-9934](https://github.com/xyringe/CVE-2017-9934) :  ![starts](https://img.shields.io/github/stars/xyringe/CVE-2017-9934.svg) ![forks](https://img.shields.io/github/forks/xyringe/CVE-2017-9934.svg)

## CVE-2017-9841
 Util/PHP/eval-stdin.php in PHPUnit before 4.8.28 and 5.x before 5.6.3 allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a &quot;&lt;?php &quot; substring, as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.



- [https://github.com/RandomRobbieBF/phpunit-brute](https://github.com/RandomRobbieBF/phpunit-brute) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/phpunit-brute.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/phpunit-brute.svg)

- [https://github.com/incogbyte/laravel-phpunit-rce-masscaner](https://github.com/incogbyte/laravel-phpunit-rce-masscaner) :  ![starts](https://img.shields.io/github/stars/incogbyte/laravel-phpunit-rce-masscaner.svg) ![forks](https://img.shields.io/github/forks/incogbyte/laravel-phpunit-rce-masscaner.svg)

- [https://github.com/ludy-dev/PHPUnit_eval-stdin_RCE](https://github.com/ludy-dev/PHPUnit_eval-stdin_RCE) :  ![starts](https://img.shields.io/github/stars/ludy-dev/PHPUnit_eval-stdin_RCE.svg) ![forks](https://img.shields.io/github/forks/ludy-dev/PHPUnit_eval-stdin_RCE.svg)

- [https://github.com/mbrasile/CVE-2017-9841](https://github.com/mbrasile/CVE-2017-9841) :  ![starts](https://img.shields.io/github/stars/mbrasile/CVE-2017-9841.svg) ![forks](https://img.shields.io/github/forks/mbrasile/CVE-2017-9841.svg)

- [https://github.com/cyberharsh/Php-unit-CVE-2017-9841](https://github.com/cyberharsh/Php-unit-CVE-2017-9841) :  ![starts](https://img.shields.io/github/stars/cyberharsh/Php-unit-CVE-2017-9841.svg) ![forks](https://img.shields.io/github/forks/cyberharsh/Php-unit-CVE-2017-9841.svg)

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

- [https://github.com/hahwul/struts2-rce-cve-2017-9805-ruby](https://github.com/hahwul/struts2-rce-cve-2017-9805-ruby) :  ![starts](https://img.shields.io/github/stars/hahwul/struts2-rce-cve-2017-9805-ruby.svg) ![forks](https://img.shields.io/github/forks/hahwul/struts2-rce-cve-2017-9805-ruby.svg)

- [https://github.com/Lone-Ranger/apache-struts-pwn_CVE-2017-9805](https://github.com/Lone-Ranger/apache-struts-pwn_CVE-2017-9805) :  ![starts](https://img.shields.io/github/stars/Lone-Ranger/apache-struts-pwn_CVE-2017-9805.svg) ![forks](https://img.shields.io/github/forks/Lone-Ranger/apache-struts-pwn_CVE-2017-9805.svg)

- [https://github.com/0xd3vil/CVE-2017-9805-Exploit](https://github.com/0xd3vil/CVE-2017-9805-Exploit) :  ![starts](https://img.shields.io/github/stars/0xd3vil/CVE-2017-9805-Exploit.svg) ![forks](https://img.shields.io/github/forks/0xd3vil/CVE-2017-9805-Exploit.svg)

- [https://github.com/BeyondCy/S2-052](https://github.com/BeyondCy/S2-052) :  ![starts](https://img.shields.io/github/stars/BeyondCy/S2-052.svg) ![forks](https://img.shields.io/github/forks/BeyondCy/S2-052.svg)

- [https://github.com/UbuntuStrike/struts_rest_rce_fuzz-CVE-2017-9805-](https://github.com/UbuntuStrike/struts_rest_rce_fuzz-CVE-2017-9805-) :  ![starts](https://img.shields.io/github/stars/UbuntuStrike/struts_rest_rce_fuzz-CVE-2017-9805-.svg) ![forks](https://img.shields.io/github/forks/UbuntuStrike/struts_rest_rce_fuzz-CVE-2017-9805-.svg)

- [https://github.com/z3bd/CVE-2017-9805](https://github.com/z3bd/CVE-2017-9805) :  ![starts](https://img.shields.io/github/stars/z3bd/CVE-2017-9805.svg) ![forks](https://img.shields.io/github/forks/z3bd/CVE-2017-9805.svg)

- [https://github.com/jongmartinez/-CVE-2017-9805-](https://github.com/jongmartinez/-CVE-2017-9805-) :  ![starts](https://img.shields.io/github/stars/jongmartinez/-CVE-2017-9805-.svg) ![forks](https://img.shields.io/github/forks/jongmartinez/-CVE-2017-9805-.svg)

- [https://github.com/wifido/CVE-2017-9805-Exploit](https://github.com/wifido/CVE-2017-9805-Exploit) :  ![starts](https://img.shields.io/github/stars/wifido/CVE-2017-9805-Exploit.svg) ![forks](https://img.shields.io/github/forks/wifido/CVE-2017-9805-Exploit.svg)

- [https://github.com/sujithvaddi/apache_struts_cve_2017_9805](https://github.com/sujithvaddi/apache_struts_cve_2017_9805) :  ![starts](https://img.shields.io/github/stars/sujithvaddi/apache_struts_cve_2017_9805.svg) ![forks](https://img.shields.io/github/forks/sujithvaddi/apache_struts_cve_2017_9805.svg)

- [https://github.com/rvermeulen/apache-struts-cve-2017-9805](https://github.com/rvermeulen/apache-struts-cve-2017-9805) :  ![starts](https://img.shields.io/github/stars/rvermeulen/apache-struts-cve-2017-9805.svg) ![forks](https://img.shields.io/github/forks/rvermeulen/apache-struts-cve-2017-9805.svg)

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

- [https://github.com/shacojx/dp](https://github.com/shacojx/dp) :  ![starts](https://img.shields.io/github/stars/shacojx/dp.svg) ![forks](https://img.shields.io/github/forks/shacojx/dp.svg)

- [https://github.com/ictnamanh/CVE-2017-9248](https://github.com/ictnamanh/CVE-2017-9248) :  ![starts](https://img.shields.io/github/stars/ictnamanh/CVE-2017-9248.svg) ![forks](https://img.shields.io/github/forks/ictnamanh/CVE-2017-9248.svg)

- [https://github.com/ZhenwarX/Telerik-CVE-2017-9248-PoC](https://github.com/ZhenwarX/Telerik-CVE-2017-9248-PoC) :  ![starts](https://img.shields.io/github/stars/ZhenwarX/Telerik-CVE-2017-9248-PoC.svg) ![forks](https://img.shields.io/github/forks/ZhenwarX/Telerik-CVE-2017-9248-PoC.svg)

## CVE-2017-9101
 import.php (aka the Phonebook import feature) in PlaySMS 1.4 allows remote code execution via vectors involving the User-Agent HTTP header and PHP code in the name of a file.



- [https://github.com/jasperla/CVE-2017-9101](https://github.com/jasperla/CVE-2017-9101) :  ![starts](https://img.shields.io/github/stars/jasperla/CVE-2017-9101.svg) ![forks](https://img.shields.io/github/forks/jasperla/CVE-2017-9101.svg)

## CVE-2017-9097
 In Anti-Web through 3.8.7, as used on NetBiter FGW200 devices through 3.21.2, WS100 devices through 3.30.5, EC150 devices through 1.40.0, WS200 devices through 3.30.4, EC250 devices through 1.40.0, and other products, an LFI vulnerability allows a remote attacker to read or modify files through a path traversal technique, as demonstrated by reading the password file, or using the template parameter to cgi-bin/write.cgi to write to an arbitrary file.



- [https://github.com/MDudek-ICS/AntiWeb_testing-Suite](https://github.com/MDudek-ICS/AntiWeb_testing-Suite) :  ![starts](https://img.shields.io/github/stars/MDudek-ICS/AntiWeb_testing-Suite.svg) ![forks](https://img.shields.io/github/forks/MDudek-ICS/AntiWeb_testing-Suite.svg)

## CVE-2017-8917
 SQL injection vulnerability in Joomla! 3.7.x before 3.7.1 allows attackers to execute arbitrary SQL commands via unspecified vectors.



- [https://github.com/stefanlucas/Exploit-Joomla](https://github.com/stefanlucas/Exploit-Joomla) :  ![starts](https://img.shields.io/github/stars/stefanlucas/Exploit-Joomla.svg) ![forks](https://img.shields.io/github/forks/stefanlucas/Exploit-Joomla.svg)

- [https://github.com/brianwrf/Joomla3.7-SQLi-CVE-2017-8917](https://github.com/brianwrf/Joomla3.7-SQLi-CVE-2017-8917) :  ![starts](https://img.shields.io/github/stars/brianwrf/Joomla3.7-SQLi-CVE-2017-8917.svg) ![forks](https://img.shields.io/github/forks/brianwrf/Joomla3.7-SQLi-CVE-2017-8917.svg)

- [https://github.com/cved-sources/cve-2017-8917](https://github.com/cved-sources/cve-2017-8917) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2017-8917.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2017-8917.svg)

- [https://github.com/SiopySh/CVE-2017-8917](https://github.com/SiopySh/CVE-2017-8917) :  ![starts](https://img.shields.io/github/stars/SiopySh/CVE-2017-8917.svg) ![forks](https://img.shields.io/github/forks/SiopySh/CVE-2017-8917.svg)

## CVE-2017-8890
 The inet_csk_clone_lock function in net/ipv4/inet_connection_sock.c in the Linux kernel through 4.10.15 allows attackers to cause a denial of service (double free) or possibly have unspecified other impact by leveraging use of the accept system call.



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

- [https://github.com/Lz1y/CVE-2017-8759](https://github.com/Lz1y/CVE-2017-8759) :  ![starts](https://img.shields.io/github/stars/Lz1y/CVE-2017-8759.svg) ![forks](https://img.shields.io/github/forks/Lz1y/CVE-2017-8759.svg)

- [https://github.com/JonasUliana/CVE-2017-8759](https://github.com/JonasUliana/CVE-2017-8759) :  ![starts](https://img.shields.io/github/stars/JonasUliana/CVE-2017-8759.svg) ![forks](https://img.shields.io/github/forks/JonasUliana/CVE-2017-8759.svg)

- [https://github.com/jacobsoo/RTF-Cleaner](https://github.com/jacobsoo/RTF-Cleaner) :  ![starts](https://img.shields.io/github/stars/jacobsoo/RTF-Cleaner.svg) ![forks](https://img.shields.io/github/forks/jacobsoo/RTF-Cleaner.svg)

- [https://github.com/ashr/CVE-2017-8759-exploits](https://github.com/ashr/CVE-2017-8759-exploits) :  ![starts](https://img.shields.io/github/stars/ashr/CVE-2017-8759-exploits.svg) ![forks](https://img.shields.io/github/forks/ashr/CVE-2017-8759-exploits.svg)

- [https://github.com/homjxi0e/CVE-2017-8759_-SOAP_WSDL](https://github.com/homjxi0e/CVE-2017-8759_-SOAP_WSDL) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-8759_-SOAP_WSDL.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-8759_-SOAP_WSDL.svg)

- [https://github.com/BasuCert/CVE-2017-8759](https://github.com/BasuCert/CVE-2017-8759) :  ![starts](https://img.shields.io/github/stars/BasuCert/CVE-2017-8759.svg) ![forks](https://img.shields.io/github/forks/BasuCert/CVE-2017-8759.svg)

- [https://github.com/ChaitanyaHaritash/CVE-2017-8759](https://github.com/ChaitanyaHaritash/CVE-2017-8759) :  ![starts](https://img.shields.io/github/stars/ChaitanyaHaritash/CVE-2017-8759.svg) ![forks](https://img.shields.io/github/forks/ChaitanyaHaritash/CVE-2017-8759.svg)

- [https://github.com/zhengkook/CVE-2017-8759](https://github.com/zhengkook/CVE-2017-8759) :  ![starts](https://img.shields.io/github/stars/zhengkook/CVE-2017-8759.svg) ![forks](https://img.shields.io/github/forks/zhengkook/CVE-2017-8759.svg)

- [https://github.com/l0n3rs/CVE-2017-8759](https://github.com/l0n3rs/CVE-2017-8759) :  ![starts](https://img.shields.io/github/stars/l0n3rs/CVE-2017-8759.svg) ![forks](https://img.shields.io/github/forks/l0n3rs/CVE-2017-8759.svg)

- [https://github.com/smashinu/CVE-2017-8759Expoit](https://github.com/smashinu/CVE-2017-8759Expoit) :  ![starts](https://img.shields.io/github/stars/smashinu/CVE-2017-8759Expoit.svg) ![forks](https://img.shields.io/github/forks/smashinu/CVE-2017-8759Expoit.svg)

- [https://github.com/adeljck/CVE-2017-8759](https://github.com/adeljck/CVE-2017-8759) :  ![starts](https://img.shields.io/github/stars/adeljck/CVE-2017-8759.svg) ![forks](https://img.shields.io/github/forks/adeljck/CVE-2017-8759.svg)

- [https://github.com/Winter3un/cve_2017_8759](https://github.com/Winter3un/cve_2017_8759) :  ![starts](https://img.shields.io/github/stars/Winter3un/cve_2017_8759.svg) ![forks](https://img.shields.io/github/forks/Winter3un/cve_2017_8759.svg)

- [https://github.com/tahisaad6/CVE-2017-8759-Exploit-sample2](https://github.com/tahisaad6/CVE-2017-8759-Exploit-sample2) :  ![starts](https://img.shields.io/github/stars/tahisaad6/CVE-2017-8759-Exploit-sample2.svg) ![forks](https://img.shields.io/github/forks/tahisaad6/CVE-2017-8759-Exploit-sample2.svg)

- [https://github.com/GayashanM/OHTS](https://github.com/GayashanM/OHTS) :  ![starts](https://img.shields.io/github/stars/GayashanM/OHTS.svg) ![forks](https://img.shields.io/github/forks/GayashanM/OHTS.svg)

- [https://github.com/varunsaru/SNP](https://github.com/varunsaru/SNP) :  ![starts](https://img.shields.io/github/stars/varunsaru/SNP.svg) ![forks](https://img.shields.io/github/forks/varunsaru/SNP.svg)

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

- [https://github.com/dcsync/rtfkit](https://github.com/dcsync/rtfkit) :  ![starts](https://img.shields.io/github/stars/dcsync/rtfkit.svg) ![forks](https://img.shields.io/github/forks/dcsync/rtfkit.svg)

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

- [https://github.com/Lynggaard91/windows2016fixCVE-2017-8529](https://github.com/Lynggaard91/windows2016fixCVE-2017-8529) :  ![starts](https://img.shields.io/github/stars/Lynggaard91/windows2016fixCVE-2017-8529.svg) ![forks](https://img.shields.io/github/forks/Lynggaard91/windows2016fixCVE-2017-8529.svg)

## CVE-2017-8486
 Microsoft Windows 7 SP1, Windows Server 2008 SP2 and R2 SP1, Windows 8.1 and Windows RT 8.1, Windows Server 2012 and R2, Windows 10 Gold, 1511, 1607, 1703, and Windows Server 2016 allows an information disclosure due to the way it handles objects in memory, aka &quot;Win32k Information Disclosure Vulnerability&quot;.



- [https://github.com/Securitykid/CVE-2017-8464-exp-generator](https://github.com/Securitykid/CVE-2017-8464-exp-generator) :  ![starts](https://img.shields.io/github/stars/Securitykid/CVE-2017-8464-exp-generator.svg) ![forks](https://img.shields.io/github/forks/Securitykid/CVE-2017-8464-exp-generator.svg)

## CVE-2017-8465
 Microsoft Windows 8.1 and Windows RT 8.1, Windows Server 2012 R2, Windows 10 Gold, 1511, 1607, and 1703, and Windows Server 2016 allow an attacker to run processes in an elevated context when the Windows kernel improperly handles objects in memory, aka &quot;Win32k Elevation of Privilege Vulnerability.&quot; This CVE ID is unique from CVE-2017-8468.



- [https://github.com/nghiadt1098/CVE-2017-8465](https://github.com/nghiadt1098/CVE-2017-8465) :  ![starts](https://img.shields.io/github/stars/nghiadt1098/CVE-2017-8465.svg) ![forks](https://img.shields.io/github/forks/nghiadt1098/CVE-2017-8465.svg)

## CVE-2017-8464
 Windows Shell in Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, 1703, and Windows Server 2016 allows local users or remote attackers to execute arbitrary code via a crafted .LNK file, which is not properly handled during icon display in Windows Explorer or any other application that parses the icon of the shortcut. aka &quot;LNK Remote Code Execution Vulnerability.&quot;



- [https://github.com/3gstudent/CVE-2017-8464-EXP](https://github.com/3gstudent/CVE-2017-8464-EXP) :  ![starts](https://img.shields.io/github/stars/3gstudent/CVE-2017-8464-EXP.svg) ![forks](https://img.shields.io/github/forks/3gstudent/CVE-2017-8464-EXP.svg)

- [https://github.com/Securitykid/CVE-2017-8464-exp-generator](https://github.com/Securitykid/CVE-2017-8464-exp-generator) :  ![starts](https://img.shields.io/github/stars/Securitykid/CVE-2017-8464-exp-generator.svg) ![forks](https://img.shields.io/github/forks/Securitykid/CVE-2017-8464-exp-generator.svg)

- [https://github.com/Elm0D/CVE-2017-8464](https://github.com/Elm0D/CVE-2017-8464) :  ![starts](https://img.shields.io/github/stars/Elm0D/CVE-2017-8464.svg) ![forks](https://img.shields.io/github/forks/Elm0D/CVE-2017-8464.svg)

- [https://github.com/xssfile/CVE-2017-8464-EXP](https://github.com/xssfile/CVE-2017-8464-EXP) :  ![starts](https://img.shields.io/github/stars/xssfile/CVE-2017-8464-EXP.svg) ![forks](https://img.shields.io/github/forks/xssfile/CVE-2017-8464-EXP.svg)

- [https://github.com/X-Vector/usbhijacking](https://github.com/X-Vector/usbhijacking) :  ![starts](https://img.shields.io/github/stars/X-Vector/usbhijacking.svg) ![forks](https://img.shields.io/github/forks/X-Vector/usbhijacking.svg)

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

## CVE-2017-8046
 Malicious PATCH requests submitted to servers using Spring Data REST versions prior to 2.6.9 (Ingalls SR9), versions prior to 3.0.1 (Kay SR1) and Spring Boot versions prior to 1.5.9, 2.0 M6 can use specially crafted JSON data to run arbitrary Java code.



- [https://github.com/m3ssap0/spring-break_cve-2017-8046](https://github.com/m3ssap0/spring-break_cve-2017-8046) :  ![starts](https://img.shields.io/github/stars/m3ssap0/spring-break_cve-2017-8046.svg) ![forks](https://img.shields.io/github/forks/m3ssap0/spring-break_cve-2017-8046.svg)

- [https://github.com/m3ssap0/SpringBreakVulnerableApp](https://github.com/m3ssap0/SpringBreakVulnerableApp) :  ![starts](https://img.shields.io/github/stars/m3ssap0/SpringBreakVulnerableApp.svg) ![forks](https://img.shields.io/github/forks/m3ssap0/SpringBreakVulnerableApp.svg)

- [https://github.com/cved-sources/cve-2017-8046](https://github.com/cved-sources/cve-2017-8046) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2017-8046.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2017-8046.svg)

- [https://github.com/Soontao/CVE-2017-8046-DEMO](https://github.com/Soontao/CVE-2017-8046-DEMO) :  ![starts](https://img.shields.io/github/stars/Soontao/CVE-2017-8046-DEMO.svg) ![forks](https://img.shields.io/github/forks/Soontao/CVE-2017-8046-DEMO.svg)

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



- [https://github.com/JrDw0/CVE-2017-7921-EXP](https://github.com/JrDw0/CVE-2017-7921-EXP) :  ![starts](https://img.shields.io/github/stars/JrDw0/CVE-2017-7921-EXP.svg) ![forks](https://img.shields.io/github/forks/JrDw0/CVE-2017-7921-EXP.svg)

- [https://github.com/BurnyMcDull/CVE-2017-7921](https://github.com/BurnyMcDull/CVE-2017-7921) :  ![starts](https://img.shields.io/github/stars/BurnyMcDull/CVE-2017-7921.svg) ![forks](https://img.shields.io/github/forks/BurnyMcDull/CVE-2017-7921.svg)

- [https://github.com/chrisjd20/hikvision_CVE-2017-7921_auth_bypass_config_decryptor](https://github.com/chrisjd20/hikvision_CVE-2017-7921_auth_bypass_config_decryptor) :  ![starts](https://img.shields.io/github/stars/chrisjd20/hikvision_CVE-2017-7921_auth_bypass_config_decryptor.svg) ![forks](https://img.shields.io/github/forks/chrisjd20/hikvision_CVE-2017-7921_auth_bypass_config_decryptor.svg)

- [https://github.com/MisakaMikato/cve-2017-7921-golang](https://github.com/MisakaMikato/cve-2017-7921-golang) :  ![starts](https://img.shields.io/github/stars/MisakaMikato/cve-2017-7921-golang.svg) ![forks](https://img.shields.io/github/forks/MisakaMikato/cve-2017-7921-golang.svg)

- [https://github.com/A403/CVE_2017_7921_EXP](https://github.com/A403/CVE_2017_7921_EXP) :  ![starts](https://img.shields.io/github/stars/A403/CVE_2017_7921_EXP.svg) ![forks](https://img.shields.io/github/forks/A403/CVE_2017_7921_EXP.svg)

## CVE-2017-7912
 Hanwha Techwin SRN-4000, SRN-4000 firmware versions prior to SRN4000_v2.16_170401, A specially crafted http request and response could allow an attacker to gain access to the device management page with admin privileges without proper authentication.



- [https://github.com/homjxi0e/CVE-2017-7912_Sneak](https://github.com/homjxi0e/CVE-2017-7912_Sneak) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-7912_Sneak.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-7912_Sneak.svg)

## CVE-2017-7679
 In Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26, mod_mime can read one byte past the end of a buffer when sending a malicious Content-Type response header.



- [https://github.com/snknritr/CVE-2017-7679-in-python](https://github.com/snknritr/CVE-2017-7679-in-python) :  ![starts](https://img.shields.io/github/stars/snknritr/CVE-2017-7679-in-python.svg) ![forks](https://img.shields.io/github/forks/snknritr/CVE-2017-7679-in-python.svg)

## CVE-2017-7651
 In Eclipse Mosquitto 1.4.14, a user can shutdown the Mosquitto server simply by filling the RAM memory with a lot of connections with large payload. This can be done without authentications if occur in connection phase of MQTT protocol.



- [https://github.com/mukkul007/MqttAttack](https://github.com/mukkul007/MqttAttack) :  ![starts](https://img.shields.io/github/stars/mukkul007/MqttAttack.svg) ![forks](https://img.shields.io/github/forks/mukkul007/MqttAttack.svg)

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

- [https://github.com/MaxSecurity/CVE-2017-7529-POC](https://github.com/MaxSecurity/CVE-2017-7529-POC) :  ![starts](https://img.shields.io/github/stars/MaxSecurity/CVE-2017-7529-POC.svg) ![forks](https://img.shields.io/github/forks/MaxSecurity/CVE-2017-7529-POC.svg)

- [https://github.com/ninjabuster/exploit-nginx-1.10.3](https://github.com/ninjabuster/exploit-nginx-1.10.3) :  ![starts](https://img.shields.io/github/stars/ninjabuster/exploit-nginx-1.10.3.svg) ![forks](https://img.shields.io/github/forks/ninjabuster/exploit-nginx-1.10.3.svg)

- [https://github.com/cyberharsh/nginx-CVE-2017-7529](https://github.com/cyberharsh/nginx-CVE-2017-7529) :  ![starts](https://img.shields.io/github/stars/cyberharsh/nginx-CVE-2017-7529.svg) ![forks](https://img.shields.io/github/forks/cyberharsh/nginx-CVE-2017-7529.svg)

- [https://github.com/cved-sources/cve-2017-7529](https://github.com/cved-sources/cve-2017-7529) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2017-7529.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2017-7529.svg)

- [https://github.com/Moazj8/Nginx-Remote-Integer-Overflow-Vulnerability](https://github.com/Moazj8/Nginx-Remote-Integer-Overflow-Vulnerability) :  ![starts](https://img.shields.io/github/stars/Moazj8/Nginx-Remote-Integer-Overflow-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/Moazj8/Nginx-Remote-Integer-Overflow-Vulnerability.svg)

- [https://github.com/cyberk1w1/CVE-2017-7529](https://github.com/cyberk1w1/CVE-2017-7529) :  ![starts](https://img.shields.io/github/stars/cyberk1w1/CVE-2017-7529.svg) ![forks](https://img.shields.io/github/forks/cyberk1w1/CVE-2017-7529.svg)

- [https://github.com/daehee/nginx-overflow](https://github.com/daehee/nginx-overflow) :  ![starts](https://img.shields.io/github/stars/daehee/nginx-overflow.svg) ![forks](https://img.shields.io/github/forks/daehee/nginx-overflow.svg)

- [https://github.com/fu2x2000/CVE-2017-7529-Nginx---Remote-Integer-Overflow-Exploit](https://github.com/fu2x2000/CVE-2017-7529-Nginx---Remote-Integer-Overflow-Exploit) :  ![starts](https://img.shields.io/github/stars/fu2x2000/CVE-2017-7529-Nginx---Remote-Integer-Overflow-Exploit.svg) ![forks](https://img.shields.io/github/forks/fu2x2000/CVE-2017-7529-Nginx---Remote-Integer-Overflow-Exploit.svg)

- [https://github.com/fardeen-ahmed/Remote-Integer-Overflow-Vulnerability](https://github.com/fardeen-ahmed/Remote-Integer-Overflow-Vulnerability) :  ![starts](https://img.shields.io/github/stars/fardeen-ahmed/Remote-Integer-Overflow-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/fardeen-ahmed/Remote-Integer-Overflow-Vulnerability.svg)

- [https://github.com/devansh3008/Cve_Finder_2017-7529](https://github.com/devansh3008/Cve_Finder_2017-7529) :  ![starts](https://img.shields.io/github/stars/devansh3008/Cve_Finder_2017-7529.svg) ![forks](https://img.shields.io/github/forks/devansh3008/Cve_Finder_2017-7529.svg)

## CVE-2017-7525
 A deserialization flaw was discovered in the jackson-databind, versions before 2.6.7.1, 2.7.9.1 and 2.8.9, which could allow an unauthenticated user to perform code execution by sending the maliciously crafted input to the readValue method of the ObjectMapper.



- [https://github.com/SecureSkyTechnology/study-struts2-s2-054_055-jackson-cve-2017-7525_cve-2017-15095](https://github.com/SecureSkyTechnology/study-struts2-s2-054_055-jackson-cve-2017-7525_cve-2017-15095) :  ![starts](https://img.shields.io/github/stars/SecureSkyTechnology/study-struts2-s2-054_055-jackson-cve-2017-7525_cve-2017-15095.svg) ![forks](https://img.shields.io/github/forks/SecureSkyTechnology/study-struts2-s2-054_055-jackson-cve-2017-7525_cve-2017-15095.svg)

- [https://github.com/JavanXD/Demo-Exploit-Jackson-RCE](https://github.com/JavanXD/Demo-Exploit-Jackson-RCE) :  ![starts](https://img.shields.io/github/stars/JavanXD/Demo-Exploit-Jackson-RCE.svg) ![forks](https://img.shields.io/github/forks/JavanXD/Demo-Exploit-Jackson-RCE.svg)

- [https://github.com/Nazicc/S2-055](https://github.com/Nazicc/S2-055) :  ![starts](https://img.shields.io/github/stars/Nazicc/S2-055.svg) ![forks](https://img.shields.io/github/forks/Nazicc/S2-055.svg)

- [https://github.com/Ingenuity-Fainting-Goats/CVE-2017-7525-Jackson-Deserialization-Lab](https://github.com/Ingenuity-Fainting-Goats/CVE-2017-7525-Jackson-Deserialization-Lab) :  ![starts](https://img.shields.io/github/stars/Ingenuity-Fainting-Goats/CVE-2017-7525-Jackson-Deserialization-Lab.svg) ![forks](https://img.shields.io/github/forks/Ingenuity-Fainting-Goats/CVE-2017-7525-Jackson-Deserialization-Lab.svg)

- [https://github.com/BassinD/jackson-RCE](https://github.com/BassinD/jackson-RCE) :  ![starts](https://img.shields.io/github/stars/BassinD/jackson-RCE.svg) ![forks](https://img.shields.io/github/forks/BassinD/jackson-RCE.svg)

- [https://github.com/Dannners/jackson-deserialization-2017-7525](https://github.com/Dannners/jackson-deserialization-2017-7525) :  ![starts](https://img.shields.io/github/stars/Dannners/jackson-deserialization-2017-7525.svg) ![forks](https://img.shields.io/github/forks/Dannners/jackson-deserialization-2017-7525.svg)

## CVE-2017-7494
 Samba since version 3.5.0 and before 4.6.4, 4.5.10 and 4.4.14 is vulnerable to remote code execution vulnerability, allowing a malicious client to upload a shared library to a writable share, and then cause the server to load and execute it.



- [https://github.com/opsxcq/exploit-CVE-2017-7494](https://github.com/opsxcq/exploit-CVE-2017-7494) :  ![starts](https://img.shields.io/github/stars/opsxcq/exploit-CVE-2017-7494.svg) ![forks](https://img.shields.io/github/forks/opsxcq/exploit-CVE-2017-7494.svg)

- [https://github.com/joxeankoret/CVE-2017-7494](https://github.com/joxeankoret/CVE-2017-7494) :  ![starts](https://img.shields.io/github/stars/joxeankoret/CVE-2017-7494.svg) ![forks](https://img.shields.io/github/forks/joxeankoret/CVE-2017-7494.svg)

- [https://github.com/betab0t/cve-2017-7494](https://github.com/betab0t/cve-2017-7494) :  ![starts](https://img.shields.io/github/stars/betab0t/cve-2017-7494.svg) ![forks](https://img.shields.io/github/forks/betab0t/cve-2017-7494.svg)

- [https://github.com/Waffles-2/SambaCry](https://github.com/Waffles-2/SambaCry) :  ![starts](https://img.shields.io/github/stars/Waffles-2/SambaCry.svg) ![forks](https://img.shields.io/github/forks/Waffles-2/SambaCry.svg)

- [https://github.com/brianwrf/SambaHunter](https://github.com/brianwrf/SambaHunter) :  ![starts](https://img.shields.io/github/stars/brianwrf/SambaHunter.svg) ![forks](https://img.shields.io/github/forks/brianwrf/SambaHunter.svg)

- [https://github.com/I-Rinka/BIT-EternalBlue-for-macOS_Linux](https://github.com/I-Rinka/BIT-EternalBlue-for-macOS_Linux) :  ![starts](https://img.shields.io/github/stars/I-Rinka/BIT-EternalBlue-for-macOS_Linux.svg) ![forks](https://img.shields.io/github/forks/I-Rinka/BIT-EternalBlue-for-macOS_Linux.svg)

- [https://github.com/Zer0d0y/Samba-CVE-2017-7494](https://github.com/Zer0d0y/Samba-CVE-2017-7494) :  ![starts](https://img.shields.io/github/stars/Zer0d0y/Samba-CVE-2017-7494.svg) ![forks](https://img.shields.io/github/forks/Zer0d0y/Samba-CVE-2017-7494.svg)

- [https://github.com/homjxi0e/CVE-2017-7494](https://github.com/homjxi0e/CVE-2017-7494) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-7494.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-7494.svg)

- [https://github.com/gunsan92/CVE2017-7494_quicktest](https://github.com/gunsan92/CVE2017-7494_quicktest) :  ![starts](https://img.shields.io/github/stars/gunsan92/CVE2017-7494_quicktest.svg) ![forks](https://img.shields.io/github/forks/gunsan92/CVE2017-7494_quicktest.svg)

- [https://github.com/cved-sources/cve-2017-7494](https://github.com/cved-sources/cve-2017-7494) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2017-7494.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2017-7494.svg)

- [https://github.com/incredible1yu/CVE-2017-7494](https://github.com/incredible1yu/CVE-2017-7494) :  ![starts](https://img.shields.io/github/stars/incredible1yu/CVE-2017-7494.svg) ![forks](https://img.shields.io/github/forks/incredible1yu/CVE-2017-7494.svg)

- [https://github.com/m4udSec/noSAMBAnoCRY-CVE-2017-7494](https://github.com/m4udSec/noSAMBAnoCRY-CVE-2017-7494) :  ![starts](https://img.shields.io/github/stars/m4udSec/noSAMBAnoCRY-CVE-2017-7494.svg) ![forks](https://img.shields.io/github/forks/m4udSec/noSAMBAnoCRY-CVE-2017-7494.svg)

- [https://github.com/yinyinmeimei/CVE-2017-7494-payload](https://github.com/yinyinmeimei/CVE-2017-7494-payload) :  ![starts](https://img.shields.io/github/stars/yinyinmeimei/CVE-2017-7494-payload.svg) ![forks](https://img.shields.io/github/forks/yinyinmeimei/CVE-2017-7494-payload.svg)

- [https://github.com/john-80/cve-2017-7494](https://github.com/john-80/cve-2017-7494) :  ![starts](https://img.shields.io/github/stars/john-80/cve-2017-7494.svg) ![forks](https://img.shields.io/github/forks/john-80/cve-2017-7494.svg)

- [https://github.com/Hansindu-M/CVE-2017-7494_IT19115344](https://github.com/Hansindu-M/CVE-2017-7494_IT19115344) :  ![starts](https://img.shields.io/github/stars/Hansindu-M/CVE-2017-7494_IT19115344.svg) ![forks](https://img.shields.io/github/forks/Hansindu-M/CVE-2017-7494_IT19115344.svg)

- [https://github.com/adjaliya/-CVE-2017-7494-Samba-Exploit-POC](https://github.com/adjaliya/-CVE-2017-7494-Samba-Exploit-POC) :  ![starts](https://img.shields.io/github/stars/adjaliya/-CVE-2017-7494-Samba-Exploit-POC.svg) ![forks](https://img.shields.io/github/forks/adjaliya/-CVE-2017-7494-Samba-Exploit-POC.svg)

## CVE-2017-7472
 The KEYS subsystem in the Linux kernel before 4.10.13 allows local users to cause a denial of service (memory consumption) via a series of KEY_REQKEY_DEFL_THREAD_KEYRING keyctl_set_reqkey_keyring calls.



- [https://github.com/homjxi0e/CVE-2017-7472](https://github.com/homjxi0e/CVE-2017-7472) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-7472.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-7472.svg)

## CVE-2017-7376
 Buffer overflow in libxml2 allows remote attackers to execute arbitrary code by leveraging an incorrect limit for port values when handling redirects.



- [https://github.com/brahmstaedt/libxml2-exploit](https://github.com/brahmstaedt/libxml2-exploit) :  ![starts](https://img.shields.io/github/stars/brahmstaedt/libxml2-exploit.svg) ![forks](https://img.shields.io/github/forks/brahmstaedt/libxml2-exploit.svg)

## CVE-2017-7374
 Use-after-free vulnerability in fs/crypto/ in the Linux kernel before 4.10.7 allows local users to cause a denial of service (NULL pointer dereference) or possibly gain privileges by revoking keyring keys being used for ext4, f2fs, or ubifs encryption, causing cryptographic transform objects to be freed prematurely.



- [https://github.com/ww9210/cve-2017-7374](https://github.com/ww9210/cve-2017-7374) :  ![starts](https://img.shields.io/github/stars/ww9210/cve-2017-7374.svg) ![forks](https://img.shields.io/github/forks/ww9210/cve-2017-7374.svg)

## CVE-2017-7269
 Buffer overflow in the ScStoragePathFromUrl function in the WebDAV service in Internet Information Services (IIS) 6.0 in Microsoft Windows Server 2003 R2 allows remote attackers to execute arbitrary code via a long header beginning with &quot;If: &lt;http://&quot; in a PROPFIND request, as exploited in the wild in July or August 2016.



- [https://github.com/zcgonvh/cve-2017-7269](https://github.com/zcgonvh/cve-2017-7269) :  ![starts](https://img.shields.io/github/stars/zcgonvh/cve-2017-7269.svg) ![forks](https://img.shields.io/github/forks/zcgonvh/cve-2017-7269.svg)

- [https://github.com/lcatro/CVE-2017-7269-Echo-PoC](https://github.com/lcatro/CVE-2017-7269-Echo-PoC) :  ![starts](https://img.shields.io/github/stars/lcatro/CVE-2017-7269-Echo-PoC.svg) ![forks](https://img.shields.io/github/forks/lcatro/CVE-2017-7269-Echo-PoC.svg)

- [https://github.com/zcgonvh/cve-2017-7269-tool](https://github.com/zcgonvh/cve-2017-7269-tool) :  ![starts](https://img.shields.io/github/stars/zcgonvh/cve-2017-7269-tool.svg) ![forks](https://img.shields.io/github/forks/zcgonvh/cve-2017-7269-tool.svg)

- [https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269](https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/g0rx/iis6-exploit-2017-CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/g0rx/iis6-exploit-2017-CVE-2017-7269.svg)

- [https://github.com/eliuha/webdav_exploit](https://github.com/eliuha/webdav_exploit) :  ![starts](https://img.shields.io/github/stars/eliuha/webdav_exploit.svg) ![forks](https://img.shields.io/github/forks/eliuha/webdav_exploit.svg)

- [https://github.com/Al1ex/CVE-2017-7269](https://github.com/Al1ex/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2017-7269.svg)

- [https://github.com/slimpagey/IIS_6.0_WebDAV_Ruby](https://github.com/slimpagey/IIS_6.0_WebDAV_Ruby) :  ![starts](https://img.shields.io/github/stars/slimpagey/IIS_6.0_WebDAV_Ruby.svg) ![forks](https://img.shields.io/github/forks/slimpagey/IIS_6.0_WebDAV_Ruby.svg)

- [https://github.com/caicai1355/CVE-2017-7269-exploit](https://github.com/caicai1355/CVE-2017-7269-exploit) :  ![starts](https://img.shields.io/github/stars/caicai1355/CVE-2017-7269-exploit.svg) ![forks](https://img.shields.io/github/forks/caicai1355/CVE-2017-7269-exploit.svg)

- [https://github.com/jrrombaldo/CVE-2017-7269](https://github.com/jrrombaldo/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/jrrombaldo/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/jrrombaldo/CVE-2017-7269.svg)

- [https://github.com/xiaovpn/CVE-2017-7269](https://github.com/xiaovpn/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/xiaovpn/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/xiaovpn/CVE-2017-7269.svg)

- [https://github.com/1nf1n17yk1ng/CVE-2017-7269](https://github.com/1nf1n17yk1ng/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/1nf1n17yk1ng/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/1nf1n17yk1ng/CVE-2017-7269.svg)

- [https://github.com/M1a0rz/CVE-2017-7269](https://github.com/M1a0rz/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/M1a0rz/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/M1a0rz/CVE-2017-7269.svg)

- [https://github.com/whiteHat001/cve-2017-7269picture](https://github.com/whiteHat001/cve-2017-7269picture) :  ![starts](https://img.shields.io/github/stars/whiteHat001/cve-2017-7269picture.svg) ![forks](https://img.shields.io/github/forks/whiteHat001/cve-2017-7269picture.svg)

- [https://github.com/mirrorblack/CVE-2017-7269](https://github.com/mirrorblack/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/mirrorblack/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/mirrorblack/CVE-2017-7269.svg)

- [https://github.com/homjxi0e/cve-2017-7269](https://github.com/homjxi0e/cve-2017-7269) :  ![starts](https://img.shields.io/github/stars/homjxi0e/cve-2017-7269.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/cve-2017-7269.svg)

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

## CVE-2017-7061
 An issue was discovered in certain Apple products. iOS before 10.3.3 is affected. Safari before 10.1.2 is affected. iCloud before 6.2.2 on Windows is affected. iTunes before 12.6.2 on Windows is affected. tvOS before 10.2.2 is affected. The issue involves the &quot;WebKit&quot; component. It allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption and application crash) via a crafted web site.



- [https://github.com/TheLoneHaxor/jailbreakme103](https://github.com/TheLoneHaxor/jailbreakme103) :  ![starts](https://img.shields.io/github/stars/TheLoneHaxor/jailbreakme103.svg) ![forks](https://img.shields.io/github/forks/TheLoneHaxor/jailbreakme103.svg)

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

## CVE-2017-6008
 A kernel pool overflow in the driver hitmanpro37.sys in Sophos SurfRight HitmanPro before 3.7.20 Build 286 (included in the HitmanPro.Alert solution and Sophos Clean) allows local users to escalate privileges via a malformed IOCTL call.



- [https://github.com/cbayet/Exploit-CVE-2017-6008](https://github.com/cbayet/Exploit-CVE-2017-6008) :  ![starts](https://img.shields.io/github/stars/cbayet/Exploit-CVE-2017-6008.svg) ![forks](https://img.shields.io/github/forks/cbayet/Exploit-CVE-2017-6008.svg)

## CVE-2017-5954
 An issue was discovered in the serialize-to-js package 0.5.0 for Node.js. Untrusted data passed into the deserialize() function can be exploited to achieve arbitrary code execution by passing a JavaScript Object with an Immediately Invoked Function Expression (IIFE).



- [https://github.com/ossf-cve-benchmark/CVE-2017-5954](https://github.com/ossf-cve-benchmark/CVE-2017-5954) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-5954.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-5954.svg)

## CVE-2017-5941
 An issue was discovered in the node-serialize package 0.0.4 for Node.js. Untrusted data passed into the unserialize() function can be exploited to achieve arbitrary code execution by passing a JavaScript Object with an Immediately Invoked Function Expression (IIFE).



- [https://github.com/p1gz/CVE-2017-5941-NodeJS-RCE](https://github.com/p1gz/CVE-2017-5941-NodeJS-RCE) :  ![starts](https://img.shields.io/github/stars/p1gz/CVE-2017-5941-NodeJS-RCE.svg) ![forks](https://img.shields.io/github/forks/p1gz/CVE-2017-5941-NodeJS-RCE.svg)

## CVE-2017-5816
 A Remote Code Execution vulnerability in HPE Intelligent Management Center (iMC) PLAT version 7.3 E0504P04 was found.



- [https://github.com/oxagast/oxasploits](https://github.com/oxagast/oxasploits) :  ![starts](https://img.shields.io/github/stars/oxagast/oxasploits.svg) ![forks](https://img.shields.io/github/forks/oxagast/oxasploits.svg)

## CVE-2017-5792
 A Remote Code Execution vulnerability in HPE Intelligent Management Center (iMC) PLAT version 7.3 E0504P2 was found.



- [https://github.com/scanfsec/HPE-iMC-7.3-RMI-Java-Deserialization](https://github.com/scanfsec/HPE-iMC-7.3-RMI-Java-Deserialization) :  ![starts](https://img.shields.io/github/stars/scanfsec/HPE-iMC-7.3-RMI-Java-Deserialization.svg) ![forks](https://img.shields.io/github/forks/scanfsec/HPE-iMC-7.3-RMI-Java-Deserialization.svg)

## CVE-2017-5754
 Systems with microprocessors utilizing speculative execution and indirect branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis of the data cache.



- [https://github.com/speed47/spectre-meltdown-checker](https://github.com/speed47/spectre-meltdown-checker) :  ![starts](https://img.shields.io/github/stars/speed47/spectre-meltdown-checker.svg) ![forks](https://img.shields.io/github/forks/speed47/spectre-meltdown-checker.svg)

- [https://github.com/raphaelsc/Am-I-affected-by-Meltdown](https://github.com/raphaelsc/Am-I-affected-by-Meltdown) :  ![starts](https://img.shields.io/github/stars/raphaelsc/Am-I-affected-by-Meltdown.svg) ![forks](https://img.shields.io/github/forks/raphaelsc/Am-I-affected-by-Meltdown.svg)

- [https://github.com/ionescu007/SpecuCheck](https://github.com/ionescu007/SpecuCheck) :  ![starts](https://img.shields.io/github/stars/ionescu007/SpecuCheck.svg) ![forks](https://img.shields.io/github/forks/ionescu007/SpecuCheck.svg)

- [https://github.com/nsacyber/Hardware-and-Firmware-Security-Guidance](https://github.com/nsacyber/Hardware-and-Firmware-Security-Guidance) :  ![starts](https://img.shields.io/github/stars/nsacyber/Hardware-and-Firmware-Security-Guidance.svg) ![forks](https://img.shields.io/github/forks/nsacyber/Hardware-and-Firmware-Security-Guidance.svg)

- [https://github.com/Viralmaniar/In-Spectre-Meltdown](https://github.com/Viralmaniar/In-Spectre-Meltdown) :  ![starts](https://img.shields.io/github/stars/Viralmaniar/In-Spectre-Meltdown.svg) ![forks](https://img.shields.io/github/forks/Viralmaniar/In-Spectre-Meltdown.svg)

- [https://github.com/mathse/meltdown-spectre-bios-list](https://github.com/mathse/meltdown-spectre-bios-list) :  ![starts](https://img.shields.io/github/stars/mathse/meltdown-spectre-bios-list.svg) ![forks](https://img.shields.io/github/forks/mathse/meltdown-spectre-bios-list.svg)

- [https://github.com/neuhalje/presentation_meltdown_spectre](https://github.com/neuhalje/presentation_meltdown_spectre) :  ![starts](https://img.shields.io/github/stars/neuhalje/presentation_meltdown_spectre.svg) ![forks](https://img.shields.io/github/forks/neuhalje/presentation_meltdown_spectre.svg)

- [https://github.com/jarmouz/spectre_meltdown](https://github.com/jarmouz/spectre_meltdown) :  ![starts](https://img.shields.io/github/stars/jarmouz/spectre_meltdown.svg) ![forks](https://img.shields.io/github/forks/jarmouz/spectre_meltdown.svg)

- [https://github.com/gonoph/ansible-meltdown-spectre](https://github.com/gonoph/ansible-meltdown-spectre) :  ![starts](https://img.shields.io/github/stars/gonoph/ansible-meltdown-spectre.svg) ![forks](https://img.shields.io/github/forks/gonoph/ansible-meltdown-spectre.svg)

- [https://github.com/miglen/Awesome-Meltdown-Spectre](https://github.com/miglen/Awesome-Meltdown-Spectre) :  ![starts](https://img.shields.io/github/stars/miglen/Awesome-Meltdown-Spectre.svg) ![forks](https://img.shields.io/github/forks/miglen/Awesome-Meltdown-Spectre.svg)

- [https://github.com/zzado/Meltdown](https://github.com/zzado/Meltdown) :  ![starts](https://img.shields.io/github/stars/zzado/Meltdown.svg) ![forks](https://img.shields.io/github/forks/zzado/Meltdown.svg)

- [https://github.com/jdmulloy/meltdown-aws-scanner](https://github.com/jdmulloy/meltdown-aws-scanner) :  ![starts](https://img.shields.io/github/stars/jdmulloy/meltdown-aws-scanner.svg) ![forks](https://img.shields.io/github/forks/jdmulloy/meltdown-aws-scanner.svg)

- [https://github.com/speecyy/Am-I-affected-by-Meltdown](https://github.com/speecyy/Am-I-affected-by-Meltdown) :  ![starts](https://img.shields.io/github/stars/speecyy/Am-I-affected-by-Meltdown.svg) ![forks](https://img.shields.io/github/forks/speecyy/Am-I-affected-by-Meltdown.svg)

- [https://github.com/GregAskew/SpeculativeExecutionAssessment](https://github.com/GregAskew/SpeculativeExecutionAssessment) :  ![starts](https://img.shields.io/github/stars/GregAskew/SpeculativeExecutionAssessment.svg) ![forks](https://img.shields.io/github/forks/GregAskew/SpeculativeExecutionAssessment.svg)

- [https://github.com/kevincoakley/puppet-spectre_meltdown](https://github.com/kevincoakley/puppet-spectre_meltdown) :  ![starts](https://img.shields.io/github/stars/kevincoakley/puppet-spectre_meltdown.svg) ![forks](https://img.shields.io/github/forks/kevincoakley/puppet-spectre_meltdown.svg)

## CVE-2017-5753
 Systems with microprocessors utilizing speculative execution and branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis.



- [https://github.com/speed47/spectre-meltdown-checker](https://github.com/speed47/spectre-meltdown-checker) :  ![starts](https://img.shields.io/github/stars/speed47/spectre-meltdown-checker.svg) ![forks](https://img.shields.io/github/forks/speed47/spectre-meltdown-checker.svg)

- [https://github.com/Eugnis/spectre-attack](https://github.com/Eugnis/spectre-attack) :  ![starts](https://img.shields.io/github/stars/Eugnis/spectre-attack.svg) ![forks](https://img.shields.io/github/forks/Eugnis/spectre-attack.svg)

- [https://github.com/nsacyber/Hardware-and-Firmware-Security-Guidance](https://github.com/nsacyber/Hardware-and-Firmware-Security-Guidance) :  ![starts](https://img.shields.io/github/stars/nsacyber/Hardware-and-Firmware-Security-Guidance.svg) ![forks](https://img.shields.io/github/forks/nsacyber/Hardware-and-Firmware-Security-Guidance.svg)

- [https://github.com/mathse/meltdown-spectre-bios-list](https://github.com/mathse/meltdown-spectre-bios-list) :  ![starts](https://img.shields.io/github/stars/mathse/meltdown-spectre-bios-list.svg) ![forks](https://img.shields.io/github/forks/mathse/meltdown-spectre-bios-list.svg)

- [https://github.com/poilynx/spectre-attack-example](https://github.com/poilynx/spectre-attack-example) :  ![starts](https://img.shields.io/github/stars/poilynx/spectre-attack-example.svg) ![forks](https://img.shields.io/github/forks/poilynx/spectre-attack-example.svg)

- [https://github.com/neuhalje/presentation_meltdown_spectre](https://github.com/neuhalje/presentation_meltdown_spectre) :  ![starts](https://img.shields.io/github/stars/neuhalje/presentation_meltdown_spectre.svg) ![forks](https://img.shields.io/github/forks/neuhalje/presentation_meltdown_spectre.svg)

- [https://github.com/ixtal23/spectreScope](https://github.com/ixtal23/spectreScope) :  ![starts](https://img.shields.io/github/stars/ixtal23/spectreScope.svg) ![forks](https://img.shields.io/github/forks/ixtal23/spectreScope.svg)

- [https://github.com/EdwardOwusuAdjei/Spectre-PoC](https://github.com/EdwardOwusuAdjei/Spectre-PoC) :  ![starts](https://img.shields.io/github/stars/EdwardOwusuAdjei/Spectre-PoC.svg) ![forks](https://img.shields.io/github/forks/EdwardOwusuAdjei/Spectre-PoC.svg)

- [https://github.com/GarnetSunset/CiscoSpectreTakeover](https://github.com/GarnetSunset/CiscoSpectreTakeover) :  ![starts](https://img.shields.io/github/stars/GarnetSunset/CiscoSpectreTakeover.svg) ![forks](https://img.shields.io/github/forks/GarnetSunset/CiscoSpectreTakeover.svg)

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

- [https://github.com/Eugnis/spectre-attack](https://github.com/Eugnis/spectre-attack) :  ![starts](https://img.shields.io/github/stars/Eugnis/spectre-attack.svg) ![forks](https://img.shields.io/github/forks/Eugnis/spectre-attack.svg)

- [https://github.com/ionescu007/SpecuCheck](https://github.com/ionescu007/SpecuCheck) :  ![starts](https://img.shields.io/github/stars/ionescu007/SpecuCheck.svg) ![forks](https://img.shields.io/github/forks/ionescu007/SpecuCheck.svg)

- [https://github.com/nsacyber/Hardware-and-Firmware-Security-Guidance](https://github.com/nsacyber/Hardware-and-Firmware-Security-Guidance) :  ![starts](https://img.shields.io/github/stars/nsacyber/Hardware-and-Firmware-Security-Guidance.svg) ![forks](https://img.shields.io/github/forks/nsacyber/Hardware-and-Firmware-Security-Guidance.svg)

- [https://github.com/Viralmaniar/In-Spectre-Meltdown](https://github.com/Viralmaniar/In-Spectre-Meltdown) :  ![starts](https://img.shields.io/github/stars/Viralmaniar/In-Spectre-Meltdown.svg) ![forks](https://img.shields.io/github/forks/Viralmaniar/In-Spectre-Meltdown.svg)

- [https://github.com/opsxcq/exploit-cve-2017-5715](https://github.com/opsxcq/exploit-cve-2017-5715) :  ![starts](https://img.shields.io/github/stars/opsxcq/exploit-cve-2017-5715.svg) ![forks](https://img.shields.io/github/forks/opsxcq/exploit-cve-2017-5715.svg)

- [https://github.com/mathse/meltdown-spectre-bios-list](https://github.com/mathse/meltdown-spectre-bios-list) :  ![starts](https://img.shields.io/github/stars/mathse/meltdown-spectre-bios-list.svg) ![forks](https://img.shields.io/github/forks/mathse/meltdown-spectre-bios-list.svg)

- [https://github.com/poilynx/spectre-attack-example](https://github.com/poilynx/spectre-attack-example) :  ![starts](https://img.shields.io/github/stars/poilynx/spectre-attack-example.svg) ![forks](https://img.shields.io/github/forks/poilynx/spectre-attack-example.svg)

- [https://github.com/neuhalje/presentation_meltdown_spectre](https://github.com/neuhalje/presentation_meltdown_spectre) :  ![starts](https://img.shields.io/github/stars/neuhalje/presentation_meltdown_spectre.svg) ![forks](https://img.shields.io/github/forks/neuhalje/presentation_meltdown_spectre.svg)

- [https://github.com/ixtal23/spectreScope](https://github.com/ixtal23/spectreScope) :  ![starts](https://img.shields.io/github/stars/ixtal23/spectreScope.svg) ![forks](https://img.shields.io/github/forks/ixtal23/spectreScope.svg)

- [https://github.com/jarmouz/spectre_meltdown](https://github.com/jarmouz/spectre_meltdown) :  ![starts](https://img.shields.io/github/stars/jarmouz/spectre_meltdown.svg) ![forks](https://img.shields.io/github/forks/jarmouz/spectre_meltdown.svg)

- [https://github.com/EdwardOwusuAdjei/Spectre-PoC](https://github.com/EdwardOwusuAdjei/Spectre-PoC) :  ![starts](https://img.shields.io/github/stars/EdwardOwusuAdjei/Spectre-PoC.svg) ![forks](https://img.shields.io/github/forks/EdwardOwusuAdjei/Spectre-PoC.svg)

- [https://github.com/GarnetSunset/CiscoSpectreTakeover](https://github.com/GarnetSunset/CiscoSpectreTakeover) :  ![starts](https://img.shields.io/github/stars/GarnetSunset/CiscoSpectreTakeover.svg) ![forks](https://img.shields.io/github/forks/GarnetSunset/CiscoSpectreTakeover.svg)

- [https://github.com/gonoph/ansible-meltdown-spectre](https://github.com/gonoph/ansible-meltdown-spectre) :  ![starts](https://img.shields.io/github/stars/gonoph/ansible-meltdown-spectre.svg) ![forks](https://img.shields.io/github/forks/gonoph/ansible-meltdown-spectre.svg)

- [https://github.com/miglen/Awesome-Meltdown-Spectre](https://github.com/miglen/Awesome-Meltdown-Spectre) :  ![starts](https://img.shields.io/github/stars/miglen/Awesome-Meltdown-Spectre.svg) ![forks](https://img.shields.io/github/forks/miglen/Awesome-Meltdown-Spectre.svg)

- [https://github.com/pedrolucasoliva/spectre-attack-demo](https://github.com/pedrolucasoliva/spectre-attack-demo) :  ![starts](https://img.shields.io/github/stars/pedrolucasoliva/spectre-attack-demo.svg) ![forks](https://img.shields.io/github/forks/pedrolucasoliva/spectre-attack-demo.svg)

- [https://github.com/dmo2118/retpoline-audit](https://github.com/dmo2118/retpoline-audit) :  ![starts](https://img.shields.io/github/stars/dmo2118/retpoline-audit.svg) ![forks](https://img.shields.io/github/forks/dmo2118/retpoline-audit.svg)

- [https://github.com/GregAskew/SpeculativeExecutionAssessment](https://github.com/GregAskew/SpeculativeExecutionAssessment) :  ![starts](https://img.shields.io/github/stars/GregAskew/SpeculativeExecutionAssessment.svg) ![forks](https://img.shields.io/github/forks/GregAskew/SpeculativeExecutionAssessment.svg)

- [https://github.com/kevincoakley/puppet-spectre_meltdown](https://github.com/kevincoakley/puppet-spectre_meltdown) :  ![starts](https://img.shields.io/github/stars/kevincoakley/puppet-spectre_meltdown.svg) ![forks](https://img.shields.io/github/forks/kevincoakley/puppet-spectre_meltdown.svg)

## CVE-2017-5693
 Firmware in the Intel Puma 5, 6, and 7 Series might experience resource depletion or timeout, which allows a network attacker to create a denial of service via crafted network traffic.



- [https://github.com/TransLunarInjection/Puma6Fail](https://github.com/TransLunarInjection/Puma6Fail) :  ![starts](https://img.shields.io/github/stars/TransLunarInjection/Puma6Fail.svg) ![forks](https://img.shields.io/github/forks/TransLunarInjection/Puma6Fail.svg)

## CVE-2017-5689
 An unprivileged network attacker could gain system privileges to provisioned Intel manageability SKUs: Intel Active Management Technology (AMT) and Intel Standard Manageability (ISM). An unprivileged local attacker could provision manageability features gaining unprivileged network or local system privileges on Intel manageability SKUs: Intel Active Management Technology (AMT), Intel Standard Manageability (ISM), and Intel Small Business Technology (SBT).



- [https://github.com/bartblaze/Disable-Intel-AMT](https://github.com/bartblaze/Disable-Intel-AMT) :  ![starts](https://img.shields.io/github/stars/bartblaze/Disable-Intel-AMT.svg) ![forks](https://img.shields.io/github/forks/bartblaze/Disable-Intel-AMT.svg)

- [https://github.com/embedi/amt_auth_bypass_poc](https://github.com/embedi/amt_auth_bypass_poc) :  ![starts](https://img.shields.io/github/stars/embedi/amt_auth_bypass_poc.svg) ![forks](https://img.shields.io/github/forks/embedi/amt_auth_bypass_poc.svg)

- [https://github.com/CerberusSecurity/CVE-2017-5689](https://github.com/CerberusSecurity/CVE-2017-5689) :  ![starts](https://img.shields.io/github/stars/CerberusSecurity/CVE-2017-5689.svg) ![forks](https://img.shields.io/github/forks/CerberusSecurity/CVE-2017-5689.svg)

- [https://github.com/x1sec/amthoneypot](https://github.com/x1sec/amthoneypot) :  ![starts](https://img.shields.io/github/stars/x1sec/amthoneypot.svg) ![forks](https://img.shields.io/github/forks/x1sec/amthoneypot.svg)

- [https://github.com/Bijaye/intel_amt_bypass](https://github.com/Bijaye/intel_amt_bypass) :  ![starts](https://img.shields.io/github/stars/Bijaye/intel_amt_bypass.svg) ![forks](https://img.shields.io/github/forks/Bijaye/intel_amt_bypass.svg)

- [https://github.com/baonq-me/cve2017-5689](https://github.com/baonq-me/cve2017-5689) :  ![starts](https://img.shields.io/github/stars/baonq-me/cve2017-5689.svg) ![forks](https://img.shields.io/github/forks/baonq-me/cve2017-5689.svg)

- [https://github.com/TheWay-hue/CVE-2017-5689-Checker](https://github.com/TheWay-hue/CVE-2017-5689-Checker) :  ![starts](https://img.shields.io/github/stars/TheWay-hue/CVE-2017-5689-Checker.svg) ![forks](https://img.shields.io/github/forks/TheWay-hue/CVE-2017-5689-Checker.svg)

## CVE-2017-5674
 A vulnerability in a custom-built GoAhead web server used on Foscam, Vstarcam, and multiple white-label IP camera models allows an attacker to craft a malformed HTTP (&quot;GET system.ini HTTP/1.1\n\n&quot; - note the lack of &quot;/&quot; in the path field of the request) request that will disclose the configuration file with the login password.



- [https://github.com/eR072391/cve-2017-5674](https://github.com/eR072391/cve-2017-5674) :  ![starts](https://img.shields.io/github/stars/eR072391/cve-2017-5674.svg) ![forks](https://img.shields.io/github/forks/eR072391/cve-2017-5674.svg)

## CVE-2017-5645
 In Apache Log4j 2.x before 2.8.2, when using the TCP socket server or UDP socket server to receive serialized log events from another application, a specially crafted binary payload can be sent that, when deserialized, can execute arbitrary code.



- [https://github.com/pimps/CVE-2017-5645](https://github.com/pimps/CVE-2017-5645) :  ![starts](https://img.shields.io/github/stars/pimps/CVE-2017-5645.svg) ![forks](https://img.shields.io/github/forks/pimps/CVE-2017-5645.svg)

## CVE-2017-5638
 The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.



- [https://github.com/mazen160/struts-pwn](https://github.com/mazen160/struts-pwn) :  ![starts](https://img.shields.io/github/stars/mazen160/struts-pwn.svg) ![forks](https://img.shields.io/github/forks/mazen160/struts-pwn.svg)

- [https://github.com/Flyteas/Struts2-045-Exp](https://github.com/Flyteas/Struts2-045-Exp) :  ![starts](https://img.shields.io/github/stars/Flyteas/Struts2-045-Exp.svg) ![forks](https://img.shields.io/github/forks/Flyteas/Struts2-045-Exp.svg)

- [https://github.com/Z-0ne/ScanS2-045-Nmap](https://github.com/Z-0ne/ScanS2-045-Nmap) :  ![starts](https://img.shields.io/github/stars/Z-0ne/ScanS2-045-Nmap.svg) ![forks](https://img.shields.io/github/forks/Z-0ne/ScanS2-045-Nmap.svg)

- [https://github.com/mthbernardes/strutszeiro](https://github.com/mthbernardes/strutszeiro) :  ![starts](https://img.shields.io/github/stars/mthbernardes/strutszeiro.svg) ![forks](https://img.shields.io/github/forks/mthbernardes/strutszeiro.svg)

- [https://github.com/immunio/apache-struts2-CVE-2017-5638](https://github.com/immunio/apache-struts2-CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/immunio/apache-struts2-CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/immunio/apache-struts2-CVE-2017-5638.svg)

- [https://github.com/jas502n/S2-045-EXP-POC-TOOLS](https://github.com/jas502n/S2-045-EXP-POC-TOOLS) :  ![starts](https://img.shields.io/github/stars/jas502n/S2-045-EXP-POC-TOOLS.svg) ![forks](https://img.shields.io/github/forks/jas502n/S2-045-EXP-POC-TOOLS.svg)

- [https://github.com/PolarisLab/S2-045](https://github.com/PolarisLab/S2-045) :  ![starts](https://img.shields.io/github/stars/PolarisLab/S2-045.svg) ![forks](https://img.shields.io/github/forks/PolarisLab/S2-045.svg)

- [https://github.com/jas502n/st2-046-poc](https://github.com/jas502n/st2-046-poc) :  ![starts](https://img.shields.io/github/stars/jas502n/st2-046-poc.svg) ![forks](https://img.shields.io/github/forks/jas502n/st2-046-poc.svg)

- [https://github.com/ret2jazzy/Struts-Apache-ExploitPack](https://github.com/ret2jazzy/Struts-Apache-ExploitPack) :  ![starts](https://img.shields.io/github/stars/ret2jazzy/Struts-Apache-ExploitPack.svg) ![forks](https://img.shields.io/github/forks/ret2jazzy/Struts-Apache-ExploitPack.svg)

- [https://github.com/shawnmckinney/remote-code-execution-sample](https://github.com/shawnmckinney/remote-code-execution-sample) :  ![starts](https://img.shields.io/github/stars/shawnmckinney/remote-code-execution-sample.svg) ![forks](https://img.shields.io/github/forks/shawnmckinney/remote-code-execution-sample.svg)

- [https://github.com/sUbc0ol/Apache-Struts2-RCE-Exploit-v2-CVE-2017-5638](https://github.com/sUbc0ol/Apache-Struts2-RCE-Exploit-v2-CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/sUbc0ol/Apache-Struts2-RCE-Exploit-v2-CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/sUbc0ol/Apache-Struts2-RCE-Exploit-v2-CVE-2017-5638.svg)

- [https://github.com/xsscx/cve-2017-5638](https://github.com/xsscx/cve-2017-5638) :  ![starts](https://img.shields.io/github/stars/xsscx/cve-2017-5638.svg) ![forks](https://img.shields.io/github/forks/xsscx/cve-2017-5638.svg)

- [https://github.com/jrrdev/cve-2017-5638](https://github.com/jrrdev/cve-2017-5638) :  ![starts](https://img.shields.io/github/stars/jrrdev/cve-2017-5638.svg) ![forks](https://img.shields.io/github/forks/jrrdev/cve-2017-5638.svg)

- [https://github.com/tahmed11/strutsy](https://github.com/tahmed11/strutsy) :  ![starts](https://img.shields.io/github/stars/tahmed11/strutsy.svg) ![forks](https://img.shields.io/github/forks/tahmed11/strutsy.svg)

- [https://github.com/payatu/CVE-2017-5638](https://github.com/payatu/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/payatu/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/payatu/CVE-2017-5638.svg)

- [https://github.com/Iletee/struts2-rce](https://github.com/Iletee/struts2-rce) :  ![starts](https://img.shields.io/github/stars/Iletee/struts2-rce.svg) ![forks](https://img.shields.io/github/forks/Iletee/struts2-rce.svg)

- [https://github.com/initconf/CVE-2017-5638_struts](https://github.com/initconf/CVE-2017-5638_struts) :  ![starts](https://img.shields.io/github/stars/initconf/CVE-2017-5638_struts.svg) ![forks](https://img.shields.io/github/forks/initconf/CVE-2017-5638_struts.svg)

- [https://github.com/R4v3nBl4ck/Apache-Struts-2-CVE-2017-5638-Exploit-](https://github.com/R4v3nBl4ck/Apache-Struts-2-CVE-2017-5638-Exploit-) :  ![starts](https://img.shields.io/github/stars/R4v3nBl4ck/Apache-Struts-2-CVE-2017-5638-Exploit-.svg) ![forks](https://img.shields.io/github/forks/R4v3nBl4ck/Apache-Struts-2-CVE-2017-5638-Exploit-.svg)

- [https://github.com/0x00-0x00/CVE-2017-5638](https://github.com/0x00-0x00/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/0x00-0x00/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/0x00-0x00/CVE-2017-5638.svg)

- [https://github.com/evolvesecurity/vuln-struts2-vm](https://github.com/evolvesecurity/vuln-struts2-vm) :  ![starts](https://img.shields.io/github/stars/evolvesecurity/vuln-struts2-vm.svg) ![forks](https://img.shields.io/github/forks/evolvesecurity/vuln-struts2-vm.svg)

- [https://github.com/falcon-lnhg/StrutsShell](https://github.com/falcon-lnhg/StrutsShell) :  ![starts](https://img.shields.io/github/stars/falcon-lnhg/StrutsShell.svg) ![forks](https://img.shields.io/github/forks/falcon-lnhg/StrutsShell.svg)

- [https://github.com/oktavianto/CVE-2017-5638-Apache-Struts2](https://github.com/oktavianto/CVE-2017-5638-Apache-Struts2) :  ![starts](https://img.shields.io/github/stars/oktavianto/CVE-2017-5638-Apache-Struts2.svg) ![forks](https://img.shields.io/github/forks/oktavianto/CVE-2017-5638-Apache-Struts2.svg)

- [https://github.com/win3zz/CVE-2017-5638](https://github.com/win3zz/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/win3zz/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/win3zz/CVE-2017-5638.svg)

- [https://github.com/lolwaleet/ExpStruts](https://github.com/lolwaleet/ExpStruts) :  ![starts](https://img.shields.io/github/stars/lolwaleet/ExpStruts.svg) ![forks](https://img.shields.io/github/forks/lolwaleet/ExpStruts.svg)

- [https://github.com/Greynad/struts2-jakarta-inject](https://github.com/Greynad/struts2-jakarta-inject) :  ![starts](https://img.shields.io/github/stars/Greynad/struts2-jakarta-inject.svg) ![forks](https://img.shields.io/github/forks/Greynad/struts2-jakarta-inject.svg)

- [https://github.com/opt9/Strutscli](https://github.com/opt9/Strutscli) :  ![starts](https://img.shields.io/github/stars/opt9/Strutscli.svg) ![forks](https://img.shields.io/github/forks/opt9/Strutscli.svg)

- [https://github.com/dock0d1/Apache-Struts-2-CVE-2017-5638-Exploit](https://github.com/dock0d1/Apache-Struts-2-CVE-2017-5638-Exploit) :  ![starts](https://img.shields.io/github/stars/dock0d1/Apache-Struts-2-CVE-2017-5638-Exploit.svg) ![forks](https://img.shields.io/github/forks/dock0d1/Apache-Struts-2-CVE-2017-5638-Exploit.svg)

- [https://github.com/aljazceru/CVE-2017-5638-Apache-Struts2](https://github.com/aljazceru/CVE-2017-5638-Apache-Struts2) :  ![starts](https://img.shields.io/github/stars/aljazceru/CVE-2017-5638-Apache-Struts2.svg) ![forks](https://img.shields.io/github/forks/aljazceru/CVE-2017-5638-Apache-Struts2.svg)

- [https://github.com/opt9/Strutshock](https://github.com/opt9/Strutshock) :  ![starts](https://img.shields.io/github/stars/opt9/Strutshock.svg) ![forks](https://img.shields.io/github/forks/opt9/Strutshock.svg)

- [https://github.com/paralelo14/CVE_2017_5638](https://github.com/paralelo14/CVE_2017_5638) :  ![starts](https://img.shields.io/github/stars/paralelo14/CVE_2017_5638.svg) ![forks](https://img.shields.io/github/forks/paralelo14/CVE_2017_5638.svg)

- [https://github.com/riyazwalikar/struts-rce-cve-2017-5638](https://github.com/riyazwalikar/struts-rce-cve-2017-5638) :  ![starts](https://img.shields.io/github/stars/riyazwalikar/struts-rce-cve-2017-5638.svg) ![forks](https://img.shields.io/github/forks/riyazwalikar/struts-rce-cve-2017-5638.svg)

- [https://github.com/ggolawski/struts-rce](https://github.com/ggolawski/struts-rce) :  ![starts](https://img.shields.io/github/stars/ggolawski/struts-rce.svg) ![forks](https://img.shields.io/github/forks/ggolawski/struts-rce.svg)

- [https://github.com/pr0x1ma-byte/cybersecurity-struts2](https://github.com/pr0x1ma-byte/cybersecurity-struts2) :  ![starts](https://img.shields.io/github/stars/pr0x1ma-byte/cybersecurity-struts2.svg) ![forks](https://img.shields.io/github/forks/pr0x1ma-byte/cybersecurity-struts2.svg)

- [https://github.com/un4ckn0wl3z/CVE-2017-5638](https://github.com/un4ckn0wl3z/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/un4ckn0wl3z/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/un4ckn0wl3z/CVE-2017-5638.svg)

- [https://github.com/m3ssap0/struts2_cve-2017-5638](https://github.com/m3ssap0/struts2_cve-2017-5638) :  ![starts](https://img.shields.io/github/stars/m3ssap0/struts2_cve-2017-5638.svg) ![forks](https://img.shields.io/github/forks/m3ssap0/struts2_cve-2017-5638.svg)

- [https://github.com/jptr218/struts_hack](https://github.com/jptr218/struts_hack) :  ![starts](https://img.shields.io/github/stars/jptr218/struts_hack.svg) ![forks](https://img.shields.io/github/forks/jptr218/struts_hack.svg)

- [https://github.com/ludy-dev/XworkStruts-RCE](https://github.com/ludy-dev/XworkStruts-RCE) :  ![starts](https://img.shields.io/github/stars/ludy-dev/XworkStruts-RCE.svg) ![forks](https://img.shields.io/github/forks/ludy-dev/XworkStruts-RCE.svg)

- [https://github.com/andypitcher/check_struts](https://github.com/andypitcher/check_struts) :  ![starts](https://img.shields.io/github/stars/andypitcher/check_struts.svg) ![forks](https://img.shields.io/github/forks/andypitcher/check_struts.svg)

- [https://github.com/sUbc0ol/Apache-Struts-CVE-2017-5638-RCE-Mass-Scanner](https://github.com/sUbc0ol/Apache-Struts-CVE-2017-5638-RCE-Mass-Scanner) :  ![starts](https://img.shields.io/github/stars/sUbc0ol/Apache-Struts-CVE-2017-5638-RCE-Mass-Scanner.svg) ![forks](https://img.shields.io/github/forks/sUbc0ol/Apache-Struts-CVE-2017-5638-RCE-Mass-Scanner.svg)

- [https://github.com/mike-williams/Struts2Vuln](https://github.com/mike-williams/Struts2Vuln) :  ![starts](https://img.shields.io/github/stars/mike-williams/Struts2Vuln.svg) ![forks](https://img.shields.io/github/forks/mike-williams/Struts2Vuln.svg)

- [https://github.com/Masahiro-Yamada/OgnlContentTypeRejectorValve](https://github.com/Masahiro-Yamada/OgnlContentTypeRejectorValve) :  ![starts](https://img.shields.io/github/stars/Masahiro-Yamada/OgnlContentTypeRejectorValve.svg) ![forks](https://img.shields.io/github/forks/Masahiro-Yamada/OgnlContentTypeRejectorValve.svg)

- [https://github.com/KarzsGHR/S2-046_S2-045_POC](https://github.com/KarzsGHR/S2-046_S2-045_POC) :  ![starts](https://img.shields.io/github/stars/KarzsGHR/S2-046_S2-045_POC.svg) ![forks](https://img.shields.io/github/forks/KarzsGHR/S2-046_S2-045_POC.svg)

- [https://github.com/gh0st27/Struts2Scanner](https://github.com/gh0st27/Struts2Scanner) :  ![starts](https://img.shields.io/github/stars/gh0st27/Struts2Scanner.svg) ![forks](https://img.shields.io/github/forks/gh0st27/Struts2Scanner.svg)

- [https://github.com/invisiblethreat/strutser](https://github.com/invisiblethreat/strutser) :  ![starts](https://img.shields.io/github/stars/invisiblethreat/strutser.svg) ![forks](https://img.shields.io/github/forks/invisiblethreat/strutser.svg)

- [https://github.com/gsfish/S2-Reaper](https://github.com/gsfish/S2-Reaper) :  ![starts](https://img.shields.io/github/stars/gsfish/S2-Reaper.svg) ![forks](https://img.shields.io/github/forks/gsfish/S2-Reaper.svg)

- [https://github.com/SpiderMate/Stutsfi](https://github.com/SpiderMate/Stutsfi) :  ![starts](https://img.shields.io/github/stars/SpiderMate/Stutsfi.svg) ![forks](https://img.shields.io/github/forks/SpiderMate/Stutsfi.svg)

- [https://github.com/pasannirmana/Aspire](https://github.com/pasannirmana/Aspire) :  ![starts](https://img.shields.io/github/stars/pasannirmana/Aspire.svg) ![forks](https://img.shields.io/github/forks/pasannirmana/Aspire.svg)

- [https://github.com/Aasron/Struts2-045-Exp](https://github.com/Aasron/Struts2-045-Exp) :  ![starts](https://img.shields.io/github/stars/Aasron/Struts2-045-Exp.svg) ![forks](https://img.shields.io/github/forks/Aasron/Struts2-045-Exp.svg)

- [https://github.com/colorblindpentester/CVE-2017-5638](https://github.com/colorblindpentester/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/colorblindpentester/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/colorblindpentester/CVE-2017-5638.svg)

- [https://github.com/eeehit/CVE-2017-5638](https://github.com/eeehit/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/eeehit/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/eeehit/CVE-2017-5638.svg)

- [https://github.com/random-robbie/CVE-2017-5638](https://github.com/random-robbie/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/random-robbie/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/random-robbie/CVE-2017-5638.svg)

- [https://github.com/AndreasKl/CVE-2017-5638](https://github.com/AndreasKl/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/AndreasKl/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/AndreasKl/CVE-2017-5638.svg)

- [https://github.com/Badbird3/CVE-2017-5638](https://github.com/Badbird3/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/Badbird3/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/Badbird3/CVE-2017-5638.svg)

- [https://github.com/Xhendos/CVE-2017-5638](https://github.com/Xhendos/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/Xhendos/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/Xhendos/CVE-2017-5638.svg)

- [https://github.com/bongbongco/cve-2017-5638](https://github.com/bongbongco/cve-2017-5638) :  ![starts](https://img.shields.io/github/stars/bongbongco/cve-2017-5638.svg) ![forks](https://img.shields.io/github/forks/bongbongco/cve-2017-5638.svg)

- [https://github.com/lizhi16/CVE-2017-5638](https://github.com/lizhi16/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/lizhi16/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/lizhi16/CVE-2017-5638.svg)

- [https://github.com/injcristianrojas/cve-2017-5638](https://github.com/injcristianrojas/cve-2017-5638) :  ![starts](https://img.shields.io/github/stars/injcristianrojas/cve-2017-5638.svg) ![forks](https://img.shields.io/github/forks/injcristianrojas/cve-2017-5638.svg)

- [https://github.com/jongmartinez/CVE-2017-5638](https://github.com/jongmartinez/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/jongmartinez/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/jongmartinez/CVE-2017-5638.svg)

- [https://github.com/mcassano/cve-2017-5638](https://github.com/mcassano/cve-2017-5638) :  ![starts](https://img.shields.io/github/stars/mcassano/cve-2017-5638.svg) ![forks](https://img.shields.io/github/forks/mcassano/cve-2017-5638.svg)

- [https://github.com/bhagdave/CVE-2017-5638](https://github.com/bhagdave/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/bhagdave/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/bhagdave/CVE-2017-5638.svg)

- [https://github.com/jrrombaldo/CVE-2017-5638](https://github.com/jrrombaldo/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/jrrombaldo/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/jrrombaldo/CVE-2017-5638.svg)

- [https://github.com/homjxi0e/CVE-2017-5638](https://github.com/homjxi0e/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-5638.svg)

- [https://github.com/leandrocamposcardoso/CVE-2017-5638-Mass-Exploit](https://github.com/leandrocamposcardoso/CVE-2017-5638-Mass-Exploit) :  ![starts](https://img.shields.io/github/stars/leandrocamposcardoso/CVE-2017-5638-Mass-Exploit.svg) ![forks](https://img.shields.io/github/forks/leandrocamposcardoso/CVE-2017-5638-Mass-Exploit.svg)

- [https://github.com/cafnet/apache-struts-v2-CVE-2017-5638](https://github.com/cafnet/apache-struts-v2-CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/cafnet/apache-struts-v2-CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/cafnet/apache-struts-v2-CVE-2017-5638.svg)

- [https://github.com/sjitech/test_struts2_vulnerability_CVE-2017-5638](https://github.com/sjitech/test_struts2_vulnerability_CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/sjitech/test_struts2_vulnerability_CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/sjitech/test_struts2_vulnerability_CVE-2017-5638.svg)

- [https://github.com/c002/Apache-Struts](https://github.com/c002/Apache-Struts) :  ![starts](https://img.shields.io/github/stars/c002/Apache-Struts.svg) ![forks](https://img.shields.io/github/forks/c002/Apache-Struts.svg)

- [https://github.com/TamiiLambrado/Apache-Struts-CVE-2017-5638-RCE-Mass-Scanner](https://github.com/TamiiLambrado/Apache-Struts-CVE-2017-5638-RCE-Mass-Scanner) :  ![starts](https://img.shields.io/github/stars/TamiiLambrado/Apache-Struts-CVE-2017-5638-RCE-Mass-Scanner.svg) ![forks](https://img.shields.io/github/forks/TamiiLambrado/Apache-Struts-CVE-2017-5638-RCE-Mass-Scanner.svg)

- [https://github.com/jpacora/Struts2Shell](https://github.com/jpacora/Struts2Shell) :  ![starts](https://img.shields.io/github/stars/jpacora/Struts2Shell.svg) ![forks](https://img.shields.io/github/forks/jpacora/Struts2Shell.svg)

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



- [https://github.com/teambugsbunny/wpUsersScan](https://github.com/teambugsbunny/wpUsersScan) :  ![starts](https://img.shields.io/github/stars/teambugsbunny/wpUsersScan.svg) ![forks](https://img.shields.io/github/forks/teambugsbunny/wpUsersScan.svg)

- [https://github.com/GeunSam2/CVE-2017-5487](https://github.com/GeunSam2/CVE-2017-5487) :  ![starts](https://img.shields.io/github/stars/GeunSam2/CVE-2017-5487.svg) ![forks](https://img.shields.io/github/forks/GeunSam2/CVE-2017-5487.svg)

- [https://github.com/patilkr/wp-CVE-2017-5487-exploit](https://github.com/patilkr/wp-CVE-2017-5487-exploit) :  ![starts](https://img.shields.io/github/stars/patilkr/wp-CVE-2017-5487-exploit.svg) ![forks](https://img.shields.io/github/forks/patilkr/wp-CVE-2017-5487-exploit.svg)

- [https://github.com/kr4dd/CVE-2017-5487](https://github.com/kr4dd/CVE-2017-5487) :  ![starts](https://img.shields.io/github/stars/kr4dd/CVE-2017-5487.svg) ![forks](https://img.shields.io/github/forks/kr4dd/CVE-2017-5487.svg)

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
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem.  When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/c3r34lk1ll3r/CVE-2017-5123](https://github.com/c3r34lk1ll3r/CVE-2017-5123) :  ![starts](https://img.shields.io/github/stars/c3r34lk1ll3r/CVE-2017-5123.svg) ![forks](https://img.shields.io/github/forks/c3r34lk1ll3r/CVE-2017-5123.svg)

- [https://github.com/0x5068656e6f6c/CVE-2017-5123](https://github.com/0x5068656e6f6c/CVE-2017-5123) :  ![starts](https://img.shields.io/github/stars/0x5068656e6f6c/CVE-2017-5123.svg) ![forks](https://img.shields.io/github/forks/0x5068656e6f6c/CVE-2017-5123.svg)

- [https://github.com/Synacktiv-contrib/exploiting-cve-2017-5123](https://github.com/Synacktiv-contrib/exploiting-cve-2017-5123) :  ![starts](https://img.shields.io/github/stars/Synacktiv-contrib/exploiting-cve-2017-5123.svg) ![forks](https://img.shields.io/github/forks/Synacktiv-contrib/exploiting-cve-2017-5123.svg)

- [https://github.com/FloatingGuy/CVE-2017-5123](https://github.com/FloatingGuy/CVE-2017-5123) :  ![starts](https://img.shields.io/github/stars/FloatingGuy/CVE-2017-5123.svg) ![forks](https://img.shields.io/github/forks/FloatingGuy/CVE-2017-5123.svg)

- [https://github.com/teawater/CVE-2017-5123](https://github.com/teawater/CVE-2017-5123) :  ![starts](https://img.shields.io/github/stars/teawater/CVE-2017-5123.svg) ![forks](https://img.shields.io/github/forks/teawater/CVE-2017-5123.svg)

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

- [https://github.com/zakybstrd21215/PoC-CVE-2017-3881](https://github.com/zakybstrd21215/PoC-CVE-2017-3881) :  ![starts](https://img.shields.io/github/stars/zakybstrd21215/PoC-CVE-2017-3881.svg) ![forks](https://img.shields.io/github/forks/zakybstrd21215/PoC-CVE-2017-3881.svg)

- [https://github.com/homjxi0e/CVE-2017-3881-Cisco](https://github.com/homjxi0e/CVE-2017-3881-Cisco) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-3881-Cisco.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-3881-Cisco.svg)

## CVE-2017-3730
 In OpenSSL 1.1.0 before 1.1.0d, if a malicious server supplies bad parameters for a DHE or ECDHE key exchange then this can result in the client attempting to dereference a NULL pointer leading to a client crash. This could be exploited in a Denial of Service attack.



- [https://github.com/guidovranken/CVE-2017-3730](https://github.com/guidovranken/CVE-2017-3730) :  ![starts](https://img.shields.io/github/stars/guidovranken/CVE-2017-3730.svg) ![forks](https://img.shields.io/github/forks/guidovranken/CVE-2017-3730.svg)

## CVE-2017-3599
 Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server: Pluggable Auth). Supported versions that are affected are 5.6.35 and earlier and 5.7.17 and earlier. Easily &quot;exploitable&quot; vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.0 Base Score 7.5 (Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H). NOTE: the previous information is from the April 2017 CPU. Oracle has not commented on third-party claims that this issue is an integer overflow in sql/auth/sql_authentication.cc which allows remote attackers to cause a denial of service via a crafted authentication packet.



- [https://github.com/SECFORCE/CVE-2017-3599](https://github.com/SECFORCE/CVE-2017-3599) :  ![starts](https://img.shields.io/github/stars/SECFORCE/CVE-2017-3599.svg) ![forks](https://img.shields.io/github/forks/SECFORCE/CVE-2017-3599.svg)

- [https://github.com/jptr218/mysql_dos](https://github.com/jptr218/mysql_dos) :  ![starts](https://img.shields.io/github/stars/jptr218/mysql_dos.svg) ![forks](https://img.shields.io/github/forks/jptr218/mysql_dos.svg)

## CVE-2017-3506
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Web Services). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.0, 12.2.1.1 and 12.2.1.2. Difficult to exploit vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification access to critical data or all Oracle WebLogic Server accessible data as well as unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.0 Base Score 7.4 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N).



- [https://github.com/0xn0ne/weblogicScanner](https://github.com/0xn0ne/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/0xn0ne/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/0xn0ne/weblogicScanner.svg)

- [https://github.com/ianxtianxt/CVE-2017-3506](https://github.com/ianxtianxt/CVE-2017-3506) :  ![starts](https://img.shields.io/github/stars/ianxtianxt/CVE-2017-3506.svg) ![forks](https://img.shields.io/github/forks/ianxtianxt/CVE-2017-3506.svg)

- [https://github.com/Al1ex/CVE-2017-3506](https://github.com/Al1ex/CVE-2017-3506) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2017-3506.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2017-3506.svg)

## CVE-2017-3248
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.0 and 12.2.1.1. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS v3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).



- [https://github.com/0xn0ne/weblogicScanner](https://github.com/0xn0ne/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/0xn0ne/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/0xn0ne/weblogicScanner.svg)

- [https://github.com/ianxtianxt/CVE-2017-3248](https://github.com/ianxtianxt/CVE-2017-3248) :  ![starts](https://img.shields.io/github/stars/ianxtianxt/CVE-2017-3248.svg) ![forks](https://img.shields.io/github/forks/ianxtianxt/CVE-2017-3248.svg)

- [https://github.com/BabyTeam1024/CVE-2017-3248](https://github.com/BabyTeam1024/CVE-2017-3248) :  ![starts](https://img.shields.io/github/stars/BabyTeam1024/CVE-2017-3248.svg) ![forks](https://img.shields.io/github/forks/BabyTeam1024/CVE-2017-3248.svg)

## CVE-2017-3241
 Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent: RMI). Supported versions that are affected are Java SE: 6u131, 7u121 and 8u112; Java SE Embedded: 8u111; JRockit: R28.3.12. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Java SE, Java SE Embedded, JRockit. While the vulnerability is in Java SE, Java SE Embedded, JRockit, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in takeover of Java SE, Java SE Embedded, JRockit. Note: This vulnerability can only be exploited by supplying data to APIs in the specified Component without using Untrusted Java Web Start applications or Untrusted Java applets, such as through a web service. CVSS v3.0 Base Score 9.0 (Confidentiality, Integrity and Availability impacts).



- [https://github.com/xfei3/CVE-2017-3241-POC](https://github.com/xfei3/CVE-2017-3241-POC) :  ![starts](https://img.shields.io/github/stars/xfei3/CVE-2017-3241-POC.svg) ![forks](https://img.shields.io/github/forks/xfei3/CVE-2017-3241-POC.svg)

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

## CVE-2017-1635
 IBM Tivoli Monitoring V6 6.2.2.x could allow a remote attacker to execute arbitrary code on the system, caused by a use-after-free error. A remote attacker could exploit this vulnerability to execute arbitrary code on the system or cause the application to crash. IBM X-Force ID: 133243.



- [https://github.com/emcalv/tivoli-poc](https://github.com/emcalv/tivoli-poc) :  ![starts](https://img.shields.io/github/stars/emcalv/tivoli-poc.svg) ![forks](https://img.shields.io/github/forks/emcalv/tivoli-poc.svg)

- [https://github.com/bcdannyboy/cve-2017-1635-PoC](https://github.com/bcdannyboy/cve-2017-1635-PoC) :  ![starts](https://img.shields.io/github/stars/bcdannyboy/cve-2017-1635-PoC.svg) ![forks](https://img.shields.io/github/forks/bcdannyboy/cve-2017-1635-PoC.svg)

## CVE-2017-0931
 html-janitor node module suffers from a Cross-Site Scripting (XSS) vulnerability via clean() accepting user-controlled values.



- [https://github.com/ossf-cve-benchmark/CVE-2017-0931](https://github.com/ossf-cve-benchmark/CVE-2017-0931) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-0931.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-0931.svg)

## CVE-2017-0807
 An elevation of privilege vulnerability in the Android framework (ui framework). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2. Android ID: A-35056974.



- [https://github.com/kpatsakis/PoC_CVE-2017-0807](https://github.com/kpatsakis/PoC_CVE-2017-0807) :  ![starts](https://img.shields.io/github/stars/kpatsakis/PoC_CVE-2017-0807.svg) ![forks](https://img.shields.io/github/forks/kpatsakis/PoC_CVE-2017-0807.svg)

## CVE-2017-0806
 An elevation of privilege vulnerability in the Android framework (gatekeeperresponse). Product: Android. Versions: 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-62998805.



- [https://github.com/michalbednarski/ReparcelBug](https://github.com/michalbednarski/ReparcelBug) :  ![starts](https://img.shields.io/github/stars/michalbednarski/ReparcelBug.svg) ![forks](https://img.shields.io/github/forks/michalbednarski/ReparcelBug.svg)

## CVE-2017-0785
 A information disclosure vulnerability in the Android system (bluetooth). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-63146698.



- [https://github.com/ojasookert/CVE-2017-0785](https://github.com/ojasookert/CVE-2017-0785) :  ![starts](https://img.shields.io/github/stars/ojasookert/CVE-2017-0785.svg) ![forks](https://img.shields.io/github/forks/ojasookert/CVE-2017-0785.svg)

- [https://github.com/pieterbork/blueborne](https://github.com/pieterbork/blueborne) :  ![starts](https://img.shields.io/github/stars/pieterbork/blueborne.svg) ![forks](https://img.shields.io/github/forks/pieterbork/blueborne.svg)

- [https://github.com/Alfa100001/-CVE-2017-0785-BlueBorne-PoC](https://github.com/Alfa100001/-CVE-2017-0785-BlueBorne-PoC) :  ![starts](https://img.shields.io/github/stars/Alfa100001/-CVE-2017-0785-BlueBorne-PoC.svg) ![forks](https://img.shields.io/github/forks/Alfa100001/-CVE-2017-0785-BlueBorne-PoC.svg)

- [https://github.com/henrychoi7/Bluepwn](https://github.com/henrychoi7/Bluepwn) :  ![starts](https://img.shields.io/github/stars/henrychoi7/Bluepwn.svg) ![forks](https://img.shields.io/github/forks/henrychoi7/Bluepwn.svg)

- [https://github.com/RavSS/Bluetooth-Crash-CVE-2017-0785](https://github.com/RavSS/Bluetooth-Crash-CVE-2017-0785) :  ![starts](https://img.shields.io/github/stars/RavSS/Bluetooth-Crash-CVE-2017-0785.svg) ![forks](https://img.shields.io/github/forks/RavSS/Bluetooth-Crash-CVE-2017-0785.svg)

- [https://github.com/CrackSoft900/Blue-Borne](https://github.com/CrackSoft900/Blue-Borne) :  ![starts](https://img.shields.io/github/stars/CrackSoft900/Blue-Borne.svg) ![forks](https://img.shields.io/github/forks/CrackSoft900/Blue-Borne.svg)

- [https://github.com/aymankhalfatni/CVE-2017-0785](https://github.com/aymankhalfatni/CVE-2017-0785) :  ![starts](https://img.shields.io/github/stars/aymankhalfatni/CVE-2017-0785.svg) ![forks](https://img.shields.io/github/forks/aymankhalfatni/CVE-2017-0785.svg)

- [https://github.com/sigbitsadmin/diff](https://github.com/sigbitsadmin/diff) :  ![starts](https://img.shields.io/github/stars/sigbitsadmin/diff.svg) ![forks](https://img.shields.io/github/forks/sigbitsadmin/diff.svg)

- [https://github.com/SigBitsLabs/diff](https://github.com/SigBitsLabs/diff) :  ![starts](https://img.shields.io/github/stars/SigBitsLabs/diff.svg) ![forks](https://img.shields.io/github/forks/SigBitsLabs/diff.svg)

- [https://github.com/Hackerscript/BlueBorne-CVE-2017-0785](https://github.com/Hackerscript/BlueBorne-CVE-2017-0785) :  ![starts](https://img.shields.io/github/stars/Hackerscript/BlueBorne-CVE-2017-0785.svg) ![forks](https://img.shields.io/github/forks/Hackerscript/BlueBorne-CVE-2017-0785.svg)

## CVE-2017-0781
 A remote code execution vulnerability in the Android system (bluetooth). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-63146105.



- [https://github.com/ojasookert/CVE-2017-0781](https://github.com/ojasookert/CVE-2017-0781) :  ![starts](https://img.shields.io/github/stars/ojasookert/CVE-2017-0781.svg) ![forks](https://img.shields.io/github/forks/ojasookert/CVE-2017-0781.svg)

- [https://github.com/marcinguy/android712-blueborne](https://github.com/marcinguy/android712-blueborne) :  ![starts](https://img.shields.io/github/stars/marcinguy/android712-blueborne.svg) ![forks](https://img.shields.io/github/forks/marcinguy/android712-blueborne.svg)

- [https://github.com/CrackSoft900/Blue-Borne](https://github.com/CrackSoft900/Blue-Borne) :  ![starts](https://img.shields.io/github/stars/CrackSoft900/Blue-Borne.svg) ![forks](https://img.shields.io/github/forks/CrackSoft900/Blue-Borne.svg)

- [https://github.com/mjancek/BlueborneDetection](https://github.com/mjancek/BlueborneDetection) :  ![starts](https://img.shields.io/github/stars/mjancek/BlueborneDetection.svg) ![forks](https://img.shields.io/github/forks/mjancek/BlueborneDetection.svg)

## CVE-2017-0564
 An elevation of privilege vulnerability in the kernel ION subsystem could enable a local malicious application to execute arbitrary code within the context of the kernel. This issue is rated as Critical due to the possibility of a local permanent device compromise, which may require reflashing the operating system to repair the device. Product: Android. Versions: Kernel-3.10, Kernel-3.18. Android ID: A-34276203.



- [https://github.com/guoygang/CVE-2017-0564-ION-PoC](https://github.com/guoygang/CVE-2017-0564-ION-PoC) :  ![starts](https://img.shields.io/github/stars/guoygang/CVE-2017-0564-ION-PoC.svg) ![forks](https://img.shields.io/github/forks/guoygang/CVE-2017-0564-ION-PoC.svg)

## CVE-2017-0554
 An elevation of privilege vulnerability in the Telephony component could enable a local malicious application to access capabilities outside of its permission levels. This issue is rated as Moderate because it could be used to gain access to elevated capabilities, which are not normally accessible to a third-party application. Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1. Android ID: A-33815946.



- [https://github.com/lanrat/tethr](https://github.com/lanrat/tethr) :  ![starts](https://img.shields.io/github/stars/lanrat/tethr.svg) ![forks](https://img.shields.io/github/forks/lanrat/tethr.svg)

## CVE-2017-0541
 A remote code execution vulnerability in sonivox in Mediaserver could enable an attacker using a specially crafted file to cause memory corruption during media file and data processing. This issue is rated as Critical due to the possibility of remote code execution within the context of the Mediaserver process. Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1. Android ID: A-34031018.



- [https://github.com/JiounDai/CVE-2017-0541](https://github.com/JiounDai/CVE-2017-0541) :  ![starts](https://img.shields.io/github/stars/JiounDai/CVE-2017-0541.svg) ![forks](https://img.shields.io/github/forks/JiounDai/CVE-2017-0541.svg)

- [https://github.com/likescam/CVE-2017-0541](https://github.com/likescam/CVE-2017-0541) :  ![starts](https://img.shields.io/github/stars/likescam/CVE-2017-0541.svg) ![forks](https://img.shields.io/github/forks/likescam/CVE-2017-0541.svg)

## CVE-2017-0478
 A remote code execution vulnerability in the Framesequence library could enable an attacker using a specially crafted file to execute arbitrary code in the context of an unprivileged process. This issue is rated as High due to the possibility of remote code execution in an application that uses the Framesequence library. Product: Android. Versions: 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1. Android ID: A-33718716.



- [https://github.com/JiounDai/CVE-2017-0478](https://github.com/JiounDai/CVE-2017-0478) :  ![starts](https://img.shields.io/github/stars/JiounDai/CVE-2017-0478.svg) ![forks](https://img.shields.io/github/forks/JiounDai/CVE-2017-0478.svg)

- [https://github.com/likescam/CVE-2017-0478](https://github.com/likescam/CVE-2017-0478) :  ![starts](https://img.shields.io/github/stars/likescam/CVE-2017-0478.svg) ![forks](https://img.shields.io/github/forks/likescam/CVE-2017-0478.svg)

## CVE-2017-0411
 An elevation of privilege vulnerability in the Framework APIs could enable a local malicious application to execute arbitrary code within the context of a privileged process. This issue is rated as High because it could be used to gain local access to elevated capabilities, which are not normally accessible to a third-party application. Product: Android. Versions: 7.0, 7.1.1. Android ID: A-33042690.



- [https://github.com/lulusudoku/PoC](https://github.com/lulusudoku/PoC) :  ![starts](https://img.shields.io/github/stars/lulusudoku/PoC.svg) ![forks](https://img.shields.io/github/forks/lulusudoku/PoC.svg)

## CVE-2017-0290
 The Microsoft Malware Protection Engine running on Microsoft Forefront and Microsoft Defender on Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, and 1703, and Windows Server 2016 does not properly scan a specially crafted file leading to memory corruption, aka &quot;Microsoft Malware Protection Engine Remote Code Execution Vulnerability.&quot;



- [https://github.com/homjxi0e/CVE-2017-0290-](https://github.com/homjxi0e/CVE-2017-0290-) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-0290-.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-0290-.svg)

## CVE-2017-0263
 The kernel-mode drivers in Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, 1703, and Windows Server 2016 allow local users to gain privileges via a crafted application, aka &quot;Win32k Elevation of Privilege Vulnerability.&quot;



- [https://github.com/R06otMD5/cve-2017-0263-poc](https://github.com/R06otMD5/cve-2017-0263-poc) :  ![starts](https://img.shields.io/github/stars/R06otMD5/cve-2017-0263-poc.svg) ![forks](https://img.shields.io/github/forks/R06otMD5/cve-2017-0263-poc.svg)

## CVE-2017-0261
 Microsoft Office 2010 SP2, Office 2013 SP1, and Office 2016 allow a remote code execution vulnerability when the software fails to properly handle objects in memory, aka &quot;Office Remote Code Execution Vulnerability&quot;. This CVE ID is unique from CVE-2017-0262 and CVE-2017-0281.



- [https://github.com/kcufId/eps-CVE-2017-0261](https://github.com/kcufId/eps-CVE-2017-0261) :  ![starts](https://img.shields.io/github/stars/kcufId/eps-CVE-2017-0261.svg) ![forks](https://img.shields.io/github/forks/kcufId/eps-CVE-2017-0261.svg)

- [https://github.com/erfze/CVE-2017-0261](https://github.com/erfze/CVE-2017-0261) :  ![starts](https://img.shields.io/github/stars/erfze/CVE-2017-0261.svg) ![forks](https://img.shields.io/github/forks/erfze/CVE-2017-0261.svg)

## CVE-2017-0248
 Microsoft .NET Framework 2.0, 3.5, 3.5.1, 4.5.2, 4.6, 4.6.1, 4.6.2 and 4.7 allow an attacker to bypass Enhanced Security Usage taggings when they present a certificate that is invalid for a specific use, aka &quot;.NET Security Feature Bypass Vulnerability.&quot;



- [https://github.com/rubenmamo/CVE-2017-0248-Test](https://github.com/rubenmamo/CVE-2017-0248-Test) :  ![starts](https://img.shields.io/github/stars/rubenmamo/CVE-2017-0248-Test.svg) ![forks](https://img.shields.io/github/forks/rubenmamo/CVE-2017-0248-Test.svg)

## CVE-2017-0213
 Windows COM Aggregate Marshaler in Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, and 1703, and Windows Server 2016 allows an elevation privilege vulnerability when an attacker runs a specially crafted application, aka &quot;Windows COM Elevation of Privilege Vulnerability&quot;. This CVE ID is unique from CVE-2017-0214.



- [https://github.com/zcgonvh/CVE-2017-0213](https://github.com/zcgonvh/CVE-2017-0213) :  ![starts](https://img.shields.io/github/stars/zcgonvh/CVE-2017-0213.svg) ![forks](https://img.shields.io/github/forks/zcgonvh/CVE-2017-0213.svg)

- [https://github.com/eonrickity/CVE-2017-0213](https://github.com/eonrickity/CVE-2017-0213) :  ![starts](https://img.shields.io/github/stars/eonrickity/CVE-2017-0213.svg) ![forks](https://img.shields.io/github/forks/eonrickity/CVE-2017-0213.svg)

- [https://github.com/shaheemirza/CVE-2017-0213-](https://github.com/shaheemirza/CVE-2017-0213-) :  ![starts](https://img.shields.io/github/stars/shaheemirza/CVE-2017-0213-.svg) ![forks](https://img.shields.io/github/forks/shaheemirza/CVE-2017-0213-.svg)

- [https://github.com/jbooz1/CVE-2017-0213](https://github.com/jbooz1/CVE-2017-0213) :  ![starts](https://img.shields.io/github/stars/jbooz1/CVE-2017-0213.svg) ![forks](https://img.shields.io/github/forks/jbooz1/CVE-2017-0213.svg)

- [https://github.com/Jos675/CVE-2017-0213-Exploit](https://github.com/Jos675/CVE-2017-0213-Exploit) :  ![starts](https://img.shields.io/github/stars/Jos675/CVE-2017-0213-Exploit.svg) ![forks](https://img.shields.io/github/forks/Jos675/CVE-2017-0213-Exploit.svg)

- [https://github.com/likescam/CVE-2017-0213](https://github.com/likescam/CVE-2017-0213) :  ![starts](https://img.shields.io/github/stars/likescam/CVE-2017-0213.svg) ![forks](https://img.shields.io/github/forks/likescam/CVE-2017-0213.svg)

- [https://github.com/billa3283/CVE-2017-0213](https://github.com/billa3283/CVE-2017-0213) :  ![starts](https://img.shields.io/github/stars/billa3283/CVE-2017-0213.svg) ![forks](https://img.shields.io/github/forks/billa3283/CVE-2017-0213.svg)

## CVE-2017-0204
 Microsoft Outlook 2007 SP3, Microsoft Outlook 2010 SP2, Microsoft Outlook 2013 SP1, and Microsoft Outlook 2016 allow remote attackers to bypass the Office Protected View via a specially crafted document, aka &quot;Microsoft Office Security Feature Bypass Vulnerability.&quot;



- [https://github.com/ryhanson/CVE-2017-0204](https://github.com/ryhanson/CVE-2017-0204) :  ![starts](https://img.shields.io/github/stars/ryhanson/CVE-2017-0204.svg) ![forks](https://img.shields.io/github/forks/ryhanson/CVE-2017-0204.svg)

## CVE-2017-0199
 Microsoft Office 2007 SP3, Microsoft Office 2010 SP2, Microsoft Office 2013 SP1, Microsoft Office 2016, Microsoft Windows Vista SP2, Windows Server 2008 SP2, Windows 7 SP1, Windows 8.1 allow remote attackers to execute arbitrary code via a crafted document, aka &quot;Microsoft Office/WordPad Remote Code Execution Vulnerability w/Windows API.&quot;



- [https://github.com/bhdresh/CVE-2017-0199](https://github.com/bhdresh/CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/bhdresh/CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/bhdresh/CVE-2017-0199.svg)

- [https://github.com/haibara3839/CVE-2017-0199-master](https://github.com/haibara3839/CVE-2017-0199-master) :  ![starts](https://img.shields.io/github/stars/haibara3839/CVE-2017-0199-master.svg) ![forks](https://img.shields.io/github/forks/haibara3839/CVE-2017-0199-master.svg)

- [https://github.com/NotAwful/CVE-2017-0199-Fix](https://github.com/NotAwful/CVE-2017-0199-Fix) :  ![starts](https://img.shields.io/github/stars/NotAwful/CVE-2017-0199-Fix.svg) ![forks](https://img.shields.io/github/forks/NotAwful/CVE-2017-0199-Fix.svg)

- [https://github.com/SyFi/cve-2017-0199](https://github.com/SyFi/cve-2017-0199) :  ![starts](https://img.shields.io/github/stars/SyFi/cve-2017-0199.svg) ![forks](https://img.shields.io/github/forks/SyFi/cve-2017-0199.svg)

- [https://github.com/Exploit-install/CVE-2017-0199](https://github.com/Exploit-install/CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/Exploit-install/CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/Exploit-install/CVE-2017-0199.svg)

- [https://github.com/SwordSheath/CVE-2017-8570](https://github.com/SwordSheath/CVE-2017-8570) :  ![starts](https://img.shields.io/github/stars/SwordSheath/CVE-2017-8570.svg) ![forks](https://img.shields.io/github/forks/SwordSheath/CVE-2017-8570.svg)

- [https://github.com/jacobsoo/RTF-Cleaner](https://github.com/jacobsoo/RTF-Cleaner) :  ![starts](https://img.shields.io/github/stars/jacobsoo/RTF-Cleaner.svg) ![forks](https://img.shields.io/github/forks/jacobsoo/RTF-Cleaner.svg)

- [https://github.com/kn0wm4d/htattack](https://github.com/kn0wm4d/htattack) :  ![starts](https://img.shields.io/github/stars/kn0wm4d/htattack.svg) ![forks](https://img.shields.io/github/forks/kn0wm4d/htattack.svg)

- [https://github.com/nicpenning/RTF-Cleaner](https://github.com/nicpenning/RTF-Cleaner) :  ![starts](https://img.shields.io/github/stars/nicpenning/RTF-Cleaner.svg) ![forks](https://img.shields.io/github/forks/nicpenning/RTF-Cleaner.svg)

- [https://github.com/n1shant-sinha/CVE-2017-0199](https://github.com/n1shant-sinha/CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/n1shant-sinha/CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/n1shant-sinha/CVE-2017-0199.svg)

- [https://github.com/bloomer1016/2017-11-17-Maldoc-Using-CVE-2017-0199](https://github.com/bloomer1016/2017-11-17-Maldoc-Using-CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/bloomer1016/2017-11-17-Maldoc-Using-CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/bloomer1016/2017-11-17-Maldoc-Using-CVE-2017-0199.svg)

- [https://github.com/sUbc0ol/Microsoft-Word-CVE-2017-0199-](https://github.com/sUbc0ol/Microsoft-Word-CVE-2017-0199-) :  ![starts](https://img.shields.io/github/stars/sUbc0ol/Microsoft-Word-CVE-2017-0199-.svg) ![forks](https://img.shields.io/github/forks/sUbc0ol/Microsoft-Word-CVE-2017-0199-.svg)

- [https://github.com/zakybstrd21215/PoC-CVE-2017-0199](https://github.com/zakybstrd21215/PoC-CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/zakybstrd21215/PoC-CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/zakybstrd21215/PoC-CVE-2017-0199.svg)

- [https://github.com/Nacromencer/cve2017-0199-in-python](https://github.com/Nacromencer/cve2017-0199-in-python) :  ![starts](https://img.shields.io/github/stars/Nacromencer/cve2017-0199-in-python.svg) ![forks](https://img.shields.io/github/forks/Nacromencer/cve2017-0199-in-python.svg)

- [https://github.com/joke998/Cve-2017-0199-](https://github.com/joke998/Cve-2017-0199-) :  ![starts](https://img.shields.io/github/stars/joke998/Cve-2017-0199-.svg) ![forks](https://img.shields.io/github/forks/joke998/Cve-2017-0199-.svg)

- [https://github.com/viethdgit/CVE-2017-0199](https://github.com/viethdgit/CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/viethdgit/CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/viethdgit/CVE-2017-0199.svg)

- [https://github.com/likescam/CVE-2017-0199](https://github.com/likescam/CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/likescam/CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/likescam/CVE-2017-0199.svg)

- [https://github.com/joke998/Cve-2017-0199](https://github.com/joke998/Cve-2017-0199) :  ![starts](https://img.shields.io/github/stars/joke998/Cve-2017-0199.svg) ![forks](https://img.shields.io/github/forks/joke998/Cve-2017-0199.svg)

- [https://github.com/ryhanson/CVE-2017-0199](https://github.com/ryhanson/CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/ryhanson/CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/ryhanson/CVE-2017-0199.svg)

- [https://github.com/Winter3un/cve_2017_0199](https://github.com/Winter3un/cve_2017_0199) :  ![starts](https://img.shields.io/github/stars/Winter3un/cve_2017_0199.svg) ![forks](https://img.shields.io/github/forks/Winter3un/cve_2017_0199.svg)

- [https://github.com/stealth-ronin/CVE-2017-0199-PY-KIT](https://github.com/stealth-ronin/CVE-2017-0199-PY-KIT) :  ![starts](https://img.shields.io/github/stars/stealth-ronin/CVE-2017-0199-PY-KIT.svg) ![forks](https://img.shields.io/github/forks/stealth-ronin/CVE-2017-0199-PY-KIT.svg)

## CVE-2017-0145
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka &quot;Windows SMB Remote Code Execution Vulnerability.&quot; This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0144, CVE-2017-0146, and CVE-2017-0148.



- [https://github.com/peterpt/eternal_scanner](https://github.com/peterpt/eternal_scanner) :  ![starts](https://img.shields.io/github/stars/peterpt/eternal_scanner.svg) ![forks](https://img.shields.io/github/forks/peterpt/eternal_scanner.svg)

- [https://github.com/MelonSmasher/chef_tissues](https://github.com/MelonSmasher/chef_tissues) :  ![starts](https://img.shields.io/github/stars/MelonSmasher/chef_tissues.svg) ![forks](https://img.shields.io/github/forks/MelonSmasher/chef_tissues.svg)

## CVE-2017-0144
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka &quot;Windows SMB Remote Code Execution Vulnerability.&quot; This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.



- [https://github.com/peterpt/eternal_scanner](https://github.com/peterpt/eternal_scanner) :  ![starts](https://img.shields.io/github/stars/peterpt/eternal_scanner.svg) ![forks](https://img.shields.io/github/forks/peterpt/eternal_scanner.svg)

- [https://github.com/Ali-Imangholi/EternalBlueTrojan](https://github.com/Ali-Imangholi/EternalBlueTrojan) :  ![starts](https://img.shields.io/github/stars/Ali-Imangholi/EternalBlueTrojan.svg) ![forks](https://img.shields.io/github/forks/Ali-Imangholi/EternalBlueTrojan.svg)

- [https://github.com/kimocoder/eternalblue](https://github.com/kimocoder/eternalblue) :  ![starts](https://img.shields.io/github/stars/kimocoder/eternalblue.svg) ![forks](https://img.shields.io/github/forks/kimocoder/eternalblue.svg)

- [https://github.com/EEsshq/CVE-2017-0144---EtneralBlue-MS17-010-Remote-Code-Execution](https://github.com/EEsshq/CVE-2017-0144---EtneralBlue-MS17-010-Remote-Code-Execution) :  ![starts](https://img.shields.io/github/stars/EEsshq/CVE-2017-0144---EtneralBlue-MS17-010-Remote-Code-Execution.svg) ![forks](https://img.shields.io/github/forks/EEsshq/CVE-2017-0144---EtneralBlue-MS17-010-Remote-Code-Execution.svg)

## CVE-2017-0143
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka &quot;Windows SMB Remote Code Execution Vulnerability.&quot; This vulnerability is different from those described in CVE-2017-0144, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.



- [https://github.com/valarauco/wannafind](https://github.com/valarauco/wannafind) :  ![starts](https://img.shields.io/github/stars/valarauco/wannafind.svg) ![forks](https://img.shields.io/github/forks/valarauco/wannafind.svg)

- [https://github.com/NatteeSetobol/Etern-blue-Windows-7-Checker](https://github.com/NatteeSetobol/Etern-blue-Windows-7-Checker) :  ![starts](https://img.shields.io/github/stars/NatteeSetobol/Etern-blue-Windows-7-Checker.svg) ![forks](https://img.shields.io/github/forks/NatteeSetobol/Etern-blue-Windows-7-Checker.svg)

- [https://github.com/1nf1n17yk1ng/MS17-010_CVE-2017-0143](https://github.com/1nf1n17yk1ng/MS17-010_CVE-2017-0143) :  ![starts](https://img.shields.io/github/stars/1nf1n17yk1ng/MS17-010_CVE-2017-0143.svg) ![forks](https://img.shields.io/github/forks/1nf1n17yk1ng/MS17-010_CVE-2017-0143.svg)

## CVE-2017-0108
 The Windows Graphics Component in Microsoft Office 2007 SP3; 2010 SP2; and Word Viewer; Skype for Business 2016; Lync 2013 SP1; Lync 2010; Live Meeting 2007; Silverlight 5; Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; and Windows 7 SP1 allows remote attackers to execute arbitrary code via a crafted web site, aka &quot;Graphics Component Remote Code Execution Vulnerability.&quot; This vulnerability is different from that described in CVE-2017-0014.



- [https://github.com/homjxi0e/CVE-2017-0108](https://github.com/homjxi0e/CVE-2017-0108) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-0108.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-0108.svg)

## CVE-2017-0106
 Microsoft Excel 2007 SP3, Microsoft Outlook 2010 SP2, Microsoft Outlook 2013 SP1, and Microsoft Outlook 2016 allow remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted document, aka &quot;Microsoft Office Memory Corruption Vulnerability.&quot;



- [https://github.com/ryhanson/CVE-2017-0106](https://github.com/ryhanson/CVE-2017-0106) :  ![starts](https://img.shields.io/github/stars/ryhanson/CVE-2017-0106.svg) ![forks](https://img.shields.io/github/forks/ryhanson/CVE-2017-0106.svg)

## CVE-2017-0100
 A DCOM object in Helppane.exe in Microsoft Windows 7 SP1; Windows Server 2008 R2; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows local users to gain privileges via a crafted application, aka &quot;Windows HelpPane Elevation of Privilege Vulnerability.&quot;



- [https://github.com/cssxn/CVE-2017-0100](https://github.com/cssxn/CVE-2017-0100) :  ![starts](https://img.shields.io/github/stars/cssxn/CVE-2017-0100.svg) ![forks](https://img.shields.io/github/forks/cssxn/CVE-2017-0100.svg)

## CVE-2017-0075
 Hyper-V in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows guest OS users to execute arbitrary code on the host OS via a crafted application, aka &quot;Hyper-V Remote Code Execution Vulnerability.&quot; This vulnerability is different from that described in CVE-2017-0109.



- [https://github.com/4B5F5F4B/HyperV](https://github.com/4B5F5F4B/HyperV) :  ![starts](https://img.shields.io/github/stars/4B5F5F4B/HyperV.svg) ![forks](https://img.shields.io/github/forks/4B5F5F4B/HyperV.svg)

## CVE-2017-0065
 Microsoft Edge allows remote attackers to obtain sensitive information from process memory via a crafted web site, aka &quot;Microsoft Browser Information Disclosure Vulnerability.&quot; This vulnerability is different from those described in CVE-2017-0009, CVE-2017-0011, CVE-2017-0017, and CVE-2017-0068.



- [https://github.com/Dankirk/cve-2017-0065](https://github.com/Dankirk/cve-2017-0065) :  ![starts](https://img.shields.io/github/stars/Dankirk/cve-2017-0065.svg) ![forks](https://img.shields.io/github/forks/Dankirk/cve-2017-0065.svg)

## CVE-2017-0038
 gdi32.dll in Graphics Device Interface (GDI) in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, and Windows 10 Gold, 1511, and 1607 allows remote attackers to obtain sensitive information from process heap memory via a crafted EMF file, as demonstrated by an EMR_SETDIBITSTODEVICE record with modified Device Independent Bitmap (DIB) dimensions. NOTE: this vulnerability exists because of an incomplete fix for CVE-2016-3216, CVE-2016-3219, and/or CVE-2016-3220.



- [https://github.com/k0keoyo/CVE-2017-0038-EXP-C-JS](https://github.com/k0keoyo/CVE-2017-0038-EXP-C-JS) :  ![starts](https://img.shields.io/github/stars/k0keoyo/CVE-2017-0038-EXP-C-JS.svg) ![forks](https://img.shields.io/github/forks/k0keoyo/CVE-2017-0038-EXP-C-JS.svg)

## CVE-2017-0005
 The Graphics Device Interface (GDI) in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607 allows local users to gain privileges via a crafted application, aka &quot;Windows GDI Elevation of Privilege Vulnerability.&quot; This vulnerability is different from those described in CVE-2017-0001, CVE-2017-0025, and CVE-2017-0047.



- [https://github.com/sheri31/0005poc](https://github.com/sheri31/0005poc) :  ![starts](https://img.shields.io/github/stars/sheri31/0005poc.svg) ![forks](https://img.shields.io/github/forks/sheri31/0005poc.svg)
