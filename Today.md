# Update 2023-01-14
## CVE-2023-23455
 atm_tc_enqueue in net/sched/sch_atm.c in the Linux kernel through 6.1.4 allows attackers to cause a denial of service because of type confusion (non-negative numbers can sometimes indicate a TC_ACT_SHOT condition rather than valid classification results).

- [https://github.com/Live-Hack-CVE/CVE-2023-23455](https://github.com/Live-Hack-CVE/CVE-2023-23455) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23455.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23455.svg)


## CVE-2023-23454
 cbq_classify in net/sched/sch_cbq.c in the Linux kernel through 6.1.4 allows attackers to cause a denial of service (slab-out-of-bounds read) because of type confusion (non-negative numbers can sometimes indicate a TC_ACT_SHOT condition rather than valid classification results).

- [https://github.com/Live-Hack-CVE/CVE-2023-23454](https://github.com/Live-Hack-CVE/CVE-2023-23454) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23454.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23454.svg)


## CVE-2023-22488
 Flarum is a forum software for building communities. Using the notifications feature, one can read restricted/private content and bypass access checks that would be in place for such content. The notification-sending component does not check that the subject of the notification can be seen by the receiver, and proceeds to send notifications through their different channels. The alerts do not leak data despite this as they are listed based on a visibility check, however, emails are still sent out. This means that, for extensions which restrict access to posts, any actor can bypass the restriction by subscribing to the discussion if the Subscriptions extension is enabled. The attack allows the leaking of some posts in the forum database, including posts awaiting approval, posts in tags the user has no access to if they could subscribe to a discussion before it becomes private, and posts restricted by third-party extensions. All Flarum versions prior to v1.6.3 are affected. The vulnerability has been fixed and published as flarum/core v1.6.3. All communities running Flarum should upgrade as soon as possible to v1.6.3. As a workaround, disable the Flarum Subscriptions extension or disable email notifications altogether. There are no other supported workarounds for this issue for Flarum versions below 1.6.3.

- [https://github.com/Live-Hack-CVE/CVE-2023-22488](https://github.com/Live-Hack-CVE/CVE-2023-22488) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22488.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22488.svg)


## CVE-2023-22477
 Mercurius is a GraphQL adapter for Fastify. Any users of Mercurius until version 10.5.0 are subjected to a denial of service attack by sending a malformed packet over WebSocket to `/graphql`. This issue was patched in #940. As a workaround, users can disable subscriptions.

- [https://github.com/Live-Hack-CVE/CVE-2023-22477](https://github.com/Live-Hack-CVE/CVE-2023-22477) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22477.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22477.svg)


## CVE-2023-22417
 A Missing Release of Memory after Effective Lifetime vulnerability in the Flow Processing Daemon (flowd) of Juniper Networks Junos OS allows a network-based, unauthenticated attacker to cause a Denial of Service (DoS). In an IPsec VPN environment, a memory leak will be seen if a DH or ECDH group is configured. Eventually the flowd process will crash and restart. This issue affects Juniper Networks Junos OS on SRX Series: All versions prior to 19.3R3-S7; 19.4 versions prior to 19.4R2-S8, 19.4R3-S10; 20.2 versions prior to 20.2R3-S6; 20.3 versions prior to 20.3R3-S5; 20.4 versions prior to 20.4R3-S5; 21.1 versions prior to 21.1R3-S4; 21.2 versions prior to 21.2R3; 21.3 versions prior to 21.3R3; 21.4 versions prior to 21.4R2.

- [https://github.com/Live-Hack-CVE/CVE-2023-22417](https://github.com/Live-Hack-CVE/CVE-2023-22417) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22417.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22417.svg)


## CVE-2023-22416
 A Buffer Overflow vulnerability in SIP ALG of Juniper Networks Junos OS allows a network-based, unauthenticated attacker to cause a Denial of Service (DoS). On all MX Series and SRX Series platform with SIP ALG enabled, when a malformed SIP packet is received, the flow processing daemon (flowd) will crash and restart. This issue affects: Juniper Networks Junos OS on MX Series and SRX Series 20.4 versions prior to 20.4R3-S5; 21.1 versions prior to 21.1R3-S4; 21.2 versions prior to 21.2R3-S2; 21.3 versions prior to 21.3R3-S1; 21.4 versions prior to 21.4R3; 22.1 versions prior to 22.1R1-S2, 22.1R2; 22.2 versions prior to 22.2R1-S1, 22.2R2. This issue does not affect Juniper Networks Junos OS versions prior to 20.4R1 on SRX Series.

- [https://github.com/Live-Hack-CVE/CVE-2023-22416](https://github.com/Live-Hack-CVE/CVE-2023-22416) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22416.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22416.svg)


## CVE-2023-22415
 An Out-of-Bounds Write vulnerability in the H.323 ALG of Juniper Networks Junos OS allows an unauthenticated, network-based attacker to cause Denial of Service (DoS). On all MX Series and SRX Series platform, when H.323 ALG is enabled and specific H.323 packets are received simultaneously, a flow processing daemon (flowd) crash will occur. Continued receipt of these specific packets will cause a sustained Denial of Service (DoS) condition. This issue affects: Juniper Networks Junos OS on MX Series and SRX Series All versions prior to 19.4R3-S10; 20.2 versions prior to 20.2R3-S6; 20.3 versions prior to 20.3R3-S6; 20.4 versions prior to 20.4R3-S5; 21.1 versions prior to 21.1R3-S4; 21.2 versions prior to 21.2R3-S3; 21.3 versions prior to 21.3R3-S3; 21.4 versions prior to 21.4R3; 22.1 versions prior to 22.1R2-S1, 22.1R3; 22.2 versions prior to 22.2R1-S2, 22.2R2.

- [https://github.com/Live-Hack-CVE/CVE-2023-22415](https://github.com/Live-Hack-CVE/CVE-2023-22415) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22415.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22415.svg)


## CVE-2023-22414
 A Missing Release of Memory after Effective Lifetime vulnerability in Flexible PIC Concentrator (FPC) of Juniper Networks Junos OS allows an adjacent, unauthenticated attacker from the same shared physical or logical network, to cause a heap memory leak and leading to FPC crash. On all Junos PTX Series and QFX10000 Series, when specific EVPN VXLAN Multicast packets are processed, an FPC heap memory leak is observed. The FPC memory usage can be monitored using the CLI command &quot;show heap extensive&quot;. Following is an example output. ID Base Total(b) Free(b) Used(b) % Name Peak used % -- -------- --------- --------- --------- --- ----------- ----------- 0 37dcf000 3221225472 1694526368 1526699104 47 Kernel 47 1 17dcf000 1048576 1048576 0 0 TOE DMA 0 2 17ecf000 1048576 1048576 0 0 DMA 0 3 17fcf000 534773760 280968336 253805424 47 Packet DMA 47 This issue affects: Juniper Networks Junos OS PTX Series and QFX10000 Series 20.2 versions prior to 20.2R3-S6; 20.3 versions prior to 20.3R3-S6; 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S3; 21.2 versions prior to 21.2R3-S1; 21.3 versions prior to 21.3R3; 21.4 versions prior to 21.4R3; 22.1 versions prior to 22.1R2; 22.2 versions prior to 22.2R2. This issue does not affect Juniper Networks Junos OS versions prior to 20.1R1 on PTX Series and QFX10000 Series.

- [https://github.com/Live-Hack-CVE/CVE-2023-22414](https://github.com/Live-Hack-CVE/CVE-2023-22414) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22414.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22414.svg)


## CVE-2023-22413
 An Improper Check or Handling of Exceptional Conditions vulnerability in the IPsec library of Juniper Networks Junos OS allows a network-based, unauthenticated attacker to cause Denial of Service (DoS). On all MX platforms with MS-MPC or MS-MIC card, when specific IPv4 packets are processed by an IPsec6 tunnel, the Multiservices PIC Management Daemon (mspmand) process will core and restart. This will lead to FPC crash. Traffic flow is impacted while mspmand restarts. Continued receipt of these specific packets will cause a sustained Denial of Service (DoS) condition. This issue only occurs if an IPv4 address is not configured on the multiservice interface. This issue affects: Juniper Networks Junos OS on MX Series All versions prior to 19.4R3-S9; 20.1 version 20.1R3-S5 and later versions; 20.2 versions prior to 20.2R3-S5; 20.3 versions prior to 20.3R3-S5; 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S3; 21.2 versions prior to 21.2R3-S1; 21.3 versions prior to 21.3R3; 21.4 versions prior to 21.4R2-S1, 21.4R3; 22.1 versions prior to 22.1R2.

- [https://github.com/Live-Hack-CVE/CVE-2023-22413](https://github.com/Live-Hack-CVE/CVE-2023-22413) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22413.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22413.svg)


## CVE-2023-22412
 An Improper Locking vulnerability in the SIP ALG of Juniper Networks Junos OS on MX Series with MS-MPC or MS-MIC card and SRX Series allows an unauthenticated, network-based attacker to cause a flow processing daemon (flowd) crash and thereby a Denial of Service (DoS). Continued receipt of these specific packets will cause a sustained Denial of Service condition. This issue occurs when SIP ALG is enabled and specific SIP messages are processed simultaneously. This issue affects: Juniper Networks Junos OS on MX Series and SRX Series 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S3; 21.2 versions prior to 21.2R3-S2; 21.3 versions prior to 21.3R3; 21.4 versions prior to 21.4R3; 22.1 versions prior to 22.1R2. This issue does not affect Juniper Networks Junos OS versions prior to 20.4R1 on MX Series, or SRX Series.

- [https://github.com/Live-Hack-CVE/CVE-2023-22412](https://github.com/Live-Hack-CVE/CVE-2023-22412) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22412.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22412.svg)


## CVE-2023-22411
 An Out-of-Bounds Write vulnerability in Flow Processing Daemon (flowd) of Juniper Networks Junos OS allows an unauthenticated, network-based attacker to cause Denial of Service (DoS). On SRX Series devices using Unified Policies with IPv6, when a specific IPv6 packet goes through a dynamic-application filter which will generate an ICMP deny message, the flowd core is observed and the PFE is restarted. This issue affects: Juniper Networks Junos OS on SRX Series: 19.2 versions prior to 19.2R3-S6; 19.3 versions prior to 19.3R3-S6; 19.4 versions prior to 19.4R3-S9; 20.2 versions prior to 20.2R3-S5; 20.3 versions prior to 20.3R3-S4; 20.4 versions prior to 20.4R3-S3; 21.1 versions prior to 21.1R3; 21.2 versions prior to 21.2R3; 21.3 versions prior to 21.3R2; 21.4 versions prior to 21.4R2.

- [https://github.com/Live-Hack-CVE/CVE-2023-22411](https://github.com/Live-Hack-CVE/CVE-2023-22411) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22411.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22411.svg)


## CVE-2023-22410
 A Missing Release of Memory after Effective Lifetime vulnerability in the Juniper Networks Junos OS on MX Series platforms with MPC10/MPC11 line cards, allows an unauthenticated adjacent attacker to cause a Denial of Service (DoS). Devices are only vulnerable when the Suspicious Control Flow Detection (scfd) feature is enabled. Upon enabling this specific feature, an attacker sending specific traffic is causing memory to be allocated dynamically and it is not freed. Memory is not freed even after deactivating this feature. Sustained processing of such traffic will eventually lead to an out of memory condition that prevents all services from continuing to function, and requires a manual restart to recover. The FPC memory usage can be monitored using the CLI command &quot;show chassis fpc&quot;. On running the above command, the memory of AftDdosScfdFlow can be observed to detect the memory leak. This issue affects Juniper Networks Junos OS on MX Series: All versions prior to 20.2R3-S5; 20.3 version 20.3R1 and later versions.

- [https://github.com/Live-Hack-CVE/CVE-2023-22410](https://github.com/Live-Hack-CVE/CVE-2023-22410) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22410.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22410.svg)


## CVE-2023-22409
 An Unchecked Input for Loop Condition vulnerability in a NAT library of Juniper Networks Junos OS allows a local authenticated attacker with low privileges to cause a Denial of Service (DoS). When an inconsistent &quot;deterministic NAT&quot; configuration is present on an SRX, or MX with SPC3 and then a specific CLI command is issued the SPC will crash and restart. Repeated execution of this command will lead to a sustained DoS. Such a configuration is characterized by the total number of port blocks being greater than the total number of hosts. An example for such configuration is: [ services nat source pool TEST-POOL address x.x.x.0/32 to x.x.x.15/32 ] [ services nat source pool TEST-POOL port deterministic block-size 1008 ] [ services nat source pool TEST-POOL port deterministic host address y.y.y.0/24] [ services nat source pool TEST-POOL port deterministic include-boundary-addresses] where according to the following calculation: 65536-1024=64512 (number of usable ports per IP address, implicit) 64512/1008=64 (number of port blocks per Nat IP) x.x.x.0/32 to x.x.x.15/32 = 16 (NAT IP addresses available in NAT pool) total port blocks in NAT Pool = 64 blocks per IP * 16 IPs = 1024 Port blocks host address y.y.y.0/24 = 256 hosts (with include-boundary-addresses) If the port block size is configured to be 4032, then the total port blocks are (64512/4032) * 16 = 256 which is equivalent to the total host addresses of 256, and the issue will not be seen. This issue affects Juniper Networks Junos OS on SRX Series, and MX Series with SPC3: All versions prior to 19.4R3-S10; 20.1 version 20.1R1 and later versions; 20.2 versions prior to 20.2R3-S6; 20.3 versions prior to 20.3R3-S6; 20.4 versions prior to 20.4R3-S5; 21.1 versions prior to 21.1R3-S4; 21.2 versions prior to 21.2R3-S3; 21.3 versions prior to 21.3R3-S3; 21.4 versions prior to 21.4R3-S1; 22.1 versions prior to 22.1R2-S2, 22.1R3; 22.2 versions prior to 22.2R2.

- [https://github.com/Live-Hack-CVE/CVE-2023-22409](https://github.com/Live-Hack-CVE/CVE-2023-22409) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22409.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22409.svg)


## CVE-2023-22408
 An Improper Validation of Array Index vulnerability in the SIP ALG of Juniper Networks Junos OS on SRX 5000 Series allows a network-based, unauthenticated attacker to cause a Denial of Service (DoS). When an attacker sends an SIP packets with a malformed SDP field then the SIP ALG can not process it which will lead to an FPC crash and restart. Continued receipt of these specific packets will lead to a sustained Denial of Service. This issue can only occur when both below mentioned conditions are fulfilled: 1. Call distribution needs to be enabled: [security alg sip enable-call-distribution] 2. The SIP ALG needs to be enabled, either implicitly / by default or by way of configuration. To confirm whether SIP ALG is enabled on SRX, and MX with SPC3 use the following command: user@host&gt; show security alg status | match sip SIP : Enabled This issue affects Juniper Networks Junos OS on SRX 5000 Series: 20.4 versions prior to 20.4R3-S5; 21.1 versions prior to 21.1R3-S4; 21.2 versions prior to 21.2R3-S3; 21.3 versions prior to 21.3R3-S3; 21.4 versions prior to 21.4R3-S2; 22.1 versions prior to 22.1R2-S2, 22.1R3; 22.2 versions prior to 22.2R3; 22.3 versions prior to 22.3R1-S1, 22.3R2. This issue does not affect Juniper Networks Junos OS versions prior to 20.4R1.

- [https://github.com/Live-Hack-CVE/CVE-2023-22408](https://github.com/Live-Hack-CVE/CVE-2023-22408) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22408.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22408.svg)


## CVE-2023-22407
 An Incomplete Cleanup vulnerability in the Routing Protocol Daemon (rpd) of Juniper Networks Junos OS and Junos OS Evolved allows an adjacent, unauthenticated attacker to cause a Denial of Service (DoS). An rpd crash can occur when an MPLS TE tunnel configuration change occurs on a directly connected router. This issue affects: Juniper Networks Junos OS All versions prior to 18.4R2-S7; 19.1 versions prior to 19.1R3-S2; 19.2 versions prior to 19.2R3; 19.3 versions prior to 19.3R3; 19.4 versions prior to 19.4R3; 20.1 versions prior to 20.1R2; 20.2 versions prior to 20.2R2. Juniper Networks Junos OS Evolved All versions prior to 19.2R3-EVO; 19.3 versions prior to 19.3R3-EVO; 19.4 versions prior to 19.4R3-EVO; 20.1 versions prior to 20.1R3-EVO; 20.2 versions prior to 20.2R2-EVO.

- [https://github.com/Live-Hack-CVE/CVE-2023-22407](https://github.com/Live-Hack-CVE/CVE-2023-22407) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22407.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22407.svg)


## CVE-2023-22406
 A Missing Release of Memory after Effective Lifetime vulnerability in the kernel of Juniper Networks Junos OS and Junos OS Evolved allows an adjacent, unauthenticated attacker to cause a Denial of Service (DoS). In a segment-routing scenario with OSPF as IGP, when a peer interface continuously flaps, next-hop churn will happen and a continuous increase in Routing Protocol Daemon (rpd) memory consumption will be observed. This will eventually lead to an rpd crash and restart when the memory is full. The memory consumption can be monitored using the CLI command &quot;show task memory detail&quot; as shown in the following example: user@host&gt; show task memory detail | match &quot;RT_NEXTHOPS_TEMPLATE|RT_TEMPLATE_BOOK_KEE&quot; RT_NEXTHOPS_TEMPLATE 1008 1024 T 50 51200 50 51200 RT_NEXTHOPS_TEMPLATE 688 768 T 50 38400 50 38400 RT_NEXTHOPS_TEMPLATE 368 384 T 412330 158334720 412330 158334720 RT_TEMPLATE_BOOK_KEE 2064 2560 T 33315 85286400 33315 85286400 user@host&gt; show task memory detail | match &quot;RT_NEXTHOPS_TEMPLATE|RT_TEMPLATE_BOOK_KEE&quot; RT_NEXTHOPS_TEMPLATE 1008 1024 T 50 51200 50 51200 RT_NEXTHOPS_TEMPLATE 688 768 T 50 38400 50 38400 RT_NEXTHOPS_TEMPLATE 368 384 T 419005 160897920 419005 160897920 &lt;=== RT_TEMPLATE_BOOK_KEE 2064 2560 T 39975 102336000 39975 10233600 &lt;=== This issue affects: Juniper Networks Junos OS All versions prior to 19.3R3-S7; 19.4 versions prior to 19.4R2-S8, 19.4R3-S9; 20.2 versions prior to 20.2R3-S5; 20.3 versions prior to 20.3R3-S5; 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S3; 21.2 versions prior to 21.2R3-S2; 21.3 versions prior to 21.3R3-S1; 21.4 versions prior to 21.4R2-S1, 21.4R3; 22.1 versions prior to 22.1R2. Juniper Networks Junos OS Evolved All versions prior to 20.4R3-S4-EVO; 21.4 versions prior to 21.4R2-S1-EVO, 21.4R3-EVO; 22.1 versions prior to 22.1R2-EVO.

- [https://github.com/Live-Hack-CVE/CVE-2023-22406](https://github.com/Live-Hack-CVE/CVE-2023-22406) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22406.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22406.svg)


## CVE-2023-22405
 An Improper Preservation of Consistency Between Independent Representations of Shared State vulnerability in the Packet Forwarding Engine (PFE) of Juniper Networks Junos OS allows an adjacent, unauthenticated attacker to cause a Denial of Service (DoS) to device due to out of resources. When a device is configured with &quot;service-provider/SP style&quot; switching, and mac-limiting is configured on an Aggregated Ethernet (ae) interface, and then a PFE is restarted or the device is rebooted, mac-limiting doesn't work anymore. Please note that the issue might not be apparent as traffic will continue to flow through the device although the mac table and respective logs will indicate that mac limit is reached. Functionality can be restored by removing and re-adding the MAC limit configuration. This issue affects Juniper Networks Junos OS on QFX5k Series, EX46xx Series: All versions prior to 20.2R3-S5; 20.3 versions prior to 20.3R3-S5; 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S3; 21.2 versions prior to 21.2R3-S1; 21.3 versions prior to 21.3R3 on; 21.4 versions prior to 21.4R3 on; 22.1 versions prior to 22.1R2 on.

- [https://github.com/Live-Hack-CVE/CVE-2023-22405](https://github.com/Live-Hack-CVE/CVE-2023-22405) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22405.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22405.svg)


## CVE-2023-22404
 An Out-of-bounds Write vulnerability in the Internet Key Exchange Protocol daemon (iked) of Juniper Networks Junos OS on SRX series and MX with SPC3 allows an authenticated, network-based attacker to cause a Denial of Service (DoS). iked will crash and restart, and the tunnel will not come up when a peer sends a specifically formatted payload during the negotiation. This will impact other IKE negotiations happening at the same time. Continued receipt of this specifically formatted payload will lead to continuous crashing of iked and thereby the inability for any IKE negotiations to take place. Note that this payload is only processed after the authentication has successfully completed. So the issue can only be exploited by an attacker who can successfully authenticate. This issue affects Juniper Networks Junos OS on SRX Series, and MX Series with SPC3: All versions prior to 19.3R3-S7; 19.4 versions prior to 19.4R3-S9; 20.2 versions prior to 20.2R3-S5; 20.3 versions prior to 20.3R3-S5; 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S3; 21.2 versions prior to 21.2R3-S2; 21.3 versions prior to 21.3R3-S1; 21.4 versions prior to 21.4R2-S1, 21.4R3; 22.1 versions prior to 22.1R1-S2, 22.1R2.

- [https://github.com/Live-Hack-CVE/CVE-2023-22404](https://github.com/Live-Hack-CVE/CVE-2023-22404) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22404.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22404.svg)


## CVE-2023-22403
 An Allocation of Resources Without Limits or Throttling vulnerability in the Packet Forwarding Engine (PFE) of Juniper Networks Junos OS allows a network-based, unauthenticated attacker to cause a Denial of Service (DoS). On QFX10k Series Inter-Chassis Control Protocol (ICCP) is used in MC-LAG topologies to exchange control information between the devices in the topology. ICCP connection flaps and sync issues will be observed due to excessive specific traffic to the local device. This issue affects Juniper Networks Junos OS: All versions prior to 20.2R3-S7; 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S3; 21.2 versions prior to 21.2R3-S1; 21.3 versions prior to 21.3R3; 21.4 versions prior to 21.4R3; 22.1 versions prior to 22.1R2.

- [https://github.com/Live-Hack-CVE/CVE-2023-22403](https://github.com/Live-Hack-CVE/CVE-2023-22403) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22403.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22403.svg)


## CVE-2023-22402
 A Use After Free vulnerability in the kernel of Juniper Networks Junos OS Evolved allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS). In a Non Stop Routing (NSR) scenario, an unexpected kernel restart might be observed if &quot;bgp auto-discovery&quot; is enabled and if there is a BGP neighbor flap of auto-discovery sessions for any reason. This is a race condition which is outside of an attackers direct control and it depends on system internal timing whether this issue occurs. This issue affects Juniper Networks Junos OS Evolved: 21.3 versions prior to 21.3R3-EVO; 21.4 versions prior to 21.4R2-EVO; 22.1 versions prior to 22.1R2-EVO; 22.2 versions prior to 22.2R1-S1-EVO, 22.2R2-EVO.

- [https://github.com/Live-Hack-CVE/CVE-2023-22402](https://github.com/Live-Hack-CVE/CVE-2023-22402) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22402.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22402.svg)


## CVE-2023-22401
 An Improper Validation of Array Index vulnerability in the Advanced Forwarding Toolkit Manager daemon (aftmand) of Juniper Networks Junos OS and Junos OS Evolved allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS). On the PTX10008 and PTX10016 platforms running Junos OS or Junos OS Evolved, when a specific SNMP MIB is queried this will cause a PFE crash and the FPC will go offline and not automatically recover. A system restart is required to get the affected FPC in an operational state again. This issue affects: Juniper Networks Junos OS 22.1 version 22.1R2 and later versions; 22.1 versions prior to 22.1R3; 22.2 versions prior to 22.2R2. Juniper Networks Junos OS Evolved 21.3-EVO version 21.3R3-EVO and later versions; 21.4-EVO version 21.4R1-S2-EVO, 21.4R2-EVO and later versions prior to 21.4R2-S1-EVO; 22.1-EVO version 22.1R2-EVO and later versions prior to 22.1R3-EVO; 22.2-EVO versions prior to 22.2R1-S1-EVO, 22.2R2-EVO.

- [https://github.com/Live-Hack-CVE/CVE-2023-22401](https://github.com/Live-Hack-CVE/CVE-2023-22401) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22401.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22401.svg)


## CVE-2023-22400
 An Uncontrolled Resource Consumption vulnerability in the PFE management daemon (evo-pfemand) of Juniper Networks Junos OS Evolved allows an unauthenticated, network-based attacker to cause an FPC crash leading to a Denial of Service (DoS). When a specific SNMP GET operation or a specific CLI command is executed this will cause a GUID resource leak, eventually leading to exhaustion and result in an FPC crash and reboot. GUID exhaustion will trigger a syslog message like one of the following for example: evo-pfemand[&lt;pid&gt;]: get_next_guid: Ran out of Guid Space ... evo-aftmand-zx[&lt;pid&gt;]: get_next_guid: Ran out of Guid Space ... This leak can be monitored by running the following command and taking note of the value in the rightmost column labeled Guids: user@host&gt; show platform application-info allocations app evo-pfemand | match &quot;IFDId|IFLId|Context&quot; Node Application Context Name Live Allocs Fails Guids re0 evo-pfemand net::juniper::interfaces::IFDId 0 3448 0 3448 re0 evo-pfemand net::juniper::interfaces::IFLId 0 561 0 561 user@host&gt; show platform application-info allocations app evo-pfemand | match &quot;IFDId|IFLId|Context&quot; Node Application Context Name Live Allocs Fails Guids re0 evo-pfemand net::juniper::interfaces::IFDId 0 3784 0 3784 re0 evo-pfemand net::juniper::interfaces::IFLId 0 647 0 647 This issue affects Juniper Networks Junos OS Evolved: All versions prior to 20.4R3-S3-EVO; 21.1-EVO version 21.1R1-EVO and later versions; 21.2-EVO versions prior to 21.2R3-S4-EVO; 21.3-EVO version 21.3R1-EVO and later versions; 21.4-EVO versions prior to 21.4R2-EVO.

- [https://github.com/Live-Hack-CVE/CVE-2023-22400](https://github.com/Live-Hack-CVE/CVE-2023-22400) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22400.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22400.svg)


## CVE-2023-22399
 When sFlow is enabled and it monitors a packet forwarded via ECMP, a buffer management vulnerability in the dcpfe process of Juniper Networks Junos OS on QFX10K Series systems allows an attacker to cause the Packet Forwarding Engine (PFE) to crash and restart by sending specific genuine packets to the device, resulting in a Denial of Service (DoS) condition. The dcpfe process tries to copy more data into a smaller buffer, which overflows and corrupts the buffer, causing a crash of the dcpfe process. Continued receipt and processing of these packets will create a sustained Denial of Service (DoS) condition. This issue affects Juniper Networks Junos OS on QFX10K Series: All versions prior to 19.4R3-S9; 20.2 versions prior to 20.2R3-S6; 20.3 versions prior to 20.3R3-S6; 20.4 versions prior to 20.4R3-S5; 21.1 versions prior to 21.1R3-S4; 21.2 versions prior to 21.2R3-S3; 21.3 versions prior to 21.3R3-S2; 21.4 versions prior to 21.4R2-S2, 21.4R3; 22.1 versions prior to 22.1R2; 22.2 versions prior to 22.2R1-S2, 22.2R2.

- [https://github.com/Live-Hack-CVE/CVE-2023-22399](https://github.com/Live-Hack-CVE/CVE-2023-22399) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22399.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22399.svg)


## CVE-2023-22397
 An Allocation of Resources Without Limits or Throttling weakness in the memory management of the Packet Forwarding Engine (PFE) on Juniper Networks Junos OS Evolved PTX10003 Series devices allows an adjacently located attacker who has established certain preconditions and knowledge of the environment to send certain specific genuine packets to begin a Time-of-check Time-of-use (TOCTOU) Race Condition attack which will cause a memory leak to begin. Once this condition begins, and as long as the attacker is able to sustain the offending traffic, a Distributed Denial of Service (DDoS) event occurs. As a DDoS event, the offending packets sent by the attacker will continue to flow from one device to another as long as they are received and processed by any devices, ultimately causing a cascading outage to any vulnerable devices. Devices not vulnerable to the memory leak will process and forward the offending packet(s) to neighboring devices. Due to internal anti-flood security controls and mechanisms reaching their maximum limit of response in the worst-case scenario, all affected Junos OS Evolved devices will reboot in as little as 1.5 days. Reboots to restore services cannot be avoided once the memory leak begins. The device will self-recover after crashing and rebooting. Operator intervention isn't required to restart the device. This issue affects: Juniper Networks Junos OS Evolved on PTX10003: All versions prior to 20.4R3-S4-EVO; 21.3 versions prior to 21.3R3-S1-EVO; 21.4 versions prior to 21.4R2-S2-EVO, 21.4R3-EVO; 22.1 versions prior to 22.1R1-S2-EVO, 22.1R2-EVO; 22.2 versions prior to 22.2R2-EVO. To check memory, customers may VTY to the PFE first then execute the following show statement: show jexpr jtm ingress-main-memory chip 255 | no-more Alternatively one may execute from the RE CLI: request pfe execute target fpc0 command &quot;show jexpr jtm ingress-main-memory chip 255 | no-more&quot; Iteration 1: Example output: Mem type: NH, alloc type: JTM 136776 bytes used (max 138216 bytes used) 911568 bytes available (909312 bytes from free pages) Iteration 2: Example output: Mem type: NH, alloc type: JTM 137288 bytes used (max 138216 bytes used) 911056 bytes available (909312 bytes from free pages) The same can be seen in the CLI below, assuming the scale does not change: show npu memory info Example output: FPC0:NPU16 mem-util-jnh-nh-size 2097152 FPC0:NPU16 mem-util-jnh-nh-allocated 135272 FPC0:NPU16 mem-util-jnh-nh-utilization 6

- [https://github.com/Live-Hack-CVE/CVE-2023-22397](https://github.com/Live-Hack-CVE/CVE-2023-22397) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22397.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22397.svg)


## CVE-2023-22395
 A Missing Release of Memory after Effective Lifetime vulnerability in the kernel of Juniper Networks Junos OS allows an unauthenticated, adjacent attacker to cause a Denial of Service (DoS). In an MPLS scenario specific packets destined to an Integrated Routing and Bridging (irb) interface of the device will cause a buffer (mbuf) to leak. Continued receipt of these specific packets will eventually cause a loss of connectivity to and from the device, and requires a reboot to recover. These mbufs can be monitored by using the CLI command 'show system buffers': user@host&gt; show system buffers 783/1497/2280 mbufs in use (current/cache/total) user@host&gt; show system buffers 793/1487/2280 mbufs in use (current/cache/total) &lt;&lt;&lt;&lt;&lt;&lt; mbuf usage increased This issue affects Juniper Networks Junos OS: All versions prior to 19.3R3-S7; 19.4 versions prior to 19.4R3-S9; 20.1 version 20.1R1 and later versions; 20.2 versions prior to 20.2R3-S5; 20.3 versions prior to 20.3R3-S5; 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S3; 21.2 versions prior to 21.2R3-S2; 21.3 versions prior to 21.3R3-S1; 21.4 versions prior to 21.4R3; 22.1 versions prior to 22.1R2.

- [https://github.com/Live-Hack-CVE/CVE-2023-22395](https://github.com/Live-Hack-CVE/CVE-2023-22395) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22395.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22395.svg)


## CVE-2023-0258
 A vulnerability was found in SourceCodester Online Food Ordering System 2.0. It has been rated as problematic. Affected by this issue is some unknown functionality of the component Category List Handler. The manipulation of the argument Reason with the input &quot;&gt;&lt;script&gt;prompt(1)&lt;/script&gt; leads to cross site scripting. The attack may be launched remotely. VDB-218186 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2023-0258](https://github.com/Live-Hack-CVE/CVE-2023-0258) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0258.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0258.svg)


## CVE-2023-0257
 A vulnerability was found in SourceCodester Online Food Ordering System 2.0. It has been declared as critical. Affected by this vulnerability is an unknown functionality of the file /fos/admin/index.php?page=menu of the component Menu Form. The manipulation of the argument Image with the input &lt;?php system($_GET['c']); ?&gt; leads to unrestricted upload. The attack can be launched remotely. The identifier VDB-218185 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2023-0257](https://github.com/Live-Hack-CVE/CVE-2023-0257) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0257.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0257.svg)


## CVE-2023-0256
 A vulnerability was found in SourceCodester Online Food Ordering System 2.0. It has been classified as critical. Affected is an unknown function of the file /fos/admin/ajax.php?action=login of the component Login Page. The manipulation of the argument Username leads to sql injection. It is possible to launch the attack remotely. The identifier of this vulnerability is VDB-218184.

- [https://github.com/Live-Hack-CVE/CVE-2023-0256](https://github.com/Live-Hack-CVE/CVE-2023-0256) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0256.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0256.svg)


## CVE-2023-0254
 The Simple Membership WP user Import plugin for WordPress is vulnerable to SQL Injection via the &#8216;orderby&#8217; parameter in versions up to, and including, 1.7 due to insufficient escaping on the user supplied parameter. This makes it possible for authenticated attackers with administrative privileges to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/Live-Hack-CVE/CVE-2023-0254](https://github.com/Live-Hack-CVE/CVE-2023-0254) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0254.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0254.svg)


## CVE-2023-0247
 Uncontrolled Search Path Element in GitHub repository bits-and-blooms/bloom prior to 3.3.1.

- [https://github.com/Live-Hack-CVE/CVE-2023-0247](https://github.com/Live-Hack-CVE/CVE-2023-0247) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0247.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0247.svg)


## CVE-2023-0042
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 11.4 prior to 15.5.7, 15.6 prior to 15.6.4, and 15.7 prior to 15.7.2. GitLab Pages allows redirection to arbitrary protocols.

- [https://github.com/Live-Hack-CVE/CVE-2023-0042](https://github.com/Live-Hack-CVE/CVE-2023-0042) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0042.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0042.svg)


## CVE-2022-48258
 In Eternal Terminal 6.2.1, etserver and etclient have world-readable logfiles.

- [https://github.com/Live-Hack-CVE/CVE-2022-48258](https://github.com/Live-Hack-CVE/CVE-2022-48258) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48258.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48258.svg)


## CVE-2022-48257
 In Eternal Terminal 6.2.1, etserver and etclient have predictable logfile names in /tmp.

- [https://github.com/Live-Hack-CVE/CVE-2022-48257](https://github.com/Live-Hack-CVE/CVE-2022-48257) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48257.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48257.svg)


## CVE-2022-48256
 Technitium DNS Server before 10.0 allows a self-CNAME denial-of-service attack in which a CNAME loop causes an answer to contain hundreds of records.

- [https://github.com/Live-Hack-CVE/CVE-2022-48256](https://github.com/Live-Hack-CVE/CVE-2022-48256) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48256.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48256.svg)


## CVE-2022-47974
 The Bluetooth AVRCP module has a vulnerability that can lead to DoS attacks.Successful exploitation of this vulnerability may cause the Bluetooth process to restart.

- [https://github.com/Live-Hack-CVE/CVE-2022-47974](https://github.com/Live-Hack-CVE/CVE-2022-47974) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47974.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47974.svg)


## CVE-2022-47927
 An issue was discovered in MediaWiki before 1.35.9, 1.36.x through 1.38.x before 1.38.5, and 1.39.x before 1.39.1. When installing with a pre-existing data directory that has weak permissions, the SQLite files are created with file mode 0644, i.e., world readable to local users. These files include credentials data.

- [https://github.com/Live-Hack-CVE/CVE-2022-47927](https://github.com/Live-Hack-CVE/CVE-2022-47927) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47927.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47927.svg)


## CVE-2022-47544
 An issue was discovered in Siren Investigate before 12.1.7. Script variable whitelisting is insufficiently sandboxed.

- [https://github.com/Live-Hack-CVE/CVE-2022-47544](https://github.com/Live-Hack-CVE/CVE-2022-47544) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47544.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47544.svg)


## CVE-2022-47543
 An issue was discovered in Siren Investigate before 12.1.7. There is an ACL bypass on global objects.

- [https://github.com/Live-Hack-CVE/CVE-2022-47543](https://github.com/Live-Hack-CVE/CVE-2022-47543) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47543.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47543.svg)


## CVE-2022-47102
 A cross-site scripting (XSS) vulnerability in Student Study Center Management System V 1.0 allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the name parameter.

- [https://github.com/Live-Hack-CVE/CVE-2022-47102](https://github.com/Live-Hack-CVE/CVE-2022-47102) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47102.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47102.svg)


## CVE-2022-46762
 The memory management module has a logic bypass vulnerability.Successful exploitation of this vulnerability may affect data confidentiality.

- [https://github.com/Live-Hack-CVE/CVE-2022-46762](https://github.com/Live-Hack-CVE/CVE-2022-46762) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46762.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46762.svg)


## CVE-2022-46761
 The system has a vulnerability that may cause dynamic hiding and restoring of app icons.Successful exploitation of this vulnerability may cause malicious hiding of app icons.

- [https://github.com/Live-Hack-CVE/CVE-2022-46761](https://github.com/Live-Hack-CVE/CVE-2022-46761) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46761.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46761.svg)


## CVE-2022-46689
 A race condition was addressed with additional validation. This issue is fixed in tvOS 16.2, macOS Monterey 12.6.2, macOS Ventura 13.1, macOS Big Sur 11.7.2, iOS 15.7.2 and iPadOS 15.7.2, iOS 16.2 and iPadOS 16.2, watchOS 9.2. An app may be able to execute arbitrary code with kernel privileges.

- [https://github.com/BomberFish/Mandela](https://github.com/BomberFish/Mandela) :  ![starts](https://img.shields.io/github/stars/BomberFish/Mandela.svg) ![forks](https://img.shields.io/github/forks/BomberFish/Mandela.svg)


## CVE-2022-46623
 Judging Management System v1.0.0 was discovered to contain a SQL injection vulnerability via the username parameter.

- [https://github.com/Live-Hack-CVE/CVE-2022-46623](https://github.com/Live-Hack-CVE/CVE-2022-46623) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46623.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46623.svg)


## CVE-2022-46622
 A cross-site scripting (XSS) vulnerability in Judging Management System v1.0 allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the firstname parameter.

- [https://github.com/Live-Hack-CVE/CVE-2022-46622](https://github.com/Live-Hack-CVE/CVE-2022-46622) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46622.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46622.svg)


## CVE-2022-46505
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/SmallTown123/details-for-CVE-2022-46505](https://github.com/SmallTown123/details-for-CVE-2022-46505) :  ![starts](https://img.shields.io/github/stars/SmallTown123/details-for-CVE-2022-46505.svg) ![forks](https://img.shields.io/github/forks/SmallTown123/details-for-CVE-2022-46505.svg)


## CVE-2022-46502
 Online Student Enrollment System v1.0 was discovered to contain a SQL injection vulnerability via the username parameter at /student_enrollment/admin/login.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-46502](https://github.com/Live-Hack-CVE/CVE-2022-46502) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46502.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46502.svg)


## CVE-2022-46478
 The RPC interface in datax-web v1.0.0 and v2.0.0 to v2.1.2 contains no permission checks by default which allows attackers to execute arbitrary commands via crafted Hessian serialized data.

- [https://github.com/Live-Hack-CVE/CVE-2022-46478](https://github.com/Live-Hack-CVE/CVE-2022-46478) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46478.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46478.svg)


## CVE-2022-46471
 Online Health Care System v1.0 was discovered to contain a SQL injection vulnerability via the consulting_id parameter at /healthcare/Admin/consulting_detail.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-46471](https://github.com/Live-Hack-CVE/CVE-2022-46471) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46471.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46471.svg)


## CVE-2022-46169
 Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/Anthonyc3rb3ru5/CVE-2022-46169](https://github.com/Anthonyc3rb3ru5/CVE-2022-46169) :  ![starts](https://img.shields.io/github/stars/Anthonyc3rb3ru5/CVE-2022-46169.svg) ![forks](https://img.shields.io/github/forks/Anthonyc3rb3ru5/CVE-2022-46169.svg)


## CVE-2022-45729
 A cross-site scripting (XSS) vulnerability in Doctor Appointment Management System v1.0.0 allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the Employee ID parameter.

- [https://github.com/Live-Hack-CVE/CVE-2022-45729](https://github.com/Live-Hack-CVE/CVE-2022-45729) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45729.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45729.svg)


## CVE-2022-45728
 Doctor Appointment Management System v1.0.0 was discovered to contain a cross-site scripting (XSS) vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-45728](https://github.com/Live-Hack-CVE/CVE-2022-45728) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45728.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45728.svg)


## CVE-2022-43591
 A buffer overflow vulnerability exists in the QML QtScript Reflect API of Qt Project Qt 6.3.2. A specially-crafted javascript code can trigger an out-of-bounds memory access, which can lead to arbitrary code execution. Target application would need to access a malicious web page to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-43591](https://github.com/Live-Hack-CVE/CVE-2022-43591) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43591.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43591.svg)


## CVE-2022-42285
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Live-Hack-CVE/CVE-2022-42285](https://github.com/Live-Hack-CVE/CVE-2022-42285) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42285.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42285.svg)


## CVE-2022-42284
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Live-Hack-CVE/CVE-2022-42284](https://github.com/Live-Hack-CVE/CVE-2022-42284) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42284.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42284.svg)


## CVE-2022-42283
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Live-Hack-CVE/CVE-2022-42283](https://github.com/Live-Hack-CVE/CVE-2022-42283) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42283.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42283.svg)


## CVE-2022-42282
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Live-Hack-CVE/CVE-2022-42282](https://github.com/Live-Hack-CVE/CVE-2022-42282) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42282.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42282.svg)


## CVE-2022-42281
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Live-Hack-CVE/CVE-2022-42281](https://github.com/Live-Hack-CVE/CVE-2022-42281) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42281.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42281.svg)


## CVE-2022-42280
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Live-Hack-CVE/CVE-2022-42280](https://github.com/Live-Hack-CVE/CVE-2022-42280) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42280.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42280.svg)


## CVE-2022-42279
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Live-Hack-CVE/CVE-2022-42279](https://github.com/Live-Hack-CVE/CVE-2022-42279) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42279.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42279.svg)


## CVE-2022-42278
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Live-Hack-CVE/CVE-2022-42278](https://github.com/Live-Hack-CVE/CVE-2022-42278) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42278.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42278.svg)


## CVE-2022-42277
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Live-Hack-CVE/CVE-2022-42277](https://github.com/Live-Hack-CVE/CVE-2022-42277) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42277.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42277.svg)


## CVE-2022-42276
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Live-Hack-CVE/CVE-2022-42276](https://github.com/Live-Hack-CVE/CVE-2022-42276) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42276.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42276.svg)


## CVE-2022-42275
 NVIDIA BMC IPMI handler allows an unauthenticated host to write to a host SPI flash bypassing secureboot protections. This may lead to a loss of integrity and denial of service.

- [https://github.com/Live-Hack-CVE/CVE-2022-42275](https://github.com/Live-Hack-CVE/CVE-2022-42275) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42275.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42275.svg)


## CVE-2022-42274
 NVIDIA BMC contains a vulnerability in IPMI handler, where an authorized attacker can cause a buffer overflow and cause a denial of service or gain code execution.

- [https://github.com/Live-Hack-CVE/CVE-2022-42274](https://github.com/Live-Hack-CVE/CVE-2022-42274) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42274.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42274.svg)


## CVE-2022-42265
 NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer (nvidia.ko), where an integer overflow may lead to information disclosure or data tampering.

- [https://github.com/Live-Hack-CVE/CVE-2022-42265](https://github.com/Live-Hack-CVE/CVE-2022-42265) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42265.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42265.svg)


## CVE-2022-41778
 Delta Electronics InfraSuite Device Master versions 00.00.01a and prior deserialize user-supplied data provided through the Device-DataCollect service port without proper verification. An attacker could provide malicious serialized objects to execute arbitrary code upon deserialization.

- [https://github.com/Live-Hack-CVE/CVE-2022-41778](https://github.com/Live-Hack-CVE/CVE-2022-41778) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-41778.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-41778.svg)


## CVE-2022-40983
 An integer overflow vulnerability exists in the QML QtScript Reflect API of Qt Project Qt 6.3.2. A specially-crafted javascript code can trigger an integer overflow during memory allocation, which can lead to arbitrary code execution. Target application would need to access a malicious web page to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-40983](https://github.com/Live-Hack-CVE/CVE-2022-40983) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-40983.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-40983.svg)


## CVE-2022-40867
 Tenda W20E router V15.11.0.6 (US_W20EV4.0br_V15.11.0.6(1068_1546_841)_CN_TDC) contains a stack overflow vulnerability in the function formIPMacBindDel with the request /goform/delIpMacBind/

- [https://github.com/Live-Hack-CVE/CVE-2022-40867](https://github.com/Live-Hack-CVE/CVE-2022-40867) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-40867.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-40867.svg)


## CVE-2022-40519
 Information disclosure due to buffer overread in Core

- [https://github.com/Live-Hack-CVE/CVE-2022-40519](https://github.com/Live-Hack-CVE/CVE-2022-40519) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-40519.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-40519.svg)


## CVE-2022-40518
 Information disclosure due to buffer overread in Core

- [https://github.com/Live-Hack-CVE/CVE-2022-40518](https://github.com/Live-Hack-CVE/CVE-2022-40518) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-40518.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-40518.svg)


## CVE-2022-40517
 Memory corruption in core due to stack-based buffer overflow

- [https://github.com/Live-Hack-CVE/CVE-2022-40517](https://github.com/Live-Hack-CVE/CVE-2022-40517) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-40517.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-40517.svg)


## CVE-2022-40516
 Memory corruption in Core due to stack-based buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2022-40516](https://github.com/Live-Hack-CVE/CVE-2022-40516) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-40516.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-40516.svg)


## CVE-2022-39185
 EXFO - BV-10 Performance Endpoint Unit Undocumented privileged user. Unit has an undocumented hard-coded privileged user.

- [https://github.com/Live-Hack-CVE/CVE-2022-39185](https://github.com/Live-Hack-CVE/CVE-2022-39185) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-39185.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-39185.svg)


## CVE-2022-39184
 EXFO - BV-10 Performance Endpoint Unit authentication bypass User can manually manipulate access enabling authentication bypass.

- [https://github.com/Live-Hack-CVE/CVE-2022-39184](https://github.com/Live-Hack-CVE/CVE-2022-39184) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-39184.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-39184.svg)


## CVE-2022-39183
 Moodle Plugin - SAML Auth may allow Open Redirect through unspecified vectors.

- [https://github.com/Live-Hack-CVE/CVE-2022-39183](https://github.com/Live-Hack-CVE/CVE-2022-39183) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-39183.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-39183.svg)


## CVE-2022-39182
 H C Mingham-Smith Ltd - Tardis 2000 Privilege escalation.Version 1.6 is vulnerable to privilege escalation which may allow a malicious actor to gain system privileges.

- [https://github.com/Live-Hack-CVE/CVE-2022-39182](https://github.com/Live-Hack-CVE/CVE-2022-39182) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-39182.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-39182.svg)


## CVE-2022-39073
 There is a command injection vulnerability in ZTE MF286R, Due to insufficient validation of the input parameters, an attacker could use the vulnerability to execute arbitrary commands.

- [https://github.com/Live-Hack-CVE/CVE-2022-39073](https://github.com/Live-Hack-CVE/CVE-2022-39073) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-39073.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-39073.svg)


## CVE-2022-39072
 There is a SQL injection vulnerability in Some ZTE Mobile Internet products. Due to insufficient validation of the input parameters of the SNTP interface, an authenticated attacker could use the vulnerability to execute stored XSS attacks.

- [https://github.com/Live-Hack-CVE/CVE-2022-39072](https://github.com/Live-Hack-CVE/CVE-2022-39072) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-39072.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-39072.svg)


## CVE-2022-37933
 A potential security vulnerability has been identified in HPE Superdome Flex and Superdome Flex 280 servers. The vulnerability could be exploited to allow local unauthorized data injection. HPE has made the following software updates to resolve the vulnerability in HPE Superdome Flex firmware 3.60.50 and below and Superdome Flex 280 servers firmware 1.40.60 and below.

- [https://github.com/Live-Hack-CVE/CVE-2022-37933](https://github.com/Live-Hack-CVE/CVE-2022-37933) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-37933.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-37933.svg)


## CVE-2022-36002
 TensorFlow is an open source platform for machine learning. When `Unbatch` receives a nonscalar input `id`, it gives a `CHECK` fail that can trigger a denial of service attack. We have patched the issue in GitHub commit 4419d10d576adefa36b0e0a9425d2569f7c0189f. The fix will be included in TensorFlow 2.10.0. We will also cherrypick this commit on TensorFlow 2.9.1, TensorFlow 2.8.1, and TensorFlow 2.7.2, as these are also affected and still in supported range. There are no known workarounds for this issue.

- [https://github.com/Live-Hack-CVE/CVE-2022-36002](https://github.com/Live-Hack-CVE/CVE-2022-36002) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36002.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36002.svg)


## CVE-2022-35783
 Azure Site Recovery Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2022-35774, CVE-2022-35775, CVE-2022-35780, CVE-2022-35781, CVE-2022-35782, CVE-2022-35784, CVE-2022-35785, CVE-2022-35786, CVE-2022-35787, CVE-2022-35788, CVE-2022-35789, CVE-2022-35790, CVE-2022-35791, CVE-2022-35799, CVE-2022-35800, CVE-2022-35801, CVE-2022-35802, CVE-2022-35807, CVE-2022-35808, CVE-2022-35809, CVE-2022-35810, CVE-2022-35811, CVE-2022-35812, CVE-2022-35813, CVE-2022-35814, CVE-2022-35815, CVE-2022-35816, CVE-2022-35817, CVE-2022-35818, CVE-2022-35819.

- [https://github.com/Live-Hack-CVE/CVE-2022-35812](https://github.com/Live-Hack-CVE/CVE-2022-35812) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35812.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35812.svg)


## CVE-2022-35281
 IBM Maximo Asset Management 7.6.1.1, 7.6.1.2, 7.6.1.3 and the IBM Maximo Manage 8.3, 8.4 application in IBM Maximo Application Suite are vulnerable to CSV injection. IBM X-Force ID: 2306335.

- [https://github.com/Live-Hack-CVE/CVE-2022-35281](https://github.com/Live-Hack-CVE/CVE-2022-35281) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35281.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35281.svg)


## CVE-2022-33300
 Memory corruption in Automotive Android OS due to improper input validation.

- [https://github.com/Live-Hack-CVE/CVE-2022-33300](https://github.com/Live-Hack-CVE/CVE-2022-33300) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33300.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33300.svg)


## CVE-2022-33299
 Transient DOS due to null pointer dereference in Bluetooth HOST while receiving an attribute protocol PDU with zero length data.

- [https://github.com/Live-Hack-CVE/CVE-2022-33299](https://github.com/Live-Hack-CVE/CVE-2022-33299) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33299.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33299.svg)


## CVE-2022-33290
 Transient DOS in Bluetooth HOST due to null pointer dereference when a mismatched argument is passed.

- [https://github.com/Live-Hack-CVE/CVE-2022-33290](https://github.com/Live-Hack-CVE/CVE-2022-33290) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33290.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33290.svg)


## CVE-2022-33286
 Transient DOS due to buffer over-read in WLAN while processing 802.11 management frames.

- [https://github.com/Live-Hack-CVE/CVE-2022-33286](https://github.com/Live-Hack-CVE/CVE-2022-33286) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33286.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33286.svg)


## CVE-2022-33284
 Information disclosure due to buffer over-read in WLAN while parsing BTM action frame.

- [https://github.com/Live-Hack-CVE/CVE-2022-33284](https://github.com/Live-Hack-CVE/CVE-2022-33284) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33284.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33284.svg)


## CVE-2022-33283
 Information disclosure due to buffer over-read in WLAN while WLAN frame parsing due to missing frame length check.

- [https://github.com/Live-Hack-CVE/CVE-2022-33283](https://github.com/Live-Hack-CVE/CVE-2022-33283) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-33283.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-33283.svg)


## CVE-2022-30190
 Microsoft Windows Support Diagnostic Tool (MSDT) Remote Code Execution Vulnerability.

- [https://github.com/nanaao/PicusSecurity4.Week.Repo](https://github.com/nanaao/PicusSecurity4.Week.Repo) :  ![starts](https://img.shields.io/github/stars/nanaao/PicusSecurity4.Week.Repo.svg) ![forks](https://img.shields.io/github/forks/nanaao/PicusSecurity4.Week.Repo.svg)


## CVE-2022-25715
 Memory corruption in display driver due to incorrect type casting while accessing the fence structure fields

- [https://github.com/Live-Hack-CVE/CVE-2022-25715](https://github.com/Live-Hack-CVE/CVE-2022-25715) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-25715.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-25715.svg)


## CVE-2022-24913
 Versions of the package com.fasterxml.util:java-merge-sort before 1.1.0 are vulnerable to Insecure Temporary File in the StdTempFileProvider() function in StdTempFileProvider.java, which uses the permissive File.createTempFile() function, exposing temporary file contents.

- [https://github.com/Live-Hack-CVE/CVE-2022-24913](https://github.com/Live-Hack-CVE/CVE-2022-24913) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-24913.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-24913.svg)


## CVE-2022-4498
 In TP-Link routers, Archer C5 and WR710N-V1, running the latest available code, when receiving HTTP Basic Authentication the httpd service can be sent a crafted packet that causes a heap overflow. This can result in either a DoS (by crashing the httpd process) or an arbitrary code execution.

- [https://github.com/Live-Hack-CVE/CVE-2022-4498](https://github.com/Live-Hack-CVE/CVE-2022-4498) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4498.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4498.svg)


## CVE-2022-3870
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 10.0 before 15.5.7, all versions starting from 15.6 before 15.6.4, all versions starting from 15.7 before 15.7.2. GitLab allows unauthenticated users to download user avatars using the victim's user ID, on private instances that restrict public level visibility.

- [https://github.com/Live-Hack-CVE/CVE-2022-3870](https://github.com/Live-Hack-CVE/CVE-2022-3870) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3870.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3870.svg)


## CVE-2022-3752
 An unauthorized user could use a specially crafted sequence of Ethernet/IP messages, combined with heavy traffic loading to cause a denial-of-service condition in Rockwell Automation Logix controllers resulting in a major non-recoverable fault. If the target device becomes unavailable, a user would have to clear the fault and redownload the user project file to bring the device back online and continue normal operation.

- [https://github.com/Live-Hack-CVE/CVE-2022-3752](https://github.com/Live-Hack-CVE/CVE-2022-3752) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3752.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3752.svg)


## CVE-2022-3715
 A flaw was found in the bash package, where a heap-buffer overflow can occur in valid parameter_transform. This issue may lead to memory problems.

- [https://github.com/Live-Hack-CVE/CVE-2022-3715](https://github.com/Live-Hack-CVE/CVE-2022-3715) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3715.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3715.svg)


## CVE-2022-3656
 Insufficient data validation in File System in Google Chrome prior to 107.0.5304.62 allowed a remote attacker to bypass file system restrictions via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/momika233/CVE-2022-3656](https://github.com/momika233/CVE-2022-3656) :  ![starts](https://img.shields.io/github/stars/momika233/CVE-2022-3656.svg) ![forks](https://img.shields.io/github/forks/momika233/CVE-2022-3656.svg)


## CVE-2022-3613
 An issue has been discovered in GitLab CE/EE affecting all versions before 15.5.7, all versions starting from 15.6 before 15.6.4, all versions starting from 15.7 before 15.7.2. A crafted Prometheus Server query can cause high resource consumption and may lead to Denial of Service.

- [https://github.com/Live-Hack-CVE/CVE-2022-3613](https://github.com/Live-Hack-CVE/CVE-2022-3613) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3613.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3613.svg)


## CVE-2022-3573
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 15.4 before 15.5.7, all versions starting from 15.6 before 15.6.4, all versions starting from 15.7 before 15.7.2. Due to the improper filtering of query parameters in the wiki changes page, an attacker can execute arbitrary JavaScript on the self-hosted instances running without strict CSP.

- [https://github.com/Live-Hack-CVE/CVE-2022-3573](https://github.com/Live-Hack-CVE/CVE-2022-3573) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3573.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3573.svg)


## CVE-2022-3565
 A vulnerability, which was classified as critical, has been found in Linux Kernel. Affected by this issue is the function del_timer of the file drivers/isdn/mISDN/l1oip_core.c of the component Bluetooth. The manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-211088.

- [https://github.com/Live-Hack-CVE/CVE-2022-3565](https://github.com/Live-Hack-CVE/CVE-2022-3565) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3565.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3565.svg)


## CVE-2022-3518
 A vulnerability classified as problematic has been found in SourceCodester Sanitization Management System 1.0. Affected is an unknown function of the component User Creation Handler. The manipulation of the argument First Name/Middle Name/Last Name leads to cross site scripting. It is possible to launch the attack remotely. VDB-211014 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-3518](https://github.com/Live-Hack-CVE/CVE-2022-3518) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3518.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3518.svg)


## CVE-2022-3514
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 6.6 before 15.5.7, all versions starting from 15.6 before 15.6.4, all versions starting from 15.7 before 15.7.2. An attacker may cause Denial of Service on a GitLab instance by exploiting a regex issue in the submodule URL parser.

- [https://github.com/Live-Hack-CVE/CVE-2022-3514](https://github.com/Live-Hack-CVE/CVE-2022-3514) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3514.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3514.svg)


## CVE-2022-2509
 A vulnerability found in gnutls. This security flaw happens because of a double free error occurs during verification of pkcs7 signatures in gnutls_pkcs7_verify function.

- [https://github.com/Live-Hack-CVE/CVE-2022-2509](https://github.com/Live-Hack-CVE/CVE-2022-2509) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2509.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2509.svg)


## CVE-2022-2172
 The LinkWorth WordPress plugin before 3.3.4 does not implement nonce checks, which could allow attackers to make a logged in admin change settings via a CSRF attack.

- [https://github.com/Live-Hack-CVE/CVE-2022-2172](https://github.com/Live-Hack-CVE/CVE-2022-2172) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2172.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2172.svg)


## CVE-2021-46868
 The HW_KEYMASTER module has a problem in releasing memory.Successful exploitation of this vulnerability may result in out-of-bounds memory access.

- [https://github.com/Live-Hack-CVE/CVE-2021-46868](https://github.com/Live-Hack-CVE/CVE-2021-46868) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-46868.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-46868.svg)


## CVE-2021-46867
 The HW_KEYMASTER module has a problem in releasing memory.Successful exploitation of this vulnerability may result in out-of-bounds memory access.

- [https://github.com/Live-Hack-CVE/CVE-2021-46867](https://github.com/Live-Hack-CVE/CVE-2021-46867) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-46867.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-46867.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/scarmandef/CVE-2021-41773](https://github.com/scarmandef/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/scarmandef/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/scarmandef/CVE-2021-41773.svg)
- [https://github.com/McSl0vv/CVE-2021-41773](https://github.com/McSl0vv/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/McSl0vv/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/McSl0vv/CVE-2021-41773.svg)
- [https://github.com/m96dg/CVE-2021-41773-exercise](https://github.com/m96dg/CVE-2021-41773-exercise) :  ![starts](https://img.shields.io/github/stars/m96dg/CVE-2021-41773-exercise.svg) ![forks](https://img.shields.io/github/forks/m96dg/CVE-2021-41773-exercise.svg)
- [https://github.com/12345qwert123456/CVE-2021-41773](https://github.com/12345qwert123456/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/12345qwert123456/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/12345qwert123456/CVE-2021-41773.svg)
- [https://github.com/Live-Hack-CVE/CVE-2021-41773](https://github.com/Live-Hack-CVE/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-41773.svg)


## CVE-2021-21309
 Redis is an open-source, in-memory database that persists on disk. In affected versions of Redis an integer overflow bug in 32-bit Redis version 4.0 or newer could be exploited to corrupt the heap and potentially result with remote code execution. Redis 4.0 or newer uses a configurable limit for the maximum supported bulk input size. By default, it is 512MB which is a safe value for all platforms. If the limit is significantly increased, receiving a large request from a client may trigger several integer overflow scenarios, which would result with buffer overflow and heap corruption. We believe this could in certain conditions be exploited for remote code execution. By default, authenticated Redis users have access to all configuration parameters and can therefore use the &#8220;CONFIG SET proto-max-bulk-len&#8221; to change the safe default, making the system vulnerable. **This problem only affects 32-bit Redis (on a 32-bit system, or as a 32-bit executable running on a 64-bit system).** The problem is fixed in version 6.2, and the fix is back ported to 6.0.11 and 5.0.11. Make sure you use one of these versions if you are running 32-bit Redis. An additional workaround to mitigate the problem without patching the redis-server executable is to prevent clients from directly executing `CONFIG SET`: Using Redis 6.0 or newer, ACL configuration can be used to block the command. Using older versions, the `rename-command` configuration directive can be used to rename the command to a random string unknown to users, rendering it inaccessible. Please note that this workaround may have an additional impact on users or operational systems that expect `CONFIG SET` to behave in certain ways.

- [https://github.com/Live-Hack-CVE/CVE-2021-21309](https://github.com/Live-Hack-CVE/CVE-2021-21309) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-21309.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-21309.svg)


## CVE-2020-16899
 A denial of service vulnerability exists when the Windows TCP/IP stack improperly handles ICMPv6 Router Advertisement packets, aka 'Windows TCP/IP Denial of Service Vulnerability'.

- [https://github.com/advanced-threat-research/CVE-2020-16899](https://github.com/advanced-threat-research/CVE-2020-16899) :  ![starts](https://img.shields.io/github/stars/advanced-threat-research/CVE-2020-16899.svg) ![forks](https://img.shields.io/github/forks/advanced-threat-research/CVE-2020-16899.svg)


## CVE-2019-10149
 A flaw was found in Exim versions 4.87 to 4.91 (inclusive). Improper validation of recipient address in deliver_message() function in /src/deliver.c may lead to remote command execution.

- [https://github.com/cloudflare/exim-cve-2019-10149-data](https://github.com/cloudflare/exim-cve-2019-10149-data) :  ![starts](https://img.shields.io/github/stars/cloudflare/exim-cve-2019-10149-data.svg) ![forks](https://img.shields.io/github/forks/cloudflare/exim-cve-2019-10149-data.svg)


## CVE-2018-17182
 An issue was discovered in the Linux kernel through 4.18.8. The vmacache_flush_all function in mm/vmacache.c mishandles sequence number overflows. An attacker can trigger a use-after-free (and possibly gain privileges) via certain thread creation, map, unmap, invalidation, and dereference operations.

- [https://github.com/jas502n/CVE-2018-17182](https://github.com/jas502n/CVE-2018-17182) :  ![starts](https://img.shields.io/github/stars/jas502n/CVE-2018-17182.svg) ![forks](https://img.shields.io/github/forks/jas502n/CVE-2018-17182.svg)


## CVE-2018-11776
 Apache Struts versions 2.3 to 2.3.34 and 2.5 to 2.5.16 suffer from possible Remote Code Execution when alwaysSelectFullNamespace is true (either by user or a plugin like Convention Plugin) and then: results are used with no namespace and in same time, its upper package have no or wildcard namespace and similar to results, same possibility when using url tag which doesn't have value and action set and in same time, its upper package have no or wildcard namespace.

- [https://github.com/ArunBhandarii/Apache-Struts-0Day-Exploit](https://github.com/ArunBhandarii/Apache-Struts-0Day-Exploit) :  ![starts](https://img.shields.io/github/stars/ArunBhandarii/Apache-Struts-0Day-Exploit.svg) ![forks](https://img.shields.io/github/forks/ArunBhandarii/Apache-Struts-0Day-Exploit.svg)


## CVE-2018-8976
 In Exiv2 0.26, jpgimage.cpp allows remote attackers to cause a denial of service (image.cpp Exiv2::Internal::stringFormat out-of-bounds read) via a crafted file.

- [https://github.com/Live-Hack-CVE/CVE-2018-8976](https://github.com/Live-Hack-CVE/CVE-2018-8976) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-8976.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-8976.svg)


## CVE-2017-18005
 Exiv2 0.26 has a Null Pointer Dereference in the Exiv2::DataValue::toLong function in value.cpp, related to crafted metadata in a TIFF file.

- [https://github.com/Live-Hack-CVE/CVE-2017-18005](https://github.com/Live-Hack-CVE/CVE-2017-18005) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-18005.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-18005.svg)


## CVE-2017-17669
 There is a heap-based buffer over-read in the Exiv2::Internal::PngChunk::keyTXTChunk function of pngchunk_int.cpp in Exiv2 0.26. A crafted PNG file will lead to a remote denial of service attack.

- [https://github.com/Live-Hack-CVE/CVE-2017-17669](https://github.com/Live-Hack-CVE/CVE-2017-17669) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-17669.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-17669.svg)


## CVE-2017-14864
 An Invalid memory address dereference was discovered in Exiv2::getULong in types.cpp in Exiv2 0.26. The vulnerability causes a segmentation fault and application crash, which leads to denial of service.

- [https://github.com/Live-Hack-CVE/CVE-2017-14864](https://github.com/Live-Hack-CVE/CVE-2017-14864) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-14864.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-14864.svg)


## CVE-2017-14862
 An Invalid memory address dereference was discovered in Exiv2::DataValue::read in value.cpp in Exiv2 0.26. The vulnerability causes a segmentation fault and application crash, which leads to denial of service.

- [https://github.com/Live-Hack-CVE/CVE-2017-14862](https://github.com/Live-Hack-CVE/CVE-2017-14862) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-14862.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-14862.svg)


## CVE-2017-14443
 An exploitable information leak vulnerability exists in Insteon Hub running firmware version 1012. The HTTP server implementation incorrectly checks the number of GET parameters supplied, leading to an arbitrarily controlled information leak on the whole device memory. An attacker can send an authenticated HTTP request to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2017-14443](https://github.com/Live-Hack-CVE/CVE-2017-14443) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-14443.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-14443.svg)


## CVE-2017-11591
 There is a Floating point exception in the Exiv2::ValueType function in Exiv2 0.26 that will lead to a remote denial of service attack via crafted input.

- [https://github.com/Live-Hack-CVE/CVE-2017-11591](https://github.com/Live-Hack-CVE/CVE-2017-11591) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-11591.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-11591.svg)


## CVE-2017-5242
 Nexpose and InsightVM virtual appliances downloaded between April 5th, 2017 and May 3rd, 2017 contain identical SSH host keys. Normally, a unique SSH host key should be generated the first time a virtual appliance boots.

- [https://github.com/Live-Hack-CVE/CVE-2017-5242](https://github.com/Live-Hack-CVE/CVE-2017-5242) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-5242.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-5242.svg)


## CVE-2009-10002
 A vulnerability, which was classified as problematic, has been found in dpup fittr-flickr. This issue affects some unknown processing of the file fittr-flickr/features/easy-exif.js of the component EXIF Preview Handler. The manipulation leads to cross site scripting. The attack may be initiated remotely. The name of the patch is 08875dd8a2e5d0d16568bb0d67cb4328062fccde. It is recommended to apply a patch to fix this issue. The identifier VDB-218297 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2009-10002](https://github.com/Live-Hack-CVE/CVE-2009-10002) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2009-10002.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2009-10002.svg)


## CVE-2009-10001
 A vulnerability classified as problematic was found in jianlinwei cool-php-captcha up to 0.2. This vulnerability affects unknown code of the file example-form.php. The manipulation of the argument captcha with the input %3Cscript%3Ealert(1)%3C/script%3E leads to cross site scripting. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. Upgrading to version 0.3 is able to address this issue. The name of the patch is c84fb6b153bebaf228feee0cbf50728d27ae3f80. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-218296.

- [https://github.com/Live-Hack-CVE/CVE-2009-10001](https://github.com/Live-Hack-CVE/CVE-2009-10001) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2009-10001.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2009-10001.svg)

