# Update 2024-01-10
## CVE-2023-46604
 The Java OpenWire protocol marshaller is vulnerable to Remote Code Execution. This vulnerability may allow a remote attacker with network access to either a Java-based OpenWire broker or client to run arbitrary shell commands by manipulating serialized class types in the OpenWire protocol to cause either the client or the broker (respectively) to instantiate any class on the classpath. Users are recommended to upgrade both brokers and clients to version 5.15.16, 5.16.7, 5.17.6, or 5.18.3 which fixes this issue.

- [https://github.com/hh-hunter/cve-2023-46604](https://github.com/hh-hunter/cve-2023-46604) :  ![starts](https://img.shields.io/github/stars/hh-hunter/cve-2023-46604.svg) ![forks](https://img.shields.io/github/forks/hh-hunter/cve-2023-46604.svg)


## CVE-2023-41474
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/JBalanza/CVE-2023-41474](https://github.com/JBalanza/CVE-2023-41474) :  ![starts](https://img.shields.io/github/stars/JBalanza/CVE-2023-41474.svg) ![forks](https://img.shields.io/github/forks/JBalanza/CVE-2023-41474.svg)


## CVE-2023-24489
 A vulnerability has been discovered in the customer-managed ShareFile storage zones controller which, if exploited, could allow an unauthenticated attacker to remotely compromise the customer-managed ShareFile storage zones controller.

- [https://github.com/codeb0ss/CVE-2023-24489-PoC](https://github.com/codeb0ss/CVE-2023-24489-PoC) :  ![starts](https://img.shields.io/github/stars/codeb0ss/CVE-2023-24489-PoC.svg) ![forks](https://img.shields.io/github/forks/codeb0ss/CVE-2023-24489-PoC.svg)


## CVE-2022-45688
 A stack overflow in the XML.toJSONObject component of hutool-json v5.8.10 allows attackers to cause a Denial of Service (DoS) via crafted JSON or XML data.

- [https://github.com/scabench/jsonorg-fp1](https://github.com/scabench/jsonorg-fp1) :  ![starts](https://img.shields.io/github/stars/scabench/jsonorg-fp1.svg) ![forks](https://img.shields.io/github/forks/scabench/jsonorg-fp1.svg)


## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/Gotcha-1G/CVE-2022-42889](https://github.com/Gotcha-1G/CVE-2022-42889) :  ![starts](https://img.shields.io/github/stars/Gotcha-1G/CVE-2022-42889.svg) ![forks](https://img.shields.io/github/forks/Gotcha-1G/CVE-2022-42889.svg)


## CVE-2022-41049
 Windows Mark of the Web Security Feature Bypass Vulnerability

- [https://github.com/NathanOrr101/CVE-2022-41049-POC](https://github.com/NathanOrr101/CVE-2022-41049-POC) :  ![starts](https://img.shields.io/github/stars/NathanOrr101/CVE-2022-41049-POC.svg) ![forks](https://img.shields.io/github/forks/NathanOrr101/CVE-2022-41049-POC.svg)


## CVE-2022-36553
 Hytec Inter HWL-2511-SS v1.05 and below was discovered to contain a command injection vulnerability via the component /www/cgi-bin/popen.cgi.

- [https://github.com/0xNslabs/CVE-2022-36553-PoC](https://github.com/0xNslabs/CVE-2022-36553-PoC) :  ![starts](https://img.shields.io/github/stars/0xNslabs/CVE-2022-36553-PoC.svg) ![forks](https://img.shields.io/github/forks/0xNslabs/CVE-2022-36553-PoC.svg)


## CVE-2022-36267
 In Airspan AirSpot 5410 version 0.3.4.1-4 and under there exists a Unauthenticated remote command injection vulnerability. The ping functionality can be called without user authentication when crafting a malicious http request by injecting code in one of the parameters allowing for remote code execution. This vulnerability is exploited via the binary file /home/www/cgi-bin/diagnostics.cgi that accepts unauthenticated requests and unsanitized data. As a result, a malicious actor can craft a specific request and interact remotely with the device.

- [https://github.com/0xNslabs/CVE-2022-36267-PoC](https://github.com/0xNslabs/CVE-2022-36267-PoC) :  ![starts](https://img.shields.io/github/stars/0xNslabs/CVE-2022-36267-PoC.svg) ![forks](https://img.shields.io/github/forks/0xNslabs/CVE-2022-36267-PoC.svg)


## CVE-2021-44529
 A code injection vulnerability in the Ivanti EPM Cloud Services Appliance (CSA) allows an unauthenticated user to execute arbitrary code with limited permissions (nobody).

- [https://github.com/jax7sec/CVE-2021-44529](https://github.com/jax7sec/CVE-2021-44529) :  ![starts](https://img.shields.io/github/stars/jax7sec/CVE-2021-44529.svg) ![forks](https://img.shields.io/github/forks/jax7sec/CVE-2021-44529.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/ilurer/CVE-2021-41773-42013](https://github.com/ilurer/CVE-2021-41773-42013) :  ![starts](https://img.shields.io/github/stars/ilurer/CVE-2021-41773-42013.svg) ![forks](https://img.shields.io/github/forks/ilurer/CVE-2021-41773-42013.svg)
- [https://github.com/m96dg/CVE-2021-41773-exercise](https://github.com/m96dg/CVE-2021-41773-exercise) :  ![starts](https://img.shields.io/github/stars/m96dg/CVE-2021-41773-exercise.svg) ![forks](https://img.shields.io/github/forks/m96dg/CVE-2021-41773-exercise.svg)
- [https://github.com/McSl0vv/CVE-2021-41773](https://github.com/McSl0vv/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/McSl0vv/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/McSl0vv/CVE-2021-41773.svg)


## CVE-2021-3708
 D-Link router DSL-2750U with firmware vME1.16 or prior versions is vulnerable to OS command injection. An unauthenticated attacker on the local network may exploit this, with CVE-2021-3707, to execute any OS commands on the vulnerable device.

- [https://github.com/HadiMed/DSL-2750U-Full-chain](https://github.com/HadiMed/DSL-2750U-Full-chain) :  ![starts](https://img.shields.io/github/stars/HadiMed/DSL-2750U-Full-chain.svg) ![forks](https://img.shields.io/github/forks/HadiMed/DSL-2750U-Full-chain.svg)


## CVE-2020-1350
 A remote code execution vulnerability exists in Windows Domain Name System servers when they fail to properly handle requests, aka 'Windows DNS Server Remote Code Execution Vulnerability'.

- [https://github.com/CVEmaster/CVE-2020-1350](https://github.com/CVEmaster/CVE-2020-1350) :  ![starts](https://img.shields.io/github/stars/CVEmaster/CVE-2020-1350.svg) ![forks](https://img.shields.io/github/forks/CVEmaster/CVE-2020-1350.svg)


## CVE-2020-0471
 In reassemble_and_dispatch of packet_fragmenter.cc, there is a possible way to inject packets into an encrypted Bluetooth connection due to improper input validation. This could lead to remote escalation of privilege between two Bluetooth devices by a proximal attacker, with no additional execution privileges needed. User interaction is not needed for exploitation. Product: Android; Versions: Android-8.0, Android-8.1, Android-9, Android-10, Android-11; Android ID: A-169327567.

- [https://github.com/nanopathi/system_bt_AOSP10_r33_CVE-2020-0471](https://github.com/nanopathi/system_bt_AOSP10_r33_CVE-2020-0471) :  ![starts](https://img.shields.io/github/stars/nanopathi/system_bt_AOSP10_r33_CVE-2020-0471.svg) ![forks](https://img.shields.io/github/forks/nanopathi/system_bt_AOSP10_r33_CVE-2020-0471.svg)


## CVE-2015-3864
 Integer underflow in the MPEG4Extractor::parseChunk function in MPEG4Extractor.cpp in libstagefright in mediaserver in Android before 5.1.1 LMY48M allows remote attackers to execute arbitrary code via crafted MPEG-4 data, aka internal bug 23034759.  NOTE: this vulnerability exists because of an incomplete fix for CVE-2015-3824.

- [https://github.com/Bhathiya404/Exploiting-Stagefright-Vulnerability-CVE-2015-3864](https://github.com/Bhathiya404/Exploiting-Stagefright-Vulnerability-CVE-2015-3864) :  ![starts](https://img.shields.io/github/stars/Bhathiya404/Exploiting-Stagefright-Vulnerability-CVE-2015-3864.svg) ![forks](https://img.shields.io/github/forks/Bhathiya404/Exploiting-Stagefright-Vulnerability-CVE-2015-3864.svg)

