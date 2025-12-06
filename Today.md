# Update 2025-12-06
## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/assetnote/react2shell-scanner](https://github.com/assetnote/react2shell-scanner) :  ![starts](https://img.shields.io/github/stars/assetnote/react2shell-scanner.svg) ![forks](https://img.shields.io/github/forks/assetnote/react2shell-scanner.svg)
- [https://github.com/heiheishushu/rsc_detect_CVE-2025-55182](https://github.com/heiheishushu/rsc_detect_CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/heiheishushu/rsc_detect_CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/heiheishushu/rsc_detect_CVE-2025-55182.svg)
- [https://github.com/jctommasi/react2shellVulnApp](https://github.com/jctommasi/react2shellVulnApp) :  ![starts](https://img.shields.io/github/stars/jctommasi/react2shellVulnApp.svg) ![forks](https://img.shields.io/github/forks/jctommasi/react2shellVulnApp.svg)
- [https://github.com/CymulateResearch/React2Shell-Scanner](https://github.com/CymulateResearch/React2Shell-Scanner) :  ![starts](https://img.shields.io/github/stars/CymulateResearch/React2Shell-Scanner.svg) ![forks](https://img.shields.io/github/forks/CymulateResearch/React2Shell-Scanner.svg)
- [https://github.com/shamo0/react2shell-PoC](https://github.com/shamo0/react2shell-PoC) :  ![starts](https://img.shields.io/github/stars/shamo0/react2shell-PoC.svg) ![forks](https://img.shields.io/github/forks/shamo0/react2shell-PoC.svg)
- [https://github.com/ZihxS/check-react-rce-cve-2025-55182](https://github.com/ZihxS/check-react-rce-cve-2025-55182) :  ![starts](https://img.shields.io/github/stars/ZihxS/check-react-rce-cve-2025-55182.svg) ![forks](https://img.shields.io/github/forks/ZihxS/check-react-rce-cve-2025-55182.svg)
- [https://github.com/songsanggggg/CVE-2025-55182](https://github.com/songsanggggg/CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/songsanggggg/CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/songsanggggg/CVE-2025-55182.svg)
- [https://github.com/mattcbarrett/check-cve-2025-66478](https://github.com/mattcbarrett/check-cve-2025-66478) :  ![starts](https://img.shields.io/github/stars/mattcbarrett/check-cve-2025-66478.svg) ![forks](https://img.shields.io/github/forks/mattcbarrett/check-cve-2025-66478.svg)
- [https://github.com/wangxso/CVE-2025-66478-POC](https://github.com/wangxso/CVE-2025-66478-POC) :  ![starts](https://img.shields.io/github/stars/wangxso/CVE-2025-66478-POC.svg) ![forks](https://img.shields.io/github/forks/wangxso/CVE-2025-66478-POC.svg)
- [https://github.com/Malayke/Next.js-RSC-RCE-Scanner-CVE-2025-66478](https://github.com/Malayke/Next.js-RSC-RCE-Scanner-CVE-2025-66478) :  ![starts](https://img.shields.io/github/stars/Malayke/Next.js-RSC-RCE-Scanner-CVE-2025-66478.svg) ![forks](https://img.shields.io/github/forks/Malayke/Next.js-RSC-RCE-Scanner-CVE-2025-66478.svg)
- [https://github.com/Security-Phoenix-demo/freight-night-rce-react-next-CVE-2025-55182-CVE-2025-66478](https://github.com/Security-Phoenix-demo/freight-night-rce-react-next-CVE-2025-55182-CVE-2025-66478) :  ![starts](https://img.shields.io/github/stars/Security-Phoenix-demo/freight-night-rce-react-next-CVE-2025-55182-CVE-2025-66478.svg) ![forks](https://img.shields.io/github/forks/Security-Phoenix-demo/freight-night-rce-react-next-CVE-2025-55182-CVE-2025-66478.svg)
- [https://github.com/tobiasGuta/Next.js-RSC-RCE-Scanner-Burp-Suite-Extension](https://github.com/tobiasGuta/Next.js-RSC-RCE-Scanner-Burp-Suite-Extension) :  ![starts](https://img.shields.io/github/stars/tobiasGuta/Next.js-RSC-RCE-Scanner-Burp-Suite-Extension.svg) ![forks](https://img.shields.io/github/forks/tobiasGuta/Next.js-RSC-RCE-Scanner-Burp-Suite-Extension.svg)


## CVE-2025-65900
 Kalmia CMS version 0.2.0 contains an Incorrect Access Control vulnerability in the /kal-api/auth/users API endpoint. Due to insufficient permission validation and excessive data exposure in the backend, an authenticated user with basic read permissions can retrieve sensitive information for all platform users.

- [https://github.com/Noxurge/CVE-2025-65900](https://github.com/Noxurge/CVE-2025-65900) :  ![starts](https://img.shields.io/github/stars/Noxurge/CVE-2025-65900.svg) ![forks](https://img.shields.io/github/forks/Noxurge/CVE-2025-65900.svg)


## CVE-2025-65899
 Kalmia CMS version 0.2.0 contains a user enumeration vulnerability in its authentication mechanism. The application returns different error messages for invalid users (user_not_found) versus valid users with incorrect passwords (invalid_password). This observable response discrepancy allows unauthenticated attackers to enumerate valid usernames on the system.

- [https://github.com/Noxurge/CVE-2025-65899](https://github.com/Noxurge/CVE-2025-65899) :  ![starts](https://img.shields.io/github/stars/Noxurge/CVE-2025-65899.svg) ![forks](https://img.shields.io/github/forks/Noxurge/CVE-2025-65899.svg)


## CVE-2025-65806
 The E-POINT CMS eagle.gsam-1169.1 file upload feature improperly handles nested archive files. An attacker can upload a nested ZIP (a ZIP containing another ZIP) where the inner archive contains an executable file (e.g. webshell.php). When the application extracts the uploaded archives, the executable may be extracted into a web-accessible directory. This can lead to remote code execution (RCE), data disclosure, account compromise, or further system compromise depending on the web server/process privileges. The issue arises from insufficient validation of archive contents and inadequate restrictions on extraction targets.

- [https://github.com/Bidon47/CVE-2025-65806](https://github.com/Bidon47/CVE-2025-65806) :  ![starts](https://img.shields.io/github/stars/Bidon47/CVE-2025-65806.svg) ![forks](https://img.shields.io/github/forks/Bidon47/CVE-2025-65806.svg)


## CVE-2025-65637
 A denial-of-service vulnerability exists in github.com/sirupsen/logrus when using Entry.Writer() to log a single-line payload larger than 64KB without newline characters. Due to limitations in the internal bufio.Scanner, the read fails with "token too long" and the writer pipe is closed, leaving Writer() unusable and causing application unavailability (DoS). This affects versions  1.8.3, 1.9.0, and 1.9.2. The issue is fixed in 1.8.3, 1.9.1, and 1.9.3+, where the input is chunked and the writer continues to function even if an error is logged.

- [https://github.com/mjuanxd/logrus-dos-poc](https://github.com/mjuanxd/logrus-dos-poc) :  ![starts](https://img.shields.io/github/stars/mjuanxd/logrus-dos-poc.svg) ![forks](https://img.shields.io/github/forks/mjuanxd/logrus-dos-poc.svg)


## CVE-2025-65346
 alexusmai laravel-file-manager 3.3.1 and below is vulnerable to Directory Traversal. The unzip/extraction functionality improperly allows archive contents to be written to arbitrary locations on the filesystem due to insufficient validation of extraction paths.

- [https://github.com/Theethat-Thamwasin/CVE-2025-65346](https://github.com/Theethat-Thamwasin/CVE-2025-65346) :  ![starts](https://img.shields.io/github/stars/Theethat-Thamwasin/CVE-2025-65346.svg) ![forks](https://img.shields.io/github/forks/Theethat-Thamwasin/CVE-2025-65346.svg)


## CVE-2025-63499
 Alinto Sogo 5.12.3 is vulnerable to Cross Site Scripting (XSS) via the theme parameter.

- [https://github.com/poblaguev-tot/CVE-2025-63499](https://github.com/poblaguev-tot/CVE-2025-63499) :  ![starts](https://img.shields.io/github/stars/poblaguev-tot/CVE-2025-63499.svg) ![forks](https://img.shields.io/github/forks/poblaguev-tot/CVE-2025-63499.svg)


## CVE-2025-61148
 An Insecure Direct Object Reference (IDOR) vulnerability in the EduplusCampus 3.0.1 Student Payment API allows authenticated users to access other students personal and financial records by modifying the 'rec_no' parameter in the /student/get-receipt endpoint.

- [https://github.com/sharma19d/CVE-2025-61148](https://github.com/sharma19d/CVE-2025-61148) :  ![starts](https://img.shields.io/github/stars/sharma19d/CVE-2025-61148.svg) ![forks](https://img.shields.io/github/forks/sharma19d/CVE-2025-61148.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/ejpir/CVE-2025-55182-research](https://github.com/ejpir/CVE-2025-55182-research) :  ![starts](https://img.shields.io/github/stars/ejpir/CVE-2025-55182-research.svg) ![forks](https://img.shields.io/github/forks/ejpir/CVE-2025-55182-research.svg)
- [https://github.com/msanft/CVE-2025-55182](https://github.com/msanft/CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/msanft/CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/msanft/CVE-2025-55182.svg)
- [https://github.com/assetnote/react2shell-scanner](https://github.com/assetnote/react2shell-scanner) :  ![starts](https://img.shields.io/github/stars/assetnote/react2shell-scanner.svg) ![forks](https://img.shields.io/github/forks/assetnote/react2shell-scanner.svg)
- [https://github.com/dwisiswant0/CVE-2025-55182](https://github.com/dwisiswant0/CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/dwisiswant0/CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/dwisiswant0/CVE-2025-55182.svg)
- [https://github.com/MrR0b0t19/CVE-2025-55182-shellinteractive](https://github.com/MrR0b0t19/CVE-2025-55182-shellinteractive) :  ![starts](https://img.shields.io/github/stars/MrR0b0t19/CVE-2025-55182-shellinteractive.svg) ![forks](https://img.shields.io/github/forks/MrR0b0t19/CVE-2025-55182-shellinteractive.svg)
- [https://github.com/c0rydoras/CVE-2025-55182](https://github.com/c0rydoras/CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/c0rydoras/CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/c0rydoras/CVE-2025-55182.svg)
- [https://github.com/gensecaihq/react2shell-scanner](https://github.com/gensecaihq/react2shell-scanner) :  ![starts](https://img.shields.io/github/stars/gensecaihq/react2shell-scanner.svg) ![forks](https://img.shields.io/github/forks/gensecaihq/react2shell-scanner.svg)
- [https://github.com/jf0x3a/CVE-2025-55182-exploit](https://github.com/jf0x3a/CVE-2025-55182-exploit) :  ![starts](https://img.shields.io/github/stars/jf0x3a/CVE-2025-55182-exploit.svg) ![forks](https://img.shields.io/github/forks/jf0x3a/CVE-2025-55182-exploit.svg)
- [https://github.com/ZihxS/check-react-rce-cve-2025-55182](https://github.com/ZihxS/check-react-rce-cve-2025-55182) :  ![starts](https://img.shields.io/github/stars/ZihxS/check-react-rce-cve-2025-55182.svg) ![forks](https://img.shields.io/github/forks/ZihxS/check-react-rce-cve-2025-55182.svg)
- [https://github.com/ThemeHackers/CVE-2025-55182](https://github.com/ThemeHackers/CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/ThemeHackers/CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/ThemeHackers/CVE-2025-55182.svg)
- [https://github.com/acheong08/CVE-2025-55182-poc](https://github.com/acheong08/CVE-2025-55182-poc) :  ![starts](https://img.shields.io/github/stars/acheong08/CVE-2025-55182-poc.svg) ![forks](https://img.shields.io/github/forks/acheong08/CVE-2025-55182-poc.svg)
- [https://github.com/jctommasi/react2shellVulnApp](https://github.com/jctommasi/react2shellVulnApp) :  ![starts](https://img.shields.io/github/stars/jctommasi/react2shellVulnApp.svg) ![forks](https://img.shields.io/github/forks/jctommasi/react2shellVulnApp.svg)
- [https://github.com/mingyisecurity-lab/CVE-2025-55182-TOOLS](https://github.com/mingyisecurity-lab/CVE-2025-55182-TOOLS) :  ![starts](https://img.shields.io/github/stars/mingyisecurity-lab/CVE-2025-55182-TOOLS.svg) ![forks](https://img.shields.io/github/forks/mingyisecurity-lab/CVE-2025-55182-TOOLS.svg)
- [https://github.com/EynaExp/CVE-2025-55182-POC](https://github.com/EynaExp/CVE-2025-55182-POC) :  ![starts](https://img.shields.io/github/stars/EynaExp/CVE-2025-55182-POC.svg) ![forks](https://img.shields.io/github/forks/EynaExp/CVE-2025-55182-POC.svg)
- [https://github.com/Rsatan/CVE-2025-55182-Tools](https://github.com/Rsatan/CVE-2025-55182-Tools) :  ![starts](https://img.shields.io/github/stars/Rsatan/CVE-2025-55182-Tools.svg) ![forks](https://img.shields.io/github/forks/Rsatan/CVE-2025-55182-Tools.svg)
- [https://github.com/sudo-Yangziran/CVE-2025-55182POC](https://github.com/sudo-Yangziran/CVE-2025-55182POC) :  ![starts](https://img.shields.io/github/stars/sudo-Yangziran/CVE-2025-55182POC.svg) ![forks](https://img.shields.io/github/forks/sudo-Yangziran/CVE-2025-55182POC.svg)
- [https://github.com/SoICT-BKSEC/CVE-2025-55182-docker-lab](https://github.com/SoICT-BKSEC/CVE-2025-55182-docker-lab) :  ![starts](https://img.shields.io/github/stars/SoICT-BKSEC/CVE-2025-55182-docker-lab.svg) ![forks](https://img.shields.io/github/forks/SoICT-BKSEC/CVE-2025-55182-docker-lab.svg)
- [https://github.com/ivaavimusic/React19-fix-vibecoders](https://github.com/ivaavimusic/React19-fix-vibecoders) :  ![starts](https://img.shields.io/github/stars/ivaavimusic/React19-fix-vibecoders.svg) ![forks](https://img.shields.io/github/forks/ivaavimusic/React19-fix-vibecoders.svg)
- [https://github.com/CymulateResearch/React2Shell-Scanner](https://github.com/CymulateResearch/React2Shell-Scanner) :  ![starts](https://img.shields.io/github/stars/CymulateResearch/React2Shell-Scanner.svg) ![forks](https://img.shields.io/github/forks/CymulateResearch/React2Shell-Scanner.svg)
- [https://github.com/shamo0/react2shell-PoC](https://github.com/shamo0/react2shell-PoC) :  ![starts](https://img.shields.io/github/stars/shamo0/react2shell-PoC.svg) ![forks](https://img.shields.io/github/forks/shamo0/react2shell-PoC.svg)
- [https://github.com/joaonevess/rust-flight](https://github.com/joaonevess/rust-flight) :  ![starts](https://img.shields.io/github/stars/joaonevess/rust-flight.svg) ![forks](https://img.shields.io/github/forks/joaonevess/rust-flight.svg)
- [https://github.com/songsanggggg/CVE-2025-55182](https://github.com/songsanggggg/CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/songsanggggg/CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/songsanggggg/CVE-2025-55182.svg)
- [https://github.com/MedusaSH/POC-CVE-2025-55182](https://github.com/MedusaSH/POC-CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/MedusaSH/POC-CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/MedusaSH/POC-CVE-2025-55182.svg)
- [https://github.com/ps-interactive/cve-2025-55182](https://github.com/ps-interactive/cve-2025-55182) :  ![starts](https://img.shields.io/github/stars/ps-interactive/cve-2025-55182.svg) ![forks](https://img.shields.io/github/forks/ps-interactive/cve-2025-55182.svg)
- [https://github.com/Cillian-Collins/CVE-2025-55182](https://github.com/Cillian-Collins/CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/Cillian-Collins/CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/Cillian-Collins/CVE-2025-55182.svg)
- [https://github.com/0xPThree/cve-2025-55182](https://github.com/0xPThree/cve-2025-55182) :  ![starts](https://img.shields.io/github/stars/0xPThree/cve-2025-55182.svg) ![forks](https://img.shields.io/github/forks/0xPThree/cve-2025-55182.svg)
- [https://github.com/dissy123/cve-2025-55182](https://github.com/dissy123/cve-2025-55182) :  ![starts](https://img.shields.io/github/stars/dissy123/cve-2025-55182.svg) ![forks](https://img.shields.io/github/forks/dissy123/cve-2025-55182.svg)
- [https://github.com/carlosaruy/CVE-2025-55182](https://github.com/carlosaruy/CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/carlosaruy/CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/carlosaruy/CVE-2025-55182.svg)
- [https://github.com/atastycookie/CVE-2025-55182](https://github.com/atastycookie/CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/atastycookie/CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/atastycookie/CVE-2025-55182.svg)
- [https://github.com/marginaldeer/CVE-2025-55182_scanner](https://github.com/marginaldeer/CVE-2025-55182_scanner) :  ![starts](https://img.shields.io/github/stars/marginaldeer/CVE-2025-55182_scanner.svg) ![forks](https://img.shields.io/github/forks/marginaldeer/CVE-2025-55182_scanner.svg)
- [https://github.com/Chelsea486MHz/CVE-2025-55182-test](https://github.com/Chelsea486MHz/CVE-2025-55182-test) :  ![starts](https://img.shields.io/github/stars/Chelsea486MHz/CVE-2025-55182-test.svg) ![forks](https://img.shields.io/github/forks/Chelsea486MHz/CVE-2025-55182-test.svg)
- [https://github.com/aspen-labs/CVE-2025-55182-checker](https://github.com/aspen-labs/CVE-2025-55182-checker) :  ![starts](https://img.shields.io/github/stars/aspen-labs/CVE-2025-55182-checker.svg) ![forks](https://img.shields.io/github/forks/aspen-labs/CVE-2025-55182-checker.svg)
- [https://github.com/hzhsec/cve_2025_55182_test](https://github.com/hzhsec/cve_2025_55182_test) :  ![starts](https://img.shields.io/github/stars/hzhsec/cve_2025_55182_test.svg) ![forks](https://img.shields.io/github/forks/hzhsec/cve_2025_55182_test.svg)
- [https://github.com/tlfyyds/cve-2025-55182-getshell](https://github.com/tlfyyds/cve-2025-55182-getshell) :  ![starts](https://img.shields.io/github/stars/tlfyyds/cve-2025-55182-getshell.svg) ![forks](https://img.shields.io/github/forks/tlfyyds/cve-2025-55182-getshell.svg)
- [https://github.com/clevernyyyy/CVE-2025-55182-Dockerized](https://github.com/clevernyyyy/CVE-2025-55182-Dockerized) :  ![starts](https://img.shields.io/github/stars/clevernyyyy/CVE-2025-55182-Dockerized.svg) ![forks](https://img.shields.io/github/forks/clevernyyyy/CVE-2025-55182-Dockerized.svg)
- [https://github.com/joshterrill/CVE-2025-55182-realistic-poc](https://github.com/joshterrill/CVE-2025-55182-realistic-poc) :  ![starts](https://img.shields.io/github/stars/joshterrill/CVE-2025-55182-realistic-poc.svg) ![forks](https://img.shields.io/github/forks/joshterrill/CVE-2025-55182-realistic-poc.svg)
- [https://github.com/im-hanzou/CVE-2025-55182-POC-SCANNER](https://github.com/im-hanzou/CVE-2025-55182-POC-SCANNER) :  ![starts](https://img.shields.io/github/stars/im-hanzou/CVE-2025-55182-POC-SCANNER.svg) ![forks](https://img.shields.io/github/forks/im-hanzou/CVE-2025-55182-POC-SCANNER.svg)
- [https://github.com/aquinn-r7/CVE-2025-55182-VulnCheckPOC](https://github.com/aquinn-r7/CVE-2025-55182-VulnCheckPOC) :  ![starts](https://img.shields.io/github/stars/aquinn-r7/CVE-2025-55182-VulnCheckPOC.svg) ![forks](https://img.shields.io/github/forks/aquinn-r7/CVE-2025-55182-VulnCheckPOC.svg)
- [https://github.com/ZemarKhos/CVE-2025-55182-Exploit-PoC-Scanner](https://github.com/ZemarKhos/CVE-2025-55182-Exploit-PoC-Scanner) :  ![starts](https://img.shields.io/github/stars/ZemarKhos/CVE-2025-55182-Exploit-PoC-Scanner.svg) ![forks](https://img.shields.io/github/forks/ZemarKhos/CVE-2025-55182-Exploit-PoC-Scanner.svg)
- [https://github.com/oways/React2shell-CVE-2025-55182-checker](https://github.com/oways/React2shell-CVE-2025-55182-checker) :  ![starts](https://img.shields.io/github/stars/oways/React2shell-CVE-2025-55182-checker.svg) ![forks](https://img.shields.io/github/forks/oways/React2shell-CVE-2025-55182-checker.svg)
- [https://github.com/rpjboyarski/java4script](https://github.com/rpjboyarski/java4script) :  ![starts](https://img.shields.io/github/stars/rpjboyarski/java4script.svg) ![forks](https://img.shields.io/github/forks/rpjboyarski/java4script.svg)
- [https://github.com/Security-Phoenix-demo/freight-night-rce-react-next-CVE-2025-55182-CVE-2025-66478](https://github.com/Security-Phoenix-demo/freight-night-rce-react-next-CVE-2025-55182-CVE-2025-66478) :  ![starts](https://img.shields.io/github/stars/Security-Phoenix-demo/freight-night-rce-react-next-CVE-2025-55182-CVE-2025-66478.svg) ![forks](https://img.shields.io/github/forks/Security-Phoenix-demo/freight-night-rce-react-next-CVE-2025-55182-CVE-2025-66478.svg)
- [https://github.com/nxgn-kd01/react2shell-scanner](https://github.com/nxgn-kd01/react2shell-scanner) :  ![starts](https://img.shields.io/github/stars/nxgn-kd01/react2shell-scanner.svg) ![forks](https://img.shields.io/github/forks/nxgn-kd01/react2shell-scanner.svg)
- [https://github.com/tobiasGuta/Next.js-RSC-RCE-Scanner-Burp-Suite-Extension](https://github.com/tobiasGuta/Next.js-RSC-RCE-Scanner-Burp-Suite-Extension) :  ![starts](https://img.shields.io/github/stars/tobiasGuta/Next.js-RSC-RCE-Scanner-Burp-Suite-Extension.svg) ![forks](https://img.shields.io/github/forks/tobiasGuta/Next.js-RSC-RCE-Scanner-Burp-Suite-Extension.svg)
- [https://github.com/M0onPu15e/next.js-scanner](https://github.com/M0onPu15e/next.js-scanner) :  ![starts](https://img.shields.io/github/stars/M0onPu15e/next.js-scanner.svg) ![forks](https://img.shields.io/github/forks/M0onPu15e/next.js-scanner.svg)


## CVE-2025-48384
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When reading a config value, Git strips any trailing carriage return and line feed (CRLF). When writing a config entry, values with a trailing CR are not quoted, causing the CR to be lost when the config is later read. When initializing a submodule, if the submodule path contains a trailing CR, the altered path is read resulting in the submodule being checked out to an incorrect location. If a symlink exists that points the altered path to the submodule hooks directory, and the submodule contains an executable post-checkout hook, the script may be unintentionally executed after checkout. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.

- [https://github.com/zr0n/CVE-2025-48384-main](https://github.com/zr0n/CVE-2025-48384-main) :  ![starts](https://img.shields.io/github/stars/zr0n/CVE-2025-48384-main.svg) ![forks](https://img.shields.io/github/forks/zr0n/CVE-2025-48384-main.svg)
- [https://github.com/zr0n/CVE-2025-48384-sub](https://github.com/zr0n/CVE-2025-48384-sub) :  ![starts](https://img.shields.io/github/stars/zr0n/CVE-2025-48384-sub.svg) ![forks](https://img.shields.io/github/forks/zr0n/CVE-2025-48384-sub.svg)


## CVE-2025-38676
maximum length.

- [https://github.com/14mb1v45h/CVE-2025-38676](https://github.com/14mb1v45h/CVE-2025-38676) :  ![starts](https://img.shields.io/github/stars/14mb1v45h/CVE-2025-38676.svg) ![forks](https://img.shields.io/github/forks/14mb1v45h/CVE-2025-38676.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/jmbowes/NextSecureScan](https://github.com/jmbowes/NextSecureScan) :  ![starts](https://img.shields.io/github/stars/jmbowes/NextSecureScan.svg) ![forks](https://img.shields.io/github/forks/jmbowes/NextSecureScan.svg)


## CVE-2025-24091
 An app could impersonate system notifications. Sensitive notifications now require restricted entitlements. This issue is fixed in iOS 18.3 and iPadOS 18.3, iPadOS 17.7.3. An app may be able to cause a denial-of-service.

- [https://github.com/TS0NW0RK/DFURoulette](https://github.com/TS0NW0RK/DFURoulette) :  ![starts](https://img.shields.io/github/stars/TS0NW0RK/DFURoulette.svg) ![forks](https://img.shields.io/github/forks/TS0NW0RK/DFURoulette.svg)


## CVE-2025-13486
 The Advanced Custom Fields: Extended plugin for WordPress is vulnerable to Remote Code Execution in versions 0.9.0.5 through 0.9.1.1 via the prepare_form() function. This is due to the function accepting user input and then passing that through call_user_func_array(). This makes it possible for unauthenticated attackers to execute arbitrary code on the server, which can be leveraged to inject backdoors or create new administrative user accounts.

- [https://github.com/0xnemian/CVE-2025-13486.-CVE-2025-13486](https://github.com/0xnemian/CVE-2025-13486.-CVE-2025-13486) :  ![starts](https://img.shields.io/github/stars/0xnemian/CVE-2025-13486.-CVE-2025-13486.svg) ![forks](https://img.shields.io/github/forks/0xnemian/CVE-2025-13486.-CVE-2025-13486.svg)
- [https://github.com/0xanis/CVE-2025-13486-POC](https://github.com/0xanis/CVE-2025-13486-POC) :  ![starts](https://img.shields.io/github/stars/0xanis/CVE-2025-13486-POC.svg) ![forks](https://img.shields.io/github/forks/0xanis/CVE-2025-13486-POC.svg)
- [https://github.com/KrE80r/cve-2025-13486-vuln-setup](https://github.com/KrE80r/cve-2025-13486-vuln-setup) :  ![starts](https://img.shields.io/github/stars/KrE80r/cve-2025-13486-vuln-setup.svg) ![forks](https://img.shields.io/github/forks/KrE80r/cve-2025-13486-vuln-setup.svg)


## CVE-2025-12744
 A flaw was found in the ABRT daemon’s handling of user-supplied mount information.ABRT copies up to 12 characters from an untrusted input and places them directly into a shell command (docker inspect %s) without proper validation. An unprivileged local user can craft a payload that injects shell metacharacters, causing the root-running ABRT process to execute attacker-controlled commands and ultimately gain full root privileges.

- [https://github.com/initstring/abrt_root](https://github.com/initstring/abrt_root) :  ![starts](https://img.shields.io/github/stars/initstring/abrt_root.svg) ![forks](https://img.shields.io/github/forks/initstring/abrt_root.svg)


## CVE-2025-7338
 Multer is a node.js middleware for handling `multipart/form-data`. A vulnerability that is present starting in version 1.4.4-lts.1 and prior to version 2.0.2 allows an attacker to trigger a Denial of Service (DoS) by sending a malformed multi-part upload request. This request causes an unhandled exception, leading to a crash of the process. Users should upgrade to version 2.0.2 to receive a patch. No known workarounds are available.

- [https://github.com/r2c-CSE/multer-sca-rule-test_cve-2025-7338](https://github.com/r2c-CSE/multer-sca-rule-test_cve-2025-7338) :  ![starts](https://img.shields.io/github/stars/r2c-CSE/multer-sca-rule-test_cve-2025-7338.svg) ![forks](https://img.shields.io/github/forks/r2c-CSE/multer-sca-rule-test_cve-2025-7338.svg)


## CVE-2025-6980
 Captive Portal can expose sensitive information

- [https://github.com/BishopFox/CVE-2025-6980-check](https://github.com/BishopFox/CVE-2025-6980-check) :  ![starts](https://img.shields.io/github/stars/BishopFox/CVE-2025-6980-check.svg) ![forks](https://img.shields.io/github/forks/BishopFox/CVE-2025-6980-check.svg)


## CVE-2025-6394
 A vulnerability was found in code-projects Simple Online Hotel Reservation System 1.0. It has been declared as critical. Affected by this vulnerability is an unknown functionality of the file /add_reserve.php. The manipulation of the argument firstname leads to sql injection. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. Other parameters might be affected as well.

- [https://github.com/alexlee820/CVE-2025-63945-Tencent-iOA-EoP](https://github.com/alexlee820/CVE-2025-63945-Tencent-iOA-EoP) :  ![starts](https://img.shields.io/github/stars/alexlee820/CVE-2025-63945-Tencent-iOA-EoP.svg) ![forks](https://img.shields.io/github/forks/alexlee820/CVE-2025-63945-Tencent-iOA-EoP.svg)


## CVE-2024-29895
 Cacti provides an operational monitoring and fault management framework. A command injection vulnerability on the 1.3.x DEV branch allows any unauthenticated user to execute arbitrary command on the server when `register_argc_argv` option of PHP is `On`. In `cmd_realtime.php` line 119, the `$poller_id` used as part of the command execution is sourced from `$_SERVER['argv']`, which can be controlled by URL when `register_argc_argv` option of PHP is `On`. And this option is `On` by default in many environments such as the main PHP Docker image for PHP. Commit 53e8014d1f082034e0646edc6286cde3800c683d contains a patch for the issue, but this commit was reverted in commit 99633903cad0de5ace636249de16f77e57a3c8fc.

- [https://github.com/apaz-dev/CVE-2024-29895](https://github.com/apaz-dev/CVE-2024-29895) :  ![starts](https://img.shields.io/github/stars/apaz-dev/CVE-2024-29895.svg) ![forks](https://img.shields.io/github/forks/apaz-dev/CVE-2024-29895.svg)


## CVE-2024-9680
 An attacker was able to achieve code execution in the content process by exploiting a use-after-free in Animation timelines. We have had reports of this vulnerability being exploited in the wild. This vulnerability affects Firefox  131.0.2, Firefox ESR  128.3.1, Firefox ESR  115.16.1, Thunderbird  131.0.1, Thunderbird  128.3.1, and Thunderbird  115.16.0.

- [https://github.com/moscovium-mc/Tor-0day-JavaScript-Exploit](https://github.com/moscovium-mc/Tor-0day-JavaScript-Exploit) :  ![starts](https://img.shields.io/github/stars/moscovium-mc/Tor-0day-JavaScript-Exploit.svg) ![forks](https://img.shields.io/github/forks/moscovium-mc/Tor-0day-JavaScript-Exploit.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/pararam-org/CVE-2024-4577](https://github.com/pararam-org/CVE-2024-4577) :  ![starts](https://img.shields.io/github/stars/pararam-org/CVE-2024-4577.svg) ![forks](https://img.shields.io/github/forks/pararam-org/CVE-2024-4577.svg)


## CVE-2024-2928
 A Local File Inclusion (LFI) vulnerability was identified in mlflow/mlflow, specifically in version 2.9.2, which was fixed in version 2.11.3. This vulnerability arises from the application's failure to properly validate URI fragments for directory traversal sequences such as '../'. An attacker can exploit this flaw by manipulating the fragment part of the URI to read arbitrary files on the local file system, including sensitive files like '/etc/passwd'. The vulnerability is a bypass to a previous patch that only addressed similar manipulation within the URI's query string, highlighting the need for comprehensive validation of all parts of a URI to prevent LFI attacks.

- [https://github.com/rain321654/sjtu_CVE-2024-2928](https://github.com/rain321654/sjtu_CVE-2024-2928) :  ![starts](https://img.shields.io/github/stars/rain321654/sjtu_CVE-2024-2928.svg) ![forks](https://img.shields.io/github/forks/rain321654/sjtu_CVE-2024-2928.svg)


## CVE-2023-27163
 request-baskets up to v1.2.1 was discovered to contain a Server-Side Request Forgery (SSRF) via the component /api/baskets/{name}. This vulnerability allows attackers to access network resources and sensitive information via a crafted API request.

- [https://github.com/apaz-dev/CVE-2023-27163](https://github.com/apaz-dev/CVE-2023-27163) :  ![starts](https://img.shields.io/github/stars/apaz-dev/CVE-2023-27163.svg) ![forks](https://img.shields.io/github/forks/apaz-dev/CVE-2023-27163.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/TheLastVvV/CVE-2021-41773](https://github.com/TheLastVvV/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/TheLastVvV/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/TheLastVvV/CVE-2021-41773.svg)
- [https://github.com/Fa1c0n35/CVE-2021-41773](https://github.com/Fa1c0n35/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Fa1c0n35/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Fa1c0n35/CVE-2021-41773.svg)
- [https://github.com/vuongnv3389-sec/cve-2021-41773](https://github.com/vuongnv3389-sec/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/vuongnv3389-sec/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/vuongnv3389-sec/cve-2021-41773.svg)
- [https://github.com/skentagon/CVE-2021-41773](https://github.com/skentagon/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/skentagon/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/skentagon/CVE-2021-41773.svg)


## CVE-2021-3007
 Laminas Project laminas-http before 2.14.2, and Zend Framework 3.0.0, has a deserialization vulnerability that can lead to remote code execution if the content is controllable, related to the __destruct method of the Zend\Http\Response\Stream class in Stream.php. NOTE: Zend Framework is no longer supported by the maintainer. NOTE: the laminas-http vendor considers this a "vulnerability in the PHP language itself" but has added certain type checking as a way to prevent exploitation in (unrecommended) use cases where attacker-supplied data can be deserialized

- [https://github.com/KrE80r/cve-2021-3007-vulnerable](https://github.com/KrE80r/cve-2021-3007-vulnerable) :  ![starts](https://img.shields.io/github/stars/KrE80r/cve-2021-3007-vulnerable.svg) ![forks](https://img.shields.io/github/forks/KrE80r/cve-2021-3007-vulnerable.svg)
- [https://github.com/yunus-a1i/CVE-2021-3007-docker-poc](https://github.com/yunus-a1i/CVE-2021-3007-docker-poc) :  ![starts](https://img.shields.io/github/stars/yunus-a1i/CVE-2021-3007-docker-poc.svg) ![forks](https://img.shields.io/github/forks/yunus-a1i/CVE-2021-3007-docker-poc.svg)


## CVE-2019-1993
 In register_app of btif_hd.cc, there is a possible memory corruption due to an integer overflow. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. Product: Android. Versions: Android-8.0 Android-8.1 Android-9. Android ID: A-119819889.

- [https://github.com/bsmithbuf/VIVOTEK_CVE_2019_19936](https://github.com/bsmithbuf/VIVOTEK_CVE_2019_19936) :  ![starts](https://img.shields.io/github/stars/bsmithbuf/VIVOTEK_CVE_2019_19936.svg) ![forks](https://img.shields.io/github/forks/bsmithbuf/VIVOTEK_CVE_2019_19936.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock."  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/DrHaitham/CVE-2014-6271-Shellshock-](https://github.com/DrHaitham/CVE-2014-6271-Shellshock-) :  ![starts](https://img.shields.io/github/stars/DrHaitham/CVE-2014-6271-Shellshock-.svg) ![forks](https://img.shields.io/github/forks/DrHaitham/CVE-2014-6271-Shellshock-.svg)


## CVE-2010-4221
 Multiple stack-based buffer overflows in the pr_netio_telnet_gets function in netio.c in ProFTPD before 1.3.3c allow remote attackers to execute arbitrary code via vectors involving a TELNET IAC escape character to a (1) FTP or (2) FTPS server.

- [https://github.com/Mafiosohack/Offensive-lab-2](https://github.com/Mafiosohack/Offensive-lab-2) :  ![starts](https://img.shields.io/github/stars/Mafiosohack/Offensive-lab-2.svg) ![forks](https://img.shields.io/github/forks/Mafiosohack/Offensive-lab-2.svg)


## CVE-2002-0083
 Off-by-one error in the channel code of OpenSSH 2.0 through 3.0.2 allows local users or remote malicious servers to gain privileges.

- [https://github.com/stuxbench/dropbear-cve-2002-0083](https://github.com/stuxbench/dropbear-cve-2002-0083) :  ![starts](https://img.shields.io/github/stars/stuxbench/dropbear-cve-2002-0083.svg) ![forks](https://img.shields.io/github/forks/stuxbench/dropbear-cve-2002-0083.svg)

