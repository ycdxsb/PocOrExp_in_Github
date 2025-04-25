# Update 2025-04-25
## CVE-2025-32965
 xrpl.js is a JavaScript/TypeScript API for interacting with the XRP Ledger in Node.js and the browser. Versions 4.2.1, 4.2.2, 4.2.3, and 4.2.4 of xrpl.js were compromised and contained malicious code designed to exfiltrate private keys. Version 2.14.2 is also malicious, though it is less likely to lead to exploitation as it is not compatible with other 2.x versions. Anyone who used one of these versions should stop immediately and rotate any private keys or secrets used with affected systems. Users of xrpl.js should pgrade to version 4.2.5 or 2.14.3 to receive a patch. To secure funds, think carefully about whether any keys may have been compromised by this supply chain attack, and mitigate by sending funds to secure wallets, and/or rotating keys. If any account's master key is potentially compromised, disable the key.

- [https://github.com/yusufdalbudak/CVE-2025-32965-xrpl-js-poc](https://github.com/yusufdalbudak/CVE-2025-32965-xrpl-js-poc) :  ![starts](https://img.shields.io/github/stars/yusufdalbudak/CVE-2025-32965-xrpl-js-poc.svg) ![forks](https://img.shields.io/github/forks/yusufdalbudak/CVE-2025-32965-xrpl-js-poc.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/tobiasGuta/Erlang-OTP-CVE-2025-32433](https://github.com/tobiasGuta/Erlang-OTP-CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/tobiasGuta/Erlang-OTP-CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/tobiasGuta/Erlang-OTP-CVE-2025-32433.svg)


## CVE-2025-31137
 React Router is a multi-strategy router for React bridging the gap from React 18 to React 19. There is a vulnerability in Remix/React Router that affects all Remix 2 and React Router 7 consumers using the Express adapter. Basically, this vulnerability allows anyone to spoof the URL used in an incoming Request by putting a URL pathname in the port section of a URL that is part of a Host or X-Forwarded-Host header sent to a Remix/React Router request handler. This issue has been patched and released in Remix 2.16.3 and React Router 7.4.1.

- [https://github.com/pouriam23/vulnerability-in-Remix-React-Router-CVE-2025-31137-](https://github.com/pouriam23/vulnerability-in-Remix-React-Router-CVE-2025-31137-) :  ![starts](https://img.shields.io/github/stars/pouriam23/vulnerability-in-Remix-React-Router-CVE-2025-31137-.svg) ![forks](https://img.shields.io/github/forks/pouriam23/vulnerability-in-Remix-React-Router-CVE-2025-31137-.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/kh4sh3i/CVE-2025-29927](https://github.com/kh4sh3i/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/kh4sh3i/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/kh4sh3i/CVE-2025-29927.svg)


## CVE-2025-24963
 Vitest is a testing framework powered by Vite. The `__screenshot-error` handler on the browser mode HTTP server that responds any file on the file system. Especially if the server is exposed on the network by `browser.api.host: true`, an attacker can send a request to that handler from remote to get the content of arbitrary files.This `__screenshot-error` handler on the browser mode HTTP server responds any file on the file system. This code was added by commit `2d62051`. Users explicitly exposing the browser mode server to the network by `browser.api.host: true` may get any files exposed. This issue has been addressed in versions 2.1.9 and 3.0.4. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/0xdeviner/CVE-2025-24963](https://github.com/0xdeviner/CVE-2025-24963) :  ![starts](https://img.shields.io/github/stars/0xdeviner/CVE-2025-24963.svg) ![forks](https://img.shields.io/github/forks/0xdeviner/CVE-2025-24963.svg)


## CVE-2024-49138
 Windows Common Log File System Driver Elevation of Privilege Vulnerability

- [https://github.com/CyprianAtsyor/letsdefend-cve-2024-49138-investigation](https://github.com/CyprianAtsyor/letsdefend-cve-2024-49138-investigation) :  ![starts](https://img.shields.io/github/stars/CyprianAtsyor/letsdefend-cve-2024-49138-investigation.svg) ![forks](https://img.shields.io/github/forks/CyprianAtsyor/letsdefend-cve-2024-49138-investigation.svg)


## CVE-2024-27876
 A race condition was addressed with improved locking. This issue is fixed in macOS Ventura 13.7, iOS 17.7 and iPadOS 17.7, visionOS 2, iOS 18 and iPadOS 18, macOS Sonoma 14.7, macOS Sequoia 15. Unpacking a maliciously crafted archive may allow an attacker to write arbitrary files.

- [https://github.com/0xilis/CVE-2024-27876](https://github.com/0xilis/CVE-2024-27876) :  ![starts](https://img.shields.io/github/stars/0xilis/CVE-2024-27876.svg) ![forks](https://img.shields.io/github/forks/0xilis/CVE-2024-27876.svg)

