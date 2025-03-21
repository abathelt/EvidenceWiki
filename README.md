## EvidenceWiki
All of my threat intel recommendations for aspiring Information Security Analyst. This section contains information about evidence at analyst's disposal `IP`, `domain`, `email`, `hash`, `files`.
- 💻 [Domain & IP](#domain-ip)
- 📁 [Files, Hash & Sandbox](#files-hashes)
- 🐟 [Phishing](#phish-ing)
- 👤 [UserAgent](#user-agent)
- ⛏️ [Miner](#min-er)
- 🖹 [Encoder/Decoder](#encode-decode)
- 🔎 [Google Dorks](#google-dork)
- 🌐 [OSINT](#osint-fav)
- 📖 [Dumps](#dum-ps)
- 🐛 [Vulnerabilities](#vuln)
- 🔄 [URL Sshorteners](#short)
- 🔑 [List of Default Passwords](#list-dp)
- 🧰 [Forensic](#forensic-list)
- 📋 [Cheatsheet](#cheat-sheet)
- ✍️ [Effective writing](#effective-write)
- 👩‍🎓 [Education resources](https://github.com/abathelt/Resources/blob/main/README.md)

#### Useful Extention
- [Mitaka - Chrome](https://chrome.google.com/webstore/detail/mitaka/bfjbejmeoibbdpfdbmbacmefcbannnbg/related?authuser=0) - for searching IP, domain, URL, hash, etc. via the context menu.
- [Mitaka - Firefox]([https://chrome.google.com/webstore/detail/mitaka/bfjbejmeoibbdpfdbmbacmefcbannnbg/related?authuser=0](https://addons.mozilla.org/en-US/firefox/addon/mitaka/)) - for searching IP, domain, URL, hash, etc. via the context menu.

### Threat Intel Resources 
Threat intel resource used by analysts on a daily basis.

#### <a name="domain-ip"></a>💻 Domain & IP (top 6 are the most used by me)
- [AbuseIPDB](https://www.abuseipdb.com/) 
- [Talos Intelligence](https://talosintelligence.com/)
- [VirtusTotal](https://www.virustotal.com/gui/)
- [WhoIs](https://whois.domaintools.com/)
- [Redirect tracker](https://www.websiteplanet.com/webtools/redirected/?url=)
- [Cyren IP Reputation Check](https://www.cyren.com/security-center/cyren-ip-reputation-check-gate)
- [URL Query](https://urlquery.net/) - employs a diverse range of threat detection systems to ensure comprehensive security analysis of URLs. 
- [CyberGordon](https://cybergordon.com/) - provides you threat and risk information about observables like IP address or web domain
- [Abuse.ch](https://abuse.ch/) - to identify and track malware and botnets
- [URL2PNG](https://www.url2png.com/) - does a screenshot of the website
- [URLScan](https://urlscan.io/)
- [Robtex](https://www.robtex.com/) - used for various kinds of research of IP numbers, Domain names, etc
- [AlienVault](https://otx.alienvault.com/browse/global/pulses?include_inactive=0&sort=-modified&page=1)
- [RiskIQ](https://community.riskiq.com/home)
- [ThreatCrowd](https://www.threatcrowd.org/) 
- [IPVoid](https://www.ipvoid.com/)
- [TI Search Engine](https://maltiverse.com/search)
- [Shodan](https://www.shodan.io/) - IoT search
- [Gray Hat Warfare](https://buckets.grayhatwarfare.com/) - public buckets 
- [GrayNoise](https://viz.greynoise.io/)
- [DNSdumpster](https://dnsdumpster.com/) 
- [URLVoid](https://www.urlvoid.com/) 
- [Polyswarm](https://polyswarm.network/)
- [Forecpoint CSI (URL/IP)](http://csi.forcepoint.com/) 
- [Domain Dossier](https://centralops.net/co/DomainDossier.aspx) 
- [URLhaus](https://urlhaus.abuse.ch/browse/) 
- [Browse Botnet C&Cs](https://feodotracker.abuse.ch/browse/) 
- [Etherscan](https://etherscan.io/) - Blockchain Explorer 
- [ReversDNS](https://viewdns.info/reversewhois/) 
- [DNSRecord](https://viewdns.info/dnsrecord/)
- [CentralOPS](https://centralops.net/co/) - domain check
- [Have I been Squatted](https://www.haveibeensquatted.com/) - Check if a domain has been typosquatted

#### <a name="files-hashes"></a>📁 Files, Hash & Sandbox (DO NOT upload internal files!) 
- [VirtusTotal](https://www.virustotal.com/gui/)
- [Malware Hash Registry (MHR)](https://hash.cymru.com/) - checking hashes against malware data
- [InQuest Labs](https://labs.inquest.net/)
- [ThreatMiner](https://www.threatminer.org/) - sata mining for threat intelligence (hash/IP/URL)
- [Metadefender Cloud - OPSWAT](https://metadefender.opswat.com/)
- [Any.Run](https://app.any.run/) - sandbox
- [VirSCAN.org](http://virscan.org/)
- [TotalHash](https://totalhash.cymru.com/)
- [CTX](https://www.ctx.io/) - korean website but really good
- [Intezer analyze](https://analyze.intezer.com/) - All malware analysis tools under one platform
- [Cuckoo](https://cuckoo.cert.ee/) - sandbox
- [Joe Sandbox](https://www.joesandbox.com/#windows) 
- [Analyzing Malicious Documents Cheat sheet](https://www.sans.org/security-resources/posters/dfir/)
- [30 Online Malware Analysis Sandboxes / Static Analyzers](https://redteamer.medium.com/15-online-sandboxes-for-malware-analysis-f8885ecb8a35)

#### <a name="phish-ing"></a>🐟 Phishing 
- [EmailRep](https://emailrep.io/)
- [Verify-Email](https://verify-email.org/)
- [MX Toolbox](https://mxtoolbox.com/SuperTool.aspx) - All of your MX record, DNS, blacklist and SMTP diagnostics in one integrated tool.
- [PhishTank](https://www.phishtank.com/)
- [castrickclues](https://castrickclues.com/)
- [Spy Dialer](https://www.spydialer.com/default.aspx)
- [CheckPhish](https://checkphish.ai/)
- [Reverse Email Lookup](https://thatsthem.com/reverse-email-lookup)
- [Have I Been Pwned](https://haveibeenpwned.com/)
- [Have I Been Sold](https://haveibeensold.app/)
- [email-finder](https://snov.io/email-finder) - searching emails for a specific domain
- [experte](https://experte.com/email-finder) - searching emails for a specific domain
- [Infoga - github](https://github.com/GiJ03/Infoga) - searching emails for a specific domain
- [findemail](https://findemail.io) - searching emails for a specific domain
- [hunter - Domain search](https://hunter.io/domain-search) - searching emails for a specific domain
- [minelead](https://minelead.io) - searching emails for a specific domain
- [intelbase](https://intelbase.is/) - have I been pwned on steroids
- [breachdirectory](https://breachdirectory.org/) - CHECK IF YOUR EMAIL OR USERNAME WAS COMPROMISED
- [scamsearch](https://scamsearch.io/#anchorCeckNow)
- [holehe](https://github.com/megadose/holehe) - Efficiently finding registered accounts from emails.
- [mailcat](https://github.com/sharsil/mailcat) - The only cat who can find existing email addresses by nickname.
- [Confense webinar "Remote Work Phishing Threats and How to Stop Them"](https://vimeo.com/418602022/7935ced585)

#### <a name="user-agent"></a>👤 UserAgent: 
- [UserAgentString](http://useragentstring.com/)
- [ParseUserAegnt](https://developers.whatismybrowser.com/useragents/parse/#parse-useragent)
- [History of the browser user-agent string](https://webaim.org/blog/user-agent-string-history/)

#### <a name="min-er"></a>⛏️ Miner/Blockchain
- [Block Cypher](https://live.blockcypher.com/) - search the block chain
- [Ether Chain](https://www.etherchain.org/) - The Ethereum Block Chain Explorer

#### <a name="encode-decode"></a>🖹 Encode/Decode 
- [CyberChef](https://gchq.github.io/CyberChef/) - encryption, encoding, compression and data analysis.
- [Puny Coder](https://www.punycoder.com/) - is a special encoding used to convert Unicode characters to ASCII, which is a smaller, restricted character set. Punycode is used to encode internationalized domain names (IDN).
- [BASE64](https://www.base64decode.org/) - Decode from Base64 format or encode into it with various advanced options. 
- [Hexed](https://hexed.it/) - analyse and edit binary files everywhere
- [Uncoder](https://uncoder.io/) - Universal sigma rule converter for various siem, edr, and ntdr formats
- [ShellCheck](https://www.shellcheck.net/) - finds bugs in your shell scripts.
- [Explain shell code](https://explainshell.com/) - write down a command-line to see the help text that matches each argument
- [Dan's Tools - Base64](https://www.url-encode-decode.com/base64-encode-decode/)
- [Code Decode/Encoder](https://www.browserling.com/tools/utf16-encode)
- [Script converter](https://www.freeformatter.com/javascript-beautifier.html#ad-output) - These tools include several formatters, validators, code minifiers, string escapers, encoders and decoders, message digesters, web resources and more
- [Hash Analyzer](https://www.tunnelsup.com/hash-analyzer/)
- [Hashes examples](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [Filecrypt](https://filecrypt.co/Create.html) - The simple, secure file-hosting application
- [PSDecode](https://github.com/R3MRUM/PSDecode) - This is a PowerShell script for deobfuscating other encoded PowerShell scripts. 

#### <a name="google-dork"></a>🔎 Google Dorks 
- [OSINTcurio.us](https://osintcurio.us/2019/12/20/google-dorks/)
- [ahrefs](https://ahrefs.com/blog/google-advanced-search-operators/)
- [Cheatsheet](http://www.googleguide.com/print/adv_op_ref.pdf)

#### <a name="osint-fav"></a>🌐 OSINT 
- [OSINT Framework](https://osintframework.com/)
- [Start.me The Ultimate OSINT collection](https://start.me/p/DPYPMz/the-ultimate-osint-collection)
- [OSINT ME](https://www.osintme.com/)
- [Start.me OSINT](https://start.me/p/ZME8nR/osint)
- [Start.me OSINT Tools](https://start.me/p/7kxyy2/osint-tools-curated-by-lorand-bodo)
- [Start.me Open Source Intelligence (OSINT) ](https://start.me/p/gy0NXp/open-source-intelligence-osint)
- [OSINT collection github](https://github.com/Ph055a/OSINT_Collection#pastebins)
- [Explot Database](https://www.exploit-db.com/google-hacking-database)
- [DSNTwits - TypoSquatting](https://dnstwister.report/)
- [IntelTechniques by Michael Bazzell](https://inteltechniques.com/links.html)

#### <a name="dum-ps"></a>📖 Dumps 
- [PSbdmp](https://psbdmp.ws/)
- [Pastebin](https://pastebin.com/)

#### <a name="vuln"></a>🐛 Vulnerabilities 
- [CVE Trends](https://cvetrends.com/)
- [Exploit DB](https://www.exploit-db.com/)
- [AttackerKB](https://attackerkb.com/)
- [Rapid7 DB](https://www.rapid7.com/db/)
- [NIST NVD](https://nvd.nist.gov/vuln/search)
- [MITRE CVE](https://cve.mitre.org/cve/search_cve_list.html)
- [CVE details](https://www.cvedetails.com/)

#### Malware
- [Dasmalwerk](https://dasmalwerk.eu/) - malware samples
- [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/training-exercises.html) - traffic analysis exercises

#### <a name="short"></a>🔄 URL Shorteners
- [bit.ly](https://bitly.com/) - You can verify the destination of any Bitly link by adding a plus symbol ("+") at the end of the URL (e.g. bitly.is/meta+) 
- [s.id](https://home.s.id/)
- [smarturl.it](https://manage.smarturl.it/)
- [tiny.pl](https://tiny.pl/)
- [tinyurl.com](https://tinyurl.com/app)
- [x.co](https://shortener.godaddy.com/)

#### <a name="list-dp"></a>🔑 List of Default Passwords 
- [Data Recovery](https://datarecovery.com/rd/default-passwords/)

#### <a name="forensic-list"></a>🧰 Forensic
- [Start.me Forensics](https://start.me/p/q6mw4Q/forensics)
- [Start.me Digital Forensic](https://start.me/p/ekq7Al/digital-forensics)

### OTHER
#### <a name="cheat-sheet"></a>📋 CheatSheets 
- [DIRF cheatsheet](https://www.dfir.training/cheat-sheets)
- [Zelter's Security Incident Survey Cheat Sheet](https://www.sans.org/reading-room/whitepapers/incident/incident-handlers-handbook-33901)

#### <a name="effective-write"></a>✍️ Effective Writing  
- [Better Threat Reports](https://zeltser.com/write-better-threat-reports)
- [Language Tool](https://languagetool.org/)
- [Grammarly](https://app.grammarly.com/)
- [How to Ask Questions to Succeed with Security Projects](https://zeltser.com/how-to-ask-questions-to-succeed-with-security-projects/)

