const tools = [
  { id: 'virustotal', name: 'VirusTotal', desc: 'File / URL / IP scans', url: 'https://www.virustotal.com/', category: 'security' },
  { id: 'shodan', name: 'Shodan', desc: 'Host search', url: 'https://www.shodan.io/', category: 'security' },
  { id: 'censys', name: 'Censys', desc: 'Internet-wide search', url: 'https://search.censys.io/', category: 'security' },

  //? Search engines
  { id: 'google', name: 'Google Search', desc: 'Web search', url: 'https://www.google.com/', category: 'search' },
  { id: 'bing', name: 'Bing', desc: 'Web search', url: 'https://www.bing.com/', category: 'search' },
  { id: 'duckduckgo', name: 'DuckDuckGo', desc: 'Privacy search', url: 'https://duckduckgo.com/', category: 'search' },
  { id: 'yahoo', name: 'Yahoo! Search', desc: 'Web search', url: 'https://search.yahoo.com/', category: 'search' },
  { id: 'aol', name: 'AOL Search', desc: 'Web search', url: 'https://search.aol.com/', category: 'search' },
  { id: 'ask', name: 'Ask', desc: 'Web search', url: 'https://www.ask.com/', category: 'search' },
  { id: 'brave', name: 'Brave Search', desc: 'Privacy-first search', url: 'https://search.brave.com/', category: 'search' },
  { id: 'you', name: 'YOU.com', desc: 'AI-assisted search', url: 'https://you.com/', category: 'search' },
  { id: 'kagi', name: 'Kagi', desc: 'Premium search', url: 'https://kagi.com/', category: 'search' },
  { id: 'qwant', name: 'Qwant', desc: 'Privacy search', url: 'https://www.qwant.com/', category: 'search' },
  { id: 'startpage', name: 'Startpage', desc: 'Privacy search', url: 'https://www.startpage.com/', category: 'search' },
  { id: 'mojeek', name: 'Mojeek', desc: 'Independent search engine', url: 'https://www.mojeek.com/', category: 'search' },
  { id: 'presearch', name: 'Presearch', desc: 'Decentralized search', url: 'https://presearch.org/', category: 'search' },
  { id: 'gibiru', name: 'Gibiru', desc: 'Uncensored search', url: 'https://gibiru.com/', category: 'search' },
  { id: 'searchencrypt', name: 'Search Encrypt', desc: 'Encrypted search', url: 'https://www.searchencrypt.com/', category: 'search' },
  { id: 'swisscows', name: 'Swisscows', desc: 'Semantic search', url: 'https://swisscows.com/', category: 'search' },
  { id: 'yandex', name: 'Yandex', desc: 'Web search', url: 'https://yandex.com/', category: 'search' },
  { id: 'wow', name: 'Wolfram Alpha', desc: 'Computational search', url: 'https://www.wolframalpha.com/', category: 'search' },
  { id: 'ghdb', name: 'Google Hacking Database', desc: 'ExploitDB Dorks', url: 'https://www.exploit-db.com/google-hacking-database', category: 'search' },

  //? OSINT specific
  { id: 'urlscan', name: 'URLscan', desc: 'Website scanning and screenshots', url: 'https://urlscan.io/', category: 'osint' },
  { id: 'hybrid', name: 'Hybrid-Analysis', desc: 'Malware analysis', url: 'https://www.hybrid-analysis.com/', category: 'osint' },
  { id: 'anyrun', name: 'ANY.RUN', desc: 'Interactive malware sandbox', url: 'https://any.run/', category: 'osint' },
  { id: 'malwarebazaar', name: 'MalwareBazaar', desc: 'Malware sample database', url: 'https://bazaar.abuse.ch/', category: 'osint' },
  { id: 'otx', name: 'AlienVault OTX', desc: 'Threat intel pulses', url: 'https://otx.alienvault.com/', category: 'osint' },
  { id: 'greynoise', name: 'GreyNoise', desc: 'Internet noise intel', url: 'https://www.greynoise.io/', category: 'osint' },
  { id: 'riskiq', name: 'RiskIQ / PassiveTotal', desc: 'Passive DNS and risk intel', url: 'https://community.riskiq.com/', category: 'osint' },
  { id: 'cirtc', name: 'CIRCL Passive DNS', desc: 'Passive DNS', url: 'https://www.circl.lu/pdns/', category: 'osint' },
  { id: 'threatfox', name: 'ThreatFox', desc: 'Malware IOCs', url: 'https://threatfox.abuse.ch/', category: 'osint' },
  { id: 'threatcrowd', name: 'ThreatCrowd', desc: 'Threat intelligence', url: 'https://www.threatcrowd.org/', category: 'osint' },
  { id: 'zoomeye', name: 'ZoomEye', desc: 'Internet asset search', url: 'https://www.zoomeye.org/', category: 'osint' },
  { id: 'binaryedge', name: 'BinaryEdge', desc: 'Internet attack surface', url: 'https://app.binaryedge.io/', category: 'osint' },
  { id: 'fofa', name: 'FOFA', desc: 'Asset search engine', url: 'https://fofa.so/', category: 'osint' },
  { id: 'spyse', name: 'Spyse', desc: 'Cyber asset search', url: 'https://spyse.com/', category: 'osint' },
  { id: 'ipinfo', name: 'IPinfo', desc: 'IP geolocation & data', url: 'https://ipinfo.io/', category: 'osint' },
  { id: 'abuseipdb', name: 'AbuseIPDB', desc: 'Abuse reports for IPs', url: 'https://www.abuseipdb.com/', category: 'osint' },
  { id: 'crtsh', name: 'crt.sh', desc: 'Certificate transparency search', url: 'https://crt.sh/', category: 'osint' },
  { id: 'securitytrails', name: 'SecurityTrails', desc: 'Domain & DNS history', url: 'https://securitytrails.com/', category: 'osint' },
  { id: 'dnslytics', name: 'DNSlytics', desc: 'DNS & WHOIS lookup', url: 'https://www.dnslytics.com/', category: 'osint' },
  { id: 'whoisdomaintools', name: 'Whois / DomainTools', desc: 'Domain registration', url: 'https://whois.domaintools.com/', category: 'osint' },
  { id: 'viewdns', name: 'ViewDNS', desc: 'DNS tools', url: 'https://viewdns.info/', category: 'osint' },
  { id: 'mx', name: 'MxToolbox', desc: 'DNS and blacklist checks', url: 'https://mxtoolbox.com/', category: 'osint' },
  { id: 'ssllabs', name: 'SSL Labs', desc: 'SSL/TLS assessment', url: 'https://www.ssllabs.com/ssltest/', category: 'osint' },
  { id: 'talos', name: 'Cisco Talos', desc: 'Reputation center', url: 'https://talosintelligence.com/', category: 'osint' },
  { id: 'intelx', name: 'Intelligence X', desc: 'Search archive & darkweb', url: 'https://intelx.io/', category: 'osint' },
  { id: 'builtwith', name: 'BuiltWith', desc: 'Web technology profiler', url: 'https://builtwith.com/', category: 'osint' },
  { id: 'dnsdumpster', name: 'DNSDumpster', desc: 'DNS reconnaissance', url: 'https://dnsdumpster.com/', category: 'osint' },
  { id: 'wigle', name: 'WiGLE', desc: 'Wireless network mapping', url: 'https://wigle.net/', category: 'osint' },

  //? Archives
  { id: 'wayback', name: 'Wayback Machine', desc: 'Archived webpages', url: 'https://web.archive.org/', category: 'archive' },
  { id: 'archive_today', name: 'archive.today', desc: 'Save / view snapshots', url: 'https://archive.today/', category: 'archive' },
  { id: 'internet_archive', name: 'Internet Archive', desc: 'Archive.org', url: 'https://archive.org/', category: 'archive' },

  //? Code & Repo
  { id: 'github', name: 'GitHub Search', desc: 'Code & repo search', url: 'https://github.com/', category: 'code' },
  { id: 'gitgrep', name: 'grep.app', desc: 'Code search', url: 'https://grep.app/', category: 'code' },
  { id: 'searchcode', name: 'SearchCode', desc: 'Code search', url: 'https://searchcode.com/', category: 'code' },
  { id: 'sourcegraph', name: 'SourceGraph', desc: 'Code search across repos', url: 'https://sourcegraph.com/', category: 'code' },
  { id: 'publicwww', name: 'PublicWWW', desc: 'Find sites using code/snippets', url: 'https://publicwww.com/', category: 'code' },
  { id: 'nerdydata', name: 'NerdyData', desc: 'Code and data search', url: 'https://www.nerdydata.com/', category: 'code' },

  //? People
  { id: 'pipl', name: 'Pipl', desc: 'People search (paid)', url: 'https://pipl.com/', category: 'people' },
  { id: 'hunter', name: 'Hunter.io', desc: 'Email discovery', url: 'https://hunter.io/', category: 'people' },
  { id: 'clearbit', name: 'Clearbit', desc: 'Company / person lookup', url: 'https://clearbit.com/', category: 'people' },
  { id: 'fullcontact', name: 'FullContact', desc: 'Contact enrichment', url: 'https://www.fullcontact.com/', category: 'people' },
  { id: 'zoominfo', name: 'ZoomInfo', desc: 'Business intelligence', url: 'https://www.zoominfo.com/', category: 'people' },
  { id: 'hibp', name: 'Have I Been Pwned', desc: 'Breach check', url: 'https://haveibeenpwned.com/', category: 'people' },
  { id: 'epieos', name: 'Epieos', desc: 'Email & Phone reverse lookup', url: 'https://epieos.com/', category: 'people' },
  { id: 'whatsmyname', name: 'WhatsMyName', desc: 'Username enumeration', url: 'https://whatsmyname.app/', category: 'people' },

  //? Paste sites
  { id: 'pastebin', name: 'Pastebin', desc: 'Popular paste site', url: 'https://pastebin.com/', category: 'paste' },
  { id: 'pastesearches', name: 'Hunting Abuse.ch', desc: 'Malicious pastes', url: 'https://hunting.abuse.ch/', category: 'paste' },
  { id: 'gist', name: 'GitHub Gist', desc: 'Code snippets', url: 'https://gist.github.com/', category: 'paste' },

  //? Social
  { id: 'pushshift', name: 'Pushshift', desc: 'Reddit data provider', url: 'https://search.pushshift.io/', category: 'social' },
  { id: 'socialsearcher', name: 'Social Searcher', desc: 'Social media search', url: 'https://www.social-searcher.com/', category: 'social' },

  //?   Image
  { id: 'tineye', name: 'TinEye', desc: 'Reverse image search', url: 'https://tineye.com/', category: 'image' },
  { id: 'exifviewer', name: 'Exif Viewer', desc: 'Image metadata', url: 'https://exif-viewer.com/', category: 'image' },
  { id: 'imgur', name: 'Imgur Search', desc: 'Imgur image search', url: 'https://imgur.com/', category: 'image' },

  //? Domain & Business
  { id: 'opencorporates', name: 'OpenCorporates', desc: 'Company data', url: 'https://opencorporates.com/', category: 'business' },
  { id: 'crunchbase', name: 'Crunchbase', desc: 'Company intelligence', url: 'https://www.crunchbase.com/', category: 'business' },
  { id: 'whoisxml', name: 'WhoisXML API', desc: 'WHOIS and domain data', url: 'https://whoisxmlapi.com/', category: 'business' },

  //? Miscellaneous
  { id: 'osintframework', name: 'OSINT Framework', desc: 'OSINT tool map', url: 'https://osintframework.com/', category: 'misc' },
  { id: 'spiderfoot', name: 'SpiderFoot HX', desc: 'Automated OSINT scanner', url: 'https://www.spiderfoot.net/', category: 'misc' },
  { id: 'maltego', name: 'Maltego', desc: 'Graph-based link analysis', url: 'https://www.maltego.com/', category: 'misc' },
  { id: 'amass', name: 'Amass', desc: 'Asset discovery (tool)', url: 'https://github.com/OWASP/Amass', category: 'misc' },
  { id: 'theharvester', name: 'theHarvester', desc: 'OSINT email/host discovery', url: 'https://github.com/laramies/theHarvester', category: 'misc' },
  { id: 'reconng', name: 'Recon-ng', desc: 'Web reconnaissance framework', url: 'https://github.com/lanmaster53/recon-ng', category: 'misc' },
  { id: 'osintcombine', name: 'OSINT Combine Tools', desc: 'Tools collection', url: 'https://www.osintcombine.com/tools', category: 'misc' },
  { id: 'darksearch', name: 'DarkSearch', desc: 'Search dark web', url: 'https://darksearch.io/', category: 'misc' },
  { id: 'leakix', name: 'LeakIX', desc: 'Exposed assets', url: 'https://leakix.net/', category: 'misc' },
  { id: 'filepursuit', name: 'FilePursuit', desc: 'File search engine', url: 'https://filepursuit.com/', category: 'misc' },
  { id: 'wpscan', name: 'WPSCAN', desc: 'WordPress vulnerability scanner', url: 'https://wpscan.com/', category: 'misc' },
  { id: 'netlas', name: 'Netlas', desc: 'Netlas asset search', url: 'https://app.netlas.io/', category: 'misc' },
];