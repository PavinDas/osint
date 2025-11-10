const tools = [
  { id: 'virustotal', name: 'VirusTotal', desc: 'File / URL / IP scans', url: 'https://www.virustotal.com/gui/search/{query}' },
  { id: 'shodan', name: 'Shodan', desc: 'Host search', url: 'https://www.shodan.io/host/{query}' },
  { id: 'censys', name: 'Censys', desc: 'Internet-wide search', url: 'https://search.censys.io/search?resource=hosts&q={query}' },

  // ! Search engines
  { id: 'google', name: 'Google Search', desc: 'Web search', url: 'https://www.google.com/search?q={query}' },
  { id: 'bing', name: 'Bing', desc: 'Web search', url: 'https://www.bing.com/search?q={query}' },
  { id: 'duckduckgo', name: 'DuckDuckGo', desc: 'Privacy search', url: 'https://duckduckgo.com/?q={query}' },
  { id: 'yahoo', name: 'Yahoo! Search', desc: 'Web search', url: 'https://search.yahoo.com/search?p={query}' },
  { id: 'aol', name: 'AOL Search', desc: 'Web search', url: 'https://search.aol.com/aol/search?q={query}' },
  { id: 'ask', name: 'Ask', desc: 'Web search', url: 'https://www.ask.com/web?q={query}' },
  { id: 'brave', name: 'Brave Search', desc: 'Privacy-first search', url: 'https://search.brave.com/search?q={query}' },
  { id: 'you', name: 'YOU.com', desc: 'AI-assisted search', url: 'https://you.com/search?q={query}' },
  { id: 'kagi', name: 'Kagi', desc: 'Premium search', url: 'https://kagi.com/search?q={query}' },
  { id: 'qwant', name: 'Qwant', desc: 'Privacy search', url: 'https://www.qwant.com/?q={query}' },
  { id: 'startpage', name: 'Startpage', desc: 'Privacy search', url: 'https://www.startpage.com/sp/search?q={query}' },
  { id: 'duckduckgo_simple', name: 'DuckDuckGo (alt)', desc: 'Search', url: 'https://duckduckgo.com/?q={query}' },
  { id: 'mojeek', name: 'Mojeek', desc: 'Independent search engine', url: 'https://www.mojeek.com/search?q={query}' },
  { id: 'presearch', name: 'Presearch', desc: 'Decentralized search', url: 'https://presearch.org/search?q={query}' },
  { id: 'gibiru', name: 'Gibiru', desc: 'Uncensored search', url: 'https://gibiru.com/search?q={query}' },
  { id: 'brave_search', name: 'Brave (alt)', desc: 'Search', url: 'https://search.brave.com/search?q={query}' },
  { id: 'searchencrypt', name: 'Search Encrypt', desc: 'Encrypted search', url: 'https://www.searchencrypt.com/search.php?q={query}' },
  { id: 'swisscows', name: 'Swisscows', desc: 'Semantic search', url: 'https://swisscows.com/web?query={query}' },
  { id: 'qwant_alt', name: 'Qwant (alt)', desc: 'Search', url: 'https://www.qwant.com/?q={query}' },
  { id: 'you_alt', name: 'YOU (alt)', desc: 'AI search', url: 'https://you.com/search?q={query}' },
  { id: 'kagi_alt', name: 'Kagi (alt)', desc: 'Search', url: 'https://kagi.com/search?q={query}' },
  { id: 'instya', name: 'Instya', desc: 'Search engine', url: 'https://www.instya.com/search?q={query}' },
  { id: 'lycos', name: 'Lycos', desc: 'Search engine', url: 'https://search.lycos.com/web/?q={query}' },
  { id: 'searchcom', name: 'Search.com', desc: 'Search engine', url: 'https://www.search.com/search?q={query}' },
  { id: 'yandex', name: 'Yandex', desc: 'Web search', url: 'https://yandex.com/search/?text={query}' },
  { id: 'wow', name: 'Wolfram Alpha', desc: 'Computational search', url: 'https://www.wolframalpha.com/input?i={query}' },
  { id: 'goodsearch', name: 'Goodsearch', desc: 'Charity-focused search', url: 'https://www.goodsearch.com/search?q={query}' },
  { id: 'ask_alt', name: 'Ask (alt)', desc: 'Search', url: 'https://www.ask.com/web?q={query}' },

  // ! OSINT specific
  { id: 'urlscan', name: 'URLscan', desc: 'Website scanning and screenshots', url: 'https://urlscan.io/search/#{query}' },
  { id: 'hybrid', name: 'Hybrid-Analysis', desc: 'Malware analysis', url: 'https://www.hybrid-analysis.com/search?query={query}' },
  { id: 'anyrun', name: 'ANY.RUN', desc: 'Interactive malware sandbox', url: 'https://any.run/search/?q={query}' },
  { id: 'malwarebazaar', name: 'MalwareBazaar', desc: 'Malware sample database', url: 'https://bazaar.abuse.ch/browse/{query}' },
  { id: 'otx', name: 'AlienVault OTX', desc: 'Threat intel pulses', url: 'https://otx.alienvault.com/indicator/{query}' },
  { id: 'greynoise', name: 'GreyNoise', desc: 'Internet noise intel', url: 'https://www.greynoise.io/search?query={query}' },
  { id: 'riskiq', name: 'RiskIQ / PassiveTotal', desc: 'Passive DNS and risk intel', url: 'https://community.riskiq.com/search/?q={query}' },
  { id: 'cirtc', name: 'CIRCL Passive DNS', desc: 'Passive DNS', url: 'https://www.circl.lu/pdns/?q={query}' },
  { id: 'threatfox', name: 'ThreatFox', desc: 'Malware IOCs', url: 'https://threatfox.abuse.ch/browse.php?search={query}' },
  { id: 'threatcrowd', name: 'ThreatCrowd', desc: 'Threat intelligence', url: 'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={query}' },
  { id: 'zoomeye', name: 'ZoomEye', desc: 'Internet asset search', url: 'https://www.zoomeye.org/search?query={query}' },
  { id: 'binaryedge', name: 'BinaryEdge', desc: 'Internet attack surface', url: 'https://app.binaryedge.io/query?query={query}' },
  { id: 'fofa', name: 'FOFA', desc: 'Asset search engine', url: 'https://fofa.so/result?q={query}' },
  { id: 'spyse', name: 'Spyse', desc: 'Cyber asset search', url: 'https://spyse.com/search?query={query}' },
  { id: 'spyse_alt', name: 'Spyse (alt)', desc: 'Search', url: 'https://spyse.com/search?query={query}' },
  { id: 'ipinfo', name: 'IPinfo', desc: 'IP geolocation & data', url: 'https://ipinfo.io/{query}' },
  { id: 'abuseipdb', name: 'AbuseIPDB', desc: 'Abuse reports for IPs', url: 'https://www.abuseipdb.com/check/{query}' },
  { id: 'crtsh', name: 'crt.sh', desc: 'Certificate transparency search', url: 'https://crt.sh/?q={query}' },
  { id: 'securitytrails', name: 'SecurityTrails', desc: 'Domain & DNS history', url: 'https://securitytrails.com/domain/{query}' },
  { id: 'dnslytics', name: 'DNSlytics', desc: 'DNS & WHOIS lookup', url: 'https://www.dnslytics.com/domain/{query}' },
  { id: 'whoisdomaintools', name: 'Whois / DomainTools', desc: 'Domain registration', url: 'https://whois.domaintools.com/{query}' },
  { id: 'viewdns', name: 'ViewDNS', desc: 'DNS tools', url: 'https://viewdns.info/?domain={query}' },
  { id: 'mx', name: 'MxToolbox', desc: 'DNS and blacklist checks', url: 'https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{query}&run=toolpage' },
  { id: 'ssllabs', name: 'SSL Labs', desc: 'SSL/TLS assessment', url: 'https://www.ssllabs.com/ssltest/analyze.html?d={query}' },
  { id: 'talos', name: 'Cisco Talos', desc: 'Reputation center', url: 'https://talosintelligence.com/reputation_center/lookup?search={query}' },

  // ! Archives
  { id: 'wayback', name: 'Wayback Machine', desc: 'Archived webpages', url: 'https://web.archive.org/web/*/{query}' },
  { id: 'archive_today', name: 'archive.today', desc: 'Save / view snapshots', url: 'https://archive.today/?run=1&url={query}' },
  { id: 'internet_archive', name: 'Internet Archive', desc: 'Archive.org', url: 'https://archive.org/search.php?query={query}' },

  // ! Code & Repo
  { id: 'github', name: 'GitHub Search', desc: 'Code & repo search', url: 'https://github.com/search?q={query}' },
  { id: 'gitgrep', name: 'grep.app', desc: 'Code search', url: 'https://grep.app/search?q={query}' },
  { id: 'searchcode', name: 'SearchCode', desc: 'Code search', url: 'https://searchcode.com/?q={query}' },
  { id: 'sourcegraph', name: 'SourceGraph', desc: 'Code search across repos', url: 'https://sourcegraph.com/search?q={query}' },
  { id: 'publicwww', name: 'PublicWWW', desc: 'Find sites using code/snippets', url: 'https://publicwww.com/websites/{query}/' },
  { id: 'nerdydata', name: 'NerdyData', desc: 'Code and data search', url: 'https://www.nerdydata.com/search?query={query}' },

  // ! People
  { id: 'pipl', name: 'Pipl', desc: 'People search (paid)', url: 'https://pipl.com/search/?q={query}' },
  { id: 'hunter', name: 'Hunter.io', desc: 'Email discovery', url: 'https://hunter.io/search?q={query}' },
  { id: 'clearbit', name: 'Clearbit', desc: 'Company / person lookup', url: 'https://clearbit.com/search?query={query}' },
  { id: 'fullcontact', name: 'FullContact', desc: 'Contact enrichment', url: 'https://www.fullcontact.com/' },
  { id: 'zoominfo', name: 'ZoomInfo', desc: 'Business intelligence', url: 'https://www.zoominfo.com/search?q={query}' },

  // ! Paste sites & paste search
  { id: 'pastebin', name: 'Pastebin', desc: 'Popular paste site', url: 'https://pastebin.com/search?q={query}' },
  { id: 'pastesearches', name: 'Hunting Abuse.ch / Abuse.ch', desc: 'Malicious pastes and hunting', url: 'https://hunting.abuse.ch/?search={query}' },
  { id: 'pastebin_pl', name: 'Pastebin.pl', desc: 'Paste service', url: 'https://pastebin.pl/search?q={query}' },
  { id: 'rentry', name: 'Rentry', desc: 'Simple markdown paste', url: 'https://rentry.co/search?q={query}' },
  { id: 'spacebin', name: 'Spacebin', desc: 'Paste service (spaceb.in)', url: 'https://spaceb.in/?s={query}' },
  { id: 'hastebin', name: 'Hastebin', desc: 'Paste service', url: 'https://www.toptal.com/developers/hastebin/{query}' },
  { id: 'gist', name: 'GitHub Gist', desc: 'Code snippets', url: 'https://gist.github.com/search?q={query}' },
  { id: '0bin', name: '0bin', desc: 'Encrypted paste', url: 'https://0bin.net/search?q={query}' },
  { id: 'pasteee', name: 'Paste.ee', desc: 'Paste service', url: 'https://paste.ee/search?q={query}' },

  // ! Social
  { id: 'pushshift', name: 'Pushshift', desc: 'Reddit data provider', url: 'https://search.pushshift.io/?q={query}' },
  { id: 'redditarchive', name: 'Reddit Archive', desc: 'Archived reddit', url: 'http://www.redditarchive.com/search?q={query}' },
  { id: 'socialsearcher', name: 'Social Searcher', desc: 'Social media search', url: 'https://www.social-searcher.com/search?q={query}' },

  // ! Image
  { id: 'tineye', name: 'TinEye', desc: 'Reverse image search', url: 'https://tineye.com/search?q={query}' },
  { id: 'exifviewer', name: 'Exif Viewer', desc: 'Image metadata', url: 'https://exif-viewer.com/' },
  { id: 'imgur', name: 'Imgur Search', desc: 'Imgur image search', url: 'https://imgur.com/search?q={query}' },

  // ! Domain & Business
  { id: 'opencorporates', name: 'OpenCorporates', desc: 'Company data', url: 'https://opencorporates.com/companies?q={query}' },
  { id: 'crunchbase', name: 'Crunchbase', desc: 'Company intelligence', url: 'https://www.crunchbase.com/search?query={query}' },
  { id: 'whoisxml', name: 'WhoisXML API', desc: 'WHOIS and domain data', url: 'https://whoisxmlapi.com/' },

  // ! Miscellaneous
  { id: 'osintframework', name: 'OSINT Framework', desc: 'OSINT tool map', url: 'https://osintframework.com/' },
  { id: 'spiderfoot', name: 'SpiderFoot HX', desc: 'Automated OSINT scanner', url: 'https://www.spiderfoot.net/' },
  { id: 'maltego', name: 'Maltego', desc: 'Graph-based link analysis', url: 'https://www.maltego.com/' },
  { id: 'amass', name: 'Amass', desc: 'Asset discovery (tool)', url: 'https://github.com/OWASP/Amass' },
  { id: 'theharvester', name: 'theHarvester', desc: 'OSINT email/host discovery', url: 'https://github.com/laramies/theHarvester' },
  { id: 'reconng', name: 'Recon-ng', desc: 'Web reconnaissance framework', url: 'https://github.com/lanmaster53/recon-ng' },
  { id: 'osintcombine', name: 'OSINT Combine Tools', desc: 'Tools collection', url: 'https://www.osintcombine.com/tools' },
  { id: 'darksearch', name: 'DarkSearch', desc: 'Search dark web', url: 'https://darksearch.io/' },
  { id: 'leakix', name: 'LeakIX', desc: 'Exposed assets', url: 'https://leakix.net/' },
  { id: 'mx_all', name: 'MxToolbox (alt)', desc: 'Various network checks', url: 'https://mxtoolbox.com/' },
  { id: 'filepursuit', name: 'FilePursuit', desc: 'File search engine', url: 'https://filepursuit.com/search?q={query}' },
  { id: 'filesec', name: 'Filesec.io', desc: 'File search', url: 'https://filesec.io/search?q={query}' },
  { id: 'findsecuritycontacts', name: 'Find Security Contacts', desc: 'Security contact finder', url: 'https://findsecuritycontacts.com/{query}' },
  { id: 'wpscan', name: 'WPSCAN', desc: 'WordPress vulnerability scanner', url: 'https://wpscan.com/search?term={query}' },
  { id: 'yaraify', name: 'YARAif', desc: 'YARA scan service', url: 'https://yaraify.abuse.ch/scan/{query}' },
  { id: 'shodan_alt', name: 'Shodan (alt)', desc: 'Search', url: 'https://www.shodan.io/search?query={query}' },
  { id: 'netlas', name: 'Netlas', desc: 'Netlas asset search', url: 'https://app.netlas.io/search?q={query}' },
  { id: 'odin_search', name: 'ODIN', desc: 'ODIN search', url: 'https://search.odin.io/?q={query}' },
  { id: 'aleph', name: 'OCCRP Aleph', desc: 'Investigative documents', url: 'https://aleph.occrp.org/?q={query}' },
  { id: 'shadowserver', name: 'Shadowserver', desc: 'Security data', url: 'https://dashboard.shadowserver.org/' },
  { id: 'wipo', name: 'WIPO Brand Database', desc: 'IP / trademarks', url: 'https://www3.wipo.int/branddb/en/' },
  { id: 'wws', name: 'WorldWideScience', desc: 'Global science search', url: 'http://worldwidescience.org/search?q={query}' },
  { id: 'zanran', name: 'Zanran', desc: 'Data in images/graphs', url: 'http://zanran.com/search?q={query}' },
  { id: 'similarsites', name: 'SimilarSites', desc: 'Find similar websites', url: 'http://www.similarsites.com/site/{query}' },
  { id: 'siteslike', name: 'SitesLike', desc: 'Find similar sites', url: 'http://www.siteslike.com/search?keyword={query}' },
  { id: 'saymine', name: 'SayMine', desc: 'Personal data search', url: 'https://www.saymine.com/mineapp' },
  { id: 'meawfy', name: 'Meawfy', desc: 'Search', url: 'https://meawfy.com/search?q={query}' },
  { id: 'redarcs', name: 'REDARCS / The Eye', desc: 'Large archives', url: 'https://the-eye.eu/redarcs/?q={query}' },

  // ! search
  { id: 'searchengines_index', name: 'Search Engines Index', desc: 'Opens a search engine', url: 'https://www.google.com/search?q={query}' }
];

const searchToolsEl = document.getElementById('searchTools');
const favoritesEl = document.getElementById('favorites');
const filterInput = document.getElementById('filterInput');

let favorites = JSON.parse(localStorage.getItem('favorites') || '[]');

function buildUrl(tool) {
  const template = (tool && tool.url) ? tool.url : '';
  return template.replace('{query}', '');
}

// ! Category tools with alphabetic order
function groupByAlphabet(list) {
  const groups = {};
  list.slice().sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }))
    .forEach(t => {
      const ch = (t.name && t.name[0]) ? t.name[0].toUpperCase() : '#';
      const letter = /^[A-Z]$/.test(ch) ? ch : '#';
      groups[letter] = groups[letter] || [];
      groups[letter].push(t);
    });
  return groups;
}

function renderTools(list = tools) {
  searchToolsEl.innerHTML = '';

  const groups = groupByAlphabet(list);
  const letters = Object.keys(groups).sort((a,b) => {
    if (a === '#') return 1;
    if (b === '#') return -1;
    return a.localeCompare(b);
  });

  letters.forEach(letter => {
    const section = document.createElement('section');
    section.className = 'alpha-section';

    const header = document.createElement('h2');
    header.className = 'alpha-header';
    header.textContent = letter;
    section.appendChild(header);

    const container = document.createElement('div');
    container.className = 'cards alpha-cards';

    groups[letter].forEach(t => {
      const card = document.createElement('div');
      card.className = 'card tool-card';
      card.innerHTML = `
        <div class="card-header">
          <h3>${t.name}</h3>
          <button class="fav-btn" data-id="${t.id}" title="Toggle favorite">${favorites.includes(t.id) ? '★' : '☆'}</button>
        </div>
        <p class="desc">${t.desc}</p>
      `;
      card.addEventListener('click', (ev) => {
        if (ev.target && ev.target.classList.contains('fav-btn')) return;
        const url = buildUrl(t);
        window.open(url, '_blank', 'noopener');
      });
      card.querySelector('.fav-btn').addEventListener('click', (ev) => {
        ev.stopPropagation();
        const id = ev.currentTarget.dataset.id;
        toggleFavorite(id);
        ev.currentTarget.textContent = favorites.includes(id) ? '★' : '☆';
        saveAndRender();
      });

      container.appendChild(card);
    });

    section.appendChild(container);
    searchToolsEl.appendChild(section);
  });
}

function renderFavorites() {
  favoritesEl.innerHTML = '';
  const favTools = tools.filter(t => favorites.includes(t.id));
  if (favTools.length === 0) {
    favoritesEl.innerHTML = '<p>No favorites yet. Click ☆ on any tool to save it.</p>';
    return;
  }
  favTools.forEach(t => {
    const el = document.createElement('div');
    el.className = 'card fav-card';
    el.innerHTML = `<h4>${t.name}</h4><p class="desc small">${t.desc}</p>`;
    el.addEventListener('click', () => window.open(buildUrl(t), '_blank', 'noopener'));
    favoritesEl.appendChild(el);
  });
}

function toggleFavorite(id) {
  if (favorites.includes(id)) favorites = favorites.filter(x => x !== id);
  else favorites.push(id);
}

function saveAndRender() {
  localStorage.setItem('favorites', JSON.stringify(favorites));
  renderFavorites();
  const filter = filterInput.value.trim().toLowerCase();
  const filtered = tools.filter(t => t.name.toLowerCase().includes(filter) || t.desc.toLowerCase().includes(filter));
  renderTools(filtered);
}

filterInput.addEventListener('input', () => {
  const q = filterInput.value.trim().toLowerCase();
  const filtered = tools.filter(t => t.name.toLowerCase().includes(q) || t.desc.toLowerCase().includes(q));
  renderTools(filtered);
});

renderTools(tools);
renderFavorites();
