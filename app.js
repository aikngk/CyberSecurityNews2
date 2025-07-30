class CVEDashboard {
    constructor() {
        this.feeds = [
            {
                name: "ZDI Upcoming",
                url: "https://www.zerodayinitiative.com/rss/upcoming/",
                description: "ZDI 未公開/即將公告漏洞通報",
                category: "zdi"
            },
            {
                name: "ZDI Published", 
                url: "https://www.zerodayinitiative.com/rss/published/",
                description: "ZDI 已經公開的漏洞通報",
                category: "zdi"
            },
            {
                name: "ZDI Blog",
                url: "https://www.zerodayinitiative.com/rss/blog/",
                description: "ZDI 資安研究/分析部落格", 
                category: "zdi"
            },
            {
                name: "CVE Official",
                url: "https://nvd.nist.gov/download/nvd-rss.xml",
                description: "官方 CVE 資訊與漏洞動態",
                category: "cve"
            },
            {
                name: "CVEFeed.io",
                url: "https://cvefeed.io/rssfeed/",
                description: "最新 CVE，另有高嚴重性專區",
                category: "cve"
            },
            {
                name: "CVE High/Critical",
                url: "https://cvefeed.io/rssfeed/severity-high-critical/", 
                description: "只推送危險性等級為 High & Critical 的 CVE",
                category: "cve"
            },
            {
                name: "Cisco Advisory",
                url: "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
                description: "Cisco 官方產品安全通告",
                category: "vendor"
            },
            {
                name: "HKCERT Security Bulletin", 
                url: "https://www.hkcert.org/tc/getrss/security-bulletin",
                description: "保安公告及保安博錄",
                category: "local"
            },
            {
                name: "HKCERT Security News",
                url: "https://www.hkcert.org/tc/getrss/security-news", 
                description: "相關新聞",
                category: "local"
            },
            {
                name: "GOVCERT Security Alerts",
                url: "https://www.govcert.gov.hk/tc/rss_security_alerts.xml",
                description: "保安警報", 
                category: "local"
            },
            {
                name: "GOVCERT Security Blogs",
                url: "https://www.govcert.gov.hk/tc/rss_security_blogs.xml",
                description: "保安博錄",
                category: "local"
            }
        ];

        this.config = {
            refreshInterval: 43200000, // 12 hours
            corsProxies: [
                "https://api.allorigins.win/raw?url=",
                "https://corsproxy.io/?",
                "https://cors-anywhere.herokuapp.com/"
            ],
            // maxEntriesPerFeed is no longer used in parsing but kept for reference
            maxEntriesPerFeed: 10,
            requestTimeout: 15000,
            maxRetries: 3,
            severityKeywords: {
                critical: ["critical", "severe", "urgent", "高危", "嚴重", "緊急", "9.0", "10.0"],
                high: ["high", "important", "高", "重要", "7.0", "8.0", "9."], 
                medium: ["medium", "moderate", "中等", "中度", "4.0", "5.0", "6.0"],
                low: ["low", "minor", "低", "輕微", "1.0", "2.0", "3.0"]
            }
        };

        this.entries = [];
        this.filteredEntries = [];
        this.feedStatus = {};
        this.refreshTimer = null;
        this.lastUpdateTime = null;
        this.currentProxyIndex = 0;

        // Add sample data for demonstration
        this.sampleEntries = this.generateSampleEntries();

        this.init();
    }

    generateSampleEntries() {
        return [
            {
                id: 'sample-1',
                title: 'CVE-2024-12345: Critical Remote Code Execution in Apache HTTP Server',
                description: 'A critical vulnerability has been discovered in Apache HTTP Server that allows remote attackers to execute arbitrary code on affected systems. This vulnerability affects versions 2.4.0 through 2.4.58.',
                link: 'https://nvd.nist.gov/vuln/detail/CVE-2024-12345',
                date: new Date(Date.now() - 3600000), // 1 hour ago
                source: 'CVE Official',
                category: 'cve',
                severity: 'critical'
            },
            {
                id: 'sample-2',
                title: 'ZDI-24-001: Microsoft Windows Kernel Privilege Escalation',
                description: 'This vulnerability allows local attackers to escalate privileges on affected installations of Microsoft Windows. An attacker must first obtain the ability to execute low-privileged code.',
                link: 'https://www.zerodayinitiative.com/advisories/ZDI-24-001/',
                date: new Date(Date.now() - 7200000), // 2 hours ago
                source: 'ZDI Published',
                category: 'zdi',
                severity: 'high'
            },
            {
                id: 'sample-3',
                title: 'Cisco Security Advisory: Multiple Vulnerabilities in Cisco IOS XE',
                description: 'Multiple vulnerabilities in Cisco IOS XE Software could allow an unauthenticated, remote attacker to cause a denial of service condition.',
                link: 'https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z',
                date: new Date(Date.now() - 14400000), // 4 hours ago
                source: 'Cisco Advisory',
                category: 'vendor',
                severity: 'medium'
            },
            {
                id: 'sample-4',
                title: 'HKCERT-SA-24-001: Security Update for Google Chrome',
                description: 'Google has released Chrome version 120.0.6099.224 for Windows, Mac and Linux to address multiple security vulnerabilities.',
                link: 'https://www.hkcert.org/security-bulletin/google-has-released-chrome-version-120-0-6099-224',
                date: new Date(Date.now() - 21600000), // 6 hours ago
                source: 'HKCERT Security Bulletin',
                category: 'local',
                severity: 'high'
            },
            {
                id: 'sample-5',
                title: 'CVE-2024-54321: SQL Injection Vulnerability in WordPress Plugin',
                description: 'An SQL injection vulnerability was discovered in a popular WordPress plugin affecting over 100,000 installations.',
                link: 'https://cvefeed.io/vuln/detail/CVE-2024-54321',
                date: new Date(Date.now() - 28800000), // 8 hours ago
                source: 'CVEFeed.io',
                category: 'cve',
                severity: 'medium'
            },
            {
                id: 'sample-6',
                title: 'GOVCERT Alert: Ransomware Campaign Targeting Healthcare Sector',
                description: '政府電腦保安事故協調中心發出警告，針對醫療保健行業的勒索軟件攻擊活動有所增加。',
                link: 'https://www.govcert.gov.hk/tc/alerts/24001',
                date: new Date(Date.now() - 43200000), // 12 hours ago
                source: 'GOVCERT Security Alerts',
                category: 'local',
                severity: 'critical'
            }
        ];
    }

    init() {
        this.setupEventListeners();
        this.initializeFeedStatus();
        this.loadFeeds();
        this.startRefreshTimer();
    }

    setupEventListeners() {
        // Refresh button
        document.getElementById('refreshBtn').addEventListener('click', () => {
            this.loadFeeds(true);
        });

        // Retry button
        document.getElementById('retryBtn').addEventListener('click', () => {
            this.loadFeeds(true);
        });

        // Search input
        document.getElementById('searchInput').addEventListener('input', (e) => {
            this.filterEntries();
        });

        // Severity filter buttons
        document.querySelectorAll('[data-severity]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                document.querySelectorAll('[data-severity]').forEach(b => b.classList.remove('active'));
                e.target.classList.add('active');
                this.filterEntries();
            });
        });

        // Category filter buttons
        document.querySelectorAll('[data-category]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                document.querySelectorAll('[data-category]').forEach(b => b.classList.remove('active'));
                e.target.classList.add('active');
                this.filterEntries();
            });
        });
    }

    initializeFeedStatus() {
        const statusGrid = document.getElementById('feedStatusGrid');
        statusGrid.innerHTML = '';

        this.feeds.forEach(feed => {
            this.feedStatus[feed.name] = { status: 'loading', count: 0 };
            
            const statusCard = document.createElement('div');
            statusCard.className = 'feed-status-card';
            statusCard.innerHTML = `
                <div class="status-dot loading" id="status-${this.slugify(feed.name)}"></div>
                <span class="feed-name">${feed.name}</span>
                <span class="feed-count" id="count-${this.slugify(feed.name)}">0</span>
            `;
            statusGrid.appendChild(statusCard);
        });
    }

    async loadFeeds(isManualRefresh = false) {
        if (isManualRefresh) {
            document.getElementById('refreshBtn').classList.add('loading');
        }

        this.showLoadingState();
        this.entries = [];
        
        let loadedFeeds = 0;
        const totalFeeds = this.feeds.length;

        // Start with sample data
        this.entries = [...this.sampleEntries];
        this.updateProgress(0, totalFeeds);

        const feedPromises = this.feeds.map(async (feed, index) => {
            try {
                this.updateFeedStatus(feed.name, 'loading', 0);
                
                // Add delay to avoid overwhelming servers
                await new Promise(resolve => setTimeout(resolve, index * 500));
                
                const entries = await this.fetchFeedWithRetry(feed);
                
                if (entries.length > 0) {
                    // Remove sample entries from same source and add real ones
                    this.entries = this.entries.filter(e => e.source !== feed.name);
                    this.entries.push(...entries);
                    this.updateFeedStatus(feed.name, 'success', entries.length);
                } else {
                    // Keep sample entry if no real data loaded
                    const sampleEntry = this.sampleEntries.find(e => e.source === feed.name);
                    if (sampleEntry && !this.entries.some(e => e.source === feed.name)) {
                        this.entries.push(sampleEntry);
                    }
                    this.updateFeedStatus(feed.name, 'error', sampleEntry ? 1 : 0);
                }
                
            } catch (error) {
                console.error(`Failed to load feed ${feed.name}:`, error);
                // Keep sample entry if available
                const sampleEntry = this.sampleEntries.find(e => e.source === feed.name);
                if (sampleEntry && !this.entries.some(e => e.source === feed.name)) {
                    this.entries.push(sampleEntry);
                }
                this.updateFeedStatus(feed.name, 'error', sampleEntry ? 1 : 0);
            }
            
            loadedFeeds++;
            this.updateProgress(loadedFeeds, totalFeeds);
        });

        try {
            await Promise.all(feedPromises);
            
            // Sort entries by date (newest first)
            this.entries.sort((a, b) => new Date(b.date) - new Date(a.date));
            
            this.lastUpdateTime = new Date();
            this.updateLastUpdateTime();
            this.filterEntries();
            this.showContent();
            this.updateStats();
            
        } catch (error) {
            console.error('Error loading feeds:', error);
            // Still show content with sample data
            this.lastUpdateTime = new Date();
            this.updateLastUpdateTime();
            this.filterEntries();
            this.showContent();
            this.updateStats();
        }

        if (isManualRefresh) {
            document.getElementById('refreshBtn').classList.remove('loading');
        }
    }

    async fetchFeedWithRetry(feed, retryCount = 0) {
        const maxRetries = this.config.maxRetries;
        
        for (let proxyIndex = 0; proxyIndex < this.config.corsProxies.length; proxyIndex++) {
            try {
                const proxy = this.config.corsProxies[proxyIndex];
                const entries = await this.fetchFeed(feed, proxy);
                return entries;
            } catch (error) {
                console.warn(`Proxy ${proxyIndex} failed for ${feed.name}:`, error.message);
                continue;
            }
        }
        
        if (retryCount < maxRetries) {
            await new Promise(resolve => setTimeout(resolve, Math.pow(2, retryCount) * 1000));
            return this.fetchFeedWithRetry(feed, retryCount + 1);
        }
        
        throw new Error(`All proxies failed for ${feed.name}`);
    }

    async fetchFeed(feed, proxy) {
        const proxyUrl = proxy + encodeURIComponent(feed.url);
        
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.config.requestTimeout);

        try {
            const response = await fetch(proxyUrl, {
                method: 'GET',
                headers: {
                    'Accept': 'application/rss+xml, application/xml, text/xml, */*'
                },
                signal: controller.signal
            });

            clearTimeout(timeoutId);

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const xmlText = await response.text();
            if (!xmlText || xmlText.length < 100) {
                throw new Error('Empty or invalid response');
            }

            const parser = new DOMParser();
            const xmlDoc = parser.parseFromString(xmlText, 'text/xml');

            // Check for XML parsing errors
            const parserError = xmlDoc.querySelector('parsererror');
            if (parserError) {
                throw new Error('XML parsing error');
            }

            return this.parseRSSFeed(xmlDoc, feed);
        } catch (error) {
            clearTimeout(timeoutId);
            throw error;
        }
    }

    parseRSSFeed(xmlDoc, feed) {
        const entries = [];
        const items = xmlDoc.querySelectorAll('item, entry');

        // *** CHANGE: Set a date for one month ago to filter entries ***
        const oneMonthAgo = new Date();
        oneMonthAgo.setMonth(oneMonthAgo.getMonth() - 1);

        items.forEach((item, index) => {
            // *** CHANGE: The maxEntriesPerFeed check has been removed to parse all items from the feed. ***

            const pubDate = this.getDate(item);

            // *** CHANGE: Check if the entry is within the last month. If not, skip it. ***
            if (pubDate < oneMonthAgo) {
                return;
            }

            const title = this.getTextContent(item, 'title');
            const description = this.getTextContent(item, 'description, summary, content');
            const link = this.getLinkHref(item);

            if (title) {
                const entry = {
                    id: `${feed.name}-${index}-${Date.now()}`,
                    title: this.cleanText(title),
                    description: this.cleanText(description),
                    link: link || '#',
                    date: pubDate,
                    source: feed.name,
                    category: feed.category,
                    severity: this.detectSeverity(title + ' ' + description)
                };

                entries.push(entry);
            }
        });

        return entries;
    }

    getTextContent(item, selectors) {
        const selectorList = selectors.split(', ');
        for (const selector of selectorList) {
            const element = item.querySelector(selector);
            if (element) {
                return element.textContent || element.innerHTML || '';
            }
        }
        return '';
    }

    getLinkHref(item) {
        // Try different link formats
        const link = item.querySelector('link');
        if (link) {
            const href = link.getAttribute('href') || link.textContent || '';
            if (href && href.startsWith('http')) return href;
        }
        
        const guid = item.querySelector('guid');
        if (guid && guid.textContent && guid.textContent.startsWith('http')) {
            return guid.textContent;
        }
        
        return '';
    }

    getDate(item) {
        const dateSelectors = ['pubDate', 'published', 'dc\\:date', 'date', 'updated'];
        
        for (const selector of dateSelectors) {
            const dateElement = item.querySelector(selector);
            if (dateElement) {
                const dateStr = dateElement.textContent;
                const date = new Date(dateStr);
                if (!isNaN(date.getTime())) {
                    return date;
                }
            }
        }
        
        return new Date(); // Fallback to current date
    }

    cleanText(text) {
        if (!text) return '';
        
        // Remove HTML tags
        const div = document.createElement('div');
        div.innerHTML = text;
        text = div.textContent || div.innerText || '';
        
        // Clean up whitespace and limit length
        text = text.replace(/\s+/g, ' ').trim();
        return text.length > 300 ? text.substring(0, 300) + '...' : text;
    }

    detectSeverity(text) {
        const lowerText = text.toLowerCase();
        
        for (const [severity, keywords] of Object.entries(this.config.severityKeywords)) {
            if (keywords.some(keyword => lowerText.includes(keyword.toLowerCase()))) {
                return severity;
            }
        }
        
        return 'medium'; // Default severity
    }

    filterEntries() {
        const searchTerm = document.getElementById('searchInput').value.toLowerCase();
        const activeSeverity = document.querySelector('[data-severity].active')?.dataset.severity || 'all';
        const activeCategory = document.querySelector('[data-category].active')?.dataset.category || 'all';

        this.filteredEntries = this.entries.filter(entry => {
            const matchesSearch = !searchTerm || 
                entry.title.toLowerCase().includes(searchTerm) ||
                entry.description.toLowerCase().includes(searchTerm) ||
                entry.source.toLowerCase().includes(searchTerm);

            const matchesSeverity = activeSeverity === 'all' || entry.severity === activeSeverity;
            const matchesCategory = activeCategory === 'all' || entry.category === activeCategory;

            return matchesSearch && matchesSeverity && matchesCategory;
        });

        this.renderEntries();
    }

    renderEntries() {
        const contentGrid = document.getElementById('contentGrid');
        const noResults = document.getElementById('noResults');

        if (this.filteredEntries.length === 0) {
            contentGrid.innerHTML = '';
            noResults.classList.remove('hidden');
            return;
        }

        noResults.classList.add('hidden');
        
        contentGrid.innerHTML = this.filteredEntries.map(entry => `
            <article class="cve-entry">
                <div class="entry-header">
                    <div class="entry-source">
                        <div class="source-icon ${entry.category}">${this.getSourceIcon(entry.category)}</div>
                        <span class="source-name">${entry.source}</span>
                    </div>
                    <div class="severity-badge severity-${entry.severity}">${entry.severity}</div>
                </div>
                
                <h3 class="entry-title">
                    <a href="${entry.link}" target="_blank" rel="noopener noreferrer">${entry.title}</a>
                </h3>
                
                <p class="entry-description">${entry.description}</p>
                
                <div class="entry-footer">
                    <span class="entry-date">${this.formatDate(entry.date)}</span>
                    <a href="${entry.link}" class="entry-link" target="_blank" rel="noopener noreferrer">Read More</a>
                </div>
            </article>
        `).join('');
    }

    getSourceIcon(category) {
        const icons = {
            cve: 'CVE',
            zdi: 'ZDI',
            vendor: 'VND',
            local: 'LOC'
        };
        return icons[category] || 'RSS';
    }

    formatDate(date) {
        if (!date) return 'Unknown';
        
        const now = new Date();
        const diff = now - date;
        const minutes = Math.floor(diff / 60000);
        const hours = Math.floor(diff / 3600000);
        const days = Math.floor(diff / 86400000);

        if (minutes < 60) {
            return `${minutes}m ago`;
        } else if (hours < 24) {
            return `${hours}h ago`;
        } else if (days < 7) {
            return `${days}d ago`;
        } else {
            return date.toLocaleDateString('zh-TW');
        }
    }

    updateFeedStatus(feedName, status, count) {
        this.feedStatus[feedName] = { status, count };
        
        const statusDot = document.getElementById(`status-${this.slugify(feedName)}`);
        const countSpan = document.getElementById(`count-${this.slugify(feedName)}`);
        
        if (statusDot) {
            statusDot.className = `status-dot ${status}`;
        }
        
        if (countSpan) {
            countSpan.textContent = count;
        }
    }

    updateProgress(loaded, total) {
        const progressFill = document.getElementById('progressFill');
        const progressText = document.getElementById('progressText');
        
        const percentage = (loaded / total) * 100;
        progressFill.style.width = `${percentage}%`;
        progressText.textContent = `${loaded}/${total} feeds loaded`;
    }

    updateLastUpdateTime() {
        const lastUpdateElement = document.getElementById('lastUpdateTime');
        if (this.lastUpdateTime) {
            lastUpdateElement.textContent = this.lastUpdateTime.toLocaleString('zh-TW');
        }
    }

    updateStats() {
        const totalCount = document.getElementById('totalCount');
        const criticalCount = document.getElementById('criticalCount');
        const highCount = document.getElementById('highCount');

        totalCount.textContent = this.entries.length;
        criticalCount.textContent = this.entries.filter(e => e.severity === 'critical').length;
        highCount.textContent = this.entries.filter(e => e.severity === 'high').length;
    }

    startRefreshTimer() {
        this.updateRefreshTimer();
        
        // Update timer every minute
        setInterval(() => {
            this.updateRefreshTimer();
        }, 60000);

        // Set main refresh timer
        this.refreshTimer = setInterval(() => {
            this.loadFeeds();
        }, this.config.refreshInterval);
    }

    updateRefreshTimer() {
        const nextRefreshElement = document.getElementById('nextRefreshTime');
        
        if (this.lastUpdateTime) {
            const nextRefresh = new Date(this.lastUpdateTime.getTime() + this.config.refreshInterval);
            const now = new Date();
            const diff = nextRefresh - now;
            
            if (diff > 0) {
                const hours = Math.floor(diff / 3600000);
                const minutes = Math.floor((diff % 3600000) / 60000);
                nextRefreshElement.textContent = `${hours}h ${minutes}m`;
            } else {
                nextRefreshElement.textContent = 'Refreshing...';
            }
        } else {
            nextRefreshElement.textContent = '--';
        }
    }

    showLoadingState() {
        document.getElementById('loadingState').classList.remove('hidden');
        document.getElementById('errorState').classList.add('hidden');
        document.getElementById('contentGrid').classList.add('hidden');
        document.getElementById('noResults').classList.add('hidden');
    }

    showErrorState() {
        document.getElementById('loadingState').classList.add('hidden');
        document.getElementById('errorState').classList.remove('hidden');
        document.getElementById('contentGrid').classList.add('hidden');
        document.getElementById('noResults').classList.add('hidden');
    }

    showContent() {
        document.getElementById('loadingState').classList.add('hidden');
        document.getElementById('errorState').classList.add('hidden');
        document.getElementById('contentGrid').classList.remove('hidden');
    }

    slugify(text) {
        return text.toLowerCase()
            .replace(/[^a-z0-9]+/g, '-')
            .replace(/^-+|-+$/g, '');
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new CVEDashboard();
});