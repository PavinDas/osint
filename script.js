// State Management
let favorites = [];
let filteredTools = [...tools];

// DOM Elements
const searchInput = document.getElementById('searchInput');
const toolsContainer = document.getElementById('toolsContainer');
const favoritesGrid = document.getElementById('favoritesGrid');
const favoritesSection = document.getElementById('favoritesSection');
const emptyFavoritesSection = document.getElementById('emptyFavoritesSection');
const noResultsMessage = document.getElementById('noResultsMessage');
const toolCountEl = document.getElementById('toolCount');
const favCountEl = document.getElementById('favCount');
const filteredCountEl = document.getElementById('filteredCount');
const searchTermEl = document.getElementById('searchTerm');
const yearEl = document.getElementById('year');

// Initialize
function init() {
    loadFavorites();
    updateToolCount();
    updateFilteredCount();
    renderAll();
    setupEventListeners();
    yearEl.textContent = new Date().getFullYear();
}

// Load favorites from localStorage
function loadFavorites() {
    try {
        const stored = localStorage.getItem('osint-favorites');
        if (stored) {
            favorites = JSON.parse(stored);
        }
    } catch (e) {
        console.error('Failed to load favorites', e);
        favorites = [];
    }
}

// Save favorites to localStorage
function saveFavorites() {
    try {
        localStorage.setItem('osint-favorites', JSON.stringify(favorites));
    } catch (e) {
        console.error('Failed to save favorites', e);
    }
}

// Toggle favorite
function toggleFavorite(toolId) {
    const index = favorites.indexOf(toolId);
    const wasFavorite = index > -1;

    if (wasFavorite) {
        favorites.splice(index, 1);
    } else {
        favorites.push(toolId);
    }

    saveFavorites();

    // Update UI without full re-render
    updateFavoriteButtons(toolId, !wasFavorite);
    renderFavorites();
}

// Update specific tool buttons in the DOM
function updateFavoriteButtons(toolId, isFavorite) {
    const buttons = document.querySelectorAll(`.star-btn[data-id="${toolId}"]`);
    buttons.forEach(btn => {
        if (isFavorite) {
            btn.classList.add('active');
            btn.setAttribute('title', 'Remove from favorites');
            const svg = btn.querySelector('svg');
            if (svg) svg.setAttribute('fill', 'currentColor');
        } else {
            btn.classList.remove('active');
            btn.setAttribute('title', 'Add to favorites');
            const svg = btn.querySelector('svg');
            if (svg) svg.setAttribute('fill', 'none');
        }
    });
}

// Open tool in new tab
function openTool(tool) {
    const url = tool.url.replace('{query}', '');
    window.open(url, '_blank', 'noopener,noreferrer');
}

// Filter tools based on search query
function filterTools(query) {
    const searchTerm = query.toLowerCase().trim();

    if (!searchTerm) {
        filteredTools = [...tools];
    } else {
        filteredTools = tools.filter(tool =>
            tool.name.toLowerCase().includes(searchTerm) ||
            tool.desc.toLowerCase().includes(searchTerm) ||
            (tool.category && tool.category.toLowerCase().includes(searchTerm))
        );
    }

    renderAllTools();
    updateFilteredCount();
}

// Format category name (e.g. "ai_and_llm" -> "AI and LLM")
function formatCategory(category) {
    if (!category) return 'Uncategorized';
    return category
        .split('_')
        .map(word => {
            if (['ai', 'llm', 'osint', 'ip', 'dns', 'url', 'saas', 'mac', 'vpn', 'rss', 'api', 'ioc', 'ttp', 'ssl', 'tls', 'gps', 'gnss'].includes(word.toLowerCase())) {
                return word.toUpperCase();
            }
            return word.charAt(0).toUpperCase() + word.slice(1);
        })
        .join(' ');
}

// Group tools by category
function groupToolsByCategory(toolsList) {
    const grouped = {};
    toolsList.forEach(tool => {
        const cat = tool.category || 'miscellaneous';
        if (!grouped[cat]) {
            grouped[cat] = [];
        }
        grouped[cat].push(tool);
    });
    return grouped;
}

// Create tool card HTML
function createToolCard(tool, isFavorite = false) {
    return `
        <div class="tool-card" onclick="openTool(tools.find(t => t.id === '${tool.id}'))">
            <div class="card-top">
                <div class="card-info">
                    <h3 class="card-name">${tool.name}</h3>
                    <p class="card-desc">${tool.desc}</p>
                </div>
                <button 
                    class="star-btn ${isFavorite ? 'active' : ''}" 
                    data-id="${tool.id}"
                    onclick="event.stopPropagation(); toggleFavorite('${tool.id}')"
                    title="${isFavorite ? 'Remove from favorites' : 'Add to favorites'}"
                >
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="${isFavorite ? 'currentColor' : 'none'}" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon>
                    </svg>
                </button>
            </div>
            <button class="open-btn" onclick="event.stopPropagation(); openTool(tools.find(t => t.id === '${tool.id}'))">
                <span>Open Tool</span>
                <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>
                    <polyline points="15 3 21 3 21 9"></polyline>
                    <line x1="10" y1="14" x2="21" y2="3"></line>
                </svg>
            </button>
        </div>
    `;
}

// Render favorites section
function renderFavorites() {
    const favoriteTools = tools.filter(tool => favorites.includes(tool.id));

    if (favoriteTools.length > 0) {
        favoritesSection.style.display = 'block';
        emptyFavoritesSection.style.display = 'none';

        favoritesGrid.innerHTML = favoriteTools
            .map(tool => createToolCard(tool, true))
            .join('');

        favCountEl.textContent = favoriteTools.length;
    } else {
        favoritesSection.style.display = 'none';

        // Only show empty state if not searching
        if (!searchInput.value.trim()) {
            emptyFavoritesSection.style.display = 'block';
        } else {
            emptyFavoritesSection.style.display = 'none';
        }
    }
}

// Render all tools grouped by letter
// Render all tools grouped by category
function renderAllTools() {
    const searchTerm = searchInput.value.trim();

    if (filteredTools.length === 0) {
        noResultsMessage.style.display = 'block';
        toolsContainer.style.display = 'none';
        searchTermEl.textContent = searchTerm;
        return;
    }

    noResultsMessage.style.display = 'none';
    toolsContainer.style.display = 'flex';

    const grouped = groupToolsByCategory(filteredTools);
    const categories = Object.keys(grouped).sort();

    toolsContainer.innerHTML = categories.map(cat => `
        <div class="category-group">
            <div class="category-header">
                <h2 class="category-title">${formatCategory(cat)}</h2>
                <div class="category-divider"></div>
            </div>
            <div class="tools-grid">
                ${grouped[cat].map(tool =>
        createToolCard(tool, favorites.includes(tool.id))
    ).join('')}
            </div>
        </div>
    `).join('');
}

// Render everything
function renderAll() {
    renderFavorites();
    renderAllTools();
}

// Update counts
function updateToolCount() {
    toolCountEl.textContent = `${tools.length} Tools`;
}

function updateFilteredCount() {
    const count = filteredTools.length;
    filteredCountEl.textContent = `${count} ${count === 1 ? 'tool' : 'tools'}`;
}

// Setup event listeners
function setupEventListeners() {
    searchInput.addEventListener('input', (e) => {
        filterTools(e.target.value);
    });

    // Header scroll effect
    window.addEventListener('scroll', () => {
        const header = document.querySelector('.header');
        if (header) {
            if (window.scrollY > 10) {
                header.classList.add('scrolled');
            } else {
                header.classList.remove('scrolled');
            }
        }
    });

    // Spotlight hover effect for cards (Performance optimized)
    const container = document.querySelector('.main-content');
    if (container) {
        container.addEventListener('mousemove', (e) => {
            const card = e.target.closest('.tool-card');
            if (card) {
                const rect = card.getBoundingClientRect();
                const x = e.clientX - rect.left;
                const y = e.clientY - rect.top;

                card.style.setProperty('--mouse-x', `${x}px`);
                card.style.setProperty('--mouse-y', `${y}px`);
            }
        });
    }
}

// Start the app
init();

// Category Navigation
const showCategoriesBtn = document.getElementById('showCategoriesBtn');
const categoryNavSection = document.getElementById('categoryNavSection');
const closeCategoriesBtn = document.getElementById('closeCategoriesBtn');
const categoryButtonsContainer = document.getElementById('categoryButtonsContainer');

function toggleCategoryNav() {
    if (categoryNavSection.style.display === 'none') {
        renderCategoryButtons();
        categoryNavSection.style.display = 'block';
        showCategoriesBtn.classList.add('active');
        // Scroll to top to show categories
        window.scrollTo({
            top: 0,
            behavior: 'smooth'
        });
    } else {
        categoryNavSection.style.display = 'none';
        showCategoriesBtn.classList.remove('active');
    }
}

function renderCategoryButtons() {
    const categories = [...new Set(tools.map(tool => tool.category || 'miscellaneous'))].sort();

    categoryButtonsContainer.innerHTML = categories.map(cat => `
        <button class="category-btn" onclick="scrollToCategory('${cat}')">
            ${formatCategory(cat)}
        </button>
    `).join('');
}

function scrollToCategory(category) {
    const categoryHeaders = document.querySelectorAll('.category-title');
    let targetHeader = null;

    for (const header of categoryHeaders) {
        if (header.textContent === formatCategory(category)) {
            targetHeader = header;
            break;
        }
    }

    if (targetHeader) {
        // Close category menu on selection
        categoryNavSection.style.display = 'none';

        // Scroll to element with offset for fixed header
        const headerOffset = 100;
        const elementPosition = targetHeader.getBoundingClientRect().top;
        const offsetPosition = elementPosition + window.pageYOffset - headerOffset;

        window.scrollTo({
            top: offsetPosition,
            behavior: "smooth"
        });
    }
}

// Event Listeners for Category Nav
if (showCategoriesBtn) {
    showCategoriesBtn.addEventListener('click', toggleCategoryNav);
}

if (closeCategoriesBtn) {
    closeCategoriesBtn.addEventListener('click', toggleCategoryNav);
}

// Scroll to top functionality
const scrollToTopBtn = document.createElement('button');
scrollToTopBtn.className = 'scroll-to-top';
scrollToTopBtn.innerHTML = `
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <polyline points="18 15 12 9 6 15"></polyline>
    </svg>
`;
document.body.appendChild(scrollToTopBtn);

scrollToTopBtn.addEventListener('click', () => {
    window.scrollTo({
        top: 0,
        behavior: 'smooth'
    });
});

window.addEventListener('scroll', () => {
    if (window.scrollY > 300) {
        scrollToTopBtn.classList.add('visible');
    } else {
        scrollToTopBtn.classList.remove('visible');
    }
});
