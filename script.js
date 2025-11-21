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
    if (index > -1) {
        favorites.splice(index, 1);
    } else {
        favorites.push(toolId);
    }
    saveFavorites();
    renderAll();
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

// Group tools by first letter
function groupToolsByLetter(toolsList) {
    const sorted = [...toolsList].sort((a, b) =>
        a.name.localeCompare(b.name, undefined, { sensitivity: 'base' })
    );
    
    const grouped = {};
    sorted.forEach(tool => {
        const firstChar = tool.name[0].toUpperCase();
        const letter = /^[A-Z]$/.test(firstChar) ? firstChar : '#';
        if (!grouped[letter]) {
            grouped[letter] = [];
        }
        grouped[letter].push(tool);
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
    
    const grouped = groupToolsByLetter(filteredTools);
    const letters = Object.keys(grouped).sort((a, b) => {
        if (a === '#') return 1;
        if (b === '#') return -1;
        return a.localeCompare(b);
    });
    
    toolsContainer.innerHTML = letters.map(letter => `
        <div class="alpha-group">
            <div class="alpha-header">
                <div class="alpha-letter">${letter}</div>
                <div class="alpha-divider"></div>
            </div>
            <div class="tools-grid">
                ${grouped[letter].map(tool => 
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
}

// Start the app
init();
