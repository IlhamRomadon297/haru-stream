
// ── STATE ───────────────────────────────────────────────────
const APP = {
  token:          localStorage.getItem('hs_token') || null,
  user:           null,
  currentView:    'dashboard',
  mediaView:      'list',  // 'list' | 'grid'
  currentDrive:   null,    // null = all drives
  currentFolder:  undefined, // undefined = all, null = unsorted, number = folder id
  mediaData:      [],      // current sorted data set (mirrors DB order)
  selectedIds:    new Set(),
  page:           1,
  totalPages:     1,
  totalItems:     0,
  drives:         [],
  folders:        [],
  exportSeparator: 'newline',
  searchTimeout:  null,
  charts:         {},
};

const BASE_URL = window.location.origin;

// ── UTILS ────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

function formatBytes(bytes, decimals = 1) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024, dm = decimals < 0 ? 0 : decimals;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function formatNumber(n) {
  return parseInt(n || 0).toLocaleString();
}

function fmtResolutionBadge(res) {
  if (!res) return '<span class="badge badge-gray">Unknown</span>';
  const cls = res.includes('4K') ? 'badge-purple' : res.includes('1080') ? 'badge-green' : res.includes('720') ? 'badge-yellow' : 'badge-gray';
  return `<span class="badge ${cls}">${res}</span>`;
}

function showToast(msg, type = 'info', duration = 3000) {
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  const icon = type === 'success' ? 'fa-check-circle' : type === 'error' ? 'fa-exclamation-circle' : 'fa-info-circle';
  t.innerHTML = `<i class="fas ${icon}"></i><span>${msg}</span>`;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), duration);
}

async function apiFetch(path, opts = {}) {
  const res = await fetch(BASE_URL + path, {
    ...opts,
    headers: {
      'Content-Type': 'application/json',
      ...(APP.token ? { Authorization: `Bearer ${APP.token}` } : {}),
      ...(opts.headers || {}),
    },
    body: opts.body ? (typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body)) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401) { handleLogout(); }
  return { ok: res.ok, status: res.status, data };
}

function setButtonLoading(id, loading, label = '') {
  const btn = $(id);
  if (!btn) return;
  btn.disabled = loading;
  if (loading) { btn.dataset.orig = btn.innerHTML; btn.innerHTML = '<i class="fas fa-circle-notch fa-spin mr-2"></i>Loading...'; }
  else { btn.innerHTML = btn.dataset.orig || label; }
}

// ── AUTH ─────────────────────────────────────────────────────
function switchAuthTab(tab) {
  $('login-form').classList.toggle('hidden', tab !== 'login');
  $('register-form').classList.toggle('hidden', tab !== 'register');
  $('tab-login').classList.toggle('active', tab === 'login');
  $('tab-register').classList.toggle('active', tab === 'register');
}

async function handleLoginSubmit(e) {
  e.preventDefault();
  const btn = $('login-btn');
  btn.disabled = true;
  btn.innerHTML = '<i class="fas fa-circle-notch fa-spin mr-2"></i>Signing in...';
  const { ok, data } = await apiFetch('/api/auth/login', {
    method: 'POST',
    body: { username: $('login-username').value, password: $('login-password').value },
  });
  if (ok && data.token) {
    APP.token = data.token;
    APP.user  = data.user;
    localStorage.setItem('hs_token', data.token);
    initApp();
  } else {
    showToast(data.error || 'Login failed.', 'error');
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-sign-in-alt mr-2"></i>Sign In';
  }
}

async function handleRegisterSubmit(e) {
  e.preventDefault();
  const btn = $('register-btn');
  btn.disabled = true;
  btn.innerHTML = '<i class="fas fa-circle-notch fa-spin mr-2"></i>Creating account...';
  const { ok, data } = await apiFetch('/api/auth/register', {
    method: 'POST',
    body: {
      username: $('reg-username').value,
      email:    $('reg-email').value || undefined,
      password: $('reg-password').value,
    },
  });
  if (ok && data.token) {
    APP.token = data.token;
    APP.user  = data.user;
    localStorage.setItem('hs_token', data.token);
    initApp();
  } else {
    showToast(data.error || 'Registration failed.', 'error');
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-user-plus mr-2"></i>Create Account';
  }
}

function handleLogout() {
  APP.token = null;
  APP.user  = null;
  localStorage.removeItem('hs_token');
  $('app').classList.add('hidden');
  $('login-screen').classList.remove('hidden');
}

function togglePasswordVisibility(inputId) {
  const inp = $(inputId);
  inp.type = inp.type === 'password' ? 'text' : 'password';
}

// ── SIDEBAR & VIEWS ─────────────────────────────────────────────────────────
function toggleSidebar() {
  $('sidebar').classList.toggle('expanded');
}

// ── APP INIT ─────────────────────────────────────────────────
async function initApp() {
  $('login-screen').classList.add('hidden');
  $('app').classList.remove('hidden');
  // Fetch user info
  const { ok, data } = await apiFetch('/api/auth/me');
  if (ok) {
    APP.user = data.user;
    $('sidebar-username').textContent = data.user.username;
    $('sidebar-role').textContent = data.user.role.toUpperCase();
  }
  showView('dashboard');
  loadDrives();
}

// Auto-login if token exists
if (APP.token) {
  document.addEventListener('DOMContentLoaded', () => {
    apiFetch('/api/auth/me').then(({ ok }) => {
      if (ok) initApp();
      else {
        localStorage.removeItem('hs_token');
        APP.token = null;
      }
    });
  });
}

// ── SIDEBAR & VIEWS ──────────────────────────────────────────
function toggleSidebar() {
  $('sidebar').classList.toggle('collapsed');
}

const VIEW_META = {
  dashboard: { title: 'Dashboard',      subtitle: 'Overview & Analytics',            nav: 'nav-dashboard' },
  upload:    { title: 'File Upload',    subtitle: 'Upload from device or remote URL', nav: 'nav-upload'    },
  media:     { title: 'Media Center',   subtitle: 'Browse and manage your video library', nav: 'nav-media' },
  drives:    { title: 'Drive Settings', subtitle: 'Manage Google Drive credentials',  nav: 'nav-drives'    },
};

function showView(name) {
  APP.currentView = name;
  const views = ['dashboard', 'upload', 'media', 'drives'];
  views.forEach(v => {
    const el = $(`view-${v}`);
    if (el) {
      el.classList.toggle('hidden', v !== name);
      el.classList.toggle('flex', v === name && v === 'media');
    }
    const nav = $(`nav-${v}`);
    if (nav) nav.classList.toggle('active', v === name);
  });

  const meta = VIEW_META[name];
  if (meta) {
    $('page-title').textContent    = meta.title;
    $('page-subtitle').textContent = meta.subtitle;
  }

  if (name === 'dashboard') loadDashboard();
  if (name === 'media')     { loadFolders(); loadMedia(); }
  if (name === 'drives')    { loadDrives(); loadAutoSyncSettings(); }
  if (name === 'upload')    populateDriveSelects();
}

// ── DASHBOARD ────────────────────────────────────────────────
async function loadDashboard() {
  const { ok, data } = await apiFetch('/api/stats');
  if (!ok) return;
  const s = data.stats;
  $('stat-views').textContent     = formatNumber(s.total_views);
  $('stat-downloads').textContent = formatNumber(s.total_downloads);
  $('stat-storage').textContent   = formatBytes(s.total_size);
  $('stat-videos').textContent    = formatNumber(s.total_videos);

  // Top videos table
  const tbody = $('top-videos-tbody');
  tbody.innerHTML = data.top_videos.length === 0
    ? '<tr><td colspan="5" class="text-center py-8" style="color:#475569">No data yet. Sync a drive to get started.</td></tr>'
    : data.top_videos.map(v => `
        <tr>
          <td>
            <a href="/embed/${v.id}" target="_blank" class="font-medium text-sm hover:text-brand-300 transition-colors" style="color:#c7d2fe">${escHtml(v.title)}</a>
          </td>
          <td>${fmtResolutionBadge(v.resolution)}</td>
          <td><span class="font-mono text-sm" style="color:#94a3b8">${formatNumber(v.views)}</span></td>
          <td><span class="font-mono text-sm" style="color:#94a3b8">${formatNumber(v.downloads)}</span></td>
          <td><span class="font-mono text-xs" style="color:#64748b">${formatBytes(v.size)}</span></td>
        </tr>`).join('');

      // Render charts
      buildBarChart(data.top_videos);
      buildDonutChart(data.top_videos);
}

function buildBarChart(topVideos) {
  const ctx = $('areaChart')?.getContext('2d');
  if (!ctx) return;
  if (APP.charts.area) APP.charts.area.destroy();

  const data = topVideos.slice(0, 7);
  const labels = data.map(v => v.title.length > 20 ? v.title.substring(0, 20) + '...' : v.title);
  const views = data.map(v => v.views);

  const grad = ctx.createLinearGradient(0, 0, 0, 240);
  grad.addColorStop(0, 'rgba(99,102,241,0.35)');
  grad.addColorStop(1, 'rgba(99,102,241,0)');

  APP.charts.area = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Views',
        data: views,
        borderColor: '#6366f1',
        backgroundColor: grad,
        borderWidth: 2,
        borderRadius: 4
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false }, tooltip: { backgroundColor: '#141428', borderColor: '#2a2a4a', borderWidth: 1, titleColor: '#a5b4fc', bodyColor: '#94a3b8' } },
      scales: {
        x: { grid: { color: 'rgba(30,30,56,0.8)' }, ticks: { color: '#475569', font: { size: 11 } } },
        y: { grid: { color: 'rgba(30,30,56,0.8)' }, ticks: { color: '#475569', font: { size: 11 } }, beginAtZero: true },
      },
    },
  });
}

function buildDonutChart(topVideos) {
  const ctx = $('donutChart')?.getContext('2d');
  if (!ctx) return;
  if (APP.charts.donut) APP.charts.donut.destroy();

  const resCounts = { '4K': 0, '1080p': 0, '720p': 0, '480p': 0, 'Other': 0 };
  topVideos.forEach(v => {
    if (v.resolution === '4K') resCounts['4K']++;
    else if (v.resolution === '1080p') resCounts['1080p']++;
    else if (v.resolution === '720p') resCounts['720p']++;
    else if (v.resolution === '480p') resCounts['480p']++;
    else resCounts['Other']++;
  });
  
  const labels  = ['4K', '1080p', '720p', '480p', 'Other'];
  const data    = [resCounts['4K'], resCounts['1080p'], resCounts['720p'], resCounts['480p'], resCounts['Other']];
  const colors  = ['#6366f1', '#8b5cf6', '#a78bfa', '#c4b5fd', '#4338ca'];

  APP.charts.donut = new Chart(ctx, {
    type: 'doughnut',
    data: { labels, datasets: [{ data, backgroundColor: colors, borderWidth: 0, hoverOffset: 6 }] },
    options: {
      responsive: true, maintainAspectRatio: false,
      cutout: '72%',
      plugins: { legend: { display: false }, tooltip: { backgroundColor: '#141428', borderColor: '#2a2a4a', borderWidth: 1, titleColor: '#a5b4fc', bodyColor: '#94a3b8' } },
    },
  });

  // Legend
  const legend = $('donut-legend');
  legend.innerHTML = labels.map((l, i) => `
    <div class="flex items-center justify-between">
      <div class="flex items-center gap-2">
        <div class="w-2.5 h-2.5 rounded-sm flex-shrink-0" style="background:${colors[i]}"></div>
        <span class="text-xs" style="color:#94a3b8">${l}</span>
      </div>
      <span class="text-xs font-mono" style="color:#64748b">${data[i]}</span>
    </div>`).join('');
}

// ── SYNC ─────────────────────────────────────────────────────
async function triggerSync(driveId) {
  $('sync-status').classList.remove('hidden');
  $('sync-status').classList.add('flex');
  const { ok, data } = await apiFetch('/api/media/sync', {
    method: 'POST',
    body: driveId ? { drive_id: driveId } : {},
  });
  $('sync-status').classList.add('hidden');
  $('sync-status').classList.remove('flex');

  if (ok) {
    showToast(`✔ Sync complete — ${data.synced} files indexed.`, 'success', 4000);
    if (APP.currentView === 'media')    loadMedia();
    if (APP.currentView === 'dashboard') loadDashboard();
  } else {
    showToast(data.error || 'Sync failed.', 'error');
  }
}

async function loadDrives() {
  const { ok, data } = await apiFetch('/api/settings/drives');
  if (!ok) return;
  APP.drives = data.drives || [];
  renderDrivesList();
  populateDriveSelects();
  renderDriveTree();
}

function renderDrivesList() {
  const container = $('drives-list');
  if (!APP.drives.length) {
    container.innerHTML = `
      <div class="glass-card rounded-2xl p-10 text-center">
        <div class="w-16 h-16 rounded-2xl mx-auto mb-4 flex items-center justify-center" style="background:rgba(99,102,241,0.1)">
          <i class="fab fa-google-drive text-2xl" style="color:#6366f1"></i>
        </div>
        <div class="text-sm font-semibold text-white mb-2">No drives connected yet</div>
        <div class="text-xs mb-5" style="color:#64748b">Add your first Google Drive account to start indexing videos.</div>
        <button onclick="openAddDriveModal()" class="btn-gradient px-6 py-2.5 rounded-xl text-sm font-semibold text-white"><i class="fas fa-plus mr-2"></i>Connect First Drive</button>
      </div>`;
    return;
  }

  container.innerHTML = APP.drives.map(d => {
    const pct = d.quota_total > 0 ? Math.round((d.quota_used / d.quota_total) * 100) : 0;
    const synced = d.last_synced_at ? new Date(d.last_synced_at).toLocaleString() : 'Never';
    return `
      <div class="glass-card rounded-2xl p-5 transition-all" id="drive-card-${d.id}">
        <div class="flex items-start justify-between gap-4">
          <div class="flex items-center gap-3">
            <div class="w-11 h-11 rounded-xl flex items-center justify-center flex-shrink-0" style="background:rgba(99,102,241,0.15)">
              <i class="fab fa-google-drive" style="color:#6366f1;font-size:18px"></i>
            </div>
            <div>
              <div class="font-semibold text-sm text-white">${escHtml(d.drive_name)}</div>
              <div class="text-xs mt-0.5" style="color:#64748b">Last synced: ${synced}</div>
            </div>
          </div>
          <div class="flex items-center gap-2 flex-shrink-0">
            <span class="badge ${d.is_active ? 'badge-green' : 'badge-red'}">${d.is_active ? 'Active' : 'Disabled'}</span>
            <button onclick="triggerSync(${d.id})" class="px-3 py-1.5 rounded-lg text-xs font-semibold transition-all hover:opacity-80" style="background:rgba(99,102,241,0.15);color:#a5b4fc;border:1px solid rgba(99,102,241,0.25)">
              <i class="fas fa-sync-alt mr-1"></i>Sync
            </button>
            <button onclick="deleteDrive(${d.id})" class="p-1.5 rounded-lg text-xs transition-colors hover:bg-red-500/20" style="color:#f87171;background:none;border:none;cursor:pointer">
              <i class="fas fa-trash"></i>
            </button>
          </div>
        </div>
        ${d.quota_total > 0 ? `
        <div class="mt-4">
          <div class="flex justify-between text-xs mb-1.5" style="color:#64748b">
            <span>Storage Usage</span>
            <span>${formatBytes(d.quota_used)} / ${formatBytes(d.quota_total)} (${pct}%)</span>
          </div>
          <div class="progress-bar">
            <div class="progress-bar-fill" style="width:${pct}%"></div>
          </div>
        </div>` : ''}
      </div>`;
  }).join('');
}

function openAddDriveModal() { $('modal-add-drive').classList.remove('hidden'); }

async function submitAddDrive(e) {
  e.preventDefault();
  setButtonLoading('add-drive-btn', true);
  const { ok, data } = await apiFetch('/api/settings/drives', {
    method: 'POST',
    body: {
      drive_name:     $('drive-name').value,
      client_id:      $('drive-client-id').value,
      client_secret:  $('drive-client-secret').value,
      refresh_token:  $('drive-refresh-token').value,
      root_folder_id: $('drive-root-folder').value || undefined,
    },
  });
  setButtonLoading('add-drive-btn', false);
  if (ok) {
    showToast('Drive connected successfully!', 'success');
    closeModal('modal-add-drive');
    e.target.reset();
    loadDrives();
  } else {
    showToast(data.error || 'Failed to connect drive.', 'error', 5000);
  }
}

async function deleteDrive(id) {
  if (!confirm('Remove this drive? All indexed videos from this drive will be deleted.')) return;
  const { ok, data } = await apiFetch(`/api/settings/drives/${id}`, { method: 'DELETE' });
  if (ok) { showToast('Drive removed.', 'success'); loadDrives(); }
  else     showToast(data.error || 'Failed to remove.', 'error');
}

// ── MEDIA ────────────────────────────────────────────────────
async function loadFolders() {
  const { ok, data } = await apiFetch('/api/media?limit=1');
  if (!ok) return;
  APP.folders = data.folders || [];
  renderFolderTree();
  populateFolderSelects();
}

function renderDriveTree() {
  const tree = $('drive-tree');
  if (!APP.drives) { tree.innerHTML = ''; return; }
  
  const html = APP.drives.map(d => `
    <div class="folder-tree-item ${APP.currentDrive === d.id ? 'active' : ''}" id="dtree-${d.id}" onclick="selectDrive(${d.id})" style="padding-left:10px">
      <i class="fab fa-google-drive text-xs" style="color:#10b981"></i>
      <span>${escHtml(d.drive_name)}</span>
    </div>
  `).join('');
  tree.innerHTML = html;
}

function selectDrive(id) {
  APP.currentDrive = id;
  APP.page = 1;
  // Update active states for drives
  document.querySelectorAll('#drive-tree .folder-tree-item, #drive-all').forEach(el => el.classList.remove('active'));
  if (id === null) { 
    $('drive-all').classList.add('active'); 
  } else {
    const el = $(`dtree-${id}`);
    if (el) el.classList.add('active');
  }
  loadMedia();
}

function renderFolderTree() {
  const tree = $('folder-tree');
  const buildItems = (parentId) => APP.folders
    .filter(f => (f.parent_id || null) === parentId)
    .sort((a, b) => a.sort_order - b.sort_order || a.name.localeCompare(b.name))
    .map(f => `
      <div class="folder-tree-item ${APP.currentFolder === f.id ? 'active' : ''}" id="ftree-${f.id}" onclick="selectFolder(${f.id})" style="padding-left:${f.parent_id ? '20px' : '10px'}">
        <i class="fas fa-folder text-xs" style="color:${f.color || '#6366f1'}"></i>
        <span>${escHtml(f.name)}</span>
      </div>
      ${buildItems(f.id)}
    `).join('');
  tree.innerHTML = buildItems(null);
}

function selectFolder(id) {
  APP.currentFolder = id;
  APP.page = 1;
  // Update active states for folders
  document.querySelectorAll('#folder-tree .folder-tree-item, #folder-all, #folder-unsorted').forEach(el => el.classList.remove('active'));
  if (id === null)    { $('folder-all').classList.add('active'); }
  else if (id === 'null') { $('folder-unsorted').classList.add('active'); }
  else if (id !== undefined) {
    const el = $(`ftree-${id}`);
    if (el) el.classList.add('active');
  }
  loadMedia();
}

async function loadMedia() {
  const search  = $('media-search')?.value || '';
  const sortBy  = $('media-sort-by')?.value || 'title';
  const sortDir = $('media-sort-dir')?.value || 'asc';
  const driveFilter = $('media-drive-filter')?.value || '';
  const limit   = 100;

  let url = `/api/media?search=${encodeURIComponent(search)}&sort_by=${sortBy}&sort_dir=${sortDir}&page=${APP.page}&limit=${limit}`;
  
  if (driveFilter) {
    url += `&drive_id=${driveFilter}`;
  } else if (APP.currentDrive) {
    url += `&drive_id=${APP.currentDrive}`;
  }

  if (APP.currentFolder === 'null') {
    url += '&folder_id=null'; // Unsorted
  } else if (APP.currentFolder !== null && APP.currentFolder !== undefined) {
    url += `&folder_id=${APP.currentFolder}`; // Specific folder
  }

  const { ok, data } = await apiFetch(url);
  if (!ok) { showToast('Failed to load media.', 'error'); return; }

  APP.mediaData  = data.videos || [];
  APP.totalItems = data.total || 0;
  APP.totalPages = Math.ceil(APP.totalItems / limit);
  APP.folders    = data.folders || [];

  renderFolderTree();
  renderMediaTable();
  updatePagination();
}

function renderMediaTable() {
  if (APP.mediaView === 'grid') { renderMediaGrid(); return; }

  const showResolution = $('col-resolution')?.checked;
  const showSize       = $('col-size')?.checked;
  const showViews      = $('col-views')?.checked;
  const showLinks      = $('col-links')?.checked;

  // Toggle header visibility
  $('th-resolution').style.display = showResolution ? '' : 'none';
  $('th-size').style.display       = showSize ? '' : 'none';
  $('th-views').style.display      = showViews ? '' : 'none';
  $('th-links').style.display      = showLinks ? '' : 'none';

  const tbody = $('media-tbody');
  if (!APP.mediaData.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="text-center py-14" style="color:#475569">
      <i class="fas fa-film text-3xl mb-3 block" style="color:#1e1e38"></i>
      No videos found. Try syncing a drive or adjusting your search.
    </td></tr>`;
    return;
  }

  tbody.innerHTML = APP.mediaData.map(v => {
    const isSelected = APP.selectedIds.has(v.id);
    const embedLink  = `${BASE_URL}/embed/${v.id}`;
    return `<tr class="${isSelected ? 'selected' : ''}" id="tr-${v.id}">
      <td><input type="checkbox" class="accent-brand-500 cursor-pointer" ${isSelected ? 'checked' : ''} onchange="toggleRowSelect(${v.id}, this)" /></td>
      <td>
        <div class="flex items-center gap-2">
          <div class="w-8 h-8 rounded-lg flex-shrink-0 flex items-center justify-center" style="background:rgba(99,102,241,0.1)">
            <i class="fas fa-play-circle text-xs" style="color:#6366f1"></i>
          </div>
          <div class="filename-cell">
            <span class="fname text-sm font-medium transition-colors" style="color:#c7d2fe"
              onclick="openVideoDetail(${v.id})"
              title="${escHtml(v.title)}">${escHtml(v.title)}</span>
          </div>
        </div>
      </td>
      <td style="display:${showResolution ? '' : 'none'}">${fmtResolutionBadge(v.resolution)}</td>
      <td style="display:${showSize ? '' : 'none'}"><span class="text-xs font-mono" style="color:#64748b">${formatBytes(v.size)}</span></td>
      <td style="display:${showViews ? '' : 'none'}"><span class="text-xs font-mono" style="color:#94a3b8">${formatNumber(v.views)}</span></td>
      <td style="display:${showLinks ? '' : 'none'}">
        <div class="flex items-center gap-1.5">
          <button onclick="openVideoDetail(${v.id})" class="p-1.5 rounded-lg text-xs transition-colors hover:bg-brand-500/20" style="color:#a5b4fc;background:none;border:none;cursor:pointer" title="Video Detail"><i class="fas fa-info-circle"></i></button>
          <a href="${embedLink}" target="_blank" class="p-1.5 rounded-lg text-xs transition-colors hover:bg-brand-500/20" style="color:#6366f1" title="Open in new tab"><i class="fas fa-external-link-alt"></i></a>
          <button onclick="copyToClipboard('${embedLink}')" class="p-1.5 rounded-lg text-xs transition-colors hover:bg-white/5" style="color:#64748b;background:none;border:none;cursor:pointer" title="Copy Embed URL"><i class="fas fa-copy"></i></button>
        </div>
      </td>
      <td>
        <div class="flex items-center gap-1">
          <button onclick="deleteVideo(${v.id})" class="p-1.5 rounded-lg text-xs transition-colors hover:bg-red-500/20" style="color:#f87171;background:none;border:none;cursor:pointer" title="Delete"><i class="fas fa-trash"></i></button>
        </div>
      </td>
    </tr>`;
  }).join('');
}

function renderMediaGrid() {
  const grid = $('media-grid');
  $('media-list-view').classList.add('hidden');
  $('media-grid-view').classList.remove('hidden');

  if (!APP.mediaData.length) {
    grid.innerHTML = `<div class="col-span-full text-center py-14" style="color:#475569"><i class="fas fa-film text-3xl mb-3 block" style="color:#1e1e38"></i>No videos found.</div>`;
    return;
  }

  grid.innerHTML = APP.mediaData.map(v => {
    const embedLink = `${BASE_URL}/embed/${v.id}`;
    return `
      <div class="video-grid-card group" onclick="window.open('${embedLink}','_blank')">
        <div class="relative" style="padding-bottom:56.25%;background:#0f0f1a">
          ${v.thumbnail_url
            ? `<img src="${escHtml(v.thumbnail_url)}" class="absolute inset-0 w-full h-full object-cover" loading="lazy" onerror="this.style.display='none'" />`
            : `<div class="absolute inset-0 flex items-center justify-center"><i class="fas fa-play-circle text-3xl" style="color:#2a2a4a"></i></div>`
          }
          <div class="absolute inset-0 flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity" style="background:rgba(0,0,0,0.5)">
            <div class="w-12 h-12 rounded-full flex items-center justify-center" style="background:rgba(99,102,241,0.8)"><i class="fas fa-play text-white"></i></div>
          </div>
          ${v.resolution ? `<span class="absolute top-2 right-2 badge badge-purple text-xs">${v.resolution}</span>` : ''}
        </div>
        <div class="p-3">
          <div class="text-sm font-medium text-white line-clamp-2 mb-1 leading-snug">${escHtml(v.title)}</div>
          <div class="flex items-center justify-between">
            <span class="text-xs" style="color:#64748b">${formatBytes(v.size)}</span>
            <div class="flex items-center gap-2 text-xs" style="color:#475569">
              <span><i class="fas fa-eye mr-1"></i>${formatNumber(v.views)}</span>
            </div>
          </div>
        </div>
      </div>`;
  }).join('');
}

function setMediaView(view) {
  APP.mediaView = view;
  $('media-list-view').classList.toggle('hidden', view !== 'list');
  $('media-grid-view').classList.toggle('hidden', view !== 'grid');
  $('view-list-btn').style.background = view === 'list' ? 'rgba(99,102,241,0.2)' : 'transparent';
  $('view-list-btn').style.color      = view === 'list' ? '#a5b4fc' : '#64748b';
  $('view-grid-btn').style.background = view === 'grid' ? 'rgba(99,102,241,0.2)' : 'transparent';
  $('view-grid-btn').style.color      = view === 'grid' ? '#a5b4fc' : '#64748b';
  renderMediaTable();
}

function updatePagination() {
  const bar = $('pagination-bar');
  if (APP.totalPages <= 1) { bar.classList.add('hidden'); return; }
  bar.classList.remove('hidden');
  $('pagination-info').textContent = `Page ${APP.page} of ${APP.totalPages} (${formatNumber(APP.totalItems)} videos)`;
  $('btn-prev').disabled = APP.page <= 1;
  $('btn-next').disabled = APP.page >= APP.totalPages;
}

function changePage(delta) {
  APP.page = Math.max(1, Math.min(APP.totalPages, APP.page + delta));
  loadMedia();
}

function debounceSearch() {
  clearTimeout(APP.searchTimeout);
  APP.searchTimeout = setTimeout(() => { APP.page = 1; loadMedia(); }, 300);
}

function sortByColumn(col) {
  const sortBy = $('media-sort-by');
  const sortDir = $('media-sort-dir');
  if (sortBy.value === col) {
    sortDir.value = sortDir.value === 'asc' ? 'desc' : 'asc';
  } else {
    sortBy.value  = col;
    sortDir.value = 'asc';
  }
  APP.page = 1;
  loadMedia();
}

// ── SELECTION ─────────────────────────────────────────────────
function toggleRowSelect(id, cb) {
  if (cb.checked) APP.selectedIds.add(id);
  else            APP.selectedIds.delete(id);
  const tr = $(`tr-${id}`);
  if (tr) tr.classList.toggle('selected', cb.checked);
  updateBulkBar();
}

function toggleAllCheckboxes() {
  const master = $('check-all');
  APP.mediaData.forEach(v => {
    if (master.checked) APP.selectedIds.add(v.id);
    else                APP.selectedIds.delete(v.id);
  });
  renderMediaTable();
  updateBulkBar();
}

function clearSelection() {
  APP.selectedIds.clear();
  $('check-all').checked = false;
  renderMediaTable();
  updateBulkBar();
}

function updateBulkBar() {
  const bar = $('bulk-bar');
  if (APP.selectedIds.size > 0) {
    bar.style.display = 'flex';
    $('bulk-count').textContent = APP.selectedIds.size;
  } else {
    bar.style.display = 'none';
  }
}

async function bulkDelete() {
  if (!APP.selectedIds.size) return;
  if (!confirm(`Delete ${APP.selectedIds.size} selected video(s)? This cannot be undone.`)) return;
  const { ok, data } = await apiFetch('/api/media', {
    method: 'DELETE',
    body: { video_ids: [...APP.selectedIds] },
  });
  if (ok) { showToast(`${data.deleted} videos deleted.`, 'success'); clearSelection(); loadMedia(); }
  else    showToast(data.error || 'Delete failed.', 'error');
}

async function bulkMove() {
  if (!APP.selectedIds.size || !APP.folders.length) {
    showToast('No folders available. Create a folder first.', 'info'); return;
  }
  const folderList = APP.folders.map(f => `${f.id}: ${f.name}`).join('\n');
  const input = prompt(`Enter the target folder ID:\n\n${folderList}\n\n(Leave blank to move to root)`);
  if (input === null) return;
  const fid = input.trim() ? parseInt(input.trim()) : null;
  const { ok, data } = await apiFetch('/api/media/move', {
    method: 'POST',
    body: { video_ids: [...APP.selectedIds], folder_id: fid },
  });
  if (ok) { showToast(`Moved ${data.moved} videos.`, 'success'); clearSelection(); loadMedia(); }
  else    showToast(data.error || 'Move failed.', 'error');
}

async function deleteVideo(id) {
  if (!confirm('Delete this video from the index?')) return;
  const { ok, data } = await apiFetch('/api/media', {
    method: 'DELETE',
    body: { video_ids: [id] },
  });
  if (ok) { showToast('Video removed.', 'success'); loadMedia(); }
  else    showToast(data.error || 'Delete failed.', 'error');
}

// ── COLUMN TOGGLE ─────────────────────────────────────────────
function toggleColumnDropdown() {
  $('col-dropdown').classList.toggle('hidden');
}
document.addEventListener('click', e => {
  if (!$('col-toggle-btn')?.contains(e.target) && !$('col-dropdown')?.contains(e.target)) {
    $('col-dropdown')?.classList.add('hidden');
  }
});

// ── UPLOAD ────────────────────────────────────────────────────
function switchUploadTab(tab) {
  $('upload-device-panel').classList.toggle('hidden', tab !== 'device');
  $('upload-remote-panel').classList.toggle('hidden', tab !== 'remote');
  $('upload-tab-device').classList.toggle('active', tab === 'device');
  $('upload-tab-remote').classList.toggle('active', tab === 'remote');
}

function populateDriveSelects() {
  const opts = '<option value="">Select Drive...</option>' +
    APP.drives.map(d => `<option value="${d.id}">${escHtml(d.drive_name)}</option>`).join('');
  ['device-drive-select', 'remote-drive-select'].forEach(id => {
    const el = $(id);
    if (el) el.innerHTML = opts;
  });

  const mediaDriveFilter = $('media-drive-filter');
  if (mediaDriveFilter) {
    mediaDriveFilter.innerHTML = '<option value="">Semua Drive</option>' +
      APP.drives.map(d => `<option value="${d.id}">${escHtml(d.drive_name)}</option>`).join('');
  }
}

function populateFolderSelects() {
  const opts = '<option value="">— Root (No folder) —</option>' +
    '<option value="NEW_FOLDER" style="color:#10b981;font-weight:bold;">＋ Create New Folder...</option>' +
    APP.folders.map(f => `<option value="${f.id}">${escHtml(f.name)}</option>`).join('');
  ['device-folder-select', 'remote-folder-select', 'folder-parent-select'].forEach(id => {
    const el = $(id);
    if (el) el.innerHTML = opts;
  });
}

function handleDragOver(e) { e.preventDefault(); $('drop-zone').style.borderColor = '#6366f1'; }
function handleDragLeave()  { $('drop-zone').style.borderColor = '#2a2a4a'; }
function handleDropZoneDrop(e) {
  e.preventDefault();
  $('drop-zone').style.borderColor = '#2a2a4a';
  handleFileSelect({ target: { files: e.dataTransfer.files } });
}

let uploadQueue = [];
function handleFileSelect(e) {
  const files = Array.from(e.target.files || []);
  uploadQueue = [...uploadQueue, ...files];
  renderUploadQueue();
}

function renderUploadQueue() {
  const container = $('upload-queue');
  if (!uploadQueue.length) { container.classList.add('hidden'); return; }
  container.classList.remove('hidden');
  container.innerHTML = uploadQueue.map((f, i) => `
    <div class="flex items-center gap-3 p-3 rounded-xl" style="background:#1a1a30;border:1px solid #2a2a4a">
      <i class="fas fa-file-video text-sm" style="color:#6366f1"></i>
      <div class="flex-1 min-w-0">
        <div class="text-sm font-medium text-white truncate">${escHtml(f.name)}</div>
        <div class="text-xs" style="color:#64748b">${formatBytes(f.size)}</div>
      </div>
      <button onclick="uploadQueue.splice(${i},1);renderUploadQueue()" style="color:#f87171;background:none;border:none;cursor:pointer"><i class="fas fa-times text-xs"></i></button>
    </div>`).join('');
}

function clearUploadQueue() { uploadQueue = []; renderUploadQueue(); $('file-input').value = ''; }

async function startDeviceUpload() {
  const driveId = $('device-drive-select').value;
  const folderId = $('device-folder-select').value;
  if (!driveId) { showToast('Please select a target drive.', 'error'); return; }
  if (!uploadQueue.length) { showToast('No files in queue.', 'error'); return; }

  const files = [...uploadQueue];
  uploadQueue = [];
  renderUploadQueue();

  const progressArea = $('device-progress');
  progressArea.classList.remove('hidden');
  progressArea.innerHTML = '';

  const CHUNK_SIZE = 10 * 1024 * 1024; // 10MB

  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    const id = 'dev-up-' + i;
    progressArea.insertAdjacentHTML('beforeend', `
      <div id="${id}" class="flex items-center gap-3 p-3 rounded-xl" style="background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.05)">
        <i class="fas fa-spinner fa-spin text-brand-400"></i>
        <div class="flex-1 min-w-0">
          <div class="text-sm font-medium text-white truncate">${escHtml(file.name)}</div>
          <div class="w-full bg-slate-800 rounded-full h-1.5 mt-2">
            <div id="${id}-bar" class="bg-brand-500 h-1.5 rounded-full" style="width: 0%"></div>
          </div>
        </div>
        <div id="${id}-pct" class="text-xs font-semibold text-brand-400">0%</div>
      </div>
    `);

    const updateUI = (pct, color, iconClass) => {
      if (pct !== null) {
        $(`${id}-bar`).style.width = pct + '%';
        $(`${id}-pct`).textContent = pct + '%';
      }
      if (color) $(`${id}-pct`).style.color = color;
      if (iconClass) {
        const icon = $(id).querySelector('i');
        icon.className = iconClass;
        if (color) icon.style.color = color;
      }
    };

    try {
      // 1. Get Session URL
      updateUI(0, null, 'fas fa-spinner fa-spin');
      const sessRes = await apiFetch(`/api/drives/${driveId}/upload-session`, {
        method: 'POST',
        body: {
          filename: file.name,
          mimeType: file.type || 'application/octet-stream',
          folder_id: folderId || null,
          contentLength: file.size
        }
      });
      if (!sessRes.ok) throw new Error(sessRes.data.error || 'Failed to initialize session');
      const uploadUrl = sessRes.data.uploadUrl;

      // 2. Chunked Upload
      let uploadedBytes = 0;
      let driveFileId = null;

      for (let start = 0; start < file.size; start += CHUNK_SIZE) {
        const end = Math.min(start + CHUNK_SIZE, file.size);
        const chunk = file.slice(start, end);
        
        const chunkRes = await fetch(uploadUrl, {
          method: 'PUT',
          headers: {
            'Content-Range': `bytes ${start}-${end - 1}/${file.size}`
          },
          body: chunk
        });

        if (chunkRes.status === 308) {
          // Resume incomplete, continue
          uploadedBytes = end;
          const pct = Math.round((uploadedBytes / file.size) * 100);
          updateUI(pct);
        } else if (chunkRes.status === 200 || chunkRes.status === 201) {
          // Done
          const result = await chunkRes.json();
          driveFileId = result.id;
          updateUI(100);
          break;
        } else {
          throw new Error('Upload failed with status ' + chunkRes.status);
        }
      }

      if (!driveFileId) throw new Error('Failed to retrieve file ID');

      // 3. Finalize
      const finalizeRes = await apiFetch(`/api/drives/${driveId}/upload-complete`, {
        method: 'POST',
        body: {
          drive_file_id: driveFileId,
          folder_id: folderId || null,
          title: file.name,
          mime_type: file.type || 'application/octet-stream'
        }
      });
      if (!finalizeRes.ok) throw new Error(finalizeRes.data.error || 'Failed to index file');

      updateUI(100, '#10b981', 'fas fa-check-circle');
    } catch (e) {
      updateUI(null, '#ef4444', 'fas fa-times-circle');
      $(`${id}-pct`).textContent = 'Failed';
      console.error('Device upload failed:', e);
    }
  }

  showToast('Upload process completed.', 'success');
  loadMedia(); // refresh library
}

function updateUrlCount() {
  const urls = $('remote-urls').value.split('\n').filter(l => l.trim());
  $('url-count').textContent = `${urls.length} URL${urls.length !== 1 ? 's' : ''}`;
}

async function startRemoteUpload() {
  const driveId   = $('remote-drive-select').value;
  const folderId  = $('remote-folder-select').value;
  const prefix    = $('remote-title-prefix').value;
  const rawUrls   = $('remote-urls').value;
  const urls      = rawUrls.split('\n').map(l => l.trim()).filter(Boolean);

  if (!driveId) { showToast('Please select a target drive.', 'error'); return; }
  if (!urls.length) { showToast('Enter at least one URL.', 'error'); return; }

  const progressArea = $('remote-progress');
  progressArea.classList.remove('hidden');
  progressArea.innerHTML = urls.map((u, i) => `
    <div id="rp-${i}" class="flex items-center gap-3 p-3 rounded-xl text-xs" style="background:#1a1a30;border:1px solid #2a2a4a">
      <i class="fas fa-circle-notch fa-spin" style="color:#6366f1"></i>
      <div class="flex-1 truncate" style="color:#94a3b8">${escHtml(u)}</div>
      <span id="rp-status-${i}" style="color:#64748b">Queued</span>
    </div>`).join('');

  const { ok, data } = await apiFetch('/api/media/upload/remote', {
    method: 'POST',
    body: { urls, drive_id: parseInt(driveId), folder_id: folderId ? parseInt(folderId) : null, title_prefix: prefix || undefined },
  });

  if (ok) {
    data.results.forEach((r, i) => {
      const el = $(`rp-${i}`);
      if (!el) return;
      const icon  = r.status === 'success' ? 'fa-check-circle' : 'fa-exclamation-circle';
      const color = r.status === 'success' ? '#34d399' : '#f87171';
      el.querySelector('i').className = `fas ${icon}`;
      el.querySelector('i').style.color = color;
      const stat = $(`rp-status-${i}`);
      stat.textContent = r.status === 'success' ? 'Done ✓' : `Error: ${r.error}`;
      stat.style.color = color;
    });
    showToast(`Upload batch complete!`, 'success');
    loadMedia();
  } else {
    showToast(data.error || 'Upload failed.', 'error');
  }
}

// ── VIDEO DETAIL MODAL ───────────────────────────────────────
function openVideoDetail(videoId) {
  // Find the video in current page data first (fast path)
  const v = APP.mediaData.find(x => x.id === videoId);
  if (!v) return;
  _populateVideoDetailModal(v);
}

function _populateVideoDetailModal(v) {
  const base        = BASE_URL;
  const cleanTitle  = (v.title || 'video.mp4').replace(/[^a-zA-Z0-9.\-_ ]/g, '_');
  const streamUrl   = `${base}/stream/${v.id}/${encodeURIComponent(cleanTitle)}`;
  const embedLink   = `${base}/embed/${v.id}`;
  const streamLink  = streamUrl;
  const dlLink      = `${streamUrl}?download=1`;
  const embedCode   = `<iframe src="${embedLink}" width="640" height="360" frameborder="0" allowfullscreen></iframe>`;

  // Header
  $('vd-title').textContent = v.title;
  $('vd-meta').textContent  = `${v.drive_name || 'Drive'} · ${formatBytes(v.size)} · Added ${v.created_at ? new Date(v.created_at).toLocaleDateString() : '—'}`;

  // Stats
  $('vd-resolution').textContent = v.resolution || '—';
  $('vd-size').textContent       = formatBytes(v.size);
  $('vd-views').textContent      = formatNumber(v.views);

  // Links
  $('vd-link-player').textContent    = embedLink;
  $('vd-link-player-open').href      = embedLink;
  $('vd-link-download').textContent  = dlLink;
  $('vd-link-download-open').href    = dlLink;
  $('vd-link-stream').textContent    = streamLink;
  $('vd-link-code').textContent      = embedCode;

  // Open tab button
  $('vd-open-tab').href = embedLink;

  // Drive info
  $('vd-fileid').textContent = v.id;
  $('vd-drive').textContent  = v.drive_name || '—';

  // Load iframe (use embed URL; player handles heavy/light detection itself)
  const iframe = $('vd-iframe');
  if (iframe.src !== embedLink) iframe.src = embedLink;

  // Show modal
  $('modal-video-detail').classList.remove('hidden');
}

function vdCopy(elementId) {
  const el = $(elementId);
  if (!el) return;
  const text = el.textContent || el.innerText;
  navigator.clipboard.writeText(text)
    .then(() => showToast('Copied!', 'success', 1500))
    .catch(() => {
      // Fallback
      const ta = document.createElement('textarea');
      ta.value = text; document.body.appendChild(ta);
      ta.select(); document.execCommand('copy');
      ta.remove();
      showToast('Copied!', 'success', 1500);
    });
}

// Close video modal: also stop iframe to prevent background audio
function closeVideoDetail() {
  $('vd-iframe').src = '';
  closeModal('modal-video-detail');
}

// ── AUTO-SYNC SETTINGS ───────────────────────────────────
let _autoSyncSettings = null;

async function loadAutoSyncSettings() {
  const { ok, data } = await apiFetch('/api/settings/auto-sync');
  if (!ok) return;
  _autoSyncSettings = data;
  $('autosync-enabled').checked = data.auto_sync_enabled;
  $('autosync-interval').value  = String(data.auto_sync_interval_minutes || 30);

  const last = data.last_auto_sync_at ? new Date(data.last_auto_sync_at) : null;
  if (last && last.getFullYear() > 1970) {
    $('autosync-last').textContent = last.toLocaleString();
    // Compute next
    const next = new Date(last.getTime() + data.auto_sync_interval_minutes * 60000);
    const now  = new Date();
    if (next > now) {
      const diffMin = Math.ceil((next - now) / 60000);
      $('autosync-next').textContent = `~${diffMin} min (${next.toLocaleTimeString()})`;
    } else {
      $('autosync-next').textContent = 'Pending (next cron tick)';
    }
  } else {
    $('autosync-last').textContent = 'Never';
    $('autosync-next').textContent = data.auto_sync_enabled ? 'Will run on next cron tick' : '—';
  }
}

async function saveAutoSync() {
  const enabled  = $('autosync-enabled').checked;
  const interval = parseInt($('autosync-interval').value);
  const { ok, data } = await apiFetch('/api/settings/auto-sync', {
    method: 'POST',
    body: { auto_sync_enabled: enabled, auto_sync_interval_minutes: interval },
  });
  if (ok) {
    showToast(enabled ? `Auto-sync enabled — every ${interval} min` : 'Auto-sync disabled', 'success', 2500);
    loadAutoSyncSettings(); // refresh display
  } else {
    showToast(data.error || 'Failed to save settings', 'error');
  }
}

// ── EXPORT MODAL ──────────────────────────────────────────────
let exportBulkOnly = false;
function openExportModal(bulkOnly = false) {
  exportBulkOnly = bulkOnly;
  $('modal-export').classList.remove('hidden');
}

function setExportSeparator(type) {
  APP.exportSeparator = type;
  ['newline','tab','csv','pipe'].forEach(t => $(`sep-${t}`)?.classList.toggle('active', t === type));
}

function getExportData() {
  return exportBulkOnly
    ? APP.mediaData.filter(v => APP.selectedIds.has(v.id))
    : APP.mediaData;
}

function generateExportText() {
  const data = getExportData();
  const sep  = { newline: '\n', tab: '\t', csv: ',', pipe: ' | ' }[APP.exportSeparator] || '\n';
  const fields = {
    title:        $('exp-title')?.checked,
    file_id:      $('exp-file-id')?.checked,
    resolution:   $('exp-resolution')?.checked,
    size:         $('exp-size')?.checked,
    embed_link:   $('exp-embed-link')?.checked,
    embed_code:   $('exp-embed-code')?.checked,
    stream_link:  $('exp-stream-link')?.checked,
    download_link:$('exp-download-link')?.checked,
    views:        $('exp-views')?.checked,
  };

  const lines = data.map(v => {
    const parts = [];
    const cleanTitle = (v.title || 'video.mp4').replace(/[^a-zA-Z0-9.\-_ ]/g, '_');
    const streamUrl  = `${BASE_URL}/stream/${v.id}/${encodeURIComponent(cleanTitle)}`;

    if (fields.title)        parts.push(v.title);
    if (fields.file_id)      parts.push(v.id);
    if (fields.resolution)   parts.push(v.resolution || '');
    if (fields.size)         parts.push(formatBytes(v.size));
    if (fields.embed_link)   parts.push(`${BASE_URL}/embed/${v.id}`);
    if (fields.embed_code)   parts.push(`<iframe src="${BASE_URL}/embed/${v.id}" width="640" height="360" frameborder="0" allowfullscreen></iframe>`);
    if (fields.stream_link)  parts.push(streamUrl);
    if (fields.download_link)parts.push(`${streamUrl}?download=1`);
    if (fields.views)        parts.push(String(v.views));
    return APP.exportSeparator === 'newline' ? parts.join('\n') : parts.join(sep);
  });

  const divider = APP.exportSeparator === 'newline' ? '\n\n' : '\n';
  return lines.join(divider);
}

/**
 * Player4Me-style: open the exported content as a Blob URL in a new tab.
 * This gives a clean, scrollable, full-page text view for easy bulk-copying.
 */
function openExportBlob() {
  const text = generateExportText();
  if (!text.trim()) { showToast('No data to export. Select fields and try again.', 'error'); return; }
  const blob   = new Blob([text], { type: 'text/plain;charset=utf-8' });
  const blobUrl = URL.createObjectURL(blob);
  const win = window.open(blobUrl, '_blank');
  // Revoke after short delay so the tab can read it
  setTimeout(() => URL.revokeObjectURL(blobUrl), 5000);
  if (!win) showToast('Pop-up blocked. Please allow pop-ups for this site.', 'error');
  else closeModal('modal-export');
}

function downloadExport() {
  const val = generateExportText();
  const blob = new Blob([val], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `harustream-export-${Date.now()}.txt`;
  a.click();
}

async function exportToTelegraph() {
  const originalSep = APP.exportSeparator;
  // Force newline separator for Telegraph
  APP.exportSeparator = 'newline';
  const text = generateExportText();
  APP.exportSeparator = originalSep;
  
  if (!text.trim()) { showToast('No data to export.', 'error'); return; }
  
  showToast('Creating Telegra.ph page...', 'info', 2000);
  try {
    const title = 'HaruStream Export ' + new Date().toISOString().slice(0,10);
    
    // 1. Get or create Telegraph account
    let token = localStorage.getItem('telegraph_token');
    if (!token) {
      const accRes = await fetch('https://api.telegra.ph/createAccount?short_name=HaruStream&author_name=HaruStream');
      const accJson = await accRes.json();
      token = accJson.result.access_token;
      localStorage.setItem('telegraph_token', token);
    }
    
    // 2. Format content into Telegraph nodes
    const content = [];
    text.split('\n').forEach(line => {
      if (!line.trim()) {
        content.push({ tag: 'br' });
      } else if (line.startsWith('http://') || line.startsWith('https://')) {
        content.push({ tag: 'a', attrs: { href: line, target: '_blank' }, children: [line] });
        content.push({ tag: 'br' });
      } else if (line.startsWith('<iframe')) {
        // Just text for iframe code
        content.push({ tag: 'code', children: [line] });
        content.push({ tag: 'br' });
      } else {
        content.push({ tag: 'p', children: [line] });
      }
    });
    
    // 3. Create page
    const pageRes = await fetch('https://api.telegra.ph/createPage', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        access_token: token,
        title: title,
        content: content,
        return_content: false
      })
    });
    
    const pageJson = await pageRes.json();
    if (pageJson.ok) {
      window.open(pageJson.result.url, '_blank');
      closeModal('modal-export');
    } else {
      throw new Error(pageJson.error);
    }
  } catch (e) {
    console.error(e);
    // Fallback to katb.in if telegraph fails
    try {
      showToast('Telegra.ph failed. Trying katb.in...', 'info', 2000);
      const kRes = await fetch('https://katb.in/api/paste', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ paste: { content: text } })
      });
      const kJson = await kRes.json();
      if (kJson.id) {
        window.open('https://katb.in/' + kJson.id, '_blank');
        closeModal('modal-export');
      } else {
        throw new Error('Katb.in failed');
      }
    } catch(err) {
      showToast('Export failed: ' + e.message, 'error');
    }
  }
}

// ── FOLDER MODALS ─────────────────────────────────────────────
function openNewFolderModal() {
  populateFolderSelects();
  $('modal-new-folder').classList.remove('hidden');
}

async function submitNewFolder(e) {
  e.preventDefault();
  const { ok, data } = await apiFetch('/api/folders', {
    method: 'POST',
    body: {
      name:      $('folder-name-input').value,
      parent_id: $('folder-parent-select').value ? parseInt($('folder-parent-select').value) : null,
      color:     $('folder-color-input').value,
    },
  });
  if (ok) {
    showToast('Folder created!', 'success');
    closeModal('modal-new-folder');
    e.target.reset();
    loadFolders();
  } else {
    showToast(data.error || 'Failed to create folder.', 'error');
  }
}

// ── UTILS ─────────────────────────────────────────────────────
function closeModal(id) {
  const el = $(id);
  if (!el) return;
  el.classList.add('hidden');
  // If closing the video detail modal, also stop the iframe
  if (id === 'modal-video-detail') {
    const iframe = $('vd-iframe');
    if (iframe) iframe.src = '';
  }
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => showToast('Copied!', 'success'));
}

function escHtml(str) {
  return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// Close modals on overlay click
document.querySelectorAll('.modal-overlay').forEach(overlay => {
  overlay.addEventListener('click', e => {
    if (e.target === overlay) {
      overlay.classList.add('hidden');
      if (overlay.id === 'modal-video-detail') {
        const iframe = $('vd-iframe');
        if (iframe) iframe.src = '';
      }
    }
  });
});

// Keyboard shortcuts
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    document.querySelectorAll('.modal-overlay').forEach(m => m.classList.add('hidden'));
    $('col-dropdown')?.classList.add('hidden');
  }
});
