// SecureOps AI Frontend - Dynamic API Integration with Fallback
(function(){
  'use strict';

  // Simple router mapping
  const routes = {
    '/': renderHome,
    '/dashboard': renderDashboard,
    '/metrics': renderMetrics,
    '/logs': renderLogs,
    '/about': renderAbout
  };

  function qs(sel, root=document){return root.querySelector(sel)}
  function qsa(sel, root=document){return Array.from(root.querySelectorAll(sel))}

  // API Helper Functions
  async function apiCall(endpoint, options = {}) {
    try {
      const url = getApiUrl(endpoint);
      const response = await fetch(url, {
        headers: {
          'Content-Type': 'application/json',
          ...options.headers
        },
        ...options
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      return await response.json();
    } catch (error) {
      console.warn(`API call failed for ${endpoint}:`, error);
      return getFallbackData(endpoint);
    }
  }

  // Fallback data when API is unavailable
  function getFallbackData(endpoint) {
    const fallbacks = {
      '/dashboard/security-metrics': {
        active_agents: 42,
        alerts_today: 7,
        avg_response_ms: 123,
        incidents_open: 3,
        last_updated: new Date().toISOString()
      },
      '/dashboard/system-health': {
        cpu: [12,18,25,22,34,29,31],
        memory: [40,42,41,43,45,46,44],
        uptime: '7d 14h 32m'
      },
      '/audit/logs': [
        {timestamp:'2025-11-05 09:12', level:'INFO', message:'Service started'},
        {timestamp:'2025-11-05 10:02', level:'WARN', message:'Unusual auth attempts detected'},
        {timestamp:'2025-11-05 11:00', level:'ALERT', message:'MFA challenge failed 3 times for user alice'}
      ]
    };
    return fallbacks[endpoint] || { status: 'offline', message: 'Demo mode - backend unavailable' };
  }

  // Data store for API responses
  let appData = {
    metrics: null,
    systemHealth: null,
    auditLogs: null,
    isOnline: false
  };

  function setContent(html){qs('#main').innerHTML = html}

  async function renderHome(){
    // Show loading state
    setContent(`
      <div class="card">
        <h2 class="h1">SecureOps AI Dashboard</h2>
        <p class="small">Loading system metrics... ${appData.isOnline ? '🟢 Backend Connected' : '🟡 Demo Mode'}</p>
      </div>
    `);

    // Fetch latest metrics
    const metrics = await apiCall(CONFIG.ENDPOINTS.DASHBOARD.METRICS);
    appData.metrics = metrics;
    appData.isOnline = !metrics.status || metrics.status !== 'offline';

    setContent(`
      <div class="card">
        <h2 class="h1">SecureOps AI Dashboard ${appData.isOnline ? '🟢' : '🟡'}</h2>
        <p class="small">${appData.isOnline ? 'Connected to live backend' : 'Running in demo mode - backend unavailable'}</p>
        ${metrics.last_updated ? `<p class="small">Last updated: ${new Date(metrics.last_updated).toLocaleString()}</p>` : ''}
      </div>
      <div class="grid">
        <div class="card">
          <h3 class="h1">System KPIs</h3>
          <div class="kpi"><div><div class="small">Active agents</div><div class="val">${metrics.active_agents}</div></div><div class="badge">secure</div></div>
          <div class="kpi"><div><div class="small">Alerts today</div><div class="val">${metrics.alerts_today}</div></div><div class="badge">review</div></div>
          <div style="height:12px"></div>
          <div class="small">Average response time: <strong>${metrics.avg_response_ms} ms</strong></div>
          <div class="small">Open incidents: <strong>${metrics.incidents_open}</strong></div>
        </div>
        <div class="card">
          <h3 class="h1">Security Status</h3>
          <ul>
            <li class="small">✅ MFA enabled for admin accounts</li>
            <li class="small">✅ Password strength policy active</li>
            <li class="small">✅ Rate limiting on auth endpoints</li>
            <li class="small">✅ Audit logging operational</li>
          </ul>
          <div class="small" style="margin-top:10px">
            <strong>Backend Status:</strong> 
            <span style="color:${appData.isOnline ? 'var(--success)' : 'var(--accent)'}">
              ${appData.isOnline ? 'Online' : 'Demo Mode'}
            </span>
          </div>
        </div>
      </div>
    `)
  }

  async function renderDashboard(){
    setContent(`<div class="card"><h2 class="h1">Loading dashboard...</h2></div>`);
    
    const [metrics, alerts] = await Promise.all([
      apiCall(CONFIG.ENDPOINTS.DASHBOARD.METRICS),
      apiCall(CONFIG.ENDPOINTS.DASHBOARD.ALERTS)
    ]);

    setContent(`
      <div class="card">
        <h2 class="h1">Security Dashboard ${appData.isOnline ? '🟢' : '🟡'}</h2>
        <p class="small">Real-time security overview and incident management.</p>
        <div class="grid">
          <div class="card"><h4 class="small">Incidents open</h4><div class="val">${metrics.incidents_open || 0}</div></div>
          <div class="card"><h4 class="small">Avg response</h4><div class="val">${metrics.avg_response_ms || 0} ms</div></div>
        </div>
      </div>
      <div class="card">
        <h3 class="h1">Security Controls</h3>
        <p class="small">${appData.isOnline ? 'Connected to live backend - full functionality available' : 'Demo mode - view-only access'}</p>
        <div class="grid">
          <div class="card">
            <div class="small">Alert Management</div>
            <button onclick="refreshData()" class="badge" style="cursor:pointer;margin-top:8px">🔄 Refresh Data</button>
          </div>
          <div class="card">
            <div class="small">System Status</div>
            <div style="margin-top:8px">
              <span class="badge">Auth: Active</span>
              <span class="badge">Logging: ${appData.isOnline ? 'Live' : 'Demo'}</span>
            </div>
          </div>
        </div>
      </div>
    `)
  }

  async function renderMetrics(){
    setContent(`<div class="card"><h2 class="h1">Loading system metrics...</h2></div>`);
    
    const systemHealth = await apiCall(CONFIG.ENDPOINTS.DASHBOARD.SYSTEM_HEALTH);
    appData.systemHealth = systemHealth;

    setContent(`
      <div class="card">
        <h2 class="h1">System Metrics ${appData.isOnline ? '🟢' : '🟡'}</h2>
        <p class="small">Real-time system performance and health monitoring</p>
        ${systemHealth.uptime ? `<p class="small">Uptime: ${systemHealth.uptime}</p>` : ''}
      </div>
      <div class="grid">
        <div class="card">
          <h3 class="h1">CPU Usage</h3>
          <pre class="code">${(systemHealth.cpu || []).join(' | ') || 'No data'}</pre>
          <div class="small">Last 7 measurements (%)</div>
        </div>
        <div class="card">
          <h3 class="h1">Memory Usage</h3>
          <pre class="code">${(systemHealth.memory || []).join(' | ') || 'No data'}</pre>
          <div class="small">Last 7 measurements (%)</div>
        </div>
      </div>
      <div class="card">
        <h3 class="h1">Performance Insights</h3>
        <p class="small">System performance analysis based on current metrics</p>
        <div class="small">
          • CPU avg: ${systemHealth.cpu ? Math.round(systemHealth.cpu.reduce((a,b) => a+b) / systemHealth.cpu.length) : 'N/A'}%<br>
          • Memory avg: ${systemHealth.memory ? Math.round(systemHealth.memory.reduce((a,b) => a+b) / systemHealth.memory.length) : 'N/A'}%<br>
          • Status: ${appData.isOnline ? 'All systems operational' : 'Demo mode'}
        </div>
      </div>
    `)
  }

  async function renderLogs(){
    setContent(`<div class="card"><h2 class="h1">Loading audit logs...</h2></div>`);
    
    const logs = await apiCall(CONFIG.ENDPOINTS.AUDIT.LOGS);
    appData.auditLogs = logs;

    setContent(`
      <div class="card">
        <h2 class="h1">Audit Logs ${appData.isOnline ? '🟢' : '🟡'}</h2>
        <p class="small">Security events and system activity logs</p>
        <button onclick="refreshLogs()" class="badge" style="cursor:pointer;margin-left:10px">🔄 Refresh</button>
      </div>
      <div class="card">
        <table style="width:100%;border-collapse:collapse">
          <thead>
            <tr style="border-bottom:1px solid rgba(255,255,255,0.1)">
              <th class="small" style="text-align:left;padding:8px">Timestamp</th>
              <th class="small" style="text-align:left;padding:8px">Level</th>
              <th class="small" style="text-align:left;padding:8px">Event</th>
            </tr>
          </thead>
          <tbody>
            ${Array.isArray(logs) ? logs.map(l=>`
              <tr>
                <td class="small" style="padding:8px">${l.timestamp || l.ts}</td>
                <td class="small" style="padding:8px">
                  <span class="badge" style="background:${l.level==='ALERT'?'var(--danger)':l.level==='WARN'?'var(--accent)':'var(--success)'}">
                    ${l.level}
                  </span>
                </td>
                <td class="small" style="padding:8px">${l.message || l.msg}</td>
              </tr>
            `).join('') : '<tr><td colspan="3" class="small center">No logs available</td></tr>'}
          </tbody>
        </table>
      </div>
    `)
  }

  function renderAbout(){
    setContent(`
      <div class="card">
        <h2 class="h1">SecureOps AI - Full Stack Deployment</h2>
        <p class="small">This frontend is deployed on GitHub Pages and dynamically connects to a live backend API.</p>
        
        <h4 class="small">Architecture</h4>
        <div class="code" style="margin:10px 0">
Frontend: GitHub Pages (${window.location.origin})<br>
Backend: ${CONFIG.API_BASE_URL}<br>
Status: ${appData.isOnline ? '🟢 Connected' : '🟡 Demo Mode'}
        </div>

        <h4 class="small">Deployment Setup</h4>
        <ol class="small">
          <li>Frontend deployed via GitHub Pages from <code>/docs</code> folder</li>
          <li>Backend deployed on Render/Vercel/Railway with CORS enabled</li>
          <li>Environment detection automatically switches API endpoints</li>
          <li>Fallback to demo mode when backend is unavailable</li>
        </ol>

        <h4 class="small">Features</h4>
        <ul class="small">
          <li>✅ Real-time security metrics</li>
          <li>✅ Live audit log streaming</li>
          <li>✅ System health monitoring</li>
          <li>✅ Cross-origin request handling</li>
          <li>✅ Graceful degradation to demo mode</li>
        </ul>

        <div class="card" style="margin-top:20px">
          <h4 class="small">API Configuration</h4>
          <button onclick="testConnection()" class="badge" style="cursor:pointer">🔗 Test Backend Connection</button>
          <div id="connectionTest" style="margin-top:10px"></div>
        </div>
      </div>
    `)
  }

  // Global helper functions
  window.refreshData = async function() {
    if (window.location.hash === '#/dashboard' || !window.location.hash || window.location.hash === '#/') {
      await renderHome();
    }
  };

  window.refreshLogs = async function() {
    await renderLogs();
  };

  window.testConnection = async function() {
    const testEl = qs('#connectionTest');
    testEl.innerHTML = '<div class="small">Testing connection...</div>';
    
    try {
      const response = await fetch(`${CONFIG.API_BASE_URL}/health`, { 
        method: 'GET',
        mode: 'cors'
      });
      
      if (response.ok) {
        testEl.innerHTML = '<div class="small" style="color:var(--success)">✅ Backend connection successful!</div>';
      } else {
        throw new Error(`HTTP ${response.status}`);
      }
    } catch (error) {
      testEl.innerHTML = `<div class="small" style="color:var(--accent)">⚠️ Backend unavailable: ${error.message}</div>`;
    }
  };

  // Navigation handler
  function navigate(){
    const path = location.hash.replace('#','') || '/';
    (routes[path] || renderHome)();
    // update active link
    qsa('a[data-route]').forEach(a=>{
      const href = a.getAttribute('href').replace('#','')||'/';
      a.classList.toggle('active', href===path);
    })
  }

  // wire links
  document.addEventListener('click', (ev)=>{
    const a = ev.target.closest && ev.target.closest('a[data-route]');
    if(a){ ev.preventDefault(); location.hash = a.getAttribute('href'); }
  });

  window.addEventListener('hashchange', navigate);

  // init
  navigate();
})();
