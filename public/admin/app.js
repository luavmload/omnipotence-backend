const $ = sel => document.querySelector(sel)

let page = 1
let adminCount = 0
let currentUser = null
let sessionToken = null
let antiTamperToken = null
let sessionNonce = null
const perPage = 25
const API_BASE = './api'

async function loadBranding(){
  try{
    const res = await fetch('config.json')
    const cfg = await res.json()
    if (cfg?.brand) {
      const b = cfg.brand
      document.querySelector('.logo').textContent = b.logo || document.querySelector('.logo').textContent
      document.querySelector('h1').textContent = b.title || document.querySelector('h1').textContent
      const sub = document.querySelector('.subtitle')
      if (sub) sub.textContent = b.subtitle || sub.textContent
      if (b.accent) document.documentElement.style.setProperty('--accent', b.accent)
    }
  }catch(e){console.warn('branding load failed',e)}
}

async function fetchChallenge() {
  const headers = {}
  if (sessionToken) headers['Authorization'] = `Bearer ${sessionToken}`
  try {
    const res = await fetch(`${API_BASE}/challenge`, { headers })
    const newAntiTamper = res.headers.get('x-anti-tamper')
    if (newAntiTamper) antiTamperToken = newAntiTamper
    const json = await res.json()
    if (json.ok) {
      antiTamperToken = json.antiTamper
      if (json.nonce) sessionNonce = json.nonce
    }
  } catch (e) {
    console.warn('challenge fetch failed', e)
  }
}

function showLogin(message) {
  $('#loginPage').classList.remove('hidden')
  $('#dashboard').classList.add('hidden')
  $('#loginError').textContent = message || ''
}

function showDashboard(message) {
  $('#loginPage').classList.add('hidden')
  $('#dashboard').classList.remove('hidden')
  $('#statusMessage').textContent = message || ''
}

function clearSession() {
  sessionToken = null
  antiTamperToken = null
  sessionNonce = null
  currentUser = null
  localStorage.removeItem('admin_session_token')
  localStorage.removeItem('admin_user')
  $('#username').value = ''
  $('#password').value = ''
  showLogin()
  fetchChallenge()
}

async function initSession(token, user) {
  sessionToken = token
  if (user) {
    localStorage.setItem('admin_user', JSON.stringify(user))
    currentUser = user
  }
  localStorage.setItem('admin_session_token', token)
  await fetchChallenge()
  if (!sessionNonce) {
    clearSession()
    showLogin('Session expired. Please login again.')
    return false
  }
  showDashboard('Logged in')
  $('#currentUser').textContent = currentUser.displayName || currentUser.username
  await loadKeys()
  await loadDetectionStatus()
  return true
}

async function adminFetch(path, opts = {}) {
  opts.headers = opts.headers || {}
  if (sessionToken) opts.headers['Authorization'] = `Bearer ${sessionToken}`
  if (sessionNonce) opts.headers['X-Session-Nonce'] = sessionNonce
  if (antiTamperToken && !sessionNonce) opts.headers['X-Anti-Tamper'] = antiTamperToken
  if (!opts.method) opts.method = 'GET'
  if (opts.body && typeof opts.body === 'object') {
    opts.body = JSON.stringify(opts.body)
    opts.headers['Content-Type'] = 'application/json'
  }

  const res = await fetch(path, opts)
  const newToken = res.headers.get('x-session-token')
  if (newToken) {
    sessionToken = newToken
    localStorage.setItem('admin_session_token', newToken)
  }
  const json = await res.json().catch(() => ({ ok: false, error: 'Invalid response' }))
  if (res.status === 401) {
    clearSession()
    showLogin('Unauthorized. Please login again.')
    return { ok: false, error: 'Unauthorized' }
  }
  return json
}

async function loadKeys() {
  const search = $('#search').value
  const res = await adminFetch(`${API_BASE}/keys?page=${page}&perPage=${perPage}&search=${encodeURIComponent(search)}`)
  if (!res.ok) {
    $('#statusMessage').textContent = res.error || 'Failed to load keys.'
    return
  }

  const tbody = $('#keysTable tbody')
  tbody.innerHTML = ''
  res.keys.forEach(k => {
    const tr = document.createElement('tr')
    tr.innerHTML = `<td>${k.key}</td><td>${k.used}</td><td>${k.banned ? (k.ban_reason ? 'YES - ' + k.ban_reason : 'YES') : ''}</td><td>${k.hwid || ''}</td><td>${k.ip || ''}</td><td>${k.uses_count || 0}</td><td>${k.last_verified || ''}</td><td>
      <button data-key="${k.key}" class="ban">${k.banned ? 'Unban' : 'Ban'}</button>
      <button data-key="${k.key}" class="reset">Reset</button>
      <button data-key="${k.key}" class="del">Delete</button>
    </td>`
    tbody.appendChild(tr)
  })
  $('#pageInfo').textContent = `Page ${res.page} / Total ${res.total}`
  $('#statusMessage').textContent = `${res.total} key(s) loaded.` 
}

document.addEventListener('click', async (e) => {
  if (e.target.matches('#login')) {
    const username = $('#username').value.trim()
    const password = $('#password').value.trim()
    if (!username || !password) {
      showLogin('Username and password required.')
      return
    }
    const res = await adminFetch(`${API_BASE}/login`, { method: 'POST', body: { username, password } })
    if (!res.ok) {
      showLogin(res.error || 'Login failed.')
      return
    }
    if (res.nonce) sessionNonce = res.nonce
    await initSession(res.token, res.user)
    return
  }

  if (e.target.matches('#logout')) {
    clearSession()
    return
  }

  if (e.target.matches('#manageAdmins')) {
    const panel = document.getElementById('adminsPanel')
    const keysControls = document.getElementById('keysControls')
    const detectionPanel = document.getElementById('detectionPanel')
    const keysPanel = document.getElementById('keysPanel')
    const isHidden = panel.classList.contains('hidden')
    if (isHidden) {
      panel.classList.remove('hidden')
      keysControls.classList.add('hidden')
      detectionPanel.classList.add('hidden')
      keysPanel.classList.add('hidden')
      loadAdmins()
      e.target.textContent = 'Manage Keys'
    } else {
      panel.classList.add('hidden')
      keysControls.classList.remove('hidden')
      detectionPanel.classList.remove('hidden')
      keysPanel.classList.remove('hidden')
      e.target.textContent = 'Manage Users'
    }
    return
  }

  if (e.target.matches('#generate')) {
    const count = parseInt($('#genCount').value) || 1
    const prefix = $('#genPrefix').value || 'OMNIPOTENCE'
    const res = await adminFetch(`${API_BASE}/generate`, { method: 'POST', body: { count, prefix } })
    if (!res.ok) {
      $('#statusMessage').textContent = res.error || 'Failed to generate keys.'
      return
    }
    $('#statusMessage').textContent = `Created ${res.created} key(s).`
    loadKeys()
    return
  }

  if (e.target.matches('#searchBtn')) { page = 1; loadKeys(); return }
  if (e.target.matches('#prev')) { if (page > 1) { page--; loadKeys() } return }
  if (e.target.matches('#next')) { page++; loadKeys(); return }

  if (e.target.matches('button.ban')) {
    const key = e.target.dataset.key
    if (e.target.textContent === 'Unban') {
      const res = await adminFetch(`${API_BASE}/unban`, { method: 'POST', body: { key } })
      if (!res.ok) { $('#statusMessage').textContent = res.error || 'Failed to unban.'; return }
    } else {
      const result = await showInputModal('Ban key', [
        { name: 'reason', label: 'Ban Reason', type: 'text', placeholder: 'Optional reason' }
      ])
      if (!result) return
      const res = await adminFetch(`${API_BASE}/ban`, { method: 'POST', body: { key, reason: result.reason || '' } })
      if (!res.ok) { $('#statusMessage').textContent = res.error || 'Failed to ban.'; return }
    }
    loadKeys()
    return
  }

  if (e.target.matches('button.reset')) {
    const key = e.target.dataset.key
    showConfirm(`Reset HWID/IP for key ${key}? This will allow a new device to activate it.`)
      .then(async confirmed => {
        if (!confirmed) return
        const res = await adminFetch(`${API_BASE}/key/reset`, { method: 'POST', body: { key } })
        if (!res.ok) {
          $('#statusMessage').textContent = res.error || 'Failed to reset key.'
          return
        }
        $('#statusMessage').textContent = 'Key HWID/IP reset.'
        loadKeys()
      })
    return
  }

  if (e.target.matches('button.del')) {
    const key = e.target.dataset.key
    showConfirm(`Delete key ${key}? This action cannot be undone.`)
      .then(async confirmed => {
        if (!confirmed) return
        const res = await adminFetch(`${API_BASE}/key/${encodeURIComponent(key)}`, { method: 'DELETE' })
        if (!res.ok) {
          $('#statusMessage').textContent = res.error || 'Failed to delete key.'
          return
        }
        loadKeys()
      })
    return
  }

  if (e.target.matches('#confirmAccept')) {
    document.dispatchEvent(new CustomEvent('confirm-accept'))
    return
  }

  if (e.target.matches('#confirmDeny')) {
    document.dispatchEvent(new CustomEvent('confirm-deny'))
    return
  }

  if (e.target.matches('#createAdmin')) {
    const result = await showInputModal('Create admin', [
      { name: 'username', label: 'Username', type: 'text' },
      { name: 'displayName', label: 'Display Name', type: 'text' },
      { name: 'password', label: 'Password', type: 'password' }
    ])
    if (!result) return
    const username = (result.username || '').trim()
    const password = result.password || ''
    const displayName = (result.displayName || '').trim()
    if (!username || !password) { $('#statusMessage').textContent = 'Username and password required.'; return }
    const res = await adminFetch(`${API_BASE}/admins`, { method: 'POST', body: { username, password, displayName } })
    if (!res.ok) { $('#statusMessage').textContent = res.error || 'Failed to create admin.'; return }
    loadAdmins()
    return
  }

  if (e.target.matches('button.delete-admin')) {
    if (adminCount <= 1) { $('#statusMessage').textContent = 'Cannot delete the last admin.'; return }
    const username = e.target.dataset.username
    const confirmed = await showConfirm(`Delete admin ${username}? This cannot be undone.`)
    if (!confirmed) return
    const res = await adminFetch(`${API_BASE}/admins/${encodeURIComponent(username)}`, { method: 'DELETE' })
    if (!res.ok) { $('#statusMessage').textContent = res.error || 'Failed to delete admin.'; return }
    loadAdmins()
    return
  }

  if (e.target.matches('#saveDetection')) {
    const btn = e.target
    const status = $('#detectionStatus').value
    const version = $('#detectionVersion').value.trim() || '1.0'
    const res = await adminFetch(`${API_BASE}/detection`, { method: 'PUT', body: { status, version } })
    if (!res.ok) { $('#statusMessage').textContent = res.error || 'Failed to save detection config.'; return }
    const origText = btn.textContent
    btn.textContent = 'Saved!'
    btn.style.background = 'rgba(74,222,128,0.25)'
    setTimeout(() => {
      btn.textContent = origText
      btn.style.background = ''
    }, 1000)
    return
  }

  if (e.target.matches('button.edit-admin')) {
    const username = e.target.dataset.username
    const row = e.target.closest('tr')
    const currentDisplay = row ? row.children[1].textContent : ''
    const result = await showInputModal('Edit admin', [
      { name: 'username', label: 'Username', type: 'text', value: username },
      { name: 'displayName', label: 'Display Name', type: 'text', value: currentDisplay },
      { name: 'password', label: 'New Password (leave blank to keep)', type: 'password', value: '' }
    ])
    if (!result) return
    const body = {}
    const newUsername = (result.username || '').trim()
    if (newUsername && newUsername !== username) body.username = newUsername
    if (result.displayName !== undefined && result.displayName !== '') body.displayName = result.displayName
    if (result.password) body.password = result.password
    if (Object.keys(body).length === 0) return
    const res = await adminFetch(`${API_BASE}/admins/${encodeURIComponent(username)}`, { method: 'PUT', body })
    if (!res.ok) { $('#statusMessage').textContent = res.error || 'Failed to update admin.'; return }
    loadAdmins()
    return
  }
})

function showConfirm(message) {
  return new Promise(resolve => {
    const modal = $('#confirmModal')
    $('#confirmText').textContent = message
    modal.classList.remove('hidden')

    const handleAccept = () => {
      cleanup()
      resolve(true)
    }
    const handleDeny = () => {
      cleanup()
      resolve(false)
    }
    const cleanup = () => {
      modal.classList.add('hidden')
      document.removeEventListener('confirm-accept', handleAccept)
      document.removeEventListener('confirm-deny', handleDeny)
    }

    document.addEventListener('confirm-accept', handleAccept)
    document.addEventListener('confirm-deny', handleDeny)
  })
}

function showInputModal(title, fields) {
  return new Promise(resolve => {
    const modal = $('#inputModal')
    $('#inputTitle').textContent = title
    const container = $('#inputFields')
    container.innerHTML = ''
    const inputs = {}
    fields.forEach(f => {
      const wrap = document.createElement('div')
      wrap.className = 'field'
      const label = document.createElement('span')
      label.textContent = f.label || f.name
      const input = document.createElement('input')
      input.type = f.type || 'text'
      input.id = `modal_${f.name}`
      if (f.placeholder) input.placeholder = f.placeholder
      if (f.value) input.value = f.value
      wrap.appendChild(label)
      wrap.appendChild(input)
      container.appendChild(wrap)
      inputs[f.name] = input
    })

    modal.classList.remove('hidden')

    const accept = () => {
      const result = {}
      Object.keys(inputs).forEach(k => result[k] = inputs[k].value)
      cleanup()
      resolve(result)
    }
    const cancel = () => { cleanup(); resolve(null) }
    const cleanup = () => {
      modal.classList.add('hidden')
      document.removeEventListener('confirm-accept', accept)
      document.removeEventListener('confirm-deny', cancel)
      document.getElementById('inputAccept').removeEventListener('click', accept)
      document.getElementById('inputCancel').removeEventListener('click', cancel)
    }

    document.getElementById('inputAccept').addEventListener('click', accept)
    document.getElementById('inputCancel').addEventListener('click', cancel)
    document.addEventListener('confirm-accept', accept)
    document.addEventListener('confirm-deny', cancel)
    const first = fields[0]
    setTimeout(() => { const el = document.getElementById(`modal_${first.name}`); if (el) el.focus() }, 50)
  })
}

async function loadDetectionStatus() {
  const res = await adminFetch(`${API_BASE}/detection`)
  if (!res.ok) { $('#statusMessage').textContent = res.error || 'Failed to load detection config.'; return }
  $('#detectionStatus').value = res.status || 'undetected'
  $('#detectionVersion').value = res.version || '1.0'
}

async function loadAdmins() {
  const res = await adminFetch(`${API_BASE}/admins`)
  if (!res.ok) { $('#statusMessage').textContent = res.error || 'Failed to load admins.'; return }
  adminCount = res.admins.length
  const tbody = $('#adminsTable tbody')
  tbody.innerHTML = ''
  res.admins.forEach(a => {
    const tr = document.createElement('tr')
    tr.innerHTML = `<td>${a.username}</td><td>${a.displayName || ''}</td><td>
      <button data-username="${a.username}" class="edit-admin">Edit</button>
      <button data-username="${a.username}" class="delete-admin">${adminCount <= 1 ? 'Delete (disabled)' : 'Delete'}</button>
    </td>`
    tbody.appendChild(tr)
  })
}

document.addEventListener('DOMContentLoaded', async () => {
  loadBranding()
  const token = localStorage.getItem('admin_session_token')
  if (!token) {
    showLogin()
    await fetchChallenge()
    return
  }
  let user = null
  try {
    const raw = localStorage.getItem('admin_user')
    if (raw) user = JSON.parse(raw)
  } catch (e) {}
  const ok = await initSession(token, user)
  if (!ok) {
    showLogin('Session expired. Please login again.')
  }
})

document.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    const active = document.activeElement
    if (active && (active.id === 'username' || active.id === 'password')) {
      e.preventDefault()
      document.querySelector('#login').click()
    }
  }
})
