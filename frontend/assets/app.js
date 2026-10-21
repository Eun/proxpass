// ProxPass admin SPA — Alpine application.
//
// `app()` is the single Alpine component for the whole UI. It composes the
// bare api() client (defined inline in index.html) and adds navigation, a
// declarative table of /v1 resources, and generic list/create/edit/delete
// handlers driven by that table. Adding a resource is data, not code: give it
// columns, form fields, and which verbs it supports.
//
// Field names below are snake_case on purpose: every /v1 admin schema uses the
// Go model's json tags verbatim (api_url, public_keys, group_ids, …), so the
// request/response bodies map 1:1 to what the form collects.

function app() {
    return {
        ...api(),

        // ---- shell state ----
        view: 'dashboard',
        tokenInput: '',
        authError: '',
        error: '',
        notice: '',
        loading: false,
        busy: false,
        search: '',

        // rows for the current resource view; cache keeps the last-loaded list
        // for each resource so cross-resource lookups (e.g. instance names on
        // the guests table) and the dashboard counts work without refetching.
        rows: [],
        cache: {},

        modal: { open: false, mode: 'create', data: {} },

        // policy + discovery view state
        policyForm: { clients: '', groups: '' },
        discoverInstance: '',
        discoverResult: null,

        chart: null,

        // ---- navigation definition ----
        get nav() {
            return [
                { id: 'dashboard', label: 'Dashboard', icon: icon.home },
                { id: 'instances', label: 'Instances', icon: icon.server },
                { id: 'guests', label: 'Guests', icon: icon.desktop },
                { id: 'clients', label: 'Clients', icon: icon.users },
                { id: 'groups', label: 'Groups', icon: icon.collection },
                { id: 'access', label: 'Guest Access', icon: icon.key },
                { id: 'instanceAccess', label: 'Node Access', icon: icon.key },
                { id: 'policy', label: 'Default Policy', icon: icon.shield },
                { id: 'adminKeys', label: 'Admin Keys', icon: icon.key },
                { id: 'settings', label: 'Settings', icon: icon.cog },
                { id: 'discover', label: 'Discovery', icon: icon.refresh },
            ];
        },

        // ---- resource table: the heart of the generic UI ----
        get resources() {
            const self = this;
            return {
                instances: {
                    singular: 'instance', path: '/instances',
                    create: true, edit: true, remove: true,
                    columns: [
                        { key: 'id', label: 'ID' },
                        { key: 'name', label: 'Name' },
                        { key: 'api_url', label: 'API URL' },
                        { key: 'node', label: 'Node' },
                        { key: 'console_transport', label: 'Console' },
                        { key: 'ssh_host', label: 'SSH host' },
                    ],
                    fields: [
                        { key: 'name', label: 'Name', required: true },
                        { key: 'api_url', label: 'API URL', required: true, placeholder: 'https://pve:8006' },
                        { key: 'api_token_id', label: 'API token ID', required: true, placeholder: 'user@pam!token' },
                        { key: 'api_token_secret', label: 'API token secret', type: 'password', required: true },
                        { key: 'node', label: 'Node', help: 'Learned from the API if left blank on add.' },
                        { key: 'console_transport', label: 'Console transport', type: 'select', options: ['termproxy', 'ssh'] },
                        { key: 'ssh_host', label: 'SSH host', placeholder: 'optional; enables node shell / SFTP' },
                        { key: 'ssh_port', label: 'SSH port', type: 'number' },
                        { key: 'ssh_user', label: 'SSH user', placeholder: 'root' },
                        { key: 'ssh_fingerprint', label: 'SSH fingerprint', help: 'Pin a host key that has no DNSSEC SSHFP.' },
                        { key: 'insecure_tls', label: 'Skip TLS verification', type: 'checkbox' },
                        { key: 'insecure_ssh', label: 'Skip SSH host-key verification', type: 'checkbox' },
                    ],
                    defaults: { console_transport: 'termproxy', ssh_port: 22, insecure_tls: false, insecure_ssh: false },
                    numeric: ['ssh_port'],
                },
                guests: {
                    singular: 'guest', path: '/guests',
                    columns: [
                        { key: 'id', label: 'ID' },
                        { key: 'type', label: 'Type' },
                        { key: 'name', label: 'Name' },
                        { key: 'proxmox_id', label: 'VMID' },
                        { key: 'status', label: 'Status', render: (v) => badge(v, v === 'running' ? 'green' : 'gray') },
                        { key: 'instance_id', label: 'Instance', render: (v) => self.instanceName(v) },
                    ],
                },
                clients: {
                    singular: 'client', path: '/clients',
                    create: true, edit: true, remove: true,
                    columns: [
                        { key: 'id', label: 'ID' },
                        { key: 'name', label: 'Name' },
                        { key: 'public_keys', label: 'Keys', render: (v) => (v || []).length + ' key(s)' },
                        { key: 'group_ids', label: 'Groups', render: (v) => (v || []).join(', ') || '—' },
                    ],
                    fields: [
                        { key: 'name', label: 'Name', required: true },
                        { key: 'public_keys', label: 'Public keys', type: 'textarea', required: true, help: 'One SSH public key per line.', placeholder: 'ssh-ed25519 AAAA… alice' },
                        { key: 'group_ids', label: 'Group IDs', help: 'Comma-separated group IDs.' },
                    ],
                    defaults: { public_keys: [], group_ids: [] },
                    lists: { public_keys: 'lines', group_ids: 'intCsv' },
                },
                groups: {
                    singular: 'group', path: '/groups',
                    create: true, edit: true, remove: true,
                    columns: [
                        { key: 'id', label: 'ID' },
                        { key: 'name', label: 'Name' },
                        { key: 'client_ids', label: 'Members', render: (v) => (v || []).join(', ') || '—' },
                    ],
                    fields: [
                        { key: 'name', label: 'Name', required: true },
                        { key: 'client_ids', label: 'Client IDs', help: 'Comma-separated client IDs.' },
                    ],
                    defaults: { client_ids: [] },
                    lists: { client_ids: 'intCsv' },
                },
                adminKeys: {
                    singular: 'admin key', path: '/admin-keys',
                    create: true, remove: true,
                    // admin-keys list returns {public_keys:[...]}; normalize to rows.
                    unwrap: (data) => (data.public_keys || []).map((k) => ({ id: k, public_key: k })),
                    columns: [
                        { key: 'public_key', label: 'Public key', render: (v) => '<code class="text-xs break-all">' + esc(v) + '</code>' },
                    ],
                    fields: [
                        { key: 'public_key', label: 'Public key', type: 'textarea', required: true, placeholder: 'ssh-ed25519 AAAA… admin' },
                    ],
                    // POST/DELETE use the AdminKey body {public_key}
                    createBody: (d) => ({ public_key: d.public_key }),
                    removeBody: (row) => ({ public_key: row.public_key }),
                },
                settings: {
                    singular: 'setting', path: '/settings',
                    // settings has no list endpoint; a fixed, known set is shown.
                    staticKeys: ['public_endpoint', 'default_ssh_user', 'ssh_key_algorithm'],
                    edit: true, editKey: true,
                    columns: [
                        { key: 'key', label: 'Key' },
                        { key: 'value', label: 'Value', render: (v) => v ? esc(v) : '<span class="text-gray-300">(unset)</span>' },
                    ],
                    fields: [
                        { key: 'value', label: 'Value', required: false, help: 'Leave blank to clear.' },
                    ],
                },
            };
        },

        currentResource() {
            return this.resources[this.view] || { columns: [] };
        },

        // ---- lifecycle ----
        init() {
            if (this.authed) this.go('dashboard');
        },

        async signIn() {
            const t = (this.tokenInput || '').trim();
            if (!t) { this.authError = 'Enter a token.'; return; }
            this.busy = true; this.authError = '';
            this.saveToken(t);
            try {
                // Validate by hitting a cheap admin endpoint.
                await this.request('GET', '/instances');
                this.tokenInput = '';
                this.go('dashboard');
            } catch (e) {
                this.clearToken();
                this.authError = e.isAuth ? 'Token rejected (not an admin credential).' : e.message;
            } finally {
                this.busy = false;
            }
        },

        signOut() {
            this.clearToken();
            this.view = 'dashboard';
            this.rows = []; this.cache = {};
        },

        navLabel() {
            const item = this.nav.find((n) => n.id === this.view);
            return item ? item.label : '';
        },

        async go(id) {
            this.view = id;
            this.search = '';
            this.error = '';
            this.modal.open = false;
            if (id === 'dashboard') return this.loadDashboard();
            if (id === 'access') return this.loadAccess('/access-rules', 'guest');
            if (id === 'instanceAccess') return this.loadAccess('/instance-access-rules', 'instance');
            if (id === 'policy') return this.loadPolicy();
            if (id === 'discover') return this.ensureInstances();
            if (this.resources[id]) return this.loadResource(id);
        },

        refresh() { this.go(this.view); },

        // ---- generic list loading ----
        async loadResource(id) {
            const r = this.resources[id];
            if (r.staticKeys) return this.loadSettings(r);
            this.loading = true; this.rows = [];
            try {
                let data = await this.request('GET', r.path);
                if (r.unwrap) data = r.unwrap(data);
                this.rows = Array.isArray(data) ? data : [];
                this.cache[id] = this.rows;
            } catch (e) { this.fail(e); }
            finally { this.loading = false; }
        },

        async loadSettings(r) {
            this.loading = true; this.rows = [];
            const out = [];
            for (const key of r.staticKeys) {
                try {
                    const s = await this.request('GET', r.path + '/' + encodeURIComponent(key));
                    out.push({ id: key, key: s.key, value: s.value });
                } catch (e) {
                    if (e.status === 404) out.push({ id: key, key, value: '' });
                    else if (e.isAuth) { this.fail(e); break; }
                }
            }
            this.rows = out;
            this.loading = false;
        },

        // ---- dashboard ----
        async loadDashboard() {
            this.loading = true;
            try {
                const [instances, guests, clients, groups] = await Promise.all([
                    this.request('GET', '/instances'),
                    this.request('GET', '/guests'),
                    this.request('GET', '/clients'),
                    this.request('GET', '/groups'),
                ]);
                this.cache.instances = instances || [];
                this.cache.guests = guests || [];
                this.cache.clients = clients || [];
                this.cache.groups = groups || [];
                this.$nextTick(() => this.drawChart());
            } catch (e) { this.fail(e); }
            finally { this.loading = false; }
        },

        get dashCards() {
            return [
                { id: 'instances', label: 'Instances', count: (this.cache.instances || []).length },
                { id: 'guests', label: 'Guests', count: (this.cache.guests || []).length },
                { id: 'clients', label: 'Clients', count: (this.cache.clients || []).length },
                { id: 'groups', label: 'Groups', count: (this.cache.groups || []).length },
            ];
        },

        drawChart() {
            const el = document.getElementById('guestChart');
            if (!el || typeof Chart === 'undefined') return;
            const guests = this.cache.guests || [];
            const running = guests.filter((g) => g.status === 'running').length;
            const stopped = guests.length - running;
            if (this.chart) this.chart.destroy();
            this.chart = new Chart(el, {
                type: 'bar',
                data: {
                    labels: ['Running', 'Stopped'],
                    datasets: [{ data: [running, stopped], backgroundColor: ['#1f4b8e', '#9ca3af'] }],
                },
                options: { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } },
            });
        },

        // ---- helpers for cross-resource display ----
        async ensureInstances() {
            if (!this.cache.instances) {
                try { this.cache.instances = await this.request('GET', '/instances') || []; }
                catch (e) { this.fail(e); }
            }
        },
        instanceName(id) {
            const inst = (this.cache.instances || []).find((i) => i.id === id);
            return inst ? esc(inst.name) : ('#' + id);
        },

        // ---- filtering / rendering ----
        filteredRows() {
            const q = this.search.trim().toLowerCase();
            if (!q) return this.rows;
            return this.rows.filter((row) => JSON.stringify(row).toLowerCase().includes(q));
        },
        renderCell(col, row) {
            const v = row[col.key];
            if (col.render) return col.render(v, row);
            if (v === null || v === undefined || v === '') return '<span class="text-gray-300">—</span>';
            if (typeof v === 'boolean') return v ? '✓' : '✗';
            if (Array.isArray(v)) return esc(v.join(', '));
            return esc(String(v));
        },

        // ---- create / edit modal ----
        openCreate() {
            const r = this.currentResource();
            this.modal = { open: true, mode: 'create', data: { ...(r.defaults || {}) } };
        },
        openEdit(row) {
            const r = this.currentResource();
            const data = { ...row };
            // Convert list fields back to their editable string form.
            if (r.lists) {
                for (const [k, kind] of Object.entries(r.lists)) {
                    data[k] = (row[k] || []).join(kind === 'lines' ? '\n' : ', ');
                }
            }
            this.modal = { open: true, mode: 'edit', data };
        },
        closeModal() { this.modal.open = false; },

        async submitModal() {
            const r = this.currentResource();
            const d = { ...this.modal.data };

            // Access rules: POST grant with {subject, *_ids}
            if (r.access) {
                const targetIds = this.accessKind === 'guest'
                    ? { guest_ids: [Number(d.target_id)] }
                    : { instance_ids: [Number(d.target_id)] };
                this.busy = true;
                try {
                    await this.request('POST', this.accessPath + '/grant', {
                        subject: { kind: d.subject_type, id: Number(d.subject_id) },
                        ...targetIds,
                    });
                    this.ok('Access granted.'); this.closeModal();
                    this.loadAccess(this.accessPath, this.accessKind);
                } catch (e) { this.fail(e); } finally { this.busy = false; }
                return;
            }

            // Settings: PUT /settings/{key} with {value}
            if (r.editKey) {
                this.busy = true;
                try {
                    await this.request('PUT', r.path + '/' + encodeURIComponent(this.modal.data.key), { value: d.value || '' });
                    this.ok('Setting saved.'); this.closeModal(); this.loadResource(this.view);
                } catch (e) { this.fail(e); } finally { this.busy = false; }
                return;
            }

            // Coerce numeric + list fields to the shapes the API expects.
            (r.numeric || []).forEach((k) => { if (d[k] !== undefined && d[k] !== '') d[k] = Number(d[k]); });
            if (r.lists) {
                for (const [k, kind] of Object.entries(r.lists)) {
                    d[k] = parseList(d[k], kind);
                }
            }
            if (this.modal.mode === 'create') d.id = d.id || 0;

            const body = r.createBody && this.modal.mode === 'create' ? r.createBody(d) : d;
            this.busy = true;
            try {
                if (this.modal.mode === 'create') {
                    await this.request('POST', r.path, body);
                    this.ok(cap(r.singular) + ' created.');
                } else {
                    await this.request('PUT', r.path + '/' + d.id, d);
                    this.ok(cap(r.singular) + ' updated.');
                }
                this.closeModal();
                this.loadResource(this.view);
            } catch (e) { this.fail(e); }
            finally { this.busy = false; }
        },

        async removeRow(row) {
            const r = this.currentResource();
            if (!confirm('Delete this ' + r.singular + '?')) return;
            try {
                if (r.removeBody) {
                    await this.request('DELETE', r.path, r.removeBody(row));
                } else {
                    await this.request('DELETE', r.path + '/' + row.id);
                }
                this.ok(cap(r.singular) + ' deleted.');
                this.loadResource(this.view);
            } catch (e) { this.fail(e); }
        },

        // ---- access rules (guest + instance) ----
        accessKind: 'guest',
        accessPath: '/access-rules',
        async loadAccess(path, kind) {
            this.accessPath = path; this.accessKind = kind;
            this.loading = true; this.rows = [];
            await this.ensureInstances();
            try {
                const data = await this.request('GET', path);
                this.rows = (data || []).map((row) => ({ ...row, id: row.id }));
            } catch (e) { this.fail(e); }
            finally { this.loading = false; }
            // Inject a resource definition for the access view on the fly.
            this.resources[this.view] = this.accessResource();
        },
        accessResource() {
            const self = this;
            const targetKey = self.accessKind === 'guest' ? 'guest_id' : 'instance_id';
            const targetLabel = self.accessKind === 'guest' ? 'Guest' : 'Instance';
            return {
                singular: 'access rule',
                path: self.accessPath,
                columns: [
                    { key: 'id', label: 'ID' },
                    { key: 'type', label: 'Subject type', render: (v) => badge(v, 'gray') },
                    { key: 'subject_id', label: 'Subject ID' },
                    { key: targetKey, label: targetLabel, render: (v) => self.accessKind === 'instance' ? self.instanceName(v) : String(v) },
                ],
                create: true,
                // A rule is granted (create) or revoked (delete) via the
                // grant/revoke sub-paths with a {subject, *_ids} body, so these
                // flags route submit/remove through the access-specific code.
                access: true,
                // The grant form: who (client/group + id) gets access to which
                // target (guest/instance id).
                fields: [
                    { key: 'subject_type', label: 'Subject type', type: 'select', options: ['client', 'group'], required: true },
                    { key: 'subject_id', label: 'Subject ID', type: 'number', required: true, help: 'The client or group ID.' },
                    { key: 'target_id', label: targetLabel + ' ID', type: 'number', required: true },
                ],
                defaults: { subject_type: 'client' },
                rowActions: [
                    { label: 'Revoke', run: (row) => self.revokeAccess(row) },
                ],
            };
        },

        // revokeAccess removes one subject→target rule via the revoke sub-path.
        async revokeAccess(row) {
            if (!confirm('Revoke this access rule?')) return;
            const targetIds = this.accessKind === 'guest'
                ? { guest_ids: [row.guest_id] }
                : { instance_ids: [row.instance_id] };
            try {
                await this.request('POST', this.accessPath + '/revoke', {
                    subject: { kind: row.type, id: row.subject_id },
                    ...targetIds,
                });
                this.ok('Access revoked.');
                this.loadAccess(this.accessPath, this.accessKind);
            } catch (e) { this.fail(e); }
        },

        // ---- default policy ----
        async loadPolicy() {
            this.busy = true;
            try {
                const p = await this.request('GET', '/policy');
                this.policyForm.clients = (p.authorized_client_ids || []).join(', ');
                this.policyForm.groups = (p.authorized_group_ids || []).join(', ');
            } catch (e) { this.fail(e); }
            finally { this.busy = false; }
        },
        async savePolicy() {
            this.busy = true;
            try {
                await this.request('PUT', '/policy', {
                    authorized_client_ids: parseList(this.policyForm.clients, 'intCsv'),
                    authorized_group_ids: parseList(this.policyForm.groups, 'intCsv'),
                });
                this.ok('Default policy saved.');
            } catch (e) { this.fail(e); }
            finally { this.busy = false; }
        },

        // ---- discovery ----
        async runDiscover() {
            this.busy = true; this.discoverResult = null;
            try {
                const q = this.discoverInstance ? ('?instance=' + encodeURIComponent(this.discoverInstance)) : '';
                this.discoverResult = await this.request('POST', '/discover' + q);
                this.ok('Discovery complete.');
            } catch (e) { this.fail(e); }
            finally { this.busy = false; }
        },

        // ---- flash helpers ----
        ok(msg) { this.notice = msg; this.error = ''; setTimeout(() => { if (this.notice === msg) this.notice = ''; }, 4000); },
        fail(e) {
            if (e.isAuth) { this.error = 'Not authorized — check your token.'; this.signOut(); return; }
            this.error = e.message;
        },
    };
}

// ---- small utilities ----
function parseList(v, kind) {
    if (Array.isArray(v)) return v;
    const s = (v || '').trim();
    if (!s) return [];
    if (kind === 'lines') return s.split('\n').map((x) => x.trim()).filter(Boolean);
    // intCsv
    return s.split(',').map((x) => x.trim()).filter(Boolean).map(Number).filter((n) => !Number.isNaN(n));
}
function esc(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function cap(s) { return s.charAt(0).toUpperCase() + s.slice(1); }
function badge(text, color) {
    const colors = { green: 'bg-green-100 text-green-700', gray: 'bg-gray-100 text-gray-600', red: 'bg-red-100 text-red-700' };
    return '<span class="px-2 py-0.5 rounded text-xs font-medium ' + (colors[color] || colors.gray) + '">' + esc(text) + '</span>';
}

// Inline SVG icons (Heroicons outline), kept tiny and dependency-free.
const icon = {
    home: '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"/></svg>',
    server: '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"/></svg>',
    desktop: '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg>',
    users: '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a4 4 0 00-3-3.87M9 20H4v-2a4 4 0 013-3.87m6-1.13a4 4 0 10-4-4 4 4 0 004 4z"/></svg>',
    collection: '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/></svg>',
    key: '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/></svg>',
    shield: '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>',
    cog: '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>',
    refresh: '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>',
};
