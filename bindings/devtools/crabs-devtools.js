//
// crabs-devtools.js — <crabs-devtools> web component and attach() helper.
//
// Zero dependencies. Light theme only ("soft & friendly": rounded corners,
// pill badges, subtle shadows, pastel status colors). Works in any framework
// or plain HTML.
//
// Usage (browser):
//   <script src="bindings/devtools/devtools-api.js"></script>
//   <script src="bindings/devtools/crabs-devtools.js"></script>
//   const { panel } = CRABSDevtools.attach(node, { nodeId: 'admin' });
//

'use strict';

(function registerCrabsDevtools() {
  if (typeof window === 'undefined' || !window.customElements) return;

  // Diff badge highlighting for the State tab tree.
  const BADGE_COLORS = { added: '#d1fae5', changed: '#fef3c7', removed: '#fee2e2' };
  const BADGE_TEXT = { added: '#065f46', changed: '#92400e', removed: '#991b1b' };

  const STYLES = `
    :host { all: initial; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    .panel {
      font: 12px/1.5 -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      color: #111827; background: #ffffff;
      border: 1px solid #e5e7eb; border-radius: 14px;
      box-shadow: 0 2px 10px rgba(0,0,0,.06);
      display: flex; flex-direction: column; height: 380px; overflow: hidden;
    }
    .tabbar { display: flex; gap: 8px; padding: 8px 12px; align-items: center; }
    .tab {
      padding: 3px 12px; border-radius: 999px; cursor: pointer; user-select: none;
      color: #9ca3af; font-weight: 500; border: none; background: transparent;
      font-size: 11px; font-family: inherit;
    }
    .tab:focus-visible { outline: 2px solid #1a56db; }
    .tab.active { background: #e8f0fe; color: #1a56db; font-weight: 600; }
    .body { flex: 1; overflow: auto; padding: 8px 12px; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11px; }
    .row { display: flex; justify-content: space-between; gap: 8px; padding: 4px 8px;
           border-radius: 8px; margin-bottom: 3px; }
    .row.accept { background: #f0fdf4; }
    .row.reject { background: #fef2f2; }
    .ok { color: #059669; font-weight: 600; }
    .bad { color: #dc2626; font-weight: 600; }
    .muted { color: #9ca3af; }
    .error-banner { background: #fef2f2; color: #991b1b; border-radius: 8px;
                    padding: 6px 10px; margin-bottom: 6px; }
    input.filter {
      flex: 1; border: 1px solid #e5e7eb; border-radius: 8px; padding: 3px 8px;
      font-size: 11px; font-family: inherit;
    }
    .toolbar { display: flex; gap: 6px; margin-bottom: 6px; }
    .detail { background: #f3f4f6; border-radius: 8px; padding: 6px 8px; margin: 3px 0;
              font-family: ui-monospace, monospace; font-size: 11px; white-space: pre-wrap; }
    .toggle {
      position: fixed; bottom: 16px; right: 16px; z-index: 2147483647;
      width: 36px; height: 36px; border-radius: 999px;
      font: 700 9px/1 -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      letter-spacing: .04em; cursor: pointer; user-select: none;
      box-shadow: 0 2px 8px rgba(0,0,0,.12);
    }
    .toggle.open { background: #1a56db; color: #ffffff; border: 1px solid #1a56db; }
    .toggle.collapsed { background: #ffffff; color: #1a56db; border: 1px solid #e5e7eb; }
    /* Overlay styling must live on the HOST: attach() adds the overlay
       class to the <crabs-devtools> element itself, so :host(.overlay) is
       what applies it. The inner .panel then fills the fixed-size host. */
    :host(.overlay) {
      position: fixed;
      top: 0; right: 0; bottom: 0;
      width: 380px;
      max-width: 100vw;
      z-index: 10000;
      border-radius: 14px 0 0 14px;
      height: 100vh;
      box-shadow: -2px 0 14px rgba(0,0,0,.12);
      display: block;
    }
    :host(.overlay) .panel { height: 100%; }
    :host(.overlay.collapsed) .panel { display: none; }
    .pause, .export {
      padding: 3px 10px; border-radius: 999px; cursor: pointer; user-select: none;
      border: 1px solid #e5e7eb; background: #ffffff; color: #1a56db;
      font-size: 11px; font-weight: 600; font-family: inherit;
    }
    .pause:hover, .export:hover { background: #e8f0fe; }
    .export { margin-left: auto; }
    .paused-banner { color: #9ca3af; font-size: 11px; margin-bottom: 6px; }
    .overview { color: #6b7280; padding: 8px 12px 0; font-size: 11px; }
    .tree-row {
      line-height: 20px; padding-right: 8px; border-radius: 6px;
    }
    .tree-row:hover { background: #f3f4f6; }
    .tree-toggle { user-select: none; }
  `;

  // Leaf formatting: strings verbatim (opaque payloads already arrive as
  // "[encrypted: N bytes]"), everything else JSON.
  function formatLeaf(value) {
    if (value === null) return 'null';
    if (typeof value === 'string') return value;
    return JSON.stringify(value);
  }

  // Render a snapshot subtree as an expandable tree. `diffs` maps dot-paths
  // to 'added' | 'changed' | 'removed' for badge highlighting; `expandedPaths`
  // is a per-panel Set of dot-paths that persists across re-renders.
  function renderStateTree(container, snapshot, diffs, expandedPaths) {
    container.innerHTML = '';
    const lastKey = (path) => path.split('.').pop();
    const appendBadge = (row, diff) => {
      const badge = document.createElement('span');
      badge.className = 'diff-badge';
      badge.textContent = diff;
      badge.style.background = BADGE_COLORS[diff] || '#f3f4f6';
      badge.style.color = BADGE_TEXT[diff] || '#374151';
      badge.style.borderRadius = '8px';
      badge.style.padding = '0 6px';
      badge.style.fontSize = '10px';
      badge.style.marginLeft = '6px';
      row.appendChild(badge);
    };
    const renderValue = (value, path, depth) => {
      const row = document.createElement('div');
      row.className = 'tree-row';
      row.style.paddingLeft = (depth * 14) + 'px';
      const isObject = value !== null && typeof value === 'object';
      if (isObject && Object.keys(value).length > 0) {
        const keys = Object.keys(value);
        const toggle = document.createElement('span');
        toggle.className = 'tree-toggle mono';
        const expanded = expandedPaths.has(path);
        toggle.textContent = (expanded ? '▾ ' : '▸ ') +
          (path ? lastKey(path) : 'state') + ' (' + keys.length + ')';
        toggle.style.cursor = 'pointer';
        toggle.addEventListener('click', () => {
          if (expandedPaths.has(path)) expandedPaths.delete(path);
          else expandedPaths.add(path);
          renderStateTree(container, snapshot, diffs, expandedPaths);
        });
        row.appendChild(toggle);
        if (diffs[path]) appendBadge(row, diffs[path]);
        // Timeline rows jump here by item name (Step 5): tag each item's
        // row so focusItem can find and flash it.
        if (/^items\.\d+$/.test(path) && value.name) {
          row.setAttribute('data-item-name', value.name);
        }
        container.appendChild(row);
        if (expanded) {
          for (const key of keys) {
            renderValue(value[key], path ? path + '.' + key : key, depth + 1);
          }
        }
      } else {
        const label = document.createElement('span');
        label.className = 'mono';
        label.textContent = (path ? lastKey(path) : 'state') + ': ' +
          formatLeaf(value);
        row.appendChild(label);
        if (diffs[path]) appendBadge(row, diffs[path]);
        container.appendChild(row);
      }
    };
    renderValue(snapshot, '', 0);
  }

  // Compact one-line summary from the C snapshot writer's fields
  // (src/Devtools/devtools.c _write_snapshot_json): node_id, version, hlc
  // {physical, nanos, logical, node}, log_head {entries, state_hash},
  // schedules[].
  function overviewLine(snapshot) {
    if (!snapshot || snapshot.error) return 'no snapshot yet';
    const pending = (snapshot.schedules || []).length;
    const head = (snapshot.log_head && snapshot.log_head.state_hash) || '';
    const hlc = snapshot.hlc;
    const hlcLabel = hlc ? hlc.physical + '·' + hlc.logical : '—';
    return '#' + snapshot.node_id + ' · v' + snapshot.version +
      ' · hlc ' + hlcLabel + ' · log ' + head.slice(0, 8) +
      ' · ' + pending + ' pending';
  }

  // The controller diffs and this panel's tree must flatten the same shape,
  // so deriveView is shared from devtools-api.js. Scripts load in order at
  // attach() time, but resolve lazily here for safety.
  function deriveView(snapshot) {
    if (window.CRABSDevtoolsApi && window.CRABSDevtoolsApi.deriveView) {
      return window.CRABSDevtoolsApi.deriveView(snapshot);
    }
    if (typeof require === 'function') {
      return require('./devtools-api.js').deriveView(snapshot);
    }
    return snapshot;
  }

  class CrabsDevtools extends HTMLElement {
    constructor() {
      super();
      this.attachShadow({ mode: 'open' });
      this.activeTab = 'state';
      this.data = { snapshot: null, allEvents: [], diffs: {} };
      // Expand/collapse state persists across refreshes so the tree does not
      // snap shut on every snapshot pull.
      this.expandedPaths = new Set(['', 'items']);
      this.filterText = '';
      this.paused = false;
      this.collapsedState = false;
    }

    get collapsed() { return this.collapsedState; }
    set collapsed(value) {
      this.collapsedState = Boolean(value);
      this.applyCollapsed();
    }

    connectedCallback() {
      // Re-connecting an already-initialized element (e.g. a DOM move) must
      // not append a second panel/toggle.
      if (this.root) return;
      const style = document.createElement('style');
      style.textContent = STYLES;
      const root = document.createElement('div');
      root.className = 'panel';
      const toggle = document.createElement('button');
      toggle.className = 'toggle';
      toggle.textContent = 'CRABS';
      toggle.addEventListener('click', () => {
        this.collapsed = !this.collapsed;
      });
      this.shadowRoot.append(style, root, toggle);
      this.root = root;
      this.toggleButton = toggle;
      this.applyCollapsed();
      this.render();
    }

    applyCollapsed() {
      if (!this.root || !this.toggleButton) return;
      this.root.style.display = this.collapsedState ? 'none' : '';
      // Mirror the state on the host so :host(.overlay.collapsed) applies
      // (and authors get a styling hook); in overlay mode the launcher
      // button stays visible because only the inner .panel is hidden.
      this.classList.toggle('collapsed', this.collapsedState);
      this.toggleButton.className =
        'toggle ' + (this.collapsedState ? 'collapsed' : 'open');
      this.toggleButton.setAttribute('aria-expanded', String(!this.collapsedState));
    }

    update(data) {
      const wasConnected = this.isConnected;
      this.data = {
        snapshot: data.snapshot || this.data.snapshot,
        allEvents: data.allEvents || this.data.allEvents,
        diffs: data.diffs || this.data.diffs,
      };
      // While paused the panel stays frozen on the pause-moment view; the
      // merged data is picked up by the next render (e.g. on resume).
      if (wasConnected && !this.paused) this.render();
    }

    render() {
      if (!this.root) return;
      const snapshot = this.data.snapshot;
      // Overview header: node id, version, hlc, log head, pending schedules.
      const overview = document.createElement('div');
      overview.className = 'overview mono';
      overview.textContent = overviewLine(snapshot);
      this.root.replaceChildren(overview);
      const tabbar = document.createElement('div');
      tabbar.className = 'tabbar';
      for (const tab of ['state', 'timeline']) {
        const button = document.createElement('button');
        button.className = 'tab' + (tab === this.activeTab ? ' active' : '');
        button.textContent = tab[0].toUpperCase() + tab.slice(1);
        button.setAttribute('aria-selected', String(tab === this.activeTab));
        button.addEventListener('click', () => {
          this.activeTab = tab;
          this.render();
        });
        tabbar.appendChild(button);
      }
      const exportButton = document.createElement('button');
      exportButton.className = 'export';
      exportButton.textContent = 'Export';
      exportButton.addEventListener('click', () => {
        const blob = new Blob([JSON.stringify(this.data.snapshot, null, 2)],
                              { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = 'crabs-snapshot-' +
          ((this.data.snapshot && this.data.snapshot.node_id) || 'node') +
          '.json';
        link.click();
        URL.revokeObjectURL(url);
      });
      tabbar.appendChild(exportButton);
      this.root.appendChild(tabbar);
      const body = document.createElement('div');
      body.className = 'body';
      if (snapshot && snapshot.error) {
        const banner = document.createElement('div');
        banner.className = 'error-banner';
        banner.textContent = snapshot.error;
        body.appendChild(banner);
      }
      const renderer = {
        state: () => this.renderState(body),
        timeline: () => this.renderTimeline(body),
      }[this.activeTab];
      renderer();
      this.root.appendChild(body);
    }

    // Jump from a timeline row to the State tab and flash the item's row so
    // the eye lands on it (expand state is only widened, never collapsed).
    focusItem(itemName) {
      this.activeTab = 'state';
      this.expandedPaths.add('items');
      this.expandedPaths.add('');
      this.render();
      const row = this.root.querySelector(
        '[data-item-name="' + CSS.escape(itemName) + '"]');
      if (!row) return;
      row.style.transition = 'background-color 800ms ease-out';
      row.style.backgroundColor = '#fef3c7';
      setTimeout(() => { row.style.backgroundColor = 'transparent'; }, 60);
      setTimeout(() => {
        row.style.transition = '';
        row.style.backgroundColor = '';
      }, 900);
    }

    renderState(body) {
      const snapshot = this.data.snapshot;
      if (!snapshot) {
        body.innerHTML = '<span class="muted">No snapshot yet.</span>';
        return;
      }
      renderStateTree(body, deriveView(snapshot), this.data.diffs || {},
                      this.expandedPaths);
    }

    renderTimeline(body) {
      const toolbar = document.createElement('div');
      toolbar.className = 'toolbar';
      const filter = document.createElement('input');
      filter.className = 'filter';
      filter.placeholder = 'filter: type, signer, item…';
      filter.value = this.filterText;
      filter.addEventListener('input', () => {
        // Filter the existing rows in place: a full re-render would rebuild
        // the body and destroy the input (losing focus and open details).
        this.filterText = filter.value;
        const needle = this.filterText.toLowerCase();
        for (const row of timelineRows) {
          const event = row._event;
          const haystack = (event.op_type + ' ' + event.signer + ' ' +
            event.target + ' ' + event.node).toLowerCase();
          row.style.display = haystack.includes(needle) ? '' : 'none';
        }
      });
      toolbar.appendChild(filter);
      const pauseButton = document.createElement('button');
      pauseButton.className = 'pause';
      pauseButton.textContent = this.paused ? '▶ Resume' : '⏸ Pause';
      pauseButton.addEventListener('click', () => {
        this.paused = !this.paused;
        this.render();
      });
      toolbar.appendChild(pauseButton);
      body.appendChild(toolbar);

      if (this.paused) {
        const banner = document.createElement('div');
        banner.className = 'paused-banner';
        banner.textContent = 'Paused — ' + this.data.allEvents.length +
          ' events buffered';
        body.appendChild(banner);
      }

      const needle = this.filterText.toLowerCase();
      const events = this.data.allEvents.filter((event) => {
        if (!needle) return true;
        return (event.op_type + ' ' + event.signer + ' ' + event.target + ' ' + event.node)
          .toLowerCase().includes(needle);
      });
      const timelineRows = [];
      for (const event of events.slice().reverse().slice(0, 200)) {
        const row = document.createElement('div');
        row._event = event;
        row.className = 'row ' + (event.result === 'accepted' ? 'accept' : 'reject');
        const left = document.createElement('span');
        left.textContent = event.signer + ' · ' + event.op_type +
          (event.target ? ' ' + event.target : '');
        const right = document.createElement('span');
        right.className = event.result === 'accepted' ? 'ok' : 'bad';
        right.textContent = event.result === 'accepted'
          ? '✓' + (event.transition ? ' ' + event.transition : '')
          : '✗ ' + (event.error || '');
        row.appendChild(left);
        row.appendChild(right);
        timelineRows.push(row);
        row.addEventListener('click', () => {
          // A row with a target jumps to that item in the State tree and
          // flashes it; rows without a target keep the JSON detail toggle.
          if (event.target) { this.focusItem(event.target); return; }
          const existing = row.nextSibling;
          if (existing && existing.className === 'detail') { existing.remove(); return; }
          const detail = document.createElement('div');
          detail.className = 'detail';
          detail.textContent = JSON.stringify(event, null, 1);
          row.after(detail);
        });
        body.appendChild(row);
      }
    }

  }

  if (!window.customElements.get('crabs-devtools')) {
    window.customElements.define('crabs-devtools', CrabsDevtools);
  }

  function attach(node, options = {}) {
    let createDevtoolsController;
    if (window.CRABSDevtoolsApi) {
      createDevtoolsController = window.CRABSDevtoolsApi.createDevtoolsController;
    } else if (typeof require === 'function') {
      createDevtoolsController =
        require('./devtools-api.js').createDevtoolsController;
    }
    if (!createDevtoolsController) {
      throw new Error(
        'crabs-devtools: load devtools-api.js before crabs-devtools.js ' +
        '(window.CRABSDevtoolsApi missing)');
    }
    const controller = createDevtoolsController(node, options);
    const panel = document.createElement('crabs-devtools');
    controller.onUpdate((data) => panel.update({
      snapshot: data.snapshot,
      allEvents: data.allEvents,
      diffs: data.diffs,
    }));
    // mount === null → overlay mode: the panel becomes a fixed-position
    // overlay appended to document.body. A provided mount keeps the panel
    // in the normal document flow inside that container.
    const mount = options.mount || null;
    const overlayMode = mount === null;
    const host = mount || document.body;
    host.appendChild(panel);
    if (overlayMode) panel.classList.add('overlay');
    controller.refresh();
    return { panel, controller };
  }

  window.CRABSDevtools = { attach };
})();
