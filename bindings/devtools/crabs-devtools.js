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

  // Timeline layer pill colors: [background, text]. Unknown or missing
  // layers fall back to gray with the 'op' label. 'spawn' (violet) marks
  // lineage spawn ops; 'lineage' (teal) marks attest/dissolve/withdraw
  // lineage lifecycle events.
  const LAYER_COLORS = {
    op: ['#dbeafe', '#1e40af'],
    schedule: ['#fef3c7', '#92400e'],
    trigger: ['#d1fae5', '#065f46'],
    attribute: ['#e5e7eb', '#374151'],
    spawn: ['#ede9fe', '#5b21b6'],
    lineage: ['#ccfbf1', '#0f766e'],
  };
  const LAYER_FALLBACK = { background: '#f3f4f6', color: '#374151', label: 'op' };

  // Lineage mode/status pill colors for the State tab's lineage section:
  // [background, text], same light-theme pastel family as the layer pills
  // above (Tailwind 100-level fills with 800/700-level text). Unknown values
  // fall back to the shared gray.
  const LINEAGE_MODE_COLORS = {
    shared_root: ['#e0e7ff', '#3730a3'],
    delegated_copy: ['#ede9fe', '#5b21b6'],
    sovereign: ['#ccfbf1', '#0f766e'],
  };
  const LINEAGE_STATUS_COLORS = {
    active: ['#d1fae5', '#065f46'],
    attestation_revoked: ['#fef3c7', '#92400e'],
    dissolved: ['#fee2e2', '#991b1b'],
    withdrawn: ['#e5e7eb', '#374151'],
  };
  const LINEAGE_PILL_FALLBACK = ['#f3f4f6', '#374151'];

  // Write-domain pill colors (write-domains v1) for the State tab's item
  // rows: [background, text], same light-theme pastel family. The C
  // snapshot emits domain as one of these three words (unknown/missing
  // falls back to the shared gray, same as the lineage pills).
  const DOMAIN_PILL_COLORS = {
    free: ['#e5e7eb', '#374151'],
    sovereign: ['#ccfbf1', '#0f766e'],
    group: ['#e0e7ff', '#3730a3'],
  };

  // Toggle icon: the Encryptstacean logo from the project README,
  // downscaled to 72px and inlined as a data URI so the devtools stay
  // zero-dependency and path-independent.
  const CRABS_ICON_DATA_URI =
    'data:image/png;base64,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';

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
      pointer-events: auto;
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
      height: 100vh;
      display: block;
      overflow: hidden;
      /* The host is an invisible fixed container: it paints NOTHING itself
         (a shadow/radius here would leave a ghost ring after the panel
         slides out) and never intercepts page clicks while collapsed. */
      pointer-events: none;
    }
    :host(.overlay) .panel {
      height: 100%;
      border-radius: 14px 0 0 14px;
      box-shadow: -2px 0 14px rgba(0,0,0,.12);
      pointer-events: auto;
      /* Slide in/out from the right edge on toggle (Vue DevTools style). */
      transition: transform .28s ease, box-shadow .28s ease;
    }
    :host(.overlay.collapsed) .panel {
      transform: translateX(110%);
      box-shadow: none;
    }
    .node-select {
      margin-left: auto; padding: 3px 8px; border-radius: 999px;
      border: 1px solid #e5e7eb; background: #ffffff; color: #1e40af;
      font-size: 11px; font-weight: 600; font-family: inherit; cursor: pointer;
    }
    .close {
      padding: 3px 10px; border-radius: 999px; cursor: pointer; user-select: none;
      border: 1px solid #e5e7eb; background: #ffffff; color: #6b7280;
      font-size: 11px; font-weight: 600; font-family: inherit;
    }
    .close:hover { background: #fee2e2; color: #991b1b; }
    .pause, .export {
      padding: 3px 10px; border-radius: 999px; cursor: pointer; user-select: none;
      border: 1px solid #e5e7eb; background: #ffffff; color: #1a56db;
      font-size: 11px; font-weight: 600; font-family: inherit;
    }
    .pause:hover, .export:hover { background: #e8f0fe; }
    .export { margin-left: auto; }
    .paused-banner { color: #9ca3af; font-size: 11px; margin-bottom: 6px; }
    .brand {
      display: flex; align-items: center; gap: 7px;
      padding: 10px 12px 0;
    }
    .brand-icon { width: 64px; height: 64px; display: block; }
    .brand-name {
      font-weight: 700; font-size: 17px; color: #1a56db; letter-spacing: .04em;
    }
    .brand-tag { font-size: 14px; color: #9ca3af; font-weight: 500; }
    .overview { color: #6b7280; padding: 6px 12px 0; font-size: 11px; }
    .tree-row {
      line-height: 20px; padding-right: 8px; border-radius: 6px;
    }
    .tree-row:hover { background: #f3f4f6; }
    .tree-toggle { user-select: none; }
    .layer-filter { display: flex; gap: 10px; align-items: center; margin-bottom: 6px; }
    .layer-filter label {
      display: inline-flex; align-items: center; gap: 4px;
      font-size: 11px; color: #374151; cursor: pointer; user-select: none;
    }
    .layer-filter input { accent-color: #1a56db; margin: 0; }
    .layer-filter .layer-filter-label { color: #9ca3af; cursor: default; }
    .layer-pill {
      display: inline-flex; align-items: center; border-radius: 999px;
      font-size: 10px; line-height: 15px; padding: 0 6px; margin: 0 4px;
      vertical-align: middle; white-space: nowrap;
    }
  `;

  // Leaf formatting: strings verbatim (opaque payloads already arrive as
  // "[encrypted: N bytes]"), everything else JSON.
  function formatLeaf(value) {
    if (value === null) return 'null';
    if (typeof value === 'string') return value;
    return JSON.stringify(value);
  }

  // Human attestation-TTL hint, exact below a second, then m/h with the
  // simple unit ladder and one decimal in days (e.g. '800ms', '45s',
  // '5m', '2h', '1.5d'). Returns '' for anything non-numeric so a
  // malformed entry renders without a hint instead of lying (e.g. 'NaNm').
  function formatDurationHint(ttlMs) {
    if (typeof ttlMs !== 'number' || !(ttlMs >= 0)) return '';
    if (ttlMs < 1000) return ttlMs + 'ms';
    const seconds = ttlMs / 1000;
    if (seconds < 60) return Math.floor(seconds) + 's';
    if (seconds < 3600) return Math.floor(seconds / 60) + 'm';
    if (seconds < 86400) return Math.floor(seconds / 3600) + 'h';
    return (seconds / 86400).toFixed(1) + 'd';
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
    // Mode/status pills in the lineage section reuse the timeline's pill
    // idiom ('layer-pill' class) with the lineage palettes above.
    const appendPill = (row, label, colors) => {
      const pill = document.createElement('span');
      pill.className = 'layer-pill';
      pill.textContent = String(label);
      const [background, textColor] = colors || LINEAGE_PILL_FALLBACK;
      pill.style.background = background;
      pill.style.color = textColor;
      row.appendChild(pill);
    };
    // One lineage child's row: child_id, residency marker, attestation TTL
    // hint, mode + status pills, and a diff badge when any field under the
    // child changed (or was added) in the latest snapshot.
    const renderLineageRow = (childId, child, depth) => {
      const row = document.createElement('div');
      row.className = 'tree-row';
      row.style.paddingLeft = (depth * 14) + 'px';
      const identifier = document.createElement('span');
      identifier.className = 'mono';
      identifier.textContent = childId;
      row.appendChild(identifier);
      // Residency comes from the C snapshot (lineage_query_resident_child):
      // true only while the parent still holds the child in this process.
      const residency = document.createElement('span');
      residency.className = 'mono';
      residency.style.color = '#9ca3af';
      residency.textContent = child.resident === true
        ? ' [resident]' : ' [off-process]';
      row.appendChild(residency);
      const ttlHint = formatDurationHint(child.attestation_ttl_ms);
      if (ttlHint) {
        const ttl = document.createElement('span');
        ttl.className = 'mono';
        ttl.style.color = '#9ca3af';
        ttl.textContent = ' · ttl ' + ttlHint;
        row.appendChild(ttl);
      }
      appendPill(row, child.mode, LINEAGE_MODE_COLORS[child.mode]);
      appendPill(row, child.status, LINEAGE_STATUS_COLORS[child.status]);
      const changedPath = Object.keys(diffs).find(
        (diffPath) => diffPath.indexOf('children.' + childId + '.') === 0);
      if (changedPath) appendBadge(row, diffs[changedPath]);
      container.appendChild(row);
    };

    // The Lineage section: keyed child-machine manifest from the snapshot
    // ('lineage (' + N + ')' header, matching the other section headers).
    const renderLineageSection = (childrenByKey, depth) => {
      const childIds = Object.keys(childrenByKey);
      const row = document.createElement('div');
      row.className = 'tree-row';
      row.style.paddingLeft = (depth * 14) + 'px';
      if (childIds.length === 0) {
        const label = document.createElement('span');
        label.className = 'mono muted';
        label.textContent = 'lineage: none';
        row.appendChild(label);
        container.appendChild(row);
        return;
      }
      const toggle = document.createElement('span');
      toggle.className = 'tree-toggle mono';
      const expanded = expandedPaths.has('children');
      toggle.textContent = (expanded ? '▾ ' : '▸ ') +
        'lineage (' + childIds.length + ')';
      toggle.style.cursor = 'pointer';
      toggle.addEventListener('click', () => {
        if (expandedPaths.has('children')) expandedPaths.delete('children');
        else expandedPaths.add('children');
        renderStateTree(container, snapshot, diffs, expandedPaths);
      });
      row.appendChild(toggle);
      container.appendChild(row);
      if (expanded) {
        for (const childId of childIds) {
          renderLineageRow(childId, childrenByKey[childId], depth + 1);
        }
      }
    };

    const renderValue = (value, path, depth) => {
      // The children manifest gets a dedicated lineage section (pills,
      // residency) instead of the generic field-per-row tree.
      if (path === 'children') {
        renderLineageSection(value, depth);
        return;
      }
      const row = document.createElement('div');
      row.className = 'tree-row';
      row.style.paddingLeft = (depth * 14) + 'px';
      // Item rows (items.<index>): the C snapshot emits additive
      // write-domain fields (domain/writer/item_seq/item_digest_head/
      // ordering_module/fork_count/forks). Render the domain pill plus a
      // chain-head hint on the row; the quarantine set becomes a Forks
      // section instead of a generic subtree. All strings land via
      // textContent — the panel's established XSS discipline.
      const isItemRow = /^items\.\d+$/.test(path) && value !== null &&
                        typeof value === 'object' && value.name;
      const isObject = value !== null && typeof value === 'object';
      if (isObject && Object.keys(value).length > 0) {
        const keys = Object.keys(value).filter(
          (key) => !(isItemRow && key === 'forks'));
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
        if (isItemRow) {
          row.setAttribute('data-item-name', value.name);
          if (typeof value.domain === 'string') {
            appendPill(row, value.domain, DOMAIN_PILL_COLORS[value.domain]);
          }
          if (value.domain === 'sovereign') {
            const chainHint = document.createElement('span');
            chainHint.className = 'mono';
            chainHint.style.color = '#9ca3af';
            chainHint.textContent = ' · seq ' + (value.item_seq || 0) +
              ' · head ' + (value.item_digest_head || '');
            row.appendChild(chainHint);
          }
        }
        container.appendChild(row);
        if (expanded) {
          for (const key of keys) {
            renderValue(value[key], path ? path + '.' + key : key, depth + 1);
          }
          if (isItemRow && Array.isArray(value.forks) &&
              value.forks.length > 0) {
            const forksHeader = document.createElement('div');
            forksHeader.className = 'tree-row';
            forksHeader.style.paddingLeft = ((depth + 1) * 14) + 'px';
            const forksLabel = document.createElement('span');
            forksLabel.className = 'mono';
            forksLabel.textContent = 'Forks (' + value.forks.length +
              ') — quarantined writers:';
            forksHeader.appendChild(forksLabel);
            container.appendChild(forksHeader);
            for (const forkEntry of value.forks) {
              const forkRow = document.createElement('div');
              forkRow.className = 'tree-row';
              forkRow.style.paddingLeft = ((depth + 2) * 14) + 'px';
              const forkText = document.createElement('span');
              forkText.className = 'mono';
              forkText.textContent = String(forkEntry.writer) +
                ' · evidence ' + String(forkEntry.evidence_head || '');
              forkRow.appendChild(forkText);
              container.appendChild(forkRow);
            }
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
      this.expandedPaths = new Set(['', 'items', 'children']);
      this.filterText = '';
      // Layer visibility persists per-panel across re-renders; all layers
      // are shown until a checkbox is unchecked.
      this.visibleLayers = new Set(Object.keys(LAYER_COLORS));
      this.paused = false;
      // Start collapsed: the CRABS launcher button opens the panel, so
      // the devtools never cover the app until asked for.
      this.collapsedState = true;
      // Multi-node support: several attach() calls can share one panel
      // (Vue DevTools style). Each entry is { nodeId, controller, update }.
      this.controllers = [];
      this.activeController = null;
    }

    registerController(nodeId, controller) {
      const entry = { nodeId, controller };
      this.controllers.push(entry);
      if (this.controllers.length === 1) {
        this.activeController = entry;
      }
      // Re-render immediately so the node selector appears the moment a
      // second machine attaches (not only on the next change event).
      if (this.root) this.render();
      return entry;
    }

    activateController(entry) {
      if (this.activeController === entry) return;
      this.activeController = entry;
      // Switching nodes pulls a fresh snapshot immediately; the resulting
      // onUpdate lands in update() for the now-active controller.
      entry.controller.refresh();
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
      // Overlay mode slides the panel out via :host(.overlay.collapsed)
      // transform; only in-flow mode hides it outright (display:none would
      // kill the slide transition). Overlay mode always clears the inline
      // display — connectedCallback can run BEFORE attach() adds the
      // overlay class (appendChild happens first), leaving a stale
      // display:none that would override the slide.
      if (!this.classList.contains('overlay')) {
        this.root.style.display = this.collapsedState ? 'none' : '';
      } else if (this.root.style.display === 'none') {
        this.root.style.display = '';
      }
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
      // Branding: the Encryptstacean logo from the project README plus the
      // CRABS wordmark, top-left of the panel.
      const brand = document.createElement('div');
      brand.className = 'brand';
      const brandIcon = document.createElement('img');
      brandIcon.className = 'brand-icon';
      brandIcon.src = CRABS_ICON_DATA_URI;
      brandIcon.alt = 'CRABS logo';
      const brandName = document.createElement('span');
      brandName.className = 'brand-name';
      brandName.textContent = 'CRABS';
      const brandTag = document.createElement('span');
      brandTag.className = 'brand-tag';
      brandTag.textContent = 'state machine inspector';
      brand.append(brandIcon, brandName, brandTag);
      // Overview header: node id, version, hlc, log head, pending schedules.
      const overview = document.createElement('div');
      overview.className = 'overview mono';
      overview.textContent = overviewLine(snapshot);
      this.root.replaceChildren(brand, overview);
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
      // Node selector: visible only when multiple state machines share
      // this panel (Vue DevTools-style instance switching).
      if (this.controllers.length > 1) {
        const selector = document.createElement('select');
        selector.className = 'node-select';
        selector.setAttribute('aria-label', 'State machine to inspect');
        for (const entry of this.controllers) {
          const option = document.createElement('option');
          option.value = entry.nodeId;
          option.textContent = entry.nodeId;
          if (entry === this.activeController) option.selected = true;
          selector.appendChild(option);
        }
        selector.addEventListener('change', () => {
          const selected = this.controllers.find(
            (entry) => entry.nodeId === selector.value);
          if (selected) this.activateController(selected);
        });
        tabbar.appendChild(selector);
      }
      const closeButton = document.createElement('button');
      closeButton.className = 'close';
      closeButton.textContent = '×';
      closeButton.title = 'Hide panel (CRABS launcher re-opens it)';
      closeButton.setAttribute('aria-label', 'Hide devtools panel');
      closeButton.addEventListener('click', () => {
        this.collapsed = true;
      });
      tabbar.appendChild(closeButton);
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

    // A row is visible iff its layer is checked AND the text filter matches.
    // Unknown/missing layers count as 'op', matching the fallback pill.
    eventVisible(event, needle) {
      const layer = LAYER_COLORS[event.layer] ? event.layer : LAYER_FALLBACK.label;
      if (!this.visibleLayers.has(layer)) return false;
      if (!needle) return true;
      return (event.op_type + ' ' + event.signer + ' ' +
        event.target + ' ' + event.node).toLowerCase().includes(needle);
    }

    renderTimeline(body) {
      // Layer filter row: one checkbox per layer above the text filter. Toggling
      // patches the existing rows in place (same rationale as the text
      // filter — a re-render would destroy input focus and open details).
      const layerFilter = document.createElement('div');
      layerFilter.className = 'layer-filter';
      const layerFilterLabel = document.createElement('label');
      layerFilterLabel.className = 'layer-filter-label';
      layerFilterLabel.textContent = 'layers:';
      layerFilter.appendChild(layerFilterLabel);
      for (const layer of Object.keys(LAYER_COLORS)) {
        const layerOption = document.createElement('label');
        const layerCheckbox = document.createElement('input');
        layerCheckbox.type = 'checkbox';
        layerCheckbox.checked = this.visibleLayers.has(layer);
        layerCheckbox.addEventListener('change', () => {
          if (layerCheckbox.checked) this.visibleLayers.add(layer);
          else this.visibleLayers.delete(layer);
          const needle = this.filterText.toLowerCase();
          for (const row of timelineRows) {
            row.style.display =
              this.eventVisible(row._event, needle) ? '' : 'none';
          }
        });
        layerOption.appendChild(layerCheckbox);
        layerOption.appendChild(document.createTextNode(layer));
        layerFilter.appendChild(layerOption);
      }
      body.appendChild(layerFilter);

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
          row.style.display = this.eventVisible(row._event, needle) ? '' : 'none';
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
        // Rows hidden by the layer filter start hidden; toggling a checkbox
        // only flips display, so the click/detail wiring stays intact.
        if (!this.eventVisible(event, needle)) row.style.display = 'none';
        const left = document.createElement('span');
        left.textContent = event.signer + ' ·';
        const pill = document.createElement('span');
        pill.className = 'layer-pill';
        const layerColors = LAYER_COLORS[event.layer] || null;
        pill.textContent = layerColors ? event.layer : LAYER_FALLBACK.label;
        pill.style.background = layerColors ? layerColors[0] : LAYER_FALLBACK.background;
        pill.style.color = layerColors ? layerColors[1] : LAYER_FALLBACK.color;
        left.appendChild(pill);
        const eventText = document.createElement('span');
        eventText.textContent = ' ' + event.op_type +
          (event.target ? ' ' + event.target : '') +
          (event.preview ? ' · ' + event.preview : '');
        left.appendChild(eventText);
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

  // Shared-panel registries: one overlay panel per document, one in-flow
  // panel per mount element. Additional attach() calls register additional
  // state machines (a node selector appears) instead of stacking panels.
  let sharedOverlayPanel = null;
  const mountedPanels = new WeakMap();

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
    const nodeId = options.nodeId || node.adminId || null;

    // mount === null → overlay mode: ONE fixed-position overlay panel per
    // document is shared by every attach() call — additional state machines
    // register into it and a node selector appears in the tab bar (Vue
    // DevTools style). A provided mount keeps the panel in normal flow
    // inside that container, one panel per mount element.
    const mount = options.mount || null;
    const overlayMode = mount === null;
    let panel = overlayMode ? sharedOverlayPanel : mountedPanels.get(mount);
    const isNewPanel = !panel || !panel.isConnected;
    if (isNewPanel) {
      panel = document.createElement('crabs-devtools');
      // Classify BEFORE appending: connectedCallback fires synchronously on
      // append and reads the class to pick overlay vs in-flow collapse.
      if (overlayMode) {
        panel.classList.add('overlay');
        sharedOverlayPanel = panel;
      } else {
        mountedPanels.set(mount, panel);
      }
      const host = mount || document.body;
      host.appendChild(panel);
    }
    const entry = panel.registerController(nodeId, controller);
    // Every controller pushes into the panel; the panel renders only the
    // ACTIVE one. Dormant controllers keep refreshing in the background
    // (their events and snapshots accumulate); selecting a node in the
    // selector activates it and re-renders from its data.
    controller.onUpdate((data) => {
      if (panel.activeController !== entry) return;
      panel.update({
        snapshot: data.snapshot,
        allEvents: data.allEvents,
        diffs: data.diffs,
      });
    });
    if (isNewPanel) controller.refresh();
    return { panel, controller };
  }

  window.CRABSDevtools = { attach };
})();
