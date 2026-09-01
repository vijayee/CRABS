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

  const STATE_COLORS = {
    idle: '#e5e7eb', locked: '#fef3c7', modified: '#dbeafe',
    verified: '#d1fae5', error: '#fee2e2', unknown: '#f3f4f6',
  };
  const STATE_TEXT = {
    idle: '#374151', locked: '#92400e', modified: '#1e40af',
    verified: '#065f46', error: '#991b1b', unknown: '#374151',
  };

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
    .badge {
      display: inline-block; padding: 1px 8px; border-radius: 999px;
      font-size: 10px; font-weight: 600;
    }
    .card {
      background: #f9fafb; border-radius: 8px; padding: 6px 10px; margin-bottom: 6px;
      cursor: pointer;
    }
    .card.selected { outline: 2px solid #1a56db; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11px; }
    .row { display: flex; justify-content: space-between; gap: 8px; padding: 4px 8px;
           border-radius: 8px; margin-bottom: 3px; }
    .row.accept { background: #f0fdf4; }
    .row.reject { background: #fef2f2; }
    .ok { color: #059669; font-weight: 600; }
    .bad { color: #dc2626; font-weight: 600; }
    .muted { color: #9ca3af; }
    pre.value { background: #f3f4f6; border-radius: 8px; padding: 6px 8px;
                overflow-x: auto; font-family: ui-monospace, monospace; font-size: 11px; }
    .warn { background: #fef9c3; color: #854d0e; padding: 2px 8px; border-radius: 999px;
            font-size: 10px; font-weight: 600; }
    .error-banner { background: #fef2f2; color: #991b1b; border-radius: 8px;
                    padding: 6px 10px; margin-bottom: 6px; }
    input.filter {
      flex: 1; border: 1px solid #e5e7eb; border-radius: 8px; padding: 3px 8px;
      font-size: 11px; font-family: inherit;
    }
    .toolbar { display: flex; gap: 6px; margin-bottom: 6px; }
    .detail { background: #f3f4f6; border-radius: 8px; padding: 6px 8px; margin: 3px 0;
              font-family: ui-monospace, monospace; font-size: 11px; white-space: pre-wrap; }
    .fsm { display: flex; align-items: center; gap: 4px; margin-top: 6px; flex-wrap: wrap; }
    .fsm .stop { padding: 1px 8px; border-radius: 999px; font-size: 10px; }
    .fsm .arrow { color: #9ca3af; }
    .toggle {
      position: fixed; bottom: 16px; right: 16px; z-index: 2147483647;
      width: 36px; height: 36px; border-radius: 999px;
      font: 700 9px/1 -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      letter-spacing: .04em; cursor: pointer; user-select: none;
      box-shadow: 0 2px 8px rgba(0,0,0,.12);
    }
    .toggle.open { background: #1a56db; color: #ffffff; border: 1px solid #1a56db; }
    .toggle.collapsed { background: #ffffff; color: #1a56db; border: 1px solid #e5e7eb; }
    .pause {
      padding: 3px 10px; border-radius: 999px; cursor: pointer; user-select: none;
      border: 1px solid #e5e7eb; background: #ffffff; color: #1a56db;
      font-size: 11px; font-weight: 600; font-family: inherit;
    }
    .pause:hover { background: #e8f0fe; }
    .paused-banner { color: #9ca3af; font-size: 11px; margin-bottom: 6px; }
  `;

  const ORDERED_STATES = ['idle', 'locked', 'modified', 'verified'];

  class CrabsDevtools extends HTMLElement {
    constructor() {
      super();
      this.attachShadow({ mode: 'open' });
      this.activeTab = 'timeline';
      this.data = { snapshot: null, allEvents: [] };
      this.filterText = '';
      this.selectedItem = null;
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
      this.toggleButton.className =
        'toggle ' + (this.collapsedState ? 'collapsed' : 'open');
      this.toggleButton.setAttribute('aria-expanded', String(!this.collapsedState));
    }

    update(data) {
      const wasConnected = this.isConnected;
      this.data = {
        snapshot: data.snapshot || this.data.snapshot,
        allEvents: data.allEvents || this.data.allEvents,
      };
      // While paused the panel stays frozen on the pause-moment view; the
      // merged data is picked up by the next render (e.g. on resume).
      if (wasConnected && !this.paused) this.render();
    }

    render() {
      if (!this.root) return;
      const snapshot = this.data.snapshot;
      const tabbar = document.createElement('div');
      tabbar.className = 'tabbar';
      for (const tab of ['states', 'timeline', 'crdt', 'config']) {
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
      this.root.replaceChildren(tabbar);
      const body = document.createElement('div');
      body.className = 'body';
      if (snapshot && snapshot.error) {
        const banner = document.createElement('div');
        banner.className = 'error-banner';
        banner.textContent = snapshot.error;
        body.appendChild(banner);
      }
      const renderer = {
        states: () => this.renderStates(body),
        timeline: () => this.renderTimeline(body),
        crdt: () => this.renderCrdt(body),
        config: () => this.renderConfig(body),
      }[this.activeTab];
      renderer();
      this.root.appendChild(body);
    }

    stateBadge(state) {
      const badge = document.createElement('span');
      badge.className = 'badge';
      badge.textContent = state;
      badge.style.background = STATE_COLORS[state] || STATE_COLORS.unknown;
      badge.style.color = STATE_TEXT[state] || STATE_TEXT.unknown;
      return badge;
    }

    renderStates(body) {
      const snapshot = this.data.snapshot;
      if (!snapshot || !snapshot.items) {
        body.innerHTML = '<span class="muted">No snapshot yet.</span>';
        return;
      }
      for (const item of snapshot.items) {
        const card = document.createElement('div');
        card.className = 'card' + (this.selectedItem === item.name ? ' selected' : '');
        const title = document.createElement('div');
        title.appendChild(document.createTextNode(item.name + ' '));
        title.appendChild(this.stateBadge(item.protocol_state));
        card.appendChild(title);
        const meta = document.createElement('div');
        meta.className = 'muted';
        meta.textContent = item.crdt_type;
        card.appendChild(meta);
        if (this.selectedItem === item.name) {
          const fsm = document.createElement('div');
          fsm.className = 'fsm';
          for (let stateIndex = 0; stateIndex < ORDERED_STATES.length; stateIndex++) {
            if (stateIndex > 0) {
              const arrow = document.createElement('span');
              arrow.className = 'arrow';
              arrow.textContent = '→';
              fsm.appendChild(arrow);
            }
            const stop = document.createElement('span');
            stop.className = 'stop';
            stop.textContent = ORDERED_STATES[stateIndex];
            if (ORDERED_STATES[stateIndex] === item.protocol_state) {
              stop.style.background = '#e8f0fe';
              stop.style.color = '#1a56db';
              stop.style.fontWeight = '600';
            } else {
              stop.style.background = STATE_COLORS[ORDERED_STATES[stateIndex]];
              stop.style.color = STATE_TEXT[ORDERED_STATES[stateIndex]];
            }
            fsm.appendChild(stop);
          }
          if (item.protocol_state === 'error') {
            fsm.appendChild(document.createTextNode(' (off-ramp) '));
            fsm.appendChild(this.stateBadge('error'));
          }
          const itemEvents = this.data.allEvents.filter(
            (event) => event.target === item.name);
          const fsmHistory = document.createElement('div');
          fsmHistory.className = 'fsm-history';
          for (const event of itemEvents.slice(-5).reverse()) {
            const line = document.createElement('div');
            line.className = 'muted';
            line.textContent = event.op_type + ' ' +
              (event.transition ? '(' + event.transition + ')' : '');
            fsmHistory.appendChild(line);
          }
          fsm.after(fsmHistory);
        }
        card.addEventListener('click', () => {
          this.selectedItem = this.selectedItem === item.name ? null : item.name;
          this.render();
        });
        body.appendChild(card);
      }
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

    renderCrdt(body) {
      const snapshot = this.data.snapshot;
      if (!snapshot || !snapshot.items) {
        body.innerHTML = '<span class="muted">No snapshot yet.</span>';
        return;
      }
      for (const item of snapshot.items) {
        const card = document.createElement('div');
        card.className = 'card';
        const title = document.createElement('div');
        title.appendChild(document.createTextNode(item.name + ' · '));
        const type = document.createElement('span');
        type.className = 'muted';
        type.textContent = item.crdt_type;
        title.appendChild(type);
        card.appendChild(title);
        const value = document.createElement('pre');
        value.className = 'value';
        value.textContent = JSON.stringify(item.value, null, 1);
        card.appendChild(value);
        body.appendChild(card);
      }
    }

    renderConfig(body) {
      const snapshot = this.data.snapshot;
      if (!snapshot) {
        body.innerHTML = '<span class="muted">No snapshot yet.</span>';
        return;
      }
      for (const policy of snapshot.policies || []) {
        const row = document.createElement('div');
        row.className = 'row';
        const left = document.createElement('b');
        left.textContent = policy.operation;
        const right = document.createElement('span');
        right.textContent = policy.expression;
        row.appendChild(left);
        row.appendChild(right);
        body.appendChild(row);
      }
      for (const trigger of snapshot.triggers || []) {
        const row = document.createElement('div');
        row.className = 'row';
        const left = document.createElement('span');
        left.textContent = trigger.id + ' · ' + trigger.condition;
        const right = document.createElement('span');
        if (trigger.fired) {
          right.className = 'warn';
          right.textContent = 'FIRED';
        } else {
          right.className = 'muted';
          right.textContent = trigger.enabled ? 'armed' : 'disabled';
        }
        row.appendChild(left);
        row.appendChild(right);
        body.appendChild(row);
      }
      for (const user of snapshot.users || []) {
        const row = document.createElement('div');
        row.className = 'row';
        const left = document.createElement('b');
        left.textContent = user.id;
        const right = document.createElement('span');
        right.className = 'muted';
        right.textContent = user.attrs.length + ' attrs · ' + user.keys + ' keys';
        row.appendChild(left);
        row.appendChild(right);
        body.appendChild(row);
      }
      if (snapshot.log_head) {
        const head = document.createElement('div');
        head.className = 'muted mono';
        head.textContent = 'log: ' + snapshot.log_head.entries + ' entries · head ' +
          (snapshot.log_head.state_hash || '').slice(0, 12);
        body.appendChild(head);
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
    }));
    (options.mount || document.body).appendChild(panel);
    controller.refresh();
    return { panel, controller };
  }

  window.CRABSDevtools = { attach };
})();
