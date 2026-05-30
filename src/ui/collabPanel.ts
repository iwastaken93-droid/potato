/**
 * Premium Collaborative Workspace Sync UI Panel
 * Part of the Universal Reverse Engineering Tool
 * Supports connecting to room, viewing peers, syncing and displaying comments, highlights, and renames.
 */

import {
  CollabEngine,
  Peer,
  SyncComment,
  SyncHighlight,
  SyncRename,
} from '../network/collab.js';

export interface CollabPanelOptions {
  onNavigate: (
    targetView: 'assembly' | 'hex' | 'decompiler',
    address: number
  ) => void;
  onCommentSynced?: (address: number, comment: string) => void;
  onHighlightSynced?: (address: number, color: string) => void;
  onRenameSynced?: (
    oldName: string,
    newName: string,
    type: 'function' | 'variable'
  ) => void;
  onCursorSynced?: (
    address: number,
    view: 'assembly' | 'hex' | 'decompiler'
  ) => void;
}

export class CollabPanel {
  private container: HTMLElement;
  private options: CollabPanelOptions;
  private engine: CollabEngine;

  // DOM Elements
  private rootEl!: HTMLDivElement;
  private connectionContainer!: HTMLDivElement;
  private activeRoomDetails!: HTMLDivElement;
  private peersListEl!: HTMLDivElement;
  private activityLogEl!: HTMLDivElement;

  // Connect Form Inputs
  private usernameInput!: HTMLInputElement;
  private roomInput!: HTMLInputElement;
  private connectBtn!: HTMLButtonElement;

  // Interactive Simulator Elements
  private actionCommentAddrInput!: HTMLInputElement;
  private actionCommentTextInput!: HTMLInputElement;
  private actionHighlightAddrInput!: HTMLInputElement;
  private actionHighlightColorSelect!: HTMLSelectElement;
  private actionRenameOldInput!: HTMLInputElement;
  private actionRenameNewInput!: HTMLInputElement;
  private actionRenameTypeSelect!: HTMLSelectElement;
  private actionCursorAddrInput!: HTMLInputElement;
  private actionCursorViewSelect!: HTMLSelectElement;

  private unsubscribes: (() => void)[] = [];

  constructor(container: HTMLElement, options: CollabPanelOptions) {
    this.container = container;
    this.options = options;
    this.engine = new CollabEngine();

    this.initLayout();
    this.setupSubscriptions();
    this.setupEvents();
    this.updateUIState();
  }

  /**
   * Cleans up listeners when panel is destroyed
   */
  public destroy(): void {
    this.unsubscribes.forEach((unsub) => unsub());
    this.unsubscribes = [];
    this.engine.disconnect();
  }

  private initLayout(): void {
    this.container.innerHTML = '';

    this.rootEl = document.createElement('div');
    this.rootEl.className = 'collab-panel-root glass-panel';
    this.rootEl.style.cssText = `
      display: flex;
      flex-direction: column;
      height: 100%;
      padding: 1.5rem;
      gap: 1.25rem;
      box-sizing: border-box;
      overflow-y: auto;
    `;

    // Inject CSS styles matching global design system
    if (!document.getElementById('collab-panel-styles')) {
      const style = document.createElement('style');
      style.id = 'collab-panel-styles';
      style.textContent = `
        .collab-panel-root {
          background: rgba(22, 26, 33, 0.45);
          backdrop-filter: blur(20px);
          -webkit-backdrop-filter: blur(20px);
          border: 1px solid var(--border-color, rgba(255,255,255,0.08));
          border-radius: var(--radius-lg, 8px);
          box-shadow: var(--shadow-lg, 0 10px 15px -3px rgba(0,0,0,0.1));
        }

        .collab-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          border-bottom: 1px solid var(--border-color, rgba(255,255,255,0.08));
          padding-bottom: 0.75rem;
        }

        .collab-title {
          font-size: 1.25rem;
          font-weight: 700;
          color: var(--text-primary, #ffffff);
          display: flex;
          align-items: center;
          gap: 0.5rem;
        }

        .collab-title::before {
          content: '👥';
          font-size: 1.2rem;
        }

        .collab-grid {
          display: grid;
          grid-template-columns: 320px 1fr;
          gap: 1.25rem;
          flex: 1;
          min-height: 0;
        }

        @media (max-width: 768px) {
          .collab-grid {
            grid-template-columns: 1fr;
          }
        }

        .collab-sidebar {
          display: flex;
          flex-direction: column;
          gap: 1rem;
        }

        .collab-card {
          background: rgba(15, 17, 21, 0.6);
          border: 1px solid var(--border-color, rgba(255,255,255,0.08));
          border-radius: var(--radius-md, 6px);
          padding: 1rem;
          display: flex;
          flex-direction: column;
          gap: 0.75rem;
        }

        .collab-card-title {
          font-size: 0.9rem;
          font-weight: 600;
          color: var(--text-muted, #94a3b8);
          text-transform: uppercase;
          letter-spacing: 0.05em;
          border-bottom: 1px solid rgba(255,255,255,0.04);
          padding-bottom: 0.5rem;
        }

        .collab-input-group {
          display: flex;
          flex-direction: column;
          gap: 0.4rem;
        }

        .collab-label {
          font-size: 0.8rem;
          color: var(--text-muted, #94a3b8);
        }

        .collab-input {
          background: rgba(15, 17, 21, 0.8);
          border: 1px solid var(--border-color, rgba(255,255,255,0.08));
          border-radius: var(--radius-sm, 4px);
          color: var(--text-primary, #ffffff);
          padding: 0.5rem 0.75rem;
          font-size: 0.85rem;
          outline: none;
          transition: border-color var(--transition-fast, 0.2s);
        }

        .collab-input:focus {
          border-color: var(--accent-start, #6366f1);
        }

        .collab-btn {
          background: linear-gradient(135deg, var(--accent-start, #6366f1) 0%, var(--accent-end, #8b5cf6) 100%);
          color: #ffffff;
          border: none;
          border-radius: var(--radius-sm, 4px);
          padding: 0.5rem 1rem;
          font-weight: 600;
          cursor: pointer;
          transition: opacity 0.2s;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 0.5rem;
        }

        .collab-btn:hover {
          opacity: 0.9;
        }

        .collab-btn-secondary {
          background: rgba(255, 255, 255, 0.05);
          border: 1px solid var(--border-color, rgba(255,255,255,0.08));
          color: var(--text-primary, #ffffff);
        }

        .collab-btn-secondary:hover {
          background: rgba(255, 255, 255, 0.1);
        }

        .collab-peer-row {
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 0.4rem 0.5rem;
          border-radius: 4px;
          background: rgba(255, 255, 255, 0.01);
        }

        .collab-peer-info {
          display: flex;
          align-items: center;
          gap: 0.5rem;
        }

        .collab-peer-avatar {
          width: 8px;
          height: 8px;
          border-radius: 50%;
        }

        .collab-peer-name {
          font-size: 0.85rem;
          font-weight: 500;
          color: var(--text-primary, #ffffff);
        }

        .collab-peer-status {
          font-size: 0.75rem;
          padding: 0.1rem 0.35rem;
          border-radius: 9999px;
          background: rgba(255, 255, 255, 0.05);
          color: var(--text-muted, #94a3b8);
        }

        .collab-peer-status.connected {
          color: #10B981;
          background: rgba(16, 185, 129, 0.1);
        }

        .collab-peer-status.idle {
          color: #F59E0B;
          background: rgba(245, 158, 11, 0.1);
        }

        .collab-activity-panel {
          display: flex;
          flex-direction: column;
          gap: 1rem;
          background: rgba(15, 17, 21, 0.4);
          border: 1px solid var(--border-color, rgba(255,255,255,0.08));
          border-radius: var(--radius-md, 6px);
          padding: 1rem;
          min-height: 0;
        }

        .collab-activity-list {
          flex: 1;
          overflow-y: auto;
          display: flex;
          flex-direction: column;
          gap: 0.75rem;
          padding-right: 0.5rem;
        }

        .collab-activity-item {
          background: rgba(255, 255, 255, 0.02);
          border: 1px solid rgba(255, 255, 255, 0.04);
          border-left-width: 4px;
          border-radius: 4px;
          padding: 0.75rem;
          display: flex;
          flex-direction: column;
          gap: 0.4rem;
          transition: transform var(--transition-fast, 0.2s);
        }

        .collab-activity-item:hover {
          transform: translateX(4px);
          background: rgba(255, 255, 255, 0.04);
        }

        .collab-activity-meta {
          display: flex;
          justify-content: space-between;
          align-items: center;
          font-size: 0.75rem;
          color: var(--text-muted, #94a3b8);
        }

        .collab-activity-peer {
          font-weight: 600;
          color: var(--text-primary, #ffffff);
        }

        .collab-activity-content {
          font-size: 0.85rem;
          color: var(--text-primary, #ffffff);
          word-break: break-all;
        }

        .collab-address-link {
          color: var(--accent-start, #6366f1);
          text-decoration: none;
          font-family: monospace;
          font-weight: bold;
          cursor: pointer;
        }

        .collab-address-link:hover {
          text-decoration: underline;
        }

        .collab-form-row {
          display: flex;
          gap: 0.5rem;
          flex-wrap: wrap;
        }

        .collab-badge {
          display: inline-block;
          font-size: 0.75rem;
          padding: 0.1rem 0.4rem;
          border-radius: 3px;
          font-weight: 600;
          text-transform: uppercase;
        }

        .badge-comment {
          background: rgba(99, 102, 241, 0.15);
          color: #818cf8;
          border: 1px solid rgba(99, 102, 241, 0.3);
        }

        .badge-highlight {
          background: rgba(16, 185, 129, 0.15);
          color: #34d399;
          border: 1px solid rgba(16, 185, 129, 0.3);
        }

        .badge-rename {
          background: rgba(245, 158, 11, 0.15);
          color: #fbbf24;
          border: 1px solid rgba(245, 158, 11, 0.3);
        }
      `;
      document.head.appendChild(style);
    }

    // Title / Header
    const header = document.createElement('div');
    header.className = 'collab-header';
    header.innerHTML = `
      <div class="collab-title">Collaborative Sync Workspace</div>
      <div style="font-size: 0.8rem; color: var(--text-muted, #94a3b8);">Sync Engine status: <span id="collab-status-badge" style="font-weight: 700; color: #EF4444;">Offline</span></div>
    `;
    this.rootEl.appendChild(header);

    // Main Grid
    const grid = document.createElement('div');
    grid.className = 'collab-grid';

    // Sidebar Container
    const sidebar = document.createElement('div');
    sidebar.className = 'collab-sidebar';

    // Connection Info Card
    this.connectionContainer = document.createElement('div');
    this.connectionContainer.className = 'collab-card';
    sidebar.appendChild(this.connectionContainer);

    // Peers Card
    const peersCard = document.createElement('div');
    peersCard.className = 'collab-card';
    peersCard.innerHTML = `<div class="collab-card-title">Connected Peers</div>`;
    this.peersListEl = document.createElement('div');
    this.peersListEl.style.cssText =
      'display: flex; flex-direction: column; gap: 0.5rem;';
    peersCard.appendChild(this.peersListEl);
    sidebar.appendChild(peersCard);

    // Local Action triggers card (Allows sending comments/highlights/renames)
    const actionCard = document.createElement('div');
    actionCard.className = 'collab-card';
    actionCard.innerHTML = `<div class="collab-card-title">Local Workspace Actions</div>`;

    // Comment fields
    const commentGroup = document.createElement('div');
    commentGroup.className = 'collab-input-group';
    commentGroup.innerHTML = `
      <label class="collab-label">Send Comment</label>
      <div class="collab-form-row">
        <input type="text" id="collab-comment-addr" class="collab-input" placeholder="0x1000" style="width: 70px;">
        <input type="text" id="collab-comment-text" class="collab-input" placeholder="Add comment content..." style="flex: 1;">
        <button id="collab-btn-send-comment" class="collab-btn collab-btn-secondary" style="padding: 0.4rem 0.6rem;">Send</button>
      </div>
    `;
    actionCard.appendChild(commentGroup);

    // Highlight fields
    const highlightGroup = document.createElement('div');
    highlightGroup.className = 'collab-input-group';
    highlightGroup.innerHTML = `
      <label class="collab-label">Sync Highlight Address</label>
      <div class="collab-form-row">
        <input type="text" id="collab-highlight-addr" class="collab-input" placeholder="0x1000" style="width: 70px;">
        <select id="collab-highlight-color" class="collab-input" style="flex: 1; background: rgba(15, 17, 21, 0.8);">
          <option value="#EF4444">🔴 Red (#EF4444)</option>
          <option value="#10B981">🟢 Green (#10B981)</option>
          <option value="#3B82F6">🔵 Blue (#3B82F6)</option>
          <option value="#F59E0B">🟡 Yellow (#F59E0B)</option>
          <option value="#8B5CF6">🟣 Purple (#8B5CF6)</option>
        </select>
        <button id="collab-btn-send-highlight" class="collab-btn collab-btn-secondary" style="padding: 0.4rem 0.6rem;">Sync</button>
      </div>
    `;
    actionCard.appendChild(highlightGroup);

    // Rename fields
    const renameGroup = document.createElement('div');
    renameGroup.className = 'collab-input-group';
    renameGroup.innerHTML = `
      <label class="collab-label">Rename Function/Variable</label>
      <div class="collab-form-row">
        <input type="text" id="collab-rename-old" class="collab-input" placeholder="sub_1000" style="flex: 1; min-width: 70px;">
        <input type="text" id="collab-rename-new" class="collab-input" placeholder="decrypt" style="flex: 1; min-width: 70px;">
        <select id="collab-rename-type" class="collab-input" style="width: 85px; background: rgba(15, 17, 21, 0.8);">
          <option value="function">Function</option>
          <option value="variable">Variable</option>
        </select>
        <button id="collab-btn-send-rename" class="collab-btn collab-btn-secondary" style="padding: 0.4rem 0.6rem;">Rename</button>
      </div>
    `;
    actionCard.appendChild(renameGroup);

    // Cursor broadcast fields
    const cursorGroup = document.createElement('div');
    cursorGroup.className = 'collab-input-group';
    cursorGroup.innerHTML = `
      <label class="collab-label">Broadcast My Cursor</label>
      <div class="collab-form-row">
        <input type="text" id="collab-cursor-addr" class="collab-input" placeholder="0x1000" style="width: 70px;">
        <select id="collab-cursor-view" class="collab-input" style="flex: 1; background: rgba(15, 17, 21, 0.8);">
          <option value="assembly">Assembly</option>
          <option value="decompiler">Decompiler</option>
          <option value="hex">Hex Viewer</option>
        </select>
        <button id="collab-btn-send-cursor" class="collab-btn collab-btn-secondary" style="padding: 0.4rem 0.6rem;">Move</button>
      </div>
    `;
    actionCard.appendChild(cursorGroup);

    sidebar.appendChild(actionCard);
    grid.appendChild(sidebar);

    // Activity log view
    this.activityLogEl = document.createElement('div');
    this.activityLogEl.className = 'collab-activity-panel';
    this.activityLogEl.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid rgba(255,255,255,0.08); padding-bottom: 0.5rem;">
        <div style="font-weight: 700; color: var(--text-primary, #ffffff); font-size: 0.95rem;">Live Workspace Activity Stream</div>
        <button id="collab-btn-simulate" class="collab-btn" style="padding: 0.25rem 0.75rem; font-size: 0.75rem; background: linear-gradient(135deg, #10B981, #059669);">⚡ Simulate Peer Action</button>
      </div>
      <div id="collab-activity-list" class="collab-activity-list" style="max-height: 250px; overflow-y: auto;"></div>

      <!-- Visual Cursor Screen -->
      <div style="border-top: 1px solid rgba(255,255,255,0.08); padding-top: 1rem; margin-top: 1rem; display: flex; flex-direction: column; gap: 0.5rem;">
        <div style="font-weight: 700; color: var(--text-primary, #ffffff); font-size: 0.95rem;">Visual Workspace Cursors Screen</div>
        <div id="collab-cursors-container" style="position: relative; height: 180px; background: rgba(10, 12, 16, 0.85); border: 1px solid rgba(255,255,255,0.08); border-radius: 4px; overflow: hidden; display: flex; justify-content: space-around; align-items: center; padding: 10px;">
           <div id="view-assembly" style="border: 1px solid rgba(255,255,255,0.1); border-radius: 4px; flex: 1; height: 100%; margin: 5px; background: rgba(255, 255, 255, 0.02); position: relative; display: flex; flex-direction: column; align-items: center;">
              <div style="font-size: 0.75rem; font-weight: bold; color: var(--text-muted, #94a3b8); margin-top: 5px; pointer-events: none;">Assembly</div>
              <div class="cursors-area" style="position: absolute; top: 25px; left: 0; right: 0; bottom: 0; pointer-events: none; width: 100%; height: calc(100% - 25px);"></div>
           </div>
           <div id="view-decompiler" style="border: 1px solid rgba(255,255,255,0.1); border-radius: 4px; flex: 1; height: 100%; margin: 5px; background: rgba(255, 255, 255, 0.02); position: relative; display: flex; flex-direction: column; align-items: center;">
              <div style="font-size: 0.75rem; font-weight: bold; color: var(--text-muted, #94a3b8); margin-top: 5px; pointer-events: none;">Decompiler</div>
              <div class="cursors-area" style="position: absolute; top: 25px; left: 0; right: 0; bottom: 0; pointer-events: none; width: 100%; height: calc(100% - 25px);"></div>
           </div>
           <div id="view-hex" style="border: 1px solid rgba(255,255,255,0.1); border-radius: 4px; flex: 1; height: 100%; margin: 5px; background: rgba(255, 255, 255, 0.02); position: relative; display: flex; flex-direction: column; align-items: center;">
              <div style="font-size: 0.75rem; font-weight: bold; color: var(--text-muted, #94a3b8); margin-top: 5px; pointer-events: none;">Hex Viewer</div>
              <div class="cursors-area" style="position: absolute; top: 25px; left: 0; right: 0; bottom: 0; pointer-events: none; width: 100%; height: calc(100% - 25px);"></div>
           </div>
        </div>
      </div>
    `;
    grid.appendChild(this.activityLogEl);

    this.rootEl.appendChild(grid);
    this.container.appendChild(this.rootEl);

    // Form inputs resolution
    this.actionCommentAddrInput = this.rootEl.querySelector(
      '#collab-comment-addr'
    ) as HTMLInputElement;
    this.actionCommentTextInput = this.rootEl.querySelector(
      '#collab-comment-text'
    ) as HTMLInputElement;
    this.actionHighlightAddrInput = this.rootEl.querySelector(
      '#collab-highlight-addr'
    ) as HTMLInputElement;
    this.actionHighlightColorSelect = this.rootEl.querySelector(
      '#collab-highlight-color'
    ) as HTMLSelectElement;
    this.actionRenameOldInput = this.rootEl.querySelector(
      '#collab-rename-old'
    ) as HTMLInputElement;
    this.actionRenameNewInput = this.rootEl.querySelector(
      '#collab-rename-new'
    ) as HTMLInputElement;
    this.actionRenameTypeSelect = this.rootEl.querySelector(
      '#collab-rename-type'
    ) as HTMLSelectElement;
    this.actionCursorAddrInput = this.rootEl.querySelector(
      '#collab-cursor-addr'
    ) as HTMLInputElement;
    this.actionCursorViewSelect = this.rootEl.querySelector(
      '#collab-cursor-view'
    ) as HTMLSelectElement;
  }

  private setupSubscriptions(): void {
    // Connection state
    this.unsubscribes.push(
      this.engine.subscribeConnectionState((connected) => {
        this.updateUIState();
        const badge = this.rootEl.querySelector(
          '#collab-status-badge'
        ) as HTMLElement;
        if (badge) {
          if (connected) {
            badge.style.color = '#10B981';
            badge.textContent = `Online - ${this.engine.getRoomName()}`;
          } else {
            badge.style.color = '#EF4444';
            badge.textContent = 'Offline';
          }
        }
      })
    );

    // Peer updates
    this.unsubscribes.push(
      this.engine.subscribePeers((peers) => {
        this.renderPeers(peers);
        this.drawCursorsOnScreen();
      })
    );

    // Comments syncing
    this.unsubscribes.push(
      this.engine.subscribeComment((data) => {
        // Real-time update of typing area if we are currently looking at the same address,
        // but only if the change came from a remote peer, preserving selection range.
        const addrStr = this.actionCommentAddrInput.value.trim();
        const currentAddr = parseInt(addrStr, 16) || parseInt(addrStr, 10);
        if (
          data.address === currentAddr &&
          data.peerName !== this.engine.getUsername()
        ) {
          const input = this.actionCommentTextInput;
          const selectionStart = input.selectionStart;
          const selectionEnd = input.selectionEnd;
          const oldLen = input.value.length;

          input.value = data.comment;

          const diff = data.comment.length - oldLen;
          if (selectionStart !== null && selectionEnd !== null) {
            input.setSelectionRange(selectionStart + diff, selectionEnd + diff);
          }
        }

        this.appendActivity(
          'comment',
          `Added comment at <a class="collab-address-link" data-addr="${data.address}">0x${data.address.toString(16)}</a>: "${data.comment}"`,
          data.peerName
        );
        if (this.options.onCommentSynced) {
          this.options.onCommentSynced(data.address, data.comment);
        }
      })
    );

    // Highlights syncing
    this.unsubscribes.push(
      this.engine.subscribeHighlight((data) => {
        this.appendActivity(
          'highlight',
          `Highlighted address <a class="collab-address-link" data-addr="${data.address}">0x${data.address.toString(16)}</a> with color <span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:${data.color};"></span>`,
          data.peerName
        );
        if (this.options.onHighlightSynced) {
          this.options.onHighlightSynced(data.address, data.color);
        }
      })
    );

    // Renames syncing
    this.unsubscribes.push(
      this.engine.subscribeRename((data) => {
        const itemType = data.type === 'function' ? 'function' : 'variable';
        this.appendActivity(
          'rename',
          `Renamed ${itemType} <span style="font-family:monospace;color:#F59E0B;">${data.originalName}</span> to <span style="font-family:monospace;color:#10B981;font-weight:bold;">${data.renamedName}</span>`,
          data.peerName
        );
        if (this.options.onRenameSynced) {
          this.options.onRenameSynced(
            data.originalName,
            data.renamedName,
            data.type
          );
        }
      })
    );

    // Cursors syncing
    this.unsubscribes.push(
      this.engine.subscribeCursor((data) => {
        this.drawCursorsOnScreen();
        if (this.options.onCursorSynced) {
          this.options.onCursorSynced(data.address, data.view);
        }
      })
    );
  }

  private setupEvents(): void {
    // Address link clicks in Activity Log
    const listEl = this.rootEl.querySelector(
      '#collab-activity-list'
    ) as HTMLDivElement;
    if (listEl) {
      listEl.addEventListener('click', (e) => {
        const target = e.target as HTMLElement;
        if (target.classList.contains('collab-address-link')) {
          const addr = parseInt(target.getAttribute('data-addr') || '0', 10);
          if (addr) {
            this.options.onNavigate('assembly', addr);
          }
        }
      });
    }

    // Real-time input synchronizer
    const commentTextInput = this.rootEl.querySelector(
      '#collab-comment-text'
    ) as HTMLInputElement;
    if (commentTextInput) {
      commentTextInput.addEventListener('input', () => {
        if (!this.engine.isConnected()) return;
        const addrStr = this.actionCommentAddrInput.value.trim();
        const comment = commentTextInput.value;
        if (!addrStr) return;
        const addr = parseInt(addrStr, 16) || parseInt(addrStr, 10);
        if (isNaN(addr)) return;
        this.engine.sendComment(addr, comment);
      });
    }

    // Local action button: Comment
    const sendCommentBtn = this.rootEl.querySelector(
      '#collab-btn-send-comment'
    ) as HTMLButtonElement;
    if (sendCommentBtn) {
      sendCommentBtn.addEventListener('click', () => {
        if (!this.engine.isConnected()) {
          alert('Connect to a collaboration session first.');
          return;
        }
        const addrStr = this.actionCommentAddrInput.value.trim();
        const comment = this.actionCommentTextInput.value.trim();
        if (!addrStr || !comment) return;
        const addr = parseInt(addrStr, 16) || parseInt(addrStr, 10);
        if (isNaN(addr)) {
          alert('Invalid address format');
          return;
        }
        this.engine.sendComment(addr, comment);
        this.actionCommentAddrInput.value = '';
        this.actionCommentTextInput.value = '';
      });
    }

    // Local action button: Highlight
    const sendHighlightBtn = this.rootEl.querySelector(
      '#collab-btn-send-highlight'
    ) as HTMLButtonElement;
    if (sendHighlightBtn) {
      sendHighlightBtn.addEventListener('click', () => {
        if (!this.engine.isConnected()) {
          alert('Connect to a collaboration session first.');
          return;
        }
        const addrStr = this.actionHighlightAddrInput.value.trim();
        const color = this.actionHighlightColorSelect.value;
        if (!addrStr) return;
        const addr = parseInt(addrStr, 16) || parseInt(addrStr, 10);
        if (isNaN(addr)) {
          alert('Invalid address format');
          return;
        }
        this.engine.sendHighlight(addr, color);
        this.actionHighlightAddrInput.value = '';
      });
    }

    // Local action button: Rename
    const sendRenameBtn = this.rootEl.querySelector(
      '#collab-btn-send-rename'
    ) as HTMLButtonElement;
    if (sendRenameBtn) {
      sendRenameBtn.addEventListener('click', () => {
        if (!this.engine.isConnected()) {
          alert('Connect to a collaboration session first.');
          return;
        }
        const oldName = this.actionRenameOldInput.value.trim();
        const newName = this.actionRenameNewInput.value.trim();
        const type = this.actionRenameTypeSelect.value as
          | 'function'
          | 'variable';
        if (!oldName || !newName) return;
        this.engine.sendRename(oldName, newName, type);
        this.actionRenameOldInput.value = '';
        this.actionRenameNewInput.value = '';
      });
    }

    // Local action button: Cursor
    const sendCursorBtn = this.rootEl.querySelector(
      '#collab-btn-send-cursor'
    ) as HTMLButtonElement;
    if (sendCursorBtn) {
      sendCursorBtn.addEventListener('click', () => {
        if (!this.engine.isConnected()) {
          alert('Connect to a collaboration session first.');
          return;
        }
        const addrStr = this.actionCursorAddrInput.value.trim();
        const view = this.actionCursorViewSelect.value as
          | 'assembly'
          | 'hex'
          | 'decompiler';
        if (!addrStr) return;
        const addr = parseInt(addrStr, 16) || parseInt(addrStr, 10);
        if (isNaN(addr)) {
          alert('Invalid address format');
          return;
        }
        this.engine.sendCursor(addr, view);
        this.actionCursorAddrInput.value = '';
      });
    }

    // Action button: Simulate Peer Action
    const simulateBtn = this.rootEl.querySelector(
      '#collab-btn-simulate'
    ) as HTMLButtonElement;
    if (simulateBtn) {
      simulateBtn.addEventListener('click', () => {
        if (!this.engine.isConnected()) {
          alert('Connect to a collaboration session first.');
          return;
        }
        this.engine.simulateRemoteAction();
      });
    }
  }

  private updateUIState(): void {
    const isConnected = this.engine.isConnected();
    if (!isConnected) {
      this.connectionContainer.innerHTML = `
        <div class="collab-card-title">Join Collaborative Room</div>
        <div class="collab-input-group">
          <label class="collab-label" for="collab-username">Username</label>
          <input type="text" id="collab-username" class="collab-input" placeholder="User_${Math.floor(Math.random() * 9000 + 1000)}" value="SecExplorer">
        </div>
        <div class="collab-input-group">
          <label class="collab-label" for="collab-room">Room / Session Name</label>
          <input type="text" id="collab-room" class="collab-input" placeholder="patch-analysis-v2" value="shared-re-room">
        </div>
        <button id="collab-btn-connect" class="collab-btn" style="margin-top: 0.5rem;">🔗 Connect Room</button>
      `;

      // Setup connects events
      this.usernameInput = this.connectionContainer.querySelector(
        '#collab-username'
      ) as HTMLInputElement;
      this.roomInput = this.connectionContainer.querySelector(
        '#collab-room'
      ) as HTMLInputElement;
      this.connectBtn = this.connectionContainer.querySelector(
        '#collab-btn-connect'
      ) as HTMLButtonElement;

      this.connectBtn.addEventListener('click', () => {
        const username = this.usernameInput.value.trim();
        const room = this.roomInput.value.trim();
        if (!room) {
          alert('Room Name cannot be empty.');
          return;
        }
        this.engine.connect(room, username);
      });

      this.peersListEl.innerHTML = `
        <div style="font-size: 0.8rem; color: var(--text-muted, #94a3b8); text-align: center; padding: 1rem 0;">
          Offline. Connect to view peer workspace cursors.
        </div>
      `;
    } else {
      this.connectionContainer.innerHTML = `
        <div class="collab-card-title">Room Connection</div>
        <div style="display:flex; flex-direction:column; gap:0.25rem;">
          <div style="font-size: 0.85rem; color: var(--text-primary, #ffffff); font-weight:600;">Room: ${this.engine.getRoomName()}</div>
          <div style="font-size: 0.8rem; color: var(--text-muted, #94a3b8);">Alias: ${this.engine.getUsername()}</div>
        </div>
        <button id="collab-btn-disconnect" class="collab-btn collab-btn-secondary" style="margin-top: 0.5rem;">🔌 Leave Room</button>
      `;

      const disconnectBtn = this.connectionContainer.querySelector(
        '#collab-btn-disconnect'
      ) as HTMLButtonElement;
      disconnectBtn.addEventListener('click', () => {
        this.engine.disconnect();
      });
    }
  }

  private renderPeers(peers: Peer[]): void {
    if (!this.engine.isConnected()) return;
    this.peersListEl.innerHTML = '';

    if (peers.length === 0) {
      this.peersListEl.innerHTML = `
        <div style="font-size: 0.8rem; color: var(--text-muted, #94a3b8); text-align: center; padding: 0.5rem 0;">
          No other peers in room
        </div>
      `;
      return;
    }

    peers.forEach((peer) => {
      const row = document.createElement('div');
      row.className = 'collab-peer-row';
      row.innerHTML = `
        <div class="collab-peer-info">
          <div class="collab-peer-avatar" style="background: ${peer.color};"></div>
          <span class="collab-peer-name">${peer.name}</span>
        </div>
        <span class="collab-peer-status ${peer.status}">${peer.status}</span>
      `;
      this.peersListEl.appendChild(row);
    });
  }

  private drawCursorsOnScreen(): void {
    // Clear all cursor areas first
    const areas = this.rootEl.querySelectorAll('.cursors-area');
    areas.forEach((area) => (area.innerHTML = ''));

    // Get cursors from the engine
    const activeCursors = this.engine.getCursors();

    activeCursors.forEach((cursor) => {
      // Find the appropriate cursor area for the view
      const viewId =
        cursor.view === 'hex'
          ? 'view-hex'
          : cursor.view === 'decompiler'
            ? 'view-decompiler'
            : 'view-assembly';
      const area = this.rootEl.querySelector(`#${viewId} .cursors-area`);
      if (!area) return;

      const cursorEl = document.createElement('div');
      cursorEl.className = 'remote-cursor';
      // Compute coordinates based on the address
      const x = 10 + (cursor.address % 60);
      const y = 10 + ((cursor.address >> 4) % 60);

      cursorEl.style.cssText = `
        position: absolute;
        left: ${x}%;
        top: ${y}%;
        display: flex;
        flex-direction: column;
        align-items: flex-start;
        z-index: 100;
        cursor: pointer;
        pointer-events: auto;
      `;

      cursorEl.innerHTML = `
        <div style="width: 2px; height: 14px; background-color: ${cursor.color};"></div>
        <div style="background-color: ${cursor.color}; color: white; font-size: 9px; font-weight: bold; padding: 1px 4px; border-radius: 2px; white-space: nowrap; margin-top: -2px;">
          ${cursor.peerName} (0x${cursor.address.toString(16)})
        </div>
      `;

      cursorEl.addEventListener('click', (e) => {
        e.stopPropagation();
        this.options.onNavigate(cursor.view, cursor.address);
      });

      area.appendChild(cursorEl);
    });
  }

  /**
   * Updates the local peer's cursor and broadcasts it to all other peers.
   */
  public updateLocalCursor(address: number, view: 'assembly' | 'hex' | 'decompiler'): void {
    if (this.engine && this.engine.isConnected()) {
      this.engine.sendCursor(address, view);
    }
  }

  private appendActivity(
    type: 'comment' | 'highlight' | 'rename',
    content: string,
    peerName: string
  ): void {
    const list = this.rootEl.querySelector(
      '#collab-activity-list'
    ) as HTMLDivElement;
    if (!list) return;

    const item = document.createElement('div');
    item.className = 'collab-activity-item';

    // Left border accent color match
    let color = '#6366F1';
    let badgeType = 'badge-comment';
    if (type === 'highlight') {
      color = '#10B981';
      badgeType = 'badge-highlight';
    } else if (type === 'rename') {
      color = '#F59E0B';
      badgeType = 'badge-rename';
    }

    item.style.borderLeftColor = color;

    const timeStr = new Date().toLocaleTimeString();

    item.innerHTML = `
      <div class="collab-activity-meta">
        <div>
          <span class="collab-badge ${badgeType}">${type}</span>
          <span class="collab-activity-peer">${peerName}</span>
        </div>
        <div>${timeStr}</div>
      </div>
      <div class="collab-activity-content">${content}</div>
    `;

    // Limit to top 50 logs and prepend to top
    if (list.firstChild) {
      list.insertBefore(item, list.firstChild);
    } else {
      list.appendChild(item);
    }

    while (list.children.length > 50) {
      list.removeChild(list.lastChild!);
    }
  }
}
