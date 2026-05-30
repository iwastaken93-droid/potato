/**
 * Collaborative Workspace Sync engine.
 * Supports mock WebRTC/WebSocket sync of session comments, highlighted addresses, and decompilation renames.
 * Implements a real-time conflict-free replicated data type (CRDT) system:
 * - Yjs-like sequence CRDT for collaborative comment text.
 * - LWW-Register (Last-Write-Wins) for highlights and renames.
 * Supports configurable simulated latency and multi-client synchronization.
 */

export interface Peer {
  id: string;
  name: string;
  color: string;
  status: 'connected' | 'idle' | 'disconnected';
}

export interface SyncComment {
  address: number;
  comment: string;
  peerName: string;
  timestamp: number;
}

export interface SyncHighlight {
  address: number;
  color: string;
  peerName: string;
  timestamp: number;
}

export interface SyncRename {
  originalName: string;
  renamedName: string;
  type: 'function' | 'variable';
  peerName: string;
  timestamp: number;
}

type ConnectionStateCallback = (connected: boolean) => void;
type PeerCallback = (peers: Peer[]) => void;
type CommentCallback = (data: SyncComment) => void;
type HighlightCallback = (data: SyncHighlight) => void;
type RenameCallback = (data: SyncRename) => void;

// Simple diff utility to identify edits between two strings
export function computeStringDiff(
  oldStr: string,
  newStr: string
): Array<{ type: 'insert' | 'delete'; index: number; text: string }> {
  let start = 0;
  while (
    start < oldStr.length &&
    start < newStr.length &&
    oldStr[start] === newStr[start]
  ) {
    start++;
  }
  let oldEnd = oldStr.length;
  let newEnd = newStr.length;
  while (
    oldEnd > start &&
    newEnd > start &&
    oldStr[oldEnd - 1] === newStr[newEnd - 1]
  ) {
    oldEnd--;
    newEnd--;
  }

  const ops: Array<{ type: 'insert' | 'delete'; index: number; text: string }> =
    [];
  if (oldEnd > start) {
    ops.push({
      type: 'delete',
      index: start,
      text: oldStr.substring(start, oldEnd),
    });
  }
  if (newEnd > start) {
    ops.push({
      type: 'insert',
      index: start,
      text: newStr.substring(start, newEnd),
    });
  }
  return ops;
}

// Yjs-like sequence CRDT for collaborative text editing
export class MockYText {
  private items: Array<{
    id: string;
    char: string;
    origin: string | null;
    deleted: boolean;
  }> = [];

  constructor() {}

  public insert(
    index: number,
    char: string,
    client: string,
    clock: number
  ): { id: string; origin: string | null } {
    let origin: string | null = null;
    let visibleCount = 0;
    let insertPos = 0;

    for (let i = 0; i < this.items.length; i++) {
      if (!this.items[i].deleted) {
        if (visibleCount === index) {
          break;
        }
        visibleCount++;
      }
      insertPos++;
    }

    if (insertPos > 0) {
      origin = this.items[insertPos - 1].id;
    }

    const id = `${client}:${clock}`;
    this.applyInsert(id, char, origin);
    return { id, origin };
  }

  public delete(index: number): string {
    let visibleCount = 0;
    for (let i = 0; i < this.items.length; i++) {
      if (!this.items[i].deleted) {
        if (visibleCount === index) {
          this.items[i].deleted = true;
          return this.items[i].id;
        }
        visibleCount++;
      }
    }
    return '';
  }

  public applyInsert(id: string, char: string, origin: string | null): boolean {
    if (this.items.some((item) => item.id === id)) return false;

    let insertPos = 0;
    if (origin !== null) {
      const idx = this.items.findIndex((item) => item.id === origin);
      if (idx !== -1) {
        insertPos = idx + 1;
      } else {
        insertPos = this.items.length;
      }
    }

    while (
      insertPos < this.items.length &&
      this.items[insertPos].origin === origin
    ) {
      if (this.items[insertPos].id < id) {
        break;
      }
      insertPos++;
    }

    this.items.splice(insertPos, 0, { id, char, origin, deleted: false });
    return true;
  }

  public applyDelete(id: string): boolean {
    const item = this.items.find((item) => item.id === id);
    if (item && !item.deleted) {
      item.deleted = true;
      return true;
    }
    return false;
  }

  public toString(): string {
    return this.items
      .filter((item) => !item.deleted)
      .map((item) => item.char)
      .join('');
  }

  public getItems() {
    return [...this.items];
  }

  public merge(otherItems: Array<{ id: string; char: string; origin: string | null; deleted: boolean }>): void {
    for (const item of otherItems) {
      this.applyInsert(item.id, item.char, item.origin);
      if (item.deleted) {
        this.applyDelete(item.id);
      }
    }
  }
}

// Global network broker simulating message passing between CollabEngines with latency
export class MockNetworkBroker {
  private static rooms: Map<string, Set<CollabEngine>> = new Map();

  public static join(room: string, engine: CollabEngine): void {
    if (!this.rooms.has(room)) {
      this.rooms.set(room, new Set());
    }
    this.rooms.get(room)!.add(engine);
  }

  public static leave(room: string, engine: CollabEngine): void {
    const set = this.rooms.get(room);
    if (set) {
      set.delete(engine);
      if (set.size === 0) {
        this.rooms.delete(room);
      }
    }
  }

  public static broadcast(
    room: string,
    sender: CollabEngine,
    message: any,
    latencyMs: number = 0
  ): void {
    const peers = this.rooms.get(room);
    if (!peers) return;

    for (const peer of peers) {
      if (peer === sender) continue;

      if (latencyMs > 0) {
        setTimeout(() => {
          if (peer.isConnected() && peer.getRoomName() === room) {
            peer.receiveMessage(message);
          }
        }, latencyMs);
      } else {
        peer.receiveMessage(message);
      }
    }
  }
}

export class CollabEngine {
  private connected: boolean = false;
  private roomName: string = '';
  private username: string = '';
  private peers: Peer[] = [];

  // CRDT states
  private commentTexts: Map<number, MockYText> = new Map();
  private commentMetadata: Map<
    number,
    { peerName: string; timestamp: number }
  > = new Map();

  private highlights: Map<
    number,
    SyncHighlight & { clock: number; client: string }
  > = new Map();
  private renames: Map<string, SyncRename & { clock: number; client: string }> =
    new Map();

  private lamportClock: number = 0;
  private latencyMs: number = 0;

  // WebSocket fields
  private ws: any = null;
  private wsUrl: string = '';
  private reconnectTimeout: any = null;
  private messageQueue: any[] = [];
  private reconnectAttempts: number = 0;

  // Callbacks
  private onConnectionStateCallbacks: Set<ConnectionStateCallback> = new Set();
  private onPeerCallbacks: Set<PeerCallback> = new Set();
  private onCommentCallbacks: Set<CommentCallback> = new Set();
  private onHighlightCallbacks: Set<HighlightCallback> = new Set();
  private onRenameCallbacks: Set<RenameCallback> = new Set();

  private simulationInterval: any = null;

  constructor() {}

  public isConnected(): boolean {
    return this.connected;
  }

  public getRoomName(): string {
    return this.roomName;
  }

  public getUsername(): string {
    return this.username;
  }

  public getPeers(): Peer[] {
    return [...this.peers];
  }

  public setLatency(ms: number): void {
    this.latencyMs = ms;
  }

  public getLatency(): number {
    return this.latencyMs;
  }

  public getComments(): Map<number, SyncComment> {
    const result = new Map<number, SyncComment>();
    for (const [address, ytext] of this.commentTexts.entries()) {
      const meta = this.commentMetadata.get(address) || {
        peerName: 'System',
        timestamp: Date.now(),
      };
      result.set(address, {
        address,
        comment: ytext.toString(),
        peerName: meta.peerName,
        timestamp: meta.timestamp,
      });
    }
    return result;
  }

  public getHighlights(): Map<number, SyncHighlight> {
    const result = new Map<number, SyncHighlight>();
    for (const [address, data] of this.highlights.entries()) {
      result.set(address, {
        address: data.address,
        color: data.color,
        peerName: data.peerName,
        timestamp: data.timestamp,
      });
    }
    return result;
  }

  public getRenames(): Map<string, SyncRename> {
    const result = new Map<string, SyncRename>();
    for (const [originalName, data] of this.renames.entries()) {
      result.set(originalName, {
        originalName: data.originalName,
        renamedName: data.renamedName,
        type: data.type,
        peerName: data.peerName,
        timestamp: data.timestamp,
      });
    }
    return result;
  }

  // Event subscription
  public subscribeConnectionState(cb: ConnectionStateCallback): () => void {
    this.onConnectionStateCallbacks.add(cb);
    return () => this.onConnectionStateCallbacks.delete(cb);
  }

  public subscribePeers(cb: PeerCallback): () => void {
    this.onPeerCallbacks.add(cb);
    return () => this.onPeerCallbacks.delete(cb);
  }

  public subscribeComment(cb: CommentCallback): () => void {
    this.onCommentCallbacks.add(cb);
    return () => this.onCommentCallbacks.delete(cb);
  }

  public subscribeHighlight(cb: HighlightCallback): () => void {
    this.onHighlightCallbacks.add(cb);
    return () => this.onHighlightCallbacks.delete(cb);
  }

  public subscribeRename(cb: RenameCallback): () => void {
    this.onRenameCallbacks.add(cb);
    return () => this.onRenameCallbacks.delete(cb);
  }

  /**
   * Get full serialized state of all CRDT structures.
   */
  public getFullState() {
    const serializedComments: Array<{ address: number; items: any[] }> = [];
    for (const [address, ytext] of this.commentTexts.entries()) {
      serializedComments.push({ address, items: ytext.getItems() });
    }
    const serializedHighlights = Array.from(this.highlights.entries());
    const serializedRenames = Array.from(this.renames.entries());
    return {
      comments: serializedComments,
      highlights: serializedHighlights,
      renames: serializedRenames,
      lamportClock: this.lamportClock,
    };
  }

  /**
   * Merge external full CRDT state structure.
   */
  public mergeState(state: any): void {
    if (!state) return;
    if (state.lamportClock && state.lamportClock > this.lamportClock) {
      this.lamportClock = state.lamportClock;
    }
    if (state.comments) {
      for (const entry of state.comments) {
        if (!this.commentTexts.has(entry.address)) {
          this.commentTexts.set(entry.address, new MockYText());
        }
        const ytext = this.commentTexts.get(entry.address)!;
        ytext.merge(entry.items);
        this.notifyComment({
          address: entry.address,
          comment: ytext.toString(),
          peerName: 'System Sync',
          timestamp: Date.now(),
        });
      }
    }
    if (state.highlights) {
      for (const [address, stateData] of state.highlights) {
        const current = this.highlights.get(address);
        const isNewer =
          !current ||
          stateData.clock > current.clock ||
          (stateData.clock === current.clock && stateData.client > current.client);

        if (isNewer) {
          this.highlights.set(address, stateData);
          this.notifyHighlight(stateData);
        }
      }
    }
    if (state.renames) {
      for (const [originalName, stateData] of state.renames) {
        const current = this.renames.get(originalName);
        const isNewer =
          !current ||
          stateData.clock > current.clock ||
          (stateData.clock === current.clock && stateData.client > current.client);

        if (isNewer) {
          this.renames.set(originalName, stateData);
          this.notifyRename(stateData);
        }
      }
    }
  }

  /**
   * Connect to collaborative room (optionally using real WebSocket).
   */
  public connect(room: string, username: string, wsUrl?: string): void {
    if (this.connected) return;

    this.roomName = room;
    this.username = username || 'ReverseEngineer';
    this.connected = true;

    // Set up initial peers
    this.peers = [
      { id: 'p1', name: 'Alice_SEC', color: '#10B981', status: 'connected' },
      { id: 'p2', name: 'Bob_Fuzz', color: '#3B82F6', status: 'connected' },
      { id: 'p3', name: 'Charlie_Mal', color: '#F59E0B', status: 'idle' },
    ];

    MockNetworkBroker.join(room, this);

    this.notifyConnectionState();
    this.notifyPeers();

    const actualWsUrl = wsUrl || (typeof window !== 'undefined' && (window as any).collabWebSocketUrl);

    if (actualWsUrl && typeof WebSocket !== 'undefined') {
      this.wsUrl = actualWsUrl;
      this.connectWebSocket();
    } else {
      // Broadcast join to other active clients via mock broker
      MockNetworkBroker.broadcast(
        this.roomName,
        this,
        {
          type: 'peer_join',
          peer: {
            id: this.username,
            name: this.username,
            color: '#8B5CF6',
            status: 'connected',
          },
        },
        this.latencyMs
      );
    }

    this.startSimulation();
  }

  private connectWebSocket(): void {
    if (typeof WebSocket === 'undefined') return;
    if (this.ws) {
      try {
        this.ws.close();
      } catch (e) {}
    }

    const url = `${this.wsUrl}?room=${encodeURIComponent(this.roomName)}&username=${encodeURIComponent(this.username)}`;
    try {
      this.ws = new WebSocket(url);

      this.ws.onopen = () => {
        this.reconnectAttempts = 0;
        
        // Request initial state from other peers
        this.sendWebSocketMessage({
          type: 'request_sync',
          sender: this.username,
        });

        // Send peer join information
        this.sendWebSocketMessage({
          type: 'peer_join',
          peer: {
            id: this.username,
            name: this.username,
            color: '#8B5CF6',
            status: 'connected',
          },
        });

        // Flush offline message queue
        while (this.messageQueue.length > 0) {
          const msg = this.messageQueue.shift();
          this.sendWebSocketMessage(msg);
        }
      };

      this.ws.onmessage = (event: any) => {
        try {
          const msg = JSON.parse(event.data);
          this.receiveWebSocketMessage(msg);
        } catch (e) {
          console.error('Failed to parse websocket message', e);
        }
      };

      this.ws.onclose = () => {
        this.ws = null;
        if (this.connected) {
          const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);
          this.reconnectAttempts++;
          this.reconnectTimeout = setTimeout(() => {
            if (this.connected) this.connectWebSocket();
          }, delay);
        }
      };

      this.ws.onerror = (err: any) => {
        console.error('Collab WebSocket error', err);
      };
    } catch (e) {
      console.error('Failed to create WebSocket connection', e);
    }
  }

  private sendWebSocketMessage(msg: any): void {
    if (this.ws && this.ws.readyState === 1 /* OPEN */) {
      this.ws.send(JSON.stringify(msg));
    } else {
      this.messageQueue.push(msg);
    }
  }

  private receiveWebSocketMessage(msg: any): void {
    if (!this.connected) return;

    if (msg.type === 'request_sync') {
      // Send our current full state to the requester
      this.sendWebSocketMessage({
        type: 'sync_state',
        state: this.getFullState(),
        recipient: msg.sender,
      });
      return;
    }

    if (msg.type === 'sync_state') {
      if (msg.recipient === this.username) {
        this.mergeState(msg.state);
      }
      return;
    }

    this.receiveMessage(msg);
  }

  /**
   * Disconnect from collaboration room.
   */
  public disconnect(): void {
    if (!this.connected) return;

    this.stopSimulation();

    if (this.ws) {
      try {
        this.ws.send(JSON.stringify({
          type: 'peer_leave',
          peerId: this.username,
        }));
        this.ws.close();
      } catch (e) {}
      this.ws = null;
    } else {
      // Broadcast leave via mock broker
      MockNetworkBroker.broadcast(
        this.roomName,
        this,
        {
          type: 'peer_leave',
          peerId: this.username,
        },
        this.latencyMs
      );
    }

    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = null;
    }

    MockNetworkBroker.leave(this.roomName, this);

    this.connected = false;
    this.roomName = '';
    this.username = '';
    this.peers = [];
    this.commentTexts.clear();
    this.commentMetadata.clear();
    this.highlights.clear();
    this.renames.clear();
    this.messageQueue = [];
    this.reconnectAttempts = 0;

    this.notifyConnectionState();
    this.notifyPeers();
  }

  /**
   * Broadcast a comment operation.
   */
  public sendComment(address: number, comment: string): void {
    if (!this.connected) return;

    if (!this.commentTexts.has(address)) {
      this.commentTexts.set(address, new MockYText());
    }

    const ytext = this.commentTexts.get(address)!;
    const oldVal = ytext.toString();
    const diffs = computeStringDiff(oldVal, comment);

    this.commentMetadata.set(address, {
      peerName: this.username,
      timestamp: Date.now(),
    });

    for (const diff of diffs) {
      if (diff.type === 'insert') {
        for (let i = 0; i < diff.text.length; i++) {
          this.lamportClock++;
          const char = diff.text[i];
          const { id, origin } = ytext.insert(
            diff.index + i,
            char,
            this.username,
            this.lamportClock
          );

          const message = {
            type: 'comment_op',
            address,
            op: {
              type: 'insert',
              id,
              char,
              origin,
              peerName: this.username,
              timestamp: Date.now(),
            },
          };

          if (this.ws) {
            this.sendWebSocketMessage(message);
          } else {
            MockNetworkBroker.broadcast(this.roomName, this, message, this.latencyMs);
          }
        }
      } else if (diff.type === 'delete') {
        for (let i = 0; i < diff.text.length; i++) {
          const id = ytext.delete(diff.index);
          if (id) {
            const message = {
              type: 'comment_op',
              address,
              op: {
                type: 'delete',
                id,
                peerName: this.username,
                timestamp: Date.now(),
              },
            };

            if (this.ws) {
              this.sendWebSocketMessage(message);
            } else {
              MockNetworkBroker.broadcast(this.roomName, this, message, this.latencyMs);
            }
          }
        }
      }
    }

    // Trigger local state notification
    this.notifyComment({
      address,
      comment: ytext.toString(),
      peerName: this.username,
      timestamp: Date.now(),
    });
  }

  /**
   * Broadcast a highlighted address using LWW-Register strategy.
   */
  public sendHighlight(address: number, color: string): void {
    if (!this.connected) return;

    this.lamportClock++;
    const state = {
      address,
      color,
      peerName: this.username,
      timestamp: Date.now(),
      clock: this.lamportClock,
      client: this.username,
    };

    this.highlights.set(address, state);
    this.notifyHighlight(state);

    const message = {
      type: 'highlight_op',
      state,
    };

    if (this.ws) {
      this.sendWebSocketMessage(message);
    } else {
      MockNetworkBroker.broadcast(this.roomName, this, message, this.latencyMs);
    }
  }

  /**
   * Broadcast a decompilation rename using LWW-Register strategy.
   */
  public sendRename(
    originalName: string,
    renamedName: string,
    type: 'function' | 'variable'
  ): void {
    if (!this.connected) return;

    this.lamportClock++;
    const state = {
      originalName,
      renamedName,
      type,
      peerName: this.username,
      timestamp: Date.now(),
      clock: this.lamportClock,
      client: this.username,
    };

    this.renames.set(originalName, state);
    this.notifyRename(state);

    const message = {
      type: 'rename_op',
      state,
    };

    if (this.ws) {
      this.sendWebSocketMessage(message);
    } else {
      MockNetworkBroker.broadcast(this.roomName, this, message, this.latencyMs);
    }
  }

  /**
   * Receive and process a message from another peer.
   */
  public receiveMessage(msg: any): void {
    if (!this.connected) return;

    switch (msg.type) {
      case 'peer_join': {
        if (!this.peers.some((p) => p.id === msg.peer.id)) {
          this.peers.push(msg.peer);
          this.notifyPeers();
        }
        break;
      }
      case 'peer_leave': {
        this.peers = this.peers.filter((p) => p.id !== msg.peerId);
        this.notifyPeers();
        break;
      }
      case 'comment_op': {
        const { address, op } = msg;
        if (!this.commentTexts.has(address)) {
          this.commentTexts.set(address, new MockYText());
        }
        const ytext = this.commentTexts.get(address)!;

        let changed = false;
        if (op.type === 'insert') {
          changed = ytext.applyInsert(op.id, op.char, op.origin);
        } else if (op.type === 'delete') {
          changed = ytext.applyDelete(op.id);
        }

        if (changed) {
          this.commentMetadata.set(address, {
            peerName: op.peerName,
            timestamp: op.timestamp,
          });
          this.notifyComment({
            address,
            comment: ytext.toString(),
            peerName: op.peerName,
            timestamp: op.timestamp,
          });
        }
        break;
      }
      case 'highlight_op': {
        const { state } = msg;
        const current = this.highlights.get(state.address);

        // LWW logic
        const isNewer =
          !current ||
          state.clock > current.clock ||
          (state.clock === current.clock && state.client > current.client);

        if (isNewer) {
          this.highlights.set(state.address, state);
          this.notifyHighlight(state);
        }
        break;
      }
      case 'rename_op': {
        const { state } = msg;
        const current = this.renames.get(state.originalName);

        // LWW logic
        const isNewer =
          !current ||
          state.clock > current.clock ||
          (state.clock === current.clock && state.client > current.client);

        if (isNewer) {
          this.renames.set(state.originalName, state);
          this.notifyRename(state);
        }
        break;
      }
    }
  }

  /**
   * Simulate a remote peer action explicitly.
   */
  public simulateRemoteAction(): void {
    if (!this.connected) return;

    const actions = [
      'comment',
      'highlight',
      'rename',
      'peer_join',
      'peer_leave',
    ];
    const action = actions[Math.floor(Math.random() * actions.length)];
    const mockPeers = this.peers.filter((p) => p.status === 'connected');
    if (mockPeers.length === 0 && action !== 'peer_join') return;

    const randomPeer = mockPeers[Math.floor(Math.random() * mockPeers.length)];

    switch (action) {
      case 'comment': {
        const addresses = [0x1000, 0x1020, 0x1044, 0x2010];
        const address = addresses[Math.floor(Math.random() * addresses.length)];
        const currentText = this.commentTexts.get(address)?.toString() || '';

        // Append or insert characters simulating key presses
        const phrase = ' verified';
        const targetComment =
          currentText.length > 20 ? 'Loop check' : currentText + phrase;

        this.lamportClock++;
        // Create comment update via operations
        if (!this.commentTexts.has(address)) {
          this.commentTexts.set(address, new MockYText());
        }
        const ytext = this.commentTexts.get(address)!;
        const diffs = computeStringDiff(ytext.toString(), targetComment);

        for (const diff of diffs) {
          if (diff.type === 'insert') {
            for (let i = 0; i < diff.text.length; i++) {
              this.lamportClock++;
              const char = diff.text[i];
              const { id, origin } = ytext.insert(
                diff.index + i,
                char,
                randomPeer.name,
                this.lamportClock
              );

              // Notify local engine of simulated action as if received from network
              this.receiveMessage({
                type: 'comment_op',
                address,
                op: {
                  type: 'insert',
                  id,
                  char,
                  origin,
                  peerName: randomPeer.name,
                  timestamp: Date.now(),
                },
              });
            }
          }
        }
        break;
      }
      case 'highlight': {
        const addresses = [0x1004, 0x1028, 0x1080, 0x2014];
        const colors = ['#EF4444', '#10B981', '#3B82F6', '#F59E0B', '#8B5CF6'];
        const address = addresses[Math.floor(Math.random() * addresses.length)];
        const color = colors[Math.floor(Math.random() * colors.length)];

        this.lamportClock++;
        this.receiveMessage({
          type: 'highlight_op',
          state: {
            address,
            color,
            peerName: randomPeer.name,
            timestamp: Date.now(),
            clock: this.lamportClock,
            client: randomPeer.name,
          },
        });
        break;
      }
      case 'rename': {
        const renames = [
          { oldName: 'sub_1000', newName: 'decrypt_payload', type: 'function' },
          {
            oldName: 'sub_1040',
            newName: 'initialize_socket',
            type: 'function',
          },
          { oldName: 'dword_4020', newName: 'g_is_debugged', type: 'variable' },
        ] as const;
        const rename = renames[Math.floor(Math.random() * renames.length)];

        this.lamportClock++;
        this.receiveMessage({
          type: 'rename_op',
          state: {
            originalName: rename.oldName,
            renamedName: rename.newName,
            type: rename.type,
            peerName: randomPeer.name,
            timestamp: Date.now(),
            clock: this.lamportClock,
            client: randomPeer.name,
          },
        });
        break;
      }
      case 'peer_join': {
        const names = ['Dave_Crypt', 'Eve_Pwn', 'Mallory_Mitm'];
        const unusedName = names.find(
          (n) => !this.peers.some((p) => p.name === n)
        );
        if (unusedName) {
          const newPeer: Peer = {
            id: unusedName,
            name: unusedName,
            color: '#EC4899',
            status: 'connected',
          };
          this.receiveMessage({
            type: 'peer_join',
            peer: newPeer,
          });
        }
        break;
      }
      case 'peer_leave': {
        const removable = this.peers.filter(
          (p) => p.id !== 'p1' && p.id !== 'p2' && p.id !== 'p3'
        );
        if (removable.length > 0) {
          const target =
            removable[Math.floor(Math.random() * removable.length)];
          this.receiveMessage({
            type: 'peer_leave',
            peerId: target.id,
          });
        }
        break;
      }
    }
  }

  private notifyConnectionState(): void {
    for (const cb of this.onConnectionStateCallbacks) {
      try {
        cb(this.connected);
      } catch (e) {
        console.error(e);
      }
    }
  }

  private notifyPeers(): void {
    for (const cb of this.onPeerCallbacks) {
      try {
        cb([...this.peers]);
      } catch (e) {
        console.error(e);
      }
    }
  }

  private notifyComment(data: SyncComment): void {
    for (const cb of this.onCommentCallbacks) {
      try {
        cb(data);
      } catch (e) {
        console.error(e);
      }
    }
  }

  private notifyHighlight(data: SyncHighlight): void {
    for (const cb of this.onHighlightCallbacks) {
      try {
        cb(data);
      } catch (e) {
        console.error(e);
      }
    }
  }

  private notifyRename(data: SyncRename): void {
    for (const cb of this.onRenameCallbacks) {
      try {
        cb(data);
      } catch (e) {
        console.error(e);
      }
    }
  }

  private startSimulation(): void {
    this.stopSimulation();
    this.simulationInterval = setInterval(() => {
      this.simulateRemoteAction();
    }, 15000);
  }

  private stopSimulation(): void {
    if (this.simulationInterval) {
      clearInterval(this.simulationInterval);
      this.simulationInterval = null;
    }
  }
}
