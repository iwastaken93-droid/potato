// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { CollabEngine } from '../src/network/collab.js';
import { CollabPanel } from '../src/ui/collabPanel.js';

describe('CollabEngine & CollabPanel Sync Tests', () => {
  let engine: CollabEngine;

  beforeEach(() => {
    engine = new CollabEngine();
  });

  afterEach(() => {
    engine.disconnect();
  });

  it('should initialize offline and connect to a room', () => {
    expect(engine.isConnected()).toBe(false);
    expect(engine.getRoomName()).toBe('');

    engine.connect('test-room', 'Explorer');
    expect(engine.isConnected()).toBe(true);
    expect(engine.getRoomName()).toBe('test-room');
    expect(engine.getUsername()).toBe('Explorer');
    expect(engine.getPeers().length).toBeGreaterThan(0);
  });

  it('should sync comments and trigger callbacks', () => {
    engine.connect('test-room', 'Explorer');

    const callback = vi.fn();
    engine.subscribeComment(callback);

    engine.sendComment(0x1000, 'Verify decrypt block');

    expect(callback).toHaveBeenCalledTimes(1);
    const mockArg = callback.mock.calls[0][0];
    expect(mockArg.address).toBe(0x1000);
    expect(mockArg.comment).toBe('Verify decrypt block');
    expect(mockArg.peerName).toBe('Explorer');

    const commentsMap = engine.getComments();
    expect(commentsMap.has(0x1000)).toBe(true);
    expect(commentsMap.get(0x1000)?.comment).toBe('Verify decrypt block');
  });

  it('should sync highlights and trigger callbacks', () => {
    engine.connect('test-room', 'Explorer');

    const callback = vi.fn();
    engine.subscribeHighlight(callback);

    engine.sendHighlight(0x2000, '#EF4444');

    expect(callback).toHaveBeenCalledTimes(1);
    const mockArg = callback.mock.calls[0][0];
    expect(mockArg.address).toBe(0x2000);
    expect(mockArg.color).toBe('#EF4444');

    const highlightsMap = engine.getHighlights();
    expect(highlightsMap.get(0x2000)?.color).toBe('#EF4444');
  });

  it('should sync decompilation renames and trigger callbacks', () => {
    engine.connect('test-room', 'Explorer');

    const callback = vi.fn();
    engine.subscribeRename(callback);

    engine.sendRename('sub_1040', 'initialize_network', 'function');

    expect(callback).toHaveBeenCalledTimes(1);
    const mockArg = callback.mock.calls[0][0];
    expect(mockArg.originalName).toBe('sub_1040');
    expect(mockArg.renamedName).toBe('initialize_network');
    expect(mockArg.type).toBe('function');

    const renamesMap = engine.getRenames();
    expect(renamesMap.get('sub_1040')?.renamedName).toBe('initialize_network');
  });

  it('should simulate remote peer actions', () => {
    engine.connect('test-room', 'Explorer');

    const commentCb = vi.fn();
    const highlightCb = vi.fn();
    const renameCb = vi.fn();
    const peersCb = vi.fn();

    engine.subscribeComment(commentCb);
    engine.subscribeHighlight(highlightCb);
    engine.subscribeRename(renameCb);
    engine.subscribePeers(peersCb);

    // Call simulation multiple times to cover different branch options
    for (let i = 0; i < 20; i++) {
      engine.simulateRemoteAction();
    }

    // At least some callbacks should have been invoked
    const totalCalls =
      commentCb.mock.calls.length +
      highlightCb.mock.calls.length +
      renameCb.mock.calls.length +
      peersCb.mock.calls.length;

    expect(totalCalls).toBeGreaterThan(0);
  });

  it('should disconnect cleanly', () => {
    engine.connect('test-room', 'Explorer');
    engine.disconnect();

    expect(engine.isConnected()).toBe(false);
    expect(engine.getRoomName()).toBe('');
    expect(engine.getPeers().length).toBe(0);
    expect(engine.getComments().size).toBe(0);
  });

  it('should resolve conflicts from simultaneous edits on highlights using LWW-Register', async () => {
    const peerA = new CollabEngine();
    const peerB = new CollabEngine();

    peerA.connect('sync-room', 'Alice');
    peerB.connect('sync-room', 'Bob');

    // Simulate latency of 50ms
    peerA.setLatency(50);
    peerB.setLatency(50);

    // Concurrent highlights on the same address
    peerA.sendHighlight(0x3000, '#3B82F6'); // Blue
    peerB.sendHighlight(0x3000, '#EF4444'); // Red

    // Wait for latency delivery (50ms + margin)
    await new Promise((resolve) => setTimeout(resolve, 150));

    const colorA = peerA.getHighlights().get(0x3000)?.color;
    const colorB = peerB.getHighlights().get(0x3000)?.color;

    // Both must have converged on the exact same color
    expect(colorA).toBe(colorB);

    peerA.disconnect();
    peerB.disconnect();
  });

  it('should resolve concurrent text insertions in comments using Yjs-like sequence CRDT', async () => {
    const peerA = new CollabEngine();
    const peerB = new CollabEngine();

    peerA.connect('text-room', 'Alice');
    peerB.connect('text-room', 'Bob');

    // Sync initial comment
    peerA.sendComment(0x4000, 'BaseText');
    await new Promise((resolve) => setTimeout(resolve, 50));

    // Ensure peerB has the initial state
    expect(peerB.getComments().get(0x4000)?.comment).toBe('BaseText');

    // Set latency
    peerA.setLatency(100);
    peerB.setLatency(100);

    // Alice inserts 'A' at index 0 ('ABaseText')
    peerA.sendComment(0x4000, 'ABaseText');

    // Bob inserts 'B' at index 0 ('BBaseText') concurrently
    peerB.sendComment(0x4000, 'BBaseText');

    // Wait for sync (100ms latency + margin)
    await new Promise((resolve) => setTimeout(resolve, 250));

    const commentA = peerA.getComments().get(0x4000)?.comment;
    const commentB = peerB.getComments().get(0x4000)?.comment;

    // Both must converge to the same merged string (either 'ABBaseText' or 'BABaseText')
    expect(commentA).toBe(commentB);
    expect(commentA).toContain('A');
    expect(commentA).toContain('B');
    expect(commentA).toContain('BaseText');
    expect(commentA?.length).toBe(10); // 'BaseText' (8) + 'A' (1) + 'B' (1)

    peerA.disconnect();
    peerB.disconnect();
  });
});

describe('CollabPanel DOM Tests', () => {
  let container: HTMLDivElement;
  let panel: CollabPanel;
  const mockNavigate = vi.fn();

  beforeEach(() => {
    container = document.createElement('div');
    document.body.appendChild(container);
    panel = new CollabPanel(container, {
      onNavigate: mockNavigate,
    });
  });

  afterEach(() => {
    panel.destroy();
    container.remove();
  });

  it('should render the collab panel layout structure', () => {
    const root = container.querySelector('.collab-panel-root');
    expect(root).toBeTruthy();

    const title = container.querySelector('.collab-title');
    expect(title?.textContent).toBe('Collaborative Sync Workspace');

    // Offline connection panel is rendered by default
    const usernameInput = container.querySelector('#collab-username');
    expect(usernameInput).toBeTruthy();
  });

  it('should allow joining a room from the UI', () => {
    const usernameInput = container.querySelector(
      '#collab-username'
    ) as HTMLInputElement;
    const roomInput = container.querySelector(
      '#collab-room'
    ) as HTMLInputElement;
    const connectBtn = container.querySelector(
      '#collab-btn-connect'
    ) as HTMLButtonElement;

    usernameInput.value = 'TestExplorer';
    roomInput.value = 'test-room';
    connectBtn.click();

    // Verify UI updated to room connection info
    const disconnectBtn = container.querySelector('#collab-btn-disconnect');
    expect(disconnectBtn).toBeTruthy();
  });
});

describe('CollabEngine WebSocket Sync Tests', () => {
  let originalWebSocket: any;
  let mockWebSocketInstance: any = null;
  let mockWebSocketConstructor: any;
  let sentMessages: any[] = [];

  beforeEach(() => {
    originalWebSocket = (globalThis as any).WebSocket;
    sentMessages = [];
    mockWebSocketConstructor = vi.fn().mockImplementation(function (url: string) {
      this.url = url;
      this.readyState = 0; // CONNECTING
      this.send = vi.fn().mockImplementation((data: string) => {
        sentMessages.push(JSON.parse(data));
      });
      this.close = vi.fn();
      mockWebSocketInstance = this;
      return this;
    });
    (globalThis as any).WebSocket = mockWebSocketConstructor;
  });

  afterEach(() => {
    (globalThis as any).WebSocket = originalWebSocket;
  });

  it('should connect using real WebSocket when wsUrl is provided and trigger request_sync', () => {
    const engine = new CollabEngine();
    engine.connect('sync-room', 'Alice', 'ws://localhost:8080/collab');

    expect(mockWebSocketConstructor).toHaveBeenCalledWith(
      'ws://localhost:8080/collab?room=sync-room&username=Alice'
    );
    expect(mockWebSocketInstance).toBeTruthy();

    // Simulate connection open
    mockWebSocketInstance.readyState = 1; // OPEN
    mockWebSocketInstance.onopen();

    // Check request_sync was sent
    expect(sentMessages).toContainEqual({
      type: 'request_sync',
      sender: 'Alice',
    });
    expect(sentMessages).toContainEqual({
      type: 'peer_join',
      peer: {
        id: 'Alice',
        name: 'Alice',
        color: '#8B5CF6',
        status: 'connected',
      },
    });

    engine.disconnect();
  });

  it('should queue messages while offline and flush when connection opens', () => {
    const engine = new CollabEngine();
    engine.connect('sync-room', 'Alice', 'ws://localhost:8080/collab');

    // WebSocket is still CONNECTING (readyState = 0), send highlight
    engine.sendHighlight(0x1000, '#EF4444');

    // No message sent yet
    expect(sentMessages.length).toBe(0);

    // Open connection
    mockWebSocketInstance.readyState = 1; // OPEN
    mockWebSocketInstance.onopen();

    // Check the queued highlight is sent along with sync request
    expect(sentMessages).toContainEqual(expect.objectContaining({
      type: 'highlight_op',
      state: expect.objectContaining({
        address: 0x1000,
        color: '#EF4444',
      }),
    }));

    engine.disconnect();
  });

  it('should handle request_sync and respond with full state', () => {
    const engine = new CollabEngine();
    engine.connect('sync-room', 'Alice', 'ws://localhost:8080/collab');

    mockWebSocketInstance.readyState = 1;
    mockWebSocketInstance.onopen();
    sentMessages = []; // Reset list

    // Set some local states
    engine.sendHighlight(0x2000, '#10B981');

    // Simulate receiving request_sync
    mockWebSocketInstance.onmessage({
      data: JSON.stringify({
        type: 'request_sync',
        sender: 'Bob',
      }),
    });

    // Alice should reply with sync_state containing her state
    expect(sentMessages).toContainEqual(expect.objectContaining({
      type: 'sync_state',
      recipient: 'Bob',
      state: expect.objectContaining({
        highlights: expect.arrayContaining([
          expect.arrayContaining([
            0x2000,
            expect.objectContaining({ color: '#10B981' })
          ])
        ])
      }),
    }));

    engine.disconnect();
  });

  it('should handle sync_state and merge external updates', () => {
    const engine = new CollabEngine();
    engine.connect('sync-room', 'Alice', 'ws://localhost:8080/collab');

    mockWebSocketInstance.readyState = 1;
    mockWebSocketInstance.onopen();

    const externalState = {
      lamportClock: 10,
      comments: [
        {
          address: 0x3000,
          items: [{ id: 'Bob:1', char: 'H', origin: null, deleted: false }],
        },
      ],
      highlights: [
        [
          0x4000,
          {
            address: 0x4000,
            color: '#3B82F6',
            peerName: 'Bob',
            timestamp: Date.now(),
            clock: 5,
            client: 'Bob',
          },
        ],
      ],
      renames: [
        [
          'sub_1000',
          {
            originalName: 'sub_1000',
            renamedName: 'run_analysis',
            type: 'function',
            peerName: 'Bob',
            timestamp: Date.now(),
            clock: 5,
            client: 'Bob',
          },
        ],
      ],
    };

    // Receive sync_state message
    mockWebSocketInstance.onmessage({
      data: JSON.stringify({
        type: 'sync_state',
        recipient: 'Alice',
        state: externalState,
      }),
    });

    // Verify merged comments
    expect(engine.getComments().get(0x3000)?.comment).toBe('H');
    // Verify merged highlights
    expect(engine.getHighlights().get(0x4000)?.color).toBe('#3B82F6');
    // Verify merged renames
    expect(engine.getRenames().get('sub_1000')?.renamedName).toBe('run_analysis');

    engine.disconnect();
  });
});
