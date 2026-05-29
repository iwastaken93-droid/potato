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
