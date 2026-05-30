// @vitest-environment jsdom
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { LoadingScreen } from '../src/ui/loadingScreen.js';

describe('LoadingScreen Unit Tests', () => {
  let screen: LoadingScreen;

  beforeEach(() => {
    screen = new LoadingScreen();
  });

  afterEach(() => {
    screen.destroy();
  });

  it('should initialize and display elements correctly', () => {
    expect(screen).toBeDefined();
    
    const overlay = document.querySelector('.premium-loader-overlay');
    expect(overlay).toBeDefined();
    expect(overlay?.classList.contains('active')).toBe(false);
  });

  it('should show and hide loading screen', () => {
    screen.show('test_binary.bin');
    const overlay = document.querySelector('.premium-loader-overlay');
    expect(overlay?.classList.contains('active')).toBe(true);

    const title = overlay?.querySelector('.premium-loader-title');
    expect(title?.textContent).toBe('Analyzing test_binary.bin');

    screen.hide();
    expect(overlay?.classList.contains('active')).toBe(false);
  });

  it('should update progress and chunk counter', () => {
    screen.show('test.bin');
    screen.update(45, 3, 10, 'Processing...');

    const progressBar = document.querySelector('#premium-loader-bar') as HTMLDivElement;
    expect(progressBar.style.width).toBe('45%');

    const statusText = document.querySelector('.premium-loader-status');
    expect(statusText?.textContent).toBe('Processing...');

    const chunkCounter = document.querySelector('.premium-chunk-counter');
    expect(chunkCounter?.textContent).toBe('Processed Chunks: 3 / 10');
  });

  it('should trigger cancel callbacks', () => {
    const cancelSpy = vi.fn();
    screen.onCancel(cancelSpy);

    screen.show('test.bin');
    const cancelBtn = document.querySelector('#premium-loader-cancel') as HTMLButtonElement;
    cancelBtn.click();

    expect(cancelSpy).toHaveBeenCalled();
  });
});
