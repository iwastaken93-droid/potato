/**
 * Binary Patching Engine
 * Tracks patches, modifies binary data, and exports modified binaries.
 */

export interface PatchRecord {
  id: string;
  address: number; // Virtual address of the patch
  offset: number; // File offset in the binary
  originalBytes: Uint8Array;
  patchedBytes: Uint8Array;
  timestamp: number;
  description: string;
  active: boolean;
}

export interface Transaction {
  id: string;
  type: 'apply' | 'toggle' | 'remove' | 'clear' | 'undo' | 'redo';
  description: string;
  timestamp: number;
  patchId?: string;
}

export class BinaryPatcher {
  private originalBinary: Uint8Array;
  private patchedBinary: Uint8Array;
  private history: PatchRecord[] = [];
  private listeners: ((
    patchedBinary: Uint8Array,
    history: PatchRecord[]
  ) => void)[] = [];
  private transactionLog: Transaction[] = [];
  private undoStack: PatchRecord[][] = [];
  private redoStack: PatchRecord[][] = [];

  private cloneHistory(history: PatchRecord[]): PatchRecord[] {
    return history.map(patch => ({
      ...patch,
      originalBytes: new Uint8Array(patch.originalBytes),
      patchedBytes: new Uint8Array(patch.patchedBytes),
    }));
  }

  private saveState(type: 'apply' | 'toggle' | 'remove' | 'clear', description: string, patchId?: string): void {
    this.undoStack.push(this.cloneHistory(this.history));
    this.redoStack = [];
    this.transactionLog.push({
      id: 'tx_' + Math.random().toString(36).substring(2, 11),
      type,
      description,
      timestamp: Date.now(),
      patchId,
    });
  }

  constructor(originalBinary: Uint8Array) {
    this.originalBinary = new Uint8Array(originalBinary);
    this.patchedBinary = new Uint8Array(originalBinary);
  }

  public getOriginalBinary(): Uint8Array {
    return this.originalBinary;
  }

  public getPatchedBinary(): Uint8Array {
    return this.patchedBinary;
  }

  public getHistory(): PatchRecord[] {
    return this.history;
  }

  /**
   * Applies a patch at a specific virtual address/offset.
   */
  public applyPatch(
    offset: number,
    patchedBytes: Uint8Array,
    address: number,
    description: string
  ): PatchRecord {
    if (
      offset < 0 ||
      offset + patchedBytes.length > this.originalBinary.length
    ) {
      throw new Error(
        `Patch out of bounds. Offset: ${offset}, length: ${patchedBytes.length}, binary size: ${this.originalBinary.length}`
      );
    }

    const originalBytes = this.patchedBinary.slice(
      offset,
      offset + patchedBytes.length
    );

    const record: PatchRecord = {
      id: 'patch_' + Math.random().toString(36).substring(2, 11),
      address,
      offset,
      originalBytes,
      patchedBytes,
      timestamp: Date.now(),
      description,
      active: true,
    };

    this.saveState('apply', `Applied patch at address 0x${address.toString(16)}`, record.id);
    this.history.push(record);
    this.reapplyAll();
    return record;
  }

  /**
   * Toggles the active status of a patch.
   */
  public togglePatch(id: string): boolean {
    const record = this.history.find((p) => p.id === id);
    if (!record) return false;

    this.saveState('toggle', `Toggled patch ${id} (${record.active ? 'deactivated' : 'activated'})`, id);
    record.active = !record.active;
    this.reapplyAll();
    return true;
  }

  /**
   * Removes a patch completely from the history.
   */
  public removePatch(id: string): boolean {
    const index = this.history.findIndex((p) => p.id === id);
    if (index === -1) return false;

    const record = this.history[index];
    this.saveState('remove', `Removed patch ${id} at address 0x${record.address.toString(16)}`, id);
    this.history.splice(index, 1);
    this.reapplyAll();
    return true;
  }

  /**
   * Clears all patches.
   */
  public clearAll(): void {
    this.saveState('clear', 'Cleared all patches');
    this.history = [];
    this.reapplyAll();
  }

  public getTransactionLog(): Transaction[] {
    return this.transactionLog;
  }

  public canUndo(): boolean {
    return this.undoStack.length > 0;
  }

  public canRedo(): boolean {
    return this.redoStack.length > 0;
  }

  public undo(): boolean {
    if (!this.canUndo()) return false;

    const previous = this.undoStack.pop()!;
    this.redoStack.push(this.cloneHistory(this.history));
    this.history = previous;

    this.transactionLog.push({
      id: 'tx_' + Math.random().toString(36).substring(2, 11),
      type: 'undo',
      description: 'Undo last operation',
      timestamp: Date.now(),
    });

    this.reapplyAll();
    return true;
  }

  public redo(): boolean {
    if (!this.canRedo()) return false;

    const next = this.redoStack.pop()!;
    this.undoStack.push(this.cloneHistory(this.history));
    this.history = next;

    this.transactionLog.push({
      id: 'tx_' + Math.random().toString(36).substring(2, 11),
      type: 'redo',
      description: 'Redo last undone operation',
      timestamp: Date.now(),
    });

    this.reapplyAll();
    return true;
  }

  /**
   * Reapplies active patches on top of the original binary.
   */
  private reapplyAll(): void {
    const temp = new Uint8Array(this.originalBinary);
    for (const patch of this.history) {
      if (patch.active) {
        temp.set(patch.patchedBytes, patch.offset);
      }
    }
    this.patchedBinary = temp;
    this.notifyListeners();
  }

  /**
   * Subscribes to changes to the binary or patch history.
   */
  public subscribe(
    listener: (patchedBinary: Uint8Array, history: PatchRecord[]) => void
  ): () => void {
    this.listeners.push(listener);
    return () => {
      this.listeners = this.listeners.filter((l) => l !== listener);
    };
  }

  private notifyListeners(): void {
    for (const listener of this.listeners) {
      try {
        listener(this.patchedBinary, this.history);
      } catch (err) {
        console.error('Error in patch listener:', err);
      }
    }
  }

  /**
   * Exports/Downloads the patched binary.
   */
  public exportBinary(filename: string): void {
    const blob = new Blob([this.patchedBinary.buffer as ArrayBuffer], {
      type: 'application/octet-stream',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download =
      filename.replace(/\.[^/.]+$/, '') +
      '_patched' +
      (filename.includes('.')
        ? filename.substring(filename.lastIndexOf('.'))
        : '');
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  /**
   * Parses string representation of bytes (hex or assembly shorthand).
   */
  public static parseInput(input: string, arch: string = 'x86_64'): Uint8Array {
    const cleaned = input.trim();
    if (!cleaned) {
      throw new Error('Input is empty');
    }

    // Try parsing as assembly instruction mnemonics (lightweight helper/mock assembler)
    const lowerInput = cleaned.toLowerCase().replace(/\s+/g, ' ');
    if (arch === 'x86_64') {
      if (lowerInput === 'nop') {
        return new Uint8Array([0x90]);
      }
      if (lowerInput === 'ret' || lowerInput === 'retn') {
        return new Uint8Array([0xc3]);
      }
      if (lowerInput === 'int3') {
        return new Uint8Array([0xcc]);
      }
      if (lowerInput === 'xor eax, eax') {
        return new Uint8Array([0x31, 0xc0]);
      }
      if (lowerInput === 'xor edi, edi') {
        return new Uint8Array([0x31, 0xff]);
      }
      if (lowerInput === 'xor esi, esi') {
        return new Uint8Array([0x31, 0xf6]);
      }
      if (lowerInput === 'xor ebx, ebx') {
        return new Uint8Array([0x31, 0xdb]);
      }
      if (lowerInput === 'xor ecx, ecx') {
        return new Uint8Array([0x31, 0xc9]);
      }
      if (lowerInput === 'xor edx, edx') {
        return new Uint8Array([0x31, 0xd2]);
      }
      // Jump short instructions
      if (lowerInput.startsWith('jmp ')) {
        const targetStr = lowerInput.substring(4).trim();
        const numVal = parseInt(
          targetStr.startsWith('0x') ? targetStr : '0x' + targetStr,
          16
        );
        if (!isNaN(numVal)) {
          // Return a placeholder jump instruction or mock jump instruction
          return new Uint8Array([0xeb, 0xfe]); // jmp short $
        }
      }
    }

    // Otherwise, parse as Hex Bytes: e.g., "90 90" or "9090" or "\x90\x90"
    const hexCleaned = cleaned.replace(/(0x|\\x|\s|,)/gi, '');
    if (hexCleaned.length % 2 !== 0) {
      throw new Error(
        'Invalid hex string length (must be even number of characters)'
      );
    }
    const bytes = new Uint8Array(hexCleaned.length / 2);
    for (let i = 0; i < hexCleaned.length; i += 2) {
      const byteValue = parseInt(hexCleaned.substring(i, i + 2), 16);
      if (isNaN(byteValue)) {
        throw new Error(
          `Invalid hex character: ${hexCleaned.substring(i, i + 2)}`
        );
      }
      bytes[i / 2] = byteValue;
    }
    return bytes;
  }

  public serializeState(): any {
    const toHexStr = (arr: Uint8Array) => {
      let hex = '';
      for (let i = 0; i < arr.length; i++) {
        hex += arr[i].toString(16).padStart(2, '0');
      }
      return hex;
    };

    const serializePatchRecord = (p: PatchRecord) => ({
      id: p.id,
      address: p.address,
      offset: p.offset,
      originalBytes: toHexStr(p.originalBytes),
      patchedBytes: toHexStr(p.patchedBytes),
      timestamp: p.timestamp,
      description: p.description,
      active: p.active
    });

    return {
      history: this.history.map(serializePatchRecord),
      undoStack: this.undoStack.map(stack => stack.map(serializePatchRecord)),
      redoStack: this.redoStack.map(stack => stack.map(serializePatchRecord)),
      transactionLog: this.transactionLog
    };
  }

  public deserializeState(state: any): void {
    const fromHexStr = (hex: string) => {
      if (!hex) return new Uint8Array(0);
      const bytes = new Uint8Array(hex.length / 2);
      for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
      }
      return bytes;
    };

    const deserializePatchRecord = (p: any): PatchRecord => ({
      id: p.id,
      address: Number(p.address),
      offset: Number(p.offset),
      originalBytes: fromHexStr(p.originalBytes),
      patchedBytes: fromHexStr(p.patchedBytes),
      timestamp: Number(p.timestamp),
      description: String(p.description),
      active: Boolean(p.active)
    });

    this.history = (state.history || []).map(deserializePatchRecord);
    this.undoStack = (state.undoStack || []).map((stack: any) => stack.map(deserializePatchRecord));
    this.redoStack = (state.redoStack || []).map((stack: any) => stack.map(deserializePatchRecord));
    this.transactionLog = state.transactionLog || [];
    this.reapplyAll();
  }
}

