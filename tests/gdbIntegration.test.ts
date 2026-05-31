import { describe, it, expect } from 'vitest';
import { Emulator } from '../src/emulator/emulator.js';
import {
  GDBProtocolParser,
  handleGDBCommand,
  formatPacket,
  calculateChecksum,
  GDBPacket,
} from '../src/emulator/gdbProtocol.js';

/**
 * Mock helper simulating a live connection channel with latency and packet routing.
 */
export class GDBLiveConnectionSimulator {
  private clientParser: GDBProtocolParser;
  private serverParser: GDBProtocolParser;
  private clientReceivedPackets: GDBPacket[] = [];
  private serverReceivedPackets: GDBPacket[] = [];
  private pendingTransmissions: Promise<void>[] = [];
  public latencyMs: number = 0;

  constructor(public emulator: Emulator) {
    // Server parser simulates target side
    this.serverParser = new GDBProtocolParser((packet) => {
      this.serverReceivedPackets.push(packet);
      if (packet.type === 'packet') {
        if (packet.data !== undefined) {
          // ACK then response
          this.sendToClient('+');
          const resp = handleGDBCommand(packet.data, this.emulator);
          this.sendToClient(formatPacket(resp));
        } else {
          // Checksum fail -> NAK
          this.sendToClient('-');
        }
      }
    });

    // Client parser simulates host GDB side
    this.clientParser = new GDBProtocolParser((packet) => {
      this.clientReceivedPackets.push(packet);
    });
  }

  private async delay(): Promise<void> {
    if (this.latencyMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, this.latencyMs));
    } else {
      await new Promise((resolve) => queueMicrotask(resolve));
    }
  }

  public async sendToServer(data: string): Promise<void> {
    const promise = (async () => {
      // Send in characters to simulate streaming transfer
      for (let i = 0; i < data.length; i++) {
        this.serverParser.feed(data[i]);
        await this.delay();
      }
    })();
    this.pendingTransmissions.push(promise);
    await promise;
  }

  public async sendToClient(data: string): Promise<void> {
    const promise = (async () => {
      for (let i = 0; i < data.length; i++) {
        this.clientParser.feed(data[i]);
        await this.delay();
      }
    })();
    this.pendingTransmissions.push(promise);
    await promise;
  }

  public async flush(): Promise<void> {
    while (this.pendingTransmissions.length > 0) {
      const current = [...this.pendingTransmissions];
      this.pendingTransmissions = [];
      await Promise.all(current);
    }
  }

  public getClientPackets(): GDBPacket[] {
    return this.clientReceivedPackets;
  }

  public getServerPackets(): GDBPacket[] {
    return this.serverReceivedPackets;
  }

  public clear(): void {
    this.clientReceivedPackets = [];
    this.serverReceivedPackets = [];
  }
}

describe('GDB Remote Debugging Integration & Live Simulator', () => {
  it('should support connection handshake and query commands', async () => {
    const emulator = new Emulator();
    emulator.reset();
    const sim = new GDBLiveConnectionSimulator(emulator);

    // Send qSupported packet
    await sim.sendToServer(formatPacket('qSupported'));
    await sim.flush();

    // Should receive ACK (+) and response packet (PacketSize=1024)
    const clientPackets = sim.getClientPackets();
    expect(clientPackets).toContainEqual({ type: 'ack' });
    expect(clientPackets).toContainEqual({
      type: 'packet',
      data: 'PacketSize=1024',
      raw: 'PacketSize=1024',
    });
  });

  it('should handle streaming packet fragmentation with latency', async () => {
    const emulator = new Emulator();
    emulator.reset();
    const sim = new GDBLiveConnectionSimulator(emulator);
    sim.latencyMs = 2; // Inject artificial latency

    // Send packet fragmented
    const fullPacket = formatPacket('qSupported');
    const part1 = fullPacket.slice(0, 5);
    const part2 = fullPacket.slice(5);

    await sim.sendToServer(part1);
    // Ensure it hasn't processed fully yet
    expect(sim.getClientPackets().length).toBe(0);

    await sim.sendToServer(part2);
    await sim.flush();

    expect(sim.getClientPackets()).toContainEqual({ type: 'ack' });
    expect(sim.getClientPackets()).toContainEqual({
      type: 'packet',
      data: 'PacketSize=1024',
      raw: 'PacketSize=1024',
    });
  });

  it('should request register access, write it, and verify the change', async () => {
    const emulator = new Emulator();
    emulator.reset();
    const sim = new GDBLiveConnectionSimulator(emulator);

    // Write general register RAX (index 0) to 0x1234567890abcdefn
    // RAX val: efcdab9078563412
    const writeReq = formatPacket('P0=efcdab9078563412');
    await sim.sendToServer(writeReq);
    await sim.flush();

    expect(sim.getClientPackets()).toContainEqual({ type: 'ack' });
    expect(sim.getClientPackets()).toContainEqual({
      type: 'packet',
      data: 'OK',
      raw: 'OK',
    });

    sim.clear();

    // Query RAX (p0)
    await sim.sendToServer(formatPacket('p0'));
    await sim.flush();

    expect(sim.getClientPackets()).toContainEqual({
      type: 'packet',
      data: 'efcdab9078563412',
      raw: 'efcdab9078563412',
    });
    expect(emulator.cpu.read('rax')).toBe(0x1234567890abcdefn);
  });

  it('should perform memory map, writes, and reads over RSP connection simulator', async () => {
    const emulator = new Emulator();
    emulator.reset();
    emulator.memory.map(0x2000n, 0x100);
    const sim = new GDBLiveConnectionSimulator(emulator);

    // Write: M2000,4:deadbeef
    const writeCmd = formatPacket('M2000,4:deadbeef');
    await sim.sendToServer(writeCmd);
    await sim.flush();

    expect(sim.getClientPackets()).toContainEqual({
      type: 'packet',
      data: 'OK',
      raw: 'OK',
    });

    sim.clear();

    // Read: m2000,4
    const readCmd = formatPacket('m2000,4');
    await sim.sendToServer(readCmd);
    await sim.flush();

    expect(sim.getClientPackets()).toContainEqual({
      type: 'packet',
      data: 'deadbeef',
      raw: 'deadbeef',
    });
  });

  it('should handle stepping instructions and target state verification', async () => {
    const emulator = new Emulator();
    emulator.reset(0x1000);
    emulator.memory.map(0x1000n, 0x10);

    // Write a mov rax, rax instruction at 0x1000
    emulator.instructions.set(0x1000, {
      address: 0x1000,
      mnemonic: 'mov',
      opStr: 'rax, rax',
      bytes: new Uint8Array([0x48, 0x89, 0xc0]),
      size: 3,
      operands: [
        { type: 'reg', reg: 'rax' },
        { type: 'reg', reg: 'rax' },
      ],
    });

    const sim = new GDBLiveConnectionSimulator(emulator);

    // Step cmd: 's' -> expect S05 stop reply
    await sim.sendToServer(formatPacket('s'));
    await sim.flush();

    expect(sim.getClientPackets()).toContainEqual({
      type: 'packet',
      data: 'S05',
      raw: 'S05',
    });
    expect(emulator.cpu.read('rip')).toBe(0x1003n);
  });

  it('should send NAK (-) back when bad checksum is parsed', async () => {
    const emulator = new Emulator();
    emulator.reset();
    const sim = new GDBLiveConnectionSimulator(emulator);

    // Send malformed packet (wrong checksum)
    await sim.sendToServer('$qSupported#00');
    await sim.flush();

    expect(sim.getClientPackets()).toContainEqual({ type: 'nak' });
  });
});
