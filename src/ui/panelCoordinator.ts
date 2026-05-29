/**
 * Panel Coordinator for the Universal Reverse Engineering Tool (URET).
 * Manages UI view components, lazy loaded panels, sync/routing callbacks, and patches propagation.
 */

import { HexViewer } from './hexViewer.js';
import { AssemblyView } from './assemblyView.js';
import { CFGVisualizer } from './cfgVisualizer.js';
import { DependencyGraph } from './dependencyGraph.js';
import { MemoryMapOverlay } from './memoryMap.js';
import { StringsView } from './stringsView.js';
import { SearchPanel } from './searchPanel.js';
import { SignaturePanel } from './signaturePanel.js';
import { EmulatorPanel } from './emulatorPanel.js';
import { GDBPanel } from './gdbPanel.js';
import { ReportPanel } from './reportPanel.js';
import { XRefsPanel } from './xrefsPanel.js';
import { ImportsExportsPanel } from './importsExportsPanel.js';
import { AIPanel } from './aiPanel.js';
import { BinaryPatcher, PatchRecord } from '../analyzer/patcher.js';
import { PatcherPanel } from './patcherPanel.js';
import { buildFCG } from '../analyzer/fcg.js';
import { FCGVisualizer } from './fcgVisualizer.js';
import { CollabPanel } from './collabPanel.js';
import { YaraPanel } from './yaraPanel.js';
import { TypeSystemPanel } from './typeSystemPanel.js';
import { MetadataPanel } from './metadataPanel.js';
import { DemanglerPanel } from './demanglerPanel.js';
import { DiffPanel } from './diffPanel.js';
import { PluginsPanel } from './pluginsPanel.js';
import { MachoObjcPanel } from './machoObjcPanel.js';
import { TabName } from './tabManager.js';
import { Instruction, Section, Symbol } from '../disassembler/types.js';
import { buildCFG, BasicBlock as CoreBasicBlock } from '../disassembler/cfg.js';
import { Decompiler, BasicBlock as DecompilerBlock } from '../disassembler/decompiler.js';
import { DisassemblerRouter } from '../disassembler/router.js';

export interface CoordinatorHost {
  state: any;
  switchTab: (tabName: TabName) => void;
  selectSymbol: (sym: Symbol) => void;
  renderSidebarList: () => void;
}

export class PanelCoordinator {
  // UI Components
  public hexViewer: HexViewer | null = null;
  public assemblyView: AssemblyView | null = null;
  public cfgVisualizer: CFGVisualizer | null = null;
  public dependencyGraph: DependencyGraph | null = null;
  public memoryMapOverlay: MemoryMapOverlay | null = null;
  public stringsView: StringsView | null = null;
  public searchPanel: SearchPanel | null = null;
  public signaturePanel: SignaturePanel | null = null;
  public emulatorPanel: EmulatorPanel | null = null;
  public gdbPanel: GDBPanel | null = null;
  public reportPanel: ReportPanel | null = null;
  public xrefsPanel: XRefsPanel | null = null;
  public importsExportsPanel: ImportsExportsPanel | null = null;
  public aiPanel: AIPanel | null = null;
  public patcherPanel: PatcherPanel | null = null;
  public fcgVisualizer: FCGVisualizer | null = null;
  public collabPanel: CollabPanel | null = null;
  public yaraPanel: YaraPanel | null = null;
  public typeSystemPanel: TypeSystemPanel | null = null;
  public metadataPanel: MetadataPanel | null = null;
  public demanglerPanel: DemanglerPanel | null = null;
  public diffPanel: DiffPanel | null = null;
  public pluginsPanel: PluginsPanel | null = null;
  public machoObjcPanel: MachoObjcPanel | null = null;

  // View dirty flags
  public cfgNeedsUpdate = true;
  public emulatorNeedsUpdate = true;
  public collabNeedsUpdate = true;
  public pluginsNeedsUpdate = true;
  public searchNeedsUpdate = true;
  public reportNeedsUpdate = true;
  public yaraNeedsUpdate = true;
  public metadataNeedsUpdate = true;
  public typeSystemNeedsUpdate = true;
  public diffNeedsUpdate = true;

  constructor(private host: CoordinatorHost) {}

  public onBinaryLoaded(patcher: BinaryPatcher | null) {
    this.cfgNeedsUpdate = true;
    this.emulatorNeedsUpdate = true;
    this.collabNeedsUpdate = true;
    this.pluginsNeedsUpdate = true;
    this.searchNeedsUpdate = true;
    this.reportNeedsUpdate = true;
    this.yaraNeedsUpdate = true;
    this.metadataNeedsUpdate = true;
    this.typeSystemNeedsUpdate = true;
    this.diffNeedsUpdate = true;

    this.initHexViewer();
    this.initAssemblyViewer();
    this.initStringsViewer();
    this.initSignaturePanel();
    this.initDependencyGraph();
    this.initGDBPanel();
    this.initXRefsPanel();
    this.initImportsExportsPanel();
    this.initPatcherPanel(patcher);
    this.initFCGViewer();
    this.initDemanglerPanel();
    this.initMachoObjcPanel();
    this.updateActiveTabPanel();
    this.updateDecompiler();

    // Reset memory map overlay so it regenerates for new binary
    this.memoryMapOverlay = null;
  }

  public handleTabChange(tabName: TabName) {
    // Trigger components updates or re-render if needed
    if (tabName === 'hex' && this.hexViewer) {
      // Re-trigger layout alignment inside container
    } else if (tabName === 'assembly' && this.assemblyView) {
      if (this.host.state.selectedSymbol) {
        this.assemblyView.navigateToAddress(this.host.state.selectedSymbol.address);
      }
    } else if (tabName === 'typeSystem' && this.typeSystemPanel) {
      this.typeSystemPanel.updateArchitecture(this.host.state.architecture);
    } else if (tabName === 'dependencies' && this.dependencyGraph) {
      // Re-trigger layout/resizing inside canvas container
      setTimeout(() => {
        if (this.dependencyGraph) {
          const resizeEvent = new Event('resize');
          window.dispatchEvent(resizeEvent);
        }
      }, 50);
    } else if (tabName === 'plugins' && this.pluginsPanel) {
      this.pluginsPanel.updateData(
        this.host.state.binaryData,
        this.host.state.sections,
        this.host.state.symbols,
        this.host.state.instructions
      );
    }
  }

  public updateActiveTabPanel() {
    if (!this.host.state) return;
    const tabName = this.host.state.activeTab;
    if (tabName === 'cfg' && this.cfgNeedsUpdate) {
      this.initCFGViewer();
      this.cfgNeedsUpdate = false;
    } else if (tabName === 'emulator' && this.emulatorNeedsUpdate) {
      this.initEmulatorPanel();
      this.emulatorNeedsUpdate = false;
    } else if (tabName === 'collab' && this.collabNeedsUpdate) {
      this.initCollabPanel();
      this.collabNeedsUpdate = false;
    } else if (tabName === 'plugins' && this.pluginsNeedsUpdate) {
      this.initPluginsPanel();
      this.pluginsNeedsUpdate = false;
    } else if (tabName === 'search' && this.searchNeedsUpdate) {
      this.initSearchPanel();
      this.searchNeedsUpdate = false;
    } else if (tabName === 'report' && this.reportNeedsUpdate) {
      this.initReportPanel();
      this.reportNeedsUpdate = false;
    } else if (tabName === 'yara' && this.yaraNeedsUpdate) {
      this.initYaraPanel();
      this.yaraNeedsUpdate = false;
    } else if (tabName === 'metadata' && this.metadataNeedsUpdate) {
      this.initMetadataPanel();
      this.metadataNeedsUpdate = false;
    } else if (tabName === 'typeSystem' && this.typeSystemNeedsUpdate) {
      this.initTypeSystemPanel();
      this.typeSystemNeedsUpdate = false;
    } else if (tabName === 'diff' && this.diffNeedsUpdate) {
      this.initDiffPanel();
      this.diffNeedsUpdate = false;
    }
  }

  public initHexViewer() {
    const container = document.getElementById('hex-viewer-container')!;
    if (this.hexViewer) {
      this.hexViewer.setData(this.host.state.binaryData);
    } else {
      this.hexViewer = new HexViewer(container, this.host.state.binaryData, {
        onOffsetSelect: (offset: number | null) => {
          if (offset !== null && this.assemblyView) {
            // Find instruction corresponding to the offset
            const address =
              (this.host.state.sections.find((s: any) => s.flags.execute)
                ?.virtualAddress || 0x1000) + offset;
            this.assemblyView.navigateToAddress(address, false);
          }
        },
      });
    }
  }

  public initStringsViewer() {
    const container = document.getElementById('strings-viewer-container')!;
    if (this.stringsView) {
      this.stringsView.setStrings(this.host.state.extractedStrings);
    } else {
      this.stringsView = new StringsView(
        container,
        this.host.state.extractedStrings,
        {
          onNavigate: (offset: number, address: number) => {
            if (this.hexViewer) {
              this.hexViewer.setSelectedOffset(offset);
            }
            if (this.assemblyView) {
              this.assemblyView.navigateToAddress(address);
            }
            this.host.switchTab('assembly');
          },
        }
      );
    }
  }

  public initSearchPanel() {
    const container = document.getElementById('search-panel-container')!;
    if (this.searchPanel) {
      this.searchPanel.updateData(
        this.host.state.binaryData,
        this.host.state.sections,
        this.host.state.symbols,
        this.host.state.instructions,
        this.host.state.extractedStrings
      );
    } else {
      this.searchPanel = new SearchPanel(container, {
        onNavigate: (
          targetView: 'assembly' | 'hex' | 'decompiler',
          address: number
        ) => {
          if (targetView === 'assembly') {
            if (this.assemblyView) {
              this.assemblyView.navigateToAddress(address);
            }
            this.host.switchTab('assembly');
          } else if (targetView === 'hex') {
            if (this.hexViewer) {
              const executeSection = this.host.state.sections.find(
                (s: any) => s.flags.execute
              );
              const textBaseAddress = executeSection
                ? executeSection.virtualAddress
                : 0x1000;
              const offset = address - textBaseAddress;
              if (offset >= 0 && offset < this.host.state.binaryData.length) {
                this.hexViewer.setSelectedOffset(offset);
              }
            }
            this.host.switchTab('hex');
          } else if (targetView === 'decompiler') {
            // Find enclosing function symbol
            const funcSyms = this.host.state.symbols
              .filter((s: Symbol) => s.type === 'function')
              .sort((a: Symbol, b: Symbol) => a.address - b.address);

            let enclosingSym = funcSyms[0];
            for (let i = 0; i < funcSyms.length; i++) {
              if (funcSyms[i].address <= address) {
                enclosingSym = funcSyms[i];
              } else {
                break;
              }
            }

            if (enclosingSym) {
              this.host.selectSymbol(enclosingSym);
            }
            this.host.switchTab('decompiler');
          }
        },
      });
      this.searchPanel.updateData(
        this.host.state.binaryData,
        this.host.state.sections,
        this.host.state.symbols,
        this.host.state.instructions,
        this.host.state.extractedStrings
      );
    }
  }

  public initSignaturePanel() {
    const container = document.getElementById('signatures-viewer-container')!;
    if (this.signaturePanel) {
      this.signaturePanel.updateData(
        this.host.state.binaryData,
        this.host.state.sections
      );
    } else {
      this.signaturePanel = new SignaturePanel(container, {
        onNavigate: (
          targetView: 'assembly' | 'hex' | 'decompiler',
          address: number
        ) => {
          if (targetView === 'assembly') {
            if (this.assemblyView) {
              this.assemblyView.navigateToAddress(address);
            }
            this.host.switchTab('assembly');
          } else if (targetView === 'hex') {
            if (this.hexViewer) {
              const executeSection = this.host.state.sections.find(
                (s: any) => s.flags.execute
              );
              const textBaseAddress = executeSection
                ? executeSection.virtualAddress
                : 0x1000;
              const offset = address - textBaseAddress;
              if (offset >= 0 && offset < this.host.state.binaryData.length) {
                this.hexViewer.setSelectedOffset(offset);
              }
            }
            this.host.switchTab('hex');
          } else if (targetView === 'decompiler') {
            // Find enclosing function symbol
            const funcSyms = this.host.state.symbols
              .filter((s: Symbol) => s.type === 'function')
              .sort((a: Symbol, b: Symbol) => a.address - b.address);

            let enclosingSym = funcSyms[0];
            for (let i = 0; i < funcSyms.length; i++) {
              if (funcSyms[i].address <= address) {
                enclosingSym = funcSyms[i];
              } else {
                break;
              }
            }

            if (enclosingSym) {
              this.host.selectSymbol(enclosingSym);
            }
            this.host.switchTab('decompiler');
          }
        },
      });
      this.signaturePanel.updateData(
        this.host.state.binaryData,
        this.host.state.sections
      );
    }
  }

  public initAssemblyViewer() {
    const container = document.getElementById('assembly-viewer-container')!;
    if (this.assemblyView) {
      this.assemblyView.destroy();
    }

    this.assemblyView = new AssemblyView(container, this.host.state.instructions, {
      onInstructionSelect: (inst: Instruction) => {
        // Sync hex viewer selection
        const executeSection = this.host.state.sections.find(
          (s: any) => s.flags.execute
        );
        if (executeSection) {
          const offset = inst.address - executeSection.virtualAddress;
          if (
            offset >= 0 &&
            offset < this.host.state.binaryData.length &&
            this.hexViewer
          ) {
            this.hexViewer.setSelectedOffset(offset);
          }
        }
        if (this.xrefsPanel) {
          this.xrefsPanel.selectAddress(inst.address);
        }
      },
    });
  }

  public initCFGViewer() {
    const container = document.getElementById('cfg-viewer-container')!;
    container.innerHTML = '';

    // Create visualization with state blocks
    this.cfgVisualizer = new CFGVisualizer(container, this.host.state.cfgBlocks, {
      layout: 'layered',
      onBlockSelect: (blockId: string | null) => {
        if (blockId) {
          const block = this.host.state.cfgBlocks.find((b: CoreBasicBlock) => b.id === blockId);
          if (block && this.assemblyView) {
            this.assemblyView.navigateToAddress(block.startAddress);
          }
        }
      },
    });
  }

  public initDependencyGraph() {
    const container = document.getElementById('dependency-graph-container')!;
    if (this.dependencyGraph) {
      this.dependencyGraph.destroy();
    }

    if (this.host.state.dependencies) {
      this.dependencyGraph = new DependencyGraph(
        container,
        this.host.state.dependencies,
        {
          onNodeSelect: (node) => {
            if (node && node.address && this.assemblyView) {
              this.assemblyView.navigateToAddress(node.address);
            }
          },
        }
      );
    }
  }

  public initReportPanel() {
    const container = document.getElementById('report-panel-container')!;
    if (this.reportPanel) {
      this.reportPanel.updateData(
        this.host.state.fileName,
        this.host.state.fileSize,
        this.host.state.binaryData,
        this.host.state.architecture,
        this.host.state.entryPoint,
        this.host.state.sections,
        this.host.state.symbols,
        this.host.state.extractedStrings
      );
    } else {
      this.reportPanel = new ReportPanel(container);
      this.reportPanel.updateData(
        this.host.state.fileName,
        this.host.state.fileSize,
        this.host.state.binaryData,
        this.host.state.architecture,
        this.host.state.entryPoint,
        this.host.state.sections,
        this.host.state.symbols,
        this.host.state.extractedStrings
      );
    }
  }

  public initEmulatorPanel() {
    const container = document.getElementById('emulator-panel-container')!;
    if (this.emulatorPanel) {
      this.emulatorPanel.updateData(
        this.host.state.binaryData,
        this.host.state.sections,
        this.host.state.entryPoint,
        this.host.state.instructions
      );
    } else {
      this.emulatorPanel = new EmulatorPanel(container, {
        onNavigate: (targetView, address) => {
          if (targetView === 'assembly' && this.assemblyView) {
            this.assemblyView.navigateToAddress(address);
          }
        },
        onStep: (rip) => {
          if (this.assemblyView) {
            this.assemblyView.navigateToAddress(rip);
          }
        },
      });
      this.emulatorPanel.updateData(
        this.host.state.binaryData,
        this.host.state.sections,
        this.host.state.entryPoint,
        this.host.state.instructions
      );
    }
  }

  public initGDBPanel() {
    const container = document.getElementById('gdb-panel-container')!;
    if (this.gdbPanel) {
      this.gdbPanel.updateData(
        this.host.state.binaryData,
        this.host.state.sections,
        this.host.state.entryPoint,
        this.host.state.instructions
      );
    } else {
      this.gdbPanel = new GDBPanel(container, {
        onNavigate: (targetView, address) => {
          if (targetView === 'assembly' && this.assemblyView) {
            this.assemblyView.navigateToAddress(address);
          }
        },
        onStep: (rip) => {
          if (this.assemblyView) {
            this.assemblyView.navigateToAddress(rip);
          }
        },
      });
      this.gdbPanel.updateData(
        this.host.state.binaryData,
        this.host.state.sections,
        this.host.state.entryPoint,
        this.host.state.instructions
      );
    }
  }

  public initXRefsPanel() {
    const container = document.getElementById('xrefs-panel-container')!;
    if (this.xrefsPanel) {
      this.xrefsPanel.updateData(
        this.host.state.binaryData,
        this.host.state.sections,
        this.host.state.symbols,
        this.host.state.instructions,
        this.host.state.extractedStrings
      );
    } else {
      this.xrefsPanel = new XRefsPanel(container, {
        onNavigate: (
          targetView: 'assembly' | 'hex' | 'decompiler',
          address: number
        ) => {
          if (targetView === 'assembly') {
            if (this.assemblyView) {
              this.assemblyView.navigateToAddress(address);
            }
            this.host.switchTab('assembly');
          } else if (targetView === 'hex') {
            if (this.hexViewer) {
              const executeSection = this.host.state.sections.find(
                (s: any) => s.flags.execute
              );
              const textBaseAddress = executeSection
                ? executeSection.virtualAddress
                : 0x1000;
              const offset = address - textBaseAddress;
              if (offset >= 0 && offset < this.host.state.binaryData.length) {
                this.hexViewer.setSelectedOffset(offset);
              }
            }
            this.host.switchTab('hex');
          } else if (targetView === 'decompiler') {
            // Find enclosing function symbol
            const funcSyms = this.host.state.symbols
              .filter((s: Symbol) => s.type === 'function')
              .sort((a: Symbol, b: Symbol) => a.address - b.address);

            let enclosingSym = funcSyms[0];
            for (let i = 0; i < funcSyms.length; i++) {
              if (funcSyms[i].address <= address) {
                enclosingSym = funcSyms[i];
              } else {
                break;
              }
            }

            if (enclosingSym) {
              this.host.selectSymbol(enclosingSym);
            }
            this.host.switchTab('decompiler');
          }
        },
      });
      this.xrefsPanel.updateData(
        this.host.state.binaryData,
        this.host.state.sections,
        this.host.state.symbols,
        this.host.state.instructions,
        this.host.state.extractedStrings
      );
    }
  }

  public initImportsExportsPanel() {
    const container = document.getElementById('imports-exports-container')!;
    if (this.importsExportsPanel) {
      this.importsExportsPanel.updateData(this.host.state.dependencies);
    } else {
      this.importsExportsPanel = new ImportsExportsPanel(
        container,
        this.host.state.dependencies,
        {
          onNavigate: (targetView: 'assembly' | 'hex', address: number) => {
            if (targetView === 'assembly' && this.assemblyView) {
              this.assemblyView.navigateToAddress(address);
            } else if (targetView === 'hex' && this.hexViewer) {
              const executeSection = this.host.state.sections.find(
                (s: any) => s.flags.execute
              );
              const textBaseAddress = executeSection
                ? executeSection.virtualAddress
                : 0x1000;
              const offset = address - textBaseAddress;
              if (offset >= 0 && offset < this.host.state.binaryData.length) {
                this.hexViewer.setSelectedOffset(offset);
              }
            }
            this.host.switchTab(targetView);
          },
        }
      );
    }
  }

  public initPatcherPanel(patcher: BinaryPatcher | null) {
    const container = document.getElementById('patcher-panel-container')!;
    if (this.patcherPanel && patcher) {
      this.patcherPanel.updateData(
        this.host.state.sections,
        this.host.state.fileName,
        this.host.state.architecture
      );
    } else if (patcher) {
      this.patcherPanel = new PatcherPanel(container, patcher, {
        onPatchApplied: (patchedBinary: Uint8Array, patches: PatchRecord[]) => {
          // 1. Update binary data in state
          this.host.state.binaryData = patchedBinary;

          // 2. Re-disassemble the binary to get new instructions!
          const router = new DisassemblerRouter();
          const instructions = router.disassemble(patchedBinary, {
            arch: this.host.state.architecture,
            baseAddress:
              this.host.state.sections.find((s: any) => s.flags.execute)
                ?.virtualAddress || 0x1000,
            entryPoint: this.host.state.entryPoint,
          });

          this.host.state.instructions = instructions;

          // 3. Re-build CFG blocks
          const cfgBlocks = buildCFG(instructions);
          this.host.state.cfgBlocks = cfgBlocks;

          // 4. Update the active/relevant viewer datasets
          if (this.hexViewer) {
            this.hexViewer.setData(patchedBinary);
          }
          if (this.assemblyView) {
            this.assemblyView.setInstructions(instructions);
          }
          if (this.cfgVisualizer) {
            this.initCFGViewer();
          }
          if (this.emulatorPanel) {
            this.emulatorPanel.updateData(
              patchedBinary,
              this.host.state.sections,
              this.host.state.entryPoint,
              instructions
            );
          }
          if (this.gdbPanel) {
            this.gdbPanel.updateData(
              patchedBinary,
              this.host.state.sections,
              this.host.state.entryPoint,
              instructions
            );
          }
          if (this.yaraPanel) {
            this.yaraPanel.updateData(patchedBinary, this.host.state.sections);
          }
          if (this.fcgVisualizer) {
            this.initFCGViewer();
          }
        },
      });
    }
  }

  public updateDecompiler() {
    const container = document.getElementById('decompiler-viewer-container')!;
    if (!this.host.state || this.host.state.cfgBlocks.length === 0) {
      container.textContent = '// No code to decompile';
      return;
    }

    // Convert core CFG blocks structure to structure expected by the Decompiler
    const decompilerBlocks: DecompilerBlock[] = this.host.state.cfgBlocks.map(
      (block: CoreBasicBlock) => ({
        id: block.id,
        successors: block.successors,
        instructions: block.instructions.map((inst: Instruction) => ({
          address: inst.address,
          op: inst.mnemonic.toUpperCase(),
          args: inst.operands
            ? inst.operands
                .map((op: any) => {
                  if (op.type === 'reg') return String(op.reg);
                  if (op.type === 'imm')
                    return `0x${Number(op.imm).toString(16)}`;
                  if (op.type === 'mem' && op.mem) {
                    const parts: string[] = [];
                    if (op.mem.base) parts.push(String(op.mem.base));
                    if (op.mem.index) {
                      const scaleStr = op.mem.scale ? ` * ${op.mem.scale}` : '';
                      parts.push(`${op.mem.index}${scaleStr}`);
                    }
                    if (op.mem.disp)
                      parts.push(`0x${Number(op.mem.disp).toString(16)}`);
                    return `[${parts.join(' + ')}]`;
                  }
                  return '';
                })
                .filter(Boolean)
            : [inst.opStr],
        })),
      })
    );

    const decompiler = new Decompiler();
    const entryBlock = decompilerBlocks[0];

    try {
      const funcName = this.host.state.selectedSymbol
        ? this.host.state.selectedSymbol.name
        : 'main';
      const result = decompiler.decompile(
        funcName,
        ['a0', 'a1'],
        decompilerBlocks,
        entryBlock?.id || ''
      );
      container.textContent = result.pseudocode;

      if (!this.aiPanel) {
        const aiContainer = document.getElementById('ai-panel-container')!;
        if (aiContainer) {
          this.aiPanel = new AIPanel(aiContainer, {
            onNavigateToAddress: (address: number) => {
              if (this.assemblyView) {
                this.assemblyView.navigateToAddress(address);
              }
              this.host.switchTab('assembly');
            },
          });
        }
      }
      if (this.aiPanel) {
        this.aiPanel.updateSymbolData(
          this.host.state.selectedSymbol,
          result.pseudocode
        );
      }
    } catch (err) {
      container.textContent = `// Decompilation failed: ${err}`;
      if (this.aiPanel) {
        this.aiPanel.updateSymbolData(this.host.state.selectedSymbol, '');
      }
    }
  }

  public initFCGViewer() {
    const container = document.getElementById('fcg-viewer-container')!;
    container.innerHTML = '';
    const fcgGraph = buildFCG(this.host.state.symbols, this.host.state.instructions);
    this.fcgVisualizer = new FCGVisualizer(container, fcgGraph, {
      onNodeSelect: (address: number) => {
        if (this.assemblyView) {
          this.assemblyView.navigateToAddress(address);
        }
        this.host.switchTab('assembly');
      },
    });
  }

  public initCollabPanel() {
    const container = document.getElementById('collab-panel-container')!;
    if (this.collabPanel) {
      this.collabPanel.destroy();
    }
    this.collabPanel = new CollabPanel(container, {
      onNavigate: (
        targetView: 'assembly' | 'hex' | 'decompiler',
        address: number
      ) => {
        if (targetView === 'assembly' && this.assemblyView) {
          this.assemblyView.navigateToAddress(address);
        } else if (targetView === 'hex' && this.hexViewer) {
          const executeSection = this.host.state.sections.find(
            (s: any) => s.flags.execute
          );
          const textBaseAddress = executeSection
            ? executeSection.virtualAddress
            : 0x1000;
          const offset = address - textBaseAddress;
          if (offset >= 0 && offset < this.host.state.binaryData.length) {
            this.hexViewer.setSelectedOffset(offset);
          }
        } else if (targetView === 'decompiler') {
          const funcSyms = this.host.state.symbols
            .filter((s: Symbol) => s.type === 'function')
            .sort((a: Symbol, b: Symbol) => a.address - b.address);

          let enclosingSym = funcSyms[0];
          for (let i = 0; i < funcSyms.length; i++) {
            if (funcSyms[i].address <= address) {
              enclosingSym = funcSyms[i];
            } else {
              break;
            }
          }
          if (enclosingSym) {
            this.host.selectSymbol(enclosingSym);
          }
        }
        this.host.switchTab(targetView);
      },
      onCommentSynced: (address: number, comment: string) => {},
      onHighlightSynced: (address: number, color: string) => {},
      onRenameSynced: (
        oldName: string,
        newName: string,
        type: 'function' | 'variable'
      ) => {
        const sym = this.host.state.symbols.find((s: Symbol) => s.name === oldName);
        if (sym) {
          sym.name = newName;
          this.host.renderSidebarList();
        }
      },
    });
  }

  public initYaraPanel() {
    const container = document.getElementById('yara-panel-container')!;
    if (this.yaraPanel) {
      this.yaraPanel.updateData(this.host.state.binaryData, this.host.state.sections);
    } else {
      this.yaraPanel = new YaraPanel(container, {
        onNavigate: (
          targetView: 'assembly' | 'hex' | 'decompiler',
          address: number
        ) => {
          if (targetView === 'assembly' && this.assemblyView) {
            this.assemblyView.navigateToAddress(address);
          } else if (targetView === 'hex' && this.hexViewer) {
            const executeSection = this.host.state.sections.find(
              (s: any) => s.flags.execute
            );
            const textBaseAddress = executeSection
              ? executeSection.virtualAddress
              : 0x1000;
            const offset = address - textBaseAddress;
            if (offset >= 0 && offset < this.host.state.binaryData.length) {
              this.hexViewer.setSelectedOffset(offset);
            }
          } else if (targetView === 'decompiler') {
            const funcSyms = this.host.state.symbols
              .filter((s: Symbol) => s.type === 'function')
              .sort((a: Symbol, b: Symbol) => a.address - b.address);

            let enclosingSym = funcSyms[0];
            for (let i = 0; i < funcSyms.length; i++) {
              if (funcSyms[i].address <= address) {
                enclosingSym = funcSyms[i];
              } else {
                break;
              }
            }
            if (enclosingSym) {
              this.host.selectSymbol(enclosingSym);
            }
          }
          this.host.switchTab(targetView);
        },
      });
      this.yaraPanel.updateData(this.host.state.binaryData, this.host.state.sections);
    }
  }

  public initPluginsPanel() {
    const container = document.getElementById('plugins-panel-container')!;
    if (this.pluginsPanel) {
      this.pluginsPanel.updateData(
        this.host.state.binaryData,
        this.host.state.sections,
        this.host.state.symbols,
        this.host.state.instructions
      );
    } else {
      this.pluginsPanel = new PluginsPanel(container, {
        onNavigate: (
          targetView: 'assembly' | 'hex' | 'decompiler',
          address: number
        ) => {
          if (targetView === 'assembly' && this.assemblyView) {
            this.assemblyView.navigateToAddress(address);
          }
          this.host.switchTab(targetView);
        },
      });
      this.pluginsPanel.updateData(
        this.host.state.binaryData,
        this.host.state.sections,
        this.host.state.symbols,
        this.host.state.instructions
      );
    }
  }

  public initMetadataPanel() {
    const container = document.getElementById('metadata-panel-container')!;
    if (!container) return;
    if (this.metadataPanel) {
      this.metadataPanel.updateData({
        fileName: this.host.state.fileName,
        fileSize: this.host.state.fileSize,
        binaryData: this.host.state.binaryData,
        architecture: this.host.state.architecture,
        entryPoint: this.host.state.entryPoint,
        sectionsCount: this.host.state.sections.length,
        symbolsCount: this.host.state.symbols.length,
        lastModified: this.host.state.lastModified,
        objc: this.host.state.objc,
      });
    } else {
      this.metadataPanel = new MetadataPanel(container);
      this.metadataPanel.updateData({
        fileName: this.host.state.fileName,
        fileSize: this.host.state.fileSize,
        binaryData: this.host.state.binaryData,
        architecture: this.host.state.architecture,
        entryPoint: this.host.state.entryPoint,
        sectionsCount: this.host.state.sections.length,
        symbolsCount: this.host.state.symbols.length,
        lastModified: this.host.state.lastModified,
        objc: this.host.state.objc,
      });
    }
  }

  public initTypeSystemPanel() {
    const container = document.getElementById('type-system-container')!;
    if (container) {
      if (this.typeSystemPanel) {
        this.typeSystemPanel.updateArchitecture(this.host.state.architecture);
      } else {
        this.typeSystemPanel = new TypeSystemPanel(container, {
          onNavigate: (
            targetView: 'assembly' | 'hex' | 'decompiler',
            address: number
          ) => {
            if (targetView === 'assembly' && this.assemblyView) {
              this.assemblyView.navigateToAddress(address);
            } else if (targetView === 'hex' && this.hexViewer) {
              const executeSection = this.host.state.sections.find(
                (s: any) => s.flags.execute
              );
              const textBaseAddress = executeSection
                ? executeSection.virtualAddress
                : 0x1000;
              const offset = address - textBaseAddress;
              if (offset >= 0 && offset < this.host.state.binaryData.length) {
                this.hexViewer.setSelectedOffset(offset);
              }
            } else if (targetView === 'decompiler') {
              const funcSyms = this.host.state.symbols
                .filter((s: Symbol) => s.type === 'function')
                .sort((a: Symbol, b: Symbol) => a.address - b.address);

              let enclosingSym = funcSyms[0];
              for (let i = 0; i < funcSyms.length; i++) {
                if (funcSyms[i].address <= address) {
                  enclosingSym = funcSyms[i];
                } else {
                  break;
                }
              }
              if (enclosingSym) {
                this.host.selectSymbol(enclosingSym);
              }
            }
            this.host.switchTab(targetView);
          },
        });
        this.typeSystemPanel.updateArchitecture(this.host.state.architecture);
      }
    }
  }

  public initDiffPanel() {
    const container = document.getElementById('diff-panel-container')!;
    if (container) {
      if (this.diffPanel) {
        this.diffPanel.updateData(
          this.host.state.binaryData,
          this.host.state.sections,
          this.host.state.instructions,
          this.host.state.fileName
        );
      } else {
        this.diffPanel = new DiffPanel(container);
        this.diffPanel.updateData(
          this.host.state.binaryData,
          this.host.state.sections,
          this.host.state.instructions,
          this.host.state.fileName
        );
      }
    }
  }

  public initMachoObjcPanel() {
    const container = document.getElementById('macho-objc-container')!;
    if (!container) return;
    if (this.machoObjcPanel) {
      this.machoObjcPanel.updateData(this.host.state.objc || null);
    } else {
      this.machoObjcPanel = new MachoObjcPanel(container, {
        onNavigate: (
          targetView: 'assembly' | 'hex' | 'decompiler',
          address: number
        ) => {
          if (targetView === 'assembly' && this.assemblyView) {
            this.assemblyView.navigateToAddress(address);
            this.host.switchTab('assembly');
          } else if (targetView === 'hex' && this.hexViewer) {
            const executeSection = this.host.state.sections.find(
              (s: any) => s.flags.execute
            );
            const textBaseAddress = executeSection
              ? executeSection.virtualAddress
              : 0x1000;
            const offset = address - textBaseAddress;
            if (offset >= 0 && offset < this.host.state.binaryData.length) {
              this.hexViewer.setSelectedOffset(offset);
            }
            this.host.switchTab('hex');
          } else if (targetView === 'decompiler') {
            // Find enclosing function symbol
            const funcSyms = this.host.state.symbols
              .filter((s: Symbol) => s.type === 'function')
              .sort((a: Symbol, b: Symbol) => a.address - b.address);

            let enclosingSym = funcSyms[0];
            for (let i = 0; i < funcSyms.length; i++) {
              if (funcSyms[i].address <= address) {
                enclosingSym = funcSyms[i];
              } else {
                break;
              }
            }

            if (enclosingSym) {
              this.host.selectSymbol(enclosingSym);
            }
            this.host.switchTab('decompiler');
          }
        },
      });
      this.machoObjcPanel.updateData(this.host.state.objc || null);
    }
  }

  public initDemanglerPanel() {
    const container = document.getElementById('demangler-panel-container')!;
    if (this.demanglerPanel) {
      this.demanglerPanel.updateData(this.host.state.symbols);
    } else {
      this.demanglerPanel = new DemanglerPanel(container, this.host.state.symbols, {
        onNavigate: (targetView: 'assembly' | 'hex', address: number) => {
          if (targetView === 'assembly' && this.assemblyView) {
            this.assemblyView.navigateToAddress(address);
          } else if (targetView === 'hex' && this.hexViewer) {
            const executeSection = this.host.state.sections.find(
              (s: any) => s.flags.execute
            );
            const textBaseAddress = executeSection
              ? executeSection.virtualAddress
              : 0x1000;
            const offset = address - textBaseAddress;
            if (offset >= 0 && offset < this.host.state.binaryData.length) {
              this.hexViewer.setSelectedOffset(offset);
            }
          }
          this.host.switchTab(targetView);
        },
      });
    }
  }

  public showMemoryMap() {
    if (!this.memoryMapOverlay) {
      this.memoryMapOverlay = new MemoryMapOverlay(
        this.host.state.binaryData,
        this.host.state.sections,
        {
          onNavigate: (offset: number, address: number) => {
            if (this.hexViewer) {
              this.hexViewer.setSelectedOffset(offset);
            }
            if (this.assemblyView) {
              this.assemblyView.navigateToAddress(address);
            }
            // Switch to assembly tab if currently in another tab
            if (
              this.host.state.activeTab !== 'hex' &&
              this.host.state.activeTab !== 'assembly'
            ) {
              this.host.switchTab('assembly');
            }
          },
        }
      );
    }
    this.memoryMapOverlay.show();
  }
}
