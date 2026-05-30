/**
 * Panel Coordinator for the Universal Reverse Engineering Tool (URET).
 * Manages UI view components, lazy loaded panels, sync/routing callbacks, and patches propagation.
 */

import { HexViewer } from './hexViewer.js';
import { AssemblyView } from './assemblyView.js';
import type { CFGVisualizer } from './cfgVisualizer.js';
import type { DependencyGraph } from './dependencyGraph.js';
import type { MemoryMapOverlay } from './memoryMap.js';
import { StringsView } from './stringsView.js';
import type { SearchPanel } from './searchPanel.js';
import type { SignaturePanel } from './signaturePanel.js';
import type { EmulatorPanel } from './emulatorPanel.js';
import type { GDBPanel } from './gdbPanel.js';
import type { ReportPanel } from './reportPanel.js';
import type { XRefsPanel } from './xrefsPanel.js';
import type { ImportsExportsPanel } from './importsExportsPanel.js';
import type { AIPanel } from './aiPanel.js';
import { BinaryPatcher, PatchRecord } from '../analyzer/patcher.js';
import type { PatcherPanel } from './patcherPanel.js';
import { buildFCG } from '../analyzer/fcg.js';
import type { FCGVisualizer } from './fcgVisualizer.js';
import type { CollabPanel } from './collabPanel.js';
import type { YaraPanel } from './yaraPanel.js';
import type { TypeSystemPanel } from './typeSystemPanel.js';
import type { MetadataPanel } from './metadataPanel.js';
import type { DemanglerPanel } from './demanglerPanel.js';
import type { DiffPanel } from './diffPanel.js';
import type { PluginsPanel } from './pluginsPanel.js';
import type { MachoObjcPanel } from './machoObjcPanel.js';
import { TabName } from './tabManager.js';
import { Instruction, Section, Symbol } from '../disassembler/types.js';
import { buildCFG, BasicBlock as CoreBasicBlock } from '../disassembler/cfg.js';
import { Decompiler, BasicBlock as DecompilerBlock } from '../disassembler/decompiler.js';
import { DisassemblerRouter } from '../disassembler/router.js';

import { PANEL_REGISTRY } from './panelRegistry.js';
import {
  handleTabChange,
  handleOffsetSelect,
  handleStringNavigate,
  handleSearchNavigate,
  handleInstructionSelect,
  handleBlockSelect,
  handleNodeSelect,
  handleCollabNavigate,
  handleCollabRename
} from './panelEvents.js';

export { PANEL_REGISTRY };

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
  public signatureNeedsUpdate = true;
  public dependencyNeedsUpdate = true;
  public gdbNeedsUpdate = true;
  public xrefsNeedsUpdate = true;
  public importsExportsNeedsUpdate = true;
  public patcherNeedsUpdate = true;
  public fcgNeedsUpdate = true;
  public demanglerNeedsUpdate = true;
  public machoObjcNeedsUpdate = true;

  private currentPatcher: BinaryPatcher | null = null;

  constructor(public host: CoordinatorHost) {}

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
    this.signatureNeedsUpdate = true;
    this.dependencyNeedsUpdate = true;
    this.gdbNeedsUpdate = true;
    this.xrefsNeedsUpdate = true;
    this.importsExportsNeedsUpdate = true;
    this.patcherNeedsUpdate = true;
    this.fcgNeedsUpdate = true;
    this.demanglerNeedsUpdate = true;
    this.machoObjcNeedsUpdate = true;

    this.currentPatcher = patcher;

    this.initHexViewer();
    this.initAssemblyViewer();
    this.initStringsViewer();
    this.updateActiveTabPanel();
    this.updateDecompiler();

    // Reset memory map overlay so it regenerates for new binary
    this.memoryMapOverlay = null;
  }

  public handleTabChange(tabName: TabName) {
    handleTabChange(this, tabName);
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
    } else if (tabName === 'signatures' && this.signatureNeedsUpdate) {
      this.initSignaturePanel();
      this.signatureNeedsUpdate = false;
    } else if (tabName === 'dependencies' && this.dependencyNeedsUpdate) {
      this.initDependencyGraph();
      this.dependencyNeedsUpdate = false;
    } else if (tabName === 'gdb' && this.gdbNeedsUpdate) {
      this.initGDBPanel();
      this.gdbNeedsUpdate = false;
    } else if (tabName === 'xrefs' && this.xrefsNeedsUpdate) {
      this.initXRefsPanel();
      this.xrefsNeedsUpdate = false;
    } else if (tabName === 'importsExports' && this.importsExportsNeedsUpdate) {
      this.initImportsExportsPanel();
      this.importsExportsNeedsUpdate = false;
    } else if (tabName === 'patcher' && this.patcherNeedsUpdate) {
      this.initPatcherPanel(this.currentPatcher);
      this.patcherNeedsUpdate = false;
    } else if (tabName === 'fcg' && this.fcgNeedsUpdate) {
      this.initFCGViewer();
      this.fcgNeedsUpdate = false;
    } else if (tabName === 'demangler' && this.demanglerNeedsUpdate) {
      this.initDemanglerPanel();
      this.demanglerNeedsUpdate = false;
    } else if (tabName === 'machoObjc' && this.machoObjcNeedsUpdate) {
      this.initMachoObjcPanel();
      this.machoObjcNeedsUpdate = false;
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

  public async initSearchPanel() {
    const container = document.getElementById('search-panel-container')!;
    if (!container) return;
    if (this.searchPanel) {
      this.searchPanel.updateData(
        this.host.state.binaryData,
        this.host.state.sections,
        this.host.state.symbols,
        this.host.state.instructions,
        this.host.state.extractedStrings
      );
    } else {
      let SearchPanelClass = PANEL_REGISTRY['SearchPanel'];
      if (!SearchPanelClass) {
        SearchPanelClass = (await import('./searchPanel.js')).SearchPanel;
      }
      this.searchPanel = new SearchPanelClass(container, {
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
      this.searchPanel?.updateData(
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
      return;
    }
    const SignaturePanelClass = PANEL_REGISTRY['SignaturePanel'];
    const init = (Clazz: any) => {
      this.signaturePanel = new Clazz(container, {
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
      this.signaturePanel?.updateData(
        this.host.state.binaryData,
        this.host.state.sections
      );
    };

    if (SignaturePanelClass) {
      init(SignaturePanelClass);
    } else {
      import('./signaturePanel.js').then((m) => init(m.SignaturePanel));
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

    const CFGVisualizerClass = PANEL_REGISTRY['CFGVisualizer'];
    const init = (Clazz: any) => {
      this.cfgVisualizer = new Clazz(container, this.host.state.cfgBlocks, {
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
    };

    if (CFGVisualizerClass) {
      init(CFGVisualizerClass);
    } else {
      import('./cfgVisualizer.js').then((m) => init(m.CFGVisualizer));
    }
  }

  public initDependencyGraph() {
    const container = document.getElementById('dependency-graph-container')!;
    if (this.dependencyGraph) {
      this.dependencyGraph.destroy();
    }

    if (this.host.state.dependencies) {
      const DependencyGraphClass = PANEL_REGISTRY['DependencyGraph'];
      const init = (Clazz: any) => {
        this.dependencyGraph = new Clazz(
          container,
          this.host.state.dependencies,
          {
            onNodeSelect: (node: any) => {
              if (node && node.address && this.assemblyView) {
                this.assemblyView.navigateToAddress(node.address);
              }
            },
          }
        );
      };

      if (DependencyGraphClass) {
        init(DependencyGraphClass);
      } else {
        import('./dependencyGraph.js').then((m) => init(m.DependencyGraph));
      }
    }
  }

  public async initReportPanel() {
    const container = document.getElementById('report-panel-container')!;
    if (!container) return;
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
      let ReportPanelClass = PANEL_REGISTRY['ReportPanel'];
      if (!ReportPanelClass) {
        ReportPanelClass = (await import('./reportPanel.js')).ReportPanel;
      }
      this.reportPanel = new ReportPanelClass(container);
      this.reportPanel?.updateData(
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

  public async initEmulatorPanel() {
    const container = document.getElementById('emulator-panel-container')!;
    if (!container) return;
    if (this.emulatorPanel) {
      this.emulatorPanel.updateData(
        this.host.state.binaryData,
        this.host.state.sections,
        this.host.state.entryPoint,
        this.host.state.instructions
      );
    } else {
      let EmulatorPanelClass = PANEL_REGISTRY['EmulatorPanel'];
      if (!EmulatorPanelClass) {
        EmulatorPanelClass = (await import('./emulatorPanel.js')).EmulatorPanel;
      }
      this.emulatorPanel = new EmulatorPanelClass(container, {
        onNavigate: (targetView: 'assembly' | 'hex' | 'decompiler', address: number) => {
          if (targetView === 'assembly' && this.assemblyView) {
            this.assemblyView.navigateToAddress(address);
          }
        },
        onStep: (rip: number) => {
          if (this.assemblyView) {
            this.assemblyView.navigateToAddress(rip);
          }
        },
      });
      this.emulatorPanel?.updateData(
        this.host.state.binaryData,
        this.host.state.sections,
        this.host.state.entryPoint,
        this.host.state.instructions
      );
    }
  }

  public async initGDBPanel() {
    const container = document.getElementById('gdb-panel-container')!;
    if (!container) return;
    if (this.gdbPanel) {
      this.gdbPanel.updateData(
        this.host.state.binaryData,
        this.host.state.sections,
        this.host.state.entryPoint,
        this.host.state.instructions
      );
    } else {
      let GDBPanelClass = PANEL_REGISTRY['GDBPanel'];
      if (!GDBPanelClass) {
        GDBPanelClass = (await import('./gdbPanel.js')).GDBPanel;
      }
      this.gdbPanel = new GDBPanelClass(container, {
        onNavigate: (targetView: 'assembly' | 'hex' | 'decompiler', address: number) => {
          if (targetView === 'assembly' && this.assemblyView) {
            this.assemblyView.navigateToAddress(address);
          }
        },
        onStep: (rip: number) => {
          if (this.assemblyView) {
            this.assemblyView.navigateToAddress(rip);
          }
        },
      });
      this.gdbPanel?.updateData(
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
      return;
    }
    const XRefsPanelClass = PANEL_REGISTRY['XRefsPanel'];
    const init = (Clazz: any) => {
      this.xrefsPanel = new Clazz(container, {
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
      this.xrefsPanel?.updateData(
        this.host.state.binaryData,
        this.host.state.sections,
        this.host.state.symbols,
        this.host.state.instructions,
        this.host.state.extractedStrings
      );
    };

    if (XRefsPanelClass) {
      init(XRefsPanelClass);
    } else {
      import('./xrefsPanel.js').then((m) => init(m.XRefsPanel));
    }
  }

  public initImportsExportsPanel() {
    const container = document.getElementById('imports-exports-container')!;
    if (this.importsExportsPanel) {
      this.importsExportsPanel.updateData(this.host.state.dependencies);
      return;
    }
    const ImportsExportsPanelClass = PANEL_REGISTRY['ImportsExportsPanel'];
    const init = (Clazz: any) => {
      this.importsExportsPanel = new Clazz(
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
    };

    if (ImportsExportsPanelClass) {
      init(ImportsExportsPanelClass);
    } else {
      import('./importsExportsPanel.js').then((m) => init(m.ImportsExportsPanel));
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
      return;
    }
    if (patcher) {
      const PatcherPanelClass = PANEL_REGISTRY['PatcherPanel'];
      const init = (Clazz: any) => {
        this.patcherPanel = new Clazz(container, patcher, {
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
      };

      if (PatcherPanelClass) {
        init(PatcherPanelClass);
      } else {
        import('./patcherPanel.js').then((m) => init(m.PatcherPanel));
      }
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
          const AIPanelClass = PANEL_REGISTRY['AIPanel'];
          if (AIPanelClass) {
            this.aiPanel = new AIPanelClass(aiContainer, {
              onNavigateToAddress: (address: number) => {
                if (this.assemblyView) {
                  this.assemblyView.navigateToAddress(address);
                }
                this.host.switchTab('assembly');
              },
            });
            if (this.aiPanel) {
              this.aiPanel.updateSymbolData(
                this.host.state.selectedSymbol,
                result.pseudocode
              );
            }
          } else {
            import('./aiPanel.js').then(({ AIPanel }) => {
              this.aiPanel = new AIPanel(aiContainer, {
                onNavigateToAddress: (address: number) => {
                  if (this.assemblyView) {
                    this.assemblyView.navigateToAddress(address);
                  }
                  this.host.switchTab('assembly');
                },
              });
              if (this.aiPanel) {
                this.aiPanel.updateSymbolData(
                  this.host.state.selectedSymbol,
                  result.pseudocode
                );
              }
            });
          }
        }
      } else {
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
    const FCGVisualizerClass = PANEL_REGISTRY['FCGVisualizer'];
    const init = (Clazz: any) => {
      this.fcgVisualizer = new Clazz(container, fcgGraph, {
        onNodeSelect: (address: number) => {
          if (this.assemblyView) {
            this.assemblyView.navigateToAddress(address);
          }
          this.host.switchTab('assembly');
        },
      });
    };

    if (FCGVisualizerClass) {
      init(FCGVisualizerClass);
    } else {
      import('./fcgVisualizer.js').then((m) => init(m.FCGVisualizer));
    }
  }

  public async initCollabPanel() {
    const container = document.getElementById('collab-panel-container')!;
    if (!container) return;
    if (this.collabPanel) {
      this.collabPanel.destroy();
    }
    let CollabPanelClass = PANEL_REGISTRY['CollabPanel'];
    if (!CollabPanelClass) {
      CollabPanelClass = (await import('./collabPanel.js')).CollabPanel;
    }
    this.collabPanel = new CollabPanelClass(container, {
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

  public async initYaraPanel() {
    const container = document.getElementById('yara-panel-container')!;
    if (!container) return;
    if (this.yaraPanel) {
      this.yaraPanel.updateData(this.host.state.binaryData, this.host.state.sections);
    } else {
      let YaraPanelClass = PANEL_REGISTRY['YaraPanel'];
      if (!YaraPanelClass) {
        YaraPanelClass = (await import('./yaraPanel.js')).YaraPanel;
      }
      this.yaraPanel = new YaraPanelClass(container, {
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
      this.yaraPanel?.updateData(this.host.state.binaryData, this.host.state.sections);
    }
  }

  public async initPluginsPanel() {
    const container = document.getElementById('plugins-panel-container')!;
    if (!container) return;
    if (this.pluginsPanel) {
      this.pluginsPanel.updateData(
        this.host.state.binaryData,
        this.host.state.sections,
        this.host.state.symbols,
        this.host.state.instructions
      );
    } else {
      let PluginsPanelClass = PANEL_REGISTRY['PluginsPanel'];
      if (!PluginsPanelClass) {
        PluginsPanelClass = (await import('./pluginsPanel.js')).PluginsPanel;
      }
      this.pluginsPanel = new PluginsPanelClass(container, {
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
      this.pluginsPanel?.updateData(
        this.host.state.binaryData,
        this.host.state.sections,
        this.host.state.symbols,
        this.host.state.instructions
      );
    }
  }

  public async initMetadataPanel() {
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
      let MetadataPanelClass = PANEL_REGISTRY['MetadataPanel'];
      if (!MetadataPanelClass) {
        MetadataPanelClass = (await import('./metadataPanel.js')).MetadataPanel;
      }
      this.metadataPanel = new MetadataPanelClass(container);
      this.metadataPanel?.updateData({
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

  public async initTypeSystemPanel() {
    const container = document.getElementById('type-system-container')!;
    if (container) {
      if (this.typeSystemPanel) {
        this.typeSystemPanel.updateArchitecture(this.host.state.architecture);
      } else {
        let TypeSystemPanelClass = PANEL_REGISTRY['TypeSystemPanel'];
        if (!TypeSystemPanelClass) {
          TypeSystemPanelClass = (await import('./typeSystemPanel.js')).TypeSystemPanel;
        }
        this.typeSystemPanel = new TypeSystemPanelClass(container, {
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
        this.typeSystemPanel?.updateArchitecture(this.host.state.architecture);
      }
    }
  }

  public async initDiffPanel() {
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
        let DiffPanelClass = PANEL_REGISTRY['DiffPanel'];
        if (!DiffPanelClass) {
          DiffPanelClass = (await import('./diffPanel.js')).DiffPanel;
        }
        this.diffPanel = new DiffPanelClass(container);
        this.diffPanel?.updateData(
          this.host.state.binaryData,
          this.host.state.sections,
          this.host.state.instructions,
          this.host.state.fileName
        );
      }
    }
  }

  public async initMachoObjcPanel() {
    const container = document.getElementById('macho-objc-container')!;
    if (!container) return;
    if (this.machoObjcPanel) {
      this.machoObjcPanel.updateData(this.host.state.objc || null);
    } else {
      let MachoObjcPanelClass = PANEL_REGISTRY['MachoObjcPanel'];
      if (!MachoObjcPanelClass) {
        MachoObjcPanelClass = (await import('./machoObjcPanel.js')).MachoObjcPanel;
      }
      this.machoObjcPanel = new MachoObjcPanelClass(container, {
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
      this.machoObjcPanel?.updateData(this.host.state.objc || null);
    }
  }

  public async initDemanglerPanel() {
    const container = document.getElementById('demangler-panel-container')!;
    if (!container) return;
    if (this.demanglerPanel) {
      this.demanglerPanel.updateData(this.host.state.symbols);
    } else {
      let DemanglerPanelClass = PANEL_REGISTRY['DemanglerPanel'];
      if (!DemanglerPanelClass) {
        DemanglerPanelClass = (await import('./demanglerPanel.js')).DemanglerPanel;
      }
      this.demanglerPanel = new DemanglerPanelClass(container, this.host.state.symbols, {
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
      const MemoryMapOverlayClass = PANEL_REGISTRY['MemoryMapOverlay'];
      const init = (Clazz: any) => {
        const overlay = new Clazz(
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
        this.memoryMapOverlay = overlay;
        overlay.show();
      };

      if (MemoryMapOverlayClass) {
        init(MemoryMapOverlayClass);
      } else {
        import('./memoryMap.js').then((m) => init(m.MemoryMapOverlay));
      }
    } else {
      this.memoryMapOverlay.show();
    }
  }
}
