import { TabName } from './tabManager.js';
import type { PanelCoordinator } from './panelCoordinator.js';
import type { Instruction, Symbol } from '../disassembler/types.js';

export function handleTabChange(coordinator: PanelCoordinator, tabName: TabName) {
  if (tabName === 'hex' && coordinator.hexViewer) {
    // Re-trigger layout alignment inside container
  } else if (tabName === 'assembly' && coordinator.assemblyView) {
    if (coordinator.host.state.selectedSymbol) {
      coordinator.assemblyView.navigateToAddress(coordinator.host.state.selectedSymbol.address);
    }
  } else if (tabName === 'typeSystem' && coordinator.typeSystemPanel) {
    coordinator.typeSystemPanel.updateArchitecture(coordinator.host.state.architecture);
  } else if (tabName === 'dependencies' && coordinator.dependencyGraph) {
    // Re-trigger layout/resizing inside canvas container
    setTimeout(() => {
      if (coordinator.dependencyGraph) {
        const resizeEvent = new Event('resize');
        window.dispatchEvent(resizeEvent);
      }
    }, 50);
  } else if (tabName === 'plugins' && coordinator.pluginsPanel) {
    coordinator.pluginsPanel.updateData(
      coordinator.host.state.binaryData,
      coordinator.host.state.sections,
      coordinator.host.state.symbols,
      coordinator.host.state.instructions
    );
  }
}

export function handleOffsetSelect(coordinator: PanelCoordinator, offset: number | null) {
  if (offset !== null && coordinator.assemblyView) {
    const address =
      (coordinator.host.state.sections.find((s: any) => s.flags.execute)
        ?.virtualAddress || 0x1000) + offset;
    coordinator.assemblyView.navigateToAddress(address, false);
  }
}

export function handleStringNavigate(coordinator: PanelCoordinator, offset: number, address: number) {
  if (coordinator.hexViewer) {
    coordinator.hexViewer.setSelectedOffset(offset);
  }
  if (coordinator.assemblyView) {
    coordinator.assemblyView.navigateToAddress(address);
  }
  coordinator.host.switchTab('assembly');
}

export function handleSearchNavigate(
  coordinator: PanelCoordinator,
  targetView: 'assembly' | 'hex' | 'decompiler',
  address: number
) {
  if (targetView === 'assembly') {
    if (coordinator.assemblyView) {
      coordinator.assemblyView.navigateToAddress(address);
    }
    coordinator.host.switchTab('assembly');
  } else if (targetView === 'hex') {
    if (coordinator.hexViewer) {
      const executeSection = coordinator.host.state.sections.find(
        (s: any) => s.flags.execute
      );
      const textBaseAddress = executeSection
        ? executeSection.virtualAddress
        : 0x1000;
      const offset = address - textBaseAddress;
      if (offset >= 0 && offset < coordinator.host.state.binaryData.length) {
        coordinator.hexViewer.setSelectedOffset(offset);
      }
    }
    coordinator.host.switchTab('hex');
  } else if (targetView === 'decompiler') {
    const funcSyms = coordinator.host.state.symbols
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
      coordinator.host.selectSymbol(enclosingSym);
    }
    coordinator.host.switchTab('decompiler');
  }
}

export function handleInstructionSelect(coordinator: PanelCoordinator, inst: Instruction) {
  const executeSection = coordinator.host.state.sections.find(
    (s: any) => s.flags.execute
  );
  if (executeSection) {
    const offset = inst.address - executeSection.virtualAddress;
    if (
      offset >= 0 &&
      offset < coordinator.host.state.binaryData.length &&
      coordinator.hexViewer
    ) {
      coordinator.hexViewer.setSelectedOffset(offset);
    }
  }
  if (coordinator.xrefsPanel) {
    coordinator.xrefsPanel.selectAddress(inst.address);
  }
}

export function handleBlockSelect(coordinator: PanelCoordinator, blockId: string | null) {
  if (blockId) {
    const block = coordinator.host.state.cfgBlocks.find((b: any) => b.id === blockId);
    if (block && coordinator.assemblyView) {
      coordinator.assemblyView.navigateToAddress(block.startAddress);
    }
  }
}

export function handleNodeSelect(coordinator: PanelCoordinator, address: number) {
  if (coordinator.assemblyView) {
    coordinator.assemblyView.navigateToAddress(address);
  }
  coordinator.host.switchTab('assembly');
}

export function handleCollabNavigate(
  coordinator: PanelCoordinator,
  targetView: 'assembly' | 'hex' | 'decompiler',
  address: number
) {
  if (targetView === 'assembly' && coordinator.assemblyView) {
    coordinator.assemblyView.navigateToAddress(address);
  } else if (targetView === 'hex' && coordinator.hexViewer) {
    const executeSection = coordinator.host.state.sections.find(
      (s: any) => s.flags.execute
    );
    const textBaseAddress = executeSection
      ? executeSection.virtualAddress
      : 0x1000;
    const offset = address - textBaseAddress;
    if (offset >= 0 && offset < coordinator.host.state.binaryData.length) {
      coordinator.hexViewer.setSelectedOffset(offset);
    }
  } else if (targetView === 'decompiler') {
    const funcSyms = coordinator.host.state.symbols
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
      coordinator.host.selectSymbol(enclosingSym);
    }
  }
  coordinator.host.switchTab(targetView);
}

export function handleCollabRename(
  coordinator: PanelCoordinator,
  oldName: string,
  newName: string
) {
  const sym = coordinator.host.state.symbols.find((s: Symbol) => s.name === oldName);
  if (sym) {
    sym.name = newName;
    coordinator.host.renderSidebarList();
  }
}
