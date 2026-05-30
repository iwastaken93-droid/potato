/**
 * Panel Registry for the Universal Reverse Engineering Tool (URET).
 * Holds registration mapping for lazy-loaded UI panels.
 */

export const PANEL_REGISTRY: Record<string, any> = (globalThis as any).PANEL_REGISTRY || ((globalThis as any).PANEL_REGISTRY = {});
