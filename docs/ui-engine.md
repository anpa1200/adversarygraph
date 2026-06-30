# AdversaryGraph UI Engine

AdversaryGraph keeps the existing React, Vite, TypeScript, and Tailwind stack, and adds a mature component/system layer for complex security workspaces. The goal is incremental migration, not a full UI rewrite.

## Component Layer

Reusable wrappers live in `frontend/src/components/ui/`. New feature work should prefer these wrappers over direct third-party usage so styling, accessibility, and behavior stay consistent.

| Capability | Library | Local wrapper | Intended use |
| --- | --- | --- | --- |
| Dialogs, popovers, tabs, scroll areas, selects, tooltips | Radix UI | `dialog.tsx`, `popover.tsx`, `tabs.tsx`, `scroll-area.tsx`, `select.tsx`, `tooltip.tsx` | Modals, entity drawers, filters, field selectors, compact help |
| Command palette | `cmdk` | `command.tsx` | Global search, quick actions, investigation navigation |
| Data tables | TanStack Table | `data-table.tsx` | CVE, IOC, asset, event, and log tables |
| Virtualized lists | TanStack Virtual | `virtual-list.tsx` | Large logs, telemetry streams, IOC lists, CVE result sets |
| Entity graphs | React Flow / XYFlow | `graph.tsx` | Attack chains, CVE/APT/TTP/IOC graphs, investigation graphs |
| Resizable panels | `react-resizable-panels` | `resizable.tsx` | Debugger, decompiler, malware analysis, split investigation workspaces |
| Code editor | Monaco Editor | `code-editor.tsx` | Decompiled code, logs, rules, generated detections, scripts |
| Charts | Recharts | `chart.tsx` | Telemetry summaries, coverage charts, scoring dashboards |

## Migration Rules

1. Keep pages feature-first. Move reusable UI behavior into `components/ui`, not into page-local helpers.
2. Use `DataTable` for new dense datasets instead of hand-built tables.
3. Use `VirtualList` for any log or record list that can exceed a few hundred rows.
4. Use `EntityGraph` for graph views instead of new D3-only one-off graph renderers unless custom force-layout behavior is required.
5. Use `ResizablePanelGroup` for IDE-style workspaces such as malware debug, decompilation, and attack telemetry.
6. Use `CodeEditor` for decompiled code, SIEM payloads, Sigma/YARA/STIX snippets, and detection engineering output.
7. Import heavy components directly from their files when possible. Do not import the entire `components/ui` barrel from `App.tsx`; this keeps Monaco and graph packages out of the first bundle.

## Current Status

The foundation is installed and build-validated. Existing screens continue to work with their current components. Future work can migrate high-impact areas first:

- CVE Library, IOC Library, Asset Surface, and Attack Simulation logs to `DataTable` and `VirtualList`.
- Attack chain graph and CVE/APT/TTP/IOC correlation graph to `EntityGraph`.
- Malware Debugger and Decompilation IDE to `ResizablePanelGroup` and `CodeEditor`.
- Global search and quick analyst actions to `CommandDialog`.
