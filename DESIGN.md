# Janus visual system

## Direction

Janus is a personal local vault: quiet, precise, and explicit about where data lives. The visual world is an instrument rather than a SaaS dashboard. The sidebar is graphite like a durable cover; the workspace is warm paper; copper marks action and local signal; red is reserved for destructive actions.

## Palette

- Ink: `#202321` and soft ink `#343936`
- Graphite: `#292D2A` and deep graphite `#1E211F`
- Ivory paper: `#F1EEE6` and bright paper `#F8F6F0`
- Paper line: `#D2CEC3`
- Copper action: `#9A542F`; bright copper `#AD643A`; soft copper `#EAD1BC`
- Destructive red: `#96362F`
- Success green: `#5A8465`

## Typography

- Display and section headings: local Georgia/Times serif. Editorial, calm, and available without a network request.
- Interface copy: local system sans stack.
- Secrets and measured metadata: local system monospace stack, never as decorative body typography.
- Functional UI text stays at or above 11px; primary copy stays 13px or larger.

## Components

- Janus mark: two interlocking geometric faces/keys, drawn in copper and ivory. No emoji icons.
- Navigation: graphite rail with copper-tinted active state and compact geometric line icons.
- Surfaces: warm paper with defined lines; use elevation selectively and avoid nested card stacks.
- Actions: copper filled primary button, ivory outlined secondary action, red outline for destructive actions.
- Secret display: dark-edged paper field with monospace content and explicit copy/reveal controls.
- Authentication: centered paper sheet in a graphite field with local-first status copy.

## Motion and responsive behavior

- Use one short upward reveal for route/tab changes and modal entrance.
- Respect `prefers-reduced-motion`.
- At narrow widths, the sidebar becomes a horizontal navigation rail, list actions expand to full-width controls, and modal form actions stack.

## Product truth

The frontend remains dependency-light and local-first. No analytics, telemetry, remote images, synchronization, or hosted authentication are introduced. The current Flask routes, DOM IDs, and API behavior remain the contract.
