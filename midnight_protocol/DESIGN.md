---
name: Midnight Protocol
colors:
  surface: '#051424'
  surface-dim: '#051424'
  surface-bright: '#2c3a4c'
  surface-container-lowest: '#010f1f'
  surface-container-low: '#0d1c2d'
  surface-container: '#122131'
  surface-container-high: '#1c2b3c'
  surface-container-highest: '#273647'
  on-surface: '#d4e4fa'
  on-surface-variant: '#c7c6cd'
  inverse-surface: '#d4e4fa'
  inverse-on-surface: '#233143'
  outline: '#909097'
  outline-variant: '#46464c'
  surface-tint: '#c2c6db'
  primary: '#c2c6db'
  on-primary: '#2b3040'
  primary-container: '#0a0f1e'
  on-primary-container: '#777b8e'
  inverse-primary: '#595e70'
  secondary: '#bdf4ff'
  on-secondary: '#00363d'
  secondary-container: '#00e3fd'
  on-secondary-container: '#00616d'
  tertiary: '#bfc6de'
  on-tertiary: '#293043'
  tertiary-container: '#080f21'
  on-tertiary-container: '#757c92'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#dee1f7'
  primary-fixed-dim: '#c2c6db'
  on-primary-fixed: '#161b2b'
  on-primary-fixed-variant: '#414658'
  secondary-fixed: '#9cf0ff'
  secondary-fixed-dim: '#00daf3'
  on-secondary-fixed: '#001f24'
  on-secondary-fixed-variant: '#004f58'
  tertiary-fixed: '#dbe2fb'
  tertiary-fixed-dim: '#bfc6de'
  on-tertiary-fixed: '#141b2d'
  on-tertiary-fixed-variant: '#3f465a'
  background: '#051424'
  on-background: '#d4e4fa'
  surface-variant: '#273647'
typography:
  display:
    fontFamily: Inter
    fontSize: 36px
    fontWeight: '700'
    lineHeight: 44px
    letterSpacing: -0.02em
  headline-lg:
    fontFamily: Inter
    fontSize: 28px
    fontWeight: '600'
    lineHeight: 36px
  headline-md:
    fontFamily: Inter
    fontSize: 20px
    fontWeight: '600'
    lineHeight: 28px
  body-lg:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
  body-md:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  label-mono:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '500'
    lineHeight: 16px
    letterSpacing: 0.05em
  stats-lg:
    fontFamily: JetBrains Mono
    fontSize: 24px
    fontWeight: '700'
    lineHeight: 32px
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  base: 4px
  xs: 4px
  sm: 8px
  md: 16px
  lg: 24px
  xl: 32px
  gutter: 16px
  margin: 24px
---

## Brand & Style

The design system is engineered for high-stakes cybersecurity environments, specifically Endpoint Detection & Response (EDR) platforms. The brand personality is authoritative, vigilant, and high-performance. It balances a "Command Center" aesthetic with modern SaaS usability.

The design style utilizes **Corporate Modern** structures infused with **Cyberpunk-Minimalism**. This is achieved through a deep dark-mode foundation, high-contrast semantic signaling, and subtle neon glows that highlight active threats or system states. The interface prioritizes information density and rapid cognitive processing, using crisp borders and mechanical precision to instill a sense of security and control.

## Colors

The palette is anchored by **Midnight Blue** (`#0A0F1E`) to reduce eye strain during long monitoring shifts. **Neon Blue** (`#00E5FF`) serves as the primary action color and focal point for active telemetry.

### Semantic Triage
Color is the primary vehicle for urgency. Use these strictly:
- **Critical (Crimson):** Immediate action required. Used for active breaches and malware execution.
- **High (Orange):** Suspicious lateral movement or privilege escalation.
- **Medium (Yellow):** Policy violations or unusual outbound traffic.
- **Low (Green):** Normal system health and successful patches.
- **Info (Blue):** General audit logs and system metadata.

Surfaces use layered variations of the midnight base to create visual hierarchy without relying on heavy shadows.

## Typography

This design system utilizes **Inter** for all UI controls and prose to ensure maximum legibility at small sizes. For technical data, IP addresses, and hash values, **JetBrains Mono** is employed to distinguish machine-readable data from human-readable interface elements.

- **Headlines:** Use tight letter-spacing and semi-bold weights to maintain a compact, "instrument panel" feel.
- **Labels:** Always use the monospaced font for status badges, timestamps, and IDs.
- **Case:** Use ALL CAPS for `label-mono` styles to improve scanability in dense data grids.

## Layout & Spacing

The layout follows a **Fixed Grid** logic for the sidebar and a **Fluid Grid** for the main dashboard content. It uses a rigorous 4px baseline grid to ensure a dense, organized appearance characteristic of professional monitoring tools.

### Grid Configuration
- **Desktop:** 12-column grid with 16px gutters.
- **Tablet:** 8-column grid with 12px gutters.
- **Information Density:** High. Elements should be packed closely, using subtle borders rather than large margins to define boundaries.

### Responsive Behavior
On mobile devices, dashboards collapse into a single-column scroll, with key metrics (Severity counts) pinned to the top in a horizontal scroller.

## Elevation & Depth

Elevation in this design system is communicated through **Tonal Layering** and **Crisp Outlines** rather than soft shadows.

- **Base Level:** `#0A0F1E` (The "Darkroom" background).
- **Surface Level:** `#161D2F` (Card containers, sidebars).
- **Overlay Level:** `#1E293B` (Modals, tooltips).
- **Borders:** 1px solid `#2D3748`. Active or focused elements receive a `0 0 8px` outer glow in the primary action color (`#00E5FF`).
- **Depth:** Use 1px "inner-top" borders on cards to simulate a slightly recessed or beveled edge, reinforcing the hardware-interface aesthetic.

## Shapes

The design system uses a **Soft (0.25rem)** roundedness approach. This provides a professional, technical look that avoids the "playfulness" of highly rounded corners while remaining more modern than sharp 90-degree angles.

- **Components (Buttons, Inputs):** 4px (0.25rem).
- **Cards/Containers:** 8px (0.5rem).
- **Selection Indicators:** Use vertical 2px bars on the left side of active list items rather than rounding the entire background.

## Components

### Buttons
- **Primary:** Solid Neon Blue background, dark text. Add a subtle `drop-shadow` glow on hover.
- **Ghost:** Transparent background with Neon Blue borders. Use for secondary actions like "Export" or "Filter".
- **Severity Buttons:** Small, condensed buttons using the semantic palette for quick status changes.

### Inputs & Search
- Inputs should have a dark, recessed background (`#070B14`) and a prominent 1px border.
- The focus state must use a Neon Blue border with a 4px outer glow.

### Data Tables (EDR Core)
- Zebra striping is discouraged; use 1px horizontal dividers instead.
- Active rows use a 2px Neon Blue left-border highlight.
- Use `label-mono` for all table cell data.

### Status Chips
- Small, rectangular badges with a subtle background tint (15% opacity) and 100% opacity text of the semantic color.
- Example: A "Critical" chip has a dark red background with vibrant crimson text.

### Detection Cards
- Cards feature a "header bar" color-coded by severity.
- Metrics within cards should use the `stats-lg` typography style for immediate visibility of counts (e.g., "42 Affected Endpoints").