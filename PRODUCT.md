# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Existing Flask application with dependency-free HTML, CSS, and JavaScript frontend. No frontend framework should be introduced for this redesign.

## Users

Primarily one person managing personal credentials and secure notes on their own computer. This is inferred from the local-first product brief and repository documentation.

## Product Purpose

Janus stores credentials and secure notes locally, generates strong passwords, and lets the user access those records through a local Flask application. Success means the user can find, create, reveal, copy, and manage secrets with confidence that the default workflow does not depend on a hosted account or online synchronization.

## Positioning

Janus is a personal local vault rather than a managed cloud password service. SQLite is the default storage and the frontend is intentionally dependency-light and inspectable.

## Operating Context

The application runs on the user's own computer, normally at a local address. The main workflows are signing in, viewing credentials, creating credentials, generating passwords, managing encrypted notes, and logging out or locking access.

## Capabilities and Constraints

- Preserve the existing Flask routes, API contracts, HTML IDs, and JavaScript behavior unless a change is required for accessibility or visual clarity.
- Keep the default experience 100% local-first; do not add telemetry, hosted authentication, remote assets, analytics, or synchronization.
- SQLite is the default database.
- Credentials and notes are encrypted or protected by the existing backend security model.
- The frontend must remain dependency-free and responsive.
- Existing terminology includes credentials, secure notes, password generator, account password, master password, and note password.
- The product is educational and personal-use software, not a professionally audited password manager.

## Brand Commitments

- Product name: Janus.
- The visual redesign must move from a generic SaaS dashboard to “Seu Cofre Pessoal”.
- Use charcoal or warm gray backgrounds, ivory or graphite surfaces, copper/amber accents, red only for destructive actions, editorial and precise typography, and monospace only for secrets.
- The Janus mark should suggest two faces or keys and must not use a padlock emoji.

## Evidence on Hand

- Product documentation: README.md and SECURITY.md.
- Current interface: src/frontend/login.html, register.html, dashboard.html, note-access.html, css/style.css, and js/script.js.
- Existing screenshots: docs/screenshots/login.png and docs/screenshots/register.png.
- No testimonials, external brand assets, or verified security certifications are available. Do not fabricate them.

## Product Principles

1. Local by default and explicit about where data lives.
2. Calm and precise around high-risk actions.
3. Fast for the recurring task of finding and copying a credential.
4. Security language should explain behavior rather than make absolute promises.
5. The interface should remain inspectable, lightweight, and useful offline after setup.

## Accessibility & Inclusion

Use semantic HTML, visible keyboard focus, sufficient contrast, labeled controls, status announcements for async actions, reduced-motion support, and responsive layouts that remain usable on narrow screens.
