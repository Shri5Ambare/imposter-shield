"""Attended report-form assistant.

This is the deliberately *human-in-the-loop* version of "automated reporting".

What it does:
  - Opens the platform's official impersonation/report form in a HEADED browser.
  - Pre-fills the fields it can (your contact info, the suspect URL, a description
    drawn from the dossier) using ordinary, documented selectors.
  - Then STOPS, surfaces the page to a human, and waits. The human reads the
    pre-filled form, handles any identity/CAPTCHA step themselves, and clicks
    submit.

What it deliberately does NOT do:
  - No CAPTCHA solving, no fingerprint spoofing, no proxy rotation, no headless
    stealth. If the platform wants to confirm a human is filing, a human is.
  - No unattended/bulk submission loop. One case, one human, one click.

Why it's built this way: an automated pipeline that defeats a platform's
anti-abuse controls and files reports on its own is the exact tooling used for
false-report brigading. Keeping submission attended keeps reports credible (they
don't get bulk-discarded as bot traffic) and keeps every filing attributable to a
named person — which is also what makes them effective.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ReportContext:
    report_form_url: str          # the platform's official impersonation form
    suspect_url: str
    reporter_name: str
    reporter_email: str
    description: str              # short narrative, usually summarised from dossier
    dossier_pdf: str | None = None
    # Map of {logical field -> CSS selector}. Supplied per-platform from config,
    # using each platform's own documented form. No scraping of protected flows.
    field_selectors: dict = field(default_factory=dict)


def prefill_and_handoff(ctx: ReportContext, *, attach: bool = True) -> None:
    """Open the form, fill what we safely can, then yield to the human.

    Runs HEADED on purpose. Returns only after the human closes the browser, so
    the calling worker can record 'submitted by <reviewer>' from the dashboard.
    """
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        # headless=False is intentional and load-bearing: a person watches and submits.
        browser = p.chromium.launch(headless=False)
        page = browser.new_page()
        page.goto(ctx.report_form_url, wait_until="domcontentloaded")

        sel = ctx.field_selectors
        # Best-effort fill; missing selectors are skipped, never forced.
        for logical, value in (
            ("name", ctx.reporter_name),
            ("email", ctx.reporter_email),
            ("suspect_url", ctx.suspect_url),
            ("description", ctx.description),
        ):
            css = sel.get(logical)
            if not css:
                continue
            try:
                page.fill(css, value, timeout=5000)
            except Exception:  # noqa: BLE001 - layout drift shouldn't abort handoff
                pass

        if attach and ctx.dossier_pdf and sel.get("attachment"):
            try:
                page.set_input_files(sel["attachment"], ctx.dossier_pdf, timeout=5000)
            except Exception:  # noqa: BLE001
                pass

        _show_handoff_banner(page)

        # Block until the human is done. We never click submit ourselves.
        try:
            page.wait_for_event("close", timeout=0)
        except Exception:  # noqa: BLE001 - browser closed by reviewer
            pass
        finally:
            try:
                browser.close()
            except Exception:  # noqa: BLE001
                pass


def _show_handoff_banner(page) -> None:
    """Inject a visible banner so the reviewer knows the form is theirs to submit."""
    page.evaluate(
        """() => {
            const b = document.createElement('div');
            b.textContent = 'ImposterShield pre-filled this form. REVIEW the details, '
                + 'complete any human verification, then submit it yourself.';
            Object.assign(b.style, {
                position: 'fixed', top: '0', left: '0', right: '0', zIndex: 2147483647,
                background: '#b91c1c', color: 'white', font: '600 14px system-ui',
                padding: '10px 14px', textAlign: 'center'
            });
            document.body.appendChild(b);
        }"""
    )
