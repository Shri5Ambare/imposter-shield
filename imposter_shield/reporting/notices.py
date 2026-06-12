"""Non-copyright notice drafts: defamation and fraud/scam report narratives.

DMCA (in dmca.py) only addresses stolen *photos*. The two harms that actually
hurt victims need different tracks:

  - **Financial scam** -> platform impersonation/fraud report, flagged that the
    account is defrauding third parties (escalates to high priority).
  - **Defamation** -> platform defamation report and/or a documented notice.
    Defamation law is jurisdiction-specific, so this is a DRAFT for the
    complainant (and ideally their lawyer) to finalize — never auto-sent.

All output is review-required text. Nothing here sends anything.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date


@dataclass
class FraudReport:
    platform: str
    impostor_url: str
    real_handle: str
    incidents: list[str]            # short descriptions of scam attempts
    victim_count: int | None = None

    def render(self) -> str:
        bullets = "\n".join(f"  - {i}" for i in self.incidents)
        vc = f"\nKnown affected users: at least {self.victim_count}." if self.victim_count else ""
        return f"""PLATFORM REPORT — IMPERSONATION WITH FINANCIAL FRAUD
Date: {date.today():%B %d, %Y}
Platform: {self.platform}

The account at {self.impostor_url} is impersonating {self.real_handle} and is
actively using that false identity to solicit money from that person's audience.
This is not a passive impersonation; it is causing financial harm to third
parties and should be treated as fraud, not a routine name dispute.

Documented incidents:
{bullets}{vc}

Requested action: immediate suspension of the account pending review, given
ongoing financial harm to users who believe they are interacting with the
genuine account holder.

[REVIEW REQUIRED] Verify each incident and attach the evidence dossier before a
human submits this through the platform's official reporting form.
"""


@dataclass
class DefamationNotice:
    complainant_name: str
    contact_email: str
    platform: str
    impostor_url: str
    false_statements: list[str]     # the specific damaging false claims
    jurisdiction: str = "[your jurisdiction]"
    attachments: list[str] = field(default_factory=list)

    def render(self) -> str:
        items = "\n".join(f"  {n}. \"{s}\"" for n, s in enumerate(self.false_statements, 1))
        return f"""NOTICE OF DEFAMATORY IMPERSONATION  (DRAFT — legal review required)
Date: {date.today():%B %d, %Y}
To: Trust & Safety / Legal, {self.platform}

I, {self.complainant_name}, am the subject of an impersonation account at
{self.impostor_url}. The account publishes false statements of fact, attributed
to me, that injure my reputation. The following statements are false and were not
made by me:
{items}

These statements are presented as my own words to third parties and are causing
reputational harm. I request removal of the account and the offending content.

This notice is governed by the defamation law of {self.jurisdiction}, which
varies by location; this draft should be reviewed by counsel before sending, and
finalized with the correct legal standard and any required formalities.

Contact: {self.complainant_name} <{self.contact_email}>

[REVIEW REQUIRED] Do not send without legal review. Truth, opinion, and
jurisdiction-specific elements must be confirmed by a qualified attorney.
"""
