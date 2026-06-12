"""DMCA takedown-notice drafting.

Generates a complete, legally-structured 17 U.S.C. §512(c) notice for a human to
review, sign, and send to the platform's *registered* copyright agent. We
deliberately stop short of auto-sending: a DMCA notice is a sworn legal statement
("under penalty of perjury"), so a named human must own it.

Designated-agent contacts are looked up in the U.S. Copyright Office DMCA
directory (https://dmca.copyright.gov/osp/), not hardcoded guesses — addresses
change and a misdirected notice is a void notice.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date


@dataclass
class DMCAClaim:
    complainant_name: str         # the real rights-holder (or authorized agent)
    complainant_title: str        # e.g. "self" or "authorized agent for <name>"
    contact_email: str
    contact_address: str
    contact_phone: str
    original_work_urls: list[str]      # where the genuine photos legitimately live
    infringing_urls: list[str]         # the stolen copies on the impostor account
    platform_name: str
    work_description: str = "original photographs of the complainant"


def designated_agent_hint(platform_name: str) -> str:
    """Pointer to the authoritative source, not a hardcoded address."""
    return (
        f"Look up {platform_name}'s current DMCA designated agent at "
        "https://dmca.copyright.gov/osp/ before sending. Many platforms also "
        "provide a web copyright form (preferred over email)."
    )


def render_notice(claim: DMCAClaim) -> str:
    today = date.today().strftime("%B %d, %Y")
    originals = "\n".join(f"  - {u}" for u in claim.original_work_urls)
    infringing = "\n".join(f"  - {u}" for u in claim.infringing_urls)

    return f"""DMCA TAKEDOWN NOTICE
Date: {today}

To: Designated Copyright Agent, {claim.platform_name}
({designated_agent_hint(claim.platform_name)})

Re: Notice of Copyright Infringement under 17 U.S.C. § 512(c)

To Whom It May Concern,

I, {claim.complainant_name} ({claim.complainant_title}), submit this notice
regarding the unauthorized use of copyrighted material on your service.

1. IDENTIFICATION OF THE COPYRIGHTED WORK
   The work is {claim.work_description}, for which I am the copyright owner or
   am authorized to act on the owner's behalf. The original work is published at:
{originals}

2. IDENTIFICATION OF THE INFRINGING MATERIAL
   The following URLs host copies of my work used without authorization:
{infringing}

3. GOOD-FAITH STATEMENT
   I have a good-faith belief that the use of the material described above is not
   authorized by the copyright owner, its agent, or the law.

4. ACCURACY STATEMENT (under penalty of perjury)
   The information in this notice is accurate, and I swear, under penalty of
   perjury, that I am the copyright owner or am authorized to act on behalf of
   the owner of an exclusive right that is allegedly infringed.

5. CONTACT INFORMATION
   Name:    {claim.complainant_name}
   Address: {claim.contact_address}
   Phone:   {claim.contact_phone}
   Email:   {claim.contact_email}

6. SIGNATURE
   ____________________________________   Date: ________________
   {claim.complainant_name}

[REVIEW REQUIRED] This draft must be read, verified for accuracy, and signed by
the named complainant before sending. Sending a knowingly false notice carries
liability under 17 U.S.C. § 512(f).
"""


@dataclass
class DMCAPackage:
    notice_text: str
    send_to_hint: str
    attachments: list[str] = field(default_factory=list)  # dossier PDF path(s)


def build_package(claim: DMCAClaim, dossier_pdf: str | None = None) -> DMCAPackage:
    return DMCAPackage(
        notice_text=render_notice(claim),
        send_to_hint=designated_agent_hint(claim.platform_name),
        attachments=[dossier_pdf] if dossier_pdf else [],
    )
