"""Evidence dossier generation.

Produces a structured PDF a human can attach to a support ticket or DMCA notice:
side-by-side photo comparison, EXIF/provenance findings, timeline discrepancy,
the per-signal score breakdown, and exact URLs. A good dossier is what turns an
auto-ignored report into an actioned one — because a moderator can verify the
claim in seconds.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class DossierData:
    case_id: str
    protected_name: str
    protected_handle: str
    suspect_url: str
    suspect_handle: str
    confidence: float
    score_breakdown: dict
    notes: list[str] = field(default_factory=list)
    truth_image_path: str | None = None
    suspect_image_path: str | None = None
    exif_findings: list[str] = field(default_factory=list)
    timeline: list[tuple[str, str]] = field(default_factory=list)  # (label, value)
    reviewer: str = "UNASSIGNED"


def build_dossier(data: DossierData, out_path: str) -> str:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage,
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

    styles = getSampleStyleSheet()
    h = styles["Heading2"]
    body = styles["BodyText"]
    small = ParagraphStyle("small", parent=body, fontSize=8, textColor=colors.grey)

    story = []
    story.append(Paragraph("Impersonation Evidence Dossier", styles["Title"]))
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    story.append(Paragraph(
        f"Case {data.case_id} &nbsp;•&nbsp; generated {generated} &nbsp;•&nbsp; "
        f"prepared for review by <b>{data.reviewer}</b>", small))
    story.append(Spacer(1, 0.2 * inch))

    # --- summary -----------------------------------------------------------
    story.append(Paragraph("1. Summary", h))
    summary = [
        ["Protected identity", f"{data.protected_name} (@{data.protected_handle})"],
        ["Suspected impostor", f"@{data.suspect_handle}"],
        ["Suspect URL", data.suspect_url],
        ["Confidence score", f"{data.confidence:.0%}"],
    ]
    t = Table(summary, colWidths=[1.8 * inch, 4.5 * inch])
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("BACKGROUND", (0, 0), (0, -1), colors.whitesmoke),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.2 * inch))

    # --- side-by-side images ----------------------------------------------
    if data.truth_image_path and data.suspect_image_path:
        story.append(Paragraph("2. Photo comparison", h))
        try:
            imgs = [[
                RLImage(data.truth_image_path, width=2.6 * inch, height=2.6 * inch),
                RLImage(data.suspect_image_path, width=2.6 * inch, height=2.6 * inch),
            ], [
                Paragraph("Official photo (Source of Truth)", small),
                Paragraph("Photo on suspected impostor account", small),
            ]]
            it = Table(imgs, colWidths=[3.1 * inch, 3.1 * inch])
            it.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER")]))
            story.append(it)
        except Exception as exc:  # noqa: BLE001
            story.append(Paragraph(f"[images unavailable: {exc}]", small))
        story.append(Spacer(1, 0.2 * inch))

    # --- findings ----------------------------------------------------------
    story.append(Paragraph("3. Findings", h))
    for note in data.notes:
        story.append(Paragraph(f"• {note}", body))
    for ex in data.exif_findings:
        story.append(Paragraph(f"• EXIF: {ex}", body))
    story.append(Spacer(1, 0.15 * inch))

    # --- timeline ----------------------------------------------------------
    if data.timeline:
        story.append(Paragraph("4. Timeline", h))
        tl = Table([["Event", "Date"]] + [[k, v] for k, v in data.timeline],
                   colWidths=[3.5 * inch, 2.8 * inch])
        tl.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
        ]))
        story.append(tl)
        story.append(Spacer(1, 0.2 * inch))

    # --- score breakdown ---------------------------------------------------
    story.append(Paragraph("5. How the score was computed", h))
    for k, v in data.score_breakdown.items():
        if k in ("inputs", "weights"):
            continue
        story.append(Paragraph(f"• {k}: {v}", small))

    story.append(Spacer(1, 0.3 * inch))
    story.append(Paragraph(
        "This dossier was assembled by an automated system and reviewed by the named "
        "human above prior to submission. Scores are advisory evidence, not adjudication.",
        small))

    SimpleDocTemplate(out_path, pagesize=letter).build(story)
    return out_path
