"""Minimal end-to-end example (no network, no heavy models actually invoked).

Shows the data flow: Source of Truth + a suspect candidate -> score -> review
decision. Swap the stubbed signals for real verification calls once deps are
installed (`pip install -r requirements.txt`).
"""
from imposter_shield.core import scoring
from imposter_shield.reporting import dmca


def main() -> None:
    # --- pretend verification already ran and produced these signals ----------
    decision = scoring.fuse(
        scoring.SignalInputs(
            face=0.94,             # strong facial match to a Source-of-Truth photo
            text=0.88,             # bio is a close paraphrase
            watermark_hit=True,    # our invisible watermark found on their image
            account_age_days=12,
            followers=30,
            following=900,
            network_overlap=0.42,
        ),
        review_threshold=0.90,
    )

    print(f"confidence: {decision.score:.0%}")
    print(f"enters human review queue: {decision.enters_review}")
    print("why:")
    for note in decision.notes:
        print(f"  - {note}")

    # --- if it qualifies, draft (do not send) a DMCA notice -------------------
    if decision.enters_review:
        pkg = dmca.build_package(
            dmca.DMCAClaim(
                complainant_name="Jane Doe",
                complainant_title="self",
                contact_email="jane@example.com",
                contact_address="123 Main St, Springfield",
                contact_phone="+1-555-0100",
                original_work_urls=["https://instagram.com/real_jane"],
                infringing_urls=["https://instagram.com/real_jane_official1"],
                platform_name="Instagram",
            )
        )
        print("\n--- DMCA DRAFT (review & sign before sending) ---")
        print(pkg.notice_text)
        print("send to:", pkg.send_to_hint)


if __name__ == "__main__":
    main()
