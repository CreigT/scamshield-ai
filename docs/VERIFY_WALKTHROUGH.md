# VERIFY Walkthrough — No Navigation of Suspect URL

**Goal:** Confirm a check processes content and returns a verdict without the service fetching or navigating the user-supplied URL.

## Steps
1. Start the service locally (`uvicorn app.main:app --reload --port 8080`).
2. POST to /api/check with sample content that includes a clearly fake or controlled URL (e.g. http://example.invalid/test).
3. Observe the response verdict and evidence codes.
4. Confirm in server logs or network monitoring that no request was made to the user-supplied URL itself.
5. Check any audit output: only hash + verdict + evidence codes should appear.

## Pass Criteria
- Verdict is returned.
- No outbound request occurs to the suspect URL.
- Audit contains no raw body.

## Fail Criteria
- Service fetches or navigates the user-supplied URL.
- Raw content appears in audit or logs.
- Service fails hard when external API keys are absent.

This verifies the core boundary stated in the operational card.
