# Historical security UI acceptance on a fresh fixture

This is an execution guide, not an acceptance result. Use a newly initialized
fixture and credentials supplied only through its dedicated setup channel. Keep
all previous account helpers, passwords and sessions out of the run. Mount the
newly built `ui/dist` read-only in the API runtime; an old image's cached UI does
not validate this change.

1. Seed a private model with at least two real commits: a benign older revision
   with a completed report and an inert blocked revision with a completed report.
   Reuse the explicitly authorized new-empty app helper and its actual HTTP/SDK
   uploads. Record the complete immutable IDs in memory/public result metadata.
2. Sign in normally and open the model's security card. Choose its main branch.
   The historical selector must show title, author date and short SHA. Open the
   identity details and compare the displayed complete SHA with the API commit.
3. Select the benign older commit, then the newer blocked commit. While the next
   request is pending, the former commit's evidence must disappear. Once loaded,
   the overview/evidence must match the selected complete SHA, report ID and
   generation. A stale or mismatched response must produce the mismatch error.
   Repeat quickly in both directions to exercise response ordering.
4. Add a branch and tag with the same display name pointing to different commits
   when the fixture API supports it. Select each group in turn. Requests use
   `refs/heads/...` and `refs/tags/...`, so each history must resolve correctly.
5. For pagination, seed a separate model with 21 or more small inert text-only
   commits through real uploads. Page 1 requests 20 commits; page 2 requests the
   next page. Browsing a page preserves the already selected immutable report.
   Choosing another commit changes it. A selected commit absent from the page is
   retained as a clearly labeled selected item. Search applies only to this page.
6. Grant a newly created account read-only access to this private model. It must
   browse commit history and security evidence, while rescan/cancel/policy write
   controls remain unavailable. An account with no model read access must receive
   the normal API denial; the selector must show the error and must not reuse a
   previous model's options or reports.
7. Use an empty model/revision to check the empty state. Interrupt only the owned
   fixture API or use an isolated request-failure test to check commit-list error
   and retry. Restore it and retry. Keep server admission fail-closed throughout.

Capture only public screenshots/result codes, selected complete SHA, report ID,
generation, page/request parameters and actual outcome. Do not export cookies,
access tokens, browser storage, passwords or raw request headers. Distinguish
actual browser observations from API seed results and automated unit tests.

Local automated regression: `node node_modules/vitest/vitest.mjs run
src/features/models/security` inside `ui/`. The asynchronous QueryObserver test
checks that selecting a different complete SHA clears a previous pass while the
new request is pending; option tests reject abbreviated and duplicate IDs.
