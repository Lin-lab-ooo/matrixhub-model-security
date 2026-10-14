---
name: QA Task
about: A QA task. Defaults to a subtask of a parent issue
title: "[QA] "
labels: kind/feature, area/test

---
<!-- Defaults to a subtask of a parent (tracking) issue. To use as a standalone/normal issue, overwrite the feature section below with the actual details. -->

**What is the feature and Why is this needed**:

The feature is detailed in the parent issue.

**QA requirements**:

- Document the **test cases / scenarios** to be covered for this feature.
- Ask the **corresponding developer** to review the test cases. **@mention them on this QA task** on the **Test cases reviewed** checklist line when the test cases are ready (replace `@username` with their GitHub username). The developer must leave **at least one constructive comment** on this QA task.
- Perform **manual testing** and record the steps performed and results if necessary(used for later user doc updating).
- **Adjust and verify user docs** on [matrixhub.ai](https://matrixhub.ai): follow the user-facing documentation for this feature(find link in the Doc issue or Dev issue), confirm the steps and examples are accurate and work as described. Paste the verified doc link in the checklist. If the documentation has issues, **open a PR directly** to fix it. If large sections are missing and you are unsure the details, **describe the gap**, then **reopen the Doc or Backend task** and ask the relevant owner to complete the documentation before re-verifying.

---

**Completion checklist**:

- [ ] **Test Cases**:
- [ ] **Test cases reviewed**: @username
- [ ] **Manual Test**
- [ ] **Adjust and verify user docs**:

The artifacts above should be described or linked in this checklist or the associated PR.

Before closing this issue, ensure all checklist items above are completed and checked off.
