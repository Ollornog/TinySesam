---
type: Task
title: Panel field for the app of an invitation
status: offen
points: 1
id: T-157
milestone: M-5
created: '2026-11-28'
---
# T-157 — Panel field for the app of an invitation

**Story points:** 1

Follow-up of T-152. create_invite takes app= so the registration page appears in the app's frame, but the admin panel offers the field only in the JSON API. Add a select of the configured apps to the invitation form. Acceptance: browser test creates an invitation with an app from the panel and the registration page shows that app's frame.
