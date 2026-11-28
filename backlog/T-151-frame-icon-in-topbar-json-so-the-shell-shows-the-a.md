---
type: Task
title: frame.icon in topbar.json, so the shell shows the application's icon in the frame
status: erledigt
points: 3
id: T-151
milestone: M-2
created: '2026-11-28'
---
# T-151 — frame.icon in topbar.json, so the shell shows the application's icon in the frame

**Story points:** 3

Since T-104 the application icon (`apps[id].icon`) appears on the gate sign-in, in TinySesam's frame and in the area, but not in the shell drawn on the application's host. Add `frame.icon` to `topbar.json` (spec §8d) with vectors and support in the five clients.

## Done (sprint S8, 2026-11-28)

`topbar.data` gives `frame.icon` (`topbar.icon_address`: a path with the origin of `base` in front, B-21; a `data:`
icon unchanged); `shell.js` draws it before the name in the frame (browser test B4 on Ex1, the icon loads from
TinySesam's origin under the Go page's CSP); spec §8d, vectors `frame-icon-*`, the five clients normalise it.
