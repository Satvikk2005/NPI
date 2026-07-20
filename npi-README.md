# NPI Dashboard — Supervisor Console

A lightweight, no-build-step dashboard for tracking New Product Introduction
(NPI) programs — modeled on your VECV/Eicher PMO tracker slides (Pro 8035XM,
VE5158, Pro 3019, etc.)

## Files

| File                  | Purpose                                          |
|------------------------|---------------------------------------------------|
| `npi-dashboard.html`  | **Everything** — HTML, CSS, and JS in one file    |

That's it — just one file. No separate stylesheet, no separate script file,
nothing to keep in the same folder or accidentally rename and break.

## How to run it

1. Download `npi-dashboard.html`.
2. Double-click it (or open it in any browser).

If you want it on a shared network drive / intranet so multiple supervisors
can open the same link, host this single file on any static file server
(IIS, nginx, or even `python -m http.server` from that folder) and share the
URL.

## Editing project data

Since everything is in one file now, your project data (the `PROJECT_DATA`
object) lives inside `npi-dashboard.html` itself, inside the first
`<script>` block near the bottom of the file. Open the file in a text editor
(Notepad, VS Code, etc.) — not a browser — to find and edit it.

Search for `const PROJECT_DATA = {` to jump straight to it. Each program is a
`project({...})` block under the right `line` (`MHD` or `HD`) → `classId`
(`"1"`, `"2"`, `"3"`). Copy an existing block, change the fields, save, and
reload the page in your browser.

## Navigation flow

```
Landing ("NPI Dashboard")
   │
   ├── MHD ──► Class 1 / 2 / 3 ──► Program list ──► Program dashboard
   └── HD  ──► Class 1 / 2 / 3 ──► Program list ──► Program dashboard
```

Each step is a click. The breadcrumb at the top (NPI / HD / Class 3 / Program
name) lets you jump back to any earlier step. The URL hash updates as you
navigate (e.g. `#HD/class-3/ve5158-new-hd-cabin`), so you can bookmark or
share a direct link to one program's dashboard.

## What's on a program dashboard

- **Status banner** — Y (on track) / R (at risk) / G (ahead/complete), click the
  dropdown in the meta strip to change it.
- **Meta strip** — CPM, Code, EPL, SOP target, Status. Click any value to edit
  it in place.
- **Phase timeline** — PreStudy → Concept Study → Detail Dev. → Final Dev. →
  Industrialization → Follow Up, with your week-codes (W2440 etc.) shown as
  chips under each phase. Click a phase bar to mark it as the current phase
  (it gets the amber highlight ring).
- **Topic Tracker** — the Q/D table from your slides (PFD/PFMEA/AOS, SOP/QC
  Sheet, Fixture Tools, etc.) with Plan, Actual, RYG status, and Remarks — all
  editable in place. "+ Add topic row" appends a new tracked item.
- **NCR table** — Design/Part/Process rows with G / Y(P1-P3) / R(P1-P3) /
  Total, same shape as your VDFA observation tables. Totals row recalculates
  automatically as you edit.
- **Achievements / Upcoming Activities / Support Required** — the three
  bullet-list panels from your slides. Click text to edit, ✕ to remove, "+
  add" to append.
- **Notes block** (optional, bottom right) — for anything like your "VE5158
  Key Dates" or "Applicable Models" panels.

## Saving

Every edit saves automatically to the browser's local storage on that device
— there's no backend, so it's instant and offline-friendly. Refreshing the
page keeps your edits. There's nothing to click to "save."

**Note on scope:** local storage is per-browser, per-device. If you need the
same data visible to multiple supervisors across different computers, you'll
need a small shared backend (see "Going further" below) — happy to build that
next if useful.

### Resetting to the original PPT data

If edits get messy and you want to start over from the original slide data,
press **Alt+Shift+R** anywhere in the app and confirm. This wipes local edits
and reloads everything fresh from the seed data in the file.

## Adding a new program

Two ways:

1. **Through the UI** — open a class that has zero programs and click "+ Add
   Program."
2. **Directly in the file** — open `npi-dashboard.html` in a text editor,
   find `const PROJECT_DATA = {`, copy an existing `project({...})` block
   under the right `line` → `classId`, change the fields, save, and reload.
   This is the more reliable way to seed a full program with all its
   milestones/topics/NCR rows at once, mirroring exactly how the PPT slide is
   laid out.

## Editing colors / look

Everything visual is controlled by CSS variables near the top of the
`<style>` block (`:root { ... }`) — `--amber`, `--safety-red`,
`--signal-green`, `--steel-900`, etc. Change a value there and it updates
everywhere.

## Going further (optional, tell me if you want any of these)

- **Shared/cloud storage** so all supervisors see the same live data instead
  of per-device local storage (would need a small backend — happy to build
  with Python/Flask or a simple cloud database).
- **Export to PDF/PPT** in the exact slide format you already use for
  leadership reviews.
- **Login / role-based access** (supervisor edit vs. viewer read-only).
- **Weekly snapshot history** so you can see how a program's RYG status
  trended over past weeks instead of only the current state.
- **Search/filter** across all programs (e.g. "show me everything that's
  currently Red").
