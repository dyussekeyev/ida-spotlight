# IDA Spotlight

**IDA Spotlight** is a workflow-centric triage plugin for IDA Pro that helps reverse engineers quickly identify *high-value* functions in large binaries.

Instead of manually scrolling through hundreds or thousands of functions, IDA Spotlight scores, ranks, and explains *why* a function may be interesting — enabling analysts to focus their time where it matters most.

---

## Key Features

### 🔍 Function Scoring & Prioritization
- Scores functions based on:
  - API calls
  - Embedded strings
  - Contextual relationships between functions
- Produces an explainable score with detailed reasons.

### 🚦 Priority Tiers
- Automatically assigns **Critical / High / Medium / Low** priority tiers.
- Priority tiers are computed **only for non-library functions**.
- Library functions are excluded from top-10% / top-30% calculations.

### 📚 Library Function Awareness (FLIRT)
- Detects library functions using IDA’s `FUNC_LIB` flag.
- Library functions:
  - Are hidden by default in the main view.
  - Are visually highlighted in light blue when shown.
  - Receive a configurable score penalty.
  - Are clearly marked in the Inspector.

### 🙌🏻 Dual‑View Workflow
- **IDA Spotlight View**
  - Ranked table of functions.
  - Search and filtering.
  - Context menu actions (inspect, export, copy).
- **IDA Spotlight Inspect**
  - Inspector-only window.
  - Can be synchronized with any `IDA View-A/B/C` or `Pseudocode-A/B/C`.
  - Follows cursor movement like native IDA subviews (Hex View style).

### 📤 Export & Reporting
- Export results to **CSV** or **JSON**.
- Includes scores, priorities, library flags, and reasoning.

---

## Why It Matters

Modern malware and large binaries often contain thousands of functions.
IDA Spotlight reduces cognitive load by:

- Highlighting what deserves attention first.
- Explaining *why* a function is interesting.
- Integrating seamlessly into existing IDA workflows.

The plugin is designed to feel **IDA-native**, not like an external script.

---

## Installation

1. Copy the plugin directory into your IDA plugins folder.
2. Ensure `signals.json` is present next to `ida-spotlight.py`.
3. Launch IDA Pro (9.1+).
4. Open via:

```
View → Open subviews → IDA Spotlight View
```

---

## Animation

![Spotlight View](screenshots/view.gif)
![Spotlight Inspect](screenshots/inspect.gif)

---

## Screenshots

![Spotlight View](screenshots/view.png)
![Spotlight Inspect](screenshots/inspect.png)

---

## Author

**Askar Dyussekeyev**  
Email: dyussekeyev@yandex.kz

---

## License

Apache-2.0

