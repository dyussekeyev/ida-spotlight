# 🔦 IDA Spotlight

**IDA Spotlight** is a workflow-centric triage and correlation plugin for IDA Pro that helps reverse engineers quickly identify *high-value* functions in large binaries and *correlate* the current binary with previously analyzed samples.

Spotlight is not just a scoring tool — it is a knowledge-driven analysis assistant.

---

## Key Features

### 🔍 Function Scoring & Prioritization
- Scores functions based on API calls, strings, and contextual relationships.
- Produces an explainable score with detailed reasons.

### 🚦 Priority Tiers
- Automatically assigns **Critical / High / Medium / Low** priority tiers.
- Priority tiers are computed **only for non-library functions**.
- Library functions are excluded from top-10% / top-30% calculations.

### 📚 Library Function Awareness (FLIRT)
- Detects library functions using IDA’s ^FUNC_LIB^ flag.
- Library functions are deprioritized and visually marked.
- Priority tiers are computed only for non-library code.

### 💡 Spotlight Knowledge Base (KB)
Spotlight maintains a *SQLite*-based knowledge base of previously analyzed IDBs.
Each indexed IDB stores structural features such as:
- Import fingerprints
- Imported function names
- Section name profiles
- Function name normalization
The KB enables correlation between the current IDB and historical samples.

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

