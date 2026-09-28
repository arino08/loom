# Major project review materials (Group 14)

| File | What it is |
|------|------------|
| `Loom_Major_Project_Presentation.pptx` | 16-slide IEEE-style deck with native architecture/flow diagrams and speaker notes |
| `Presenter1_…pdf` – `Presenter4_…pdf` | Speaking scripts: running order, per-slide script, live-demo runbook, jury Q&A, key numbers |
| `Presentation_Run_of_Show_and_Full_Script.pdf` | The whole presentation start to finish: roles, stage setup, countdown, minute-by-minute timeline, full script with demo keypresses, contingencies, Q&A routing |
| `Loom_Technical_Design_and_Security_Report.pdf` | How every part works, with the cryptography and sandbox explained in depth |

`src/` holds the generators (pptxgenjs for the deck, ReportLab for the PDFs) and the
figures used in the report, so the materials can be regenerated after edits.

The live demo is driven by `demo/present.sh` (one keypress per scenario); see the run of show.
