# Contributing

Thanks for your interest! Issues and pull requests are welcome.

- **Bugs:** open an issue with the MLWINT version (Help → About), Windows version, what you did and what you
  expected. Attach anonymised report excerpts, never the file itself (see [SECURITY.md](SECURITY.md)).
- **Development setup:** [docs/building.md](docs/building.md).
- **Before a pull request:** run the self-checks that cover your change (table at the end of `docs/building.md`)
  and `flutter analyze` in `mlwint_app/`.
- **Principles to keep:** read-only (never delete, move, run or upload a user's files); offline by default;
  every score part explained; plain-language advice; models evaluated on time-ordered data with the test weeks
  scored only after every choice is frozen.
- **Models:** detector changes need the Phase 1 evaluation (see `pipeline/` and `docs/methodology.md`) and a new
  `"models"` version in `version.json`.
