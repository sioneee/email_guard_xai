# Codex Instructions

## Efficiency
Minimize token and usage consumption.

- Do not scan the entire repository unless necessary.
- Read only files relevant to the current task.
- Prefer targeted searches over opening many files.
- Do not repeatedly read files whose relevant contents are already known.
- Keep explanations concise unless I request details.
- Do not perform unnecessary analysis or exploration.

## Before Editing

Before modifying code:

1. Identify the minimum set of files required.
2. Inspect only those files.
3. Preserve the existing architecture whenever possible.
4. Prefer minimal changes over large refactoring.

If the task can be completed by modifying one file, do not modify unrelated files.

## Code Changes

- Make the smallest change necessary to complete the task.
- Do not refactor unrelated working code.
- Do not rename files, functions, variables, or directories unless necessary.
- Do not add unnecessary dependencies.
- Preserve existing behavior unless the requested task requires changing it.

## Testing

- Run only tests relevant to the modified code.
- Do not run the entire test suite unless necessary or explicitly requested.
- Do not repeatedly run the same command without a reason.
- If a command fails, inspect the error before retrying.

## Project Exploration

When locating code:

1. Search for relevant symbols, filenames, or keywords first.
2. Open only the most relevant files.
3. Expand exploration only when required.

Avoid reading large datasets, generated files, binaries, model files,
virtual environments, caches, build outputs, or dependency directories
unless explicitly required.

Ignore these directories/files when possible:

- node_modules/
- .git/
- .venv/
- venv/
- __pycache__/
- dist/
- build/
- datasets/
- data/
- *.csv
- *.parquet
- *.pkl
- *.joblib
- large binary/model files

## Communication

Keep responses short and practical.

After making changes, report only:

1. Files changed
2. What changed
3. Whether relevant tests passed
4. Any remaining issue

Do not provide long explanations unless requested.

## Important

If completing a task would require scanning a large portion of the
repository, downloading large files, retraining a model, or performing
expensive operations, explain why first and wait for confirmation.