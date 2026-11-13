Fixture projects for the docs-example runner (tests/integration/docs/).

Each directory is a project a docs page can start in. A page starts in
sample-project unless a block's marker says fixture=<name>. The runner copies
the directory and commits it to a fresh git repository, so every page sees the
same files and the same history.

Not markdown on purpose: every *.md file in the repository is a docs page to the
docs checks, and these are data.
