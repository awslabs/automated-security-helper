ash.sarif is the SARIF the visual suite's stub ASH CLI writes (see ui-test-in-container.sh).

It is ../../test/resources/real-cli/exit1/ash.sarif, the captured real ASH 3.7.0 exit-1 run, with
two results appended and nothing else changed:

  UI-FIXTURE-WARNING  level "warning", leak.py line 1, columns 15-37 ("packaging verification")
  UI-FIXTURE-NOTE     level "note",    leak.py line 1, columns 39-60 ("Not a real credential")

The capture holds three findings, all "error", so on its own the editor scene would render the
error highlight style only, and a change to how a warning or a note is drawn would pass every
scene. The two added results give each level its own pixels. They sit on line 1, apart from each
other and from the errors on line 2, so no two highlights overlap and blend.

The aggregated results file and the console tail are still replayed from the capture unchanged:
the plugin counts findings from the SARIF, and reads only scanner status from the aggregated file.

To regenerate: load the capture, deep-copy its first result twice, set ruleId, level, message and
the region (startLine/endLine 1, startColumn, endColumn, snippet), append both, and write the
JSON back compact, as the capture is (separators "," and ":", no trailing newline).
