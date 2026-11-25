# Captured ShellCheck 0.11.0 output

`positive.json1` and `negative.json1` are the `json1` documents ShellCheck 0.11.0
printed on stdout. The unit tests serve them from a fake subprocess, so they run on
every platform without the binary.

Argv (the form the scanner uses, started in the directory of the input):

```text
shellcheck --norc --format=json1 --severity=style -- bad.sh
```

`bad.sh` is three lines after the shebang:

```sh
#!/bin/bash
echo $1
for f in $(ls); do cat $f; done
x=`date`
```

It gives five comments (SC2086 twice, SC2045, SC2034, SC2006), exit status 1.
`negative.json1` is the output for a clean script, exit status 0.

Facts the captures show and the scanner relies on: every comment has `file`, `line`,
`endLine`, `column`, `endColumn`, `level`, `code`, `message` and a `fix` that is either
null or an object of replacements; `code` is an integer, so the rule id is `SC` plus
that number; the four levels are `error`, `warning`, `info` and `style`.
