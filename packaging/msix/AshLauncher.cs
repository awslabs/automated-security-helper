// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// The executable an MSIX Application entry points at.
//
// WHY THIS FILE EXISTS AT ALL
//
// The .deb and .rpm create ASH's virtualenv in a post-install scriptlet and put a shell
// wrapper on PATH. MSIX has no post-install hook: a package is a signed, immutable
// directory that Windows extracts under C:\Program Files\WindowsApps and never executes
// anything from at install time. So the venv cannot exist when the package is installed,
// and the only moment left to create it is the first time a user runs ASH. That is what
// this program does, and it is the entire reason a compiled launcher is in the payload
// instead of a one-line script.
//
// The venv also cannot live inside the package, because the package is read only. It goes
// under %LOCALAPPDATA%\ash\venv. Writes to AppData pass through for a mediumIL packaged app
// rather than being redirected into a per-package store, so that path is the one a user sees
// and can delete.
//
// WHY IT IS NOT A .CMD OR .PS1
//
// Application/@Executable must name a file ending in .exe. A batch file cannot be an
// Application target, and a launcher that shelled out to powershell.exe for every
// invocation would pay a process start on every scan and would have to re-quote the user's
// arguments through a second parser, which is the classic way a path with a space in it
// starts failing.
//
// WHY THREE COPIES OF ONE SOURCE
//
// [project.scripts] declares three console scripts (ash, ashv3, automated-security-helper)
// and all three must be reachable. MSIX documents one app execution alias per Application,
// so there are three Applications, and each needs its own Executable. Rather than three
// near-identical sources, msix.py compiles THIS source three times to three output names
// and the program reads its own filename to decide which venv console script to run.
//
// That indirection is deliberate: it means `ashv3.exe` runs the venv's `ashv3.exe`, so the
// deprecation warning users see comes from the wheel's own run_ashv3 wrapper. A launcher
// that hardcoded "always run ash" would silently drop that warning, and a launcher that
// printed its own warning would be a second copy of a message that already exists.
//
// It reads its own FILE NAME rather than the alias that was typed, on purpose. A process
// started through an app execution alias cannot reliably report which alias invoked it, so
// deriving behavior from the alias would rest on an undocumented mechanism. The filename
// inside the package is fixed at pack time and msix.py asserts it matches the alias, so the
// two agree without this program having to ask the OS which name was used.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

internal static class AshLauncher
{
    // Both overrides exist for the verification script, which has to drive a first run and a
    // warm run without touching the developer's real venv, and for a user whose LOCALAPPDATA
    // is on a slow or full volume.
    private const string VenvOverrideVariable = "ASH_MSIX_VENV";
    private const string PythonOverrideVariable = "ASH_MSIX_PYTHON";

    // The probe below must print this exact token. An interpreter that is too old prints the
    // other one, and the Microsoft Store's python.exe placeholder (which opens the Store
    // rather than running anything) prints neither. Testing the exit code alone would read
    // that placeholder as a working Python.
    private const string PythonOkToken = "ASH_PY_OK";
    private const string PythonOldToken = "ASH_PY_OLD";

    private static int Main()
    {
        try
        {
            string launcherPath = Process.GetCurrentProcess().MainModule.FileName;
            string packageRoot = Path.GetDirectoryName(launcherPath);
            string scriptName = Path.GetFileNameWithoutExtension(launcherPath);

            string venvDirectory = ResolveVenvDirectory();
            string target = Path.Combine(venvDirectory, "Scripts", scriptName + ".exe");

            if (!File.Exists(target))
            {
                CreateVenv(venvDirectory, packageRoot, scriptName);
            }

            return Run(target);
        }
        catch (LauncherError error)
        {
            // A named failure with a next step. Everything this program deliberately fails at
            // is a condition the user can act on (no Python, no index, unwritable
            // LOCALAPPDATA), so a bare stack trace would be strictly worse than a sentence.
            Console.Error.WriteLine("ash: " + error.Message);
            return 1;
        }
        catch (IOException error)
        {
            // Disk full, LOCALAPPDATA on a disconnected redirected profile, a venv directory
            // held open by another process. Also user-actionable, but the message comes from
            // Windows rather than from this program, so it is passed through with the path.
            Console.Error.WriteLine("ash: file system error while preparing the virtualenv: " + error.Message);
            return 1;
        }
        catch (UnauthorizedAccessException error)
        {
            Console.Error.WriteLine("ash: permission denied while preparing the virtualenv: " + error.Message);
            return 1;
        }
        // Anything else is a defect in this launcher rather than a condition a user can fix,
        // and is deliberately left to crash with a stack trace. Swallowing it into a tidy
        // sentence would make a bug here indistinguishable from a broken environment.
    }

    private static string ResolveVenvDirectory()
    {
        string overridden = Environment.GetEnvironmentVariable(VenvOverrideVariable);
        if (!string.IsNullOrEmpty(overridden))
        {
            return overridden;
        }

        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrEmpty(localAppData))
        {
            throw new LauncherError(
                "could not locate LOCALAPPDATA, so there is nowhere to create ASH's " +
                "virtualenv. Set " + VenvOverrideVariable + " to a writable directory.");
        }

        return Path.Combine(localAppData, "ash", "venv");
    }

    // Creates the venv in a sibling staging directory and moves it into place when it is
    // known good. Two reasons, and the second is the one that bites.
    //
    // A half built venv left at the real path by an interrupted or failed install would be
    // found by the next run, which checks only whether the console script exists; the run
    // after that would then fail in a way that looks nothing like "the first run did not
    // finish". Staging means the real path either does not exist or is complete.
    //
    // And two shells can run ash for the first time at the same moment. Both build their own
    // staging directory; the first to finish moves it into place and the second discovers the
    // destination already exists, discards its own work and continues. Directory.Move fails
    // rather than merging when the destination exists, which is what makes that check honest.
    private static void CreateVenv(string venvDirectory, string packageRoot, string scriptName)
    {
        string wheel = FindTheWheel(packageRoot);
        string python = FindPython();

        string staging = venvDirectory + ".staging-" + Process.GetCurrentProcess().Id;
        if (Directory.Exists(staging))
        {
            Directory.Delete(staging, true);
        }

        // Progress goes to stderr, not stdout. A first run can take a minute while pip
        // resolves ASH's dependencies, so saying nothing looks like a hang; but ASH's stdout
        // is read by scripts, and a banner mixed into it would corrupt a piped report.
        Console.Error.WriteLine("ash: first run, creating a virtualenv at " + venvDirectory);
        Console.Error.WriteLine("ash: this resolves ASH's dependencies from a Python index and happens once.");

        try
        {
            RunOrThrow(
                python.Executable,
                python.PrefixArguments + "-m venv " + Quote(staging),
                "failed to create a virtualenv with " + python.Description + ".");

            string stagedPython = Path.Combine(staging, "Scripts", "python.exe");
            if (!File.Exists(stagedPython))
            {
                throw new LauncherError(
                    "python -m venv reported success but produced no " + stagedPython + ".");
            }

            // The wheel comes from the package; its DEPENDENCIES come from an index. That
            // split is the whole reason this package is not self contained, and README.msix
            // documents it along with the offline wheelhouse commands.
            RunOrThrow(
                stagedPython,
                "-m pip install --disable-pip-version-check --no-warn-script-location " + Quote(wheel),
                "failed to install " + Path.GetFileName(wheel) + " into the new virtualenv. " +
                "This step needs a reachable Python package index; see README.msix for how " +
                "to stage a wheelhouse on a host that has none.");

            // Asserted rather than assumed. A wheel can install cleanly and still produce no
            // console script if its entry point metadata is wrong, and the failure would
            // otherwise surface as a missing file on the NEXT run, one layer away from its
            // cause.
            string stagedTarget = Path.Combine(staging, "Scripts", scriptName + ".exe");
            if (!File.Exists(stagedTarget))
            {
                throw new LauncherError(
                    Path.GetFileName(wheel) + " installed but produced no '" + scriptName +
                    "' entry point, so this package's Application entries and the wheel's " +
                    "[project.scripts] have gone out of step.");
            }

            Directory.CreateDirectory(Path.GetDirectoryName(venvDirectory));
            try
            {
                Directory.Move(staging, venvDirectory);
            }
            catch (IOException)
            {
                if (!File.Exists(Path.Combine(venvDirectory, "Scripts", scriptName + ".exe")))
                {
                    throw;
                }
                // Another first run won the race and its venv is complete. Nothing to do.
            }
        }
        finally
        {
            if (Directory.Exists(staging))
            {
                try
                {
                    Directory.Delete(staging, true);
                }
                catch (IOException)
                {
                    // Leaving a staging directory behind is untidy and harmless; failing the
                    // user's command because cleanup could not delete it would not be.
                }
            }
        }
    }

    // The "exactly one bundled wheel" rule, enforced here as well as at pack time.
    //
    // packaging/README.md phrases the publishing boundary as a count on purpose: if there is
    // one wheel, no third party code shipped, and anyone can check it without judging each
    // dependency. msix.py asserts it when it builds the layout. This asserts it again at
    // runtime, because the pack-time check cannot see a package someone assembled another way,
    // and because installing a second wheel found here would be exactly the mistake the rule
    // exists to prevent.
    private static string FindTheWheel(string packageRoot)
    {
        string wheelDirectory = Path.Combine(packageRoot, "wheels");
        if (!Directory.Exists(wheelDirectory))
        {
            throw new LauncherError("no " + wheelDirectory + " directory; the package is malformed.");
        }

        string[] wheels = Directory.GetFiles(wheelDirectory, "*.whl");
        if (wheels.Length != 1)
        {
            throw new LauncherError(
                "expected exactly 1 wheel under " + wheelDirectory + ", found " +
                wheels.Length + ". A package carrying dependency wheels would put third " +
                "party code in a published artifact; see packaging/README.md.");
        }

        return wheels[0];
    }

    private struct PythonCandidate
    {
        public string Executable;
        public string PrefixArguments;
        public string Description;
    }

    // Candidate order matters. py.exe is the Windows launcher and asking it for -3 gets the
    // newest registered CPython, which is the closest thing Windows has to a correct answer.
    // A bare python.exe is last because on a machine with no real Python installed it
    // resolves to the Microsoft Store placeholder, and the version probe is what tells that
    // placeholder apart from an interpreter.
    private static PythonCandidate FindPython()
    {
        string overridden = Environment.GetEnvironmentVariable(PythonOverrideVariable);
        List<PythonCandidate> candidates = new List<PythonCandidate>();

        if (!string.IsNullOrEmpty(overridden))
        {
            candidates.Add(new PythonCandidate
            {
                Executable = overridden,
                PrefixArguments = "",
                Description = PythonOverrideVariable + " (" + overridden + ")",
            });
        }
        else
        {
            candidates.Add(new PythonCandidate { Executable = "py", PrefixArguments = "-3 ", Description = "py -3" });
            candidates.Add(new PythonCandidate { Executable = "python3", PrefixArguments = "", Description = "python3" });
            candidates.Add(new PythonCandidate { Executable = "python", PrefixArguments = "", Description = "python" });
        }

        bool sawSomethingTooOld = false;
        foreach (PythonCandidate candidate in candidates)
        {
            string probe = candidate.PrefixArguments +
                "-c \"import sys; sys.stdout.write('" + PythonOkToken +
                "' if sys.version_info >= (3, 10) else '" + PythonOldToken + "')\"";
            string output;
            if (!TryCapture(candidate.Executable, probe, out output))
            {
                continue;
            }
            if (output.Contains(PythonOkToken))
            {
                return candidate;
            }
            if (output.Contains(PythonOldToken))
            {
                sawSomethingTooOld = true;
            }
        }

        throw new LauncherError(
            sawSomethingTooOld
                ? "found a Python interpreter, but every one tried is older than 3.10, which " +
                  "is ASH's floor. Install a supported Python, or point " +
                  PythonOverrideVariable + " at one."
                : "found no Python interpreter. ASH's MSIX package carries ASH's wheel but " +
                  "not an interpreter, so Python 3.10 or newer has to be on the machine. " +
                  "Install it, or point " + PythonOverrideVariable + " at an existing one.");
    }

    // Starts the venv's console script and hands it the user's arguments untouched.
    //
    // The arguments come from Environment.CommandLine with the leading program token removed,
    // NOT from a re-quoted string[] args. Rebuilding a command line from a parsed argv means
    // reimplementing the CommandLineToArgvW quoting rules in reverse, and getting that subtly
    // wrong is how `ash scan --source-dir "C:\my repo"` turns into two arguments. Passing the
    // original tail through is exact by construction.
    //
    // This also keeps the CLI's own option shapes intact without knowing anything about them,
    // including that -V is --version while -v is --verbose.
    private static int Run(string target)
    {
        ProcessStartInfo start = new ProcessStartInfo(target, CommandLineTail());
        // False so the child inherits this console's handles. Redirecting would mean pumping
        // three streams and would break ASH's progress rendering, which asks the terminal
        // what it is.
        start.UseShellExecute = false;

        using (Process child = Process.Start(start))
        {
            // Ctrl+C reaches every process attached to the console, so the child already gets
            // it. Declining to die here lets this program outlive the signal long enough to
            // report the child's real exit code instead of being killed mid-wait.
            Console.CancelKeyPress += delegate (object sender, ConsoleCancelEventArgs e)
            {
                e.Cancel = true;
            };

            child.WaitForExit();
            return child.ExitCode;
        }
    }

    // Windows parses the program name at the front of a command line by a simpler rule than
    // the rest of it: a quoted argv[0] ends at the next quote, with no backslash escaping,
    // and an unquoted one ends at the first whitespace. That is the whole rule, and it is why
    // this does not need a general purpose tokenizer.
    private static string CommandLineTail()
    {
        string raw = Environment.CommandLine;
        int index = 0;

        if (index < raw.Length && raw[index] == '"')
        {
            index++;
            while (index < raw.Length && raw[index] != '"')
            {
                index++;
            }
            if (index < raw.Length)
            {
                index++;
            }
        }
        else
        {
            while (index < raw.Length && !char.IsWhiteSpace(raw[index]))
            {
                index++;
            }
        }

        return raw.Substring(index).TrimStart();
    }

    private static void RunOrThrow(string executable, string arguments, string failureMessage)
    {
        ProcessStartInfo start = new ProcessStartInfo(executable, arguments);
        start.UseShellExecute = false;
        // Not redirected. pip's own output is the only useful diagnostic when a dependency
        // fails to resolve, and capturing it to re-print a summary would hide the line that
        // names the package.
        using (Process child = Process.Start(start))
        {
            child.WaitForExit();
            if (child.ExitCode != 0)
            {
                throw new LauncherError(failureMessage + " (exit code " + child.ExitCode + ")");
            }
        }
    }

    private static bool TryCapture(string executable, string arguments, out string output)
    {
        output = "";
        try
        {
            ProcessStartInfo start = new ProcessStartInfo(executable, arguments);
            start.UseShellExecute = false;
            start.RedirectStandardOutput = true;
            start.RedirectStandardError = true;
            start.CreateNoWindow = true;
            using (Process child = Process.Start(start))
            {
                output = child.StandardOutput.ReadToEnd();
                child.StandardError.ReadToEnd();
                child.WaitForExit();
                return true;
            }
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // The candidate is not on PATH. Not an error; that is what probing means.
            return false;
        }
    }

    private static string Quote(string value)
    {
        return "\"" + value + "\"";
    }

    private sealed class LauncherError : Exception
    {
        public LauncherError(string message) : base(message)
        {
        }
    }
}
