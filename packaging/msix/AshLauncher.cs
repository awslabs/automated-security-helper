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
// under the package's own per-user state directory,
// %LOCALAPPDATA%\Packages\<PackageFamilyName>\LocalCache\ash-venv.
//
// That location rather than a plain %LOCALAPPDATA%\ash\venv, and the reason is uninstall.
// MSIX has no uninstall hook any more than it has an install hook, so nothing can run `rm -rf`
// on the way out the way the .deb's prerm and the .rpm's %postun do. What Windows does do is
// delete %LOCALAPPDATA%\Packages\<PackageFamilyName> when the package is removed. Putting the
// venv there is the only way to get the .deb and .rpm behavior, where removing the package
// reclaims the several hundred megabytes pip installed, without asking the user to know that
// a directory somewhere else is now orphaned.
//
// The cost, which is why ASH_MSIX_VENV exists: that path is about 60 characters longer than
// %LOCALAPPDATA%\ash\venv, and a venv's deepest site-packages paths are already long. On a
// system without long paths enabled, a dependency with a deep tree can exceed MAX_PATH during
// pip install. The override is the documented answer, and README.msix says so.
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

    // Written as the last act of a successful bootstrap and checked before the venv is used.
    // CreateVenv explains why completeness is a file of its own rather than the presence of a
    // console script.
    private const string CompletionMarker = ".ash-bootstrap-complete";

    // The probe below must print this exact token. An interpreter that is too old prints the
    // other one, and the Microsoft Store's python.exe placeholder (which opens the Store
    // rather than running anything) prints neither. Testing the exit code alone would read
    // that placeholder as a working Python.
    private const string PythonOkToken = "ASH_PY_OK";
    private const string PythonOldToken = "ASH_PY_OLD";
    // A third verdict, for an interpreter above the range CI exercises. It was added while
    // 3.14 was believed to be the cause of a silent failure that turned out to have a
    // different cause entirely; FindPython has the correction and the reason the bound stays.
    private const string PythonNewToken = "ASH_PY_NEW";

    private static int Main()
    {
        try
        {
            // The entry assembly's location, not Process.GetCurrentProcess().MainModule
            // .FileName. Those are the same path for a .NET Framework exe launched directly,
            // and they diverge the moment anything hosts the assembly: under a host process
            // MainModule is the HOST's executable, so the script name would be read from the
            // wrong filename and the package root would point at the wrong directory. That is
            // not a hypothetical, it is what running this under mono does, which is also the
            // only way to exercise this file off Windows.
            string launcherPath = System.Reflection.Assembly.GetEntryAssembly().Location;
            if (string.IsNullOrEmpty(launcherPath))
            {
                throw new LauncherError(
                    "could not determine this launcher's own path, so there is no way to tell "
                    + "which ASH entry point it stands for or where the package is.");
            }
            string packageRoot = Path.GetDirectoryName(launcherPath);
            string scriptName = Path.GetFileNameWithoutExtension(launcherPath);

            string venvDirectory = ResolveVenvDirectory();
            string target = Path.Combine(venvDirectory, "Scripts", scriptName + ".exe");

            if (!IsBootstrapped(venvDirectory, target))
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

    // kernel32's package-identity API, rather than Windows.Storage.ApplicationData.Current
    // .LocalFolder, which is the WinRT way to ask the same question. WinRT would mean a
    // Windows.winmd reference and a compile that depends on which SDK is installed; this
    // launcher is built by csc.exe from the .NET Framework with no SDK at all, and one
    // P/Invoke keeps it that way.
    private const int ErrorInsufficientBuffer = 122;
    private const int AppmodelErrorNoPackage = 15700;

    [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern int GetCurrentPackageFamilyName(ref int length, System.Text.StringBuilder name);

    private static string PackageFamilyNameOrNull()
    {
        try
        {
            int length = 0;
            int result = GetCurrentPackageFamilyName(ref length, null);
            if (result == AppmodelErrorNoPackage)
            {
                // Running outside a package. Happens when a developer runs a compiled launcher
                // straight out of the layout directory, which is a useful thing to be able to
                // do, so it is a supported case rather than an error.
                return null;
            }
            if (result != ErrorInsufficientBuffer)
            {
                return null;
            }

            System.Text.StringBuilder buffer = new System.Text.StringBuilder(length);
            result = GetCurrentPackageFamilyName(ref length, buffer);
            return result == 0 ? buffer.ToString() : null;
        }
        catch (EntryPointNotFoundException)
        {
            // The export is present on every Windows this package can install on, so this
            // arm is not about Windows. It is about being able to compile and exercise this
            // launcher's logic on a machine that is not Windows at all, where the P/Invoke
            // throws before it can return a value. Without this the whole program is
            // untestable anywhere but the target, and the wheel-count rule below is the kind
            // of thing worth being able to test.
            return null;
        }
        catch (DllNotFoundException)
        {
            return null;
        }
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

        string family = PackageFamilyNameOrNull();
        if (family == null)
        {
            // Unpackaged. There is no per-package directory to use and nothing will clean up
            // after this, which is stated because it differs from the packaged case.
            return Path.Combine(localAppData, "ash", "venv");
        }

        return Path.Combine(localAppData, "Packages", family, "LocalCache", "ash-venv");
    }

    // Whether the venv at the real path is finished. Deliberately not "does the console script
    // exist": pip writes the Scripts\*.exe shims before the last of site-packages, so a
    // bootstrap killed near the end leaves a console script that runs and then dies on a
    // missing import. The marker is written after pip returns 0 AND after the console script is
    // confirmed, so its presence is the only honest answer to this question.
    private static bool IsBootstrapped(string venvDirectory, string target)
    {
        return File.Exists(Path.Combine(venvDirectory, CompletionMarker)) && File.Exists(target);
    }

    // Creates the venv AT ITS FINAL PATH, under a cross-process lock, and marks it complete
    // when pip has finished. It used to build in a sibling <venv>.staging-<pid> and
    // Directory.Move it into place, and why that had to change is the point of this comment.
    //
    // A Windows venv is not relocatable. pip writes each console script as a small .exe with
    // the ABSOLUTE path of the interpreter it was generated for embedded in it, so after a move
    // every shim in the venv names a directory that no longer exists. python.exe survives,
    // because it finds its home through the pyvenv.cfg beside it and that lookup is relative.
    // The venv therefore looks healthy from every angle except the one that matters.
    //
    // On the MSIX leg of ASH - Package Build, with the staging-and-move code, three things were
    // true at once. The venv's own python.exe ran and reported its version, so the interpreter
    // survived the move. Every .exe in Scripts failed -- `ash --version` through the launcher
    // and the venv's Scripts\ash.exe run directly both exited 1. And both of those wrote
    // NOTHING to stdout or stderr, which is the reading that matters: a Python that starts and
    // then fails to import writes a traceback, so empty streams mean Python never started. The
    // venv's pyvenv.cfg named `python -m venv <venv>.staging-7836` as the command that built it,
    // and that directory is deleted after the move.
    //
    // A shim whose embedded interpreter path no longer exists accounts for all of that. Nothing
    // else does. packaging/flatpak hit the same fault and answered it by invoking its
    // interpreter directly rather than trusting a shim.
    //
    // One honest limit on that evidence, because the comment here used to claim more. The two
    // probes in verify-on-windows.ps1 that reach ASH through the interpreter were, at the time,
    // run without -I, so cwd was on sys.path and they imported the REPOSITORY checkout rather
    // than what pip put in site-packages. They therefore did not prove site-packages intact, and
    // that script now passes -I so they do. The conclusion above does not rest on them; it rests
    // on the empty streams. Step 6 of that script also reads the interpreter path back out of
    // ash.exe now and fails by name if it does not exist, which is the direct check.
    //
    // Building at the final path is what removes the move. Both properties staging bought are
    // real and are kept by other means.
    //
    // A half built venv must not be mistaken for a finished one. Staging got that by making the
    // real path appear atomically. The marker file gets it by being written last, with
    // IsBootstrapped checking the marker rather than the console script, and an unfinished tree
    // found here is deleted and rebuilt rather than used.
    //
    // Two shells can run ash for the first time at the same moment. Staging let both build a
    // full copy and threw one away, which cost a duplicate download of every dependency. The
    // lock makes the second wait for the first and then find the work already done.
    private static void CreateVenv(string venvDirectory, string packageRoot, string scriptName)
    {
        string wheel = FindTheWheel(packageRoot);
        string target = Path.Combine(venvDirectory, "Scripts", scriptName + ".exe");

        // The parent has to exist before a lock file can be created beside the venv.
        Directory.CreateDirectory(Path.GetDirectoryName(venvDirectory));

        using (WaitForGate(venvDirectory))
        {
            // Re-checked under the lock, because the wait may have been a wait for another
            // process to do exactly this work.
            if (IsBootstrapped(venvDirectory, target))
            {
                return;
            }

            // Either a previous bootstrap died partway or this is a first run. Both are handled
            // the same way, because anything without the marker is by definition unfinished and
            // there is nothing in it worth keeping.
            if (Directory.Exists(venvDirectory))
            {
                Console.Error.WriteLine(
                    "ash: removing an unfinished virtualenv at " + venvDirectory + " and starting over.");
                Directory.Delete(venvDirectory, true);
            }

            PythonCandidate python = FindPython();

            // Progress goes to stderr, not stdout. A first run can take a minute while pip
            // resolves ASH's dependencies, so saying nothing looks like a hang; but ASH's stdout
            // is read by scripts, and a banner mixed into it would corrupt a piped report.
            Console.Error.WriteLine("ash: first run, creating a virtualenv at " + venvDirectory);
            Console.Error.WriteLine("ash: this resolves ASH's dependencies from a Python index and happens once.");

            bool finished = false;
            try
            {
                RunOrThrow(
                    python.Executable,
                    python.PrefixArguments + "-m venv " + Quote(venvDirectory),
                    "failed to create a virtualenv with " + python.Description + ".");

                string venvPython = Path.Combine(venvDirectory, "Scripts", "python.exe");
                if (!File.Exists(venvPython))
                {
                    throw new LauncherError(
                        "python -m venv reported success but produced no " + venvPython + ".");
                }

                // The wheel comes from the package; its DEPENDENCIES come from an index. That
                // split is the whole reason this package is not self contained, and README.msix
                // documents it along with the offline wheelhouse commands.
                RunOrThrow(
                    venvPython,
                    "-m pip install --disable-pip-version-check --no-warn-script-location " + Quote(wheel),
                    "failed to install " + Path.GetFileName(wheel) + " into the new virtualenv. " +
                    "This step needs a reachable Python package index; see README.msix for how " +
                    "to stage a wheelhouse on a host that has none.");

                // Asserted rather than assumed. A wheel can install cleanly and still produce no
                // console script if its entry point metadata is wrong, and the failure would
                // otherwise surface as a missing file on the NEXT run, one layer away from its
                // cause.
                if (!File.Exists(target))
                {
                    throw new LauncherError(
                        Path.GetFileName(wheel) + " installed but produced no '" + scriptName +
                        "' entry point, so this package's Application entries and the wheel's " +
                        "[project.scripts] have gone out of step.");
                }

                File.WriteAllText(
                    Path.Combine(venvDirectory, CompletionMarker),
                    "Written by ASH's MSIX launcher once pip finished installing ASH's wheel." +
                    Environment.NewLine +
                    "The presence of THIS file, not of any console script, is what marks this" +
                    Environment.NewLine +
                    "virtualenv usable. Deleting it forces the next ash run to rebuild." +
                    Environment.NewLine);
                finished = true;
            }
            finally
            {
                if (!finished && Directory.Exists(venvDirectory))
                {
                    try
                    {
                        Directory.Delete(venvDirectory, true);
                    }
                    catch (IOException)
                    {
                        // The next run deletes it anyway, since it has no marker. Replacing a
                        // real diagnostic with a cleanup error would be strictly worse.
                    }
                }
            }
        }
    }

    // Serializes first runs across processes. The lock file sits BESIDE the venv rather than
    // inside it, because the venv directory is deleted and recreated under this lock and an
    // open handle to something inside it is exactly what would stop that delete.
    private static FileStream WaitForGate(string venvDirectory)
    {
        string gatePath = venvDirectory + ".lock";
        // Bounded rather than infinite. A first run takes about a minute in CI and longer on a
        // slow link, so the budget is generous; but a wedged holder should end in a sentence
        // naming the file to delete, not in a command that never returns.
        DateTime deadline = DateTime.UtcNow.AddMinutes(30);
        while (true)
        {
            try
            {
                return new FileStream(
                    gatePath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            }
            catch (IOException)
            {
                // Held by another first run, which is the normal case this exists for.
                if (DateTime.UtcNow >= deadline)
                {
                    throw new LauncherError(
                        "waited 30 minutes for another ash process to finish creating the " +
                        "virtualenv at " + venvDirectory + ", and it never did. If no other ash " +
                        "is running, delete " + gatePath + " and run this again.");
                }
                System.Threading.Thread.Sleep(500);
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
            // Version-specific probes first, newest supported down to the floor, then the
            // generic names as a fallback. This is the order packaging/chocolatey's
            // chocolateyinstall.ps1 already uses, and it exists for the same reason: `py -3`
            // and `python3` resolve to whatever is newest or first on PATH, which is not
            // necessarily a version ASH is tested against.
            candidates.Add(new PythonCandidate { Executable = "py", PrefixArguments = "-3.13 ", Description = "py -3.13" });
            candidates.Add(new PythonCandidate { Executable = "py", PrefixArguments = "-3.12 ", Description = "py -3.12" });
            candidates.Add(new PythonCandidate { Executable = "py", PrefixArguments = "-3.11 ", Description = "py -3.11" });
            candidates.Add(new PythonCandidate { Executable = "py", PrefixArguments = "-3.10 ", Description = "py -3.10" });
            candidates.Add(new PythonCandidate { Executable = "py", PrefixArguments = "-3 ", Description = "py -3" });
            candidates.Add(new PythonCandidate { Executable = "python3", PrefixArguments = "", Description = "python3" });
            candidates.Add(new PythonCandidate { Executable = "python", PrefixArguments = "", Description = "python" });
        }

        // The probe has a CEILING as well as a floor. Read the next three paragraphs before
        // reasoning about that ceiling, because the measurement it was originally justified
        // by turned out not to say what it was taken to say.
        //
        // The check used to be `sys.version_info >= (3, 10)` and nothing else. A
        // windows-latest runner selected Python 3.14.7 out of the hosted toolcache, the venv
        // built, pip reported "Successfully installed automated-security-helper-3.7.0", and
        // then `ash --version` exited 1 writing nothing to stdout or stderr. Chocolatey
        // passed on the same image in the same run and its nuspec declares
        // `python3 [3.10,3.14)`, so 3.14 looked like the discriminator and this ceiling was
        // added.
        //
        // IT WAS NOT THE DISCRIMINATOR. With the ceiling in place the job pinned 3.13.15 and
        // `ash --version` failed identically -- same exit 1, same empty streams. The real
        // cause was the venv being built at a staging path and renamed, which invalidates
        // every console-script shim in it; CreateVenv now describes that in full. The
        // Chocolatey comparison was a coincidence of a package that does not move its venv.
        //
        // The bound is kept anyway, on the narrower ground that it was never entitled to
        // claim: ash-unified-ci.yml exercises 3.10 through 3.13 and nothing above, so 3.14
        // is untested rather than known-broken, and Chocolatey declares the same range for
        // the same reason. It is narrower than the `requires-python = ">=3.10,<4"` in
        // pyproject.toml, and that gap is real. Once 3.14 is actually exercised in CI this
        // ceiling has nothing left holding it up and should move with Chocolatey's.
        bool sawSomethingTooOld = false;
        bool sawSomethingTooNew = false;
        foreach (PythonCandidate candidate in candidates)
        {
            string probe = candidate.PrefixArguments +
                "-c \"import sys; sys.stdout.write('" + PythonNewToken +
                "' if sys.version_info >= (3, 14) else ('" + PythonOkToken +
                "' if sys.version_info >= (3, 10) else '" + PythonOldToken + "'))\"";
            string output;
            if (!TryCapture(candidate.Executable, probe, out output))
            {
                continue;
            }
            // Checked before the OK token, because ASH_PY_OK is a substring of nothing here
            // but the order still matters if these tokens are ever edited to share a prefix.
            if (output.Contains(PythonNewToken))
            {
                sawSomethingTooNew = true;
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

        string reason;
        if (sawSomethingTooNew && !sawSomethingTooOld)
        {
            reason =
                "found a Python interpreter, but every one tried is 3.14 or newer. ASH is " +
                "exercised on 3.10 through 3.13 and its console script has been measured " +
                "failing silently on 3.14 for Windows, so this package will not build a " +
                "virtualenv against one. Install a Python in [3.10, 3.14), or point " +
                PythonOverrideVariable + " at one. The override is not version-checked, so " +
                "it can be used to try 3.14 deliberately.";
        }
        else if (sawSomethingTooOld || sawSomethingTooNew)
        {
            reason =
                "found Python interpreters, but none in [3.10, 3.14). 3.10 is ASH's floor, " +
                "and 3.14 is above what ASH is exercised on. Install a Python in that " +
                "range, or point " + PythonOverrideVariable + " at one.";
        }
        else
        {
            reason =
                "found no Python interpreter. ASH's MSIX package carries ASH's wheel but " +
                "not an interpreter, so a Python in [3.10, 3.14) has to be on the machine. " +
                "Install one, or point " + PythonOverrideVariable + " at an existing one.";
        }
        throw new LauncherError(reason);
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
