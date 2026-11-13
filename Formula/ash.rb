class Ash < Formula
  include Language::Python::Virtualenv

  desc "Automated Security Helper - security scanning tool for code repositories"
  homepage "https://github.com/awslabs/automated-security-helper"
  # Kept current by `cz bump` via [tool.commitizen] version_files in
  # pyproject.toml. tests/unit/test_homebrew_formula_version.py fails if this
  # drifts from the packaged version, because a stale-but-real tag installs an
  # old ASH without failing anything.
  #
  # This line is the release form, and it is the only line CI does not test as
  # written. Installed verbatim it builds the tagged release, not the commit
  # under test, and the test block below needs a release that has `ashx`. So
  # CI installs a copy in which only this line differs: it points at a `git
  # archive` tarball of the commit under test. scripts/e2e/brew_formula.py
  # writes that copy for the e2e leg (tests/unit/test_e2e_brew_formula.py holds
  # it to that), and .github/scripts/render-homebrew-formula.py writes it for
  # the validate-install leg. Edit the formula here, never in the copy.
  url "https://github.com/awslabs/automated-security-helper.git", tag: "v4.0.0"
  license "Apache-2.0"

  # The formula is named `ash` and the file is Formula/ash.rb: that is the
  # distribution identifier (`brew install ash`, and a [tool.commitizen]
  # version_files entry), not the command. `install` links every console script
  # the wheel declares, so `ashx` (the v4 command), the deprecated `ash` and
  # `ashv3`, and `automated-security-helper` are all on PATH. Homebrew is one of
  # the three channels that keep the deprecated `ash`; the others are pip and the
  # container image.

  # After the build, Homebrew rewrites every dylib ID in the keg to the library's
  # absolute opt path, and fails the install ("Failed to fix install linkage") on a
  # Mach-O whose header has no room for the longer name. The locked orjson wheel's
  # extension module is one: a dylib with the ID @rpath/orjson.cpython-312-darwin.so
  # and no header padding, because it is prebuilt rather than linked under
  # Homebrew's -headerpad_max_install_names. Python loads extension modules by path,
  # so the install name is never read; leave @rpath IDs as they are.
  preserve_rpath

  depends_on "uv" => :build
  # cdk-nag runs on Node.js and npm-audit runs npm. Both are in ASH's default and
  # precommit scanner sets, so without Node.js those scans report them MISSING.
  depends_on "node"
  depends_on "python@3.12"

  # ASH's Python dependencies come from the uv.lock committed at the tag above,
  # not from `resource` blocks. `virtualenv_install_with_resources` installs with
  # pip `--no-deps`, so a dependency without a resource block is silently left
  # out (this formula had none, and `ash` died on `import typer`). The lock moves
  # with the tag, so a release that changes dependencies needs no edit here.
  #
  # uv installs the versions the lock names, including the `cdk` extra cdk-nag
  # needs, and checks each of those files against the sha256 the lock records.
  # ASH itself is built from the tag's source, and its build requirements
  # (hatchling, and packaging, pathspec, pluggy, tomlkit and trove-classifiers
  # under it) are not covered: uv resolves them from PyPI by the version range in
  # [build-system] requires, unhashed, as a PEP 517 build does. `uv sync` takes
  # no hashed build constraints (`uv build` does).
  #
  # `install` downloads the locked wheels, so it needs network access: building
  # with HOMEBREW_FORMULA_BUILD_NETWORK=deny is not supported and fails at
  # `uv sync` ("Failed to download"). tests/unit/test_homebrew_formula_install.py
  # holds the shape of this method.
  def install
    venv = virtualenv_create(libexec, "python3.12", system_site_packages: false)

    ENV["UV_PROJECT_ENVIRONMENT"] = venv.root.to_s
    ENV["UV_PYTHON_DOWNLOADS"] = "never"
    ENV["UV_NO_CONFIG"] = "1"
    ENV["UV_LINK_MODE"] = "copy"
    # uv's cache stays outside the source tree. ASH is built from buildpath, and
    # hatchling walks the whole project root for the files it packages while uv is
    # still writing and renaming temporary entries in its cache; a cache under
    # buildpath made that walk fail (FileNotFoundError in hatchling's safe_walk on a
    # directory that was gone between listing and stat). The cache is made under
    # Homebrew's temporary directory and deleted when the block ends.
    Dir.mktmpdir("ash-uv-cache-") do |cache|
      ENV["UV_CACHE_DIR"] = cache
      system "uv", "sync", "--frozen", "--no-dev", "--no-editable", "--extra", "cdk",
             "--python", (venv.root/"bin/python").to_s
    end

    # uv records the directory it built ASH from in the dist-info's direct_url.json.
    # That is this build directory, which Homebrew deletes after the install and
    # which another local account can create again. Container mode would take a tree
    # planted there for the source ASH was installed from and build it, so the record
    # is removed, and the install is resolved by the commit its package build
    # recorded, as an install from an index is.
    dist_infos = Dir[(venv.root/"lib/python*/site-packages/automated_security_helper-*.dist-info").to_s]
    odie "expected one automated_security_helper dist-info, found #{dist_infos.length}" if dist_infos.length != 1
    rm_f "#{dist_infos.first}/direct_url.json"

    # The lock includes uv itself, and scans install bandit, checkov and other
    # tools with it. Putting the virtualenv's bin first on PATH makes ASH use the
    # uv version it was locked with rather than whichever one is on the user's
    # PATH, the same thing `uvx` does. Node.js goes last, so a node the user put
    # on PATH still wins and this one is there when none is.
    path = "#{libexec}/bin:$PATH:#{Formula["node"].opt_bin}"
    %w[ashx ash ashv3 automated-security-helper agentic-security-harness].each do |script|
      (bin/script).write_env_script libexec/"bin"/script, PATH: path
    end
  end

  def caveats
    <<~EOS
      The command is `ashx`:
        ashx --help
        ashx dependencies install   # provision the scanners ASH can install

      `ash` still works but is deprecated: it prints a one-line warning to stderr
      and then runs `ashx`. On many hosts `ash` is also the Almquist shell, so
      scripts should call `ashx`.
    EOS
  end

  test do
    # The console script under test, named once so that renaming it is a one-line
    # change in this block.
    ashx = bin/"ashx"
    assert_match "automated-security-helper", shell_output("#{ashx} --version")

    # The deprecated alias this channel keeps must still run and must say it is
    # deprecated, on stderr, in the one line cli/deprecations.py prints.
    assert_match "the 'ash' command is deprecated",
                 shell_output("#{bin}/ash --version 2>&1 >/dev/null")

    # `ashx --version` is not evidence the venv is complete. A dependency missing
    # from the install leaves a module absent rather than failing the build, and
    # ASH imports most of its plugin tree lazily -- so the version print can
    # succeed on an install that cannot scan anything. This runs a real scan for
    # the same reason packaging/deb/verify-in-container.sh and
    # packaging/rpm/verify-in-container.sh do.
    #
    # The assertion is on findings, not on the exit code. An ASH scan that finds
    # nothing exits 0, so "it ran and exited 0" is indistinguishable from a scan
    # that never happened. `--no-fail-on-findings` keeps the exit code at 0 so
    # that Homebrew's `system` does not raise on the finding this fixture is
    # planted to produce, which leaves the SARIF count as the only thing being
    # asserted.
    #
    # detect-secrets is named because it is a Python dependency of ASH, so this
    # scan needs nothing beyond what the formula installed, and
    # DetectSecretsScanner drives the library in process rather than shelling out
    # to a tool the formula never installed. Left unnarrowed the scan selects all
    # ten, nine report MISSING for tools this test never intended to provide, and
    # the run fails for a reason that has nothing to do with the formula.
    #
    # The planted value is AWS's published documentation example key. The marker
    # keeps this repository's own scan quiet on that one line; the file written
    # below gets the value without the marker, so the scan here still reports it.
    planted_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" # pragma: allowlist secret
    (testpath/"leak.py").write <<~PYTHON
      # Fixture for formula verification. Not a real credential.
      AWS_SECRET_ACCESS_KEY = "#{planted_key}"
    PYTHON

    system ashx.to_s, "scan",
           "--source-dir", testpath.to_s,
           "--output-dir", (testpath/"ash_output").to_s,
           "--scanners", "detect-secrets",
           "--no-progress",
           "--no-fail-on-findings"

    sarif = JSON.parse((testpath/"ash_output/reports/ash.sarif").read)
    findings = sarif.fetch("runs").sum { |run| run.fetch("results", []).length }
    assert_operator findings, :>, 0,
                    "ashx scan reported 0 findings on a fixture planted with an " \
                    "AWS secret, so this install cannot be shown to scan"

    # cdk-nag needs the cdk extra and Node.js, both of which the formula installs:
    # the scan has to run it, PASSED or FAILED, never MISSING, with the exit status
    # that goes with the result. Which of the two depends on the release (v3.7.0
    # reports this unencrypted bucket as PASSED), so it is not asserted here;
    # .github/actions/validate-install/homebrew.sh checks the findings in CI.
    (testpath/"cfn/template.yaml").write <<~YAML
      AWSTemplateFormatVersion: "2010-09-09"
      Resources:
        Bucket:
          Type: AWS::S3::Bucket
    YAML
    # The exit status goes on a line of its own, after ashx's last line whatever it ends with.
    exited = shell_output("#{ashx} scan --source-dir #{testpath}/cfn --output-dir #{testpath}/out-cfn " \
                          "--simple --phases scan --phases report --scanners cdk-nag; " \
                          "rc=$?; echo; echo \"ashx exited $rc\"")
                 .lines.last.strip
    status = JSON.parse((testpath/"out-cfn/ash_aggregated_results.json").read)
                 .dig("scanner_results", "cdk-nag", "status")
    assert_includes %w[PASSED FAILED], status, "cdk-nag reported #{status}"
    assert_equal((status == "FAILED") ? "ashx exited 2" : "ashx exited 0", exited)
  end
end
