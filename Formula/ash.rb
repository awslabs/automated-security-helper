class Ash < Formula
  include Language::Python::Virtualenv

  desc "Automated Security Helper - security scanning tool for code repositories"
  homepage "https://github.com/awslabs/automated-security-helper"
  # Kept current by `cz bump` via [tool.commitizen] version_files in
  # pyproject.toml. tests/unit/test_homebrew_formula_version.py fails if this
  # drifts from the packaged version, because a stale-but-real tag installs an
  # old ASH without failing anything.
  #
  # CI installs a copy of this formula in which only this line differs: it points
  # at a tarball of the commit under test (.github/scripts/render-homebrew-formula.py).
  url "https://github.com/awslabs/automated-security-helper.git", tag: "v3.7.1"
  license "Apache-2.0"

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
    %w[ash ashv3 automated-security-helper].each do |script|
      (bin/script).write_env_script libexec/"bin"/script, PATH: path
    end
  end

  test do
    assert_match "automated-security-helper", shell_output("#{bin}/ash --version")

    (testpath/"src/sample.py").write "print('hello')\n"
    # detect-secrets is a Python dependency of ASH, so this scan needs nothing
    # beyond what the formula installed; it fails if a dependency is missing.
    system (bin/"ash").to_s, "scan", "--source-dir", (testpath/"src").to_s,
           "--output-dir", (testpath/"out").to_s,
           "--simple", "--phases", "scan", "--phases", "report", "--scanners", "detect-secrets"
    assert_path_exists testpath/"out/ash_aggregated_results.json"

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
    # The exit status goes on a line of its own, after ash's last line whatever it ends with.
    exited = shell_output("#{bin}/ash scan --source-dir #{testpath}/cfn --output-dir #{testpath}/out-cfn " \
                          "--simple --phases scan --phases report --scanners cdk-nag; " \
                          "rc=$?; echo; echo \"ash exited $rc\"")
                 .lines.last.strip
    status = JSON.parse((testpath/"out-cfn/ash_aggregated_results.json").read)
                 .dig("scanner_results", "cdk-nag", "status")
    assert_includes %w[PASSED FAILED], status, "cdk-nag reported #{status}"
    assert_equal((status == "FAILED") ? "ash exited 2" : "ash exited 0", exited)
  end
end
