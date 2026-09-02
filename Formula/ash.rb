class Ash < Formula
  include Language::Python::Virtualenv

  desc "Automated Security Helper - security scanning tool for code repositories"
  homepage "https://github.com/awslabs/automated-security-helper"
  # Kept current by `cz bump` via [tool.commitizen] version_files in
  # pyproject.toml. tests/unit/test_homebrew_formula_version.py fails if this
  # drifts from the packaged version, because a stale-but-real tag installs an
  # old ASH without failing anything.
  url "https://github.com/awslabs/automated-security-helper.git", tag: "v3.7.0"
  license "Apache-2.0"

  depends_on "python@3.12"
  depends_on "uv"

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match "automated-security-helper", shell_output("#{bin}/ash --version")
  end
end
