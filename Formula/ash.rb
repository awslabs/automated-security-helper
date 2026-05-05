class Ash < Formula
  include Language::Python::Virtualenv

  desc "Automated Security Helper - security scanning tool for code repositories"
  homepage "https://github.com/awslabs/automated-security-helper"
  url "https://github.com/awslabs/automated-security-helper.git", tag: "v3.4.1"
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
