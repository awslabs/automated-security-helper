# Snyk Plugin CI/CD Setup Guide

This guide provides detailed instructions for setting up the Snyk plugin in CI/CD environments, specifically for the GitHub Actions workflow in the automated-security-helper repository.

## GitHub Secret Configuration

The Snyk plugin requires a `SNYK_TOKEN` to authenticate with Snyk's services. This token must be configured as a GitHub repository secret.

### Setting up SNYK_TOKEN Secret

1. **Obtain a Snyk API Token**:
   - Log in to your [Snyk account](https://app.snyk.io/)
   - Navigate to **Account Settings** → **API Token**
   - Generate a new token or copy your existing one
   - The token format will look like: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`

2. **Add Secret to GitHub Repository**:
   - Navigate to your GitHub repository
   - Go to **Settings** → **Secrets and variables** → **Actions**
   - Click **New repository secret**
   - Name: `SNYK_TOKEN`
   - Value: Your Snyk API token from step 1
   - Click **Add secret**

### Verification

The GitHub Actions workflow will automatically use the `SNYK_TOKEN` secret when running community plugin tests. You can verify the setup by:

1. Checking that the secret appears in your repository's Actions secrets list
2. Running the workflow and ensuring Snyk CLI authentication succeeds
3. Reviewing the workflow logs for successful Snyk plugin execution

## Local Development Setup

For local development and testing, you can set up Snyk authentication using one of these methods:

### Option 1: Environment Variable
```bash
export SNYK_TOKEN=your-snyk-token-here
```

### Option 2: CLI Authentication
```bash
snyk auth
```
This will open a browser window for authentication and store credentials locally.

### Option 3: Configuration File
Snyk CLI will automatically check for credentials at `~/.config/configstore/snyk.json`.

## Troubleshooting

### Common Issues

**Authentication Failed**:
- Verify the `SNYK_TOKEN` secret is correctly set in GitHub
- Ensure the token is valid and hasn't expired
- Check that the token has appropriate permissions for Snyk Code

**Workflow Fails on Community Plugin Tests**:
- The workflow will skip Snyk tests gracefully if `SNYK_TOKEN` is not available
- Check the workflow logs for specific error messages
- Ensure npm is available for Snyk CLI installation

**Rate Limiting**:
- Snyk may apply rate limits based on your subscription tier
- Consider upgrading your Snyk plan for higher rate limits
- Implement retry logic if needed

### Debug Mode

To troubleshoot issues in the workflow, you can:

1. Check the "Install Community Plugin Tools" step logs
2. Look for Snyk CLI version and authentication status
3. Review the scan execution logs for detailed error messages

## Security Considerations

- **Token Security**: Never commit Snyk tokens to version control
- **Token Rotation**: Regularly rotate your Snyk API tokens
- **Access Control**: Limit repository access to trusted contributors
- **Monitoring**: Monitor token usage in your Snyk dashboard

## Integration Testing

The GitHub Actions workflow tests both Snyk and Trivy plugins together to ensure:

- Both tools install correctly on all supported platforms
- Plugins don't conflict with each other
- Scan results are properly generated and formatted
- All output formats (SARIF, JSON, HTML, etc.) work correctly

## Platform Support

The Snyk plugin is tested on:

- **Linux**: Ubuntu (x86_64 and ARM64)
- **macOS**: Latest version (x86_64)
- **Windows**: Latest version (x86_64)

All platforms use npm for cross-platform Snyk CLI installation, ensuring consistent behavior across environments.
