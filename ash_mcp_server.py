#!/usr/bin/env python3
"""
ASH (Automated Security Helper) MCP Server

A simple MCP server that exposes ASH security scanning capabilities in local mode.
This allows LLMs to perform security scans and analyze results through the Model Context Protocol.
"""

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict
from datetime import datetime

from mcp.server.fastmcp import FastMCP, Context


# Initialize the MCP server
mcp = FastMCP("ASH Security Scanner")


def check_ash_installation() -> tuple[bool, str]:
    """Check if ASH is installed and available"""
    try:
        result = subprocess.run(
            ["ash", "--version"], 
            capture_output=True, 
            text=True, 
            timeout=10
        )
        if result.returncode == 0:
            return True, result.stdout.strip()
        else:
            return False, "ASH command failed"
    except FileNotFoundError:
        return False, "ASH not found in PATH"
    except Exception as e:
        return False, f"Error checking ASH: {str(e)}"


def parse_ash_results(output_dir: str) -> Dict[str, Any]:
    """Parse ASH scan results from the output directory"""
    results = {
        "scanners_run": [],
        "total_findings": 0,
        "actionable_findings": 0,
        "reports_generated": []
    }
    
    try:
        # Look for the aggregated results JSON file
        aggregated_results_path = Path(output_dir) / "ash_aggregated_results.json"
        if aggregated_results_path.exists():
            with open(aggregated_results_path, 'r') as f:
                data = json.load(f)
                # Extract key information
                if 'scanners' in data:
                    results["scanners_run"] = list(data['scanners'].keys())
                if 'summary' in data:
                    results.update(data['summary'])
        
        # Look for report files
        reports_dir = Path(output_dir) / "reports"
        if reports_dir.exists():
            for report_file in reports_dir.iterdir():
                if report_file.is_file():
                    results["reports_generated"].append({
                        "name": report_file.name,
                        "path": str(report_file),
                        "size_bytes": report_file.stat().st_size
                    })
    
    except Exception as e:
        results["parse_error"] = str(e)
    
    return results


@mcp.resource("ash://status")
def get_ash_status() -> str:
    """Get the current status of ASH installation"""
    is_installed, info = check_ash_installation()
    
    if is_installed:
        return f"""ASH Status: ✅ READY

{info}

ASH is installed and ready to perform security scans in local mode.
Local mode includes these scanners:
• Bandit (Python security issues)
• Semgrep (Multi-language security patterns) 
• detect-secrets (Hardcoded secrets detection)
• Checkov (Infrastructure as Code security)
• cdk-nag (CDK security issues)
"""
    else:
        return f"""ASH Status: ❌ NOT AVAILABLE

{info}

To install ASH, run:
pipx install git+https://github.com/awslabs/automated-security-helper.git@v3.0.0-beta

Or with pip:
pip install git+https://github.com/awslabs/automated-security-helper.git@v3.0.0-beta
"""


@mcp.resource("ash://help")
def get_ash_help() -> str:
    """Get help information about ASH usage"""
    return """ASH (Automated Security Helper) Usage Guide

ASH is a security scanning orchestrator that runs multiple security tools:

🔍 **What ASH Scans For:**
• Python security issues (Bandit)
• Multi-language security patterns (Semgrep)
• Hardcoded secrets and credentials (detect-secrets)
• Infrastructure as Code issues (Checkov)
• CDK security problems (cdk-nag)

📁 **Supported File Types:**
• Python (.py)
• JavaScript/TypeScript (.js, .ts)
• CloudFormation (.yaml, .yml, .json)
• Terraform (.tf)
• Dockerfile
• And many more...

⚙️ **Local Mode Benefits:**
• Fast execution (Python-only scanners)
• No Docker required
• Good for development and CI/CD
• Covers most common security issues

🎯 **Best Practices:**
• Run scans early and often
• Review all findings, even low severity
• Use in pre-commit hooks for continuous security
• Combine with manual security reviews
"""


@mcp.tool()
async def scan_directory(
    directory_path: str,
    severity_threshold: str = "MEDIUM",
    ctx: Context = None
) -> Dict[str, Any]:
    """
    Perform a security scan on a directory using ASH in local mode
    
    Args:
        directory_path: Path to the directory to scan
        severity_threshold: Minimum severity threshold (LOW, MEDIUM, HIGH, CRITICAL)
    """
    # Validate directory exists
    if not os.path.exists(directory_path):
        return {
            "success": False,
            "error": f"Directory does not exist: {directory_path}"
        }
    
    if not os.path.isdir(directory_path):
        return {
            "success": False,
            "error": f"Path is not a directory: {directory_path}"
        }
    
    # Validate severity threshold
    valid_severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    if severity_threshold not in valid_severities:
        return {
            "success": False,
            "error": f"Invalid severity threshold: {severity_threshold}. Must be one of: {', '.join(valid_severities)}"
        }
    
    # Check ASH installation
    is_installed, version_info = check_ash_installation()
    if not is_installed:
        return {
            "success": False,
            "error": f"ASH is not installed: {version_info}"
        }
    
    if ctx:
        ctx.info(f"Starting ASH security scan of {directory_path}")
        await ctx.report_progress(0, 100, "Initializing scan...")
    
    start_time = datetime.now()
    
    try:
        # Create temporary output directory
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = os.path.join(temp_dir, "ash_output")
            
            # Build ASH command for local mode
            cmd = [
                "ash",
                "--mode", "local",
                "--source-dir", directory_path,
                "--output-dir", output_dir,
                "--severity-threshold", severity_threshold,
                "--no-fail-on-findings"  # Don't fail on findings for MCP usage
            ]
            
            if ctx:
                await ctx.report_progress(25, 100, "Running ASH scan...")
            
            # Execute ASH scan
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180  # 3 minute timeout for local mode
            )
            
            if ctx:
                await ctx.report_progress(75, 100, "Parsing results...")
            
            # Parse results
            findings_summary = parse_ash_results(output_dir)
            execution_time = (datetime.now() - start_time).total_seconds()
            
            if ctx:
                await ctx.report_progress(100, 100, "Scan complete!")
            
            return {
                "success": True,
                "exit_code": result.returncode,
                "scan_path": directory_path,
                "mode": "local",
                "severity_threshold": severity_threshold,
                "findings_summary": findings_summary,
                "execution_time_seconds": round(execution_time, 2),
                "ash_version": version_info,
                "stdout": result.stdout,
                "stderr": result.stderr if result.stderr else None
            }
    
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "ASH scan timed out after 3 minutes",
            "execution_time_seconds": (datetime.now() - start_time).total_seconds()
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Error running ASH scan: {str(e)}",
            "execution_time_seconds": (datetime.now() - start_time).total_seconds()
        }


@mcp.tool()
def check_installation() -> Dict[str, Any]:
    """Check if ASH is properly installed and ready to use"""
    is_installed, info = check_ash_installation()
    
    return {
        "installed": is_installed,
        "version_info": info if is_installed else None,
        "error": None if is_installed else info,
        "mode_supported": "local",
        "ready_to_scan": is_installed
    }


@mcp.prompt()
def analyze_security_findings(scan_results: str) -> str:
    """Create a prompt for analyzing ASH security scan results"""
    return f"""Please analyze these ASH security scan results and provide:

1. **Summary**: Brief overview of the security scan results
2. **Key Findings**: Most important security issues discovered
3. **Risk Assessment**: Categorize findings by severity and potential impact
4. **Recommendations**: Specific actions to address the security issues
5. **Next Steps**: Prioritized list of what to fix first

Scan Results:
```json
{scan_results}
```

Focus on actionable insights and practical remediation steps."""


if __name__ == "__main__":
    # Run the MCP server
    mcp.run()
