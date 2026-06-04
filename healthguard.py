#!/usr/bin/env python3
"""
IEEE CyberSalukis HealthGuard OSINT
====================================
Open-Source Digital Public Good (DPG)
Automated OSINT Reconnaissance Framework for Healthcare AI Security

IEEE SA Cybersecurity Hackathon 2026
Team: IEEE CyberSalukis

Usage:
    python healthguard.py --target "Memorial Hospital" --domain memorialhospital.org --all-modules
    python healthguard.py --target "Health System" --domain hs.org --module dork-scan
    python healthguard.py --report --input output/findings.json
"""

import click
import json
import os
import sys
import datetime
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint

from src.config.loader import load_config
from src.modules.dork_scan import DorkScanner
from src.modules.llm_recon import LLMRecon
from src.modules.github_intel import GitHubIntel
from src.modules.shodan_scan import ShodanScanner
from src.modules.censys_scan import CensysScanner
from src.modules.ivre_recon import IVRERecon
from src.modules.leakix_scan import LeakIXScanner
from src.modules.vendor_intel import VendorIntel
from src.modules.social_recon import SocialRecon
from src.reports.report_generator import ReportGenerator
from src.utils.normalizer import normalize_findings

console = Console()

BANNER = """
╔══════════════════════════════════════════════════════════════════════════════╗
║          IEEE CyberSalukis HealthGuard OSINT                               ║
║          Open-Source Digital Public Good (DPG)                             ║
║          Healthcare AI Attack Surface Reconnaissance Framework             ║
║                                                                            ║
║          IEEE SA Cybersecurity Hackathon 2026                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

  ⚠  AUTHORIZED USE ONLY — Passive OSINT against systems you own or have
     explicit written permission to assess. See docs/RESPONSIBLE_USE.md
"""

MODULE_MAP = {
    "dork-scan":    ("Google Dork Scanner",              DorkScanner),
    "llm-recon":    ("LLM Vulnerability Recon",          LLMRecon),
    "github-intel": ("GitHub Intelligence",              GitHubIntel),
    "shodan-scan":  ("Shodan IoT/Infra Scanner",         ShodanScanner),
    "censys-scan":  ("Censys Infrastructure Scanner",    CensysScanner),
    "ivre-recon":   ("IVRE Open-Source Network Recon",   IVRERecon),
    "leakix-scan":  ("LeakIX Data Leak Scanner",         LeakIXScanner),
    "vendor-intel": ("Vendor Supply Chain Intel",        VendorIntel),
    "social-recon": ("Social Engineering Surface",       SocialRecon),
}


@click.command()
@click.option("--target",   "-t", default=None, help="Target organization name (e.g. 'Memorial Hospital')")
@click.option("--domain",   "-d", default=None, help="Target domain (e.g. memorialhospital.org)")
@click.option("--module",   "-m", default=None,
              type=click.Choice(list(MODULE_MAP.keys()) + ["all"]),
              help="Specific module to run, or 'all'")
@click.option("--all-modules", is_flag=True, default=False, help="Run all reconnaissance modules")
@click.option("--report",   "-r", is_flag=True, default=False, help="Generate report only (requires --input)")
@click.option("--input",    "-i", default=None,  help="Path to existing findings JSON for report generation")
@click.option("--output",   "-o", default="output", help="Output directory (default: ./output)")
@click.option("--format",   "-f", default="txt",
              type=click.Choice(["txt", "json", "both"]),
              help="Report output format (default: txt)")
@click.option("--config",   "-c", default="config/config.yaml", help="Config file path")
@click.option("--passive-only", is_flag=True, default=False, help="Disable direct HTTP endpoint checks")
@click.option("--enable-http-probes", is_flag=True, default=False, help="Allow optional low-impact HTTP endpoint checks when authorized")
@click.option("--verbose",  "-v", is_flag=True, default=False, help="Verbose output")
@click.option("--quiet",    "-q", is_flag=True, default=False, help="Suppress banner and progress output")
def main(target, domain, module, all_modules, report, input, output, format, config, passive_only, enable_http_probes, verbose, quiet):
    """
    IEEE CyberSalukis HealthGuard OSINT — Healthcare AI Attack Surface Reconnaissance

    Run OSINT reconnaissance against healthcare AI deployments to discover
    externally visible attack surface before adversaries do.

    Examples:\n
      python healthguard.py --target "Memorial Hospital" --domain memorialhospital.org --all-modules\n
      python healthguard.py -t "Health System" -d hs.org -m dork-scan\n
      python healthguard.py --report --input output/findings.json --format both
    """

    if not quiet:
        console.print(BANNER, style="bold cyan")

    # ── Load config ──────────────────────────────────────────────────────────
    cfg = load_config(config)
    if passive_only and enable_http_probes:
        console.print("[bold red]Error:[/bold red] Use either --passive-only or --enable-http-probes, not both.")
        sys.exit(1)

    cfg.setdefault("scope", {})
    if passive_only:
        cfg["scope"]["passive_only"] = True
    elif enable_http_probes:
        cfg["scope"]["passive_only"] = False

    if verbose:
        console.print(f"[dim]Config loaded from: {config}[/dim]")
        console.print(f"[dim]Passive-only mode: {cfg.get('scope', {}).get('passive_only', True)}[/dim]")

    # ── Report-only mode ─────────────────────────────────────────────────────
    if report:
        if not input:
            console.print("[bold red]Error:[/bold red] --report requires --input <findings.json>")
            sys.exit(1)
        _generate_report_only(input, output, format, cfg)
        return

    # ── Validate recon args ──────────────────────────────────────────────────
    if not target and not domain:
        console.print("[bold red]Error:[/bold red] Provide --target and/or --domain for reconnaissance.")
        console.print("  Example: python healthguard.py -t 'Memorial Hospital' -d memorialhospital.org --all-modules")
        sys.exit(1)

    run_all = all_modules or (module == "all")
    if not run_all and not module:
        console.print("[bold red]Error:[/bold red] Specify --module <name> or --all-modules")
        sys.exit(1)

    # ── Setup output dir ─────────────────────────────────────────────────────
    out_path = Path(output)
    out_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = (target or domain).replace(" ", "_").lower()
    session_id = f"{safe_target}_{timestamp}"

    console.print(Panel(
        f"[bold]Target:[/bold]  {target or 'Not specified'}\n"
        f"[bold]Domain:[/bold]  {domain or 'Not specified'}\n"
        f"[bold]Modules:[/bold] {'ALL' if run_all else module}\n"
        f"[bold]Session:[/bold] {session_id}",
        title="[bold cyan]Assessment Configuration[/bold cyan]",
        border_style="cyan"
    ))

    # ── Run modules ───────────────────────────────────────────────────────────
    all_findings = []
    modules_to_run = list(MODULE_MAP.keys()) if run_all else [module]

    for mod_key in modules_to_run:
        mod_label, ModClass = MODULE_MAP[mod_key]
        console.print(f"\n[bold cyan]▶ Running:[/bold cyan] {mod_label}")

        try:
            mod_instance = ModClass(
                target=target,
                domain=domain,
                config=cfg,
                verbose=verbose
            )
            findings = mod_instance.run()
            all_findings.extend(findings)

            status_color = "green" if findings else "yellow"
            console.print(f"  [bold {status_color}]✓[/bold {status_color}] {len(findings)} finding(s) from {mod_label}")

        except Exception as e:
            console.print(f"  [bold red]✗[/bold red] {mod_label} error: {e}")
            if verbose:
                import traceback
                traceback.print_exc()

    # ── Normalize & deduplicate ───────────────────────────────────────────────
    normalized = normalize_findings(all_findings)
    console.print(f"\n[bold]Total findings:[/bold] {len(normalized)} (after deduplication)")

    # ── Save raw findings JSON ────────────────────────────────────────────────
    findings_file = out_path / f"{session_id}_findings.json"
    with open(findings_file, "w") as f:
        json.dump({
            "meta": {
                "target": target,
                "domain": domain,
                "timestamp": timestamp,
                "session_id": session_id,
                "modules_run": modules_to_run,
                "total_findings": len(normalized)
            },
            "findings": normalized
        }, f, indent=2)

    console.print(f"[dim]Findings saved: {findings_file}[/dim]")

    # ── Generate report ───────────────────────────────────────────────────────
    generator = ReportGenerator(config=cfg)
    report_data = {
        "target": target,
        "domain": domain,
        "timestamp": timestamp,
        "session_id": session_id,
        "modules_run": modules_to_run,
        "findings": normalized
    }

    if format in ("txt", "both"):
        txt_file = out_path / f"{session_id}_report.txt"
        generator.generate_text_report(report_data, str(txt_file))
        console.print(f"[bold green]✓ Report:[/bold green] {txt_file}")

    if format in ("json", "both"):
        json_report_file = out_path / f"{session_id}_report.json"
        generator.generate_json_report(report_data, str(json_report_file))
        console.print(f"[bold green]✓ JSON Report:[/bold green] {json_report_file}")

    console.print(Panel(
        f"[bold green]Assessment Complete[/bold green]\n"
        f"Session: {session_id}\n"
        f"Findings: {len(normalized)}\n"
        f"Output: {out_path}/",
        border_style="green"
    ))


def _generate_report_only(input_file, output_dir, fmt, cfg):
    """Generate a report from an existing findings JSON file."""
    try:
        with open(input_file) as f:
            data = json.load(f)
    except FileNotFoundError:
        console.print(f"[bold red]Error:[/bold red] File not found: {input_file}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        console.print(f"[bold red]Error:[/bold red] Invalid JSON: {e}")
        sys.exit(1)

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    session_id = data.get("meta", {}).get("session_id", "report")
    generator = ReportGenerator(config=cfg)

    report_data = {
        "target":      data.get("meta", {}).get("target", "Unknown"),
        "domain":      data.get("meta", {}).get("domain", "Unknown"),
        "timestamp":   data.get("meta", {}).get("timestamp", "Unknown"),
        "session_id":  session_id,
        "modules_run": data.get("meta", {}).get("modules_run", []),
        "findings":    data.get("findings", [])
    }

    if fmt in ("txt", "both"):
        txt_file = out_path / f"{session_id}_report.txt"
        generator.generate_text_report(report_data, str(txt_file))
        console.print(f"[bold green]✓ Report:[/bold green] {txt_file}")

    if fmt in ("json", "both"):
        json_file = out_path / f"{session_id}_report.json"
        generator.generate_json_report(report_data, str(json_file))
        console.print(f"[bold green]✓ JSON Report:[/bold green] {json_file}")


if __name__ == "__main__":
    main()
