"""Sandtrap command line (hackathon-built). Usage: uv run python -m src.cli.sandtrap scan fixtures/gated-stealer"""

import argparse
import logging
import os
import sys
import time

os.environ.setdefault("CONSOLE_LOG_LEVEL", "WARNING")  # before the app imports configure logging; full logs still go to logs/

from rich.console import Console
from rich.panel import Panel

from src.app.sandtrap.graph import scan
from src.app.sandtrap.sandbox import gc

console = Console()
for noisy in ('httpcore', 'httpx', 'openai', 'langfuse', 'urllib3', 'hpack'):
    logging.getLogger(noisy).setLevel(logging.WARNING)


def narrate(kind: str, data: dict) -> None:
    if kind == "stage":
        console.print(f"[bold cyan]> {data['name']}[/] {data['detail']}")
    elif kind == "egress":
        console.print(f"  [yellow]egress locked:[/] {data['rules']}")
    elif kind == "install":
        console.print(f"  install ok={data['ok']} traced events={data['events']}")
    elif kind == "static":
        console.print(f"  [bold blue]static layer (capa)[/] {data['findings']} capability findings")
    elif kind == "baseline":
        console.print(f"  baseline: {data['events']} events, exit {data['exit']}")
    elif kind == "tool":
        console.print(f"  [dim]agent tool: {data['name']} {data['args']}[/]")
    elif kind == "hypothesis":
        p = data["probe"]
        console.print(Panel(f"{data['text']}\n[dim]lure={p['lure']} env={p['env']} clock+{p['clock_offset_days']}d[/]",
                            title=f"hypothesis -> experiment r{p['round']}", border_style="magenta"))
    elif kind == "probe_result":
        console.print("[dim]" + data["digest"][:900] + "[/]")
    elif kind == "skills":
        console.print(f"  [bold green]threat memory[/] skills from earlier scans tried first: {data['names']}")
    elif kind == "skill_learned":
        console.print(f"  [bold green]new skill learned[/] {data['name']}: {data['description']}")
    elif kind == "cache":
        console.print(f"  [bold green]threat memory[/] identical sample analysed before: serving the stored result")
    elif kind == "race":
        console.print(f"  [bold magenta]fork-and-race[/] {data['phase']} {({k: v for k, v in data.items() if k != 'phase'})}")
    elif kind == "verify":
        console.print(f"  [bold]patch verification[/] attempt {data['attempt']}: exfiltration={'YES' if data['leaked'] else 'no'} credential-reads={'YES' if data['read_creds'] else 'no'} smoke-test={'pass' if data['smoke_ok'] else 'FAIL'}")
    elif kind == "conclude":
        console.print(Panel(data["summary"], title="agent summary", border_style="green"))
    elif kind == "verdict":
        console.print(Panel(data["terminal"], title="SANDTRAP VERDICT", border_style="red" if data["verdict"] == "malicious" else "yellow"))


def main() -> int:
    parser = argparse.ArgumentParser(prog="sandtrap")
    sub = parser.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan a package directory or pypi:<name>")
    s.add_argument("target")
    s.add_argument("--out", default="out")
    s.add_argument("--probes", type=int, default=5)
    s.add_argument("--no-remediate", action="store_true")
    s.add_argument("--no-memory", action="store_true", help="do not read or write threat memory")
    s.add_argument("--enrich", action="store_true", help="add a cited threat brief from the deep-research agent (slow)")
    s.add_argument("--publish", action="store_true", help="host the report at a public CreateOS sandbox URL")
    s.add_argument("--cache", action="store_true", help="serve a stored result for an identical sample hash")
    sub.add_parser("doctor", help="verify Stripe Projects, CreateOS, LLM, Neon, Langfuse and capa")
    m = sub.add_parser("mail", help="run the email intake: scan pypi:<package> sent to the agent's AgentMail inbox")
    m.add_argument("--once", action="store_true")
    m.add_argument("--no-publish", action="store_true")
    pub = sub.add_parser("publish", help="publish an existing report folder at a public CreateOS URL")
    pub.add_argument("report_dir")
    g = sub.add_parser("gc", help="destroy leftover sandtrap-* sandboxes and their forks")
    g.add_argument("--all", action="store_true", help="destroy every live sandbox of the account")
    args = parser.parse_args()
    if args.cmd == "gc":
        console.print(f"removed {gc(everything=args.all)} sandbox(es)")
        return 0
    if args.cmd == "doctor":
        from src.app.sandtrap.doctor import run_doctor

        checks = run_doctor()
        for c in checks:
            console.print(f"  [{'green' if c.ok else 'red'}]{'OK  ' if c.ok else 'FAIL'}[/] {c.name:22} {c.detail}")
        return 0 if all(c.ok for c in checks if c.name != "langfuse") else 1
    if args.cmd == "mail":
        from src.app.sandtrap.mail import run as run_mail

        run_mail(once=args.once, publish=not args.no_publish, echo=console.print)
        return 0
    if args.cmd == "publish":
        from src.app.sandtrap.hosting import publish_report

        console.print(publish_report(args.report_dir))
        return 0
    started = time.time()
    report = scan(args.target, emit=narrate, out_dir=args.out, probe_budget=args.probes, remediate=not args.no_remediate,
                  use_memory=not args.no_memory, use_cache=args.cache, enrich=args.enrich)
    if args.publish:
        from src.app.sandtrap.hosting import publish_report

        report.report_url = publish_report(f"{args.out}/{report.job}")
        console.print(f"[bold green]public report:[/] {report.report_url}")
    console.print(f"[bold]done in {time.time() - started:.0f}s[/]  report: {args.out}/{report.job}/report.html  sandbox destroyed: {report.destroyed}")
    return 0 if report.verdict in ("clean", "malicious", "suspicious", "inconclusive") else 1


if __name__ == "__main__":
    sys.exit(main())
