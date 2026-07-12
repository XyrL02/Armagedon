"""
Armagedon BloodHound Analyzer Module

Load BloodHound ingested JSON files, analyze privilege escalation paths,
and auto-execute the most promising attack paths using Armagedon modules.

Modes:
    CHECK   — verify BloodHound files are loadable and show summary
    ANALYZE — find and display attack paths (no execution)
    EXPLOIT — find paths and auto-execute the most promising ones
"""

import os
import sys
import json
import logging
import importlib
from pathlib import Path
from datetime import datetime

log = logging.getLogger("armagedon.modules.auxiliary.bloodhound_analyzer")

CVE = "N/A"
DESCRIPTION = "BloodHound Attack Path Analyzer — load BH JSON, find privesc paths, auto-execute"
PLATFORM = "Windows"
RANK = "normal"
AUTHOR = "Armagedon"
DISCLOSURE = "N/A"

SAFE_MODE = int(os.environ.get("ARMAGEDON_SAFE_MODE", "1"))
SAFETY_LEVEL = "LOW"

OPTIONS = {
    "BLOODHOUND_DIR": "",
    "BLOODHOUND_FILE": "",
    "SOURCE_USER": "",
    "TARGET_SID": "",
    "MODE": "ANALYZE",
    "MAX_DEPTH": 6,
    "MAX_PATHS": 20,
    "AUTO_EXEC": False,
    "AUTO_EXEC_LIMIT": 5,
    "OUTPUT_DIR": "",
    "VERBOSE": False,
}

REQUIRED = {"BLOODHOUND_DIR": False, "BLOODHOUND_FILE": False}
DESCRIPTIONS = {
    "BLOODHOUND_DIR": "Directory containing BloodHound JSON files (users.json, groups.json, etc.)",
    "BLOODHOUND_FILE": "Single BloodHound JSON file (alternative to directory)",
    "SOURCE_USER": "SID or name of the source user to search from (empty = all users)",
    "TARGET_SID": "SID of the specific target to reach (empty = all high-value targets)",
    "MODE": "CHECK | ANALYZE | EXPLOIT (what to do with discovered paths)",
    "MAX_DEPTH": "Maximum path length (number of edges, default 6)",
    "MAX_PATHS": "Maximum paths to find (default 20)",
    "AUTO_EXEC": "Automatically execute auto-executable attack paths (EXPLOIT mode only)",
    "AUTO_EXEC_LIMIT": "Max number of paths to auto-execute (default 5)",
    "OUTPUT_DIR": "Output directory for exported paths (auto-generated if empty)",
    "VERBOSE": "Print detailed analysis output",
}


def _get_analyzer():
    """Import and return the BloodHoundAnalyzer."""
    from armagedon.core.bloodhound import BloodHoundAnalyzer
    return BloodHoundAnalyzer()


def _resolve_source_sid(analyzer, source: str) -> str:
    """Resolve a user name or SID to the actual object SID."""
    if not source:
        return None

    # Direct SID match
    if source in analyzer.nodes:
        return source

    # Name match
    for oid, node in analyzer.nodes.items():
        if node.name.lower() == source.lower():
            return oid
        # Match just the username part
        if "\\" in node.name:
            user_part = node.name.split("\\", 1)[1]
            if user_part.lower() == source.lower():
                return oid
        if "@" in node.name:
            user_part = node.name.split("@")[0]
            if user_part.lower() == source.lower():
                return oid

    log.warning("Source user not found: %s", source)
    return None


def _run_module(module_path: str, options: dict, verbose: bool = False) -> dict:
    """Dynamically import and run an Armagedon module."""
    try:
        # Convert path like "post/ad_post_enum" to import path
        parts = module_path.split("/")
        mod = importlib.import_module(f"armagedon.modules.{parts[0]}.{parts[1]}")

        if hasattr(mod, "check"):
            ok, msg = mod.check(options=options)
            if not ok:
                return {"success": False, "error": f"Check failed: {msg}"}

        if hasattr(mod, "run"):
            result = mod.run(options=options, mode="EXPLOIT")
            return result
        else:
            return {"success": False, "error": f"Module {module_path} has no run()"}
    except Exception as e:
        log.error("Failed to run %s: %s", module_path, e)
        return {"success": False, "error": str(e)}


# ─── Module interface ─────────────────────────────────────────────────────────

def check(options=None, target=None, **kwargs):
    """Verify BloodHound files are loadable."""
    opts = dict(options or {})
    bh_dir = opts.get("BLOODHOUND_DIR", "")
    bh_file = opts.get("BLOODHOUND_FILE", "")

    if not bh_dir and not bh_file:
        return False, "Set BLOODHOUND_DIR or BLOODHOUND_FILE to BloodHound JSON"

    if bh_dir:
        p = Path(bh_dir)
        if not p.is_dir():
            return False, f"Directory not found: {bh_dir}"
        jsons = list(p.glob("*.json"))
        if not jsons:
            return False, f"No JSON files in {bh_dir}"
        return True, f"Found {len(jsons)} JSON files in {bh_dir}"

    if bh_file:
        if not Path(bh_file).is_file():
            return False, f"File not found: {bh_file}"
        return True, f"File: {bh_file}"

    return False, "No BloodHound input specified"


def run(options=None, target=None, mode="CHECK", **kwargs):
    """Execute BloodHound analysis and optional auto-exploitation.

    Modes:
        CHECK   — verify files load and show summary
        ANALYZE — find and display attack paths (no execution)
        EXPLOIT — find paths and auto-execute promising ones
    """
    global OPTIONS
    opts = dict(options or {})
    if target:
        opts["RHOSTS"] = target
    OPTIONS.update(opts)

    bh_dir = opts.get("BLOODHOUND_DIR", "")
    bh_file = opts.get("BLOODHOUND_FILE", "")
    source_user = opts.get("SOURCE_USER", "")
    target_sid = opts.get("TARGET_SID", "")
    max_depth = int(opts.get("MAX_DEPTH", 6))
    max_paths = int(opts.get("MAX_PATHS", 20))
    auto_exec = opts.get("AUTO_EXEC", False)
    auto_exec_limit = int(opts.get("AUTO_EXEC_LIMIT", 5))
    verbose = opts.get("VERBOSE", False)

    log.info("bloodhound_analyzer mode=%s dir=%s file=%s", mode, bh_dir, bh_file)

    # ── Load BloodHound data ───────────────────────────────────────────────
    analyzer = _get_analyzer()

    if bh_dir:
        loaded = analyzer.load_from_directory(bh_dir)
    elif bh_file:
        loaded = analyzer.load_from_file(bh_file)
    else:
        return {"success": False, "error": "No BloodHound input specified"}

    if not loaded:
        return {"success": False, "error": "Failed to load BloodHound data"}

    summary = analyzer.summary()

    if mode.upper() == "CHECK":
        return {
            "success": True,
            "message": "BloodHound data loaded successfully",
            "summary": summary,
        }

    # ── Find attack paths ──────────────────────────────────────────────────
    source_sid = _resolve_source_sid(analyzer, source_user)

    if target_sid:
        # Filter high_value_nodes to just the target
        original_hv = analyzer.high_value_nodes.copy()
        analyzer.high_value_nodes = {target_sid} if target_sid in analyzer.nodes else set()

    paths = analyzer.find_attack_paths(
        source_sid=source_sid,
        max_depth=max_depth,
        max_paths=max_paths,
    )

    if target_sid:
        analyzer.high_value_nodes = original_hv

    analyzer.print_paths(max_display=20)

    # ── Export paths ───────────────────────────────────────────────────────
    output_dir = opts.get("OUTPUT_DIR", "")
    if not output_dir:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join(os.getcwd(), f"bloodhound_analysis_{ts}")
    os.makedirs(output_dir, exist_ok=True)

    export_path = os.path.join(output_dir, "attack_paths.json")
    analyzer.export_paths(export_path)

    # Write summary
    summary_path = os.path.join(output_dir, "summary.json")
    Path(summary_path).write_text(json.dumps(summary, indent=2))

    result = {
        "success": True,
        "summary": summary,
        "paths_found": len(paths),
        "export_path": export_path,
        "output_dir": output_dir,
    }

    # ── Auto-execute (EXPLOIT mode only) ──────────────────────────────────
    if mode.upper() == "EXPLOIT" and auto_exec and paths:
        exec_results = []
        executable = [p for p in paths if p.auto_executable]

        print(f"\n{'='*60}")
        print(f"  AUTO-EXECUTION: {len(executable)} executable paths "
              f"(limit: {auto_exec_limit})")
        print(f"{'='*60}\n")

        for i, path in enumerate(executable[:auto_exec_limit], 1):
            src = analyzer.nodes.get(path.source)
            tgt = analyzer.nodes.get(path.target)
            src_name = src.display_name if src else path.source
            tgt_name = tgt.display_name if tgt else path.target

            print(f"  [{i}/{auto_exec_limit}] Executing: {path.path_type}")
            print(f"      {src_name} → {tgt_name}")
            print(f"      Module: {path.auto_exec_module}")

            exec_opts = dict(path.auto_exec_options)
            # Fill in credentials from options
            if "USERNAME" not in exec_opts and opts.get("USERNAME"):
                exec_opts["USERNAME"] = opts["USERNAME"]
            if "PASSWORD" not in exec_opts and opts.get("PASSWORD"):
                exec_opts["PASSWORD"] = opts["PASSWORD"]
            if "DOMAIN" not in exec_opts and opts.get("DOMAIN"):
                exec_opts["DOMAIN"] = opts["DOMAIN"]
            if "RHOSTS" not in exec_opts and opts.get("RHOSTS"):
                exec_opts["RHOSTS"] = opts["RHOSTS"]

            # Resolve target hostname
            if tgt and tgt.object_type == "computer":
                hostname = tgt.properties.get("dnshostname", "")
                if hostname and "RHOSTS" not in exec_opts:
                    exec_opts["RHOSTS"] = hostname

            if not exec_opts.get("RHOSTS"):
                print("      [!] No target — skipping")
                exec_results.append({"path": i, "status": "skipped", "reason": "no target"})
                continue

            print(f"      Target: {exec_opts.get('RHOSTS', 'N/A')}")

            exec_result = _run_module(path.auto_exec_module, exec_opts, verbose)
            success = exec_result.get("success", False)
            status = "SUCCESS" if success else "FAILED"

            print(f"      Result: {status}")
            if not success:
                print(f"      Error: {exec_result.get('error', 'unknown')}")

            exec_results.append({
                "path": i,
                "path_type": path.path_type,
                "source": src_name,
                "target": tgt_name,
                "module": path.auto_exec_module,
                "status": status,
                "result": exec_result,
            })

        result["auto_exec_results"] = exec_results
        result["auto_executed"] = len([r for r in exec_results if r["status"] == "SUCCESS"])

    # ── Summary output ─────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  BLOODHOUND ANALYSIS COMPLETE")
    print(f"{'='*60}")
    print(f"  Nodes:         {summary.get('total_nodes', 0)}")
    print(f"  Edges:         {summary.get('total_edges', 0)}")
    print(f"  High-Value:    {summary.get('high_value_targets', 0)}")
    print(f"  Attack Paths:  {len(paths)}")
    print(f"  Output:        {output_dir}")
    if mode.upper() == "EXPLOIT" and auto_exec:
        executed = result.get("auto_executed", 0)
        print(f"  Auto-Executed: {executed}")
    print(f"{'='*60}\n")

    return result
