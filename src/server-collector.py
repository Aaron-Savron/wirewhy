"""Collect bounded server evidence. Invoked locally or streamed over SSH."""
import base64
import concurrent.futures
import datetime
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
from urllib.parse import urlsplit


def command(args):
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=4)
        return {"code": proc.returncode, "stdout": proc.stdout[:524288], "stderr": proc.stderr[:16384]}
    except FileNotFoundError:
        return {"code": 127, "stdout": "", "stderr": "Command not installed."}
    except subprocess.TimeoutExpired:
        return {"code": 124, "stdout": "", "stderr": "Command timed out."}


def state(result):
    value = result["stdout"].strip()
    if value in ("active", "inactive", "failed", "activating", "deactivating", "unknown"):
        return value
    return "unavailable"


def parse_config(text):
    # Keep quotes intact. Braces inside a quoted log_format are not blocks.
    pattern = r'''\#.*?$|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[{};]|(?:\$\{[^}]*\}|[^\s{};"'\#])+'''
    tokens = re.findall(pattern, text, re.M)
    root = {"name": "root", "directives": [], "children": []}
    stack = [root]
    pending = []
    for token in tokens:
        if token.startswith("#"):
            continue
        if token == "{":
            child = {"name": pending[0] if pending else "", "args": pending[1:], "directives": [], "children": []}
            stack[-1]["children"].append(child)
            stack.append(child)
            pending = []
        elif token == "}":
            if len(stack) > 1:
                stack.pop()
            pending = []
        elif token == ";":
            if pending:
                stack[-1]["directives"].append(pending)
            pending = []
        else:
            try:
                pending.append(shlex.split(token)[0])
            except (ValueError, IndexError):
                pending.append(token)
    return root


def walk(node):
    yield node
    for child in node["children"]:
        yield from walk(child)


def host_match(pattern, host):
    pattern = pattern.lower()
    if pattern == host:
        return True
    if pattern.startswith("*."):
        return host.endswith(pattern[1:])
    if pattern.startswith("."):
        return host == pattern[1:] or host.endswith(pattern)
    if pattern.endswith(".*"):
        return host.startswith(pattern[:-1])
    return False


def discover(text, host, prefix):
    tree = parse_config(text)
    matches = [node for node in walk(tree) if node["name"] == "server" and any(
        directive[0] == "server_name" and any(host_match(name, host) for name in directive[1:])
        for directive in node["directives"])]
    inherited = [directive for node in walk(tree) if node["name"] in ("root", "http")
                 for directive in node["directives"] if directive[0] in ("error_log", "access_log")]
    logs = []
    upstreams = []
    for node in matches:
        for kind in ("error_log", "access_log"):
            own = [directive for directive in node["directives"] if directive[0] == kind]
            inherited_kind = [directive for directive in inherited if directive[0] == kind]
            directives = [(directive, bool(own)) for directive in (own or inherited_kind)]
            directives += [(directive, True) for child in walk(node) if child is not node
                           for directive in child["directives"] if directive[0] == kind]
            for directive, scoped in directives:
                if len(directive) < 2 or directive[1] in ("off", "stderr") or "$" in directive[1] or directive[1].startswith("syslog:"):
                    continue
                path = directive[1] if os.path.isabs(directive[1]) else os.path.join(prefix, directive[1])
                logs.append({"path": path, "kind": "nginx-error" if kind == "error_log" else "nginx-access", "siteScoped": scoped})
    named = {node["args"][0]: [directive[1] for directive in node["directives"] if directive[0] == "server" and len(directive) > 1]
             for node in walk(tree) if node["name"] == "upstream" and node.get("args")}
    for node in matches:
        for child in walk(node):
            for directive in child["directives"]:
                if directive[0] in ("proxy_pass", "fastcgi_pass") and len(directive) > 1:
                    value = directive[1]
                    name = urlsplit(value).hostname if "://" in value else value
                    upstreams.extend(named.get(name, [value]))
    return {"matched": bool(matches), "logs": logs, "upstreams": upstreams}


def tail_file(path):
    try:
        if not stat.S_ISREG(os.stat(path).st_mode):
            return {"ok": False, "reason": "Not a regular log file."}
        with open(path, "rb") as stream:
            stream.seek(0, os.SEEK_END)
            size = stream.tell()
            start = max(0, size - 131072)
            stream.seek(start)
            lines = stream.read(131072).decode("utf-8", "replace").splitlines()
            if start and lines:
                lines = lines[1:]
            return {"ok": True, "lines": lines[-300:]}
    except PermissionError:
        return {"ok": False, "reason": "Permission denied. Try --sudo."}
    except (OSError, ValueError):
        return {"ok": False, "reason": "Log file is unavailable."}


def auto_service(upstreams):
    ports = set()
    for upstream in upstreams:
        match = re.match(r"(?:https?://)?(?:127\.0\.0\.1|localhost|\[::1\]):(\d+)", upstream)
        if match:
            ports.add(match.group(1))
    if not ports:
        return None
    sockets = command(["ss", "-ltnp"])
    for line in sockets["stdout"].splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[3].rsplit(":", 1)[-1] not in ports:
            continue
        pid = re.search(r"pid=(\d+)", line)
        if not pid:
            continue
        try:
            with open("/proc/" + pid.group(1) + "/cgroup") as stream:
                match = re.search(r"/([^/\n]+\.service)(?:/|$)", stream.read())
                if match:
                    return match.group(1)
        except OSError:
            pass
    return None


def collect(options):
    now = datetime.datetime.now().astimezone()
    output = {"collectedAt": now.isoformat(), "timezoneOffsetMinutes": int(now.utcoffset().total_seconds() / 60), "nginx": {}, "app": None, "logs": [], "issues": []}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        config_command = ["nginx", "-T"] + (["-c", options["nginxConfig"]] if options.get("nginxConfig") else [])
        futures = [pool.submit(command, args) for args in (["nginx", "-v"], config_command, ["systemctl", "is-active", "nginx"])]
        version, config, running = [future.result() for future in futures]
    available = version["code"] != 127
    process_state = state(running)
    processes = command(["pgrep", "-x", "nginx"])
    daemon = "running" if processes["code"] == 0 else "stopped" if processes["code"] == 1 else "unknown"
    if process_state == "unavailable" and available:
        process_state = "active" if daemon == "running" else "inactive" if daemon == "stopped" else "unknown"
    denied = "permission denied" in config["stderr"].lower()
    config_state = "ok" if config["code"] == 0 else "unavailable" if denied or config["code"] in (124, 127) else "invalid"
    match = re.search(r"nginx/[\w.\-]+", version["stderr"] + version["stdout"])
    output["nginx"] = {"installed": available, "version": match.group(0) if match else None, "service": process_state, "process": daemon, "config": config_state, "configError": config["stderr"] if config_state != "ok" else None}
    if denied:
        output["issues"].append("NGINX config needs elevated read access. Try --sudo.")
    prefix = "/usr/share/nginx"
    if config["code"] == 0:
        details = command(["nginx", "-V"])
        match = re.search(r"--prefix=(\S+)", details["stderr"])
        if match:
            prefix = match.group(1).strip("'\"")
    discovered = discover(config["stdout"], options["hostname"], prefix)
    output["nginx"]["siteMatched"] = discovered["matched"]
    service = options.get("service") or auto_service(discovered["upstreams"]) or options.get("discoveredService")
    if service:
        output["app"] = {"service": service, "state": state(command(["systemctl", "is-active", service])), "discovered": not bool(options.get("service"))}
    if not options.get("collectLogs"):
        return output
    log_sources = discovered["logs"] or [
        {"path": "/var/log/nginx/error.log", "kind": "nginx-error", "siteScoped": False},
        {"path": "/var/log/nginx/access.log", "kind": "nginx-access", "siteScoped": False}]
    log_sources += [{"path": path, "kind": "app-file", "siteScoped": True} for path in options.get("logs", [])]
    seen = set()
    for source in log_sources[:12]:
        if source["path"] in seen:
            continue
        seen.add(source["path"])
        output["logs"].append(dict(source, **tail_file(source["path"])))
    units = [("nginx.service", "nginx-journal", False)]
    if service:
        units.append((service, "app-journal", True))
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        journals = list(pool.map(lambda item: command(["journalctl", "--no-pager", "-o", "short-iso-precise", "--since", "-10min", "-n", "300", "-u", item[0]]), units))
    for (unit, kind, scoped), journal in zip(units, journals):
        output["logs"].append({"path": "journal:" + unit, "kind": kind, "siteScoped": scoped, "ok": journal["code"] == 0,
                               "lines": journal["stdout"].splitlines()[-300:] if journal["code"] == 0 else [],
                               "reason": None if journal["code"] == 0 else "Journal unavailable. Check read permissions."})
    return output


if __name__ == "__main__":
    try:
        options = json.loads(base64.b64decode(sys.argv[1]))
        print(json.dumps(collect(options)))
    except Exception:
        print(json.dumps({"error": "Server evidence collection failed."}))
        sys.exit(1)
