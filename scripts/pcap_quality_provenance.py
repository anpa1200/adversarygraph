"""Record revision/content identities without reading environment secrets."""
import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def run(*args):
    return subprocess.check_output(args, text=True, timeout=30).strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    tracked = run("git", "-C", str(root), "diff", "--name-only").splitlines()
    untracked = run("git", "-C", str(root), "ls-files", "--others", "--exclude-standard").splitlines()
    files = []
    for name in sorted(set(tracked + untracked)):
        path = root / name
        if path.is_symlink() or not path.is_file():
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        record = {"path": name, "sha256": digest}
        container = None
        if name.startswith("backend/app/"):
            container, deployed = "adversarygraph-api-1", "/app/" + name.removeprefix("backend/")
        elif name == "pcap_analyzer/app.py":
            container, deployed = "adversarygraph-pcap-analyzer-1", "/app/app.py"
        if container:
            actual = run("docker", "exec", container, "sha256sum", deployed).split()[0]
            record.update(container=container, deployed_sha256=actual, deployed_matches_source=actual == digest)
        files.append(record)
    ids = run("docker", "ps", "-q", "--filter", "label=com.docker.compose.project=adversarygraph").splitlines()
    containers = []
    for identifier in ids:
        data = json.loads(run("docker", "inspect", "--format", '{{json .Name}}', identifier))
        containers.append({"name": data.lstrip("/"),
                           "image": run("docker", "inspect", "--format", '{{.Config.Image}}', identifier),
                           "image_id": run("docker", "inspect", "--format", '{{.Image}}', identifier),
                           "state": run("docker", "inspect", "--format", '{{.State.Status}}', identifier),
                           "health": run("docker", "inspect", "--format", '{{if .State.Health}}{{.State.Health.Status}}{{end}}', identifier)})
    result = {"utc": datetime.now(timezone.utc).isoformat(), "worktree": str(root),
              "branch": run("git", "-C", str(root), "branch", "--show-current"),
              "base_commit": run("git", "-C", str(root), "rev-parse", "HEAD"),
              "committed": False, "pushed": False, "files": files, "containers": containers,
              "all_checked_deployed_sources_match": all(f.get("deployed_matches_source", True) for f in files)}
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    assert result["all_checked_deployed_sources_match"]
    print(json.dumps({"files": len(files), "checked_production_sources": sum("container" in f for f in files),
                      "all_sources_match": result["all_checked_deployed_sources_match"], "healthy_containers": sum(c["health"] == "healthy" for c in containers)}))


if __name__ == "__main__":
    main()
