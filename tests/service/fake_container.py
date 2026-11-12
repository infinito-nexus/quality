"""
Args:
    argv[1]: JSON file holding {"info": text, "containers": [ids], "steps": {step: {"exit": n, "stdout": text}}},
        info being what `info` prints and step the last part of the container name (fetch, prepare, scan,
        database).
    argv[2]: JSON-lines file each call appends {"argv": [...], "stdin": text or null} to.
    argv[3:]: The container CLI arguments the launcher passes.

Exit codes:
    The configured exit of a `run` step, else 0.
"""

import json
import sys


def main(behaviour_file, calls_file, *args):
    with open(behaviour_file, encoding="utf-8") as handle:
        behaviour = json.load(handle)
    stdin = sys.stdin.buffer.read().decode("utf-8", "replace") if "--interactive" in args else None
    with open(calls_file, "a", encoding="utf-8") as handle:
        handle.write(json.dumps({"argv": list(args), "stdin": stdin}) + "\n")
    if args[0] == "info":
        sys.stdout.write(behaviour["info"])
    elif args[:2] == ("ps", "-aq"):
        print("\n".join(behaviour["containers"]))
    elif args[0] == "run":
        name = next(arg for arg in args if arg.startswith("--name="))
        step = behaviour["steps"][name.rsplit("-", 1)[-1]]
        sys.stdout.write(step["stdout"])
        return step["exit"]
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
