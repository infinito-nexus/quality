import json
from collections import Counter

from quality import QualityError, printable
from quality.image import engines

LETTERS = {"CRITICAL": "C", "HIGH": "H", "MEDIUM": "M", "LOW": "L", engines.UNKNOWN: "?"}
ORDER = tuple(LETTERS.values())
HINTS = 2
EMPTY = "-"
LATEST = "latest"
HEADER = "image\ttag\tsev\tfix\tnofix\tengines"


def split_ref(ref: str) -> tuple:
    """
    Args:
        ref: `[registry/]path[:tag][@digest]`.

    Returns:
        (key, name, tag): key is the last path segment and the tag, so
        registry and mirror prefixes join; tag is latest when none is named.
    """
    head, _, last = ref.split("@", 1)[0].rpartition("/")
    base, colon, tag = last.partition(":")
    tag = tag if colon else LATEST
    return f"{base}:{tag}", f"{head}/{base}" if head else base, tag


def loaded(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as stream:
            document = json.load(stream)
    except (OSError, ValueError) as error:
        raise QualityError(f"{path} is unreadable: {type(error).__name__}") from None
    if not isinstance(document, dict) or not all(isinstance(document.get(key), list) for key in ("findings", "unscanned")):
        raise QualityError(f"{path} is no `quality image --json` report")
    return document


def add_finding(rows: dict, finding: dict) -> None:
    key, name, tag = split_ref(finding["path"])
    row = rows.setdefault(key, {"image": name, "tag": tag, "engines": set(), "ids": {}})
    if len(name) > len(row["image"]):
        row["image"] = name
    row["engines"].update(finding["engines"])
    for identifier, entry in finding["vulnerabilities"].items():
        known = row["ids"].setdefault(identifier, {"severity": engines.UNKNOWN, "fixes": {}})
        known["severity"] = engines.graver(known["severity"], entry["severity"])
        if entry["fixed"]:
            fixes = known["fixes"]
            fixes[finding["package"]] = engines.highest([fixes.get(finding["package"], ""), entry["fixed"]])


def top_packages(ids: dict) -> list:
    """
    Args:
        ids: Id to its severity and fixes, package to fixed-in version.

    Returns:
        The HINTS packages that fix the most ids, each with the highest
        fixed-in version and that count.
    """
    counts = Counter(package for entry in ids.values() for package in entry["fixes"])
    best = {}
    for entry in ids.values():
        for package, version in entry["fixes"].items():
            best[package] = engines.highest([best.get(package, ""), version])
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:HINTS]
    return [{"package": package, "fixed": best[package], "ids": count} for package, count in ranked]


def image_row(row: dict) -> dict:
    ids = row["ids"]
    known = [entry["severity"] if entry["severity"] in LETTERS else engines.UNKNOWN for entry in ids.values()]
    counts = Counter(LETTERS[severity] for severity in known)
    return {
        "image": row["image"],
        "tag": row["tag"],
        "severities": {letter: counts[letter] for letter in ORDER},
        "fixed": sum(1 for entry in ids.values() if entry["fixes"]),
        "total": len(ids),
        "packages": top_packages(ids),
        "nofix": sorted(identifier for identifier, entry in ids.items() if not entry["fixes"]),
        "engines": sorted(row["engines"]),
    }


def weight(image: dict) -> tuple:
    return (*(-image["severities"][letter] for letter in ORDER), image["image"], image["tag"])


def reduced(paths: list) -> dict:
    """
    Args:
        paths: `quality image --json` reports.

    Returns:
        One row per image keyed by last path segment and tag, gravest first,
        and every unscanned image with its reason.

    Raises:
        QualityError: A report is unreadable or holds a finding without the
            fields `quality image` writes.
    """
    rows, unscanned = {}, []
    for path in paths:
        document = loaded(path)
        try:
            for item in document["findings"]:
                add_finding(rows, item)
            unscanned += [{"image": item["path"], "reason": item["reason"]} for item in document["unscanned"]]
        except (KeyError, TypeError, AttributeError):
            raise QualityError(f"{path} holds an entry `quality image --json` never writes") from None
    return {"images": sorted((image_row(row) for row in rows.values()), key=weight), "unscanned": unscanned}


def text_line(image: dict) -> str:
    severities = " ".join(f"{letter}{count}" for letter, count in image["severities"].items() if count) or EMPTY
    hints = "; ".join(f"{item['package']}>{item['fixed']}" for item in image["packages"])
    fix = f"{image['fixed']}/{image['total']} {hints}".rstrip()
    fields = (image["image"], image["tag"], severities, fix, ",".join(image["nofix"]) or EMPTY, ",".join(image["engines"]))
    return "\t".join(printable(field) for field in fields)


def report(paths: list, as_json: bool) -> int:
    """
    Args:
        paths: `quality image --json` reports.
        as_json: Print JSON instead of a tab-separated table.

    Returns:
        0 once the reduction is printed.

    Raises:
        QualityError: No report is named.
    """
    if not paths:
        raise QualityError("`quality image report` needs at least one `quality image --json` report")
    document = reduced(paths)
    if as_json:
        print(json.dumps(document, indent=2, sort_keys=True))
        return 0
    lines = [HEADER, *(text_line(image) for image in document["images"])]
    if document["unscanned"]:
        lines += ["unscanned:", *(printable(f"{item['image']}: {item['reason']}") for item in document["unscanned"])]
    print("\n".join(lines))
    return 0
