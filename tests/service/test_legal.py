import json
import re

import jinja2
import pytest

from tests.service.support import ROLE, ROOT, load_launcher
from tests.service.webapp import BASE, build, headers

CONTROLLER = {
    "name": "Example & Operator",
    "street": "Example Street 7",
    "postal_code": "01234",
    "city": "Example City",
    "country": "Example Country",
    "email": "privacy@operator.example",
}
RESOLVERS = ["192.0.2.53", "198.51.100.53"]
HOST_LOG_DAYS = 5
LEGAL = {"controller": CONTROLLER, "resolvers": RESOLVERS, "host_log_days": HOST_LOG_DAYS}
RETENTION_HOURS = 7
SESSION_HOURS = 3
LOG_DIRECTIVES = {"access_log off;", "error_log /dev/null crit;"}
BASIS = re.compile(r"(?:Legal basis|Rechtsgrundlage): (Art\. 6\S*(?: Abs\. 1 lit\. [a-f])? (?:GDPR|DSGVO))")
LOG_CLAIMS = {
    "en": {
        "access": "The web server writes no access log and no error log for this service.",
        "container": "The containers that fetch and scan a submission keep no container log.",
    },
    "de": {
        "access": "Der Webserver schreibt für diesen Dienst kein Zugriffs- und kein Fehlerprotokoll.",
        "container": "Die Container, die eine Einreichung holen und prüfen, führen kein Container-Protokoll.",
    },
}
PRIVACY = {
    "en": {
        "sections": (
            ("Controller", ("Email:",)),
            ("What is processed, why, and on which legal basis", ()),
            (
                "Recipients",
                (
                    "Apart from the two below, there are no recipients outside the controller.",
                    "receives the host name, the repository path, the service's address",
                    f"DNS resolvers it is configured with ({', '.join(RESOLVERS)})",
                    "Legal basis for both: Art. 6(1)(b) GDPR",
                    "Keycloak",
                ),
            ),
            (
                "How long",
                (f"{RETENTION_HOURS} hours", f"{SESSION_HOURS} hours", "removed from memory with the next request"),
            ),
            (
                "What is not processed",
                (
                    LOG_CLAIMS["en"]["access"],
                    LOG_CLAIMS["en"]["container"],
                    "Other parts of the platform still write lines to the host's system journal",
                    "before the browser names the server (SNI)",
                    "plain HTTP",
                    "the www. variant or to an alias domain of the service",
                    "access lines of the controller's Keycloak",
                    "Keycloak event lines with the service's client ID",
                    "central log store (Loki)",
                    f"at most {HOST_LOG_DAYS} days",
                    "Legal basis for that: Art. 6(1)(f) GDPR",
                ),
            ),
            ("Outbound requests", ("through a proxy",)),
            ("Your rights", ("Art. 15 to 21 GDPR", "Art. 21 GDPR", "Art. 77 GDPR")),
            ("Automated decisions", ("Art. 22 GDPR",)),
            ("Obligation to provide data", ("not obliged",)),
        ),
        "items": (
            ("The repository URL", "Art. 6(1)(b) GDPR"),
            ("The report", "Art. 6(1)(b) GDPR"),
            ("Your network address", "Art. 6(1)(f) GDPR"),
            ("The host name of a repository URL submitted without login", "Art. 6(1)(f) GDPR"),
            ("After an optional login", "Art. 6(1)(b) GDPR"),
        ),
    },
    "de": {
        "sections": (
            ("Verantwortlicher", ("E-Mail:",)),
            ("Was verarbeitet wird, wozu und auf welcher Rechtsgrundlage", ()),
            (
                "Empfänger",
                (
                    "Abgesehen von den beiden folgenden gibt es keine Empfänger außerhalb des Verantwortlichen.",
                    "der den Hostnamen, den Pfad des Repositorys, die Adresse des Dienstes",
                    f"DNS-Resolver, mit denen er eingerichtet ist ({', '.join(RESOLVERS)})",
                    "Rechtsgrundlage für beides: Art. 6 Abs. 1 lit. b DSGVO",
                    "Keycloak",
                ),
            ),
            (
                "Wie lange",
                (f"{RETENTION_HOURS} Stunden", f"{SESSION_HOURS} Stunden", "mit der nächsten Anfrage"),
            ),
            (
                "Was nicht verarbeitet wird",
                (
                    LOG_CLAIMS["de"]["access"],
                    LOG_CLAIMS["de"]["container"],
                    "Andere Teile der Plattform schreiben trotzdem Zeilen in das Systemjournal des Hosts",
                    "bevor der Browser den Servernamen nennt (SNI)",
                    "unverschlüsseltes HTTP",
                    "die www.-Variante oder an eine Alias-Domain des Dienstes",
                    "Zugriffszeilen des Keycloak des Verantwortlichen",
                    "Ereigniszeilen von Keycloak mit der Client-ID des Dienstes",
                    "zentralen Protokollspeicher (Loki)",
                    f"höchstens {HOST_LOG_DAYS} Tage",
                    "Rechtsgrundlage dafür: Art. 6 Abs. 1 lit. f DSGVO",
                ),
            ),
            ("Ausgehende Anfragen", ("über einen Proxy",)),
            ("Ihre Rechte", ("Art. 15 bis 21 DSGVO", "Art. 21 DSGVO", "Art. 77 DSGVO")),
            ("Automatisierte Entscheidungen", ("Art. 22 DSGVO",)),
            ("Pflicht zur Bereitstellung", ("nicht verpflichtet",)),
        ),
        "items": (
            ("Die eingereichte Repository-URL", "Art. 6 Abs. 1 lit. b DSGVO"),
            ("Der Bericht", "Art. 6 Abs. 1 lit. b DSGVO"),
            ("Ihre Netzwerkadresse", "Art. 6 Abs. 1 lit. f DSGVO"),
            ("Der Hostname einer ohne Anmeldung eingereichten Repository-URL", "Art. 6 Abs. 1 lit. f DSGVO"),
            ("Nach einer freiwilligen Anmeldung", "Art. 6 Abs. 1 lit. b DSGVO"),
        ),
    },
}
QUAD9 = {
    "en": ("Quad9, based in Switzerland, a third country", "Decision 2000/518/EC", "Art. 45(9) GDPR"),
    "de": ("Quad9 mit Sitz in der Schweiz, einem Drittland", "Entscheidung 2000/518/EG", "Art. 45 Abs. 9 DSGVO"),
}
CORE_DEFAULTS = {
    "company": {
        "titel": "Infinito.Nexus by Inventor",
        "address": {"street": "Binary Avenue 01", "postal_code": "00001", "city": "Cybertown", "country": "Nexusland"},
    },
    "contact": {"email": "contact@infinito.nexus"},
}
OPERATOR = {
    "company": {
        "titel": "Example Operator",
        "address": {"street": "Example Street 7", "postal_code": "01234", "city": "Example City", "country": "Germany"},
    },
    "contact": {"email": "privacy@operator.example"},
}
DEMO_CASES = (
    ("untouched", CORE_DEFAULTS, "example.org", ["city", "country", "email", "name", "postal_code", "street"]),
    (
        "country-only",
        {
            **CORE_DEFAULTS,
            "company": {**CORE_DEFAULTS["company"], "address": {**CORE_DEFAULTS["company"]["address"], "country": "DE"}},
        },
        "example.org",
        ["city", "email", "name", "postal_code", "street"],
    ),
    ("operator", OPERATOR, "example.org", []),
    ("core-contact-on-own-domain", {**OPERATOR, "contact": CORE_DEFAULTS["contact"]}, "infinito.nexus", []),
    ("core-contact-on-foreign-domain", {**OPERATOR, "contact": CORE_DEFAULTS["contact"]}, "example.org", ["email"]),
)
STACK_INCLUDE = """    name: sys-stk-full
  vars:
    compose_handlers_flush: true
    webserver_extra_configuration: "{{ lookup('template', 'nginx/server.conf.j2') }}"
"""


def flake_packages():
    """
    Returns:
        nixpkgs attribute of every package the scan and proxy images of flake.nix bundle.
    """
    flake = (ROOT / "flake.nix").read_text(encoding="utf-8")
    block = re.search(r"toolPackages = \{([^}]*)\}", flake).group(1)
    tools = re.findall(r"=\s*(?:pkgs\.)?([\w.-]+);", block)
    scan = re.search(r"paths = tools \+\+ \(with pkgs; \[([^\]]*)\]\)", flake).group(1).split()
    proxy = re.search(r'"quality-proxy"; paths = \[([^\]]*)\]', flake).group(1).split()
    runner = re.search(r"runner = pkgs\.python3\.withPackages \(ps: \[([^\]]*)\]\)", flake).group(1).split()
    modules = {f"python3Packages.{name.removeprefix('ps.')}" for name in runner}
    return (set(tools + scan + proxy) - {"runner"}) | {"python3"} | modules


def table(page, name):
    return page.split(f'<table id="{name}">')[1].split("</table>")[0]


def page_of(app, path):
    response = app.test_client(use_cookies=False).get(path, headers=headers())
    assert response.status_code == 200
    return response.get_data(as_text=True)


def sections(page):
    main = page.split("<main>")[1].split("</main>")[0]
    return re.findall(r"<h2>(.*?)</h2>(.*?)(?=<h2>|\Z)", main, re.S)


def test_privacy_pages_hold_every_required_section(tmp_path):
    app, _state = build(tmp_path, **LEGAL)
    limits = app.extensions["quality"]["settings"]["limits"]
    limits.update(retention_hours=RETENTION_HOURS, session_hours=SESSION_HOURS)
    for language, expected in PRIVACY.items():
        page = page_of(app, f"/privacy?lang={language}")
        found = sections(page)
        assert [heading for heading, _body in found] == [heading for heading, _markers in expected["sections"]]
        for (heading, markers), (_heading, body) in zip(expected["sections"], found):
            for marker in markers:
                assert marker in body, (language, heading, marker)
        controller_section = found[0][1]
        for field, value in CONTROLLER.items():
            assert value.replace("&", "&amp;") in controller_section, (language, field)
        assert "{{" not in page and "{%" not in page
    assert app.test_client(use_cookies=False).get("/privacy?lang=fr", headers=headers()).status_code == 404


def test_privacy_pages_name_the_legal_basis_of_each_processing(tmp_path):
    app, _state = build(tmp_path, **LEGAL)
    for language, expected in PRIVACY.items():
        processing = sections(page_of(app, f"/privacy?lang={language}"))[1][1]
        items = [item.strip() for item in re.findall(r"<li>(.*?)</li>", processing, re.S)]
        assert len(items) == len(expected["items"]), language
        for item, (start, basis) in zip(items, expected["items"]):
            assert item.startswith(start), (language, start)
            assert BASIS.findall(item) == [basis], (language, start)


def test_privacy_log_claims_match_the_code(tmp_path):
    directives = (ROLE / "templates" / "nginx" / "server.conf.j2").read_text(encoding="utf-8").splitlines()
    assert {line.strip() for line in directives if "log" in line.strip().split(" ")[0]} == LOG_DIRECTIVES
    assert STACK_INCLUDE in (ROLE / "tasks" / "00_core.yml").read_text(encoding="utf-8")
    assert "--log-driver=none" in load_launcher().Launcher(BASE).sandbox("probe", "none")
    app, _state = build(tmp_path, **LEGAL)
    for language, claims in LOG_CLAIMS.items():
        page = page_of(app, f"/privacy?lang={language}")
        for claim in claims.values():
            assert claim in page, (language, claim)


def default_resolvers():
    services = (ROLE / "meta" / "services.yml").read_text(encoding="utf-8")
    block = re.search(r"^  dns_nameservers:\n((?:    - .+\n)+)", services, re.M).group(1)
    return [line.strip().removeprefix("- ") for line in block.splitlines()]


def test_privacy_names_quad9_only_for_the_default_resolvers(tmp_path):
    defaults, _state = build(tmp_path / "defaults", **{**LEGAL, "resolvers": default_resolvers()})
    others, _state = build(tmp_path / "others", **LEGAL)
    for language, markers in QUAD9.items():
        default_recipients = sections(page_of(defaults, f"/privacy?lang={language}"))[2][1]
        other_recipients = sections(page_of(others, f"/privacy?lang={language}"))[2][1]
        for marker in markers:
            assert marker in default_recipients, (language, marker)
            assert marker not in other_recipients, (language, marker)


@pytest.mark.parametrize(
    ("controller", "message"),
    [
        (None, "leaves controller name, street, postal_code, city, country, email empty"),
        ({**CONTROLLER, "email": " "}, "leaves controller email empty"),
    ],
)
def test_controller_data_is_required(tmp_path, controller, message):
    with pytest.raises(SystemExit, match=message):
        build(tmp_path, controller=controller)


def role_variable(name):
    text = (ROLE / "vars" / "main.yml").read_text(encoding="utf-8")
    return re.search(rf"^{name}:(.*?)(?=^\S)", text, re.S | re.M).group(1)


def demo_check(service_provider, environment, domain):
    """
    Args:
        service_provider: Merged service_provider of the inventory.
        environment: Core's ENVIRONMENT.
        domain: Core's DOMAIN_PRIMARY.

    Returns:
        (fields the role reports as demo data, whether its assert runs, whether the assert passes).
    """
    jinja = jinja2.Environment(undefined=jinja2.StrictUndefined)
    jinja.filters.update(
        dict2items=lambda mapping: [{"key": key, "value": value} for key, value in mapping.items()],
        intersect=lambda left, right: [item for item in left if item in right],
        difference=lambda left, right: [item for item in left if item not in right],
    )
    context = {
        "service_provider": service_provider,
        "defaults_service_provider": CORE_DEFAULTS,
        "DOMAIN_PRIMARY": domain,
        "ENVIRONMENT": environment,
    }
    for name in ("QUALITY_CHECK_CONTROLLER", "QUALITY_CHECK_CONTROLLER_DEFAULTS"):
        fields = re.findall(r'^  (\w+): "\{\{ (.+?) \}\}"$', role_variable(name), re.M)
        context[name] = {field: jinja.compile_expression(source)(**context) for field, source in fields}
    demo = role_variable("QUALITY_CHECK_CONTROLLER_DEMO_FIELDS").removeprefix(" >-").strip()
    demo = " ".join(demo.removeprefix("{{").removesuffix("}}").split())
    context["QUALITY_CHECK_CONTROLLER_DEMO_FIELDS"] = jinja.compile_expression(demo)(**context)
    tasks = (ROLE / "tasks" / "00_core.yml").read_text(encoding="utf-8")
    task = re.search(r"Refuse core's demo controller.*?that: (.+?)\n.*?when: (.+?)\n", tasks, re.S)
    runs = jinja.compile_expression(task.group(2))(**context)
    passes = jinja.compile_expression(task.group(1))(**context)
    return context["QUALITY_CHECK_CONTROLLER_DEMO_FIELDS"], runs, passes


@pytest.mark.parametrize(
    ("service_provider", "domain", "fields"),
    [case[1:] for case in DEMO_CASES],
    ids=[case[0] for case in DEMO_CASES],
)
def test_demo_controller_is_refused_outside_development(service_provider, domain, fields):
    assert demo_check(service_provider, "production", domain) == (fields, True, not fields)
    assert demo_check(service_provider, "development", domain)[1] is False


def test_notices_list_every_flake_package_at_its_locked_revision(tmp_path):
    app, _state = build(tmp_path, controller=CONTROLLER)
    page = page_of(app, "/notices")
    row = r'<tr><td><code>([^<]+)</code></td><td>([^<]+)</td><td><a href="(https?://[^"]+)">'
    rows = re.findall(row, table(page, "nix"))
    assert {attribute for attribute, _licence, _link in rows} == flake_packages()
    assert all(licence.strip() for _attribute, licence, _link in rows)
    lock = json.loads((ROOT / "flake.lock").read_text(encoding="utf-8"))
    for name in lock["nodes"]["root"]["inputs"].values():
        locked = lock["nodes"][name]["locked"]
        if locked["type"] == "tarball":
            assert f"<code>{name}</code>" in page, name
        else:
            assert locked["rev"] in page, name


def test_notices_list_every_web_image_package(tmp_path):
    app, _state = build(tmp_path, controller=CONTROLLER)
    web = table(page_of(app, "/notices"), "web")
    requirements = (ROOT / "service" / "web" / "requirements.txt").read_text(encoding="utf-8").split()
    dockerfile = (ROOT / "service" / "web" / "Dockerfile").read_text(encoding="utf-8")
    widget = re.search(r"registry\.npmjs\.org/altcha/-/altcha-([0-9.]+)\.tgz", dockerfile).group(1)
    pins = [pin.split("==") for pin in requirements] + [["altcha (widget)", widget]]
    for name, version in pins:
        row = rf"<tr><td><code>{re.escape(name)}</code></td><td>{re.escape(version)}</td><td>[^<]+</td>"
        assert re.search(row, web), name
