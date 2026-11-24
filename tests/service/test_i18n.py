import gettext
import re

from flask import url_for
from quality_web import ERRORS, i18n

from tests.service.webapp import build, headers

TEMPLATES = i18n.LOCALE.parent / "templates"
ARABIC = "فحص"


class Catalog(gettext.NullTranslations):
    def __init__(self, texts):
        super().__init__()
        self.texts = texts

    def pgettext(self, context, message):
        if context in self.texts:
            return self.texts[context]
        return super().pgettext(context, message)


def tagged(code):
    return Catalog({f"{i18n.DOMAIN}:{key}": f"[{code}] {text}" for key, text in i18n.SOURCE.items()})


def with_languages(tmp_path):
    app, _state = build(tmp_path)
    app.extensions["quality"]["languages"].update(fr=(tagged("fr"), "ltr"), ar=(tagged("ar"), "rtl"))
    return app


def page(app, path, **extra):
    response = app.test_client(use_cookies=False).get(path, headers=headers(**extra))
    assert response.status_code == 200
    return response


def test_every_source_key_is_used_and_every_used_key_exists():
    used = set()
    for template in TEMPLATES.glob("*.html.j2"):
        used |= set(re.findall(r"""\bt\(["']([\w.]+)["']""", template.read_text(encoding="utf-8")))
    used |= {"pending.queued", "pending.running"} | {f"error.{code}" for code in ERRORS}
    assert used == set(i18n.SOURCE)


def test_complete_requires_every_message_with_its_placeholders():
    full = {f"{i18n.DOMAIN}:{key}": text for key, text in i18n.SOURCE.items()}
    assert i18n.complete(Catalog(dict(full))) == list(i18n.SOURCE.values())
    missing = dict(full)
    missing.pop(f"{i18n.DOMAIN}:brand")
    assert i18n.complete(Catalog(missing)) is None
    renamed = {**full, f"{i18n.DOMAIN}:index.file": "{size} KiB"}
    assert i18n.complete(Catalog(renamed)) is None


def test_direction_follows_the_script():
    assert i18n.direction([ARABIC, "quality"]) == "rtl"
    assert i18n.direction(["Quality check"]) == "ltr"


def test_english_is_the_only_language_without_compiled_catalogs(tmp_path):
    app, _state = build(tmp_path)
    assert sorted(app.extensions["quality"]["languages"]) == [i18n.DEFAULT]
    body = page(app, "/", **{"Accept-Language": "fr"}).get_data(as_text=True)
    assert '<html lang="en" dir="ltr">' in body
    assert 'name="lang"' not in body


def test_accept_language_picks_the_interface_language(tmp_path):
    response = page(with_languages(tmp_path), "/", **{"Accept-Language": "fr-CH, de;q=0.5"})
    body = response.get_data(as_text=True)
    assert '<html lang="fr" dir="ltr">' in body
    assert "[fr] Static quality scan" in body
    assert "lang=fr" not in body.split("<main>")[0]
    assert "Accept-Language" in response.headers["Vary"]


def test_lang_parameter_wins_and_follows_every_link(tmp_path):
    body = page(with_languages(tmp_path), "/?lang=ar", **{"Accept-Language": "fr"}).get_data(as_text=True)
    assert '<html lang="ar" dir="rtl">' in body
    assert 'href="/privacy?lang=ar"' in body
    assert 'action="/submit?lang=ar"' in body


def test_report_links_stay_language_free(tmp_path):
    app = with_languages(tmp_path)
    with app.test_request_context("/?lang=ar", headers=headers()):
        i18n.choose_language()
        assert url_for("pages.report", job_id="abc") == "/r/abc"
        assert url_for("pages.notices") == "/notices?lang=ar"


def test_unknown_lang_parameter_falls_back_to_accept_language(tmp_path):
    body = page(with_languages(tmp_path), "/?lang=xx", **{"Accept-Language": "fr"}).get_data(as_text=True)
    assert '<html lang="fr" dir="ltr">' in body
    assert "lang=xx" not in body


def test_placeholder_values_are_escaped(tmp_path):
    app = with_languages(tmp_path)
    with app.test_request_context("/?lang=fr", headers=headers()):
        i18n.choose_language()
        assert i18n.translate("report.failed", reason="<b>") == "[fr] Not checked: &lt;b&gt;."


def legal_body(page, language):
    marker = f'<div lang="{language}" dir="ltr">'
    assert marker in page
    return page.split(marker)[1].split("</main>")[0]


def test_legal_pages_stay_authored(tmp_path):
    app = with_languages(tmp_path)
    english = page(app, "/privacy?lang=en").get_data(as_text=True)
    french = page(app, "/privacy?lang=fr").get_data(as_text=True)
    german = page(app, "/privacy?lang=de", **{"Accept-Language": "fr"}).get_data(as_text=True)
    assert "[fr] This page exists in English and German only." in french
    assert legal_body(french, "en") == legal_body(english, "en")
    assert legal_body(german, "de")
    assert "This page exists in English and German only." not in english + german
