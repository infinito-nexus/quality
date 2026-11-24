import gettext
import json
import re
import unicodedata
from pathlib import Path

from flask import current_app, g, request
from markupsafe import Markup

DOMAIN = "quality"
DEFAULT = "en"
LOCALE = Path(__file__).parent / "locale"
SOURCE = json.loads((LOCALE / f"{DOMAIN}.yml").read_text(encoding="utf-8"))
PLACEHOLDER = re.compile(r"\{(\w+)\}")
RIGHT_TO_LEFT = frozenset({"R", "AL"})
SHARED_LINKS = frozenset({"pages.report"})


class Missing(gettext.NullTranslations):
    def pgettext(self, context, _message):
        raise LookupError(context)


def complete(translations):
    """
    Args:
        translations: Catalog of one language.

    Returns:
        Its translation of every source message, or None when one is missing, fuzzy or changes the placeholders.
    """
    translations.add_fallback(Missing())
    try:
        texts = [translations.pgettext(f"{DOMAIN}:{key}", text) for key, text in SOURCE.items()]
    except LookupError:
        return None
    for text, source in zip(texts, SOURCE.values()):
        if set(PLACEHOLDER.findall(text)) != set(PLACEHOLDER.findall(source)):
            return None
    return texts


def direction(texts):
    kinds = [unicodedata.bidirectional(char) for char in "".join(texts)]
    return "rtl" if sum(kind in RIGHT_TO_LEFT for kind in kinds) > kinds.count("L") else "ltr"


def load(locale):
    """
    Args:
        locale: Directory holding <code>/LC_MESSAGES/quality.mo.

    Returns:
        {code: (translations, text direction)} of English and every complete catalog.
    """
    languages = {DEFAULT: (gettext.NullTranslations(), "ltr")}
    for path in sorted(locale.glob(f"*/LC_MESSAGES/{DOMAIN}.mo")):
        with path.open("rb") as handle:
            translations = gettext.GNUTranslations(handle)
        texts = complete(translations)
        if texts is not None:
            languages[path.parent.parent.name] = (translations, direction(texts))
    return languages


def offered():
    return current_app.extensions["quality"]["languages"]


def choose_language():
    chosen = request.args.get("lang")
    g.explicit = chosen in offered()
    g.language = chosen if g.explicit else request.accept_languages.best_match(offered(), default=DEFAULT)


def keep_language(endpoint, values):
    if g.get("explicit") and endpoint not in SHARED_LINKS:
        values.setdefault("lang", g.language)


def translate(key, **values):
    """
    Args:
        key: Message key of locale/quality.yml.
        values: Placeholder values; Markup passes unescaped.

    Returns:
        The message in the request's language, HTML-escaped.
    """
    translations, _direction = offered()[g.language]
    parts = PLACEHOLDER.split(translations.pgettext(f"{DOMAIN}:{key}", SOURCE[key]))
    return Markup("").join(values[part] if index % 2 else part for index, part in enumerate(parts))


def language_context():
    return {
        "t": translate,
        "language": g.language,
        "direction": offered()[g.language][1],
        "languages": sorted(offered()),
    }


def vary(response):
    response.vary.add("Accept-Language")
    return response
