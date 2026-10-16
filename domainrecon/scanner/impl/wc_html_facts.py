# =============================================================================
# DomainRecon - Contenu web : relevé des faits d'une page HTML (sans réseau)
# =============================================================================
# Analyseur unique, partagé par les modules du contenu web (tech_stack,
# html_intel, linked_domains, favicon_hash, js_dependencies, js_secrets) :
# scripts (externes et en ligne), feuilles de style et icônes, URL référencées,
# formulaires, métadonnées, commentaires, textes. Il évite les expressions
# régulières, qui se trompent sur l'ordre des attributs, les guillemets, les majuscules et les balises sur plusieurs lignes.
# Toutes les collections sont bornées : une page hostile ne gonfle pas la mémoire.
# =============================================================================

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

# Bornes (nombre d'éléments conservés, taille cumulée des textes).
MAX_URLS = 2000
MAX_SCRIPTS = 300
MAX_LINKS = 300
MAX_FORMS = 50
MAX_COMMENTS = 200
MAX_CLASSES = 3000
MAX_ATTR_VALUES = 3000
INLINE_SCRIPT_LIMIT = 256 * 1024
TEXT_LIMIT = 256 * 1024
COMMENT_LIMIT = 64 * 1024

# Attributs qui portent une URL (hors srcset, traité à part).
URL_ATTRIBUTES = ("src", "href", "action", "data-src", "poster", "formaction", "data")

_SRCSET_URL_RE = re.compile(r"(?:^|,)\s*([^\s,]+)")


class PageFacts(HTMLParser):
    """Relève les faits d'une page HTML : `PageFacts.parse(html, base_url)`."""

    def __init__(self, base_url: str = ""):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.urls: list[str] = []
        # {"src", "integrity", "crossorigin", "type", "tag_index"} des <script src>.
        self.scripts: list[dict] = []
        self.inline_scripts: list[str] = []
        # {"rel", "href", "integrity", "crossorigin", "as", "type", "sizes"} des <link>.
        self.links: list[dict] = []
        # {"action", "method", "has_password", "hidden": [noms]} des <form>.
        self.forms: list[dict] = []
        self.hidden_inputs: list[dict] = []
        self.metas: dict[str, str] = {}
        self.comments: list[str] = []
        self.attr_names: set[str] = set()
        self.attr_values: dict[str, str] = {}
        self.ids: set[str] = set()
        self.classes: set[str] = set()
        self.input_names: set[str] = set()
        self.mailto: list[str] = []
        self.text_parts: list[str] = []
        self.title: str | None = None
        self.base_href: str | None = None
        self._text_size = 0
        self._comment_size = 0
        self._inline_size = 0
        self._in_script = False
        self._in_style = False
        self._in_title = False
        self._inline_chunks: list[str] = []
        self._form_stack: list[dict] = []

    @classmethod
    def parse(cls, html: str, base_url: str = "") -> "PageFacts":
        facts = cls(base_url)
        try:
            facts.feed(html or "")
            facts.close()
        except Exception:  # noqa: BLE001 - HTML très mal formé : on garde ce qui a été relevé
            pass
        facts._flush_inline()
        return facts

    # --- Résolution d'URL -----------------------------------------------------

    def resolve(self, url: str) -> str | None:
        """URL absolue (http/https) d'une référence de la page, ou None (data:, javascript:, vide…)."""
        url = (url or "").strip()
        if not url or url.startswith("#"):
            return None
        base = self.base_href or self.base_url
        try:
            joined = urljoin(base, url) if base else url
            parts = urlsplit(joined)
        except ValueError:
            return None
        if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
            return None
        return joined

    # --- Analyse -----------------------------------------------------------------

    def _flush_inline(self) -> None:
        if self._inline_chunks:
            text = "".join(self._inline_chunks)
            self._inline_chunks = []
            if text.strip():
                self.inline_scripts.append(text)

    def handle_starttag(self, tag, attrs):
        values: dict[str, str] = {}
        for key, value in attrs:
            key = key.lower()
            values[key] = value or ""
            self.attr_names.add(key)
            if len(self.attr_values) < MAX_ATTR_VALUES and key not in self.attr_values:
                self.attr_values[key] = value or ""
        for key in URL_ATTRIBUTES:
            if values.get(key) and len(self.urls) < MAX_URLS:
                self.urls.append(values[key])
        if values.get("srcset"):
            for found in _SRCSET_URL_RE.findall(values["srcset"])[:20]:
                if len(self.urls) < MAX_URLS:
                    self.urls.append(found)
        if values.get("id"):
            self.ids.add(values["id"].lower())
        if values.get("class") and len(self.classes) < MAX_CLASSES:
            self.classes.update(values["class"].split())
        if tag == "base" and values.get("href") and self.base_href is None:
            self.base_href = self.resolve(values["href"])
        elif tag == "meta":
            name = (
                (values.get("name") or values.get("property") or values.get("http-equiv") or "")
                .strip()
                .lower()
            )
            if name and "content" in values and name not in self.metas:
                self.metas[name] = values["content"].strip()
        elif tag == "script":
            self._flush_inline()
            if values.get("src"):
                if len(self.scripts) < MAX_SCRIPTS:
                    self.scripts.append(
                        {
                            "src": values["src"].strip(),
                            "integrity": values.get("integrity", "").strip(),
                            "crossorigin": "crossorigin" in values,
                            "type": values.get("type", "").strip().lower(),
                        }
                    )
                self._in_script = False
            else:
                self._in_script = True
        elif tag == "style":
            self._in_style = True
        elif tag == "title":
            self._in_title = True
        elif tag == "link":
            if len(self.links) < MAX_LINKS:
                self.links.append(
                    {
                        "rel": " ".join(values.get("rel", "").lower().split()),
                        "href": values.get("href", "").strip(),
                        "integrity": values.get("integrity", "").strip(),
                        "crossorigin": "crossorigin" in values,
                        "as": values.get("as", "").lower(),
                        "type": values.get("type", "").lower(),
                        "sizes": values.get("sizes", "").lower(),
                    }
                )
        elif tag == "form":
            form = {
                "action": values.get("action", "").strip(),
                "method": (values.get("method") or "get").strip().lower(),
                "has_password": False,
                "hidden": [],
            }
            if len(self.forms) < MAX_FORMS:
                self.forms.append(form)
            self._form_stack.append(form)
        elif tag == "input":
            kind = values.get("type", "text").strip().lower()
            name = values.get("name", "").strip()
            if name:
                self.input_names.add(name.lower())
            form = self._form_stack[-1] if self._form_stack else None
            if kind == "password" and form is not None:
                form["has_password"] = True
            if kind == "hidden" and name and len(self.hidden_inputs) < 200:
                self.hidden_inputs.append({"name": name[:80], "value": values.get("value", "")[:80]})
                if form is not None and len(form["hidden"]) < 30:
                    form["hidden"].append(name[:80])
        elif tag == "a" and values.get("href", "").lower().startswith("mailto:"):
            target = values["href"][7:].split("?", 1)[0].strip()
            if target and len(self.mailto) < 100:
                self.mailto.extend(part.strip() for part in target.split(",") if part.strip())

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False
            self._flush_inline()
        elif tag == "style":
            self._in_style = False
        elif tag == "title":
            self._in_title = False
        elif tag == "form" and self._form_stack:
            self._form_stack.pop()

    def handle_data(self, data):
        if self._in_script:
            if self._inline_size < INLINE_SCRIPT_LIMIT:
                self._inline_chunks.append(data)
                self._inline_size += len(data)
        elif self._in_style:
            return
        else:
            if self._in_title and self.title is None and data.strip():
                self.title = data.strip()[:200]
            if self._text_size < TEXT_LIMIT:
                self.text_parts.append(data)
                self._text_size += len(data)

    def handle_comment(self, data):
        if len(self.comments) < MAX_COMMENTS and self._comment_size < COMMENT_LIMIT:
            self.comments.append(data)
            self._comment_size += len(data)

    # --- Aides -----------------------------------------------------------------------

    @property
    def text(self) -> str:
        return " ".join(self.text_parts)

    @property
    def inline_text(self) -> str:
        return "\n".join(self.inline_scripts)

    def resolved_urls(self) -> list[str]:
        """URL absolues http(s) de tout ce que la page référence, sans doublon, dans l'ordre."""
        seen: set[str] = set()
        found: list[str] = []
        for raw in self.urls:
            url = self.resolve(raw)
            if url and url not in seen:
                seen.add(url)
                found.append(url)
        return found
