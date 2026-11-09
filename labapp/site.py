"""Storefront pages for the deeper lab trials.

``scan_xss`` takes one URL and one parameter. These pages exist so that URL can
be an ordinary shop page instead of a labelled fixture. Every sink here is
still a GET query parameter reflected into the HTML body, which is the
documented contract; the sinks are simply buried inside normal markup. The
canonical /body, /attribute, /script, /url, /encoded and /multi routes stay in
``app.py`` for the acceptance fixtures and the demo.

Two pages are deliberately *not* reachable by a GET scan: /search only reflects
on POST, and /suggest renders client-side. They are diagnostics, not sinks.

ponytail: hand-written strings and one stylesheet. No template engine, no
database, no external asset. If a page grows past a screenful, split it before
adding a dependency.
"""

from __future__ import annotations

from html import escape

NAV = (
    ("/", "Home"),
    ("/catalog", "Catalog"),
    ("/support", "Support"),
    ("/share", "Share"),
)

PRODUCTS = (
    {"sku": "VF-101", "name": "Linen table runner", "tag": "table", "price": "$48",
     "blurb": "Stone-washed linen, 180 cm."},
    {"sku": "VF-102", "name": "Stoneware carafe", "tag": "table", "price": "$36",
     "blurb": "Unglazed outside, sealed within."},
    {"sku": "VF-103", "name": "Oak serving board", "tag": "kitchen", "price": "$54",
     "blurb": "Oiled European oak, 42 cm."},
    {"sku": "VF-104", "name": "Wool throw", "tag": "living", "price": "$92",
     "blurb": "Undyed lambswool, 130 × 180 cm."},
    {"sku": "VF-105", "name": "Ceramic mug, set of two", "tag": "kitchen", "price": "$28",
     "blurb": "Speckled glaze, 300 ml."},
    {"sku": "VF-106", "name": "Paper shade pendant", "tag": "living", "price": "$64",
     "blurb": "Folded washi paper, 35 cm."},
)

SUGGESTIONS = (
    "linen table runner",
    "stoneware carafe",
    "oak serving board",
    "wool throw",
    "ceramic mug set",
    "paper shade pendant",
)

CSS = """
:root{--ink:#191b1f;--muted:#5d6169;--paper:#fbfaf8;--card:#fff;--line:#e4e0da;
--accent:#265f4e;--radius:14px}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);
font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
a{color:var(--accent)}
.wrap{max-width:1040px;margin:0 auto;padding:0 22px}
.site-header{border-bottom:1px solid var(--line);background:#fff}
.site-header .wrap{display:flex;align-items:center;gap:26px;justify-content:space-between;
padding-top:16px;padding-bottom:16px;flex-wrap:wrap}
.brand{font-weight:650;letter-spacing:-.01em;font-size:19px;text-decoration:none;color:var(--ink)}
.brand span{color:var(--accent)}
nav a{margin-left:20px;text-decoration:none;color:var(--muted);font-size:15px}
nav a[aria-current="page"]{color:var(--ink);font-weight:600}
.hero{padding:64px 0 48px;background:linear-gradient(180deg,#f1f5f2,#fbfaf8)}
.hero h1{font-size:clamp(30px,5vw,46px);line-height:1.1;margin:0 0 14px;letter-spacing:-.02em}
.hero p{max-width:46ch;color:var(--muted);margin:0 0 24px}
.button{display:inline-block;background:var(--accent);color:#fff;padding:11px 20px;
border-radius:999px;text-decoration:none;font-weight:600;font-size:15px;border:0}
.button.secondary{background:#fff;color:var(--ink);border:1px solid var(--line)}
.page-head{padding:40px 0 8px}
.page-head h1{margin:0 0 6px;font-size:32px;letter-spacing:-.02em}
.lede{color:var(--muted);margin:0 0 18px}
.filters{display:flex;gap:12px;flex-wrap:wrap;align-items:end;margin:22px 0 8px}
.filters label{display:flex;flex-direction:column;gap:6px;font-size:13px;color:var(--muted)}
input,select{font:inherit;padding:9px 11px;border:1px solid var(--line);border-radius:10px;
background:#fff;color:var(--ink);min-width:190px}
button{font:inherit;padding:10px 18px;border-radius:10px;border:1px solid var(--accent);
background:var(--accent);color:#fff;font-weight:600}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0 0}
.chip{background:#eef3f0;color:var(--accent);border-radius:999px;padding:5px 12px;font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:18px;
padding:26px 0 56px}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);
padding:18px;display:flex;flex-direction:column;gap:6px;text-decoration:none;color:inherit}
.card .thumb{height:120px;border-radius:10px;background:linear-gradient(135deg,#e9efe9,#dbe7e0);
margin-bottom:6px}
.card h2{font-size:16px;margin:0}
.card .price{margin:0;color:var(--muted);font-size:14px}
.card .meta{font-size:12px;color:var(--muted);letter-spacing:.04em;text-transform:uppercase;
margin:0}
.card .more{margin-top:auto;font-size:14px;text-decoration:none;font-weight:600;color:var(--accent)}
.sku{font:12px/1 ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--muted)}
.crumb{font-size:13px;color:var(--muted);margin:0 0 14px}
.faq{display:grid;gap:14px;padding:20px 0 8px}
.faq article{background:#fff;border:1px solid var(--line);border-radius:var(--radius);
padding:16px 18px}
.faq h2{font-size:16px;margin:0 0 5px}
.faq p{margin:0;color:var(--muted);font-size:15px}
.widget{background:#fff;border:1px solid var(--line);border-radius:var(--radius);
padding:16px 18px;margin:18px 0 56px}
.panel{background:#fff;border:1px solid var(--line);border-radius:var(--radius);
padding:20px 22px;margin:22px 0 56px}
.site-footer{border-top:1px solid var(--line);padding:26px 0 40px;color:var(--muted);
font-size:13px}
.site-footer a{color:var(--muted);margin-right:16px}
@media (max-width:560px){.hero{padding:44px 0 30px}nav a{margin:0 14px 0 0}}
"""


def layout(title: str, body: str, active: str = "") -> bytes:
    links = []
    for href, label in NAV:
        current = ' aria-current="page"' if href == active else ""
        links.append(f'<a href="{href}"{current}>{label}</a>')
    return (
        "<!doctype html>\n<html lang=\"en\">\n<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{escape(title)} · Verity Home</title>\n"
        '<link rel="stylesheet" href="/assets/site.css">\n'
        "</head>\n<body>\n"
        '<header class="site-header"><div class="wrap">'
        '<a class="brand" href="/">Verity <span>Home</span></a>'
        f"<nav>{''.join(links)}</nav></div></header>\n"
        f"{body}\n"
        '<footer class="site-footer"><div class="wrap">'
        '<a href="/catalog">Catalog</a><a href="/reviews">Reviews</a>'
        '<a href="/support">Support</a>'
        "<p>Verity Home · 14 Alder Lane, Bristol · Mon–Fri 9–5</p>"
        "</div></footer>\n</body>\n</html>"
    ).encode("utf-8")


def _cards(items: tuple[dict, ...], query: str = "") -> str:
    hint = f' data-query="{query}"' if query else ""
    if not items:
        return f'<p class="lede"{hint}>No products match these filters.</p>'
    cards = []
    for product in items:
        cards.append(
            '<a class="card" href="/products?sku=' + product["sku"] + '">'
            '<span class="thumb"></span>'
            f'<p class="meta">{product["tag"]}</p>'
            f'<h2>{product["name"]}</h2>'
            f'<p class="price">{product["price"]}</p>'
            f'<p class="price">{product["blurb"]}</p>'
            '<span class="more">View details</span></a>'
        )
    return f'<div class="grid"{hint}>' + "".join(cards) + "</div>"


def home() -> bytes:
    rooms = (
        ("table", "Linen &amp; stoneware", "From $18"),
        ("kitchen", "Boards &amp; mugs", "From $28"),
        ("living", "Throws &amp; lighting", "From $64"),
    )
    cards = "".join(
        f'<a class="card" href="/catalog?q={tag}"><span class="thumb"></span>'
        f'<p class="meta">{tag}</p><h2>{name}</h2>'
        f'<p class="price">{price}</p>'
        '<span class="more">Shop the range</span></a>'
        for tag, name, price in rooms
    )
    body = (
        '<main><section class="hero"><div class="wrap">'
        "<h1>Everyday objects, made to last.</h1>"
        "<p>Linen, stoneware and oak for the rooms you actually live in. "
        "Packed by hand in Bristol, free returns for 30 days.</p>"
        '<a class="button" href="/catalog">Browse the catalog</a>'
        '</div></section><div class="wrap">'
        f'<div class="grid">{cards}</div></div></main>'
    )
    return layout("Home", body, "/")


def catalog(q: str = "", sort: str = "", page: str = "") -> bytes:
    """Catalog page.

    The heading echoes the search term escaped. The filter chip echoes it raw
    as a text node. The product grid also copies it raw into ``data-query``.
    The two raw sinks are different contexts, so a scan can confirm both; the
    escaped heading stays inert.
    """
    safe = escape(q, quote=True)
    try:
        page_no = max(1, min(20, int(page or "1")))
    except ValueError:
        page_no = 1
    if sort == "price":
        items = tuple(sorted(PRODUCTS, key=lambda item: item["price"]))
    elif sort == "name":
        items = tuple(sorted(PRODUCTS, key=lambda item: item["name"]))
    else:
        items = PRODUCTS
    if q:
        needle = q.lower()
        items = tuple(
            item
            for item in items
            if needle in item["name"].lower()
            or needle in item["tag"].lower()
            or needle in item["blurb"].lower()
        )
    selected = {
        "relevance": "", "price": "", "name": "",
    }
    for key in selected:
        selected[key] = ' selected' if key == sort else ""

    chips = ""
    if q:
        chips = f'<div class="chips"><span class="chip">{q}</span></div>'

    heading = f"Results for “{safe}”" if q else "Six pieces we make all year."
    body = (
        '<main class="wrap"><section class="page-head">'
        "<h1>Catalog</h1>"
        f'<p class="lede">{heading}</p></section>'
        '<form class="filters" method="get" action="/catalog">'
        '<label>Search<input name="q" placeholder="Linen, oak, mug" autocomplete="off"></label>'
        '<label>Sort<select name="sort">'
        f'<option value="relevance"{selected["relevance"]}>Relevance</option>'
        f'<option value="price"{selected["price"]}>Price</option>'
        f'<option value="name"{selected["name"]}>Name</option>'
        "</select></label>"
        "<button>Apply</button></form>"
        f"{chips}"
        f'<p class="crumb">Page {page_no}</p>'
        f"{_cards(items, q)}"
        "</main>"
    )
    return layout("Catalog", body, "/catalog")


def products(sku: str = "") -> bytes:
    """Product detail. The SKU is echoed raw into a data attribute."""
    match = next((item for item in PRODUCTS if item["sku"] == sku), None)
    name = match["name"] if match else "Product detail"
    if match:
        detail = (
            '<div class="panel">'
            f'<h1>{match["name"]}</h1>'
            f'<p class="lede">{match["blurb"]} In stock, ships in two working days.</p>'
            f'<p class="price">{match["price"]}</p>'
            '<a class="button" href="/catalog">Back to the catalog</a>'
            "</div>"
        )
    else:
        detail = (
            '<div class="panel"><h1>We could not find that piece.</h1>'
            '<p class="lede">It may have sold out. Browse the catalog for what is '
            "available this week.</p>"
            '<a class="button" href="/catalog">Browse the catalog</a></div>'
        )
    body = (
        '<main class="wrap"><section class="page-head">'
        f'<p class="crumb">Catalog / <span class="sku" data-sku="{sku}">{name}</span></p>'
        f"</section>{detail}</main>"
    )
    return layout("Product", body, "/catalog")


def support(topic: str = "") -> bytes:
    """Support page. The topic is echoed raw into an inline widget config."""
    topic_js = topic or "orders"
    articles = (
        ("Delivery", "Orders leave Bristol within two working days. "
                     "Tracking arrives by email the evening they ship."),
        ("Returns", "Unused pieces can go back within 30 days. "
                    "We pay the return postage on orders over $75."),
        ("Care", "Linen softens with every wash. Machine wash cold, "
                 "line dry, and skip the iron if you can."),
    )
    faq = "".join(
        f'<article><h2>{title}</h2><p>{text}</p></article>'
        for title, text in articles
    )
    body = (
        '<main class="wrap"><section class="page-head">'
        "<h1>Support</h1>"
        '<p class="lede">Answers to the questions we get most weeks.</p></section>'
        f'<section class="faq">{faq}</section>'
        '<div class="widget"><p class="meta">Help widget</p>'
        '<p>Suggested reading for <strong id="topic-label">orders</strong>.</p></div>'
        "<script>window.VerityHelp = "
        f'{{ topic: "{topic_js}", locale: "en-GB", theme: "light" }};</script>'
        "<script>"
        'var config = window.VerityHelp || {};'
        'var label = document.getElementById("topic-label");'
        'if (label && config.topic) { label.textContent = config.topic; }'
        "</script></main>"
    )
    return layout("Support", body, "/support")


def share(next_url: str = "") -> bytes:
    """Share page. The continue link keeps the caller's next step."""
    target = next_url or "/catalog"
    body = (
        '<main class="wrap"><section class="page-head">'
        "<h1>Share this list</h1>"
        '<p class="lede">Send the catalog to someone, or pick up where you left off.</p>'
        "</section>"
        '<div class="panel"><p>Your list is saved to this browser. '
        "Continue when you are ready.</p>"
        f'<a class="button" href="{target}">Continue shopping</a></div></main>'
    )
    return layout("Share", body, "/share")


def reviews(q: str = "") -> bytes:
    """Customer reviews. Every echo is escaped; this is the lookalike page."""
    safe = escape(q, quote=True)
    notes = (
        ("Alder table runner", "Washed it four times and it still hangs straight."),
        ("Stoneware carafe", "Pours without a drip, which is rarer than it sounds."),
        ("Wool throw", "Warm without the itch. The undyed colour suits the sofa."),
    )
    cards = "".join(
        f'<article><h2>{title}</h2><p>{text}</p></article>' for title, text in notes
    )
    heading = f"Matching “{safe}”" if q else "What people say after a season of use."
    body = (
        '<main class="wrap"><section class="page-head">'
        "<h1>Reviews</h1>"
        f'<p class="lede">{heading}</p></section>'
        f'<section class="faq">{cards}</section></main>'
    )
    return layout("Reviews", body, "/catalog")


def search_form() -> bytes:
    """GET /search. The form posts; the query string is never echoed here."""
    body = (
        '<main class="wrap"><section class="page-head">'
        "<h1>Search</h1>"
        '<p class="lede">Find a piece by name or material.</p></section>'
        '<form class="filters" method="post" action="/search">'
        '<label>Search the catalog<input name="q" placeholder="Wool, oak, carafe" '
        'autocomplete="off"></label>'
        "<button>Search</button></form></main>"
    )
    return layout("Search", body, "/catalog")


def search_results(q: str) -> bytes:
    """POST /search. The term is echoed raw; there is no GET form of this page."""
    needle = q.lower()
    items = tuple(
        item
        for item in PRODUCTS
        if needle in item["name"].lower()
        or needle in item["tag"].lower()
        or needle in item["blurb"].lower()
    )
    body = (
        '<main class="wrap"><section class="page-head">'
        "<h1>Search</h1>"
        f'<p class="lede">Results for “{q}”</p></section>'
        f"{_cards(items)}</main>"
    )
    return layout("Search results", body, "/catalog")


def suggest() -> bytes:
    """GET /suggest. Suggestions are rendered client-side from location.search."""
    items = "".join(
        f"<li>{item}</li>" for item in SUGGESTIONS
    )
    body = (
        '<main class="wrap"><section class="page-head">'
        "<h1>Suggestions</h1>"
        '<p class="lede">Start typing a material or a room.</p></section>'
        '<div class="panel"><ul id="suggestions">'
        f"{items}</ul></div>"
        "<script>"
        'var term = (new URLSearchParams(location.search).get("q") || "").toLowerCase();'
        'var list = document.getElementById("suggestions");'
        "if (list && term) {"
        'Array.prototype.slice.call(list.children).forEach(function (item) {'
        'item.style.display = item.textContent.toLowerCase().indexOf(term) === -1'
        ' ? "none" : "";'
        "});}</script></main>"
    )
    return layout("Suggestions", body, "/catalog")
