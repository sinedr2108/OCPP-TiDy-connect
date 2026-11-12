"""Mjesečni PDF obračun punjenja: za organizaciju, za jednog korisnika ili za cijelu platformu."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from fpdf import FPDF

from .timeutil import fmt

MONTHS = ["siječanj", "veljača", "ožujak", "travanj", "svibanj", "lipanj", "srpanj", "kolovoz", "rujan",
          "listopad", "studeni", "prosinac"]

FONT_DIRS = ["/usr/share/fonts/truetype/dejavu", "/usr/share/fonts/dejavu", "/usr/share/fonts/TTF",
             "C:/Windows/Fonts"]
TRANSLIT = str.maketrans("čćđšžČĆĐŠŽ–·€", "ccdszCCDSZ-*E")


@dataclass
class Row:
    started_at: object
    station: str
    user: str
    card: str
    kwh: float
    price: float
    eur: float


@dataclass
class Statement:
    title: str            # npr. "Firma d.o.o." ili "Ana Horvat"
    subtitle: str         # npr. "Tvrtka · Ilica 1, Zagreb"
    year: int
    month: int
    rows: list[Row] = field(default_factory=list)


def _font_paths() -> tuple[Path, Path] | None:
    for d in FONT_DIRS:
        reg, bold = Path(d) / "DejaVuSans.ttf", Path(d) / "DejaVuSans-Bold.ttf"
        if reg.exists():
            return reg, bold if bold.exists() else reg
    return None


class _PDF(FPDF):
    def __init__(self, footer_text: str):
        super().__init__(format="A4")
        self.footer_text = footer_text
        fonts = _font_paths()
        if fonts:
            self.add_font("Body", "", str(fonts[0]))
            self.add_font("Body", "B", str(fonts[1]))
            self.family, self.unicode = "Body", True
        else:  # bez Unicode fonta: dijakritici se transliteriraju
            self.family, self.unicode = "Helvetica", False
        self.set_auto_page_break(True, 18)

    def t(self, s) -> str:
        s = str(s)
        return s if self.unicode else s.translate(TRANSLIT).encode("latin-1", "replace").decode("latin-1")

    def footer(self):
        self.set_y(-12)
        self.set_font(self.family, "", 8)
        self.set_text_color(120)
        self.cell(0, 6, self.t(f"{self.footer_text} · stranica {self.page_no()}/{{nb}}"), align="C")


def _table(pdf: _PDF, headers: list[str], widths: list[float], rows: list[list], right: set[int],
           bold_last: bool = False):
    pdf.set_font(pdf.family, "B", 8.5)
    pdf.set_fill_color(231, 245, 239)
    for h, w, i in zip(headers, widths, range(len(headers))):
        pdf.cell(w, 7, pdf.t(h), border="B", fill=True, align="R" if i in right else "L")
    pdf.ln()
    pdf.set_font(pdf.family, "", 8.5)
    for n, r in enumerate(rows):
        if bold_last and n == len(rows) - 1:
            pdf.set_font(pdf.family, "B", 8.5)
        for v, w, i in zip(r, widths, range(len(r))):
            text = pdf.t(v)
            while pdf.get_string_width(text) > w - 1.5 and len(text) > 3:
                text = text[:-2] + "…" if pdf.unicode else text[:-2] + "."
            pdf.cell(w, 6, text, border="B", align="R" if i in right else "L")
        pdf.ln()
    pdf.ln(4)


def _num(v: float, d: int = 2) -> str:
    return f"{v:,.{d}f}".replace(",", " ").replace(".", ",")


def build(st: Statement) -> bytes:
    period = f"{MONTHS[st.month - 1]} {st.year}"
    pdf = _PDF(f"Obračun punjenja · {st.title} · {period}")
    pdf.alias_nb_pages()
    pdf.add_page()
    logo = Path(__file__).parent / "static" / "tid-charge-mark.png"
    if logo.exists():
        pdf.image(str(logo), x=pdf.w - pdf.r_margin - 34, y=pdf.t_margin - 2, w=34)
    pdf.set_text_color(232, 70, 69)
    pdf.set_font(pdf.family, "B", 16)
    pdf.cell(pdf.get_string_width(pdf.t("TiD")) + 0.2, 9, pdf.t("TiD"))
    pdf.set_text_color(29, 35, 48)
    pdf.cell(0, 9, pdf.t("y Charge · Obračun punjenja"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(29, 35, 48)
    pdf.set_font(pdf.family, "B", 12)
    pdf.cell(0, 7, pdf.t(f"{st.title} · {period}"), new_x="LMARGIN", new_y="NEXT")
    if st.subtitle:
        pdf.set_font(pdf.family, "", 9)
        pdf.set_text_color(102, 112, 133)
        pdf.cell(0, 5, pdf.t(st.subtitle), new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(29, 35, 48)
    pdf.ln(4)

    kwh = sum(r.kwh for r in st.rows)
    eur = sum(r.eur for r in st.rows)
    pdf.set_font(pdf.family, "B", 11)
    for label, value in [("Punjenja", str(len(st.rows))), ("Energija", f"{_num(kwh)} kWh"),
                         ("Iznos", f"{_num(eur)} €")]:
        pdf.set_font(pdf.family, "", 9)
        pdf.cell(25, 7, pdf.t(label))
        pdf.set_font(pdf.family, "B", 11)
        pdf.cell(0, 7, pdf.t(value), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    if not st.rows:
        pdf.set_font(pdf.family, "", 10)
        pdf.cell(0, 8, pdf.t("U ovom mjesecu nema punjenja."))
        return bytes(pdf.output())

    def group(key):
        agg: dict[str, list[float]] = {}
        for r in st.rows:
            a = agg.setdefault(getattr(r, key) or "—", [0, 0.0, 0.0])
            a[0] += 1
            a[1] += r.kwh
            a[2] += r.eur
        return sorted(agg.items(), key=lambda kv: -kv[1][1])

    users = group("user")
    if len(users) > 1 or users[0][0] != st.title:
        pdf.set_font(pdf.family, "B", 11)
        pdf.cell(0, 8, pdf.t("Po korisniku"), new_x="LMARGIN", new_y="NEXT")
        rows = [[k, n, _num(e), _num(c)] for k, (n, e, c) in users] + [["Ukupno", len(st.rows), _num(kwh), _num(eur)]]
        _table(pdf, ["Korisnik", "Punjenja", "kWh", "EUR"], [100, 25, 30, 30], rows, {1, 2, 3}, bold_last=True)

    stations = group("station")
    pdf.set_font(pdf.family, "B", 11)
    pdf.cell(0, 8, pdf.t("Po punionici"), new_x="LMARGIN", new_y="NEXT")
    rows = [[k, n, _num(e), _num(c)] for k, (n, e, c) in stations]
    _table(pdf, ["Punionica", "Punjenja", "kWh", "EUR"], [100, 25, 30, 30], rows, {1, 2, 3})

    pdf.set_font(pdf.family, "B", 11)
    pdf.cell(0, 8, pdf.t("Sva punjenja"), new_x="LMARGIN", new_y="NEXT")
    rows = [[fmt(r.started_at, "%d.%m. %H:%M"), r.station, r.user, r.card, _num(r.kwh), _num(r.price, 4), _num(r.eur)]
            for r in sorted(st.rows, key=lambda r: r.started_at)]
    rows.append(["Ukupno", "", "", "", _num(kwh), "", _num(eur)])
    _table(pdf, ["Početak", "Punionica", "Korisnik", "Kartica", "kWh", "€/kWh", "EUR"],
           [24, 40, 42, 26, 17, 17, 20], rows, {4, 5, 6}, bold_last=True)
    pdf.set_font(pdf.family, "", 7.5)
    pdf.set_text_color(102, 112, 133)
    pdf.multi_cell(0, 4, pdf.t("Vremena su po lokalnom vremenu. Cijena je zaključana na početku svakog punjenja. "
                               "Ovo je obračun potrošnje, a ne račun."))
    return bytes(pdf.output())
