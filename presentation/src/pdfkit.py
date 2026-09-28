"""Shared ReportLab styling for the Loom presentation documents."""
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_JUSTIFY
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (BaseDocTemplate, PageTemplate, Frame, Paragraph, Spacer, Table, TableStyle,
                                KeepTogether, PageBreak, Preformatted, CondPageBreak)

F = "/usr/share/fonts/truetype/"
pdfmetrics.registerFont(TTFont("Body", F + "crosextra/Carlito-Regular.ttf"))
pdfmetrics.registerFont(TTFont("Body-B", F + "crosextra/Carlito-Bold.ttf"))
pdfmetrics.registerFont(TTFont("Body-I", F + "crosextra/Carlito-Italic.ttf"))
pdfmetrics.registerFont(TTFont("Body-BI", F + "crosextra/Carlito-BoldItalic.ttf"))
pdfmetrics.registerFont(TTFont("Head", F + "crosextra/Caladea-Bold.ttf"))
pdfmetrics.registerFont(TTFont("Head-R", F + "crosextra/Caladea-Regular.ttf"))
pdfmetrics.registerFont(TTFont("Mono", F + "dejavu/DejaVuSansMono.ttf"))
pdfmetrics.registerFont(TTFont("Mono-B", F + "dejavu/DejaVuSansMono-Bold.ttf"))
pdfmetrics.registerFont(TTFont("Sym", F + "dejavu/DejaVuSans.ttf"))
from reportlab.lib.fonts import addMapping
addMapping("Body", 0, 0, "Body"); addMapping("Body", 1, 0, "Body-B"); addMapping("Body", 0, 1, "Body-I"); addMapping("Body", 1, 1, "Body-BI")
addMapping("Mono", 0, 0, "Mono"); addMapping("Mono", 1, 0, "Mono-B"); addMapping("Mono", 0, 1, "Mono"); addMapping("Mono", 1, 1, "Mono-B")

INK = colors.HexColor("#161B33"); INDIGO = colors.HexColor("#2E3A8C"); INDIGO2 = colors.HexColor("#4455C7")
SOFT = colors.HexColor("#E9ECF8"); SOFT2 = colors.HexColor("#F4F5FA"); AMBER = colors.HexColor("#E0A526")
AMBERSOFT = colors.HexColor("#FBF1D8"); TEXT = colors.HexColor("#1B2030"); MUTED = colors.HexColor("#5B6275")
LINE = colors.HexColor("#CDD2E3"); GREEN = colors.HexColor("#2B7651"); GREENSOFT = colors.HexColor("#DCEEE3")
RED = colors.HexColor("#B0352A"); REDSOFT = colors.HexColor("#F6DFDB")

S = {
    "title": ParagraphStyle("title", fontName="Head", fontSize=26, leading=30, textColor=INK, spaceAfter=4),
    "subtitle": ParagraphStyle("subtitle", fontName="Head-R", fontSize=14, leading=18, textColor=INDIGO, spaceAfter=10),
    "eyebrow": ParagraphStyle("eyebrow", fontName="Body-B", fontSize=9, leading=11, textColor=INDIGO2, spaceAfter=2),
    "h1": ParagraphStyle("h1", fontName="Head", fontSize=17, leading=21, textColor=INK, spaceBefore=12, spaceAfter=6),
    "h2": ParagraphStyle("h2", fontName="Head", fontSize=13, leading=16, textColor=INDIGO, spaceBefore=9, spaceAfter=4),
    "h3": ParagraphStyle("h3", fontName="Body-B", fontSize=11, leading=14, textColor=INK, spaceBefore=6, spaceAfter=2),
    "body": ParagraphStyle("body", fontName="Body", fontSize=10.5, leading=14.5, textColor=TEXT, spaceAfter=6, alignment=TA_JUSTIFY),
    "say": ParagraphStyle("say", fontName="Body", fontSize=11.5, leading=16, textColor=TEXT, spaceAfter=6, leftIndent=8),
    "cue": ParagraphStyle("cue", fontName="Body-I", fontSize=10, leading=13, textColor=MUTED, spaceAfter=5, leftIndent=8),
    "small": ParagraphStyle("small", fontName="Body", fontSize=9, leading=11.5, textColor=MUTED),
    "cell": ParagraphStyle("cell", fontName="Body", fontSize=9.5, leading=12, textColor=TEXT),
    "cellb": ParagraphStyle("cellb", fontName="Body-B", fontSize=9.5, leading=12, textColor=TEXT),
    "cellh": ParagraphStyle("cellh", fontName="Body-B", fontSize=9.5, leading=12, textColor=colors.white),
    "bullet": ParagraphStyle("bullet", fontName="Body", fontSize=10.5, leading=14, textColor=TEXT, leftIndent=14, bulletIndent=4, spaceAfter=3),
    "q": ParagraphStyle("q", fontName="Body-B", fontSize=10.5, leading=14, textColor=INK, spaceBefore=6, spaceAfter=2),
    "a": ParagraphStyle("a", fontName="Body", fontSize=10.5, leading=14, textColor=TEXT, leftIndent=10, spaceAfter=4, alignment=TA_JUSTIFY),
    "code": ParagraphStyle("code", fontName="Mono", fontSize=8.6, leading=11, textColor=colors.white),
    "mono": ParagraphStyle("mono", fontName="Mono", fontSize=9, leading=12, textColor=TEXT),
}


def P(t, st="body"):
    return Paragraph(t, S[st])


def bullets(items, st="bullet"):
    return [Paragraph(i, S[st], bulletText="•") for i in items]


def boxed(flowables, bg=SOFT, border=None, pad=8):
    t = Table([[flowables]], colWidths=[None])
    style = [("BACKGROUND", (0, 0), (-1, -1), bg), ("LEFTPADDING", (0, 0), (-1, -1), pad), ("RIGHTPADDING", (0, 0), (-1, -1), pad),
             ("TOPPADDING", (0, 0), (-1, -1), pad - 2), ("BOTTOMPADDING", (0, 0), (-1, -1), pad - 2)]
    if border:
        style.append(("BOX", (0, 0), (-1, -1), 1, border))
    t.setStyle(TableStyle(style))
    return t


def code(text):
    t = Table([[Preformatted(text, S["code"])]], colWidths=[None])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), INK), ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                           ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    return t


def table(rows, widths, head=True, zebra=True, header_bg=INDIGO):
    data = []
    for i, r in enumerate(rows):
        data.append([c if not isinstance(c, str) else Paragraph(c, S["cellh"] if (head and i == 0) else S["cell"]) for c in r])
    t = Table(data, colWidths=widths, repeatRows=1 if head else 0)
    st = [("GRID", (0, 0), (-1, -1), 0.4, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
          ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5), ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]
    if head:
        st.append(("BACKGROUND", (0, 0), (-1, 0), header_bg))
    if zebra:
        for i in range(1 if head else 0, len(rows)):
            if i % 2 == (1 if head else 0):
                st.append(("BACKGROUND", (0, i), (-1, i), SOFT2))
    t.setStyle(TableStyle(st))
    return t


def build(path, story, header_text):
    def deco(c, d):
        c.saveState()
        w, h = A4
        # woven motif
        x0, y0, s = w - 20 * mm, h - 16 * mm, 7 * mm
        c.setFillColor(INDIGO2)
        for f in (0.15, 0.45, 0.75):
            c.rect(x0 + s * f - 0.45 * mm, y0, 0.9 * mm, s, stroke=0, fill=1)
        c.setFillColor(INK)
        for f in (0.2, 0.5, 0.8):
            c.rect(x0, y0 + s * f - 0.45 * mm, s, 0.9 * mm, stroke=0, fill=1)
        c.setFont("Body", 8); c.setFillColor(MUTED)
        c.drawString(18 * mm, 10 * mm, header_text)
        c.drawRightString(w - 18 * mm, 10 * mm, f"page {d.page}")
        c.restoreState()
    doc = BaseDocTemplate(path, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=20 * mm, bottomMargin=18 * mm,
                          title=header_text, author="Loom team")
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="f")
    doc.addPageTemplates([PageTemplate(id="p", frames=[frame], onPage=deco)])
    doc.build(story)
    return doc.width
