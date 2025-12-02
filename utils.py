# utils.py
# -*- coding: utf-8 -*-
import os
from datetime import datetime
from zoneinfo import ZoneInfo

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import cm
from reportlab.lib.colors import Color
from reportlab.lib import colors  # cores nomeadas (black, grey, etc.)

# Imports para QR Code
from reportlab.graphics.barcode import qr
from reportlab.graphics.shapes import Drawing
from reportlab.graphics import renderPDF

BR_TZ = ZoneInfo("America/Sao_Paulo")

# ---- mapa simples p/ títulos/carga/validade por NR (fallback opcional)
CERT_DATA = {
    "NR-06": {"titulo": "NR-06 — Equipamentos de Proteção Individual", "carga_h": 8,  "validade_meses": 24, "conteudo": [
        "Responsabilidades (empregado/empregador) e fundamentos legais",
        "Seleção, ajuste, uso, higienização e vida útil dos EPIs",
        "Integração EPI x EPC x procedimentos; registros e rastreabilidade",
    ]},
    "NR-12": {"titulo": "NR-12 — Segurança em Máquinas e Equipamentos", "carga_h": 4,  "validade_meses": 24, "conteudo": [
        "Análise de perigos; proteções fixas e móveis; enclausuramentos",
        "Parada de emergência; bloqueio e etiquetagem (LOTO)",
        "Procedimentos seguros e inspeções de rotina",
    ]},
    "NR-18": {"titulo": "NR-18 — Condições de Segurança na Construção", "carga_h": 4,  "validade_meses": 24, "conteudo": [
        "Canteiro, circulação e sinalização",
        "Escadas/andaimes/plataformas: critérios de montagem segura",
        "Movimentação de cargas e proteção coletiva",
    ]},
    "NR-33": {"titulo": "NR-33 — Segurança em Espaços Confinados", "carga_h": 16, "validade_meses": 12, "conteudo": [
        "Reconhecimento/avaliação de riscos e monitoramento atmosférico",
        "Permissão de Entrada e Trabalho (PET), isolamentos e ventilação",
        "Seleção de EPIs/ERAs e noções de resgate",
    ]},
    "NR-35": {"titulo": "NR-35 — Trabalho em Altura", "carga_h": 8,  "validade_meses": 24, "conteudo": [
        "Análise de risco e PT; SPQ, ancoragens e linhas de vida",
        "Seleção/inspeção de cinturões, talabartes e conectores",
        "Noções de resgate e atendimento a emergências",
    ]},
}


def _nr_key_from_name(name: str) -> str | None:
    if not name:
        return None
    s = name.upper().strip().replace("NR -", "NR-").replace("NR ", "NR-")
    if s.startswith("NR-") and len(s) >= 5 and s[3:5].isdigit():
        return s[:5]
    return None


def _first_existing(paths):
    for p in paths:
        if os.path.exists(p):
            return p
    return None


def _multiline_center(c: canvas.Canvas, lines, x, y_start, lh=0.7 * cm, font=("Helvetica", 12)):
    if isinstance(lines, str):
        lines = [lines]
    c.setFont(*font)
    y = y_start
    for line in lines:
        c.drawCentredString(x, y, line)
        y -= lh
    return y


def _bullets(c: canvas.Canvas, items, x_left, y_start, max_width, lh=0.58 * cm, font=("Helvetica", 11)):
    import textwrap
    c.setFont(*font)
    y = y_start
    for it in items:
        text = f"• {it}"
        if c.stringWidth(text, font[0], font[1]) <= max_width:
            c.drawString(x_left, y, text)
            y -= lh
        else:
            # quebra aproximada por largura
            for w in textwrap.wrap(text, width=105):
                c.drawString(x_left, y, w)
                y -= lh
    return y


def _parse_description_to_items(desc: str) -> list[str]:
    """
    Converte a descrição livre do curso (Course.description) em uma
    lista de itens para bullets. Aceita:
      - quebras de linha
      - ponto-e-vírgula ';'
      - vírgulas ','
      - marcadores '•'
    """
    if not desc:
        return []
    raw = desc.replace("\r", "\n")
    raw = raw.replace("•", "\n")  # troca bullets por quebras
    parts = []
    for chunk in raw.split("\n"):
        chunk = chunk.strip()
        if not chunk:
            continue
        subparts = []
        for p in chunk.replace(";", ",").split(","):
            p = p.strip(" -–—•\t ")
            if p:
                subparts.append(p)
        if subparts:
            parts.extend(subparts)
    seen, items = set(), []
    for p in parts:
        if p not in seen:
            items.append(p)
            seen.add(p)
    return items


# --- helper para CPF
def _only_digits(s: str) -> str:
    return "".join(ch for ch in (s or "") if ch.isdigit())


def _format_cpf(cpf_raw: str) -> str:
    d = _only_digits(cpf_raw)
    if len(d) == 11:
        return f"{d[0:3]}.{d[3:6]}.{d[6:9]}-{d[9:11]}"
    return cpf_raw or "-"


def generate_certificate_pdf(
    user,
    company,
    course,
    issued_at: datetime,
    out_dir: str = "generated",
    *,
    ip_address: str | None = None,
    access_dt: datetime | None = None,
):
    """
    Gera o PDF do certificado.
    - ip_address: IP do dispositivo que acessou (aparece no centro do certificado).
    - access_dt: data/hora do acesso; se não informado, usa issued_at.
    """
    os.makedirs(out_dir, exist_ok=True)

    # arquivo de saída
    data_str = issued_at.astimezone(BR_TZ).strftime("%Y%m%d")
    safe = lambda s: "".join(c for c in s if c.isalnum() or c in (" ", "_", "-")).strip().replace(" ", "_")
    filename = f"Certificado_{safe(course.name)}_{safe(user.name)}_{data_str}.pdf"
    filepath = os.path.join(out_dir, filename)

    c = canvas.Canvas(filepath, pagesize=A4)
    w, h = A4

    # faixa superior (#ed3637)
    red = Color(0.929, 0.212, 0.216)
    c.setFillColor(red)
    c.rect(0, h - 2.0 * cm, w, 2.0 * cm, fill=1, stroke=0)

    # logo
    logo_path = _first_existing([
        os.path.join("static", "img", "apoio_logo.png"),
        os.path.join("static", "img", "logo.png"),
        os.path.join("static", "img", "brand.png"),
    ])
    if logo_path:
        c.drawImage(
            logo_path, 1.2 * cm, h - 1.7 * cm,
            width=4.0 * cm, height=1.3 * cm,
            mask='auto', preserveAspectRatio=True, anchor='nw'
        )

    # título “APOIO ENGENHARIA” dentro da faixa
    c.setFillColorRGB(1, 1, 1)
    c.setFont("Helvetica-Bold", 20)
    c.drawCentredString(w / 2, h - 1.28 * cm, "APOIO ENGENHARIA")

    # título “CERTIFICADO” centralizado (fora da faixa)
    c.setFillColor(colors.black)
    c.setFont("Helvetica-Bold", 30)
    c.drawCentredString(w / 2, h - 3.8 * cm, "CERTIFICADO")

    # dados do curso/aluno
    nr_key = _nr_key_from_name(course.name or "")
    info = CERT_DATA.get(nr_key, {})
    titulo = info.get("titulo") or (course.name or "Curso")
    carga = info.get("carga_h", getattr(course, "duration_hours", 0) or 0)
    validade = info.get("validade_meses", getattr(course, "validity_months", 0) or 0)

    # conteúdo programático
    conteudo_desc = _parse_description_to_items(getattr(course, "description", "") or "")
    conteudo_map = info.get("conteudo", [])
    conteudo = conteudo_desc if conteudo_desc else conteudo_map

    nome_aluno = getattr(user, "name", "") or "-"
    cpf_aluno = _format_cpf(getattr(user, "cpf", "") or "")
    local = getattr(company, "city_state", None) or "Serra/ES"
    data_br = issued_at.astimezone(BR_TZ).strftime("%d/%m/%Y")

    y = h - 5.8 * cm
    y = _multiline_center(
        c,
        [
            f"Certificamos que {nome_aluno},",
            f"concluiu o curso {titulo}, com carga horária de {carga} hora(s).",
            f"Validade do certificado: {validade} mês(es).",
            f"{local}, {data_br}",
        ],
        w / 2, y, lh=0.75 * cm, font=("Helvetica", 12)
    )

    # Conteúdo Programático (se houver)
    if conteudo:
        y -= 0.9 * cm
        c.setFont("Helvetica-Bold", 12)
        c.drawString(2.0 * cm, y, "Conteúdo Programático:")
        y -= 0.6 * cm
        y = _bullets(
            c, conteudo,
            x_left=2.0 * cm,
            y_start=y,
            max_width=w - 4.0 * cm,
            font=("Helvetica", 11)
        )
        y -= 0.4 * cm

    # ============================================================
    # BLOCO CENTRALIZADO (substitui o selo): Nome + CPF + IP + Acessado em
    # ============================================================
    bloco_top_y = max(9.2 * cm, y - 0.2 * cm)  # um pouco mais alto para 4 linhas
    bloco_h = 4.2 * cm
    bloco_w = 12.0 * cm
    bloco_x = (w - bloco_w) / 2.0
    bloco_y = bloco_top_y - bloco_h

    # moldura leve (opcional)
    c.setStrokeColor(colors.grey)
    c.rect(bloco_x, bloco_y, bloco_w, bloco_h, stroke=1, fill=0)

    # textos centralizados no bloco
    dt_acesso = (access_dt or issued_at).astimezone(BR_TZ)
    ip_txt = f"Dispositivo: {ip_address}" if ip_address else "Dispositivo: não identificado"
    when_txt = f"Acessado em {dt_acesso.strftime('%d/%m/%Y %H:%M:%S')}"

    c.setFillColor(colors.black)
    c.setFont("Helvetica-Bold", 16)
    c.drawCentredString(w / 2, bloco_y + bloco_h - 0.9 * cm, nome_aluno)

    c.setFont("Helvetica", 13)
    c.setFillColor(colors.black)
    c.drawCentredString(w / 2, bloco_y + bloco_h - 1.75 * cm, f"CPF: {cpf_aluno}")

    c.setFont("Helvetica", 13)
    c.setFillColor(colors.darkblue)
    c.drawCentredString(w / 2, bloco_y + bloco_h - 2.55 * cm, ip_txt)

    c.setFont("Helvetica", 12)
    c.setFillColor(colors.grey)
    c.drawCentredString(w / 2, bloco_y + 0.8 * cm, when_txt)

    # ------------------------------------------------------------
    # DOIS BLOCOS DE ASSINATURA (PARTICIPANTE + EMPRESA)
    # ------------------------------------------------------------
    linha_y = 4.5 * cm          # posição vertical das linhas de assinatura
    bloco_ass_w = 7.0 * cm      # largura de cada bloco de assinatura
    margem_x = 2.0 * cm

    # Participante (lado esquerdo)
    part_x = margem_x
    c.setLineWidth(1)
    c.setStrokeColor(colors.black)
    c.line(part_x, linha_y, part_x + bloco_ass_w, linha_y)
    c.setFont("Helvetica", 11)
    c.setFillColor(colors.black)
    c.drawCentredString(part_x + bloco_ass_w / 2.0, linha_y - 0.8 * cm, "Participante")

    # Representante da Empresa (lado direito)
    emp_x = w - margem_x - bloco_ass_w
    c.line(emp_x, linha_y, emp_x + bloco_ass_w, linha_y)
    c.drawCentredString(emp_x + bloco_ass_w / 2.0, linha_y - 0.8 * cm, "Representante da Empresa")

    # ------------------------------------------------------------
    # ASSINATURA DIGITAL SOBRE O BLOCO DO PARTICIPANTE
    # ------------------------------------------------------------
    assinatura_path = _first_existing([
        os.path.join("static", "img", "assinatura_digital.png"),
        os.path.join("static", "img", "assinatura.png"),
        os.path.join("static", "img", "signature.png"),
    ])
    if assinatura_path:
        # tamanho máximo da imagem dentro do bloco do participante
        max_w = bloco_ass_w * 0.70
        max_h = 2.0 * cm

        # centraliza a assinatura no bloco do PARTICIPANTE
        img_x = part_x + (bloco_ass_w - max_w) / 2.0
        img_y = linha_y + 0.25 * cm  # um pouquinho acima da linha

        c.drawImage(
            assinatura_path,
            img_x,
            img_y,
            width=max_w,
            height=max_h,
            mask="auto",
            preserveAspectRatio=True,
            anchor="sw"
        )

    # ------------------------------------------------------------
    # QR CODE NO RODAPÉ (dados básicos do certificado)
    # ------------------------------------------------------------
    try:
        qr_data = (
            f"Certificado LMS Apoio Engenharia | "
            f"Nome: {nome_aluno} | CPF: {cpf_aluno} | "
            f"Curso: {titulo} | Emitido em: {data_br}"
        )
        qr_code = qr.QrCodeWidget(qr_data)
        bounds = qr_code.getBounds()
        qr_w = bounds[2] - bounds[0]
        qr_h = bounds[3] - bounds[1]

        qr_size = 2.8 * cm
        d = Drawing(qr_size, qr_size, transform=[qr_size / qr_w, 0, 0, qr_size / qr_h, 0, 0])
        d.add(qr_code)

        # posição: canto inferior esquerdo, acima do rodapé
        qr_x = 1.5 * cm
        qr_y = 1.6 * cm
        renderPDF.draw(d, c, qr_x, qr_y)
    except Exception as e:
        # se der qualquer erro com QR, só loga no console e segue
        print("[WARN] Falha ao gerar QR Code no certificado:", e)

    # rodapé
    c.setFont("Helvetica-Oblique", 9.5)
    c.setFillColorRGB(0.25, 0.25, 0.25)
    c.drawCentredString(
        w / 2,
        1.3 * cm,
        "Válido enquanto respeitados prazos e normas aplicáveis."
    )

    c.showPage()
    c.save()
    return filepath
