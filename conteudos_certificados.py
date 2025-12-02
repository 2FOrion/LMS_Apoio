# -*- coding: utf-8 -*-

# Mapa de conteúdos, carga horária e validade por NR.
# As cargas/validade batem com o seed do seu app:
#  NR-12 = 4h / 24m • NR-18 = 4h / 24m • NR-33 = 16h / 12m • NR-35 = 8h / 24m • (extra) NR-06 = 8h / 24m

CERT_DATA = {
    "NR-06": {
        "titulo": "NR-06 — Equipamento de Proteção Individual (EPI)",
        "carga_h": 8,
        "validade_meses": 24,
        "conteudo": [
            "Fundamentos legais da NR-06 e responsabilidades (empregador e empregado)",
            "Reconhecimento de perigos e seleção adequada de EPIs",
            "Ajuste, uso correto, limitações e higienização de EPIs",
            "Armazenamento, vida útil e rastreabilidade de entrega/recebimento",
            "Integração EPI x EPC x Procedimentos; comunicação de desvios",
        ],
    },
    "NR-12": {
        "titulo": "NR-12 — Segurança em Máquinas e Equipamentos",
        "carga_h": 4,
        "validade_meses": 24,
        "conteudo": [
            "Princípios gerais e requisitos essenciais de segurança da NR-12",
            "Riscos mecânicos, elétricos e de automação; análise de perigos",
            "Proteções fixas e móveis, distâncias de segurança, enclausuramentos",
            "Dispositivos de parada de emergência e bloqueio/etiquetagem (LOTO)",
            "Procedimentos operacionais seguros e inspeções de rotina",
        ],
    },
    "NR-18": {
        "titulo": "NR-18 — Condições de Segurança na Indústria da Construção",
        "carga_h": 4,
        "validade_meses": 24,
        "conteudo": [
            "Organização de canteiro, circulação e sinalização",
            "Escadas, andaimes, plataformas e guarda-corpo: montagem segura",
            "Movimentação de cargas, içamento e amarrações",
            "Eletricidade de obra, equipamentos portáteis e proteção coletiva",
            "Documentação e permissões de trabalho aplicáveis",
        ],
    },
    "NR-33": {
        "titulo": "NR-33 — Segurança e Saúde em Espaços Confinados",
        "carga_h": 16,
        "validade_meses": 12,
        "conteudo": [
            "Definições, responsabilidades e classificação de ambientes",
            "Reconhecimento, avaliação e controle de riscos (atmosféricos e físicos)",
            "Permissão de Entrada e Trabalho (PET) e monitoramento contínuo",
            "Ventilação, isolamentos, bloqueios e resgate básico",
            "Seleção e uso de EPIs/ERAs; comunicação e emergências",
        ],
    },
    "NR-35": {
        "titulo": "NR-35 — Trabalho em Altura",
        "carga_h": 8,
        "validade_meses": 24,
        "conteudo": [
                "Requisitos e responsabilidades; análise de risco e PT",
                "Sistemas de proteção contra quedas (SPQ), ancoragens e linhas de vida",
                "Seleção/inspeção de cinturões, talabartes e conectores",
                "Montagem segura de escadas, andaimes e plataformas de trabalho",
                "Procedimentos de emergência e noções de resgate",
        ],
    },
}


def get_nr_key_from_course_name(name: str) -> str | None:
    """
    Tenta extrair a 'NR-XX' do nome do curso. Ex.: 'NR-35 - Trabalho em Altura' -> 'NR-35'.
    Retorna None se não encontrar.
    """
    if not name:
        return None
    name = name.strip().upper()
    # formatos usuais: "NR-35", "NR 35", "NR-35" etc.
    name = name.replace("NR -", "NR-").replace("NR-", "NR-").replace("NR ", "NR-")
    if name.startswith("NR-") and len(name) >= 5 and name[3:5].isdigit():
        return name[:5]
    return None


def get_cert_info_for_course(course_name: str) -> dict:
    """
    Retorna um dicionário com: titulo, carga_h, validade_meses e conteudo (lista de strings).
    Se não achar a NR, devolve um set básico usando os dados padrão do curso.
    """
    key = get_nr_key_from_course_name(course_name or "")
    if key and key in CERT_DATA:
        return CERT_DATA[key]
    # fallback “genérico”
    return {
        "titulo": course_name or "Curso",
        "carga_h": None,
        "validade_meses": None,
        "conteudo": [],
    }
