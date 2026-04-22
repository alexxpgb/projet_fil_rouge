from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, ListFlowable, ListItem


def build_pdf(output_path: str) -> None:
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title="SOCket - Comparaison au referentiel UF CYBER B3",
        author="Equipe SOCket",
    )

    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    heading_style = styles["Heading2"]
    body_style = styles["BodyText"]
    body_style.spaceAfter = 8
    small_style = ParagraphStyle("small", parent=body_style, fontSize=9, textColor="#555555")

    story = []
    story.append(Paragraph("SOCket - Comparaison au referentiel UF CYBER B3", title_style))
    story.append(Paragraph(f"Date de generation: {datetime.now().strftime('%d/%m/%Y %H:%M')}", small_style))
    story.append(Spacer(1, 12))

    story.append(Paragraph("1. Objet du document", heading_style))
    story.append(
        Paragraph(
            "Ce document compare l'etat actuel du projet SOCket aux attentes du document "
            "UF_CYBER_B3. Il sert de support de pilotage pour atteindre un niveau de couverture "
            "maximal des competences techniques et transverses.",
            body_style,
        )
    )

    story.append(Paragraph("2. Etat de couverture actuel", heading_style))
    coverage_items = [
        "Plateforme SOC fonctionnelle (ingestion, incident, ticketing, dashboard): <b>OK</b>",
        "GRC et analyse de risques documentees: <b>Partiellement OK</b>",
        "Gestion d'incident et workflow operationnel: <b>OK</b>",
        "PCA/PRA documente: <b>Partiellement OK</b>",
        "BDD relationnelle + NoSQL (SQLite + MongoDB logs): <b>OK</b>",
        "CI/CD securite (Semgrep, npm audit, pip-audit): <b>OK</b>",
        "Pentest/audit avec preuves techniques: <b>Partiellement OK</b>",
        "Forensic (collecte preuves, timeline, rapport): <b>A renforcer</b>",
    ]
    story.append(
        ListFlowable(
            [ListItem(Paragraph(item, body_style)) for item in coverage_items],
            bulletType="bullet",
            leftIndent=18,
        )
    )

    story.append(Spacer(1, 10))
    story.append(Paragraph("3. Evolutions deja implementees (dernier sprint)", heading_style))
    implemented_items = [
        "Validation stricte des payloads API avec Zod.",
        "Rate limiting sur /auth/login et /logs/ingest.",
        "Lockout temporaire apres echecs repetes de connexion.",
        "Journal d'audit securite en base (audit_logs) + endpoint admin.",
        "Frontend enrichi avec visualisation des audit logs.",
        "Tests d'integration securite backend (5 tests, 5 passes).",
    ]
    story.append(
        ListFlowable(
            [ListItem(Paragraph(item, body_style)) for item in implemented_items],
            bulletType="bullet",
            leftIndent=18,
        )
    )

    story.append(Spacer(1, 10))
    story.append(Paragraph("4. Plan d'amelioration pour viser la note maximale", heading_style))
    plan_items = [
        "<b>Pentest preuve par preuve</b>: executer des scenarios Web/API/Infra et documenter avant/apres correction.",
        "<b>Forensic complet</b>: simuler un incident, collecter artefacts, produire timeline et rapport final.",
        "<b>PRA teste</b>: demontrer une restauration SQLite + MongoDB avec RPO/RTO verifies.",
        "<b>Hardening infra</b>: reverse proxy TLS, segmentation reseau Docker, sauvegardes automatisees.",
        "<b>GRC approfondie</b>: renforcer PSSI, EBIOS light detaillee, indicateurs MTTD/MTTR mensuels.",
    ]
    story.append(
        ListFlowable(
            [ListItem(Paragraph(item, body_style)) for item in plan_items],
            bulletType="1",
            leftIndent=18,
        )
    )

    story.append(Spacer(1, 12))
    story.append(Paragraph("5. Estimation de niveau actuel", heading_style))
    story.append(
        Paragraph(
            "Sur la base des livrables techniques actuellement presentes, le projet se situe "
            "dans une couverture estimee entre 75% et 85% des attendus UF, avec un potentiel "
            "de progression rapide vers 90%+ apres integration des volets forensic, pentest "
            "documente et PRA teste en conditions reelles.",
            body_style,
        )
    )

    doc.build(story)


if __name__ == "__main__":
    build_pdf("docs/rapport_comparatif_uf_cyber_b3.pdf")
