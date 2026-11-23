"""Auditorías por host y seguimiento manual de remediación."""
from datetime import datetime, timezone
import json

import pandas as pd
import streamlit as st

from audit import AUDIT_PORTS
from ui_theme import PALETTE


def _style_findings(df):
    def highlight(row):
        prio = str(row.get("Prioridad", "")).lower()
        if prio in ("alta", "crítica", "critica"):
            return [f"background-color: {PALETTE['danger_tint']}"] * len(row)
        if prio == "media":
            return [f"background-color: {PALETTE['warning_tint']}"] * len(row)
        if prio == "baja":
            return [f"background-color: {PALETTE['info_tint']}"] * len(row)
        return [""] * len(row)

    return df.style.apply(highlight, axis=1)


def render_audit(engine, snap, devices):
    targets = {row["IP"]: row for row in devices}

    with st.container(border=True):
        st.markdown("**:material/policy: Ejecutar auditoría técnica de host**")
        st.caption(
            "Comprobaciones acotadas por equipo: conectividad TCP, `HEAD /` HTTP y negociación TLS. "
            "No autentica, no sigue redirecciones ni ejecuta exploits."
        )
        if targets:
            with st.form("audit_launch_form", border=False):
                c_target, c_host, c_submit = st.columns([5, 5, 2], vertical_alignment="bottom")
                with c_target:
                    target = st.selectbox(
                        "Equipo a auditar",
                        list(targets),
                        format_func=lambda ip: f"{targets[ip].get('Nombre') or ip} · {ip}",
                        key="audit_target",
                    )
                with c_host:
                    hostname = st.text_input(
                        "Nombre DNS del servicio (opcional, Host/SNI)",
                        key="audit_hostname",
                        placeholder="Ej. intranet.local",
                        help="Sólo se conecta a la IP seleccionada; este nombre no se resuelve ni cambia el destino.",
                    )
                with c_submit:
                    submitted = st.form_submit_button(
                        "Auditar equipo",
                        type="primary",
                        icon=":material/play_arrow:",
                        disabled=snap["job"]["running"],
                        width="stretch",
                    )
                if submitted:
                    try:
                        if engine.start_audit(target, hostname):
                            st.rerun()
                    except (ValueError, OSError) as exc:
                        st.error(str(exc), icon=":material/error:")
            st.caption(
                "Puertos evaluados: "
                + ", ".join(map(str, AUDIT_PORTS))
                + ". Las comprobaciones generan conexiones visibles en el objetivo."
            )
        else:
            st.info(
                "Descubre dispositivos o inicia captura para seleccionar un equipo de la LAN.",
                icon=":material/info:",
            )

    reports = {row["ip"]: row for row in reversed(snap["audits"])}
    if not reports:
        st.caption(
            "Sin auditorías ejecutadas en esta sesión. Se conservan los últimos resultados de hasta 16 equipos."
        )
        return

    top_sel, top_export = st.columns([8, 4], vertical_alignment="bottom")
    with top_sel:
        ip = st.selectbox("Informe por equipo", list(reports), key="audit_report")
    report = reports[ip]
    with top_export:
        with st.container(horizontal=True, horizontal_alignment="right"):
            st.download_button(
                "Exportar auditoría JSON",
                json.dumps(report, ensure_ascii=False, indent=2),
                file_name=f"auditoria_{ip}.json",
                mime="application/json",
                icon=":material/download:",
                key="audit_export",
                on_click="ignore",
            )

    findings = report["findings"]
    active = [row for row in findings if row["Verificacion"] == "Detectado"]
    unevaluable = sum(row["Estado"] == "No evaluable" for row in report["checks"])
    managed = sum(row["Gestion"] not in ("Pendiente", "En progreso") for row in findings)
    timestamp = datetime.fromtimestamp(report["finished"], timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )

    with st.container(horizontal=True, vertical_alignment="center"):
        st.badge(f"Informe {report['id'][:8]}", icon=":material/description:", color="blue")
        st.badge(ip, icon=":material/dns:", color="gray")
        if report["hostname"]:
            st.badge(f"SNI: {report['hostname']}", icon=":material/language:", color="gray")
        st.caption(f"Finalizado: {timestamp}")

    if report["cancelled"]:
        st.warning(
            "Auditoría cancelada: resultados parciales. Repite la evaluación antes de sacar conclusiones.",
            icon=":material/warning:",
        )

    c1, c2, c3 = st.columns(3)
    with c1:
        st.metric(
            "Hallazgos detectados",
            len(active),
            delta="Requiere revisión" if active else "Sin hallazgos activos",
            delta_color="inverse" if active else "normal",
            border=True,
        )
    with c2:
        st.metric("Pruebas no evaluables", unevaluable, border=True)
    with c3:
        st.metric(
            "Gestionados",
            managed,
            delta=f"de {len(findings)} total" if findings else None,
            delta_color="off",
            border=True,
        )

    st.caption(
        "«Mitigado por usuario» es una anotación operativa. Una reauditoría sólo confirma que el "
        "hallazgo dejó de observarse en las pruebas completadas; no certifica ausencia total de vulnerabilidades."
    )

    if findings:
        with st.container(border=True):
            st.markdown("**:material/fact_check: Resumen de hallazgos**")
            findings_df = pd.DataFrame(findings)[
                ["Puerto", "Prioridad", "Regla", "Confianza", "Verificacion", "Gestion", "Nota"]
            ]
            st.dataframe(
                _style_findings(findings_df),
                hide_index=True,
                width="stretch",
                column_config={
                    "Puerto": st.column_config.NumberColumn("Puerto", format="%d"),
                    "Prioridad": st.column_config.TextColumn("Prioridad"),
                    "Regla": st.column_config.TextColumn("Regla"),
                    "Verificacion": st.column_config.TextColumn("Verificación"),
                    "Gestion": st.column_config.TextColumn("Gestión"),
                },
            )

        with st.container(border=True):
            st.markdown("**:material/build: Plan de remediación y seguimiento**")
            by_id = {row["ID"]: row for row in findings}
            finding_id = st.selectbox(
                "Hallazgo para revisar / plan de parcheo",
                list(by_id),
                format_func=lambda key: (
                    f"[{by_id[key]['Prioridad']}] Puerto {by_id[key]['Puerto']} · {by_id[key]['Regla']}"
                ),
                key="audit_finding",
            )
            row = by_id[finding_id]

            ev_col, form_col = st.columns([6, 6])
            with ev_col:
                st.markdown("**Evidencia técnica**")
                st.code(row["Evidencia"], language=None)
                st.markdown("**Acción recomendada**")
                st.info(row["Recomendacion"], icon=":material/tips_and_updates:")
                if row["Referencia"]:
                    st.link_button(
                        "Consultar referencia técnica",
                        row["Referencia"],
                        icon=":material/open_in_new:",
                    )

            with form_col:
                states = [
                    "Pendiente",
                    "En progreso",
                    "Mitigado por usuario",
                    "Falso positivo / aceptado",
                ]
                with st.form("audit_remediation_form", border=False):
                    state = st.selectbox(
                        "Estado del trabajo",
                        states,
                        index=states.index(row["Gestion"]),
                        key=f"audit_state_{finding_id}",
                    )
                    note = st.text_area(
                        "Parche aplicado, responsable o motivo de aceptación",
                        value=row["Nota"],
                        max_chars=500,
                        key=f"audit_note_{finding_id}",
                        height=130,
                    )
                    if st.form_submit_button(
                        "Guardar seguimiento",
                        type="primary",
                        icon=":material/save:",
                        width="stretch",
                    ):
                        engine.update_finding(ip, finding_id, state, note)
                        st.success(
                            "Seguimiento actualizado. Repite la auditoría para verificar el resultado.",
                            icon=":material/check_circle:",
                        )
    else:
        st.info(
            "Sin hallazgos dentro de las pruebas ejecutadas. Revisa las pruebas no evaluables; "
            "esto no equivale a certificar un equipo seguro.",
            icon=":material/check_circle:",
        )

    with st.expander("Evidencias y cobertura de todas las pruebas", icon=":material/list_alt:"):
        st.dataframe(pd.DataFrame(report["checks"]), hide_index=True, width="stretch")
