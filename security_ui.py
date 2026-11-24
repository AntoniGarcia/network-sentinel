"""Panel de visibilidad de red sobre la telemetría del monitor."""
from collections import defaultdict
from html import escape
import ipaddress
import math
import sqlite3
import time

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from audit_ui import render_audit
from security import local_networks
from ui_theme import FONT_FAMILY, PALETTE, apply_chart_layout


@st.cache_data(ttl=30)
def available_networks():
    return local_networks()


def frame(rows):
    result = pd.DataFrame(rows)
    for col in ("Hora", "Primero", "Ultimo", "Confirmado", "Revisada"):
        if col in result:
            result[col] = pd.to_datetime(result[col], unit="s", utc=True).dt.strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            )
    return result


def network_figure(rows, devices):
    totals = defaultdict(int)
    edges = defaultdict(int)
    for row in rows:
        edges[(row["Origen"], row["Destino"])] += row["Bytes"]
        totals[row["Origen"]] += row["Bytes"]
        totals[row["Destino"]] += row["Bytes"]

    kinds = {d["IP"]: d["Tipo"] for d in devices}
    names = {d["IP"]: d.get("Nombre", "") for d in devices}
    chosen = sorted(totals, key=totals.get, reverse=True)[:40]
    if not chosen:
        chosen = [d["IP"] for d in devices if d["Tipo"] != "Externo"][:40]

    positions = {}
    lanes = [(-1, "Este equipo", "Este equipo"), (0, "LAN", "Red local (LAN)"), (1, "Externo", "Externo")]
    for x, kind, _ in lanes:
        members = sorted(ip for ip in chosen if kinds.get(ip, "Externo") == kind)
        for i, ip in enumerate(members):
            positions[ip] = (x, (i - (len(members) - 1) / 2) / max(len(members), 1) * 1.8)

    fig = go.Figure()

    for divider_x in (-0.5, 0.5):
        fig.add_shape(
            type="line",
            x0=divider_x,
            x1=divider_x,
            y0=-1.15,
            y1=1.15,
            line=dict(color="rgba(148, 163, 184, 0.14)", width=1, dash="dot"),
        )

    for x, _, title in lanes:
        fig.add_annotation(
            x=x,
            y=1.18,
            text=f"<b>{title}</b>",
            showarrow=False,
            font=dict(family=FONT_FAMILY, size=11, color=PALETTE["muted"]),
        )

    if not positions:
        fig.add_annotation(
            text="Sin nodos visibles para el filtro actual. Inicia la captura o ejecuta descubrimiento LAN.",
            xref="paper",
            yref="paper",
            x=0.5,
            y=0.48,
            showarrow=False,
            font=dict(family=FONT_FAMILY, size=13, color=PALETTE["muted"]),
        )

    for (src, dst), size in sorted(edges.items(), key=lambda pair: pair[1], reverse=True)[:70]:
        if src not in positions or dst not in positions:
            continue
        x1, y1 = positions[src]
        x2, y2 = positions[dst]
        fig.add_trace(
            go.Scatter(
                x=[x1, x2],
                y=[y1, y2],
                mode="lines",
                line=dict(
                    color="rgba(96, 165, 250, 0.28)",
                    width=min(4.5, 1 + math.log10(size + 1) / 2),
                ),
                text=[f"<b>{escape(src)} → {escape(dst)}</b><br>{size / 1024:.1f} KiB"] * 2,
                hoverinfo="text",
                showlegend=False,
            )
        )

    colors = {
        "Este equipo": PALETTE["blue"],
        "LAN": PALETTE["emerald"],
        "Externo": PALETTE["amber"],
    }
    for kind, color in colors.items():
        ips = [ip for ip in positions if kinds.get(ip, "Externo") == kind]
        fig.add_trace(
            go.Scatter(
                x=[positions[ip][0] for ip in ips],
                y=[positions[ip][1] for ip in ips],
                mode="markers+text",
                text=[escape(names.get(ip) or ip) for ip in ips],
                textposition="top center",
                textfont=dict(family=FONT_FAMILY, size=11, color=PALETTE["text"]),
                name=kind,
                marker=dict(
                    size=[12 + min(14, math.log10(totals[ip] + 1) * 2) for ip in ips],
                    color=color,
                    line=dict(color=PALETTE["bg"], width=1.8),
                ),
                hovertext=[
                    f"<b>{escape(names.get(ip) or ip)}</b><br>"
                    f"IP: {escape(ip)}<br>"
                    f"Segmento: {escape(kind)}<br>"
                    f"Volumen: {totals[ip] / 1024:.1f} KiB"
                    for ip in ips
                ],
                hoverinfo="text",
            )
        )

    return apply_chart_layout(
        fig,
        height=430,
        margin=dict(l=20, r=20, t=24, b=16),
        xaxis=dict(visible=False, range=[-1.35, 1.35]),
        yaxis=dict(visible=False, range=[-1.2, 1.3]),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=-0.06,
            xanchor="center",
            x=0.5,
            font=dict(color=PALETTE["muted"], size=12),
        ),
    )


def ports_figure(top):
    fig = go.Figure()
    if not top:
        fig.add_annotation(
            text="Sin puertos de destino registrados todavía",
            xref="paper",
            yref="paper",
            x=0.5,
            y=0.5,
            showarrow=False,
            font=dict(family=FONT_FAMILY, size=13, color=PALETTE["muted"]),
        )
        return apply_chart_layout(
            fig,
            height=340,
            margin=dict(l=16, r=24, t=12, b=24),
            xaxis=dict(visible=False),
            yaxis=dict(visible=False),
        )

    values = [v for _, v in top][::-1]
    labels = [f"{proto}/{port}" for (port, proto), _ in top][::-1]
    fig.add_trace(
        go.Bar(
            x=values,
            y=labels,
            orientation="h",
            marker=dict(color=PALETTE["emerald"], line=dict(width=0)),
            text=[f"{v:,}" for v in values],
            textposition="outside",
            textfont=dict(family=FONT_FAMILY, color=PALETTE["muted"], size=11),
            hovertemplate="<b>%{y}</b><br>Paquetes: %{x:,}<extra></extra>",
        )
    )
    max_val = max(values) if values else 1
    return apply_chart_layout(
        fig,
        height=340,
        margin=dict(l=12, r=56, t=12, b=28),
        xaxis=dict(
            title=dict(text="Paquetes", font=dict(color=PALETTE["muted"], size=11)),
            gridcolor=PALETTE["grid"],
            zerolinecolor=PALETTE["border"],
            range=[0, max_val * 1.2],
            tickfont=dict(color=PALETTE["muted"], size=11),
        ),
        yaxis=dict(title="", tickfont=dict(color=PALETTE["text"], size=12)),
        bargap=0.3,
    )


def _style_alert_rows(df):
    def highlight(row):
        if row.get("Nivel") == "Revisar" and row.get("Estado") == "Pendiente":
            return [f"background-color: {PALETTE['warning_tint']}"] * len(row)
        return [""] * len(row)

    return df.style.apply(highlight, axis=1)


@st.fragment(run_every="2s")
def render_security(monitor):
    engine = monitor.security
    snap = engine.snapshot()

    recent = [r for r in snap["connections"] if r["Ultimo"] >= time.time() - 60]
    lan = [d for d in snap["devices"] if d["Tipo"] != "Externo"]
    external_count = sum(d["Tipo"] == "Externo" for d in snap["devices"])
    pending_review = sum(
        r["Nivel"] == "Revisar" and r["Estado"] == "Pendiente" for r in snap["alerts"]
    )
    recognized_count = sum(bool(d.get("Reconocido")) for d in lan)

    k1, k2, k3, k4 = st.columns(4)
    with k1:
        st.metric(
            "Equipos LAN observados",
            len(lan),
            delta=f"{recognized_count} reconocidos",
            delta_color="off",
            border=True,
        )
    with k2:
        st.metric(
            "Flujos activos (1 min)",
            len(recent),
            delta=f"{len(snap['connections'])} retenidos",
            delta_color="off",
            border=True,
        )
    with k3:
        st.metric(
            "Destinos externos",
            external_count,
            border=True,
        )
    with k4:
        st.metric(
            "Señales pendientes",
            pending_review,
            delta="Requiere revisión" if pending_review else "Sin alertas activas",
            delta_color="inverse" if pending_review else "normal",
            border=True,
        )

    bar_left, bar_right = st.columns([8, 4], vertical_alignment="center")
    with bar_left:
        st.caption(
            "Los nombres y reconocimientos persisten entre reinicios. "
            "Que un equipo esté reconocido o sin alertas no certifica ausencia de riesgo."
        )
    with bar_right:
        with st.container(horizontal=True, horizontal_alignment="right"):
            with st.popover("Alcance de visibilidad", icon=":material/visibility:"):
                st.markdown(
                    "La telemetría refleja únicamente el tráfico visible en la interfaz seleccionada. "
                    "Desde un equipo final normalmente se observa tráfico propio, broadcast y multicast. "
                    "Para inspeccionar el tráfico de toda la LAN se requiere captura en el router "
                    "o un puerto espejo (SPAN/mirror). El descubrimiento local detecta vecinos activos, "
                    "pero no revela su navegación."
                )

    if snap["registry_error"]:
        st.error(snap["registry_error"], icon=":material/error:")

    job = snap["job"]
    if job["running"]:
        with st.container(border=True):
            j_col, c_col = st.columns([9, 3], vertical_alignment="center")
            with j_col:
                st.progress(
                    min(job["progress"] / max(job["total"], 1), 1.0),
                    text=f"{job['message']} · {job['progress']}/{job['total']}",
                )
            with c_col:
                if st.button(
                    "Cancelar tarea",
                    icon=":material/cancel:",
                    key="cancel_discovery",
                    width="stretch",
                ):
                    engine.cancel()
    elif job["error"]:
        st.error(job["error"], icon=":material/error:")

    map_tab, inventory_tab, ports_tab, dns_tab, alerts_tab, audit_tab = st.tabs(
        [
            ":material/hub: Mapa y conexiones",
            ":material/devices: Dispositivos",
            ":material/lan: Puertos",
            ":material/dns: DNS y dominios",
            ":material/notifications_active: Alertas",
            ":material/verified_user: Auditoría y parches",
        ]
    )

    with map_tab:
        with st.container(border=True):
            f1, f2 = st.columns([5, 7], vertical_alignment="bottom")
            with f1:
                selected = st.selectbox(
                    "Filtrar por equipo",
                    ["Todos"] + sorted(d["IP"] for d in snap["devices"]),
                    key="security_host",
                )
            with f2:
                window_options = ["Último minuto", "Últimos 5 minutos", "Registros retenidos"]
                window = st.segmented_control(
                    "Periodo de flujos",
                    window_options,
                    default="Último minuto",
                    key="security_window",
                )
                window = window or "Último minuto"

        age = {
            "Último minuto": 60,
            "Últimos 5 minutos": 300,
            "Registros retenidos": float("inf"),
        }[window]
        rows = [
            r
            for r in snap["connections"]
            if time.time() - r["Ultimo"] <= age
            and (selected == "Todos" or selected in (r["Origen"], r["Destino"]))
        ]

        with st.container(border=True):
            st.markdown("**:material/hub: Topología de comunicaciones observadas**")
            st.caption(
                "Hasta 40 nodos y 70 enlaces · el grosor refleja bytes retenidos. "
                "El periodo filtra por última actividad; los bytes por flujo son acumulados."
            )
            st.plotly_chart(
                network_figure(rows, snap["devices"]),
                width="stretch",
                key="security_map",
                config={"displayModeBar": False},
            )

        with st.container(border=True):
            tbl_head, tbl_action = st.columns([8, 4], vertical_alignment="center")
            with tbl_head:
                st.markdown(f"**:material/swap_horiz: Flujos registrados ({len(rows)})**")
            if rows:
                connections = frame(sorted(rows, key=lambda r: r["Ultimo"], reverse=True))
                with tbl_action:
                    with st.container(horizontal=True, horizontal_alignment="right"):
                        st.download_button(
                            "Exportar CSV",
                            connections.to_csv(index=False).encode("utf-8-sig"),
                            file_name="conexiones.csv",
                            mime="text/csv",
                            icon=":material/download:",
                            key="export_connections",
                            on_click="ignore",
                        )
                st.dataframe(
                    connections,
                    hide_index=True,
                    width="stretch",
                    column_config={
                        "Origen": st.column_config.TextColumn("Origen", pinned=True),
                        "Destino": st.column_config.TextColumn("Destino"),
                        "Puerto_origen": st.column_config.NumberColumn("P. origen", format="%d"),
                        "Puerto_destino": st.column_config.NumberColumn("P. destino", format="%d"),
                        "Bytes": st.column_config.NumberColumn("Bytes", format="%d"),
                        "Paquetes": st.column_config.NumberColumn("Paquetes", format="%d"),
                    },
                )
            else:
                st.caption("Aún no hay conexiones para este filtro. Inicia la captura y genera tráfico.")

    with inventory_tab:
        with st.container(border=True):
            st.markdown("**:material/devices: Inventario LAN observado**")
            st.caption(
                "Inventario pasivo y por descubrimiento local, no censo exhaustivo. "
                "Una entrada ARP en caché puede ser antigua y una MAC no identifica por sí sola a una persona."
            )
            if lan:
                st.dataframe(
                    frame(sorted(lan, key=lambda r: r["IP"])),
                    hide_index=True,
                    width="stretch",
                    column_config={
                        "IP": st.column_config.TextColumn("IP", pinned=True),
                        "Reconocido": st.column_config.CheckboxColumn("Reconocido"),
                        "Presencia_reciente": st.column_config.CheckboxColumn("Activo"),
                        "Bytes": st.column_config.NumberColumn("Bytes", format="%d"),
                    },
                )
            else:
                st.caption("Sin equipos LAN registrados en esta sesión.")

        mgmt_left, mgmt_right = st.columns([7, 5])
        with mgmt_left:
            with st.container(border=True, height="stretch"):
                st.markdown("**:material/badge: Identificar y clasificar dispositivo**")
                if lan:
                    device_ip = st.selectbox(
                        "Seleccionar dispositivo",
                        [row["IP"] for row in lan],
                        format_func=lambda ip: next(
                            f"{r['Nombre']} · {ip}" if r.get("Nombre") else ip
                            for r in lan
                            if r["IP"] == ip
                        ),
                        key="registry_device",
                    )
                    device = next(row for row in lan if row["IP"] == device_ip)
                    identity = f"{device_ip}_{device['MAC']}"
                    with st.form("device_registry_form", clear_on_submit=False, border=False):
                        name = st.text_input(
                            "Nombre del dispositivo",
                            value=device["Nombre"],
                            max_chars=80,
                            key=f"device_name_{identity}",
                            placeholder="Ej. Router principal, Laptop oficina",
                        )
                        notes = st.text_area(
                            "Notas operativas",
                            value=device["Notas"],
                            max_chars=500,
                            key=f"device_notes_{identity}",
                            height=88,
                        )
                        recognized = st.checkbox(
                            "Reconozco este dispositivo",
                            value=device["Reconocido"],
                            key=f"device_known_{identity}",
                        )
                        if st.form_submit_button(
                            "Guardar dispositivo",
                            type="primary",
                            icon=":material/save:",
                            disabled=bool(snap["registry_error"]),
                        ):
                            try:
                                engine.save_device(device_ip, name, notes, recognized)
                                st.success(
                                    "Dispositivo guardado. El nombre aparecerá reflejado en el mapa.",
                                    icon=":material/check_circle:",
                                )
                            except (ValueError, OSError, sqlite3.Error) as exc:
                                st.error(str(exc), icon=":material/error:")
                    st.caption(
                        "La identidad se valida por MAC + subred cuando existe MAC; sin ella, sólo por IP (reconocimiento débil)."
                    )
                else:
                    st.caption("Inicia la captura o ejecuta descubrimiento de subred para clasificar equipos.")

        with mgmt_right:
            with st.container(border=True, height="stretch"):
                st.markdown("**:material/radar: Descubrimiento de subred local**")
                networks = available_networks()
                choices = {}
                for row in networks:
                    full = ipaddress.ip_network(row["network"])
                    suggested = ipaddress.ip_network(
                        f"{row['ip']}/{max(full.prefixlen, 24)}", strict=False
                    )
                    choices[f"{row['interface']} · {suggested}"] = str(suggested)
                if choices:
                    choice = st.selectbox(
                        "Subred IPv4 privada",
                        list(choices),
                        key="discovery_network",
                    )
                    if st.button(
                        "Descubrir equipos de esta subred",
                        type="secondary",
                        icon=":material/radar:",
                        disabled=job["running"],
                        key="start_discovery",
                        width="stretch",
                    ):
                        try:
                            engine.start_discovery(choices[choice])
                            st.rerun()
                        except (ValueError, OSError) as exc:
                            st.error(str(exc), icon=":material/error:")
                    st.caption(
                        "Envía un ping por dirección y consulta la caché de vecinos "
                        "(hasta 254 hosts, 16 hilos). Equipos con ICMP bloqueado pueden no responder."
                    )
                else:
                    st.caption("No se detectaron subredes IPv4 privadas en adaptadores activos.")

        if snap["registry"]:
            with st.expander(
                f"Dispositivos guardados en registro persistente ({len(snap['registry'])})",
                icon=":material/inventory_2:",
            ):
                st.dataframe(
                    pd.DataFrame(snap["registry"])[
                        ["name", "network", "ip", "mac", "recognized", "notes"]
                    ],
                    hide_index=True,
                    width="stretch",
                    column_config={
                        "name": st.column_config.TextColumn("Nombre"),
                        "network": st.column_config.TextColumn("Subred"),
                        "ip": st.column_config.TextColumn("IP"),
                        "mac": st.column_config.TextColumn("MAC"),
                        "recognized": st.column_config.CheckboxColumn("Reconocido"),
                        "notes": st.column_config.TextColumn("Notas"),
                    },
                )
                records = {(row["network"], row["identity"]): row for row in snap["registry"]}
                f_sel, f_btn = st.columns([8, 4], vertical_alignment="bottom")
                with f_sel:
                    forget_key = st.selectbox(
                        "Dispositivo guardado",
                        list(records),
                        format_func=lambda key: f"{records[key]['name'] or 'Sin nombre'} · {key[0]} · {key[1]}",
                        key="registry_forget",
                    )
                with f_btn:
                    if st.button(
                        "Olvidar registro",
                        icon=":material/delete:",
                        key="forget_device",
                        width="stretch",
                    ):
                        try:
                            engine.registry.forget(*forget_key)
                            st.rerun()
                        except (ValueError, OSError, sqlite3.Error) as exc:
                            st.error(str(exc), icon=":material/error:")

    with ports_tab:
        counts = defaultdict(int)
        for row in snap["connections"]:
            counts[(row["Puerto_destino"], row["Protocolo"])] += row["Paquetes"]
        top = sorted(counts.items(), key=lambda item: item[1], reverse=True)[:15]

        p_chart, p_probe = st.columns([7, 5])
        with p_chart:
            with st.container(border=True, height="stretch"):
                st.markdown("**:material/lan: Puertos de destino más frecuentes**")
                st.caption(
                    "Puertos observados ≠ puertos abiertos. El servicio se estima por número de puerto."
                )
                st.plotly_chart(
                    ports_figure(top),
                    width="stretch",
                    key="security_ports",
                    config={"displayModeBar": False},
                )
        with p_probe:
            with st.container(border=True, height="stretch"):
                st.markdown("**:material/troubleshoot: Comprobación activa TCP**")
                targets = sorted(d["IP"] for d in lan)
                if targets:
                    target = st.selectbox(
                        "Equipo local objetivo",
                        targets,
                        key="port_target",
                    )
                    if st.button(
                        "Comprobar 12 puertos TCP comunes",
                        type="primary",
                        icon=":material/troubleshoot:",
                        disabled=job["running"],
                        key="check_ports",
                        width="stretch",
                    ):
                        try:
                            engine.start_port_check(target)
                            st.rerun()
                        except (ValueError, OSError) as exc:
                            st.error(str(exc), icon=":material/error:")
                    st.caption(
                        "Realiza conexiones TCP estándar sin autenticación ni payloads. "
                        "Puede quedar registrado en el equipo objetivo; sin respuesta no garantiza puerto cerrado."
                    )
                else:
                    st.caption("Detecta al menos un equipo LAN para ejecutar comprobaciones de puertos.")

        if snap["ports"]:
            with st.container(border=True):
                st.markdown("**:material/list_alt: Resultados de comprobación TCP**")
                st.dataframe(frame(snap["ports"]), hide_index=True, width="stretch")

    with dns_tab:
        with st.container(border=True):
            st.markdown("**:material/dns: Consultas y respuestas DNS observadas**")
            query = (
                st.text_input(
                    "Filtrar dominio o IP cliente",
                    key="dns_filter",
                    placeholder="Ej. example.org o 192.168.1.10",
                )
                .strip()
                .lower()
            )
            dns_rows = [
                r
                for r in snap["dns"]
                if not query or query in r["Dominio"].lower() or query in r["Cliente"]
            ]
            st.caption(
                "Tráfico DNS visible en puerto 53. No sustituye un historial completo: "
                "caché local y DNS cifrado (DoH/DoT) no son visibles; HTTPS oculta rutas y contenido."
            )
            if dns_rows:
                st.dataframe(
                    frame(dns_rows),
                    hide_index=True,
                    width="stretch",
                    column_config={
                        "Dominio": st.column_config.TextColumn("Dominio", pinned=True),
                    },
                )
            else:
                st.caption("Sin registros DNS coincidentes con el filtro actual.")

    with alerts_tab:
        ctrl_left, ctrl_right = st.columns([8, 4], vertical_alignment="center")
        with ctrl_left:
            pending_only = st.toggle(
                "Mostrar sólo señales pendientes",
                value=True,
                key="pending_alerts",
            )
        with ctrl_right:
            with st.container(horizontal=True, horizontal_alignment="right"):
                st.download_button(
                    "Exportar informe JSON",
                    engine.export_json(),
                    file_name="informe_red.json",
                    mime="application/json",
                    icon=":material/download:",
                    key="security_report",
                    on_click="ignore",
                )

        alerts = [r for r in snap["alerts"] if not pending_only or r["Estado"] == "Pendiente"]
        with st.container(border=True):
            st.markdown(f"**:material/notifications_active: Registro de señales ({len(alerts)})**")
            if alerts:
                alerts_df = frame(alerts)
                st.dataframe(
                    _style_alert_rows(alerts_df),
                    hide_index=True,
                    width="stretch",
                    column_config={
                        "ID": None,
                        "Nivel": st.column_config.TextColumn("Nivel"),
                        "Regla": st.column_config.TextColumn("Regla"),
                        "IP": st.column_config.TextColumn("Equipo"),
                        "Estado": st.column_config.TextColumn("Estado"),
                    },
                )
                alert_by_id = {row["ID"]: row for row in alerts}
                a_sel, a_btn = st.columns([8, 4], vertical_alignment="bottom")
                with a_sel:
                    alert_id = st.selectbox(
                        "Alerta a gestionar",
                        list(alert_by_id),
                        format_func=lambda value: (
                            f"{alert_by_id[value]['Regla']} · "
                            f"{alert_by_id[value]['IP']} · {value[:8]}"
                        ),
                        key="alert_review",
                    )
                with a_btn:
                    if st.button(
                        "Marcar como revisada",
                        type="primary",
                        icon=":material/check_circle:",
                        key="review_alert",
                        width="stretch",
                    ):
                        engine.review_alert(alert_id)
                        st.rerun()
            else:
                st.caption(
                    "Sin señales coincidentes con este filtro. "
                    "Revisar una alerta no desactiva avisos futuros."
                )

        with st.expander("Reglas heurísticas activas y criterios", icon=":material/info:"):
            st.markdown(
                "- **Dispositivo nuevo:** primer avistamiento confirmado de una IP LAN no reconocida.\n"
                "- **Cambio de MAC:** asociación de una nueva dirección física a una IP LAN observada.\n"
                "- **Posible barrido TCP:** 20 o más puertos TCP SYN sin ACK hacia un mismo destino en 10 s.\n"
                "- **Servicio sin cifrado habitual:** tráfico saliente LAN hacia FTP (21) o Telnet (23).\n\n"
                "Deduplicación de 60 s por regla y origen. Son indicadores heurísticos, no diagnósticos definitivos."
            )

    with audit_tab:
        render_audit(engine, snap, lan)

    if not job["running"] and job["total"]:
        st.caption(f"Última tarea de red: {job['message']} ({job['progress']}/{job['total']})")
