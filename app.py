"""Dashboard Streamlit para Bandwidth Monitor."""

from pathlib import Path

import plotly.graph_objects as go
import streamlit as st

from capture import BandwidthMonitor, capture_diagnostics
from security_ui import render_security
from ui_theme import FONT_FAMILY, PALETTE, apply_chart_layout

st.set_page_config(
    page_title="Network Sentinel · Bandwidth Monitor",
    page_icon=":material/shield:",
    layout="wide",
    initial_sidebar_state="expanded",
)


@st.cache_resource
def get_monitor():
    return BandwidthMonitor(registry_path=Path(__file__).parent / "data" / "devices.sqlite3")


@st.cache_data(ttl="5m")
def get_available_interfaces():
    return capture_diagnostics()


def render_gauge(top_app, top_mbps, threshold):
    axis_max = max(threshold * 2, top_mbps * 1.25, 1.0)
    bar_color = PALETTE["danger"] if top_mbps > threshold else PALETTE["blue"]
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=top_mbps,
            number={
                "suffix": " Mbps",
                "valueformat": ".2f",
                "font": {"family": FONT_FAMILY, "color": PALETTE["text"], "size": 30},
            },
            gauge={
                "axis": {
                    "range": [0, axis_max],
                    "tickwidth": 1,
                    "tickcolor": PALETTE["muted"],
                    "tickfont": {"color": PALETTE["muted"], "size": 11},
                },
                "bar": {"color": bar_color, "thickness": 0.72},
                "bgcolor": PALETTE["surface"],
                "borderwidth": 1,
                "bordercolor": PALETTE["border"],
                "steps": [
                    {"range": [0, min(threshold, axis_max)], "color": "rgba(59, 130, 246, 0.08)"},
                    {"range": [min(threshold, axis_max), axis_max], "color": "rgba(239, 68, 68, 0.08)"},
                ],
                "threshold": {
                    "line": {"color": PALETTE["amber"], "width": 3},
                    "thickness": 0.85,
                    "value": threshold,
                },
            },
        )
    )
    return apply_chart_layout(
        fig,
        height=265,
        margin=dict(l=24, r=24, t=22, b=12),
    )


def render_bar_chart(df, threshold):
    fig = go.Figure()
    if df.empty:
        fig.add_annotation(
            text="Sin consumo registrado en la ventana actual",
            xref="paper",
            yref="paper",
            x=0.5,
            y=0.5,
            showarrow=False,
            font=dict(family=FONT_FAMILY, size=13, color=PALETTE["muted"]),
        )
        return apply_chart_layout(
            fig,
            height=265,
            margin=dict(l=16, r=24, t=12, b=24),
            xaxis=dict(visible=False),
            yaxis=dict(visible=False),
        )

    top5 = df.head(5).iloc[::-1]
    colors = [PALETTE["danger"] if v > threshold else PALETTE["blue"] for v in top5["Mbps"]]
    max_val = max(float(top5["Mbps"].max()), threshold, 0.1)

    fig.add_trace(
        go.Bar(
            x=top5["Mbps"],
            y=top5["Aplicación"],
            orientation="h",
            marker=dict(color=colors, line=dict(width=0)),
            text=[f"{v:.3f} Mbps" for v in top5["Mbps"]],
            textposition="outside",
            textfont=dict(family=FONT_FAMILY, color=PALETTE["muted"], size=11),
            hovertemplate="<b>%{y}</b><br>Consumo: %{x:.3f} Mbps<extra></extra>",
        )
    )
    fig.add_vline(
        x=threshold,
        line_dash="dot",
        line_color=PALETTE["amber"],
        line_width=1.5,
        annotation_text=f"Umbral ({threshold:.1f})",
        annotation_position="top right",
        annotation_font=dict(color=PALETTE["amber"], size=11),
    )
    return apply_chart_layout(
        fig,
        height=265,
        margin=dict(l=12, r=76, t=18, b=28),
        xaxis=dict(
            title=dict(text="Mbps", font=dict(color=PALETTE["muted"], size=11)),
            gridcolor=PALETTE["grid"],
            zerolinecolor=PALETTE["border"],
            range=[0, max_val * 1.28],
            tickfont=dict(color=PALETTE["muted"], size=11),
        ),
        yaxis=dict(
            title="",
            tickfont=dict(color=PALETTE["text"], size=12),
        ),
        bargap=0.35,
    )


def render_history_chart(history):
    fig = go.Figure()
    series = [
        ("Descarga Mbps", "Descarga", PALETTE["blue"], PALETTE["blue_fill"]),
        ("Subida Mbps", "Subida", PALETTE["amber"], PALETTE["amber_fill"]),
    ]
    for column, label, color, fill in series:
        fig.add_trace(
            go.Scatter(
                x=history["Hora"],
                y=history[column],
                name=label,
                mode="lines",
                line=dict(color=color, width=2),
                fill="tozeroy",
                fillcolor=fill,
                hovertemplate=f"{label}: %{{y:.3f}} Mbps<extra></extra>",
            )
        )
    return apply_chart_layout(
        fig,
        height=250,
        margin=dict(l=16, r=16, t=16, b=24),
        hovermode="x unified",
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1.0,
            font=dict(color=PALETTE["muted"], size=12),
        ),
        xaxis=dict(
            gridcolor=PALETTE["grid"],
            showgrid=False,
            tickfont=dict(color=PALETTE["muted"], size=11),
        ),
        yaxis=dict(
            title=dict(text="Mbps", font=dict(color=PALETTE["muted"], size=11)),
            gridcolor=PALETTE["grid"],
            zerolinecolor=PALETTE["border"],
            tickfont=dict(color=PALETTE["muted"], size=11),
        ),
    )


def render_dashboard(df, stats, threshold, history):
    top_app = df.iloc[0]["Aplicación"] if not df.empty else ""
    top_mbps = float(df.iloc[0]["Mbps"]) if not df.empty else 0.0
    download_mbps = float(df["Descarga Mbps"].sum()) if not df.empty else 0.0
    upload_mbps = float(df["Subida Mbps"].sum()) if not df.empty else 0.0
    total_session_mb = stats["total_bytes"] / 1048576
    dl_session_mb = stats["download_bytes"] / 1048576
    ul_session_mb = stats["upload_bytes"] / 1048576
    alert_apps = df[df["Mbps"] > threshold] if not df.empty else df

    dl_spark = history["Descarga Mbps"].tail(30).tolist() if len(history) >= 2 else None
    ul_spark = history["Subida Mbps"].tail(30).tolist() if len(history) >= 2 else None

    k1, k2, k3, k4 = st.columns(4)
    with k1:
        st.metric(
            "Descarga actual",
            f"{download_mbps:.3f} Mbps",
            border=True,
            chart_data=dl_spark,
            chart_type="line",
        )
    with k2:
        st.metric(
            "Subida actual",
            f"{upload_mbps:.3f} Mbps",
            border=True,
            chart_data=ul_spark,
            chart_type="line",
        )
    with k3:
        st.metric(
            "Volumen acumulado",
            f"{total_session_mb:.2f} MiB",
            delta=f"Descarga {dl_session_mb:.1f} · Subida {ul_session_mb:.1f} MiB",
            delta_color="off",
            border=True,
        )
    with k4:
        st.metric(
            "Aplicaciones activas",
            str(len(df)),
            delta=(
                f"{len(alert_apps)} sobre umbral"
                if not alert_apps.empty
                else f"Sesión · {stats['elapsed_seconds']:.0f} s"
            ),
            delta_color="inverse" if not alert_apps.empty else "off",
            border=True,
        )

    if not alert_apps.empty:
        nombres = ", ".join(alert_apps["Aplicación"].astype(str).tolist())
        st.error(
            f"**Umbral excedido ({threshold:.1f} Mbps):** {len(alert_apps)} aplicación(es) "
            f"superan el límite configurado: {nombres}.",
            icon=":material/warning:",
        )

    col_gauge, col_bar = st.columns([5, 7])
    with col_gauge:
        with st.container(border=True, height="stretch"):
            st.markdown("**:material/speed: Mayor consumidor actual**")
            st.caption(
                f"Proceso líder: {top_app}"
                if top_app
                else "Sin procesos clasificados en la ventana actual"
            )
            st.plotly_chart(
                render_gauge(top_app, top_mbps, threshold),
                width="stretch",
                config={"displayModeBar": False},
            )
    with col_bar:
        with st.container(border=True, height="stretch"):
            st.markdown("**:material/bar_chart: Top 5 aplicaciones por consumo**")
            st.caption(f"Ventana móvil de 5 s · umbral de alerta en {threshold:.1f} Mbps")
            st.plotly_chart(
                render_bar_chart(df, threshold),
                width="stretch",
                config={"displayModeBar": False},
            )

    if not history.empty:
        with st.container(border=True):
            st.markdown("**:material/show_chart: Evolución del tráfico**")
            st.caption("Historial reciente de descarga y subida (hasta 10 minutos)")
            st.plotly_chart(
                render_history_chart(history),
                width="stretch",
                key="traffic_history",
                config={"displayModeBar": False},
            )

    with st.expander("Detalle completo de aplicaciones", icon=":material/table_rows:", expanded=False):
        def highlight_alert(row):
            style = f"background-color: {PALETTE['danger_tint']}" if row["Mbps"] > threshold else ""
            return [style] * len(row)

        st.dataframe(
            df.style.apply(highlight_alert, axis=1),
            width="stretch",
            hide_index=True,
            column_config={
                "Aplicación": st.column_config.TextColumn("Aplicación", pinned=True),
                "Mbps": st.column_config.NumberColumn("Total (Mbps)", format="%.3f"),
                "Descarga Mbps": st.column_config.NumberColumn("Descarga (Mbps)", format="%.3f"),
                "Subida Mbps": st.column_config.NumberColumn("Subida (Mbps)", format="%.3f"),
                "Bytes": st.column_config.NumberColumn("Bytes totales", format="%d"),
                "Descarga Bytes": st.column_config.NumberColumn("Descarga (B)", format="%d"),
                "Subida Bytes": st.column_config.NumberColumn("Subida (B)", format="%d"),
                "Bps": st.column_config.NumberColumn("Bps", format="%.0f"),
                "Conexiones activas": st.column_config.NumberColumn("Flujos", format="%d"),
            },
        )


@st.fragment(run_every="2s")
def render_live_dashboard(monitor, threshold):
    status = monitor.get_status()

    if not status["running"] and st.session_state.get("capturing"):
        st.session_state.capturing = False
        st.rerun(scope="app")

    if status.get("last_error"):
        st.error(status["last_error"], icon=":material/error:")
    if status.get("dns_last_error"):
        st.warning(f"Captura DNS: {status['dns_last_error']}", icon=":material/warning:")
    if status.get("proc_permission_warning"):
        st.warning(
            "No se pudo leer el mapa de procesos (psutil.net_connections). "
            "Ejecuta la aplicación como administrador/root para clasificar "
            "tráfico por proceso; mientras tanto se clasifica por dominio/puerto.",
            icon=":material/admin_panel_settings:",
        )

    with st.container(horizontal=True, vertical_alignment="center"):
        st.badge(status["state"], icon=":material/radio_button_checked:", color="green")
        st.caption(
            f"Paquetes IP: {status['packets_captured']:,} · "
            f"Paquetes DNS: {status['dns_packets_captured']:,} · "
            f"Interfaz: `{status.get('interface') or 'auto'}`"
        )

    df = monitor.get_dataframe()
    stats = monitor.get_session_stats()

    if df.empty and status["running"]:
        st.info(
            f"Capturando en la interfaz `{status['interface']}` "
            f"(IP vistos: {status['packets_captured']}, DNS vistos: {status['dns_packets_captured']}). "
            "Si los contadores no aumentan tras unos segundos, confirma la interfaz activa, "
            "la instalación de `tshark` y los permisos de captura.",
            icon=":material/sensors:",
        )
    render_dashboard(df, stats, threshold, monitor.get_history())


def main():
    monitor = get_monitor()
    st.session_state.capturing = monitor.is_running()

    with st.sidebar:
        st.subheader(":material/tune: Panel de control")

        with st.container(border=True):
            st.markdown("**:material/settings_ethernet: Motor de captura**")
            diagnosis = get_available_interfaces()
            available_interfaces = diagnosis["interfaces"]
            if diagnosis["ok"]:
                st.badge(
                    f"TShark operativo · {len(available_interfaces)} interfaz(ces)",
                    icon=":material/check_circle:",
                    color="green",
                )
            else:
                st.error(diagnosis["error"], icon=":material/error:")

            options = [None] + [name for name, _ in available_interfaces]
            labels = dict(available_interfaces)
            selected_interface = st.selectbox(
                "Interfaz de red",
                options,
                format_func=lambda name: "Autodetectar" if name is None else f"{labels[name]} ({name})",
                disabled=monitor.is_running(),
            )
            if st.button(
                "Actualizar interfaces",
                icon=":material/refresh:",
                disabled=monitor.is_running(),
                width="stretch",
            ):
                get_available_interfaces.clear()
                st.rerun()

        with st.container(border=True):
            st.markdown("**:material/monitoring: Control de sesión**")
            threshold = st.number_input(
                "Umbral de alerta (Mbps)",
                min_value=0.1,
                value=1.0,
                step=0.1,
            )

            if not st.session_state.capturing:
                if st.button(
                    "Iniciar captura",
                    type="primary",
                    icon=":material/play_arrow:",
                    width="stretch",
                    disabled=not diagnosis["ok"],
                ):
                    st.session_state.capturing = monitor.start(interface=selected_interface)
                    st.rerun()
            else:
                if st.button(
                    "Detener captura",
                    type="primary",
                    icon=":material/stop:",
                    width="stretch",
                ):
                    monitor.stop()
                    st.session_state.capturing = False
                    st.rerun()

            if st.button(
                "Nueva sesión (borrar totales)",
                icon=":material/restart_alt:",
                disabled=monitor.is_running(),
                width="stretch",
                help="Borra tráfico, alertas e inventario de esta sesión. Conserva los nombres y reconocimientos guardados.",
            ):
                monitor.reset()
                st.rerun()

        if monitor.interface:
            st.caption(f"Interfaz activa: `{monitor.interface}`")
        st.caption(
            "Requiere TShark y permisos de captura (Npcap/dumpcap). "
            "La asociación por proceso puede requerir privilegios elevados."
        )

    header_left, header_right = st.columns([7, 5], vertical_alignment="center")
    with header_left:
        st.title(":material/shield: Network Sentinel")
        st.caption("Visibilidad defensiva de red, inventario LAN y monitoreo de ancho de banda")
    with header_right:
        with st.container(horizontal=True, horizontal_alignment="right"):
            if st.session_state.capturing:
                st.badge("Captura activa", icon=":material/radio_button_checked:", color="green")
            else:
                st.badge("Captura detenida", icon=":material/pause_circle:", color="gray")
            if monitor.interface:
                st.badge(str(monitor.interface), icon=":material/settings_ethernet:", color="blue")

    security_tab, bandwidth_tab = st.tabs(
        [
            ":material/shield: Seguridad de red",
            ":material/monitoring: Consumo de este equipo",
        ]
    )
    with security_tab:
        render_security(monitor)
    with bandwidth_tab:
        st.caption(
            "IPv4 / IPv6 · ventana móvil de 5 segundos · flujos recientes y alertas combinadas de subida y descarga."
        )
        if not st.session_state.capturing:
            status = monitor.get_status()
            if status.get("last_error"):
                st.error(status["last_error"], icon=":material/error:")
            st.info(
                "La captura está detenida. Inicia una sesión desde el panel de control lateral.",
                icon=":material/info:",
            )
            render_dashboard(
                monitor.get_dataframe(),
                monitor.get_session_stats(),
                threshold,
                monitor.get_history(),
            )
        else:
            render_live_dashboard(monitor, threshold)


if __name__ == "__main__":
    main()
