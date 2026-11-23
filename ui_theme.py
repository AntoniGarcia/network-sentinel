"""Paleta corporativa y utilidades de estilo para gráficos Plotly."""

PALETTE = {
    "bg": "#0B1120",
    "surface": "#131C31",
    "border": "#243247",
    "grid": "#1E293B",
    "text": "#F1F5F9",
    "muted": "#94A3B8",
    "blue": "#3B82F6",
    "blue_fill": "rgba(59, 130, 246, 0.14)",
    "emerald": "#10B981",
    "amber": "#F59E0B",
    "amber_fill": "rgba(245, 158, 11, 0.12)",
    "danger": "#EF4444",
    "danger_tint": "rgba(239, 68, 68, 0.16)",
    "warning_tint": "rgba(245, 158, 11, 0.14)",
    "info_tint": "rgba(59, 130, 246, 0.12)",
    "edge": "rgba(148, 163, 184, 0.28)",
}

FONT_FAMILY = "Inter, -apple-system, BlinkMacSystemFont, sans-serif"


def apply_chart_layout(fig, *, height=300, margin=None, **kwargs):
    """Aplica estilo visual consistente y transparente sobre tarjetas nativas."""
    layout = dict(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family=FONT_FAMILY, color=PALETTE["text"], size=12),
        height=height,
        margin=margin or dict(l=16, r=20, t=28, b=24),
        hoverlabel=dict(
            bgcolor="#0F172A",
            bordercolor="#334155",
            font=dict(family=FONT_FAMILY, color=PALETTE["text"], size=12),
        ),
    )
    layout.update(kwargs)
    fig.update_layout(**layout)
    return fig
