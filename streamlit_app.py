from math import log10

import streamlit as st

from bifurcation import bifurcation_points
from logistic_map import logistic_orbit, lyapunov_exponent
from periodicity import estimate_period

st.set_page_config(page_title="ZENITH-1-PRO", page_icon="🌀")

st.title("ZENITH-1-PRO Logistic Map Lab")
st.caption("A deterministic, paper-only experiment in nonlinear dynamics.")
st.info(
    "PAPER-ONLY: inputs and work are bounded, results are reproducible, and "
    "the lab performs no external I/O."
)

with st.sidebar:
    st.header("Simulation controls")
    rate = st.slider(
        "Growth rate (r)",
        min_value=0.0,
        max_value=4.0,
        value=3.9,
        step=0.01,
    )
    initial_state = st.slider(
        "Initial state (x₀)",
        min_value=0.001,
        max_value=0.999,
        value=0.2,
        step=0.001,
    )
    iterations = st.slider(
        "Iterations",
        min_value=10,
        max_value=500,
        value=100,
        step=10,
    )

with st.expander("Bifurcation explorer settings", expanded=False):
    rate_min, rate_max = st.columns(2)
    sweep_min = rate_min.number_input(
        "Sweep start (r)", min_value=0.0, max_value=3.99, value=2.8, step=0.1
    )
    sweep_max = rate_max.number_input(
        "Sweep end (r)", min_value=0.01, max_value=4.0, value=4.0, step=0.1
    )
    sweep_samples = st.number_input(
        "Rate samples", min_value=2, max_value=100, value=80, step=1
    )
    sweep_iterations = st.number_input(
        "Iterations per rate", min_value=10, max_value=1_000, value=400, step=10
    )
    sweep_discard = st.number_input(
        "Discarded transient", min_value=0, max_value=999, value=300, step=10
    )
    sweep_points = st.number_input(
        "Points per rate", min_value=1, max_value=100, value=40, step=1
    )

st.latex(r"x_{n+1} = r x_n (1 - x_n)")

shadow_offset = 1e-9
primary_orbit = logistic_orbit(rate, initial_state, iterations)
shadow_orbit = logistic_orbit(rate, initial_state + shadow_offset, iterations)
divergence = [
    abs(primary - shadow)
    for primary, shadow in zip(primary_orbit, shadow_orbit, strict=True)
]
transient_iterations = min(100, iterations // 2)
exponent = lyapunov_exponent(
    rate,
    initial_state,
    iterations,
    discard=transient_iterations,
)

if exponent == float("-inf"):
    exponent_display = "−∞"
    regime = "Contracting / stable"
elif exponent > 1e-3:
    exponent_display = f"{exponent:.6f}"
    regime = "Chaotic"
elif exponent < -1e-3:
    exponent_display = f"{exponent:.6f}"
    regime = "Contracting / periodic"
else:
    exponent_display = f"{exponent:.6f}"
    regime = "Near a transition"

st.subheader("Orbit comparison")
st.write(
    "The shadow orbit starts only `1e-9` away from the primary orbit, making "
    "sensitivity to initial conditions directly visible."
)
st.line_chart(
    {
        "Primary orbit": primary_orbit,
        "Shadow orbit": shadow_orbit,
    }
)

final_column, divergence_column, range_column = st.columns(3)
final_column.metric("Final state", f"{primary_orbit[-1]:.6f}")
divergence_column.metric("Final divergence", f"{divergence[-1]:.3e}")
range_column.metric(
    "Observed range",
    f"{min(primary_orbit):.3f} – {max(primary_orbit):.3f}",
)

st.subheader("Chaos diagnostics")
st.write(
    "The finite-time Lyapunov exponent measures average local expansion after "
    f"discarding {transient_iterations} transient iterations. Positive values "
    "indicate sensitive chaos; negative values indicate contraction. Values "
    "near zero mark a transition and are not, by themselves, proof of a "
    "long-term regime."
)
exponent_column, regime_column = st.columns(2)
exponent_column.metric("Lyapunov exponent", exponent_display)
regime_column.metric("Finite-time regime", regime)

st.subheader("Periodicity explorer")
period_window = min(len(primary_orbit), 200)
period_length = estimate_period(primary_orbit[-period_window:], max_period=min(64, period_window))
period_label = "No stable short cycle detected" if period_length is None else f"{period_length} steps"
st.metric("Detected cycle length", period_label)

if period_length is not None:
    periodic_tail = primary_orbit[-period_length:]
    st.caption(
        "The visible orbit tail was evaluated for the shortest repeating cycle "
        "within a bounded tolerance."
    )
    st.line_chart({"Orbit tail": periodic_tail})

st.subheader("Bifurcation diagram")
if sweep_min >= sweep_max:
    st.warning("Choose a sweep start that is less than the sweep end.")
else:
    sweep_discard = min(int(sweep_discard), int(sweep_iterations) - 1)
    diagram = bifurcation_points(
        float(sweep_min),
        float(sweep_max),
        rate_samples=int(sweep_samples),
        iterations=int(sweep_iterations),
        discard=sweep_discard,
        points_per_rate=int(sweep_points),
    )
    st.scatter_chart(
        {
            "Growth rate (r)": [point[0] for point in diagram],
            "State (x)": [point[1] for point in diagram],
        },
        x="Growth rate (r)",
        y="State (x)",
    )
    st.caption(
        f"{len(diagram):,} deterministic samples across {int(sweep_samples)} "
        "growth rates. This finite sweep is exploratory, not a proof of "
        "long-term behavior."
    )

divergence_floor = 1e-16
st.line_chart(
    {
        "log10 absolute divergence": [
            log10(max(value, divergence_floor)) for value in divergence
        ]
    }
)
st.caption(
    "Divergence is displayed as log10 absolute divergence with a numerical "
    "floor of 1e-16."
)

st.subheader("Last 10 iterations")
tail_start = max(0, len(primary_orbit) - 10)
st.dataframe(
    [
        {
            "iteration": index,
            "primary": primary_orbit[index],
            "shadow": shadow_orbit[index],
            "absolute divergence": divergence[index],
        }
        for index in range(tail_start, len(primary_orbit))
    ],
    hide_index=True,
)
