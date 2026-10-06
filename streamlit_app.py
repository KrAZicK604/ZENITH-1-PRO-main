import streamlit as st

from logistic_map import logistic_orbit

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

st.latex(r"x_{n+1} = r x_n (1 - x_n)")

shadow_offset = 1e-9
primary_orbit = logistic_orbit(rate, initial_state, iterations)
shadow_orbit = logistic_orbit(rate, initial_state + shadow_offset, iterations)
divergence = [
    abs(primary - shadow)
    for primary, shadow in zip(primary_orbit, shadow_orbit, strict=True)
]

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
