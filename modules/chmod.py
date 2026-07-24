import streamlit as st

def render_chmod_module():
    st.title("🐧 Linux Chmod Permission Calculator")
    st.markdown("Calculate octal values, symbolic strings, and commands for Linux file system permissions.")

    st.subheader("Presets")
    preset = st.selectbox(
        "Choose a common permission preset",
        ["Custom", "Standard Executable (755)", "Private File (600)", "Read-Only File (644)", "Strict Secret (400)", "Full Access (777)"]
    )

    r_owner, w_owner, x_owner = True, True, True
    r_group, w_group, x_group = True, False, True
    r_public, w_public, x_public = True, False, True

    if preset == "Standard Executable (755)":
        r_owner, w_owner, x_owner = True, True, True
        r_group, w_group, x_group = True, False, True
        r_public, w_public, x_public = True, False, True
    elif preset == "Private File (600)":
        r_owner, w_owner, x_owner = True, True, False
        r_group, w_group, x_group = False, False, False
        r_public, w_public, x_public = False, False, False
    elif preset == "Read-Only File (644)":
        r_owner, w_owner, x_owner = True, True, False
        r_group, w_group, x_group = True, False, False
        r_public, w_public, x_public = True, False, False
    elif preset == "Strict Secret (400)":
        r_owner, w_owner, x_owner = True, False, False
        r_group, w_group, x_group = False, False, False
        r_public, w_public, x_public = False, False, False
    elif preset == "Full Access (777)":
        r_owner, w_owner, x_owner = True, True, True
        r_group, w_group, x_group = True, True, True
        r_public, w_public, x_public = True, True, True

    c1, c2, c3 = st.columns(3)

    with c1:
        st.markdown("### Owner (User)")
        u_r = st.checkbox("Read (4)", value=r_owner, key="u_r")
        u_w = st.checkbox("Write (2)", value=w_owner, key="u_w")
        u_x = st.checkbox("Execute (1)", value=x_owner, key="u_x")

    with c2:
        st.markdown("### Group")
        g_r = st.checkbox("Read (4)", value=r_group, key="g_r")
        g_w = st.checkbox("Write (2)", value=w_group, key="g_w")
        g_x = st.checkbox("Execute (1)", value=x_group, key="g_x")

    with c3:
        st.markdown("### Public (Others)")
        o_r = st.checkbox("Read (4)", value=r_public, key="o_r")
        o_w = st.checkbox("Write (2)", value=w_public, key="o_w")
        o_x = st.checkbox("Execute (1)", value=x_public, key="o_x")

    owner_val = (4 if u_r else 0) + (2 if u_w else 0) + (1 if u_x else 0)
    group_val = (4 if g_r else 0) + (2 if g_w else 0) + (1 if g_x else 0)
    other_val = (4 if o_r else 0) + (2 if o_w else 0) + (1 if o_x else 0)

    octal_str = f"{owner_val}{group_val}{other_val}"

    sym_u = f"{'r' if u_r else '-'}{'w' if u_w else '-'}{'x' if u_x else '-'}"
    sym_g = f"{'r' if g_r else '-'}{'w' if g_w else '-'}{'x' if g_x else '-'}"
    sym_o = f"{'r' if o_r else '-'}{'w' if o_w else '-'}{'x' if o_x else '-'}"
    symbolic_str = f"-{sym_u}{sym_g}{sym_o}"

    st.divider()

    res_col1, res_col2 = st.columns(2)
    with res_col1:
        st.metric("Octal Notation", octal_str)
        st.code(f"chmod {octal_str} filename", language="bash")

    with res_col2:
        st.metric("Symbolic Notation", symbolic_str)
        st.code(f"chmod u={sym_u.replace('-', '')},g={sym_g.replace('-', '')},o={sym_o.replace('-', '')} filename", language="bash")
