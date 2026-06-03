import streamlit as st
from scanner import scan_text

st.set_page_config(
    page_title="AI Security Scanner",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ AI Security Scanner")
st.subheader("Prompt Injection, Secret Leak & Suspicious URL Detection")

st.write(
    "Scan text or uploaded files for prompt injection attempts, leaked credentials, and suspicious URLs."
)

tab1, tab2 = st.tabs(["Scan Text", "Scan File"])

# =========================
# TEXT SCAN TAB
# =========================

with tab1:

    user_input = st.text_area(
        "Enter text to scan",
        height=220
    )

    if st.button("Scan Text"):

        if user_input.strip():

            result = scan_text(user_input)

            col1, col2 = st.columns(2)

            col1.metric(
                "Risk Score",
                f"{result['risk_score']}/100"
            )

            col2.metric(
                "Risk Level",
                result["overall_risk"]
            )

            if result["findings"]:

                st.subheader("Findings")

                for finding in result["findings"]:

                    st.error(
                        f"{finding['type']} | Severity: {finding['severity']}"
                    )

                    st.code(
                        finding["pattern"]
                    )

            else:
                st.success("No threats detected.")

        else:
            st.warning("Please enter text first.")


# =========================
# FILE SCAN TAB
# =========================

with tab2:

    uploaded_file = st.file_uploader(
        "Upload a file to scan",
        type=["txt", "py", "js", "html", "css", "json", "env", "md"]
    )

    if uploaded_file is not None:

        file_content = uploaded_file.read().decode(
            "utf-8",
            errors="ignore"
        )

        st.success(
            f"Uploaded: {uploaded_file.name}"
        )

        with st.expander("Preview File Content"):

            st.code(
                file_content[:3000]
            )

        if st.button("Scan Uploaded File"):

            result = scan_text(file_content)

            col1, col2 = st.columns(2)

            col1.metric(
                "Risk Score",
                f"{result['risk_score']}/100"
            )

            col2.metric(
                "Risk Level",
                result["overall_risk"]
            )

            if result["findings"]:

                st.subheader("Findings")

                for finding in result["findings"]:

                    st.error(
                        f"{finding['type']} | Severity: {finding['severity']}"
                    )

                    st.code(
                        finding["pattern"]
                    )

            else:
                st.success("No threats detected.")
