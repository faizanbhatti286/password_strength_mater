import streamlit as st
import re

# Page configuration
st.set_page_config(page_title="Password Strength Checker", page_icon="🔑", layout="centered")

# Title
st.title("🔑 Password Strength Checker")
st.write("Check how strong your password is based on common security rules.")

# Function to check password strength
def check_password_strength(password):
    strength = 0
    feedback = []

    if len(password) >= 8:
        strength += 1
    else:
        feedback.append("❌ Password should be at least 8 characters long.")

    if re.search(r"[a-z]", password):
        strength += 1
    else:
        feedback.append("❌ Password should include lowercase letters.")

    if re.search(r"[A-Z]", password):
        strength += 1
    else:
        feedback.append("❌ Password should include uppercase letters.")

    if re.search(r"\d", password):
        strength += 1
    else:
        feedback.append("❌ Password should include at least one digit (0–9).")

    if re.search(r"[!@#$%^&*]", password):
        strength += 1
    else:
        feedback.append("❌ Password should include at least one special character (e.g., !@#$%^&*).")

    return strength, feedback

# Display password input
password = st.text_input("Enter your password", type="password")

# Button to check strength
if st.button("Check strength"):
    if password:
        strength, feedback = check_password_strength(password)

        # Display strength result
        st.subheader("🔍 Password Strength:")
        st.progress(strength / 5)

        if strength == 5:
            st.success("✅ Strong password!")
        elif 3 <= strength < 5:
            st.warning("⚠️ Moderate password. You can improve it.")
        else:
            st.error("❌ Weak password. Needs improvement.")

        # Feedback
        with st.expander("🛠 Suggestions for Improvement"):
            for remark in feedback:
                st.write(remark)
    else:
        st.error("⚠️ Please enter a password to check its strength.")

   




