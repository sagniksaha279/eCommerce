function togglePassword(id) {
    const input = document.getElementById(id);
    if (input) input.type = input.type === "password" ? "text" : "password";
}

let resetInProgress = false;

async function sendResetLink() {
    if (resetInProgress) return;

    const emailInput = document.getElementById("fpEmail");
    const resetBtn = document.getElementById("resetBtn") || document.querySelector("#forgotModal .btn");
    const resetStatus = document.getElementById("resetStatus");

    if (!emailInput) return;
    const email = emailInput.value.trim();

    if (!email) {
        alert("Enter email");
        return;
    }

    if (resetBtn) {
        resetBtn.disabled = true;
        resetBtn.innerText = "Sending...";
    }

    if (resetStatus) {
        resetStatus.style.display = "block";
        resetStatus.style.color = "#0d6efd";
        resetStatus.innerText = "Checking email…";
    }

    resetInProgress = true;

    try {
        const res = await fetch("/forgot-password-link", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email })
        });

        const data = await res.json();

        if (resetStatus) {
            if (data.success && data.exists && !data.reason) {
                resetStatus.style.color = "#198754";
                resetStatus.innerText = "Reset link sent to your email!";
            } else if (data.success && !data.exists) {
                resetStatus.style.color = "#dc3545";
                resetStatus.innerText = "No account found with this email.";
            } else if (data.reason === "google_user") {
                resetStatus.style.color = "#dc3545";
                resetStatus.innerText = "Google accounts manage passwords via Google.";
            } else {
                resetStatus.style.color = "#dc3545";
                resetStatus.innerText = "Unable to send reset link.";
            }
        }

    } catch (err) {
        if (resetStatus) {
            resetStatus.style.color = "#dc3545";
            resetStatus.innerText = "Something went wrong. Try again.";
        }
    }

    setTimeout(() => {
        resetInProgress = false;
        if (resetBtn) {
            resetBtn.disabled = false;
            resetBtn.innerText = "Send Reset Link";
        }
    }, 60000);
}
const googleBtn = document.getElementById("googleLoginBtn");
const googleStatus = document.getElementById("googleLoginStatus");

if (googleBtn) {
    googleBtn.addEventListener("click", (e) => {
        e.preventDefault();

        let seconds = 0;
        googleBtn.classList.add("disabled");
        googleBtn.style.pointerEvents = "none";

        googleStatus.style.display = "block";
        googleStatus.style.color = "#0d6efd";
        googleStatus.innerHTML = `
            <div class="d-flex justify-content-center align-items-center gap-2">
                <span class="spinner-border spinner-border-sm"></span>
                <span>Redirecting to Google… please wait (0s)</span>
            </div>`;

        const timer = setInterval(() => {
            seconds++;
            googleStatus.querySelector("span:last-child").innerText =
                `Redirecting to Google… please wait (${seconds}s)`;
        }, 1000);

        setTimeout(() => {
            clearInterval(timer);
            window.location.href = "/auth/google";
        }, 1500);
    });
}
