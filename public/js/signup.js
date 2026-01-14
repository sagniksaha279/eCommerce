function togglePassword(id) {
    const i = document.getElementById(id);
    i.type = i.type === "password" ? "text" : "password";
}

const emailInput = document.getElementById("emailInput");
const sendOtpBtn = document.getElementById("sendOtpBtn");
const verifyOtpBtn = document.getElementById("verifyOtpBtn");
const otpBox = document.getElementById("otpBox");
const otpInput = document.getElementById("otpInput");
const otpStatus = document.getElementById("otpStatus");
const restFields = document.getElementById("restFields");

let seconds = 0;
let timer;
let otpSent = false;

function updateSendButton() {
    if (seconds > 0) {
        sendOtpBtn.innerText = `Resend OTP (${30 - seconds}s)`;
        sendOtpBtn.disabled = true;
    } else {
        sendOtpBtn.innerText = otpSent ? "Resend OTP" : "Send OTP";
        sendOtpBtn.disabled = false;
    }
}

sendOtpBtn.onclick = async () => {
    if (sendOtpBtn.disabled) return;

    const email = emailInput.value.trim();
    if (!email) {
        otpStatus.style.display = "block";
        otpStatus.innerText = "Please enter email";
        otpStatus.style.color = "#dc3545";
        return;
    }

    sendOtpBtn.disabled = true;
    sendOtpBtn.innerText = "Sending...";
    otpStatus.style.display = "block";
    otpStatus.innerText = "Sending OTP...";
    otpStatus.style.color = "";

    const res = await fetch("/send-otp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ email })
    });

    const data = await res.json();

    if (!data.success) {
        otpStatus.style.color = "#dc3545";

        if (data.reason === "user_exists") {
            otpStatus.innerText = "Email already registered. Redirecting to login...";
            setTimeout(() => window.location.href = "/login", 2000);
        } else if (data.reason === "cooldown") {
            otpStatus.innerText = "Please wait 30 seconds before requesting again";
            sendOtpBtn.disabled = false;
            sendOtpBtn.innerText = "Send OTP";
        } else {
            otpStatus.innerText = "Failed to send OTP. Try again.";
            sendOtpBtn.disabled = false;
            sendOtpBtn.innerText = "Send OTP";
        }
        return;
    }

    emailInput.readOnly = true;
    otpSent = true;
    otpBox.style.display = "block";
    verifyOtpBtn.style.display = "block";
    otpStatus.innerText = "OTP sent. Waiting... 0s";
    otpStatus.style.color = "#198754";

    seconds = 0;
    clearInterval(timer);
    timer = setInterval(() => {
        seconds++;
        otpStatus.innerText = `OTP sent. Waiting... ${seconds}s`;
        updateSendButton();

        if (seconds >= 30) {
            clearInterval(timer);
            seconds = 0;
            updateSendButton();
            otpStatus.innerText = "OTP expired. Click Resend";
            otpStatus.style.color = "#dc3545";
        }
    }, 1000);

    updateSendButton();
};

verifyOtpBtn.onclick = async () => {
    if (verifyOtpBtn.disabled) return;

    const email = emailInput.value.trim();
    const otp = otpInput.value.trim();

    if (!otp) {
        otpStatus.innerText = "Please enter OTP";
        otpStatus.style.color = "#dc3545";
        return;
    }

    verifyOtpBtn.disabled = true;
    verifyOtpBtn.innerText = "Verifying...";

    const res = await fetch("/verify-otp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ email, otp })
    });

    const data = await res.json();

    if (!data.success) {
        otpStatus.style.color = "#dc3545";

        if (data.reason === "user_exists") {
            otpStatus.innerText = data.message || "Email already registered. Redirecting to login...";
            setTimeout(() => window.location.href = "/login", 2000);
        } else {
            otpStatus.innerText = data.message || "Invalid OTP. Try again.";
            verifyOtpBtn.disabled = false;
            verifyOtpBtn.innerText = "Verify OTP";
        }
        return;
    }

    clearInterval(timer);
    otpStatus.innerText = "OTP verified successfully!";
    otpStatus.style.color = "#198754";
    verifyOtpBtn.innerText = "Verified ✓";
    restFields.style.display = "block";
    sendOtpBtn.disabled = true;
    sendOtpBtn.innerText = "OTP Verified";
};
