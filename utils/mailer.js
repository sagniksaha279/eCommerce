const nodemailer = require("nodemailer");

const otpStore = new Map();  

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function sendOTP(email, link) {
  if (link) {
    await transporter.sendMail({
      from: `"eAuto" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Reset Your eAuto Password",
      text: `Click this link to reset your password: ${link}`,
    });
    return;
  }

  const otp = generateOTP();
  const expiresAt = Date.now() + 5 * 60 * 1000;

  otpStore.set(email, { otp, expiresAt });

  await transporter.sendMail({
    from: `"eAuto" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: "Your eAuto OTP",
    text: `Thank You for registering with eAuto. Your OTP is ${otp}. It will expire in 5 minutes.`,
  });

  return otp;
}

function verifyOTP(email, otp) {
  const data = otpStore.get(email);
  if (!data) return false;

  if (Date.now() > data.expiresAt) {
    otpStore.delete(email);
    return false;
  }

  if (data.otp !== otp) return false;

  otpStore.delete(email);
  return true;
}

module.exports = { sendOTP, verifyOTP };