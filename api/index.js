const path = require("path");
const bcrypt = require("bcryptjs");
const express = require("express");
const app = express();
const passport = require("passport");
const cookieParser = require("cookie-parser");
const expressLayouts = require("express-ejs-layouts");
require("dotenv").config();

require("../utils/passport.js");

const jwt = require("jsonwebtoken");
const db = require("../utils/db.js");
const auth = require("../middlewares/auth.js");
const authOptional = require("../middlewares/authOptional.js");
const { sendOTP, verifyOTP } = require("../utils/mailer.js");
const { generateAccessToken } = require("../utils/jwt.js");

const serverLink = process.env.BASE_URL;

// ================== MIDDLEWARES ==================

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(passport.initialize()); // ❌ no session()

app.set("view engine", "ejs");
app.use(expressLayouts);
app.set("layout", "layouts/boilerplate");

app.set("views", path.join(process.cwd(), "views"));
app.use(express.static(path.join(process.cwd(), "public")));
app.use("/models", express.static(path.join(process.cwd(), "models")));

app.use(authOptional);

app.use((req, res, next) => {
  if (req.user && !req.user.avatar)
    req.user.avatar = "/images/default-avatar.png";

  res.locals.user = req.user || null;
  res.locals.cartCount = 0;
  next();
});

// ================== HELPERS ==================

const guestOnly = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return next();
  try {
    jwt.verify(token, process.env.JWT_SECRET);
    return res.redirect("/profile");
  } catch {
    next();
  }
};

// OTP cooldown (serverless-safe enough for short time)
const otpCooldown = new Map();

// ================== ROUTES ==================

app.get("/", (req, res) => res.render("home"));

app.get("/signup", guestOnly, (req, res) => res.render("signup"));

/**
 * OTP VERIFY → ISSUE TEMP TOKEN
 */
app.post("/verify-otp", (req, res) => {
  const { email, otp } = req.body;

  db.query("SELECT id FROM users WHERE email=?", [email], (err, rows) => {
    if (err) return res.json({ success: false });

    if (rows.length)
      return res.json({ success: false, reason: "user_exists" });

    const valid = verifyOTP(email, otp);
    if (!valid) return res.json({ success: false });

    const otpToken = jwt.sign(
      { email, purpose: "signup" },
      process.env.JWT_SECRET,
      { expiresIn: "10m" }
    );

    res.cookie("otpToken", otpToken, {
      httpOnly: true,
      secure: true,
      sameSite: "lax"
    });

    res.json({ success: true });
  });
});

/**
 * SEND OTP
 */
app.post("/send-otp", async (req, res) => {
  const { email } = req.body;

  const lastSent = otpCooldown.get(email);
  if (lastSent && Date.now() - lastSent < 30000)
    return res.json({ success: false, reason: "cooldown" });

  db.query("SELECT * FROM users WHERE email=?", [email], async (err, users) => {
    if (err) return res.json({ success: false });

    if (users.length)
      return res.json({ success: false, reason: "user_exists" });

    await sendOTP(email);
    otpCooldown.set(email, Date.now());
    res.json({ success: true });
  });
});

/**
 * SIGNUP
 */
app.post("/signup", async (req, res) => {
  const otpToken = req.cookies.otpToken;
  if (!otpToken) return res.render("signup", { message: "Verify OTP first" });

  let decoded;
  try {
    decoded = jwt.verify(otpToken, process.env.JWT_SECRET);
  } catch {
    return res.render("signup", { message: "OTP expired" });
  }

  const { name, email, password, address } = req.body;
  if (decoded.email !== email)
    return res.render("signup", { message: "OTP mismatch" });

  const hashed = await bcrypt.hash(password, 10);

  db.query(
    "INSERT INTO users (name,email,password,address) VALUES (?,?,?,?)",
    [name, email, hashed, address || null],
    () => {
      res.clearCookie("otpToken");
      res.redirect("/login");
    }
  );
});

/**
 * LOGIN
 */
app.get("/login", guestOnly, (req, res) =>
  res.render("login", { message: null })
);

app.post("/login", (req, res) => {
  const { email, password, remember } = req.body;

  db.query("SELECT * FROM users WHERE email=?", [email], async (err, users) => {
    if (err || !users.length) return res.redirect("/login");

    const user = users[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.redirect("/login");

    const token = generateAccessToken(user);

    res.cookie("token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      maxAge: remember ? 30 * 24 * 60 * 60 * 1000 : undefined
    });

    res.redirect("/profile");
  });
});

/**
 * LOGOUT
 */
app.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/");
});

/**
 * PROFILE
 */
app.get("/profile", auth, (req, res) =>
  res.render("profile", { user: req.user, message: null })
);

/**
 * GOOGLE AUTH
 */
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { session: false, failureRedirect: "/login" }),
  (req, res) => {
    const token = generateAccessToken(req.user);
    res.cookie("token", token, { httpOnly: true, secure: true });
    res.redirect("/profile");
  }
);

/**
 * PRODUCTS
 */
app.get("/products", (req, res) => res.render("products"));

app.get("/products/:id", authOptional, (req, res) => {
  const id = req.params.id;

  if (req.user) {
    db.query(
      "INSERT INTO recently_viewed (user_id, product_id) VALUES (?,?)",
      [req.user.id, id]
    );
  }

  db.query("SELECT * FROM products WHERE id=?", [id], (err, product) => {
    res.render("product", { product: product[0], user: req.user });
  });
});

/**
 * CART
 */
app.get("/cart", (req, res) =>
  res.json({ working: "is on", timeline: "6 days" })
);

// ================== EXPORT ==================
module.exports = app;
