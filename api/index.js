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
const db = require("../utils/db.js"); // pooled DB
const auth = require("../middlewares/auth.js");
const authOptional = require("../middlewares/authOptional.js");
const { sendOTP, verifyOTP } = require("../utils/mailer.js");
const { generateAccessToken } = require("../utils/jwt.js");

const serverLink = process.env.BASE_URL;

// ================== MIDDLEWARES ==================

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(passport.initialize());

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

const otpCooldown = new Map();

// ================== ROUTES ==================

app.get("/", (req, res) => res.render("home"));

app.get("/signup", guestOnly, (req, res) => res.render("signup"));

/**
 * VERIFY OTP
 */
app.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;

  try {
    const rows = await db.query(
      "SELECT id FROM users WHERE email=?",
      [email]
    );

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
  } catch (err) {
    console.error(err);
    res.json({ success: false });
  }
});

/**
 * SEND OTP
 */
app.post("/send-otp", async (req, res) => {
  const { email } = req.body;

  const lastSent = otpCooldown.get(email);
  if (lastSent && Date.now() - lastSent < 30000)
    return res.json({ success: false, reason: "cooldown" });

  try {
    const users = await db.query(
      "SELECT id FROM users WHERE email=?",
      [email]
    );

    if (users.length)
      return res.json({ success: false, reason: "user_exists" });

    await sendOTP(email);
    otpCooldown.set(email, Date.now());
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.json({ success: false });
  }
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

  try {
    const hashed = await bcrypt.hash(password, 10);

    await db.query(
      "INSERT INTO users (name,email,password,address) VALUES (?,?,?,?)",
      [name, email, hashed, address || null]
    );

    res.clearCookie("otpToken");
    res.redirect("/login");
  } catch (err) {
    console.error(err);
    res.render("signup", { message: "Signup failed" });
  }
});

/**
 * LOGIN
 */
app.get("/login", guestOnly, (req, res) =>
  res.render("login", { message: null })
);

app.post("/login", async (req, res) => {
  const { email, password, remember } = req.body;

  try {
    const users = await db.query(
      "SELECT * FROM users WHERE email=?",
      [email]
    );

    if (!users.length) return res.redirect("/login");

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
  } catch (err) {
    console.error(err);
    res.redirect("/login");
  }
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

app.get("/auth/google/callback",passport.authenticate("google", { failureRedirect: "/login" }),(req, res) => {
        db.query("SELECT * FROM users WHERE id = ?", [req.user.id], (err, results) => {
            if (err || !results.length) 
                return res.redirect("/login");
            const user = results[0];
            const userData = { id: user.id, email: user.email, name: user.name, avatar: user.avatar || '/images/default-avatar.png',
                google_id: user.google_id, address: user.address,role: user.role
            };
        
            const token = generateAccessToken(userData);
            res.cookie("token", token, { httpOnly: true });
            
            res.redirect("/profile");
        });
    }
);

/**
 * PRODUCTS
 */
app.get("/products", (req, res) => res.render("products"));

app.get("/products/:id", authOptional, async (req, res) => {
  const id = req.params.id;

  try {
    if (req.user) {
      await db.query(
        "INSERT INTO recently_viewed (user_id, product_id) VALUES (?,?)",
        [req.user.id, id]
      );
    }

    const product = await db.query(
      "SELECT * FROM products WHERE id=?",
      [id]
    );

    res.render("product", { product: product[0], user: req.user });
  } catch (err) {
    console.error(err);
    res.status(500).send("Error");
  }
});

/**
 * CART
 */
app.get("/cart", (req, res) =>
  res.json({ working: "is on", timeline: "6 days" })
);

// ================== EXPORT ==================
module.exports = app;
