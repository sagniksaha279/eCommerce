const path = require("path");
const bcrypt = require("bcryptjs");
const express = require("express");
const app = express();
const passport = require("passport");
const cookieParser = require("cookie-parser");
const session = require("express-session"); // Added
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

// Session configuration (REQUIRED for Passport)
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

app.use(passport.initialize());
app.use(passport.session()); // Added for persistent login sessions

app.set("view engine", "ejs");
app.use(expressLayouts);
app.set("layout", "layouts/boilerplate");

app.set("views", path.join(process.cwd(), "views"));
app.use(express.static(path.join(process.cwd(), "public")));
app.use("/models", express.static(path.join(process.cwd(), "models")));

app.use(authOptional);

app.use((req, res, next) => {
  if (req.user && !req.user.avatar) {
    req.user.avatar = "/images/default-avatar.png";
  }
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
  } catch (err) {
    // Invalid token - clear it and continue
    res.clearCookie("token");
    next();
  }
};

// OTP cooldown with cleanup
const otpCooldown = new Map();

// Clean up old entries every hour
setInterval(() => {
  const now = Date.now();
  for (const [email, timestamp] of otpCooldown.entries()) {
    if (now - timestamp > 3600000) { // 1 hour
      otpCooldown.delete(email);
    }
  }
}, 3600000);

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

    if (rows.length) {
      return res.status(400).json({ 
        success: false, 
        reason: "user_exists",
        message: "User already exists with this email" 
      });
    }

    const valid = verifyOTP(email, otp);
    if (!valid) {
      return res.status(400).json({ 
        success: false, 
        message: "Invalid or expired OTP" 
      });
    }

    const otpToken = jwt.sign(
      { email, purpose: "signup" },
      process.env.JWT_SECRET,
      { expiresIn: "10m" }
    );

    res.cookie("otpToken", otpToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: "lax",
      maxAge: 10 * 60 * 1000 // 10 minutes
    });

    res.json({ success: true });
  } catch (err) {
    console.error("OTP verification error:", err);
    res.status(500).json({ 
      success: false, 
      message: "Server error during OTP verification" 
    });
  }
});

/**
 * SEND OTP
 */
app.post("/send-otp", async (req, res) => {
  const { email } = req.body;

  // Validate email
  if (!email || !email.includes('@')) {
    return res.status(400).json({ 
      success: false, 
      reason: "invalid_email" 
    });
  }

  const lastSent = otpCooldown.get(email);
  if (lastSent && Date.now() - lastSent < 30000) {
    return res.status(429).json({ 
      success: false, 
      reason: "cooldown",
      retryAfter: Math.ceil((30000 - (Date.now() - lastSent)) / 1000)
    });
  }

  try {
    const users = await db.query(
      "SELECT id FROM users WHERE email=?",
      [email]
    );

    if (users.length) {
      return res.status(400).json({ 
        success: false, 
        reason: "user_exists" 
      });
    }

    await sendOTP(email);
    otpCooldown.set(email, Date.now());
    
    res.json({ 
      success: true,
      message: "OTP sent successfully" 
    });
  } catch (err) {
    console.error("Send OTP error:", err);
    res.status(500).json({ 
      success: false, 
      message: "Failed to send OTP" 
    });
  }
});

/**
 * SIGNUP
 */
app.post("/signup", async (req, res) => {
  const otpToken = req.cookies.otpToken;
  
  if (!otpToken) {
    return res.render("signup", { 
      message: "OTP verification required. Please verify your email first." 
    });
  }

  let decoded;
  try {
    decoded = jwt.verify(otpToken, process.env.JWT_SECRET);
    if (decoded.purpose !== "signup") {
      throw new Error("Invalid token purpose");
    }
  } catch (err) {
    res.clearCookie("otpToken");
    return res.render("signup", { 
      message: "OTP session expired. Please request a new OTP." 
    });
  }

  const { name, email, password, address } = req.body;
  
  // Validate input
  if (!name || !email || !password) {
    return res.render("signup", { 
      message: "Name, email, and password are required" 
    });
  }

  if (decoded.email !== email) {
    return res.render("signup", { 
      message: "Email mismatch with OTP verification" 
    });
  }

  try {
    const hashed = await bcrypt.hash(password, 12);

    await db.query(
      "INSERT INTO users (name, email, password, address) VALUES (?, ?, ?, ?)",
      [name, email, hashed, address || null]
    );

    res.clearCookie("otpToken");
    res.redirect("/login?message=signup_success");
  } catch (err) {
    console.error("Signup error:", err);
    
    let message = "Signup failed";
    if (err.code === 'ER_DUP_ENTRY') {
      message = "Email already exists";
    }
    
    res.render("signup", { message });
  }
});

/**
 * LOGIN
 */
app.get("/login", guestOnly, (req, res) => {
  const message = req.query.message || null;
  res.render("login", { message });
});

app.post("/login", async (req, res) => {
  const { email, password, remember } = req.body;

  try {
    const users = await db.query(
      "SELECT * FROM users WHERE email=?",
      [email]
    );

    if (!users.length) {
      return res.render("login", { 
        message: "Invalid email or password" 
      });
    }

    const user = users[0];
    const match = await bcrypt.compare(password, user.password);
    
    if (!match) {
      return res.render("login", { 
        message: "Invalid email or password" 
      });
    }

    const token = generateAccessToken(user);

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: "lax",
      maxAge: remember ? 30 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000
    });

    res.redirect("/profile");
  } catch (err) {
    console.error("Login error:", err);
    res.render("login", { 
      message: "Login failed. Please try again." 
    });
  }
});

/**
 * LOGOUT
 */
app.get("/logout", (req, res) => {
  res.clearCookie("token");
  req.logout((err) => {
    if (err) console.error("Logout error:", err);
    res.redirect("/");
  });
});

/**
 * PROFILE
 */
app.get("/profile", auth, async (req, res) => {
  try {
    // Refresh user data from database
    const [user] = await db.query(
      "SELECT * FROM users WHERE id = ?",
      [req.user.id]
    );
    
    if (!user) {
      res.clearCookie("token");
      return res.redirect("/login");
    }
    
    res.render("profile", { 
      user: { 
        ...user,
        avatar: user.avatar || "/images/default-avatar.png"
      }, 
      message: null 
    });
  } catch (err) {
    console.error("Profile error:", err);
    res.status(500).render("error", { message: "Failed to load profile" });
  }
});

/**
 * GOOGLE AUTH
 */
app.get(
  "/auth/google",
  passport.authenticate("google", { 
    scope: ["profile", "email"],
    prompt: "select_account" // Optional: gives user account selection
  })
);

app.get("/auth/google/callback",
  passport.authenticate("google", { 
    failureRedirect: "/login",
    failureMessage: true 
  }),
  async (req, res) => {
    try {
      // User is authenticated by passport, req.user is set
      const userData = {
        id: req.user.id,
        email: req.user.email,
        name: req.user.name,
        avatar: req.user.avatar || '/images/default-avatar.png',
        google_id: req.user.google_id,
        address: req.user.address,
        role: req.user.role
      };

      const token = generateAccessToken(userData);
      
      res.cookie("token", token, { 
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: "lax",
        maxAge: 24 * 60 * 60 * 1000
      });
      
      res.redirect("/profile");
    } catch (err) {
      console.error("Google callback error:", err);
      res.redirect("/login?message=google_auth_failed");
    }
  }
);

/**
 * PRODUCTS
 */
app.get("/products", async (req, res) => {
  try {
    const products = await db.query(
      "SELECT * FROM products WHERE available = 1 ORDER BY created_at DESC"
    );
    res.render("products", { products, user: req.user });
  } catch (err) {
    console.error("Products error:", err);
    res.status(500).render("error", { message: "Failed to load products" });
  }
});

app.get("/products/:id", authOptional, async (req, res) => {
  const id = req.params.id;

  try {
    // Get product first
    const products = await db.query(
      "SELECT * FROM products WHERE id=? AND available = 1",
      [id]
    );

    if (!products.length) {
      return res.status(404).render("error", { 
        message: "Product not found" 
      });
    }

    const product = products[0];

    // Add to recently viewed if user is logged in
    if (req.user) {
      try {
        // Remove old entries to keep only recent ones
        await db.query(
          `DELETE FROM recently_viewed 
           WHERE user_id = ? AND product_id = ? 
           OR id IN (
             SELECT id FROM (
               SELECT id FROM recently_viewed 
               WHERE user_id = ? 
               ORDER BY viewed_at DESC 
               LIMIT 100 OFFSET 20
             ) AS old
           )`,
          [req.user.id, id, req.user.id]
        );
        
        await db.query(
          "INSERT INTO recently_viewed (user_id, product_id) VALUES (?,?)",
          [req.user.id, id]
        );
      } catch (err) {
        console.error("Recently viewed error:", err);
        // Don't fail the whole request if this fails
      }
    }

    res.render("product", { 
      product, 
      user: req.user 
    });
  } catch (err) {
    console.error("Product detail error:", err);
    res.status(500).render("error", { 
      message: "Failed to load product details" 
    });
  }
});

/**
 * CART
 */
app.get("/cart", auth, async (req, res) => {
  try {
    const cartItems = await db.query(
      `SELECT c.*, p.name, p.price, p.image, p.available 
       FROM cart c 
       JOIN products p ON c.product_id = p.id 
       WHERE c.user_id = ? AND p.available = 1`,
      [req.user.id]
    );
    
    const total = cartItems.reduce((sum, item) => 
      sum + (item.price * item.quantity), 0);
    
    res.render("cart", {
      cartItems,
      total: total.toFixed(2),
      user: req.user
    });
  } catch (err) {
    console.error("Cart error:", err);
    res.status(500).render("error", { 
      message: "Failed to load cart" 
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).render("error", { 
    message: "Something went wrong. Please try again later." 
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).render("error", { 
    message: "Page not found" 
  });
});

// ================== EXPORT ==================
module.exports = app;
