const path = require("path");
const bcrypt = require("bcryptjs");
const express = require("express");
const app = express();
const passport = require("passport");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const expressLayouts = require("express-ejs-layouts");
require("dotenv").config();
require("./utils/passport.js");
const jwt = require("jsonwebtoken");
const db = require("./utils/db.js");
const auth = require("./middlewares/auth.js");
const { sendOTP, verifyOTP } = require("./utils/mailer.js");
const authOptional = require("./middlewares/authOptional.js");
const { generateAccessToken, generateRefreshToken } = require("./utils/jwt.js");

const PORT = 3000;
const serverLink = "http://localhost:3000";

//MiddleWares
app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.set("view engine", "ejs");
app.use(expressLayouts);
app.use(session({
    secret: "session_secret",
    resave: false,
    saveUninitialized: false
}));
app.use(cookieParser()); 
const guestOnly = (req, res, next) => {
    const token = req.cookies.token;
    if (token) {
        try {
            jwt.verify(token, process.env.JWT_SECRET);
            return res.redirect("/profile");
        } catch {
            return next();
        }
    }
    next();
};
app.use(authOptional);
app.use((req, res, next) =>{
    if (req.user && !req.user.avatar)
        req.user.avatar = '/images/default-avatar.png';
    next();
});
app.use((req, res, next) => {
    //Cart Count
    res.locals.user = req.user || null;
    res.locals.cartCount = 0; 
    next();
}); 
const otpCooldown = new Map();
app.use(cookieParser());
app.use(passport.initialize());
app.use(passport.session());
app.set("layout", "layouts/boilerplate");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname,"public")));
app.use("/models", express.static(path.join(__dirname, "models")));

//======================ROUTES=====================

app.get("/",(req,res)=>{
    res.render("home.ejs");
});

app.get("/signup", guestOnly, (req,res)=>{
    res.render("signup.ejs");
});


app.post("/signup", async (req, res) => {
    const { name, email, password, address } = req.body;
    if (!req.session.otpVerified || req.session.otpEmail !== email) {
        return res.render("signup", { message: "Please verify OTP first" });
    }

    db.query("SELECT id FROM users WHERE email = ?", [email], async (err, rows) => {
        if (err) {
            console.error("Database error:", err);
            return res.render("signup", { message: "Database error" });
        }
        
        if (rows.length > 0) {
            req.session.otpVerified = false;
            req.session.otpEmail = null;
            return res.render("signup", { message: "Email already registered. Please login." });
        }

        try {
            const hashedPassword = await bcrypt.hash(password, 10);
            db.query("INSERT INTO users (name, email, password, address) VALUES (?, ?, ?, ?)", [name, email, hashedPassword, address || null], (err, result) => {
                if (err) {
                    console.error("Insert error:", err);
                    return res.render("signup", { message: "Registration failed" });
                }
                req.session.otpVerified = false;
                req.session.otpEmail = null;
                res.redirect("/login");
            });
        } catch (error) {
            console.error("Hashing error:", error);
            res.render("signup", { message: "Registration failed" });
        }
    });
});


app.get("/login",guestOnly,(req,res)=>{
    res.render("login", { message: null });
});

app.post("/login", (req, res) => {
    const { email, password, remember } = req.body;

    db.query("SELECT * FROM users WHERE email=?", [email], async (err, result) => {
        if (err || !result.length) return res.redirect("/login");

        const user = result[0];
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.redirect("/login");

        const token = generateAccessToken(user);

        res.cookie("token", token, {
            httpOnly: true,
            secure: false,         
            sameSite: "lax",
            maxAge: remember ? 30 * 24 * 60 * 60 * 1000  : undefined
        });

        res.redirect("/profile");
    });
});


app.get("/logout", (req, res, next) => {
    res.clearCookie("token");
    res.clearCookie("refreshToken");
    req.logout(function(err) {
        if (err) return next(err);
        if (req.session) {
            req.session.destroy(() => {
                return res.redirect("/"); 
            });
        } else {
            return res.redirect("/");
        }
    });
});

app.get("/profile", (req, res) => {
    const token = req.cookies.token;

    if (!token) {
        return res.redirect("/login?message=Please login to view your profile");
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        db.query("SELECT * FROM users WHERE id=?", [decoded.id], (err, users) => {
            if (err || !users.length) {
                res.clearCookie("token");
                return res.redirect("/login?message=Session expired. Please login again.");
            }

            const user = users[0];

            if (!user.avatar) user.avatar = "/images/default-avatar.png";

            db.query(`SELECT p.id, p.name, p.image FROM recently_viewed rv JOIN products p ON rv.product_id = p.id WHERE rv.user_id=? ORDER BY rv.viewed_at DESC LIMIT 5`,[user.id],
                (err, recent) => {
                    user.recent = recent || [];
                    db.query(`SELECT p.id, p.name, p.image FROM wishlist w JOIN products p ON w.product_id = p.id WHERE w.user_id=?`,[user.id],(err, wishlist) => {
                            user.wishlist = wishlist || [];
                            res.render("profile", { user, message: null });
                    });
            });
        });
    } catch (err) {
        res.clearCookie("token"); 
        return res.redirect("/login?message=Session expired. Please login again.");
    }
});


app.post("/update-address", async (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.redirect("/login");

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const { address } = req.body;

        db.query("UPDATE users SET address = ? WHERE id = ?",[address || null, decoded.id],(err, result) => {
                if (err) {
                    console.error("Error updating address:", err);
                    return res.redirect("/profile");
                }
                res.redirect("/profile");
        });
    }catch (err) {
        console.error("JWT verification error:", err);
        res.redirect("/login");
    }
});

app.post("/change-password", async (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.redirect("/login");

    const jwt = require("jsonwebtoken");
    const bcrypt = require("bcryptjs");

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const { currentPassword, newPassword, confirmPassword } = req.body;

        if (newPassword !== confirmPassword)
            return res.redirect("/profile");

        db.query("SELECT * FROM users WHERE id=?",[decoded.id],async (err, users) => {
                if (err || !users.length) return res.redirect("/profile");
                const user = users[0];
                if (user.google_id) return res.redirect("/profile");
                const match = await bcrypt.compare(currentPassword, user.password);
                if (!match) return res.redirect("/profile");

                const hashed = await bcrypt.hash(newPassword, 10);

                db.query("UPDATE users SET password=? WHERE id=?",[hashed, user.id],() => res.redirect("/profile"));
        });
    }catch {
        res.redirect("/login");
    }
});

app.post("/forgot-password-link", (req, res) => {
    const { email } = req.body;

    db.query("SELECT * FROM users WHERE email=?", [email], async (err, users) => {
        if (err) return res.json({ success: false, exists: false });

        if (!users.length)
            return res.json({ success: true, exists: false });

        const user = users[0];

        if (user.google_id)
            return res.json({ success: true, exists: true, reason: "google_user" });

        const token = jwt.sign({ email },process.env.JWT_SECRET,{ expiresIn: "15m" });

        const link = `${serverLink}/reset-password/${token}`;
        await sendOTP(email, link);

        res.json({ success: true, exists: true });
    });
});


app.get("/reset-password/:token", (req, res) => {
    try {
        jwt.verify(req.params.token, process.env.JWT_SECRET);
        res.render("reset-password", { token: req.params.token });
    } catch {
        res.send("Invalid or expired link");
    }
});

app.post("/reset-password", async (req, res) => {
    const { token, password } = req.body;
    const { email } = jwt.verify(token, process.env.JWT_SECRET);

    const hashed = await bcrypt.hash(password, 10);
    db.query("UPDATE users SET password=? WHERE email=?", [hashed, email]);
    res.redirect("/login");
});

//===========OTP==========
app.post("/send-otp", async (req, res) => {
    const { email } = req.body;
    const lastSent = otpCooldown.get(email);

    if (lastSent && Date.now() - lastSent < 30000) 
        return res.json({ success: false, reason: "cooldown" });

    db.query("SELECT * FROM users WHERE email=?", [email], async (err, users) => {
        if (err) {
            console.error("Database error:", err);
            return res.json({ success: false, reason: "error" });
        }
        if (users.length > 0) {
            if (users[0].google_id) {
                return res.json({ success: false, reason: "google_user" });
            }
            return res.json({ 
                success: false, 
                reason: "user_exists",
                message: "Email already registered. Please login."
            });
        }
        try {
            await sendOTP(email);
            otpCooldown.set(email, Date.now());
            res.json({ success: true });
        } catch (error) {
            console.error("Send OTP error:", error);
            res.json({ success: false, reason: "email_error" });
        }
    });
});

app.post("/verify-otp", (req, res) => {
    const { email, otp } = req.body;
    db.query("SELECT id FROM users WHERE email = ?", [email], (err, rows) => {
        if (err) {
            return res.json({ success: false, message: "Database error" });
        }
        
        if (rows.length > 0) {
            return res.json({ 
                success: false, 
                reason: "user_exists",
                message: "Email already registered. Please login."
            });
        }
        const valid = verifyOTP(email, otp);
        if (!valid) {
            return res.json({ 
                success: false, 
                message: "Invalid OTP" 
            });
        }
        req.session.otpVerified = true;
        req.session.otpEmail = email;
        res.json({ success: true });
    });
});

app.get("/auth/google",passport.authenticate("google", { scope: ["profile", "email"] }));

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

app.get("/products",(req,res)=>{
    res.render("products.ejs");
});

app.get("/products/:id", authOptional, (req, res) => {
    const productId = req.params.id;

    if (req.user) {
        db.query(
            "INSERT INTO recently_viewed (user_id, product_id) VALUES (?, ?)",
            [req.user.id, productId]
        );
    }

    db.query("SELECT * FROM products WHERE id=?", [productId], (err, product) => {
        res.render("product", {
            product: product[0],
            user: req.user
        });
    });
});

app.get("/cart",(req,res)=>{
    res.json({
        working : "is on",
        timeline : "6 days from here",
        tensionLu : "Nahin re tera bhai hain naa" 
    });
});

// app.listen(PORT,()=>{
//     console.log(`Server is running on port:${PORT}`);
// });
module.exports = app;
