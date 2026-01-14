const jwt = require("jsonwebtoken");
const db = require("../utils/db");

module.exports = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.redirect("/login");

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        db.query("SELECT * FROM users WHERE id=?", [decoded.id], (err, result) => {
            if (err || !result.length) return res.redirect("/login");
            req.user = result[0];
            next();
        });

    } catch (err) {
        return res.redirect("/login");
    }
};
