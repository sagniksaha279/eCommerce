const jwt = require("jsonwebtoken");
const db = require("../utils/db.js");

module.exports = async (req, res, next) => {
    if (req.isAuthenticated && req.isAuthenticated()) {
        req.user = req.user || null;

        if (req.user) {
            if (!req.user.avatar || req.user.avatar === 'null') {
                if (req.user.google_id && req.user.google_avatar) {
                    req.user.avatar = req.user.google_avatar;
                } else {
                    req.user.avatar = '/images/default-avatar.png';
                }
            }
        }

        return next();
    }

    const token = req.cookies?.token;
    if (!token) {
        req.user = null;
        return next();
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        db.query("SELECT * FROM users WHERE id = ?", [decoded.id], (err, results) => {
            if (err || !results.length) {
                req.user = null;
                return next();
            }

            const user = results[0];

            if (!user.avatar || user.avatar === 'null') {
                if (user.google_id && user.google_avatar) {
                    user.avatar = user.google_avatar;
                } else {
                    user.avatar = '/images/default-avatar.png';
                }
            }

            req.user = {
                ...user,
                iat: decoded.iat,
                exp: decoded.exp
            };

            next();
        });
    } catch (err) {
        req.user = null;
        next();
    }
};
