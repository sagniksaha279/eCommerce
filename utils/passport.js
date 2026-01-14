// utils/passport.js
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const db = require("./db");

const server = "https://e-commerce-279.vercel.app";

passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: `${server}/auth/google/callback`
        },
        (accessToken, refreshToken, profile, done) => {
            const email = profile.emails[0].value;
            const name = profile.displayName;
            const googleId = profile.id;

            // Get Google avatar or use default
            const googleAvatar = profile.photos && profile.photos.length ? profile.photos[0].value : null;
            const avatar = googleAvatar || '/images/default-avatar.png';

            db.query("SELECT * FROM users WHERE email=?", [email], (err, result) => {
                if (err) return done(err);
                
                if (result.length) {
                    // Update user with Google avatar if they don't have one yet
                    const existingUser = result[0];
                    if ((!existingUser.avatar || existingUser.avatar === '/images/default-avatar.png') && googleAvatar) {
                        db.query("UPDATE users SET avatar=? WHERE id=?", 
                            [googleAvatar, existingUser.id],
                            (updateErr) => {
                                if (updateErr) return done(updateErr);
                                done(null, { 
                                    ...existingUser, 
                                    avatar: googleAvatar 
                                });
                            }
                        );
                    } else {
                        done(null, existingUser);
                    }
                } else {
                    // New user - insert with avatar
                    db.query(
                        "INSERT INTO users (name, email, google_id, avatar) VALUES (?, ?, ?, ?)",
                        [name, email, googleId, avatar],
                        (err, res) => {
                            if (err) return done(err);
                            done(null, { 
                                id: res.insertId, 
                                name, 
                                email, 
                                google_id: googleId, 
                                avatar 
                            });
                        }
                    );
                }
            });
        }
    )
);

passport.serializeUser((user, done) => done(null, user.id));

passport.deserializeUser((id, done) => {
    db.query("SELECT * FROM users WHERE id=?", [id], (err, result) => {
        if (err) return done(err);
        if (!result.length) return done(null, false);
        
        const user = result[0];
        
        // CRITICAL FIX: Ensure avatar always has a value
        if (!user.avatar) {
            user.avatar = '/images/default-avatar.png';
        }
        
        done(null, user);
    });
});
