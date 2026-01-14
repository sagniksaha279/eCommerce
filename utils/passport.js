const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const db = require("./db");

const server = process.env.BASE_URL || "http://localhost:3000";

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${server}/auth/google/callback`,
      proxy: process.env.NODE_ENV === 'production' // Trust proxy in production
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails[0].value;
        const name = profile.displayName;
        const googleId = profile.id;
        const googleAvatar = profile.photos && profile.photos.length 
          ? profile.photos[0].value.replace('s96-c', 's400-c') // Get higher resolution
          : null;
        
        // Check if user exists by google_id OR email
        const users = await db.query(
          "SELECT * FROM users WHERE google_id = ? OR email = ?",
          [googleId, email]
        );

        let user = users[0];

        if (user) {
          // Update existing user with Google info if missing
          if (!user.google_id) {
            await db.query(
              "UPDATE users SET google_id = ? WHERE id = ?",
              [googleId, user.id]
            );
            user.google_id = googleId;
          }
          
          // Update avatar if from Google and user doesn't have one
          if (googleAvatar && (!user.avatar || user.avatar.includes('default-avatar'))) {
            await db.query(
              "UPDATE users SET avatar = ? WHERE id = ?",
              [googleAvatar, user.id]
            );
            user.avatar = googleAvatar;
          }
          
          return done(null, user);
        } else {
          // Create new user
          const result = await db.query(
            `INSERT INTO users (name, email, google_id, avatar, email_verified) 
             VALUES (?, ?, ?, ?, ?)`,
            [name, email, googleId, googleAvatar || '/images/default-avatar.png', 1]
          );
          
          user = {
            id: result.insertId,
            name,
            email,
            google_id: googleId,
            avatar: googleAvatar || '/images/default-avatar.png',
            email_verified: 1,
            role: 'user',
            created_at: new Date()
          };
          
          return done(null, user);
        }
      } catch (err) {
        console.error("Passport Google strategy error:", err);
        return done(err, null);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const users = await db.query(
      "SELECT id, name, email, avatar, google_id, address, role FROM users WHERE id = ?",
      [id]
    );
    
    if (!users.length) {
      return done(null, false);
    }
    
    const user = users[0];
    // Ensure avatar has a value
    if (!user.avatar) {
      user.avatar = '/images/default-avatar.png';
    }
    
    done(null, user);
  } catch (err) {
    console.error("Passport deserialize error:", err);
    done(err, null);
  }
});

module.exports = passport;
