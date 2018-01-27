const express = require("express");
const sequelize = require("sequelize");
const sqlite = require("sqlite3");
const passport = require("passport");
const FacebookStrategy = require("passport-facebook").Strategy;

const sequelize = new Sequelize("Music", "michael", null, {
    host: "localhost",
    dialect: "sqlite",
    storage: "./Chinook_Sqlite_AutoIncrementPKs.sqlite"
  });

  const User = sequelize.define(
    "User",
    {
      userId: {
        type: Sequelize.STRING,
        autoIncrement: true,
        primaryKey: true
      },
      authId: type: Sequelize.STRING,
      name: Sequelize.STRING,
      email: Sequelize.STRING,
      role: Sequelize.STRING
    },
    {
      freezeTableName: true
    }
  );

  passport.serializeUser((user, done) => {
    done(null, user._id)
});

passport.deserializeUser((id, done) => {
    User.findAll({ where: {
        userId: id
    }}, (err, user) => {
        if(err || !user ) return done(err, null);
        done(null, user);
    });
});

function(app, option) {
    // if success and failure redirects aren't specific, set some reasonable defaults
    if(!options.successRedirect)
        options.successRedirect = '/account';
    if(!options.failureRedirect)
        options.failureRedirect = '/login';

    return {
        init: function() { /* TODO */ },
        registerRoutes: function() { /* TODO */ }
    }
};

init: function() {
    var env = app.get("env");
    var config = options.providers;

    //configure Facebook strategy
    passport.use(
      new FacebookStrategy(
        {
          clientId: config.facebook[env].appId,
          clientSecret: config.facebook[env].appSecret,
          callbackURL: "/auth/facebook/callback"
        },
        function(accessToken, refreshToken, profile, done) {
          const authId = "facebook:" + profile.id;
          User.findOne({ where: { authId: authId } }, function(err, user) {
            if (err) return done(err, null);
            if (user) return done(null, user);
            User.create({
              authId: authId,
              name: profile.displayName,
              role: "user"
            });
          });
        }
      )
    );

    app.use(passport.initialize());
    app.use(passport.session());
  }

  registerRoutes: function() {
    // register Facebook routes
    app.get("/auth/facebook", function(req, res, next) {
      passport.authenticate("facebook", {
        callbackURL:
          "auth/facebook/callback?redirect=" +
          encodeURIComponent(req.query.redirect)
      })(req, res, next);
    });

    app.get(
      "/auth/facebook/callback",
      passport.authenticate(
        "facebook",
        { failureRedirect: options.failureRedirect },
        function(req, res) {
          // we only get here on successful authentication
          res.redirect(303, req.query.redirect || options.successRedirect);
        }
      )
    );
  }



  app.get('/account', (req, res) => {
    if(!req.session.passport.user)
      return res.redirect(303, '/unauthorized');
    res.render('account');
  })

  function adminOnly(req, res) {
    const user = req.session.passport.user;
    if(user && req.role === 'admin') return next();
    res.redirect(303, '/unauthorized');
  }