var passport = require('passport');

exports.callback = function (email, password, done) {
    exports.User.all({
        email: email
    }, function (err, users) {
        if (err) {
            return done(err);
        }
        if (!users || users.length === 0) {
            return done(err, false);
        }
        var user = users[0];
        if (!exports.User.verifyPassword(password, user.password)) {
          return done(err, false);
        }
        return done(err, user);
    });
};

exports.init = function (conf, app) {
    var Strategy = require('passport-local').Strategy;
    passport.use(new Strategy({
        usernameField: conf.usernameField || 'email'
    }, exports.callback));

    app.post('/login', passport.authenticate('local', {
        failureRedirect: '/login',
        failureFlash: true
    }), exports.redirectOnSuccess);

};

