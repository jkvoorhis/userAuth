var express = require('express'),
    exphbs  = require('express3-handlebars'),
    passport = require('passport'),
    LocalStrategy = require('passport-local'),
    TwitterStrategy = require('passport-twitter'),
    GoolgeStrategy = require('passport-google'),
    FacebookStrategy = require('passport-facebook'),
    bcrypt = require('bcryptjs'),
    Q = require('q'),
    config = require('./config'), //config file contains all tokens and other private info
    db = require('orchestrate')(config.db); //config.db holds Orchestrate token

var app = express();

// Passport session setup.
//   To support persistent login sessions, Passport needs to be able to
//   serialize users into and deserialize users out of the session.  Typically,
//   this will be as simple as storing the user ID when serializing, and finding
//   the user by ID when deserializing.  However, since this example does not
//   have a database of user records, the complete GitHub profile is serialized
//   and deserialized.
passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(obj, done) {
  done(null, obj);
});


//function to put a local user in DB when they register
function localReg (username, password) {
  var deferred = Q.defer();
  var hash = bcrypt.hashSync(password, 8);
  var user = {
    "username": username,
    "password": hash,
    "avatar": "http://placepuppy.it/images/homepage/Beagle_puppy_6_weeks.JPG"
  }
  db.put('local-users', username, user)
  .then(function () {
    console.log("USER: " + user);
    deferred.resolve(user);
  })
  .fail(function (err) {
    console.log("PUT FAIL:" + err.body);
    deferred.resolve(err);
  });
  return deferred.promise;
};

function localAuth (username, password) {
  var deferred = Q.defer();

  db.get('local-users', username)
  .then(function (result){
    console.log("FOUND USER");
    var hash = result.body.password;
    console.log(hash);
    console.log(bcrypt.compareSync(password, hash));
    if (bcrypt.compareSync(password, hash)) {
      deferred.resolve(result.body);
    } else {
      deferred.resolve("Passwords did not match");
    }
  }).fail(function (err){
    console.log(err.body);
    deferred.resolve(err.body);
  });

  return deferred.promise;
  //check if user exists
    //if user exists check if passwords match (use bcrypt.compareSync(password, hash); // true where 'hash' is password in DB)
      //if password matches take into website
  //if user doesn't exist or password doesn't match tell them it failed
}

// Use the LocalStrategy within Passport to login users.
//NEED TO ADD FUNCTIONALITY TO SEE IF USER ALREADY EXISTS BEFORE CREATING
passport.use('local-signin', new LocalStrategy(
  function(username, password, done) {
    localAuth(username, password)
    .then(function (user) {
      console.log("LOGGED IN AS: " + user.username);
      done(null, user);
    })
    .fail(function (err){
      console.log(err.body);
    });
  }
));

// Use the LocalStrategy within Passport to Register/"signup" users.
//NEED TO ADD FUNCTIONALITY TO SEE IF USER ALREADY EXISTS BEFORE CREATING
passport.use('local-signup', new LocalStrategy(
  function(username, password, done) {
    localReg(username, password)
    .then(function (user) {
      console.log(user);
      done(null, user);
    })
    .fail(function (err){
      console.log(err.body);
    });
  }
));

// Simple route middleware to ensure user is authenticated.
//   Use this route middleware on any resource that needs to be protected.  If
//   the request is authenticated (typically via a persistent login session),
//   the request will proceed.  Otherwise, the user will be redirected to the
//   login page.
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) { return next(); }
  req.session.error = 'Please sign in!';
  res.redirect('/signin');
}



// configure Express
app.use(express.logger());
app.use(express.cookieParser());
app.use(express.bodyParser());
app.use(express.methodOverride());
app.use(express.session({ secret: 'supernova' }));
app.use(passport.initialize());
app.use(passport.session());

// Session-persisted message middleware
app.use(function(req, res, next){
  var err = req.session.error,
    msg = req.session.notice,
    success = req.session.success;

  delete req.session.error;
  delete req.session.success;
  delete req.session.notice;

  if (err) res.locals.error = err;
    if (msg) res.locals.notice = msg;
    if (success) res.locals.success = success;

  next();
});

app.use(app.router);

var hbs = exphbs.create({
    defaultLayout: 'main',
    // helpers: helpers
});
app.engine('handlebars', hbs.engine);
app.set('view engine', 'handlebars');

app.get('/',  function(req, res){
  res.render('home', {user: req.user});
});

app.get('/signin', function(req, res){
  res.render('signin');
});

app.post('/local-reg', passport.authenticate('local-signup', {
  successRedirect: '/',
  failureRedirect: '/signin',
  failureFlash: true 
  })
);

app.post('/login', passport.authenticate('local-signin', { 
  successRedirect: '/',
  failureRedirect: '/signin',
  failureFlash: true 
  })
);

var port = process.env.PORT || 5000;
app.listen(port);
console.log("on " + port + "!");