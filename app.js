//jshint esversion:6

require('dotenv').config();
const express = require('express');
const ejs = require('ejs');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');



const app = express();

app.use(express.static('public'));

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'keyboard cat.',
    resave: false,
    saveUninitialized: true
   
}));

app.use(passport.initialize());
app.use(passport.session());

//Database connection
mongoose.set("strictQuery", false);
mongoose.connect(process.env.DB_HOST);

// Create user schema
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

//add plusgins to db schema
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);
passport.use(User.createStrategy());

// used to serialize the user for the session
passport.serializeUser((user, done) =>{
    done(null, user.id); 
});

// used to deserialize the user
passport.deserializeUser((id, done)=> {
    User.findById(id, (err, user)=> {
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfile:"https://www.googleapis.com/oauth2/userinfo"
 
  },
    function (accessToken, refreshToken, profile, cb) {
       
    User.findOrCreate({ googleId: profile.id }, (err, user) =>{
      return cb(err, user);
    });
  }
));





app.get('/', (req, res) => {
    res.render("home");
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

  app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });


app.get('/login', (req, res) => {
    res.render("login");
});

app.get('/register', (req, res) => {
    res.render("register");
});

app.get('/secrets', (req, res) =>{
    //query users with secrets
    User.find({"secret": { $ne: null }}, (err, foundUsers)=>{
        if (err) {
            console.log(err);
        } else {
            if (foundUsers) {
                res.render('secrets', {usersWithSecrets: foundUsers })
            }
        }
    });
});













app.get('/submit', (req, res) => {
    if (req.isAuthenticated) {
        res.render('submit')
    }else { res.redirect('/login') }
  
})
app.post('/submit', (req, res) => {
    const submittedSceret = req.body.secret;
    console.log(req.user.id);
    //add  submitted secret to the user account
    User.findById(req.user.id, (err, foundUser) => {
        if (err) {
            console.log(err)
        } else {
            if (foundUser) {
                foundUser.secret = submittedSceret
                foundUser.save(() => {
                    res.redirect('/secrets')
                });
            }
           
        }
    });
});

app.get('/logout', (req, res) => {
    req.logout(req.user, err => {
      if(err) return next(err);
      res.redirect("/");
    });
  });
    

//register
app.post('/register',  (req, res)=> {
    User.register({ username: req.body.username },req.body.password, function (err, usr) {
        if (err) {
            console.log(err);
            res.redirect('/register');
        } else {
            passport.authenticate('local')(req, res, function () {
                res.redirect('/secrets');
            })
        }
    });
});

//login
app.post('/login', passport.authenticate('local') , (req, res) =>{

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user,  (err)=> {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate('local')(req, res,  ()=> {
                res.redirect('/secrets');
            });
        }
    })
   
});




app.listen(3000,  () =>{
    console.log('server strated on port', 3000);
});