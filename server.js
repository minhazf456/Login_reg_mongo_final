const express = require("express");
const app = express();
const mongoose = require('mongoose');
const session = require('express-session');
const flash = require('express-flash');

var bcrypt = require('bcryptjs');

app.use(flash());
app.set('view engine', 'ejs');
app.set('views', __dirname + '/views');
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname + "/static"));
app.use(session({
    secret: 'keyboardkitteh',
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 60000 }
}))

mongoose.connect('mongodb://localhost/users_login', { useNewUrlParser: true });

const UserSchema = new mongoose.Schema({
    email: { type: String, required: true },
    first_name: { type: String, required: true },
    last_name: { type: String, required: true },
    birthday: { type: String, required: true },
    password_hash: { type: String, required: true },
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);

app.get('/', (req, res) => {
    res.render('index');
})

app.post('/login', (req, res) => {
    User.findOne({ "email": req.body.email })
        .then((user) => {
            return bcrypt.compare(req.body.password, user.password_hash);
        })
        .then((result) => {
            //`result` here is whether the password was correct or not
            if (result){
                res.redirect("/success")
            } else {
                req.flash("reg", "Wrong password");
                res.redirect("/");
            }
        })
        .catch((err) => {
            for (var key in err.errors) {
                req.flash("reg", err.errors[key].message);
            }
            req.flash("reg", "Error finding user account");
            res.redirect("/");
        })



})

app.post('/register', (req, res) => {
    var error = false;
    if (!(req.body.email.includes('@') && req.body.email.includes('.'))) {
        req.flash('reg', "Not an email!")
        error = true;
    }
    //Added an inner set of parenthesis here to make this work
    if (!(req.body.first_name.length > 1)) {
        req.flash('reg', "Please add more than one character to your first name");
        error = true;
    }
    //Added an inner set of parenthesis here to make this work
    if (!(req.body.last_name.length > 1)) {
        req.flash('reg', "Please add more than one character to your last name");
        error = true;
    }
    if (req.body.password != req.body.cpassword) {
        req.flash('reg', "Passwords don't match");
        error = true;
    }
    //Added an inner set of parenthesis here to make this work
    if (!(req.body.password.length > 5)) {
        req.flash('reg', "Password should have more than 5 characters");
        error = true;
    }
    var re = /[0-9]/;
    if (!re.test(req.body.password)) {
        req.flash('reg', "Password should contain a digit");
        error = true;
    }
    if (error) {
        res.redirect("/")
    } else {
        //Hash password (asynchronously)
        bcrypt.hash(req.body.password, 8)
            .then((hash) => {
                req.body.password_hash = hash;
                delete req.body.password;
                delete req.body.cpassword;
                //Create the user
                return User.create(req.body);
            })
            .then((user) => {
                req.flash("reg", "User created! " + user.email);
                res.redirect("/");
            })
            .catch((err) => {
                for (var key in err.errors) {
                    req.flash("reg", err.errors[key].message);
                }
                res.redirect("/");
            });
    }

})

app.get('/success', (req, res) => {
    res.end("Success")
})



app.listen(8000, () => console.log("listening on port 8000"));