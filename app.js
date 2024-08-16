const express               =  require('express'),
      expSession            =  require("express-session"),
      app                   =  express(),
      mongoose              =  require("mongoose"),
      passport              =  require("passport"),
      bodyParser            =  require("body-parser"),
      LocalStrategy         =  require("passport-local"),
      passportLocalMongoose =  require("passport-local-mongoose"),
      User                  =  require("./models/user")
      mongoSanitize         =  require("express-mongo-sanitize")
      rateLimit             =  require('express-rate-limit');
      xss                   =  require('xss-clean')
      helmet                =  require('helmet')

//Connecting database
mongoose.connect("mongodb://localhost/auth_demo");

app.use(expSession({
    secret:"mysecret",       //decode or encode session
    resave: false,          
    saveUninitialized:true,
    cookie: {
        httpOnly: true,
        secure: true,
        maxAge: 1 * 60 * 1000
    }
}))

passport.serializeUser(User.serializeUser());       //session encoding
passport.deserializeUser(User.deserializeUser());   //session decoding
passport.use(new LocalStrategy(User.authenticate()));
app.set("view engine","ejs");
app.use(bodyParser.urlencoded(
      { extended:true }
))
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static("public"));


//=======================
//      O W A S P
//=======================
app.use(mongoSanitize());
// Preventing Brute Force & DOS Attacks Rate Limiting
const limit = rateLimit({
    max: 100, // max requests
    windowMs: 60 * 60 * 1000, // 1 Hour of 'ban' / lockout
    message: 'Too many requests' // message to send
});

app.use('/routeName', limit); // Setting limiter on specific route
app.use(express.json({ limit: '10kb'}));
app.use(xss());
app.use(helmet());

//=======================
//      R O U T E S
//=======================
app.get("/", (req,res) =>{
    res.render("home");
})
app.get("/userprofile" ,(req,res) =>{
    res.render("userprofile");
})
//Auth Routes
app.get("/login",(req,res)=>{
    res.render("login");
});
app.post("/login",passport.authenticate("local",{
    successRedirect:"/userprofile",
    failureRedirect:"/login"
}),function (req, res){
});
app.get("/register",(req,res)=>{
    res.render("register");
});

app.post("/register", (req, res) => {
    const { username, email, phone, password } = req.body;
    let errors = {};

    // Validate username
    if (!username || username.length < 3) {
        errors.username = "Username must be at least 3 characters long.";
    }

    // Validate password strength
    const passwordRegex = /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (!passwordRegex.test(password)) {
        errors.password = "Password must be at least 8 characters long, contain one uppercase letter, one lowercase letter, one number, and one special character.";
    }

    // If there are any validation errors, render the register page with the errors
    if (Object.keys(errors).length > 0) {
        return res.render("register", { errorMessage: errors });
    }

    // If all validations pass, proceed with registration
    User.register(new User({ username, email, phone }), password, (err, user) => {
        if (err) {
            console.log(err);
            return res.render("register", { errors: { general: err.message } });
        }
        passport.authenticate("local")(req, res, function () {
            res.redirect("/login");
        });
    });
});





//Listen On Server
app.listen(process.env.PORT || 3000,function (err) {
    if(err){
        console.log(err);
    }else {
        console.log("Server Started At Port 3000");  
    }
});