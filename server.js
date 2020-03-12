require("dotenv").config();                 //FOR SAVING SECRET AND KEYS
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");


const app = express();

app.use(bodyParser.urlencoded({ extended: true })); 
app.use(bodyParser.json());
mongoose.set('useCreateIndex', true);

const port = process.env.PORT || 5000 ;

//CONNECTING TO MONGODB
mongoose.connect("mongodb+srv://admin:" + process.env.MONGO_PASSWORD + "@cluster0-r2ehn.mongodb.net/test?retryWrites=true&w=majority" ,{ useNewUrlParser: true ,  useUnifiedTopology: true })
.then(() => console.log("MongoDB connected"))
.catch((err) => {console.log(err)});

//SCHEMA FOR INDIVIDUAL NOTE
const note = {
    id: String,
    title : String,
    content : String
}

//User Schema with Name, Email, Password as Hash 

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email:{
        type:String,
        required:true,
        unique:true
    },
    password:{
        type:String,
        required:true
    },
    notes: [note], //ARRAY OF OBJECTS 
    date: {
        type: Date,
        default : Date.now
    } 
});

const User = mongoose.model("User", userSchema);

//ROUTES

// @route POST
//@desc GET data of a user
//@Access Public
 app.post("/api/user", (req, res) => {
    User.findById(req.body.userid)
    .then(user => res.json(user));
 });



// @route POST
//@desc  Save new User (Register)
//@Access Public
 app.post("/api/users" , (req,res) => {
     //Checking for empty fields
     const {name , email , password} = req.body;
     if(!name || !email || !password){
        return res.status(400).json({msg:"Please enter all the fields!"})
    }
    //Checking for existing user
    User.findOne({email})
    .then(user => {
        if(user)
        return res.status(400).json({msg: "User already exists."});
       });
        //Create salt and Hash
        bcrypt.hash(req.body.password,10,(err,hash) => {
            if(err) throw err;
            const newUser = new User({
                name: req.body.name,
                email : req.body.email,
                password: hash
                });
                newUser.save()
                .then(user => {
                    jwt.sign(
                        {id: user.id },process.env.JWTSECRET,{expiresIn:3600},(err,token) => {
                            if(err) throw err;
                            res.json({token
                            });
                        }
                    )

                  
                });    
       }); 
     });
// @route POST
//@desc Fetch data of a user(LOGIN)
//@Access Public
app.post("/api/users/auth" , (req,res) => {

    //Checking for empty fields
    const { email , password} = req.body;
    if(!email || !password){
       return res.status(400).json({msg:"Please enter all the fields!"})
   }
   //Checking for existing user
   User.findOne({email})
   .then(user => {
       if(!user)
       return res.status(400).json({msg: "User doesn't exists."});
       //Validate passwords
       bcrypt.compare(password,user.password,(err,result) => {
        if(!result) return res.status(400).json({msg:"Invalid Credentials"}); 
        jwt.sign(
            {id: user.id },process.env.JWTSECRET,{expiresIn:3600},(err,token) => {
                if(err) throw err;
                return res.status(200).json({ token});
            }
        )
        
        });
      });
    });

    // @route POST
    //@desc VERIFYING JWT 

    app.post("/api/tokenverify",(req,res) => {
        try {
            var decoded = jwt.verify(req.body.token , process.env.JWTSECRET);
            res.status(200).json({userid:decoded.id,userLoggedIn:true});
          } catch(err) {
            // err
            res.status(400).json({msg:"not found"});
          }
        
    });

    // @ROUTE POST
    //desc PUSH THE NOTE TO THE DATABASE 
    app.post("/api/user/addnote", (req, res) => {
        User.findOneAndUpdate(req.body.userid, {$push: {notes: req.body.note}},{ new: true, passRawResult : true }, function(err, doc, res){
            console.log("Success!");
        })
        .catch(err => console.log(err));
     });


     // @route POST
     //desc DELETE THE PARTICULAR NOTE FROM DATABASE BY NOTEID 
     app.post("/api/user/deletenote", (req, res) => {
        User.findOneAndUpdate(req.body.userid, {$pull: {notes: {id : req.body.noteId}}},{ new: true, passRawResult : true }, function(err, doc, res){
            console.log("Success!");
        });
     });
    

    

app.listen(port,() => {
    console.log("Server started at port 5000!");
});
