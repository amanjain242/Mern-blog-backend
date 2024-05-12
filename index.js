const express = require('express')
const cors = require('cors');
const mongoose = require('mongoose');
const User = require('./models/User')
const Post = require('./models/Post')
const bcrypt = require('bcrypt')
const multer = require('multer')
const app = express();
const fs = require('fs')


const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const uploadMiddleware = multer({dest: 'uploads/'})

const secret = 'dsfalkdfiesdffefkajfd';
const salt = bcrypt.genSaltSync(10)

require('dotenv').config()

const PORT = process.env.PORT || 4000;

app.use(cors({credentials:true,origin:'http://localhost:3000'}));
app.use(express.json());
app.use(cookieParser());
app.use('/uploads',express.static(__dirname + '/uploads'))

const url = process.env.MONGO_URL;
const connect = async (url) => {
    await mongoose.connect(url)
}

app.post('/register', async (req, res) => {
    //get all data from body
    const { username, password } = req.body
    try {
        const userDoc = await User.create({ 
            username,
            password:bcrypt.hashSync(password,salt),
         })
        res.json(userDoc);
    } catch(e){
        console.log(e)
        res.status(400).json(e);
    }
});

app.post('/login', async (req,res) => {
    //get all data from body
    const {username,password} = req.body;
    // checking if user already exists
    const userDoc = await User.findOne({username});
    //encrypt the password 
    const passOk = bcrypt.compareSync(password, userDoc.password);
    if(passOk){
        //logged in 
        jwt.sign({username,id:userDoc._id},secret,{}, (err,token)=>{
            if(err) throw err;
            res.cookie('token',token).json({
                id: userDoc._id,
                username,
            }); 
        })
        //res.json()
    }
    else{
        res.status(400).json('wrong credentials')
    }
})

app.get('/profile', (req,res) =>{
    const {token}  = req.cookies;
    jwt.verify(token, secret, {}, (err, info) => {
        if(err) throw err;
        res.json(info);
    })
    res.json(req.cookies);
})

app.post('/logout',(req,res) => {
    res.cookie('token', '').json('ok');
})

app.post('/post' ,uploadMiddleware.single('file'), async (req,res) =>{
    const {originalname,path} = req.file;
    const parts = originalname.split('.');
    const ext = parts[parts.length - 1]
    const newPath = path+'.'+ext
    fs.renameSync(path, newPath)

    const {token}  = req.cookies;
    jwt.verify(token, secret, {}, async (err, info) => {
        if(err) throw err;
        const {title,summary,content} = req.body;
        const postDoc = await Post.create({
        title,
        summary,
        content,
        cover:newPath,
        author:info.id
    })
    res.json(postDoc)
    })

   
})

app.put('/post', uploadMiddleware.single('file'), async (req,res) => {
    let newPath = null;
    if(req.file){
        const {originalname,path} = req.file;
        const parts = originalname.split('.');
        const ext = parts[parts.length - 1]
        newPath = path+'.'+ext
        fs.renameSync(path, newPath)
    }
    const {token} = req.cookies;
    jwt.verify(token, secret, {}, async (err, info) => {
        if(err) throw err;
        const {id,title,summary,content} = req.body;
        const postDoc = await Post.findById(id)
        const isAuthor = JSON.stringify(postDoc.author) === JSON.stringify(info.id);
        if(!isAuthor) {
            return res.status(400).json('you are not the author')
        }
        await postDoc.updateOne({
            title,
            summary,
            content,
            cover:newPath ? newPath : postDoc.cover,
        })
        res.json(postDoc)
    })
  

})

app.get('/post', async (req,res) => {
    res.json(
        await Post.find()
        .populate('author',['username'])
        .sort({createdAt: -1})
        .limit(20)
        );
})

app.get('/post/:id', async (req,res) => {
    const {id} = req.params;
    const postDoc = await Post.findById(id).populate('author',['username']);
    res.json(postDoc);
})


app.delete('/post/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const postDoc = await Post.findById(id);

        if (!postDoc) {
            return res.status(404).json({ error: 'Post not found' });
        }

        // Check if the logged-in user is the author of the post
        const { token } = req.cookies;
        jwt.verify(token, secret, {}, async (err, info) => {
            if (err) throw err;

            if (JSON.stringify(postDoc.author) !== JSON.stringify(info.id)) {
                return res.status(403).json({ error: 'You are not the author of this post' });
            }

            // Delete the post
            await Post.findByIdAndDelete(id);
            res.json({ success: true });
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});



app.listen(PORT, () => {
    connect(url);
    console.log("server started");
})


//21Zj16slKhjffCbT
//mongodb+srv://jainlucc321:21Zj16slKhjffCbT@cluster0.zku5jtl.mongodb.net/?retryWrites=true&w=majority
// DSEcTtr5R5Q11oSM