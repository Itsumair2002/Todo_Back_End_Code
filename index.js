const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { z } = require('zod')
const nodemailer = require('nodemailer')

const app = express();
app.use(cors());
app.use(express.json());

let otpStore = {}
const JWT_SECRET = process.env.JWT_SECRET;

const Schema = mongoose.Schema;
const ObjectId = Schema.Types.ObjectId;

const User = new Schema({
    email: { type: String, unique: true },
    password: { type: String, required: true }
});

const Todo = new Schema({
    title: { type: String, required: true },
    userId: { type: ObjectId, ref: "users", required: true }
});

const UserModel = mongoose.model("users", User);
const TodoModel = mongoose.model("todos", Todo);

function auth(req, res, next) {
    const token = req.headers.token;
    try {
        const response = jwt.verify(token, JWT_SECRET);
        req.userId = response.id;
        next();
    } catch (error) {
        return res.json({ message: "Incorrect Credentials" });
    }
}
async function sendOTP(receiveremail, otp) {
    try {
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            host: 'smtp.gmail.com',
            port: 587,
            secure: false,
            auth: {
                user: process.env.EMAIL,
                pass: process.env.PASSWORD,
            },
            tls: {
                ciphers: 'SSLv3'
            }
        })
        const mailOptions = {
            from: 'officialtodoapplication@gmail.com',
            to: receiveremail,
            subject: 'OTP for Todo Application',
            text: `Your One Time Password for Todo Application is ${otp}`,
        }
        const info = await transporter.sendMail(mailOptions)
        console.log('message sent: %s', info.messageId)
    } catch (error) {
        console.log(error)
    }

}
const generateOTP = () => {
    const otp = Math.floor(100000 + Math.random() * 900000);
    return otp;
};

async function connectToDatabase() {
    try {
        await mongoose.connect(process.env.MONGOOSEURL);
        startServer();
    } catch (error) {
        console.log('Error connecting to the database');
    }
}
function check(body) {
    const requiredBody = z.object({
        email: z.string().trim().min(3).max(50).email(),
        password: z.string().trim().min(5).max(50)
    })
    const parsedDataWithSuccess = requiredBody.safeParse(body)
    if (!parsedDataWithSuccess.success) {
        res.status(203).json({ message: "Incorrect format", error: parsedDataWithSuccess.error.errors })
        return
    }
}

function startServer() {

    async function hashPassword(password) {
        try {
            const hash = await bcrypt.hash(password, 10);
            return hash;
        } catch (error) {
            console.log('Error occured while hashing the password: ', error);
            return null;
        }
    }

    async function verifyPassword(password, hashedPassword) {
        try {
            const match = await bcrypt.compare(password, hashedPassword);
            return match;
        } catch (error) {
            console.log('Error while verifying the password: ', error);
            return false;
        }
    }
    app.post("/check", async (req, res) => {
        check(req.body)
        const user = await UserModel.findOne({ email: req.body.email });
        if (user) {
            return res.status(202).json({ message: "User already registered" });
        }
        res.status(200).json({ message: "Details are correct and user is unique"})
    })
    app.post("/signup", async (req, res) => {
        check(req.body)
        let email = req.body.email
        let password = req.body.password
        try {
            let hashedPassword = await hashPassword(password);
            if (hashedPassword) {
                let response = await UserModel.create({
                    email: email,
                    password: hashedPassword
                });
                console.log(response)
                res.status(200).json({ message: "You are signed up!" });
            } else res.status(500).json({ message: "Error hashing the password" });
        } catch (error) {
            if (error.code === 11000) {
                res.status(403).json({ message: "User already registered!" })
            } else {
                console.log('Error: ', error.code);
                res.status(400).json({ message: "Error while signup!" });
            }
        }
    });

    app.post("/signin", async (req, res) => {
        let email = req.headers.email;
        let password = req.headers.password;

        try {
            const user = await UserModel.findOne({ email: email });
            if (!user) {
                return res.status(205).json({ message: "User not found!" });
            }
            const isPasswordValid = await verifyPassword(password, user.password);
            if (!isPasswordValid) {
                return res.status(204).json({ message: "Password is not valid!" });
            }
            const token = jwt.sign({ id: user._id }, JWT_SECRET);
            res.status(200).json({ token });
        } catch (error) {
            console.log("Error during signin: ", error);
            res.status(500).json({ message: "Error signing in. Please try again." });
        }
    });

    app.post("/addTodo", auth, async (req, res) => {
        let title = req.body.title;
        let userId = req.userId;
        let todos = await TodoModel.find({ userId: userId })
        let response = todos.find(e => e.title === title)
        if (!response) {
            await TodoModel.create({ title: title, userId: userId });
            res.json({ message: "Todos created" });
        } else {
            res.json({ message: "Todo exists already" })
        }
    });

    app.delete("/deleteTodo", auth, async (req, res) => {
        let id = req.headers.id;
        try {
            await TodoModel.deleteOne({ _id: id });
            res.json({ message: "Todo deleted successfully " });
        } catch (error) {
            res.json({ message: "Error deleting the todos " });
        }
    });

    app.put("/editTodo", auth, async (req, res) => {
        let id = req.body.id;
        let title = req.body.title;
        try {
            await TodoModel.updateOne({ _id: id }, { title: title });
            res.json({ message: "Todo edited Successfully" });
        } catch (error) {
            res.json({ message: "Error editing the todo" });
        }
    });

    app.get("/getTodos", auth, async (req, res) => {
        let userId = req.userId;
        try {
            let todos = await TodoModel.find({ userId: userId });
            res.json({ todos });
        } catch (error) {
            res.json({ message: "Error fetching the todos" });
        }
    });
    app.post("/sendOtp", async (req, res) => {
        let email = req.body.email;
        let otp = generateOTP();

        otpStore[email] = otp;
        setTimeout(() => {
            delete otpStore[email];
        }, 1000 * 60 * 5);

        try {
            await sendOTP(email, otp);
            res.status(200).json({ message: "OTP sent successfully" });
        } catch (error) {
            res.status(500).json({ message: "Error sending OTP" });
        }
    });

    app.post("/verifyOtp", async (req, res) => {
        let { email, otp } = req.body;

        if (otpStore[email]) {
            if (otpStore[email] == otp) {
                delete otpStore[email];
                return res.status(200).json({ message: "OTP was verified successfully" });
            } else {
                console.log(otpStore)
                return res.status(204).json({ message: "Invalid OTP!" });
            }
        } else {
            console.log(otpStore)
            return res.status(205).json({ message: "Expired OTP" });
        }
    });
}
connectToDatabase();
app.listen(process.env.PORT, () => console.log('The server is running...'));
