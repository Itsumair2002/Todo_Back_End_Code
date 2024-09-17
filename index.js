const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = 'klsdhjfklashdfdsf';

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

async function connectToDatabase() {
    try {
        await mongoose.connect("mongodb+srv://umair:umair123@cluster0.0ozeb.mongodb.net/Todo_Application");
        console.log('Connection to the Database is established');
        startServer();
    } catch (error) {
        console.log('Error connecting to the database');
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

    app.post("/signup", async (req, res) => {
        let email = req.body.email;
        let password = req.body.password;
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
            if(error.code === 11000){
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
                return res.status(403).json({ message: "User not found!" });
            }
            const isPasswordValid = await verifyPassword(password, user.password);
            if (!isPasswordValid) {
                return res.status(400).json({ message: "Password is not valid!" });
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
        await TodoModel.create({ title: title, userId: userId });
        res.json({ message: "Todos created" });
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
}

connectToDatabase();

app.listen(5000, () => console.log('The server is running...'));
