const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const http = require("http");
const mongoose = require("mongoose");
const userModel = require("./models");
const { randomBytes } = require("crypto");

const { verifyPackedAttestation } = require("./newtest");

const { crpy1 } = require("./testex");

const app = express();
app.use(cors());
app.use(bodyParser.json());

app.post("/register-request", async (req, res) => {
    const { name } = req.body;

    const user = await userModel.findOne({ name });
    if (user)
        return res.status(400).json({ message: "user already registered" });

    var challenge = randomBytes(64).toString("hex");

    const newUser = await new userModel({ name, challenge });
    try {
        newUser.save();
    } catch (e) {
        return res.sendStatus(500);
    }

    res.status(200).json(challenge);
});

app.post("/register", async (req, res) => {
    const { name } = req.body;

    const user = await userModel.findOne({ name });
    if (!user) {
        return res.sendStatus(400);
    }

    const myexport = verifyPackedAttestation(
        req.body.parsed.response.attestationObject,
        req.body.parsed.response.clientDataJSON
    );

    if (!myexport.dataValid) return res.sendStatus(400);

    user.publicKey = myexport.publicKey;
    user.webId = req.body.parsed.rawId;
    user.save();

    res.status(200).json({ dataValid: myexport.dataValid });
});

app.post("/login-request", async (req, res) => {
    const { name } = req.body;

    const user = await userModel.findOne({ name });

    if (!user) return res.sendStatus(400);

    res.status(200).json({ webId: user.webId, challenge: user.challenge });
});

app.post("/login", async (req, res) => {
    const user = await userModel.findOne({ name: req.body.name });

    // console.log("user", user);

    const validate = await crpy1(
        req.body.parsed.response.authenticatorData,
        req.body.parsed.response.clientDataJSON,
        req.body.parsed.response.signature,
        user.publicKey
    );

    res.status(200).json({ dataValid: validate });
});

mongoose.connect(
    MONGODB_URL,
    {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    }
);

const db = mongoose.connection;
db.on("error", console.error.bind(console, "connection error: "));
db.once("open", function () {
    console.log("Connected successfully");
});

http.createServer(app).listen(8000, () => {
    console.log(
        "Server is listening at http://localhost:8000. Ctrl^C to stop it."
    );
});
