const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const http = require("http");
const mongoose = require("mongoose");
const userModel = require("./models");
const { randomBytes } = require("crypto");

const { verifyPackedAttestation } = require("./attestation");

const { validateAssertion } = require("./assertion");
const { parseClientData, encodeString, decodeString } = require("./util");

const app = express();
app.use(cors());
app.use(bodyParser.json());

app.post("/webauthn/register/request", async (req, res) => {
  const { name } = req.body;

  const user = await userModel.findOne({ name });
  if (user) return res.status(400).json({ message: "user already registered" });

  var challenge = randomBytes(64).toString("hex");

  console.log("chall", challenge);

  const newUser = await new userModel({ name, challenge });
  try {
    newUser.save();
  } catch (e) {
    return res.sendStatus(500);
  }

  res.status(200).json(challenge);
});

app.post("/webauthn/register", async (req, res) => {
  const { name } = req.body;

  const user = await userModel.findOne({ name });

  if (!user) {
    return res.sendStatus(400);
  }

  const parsedClient = await parseClientData(req.body.response.clientDataJSON);

  console.log("pared ", parsedClient);

  const myexport = verifyPackedAttestation(
    req.body.response.attestationObject,
    req.body.response.clientDataJSON
  );

  if (!myexport.dataValid) return res.sendStatus(400);

  user.publicKey = encodeString(myexport.publicKey);
  user.rawId = req.body.parsed.rawId;
  user.origin = parsedClient.origin;
  user.save();

  res.status(200).json({ dataValid: myexport.dataValid });
});

app.post("/webauthn/authenticate/request", async (req, res) => {
  const { name } = req.body;

  const user = await userModel.findOne({ name });

  if (!user) return res.sendStatus(400);

  res.status(200).json({ webId: user.webId, challenge: user.challenge });
});

app.post("/webauthn/authenticate", async (req, res) => {
  const user = await userModel.findOne({ name: req.body.name });

  const parsedClient = await parseClientData(req.body.parsed.clientDataJSON);

  if (parsedClient.origin != user.origin) return res.sendStatus(400);

  const validate = await validateAssertion(
    req.body.response.authenticatorData,
    req.body.response.clientDataJSON,
    req.body.response.signature,
    decodeString(user.publicKey)
  );

  res.status(200).json({ dataValid: validate });
});

// db connect
mongoose.connect(
  "mongodb+srv://dummy:dummy@farmapi.5ieyq.mongodb.net/wenauth?retryWrites=true&w=majority",
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

http.createServer(app).listen(3000, () => {
  console.log(
    "Server is listening at http://localhost:3000. Ctrl^C to stop it."
  );
});
