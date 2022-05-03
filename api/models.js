const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
    publicKey: {
        type: String,
        // required: true,
    },
    challenge: String,
    webId: String,
    name: String,
});

const User = mongoose.model("User", UserSchema);

module.exports = User;
