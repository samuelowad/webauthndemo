const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  publicKey: {
    type: String,
  },
  challenge: String,
  rawId: String,
  name: String,
  origin: String,
  valid: {
    type: Boolean,
    default: true,
  },
});

const User = mongoose.model("User", UserSchema);

module.exports = User;
