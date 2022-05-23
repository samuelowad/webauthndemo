const { createVerify } = require("crypto");

const { convertASN1toPEM, parseAuthData, hash } = require("./util");

exports.crpy = (signatureBaseBuffer, signatureBuffer, publicKey) => {
  const te = createVerify("sha256")
    .update(signatureBaseBuffer)
    .verify(publicKey, signatureBuffer);

  console.log(" saved public key", te);
  return te;
};

exports.validateAssertion = (
  authenticatorData,
  clientDataJSON,
  base64Signature,
  publicKey
) => {
  const authenticatorDataBuffer = Buffer.from(authenticatorData, "base64");

  const parsedAuthenticatorData = parseAuthData(authenticatorDataBuffer);
  // tslint:disable-next-line
  if (!parsedAuthenticatorData.flags.up) {
    throw new Error("User was NOT presented durring authentication!");
  }

  const clientDataHash = hash("SHA256", Buffer.from(clientDataJSON, "base64"));

  const signatureBaseBuffer = Buffer.concat([
    authenticatorDataBuffer,
    clientDataHash,
  ]);

  const signatureBuffer = Buffer.from(base64Signature, "base64");

  const pemKey = convertASN1toPEM(Buffer.from(publicKey, "base64"));

  const te = createVerify("sha256")
    .update(signatureBaseBuffer)
    .verify(pemKey, signatureBuffer);

  console.log("saved", te);
  return te;
};

// crpy();
