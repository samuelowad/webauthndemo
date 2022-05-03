const { createVerify, createHash } = require("crypto");
const { decodeAllSync } = require("cbor");

const { convertASN1toPEM, parseAuthData } = require("./util");

let nsignatureBaseBuffer = undefined,
    nsignatureBuffer = undefined,
    npublicKey = undefined,
    opublicKey = undefined;

const hash = (alg, data) => {
    return createHash(alg).update(data).digest();
};

exports.crpy = (signatureBaseBuffer, signatureBuffer, publicKey) => {
    // opublicKey = publicKey;
    // if (nsignatureBuffer == undefined) {
    //     console.log("here loggin");
    //     nsignatureBaseBuffer = signatureBaseBuffer;
    //     nsignatureBuffer = signatureBuffer;
    //     npublicKey = publicKey;
    // }
    if (opublicKey == undefined) {
        console.log("hereee");
        opublicKey = publicKey;
        const te = createVerify("sha256")
            .update(signatureBaseBuffer)
            .verify(publicKey, signatureBuffer);

        console.log("not saved", te);
        return te;
    }

    const te = createVerify("sha256")
        .update(signatureBaseBuffer)
        .verify(opublicKey, signatureBuffer);

    console.log(" saved public key", te);
    return te;
};

exports.crpy1 = (
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

    const clientDataHash = hash(
        "SHA256",
        Buffer.from(clientDataJSON, "base64")
    );

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
