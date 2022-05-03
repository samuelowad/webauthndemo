const { decodeAllSync } = require("cbor");

exports.convertCOSEPublicKeyToRawPKCSECDHAKey = (cosePublicKey) => {
    /* 
    +------+-------+-------+---------+----------------------------------+
    | name | key   | label | type    | description                      |
    |      | type  |       |         |                                  |
    +------+-------+-------+---------+----------------------------------+
    | crv  | 2     | -1    | int /   | EC Curve identifier - Taken from |
    |      |       |       | tstr    | the COSE Curves registry         |
    |      |       |       |         |                                  |
    | x    | 2     | -2    | bstr    | X Coordinate                     |
    |      |       |       |         |                                  |
    | y    | 2     | -3    | bstr /  | Y Coordinate                     |
    |      |       |       | bool    |                                  |
    |      |       |       |         |                                  |
    | d    | 2     | -4    | bstr    | Private key                      |
    +------+-------+-------+---------+----------------------------------+
    */

    const coseStruct = decodeAllSync(cosePublicKey)[0];
    const tag = Buffer.from([0x04]);
    const x = coseStruct.get(-2);
    const y = coseStruct.get(-3);

    return Buffer.concat([tag, x, y]);
};

exports.parseAuthData = (buffer) => {
    let rpIdHash = buffer.slice(0, 32);
    buffer = buffer.slice(32);
    let flagsBuf = buffer.slice(0, 1);
    buffer = buffer.slice(1);
    let flagsInt = flagsBuf[0];
    let flags = {
        up: !!(flagsInt & 0x01),
        uv: !!(flagsInt & 0x04),
        at: !!(flagsInt & 0x40),
        ed: !!(flagsInt & 0x80),
        flagsInt,
    };

    let counterBuf = buffer.slice(0, 4);
    buffer = buffer.slice(4);
    let counter = counterBuf.readUInt32BE(0);

    // console.log(counter);

    let aaguid = undefined;
    let credID = undefined;
    let COSEPublicKey = undefined;

    if (flags.at) {
        aaguid = buffer.slice(0, 16);
        buffer = buffer.slice(16);
        let credIDLenBuf = buffer.slice(0, 2);
        buffer = buffer.slice(2);
        let credIDLen = credIDLenBuf.readUInt16BE(0);
        credID = buffer.slice(0, credIDLen);
        buffer = buffer.slice(credIDLen);
        COSEPublicKey = buffer;
    }

    return {
        rpIdHash,
        flagsBuf,
        flags,
        counter,
        counterBuf,
        aaguid,
        credID,
        COSEPublicKey,
    };
};

exports.convertASN1toPEM = (pkBuffer) => {
    if (!Buffer.isBuffer(pkBuffer)) {
        throw new Error("ASN1toPEM: pkBuffer must be Buffer.");
    }

    let type;
    if (pkBuffer.length === 65 && pkBuffer[0] === 0x04) {
        /*
            If needed, we encode rawpublic key to ASN structure, adding metadata:
            SEQUENCE {
              SEQUENCE {
                 OBJECTIDENTIFIER 1.2.840.10045.2.1 (ecPublicKey)
                 OBJECTIDENTIFIER 1.2.840.10045.3.1.7 (P-256)
              }
              BITSTRING <raw public key>
            }
            Luckily, to do that, we just need to prefix it with constant 26 bytes (metadata is constant).
        */
        pkBuffer = Buffer.concat([
            Buffer.from(
                "3059301306072a8648ce3d020106082a8648ce3d030107034200",
                "hex"
            ),
            pkBuffer,
        ]);

        type = "PUBLIC KEY";
    } else {
        type = "CERTIFICATE";
    }

    const b64cert = pkBuffer.toString("base64");

    const PEMKeyMatches = b64cert.match(/.{1,64}/g);

    if (!PEMKeyMatches) {
        throw new Error("Invalid key");
    }

    const PEMKey = PEMKeyMatches.join("\n");

    return `-----BEGIN ${type}-----\n` + PEMKey + `\n-----END ${type}-----\n`;
};
