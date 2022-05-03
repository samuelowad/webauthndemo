const { createHash, createVerify } = require("crypto");
const base64url = require("base64url");
const cbor = require("cbor");
const jsrsasign = require("jsrsasign");
const elliptic = require("elliptic");
const NodeRSA = require("node-rsa");
const {
    convertCOSEPublicKeyToRawPKCSECDHAKey,
    parseAuthData,
} = require("./util");

// npm i base64url cbor jsrsasign node-rsa

let COSEKEYS = {
    kty: 1,
    alg: 3,
    crv: -1,
    x: -2,
    y: -3,
    n: -1,
    e: -2,
};

let COSEKTY = {
    OKP: 1,
    EC2: 2,
    RSA: 3,
};

let COSERSASCHEME = {
    "-3": "pss-sha256",
    "-39": "pss-sha512",
    "-38": "pss-sha384",
    "-65535": "pkcs1-sha1",
    "-257": "pkcs1-sha256",
    "-258": "pkcs1-sha384",
    "-259": "pkcs1-sha512",
};

var COSECRV = {
    1: "p256",
    2: "p384",
    3: "p521",
};

var COSEALGHASH = {
    "-257": "sha256",
    "-258": "sha384",
    "-259": "sha512",
    "-65535": "sha1",
    "-39": "sha512",
    "-38": "sha384",
    "-37": "sha256",
    "-260": "sha256",
    "-261": "sha512",
    "-7": "sha256",
    "-36": "sha512",
};

let hash = (alg, message) => {
    return createHash(alg).update(message).digest();
};

let base64ToPem = (b64cert) => {
    // console.log("baseto", b64cert);
    let pemcert = "";
    for (let i = 0; i < b64cert.length; i += 64)
        pemcert += b64cert.slice(i, i + 64) + "\n";

    return (
        "-----BEGIN CERTIFICATE-----\n" + pemcert + "-----END CERTIFICATE-----"
    );
};

var getCertificateInfo = (certificate) => {
    let subjectCert = new jsrsasign.X509();
    subjectCert.readCertPEM(certificate);

    let subjectString = subjectCert.getSubjectString();
    let subjectParts = subjectString.slice(1).split("/");

    let subject = {};
    for (let field of subjectParts) {
        let kv = field.split("=");
        subject[kv[0]] = kv[1];
    }

    let version = subjectCert.version;
    let basicConstraintsCA = !!subjectCert.getExtBasicConstraints().cA;

    return {
        subject,
        version,
        basicConstraintsCA,
    };
};

exports.verifyPackedAttestation = (attestationObject, clientDataJSON) => {
    let attestationBuffer = base64url.toBuffer(attestationObject);
    let attestationStruct = cbor.decodeAllSync(attestationBuffer)[0];

    //   console.log(m(attestationStruct.authData));

    let authDataStruct = parseAuthData(attestationStruct.authData);

    const publicKey = convertCOSEPublicKeyToRawPKCSECDHAKey(
        authDataStruct.COSEPublicKey
    );

    let clientDataHashBuf = hash("sha256", base64url.toBuffer(clientDataJSON));
    let signatureBaseBuffer = Buffer.concat([
        attestationStruct.authData,
        clientDataHashBuf,
    ]);

    let signatureBuffer = attestationStruct.attStmt.sig;
    let signatureIsValid = false;

    if (attestationStruct.attStmt.x5c) {
        /* ----- Verify FULL attestation ----- */

        // hard coded base64 string valid
        // let leafCert = base64ToPem(
        //     "MIIC2DCCAcCgAwIBAgIJALA5KjdfOKLrMA0GCSqGSIb3DQEBCwUAMC4xLDAqBgNVBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgwMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjBuMQswCQYDVQQGEwJTRTESMBAGA1UECgwJWXViaWNvIEFCMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMScwJQYDVQQDDB5ZdWJpY28gVTJGIEVFIFNlcmlhbCA5MjU1MTQxNjAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATBUzDbxw7VyKPri/NcB5oy/eVWBkwkXfQNU1gLc+nLR5EP7xcV93l5aHDpq1wXjOuZA5jBJoWpb6nbhhWOI9nCo4GBMH8wEwYKKwYBBAGCxAoNAQQFBAMFBAMwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjcwEwYLKwYBBAGC5RwCAQEEBAMCBDAwIQYLKwYBBAGC5RwBAQQEEgQQL8BXn4ETR+qxFrtajbkgKjAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQABaTFk5Jj2iKM7SQ+rIS9YLEj4xxyJlJ9fGOoidDllzj4z7UpdC2JQ+ucOBPY81JO6hJTwcEkIdwoQPRZO5ZAScmBDNuIizJxqiQct7vF4J6SJHwEexWpF4XztIHtWEmd8JbnlvMw1lMwx+UuD06l11LxkfhK/LN613S91FABcf/ViH6rqmSpHu+II26jWeYEltk0Wf7jvOtRFKkROFBl2WPc2Dg1eRRYOKSJMqQhQn2Bud83uPFxT1H5yT29MKtjy6DJyzP4/UQjhLmuy9NDt+tlbtvfrXbrIitVMRE6oRert0juvM8PPMb6tvVYQfiM2IaYLKChn5yFCywvR9Xa+"
        // );

        // original
        let leafCert = base64ToPem(
            attestationStruct.attStmt.x5c[0].toString("base64")
        );

        // console.log(leafCert);
        let certInfo = getCertificateInfo(leafCert);

        if (certInfo.subject.OU !== "Authenticator Attestation")
            throw new Error(
                'Batch certificate OU MUST be set strictly to "Authenticator Attestation"!'
            );

        if (!certInfo.subject.CN)
            throw new Error("Batch certificate CN MUST no be empty!");

        if (!certInfo.subject.O)
            throw new Error("Batch certificate CN MUST no be empty!");

        if (!certInfo.subject.C || certInfo.subject.C.length !== 2)
            throw new Error(
                "Batch certificate C MUST be set to two character ISO 3166 code!"
            );

        if (certInfo.basicConstraintsCA)
            throw new Error(
                "Batch certificate basic constraints CA MUST be false!"
            );

        if (certInfo.version !== 3)
            throw new Error("Batch certificate version MUST be 3(ASN1 2)!");

        signatureIsValid = createVerify("sha256")
            .update(signatureBaseBuffer)
            .verify(leafCert, signatureBuffer);

        /* ----- Verify FULL attestation ENDS ----- */
    } else if (attestationStruct.attStmt.ecdaaKeyId) {
        throw new Error("ECDAA IS NOT SUPPORTED YET!");
    } else {
        /* ----- Verify SURROGATE attestation ----- */
        let pubKeyCose = cbor.decodeAllSync(authDataStruct.COSEPublicKey)[0];
        let hashAlg = COSEALGHASH[pubKeyCose.get(COSEKEYS.alg)];
        if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.EC2) {
            let x = pubKeyCose.get(COSEKEYS.x);
            let y = pubKeyCose.get(COSEKEYS.y);

            let ansiKey = Buffer.concat([Buffer.from([0x04]), x, y]);

            let signatureBaseHash = hash(hashAlg, signatureBaseBuffer);

            let ec = new elliptic.ec(COSECRV[pubKeyCose.get(COSEKEYS.crv)]);
            let key = ec.keyFromPublic(ansiKey);

            signatureIsValid = key.verify(signatureBaseHash, signatureBuffer);
        } else if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.RSA) {
            let signingScheme = COSERSASCHEME[pubKeyCose.get(COSEKEYS.alg)];

            let key = new NodeRSA(undefined, { signingScheme });
            key.importKey(
                {
                    n: pubKeyCose.get(COSEKEYS.n),
                    e: 65537,
                },
                "components-public"
            );

            signatureIsValid = key.verify(signatureBaseBuffer, signatureBuffer);
        } else if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.OKP) {
            let x = pubKeyCose.get(COSEKEYS.x);
            let signatureBaseHash = hash(hashAlg, signatureBaseBuffer);

            let key = new elliptic.eddsa("ed25519");
            key.keyFromPublic(x);

            signatureIsValid = key.verify(signatureBaseHash, signatureBuffer);
        }
        /* ----- Verify SURROGATE attestation ENDS ----- */
    }

    if (!signatureIsValid) throw new Error("Failed to verify the signature!");

    console.log("dataValid", signatureIsValid);
    console.log("publickey", publicKey.toString("base64"));

    return {
        dataValid: signatureIsValid,
        publicKey: publicKey.toString("base64"),
    };
};

// data from my frontend
let packedSurrogateAttestationWebAuthnSample = {
    id: "H6X2BnnjgOzu_Oj87vpRnwMJeJYVzwM3wtY1lhAfQ14",
    rawId: "H6X2BnnjgOzu_Oj87vpRnwMJeJYVzwM3wtY1lhAfQ14",
    response: {
        attestationObject:
            "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEYwRAIgUPyWnk2ggW7UMRC8hcmB/V+kvaI0Ke4EPGOZkjz6rQsCIDT96mZHhJyoQbYuye54SoW0irwxSWBLa4Y8XqDhBZO1Y3g1Y4FZAtwwggLYMIIBwKADAgECAgkAsDkqN184ouswDQYJKoZIhvcNAQELBQAwLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMG4xCzAJBgNVBAYTAlNFMRIwEAYDVQQKDAlZdWJpY28gQUIxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xJzAlBgNVBAMMHll1YmljbyBVMkYgRUUgU2VyaWFsIDkyNTUxNDE2MDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMFTMNvHDtXIo+uL81wHmjL95VYGTCRd9A1TWAtz6ctHkQ/vFxX3eXlocOmrXBeM65kDmMEmhalvqduGFY4j2cKjgYEwfzATBgorBgEEAYLECg0BBAUEAwUEAzAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuNzATBgsrBgEEAYLlHAIBAQQEAwIEMDAhBgsrBgEEAYLlHAEBBAQSBBAvwFefgRNH6rEWu1qNuSAqMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBAAFpMWTkmPaIoztJD6shL1gsSPjHHImUn18Y6iJ0OWXOPjPtSl0LYlD65w4E9jzUk7qElPBwSQh3ChA9Fk7lkBJyYEM24iLMnGqJBy3u8XgnpIkfAR7FakXhfO0ge1YSZ3wlueW8zDWUzDH5S4PTqXXUvGR+Er8s3rXdL3UUAFx/9WIfquqZKke74gjbqNZ5gSW2TRZ/uO861EUqRE4UGXZY9zYODV5FFg4pIkypCFCfYG53ze48XFPUfnJPb0wq2PLoMnLM/j9RCOEua7L00O362Vu29+tdusiK1UxETqhF6u3SO68zw88xvq29VhB+IzYhpgsoKGfnIULLC9H1dr5oYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAMvwFefgRNH6rEWu1qNuSAqAECCXPhcLZKzfcW8Mj3LZP3/WJFcJHfGjdnZNGi8xeq3kMuQu4VvgGfF3YYkUsTTtKkdDQSPw0igU41vXcQurHJlpQECAyYgASFYIIfM6uMpGEKT4NN7IjndfRk7xreErGdeLvv4x3qYU1ZkIlgg1n5JrtJ3koCE23Y87TdOIbl2TuFZfFGjgjv1djWr9mo=",
        clientDataJSON:
            "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiRVVWUDlqZXFMS3N0bjZqY25Cc2lJU3JBY09WTzF6SnZiNTFocDFRc19XayIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0=",
    },
    type: "public-key",
};

// data from demo2

// // validate assert from demo site https://psteniusubi.github.io/webauthn-tester/
// const validateFidoPackedKey = () => {
//     const authenticatorDataBuffer = Buffer.from(
//         "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MBAAAADA==",
//         "base64"
//     );

//     const authenticatorData = parseAuthData(authenticatorDataBuffer);

//     // tslint:disable-next-line
//     if (!authenticatorData.flags.up) {
//         throw new Error("User was NOT presented durring authentication!");
//     }

//     const clientDataHash = hash(
//         "SHA256",
//         Buffer.from(
//             "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoielVoSWlYSWdqRHN0MHhRRVZYelRRYmZFSElFSjc4WTJlWm5XRjB5VlE0SSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9",
//             "base64"
//         )
//     );
//     const signatureBaseBuffer = Buffer.concat([
//         authenticatorDataBuffer,
//         clientDataHash,
//     ]);

//     const publicKey = convertASN1toPEM(
//         Buffer.from(
//             "BIfM6uMpGEKT4NN7IjndfRk7xreErGdeLvv4x3qYU1Zk1n5JrtJ3koCE23Y87TdOIbl2TuFZfFGjgjv1djWr9mo=",
//             "base64"
//         )
//     );
//     const signatureBuffer = Buffer.from(
//         "MEYCIQDDs2WZvHaFK3QeA0eqt9BVXptQQ6SKwvctVdNswRkQGwIhAJfnIcRYojUNooBJv2Jo3z1JVzrcEhC8zfF7cg2S7HgW",
//         "base64"
//     );

//     return createVerify("sha256")
//         .update(signatureBaseBuffer)
//         .verify(publicKey, signatureBuffer);
// };

// console.log("data from demo site", validateFidoPackedKey());

// console.log(verifyPackedAttestation(packedFullAttestationWebAuthnSample));
// console.log(
//     verifyPackedAttestation(
//         packedSurrogateAttestationWebAuthnSample.response.attestationObject,
//         packedSurrogateAttestationWebAuthnSample.response.clientDataJSON
//     )
// );
