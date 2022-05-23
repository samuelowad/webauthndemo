// let clientDataJSON;
// let publicKey;
// let credentialId;

// let dbPubkey = undefined;

const url = "http://localhost:3000";
// const url ="https://lucky-guests-matter-193-6-53-166.loca.lt/"

// webauthn create
async function webCreate() {
  const person = prompt("Please enter your name");
  const clientId = prompt("Please enter your clientId");
  const authenticatorName = prompt("Please enter your authenticattorName");
  const origin = prompt("Please enter your origin");

  // get challenge
  const { data, error } = await apiCall(
    { clientId, authenticatorName, origin },
    "webauthn/register/request"
  );

  if (error) return;

  const publicKeyCredentialCreationOptions = {
    // challenge: Uint8Array.from(data, (c) => c.charCodeAt(0)),
    challenge: f(data.challenge),
    rp: {
      name: "localhost",
      //id: "http://127.0.0.1:3000",
    },
    user: {
      id: Uint8Array.from("UZSL85T9AFC", (c) => c.charCodeAt(0)),
      name: "lee@webauthn.guide",
      displayName: person,
    },
    pubKeyCredParams: [{ alg: -7, type: "public-key" }],
    authenticatorSelection: {
      //       authenticatorAttachment: "cross-platform",
      userVerification: "discouraged",
    },
    timeout: 60000,
    attestation: "direct",
  };
  const cred = [
    await navigator.credentials.create({
      publicKey: publicKeyCredentialCreationOptions,
    }),
  ];

  const parsed = cred.map((item) => {
    return {
      id: item.id,
      rawId: m(item.rawId),
      response: {
        attestationObject: m(item.response.attestationObject),
        clientDataJSON: m(item.response.clientDataJSON),
      },
      type: item.type,
    };
  })[0];

  const attestationData = { ...parsed, clientId, authenticatorName };

  console.log("attes", attestationData);

  const validateAttestion = apiCall(attestationData, "webauthn/register");
  alert("user registered");
}

// webauth get

async function webGet() {
  const person = prompt("Please enter your name");
  const clientId = prompt("Please enter your clientId");
  const authenticatorName = prompt("Please enter your authenticattorName");

  // get rawId and challenge
  const { data, error } = await apiCall(
    { clientId, authenticatorName },
    "webauthn/authenticate/request"
  );

  if (error) return;
  const publicKeyCredentialRequestOptions = {
    // challenge: Uint8Array.from(data.challenge, (c) => c.charCodeAt(0)),
    challenge: f(data.challenge),

    allowCredentials: [
      {
        id: f(data.rawId),
        type: "public-key",
        transports: ["usb", "ble", "nfc"],
      },
    ],
    timeout: 60000,
  };
  const assertion = [
    await navigator.credentials.get({
      publicKey: publicKeyCredentialRequestOptions,
    }),
  ];

  const parsed = assertion.map((item) => {
    return {
      id: item.id,
      rawId: m(item.rawId),
      response: {
        authenticatorData: m(item.response.authenticatorData),
        clientDataJSON: m(item.response.clientDataJSON),
        signature: m(item.response.signature),
      },
      type: item.type,
    };
  })[0];

  //   const assertionData = Object.assign({ parsed, name: person });
  const assertionData = { ...parsed, clientId, authenticatorName };

  console.log("assert", assertionData);

  const valAssert = await apiCall(assertionData, "webauthn/authenticate");
  if (valAssert.data) alert("login successful");
}

// check for support
function supported() {
  return !!(
    navigator.credentials &&
    navigator.credentials.create &&
    navigator.credentials.get &&
    window.PublicKeyCredential
  );
}

console.log(supported());

// convert to base64
function m(e) {
  let i = new Uint8Array(e),
    a = "";
  //localhost:8080/
  http: for (let l of i) a += String.fromCharCode(l);
  return btoa(a).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

// to buffer
function f(e) {
  let i = "==".slice(0, (4 - (e.length % 4)) % 4),
    a = e.replace(/-/g, "+").replace(/_/g, "/") + i,
    c = atob(a),
    s = new ArrayBuffer(c.length),
    l = new Uint8Array(s);
  for (let u = 0; u < c.length; u++) l[u] = c.charCodeAt(u);
  return s;
}

async function apiCall(data, endpoint) {
  let error = true,
    callRes;

  await $.ajax({
    type: "POST",
    url: `${url}/${endpoint}`,
    data: JSON.stringify(data),
    success: (data) => {
      error = false;
      callRes = data;
    },
    error: () => {
      // if(endpoint=="register-request")
      switch (endpoint) {
        case "register-request":
          alert("user already registered");
          break;
        case "register":
          alert("error during registration");
          break;
        default:
          alert("error occured");
          break;
      }
    },
    dataType: "json",
    contentType: "application/json",
  });

  return { data: callRes, error };
}
