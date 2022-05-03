// let clientDataJSON;
// let publicKey;
// let credentialId;

// let dbPubkey = undefined;

const url = "http://localhost:8000";

// webauthn create
async function webCreate() {
  const person = prompt("Please enter your name");

  // get challenge
  const { data, error } = await apiCall({ name: person }, "register-request");

  if (error) return;

  const publicKeyCredentialCreationOptions = {
    challenge: Uint8Array.from(data, (c) => c.charCodeAt(0)),
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
      authenticatorAttachment: "cross-platform",
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

  const attestationData = Object.assign({ parsed, name: person });

  const validateAttestion = apiCall(attestationData, "register");
  alert("user registered");
}

// webauth get

async function webGet() {
  const person = prompt("Please enter your name");

  // get rawId and challenge
  const { data, error } = await apiCall({ name: person }, "login-request");

  if (error) return;
  const publicKeyCredentialRequestOptions = {
    challenge: Uint8Array.from(data.challenge, (c) => c.charCodeAt(0)),
    allowCredentials: [
      {
        id: f(data.webId),
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

  const assertionData = Object.assign({ parsed, name: person });

  const valAssert = await apiCall(assertionData, "login");
  if (valAssert.data) alert("login successful");
}

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
