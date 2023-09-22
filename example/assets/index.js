/** @param {string} base64String */
function urlBase64ToUint8Array(base64String) {
  var padding = "=".repeat((4 - (base64String.length % 4)) % 4);
  var base64 = (base64String + padding).replace(/\-/g, "+").replace(/_/g, "/");

  var rawData = window.atob(base64);
  var outputArray = new Uint8Array(rawData.length);

  for (var i = 0; i < rawData.length; ++i) {
    outputArray[i] = rawData.charCodeAt(i);
  }
  return outputArray;
}

/** @typedef {Promise<{ "public": string }>} VapidKeys */
/** @returns {VapidKeys} */
async function fetchVapidKeys() {
  return fetch("/api/vapid.json").then((resp) => resp.json());
}

/** @param {VapidKeys} vapidKeys */
async function subscribeUserToPush(vapidKeys) {
  const registration = await navigator.serviceWorker.register("service-worker.js");
  registration.update();
  const pushSubscription = await registration.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: urlBase64ToUint8Array(vapidKeys.publicKey),
  });
  console.log("Received PushSubscription: ", pushSubscription);

  return pushSubscription;
}

async function askPermission() {
  const permissionResult = await Notification.requestPermission();
  if (permissionResult !== "granted") {
    throw new Error("We weren't granted permission.");
  }
}

async function main() {
  let details = document.getElementById("details");
  let state = document.getElementById("state");

  try {
    let keys = await fetchVapidKeys();
    await askPermission();
    state.subscription = await subscribeUserToPush(keys);
    details.textContent = JSON.stringify(state.subscription, null, 4);
  } catch (error) {
    if (error instanceof Error) {
      state.innerText = error.message;
    }
  }

  try {
    await fetch("/api/register", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(state.subscription),
    });
  } catch (error) {
    if (error instanceof Error) {
      state.innerText = error.message;
    }
  }
}

document.querySelector("#retry").addEventListener("click", main);
main();
