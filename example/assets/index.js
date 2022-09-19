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
  return fetch("vapid.json").then((resp) => resp.json())
}

/** @param {VapidKeys} vapidKeys */
async function subscribeUserToPush(vapidKeys) {
  const registration = await navigator.serviceWorker.register("sw.js");
  registration.update();
  const pushSubscription = await registration.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: urlBase64ToUint8Array(vapidKeys.publicKey),
  });
  console.log("Received PushSubscription: ", JSON.stringify(pushSubscription));
  return pushSubscription;
}

async function askPermission() {
  const permissionResult = await Notification.requestPermission();
  if (permissionResult !== "granted") {
    throw new Error("We weren't granted permission.");
  }
}

async function main() {
  /** @type {HTMLButtonElement} */
  let button = document.getElementById("subscribe");
  let state = document.getElementById("state");
  button.onclick = async () => {
    try {
      let keys = await fetchVapidKeys();
      await askPermission();
      await subscribeUserToPush(keys);
      button.disabled = true;
    } catch (error) {
      if (error instanceof Error) {
        state.innerText = error.message;
      }
    }
  };
}
main();
