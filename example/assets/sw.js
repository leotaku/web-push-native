self.addEventListener("activate", () => {
  console.log("activate");
  clients.claim();
});

self.addEventListener("install", () => {
  console.log("install");
  self.skipWaiting();
});

self.addEventListener("push", async (event) => {
  try {
    console.log("push");
    let data = event.data.json();
    const options = {
      body: data.body,
    };
    await self.registration.showNotification(data.title, options);
  } catch (err) {
    console.log(err)
  }
});
