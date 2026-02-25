const axios = require("axios");

(async function () {
  await axios.get("http://localhost:3000/redirect?url=http://localhost:8182", {
    headers: {
      Cookie: "session=some-secret-value",
    },
  });
})();
