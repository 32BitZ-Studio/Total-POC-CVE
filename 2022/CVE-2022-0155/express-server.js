const express = require("express");
const app = express();
const port = 3000;

app.get("/redirect", (req, res) => {
  console.log(req.query);
  const url = req.query.url;
  if (url) {
    res.redirect(url);
  } else {
    res.status(400).send("Bad Request: URL parameter is missing.");
  }
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
