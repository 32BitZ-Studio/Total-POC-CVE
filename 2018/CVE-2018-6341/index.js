const path = require('path');
const fs = require('fs');
const express = require('express');

const React = require('react');
const ReactDOMServer = require('react-dom/server');

const PORT = process.env.PORT || 3006;
const app = express();

app.get('/', (req, res) => {
    // Render React component tree to a string in the server
    let props = {};
    let userProvidedData = '></div><script>alert("insert xss here")</script>';
    props[userProvidedData] = "dummy";
    let element = React.createElement("div", {...props}); // non-JSX syntax
    let app = ReactDOMServer.renderToString(element);
    
    // Respond a client with this data
    const indexFile = path.resolve('./public/index.html');
    fs.readFile(indexFile, 'utf8', (err, data) => {
      if (err) {
        console.error('Something went wrong:', err);
        return res.status(500).send('Something went wrong');
      }
  
      return res.send(
        data.replace('<div id="root"></div>', `<div id="root">${app}</div>`)
      );
    });
  });
  
  app.use(express.static('./public'));
  
  app.listen(PORT, () => {
    console.log(`Server is listening on port ${PORT}`);
  });