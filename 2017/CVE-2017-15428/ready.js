// Credit: https://github.com/saelo/cve-2018-4233/blob/master/ready.js
// Simple promise to be resolved when the document is loaded.
// Subsequent code can simply do
//
//      ready = Promise.all([ready, new Promise(...)]);
//
// to add more dependencies.
var ready = new Promise(function(resolve) {
    if (typeof(window) === 'undefined')
        resolve();
    else
        window.onload = function() {
            resolve();
        }
});
