/*=======================================================================*\
|| ###################################################################### ||
|| # vBulletin 5.6.0
|| # ------------------------------------------------------------------ # ||
|| # Copyright 2000-2020 MH Sub I, LLC dba vBulletin. All Rights Reserved.  # ||
|| # This file may not be redistributed in whole or significant part.   # ||
|| # ----------------- VBULLETIN IS NOT FREE SOFTWARE ----------------- # ||
|| # http://www.vbulletin.com | http://www.vbulletin.com/license.html   # ||
|| ###################################################################### ||
\*========================================================================*/
(function(){window.vBulletin=window.vBulletin||{};window.vBulletin.Responsive=window.vBulletin.Responsive||{};window.vBulletin.Responsive.Debounce=window.vBulletin.Responsive.Debounce||{};vBulletin.Responsive.Debounce.checkBrowserSize=(function(){function A(G){return G.replace(/^\s+/,"").replace(/\s+$/,"")}function D(G){var H=G.className+"";if(H!=""){H=" "+A(H.replace(/\s+/g," "))+" "}return H}function B(G,H){return(G.indexOf(" "+H+" ")!=-1)}function C(G,H){var I=D(G);if(!B(I,H)){G.className=A(I+H)}}function F(H,I){var J=D(H),G=J;while(true){if(!B(G,I)){break}G=G.replace(" "+I+" "," ")}if(J!=G){H.className=A(G)}}function E(){if(!Modernizr){return }if(Modernizr.mq("(max-width: 479px)")){C(document.body,"l-xsmall")}else{F(document.body,"l-xsmall")}if(Modernizr.mq("(max-width: 767px)")){C(document.body,"l-small")}else{F(document.body,"l-small")}if(Modernizr.mq("(min-width: 768px)")){C(document.body,"l-desktop")}else{F(document.body,"l-desktop")}}return E})()})();