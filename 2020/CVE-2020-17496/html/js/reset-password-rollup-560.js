// ***************************
// js.compressed/password.js
// ***************************
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
window.vBulletin=window.vBulletin||{};window.vBulletin.phrase=window.vBulletin.phrase||{};window.vBulletin.phrase.precache=window.vBulletin.phrase.precache||[];window.vBulletin.phrase.precache=$.merge(window.vBulletin.phrase.precache,["error","password_needs_numbers","password_needs_special_chars","password_needs_uppercase","password_too_short","passwords_must_match",]);window.vBulletin.options=window.vBulletin.options||{};window.vBulletin.options.precache=window.vBulletin.options.precache||[];window.vBulletin.options.precache=$.merge(window.vBulletin.options.precache,["passwordminlength","passwordrequirenumbers","passwordrequirespecialchars","passwordrequireuppercase",]);(function(C){function B(E,D){vBulletin.error("error",E,function(){D.focus()})}function A(F,H){var D=F.val();if(D.length<vBulletin.options.get("passwordminlength")){B("password_too_short",F);return false}if(vBulletin.options.get("passwordrequireuppercase")&&!D.match(/[A-Z]/)){B("password_needs_uppercase",F);return false}if(vBulletin.options.get("passwordrequirenumbers")&&!D.match(/[0-9]/)){B("password_needs_numbers",F);return false}if(vBulletin.options.get("passwordrequirespecialchars")){var E=vBulletin.regexEscape(" !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"),G=new RegExp("["+E+"]");if(!D.match(G)){B("password_needs_special_chars",F);return false}}if(H&&H.val&&D!=H.val()){B("passwords_must_match",H);return false}return true}window.vBulletin.checkPassword=A})(jQuery);;

// ***************************
// js.compressed/reset-password.js
// ***************************
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
(function(A){function B(){var C=A("#reset-password-form");C.submit(function(F){var D=C.find(':input[name="new-password"]'),E=C.find(':input[name="new-password-confirm"]');if(!vBulletin.checkPassword(D,E)){return false}return true})}A(document).ready(B)})(jQuery);;

