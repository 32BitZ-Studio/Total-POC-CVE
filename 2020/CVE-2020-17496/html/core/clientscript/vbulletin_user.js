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
(function(C){var D=".js-serialize-form-data";function A(F){var G=C(F.currentTarget),H=G.find(D);H.each(function(K){var M=C(this).data("source"),L=M&&G.find('input[name="'+M+'[]"]:checked')||[],J=[],I="";if(L.length){L.each(function(O,N){J.push(parseInt(N.value,10))});L.prop("disabled",true);I=J.join(",");G.append('<input type="hidden" name="'+M+'_csv" value="'+I+'"/>')}});return true}function B(){var G=C(D),F=G.length&&G.closest("form");if(!F.length){return }F.on("submit",A)}function E(){C(B)}E()})(jQuery);