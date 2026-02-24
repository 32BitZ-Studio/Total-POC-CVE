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
(function(A){A(document).ready(function(){A(".js-synlist-container .cbsubgroup-trigger").off("click").on("click",function(){var C=A(this).closest(".js-synlist-container");var D=!C.find(".cbsubgroup").toggleClass("hide").is(".hide");C.find(".js-synlist-collapseclose").toggleClass("hide",!D);C.find(".js-synlist-collapseopen").toggleClass("hide",D)});var B=A(".js-tag-phrase-data");if(B.length){(new vB_Inline_Mod("inlineMod_tags","tag","tagsform",B.data("gox"),"vbulletin_inline"))}})})(jQuery);