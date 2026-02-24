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
window.vBulletin=window.vBulletin||{};window.vBulletin.phrase=window.vBulletin.phrase||{};window.vBulletin.phrase.precache=window.vBulletin.phrase.precache||[];window.vBulletin.phrase.precache=$.merge(window.vBulletin.phrase.precache,[]);(function(C){function A(E){B(C(E.target).data("item-name"));return false}function B(E){C(".js-markup-library-item").removeClass("b-comp-menu-vert__item--selected").filter(function(){return C(this).data("item-name")==E}).addClass("b-comp-menu-vert__item--selected");C(".js-markup-library-item-content").addClass("h-hide").filter(function(){return C(this).data("item-name")==E}).removeClass("h-hide")}function D(){var F=C(".js-markup-library-item"),E=F.find(".b-comp-menu-vert__item--selected");if(E.length==0){E=F}F.on("click",A);B(E.first().data("item-name"))}C(D)})(jQuery);