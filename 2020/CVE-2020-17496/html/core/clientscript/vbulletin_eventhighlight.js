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
(function(D){function B(){var G=!!D(".js-checkable-toggle:checked").length;D(".js-checkable").prop("checked",G)}function F(){var I=D(".js-checkable"),H=D(".js-checkable:checked"),G=I.length==H.length;D(".js-checkable-toggle").prop("checked",G)}function A(){var G=D(".js-colorpicker-data");if(G.length==1){window.vbphrase=window.vbphrase||{};D.each(G.data("phrases"),function(I,H){window.vbphrase[I]=H});window.bburl=G.data("bburl");window.cpstylefolder=G.data("cpstylefolder");window.colorPickerWidth=G.data("colorpickerwidth");window.colorPickerType=G.data("colorpickertype")}if(typeof init_color_preview=="function"){init_color_preview()}}function C(){D(".js-checkable-toggle").off("click",B).on("click",B);D(".js-checkable").off("click",F).on("click",F);A()}function E(){D(C)}E()})(jQuery);