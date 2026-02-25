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
window.vBulletin=window.vBulletin||{};window.vBulletin.phrase=window.vBulletin.phrase||{};window.vBulletin.phrase.precache=window.vBulletin.phrase.precache||[];window.vBulletin.phrase.precache=$.merge(window.vBulletin.phrase.precache,[]);window.vBulletin.options=window.vBulletin.options||{};window.vBulletin.options.precache=window.vBulletin.options.precache||[];window.vBulletin.options.precache=$.merge(window.vBulletin.options.precache,[]);(function(C,B,A){function D(G){if(G.data("vb-tabbedcontainer-tabs-initialized")=="1"){return }var F=G.data("default-tab")||0;G.tabs({create:function(H,I){G.find(".js-tabs-loading-placeholder").remove();G.find(".js-show-on-tabs-create").removeClass("h-hide");G.tabs("option","active",F)},activate:function(H,I){I.newPanel.find(".js-parent-tab-render-listener").trigger("parent-tab-render")},});G.attr("data-vb-tabbedcontainer-tabs-initialized","1")}function E(){C(function(){var F=C(".js-tabbedcontainer-widget-tab-wrapper");if(!F.length){return }C.each(F,function(G,H){D(C(H))})})}E()})(jQuery,window,window.document);