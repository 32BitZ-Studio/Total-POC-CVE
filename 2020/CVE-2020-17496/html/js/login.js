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
window.vBulletin=window.vBulletin||{};(function(A){var B=A(document);B.on("submit",".js-login-form-main",function(J){J.preventDefault();var E=A(this),I=E.closest(".js-login-form-main-container"),D=A(".js-error-box",I),H=A(".js-login-message-box",I),F=A(".js-login-button",I);H.height(E.height());var C=function(K){F.prop("disabled",!K);H.toggleClass("h-hide",K);E.toggleClass("h-hide",!K)};var G=function(K){D.html(K).toggleClass("h-hide",!K);E.find(".js-login-username, .js-login-password").toggleClass("badlogin",!!K)};C(false);G("");vBulletin.loadingIndicator.suppressNextAjaxIndicator();vBulletin.AJAX({call:"/auth/ajax-login",data:E.serializeArray(),success:function(){location.reload()},api_error:function(K){G(vBulletin.phrase.get(K[0]));C(true)},after_error:function(){C(true)}})});B.on("focus",".js-login-username, .js-login-password",function(C){A(this).removeClass("badlogin")})})(jQuery);