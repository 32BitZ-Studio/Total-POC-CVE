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
(function(A){function B(){var C=A("#reset-password-form");C.submit(function(F){var D=C.find(':input[name="new-password"]'),E=C.find(':input[name="new-password-confirm"]');if(!vBulletin.checkPassword(D,E)){return false}return true})}A(document).ready(B)})(jQuery);