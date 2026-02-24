<?php
/*========================================================================*\
|| ###################################################################### ||
|| # vBulletin 5.6.0
|| # ------------------------------------------------------------------ # ||
|| # Copyright 2000-2020 MH Sub I, LLC dba vBulletin. All Rights Reserved.  # ||
|| # This file may not be redistributed in whole or significant part.   # ||
|| # ----------------- VBULLETIN IS NOT FREE SOFTWARE ----------------- # ||
|| # http://www.vbulletin.com | http://www.vbulletin.com/license.html   # ||
|| ###################################################################### ||
\*========================================================================*/

// ######################## SET PHP ENVIRONMENT ###########################
error_reporting(E_ALL & ~E_NOTICE);

// ##################### DEFINE IMPORTANT CONSTANTS #######################
define('CVS_REVISION', '$RCSfile$ - $Revision: 102873 $');

// #################### PRE-CACHE TEMPLATES AND DATA ######################
global $phrasegroups, $specialtemplates, $vbphrase;
$phrasegroups = array();
$specialtemplates = array();

// ########################## REQUIRE BACK-END ############################
require_once(dirname(__FILE__) . '/global.php');

// ########################################################################
// ######################### START MAIN SCRIPT ############################
// ########################################################################

$vbulletin->input->clean_array_gpc('r', array(
	'name' => vB_Cleaner::TYPE_STR,
	'dir'  => vB_Cleaner::TYPE_STR
));

$vbulletin->GPC['name'] = preg_replace('#[^a-z0-9_-]#', '', $vbulletin->GPC['name']);

$options = vB::getDatastore()->getValue('options');

?><!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" dir="<?php echo vB_Template_Runtime::fetchStyleVar('textdirection'); ?>" lang="<?php echo vB_Template_Runtime::fetchStyleVar('languagecode'); ?>">
<head>
	<title><?php echo $vbulletin->options['bbtitle'] . " - vBulletin $vbphrase[control_panel]"; ?></title>
	<base href="<?php echo vB::getDatastore()->getOption('frontendurl')?>/" />
	<meta http-equiv="Content-Type" content="text/html; charset=<?php echo vB_Template_Runtime::fetchStyleVar('charset'); ?>" />
	<link rel="stylesheet" type="text/css" href="<?php echo get_cpstyle_href('controlpanel.css'); ?>" />
	<script type="text/javascript">
	var BBURL = "<?php echo $options['bburl']; ?>";
	</script>
	<script type="text/javascript" src="core/clientscript/yui/yahoo-dom-event/yahoo-dom-event.js?v=<?php echo SIMPLE_VERSION; ?>"></script>
	<script type="text/javascript" src="core/clientscript/yui/connection/connection-min.js?v=<?php echo SIMPLE_VERSION; ?>"></script>
	<script type="text/javascript" src="js/jquery/jquery-<?php echo JQUERY_VERSION; ?>.min.js"></script>
	<script type="text/javascript" src="js/jquery/jquery.cookie.min.js?v=<?php echo SIMPLE_VERSION; ?>"></script>
	<script type="text/javascript" src="core/clientscript/vbulletin_global.js?v=<?php echo SIMPLE_VERSION; ?>"></script>
	<script type="text/javascript" src="core/clientscript/vbulletin-core.js?v=<?php echo SIMPLE_VERSION; ?>"></script>
	<script type="text/javascript">
	<!--
	function js_textarea_send(textarea,doclose)
	{
		opener.document.getElementsByName('<?php echo $vbulletin->GPC['name']; ?>')[0].value = textarea.value;
		if (doclose==1)
		{
			opener.focus();
			self.close();
		}
	}
	// -->
	</script>
</head>
<body onload="self.focus(); fetch_object('popuptextarea').value=opener.document.getElementsByName('<?php echo $vbulletin->GPC['name']; ?>')[0].value;" style="margin:0px">
<form name="popupform" tabindex="1">
<table cellpadding="4" cellspacing="0" border="0" width="100%" height="100%" class="tborder">
<tr>
	<td class="tcat" align="center"><b><?php echo $vbphrase['edit_text']; ?></b></td>
</tr>
<tr>
	<td class="alt1" align="center"><textarea name="popuptextarea" id="popuptextarea" class="code" style="width:95%; height:500px" onkeydown="js_textarea_send(this, 0);" onkeyup="js_textarea_send(this, 0);" dir="<?php echo ($vbulletin->GPC['dir'] ? 'ltr' : 'rtl') ?>"></textarea></td>
</tr>
<tr>
	<td class="tfoot" align="center">
	<input type="button" class="button" value="<?php echo $vbphrase['send']; ?>" onclick="js_textarea_send(this.form.popuptextarea, 1);" accesskey="s" />
	</td>
</tr>
</table>
</form>
</body>
</html>

<?php

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102873 $
|| #######################################################################
\*=========================================================================*/
