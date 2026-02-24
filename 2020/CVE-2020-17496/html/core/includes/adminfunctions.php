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

/**
 * @package vBLegacy
 */
global $vbulletin;
error_reporting(E_ALL & ~E_NOTICE);
define('ADMINHASH', md5(vB_Request_Web::$COOKIE_SALT . $vbulletin->userinfo['userid'] . $vbulletin->userinfo['secret']));
// #############################################################################

/**
* Displays the login form for the various control panel areas
*
* The actual form displayed is dependent upon the VB_AREA constant
*/
function print_cp_login($mismatch = false)
{
	global $vbulletin, $vbphrase;

	if ($vbulletin->GPC['ajax'])
	{
		print_stop_message2('you_have_been_logged_out_of_the_cp');
	}

	$userInfo =  vB::getCurrentSession()->fetch_userinfo();
	$focusfield = ($userInfo['userid'] == 0 ? 'username' : 'password');

	$vbulletin->input->clean_array_gpc('r', array(
		'vb_login_username' => vB_Cleaner::TYPE_NOHTML,
		'loginerror'        => vB_Cleaner::TYPE_STR,
		'loginerror_arr'		=> vB_Cleaner::TYPE_ARRAY_STR,
		'strikes'           => vB_Cleaner::TYPE_INT,
	));

	$options = vB::getDatastore()->getValue('options');

	$printusername = '';
	if (!empty($vbulletin->GPC['vb_login_username']))
	{
		$printusername = $vbulletin->GPC['vb_login_username'];
	}
	else if($userInfo['userid'])
	{
		//email only
		if($options['logintype'] == 0)
		{
			$printusername = $userInfo['email'];
		}
		else
		{
			$printusername = $userInfo['username'];
		}
	}

	$vbulletin->userinfo['badlocation'] = 1;

	switch(VB_AREA)
	{
		case 'AdminCP':
			$pagetitle = $vbphrase['admin_control_panel'];
			$getcssoptions = fetch_cpcss_options();
			$cssoptions = array();
			foreach ($getcssoptions AS $folder => $foldername)
			{
				$key = ($folder == $options['cpstylefolder'] ? '' : $folder);
				$cssoptions["$key"] = $foldername;
			}
			$showoptions = true;
			$logintype = 'cplogin';
		break;

		case 'ModCP':
			$pagetitle = $vbphrase['moderator_control_panel'];
			$showoptions = false;
			$logintype = 'modcplogin';
		break;

		default:
			// Legacy Hook 'admin_login_area_switch' Removed //
	}

	define('NO_PAGE_TITLE', true);
	print_cp_header($vbphrase['log_in'], "document.forms.loginform.vb_login_$focusfield.focus()");

	require_once(DIR . '/includes/functions_misc.php');
	$postvars = construct_post_vars_html();

	$forumhome_url = vB5_Route::buildUrl('home|fullurl');

	//Don't to pull the customized style here.  If we're logging in we don't have a user so use the configured default
	?>
	<script type="text/javascript" src="core/clientscript/vbulletin_md5.js?v=<?php echo SIMPLE_VERSION; ?>"></script>
	<script type="text/javascript">
	<!--
	function js_show_options(objectid, clickedelm)
	{
		fetch_object(objectid).style.display = "";
		clickedelm.disabled = true;
	}
	function js_fetch_url_append(origbit,addbit)
	{
		if (origbit.search(/\?/) != -1)
		{
			return origbit + '&' + addbit;
		}
		else
		{
			return origbit + '?' + addbit;
		}
	}
	function js_do_options(formobj)
	{
		if (typeof(formobj.nojs) != "undefined" && formobj.nojs.checked == true)
		{
			formobj.url.value = js_fetch_url_append(formobj.url.value, 'nojs=1');
		}
		return true;
	}
	//-->
	</script>
	<form action="login.php?do=login" method="post" name="loginform" onsubmit="md5hash(vb_login_password, vb_login_md5password, vb_login_md5password_utf); js_do_options(this)">
	<input type="hidden" name="url" value="<?php echo $vbulletin->scriptpath; ?>" />
	<input type="hidden" name="s" value="<?php echo vB::getCurrentSession()->get('dbsessionhash'); ?>" />
	<input type="hidden" name="securitytoken" value="<?php echo $vbulletin->userinfo['securitytoken']; ?>" />
	<input type="hidden" name="logintype" value="<?php echo $logintype; ?>" />
	<input type="hidden" name="do" value="login" />
	<input type="hidden" name="vb_login_md5password" value="" />
	<input type="hidden" name="vb_login_md5password_utf" value="" />
	<?php echo $postvars ?>
	<p>&nbsp;</p><p>&nbsp;</p>
	<table class="tborder" cellpadding="0" cellspacing="0" border="0" width="450" align="center"><tr><td>

		<!-- header -->
		<div class="tcat" style="text-align:center"><b><?php echo $vbphrase['log_in']; ?></b></div>
		<!-- /header -->

		<!-- logo and version -->
		<table cellpadding="4" cellspacing="0" border="0" width="100%" class="login-logo">
		<tr valign="bottom">
			<td><img src="core/cpstyles/<?php echo $options['cpstylefolder']; ?>/cp_logo.<?php echo $options['cpstyleimageext']; ?>" title="<?php echo $vbphrase['vbulletin_copyright']; ?>" border="0" /></td>
			<td>
				<b><a href="<?php echo $forumhome_url ?>"><?php echo $options['bbtitle']; ?></a></b><br />
				<?php echo "vBulletin " . $options['templateversion'] . " $pagetitle"; ?><br />
				&nbsp;
			</td>
		</tr>
		<?php

		if ($mismatch)
		{
			?>
			<tr>
				<td colspan="2" class="navbody"><b><?php echo $vbphrase['to_continue_this_action']; ?></b></td>
			</tr>
			<?php
		}

		$error = array();
		if ($vbulletin->GPC['loginerror'])
		{
			//old style error left in for backwards compatibility.
			$error = array($vbulletin->GPC['loginerror'], vB5_Route::buildUrl('lostpw|fullurl'), $vbulletin->GPC['strikes']);
		}
		else if ($vbulletin->GPC['loginerror_arr'])
		{
			//this handles arbitrary error arrays by passing all of the params through.  Need to make
			//sure we don't introduce a XSS exploit here.
			$error = array_map('htmlspecialchars', $vbulletin->GPC['loginerror_arr']);

			//make sure that we don't have any javascript: style urls in the phrase data.
			foreach($error AS $key => $value)
			{
				if(preg_match('#^javascript:#', $value))
				{
					$error[$key] = '';
				}
			}
		}

		if ($error)
		{
			$errortext = vB_Api::instanceInternal('phrase')->renderPhrases(array('loginerror' => $error));
			$errortext = $errortext['phrases']['loginerror'];
			?>
			<tr>
				<td colspan="2" class="navbody error"><b><?php echo $errortext ?></b></td>
			</tr>
			<?php
		}

		?>
		</table>
		<!-- /logo and version -->

		<table cellpadding="4" cellspacing="0" border="0" width="100%" class="alt1">
		<col width="50%" style="text-align:<?php echo vB_Template_Runtime::fetchStyleVar('right'); ?>; white-space:nowrap"></col>
		<col></col>
		<col width="50%"></col>

		<!-- login fields -->
<?php
		switch( intval($options['logintype']) )
		{
			case 0:
				//email
				$namefield = $vbphrase['email'];
				break;
			case 1:
				// username
				$namefield = $vbphrase['username'];
				break;
			case 2:
				// both
				$namefield = $vbphrase['username_or_email'];
				break;
			default:
				// should not happen.
				break;
		}

		$fields = array();
		$fields[] = array(
			'label' => $namefield,
			'type' => 'text',
			'name' => 'vb_login_username',
			'value' => $printusername,
			'accesskey' => 'u',
			'tabindex' => '1',
			'id' => 'vb_login_username',
		);

		$fields[] = array(
			'label' => $vbphrase['password'],
			'type' => 'password',
			'name' => 'vb_login_password',
			'autocomplete' => 'off',
			'accesskey' => 'p',
			'tabindex' => '2',
			'id' => 'vb_login_password',
		);

		$needMfa = vB_Api::instanceInternal('user')->needMfa($logintype);
		if ($needMfa['enabled'])
		{
			$fields[] = array(
				'label' => $vbphrase['mfa_auth'],
				'type' => 'text',
				'name' => 'vb_login_mfa_authcode',
				'autocomplete' => 'off',
				'tabindex' => '3',
				'id' => 'vb_login_mfa_authcode',
			);
		}

		//should probably be moved to CSS, but that's the first thread in a big ball of yarn.
		$fieldstyle = 'padding-' . vB_Template_Runtime::fetchStyleVar('left') . ':5px; font-weight:bold; width:250px';

		echo '<tbody>';

		foreach($fields AS $index => $field)
		{
			$label = $field['label'];
			unset($field['label']);

			$attributes = array();
			foreach($field AS $name => $value)
			{
				$attributes[] = $name . '="' . $value . '"';
			}

			echo
				'<tr>
					<td>' . $label . '</td>
					<td><input style="' .  $fieldstyle . '" ' . implode(' ', $attributes) . ' /></td>
					<td>&nbsp;</td>
				</tr>';
		}

		echo '</tbody>';
?>
		<tr style="display: none" id="cap_lock_alert">
			<td>&nbsp;</td>
			<td class="tborder"><?php echo $vbphrase['caps_lock_is_on']; ?></td>
			<td>&nbsp;</td>
		</tr>
		</tbody>
		<!-- /login fields -->

		<?php if ($showoptions) { ?>
		<!-- admin options -->
		<tbody id="loginoptions" style="display:none">
		<tr>
			<td><?php echo $vbphrase['style']; ?></td>
			<td><select name="cssprefs" class="login" style="padding-<?php echo vB_Template_Runtime::fetchStyleVar('left'); ?>:5px; font-weight:normal; width:250px" tabindex="5"><?php echo construct_select_options($cssoptions, $csschoice); ?></select></td>
			<td>&nbsp;</td>
		</tr>
		<tr>
			<td><?php echo $vbphrase['options']; ?></td>
			<td>
				<label><input type="checkbox" name="nojs" value="1" tabindex="6" /> <?php echo $vbphrase['save_open_groups_automatically']; ?></label>
			</td>
			<td class="login">&nbsp;</td>
		</tr>
		</tbody>
		<!-- END admin options -->
		<?php } ?>

		<!-- submit row -->
		<tbody>
		<tr>
			<td colspan="3" align="center">
				<input type="submit" class="button" value="  <?php echo $vbphrase['log_in']; ?>  " accesskey="s" tabindex="3" />
				<?php if ($showoptions) { ?><input type="button" class="button" value=" <?php echo $vbphrase['options']; ?> " accesskey="o" onclick="js_show_options('loginoptions', this)" tabindex="4" /><?php } ?>
			</td>
		</tr>
		</tbody>
		<!-- /submit row -->
		</table>

	</td></tr></table>
	</form>
	<script type="text/javascript">
	<!--
	function caps_check(e)
	{
		var detected_on = detect_caps_lock(e);
		var alert_box = fetch_object('cap_lock_alert');

		if (alert_box.style.display == '')
		{
			// box showing already, hide if caps lock turns off
			if (!detected_on)
			{
				alert_box.style.display = 'none';
			}
		}
		else
		{
			if (detected_on)
			{
				alert_box.style.display = '';
			}
		}
	}
	fetch_object('vb_login_password').onkeypress = caps_check;
	//-->
	</script>
	<?php

	define('NO_CP_COPYRIGHT', true);
	unset($GLOBALS['DEVDEBUG']);
	print_cp_footer();
}


/**
 * Cover function for extra scripts -- primarily used by tools.php
 *
 * Intended to allow us to split the logic from print_cp_header if needed at a later
 * date.  print_cp_header has a growing number of parameters which is an indication
 * that it may be serving too many masters already.
 *
 * @param	string	The page title
 * @param 	string 	The base url (should be to the site root).  If blank will use the url set in the options.
 */
function print_tools_header($title, $base)
{
	return print_cp_header($title, '', '', 0, '', $base);
}

// #############################################################################
/**
* Starts Gzip encoding and prints out the main control panel page start / header
*
* @param	string	The page title
* @param	string	Javascript functions to be run on page start - for example "alert('moo'); alert('baa');"
* @param	string	Code to be inserted into the <head> of the page
* @param	integer	Width in pixels of page margins (default = 0)
* @param	string	HTML attributes for <body> tag - for example 'bgcolor="red" text="orange"'
* @param 	string 	The base url (should be to the site root).  If blank will use the url set in the options.
* @param 	string 	Note to the right of the title
*/
function print_cp_header($title = '', $onload = '', $headinsert = '', $marginwidth = 0, $bodyattributes = '', $base = '', $titlenote= '')
{
	global $vbulletin, $vbphrase;

	$options = vB::getDatastore()->getValue('options');
	$userinfo = vB_User::fetchUserinfo(0, array('admin'));

	// start GZ encoding output
	if ($options['gzipoutput'] AND !$vbulletin->nozip AND !headers_sent() AND function_exists('ob_start') AND function_exists('crc32') AND function_exists('gzcompress'))
	{
		// This will destroy all previous output buffers that could have been stacked up here.
		while (ob_get_level())
		{
			@ob_end_clean();
		}
		ob_start();
	}

	$titlestring =  $options['bbtitle'];
	if($title)
	{
		$titlestring = $title . '- ' . $titlestring;
	}

	// get the appropriate <title> for the page
	switch(VB_AREA)
	{
		case 'AdminCP':
			$titlestring = $titlestring . " - vBulletin $vbphrase[admin_control_panel]";
			break;
		case 'ModCP':
			$titlestring . " - vBulletin $vbphrase[moderator_control_panel]";
			break;
		case 'Upgrade':
		case 'Install':
			$titlestring = 'vBulletin ' . $titlestring;
			break;
	}

	if (!$base)
	{
		$base = $options['frontendurl'] . '/';
	}

	// set up some options for nav-panel and head frames
	if (defined('IS_NAV_PANEL'))
	{
		$htmlattributes = ' class="navbody"';
		$bodyattributes .= ' class="navbody"';
		$base = '<base target="main" href="' . $base .'" />';
	}
	else
	{
		$htmlattributes = '';
		$base = '<base href="' . $base .'" />';
	}


	// print out the page header
	echo '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">' . "\r\n";
	echo "<html xmlns=\"http://www.w3.org/1999/xhtml\" dir=\"" . vB_Template_Runtime::fetchStyleVar('textdirection') . "\" lang=\"" . vB_Template_Runtime::fetchStyleVar('languagecode') . "\"$htmlattributes>\r\n";
	echo "<head>
	$base
	<title>$titlestring</title>
	<meta http-equiv=\"Content-Type\" content=\"text/html; charset=" . vB_Template_Runtime::fetchStyleVar('charset') . "\" />
	<link rel=\"stylesheet\" type=\"text/css\" href=\"core/cpstyles/global.css?v={$options['simpleversion']}\" />
	<link rel=\"stylesheet\" type=\"text/css\" href=\"core/cpstyles/" . $userinfo['cssprefs'] . "/controlpanel.css?v={$options['simpleversion']}\" />
	<style type=\"text/css\">
		.page { background-color:white; color:black; }
		.time { color:silver; }
		.error { color:red; }
		/* Start generic feature management styles */

		.feature_management_header {
			font-size:16px;
		}

		/* End generic feature management styles */


		/* Start Styles for Category Manager */

		#category_title_controls {
			padding-" . vB_Template_Runtime::fetchStyleVar('left') . ": 10px;
			font-weight:bold;
			font-size:14px;
		}

		.picker_overlay {
			/*
				background-color:black;
				color:white;
			*/
			background-color:white;
			color:black;
			font-size:14px;
			padding:3px;
			border:1px solid black;
		}

		.selected_marker {
			margin-" . vB_Template_Runtime::fetchStyleVar('right') . ":4px;
			margin-top:4px;
			float:" . vB_Template_Runtime::fetchStyleVar('left') . ";
		}

		.section_name {
			font-size:14px;
			font-weight:bold;
			padding:0.2em 1em;
			margin: 0.5em 0.2em;
			/*
			color:#a2de97;
			background-color:black;
			*/
			background-color:white;
		}

		.tcat .picker_overlay a, .picker_overlay a, a.section_switch_link {
			/*
			color:#a2de97;
			*/
			color:blue;
		}

		.tcat .picker_overlay a:hover, .picker_overlay a:hover, a.section_switch_link:hover {
			color:red;
		}
		/* End Styles for Category Manager */


		/* Start Styles for CMS Pages */
		.b-pagination {
			display: inline-block;
		}
		.b-pagination a {
			padding: 2px;
			cursor: pointer;
			background: #FFFFFF;
			border: 1px solid #BFC5C9;
		}
		.b-pagination a.selected {
			background: #37ACFE;
			border: 1px solid #2989CC;
			color: #FFFFFF;
		}

		.h-wordwrap {
			word-wrap: break-word;
		}

		.h-margin-top-s {
			margin-top:10px;
		}
		.h-margin-bottom-s {
			margin-bottom:10px;
		}

		.h-margin-top-xs {
			margin-top:3px;
		}

		.h-width-xl {
			width: 45%;
		}

		.h-width-l {
			width: 25%;
		}

		.h-width-m {
			width: 10%;
		}

		.h-width-s {
			width: 5%;
		}

		/* DatePicker Container */
		.ui-datepicker {
			border: 1px solid #2989CC;
			padding: 5px;
			background-color: #FFFFFF;
		}
		.ui-datepicker td {
			padding: 1px;
		}
		.ui-datepicker a {
			cursor: pointer;
			display: block;
			padding: .2em;
			text-align: right;
			text-decoration: none;
		}
		.ui-datepicker .ui-datepicker-title { margin: 0 2.3em; line-height: 1.8em; text-align: center; }
		.ui-datepicker .ui-datepicker-prev, .ui-datepicker .ui-datepicker-next { position:absolute; top: 2px; width: 1.8em; height: 1.8em; }
		.ui-datepicker .ui-datepicker-prev {" . vB_Template_Runtime::fetchStyleVar('left') . ":2px; }
		.ui-datepicker .ui-datepicker-next {" . vB_Template_Runtime::fetchStyleVar('right') . ":2px; }
		#ui-datepicker-div { display:none }
		/* End of DatePicker Container */

		/* End Styles for CMS Pages */

		/* Start styles for utility functions*/
		.alt1 .collapse {
			background-color: #F6F6F6;
		}
		.alt2 .collapse {
			background-color: #FFF;
		}
		.collapse input.collapse-control,
		input.table-collapse-control {
			display: none;
		}
		.collapse-label {
			display: block;
			cursor: pointer;
			color: white;
			#text-decoration: underline;
			font-weight:bold;
			padding: 3px;
			background-color: #53575E;

			-webkit-user-select: none; /* Safari */
			-moz-user-select: none; /* Firefox */
			-ms-user-select: none; /* IE10+/Edge */
			user-select: none; /* Standard */
		}
		.collapse-content {
			padding-top: 5px;
			padding-bottom: 5px;
		}
		/*
			Note
			... table tr.collapse-toggle ~ tr
			instead of
			... table tr.collapse-toggle ~ tr:not(.collapse-toggle)
			is an intentional design decision. This will allow
			inserting multiple collapse/expand (which are paired)
			controls in a long table so that the collapse is easily
			accessible without having to scroll all the way up or down,
			and when collapsed only the first expand control will be
			visible.
		 */
		.collapse input.collapse-control ~ .collapse-content,
		.collapse input.collapse-control ~ .collapse-hide-on-collapse,
		.collapse input:checked.collapse-control ~ .collapse-show-on-collapse,
		input.table-collapse-control ~ table tr.collapse-toggle ~ tr,
		input.table-collapse-control ~ table .collapse-hide-on-collapse,
		input:checked.table-collapse-control ~ table .collapse-show-on-collapse {
			visibility: visible;
			display:none;
		}
		.collapse input:checked.collapse-control ~ .collapse-content,
		.collapse input:checked.collapse-control ~ .collapse-hide-on-collapse,
		.collapse input:not(:checked).collapse-control ~ .collapse-show-on-collapse,
		input:checked.table-collapse-control ~ table .collapse-hide-on-collapse,
		input:not(:checked).table-collapse-control ~ table .collapse-show-on-collapse {
			display: block;
		}
		input:checked.table-collapse-control ~ table tr.collapse-toggle ~ tr {
			display: table-row;
		}
		/* End styles for utility functions */

		/* Styles that need Stylevars */
		#acp-top-links .left {
			float: " . vB_Template_Runtime::fetchStyleVar('left') . ";
		}
		#acp-top-links .right {
			float: " . vB_Template_Runtime::fetchStyleVar('right') . ";
		}
		#acp-top-links li.rightmost {
			padding-" . vB_Template_Runtime::fetchStyleVar('right') . ": 0;
		}
		.acp-nav-controls a.nav-left {
			float: " . vB_Template_Runtime::fetchStyleVar('left') . ";
			margin-" . vB_Template_Runtime::fetchStyleVar('right') . ": 0px;
		}
		.acp-nav-controls a.nav-right {
			float: " . vB_Template_Runtime::fetchStyleVar('left') . ";
			margin-" . vB_Template_Runtime::fetchStyleVar('right') . ": 0px;
			margin-" . vB_Template_Runtime::fetchStyleVar('left') . ": 4px;
		}
		.navtitle {
			padding-" . vB_Template_Runtime::fetchStyleVar('left') . ": 20px;
		}
		.acp-nav-arrow {
			margin-" . vB_Template_Runtime::fetchStyleVar('right') . ": 20px;
		}
		.navgroup a {
			padding-" . vB_Template_Runtime::fetchStyleVar('left') . ": 20px;
		}
		.tcat {
			text-align: " . vB_Template_Runtime::fetchStyleVar('left') . ";
		}
		#acp-logo-bar .logo {
			float: " . vB_Template_Runtime::fetchStyleVar('left') . ";
		}
		#acp-logo-bar .links {
			float: " . vB_Template_Runtime::fetchStyleVar('left') . ";
		}
		#acp-logo-bar .header-item {
			float: " . vB_Template_Runtime::fetchStyleVar('left') . ";
			margin-" . vB_Template_Runtime::fetchStyleVar('right') . ": 15px;
		}
		#acp-logo-bar .search {
			float: " . vB_Template_Runtime::fetchStyleVar('right') . ";
			margin-" . vB_Template_Runtime::fetchStyleVar('right') . ": 35px;
		}
		#acp-logo-bar .search .button {
			float:" . vB_Template_Runtime::fetchStyleVar('right') . ";
			margin-" . vB_Template_Runtime::fetchStyleVar('left') . ": 5px;
			margin-" . vB_Template_Runtime::fetchStyleVar('right') . ": 0;
		}
		.tfoot {
			text-align: " . vB_Template_Runtime::fetchStyleVar('right') . ";
		}
		.tfoot ul {
			text-align: " . vB_Template_Runtime::fetchStyleVar('left') . ";
		}
		.hide {
			display:none;
		}
		.adminmessage-button-item,
		/* extra selectors to override other css */
		.button.adminmessage-button-item {
			margin: 0;
			margin-" . vB_Template_Runtime::fetchStyleVar('left') . ": 10px;
			min-width: 20px;
			display: inline-block;
		}

		/* this duplicates frontend css, which isn't available here */
		.h-left {
			float: " . vB_Template_Runtime::fetchStyleVar('left') . ";
		}
		.h-right {
			float: " . vB_Template_Runtime::fetchStyleVar('right') . ";
		}

	" . (vB::getDbAssertor()->getDBConnection()->doExplain ? "
		.query { background: #FFF; border: 1px solid red; margin: 0 0 10px 0; padding: 10px; }
		.query h4 { margin: 0 0 10px 0; }
		.query pre {display:block;overflow:auto;border:1px solid black;margin:0 0 10px 0;padding:10px;background:#F6F6F6;}
		.query pre.trace {height: 30px; cursor: pointer; margin: 10px 0 0 0; background: #FCFCFC;}
		.query ul {padding:0;margin:0;list-style:none;}
		.query table {margin:0 0 10px 0;background:#000;}
		.query table th {background:#F6F6F6;text-align:left;}
		.query table td {background:#FFF;}
	" : "") . "
	</style>
	<script type=\"text/javascript\">
	<!--
	var SESSIONHASH = \"" . vB::getCurrentSession()->get('sessionhash') . "\";
	var ADMINHASH = \"" . ADMINHASH . "\";
	var SECURITYTOKEN = \"" . $userinfo['securitytoken'] . "\";
	var IMGDIR_MISC = \"core/cpstyles/" . $userinfo['cssprefs'] . "\";
	var BBURL = \"" . $options['bburl'] . "\";
	//-->
	</script>
	<script type=\"text/javascript\" src=\"core/clientscript/yui/yuiloader-dom-event/yuiloader-dom-event.js\"></script>
	<script type=\"text/javascript\" src=\"core/clientscript/yui/connection/connection-min.js\"></script>
	<script type=\"text/javascript\" src=\"js/jquery/jquery-" . JQUERY_VERSION . ".min.js\"></script>
	<script type=\"text/javascript\" src=\"js/jquery/jquery.cookie.min.js?v=" . SIMPLE_VERSION . "\"></script>
	<script type=\"text/javascript\" src=\"core/clientscript/vbulletin_global.js\"></script>
	<script type=\"text/javascript\" src=\"core/clientscript/vbulletin-core.js\"></script>\n\r
	$headinsert
";

	$vb5_config = vB::getConfig();
	$isDebug = ($vb5_config['Misc']['debug'] ? '1' : '0');
	$isSiteOff = ($options['bbactive'] ? '0' : '1');

	echo "</head>\r\n";
	echo "<body style=\"margin:{$marginwidth}px\" onload=\"$onload\"$bodyattributes>\r\n";
	echo '<div class="js-admincp-data hide" data-debug="' . $isDebug . '" data-siteoff="' . $isSiteOff . '"></div>';

	if($title != '' AND !defined('IS_NAV_PANEL') AND !defined('NO_PAGE_TITLE'))
	{
		echo
			'<div class="pagetitle-container">' .
				'<div class="pagetitle">' . $title .	'</div>' .
				'<div class="pagetitle-note">' . $titlenote . '</div>'.
			'</div>' . "\r\n" .
			'<div class="acp-content-wrapper">' . "\r\n";
	}
	echo "<!-- END CONTROL PANEL HEADER -->\r\n\r\n";
	define('DONE_CPHEADER', true);
}

function print_cp_description($phrases, $file, $action)
{
	$text = $phrases["admincp_description_{$file}_{$action}"] ?? '';
	if($text)
	{
		print_table_start(null, null, 0, 'description_table', false, false);
		print_description_row($text, false, 1);
		print_table_footer(1, '', '', false);
	}
}

// #############################################################################
/**
* Prints the page footer, finishes Gzip encoding and terminates execution
*/
function print_cp_footer()
{
	global $vbulletin, $level, $vbphrase;
	$vb5_config = vB::getConfig();

	echo "\r\n\r\n<!-- START CONTROL PANEL FOOTER -->\r\n";

	if ($vb5_config['Misc']['debug'])
	{
		echo '<br /><br />';
		if (defined('CVS_REVISION'))
		{
			$re = '#^\$' . 'RCS' . 'file: (.*\.php),v ' . '\$ - \$' . 'Revision: ([0-9\.]+) \$$#siU';
			$cvsversion = preg_replace($re, '\1, CVS v\2', CVS_REVISION);
		}
		if (isset($GLOBALS['DEVDEBUG']) AND $size = sizeof($GLOBALS['DEVDEBUG']))
		{
			$displayarray = array();
			$displayarray[] = "<select id=\"moo\"><option selected=\"selected\">DEBUG MESSAGES ($size)</option>\n" . construct_select_options($GLOBALS['DEVDEBUG'],-1,1) . "\t</select>";
			if (defined('CVS_REVISION'))
			{
				$displayarray[] = "<p style=\"font: bold 11px tahoma;\">$cvsversion</p>";
			}
			$displayarray[] = "<p style=\"font: bold 11px tahoma;\">SQL Queries (" . $vbulletin->db->querycount . ")</p>";

			$buttons = "<input type=\"button\" class=\"button\" value=\"Explain\" onclick=\"window.location = '" . $vbulletin->scriptpath . iif(strpos($vbulletin->scriptpath, '?') > 0, '&amp;', '?') . 'explain=1' . "';\" />" . "\n" . "<input type=\"button\" class=\"button\" value=\"Reload\" onclick=\"window.location = window.location;\" />";

			//this doesn't work (the docs/phrasedev.php was removed a long time ago), but its not clear what purpose this branch serves,
			//how to hit it, and how it was intended to work previously.
			print_form_header('../docs/phrasedev', 'dofindphrase', 0, 1, 'debug', '90%', '_phrasefind');

			$displayarray[] =& $buttons;

			print_cells_row($displayarray, 0, 'thead');
			print_table_footer();
			echo '<p align="center" class="smallfont">' . date('r T') . '</p>';
		}
		else
		{
			echo "<p align=\"center\" class=\"smallfont\">SQL Queries (" . $vbulletin->db->querycount . ") | " . (!empty($cvsversion) ? "$cvsversion | " : '') . "<a href=\"" . $vbulletin->scriptpath . iif(strpos($vbulletin->scriptpath, '?') > 0, '&amp;', '?') . "explain=1\">Explain</a></p>";
			if (function_exists('memory_get_usage'))
			{
				echo "<p align=\"center\" class=\"smallfont\">Memory Usage: " . vb_number_format(round(memory_get_usage() / 1024, 2)) . " KiB</p>";
			}
		}

		$_REQUEST['do'] = htmlspecialchars_uni($_REQUEST['do']);

		echo "<script type=\"text/javascript\">window.status = \"" . construct_phrase($vbphrase['logged_in_user_x_executed_y_queries'], $vbulletin->userinfo['username'], $vbulletin->db->querycount) . " \$_REQUEST[do] = '$_REQUEST[do]'\";</script>";
	}

	if (!defined('NO_CP_COPYRIGHT'))
	{
		$output_version = defined('ADMIN_VERSION_VBULLETIN') ? ADMIN_VERSION_VBULLETIN : $vbulletin->options['templateversion'];
		echo '<div class="acp-footer">' .
			construct_phrase($vbphrase['vbulletin_copyright_orig'], $output_version, date('Y')) .
			'</div>';
	}
	if (!defined('IS_NAV_PANEL') AND !defined('NO_PAGE_TITLE') AND VB_AREA != 'Upgrade' AND VB_AREA != 'Install')
	{
		echo "\n</div>";
	}

	// Legacy Hook 'admin_complete' Removed //
	if (vB::getDatastore()->getOption('gzipoutput') AND function_exists("ob_start") AND function_exists("crc32") AND function_exists("gzcompress") AND !$vbulletin->nozip)
	{
		$text = ob_get_contents();
		while (ob_get_level())
		{
			@ob_end_clean();
		}

		if (!headers_sent() AND SAPI_NAME != 'apache2filter')
		{
			$newtext = fetch_gzipped_text($text, vB::getDatastore()->getOption('gziplevel'));
		}
		else
		{
			$newtext = $text;
		}

		if (!headers_sent())
		{
			@header('Content-Length: ' . strlen($newtext));
		}
		echo $newtext;
	}

	//make sure that shutdown functions get called on exit.
	$vbulletin->shutdown->shutdown();
	//we might intercept the output in shutdown and having output when that happens
	//is problematic.
	flush();
	if (defined('NOSHUTDOWNFUNC'))
	{
		exec_shut_down();
	}

	// terminate script execution now - DO NOT REMOVE THIS!
	exit;
}

// #############################################################################
/**
* Returns a number, unused in an ID thus far on the page.
* Functions that output elements with ID attributes use this internally.
*
* @param	boolean	Whether or not to increment the counter before returning
*
* @return	integer	Unused number
*/
function fetch_uniqueid_counter($increment = true)
{
	static $counter = 0;
	if ($increment)
	{
		return ++$counter;
	}
	else
	{
		return $counter;
	}
}

// #############################################################################
/**
* Prints the standard form header, setting target script and action to perform
*
* @param	string	PHP script to which the form will submit (ommit file suffix)
* @param	string	'do' action for target script
* @param	boolean	Whether or not to include an encoding type for the form (for file uploads)
* @param	boolean	Whether or not to add a <table> to give the form structure
* @param	string	Name for the form - <form name="$name" ... >
* @param	string  unused
* @param	string	Value for 'target' attribute of form
* @param	boolean unused
* @param	string	Form method (GET / POST)
* @param	integer	CellSpacing for Table
*/
function print_form_header(
	$phpscript = '',
	$do = '',
	$uploadform = false,
	$addtable = true,
	$name = 'cpform',
	$width = '100%',
	$target = '',
	$echobr = false,
	$method = 'post',
	$cellspacing = 0,
	$border_collapse = false,
	$formid = '',
	$fixtablewidth = false,
	$collapsible_table_id = '',
	$table_collapsed = true
)
{
	global $tableadded;

	if (($quote_pos = strpos($name, '"')) !== false)
	{
		$clean_name = substr($name, 0, $quote_pos);
	}
	else
	{
		$clean_name = $name;
	}
	/** @TODO change this when querycount is known */
	$querycount = 'unknown';//$vbulletin->db->querycount
	echo "\n<!-- form started:" . $querycount . " queries executed -->\n";
	echo "<form action=\"$phpscript.php?do=$do\"" . ($uploadform ? " enctype=\"multipart/form-data\"" : "") . " method=\"$method\"" . ($target ? " target=\"$target\"" : "") . " name=\"$clean_name\" id=\"" . ($formid ? $formid : $clean_name) . "\">\n";

	$session = vB::getCurrentSession();
	$sessionhash = $session->get('sessionhash');

	//in tools.php sometimes we don't have a session because things are really broken
	//try to do what we can
	try
	{
		$userInfo = $session->fetch_userinfo();
		$securitytoken =  $userInfo['securitytoken'];
	}
	catch(Exception $e)
	{
		$securitytoken = '';
	}

	if (!empty($sessionhash))
	{
		echo "<input type=\"hidden\" name=\"s\" value=\"" . htmlspecialchars_uni($sessionhash) . "\" />\n";
	}
	//construct_hidden_code('do', $do);
	echo "<input type=\"hidden\" name=\"do\" id=\"do\" value=\"" . htmlspecialchars_uni($do) . "\" />\n";
	if (strtolower(substr($method, 0, 4)) == 'post') // do this because we now do things like 'post" onsubmit="bla()' and we need to just know if the string BEGINS with POST
	{
		echo "<input type=\"hidden\" name=\"adminhash\" value=\"" . ADMINHASH . "\" />\n";
		echo "<input type=\"hidden\" name=\"securitytoken\" value=\"$securitytoken\" />\n";
	}

	if ($addtable)
	{
		print_table_start(
			null,
			null,
			$cellspacing,
			$clean_name . '_table',
			$border_collapse,
			$fixtablewidth,
			$collapsible_table_id,
			$table_collapsed
		);
	}
	else
	{
		$tableadded = 0;
	}
}

/*
 * Mostly an alias print_form_header() with a $collapsible_table_id, and returns
 * $collapsible_table_id .
 */
function print_form_header_with_collapsible_table(
	$table_collapsed = true,
	$phpscript = '',
	$do = '',
	$uploadform = false,
	$addtable = true,
	$name = 'cpform',
	$width = '100%',
	$target = '',
	$echobr = false,
	$method = 'post',
	$cellspacing = 0,
	$border_collapse = false,
	$formid = '',
	$fixtablewidth = false
)
{
	$collapsible_table_id = uniqid("acp-collapse-");

	print_form_header(
		$phpscript,
		$do,
		$uploadform,
		$addtable,
		$name,
		$width,
		$target,
		$echobr,
		$method,
		$cellspacing,
		$border_collapse,
		$formid,
		$fixtablewidth,
		$collapsible_table_id,
		$table_collapsed
	);

	return $collapsible_table_id;
}

// #############################################################################
/**
* Prints an opening <table> tag with standard attributes
*
* @param	boolean unused
* @param	string	usused
* @param	integer	Width in pixels for the table's 'cellspacing' attribute
* @param	boolean Whether to collapse borders in the table
* @param	boolean Whether to use fixed table-layout or not. Will set min-table width to be 900px if true.
* @param	string (optional) HTML ID value. If not empty, this will add some controls for collapse the table contents.
*/
function print_table_start(
	$echobr = false,
	$width = '100%',
	$cellspacing = 0,
	$id = '',
	$border_collapse = false,
	$fixtablewidth = false,
	$collapsible_table_id = '',
	$table_collapsed = true
)
{
	global $tableadded;

	$tableadded = 1;

	$id_html = ($id == '' ? '' : " id=\"$id\"");

	$style = "border-collapse:" . ($border_collapse ? 'collapse' : 'separate') .
			($fixtablewidth?"; table-layout: fixed; width: 100%; min-width: 900px;":"");
	$extra_classes = "";
	if ($collapsible_table)
	{
		$extra_classes = " collapse";
	}

	$checkbox = '';
	if (!empty($collapsible_table_id))
	{
		$checked = $table_collapsed ? '' : ' checked';
		$collapsible_table_id = htmlentities($collapsible_table_id);
		$checkbox = "\n<input
				class=\"table-collapse-control\"
				id=\"{$collapsible_table_id}\" type=\"checkbox\"{$checked}/>";
	}
	echo "$checkbox\n<table
				cellpadding=\"4\"
				cellspacing=\"$cellspacing\"
				border=\"0\"
				align=\"center\"
				width=\"100%\"
				style=\"$style\"
				class=\"tborder{$extra_classes}\"$id_html>\n";
}

// #############################################################################
/**
* Prints submit and reset buttons for the current form, then closes the form and table tags
*
* @param	string	Value for submit button - if left blank, will use $vbphrase['save']
* @param	string	Value for reset button - if left blank, will use $vbphrase['reset']
* @param	integer	Number of table columns the cell containing the buttons should span
* @param	string	Optional value for 'Go Back' button
* @param	string	Optional arbitrary HTML code to add to the table cell
* @param	boolean	If true, reverses the order of the buttons in the cell
*/
function print_submit_row($submitname = '', $resetname = '_default_', $colspan = 2, $goback = '', $extra = '', $alt = false)
{
	$vb5_config =& vB::getConfig();
	$vbphrase = vB_Api::instanceInternal('phrase')->fetch(array('save', 'reset'));

	static $count = 0;
	// do submit button
	if ($submitname === '_default_' OR $submitname === '')
	{
		$submitname = $vbphrase['save'];
	}

	$button1 = "\t<input type=\"submit\" id=\"submit$count\" class=\"button\" tabindex=\"1\" value=\"" . str_pad($submitname, 8, ' ', STR_PAD_BOTH) . "\" accesskey=\"s\" />\n";

	// do extra stuff
	$extrabutton = '';
	if ($extra)
	{
		$extrabutton = "\t$extra\n";
	}

	// do reset button
	$resetbutton = '';
	if ($resetname)
	{
		if ($resetname === '_default_')
		{
			$resetname = $vbphrase['reset'];
		}

		$resetbutton .= "\t<input type=\"reset\" id=\"reset$count\" class=\"button\" tabindex=\"1\" value=\"" . str_pad($resetname, 8, ' ', STR_PAD_BOTH) . "\" accesskey=\"r\" />\n";
	}

	// do goback button
	$button2 = '';
	if ($goback)
	{
		$button2 = "\t<input type=\"button\" id=\"goback$count\" class=\"button\" value=\"" . str_pad($goback, 8, ' ', STR_PAD_BOTH) . "\" tabindex=\"1\"
			onclick=\"if (history.length) { history.back(1); } else { self.close(); }\"
			/>
			<script type=\"text/javascript\">
			<!--
			if (history.length < 1 || ((is_saf || is_moz) && history.length <= 1)) // safari + gecko start at 1
			{
				document.getElementById('goback$count').parentNode.removeChild(document.getElementById('goback$count'));
			}
			//-->
			</script>\n";
	}

	if ($alt)
	{
		$tfoot = $button2 . $extrabutton . $resetbutton . $button1;
	}
	else
	{
		$tfoot = $button1 . $extrabutton . $resetbutton . $button2;
	}

	// do debug tooltip
	if ($vb5_config['Misc']['debug'] AND is_array($GLOBALS['_HIDDENFIELDS']))
	{
		$tooltip = "HIDDEN FIELDS:";
		foreach($GLOBALS['_HIDDENFIELDS'] AS $key => $val)
		{
			$tooltip .= "\n\$$key = &quot;$val&quot;";
		}
	}
	else
	{
		$tooltip = '';
	}

	$count++;

	print_table_footer($colspan, $tfoot, $tooltip);
}

// #############################################################################
/**
* Prints a closing table tag and closes the form tag if it is open
*
* @param	integer	Column span of the optional table row to be printed
* @param	string	If specified, creates an additional table row with this code as its contents
* @param	string	Tooltip for optional table row
* @param	boolean	Whether or not to close the <form> tag
* @param	string	Extra HTML to print
* @param	string	class to use other than 'tfoot'
*/
function print_table_footer($colspan = 2, $rowhtml = '', $tooltip = '', $echoform = true, $extra = '', $class = 'tfoot')
{
	global $tableadded, $vbulletin;

	if ($rowhtml)
	{
		$tooltip = iif($tooltip != '', " title=\"$tooltip\"", '');
		if ($tableadded)
		{
			echo "<tr>\n\t<td class=\"" . $class . "\"" . iif($colspan != 1 ," colspan=\"$colspan\"") . " align=\"center\"$tooltip>$rowhtml</td>\n</tr>\n";
		}
		else
		{
			echo "<p align=\"center\"$tooltip>$rowhtml</p>\n";
		}
	}

	if ($tableadded)
	{
		echo "</table>\n";
	}

	if ($extra)
	{
		echo $extra;
	}

	if ($echoform)
	{
		print_hidden_fields();

		echo "</form>\n<!-- form ended: " . $vbulletin->db->querycount ." queries executed -->\n\n";
	}
}

// #############################################################################
/**
* Prints out a closing table tag and opens another for page layout purposes
*
* @param	string	Code to be inserted between the two tables
* @param	string	Width for the new table - default = '100%'
*/
function print_table_break($insert = '', $width = '100%')
{
// ends the current table, leaves a break and starts it again.
	echo "</table>\n<br />\n\n";
	if ($insert)
	{
		echo "<!-- start mid-table insert -->\n$insert\n<!-- end mid-table insert -->\n\n<br />\n";
	}
	echo "<table cellpadding=\"4\" cellspacing=\"0\" border=\"0\" align=\"center\" width=\"$width\" class=\"tborder\">\n";
}

// #############################################################################
/**
* Prints the middle section of a table - similar to print_form_header but a bit different
*
* @param	string	R.A.T. value to be used
* @param	boolean	Specifies cb parameter
*
* @return	mixed	R.A.T.
*/
function print_form_middle($ratval, $call = true)
{
	global $vbulletin, $uploadform;
}

// #############################################################################
/**
* Prints out all cached hidden field values, then empties the $_HIDDENFIELDS array and starts again
*/
function print_hidden_fields()
{
	global $_HIDDENFIELDS;
	if (is_array($_HIDDENFIELDS))
	{
		//DEVDEBUG("Do hidden fields...");
		foreach($_HIDDENFIELDS AS $name => $value)
		{
			echo "<input type=\"hidden\" name=\"$name\" value=\"$value\" />\n";
			//DEVDEBUG("> hidden field: $name='$value'");
		}
	}
	$_HIDDENFIELDS = array();
}

// #############################################################################
/**
* Ensures that the specified text direction is valid
*
* @param	string	Text direction choice (ltr / rtl)
*
* @return	string	Valid text direction attribute
*/
function verify_text_direction($choice)
{

	$choice = strtolower($choice);

	// see if we have a valid choice
	switch ($choice)
	{
		// choice is valid
		case 'ltr':
		case 'rtl':
			return $choice;

		// choice is not valid
		default:
			if ($textdirection = vB_Template_Runtime::fetchStyleVar('textdirection'))
			{
				// invalid choice - return vB_Template_Runtime::fetchStyleVar default
				return $textdirection;
			}
			else
			{
				// invalid choice and no default defined
				return 'ltr';
			}
	}
}

// #############################################################################
/**
* Returns the alternate background css class from its current state
*
* @return	string
*/
function fetch_row_bgclass()
{
// returns the current alternating class for <TR> rows in the CP.
	global $bgcounter;
	return ($bgcounter++ % 2) == 0 ? 'alt1' : 'alt2';
}

// #############################################################################
/**
* Makes a column-spanning bar with a named <A> and a title, then  reinitialises the background class counter.
*
* @param	string	Title for the row
* @param	integer	Number of columns to span
* @param	boolean	Whether or not to htmlspecialchars the title
* @param	string	Name for html fragment to link to this table anchor tag
* @param	string	Alignment for the title (center / left / right)
* @param	boolean	Whether or not to show the help button in the row
*/
function print_table_header($title, $colspan = 2, $htmlise = false, $anchor = '', $align = 'center', $helplink = true)
{
	global $bgcounter;

	if ($htmlise)
	{
		$title = htmlspecialchars_uni($title);
	}
	$title = "<b>$title</b>";
	if ($anchor != '')
	{
		$title = "<span id=\"$anchor\">$title</span>";
	}
	if ($helplink AND $help = construct_help_button('', NULL, '', 1))
	{
		$title = "\n\t\t<div style=\"float:" . vB_Template_Runtime::fetchStyleVar('right') . "\">$help</div>\n\t\t$title\n\t";
	}

	echo "<tr>\n\t<td class=\"tcat\" align=\"$align\"" . ($colspan != 1 ? " colspan=\"$colspan\"" : "") . ">$title</td>\n</tr>\n";

	$bgcounter = 0;
}

// #############################################################################
/**
* Prints a two-cell row with arbitrary contents in each cell
*
* @param	string	HTML contents for first cell
* @param	string	HTML comments for second cell
* @param	string	CSS class for row - if not specified, uses alternating alt1/alt2 classes
* @param	string	Vertical alignment attribute for row (top / bottom etc.)
* @param	string	Name for help button
* @param	boolean	If true, set first cell to 30% width and second to 70%
* @param 	array 	Two element array of integers to set the colspans for first and second element (array[0] and array[1])
*/
function print_label_row($title, $value = '&nbsp;', $class = '', $valign = 'top', $helpname = NULL, $dowidth = false, $colspan = array(1,1), $helpOptions = array())
{
	if (!$class)
	{
		$class = fetch_row_bgclass();
	}

	if ($helpname !== NULL AND $helpbutton = construct_table_help_button($helpname, NULL, '', 0, $helpOptions))
	{
		$value = '<table cellpadding="0" cellspacing="0" border="0" width="100%"><tr valign="top"><td>' . $value . "</td><td align=\"" . vB_Template_Runtime::fetchStyleVar('right') . "\" style=\"padding-" . vB_Template_Runtime::fetchStyleVar('left') . ":4px\">$helpbutton</td></tr></table>";
	}

	if ($dowidth)
	{
		if (is_numeric($dowidth))
		{
			$left_width = $dowidth;
			$right_width = 100 - $dowidth;
		}
		else
		{
			$left_width = 70;
			$right_width = 30;
		}
	}

	$colattr = array();
	foreach($colspan as $col)
	{
		if ($col < 1)
		{
			$colattr[] = '';
		}
		else
		{
			$colattr[] = ' colspan="' . $col . '" ';
		}
	}

	echo "<tr valign=\"$valign\">
	<td class=\"$class\"" . ($dowidth ? " width=\"$left_width%\"" : '') . $colattr[0] . ">$title</td>
	<td class=\"$class\"" . ($dowidth ? " width=\"$right_width%\"" : '') . $colattr[1] . ">$value</td>\n</tr>\n";
}

function print_collapse_control_row($expandLabel, $collapseLabel, $id, $colspan = 2)
{
	$class = fetch_row_bgclass();

	$html_id = htmlentities($id);

	if ($colspan > 1)
	{
		$colspan = ' colspan="' . intval($colspan) . '"';
	}
	else
	{
		$colspan = '';
	}

	echo "
		<tr valign=\"\" class=\"collapse-toggle\">
			<td class=\"{$class}\"{$colspan}>
				<label class=\"collapse-label collapse-show-on-collapse\" for=\"{$html_id}\">
					[+] {$expandLabel}
				</label>
				<label class=\"collapse-label collapse-hide-on-collapse\" for=\"{$html_id}\">
					[-] {$collapseLabel}
				</label>
			</td>
		</tr>\n";

	return $id;
}

// #############################################################################
/**
* Prints a row containing an <input type="text" />
*
* @param	string	Title for row
* @param	string	Name for input field
* @param	string	Value for input field
* @param	boolean	Whether or not to htmlspecialchars the input field value
* @param	integer	Size for input field
* @param	integer	Max length for input field
* @param	string	Text direction for input field
* @param	mixed	If specified, overrides the default CSS class for the input field
* @param 	array 	Two element array of integers to set the colspans for the label and input (array[0] and array[1])
* @param	array	Array of attribuite => value pairs to add to the <input> element.
*/
function print_input_row($title, $name, $value = '', $htmlise = true, $size = 35, $maxlength = 0, $direction = '', $inputclass = false, $inputid = false, $colspan = array(1,1), $attributes = array())
{
	global $vbulletin;
	$vb5_config = vB::getConfig();

	$direction = verify_text_direction($direction);

	if($inputid===false)
	{
		$id = 'it_' . $name . '_' . fetch_uniqueid_counter();
	}
	else
	{
		$id = $inputid;
	}

	if (is_array($attributes) AND !empty($attributes))
	{
		$attribuitePairs = array();
		foreach ($attributes AS $k => $v)
		{
			$attribuitePairs[] = $k . '="' . $v . '"';
		}
		$attribuitePairs = ' ' . implode(' ', $attribuitePairs);
	}
	else
	{
		$attribuitePairs = '';
	}

	print_label_row(
		$title,
		"<div id=\"ctrl_$name\"><input type=\"text\" class=\"" . iif($inputclass, $inputclass, 'bginput') .
		"\" name=\"$name\" id=\"$id\" value=\"" . iif($htmlise, htmlspecialchars_uni($value), $value) . "\" size=\"$size\"" .
		iif($maxlength, " maxlength=\"$maxlength\"") . " dir=\"$direction\" tabindex=\"1\"" .
		iif($vb5_config['Misc']['debug'], " title=\"name=&quot;$name&quot;\"") . $attribuitePairs . " /></div>",
		'', 'top', $name, false, $colspan
	);
}

// #############################################################################
/**
* Prints a row containing an <input type="text" /> and a <select>
*
* @param	string	Title for row
* @param	string	Name for input field
* @param	string	Value for input field
* @param	string	Name for select field
* @param	array	Array of options for select field - array(0 => 'No', 1 => 'Yes') etc.
* @param	string	Value of selected option for select field
* @param	boolean	Whether or not to htmlspecialchars the input field value
* @param	integer	Size for input field
* @param	integer	Size for select field (if not 0, is multi-row)
* @param	integer	Max length for input field
* @param	string	Text direction for input field
* @param	mixed	If specified, overrides the default CSS class for the input field
* @param	boolean	Allow multiple selections from select field?
*/
function print_input_select_row($title, $inputname, $inputvalue = '', $selectname, $selectarray, $selected = '', $htmlise = true, $inputsize = 35, $selectsize = 0, $maxlength = 0, $direction = '', $inputclass = false, $multiple = false)
{
	global $vbulletin;
	$vb5_config = vB::getConfig();

	$direction = verify_text_direction($direction);

	print_label_row(
		$title,
		"<div id=\"ctrl_$inputname\">" .
		"<input type=\"text\" class=\"" . iif($inputclass, $inputclass, 'bginput') . "\" name=\"$inputname\" value=\"" . iif($htmlise, htmlspecialchars_uni($inputvalue), $inputvalue) . "\" size=\"$inputsize\"" . iif($maxlength, " maxlength=\"$maxlength\"") . " dir=\"$direction\" tabindex=\"1\"" . iif($vb5_config['Misc']['debug'], " title=\"name=&quot;$inputname&quot;\"") . " />&nbsp;" .
		"<select name=\"$selectname\" tabindex=\"1\" class=\"" . iif($inputclass, $inputclass, 'bginput') . '"' . iif($selectsize, " size=\"$selectsize\"") . iif($multiple, ' multiple="multiple"') . iif($vb5_config['Misc']['debug'], " title=\"name=&quot;$selectname&quot;\"") . ">\n" .
		construct_select_options($selectarray, $selected, $htmlise) .
		"</select></div>\n",
		'', 'top', $inputname
	);
}

// #############################################################################
/**
* Prints a row containing a <textarea>
*
* @param	string	Title for row
* @param	string	Name for textarea field
* @param	string	Value for textarea field
* @param	integer	Number of rows for textarea field
* @param	integer	Number of columns for textarea field
* @param	boolean	Whether or not to htmlspecialchars the textarea field value
* @param	boolean	Whether or not to show the 'large edit box' button
* @param	string	Text direction for textarea field
* @param	mixed	If specified, overrides the default CSS class for the textare field
*
* @return string the textareaid value
*/
function print_textarea_row($title, $name, $value = '', $rows = 4, $cols = 40, $htmlise = true, $doeditbutton = true, $direction = '', $textareaclass = false)
{
	global $vbulletin;
	static $vbphrase;
	$vb5_config =& vB::getConfig();

	if (empty($vbphrase))
	{
		$vbphrase = vB_Api::instanceInternal('phrase')->fetch(array('large_edit_box', 'increase_size', 'decrease_size'));
	}

	$direction = verify_text_direction($direction);

	if (!$doeditbutton OR strpos($name,'[') !== false)
	{
		$openwindowbutton = '';
	}
	else
	{
		$openwindowbutton = '<p><input type="button" unselectable="on" value="' . $vbphrase['large_edit_box'] . '" class="button" style="font-weight:normal" onclick="window.open(\'admincp/textarea.php?dir=' . $direction . '&name=' . $name. '\',\'textpopup\',\'resizable=yes,scrollbars=yes,width=\' + (screen.width - (screen.width/10)) + \',height=600\');" /></p>';
	}

	$vbulletin->textarea_id = 'ta_' . $name . '_' . fetch_uniqueid_counter();

	// trigger hasLayout for IE to prevent template box from jumping (#22761)
	$ie_reflow_css = (is_browser('ie') ? 'style="zoom:1"' : '');

	$resizer = "<div class=\"smallfont sizetools\"><a class=\"increase\" href=\"#\" $ie_reflow_css onclick=\"return resize_textarea(1, '{$vbulletin->textarea_id}')\">$vbphrase[increase_size]</a> <a class=\"decrease\" href=\"#\" $ie_reflow_css onclick=\"return resize_textarea(-1, '{$vbulletin->textarea_id}')\">$vbphrase[decrease_size]</a></div>";

	print_label_row(
		$title . $openwindowbutton,
		"<div id=\"ctrl_$name\"><textarea name=\"$name\" id=\"{$vbulletin->textarea_id}\"" . iif($textareaclass, " class=\"$textareaclass\"") . " rows=\"$rows\" cols=\"$cols\" wrap=\"virtual\" dir=\"$direction\" tabindex=\"1\"" . iif($vb5_config['Misc']['debug'], " title=\"name=&quot;$name&quot;\"") . ">" . iif($htmlise, htmlspecialchars_uni($value), $value) . "</textarea>$resizer</div>",
		'', 'top', $name
	);

	//we really shouldn't be indirecting through a global object -- we'll leave it for backwards compatibility
	//but we'll also return the value properly so that we can start removing the references
	return $vbulletin->textarea_id;
}

// #############################################################################
/**
* Prints a row containing 'yes', 'no' <input type="radio" / > buttons
*
* @param	string	Title for row
* @param	string	Name for radio buttons
* @param	string	Selected button's value
* @param	string	Optional Javascript code to run when radio buttons are clicked - example: ' onclick="do_something()"'
*/
function print_yes_no_row($title, $name, $value = 1, $onclick = '', $helpOptions = array())
{
	//I'm not sure why we don't use the global phrase array here.  Globals are ugly, but so is this.
	//Also the api caches the fetch, so the static is kind of superfluous.
	static $vbphrase;
	if (empty($vbphrase))
	{
		$vbphrase = vB_Api::instanceInternal('phrase')->fetch(array('yes', 'no', 'yes_but_not_parsing_html'));
	}

	$vb5_config =& vB::getConfig();

	if ($onclick)
	{
		$onclick = ' onclick="' . $onclick . '"';
	}

	$rtlmarker = (vB_Template_Runtime::fetchStyleVar('textdirection') == 'rtl' ? '&rlm;' : '');
	$uniqueid = fetch_uniqueid_counter();

	$inputid = array();
	$debugtitle = array_fill(0, 2, '');
	for($i = 0; $i <= 1; $i++)
	{
		$inputid[$i] = "rb_{$i}_{$name}_$uniqueid";
		if($vb5_config['Misc']['debug'])
		{
			$debugtitle[$i] = ' title="' . htmlspecialchars('name="' . $name . '" value="' . $i . '"') . '"';
		}
	}

	//we have this mysterious value of 2 to deal with.
	$checked = array_fill(0, 2, '');
	$checked[($value > 0 ? 1 : 0)] = ' checked="checked"';

	//this is a *problem* we should not be handling special logic for stray fields in a function this generic.
	//I'm about 99% sure that the pmpopup is no longer used and we can blast it.  This is here because
	//the field was set up as 0=off, 1=on but no new pms, 2=on, new pms. If it's currently 2, we don't want
	//to implicitly save it back to 1.
	$value1 = 1;
	if($name == 'user[pmpopup]' AND $value == 2)
	{
		$value1 = 2;
	}

	$description ='
		<div id="ctrl_' . $name . '" class="smallfont" style="white-space:nowrap">
		<label for="' . $inputid[1] . '">
			<input type="radio" name="' . $name . '" id="' . $inputid[1] . '" value="' . $value1 . '" tabindex="1"' . $onclick . $debugtitle[1] . $checked[1] . ' />' .
			$vbphrase['yes'] . $rtlmarker . '
		</label>
		<label for="' . $inputid[0] . '">
			<input type="radio" name="' . $name . '" id="' . $inputid[0] . '" value="0" tabindex="1"' . $onclick . $debugtitle[0] . $checked[0] . ' />' .
			$vbphrase['no'] . $rtlmarker . '
		</label>
		</div>';

	print_label_row($title, $description,	'', 'top', $name, false, array(1, 1), $helpOptions);
}

// #############################################################################
/**
* Prints a row containing 'yes', 'no' and 'other' <input type="radio" /> buttons
*
* @param	string	Title for row
* @param	string	Name for radio buttons
* @param	string	Text label for third button
* @param	string	Selected button's value
* @param	string	Optional Javascript code to run when radio buttons are clicked - example: ' onclick="do_something()"'
*/
function print_yes_no_other_row($title, $name, $thirdopt, $value = 1, $onclick = '')
{
	global $vbphrase, $vbulletin;
	$vb5_config = vB::getConfig();

	if ($onclick)
	{
		$onclick = " onclick=\"$onclick\"";
	}

	$uniqueid = fetch_uniqueid_counter();

	print_label_row(
		$title,
		"<div id=\"ctrl_$name\" class=\"smallfont\" style=\"white-space:nowrap\">
		<label for=\"rb_1_{$name}_$uniqueid\"><input type=\"radio\" name=\"$name\" id=\"rb_1_{$name}_$uniqueid\" value=\"1\" tabindex=\"1\"$onclick" . iif($vb5_config['Misc']['debug'], " title=\"name=&quot;$name&quot; value=&quot;1&quot;\"") . iif($value == 1, ' checked="checked"') . " />$vbphrase[yes]" . iif(vB_Template_Runtime::fetchStyleVar('textdirection') == 'rtl', "&rlm;") . "</label>
		<label for=\"rb_0_{$name}_$uniqueid\"><input type=\"radio\" name=\"$name\" id=\"rb_0_{$name}_$uniqueid\" value=\"0\" tabindex=\"1\"$onclick" . iif($vb5_config['Misc']['debug'], " title=\"name=&quot;$name&quot; value=&quot;0&quot;\"") . iif($value == 0, ' checked="checked"') . " />$vbphrase[no]" . iif(vB_Template_Runtime::fetchStyleVar('textdirection') == 'rtl', "&rlm;") . "</label>
		<label for=\"rb_x_{$name}_$uniqueid\"><input type=\"radio\" name=\"$name\" id=\"rb_x_{$name}_$uniqueid\" value=\"-1\" tabindex=\"1\"$onclick" . iif($vb5_config['Misc']['debug'], " title=\"name=&quot;$name&quot; value=&quot;-1&quot;\"") . iif($value == -1, ' checked="checked"') . " />$thirdopt" . iif(vB_Template_Runtime::fetchStyleVar('textdirection') == 'rtl', "&rlm;") . "</label>
		\n\t</div>",
		'', 'top', $name
	);
}

// #############################################################################
/**
* Prints a row containing an <input type="checkbox" />
*
* @param	string	Title for row
* @param	string	Name for checkbox
* @param	boolean	Whether or not to check the box
* @param	string	Value for checkbox
* @param	string	Text label for checkbox
* @param	string	Optional Javascript code to run when checkbox is clicked - example: ' onclick="do_something()"'
*/
function print_checkbox_row($title, $name, $checked = true, $value = 1, $labeltext = '', $onclick = '', $disabled = false)
{
	global $vbphrase, $vbulletin;
	$vb5_config = vB::getConfig();

	if ($labeltext == '')
	{
		$labeltext = $vbphrase['yes'];
	}

	$uniqueid = fetch_uniqueid_counter();

	$additionalHtml = "";
	if ($disabled)
	{
		// Add hidden input since a disabled checkbox won't send its data with the POST
		$additionalHtml = "<input type=\"hidden\" name=\"$name\" value=\"$value\" />";
	}

	print_label_row(
		"<label for=\"{$name}_$uniqueid\">$title</label>",
		"<div id=\"ctrl_$name\">
			<label for=\"{$name}_$uniqueid\" class=\"smallfont\">
				<input type=\"checkbox\" name=\"$name\"
						id=\"{$name}_$uniqueid\" value=\"$value\" tabindex=\"1\""
						. ($onclick ? " onclick=\"$onclick\"": '')
						. ($vb5_config['Misc']['debug'] ? " title=\"name=&quot;$name&quot;\"" : '')
						. ($checked ? ' checked="checked"' : '')
						. ($disabled ? ' disabled' : '')
						. " />
				$additionalHtml
				$labeltext
			</label>
		</div>",
		'', 'top', $name
	);
}

// #############################################################################
/**
* Prints a row containing a single 'yes' <input type="radio" /> button
*
* @param	string	Title for row
* @param	string	Name for radio button
* @param	string	Text label for radio button
* @param	boolean	Whether or not to check the radio button
* @param	string	Value for radio button
*/
function print_yes_row($title, $name, $yesno, $checked, $value = 1)
{
	$vb5_config = vB::getConfig();

	$uniqueid = fetch_uniqueid_counter();

	$inputid = "{$name}_{$value}_$uniqueid";
	$debugtitle = ($vb5_config['Misc']['debug'] ? ' title="name=' . htmlspecialchars('"' . $name . '"') . '"' : '');
	$checkedattribute = ($checked ? ' checked="checked"' : '');

	print_label_row(
		'<label for="' . $inputid . '">' . $title . '</label>',
		"<div id=\"ctrl_$name\"><label for=\"$inputid\"><input type=\"radio\" name=\"$name\" id=\"$inputid\" value=\"$value\" tabindex=\"1\"" . $debugtitle . $checkedattribute . " />$yesno</label></div>",
		'',
		'top',
		$name
	);
}

// #############################################################################
/**
* Prints a row containing an <input type="password" />
*
* @param	string	Title for row
* @param	string	Name for password field
* @param	string	Value for password field
* @param	boolean	Whether or not to htmlspecialchars the value
* @param	integer	Size of the password field
*/
function print_password_row($title, $name, $value = '', $htmlise = 1, $size = 35)
{
	global $vbulletin;
	$vb5_config = vB::getConfig();

	print_label_row(
		$title,
		"<div id=\"ctrl_$name\"><input type=\"password\" autocomplete=\"off\" class=\"bginput\" name=\"$name\" value=\"" . iif($htmlise, htmlspecialchars_uni($value), $value) . "\" size=\"$size\" tabindex=\"1\"" . iif($vb5_config['Misc']['debug'], " title=\"name=&quot;$name&quot;\"") . " /></div>",
		'', 'top', $name
	);
}

// #############################################################################
/**
* Prints a row containing an <input type="file" />
*
* @param	string	Title for row
* @param	string	Name for file upload field
* @param	integer	Max uploaded file size in bytes
* @param	integer	Size of file upload field
* @param	string|null	Name for help button
*/
function print_upload_row($title, $name, $maxfilesize = 1000000, $size = 35, $helpname = null)
{
	global $vbulletin;
	$vb5_config = vB::getConfig();

	construct_hidden_code('MAX_FILE_SIZE', $maxfilesize);

	// Don't style the file input for Opera or Firefox 3. #25838
	$use_bginput = (is_browser('opera') OR is_browser('firefox', 3) ? false : true);

	$helpname = $helpname === null ? $name : null;

	print_label_row(
		$title,
		"<div id=\"ctrl_$name\"><input type=\"file\"" . ($use_bginput ? ' class="bginput"' : '') . " name=\"$name\" size=\"$size\" tabindex=\"1\"" . iif($vb5_config['Misc']['debug'], " title=\"name=&quot;$name&quot;\"") . " /></div>",
		'', 'top', $helpname
	);
}

// #############################################################################
/**
* Prints a row containing an <input type="file" /> with an image preview field.
*
* @param	string	Title for row
* @param	string	Name for file upload field
* @param	integer	Max uploaded file size in bytes
* @param	integer	Size of file upload field
* @param	string|null	Name for help button
*/
function print_channel_icon_upload_row($title, $name, $helpname = null, $filedataid = null, $filedataname = null)
{
	global $vbulletin, $vbphrase;
	$vb5_config = vB::getConfig();

	$imageurl_html = '';
	if (!empty($filedataid))
	{
		$filedataid = intval($filedataid);
		$size = '&type=icon';
		$imageurl_html = htmlentities('filedata/fetch?filedataid=' . intval($filedataid) . $size);
	}

	if (!empty($filedataname))
	{
		$filedataname_html = htmlentities($filedataname);
	}
	else
	{
		$filedataname_html = htmlentities($name . '[filedataid]');
	}

	$titleAttribute = '';
	if ($vb5_config['Misc']['debug'])
	{
		$titleAttribute =  ' title="name=&quot;' . $name . '&quot;"';
	}

	$helpname = $helpname ?? $name;
	$name_html = htmlentities($name);

	$revertRemoveButtonsHtml = "<button
		class=\"bginput js-image-upload-remove\"
		". ($filedataid ? '': 'disabled') ."
		data-for=\"$name_html\"
		type=\"button\"
		>$vbphrase[remove]</button>";
	if ($filedataid)
	{
		// "revert" is only meaningful if the channel already had an icon.
		$revertRemoveButtonsHtml .= "&nbsp;<button
			class=\"bginput js-image-upload-revert\"
			disabled
			data-for=\"$name_html\"
			type=\"button\"
			>$vbphrase[revert]</button>";
	}

	$html = "<div id=\"ctrl_{$name_html}\">
				<div class=\"channel-icon-preview-wrapper\">
					<input type=\"hidden\"
						name=\"$filedataname_html\"
						class=\"js-image-upload-filedataid\"
						data-for=\"$name_html\"
						value=\"$filedataid\"
						data-orig-value=\"$filedataid\"
						/>
					<input
						type=\"file\"
						class=\"bginput js-image-upload-update-preview\"
						name=\"$name_html\"
						tabindex=\"1\"
						$titleAttribute />
					<div class=\"js-channel-icon-preview-wrapper". ($filedataid ? '': ' hide') . "\"
						data-for=\"$name_html\"
						>
						<img
							src=\"$imageurl_html\"
							data-orig-src=\"$imageurl_html\"
							class=\"channel-icon\"
							data-for=\"$name_html\"
							title=\"$vbphrase[new_posts]\"
							/><!--
							--><span>/</span><!--
							--><img
							src=\"$imageurl_html\"
							data-orig-src=\"$imageurl_html\"
							class=\"channel-icon channel-icon--read\"
							data-for=\"$name_html\"
							title=\"$vbphrase[no_new_posts]\"
							/>
					</div>
				</div>
				$revertRemoveButtonsHtml
			</div>";

	print_label_row($title, $html, '', 'top', $helpname);
}

function print_channel_icon_preview_row($title, $helpname = null, $filedataid)
{
	global $vbulletin, $vbphrase;
	$vb5_config = vB::getConfig();

	$imageurl_html = '';
	if (!empty($filedataid))
	{
		$filedataid = intval($filedataid);
		$size = '&type=icon';
		$imageurl_html = htmlentities('filedata/fetch?filedataid=' . intval($filedataid) . $size);
	}
	else
	{
		return;
	}
	$html = "<div class=\"channel-icon-preview-wrapper\">
					<img
						src=\"$imageurl_html\"
						class=\"channel-icon\"
						title=\"$vbphrase[new_posts]\"
						/><!--
						--><span>/</span><!--
						--><img
						src=\"$imageurl_html\"
						class=\"channel-icon channel-icon--read\"
						title=\"$vbphrase[no_new_posts]\"
						/>
			</div>";

	print_label_row($title, $html, '', 'top', $helpname);
}

// #############################################################################
/**
* Prints a column-spanning row containing arbitrary HTML
*
* @param	string	HTML contents for row
* @param	boolean	Whether or not to htmlspecialchars the row contents
* @param	integer	Number of columns to span
* @param	string	Optional CSS class to override the alternating classes
* @param	string	Alignment for row contents
* @param	string	Name for help button
*/
function print_description_row($text, $htmlise = false, $colspan = 2, $class = '', $align = '', $helpname = NULL)
{
	if (!$class)
	{
		$class = fetch_row_bgclass();
	}

	if ($helpname !== NULL AND $help = construct_help_button($helpname))
	{
		$text = "\n\t\t<div style=\"float:" . vB_Template_Runtime::fetchStyleVar('right') . "\">$help</div>\n\t\t$text\n\t";
	}

	echo "<tr valign=\"top\">
	<td class=\"$class\"" . iif($colspan != 1," colspan=\"$colspan\"") . iif($align, " align=\"$align\"") . ">" . iif($htmlise, htmlspecialchars_uni($text), $text) . "</td>\n</tr>\n";
}

// #############################################################################
/**
* Prints a <colgroup> section for styling table columns
*
* @param	array	Column styles - each array element represents HTML code for a column
*/
function print_column_style_code($columnstyles)
{
	if (is_array($columnstyles))
	{
		$span = sizeof($columnstyles);
		if ($span > 1)
		{
			echo "<colgroup span=\"$span\">\n";
		}
		foreach ($columnstyles AS $columnstyle)
		{
			if ($columnstyle != '')
			{
				$columnstyle = " style=\"$columnstyle\"";
			}
			echo "\t<col$columnstyle></col>\n";
		}
		if ($span > 1)
		{
			echo "</colgroup>\n";
		}
	}
}

// #############################################################################
/**
* Adds an entry to the $_HIDDENFIELDS array for later printing as an <input type="hidden" />
*
* @param	string	Name for hidden field
* @param	string	Value for hidden field
* @param	boolean	Whether or not to htmlspecialchars the hidden field value
*/
function construct_hidden_code($name, $value = '', $htmlise = true)
{
	global $_HIDDENFIELDS;

	$_HIDDENFIELDS["$name"] = iif($htmlise, htmlspecialchars_uni($value), $value);
}

// #############################################################################
/**
* Prints a row containing form elements to input a date & time
*
* Resulting form element names: $name[day], $name[month], $name[year], $name[hour], $name[minute]
*
* @param	string	Title for row
* @param	string	Base name for form elements - $name[day], $name[month], $name[year] etc.
* @param	mixed	Unix timestamp to be represented by the form fields OR SQL date field (yyyy-mm-dd)
* @param	boolean	Whether or not to show the time input components, or only the date
* @param	boolean	If true, expect an SQL date field from the unix timestamp parameter instead (for birthdays)
* @param	string	Vertical alignment for the row
*/
function print_time_row($title, $name = 'date', $unixtime = '', $showtime = true, $birthday = false, $valign = 'middle')
{
	global $vbphrase, $vbulletin;
	$vb5_config = vB::getConfig();
	static $datepicker_output = false;

	if (!$datepicker_output)
	{
		echo '
			<script type="text/javascript" src="core/clientscript/vbulletin_date_picker.js?v=' . SIMPLE_VERSION . '"></script>
			<script type="text/javascript">
			<!--
				vbphrase["sunday"]    = "' . $vbphrase['sunday'] . '";
				vbphrase["monday"]    = "' . $vbphrase['monday'] . '";
				vbphrase["tuesday"]   = "' . $vbphrase['tuesday'] . '";
				vbphrase["wednesday"] = "' . $vbphrase['wednesday'] . '";
				vbphrase["thursday"]  = "' . $vbphrase['thursday'] . '";
				vbphrase["friday"]    = "' . $vbphrase['friday'] . '";
				vbphrase["saturday"]  = "' . $vbphrase['saturday'] . '";
			-->
			</script>
		';
		$datepicker_output = true;
	}

	$monthnames = array(
		0  => '- - - -',
		1  => $vbphrase['january'],
		2  => $vbphrase['february'],
		3  => $vbphrase['march'],
		4  => $vbphrase['april'],
		5  => $vbphrase['may'],
		6  => $vbphrase['june'],
		7  => $vbphrase['july'],
		8  => $vbphrase['august'],
		9  => $vbphrase['september'],
		10 => $vbphrase['october'],
		11 => $vbphrase['november'],
		12 => $vbphrase['december'],
	);

	if (is_array($unixtime))
	{
		require_once(DIR . '/includes/functions_misc.php');
		$unixtime = vbmktime(0, 0, 0, $unixtime['month'], $unixtime['day'], $unixtime['year']);
	}

	if ($birthday)
	{ // mktime() on win32 doesn't support dates before 1970 so we can't fool with a negative timestamp
		if ($unixtime == '')
		{
			$month = 0;
			$day = '';
			$year = '';
		}
		else
		{
			$temp = explode('-', $unixtime);
			$month = intval($temp[0]);
			$day = intval($temp[1]);
			if ($temp[2] == '0000')
			{
				$year = '';
			}
			else
			{
				$year = intval($temp[2]);
			}
		}
	}
	else
	{
		if ($unixtime)
		{
			$month = vbdate('n', $unixtime, false, false);
			$day = vbdate('j', $unixtime, false, false);
			$year = vbdate('Y', $unixtime, false, false);
			$hour = vbdate('G', $unixtime, false, false);
			$minute = vbdate('i', $unixtime, false, false);
		}
	}

	$cell = array();
	$cell[] = "<label for=\"{$name}_month\">$vbphrase[month]</label><br /><select name=\"{$name}[month]\" id=\"{$name}_month\" tabindex=\"1\" class=\"bginput\"" . iif($vb5_config['Misc']['debug'], " title=\"name=&quot;$name" . "[month]&quot;\"") . ">\n" . construct_select_options($monthnames, $month) . "\t\t</select>";
	$cell[] = "<label for=\"{$name}_date\">$vbphrase[day]</label><br /><input type=\"text\" class=\"bginput\" name=\"{$name}[day]\" id=\"{$name}_date\" value=\"$day\" size=\"4\" maxlength=\"2\" tabindex=\"1\"" . iif($vb5_config['Misc']['debug'], " title=\"name=&quot;$name" . "[day]&quot;\"") . ' />';
	$cell[] = "<label for=\"{$name}_year\">$vbphrase[year]</label><br /><input type=\"text\" class=\"bginput\" name=\"{$name}[year]\" id=\"{$name}_year\" value=\"$year\" size=\"4\" maxlength=\"4\" tabindex=\"1\"" . iif($vb5_config['Misc']['debug'], " title=\"name=&quot;$name" . "[year]&quot;\"") . ' />';
	if ($showtime)
	{
		$cell[] = $vbphrase['hour'] . '<br /><input type="text" tabindex="1" class="bginput" name="' . $name . '[hour]" value="' . $hour . '" size="4"' . iif($vb5_config['Misc']['debug'], " title=\"name=&quot;$name" . "[hour]&quot;\"") . ' />';
		$cell[] = $vbphrase['minute'] . '<br /><input type="text" tabindex="1" class="bginput" name="' . $name . '[minute]" value="' . $minute . '" size="4"' . iif($vb5_config['Misc']['debug'], " title=\"name=&quot;$name" . "[minute]&quot;\"") . ' />';
	}
	$inputs = '';
	foreach($cell AS $html)
	{
		$inputs .= "\t\t<td><span class=\"smallfont\">$html</span></td>\n";
	}

	print_label_row(
		$title,
		"<div id=\"ctrl_$name\"><table cellpadding=\"0\" cellspacing=\"2\" border=\"0\"><tr>\n$inputs\t\n</tr></table></div>",
		'', 'top', $name
	);

	echo "<script type=\"text/javascript\"> new vB_DatePicker(\"{$name}_year\", \"{$name}_\", \"" . $vbulletin->userinfo['startofweek']  . "\"); </script>\r\n";
}

// #############################################################################
/**
* Prints a row containing an arbitrary number of cells, each containing arbitrary HTML
*
* @param	array	Each array element contains the HTML code for one cell. If the array contains 4 elements, 4 cells will be printed
* @param	boolean	If true, make all cells' contents bold and use the 'thead' CSS class
* @param	mixed	If specified, override the alternating CSS classes with the specified class
* @param	integer	Cell offset - controls alignment of cells... best to experiment with small +ve and -ve numbers
* @param	string	Vertical alignment for the row
* @param	boolean	Whether or not to treat the cells as part of columns - will alternate classes horizontally instead of vertically
* @param	boolean	Whether or not to use 'smallfont' for cell contents
* @param	mixed	Boolean, Whether or not to wrap text for the whole row.
* @param	array	Specify an array of booleans to choose specific columns to no-wrap
* @param	array 	Specify an array of (string) css helper classes to append to class
* @param	array	Advanced alignment control, specify an array of alignments to do column specific alignments instead of using $i
*/
function print_cells_row($array, $isheaderrow = false, $class = false, $i = 0, $valign = 'top', $column = false, $smallfont = false, $nowrap = false, $alignArray = false)
{
	global $colspan, $bgcounter;

	if (is_array($array))
	{
		$colspan = sizeof($array);
		if ($colspan)
		{
			$j = 0;
			$doecho = 0;

			if (!$class AND !$column AND !$isheaderrow)
			{
				$bgclass = fetch_row_bgclass();
			}
			elseif ($isheaderrow)
			{
				$bgclass = 'thead';
			}
			else
			{
				$bgclass = $class;
			}

			$bgcounter = iif($column, 0, $bgcounter);
			$nowrapall = (!empty($nowrap) AND !is_array($nowrap));
			$out = "<tr valign=\"$valign\" align=\"center\"" . ($nowrapall? "style=\"white-space:nowrap\"": ""). ">\n";

			foreach($array AS $key => $val)
			{
				$j++;
				if ($val == '' AND !is_int($val))
				{
					$val = '&nbsp;';
				}
				else
				{
					$doecho = 1;
				}

				if ($i++ < 1)
				{
					$align = ' align="' . vB_Template_Runtime::fetchStyleVar('left') . '"';
				}
				elseif ($j == $colspan AND $i == $colspan AND $j != 2)
				{
					$align = ' align="' . vB_Template_Runtime::fetchStyleVar('right') . '"';
				}
				else
				{
					$align = '';
				}

				if (is_array($alignArray) AND $alignArray[$key])
				{
					$align = ' align="' . $alignArray[$key] . '"';
				}

				if (!$class AND $column)
				{
					$bgclass = fetch_row_bgclass();
				}
				if ($smallfont)
				{
					$val = "<span class=\"smallfont\">$val</span>";
				}

				$style = (is_array($nowrap) AND $nowrap[$key])? "style=\"white-space:nowrap\"" : "";

				$out .= "\t<td" . iif($column, " class=\"$bgclass\"", " class=\"$bgclass\"") . "$align $style>$val</td>\n";
			}

			$out .= "</tr>\n";

			if ($doecho)
			{
				echo $out;
			}
		}
	}
}

// #############################################################################
/**
* Prints a row containing a number of <input type="checkbox" /> fields representing a user's membergroups
*
* @param	string	Title for row
* @param	string	Base name for checkboxes - $name[]
* @param	integer	Number of columns to split checkboxes into
* @param	mixed	Either NULL or a user info array
*/
function print_membergroup_row($title, $name = 'membergroup', $columns = 0, $userarray = NULL)
{
	global $vbulletin, $iusergroupcache;
	$vb5_config = vB::getConfig();

	$uniqueid = fetch_uniqueid_counter();

	if (!is_array($iusergroupcache))
	{
		$iusergroupcache = array();
		$usergroups = $vbulletin->db->query_read("SELECT usergroupid,title FROM " . TABLE_PREFIX . "usergroup ORDER BY title");
		while ($usergroup = $vbulletin->db->fetch_array($usergroups))
		{
			$iusergroupcache["$usergroup[usergroupid]"] = $usergroup['title'];
		}
		unset($usergroup);
		$vbulletin->db->free_result($usergroups);
	}
	// create a blank user array if one is not set
	if (!is_array($userarray))
	{
		$userarray = array('usergroupid' => 0, 'membergroupids' => '');
	}
	$options = array();
	foreach($iusergroupcache AS $usergroupid => $grouptitle)
	{
		// don't show the user's primary group (if set)
		if ($usergroupid != $userarray['usergroupid'])
		{
			$options[] = "\t\t<div><label for=\"$name{$usergroupid}_$uniqueid\" title=\"usergroupid: $usergroupid\"><input type=\"checkbox\" tabindex=\"1\" name=\"$name"."[]\" id=\"$name{$usergroupid}_$uniqueid\" value=\"$usergroupid\"" . iif(strpos(",$userarray[membergroupids],", ",$usergroupid,") !== false, ' checked="checked"') . iif($vb5_config['Misc']['debug'], " title=\"name=&quot;$name&quot;\"") . " />$grouptitle</label></div>\n";
		}
	}

	$class = fetch_row_bgclass();
	if ($columns > 1)
	{
		$html = "\n\t<table cellpadding=\"0\" cellspacing=\"0\" border=\"0\"><tr valign=\"top\">\n";
		$counter = 0;
		$totaloptions = sizeof($options);
		$percolumn = ceil($totaloptions/$columns);
		for ($i = 0; $i < $columns; $i++)
		{
			$html .= "\t<td class=\"$class\"><span class=\"smallfont\">\n";
			for ($j = 0; $j < $percolumn; $j++)
			{
				$html .= $options[$counter++];
			}
			$html .= "\t</span></td>\n";
		}
		$html .= "</tr></table>\n\t";
	}
	else
	{
		$html = "<div id=\"ctrl_$name\" class=\"smallfont\">\n" . implode('', $options) . "\t</div>";
	}

	print_label_row($title, $html, $class, 'top', $name);
}

// #############################################################################
/**
* Prints a row containing a <select> field
*
* @param	string	Title for row
* @param	string	Name for select field
* @param	array	Array of value => text pairs representing '<option value="$key">$value</option>' fields
* @param	string	Selected option
* @param	boolean	Whether or not to htmlspecialchars the text for the options
* @param	integer	Size of select field (non-zero means multi-line)
* @param	boolean	Whether or not to allow multiple selections
*/
function print_select_row($title, $name, $array, $selected = '', $htmlise = false, $size = 0, $multiple = false)
{
	global $vbulletin;
	$vb5_config = vB::getConfig();

	$uniqueid = fetch_uniqueid_counter();

	$select = "<div id=\"ctrl_$name\"><select name=\"$name\" id=\"sel_{$name}_$uniqueid\" tabindex=\"1\" class=\"bginput\"" . iif($size, " size=\"$size\"") . iif($multiple, ' multiple="multiple"') . iif($vb5_config['Misc']['debug'], " title=\"name=&quot;$name&quot;\"") . ">\n";
	$select .= construct_select_options($array, $selected, $htmlise);
	$select .= "</select></div>\n";

	print_label_row($title, $select, '', 'top', $name);
}

// #############################################################################
/**
* Returns a list of <option> fields, optionally with one selected
*
* @param	array	Array of value => text pairs representing '<option value="$key">$value</option>' fields
* @param	string	Selected option
* @param	boolean	Whether or not to htmlspecialchars the text for the options
*
* @return	string	List of <option> tags
*/
function construct_select_options($array, $selectedid = '', $htmlise = false, $disableOthers = false)
{
	if (is_array($array))
	{
		$options = '';
		foreach($array AS $key => $val)
		{
			if (is_array($val))
			{
				$options .= "\t\t<optgroup label=\"" . iif($htmlise, htmlspecialchars_uni($key), $key) . "\">\n";
				$options .= construct_select_options($val, $selectedid, $tabindex, $htmlise);
				$options .= "\t\t</optgroup>\n";
			}
			else
			{
				if (is_array($selectedid))
				{
					$selected = iif(in_array($key, $selectedid), ' selected="selected"', '');
				}
				else
				{
					$selected = iif($key == $selectedid, ' selected="selected"', '');
				}

				$disabled = '';
				if ($disableOthers AND !empty($selectedid) AND empty($selected))
				{
					$disabled = ' disabled';
				}

				$options .= "\t\t<option value=\"" . iif($key !== 'no_value', $key) . "\"$selected$disabled>" . iif($htmlise, vB_String::htmlSpecialCharsUni($val), $val) . "</option>\n";
			}
		}
	}
	return $options;
}

// #############################################################################
/**
* Prints a row containing a number of <input type="radio" /> buttons
*
* @param	string	Title for row
* @param	string	Name for radio buttons
* @param	array	Array of value => text pairs representing '<input type="radio" value="$key" />$value' fields
* @param	string	Selected radio button value
* @param	string	CSS class for <span> surrounding radio buttons
* @param	boolean	Whether or not to htmlspecialchars the text for the buttons
*/
function print_radio_row($title, $name, $array, $checked = '', $class = 'normal', $htmlise = false, $horizontal = false)
{
	$radios = "<div class=\"$class\">\n";
	$radios .= construct_radio_options($name, $array, $checked, $htmlise, '', $horizontal);
	$radios .= "\t</div>";

	print_label_row($title, $radios, '', 'top', $name);
}

// #############################################################################
/**
* Returns a list of <input type="radio" /> buttons, optionally with one selected
*
* @param	string	Name for radio buttons
* @param	array	Array of value => text pairs representing '<input type="radio" value="$key" />$value' fields
* @param	string	Selected radio button value
* @param	boolean	Whether or not to htmlspecialchars the text for the buttons
* @param	string	Indent string to place before buttons
*
* @return	string	List of <input type="radio" /> buttons
*/
function construct_radio_options($name, $array, $checkedid = '', $htmlise = false, $indent = '', $horizontal = false)
{
	global $vbulletin;
	$vb5_config = vB::getConfig();

	$options = "<div class=\"ctrl_$ctrl\">";

	if (is_array($array))
	{
		$uniqueid = fetch_uniqueid_counter();

		foreach($array AS $key => $val)
		{
			if (is_array($val))
			{
				$options .= "\t\t<b>" . iif($htmlise, htmlspecialchars_uni($key), $key) . "</b><br />\n";
				$options .= construct_radio_options($name, $val, $checkedid, $htmlise, '&nbsp; &nbsp; ');
			}
			else
			{
				$options .= "\t\t<label for=\"rb_$name{$key}_$uniqueid\">$indent<input type=\"radio\" name=\"$name\" id=\"rb_$name{$key}_$uniqueid\" tabindex=\"1\" value=\"" . iif($key !== 'no_value', $key) . "\"" . iif($vb5_config['Misc']['debug'], " title=\"name=&quot;$name&quot; value=&quot;$key&quot;\"") . iif($key == $checkedid, ' checked="checked"') . " />" . iif($htmlise, htmlspecialchars_uni($val), $val) . "</label>";
				if(!$horizontal)
				{
					$options .= '<br />';
				}
				$options .= "\n";
			}
		}
	}

	$options .= "</div>";

	return $options;
}

// #############################################################################
/**
* Prints a row containing a <select> menu containing the results of a simple select from a db table
*
* NB: This will only work if the db table contains '{tablename}id' and 'title' fields
*
* @param	string	Title for row
* @param	string	Name for select field
* @param	string	Name of db table to select from
* @param	string	Value of selected option
* @param	string	Optional extra <option> for the top of the list - value is -1, specify text here
* @param	integer	Size of select field. If non-zero, shows multi-line
* @param	string	Optional 'WHERE' clause for the SELECT query
* @param	boolean	Whether or not to allow multiple selections
*/
function print_chooser_row($title, $name, $tablename, $selvalue = -1, $extra = '', $size = 0, $wherecondition = '', $multiple = false)
{
	global $vbulletin;

	$tableid = $tablename . 'id';

	// check for cached version first...
	$cachename = 'i' . $tablename . 'cache_' .  md5($wherecondition);

	if (!is_array($GLOBALS["$cachename"]))
	{
		$GLOBALS["$cachename"] = array();
		$result = $vbulletin->db->query_read("SELECT title, $tableid FROM " . TABLE_PREFIX . "$tablename $wherecondition ORDER BY title");
		while ($currow = $vbulletin->db->fetch_array($result))
		{
			$GLOBALS["$cachename"]["$currow[$tableid]"] = $currow['title'];
		}
		unset($currow);
		$vbulletin->db->free_result($result);
	}

	$selectoptions = array();
	if ($extra)
	{
		$selectoptions['-1'] = $extra;
	}

	foreach ($GLOBALS["$cachename"] AS $itemid => $itemtitle)
	{
		$selectoptions["$itemid"] = $itemtitle;
	}

	print_select_row($title, $name, $selectoptions, $selvalue, 0, $size, $multiple);
}

// #############################################################################
/**
* Prints a row containing a <select> list of channels, complete with displayorder, parenting and depth information
*
* @param	string	text for the left cell of the table row
* @param	string	name of the <select>
* @param	mixed	selected <option>
* @param	string	name given to the -1 <option>
* @param	boolean	display the -1 <option> or not.
* @param	boolean	when true, allows multiple selections to be made. results will be stored in $name's array
* @param	string	Text to be used in sprintf() to indicate a 'category' channel, eg: '%s (Category)'. Leave blank for no category indicator
* @param bool $skip_root -- Whether to display the top level channel.
*/
function print_channel_chooser($title, $name, $selectedid = -1, $topname = null, $displayselectchannel = false, $multiple = false, $category_phrase = null, $skip_root = false)
{
	if ($displayselectchannel AND $selectedid <= 0)
	{
		$selectedid = 0;
	}

	$channels = vB_Api::instanceInternal('search')->getChannels();

	if ($skip_root)
	{
		$channels = current($channels);
		$channels = $channels['channels'];
	}

	$options = construct_channel_chooser_options($channels, $displayselectchannel, $topname, $category_phrase);
	print_select_row($title, $name, $options, $selectedid, 0, $multiple ? 10 : 0, $multiple);
}

// #############################################################################
/**
* Returns a list of <option> tags representing the list of channels
*
* @param	integer	Selected channel ID
* @param	boolean	Whether or not to display the 'Select Channel' option
* @param	string	If specified, name for the optional top element - no name, no display
* @param	string	Text to be used in sprintf() to indicate a 'category' channel, eg: '%s (Category)'. Leave blank for no category indicator
*
* @return	string	List of <option> tags
*/
function construct_channel_chooser($selectedid = -1, $displayselectchannel = false, $topname = null, $category_phrase = null)
{
	$channels = vB_Api::instanceInternal('search')->getChannels();
	return construct_select_options(construct_channel_chooser_options($channels, $displayselectchannel, $topname, $category_phrase), $selectedid);
}


// #############################################################################
/**
* Returns a list of <option> tags representing the list of forums
*
* @param	integer	Selected forum ID
* @param	boolean	Whether or not to display the 'Select Forum' option
* @param	string	If specified, name for the optional top element - no name, no display
* @param	string	Text to be used in sprintf() to indicate a 'category' forum, eg: '%s (Category)'. Leave blank for no category indicator
*
* @return	string	List of <option> tags
*/
function construct_forum_chooser($selectedid = -1, $displayselectforum = false, $topname = null, $category_phrase = null)
{
	return construct_select_options(construct_forum_chooser_options($displayselectforum, $topname, $category_phrase), $selectedid);
}

// #############################################################################
/**
* Returns a list of <option> tags representing the list of forums
*
* @param	boolean	Whether or not to display the 'Select Forum' option
* @param	string	If specified, name for the optional top element - no name, no display
* @param	string	Text to be used in sprintf() to indicate a 'category' forum, eg: '%s (Category)'. Leave blank for no category indicator
*
* @return	string	List of <option> tags
*/
function construct_forum_chooser_options($displayselectforum = false, $topname = null, $category_phrase = null)
{
	static $vbphrase;

	if (empty($vbphrase))
	{
		$vbphrase = vB_Api::instanceInternal('phrase')->fetch(array('select_forum', 'forum_is_closed_for_posting'));
	}
	$channels = vB_Api::instanceInternal('search')->getChannels(true);
	unset($channels[1]); // Unset Home channel

	$selectoptions = array();

	if ($displayselectforum)
	{
		$selectoptions[0] = $vbphrase['select_forum'];
	}

	if ($topname)
	{
		$selectoptions['-1'] = $topname;
		$startdepth = '--';
	}
	else
	{
		$startdepth = '';
	}

	if (!$category_phrase)
	{
		$category_phrase = '%s';
	}

	foreach ($channels AS $nodeid => $channel)
	{
		$channel['title'] = vB_String::htmlSpecialCharsUni(sprintf($category_phrase, $channel['title']));

		$selectoptions["$nodeid"] = construct_depth_mark($channel['depth'] - 1, '--', $startdepth) . ' ' . $channel['title'];
	}

	return $selectoptions;
}
// #############################################################################
/**
* Returns a list of <option> tags representing the list of channels
*
* @param	array	List of Channels to display
* @param	boolean	Whether or not to display the 'Select Channel' option
* @param	string	If specified, name for the optional top element - no name, no display
* @param	string	Text to be used in sprintf() to indicate a 'category' forum, eg: '%s (Category)'. Leave blank for no category indicator
*
* @return	string	List of <option> tags
*/
function construct_channel_chooser_options($channels, $displayselectchannel = false, $topname = null, $category_phrase = null)
{
	global $vbulletin, $vbphrase;

	$selectoptions = array();

	if ($displayselectchannel)
	{
		$selectoptions[0] = $vbphrase['select_channel'];
	}

	if ($topname)
	{
		$selectoptions['-1'] = $topname;
		$startdepth = '--';
	}
	else
	{
		$startdepth = '';
	}

	if (!$category_phrase)
	{
		$category_phrase = '%s';
	}

	foreach ($channels AS $nodeid => $channel)
	{
		if (!($channel['options'] & $vbulletin->bf_misc_forumoptions['cancontainthreads']))
		{
			$channel['htmltitle'] = sprintf($category_phrase, $channel['htmltitle']);
		}

		$selectoptions["$nodeid"] = $startdepth . str_repeat('--', $channel['depth']) . ' ' . vB_String::htmlSpecialCharsUni($channel['htmltitle']);
		if (!empty($channel['channels']))
		{
			$selectoptions += construct_channel_chooser_options($channel['channels'], $displayselectchannel, $topname, $category_phrase);
		}
	}

	return $selectoptions;
}
// #############################################################################
/**
* Returns a 'depth mark' for use in prefixing items that need to show depth in a hierarchy
*
* @param	integer	Depth of item (0 = no depth, 3 = third level depth)
* @param	string	Character or string to repeat $depth times to build the depth mark
* @param	string	Existing depth mark to append to
*
* @return	string
*/
function construct_depth_mark($depth, $depthchar, $depthmark = '')
{
	return $depthmark . str_repeat($depthchar, $depth);
}

// #############################################################################
/**
* Essentially just a wrapper for construct_help_button()
*
* @param	string	Option name
* @param	string	Action / Do name
* @param	string	Script name
* @param	integer	Help type
*
* @return	string
*/
function construct_table_help_button($option = '', $action = NULL, $script = '', $helptype = 0, $helpOptions = array())
{
	if ($helplink = construct_help_button($option, $action, $script, $helptype, $helpOptions))
	{
		return "$helplink ";
	}
	else
	{
		return '';
	}
}


function get_help_options()
{
	static $helpcache = null;
	if(is_null($helpcache))
	{
		try
		{
			$db = vB::getDbAssertor();
			$helptopics = $db->select('vBForum:adminhelp', array(), false, array('script', 'action', 'optionname'));

			$helpcache = array();
			foreach($helptopics AS $helptopic)
			{
				$multactions = explode(',', $helptopic['action']);
				foreach ($multactions AS $act)
				{
					$act = trim($act);
					$helpcache[$helptopic['script']][$act][$helptopic['optionname']] = 1;
				}
			}
		}
		//this most likely means that we are calling the help from tools.php or some other
		//context where the DB isn't set up and thus the query fails.  We should really
		//avoid doing this but we don't want to crash things if it happens
		catch(Exception $e)
		{
			$helpcache = array();
		}
	}

	return $helpcache;
}

// #############################################################################
/**
* Returns a help-link button for the specified script/action/option if available
*
* @param	string	Option name
* @param	string	Action / Do name (script.php?do=SOMETHING)
* @param	string	Script name (SCRIPT.php?do=something)
* @param	integer	Help type
*
* @return	string
*/
function construct_help_button($option = '', $action = null, $script = '', $helptype = 0, $helpOptions = array())
{
	// used to make a link to the help section of the CP related to the current action
	global $vbphrase, $vbulletin;

	$helpcache = get_help_options();

	$vb5_config = vB::getConfig();

	if ($action === null)
	{
		// matches type as well (===)
		$action = $_REQUEST['do'];
	}

	if (empty($script))
	{
		$script = $vbulletin->scriptpath;
	}

	if ($strpos = strpos($script, '?'))
	{
		$script = basename(substr($script, 0, $strpos));
	}
	else
	{
		$script = basename($script);
	}

	if ($strpos = strpos($script, '.'))
	{
		$script = substr($script, 0, $strpos); // remove the .php part as people may have different extensions
	}

	if ($option AND !isset($helpcache[$script][$action][$option]))
	{
		if (preg_match('#^[a-z0-9_]+(\[([a-z0-9_]+)\])+$#si', trim($option), $matches))
		{
			// parse out array notation, to just get index
			$option = $matches[2];
		}

		$option = str_replace('[]', '', $option);
	}

	if (!empty($helpOptions['prefix']))
	{
		$option = $helpOptions['prefix'] .  $option;
	}

	if (!$option)
	{
		if (!isset($helpcache[$script][$action]))
		{
			return '';
		}
	}
	else
	{
		if (!isset($helpcache[$script][$action][$option]))
		{
			if ($vb5_config['Misc']['debug'] AND defined('DEV_EXTRA_CONTROLS') AND DEV_EXTRA_CONTROLS)
			{
				return construct_link_code('AddHelp', "help.php?do=edit&amp;option=" . urlencode($option) . '&amp;script=' .
					urlencode($script) . '&amp;scriptaction=' . urlencode($action));
			}
			else
			{
				return '';
			}
		}
	}

	$vboptions = vB::getDatastore()->getValue('options');

	$helplink = "js_open_help('" . urlencode($script) . "', '" . urlencode($action) . "', '" . urlencode($option) . "'); return false;";

	$id = '';
	if ($option)
	{
		$id = $script . '_' . $action . '_' . $option;
	}

	switch ($helptype)
	{
		case 1:
			$linkphrase = $vbphrase['help'] . ' ';
			$titlephrase = $vbphrase['click_for_help_on_these_options'];
			$style = ' style="vertical-align:middle"';
			break;

		default:
			$linkphrase = '';
			$titlephrase = $vbphrase['click_for_help_on_these_options'];
			$style = '';
			break;
	}

	$linkbody = $linkphrase . '<img src="' . get_cpstyle_href('cp_help.' . $vboptions['cpstyleimageext']) .
		'" alt="" border="0" title="' . $titlephrase . '"' . $style . ' />';
	return '<a id="' . $id . '" class="helplink" href="#" onclick="' . $helplink .'">' . $linkbody . '</a>';
}

// #############################################################################
/**
* Returns a hyperlink
*
* @param	string	Hyperlink text
* @param	string	Hyperlink URL
* @param	boolean|string If true, hyperlink target="_blank" if a string value will use that as the target
* @param	string	If specified, parameter will be used as title="x" tooltip for link
* @param	bool	include the "admincp" prefix
*
* @param	string
*/
function construct_link_code($text, $url, $newwin = false, $tooltip = '', $smallfont = false, $admincp = true)
{
	if ($newwin === true OR $newwin === 1)
	{
		$newwin = '_blank';
	}

	if ($admincp)
	{
		$prefix = 'admincp/';
	}
	else
	{
		$prefix = '';
	}

	$target = '';
	if($newwin)
	{
		$target = ' target="' . $newwin . '"';
	}

	$title = '';
	if(!empty($tooltip))
	{
		$title = ' title="' . $tooltip . '"';
	}

	$link = 	" <a href=\"" . $prefix . $url . "\"" . $target . $title . '>' .
		(vB_Template_Runtime::fetchStyleVar('textdirection') == 'rtl' ? "[$text&lrm;]</a>&rlm; " : "[$text]</a> ");

	if ($smallfont)
	{
		$link = '<span class="smallfont">' . $link . '</span>';
	}

	return $link;
}

/**
* Returns a hyperlink
*
* @param	string	Hyperlink text
* @param	string	Hyperlink URL
* @param	boolean|string If true, hyperlink target="_blank" if a string value will use that as the target
* @param	string	If specified, parameter will be used as title="x" tooltip for link
*
* @param	string
*/
function construct_link_code2($text, $url, $newwin = false, $tooltip = '', $smallfont = false)
{
	if ($newwin === true OR $newwin === 1)
	{
		$newwin = '_blank';
	}

	$target = '';
	if($newwin)
	{
		$target = ' target="' . $newwin . '"';
	}

	$title = '';
	if(!empty($tooltip))
	{
		$title = ' title="' . $tooltip . '"';
	}

	$rlmarker = '';
	if(vB_Template_Runtime::fetchStyleVar('textdirection') == 'rtl')
	{
		$text = "$text&lrm;";
		$rlmarker = '&rlm;';
	}

	$link =	' <a href="' . htmlspecialchars($url) . '"' . $target . $title . '>[' . $text . ']</a>' . $marker . ' ';

	if ($smallfont)
	{
		$link = '<span class="smallfont">' . $link . '</span>';
	}

	return $link;
}


// #############################################################################
/**
* Returns an <input type="button" /> that acts like a hyperlink
*
* @param	string	Value for button
* @param	string	Hyperlink URL; special cases 'submit' and 'reset'
* @param	boolean	If true, hyperlink will open in a new window
* @param	string	If specified, parameter will be used as title="x" tooltip for button
* @param	boolean	If true, the hyperlink URL parameter will be treated as a javascript function call instead
*
* @return	string
*/
function construct_button_code($text = 'Click!', $link = '', $newwindow = false, $tooltip = '', $jsfunction = 0)
{
	if (preg_match('#^(submit|reset),?(\w+)?$#siU', $link, $matches))
	{
		$name_attribute = ($matches[2] ? " name=\"$matches[2]\"" : '');
		return " <input type=\"$matches[1]\"$name_attribute class=\"button\" value=\"$text\" title=\"$tooltip\" tabindex=\"1\" />";
	}
	else
	{
		$onclick = '';
		if($jsfunction)
		{
			$onclick = $link;
		}
		else if($newwindow)
		{
			$onclick = "window.open('$link')";
		}
		else
		{
			$onclick = "vBRedirect('$link')";
		}

		//the extra tooltip looks *wrong* but I need to do a search and destroy on that.
		return " <input type=\"button\" class=\"button\" value=\"$text\" title=\"$tooltip\" tabindex=\"1\" onclick=\"$onclick;\" $tooltip/> ";
	}
}

/**
 * Returns an <input type="button" /> that handles an "onclick" event.
 *
 * @param string $text -- button label
 * @param	string $link -- the url to link to on click
 * @param	boolean $newwindow -- whether to open the link in a new window or redirect the current page.
 * @param	string $id -- the html id value
 * @param	string $extraclass -- an extra class value for the button
 * @param	string $tooltip -- a tooltip for the button
 * @return string -- the html for the button.
 */
function construct_link_button_code($text, $link, $newwindow = false, $id='', $extraclass='', $tooltip='')
{
	if($newwindow)
	{
		$onclick = "window.open('$link')";
	}
	else
	{
		$onclick = "vBRedirect('$link')";
	}

	return construct_event_button_code($text, $onclick, $id, $extraclass, $tooltip);
}

/**
 * Returns an <input type="button" /> that handles an "onclick" event.
 *
 * @param string $text -- button label
 * @param	string $onclick -- the onlclick code
 * @param	string $id -- the html id value
 * @param	string $extraclass -- an extra class value for the button
 * @param	string $tooltip -- a tooltip for the button
 * @return string -- the html for the button.
 */
function construct_event_button_code($text, $onclick, $id='', $extraclass='', $tooltip='')
{
	$onclick = htmlspecialchars($onclick);

	$class = 'button';
	if($extraclass)
	{
		$class .= ' ' . $extraclass;
	}

	$button = '<input type="button" class="' . $class . '" value="' . $text . '"';
	if($tooltip)
	{
		$button .= ' title="' . $tooltip . '"';
	}

	if($id)
	{
		$button .= ' id="' . $id . '"';
	}

	$button .= ' tabindex="1" onclick="' . $onclick . '"/> ';
	return $button;
}

/**
* Checks whether or not the visiting user has administrative permissions
*
* This function can optionally take any number of parameters, each of which
* should be a particular administrative permission you want to check. For example:
* can_administer('canadminsettings', 'canadminstyles', 'canadminlanguages')
* If any one of these permissions is met, the function will return true.
*
* If no parameters are specified, the function will simply check that the user is an administrator.
*
* @return	boolean
*/
function can_administer()
{
	global $vbulletin, $_NAVPREFS;

	static $admin, $superadmins;

	$vb5_config =& vB::getConfig();

	if (!isset($_NAVPREFS))
	{
		$_NAVPREFS = preg_split('#,#', $vbulletin->userinfo['navprefs'], -1, PREG_SPLIT_NO_EMPTY);
	}

	if (!is_array($superadmins))
	{
		$superadmins = preg_split('#\s*,\s*#s', $vb5_config['SpecialUsers']['superadmins'], -1, PREG_SPLIT_NO_EMPTY);
	}

	$do = func_get_args();
	$userContext = vB::getUserContext();

	if ($vbulletin->userinfo['userid'] < 1)
	{
		// user is a guest - definitely not an administrator
		return false;
	}
	else if (!$userContext->isAdministrator())
	{
		// user is not an administrator at all
		return false;
	}
	else if ($userContext->isSuperAdmin())
	{
		// user is a super administrator (defined in config.php) so can do anything
		return true;
	}
	else if (empty($do))
	{
		// user is an administrator and we are not checking a specific permission
		return true;
	}
	else if (!isset($admin))
	{
		// query specific admin permissions from the administrator table and assign them to $adminperms
		$getperms = $vbulletin->db->query_first("
			SELECT *
			FROM " . TABLE_PREFIX . "administrator
			WHERE userid = " . $vbulletin->userinfo['userid']
		);

		$admin = $getperms;

		// add normal adminpermissions and specific adminpermissions
		$adminperms = $getperms['adminpermissions'] + $vbulletin->userinfo['permissions']['adminpermissions'];

		// save nav prefs choices
		$_NAVPREFS = preg_split('#,#', $getperms['navprefs'], -1, PREG_SPLIT_NO_EMPTY);
	}

	// final bitfield check on each permission we are checking
	foreach($do AS $field)
	{
		if (!$userContext->hasAdminPermission($field))
		{
			return false;
		}
	}

	// Legacy Hook 'can_administer' Removed //

	// if we got this far then there is no permission, unless the hook says so
	return true;
}

// #############################################################################
/**
* Halts execution and prints an error message stating that the administrator does not have permission to perform this action
*
* @param	string	This parameter is no longer used
*/
function print_cp_no_permission($do = '')
{
	global $vbulletin, $vbphrase;

	if (!defined('DONE_CPHEADER'))
	{
		print_cp_header($vbphrase['vbulletin_message']);
	}

	print_stop_message('no_access_to_admin_control', vB::getCurrentSession()->get('sessionurl'), $vbulletin->userinfo['userid']);

}

// #############################################################################
/**
* Saves data into the adminutil table in the database
*
* @param	string	Name of adminutil record to be saved
* @param	string	Data to be saved into the adminutil table
*
* @return	boolean
*/
function build_adminutil_text($title, $text = '')
{
	global $vbulletin;

	if ($text == '')
	{
		$vbulletin->db->query_write("
			DELETE FROM " . TABLE_PREFIX . "adminutil
			WHERE title = '" . $vbulletin->db->escape_string($title) . "'
		");
	}
	else
	{
		/*insert query*/
		$vbulletin->db->query_write("
			REPLACE INTO " . TABLE_PREFIX . "adminutil
			(title, text)
			VALUES
			('" . $vbulletin->db->escape_string($title) . "', '" . $vbulletin->db->escape_string($text) . "')
		");
	}

	return true;
}

// #############################################################################
/**
* Returns data from the adminutil table in the database
*
* @param	string	Name of the adminutil record to be fetched
*
* @return	string
*/
function fetch_adminutil_text($title)
{
	$text = vB::getDbAssertor()->getRow('adminutil', array('title' => $title));
	return $text['text'];
}

// #############################################################################
/**
* Halts execution and prints a Javascript redirect function to cause the browser to redirect to the specified page
*
* @param	string	Redirect target URL
* @param	float	Time delay (in seconds) before the redirect will occur
* @deprecated use print_cp_redirect
*/
function print_cp_redirect_old($gotopage, $timeout = 0)
{
	// performs a delayed javascript page redirection
	// get rid of &amp; if there are any...
	global $vbphrase;
	$gotopage = str_replace('&amp;', '&', $gotopage);

	if (!empty($gotopage) && ((($hashpos = strpos($gotopage, '#')) !== false) OR (($hashpos = strpos($gotopage, '%23')) !== false)))
	{
		$hashsize = (strpos($gotopage, '#') !== false) ? 1 : 3;
		$hash = substr($gotopage, $hashpos + $hashsize);
		$gotopage = substr($gotopage, 0, $hashpos);
	}

	$gotopage = create_full_url($gotopage);
	$gotopage = str_replace('"', '', $gotopage);
	if (!empty($hash))
	{
		$gotopage .= '#'.$hash;
	}

	if ($timeout == 0)
	{
		echo '<p align="center" class="smallfont"><a href="' . $gotopage . '">' . $vbphrase['processing_complete_proceed'] . '</a></p>';
		echo "\n<script type=\"text/javascript\">\n";
		echo "window.location=\"$gotopage\";";
		echo "\n</script>\n";
	}
	else
	{
		echo "\n<script type=\"text/javascript\">\n";
		echo "myvar = \"\"; timeout = " . ($timeout*10) . ";
		function exec_refresh()
		{
			window.status=\"" . $vbphrase['redirecting']."\"+myvar; myvar = myvar + \" .\";
			timerID = setTimeout(\"exec_refresh();\", 100);
			if (timeout > 0)
			{ timeout -= 1; }
			else { clearTimeout(timerID); window.status=\"\"; window.location=\"$gotopage\"; }
		}
		exec_refresh();";
		echo "\n</script>\n";
		echo '<p align="center" class="smallfont"><a href="' . $gotopage . '" onclick="javascript:clearTimeout(timerID);">' . $vbphrase['processing_complete_proceed'] . '</a></p>';
	}
	print_cp_footer();
	exit;
}

/**
 * @deprecated use print_cp_redirect and get_redirect_url directly
 */
function print_cp_redirect2($file, $extra = array(), $timeout = 0, $route = 'admincp')
{
	print_cp_redirect_old(get_redirect_url($file, $extra, $route), $timeout);
}

// #############################################################################
/**
* Halts execution and prints a Javascript redirect function to cause the browser to redirect to the specified page
*
* @param	string	Redirect target URL -- this should *not* be hmtl encoded
* @param	float	Time delay (in seconds) before the redirect will occur
*/
function print_cp_redirect($gotopage, $timeout = 0)
{
	global $vbphrase;

	//create_full_url is old and weird.  Let's just check to see if this is an absolute url and
	//go with it.  We should probably mostly have a fully qualified url from get_redirect_url
	//(which is the most likely source of $goto page).  And we only likely need it for the
	//javascript which can get squirrely in IE (which doesn't always respect the base url in
	//javascript). At some point we should allow relative urls (to the base) and remove this
	//entirely.
	if (strtolower(substr($gotopage, 0, 4)) != 'http')
	{
		$gotopage = vB::getDatastore()->getOption('frontendurl') . '/' . ltrim($gotopage, '/');
	}

	$gotopagehtml = htmlentities($gotopage);
	if ($timeout == 0)
	{
		echo '<p align="center" class="smallfont"><a href="' . $gotopagehtml . '">' . $vbphrase['processing_complete_proceed'] . '</a></p>';
		echo "\n<script type=\"text/javascript\">\n";
		echo "window.location=\"$gotopage\";";
		echo "\n</script>\n";
	}
	else
	{
		echo "\n<script type=\"text/javascript\">\n";
		echo "myvar = \"\"; timeout = " . ($timeout*10) . ";
		function exec_refresh()
		{
			window.status=\"" . $vbphrase['redirecting']."\"+myvar; myvar = myvar + \" .\";
			timerID = setTimeout(\"exec_refresh();\", 100);
			if (timeout > 0)
			{
				timeout -= 1;
			}
			else
			{
				clearTimeout(timerID);
				window.status=\"\";
				window.location=\"$gotopage\";
			}
		}
		exec_refresh();";
		echo "\n</script>\n";
		echo '<p align="center" class="smallfont"><a href="' . $gotopagehtml . '" onclick="javascript:clearTimeout(timerID);">' . $vbphrase['processing_complete_proceed'] . '</a></p>';
	}
	print_cp_footer();
	exit;
}


// #############################################################################
/**
* Prints a block of HTML containing a character that multiplies in width via javascript - a kind of progress meter
*
* @param	string	Text to be printed above the progress meter
* @param	string	Character to be used as the progress meter
* @param	string	Name to be given as the id for the HTML element containing the progress meter
*/
function print_dots_start($text, $dotschar = ':', $elementid = 'dotsarea')
{
	if (defined('NO_IMPORT_DOTS'))
	{
		return;
	}

	vbflush(); ?>
	<p align="center"><?php echo $text; ?><br /><br />[<span class="progress_dots" id="<?php echo $elementid; ?>"><?php echo $dotschar; ?></span>]</p>
	<script type="text/javascript"><!--
	function js_dots()
	{
		<?php echo $elementid; ?>.innerText = <?php echo $elementid; ?>.innerText + "<?php echo $dotschar; ?>";
		jstimer = setTimeout("js_dots();", 75);
	}
	if (document.all)
	{
		js_dots();
	}
	//--></script>
	<?php vbflush();
}

// #############################################################################
/**
* Prints a javascript code block that will halt the progress meter started with print_dots_start()
*/
function print_dots_stop()
{
	if (defined('NO_IMPORT_DOTS'))
	{
		return;
	}

	vbflush(); ?>
	<script type="text/javascript"><!--
	if (document.all)
	{
		clearTimeout(jstimer);
	}
	//--></script>
	<?php vbflush();
}

// #############################################################################
/**
* Writes data to a file
*
* @param	string	Path to file (including file name)
* @param	string	Data to be saved into the file
* @param	boolean	If true, will create a backup of the file called {filename}old
*/
function file_write($path, $data, $backup = false)
{
	if (file_exists($path) != false)
	{
		if ($backup)
		{
			$filenamenew = $path . 'old';
			rename($path, $filenamenew);
		}
		else
		{
			unlink($path);
		}
	}
	if ($data != '')
	{
		$filenum = fopen($path, 'w');
		fwrite($filenum, $data);
		fclose($filenum);
	}
}

// #############################################################################
/**
* Returns the contents of a file
*
* @param	string	Path to file (including file name)
*
* @return	string	If file does not exist, returns an empty string
*/
function file_read($path)
{
	// On some versions of PHP under IIS, file_exists returns false for uploaded files,
	// even though the file exists and is readable. http://bugs.php.net/bug.php?id=38308
	if(!file_exists($path) AND !is_uploaded_file($path))
	{
		return '';
	}
	else
	{
		$filestuff = @file_get_contents($path);
		return $filestuff;
	}
}

// #############################################################################
/**
 * @deprecated
* Reads settings from the settings then saves the values to the datastore
*
* After reading the contents of the setting table, the function will rebuild
* the $vbulletin->options array, then serialize the array and save that serialized
* array into the 'options' entry of the datastore in the database
*
* @return	array	The $vbulletin->options array
*/
function build_options()
{
	return vB::getDatastore()->build_options();
}

// #############################################################################
/**
* Saves a log into the adminlog table in the database
*
* @param	string	Extra info to be saved
* @param	integer	User ID of the visiting user
* @param	string	Name of the script this log applies to
* @param	string	Action / Do branch being viewed
*/
function log_admin_action($extrainfo = '', $userid = -1, $script = '', $scriptaction = '')
{
	// logs current activity to the adminlog db table

	if ($userid == -1)
	{
		$userInfo = vB::getCurrentSession()->fetch_userinfo();
		$userid = $userInfo['userid'];
	}
	if (empty($script))
	{
		$script = !empty($_SERVER['REQUEST_URI']) ? basename(strtok($_SERVER['REQUEST_URI'],'?')) : basename($_SERVER['PHP_SELF']);
	}
	if (empty($scriptaction))
	{
		$scriptaction = $_REQUEST['do'];
	}

	vB::getDbAssertor()->assertQuery('vBForum:adminlog',
			array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERT,
					'userid' => $userid,
					'dateline' => TIMENOW,
					'script' => $script,
					'action' => $scriptaction,
					'extrainfo' => $extrainfo,
					'ipaddress' => IPADDRESS,
			)
	);
}

// #############################################################################
/**
* Checks whether or not the visiting user can view logs
*
* @param	string	Comma-separated list of user IDs permitted to view logs
* @param	boolean	Variable to return if the previous parameter is found to be empty
* @param	string	Message to print if the user is NOT permitted to view
*
* @return	boolean
*/
function can_access_logs($idvar, $defaultreturnvar = false, $errmsg = '')
{
	if (empty($idvar))
	{
		return $defaultreturnvar;
	}
	else
	{
		$perm = trim($idvar);
		$logperms = explode(',', $perm);
		$userinfo = vB::getCurrentSession()->fetch_userinfo();
		if (in_array($userinfo['userid'], $logperms))
		{
			return true;
		}
		else
		{
			echo $errmsg;
			return false;
		}
	}
}

// #############################################################################
/**
* Prints a dialog box asking if the user is sure they want to delete the specified item from the database
*
* @param	string	Name of table from which item will be deleted
* @param	mixed		ID of item to be deleted
* @param	string	PHP script to which the form will submit
* @param	string	'do' action for target script
* @param	string	Word describing item to be deleted - eg: 'forum' or 'user' or 'post' etc.
* @param	mixed		If not empty, an array containing name=>value pairs to be used as hidden input fields
* @param	string	Extra text to be printed in the dialog box
* @param	string	Name of 'title' field in the table in the database
* @param	string	Name of 'idfield' field in the table in the database
*/
function print_delete_confirmation($table, $itemid, $phpscript, $do, $itemname = '', $hiddenfields = 0, $extra = '', $titlename = 'title', $idfield = '')
{
	global $vbphrase;

	$idfield = $idfield ? $idfield : $table . 'id';
	$itemname = $itemname ? $itemname : $table;
	$deleteword = 'delete';
	$encodehtml = true;
	$assertor = vB::getDbAssertor();

	switch($table)
	{
		case 'infraction':
			$item = vB_Library::instance('content_infraction')->getInfraction($itemid);
			$item['title'] = (!empty($item) AND isset($item['title'])) ? $item['title'] : '';
			break;
		case 'reputation':
			$item = $assertor->getRow('vBForum:reputation', array('reputationid' => $itemid));
			$item['title'] = (!empty($item) AND isset($item['reputationid'])) ? $item['reputationid'] : '';
			break;
		case 'user':
			$item = $assertor->getRow('user', array('userid' => $itemid));
			$item['title'] = (!empty($item) AND isset($item['username'])) ? $item['username'] : '';
			break;
		case 'moderator':
			$item = $assertor->getRow('vBForum:getModeratorBasicFields', array('moderatorid' => $itemid));
			$item['title'] = construct_phrase($vbphrase['x_from_the_forum_y'], $item['username'], $item['title']);
			$encodehtml = false;
			break;
		case 'calendarmoderator':
			$item = $assertor->getRow('vBForum:getCalendarModeratorBasicFields', array('calendarmoderatorid' => $itemid));
			$item['title'] = construct_phrase($vbphrase['x_from_the_calendar_y'], $item['username'], $item['title']);
			$encodehtml = false;
			break;
		case 'phrase':
			$item = $assertor->getRow('vBForum:phrase', array('phraseid' => $itemid));
			$item['title'] = (!empty($item) AND isset($item['varname'])) ? $item['varname'] : '';
			break;
		case 'userpromotion':
			$item = $assertor->getRow('getUserPromotionBasicFields', array('userpromotionid' => $itemid));
			break;
		case 'usergroupleader':
			$item = $assertor->getRow('vBForum:getUserGroupLeaderBasicFields', array('usergroupleaderid' => $itemid));
			break;
		case 'setting':
			$item = $assertor->getRow('setting', array('varname' => $itemid));
			$item['title'] = (!empty($item) AND isset($item['varname'])) ? $item['varname'] : '';
			$idfield = 'title';
			break;
		case 'settinggroup':
			$item = $assertor->getRow('settinggroup', array('grouptitle' => $itemid));
			$item['title'] = (!empty($item) AND isset($item['grouptitle'])) ? $item['grouptitle'] : '';
			$idfield = 'title';
			break;
		case 'adminhelp':
			$item = $assertor->getRow('vBForum:getAdminHelpBasicFields', array('adminhelpid' => $itemid));
			break;
		case 'faq':
			$item = $assertor->getRow('vBForum:getFaqBasicFields', array('faqname' => $itemid));
			$idfield = 'faqname';
			break;
		case 'hook':
			$item = $assertor->getRow('hook', array('hookid' => $itemid));
			$item['title'] = (!empty($item) AND isset($item['title'])) ? $item['title'] : '';
			break;
		case 'product':
			$item = $assertor->getRow('product', array('productid' => $itemid));
			$item['title'] = (!empty($item) AND isset($item['title'])) ? $item['title'] : '';
			break;
		case 'prefix':
			$item = $assertor->getRow('vBForum:prefix', array('prefixid' => $itemid));
			$item['title'] = (!empty($item['prefixid'])) ? $vbphrase["prefix_$item[prefixid]_title_plain"] : '';
			break;
		case 'prefixset':
			$item = $assertor->getRow('vBForum:prefixset', array('prefixsetid' => $itemid));
			$item['title'] = (!empty($item['prefixsetid'])) ? $vbphrase["prefixset_$item[prefixsetid]_title"] : '';
			break;
		case 'stylevar':
			$item = $assertor->getRow('vBForum:stylevar', array('stylevarid' => $itemid));
			break;
		case 'announcement':
			$item = $assertor->getRow('vBForum:announcement', array('announcementid' => $itemid));
			$item['title'] = (!empty($item) AND isset($item['title'])) ? $item['title'] : '';
			break;
		case 'notice':
			$handled = false;
			// Legacy Hook 'admin_delete_confirmation' Removed //
			if (!$handled)
			{
				$item = $assertor->getRow('vBForum:notice', array($idfield => $itemid));
				$item['title'] = (!empty($item) AND isset($item[$titlename])) ? $item[$titlename] : '';
			}
			break;
		case 'eventhighlight':
			$item = vB_Api::instanceInternal('eventhighlight')->getEventHighlightAdmin($itemid);
			$item['title'] = (!empty($item) AND isset($item['name'])) ? $item['name'] : '';
			break;
		default:
			$handled = false;
			// Legacy Hook 'admin_delete_confirmation' Removed //
			if (!$handled)
			{
				$item = $assertor->getRow($table, array($idfield => $itemid));
				$item['title'] = (!empty($item) AND isset($item[$titlename])) ? $item[$titlename] : '';
			}
			break;
	}

	switch($table)
	{
		case 'template':
			if ($itemname == 'replacement_variable')
			{
				$deleteword = 'delete';
			}
			else
			{
				$deleteword = 'revert';
			}
		break;

		case 'adminreminder':
			if (vbstrlen($item['title']) > 30)
			{
				$item['title'] = substr($item['title'], 0, 30) . '...';
			}
		break;

		case 'vBForum:subscription':
			$item['title'] = (!empty($item['subscriptionid'])) ? $vbphrase['sub' . $item['subscriptionid'] . '_title'] : '';
		break;

		case 'stylevar':
			$item['title'] = (!empty($item['stylevarid'])) ? $vbphrase['stylevar' . $item['stylevarid'] . $titlename . '_name'] : '';

			//Friendly names not
			if (!$item['title'])
			{
				$item['title'] = $item["$idfield"];
			}

			$deleteword = 'revert';
		break;
	}

	if ($encodehtml
		AND (strcspn($item['title'], '<>"') < strlen($item['title'])
			OR (strpos($item['title'], '&') !== false AND !preg_match('/&(#[0-9]+|amp|lt|gt|quot);/si', $item['title']))
		)
	)
	{
		// title contains html entities that should be encoded
		$item['title'] = htmlspecialchars_uni($item['title']);
	}

	if ($item["$idfield"] == $itemid AND !empty($itemid))
	{
		echo "<p>&nbsp;</p><p>&nbsp;</p>";
		print_form_header("admincp/$phpscript", $do, 0, 1, '', '75%');
		construct_hidden_code(($idfield == 'styleid' OR $idfield == 'languageid') ? 'do' . $idfield : $idfield, $itemid);
		if (is_array($hiddenfields))
		{
			foreach($hiddenfields AS $varname => $value)
			{
				construct_hidden_code($varname, $value);
			}
		}
		print_table_header(construct_phrase($vbphrase['confirm_deletion_x'], $item['title']));
		print_description_row("
			<blockquote><br />
			" . construct_phrase(
					$vbphrase["are_you_sure_want_to_{$deleteword}_{$itemname}_x"],
					$item['title'],
					$idfield,
					$item["$idfield"],
					iif($extra, "$extra<br /><br />")
				) . "
			<br /></blockquote>\n\t");
		print_submit_row($vbphrase['yes'], 0, 2, $vbphrase['no']);
	}
	else
	{
		print_stop_message('could_not_find', '<b>' . $itemname . '</b>', $idfield, $itemid);
	}
}

// #############################################################################
/**
* Prints a dialog box asking if the user if they want to continue
*
* @param	string	Phrase that is presented to the user
* @param	string	PHP script to which the form will submit
* @param	string	'do' action for target script
* @param	mixed		If not empty, an array containing name=>value pairs to be used as hidden input fields
*/
function print_confirmation($phrase, $phpscript, $do, $hiddenfields = array())
{
	global $vbulletin, $vbphrase;

	echo "<p>&nbsp;</p><p>&nbsp;</p>";
	print_form_header("admincp/$phpscript", $do, 0, 1, '', '75%');
	if (is_array($hiddenfields))
	{
		foreach($hiddenfields AS $varname => $value)
		{
			construct_hidden_code($varname, $value);
		}
	}
	print_table_header($vbphrase['confirm_action']);
	print_description_row("
		<blockquote><br />
		$phrase
		<br /></blockquote>\n\t");
	print_submit_row($vbphrase['yes'], 0, 2, $vbphrase['no']);

}

// #############################################################################
/**
* Halts execution and shows a message based upon a parsed phrase
*
* After the first parameter, this function can take any number of additional
* parameters, in order to replace {1}, {2}, {3},... {n} variable place holders
* within the given phrase text. The parsed phrase is then passed to print_cp_message()
*
* Note that a redirect can be performed if CP_REDIRECT is defined with a URL
*
* @deprecated
* @param	string	Name of phrase (from the Error phrase group)
* @param	string	1st variable replacement {1}
* @param	string	2nd variable replacement {2}
* @param	string	Nth variable replacement {n}
*/
function print_stop_message($phrasename)
{
	global $vbulletin, $vbphrase;

	$phraseAux = vB_Api::instanceInternal('phrase')->fetch(array($phrasename));
	$message = $phraseAux[$phrasename];

	$args = func_get_args();
	if (sizeof($args) > 1)
	{
		$args[0] = $message;
		$message = call_user_func_array('construct_phrase', $args);
	}

	if (defined('CP_CONTINUE'))
	{
		define('CP_REDIRECT', CP_CONTINUE);
	}

	if ($vbulletin->GPC['ajax'])
	{
		$xml = new vB_XML_Builder_Ajax('text/xml');
		$xml->add_tag('error', $message);
		$xml->print_xml();
	}

	if (VB_AREA == 'Upgrade')
	{
		echo $message;
		exit;
	}

	print_cp_message(
		$message,
		defined('CP_REDIRECT') ? CP_REDIRECT : NULL,
		1,
		defined('CP_BACKURL') ? CP_BACKURL : NULL,
		defined('CP_CONTINUE') ? true : false
	);
}

/**
 * Turn the filename, extra params into a url -- this should only be called by
 * functions in the adminfunction.php file.
 *
 * @param  string Admin CP file name
 * @param  array  Array of key=>value pairs for query params. A #fragament can be included
 *                by using '#' for the key.
 * @param  string Route name
 *
 * @return string URL
 *
 * @private
 */
function get_redirect_url($file, $extra, $route = 'admincp')
{
	/*
		Remove preceding "$route/" (ex. "admincp/" and succeeding ".php", only leaving the filename.
		Since the admincp ROUTE is used to create the URL, the prefix & file extension must not be in the $file route data.
	 */
	if (empty($route))
	{
		// Route creation will flop if no route's given. This is actually a *caller* bug, but let's be nice and put up a default.
		$route = 'admincp';
	}
	$file = preg_replace('#^' . preg_quote($route, '#'). '/|\.php$#si', '', $file);
	$vb5_options = vB::getDatastore()->getValue('options');

	$fragment = '';
	if (!empty($extra['#']))
	{
		$fragment = $extra['#'];
		unset($extra['#']);
	}

	if (strpos(VB_URL, $vb5_options['bburl']) !== false)
	{
		$redirect = $file . '.php?' . http_build_query($extra) . ($fragment ? "#$fragment" : '');
	}
	else
	{
		$redirect = vB5_Route::buildUrl($route . '|fullurl', array('file' => $file), $extra, $fragment);
	}
	return $redirect;
}

function print_modcp_stop_message2($phrase, $file = NULL, $extra = array(), $backurl = NULL, $continue = false)
{
	return print_stop_message2($phrase, $file, $extra, $backurl, $continue, 'modcp');
}



function print_stop_message_array($phrases, $file = NULL, $extra = array(), $backurl = NULL, $continue = false, $redirect_route = 'admincp')
{
	$phrases = vB_Api::instanceInternal('phrase')->renderPhrases($phrases);
	$message = implode("<br/><br/>", $phrases['phrases']);

	//todo -- figure out where this is needed and remove.
	global $vbulletin;
	if ($vbulletin->GPC['ajax'])
	{
		$xml = new vB_XML_Builder_Ajax('text/xml');
		$xml->add_tag('error', $message);
		$xml->print_xml();
	}

	//todo -- figure out where this is needed and remove.
	if (VB_AREA == 'Upgrade')
	{
		echo $message;
		exit;
	}

	$hash = '';
	if ($file)
	{
		if (!empty($extra['#']))
		{
			$hash = '#' . $extra['#'];
			unset($extra['#']);
		}
		$redirect = get_redirect_url($file, $extra, $redirect_route);
	}

	print_cp_message(
		$message,
		$redirect . $hash,
		1,
		$backurl,
		$continue
	);
}

function print_stop_message2($phrase, $file = NULL, $extra = array(), $backurl = NULL, $continue = false, $redirect_route = 'admincp')
{
	//handle phrase as a string
	if (!is_array($phrase))
	{
		$phrase = array($phrase);
	}

	$phrases = vB_Api::instanceInternal('phrase')->renderPhrases(array($phrase));
	$message = reset($phrases['phrases']);

	//todo -- figure out where this is needed and remove.
	global $vbulletin;
	if ($vbulletin->GPC['ajax'])
	{
		$xml = new vB_XML_Builder_Ajax('text/xml');
		$xml->add_tag('error', $message);
		$xml->print_xml();
	}

	//todo -- figure out where this is needed and remove.
	if (VB_AREA == 'Upgrade')
	{
		echo $message;
		exit;
	}

	$hash = '';
	if ($file)
	{
		if (!empty($extra['#']))
		{
			$hash = '#' . $extra['#'];
			unset($extra['#']);
		}
		$redirect = get_redirect_url($file, $extra, $redirect_route);
	}

	print_cp_message(
		$message,
		$redirect . $hash,
		1,
		$backurl,
		$continue
	);
}

// #############################################################################
/**
* Halts execution and shows the specified message
*
* @param	string	Message to display
* @param	mixed	If specified, a redirect will be performed to the URL in this parameter
* @param	integer	If redirect is specified, this is the time in seconds to delay before redirect
* @param	string	If specified, will provide a specific URL for "Go Back". If empty, no button will be displayed!
* @param bool		If true along with redirect, 'CONTINUE' button will be used instead of automatic redirect
*/
function print_cp_message($text = '', $redirect = NULL, $delay = 1, $backurl = NULL, $continue = false)
{
	global $vbulletin, $vbphrase;

	if ($vbulletin->GPC['ajax'])
	{
		$xml = new vB_XML_Builder_Ajax('text/xml');
		$xml->add_tag('error', $text);
		$xml->print_xml();
		exit;
	}

	if ($redirect)
	{
		if ((($hashpos = strpos($redirect, '#')) !== false) OR (($hashpos = strpos($redirect, '%23')) !== false))
		{
			$hashsize = (strpos($redirect, '#') !== false) ? 1 : 3;
			$hash = substr($redirect, $hashpos + $hashsize);
			$redirect = substr($redirect, 0, $hashpos);
		}

		if ($session = vB::getCurrentSession()->get('sessionurl'))
		{
			if (strpos($redirect, $session) !== false)
			{
				if (strpos($redirect, '?') === false)
				{
					$redirect .= '?' . $session;
				}
				else
				{
					$redirect .= '&' . $session;
				}
			}
		}
	}

	if (!defined('DONE_CPHEADER'))
	{
		print_cp_header($vbphrase['vbulletin_message']);
	}

	print_form_header('admincp/', '', 0, 1, 'messageform', '65%');
	print_table_header(new vB_Phrase('global', 'vbulletin_message'));
	print_description_row("<blockquote><br />$text<br /><br /></blockquote>");

	if ($redirect)
	{
		// redirect to the new page
		if ($continue)
		{
			$continueurl = create_full_url(str_replace('&amp;', '&', $redirect));
			if (!empty($hash))
			{
				$continueurl .= '#'.$hash;
			}

			print_table_footer(2, construct_button_code($vbphrase['continue'], $continueurl));
		}
		else
		{
			print_table_footer();

			$redirect_click = create_full_url($redirect);
			if (!empty($hash))
			{
				$redirect_click .= '#'.$hash;
				$redirect .= '#'.$hash;
			}
			$redirect_click = str_replace('"', '', $redirect_click);

			echo '<p align="center" class="smallfont">' . construct_phrase($vbphrase['if_you_are_not_automatically_redirected_click_here_x'], $redirect_click) . "</p>\n";
			print_cp_redirect($redirect, $delay);
		}
	}
	else
	{
		// end the table and halt
		if ($backurl === NULL)
		{
			$backurl = 'javascript:history.back(1)';
		}

		if (strpos($backurl, 'history.back(') !== false)
		{
			//if we are attempting to run a history.back(1), check we have a history to go back to, otherwise attempt to close the window.
			$back_button = '&nbsp;
				<input type="button" id="backbutton" class="button" value="' . (new vB_Phrase('global', 'go_back')) . '" title="" tabindex="1" onclick="if (history.length) { history.back(1); } else { self.close(); }"/>
				&nbsp;
				<script type="text/javascript">
				<!--
				if (history.length < 1 || ((is_saf || is_moz) && history.length <= 1)) // safari + gecko start at 1
				{
					document.getElementById("backbutton").parentNode.removeChild(document.getElementById("backbutton"));
				}
				//-->
				</script>';

			// remove the back button if it leads back to the login redirect page
			if (strpos($vbulletin->url, 'login.php?do=login') !== false)
			{
				$back_button = '';
			}
		}
		else if ($backurl !== '')
		{
			// regular window.location=url call
			$backurl = create_full_url($backurl);
			$backurl = str_replace(array('"', "'"), '', $backurl);
			$back_button = '<input type="button" class="button" value="' . (new vB_Phrase('global', 'go_back')) . '" title="" tabindex="1" onclick="window.location=\'' . $backurl . '\';"/>';
		}
		else
		{
			$back_button = '';
		}

		print_table_footer(2, $back_button);
	}

	// and now terminate the script
	print_cp_footer();
}

/**
* Verifies the CP sessionhash is sent through with the request to prevent
* an XSS-style issue.
*
* @param	boolean	Whether to halt if an error occurs
* @param	string	Name of the input variable to look at
*
* @return	boolean	True on success, false on failure
*/
function verify_cp_sessionhash($halt = true, $input = 'hash')
{
	global $vbulletin;

	assert_cp_sessionhash();

	if (!isset($vbulletin->GPC["$input"]))
	{
		$vbulletin->input->clean_array_gpc('r', array(
			$input => vB_Cleaner::TYPE_STR
		));
	}

	if ($vbulletin->GPC["$input"] != CP_SESSIONHASH)
	{
		if ($halt)
		{
			print_stop_message2('security_alert_hash_mismatch');
		}
		else
		{
			return false;
		}
	}

	return true;
}

/**
 * Defines a valid CP_SESSIONHASH.
 */
function assert_cp_sessionhash()
{
	if (defined('CP_SESSIONHASH'))
	{
		return;
	}

	global $vbulletin;
	$options = vB::getDatastore()->getValue('options');
	$userId = vB::getCurrentSession()->get('userid');
	$timeNow = vB::getRequest()->getTimeNow();
	$assertor = vB::getDbAssertor();

	$cpsession = array();

	$vbulletin->input->clean_array_gpc('c', array(
		COOKIE_PREFIX . 'cpsession' => vB_Cleaner::TYPE_STR,
	));

	if (!empty($vbulletin->GPC[COOKIE_PREFIX . 'cpsession']))
	{
		$timecut = ($options['timeoutcontrolpanel'] ? intval($timeNow - $options['cookietimeout']) : intval($timeNow - 3600));
		$cpsession = $assertor->getRow('cpsession', array(
			vB_dB_Query::CONDITIONS_KEY => array(
				array('field' => 'userid', 'operator' => vB_dB_Query::OPERATOR_EQ, 'value' => $userId),
				array('field' => 'hash', 'operator' => vB_dB_Query::OPERATOR_EQ, 'value' => $vbulletin->GPC[COOKIE_PREFIX . 'cpsession']),
				array('field' => 'dateline', 'operator' => vB_dB_Query::OPERATOR_GT, 'value' => $timecut),
			)
		));

		if (!empty($cpsession))
		{
			$assertor->assertQuery('cpSessionUpdate', array(
				'timenow' => $timeNow,
				'userid' => $userId,
				'hash' => $vbulletin->GPC[COOKIE_PREFIX . 'cpsession']
			));
		}
	}

	vB::getCurrentSession()->setCpsessionHash($cpsession['hash']);
	define('CP_SESSIONHASH', $cpsession['hash']);
}

// #############################################################################
/**
* Returns an array of timezones, keyed with their offset from GMT
*
* @return	array	Timezones array
*/
function fetch_timezones_array()
{
	global $vbphrase;

	return array(
		'-12'  => $vbphrase['timezone_gmt_minus_1200'],
		'-11'  => $vbphrase['timezone_gmt_minus_1100'],
		'-10'  => $vbphrase['timezone_gmt_minus_1000'],
		'-9.5' => $vbphrase['timezone_gmt_minus_0930'],
		'-9'   => $vbphrase['timezone_gmt_minus_0900'],
		'-8'   => $vbphrase['timezone_gmt_minus_0800'],
		'-7'   => $vbphrase['timezone_gmt_minus_0700'],
		'-6'   => $vbphrase['timezone_gmt_minus_0600'],
		'-5'   => $vbphrase['timezone_gmt_minus_0500'],
		'-4.5' => $vbphrase['timezone_gmt_minus_0430'],
		'-4'   => $vbphrase['timezone_gmt_minus_0400'],
		'-3.5' => $vbphrase['timezone_gmt_minus_0330'],
		'-3'   => $vbphrase['timezone_gmt_minus_0300'],
		'-2'   => $vbphrase['timezone_gmt_minus_0200'],
		'-1'   => $vbphrase['timezone_gmt_minus_0100'],
		'0'    => $vbphrase['timezone_gmt_plus_0000'],
		'1'    => $vbphrase['timezone_gmt_plus_0100'],
		'2'    => $vbphrase['timezone_gmt_plus_0200'],
		'3'    => $vbphrase['timezone_gmt_plus_0300'],
		'3.5'  => $vbphrase['timezone_gmt_plus_0330'],
		'4'    => $vbphrase['timezone_gmt_plus_0400'],
		'4.5'  => $vbphrase['timezone_gmt_plus_0430'],
		'5'    => $vbphrase['timezone_gmt_plus_0500'],
		'5.5'  => $vbphrase['timezone_gmt_plus_0530'],
		'5.75' => $vbphrase['timezone_gmt_plus_0545'],
		'6'    => $vbphrase['timezone_gmt_plus_0600'],
		'6.5'  => $vbphrase['timezone_gmt_plus_0630'],
		'7'    => $vbphrase['timezone_gmt_plus_0700'],
		'8'    => $vbphrase['timezone_gmt_plus_0800'],
		'8.5'  => $vbphrase['timezone_gmt_plus_0830'],
		'8.75' => $vbphrase['timezone_gmt_plus_0845'],
		'9'    => $vbphrase['timezone_gmt_plus_0900'],
		'9.5'  => $vbphrase['timezone_gmt_plus_0930'],
		'10'   => $vbphrase['timezone_gmt_plus_1000'],
		'10.5'  => $vbphrase['timezone_gmt_plus_1030'],
		'11'   => $vbphrase['timezone_gmt_plus_1100'],
		'12'   => $vbphrase['timezone_gmt_plus_1200']
	);
}

// #############################################################################
/**
* Reads all data from the specified image table and writes the serialized data to the datastore
*
* @param	string	Name of image table (avatar/icon/smilie)
*/
function build_image_cache($table)
{
	global $vbulletin;

	if ($table == 'avatar')
	{
		return;
	}

	DEVDEBUG("Updating $table cache template...");

	$itemid = $table.'id';
	if ($table == 'smilie')
	{
		// the smilie cache is basically only used for parsing; displaying smilies comes from a query
		$items = $vbulletin->db->query_read("
			SELECT *, LENGTH(smilietext) AS smilielen
			FROM " . TABLE_PREFIX . "$table
			WHERE LENGTH(TRIM(smilietext)) > 0
			ORDER BY smilielen DESC
		");
	}
	else
	{
		$items = $vbulletin->db->query_read("SELECT * FROM " . TABLE_PREFIX . "$table ORDER BY imagecategoryid, displayorder");
	}

	$itemarray = array();

	while ($item = $vbulletin->db->fetch_array($items))
	{
		$itemarray["$item[$itemid]"] = array();
		foreach ($item AS $field => $value)
		{
			if (!is_numeric($field))
			{
				$itemarray["$item[$itemid]"]["$field"] = $value;
			}
		}
	}

	build_datastore($table . 'cache', serialize($itemarray), 1);
}

// #############################################################################
/**
* Reads all data from the bbcode table and writes the serialized data to the datastore
*/
function build_bbcode_cache()
{
	global $vbulletin;
	DEVDEBUG("Updating bbcode cache template...");
	$bbcodes = $vbulletin->db->query_read("
		SELECT *
		FROM " . TABLE_PREFIX . "bbcode
	");
	$bbcodearray = array();
	while ($bbcode = $vbulletin->db->fetch_array($bbcodes))
	{
		$bbcodearray["$bbcode[bbcodeid]"] = array();
		foreach ($bbcode AS $field => $value)
		{
			if (!is_numeric($field))
			{
				$bbcodearray["$bbcode[bbcodeid]"]["$field"] = $value;

			}
		}

		$bbcodearray["$bbcode[bbcodeid]"]['strip_empty'] = (intval($bbcode['options']) & $vbulletin->bf_misc['bbcodeoptions']['strip_empty']) ? 1 : 0 ;
		$bbcodearray["$bbcode[bbcodeid]"]['stop_parse'] = (intval($bbcode['options']) & $vbulletin->bf_misc['bbcodeoptions']['stop_parse']) ? 1 : 0 ;
		$bbcodearray["$bbcode[bbcodeid]"]['disable_smilies'] = (intval($bbcode['options']) & $vbulletin->bf_misc['bbcodeoptions']['disable_smilies']) ? 1 : 0 ;
		$bbcodearray["$bbcode[bbcodeid]"]['disable_wordwrap'] = (intval($bbcode['options']) & $vbulletin->bf_misc['bbcodeoptions']['disable_wordwrap']) ? 1 : 0 ;
	}

	build_datastore('bbcodecache', serialize($bbcodearray), 1);
}

// #############################################################################
/**
* Prints a <script> block that allows you to call js_open_phrase_ref() from Javascript
*
* @param	integer	ID of initial language to be displayed
* @param	integer	ID of initial phrasetype to be displayed
* @param	integer	Pixel width of popup window
* @param	integer	Pixel height of popup window
*/
function print_phrase_ref_popup_javascript($languageid = 0, $fieldname = '', $width = 700, $height = 202)
{
	global $vbulletin;

	$q =  iif($languageid, "&languageid=$languageid", '');
	$q .= iif($$fieldname, "&fieldname=$fieldname", '');

	echo "<script type=\"text/javascript\">\n<!--
	function js_open_phrase_ref(languageid,fieldname)
	{
		var qs = '';
		if (languageid != 0) qs += '&languageid=' + languageid;
		if (fieldname != '') qs += '&fieldname=' + fieldname;
		window.open('admincp/phrase.php?" . vB::getCurrentSession()->get('sessionurl') . "do=quickref' + qs, 'quickref', 'width=$width,height=$height,resizable=yes');
	}\n// -->\n</script>\n";
}
// #############################################################################

function get_disabled_perms($usergroup)
{
	$datastore = vB::getDatastore();
	$bf_ugp_generic = $datastore->getValue('bf_ugp_genericpermissions');
	$bf_ugp_signature = $datastore->getValue('bf_ugp_signaturepermissions');

	$disabled = array();
	// Avatars disabled so don't inherit any of the avatar settings
	if (!($usergroup['genericpermissions'] & $bf_ugp_generic['canuseavatar']))
	{
		$disabled['avatarmaxwidth'] = -1;
		$disabled['avatarmaxheight'] = -1;
		$disabled['avatarmaxsize'] = -1;
	}

	// Signature pics or signatures are disabled so don't inherit any of the signature pic settings
	if (
		!($usergroup['signaturepermissions'] & $bf_ugp_signature['cansigpic']) OR
		!($usergroup['genericpermissions'] & $bf_ugp_generic['canusesignature'])
	)
	{
		$disabled['sigpicmaxwidth'] = -1;
		$disabled['sigpicmaxheight'] = -1;
		$disabled['sigpicmaxsize'] = -1;
	}

	// Signatures are disabled so don't inherit any of the signature settings
	if (!($usergroup['genericpermissions'] & $bf_ugp_generic['canusesignature']))
	{
		$disabled['sigmaxrawchars'] = -1;
		$disabled['sigmaxchars'] = -1;
		$disabled['sigmaxlines'] = -1;
		$disabled['sigmaxsizebbcode'] = -1;
		$disabled['sigmaximages'] = -1;
		$disabled['signaturepermissions'] = 0;
	}
	return $disabled;
}

// #############################################################################
/**
* Returns a string safe for use in Javascript code
*
* @param	string	Text to be made safe
* @param	string	Quote type to be used in Javascript (either ' or ")
*
* @return	string
*/
function fetch_js_safe_string($object, $quotechar = '"')
{
	$find = array(
		"\r\n",
		"\n",
		'"'
	);

	$replace = array(
		'\r\n',
		'\n',
		"\\$quotechar",
	);

	$object = str_replace($find, $replace, $object);

	return $object;
}

// #############################################################################
/**
* Returns a string safe for use in Javascript code
*
* @param	string	Text to be made safe
* @param	string	Quote type to be used in Javascript (either ' or ")
*
* @return	string
*/
function fetch_js_unsafe_string($object, $quotechar = '"')
{
	$find = array(
		'\r\n',
		'\n',
		"\\$quotechar",
	);

	$replace = array(
		"\r\n",
		"\n",
		"$quotechar",
	);

	$object = str_replace($find, $replace, $object);

	return $object;
}

// #############################################################################
/**
* Returns an array of folders containing control panel CSS styles
*
* Styles are read from /path/to/vbulletin/cpstyles/
*
* @return	array
*/
function fetch_cpcss_options()
{
	$folders = array();

	if ($handle = @opendir(DIR . '/cpstyles'))
	{
		while ($folder = readdir($handle))
		{
			if ($folder == '.' OR $folder == '..')
			{
				continue;
			}
			if (is_dir(DIR . "/cpstyles/$folder") AND @file_exists(DIR . "/cpstyles/$folder/controlpanel.css"))
			{
				$folders["$folder"] = $folder;
			}
		}
		closedir($handle);
		uksort($folders, 'strnatcasecmp');
		$folders = str_replace('_', ' ', $folders);
	}

	return $folders;
}

// ############################## Start vbflush ####################################
/**
* Force the output buffers to the browser
*/
function vbflush()
{
	static $gzip_handler = null;
	if ($gzip_handler === null)
	{
		$gzip_handler = false;
		$output_handlers = ob_list_handlers();
		if (is_array($output_handlers))
		{
			foreach ($output_handlers AS $handler)
			{
				if ($handler == 'ob_gzhandler')
				{
					$gzip_handler = true;
					break;
				}
			}
		}
	}

	if ($gzip_handler)
	{
		// forcing a flush with this is very bad
		return;
	}

	if (ob_get_length() !== false)
	{
		@ob_flush();
	}
	flush();
}

// ############################## Start fetch_product_list ####################################
/**
* Returns an array of currently installed products. Always includes 'vBulletin'.
*
* @param	boolean	If true, SELECT *, otherwise SELECT productid, title
* @param	boolean	Allow a previously cached version to be used
*
* @return	array
*/
function fetch_product_list($alldata = false, $use_cached = true)
{
	if ($alldata)
	{
		static $all_data_cache = false;

		if ($all_data_cache === false)
		{
			$productlist = array(
				'vbulletin' => array(
					'productid' => 'vbulletin',
					'title' => 'vBulletin',
					'description' => '',
					'version' => vB::getDatastore()->getOption('templateversion'),
					'active' => 1
				)
			);

			$products = vB::getDbAssertor()->assertQuery('vBForum:fetchproduct');
			foreach ($products as $product)
			{
				$productlist["$product[productid]"] = $product;
			}

			$all_data_cache = $productlist;
		}
		else
		{
			$productlist = $all_data_cache;
		}
	}
	else
	{
		$productlist = array(
			'vbulletin' => 'vBulletin'
		);

		$products = vB::getDbAssertor()->assertQuery('vBForum:fetchproduct');
		foreach ($products as $product)
		{
			$productlist["$product[productid]"] = $product['title'];
		}
	}

	return $productlist;
}

// ############################## Start build_product_datastore ####################################
/**
* Stores the list of currently installed products into the datastore.
*/
function build_product_datastore()
{
	$products = array('vbulletin' => 1);

	$productList = vB::getDbAssertor()->getRows('product', array(vB_dB_Query::COLUMNS_KEY => array('productid', 'active')));

	foreach ($productList AS $product)
	{
		$products[$product['productid']] = $product['active'];
	}

	vB::getDatastore()->build('products', serialize($products), 1);
}

/**
* Verifies that the optimizer you are using with vB is compatible. Bugs in
* various versions of optimizers have rendered vB unusable.
*
* @return	string|bool	Returns true if no error, else returns a string that represents the error that occured
*/
function verify_optimizer_environment()
{
	if (extension_loaded('eAccelerator'))
	{
		// first, attempt to use phpversion()...
		if ($eaccelerator_version = phpversion('eAccelerator'))
		{
			if (version_compare($eaccelerator_version, '0.9.3', '<') AND (@ini_get('eaccelerator.enable') OR @ini_get('eaccelerator.optimizer')))
			{
				return 'eaccelerator_too_old';
			}
		}
		// phpversion() failed, use phpinfo data
		else if (function_exists('phpinfo') AND function_exists('ob_start') AND @ob_start())
		{
			eval('phpinfo();');
			$info = @ob_get_contents();
			@ob_end_clean();
			preg_match('#<tr class="h"><th>eAccelerator support</th><th>enabled</th></tr>(?:\s+)<tr><td class="e">Version </td><td class="v">(.*?)</td></tr>(?:\s+)<tr><td class="e">Caching Enabled </td><td class="v">(.*?)</td></tr>(?:\s+)<tr><td class="e">Optimizer Enabled </td><td class="v">(.*?)</td></tr>#si', $info, $hits);
			if (!empty($hits[0]))
			{
				$version = trim($hits[1]);
				$caching = trim($hits[2]);
				$optimizer = trim($hits[3]);

				if (($caching === 'true' OR $optimizer === 'true') AND version_compare($version, '0.9.3', '<'))
				{
					return 'eaccelerator_too_old';
				}
			}
		}
	}
	else if (extension_loaded('apc'))
	{
		// first, attempt to use phpversion()...
		if ($apc_version = phpversion('apc'))
		{
			if (version_compare($apc_version, '2.0.4', '<'))
			{
				return 'apc_too_old';
			}
		}
		// phpversion() failed, use phpinfo data
		else if (function_exists('phpinfo') AND function_exists('ob_start') AND @ob_start())
		{
			eval('phpinfo();');
			$info = @ob_get_contents();
			@ob_end_clean();
			preg_match('#<tr class="h"><th>APC support</th><th>enabled</th></tr>(?:\s+)<tr><td class="e">Version </td><td class="v">(.*?)</td></tr>#si', $info, $hits);
			if (!empty($hits[0]))
			{
				$version = trim($hits[1]);

				if (version_compare($version, '2.0.4', '<'))
				{
					return 'apc_too_old';
				}
			}
		}
	}

	return true;
}

/**
* Checks userid is a user that shouldn't be editable
*
* @param	integer	userid to check
*
* @return	boolean
*/
function is_unalterable_user($userid)
{
	global $vbulletin;

	static $noalter = null;

	$vb5_config =& vB::getConfig();

	if (!$userid)
	{
		return false;
	}

	if ($noalter === null)
	{
		$noalter = explode(',', $vb5_config['SpecialUsers']['undeletableusers']);

		if (!is_array($noalter))
		{
			$noalter = array();
		}
	}

	return in_array($userid, $noalter);
}

/**
* Resolves an image URL used in the CP that should be relative to the root directory.
*
* @param	string	The path to resolve
*
* @return	string	Resolved path
*/
function resolve_cp_image_url($image_path)
{
	if ($image_path[0] == '/' OR preg_match('#^https?://#i', $image_path))
	{
		return $image_path;
	}
	else
	{
		return vB::getDatastore()->getOption('bburl') . "/$image_path";
	}
}

/**
* Prints JavaScript to automatically submit the named form. Primarily used
* for automatic redirects via POST.
*
* @param	string	Form name (in HTML)
*/
function print_form_auto_submit($form_name)
{
	$form_name = preg_replace('#[^a-z0-9_]#i', '', $form_name);

	?>
	<script type="text/javascript">
	<!--
	if (document.<?php echo $form_name; ?>)
	{
		function send_submit()
		{
			var submits = YAHOO.util.Dom.getElementsBy(
				function(element) { return (element.type == "submit") },
				"input", this
			);
			var submit_button;

			for (var i = 0; i < submits.length; i++)
			{
				submit_button = submits[i];
				submit_button.disabled = true;
				setTimeout(function() { submit_button.disabled = false; }, 10000);
			}

			return false;
		}

		YAHOO.util.Event.on(document.<?php echo $form_name; ?>, 'submit', send_submit);
		send_submit.call(document.<?php echo $form_name; ?>);
		document.<?php echo $form_name; ?>.submit();
	}
	// -->
	</script>
	<?php
}

/**
 * Prints a standard table with a warning/notice
 *
 * @param	Message to print
 */
function print_warning_table($message)
{
	print_table_start();
	print_description_row($message, false, 2, 'warning');
	print_table_footer(2, '', '', false);
}

/**
*	Get a list from the parsed xml array
*
* A common way to format lists in xml is
* <tag>
* 	<subtag />
* 	<subtag />
*   ...
* </tag>
*
* The problem is a single item is ambiguous
* <tag>
* 	<subtag />
* </tag>
*
* It could be a one element list or it could be a scalar child -- we only
* know from the context of the data, which the parser doesn't know.  Our parser
* assumes that it is a scalar value unless there are multiple tags with the same
* name.  Therefor so the first is rendered as:
*
* tag['subtag'] = array (0 => $element, 1 => $element)
*
* While the second is:
*
* tag['subtag'] = $element.
*
* Rather than handle each list element as a special case if there is only one item in the
* xml, this function will examine the element passed and if it isn't a 0 indexed array
* as expect will wrap the single element in an array() call.  The first case is not
* affected and the second is converted to tag['subtag'] = array(0 => $element), which
* is what we'd actually expect.
*
*	@param array The array entry for the list value.
* @return The list properly regularized to a numerically indexed array.
*/
function get_xml_list($xmlarray)
{
	if (is_array($xmlarray) AND array_key_exists(0, $xmlarray))
	{
		return $xmlarray;
	}
	else
	{
		return array($xmlarray);
	}
}

/**
* Returns HTML for a collapsible element
*
* @param	string  $content                   HTML content
* @param	string  $expandMeLabel             Label for expanding the collapsed element
* @param	string  $collapseMeLabel           Label for collapsing the expanded element
* @param	bool    $collapsed                 Optional, default true. If set to false, the element will be expanded by default.
* @param	string  $id                        A unique ID for this element. If empty, it'll generate its own ID via uniqid().
* @param	string  $collapseMeLabelLocation   Optional string "top"|"bottom"|"both", default "top". Shows the collapser label/UI
*			                                   above or below the content as specified.
* @return string HTML
*/
function get_collapser(
	$content,
	$expandMeLabel = "Click to Collapse/Expand",
	$collapseMeLabel = "",
	$collapsed = true,
	$id = "",
	$collapseMeLabelLocation = "top"
)
{
	if (empty($id))
	{
		$id = uniqid("acp-collapse-");
	}
	$html_id = htmlentities($id);
	$checked = ($collapsed ? "":"checked");
	if (empty($collapseMeLabel))
	{
		$collapseMeLabel = $expandMeLabel;
	}
	$expandMeLabel = "
			<label class=\"collapse-label collapse-show-on-collapse\" for=\"{$html_id}\">
				[+] {$expandMeLabel}
			</label>";
	$collapseMeLabel = "
			<label class=\"collapse-label collapse-hide-on-collapse\" for=\"{$html_id}\">
				[-] {$collapseMeLabel}
			</label>";
	$html = "
		<div class=\"collapse\">
			<input class=\"collapse-control\" id=\"{$html_id}\" type=\"checkbox\" {$checked}/>
			{$expandMeLabel}" .
			(($collapseMeLabelLocation == "top" OR $collapseMeLabelLocation == "both")? $collapseMeLabel: "") .
			"<div class=\"collapse-content\">
				{$content}
			</div>" .
			(($collapseMeLabelLocation == "bottom" OR $collapseMeLabelLocation == "both")? $collapseMeLabel: "") .
		"
		</div>
	";

	return $html;
}

/**
* Returns HTML for a link to a specific setting/option
*
* @param	array	$setting    Setting data, typically a row from the `setting` table.
*								Must have the grouptitle & varname keys
*/
function get_setting_link($setting, $text = "", $tooltip = "")
{
	$grouptitle = $setting['grouptitle'];
	$varname = $setting['varname'];
	$phrases = get_setting_phrases($setting['product']);
	$link = "index.php?loc=" . urlencode("admincp/options.php?do=options&varname={$varname}");
	if (empty($text))
	{
		$text = $phrases["setting_{$varname}_title"];
		$text = (empty($text) ? $varname : $text);
		$tooltip = htmlentities($phrases["setting_{$varname}_desc"]);
	}

	return construct_link_code($text, $link, true, $tooltip);
}

function get_setting_phrases($product)
{
	// query settings phrases
	static $settingphrase = array();
	if (!isset($settingphrase[$product]))
	{
		$settingphrase[$product] = array();
		$phrases = vB::getDbAssertor()->assertQuery('vBForum:phrase',
				array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
					'fieldname' => 'vbsettings',
					'languageid' => array(-1, 0, LANGUAGEID),
					'product' => $product,
				),
				array('field' => 'languageid', 'direction' => vB_dB_Query::SORT_ASC)
		);
		if ($phrases AND $phrases->valid())
		{
			foreach ($phrases AS $phrase)
			{
				$settingphrase[$product]["$phrase[varname]"] = $phrase['text'];
			}
		}
	}
	return $settingphrase[$product];
}

function get_cpstyle_href($file)
{
	//$options = vB::getDatastore()->getValue('options');
	$userinfo = vB_User::fetchUserinfo(0, array('admin'));
	return 'core/cpstyles/' . $userinfo['cssprefs'] . '/' . $file;
}

function get_log_paging_html($pagenumber, $totalpages, $baseUrl, $query, $phrases)
{
	$firstpage = '';
	$prevpage = '';
	$nextpage = '';
	$lastpage = '';

	$buttontemplate = '<input type="button" class="button" value="%1$s" tabindex="1" onclick="vBRedirect(\'%2$s\');">';

	if ($pagenumber != 1)
	{
		$query['page'] = 1;
		$url = htmlspecialchars_uni($baseUrl . http_build_query($query));
		$firstpage = sprintf($buttontemplate, '&laquo; ' . $phrases['first_page'], $url);

		$query['page'] = $pagenumber - 1;
		$url = htmlspecialchars_uni($baseUrl . http_build_query($query));
		$prevpage = sprintf($buttontemplate, '&lt; ' . $phrases['prev_page'], $url);
	}

	if ($pagenumber != $totalpages)
	{
		$query['page'] = $pagenumber + 1;
		$url = htmlspecialchars_uni($baseUrl . http_build_query($query));
		$nextpage = sprintf($buttontemplate, $phrases['next_page']  . ' &gt;', $url);

		$query['page'] = $totalpages;
		$url = htmlspecialchars_uni($baseUrl . http_build_query($query));
		$lastpage = sprintf($buttontemplate, $phrases['last_page']  . ' &raquo;', $url);
	}

	return "$firstpage $prevpage &nbsp; $nextpage $lastpage";
}

//consolidated from adminfunctions_forums.php
function print_channel_permission_rows($customword, $channelpermission = array(), $extra = '')
{
	global $vbphrase;
	$check_all_template = 'js_check_all_option(this.form, %d);';
	if($extra != '')
	{
		$check_all_template = 'if (js_set_custom()) {' . $check_all_template . '}';
	}

	$all_yes = sprintf($check_all_template, 1);
	$all_no = sprintf($check_all_template, 0);

	print_label_row(
		"<b>$customword</b>",'
		<input type="button" class="button" value="' . $vbphrase['all_yes'] . '" onclick="' . $all_yes . '" class="button" />
		<input type="button" class="button" value="' . $vbphrase['all_no'] . '" onclick="' . $all_no . '" class="button" />
		', 'tcat', 'middle'
	);

	// Load permissions
	require_once(DIR . '/includes/class_bitfield_builder.php');

	$bitvalues = array('forumpermissions', 'forumpermissions2', 'moderatorpermissions', 'createpermissions');
	$permFields = vB_ChannelPermission::fetchPermFields();
	$permPhrases = vB_ChannelPermission::fetchPermPhrases();

	if (empty($channelpermission))
	{
		// we need the defaults to be displayed
		$channelpermission = vB_ChannelPermission::instance()->fetchPermissions(1);
		$channelpermission = current($channelpermission);
	}

	foreach($permFields AS $permField => $type)
	{
		//Do the non-bitmap fields first.
		switch ($type)
		{
			case vB_ChannelPermission::TYPE_HOURS:
			case vB_ChannelPermission::TYPE_COUNT:
				$permvalue = $channelpermission[$permField];
				print_input_row($vbphrase[$permPhrases[$permField]], $permField, $permvalue, true, 35, 0, '', false, 'channelPerm_' . $permField);
				break;

			case vB_ChannelPermission::TYPE_BOOL:
				$permvalue = &$channelpermission[$permField];
				print_yes_no_row($vbphrase[$permPhrases[$permField]], $permField, $permvalue, $extra);
				break;
		}
	}

	//now do the bitmaps
	foreach($permFields AS $permField => $type)
	{
		if ($type == vB_ChannelPermission::TYPE_BITMAP)
		{
			if ($permField !== 'forumpermissions2')
			{
				print_table_header($vbphrase[$permPhrases[$permField]]);
			}

			foreach ($channelpermission['bitfields'][$permField] AS $permBit )
			{
				if ($permBit['used'])
				{
					$helpOptions = array();
					if ($permField == 'moderatorpermissions')
					{
						if (empty($permBit['phrase']))
						{
							$permBit['phrase'] = "moderator_add_edit_" . $permBit['name'] . "_title";
						}

						if ($permBit['name'] == 'canopenclose')
						{
							$helpOptions = array('prefix' => $permField);
						}
					}

					$phrase = (isset($vbphrase[$permBit['phrase']]) ? $vbphrase[$permBit['phrase']] : $permBit['phrase']);
					print_yes_no_row($phrase,	$permField . '[' . $permBit['name'] . ']', $permBit['set'], $extra, $helpOptions);
				}
			}
		}
	}
}

//consolidated from adminfunctions_attachment.php
function verify_upload_folder($attachpath)
{
	if ($attachpath == '')
	{
		print_stop_message2('please_complete_required_fields');
	}

	// Get realpath.
	$test = realpath($attachpath);

	if (!$test)
	{
		// If above fails, try relative path instead.
		$test = realpath(DIR . DIRECTORY_SEPARATOR . $attachpath);
	}

	if (!is_dir($test) OR !is_writable($test))
	{
		print_stop_message2(array('test_file_write_failed',  $attachpath));
	}

	if (!is_dir($test . '/test'))
	{
		@umask(0);
		if (!@mkdir($test . '/test', 0777))
		{
			print_stop_message2(array('test_file_write_failed',  $attachpath));
		}
	}

	@chmod($test . '/test', 0777);

	if ($fp = @fopen($test . '/test/test.attach', 'wb'))
	{
		fclose($fp);
		if (!@unlink($test . '/test/test.attach'))
		{
			print_stop_message2(array('test_file_write_failed',  $attachpath));
		}
		@rmdir($test . '/test');
	}
	else
	{
		print_stop_message2(array('test_file_write_failed',  $attachpath));
	}
}

function build_attachment_permissions()
{
	$data = array();
	$types = vB::getDbAssertor()->assertQuery('vBForum:fetchAllAttachPerms');

	foreach ($types as $type)
	{
		if (empty($data["$type[extension]"]))
		{
			$contenttypes = unserialize($type['contenttypes']);
			$data["$type[extension]"] = array(
				'size'         => $type['default_size'],
				'width'        => $type['default_width'],
				'height'       => $type['default_height'],
				'contenttypes' => $contenttypes,
			);
		}

		if (!empty($type['usergroupid']))
		{
			$data["$type[extension]"]['custom']["$type[usergroupid]"] = array(
				'size'         => $type['custom_size'],
				'width'        => $type['custom_width'],
				'height'       => $type['custom_height'],
				'permissions'  => $type['custom_permissions'],
			);
		}
	}

	build_datastore('attachmentcache', serialize($data), true);
}

//consolidated from adminfunctions_reputation.php
function build_reputationids()
{
	$assertor = vB::getDbAssertor();
	$count = 1;

	$reputations = $assertor->getRows('vBForum:reputationlevel', array(), array('minimumreputation'));

	$ourreputation = array();
	foreach ($reputations AS $reputation)
	{
		$ourreputation[$count]['value'] = $reputation['minimumreputation'];
		$ourreputation[$count]['index'] = $reputation['reputationlevelid'];
		$count++;
	}

	if ($count > 1)
	{
		$assertor->assertQuery('vBForum:buildReputationIds', array('ourreputation' => $ourreputation));
	}
	else
	{
		// it seems we have deleted all of our reputation levels??
		$assertor->assertQuery('user', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'reputationlevelid' => 0,
			vB_dB_Query::CONDITIONS_KEY => array(
				array('field' => 'userid', 'value' => 0, 'operator' => vB_dB_Query::OPERATOR_GT)
			)
		));
	}
}

//consolidated from adminfunctions_stats.php
function print_statistic_result($date, $bar, $value, $width)
{
	$bgclass = fetch_row_bgclass();

	$style = 'width:' . $width . '%; ' .
		'height: 23px; ' .
		'border:' . vB_Template_Runtime::fetchStyleVar('poll_result_border') . '; ' .
		'background:' . vB_Template_Runtime::fetchStyleVar('poll_result_color_' . str_pad(strval(intval($bar)), 2, '0', STR_PAD_LEFT)) . '; ';

	echo '<tr><td width="0" class="' . $bgclass . '">' . $date . "</td>\n";
	echo '<td width="100%" class="' . $bgclass . '" nowrap="nowrap"><div style="' . $style . '">&nbsp;</div></td>' . "\n";
	echo '<td width="0%" class="' . $bgclass . '" nowrap="nowrap">' . $value . "</td></tr>\n";
}

function print_statistic_code($title, $name, $start, $end, $nullvalue = true, $scope = 'daily', $sort = 'date_desc', $script = 'stats')
{

	global $vbphrase;

	print_form_header("admincp/$script", $name);
	print_table_header($title);

	print_time_row($vbphrase['start_date'], 'start', $start, false);
	print_time_row($vbphrase['end_date'], 'end', $end, false);

	if ($name != 'activity')
	{
		print_select_row($vbphrase['scope'], 'scope', array('daily' => $vbphrase['daily'], 'weekly' => $vbphrase['weekly_gstats'], 'monthly' => $vbphrase['monthly']), $scope);
	}
	else
	{
		construct_hidden_code('scope', 'daily');
	}
	print_select_row($vbphrase['order_by_gcpglobal'], 'sort', array(
		'date_asc'   => $vbphrase['date_ascending'],
		'date_desc'  => $vbphrase['date_descending'],
		'total_asc'  => $vbphrase['total_ascending'],
		'total_desc' => $vbphrase['total_descending'],
	), $sort);
	print_yes_no_row($vbphrase['include_empty_results'], 'nullvalue', $nullvalue);
	print_submit_row($vbphrase['go']);
}

//consolidated from adminfunctions_stylevar.php
function fetch_stylevars_array()
{
	global $vbulletin;
	static $stylevars = array();

	if (empty($stylevars))
	{
		if ($vbulletin->GPC['dostyleid'] > 0)
		{
			$parentlist = vB_Library::instance('Style')->fetchTemplateParentlist($vbulletin->GPC['dostyleid']);
			$parentlist = explode(',',trim($parentlist));
		}
		else
		{
			$parentlist = array('-1');
		}
		$stylevars_result = vB::getDbAssertor()->assertQuery('fetchStylevarsArray', array('parentlist' => $parentlist));
		foreach ($stylevars_result as $sv)
		{
			$sv['styleid'] = $sv['stylevarstyleid'];
			if (empty($stylevars[$sv['stylevargroup']][$sv['stylevarid']]['currentstyle']))
			{
				// Skip if Stylevar was already found as changed in the current style
				$stylevars[$sv['stylevargroup']][$sv['stylevarid']] = $sv;
				if ($sv['styleid'] == $vbulletin->GPC['dostyleid'])
				{
					// Stylevar was changed in the current style, no need to check for
					// customized stylevars in the parent styles after that.
					$stylevars[$sv['stylevargroup']][$sv['stylevarid']]['currentstyle'] = '1';
				}
			}
		}
	}

	// sort it so it's nice and neat

	// sort groups
	$groups = array_keys($stylevars);
	natsort($groups);

	// show specific groups at the top
	// Keep this in sync with the sorting in the "getExistingStylevars" query
	$moveGroupsToTop = array('GlobalPalette', 'Global');
	foreach ($moveGroupsToTop AS $moveGroupToTop)
	{
		$moveGroupToTopKey = array_search($moveGroupToTop, $groups, true);
		if ($moveGroupToTopKey !== false)
		{
			// remove it
			unset($groups[$moveGroupToTopKey]);
		}
	}
	natsort($moveGroupsToTop);
	$groups = array_merge($moveGroupsToTop, $groups);

	// sort stylevars
	$to_return = array();
	foreach($groups AS $group)
	{
		$stylevarids = array_keys($stylevars[$group]);
		natsort($stylevarids);
		foreach ($stylevarids AS $stylevarid)
		{
			// don't need to go any deeper, stylevar.styleid doesn't really matter in display sorting
			$to_return[$group][$stylevarid] = $stylevars[$group][$stylevarid];
		}
	}

	return $to_return;
}

//consolidated from functions_forumlist.php -- functions now only used by the admincp
function cache_moderators($userid = false)
{
	global $imodcache, $mod;

	$imodcache = array();
	$mod = array();
	try
	{
		$forummoderators = vB::getDbAssertor()->assertQuery('vBForum:getCacheModerators', array('userid' => $userid));
	}
	// @TODO improve this exception handling from the assertor
	catch (Exception $ex)
	{
		$forummoderators = false;
	}

	while($forummoderators AND $forummoderators->valid())
	{
		$moderator = $forummoderators->current();
		try
		{
			$moderator['musername'] = vB_Api::instanceInternal('user')->fetchMusername($moderator);
			$imodcache["$moderator[nodeid]"]["$moderator[userid]"] = $moderator;
			$mod["$moderator[userid]"] = 1;
		}
		catch (vB_Exception_Api $ex)
		{
			// do nothing...
		}
		$forummoderators->next();
	}
}

/**
* A version of cache_moderators that can be safely called multiple times
* without doing extra work.
*/
function cache_moderators_once($userid = null)
{
	global $imodcache;
	if (!isset($imodcache))
	{
		cache_moderators($userid);
	}
}

//consolidated from functions_socialgroup.php -- functions now only used by the admincp
/**
 * Takes information regardign a group, and prepares the information within it
 * for display
 *
 * @param	array	Group Array
 *
 * @return	array	Group Array with prepared information
 * @deprecated  This is only used in admincp/socialgroups.php and will be removed
 * 	once that usage is gone.  In the meantime expect parts not used by the caller
 * 	to be removed if they prove problematic.
 */
function prepare_socialgroup($group)
{
	global $vbulletin;

	if (!is_array($group))
	{
		return array();
	}

	$group['joindate'] = (!empty($group['joindate']) ?
		vbdate($vbulletin->options['dateformat'], $group['joindate'], true) : '');
	$group['createtime'] = (!empty($group['createdate']) ?
		vbdate($vbulletin->options['timeformat'], $group['createdate'], true) : '');
	$group['createdate'] = (!empty($group['createdate']) ?
		vbdate($vbulletin->options['dateformat'], $group['createdate'], true) : '');

	$group['lastupdatetime'] = (!empty($group['lastupdate']) ?
		vbdate($vbulletin->options['timeformat'], $group['lastupdate'], true) : '');
	$group['lastupdatedate'] = (!empty($group['lastupdate']) ?
		vbdate($vbulletin->options['dateformat'], $group['lastupdate'], true) : '');

	$group['visible'] = vb_number_format($group['visible']);
	$group['moderation'] = vb_number_format($group['moderation']);

	$group['members'] = vb_number_format($group['members']);
	$group['moderatedmembers'] = vb_number_format($group['moderatedmembers']);

	$group['categoryname'] = htmlspecialchars_uni($group['categoryname']);
	$group['discussions'] = vb_number_format($group['discussions']);
	$group['lastdiscussion'] = fetch_word_wrapped_string(fetch_censored_text($group['lastdiscussion']));

	if (!($group['options'] & $vbulletin->bf_misc_socialgroupoptions['enable_group_albums']))
	{
		// albums disabled in this group - force 0 pictures
		$group['picturecount'] = 0;
	}
	$group['rawpicturecount'] = $group['picturecount'];
	$group['picturecount'] = vb_number_format($group['picturecount']);

	$group['rawname'] = $group['name'];
	$group['rawdescription'] = $group['description'];

	$group['name'] = fetch_word_wrapped_string(fetch_censored_text($group['name']));

	if ($group['description'])
	{
 		$group['shortdescription'] = fetch_word_wrapped_string(fetch_censored_text(vB_String::fetchTrimmedTitle($group['description'], 185)));
	}
	else
	{
		$group['shortdescription'] = $group['name'];
	}

 	$group['mediumdescription'] = fetch_word_wrapped_string(fetch_censored_text(vB_String::fetchTrimmedTitle($group['description'], 1000)));
	$group['description'] = nl2br(fetch_word_wrapped_string(fetch_censored_text($group['description'])));

	$group['is_owner'] = ($group['creatoruserid'] == $vbulletin->userinfo['userid']);

 	$group['lastpostdate'] = vbdate($vbulletin->options['dateformat'], $group['lastpost'], true);
 	$group['lastposttime'] = vbdate($vbulletin->options['timeformat'], $group['lastpost']);

 	// check read marking
	//remove notice and make readtime determination a bit more clear
	if (!empty($group['readtime']))
	{
		$readtime = $group['readtime'];
	}
	else
	{
		$readtime = fetch_bbarray_cookie('group_marking', $group['groupid']);
		if (!$readtime)
		{
			$readtime = $vbulletin->userinfo['lastvisit'];
		}
	}

 	// check if social group is moderated to join
 	$group['membermoderated'] = ('moderated' == $group['type']);

 	// posts older than markinglimit days won't be highlighted as new
	$oldtime = (TIMENOW - ($vbulletin->options['markinglimit'] * 24 * 60 * 60));
	$readtime = max((int)$readtime, $oldtime);
	$group['readtime'] = $readtime;
	$group['is_read'] = ($readtime >= $group['lastpost']);

	// Legacy Hook 'group_prepareinfo' Removed //

	return $group;
}

//consolidated from functions_user.php -- functions now only used by the admincp/modcp
/**
 * Fetches the URL for a User's Avatar
 *
 * @param	integer	The User ID
 * @param	boolean	Whether to get the Thumbnailed avatar or not
 *
 * @return	array	Information regarding the avatar
 *
 */
function fetch_avatar_url($userid, $thumb = false)
{
	global $vbulletin, $show;
	static $avatar_cache = array();

	if (isset($avatar_cache["$userid"]))
	{
		$avatarurl = $avatar_cache["$userid"]['avatarurl'];
		$avatarinfo = $avatar_cache["$userid"]['avatarinfo'];
	}
	else
	{
		if ($avatarinfo = fetch_userinfo($userid, 2, 0, 1))
		{
			$perms = cache_permissions($avatarinfo, false);
			$avatarurl = array();

			if ($avatarinfo['hascustomavatar'])
			{
				$avatarurl = array('hascustom' => 1);

				if ($vbulletin->options['usefileavatar'])
				{
					$avatarurl[] = $vbulletin->options['avatarurl'] . ($thumb ? '/thumbs' : '') . "/avatar{$userid}_{$avatarinfo['avatarrevision']}.gif";
				}
				else
				{
					$avatarurl[] = "image.php?" . vB::getCurrentSession()->get('sessionurl') . "u=$userid&amp;dateline=$avatarinfo[avatardateline]" . ($thumb ? '&amp;type=thumb' : '') ;
				}

				if ($thumb)
				{
					if ($avatarinfo['width_thumb'] AND $avatarinfo['height_thumb'])
					{
						$avatarurl[] = " width=\"$avatarinfo[width_thumb]\" height=\"$avatarinfo[height_thumb]\" ";
					}
				}
				else
				{
					if ($avatarinfo['avwidth'] AND $avatarinfo['avheight'])
					{
						$avatarurl[] = " width=\"$avatarinfo[avwidth]\" height=\"$avatarinfo[avheight]\" ";
					}
				}
			}
			elseif (!empty($avatarinfo['avatarpath']))
			{
				$avatarurl = array('hascustom' => 0, $avatarinfo['avatarpath']);
			}
			else
			{
				$avatarurl = '';
			}

		}
		else
		{
			$avatarurl = '';
		}

		$avatar_cache["$userid"]['avatarurl'] = $avatarurl;
		$avatar_cache["$userid"]['avatarinfo'] = $avatarinfo;
	}

	if ( // no avatar defined for this user
		empty($avatarurl)
		OR // visitor doesn't want to see avatars
		($vbulletin->userinfo['userid'] > 0 AND !$vbulletin->userinfo['showavatars'])
		OR // user has a custom avatar but no permission to display it
		(!$avatarinfo['avatarid'] AND !($perms['genericpermissions'] & $vbulletin->bf_ugp_genericpermissions['canuseavatar']) AND !$avatarinfo['adminavatar']) //
	)
	{
		$show['avatar'] = false;
	}
	else
	{
		$show['avatar'] = true;
	}

	return $avatarurl;
}

function scanVbulletinGPCFile($keys, $uploadedOnly = true)
{
	global $vbulletin;

	if (!is_array($keys))
	{
		$keys = array((string) $keys);
	}

	$scanLib = vB_Library::instance('filescan');

	foreach ($keys AS $key)
	{
		if (
			empty($vbulletin->GPC[$key]['tmp_name']) OR
			($uploadedOnly AND !is_uploaded_file($vbulletin->GPC[$key]['tmp_name']))
		)
		{
			continue;
		}

		$check = $scanLib->scanFile($vbulletin->GPC[$key]['tmp_name']);
		if (empty($check))
		{
			// TODO: Is removing the uploaded tmp file that was caught the right approach?
			@unlink($vbulletin->GPC[$key]['tmp_name']);
			print_stop_message2('filescan_fail_uploaded_file');
		}
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103832 $
|| #######################################################################
\*=========================================================================*/
