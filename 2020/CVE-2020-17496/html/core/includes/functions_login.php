<?php if (!defined('VB_ENTRY')) die('Access denied.');
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

// ###################### Start replacesession #######################
function fetch_replaced_session_url($url)
{
	// replace the sessionhash in $url with the current one
	global $vbulletin;

	$url = addslashes($url);
	$url = fetch_removed_sessionhash($url);

	if (vB::getCurrentSession()->get('sessionurl') != '')
	{
		if (strpos($url, '?') !== false)
		{
			$url .= '&amp;' . vB::getCurrentSession()->get('sessionurl');
		}
		else
		{
			$url .= '?' . vB::getCurrentSession()->get('sessionurl');
		}
	}

	return $url;
}

// ###################### Start removesessionhash #######################
function fetch_removed_sessionhash($string)
{
	return preg_replace('/([^a-z0-9])(s|sessionhash)=[a-z0-9]{32}(&amp;|&)?/', '\\1', $string);
}

// ###################### Start do login redirect #######################
function do_login_redirect()
{
	global $vbulletin, $vbphrase;

	$vbulletin->input->fetch_basepath();

	if (
		preg_match('#login.php(?:\?|$)#', $vbulletin->url)
		OR strpos($vbulletin->url, 'do=logout') !== false
		OR (!$vbulletin->options['allowmultiregs'] AND strpos($vbulletin->url, $vbulletin->basepath . 'register.php') === 0)
	)
	{
		$forumHome = vB_Library::instance('content_channel')->getForumHomeChannel();
		$vbulletin->url = vB5_Route::buildUrl($forumHome['routeid'] . '|fullurl');
	}
	else
	{
		$vbulletin->url = fetch_replaced_session_url($vbulletin->url);
		$vbulletin->url = preg_replace('#^/+#', '/', $vbulletin->url); // bug 3654 don't ask why
	}

	$temp = strpos($vbulletin->url, '?');
	if ($temp)
	{
		$formfile = substr($vbulletin->url, 0, $temp);
	}
	else
	{
		$formfile =& $vbulletin->url;
	}

	$postvars = $vbulletin->GPC['postvars'];

	// Legacy Hook 'login_redirect' Removed //

	if (!VB_API)
	{
		// recache the global group to get the stuff from the new language
		$globalgroup = $vbulletin->db->query_first_slave("
			SELECT phrasegroup_global, languagecode, charset
			FROM " . TABLE_PREFIX . "language
			WHERE languageid = " . intval($vbulletin->userinfo['languageid'] ? $vbulletin->userinfo['languageid'] : $vbulletin->options['languageid'])
		);
		if ($globalgroup)
		{
			$vbphrase = array_merge($vbphrase, unserialize($globalgroup['phrasegroup_global']));

			if (vB_Template_Runtime::fetchStyleVar('charset') != $globalgroup['charset'])
			{
				// change the character set in a bunch of places - a total hack
				global $headinclude;

				$headinclude = str_replace(
					"content=\"text/html; charset=" . vB_Template_Runtime::fetchStyleVar('charset') . "\"",
					"content=\"text/html; charset=$globalgroup[charset]\"",
					$headinclude
				);

				vB_Template_Runtime::addStyleVar('charset', $globalgroup['charset'], 'imgdir');
				$vbulletin->userinfo['lang_charset'] = $globalgroup['charset'];

				exec_headers();
			}
			if ($vbulletin->GPC['postvars'])
			{
				$postvars = array();
				$client_string = verify_client_string($vbulletin->GPC['postvars']);
				if ($client_string)
				{
					$postvars = @json_decode($client_string, true);
				}

				if ($postvars['securitytoken'] == 'guest')
				{
					$vbulletin->userinfo['securitytoken_raw'] = sha1($vbulletin->userinfo['userid'] . sha1($vbulletin->userinfo['secret']) . sha1(vB_Request_Web::$COOKIE_SALT));
					$vbulletin->userinfo['securitytoken'] = TIMENOW . '-' . sha1(TIMENOW . $vbulletin->userinfo['securitytoken_raw']);
					$postvars['securitytoken'] = $vbulletin->userinfo['securitytoken'];
					$vbulletin->GPC['postvars'] = sign_client_string(json_encode($postvars));
				}
			}

			vB_Template_Runtime::addStyleVar('languagecode', $globalgroup['languagecode']);
		}
	}

	//this is only called for the cp login anymore.  And the other redirect branch had bad code.
	//so we'll just issue the cp redirect and call it a day.
	require_once(DIR . '/includes/adminfunctions.php');
	print_cp_redirect_old($vbulletin->url);
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101127 $
|| #######################################################################
\*=========================================================================*/
