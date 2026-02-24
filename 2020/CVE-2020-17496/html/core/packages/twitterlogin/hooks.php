<?php
class twitterlogin_Hooks
{
	public static function hookShowExternalLoginButton($params)
	{
		$api = vB_Api::instance('TwitterLogin:ExternalLogin');
		$state = $api->getState();
		$params['buttons']['twitterlogin'] = $state['enabled'];
	}

	public static function hookShowExternalRegistrationBlock($params)
	{
		$api = vB_Api::instance('TwitterLogin:ExternalLogin');
		$state = $api->getState();
		$params['blocks']['twitterlogin'] = $state['register_enabled'];
	}

	public static function hookUserAfterSave($params)
	{
		if ($params['newuser'] AND
			$params['userid'] AND
			!empty($_REQUEST['twitterlogin']['external_userid']) AND
			!empty($_REQUEST['twitterlogin']['twitterlogin_saved'])
		)
		{
			// numeric string, do not convert to integer.
			$ext_id = (string) $_REQUEST['twitterlogin']['external_userid'];
			$twitterlogin_saved = $_REQUEST['twitterlogin']['twitterlogin_saved'];

			$api = vB_Api::instance('TwitterLogin:ExternalLogin');
			$lib = vB_Library::instance('TwitterLogin:ExternalLogin');

			$authRecord = $lib->getSessionAuthRecord();
			if ($authRecord['additional_params']['twitterlogin_register_nonce'] == $twitterlogin_saved AND
				$authRecord['additional_params']['external_userid'] == $ext_id
			)
			{
				// Store the external_userid & access token+secret pair.
				$userAuth = array(
					'userid' => $params['userid'],
					// loginlibraryid is auto-populated
					'external_userid' => $ext_id,
					'token' => $authRecord['token'],
					'token_secret' => $authRecord['token_secret'],
				);
				$lib->saveUserLink($userAuth);
			}
		}
	}

	public static function hookAdminCPUserExternalConnections($params)
	{
		$ext_userid = '';
		if (!empty($params['userid']))
		{
			$lib = vB_Library::instance('TwitterLogin:ExternalLogin');
			$auth = $lib->getUserAuthRecord(null, null, $params['userid']);
			if (!empty($auth['external_userid']))
			{
				$ext_userid = $auth['external_userid'];
			}
		}

		$params['externalConnections'][] = array(
			'titlephrase' => 'twitterlogin_twitter',
			'connected' => !empty($ext_userid),
			'helpname' => NULL,
			'displayorder' => 20,
		);
	}

	public static function hookTemplateGroupPhrase($params)
	{
		$params['groups']['twitterlogin'] = 'group_twitterlogin';
	}

	public static function hookSetRouteWhitelist($params)
	{
		/*
			Login callback
		 */
		$params['whitelistRoute'][] = 'twitterlogin/auth_callback';
	}

	public static function hookGetRoutingControllerActionWhitelist($params)
	{
		/*
			Login callback
		 */
		$params['whitelist']["twitterlogin.page"] = array(
			'actionauthcallback',
		);
	}
}
