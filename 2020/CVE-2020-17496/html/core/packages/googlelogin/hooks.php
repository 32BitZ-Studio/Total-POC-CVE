<?php
class googlelogin_Hooks
{
	public static function hookShowExternalLoginButton($params)
	{
		$api = vB_Api::instance('googlelogin:ExternalLogin');
		$state = $api->getState();
		$params['buttons']['googlelogin'] = $state['enabled'];
	}

	public static function hookShowExternalRegistrationBlock($params)
	{
		$api = vB_Api::instance('googlelogin:ExternalLogin');
		$state = $api->getState();
		$params['blocks']['googlelogin'] = $state['register_enabled'];
	}

	public static function hookUserAfterSave($params)
	{
		if ($params['newuser'] AND
			$params['userid'] AND
			!empty($_REQUEST['googlelogin']['external_userid']) AND
			!empty($_REQUEST['googlelogin']['googlelogin_saved'])
		)
		{
			// numeric string, do not convert to integer.
			$ext_id = (string) $_REQUEST['googlelogin']['external_userid'];
			$googlelogin_saved = $_REQUEST['googlelogin']['googlelogin_saved'];

			$api = vB_Api::instance('googlelogin:ExternalLogin');
			$lib = vB_Library::instance('googlelogin:ExternalLogin');

			$authRecord = $lib->getSessionAuthRecord();
			if ($authRecord['additional_params']['googlelogin_saved'] == $googlelogin_saved AND
				$authRecord['additional_params']['external_userid'] == $ext_id
			)
			{
				// Store the external_userid
				$userAuth = array(
					'userid' => $params['userid'],
					// loginlibraryid is auto-populated
					'external_userid' => $ext_id,
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
			$lib = vB_Library::instance('googlelogin:ExternalLogin');
			$auth = $lib->getUserAuthRecord(null, null, $params['userid']);
			if (!empty($auth['external_userid']))
			{
				$ext_userid = $auth['external_userid'];
			}
		}

		$params['externalConnections'][] = array(
			'titlephrase' => 'googlelogin_google',
			'connected' => !empty($ext_userid),
			'helpname' => NULL,
			'displayorder' => 30,
		);
	}

	public static function hookTemplateGroupPhrase($params)
	{
		$params['groups']['googlelogin'] = 'group_googlelogin';
	}

	public static function hookSetRouteWhitelist($params)
	{
		/*
			Login callback
		 */
		$params['whitelistRoute'][] = 'googlelogin/json';
	}

	public static function hookGetRoutingControllerActionWhitelist($params)
	{
		/*
			Login callback
		 */
		$params['whitelist']["googlelogin.page"] = array(
			'json',
		);
	}
}
