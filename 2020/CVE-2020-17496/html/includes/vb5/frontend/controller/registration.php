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

class vB5_Frontend_Controller_Registration extends vB5_Frontend_Controller
{
	/**
	 * Responds to a request to create a new user.
	 */
	public function actionRegistration()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$vboptions = vB5_Template_Options::instance()->getOptions();
		$vboptions = $vboptions['options'];

		//We need at least a username, email
		//The front end handles checks in general for this stuff and the API save
		//function will by necesity provide the required back end checks (and, frankly,
		//better error messages).  Not sure if we need this
		if (empty($_REQUEST['username']) OR empty($_REQUEST['email']))
		{
			$this->sendAsJson(array('errors' => array('insufficient data')));
			return;
		}

		//blank passwords are acceptable in some cases.  We'll rely on the internal API function to sort
		//out which is which.
		$password = trim($_REQUEST['password'] ?? '');
		$username = trim($_REQUEST['username']);


		$postdata = array(
			'username' => $username,
			'email' => $_REQUEST['email'],
			'eustatus' => intval($_REQUEST['eustatus']),
			'privacyconsent' => (isset($_REQUEST['privacyconsent']) ? intval($_REQUEST['privacyconsent']) : 0),
		);

		if (isset($_REQUEST['month']) AND isset($_REQUEST['day']) AND !empty($_REQUEST['year']))
		{
			$postdata['birthday'] = $this->formatBirthday($_REQUEST['year'], $_REQUEST['month'], $_REQUEST['day']);
		}

		if (!empty($_REQUEST['guardian']))
		{
			$postdata['parentemail'] = $_REQUEST['guardian'];
		}


		// Coppa cookie check
		$coppaage = vB5_Cookie::get('coppaage', vB5_Cookie::TYPE_STRING);
		if ($vboptions['usecoppa'] AND $vboptions['checkcoppa'])
		{
			if ($coppaage)
			{
				$dob = explode('-', $coppaage);
				$month = $dob[0];
				$day = $dob[1];
				$year = $dob[2];
				$postdata['birthday'] = $this->formatBirthday($year, $month, $day);
			}
			else
			{
				//this should probably use the same format as the other birthday strings, but that would involve chaning
				//the behavior and we need to double check the implications first.
				vB5_Cookie::set('coppaage', $_REQUEST['month'] . '-' . $_REQUEST['day'] . '-' . $_REQUEST['year'], 365, 0);
			}
		}

		$data = array(
			'userid'   => 0,
			'password' => $password,
			'user'     => $postdata,
			array(),
			array(),
			'userfield' => (!empty($_REQUEST['userfield']) ? $_REQUEST['userfield'] : false),
			array(),
			isset($_REQUEST['humanverify']) ? $_REQUEST['humanverify'] : '',
			array('acnt_settings' => true, 'fbautoregister' => !empty($_REQUEST['fbautoregister'])),
		);

		// add facebook data
		$api = Api_InterfaceAbstract::instance();
		if ($api->callApi('facebook', 'isFacebookEnabled') && $api->callApi('facebook', 'userIsLoggedIn'))
		{
			$fbUserInfo = $api->callApi('facebook', 'getFbUserInfo');
			$data['user']['fbuserid'] = $fbUserInfo['id'];
			$data['user']['fbname'] = $fbUserInfo['name'];
			$data['user']['fbjoindate'] = time();
		}

		$abort = false;

		$api->invokeHook('hookRegistrationBeforeSave', array(
			'this' => $this,
			'data' => &$data,
			'abort' => &$abort,
		));

		// Abort without saving if the hook requests it.
		if ($abort)
		{
			return;
		}

		$userid = $api->callApi('user', 'save', $data);

		if (isset($userid['errors']))
		{
			$this->sendAsJson($userid);
			return;
		}

		if(!$this->loginUser($api, $vboptions, $userid, $password))
		{
			return;
		}

		$frontendurl = vB5_Template_Options::instance()->get('options.frontendurl');

		$urlPath = $this->getUrlRedirectPath($_POST);
		if($urlPath === false)
		{
			$urlPath = $frontendurl;
		}
		$response = array('urlPath' => $urlPath);

		//sort out which message/next flow we need to flag for the caller.  A lot depends
		//on the specifics of how the user got created which in turn depend a lot on internal
		//configuration.
		$userinfo = $api->callApi('user', 'fetchUserinfo');
		if ($api->callApi('user', 'needsCoppa', array($userinfo['birthday'])))
		{
			$response['usecoppa'] = true;
			$response['urlPath'] = vB5_Route::buildUrl('coppa-form|bburl');
		}
		//email verification required
		else if ($userinfo['usergroupid'] == 3)
		{
			$response['msg'] = array(
				'registeremail',
				vB5_String::htmlSpecialCharsUni($postdata['username']),
				$postdata['email'],
				$frontendurl,
			);
		}
		//user is moderated
		else if ($userinfo['usergroupid'] == 4)
		{
			$response['msg'] = array(
				'moderateuser',
				vB5_String::htmlSpecialCharsUni($postdata['username']),
				$frontendurl,
			);
		}
		else
		{
			$routeProfile = $api->callApi('route', 'getUrl', array('route' => 'profile|fullurl', 'data' => array('userid' => $userid), array()));
			$routeuserSettings = $api->callApi('route', 'getUrl', array('route' => 'settings|fullurl', 'data' => array('tab' => 'profile'), array()));
			$routeAccount = $api->callApi('route', 'getUrl', array('route' => 'settings|fullurl', 'data' => array('tab' => 'account'), array()));
			$response['msg'] = array(
				'registration_complete',
				vB5_String::htmlSpecialCharsUni($postdata['username']),
				$routeProfile,
				$routeAccount,
				$routeuserSettings,
				$frontendurl,
			);
		}

		// Also provide a CSRF token that the current page can use from this point on.
		if (!empty($userinfo['securitytoken']))
		{
			$response['newtoken'] = $userinfo['securitytoken'];
		}

		$this->sendAsJson($response);
	}

	private function loginUser($api, $vboptions, $userid, $password)
	{
		//if we don't have a password and we succeeded in registration, then we must have
		//signed up via facebook with autoregister on.
		if($password)
		{
			$loginInfo = $api->callApi('user', 'loginSpecificUser', array($userid, array('password' => $password), array(), ''));
		}
		else
		{
			$cookie_name = 'fbsr_' .  $vboptions['facebookappid'];
			$info['signedrequest'] = strval($_COOKIE[$cookie_name] ?? '');

			// try to login
			$loginInfo = $api->callApi('user', 'loginExternal', array('facebook', $info, $userid));
		}

		if(!empty($loginInfo['errors']))
		{
			$this->sendAsJson($loginInfo);
			return false;
		}

		//it turns out that the returns for the two login functions are not consistant
		if(isset($loginInfo['login']))
		{
			$loginInfo = $loginInfo['login'];
		}

		vB5_Auth::setLoginCookies($loginInfo, '', true);
		return true;
	}

	private function getUrlRedirectPath($post)
	{
		//for various reasons we pass the url value (if we pass it) in base64
		$urlPath = '';
		if (!empty($post['urlpath']))
		{
			$urlPath = base64_decode(trim($post['urlpath']), true);
		}

		$application = vB5_ApplicationAbstract::instance();

		//we don't want to redirect to some urls either because it doesn't make a lot of sense or because
		//somebody is trying to spoof somebody.
		if (
			!$urlPath OR
			strpos($urlPath, '/auth/') !== false OR
			strpos($urlPath, '/register') !== false OR
			!$application->allowRedirectToUrl($urlPath)
		)
		{
			return false;
		}

		return $urlPath;
	}

	private function formatBirthday($year, $month, $day)
	{
		$month = str_pad($month, 2, '0', STR_PAD_LEFT);
		$day = str_pad($day, 2, '0', STR_PAD_LEFT);
		return $postdata['birthday'] = $year . '-' . $month . '-' . $day;
	}

	/**
	 *	Checks whether a user with a specific birthday is COPPA
	 */
	public function actionIscoppa()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$vboptions = vB5_Template_Options::instance()->getOptions();
		$vboptions = $vboptions['options'];

		// Coppaage cookie
		if ($vboptions['usecoppa'] AND $vboptions['checkcoppa'])
		{
			vB5_Cookie::set('coppaage', $_REQUEST['month'] . '-' . $_REQUEST['day'] . '-' . $_REQUEST['year'], 365, 0);
		}

		//Note that 0 = wide open
		// 1 means COPPA users (under 13) can register but need approval before posting
		// 2 means COPPA users cannot register
		$api = Api_InterfaceAbstract::instance();
		$coppa = $api->callApi('user', 'needsCoppa', array('data' => $_REQUEST));

		$this->sendAsJson(array('needcoppa' => $coppa));
	}

	/**
	 *	Checks whether a user is valid
	 **/
	public function actionCheckUsername()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		if (empty($_REQUEST['username']))
		{
			return false;
		}

		$api = Api_InterfaceAbstract::instance();

		$result = $api->callApi('user', 'checkUsername', array('candidate' => $_REQUEST['username']));

		$this->sendAsJson($result);
	}

	/**
	 * Activate an user who is in "Users Awaiting Email Confirmation" usergroup
	 */
	public function actionActivateUser()
	{
		// Given to users as a link with query params, so we need to accept GET requests
		// even though technically this does change something server-side

		$get = array(
			'u' => !empty($_GET['u']) ? intval($_GET['u']) : 0, // Userid
			'i' => !empty($_GET['i']) ? trim($_GET['i']) : '', // Activate ID
		);

		$api = Api_InterfaceAbstract::instance();
		$result = $api->callApi('user', 'activateUser', array('userid' => $get['u'], 'activateid' => $get['i']));

		$phraseController = vB5_Template_Phrase::instance();
		$phraseController->register(array('registration'));

		if (!empty($result['errors']) AND is_array($result['errors']))
		{
			$phraseArgs = is_array($result['errors'][0]) ? $result['errors'][0] : array($result['errors'][0]);
		}
		else
		{
			$phraseArgs = is_array($result) ? $result : array($result);
		}
		$messagevar = call_user_func_array(array($phraseController, 'getPhrase'), $phraseArgs);

		vB5_ApplicationAbstract::showMsgPage($phraseController->getPhrase('registration'), $messagevar);

	}

	/**
	 * Activate an user who is in "Users Awaiting Email Confirmation" usergroup
	 * This action is for Activate form submission
	 */
	public function actionActivateForm()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$post = array(
			'username' => !empty($_POST['username']) ? trim($_POST['username']) : '', // username
			'activateid' => !empty($_POST['activateid']) ? trim($_POST['activateid']) : '', // Activate ID
		);

		$api = Api_InterfaceAbstract::instance();
		$result = $api->callApi('user', 'activateUserByUsername', array('username' => $post['username'], 'activateid' => $post['activateid']));

		if (empty($result['errors']))
		{
			$response['msg'] = $result;
			if ($response['msg'] == 'registration_complete')
			{
				$userinfo = $api->callApi('user', 'fetchByUsername', array('username' => $post['username']));
				$routeProfile = $api->callApi('route', 'getUrl', array('route' => 'profile', 'data' => array('userid' => $userinfo['userid']), array()));
				$routeuserSettings = $api->callApi('route', 'getUrl', array('route' => 'settings', 'data' => array('tab' => 'profile'), array()));
				$routeAccount = $api->callApi('route', 'getUrl', array('route' => 'settings', 'data' => array('tab' => 'account'), array()));
				$response['msg_params'] = array(
					$post['username'],
					vB5_Template_Options::instance()->get('options.frontendurl') . $routeProfile,
					vB5_Template_Options::instance()->get('options.frontendurl') . $routeAccount,
					vB5_Template_Options::instance()->get('options.frontendurl') . $routeuserSettings,
					vB5_Template_Options::instance()->get('options.frontendurl')
				);
			}
			else
			{
				$response['msg_params'] = array();
			}
		}
		else
		{
			$response = $result;
		}

		$this->sendAsJson(array('response' => $response));
	}

	/**
	 * Send activate email
	 */
	public function actionActivateEmail()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$input = array(
			'email' => (isset($_POST['email']) ? trim(strval($_POST['email'])) : ''),
		);

		$api = Api_InterfaceAbstract::instance();
		$result = $api->callApi('user', 'sendActivateEmail', array('email' => $input['email']));


		if (empty($result['errors']))
		{
			$response['msg'] = 'lostactivatecode';
			$response['msg_params'] = array();
		}
		else
		{
			$response = $result;
		}

		$this->sendAsJson(array('response' => $response));
	}

	// @TODO -- remove this function
	// it appears to not be used anywere, and it's almost identical
	// to killActivation, which is used.
	// When removing this, also remove the deleteActivation function
	// in the user api.
	public function actionDeleteActivation()
	{
		$data = array(
			'u' => !empty($_GET['u']) ? intval($_GET['u']) : 0, // Userid
			'i' => !empty($_GET['i']) ? trim($_GET['i']) : '', // Activate ID
		);

		$api = Api_InterfaceAbstract::instance();
		$result = $api->callApi('user', 'deleteActivation', array('userid' => $data['u'], 'activateid' => $data['i']));

		$phraseController = vB5_Template_Phrase::instance();
		$phraseController->register('registration');

		if (!empty($result['errors']) AND is_array($result['errors']))
		{
			$phraseArgs = is_array($result['errors'][0]) ? $result['errors'][0] : array($result['errors'][0]);
		}
		else
		{
			$phraseArgs = is_array($result) ? $result : array($result);
		}
		$messagevar = call_user_func_array(array($phraseController, 'getPhrase'), $phraseArgs);
		vB5_ApplicationAbstract::showMsgPage($phraseController->getPhrase('registration'), $messagevar);
	}

	public function actionKillActivation()
	{
		// Given to users as a link with query params, so we need to accept GET requests
		// even though technically this does change something server-side

		$data = array(
			'u' => !empty($_GET['u']) ? intval($_GET['u']) : 0, // Userid
			'i' => !empty($_GET['i']) ? trim($_GET['i']) : '', // Activate ID
		);

		$api = Api_InterfaceAbstract::instance();
		$result = $api->callApi('user', 'killActivation', array('userid' => $data['u'], 'activateid' => $data['i']));

		$phraseController = vB5_Template_Phrase::instance();
		$phraseController->register('registration');

		if (!empty($result['errors']) AND is_array($result['errors']))
		{
			$phraseArgs = is_array($result['errors'][0]) ? $result['errors'][0] : array($result['errors'][0]);
		}
		else
		{
			$phraseArgs = is_array($result) ? $result : array($result);
		}
		$messagevar = call_user_func_array(array($phraseController, 'getPhrase'), $phraseArgs);

		vB5_ApplicationAbstract::showMsgPage($phraseController->getPhrase('registration'), $messagevar);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101654 $
|| #######################################################################
\*=========================================================================*/
