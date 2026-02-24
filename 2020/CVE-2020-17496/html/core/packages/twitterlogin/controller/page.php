<?php

class TwitterLogin_Controller_Page extends vB5_Frontend_Controller
{
	public function actionAuthCallback()
	{
		/*
			Upon a successful authentication, your callback_url would receive a request
			containing the oauth_token and oauth_verifier parameters. Your application
			should verify that the token matches the request token received in step 1.
		 */
		/*
			additionally our URL will have libid & userid (or guest=true if signing-in instead of linking)
			to help us find the token stored @ step 1.
			$urlSuffix =  "/twitterlogin/auth_callback?libid={$libid}&userid={$userid}";
		 */

		$api = Api_InterfaceAbstract::instance();
		$callNamed = true; // pass named vars
		$vars = array(
			'libid' => $_REQUEST['libid'],
			'oauth_token' => $_REQUEST['oauth_token'],
			'oauth_verifier' => $_REQUEST['oauth_verifier'],
			'nonce' => $_REQUEST['nonce'],
			'hash' => $_REQUEST['hash'],
		);
		/*
			Per testing, if user denies authorization for the app, the callback is passed the original
			parameters + a &denied={old token} parameter instead of the token & verifier params.
		 */
		if (isset($_REQUEST['denied']))
		{
			$vars['denied'] = $_REQUEST['denied'];
		}

		if (!empty($_REQUEST['guest']) AND empty($_REQUEST['userid']))
		{
			$check = $api->callApi('TwitterLogin:ExternalLogin', 'verifyAuthAndLogin', $vars, $callNamed);

			if (isset($check['error']))
			{
				return $this->showErrorPage($check['error']);
			}
			else if (isset($check['errors']))
			{
				// todo: render error fully?
				return $this->showErrorPage($check['errors'][0]);
			}

			vB5_Auth::setLoginCookies($check['login'], 'external', true);
			if (!empty($check['return_to_url']))
			{
				$url = $check['return_to_url'];
			}
			else
			{
				// home
				$url = vB5_Template_Options::instance()->get('options.frontendurl');
			}
			header('Location: ' . $url, true, 302);
			$this->sendAsJson(array('response' => $check));
			return true;
		}
		else if (!empty($_REQUEST['register']) AND empty($_REQUEST['userid']))
		{
			/*
				At this point, we have a sessionauth alive with verify params & return_to_url param that's pointing
				back to the register page.
				We should fetch some userinfo, save it back to the sessionauth, redirect back to the register page,
				and have the twitterlogin template hook on that register page pull data back from the sessionauth
				to prefill the registration form values.

				E.g. additiona_params:
				{"verify_token_nonce":"YUWHDXYGPIAJBUD74YFLG75AS3WAUHDM","return_to_url":"http:\/\/pluto.here\/cora\/register?urlpath=aHR0cDovL3BsdXRvLmhlcmUvY29yYS8%3D"}
			 */
			$check = $api->callApi('TwitterLogin:ExternalLogin', 'verifyAuthForvBRegistration', $vars, $callNamed);

			if (isset($check['error']))
			{
				return $this->showErrorPage($check['error']);
			}
			else if (isset($check['errors']))
			{
				// todo: render error fully?
				return $this->showErrorPage($check['errors'][0]);
			}

			if (!empty($check['return_to_url']))
			{
				$url = $check['return_to_url'];
			}
			else
			{
				// registration page
				$url = vB5_Template_Options::instance()->get('options.frontendurl') . "/register";
			}

			header('Location: ' . $url, true, 302);
			$this->sendAsJson(array('response' => $check));
			return true;
		}
		else
		{
			$check = $api->callApi('TwitterLogin:ExternalLogin', 'verifyAuthAndLinkUser', $vars, $callNamed);
		}

		if (!empty($check['error']))
		{
			return $this->showErrorPage($check['error']);
		}
		else if (!empty($check['success']))
		{
			// redirect to previous page.
			if (!empty($check['return_to_url']))
			{
				$url = $check['return_to_url'];
			}
			else
			{
				// home
				$url = vB5_Template_Options::instance()->get('options.frontendurl');
			}
			header('Location: ' . $url, true, 302);
			exit;
		}
		else
		{
			return $this->showErrorPage("unknown_error");
		}

	}



	public function showErrorPage($message)
	{
		$page = array('noindex' => true, 'nofollow' => true);
		$templater = new vB5_Template('error_page');
		$templater->registerGlobal('page', $page);
		$templater->register('error', array('message' => $message));

		$output = vB5_ApplicationAbstract::getPreheader() . $templater->render();
		echo $output;
		exit; // don't show anything else.
	}
}
