<?php

class GoogleLogin_Controller_Page extends vB5_Frontend_Controller
{
	public function json()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$router = vB5_ApplicationAbstract::instance()->getRouter();
		$arguments = $router->getArguments();
		$api = Api_InterfaceAbstract::instance();
		$callNamed = true; // pass named vars

		$result = array(
			'success' => false,
			'error' => "Unknown Action",
		);
		$vars = array();
		// common vars
		foreach (array('url', 'id_token', 'access_token') AS $__key)
		{
			if (isset($_REQUEST[$__key]))
			{
				$vars[$__key] = $_REQUEST[$__key];
			}
		}

		if (!empty($arguments['subaction']))
		{
			switch($arguments['subaction'])
			{
				case 'login':
					$result = $api->callApi('googlelogin:ExternalLogin', 'verifyAuthAndLogin', $vars, $callNamed);
					if ($result['success'])
					{

						vB5_Auth::setLoginCookies($result['login'], 'external', true);
						/*
							have JS reload. TODO: how to handle popup block (allowed on chrome, allegedly
							because browsers can distinguish user-triggered popups, but possibly because
							google owns chrome, need to test firefox & edge, as well as non-default browser
							settings)
						 */
					}
					break;
				case 'link':
					$result = $api->callApi('googlelogin:ExternalLogin', 'verifyAuthAndLinkUser', $vars, $callNamed);
					break;
				case 'unlink':
					$vars = array();
					$result = $api->callApi('googlelogin:ExternalLogin', 'unlinkUser', $vars, $callNamed);
					break;
				case 'register':
					$vars['donotlogin'] = true;
					$result = $api->callApi('googlelogin:ExternalLogin', 'verifyAuthAndLogin', $vars, $callNamed);
					if (!$result['success'] AND !empty($result['registration_url']))
					{
						// Get the registration URL so frontend can reload and show the preloaded google account information

						$result = array(
							'success' => true,
							'url' => $result['registration_url'],
						);
					}
					else
					{
						// API will return a 'externallogin_extid_notunique' error if user already exists for above call.
						// JS ajax response handler will render this message.
					}
					break;
				default:
					break;
			}
		}

		//header('Location: ' . $url, true, 302);
		$this->sendAsJson($result);
		return true;
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
