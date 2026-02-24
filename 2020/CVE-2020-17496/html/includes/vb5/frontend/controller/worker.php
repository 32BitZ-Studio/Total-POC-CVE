<?php

class vB5_Frontend_Controller_Worker extends vB5_Frontend_Controller
{

	function __construct()
	{
		parent::__construct();

		//the api init can redirect.  We need to make sure that happens before we echo anything
		$this->api = Api_InterfaceAbstract::instance();
	}

	public function actionTest()
	{
		// require a POST request for this action
		$this->verifyPostRequest();


		$results = array();
		$results['success'] = true;
		$results['timenow'] = vB5_Request::get('timeNow');
		$this->sendAsJsonAndCloseConnection($results);

		// We could do stuff here.

	}

	public function actionSendFCM()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		/*
			BEGIN >>> Clean Input <<<
		 */
		$input = array(
			'hashes'			=> (isset($_POST['hashes'])		? $_POST['hashes'] : array()), // clean below
		);

		$unclean = $input['hashes'];
		$clean = array();
		foreach ($unclean AS $__hash)
		{
			// Let's just not bother with non-strings.
			if (is_string($__hash))
			{
				$clean[] = $__hash;
			}
		}
		$input['hashes'] = $clean;
		unset($clean);


		/*
			Send response & close connection before heavy lifting
		 */
		$results = array();
		$results['success'] = true;
		$results['timenow'] = vB5_Request::get('timeNow');
		$this->sendAsJsonAndCloseConnection($results);



		/*
			Process requested task here.
		 */
		$this->api->callApi('fcmessaging', 'sendFCM', array($input['hashes']));

	}
}
