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

class vB5_Frontend_Controller_Infraction extends vB5_Frontend_Controller
{
	public function __construct()
	{
		parent::__construct();
	}

	/**
	 * Adds infraction for the specified userid and nodeid
	 *
	 */
	public function actionAdd()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$input = array(
			'infracteduserid' => (isset($_POST['infracteduserid']) ? trim(intval($_POST['infracteduserid'])) : 0),
			'infractednodeid' => (isset($_POST['infractednodeid']) ? trim(intval($_POST['infractednodeid'])) : 0),
			'infractionlevelid' => (isset($_POST['infractionlevelid']) ? trim(intval($_POST['infractionlevelid'])) : 0),
			'warning' => array(),
			'customreason' => (isset($_POST['customreason']) ? trim(strval($_POST['customreason'])) : ''),
			'points' => (isset($_POST['points']) ? trim(intval($_POST['points'])) : 0),
			'reputation_penalty' => (isset($_POST['reputation_penalty']) ? trim(intval($_POST['reputation_penalty'])) : 0),
			'expires' => (isset($_POST['expires']) ? trim(intval($_POST['expires'])) : 0),
			'period' => (isset($_POST['period']) ? trim(strval($_POST['period'])) : ''),
			'message' => (isset($_POST['message']) ? trim(strval($_POST['message'])) : ''),
			'note' => (isset($_POST['note']) ? trim(strval($_POST['note'])) : ''),
			'banreason' => (isset($_POST['banreason']) ? trim(strval($_POST['banreason'])) : ''),
		);

		if (isset($_POST['warning']) AND $_POST['warning'] == $input['infractionlevelid'])
		{
			$input['warning'][$input['infractionlevelid']] = true;
		}

		$api = Api_InterfaceAbstract::instance();
		$result = $api->callApi('content_infraction', 'add', array($input, array()));

		$this->sendAsJson($result);
	}

	/**
	 * Reverses infraction for the specified nodeid
	 *
	 */
	public function actionReverse()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$nodeid = isset($_POST['nodeid']) ? trim(intval($_POST['nodeid'])) : 0;
		$reason = isset($_POST['reason']) ? trim(strval($_POST['reason'])) : '';
		$userInfraction = isset($_POST['userinfraction']) ? trim(intval($_POST['userinfraction'])) : 0;

		$api = Api_InterfaceAbstract::instance();
		$nodeId = $api->callApi('content_infraction', ($userInfraction ? 'reverseInfraction' : 'reverseNodeInfraction'), array($nodeid, $reason));

		$this->sendAsJson($nodeId);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
