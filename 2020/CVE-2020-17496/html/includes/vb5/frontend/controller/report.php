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

class vB5_Frontend_Controller_Report extends vB5_Frontend_Controller
{
	function actionReport()
	{
		// require a POST request for this action
		$this->verifyPostRequest();
		$input = array(
			'reason' => (isset($_POST['reason']) ? trim(strval($_POST['reason'])) : ''),
			'reportnodeid' => (isset($_POST['reportnodeid']) ? trim(intval($_POST['reportnodeid'])) : 0),
		);

		$api = Api_InterfaceAbstract::instance();

		// get user info for the currently logged in user
		$user  = $api->callApi('user', 'fetchCurrentUserinfo', array());

		$reportData = array(
			'rawtext' => $input['reason'],
			'reportnodeid' => $input['reportnodeid'],
			'parentid' => $input['reportnodeid'],
			'userid' => $user['userid'],
			'authorname' => $user['username'],
			'created' => time(),
		);

		$nodeId = $api->callApi('content_report', 'add', array($reportData));
		$this->sendAsJson($nodeId);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
