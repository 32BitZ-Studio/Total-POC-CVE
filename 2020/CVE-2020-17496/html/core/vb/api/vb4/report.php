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

/**
 * vB_Api_Vb4_report
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Vb4_report extends vB_Api
{
	public function sendemail($postid, $reason)
	{
		$cleaner = vB::getCleaner();
		$postid = $cleaner->clean($postid, vB_Cleaner::TYPE_UINT);
		$reason = $cleaner->clean($reason, vB_Cleaner::TYPE_STR);

		if (empty($postid))
		{
			return array('response' => array('errormessage' => array('invalidid')));
		}

		if (empty($reason))
		{
			return array('response' => array('errormessage' => array('invalidid')));
		}

		$userinfo = vB_Api::instance('user')->fetchUserinfo();

		$data = array(
			'reportnodeid' => $postid,
			'rawtext' => $reason,
			'created' => vB::getRequest()->getTimeNow(),
			'userid' => $userinfo['userid'],
			'authorname' => $userinfo['username'],
		);
		$result = vB_Api::instance('content_report')->add($data, array('wysiwyg' => false));

		if ($result === null || isset($result['errors']))
		{
			return vB_Library::instance('vb4_functions')->getErrorResponse($result);
		}

		return array('response' => array('errormessage' => array('redirect_reportthanks')));
	}

	public function open($report_nodeid)
	{
		if (!is_array($report_nodeid))
		{
			return array('response' => array('errormessage' => 'invalidid'));
		}

		$reportApi = vB_Api::instance('content_report');

		$apiResult = $reportApi->openClose($report_nodeid, "open");
		$errors = $this->processApiErrors($apiResult, $report_nodeid);
		if (!empty($errors))
		{
			return $errors;
		}
		else
		{
			return array('response' => array('sucess' => true));
		}
	}

	public function close($report_nodeid)
	{
		if (!is_array($report_nodeid))
		{
			return array('response' => array('errormessage' => 'invalidid'));
		}

		$reportApi = vB_Api::instance('content_report');

		$apiResult = $reportApi->openClose($report_nodeid, "close");

		$errors = $this->processApiErrors($apiResult, $report_nodeid);
		if (!empty($errors))
		{
			return $errors;
		}
		else
		{
			return array('response' => array('sucess' => true));
		}
	}


	public function delete($report_nodeid)
	{
		if (!is_array($report_nodeid))
		{
			return array('response' => array('errormessage' => 'invalidid'));
		}

		$reportApi = vB_Api::instance('content_report');

		$apiResult = $reportApi->bulkdelete($report_nodeid);

		$errors = $this->processApiErrors($apiResult, $report_nodeid);
		if (!empty($errors))
		{
			return $errors;
		}
		else
		{
			return array('response' => array('sucess' => true));
		}
	}

	private function processApiErrors($apiResult, $report_nodeid)
	{
		// Note, report API's openClose() & bulkdelete() do not return anything.
		// If we have other report api calls in the future, and we have to handle null $apiResult as an error,
		// we should update this function.
		if (isset($apiResult['errors']))
		{
			if (isset($apiResult['errors'][0][0]) AND $apiResult['errors'][0][0] == "no_permission")
			{
				// TODO: does the app require these error keys to have corresponding phrases in vB5 ?
				$errorLabel = "no_permission_multiple_flag_reports";
				if (count($report_nodeid) == 1)
				{
					$errorLabel = "no_permission_single_flag_report";
				}

				return array('response' => array('errormessage' => $errorLabel));
			}
			return vB_Library::instance('vb4_functions')->getErrorResponse($apiResult);
		}
		else
		{
			return;
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
