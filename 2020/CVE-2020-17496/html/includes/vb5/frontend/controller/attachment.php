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

class vB5_Frontend_Controller_Attachment extends vB5_Frontend_Controller
{
	public function actionFetch()
	{
		// I suspect this method isn't used anywhere, since Application Light
		// takes care of serving images.
		// But if this is used anywhere, I think we can allow a GET request
		// since it's only outputting data and not making any
		// changes server-side.

		if (!empty($_REQUEST['id']) AND intval($_REQUEST['id']))
		{
			$request = array('id' => intval($_REQUEST['id']));

			if (!empty($_REQUEST['thumb']) AND intval($_REQUEST['thumb']))
			{
				$request['thumb'] = (int) $_REQUEST['thumb'];
			}
			$api = Api_InterfaceAbstract::instance();
			$fileInfo = $api->callApi('attach', 'fetchImage', $request);
			if (!empty($fileInfo))
			{
				header('Cache-control: max-age=31536000, private');
				header('Expires: ' . gmdate("D, d M Y H:i:s", TIMENOW + 31536000) . ' GMT');
				header('Last-Modified: ' . gmdate('D, d M Y H:i:s', $fileInfo['dateline']) . ' GMT');
				header('ETag: "' . $fileInfo['filedataid'] . '"');
				header('Accept-Ranges: bytes');
				header('Content-transfer-encoding: binary');
				header("Content-Length:\"" . $fileInfo['filesize'] );
				header('Content-Type: ' . $fileInfo['htmlType'] );
				header("Content-Disposition: inline filename*=" . $fileInfo['filename']);

				echo $fileInfo['filedata'];
			}
		}
	}

	public function actionRemove()
	{
		// require a POST request for this action
		// NOTE: I can't find anywhere that calls this controller method, but since
		// it's a destructive action (remove), it needs to be POST and have CSRF protection
		$this->verifyPostRequest();

		//Note that we shouldn't actually do anything here. If the filedata record isn't
		//used it will soon be deleted.
		if (!empty($_REQUEST['id']) && intval($_REQUEST['id']))
		{
			$request = array('id' => intval($_REQUEST['id']));

			$api = Api_InterfaceAbstract::instance();
			// AFAIK, there is no "attach" api, and vb_api_content_attach doesn't have a removeAttachment().
			// TODO: Figure out where this going/supposed to be going.
			$api->callApi('attach', 'removeAttachment', $request);
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
