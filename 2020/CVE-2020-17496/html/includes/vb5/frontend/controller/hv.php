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

class vB5_Frontend_Controller_Hv extends vB5_Frontend_Controller
{
	public function actionImage()
	{
		// Allow GET requests, since this is called from the src attribute of the IMG tag.

		$api = Api_InterfaceAbstract::instance();

		$image = $api->callApi('hv', 'fetchHvImage', array('hash' => $_REQUEST['hash']));

		switch ($image['type'])
		{
			case 'gif':
				header('Content-transfer-encoding: binary');
				header('Content-disposition: inline; filename=image.gif');
				header('Content-type: image/gif');
				break;

			case 'png':
				header('Content-transfer-encoding: binary');
				header('Content-disposition: inline; filename=image.png');
				header('Content-type: image/png');
				break;

			case 'jpg':
				header('Content-transfer-encoding: binary');
				header('Content-disposition: inline; filename=image.jpg');
				header('Content-type: image/jpeg');
				break;
		}

		echo $image['data'];
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
