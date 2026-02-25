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

class vB5_Frontend_Controller
{
	/** vboptions **/
	protected $vboptions = array();

	function __construct()
	{
		$vboptions = vB5_Template_Options::instance()->getOptions();
		$this->vboptions = $vboptions['options'];
	}

	/**
	 * Sends the response as a JSON encoded string
	 *
	 * @param	mixed	The data (usually an array) to send
	 */
	//this probably should be protected rather than public
	public function sendAsJson($data)
	{
		//this really isn't appropriate for this function but we need to
		//track down how to move this to the caller functions.  We should
		//*not* be altering data inside the send function
		if (isset($data['template']) AND !empty($data['template']))
		{
			$data['template'] = $this->outputPage($data['template'], false);
		}

		vB5_ApplicationAbstract::instance()->sendAsJson($data);
	}

	/**
	 * Show a simple and clear message page which contains no widget
	 *
	 * @param string $title Page title. HTML will be escaped.
	 * @param string $msg Message to display. HTML is allowed and the caller must make sure it's valid.
	 * @deprecated
	 */
	public function showMsgPage($title, $msg)
	{
		// This function basically duplicates the more common function in vB5_ApplicationAbstract.  The latter
		// doesn't handle early flush, but frankly that's overkill for a simple message page.  Better to get
		// everything running the same code.
		vB5_ApplicationAbstract::showMsgPage($title, $msg);
	}

	/**
	 * Show an error message
	 *
	 * The main purpose of this function is to convert a standard error array to the
	 * main application error page function.
	 *
	 * @param $errors -- an error array such as gets returned from the API.  Currently only
	 * 	the first error is displayed but this may change in the future.
	 */
	//we should consolidate all of the different "show message page" functions to
	//a consistant one.  Errors aren't that different from generic messages and we
	//seem to have various functions around.
	public function showErrorPage($errors)
	{
		//the base function only handles one error so we'll go with the first one
		$newErrors = array(
			'message' => $errors[0],
		);

		//the show error page function doesn't handle the exception_trace
		//quite as expected so we'll fish it out of the array and reformat it if exists
/*
 		//actually the formats are fundamentially incompatible.  We should fix this but
		//it's not worth it at the moment.
		foreach($errors AS $error)
		{
			if ($error[0] == 'exception_trace')
			{
				$newErrors['trace'] = explode("\n", $error[1]);
			}
		}
*/
		vB5_ApplicationAbstract::showErrorPage($newErrors);
	}

	/**
	 * Replaces special characters in a given string with dashes to make the string SEO friendly
	 * Note: This is really restrictive. If it can be helped, leave it to core's vB_String::getUrlIdent.
	 *
	 * @param	string	The string to be converted
	 */
	protected function toSeoFriendly($str)
	{
		if (!empty($str))
		{
			return trim(preg_replace('/[^a-z0-9]+/', '-', strtolower($str)), '-');
		}
		return $str;
	}

	/**
	 * Handle errors that are returned by API for use in JSON AJAX responses.
	 *
	 * @param	mixed	The result array to populate errors into. It will contain error phrase ids.
	 * @param	mixed	The returned object by the API call.
	 *
	 * @return	boolean	true errors are found, false, otherwise.
	 */
	protected function handleErrorsForAjax(&$result, $return)
	{
		if ($return AND !empty($return['errors']))
		{
			if (isset($return['errors'][0][1]))
			{
				// it is a phraseid with variables
				$errorList = array($return['errors'][0]);
			}
			else
			{
				$errorList = array($return['errors'][0][0]);
			}

			if (!empty($result['error']))
			{
				//merge and remove duplicate error ids
				$errorList = array_merge($errorList, $result['error']);
				$errorList = array_unique($errorList);
			}

			$result['error'] = $errorList;
			return true;
		}
		return false;
	}

	/**
	 * Checks if this is a POST request
	 */
	protected function verifyPostRequest()
	{
		// Require a POST request for certain controller methods
		// to avoid CSRF issues. See VBV-15018 for more details.
		if (strtoupper($_SERVER['REQUEST_METHOD']) != 'POST')
		{
			// show exception and stack trace in debug mode
			throw new Exception('This action only available via POST');
		}

		// Also verify CSRF token.
		vB5_ApplicationAbstract::checkCSRF();

	}

	/**
	 * Any final processing, and then output the page
	 */
	protected function outputPage($html, $exit = true)
	{
		$styleid = vB5_Template_Stylevar::instance()->getPreferredStyleId();

		if (!$styleid)
		{
			$styleid = $this->vboptions['styleid'];
		}

		$api = Api_InterfaceAbstract::instance();
		$fullPage = $api->callApi('template', 'processReplacementVars', array($html, $styleid));

		if (vB5_Config::instance()->debug)
		{
			$fullPage = str_replace('<!-- VB-DEBUG-PAGE-TIME-PLACEHOLDER -->', round(microtime(true) - VB_REQUEST_START_TIME, 4), $fullPage);
		}

		$api->invokeHook('hookFrontendBeforeOutput', array('styleid' => $styleid, 'pageHtml' => &$fullPage));

		if ($exit)
		{
			echo $fullPage;
			exit;
		}

		return $fullPage;
	}

	protected function parseBbCodeForPreview($rawText, $options = array())
	{
		$results = array();

		if (empty($rawText))
		{
			$results['parsedText'] = $rawText;
			return $results;
		}

		// parse bbcode in text
		try
		{
			$results['parsedText'] = vB5_Frontend_Controller_Bbcode::parseWysiwygForPreview($rawText, $options);
		}
		catch (Exception $e)
		{
			$results['error'] = 'error_parsing_bbcode_for_preview';

			if (vB5_Config::instance()->debug)
			{
				$results['error_trace'] = (string) $e;
			}
		}

		return $results;
	}


	/**
	 *	Adds attachment information so attachments can be created in one call
	 *
	 *	This will modify the $data array to add data under the keys
	 *	'attachments' for added attachments & 'removeattachments' for
	 *	attachments requested for removal.
	 *
	 * @param 	mixed	array of node data for insert
	 */
	protected function addAttachments(&$data)
	{
		if (isset($_POST['filedataids']) AND !empty($data['parentid']))
		{
			$api = Api_InterfaceAbstract::instance();
			$availableSettings =  $api->callApi('content_attach', 'getAvailableSettings', array());
			$availableSettings = (isset($availableSettings['settings'])? $availableSettings['settings'] : array());

			$data['attachments'] = array();
			/*
			 *	For inline inserts, the key is the temporary id that will be replaced by the nodeid by
			 *	vB_Library_Content_Text->fixAttachBBCode(), so maintaining the key $k is important.
			 */
			foreach ($_POST['filedataids'] AS $k => $filedataid)
			{
				$filedataid = (int) $filedataid;

				if ($filedataid < 1)
				{
					continue;
				}

				// We only use $availableSettings so we know which values to extract
				// from the $_POST variable. This is not here for cleaning,
				// which happens in the API. See the text and attach API cleanInput
				// methods.
				$settings = array();
				foreach ($availableSettings AS $settingkey)
				{
					if (!empty($_POST['setting'][$k][$settingkey]))
					{
						$settings[$settingkey] = $_POST['setting'][$k][$settingkey];
					}
				}

				$data['attachments'][$k] = array(
					'filedataid' => $filedataid,
					'filename' => (isset($_POST['filenames'][$k]) ? strval($_POST['filenames'][$k]) : ''),
					'settings' => $settings,
				);

			}
		}

		// if it's an update, we might have some attachment removals.
		// Let's also add removeattachments for an update, so the attachment limit
		// checks can take them into account.
		if (!empty($_POST['removeattachnodeids']))
		{
			// This list is used in 2 places.
			// First, it's used for permission checking purposes in vB_Api_Content_Text->checkAttachmentPermissions()
			// Later, it is used to delete attachments after the main node update in vB_Library_Content_Text->update().
			foreach ($_POST['removeattachnodeids'] AS $removeattachnodeid)
			{
				$removeattachnodeid = (int) $removeattachnodeid;
				if ($removeattachnodeid > 0)
				{
					$data['removeattachments'][$removeattachnodeid] = $removeattachnodeid;
				}
			}
		}
	}

	/*
		Copied from vB5_Frontend_ApplicationLight::handleAjaxApiDetached()
	*/
	protected function sendAsJsonAndCloseConnection($data)
	{
		//this really isn't appropriate for this function but we need to
		//track down how to move this to the caller functions.  We should
		//*not* be altering data inside the send function
		if (isset($data['template']) AND !empty($data['template']))
		{
			$data['template'] = $this->outputPage($data['template'], false);
		}

		vB5_ApplicationAbstract::instance()->sendAsJsonAndCloseConnection($data);
	}

	/**
	 * Generates a signed message to pass to the following page, so that the
	 * message can be displayed briefly to the user (flashed).
	 *
	 * @param  string The phrase key for the message to display
	 * @return string The signed value that should be passed as a query parameter
	 *                using the format flashmsg=<signed value>
	 */
	protected function encodeFlashMessage($phrase)
	{
		// For an overview of how the flashMessage system works, see:
		// vB5_Frontend_Controller::encodeFlashMessage()
		// vB5_Template::decodeFlashMessage()
		// vB_Api_User::verifyFlashMessageSignature()
		// displayFlashMessage() in global.js

		$api = Api_InterfaceAbstract::instance();
		$userinfo = $api->callApi('user', 'fetchUserinfo');

		$securitytoken = '';
		if (!empty($userinfo['securitytoken']))
		{
			$securitytoken = $userinfo['securitytoken'];
		}

		$timestamp = explode('-', $securitytoken, 2);
		$timestamp = $timestamp[0];

		$ret = 'msg-' . $phrase . '-' . $timestamp . '-' . substr(sha1($phrase . $securitytoken), -10);

		return $ret;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
