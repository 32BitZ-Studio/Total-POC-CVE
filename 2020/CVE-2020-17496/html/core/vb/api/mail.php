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
 * vB_Api_Mail
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Mail extends vB_Api
{
	/** sends a batch of emails
	*
	*	@param	mixed	array of recipients, or a semicolon-delimited string
	* 	@param	string	subject of the message
	* 	@param	string	content of message
	*
	* 	@return	mixed	either success => true, or array of sent, failed, errors, and message- the last is suitable for display to user.
	*/
	public function send($to, $subject, $message)
	{
		//This should only be used by admins
		if (!vB::getUserContext()->hasAdminPermission('canadminusers'))
		{
			throw new vB_Exception_Api('no_permission');
		}

		if (!is_array($to))
		{
			if (strpos($to, ';'))
			{
				$to = explode(';', $to);
			}
			else
			{
				$to = array($to);
			}
		}
		$errors = '';
		$sent = array();
		$failed = array();

  		foreach ($to AS $toemail)
		{
			//The next function returns either true, false or an error string.
			$result = vB_Mail::vbmail($toemail, $subject, $message, false, '', '', '', true);

			if (is_string($result))
			{
				$errors .= $result;
			}
				else if ($result)
			{
				$sent[] = $toemail;
			}
			else
			{
				$failed[] = $toemail;
			}
		}

		if (empty($failed) AND empty($errors))
		{
			return array('success' => true);
		}
		$message = '';

		if (!empty($errors))
		{
			$message = vB_Phrase::fetchSinglePhrase('error_x', $errors) . '. ';
		}

		if (!empty($sent))
		{
			$message .= vB_Phrase::fetchSinglePhrase('sent_to_x', implode(',', $sent));
		}

		if (!empty($failed))
		{
			$message .= vB_Phrase::fetchSinglePhrase('send_failed_to_x', implode(',', $failed));
		}

		return array (
			'sent' => $sent,
			'failed' => $failed,
			'errors' => $errors,
			'message' => $message,
		);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103369 $
|| #######################################################################
\*=========================================================================*/
