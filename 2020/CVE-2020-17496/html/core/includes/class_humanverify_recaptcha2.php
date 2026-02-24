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
* Human Verification class for reCAPTCHA Verification (http://recaptcha.net)
*
* @package 		vBulletin
* @version		$Revision: 102767 $
* @date 		$Date: 2019-09-05 17:06:36 -0700 (Thu, 05 Sep 2019) $
*
*/
class vB_HumanVerify_Recaptcha2 extends vB_HumanVerify_Abstract
{
	/**
	* Verify is supplied token/reponse is valid
	*
	*	@param	array	Values given by user 'input' and 'hash'
	*
	* @return	bool
	*/
	public function verify_token($input)
	{
		if(!empty($input['g-recaptcha-response']))
		{
			$private_key = vB::getDatastore()->getOption('hv_recaptcha_privatekey');

			$url = 'https://www.google.com/recaptcha/api/siteverify';
			$query = array(
				'secret' => $private_key,
				'remoteip' => vB::getRequest()->getIpAddress(),
				'response' => $input['g-recaptcha-response'],
			);

			$vurl = vB::getUrlLoader();
			//no idea if this is actually needed, but I don't want to muck with prior behavior here.
			$vurl->setOption(vB_Utility_Url::CLOSECONNECTION, 1);
			$result = $vurl->post($url, $query);

			if ($result === false)
			{
				$this->error = 'humanverify_recaptcha_unreachable';
				return false;
			}
			else
			{
				$result = json_decode($result['body'], true);
				if ($result['success'] === true)
				{
					return true;
				}

				switch ($result['error-codes'][0])
				{
					case 'missing-input-secret':
					case 'invalid-input-secret':
						$this->error = 'humanverify_recaptcha_privatekey';
						break;
					case 'missing-input-response':
					case 'invalid-input-response ':
					default:
						$this->error = 'humanverify_recaptcha_parameters';
						break;
				}

				return false;
			}
		}
		else
		{
			$this->error = 'humanverify_recaptcha_parameters';
			return false;
		}
	}

	/**
	* expected answer - with this class, we don't know the answer
	*
	* @return	string
	*/
	protected function fetch_answer()
	{
		return '';
	}

	/**
	 * generate token - Normally we want to generate a token to validate against. However,
	 * 		Recaptcha is doing that work for us.
	 *
	 * @param	boolean	Delete the previous hash generated
	 *
	 * @return	array	an array consisting of the hash, and the answer
	 */
	public function generate_token($deletehash = true)
	{
		return array(
			'hash' => '',
			'answer' => '',
		);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102767 $
|| #######################################################################
\*=========================================================================*/
