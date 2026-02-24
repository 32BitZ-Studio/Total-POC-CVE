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
* Human Verification class for Question & Answer Verification
*
* @package 		vBulletin
* @version		$Revision: 100503 $
* @date 		$Date: 2019-01-18 17:07:41 -0800 (Fri, 18 Jan 2019) $
*
*/
class vB_HumanVerify_Question extends vB_HumanVerify_Abstract
{
	/**
	 * Fetches a random question ID from the database
	 *
	 * @return	integer
	 *
	 */
	protected function fetch_answer()
	{
		$question = vB::getDbAssertor()->getRow('hv_question_fetch_answer');
		return $question['questionid'];
	}

	/**
	* Verify is supplied token/reponse is valid
	*
	*	@param	array	Values given by user 'input' and 'hash'
	*
	* @return	bool
	*/
	public function verify_token($input)
	{
		if (!is_array($input) OR empty($input['input']))
		{
			//if we don't have a valid question (for historical reasons
			//the "question" of the "Q&A" maps to the "answer" for the
			//original image HV implementation then accept any HV data
			//This means that the Q&A is not properly configured.
			if(!$this->fetch_answer())
			{
				return true;
			}
			else
			{
				$this->error = 'humanverify_missing';
				return false;
			}
		}
		$input['input'] = trim($input['input']);

		vB::getDbAssertor()->assertQuery('humanverify', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'viewed' => 1,
			vB_dB_Query::CONDITIONS_KEY => array(
				'hash' => $input['hash'],
				'viewed' => 0
			)
		));

		if (vB::getDbAssertor()->affected_rows())
		{
			// Hitting the master since we just updated this value
			$question = vB::getDbAssertor()->getRow('hv_question_fetch', array(
				'hash' => $input['hash'],
			));

			// Remove token since we no longer need it.
			$this->delete_token($input['hash']);

			if (!$question)
			{
				// this happens if the hash gets killed somewhere between the update and select
				$this->error = 'humanverify_question_wronganswer';
				return false;
			}
			else if (!$question['questionid'])
			{
				// this happens if no question was available, so we need to just accept their answer
				// otherwise it'd be impossible to get past
				return true;
			}
			else
			{	// Check answer!
				if ($question['regex'] AND preg_match('#' . str_replace('#', '\#', $question['regex']) . '#siU', $input['input']))
				{
					return true;
				}
				else if (
					vB::getDbAssertor()->getRow('hvanswer', array(
						vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
						'questionid' => intval($question['questionid']),
						'answer' => $input['input']
					))
				)
				{
					return true;
				}
				else
				{
					$this->error = 'humanverify_question_wronganswer';
					return false;
				}
			}
		}
		else
		{
			$this->delete_token($input['hash'], NULL, 0);
			$this->error = 'humanverify_question_wronganswer';
			return false;
		}
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 100503 $
|| #######################################################################
\*=========================================================================*/
