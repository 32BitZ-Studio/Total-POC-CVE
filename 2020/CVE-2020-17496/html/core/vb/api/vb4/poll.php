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
 * vB_Api_Vb4_poll
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Vb4_poll extends vB_Api
{

	/**
	 * Votes on a poll
	 *
	 * @param	int             $pollid          Nodeid of the poll the current user is voting on
	 * @param	int|bool[int]   $optionnumber    Id(s) of the poll option(s) that the user is voting for.
	 *			                                 For a single-vote poll, it is an integer id. For a multiple-vote
	 *			                                 poll, it must be a boolean array whose keys are the integer ids,
	 *			                                 and values are true.
	 *
	 * @return	Array				Returns response.errormessage which has one of the following strings
	 *									invalidid						specified pollid is not a poll node
	 *									useralreadyvote					user already voted on this poll
	 *									nopolloptionselected			either no option specified, or incorrectly formatted optionnumber
	 *									invalid_poll_option				optionnumber was invalid for specified pollid
	 *									unknown_error					an internal api error that can't be translated for the mapi client
	 *									redirect_pollvotethanks			vote success
	 */
	public function pollvote($pollid = 0, $optionnumber)
	{
		$cleaner = vB::getCleaner();
		$pollid = $cleaner->clean($pollid, vB_Cleaner::TYPE_UINT);
		$pollNode = vB_Api::instance('node')->getFullContentforNodes(array($pollid));
		if (empty($pollNode) || !empty($pollNode['errors']))
		{
			// Ex. handle no_permission (to view) errors
			return vB_Library::instance('vb4_functions')->getErrorResponse($pollNode);
		}
		$pollNode = reset($pollNode);

		// ensure pollid points to a poll.
		$pollTypeid = vB_Types::instance()->getContentTypeId('vBForum_Poll');
		if ($pollNode['contenttypeid'] != $pollTypeid)
		{
			return array('response' => array('errormessage' => 'invalidid'));
		}

		// Return error if user already voted.
		if ($pollNode['content']['voted'])
		{
			return array('response' => array('errormessage' => 'useralreadyvote'));
		}

		// Clean & validate optionids.
		// For provided optionnumber is not a polloption for this poll,
		// it'll throw a 'invalid_poll_option' error, see !isset($validPolloptions[$id]) below
		$validPolloptions = array();
		foreach ($pollNode['content']['options'] AS $key => $polloption)
		{
			// in practice it seems $key is the same as polloptionid, but I'm not 100% certain
			// on this ATM. If we can know this for certain and document it, we can
			// get rid of this loop here.
			$validPolloptions[$polloption['polloptionid']] =  $polloption['polloptionid'];
		}
		$polloptionids = array();
		$multiple = $pollNode['content']['multiple'];
		if ($multiple)
		{
			// this means if it's a multiple-vote poll and the option(s) are not passed in as an array
			// (even if the user voted for a single option) it'll throw a 'nopolloptionselected'
			// error, as vb4 does.
			if (is_array($optionnumber))
			{
				$optionnumber = $cleaner->clean($optionnumber, vB_Cleaner::TYPE_ARRAY_BOOL);
				foreach ($optionnumber AS $id => $vote)
				{
					$id = intval($id); // important, do not remove. Cleaning key that holds the actual id.
					if (!isset($validPolloptions[$id]))
					{
						return array('response' => array('errormessage' => 'invalid_poll_option'));
					}
					else if ($vote)
					{
						$polloptionids[] = $id;
					}
				}
				unset($id);
			}
		}
		else
		{
			$id = $cleaner->clean($optionnumber, vB_Cleaner::TYPE_UINT);
			if (!isset($validPolloptions[$id]))
			{
				return array('response' => array('errormessage' => 'invalid_poll_option'));
			}
			else
			{
				$polloptionids[] = $id;
			}
		}
		unset($optionnumber); // do not use. Use cleaned $polloptionids instead.

		if (empty($polloptionids))
		{
				return array('response' => array('errormessage' => 'nopolloptionselected'));
		}

        // the poll API actually doesn't require knowledge of the poll_id, because
        // every polloption record has the poll's nodeid.
        $result = vB_Api::instance('content_poll')->vote($polloptionids);
		if (empty($result) || !empty($result['errors']))
		{
			return vB_Library::instance('vb4_functions')->getErrorResponse($result);
		}

		return array('response' => array('errormessage' => 'redirect_pollvotethanks'));
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| #######################################################################
\*=========================================================================*/
