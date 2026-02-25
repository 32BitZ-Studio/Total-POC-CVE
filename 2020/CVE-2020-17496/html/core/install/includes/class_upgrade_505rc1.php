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

/*
if (!isset($GLOBALS['vbulletin']->db))
{
	exit;
}
*/

class vB_Upgrade_505rc1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '505rc1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.0.5 Release Candidate 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.0.5 Alpha 4';

	/**
	* Beginning version compatibility
	*
	* @var	string
	*/
	public $VERSION_COMPAT_STARTS = '';

	/**
	* Ending version compatibility
	*
	* @var	string
	*/
	public $VERSION_COMPAT_ENDS   = '';
		
	/**
	 * Step 1	-	This is exactly the same as what 504a3 step 1 used to do, except we're now allowing underscore _ in the 
	 *		urlIdents and as such the step has been moved here so that the conversation regexes will be properly updated.
	 */
	public function step_1($data = NULL)
	{
		$this->show_message(sprintf($this->phrase['version']['505rc1']['update_conversation_route_regex']));
		$assertor = vB::getDbAssertor();
		$batchsize = 200; //200; // don't have a DB with more than a few hundred routes to test any higher batch sizes
		$startat = intval($data['startat']);
		
		// fetch max routeid if necessary
		if (!isset($data['max']))
		{
			$maxRouteid  = $assertor->getRow('vBInstall:getMaxRouteid', array());
			$data['max'] = intval($maxRouteid['routeid']);
		}
		$max = intval($data['max']);
		
		// if we went through all the routes, we're done
		if($startat >= $max)
		{
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}
		
		// grab conversations in current batch
		$conversationRoutes  = $assertor->assertQuery('vBInstall:getConversationRoutes', array('startat' => $startat, 'batchsize' => $batchsize));
		
		// nothing to update this batch, kick off next batch
		if (!$conversationRoutes->valid())
		{
			$this->show_message(sprintf($this->phrase['core']['processed_records_x_y_z'], $startat + 1, $startat + $batchsize, $max));
			return array('startat' => ($startat + $batchsize), 'max' => $data['max']);
		}
		
		// construct params for method query updateConversationRouteRegex
		$routes = array();
		foreach($conversationRoutes AS $key => $routeRow)
		{
			// 500b27 could've broken custom URLs, but since it wasn't a vb4 thing, I'm assuming
			// that none existed prior to 500b27 and thus none require fixing.
			// However, we need to go through all the conversation routes and make sure that the
			// prefixes are preg_quoted. 
			// Custom URLs are defined as regex == prefix at the moment.
			if ($routeRow['regex'] !== preg_quote($routeRow['prefix']))
			{
				$route['routeid'] = $routeRow['routeid'];
				
				$route['regex'] = preg_quote($routeRow['prefix']) . '/' . vB5_Route_Conversation::REGEXP;
				$route['customregex'] = preg_quote($routeRow['prefix']);
				$routes[] = $route;
			}
		}
		
		// update regex
		$assertor->assertQuery('vBInstall:updateConversationRouteRegex', array('routes' => $routes));
		
		// output progress & return for next batch
		$this->show_message(sprintf($this->phrase['core']['processed_records_x_y_z'], $startat + 1, $startat + $batchsize, $max));
		return array('startat' => ($startat + $batchsize), 'max' => $data['max']);		
	}
	
	/**
	 * Step 2	-	This is exactly the same as what 504a3 step 2 used to do, except we're now allowing underscore _ in the 
	 *		urlIdents and as such the step has been moved here so that the conversation regexes will be properly updated.
	 *		Note that $oldRegex does not have an underscore in 505, as opposed to 504.
	 */
	public function step_2($data = NULL)
	{
		$this->show_message(sprintf($this->phrase['version']['505rc1']['update_conversation_route_old_regex']));
		$assertor = vB::getDbAssertor();
		$batchsize = 100000; // it's gonna join on the the node table. Each step took a couple seconds at most on the dev DB
		$startat = intval($data['startat']);
		
		// note that the old regex didn't have _\\[\\]. We are now disallowing [ & ], but we want to keep the
		// old regex for any prefixes that got a [ or ] in it, other wise they can't be routed.
		$oldRegex = '(?P<nodeid>[0-9]+)(?P<title>(-[^!@\\#\\$%\\^&\\*\\(\\)\\+\\?/:;"\'\\\\,\\.<>= ]*)*)(?:/page(?P<pagenum>[0-9]+))?';
		
		// fetch max nodeid if necessary
		if (!isset($data['max']))
		{
			$maxNodeid  = $assertor->getRow('vBInstall:getMaxNodeid', array());
			$data['max'] = intval($maxNodeid['maxid']);
		}
		$max = intval($data['max']);
		
		// if we went through all the routes, we're done
		if($startat >= $max)
		{
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}
		
		// grab conversations in current batch
		$conversationRoutes  = $assertor->assertQuery('vBInstall:getConversationRoutesRequiringOldRegex', array('startat' => $startat, 'batchsize' => $batchsize));
		
		// nothing to update this batch, kick off next batch
		if (!$conversationRoutes->valid())
		{
			$this->show_message(sprintf($this->phrase['core']['processed_records_x_y_z'], $startat + 1, $startat + $batchsize, $max));
			return array('startat' => ($startat + $batchsize), 'max' => $data['max']);
		}
		
		// construct params for method query updateConversationRouteRegex
		$routes = array();
		foreach($conversationRoutes AS $key => $routeRow)
		{
			// Skip custom URLs, same reasoning as step 1
			if ($routeRow['regex'] !== preg_quote($routeRow['prefix']))
			{
				$route['routeid'] = $routeRow['routeid'];
				
				// we have to use the old regex instead of vB5_Route_Conversation::REGEXP. 
				// Prefixes are based on channels, and there could be a topic with brackets 
				// in it that was in a channel without any reserved characters. If we just 
				// update all conversations with the new regex that disallows [ & ], any old topics with brackets would be broken.
				// However, any *new* conversation routes created will have the updated regexp
				$route['regex'] = preg_quote($routeRow['prefix']) . '/' . $oldRegex;
				$route['customregex'] = preg_quote($routeRow['prefix']);
				$routes[] = $route;
			}
		}
		
		// update regex
		$assertor->assertQuery('vBInstall:updateConversationRouteRegex', array('routes' => $routes));
		
		// output progress & return for next batch
		$this->show_message(sprintf($this->phrase['core']['processed_records_x_y_z'], $startat + 1, $startat + $batchsize, $max));
		return array('startat' => ($startat + $batchsize), 'max' => $data['max']);		
	}

	/**
	 * Drop userid_forumid index from moderator table.
	 *
	 */
	public function step_3()
	{
		$this->drop_index(
			sprintf($this->phrase['core']['altering_x_table'], 'moderator', 1, 3),
			'moderator',
			'userid_forumid'
		);
	}

	/**
	 * Add userid_nodeid index on moderator table.
	 *
	 */
	public function step_4()
	{
		$this->add_index(
			sprintf($this->phrase['core']['altering_x_table'], 'moderator', 2, 3),
			'moderator',
			'userid_nodeid',
			array('userid', 'nodeid'),
			'UNIQUE'
		);
	}

	/**
	 * Add nodeid index on moderator table.
	 *
	 */
	public function step_5()
	{
		$this->add_index(
			sprintf($this->phrase['core']['altering_x_table'], 'moderator', 3, 3),
			'moderator',
			'nodeid',
			'nodeid'
		);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
