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

class vB_Upgrade_503 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '503';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.0.3';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.0.3 Release Candidate 1';

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
	 *		Step 1, add the /page regex & pagenum argument to channel routes
	 */
	public function step_1()
	{	
		// output what we're doing
		$this->show_message($this->phrase['version']['503']['updating_channel_regex']);
		$assertor = vB::getDbAssertor();
		
		// guid vbulletin-4ecbdacd6a4ad0.58738735 is the home channel, which doesn't 
		// have a regex, apparently. Only grab the other channels.
		// the query grabs all vB5_Route_Channel routes without %\(\?\:/page% (unescaped: "(?:/page"  ) in the regex
		$brokenChannels = $assertor->assertQuery('vBInstall:getChannelsMissingPageRegex', array());
		
		// if the query found no channels missing /page in the regex, we're done
		if(!$brokenChannels->valid())
		{
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}
		
		$totalCount = iterator_count($brokenChannels);
		$i = 0;
		
		foreach($brokenChannels AS $channel)
		{
			// regex definition taken from vB5_Route_Channel::validInput()
			//preg_quote($data['prefix']) . '(?:/page(?P<pagenum>[0-9]+))?';
			$newregex = preg_quote($channel['prefix']) . '(?:/page(?P<pagenum>[0-9]+))?';
			$arguments = unserialize($channel['arguments']);
			$arguments['pagenum'] = '$pagenum';
			
			// update each channel one at a time. Not the fastest to do, but fastest to code.
			$this->db->query_write(
				"UPDATE " . TABLE_PREFIX . "routenew
					SET regex = '" . $newregex . "', arguments = '" . serialize($arguments) . "'
					WHERE routeid = " . $channel['routeid'] . "
				;"
			);
			
				// output progress
			if ( ((++$i)%100) === 0 OR ($i >= $totalCount) )
			{
				$this->show_message(sprintf($this->phrase['core']['processed_records_x_y_z'], 
					max($i - 99, 0), $i, $totalCount));	
			}
		}
		
		$this->show_message(sprintf($this->phrase['core']['process_done']));
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
