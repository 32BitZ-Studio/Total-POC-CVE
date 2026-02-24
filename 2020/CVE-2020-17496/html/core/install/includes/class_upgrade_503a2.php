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

/*
if (!isset($GLOBALS['vbulletin']->db))
{
	exit;
}
*/

class vB_Upgrade_503a2 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '503a2';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.0.3 Alpha 2';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.0.3 Alpha 1';

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
	
	
	
	/*	Step 1
	 *	Revert changes to blog responses caused by a now-removed part of step_3 502a2
	*/
	public function step_1($data = NULL)
	{
		// check if blogs were imported. If so, there should be a blog_text table
		if ($this->tableExists('blog_text') AND $this->tableExists('node'))
		{
			$this->show_message($this->phrase['version']['503a2']['reverting_oldid_for_imported_blog_responses']);
			$startat = intval($data['startat']);
			$batchsize = 1000;
			// oldcontenttypeid for the imported nodes we need to fix
			$oldContetypeid_blogResponse = vB_Api_ContentType::OLDTYPE_BLOGRESPONSE_502a2;

			if (!empty($data['max']))
			{
					$max = $data['max'];
			}
			else
			{
				// grab the max id for imported vb3/4 blog response
				$max = vB::getDbAssertor()->getRow(	'vBInstall:getMaxNodeidForOldContent',
											array(	'oldcontenttypeid' => array($oldContetypeid_blogResponse))
										);
				$max = $max['maxid'];
			}

			if($startat >= $max)
			{
				// we're done here
				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}
			else
			{
				// node.created should match blog_text.dateline.
				// This relies on the high likelihood that no two blog responses to the same blog 
				// will have the same dateline.
				vB::getDbAssertor()->assertQuery('vBInstall:revertImportedBlogResponseOldid', array(
					'startat' => $startat,
					'batchsize' => $batchsize,
					'oldcontenttypeid' => $oldContetypeid_blogResponse,
					'oldcontenttypeid_new' => vB_Api_ContentType::OLDTYPE_BLOGRESPONSE
				));

				// output progress
				$this->show_message(sprintf($this->phrase['core']['processed_records_x_y'], $startat + 1, $startat + $batchsize));
				// start next batch
				return array('startat' => ($startat + $batchsize), 'max' => $max);
			}
		}
		else
		{
			$this->skip_message();
		}

	}	

	public function step_2()
	{
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], 'routenew'));
		$db = vB::getDbAssertor();

		// delete routes that should not exist
		$legacyClass = array(
			'vB5_Route_Legacy_Bloghome',
		);
		foreach ($legacyClass as $c)
		{
			$db->delete('routenew', array('class' => $c));
		}

	}

	/*
	 * insert legacy routes
	 *
	 * vB5_Route_Legacy_Forumhome is skipped since it's inserted already
	 * vB5_Route_Legacy_vBCms will be tried again since it might not exist
	 */
	public function step_3()
	{
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], 'routenew'));

		$db = vB::getDbAssertor();
		$legacyClass = array(
			'vB5_Route_Legacy_Activity',
			'vB5_Route_Legacy_Announcement',
			'vB5_Route_Legacy_Archive',
			'vB5_Route_Legacy_Blog',
			'vB5_Route_Legacy_Converse',
			'vB5_Route_Legacy_Entry',
			'vB5_Route_Legacy_Faq',
			'vB5_Route_Legacy_Forum',
			//'vB5_Route_Legacy_Forumhome',
			'vB5_Route_Legacy_Group',
			'vB5_Route_Legacy_Member',
			'vB5_Route_Legacy_Misc',
			'vB5_Route_Legacy_Online',
			'vB5_Route_Legacy_Poll',
			'vB5_Route_Legacy_Post',
			'vB5_Route_Legacy_Register',
			'vB5_Route_Legacy_Search',
			'vB5_Route_Legacy_Sendmessage',
			'vB5_Route_Legacy_Subscription',
			'vB5_Route_Legacy_Tag',
			'vB5_Route_Legacy_Thread',
			'vB5_Route_Legacy_Threadprint',
			'vB5_Route_Legacy_Usercp',
		);

		// include vB5_Route_Legacy_vBCms if package exists and the route was not inserted before
		$packageId = $db->getField('package', array('class' => 'vBCms'));
		$total = $db->getRow('routenew', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_COUNT,
			'class' => 'vB5_Route_Legacy_vBCms',
		));
		if ($packageId AND empty($total['count']))
		{
			$legacyClass[] = 'vB5_Route_Legacy_vBCms';
		}

		foreach ($legacyClass as $c)
		{
			$route = new $c;
			$data = array(
				'prefix'	=> $route->getPrefix(),
				'regex'		=> $route->getRegex(),
				'class'		=> $c,
				'arguments'	=> serialize($route->getArguments()),
			);
			$data['guid'] = vB_Xml_Export_Route::createGUID($data);
			$db->delete('routenew', array('class' => $c));
			$db->insert('routenew', $data);
		}
	}

	/*	
	 *	Step 4 - Find and import the missing sent_items folders
	 *  missed by the query: vBInstall:createPMFoldersSent, VBV-9232
	 *	
	*/
	public function step_4($data = NULL)
	{

		if ($this->tableExists('pmtext') AND $this->tableExists('messagefolder'))
		{
			// output what we're doing
			$this->show_message($this->phrase['version']['503a2']['importing_missing_PM_sent_items_folders']);

			$assertor = vB::getDbAssertor();
			$batchsize = 50000;
			$startat = intval($data['startat']);

			//First see if we need to do something. Maybe we're O.K.
			if (!empty($data['maxToFix']))
			{
				$maxToFix = $data['maxToFix'];
			}
			else
			{
				$maxToFix = $assertor->getRow('vBInstall:getMaxMissingPMFoldersSent', array());
				$maxToFix = intval($maxToFix['maxToFix']);
				//If we don't have any missing, we're done.
				if (intval($maxToFix) < 1)
				{
					$this->skip_message();
					return;
				}
			}

			if ($startat >= $maxToFix)
			{
				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}

			$assertor->assertQuery('vBInstall:importMissingPMFoldersSent', array('startat' => $startat, 'batchsize' => $batchsize));
			
			// output current progress
			$this->show_message(sprintf($this->phrase['core']['processed_records_x_y_z'], $startat + 1, $startat + $batchsize, $maxToFix));
			
			return array('startat' => ($startat + $batchsize), 'maxToFix' => $maxToFix);
		}
		else
		{
			$this->skip_message();
		}

	}

	/*	
	 *	Step 5 - Find and import the missing 'messages' folders
	 *  missed by the query: vBInstall:createPMFoldersMsg, VBV-9232
	 *	
	*/
	public function step_5($data = NULL)
	{

		if ($this->tableExists('pm') AND $this->tableExists('messagefolder'))
		{
			// output what we're doing
			$this->show_message($this->phrase['version']['503a2']['importing_missing_PM_messages_folders']);

			$assertor = vB::getDbAssertor();
			$batchsize = 25000;
			$startat = intval($data['startat']);

			//First see if we need to do something. Maybe we're O.K.
			if (!empty($data['maxToFix']))
			{
				$maxToFix = $data['maxToFix'];
			}
			else
			{
				$maxToFix = $assertor->getRow('vBInstall:getMaxMissingPMMessagesFolder', array());
				$maxToFix = intval($maxToFix['maxToFix']);
				//If we don't have any missing, we're done.
				if (intval($maxToFix) < 1)
				{
					$this->skip_message();
					return;
				}
			}

			if ($startat >= $maxToFix)
			{
				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}

			$assertor->assertQuery('vBInstall:importMissingPMMessagesFolder', array('startat' => $startat, 'batchsize' => $batchsize));
			
			// output current progress
			$this->show_message(sprintf($this->phrase['core']['processed_records_x_y_z'], $startat + 1, $startat + $batchsize, $maxToFix));
			
			return array('startat' => ($startat + $batchsize), 'maxToFix' => $maxToFix);
		}
		else
		{
			$this->skip_message();
		}
	}
	
	/*	
	 *	Step 6 - Correct node fields starter = nodeid, lastcontentid = nodeid 
	 *	missed by the query: vBInstall:setPMStarter, class_upgrade_501a2	step_22-24
	 *	VBV-9232
	 *	
	*/
	public function step_6($data = NULL)
	{
		// output what we're doing
		$this->show_message($this->phrase['version']['503a2']['correcting_nodefields_orphan_infractions']);

		$assertor = vB::getDbAssertor();
		$batchsize = 1000;
		$startat = intval($data['startat']);
		
		// the following oldcontenttypes used setPMStarter
		$oldcontenttypeidsToFix = array(
											vB_Api_ContentType::OLDTYPE_ORPHAN_INFRACTION_THREAD,
											vB_Api_ContentType::OLDTYPE_ORPHAN_INFRACTION_POST,
											vB_Api_ContentType::OLDTYPE_ORPHAN_INFRACTION_PROFILE,
										);

		//First see if we need to do something. Maybe we're O.K.
		if (!empty($data['maxToFix']))
		{
			$maxToFix = $data['maxToFix'];
		}
		else
		{
			$maxToFix = $assertor->getRow('vBInstall:getMaxOldidMissingNodeStarter', 
											array('oldcontenttypeids' => $oldcontenttypeidsToFix)
										);
			$maxToFix = intval($maxToFix['maxid']);
			//If we don't have any missing, we're done.
			if (intval($maxToFix) < 1)
			{
				$this->skip_message();
				return;
			}
		}

		// finish condition
		if ($startat >= $maxToFix)
		{
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}

		$assertor->assertQuery('vBInstall:setNodeStarter', 
								array(	
									'oldcontenttypeids' => $oldcontenttypeidsToFix,
									'startat' => $startat, 
									'batchsize' => $batchsize,
								));
		
		// output current progress
		$this->show_message(sprintf($this->phrase['core']['processed_records_x_y_z'], $startat + 1, $startat + $batchsize, $maxToFix));
		
		// kickoff next batch
		return array('startat' => ($startat + $batchsize), 'maxToFix' => $maxToFix);
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
