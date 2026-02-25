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

class vB_Upgrade_503b1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '503b1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.0.3 Beta 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.0.3 Alpha 3';

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
	
	/*	
	 *	Steps 1 & 2 are copied from sprint69m8's class_upgrade_502. VBV-9700
	 *	Step 1 - Fix the node.open flag for threads incorrectly set by 500a1 steps 145
	 *	We're making a couple assumptions here: 
	 *		One, thread table has not been removed
	 *		Two, a thread that was closed in vB4 has NOT been re-opened in vB5. 
	 *			- Any vB4 thread that was re-opened in vB5 will be closed again.
	*/
	public function step_1($data = NULL)
	{
		// if imported from vB5, there should be a thread table (vB4) & node table (vB5)
		if ($this->tableExists('thread') AND $this->tableExists('node'))
		{
			//We only need to run this once.
			if (empty($data['startat']))
			{
				$log = vB::getDbAssertor()->assertQuery('vBInstall:upgradelog', array('script' => '503b1', 'step' => 1)); // Must match this step.

				if ($log->valid())
				{
					$this->skip_message();
					return;
				}
			}

			// output what we're doing
			$this->show_message($this->phrase['version']['503b1']['correcting_node_field_open']);
			
			$assertor = vB::getDbAssertor();
			$batchSize = 100000;
			// we're looking for imported threads.
			$threadId = vB_Types::instance()->getContentTypeID('vBForum_Thread');
			
			// grab startat
			$startat = intval($data['startat']);
			// grab max if using CLI & not first iteration, else fetch it from DB
			if (!empty($data['max']))
			{
				$max = intval($data['max']);
			}
			else
			{
				$max = $assertor->getRow('vBInstall:getMaxImportedPost', 
					array(	
						'contenttypeid' => $threadId
					)
				);
				$max = intval($max['maxid']);
			}
			
			// finish condition is when no thread were imported or we already processed the max oldid
			if ($max == 0 OR $max <= $startat)
			{
				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}
			
			
			// fix corrupt node.open flags for imported threads
			$assertor->assertQuery('vBInstall:fixCorruptOpenFlags',
				array(
					'oldcontenttypeid' => $threadId, 
					'startat' => $startat,
					'batchsize' => $batchSize,
				)
			);
			
			/* fix corrupt node.open flags for imported threads
			 * the reason we cannot just run this second query by itself is in 
			 * case the thread table is truncated. Also, running the first query
			 * by itself misses the following edge case:
			 * 		Thread A is closed in vB4. Site is upgraded to vB5 5.0.1. 
			 *		Thread A's parent channel is closed.
			 *		They upgrade to 5.0.2 / run the first query
			 */
			$assertor->assertQuery('vBInstall:importClosedThreadOpenFlags',
				array(
					'oldcontenttypeid' => $threadId, 
					'startat' => $startat,
					'batchsize' => $batchSize,
				)
			);
			
			// output current progress
			$this->show_message(sprintf($this->phrase['core']['processed_records_x_y_z'], $startat +1, ($startat + $batchSize), $max));	
			
			// kick off next batch
			return array('startat' => $startat + $batchSize, 'max' => $max);
		}
		else
		{
			$this->skip_message();
		}
	}
	
	/*	
	 *	Step 2 - Fix the node.showopen flag for non-starter posts incorrectly set by 500a1 step 146
	 *		Also need to set the node.showopen flag to 0 for any posts made post-upgrade against 
	 *		threads closed in vB4.
	 *	We're making a few assumptions here: 
	 *		One, thread & post tables have not been removed
	*/
	public function step_2($data = NULL)
	{
		// if imported from vB5, there should be a thread table (vB4) & node table (vB5)
		if ($this->tableExists('thread') AND $this->tableExists('post') AND $this->tableExists('node'))
		{
			//We only need to run this once.
			if (empty($data['startat']))
			{
				$log = vB::getDbAssertor()->assertQuery('vBInstall:upgradelog', array('script' => '503b1', 'step' => 2)); // Must match this step.

				if ($log->valid())
				{
					$this->skip_message();
					return;
				}
			}


			// output what we're doing
			$this->show_message($this->phrase['version']['503b1']['correcting_node_field_showopen']);
			
			$assertor = vB::getDbAssertor();
			$batchSize = 100000;
			// we only care about nodes whose parents are imported threads.
			$threadId = vB_Types::instance()->getContentTypeID('vBForum_Thread');
			
			// grab startat
			$startat = intval($data['startat']);
			// grab max if using CLI & not first iteration, else fetch it from DB
			if (!empty($data['max']) AND !empty($data['maxThread']))
			{
				$max = intval($data['max']);
				$maxThread = intval($data['maxThread']);
			}
			else
			{
				// get the max nodeid
				$max = $assertor->getRow('vBInstall:getMaxNodeid', array());
				$max = intval($max['maxid']);
				// also grab the max imported thread's oldid
				$maxThread = $assertor->getRow('vBInstall:getMaxImportedPost', 
					array(	
						'contenttypeid' => $threadId
					)
				);
				$maxThread = intval($maxThread['maxid']);
			}
			
			// finish condition is when we've walked through all nodes, or there are no nodes.
			if ($maxThread == 0 OR $max == 0 OR $max <= $startat)
			{
				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}
			
			//We're only fixing the showopen flags for nodes whose parent was an imported, closed thread
			$assertor->assertQuery('vBInstall:fixIncorrectShowopenFlags',
				array(
					'oldcontenttypeid' => $threadId, 
					'startat' => $startat,
					'batchsize' => $batchSize,
				)
			);
			
			// output current progress
			$this->show_message(sprintf($this->phrase['core']['processed_records_x_y_z'], $startat +1, ($startat + $batchSize), $max));	
			
			// kick off next batch
			return array('startat' => $startat + $batchSize, 'max' => $max, 'maxThread' => $maxThread);
		}
		else
		{
			$this->skip_message();
		}
	}
	
	/**
	* Step 3 - Rename layouts. Repurpose title to hold the phrase title.
	*/
	public function step_3()
	{
		$assertor = vB::getDbAssertor();
		// 100 => full
		$assertor->assertQuery('screenlayout', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE, 
			'screenlayoutid' => 1,
			'varname' => 'full',
			'title' => 'layout_full'
		));
		
		// 70/30 => Wide/Narrow
		$assertor->assertQuery('screenlayout', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE, 
			'screenlayoutid' => 2,
			'varname' => 'wide-narrow',
			'title' => 'layout_wide_narrow'
		));
		
		// 30/70 => Narrow/Wide
		$assertor->assertQuery('screenlayout', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE, 
			'screenlayoutid' => 4,
			'varname' => 'narrow-wide',
			'title' => 'layout_narrow_wide'
		));
		
		$this->show_message($this->phrase['version']['503b1']['rename_screen_layout']);
	}

	/**
	 * fix the missing '$pagenum' arguments for channel routes
	 * missed by query in class_upgrade_final:step5
	 */
	public function step_4($data = NULL)
	{
		$db = vB::getDbAssertor();
		$batchsize = 100;
		$results = $db->assertQuery('vBInstall:fixMissingPageArgumentsForChannels', 
			array('batchsize' => $batchsize)
		);

		if(!$results->valid())
		{
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], 'routenew'));

		foreach($results AS $record)
		{
			$arguments = unserialize($record['arguments']);
			if(empty($arguments['pagenum']))
			{
				$arguments['pagenum'] = '$pagenum';
				$db->assertQuery('routenew', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
					'routeid' => $record['routeid'],
					'arguments' => serialize($arguments)
				));
			}
		}

		// return dummy value to loop the step
		return array('startat' => 1);
	}
	
	/*
	 * Step 5 - Remove the orphan "Main Forum" Channel if added during upgrade from vB4
	 */
	public function step_5()
	{
		// output what we're doing
		$this->show_message($this->phrase['version']['503b1']['removing_orphan_channels']);
	
		// need the assertor
		$db = vB::getDbAssertor();
			
		// get the channel contenttypeid
		$channelTypeId = vB_Types::instance()->getContentTypeID('vBForum_Channel');
		
		$results = $db->assertQuery('vBInstall:findOrphanChildlessChannels', 
			array(
				'contenttypeid' => $channelTypeId,
			)
		);
		
		if (!$results->valid())
		{
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}
		
		// we need to create an admin session first so checkForumClosed() doesn't fail
		vB_Upgrade::createAdminSession();
		// instantiate vB_Library_Content_Channel, so we can call its delete() function on the node
		$channelLib = vB_Library::instance('content_channel');
		
		// delete these nodes. There shouldn't be very many of these channels.
		// The only one expected is the "Main Forum" channel
		foreach($results AS $node)
		{
			$success = $channelLib->delete(intval($node['nodeid']));
			
			// if it failed to delete, there's not much we can do.
			if (!$success)
			{
				$this->show_message(sprintf($this->phrase['version']['503b1']['node_deletion_failed_for_x'], $node['nodeid']));
			}
			else
			{
				$this->show_message(sprintf($this->phrase['version']['503b1']['deleted_node_x'], $node['nodeid']));
			}
		}
		
		$this->show_message(sprintf($this->phrase['core']['process_done']));
	}

	/**
	 * Step 6 - Ensure cache.data is MEDIUMTEXT .. not blob
	 */
	public function step_6()
	{
		$tableinfo = $this->fetch_table_info('cache');
		if (!empty($tableinfo) AND $tableinfo['data']['Type'] != strtolower('mediumtext'))
		{
			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'cache', 1, 1),
				"ALTER TABLE " . TABLE_PREFIX . "cache CHANGE data data MEDIUMTEXT"
			);			
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Step 7 - Remove no longer needed phrasetypes
	 */
	public function step_7()
	{
		if ($this->tableExists('phrasetype'))
		{
			$this->show_message($this->phrase['version']['503b1']['removing_old_phrasetypes']);
			vB::getDbAssertor()->delete('phrasetype', array(
				'fieldname' => array('contenttypes', 'holiday', 'vbblocksettings'))
			);
		}
		else
		{
			$this->skip_message();
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
