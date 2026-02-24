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

class vB_Upgrade_505a3 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '505a3';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.0.5 Alpha 3';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.0.5 Alpha 2';

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

	/** The format of the profilefield has changed and needs to be regenerated */
	public function step_1()
	{
		$this->show_message($this->phrase['version']['505a3']['update_profilefields_cache']);
		// Update hidden profile cache to include all fields on the profile page.
		require_once(DIR . '/includes/adminfunctions_profilefield.php');
		build_profilefield_cache();

	}

	/** Add thumbnail caching to the video table */
	public function step_2()
	{
		$created = false;
		if (!$this->field_exists('video', 'thumbnail'))
		{
			// Create thumbnail field
			$this->add_field(
				sprintf($this->phrase['core']['altering_x_table'], 'video', 1, 2),
				'video',
				'thumbnail',
				'VARCHAR',
				array('length' => 255, 'default' => '')
			);
			$created = true;
		}

		if (!$this->field_exists('video', 'thumbnail_date'))
		{
			// Create thumbnail_date field
			$this->add_field(
					sprintf($this->phrase['core']['altering_x_table'], 'video', 2, 2),
					'video',
					'thumbnail_date',
					'INT',
					array('length' => 11, 'null' => false, 'default' => 0, 'attributes' => 'UNSIGNED')
			);
			$created = true;
		}

		if (!$created)
		{
			$this->skip_message();
		}

	}
		
	/**
	 * Step 3 add nodeview table
	 */
	public function step_3()
	{
		if (!$this->tableExists('nodeview'))
		{
			$this->run_query(
				sprintf($this->phrase['vbphrase']['create_table'], TABLE_PREFIX . 'nodeview'),
				"
				CREATE TABLE " . TABLE_PREFIX . "nodeview (
					nodeid INT UNSIGNED NOT NULL DEFAULT '0',
					count INT UNSIGNED NOT NULL DEFAULT '0',
					PRIMARY KEY (nodeid)
				) ENGINE = " . $this->hightrafficengine . "
				",
				self::MYSQL_ERROR_TABLE_EXISTS
			);
		}
		else
		{
			$this->skip_message();
		}
	}
	
	/**
	 * Step 4 update nodeviews table with thread (column views) & threadviews tables if they exist
	 */
	public function step_4($data = NULL)
	{
		// both thread & threadviews tables are standard tables in vB4. If, for some reason, they have dropped the threadviews table,
		// but left the thread table in-tact, rather than having 2 separate upgrade classes they should just create the threadviews 
		// table & re-run the upgrader. If they dropped or truncated the thread table, then we can't import the old view counts.
		if ($this->tableExists('thread') AND $this->tableExists('threadviews'))
		{
			/*
			 *	There is a bug where sometimes the step # isn't recorded properly. It seems to affect the last step, which is
			 *	why there is a blank step_5 in this class, just so that step_4 isn't the last one.
			 *	If the upgradelog didn't record the step properly, the user will see a MySQL error: 
			 *	Duplicate entry <> for key 'PRIMARY'
			 *	Rather than doing complex checks or truncating the table & rebuilding it, I've just added a blank step_5
			*/
			//We only need to run this once.
			if (empty($data['startat']))
			{
				$log = vB::getDbAssertor()->assertQuery('vBInstall:upgradelog', array('script' => '505a3', 'step' => 4)); // Must match this step.

				if ($log->valid())
				{
					$this->skip_message();
					return;
				}
			}
			
			// output what we're doing
			$this->show_message($this->phrase['version']['505a3']['import_thread_views']);
			
			$assertor = vB::getDbAssertor();
			$batchSize = 150000;	// using the dev_42 DB, this seems to be about the sweet spot, ~3s per step
			// we only update the nodeview for threads imported from vb4
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
				$max = $assertor->getRow('vBInstall:getMaxThreadid', array());
				$max = intval($max['maxid']);
			}
			
			// finish condition is when no thread were imported or we already processed the max oldid
			if ($max == 0 OR $max <= $startat)
			{
				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}
			
			
			// import views from thread tables
			$assertor->assertQuery('vBInstall:importThreadviews',
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
	
	/**
	 * Step 5 update nodeviews table with blog (column views) & blog_views tables if they exist
	 */
	public function step_5($data = NULL)
	{
		// Using basically the same logic as step_4, just different tables
		if ($this->tableExists('blog') AND $this->tableExists('blog_views'))
		{
			//We only need to run this once.
			if (empty($data['startat']))
			{
				$log = vB::getDbAssertor()->assertQuery('vBInstall:upgradelog', array('script' => '505a3', 'step' => 5)); // Must match this step.

				if ($log->valid())
				{
					$this->skip_message();
					return;
				}
			}
			
			// output what we're doing
			$this->show_message($this->phrase['version']['505a3']['import_blog_views']);
			
			$assertor = vB::getDbAssertor();
			// dev_42 only has ~200 blogs. Inserted about 350k blog starter nodes and this size takes about ~3s per step
			// the query is very similar to step_4, so I expect their times/batchSize to be equivalent
			$batchSize = 150000;	
			// we only update the nodeview for blogs imported from vb4
			$blogId = vB_Api_ContentType::OLDTYPE_BLOGSTARTER;
			
			// grab startat
			$startat = intval($data['startat']);
			// grab max if using CLI & not first iteration, else fetch it from DB
			if (!empty($data['max']))
			{
				$max = intval($data['max']);
			}
			else
			{
				$max = $assertor->getRow('vBInstall:getMaxBlogid', array());
				$max = intval($max['maxid']);
			}
			
			// finish condition is when no thread were imported or we already processed the max oldid
			if ($max == 0 OR $max <= $startat)
			{
				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}
			
			
			// import views from blog tables
			$assertor->assertQuery('vBInstall:importBlogviews',
				array(
					'oldcontenttypeid' => $blogId, 
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
	 *	Step 6 - this step doesnt' do anything, but is necessary. For some reason, the last step in each class
	 *		doesn't seem to get recorded properly in the upgradelog. Since step_4/step_5 require a proper record,
	 *		I'm leaving this just so that step_5 isn't the last step.
	 */
	public function step_6($data = NULL)
	{
		/*                       
						 __		   					 ___________  ________
					___./ /     _.---.				|		  	| \_   __/
					\__  (__..-`       \			|	^		|  /  /
					   \            O   |			|____		|_/	 /
						`..__.   ,=====/			|_______________/
						  `._/_.'_____/
						  
		 * IF ANOTHER STEP IS ADDED, PLEASE REPLACE THIS ONE. HOWEVER, ADD A NOTE ON THAT STEP THAT 
		 * IF STEP_6 IS TO BE REMOVED, A BLANK ONE SHOULD BE INSERTED AGAIN.
		 */
		$this->skip_message();
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
