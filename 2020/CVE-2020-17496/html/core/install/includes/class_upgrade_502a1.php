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

class vB_Upgrade_502a1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '502a1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.0.2 Alpha 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.0.1';

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

	public function step_1()
	{
		$this->skip_message();
	}

	//Now attachments from blogs
	public function step_2($data = NULL)
	{
		if (isset($this->registry->products['vbblog']) AND $this->registry->products['vbblog']
			AND $this->tableExists('attachment') AND $this->tableExists('filedata'))
		{
			$assertor = vB::getDbAssertor();

			$process = 5000;
			$startat = intval($data['startat']);
			$attachTypeId =  vB_Types::instance()->getContentTypeID('vBForum_Attach');
			$blogEntryTypeId =  $assertor->getField('vBForum:contenttype', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::COLUMNS_KEY => array('contenttypeid'),
				vB_dB_Query::CONDITIONS_KEY => array('class' => 'BlogEntry')
			));

			//First see if we need to do something. Maybe we're O.K.
			$maxvB4 = $assertor->getField('vBInstall:getMaxImportedAttachment', array('contentTypeId' => $blogEntryTypeId));

			//If we don't have any attachments, we're done.
			if (intval($maxvB4) < 1)
			{
				$this->skip_message();
				return;
			}

			$maxvB5 = $assertor->getField('vBInstall:getMaxImportedPost', array('contenttypeid' => vB_Api_ContentType::OLDTYPE_BLOGATTACHMENT));
			if (empty($maxvB5))
			{
				$maxvB5 = 0;
			}

			if (($maxvB4 <= $maxvB5) AND !$startat)
			{
				$this->skip_message();
				return;
			}
			else if ( ($maxvB4 <= $maxvB5) OR ($maxvB4 < $startat) )
			{
				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}
			$maxvB5 = max($maxvB5, $startat);

			/*** first the nodes ***/
			$assertor->assertQuery('vBInstall:insertBlogAttachmentNodes', array(
				'attachTypeId' => $attachTypeId,
				'oldContentTypeId' => vB_Api_ContentType::OLDTYPE_BLOGATTACHMENT,
				'blogStarterOldContentTypeId' => vB_Api_ContentType::OLDTYPE_BLOGSTARTER_PRE502a2,
				'batchSize' => $process,
				'startAt' => $maxvB5,
				'blogEntryTypeId' => $blogEntryTypeId,
			));

			//Now populate the attach table
			$assertor->assertQuery('vBInstall:insertBlogAttachments', array(
				'oldContentTypeId' => vB_Api_ContentType::OLDTYPE_BLOGATTACHMENT,
				'batchSize' => $process,
				'startAt' => $maxvB5,
				'blogEntryTypeId' => $blogEntryTypeId,
			));

			//Now the closure record for the node
			$assertor->assertQuery('vBInstall:addClosureSelf', array(
				'contenttypeid' => vB_Api_ContentType::OLDTYPE_BLOGATTACHMENT,
				'startat' => $maxvB5,
				'batchsize' => $process,
			));

			//Add the closure records to root
			$assertor->assertQuery('vBInstall:addClosureParents', array(
				'contenttypeid' => vB_Api_ContentType::OLDTYPE_BLOGATTACHMENT,
				'startat' => $maxvB5,
				'batchsize' => $process,
			));

			$this->show_message(sprintf($this->phrase['core']['processed_records_x'], $process));

			return array('startat' => ($maxvB5 + $process - 1));
		}
		else
		{
			$this->skip_message();
		}
	}
	/**
	 * Remove/Rename FAQ link from footer navigation items
	 * Add Help link to the footer
	 */
	public function step_3()
	{
		$footernavbar = $this->db->query_first("
				SELECT footernavbar FROM " . TABLE_PREFIX . "site
				WHERE siteid = 1");

		$footernavbar_array = array();
		if (!empty($footernavbar['footernavbar']))
		{
			$footernavbar_array = unserialize($footernavbar['footernavbar']);
			$found_help = false;
			$found_faq = false;
			foreach ($footernavbar_array as $index => $footernavbar_item)
			{
				if ($footernavbar_item['url'] == 'help')
				{
					$found_help = true;
				}
				if ($footernavbar_item['url'] == 'faq')
				{
					$found_faq = true;
					unset($footernavbar_array[$index]);
				}
			}
			// add help link if it is not there
			if (!$found_help)
			{
				$this->show_message($this->phrase['version']['501a1']['adding_help_to_footer']);
				array_unshift($footernavbar_array, array(
						'title' => 'navbar_help',
						'url' => 'help',
						'newWindow' => 0
				));
				$this->run_query(
						sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'site'),
						"
						UPDATE " . TABLE_PREFIX . "site
						SET footernavbar = '" . serialize($footernavbar_array) . "'
						WHERE
						siteid = 1
						"
				);
			}
			elseif ($found_faq)
			{
				$this->show_message($this->phrase['version']['501a1']['remove_footer_link']);
				//already removed the faq from the list above
				$this->run_query(
						sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'site'),
						"
						UPDATE " . TABLE_PREFIX . "site
						SET footernavbar = '" . serialize($footernavbar_array) . "'
						WHERE
						siteid = 1
						"
				);
			}
			else
			{
				$this->skip_message();
			}
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
