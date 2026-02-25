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

class vB_Upgrade_541a3 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '541a3';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.4.1 Alpha 3';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.4.1 Alpha 2';

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

	public function step_1($data)
	{
		if ($this->tableExists('attachment'))
		{
			$oldcontenttype = array(
				vB_Api_ContentType::OLDTYPE_POSTATTACHMENT,
				vB_Api_ContentType::OLDTYPE_THREADATTACHMENT,
				vB_Api_ContentType::OLDTYPE_BLOGATTACHMENT,
				vB_Api_ContentType::OLDTYPE_ARTICLEATTACHMENT,
			);


			if(empty($data['startat']))
			{
				$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'node'));
			}

			$callback = function($startat, $nextid) use ($oldcontenttype)
			{
				vB::getDbAssertor()->assertQuery('vBInstall:fixAttachmentUser', array(
					'oldcontenttypeid' => $oldcontenttype,
					'startat' => $startat,
					'nextid' => $nextid,
				));

				$this->show_message(sprintf($this->phrase['core']['processed_records_x_y'], $startat, $nextid), true);
			};

			//this is a bit wierd because we iterate over the attach table but update using the node and attachment
			//tables.  This is because the query *really* wants to use the node rather than the attachment as the
			//driver (which limits the advantage of doing a range on attachment ids), but this allows us to only
			//look at attachment nodes without having to scan and filter on the much larger node table.
			//this does mean we'll look at all attachments and not just the ones we imported from vB4.  That's extra
			//work but doesn't hurt anything (and in most cases less extra work than trying to iterate over the node table)
			return $this->updateByIdWalk($data,	5000, 'vBInstall:getMaxAttachNodeid', 'vBForum:attach', 'nodeid', $callback);
		}
		else
		{
			$this->skip_message();
		}
	}

	//we do this as a seperate step because some databases seem to have the correct
	//username but a blank authorname
	public function step_2($data)
	{
		$oldcontenttype = array(
			vB_Api_ContentType::OLDTYPE_POSTATTACHMENT,
			vB_Api_ContentType::OLDTYPE_THREADATTACHMENT,
			vB_Api_ContentType::OLDTYPE_BLOGATTACHMENT,
			vB_Api_ContentType::OLDTYPE_ARTICLEATTACHMENT,
		);

		if(empty($data['startat']))
		{
			$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'node'));
		}

		$callback = function($startat, $nextid) use ($oldcontenttype)
		{
			vB::getDbAssertor()->assertQuery('vBInstall:fixAttachmentUsername', array(
				'oldcontenttypeid' => $oldcontenttype,
				'startat' => $startat,
				'nextid' => $nextid,
			));

			$this->show_message(sprintf($this->phrase['core']['processed_records_x_y'], $startat, $nextid), true);
		};

		//this is a bit wierd because we iterate over the attach table but update using the node and user tables.
		return $this->updateByIdWalk($data,	5000, 'vBInstall:getMaxAttachNodeid', 'vBForum:attach', 'nodeid', $callback);
	}


	// Add userauth table.
	public function step_3()
	{
		// moved to 541a4
		$this->skip_message();
	}

	// Add loginlibraries table.
	public function step_4()
	{
		// moved to 541a4
		$this->skip_message();
	}

	// Add sessionauth table.
	public function step_5()
	{
		// moved to 541a4
		$this->skip_message();
	}

	/**
	* Handle customized values for stylevars that have been renamed
	*/
	public function step_6()
	{
		$mapper = new vB_Stylevar_Mapper();

		// "post_rating_color" was renamed to "reputation_bar_active_background" and the
		// datatype changed from color to background. Transfer the color value only.
		// No preset values need to be added, since all the other values in the background
		// type can safely be left empty.
		$mapper->addMapping('post_rating_color.color', 'reputation_bar_active_background.color');

		// Do the processing
		if ($mapper->load() AND $mapper->process())
		{
			$this->show_message($this->phrase['version']['541a1']['mapping_customized_stylevars']);
			$mapper->processResults();
		}
		else
		{
			$this->skip_message();
		}
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
