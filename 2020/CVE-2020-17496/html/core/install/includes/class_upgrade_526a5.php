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

class vB_Upgrade_526a5 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '526a5';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.2.6 Alpha 5';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.2.6 Alpha 4';

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
		//this might be a good idea, but it doesn't match the install and the table
		//isn't currently used.
		$this->drop_index(
			sprintf($this->phrase['core']['altering_x_table'], 'sentto', 1, 1),
			'sentto',
			'userid'
		);
	}

	public function step_2()
	{
		$this->add_index(
			sprintf($this->phrase['core']['create_index_x_on_y'], 'user_read_deleted', TABLE_PREFIX . 'sentto'),
			'sentto',
			'user_read_deleted',
			array('userid', 'msgread', 'deleted')
		);
	}

	//the accessmask phrase group has been removed from the language file.  The
	//language import will add new groups, but won't remove any that have been removed
	//so we need to manually remove the field from the language table.
	public function step_3()
	{
		$this->drop_field(
			sprintf($this->phrase['core']['altering_x_table'], 'language', 1, 1),
			"language",
			"phrasegroup_accessmask"
		);
	}

	//and the record from the phrasetype table.  The language import will handle everything else.
	public function step_4()
	{
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table_x'], 'phrasetype', 1, 1));
		$db = vB::getDbAssertor();
		$db->delete('phrasetype', array('fieldname' => 'accessmask'));
	}


	/*
	 * Event contenttype related upgrade steps.
	 */
	// Check for vb4 event table, rename it to legacyevent.
	public function step_5()
	{
		if ($this->tableExists('event') AND $this->field_exists('event', 'calendarid'))
		{
			$assertor = vB::getDbAssertor();
			$assertor->assertQuery('vBInstall:renameLegacyEventTable');
			$this->show_message($this->phrase['version']['526a5']['renaming_legacyevent']);
		}
		else
		{
			$this->skip_message();
		}
	}

	// Add event table.
	public function step_6()
	{
		if (!$this->tableExists('event'))
		{
			$this->run_query(
				sprintf($this->phrase['vbphrase']['create_table'], TABLE_PREFIX . 'event'),
				"
					CREATE TABLE " . TABLE_PREFIX . "event (
						nodeid          INT UNSIGNED NOT NULL PRIMARY KEY,
						eventstartdate  INT UNSIGNED NOT NULL DEFAULT '0',
						eventenddate    INT UNSIGNED NOT NULL DEFAULT '0',
						location        VARCHAR (191) NOT NULL DEFAULT '',
						KEY eventstartdate (eventstartdate)
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

	// `contenttype` record (contenttypeid). Move vb4 event type to 'legacyevent' and add 'event'
	public function step_7()
	{
		$assertor = vB::getDbAssertor();
		$this->show_message($this->phrase['version']['526a5']['checking_legacyevent_conflicts']);

		$package = $assertor->getRow('package', array('productid' => "vbulletin", 'class' => 'vBForum'));
		if (empty($package['packageid']))
		{
			// something went wrong.. skip.
			$this->skip_message();
			return;
		}
		$packageid = $package['packageid'];

		$eventType = $assertor->getRow('vBForum:contenttype', array('packageid' => $packageid, 'class' => 'Event'));
		$legacyEventType = $assertor->getRow('vBForum:contenttype', array('packageid' => $packageid, 'class' => 'LegacyEvent'));
		$calendarType = $assertor->getRow('vBForum:contenttype', array('packageid' => $packageid, 'class' => 'Calendar'));

		$doInsert = false;
		if (empty($eventType))
		{
			$doInsert = true;
		}
		else
		{
			// We have an event type. If Calendar exists, but LegacyEvent does not, this is an upgrade that needs the
			// old event type renamed & the new event type added.
			// If Calendar and LegacyEvent both exist, the existing Event type is the new one, so we're good.
			if (!empty($calendarType) AND empty($legacyEventType))
			{
				// This is vB4's event. Let's keep it but rename it as legacyevent, similar to the data table.
				$assertor->update(
					'vBForum:contenttype',
					array('class' => 'LegacyEvent'),	// values
					array('packageid' => $packageid, 'class' => 'Event')	// conditions
				);
				$this->show_message($this->phrase['version']['526a5']['renaming_contenttype_legacyevent']);
				$doInsert = true;
			}
			else
			{
				// event type exists, and it's not the legacy one. We're golden.
				return $this->show_message(sprintf($this->phrase['core']['process_done']));
			}
		}


		if ($doInsert)
		{
			$this->show_message($this->phrase['version']['526a5']['inserting_contenttype_event']);
			// just insert a new one.
			$data = array(
				'class' => 'Event',
				'packageid' => $packageid,
				'canplace' => 1,
				'cansearch' => 1,
				'cantag' => 1,
				'canattach' => 1,
				'isaggregator' => 0,
			);
			$assertor->insert('vBForum:contenttype', $data);
		}
	}

	// Add createpermissions bit for event. Follow vbforum_text
	public function step_8()
	{
		// Only run once.
		if ($this->iRan(__FUNCTION__))
		{
			return;
		}

		$assertor = vB::getDbAssertor();
		$this->show_message($this->phrase['version']['526a5']['adding_event_createpermissions']);


		$permBits = $this->getUGPBitfields();

		$params = array(
			'textbit' => $permBits['createpermissions']['vbforum_text'],
			'eventbit' => $permBits['createpermissions']['vbforum_event'],
		);
		$assertor->assertQuery('vBInstall:setVbforumEventPermission', $params);
	}

	/**
	 * Add the widget.titlephrase field
	 */
	public function step_9()
	{
		$this->add_field(
			sprintf($this->phrase['core']['altering_x_table'], 'widget', 1, 1),
			'widget',
			'titlephrase',
			'VARCHAR',
			array('length' => 255, 'null' => false, 'default' => '')
		);
	}

}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
