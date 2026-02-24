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

class vB_Upgrade_517a4 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '517a4';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.7 Alpha 4';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.7 Alpha 3';

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
	 * Step 1 : Possibly long next step
	 */
	public function step_1()
	{
		$this->long_next_step();
	}

	/**
	 * Step 2 : nuke all legacy, orphaned notifications
	 */
	public function step_2($data = null)
	{
		$this->show_message($this->phrase['version']['517a4']['removing_orphan_notifications']);
		// We may need to move this into a stored query so we can put a LIMIT on it.
		$assertor = vB::getDbAssertor();
		$oldNotification = $assertor->getRow(
			'vBForum:privatemessage',
			array(
				'msgtype'	=> 'notification',
				'deleted'	=> 0,
			)
		);

		if (!empty($oldNotification))
		{
			$startat = $oldNotification['nodeid'];
			$count = $assertor->assertQuery('vBInstall:flagRemainingNotificationsForDelete');
			$this->show_message(sprintf($this->phrase['core']['processed_x_records_starting_at_y'], $count, $startat));
			return array('startat' => $startat);
		}
		else
		{
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}
	}

	/**
	 * Rename widgetinstance.parent to widgetinstance.containerinstanceid
	 */
	public function step_3()
	{
		if ($this->field_exists('widgetinstance', 'parent'))
		{
			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'widgetinstance', 1, 1),
				"ALTER TABLE " . TABLE_PREFIX . "widgetinstance CHANGE parent containerinstanceid INT UNSIGNED NOT NULL DEFAULT '0'"
			);
		}
		else
		{
			$this->skip_message();
		}

		$this->long_next_step();
	}

	public function step_4()
	{
		$result = vB::getDbAssertor()->getRow('vBInstall:checkDuplicatAttachRecords');
		if (!$result)
		{
			$this->drop_index(
				sprintf($this->phrase['core']['altering_x_table'], 'attach', 1, 2),
				'attach',
				'attach_nodeid'
			);

			$this->add_index(
				sprintf($this->phrase['core']['altering_x_table'], 'attach', 2, 2),
				'attach',
				'PRIMARY',
				array('nodeid'),
				'primary'
			);
		}
		else
		{
			$this->add_adminmessage('unique_index_x_failed',
				array(
					'dismissable' => 1,
					'status'  => 'undone',
				),
				true,
				array('PRIMARY KEY', 'attach', $this->LONG_VERSION)
			);

			$this->show_message(sprintf($this->phrase['core']['unique_index_x_failed'], 'PRIMARY KEY', 'attach', $this->LONG_VERSION));
		}
	}

	//we are okay dropping/creating this index without a check because the existing index is
	//unique.  We are merely changing it to a primary key.
	public function step_5()
	{
		$this->drop_index(
			sprintf($this->phrase['core']['altering_x_table'], 'redirect', 1, 2),
			'redirect',
			'nodeid'
		);
	}

	public function step_6()
	{
		$this->add_index(
			sprintf($this->phrase['core']['altering_x_table'], 'redirect', 2, 2),
			'redirect',
			'PRIMARY',
			array('nodeid'),
			'primary'
		);
	}

	public function step_7()
	{
		$result = vB::getDbAssertor()->assertQuery('vBInstall:removeAutoincrementPhoto');
		$this->show_message(sprintf($this->phrase['core']['altering_x_table'], 'photo', 1, 3));
	}

	public function step_8()
	{
		$this->drop_field(
			sprintf($this->phrase['core']['altering_x_table'], 'photo', 2, 3),
			'photo',
			'photoid'
		);
	}

	public function step_9()
	{
		$this->add_index(
			sprintf($this->phrase['core']['altering_x_table'], 'photo', 3, 3),
			'photo',
			'PRIMARY',
			array('nodeid'),
			'primary'
		);
	}

	public function step_10()
	{
		$result = vB::getDbAssertor()->assertQuery('vBInstall:removeAutoincrementPoll');
		$this->show_message(sprintf($this->phrase['core']['altering_x_table'], 'poll', 1, 4));
	}

	public function step_11()
	{
		$this->drop_field(
			sprintf($this->phrase['core']['altering_x_table'], 'poll', 2, 4),
			'poll',
			'pollid'
		);
	}

	public function step_12()
	{
		$this->drop_field(
			sprintf($this->phrase['core']['altering_x_table'], 'poll', 3, 4),
			'poll',
			'question'
		);
	}

	public function step_13()
	{
		$this->drop_field(
			sprintf($this->phrase['core']['altering_x_table'], 'poll', 4, 4),
			'poll',
			'dateline'
		);
	}

	/**
	 * Change widgetdefinition.label to labelphrase
	 */
	public function step_14()
	{
		if ($this->field_exists('widgetdefinition', 'label'))
		{
			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'widgetdefinition', 1, 1),
				"ALTER TABLE " . TABLE_PREFIX . "widgetdefinition CHANGE label labelphrase VARCHAR(250) NOT NULL DEFAULT ''"
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Add the widget.parentid field for widget inheritance
	 */
	public function step_15()
	{
		/*
			Note, for vB4 upgrades, the parentid can also be added prior to this by
			vB_Xml_Import_Widget::checkWidgetParentidAndAlterTable() . See VBV-16969
		 */
		$this->add_field(
			sprintf($this->phrase['core']['altering_x_table'], 'widget', 1, 1),
			'widget',
			'parentid',
			'int',
			self::FIELD_DEFAULTS
		);
	}


	public function step_16($data = null)
	{
		$this->show_message($this->phrase['version']['517a4']['fixing_node_showapproved']);

		// We may need to move this into a stored query so we can put a LIMIT on it.
		$assertor = vB::getDbAssertor();
		$next = $assertor->getRow(
			'vBForum:node',
			array(
				'approved' => 0,
				'showapproved' => 1,
				vB_dB_Query::COLUMNS_KEY => array('nodeid')
			)
		);

		if (!empty($next))
		{
			$startat = $next['nodeid'];
			$count = $assertor->assertQuery('vBInstall:fixShowApproved', array('batch_size' => 10000));
			$this->show_message(sprintf($this->phrase['core']['processed_x_records_starting_at_y'], $count, $startat));
			return array('startat' => $startat);
		}
		else
		{
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
