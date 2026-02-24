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

class vB_Upgrade_534a3 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '534a3';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.3.4 Alpha 3';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.3.4 Alpha 2';

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

	// add index on event.eventenddate
	function step_1()
	{
		$this->add_index(
			sprintf($this->phrase['core']['create_index_x_on_y'], 'eventenddate', TABLE_PREFIX . 'event'),
			'event',
			'eventenddate',
			'eventenddate'
		);
	}

	// add event.allday column
	function step_2()
	{
		$this->add_field(
			sprintf($this->phrase['core']['altering_x_table'], 'event', 1, 1),
			'event',
			'allday',
			'tinyint',
			array('length' => 1, 'null' => false, 'default' => '0')
		);
	}

	function step_3()
	{
		if ($this->field_exists('event', 'allday'))
		{
			// First, update all events with eventenddate = 0 to set allday = 1
			$this->show_message($this->phrase['version']['534a4']['setting_event_allday']);
			$assertor = vB::getDbAssertor();
			$updateConditions = array(
				array('field' => 'eventenddate', 'value' => 0, vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ),
				array('field' => 'allday', 'value' => 0, vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ),
			);
			$needUpdate = $assertor->getRow(
				'vBForum:event',
				array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_COUNT,
					vB_dB_Query::CONDITIONS_KEY => $updateConditions,
				)
			);

			if (empty($needUpdate['count']))
			{
				return $this->skip_message();
			}
			else
			{
				$this->show_message(sprintf($this->phrase['core']['processing_records_x'], $needUpdate['count']));
				$assertor->assertQuery(
					'vBForum:event',
					array(
						vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
						vB_dB_Query::CONDITIONS_KEY => $updateConditions,
						'allday' => 1
					)
				);
			}
		}
		else
		{
			// If, somehow, the order got messed up or there are DB errors such that the previous step didn't create the
			// required index, there's nothing we can do here.
			$this->skip_message();
		}
	}

	function step_4($data = null)
	{
		if ($this->field_exists('event', 'allday'))
		{
			// fetch events whose eventenddate = 0 AND allday = 1 (went through step 3), ordered by
			// userid, and calculate the enddate for each event (11:59:59PM user's timezone)

			if (empty($data['startat']))
			{
				$this->show_message($this->phrase['version']['534a4']['updating_allday_event_enddates']);
				$data['startat'] = 0;
			}

			$assertor = vB::getDbAssertor();
			$batchSize = 1000;
			$needUpdate = $assertor->getRows(
				'vBInstall:getAlldayEventsMissingEnddates',
				array('batchsize' => $batchSize,)
			);


			if (empty($needUpdate))
			{
				if (empty($data['startat']))
				{
					return $this->skip_message();
				}
				else
				{
					return $this->show_message(sprintf($this->phrase['core']['process_done']));
				}
			}
			else
			{
				$userAPI = vB_Api::instanceInternal('user');
				$eventLib = vB_Library::instance('content_event');
				$eventUpdates = array();
				foreach ($needUpdate AS $__row)
				{
					$__nodeid = $__row['nodeid'];
					$__userid = $__row['userid'];
					// We need to grab the offset for the specific date..
					$__startdate = $__row['eventstartdate'];
					$__startdate = $eventLib->getEndOfDayUnixtime($__startdate, $__userid, "12:00:00 AM");
					$__enddate = $eventLib->getEndOfDayUnixtime($__startdate, $__userid);
					// Handle unlikey case that startdate for an allday event is 11:59:59PM.
					// Although this technically makes it elapse 2 days, we should ensure
					// that eventenddate > eventstartdate.
					if ($__enddate <= $__startdate)
					{
						$__enddate = $__startdate + 1;
					}

					$eventUpdates[$__nodeid] = array(
						'nodeid' => $__nodeid,
						'eventenddate' => $__enddate,
						'eventstartdate' => $__startdate,
					);
				}
				$this->show_message(sprintf($this->phrase['core']['processing_records_x'], count($eventUpdates)));
				$assertor->assertQuery('vBInstall:updateEventEnddates', array("events" => $eventUpdates));

				// startat isn't used for anything other than forcing the next iteration.
				return array('startat' => ++$data['startat']);
			}
		}
		else
		{
			// If, somehow, the order got messed up or there are DB errors such that the previous step didn't create the
			// required index, there's nothing we can do here.
			$this->skip_message();
		}
	}

	public function step_5()
	{
		$this->add_field(
			sprintf($this->phrase['core']['altering_x_table'], 'event', 1, 1),
			'event',
			'maplocation',
			'VARCHAR',
			array('length' => 191, 'null' => false, 'default' => '')
		);
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
