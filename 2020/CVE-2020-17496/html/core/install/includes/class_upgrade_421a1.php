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

class vB_Upgrade_421a1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '421a1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '4.2.1 Alpha 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '4.2.0';

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

	/** In general, upgrade files between 4.1.5 and 500a1 are likely to be different in vB5 from their equivalent in vB4.
	 *  Since large portions of vB4 code were removed in vB5, the upgrades to ensure that code works is unnecessary. If
	 *  there are actual errors that affect vB5, those must be included of course. If there are changes whose absence would
	 *  break a later step, those are required.
	 *
	 * But since these files will only be used to upgrade to versions after 5.0.0 alpha 1, most of the upgrade steps can be
	 * omitted. We could use skip_message(), but that takes up a redirect and, in the cli upgrade, a recursion. We would rather
	 * avoid those. So we have removed those steps,
	 * Step 1 in the original is not needed because we don't use the navigation table in vB5
	 * Step 2 we don't use 'ignored' as template mergestatus. We can add the step later in vB5 upgrade steps if we port this feature into vB5
	 * Step 6 in the original is not needed because we don't use the navigation table in vB5
	 *
	 * So we have some use for step 3, 4, 5 to keep update for old events even if we don't have event module in vB5 yet.
	 * We kept event table in vB5 so we may use its old data in future.
	 */

	/*
	 * Step 1 - Add field to track titles that have been converted
	 * this ensures that no field gets double encoded if the upgrade is executed multiple times
	 */
	function step_1() // Was Step 3
	{
		$this->add_field(
			sprintf($this->phrase['core']['altering_x_table'], 'event', 1, 1),
			'event',
			'title_encoded',
			'smallint',
			self::FIELD_DEFAULTS
		);
	}

	/*
	 * Step 2 - encode event titles
	 */
	function step_2($data = null) // Was Step 4
	{
		$process = 1000;
		$startat = intval($data['startat']);

		if ($startat == 0)
		{
			$events = $this->db->query_first_slave("
				SELECT COUNT(*) AS events
				FROM " . TABLE_PREFIX . "event
				WHERE title_encoded = 0
			");

			$total = $events['events'];

			if ($total)
			{
				$this->show_message(sprintf($this->phrase['version']['421a1']['processing_event_titles'], $total));
				return array('startat' => 1);
			}
			else
			{
				$this->skip_message();
				return;
			}
		}
		else
		{
			$first = $startat - 1;
		}

		$events = $this->db->query_read_slave("
			SELECT title, eventid
			FROM " . TABLE_PREFIX . "event
			WHERE title_encoded = 0
			LIMIT $first, $process
		");

		$rows = $this->db->num_rows($events);

		if ($rows)
		{
			while ($event = $this->db->fetch_array($events))
			{
				$newtitle = htmlspecialchars_uni($event['title']);

				$this->db->query_write("
					UPDATE " . TABLE_PREFIX . "event
					SET
						title = '" . $this->db->escape_string($newtitle) . "',
						title_encoded = 1
					WHERE
						eventid = {$event['eventid']}
							AND
						title_encoded = 0
				");

			}

			$this->db->free_result($events);
			$this->show_message(sprintf($this->phrase['version']['421a1']['updated_event_titles'], $first + $rows));

			return array('startat' => $startat + $process);
		}
		else
		{
			$this->show_message($this->phrase['version']['421a1']['updated_event_titles_complete']);
		}
	}

	/*
	 * Step 3 - change default on title_encoded to 1 so any events added after this upgrade
	 * won't get double encoded if the upgrade is executed again
	 *
	 */
	function step_3() // Was Step 5
	{
		$this->run_query(
			sprintf($this->phrase['core']['altering_x_table'], 'event', 1, 1),
			"ALTER TABLE " . TABLE_PREFIX . "event CHANGE title_encoded title_encoded SMALLINT NOT NULL DEFAULT '1'"
		);
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
