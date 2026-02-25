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

class vB_Upgrade_504a2 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '504a2';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.0.4 Alpha 2';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.0.4 Alpha 1';

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
	 * Generate correct value for vboptions: frontendurl
	 */
	public function step_1()
	{
		// Get the settings directly
		$data = $this->db->query_read("
			SELECT varname, value
			FROM " . TABLE_PREFIX . "setting
			WHERE varname IN ('bburl', 'frontendurl')
			ORDER BY varname
		");

		$frontendurl = false;

		while ($setting = $this->db->fetch_array($data))
		{
			switch ($setting['varname'])
			{
				case 'bburl':
					$bburl = $setting['value'];
				break;

				case 'frontendurl':
					$frontendurl = $setting['value'];
				break;
			}
		}

		if (!$frontendurl)
		{
			$newurl = $this->db->escape_string(substr($bburl,0, strpos($bburl, '/core')));
			$this->show_message($this->phrase['version']['504a2']['updating_frontendurl_settings']);

			if (!$frontendurl)
			{
				if ($frontendurl === false)
				{
					/* Setting does not exist, add it.
					The settings import will fill in the blanks */
					$this->db->query_write("
						INSERT INTO " . TABLE_PREFIX . "setting
						(varname, value, volatile)
						VALUES
						('frontendurl', '$newurl', 1)
					");
				}
				else
				{
					// Setting exists, update it
					$this->db->query_write("
						UPDATE " . TABLE_PREFIX . "setting
						SET value = '$newurl'
						WHERE varname = 'frontendurl'
					");
				}
			}
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * New emailstamp field for session table for guest email flood check
	 */
	public function step_2()
	{
		if (!$this->field_exists('session', 'emailstamp'))
		{
			// Create nodeid field
			$this->add_field(
				sprintf($this->phrase['core']['altering_x_table'], 'session', 1, 1),
				'session',
				'emailstamp',
				'INT',
				self::FIELD_DEFAULTS
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Adding product to pagetemplate
	 */
	public function step_3()
	{
		if (!$this->field_exists('pagetemplate', 'product'))
		{
			$this->add_field(
				sprintf($this->phrase['core']['altering_x_table'], 'pagetemplate', 1, 1),
				'pagetemplate',
				'product',
				'VARCHAR',
				array(
					'length' => 25,
					'default' => 'vbulletin',
				)
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Adding product to page
	 */
	public function step_4()
	{
		if (!$this->field_exists('page', 'product'))
		{
			$this->add_field(
				sprintf($this->phrase['core']['altering_x_table'], 'page', 1, 1),
				'page',
				'product',
				'VARCHAR',
				array(
					'length' => 25,
					'default' => 'vbulletin',
				)
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Adding product to channel
	 */
	public function step_5()
	{
		if (!$this->field_exists('channel', 'product'))
		{
			$this->add_field(
				sprintf($this->phrase['core']['altering_x_table'], 'channel', 1, 1),
				'channel',
				'product',
				'VARCHAR',
				array(
					'length' => 25,
					'default' => 'vbulletin',
				)
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Adding product to routenew
	 */
	public function step_6()
	{
		if (!$this->field_exists('routenew', 'product'))
		{
			$this->add_field(
				sprintf($this->phrase['core']['altering_x_table'], 'routenew', 1, 1),
				'routenew',
				'product',
				'VARCHAR',
				array(
					'length' => 25,
					'default' => 'vbulletin',
				)
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Remove meta keyword field from node table
	 */
	public function step_7()
	{
	if ($this->field_exists('node', 'keywords'))
		{
			//If we have over a million posts we won't do this.
			$check = vB::getDbAssertor()->getRow('vBInstall:getMaxNodeid', array());

			if ($check AND !empty($check['maxid']) AND (intval($check['maxid']) > 1000000))
			{
				$this->skip_message();
				$this->add_adminmessage('can_drop_node_keywords', array('dismissable' => 1,
					'status'  => 'undone',));
			}
			else
			{
				$this->drop_field(sprintf($this->phrase['core']['altering_x_table'], 'node', 1, 1),
					'node', 'keywords'
				);

			}
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Remove meta keyword field from page table
	 */
	public function step_8()
	{
	if ($this->field_exists('page', 'metakeywords'))
		{
			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'page', 1, 1),
				"ALTER TABLE " . TABLE_PREFIX . "page DROP COLUMN metakeywords"
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Add reputation penalty for an infraction
	 */
	public function step_9()
	{
		if (!$this->field_exists('infraction', 'reputation_penalty'))
		{
			$this->add_field(
				sprintf($this->phrase['core']['altering_x_table'], 'infraction', 1, 1),
				'infraction',
				'reputation_penalty',
				'INT',
				self::FIELD_DEFAULTS
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Add reputation penalty for an infraction level
	 */
	public function step_10()
	{
		if (!$this->field_exists('infractionlevel', 'reputation_penalty'))
		{
			$this->add_field(
				sprintf($this->phrase['core']['altering_x_table'], 'infractionlevel', 1, 1),
				'infractionlevel',
				'reputation_penalty',
				'INT',
				self::FIELD_DEFAULTS
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
|| # CVS: $RCSfile$ - $Revision: 103678 $
|| #######################################################################
\*=========================================================================*/
