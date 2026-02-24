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

/**
 * vB_Api_Cron
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Cron extends vB_Api
{
	/**
	 * @var array
	 */
	protected $disableWhiteList = array('nextRun');

	/**
	 * Run cron
	 *
	 * @return bool
	 */
	public function run()
	{
		require_once(DIR . '/includes/functions_cron.php');
		exec_cron();
		return true;
	}

	/**
	 *	Run a cron
	 *
	 *	Runs the specified cron immediately without regard for it's usual scheduling
	 *
	 *	@param int $cronid
	 */
	public function runById($cronid)
	{
		$this->checkHasAdminPermission('canadmincron');
		vB_Library::instance('cron')->runById($cronid);
		return array('success' => true);
	}

	/**
	 *	Run a cron
	 *
	 *	Runs the specified cron immediately without regard for it's usual scheduling
	 *
	 *	@param string $varname -- the string identifier for the cron
	 */
	public function runByVarname($varname)
	{
		$this->checkHasAdminPermission('canadmincron');
		vB_Library::instance('cron')->runByVarname($varname);
		return array('success' => true);
	}

	/**
	 * Fetch a cron by its ID
	 *
	 * @param  int   $cronid
	 *
	 * @return array Cron information
	 */
	public function fetchById($cronid)
	{
		$this->checkHasAdminPermission('canadmincron');
		$cron = vB::getDbAssertor()->getRow('cron', array('cronid' => $cronid));
		return $this->loadCron($cron);
	}

	/**
	 * Returns a cron task based on the cron varname
	 *
	 * @param  string Cron varname
	 *
	 * @return array  Cron info
	 */
	public function fetchByVarname($varname)
	{
		$this->checkHasAdminPermission('canadmincron');
		$cron = vB::getDbAssertor()->getRow('cron', array('varname' => $varname));
		return $this->loadCron($cron);
	}

	/**
	 * Returns the cron next run time.
	 *
	 * @return int Cron next run timestamp.
	 */
	public function nextRun()
	{
		$nextrun = vB::getDatastore()->getValue('cron');

		return $nextrun ? $nextrun : 0;
	}

	/**
	 * Loads and returns a cron task
	 *
	 * @param  array Cron info
	 *
	 * @return array Cron info
	 */
	private function loadCron(&$cron)
	{
		if (!$cron)
		{
			throw new vB_Exception_Api('invalidid', array('cronid'));
		}

		$title = 'task_' . $cron['varname'] . '_title';
		$desc = 'task_' . $cron['varname'] . '_desc';
		$logphrase = 'task_' . $cron['varname'] . '_log';

		if (is_numeric($cron['minute']))
		{
			$cron['minute'] = array(0 => $cron['minute']);
		}
		else
		{
			$cron['minute'] = unserialize($cron['minute']);
		}

		$phrases = vB::getDbAssertor()->assertQuery('cron_fetchphrases', array(
			'languageid' => ($cron['volatile'] ? -1 : 0),
			'title' => $title,
			'desc' => $desc,
			'logphrase' => $logphrase,
		));
		foreach ($phrases as $phrase)
		{
			if ($phrase['varname'] == $title)
			{
				$cron['title'] = $phrase['text'];
				$cron['titlevarname'] = $title;
			}
			else if ($phrase['varname'] == $desc)
			{
				$cron['description'] = $phrase['text'];
				$cron['descvarname'] = $desc;
			}
			else if ($phrase['varname'] == $logphrase)
			{
				$cron['logphrase'] = $phrase['text'];
				$cron['logvarname'] = $logphrase;
			}
		}

		return $cron;
	}


	/**
	 * Fetches All cron tasks
	 *
	 * @return array Crons
	 */
	public function fetchAll()
	{
		$this->checkHasAdminPermission('canadmincron');
		$crons = vB::getDbAssertor()->getRows('cron_fetchall');
		return $crons;
	}

	/**
	 * Insert a new cron or Update an existing cron
	 *
	 * @param array $data Cron data to be inserted or updated
	 *              'varname'     => Varname
	 *              'filename'    => Filename
	 *              'title'       => Title
	 *              'description' => Description
	 *              'logphrase'   => Log Phrase
	 *              'weekday'     => Day of the Week (Note: this overrides the 'day of the month' option)
	 *              'day'         => Day of the Month
	 *              'hour'        => Hour
	 *              'minute'      => Minute
	 *              'active'      => Active. Boolean.
	 *              'loglevel'    => Log Entries. Boolean.
	 *              'product'     => Product
	 *              'volatile'    => vBulletin Default. Boolean.
	 * @param  int  $cronid If not 0, it's the cron ID to be updated
	 *
	 * @return int  New cron ID or updated Cron's ID
	 */
	public function save($data, $cronid = 0)
	{
		$this->checkHasAdminPermission('canadmincron');

		$cronid = intval($cronid);
		$vb5_config = vB::getConfig();
		$userinfo = vB::getDatastore()->get_value('userinfo');

		if (empty($cronid))
		{
			if (empty($data['varname']))
			{
				throw new vB_Exception_Api('please_complete_required_fields');
			}

			if (!preg_match('#^[a-z0-9_]+$#i', $data['varname'])) // match a-z, A-Z, 0-9, _ only
			{
				throw new vB_Exception_Api('invalid_phrase_varname');
			}

			if (vB::getDbAssertor()->getRow('cron', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
					'varname' => $data['varname'],
				)))
			{
				throw new vB_Exception_Api('there_is_already_option_named_x', array($data['varname']));
			}

			if (empty($data['title']))
			{
				throw new vB_Exception_Api('please_complete_required_fields');
			}
		}
		else
		{
			$cron = vB::getDbAssertor()->getRow('cron', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'cronid' => $cronid,
			));
			if (!$cron)
			{
				throw new vB_Exception_Api('invalid_option_specified');
			}

			if ((!$cron['volatile'] OR $vb5_config['Misc']['debug']) AND empty($data['title']))
			{
				// custom entry or in debug mode means the title is editable
				throw new vB_Exception_Api('please_complete_required_fields');
			}

			$data['varname'] = $cron['varname'];
		}

		if ($data['filename'] == '' OR $data['filename'] == './includes/cron/.php')
		{
			throw new vB_Exception_Api('invalid_filename_specified');
		}

		$data['weekday']	= str_replace('*', '-1', $data['weekday']);
		$data['day']		= str_replace('*', '-1', $data['day']);
		$data['hour']		= str_replace('*', '-1', $data['hour']);

		// need to deal with minute properly :)
		sort($data['minute'], SORT_NUMERIC);
		$newminute = array();
		foreach ($data['minute'] AS $time)
		{
			$newminute["$time"] = true;
		}

		unset($newminute["-2"]); // this is the "-" (don't run) entry

		if ($newminute["-1"])
		{ // its run every minute so lets just ignore every other entry
			$newminute = array(0 => -1);
		}
		else
		{
			// $newminute's keys are the values of the GPC variable, so get the values back
			$newminute = array_keys($newminute);
		}

		if (empty($cronid))
		{
			/*insert query*/
			$cronid = vB::getDbAssertor()->assertQuery('cron', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERT,
				'varname' => trim($data['varname']),
			));

			if (!empty($cronid['errors']))
			{
				throw new vB_Exception_Api('invalid_data');
			}
		}
		else
		{
			// updating an entry. If we're changing the volatile status, we
			// need to remove the entries in the opposite language id.
			// Only possible in debug mode.
			if ($data['volatile'] != $cron['volatile'])
			{
				$old_languageid = ($cron['volatile'] ? -1 : 0);
				vB::getDbAssertor()->assertQuery('phrase', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
					'languageid' => $old_languageid,
					'fieldname' => 'cron',
					'varname' => array('task_$cron[varname]_title', 'task_$cron[varname]_desc', 'task_$cron[varname]_log'),
				));
			}
		}

		$escaped_product = $data['product'];

		// update
		$result = vB::getDbAssertor()->assertQuery('cron', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'loglevel' => intval($data['loglevel']),
			'weekday' => intval($data['weekday']),
			'day' => intval($data['day']),
			'hour' => intval($data['hour']),
			'minute' => serialize($newminute),
			'filename' => $data['filename'],
			'active' => $data['active'],
			'volatile' => $data['volatile'],
			'product' => $data['product'],
			vB_dB_Query::CONDITIONS_KEY => array(
				'cronid' => $cronid,
			)
		));

		if (!empty($result['errors']))
		{
			throw new vB_Exception_Api('invalid_data');
		}

		$new_languageid = ($data['volatile'] ? -1 : 0);

		require_once(DIR . '/includes/adminfunctions.php');
		$full_product_info = fetch_product_list(true);
		$product_version = $full_product_info["$escaped_product"]['version'];

		if (!$data['volatile'] OR $vb5_config['Misc']['debug'])
		{
			/*insert_query*/
			$result = vB::getDbAssertor()->assertQuery('cron_insertphrases', array(
				'new_languageid' => $new_languageid,
				'varname' => $data['varname'],
				'product' => $data['product'],
				'username' => $userinfo['username'],
				'timenow' => vB::getRequest()->getTimeNow(),
				'product_version' => $product_version,
				'title' => trim($data['title']),
				'description' => trim($data['description']),
				'logphrase' => trim($data['logphrase']),
			));

			if (!empty($result['errors']))
			{
				throw new vB_Exception_Api('invalid_data');
			}

			require_once(DIR . '/includes/adminfunctions_language.php');
			build_language();
		}

		require_once(DIR . '/includes/functions_cron.php');
		build_cron_item($cronid);
		build_cron_next_run();

		return $cronid;
	}

	/**
	 * Update enable status of crons
	 *
	 * @param array $crons An array with cronid as key and status as value
	 *
	 * @return standard success array
	 */
	public function updateEnabled($crons)
	{
		$this->checkHasAdminPermission('canadmincron');

		$updates = array();

		$crons_result = vB::getDbAssertor()->getRows('cron', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT));
		foreach ($crons_result as $cron)
		{
			if (isset($crons["$cron[cronid]"]))
			{
				$old = $cron['active'] ? 1 : 0;
				$new = $crons["$cron[cronid]"] ? 1 : 0;

				if ($old != $new)
				{
					$updates["$cron[varname]"] = $new;
				}
			}
		}

		if (!empty($updates))
		{
			vB::getDbAssertor()->assertQuery('updateCronEnabled', array(
				'updates' => $updates,
			));
		}

		return array('success' => true);
	}

	/**
	 * Delete a cron
	 *
	 * @param int $cronid Cron ID to be deleted
	 *
	 * @return standard success array
	 */
	public function delete($cronid)
	{
		$this->checkHasAdminPermission('canadmincron');

		$cronid = intval($cronid);

		$cron = vB::getDbAssertor()->getRow('cron', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'cronid' => $cronid,
		));

		// delete phrases
		vB::getDbAssertor()->assertQuery('phrase', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'fieldname' => 'cron',
			'varname' => array('task_{$escaped_varname}_title', 'task_{$escaped_varname}_desc', 'task_{$escaped_varname}_log'),
		));

		vB::getDbAssertor()->assertQuery('cron', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'cronid' => $cronid,
		));

		require_once(DIR . '/includes/adminfunctions_language.php');
		build_language();

		return array('success' => true);
	}

	/**
	 * Toggle the enable/disable status of a cron
	 *
	 * @param int $cronid Cron ID
	 *
	 * @return void
	 */
	public function switchActive($cronid)
	{
		$this->checkHasAdminPermission('canadmincron');

		$cronid = intval($cronid);

		$cron = vB::getDbAssertor()->getRow('cron_fetchswitch', array(
			'cronid' => $cronid
		));

		if (!$cron)
		{
			throw new vB_Exception_Api('invalidid', array('cronid'));
		}
		else if (!$cron['product_active'])
		{
			throw new vB_Exception_Api('task_not_enabled_product_x_disabled', array(htmlspecialchars_uni($cron['product_title'])));
		}

		vB::getDbAssertor()->assertQuery('cron_switchactive', array(
			'cronid' => $cronid
		));

		require_once(DIR . '/includes/functions_cron.php');
		build_cron_item($cronid);
		build_cron_next_run();

	}

	/**
	 * Fetch cron log
	 *
	 * @param  string  Show Only Entries Generated By the cron with this varname. '0' means show all crons' log.
	 * @param  string  Cron log show order
	 * @param  int     Page of the cron log list
	 * @param  int     Number of entries to show per page
	 *
	 * @return array  Cron log information
	 */
	public function fetchLog($varname = '', $orderby = '', $page = 1, $perpage = 15)
	{
		$this->checkHasAdminPermission('canadmincron');

		if (empty($perpage))
		{
			$perpage = 15;
		}

		$total = vB::getDbAssertor()->getField('fetchCronLogCount', array(
			'varname' => $varname,
		));

		$totalpages = ceil($total / $perpage);

		$logs = vB::getDbAssertor()->getRows('fetchCronLog', array(
			'varname' => $varname,
			'orderby' => $orderby,
			vB_dB_Query::PARAM_LIMITPAGE => $page,
			vB_dB_Query::PARAM_LIMIT => $perpage,
		));

		return array(
			'logs' => $logs,
			'total' => $total,
		);
	}

	/**
	 * Prune Cron
	 *
	 * @param  string Remove Entries Relating to Action.
	 * @param  int    Remove Entries Older Than (Days)
	 *
	 * @return void
	 */
	public function pruneLog($varname = '', $daysprune = 30)
	{
		$this->checkHasAdminPermission('canadmincron');

		$datecut = vB::getRequest()->getTimeNow() - (86400 * $daysprune);

		vB::getDbAssertor()->assertQuery('pruneCronLog', array(
			'varname' => trim($varname),
			'datecut' => $datecut,
		));
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 100641 $
|| #######################################################################
\*=========================================================================*/
