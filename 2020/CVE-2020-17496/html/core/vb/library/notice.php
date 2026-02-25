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
 * vB_Library_Options
 *
 * @package vBLibrary
 * @access public
 */
class vB_Library_Notice extends vB_Library
{
	private $validNoticeOptions = array(
		'allowhtml',
		'allowbbcode',
		'allowsmilies',
		'parseurl',
	);

	public function getNotice($noticeid)
	{
		$db = vB::getDbAssertor();
		$datastore = vB::getDatastore();

		$row = $db->getRow('vBForum:notice', array('noticeid' => $noticeid));
		if($row)
		{
			$row['noticeoptions'] = $this->optionsToArray($datastore, $row['noticeoptions']);
			$row['notice_phrase_varname'] = "notice_{$noticeid}_html";
		}

		$row['criteria'] = array();

		$criteria_result = $db->getRows('vBForum:noticecriteria', array('noticeid' => $noticeid));
		foreach ($criteria_result AS $criterion)
		{
			//let's be consistent between how we consume the notice data and how we
			//produce it and not put the criteriaid in the array with the conditions.
			$criteriaid = $criterion['criteriaid'];
			unset($criterion['criteriaid']);
			$row['criteria'][$criteriaid] = $criterion;
		}

		return $row;
	}

	/**
	 *	Delete notices
	 *
	 *	@param int|array $noticeid
	 *	@return array -- standard success array
	 */
	public function delete($noticeid)
	{
		//if this is an empty value treat it as a request to delete nothing
		//which is already successful.
		if(!$noticeid)
		{
			return array ('success' => true);
		}

		if(!is_array($noticeid))
		{
			$noticeid = array($noticeid);
		}

		$noticeids = array_map('intval', $noticeid);

		$db = vB::getDbAssertor();

		// delete criteria
		$db->delete('vBForum:noticecriteria', array('noticeid' => $noticeids));

		// delete dismisses
		$db->delete('vBForum:noticedismissed', array('noticeid' => $noticeids));

		// delete notice
		$db->delete('vBForum:notice', array('noticeid' => $noticeids));

		// delete phrases
		$phrases = array();
		foreach($noticeids AS $noticeid)
		{
			$phrases[] = 'notice_' . $noticeid . '_html';
		}

		// we should look into using the phrase API for this
		$db->delete('vBForum:phrase', array('varname' => $phrases));

		// update the datastore notice cache
		$this->buildNoticeDatastore();

		// rebuild languages
		require_once(DIR . '/includes/adminfunctions_language.php');
		build_language(-1);

		return true;

	}

	/**
	 *	Save a notice
	 *
	 *	@param array $data
	 *		int noticeid (optional) -- if given update the notice otherwise save a new one.
	 *		string title
	 *		int displayorder
	 *		boolean active
	 *		boolean persistent
	 *		boolean dismissible
	 *		array criteria -- criteriaid => array(
	 *			string $condition1
	 *			string $condition2
	 *			string $condition3
	 *		)
	 *	@return array -- standard success array
	 */
	public function save($data)
	{
		$noticeid = $this->saveNoticeInfo(
			$data['noticeid'] ?? null,
			$data['title'],
			$data['displayorder'],
			$data['active'],
			$data['persistent'],
			$data['dismissible'],
			$data['noticeoptions'],
			$data['criteria']
		);
		$this->saveNoticePhrase($noticeid, $data['text'], $username, $templateversion);

		// update the datastore notice cache
		$this->buildNoticeDatastore();

		return $noticeid;
	}

	private function saveNoticeInfo (
		$noticeid,
		$title,
		$displayorder,
		$active,
		$persistent,
		$dismissible,
		$noticeoptions,
		$criteria_array
	)
	{
		if(is_null($title) OR $title === '')
		{
			throw new vB_Exception_Api('invalid_title_specified');
		}

		//for backwards compatibilty we want to ensure that the allowhtml flag defaults to true
		$noticeoptions['allowhtml'] = $noticeoptions['allowhtml'] ?? true;
		$db = vB::getDbAssertor();
		$data =	array(
			'title'          => $title,
			'displayorder'   => $displayorder,
			'active'         => $active,
			'persistent'     => $persistent,
			'dismissible'    => $dismissible,
			'noticeoptions'  => $this->arrayToOptions(vB::getDatastore(), $noticeoptions),
		);

		// we are editing
		if ($noticeid)
		{
			// update notice record

			$db->update('vBForum:notice', $data, array('noticeid' => $noticeid));

			// delete criteria
			$db->delete('vBForum:noticecriteria', array('noticeid' => $noticeid));

			// removing old dismissals
			if (!$dismissible)
			{
				$db->delete('vBForum:noticedismissed', array('noticeid' => $noticeid));
			}
		}
		// we are adding a new notice
		else
		{
			// insert notice record
			$noticeid = $db->insert('vBForum:notice', $data);
		}

		// Check to see if there is criteria to insert
		if ($criteria_array)
		{
			// assemble criteria insertion query
			$criteria_sql = array();
			foreach ($criteria_array AS $criteriaid => $criterion)
			{
				$criteria_sql[] = array(
					'noticeid' => $noticeid,
					'criteriaid' => $criteriaid,
					'condition1' => trim($criterion['condition1']),
					'condition2' => trim($criterion['condition2']),
					'condition3' => trim($criterion['condition3'])
				);
			}

			// insert criteria
			$db->insertMultiple('vBForum:noticecriteria',
				array('noticeid', 'criteriaid', 'condition1', 'condition2', 'condition3'),
				$criteria_sql
			);
		}

		return $noticeid;
	}

	//should look at calling the phrase library for this
	private function saveNoticePhrase($noticeid, $text)
	{
		$db = vB::getDbAssertor();

		//in some instances -- particularly the install/upgrade we might to have
		//a username set.  It's not that important so we'll just enter something
		//instead of risking an error/warning.
		$userInfo = vB_User::fetchUserinfo();
		$username = $userInfo['username'] ?? 'System';

		$options = vB::getDatastore()->getValue('options');
		$db->assertQuery('replaceIntoPhrases', array(
			'languageid' => 0,
			'varname'    => 'notice_' . $noticeid . '_html',
			'text'       => $text,
			'product'    => 'vbulletin',
			'fieldname'  => 'global',
			'enteredBy'  => $username,
			'dateline'   => vB::getRequest()->getTimeNow(),
			'version'    => $options['templateversion']
		));

		// rebuild languages
		require_once(DIR . '/includes/adminfunctions_language.php');
		build_language(-1);
	}

	public function buildNoticeDatastore()
	{
		$result = vB::getDbAssertor()->assertQuery('vBForum:fetchnoticecachevalues');

		$notice_cache = array();
		foreach($result AS $noticecriteria)
		{
			$noticeid = $noticecriteria['noticeid'];
			if (!isset($notice_cache[$noticeid]))
			{
				$notice_cache[$noticeid]['persistent'] = $noticecriteria['persistent'];
				$notice_cache[$noticeid]['dismissible'] = $noticecriteria['dismissible'];
				$notice_cache[$noticeid]['noticeoptions'] = $noticecriteria['noticeoptions'];
			}

			if ($noticecriteria['criteriaid'])
			{
				foreach (array('condition1', 'condition2', 'condition3') AS $condition)
				{
					$notice_cache[$noticeid][$noticecriteria['criteriaid']][] = $noticecriteria[$condition];
				}
			}
		}

		vB::getDatastore()->build('noticecache', serialize($notice_cache), 1);
		return $notice_cache;
	}

	public function getNoticeCache()
	{
		$datastore = vB::getDatastore();
		$cache = $datastore->getValue('noticecache');

		//something went wrong, try to rebuild it.
		if(!is_array($cache))
		{
			$cache = $this->buildNoticeDatastore();
		}

		//expand the options to an array
		foreach($cache AS $key => $value)
		{
			$cache[$key]['noticeoptions'] = $this->optionsToArray($datastore, $value['noticeoptions']);
		}

		return $cache;
	}

	//use the annoucement options bitfields instead of creating new ones
	//we're moving the functionality over to here and may rename at a later date
	//unfortunatly there are similarly named/used "forum" options that have different
	//bit values.
	private function optionsToArray($datastore, $options)
	{
		//let's only grab the values that we have defined for the options array
		//not just assume that any bitfields are valid.
		$bitfields = $datastore->getValue('bf_misc_announcementoptions');

		$return = array();
		foreach($this->validNoticeOptions AS $key)
		{
			$return[$key] = (bool) ($options & $bitfields[$key]);
		}

		return $return;
	}

	private function arrayToOptions($datastore, $options)
	{
		$bitfields = $datastore->getValue('bf_misc_announcementoptions');
		$return = 0;

		//this depends on the option keys matching the bitfield names.
		//we're isolating that assumtion to this function.
		foreach($this->validNoticeOptions AS $key)
		{
			if (!empty($options[$key]))
			{
				$return |= $bitfields[$key];
			}
		}

		return $return;
	}
}
/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 100688 $
|| #######################################################################
\*=========================================================================*/
