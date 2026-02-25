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
 * vB_Library_Page
 *
 * @package vBLibrary
 * @access public
 */
class vB_Library_Eventhighlight extends vB_Library
{
	/**
	 * Database assertor
	 */
	protected $assertor = null;

	/**
	 * Constructor
	 */
	public function __construct()
	{
		$this->assertor = vB::getDbAssertor();
	}

	/**
	 * Returns the specified event highlight for administration purposes.
	 *
	 * @param  int   Event highlight ID
	 * @param  bool  (optional) If true, add the permissions information
	 *
	 * @return array Event highlight information
	 */
	public function getEventHighlightAdmin($eventhighlightid, $withPermissions = false)
	{
		return $this->getEventHighlightInternal($eventhighlightid, $withPermissions);
	}

	/**
	 * Returns the full listing of event highlights for administration purposes.
	 *
	 * @param  array (optional) Array of eventhighlightids, if empty, all event highlights are returned
	 * @param  bool  (optional) If true, add the permissions information
	 *
	 * @return array Full listing of event highlights
	 */
	public function getEventHighlightsAdmin($eventhighlightids = array(), $withPermissions = false)
	{
		return $this->getEventHighlightsInternal($eventhighlightids, $withPermissions);
	}

	/**
	 * Returns the listing of event highlights for the currently logged in user
	 *
	 * @return array Listing of available event highlights
	 */
	public function getEventHighlightsUser()
	{
		$raweventhighlights = $this->getEventHighlightsInternal(array(), true, true);

		// apply permissions
		$return = array();
		foreach ($raweventhighlights AS $eventhighlight)
		{
			if ($eventhighlight['currentuserhaspermission'])
			{
				$return[] = $eventhighlight;
			}
		}

		return $return;
	}

	/**
	 * Returns the view information to display all event highlights
	 *
	 * @return array View information for all event highlights (permissions only affect being able to apply an event highlight to a node)
	 */
	public function getEventHighlightViewInfo()
	{
		$eventhighlights = $this->getEventHighlightsInternal(array(), false, false, true, true);

		// only return the information needed for display
		$return = array();
		foreach ($eventhighlights AS $eventhighlight)
		{
			$return[$eventhighlight['eventhighlightid']] = array(
				'backgroundcolor' => $eventhighlight['backgroundcolor'],
				'textcolor' => $eventhighlight['textcolor'],
			);
		}

		return $return;
	}

	/**
	 * Returns the specified event highlight without regard for currently
	 * logged in user or currently selected display language.
	 *
	 * @param  int   Event highlight ID
	 * @param  bool  (optional) If true, add the permissions information
	 *
	 * @return array Event highlight information
	 */
	protected function getEventHighlightInternal($eventhighlightid, $withPermissions = false)
	{
		$eventhighlights = $this->getEventHighlightsInternal(array($eventhighlightid), $withPermissions);
		$eventhighlight = array_pop($eventhighlights);

		return $eventhighlight;
	}

	/**
	 * Returns all event highlights without regard for currently
	 * logged in user or currently selected display language.
	 *
	 * @param  array (optional) Array of eventhighlightids, if empty, all event highlights are returned
	 * @param  bool  (optional) If true, add the permissions information
	 * @param  bool  (optional) If true, use the currently logged in user's preferred language
	 * @param  bool  (optional) Skip names if true
	 * @param  bool  (optional) Skip sort if true
	 *
	 * @return array Array of event highlight information
	 */
	protected function getEventHighlightsInternal($eventhighlightids = array(), $withPermissions = false, $usePreferredLanguage = false, $skipNames = false, $skipSort = false)
	{
		$conditions = array();
		if (!empty($eventhighlightids))
		{
			$addids = array();
			foreach ($eventhighlightids AS $eventhighlightid)
			{
				$eventhighlightid = (int) $eventhighlightid;
				if ($eventhighlightid > 0)
				{
					$addids[] = $eventhighlightid;
				}
			}
			if (!empty($addids))
			{
				$conditions['eventhighlightid'] = $addids;
			}
		}

		$eventhighlights = $this->assertor->getRows('vBForum:eventhighlight', $conditions, array('displayorder'));

		if ($withPermissions)
		{
			// add permissions
			$eventhighlights = $this->addPermissions($eventhighlights);
		}

		// add names
		if (!$skipNames)
		{
			$languageid = 0;
			if ($usePreferredLanguage)
			{
				$userinfo = vB::getCurrentSession()->fetch_userinfo();
				$languageid = (int) $userinfo['languageid'];

				if (!$languageid)
				{
					$options = vB::getDatastore()->getValue('options');
					$languageid = (int) $options['languageid'];
				}
			}
			$eventhighlights = $this->addNames($eventhighlights, $languageid);
		}

		// order by name as a secondary/fallback ordering after displayorder
		if (!$skipSort)
		{
			usort($eventhighlights, function($a, $b)
			{
				if ($a['displayorder'] == $b['displayorder'])
				{
					return strnatcasecmp($a['name'], $b['name']);
				}
				else
				{
					// keep the original 'displayorder' ordering
					return $a['displayorder'] < $b['displayorder'] ? -1 : ($a['displayorder'] > $b['displayorder'] ? 1 : 0);
				}
			});
		}

		return $eventhighlights;
	}

	/**
	 * Adds the event highlight name to the passed event highlight info array
	 * based on the passed language id.
	 *
	 * @param  array Event highlight info array
	 * @param  int   (optional) language id
	 *
	 * @return array Event highlight array with 'name' added.
	 */
	protected function addName($eventhighlight, $languageid = 0)
	{
		$varname = $this->getNameVarname($eventhighlight['eventhighlightid']);
		$phraseResult = $this->assertor->getRow('phrase', array(
			'varname' => $varname,
			'fieldname' => 'global',
			'languageid' => $languageid,
		));
		if (!empty($phraseResult['text']))
		{
			$eventhighlight['name'] = $phraseResult['text'];
		}
		else
		{
			$eventhighlight['name'] = '~~' . $varname . '~~';
		}

		return $eventhighlight;
	}

	/**
	 * Adds the event highlight name to all the events the passed event array
	 * based on the passed language id.
	 *
	 * @param  array Array of event highlights
	 * @param  int   (optional) language id
	 *
	 * @return array Array of event highlights, each with 'name' added.
	 */
	protected function addNames($eventhighlights, $languageid = 0)
	{
		$varnames = array();

		foreach ($eventhighlights AS $eventhighlight)
		{
			$varnames[] = $this->getNameVarname($eventhighlight['eventhighlightid']);
		}

		// if $languageid is not 0, we'll have to pull it and 0, and use the best one.
		// (essentially use 0 if the phrase is not defined in the other one)
		if ($languageid > 0)
		{
			$languageid = array(0, $languageid);
		}

		$conditions = array(
			'varname' => $varnames,
			'fieldname' => 'global',
			'languageid' => $languageid,
		);
		$phraseResult = $this->assertor->getRows('phrase', $conditions, 'languageid');
		$phrases = array();
		foreach ($phraseResult AS $phrase)
		{
			// since $phraseResult is ordered by languageid, the preferred language
			// will come last and will overwrite the default/fallback language (languageid=0)
			$phrases[$phrase['varname']] = $phrase['text'];
		}

		foreach ($eventhighlights AS $k => $v)
		{
			$varname = $this->getNameVarname($v['eventhighlightid']);
			if (!empty($phrases[$varname]))
			{
				$eventhighlights[$k]['name'] = $phrases[$varname];
			}
			else
			{
				$eventhighlights[$k]['name'] = '~~' . $varname . '~~';
			}

		}

		return $eventhighlights;
	}

	/**
	 * Adds event highlight permissions to all the events in the passed event array
	 *
	 * @param  array Array of event highlights
	 *
	 * @return array Array of event highlights, each with the 'permissions' element added.
	 */
	protected function addPermissions($eventhighlights)
	{
		$eventhighlightids = array();
		foreach ($eventhighlights AS $k => $v)
		{
			$eventhighlightids[] = $v['eventhighlightid'];
		}

		$userinfo = vB::getCurrentSession()->fetch_userinfo();
		$membergroupids = fetch_membergroupids_array($userinfo);

		$denied = $this->assertor->getRows('vBForum:eventhighlightpermission', array('eventhighlightid' => $eventhighlightids));

		foreach ($eventhighlights AS $k => $eventhighlight)
		{
			$eventhighlightid = $eventhighlight['eventhighlightid'];
			$eventhighlights[$k]['deniedusergroups'] = array();
			$eventhighlights[$k]['currentuserhaspermission'] = true;

			foreach ($denied AS $k2 => $deny)
			{
				if ($deny['eventhighlightid'] == $eventhighlightid)
				{
					$eventhighlights[$k]['deniedusergroups'][$deny['usergroupid']] = $deny['usergroupid'];
				}
			}

			foreach ($membergroupids AS $membergroupid)
			{
				if (!empty($eventhighlights[$k]['deniedusergroups'][$membergroupid]))
				{
					$eventhighlights[$k]['currentuserhaspermission'] = false;
					break;
				}
			}
		}

		return $eventhighlights;
	}

	/**
	 * Saves (creates or updates) an event highlight
	 *
	 * @param  array Event highlight information
	 *
	 * @return array Event highlight information
	 */
	public function saveEventHighlight($data)
	{
		$eventhighlightid = (int) ($data['eventhighlightid'] ?? 0);

		// load existing data
		if ($eventhighlightid)
		{
			$existing = $this->getEventHighlightInternal($eventhighlightid);
			$queryData = array(
				'backgroundcolor' => $existing['backgroundcolor'],
				'textcolor' => $existing['textcolor'],
				'displayorder' => $existing['displayorder'],
			);
			$queryName = $existing['name'];
		}
		else
		{
			$existing = array();
			$queryData = array(
				'backgroundcolor' => '',
				'textcolor' => '',
				'displayorder' => 0,
			);
			$queryName = '';
		}

		// overwrite existing data with new data, if present
		if (!empty($data['backgroundcolor']))
		{
			$queryData['backgroundcolor'] = (string) $data['backgroundcolor'];
		}
		if (!empty($data['textcolor']))
		{
			$queryData['textcolor'] = (string) $data['textcolor'];
		}
		if (isset($data['displayorder']))
		{
			// used isset() allow setting this to 0.
			$queryData['displayorder'] = (int) $data['displayorder'];
		}
		if (!empty($data['name']))
		{
			$queryName = (string) $data['name'];
		}

		// data consistency checks...

		// require name
		if (empty($queryName))
		{
			throw new vB_Exception_Api('invalid_data');
		}

		// if either background or text color is missing (or both), then
		// use a failsafe/fallback value to ensure it will be readable
		if (empty($queryData['backgroundcolor']) OR empty($queryData['textcolor']))
		{
			$queryData['backgroundcolor'] = '#FFFFFF';
			$queryData['textcolor'] = '#000000';
		}

		// save the main event highlight information
		if ($eventhighlightid)
		{
			$this->assertor->update('vBForum:eventhighlight', $queryData, array('eventhighlightid' => $eventhighlightid));
		}
		else
		{
			$eventhighlightid = $this->assertor->insert('vBForum:eventhighlight', $queryData);
		}

		// add or update phrase for the event highlight name
		if ($eventhighlightid)
		{
			$varname = $this->getNameVarname($eventhighlightid);

			$phraseData = array(
				'oldfieldname' => 'global',
				'oldvarname' => $varname,
				// key the text array by languageid, custom phrases
				// go in languageid = 0.
				'text' => array(
					0 => $queryName,
				),
				'product' => 'vbulletin',
			);

			vB_Library::instance('phrase')->save('global', $varname, $phraseData);
		}

		$this->afterUpdate();

		return array(
			'success' => true,
			'eventhighlightid' => $eventhighlightid,
		);
	}

	/**
	 * Deletes an event highlight
	 *
	 * @param  array Event highlight ID
	 *
	 * @return array Success array
	 */
	public function deleteEventHighlight($eventhighlightid)
	{
		$eventhighlightid = (int) $eventhighlightid;

		if ($eventhighlightid < 1)
		{
			throw new vB_Exception_Api('invalid_data');
		}

		$existing = $this->getEventHighlightInternal($eventhighlightid);

		if (empty($existing))
		{
			throw new vB_Exception_Api('invalid_data');
		}

		$result = $this->assertor->delete('vBForum:eventhighlight', array('eventhighlightid' => $eventhighlightid));
		if ($result)
		{
			// delete permissions
			$this->assertor->delete('vBForum:eventhighlightpermission', array('eventhighlightid' => $eventhighlightid));

			// delete name phrase
			$varname = $this->getNameVarname($eventhighlightid);

			$phraseData = array(
				'oldfieldname' => 'global',
				'oldvarname' => $varname,
				// text array is empty, so it'll delete the existing
				// phrases and not create any new ones
				'text' => array(),
			);

			vB_Library::instance('phrase')->save('global', $varname, $phraseData);

			// remove this event highlight from any events/nodes that were using it
			// if using event library update() proves to be too resource intensive,
			// we could create a streamlined function to only update eventhighlightid.
			$conditions = array('eventhighlightid' => $eventhighlightid);
			$nodeids = $this->assertor->getColumn('vBForum:event', 'nodeid', $conditions);
			$eventLib = vB_Library::instance('content_event');
			foreach ($nodeids AS $nodeid)
			{
				$eventLib->update($nodeid, array('eventhighlightid' => 0));
			}
		}

		$this->afterUpdate();

		return array('success' => $result);
	}

	/**
	 * Saves event highlight display order for multiple event highlights
	 *
	 * @param  array Display order array ('event highlight id' => 'display order')
	 *
	 * @return array Success array
	 */
	public function saveEventHighlightDisplayOrder($displayOrder)
	{
		if (!is_array($displayOrder))
		{
			throw new vB_Exception_Api('invalid_data');
		}

		foreach ($displayOrder AS $eventhighlightid => $newdisplayorder)
		{
			$eventhighlightid = (int) $eventhighlightid;
			$newdisplayorder = (int) $newdisplayorder;

			if ($eventhighlightid > 0)
			{
				$values = array('displayorder' => $newdisplayorder);
				$conditions = array('eventhighlightid' => $eventhighlightid);
				$this->assertor->update('vBForum:eventhighlight', $values, $conditions);
			}
		}

		$this->afterUpdate();

		return array('success' => true);
	}

	/**
	 * Saves event highlight permissions for one event highlight
	 *
	 * @param  int   Event highlight ID
	 * @param  bool  Deny by default (when new user groups are created, deny access to this event highlight)
	 * @param  array Array of usergroups to deny access to this event highlight
	 *
	 * @return array Success array
	 */
	public function saveEventHighlightPermissions($eventhighlightid, $denybydefault, $denyusergroups)
	{
		$eventhighlightid = (int) $eventhighlightid;
		$denybydefault = (bool) $denybydefault;
		$denyusergroups = (array) $denyusergroups;

		if ($eventhighlightid < 1)
		{
			throw new vB_Exception_Api('invalid_data');
		}

		// delete existing perms
		$conditions = array(
			'eventhighlightid' => $eventhighlightid,
		);
		$this->assertor->delete('vBForum:eventhighlightpermission', $conditions);

		// save new perms
		foreach ($denyusergroups AS $denyusergroup)
		{
			$denyusergroup = (int) $denyusergroup;
			$data = array(
				'eventhighlightid' => $eventhighlightid,
				'usergroupid' => $denyusergroup,
			);
			$this->assertor->insert('vBForum:eventhighlightpermission', $data);
		}

		$data = array(
			'denybydefault' => (int) $denybydefault,
		);
		$this->assertor->update('vBForum:eventhighlight', $data, array('eventhighlightid' => $eventhighlightid));

		$this->afterUpdate();

		return array('success' => true);
	}

	/**
	 * Handles any operations, such as cache updates, that need to happen
	 * after any of the event highlight data is updated or added.
	 */
	protected function afterUpdate()
	{
		// rebuild any cache, datastore, etc...
		// We're currently not using the datastore for event highlights,
		// but in the future, we may want to consider doing so.
	}

	/**
	 * Returns the phrase varname for the event highlight name based
	 * on the passed event highlight id.
	 *
	 * @param  int    Event highlight ID
	 *
	 * @return string Phrase varname
	 */
	protected function getNameVarname($eventhighlightid)
	{
		return 'eventhighlight_' . $eventhighlightid . '_name';
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103730 $
|| #######################################################################
\*=========================================================================*/
