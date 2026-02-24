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
 * vB_Api_Widget
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Widget extends vB_Api
{
	const WIDGETCATEGORY_SYSTEM   = 'System';
	const WIDGETCATEGORY_ABSTRACT = 'Abstract';

	// This also includes System modules when not in debug mode
	protected $nonPlaceableWidgetCategories = array('Abstract');

	// Following members are cached data from fetchWidgetInstancesByPageTemplateId()
	protected $preloadWidgetIds = array();
	protected $pagetemplateid = 0;
	protected $sectionnumber = -1; // We use 0 to request all sections

	protected $disableWhiteList = array(
		'fetchConfig',
		'fetchHierarchicalWidgetInstancesByPageTemplateId',
		'fetchSectionsByPageTemplateId',
		'fetchTabbedSubWidgetConfigs',
		'fetchDefaultConfigWithoutInstance',
	);

	protected function __construct()
	{
		parent::__construct();

		// System modules are not placeable when not in debug mode
		$vbconfig = vB::getConfig();
		if (empty($vbconfig['Misc']['debug']))
		{
			$this->nonPlaceableWidgetCategories[] = 'System';
		}
	}

	public function isSystemWidget($widgetId)
	{
		static $systemWidgetIds;

		if (!isset($systemWidgetIds) OR empty($systemWidgetIds))
		{
			$widgets = vB::getDbAssertor()->assertQuery('widget', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::COLUMNS_KEY => array('widgetid'),
				vB_dB_Query::CONDITIONS_KEY => array('category' => self::WIDGETCATEGORY_SYSTEM)
			));

			foreach ($widgets as $widget)
			{
				$systemWidgetIds[] = $widget['widgetid'];
			}
		}

		return in_array($widgetId, $systemWidgetIds);
	}

	/**
	 * Returns the widget configuration schema for the given widget instance.
	 * If no widget instance ID is given, one is created. If no page template ID
	 * is given, one is created (to be able to create the widget instance). If the
	 * widget instance ID is given, the returned config fields will contain the
	 * current values of the configured widget instance for the config type
	 * specified.
	 *
	 * @param	int	The widget ID for this widget instance
	 * @param	int	The widget instance ID that is to be configured (can be zero)
	 * @param	int	The page template ID that this widget instance belongs to (can be zero)
	 * @param	string	Specifies a config type of either "user" or "admin"
	 * @param	int	The user ID to fetch the user config from, if config type is "user" (optional)
	 *
	 * @return 	array	An array containing widgetid, widgetinstanceid, pagetemplateid, and an
	 *			array of config fields to generate the edit configuration form
	 */
	public function fetchConfigSchema($widgetid, $widgetinstanceid = 0, $pagetemplateid = 0, $configtype = 'admin', $userid = 0)
	{
		$this->checkHasAdminPermission('canusesitebuilder');

		$widgetid = intval($widgetid);
		$widgetinstanceid = intval($widgetinstanceid);
		$pagetemplateid = intval($pagetemplateid);
		$configtype = strtolower($configtype);
		$userid = intval($userid);

		if ($widgetid < 1)
		{
			throw new Exception('Invalid widget ID specified: ' . htmlspecialchars($widgetid));
		}

		if (!in_array($configtype, array('user', 'admin'), true))
		{
			throw new Exception('Invalid config type specified: ' . htmlspecialchars($widgetid));
		}

		if ($pagetemplateid < 1)
		{
			$pagetemplateid = $this->_getNewPageTemplateId();
		}

		if ($widgetinstanceid < 1)
		{
			$widgetinstanceid = $this->_getNewWidgetInstanceId($widgetid, $pagetemplateid);
		}


		$configFields = $this->_getWidgetConfigFields($widgetid, $widgetinstanceid, $configtype, $userid);

		return array(
			'widgetid' => $widgetid,
			'widgetinstanceid' => $widgetinstanceid,
			'pagetemplateid' => $pagetemplateid,
			'configs' => $configFields,
		);
	}

	public function saveNewWidgetInstance($containerinstanceid, $widgetid, $pagetemplateid, $subWidgetConfig = array())
	{

		if (empty($widgetid))
		{
			return array('widgetinstanceid' => 0);
		}

		if ($pagetemplateid < 1)
		{
			$pagetemplateid = $this->_getNewPageTemplateId();
		}

		$widgetinstanceid = $this->_getNewWidgetInstanceId($widgetid, $pagetemplateid, $containerinstanceid);


		$origDefault = $subWidgetConfigDefault = $this->fetchDefaultConfigWithoutInstance($widgetid);
		foreach ($subWidgetConfig AS $__key => $__value)
		{
			$subWidgetConfigDefault[$__key] = $__value;
		}

		// TODO: update cleanWidgetConfigData() to better handle random values coming in from above...

		// we can set containerinstanceid as part of $subWidgetConfigDefault as well.
		$this->saveAdminConfig($widgetid, $pagetemplateid, $widgetinstanceid, $subWidgetConfigDefault);


		return array('widgetinstanceid' => $widgetinstanceid, 'pagetemplateid' => $pagetemplateid,);
	}

	public function fetchTabbedSubWidgetConfigs($containerinstanceid, $tabbedContainerSubModules)
	{
		$containerConfig = $this->fetchConfig($containerinstanceid);


		if (empty($containerConfig['tab_data']))
		{
			return array();
		}

		$products = vB::getDatastore()->getValue('products');
		$usergroups = $this->fetchUsergroupsForModuleViewPerms();
		/*
			{tabnum1} => array(
				{arr first widget config},
				{arr second widget config}, ...
			),
			{tabnum2} => array(...), ...
		 */
		$subWidgetData = array();
		foreach($containerConfig['tab_data'] AS $__tabnum => $__tab)
		{
			$subWidgetData[$__tabnum] = array();

			// side note, ajax submit will omit empty arrays/objects in the data - https://bugs.jquery.com/ticket/6481
			// so tab_data[x].widgets might not get saved/set as expected if you never add a widget to it.
			if (!isset($__tab['widgets']))
			{
				// This is a tab without any widgets. Not sure why they would want a tab like this, but
				// set it to an array to avoid php notices at the foreach below.
				$__tab['widgets'] = array();
			}

			foreach ($__tab['widgets'] AS $__widget)
			{
				$__data = array();
				$__data['containerinstanceid'] = $containerinstanceid;
				if (!empty($__widget['widgetinstanceid'])) // this one has been configured via SB
				{
					$__wiid = $__widget['widgetinstanceid'];
					$__data['config'] = $this->fetchConfig($__wiid);


					$__skipModule = $this->doSkipModule($__wiid, $__data['config'], $usergroups);

					if ($__skipModule)
					{
						/*
							Alternatively, we could have it set a field that the templates check instead of skipping
							this module outright here. That would allow us to show a replacement template to indicate
							that it was skipped in the HTML for debug purposes, and/or show a custom replacement
							template that admins can set to indicate to the users that they can sign up for a
							subscription to access the missing content, ETC.
							These can be implemented as future improvements.
						 */
						continue;
					}

					if (!empty($tabbedContainerSubModules[$__wiid]))
					{
						$__data['template'] = $tabbedContainerSubModules[$__wiid]['template'];
						$__data['product'] = $tabbedContainerSubModules[$__wiid]['product'];
						$__data['product_enabled'] = $tabbedContainerSubModules[$__wiid]['product_enabled'];
						$__data['title'] = $tabbedContainerSubModules[$__wiid]['title'];
					}
					else
					{
						// Normally we shouldn't hit this case any more, because we now pass tabbedContainerSubModules
						// down through the screenlayout_widgetlist / widget_tabbedcontainer_x templates.
						// Note that tabbedContainerSubModules are initially set in fetchWidgetInstancesByPageTemplateId()
						$__row = vB::getDbAssertor()->getRow('widget', array('widgetid' => $__widget['widgetid']));
						$this->checkProductStatusSingleWidget($__row, $products);
						$__data['template'] = $__row['template'];
						$__data['product'] = $__row['product'];
						$__data['product_enabled'] = $__row['product_enabled'];
						// todo: this requires a phrase fetch. For now, just set the key so the templates do not
						// throw any undefined index notices.
						$__data['title'] = "";
					}

					// This lets us pull the widgetinstance data when we have nested containers.
					// This is particularly useful for replacing 'template' when the product is disabled.
					if (!empty($tabbedContainerSubModules[$__wiid]['tabbedContainerSubModules']))
					{
						$__data['tabbedContainerSubModules'] = $tabbedContainerSubModules[$__wiid]['tabbedContainerSubModules'];
					}
					else
					{
						$__data['tabbedContainerSubModules'] = array();
					}

				}
				else // This one might be from a fresh install.
				{
					if (isset($__widget['widgetid']))
					{
						$__data['config'] = $this->fetchDefaultConfigWithoutInstance($__widget['widgetid']);
					}
					else if (isset($__widget['guid']))
					{
						$__data['config'] = $this->fetchDefaultConfigWithoutInstance(null, $__widget['guid']);
					}
					else
					{
						continue;
					}

					// template field should be in its own, not under 'config'.
					$__data['template'] = $__data['config']['template'];
					unset($__data['config']['template']);
				}

				$subWidgetData[$__tabnum][] = $__data;
			}
		}


		return $subWidgetData;
	}

	public function fetchConfigAndIsUserEditable($widgetinstanceid = 0, $widgetid = 0, $guid = '', $userid = 0, $channelId = 0, $withTemplate = false)
	{
		$config = array();
		if (!empty($widgetinstanceid))
		{
			$config = $this->fetchConfig($widgetinstanceid, $userid, $channelId);
		}
		elseif (!empty($widgetid) OR !empty($guid))
		{
			$config = $this->fetchDefaultConfigWithoutInstance($widgetid, $guid, $withTemplate);
		}


		$widgetid = $config['widgetid']; // in case we're missing widgetid
		$defs = $this->_getWidgetDefinition($widgetid);
		$isusereditable = array();
		foreach ($defs AS $__key => $__data)
		{
			$isusereditable[$__key] = (bool) $__data['isEditable'];
		}

		return array('config' => $config, 'isusereditable' => $isusereditable);
	}

	/**
	 * Returns the final configuration for a specific widget instance.
	 *
	 * @param	int	The widget instance ID
	 * @param	int	The user ID (optional)
	 *
	 * @return	array	An associative array of the widget config items and their values
	 */
	public function fetchConfig($widgetinstanceid, $userid = 0, $channelId = 0)
	{
		$widgetinstanceid = intval($widgetinstanceid);
		$widgetInstance = $this->_getWidgetInstance($widgetinstanceid); /** the response must include widgetid (VBV-199) **/
		$userid = intval($userid);

		$returnConfig = false;

		if ($userid > 0)
		{
			$userConfig = $this->fetchUserConfig($widgetinstanceid, $userid);
			if ($userConfig !== false)
			{
				$returnConfig = $userConfig;
			}
		}

		if (!$returnConfig AND $channelId > 0)
		{
			$channelConfig = $this->fetchChannelConfig($widgetinstanceid, $channelId);
			if ($channelConfig !== false)
			{
				$returnConfig = $channelConfig;
			}
		}

		if (!$returnConfig)
		{
			$adminConfig = $this->fetchAdminConfig($widgetinstanceid);
			if ($adminConfig !== false)
			{
				$returnConfig = $adminConfig;
			}
		}

		if (!$returnConfig)
		{
			$returnConfig = $this->fetchDefaultConfig($widgetinstanceid);
		}

		// add ids
		$returnConfig['widgetid'] = $widgetInstance['widgetid'];
		$returnConfig['widgetinstanceid'] = $widgetinstanceid;

		// do pre-processing
		$returnConfig = $this->preProcessConfigValues($returnConfig);

		return $returnConfig;
	}

	/**
	 * Pre-compiles a few specific config values for consumption in templates.
	 * This greatly simplifies some of the template logic needed.
	 *
	 * @param array Array of config values
	 *
	 * @return array Array of config values with pre-processed items added.
	 */
	protected function preProcessConfigValues($widgetConfig)
	{
		// precompile the show_at_breakpoints option into CSS classes
		if (isset($widgetConfig['show_at_breakpoints']))
		{
			$widgetConfig['show_at_breakpoints_css_classes'] = '';
			if (isset($widgetConfig['show_at_breakpoints']['desktop']) AND !$widgetConfig['show_at_breakpoints']['desktop'])
			{
				$widgetConfig['show_at_breakpoints_css_classes'] .= ' b-module--hide-desktop';
			}
			if (isset($widgetConfig['show_at_breakpoints']['small']) AND !$widgetConfig['show_at_breakpoints']['small'])
			{
				$widgetConfig['show_at_breakpoints_css_classes'] .= ' b-module--hide-small';
			}
			if (isset($widgetConfig['show_at_breakpoints']['xsmall']) AND !$widgetConfig['show_at_breakpoints']['xsmall'])
			{
				$widgetConfig['show_at_breakpoints_css_classes'] .= ' b-module--hide-xsmall';
			}
		}
		else
		{
			$widgetConfig['show_at_breakpoints_css_classes'] = '';
		}

		// add other pre-compiled values here as necessary...



		return $widgetConfig;
	}

	/**
	 * Returns the final configuration for the search widget instance.
	 *
	 * @param	int	The widget instance ID
	 * @param	int	The user ID (optional)
	 *
	 * @return	array	An associative array of the widget config items and their values
	 */
	public function fetchSearchConfig($widgetinstanceid, $userid = 0, $widgetid = 0)
	{

		$widgetinstanceid = intval($widgetinstanceid);
		$userid = intval($userid);
		$contentTypes = vB_Types::instance()->getSearchableContentTypes();
		$channels = vB_Api::instanceInternal("Search")->getChannels();
		if ($userid > 0 AND !empty($widgetinstanceid))
		{
			$userConfig = $this->fetchUserConfig($widgetinstanceid, $userid);
			if ($userConfig !== false)
			{
				return array_merge($userConfig,array('contentTypes' => $contentTypes, 'channels' => $channels));
			}
		}

		// When a search module's first added to a page, it alcks a widgetinstanceid, unlike non-search modules
		// that automatically generate an instance & get the instanceid assigned.
		// In that case, we should fetch default configs from the widgetid.
		if (empty($widgetinstanceid) AND !empty($widgetid))
		{
			$adminConfig = $this->fetchDefaultConfigWithoutInstance($widgetid, '', false);
		}
		else
		{
			$adminConfig = $this->fetchAdminConfig($widgetinstanceid);
		}

		if ($adminConfig !== false)
		{
			return array_merge($adminConfig, array('contentTypes' => $contentTypes, 'channels' => $channels));
		}

		return array_merge($this->fetchDefaultConfig($widgetinstanceid), array('contentTypes' => $contentTypes, 'channels' => $channels));
	}

	/**
	 * Returns the admin configuration for a specific widget instance.
	 *
	 * @param	int	The widget instance ID
	 *
	 * @return	array|false	An associative array of the widget config items and their values
	 * 				False if there is no admin config for this widget
	 */
	public function fetchAdminConfig($widgetinstanceid)
	{
		$widgetinstanceid = intval($widgetinstanceid);

		$widgetInstance = $this->_getWidgetInstance($widgetinstanceid);
		$adminConfig = unserialize($widgetInstance['adminconfig']);
		return $adminConfig;
	}

	/**
	 * Returns the channel configuration for a specific widget instance.
	 *
	 * @param	int	The widget instance ID
	 * @param	int	The channel ID
	 *
	 * @return	array|false	An associative array of the widget config items and
	 *				their values, or false if there is no channel config
	 *				for this widget and channel.
	 */
	public function fetchChannelConfig($widgetinstanceid, $nodeId)
	{
		$widgetinstanceid = intval($widgetinstanceid);
		$nodeId = intval($nodeId);

		$cache = vB_Cache::instance(vB_Cache::CACHE_FAST);
		$cachekey = 'widgetChannelConfig_' . $this->pagetemplateid . '_' . $this->sectionnumber . '_' . $nodeId;
		$cacheevent = 'widgetChannelConfigChg_' . $this->pagetemplateid . '_' . $this->sectionnumber . '_' . $nodeId;
		$cachedchannelconfig = $cache->read($cachekey);

		// If we have the cache, return it
		if (isset($cachedchannelconfig[$widgetinstanceid][$nodeId]))
		{
			return !empty($cachedchannelconfig[$widgetinstanceid][$nodeId])?$cachedchannelconfig[$widgetinstanceid][$nodeId]:false;
		}

		// If we reach here, we don't have cache.

		// Check if $widgetinstanceid is in $this->preloadWidgetIds
		// If so, we write the cache for all preloadWidgetIds
		if ($this->preloadWidgetIds AND in_array($widgetinstanceid, $this->preloadWidgetIds))
		{
			$result = vB::getDbAssertor()->getRows(
				'widgetchannelconfig',
				array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
					'widgetinstanceid' => $this->preloadWidgetIds,
					'nodeid' => $nodeId,
				)
			);

			$cachedchannelconfig = array();
			foreach ($result as $row)
			{
				$cachedchannelconfig[$row['widgetinstanceid']][$row['nodeid']] = unserialize($row['channelconfig']);
			}
			$cache->write($cachekey, $cachedchannelconfig, false, array($cacheevent));

			if (isset($cachedchannelconfig[$widgetinstanceid][$nodeId]))
			{
				return !empty($cachedchannelconfig[$widgetinstanceid][$nodeId])?$cachedchannelconfig[$widgetinstanceid][$nodeId]:false;
			}
		}

		// If we reach here, it means that $widgetinstaceid isn't included in our cache
		// We do separated query
		$result = vB::getDbAssertor()->assertQuery(
			'widgetchannelconfig',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'widgetinstanceid' => $widgetinstanceid,
				'nodeid' => $nodeId,
			)
		);

		if ($result->valid())
		{
			$channelConfig = $result->current();
			return unserialize($channelConfig['channelconfig']);
		}

		return false;
	}

	/**
	 * Returns the user configuration for a specific widget instance.
	 *
	 * @param	int	The widget instance ID
	 * @param	int	The user ID
	 *
	 * @return	array|false	An associative array of the widget config items and
	 *				their values, or false if there is no user config
	 *				for this widget and user.
	 */
	public function fetchUserConfig($widgetinstanceid, $userid)
	{
		$widgetinstanceid = intval($widgetinstanceid);
		$userid = intval($userid);

		$cache = vB_Cache::instance(vB_Cache::CACHE_FAST);
		$cachekey = 'widgetUserConfig_' . $this->pagetemplateid . '_' . $this->sectionnumber . '_' . $userid;
		$cacheevent = 'widgetUserConfigChg_' . $this->pagetemplateid . '_' . $this->sectionnumber . '_' . $userid;
		$cacheduserconfig = $cache->read($cachekey);

		// If we have the cache, return it
		if (isset($cacheduserconfig[$widgetinstanceid][$userid]))
		{
			return !empty($cacheduserconfig[$widgetinstanceid][$userid])?$cacheduserconfig[$widgetinstanceid][$userid]:false;
		}

		// If we reach here, we don't have cache.

		// Check if $widgetinstanceid is in $this->preloadWidgetIds
		// If so, we write the cache for all preloadWidgetIds
		if ($this->preloadWidgetIds AND in_array($widgetinstanceid, $this->preloadWidgetIds))
		{
			$result = vB::getDbAssertor()->getRows(
				'widgetuserconfig',
				array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
					'widgetinstanceid' => $this->preloadWidgetIds,
					'userid' => $userid,
				)
			);

			$cacheduserconfig = array();
			foreach ($result as $row)
			{
				$cacheduserconfig[$row['widgetinstanceid']][$row['userid']] = unserialize($row['userconfig']);
			}
			$cache->write($cachekey, $cacheduserconfig, false, array($cacheevent));

			if (isset($cacheduserconfig[$widgetinstanceid][$userid]))
			{
				return !empty($cacheduserconfig[$widgetinstanceid][$userid])?$cacheduserconfig[$widgetinstanceid][$userid]:false;
			}
		}

		// If we reach here, it means that $widgetinstaceid isn't included in our cache
		// We do separated query
		$result = vB::getDbAssertor()->assertQuery(
			'widgetuserconfig',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'widgetinstanceid' => $widgetinstanceid,
				'userid' => $userid,
			)
		);

		if ($result->valid())
		{
			$userConfig = $result->current();
			return unserialize($userConfig['userconfig']);
		}

		return false;
	}

	/**
	 * Returns the default configuration for a specific widget instance.
	 *
	 * @param	int	The widget instance ID
	 *
	 * @return	array	An associative array of the widget config items and their values
	 */
	public function fetchDefaultConfig($widgetinstanceid)
	{
		$widgetinstanceid = intval($widgetinstanceid);

		$widgetInstance = $this->_getWidgetInstance($widgetinstanceid);
		$fields = $this->_getWidgetDefinition($widgetInstance['widgetid']);

		$defaultConfig = array(
			'widgetid' => $widgetInstance['widgetid'],
			'widgetinstanceid' => $widgetInstance['widgetinstanceid']
		);

		foreach ($fields as $field)
		{
			/*
			$data = @unserialize($field['defaultvalue']);
			if ($data === false && $data !== 'b:0;')
			{
				$data = $field['defaultvalue'];
			}
			*/
			// no need to unserialize & recheck stuff, this is done in _getWidgetDefinition()
			if (isset($field['defaultvalue']))
			{
				$data = $field['defaultvalue'];
			}
			else
			{
				$data = null;
			}
			$defaultConfig[$field['name']] = $data;
		}

		return $defaultConfig;
	}

	public function fetchDefaultConfigWithoutInstance($widgetid, $guid = '', $withTemplate = true)
	{
		/*
			Keep this, fetchDefaultConfig() & fetchConfig() in sync
		 */
		if (empty($widgetid))
		{
			if (empty($guid))
			{
				throw new vB_Exception_Api('Invalid widget ID');
			}

			$widget = vB::getDbAssertor()->getRow("widget", array('guid' => $guid));
			if (!empty($widget['widgetid']))
			{
				$widgetid = $widget['widgetid'];
			}
			else
			{
				throw new vB_Exception_Api('Invalid widget ID');
			}
		}
		else
		{
			$widget = vB::getDbAssertor()->getRow("widget", array('widgetid' => $widgetid));
			if (empty($widget['widgetid']))
			{
				throw new vB_Exception_Api('Invalid widget ID');
			}
		}

		$fields = $this->_getWidgetDefinition($widgetid);

		$defaultConfig = array(
			'widgetid' => $widgetid,
			'widgetinstanceid' => null,
		);

		foreach ($fields as $field)
		{
			// no need to unserialize & recheck stuff, this is done in _getWidgetDefinition()
			if (isset($field['defaultvalue']))
			{
				$data = $field['defaultvalue'];
			}
			else
			{
				$data = null;
			}
			$defaultConfig[$field['name']] = $data;
		}

		// do pre-processing
		$defaultConfig = $this->preProcessConfigValues($defaultConfig);

		if ($withTemplate)
		{
			$defaultConfig['template'] = $widget['template'];
		}

		return $defaultConfig;
	}


	public function saveWidgetinstanceContainerinstanceid($widgetinstanceid, $containerinstanceid)
	{
		$this->checkHasAdminPermission('canusesitebuilder');

		if (empty($widgetinstanceid))
		{
			return array('result' => 'skipped');
		}

		$options = array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'widgetinstanceid' => $widgetinstanceid,
			'containerinstanceid' => intval($containerinstanceid),
		);

		$result = vB::getDbAssertor()->assertQuery(
			'widgetinstance',
			$options
		);

		return array('result' => $result);
	}

	/**
	 * Saves an admin widget configuration for the given widget instance
	 *
	 * @param	int	The widget ID for this widget instance
	 * @param	int	The page template ID that this widget instance belongs to
	 * @param	int	The widget instance ID that is being configured
	 * @param	array	An associative array of widget configuration data
	 *
	 * @return 	bool	Whether or not the widget configuration was saved.
	 */
	public function saveAdminConfig($widgetid, $pagetemplateid, $widgetinstanceid, $data)
	{
		$this->checkHasAdminPermission('canusesitebuilder');

		$widgetid = intval($widgetid);
		$widgetinstanceid = intval($widgetinstanceid);
		$pagetemplateid = intval($pagetemplateid);

		if ($widgetid < 1 OR $widgetinstanceid < 1)
		{
			return false;
		}

		// WARNING: cleanWidgetConfigData is not fully implemented yet!
		$configData = $this->cleanWidgetConfigData($widgetid, $data, true);

		if (!empty($data['widget_type']) AND $data['widget_type'] == 'video-widget' AND isset($data['url']))
		{
			$videoData = vB_Api::instanceInternal('Content_Video')->getVideoFromUrl($data['url']);
			if (!empty($videoData))
			{
				$configData['embed_data'] = array(
					'provider'	=> $videoData['provider'],
					'code'		=> $videoData['code'],
				);
			}
		}

		$options = array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'widgetinstanceid' => $widgetinstanceid,
			'adminconfig' => serialize($configData),
		);

		// use isset() instead of !empty() to allow setting container to 0 (meaning this is not a submodule).
		if (isset($data['containerinstanceid']) AND is_numeric($data['containerinstanceid']))
		{
			$options['containerinstanceid'] = intval($data['containerinstanceid']);
		}

		$result = vB::getDbAssertor()->assertQuery(
			'widgetinstance',
			$options
		);
		// there is no way to tell from a failed query and
		// a query that didn't change rows (the data was the same

		return array(
			'widgetid' => $widgetid,
			'widgetinstanceid' => $widgetinstanceid,
			'pagetemplateid' => $pagetemplateid,
			'data' => $configData,
		);
	}

	/**
	 * Saves a channel widget configuration for the given widget instance
	 *
	 * @param	int	The widget instance ID that is being configured
	 * @param	int The channel ID that is being configured
	 * @param	array	An associative array of widget configuration data
	 *
	 * @return 	bool	Whether or not the widget configuration was saved.
	 */
	public function saveChannelConfig($widgetinstanceid, $nodeid, $data)
	{
		$blogAPI = vB_Api::instanceInternal('blog');
		$isBlog = $blogAPI->isBlogNode($nodeid);
		// blog owners can change their blog
		if (!$isBlog OR (vB::getCurrentSession()->get('userid') != $blogAPI->fetchOwner($nodeid)))
		{
			$this->checkHasAdminPermission('canusesitebuilder');
		}

		$widgetinstanceid = intval($widgetinstanceid);

		$widgetInstance = vB::getDbAssertor()->getRow('widgetinstance', array('widgetinstanceid' => $widgetinstanceid));

		$widgetid = intval($widgetInstance['widgetid']);

		if ($widgetid < 1 OR $widgetinstanceid < 1)
		{
			return false;
		}

		// WARNING: cleanWidgetConfigData is not fully implemented yet!
		$configData = $this->cleanWidgetConfigData($widgetid, $data, true);

		// @todo --- clean, validate, and sanitize $configData
		$current = vB::getDbAssertor()->getRow('widgetchannelconfig', array('widgetinstanceid' => $widgetinstanceid, 'nodeid' => $nodeid));
		if ($current)
		{
			$config = unserialize($current['channelconfig']);
			foreach($configData AS $key => $value)
			{
				$config[$key] = $value;
			}

			vB::getDbAssertor()->update('widgetchannelconfig',
					array('channelconfig' => serialize($config)),
					array('widgetinstanceid' => $widgetinstanceid, 'nodeid' => $nodeid)
			);
		}
		else
		{
			vB::getDbAssertor()->insert('widgetchannelconfig', array(
				'widgetinstanceid' => $widgetinstanceid,
				'nodeid'	=> $nodeid,
				'channelconfig' => serialize($configData)
			));
		}

		if ($this->preloadWidgetIds)
		{
			// Expires cache if we have preloaded widgets so that fetchChannelConfig will return updated data
			vB_Cache::instance(vB_Cache::CACHE_FAST)->event('widgetChannelConfigChg_' . $this->pagetemplateid . '_' . $this->sectionnumber . '_' . $nodeid);
		}

		return true;
	}

	// @todo
	// TODO: Remember to expires userconfig cache
	//public function saveUserConfig()
	//{}

	/**
	 * Saves the 'default' config for a widget; updates the widgetdefinitions default field
	 * currently only used for customized_copy widgets
	 *
	 * @param	int	widget id
	 * @param	array	config data for the widget
	 *
	 * @return	array
	 */
	public function saveDefaultConfig($widgetid, array $data)
	{
		$this->checkHasAdminPermission('canusesitebuilder');

		$widgetid = intval($widgetid);

		if ($widgetid < 1)
		{
			throw new vB_Exception_Api('Invalid widget ID');
		}


		// @TODO check admin perms


		$widget = $this->fetchWidget($widgetid);

		if ($widget['cloneable'] != '1')
		{
			// this may need to change if we want to use the method for purposes other
			// than manipulating cloned widgets
			throw new vB_Exception_Api('Cannot modify the default configuration for non-cloneable widgets');
		}

		// WARNING: cleanWidgetConfigData is not fully implemented yet!
		$configData = $this->cleanWidgetConfigData($widgetid, $data, false);

		foreach ($configData AS $field => $value)
		{
			$options = array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
				vB_dB_Query::CONDITIONS_KEY => array(
					'widgetid' => $widgetid,
					'name' => $field,
				),
				'defaultvalue' => $value,
			);
			$result = vB::getDbAssertor()->assertQuery('widgetdefinition', $options);
		}
		vB_Cache::instance()->event('widgetDefChg_' . $widgetid);

		return array(
			'widgetid' => $widgetid,
			'data' => $configData,
		);
	}

	private function clean_config_module_viewpermissions($data)
	{
		$cleaned = array("show" => "all");
		if (isset($data['key']))
		{
			if ($data['key'] == "show" OR $data['key'] == "hide")
			{
				$__ids = array();
				if (isset($data['value']))
				{
					foreach ($data['value'] AS $__id)
					{
						$__id = intval($__id);
						$__ids[] = $__id;
					}
				}
				$cleaned = array(
					$data['key'] => $__ids,
				);
				unset($__ids);
			}
		}
		return $cleaned;
	}

	private function clean_config_module_filter_nodes($data)
	{
		$cleaned = array("include" => array("all"));

		if (isset($data['selection_type']))
		{
			switch ($data['selection_type'])
			{
				case 'all':
				case 'current':
					// override any provided array of values with the singular exclusive all|current
					$data['value'] = array($data['selection_type']);
					break;
				case 'custom':
				default:
					// keep the provided array of values (channelids)
					break;

			}
		}

		if (isset($data['key']))
		{
			if ($data['key'] === "include" OR $data['key'] === "exclude")
			{
				// Unset the default 'include'. 'exclude' also here just in case defaults change later.
				unset($cleaned['include'], $clean['exclude']);

				$allowedStrings = array(
					"all" => 1,
					"current" => 1,
				);
				$__ids = array();
				if (isset($data['value']))
				{
					foreach ($data['value'] AS $__id)
					{
						if (isset($allowedStrings[$__id]))
						{
							$__id = (string) $__id;
						}
						else
						{
							$__id = intval($__id);
						}
						$__ids[] = $__id;
					}
				}
				$cleaned[$data['key']] = $__ids;
				unset($__ids);
			}
		}

		if (isset($data['include_children']))
		{
			$cleaned['include_children'] = (bool) $data['include_children'];
		}

		return $cleaned;
	}

	/**
	 * Cleans widget config data
	 *
	 * @param  int   The widget ID for this widget instance
	 * @param  array An associative array of widget configuration data
	 * @param  bool  Whether or not permit arbitrary config data for this widget
	 *
	 * @return array The cleaned widget data
	 */
	protected function cleanWidgetConfigData($widgetid, $data, $allowArbitraryData)
	{
		$configFields = $this->_getWidgetConfigFields($widgetid);
		$configData = array();
		if ($configFields)
		{
			foreach ($configFields AS $configField)
			{
				if (!isset($data[$configField['name']]) AND empty($configField['isRequired']))
				{
					continue;
				}

				$cleaned = null;
				// clean data
				// "validationtype" is:
				// -- force_datatype => Use the vB_Cleaner class
				// -- regex => Validate using a reg exp (not implemented)
				// -- method => Validate using a method in the widget API (not implemented)
				// "validationmethod" is the data needed in order to do
				//    the cleaning using this validation type.
				// -- For "force_datatype" => the TYPE_* constant for vB_Cleaner
				// -- For "regex" => the regular expression (not implemented)
				// -- For "method" => the method name in the widget API (not implemented)
				switch ($configField['validationtype'])
				{
					// validationtype: "force_datatype"
					// validationmethod: Contains the vB_Cleaner "TYPE_*" constant
					case 'force_datatype':
						if (!empty($configField['validationmethod']))
						{
							if (!defined('vB_Cleaner::' . $configField['validationmethod']))
							{
								throw new vB_Exception_Api('Invalid clean type for vB_Cleaner');
							}

							$dataToClean = $data[$configField['name']] ?? null;
							$cleaned = vB::getCleaner()->clean(
								$dataToClean,
								constant('vB_Cleaner::' . $configField['validationmethod']),
								isset($data[$configField['name']])
							);
						}
						else
						{
							// When VBV-14474 is fixed, change this to
							// throw the exception

							// this should throw an exception once all of our
							// config items have a proper validationtype & validationmethod
							//throw new vB_Exception_Api('Empty validation method');
							$cleaned = $data[$configField['name']] ?? null;
						}
						break;

					// validationtype: "regex"
					// validationmethod: Contains the regular expression to run for cleaning
					case 'regex':
						throw new vB_Exception_Api('Not implemented');
						break;

					// validationtype: "method"
					// validationmethod: Contains the method name in the widget API class to run for cleaning
					case 'method':
						// We now have 2 module configs, viewpermissions & filter_nodes.
						// So let's implement the method type. Check if callable, then call it.
						// Any security concerns???
						if (!empty($configField['validationmethod']) AND
							$this->cleaningMethodIsCallable($configField['validationmethod'])
						)
						{
							$validationmethod = (string) $configField['validationmethod'];
							// Some preexisting / internal modules may not have this field.
							// For module_viewpermissions, clean func will set the default
							// to show => all. Likewise, other cleaners should set a default.
							if (!isset($data[$configField['name']]))
							{
								$data[$configField['name']] = array();
							}

							$cleaned = $this->$validationmethod($data[$configField['name']]);
						}
						else
						{
							throw new vB_Exception_Api('Not implemented');
						}
						break;

					default:
						throw new vB_Exception_Api('Invalid validation type');
						break;
				}

				// save cleaned data
				$configData[$configField['name']] = $cleaned;
			}

			$configData['widget_type'] = empty($data['widget_type']) ? '' : $data['widget_type'];
		}
		else
		{
			if ($allowArbitraryData)
			{
				// @todo --- does this need to be cleaned, validated, or sanitized?
				// arbitrary data for this widget
				$configData = $data;
			}
			else
			{
				throw new vB_Exception_Api('This widget does not support arbitrary configuration data');
			}
		}

		return $configData;
	}

	private function cleaningMethodIsCallable($method)
	{
		if (gettype($method) !== "string")
		{
			return false;
		}

		// force cleaner method prefix convention
		if (strpos($method, "clean_") !== 0)
		{
			return false;
		}

		// todo: check extensions' callable.
		if (!is_callable(array($this, $method)))
		{
			return false;
		}

		// Taken from vB_Api, disallow construct/destruct calling, and arbitrary api's.
		$reflection = new ReflectionMethod($this, $method);

		if(
			$reflection->isConstructor() OR
			$reflection->isDestructor() OR
			$reflection->isStatic() OR
			$method == "callNamed"
		)
		{
			return false;
		}


		return true;
	}

	/**
	 * Returns the basic widget data for a widget
	 *
	 * @param	int	Widget ID
	 *
	 * @return	array|false	The array of widget data, or false on failure
	 */
	public function fetchWidget($widgetid)
	{
		$widgets = $this->fetchWidgets(array($widgetid));
		if (is_array($widgets))
		{
			$widgets = array_pop($widgets);
		}
		return $widgets;
	}

	/**
	 * Returns the basic widget data for multiple widgets
	 *
	 * @param array  (optional) Array of integer widget IDs, if you don't specify
	 *               any widget ids, they will all be returned
	 * @param bool   (optional) If true, any widgets that can't be placed
	 *               on a layout by the user will be filtered out. Currently
	 *               filters out System widgets when not in debug mode, and Abstract widgets
	 *
	 * @return array The array of widget data, indexed by widgetid, empty on failure
	 */
	public function fetchWidgets(array $widgetids = array(), $removeNonPlaceableWidgets = false)
	{
		$this->checkHasAdminPermission('canusesitebuilder');

		$widgetids = array_map('intval', $widgetids);
		$widgetids = array_unique($widgetids);

		$conditions = array();
		if (!empty($widgetids))
		{
			$conditions[vB_dB_Query::CONDITIONS_KEY]['widgetid'] = $widgetids;
		}

		// removes System widgets when not in debug mode
		// also removes Abstract widgets
		if ($removeNonPlaceableWidgets)
		{
			$conditions[vB_dB_Query::CONDITIONS_KEY][] = array(
				'field'    => 'category',
				'value'    => $this->nonPlaceableWidgetCategories,
				'operator' => vB_dB_Query::OPERATOR_NE,
			);
		}

		// fetch widgets, indexed by the widgetid VBV-15798
		$widgets = vB::getDbAssertor()->getRows('widget', $conditions, false, 'widgetid');

		// add titles
		$widgets = $this->addWidgetTitles($widgets);
		// Check products
		$this->checkProductStatus($widgets);

		uasort($widgets, array('vB_Api_Widget', 'compareWidgets'));

		return $widgets;
	}

	private function getWidgetTitlePhrases($widgets, $depth = 0)
	{
		// ATM we don't check and unset circular container references. Unlikely to happen
		// unless something went terribly wrong, but let's explicitly set a small recursion limit here.
		if (++$depth > 10)
		{
			return array();
		}

		$phrasestofetch = array();
		foreach ($widgets AS $widget)
		{
			if (!isset($widget['template']))
			{
				continue;
			}

			if (!empty($widget['titlephrase']))
			{
				$phrasestofetch[] = $widget['titlephrase'];
			}
			else
			{
				$phrasestofetch[] = $widget['template'] . '_widgettitle';
			}

			$phrasestofetch[] = strtolower($widget['category']) . '_widgetcat';

			if (!empty($widget['tabbedContainerSubModules']))
			{
				$extra = $this->getWidgetTitlePhrases($widget['tabbedContainerSubModules'], $depth);
				$phrasestofetch = array_merge($phrasestofetch, $extra);
			}
			if (!empty($widget['subModules']))
			{
				$extra = $this->getWidgetTitlePhrases($widget['subModules'], $depth);
				$phrasestofetch = array_merge($phrasestofetch, $extra);
			}
		}

		return array_unique($phrasestofetch);
	}

	private function addTitlesRecursive(&$widgets, $vbphrases, $depth = 0)
	{
		// ATM we don't check and unset circular container references. Unlikely to happen
		// unless something went terribly wrong, but let's explicitly set a small recursion limit here.
		if (++$depth > 10)
		{
			return;
		}

		foreach ($widgets AS &$widget)
		{
			if (!isset($widget['template']))
			{
				continue;
			}

			if (!empty($widget['titlephrase']))
			{
				$phrase = $widget['titlephrase'];
			}
			else
			{
				$phrase = $widget['template'] . '_widgettitle';
			}

			$catphrase = strtolower($widget['category']) . '_widgetcat';

			$widget['title'] = isset($vbphrases[$phrase]) ? $vbphrases[$phrase] : ('~~' . $phrase . '~~');

			//provide a default in case the phrase isn't correctly defined.
			if (isset($vbphrases[$catphrase]))
			{
				$widget['category_title'] = $vbphrases[$catphrase];
			}
			else
			{
				$widget['category_title'] = $widget['category'];
			}

			// handle submodules
			if (!empty($widget['tabbedContainerSubModules']))
			{
				$this->addTitlesRecursive($widget['tabbedContainerSubModules'], $vbphrases, $depth);
			}
			if (!empty($widget['subModules']))
			{
				$this->addTitlesRecursive($widget['subModules'], $vbphrases, $depth);
			}
		}
	}

	/**
	 * Adds the correct (phrased) widget titles to each widget in the array
	 *
	 * @param	array	Array of widgets
	 *
	 * @return	array	The same array of widgets with the title phrases added.
	 */
	protected function addWidgetTitles($widgets)
	{
		$phrasestofetch = $this->getWidgetTitlePhrases($widgets);
		$vbphrases = vB_Api::instanceInternal('phrase')->fetch($phrasestofetch);
		$this->addTitlesRecursive($widgets, $vbphrases);

		return $widgets;
	}

	protected function checkProductStatus(&$widgets, $depth = 0)
	{
		// ATM we don't check and unset circular container references. Unlikely to happen
		// unless something went terribly wrong, but let's explicitly set a recursion limit here.
		if (++$depth > 50)
		{
			return;
		}

		$products = vB::getDatastore()->getValue('products');
		foreach ($widgets AS &$widget)
		{
			$this->checkProductStatusSingleWidget($widget, $products);
			// todo: Also check subModules
			if (!empty($widget['tabbedContainerSubModules']))
			{
				$this->checkProductStatus($widget['tabbedContainerSubModules'], $depth);
			}
		}
	}

	private function checkProductStatusSingleWidget(&$widget, $products)
	{
		$defaultDisabledWidgetTemplate = "widget_product_disabled";
		$widget['product_enabled'] = true;
		if ($widget['product'] !== 'vbulletin')
		{
			if (empty($products[$widget['product']]))
			{
				$widget['product_enabled'] = false;
				if (isset($widget['template']))
				{
					$widget['template'] = $defaultDisabledWidgetTemplate;
				}
			}
		}
	}

	protected static function compareWidgets($widget1, $widget2)
	{
		return strcmp($widget1['title'], $widget2['title']);
	}

	/**
	 * Returns  multiple widget instances
	 *
	 * @param	array		Array of integer widget instance IDs
	 *
	 * @return	array		The array of widget instance data, indexed by widgetinstanceid, empty on failure
	 */
	public function fetchWidgetInstances(array $widgetInstanceIds)
	{
		$widgetInstanceIds = array_map('intval', $widgetInstanceIds);
		$widgetInstanceIds = array_unique($widgetInstanceIds);

		if (!empty($widgetInstanceIds))
		{
			$conditions = array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::CONDITIONS_KEY => array(array(
					'field' => 'widgetinstanceid',
					'value' => $widgetInstanceIds,
				)),
			);
			$sortOrder = false;
			// fetch array of widget instances, indexed by widgetinstanceid (VBV-13569)
			$widgetInstances = vB::getDbAssertor()->getRows('widgetinstance', $conditions, $sortOrder, 'widgetinstanceid');
			foreach ($widgetInstances AS $widgetInstance)
			{
				vB_Cache::instance(vB_Cache::CACHE_FAST)->write('widgetInstance_' . $widgetInstance['widgetinstanceid'], $widgetInstance, false, array('widgetInstanceChg_' . $widgetInstance['widgetinstanceid']));
			}
		}
		else
		{
			$widgetInstances = array();
		}

		return $widgetInstances;
	}

	private function fetchUsergroupsForModuleViewPerms($userid = null)
	{
		if (is_null($userid))
		{
			$userid = intval(vB::getCurrentSession()->get('userid'));
		}

		$assertor = vB::getDbAssertor();

		if (!empty($userid))
		{
			/*
				vB_Library_User::fetchUserGroups() may or may not return secondary groups
				depending on allowmembergroups. It's not supposed to check allowmembergroups,
				but the cached values it returns most of the time comes from
				vB_User::fetchUserinfo(), which does check that option.

				For this function, we *do* want to check it since it's closely related to permissions.
			 */
			//$usergroups = vB_Library::instance("user")->fetchUserGroups($userid);
			$userInfo = vB_User::fetchUserinfo($userid);
			// Taken & converted from vB_Library_User::fetchUserGroups()
			$primary_group_id = intval($userInfo['usergroupid']);

			$secondary_group_ids = array();
			if (!empty($userInfo['membergroupids']))
			{
				// Unless vB_User::fetchUserinfo() changes, this will be a comma-delimited string of ints.
				// Old code suggests there may or may not have been spaces in between, though currently inserted
				// values do not seem to have any spaces.
				if (is_string($userInfo['membergroupids']))
				{
					$userInfo['membergroupids'] = explode(",", $userInfo['membergroupids']);
				}

				foreach ($userInfo['membergroupids'] AS $__groupid)
				{
					$__groupid = trim($__groupid);
					// ignore nulls, empty strings or other weird values.
					if (is_numeric($__groupid))
					{
						$secondary_group_ids[] = intval($__groupid);
					}
				}
			}

			$infraction_group_ids = array();
			if (!empty($userInfo['infractiongroupids']))
			{
				if (is_string($userInfo['infractiongroupids']))
				{
					$userInfo['infractiongroupids'] = explode(",", $userInfo['infractiongroupids']);
				}

				foreach ($userInfo['infractiongroupids'] AS $__groupid)
				{
					$__groupid = trim($__groupid);
					if (is_numeric($__groupid))
					{
						$infraction_group_ids[] = intval($__groupid);
					}
				}
			}


			$usergroups = array(
				'groupid' => $primary_group_id,
				'secondary' => $secondary_group_ids,
				'infraction' => $infraction_group_ids,
			);

		}
		else
		{
			// Assume it's guest.
			$guestGroup = vB_Api::instance("usergroup")->fetchUsergroupBySystemID(vB_Api_UserGroup::UNREGISTERED_SYSGROUPID);
			$usergroups = array(
				'groupid' => $guestGroup['usergroupid'],
				'secondary' => array(),
				'infraction' => array(),
			);
		}


		/*
			Use infractiongroupid, primary & secondary for both show & hide.
			Presumably, some admin could want to show some kind of penalty-indication module to infracted users,
			which is why we won't limit infractiongropuid to hide logic only.

			Note, the order doesn't really matter for the the way we currently use these.
		 */
		if (!empty($usergroups['infraction']))
		{
			// Taken from vB_PermissionContext::buildBasicPermissions()

			// user.infractiongroupid links to infractiongroup.orusergroupid.
			// See vB_Library_Content_Infraction->fetchInfractionGroups() & buildInfractionGroupIds()
			$groupInfo = $assertor->getRows('infractiongroup', array('orusergroupid' => $usergroups['infraction'] ));
			$groupIds = array();
			foreach ($groupInfo AS $__row)
			{
				$groupIds[] = $__row['orusergroupid'];
			}

			$usergroups['infraction'] = array_unique($groupIds);
		}

		// AFAIK displaygroupid shouldn't affect permissions.

		return $usergroups;
	}

	private function doSkipModule($widgetinstanceid, $widgetInstanceConfig = array(), $usergroups = array())
	{
		if (empty($widgetInstanceConfig))
		{
			$widgetInstanceConfig = $this->fetchConfig($widgetinstanceid, $userid, $channelId);
		}

		if (empty($usergroups))
		{
			$usergroups = $this->fetchUsergroupsForModuleViewPerms();
		}

		$viewPerm = $widgetInstanceConfig['module_viewpermissions'];
		if (isset($viewPerm['show']))
		{
			if ($viewPerm['show'] == 'all')
			{
				$skipModule = false;
			}
			else
			{
				$skipModule = true;
				$showListKeyedById = array();
				foreach ($viewPerm['show'] AS $__usergroupid)
				{
					$showListKeyedById[$__usergroupid] = $__usergroupid;
				}

				/*
					If user has any infractiongroups, ALL must be in the show list for this module to show.
					In addition, at least 1 non-infraction usergroup must be in the show list.

					If user does not have any infractiongroups, then if *any* usergroup (primary or secondary)
					is listed, this module will show.

					Note that this handling of infractiongroups & lack of show vs. hide means that admins cannot
					create modules to show to any infractiongroup (e.g. a simple html module saying "you are
					currently penalized"), or penalize different infractiongroup separately (e.g. group 1 can
					still see some modules, group 2 cannot see any modules). They *can* emulate behavior like
					"hide from ANY infractiongroup" by deselecting all of the infractiongroups, but for more
					complex behavior around infractiongroups, they must create a separate widgetinstance for
					each desired behavior-infractiongroups pairs.
				 */
				if (!empty($usergroups['infraction']))
				{
					$allAccountedFor = true;
					foreach ($usergroups['infraction'] AS $__usergroupid)
					{
						if (!isset($showListKeyedById[$__usergroupid]))
						{
							$allAccountedFor = false;
						}
					}

					// User cannot see this module unless ALL infractiongroups are accounted for in the show list.
					if ($allAccountedFor)
					{
						// TODO: reduce code duplication without degrading readability.
						if (!empty($usergroups['groupid']) AND isset($showListKeyedById[$usergroups['groupid']]))
						{
							$skipModule = false;
						}

						if (!empty($usergroups['secondary']))
						{
							foreach ($usergroups['secondary'] AS $__usergroupid)
							{
								if (isset($showListKeyedById[$__usergroupid]))
								{
									$skipModule = false;
								}
							}
						}
					}
				}
				else
				{
					// users can have 1 primary group while they can have 0 or more secondary groups.

					if (!empty($usergroups['groupid']) AND isset($showListKeyedById[$usergroups['groupid']]))
					{
						$skipModule = false;
					}

					if (!empty($usergroups['secondary']))
					{
						foreach ($usergroups['secondary'] AS $__usergroupid)
						{
							if (isset($showListKeyedById[$__usergroupid]))
							{
								$skipModule = false;
							}
						}
					}
				}
			}
		}
		/*
		// remove "hide from" option. It'll translate to "show all" for
		// any alpha/beta configs that might've snuck in.
		// Note, below logic & $usergroupIds var do not work anymore,
		// because fetchUsergroupsForModuleViewPerms() changed to return
		// each list of groups to allow "show" logic to deal with
		// infraction groups.
		elseif(isset($viewPerm['hide']))
		{
			$skipModule = false;
			foreach ($viewPerm['hide'] AS $__usergroupid)
			{
				if (isset($usergroupIds[$__usergroupid]))
				{
					$skipModule = true;
					break;
				}
			}

		}
		*/
		else
		{
			// Unless the widget XML import failed, I don't think we'll ever
			// hit this case.
			$skipModule = false;
		}

		return $skipModule;
	}

	/**
	 * Returns  all widget instances that are associated with the
	 * given page template id.  These are the widget instances that should
	 * shown on that page template.
	 *
	 * @param	int		Page template id.
	 * @param	int		Section number. Sections start at 0. Use -1 to
	 * 				return all widget instances, specify section number
	 *				to only return the widget instances in that section.
	 * @param	int		Channel id. May have specific configuration for display and order of widgets
	 *
	 * @return	array		The array of widget instance data, empty on failure
	 */
	public function fetchWidgetInstancesByPageTemplateId($pagetemplateid, $sectionnumber = -1, $channelId = 0, $admincheck = false)
	{
		//@todo -- copied directly from scaffold-- this should be done with a JOIN and fewer queries.

		$this->pagetemplateid = intval($pagetemplateid);
		$this->sectionnumber = intval($sectionnumber);
		$userid = intval(vB::getCurrentSession()->get('userid'));
		$showall = false;
		if ($admincheck)
		{
			// Use hasAdminPermission instead of checkHasAdminPermission as latter throws an exception.
			$showall = $this->hasAdminPermission('canusesitebuilder');
		}

		$db = vB::getDbAssertor();

		$conditions = array(
			'pagetemplateid' => $this->pagetemplateid,
		);

		if ($this->sectionnumber >= 0)
		{
			// get widget instances from a specific section only
			$conditions['displaysection'] = $this->sectionnumber;
		}
		else
		{
			// get all widgets ($sectionnumber == -1)
		}

		$result = $db->assertQuery('widgetinstance', $conditions, array('containerinstanceid', 'displaysection', 'displayorder'));

		$this->preloadWidgetIds = $widgetinstanceids = $widgetinstances = $widgetids = array();
		$widgetids[] = 0;
		$cache = vB_Cache::instance(vB_Cache::CACHE_FAST);
		foreach ($result AS $widget)
		{
			$widgetids[] = $widget['widgetid'];
			$widgetinstanceids[] = $widget['widgetinstanceid'];
			$widgetinstances[] = $widget;
			if ($cache->read('widgetDefinition_' . $widget['widgetid']) === false)
			{
				$this->preloadWidgetIds[] = $widget['widgetid'];
			}
			vB_Cache::instance(vB_Cache::CACHE_FAST)->write('widgetInstance_' . $widget['widgetinstanceid'], $widget, false, array('widgetInstanceChg_' . $widget['widgetinstanceid']));
		}

		if (!empty($this->preloadWidgetIds))
		{
			// NOTE: The data retrieved and cached to "widgetDefinition_X" needs to match
			// the data in getWidgetDefinition()
			// They currently match because they both use the getWidgetdefinition query

			$widgetdefinitions_res = $db->assertQuery('getWidgetdefinition', array('widgetid' => $this->preloadWidgetIds));
			foreach ($widgetdefinitions_res AS $widgetdefinition)
			{
				$widgetdefinitions[$widgetdefinition['widgetid']][] = $widgetdefinition;
			}
			// there might be some widget that don't have configuration
			if (empty($widgetdefinitions) OR (count($this->preloadWidgetIds) != count($widgetdefinitions)))
			{
				foreach ($this->preloadWidgetIds AS $preloadWidgetId)
				{
					// add those widgets as well so we don't query them again
					if (empty($widgetdefinitions[$preloadWidgetId]))
					{
						$widgetdefinitions[$preloadWidgetId] = array();
					}
				}
			}
			if (!empty($widgetdefinitions))
			{
				foreach ($widgetdefinitions as $widgetid => $definitions)
				{
					$cache->write('widgetDefinition_' . $widgetid, $definitions, false, array('widgetDefChg_' . $widgetid));
				}
			}
		}

		//let's pre-fetch the widget instances
		if (!empty($widgetinstanceids))
		{
			$this->fetchWidgetInstances($widgetinstanceids);
		}

		$widgetdata = $db->getRows('widget', array('widgetid' => $widgetids), false, 'widgetid');
		// preload and cache widget definitions
		// order by display order
		$widgets = $allWidgets = $configInfo = $sortAgain = array();


		$usergroupIds = array();
		if (!$showall)
		{
			$usergroupIds = $this->fetchUsergroupsForModuleViewPerms($userid);
		}

		foreach ($widgetinstances AS $widgetinstance)
		{
			$__widgetinstanceid = $widgetinstance['widgetinstanceid'];
			if (!isset($configInfo[$__widgetinstanceid]))
			{
				$configInfo[$__widgetinstanceid] = $this->fetchConfig($__widgetinstanceid, $userid, $channelId);
			}

			if (!$showall)
			{
				$__skipModule = $this->doSkipModule($__widgetinstanceid, $configInfo[$__widgetinstanceid], $usergroupIds);

				if ($__skipModule)
				{
					/*
						Alternatively, we could have it set a field that the templates check instead of skipping
						this module outright here. That would allow us to show a replacement template to indicate
						that it was skipped in the HTML for debug purposes, and/or show a custom replacement
						template that admins can set to indicate to the users that they can sign up for a
						subscription to access the missing content, ETC.
						These can be implemented as future improvements.
					 */
					continue;
				}
			}


			$data = $widgetdata[$widgetinstance['widgetid']];
			$data['widgetinstanceid'] = $__widgetinstanceid;
			$data['displaysection'] = $widgetinstance['displaysection'];
			$data['displayorder'] = $widgetinstance['displayorder'];
			$data['tabbedContainerSubModules'] = array();

			/*
				If we have nested containers, with latter instances containing earlier instances,
				$allWidgets[...] might already exist with the subkey 'tabbedContainerSubModules'.
				In that case, we want to make sure we don't accidentally empty it. While it doesn't
				seem to cause serious problems, this lets us take advantage of tabbedContainerSubmodules
				later when the templates call fetchTabbedSubWidgetConfigs()
				We don't use subModules a lot (only in blog pages, AFAIK), and they're usually system
				created, but let's handle that as well.
			 */
			if (!empty($allWidgets[$data['widgetinstanceid']]['subModules']))
			{
				$data['subModules'] = $allWidgets[$data['widgetinstanceid']]['subModules'];
			}
			else
			{
				$data['subModules'] = array();
			}

			if (!empty($allWidgets[$data['widgetinstanceid']]['tabbedContainerSubModules']))
			{
				$data['tabbedContainerSubModules'] = $allWidgets[$data['widgetinstanceid']]['tabbedContainerSubModules'];
			}
			else
			{
				$data['tabbedContainerSubModules'] = array();
			}

			$allWidgets[$data['widgetinstanceid']] = $data;

			if ($widgetinstance['containerinstanceid'] > 0)
			{
				if (!isset($configInfo[$widgetinstance['containerinstanceid']]))
				{
					$configInfo[$widgetinstance['containerinstanceid']] = $this->fetchConfig($widgetinstance['containerinstanceid'], $userid, $channelId);
				}
				// Check if container has a specific display_order.
				if (isset($configInfo[$widgetinstance['containerinstanceid']]['display_order']) AND
					!empty($configInfo[$widgetinstance['containerinstanceid']]['display_order']) AND
					empty($configInfo[$widgetinstance['containerinstanceid']]['submodules_key'])
				)
				{
					$sortAgain[] = $widgetinstance['containerinstanceid'];
				}

				if (isset($configInfo[$widgetinstance['containerinstanceid']]['display_modules']) AND
					!empty($configInfo[$widgetinstance['containerinstanceid']]['display_modules']))
				{
					$allWidgets[$data['widgetinstanceid']]['hidden'] = in_array($data['widgetinstanceid'], $configInfo[$widgetinstance['containerinstanceid']]['display_modules']) ? 0 : 1;
				}
				else
				{
					$allWidgets[$data['widgetinstanceid']]['hidden'] = 0;
				}

				// Do not set subModules for tabbed_container.
				if (empty($configInfo[$widgetinstance['containerinstanceid']]['submodules_key']))
				{
					$allWidgets[$widgetinstance['containerinstanceid']]['subModules'][$data['widgetinstanceid']] =& $allWidgets[$data['widgetinstanceid']];
				}
				else
				{
					switch ($configInfo[$widgetinstance['containerinstanceid']]['submodules_key'])
					{
						// switch to avoid allowing random values in as array keys...
						// ATM we don't use any other field.
						case 'tabbedContainerSubModules':
						default:
							$allWidgets[$widgetinstance['containerinstanceid']]['tabbedContainerSubModules'][$data['widgetinstanceid']] =& $allWidgets[$data['widgetinstanceid']];
							break;
					}
				}
			}
			else
			{
				$allWidgets[$data['widgetinstanceid']]['hidden'] = 0;
				$widgets[] =& $allWidgets[$data['widgetinstanceid']];
			}
		}

		// todo: check for circular container references.

		// add titles
		$widgets = $this->addWidgetTitles($widgets);
		// Check products
		$this->checkProductStatus($widgets);

		// if there's an order in config, we need to resort submodules
		if (!empty($sortAgain))
		{
			foreach($sortAgain AS $containerInstanceId)
			{
				$newOrder = array();
				if (!empty($configInfo[$containerInstanceId]['display_order']))
				{
					foreach($configInfo[$containerInstanceId]['display_order'] AS $widgetInstanceId)
					{
						$newOrder[$widgetInstanceId] = $allWidgets[$containerInstanceId]['subModules'][$widgetInstanceId];
						unset($allWidgets[$containerInstanceId]['subModules'][$widgetInstanceId]);
					}
				}

				// append any remaining item
				$newOrder += $allWidgets[$containerInstanceId]['subModules'];
				$allWidgets[$containerInstanceId]['subModules'] = $newOrder;
			}
		}

		return $widgets;
	}

	/**
	 * Returns  all widget instances that are associated with the
	 * given page template id in a hierarchical array indexed by section number.
	 * These are the widget instances that should shown on that page template.
	 *
	 * @param	int		Page template id.
	 * @param	int		Channel id (optional)
	 *
	 * @return	array		The array of sections with widget instance data, empty on failure
	 */
	public function fetchHierarchicalWidgetInstancesByPageTemplateId($pagetemplateid, $channelId = 0, $admincheck = false)
	{
		$widgetInstances = $this->fetchWidgetInstancesByPageTemplateId($pagetemplateid, -1, $channelId, $admincheck);
		$maxDisplaySection = 0;
		foreach ($widgetInstances AS $widgetInstance)
		{
			$maxDisplaySection = (int) max($maxDisplaySection, $widgetInstance['displaysection']);
		}

		$widgets = array();
		for ($i = 0; $i <= $maxDisplaySection; ++$i)
		{
			$widgets[$i] = array();
		}

		foreach ($widgetInstances AS $widgetInstance)
		{
			$displaySection = $widgetInstance['displaysection'];
			$widgets[$displaySection][] = $widgetInstance;
		}

		return $widgets;
	}

	/**
	 * Returns an array of info, including the widget instances, to loop over
	 * and display all the layout sections.
	 *
	 * @param  int   Page template ID
	 * @param  int   Channel ID (optional)
	 *
	 * @return array The array of sections with widget instance data, empty on failure
	 */
	public function fetchLayoutSectionInfo($pagetemplateid, $channelId = 0)
	{
		$db = vB::getDbAssertor();

		$widgets = $this->fetchHierarchicalWidgetInstancesByPageTemplateId($pagetemplateid, $channelId);

		// TODO: Optimization-- this information has probably already been queried somewhere
		$pagetemplate = $db->getRow('pagetemplate', array('pagetemplateid' => $pagetemplateid));
		$screenlayout = $db->getRow('screenlayout', array('screenlayoutid' => $pagetemplate['screenlayoutid']));

		$sectiondata = array();
		if (!empty($screenlayout['sectiondata']))
		{
			$sectiondata = json_decode($screenlayout['sectiondata'], true);
		}
		$addsectiondata = array();
		if (!empty($pagetemplate['screenlayoutsectiondata']))
		{
			$addsectiondatatemp = json_decode($pagetemplate['screenlayoutsectiondata'], true);
			foreach ($addsectiondatatemp AS $addsection)
			{
				$addsectiondata[$addsection['sectionnumber']] = $addsection;
			}
			unset($addsectiondatatemp);
		}

		// return value
		$rows = array();

		// set up row and then column/section data
		foreach ($sectiondata AS $row)
		{
			$rowSections = array();
			$hasFlex = false;
			$flexFirst = false;
			$rowFixed = '';

			foreach ($row AS $section)
			{
				$sectionnumber = $section['sectionnumber'];

				if (!empty($section['layoutcolumnfixed']))
				{
					$rowFixed = $section['layoutcolumnfixed'];
				}

				$section['sectiontypes'] = explode(',', $section['sectiontype']);

				// add pagetemplate-specific overrides for screenlayout data
				if (!empty($addsectiondata[$sectionnumber]))
				{
					$addsection = $addsectiondata[$sectionnumber];
					foreach ($addsection AS $addsectionkey => $addsectionvalue)
					{
						$section[$addsectionkey] = $addsectionvalue;
					}
				}

				// add widgetinstances to each section
				// This is passed into the screenlayout_widgetlist template as $widgets
				$section['widgetinstances'] = (isset($widgets[$sectionnumber]) ? $widgets[$sectionnumber] : array());

				$key = $section['sourceorder'];
				$rowSections[$key] = $section;
			}
			// Sort by sourceorder, as they will be rendered in the markup in this order
			ksort($rowSections);

			// set some vars to keep template logic simpler
			$first = true;
			$minDisplayOrder = null;
			foreach ($rowSections AS $rowSection)
			{
				if (!empty($rowSection['layoutcolumnflex']))
				{
					$hasFlex = true;
					if ($first)
					{
						$flexFirst = true;
					}
				}
				$first = false;

				if ($minDisplayOrder === null)
				{
					$minDisplayOrder = $rowSection['displayorder'];
				}
				$minDisplayOrder = min($minDisplayOrder, $rowSection['displayorder']);
			}
			foreach ($rowSections AS $k => $rowSection)
			{
				if ($rowSection['displayorder'] == $minDisplayOrder)
				{
					$rowSections[$k]['isFirstDisplaySection'] = true;
					break;
				}
			}
			unset($first, $minDisplayOrder);

			$rows[] = array(
				'sections' => $rowSections,
				'info' => array(
					'sectionCount' => count($rowSections),
					'hasFlex' => $hasFlex,
					'flexFirst' => $flexFirst,
					'rowFixed' => $rowFixed,
				),
			);
		}

		return $rows;
	}

	/**
	 * Deletes a widget instance
	 *
	 * @param	int	Widget instance ID to delete
	 *
	 * @return	false|int	False or 0 on failure, 1 on success
	 */
	public function deleteWidgetInstance($widgetInstanceId)
	{
		return $this->deleteWidgetInstances(array(intval($widgetInstanceId)));
	}

	/**
	 * Deletes multiple widget instances
	 *
	 * @param	array	Widget instance IDs to delete
	 *
	 * @return	false|int	False or 0 on failure, number of rows deleted on success
	 */
	public function deleteWidgetInstances(array $widgetInstanceIds, $updateParents = false)
	{
		$this->checkHasAdminPermission('canusesitebuilder');
		$widgetLibrary = vB_Library::instance("widget");
		$result = $widgetLibrary->deleteWidgetInstances($widgetInstanceIds, $updateParents);

		return $result;
	}

	/**
	 * Saves (inserts/updates) one channel record. Used by
	 * {@see saveChannelWidgetConfig, saveChannels}
	 *
	 * @param	int	Channel Node ID, if available
	 * @param	array	Channel data (title, etc)
	 * @param	int	Page parent ID
	 *
	 * @return	int	Channel Node ID
	 */
	protected function saveChannel($nodeid, array $data)//, $page_parentid
	{
		$this->checkHasAdminPermission('canusesitebuilder');
		$this->checkHasAdminPermission('canadminforums');

		$db = vB::getDbAssertor();
		// TODO: this interface is not available on core
		$channelApi = vB_Api::instanceInternal('content_channel');
		$nodeid = (int) $nodeid;
		$return_page_parentid = null;

		if ($nodeid > 0)
		{
			if (isset($data['switchCategory']))
			{
				$channelApi->switchForumCategory($data['switchCategory'], $nodeid);
			}

			// this call won't update parentid
			$channelApi->update($nodeid, $data);

			// check if we need to move the channel
			if ($data['parentid'] != $data['previousParentId'])
			{
				vB_Api::instanceInternal('node')->moveNodes($nodeid, $data['parentid']);
			}
		}
		else
		{
			if (isset($data['switchCategory']) AND $data['switchCategory'] > 0)
			{
				$data['category'] = $data['switchCategory'] ? 1 : 0;
				$data['options']['cancontainthreads'] = $data['switchCategory'] ? 0 : 1;
				unset($data['switchCategory']);
			}

			//Normally we want it to be published.
			if (!isset($data['publishdate']))
			{
				$data['publishdate'] = vB::getRequest()->getTimeNow();
			}

			$nodeid = $channelApi->add($data);
		}

		$channel = $db->getRow('vBForum:node', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			vB_dB_Query::CONDITIONS_KEY => array('nodeid'=>$nodeid)
		));

		return array(
				'nodeid' => $nodeid,
				'routeid' => $channel['routeid']
			);
	}

	/**
	 * Creates a page template record for a channel. Used by
	 * {@see saveChannelWidgetConfig, saveChannels}
	 *
	 * @param	int	Page template ID
	 * @param	int	Channel Node ID
	 *
	 * @return	int	New Page template ID
	 */
	protected function saveChannelPageTemplate($pagetemplateid, $nodeid)
	{
		/*
		// create page template for this channel
		mysql_query("
			INSERT INTO " . $config->db_prefix . "pagetemplate
			(screenlayoutid, title)
			SELECT p.screenlayoutid, 'Channel #$nodeid Page Template'
			FROM " . $config->db_prefix . "pagetemplate AS p
			WHERE p.pagetemplateid = $pagetemplateid
		");
		$newpagetemplateid = (int) mysql_insert_id($dblink);
		// copy widgets to new page template (except for widget in position 0, 0)
		mysql_query("
			INSERT INTO " . $config->db_prefix . "widgetinstance
			(pagetemplateid, widgetid, displaysection, displayorder, adminconfig)
			SELECT $newpagetemplateid, w.widgetid, w.displaysection, w.displayorder, w.adminconfig
			FROM " . $config->db_prefix . "widgetinstance AS w
			WHERE w.pagetemplateid = $pagetemplateid AND w.displaysection <> 0 AND w.displayorder <> 0
		");
		// copy widget from 0, 0 position in page template id #2 (the default channel page template)
		mysql_query("
			INSERT INTO " . $config->db_prefix . "widgetinstance
			(pagetemplateid, widgetid, displaysection, displayorder, adminconfig)
			SELECT $newpagetemplateid, w.widgetid, w.displaysection, w.displayorder, w.adminconfig
			FROM " . $config->db_prefix . "widgetinstance AS w
			WHERE w.pagetemplateid = 2 AND w.displaysection = 0 AND w.displayorder = 0
		");
		// @todo save the pagetemplateid in the channel table? so
		// it's accessible when viewing a channel in the channel controller
		//
		*/

	}

	/**
	 * Recursively saves all channels in the Channel Widget Used by
	 * {@see saveChannelWidgetConfig}
	 *
	 * @param	array	Channel data
	 * @param	int	Parent node ID (used by the recursive call only)
	 * @param
	 * @param	int	Page ID where the channels are being created
	 *
	 * @return	array	Channel Information
	 */
	protected function saveChannels($channels, $parentid = 1, &$channelIds)//, $pageid
	{
		$this->checkHasAdminPermission('canusesitebuilder');
		$this->checkHasAdminPermission('canadminforums');

		if (empty($channels))
		{
			return array();
		}
		$existing_nodeids = array();
		foreach ($channels as $channel)
		{
			if (!empty($channel->nodeid))
			{
				$existing_nodeids[] = $channel->nodeid;
			}
		}
		$existingChannels = array();
		if (!empty($existing_nodeids))
		{
			$existingChannels = vB_Library::instance('content_channel')->getContent($existing_nodeids);
		}

		$channelsOut = array();

		foreach ($channels as $channel)
		{
			$channelData = array(
				'title' => $channel->title,
				'parentid' => $parentid,
				'previousParentId' => $channel->previousParentId,
				'displayorder' => $channel->displayorder
			);
			if (isset($channel->switchCategory))
			{
				$channelData['switchCategory'] = (bool)$channel->switchCategory;
			}

			if (
				!empty($channel->nodeid)
				AND !empty($existingChannels[$channel->nodeid])
				AND $channel->title == $existingChannels[$channel->nodeid]['title']
				AND $parentid == $existingChannels[$channel->nodeid]['parentid']
				AND $parentid == $channel->previousParentId
				AND $channel->displayorder == $existingChannels[$channel->nodeid]['displayorder']
				AND (!isset($channel->switchCategory) OR $channel->switchCategory == $existingChannels[$channel->nodeid]['category'])
			)
			{
				// no need to update this channel, nothing changed
				$nodeid = $channel->nodeid;
				$channelInfo = $existingChannels[$channel->nodeid];
			}
			else
			{
				$channelInfo = $this->saveChannel($channel->nodeid, $channelData);//, $pageid
				$nodeid = $channelInfo['nodeid'];
			}
			if (empty($channelInfo['routeid']))
			{
				//this can only happen if there is an invalid node record, which shouldn't happen but is bad.
				throw new vB_Exception_Content('invalid_route_contact_vbulletin_support');
			}

			//if we can't generate the url due to permissions just skip it rather than throwing an error
			try
			{
				$url = vB5_Route::buildUrl($channelInfo['routeid']);
			}
			catch(Exception $e)
			{
				$url = '';
			}

			$channelsOut[] = array(
				//'channelid' => $nodeid, // @todo - remove
				'nodeid' => $nodeid,
				//'parentchannelid' => $parentid, // @todo - remove
				'parentid' => $parentid,
				'title' => $channel->title,
				'subchannels' => $this->saveChannels($channel->subchannels, $nodeid, $channelIds),//, $channelInfo['page_parentid']
				'url' => $url
			);
			$channelIds[] = $nodeid;
		}

		return $channelsOut;
	}

	/**
	 * Returns the structure which was previously stored in the adminconfig field of widgetinstancetable
	 * @param int $rootChannelId
	 */
	public function fetchChannelWidgetAdminConfig($channelIds)
	{
		$this->checkHasAdminPermission('canusesitebuilder');
		$this->checkHasAdminPermission('canadminforums');

		// get channels for which current user has access
		$nodes = vB_Api::instanceInternal('node')->getNodes($channelIds);

		return $this->assembleChannelConfig($nodes);
	}

	public function fetchPageManagerForums()
	{
		$this->checkHasAdminPermission('canusesitebuilder');
		$this->checkHasAdminPermission('canadminforums');

		// TODO: this doesn't use pagination. If/When UI changes, use vBForum:getChannel instead
		$nodes = vB::getDbAssertor()->getRows('vBForum:getChannelWidgetInfo');

		$response = $this->assemblePageManagerChannelsConfig($nodes);

		$forums = array_shift($response['channel_hierarchy']['forum']);
		if (empty($forums))
		{
			return array();
		}

		return $forums['subchannels'];
	}

	public function fetchPageManagerGroups($channel = 'groups', $page = 1)
	{
		$this->checkHasAdminPermission('canusesitebuilder');
		$this->checkHasAdminPermission('canadminforums');

		$page = max($page, 1);

		$perpage = vB::getDatastore()->getOption('maxposts');
		if (empty($perpage))
		{
			$perpage = 20;
		}
		$from = (($page - 1) * $perpage);
		$topChannelIds = vB_Api::instanceInternal('Content_Channel')->fetchTopLevelChannelIds();

		$result['nodes'] = vB::getDbAssertor()->getRows('vBForum:getTLChannelInfo', array('channelid' => $topChannelIds[$channel], 'from' => $from, 'perpage' => $perpage), false, 'nodeid');

		$total = count($result['nodes']);
		if ($page > 1 OR $total == $perpage)
		{
			$total = vB::getDbAssertor()->getField('vBForum:getTLChannelCount', array('channelid' => $topChannelIds[$channel]));
		}

		$result['paginationInfo'] = array(
				'startcount' => $from + 1,
				'endcount' => $from + count($result['nodes']),
				'totalcount' => $total,
				'currentpage' => $page,
				'page' => $page,
				'totalpages' => ceil($total / $perpage),
//				'name' => $name,
//				'tab' => $params['tab']
				//'queryParams' => $params['queryParams']
		);
		return $result;
	}

	protected function channelDisplaySort($ch1, $ch2)
	{
		if ($ch1['displayOrder'] == $ch2['displayOrder'])
		{
			if ($ch1['nodeid'] == $ch2['nodeid'])
			{
				return 0;
			}
			else if ($ch1['nodeid'] > $ch2['nodeid'])
			{
				return 1;
			}
			else
			{
				return -1;
			}
		}
		else if ($ch1['displayOrder'] > $ch2['displayOrder'])
		{
			return 1;
		}
		else
		{
			return -1;
		}
	}

	protected function assembleChannelConfig($nodes)
	{
		// build required variables
		$channels = $channelHierarchy = $channelNodeIds = $lastContentIds =  array();

		foreach ($nodes AS $node)
		{
			if (intval($node['lastcontentid']))
			{
				$lastContentIds[] = $node['lastcontentid'];
			}

			$channels[$node['nodeid']] = array(
				'nodeid' => intval($node['nodeid']),
				'routeid' => intval($node['routeid']),
				'title'	=> $node['title'],
				'parentid' => intval($node['parentid']),
				'isSubChannel' => false,
				'lastPostTitle' => '',
				'subchannels' => array(),
				'displayOrder' => intval($node['displayorder']),
				'category' => intval((!empty($node['category']) ? $node['category'] : 0)),
			);
		}

		// preorder channels to follow display order
		uasort($channels, array($this, 'channelDisplaySort'));

		$lastContents = vB_Api::instanceInternal('node')->getNodes($lastContentIds);

		foreach ($channels as $channel)
		{
			$nodeId = $channel['nodeid'];
			$parentId = $channel['parentid'];
			$displayOrder = intval($channel['displayOrder']);

			if (!empty($nodes[$nodeId]['lastcontentid']) AND !empty($lastContents[$nodes[$nodeId]['lastcontentid']]))
			{
				$channels[$nodeId]['lastPostTitle'] = $lastContents[$nodes[$nodeId]['lastcontentid']]['htmltitle'];
				$channels[$nodeId]['lastPost'] = $lastContents[$nodes[$nodeId]['lastcontentid']];
			}

			if (isset($channels[$parentId]))
			{
				// assign by reference, so subchannels can be filled in later
				$channels[$nodeId]['isSubChannel'] = true;
				if ($displayOrder > 0)
				{
					$channels[$parentId]['subchannels']["$displayOrder.$nodeId"] =& $channels[$nodeId];
				}
				else
				{
					$channels[$parentId]['subchannels'][] =& $channels[$nodeId];
				}
			}
			else
			{
				// assign by reference, so subchannels can be filled in later
				if ($displayOrder > 0)
				{
					$channelHierarchy["$displayOrder.$nodeId"] =& $channels[$nodeId];
				}
				else
				{
					$channelHierarchy[] =& $channels[$nodeId];
				}
			}
		}

		$channelWidgetConfig = array(
			'channels'          => $channels,
			'channel_hierarchy' => $channelHierarchy,
			// this is used to update the channel url based on the page url
			'channel_node_ids'  => array_keys($channels),
		);

		return $channelWidgetConfig;
	}

	protected function assemblePageManagerChannelsConfig($nodes)
	{
		// build required variables
		$channels = $channelHierarchy = $channelNodeIds = $lastContentIds = array();
		$topChannelIds = vB_Api::instanceInternal('Content_Channel')->fetchTopLevelChannelIds();

		foreach ($nodes AS $node)
		{
			if (intval($node['lastcontentid']))
			{
				$lastContentIds[] = $node['lastcontentid'];
			}

			$channels[$node['nodeid']] = array(
					'nodeid' => intval($node['nodeid']),
					'routeid' => intval($node['routeid']),
					'title'	=> $node['title'],
					'parentid' => intval($node['parentid']),
					'isSubChannel' => false,
					'lastPostTitle' => '',
					'subchannels' => array(),
					'displayOrder' => intval($node['displayorder']),
					'category' => intval($node['category']),
			);
			if ($tl = array_search($node['nodeid'], $topChannelIds))
			{
				$channels[$node['nodeid']]['top_level'] = $tl;
			}
		}

		// preorder channels to follow display order
		uasort($channels, array($this, 'channelDisplaySort'));

		$lastContents = vB_Api::instanceInternal('node')->getNodes($lastContentIds);

		foreach ($channels AS $channel)
		{
			$nodeId = $channel['nodeid'];
			$parentId = $channel['parentid'];
			$displayOrder = intval($channel['displayOrder']);

			if (!empty($nodes[$nodeId]['lastcontentid']) AND !empty($lastContents[$nodes[$nodeId]['lastcontentid']]))
			{
				$channels[$nodeId]['lastPostTitle'] = $lastContents[$nodes[$nodeId]['lastcontentid']]['htmltitle'];
				$channels[$nodeId]['lastPost'] = $lastContents[$nodes[$nodeId]['lastcontentid']];
			}

			if (isset($channels[$parentId]))
			{
				// assign by reference, so subchannels can be filled in later
				$channels[$nodeId]['isSubChannel'] = true;
				if ($displayOrder > 0)
				{
					$channels[$parentId]['subchannels']["$displayOrder.$nodeId"] =& $channels[$nodeId];
				}
				else
				{
					$channels[$parentId]['subchannels'][] =& $channels[$nodeId];
				}

			}
			else
			{
				// assign by reference, so subchannels can be filled in later
				$index = $displayOrder > 0 ? $displayOrder : count($channelHierarchy);
				if (!empty($channel['top_level']))
				{
					$channelHierarchy[$channel['top_level']]["$index.$nodeId"] =& $channels[$nodeId];
				}
				else
				{
					$channelHierarchy["$index.$nodeId"] =& $channels[$nodeId];
				}
			}
		}

		$channelWidgetConfig = array(
				'channels'          => $channels,
				'channel_hierarchy' => $channelHierarchy,
				// this is used to update the channel url based on the page url
				'channel_node_ids'  => array_keys($channels),
		);

		return $channelWidgetConfig;
	}


	/**
	 * Saves the configuration for the Channel Widget, including creating/saving channels
	 * as necessary.
	 *
	 * @param	array	An array of channel hierarchy information
	 *
	 * @return	array	Array of information to display the channel widget config interface
	 */
	public function saveForums($data)
	{
		$this->checkHasAdminPermission('canusesitebuilder');
		$this->checkHasAdminPermission('canadminforums');

		$forums = json_decode($data);//json_decode(array_shift($arguments));

		$channelNodeIds = array();
		$topChannelIds = vB_Api::instanceInternal('Content_Channel')->fetchTopLevelChannelIds();
		$channelsOut = $this->saveChannels($forums, $topChannelIds['forum'], $channelNodeIds);//, $pageid
		$output = array(
			'forums' => $channelsOut,
		);

		return $output;
	}

	/**
	 * Saves the configuration for the Channel Widget, including creating/saving channels
	 * as necessary.
	 *
	 * @param	array	An array of channel hierarchy information
	 *
	 * @return	array	Array of information to display the channel widget config interface
	 */
	public function saveChannelWidgetConfig($data)
	{
		$this->checkHasAdminPermission('canusesitebuilder');
		$this->checkHasAdminPermission('canadminforums');

		// @todo: use the cleaner class to auto convert from json to array
		$input = json_decode($data);//json_decode(array_shift($arguments));
		$channels = $input->channels;
		$pageid = (int) $input->pageid;
//		$pagetemplateid = (int) $input->pagetemplateid;
//		$widgetid = (int) $input->widgetid;
//		$widgetinstanceid = (int) $input->widgetinstanceid;

		$db = vB::getDbAssertor();

		// return value and widget config values
		$channelNodeIds = array();
		$parentId = 1;
		$channelsOut = $this->saveChannels($channels, $parentId, $channelNodeIds, $pageid);

//		$channelWidgetConfig = array(
//			'channel_node_ids'	=> $channelNodeIds // this is used to update the channel url based on the page url
//		);
//
//		// save widget config
//		$widgetConfigSchema = $this->fetchConfigSchema($widgetid, $widgetinstanceid, $pagetemplateid, 'admin');
//
//		$widgetid = $widgetConfigSchema['widgetid'];
//		$widgetinstanceid = $widgetConfigSchema['widgetinstanceid'];
//		$pagetemplateid = $widgetConfigSchema['pagetemplateid'];
//
//		// if the pagetemplate was not created, this call will do it in order to save the widgetinstance
//		$res = $this->saveAdminConfig($widgetid, $pagetemplateid, $widgetinstanceid, $channelWidgetConfig);

		// send output
		$output = array(
//			'pagetemplateid' => $res['pagetemplateid'],
//			'widgetinstanceid' => $widgetinstanceid,
			'channels' => $channelsOut,
		);
		return $output;

	}

	/**
	 * Saves the configuration for the Search Widget,
	 *
	 * @param	array	An array of search information
	 *
	 * @return	string	search JSON string
	 */

	public function saveSearchWidgetConfig($data)
	{
		$this->checkHasAdminPermission('canusesitebuilder');

		// @todo: use the cleaner class to auto convert from json to array
		$input = json_decode($data, true);//json_decode(array_shift($arguments));
		$pageid = (int) $input['pageid'];
		$pagetemplateid = empty($input['pagetemplateid']) ? 0 : (int) $input['pagetemplateid'];
		$widgetid = (int) $input['widgetid'];
		$widgetinstanceid = (int) $input['widgetinstanceid'];

		// save widget config
		$widgetConfigSchema = $this->fetchConfigSchema($widgetid, $widgetinstanceid, $pagetemplateid, 'admin');
		$widgetid = $widgetConfigSchema['widgetid'];
		$widgetinstanceid = $widgetConfigSchema['widgetinstanceid'];
		$pagetemplateid = $widgetConfigSchema['pagetemplateid'];

		if (empty($input['searchJSON']))
		{
			return array('error' => "empty_JSON");
		}
		$data = array(
			'searchJSON' => $input['searchJSON']
		);
		if (is_array($data['searchJSON']))
		{
			// If private messages are not explicitely requested, exclude them.
			// If an unauthorized user attempts to fetch pms, the results will not be displayed.
			$pmContenTypeId = vB_Types::instance()->getContentTypeId('vBForum_PrivateMessage');
			if (!(
					(isset($data['searchJSON']['contenttypeid']) AND (
						(is_array($data['searchJSON']['contenttypeid']) AND in_array($pmContenTypeId, $data['searchJSON']['contenttypeid'])) OR
						$data['searchJSON']['contenttypeid'] == $pmContenTypeId
					)) OR
					(isset($data['searchJSON']['type']) AND (
						(is_array($data['searchJSON']['type']) AND in_array('vBForum_PrivateMessage', $data['searchJSON']['type'])) OR
						$data['searchJSON']['type'] == 'vBForum_PrivateMessage'
					))
				))
			{
				if (!isset($data['searchJSON']['exclude_type']))
				{
					$data['searchJSON']['exclude_type'] = 'vBForum_PrivateMessage';
				}
				else if (is_string($data['searchJSON']['exclude_type']) AND $data['searchJSON']['exclude_type'] != 'vBForum_PrivateMessage')
				{
					$data['searchJSON']['exclude_type'] = array($data['searchJSON']['exclude_type'], 'vBForum_PrivateMessage');
				}
				elseif(is_array($data['searchJSON']['exclude_type']) AND !in_array('vBForum_PrivateMessage', $data['searchJSON']['exclude_type']))
				{
					$data['searchJSON']['exclude_type'][] = 'vBForum_PrivateMessage';
				}
			}

			$data['searchJSON'] = json_encode($data['searchJSON']);
		}

		if (!empty($input['resultsPerPage']))
		{
			$data['resultsPerPage'] = $input['resultsPerPage'];
		}

		if (!empty($input['searchTitle']))
		{
			$data['searchTitle'] = $input['searchTitle'];
		}

		$yesNoFields = array('hide_avatars', 'hide_module_when_empty', 'hide_usernames', 'displayFooter');
		foreach ($yesNoFields AS $__name)
		{
			if (!empty($input[$__name]) AND $input[$__name] == '1')
			{
				$data[$__name] = '1';
			}
			else
			{
				$data[$__name] = '0';
			}
		}

		// show_at_breakpoints
		$data['show_at_breakpoints'] = array(
			'desktop' => 1,
			'small'   => 1,
			'xsmall'  => 1,
		);
		if (!empty($input['show_at_breakpoints']) AND is_array($input['show_at_breakpoints']))
		{
			foreach ($input['show_at_breakpoints'] AS $k => $v)
			{
				if (in_array($k, array('desktop', 'small', 'xsmall'), true))
				{
					$data['show_at_breakpoints'][$k] = ((bool) $v) ? 1 : 0;
				}
			}
		}

		// module_viewpermissions
		$data['module_viewpermissions'] = array(
			"key" => "show_all",
		);
		if (!empty($input['module_viewpermissions']))
		{
			// This will be cleaned by cleanWidgetConfigData() downstream of saveAdminConfig()
			$data['module_viewpermissions'] = $input['module_viewpermissions'];
		}

		// module_filter_nodes. Validation (cleanWidgetConfigData() downstream of saveAdminConfig())
		// will set up default values if missing.
		$data['module_filter_nodes'] = $input['module_filter_nodes'] ?? array();

		$this->saveAdminConfig($widgetid, $pagetemplateid, $widgetinstanceid, $data);

		// send output
		$output = array(
			'widgetinstanceid' => $widgetinstanceid,
			'pagetemplateid' => $pagetemplateid,
			'searchJSON' => $input['searchJSON'],
		);

		return $output;
	}


	/**
	 * Rename custom widget
	 *
	 * @param $widgetId
	 * @param $newname
	 */
	public function renameWidget($widgetId, $newtitle)
	{
		$this->checkHasAdminPermission('canusesitebuilder');

		$widgetId = (int) $widgetId;

		if ($widgetId < 1)
		{
			throw new vB_Exception_Api('invalid_widget_id');
		}

		if (empty($newtitle))
		{
			throw new vB_Exception_Api('invalid_new_widget_title');
		}

		// @TODO: Check admin permissions here

		$db = vB::getDbAssertor();

		$widget = $db->getRow('widget', array('widgetid' => $widgetId));
		if ($widget['category'] != 'customized_copy')
		{
			throw new vB_Exception_Api('widget_cannot_rename');
		}

		$db->assertQuery('widget', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'title' => $newtitle,
			vB_dB_Query::CONDITIONS_KEY => array(
				'widgetid' => $widgetId,
			)
		));

		return true;
	}

	/**
	 * Generates a new page template ID for the new page template that
	 * that widgets are being configured for. Needed to be able to
	 * generate a widget instance ID for the new widget instance.
	 *
	 * @return	int	New page template ID
	 */
	protected function _getNewPageTemplateId()
	{
		$result = vB::getDbAssertor()->assertQuery(
			'pagetemplate',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERT,
				'title' => '',
			)
		);

		if (is_array($result))
		{
			$result = array_pop($result);
		}

		return $result;
	}

	/**
	 * Generates a new widget instance ID for the widget instance
	 * being configured.
	 *
	 * @param	int	Widget ID - The new widget instance is an instance of this widget
	 * @param	int	Page template ID - The new widget instance will be on this page template
	 *
	 * @return	int	New widget instance ID
	 */
	protected function _getNewWidgetInstanceId($widgetid, $pagetemplateid, $containerinstanceid = 0)
	{
		$result = vB::getDbAssertor()->assertQuery(
			'widgetinstance',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERT,
				'pagetemplateid' => $pagetemplateid,
				'widgetid' => $widgetid,
				'containerinstanceid' => $containerinstanceid,
			)
		);

		if (is_array($result))
		{
			$result = array_pop($result);
		}

		return $result;
	}

	/**
	 * Returns stored widget instance data for the given widget instance ID
	 *
	 * @param	int	Widget instance ID
	 *
	 * @return	array	Array of widget instance data
	 */
	protected function _getWidgetInstance($widgetinstanceid)
	{
		$cache = vB_Cache::instance(vB_Cache::CACHE_FAST);
		$cachedInstance = $cache->read('widgetInstance_' . $widgetinstanceid);
		if ($cachedInstance !== false)
		{
			return $cachedInstance;
		}

		$widgetinstance = vB::getDbAssertor()->getRow('widgetinstance',array('widgetinstanceid' => $widgetinstanceid));
		$cache->write('widgetInstance_' . $widgetinstanceid, $widgetinstance, false, array('widgetInstanceChg_' . $widgetinstanceid));
		return $widgetinstance;
	}

	/**
	 * Returns the configuration fields needed to configure a widget of this type.
	 * If the widget instance ID is given, it will also set the current values for
	 * the config fields to the current configured values for the widget instance.
	 *
	 * @param	int	The widget ID
	 * @param	int	The widget instance ID that is to be configured (optional)
	 * @param	string	The config type ("user" or "admin"), used if widget instance ID is given (optional)
	 * @param	int	The user ID, used if the config type is "user" (optional)
	 *
	 * @return 	array	An associative array, keyed by the config field name and containing
	 *			name, label, type, default value, is editable, and is required
	 * 			with which the config fields can be displayed.
	 */
	protected function _getWidgetConfigFields($widgetid, $widgetinstanceid = 0, $configtype = '', $userid = 0)
	{
		$configFields = $this->_getWidgetDefinition($widgetid);

		// get current widget config
		$userid = intval($userid);
		if ($widgetinstanceid > 0)
		{
			if ($configtype == 'user' AND $userid > 0)
			{
				$widgetConfig = $this->fetchUserConfig($widgetinstanceid, $userid);
			}
			else if ($configtype == 'admin')
			{
				$widgetConfig = $this->fetchAdminConfig($widgetinstanceid);
			}
			else
			{
				// @todo Throw an API widget exception here
				throw new Exception('Must specify valid config type. If config type is "user", a valid userid must be given.');
			}

			// if there is no user/admin config for this widget instance,
			// $widgetConfig will be false
			if (is_array($widgetConfig))
			{
				foreach ($widgetConfig AS $k => $v)
				{
					$unserialized = @unserialize($v);
					if ($unserialized !== false)
					{
						$v = $unserialized;
					}

					$configFields[$k]['defaultvalue'] = $v;
				}
			}
		}

		return $configFields;
	}

	/**
	 * fetches the rows from the widgetdefinition table for a widgetid
	 * @param int $widgetid
	 * @return array
	 */
	public function getWidgetDefinition($widgetid)
	{
		// NOTE: The data retrieved and cached to "widgetDefinition_X" needs to match
		// the data in fetchWidgetInstancesByPageTemplateId()
		// They currently match because they both use the getWidgetdefinition query

		$cache = vB_Cache::instance(vB_Cache::CACHE_FAST);
		$cachedDefinitions = $cache->read('widgetDefinition_' . $widgetid);

		if ($cachedDefinitions !== false)
		{
			return $cachedDefinitions;
		}

		$definitions = vB::getDbAssertor()->getRows('getWidgetdefinition', array('widgetid' => $widgetid));
		$cache->write('widgetDefinition_' . $widgetid, $definitions, false, array('widgetDefChg_' . $widgetid));

		return $definitions;
	}


	/**
	 * Returns the config fields that define a widget
	 *
	 * @param	int	The widget ID
	 *
	 * @return 	array	The config fields
	 */
	protected function _getWidgetDefinition($widgetid)
	{
		$configFields = array();
		$fields = $this->getWidgetDefinition($widgetid);

		usort($fields, array($this,'_cmpWigetDefFields'));

		// find phrases needed for field labels, defaultvalues, and in data array
		$phrasestofetch = array();
		foreach ($fields AS $key => $field)
		{
			// unserialize data
			$data = null;
			if (isset($field['data']))
			{
				$data = @unserialize($field['data']);
				if ($data === false) // unserialize failed, or field is bool false
				{
					if ($field['data'] === 'b:0;')
					{
						// this is supposed to be boolean false, but we can't distinguish that from unserialize() return vs. unserialize() failure.
						$data = false;
					}
					else
					{
						$data = $field['data'];
					}
				}
			}

			$fields[$key]['data'] = $data;

			// unserialize default value
			if (!empty($field['defaultvalue']))
			{
				$defaultvalue = @unserialize($field['defaultvalue']);
				if ($defaultvalue !== false)
				{
					$fields[$key]['defaultvalue'] = $defaultvalue;
				}
				else if ($defaultvalue === false AND $field['defaultvalue'] === 'b:0;') // todo: double check this change...
				{
					// this is supposed to be boolean false, but we can't distinguish that from unserialize() return vs. unserialize() failure.
					$fields[$key]['defaultvalue'] = false;
				}
			}

			// label phrases
			if (!empty($field['labelphrase']))
			{
				$phrasestofetch[] = $field['labelphrase'];
			}
			// This else branch is only here as a fallback until all widget
			// config item labels are converted to use labelphrase instead of
			// building a phrase varname based on the widget template name.
			// See VBV-13872 for more details.
			// Remove this block when VBV-14473 is fixed.
			else
			{
				if (!empty($field['name']))
				{
					$phrasestofetch[] = $field['template'] . '_' . $field['name'] . '_label';
				}
			}

			// description phrases
			if (!empty($field['descriptionphrase']))
			{
				$phrasestofetch[] = $field['descriptionphrase'];
			}

			// defaultvalue phrases (string and starts with 'phrase:')
			if (!empty($field['defaultvalue']) AND is_string($field['defaultvalue']) AND !strncmp($field['defaultvalue'], 'phrase:', 7))
			{
				$phrasestofetch[] = substr($field['defaultvalue'], 7);
			}

			// data phrases (data is array, we should loop the first level to see if we need to convert string to phrase)
			if (is_array($data))
			{
				foreach ($data as $k => $v)
				{
					if (is_string($v) AND !strncmp($v, 'phrase:', 7))
					{
						$phrasestofetch[] = substr($v, 7);
					}
				}
			}
		}

		// get phrases
		$vbphrases = vB_Api::instanceInternal('phrase')->fetch($phrasestofetch);

		// insert phrases
		foreach ($fields AS $field)
		{
			if (is_array($field) AND !empty($field))
			{
				// set data
				if ($field['field'] == 'ChannelSelect')
				{
					$data = $this->_getChannelSelectOptions();
				}
				else if ($field['field'] == 'ProfileFieldSelect')
				{
					$data = $this->_getProfileFieldSelectOptions();
				}
				else if ($field['field'] == 'ContentTypeSelect')
				{
					$data = $this->_getContentTypeSelectOptions();
				}
				else
				{
					$data = $field['data'];
					if (is_array($data))
					{
						foreach ($data as $k => $v)
						{
							if (is_string($v) AND !strncmp($v, 'phrase:', 7))
							{
								$data[$k] = $vbphrases[substr($v, 7)];
							}
						}
					}
				}

				// set label
				if (!empty($field['labelphrase']))
				{
					$label = (isset($vbphrases[$field['labelphrase']]) ? $vbphrases[$field['labelphrase']] : $field['labelphrase']);
				}
				// This elseif branch is only here as a fallback until all widget
				// config item labels are converted to use labelphrase instead of
				// building a phrase varname based on the widget template name.
				// See VBV-13872 for more details.
				// Remove this block when VBV-14473 is fixed.
				else if (!empty($vbphrases[$field['template'] . '_' . $field['name'] . '_label']))
				{
					$label = $vbphrases[$field['template'] . '_' . $field['name'] . '_label'];
				}
				else
				{
					$label = '';
				}

				// set description
				if (!empty($field['descriptionphrase']))
				{
					$description = (isset($vbphrases[$field['descriptionphrase']]) ? $vbphrases[$field['descriptionphrase']] : $field['descriptionphrase']);
				}
				else
				{
					$description = '';
				}

				// set default value
				$defaultvalue = $field['defaultvalue'];
				if (!empty($defaultvalue) AND is_string($defaultvalue) AND !strncmp($defaultvalue, 'phrase:', 7))
				{
					$defaultvalue = $vbphrases[substr($field['defaultvalue'], 7)];
				}

				$configFields[$field['name']] = array(
					'name'             => $field['name'],
					'label'            => $label,
					'description'      => $description,
					'type'             => $field['field'],
					'defaultvalue'     => $defaultvalue,
					'isEditable'       => $field['isusereditable'],
					'ishiddeninput'    => !empty($field['ishiddeninput']),
					'isRequired'       => $field['isrequired'],
					'data'             => $data,
					'validationtype'   => $field['validationtype'],
					'validationmethod' => $field['validationmethod'],
				);
			}
		}

		return $configFields;
	}

	/**
	 * Gets the channel select options for the 'ChannelSelect' config type
	 *
	 * @return	array	Channel select option data
	 */
	protected function _getChannelSelectOptions()
	{
		static $channelInfo = null;

		if ($channelInfo === null)
		{
			$channels = vB_Api::instanceInternal('Search')->getChannels();
			$channelInfo = $this->_doGetChannelSelectOptions($channels);

			$phrase = vB_Api::instanceInternal('phrase')->fetch(array('use_current_channel_parens'));
			$currentChannelOption = array(
				array(
					'nodeid' => '-1',
					'text' => $phrase['use_current_channel_parens'],
				),
			);

			$channelInfo = array_merge($currentChannelOption, $channelInfo);

			unset($channels, $currentChannelOption);
		}

		return $channelInfo;
	}

	/**
	 * Gets the channel select options for the 'ChannelSelect' config type
	 * Recursive function, only called from _getChannelSelectOptions
	 *
	 * @param	array	Channel data
	 * @param	int	how many times to indent this channel name
	 *
	 * @return	array	Channel select option data
	 */
	protected function _doGetChannelSelectOptions($channels, $indent = 0)
	{
		$data = array();
		$indentText = $indent > 0 ? str_repeat('&nbsp; &nbsp; &nbsp;', $indent) : '';

		static $specialChannelNodeid = null;
		if ($specialChannelNodeid === null)
		{
			$specialChannelNodeid = vB_Api::instanceInternal('Content_Channel')->fetchChannelIdByGUID(vB_Channel::DEFAULT_CHANNEL_PARENT);
		}

		foreach ($channels AS $channel)
		{
			if ($channel['nodeid'] == $specialChannelNodeid)
			{
				// skip the 'special' channel and any descendants
				continue;
			}

			$data[] = array(
				'nodeid' => $channel['nodeid'],
				'text' => $indentText . $channel['htmltitle'],
			);

			if (!empty($channel['channels']) AND is_array($channel['channels']))
			{
				$subchannelData = $this->_doGetChannelSelectOptions($channel['channels'], $indent + 1);
				$data = array_merge($data, $subchannelData);
			}
		}

		return $data;
	}

	/**
	 * Gets the profile field select options for the 'ProfileFieldSelect' config type
	 *
	 * @return	array	Profile field select option data
	 */
	protected function _getProfileFieldSelectOptions()
	{
		static $options = null;

		if ($options === null)
		{
			$options = array();

			$profileFields = vB::getDbAssertor()->assertQuery('vBForum:profilefield',
				array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT),
				array('field' => 'displayorder', 'direction' => vB_dB_Query::SORT_ASC)
			);

			$phraseKeys = array();
			$phraseKeys[] = 'profilefield_x_fieldid_y';

			foreach ($profileFields AS $profileField)
			{
				$phraseKeys[] = 'field' . $profileField['profilefieldid'] . '_title';
			}

			$phrases = vB_Api::instanceInternal('phrase')->fetch($phraseKeys);

			foreach ($profileFields AS $profileField)
			{
				$fieldName = 'field' . $profileField['profilefieldid'];

				$options[] = array(
					'field' => $fieldName,
					'title' => construct_phrase($phrases['profilefield_x_fieldid_y'], $phrases[$fieldName . '_title'], $fieldName),
				);
			}

			unset($profileFields, $profileField, $fieldName, $phraseKeys, $phrases);
		}

		return $options;
	}

	/**
	 * Gets the content type select options for the 'ContentTypeSelect' config type
	 *
	 * @return	array	Content type select option data
	 */
	protected function _getContentTypeSelectOptions()
	{
		/*
			@TODO when VBV-17118 is fixed, this content type information should
			come from a function call instead of being hard-coded.
		*/
		return array(
			array(
				'value'   => 'show_all',
				'phrase'  => 'all',
				'special' => true,
			),
			array(
				'value'   => 'vBForum_Text',
				'phrase'  => 'discussions_only',
				'special' => false,
			),
			array(
				'value'   => 'vBForum_Gallery',
				'phrase'  => 'photos_only',
				'special' => false,
			),
			array(
				'value'   => 'vBForum_Video',
				'phrase'  => 'videos_only',
				'special' => false,
			),
			array(
				'value'   => 'vBForum_Link',
				'phrase'  => 'links_only',
				'special' => false,
			),
			array(
				'value'   => 'vBForum_Poll',
				'phrase'  => 'polls_only',
				'special' => false,
			),
			array(
				'value'   => 'vBForum_Event',
				'phrase'  => 'events_only',
				'special' => false,
			),
		);
	}

	/**
	 * compare function for widget definition sorting
	 */
	protected function _cmpWigetDefFields($f1, $f2)
	{
		if ($f1['displayorder'] == $f2['displayorder'])
		{
			return 0;
		}

		return ($f1['displayorder'] < $f2['displayorder']) ? -1 : 1;
	}

	/**
	 * Writes debugging output to the filesystem for AJAX calls
	 *
	 * @param	mixed	Output to write
	 */
	protected function _writeDebugOutput($output)
	{
		$fname = dirname(__FILE__) . '/_debug_output.txt';
		file_put_contents($fname, $output);
	}

	public function fetchWidgetInstanceTemplates($modules)
	{
		$result = array();

		if (is_array($modules) AND !empty($modules))
		{
			array_walk($modules, 'intval');

			$result = vB::getDbAssertor()->getRows('getWidgetTemplates', array('modules' => $modules));
		}

		return $result;
	}

	public function fetchWidgetGuidToWidgetidMap()
	{
		$rows = vB::getDbAssertor()->getRows('widget');
		$guidToWidgetid = array();
		foreach ($rows AS $__row)
		{
			$guidToWidgetid[$__row['guid']] = $__row['widgetid'];
		}

		return array('map' => $guidToWidgetid);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103374 $
|| #######################################################################
\*=========================================================================*/
