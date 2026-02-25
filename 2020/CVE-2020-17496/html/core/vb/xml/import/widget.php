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

class vB_Xml_Import_Widget extends vB_Xml_Import
{
	/**
	 * Widget GUIDs
	 */
	const WIDGETGUID_ABSTRACT_GLOBAL = 'vbulletin-abstractwidget-global';

	/**
	 * Array of widget info for all widgets
	 * @var array
	 */
	private $widgets = array();

	/**
	 * Map of widget info. Key is widget GUID, value is a reference to widget in $this->widgets.
	 * Should be accessed via getWidgetByGuid()
	 * @var array
	 */
	private $widgetsByGuid = null;

	/**
	 * Array of derived widgets (after inheritance)
	 * @var array
	 */
	private $derivedWidgets = array();

	/**
	 * Array of widgetids that were newly inserted (as opposed to updated) in this import
	 * @var array
	 */
	private $insertedWidgetIds = array();

	/**
	 * Returns the widget info for the passed widget GUID.
	 *
	 * @param  string      Widget GUID
	 *
	 * @return array|null  Array of widget info or null if the widget doesn't exist
	 */
	private function getWidgetByGuid($guid)
	{
		if ($this->widgetsByGuid === null)
		{
			// create the lookup table
			$this->widgetsByGuid = array();
			foreach ($this->widgets AS $key => $widget)
			{
				if (isset($this->widgetsByGuid[$widget['guid']]))
				{
					throw new Exception('Non-unique widget GUID: "' . htmlspecialchars($widget['guid']) . '"');
				}

				$this->widgetsByGuid[$widget['guid']] =& $this->widgets[$key];
			}
		}

		if (!isset($this->widgetsByGuid[$guid]))
		{
			return null;
		}
		else
		{
			return $this->widgetsByGuid[$guid];
		}
	}

	/**
	 * Normalizes and returns widget data from XML
	 *
	 * @return array Widget data
	 */
	protected function getXmlWidgetData()
	{
		if (empty($this->parsedXML['widget']))
		{
			$this->parsedXML['widget'] = array();
		}

		$widgets = (isset($this->parsedXML['widget'][0]) AND is_array($this->parsedXML['widget'][0])) ? $this->parsedXML['widget'] : array($this->parsedXML['widget']);
		if (!empty($this->parsedXML['product']))
		{
			foreach ($widgets AS $key => $widget)
			{
				$widgets[$key]['product'] = $this->parsedXML['product'];
			}
		}

		$widgets = $this->normalizeDefinitions($widgets);

		return $widgets;
	}

	/**
	 * Gets all widget info from database, ready for the inheritance process
	 *
	 * @return array Widget data
	 */
	protected function getAllWidgetData()
	{
		// get widgets
		$this->widgets = $this->db->getRows('widget', array(), false, 'widgetid');

		// get config items
		$widgetDefinitions = $this->db->getRows('widgetdefinition');
		$widgetDefinitionLookup = array();
		foreach ($widgetDefinitions AS $widgetDefinition)
		{
			$widgetid = $widgetDefinition['widgetid'];
			if (empty($widgetDefinitionLookup[$widgetid]))
			{
				$widgetDefinitionLookup[$widgetid] = array();
			}

			$widgetDefinitionLookup[$widgetid][] = $widgetDefinition;
		}
		unset($widgetDefinitions);

		foreach ($this->widgets AS $widgetid => $widget)
		{
			// add parent guid
			$parentid = $widget['parentid'];
			if ($parentid > 0 AND !empty($this->widgets[$parentid]))
			{
				$this->widgets[$widgetid]['parentguid'] = $this->widgets[$parentid]['guid'];
			}

			// add widget definitions (config items)
			if (!empty($widgetDefinitionLookup[$widgetid]))
			{
				$this->widgets[$widgetid]['definitions'] = $widgetDefinitionLookup[$widgetid];
			}
			else
			{
				$this->widgets[$widgetid]['definitions'] = array();
			}
		}

		// normalize
		$this->widgets = $this->normalizeDefinitions($this->widgets);

		return $this->widgets;
	}

	/**
	 * Normalizes the defintions array in each widget record and ensures that
	 * each definition is keyed by the defintion name.
	 *
	 * @param  array Array of widgets
	 *
	 * @return array Array of widgets with the defintion item in each widget normalized.
	 */
	private function normalizeDefinitions($widgets)
	{
		foreach ($widgets AS $key => $widget)
		{
			// normalize array
			if (empty($widget['definitions']))
			{
				$widgets[$key]['definitions'] = array();
			}
			if (!empty($widget['definitions']['definition']))
			{
				if (!empty($widget['definitions']['definition'][0]) AND is_array($widget['definitions']['definition'][0]))
				{
					$widgets[$key]['definitions'] = $widget['definitions']['definition'];
				}
				else
				{
					$widgets[$key]['definitions'] = array($widget['definitions']['definition']);
				}
			}

			// index by name
			$defs = array();
			foreach ($widgets[$key]['definitions'] AS $def)
			{
				$defs[$def['name']] = $def;
			}
			$widgets[$key]['definitions'] = $defs;
		}

		return $widgets;
	}

	/**
	 * Checks widget parentage for vBulletin widgets and adds the default global
	 * Parent if missing.
	 *
	 * @param  array The array of widget data
	 * @param  array Array of widget data from the XML file, indexed by widgetid
	 &
	 * @return array The array of widget data, with the parentguid added where missing
	 */
	private function checkParentage($widgets, $xmlWidgets)
	{
		// in addition to final upgrade step 4,
		// widget importing is called from:
		// * 500a1 upgrade step 128
		// * 500a30 upgrade step 1
		// when this is the case, we don't have the parentid column
		// yet, so we can't insert the parentid

		// see if we should run the parentage check
		$columns = $this->getTableColumnsToImport('widget');
		if (!in_array('parentid', $columns, true))
		{
			return $widgets;
		}

		foreach ($widgets AS $key => $widget)
		{
			if (
				// skip abstract widgets, which don't need a parent
				$widget['category'] === 'Abstract'
				// skip widgets that already have a parent
				OR !empty($widget['parentguid'])
				// skip non-vbulletin widgets, which don't need a parent (at this time)
				OR $widget['product'] != 'vbulletin'
			)
			{
				continue;
			}

			if (empty($xmlWidgets[$widget['widgetid']]))
			{
				// widget is NOT found in the XML we're currently importing
				// so let's add the default parent widget, since this is a
				// vBulletin widget
				// for widgets that ARE found in the XML, verifyWidgetInheritanceRules
				// will throw an exception if they don't have a parent.

				// update in database
				$parent = $this->getWidgetByGuid(self::WIDGETGUID_ABSTRACT_GLOBAL);
				$values = array('parentid' => $parent['widgetid']);
				$conditions = array('widgetid' => $widget['widgetid']);
				$this->db->update('widget', $values, $conditions);

				// update in data array
				$widgets[$key]['parentguid'] = self::WIDGETGUID_ABSTRACT_GLOBAL;
			}
		}

		return $widgets;
	}

	/**
	 * Asserts that widget inheritance rules are followed.
	 *
	 * @param  array     The array of widget data
	 * @throws Exception If there is a problem.
	 */
	private function verifyWidgetInheritanceRules($widgets)
	{
		// check if we should enforce the rules
		$columns = $this->getTableColumnsToImport('widget');
		if (!in_array('parentid', $columns, true))
		{
			// in addition to final upgrade step 4,
			// widget importing is called from:
			// * 500a1 upgrade step 128
			// * 500a30 upgrade step 1
			// when this is the case, we don't have the parentid column
			// yet, so we can't enforce the inheritance rules.
			return;
		}

		// enforce widget inheritance rules
		foreach ($widgets AS $widget)
		{
			// if a widget is not abstract, it must have a parent widget
			if ($widget['category'] !== 'Abstract')
			{
				if (empty($widget['parentguid']))
				{
					if ($widget['product'] == 'vbulletin')
					{
						throw new Exception('Non-abstract widget is missing a parent widget. Widget GUID: "' . htmlspecialchars($widget['guid']) . '"');
					}
					else
					{
						// No exception here--
						// allow non-vbulletin widgets to be parentless
						// this could change in the future.
					}
				}
				else if ($this->getWidgetByGuid($widget['parentguid']) === null)
				{
					throw new Exception('Widget has an invalid (non-existent) parent widget. Widget GUID: "' . htmlspecialchars($widget['guid']) . '"');
				}
			}

			// if a widget has a parent widget, the parent must be abstract
			if (!empty($widget['parentguid']))
			{
				$parentWidget = $this->getWidgetByGuid($widget['parentguid']);
				if (!$parentWidget OR $parentWidget['category'] !== 'Abstract')
				{
					throw new Exception('Widget has a non-abstract parent widget. Widget GUID: "' . htmlspecialchars($widget['guid']) . '"');
				}
			}
		}
	}

	/**
	 * Applies widget inheritance and builds the final "derived" widgets
	 *
	 * @param  array Array of widgets
	 * @param  array Array of widget data from the XML file, indexed by widgetid
	 *
	 * @return array Array of derived widgets
	 */
	private function buildDerivedWidgets($widgets, $xmlWidgets)
	{
		$derivedWidgets = array();
		foreach ($widgets AS $widget)
		{
			// create stack based on parentage
			$stack = array();
			$currentWidget = $widget;
			while(true)
			{
				// check for circular references
				if (isset($stack[$currentWidget['guid']]))
				{
					throw new Exception('Attempted circular widget inheritance. Widget GUID: "' . htmlspecialchars($currentWidget['guid']) . '"');
				}

				$stack[$currentWidget['guid']] = $currentWidget;

				if (empty($currentWidget['parentguid']))
				{
					break;
				}

				$currentWidget = $this->getWidgetByGuid($currentWidget['parentguid']);
			}
			unset($currentWidget);

			// merge the widgets on the stack
			$stack = array_reverse($stack);
			$derivedWidget = array();

			foreach ($stack AS $stackItem)
			{
				// if this widget is one that was just imported, and the xml data
				// does not have a property set, then remove it from the database-sourced
				// data as well, to allow the parent widget to overwrite it, unless
				// the widget has no parent
				$xmlWidget = null;
				if (isset($xmlWidgets[$stackItem['widgetid']]))
				{
					$xmlWidget = $xmlWidgets[$stackItem['widgetid']];
				}

				$derivedWidget = $this->arrayMergeRecursive($derivedWidget, $stackItem, $xmlWidget);
			}

			// correct widgetid on inherited definition items
			foreach ($derivedWidget['definitions'] AS $name => $definition)
			{
				$derivedWidget['definitions'][$name]['widgetid'] = $derivedWidget['widgetid'];
			}

			$derivedWidgets[$derivedWidget['widgetid']] = $derivedWidget;
		}

		return $derivedWidgets;
	}

	/**
	 * Creates an array containing all the key/value pairs from $array1 and $array2.
	 * If the same key is found in both arrays, AND the value is a non-array type,
	 * the value from $array2 will overwrite the value from $array1. If the value is
	 * an array, this function is called recursively to merge the arrays. Any items
	 * that are *not* set in $removeArray, will be removed from $array2.
	 *
	 * NOTE: This function does not have the same behavior as PHP's
	 * array_merge_recursive() or array_replace_recursive().
	 *
	 * @param  array      Array 1
	 * @param  array      Array 2
	 * @param  array|null If not null, items *not* set in this array will be removed from Array 2.
	 *
	 * @return array Merged array
	 */
	private function arrayMergeRecursive($array1, $array2, $removeArray)
	{
		// if $removeArray is null, don't do removal
		if (is_array($removeArray))
		{
			foreach ($array2 AS $key => $value)
			{
				if (!isset($removeArray[$key]))
				{
					unset($array2[$key]);
				}
			}
		}

		$keys = array();
		if (!empty($array1))
		{
			$keys = array_merge($keys, array_keys($array1));
		}
		if (!empty($array2))
		{
			$keys = array_merge($keys, array_keys($array2));
		}
		$keys = array_unique($keys);

		$result = array();
		foreach ($keys AS $key)
		{
			$isSet1 = isset($array1[$key]);
			$isSet2 = isset($array2[$key]);

			if ($isSet1 AND !$isSet2)
			{
				$result[$key] = $array1[$key];
			}
			else if ($isSet2 AND !$isSet1)
			{
				$result[$key] = $array2[$key];
			}
			else
			{
				if (is_array($array1[$key]) AND is_array($array2[$key]))
				{
					$subRemoveArray = null;
					if (is_array($removeArray))
					{
						if (isset($removeArray[$key]) AND is_array($removeArray[$key]))
						{
							$subRemoveArray = $removeArray[$key];
						}
					}
					$result[$key] = $this->arrayMergeRecursive($array1[$key], $array2[$key], $subRemoveArray);
				}
				else
				{
					// if only one is an array or neither is an array,
					// then the value from array2 overwrites the other.
					$result[$key] = $array2[$key];
				}
			}
		}

		return $result;
	}

	/**
	 * Inserts or updates the widgets in the database. Adds the widget ID to the
	 * passed array of widgets and returns it.
	 *
	 * @param  array The array of widgets to insert/update
	 * @param  bool  Add the product ID to the inserted record, if needed. If false, productid will be skipped entirely.
	 *
	 * @return array The passed array of widgets with a new 'widgetid' element and indexed by widget ID.
	 */
	private function saveWidgets($widgets, $addProductId = true)
	{
		$widgetTableColumns = $this->getTableColumnsToImport('widget');

		// insert or update widget records
		foreach ($widgets AS $key => $widget)
		{
			// populate fields that are missing in the xml
			// with their default values
			$values = array();
			foreach($widgetTableColumns AS $col)
			{
				if (($col == 'product') AND !empty($this->productid))
				{
					// If we don't want to add the productid,
					// then we don't even set the key in $values
					if ($addProductId)
					{
						$values[$col] = $this->productid;
					}
				}
				else if (isset($widget[$col]))
				{
					$values[$col] = $widget[$col];
				}
				else if (($col == 'canbemultiple') OR ($col == 'cloneable') OR ($col == 'isthirdparty'))
				{
					$values[$col] = 0;
				}
				else
				{
					$values[$col] = '';
				}
			}

			// update or insert
			$condition = array('guid' => $widget['guid']);
			if ($oldWidget = $this->db->getRow('widget', $condition))
			{
				$widgetid = $oldWidget['widgetid'];

				if ($this->options & self::OPTION_OVERWRITE)
				{
					// update widget
					$this->db->update('widget', $values, $condition);
				}
			}
			else
			{
				$widgetid = $this->db->insert('widget', $values);

				if (is_array($widgetid))
				{
					$widgetid = array_pop($widgetid);
				}

				// mark record as inserted for updateWidgetParentids call
				$this->insertedWidgetIds[$widgetid] = $widgetid;
			}


			// save data needed for subsequent processing
			$widgets[$key]['widgetid'] = $widgetid;

			// track imported IDs
			vB_Xml_Import::setImportedId(vB_Xml_Import::TYPE_WIDGET, $widget['guid'], $widgetid);
		}

		$indexedWidgets = array();
		foreach ($widgets AS $widgets)
		{
			$indexedWidgets[$widgets['widgetid']] = $widgets;
		}

		return $indexedWidgets;
	}

	/**
	 * Returns an array of column names which should be populated in the import
	 *
	 * @param  string Table name to get columns for. Currently only supports (widget|widgetdefinition).
	 *
	 * @return array  List of column names
	 */
	private function getTableColumnsToImport($tableName)
	{
		if (!in_array($tableName, array('widget', 'widgetdefinition'), true))
		{
			throw new Exception('Invalid table name');
		}

		// get all columns but the key (widget table has a key, widgetdefinition does not)
		$widgetTable = $this->db->fetchTableStructure($tableName);
		$widgetTableColumns = array_diff($widgetTable['structure'], array($widgetTable['key']));

		// remove any columns that are not actually in the database
		// columns have changed in the widget tables (e.g. upgrade 517a4)
		// but this is also called from upgrade500a1 step 128 before
		// new columns were added, so we can't try to insert into them
		$queryids = array(
			'widget' => 'showWidgetTableColumns',
			'widgetdefinition' => 'showWidgetDefintionTableColumns',
		);
		$cols = $this->db->getRows($queryids[$tableName]);
		$actualCols = array();
		foreach ($cols AS $col)
		{
			$actualCols[] = $col['Field'];
		}
		$widgetTableColumns = array_intersect($widgetTableColumns, $actualCols);

		return $widgetTableColumns;
	}

	private function checkWidgetParentidAndAlterTable()
	{
		/*
			Note, for vB5 -> vB5 upgrades, it's likely that the parentid column will be added by
			517a4 step_15(). If their first install was 517+, the parentid column will already
			exist from mysql-schema defined table creation.
		 */
		$widgetTableColumns = $this->getTableColumnsToImport('widget');
		if (in_array('parentid', $widgetTableColumns, true))
		{
			return true;
		}

		vB::getDbAssertor()->assertQuery('vBInstall:addWidgetParentid');

		$widgetTableColumns = $this->getTableColumnsToImport('widget');
		if (!in_array('parentid', $widgetTableColumns, true))
		{
			throw new Exception('Invalid table name');
		}

		return false;

	}

	/**
	 * Sets/updates widget parentids based on the parentguid
	 *
	 * @param  array The array of widgets
	 *
	 * @return array The passed array of widgets with a new 'parentid' element.
	 */
	private function updateWidgetParentids($widgets)
	{
		// Make sure we have parentid available.
		// (it's not available when called from upgrade 500a1 step_128 & 500a30 step_1)
		$this->checkWidgetParentidAndAlterTable();

		// lookup table
		$guidToId = array();
		$guids = array();
		foreach ($widgets AS $widget)
		{
			$guidToId[$widget['guid']] = $widget['widgetid'];
			$guids[$widget['guid']] = $widget['guid'];
		}

		// If we're importing a product widget, the provided $widgets is from the
		// XML which doesn't have the full, default widgets. Pull missing parents from
		// the full widget data.
		// avoiding $this->getAllWidgetData(); to avoid extra overhead since we have to call it
		// again after this function to get the most up-to-date full widget data
		$otherWidgets = $this->db->getRows(
			'widget',
			array(
				vB_dB_Query::COLUMNS_KEY => array(
					'widgetid',
					'guid',
				),
				vB_dB_Query::CONDITIONS_KEY => array(
					array('field' => 'guid', 'value' => $guids, 'operator' =>  vB_dB_Query::OPERATOR_NE),
				),
			),
			false,
			'widgetid'
		);
		foreach ($otherWidgets AS $widget)
		{
			$guidToId[$widget['guid']] = $widget['widgetid'];
		}

		foreach ($widgets AS $key => $widget)
		{
			$update = (!empty($this->insertedWidgetIds[$widget['widgetid']]) OR ($this->options & self::OPTION_OVERWRITE));

			// update
			if ($update AND !empty($widget['parentguid']) AND !empty($guidToId[$widget['parentguid']]))
			{
				$condition = array('widgetid' => $widget['widgetid']);
				$values = array('parentid' => $guidToId[$widget['parentguid']]);
				$this->db->update('widget', $values, $condition);

				// add parentid to array
				$widgets[$key]['parentid'] = $guidToId[$widget['parentguid']];
			}
		}

		return $widgets;
	}

	/**
	 * Saves widget config items. Removes previous widgetdefinition records and replaces
	 * them with the new data.
	 *
	 * @param array Array of widgets, each widget array must contain the widgetid.
	 */
	private function saveConfigItems($widgets)
	{
		$widgetDefinitionTableColumns = $this->getTableColumnsToImport('widgetdefinition');

		// insert new definition records
		foreach ($widgets AS $widget)
		{
			$widgetid = $widget['widgetid'];

			// Continue only if we have a widget
			// This applies to both upgrades and new installs
			if ($widget['widgetid'])
			{
				if (isset($widget['definitions']))
				{
					// Remove preexisting definitions
					$this->db->delete('widgetdefinition', array('widgetid' => $widget['widgetid']));

					// insert the new widget config item defintions
					foreach ($widget['definitions'] AS $definition)
					{
						$values = array();
						foreach($widgetDefinitionTableColumns AS $col)
						{
							if (isset($definition[$col]))
							{
								$values[$col] = $definition[$col];
							}
						}
						$values['widgetid'] = $widget['widgetid'];
						$this->db->insert('widgetdefinition', $values);
					}
				}
			}
		}
	}

	/**
	 * Updates widgetinstance.adminconfig. Removes any values that no longer exist,
	 * Inserts the default value for any new/non-existing values in the config items.
	 *
	 * @param array Widgets
	 */
	private function updateInstanceAdminConfigs($widgets)
	{
		// Note, we cannot run this step unless the inheritance is active, or else it can potentially wipe out any inherited
		// configs from widgetinstances, see VBV-16969
		// Currently, checkWidgetParentidAndAlterTable() is called waaaay before updateInstanceAdminConfigs(),
		// so we shouldn't ever hit below. But if something changes so below is called before all the inheritance
		// checks & build up go through, just throw an exception to let the dev know they broke something.
		if (!$this->checkWidgetParentidAndAlterTable())
		{
			throw Exception("updateInstanceAdminConfigs() should not have been called before widget.parentid exists. See VBV-16969");
		}
		$instances = $this->db->getRows('widgetinstance', array(
			vB_dB_Query::COLUMNS_KEY => array('widgetinstanceid', 'widgetid', 'adminconfig')
		));

		foreach ($instances AS $instance)
		{
			if (empty($instance['adminconfig']))
			{
				$adminconfig = array();
			}
			else
			{
				$adminconfig = unserialize($instance['adminconfig']);
				if (!$adminconfig)
				{
					$adminconfig = array();
				}
			}

			// can't do much for an instance of a non-existent widget
			if (!isset($widgets[$instance['widgetid']]))
			{
				continue;
			}

			// remove any items that are no longer present
			foreach ($adminconfig AS $key => $item)
			{
				if (!isset($widgets[$instance['widgetid']]['definitions'][$key]))
				{
					unset($adminconfig[$key]);
				}
			}

			// add any new items (items that don't have a value set)
			foreach ($widgets[$instance['widgetid']]['definitions'] AS $name => $definition)
			{
				if (!isset($adminconfig[$name]))
				{
					// Set default value
					// Keep this in sync with the corresponding code
					// in vB_Xml_Import_PageTemplate::import
					if (!empty($definition['defaultvalue']))
					{
						// defaultvalue can be a serialized string
						$temp = @unserialize($definition['defaultvalue']);
						if ($temp !== false)
						{
							$definition['defaultvalue'] = $temp;
						}
					}

					$adminconfig[$name] = $definition['defaultvalue'];
				}
			}

			if (!(empty($adminconfig) AND empty($instance['adminconfig'])))
			{
				$adminconfig = $this->replacePhrasePlaceholdersInArray($adminconfig);
				$adminconfig = !empty($adminconfig) ? serialize($adminconfig) : '';
				$condition = array('widgetinstanceid' => $instance['widgetinstanceid']);
				$values = array('adminconfig' => $adminconfig);
				$this->db->update('widgetinstance', $values, $condition);
			}
		}



		// TODO update saved adminconfigs
		// 1. if empty, create it based on the defaults
		// 2. if not empty, update it
		// 	A. add the default value for any config items missing
		//	B. remove any config items no longer existing.

	}

	/**
	 * Imports the data from the XML file into the database
	 */
	protected function import()
	{
		// ***** Save the new widgets we are importing

		$xmlWidgets = $this->getXmlWidgetData();
		$xmlWidgets = $this->saveWidgets($xmlWidgets);
		$xmlWidgets = $this->updateWidgetParentids($xmlWidgets);
		$this->saveConfigItems($xmlWidgets);

		// ***** Pull all widget data and apply inheritance
		$this->widgets = $this->getAllWidgetData();
		$this->widgets = $this->checkParentage($this->widgets, $xmlWidgets);
		$this->verifyWidgetInheritanceRules($this->widgets);
		$this->derivedWidgets = $this->buildDerivedWidgets($this->widgets, $xmlWidgets);
		$this->derivedWidgets = $this->saveWidgets($this->derivedWidgets, false); // don't add/change productid on save
		$this->derivedWidgets = $this->updateWidgetParentids($this->derivedWidgets);
		$this->saveConfigItems($this->derivedWidgets);
		$this->updateInstanceAdminConfigs($this->derivedWidgets);
	}

	/**
	 * Returns the derived widgets.
	 *
	 * WARNING: Only intended for use by unit tests. Do not use in
	 * any other context
	 *
	 * @return array Derived widgets
	 */
	public function getDerivedWidgets()
	{
		if (!defined('VB_UNITTEST'))
		{
			throw new Exception('This method should be called only from unit tests');
		}
		else
		{
			return $this->derivedWidgets;
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
