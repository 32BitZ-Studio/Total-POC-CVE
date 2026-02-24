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
 * vB_Library_Widget
 *
 * @package vBLibrary
 * @access public
 */
class vB_Library_Widget extends vB_Library
{
	/**
	 * Deletes multiple widget instances
	 *
	 * @param	array	Widget instance IDs to delete
	 *
	 * @return	false|int	False or 0 on failure, number of rows deleted on success
	 */
	public function deleteWidgetInstances(array $widgetInstanceIds, $updateParents = false)
	{
		$unclean = $widgetInstanceIds;
		$widgetInstanceIds = array();
		foreach ($unclean AS $__id)
		{
			$__id = intval($__id);
			// Make sure none of the instanceid is 0. Otherwise,
			// the submodule delete logic below will wipe out everything.
			if (!empty($__id))
			{
				$widgetInstanceIds[] = $__id;
			}
		}

		if (empty($widgetInstanceIds))
		{
			return false;
		}


		$db = vB::getDbAssertor();

		// we may need to delete submodules as well
		$subModules = $db->getRows('widgetinstance', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			vB_dB_Query::COLUMNS_KEY => array('widgetinstanceid'),
			vB_dB_Query::CONDITIONS_KEY => array(
				array('field' => 'containerinstanceid', 'value' => $widgetInstanceIds)
			)
		));
		if ($subModules)
		{
			$subModuleIds = array();
			foreach($subModules AS $module)
			{
				$subModuleIds[] = intval($module['widgetinstanceid']);
			}
			$this->deleteWidgetInstances($subModuleIds);
		}

		if ($updateParents AND !empty($widgetInstanceIds))
		{
			$this->removeWidgetInstanceFromParentConfigs($widgetInstanceIds);
		}

		$db->delete('widgetinstance', array(array(
			'field' => 'widgetinstanceid',
			'value' => $widgetInstanceIds,
		)));

		return $db->affected_rows();
	}

	private function removeWidgetInstanceFromParentConfigs($widgetInstanceIds)
	{
		$widgetApi = vB_Api::instanceInternal("widget");
		$widgetInstanceIds = array_unique($widgetInstanceIds);
		$widgetInstanceIdsKeyed = array_flip($widgetInstanceIds);
		$db = vB::getDbAssertor();
		/*
		todo: figure out a way to remove uninstanced widgets from parents, although I don't think
		we support that short of default-installed widgets that were never configured.
		We don't want to do below because if we're hitting this through a *single* instance delete
		rather than a product uninstall triggering an entire widget-family removal, we don't
		want to accidentally nuke *all* other instances sharing the same widget.
		$widgetids = $db->getColumn('widgetinstance', 'widgetid', array('widgetinstanceid' => $widgetInstanceIds));
		$widgetids = array_unique($widgetids);
		$widgetidsKeyed = array_flip($widgetids);
		*/
		$parentinstanceids = $db->getColumn('widgetinstance',
			'containerinstanceid',
			array(
				vB_dB_Query::CONDITIONS_KEY => array(
					array(
						'field' => 'containerinstanceid',
						'value' => 0,
						vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_GT
					),
					array(
						'field' => 'widgetinstanceid',
						'value' => $widgetInstanceIds,
						vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ
					),
				),
			)
		);
		$parentinstanceids = array_unique($parentinstanceids);
		foreach ($parentinstanceids AS $__id)
		{
			$__config = $widgetApi->fetchAdminConfig($__id);
			$__changed = false;
			if (!empty($__config['tab_data']))
			{
				foreach($__config['tab_data'] AS $__tabnum => $__tab)
				{
					if (isset($__tab['widgets']))
					{
						$__rekey = false;
						foreach ($__tab['widgets'] AS $__key => $__widget)
						{
							if (
								!empty($__widget['widgetinstanceid']) AND
								isset($widgetInstanceIdsKeyed[$__widget['widgetinstanceid']])
							)
							{
								$__changed = true;
								unset($__config['tab_data'][$__tabnum]['widgets'][$__key]);
								// The JS expects orderly arrays, not objects, and was unfortunately
								// not robust enough to handle "skipped" keys.
								// The particular JS code to handle subwidgets has *now* been updated to
								// handle the resulting objects, but let's also re-key the array in case
								// there is other JS that might not be hardened yet.
								$__rekey = true;
							}
							/*
							// Not doing anything with widgetid for now, see note above.
							else if (
								!empty($__widget['widgetid']) AND
								in_array($__widget['widgetid'], $widgetids)
							)
							{
							}
							*/
						}
						if ($__rekey)
						{
							/*
								Basically we're trying to take
									array( 0 => arrayA, 2 => arrayB, 3 => arrayC)
								and reindex it to
									array( 0 => ArrayA, 1 => arrayB, 2 => arrayC)

								The reason why I didn't just do
									$final = array_values($source)
								is because of comments online indicating that sometimes
								array_values() re-orders the array unexpectedly.

								In fact, one of the comments on array_values() PHP doc page has the following
								note:
									Remember, array_values() will ignore your beautiful numeric indexes,
									it will renumber them according tho the 'foreach' ordering:
									$a = array(
										3 => 11,
										1 => 22,
										2 => 33,
									);
									$a[0] = 44;
									print_r( array_values( $a ));
									==>
									Array(
									  [0] => 11
									  [1] => 22
									  [2] => 33
									  [3] => 44
									)
								Since the "key" of the widgets array are the displayorders, maintaining that
								relative order is crucial. Therefore, I did not want to rely on the unclear/
								undefined re-ordering behavior of array_values(), and just go with a certain
								process:
								Do ksort() first to make sure that the "foreach" ordering will be in the
								order of the indices, then walk through it to renumerate the array in the
								*expected* order.

								Just doing ksort() then array_values() might be sufficient, but again, I thought
								it was better to be sure than just assume that the undocumented but observed behavior
								of array_values() is intended rather than a byproduct & will be maintained in the
								future.
							 */
							$__newArr = array();
							ksort($__config['tab_data'][$__tabnum]['widgets']);
							foreach ($__config['tab_data'][$__tabnum]['widgets'] AS $__copydata)
							{
								$__newArr[] = $__copydata;
							}
							$__config['tab_data'][$__tabnum]['widgets'] = $__newArr;
						}
					}
				}
			}

			if ($__changed)
			{
				$options = array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
					'widgetinstanceid' => $__id,
					'adminconfig' => serialize($__config),
				);
				$result = $db->assertQuery(
					'widgetinstance',
					$options
				);
			}
		}
	}

	public function cleanFilterNodes($filterNodes, $currentChannel = null)
	{
		$filterType = "include";
		$filterChannels = "all";
		if (!empty($filterNodes))
		{
			if (!empty($filterNodes['include']))
			{
				$filterType = "include";
			}
			else if (!empty($filterNodes['exclude']))
			{
				$filterType = "exclude";
			}

			if (!empty($filterNodes[$filterType]))
			{
				$filterChannels = array_values($filterNodes[$filterType]);
				if (count($filterChannels) == 1 AND
					($filterChannels[0] === "all")
				)
				{
					// These are exclusive and don't work with arrays of nodeids.
					$filterChannels = (string) $filterChannels[0];
				}
				else
				{
					foreach ($filterChannels AS $__key => $__nodeid)
					{
						if ($__nodeid === "current")
						{
							if (empty($currentChannel))
							{
								unset($filterChannels[$__key]);
							}
							else
							{
								$filterChannels[$__key] = intval($currentChannel);
							}
						}
						else
						{
							$filterChannels[$__key] = intval($__nodeid);
						}
					}
				}
			}

			// "include" => array("all") is a nonfilter operation.
		}

		$includeChildren = true;
		if (isset($filterNodes['include_children']))
		{
			$includeChildren = (bool) $filterNodes['include_children'];
		}

		return array(
			'filterType' => $filterType,
			'filterChannels' => $filterChannels,
			'includeChildren' => $includeChildren,
		);
	}


	/**
	 * Takes an array of integer nodeids, current page nodeid, and the "ChannelIncludeExclude" type
	 * module config value, and filters the nodeids.
	 * Warning 1: the keys of the nodeids array will NOT be preserved.
	 * Warning 2: This function does NOT check any view permissions on the nodeids.
	 *
	 * @param    array    $nodeids          Array of nodeids that will be filtered. Keys will NOT be
	 *                                      preserved.
	 * @param    array    $filterNodes      Value of "ChannelIncludeExclude" type config, typically sent in
	 *                                      from templates e.g. via widgetConfig.module_filter_nodes .
	 *                                      array('include'|'exclude' => array(
	 *                                           'all'|'current'|nodeid, nodeid2, ...
	 *                                      ))
	 * @param    int      $currentNodeid    Current page's nodeid, typically sent in from templates
	 *                                      via page.nodeid .
	 *
	 * @return 	array	A subset of $nodeids that has been filtered using $filterNodes
	 */
	public function filterNodes($nodeids, $filterNodes, $currentNodeid = null)
	{
		// We need to do some array_flips() later. Let's remove any duplicates.
		$nodeids = array_unique($nodeids);

		$nodeLib = vB_Library::instance('Node');
		$closures = $nodeLib->fetchClosureParent($nodeids);
		$closuresDepthByParentChild = array();
		foreach ($closures AS $__closure)
		{
			$__parent = $__closure['parent'];
			if (!isset($closuresDepthByParentChild[$__parent]))
			{
				$closuresDepthByParentChild[$__parent] = array();
			}
			$closuresDepthByParentChild[$__parent][$__closure['child']] = intval($__closure['depth']);
		}

		// Grab the channel for the current page's nodeid, as the current page might be a topic instead
		// of a channel.
		$currentChannelid = null;
		if (!empty($currentNodeid))
		{
			$currentNode = $nodeLib->getFullContentforNodes($currentNodeid);
			$currentNode = reset($currentNode);
			$currentChannelid = $currentNode['content']['channelid'];
		}
		// note, list only worked with numerical arrays prior to PHP 7.1.0.
		//list('filterType' => $filterType, 'filterChannels' => $filterChannels) = vB_Library::instance("widget")->cleanFilterNodes($filterNodes);
		$cleaned = $this->cleanFilterNodes($filterNodes, $currentChannelid);
		$filterType = $cleaned['filterType'];
		$filterChannels = $cleaned['filterChannels'];
		$includeChildren = $cleaned['includeChildren'];

		/*
			Note, getNodes() keys the returned nodes array by nodeid, even if the provided nodeid
			list isn't keyed by nodeid, unlike getFullContentForNodes().
			Get node info for the nodeid list so that we can pull their starters & check the
			starters' vs. channels' depths. In actual use it's very likely that $nodeids will
			only be topics, but that wasn't actually ever *required*, AFAIK, so let's explicitly
			get the starters.
		 */
		$bareNodesByNodeid = $nodeLib->getNodes($nodeids, false);


		/*
			Q: If a channel is excluded/included, should we filter-out/include *only* the immediate
			children topics, or all descendant topics?
			A: Only affect immediate children, as doing so allows for *all* configuration possibilities,
			while if we affect all descendants certain configurations become impossible.

			In the future, we might want to expand the module config to add a checkbox that allows the
			admin to choose between immediate-children-only vs all descendants (immediate vs infinite).

			Edit 2018-11-01: Per new feedback, we're changing the default behavior to filter all descendant topics,
			but providing a new "include children" checkbox to maintain the old coverage.

			Set $checkDepth to -1 for infinity (affect all descendants)
			Set $checkDepth to 1 for immediate descendants only
			Reserving depth of 0 since that has real meaning/use in closure records (parent === child, self-record)
		 */
		if ($includeChildren)
		{
			$checkDepth = -1;
		}
		else
		{
			$checkDepth = 1;
		}

		/*
			$filterType : "include"|"exclude"
			$filterChannels: "all"|"current"|[(int) nodeids]
		 */
		if ($filterType === "include")
		{
			// Only include those in whitelist.
			$removeMe = array_flip($nodeids);

			if (gettype($filterChannels) === "array")
			{
				foreach ($filterChannels AS $__includeme)
				{
					if (isset($closuresDepthByParentChild[$__includeme]))
					{
						foreach($nodeids AS $__key => $__nodeid)
						{
							$__starter = $bareNodesByNodeid[$__nodeid]['starter'];
							if (isset($closuresDepthByParentChild[$__includeme][$__starter]) AND
								(
									($checkDepth < 0) OR
									$closuresDepthByParentChild[$__includeme][$__starter] === $checkDepth
								)
							)
							{
								unset($removeMe[$__nodeid]);
							}
						}
					}
				}
			}
			// handle exclusive options
			else if ($filterChannels === "all")
			{
				// no op
				$removeMe = array();
			}
		}
		else if ($filterType === "exclude")
		{
			// Exclude topics of specified channels
			$removeMe = array();

			if (gettype($filterChannels) === "array")
			{
				foreach ($filterChannels AS $__excludeme)
				{
					if (isset($closuresDepthByParentChild[$__excludeme]))
					{
						foreach($nodeids AS $__key => $__nodeid)
						{
							$__starter = $bareNodesByNodeid[$__nodeid]['starter'];
							if (isset($closuresDepthByParentChild[$__excludeme][$__starter]) AND
								(
									($checkDepth < 0) OR
									$closuresDepthByParentChild[$__excludeme][$__starter] === $checkDepth
								)
							)
							{
								$removeMe[$__nodeid] = $__key;
							}
						}
					}
				}
			}
			// handle exclusive options
			else if ($filterChannels === "all")
			{
				// We should probably block the admin from setting this combo at the frontend level
				// but if they insist on excluding all, that means they don't want any nodes...
				$removeMe = array_flip($nodeids);
			}
		}

		if (!empty($removeMe))
		{
			foreach ($removeMe AS $__nodeid => $__key)
			{
				unset($nodeids[$__key]);
			}
		}

		return array_values($nodeids);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103374 $
|| #######################################################################
\*=========================================================================*/
