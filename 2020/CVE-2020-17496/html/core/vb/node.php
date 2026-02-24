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
 * @package vBulletin
 */
class vB_Node
{
	use vB_Trait_NoSerialize;

	/**
	 * Calculates textcount, textunpubcount, totalcount, totalunpubcount for a nodeid.
	 * Used for fixing node counts and for verifying integrity
	 * @param int $nodeId
	 * @return array
	 */
	public static function getCounts($nodeId)
	{
		$excluded = self::getExcludedTypes();
		$counts = vB::getDbAssertor()->getRow('vBForum:getContentCounts', array('excludeTypes' => $excluded, 'parentid' => $nodeId));
		return $counts;
	}

	/**
	 *	Returns the content types that don't affect node counts and last data.
	 *
	 */
	public static function getExcludedTypes()
	{
		static $exclude = array();
		if (empty($exclude))
		{
			$types = vB_Types::instance()->getContentTypes();
			foreach ($types as $className => $type)
			{
				try
				{
					if (class_exists('vB_Api_Content_' . $type['class'], true))
					{
						$contentAPI = vB_Api::instanceInternal('Content_' . $type['class']);
						if ($contentAPI->getTextCountChange() == 0)
						{
							$exclude[] = $type['id'];
						}
					}
				}
				catch(exception $e)
				{

				}
			}
		}

		return $exclude;
	}

	/**
	 * Verifies integrity of a node in db. Checks "last" data, counts, that it has a route, etc.
	 *
	 * Note that this is intended for testing and diagnostics and may be slow
	 *
	 * @param 	mixed		node record. Should have at least the information from node library getNode().
	 * @return	mixed	either true or an array of error strings
	 *
	 * @deprecated.  This is currently only used by the unit tests and there is a replacement module
	 * 	for that.  We are unlikely to need this as part of the app proper and if there is need for
	 * 	a standalone test we can adapt the test module (which is designed to not be tightly coupled
	 * 	to the test code).
	 */
	public static function validateRecord($record)
	{
		static $rootid = null;
		if (!$rootid)
		{
			$rootid = (int) vB_Api::instanceInternal('content_channel')->fetchChannelIdByGUID(vB_Channel::MAIN_CHANNEL);
		}

		$db = vB::getDbAssertor();
		$result['errors'] = array();

		// -- VERIFY ROUTE --
		// @TODO remove the check and check for all types when photo and attachs have routeid
		$photoType = vB_Types::instance()->getContentTypeID('vBForum_Photo');
		$attachType = vB_Types::instance()->getContentTypeID('vBForum_Attach');
		if (!in_array($record['contenttypeid'], array($photoType, $attachType)) AND !intval($record['routeid']))
		{
			$result['errors'][] = "Invalid routeid for node: " . $record['nodeid'] . " should be greater than 0";
		}

		// -- VERIFY COUNTS --
		$counts = self::getCounts($record['nodeid']);
		foreach($counts as $key=>$count)
		{
			if ($count == NULL)
			{
				$count = 0;
			}

			if (!isset($record[$key]))
			{
				$result['errors'][] = "Couldn't check $key";
			}
			else if ($record[$key] != $count)
			{
				$result['errors'][] = "Invalid count: $key values do not match (current:{$record[$key]} - expected:$count)";
			}
		}

		// -- VERIFY SHOW PUBLISHED --
		// This could be a little more rigorous by checking parent status and making sure that the showpublished is
		// completely right.  However for now we'll simply make sure that if the node isn't published showpublished
		// isn't on (since we've seen that problem in the wild.

		$timenow =  vB::getRequest()->getTimeNow();
		if ($record['publishdate'] > $timenow OR ($record['unpublishdate'] > 0 AND $record['unpublishdate'] <= $timenow))
		{
			if ($record['showpublished'] == 1)
			{
				$result['errors'][] = "Node is not published but showpublished is true";
			}
		}

		// -- VERIFY LAST DATA --
		if (($counts['textcount'] + $counts['totalcount']) > 0)
		{
			//verify lastcontentid value is valid
			if (intval($record['lastcontentid']) == 0)
			{
				$result['errors'][] = 'Invalid lastcontentid value: the node has children that are not reflected in last content value';
			}
			else
			{
				// verify last content exists
				$excluded = self::getExcludedTypes();
				$lastcontent = $db->getRow('vBForum:getLastData', array(
					'parentid' => $record['nodeid'],
					'timenow' => vB::getRequest()->getTimeNow(),
					'excludeTypes' => $excluded
				));

				if (!$lastcontent)
				{
					$result['errors'][] = 'Couldn\'t find last content';
				}
				else
				{
					$skipCheck = false;

					if ($lastcontent['nodeid'] != $record['lastcontentid'])
					{
						$checkLast = vB_Library::instance('node')->getNode($lastcontent['nodeid']);

						if ($checkLast['publishdate'] == $record['lastcontent'])
						{
							//The selected last is just as good.
							$skipCheck = true;
						}
						else
						{
							$result['errors'][] = "Invalid lastcontentid: values do not match (expected:{$lastcontent['nodeid']} - current:{$record['lastcontentid']})";
						}
					}

					if (!$skipCheck)
					{
						if ($lastcontent['authorname'] != $record['lastcontentauthor'])
						{
							$result['errors'][] = "Invalid lastcontentauthor: values do not match (expected:{$lastcontent['authorname']} - current:{$record['lastcontentauthor']})";
						}

						if ($lastcontent['userid'] != $record['lastauthorid'])
						{
							$result['errors'][] = "Invalid lastauthorid: values do not match (expected:{$lastcontent['userid']} - current:{$record['lastauthorid']})";
						}
					}
				}
			}
		}
		// If the counts are zero, then there should be NO child that's approved and published
		else
		{
			$excluded = self::getExcludedTypes();
			$row = vB::getDbAssertor()->getRow('vBForum:getApprovedAndPublishedChildren',
				array(
					'excluded' => $excluded,
					'parentid' => $record['nodeid']
				)
			);

			if (!is_null($row))
			{
				$result['errors'][] = "Incorrect total count. Node {$record['nodeid']} should have 0 approved & published children.";
			}

		}

		//check to see that getNodeContent returns valid information. This will delete some kinds of failure in search or node API's.
		$nodeid = $record['nodeid'];
		$node = vB_Library::instance('node')->getNodeContent($nodeid);

		if (empty($node) OR empty($node[$nodeid]) OR empty($node[$nodeid]['userid']))
		{
			$result['errors'][] = "getNodeContent for $nodeid fails- probably a permissions error;";
		}

		// check that the node has a parent. Only nodeid = 1 should lack a parent.
		// Check for !empty($node[$nodeid]) to not propagate on any getNodeContent failures
		if (intval($nodeid) !== $rootid)
		{
			if (!empty($node[$nodeid]) AND intval($node[$nodeid]['parentid']) < 1)
			{
				$result['errors'][] = "Node $nodeid does not seem to have a valid parentid (found:{$node[$nodeid]['parentid']}). Only nodeid=1 should have a parentid of 0";
			}
			else // we have a valid parentid for all but the first node, so we can do some checks
			{
				/* If the node has open=1 & showopen=0, its parent must have showopen=0 (VBV-9700)
				 * Rather than checking for this specific case, let's do a general check of
				 * node.showopen = (node.open AND parent.showopen)
				 */
				// first we need the parent info
				$parentid = $node[$nodeid]['parentid'];
				$parent = vB_Library::instance('node')->getNodeContent($parentid);
				if (empty($parent) OR empty($parent[$parentid]) OR !isset($parent[$parentid]['showopen']))
				{
					$result['errors'][] = "getNodeContent for $parentid (parent of $nodeid) fails- probably a permissions error;";
				}
				else
				{
					// do a general check of node.showopen = (node.open AND parent.showopen)
					// this should also catch the case where node.open = 0 & node.showopen = 1, which should never happen.
					if ($node[$nodeid]['showopen'] != ($node[$nodeid]['open'] AND $parent[$parentid]['showopen']))
					{
						$result['errors'][] = "Invalid showopen value: Node showopen={$node[$nodeid]['showopen']} but has node.open={$node[$nodeid]['open']} and parent.showopen={$parent[$parentid]['showopen']}";
					}
				}
			}
		}

		if (empty($result['errors']))
		{
			return true;
		}
		else
		{
			return $result;
		}
	}


	public static function validateClosure($nodeid)
	{
		static $rootid = null;
		if (!$rootid)
		{
			$rootid = (int) vB_Api::instanceInternal('content_channel')->fetchChannelIdByGUID(vB_Channel::MAIN_CHANNEL);
		}

		$db = vB::getDbAssertor();
		$result = array('errors' => array());
		$closures = $db->getRows('vBForum:closure',
			array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT, 'child' => $nodeid),
			array('field' => 'depth', 'direction' => vB_dB_Query::SORT_ASC)
		);


		$nodeids = array();
		foreach($closures as $closure)
		{
			$nodeids[] = $closure['parent'];
		}

		$nodes = $db->getRows('vBForum:node',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'nodeid' => $nodeids,
				vB_dB_Query::COLUMNS_KEY => array('nodeid', 'parentid')
			),
			false,
			'nodeid'
		);

		$depth = 0;
		$nextparent = $nodeid;
		$foundRoot = false;
		foreach($closures as $closure)
		{
			if ($foundRoot)
			{
				$result['errors'][] = "Found root, but it was not the last closure record";
			}

			else if ($closure['depth'] != $depth)
			{
				$result['errors'][] = "Expected depth of $depth, found depth of " . $closure['depth'];
			}

			else if ($closure['parent'] != $nextparent)
			{
				$result['errors'][] = "Expected parent at depth of $depth to be $nextparent, found parent " . $closure['parent'];
			}

			if ($nextparent == $rootid)
			{
				$foundRoot = true;
			}

			if (isset($nodes[$nextparent]))
			{
				$nextparent = $nodes[$nextparent]['parentid'];
			}
			else
			{
				$result['errors'][] = "Did not find node for parent $nextparent";
			}
			$depth++;
		}

		if (!$foundRoot)
		{
			$result['errors'][] = "Root was not amoung the nodes parents";
		}

		if (empty($result['errors']))
		{
			return true;
		}
		else
		{
			return $result;
		}
	}

	/**
	 * This method fixes the count values for a node
	 * @param int $nodeId - Node to fix
	 */
	public static function fixNodeCount($nodeId)
	{
		$counts = self::getCounts($nodeId);
		$changes = array(
			'textcount'=> $counts['textcount'],
			'textunpubcount'=> $counts['textunpubcount'],
			'totalcount' => $counts['totalcount'],
			'totalunpubcount' => $counts['totalunpubcount'],
		);

		vB::getDbAssertor()->update('vBForum:node', $changes, array('nodeid' => $nodeId));
		vB_Cache::allCacheEvent("nodeChg_" .$nodeId);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102549 $
|| #######################################################################
\*=========================================================================*/
