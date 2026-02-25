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

// ######################## SET PHP ENVIRONMENT ###########################
error_reporting(E_ALL & ~E_NOTICE);

// ########################################################################
// ######################### START MAIN SCRIPT ############################
// ########################################################################

require_once(DIR . '/includes/class_rss_poster.php');
require_once(DIR . '/includes/functions_wysiwyg.php');

vB_Utilities::extendMemoryLimit();

@set_time_limit(0);

// #############################################################################
// slurp all enabled feeds from the database
$bf_misc_feedoptions = vB::get_datastore()->get_value('bf_misc_feedoptions');
$feeds_result = vB::getDbAssertor()->assertQuery('fetchFeeds', array('bf_misc_feedoptions_enabled' => $bf_misc_feedoptions['enabled']));
foreach ($feeds_result as $feed)
{
	// only process feeds that are due to be run (lastrun + TTL earlier than now)
	if ($feed['lastrun'] < vB::getRequest()->getTimeNow() - $feed['ttl'])
	{
		// counter for maxresults
		$feed['counter'] = 0;

		// add to $feeds slurp array
		$feeds["$feed[rssfeedid]"] = $feed;
	}
}

// #############################################################################
// extract items from feeds

$vbphrase = vB_Api::instanceInternal('phrase')->fetch(array('x_unable_to_open_url', 'x_xml_error_y_at_line_z', 'rss_feed_manager', 'announcement', 'thread'));

if (!empty($feeds))
{
	// array of items to be potentially inserted into the database
	$items = array();

	// array to store rss item logs sql
	$rsslog_insert_sql = array();

	// array to store list of inserted items
	$cronlog_items = array();

	// array to store list of forums to be updated
	$update_forumids = array();

	$feedcount = 0;
	$itemstemp = array();
	foreach (array_keys($feeds) AS $rssfeedid)
	{
		$feed =& $feeds["$rssfeedid"];

		$feed['xml'] = new vB_RSS_Poster();
		$feed['xml']->fetch_xml($feed['url']);
		if (empty($feed['xml']->xml_string))
		{
			if (defined('IN_CONTROL_PANEL'))
			{
				echo construct_phrase($vbphrase['x_unable_to_open_url'], $feed['title']);
			}
			continue;
		}
		else if ($feed['xml']->parse_xml() === false)
		{
			if (defined('IN_CONTROL_PANEL'))
			{
				echo construct_phrase($vbphrase['x_xml_error_y_at_line_z'], $feed['title'], ($feed['xml']->feedtype == 'unknown' ? 'Unknown Feed Type' : $feed['xml']->xml_object->error_string()), $feed['xml']->xml_object->error_line());
			}
			continue;
		}

		// prepare search terms if there are any
		if ($feed['searchwords'] !== '')
		{
			$feed['searchterms'] = array();
			$feed['searchwords'] = preg_quote($feed['searchwords'], '#');
			$matches = false;

			// find quoted terms or single words
			if (preg_match_all('#(?:"(?P<phrase>.*?)"|(?P<word>[^ \r\n\t]+))#', $feed['searchwords'], $matches, PREG_SET_ORDER))
			{
				foreach ($matches AS $match)
				{
					$searchword = empty($match['phrase']) ? $match['word'] : $match['phrase'];

					// Ensure empty quotes were not used
					if (!($searchword))
					{
						continue;
					}

					// exact word match required
					if (substr($searchword, 0, 2) == '\\{' AND substr($searchword, -2, 2) == '\\}')
					{
						// don't match words nested in other words - the patterns here match targets that are not surrounded by ascii alphanums below 0128 \x7F
						$feed['searchterms']["$searchword"] = '#(?<=[\x00-\x40\x5b-\x60\x7b-\x7f]|^)' . substr($searchword, 2, -2) . '(?=[\x00-\x40\x5b-\x60\x7b-\x7f]|$)#si';
					}
					// string fragment match required
					else
					{
						$feed['searchterms']["$searchword"] = "#$searchword#si";
					}
				}
			}
		}

		foreach ($feed['xml']->fetch_items() AS $item)
		{
			// attach the rssfeedid to each item
			$item['rssfeedid'] = $rssfeedid;

			if (!empty($item['summary']))
			{
				// ATOM
				$description = get_item_value($item['summary']);
			}
			elseif (!empty($item['content:encoded']))
			{
				$description = get_item_value($item['content:encoded']);
			}
			elseif (!empty($item['content']))
			{
				$description = get_item_value($item['content']);
			}
			else
			{
				$description = get_item_value($item['description']);
			}

			// backward compatability to RSS
			if (!isset($item['description']))
			{
				$item['description'] = $description;
			}
			if (!isset($item['guid']) AND isset($item['id']))
			{
				$item['guid'] =& $item['id'];
			}
			if (!isset($item['pubDate']))
			{
				if (isset($item['published']))
				{
					$item['pubDate'] =& $item['published'];
				}
				elseif(isset($item['updated']))
				{
					$item['pubDate'] =& $item['updated'];
				}
			}

			switch($feed['xml']->feedtype)
			{
				case 'atom ':
				{
					// attach a content hash to each item
					$itemtitle = (!empty($item['title']['value']) ? $item['title']['value'] : $item['title']);
					$item['contenthash'] = md5($itemtitle . $description . $item['link']['href']);
					unset($itemtitle);
					break;
				}
				case 'rss':
				default:
				{
					// attach a content hash to each item
					$item['contenthash'] = md5($item['title'] . $description . $item['link']);
				}
			}

			// generate unique id for each item
			if (is_array($item['guid']) AND !empty($item['guid']['value']))
			{
				$uniquehash = md5($item['guid']['value']);
			}
			else if (!is_array($item['guid']) AND !empty($item['guid']))
			{
				$uniquehash = md5($item['guid']);
			}
			else
			{
				$uniquehash = $item['contenthash'];
			}

			// check to see if there are search words defined for this feed
			if (is_array($feed['searchterms']))
			{
				$matched = false;

				foreach ($feed['searchterms'] AS $searchword => $searchterm)
				{
					// (search title only                     ) OR (search description if option is set..)
					if (preg_match($searchterm, $item['title']) OR ($feed['rssoptions'] & $bf_misc_feedoptions['searchboth'] AND preg_match($searchterm, $description)))
					{
						$matched = true;

						if (!($feed['rssoptions'] & $bf_misc_feedoptions['matchall']))
						{
							break;
						}
					}
					else if ($feed['rssoptions'] & $bf_misc_feedoptions['matchall'])
					{
						$matched = false;
						break;
					}
				}

				// add matched item to the potential insert array
				if ($matched AND ($feed['maxresults'] == 0 OR $feed['counter'] < $feed['maxresults']))
				{
					$feed['counter']++;
					$items["$uniquehash"] = $item;
					$itemstemp["$uniquehash"] = $uniquehash;
				}
			}
			// no search terms, insert item regardless
			else
			{
				// add item to the potential insert array
				if ($feed['maxresults'] == 0 OR $feed['counter'] < $feed['maxresults'])
				{
					$feed['counter']++;
					$items["$uniquehash"] = $item;
					$itemstemp["$uniquehash"] = $uniquehash;
				}
			}

			if (++$feedcount % 10 == 0 AND !empty($itemstemp))
			{
				$rsslogs_result = vB::getDbAssertor()->assertQuery('vBForum:rsslog', array('uniquehash' => $itemstemp));
				foreach ($rsslogs_result as $rsslog)
				{
					// remove any items which have this unique id from the list of potential inserts.
					unset($items["$rsslog[uniquehash]"]);
				}
				$itemstemp = array();
			}

		}
	}

	if (!empty($itemstemp))
	{
		// query rss log table to find items that are already inserted
		$rsslogs_result = vB::getDbAssertor()->assertQuery('vBForum:rsslog', array('uniquehash' => $itemstemp));

		foreach ($rsslogs_result as $rsslog)
		{
			// remove any items with this unique id from the list of potential inserts
			unset($items["$rsslog[uniquehash]"]);
		}
	}

	$announcementCache = array();
	if (!empty($items))
	{
		vB::getDatastore()->setOption('postminchars', 1, false);
		$error_type = (defined('IN_CONTROL_PANEL') ? vB_DataManager_Constants::ERRTYPE_CP : vB_DataManager_Constants::ERRTYPE_SILENT);
		$rss_logs_inserted = false;

		if (defined('IN_CONTROL_PANEL'))
		{
			echo "<ol>";
		}

		// process the remaining list of items to be inserted
		foreach ($items AS $uniquehash => $item)
		{
			$feed =& $feeds["$item[rssfeedid]"];
			$feed['rssoptions'] = intval($feed['rssoptions']);

			$convertHtmlToBbcode = false;
			$nl2br = false;
			if ($feed['rssoptions'] & $bf_misc_feedoptions['html2bbcode'])
			{
				$feed['rssoptions'] = $feed['rssoptions'] & ~$bf_misc_feedoptions['allowhtml'];
				$convertHtmlToBbcode = true;
				$nl2br = true;
			}

			// insert the forumid of this item into an array for the update_forum_counters() function later
			$update_forumids["$feed[forumid]"] = true;
			$bbcodeApi = vB_Api::instanceInternal('bbcode');
			switch ($feed['itemtype'])
			{
				// insert item as announcement
				case 'announcement':
				{
					// init announcement datamanager
					if ($convertHtmlToBbcode)
					{
						$pagetext = nl2br($feed['bodytemplate']);
						$pagetext = $feed['xml']->parse_template($pagetext, $item);
						$pagetext = vB_Api::instanceInternal('bbcode')->parseWysiwygHtmlToBbcode($pagetext, array('autoparselinks' => 1));
					}
					else
					{
						$pagetext = $feed['xml']->parse_template($feed['bodytemplate'], $item);
						$pagetext = vB_Api::instanceInternal('bbcode')->convertUrlToBbcode($pagetext);
					}

					$itemdata =& datamanager_init('Announcement', vB::get_registry(), $error_type);
					$itemdata->set_info('user', $feed);
					$itemdata->set('userid', $feed['userid']);
					$itemdata->set('nodeid', $feed['nodeid']);
					$itemdata->set('title', strip_bbcode(convert_wysiwyg_html_to_bbcode($feed['xml']->parse_template($feed['titletemplate'], $item))));
					$itemdata->set('pagetext', $pagetext);
					$itemdata->set('startdate', vB::getRequest()->getTimeNow());
					$itemdata->set('enddate', (vB::getRequest()->getTimeNow() + (86400 * ($feed['endannouncement'] > 0 ? $feed['endannouncement'] : 7))) - 1);
					$itemdata->set_bitfield('announcementoptions', 'allowsmilies', ($feed['rssoptions'] & $bf_misc_feedoptions['allowsmilies']) ? 1 : 0);
					$itemdata->set_bitfield('announcementoptions', 'signature', 0);
					$itemdata->set_bitfield('announcementoptions', 'allowhtml', ($feed['rssoptions'] & $bf_misc_feedoptions['allowhtml']) ? 1 : 0);
					$itemdata->set_bitfield('announcementoptions', 'allowbbcode', true);
					$itemdata->set_bitfield('announcementoptions', 'parseurl', true);

					if ($itemid = $itemdata->save())
					{
						$itemtitle = $itemdata->fetch_field('title');
						$itemlink = vB_Api::instanceInternal('route')->getUrl('admincp', array('file' => 'announcement'), array('do' => 'edit', 'a' => $itemid));
						$itemtype = 'announcement';
						$threadactiontime = 0;

						if (defined('IN_CONTROL_PANEL'))
						{
							echo "<li><a href=\"$itemlink\" target=\"feed\">$itemtitle</a></li>";
						}

						$rsslog_insert_sql[] = array(
								'rssfeedid' => $item['rssfeedid'],
								'itemid' => $itemid,
								'itemtype' => $itemtype,
								'uniquehash' => vB::getDbAssertor()->escape_string($uniquehash),
								'contenthash' => vB::getDbAssertor()->escape_string($item['contenthash']),
								'dateline' => vB::getRequest()->getTimeNow(),
								'topicactiontime' => $threadactiontime
						);

						$cronlog_items["$item[rssfeedid]"][] = "\t<li>$vbphrase[$itemtype] <a href=\"$itemlink\" target=\"logview\"><em>$itemtitle</em></a></li>";
						$announcementCache[$feed['nodeid']] = 'vB_Announcements_' . $feed['nodeid'];
					}
					break;
				}

				// insert item as thread
				case 'thread':
				default:
				{
					$pagetext = $feed['xml']->parse_template($feed['bodytemplate'], $item);
					$itemtitle = strip_bbcode(convert_wysiwyg_html_to_bbcode($feed['xml']->parse_template($feed['titletemplate'], $item)));
					if (empty($itemtitle))
					{
						$itemtitle = vB_Phrase::fetchSinglePhrase('rssposter_post_from_x', array($feed['title']));
					}

					$itemAddResult = vB_Library::instance('content_text')->add(array(
							'userid'=> $feed['userid'],
							'sticky'=> ($feed['rssoptions'] & $bf_misc_feedoptions['stickthread'] ? 1 : 0),
							'parentid' => $feed['nodeid'],
							'title' => $itemtitle,
							'rawtext' => $pagetext,
							'approved' => ($feed['rssoptions'] & $bf_misc_feedoptions['moderatethread'] ? 0 : 1),
							'showapproved' => ($feed['rssoptions'] & $bf_misc_feedoptions['moderatethread'] ? 0 : 1),
							'iconid' => (!empty($feed['iconid']) ? $feed['iconid'] : 0)
						),
						array('autoparselinks' => 1, 'nl2br' => $nl2br, 'skipDupCheck' => 1),
						$convertHtmlToBbcode
					);
					$itemid = ( !empty($itemAddResult['nodeid']) )? $itemAddResult['nodeid']:false;

					$threadactiontime = (($feed['topicactiondelay'] > 0) ? (vB::getRequest()->getTimeNow() + $feed['topicactiondelay']  * 3600) : 0);

					if ($itemid)
					{
						$itemtype = 'topic';
						$itemlink = vB_Api::instanceInternal('route')->getAbsoluteNodeUrl($itemid);
						if (defined('IN_CONTROL_PANEL'))
						{
							echo "<li><a href=\"$itemlink\" target=\"feed\">$itemtitle</a></li>";
						}

						$rsslog_insert_sql[] = array(
								'rssfeedid' => $item['rssfeedid'],
								'itemid' => $itemid,
								'itemtype' => $itemtype,
								'uniquehash' => vB::getDbAssertor()->escape_string($uniquehash),
								'contenthash' => vB::getDbAssertor()->escape_string($item['contenthash']),
								'dateline' => vB::getRequest()->getTimeNow(),
								'topicactiontime' => $threadactiontime
						);
						$cronlog_items["$item[rssfeedid]"][] = "\t<li>$vbphrase[$itemtype] <a href=\"$itemlink\" target=\"logview\"><em>$itemtitle</em></a></li>";
					}
					break;
				}
			}

			if (!empty($rsslog_insert_sql))
			{
				// insert logs
				vB::getDbAssertor()->assertQuery('replaceValues', array('table' => 'rsslog', 'values' => $rsslog_insert_sql));
				$rsslog_insert_sql = array();
				$rss_logs_inserted = true;
			}
		}

		if (defined('IN_CONTROL_PANEL'))
		{
			echo "</ol>";
		}

		if ($rss_logs_inserted)
		{
			// build cron log
			$log_items = '<ul class="smallfont">';
			foreach ($cronlog_items AS $rssfeedid => $items)
			{
				$log_items .= "<li><strong>" . $feeds[$rssfeedid]['title'] . "</strong><ul class=\"smallfont\">\r\n";
				foreach ($items AS $item)
				{
					$log_items .= $item;
				}
				$log_items .= "</ul></li>\r\n";
			}
			$log_items .= '</ul>';
		}

		if (!empty($feeds))
		{
			// update lastrun time for feeds
			vB::getDbAssertor()->update('vBForum:rssfeed', array('lastrun' => vB::getRequest()->getTimeNow()), array('rssfeedid' => array_keys($feeds)));
		}
	}
}

// #############################################################################
// check for threads that need time-delay actions
$threads_result = vB::getDbAssertor()->assertQuery('fetchRSSFeeds', array('TIMENOW' => vB::getRequest()->getTimeNow()));
$threads = array();
foreach ($threads_result as $thread)
{
	if ($thread['options'] & $bf_misc_feedoptions['unstickthread'])
	{
		vB_Api::instanceInternal('node')->setSticky(array($thread['nodeid']), false);
	}

	if ($thread['options'] & $bf_misc_feedoptions['closethread'])
	{
		vB_Api::instanceInternal('node')->closeNode($thread['nodeid']);
	}

	$threads[] = $thread['itemid'];
}

// don't work with those items again
if (!empty($threads))
{
	vB::getDbAssertor()->update('vBForum:rsslog', array('topicactioncomplete' => 1), array('itemid' => $threads, 'itemtype' => 'topic'));
}

if (!empty($announcementCache))
{
	vB_Cache::instance(vB_Cache::CACHE_STD)->event($announcementCache);
}

// #############################################################################
// all done

if (defined('IN_CONTROL_PANEL'))
{
	echo "<p><a href=\"admincp/rssposter.php" . vB::getCurrentSession()->get('sessionurl_q') . "\">$vbphrase[rss_feed_manager]</a></p>";
}

if ($log_items)
{
	log_cron_action($log_items, $nextitem, 1);
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103189 $
|| #######################################################################
\*=========================================================================*/
