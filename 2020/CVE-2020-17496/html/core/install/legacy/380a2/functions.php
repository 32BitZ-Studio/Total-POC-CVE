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

//from old functions_album.php file
/**
 * Rebuilds Album Update cache
 */
function exec_rebuild_album_updates()
{
	global $vbulletin;

	$vbulletin->db->query_write("TRUNCATE " . TABLE_PREFIX . "albumupdate");

	if (!$vbulletin->options['album_recentalbumdays'])
	{
		return;
	}

	$results = $vbulletin->db->query_read("
		SELECT album.albumid, album.userid, album.lastpicturedate, user.usergroupid, user.infractiongroupids, user.infractiongroupid
		FROM " . TABLE_PREFIX . "album AS album
		INNER JOIN " . TABLE_PREFIX . "user AS user ON (album.userid = user.userid)
		WHERE lastpicturedate > " . (TIMENOW - $vbulletin->options['album_recentalbumdays'] * 86400) . "
			AND state = 'public'
			AND visible > 0
	");

	$recent_updates = array();
	while ($result = $vbulletin->db->fetch_array($results))
	{
		cache_permissions($result, false);

		if ((4 != $result['permissions']['usergroupid']) AND (4 != $result['infractiongroupid']) AND ($result['permissions']['albumpermissions'] & $vbulletin->bf_ugp_albumpermissions['canalbum']))
		{
			$recent_updates[] = "($result[albumid], $result[lastpicturedate])";
		}
	}
	$vbulletin->db->free_result($results);

	if (sizeof($recent_updates))
	{
		$vbulletin->db->query_write("
			INSERT INTO " . TABLE_PREFIX . "albumupdate
				(albumid, dateline)
			VALUES
				" . implode (',', $recent_updates) . "
		");
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| #######################################################################
\*=========================================================================*/
