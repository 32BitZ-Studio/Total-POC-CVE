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
 * vB_Api_Vb4_album
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Vb4_album extends vB_Api
{
	public function updatealbum($description, $title, $albumtype, $albumid = null)
	{
		$cleaner = vB::getCleaner();
		$description = $cleaner->clean($description, vB_Cleaner::TYPE_STR);
		$title = $cleaner->clean($title, vB_Cleaner::TYPE_STR);
		$albumtype = $cleaner->clean($albumtype, vB_Cleaner::TYPE_STR);
		$albumid = $cleaner->clean($albumid, vB_Cleaner::TYPE_UINT);

		// TODO: Implement when vB5 is more well defined on this feature.

		$result = array();
		if ($result === null || isset($result['errors']))
		{
			return vB_Library::instance('vb4_functions')->getErrorResponse($result);
		}

		return array(
			'response' => array(
				'errormessage' => 'album_added_edited',
			),
		);
	}

	public function user($pagenumber = 1, $userid = null)
	{
		$cleaner = vB::getCleaner();
		$pagenumber = $cleaner->clean($pagenumber, vB_Cleaner::TYPE_UINT);
		$userid = $cleaner->clean($userid, vB_Cleaner::TYPE_UINT);

		if ($userid < 1)
		{
			$userinfo = $loggedUser = vB_Api::instance('user')->fetchUserinfo();
			$userid = $userinfo['userid'];
		}
		else
		{
			$userinfo = vB_Api::instance('user')->fetchUserinfo($userid);
			$loggedUser = vB_Api::instance('user')->fetchUserinfo();
		}

		$result = vB_Api::instance('profile')->fetchMedia(array('userId' => $userid), $pagenumber);
		if ($result === null || isset($result['errors']))
		{
			return vB_Library::instance('vb4_functions')->getErrorResponse($result);
		}

		$albumbits = array();

		// TODO: Implement when vB5 is more well defined on this feature.

		// Setting the $show params
		$isOwner = ($userinfo['userid'] == $loggedUser['userid']) ? 1 : 0;
		// This is the way moderated is resolved in vb4.
		//
		// 'canmoderatepictures' is not used in vb5
		// $album['moderation'] is determined by the User profile: Album options -> Picture Moderation (albums_pictures_moderation)
		//
		// if ($album['moderation'] AND (can_moderate(0, 'canmoderatepictures') OR $vbulletin->userinfo['userid'] == $album['userid']))


		return array(
			'response' => array(
				'userinfo' => vB_Library::instance('vb4_functions')->filterUserInfo($userinfo),
				'albumbits' => $albumbits,
			),
			'show' => array(
				'add_album_option' => $isOwner,
				'personalalbum' => 0, //TODO: Change this when VBV-9148 is fixed. There is no such thing as private albums in vb5 atm.
				'moderated' => 0, // TODO: Change this when moderation of album pictures is respected
			),
		);
	}

	public function album($albumid, $pagenumber = 1, $perpage = 10)
	{
		$cleaner = vB::getCleaner();
		$pagenumber = $cleaner->clean($pagenumber, vB_Cleaner::TYPE_UINT);
		$perpage = $cleaner->clean($perpage, vB_Cleaner::TYPE_UINT);
		$nodeid = $cleaner->clean($albumid, vB_Cleaner::TYPE_UINT);

		// Referenced profile_textphotodetail.xml
		$mediaFilters = array(
			'nodeid' => $nodeid,
			'page' => $pagenumber,
			'perpage' => $perpage,
		);
		$album = vB_Api::instance('profile')->getAlbum($mediaFilters);
		if ($album === null || isset($album['errors']))
		{
			return vB_Library::instance('vb4_functions')->getErrorResponse($album);
		}
		$album = $album[$nodeid];

		$picturebits = array();
		/*
		picturebits] => Array
                (
                    [0] => Array
                        (
                            [picture] => Array
                                (
                                    [attachmentid] => 76
                                    [caption_preview] => jellyfish
                                    [thumbnail_dateline] => 1430495328
                                    [hasthumbnail] => 1
                                    [pictureurl] => http://dev-vb3.internetbrands.com/mobile/vb423/attachment.php?s=f24a0cc5ae745afaae4304ab144f0a6f&amp;api=1&amp;attachmentid=76&thumb=1&stc=1&d=1430495328
                                    [picturefullurl] => http://dev-vb3.internetbrands.com/mobile/vb423/attachment.php?s=f24a0cc5ae745afaae4304ab144f0a6f&amp;api=1&amp;attachmentid=76&d=1430495328
                                )

                            [show] => Array
                                (
                                    [moderation] => 0
                                )

                        )
		 */
		$bbcodeParserInstance = new vB_Library_BbCode(true, true);
		foreach ($album['photo'] AS $photo)
		{
			$pictureUrl = $bbcodeParserInstance->getAttachmentLink($photo);
			$thumbUrl = $pictureUrl . "&type=thumb";
			$picturebits[] = array(
				'picture' => array(
					'attachmentid' => intval($photo['nodeid']),
					'caption_preview' => $photo['shortcaption'],
					'thumbnail_dateline' => $photo['publishdate'], // Or lastupdate ?
					'hasthumbnail' => 1, // TODO
					'pictureurl' => $thumbUrl,
					'picturefullurl' => $pictureUrl,
				),
				'show' => array(
					// TODO, moderation?
				),
			);
		}

		// https://admin.vbulletin.com/wiki/VB4_API_Common_Array:Pagenav_Array
		$pagenav = vB_Library::instance('vb4_functions')->pageNav($pagenumber, $perpage, $album['photocount']);
		// https://admin.vbulletin.com/wiki/VB4_API:album_album
		return array(
			'response' => array(
				'albuminfo' => array(
					'albumid' => $album['nodeid'],
					'title' => $album['title'],
					'description' => $album['description'],
				),
				'userinfo' => array(
					'userid' => $album['userid'],
					'username' => $album['authorname'],
				),
				'pagenav' => $pagenav,
				'pagenumber' => $pagenumber,
				'totalpages' => $perpage,
				'picturebits' => $picturebits,
				'total' => $album['photocount'],
				'start' =>0,	// TODO
				'end' =>0,		// TODO

			),
			'show' => array(
				'private_notice' => ($album['viewperms'] == 0),
				'edit_album_option' => 0, // TODO
				'personalalbum' => ($album['viewperms'] == 0),
			),
		);
	}


	public function picture($albumid, $attachmentid, $pagenumber = 1, $perpage = 10, $commentid = 0, $showignored = false)
	{
		$cleaner = vB::getCleaner();
		$pagenumber = $cleaner->clean($pagenumber, vB_Cleaner::TYPE_UINT);
		$perpage = $cleaner->clean($perpage, vB_Cleaner::TYPE_UINT);
		$albumid = $cleaner->clean($albumid, vB_Cleaner::TYPE_UINT);
		$photoid = $cleaner->clean($attachmentid, vB_Cleaner::TYPE_UINT);

		$mediaFilters = array(
			'nodeid' => $albumid,
		);
		$album = vB_Api::instance('profile')->getAlbum($mediaFilters);
		if ($album === null || isset($album['errors']))
		{
			return vB_Library::instance('vb4_functions')->getErrorResponse($album);
		}
		$album = $album[$albumid];

		$picturecomment_commentarea  = array(
			// TODO
			'messagestats' => array(
				'total' => 0,
				'start' => 1,
				'end' => 0,
				'perpage' => 10,
			),
		);

		$pictureinfo = array();
		/*
	            [pictureinfo] => Array
                (
                    [attachmentid] => 74
                    [albumid] => 2
                    [caption_censored] =>
                    [pictureurl] => http://dev-vb3.internetbrands.com/mobile/vb423/attachment.php?s=13eb2009e65d8e94b851981f629eb094&amp;api=1&amp;attachmentid=74&d=1430433269
                    [caption_html] =>
                    [addtime] => 1430433269
                )

            [pic_location] => Array
                (
                    [prev_attachmentid] => 76
                    [prev_text] =>
                    [prev_text_short] =>
                    [next_attachmentid] => 73
                    [next_text] =>
                    [next_text_short] =>
                    [pic_position] => 2
                )
		 */
		$userinfo = vB_Api::instance('user')->fetchUserinfo();
		$currentUserid = $userinfo['userid'];
		$picture_owner = false;
		$bbcodeParserInstance = new vB_Library_BbCode(true, true);
		$prev_attachmentid = NULL;
		$next_attachmentid = NULL;
		$picposition = 0;
		foreach ($album['photo'] AS $photo)
		{
			$picposition++;
			if ($photo['nodeid'] != $photoid)
			{
				$prev_attachmentid = $photo['nodeid'];
				continue;
			}
			if (!empty($pictureinfo))
			{
				$next_attachmentid = $photo['nodeid'];
				break;
			}

			$picture_owner = ($photo['userid'] == $currentUserid);
			$pictureUrl = $bbcodeParserInstance->getAttachmentLink($photo);
			$pictureinfo = array(
				'attachmentid' => $photo['nodeid'],
				'albumid' => $albumid,
				'pictureurl' => $pictureUrl,
				'caption_censored' => '', // TODO
				'caption_html' => '', // TODO
				'addtime' => $photo['publishdate'],
			);
		}

		$pic_location = array(
			'prev_attachmentid' => $prev_attachmentid,
			'prev_text' => '', //TODO
			'prev_text_short' => '', //TODO
			'next_attachmentid' => $next_attachmentid,
			'next_text' => '', //TODO
			'next_text_short' => '', //TODO
			'pic_position' => $picposition,
		);
		// https://admin.vbulletin.com/wiki/VB4_API:album_picture
		return array(
			'response' => array(
				'albuminfo' => array(
					'albumid' => $album['nodeid'],
					'title' => $album['title'],
					'description' => $album['description'],
				),
				'userinfo' => array(
					'userid' => $album['userid'],
					'username' => $album['authorname'],
				),
				'picturecomment_commentarea ' => $picturecomment_commentarea,
				'pictureinfo' => $pictureinfo,
				'pic_location' => $pic_location,
			),
			'show' => array(
				'picture_owner' => $picture_owner,
				'edit_album_option' => 0, // TODO
				'add_group_link' => 0, // TODO
				'reportlink' => 1, // TODO
				'moderation' => 0, // TODO
				'picturecomment_options' => 0, // TODO
			),
		);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102386 $
|| #######################################################################
\*=========================================================================*/
