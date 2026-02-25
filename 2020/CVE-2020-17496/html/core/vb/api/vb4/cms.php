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
 * vB_Api_Vb4_Cms
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Vb4_Cms extends vB_Api
{
	public function content_call($nodeid)
	{
		// not sure if this will ever be called by client,
		// this would be called if vB_Api::cms_vb4_to_vb5_method_mapping()
		// fails to map the "action" to a known function.
		// Just default to content view.
		return $this->content_view($nodeid);
	}

	private function content_delete($node)
	{
		// not implemented as client does not use it.
	}

	private function content_apply($node)
	{
		/*
			Based on CmsViewPostServerRequest &
			vBCms_Content_Article::saveData()
		 */
		$cleaner    = vB::getCleaner();
		$input = $cleaner->cleanArray($_REQUEST, array(
			'loggedinuser'        => vB_Cleaner::TYPE_UINT, // todo: what do we do with this? Probably ignore?
			'postid'              => vB_Cleaner::TYPE_UINT, // contentId (nodeid in vB5), not used.
			//'do'                 => vB_Cleaner::TYPE_STR, // do = "apply" if we got here
			'wysiwyg'             => vB_Cleaner::TYPE_BOOL, // always set to 0 by app
			'message'             => vB_Cleaner::TYPE_STR,
			'posthash'            => vB_Cleaner::TYPE_STR,

			/*
				I thought poststarttime might have something to do with publishdate, but it seems
				like in vB4, the posthash was created from
				md5(poststarttime . userid . salt) .
				In vB5, the posthash is created just from fetch_random_password(), so we don't have
				anything to validate using this...
			 */
			'poststarttime'       => vB_Cleaner::TYPE_UINT, // unused, see note above
			/*
	private static final String PARAM_PUBLISH_DATE = "publishdate";
	private static final String PARAM_PUBLISH_TIME = "publishtime[%s]";
	private static final String TIME_HOUR_OPT = "hour";
	private static final String TIME_MINUTE_OPT = "minute";
	private static final String DATE_FORMAT_PATTERN = "yyyy/MM/dd";
	private static final DateFormat postDateDf = new SimpleDateFormat(DATE_FORMAT_PATTERN);
				if (publishDate != null)
				{
					postParams.add(new BasicNameValuePair(PARAM_PUBLISH_DATE, postDateDf.format(publishDate)));
					postParams.add(new BasicNameValuePair(String.format(PARAM_PUBLISH_TIME, TIME_HOUR_OPT), String.valueOf(publishDate.getHours())));
					postParams.add(new BasicNameValuePair(String.format(PARAM_PUBLISH_TIME, TIME_MINUTE_OPT), String.valueOf(publishDate.getMinutes())));
				}
			*/
			'publishdate'         => vB_Cleaner::TYPE_STR,	 // "yyyy/MM/dd"

			'publishtime'         => vB_Cleaner::TYPE_ARRAY_UINT,
			/*
			'publishtime[hour]'   => vB_Cleaner::TYPE_UINT, // e.g. 20 for 8:36 PM
			'publishtime[minute]' => vB_Cleaner::TYPE_UINT, // e.g. 36 for 8:36PM
			 */


			'setpublish'          => vB_Cleaner::TYPE_BOOL, // 1 | 0
			'categoryids'         => vB_Cleaner::TYPE_ARRAY_UINT,
			'cms_node_title'      => vB_Cleaner::TYPE_STR,
			'comments_enabled'    => vB_Cleaner::TYPE_BOOL, // 1 | 0

			// unused by the app
			//'cms_node_url'     => vB_Cleaner::TYPE_STR,
			//'url'              => vB_Cleaner::TYPE_NOHTML,
			//'title'            => vB_Cleaner::TYPE_NOHTML, // app passes in cms_node_title but not title
			//'html_title'       => vB_Cleaner::TYPE_NOHTML,
			//'publicpreview'    => vB_Cleaner::TYPE_UINT,
			//'new_parentid'     => vB_Cleaner::TYPE_UINT,
			//'parseurl'         => vB_Cleaner::TYPE_BOOL,
			//'htmlstate'        => vB_Cleaner::TYPE_NOHTML,
			//'keepthread'       => vB_Cleaner::TYPE_UINT,
			//'allcomments'      => vB_Cleaner::TYPE_UINT,
			//'movethread'      => vB_Cleaner::TYPE_UINT,
		));

		if (isset($node['nodeid']))
		{
			$nodeid = $node['nodeid'];
		}
		else
		{
			// this is a new article creation.
			$nodeid = null;
		}
		$contentApi = vB_Api_Content::getContentApi($node['contenttypeid']);

		// todo: categoryids
		/*
			categoryids is all kinds of weird.
			It holds an array of categoryid's, and each id is matched up with
			a cb_category_{id} post param.
			In vB4, if categoryids input wasn't set, it didn't update categories at all.
			If it was set, then it kept (or added) any categoryid that was paired with
			a cb_category_{id} input, and removed any that wasn't paired.

			See vBCms_Dm_Content::postSave() for the vB4 code.

			Note: Seems like trying to change categories is broken on the android app - VBA-704
		 */
		// tags should be a comma-delimited string of tags
		$tagsList = array();
		if (!empty($input['categoryids']))
		{
			$tagids = array();
			foreach ($input['categoryids'] AS $__tagid)
			{
				if (isset($_POST['cb_category_' . $__tagid]))
				{
					$tagids[] = $__tagid;
				}
			}

			$rows = vB::getDbAssertor()->getRows('vBForum:tag', array('tagid' => $tagids));
			foreach ($rows AS $__tag)
			{
				$tagsList[] = $__tag['tagtext'];
			}
		}
		else
		{
			if (isset($nodeid))
			{
				// If categoryids isn't there, do not change tags.
				$tagsList = vB_Api::instance('tags')->getTagsList($nodeid);
			}
		}
		$tags = implode(',', $tagsList);

		$data = array(
			'rawtext' => $input['message'],
			'title' => $input['cms_node_title'],
			'tags' => $tags,
			// allow_post is converted & saved into the nodeoptions
			// by the content API
			'allow_post' => $input['comments_enabled'],
		);


		/*
			This probably needs a bit more investigation & revision. For e.g.
			we need to find out if setpublish is always set to 1 as expected for
			immediate publish & future publish, and 0 for save as draft.

			In the createcontent controller, the way we handle save as draft is
			'publish_now' is set to false, which then sets publishdate to 0
			(& node.publishdate == 0 is how we represent the "draft" state).

			For future publishing, we'd just set the publishdate to the future.

			And of course, the content API will do the permission checks and
			discard the values if the user doesn't have permission to
			pub/unpub/future-pub
		 */
		$publishdate = 0;
		if ($input['setpublish'])
		{
			// publishdate is in the format 'yyyy/MM/dd' hard-coded in the app,
			// and we need to extract the year/month/date... let's just go with
			// explode() rather than going through a date parser.
			// todo: TZ conversions between app & server?? Does the app use
			// the user's TZ offset??
			list($publishYear, $publishMonth, $publishDay) = explode("/", $input['publishdate']);

			// hour is in 24-hour format

			// taken from createcontent -> getPublishDate()
			$dateInfo = array(
				'hour' => $input['publishtime']['hour'],
				'minute' => $input['publishtime']['minute'],
				'month' =>  $publishMonth,
				'day' => $publishDay,
				'year' => $publishYear,
			);
			$publishdate = vB_Api::instance('user')->vBMktime($dateInfo);
			// todo: See if the app sends something specific for the publishdate/time
			// for a "PUBLISH NOW" option
		}
		else
		{
			// Save as draft.
			$data['publish_now'] = false; // we need this set for save-as-draft to go through.
			$publishdate = 0;
			// Note, saving an existing article as a draft does not work, see VBV-17278
		}
		// todo: test above once VBA-707 is resolved.

		$data['publishdate'] = $publishdate;


		// Currently, there's no way to pass options into an update call.
		// To get around newlines being stripped from mobile updates, there's a
		// nl2br data field for update() calls...
		// The app always sets wysiwyg to false, so other stuff might get corrupted
		// or stripped due to going through the wysiwyghtml -> bbcode parser...
		// see VBV-16386 and VBV-9886 for related info.
		if (!$input['wysiwyg'])
		{
			$data['nl2br'] = true;
		}

		if (isset($nodeid))
		{
			// Do the update
			$result = $contentApi->update($nodeid, $data);
			if (!empty($result['errors']))
			{
				return vB_Library::instance('vb4_functions')->getErrorResponse($result);
			}
		}
		else
		{
			// new content.
			$data['parentid'] = $node['parentid'];
			// see not eabove about newlines...
			unset($data['nl2br']);
			$options = array('wysiwyg' => (bool) $input['wysiwyg']);


			// Do the add
			$result = $contentApi->add($data, $options);
			// if we didn't get a numeric nodeid, something went sideways.
			if (empty($result) OR !is_numeric($result) OR !empty($result['errors']))
			{
				return vB_Library::instance('vb4_functions')->getErrorResponse($result);
			}
			$nodeid = intval($result);
		}

		// The app first makes a newattachment_manageattach call before the content_view?do=apply call
		// to save the filedata & generate the posthash. The posthash passed into this call should already
		// be saved, and the call below will link the filedata to this article node.
		vB_Library::instance('vb4_posthash')->appendAttachments($nodeid, $input['posthash']);

		return $this->content_view($nodeid);
	}

	private function getUserLangDateTimeOverrides()
	{
		$userinfo = vB_Api::instance('user')->fetchUserinfo();
		$options = vB::getDatastore()->getValue('options');

		if ($userinfo['lang_dateoverride'] != '')
		{
			$dateformat = $userinfo['lang_dateoverride'];
		}
		else
		{
			$dateformat = $options['dateformat'];
		}

		if ($userinfo['lang_timeoverride'] != '')
		{
			$timeformat = $userinfo['lang_timeoverride'];
		}
		else
		{
			$timeformat = $options['timeformat'];
		}

		return array(
			'dateformat' => $dateformat,
			'timeformat' => $timeformat,
		);
	}

	private function getSectionSubContentsArray($channelNode, $page, $perpage)
	{
		// TODO: should this array also have any section data?

		$result = $this->searchArticles($channelNode['nodeid'], $page, $perpage);

		return $this->getSubContentsArrayFromSearchResult($result);
	}

	private function getSubContentsArrayFromSearchResult($result)
	{
		$contents = array();

		if ($result === null || isset($result['errors']))
		{
			return $result;
		}

		$options = vB::getDatastore()->getValue('options');
		$dateformat = $this->getUserLangDateTimeOverrides();

		// images in mapi generally require the session suffix.
		// The preview image *might* not need it since some of them might be
		// public, but easier to just add this now.
		$sessionSuffix = "";
		$session = vB::getCurrentSession();
		if (!empty($session))
		{
			$sessionSuffix = $session->get('dbsessionhash');
			if (!empty($sessionSuffix))
			{
				// This is going to be part of a URL
				$sessionSuffix = '&s=' . urlencode($sessionSuffix);
			}
		}

		$channelTypeId = vB_Types::instance()->getContentTypeID('vBForum_Channel');
		$channelURLsByRouteid = array();

		foreach ($result['results'] AS $__article)
		{
			// get "section_url" field...
			$isChannel = ($__article['contenttypeid'] == $channelTypeId);
			if ($isChannel)
			{
				if (!isset($channelURLsByRouteid[$__article['routeid']]))
				{
					$channelURLsByRouteid[$__article['routeid']] = $this->safeBuildUrl($__article['routeid'], $__article);
				}

				$channelUrl = $channelURLsByRouteid[$__article['routeid']];
			}
			else
			{
				$parentNode = vB_Library::instance('node')->getNodeBare($__article['parentid']);
				$parentRouteid = $parentNode['routeid'];
				if (!isset($channelURLsByRouteid[$parentRouteid]))
				{
					$channelURLsByRouteid[$parentRouteid] = $this->safeBuildUrl($parentRouteid, $parentNode);
				}

				$channelUrl = $channelURLsByRouteid[$parentRouteid];
			}


			$routeData = array(
				'nodeid' => $__article['nodeid'],
				'title'  => $__article['title'],
			);
			$articleUrl = $this->safeBuildUrl($__article['routeid'], $routeData);

			// todo: Do we actually have any support for preview video? It seems like we have the text.previewvideo
			// field, but not sure if anything uses it.
			$previewVideo = "";
			$previewImage = "";
			// todo: content.previewtext is there, but I think it has to be populated by a render first???
			// getPreviewText() looks ugly. Even though it's probably more expensive, let's do the full parse so
			// we can get the prettier previewtext
			//$previewText = vB_String::getPreviewText($__article['content']['rawtext']);
			list( , , , $previewText) = vB_Library::instance('vb4_functions')->parseArticle($__article, 1);
			$previewChopped = ($__article['content']['rawtext'] != $previewText); // todo: is this right?

			if (!empty($__article['content']['previewimage']) AND is_numeric($__article['content']['previewimage']))
			{
				/*
					From templates
					filedata/fetch?id={vb:var conversation.previewimage}&amp;type={vb:var vboptions.cmspreviewimagesize}
				 */
				$typeSuffix = "&type=" . $options['cmspreviewimagesize'];
				$previewImage = "filedata/fetch?id=" . $__article['content']['previewimage'] . $typeSuffix . $sessionSuffix;
			}

			// See vB4's includes/functions_user.php's fetch_avatar_url()
			$avatarArray = array(
				'hascustom' => (bool) $__article['content']['avatar']['hascustom'],
				0 => (string) $__article['content']['avatar']['avatarpath'], // url
				1 => (string) "",
				// todo: 1: width & height attribute HTML, e.g.
				//  " width=\"$avatarinfo[width_thumb]\" height=\"$avatarinfo[height_thumb]\" "
			);


			// these bits are saved as nodeoptions.
			// They're actually translated by assembleContent to "friendly" bits in the
			// node record, so we may want to use those precomputed values instead of below
			/// once we make sure that the results array is always processed through
			// assembleContent()
			// Note: although requested by the specs, it doesn't seem like the client actually
			// uses these
			$showtitle = !($__article['nodeoptions'] & vB_Api_Node::OPTION_NODE_HIDE_TITLE);
			$showuser = !($__article['nodeoptions'] & vB_Api_Node::OPTION_NODE_HIDE_AUTHOR);
			$showpublishdate = !($__article['nodeoptions'] & vB_Api_Node::OPTION_NODE_HIDE_PUBLISHDATE);
			$showpreviewonly = !($__article['nodeoptions'] & vB_Api_Node::OPTION_NODE_DISPLAY_FULL_IN_CATEGORY);

			$content = array(
				'id'               => (int)     $__article['nodeid'], // cms_node.contentid or cms_article.contentid, but we just have node.nodeid in vB5
				'node'             => (int)     $__article['nodeid'], // cms_node.nodeid, but we just have node.nodeid in vB5
				'title'            => (string)  $__article['title'],
				'authorid'         => (int)     $__article['userid'],
				'authorname'       => (string)  $__article['authorname'],
				'page_url'         => (string)  $articleUrl,
				'showtitle'        => (bool)    $showtitle,
				'can_edit'         => (bool)    !empty($__article['content']['permissions']['canedit']),
				'showuser'         => (bool)    $showuser,
				'showpublishdate'  => (bool)    $showpublishdate,

				'viewcount'        => (int)    $__article['content']['views'],
				'showviewcount'    => (bool)   $__article['content']['display_pageviews'],

				'showrating'       => (bool)    false, // ratings were not imported to vB5.

				'publishdate'      => (int)     $__article['publishdate'],
				'setpublish'       => (int)     $__article['publishdate'], // 0 - saved as draft, greater than current time means future publish.
				'publishdatelocal' => (string) vbdate($dateformat['dateformat'], $__article['publishdate']),
				'publishtimelocal' => (string) vbdate($dateformat['timeformat'], $__article['publishdate']),

				// See note in content_view() article view handling about 'showupdated'
				'showupdated'      => (bool)    false,
				'lastupdated'      => (int)     $__article['lastupdate'],
				'dateformat'       => (string) $dateformat['dateformat'],

				'section_url'      => (string)  $channelUrl,

				'previewvideo'     => (string)  "", // todo: does this exist?

				// vB4 Article option - "Full Display in Section Page"
				// Yes = showpreviewonly 0, No = showpreviewonly 1
				'showpreviewonly'  => (bool)    $showpreviewonly,

				'previewimage'     => (string)  $previewImage,
				'previewtext'      => (string)  $previewText,
				'preview_chopped'  => (bool)    $previewChopped,
				'public_preview'   => (bool)    $__article['content']['public_preview'],

				'newcomment_url'   => (string)  "", // todo
				//'comment_count'    => (int)    $__article['content']['startertotalcount'] - 1,
				// from display_Comments template (use same count as getComments())
				'comment_count'    => (int)    $__article['content']['textcount'],

				'avatar'           => (array)  $avatarArray,
			);

			/*
				[id] => 26
				[node] => 40
				[title] => Welcome to the new CMS.  Read me first.
				[authorid] => 1
				[authorname] => kevin
				[page_url] => http://dev-vb3.internetbrands.com/mobile/vb423/content.php?40-Welcome-to-the-new-CMS-Read-me-first&amp;s=8b20680bfbfff3a63e75a59869dc89a9&amp;api=1
				[showtitle] => 1
				[can_edit] => 1
				[showuser] => 1
				[showpublishdate] => 1

				[viewcount] => 13782
				[showviewcount] => 0

				[showrating] => 0

				[publishdate] => 1257487200
				[setpublish] => 1257487200
				[publishdatelocal] => 11-06-2009
				[publishtimelocal] => 05:00 AM
				[showupdated] => 0
				[lastupdated] => 1257586791
				[dateformat] => m-d-Y

				[section_url] => http://dev-vb3.internetbrands.com/mobile/vb423/content.php?45-45-documentation&amp;s=8b20680bfbfff3a63e75a59869dc89a9&amp;api=1

				[previewvideo] =>
				[showpreviewonly] => 1
				[previewimage] => attachment.php?attachmentid=17&amp;cid=24&amp;thumb=1&amp;stc=1
				[previewtext] => Welcome to the new CMS.    Here's a quick guide of the different areas of this page.

1.  Section Navigation Widget.  This widget allows you to go to different sections. The &quot;plus icon&quot; means that this section has sub-sections. Clicking on the &quot;plus icon&quot; will display the sub-sections.

				[preview_chopped] => 1
				[newcomment_url] => http://dev-vb3.internetbrands.com/mobile/vb423/content.php?40-Welcome-to-the-new-CMS-Read-me-first&amp;s=8b20680bfbfff3a63e75a59869dc89a9&amp;api=1#comments_start
				[comment_count] => 0
				[avatar] =>
			 */


			$contents[] = $content;
			unset($content);
		}

		return array(
			'totalcount' => (int) $result['totalRecords'],
			'contentsarray' => array(
				'contents' => $contents,
			),
		);
	}

	private function notes()
	{
		/*
			"node" => `cms_node`.nodeid
			"id" => `cms_node`.contentid == `cms_{article|category|??? (content)}`.contentid

			`cms_node`.contenttypeid + contentid linked to content record in
			`cms_article` or
			`cms_category` (& possibly other records??)
			`cms_article`.pagetext seems to have the content pagetext.

			Since we don't have a "contentid" & "nodeid", just a "nodeid", I guess we'll just
			use nodeid for both. Changes pending how client uses these fields...







			`cms_node` description
			mysql> describe vb_cms_node;
+-------------------+----------------------+------+-----+---------+----------------+
| Field             | Type                 | Null | Key | Default | Extra          |
+-------------------+----------------------+------+-----+---------+----------------+
| nodeid            | int(10) unsigned     | NO   | PRI | NULL    | auto_increment |
| nodeleft          | int(10) unsigned     | NO   | MUL | NULL    |                |
| noderight         | int(10) unsigned     | NO   | MUL | NULL    |                |
| parentnode        | int(10) unsigned     | YES  | MUL | NULL    |                |
| contenttypeid     | int(10) unsigned     | NO   | MUL | NULL    |                |
| contentid         | int(10) unsigned     | YES  |     | 0       |                |
| url               | mediumtext           | YES  |     | NULL    |                |
| styleid           | int(10) unsigned     | YES  |     | NULL    |                |
| layoutid          | int(10) unsigned     | YES  |     | NULL    |                |
| userid            | int(10) unsigned     | NO   |     | 0       |                |
| publishdate       | int(10) unsigned     | YES  | MUL | NULL    |                |
| setpublish        | tinyint(3) unsigned  | YES  |     | 0       |                |
| issection         | tinyint(4)           | YES  |     | 0       |                |
| onhomepage        | tinyint(4)           | YES  |     | 0       |                |
| permissionsfrom   | int(10) unsigned     | YES  |     | 0       |                |
| lastupdated       | int(10) unsigned     | YES  |     | NULL    |                |
| publicpreview     | tinyint(4)           | YES  |     | 0       |                |
| auto_displayorder | tinyint(4)           | YES  |     | 0       |                |
| comments_enabled  | tinyint(4)           | YES  |     | 0       |                |
| new               | tinyint(3) unsigned  | NO   | MUL | 0       |                |
| showtitle         | smallint(5) unsigned | NO   |     | 1       |                |
| showuser          | smallint(5) unsigned | NO   |     | 1       |                |
| showpreviewonly   | smallint(5) unsigned | NO   |     | 1       |                |
| showupdated       | smallint(5) unsigned | NO   |     | 0       |                |
| showviewcount     | smallint(5) unsigned | NO   |     | 0       |                |
| showpublishdate   | smallint(5) unsigned | NO   |     | 1       |                |
| settingsforboth   | smallint(5) unsigned | NO   |     | 1       |                |
| includechildren   | smallint(5) unsigned | NO   |     | 1       |                |
| showall           | smallint(5) unsigned | NO   |     | 1       |                |
| editshowchildren  | smallint(5) unsigned | NO   |     | 1       |                |
| showrating        | smallint(5) unsigned | NO   |     | 0       |                |
| hidden            | smallint(5) unsigned | NO   |     | 0       |                |
| shownav           | smallint(5) unsigned | NO   |     | 0       |                |
| nosearch          | smallint(5) unsigned | NO   |     | 0       |                |
+-------------------+----------------------+------+-----+---------+----------------+
34 rows in set (0.00 sec)

			`cms_article` description
			mysql> describe vb_cms_article;
+--------------+-----------------------------+------+-----+----------+----------------+
| Field        | Type                        | Null | Key | Default  | Extra          |
+--------------+-----------------------------+------+-----+----------+----------------+
| contentid    | int(10) unsigned            | NO   | PRI | NULL     | auto_increment |
| pagetext     | mediumtext                  | NO   |     | NULL     |                |
| threadid     | int(10) unsigned            | YES  |     | NULL     |                |
| blogid       | int(10) unsigned            | YES  |     | NULL     |                |
| posttitle    | varchar(255)                | YES  |     | NULL     |                |
| postauthor   | varchar(100)                | YES  |     | NULL     |                |
| poststarter  | int(10) unsigned            | YES  |     | NULL     |                |
| blogpostid   | int(10) unsigned            | YES  |     | NULL     |                |
| postid       | int(10) unsigned            | YES  |     | NULL     |                |
| post_posted  | int(10) unsigned            | YES  |     | NULL     |                |
| post_started | int(10) unsigned            | YES  |     | NULL     |                |
| previewtext  | varchar(2048)               | YES  |     | NULL     |                |
| previewimage | varchar(256)                | YES  |     | NULL     |                |
| imagewidth   | int(10) unsigned            | YES  |     | NULL     |                |
| imageheight  | int(10) unsigned            | YES  |     | NULL     |                |
| previewvideo | mediumtext                  | YES  |     | NULL     |                |
| htmlstate    | enum('off','on','on_nl2br') | NO   |     | on_nl2br |                |
| keepthread   | smallint(5) unsigned        | NO   |     | 0        |                |
| allcomments  | smallint(5) unsigned        | NO   |     | 0        |                |
| movethread   | smallint(5) unsigned        | NO   |     | 1        |                |
+--------------+-----------------------------+------+-----+----------+----------------+
20 rows in set (0.00 sec)

			`cms_section` description


		*/

		return null;
	}

	private function searchArticles($categoryid, $page = 1, $perpage = 10)
	{
		$cleaner    = vB::getCleaner();
		$categoryid = $cleaner->clean($categoryid, vB_Cleaner::TYPE_UINT);
		$page       = $cleaner->clean($page,       vB_Cleaner::TYPE_UINT);
		$perpage    = $cleaner->clean($perpage,    vB_Cleaner::TYPE_UINT);


		// Note, this function does NOT validate if $category is an article channel.

		/*
		Based on the widget_cmschanneldisplay template's search configs

			{vb:set articleOptions.channel, {vb:var page.channelid}}
			{vb:set articleOptions.starter_only, '1'}
			{vb:set articleOptions.nolimit, 1}
			<vb:if condition="$widgetConfig['include_subcategory_content']">
				{vb:set articleOptions.depth, 0}
			<vb:else />
				{vb:set articleOptions.depth, 1}
			</vb:if>

			{vb:set articleSortOption.publishdate, 'DESC'}
			{vb:set articleOptions.sort, {vb:raw articleSortOption}}

			{vb:rawdata nodes, search, getInitialResults, {vb:raw articleOptions}, {vb:raw articleWidgetConfig.resultsPerPage}, {vb:raw page.pagenum}, 1}

		*/
		// This is dependent on "include_subcategory_content" of the widget config, but I'm not sure if
		// trying to find the channel's widgetinstance & pulling the config out here makes sense...
		// For now, I'll just default it to yes.
		$include_subcategory_content = true;
		if ($include_subcategory_content)
		{
			$depth = 0; // infinite
		}
		else
		{
			$depth = 1; // exactly 1 layer
		}

		$articleSearchOptions = array(
			'channel'       => (int)   $categoryid,
			'starter_only'  => (bool)  true,
			'nolimit'       => (bool)  true,
			'depth'         => (int)   $depth,
			'sort'          => (array) array('publishdate' => 'DESC'),
		);

		if ($perpage < 1)
		{
			$perpage = 10;
		}
		if ($page < 1)
		{
			$page = 1;
		}

		$getStarterInfo = true;

		$searchResults = vB_Api::instance("search")->getInitialResults($articleSearchOptions, $perpage, $page, $getStarterInfo);

		/*
			Add node views & replace into original

			{vb:rawdata nodes, search, getInitialResults, {vb:raw articleOptions}, {vb:raw articleWidgetConfig.resultsPerPage}, {vb:raw page.pagenum}, 1}
			{vb:data nodeResultsWithViews, node, 'mergeNodeviewsForTopics', {vb:raw nodes.results}}
			{vb:set nodes.results, {vb:raw nodeResultsWithViews}}
		 */

		if (!empty($searchResults) AND empty($searchResults['errors']))
		{
			// note, search results is already keyed by nodeid, it seems.
			$nodesWithViews = vB_Api::instance('node')->mergeNodeviewsForTopics($searchResults['results']);
			$searchResults['results'] = $nodesWithViews;
		}

		return $searchResults;
	}



	public function content_edit($nodeid, $page = 1)
	{
		$cleaner = vB::getCleaner();
		$nodeid = $cleaner->clean($nodeid, vB_Cleaner::TYPE_INT);

		$nodeApi = vB_Api::instance('node');
		if ($nodeid < 0)
		{
			// This is part of the callback of addcontent, and $nodeid is -$parentid.
			$node = array(
				'parentid' => -$nodeid,
			);
		}
		else
		{
			$result = $nodeApi->getFullContentforNodes(array($nodeid));
			if ($result === null || isset($result['errors']))
			{
				return vB_Library::instance('vb4_functions')->getErrorResponse($result);
			}
			$node = reset($result);

			$channelTypeId = vB_Types::instance()->getContentTypeID('vBForum_Channel');
			if ($channelTypeId == $node['contenttypeid'])
			{
				/*
					AFAIK there's no UI to edit sections via the app, so this is not
					implemented yet.
				 */
				return array(
					'response' => array(
						'errormessage' => array(
							"section_edit_unimplemented"
						),
					),
				);
			}
		}

		// nodelist
		$nodelist = array();
		$parentNode = $nodeApi->getNodeBare($node['parentid']);
		$articlesRootid = vB_Api::instance('content_channel')->fetchChannelIdByGUID(vB_Channel::DEFAULT_ARTICLE_PARENT);
		$rootNode = $nodeApi->getNodeBare($articlesRootid);
		$parentAdded = ($node['parentid'] == $articlesRootid);
		$sectionlist = $this->sectionlist();

		// checking for errors as a quick "can you see this node" check.
		if (empty($rootNode['errors']) AND !empty($rootNode['nodeid']))
		{
			$selected = ($node['parentid'] == $rootNode['nodeid']);
			// we skip the root for sectionlist to follow vB4 rules, but we need it back here.
			$nodelist[] = array(
				'nodeid'    => (int)    $rootNode['nodeid'],
				'selected'  => (bool)   $selected,
				'leaf'      => (string) $rootNode['title'],
			);
			// handle the case when the parent section is the "front page"
			$parentAdded = $selected;
		}


		foreach ($sectionlist AS $__sec)
		{
			$selected = ($node['parentid'] == $__sec['nodeid']);
			// nodeid, parentnode, url, title, indent
			$nodelist[] = array(
				'nodeid'    => (int)    $__sec['nodeid'],
				'selected'  => (bool)   $selected,
				'leaf'      => (string) $__sec['title'],
			);
			$parentAdded = ($parentAdded OR $selected);
		}

		if (!$parentAdded AND empty($parentNode['errors']) AND !empty($parentNode['nodeid']))
		{
			$nodelist[] = array(
				'nodeid'    => (int)    $parentNode['nodeid'],
				'selected'  => (bool)   $selected,
				'leaf'      => (string) $parentNode['title'],
			);
		}


		// categories
		// todo: Should we return a smaller subset of these categories?
		$categorylist = $this->categorylist();
		$thisNodeCategories = $this->getTags($node);
		$thisNodeCategoriesById = array();
		foreach($thisNodeCategories AS $__cat)
		{
			// categoryid, category, category_url (not used)
			$thisNodeCategoriesById[$__cat['categoryid']] = $__cat;
		}

		$categories  = array();
		foreach ($categorylist AS $__category => $__cat)
		{
			// category, categoryid
			$catid = $__cat['categoryid'];
			$selected = false;
			if (isset($thisNodeCategoriesById[$catid]))
			{
				$selected = true;
				unset($thisNodeCategoriesById[$catid]);
			}

			$categories[] = array(
				'categoryid' => (int) $catid,
				'checked' => (bool) $selected,
				'text' => (string) $__cat['category'],
			);
		}
		// since categorylist has a hard limit of 500 or so, for forums with more tags
		// there's a possibility that not all of this node's categories were included
		// in the search. So add any remaining manually here.
		if (!empty($thisNodeCategoriesById))
		{
			foreach($thisNodeCategoriesById AS $__cat)
			{
				$categories[] = array(
					'categoryid' => (int) $__cat['categoryid'],
					'checked' => (bool) true, // always true since these are the node's tags.
					'text' => (string) $__cat['category'],
				);
			}
		}


		$posthash = vB_Library::instance('vb4_posthash')->getNewPosthash();
		$timenow = vB::getRequest()->getTimeNow();

		$content = array(
			"editor" => array(
				'posthash' => (string) $posthash,
				'poststarttime' => (int) $timenow,
				'publisher' => (array) array(
					'nodelist' => (array) $nodelist,
					'categories' => (array) $categories,
				),
			),
		);


		$return = array();
		$return['response']['content']['content'] = $content;

		//$return['response']['show'] = $show;
		//$return['show'] = $show;
		// todo: bbuserinfo?

		return $return;
	}

	private function returnNoPermission()
	{
		$userid = vB::getCurrentSession()->get('userid');
		if ($userid == 0)
		{
			$error_code = 'nopermission_loggedout';
		}
		else
		{
			$error_code = 'nopermission_loggedin';
		}

		return array(
			'response' => array(
				'errormessage' => array(
					$error_code
				),
			),
		);
	}

	public function content_addcontent($nodeid, $contenttypeid, $item_type, $item_class, $item_id)
	{
		$cleaner = vB::getCleaner();
		$parentid = $cleaner->clean($nodeid, vB_Cleaner::TYPE_UINT);
		unset($nodeid);

		$contenttypeid = $cleaner->clean($contenttypeid, vB_Cleaner::TYPE_UINT);
		unset($item_type, $item_class, $item_id);

		/*
			The other params are basically useless & hard-coded, especially the contenttypeid
			that's hard-coded to "18"...
			CmsAddContentServerRequest :

			public static ServerRequestParams createRequestParams()
			{
				List<BasicNameValuePair> postParams = new ArrayList<BasicNameValuePair>();
				postParams.add(new BasicNameValuePair(PARAM_CONTENT_TYPE_ID, "18"));
				postParams.add(new BasicNameValuePair(PARAM_ITEM_CLASS, "vBCms_Section"));
				postParams.add(new BasicNameValuePair(PARAM_ITEM_ID, ZERO_VALUE));
				postParams.add(new BasicNameValuePair(PARAM_ITEM_TYPE, "content"));
				return new ServerRequestParams(null, postParams, null);
			}

			I'm not sure where this 18 even came from, as vB4's mysql-schema shows
			contenttypeid 18 should default to "UserNote":
			(18, 'UserNote', 1, '0', '0', '0', '0')

			I'm just going to assume every new CMS article is supposed to be a vBForum_Text
			type.
		 */
		if ($contenttypeid != 18)
		{
			// If this isn't 18, that means something in the app code change and we have to verify
			// that the app actually uses *real* contenttypeids pulled from the server, not some
			// arbitrary hard-coded list.
			// See VBV-17271
			return array("response" => array("errormessage" => array("unimplemented")));
		}

		// See above on why we hard-code the content_text contenttype
		//vB_Api_Content::getContentApi($contenttypeid);
		$contentApi = vB_Api::instance('content_text');
		$nodeApi = vB_Api::instance('node');

		$result = $nodeApi->getFullContentforNodes(array($parentid));
		if ($result === null OR isset($result['errors']))
		{
			return vB_Library::instance('vb4_functions')->getErrorResponse($result);
		}
		$parentNode = reset($result);

		// We're only expecting articles.
		if (!isset($parentNode['content']['channeltype'])
			OR $parentNode['content']['channeltype'] != "article"
		)
		{
			// TODO: spec this.
			return array("response" => array("errormessage" => array("invalidid")));
		}

		// Parent has to be a section (channel in vB5).
		$channelTypeId = vB_Types::instance()->getContentTypeID('vBForum_Channel');
		if ($parentNode['contenttypeid'] != $channelTypeId)
		{
			// TODO: spec this.
			return array("response" => array("errormessage" => array("invalidid")));
		}


		/*
			See vBCms_Controller_Content::actionAddNode() &
			vBCms_Content_Article::createDefaultContent() for vB4 reference

			We have to create "default content". In vB4, it seems this was either
			pasted from a forum post that the article was "promoted from", or just
			a blank article with no pagetext or title.

			We can't really create a node without title & rawtext without bypassing the
			existing checks, which we don't really want to do since doing so requires us
			to duplicate various permission checks ETC...

			One possibility is to fudge the content creation and pass back a negative number,
			because the only thing the app cares about is that it gets a numeric nodeid back,
			and then it'll callback to content_{nodeid}_edit immmediately followed by
			content_{nodeid}_view with a do=apply param with the actual post data (title,
			pagetext etc).
			However that requires us to have the content_edit, _view & _apply handlers have special
			handling for negative nodeid & understand that it's actually a callback for addcontent,
			which could be extremely fragile & sketchy as all hell.
			We'd have to somehow keep track of the parentid as well somehow, and to get around having
			to store something in the DB or session, we could just send back a -$parentid and have
			the content_edit / content_view / content_apply handlers understand that...

			Did I mention how sketchy all of this is?


			The other method is to create an article node with just placeholder data, but if the
			callback somehow fails (or even if a user happens to load the page at the wrong time),
			a placeholder CMS article would show up as published on the forum.

			We could have it save as a draft until the apply call comes through, but if we restrict
			the path to the API instead of the LIB, that would depend on the user having save-as-draft
			permissions.


			For now, I'm going with the -$parentid path.
		 */

		/*
		$data = array(
			'parentid' => $parentid,
			'title' => "",
			'rawtext' => "",
			// todo: try to save as draft? It will depend on permissions...
			//'publishdate' => 0,
		);

		$options = array(
			'wysiwyg' => false
		);

		$result = vB_Api::instance('content_text')->add($data, array());
		$contentApi->add($data, $options);
		*/

		return array(
			'response' => array(
				'content' => array(
					'content' => array(
						"nodeid" => -$parentid,
					),
				),
			),
		);

	}

	private function actuallyAddContent($parentid)
	{
		$textTypeId = vB_Types::instance()->getContentTypeID('vBForum_Text');
		$node = array(
			'contenttypeid' => $textTypeId,
			'parentid' => intval($parentid),
		);
		return $this->content_apply($node);
	}

	public function content_view($nodeid, $do = "", $contentpagenum = 1, $page = 1)
	{
		$cleaner = vB::getCleaner();
		$nodeid = $cleaner->clean($nodeid, vB_Cleaner::TYPE_INT);
		$contentpagenum = $cleaner->clean($contentpagenum, vB_Cleaner::TYPE_UINT);
		if ($contentpagenum < 1)
		{
			$contentpagenum = 1;
		}
		$commentsPageNumber = $cleaner->clean($page, vB_Cleaner::TYPE_UINT);
		if ($commentsPageNumber < 1)
		{
			$commentsPageNumber = 1;
		}
		$do = strtolower($do);

		/*
			Special snowflake handling to deal with "addcontent"...
			See notes in addcontent about this, but basically
			if nodeid is negative, it's actually a parentid and
			it's a callback after an addcontent call. We can't
			create "blank" nodes easily in vB5, so we never created
			the default content, so this should actually create the
			new article.
		 */
		if ($nodeid < 0 AND $do == "apply")
		{
			return $this->actuallyAddContent(-$nodeid);
		}

		$nodeApi = vB_Api::instance('node');
		$result = $nodeApi->getFullContentforNodes(array($nodeid));
		if ($result === null || isset($result['errors']))
		{
			return vB_Library::instance('vb4_functions')->getErrorResponse($result);
		}
		$node = reset($result);
		// add node views ($node.content.views)
		//index by nodeid since mergeNodeviewsForTopics requires it.
		$nodestemp = array(
			$node['nodeid'] => $node,
		);
		$nodesWithViews = $nodeApi->mergeNodeviewsForTopics($nodestemp);
		$node = $nodesWithViews[$node['nodeid']];

		if (!isset($node['content']['channeltype']) OR $node['content']['channeltype'] != "article")
		{
			// TODO: spec this.
			return array("response" => array("errormessage" => array("invalidid")));
		}

		switch ($do)
		{
			case "apply":
				return $this->content_apply($node);
				break;
			case "delete":
				return $this->content_delete($node);
				break;
			default:
				break;
		}


		$return = array(
			"response" => array(
				"layout" => array(
					"content" => array(), // this is the main block for CMS
				),
			),
			"show" => array(
				// todo: need specs for this
			),
		);
		$content = array(); // we'll save this in return.response.layout.content later
		$show = array();

		$dateformat = $this->getUserLangDateTimeOverrides();

		$channelTypeId = vB_Types::instance()->getContentTypeID('vBForum_Channel');
		$isChannel = ($node['contenttypeid'] == $channelTypeId);
		if ($isChannel)
		{
			// Category (Channel), or "Section" in vB4

			// todo
			$routeData = array(
				'nodeid' => $node['nodeid'],
				'title'  => $node['title'],
			);
			if ($contentpagenum > 1)
			{
				// Channels don't have "content page number" vs "page number",
				// because channels don't have comments to conflict with pagination.
				$routeData['pagenum'] = $contentpagenum;
			}
			$channelUrl = $this->safeBuildUrl($node['routeid'], $routeData);

			// todo: pull this from widgetinstance? Or is there a global option value for this?
			// 7 pulled from the items_perhomepage default set in vB4's
			// vBCms_Content_Section::aggregateContent()
			$defaultPerPage = 7;

			$results = $this->getSectionSubContentsArray($node, $contentpagenum, $defaultPerPage);
			if ($result === null || isset($result['errors']))
			{
				return vB_Library::instance('vb4_functions')->getErrorResponse($result);
			}
			$contentSubarray = $results['contentsarray'];
			$contentCount = $results['totalcount'];

			$canpublish = vB::getUserContext()->getChannelPermission('forumpermissions2', 'canpublish', $node['nodeid']);

			$pagenav = vB_Library::instance('vb4_functions')->pageNav($contentpagenum, $defaultPerPage, $contentCount);


			// Content (Section - vB4, Category - vB5)
			$content = array(
				'nodeid'                 => (int)    $node['nodeid'],
				'title'                  => (string) $node['title'], // todo: does client need htmltitle as well?
				'page_url'               => (string) $channelUrl, // todo: does this need escaping?
				// 'publishdate' (int) unused
				'publishdatelocal'       => (string) vbdate($dateformat['dateformat'], $node['publishdate']),
				'publishtimelocal'       => (string) vbdate($dateformat['timeformat'], $node['publishdate']),
				'section_list_url'       => (string) $channelUrl, // TODO: What's the actual analog of the list.php vB4 page???
				'pagenav'                => empty($pagenav) ? null : (array)  $pagenav,
				'class'                  => (string) "Section", // apparently always "Section"?
				'package'                => (string) "vBCms", // TODO: Is this the expected value??
				'result_count'           => (int)    $contentCount,
				'can_publish'            => (bool)   $canpublish, // TODO: how's this used by the app?
				'published'              => (bool)   $node['showpublished'],
				// setpublish is 0 if unpublished, greater than current time if future published
				// In vB5, all this is just saved in publishdate with the same values.
				'setpublish'             => (int)    $node['publishdate'],
				'publishdate'            => (int)    $node['publishdate'],

				'showall'                => (bool)   true, // TODO: what is this

				'content'                => (array)  $contentSubarray,
				'userid'                 => (int)    $node['userid'],
				'username'               => (string) $node['authorname'],
				'node'                   => (int)    $node['nodeid'], // Why does section return have both nodeid & node??

				'showrating'             => (bool)   false, // ratings were not imported to vB5.

				'contentid'              => (int)    0, // sections, AFAIK, didn't have contentids in vB4.
			);

		}
		else
		{
			// Article (Content Node)

			// require_once DIR . "/includes/functions.php"; //todo: is this globally included?
			// above needed for vbdate

			$parentCategoryNode = vB_Library::instance('node')->getNodeBare($node['parentid']);
			$parentUrl = $this->safeBuildUrl($parentCategoryNode['routeid'], $parentCategoryNode);

			$routeData = array(
				'nodeid' => $node['nodeid'],
				'title'  => $node['title'],
			);
			if ($contentpagenum > 1)
			{
				$routeData['contentpagenum'] = $contentpagenum;
			}
			$articleUrl = $this->safeBuildUrl($node['routeid'], $routeData);

			list($post, $poll, $pages) = vB_Library::instance('vb4_functions')->parseArticle($node, $contentpagenum);

			$nextPageUrl = "";
			$nextPage = $contentpagenum + 1;
			if (isset($pages[$nextPage]))
			{
				$nextPageUrl = $pages[$nextPage]['url'];
			}


			$showpublishdate = !($node['nodeoptions'] & vB_Api_Node::OPTION_NODE_HIDE_PUBLISHDATE);

			// commentsPageNumber is passed in as a get/post param "page", grabbed above
			// at the beginning of this function.
			// todo: did vb4 allow input params for perpage?
			// 20 pulled from vB4's vBCms_Comments::getPageView(), where it calls getComments()
			// with a hard-coded perpage value of 20.
			$commentsPerPage = 20;
			$commentsData = $this->getComments($node, $commentsPageNumber, $commentsPerPage);

			/*
				Unfortunately, node.content.taglist only has the tagtext, not the tagid,
				so we have to fetch them separately...
			 */
			$tags = $this->getTags($node);


			// Content (Article)
			$content = array(
				'node'                   => (int)    $node['nodeid'],
				'title'                  => (string) $node['title'], // todo: does client need htmltitle as well?
				'page_url'               => (string) $articleUrl, // todo: does this need escaping?
				// publishdate is used by ArticleFactory to pass to content.setPublishDate(),
				// which is latter pulled into the Article Options via CmsPublishFormActivity.
				// It is converted into a Date object from a long:
				// content.setPublishDate(JsonUtil.optDate(jsonObject.optLong(PUBLISHDATE_JSON_FIELD)));
				'publishdate'            => (int)    $node['publishdate'],

				'publishdatelocal'       => (string) vbdate($dateformat['dateformat'],$node['publishdate']),
				'publishtimelocal'       => (string) vbdate($dateformat['timeformat'], $node['publishdate']),
				'section_list_url'       => (string) $parentUrl, // TODO: What's the actual analog of the list.php vB4 page???
				'class'                  => (string) "Article", // apparently always "Article"?
				'package'                => (string) "vBCms", // TODO: Is this the expected value??
				'published'              => (bool)   $node['showpublished'],
				'userid'                 => (int)    $node['userid'],
				'username'               => (string) $node['authorname'],

				// vB4's rating data was never imported into vB5.
				// Closest thing we have might be the node votes ("likes") but
				// it doesn't seem like the nodeinfo.rating data was converted/imported
				// over into node.vote
				'showrating'             => (bool)   false,
				//'rating'                 => (int)    0,
				//'ratingnum'              => (int)    0,
				//'ratingavg'              => (float)  0,

				'showpublishdate'        => (bool)   $showpublishdate,
				// We don't have a separate "updated X" field next to the publishdate
				// as vB4 did. Nor do we have a contententry permission for this.
				// It seems that we *always* show the update time for all nodes by default,
				// but for simplicity I'll just turn this off by default for mapi cms.
				// If requested we can default this to on instead.
				'showupdated'            => (bool)   false,
				'lastupdated'            => (int)    $node['lastupdate'],

				'showviewcount'          => (bool)   $node['content']['display_pageviews'],
				'viewcount'              => (int)    $node['content']['views'],
				'dateformat'             => (string) $dateformat['dateformat'],
				// todo: hide_comment_count?
				'comment_count'          => (int)    $commentsData['comment_count'],
				'next_page_url'          => (string) $nextPageUrl,
				'pagelist'               => (array)  $pages,
				'pagetext'               => (string) $post['pagetext'],

				// 'otherattachments' may not be set in $post if article has 0 attachments.
				'otherattachments'       =>  isset($post['post']['otherattachments']) ? (array) $post['post']['otherattachments'] : null,
				// not specified in spec, but looking at the ArticleFactory class I'm pretty sure it's supported
				'imageattachments'       =>  isset($post['post']['imageattachments']) ? (array) $post['post']['imageattachments'] : null,
				'thumbnailattachments'       =>  isset($post['post']['thumbnailattachments']) ? (array) $post['post']['thumbnailattachments'] : null,

				// todo: does "promoting from a post" for articles exist in vb5??
				//'posttitle'              => (string) "",
				//'poststarter'            => (array)  array("userid" => null, "username" => ""),
				//'postauthor'             => (string) "",

				// vB4 had the pagetext in the cms_article table, and linked the
				// cms_node vs. cms_article via contentid. We don't have a separate
				// ID for the content & the "node", just a nodeid.
				'contentid'              => (int)    $node['nodeid'],

				// vB4 had separate tags vs categories.
				// vB5 imported them both as vB5 tags. Since "categories" seems to be more
				// upfront in the client app, we'll just stick vB5 tags into categories
				// & skip the tag related returns...
				//'showtags'
				//'tag_count'
				//'tags'

				'can_edit'               => (bool)   !empty($node['content']['permissions']['canedit']),
				'parenttitle'            => (string) $parentCategoryNode['title'],
				'parentid'               => (int)    $parentCategoryNode['nodeid'],
				'section_url'            => (string) $parentUrl,
				// assuming these bits are same as other vb4 mapi returns...
				'message'                => (string) $post['post']['message'],
				'message_plain'          => (string) $post['post']['message_plain'],
				'message_bbcode'         => (string) $post['post']['message_bbcode'],
				'message_html'           => (string) $post['post']['message_html'],
				// Note, if below is an empty array() or assigned a null value, the app breaks.
				// There's a check below to unset this if it's empty.
				'categories'             => (array)  $tags,
				'comment_block'          => (array)  $commentsData['comment_block'], // todo

				/*
				// These are pulled from ArticleFactory.java
				'avatarurl' => sets avatarurl in articlepublishoptions

				if 'node' (nodeid) is missing, 'article' must be present

				'userid' (provided above) if 'authorid' is missing (which it is)
				'username' (provided above) is used if 'authorname' is missing (which it is)



				'message_bbcode' is set to setMessage_bbcode() if provided,

				'previewtext' over 'pagetext' for content.setMessage() call,




				*/
				'public_preview'         => (bool)   $node['content']['public_preview'],


			);


			if (isset($content['categories']) AND empty($content['categories']))
			{
				// prevent app breakage when categories is empty array.
				unset($content['categories']);
			}

			// todo: is this correct, or does CMS have its own special show array?
			$show = $post['show'];
		}

		$return['response']['layout']['content'] = $content;

		//$return['response']['show'] = $show;
		$return['show'] = $show;

		return $return;
	}

	private function getTags($node)
	{
		$tags = array();
		if (!isset($node['nodeid']))
		{
			return $tags;
		}


		$index = 1; // for some reason this array is 1-indexed not 0-indexed.
		$rows = vB::getDbAssertor()->getRows('vBForum:getTags', array('nodeid' => $node['nodeid']));
		if (!empty($rows))
		{
			foreach($rows AS $__tag)
			{
				$tags[$index++] = array(
					'category' => (string) $__tag['tagtext'],
					'categoryid' => (int) $__tag['tagid'],
					// todo: 1) is this required, 2) how should we generate this?
					// It should be the list.php?category/{categoryid} vb4 URL, but
					// we don't have such a URL in vB5 (even if we did it wouldn't work
					// since tags don't have oldid's since they're not nodes)
					'category_url' => (string) "",
				);
				/*
				Leaving this for reference. From taglist_display template, where each
				tagtext is linked to a search of that tag:
		<vb:each from="nodeTags" value="tagText">
			{vb:strcat tagsInfo, {vb:var tagText}, ' '}
			{vb:set searchStr, '{"tag":["'}
			{vb:strcat searchStr, {vb:var tagText}, '"]}'}
			{vb:set extra.searchJSON, {vb:raw searchStr}}
			<a href="{vb:url 'search', {vb:raw nodeTags}, {vb:raw extra}}">{vb:var tagText}</a><vb:if condition="++$tagCount < count($nodeTags)">, </vb:if>
		</vb:each>
				*/
			}
		}

		return $tags;
	}

	public function sectionlist()
	{
		// This is mapped from a "api_cmssectionlist" call via vB_Api::map_vb4_input_to_vb5()


		// get all article channels
		$flat = true;
		$queryOptions = array();
		$skipCache = false;
		$articlesRoot = vB_Api::instance('content_channel')->fetchChannelIdByGUID(vB_Channel::DEFAULT_ARTICLE_PARENT);
		$channels = vB_Api::instance('search')->getChannels($flat, $queryOptions, $skipCache, $articlesRoot);

		// note, api_cmssectionlist return format is different from the other typical
		// mapi returns.
		$return = array();
		$return[] = array(); // Always unset, see note after the loop.
		foreach($channels AS $__channel)
		{
			/*
			// root "article" channel in left in sectionlist per request, VBV-17328
			if ($__channel['nodeid'] == $articlesRoot)
			{
				// vB4 always unsets the root node in the return, for some reason.
				continue;
			}
			*/

			$channelUrl = $this->safeBuildUrl($__channel['routeid'], $__channel);
			$return[] = array(
				// seems like only nodeid, title & indent are used. others are left
				// because the old docs requested them & I'd already added them.
				'nodeid'     => (int)    $__channel['nodeid'],
				// todo: does CMS root require parent to be itself?
				'parentnode' => (int)    $__channel['parentid'],
				'url'        => (string) $channelUrl,
				'title'      => (string) $__channel['title'],
				'indent'     => (int)    $__channel['depth'] - 1,
			);
		}

		/*
			For some bizarre reason, the client doesn't like it when the array is zero-indexed.
			It doesn't show any errors but none of the sections are displayed.

			The sample returns in the Docs show that the return array is 1-indexed than
			zero-indexed, but that's purely a coincidence of the 0th item being the article
			root & being unset after-the-fact, and NOT guaranteed AFAIK (see vb4's
			includes/api/1/api_cmssectionlist.php's output() where it pulls the nodes ordered by
			node.nodeleft & setNavArray() where it unsets the root node regardless of array key)
			unless something about the root node guarantees that it'll be the first returned item
			when sorted by node.nodeleft.

			In any case, the sectionlist just doesn't work period unless I remove the 0th item.
		 */
		unset($return[0]);



		return $return;
	}

	public function categorylist()
	{
		/*
			CMS categories were imported as tags into vB5.
			Note that there's no hierarchy of tags in vB5.

			We don't really want to return *all* tags in existence,
			and it seems the result of this call is used to fetch articles
			using the tag(s), so let's just use vB_Api_Tags::fetchTagsForTagNavigation()
			to try to limit the result set.

			Note that vB4 returned all categories, even ones not yet attached to nodes,
			but these categories were specific to CMS in vB4 (cms_categories, not tags
			or blog_categories) and you were able to create categories in adminCP's CMS
			manager so it's a bit different.
		 */

		// The api function has a hard limit of 500 for the limit, with a default of 25.
		$channelId = vB_Api::instance('content_channel')->fetchChannelIdByGUID(vB_Channel::DEFAULT_ARTICLE_PARENT);
		$limit = 500;
		$tags = vB_Api::instance('tags')->fetchTagsForTagNavigation($channelId, $limit);
		$return = array();
		foreach($tags AS $__tag)
		{
			/*
				CmsCategoryFactory only uses categoryid & category fields,
				and key-changes the 'category' field to the CmsCategory.title.
			 */
			$__category = (string) $__tag['tagtext'];
			$__categoryid = (int) $__tag['tagid'];
			$return[$__category] = array(
				'category'   => $__category,
				'categoryid' => $__categoryid,
			);
		}


		return $return;
	}

	public function list_category($categoryid, $page = 1)
	{
		$tagid = intval($categoryid);
		$page = max(1, intval($page)); // lower bound @ 1

		$tag = vB::getDbAssertor()->getRow('vBForum:tag', array('tagid' => $tagid));

		if (empty($tag['tagtext']))
		{
			$return = array();
			$return["response"]["errormessage"] = array("invalidid");
			return $return;
			/*
			return array(
				'response' => array(
					'layout' => array(
						'content' => array(
							'contents' => array(
								1 => ""
							),
						),
					),
				),
			);
			*/
			//$contentview->contents = array(1 => new vB_Phrase('vbcms', 'no_content_for_category_x', $this->title ))
		}

		$searchJSON = array(
			'tag' => array($tag['tagtext']),
		);

		return $this->searchAndList($searchJSON, $tag['tagtext'], $page);
	}

	public function list_section($sectionid, $page = 1)
	{
		$channelid = intval($sectionid);
		$page = max(1, intval($page)); // lower bound @ 1

		$searchJSON = array(
			'channel' => $channelid,
		);

		return $this->searchAndList($searchJSON, $username, $page);
	}

	public function list_author($userid, $page = 1)
	{
		$userid = intval($userid);
		$page = max(1, intval($page)); // lower bound @ 1

		$username = vB_Api::instance('user')->fetchUserName($userid);

		if (empty($username))
		{
			$return = array();
			$return["response"]["errormessage"] = array("invalidid");
			return $return;
		}

		$searchJSON = array(
			'authorid' => $userid,
		);

		return $this->searchAndList($searchJSON, $username, $page);
	}

	private function searchAndList($searchJSON, $rawtitle, $page, $perpage = 5)
	{
		// perpage of 5 from vBCms_Controller_List's default perpage.

		// if it's not a section search, limit the parent to article root.
		if (!isset($searchJSON['channel']) AND !isset($searchJSON['channelguid']))
		{
			$searchJSON['channelguid'] = vB_Channel::DEFAULT_ARTICLE_PARENT;
		}
		// todo: is depth required? What's the default? Ideally we want infinite.

		$getStarterInfo = true;

		$result = vB_Api::instance('search')->getInitialResults($searchJSON, $perpage, $page, $getStarterInfo);
		$results = $this->getSubContentsArrayFromSearchResult($result);

		$commonLib = vB_Library::instance('vb4_functions');
		if ($result === null || isset($result['errors']))
		{
			return $commonLib->getErrorResponse($result);
		}


		$contentSubarray = $results['contentsarray'];
		$contentCount = $results['totalcount'];
		$pagenav = $commonLib->pageNav($page, $perpage, $contentCount);

		$content = array(
			'rawtitle' => (string) $rawtitle,
			'contents' => (array)  $contentSubarray['contents'],
			'pagenav'  => (array)  $pagenav,
		);

		$return = array(
			"response" => array(
				"layout" => array(
					"content" => $content,
				),
			),
			"show" => array(
				// todo: need specs for this
			),
		);

		return $return;
	}

	private function getComments($articleNode, $commentPageNumber = 1, $commentsPerPage = 10)
	{
		$nodeApi = vB_Api::instance('node');
		$commonLib = vB_Library::instance('vb4_functions');

		$dateformat = $this->getUserLangDateTimeOverrides();

		// these are defaults for comment search pulled from the display_Comments template
		$depth = 1;
		$contenttypeid = null;
		$options = array(
			'nolimit' => 1,
			//'sort' => array('created', 'DESC'),
			// ASC is the default vB4 sort order, override vB5 display_Comments default.
			'sort' => array('publishdate' => 'ASC'),
		);
		$comments = $nodeApi->listNodeContent(
			$articleNode['nodeid'],
			$commentPageNumber,
			$commentsPerPage,
			$depth,
			$contenttypeid,
			$options
		);

		$comment_count = $articleNode['textcount']; // from display_Comments
		$cms_comments = array();

		if ($comments AND empty($comments['errors']))
		{
			foreach ($comments AS $__comment)
			{
				$postid = $__comment['nodeid'];
				$messages = $commonLib->parseArticleComment($__comment);

				$cms_comments[] = array(
					'postid'   => (int) $postid,
					'postbit'  => array(
						'post' => array(
							'postid'    => (int) $postid,
							// todo: Do we have to prepend the forum root to the relative avatarurl?
							'avatarurl'       => (string) $__comment['content']['avatar']['avatarpath'],
							'userid'          => (int) $__comment['userid'],
							'username'        => (string) $__comment['authorname'],
							'postdate'        => (string) vbdate($dateformat['dateformat'],$__comment['publishdate']),
							'posttime'        => (string) vbdate($dateformat['timeformat'],$__comment['publishdate']),
							'message'         => (string) $messages['message'],
							'message_bbcode'  => (string) $messages['message_bbcode'],
							'message_plain'   => (string) $messages['message_plain'],
							'editlink'        => (string) "", // todo: what's this
							'replylink'       => (string) "", // todo: what's this
						),
					),

				);
			}

		}

		$pagenav = $commonLib->pageNav($commentPageNumber, $commentsPerPage, $comment_count);

		$node_comments = array(
			'pagenav'     => (array) $pagenav,
			'cms_comments' => (array) $cms_comments,
		);

		$allowComments = ($articleNode['nodeoptions'] & vB_Api_Node::OPTION_ALLOW_POST) ? 1 : 0;

		$comment_block = array(
			'nodeid'        => (int)   $articleNode['nodeid'],
			// I think vB4 handled comments as like a hidden thread, so there was a separate threadid.
			// We don't have such a thing in vB5...
			'threadid'      => (int)   $articleNode['nodeid'],
			'pageno'        => (int)   $commentPageNumber,
			'node_comments' => (array) $node_comments,
			// show_comment_editor is set by CmsViewResponseFactory
			// and used for article pub options via CmsPublishFormActivity
			// Must be 0 | 1, boolean doesn't work on the app...
			'show_comment_editor' => (int) $allowComments,
		);

		$return = array(
			'comment_count' => (int)   $comment_count,
			'comment_block' => (array) $comment_block,
		);

		return $return;
	}

	private function safeBuildUrl($routeid, $routeData)
	{
		return vB_Library::instance('vb4_functions')->safeBuildUrl($routeid, $routeData);
	}


}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| #######################################################################
\*=========================================================================*/
