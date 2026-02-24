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

// ###################### Start dodigest #######################
function exec_digest($type = 2)
{
	// type = 2 : daily
	// type = 3 : weekly

	$lastdate = mktime(0, 0); // midnight today
	if ($type == 2)
	{
		// yesterday midnight
		$lastdate -= 24 * 60 * 60;
	}
	else
	{
		// last week midnight
		$lastdate -= 7 * 24 * 60 * 60;
	}

	$datastore = vB::getDatastore();
	$db = vB::getDbAssertor();
	$phraseApi = vB_Api::instanceInternal('phrase');

	$globalignore = $datastore->getOption('globalignore');
	if (trim($globalignore) != '')
	{
		$coventry = preg_split('#\s+#s', $globalignore, -1, PREG_SPLIT_NO_EMPTY);
	}
	else
	{
		$coventry = array();
	}

	require_once(DIR . '/includes/class_bbcode_alt.php');
	$vbulletin = vB::get_registry();
	$plaintext_parser = new vB_BbCodeParser_PlainText($vbulletin, fetch_tag_list());

	vB_Mail::vbmailStart();

	$bf_misc_useroptions = $datastore->getValue('bf_misc_useroptions');
	$bf_ugp_genericoptions = $datastore->getValue('bf_ugp_genericoptions');
	$bf_ugp_forumpermissions = $datastore->getValue('bf_ugp_forumpermissions');

	// get new threads (Topic Subscription)
	$threads = $db->getRows('getNewThreads', array(
		'dstonoff' => $bf_misc_useroptions['dstonoff'],
		'isnotbannedgroup' => $bf_ugp_genericoptions['isnotbannedgroup'],
		'lastdate' => intval($lastdate)
	));

	// grab all forums / subforums for given subscription (Channel Subscription)
	$forums = $db->assertQuery('getNewForums', array(
		'dstonoff' => $bf_misc_useroptions['dstonoff'],
		'type' => intval($type),
		'lastdate' => intval($lastdate),
		'channelcontenttype' => vB_Api::instanceInternal('contenttype')->fetchContentTypeIdFromClass('Channel'),
		'isnotbannedgroup' => $bf_ugp_genericoptions['isnotbannedgroup']
	));

	// we want to fetch all language records at once and using cache if possible
	$defaultLanguage = false;
	$languageIds = array();

	// Let's see which languageids we wanna fetch
	foreach ($threads AS $thread)
	{
		if ($thread['languageid'] == 0)
		{
			if (!$defaultLanguage)
			{
				$defaultLanguage = intval($datastore->getOption('languageid'));
				$languageIds[] = $defaultLanguage;
			}
		}
		else
		{
			$languageIds[] = $thread['languageid'];
		}
	}

	foreach ($forums AS $forum)
	{
		if ($forum['languageid'] == 0)
		{
			if (!$defaultLanguage)
			{
				$defaultLanguage = intval($datastore->getOption('languageid'));
				$languageIds[] = $defaultLanguage;
			}
		}
		else
		{
			$languageIds[] = $forum['languageid'];
		}
	}

	// fetch languages
	$defaultDateformat = $datastore->getOption('dateformat');
	$defaultTimeformat = $datastore->getOption('timeformat');
	$languages = vB_Library::instance('language')->fetchLanguages($languageIds);

	//update the date formats if we don't have them
	foreach($languages AS $key => $langInfo)
	{
		if(!$langInfo['dateoverride'])
		{
			$languages[$key]['dateoverride'] = $defaultDateformat;
		}

		if(!$langInfo['timeoverride'])
		{
			$languages[$key]['timeoverride'] = $defaultTimeformat;
		}
	}

	$currentUserId = vB::getCurrentSession()->get('userid');
	$request = vB::getRequest();

	try
	{
		// process threads -- note that "thread" is a hybrid record of the
		// subscription, the subscribed user, and the subscribed thread.  Some of the fields may not
		// be what you are expecting them to be.
		foreach ($threads AS $thread)
		{
			$postbits = '';

			// Make sure user have correct email notification settings.
			if ($thread['emailnotification'] != $type)
			{
				continue;
			}

			if ($thread['lastauthorid'] != $thread['userid'] AND in_array($thread['lastauthorid'], $coventry))
			{
				continue;
			}

			//privilege escalation.  This isn't something to do lightly, but as a backend script we really need
			//to generate the email with the permissions of the person we are sending it to
			$request->createSessionForUser($thread['userid']);

			$usercontext = vB::getUserContext($thread['userid']);
			if (
				!$usercontext->getChannelPermission('forumpermissions', 'canview', $thread['nodeid']) OR
				!$usercontext->getChannelPermission('forumpermissions', 'canviewthreads', $thread['nodeid']) OR
				($thread['authorid'] != $thread['userid'] AND !$usercontext->getChannelPermission('forumpermissions', 'canviewothers', $thread['nodeid']))
			)
			{
				continue;
			}

			$langInfo = $languages[$thread['languageid']];

			$userinfo = array(
				'lang_locale'    => $langInfo['locale'],
				'dstonoff'       => $thread['dstonoff'],
				'timezoneoffset' => $thread['timezoneoffset'],
			);

			//this is the *subscribing* user, not a user associated with the thread.
			$thread['username'] = unhtmlspecialchars($thread['username']);
			$thread['newposts'] = 0;

			//change some fields from the query to better display in the email.
			exec_digest_modify_thread($thread, $phraseApi, $langInfo, $userinfo);

			// Note: closure.depth = 1  on the where clause means getNewPosts only grabs replies, not comments.
			$posts = $db->getRows('getNewPosts', array('threadid' => intval($thread['nodeid']), 'lastdate' => intval($lastdate)));

			// compile
			$haveothers = false;
			foreach ($posts AS $post)
			{
				if ($post['userid'] != $thread['userid'] AND in_array($post['userid'], $coventry))
				{
					continue;
				}

				if ($post['userid'] != $thread['userid'])
				{
					$haveothers = true;
				}

				$thread['newposts']++;
				$post['htmltitle'] = unhtmlspecialchars($post['htmltitle']);
				$post['postdate'] = vbdate($langInfo['dateoverride'], $post['publishdate'], false, true, true, false, $userinfo);
				$post['posttime'] = vbdate($langInfo['timeoverride'], $post['publishdate'], false, true, true, false, $userinfo);
				$post['postusername'] = unhtmlspecialchars($post['postusername']);

				$contentAPI = vB_Library_Content::getContentApi($post['contenttypeid']);
				$contents = $contentAPI->getContent($post['nodeid']);

				$plaintext_parser->set_parsing_language($thread['languageid']);
				$post['pagetext'] = $plaintext_parser->parse($contents[$post['nodeid']]['rawtext'], $thread['parentid']);

				$postlink = vB5_Route::buildUrl($post['routeid'] . '|bburl', array('nodeid' => $post['nodeid']));

				$phrase = array(
					'digestpostbit',
					$post['htmltitle'],
					$postlink,
					$post['postusername'],
					$post['postdate'],
					$post['posttime'],
					$post['pagetext'],
				);
				$phrases = $phraseApi->renderPhrasesNoShortcode(array('postbit' => $phrase), $thread['languageid']);

				$postbits .= $phrases['phrases']['postbit'];
			}

			// Don't send an update if the subscriber is the only one who posted in the thread.
			if ($haveothers)
			{
				// make email
				// magic vars used by the phrase eval
				$threadlink = vB5_Route::buildUrl($thread['routeid'] . '|fullurl', array('nodeid' => $thread['nodeid']));

				//this link probably doesn't do what the author thinks it does, need to validate.
				$unsubscribelink =  vB5_Route::buildUrl('subscription|fullurl', array('tab' => 'subscriptions', 'userid' => $thread['userid']));

				$maildata = $phraseApi->fetchEmailPhrases(
					'digestthread',
					array(
						$thread['username'],
						$thread['prefix_plain'],
						$thread['htmltitle'],
						$thread['postusername'],
						$thread['newposts'],
						$thread['lastposter'],
						$threadlink,
						$postbits,
						$datastore->getOption('bbtitle'),
						$unsubscribelink,
					),
					array(
						$thread['prefix_plain'],
						$thread['htmltitle'],
					),
					$thread['languageid']
				);
				vB_Mail::vbmail($thread['email'], $maildata['subject'], $maildata['message']);
			}
		}

		unset($plaintext_parser);

		// process forums
		foreach ($forums as $forum)
		{
			$langInfo =& $languages[$forum['languageid']];

			$userinfo = array(
				'lang_locale'       => $langInfo['locale'],
				'dstonoff'          => $forum['dstonoff'],
				'timezoneoffset'    => $forum['timezoneoffset'],
			);

			$newthreadbits = '';
			$newthreads = 0;
			$updatedthreadbits = '';
			$updatedthreads = 0;

			$forum['username'] = unhtmlspecialchars($forum['username']);
			$forum['title_clean'] = unhtmlspecialchars($forum['title_clean']);

			$threads = $db->assertQuery('fetchForumThreads', array(
				'forumid' =>intval($forum['forumid']),
				'lastdate' => intval ($lastdate)
			));

			//privilege escalation.  This isn't something to do lightly, but as a backend script we really need
			//to generate the email with the permissions of the person we are sending it to
			$request->createSessionForUser($forum['userid']);

			$usercontext = vB::getUserContext($forum['userid']);
			foreach ($threads AS $thread)
			{
				if ($thread['userid'] != $forum['userid'] AND in_array($thread['userid'], $coventry))
				{
					continue;
				}

				// allow those without canviewthreads to subscribe/receive forum updates as they contain not post content
				if (
					!$usercontext->getChannelPermission('forumpermissions', 'canview', $thread['nodeid']) OR
					($thread['userid'] != $forum['userid'] AND !$usercontext->getChannelPermission('forumpermissions', 'canviewothers', $thread['nodeid']))
				)
				{
					continue;
				}

				//change some fields from the query to better display in the email.
				exec_digest_modify_thread($thread, $phraseApi, $langInfo, $userinfo);

				$threadlink = vB5_Route::buildUrl($thread['routeid'] . '|fullurl', array('nodeid' => $thread['nodeid']));

				//this apparently used to be an email phrase, but it no longer is.  The subject phrase half doesn't
				//exist.  There is no point in using the email render function for this.
				$phrase = array(
					'digestthreadbit_gemailbody',
					$thread['prefix_plain'],
					$thread['htmltitle'],
					$threadlink,
					$thread['forumhtmltitle'],
					$thread['postusername'],
					$thread['lastreplydate'],
					$thread['lastreplytime']
				);
				$phrases = $phraseApi->renderPhrasesNoShortcode(array('threadbit' => $phrase), $forum['languageid']);

				if ($thread['dateline'] > $lastdate)
				{
					// new thread
					$newthreads++;
					$newthreadbits .= $phrases['phrases']['threadbit'];
				}
				else
				{
					$updatedthreads++;
					$updatedthreadbits .= $phrases['phrases']['threadbit'];
				}
			}

			if (!empty($newthreads) OR !empty($updatedthreadbits))
			{
				// make email
				$forumlink = vB5_Route::buildUrl($forum['routeid'] . '|fullurl', array('nodeid' => $forum['forumid']));

				//this link probably doesn't do what the author thinks it does.  Need to validate.
				$unsubscribelink = vB5_Route::buildUrl('subscription|fullurl', array('tab' => 'subscriptions', 'userid' => $forum['userid']));

				$maildata = $phraseApi->fetchEmailPhrases(
					'digestforum',
					array(
						$forum['username'],
						$forum['title_clean'],
						$newthreads,
						$updatedthreads,
						$forumlink,
						$newthreadbits,
						$updatedthreadbits,
						$datastore->getOption('bbtitle'),
						$unsubscribelink,
					),
					array($forum['title_clean']),
					$forum['languageid']
				);
				vB_Mail::vbmail($forum['email'], $maildata['subject'], $maildata['message'], true);
			}
		}
	}
	finally
	{
		//this may not be strictly necesary because the script more or less ends at this point (and the cron stuff
		//needs to run as any user anyway), but it's more than a little tacky to drop out the function without
		//resetting the privs.  Somebody might call it later without realizing they are doing something hideously
		//insecure.
		$request->createSessionForUser($currentUserId);
	}

	vB_Mail::vbmailEnd();
}


//should be considered private to this file
function exec_digest_modify_thread(&$thread, $phraseApi, $langInfo, $userinfo)
{
	$thread['lastreplydate'] = vbdate($langInfo['dateoverride'], $thread['lastcontent'], false, true, true, false, $userinfo);
	$thread['lastreplytime'] = vbdate($langInfo['timeoverride'], $thread['lastcontent'], false, true, true, false, $userinfo);
	$thread['htmltitle'] = unhtmlspecialchars($thread['htmltitle']);
	$thread['postusername'] = unhtmlspecialchars($thread['authorname']);
	$thread['lastposter'] = unhtmlspecialchars($thread['lastcontentauthor']);

	if ($thread['prefixid'])
	{
		//it would be possible to batch these to some extent.  Not sure if it's worth it.
		$phrases = $phraseApi->renderPhrasesNoShortcode(array('prefix' => array("prefix_$thread[prefixid]_title_plain")), $langInfo['languageid']);
		$thread['prefix_plain']= $phrases['phrases']['prefix'];
	}
	else
	{
		$thread['prefix_plain'] = '';
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103396 $
|| #######################################################################
\*=========================================================================*/
