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
 * vB_Api_Vb4_newreply
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Vb4_newreply extends vB_Api
{
	public function postreply($threadid, $message, $posthash = null, $subject = null)
	{
		$cleaner = vB::getCleaner();
		$threadid = $cleaner->clean($threadid, vB_Cleaner::TYPE_UINT);
		$message = $cleaner->clean($message, vB_Cleaner::TYPE_STR);
		$subject = $cleaner->clean($subject, vB_Cleaner::TYPE_STR);
		$posthash = $cleaner->clean($posthash, vB_Cleaner::TYPE_STR);

		if (empty($threadid) || empty($message))
		{
			return array("response" => array("errormessage" => array("invalidid")));
		}

		$data = array(
			'parentid' => $threadid,
			'title' => !empty($subject) ? $subject : '(Untitled)',
			'rawtext' => $message,
			'created' => vB::getRequest()->getTimeNow(),
		);
		$result = vB_Api::instance('content_text')->add($data, array('wysiwyg' => false));
		if (empty($result) || !empty($result['errors']))
		{
			return vB_Library::instance('vb4_functions')->getErrorResponse($result);
		}

		vB_Library::instance('vb4_posthash')->appendAttachments($result, $posthash);
		return array('response' => array(
			'errormessage' => 'redirect_postthanks',
			'show' => array(
				'threadid' => $result,
				'postid' => $result,
			),
		));
	}

	public function newreply($threadid, $disablesmilies = false)
	{
		$cleaner = vB::getCleaner();
		$threadid = $cleaner->clean($threadid, vB_Cleaner::TYPE_UINT);

		$thread = vB_Api::instance('node')->getFullContentforNodes(array($threadid));
		if(empty($thread))
		{
			return array("response" => array("errormessage" => array("invalidid")));
		}
		$thread = $thread[0];

		$prefixes = vB_Library::instance('vb4_functions')->getPrefixes($threadid);
		$options = vB::getDatastore()->getValue('options');
		$postattachment = $thread['content']['createpermissions']['vbforum_attach'];
		$postattachment = empty($postattachment) ? 0 : intval($postattachment);

		/*
			additional options' checked checkboxes array...
		 */
		$checked = array(
			'parseurl' => 1,	// vb4 newreply always set this to 'checked="checked"'
			'signature' => "",	// show only if user has non-empty signature.
			//'disablesmilies' => "", // depends on channel.options.allowsmilies.
			"subscribe" => $thread['content']['subscribed'],
		);

		// 	SIGNATURE
		$userContext = vB::getUserContext();
		$currentUserId = $userContext->fetchUserId();
		$signature = vB_Api::instanceInternal('user')->fetchSignature($currentUserId);
		if (!empty($signature))
		{
			$checked['signature'] = 1;
		}

		// 	DISABLESMILIES
		// getDataForParse converts channel.options into bbcodeoptions, and this is used by the
		// frontend nodetext / bbcode parsers
		$textDataArray = vB_Api::instanceInternal('content_text')->getDataForParse(array($threadid));
		$channelAllowsSmilies = $textDataArray[$threadid]['bbcodeoptions']['allowsmilies'];
		if ($channelAllowsSmilies)
		{
			if (!empty($disablesmilies))
			{
				$checked['disablesmilies'] = 1;
			}
			else
			{
				$checked['disablesmilies'] = "";
			}
			$show['smiliebox'] = 1;
		}
		else
		{
			$show['smiliebox'] = 0;
		}


		$out = array(
			'show' => array(
				'tag_option' => 1,
				'smiliebox' => $show['smiliebox'],
			),
			'vboptions' => array(
				'postminchars' => $options['postminchars'],
				'titlemaxchars' => $options['titlemaxchars'],
			),
			'response' => array(
				'title' => '',
				'forumrules' => array(
					'can' => array(
						'postattachment' => $postattachment,
					),
				),
				'prefix_options' => $prefixes,
				'poststarttime' => 0,
				'posthash' => vB_Library::instance('vb4_posthash')->getNewPosthash(),
			),
			'checked' => $checked,
		);
		return $out;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102380 $
|| #######################################################################
\*=========================================================================*/
