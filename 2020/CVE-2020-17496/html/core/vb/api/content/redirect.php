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
 * vB_Api_Content_Redirect
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Content_Redirect extends vB_Api_Content_Text
{
	//override in client- the text name
	protected $contenttype = 'vBForum_Redirect';

	//The table for the type-specific data.
	protected $tablename = array('redirect');

	/**
	 * Constructor, no external instantiation.
	 */
	protected function __construct()
	{
		parent::__construct();
		$this->library = vB_Library::instance('Content_Redirect');
	}

	/**
	 * Adds a new node.
	 *
	 * @param  mixed   $data Array of field => value pairs which define the record.
	 * @param  array   $options Array of options for the content being created.
	 *                 Understands skipTransaction, skipFloodCheck, floodchecktime, skipDupCheck, skipNotification, nl2br, autoparselinks.
	 *                 - nl2br: if TRUE, all \n will be converted to <br /> so that it's not removed by the html parser (e.g. comments).
	 *                 - wysiwyg: if true convert html to bbcode.  Defaults to true if not given.
	 *
	 * @return integer the new nodeid
	 */
	public function add($data, $options = array())
	{
		if (!$this->library->validate($data, vB_Library_Content::ACTION_ADD))
		{
			throw new vB_Exception_Api('no_create_permissions');
		}

		$data = $this->cleanInput($data);
		$this->cleanOptions($options);

		$wysiwyg = true;
		if(isset($options['wysiwyg']))
		{
			$wysiwyg = (bool) $options['wysiwyg'];
		}

		$result = $this->library->add($data, $options, $wysiwyg);
		return $result['nodeid'];
	}


	/**
	 * Remove redirects that point to this node
	 *
	 * Requires admincp session.
	 *
	 * @param int $nodeid
	 * @return standard success array
	 */
	public function removeRedirectsFromNode($nodeid)
	{
		//don't allow arrays or other weird data
		$nodeid = intval($nodeid);

		//allow clearing related redirects for a node *if*
		//* user is a moderator (incluses admins)
		//* user has a current CP session
		//* user can delete *this* node (this is a proxy for *has enough permissions*)
		//We explicitly don't require that the user can normally delete the redirect
		//nodes themselves
		$usercontext = vB::getUserContext();
		$db = vB::getDbAssertor();

		if (!$usercontext->isModerator())
		{
			throw new vB_Exception_Api('no_permission');
		}

		$session = vB::getCurrentSession();
		if (!$session->validateCpsession())
		{
			throw new vB_Exception_Api('inlinemodauth_required');
		}

		if(!$usercontext->getChannelPermission('moderatorpermissions', 'canmanagethreads', $nodeid))
		{
			throw new vB_Exception_Api('no_permission');
		}

		$redirects = $db->getColumn('vBForum:redirect', 'nodeid', array('tonodeid' => $nodeid));
		foreach($redirects AS $redirect)
		{
			$this->library->delete($redirect);
		}

		return array('success' => true);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102627 $
|| #######################################################################
\*=========================================================================*/
