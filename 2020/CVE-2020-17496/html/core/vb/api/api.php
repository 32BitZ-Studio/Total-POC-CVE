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
 * vB_Api_Api
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Api extends vB_Api
{
	/**
	 * @var	vB_dB_Assertor Instance of the database assertor
	 * @todo Remove this and have an $assertor instance set in the parent class vB_Api for all APIs
	 */
	protected $dbassertor;

	/**
	 * Constructor
	 */
	protected function __construct()
	{
		parent::__construct();

		$this->dbassertor = vB::getDbAssertor();
	}

	/**
	 * Initializes an API client
	 *
	 * @param  int              $api_c API Client ID
	 * @param  array            $apiclientdata 'clientname', 'clientversion', 'platformname', 'platformversion', 'uniqueid'
	 *
	 * @throws vB_Exception_Api Throws 'apiclientinfomissing' if any of clientname, clientversion, platformname, platformversion, or uniqueid are missing.
	 *
	 * @return array            Api information, format:
	 *                          array(
	 *                              apiversion => string
	 *                              apiaccesstoken => string
	 *                              bbtitle => string
	 *                              bburl => string
	 *                              bbactive => int
	 *                              bbclosedreason => string (only set if bbactive = 0)
	 *                              forumhome => string
	 *                              vbulletinversion => string
	 *                              contenttypes => array(
	 *                                  content type class => content type id
	 *                                  [...]
	 *                              )
	 *                              features => array(
	 *                                  blogenabled => int
	 *                                  cmsenabled => int
	 *                                  pmsenabled => int
	 *                                  searchesenabled => int
	 *                                  groupsenabled => 1
	 *                                  albumsenabled => 0
	 *                                  multitypesearch => 1
	 *                                  visitor_messagingenabled => 1
	 *                                  taggingenabled => int
	 *                                  visitor_trackingenabled => 0
	 *                                  paidsubs => int
	 *                                  friendsenabled => 1
	 *                                  activitystream => 1
	 *                                  facebookenabled => int
	 *                                  calendarenabled => 1
	 *                              )
	 *                              permissions => empty array
	 *                              show => array(
	 *                                  registerbutton => 1
	 *                              )
	 *                              apiclientid => int
	 *                              secret => string (only if API Client ID was specified in the call)
	 *                          )
	 */
	public function init($clientname, $clientversion, $platformname, $platformversion, $uniqueid, $api_c = 0)
	{
		$clientname = strip_tags($clientname);
		$clientversion = strip_tags($clientversion);
		$platformname = strip_tags($platformname);
		$platformversion = strip_tags($platformversion);
		$uniqueid = strip_tags($uniqueid);
		$api_c = intval($api_c);

		$oldclientid = $api_c;
		if (!$api_c)
		{
			// The client doesn't have an ID yet. So we need to generate a new one.

			// All params are required.
			// uniqueid is the best to be a permanent unique id such as hardware ID (CPU ID,
			// Harddisk ID or Mobile IMIE). Some client can not get a such a uniqueid,
			// so it needs to generate an unique ID and save it in its local storage. If it
			// requires the client ID and Secret again, pass the same unique ID.
			if (!$clientname OR !$clientversion OR !$platformname OR !$platformversion OR !$uniqueid)
			{
				throw new vB_Exception_Api('apiclientinfomissing');
			}

			// Gererate clienthash.
			$clienthash = md5($clientname . $platformname . $uniqueid);

			// Generate a new secret
			$random = new vB_Utility_Random();
			$secret = $random->alphanumeric(32);

			// If the same clienthash exists, return secret back to the client.
			$client = $this->dbassertor->getRow('apiclient', array('clienthash' => $clienthash));

			$api_c = $client['apiclientid'];

			if ($api_c)
			{
				// Update secret
				// Also remove userid so it will logout previous loggedin and remembered user. (VBM-553)
				$this->dbassertor->update('apiclient',
					array(
						'secret' => $secret,
						'apiaccesstoken' => vB::getCurrentSession()->get('apiaccesstoken'),
						'lastactivity' => vB::getRequest()->getTimeNow(),
						'clientversion' => $clientversion,
						'platformversion' => $platformversion,
						'userid' => 0
					),
					array(
						'apiclientid' => $api_c,
					)
				);
			}
			else
			{
				$api_c = $this->dbassertor->insert('apiclient', array(
					'secret' => $secret,
					'clienthash' => $clienthash,
					'clientname' => $clientname,
					'clientversion' => $clientversion,
					'platformname' => $platformname,
					'platformversion' => $platformversion,
					'initialipaddress' => vB::getRequest()->getAltIp(),
					'apiaccesstoken' => vB::getCurrentSession()->get('apiaccesstoken'),
					'dateline' => vB::getRequest()->getTimeNow(),
					'lastactivity' => vB::getRequest()->getTimeNow(),
				));

				if (is_array($api_c))
				{
					$api_c = array_pop($api_c);
				}
				$api_c = (int) $api_c;
			}

			// Set session client ID
			vB::getCurrentSession()->set('apiclientid', $api_c);
		}
		else
		{
			// api_c and api_sig are verified in init.php so we don't need to verify here again.
			$api_c = intval($api_c);

			// Update lastactivity
			$this->dbassertor->update('apiclient',
				array(
					'lastactivity' => vB::getRequest()->getTimeNow(),
				),
				array(
					'apiclientid' => $api_c,
				)
			);
		}

		$contenttypescache = vB_Types::instance()->getContentTypes();

		$contenttypes = array();
		foreach ($contenttypescache as $contenttype)
		{
			$contenttypes[$contenttype['class']] = $contenttype['id'];
		}

		$vboptions = vB::getDatastore()->getValue('publicoptions');
		$session = vB::getCurrentSession();
		$userinfo = $session->fetch_userinfo();

		try
		{
		 	vB_Api::instanceInternal('paidsubscription')->checkStatus();
		 	$paidsubs = 1;
		}
		catch (Exception $e)
		{
		 	$paidsubs = 0;
		}

		$forumHome = vB_Library::instance('content_channel')->getForumHomeChannel();
		// Building the URL might fail if the usergroup (e.g. guests for a completely fresh
		// call to api_init) lacks can view channels permission on the root channel
		// In such a case, just return "" for forumhome param instead of failing - VBV-19193
		try{
			$forumhomeUrl = vB5_Route::buildUrl($forumHome['routeid'] . '|fullurl');
		}
		catch(Exception $e)
		{
			$forumhomeUrl = "";
		}

		$facebookenabled = vB_Api::instanceInternal('Facebook')->isFacebookEnabled();

		/*
			For cmsenabled & blogenabled, we want to check for view perms on the root article & blog
			channels.
			We can just go through the node API which calls content::validate(... ACTION_VIEW) already.
			If the permission checks failed, it'll throw a no_permission error. This may not be 100%
			reliable however since it's possible some other errors outside of the validation could
			block viewing CMS & Blogs, but it's certainly simple.
		 */
		$channelLibrary = vB_Library::instance('Content_Channel');
		$nodeApi = vB_Api::instance('Node');
		$articlesId = $channelLibrary->fetchChannelIdByGUID(vB_Channel::DEFAULT_ARTICLE_PARENT);
		$article = $nodeApi->getNodeFullContent($articlesId);
		$canViewArticles = (empty($article['errors']) AND !empty($article[$articlesId]));

		$blogsId = $channelLibrary->fetchChannelIdByGUID(vB_Channel::DEFAULT_BLOG_PARENT);
		$blog = $nodeApi->getNodeFullContent($blogsId);
		$canViewBlogs = (empty($blog['errors']) AND !empty($blog[$blogsId]));

		$data = array(
			'apiversion' => VB_API_VERSION,
			'apiaccesstoken' => $session->get('apiaccesstoken'),
			'bbtitle' => $vboptions['bbtitle'],
			'bburl' => $vboptions['bburl'],
			'bbactive' => $vboptions['bbactive'],
			'forumhome' => $forumhomeUrl,
			'vbulletinversion' => $vboptions['templateversion'],
			'contenttypes' => $contenttypes,
			'features' => array(
				'blogenabled' => $canViewBlogs ? 1 : 0,
				'cmsenabled' => $canViewArticles ? 1: 0,
				'pmsenabled' => $vboptions['enablepms'] ? 1 : 0,
				'searchesenabled' => $vboptions['enablesearches'] ? 1 : 0,
				'groupsenabled' => 1,
				'albumsenabled' => 0,
				'multitypesearch' => 1,
				'visitor_messagingenabled' => 1,
				'taggingenabled' => $vboptions['threadtagging'] ? 1 : 0,
				'visitor_trackingenabled' => 0,
				'paidsubs' => $paidsubs,
				'friendsenabled' => 1,
				'activitystream' => 1,
				'facebookenabled' => $facebookenabled ? 1 : 0,
				'calendarenabled' => 1,
				'privacyenabled' => $vboptions['enable_privacy_registered'] ? 1 : 0,
				'privacyguestenabled' => $vboptions['enable_privacy_guest'] ? 1 : 0,
			),
			'permissions' => array(),
			'show' => array(
				'registerbutton' => $vboptions['allowregistration'] ? 1 : 0,
				//deliberately reversed logic this setting is "is the user ltr"
				'rtl' => $userinfo['lang_options']['direction'] ? 0 : 1,
			),

		);

		if (!$vboptions['bbactive'])
		{
			$data['bbclosedreason'] = $vboptions['bbclosedreason'];
		}

		$data['apiclientid'] = $api_c;
		if (!$oldclientid)
		{
			$data['secret'] = $secret;
		}
		return $data;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103995 $
|| #######################################################################
\*=========================================================================*/
