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
* Bulk insert CMS data for upgrades
*
* @package 		vBulletin
* @version		$Revision: 101013 $
* @date 		$Date: 2019-03-15 10:31:08 -0700 (Fri, 15 Mar 2019) $
*
*/
class vB_UpgradeHelper_BulkImporter
{
	// bulk parent updates
	protected $parentUpdatesLastcontent = array();
	protected $parentUpdatesLastcontentid = array();
	protected $parentUpdatesLastupdate = array();
	protected $parentUpdatesTextcount = array();
	protected $parentUpdatesTextunpubcount = array();
	protected $parentUpdatesTotalcount = array();
	protected $parentUpdatesTotalunpubcount = array();

	// bulk updates
	protected $closureUpdates = array();
	protected $newNodeids = array();


	protected $assertor;
	protected $nodeLibrary;
	protected $textLibrary;
	//protected $searchLibrary;
	protected $nodeFields;
	protected $textFields;

	public function __construct()
	{
		$this->assertor = vB::getDbAssertor();
		$this->nodeLibrary = vB_Library::instance('node');
		$this->textLibrary = vB_Library::instance('content_text');
		//$this->searchLibrary = vB_Library::instance('search');
		$this->nodeFields = $this->nodeLibrary->getNodeFields();
		$textStructure = $this->assertor->fetchTableStructure('vBForum:text');
		$this->textFields = $textStructure['structure'];
	}

	public function importBulkCMSArticles(Iterator $source, $extra = array())
	{
		/*
			$source should be an iterator with a valid() function.
			Each element in the iterator should be an array with the following keys
				int       contenttypeid
				int       parentid           (nodeid)
				string    title
				string    description
				string    htmltitle
				string    urlident
				int       publishdate        (unixtimestamp)
				int       created            (unixtimestamp)
				int       lastupdate         (unixtimestamp)
				int       oldid
				int       oldcontenttypeid
				int       inlist             (0|1, basically bool)
				int       userid
				string    authorname
				string    previewtext
				string    previewimage
				int       public_preview     (0|1, basically bool)
				string    rawtext
				string    htmlstate          ('on'|'off'|'on_nl2br')
				int       displayorder



			todos:
				set `node`.`inlist` based on vb4's `cms_node`.`nosearch`? We don't currently support that...
				what is cms_node.hidden for?

		 */
		if (!$source->valid())
		{
			return false;
		}

		$this->assertor->beginTransaction();

		foreach($source AS $articleOrPage)
		{
			$nodeid = $this->processSingleArticleStarterData($articleOrPage);
			if (!$nodeid)
			{
				// an insert failed. Let's just rollback the entire thing.
				$this->assertor->rollbackTransaction();
				return false;
			}
		}

		$nodeids = $this->newNodeids;

		$this->doBulkUpdates();

		$this->assertor->commitTransaction();

		return $nodeids;
	}

	protected function doBulkUpdates()
	{
		// Set starters & lastcontentids to self.
		// For lastcontentid, articles will always have itself as the lastcontentid as comments added via ajax never
		// change parent lastcontent due to skipUpdateLastContent. See vB5_Frontend_Controller_Ajax::actionPostComment()
		$this->assertor->assertQuery("vBInstall:setStarterAndLastcontentidSelfByNodeList",
			array(
				'nodeList' => $this->newNodeids,
			)
		);

		// closures
		$this->assertor->assertQuery("vBInstall:addClosureSelfForNodes", array('nodeid' => $this->newNodeids));
		$this->assertor->assertQuery("vBInstall:addClosureParentsForNodes", array('nodeid' => $this->newNodeids));

		// routes
		$this->assertor->assertQuery("vBInstall:updateChannelRouteidToArticleRouteidByNodelist",
			array(
				'nodeList' => $this->newNodeids,
			)
		);

		/*
		For now, let's leave search indexing to the admin. There's already a step in 520a1 that'll notify the
		admin to rebuild search indices.

		// search indices
		foreach ($this->newNodeids AS $nodeid)
		{
			// clear any existing caches for the nodeid since we've updated data above
			$this->nodeLibrary->clearCacheEvents($nodeid);
			this->searchLibrary->index($nodeid);
			// clear any caches for the nodeid in case indexing created any.
			$this->nodeLibrary->clearCacheEvents($nodeid);
		}
		*/

		// no addTags(), tags are added separately in 510a2::step_6()

		// no notifications

		// cleanup
		$this->newNodeids = array();

		// ancestor counts, lastcontent, lastcontentid
		$parentids = array_keys($this->parentUpdatesLastcontent);
		foreach ($parentids AS $parentid)
		{
			$this->assertor->assertQuery("vBInstall:updateChannelCountsAndLastContentAndPropagateUp",
				array(
					'lastcontent' => $this->parentUpdatesLastcontent[$parentid],
					'lastcontentid' => $this->parentUpdatesLastcontentid[$parentid],
					'lastcontentauthor' => $this->parentUpdatesLastcontentauthor[$parentid],
					'lastauthorid' => $this->parentUpdatesLastauthorid[$parentid],

					'textcount' => $this->parentUpdatesTextcount[$parentid],
					'textunpubcount' => $this->parentUpdatesTextunpubcount[$parentid],
					'totalcount' => $this->parentUpdatesTotalcount[$parentid],
					'totalunpubcount' => $this->parentUpdatesTotalunpubcount[$parentid],

					'channelid' => $parentid,
				)
			);
		}

		// cleanup
		$this->parentUpdatesLastcontent = array();
		$this->parentUpdatesLastcontentid = array();
		$this->parentUpdatesLastcontentauthor = array();
		$this->parentUpdatesLastauthorid = array();
		$this->parentUpdatesTextcount = array();
		$this->parentUpdatesTextunpubcount = array();
		$this->parentUpdatesTotalcount = array();
		$this->parentUpdatesTotalunpubcount = array();

		// Clear ancestors' cache so next iteration has updated lastcontent data etc.
		$ancestorCacheEvents = array();
		$ancestors = $this->assertor->assertQuery(
			"vBForum:closure",
			array(
				vB_dB_Query::COLUMNS_KEY => array("parent"),
				"child" => $parentids,
			)
		);
		foreach ($ancestors AS $row)
		{
			// key by id just so we can skip array_unique(), no other meaning.
			$ancestorCacheEvents[$row['parent']] = "nodeChg_" . $row['parent'];
		}

		vB_Cache::allCacheEvent($ancestorCacheEvents);
		unset($ancestorCacheEvents);
		unset($parentids);
	}

	protected function processSingleArticleStarterData(&$data)
	{
		/*
			I don't recall exactly why this is needed.. possibly to strip out any characters
			that used to be allowed in vB4's `cms_node`.`url` field that's not allowed in
			vB5's node.urlident / routenew.prefix .

			I'm not sure what happens to articles that had custom URLs (if that was allowed in vB4),
			we may want to create a custom route for those and handle it better than this
		 */
		$data['urlident'] = vB_String::getUrlIdent($data['urlident']);

		/*
			Below replicates bits of vB_Library_Content_Text::add()
		 */


		$convertWysiwygTextToBbcode = false;
		/*
			todo: If we need convertWysiwygTextToBbcode logic, check how vB_Library_Content_Text::add() does it.
			It's a chunk of logic for chekcing parent channel option then passing it through bbcode parser,
			and we apparently do not need it for vB4 CMS imports, so I'm skipping it entirely.

		 */

		// todo: parseAndStrip original descriptions???
		/*
		if (empty($data['description']))
		{
			$data['description'] = (isset($data['title'])) ?
				(vB_String::getPreviewText($this->textLibrary->parseAndStrip($data['title']))) : '';
		}
		else
		{
			$data['description'] = vB_String::getPreviewText($this->textLibrary->parseAndStrip($data['description']));
		}
		*/

		/*
			Skipping the following intentionally:

			Shout prevention - If the old site allowed shouting in CMS titles, pass it through.

			Userid/authorname validation - If the old article was by a guest or some nonsensical
				userid / authorname combination, keep it the same.

			Check spam - We're just importing old data, not a good time for spam checking.


		 */

		//Set the "hasvideo" value;
		if (!empty($data['rawtext']))
		{
			$filter = '~\[video.*\[\/video~i';
			$matches = array();
			$count = preg_match_all($filter, $data['rawtext'], $matches);

			if ($count > 0 )
			{
				$data['hasvideo'] = 1;
			}
			else
			{
				$data['hasvideo'] = 0;
			}
		}



		/*
			Below replicates bits of of vB_Library_Content::add()
		 */


		/*
			todo: AFAIK vb4 CMS nodes/articles did not keep track of ipaddress.. and it doesn't makes sense
			to use the current session's IP address as it'll be either local (CLI upgrade) or an admin's
			(web upgrade)...

			So we'll leave it empty for now.
			if (empty($data['ipaddress']))
			{
				$data['ipaddress'] = vB::getRequest()->getIpAddress();
			}

		 */


		//$parentInfo = $this->nodeLibrary->getNodeFullContent($data['parentid']);
		//$parentInfo = $parentInfo[$data['parentid']];

		$parentInfo = vB_Library::instance('node')->getNodeContent($data['parentid']);
		$parentInfo = $parentInfo[$data['parentid']];

		// protected - inherit from parent
		$data['protected'] = $parentInfo['protected'];

		// starter - these are articles so they're always starters
		//$data['starter']

		// no prefixid ATM

		// no iconid ATM


		// lastupdate, created & publishdate should be the original date, NOT current time!

		// showpublished
		$data['showpublished'] = 0;
		$timeNow = vB::getRequest()->getTimeNow();
		$showpublished = (
			$parentInfo['showpublished'] == 1 AND
			$data['publishdate'] > 0 AND
			$data['publishdate'] <= $timeNow AND
			(
				empty($data['unpublishdate']) OR
				$data['unpublishdate'] <= 0 OR
				$data['unpublishdate'] >= $timeNow OR
				$data['unpublishdate'] < $data['publishdate']
			)
		);
		if ($showpublished)
		{
			$data['showpublished'] = 1;
		}

		// todo: viewperms

		// todo: featured



		if (empty($data['htmltitle']) AND !empty($data['title']))
		{
			$data['htmltitle'] = vB_String::htmlSpecialCharsUni(vB_String::stripTags($data['title']), false);
		}



		$nodevals = array();
		foreach ($data as $field => $value)
		{
			if (in_array($field, $this->nodeFields))
			{
				$nodevals[$field] = $value;
			}
		}


		if (empty($nodevals))
		{
			return false;
		}


		//default to open
		if(!isset($nodevals['open']))
		{
			$nodevals['open'] = 1;
		}

		//popagate show open from parent.  Some people can post to a closed node.
		$nodevals['showopen'] = ($nodevals['open'] AND $parentInfo['showopen']) ? 1 : 0;

		$nodevals['contenttypeid'] = vB_Types::instance()->getContentTypeId('vBForum_Text');
		$nodevals[vB_dB_Query::TYPE_KEY] = vB_dB_Query::QUERY_INSERT;

		if (isset($nodevals['publishdate']) AND ($nodevals['publishdate'] > $timeNow))
		{
			if (empty($nodevals['unpublishdate']) OR ($nodevals['unpublishdate'] > $nodevals['publishdate']))
			{
				$nodevals['nextupdate'] = $nodevals['publishdate'];
			}
		}
		else if (!empty($nodevals['unpublishdate']) AND ($nodevals['unpublishdate'] > $timeNow))
		{
			$nodevals['nextupdate'] = $nodevals['unpublishdate'];
		}

		// Update: For some reason, during upgrades, 'channeltype' from getNodeFullContent() is just blank.
		/*
		// TODO: I left this blog bit in here but I initially did NOT start writing this for both blog entries
		// and CMS articles, only the latter. So I'll need to re-review above to see if it's suitable for blog
		// imports as well.
		if($parentInfo['channeltype'] == 'blog')
		{
			// KEEP THIS IN SYNC WITH vB_Library_Content::$defaultNodeOptions['blog']
			$nodevals['nodeoptions'] = 522;
		}
		else
		{
		}
		*/
		$nodevals['nodeoptions'] = $parentInfo['nodeoptions'];

		// Set it to parent's routeid for now. It'll be fixed in bulk by updateChannelRouteidToArticleRouteidByNodelist
		$nodevals['routeid'] = $parentInfo['routeid'];

		// approved/showapproved, AFAIK vb4 CMS didn't have relevant approve fields..
		// assume it's been approved if it's been published.
		// We're skipping all of the permission check logic for this upgrade import.
		$nodevals['approved'] = 1;
		$nodevals['showapproved'] = ($nodevals['approved'] AND $parentInfo['showapproved']);

		/*
			last content notes

			Currently, "comments" in articles & blogs do not update their parent (article or blog starter)'s
			lastcontent because the controller sets skipUpdateLastContent => 1 in the content::add() call.
			We need to move this logic out of the controller and into the backend code, but for now, we can
			assume that any article is going to always have itself for the lastcontent data.
			We cannot set the lastcontentid field until after we have the nodeid (thus after we insert the
			node record). We'll leave that for the bulk updates later, and set the rest.
		 */
		// $nodevals['lastcontentid'] = // todo:
		$nodevals['lastcontent'] = $nodevals['publishdate'];
		$nodevals['lastcontentauthor'] = $nodevals['authorname'];
		$nodevals['lastauthorid'] = $nodevals['userid'];


		// Insert node record
		$nodeid = $this->assertor->assertQuery('vBForum:node', $nodevals);
		if (!$nodeid)
		{
			return false;
		}

		if (is_array($nodeid))
		{
			$nodeid = $nodeid[0];
		}

		// helper for subsequent processing
		$nodevals['nodeid'] = $nodeid;
		$this->registerBulkParentUpdates($nodevals, $parentInfo);


		// All articles are starters. Set starter.
		$this->newNodeids[] = $nodeid;
		/*
		$update = array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'starter' => $nodeid, 'nodeid' => $nodeid);
		$assertor->assertQuery('vBForum:node', $update);
		*/

		// Text data
		/*
			We could potentially switch this to do a bulk SQL instead like follows and that might be faster:
			INSERT INTO `text` (nodeid, rawtext, htmlstate, ...)
			SELECT
				...nodeid
				article.pagetext AS rawtext,
				article.htmlstate,

				article.previewtext,
				article.previewimage,
				article.previewvideo,
				article.imageheight,
				article.imagewidth,
				...
			FROM {TABLE_PREFIX}cms_node AS cms_node
			INNER JOIN {TABLE_PREFIX}cms_nodeinfo AS cms_nodeinfo
				ON cms_nodeinfo.nodeid = cms_node.nodeid
			INNER JOIN {TABLE_PREFIX}node AS category
				ON category.oldid = cms_node.parentnode AND category.oldcontenttypeid = {oldcontenttypeid_section}
			INNER JOIN {TABLE_PREFIX}cms_article AS article
				ON article.contentid = cms_node.contentid
			.. WHERE cms_node.nodeid IN {oldids}

			We could also do the same for the node data above.
			If this method isn't fast enough, we'll consider the other way.
			Also note that in that case this won't be a "generic" class but custom fitted for vb4 upgrades.
		 */

		$queryData = array();
		$queryData[vB_dB_Query::TYPE_KEY] = vB_dB_Query::QUERY_INSERT;
		foreach ($this->textFields AS $fieldname)
		{
			if (isset($data[$fieldname]))
			{
				$queryData[$fieldname] = $data[$fieldname];
			}
		}
		$queryData['nodeid'] = $nodeid;
		$this->assertor->assertQuery('vBForum:text', $queryData);


		return $nodeid;
	}

	protected function registerBulkParentUpdates($nodevals, $parentInfo)
	{
		$parentid = $nodevals['parentid'];
		// abs val updates
		if (!isset($this->parentUpdatesLastcontent[$parentid]))
		{
			$this->parentUpdatesLastcontent[$parentid] = $parentInfo['lastcontent'];
		}
		if (!isset($this->parentUpdatesLastcontentid[$parentid]))
		{
			$this->parentUpdatesLastcontentid[$parentid] = $parentInfo['lastcontentid'];
		}
		if (!isset($this->parentUpdatesLastupdate[$parentid]))
		{
			$this->parentUpdatesLastupdate[$parentid] = $parentInfo['lastupdate'];
		}
		// integer delta updates
		if (!isset($this->parentUpdatesTextcount[$parentid]))
		{
			$this->parentUpdatesTextcount[$parentid] = 0;
		}
		if (!isset($this->parentUpdatesTextunpubcount[$parentid]))
		{
			$this->parentUpdatesTextunpubcount[$parentid] = 0;
		}
		if (!isset($this->parentUpdatesTotalcount[$parentid]))
		{
			$this->parentUpdatesTotalcount[$parentid] = 0;
		}
		if (!isset($this->parentUpdatesTotalunpubcount[$parentid]))
		{
			$this->parentUpdatesTotalunpubcount[$parentid] = 0;
		}


		if ($nodevals['showpublished'])
		{
			$this->parentUpdatesTextcount[$parentid]++;
			$this->parentUpdatesTotalcount[$parentid]++;
		}
		else
		{
			$this->parentUpdatesTextunpubcount[$parentid]++;
			$this->parentUpdatesTotalunpubcount[$parentid]++;
		}

		// Note, showpublished implicitly checked publishdate <= timeNow
		if ($nodevals['showpublished'] AND
			$nodevals['publishdate'] >= $this->parentUpdatesLastcontent[$parentid]
		)
		{
			$this->parentUpdatesLastcontent[$parentid] = $nodevals['publishdate'];
			$this->parentUpdatesLastcontentid[$parentid] = $nodevals['nodeid'];
			$this->parentUpdatesLastcontentauthor[$parentid] = $nodevals['lastcontentauthor'];
			$this->parentUpdatesLastauthorid[$parentid] = $nodevals['lastauthorid'];
		}

		// todo: do child additions affect parent lastupdate ??
		// for now, let's not touch them as channel lastupdates are fairly volatile and
		// their accuracy isn't as critical, and they're likely current set to timenow
		// due to channels currently being imported by the content libraries which will
		// set lastupdate to timenow instead of the publishdate/created date of the
		// most recent article.
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| #######################################################################
\*=========================================================================*/
