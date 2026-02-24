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

/*
if (!isset($GLOBALS['vbulletin']->db))
{
	exit;
}
*/

class vB_Upgrade_510a1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '510a1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.0 Alpha 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.0.6';

	/**
	* Beginning version compatibility
	*
	* @var	string
	*/
	public $VERSION_COMPAT_STARTS = '';

	/**
	* Ending version compatibility
	*
	* @var	string
	*/
	public $VERSION_COMPAT_ENDS   = '';


	/**
	 * Update site navbars (articles home page is added in 5.0.6)
	 */
	public function step_1()
	{
		$this->syncNavbars('navbar_articles');
		$this->long_next_step();
	}


	/**
	 *	Step 2 - Delete Imported CMS stuff from 500a1 step_158 - 160
	 *		We really shouldn't try to salvage the old imported CMS data, because they were imported incorrectly. For instance,
	 *		any nested sections (i.e. further than 1 degree away from the front page) were not imported.
	 */
	public function step_2()
	{
		vB_Upgrade::createAdminSession();
		$assertor = vB::getDbAssertor();

		// based on the old step_158, the oldcontenttypeid for imported sections was the section contenttypeid
		// Since 500a27 step_10 removes old products, we have to try to figure out the contenttypeid of vBCms_Section in a bit roundabout way
		$oldContenttypeid = $assertor->getRow('vBInstall:getvBCMSSectionContenttypeid', array());
		if (!empty($oldContenttypeid))
		{
			$oldContenttypeid = $oldContenttypeid['contenttypeid'];
			// the old cms stuff was imported into the special channel
			$specialChannelId = vB_Api::instanceInternal('content_channel')->fetchChannelIdByGUID(vB_Channel::DEFAULT_CHANNEL_PARENT);

			// step_158 did something weird where it joined to the node table for seemingly no reason, then set the oldid of the CMS root to the nodeid where node.parentid = 0
			// i.e. probably the node id of the root node (which is the only node that would have a parentid = 0).
			// That's why vBInstall:findOldImportedCMSHome has a INNER JOIN {TABLE_PREFIX}node AS p ON p.parentid = 0 AND n.oldid = p.nodeid
			$cmsHome = $assertor->getRow('vBInstall:findOldImportedCMSHome', array('oldcontenttypeid' => $oldContenttypeid, 'parentid' => $specialChannelId));

			if (!empty($cmsHome) AND $this->tableExists('cms_node') AND $this->tableExists('cms_nodeinfo'))
			{
				$this->show_message($this->phrase['version']['510a1']['deleting_old_cms']);


				// Try not not get rid of the ONLY remaining CMS data if they removed or truncated the tables for some reason.
				$cmsIsThere = $assertor->getRow('vBInstall:checkOldCMSTable', array());
				if (!empty($cmsIsThere))
				{
					// delete the home CMS channel.
					vB_Library::instance('content_channel')->delete($cmsHome);
				}
				else
				{
					$this->show_message($this->phrase['version']['510a1']['failed_to_delete_old_cms']);
				}
			}
			else
			{
				// cms home wasn't found, so there is nothing to delete.
				$this->skip_message();
			}
		}
		else
		{
			// we couldn't find a vbcms package, so either vB4 CMS was not installed, or we are simply unable to find the contenttypeid and thus cannot delete.
			$this->skip_message();
		}
	}

	/**
	 * Steps 3-7 :
	 * We need to import the newly added CMS Articles Home Page/Pagetemplate/Channel/Routes (and uncategorized category)
	 * All this data is in the XML files, so we call final_upgrade steps 4-8 to import them, because we need the article channels
	 * in this upgrade version before we can import data into them. Copied from 500a1 steps 128~
	 * First, import widgets
	 */
	public function step_3()
	{
		vB_Library::clearCache();
		vB_Upgrade::createAdminSession();
		require_once(DIR . "/install/includes/class_upgrade_final.php");
		$finalUpgrader = new vB_Upgrade_final($this->registry, $this->phrase,$this->maxversion);
		$finalUpgrader->step_4();
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'widget'));
	}

	/**
	 * See step_3's comments
	 */
	public function step_4()
	{
		$this->add_field(
			sprintf($this->phrase['core']['altering_x_table'], 'pagetemplate', 1, 1),
			'pagetemplate',
			'screenlayoutsectiondata',
			'text',
			array('null' => false, 'default' => '')
		);
		$this->execute();

		vB_Library::clearCache();
		vB_Upgrade::createAdminSession();
		require_once(DIR . "/install/includes/class_upgrade_final.php");
		$finalUpgrader = new vB_Upgrade_final($this->registry, $this->phrase,$this->maxversion);
		$finalUpgrader->step_6();
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'pagetemplate'));
	}

	/**
	 * See step_3's comments
	 */
	public function step_5()
	{
		vB_Library::clearCache();
		vB_Upgrade::createAdminSession();
		require_once(DIR . "/install/includes/class_upgrade_final.php");
		$finalUpgrader = new vB_Upgrade_final($this->registry, $this->phrase,$this->maxversion);
		$finalUpgrader->step_7();
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'page'));
	}

	/**
	 * See step_3's comments
	 */
	public function step_6()
	{
		vB_Library::clearCache();
		vB_Upgrade::createAdminSession();
		require_once(DIR . "/install/includes/class_upgrade_final.php");
		$finalUpgrader = new vB_Upgrade_final($this->registry, $this->phrase,$this->maxversion);
		$finalUpgrader->step_8();
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'channel'));
	}

	/**
	 * See step_3's comments
	 */
	public function step_7()
	{
		vB_Library::clearCache();
		vB_Upgrade::createAdminSession();
		require_once(DIR . "/install/includes/class_upgrade_final.php");
		$finalUpgrader = new vB_Upgrade_final($this->registry, $this->phrase,$this->maxversion);
		$finalUpgrader->step_9();
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'routenew'));
	}


	/**
	 * See step_3's comments
	 */
	public function step_8()
	{
		vB_Library::clearCache();
		vB_Upgrade::createAdminSession();
		require_once(DIR . "/install/includes/class_upgrade_final.php");
		$finalUpgrader = new vB_Upgrade_final($this->registry, $this->phrase,$this->maxversion);
		$finalUpgrader->step_11();
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'routenew'));
	}

	/**
	 * Now the default article channels should be in place, and we're ready to import old vb4 data.
	 *	Step 9 - Import vB4 CMS Home page data
	 */
	public function step_9()
	{
		vB_Upgrade::createAdminSession();

		$currentStep = 9;	// moving upgrade steps around. This is meant to remind me to update it to match the current step

		/* We should run this only once, so that if they update the channel info, then happen to run this upgrade class again,
		 	the data doesn't get wiped.	To do this we check the upgrader log to	see if this step has been previously run.
			Note that if the user wishes to forcefully run this step again, they'll have to manually edit the upgradelog */
		$log = vB::getDbAssertor()->getRow('vBInstall:upgradelog', array('script' => '510a1', 'step' => $currentStep)); // Must match this step.

		// We removed products in one of the upgrade steps. But if they had vb4 cms, cms_node & cms_nodeinfo tables should exist.
		if ($this->tableExists('cms_node') AND $this->tableExists('cms_nodeinfo') AND empty($log))
		{
			$assertor = vB::getDbAssertor();
			$articlesRootChannelId = vB_Api::instanceInternal('content_channel')->fetchChannelIdByGUID(vB_Channel::DEFAULT_ARTICLE_PARENT);
			$sectionTypeId = $assertor->getRow('vBInstall:getvBCMSSectionContenttypeid', array());
			$sectionTypeId = $sectionTypeId['contenttypeid'];
			$oldContenttypeid = vB_Api_Contenttype::OLDTYPE_CMS_SECTION;	// oldcontenttypeid should be a defined unique constant that we can refer to later.

			// based on the old 500a1 step_158, the home page is defined as from cms_node.nodeid = 1;
			$homeSection = $assertor->getRow('vBInstall:getOldCMSHome', array('oldcontenttypeid' => $oldContenttypeid));

			if ($homeSection)
			{
				// output what we're doing
				$this->show_message($this->phrase['version']['510a1']['importing_cms_home']);

				// default settings, taken from 500a1 step_158
				foreach(array('showpublished', 'open', 'approved', 'showopen', 'showapproved', 'inlist') AS $field)
				{
					$homeSection[$field] = 1;
				}
				vB_Library::instance('content_channel')->update($articlesRootChannelId, $homeSection);
			}
			else
			{
				// home not found. Nothing to update
				$this->skip_message();
			}
		}
		else
		{
			// did not have vb4 cms OR already ran this step.
			$this->skip_message();
		}
	}

	/**
	 *	Step 10 - Import vB4 CMS Sections (sections are now called categories in vB5)
	 *	articles right under the front page should be added to uncategorized default category.
	 */
	public function step_10($data = null)
	{
		vB_Upgrade::createAdminSession();

		// We removed products in one of the upgrade steps. But if they had vb4 cms, cms_node & cms_nodeinfo tables should exist.
		if ($this->tableExists('cms_node') AND $this->tableExists('cms_nodeinfo'))
		{
			$assertor = vB::getDbAssertor();
			$channelLib = vB_Library::instance('content_channel');

			$sectionTypeId = $assertor->getRow('vBInstall:getvBCMSSectionContenttypeid', array());
			$sectionTypeId = $sectionTypeId['contenttypeid'];
			$oldContenttypeid = vB_Api_Contenttype::OLDTYPE_CMS_SECTION;

			// On my machine, 100 channels took about 10s per iteration.
			$batchSize = 100;

			if (!isset($data['startat']))
			{
				// indicate what we're doing for the first run.
				$this->show_message($this->phrase['version']['510a1']['importing_cms_sections']);
			}

			// if we didn't skip this section, but it imported 0 sections, then something might be wrong with the imported CMS home section (step_3 above)
			$sectionsToImport = $assertor->assertQuery('vBInstall:getOldCMSSections',
				array(
					'oldcontenttypeid' => $oldContenttypeid,
					'sectiontypeid' => $sectionTypeId,
					'batchsize' => $batchSize,
			));
			$processed = 0;
			if ($sectionsToImport->valid())
			{
				foreach ($sectionsToImport AS $newSection)
				{
					/* Partially Copied from article library's createArticleCategory & createChannel.
					 * It's moved here because createChannel() also calls some cleanup stuff after node creation,
					 * which is not necessary for upgrade.
					 */

					$newSection['inlist'] = 1;
					$newSection['protected'] = 0;

					$newSection['templates']['vB5_Route_Channel'] = vB_Page::getArticleChannelPageTemplate();
					$newSection['templates']['vB5_Route_Article'] = vB_Page::getArticleConversPageTemplate();
					$newSection['childroute'] = 'vB5_Route_Article';

					// add channel node
					$newSection['page_parentid'] = 0;
					$channelLib->add($newSection,
						array(
							'skipNotifications' => true,
							'skipFloodCheck' => true,
							'skipDupCheck' => true,
							'skipBuildLanguage' => true,
						)
					);

					$processed++;
				}
			}
			else
			{
				// rebuild all languages that were postponed from pagemeta/desc phrase saves
				// triggered downstream of vB_Library_Content_Channel::createChannelPages()
				vB_Library::instance('language')->rebuildAllLanguages();

				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}

			$this->show_message(sprintf($this->phrase['core']['processed_records_x'], $processed));
			// kick off next batch. Return a nonzero startat to make it iterate.
			return array('startat' => 1);
		}
		else
		{
			// did not have vb4 CMS, nothing to import.
			$this->skip_message();
		}
	}


	/**
	 *	Step 11 - Import vB4 CMS Articles & Static Pages
	 */
	public function step_11($data = NULL)
	{
		vB_Upgrade::createAdminSession();

		// We removed products in one of the upgrade steps. But if they had vb4 cms, cms_node & cms_nodeinfo tables should exist.
		if ($this->tableExists('cms_node') AND $this->tableExists('cms_nodeinfo'))
		{
			$assertor = vB::getDbAssertor();

			// using the content add() functions so that they inherit show_X properties properly
			// Going through the lib instead of API because we dont' want to go through convertWysiwygTextToBbcode()
			$textLib = vB_Library::instance('Content_Text');

			// Previously we were importing via vB_Library_Content_Text::add() at about 50 per 6.4s
			// Seems like the new bulk importer can handle about 500 imports in about 8 seconds, so it's
			// about 8 times faster. Going with this batchsize for now.
			$batchsize = 500;

			// contenttypeids
			$articleTypeId = $assertor->getRow('vBInstall:getvBCMSArticleContenttypeid', array('class' => 'Article'));
			$articleTypeId = $articleTypeId['contenttypeid'];
			$staticPageTypeId = $assertor->getRow('vBInstall:getvBCMSArticleContenttypeid', array('class' => 'StaticPage'));
			$staticPageTypeId = $staticPageTypeId['contenttypeid'];
			$textTypeId = vB_Types::instance()->getContentTypeID('vBForum_Text');
			$oldContenttypeidSection = vB_Api_Contenttype::OLDTYPE_CMS_SECTION;
			$oldContenttypeidArticle = vB_Api_Contenttype::OLDTYPE_CMS_ARTICLE;
			$oldContenttypeidStaticPage = vB_Api_Contenttype::OLDTYPE_CMS_STATICPAGE;

			// grab startat
			if (isset($data['startat']))
			{
				$startat = intval($data['startat']);
			}
			else
			{
				$this->show_message($this->phrase['version']['510a1']['importing_cms_articles']);
				// if first iteration, begin at MIN(cms_node.nodeid) for nodes that have not been imported yet
				$min = $assertor->getRow('vBInstall:getMinMissingArticleNodeid',
					array(
						'articleTypeId' => $articleTypeId,
						'staticPageTypeId' => $staticPageTypeId,
						'oldcontenttypeid_article' => $oldContenttypeidArticle,
						'oldcontenttypeid_staticpage' => $oldContenttypeidStaticPage
					)
				);
				// we use exclusive <'s, so startat should start right before the min to import
				$startat = (isset($min['minid']))? intval($min['minid']) - 1 : 0;
			}
			// grab max
			if (!empty($data['max']))
			{
				$max = intval($data['max']);
			}
			else
			{
				$max = $assertor->getRow('vBInstall:getMaxMissingArticleNodeid',
					array(
						'articleTypeId' => $articleTypeId,
						'staticPageTypeId' => $staticPageTypeId,
						'oldcontenttypeid_article' => $oldContenttypeidArticle,
						'oldcontenttypeid_staticpage' => $oldContenttypeidStaticPage
					)
				);
				$max = intval($max['maxid']);
			}

			// if startat is greater than the maximum cms_node.nodeid of previously missing vb4 data, we're done
			if ($startat >= $max)
			{
				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}

			require_once(DIR . "/install/includes/bulkimporter.php");
			$importer = new vB_UpgradeHelper_BulkImporter();

			// import data
			$articlesToImport = $assertor->assertQuery('vBInstall:getOldCMSArticles',
				array(
					'startat' => $startat,
					'batchsize' => $batchsize,
					'textTypeId' => $textTypeId,
					'oldcontenttypeid_article' => $oldContenttypeidArticle,
					'oldcontenttypeid_section' => $oldContenttypeidSection,
					'articleTypeId' => $articleTypeId
				)
			);
			if ($articlesToImport->valid())
			{
				$nodeids = $importer->importBulkCMSArticles($articlesToImport);
				if (empty($nodeids))
				{
					/*
						The importer currently has zero error handling features if something
						prevents the import of an article or section.
						I did not encounter any failures during testing, but if the node
						insert failed, presumably we could get stuck in an infinite loop
						in the upgrade step. This exception is meant to stop that.
						I think the most likely thing to happen is either a DB connection
						error or an inconsistent node table structure that somehow slipped
						through.
						In any case, we should improve the error handling as appropriate
						as we encounter them in the wild.
					 */
					throw new Exception("CMS import failed. Please check your database connection and try again.");
				}
			}

			$staticPagesToImport = $assertor->assertQuery('vBInstall:getOldCMSStaticPages',
				array(
					'startat' => $startat,
					'batchsize' => $batchsize,
					'textTypeId' => $textTypeId,
					'oldcontenttypeid_staticpage' => $oldContenttypeidStaticPage,
					'oldcontenttypeid_section' => $oldContenttypeidSection,
					'staticPageTypeId' => $staticPageTypeId
				)
			);

			if ($staticPagesToImport->valid())
			{
				$nodeids2 = $importer->importBulkCMSArticles($staticPagesToImport);
				if (empty($nodeids2))
				{
					// See note above
					throw new Exception("CMS import failed. Please check your database connection and try again.");
				}
			}

			// output current progress
			$this->show_message(sprintf($this->phrase['core']['processed_records_x_y_z'], $startat +1, min($startat + $batchsize, $max), $max));

			// kick off next batch
			return array('startat' => $startat + $batchsize, 'max' => $max);
		}
		else
		{
			// did not have vb4 CMS, nothing to import.
			$this->skip_message();
		}
	}


	/**
	 *	Step 12 - Import vB4 CMS Article Comments
	 *		They are imported as forums, so we should try to find them & move them rather than re-importing.
	 */
	public function step_12($data = null)
	{
		vB_Upgrade::createAdminSession();

		// We removed products in one of the upgrade steps. But if they had vb4 cms, cms_node & cms_nodeinfo tables should exist.
		if ($this->tableExists('cms_node') AND $this->tableExists('cms_nodeinfo'))
		{
			$assertor = vB::getDbAssertor();

			$batchsize = 500; // Need a DB w/ a large enough CMS section to fiddle with this number

			// contenttypeids
			$postTypeId =  vB_Types::instance()->getContentTypeID('vBForum_Post');
			$oldContenttypeidArticle = vB_Api_Contenttype::OLDTYPE_CMS_ARTICLE;
			$oldContenttypeidArticleComment = vB_Api_Contenttype::OLDTYPE_CMS_COMMENT;
			$oldContenttypeidStaticPage = vB_Api_Contenttype::OLDTYPE_CMS_STATICPAGE;

			// grab imported article/staticpage nodeids & put them in an array
			$nodeidQry = $assertor->assertQuery('vBInstall:getUnmovedArticleCommentNodeids',
				array(
					'posttypeid' => $postTypeId,
					'batchsize' => $batchsize,
					'oldcontenttypeid_article' => $oldContenttypeidArticle,
					'oldcontenttypeid_staticpage' => $oldContenttypeidStaticPage,
				)
			);
			$nodeids = array();
			foreach ($nodeidQry AS $node)
			{
				$nodeids[] = $node['nodeid'];
			}

			// set startat
			// we use exclusive <'s, so startat should start right before the min to import
			$startat =  (!empty($nodeids))? min($nodeids) - 1 : 0;

			if (!isset($data['startat']))
			{
				// display message for first iteration
				$this->show_message($this->phrase['version']['510a1']['updating_cms_comments']);
			}

			// grab max
			if (!empty($data['max']))
			{
				$max = intval($data['max']);
			}
			else
			{
				$max = $assertor->getRow('vBInstall:getMaxUnmovedArticleCommentNodeid',
					array(
						'posttypeid' => $postTypeId,
						'oldcontenttypeid_article' => $oldContenttypeidArticle,
						'oldcontenttypeid_staticpage' => $oldContenttypeidStaticPage,
					)
				);
				$max = intval($max['maxid']);
			}

			// if there are no remaining nodes to process, we're done
			if (empty($nodeids))
			{
				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}

			// CMS Article Comments were saved as posts with post.threadid = cms_nodeinfo.associatedthreadid
			// So they would have been imported into the node table with oldcontenttypeid = <id for vBForum_Post> AND oldid = <postid>
			// Note that the default starter post that isn't actually a comment has post.parentid = 0.


			// move nodes under article. update routeids (?). Clean up old channel(s)/comment starters?
			// set oldcontenttypeid, also create self & parent closure records. Clean up old closure records (?)
			$assertor->assertQuery('vBInstall:moveArticleCommentNodes',
				array(
					'nodeids' => $nodeids,
					'posttypeid' => $postTypeId,
					'oldcontenttypeid_article' => $oldContenttypeidArticle,
					'oldcontenttypeid_staticpage' => $oldContenttypeidStaticPage,
					'oldcontenttypeid_articlecomment' => $oldContenttypeidArticleComment,
			));
			// remove previous closure parents. Leave existing self closure alone.
			$assertor->assertQuery('vBInstall:removeArticleCommentClosureParents',
				array(
					'nodeids' => $nodeids,
					'oldcontenttypeid_articlecomment' => $oldContenttypeidArticleComment
			));
			// add closure parents.
			$assertor->assertQuery('vBInstall:addArticleCommentClosureParents',
				array(
					'nodeids' => $nodeids,
					'oldcontenttypeid_articlecomment' => $oldContenttypeidArticleComment
			));

			// output current progress
			$this->show_message(sprintf($this->phrase['core']['processed_records_x_y_z'], $startat +1, max($nodeids), $max));

			// kick off next batch
			return array('startat' => max($nodeids), 'max' => $max);
		}
		else
		{
			// did not have vb4 CMS, nothing to import.
			$this->skip_message();
		}
	}





	/**
	 *	Step 13 - Import vB4 CMS Permissions
	 */
	public function step_13()
	{
		if (!$this->tableExists('cms_permissions'))
		{
			$this->skip_message();
		}
		else
		{
			$assertor = vB::getDbAssertor();
			vB_Upgrade::createAdminSession();
			$channelTypeId = vB_Types::instance()->getContentTypeID('vBForum_Channel');
			//because the cms package is not installed we can't user getContenttypeid('vBCMS_Section');
			$package = $assertor->getRow('package', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT, 'productid' => 'vbcms'));

			if (!$package OR !empty($package['errors']))
			{
				$this->skip_message();
			}
			$sectionType = $assertor->getRow('vBForum:contenttype', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'packageid' => $package['packageid'], 'class' => 'Section'));

			if (!$sectionType OR !empty($sectionType['errors']))
			{
				$this->skip_message();
			}
			// for the oldcontenttypeid of imported data, we used contenttypeid for vBCms_Section in 500a1,
			// but we're using a defined constant when we import the data again, see "Import vB4 CMS Sections" step above
			$sectionTypeId = vB_Api_Contenttype::OLDTYPE_CMS_SECTION;
			$cmsPerms = $assertor->assertQuery('vBInstall:cms_permissions', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT));
			//VB4 CMS Permissions are:
			//1: canview
			//2: cancreate
			//4: canedit
			//8: canpublish
			//16: canUseHtml
			//32: canDownload
			$this->show_message($this->phrase['version']['510a1']['setting_cms_perms']);
			if ($cmsPerms->valid())
			{
				$forumBits = $forumBits2 = array();
				$parsedRaw = vB_Xml_Import::parseFile(DIR . '/includes/xml/bitfield_vbulletin.xml');
				foreach ($parsedRaw['bitfielddefs']['group'] AS $group)
				{
					if ($group['name'] == 'ugp')
					{
						foreach($group['group'] AS $bfgroup)
						{
							if ($bfgroup['name'] == 'forumpermissions')
							{
								foreach ($bfgroup['bitfield'] AS $bitfield)
								{
									$forumBits[$bitfield['name']] = intval($bitfield['value']);
								}
							}
							else if ($bfgroup['name'] == 'forumpermissions2')
							{
								foreach ($bfgroup['bitfield'] AS $bitfield)
								{
									$forumBits2[$bitfield['name']] = intval($bitfield['value']);
								}
							}
						}
					}
				}
				$channelPerm = vB_ChannelPermission::instance();
				foreach ($cmsPerms as $cmsPerm)
				{
					$nodeid = $assertor->getField('vBForum:node', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT, 'oldid' => $cmsPerm['nodeid'],
						'oldcontenttypeid' => $sectionTypeId, vB_dB_Query::COLUMNS_KEY => 'nodeid'));

					if ($nodeid)
					{
						$perms =  $channelPerm->fetchPermissions(1, $cmsPerm['usergroupid']);

						if ($cmsPerm['permissions'] & 1)//1: canview
						{
							$perms['forumpermissions'] |= $forumBits['canview'] | $forumBits['canviewthreads'] | $forumBits['canviewothers'];
						}
						else
						{
							$perms['forumpermissions'] &= ~$forumBits['canview'] & ~$forumBits['canviewthreads'] & ~$forumBits['canviewothers'];
						}



						if ($cmsPerm['permissions'] & 2)//2: cancreate
						{
							$perms['forumpermissions'] |= $forumBits['canpostnew'];
						}
						else
						{
							$perms['forumpermissions'] &= ~$forumBits['canpostnew'];
						}

						if ($cmsPerm['permissions'] & 4)//4: canedit
						{
							$perms['forumpermissions'] |= $forumBits['caneditpost'];
						}
						else
						{
							$perms['forumpermissions'] &= ~$forumBits['caneditpost'];
						}

						if ($cmsPerm['permissions'] & 8)//8: canpublish
						{
							$perms['forumpermissions2'] |= $forumBits2['canpublish'];
						}
						else
						{
							$perms['forumpermissions2'] &= ~$forumBits2['canpublish'];
						}

						if ($cmsPerm['permissions'] & 16)//16: canUseHtml
						{
							$perms['forumpermissions2'] |= $forumBits2['canusehtml'];
						}
						else
						{
							$perms['forumpermissions2'] &= ~$forumBits2['canusehtml'];
						}

						if ($cmsPerm['permissions'] & 32)//32: canDownload
						{
							$perms['forumpermissions'] |= $forumBits['cangetattachment'];
						}
						else
						{
							$perms['forumpermissions'] &= ~$forumBits['cangetattachment'];
						}
						$channelPerm->setPermissions($nodeid, $cmsPerm['usergroupid'], $perms);
					}
				}
			}
		}
	}


	/**
	 *	Step 14 - Import vB4 CMS Article Attachments
	 * 	Note, only articles had attachments. As far as I'm aware, static pages could not have attachments anywhere.
	 */
	public function step_14($data = NULL)
	{
		vB_Upgrade::createAdminSession();

		// We removed products in one of the upgrade steps. But if they had vb4 cms, cms_node & cms_nodeinfo tables should exist.
		// also, attachments are in attachment & filedata tables
		if ($this->tableExists('cms_node') AND $this->tableExists('cms_nodeinfo')
			AND $this->tableExists('attachment') AND $this->tableExists('filedata'))
		{
			$assertor = vB::getDbAssertor();

			$batchsize = 4000;

			// contenttypeids
			$articleTypeId = $assertor->getRow('vBInstall:getvBCMSArticleContenttypeid', array('class' => 'Article'));
			$articleTypeId = $articleTypeId['contenttypeid'];
			$attachTypeId =  vB_Types::instance()->getContentTypeID('vBForum_Attach');
			$oldContenttypeidArticle = vB_Api_Contenttype::OLDTYPE_CMS_ARTICLE;
			$oldContenttypeidArticleAttachment = vB_Api_Contenttype::OLDTYPE_ARTICLEATTACHMENT;

			// In vB4, attachment.contenttypeid = vbcms_article, contentid = cms_article.nodeid

			// grab startat
			if (isset($data['startat']))
			{
				$startat = intval($data['startat']);
			}
			else
			{
				$this->show_message($this->phrase['version']['510a1']['importing_cms_article_attachments']);
				// if first iteration, begin at MIN(attachment.attachmentid) for nodes that have not been imported yet
				$min = $assertor->getRow('vBInstall:getMinMissingArticleAttachmentid',
					array('articletypeid' => $articleTypeId, 'oldcontenttypeid_articleattachment' => $oldContenttypeidArticleAttachment));
				// we use exclusive <'s, so startat should start right before the min to import
				$startat = (isset($min['minid']))? intval($min['minid']) - 1 : 0;
			}
			// grab max
			if (!empty($data['max']))
			{
				$max = intval($data['max']);
			}
			else
			{
				$max = $assertor->getRow('vBInstall:getMaxMissingArticleAttachmentid',
					array('articletypeid' => $articleTypeId, 'oldcontenttypeid_articleattachment' => $oldContenttypeidArticleAttachment));
				$max = intval($max['maxid']);
			}

			// if startat is greater than the maximum cms_node.nodeid of previously missing vb4 data, we're done
			if ($startat >= $max)
			{
				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}

			// import data
			/*** first the nodes ***/
			$assertor->assertQuery('vBInstall:insertArticleAttachmentNodes', array(
				'attachtypeid' => $attachTypeId,
				'oldcontenttypeid_articleattachment' => $oldContenttypeidArticleAttachment,
				'oldcontenttypeid_article' => $oldContenttypeidArticle,
				'batchsize' => $batchsize,
				'startat' => $startat,
				'articletypeid' => $articleTypeId,
			));

			//Now populate the attach table
			$assertor->assertQuery('vBInstall:insertArticleAttachments', array(
				'oldcontenttypeid_articleattachment' => $oldContenttypeidArticleAttachment,
				'batchsize' => $batchsize,
				'startat' => $startat,
				'articletypeid' => $articleTypeId,
			));

			//Now the closure record for the node
			$assertor->assertQuery('vBInstall:addClosureSelf', array(
				'contenttypeid' => $oldContenttypeidArticleAttachment,
				'startat' => $startat,
				'batchsize' => $batchsize,
			));

			//Add the closure records to root
			$assertor->assertQuery('vBInstall:addClosureParents', array(
				'contenttypeid' => $oldContenttypeidArticleAttachment,
				'startat' => $startat,
				'batchsize' => $batchsize,
			));


			// output current progress
			$this->show_message(sprintf($this->phrase['core']['processed_records_x_y_z'], $startat +1, min($startat + $batchsize, $max), $max));

			// kick off next batch
			return array('startat' => $startat + $batchsize, 'max' => $max);
		}
		else
		{
			// did not have vb4 CMS, nothing to import.
			$this->skip_message();
		}
	}

	/**
	 * Step 15 - Update imported vb4 CMS Article nodes' textcount with # of children (comments)
	 *		Since the only text-type children of articles should be comments, totalcount & textcount
	 *		should be the total # of comments.
	 *		Articles were imported in step_11. Comments were imported in step_12
	 */
	public function step_15($data = null)
	{
		// We removed products in one of the upgrade steps. But if they had vb4 cms, cms_node & cms_nodeinfo tables should exist.
		if ($this->tableExists('cms_node') AND $this->tableExists('cms_nodeinfo'))
		{
			$assertor = vB::getDbAssertor();

			$batchsize = 500; // filesort with temporary, may not want to push this further. Needs some fiddling around with larger test data

			// contenttypeids
			$oldContenttypeidArticle = vB_Api_Contenttype::OLDTYPE_CMS_ARTICLE;
			$oldContenttypeidStaticPage = vB_Api_Contenttype::OLDTYPE_CMS_STATICPAGE;
			$oldContenttypeidArticleComment = vB_Api_Contenttype::OLDTYPE_CMS_COMMENT;

			// grab startat
			if (isset($data['startat']))
			{
				$startat = intval($data['startat']);
			}
			else
			{
				$this->show_message($this->phrase['version']['510a1']['updating_cms_article_textcount']);
				// start at nodeid 0
				$startat = 0;
			}

			// grab imported article/staticpage nodeids & put them in an array
			$nodeidQry = $assertor->assertQuery('vBInstall:getImportedArticleNodeids',
				array(
					'oldcontenttypeid_article' => $oldContenttypeidArticle,
					'oldcontenttypeid_staticpage' => $oldContenttypeidStaticPage,
					'startat' => $startat,
					'batchsize' => $batchsize
				)
			);
			$nodeids = array();
			foreach ($nodeidQry AS $node)
			{
				$nodeids[] = $node['nodeid'];
			}

			// grab max
			if (!empty($data['max']))
			{
				$max = intval($data['max']);
			}
			else
			{
				$max = $assertor->getRow('vBInstall:getMaxImportedArticleNodeid',
					array(
						'oldcontenttypeid_article' => $oldContenttypeidArticle,
						'oldcontenttypeid_staticpage' => $oldContenttypeidStaticPage
					)
				);
				$max = intval($max['maxid']);
			}

			// if startat is greater than the maximum cms_node.nodeid of previously missing vb4 data, we're done
			if ($startat >= $max OR empty($nodeids))
			{
				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}

			// import data
			// currently, the group by in the inner select results in filesort, but I don't think we can do anything to avoid that.
			$assertor->assertQuery('vBInstall:updateImportedArticleTextcount',
				array(
					'nodeids' => $nodeids,
					'oldcontenttypeid_article' => $oldContenttypeidArticle,
					'oldcontenttypeid_staticpage' => $oldContenttypeidStaticPage,
					'oldcontenttypeid_articlecomment' => $oldContenttypeidArticleComment
				)
			);

			// insert nodeview records
			$assertor->assertQuery('vBInstall:importArticleViewcount',
				array(
					'nodeids' => $nodeids,
					'oldcontenttypeid_article' => $oldContenttypeidArticle,
					'oldcontenttypeid_staticpage' => $oldContenttypeidStaticPage
				)
			);

			// output current progress
			$this->show_message(sprintf($this->phrase['core']['processed_records_x_y_z'], min($nodeids), max($nodeids), $max));

			// kick off next batch
			return array('startat' => max($nodeids), 'max' => $max);
		}
		else
		{
			// did not have vb4 CMS, nothing to import.
			$this->skip_message();
		}
	}

	/**
	 * Step 16 - Update imported static page nodes with new nodeoption vB_Api_Node::OPTION_NODE_DISABLE_BBCODE = 1024;
	 */
	public function step_16($data = NULL)
	{
		// We removed products in one of the upgrade steps. But if they had vb4 cms, cms_node & cms_nodeinfo tables should exist.
		if ($this->tableExists('cms_node') AND $this->tableExists('cms_nodeinfo'))
		{

			// set-up constants, objects etc.
			$assertor = vB::getDbAssertor();
			$newOption = vB_Api_Node::OPTION_NODE_DISABLE_BBCODE;
			$oldContenttypeidStaticPage = vB_Api_Contenttype::OLDTYPE_CMS_STATICPAGE;
			$batchsize = 100000;

			// grab startat
			if (isset($data['startat']))
			{
				$startat = intval($data['startat']);
			}
			else
			{
				// display what we're doing
				$this->show_message(sprintf($this->phrase['version']['510a1']['updating_staticpage_nodeoption']));
				// start at the first imported article nodeid.
				$min = $assertor->getRow('vBInstall:getStaticPageNodeidsToUpdate',
					array(
						'oldcontenttypeid_staticpage' => $oldContenttypeidStaticPage,
						'option_disable_bbcode' => $newOption
					)
				);
				// we use exclusive <'s, so startat should start right before the min to import
				$startat = (isset($min['minid']))? intval($min['minid']) - 1 : 0;

				// also set max while we're at it.
				$data['max'] = $min['maxid'];
			}

			// grab max
			if (!empty($data['max']))
			{
				$max = intval($data['max']);
			}
			else
			{
				$max = $assertor->getRow('vBInstall:getStaticPageNodeidsToUpdate',
					array(
						'oldcontenttypeid_staticpage' => $oldContenttypeidStaticPage,
						'option_disable_bbcode' => $newOption
					)
				);
				$max = intval($max['maxid']);
			}

			// if startat is greater than the maximum imported nodeid, we're done
			if ($startat >= $max)
			{
				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}

			// update node table
			$assertor->assertQuery('vBInstall:updateStaticPageNodeOptions',
				array(	'new_option' => $newOption,
						'oldcontenttypeid_staticpage' => $oldContenttypeidStaticPage,
						'startat' => $startat,
						'batchsize' => $batchsize
				)
			);

			// output progress & return for next batch
			$this->show_message(sprintf($this->phrase['core']['processed_records_x_y_z'], $startat + 1, min($startat + $batchsize, $max), $max));
			return array('startat' => ($startat + $batchsize), 'max' => $data['max']);
		}
		else
		{
			// did not have vb4 CMS, nothing to import.
			$this->skip_message();
		}
	}

	/**
	 * Step 17 - Clean up CMS comment threads
	 *	Remove any imported forums associated with CMS
	 *	Note, skipped as of VBV-11640. Let admins manually delete the forums
	 */
	public function step_17($data = NULL)
	{
		$this->skip_message();
	}

	/** We have four new admin permissions. We should set those for non-CLI users
	 *
	 */
	public function step_18($data = NULL)
	{
		// this step has been moved back to 506a1 step_1 to match w/ the SaaS branch. See VBV-12141
		// The other possible fix for this particular step's issue was to check for either this step OR
		// 506a1 step_1 in the upgradelog, but due to the upgrade log bug(?) VBV-12130, that was impossible
		$this->skip_message();

	}

	/**
	 * Step 19 - update sections totalcount data. textcount should already be accurate since
	 *		they were updated when articles & static pages were added in bulk, but comments
	 * 		were moved from their old imported nodes to under the articles without updating
	 *		the channels.
	 *	UPDATE: This step needs to be optimized, but there's an AdminCP tool to fix channel counts.
	 *	For now, just add an admincp message to run the tool
	 */
	public function step_19($data = NULL)
	{
		$this->add_adminmessage('after_upgrade_from_505_cms',
		array(
			'dismissable' => 1,
			'status'  => 'undone',
		)
		);
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101434 $
|| #######################################################################
\*=========================================================================*/
