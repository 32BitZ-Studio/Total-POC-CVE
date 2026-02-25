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

class vB_Upgrade_510a2 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '510a2';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.0 Alpha 2';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.0 Alpha 1';

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

	/**Import the vbcms permissions field if appropriate. */
	public function step_1($data = NULL)
	{
		$check = vB::getDbAssertor()->assertQuery('vBInstall:upgradelog', array('script' => '510a2', 'step' => '1'));

		//make sure we only run this once.
		if ($check->valid())
		{
			$this->skip_message();
		}
		else
		{
			$this->show_message($this->phrase['version']['510a2']['setting_cms_admin_permissions']);
			$parsedRaw = vB_Xml_Import::parseFile(DIR . '/includes/xml/bitfield_vbulletin.xml');
			$permBits = array();
			foreach ($parsedRaw['bitfielddefs']['group'] AS $group)
			{
				if ($group['name'] == 'ugp')
				{
					foreach($group['group'] AS $bfgroup)
					{
						if ($bfgroup['name'] == 'adminpermissions')
						{
							foreach ($bfgroup['bitfield'] AS $bitfield)
							{
								$permBits[$bitfield['name']] = intval($bitfield['value']);
							}
						}
					}
				}
			}
			if (!empty($permBits['canadmincms']))
			{
				if ($this->field_exists('administrator', 'vbcmspermissions'))
				{
					vB::getDbAssertor()->assertQuery('vBInstall:setCMSAdminPermFromvB4',
						array('newvalue' => $permBits['canadmincms']));
				}
				else
				{
					vB::getDbAssertor()->assertQuery('vBInstall:setCMSAdminPermFromvExisting',
						array('newvalue' => $permBits['canadmincms'], 'existing' => $permBits['canadminforums']));
				}
			}
		}
		$this->long_next_step();
	}

	/**  Add the public_preview field to the node table*/
	public function step_2($data = NULL)
	{
		$this->add_field(
			sprintf($this->phrase['core']['altering_x_table'], 'node', 1, 2),
			'node',
			'public_preview',
			'SMALLINT',
			self::FIELD_DEFAULTS
		);
		$this->long_next_step();
	}

	/** Copy over publicpreview from vB4 **/
	public function step_3($data = NULL)
	{
		if ($this->tableExists('cms_node'))
		{
			$check = vB::getDbAssertor()->assertQuery('vBInstall:upgradelog', array('script' => '510a2', 'step' => '4'));

			if ($check->valid())
			{
				$this->skip_message();
			}
			else
			{
				$this->show_message($this->phrase['version']['510a2']['setting_public_preview']);
				vB::getDbAssertor()->assertQuery('vBInstall:importPublicPreview',
				 	array('oldcontenttypes' => array(vB_Api_ContentType::OLDTYPE_CMS_ARTICLE,
				 	vB_Api_ContentType::OLDTYPE_CMS_STATICPAGE)));
			}
		}
		else
		{
			$this->skip_message();
		}

	}

	/**  index the public_preview field*/
	public function step_4($data = NULL)
	{
		$this->add_index(
			sprintf($this->phrase['core']['altering_x_table'], 'node', 2, 2),
			'node',
			'ppreview',
			'public_preview'
		);
	}

	/*
	   Add scheduled task to check for nodes that need to be published or unpublished.
	*/
	public function step_5()
	{
		$this->add_cronjob(
		array(
			'varname'  => 'scheduled_publish',
			'nextrun'  => 1320000000,
			'weekday'  => -1,
			'day'      => -1,
			'hour'     => -1,
			'minute'   => 'a:6:{i:0;i:0;i:1;i:10;i:2;i:20;i:3;i:30;i:4;i:40;i:5;i:50;}',
			'filename' => './includes/cron/unpublished.php',
			'loglevel' => 1,
			'volatile' => 1,
			'product'  => 'vbulletin'
		)
		);
	}

	/**
	 * Importing cms tags
	 */
	public function step_6($data = array())
	{
		if ($this->tableExists('cms_node'))
		{
			$assertor = vB::getDbAssertor();
			$batchsize = 1000;
			$startat = intval($data['startat']);
			$assertor = vB::getDbAssertor();

			if (isset($data['maxId']))
			{
				$maxId = intval($data['maxId']);
			}
			else
			{
				$this->show_message($this->phrase['version']['510a2']['importing_cms_tags']);
				$maxNode = $assertor->getRow('vBInstall:maxCMSNode');
				$maxId = intval($maxNode['maxId']);
			}

			if ($startat > $maxId)
			{
				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}

			$this->show_message(sprintf($this->phrase['core']['processing_records_x'], $batchsize));
			$assertor->assertQuery('vBInstall:importCMSTags', array('startat' => $startat,
				'batchsize' => $batchsize, 'cmstypes' => array(vB_Api_ContentType::OLDTYPE_CMS_STATICPAGE,
					 vB_Api_ContentType::OLDTYPE_CMS_ARTICLE)));
			return array('startat' => ($startat + $batchsize), 'maxId' => $maxId);
		}
		else
		{
			$this->skip_message();
		}
	}


	/**
	 * Importing cms categories as tags
	 */
	public function step_7($data = array())
	{
		if ($this->tableExists('cms_category'))
		{
			$this->show_message($this->phrase['version']['510a2']['importing_cms_category_tags']);
			vB::getDbAssertor()->assertQuery('vBInstall:importCMSCategoryTags',
				array('timenow' => vB::getRequest()->getTimeNow()));
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Importing cms categories as tags
	 */
	public function step_8($data = array())
	{
		if ($this->tableExists('cms_node'))
		{
			vB_Upgrade::createAdminSession();
			$assertor = vB::getDbAssertor();
			$batchsize = 1000;
			$startat = intval($data['startat']);
			$assertor = vB::getDbAssertor();

			if (isset($data['maxId']))
			{
				$maxId = intval($data['maxId']);
			}
			else
			{
				$this->show_message($this->phrase['version']['510a2']['assigning_cms_category_tags']);
				$maxNode = $assertor->getRow('vBInstall:maxCMSNode');
				$maxId = intval($maxNode['maxId']);
			}

			if ($startat > $maxId)
			{
				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}

			$this->show_message(sprintf($this->phrase['core']['processing_records_x'], $batchsize));
			$assertor->assertQuery('vBInstall:assignCMSCategoryTags', array('startat' => $startat,
				'batchsize' => $batchsize, 'cmstypes' => array(vB_Api_ContentType::OLDTYPE_CMS_STATICPAGE,
					vB_Api_ContentType::OLDTYPE_CMS_ARTICLE), 'userid' => vB::getCurrentSession()->get('userid'),
					'timenow' => vB::getRequest()->getTimeNow()));
			return array('startat' => ($startat + $batchsize), 'maxId' => $maxId);
		}
		else
		{
			$this->skip_message();
		}
	}


	/**
	 * Set new CMS nodeoptions
	 */
	public function step_9($data = array())
	{
		if ($this->tableExists('cms_node'))
		{
			$check = vB::getDbAssertor()->assertQuery('vBInstall:upgradelog', array('script' => '510a2', 'step' => '9'));

			if ($check->valid())
			{
				$this->skip_message();
			}
			else
			{
				$this->show_message($this->phrase['version']['510a2']['setting_cms_node_options']);
				vB::getDbAssertor()->assertQuery('vBInstall:importCMSnodeOptions', 
					array(
						'cmstypes' => array(vB_Api_ContentType::OLDTYPE_CMS_STATICPAGE,
											vB_Api_ContentType::OLDTYPE_CMS_ARTICLE), 
						'optiontitle' => vB_Api_Node::OPTION_NODE_HIDE_TITLE,
						'optionauthor' => vB_Api_Node::OPTION_NODE_HIDE_AUTHOR,
						'optionpubdate' => vB_Api_Node::OPTION_NODE_HIDE_PUBLISHDATE,
						'optionfulltext' => vB_Api_Node::OPTION_NODE_DISPLAY_FULL_IN_CATEGORY,
						'optionpageview' => vB_Api_Node::OPTION_NODE_DISPLAY_PAGEVIEWS,
						'optioncomment' => vB_Api_Node::OPTION_ALLOW_POST,	// first invert then bitwise & to unset this bit, then import vb4 field into the bit
					)
				);
			}
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Set node taglist field for the imported articles.
	 */
	public function step_10($data = array())
	{
		if ($this->tableExists('cms_node'))
		{
			$assertor = vB::getDbAssertor();
			$batchsize = 500;
			$startat = intval($data['startat']);
			$assertor = vB::getDbAssertor();

			if (isset($data['maxId']))
			{
				$maxId = intval($data['maxId']);
			}
			else
			{
				$this->show_message($this->phrase['version']['510a2']['setting_taglist_field']);
				$maxNode = $assertor->getRow('vBInstall:maxCMSNode');
				$maxId = intval($maxNode['maxId']);
			}

			if ($startat > $maxId)
			{
				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}

			$this->show_message(sprintf($this->phrase['core']['processing_records_x'], $batchsize));
			$nodeTags = $assertor->assertQuery('vBInstall:fetchCMSNodeTags', array('startat' => $startat,
				'batchsize' => $batchsize, 'cmstypes' => array(vB_Api_ContentType::OLDTYPE_CMS_STATICPAGE,
					 vB_Api_ContentType::OLDTYPE_CMS_ARTICLE)));
			$taglist = array();
			if ($nodeTags->valid())
			{
				foreach ($nodeTags as $nodeTag)
				{
					$taglist[$nodeTag['nodeid']][] = $nodeTag['tagtext'];
				}
			}

			foreach ($taglist as $nodeid =>$tags)
			{
				$assertor->assertQuery('vBForum:node', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
				 'nodeid' => $nodeid, 'taglist' => implode(',', $tags)));
			}

			return array('startat' => ($startat + $batchsize), 'maxId' => $maxId);
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Corrent the arguments and regex for vbcms redirect;
	 */
	public function step_11($data = array())
	{
		if ($this->tableExists('cms_node'))
		{
			$assertor = vb::getDbAssertor();
			$regex = '^content[^0-9]*(?P<oldid>[0-9]+)?(-)?(?P<urlident>[^/]*)?(/view/)?(?P<oldpage>[0-9]+)?';
			$arguments = serialize(array('oldid' => '$oldid', 'oldpage' => '$oldpage', 'urlident' > '$urlident'));
			$this->show_message($this->phrase['version']['510a2']['updating_cms_legacy_route']);
			$assertor->assertQuery('routenew', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
				 'regex' => $regex,
				'arguments' => $arguments,
				vB_dB_Query::CONDITIONS_KEY => array('class' => 'vB5_Route_Legacy_vBCms', 'prefix' => 'content.php')));

			$check = $assertor->assertQuery('routenew', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'class' => 'vB5_Route_Legacy_vBCms', 'prefix' => 'content'
			));


			if (!$check->valid())
			{
				$data = array(
					'prefix'	=> 'content',
					'regex'		=> $regex,
					'class'		=> 'vB5_Route_Legacy_vBCms',
					'arguments'	=> $arguments,
					'product'	=> 'vbulletin'
				);
				$data['guid'] = vB_Xml_Export_Route::createGUID($data);
				$assertor->insert('routenew', $data);
			}

		}
		else
		{
			$this->skip_message();
		}
	}


}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
