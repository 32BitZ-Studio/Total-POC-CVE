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

/*
if (!isset($GLOBALS['vbulletin']->db))
{
	exit;
}
*/

class vB_Upgrade_502a2 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '502a2';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.0.2 Alpha 2';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.0.2 Alpha 1';

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


	/*	Step 1
	 *	Correct oldid for imported blog channels.
	 * 	This step does not delete the "false" blog
	 * 	channels (blog entries that were imported
	 *	as channels instead in 500a22 step 1).
	*/
	public function step_1($data = NULL)
	{
		// check if blogs were imported. If so, there should be a blog_user table
		if ($this->tableExists('blog_user') AND $this->tableExists('node'))
		{
			$this->show_message($this->phrase['version']['502a2']['updating_oldid_for_imported_blogs']);
			$startat = intval($data['startat']);
			$batchsize = 20000;
			// $blog['oldcontenttypeid'] = '9999'; 	 from class_upgrade_500a22 step1
			$oldContetypeid_blogChannel = vB_Api_ContentType::OLDTYPE_BLOGCHANNEL_PRE502a2;

			if (!empty($data['max']))
			{
					$max = $data['max'];
			}
			else
			{
				// grab the max id for imported vb3/4 blog channel
				$max = vB::getDbAssertor()->getRow(	'vBInstall:getMaxNodeidForOldContent',
											array(	'oldcontenttypeid' => array($oldContetypeid_blogChannel))
										);
				$max = $max['maxid'];
			}

			if($startat > $max)
			{
				// we're done here
				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}
			else
			{

				// blog_user.bloguserid is the userid, and what oldid should be set to
				// blog.userid should be equivalent to bloguserid, and since it's easier to map
				// the imported node row to the row in the blog table, let's just use blog.userid
				vB::getDbAssertor()->assertQuery('vBInstall:updateImportedBlogChannelOldid', array(
					'startat' => $startat,
					'batchsize' => $batchsize,
					'oldcontenttypeid' => $oldContetypeid_blogChannel,
					'oldcontenttypeid_new' => vB_Api_ContentType::OLDTYPE_BLOGCHANNEL
				));

				// start next batch
				return array('startat' => ($startat + $batchsize), 'max' => $max);
			}
		}
		else
		{
			$this->skip_message();
		}

	}

	public function step_2()
	{
		$this->skip_message();
	}


	/*	Step 3
	 *	Change oldid for imported blog entries.
	 * 	class_ugprade_500a22 steps 2 & 3 set oldid for blog starters & replies
	 * 	to be blog_text.blogtextid. With the legacy entry.php rerouting, the
	 * 	oldid's for blog entries have to be blog.blogid
	*/
	public function step_3($data = NULL)
	{
		// check if blogs were imported. If so, there should be a blog_user table
		if ($this->tableExists('blog_user') AND $this->tableExists('node'))
		{
			$this->show_message($this->phrase['version']['502a2']['updating_oldid_for_imported_blog_entries']);
			$startat = intval($data['startat']);
			$batchsize = 50000;
			// blog starters: 9985, blog responses:9984 	 from class_upgrade_500a22 steps 2 & 3
			$oldContetypeid_blogStarter = vB_Api_ContentType::OLDTYPE_BLOGSTARTER_PRE502a2;

			if (!empty($data['max']))
			{
					$max = $data['max'];
			}
			else
			{
				// grab the max id for imported vb3/4 blog channel
				$max = vB::getDbAssertor()->getRow(	'vBInstall:getMaxNodeidForOldContent',
											array(	'oldcontenttypeid' => array($oldContetypeid_blogStarter))
										);
				$max = $max['maxid'];
			}

			if($startat > $max)
			{
				// we're done here
				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}
			else
			{
				// first, the blog starters
				vB::getDbAssertor()->assertQuery('vBInstall:updateImportedBlogEntryOldid', array(
					'startat' => $startat,
					'batchsize' => $batchsize,
					'oldcontenttypeid' => $oldContetypeid_blogStarter,
					'oldcontenttypeid_new' => vB_Api_ContentType::OLDTYPE_BLOGSTARTER
				));

				// blog responses should be left alone, since they don't go through entry.php the same way.

				// start next batch
				return array('startat' => ($startat + $batchsize), 'max' => $max);
			}
		}
		else
		{
			$this->skip_message();
		}

	}

	/**
	 * Step 4-5: Update paid subscriptions related data
	 */
	public function step_4()
	{
		if (!$this->field_exists('paymentapi', 'subsettings'))
		{
			// Create nodeid field
			$this->add_field(
				sprintf($this->phrase['core']['altering_x_table'], 'paymentapi', 1, 1),
				'paymentapi',
				'subsettings',
				'mediumtext',
				self::FIELD_DEFAULTS
			);
		}
		else
		{
			$this->skip_message();
		}

		if (!$this->field_exists('subscription', 'newoptions'))
		{
			// Create nodeid field
			$this->add_field(
				sprintf($this->phrase['core']['altering_x_table'], 'subscription', 1, 1),
				'subscription',
				'newoptions',
				'mediumtext',
				self::FIELD_DEFAULTS
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	public function step_5()
	{
		$this->show_message($this->phrase['version']['502a2']['converting_subscription_options']);
		$processed = false;

		// Need to go through old subscriptions and convert options to newoptions
		$subscriptions = $this->db->query_read("
			SELECT *
			FROM " . TABLE_PREFIX . "subscription
			ORDER BY subscriptionid
		");

		$_SUBSCRIPTIONOPTIONS = array(
			'tax'       => 1,
			'shipping1' => 2,
			'shipping2' => 4,
		);

		while ($sub = $this->db->fetch_array($subscriptions))
		{
			if (empty($sub['newoptions']))
			{
				$processed = true;
				$oldoptions = array_merge($sub, convert_bits_to_array($sub['options'], $_SUBSCRIPTIONOPTIONS));
				$shipping_address = ($sub['options'] & $_SUBSCRIPTIONOPTIONS['shipping1']) + ($sub['options'] & $_SUBSCRIPTIONOPTIONS['shipping2']);
				switch ($shipping_address)
				{
					case 0:
						$shipping_address = 'none';
						break;

					case 2:
						$shipping_address = 'optional';
						break;

					case 3:
						$shipping_address = 'required';
						break;
				}

				$newoption['api']['paypal'] = array(
					'show' => '1',
					'tax' => $oldoptions['tax'],
					'shipping_address' => $shipping_address,
				);

				$this->db->query_write("
					UPDATE " . TABLE_PREFIX . "subscription
					SET newoptions = '" . $this->db->escape_string(serialize($newoption)) . "'
					WHERE subscriptionid = $sub[subscriptionid]
				");

			}
		}

		// Insert subsettings field for paymentapi
		$paymentapis = $this->db->query_read("
			SELECT *
			FROM " . TABLE_PREFIX . "paymentapi
			ORDER BY paymentapiid
		");

		while ($api = $this->db->fetch_array($paymentapis))
		{
			if (empty($api['subsettings']))
			{
				$processed = true;
				$setting = array();
				switch ($api['classname'])
				{
					case 'paypal':
						$setting = array(
							'show' => array(
								'type' => 'yesno',
								'value' => 1,
								'validate' => 'boolean'
							),
							'tax' => array(
								'type' => 'yesno',
								'value' => 0,
								'validate' => 'boolean'
							),
							'shipping_address' => array(
								'type' => 'select',
								'options' => array(
									'none',
									'optional',
									'required',
								),
								'value' => 'none',
								'validate' => 'boolean'
							),
						);
						break;

					default:
						$setting = array(
							'show' => array(
								'type' => 'yesno',
								'value' => 1,
								'validate' => 'boolean'
							),
						);
				}

				$this->db->query_write("
					UPDATE " . TABLE_PREFIX . "paymentapi
					SET subsettings = '" . $this->db->escape_string(serialize($setting)) . "'
					WHERE paymentapiid = $api[paymentapiid]
				");

			}
		}

		if (!$processed)
		{
			$this->skip_message();
		}
	}

	/**
	 * Step 6 - Drop old autosave table if it exists (from vB4)
	 */
	public function step_6()
	{
		if ($this->tableExists('autosave'))
		{
			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'autosave', 1, 1),
				"DROP TABLE IF EXISTS " . TABLE_PREFIX . "autosave"
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Step 7 - Add new autosave table
	 */
	public function step_7()
	{
		$this->run_query(
			sprintf($this->phrase['vbphrase']['create_table'], TABLE_PREFIX . "autosavetext"),
			"CREATE TABLE " . TABLE_PREFIX . "autosavetext (
				parentid INT UNSIGNED NOT NULL DEFAULT '0',
				nodeid INT UNSIGNED NOT NULL DEFAULT '0',
				userid INT UNSIGNED NOT NULL DEFAULT '0',
				pagetext MEDIUMTEXT,
				dateline INT UNSIGNED NOT NULL DEFAULT '0',
				PRIMARY KEY (nodeid, parentid, userid),
				KEY userid (userid),
				KEY parentid (parentid, userid),
				KEY dateline (dateline)
			)",
			self::MYSQL_ERROR_TABLE_EXISTS
		);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
