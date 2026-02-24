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

class vB_Upgrade_552a3 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '552a3';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.5.2 Alpha 3';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.5.2 Alpha 2';

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

	public function step_1()
	{
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table_x'], 'paymentapi', 1, 1));
		$db = vB::getDbAssertor();

		//there probably isn't more than one entry with a class of 'authorizenet' but it's possible so
		//we account for it.  None of them are going to work without the signaturekey
		$results = $db->select('vBForum:paymentapi', array('classname' => 'authorizenet'));
		foreach($results AS $row)
		{
			$settings = vB_Utility_Unserialize::unserialize($row['settings']);
			if($settings)
			{
				unset($settings['authorize_md5secret']);
				if(!isset($settings['signaturekey']))
				{
					$settings['signaturekey'] = array(
						'type' => 'text',
						'value' => '',
						'validate' => 'string',
					);
				}

				$db->update('vBForum:paymentapi', array('settings' => serialize($settings)), array('paymentapiid' => $row['paymentapiid']));
			}
		}
	}

	//this could potentially be collapsed into the prior step, but add_adminmessage doesn't play nice with
	//the messages being sent and it's not worth the effort of figuring that out.  The overhead is trivial.
	public function step_2()
	{
		$db = vB::getDbAssertor();

		//there probably isn't more than one entry with a class of 'authorizenet' but it's possible so
		//we account for it.  Send the message if any of them are active.
		$results = $db->select('vBForum:paymentapi', array('classname' => 'authorizenet'));
		foreach($results AS $row)
		{
			if($row['active'])
			{
				//if we have muliple active a.net payment entries then we'll only specifically
				//alert for the first one.  It's *really* unlikely that we have more than one
				//and we don't want to spam this message (there really isn't an option for allow
				//duplicates but only if the url is different).  We'll just live with the fact that
				//the one admin affected will need to figure out they have to update all of them.
				$this->add_adminmessage(
					'anet_signaturekey_needs_updating',
					array(
						'dismissable' => 1,
						'script'      => '',
						'action'      => '',
						'execurl'     => 'subscriptions.php?do=apiedit&paymentapiid=' . $row['paymentapiid'],
						'method'      => 'get',
						'status'      => 'undone',
					)
				);

				//if we got this far, we're done here.
				return;
			}
		}

		//we didn't need to post the message.
		$this->skip_message();
	}

	/**
	 * Convert instances of group category modules/widgets to standard channel navigation modules
	 */
	public function step_3()
	{
		$result = $this->replaceModule(
			// the old (now removed) group categories module
			'vbulletin-widget_sgcategories-4eb423cfd6dea7.34930860',
			// the standard channel navigation module we're replacing it with
			'vbulletin-widget_cmschannelnavigation-4eb423cfd6dea7.34930875',
			// the default admin config we want to use for the new module instances
			// this matches the serialized config in vbulletin-pagetemplates.xml for
			// the channel navigation modules that replace the old ones
			// copying the serialized value here for easier maintenance and to avoid
			// typos at the expense of an unserialize call
			unserialize('a:4:{s:12:"root_channel";s:45:"channelguid:vbulletin-4ecbdf567f3a38.99555306";s:5:"title";s:30:"phrase:social_group_categories";s:5:"depth";s:1:"1";s:17:"hide_root_channel";s:1:"1";}')
		);

		if ($result['updated'])
		{
			$this->show_message(sprintf($this->phrase['version']['552a3']['converting_group_category_modules_to_channel_navigation_modules_x_module_instances_updated'], $result['instancesDeleted']));
		}
		else
		{
			$this->skip_message();
		}
	}

}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101170 $
|| ####################################################################
\*======================================================================*/
