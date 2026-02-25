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

class vB_Upgrade_553a4 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '553a4';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.5.3 Alpha 4';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.5.3 Alpha 3';

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
		/*
			We used to always append node.nodeid ASC sorting to every single search
			query.
			We've changed that to only append it when it's needed (when there's a
			created ASC|DESC sort), and to *match* the direction of the created sorting.
			The same direction allows mysql to use a (created, nodeid) index to sort
			and speed up certain queries.
		 */
		$this->drop_index(
			sprintf($this->phrase['core']['altering_x_table'], 'node', 1, 2),
			'node',
			'created'
		);
		$this->long_next_step();
	}

	public function step_2()
	{
		$this->add_index(
			sprintf($this->phrase['core']['altering_x_table'], 'node', 2, 2),
			'node',
			'created',
			array('created', 'nodeid')
		);
	}

	// Update the permissions for skip_moderate in 'defaultchannelpermissions'
	public function step_3()
	{
		$datastore = vB::getDatastore();
		$datastore->fetch('defaultchannelpermissions');
		$defaultchannelpermissions = vB::getDatastore()->getValue('defaultchannelpermissions');
		if (empty($defaultchannelpermissions))
		{
			// if this isn't created yet, then there's nothing to do.
			return $this->skip_message();
		}

		if (!is_array($defaultchannelpermissions))
		{
			$defaultchannelpermissions = vB_Utility_Unserialize::unserialize($defaultchannelpermissions);
		}

		$forumpermissions = $datastore->getValue('bf_ugp_forumpermissions2');
		$topicperm = $forumpermissions['skipmoderatetopics'];
		$replyperm = $forumpermissions['skipmoderatereplies'];
		$attachperm = $forumpermissions['skipmoderateattach'];

		$allperms = $topicperm | $replyperm | $attachperm;

		$needsRebuild = false;
		foreach($defaultchannelpermissions AS $__nodekey => $__innerArr)
		{
			foreach ($__innerArr AS $__groupkey => $permissions)
			{
				if (isset($permissions['skip_moderate']))
				{
					$needsRebuild = true;
					if($permissions['skip_moderate'])
					{
						$defaultchannelpermissions[$__nodekey][$__groupkey]['forumpermissions2'] |= $allperms;
					}
					else
					{
						$defaultchannelpermissions[$__nodekey][$__groupkey]['forumpermissions2'] &= ~$allperms;
					}

					unset($defaultchannelpermissions[$__nodekey][$__groupkey]['skip_moderate']);
				}
			}
		}

		if ($needsRebuild)
		{
			// show message.
			$this->show_message($this->phrase['version']['541b1']['rebuilding_defaultchannelperms_datastore']);
			$datastore->build('defaultchannelpermissions', serialize($defaultchannelpermissions), 1);
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
|| # CVS: $RCSfile$ - $Revision: 101812 $
|| ####################################################################
\*======================================================================*/
