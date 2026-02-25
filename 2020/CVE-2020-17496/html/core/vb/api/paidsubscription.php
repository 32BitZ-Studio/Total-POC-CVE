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
 * vB_Api_Paidsubscription
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Paidsubscription extends vB_Api
{
	protected $subobj = null;
	protected $apicache = array();

	protected $disableFalseReturnOnly = array('fetchAll');


	protected function __construct()
	{
		parent::__construct();
		require_once(DIR . '/includes/class_paid_subscription.php');

		// Cache subscriptions
		$this->subobj = new vB_PaidSubscription();
		$this->fetchActivePaymentApis();
	}

	protected function checkPermission()
	{
		$userinfo = vB::getCurrentSession()->fetch_userinfo();
		if ($userinfo['userid'] == 0)
		{
			// Guests are not allowed to use paid subscriptions
			throw new vB_Exception_Api('no_permission');
		}
	}

	/**
	 * Check whether paid subscriptions system is active or not
	 *
	 * @throws vB_Exception_Api
	 * @return void
	 */
	public function checkStatus()
	{
		$this->subobj->cache_user_subscriptions();

		$this->fetchActivePaymentApis();
		if (empty($this->subobj->subscriptioncache) OR empty($this->apicache) OR !vB::getDatastore()->getOption('subscriptionmethods'))
		{
			// Paid Subscription is disabled.
			throw new vB_Exception_Api('nosubscriptions');
		}
	}

	/**
	 * Fetch all subscriptions that an user can join and already joined
	 * It also fetches active payment APIs
	 *
	 * @param bool $isreg Whether to fetch subscriptions for signup page
	 * @return array Paid subscriptions info for the user.
	 */
	public function fetchAll($isreg = false)
	{
		try
		{
			$this->checkStatus();
		}
		catch (vB_Exception_Api $e)
		{
			return array();
		}

		$userinfo = vB::getCurrentSession()->fetch_userinfo();
		$usercontext = vB::getUserContext();

		$membergroupids = fetch_membergroupids_array($userinfo);
		$allow_secondary_groups = $usercontext->hasPermission('genericoptions', 'allowmembergroups');

		$subscribed = $this->fetchSubscribed();

		//Should return phrase values from here and do the rendering in the templates.
		//this could get a little complicated due to nesting of phrases below.
		$phraseApi = vB_Api::instanceInternal('phrase');

		$vbphrase = $phraseApi->fetch(array(
			'day',
			'week',
			'month',
			'year',
			'days',
			'weeks',
			'months',
			'years',
			'length_x_units_y_recurring_z',
			'recurring'
		));

		$lengths = array(
			'D' => $vbphrase['day'],
			'W' => $vbphrase['week'],
			'M' => $vbphrase['month'],
			'Y' => $vbphrase['year'],
			// plural stuff below
			'Ds' => $vbphrase['days'],
			'Ws' => $vbphrase['weeks'],
			'Ms' => $vbphrase['months'],
			'Ys' => $vbphrase['years']
		);

		$cansubscribesubscriptions = array();
		$subscribedsubscriptions = array();
		foreach ($this->subobj->subscriptioncache AS $subscription)
		{
			$subscriptionid =& $subscription['subscriptionid'];
			$subscription['cost'] = unserialize($subscription['cost']);
			$subscription['newoptions'] = @unserialize($subscription['newoptions']);
			foreach ($subscription['cost'] AS $key => $currentsub)
			{
				if ($currentsub['length'] == 1)
				{
					$currentsub['units'] = $lengths["{$currentsub['units']}"];
				}
				else
				{
					$currentsub['units'] = $lengths[$currentsub['units'] . 's'];
				}

				$phrases = $phraseApi->renderPhrases(array('length' => array(
					'length_x_units_y_recurring_z',
					$currentsub['length'],
					$currentsub['units'],
					($currentsub['recurring'] ? " ($vbphrase[recurring])" : '')
				)));

				$subscription['cost'][$key]['subscription_length'] = $phrases['phrases']['length'];
			}


			if (isset($subscribed["$subscription[subscriptionid]"]))
			{
				// This subscription has been subscribed by the user
				$subscribedsubscriptions[$subscriptionid] = $subscription;
				$subscribedsubscriptions[$subscriptionid]['subscribed'] = $subscribed["$subscription[subscriptionid]"];
			}

			if ($subscription['active'])
			{
				if ($isreg AND empty($subscription['newoptions']['regshow']))
				{
					// Display paid subscription during registration is set to false
					continue;
				}

				// Check whether to show the subscription to the user.
				if (
					!empty($subscription['deniedgroups'])
					AND
					(
						($allow_secondary_groups AND !count(array_diff($membergroupids, $subscription['deniedgroups'])))
						OR
						(!$allow_secondary_groups AND in_array($userinfo['usergroupid'], $subscription['deniedgroups']))
					)
				)
				{
					continue;
				}

				// List allowed payment apis
				$allowedapis = array();
				foreach ((array)$subscription['newoptions']['api'] as $api => $options)
				{
					if (!empty($options['show']))
					{
						$allowedapis[] = $api;
					}
				}

				$subscription['allowedapis'] = json_encode($allowedapis);

				$cansubscribesubscriptions[$subscriptionid] = $subscription;
			}
		}

		if (!$cansubscribesubscriptions AND !$subscribedsubscriptions)
		{
			return array();
		}

		return array(
			'subscribed' => $subscribedsubscriptions,
			'cansubscribe' => $cansubscribesubscriptions,
			'paymentapis' => $this->apicache,
			'currencysymbols' => $this->getCurrencySymbols(),
		);
	}

	private function getCurrencySymbols()
	{
		//this is entered by the admin.  Try very hard to bullet proof it
		//and figure out what we can salvage from bad data.
		$result = array();
		$symbols = vB::getDatastore()->getOption('currencysymbols');

		$lines = explode("\n", $symbols);
		foreach($lines AS $line)
		{
			$fields = explode('|', trim($line));
			if(count($fields) == 2)
			{
				$code = trim($fields[0]);
				$symbol = trim($fields[1]);

				if($code AND $symbol)
				{
					$result[strtolower($code)] = $symbol;
				}
			}
		}

		return $result;
	}

	/**
	 * Fetch all active payment APIs.
	 *
	 * @return array Payment APIs
	 */
	public function fetchActivePaymentApis()
	{
		if (!$this->apicache)
		{
			$paymentapis = vB::getDbAssertor()->getRows('vBForum:paymentapi', array('active' => 1));
			foreach ($paymentapis as $paymentapi)
			{
				$paymentapi['settings'] = unserialize($paymentapi['settings']);
				$this->apicache["$paymentapi[classname]"] = $paymentapi;
			}
		}
		return $this->apicache;
	}

	/**
	 * Fetch all active subscriptions current user is subscribed too
	 */
	public function fetchSubscribed()
	{
		try
		{
			$this->checkStatus();
			$this->checkPermission();
		}
		catch (vB_Exception_Api $e)
		{
			return array();
		}

		$susers = vB::getDbAssertor()->getRows('vBForum:subscriptionlog', array('status' => 1, 'userid' => vB::getUserContext()->fetchUserId()));

		$subscribed = array();
		foreach ($susers as $suser)
		{
			$subscribed["$suser[subscriptionid]"] = $suser;
		}

		return $subscribed;
	}

	/**
	 * Place a subscription order
	 */
	public function placeOrder($subscriptionid, $subscriptionsubid, $paymentapiclass, $currency)
	{
		$this->checkStatus();
		$this->checkPermission();

		$sub = $this->subobj->subscriptioncache["$subscriptionid"];
		$sub['newoptions'] = @unserialize($sub['newoptions']);

		// Verify that the payment api is allowed for this subscription
		if (empty($sub['newoptions']['api'][$paymentapiclass]['show']))
		{
			throw new vB_Exception_Api('invalid_paymentapiclass');
		}

		$userinfo = vB::getCurrentSession()->fetch_userinfo();
		$usercontext = vB::getUserContext();

		$membergroupids = fetch_membergroupids_array($userinfo);
		$allow_secondary_groups = $usercontext->hasPermission('genericoptions', 'allowmembergroups');

		if (empty($sub) OR !$sub['active'])
		{
			throw new vB_Exception_Api('invalidid');
		}

		if (
			!empty($sub['deniedgroups'])
			AND
			(
				($allow_secondary_groups AND !count(array_diff($membergroupids, $sub['deniedgroups'])))
				OR
				(!$allow_secondary_groups AND in_array($userinfo['usergroupid'], $sub['deniedgroups']))
			)
		)
		{
			throw new vB_Exception_Api('invalidid');
		}

		$costs = unserialize($sub['cost']);
		if (empty($costs["$subscriptionsubid"]['cost']["$currency"]))
		{
			throw new vB_Exception_Api('invalid_currency');
		}

		$hash = md5($userinfo['userid'] . $userinfo['secret'] . $subscriptionid . uniqid(microtime(),1));
		/* insert query */
		vB::getDbAssertor()->insert('vBForum:paymentinfo', array(
			'hash' => $hash,
			'completed' => 0,
			'subscriptionid' => $subscriptionid,
			'subscriptionsubid' => $subscriptionsubid,
			'userid' => $userinfo['userid'],
		));

		$method = vB::getDbAssertor()->getRow('vBForum:paymentapi', array('active' => 1, 'classname' => $paymentapiclass));

		$supportedcurrencies = explode(',', $method['currency']);

		if (!in_array($currency, $supportedcurrencies))
		{
			throw new vB_Exception_Api('currency_not_supported');
		}

		// TODO: vB_Template::create() has many PHP notices. We need to fix them.
		error_reporting(E_ALL & ~E_NOTICE);

		$form = $this->subobj->construct_payment($hash, $method, $costs["$subscriptionsubid"], $currency, $sub, $userinfo);
		$typetext = $method['classname'] . '_order_instructions';

		$templater = new vB5_Template('subscription_paymentbit');
			$templater->register('form', $form);
			$templater->register('method', $method);
			$templater->register('typetext', $typetext);
		$orderbit = $templater->render();

		return $orderbit;
	}

	/**
	 * User End a subscription by its own
	 *
	 * @param $subscriptionid int The id of the subscription
	 */
	public function endsubscription($subscriptionid)
	{
		$this->checkStatus();
		$this->checkPermission();

		$userinfo = vB::getCurrentSession()->fetch_userinfo();

		$this->subobj->delete_user_subscription($subscriptionid, $userinfo['userid'], -1, true);
		return array('success' => true);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101111 $
|| #######################################################################
\*=========================================================================*/
