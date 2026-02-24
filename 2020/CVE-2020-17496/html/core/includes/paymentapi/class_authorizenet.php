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

if (!isset($GLOBALS['vbulletin']->db))
{
	exit;
}

/**
* Class that provides payment verification and form generation functions
*
* @package	vBulletin
* @version	$Revision: 101078 $
* @date		$Date: 2019-03-25 15:21:56 -0700 (Mon, 25 Mar 2019) $
*/
class vB_PaidSubscriptionMethod_authorizenet extends vB_PaidSubscriptionMethod
{
	/**
	* The variable indicating if this payment provider supports recurring transactions
	*
	* @var	bool
	*/
	var $supports_recurring = false;

	/**
	* Display feedback via payment_gateway.php when the callback is made
	*
	* @var	bool
	*/
	var $display_feedback = true;

	/**
	 *	Form target for the a.net servers.  Intended to be overloaded in the test class with
	 *	differs only in that it needs to reference the a.net sandbox.
	 */
	protected $form_target = 'https://secure.authorize.net/gateway/transact.dll';
	protected $form_test_target = 'https://test.authorize.net/gateway/transact.dll';

	private $sandbox = false;

	public function __construct(&$registry)
	{
		parent::__construct($registry);
		$config = vB::getConfig();
		$this->sandbox = !empty($config['Misc']['debugpayments']);
	}

	/**
	* Perform verification of the payment, this is called from the payment gatewa
	*
	* @return	bool	Whether the payment is valid
	*/
	function verify_payment()
	{
		//these are the fields that will be verified in the order that they need to be put into 
		//the hash value.  The order must match the a.net documentation
		$verify_fields = array(
			'x_trans_id',
			'x_test_request',
			'x_response_code',
			'x_auth_code',
			'x_cvv2_resp_code',
			'x_cavv_response',
			'x_avs_code',
			'x_method',
			'x_account_number',
			'x_amount',
			'x_company',
			'x_first_name',
			'x_last_name',
			'x_address',
			'x_city',
			'x_state' ,
			'x_zip',
			'x_country',
			'x_phone',
			'x_fax',
			'x_email',
			'x_ship_to_company',
			'x_ship_to_first_name',
			'x_ship_to_last_name',
			'x_ship_to_address',
			'x_ship_to_city',
			'x_ship_to_state',
			'x_ship_to_zip',
			'x_ship_to_country',
			'x_invoice_num',
		);

		$this->registry->input->clean_array_gpc('p', array(
			'x_amount'               => vB_Cleaner::TYPE_STR,
			'x_trans_id'             => vB_Cleaner::TYPE_STR,
			'x_description'          => vB_Cleaner::TYPE_STR,
			'x_SHA2_Hash'            => vB_Cleaner::TYPE_STR,
			'x_response_code'        => vB_Cleaner::TYPE_UINT,
			'x_invoice_num'          => vB_Cleaner::TYPE_STR,
			'x_response_reason_text' => vB_Cleaner::TYPE_NOHTML,
			'x_response_reason_code' => vB_Cleaner::TYPE_NOHTML,
		));

		if (!$this->test())
		{
			$this->error = 'Payment processor not configured';
			return false;
		}

		$this->transaction_id = $this->registry->GPC['x_trans_id'];

		//if we are in text mode then the transaction id is always 0, which causes
		//problems when we try to process it.  This means we can't test a duplicate
		//transaciton case, but that's better than not being able to test the 
		//normal case (we might need to make this more sophisticatd or simpy use
		//scaffolding to test the various cases in the calling code
		if($this->sandbox AND $this->transaction_id == '0')
		{
			$this->transaction_id = 'test ' . time();
		}
		
		if (!preg_match('#([a-f0-9]{32})#i', $this->registry->GPC['x_description'], $matches))
		{
			$this->error = "No Payment Hash Found";
			return false;
		}
		$paymenthash = $matches[1];

		if(!$this->settings['signaturekey'])
		{
			$this->error = "Hash check failed";
			return false;
		}

		//Do not go through the cleaner here.  We don't want to risk altering the values of the verification
		//fields (which would cause the hash check to fail). We will *only* use them to create the hash which
		//is safe.  Even if somebody gives us garbage. (This verifies that the data hasn't been altered in transit).
		//
		//Making a copy ensures that we have only the verification fields and in
		//the order we need them. This is very important.
		$data = array();
		foreach($verify_fields AS $field)
		{
			$data[$field] = $_POST[$field];
		}
		$data = '^' . implode('^', $data) . '^';

		$check_hash = hash_hmac('sha512', $data, hex2bin($this->settings['signaturekey']));

		if (strcasecmp($check_hash, $this->registry->GPC['x_SHA2_Hash']) === 0)
		{
			if ($this->registry->GPC['x_response_code'] == 1)
			{
				$this->paymentinfo = vB::getDbAssertor()->getRow('vBForum:getPaymentinfo', array('hash' => $paymenthash));

				// lets check the values
				if (!empty($this->paymentinfo))
				{
					$this->paymentinfo['currency'] = '';
					$this->paymentinfo['amount'] = floatval($this->registry->GPC['x_amount']);
					// dont need to check the amount since authornize.net dont include the currency when its sent back
					// the hash helps us get around this though
					$this->type = 1;
					return true;
				}
			}
			else if ($this->registry->GPC['x_response_code'] == 2 OR $this->registry->GPC['x_response_code'] == 3)
			{
				$this->error = $this->registry->GPC['x_response_reason_text'] . ' (' . $this->registry->GPC['x_response_reason_code'] . ')';
			}
			else
			{
				// deliberately not phrased, this should never happen anyway
				$this->error = "Unknown Error";
			}
		}
		else
		{
			$this->error = "Hash check failed";
		}
		return false;
	}

	/**
	* Test that required settings are available, and if we can communicate with the server (if required)
	*
	* @return	bool	If the vBulletin has all the information required to accept payments
	*/
	public function test()
	{
		return (!empty($this->settings['authorize_loginid']) AND !empty($this->settings['txnkey']));
	}

	/**
	* Generates HTML for the subscription form page
	*
	* @param	string		Hash used to indicate the transaction within vBulletin
	* @param	string		The cost of this payment
	* @param	string		The currency of this payment
	* @param	array		Information regarding the subscription that is being purchased
	* @param	array		Information about the user who is purchasing this subscription
	* @param	array		Array containing specific data about the cost and time for the specific subscription period
	*
	* @return	array		Compiled form information
	*/
	function generate_form_html($hash, $cost, $currency, $subinfo, $userinfo, $timeinfo)
	{
		$currency = strtoupper($currency);

		$timenow = vB::getRequest()->getTimeNow();

		$sequence = vbrand(1, 1000);
		$data = $this->settings['authorize_loginid'] . '^' . $sequence . '^' . $timenow . '^' . $cost . '^' . $currency;
		$fingerprint = hash_hmac('sha512', $data, hex2bin($this->settings['signaturekey']));
		$form['action'] = $this->form_target;
		if($this->sandbox)
		{
			$form['action'] = $this->form_test_target;
		}

		$form['method'] = 'post';

		$templater = new vB5_Template('subscription_payment_authorizenet');
			$templater->register('cost', $cost);
			$templater->register('currency', $currency);
			$templater->register('fingerprint', $fingerprint);
			$templater->register('item', $hash);
			$templater->register('sequence', $sequence);
			$templater->register('settings', $this->settings);
			$templater->register('timenow', $timenow);
			$templater->register('userinfo', $userinfo);
		$form['hiddenfields'] = $templater->render();
		return $form;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101078 $
|| #######################################################################
\*=========================================================================*/
