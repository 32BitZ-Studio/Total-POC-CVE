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
* @version	$Revision: 102792 $
* @date		$Date: 2019-09-09 17:45:58 -0700 (Mon, 09 Sep 2019) $
*/
class vB_PaidSubscriptionMethod_google extends vB_PaidSubscriptionMethod
{
	/**
	* The variable indicating if this payment provider supports recurring transactions
	* Google recurring is in beta
	*
	* @var	bool
	*/
	public $supports_recurring = false;

	/**
	* Display feedback via payment_gateway.php when the callback is made
	*
	* @var	bool
	*/
	public $display_feedback = false;

	/*
	 *	Production Checkout URL
	 */
	protected $productionCheckoutUrl = 'https://checkout.google.com/api/checkout/v2/checkout/Merchant/';

	/*
	 *	Sandbox Checkout URL
	 */
	protected $sandboxCheckoutUrl = 'https://sandbox.google.com/checkout/api/checkout/v2/checkout/Merchant/';

	/*
	 *	Production Notification URL
	 */
	protected $productionNotifyUrl = 'https://checkout.google.com/api/checkout/v2/reports/Merchant/';

	/*
	 *	Sandbox Notification URL
	 */
	protected $sandboxNotifyUrl = 'https://sandbox.google.com/checkout/api/checkout/v2/reports/Merchant/';

	/*
	 *
	 */
	protected $diagnose = false;

	public function __construct(&$registry)
	{
		parent::__construct($registry);
	}

	/**
	* Perform verification of the payment, this is called from the payment gatewa
	*
	* @return	bool	Whether the payment is valid
	*/
	public function verify_payment()
	{
		$this->registry->input->clean_array_gpc('p', array(
			'serial-number' => vB_Cleaner::TYPE_NOHTML,
		));

		if (!$this->registry->GPC['serial-number'])
		{
			$this->sendHeader(false);
			$this->error_code = 'missing_serial_number';
			return false;
		}

		if (!$this->test())
		{
			$this->sendHeader(false);
			$this->error_code = 'Payment processor not configured';
			return false;
		}

		$xml = new vB_XML_Builder();
			$xml->add_group('notification-history-request', array('xmlns' => 'http://checkout.google.com/schema/2'));
				$xml->add_tag('serial-number', $this->registry->GPC['serial-number']);
			$xml->close_group('notification-history-request');
		$xmlString = $xml->fetch_xml();

		$submitUrl = ($this->settings['sandbox'] ? $this->sandboxNotifyUrl : $this->productionNotifyUrl)  . trim($this->settings['google_merchant_id']);
		$headers = array(
			'Authorization: Basic ' . base64_encode(trim($this->settings['google_merchant_id']) . ':' . trim($this->settings['google_merchant_key'])),
			'Content-Type: application/xml; charset=UTF-8',
			'Accept: application/xml; charset=UTF-8'
		);

		$vurl = vB::getUrlLoader();
		//no idea if this is actually needed, but I don't want to muck with prior behavior here.
		$vurl->setOption(vB_Utility_Url::CLOSECONNECTION, 1);
		$vurl->setOption(vB_Utility_Url::HTTPHEADER, $headers);
		$result = $vurl->post($submitUrl, $xmlString);
		$result = $result['body'];

		$xmlobj = new vB_XML_Parser($result);
		$xmlobj->include_first_tag = true;
		$parsed_xml = $xmlobj->parse();
		if ($parsed_xml === false OR !is_array($parsed_xml))
		{
			$this->error_code = 'xml_parse_failed';
			$this->sendHeader(false);
			return false;
		}

		$data = reset($parsed_xml);
		$notificationType = key($parsed_xml);
		$parsed_xml = $data;

		$this->transaction_id = isset($parsed_xml['google-order-number']) ? $parsed_xml['google-order-number'] : false;
		$hash = isset($parsed_xml['order-summary']['shopping-cart']['items']['item']['merchant-item-id']) ? $parsed_xml['order-summary']['shopping-cart']['items']['item']['merchant-item-id'] : false;
		$order_state = isset($parsed_xml['order-summary']['financial-order-state']) ? $parsed_xml['order-summary']['financial-order-state'] : false;
		$totalcost = isset($parsed_xml['order-summary']['total-charge-amount']['value']) ? floatval($parsed_xml['order-summary']['total-charge-amount']['value']) : 0;
		$tax = isset($parsed_xml['order-summary']['order-adjustment']['total-tax']['value']) ? floatval($parsed_xml['order-summary']['order-adjustment']['total-tax']['value']) : 0;
		$currency = isset($parsed_xml['order-summary']['total-charge-amount']['currency']) ? strtolower($parsed_xml['order-summary']['total-charge-amount']['currency']) : 0;
		$cost = $totalcost - $tax;

		if ($this->transaction_id AND $hash)
		{
			$this->paymentinfo = vB::getDbAssertor()->getRow('vBForum:getPaymentinfo', array('hash' => $hash));

			if (!empty($this->paymentinfo))
			{
				$sub = vB::getDbAssertor()->getRow('vBForum:subscription', array('subscriptionid' => $this->paymentinfo['subscriptionid']));
				$subcost = unserialize($sub['cost']);
				if ($subcost)
				{
					$this->paymentinfo['currency'] = $currency;
					$this->paymentinfo['amount'] = $cost;

					switch($notificationType)
					{
						case 'charge-amount-notification':
							if ($cost == floatval($subcost["{$this->paymentinfo[subscriptionsubid]}"]['cost'][$currency]))
							{
								$this->type = 1;
							}
							else
							{
								$this->error_code = 'invalid_payment_amount - XML: ' . $result . htmlspecialchars_uni(' SubmitURL: ' . $submitUrl . ' Headers: ' . implode(' ', $headers));
							}
							break;
						case 'refund-amount-notification':
						case 'chargeback-amount-notification':
							$this->type = 2;
							break;

						case 'new-order-notification':
						case 'risk-information-notification':
						case 'authorization-amount-notification':
							$this->error_code = 'ignored_status_update';
							$this->type = 3;
							break;

						default:
					}

					if ($this->type == 0 AND $this->error_code == '')
					{
						switch($order_state)
						{
							case 'CANCELLED':
							case 'CANCELLED_BY_GOOGLE':
								$this->type = 2;
								break;

							// Ignore these states
							case 'PAYMENT_DECLINED':
							case 'REVIEWING':
							case 'CHARGEABLE':
							case 'CHARGING':
							case 'CHARGED':
								$this->type = 3;
								$this->error_code = 'ignored_status_update';
							default:
						}
					}
				}
				else
				{
					$this->error_code = 'invalid_subscription - XML: ' . $result . htmlspecialchars_uni(' SubmitURL: ' . $submitUrl . ' Headers: ' . implode(' ', $headers));
				}
			}
			else
			{
				$this->error_code = 'invalid_payment - XML: ' . $result . htmlspecialchars_uni(' SubmitURL: ' . $submitUrl . ' Headers: ' . implode(' ', $headers));
			}
			$this->sendHeader(true);
		}
		else
		{
			$this->error_code = 'invalid_XML_response - XML: ' . $result . htmlspecialchars_uni(' SubmitURL: ' . $submitUrl . ' Headers: ' . implode(' ', $headers));
			$this->sendHeader(false);
			return false;
		}

		$xml = new vB_XML_Builder();
			$xml->add_group('notification-acknowledgment', array('xmlns' => 'http://checkout.google.com/schema/2', 'serial-number' => $this->registry->GPC['serial-number']));
			$xml->close_group();
		$xml->send_content_type_header();
		$xml->send_content_length_header();
		echo $xml->fetch_xml();

		return ($this->type > 0 AND $this->type < 3);
	}

	/*
	 *	Send response header.
	 *
	 * @param	bool	true = 200, false = 503
	 */
	protected function sendHeader($type)
	{
		$code = (($type) ? 200 : 503);
		http_response_code($code);
	}

	/**
	* Test that required settings are available, and if we can communicate with the server (if required)
	*
	* @return	bool	If the vBulletin has all the information required to accept payments
	*/
	public function test()
	{
		return (!empty($this->settings['google_merchant_key']) AND !empty($this->settings['google_merchant_id']));
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
	public function generate_form_html($hash, $cost, $currency, $subinfo, $userinfo, $timeinfo)
	{
		global $vbphrase, $vbulletin, $show;

		$item = $hash;
		$currency = strtoupper($currency);

		$form['google'] = true;
		$form['action'] = ($this->settings['sandbox'] ? $this->sandboxCheckoutUrl : $this->productionCheckoutUrl) . trim($this->settings['google_merchant_id']);
		$form['method'] = 'post';

		if ($this->diagnose)
		{
			$form['action'] .= '/diagnose';
		}

		// load settings into array so the template system can access them
		$settings =& $this->settings;
		$cartXml = $this->getCartXml($hash, $cost, $currency, $subinfo);

		$templater = vB_Template::create('subscription_payment_google');
			$templater->register('cart', base64_encode($cartXml));
			$templater->register('signature', base64_encode($this->getSignature($cartXml)));
			$templater->register('google_merchant_id', trim($this->settings['google_merchant_id']));
			$templater->register('item', $hash);
		$form['hiddenfields'] .= $templater->render();
		return $form;
	}

	/*
	 * Generate signature
	 *
	 * @param	string	XML Document
	 *
	 * @return string
	 */
	protected function getSignature($cartXml)
	{
		return $this->calcHmacSha1($this->settings['google_merchant_key'], $cartXml);
	}

	/*
	 * Generate cart XML
	 *
	 * @param	array	Subscription info
	 *
	 * @return	string	XML Document
	 */
	protected function getCartXml($hash, $cost, $currency, $subinfo)
	{
		$phrases = array(
			'sub' . $subinfo['subscriptionid'] . '_title', 'sub' . $subinfo['subscriptionid'] . '_desc'
		);
		$vbphrase = vB_Api::instanceInternal('phrase')->fetch($phrases);

		$xml = new vB_XML_Builder();
			$xml->add_group('checkout-shopping-cart', array('xmlns' => 'http://checkout.google.com/schema/2'));
				$xml->add_group('shopping-cart');
					$xml->add_group('items');
						$xml->add_group('item');
							$xml->add_tag('merchant-item-id', $hash);
							$xml->add_tag('item-name', $vbphrase['sub' . $subinfo['subscriptionid'] . '_title']);
							$xml->add_tag('item-description', $vbphrase['sub' . $subinfo['subscriptionid'] . '_desc']);
							if (!$subinfo['newoptions']['api']['google']['tax'])
							{
								$xml->add_tag('tax-table-selector', 'tax_exempt');
							}
							$xml->add_tag('unit-price', $cost, array('currency' => strtoupper($currency)));
							$xml->add_tag('quantity', 1);
							$xml->add_group('digital-content');
								$xml->add_tag('display-disposition', 'PESSIMISTIC');
								$xml->add_tag('description', $subinfo['newoptions']['api']['google']['message']);
							$xml->close_group('digital-content');
						$xml->close_group('item');
					$xml->close_group('items');
				$xml->close_group('shopping-cart');
			$xml->close_group('checkout-shopping-cart');
		return $xml->fetch_xml();
	}

	/**
	* HMAC
	*
	* @param	string		Key to hash data with
	* @param	string		Data
	*
	* @return	string		sha1 HMAC
	*/
	function calcHmacSha1($key, $data)
	{
		$blocksize = 64;
		if (strlen($key) > $blocksize)
		{
			$key = pack('H*', sha1($key));
		}
		$key = str_pad($key, $blocksize, chr(0x00));
		$ipad = str_repeat(chr(0x36), $blocksize);
		$opad = str_repeat(chr(0x5c), $blocksize);
		$hmac = pack('H*', sha1(($key^$opad) . pack('H*', sha1(($key^$ipad) . $data))));
		return $hmac;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102792 $
|| #######################################################################
\*=========================================================================*/
