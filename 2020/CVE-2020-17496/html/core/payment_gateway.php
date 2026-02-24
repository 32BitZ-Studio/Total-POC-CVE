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

// ####################### SET PHP ENVIRONMENT ###########################
error_reporting(E_ALL & ~E_NOTICE);

// #################### DEFINE IMPORTANT CONSTANTS #######################
define('THIS_SCRIPT', 'payment_gateway');
define('CSRF_PROTECTION', false);
define('SKIP_SESSIONCREATE', 1);
if (!defined('VB_ENTRY'))
{
	define('VB_ENTRY', 1);
}

// #################### PRE-CACHE TEMPLATES AND DATA ######################
// get special phrase groups
$phrasegroups = array('subscription');

// get special data templates from the datastore
$specialtemplates = array();

// pre-cache templates used by all actions
$globaltemplates = array();

// pre-cache templates used by specific actions
$actiontemplates = array();

// ######################### REQUIRE BACK-END ############################
define('VB_AREA', 'Subscriptions');
define('CWD', (($getcwd = getcwd()) ? $getcwd : '.'));
define('VB_API', false);
require_once(CWD . '/includes/init.php');

require_once(DIR . '/includes/adminfunctions.php');
require_once(DIR . '/includes/class_paid_subscription.php');

$vbulletin->input->clean_array_gpc('r', array(
	'method' => vB_Cleaner::TYPE_STR
));

$vbulletin->nozip = true;

$api = vB::getDbAssertor()->getRow('vBForum:paymentapi', array('classname' => $vbulletin->GPC['method']));
if (!empty($api) AND $api['active'])
{
	$subobj = new vB_PaidSubscription($vbulletin);
	if (file_exists(DIR . '/includes/paymentapi/class_' . $api['classname'] . '.php'))
	{
		require_once(DIR . '/includes/paymentapi/class_' . $api['classname'] . '.php');
		$api_class = 'vB_PaidSubscriptionMethod_' . $api['classname'];
		$apiobj = new $api_class($vbulletin);


		if (!empty($api['settings']))
		{
			// need to convert this from a serialized array with types to a single value
			$apiobj->settings = $subobj->construct_payment_settings($api['settings']);
		}

		if ($apiobj->verify_payment())
		{
			// its a valid payment now lets check transactionid
			$transaction = vB::getDbAssertor()->getRow('vBForum:paymenttransaction', array(
				'transactionid' => $apiobj->transaction_id,
				'paymentapiid' => $api['paymentapiid'],
			));

			if (($apiobj->type == 2 OR (empty($transaction) AND $apiobj->type == 1)) AND $vbulletin->options['paymentemail'])
			{
				if (!$vbphrase)
				{
					// initialize $vbphrase and set language constants
					$vbphrase = init_language();
				}

				$emails = explode(' ', $vbulletin->options['paymentemail']);

				$username = unhtmlspecialchars($apiobj->paymentinfo['username']);
				$userid = $apiobj->paymentinfo['userid'];
				$subscription = $vbphrase['sub' . $apiobj->paymentinfo['subscriptionid'] . '_title'];
				$amount = vb_number_format($apiobj->paymentinfo['amount'], 2) . ' ' . strtoupper($apiobj->paymentinfo['currency']);
				$processor = $api['title'];
				$transactionid = $apiobj->transaction_id;

				$memberlink = vB5_Route::buildUrl('profile|bburl', array('userid' => $userid, 'username' => $apiobj->paymentinfo['username']));

				if ($apiobj->type == 2)
				{
					$maildata = vB_Api::instanceInternal('phrase')->fetchEmailPhrases(
						'payment_reversed',
						array(
							$username,
							$vbulletin->options['bbtitle'],
							$memberlink,
							$subscription,
							$amount,
							$processor,
							$transactionid,
						),
						array($vbulletin->options['bbtitle'])
					);
				}
				else
				{
					$maildata = vB_Api::instanceInternal('phrase')->fetchEmailPhrases(
						'payment_received',
						array(
							$username,
							$vbulletin->options['bbtitle'],
							$memberlink,
							$subscription,
							$amount,
							$processor,
							$transactionid,
						),
						array($vbulletin->options['bbtitle'])
					);
				}

				foreach($emails AS $toemail)
				{
					if (trim($toemail))
					{
						vB_Mail::vbmail($toemail, $maildata['subject'], $maildata['message'], true);
					}
				}
			}

			if (empty($transaction))
			{
				// transaction hasn't been processed before
				/*insert query*/
				$trans = array(
					'transactionid' => $apiobj->transaction_id,
					'paymentinfoid' => $apiobj->paymentinfo['paymentinfoid'],
					'amount'        => $apiobj->paymentinfo['amount'],
					'currency'      => $apiobj->paymentinfo['currency'],
					'state'         => $apiobj->type,
					'dateline'      => TIMENOW,
					'paymentapiid'  => $api['paymentapiid'],
				);

				if (!$apiobj->type)
				{
					$trans['request'] = serialize(array(
						'vb_error_code' => $apiobj->error_code,
						'GET'           => serialize($_GET),
						'POST'          => serialize($_POST)
					));
				}

				vB::getDbAssertor()->insert('vBForum:paymenttransaction', $trans);

				if ($apiobj->type == 1)
				{
					$subobj->build_user_subscription($apiobj->paymentinfo['subscriptionid'], $apiobj->paymentinfo['subscriptionsubid'], $apiobj->paymentinfo['userid']);
					if ($apiobj->display_feedback)
					{
						paymentCompleteRedirect();
					}
				}
				else if ($apiobj->type == 2)
				{
					$subobj->delete_user_subscription($apiobj->paymentinfo['subscriptionid'], $apiobj->paymentinfo['userid'], $apiobj->paymentinfo['subscriptionsubid']);
				}
			}
			else if ($apiobj->type == 2)
			{
				// transaction is a reversal / refund
				$subobj->delete_user_subscription($apiobj->paymentinfo['subscriptionid'], $apiobj->paymentinfo['userid'], $apiobj->paymentinfo['subscriptionsubid']);
			}
			else
			{
				// its most likely a re-post of a payment, if we've already dealt with it serve up a redirect
				if ($apiobj->display_feedback)
				{
					paymentCompleteRedirect();
				}
			}
		}
		else
		{
			// something went horribly wrong, get $apiobj->error
			if ($apiobj->type == 3)
			{
				// type = 3 means we received a valid response but we need to ignore it .. thanks Google, obtuse!
				if ($apiobj->display_feedback)
				{
					paymentCompleteRedirect();
				}
			}
			else
			{
				$trans = array(
					'state'         => 0,
					'dateline'      => TIMENOW,
					'paymentapiid'  => $api['paymentapiid'],
					'request'       => serialize(array(
					'vb_error_code' => $apiobj->error_code,
					'GET'           => serialize($_GET),
					'POST'          => serialize($_POST)
					)),
				);
				vB::getDbAssertor()->insert('vBForum:paymenttransaction', $trans);
				if ($apiobj->display_feedback AND !empty($apiobj->error))
				{
					showError($api['title'], $apiobj->error);
				}
			}
		}
	}
}
else
{
	exec_header_redirect(vB5_Route::buildUrl('home|fullurl'));
}

function paymentCompleteRedirect()
{
	showRedirect('payment_complete', vB5_Route::buildUrl('settings|fullurl', array('tab' => 'subscriptions')));
}

function bootstrapFrontend()
{
	//boot the front end code.  This isn't ideal -- for one thing it violates the dusty and unused notion that
	//the core directory can be relocated from it's default location -- but the backend template engine
	//is creaky and can't handle rendering the header block.
	//
	//We really should relocate the callback to a frontend route/controller and get rid of this entire file
	//but that would ential a tremendous amount of risk for some difficult to test code
	require_once(__DIR__ . '/../includes/vb5/autoloader.php');
	vB5_Autoloader::register(__DIR__ . '/../');
	vB5_Frontend_Application::init('config.php');

	//this also runs some init code that we probably want to do before we get to far in.
	Api_InterfaceAbstract::instance();
}

//this function is here because it's some shim code to make this file work that
//really shouldn't be used elsewhere.
function showRedirect($phrase, $url)
{
	bootstrapFrontend();

	$preheader = vB5_ApplicationAbstract::getPreheader();
	$phrase = vB_Api::instanceInternal('phrase')->renderPhrases(array('redirect' => $phrase));
	$message = $phrase['phrases']['redirect'];

	//Copied from the standard_redirect function.  Much of this is old, old code to avoid xss problems.
	//Some of it due to the fact that, unlike now the url could be sourced from user data.  Not
	//sure why the standard html escape is inadequate (or if it even is) but I don't want to change
	//and risk weird bugs/security problems.
	static
		$str_find     = array('"',      '<',    '>'),
		$str_replace  = array('&quot;', '&lt;', '&gt;');

	$url = str_replace(chr(0), '', $url);
	$url = str_replace($str_find, $str_replace, $url);
	$js_url = addslashes_js($url, '"'); // " has been replaced by &quot;

	$url = preg_replace(
		array('/&#0*59;?/', '/&#x0*3B;?/i', '#;#'),
		'%3B',
		$url
	);
	$url = preg_replace('#&amp%3B#i', '&amp;', $url);

	define('NOPMPOPUP', 1); // No footer here

	//postvars isn't used here (and actually anywhere in the current code)
	//but it's in the template and until it's removed we should set it.
	$page = array();
	$templater = new vB5_Template('STANDARD_REDIRECT');
		$templater->registerGlobal('page', $page);
		$templater->register('errormessage', $message);
		$templater->register('formfile', $url);
		$templater->register('js_url', $js_url);
		$templater->register('postvars', '');
		$templater->register('url', $url);
	$text = $templater->render();
	print_output($preheader . $text);
	exit;
}

function showError($title, $message)
{
	bootstrapFrontend();
	vB5_ApplicationAbstract::showMsgPage($title, $message);
	exit;
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101078 $
|| #######################################################################
\*=========================================================================*/
