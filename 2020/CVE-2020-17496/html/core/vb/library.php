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
 * vB_Library
 *
 * @package vBForum
 * @access public
 */
class vB_Library
{
	use vB_Trait_NoSerialize;

	protected static $instance = array();

	protected function __construct()
	{

	}

	/**
	 * Returns singleton instance of self.
	 *
	 * @return vB_PageCache		- Reference to singleton instance of the cache handler
	 */
	public static function instance($class)
	{
		/*
			Class names are not case sensitive in PHP, but vars & array keys are.
			Make sure that we get a single instance of the requested class regardless of letter case.
		 */
		//$class = ucfirst(strtolower($class));
		//$className = 'vB_Library_' . $class;
		list($className, $package) = self::getLibraryClassNameInternal($class);
		if (!isset(self::$instance[$className]))
		{
			self::$instance[$className] = new $className();
		}

		return self::$instance[$className];
	}

	protected static function getLibraryClassNameInternal($controller)
	{
		/*
			Based on vB_Api::getApiClassNameInternal()
			Keep this in sync with vB_Api::getApiClassNameInternal()
		 */
		$values = explode(':', $controller);
		$package = '';
		if(count($values) == 1)
		{
			$c = 'vB_Library_' . ucfirst(strtolower($controller));
		}
		else
		{
			list($package, $controller) = $values;
			// todo: class names might have uppercases to help with readability, but
			// productid/package-name may be in lowercase.
			// Iff productid is always in lowercase this strtolower is OK to do,
			// but if we allow uppercases & allow case to define uniqueness of products,
			// this is NOT ok.
			// This is here to do stuff like call TwitterLogin:ExternalLogin API for the
			// twitterlogin package.
			$package = strtolower($package);
			$c = ucfirst($package) . '_Library_' . ucfirst(strtolower($controller));

			/*
				From vB_Api::getApiClass()
			 */
			$products = vB::getDatastore()->getValue('products');
			if(empty($products[$package]))
			{
				// todo: new phrase for library_class_... ?
				throw new vB_Exception_Api('api_class_product_x_is_disabled', array($controller, $package));
			}
		}

		return array($c, $package);
	}

	public static function getContentInstance($contenttypeid)
	{
		$contentType = vB_Types::instance()->getContentClassFromId($contenttypeid);
		$className = 'Content_' . $contentType['class'];

		return self::instance($className);
	}

	public static function clearCache()
	{
		self::$instance = array();
	}

	/**
	 * Checks if the text contains monitored words, and if so, sends
	 * notifications to admins and moderators if the setting is on.
	 *
	 * @param array|string String or array of strings containing the text to check
	 * @param string       The type (see the switch statement in the function)
	 * @param int          The Node ID (of the node where the text/title/tags/etc are being monitored)
	 * @param int          The User ID (of the user whose signature/title/username/etc is being monitored)
	 * @param bool         Whether or not to insert the notifications into the db now
	 * @param int          Current user id (user sending this notification)
	 */
	public function monitorWords($text, $type, $nodeid, $userid = null, $insertNotifications = true, $currentuserid = 0)
	{
		$monitoredWords = vB_String::getMonitoredWords($text);
		$notificationLib = vB_Library::instance('notification');

		if (!empty($monitoredWords))
		{
			if (!$currentuserid)
			{
				$currentuserid = vB::getCurrentSession()->get('userid');
			}

			$data = array();
			$event = '';

			list($mainType, $subType) = explode('-', $type, 2);

			switch ($mainType)
			{
				case 'node':
					$data['sentbynodeid'] = $nodeid;
					$data['sender'] = $currentuserid;
					$event = 'node-monitored-word-found';
					break;

				case 'user':
					$data['sender'] = $currentuserid;
					$event = 'user-monitored-word-found';
					break;

				default:
					break;
			}

			if (!empty($data))
			{
				$data['customdata'] = array(
					'maintype' => $mainType,
					'subtypes' => array($subType),
					'words' => $monitoredWords,
					'targetuserid' => $userid,
				);

				$notificationLib->triggerNotificationEvent($event, $data);
			}
		}

		if ($insertNotifications)
		{
			$notificationLib->insertNotificationsToDB();
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101969 $
|| #######################################################################
\*=========================================================================*/
