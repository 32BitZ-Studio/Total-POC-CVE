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
 * vB_Api_ContentType
 *
 * @package vBApi
 * @access public
 */
class vB_Api_ContentType extends vB_Api
{
	// todo: replace all references to this value with constants
	const OLDTYPE_BLOGCHANNEL = 9973;
	const OLDTYPE_BLOGSTARTER = 9972;
	const OLDTYPE_BLOGRESPONSE = 9984;              // oldcontenttype restored back to pre502a2
	const OLDTYPE_BLOGRESPONSE_502a2 = 9971;        // oldid was changed, incorrectly, in a now-removed 502a2 upgrade step.
	// previous oldcontenttypeid's for blogs, before 502a2 updated the oldid's
	const OLDTYPE_BLOGCHANNEL_PRE502a2 = 9999;      // ref class_upgrade_500a22 step 1
	const OLDTYPE_BLOGSTARTER_PRE502a2 = 9985;      // ref class_upgrade_500a22 step 2
	const OLDTYPE_BLOGRESPONSE_PRE502a2 = 9984;     // ref class_upgrade_500a22 step 3

	// orphan infractions
	const OLDTYPE_ORPHAN_INFRACTION_THREAD = 9979;  // ref class_upgrade_501a2 step_22
	const OLDTYPE_ORPHAN_INFRACTION_POST = 9978;    // ref class_upgrade_501a2 step_23
	const OLDTYPE_ORPHAN_INFRACTION_PROFILE = 9977; // ref class_upgrade_501a2 step_24

	// attachments / photos
	const OLDTYPE_SGPHOTO = 9987;                   // ref importSGPhotoNodes class_upgrade_500a29 step_9
	const OLDTYPE_PHOTO = 9986;                     // ref class_upgrade_500a28 step_18
	const OLDTYPE_SGGALLERY = 9983;                 // ref importSGPhotoNodes class_upgrade_503a3 step_11

	const OLDTYPE_THREADATTACHMENT = 9982;
	const OLDTYPE_POSTATTACHMENT = 9990;
	const OLDTYPE_BLOGATTACHMENT = 9974;
	const OLDTYPE_ARTICLEATTACHMENT = 9968;         // CMS Article attachments

	// Private Messages
	const OLDTYPE_PMSTARTER = 9989;
	const OLDTYPE_PMRESPONSE = 9981;

	// Polls
	const OLDTYPE_POLL = 9011;                      // ref fixNodeidInPolloption class_upgrade_503rc1 step_1

	// CMS Articles (Home, Sections, Articles, Categories, Tags)
	const OLDTYPE_CMS_SECTION = 9970;               // in vB5, they're imported as channels and called Categories
	const OLDTYPE_CMS_ARTICLE = 9969;
	// 9968 is article attachments, see above
	const OLDTYPE_CMS_COMMENT = 9967;
	const OLDTYPE_CMS_STATICPAGE = 9966;            // static HTML pages, same level as articles
	// Categories will be imported into vB5 as Tags.

	/**
	 * Constructor
	 */
	protected function __construct()
	{
		parent::__construct();
	}

	/**
	 * Returns the integer content type id for the given content type class name
	 *
	 * @param	string	Content Type Class Name
	 * @param	string	Package Name
	 *
	 * @return	int	Content Type ID
	 */
	public function fetchContentTypeIdFromClass($class, $package = 'vBForum')
	{
		$contenttypeid = vB_Types::instance()->getContentTypeId($package . '_' . $class);
		return $contenttypeid ? $contenttypeid : 0;
	}

	/**
	 * Returns the class name for for the given content type id
	 *
	 * @param	int	Content Type ID
	 *
	 * @return	string	Content Type Class Name
	 */
	public function fetchContentTypeClassFromId($contenttypeid)
	{
		return vB_Types::instance()->getContentTypeClass($contenttypeid);
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
