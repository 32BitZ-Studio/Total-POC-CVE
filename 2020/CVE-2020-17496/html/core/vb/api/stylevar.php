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
 * vB_Api_Stylevar
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Stylevar extends vB_Api
{
	private static $cssMappings = array(
		// Background Stylevars
		"profcustom_navbar_background_active" => 'bgimage',
		"profcustom_navbar_background" => 'bgimage',
		"profcustom_navbarbutton_background" => 'bgimage',
		"profile_button_secondary_background" => 'bgimage',
		"toolbar_background" => 'bgimage',
		"profile_content_background" => 'bgimage',
		"profile_section_background" => 'bgimage',
		"profilesidebar_button_background" => 'bgimage',
		"side_nav_background" => 'bgimage',
		"profile_button_primary_background" => 'bgimage',

		// Border
		"profcustom_navbar_border_active" => 'borders',
		"profcustom_navbar_border" => 'borders',
		"profcustom_navbarbutton_border" => 'borders',
		"side_nav_divider_border" => 'borders',
		"profcustom_navbarbuttonsecondary_border" => 'borders',
		"profile_content_border" => 'borders',
		"profile_content_divider_border" => 'borders',
		"profile_section_border" => 'borders',
		"form_dropdown_border" => 'borders',
		"side_nav_avatar_border" => 'borders',
		"side_nav_divider_border" => 'borders',
		"profilesidebar_button_border" => 'borders',
		"button_primary_border" => 'borders',

		// Color
		"profcustom_navbar_text_color_active" => 'colors',
		"profcustom_navbar_text_color" => 'colors',
		"profcustom_navbar_toolbar_text_color" => 'colors',
		"profile_section_text_color" =>  'colors',
		"profcustom_navbarbutton_color" =>  'colors',
		"profcustom_navbarbuttonsecondary_color" => 'colors',
		"profile_content_primarytext" =>  'colors',
		"profile_content_secondarytext" =>  'colors',
		"profile_content_linktext" =>  'colors',
		"profile_userpanel_textcolor" =>  'colors',
		"profile_userpanel_linkcolor" =>  'colors',
		"profilesidebar_button_text_color" =>  'colors',
		"button_primary_text_color" =>  'colors',

		// Font family
		"profile_section_font" => 'fontfamily',
		"profile_content_font" => 'fontfamily',
		"profile_userpanel_font" => 'fontfamily',
	);

	/**
	 * Saves the stylevars specified in the array for the current user
	 *
	 * @param array $stylevars - associative array like array('activity_stream_avatar_border_color' => array('color' => '#123456'))
	 */
	public function save($stylevars)
	{
		$result = array();

		$userid = vB::getCurrentSession()->get('userid');

		if (empty($userid))
		{
			//this is a wierd error to throw here.
			throw new vB_Exception_Api('logged_out_while_editing_post');
		}

		if (!$this->hasPermissions())
		{
			throw new vB_Exception_Api('no_permission');
		}

		$userContext = vB::getUserContext();

		//we really only need these for the type -- but there's not a lot of
		//point to writing a custom query for this
		$stylevardata = $this->fetch(array_keys($stylevars));
		$values = array();
		$now = vB::getRequest()->getTimeNow();
		foreach ($stylevars AS $stylevarname => $stylevarvalue)
		{
			$permType = self::$cssMappings[$stylevarname] ?? false;
			$canEdit = false;
			if ($permType)
			{
				if ($permType == 'fontfamily')
				{
					foreach ($stylevarvalue AS $key => $val)
					{
						//this implicity rejects all of the components of the font type *except* fontfamily and size
						//unless the user is a super admin.  The former isn't a huge problem since those are the
						//only ones we currently have UI for.  The latter is weird but isn't likely to cause problems
						//in practice.  Requesting a permission check on an nonexistant permission isn't a huge
						//problem.  Poking this is likely to cause more harm than good.
						if (!$userContext->hasPermission('usercsspermissions', 'caneditfont' . $key))
						{
							unset($stylevarvalue[$key]);
						}
					}

					$canEdit = true;
				}
				else if ($userContext->hasPermission('usercsspermissions', 'canedit' . $permType))
				{
					$canEdit = true;
				}

				//don't validate if we already decided not to save it.
				if($canEdit)
				{
					//a bit of a hack.  The DM's will save to the main table which we don't want,
					//but setting the values will implicity invoke the validation logic.  Which we do.
					$class ='vB_DataManager_StyleVar' . $stylevardata[$stylevarname]['datatype'];
					$svinstance = new $class(vB_DataManager_Constants::ERRTYPE_SILENT);


					foreach ($stylevarvalue AS $key => $val)
					{
						//we might want to throw an error if we get "extra" stuff but
						//1) The profile customization code that uses this is sloppy and cleaning it up
						//	is probably beyond the scope of the current work
						//2) It's useful to be a little flexible with the public API functions so that
						//	minor scripting errors don't break everything.
						//3) The extra fields are harmless if we don't actually save them.
						if($svinstance->is_child_field($key))
						{
							if(!$svinstance->set_child($key, $val))
							{
								throw new vB_Exception_Api('invalid_stylevar_value', array($stylevarname, $key));
							}

							//the verification/cleaning process may have changed the value to something
							//valid if it didn't start out that way.  Let's make sure we get the valid value.
							$stylevarvalue[$key] = $svinstance->get_child($key);
						}
						else
						{
							unset($stylevarvalue[$key]);
						}
					}

					$values[] = array(
						'stylevarid' => $stylevarname,
						'userid' => $userid,
						'value' => serialize($stylevarvalue),
						'dateline' => $now
					);
				}
			}
		}

		vB::getDbAssertor()->assertQuery('replaceValues', array('table' => 'userstylevar', 'values' => $values));
		vB_Library::instance('Style')->setCssDate();

		return $result;
	}

	/**
	 * Saves the stylevars specified in the array as default style for the whole site
	 *
	 * @param array $stylevars - associative array
	 */
	public function save_default($stylevars)
	{
		$result = array();

		if (!$this->canSaveDefault())
		{
			throw new vB_Exception_Api('no_permission_styles');
		}

		//not sure that this makes any sense.  If we have admin privs we should probably
		//be able to save the defaults even if we don't have customize profile privs.
		//However it's not likely to come up
		if (!$this->hasPermissions())
		{
			throw new vB_Exception_Api('no_permission');
		}

		$values = array();
		$now = vB::getRequest()->getTimeNow();

		$styleid = vB::getDatastore()->getOption('styleid');

		foreach ($stylevars as $stylevarname => $stylevarvalue)
		{
			$values[] = array(
				'stylevarid' => $stylevarname,
				'styleid' => $styleid,
				'value' => serialize($stylevarvalue),
				'dateline' => $now
			);
		}
		vB::getDbAssertor()->assertQuery('replaceValues', array('table' => 'stylevar', 'values' => $values));

		$style_lib = vB_Library::instance('Style');
		$style_lib->buildStyleDatastore();

		require_once(DIR . '/includes/adminfunctions_template.php');
		$style_lib->buildStyle($styleid, '', array('docss' => 1, 'dostylevars' => 1,), true);

		vB_Library::instance('Style')->setCssDate();
		return $result;
	}

	/**
	 * Deletes the listed stylevars for the current user
	 * Pass false to delete all the stylevars for the current user
	 * @param array|false $stylevars - list of stylevar names to delete
	 */
	public function delete($stylevars = array())
	{
		$userid = vB::getCurrentSession()->get('userid');
		if (empty($userid))
		{
			//should this be an error?
			return;
		}

		$options = array(
			array('field'=>'userid', 'value' => $userid, vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ)
		);

		if (!empty($stylevars))
		{
			$stylevars = array_combine($stylevars, $stylevars);
			$options[] = array('field'=>'stylevarid', 'value' => $stylevars, vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ);
		}

		vB::getDbAssertor()->delete('userstylevar', $options);

		vB_Library::instance('Style')->setCssDate();

		return array('success' => true);
	}

	/**
	 * Fetches the value of the stylevar for the user $userid
	 * Pass 0 for userid to retrieve the stylevar for the current user
	 * If the stylevar is not customized for the specified user, the value from the default stylevar will be returned
	 * Pass false for $falback to limit the results to the custom stylevar only
	 *
	 * WARNING: This returns the value as stored in the stylevar. If the stylevar inherits from
	 * another stylevar, it *WILL NOT* return the final, rendered, inherited value that should be used
	 * for display. To get the final, inherited value that should be used, use the template
	 * runtime fetchStyleVar or fetchCustomStylevar methods, which resolve inheritance.
	 *
	 * @param string $stylevar
	 * @param int $userid
	 * @param bool $fallback
	 * @param int $styleid
	 *
	 * @return array valid key should be the value of the $stylevars
	 */
	public function get($stylevarname, $userid = 0, $fallback = true, $styleid = 0)
	{
		if (empty($userid))
		{
			$userid = vB::getCurrentSession()->get('userid');
		}

		if (empty($userid))
		{
			return array();
		}

		$default_stylevars = array();
		if ($fallback)
		{
			$styleid = (int) $styleid;

			if ($styleid < 1)
			{
				$styleid = vB::getDatastore()->getOption('styleid');
			}

			if ($styleid > 0)
			{
				$parentlist = vB_Library::instance('style')->fetchTemplateParentlist($styleid);
				$parentlist = explode(',',trim($parentlist));
			}
			else
			{
				$parentlist = array('-1');
			}

			$default_stylevars_res = vB::getDbAssertor()->getRow('fetchStylevarsArray', array(
				'parentlist' => $parentlist,
				'stylevars' => array($stylevarname),
				'sortdir' => vB_dB_Query::SORT_DESC,
			));

			if (!empty($default_stylevars_res))
			{
				$default_stylevars = unserialize($default_stylevars_res['value']);
				$default_stylevars['datatype'] = $default_stylevars_res['datatype'];
			}
		}

		$userstylevar_res = vB::getDbAssertor()->getRow('userstylevar', array(
			'stylevarid' => $stylevarname,
			'userid' => $userid,
		));

		if (!empty($userstylevar_res))
		{
			$userstylevar = unserialize($userstylevar_res['value']);
			// We don't store the datatype in userstylevar, so we can't
			// add it like we do above for the default/root stylevar.
			// In any case, it's not needed, since we willuse the datatype
			// from the default/root stylevar.
		}
		else
		{
			$userstylevar = array();
		}

		return array($stylevarname => array_merge($default_stylevars, $userstylevar));
	}

	/**
	 * Fetches the stylevar values for the user $userid
	 * Pass false for $stylevars to get all the stylevars
	 * Pass 0 for userid to retrieve the stylevar for the current user
	 * Returns an associative array with keys being the list specified in the $stylevar
	 * If any of the stylevars is not customized for the specified user, the value from the default stylevar will be returned instead
	 * Pass false for $falback to limit the results to the custom stylevars only
	 *
	 * WARNING: This returns the value as stored in the stylevar. If the stylevar inherits from
	 * another stylevar, it *WILL NOT* return the final, rendered, inherited value that should be used
	 * for display. To get the final, inherited value that should be used, use the template
	 * runtime fetchStyleVar or fetchCustomStylevar methods, which resolve inheritance.
	 *
	 * @param array|false $stylevars
	 * @param int $userid
	 * @param bool $fallback
	 * @return array
	 */
	public function fetch($stylevars = array(), $userid = 0, $fallback = true)
	{
		if (empty($userid))
		{
			$userid = vB::getCurrentSession()->get('userid');
		}

		if (empty($userid))
		{
			return;
		}

		$db = vB::getDbAssertor();

		$stylevar_values = array();
		$conditions = array();
		$conditions['userid'] = $userid;

		$need_all = empty($stylevars);
		if (!$need_all)
		{
			$stylevars = array_combine($stylevars, $stylevars);
			$conditions['stylevarid'] = $stylevars;
		}
		else
		{
			$stylevars = array();
		}

		if ($fallback)
		{
			$styleid = vB::getDatastore()->getOption('styleid');
			if ($styleid > 0)
			{
				$parentlist = vB_Library::instance('style')->fetchTemplateParentlist($styleid);
				$parentlist = explode(',',trim($parentlist));
			}
			else
			{
				$parentlist = array('-1');
			}

			$default_stylevar_res = $db->assertQuery('fetchStylevarsArray', array('parentlist' => $parentlist, 'stylevars' => $stylevars));
			foreach ($default_stylevar_res AS $default_stylevar)
			{
				$stylevar_values[$default_stylevar['stylevarid']] = unserialize($default_stylevar['value']);
				$stylevar_values[$default_stylevar['stylevarid']]['datatype'] = $default_stylevar['datatype'];
			}
		}
		$userstylevar_res = $db->assertQuery('userstylevar', array(vB_dB_Query::CONDITIONS_KEY=> $conditions));

		foreach ($userstylevar_res as $stylevar)
		{
			$custom_stylevar = unserialize($stylevar['value']);
			if (!empty($stylevar_values[$stylevar['stylevarid']]))
			{
				$custom_stylevar = array_merge($stylevar_values[$stylevar['stylevarid']], $custom_stylevar);
			}

			$stylevar_values[$stylevar['stylevarid']] = $custom_stylevar;
		}

		return $stylevar_values;
	}

	public function fetch_default_stylevar($stylevars = array(), $styleid = false)
	{
		$stylevar_values = array();
		if (empty($styleid))
		{
			$styleid = vB::getDatastore()->getOption('styleid');
		}
		if ($styleid > 0)
		{
			$parentlist = vB_Library::instance('style')->fetchTemplateParentlist($styleid);
			$parentlist = explode(',',trim($parentlist));
		}
		else
		{
			$parentlist = array('-1');
		}
		$need_all = empty($stylevars);
		$default_stylevar_res = vB::getDbAssertor()->assertQuery('fetchStylevarsArray', array('parentlist' => $parentlist, 'stylevars' => $need_all ? array() : $stylevars));
		foreach ($default_stylevar_res as $default_stylevar)
		{
			$stylevar_values[$default_stylevar['stylevarid']] = unserialize($default_stylevar['value']);
			$stylevar_values[$default_stylevar['stylevarid']]['datatype'] = $default_stylevar['datatype'];
		}

		return $stylevar_values;
	}

	/**
	 * Fetches the stylevar values for the user $userid
	 * @param int $userid
	 * @return array
	 */
	public function fetch_user_stylevars($userid = 0)
	{
		if (empty($userid))
		{
			$userid = vB::getCurrentSession()->get('userid');
		}

		if (empty($userid))
		{
			return;
		}

		$conditions = array(
			array('field'=>'userid', 'value' => $userid, vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ)
		);

		$userstylevar_res = vB::getDbAssertor()->assertQuery('userstylevar', array(vB_dB_Query::CONDITIONS_KEY=> $conditions));
		$stylevar_values = array();

		foreach ($userstylevar_res AS $stylevar)
		{
			$stylevar_values[$stylevar['stylevarid']] = unserialize($stylevar['value']);
			//The 'datatype' field doesn't exist in the userstylevar table.  It's also not used by the caller (which is
			//good because it will never be set to anything useful) but can cause notices.
//			$stylevar_values[$stylevar['stylevarid']]['datatype'] = $stylevar['datatype'];
		}

		return (!empty($stylevar_values) ? $stylevar_values : array());
	}

	/**
	 * Check whether the profile page of an user is customized
	 *
	 * @param $userid User ID
	 * @return bool
	 */
	public function isProfileCustomized($userid = 0)
	{
		if (empty($userid))
		{
			$userid = vB::getCurrentSession()->get('userid');
		}

		if (empty($userid))
		{
			return false;
		}

		$count = vB::getDbAssertor()->getField('userstylevarCount', array('userid' => $userid));

		if ($count > 0)
		{
			return true;
		}

		return false;
	}

	/**
	 * This is just a public method for calling the hasPermissions method
	 */
	public function canCustomizeProfile()
	{
		return $this->hasPermissions();
	}

	/**
	 * Checkes if the current loged user has admin permisions
	 * for administration of styles
	 *
	 * @return boolean
	 */
	public function canSaveDefault()
	{
		return vB::getUserContext()->hasAdminPermission('canadminstyles');
	}

	/**
	 * Returns all the permissions that the currently logged user
	 * has for customizing profile
	 *
	 * @return array
	 */
	public function fetchCustomizationPermissions()
	{
		$permissions = array(
			'fontFamily' => 0,
			'fontSize'	 => 0,
			'colors'	 => 0,
			'bgimage'	 => 0,
			'borders'	 => 0,
		);

		if (!vB::getCurrentSession()->get('userid'))
		{
			return $permissions;
		}

		$permissions['fontFamily'] = vB::getUserContext()->hasPermission('usercsspermissions', 'caneditfontfamily');
		$permissions['fontSize']   = vB::getUserContext()->hasPermission('usercsspermissions', 'caneditfontsize');
		$permissions['colors'] 	= vB::getUserContext()->hasPermission('usercsspermissions', 'caneditcolors');
		$permissions['bgimage'] = vB::getUserContext()->hasPermission('usercsspermissions', 'caneditbgimage');
		$permissions['borders'] = vB::getUserContext()->hasPermission('usercsspermissions', 'caneditborders');

		return $permissions;
	}

	/**
	 * Checks if the currently logged user has permissions
	 * for profile style customization
	 *
	 *	@return boolean
	 */
	private function hasPermissions()
	{
		// Guest ...
		if (!vB::getCurrentSession()->get('userid'))
		{
			return false;
		}

		$usercontext = vB::getUserContext();
		$options = vB::getDatastore()->getValue('options');

		$enabled = $options['enable_profile_styling'];
		$cancustomize = $usercontext->hasPermission('usercsspermissions', 'cancustomize');

		if ($enabled AND $cancustomize)
		{
			return true;
		}

		return false;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102325 $
|| #######################################################################
\*=========================================================================*/
