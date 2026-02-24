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

//@TODO -- Remove this controller. The two methods here should be template
// helper functions of some sort. They aren't controller methods.

class vB5_Frontend_Controller_Permission extends vB5_Frontend_Controller
{
	/**
	 * Compare two arrays, and merge any non-zero values of the second into the first. Must be string => integer members
	 *
	 * @param		mixed	array of $string => integer values
	 * @param		mixed	array of $string => integer values
	 * @return		mixed	array of $string => integer values
	 */
	public function actionMergePerms($currPerms = array(), $addPerms = array())
	{
		// this is called from the templates via {vb:action}
		// but since the method name starts with 'action', it *is*
		// accessible externally via <site>/permission/merge-perms,
		// however, since it's not reading any user input from the
		// superglobals, it won't do anything.

		if (is_array($currPerms) AND is_array($addPerms))
		{
			foreach($addPerms AS $permName => $permValue)
			{
				if (is_string($permName) AND (is_numeric($permValue) OR is_bool($permValue)) AND empty($currPerms[$permName]) AND ($permValue > 0))
				{
					$currPerms[$permName] = $permValue;
				}
			}
		}

		return $currPerms;
	}

	/**
	 * Decide if the inlinemod menu should be shown
	 *
	 *	@param		array
	 *	@param		array
	 *	@param		array
	 *	@return		bool
	 */
	public function showInlinemodMenu($conversation = array(), $modPerms = array(), $options = array())
	{
		// this is called from the templates via {vb:action}
		// since the method name doesn't start with 'action'
		// it's not even accessible externally. Which leads
		// to the question of why it's even a controller method....

		// It was already decided not to show the inlinemod menu
		if (isset($options['showInlineMod']) AND !$options['showInlineMod'])
		{
			return false;
		}

		if (is_array($conversation) AND !empty($conversation))
		{
			if (
				!empty($conversation['permissions']) AND
				(
					!empty($conversation['permissions']['canmoderate']) OR
					!empty($conversation['moderatorperms']['canmoderateposts']) OR
					!empty($conversation['moderatorperms']['candeleteposts']) OR
					!empty($conversation['moderatorperms']['caneditposts']) OR
					!empty($conversation['moderatorperms']['canopenclose']) OR
					!empty($conversation['moderatorperms']['canmassmove']) OR
					!empty($conversation['moderatorperms']['canremoveposts']) OR
					!empty($conversation['moderatorperms']['cansetfeatured']) OR
					!empty($conversation['moderatorperms']['canmanagethreads']) OR
					!empty($conversation['moderatorperms']['canharddeleteposts'])
				)
			)
			{
				return true;
			}
		}

		// This is from the inlinemod_nemu
		$view = (isset($options['view']) ? $options['view'] : '');

		if (is_array($modPerms) AND !empty($modPerms))
		{
			if (
				($modPerms['canmove'] > 0) OR
				($modPerms['canopenclose'] > 0) OR
				($modPerms['candeleteposts'] > 0 AND $view == 'thread') OR
				($modPerms['canmoderateposts'] > 0) OR
				($modPerms['caneditposts'] > 0) OR
				($modPerms['candeletethread'] > 0) OR
				($modPerms['cansetfeatured'] > 0) OR
				($modPerms['canmoderateattachments'] > 0) OR
				($modPerms['canmassmove'] > 0) OR
				($modPerms['canannounce'] > 0) OR
				($modPerms['canremoveposts'] > 0) OR
				($modPerms['canundeleteposts'] > 0) OR
				($modPerms['canharddeleteposts'] > 0)
			)
			{
				return true;
			}
		}

		return false;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
