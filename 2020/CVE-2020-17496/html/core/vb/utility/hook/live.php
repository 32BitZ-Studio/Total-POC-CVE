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

/**
 *	@package vBUtility
 */

/**
 *	@package vBUtility
 */
class vB_Utility_Hook_Live
{
	use vB_Utility_Trait_NoSerialize;

	private $hook_classes = array();
	private $active_hooks = array();

	public function __construct($hook_classes)
	{
		$this->hook_classes = $this->sortHooks($hook_classes);
	}

	public function invoke($hook_name, $params)
	{
		if (isset($this->active_hooks[$hook_name]))
		{
			return;
		}

		$this->active_hooks[$hook_name] = true;

		foreach($this->hook_classes AS $hook_class)
		{
			// We use method_exists instead of is_callable for a couple of reasons.
			//
			// First is_callable will return true for classes that have __call (and
			// presubable __callStatic) defined.  Which will lead to a lot of
			// unnecesary overhead if somebody hands us such a class.
			//
			// Second is_callable will not test whether or not the method is static
			// or not, so just because its true doesn't mean it's 100% safe to call
			//
			// Third it avoids the overhead of creating an array to pass to is_callable.
			//
			// We'll have to rely on hook coders not to do something insanely stupid
			if (method_exists($hook_class, $hook_name))
			{
				$hook_class::{$hook_name}($params);
			}
		}

		unset($this->active_hooks[$hook_name]);
	}


	/**
	 *	Sort the hook classes according to their order variable.
	 *
	 *	This is necesary because the PHP interal sorts are not stable.
	 *	Hooks with the same order are going to be *common* (in fact we
	 *	have a special case for when they are all the same as that's
	 *	the most likely case).  While we don't particularly care what
	 *	order hook classes with the same order end up in, we do care
	 *	that they are consistant between page loads (it does not
	 *	appear to be a problem with the current PHP implementation, but
	 *	some QuickSort implementations like to permute the array first)
	 *	and between versions of PHP.  I'm not sufficient confident in
	 *	the latter going forward to rely on it.  Not that we do use
	 *	ksort, but the keys of the array are guarenteed to be unique.
	 */
	private function sortHooks($hook_classes)
	{
		$hook_orders = array();
		foreach($hook_classes AS $hook_class)
		{
			if (class_exists($hook_class))
			{
				$order = isset($hook_class::$order) ? $hook_class::$order : 10;
				$hook_orders[$order][] = $hook_class;
			}
		}
		ksort($hook_orders);

		$new_hook_classes = array();
		foreach($hook_orders AS $order)
		{
			foreach($order AS $class)
			{
				$new_hook_classes[] = $class;
			}
		}

		return $new_hook_classes;
	}
}
/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102681 $
|| #######################################################################
\*=========================================================================*/
