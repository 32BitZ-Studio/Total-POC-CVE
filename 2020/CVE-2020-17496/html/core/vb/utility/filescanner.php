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
 * vB_Utility_Filescanner
 *
 * @package vBulletin
 */
abstract class vB_Utility_Filescanner
{
	use vB_Utility_Trait_NoSerialize;

	protected $enabled = false;
	protected $errors = array();

	final public function __construct($vboptions)
	{
		$this->enabled = $this->checkDependencies($vboptions);
		if ($this->enabled)
		{
			$this->initialize($vboptions);
		}
	}

	final public function isEnabled()
	{
		return (bool) $this->enabled;
	}

	final public function fetchErrors()
	{
		return $this->errors;
	}

	final public function clearErrors()
	{
		$this->errors = array();
	}

	/**
	 * Do any initialization or post-checkDependencies() checks here. This will only
	 * run if checkDependencies() returned true.
	 *
	 * @param array $vboptions   Array of vBulletin options passed from the constructor
	 */
	protected function initialize($vboptions)
	{
		/*
			Perform any necessary init here, e.g. instancing dependency classes.
			Note that you can also catch any dependency errors and skip scanning via this
			implementation by setting $this->enabled = false; as necessary.
			If initialization had any errors, add error phrases like
			$this->errors[] = {error_phrase};
			so that "Enabled Scanners" setting validation can report them.
		 */
	}

	/**
	 * Check for dependencies during startup. Note that this will be called on every
	 * every upload (if product/implementation is enabled), and thus may slow down
	 * upload requests if the checks are slow/resource-intensive.
	 * Result of this function will initially control $this->enabled, but enabled
	 * value can be overriden in the extending class's initialize() function.
	 *
	 * @param array $vboptions   Array of vBulletin options passed from the constructor
	 *
	 * @return bool -- True if all (detectable) dependencies were found/installed.
	 */
	protected function checkDependencies($vboptions)
	{
		/*
			You can add any dependency errors into the error array like
			$this->errors[] = {error_phrase};
			so that "Enabled Scanners" setting validation can report them.

			Simply return true if there are no particular dependencies to check.
		 */
		return true;
	}

	/**
	 * Scan a file for malware
	 *
	 * @param string $filename -- Filename to scan
	 * @return bool -- True if scan passed.
	 */
	abstract protected function scanFile($filename);
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102624 $
|| #######################################################################
\*=========================================================================*/
