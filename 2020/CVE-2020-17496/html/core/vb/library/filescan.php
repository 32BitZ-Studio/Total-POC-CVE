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
 * vB_Library_Filescan
 *
 * @package vBLibrary
 * @access public
 */

class vB_Library_Filescan extends vB_Library
{
	protected $enabled_instances = null;
	protected $initErrors = array();


	/**
	 * Constructor
	 *
	 */
	protected function __construct()
	{
		$this->initializeInstances();
	}

	private function initializeInstances()
	{
		if (!is_null($this->enabled_instances))
		{
			return;
		}
		$this->enabled_instances = array();

		$options = vB::getDatastore()->getValue('options');
		if (!empty($options['enabled_scanner']))
		{
			$options['enabled_scanner'] = json_decode($options['enabled_scanner'], true);
			if (!is_array($options['enabled_scanner']))
			{
				$options['enabled_scanner'] = array();
			}
			$this->enabled_instances = $this->doInitInstances($options['enabled_scanner']);
		}
	}

	private function doInitInstances($scanners)
	{
		$enabled_instances = array();
		$this->initErrors = array();
		$vboptions = vB::getDatastore()->getValue('options');

		// tag usually looks like {productid}:{implementation}
		foreach ($scanners AS $tag => $enabled)
		{
			if ($enabled)
			{
				$tag = strtolower($tag);
				try
				{
					$class = vB::getVbClassName($tag, 'Utility_Filescanner', 'vB_Utility_Filescanner');
					$instance = new $class($vboptions);
					if ($instance->isEnabled())
					{
						$enabled_instances[$tag] = $instance;
					}
					$errors = $instance->fetchErrors();
					if (!empty($errors))
					{
						$this->initErrors = array_merge($this->initErrors, $errors);
					}
				}
				catch(Throwable $e)
				{
					// Ideally we wouldn't get here and the implementation will catch its own errors & wrap it into an
					// "identifiable" message when multiple scanners are enabled.
					$this->initErrors[] = $e->getMessage();
				}
			}
		}

		return $enabled_instances;
	}

	public function validateEnabledScanners($scanners)
	{
		$this->doInitInstances($scanners);
		/*
			todo: also do a test file scan?
			$testfile = ''; // e.g. our sample PDF file
			foreach ($this->enabled_instances AS $scanner)
			{
				$scanner->clearErrors();
				$scanner->scanFile($testfile);
				$errors = $scanner->fetchErrors();
				if (!empty($errors))
				{
					$this->initErrors = array_merge($this->initErrors, $errors);
				}
			}
		 */

		return $this->initErrors;
	}

	public function scanFile($filename)
	{
		$filename = realpath($filename);
		foreach ($this->enabled_instances AS $scanner)
		{
			if (!$scanner->scanFile($filename))
			{
				return false;
			}
		}

		return true;

	}


}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102624 $
|| #######################################################################
\*=========================================================================*/
