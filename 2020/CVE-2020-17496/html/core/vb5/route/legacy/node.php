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
 * handle redirects for nodes
 * that have an 'oldid' and 'oldcontenttypeid'
 */
abstract class vB5_Route_Legacy_Node extends vB5_Route_Legacy
{
	/**
	 * the key('t') for id parameter
	 * showthread.php?t=1
	 * @var array
	 */
	protected $idkey = array();
	
	/**
	 * old node contenttypeid after import
	 */
	protected $oldcontenttypeid;
	
	public function __construct($routeInfo = array(), $matches = array(), $queryString = '')
	{
		if (!empty($routeInfo))
		{
			parent::__construct($routeInfo, $matches, $queryString);
		}
		else
		{
			$this->arguments = array('oldid' => '$oldid');
		}
	}
	
	/**
	 * get the actual node after captured old id
	 * set route arguments for building new URL
	 * return new routeid
	 */
	protected function getNewRouteInfo()
	{
		$oldid = $this->captureOldId();
		$node = vB::getDbAssertor()->getRow('vBForum:node', array(
			'oldid' => $oldid,
			'oldcontenttypeid' => $this->oldcontenttypeid
		));
		
		if (empty($node))
		{
			throw new vB_Exception_404('invalid_page');
		}
		
		$this->arguments['nodeid'] = $node['nodeid'];
		return $node['routeid'];
	}
	
	/**
	 * try to get oldid by matching in order of advanced, basic, standard friendly URL pattern in vb4
	 */
	protected function captureOldId()
	{
		$argument = & $this->arguments;
		$param = & $this->queryParameters;
		$keys = array_keys($param);
		if (intval($argument['oldid']))
		{
			$oldid = $argument['oldid'];
		}
		else if (!empty($param) AND preg_match('#^(?P<oldid>[1-9]\d*)(?P<title>(?:-[^?&]*)*)#', $keys[0], $matches))
		{
			$oldid = $matches['oldid'];
		}
		else if ($set=array_intersect($keys, $this->idkey) AND $pid=intval($param[reset($set)]))
		{
			$oldid = $pid;
		}
		else
		{
			throw new vB_Exception_404('invalid_page');
		}
		return $oldid;
	}
	
	public function getRedirect301()
	{
		$data = $this->getNewRouteInfo();
		$this->queryParameters = array();
		return $data;
	}

	/**
	 * Matches:
	 * standard URL, showthread.php?t=1
	 * basic URL, showthread.php?1-title
	 * advanced URL, showthread.php/1-title
	 */
	public function getRegex()
	{
		return $this->prefix . '(?:/(?P<oldid>[1-9]\d*)(?P<title>(?:-[^?&]*)*))?';
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
