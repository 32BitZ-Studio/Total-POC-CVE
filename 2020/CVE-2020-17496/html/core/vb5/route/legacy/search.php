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

class vB5_Route_Legacy_Search extends vB5_Route_Legacy
{
	protected $prefix = 'search.php';

	protected function getNewRouteInfo()
	{
		$param = & $this->queryParameters;
		$search = array();
		// pull the parameter that still compatible with vb5 and discard others
		if (isset($param['userid']))
		{
			$user = vB_User::fetchUserinfo($param['userid']);
			if ($user !== false)
			{
				$search['author'] = $user['username'];
			}
		}
		if (isset($param['starteronly']))
		{
			$search['starter_only'] = $param['starteronly'];
		}
		if (isset($param['forumchoice']))
		{
			$oldcontenttypeid = vB_Types::instance()->getContentTypeID(array('package' => 'vBForum', 'class' =>'Forum'));
			foreach ($param['forumchoice'] as $oldid)
			{
				$node = vB::getDbAssertor()->getRow('vBForum:node', array(
					'oldid' => $oldid,
					'oldcontenttypeid' => $oldcontenttypeid
				));
				$search['channel'][] = $node['nodeid'];
			}
		}
		if (isset($param['do']))
		{
			switch ($param['do'])
			{
			case 'finduser':
				if (!empty($search))
				{
					$searchJSON = json_encode($search);
				}
				break;
			case 'getdaily':
			case 'getnew':
				$searchJSON = '{"date":"lastVisit","view":"topic","unread_only":1,"sort":{"lastcontent":"desc"},"exclude_type":["vBForum_PrivateMessage"]}';
				break;
			default:
			}
		}
		$param = array();
		if (!empty($searchJSON))
		{
			$param['searchJSON'] = $searchJSON;
		}
		return 'search';
	}
	
	public function getRedirect301()
	{
		$data = $this->getNewRouteInfo();
		return $data;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
