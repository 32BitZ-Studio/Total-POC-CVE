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
 * @package nativo
 */

/**
 * @package nativo
 */

class Nativo_Api_Nativo extends vB_Api
{
	public function meta()
	{
		$info = array();
		$db = vB::getDbAssertor();
		$options = vB::getDatastore()->getValue('options');

		$product = $db->getRow('product', array('productid' => 'nativo'));

		$info['enabled'] = $product['active'];
		$info['version'] = $product['version'];
		$info['vbversion'] = SIMPLE_VERSION;
		$info['vbfileversion'] = FILE_VERSION;
		$info['bbtitle'] = $options['bbtitle'];
		$info['remote_host'] = vB::getRequest()->getAltIp();

		return $info;
	}

	public function forums()
	{
		$config = vB::getConfig();
		if(!$config['Misc']['debug'])
		{
			if(!$this->isNativoIP(vB::getRequest()->getAltIp()))
			{
				throw new Exception('Invalid request IP address: ' . vB::getRequest()->getAltIp());
			}
		}

		$db = vB::getDbAssertor();
		$channelType = vB_Types::instance()->getContentTypeID('vBForum_Channel');
		$top = vB_Api::instanceInternal('content_channel')->fetchTopLevelChannelIds();

		$result = $db->assertQuery('vBForum:getDescendantChannelNodeIds',
			array(
				'parentnodeid' => $top['forum'],
				'channelType' => $channelType
			)
		);

		$channels = array();
		foreach($result AS $row)
		{
			$channels[] = $row['child'];
		}

		//we need all the channels, not just the ones that the user can see.
		$channels = vB_Library::instance('content_channel')->getFullContent($channels);
		$guestcontext = vB::getUserContext(0);

		$data = array();
		foreach($channels AS $channel)
		{
			if ($channel['canview'])
			{
				$item = array();
				$item['id'] = $channel['nodeid'];
				$item['name'] = $channel['title'];
				$item['description'] = $channel['description'];
				$item['parentId'] = $channel['parentid'];
				$item['acceptThreads'] = $channel['options']['cancontainthreads'];
				$item['private'] = ($guestcontext->getChannelPermission('forumpermissions', 'canview', $channel['nodeid']) ? 0 : 1);
				$item['displayorder'] = $channel['displayorder'];
				try
				{
					$item['url'] = vB5_Route::buildUrl($channel['routeid'] . '|fullurl', $channel);
				}
				catch(Exception $e)
				{
					$item['url'] = '';
				}

				$data[$channel['nodeid']] = $item;
			}
		}

		$children = array();
		foreach($data AS $key => $item)
		{
			$data[$key]['parentlist'] = $this->getParentList($data, $key);
			$children[$item['parentId']][] = $key;
		}

		foreach($data AS $key => $item)
		{
			$children[$key][] = $key;
			$data[$key]['childlist'] = implode(',', $children[$key]);
		}

		return array('forums' => $data);
	}

	private function getParentList($data, $id)
	{
		$parentlist = array();
		while(isset($data[$id]))
		{
			$parentlist[] = $id;
			$id = $data[$id]['parentId'];
		}
		return implode(',', $parentlist);
	}

	private function isNativoIP($ip)
	{
		$url = 'https://www.nativo.net/plugins/Api/AuthenticateIP?ip=' . $ip;

		$vurl = vB::getUrlLoader();
		//no idea if this is actually needed, but I don't want to muck with prior behavior here.
		$vurl->setOption(vB_Utility_Url::CLOSECONNECTION, 1);
		$result = $vurl->get($url);
		$obj = json_decode($result['body']);
		return $obj->result;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103003 $
|| #######################################################################
\*=========================================================================*/
