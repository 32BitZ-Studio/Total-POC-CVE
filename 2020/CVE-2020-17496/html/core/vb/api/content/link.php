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
 * vB_Api_Content_link
 *
 * @package vBApi
 * @author xiaoyu
 * @copyright Copyright (c) 2011
 * @version $Id: link.php 102784 2019-09-09 17:37:58Z ksours $
 * @access public
 */
class vB_Api_Content_Link extends vB_Api_Content_Text
{
	//override in client- the text name
	protected $contenttype = 'vBForum_Link';

	//The table for the type-specific data.
	protected $tablename = array('link', 'text');

	protected $providers = array();

	//Is text required for this content type?
	protected $textRequired = false;

	/**
	 * Normal constructor- protected to prevent direct instantiation
	 */
	protected function __construct()
	{
		parent::__construct();
		$this->library = vB_Library::instance('Content_Link');
	}

	/**
	 * Adds a new node.
	 *
	 * @param  mixed Array of field => value pairs which define the record.
	 * @param  array Array of options for the content being created
	 *               Understands skipTransaction, skipFloodCheck, floodchecktime, skipDupCheck, skipNotification, nl2br, autoparselinks.
	 *               - nl2br: if TRUE, all \n will be converted to <br /> so that it's not removed by the html parser (e.g. comments).
	 *               - wysiwyg: if true convert html to bbcode.  Defaults to true if not given.
	 *
	 * @return int   the new nodeid
	 */
	public function add($data, $options = array())
	{
		vB_Api::instanceInternal('hv')->verifyToken($data['hvinput'], 'post');
		return parent::add($data, $options);
	}

	/**
	 * Parse HTML Page and get its title/meta and images
	 *
	 * @param  string URL of the Page
	 *
	 * @return array
	 */
	public function parsePage($url)
	{
		// Validate url
		if (!preg_match('|^http(s)?://[a-z0-9-]+(\.[a-z0-9-]+)*(:[0-9]+)?(/.*)?$|i', $url))
		{
			throw new vB_Exception_Api('upload_invalid_url');
		}

		if (($urlparts = vB_String::parseUrl($url)) === false)
		{
			throw new vB_Exception_Api('upload_invalid_url');
		}

		$vurl = vB::getUrlLoader();
		$vurl->setOption(vB_Utility_Url::FOLLOWLOCATION, 1);
		//no idea if this is actually needed, but I don't want to muck with prior behavior here.
		$vurl->setOption(vB_Utility_Url::CLOSECONNECTION, 1);
		$vurl->setOption(vB_Utility_Url::HEADER, 1);
		$page = $vurl->get($url);

		return $this->extractData($page, $urlparts);
	}

	/**
	 * Used by parsePage() to extract the data to return
	 *
	 * @param  array|string The return value of the vB_Url call
	 * @param  array        The URL parts
	 *
	 * @return array        Array containing:
	 *                      'title' => $title,
	 *                      'meta' => $meta,
	 *                      'images' => (array) $imgurls,
	 */
	private function extractData($data, $urlparts)
	{
		if (!is_array($data))
		{
			$data = array('body' => $data);
		}

		if (!$data['body'])
		{
			// Don't throw exception here. Just return empty results
			return array(
				'title' => '',
				'meta' => '',
				'images' => null,
			);
		}

		$charset = false;
		// Check if we have content-type header and try to get charset from it
		if (!empty($data['headers']['content-type']))
		{
			$charset = $this->getCharsetFromContentType($data['headers']['content-type']);
		}

		if($charset)
		{
			$data['body'] = $this->addCharset($data['body'], $charset);
		}

		$dom = new DOMDocument();
		libxml_use_internal_errors(true);

		if (!$dom->loadHTML($data['body']))
		{
			// Invalid HTML. return empty results.
			return array(
				'title' => '',
				'meta' => '',
				'images' => null,
			);
		}

		$metaInfo = $this->getMetaValues($dom);

		//We don't check the meta http-equiv tag because we don't need to.  We
 		//don't actually need to know the source charset, the only reason we're
		//grabbing from other locations is so that we can insert a tag just
		//like the one that is already there if we have a http-equiv value.
		if (!$charset AND !empty($metaInfo['charset']))
		{
				//if we have a charset now, reparse the file with the charset
				//we can't just depend on the html because the parser won't
				//pick up this tag.
				$text = $this->addCharset($data['body'], $metaInfo['charset']);
				if (!$dom->loadHTML($text))
				{
					//if, in the unlikely event that we get an error here, reparse
					//the original text without a charset -- it worked before it should
					//work now.
					$dom->loadHTML($data['body']);
				}
				unset($text);

				//pull the meta info again, it may have changed because of the character set
				$metaInfo = $this->getMetaValues($dom);
		}



		// Get title
		$title = '';
		if ($titlenode = $dom->getElementsByTagName("title")->item(0))
		{
			$title = $titlenode->nodeValue;
		}

		if (!$title)
		{
			if(isset($metaInfo['property']['og:title']))
			{
				$title = $metaInfo['property']['og:title'];
			}
		}

		// Get Meta

		$meta = '';
		if(isset($metaInfo['name']['description']))
		{
			$meta = $metaInfo['name']['description'];
		}

		if (!$meta AND isset($metaInfo['property']['og:description']))
		{
			$meta = $metaInfo['property']['og:description'];
		}

		if (!$meta AND isset($metaInfo['name']['keywords']))
		{
			$meta = $metaInfo['name']['keywords'];
		}

		// Get baseurl
		$baseurl = '';
		if ($basenode = $dom->getElementsByTagName("base")->item(0))
		{
			if ($basenode->hasAttributes())
			{
				$item = $basenode->attributes->getNamedItem('href');

				if (!empty($item))
				{
					$baseurl = $item->nodeValue;
				}
			}
		}

		if (!$baseurl)
		{
			// We assume that the baseurl is domain+path of $url
			$baseurl = $urlparts['scheme'] . '://';
			if (!empty($urlparts['user']))
			{
				$baseurl .= $urlparts['user'] . ':' . $urlparts['pass'] . '@';
			}
			$baseurl .= $urlparts['host'];
			if (!empty($urlparts['port']))
			{
				$baseurl .= ':' . $urlparts['port'];
			}

			if (!empty($urlparts['path']))
			{
				$path = $urlparts['path'];
				// Remove filename from path
				$pos = strrpos($path, '/');
				if ($pos !== false AND $pos !== 0)
				{
					$path = substr($path, 0, $pos);
				}
				$baseurl .= $path;
			}
		}

		$baseurl = rtrim($baseurl, '/');


		// Get images
		$imgurls = array();

		//the meta scrape function doens't handle multiple items gracefully
		//and it's not clear how to make it do that without special cases
		//or complicating the other code, so leave this loop in place.
		// We need to add og:image if exists
		try
		{
			foreach ($dom->getElementsByTagName("meta") as $metanode)
			{
				if ($metanode->hasAttributes())
				{
					$metaItem = $metanode->attributes->getNamedItem('property');
					if (!empty($metaItem))
					{
						if ($metaItem->nodeValue == 'og:image')
						{
							if ($imgurl = $metanode->attributes->getNamedItem('content')->nodeValue)
							{
								$imgurls[] = $imgurl;
							}
							// Don't break here. Because Open Graph allows multiple og:image tags
						}
					}
				}
			}
		}
		catch(exception $e)
		{	}//nothing we can do- just continue;


		foreach ($dom->getElementsByTagName("img") as $imgnode)
		{
			if ($imgnode->hasAttributes() && $imgnode->attributes->getNamedItem('src'))
			{
				if ($imgurl = $imgnode->attributes->getNamedItem('src')->nodeValue)
				{
					$imgurls[] = $imgurl;
				}
			}
		}

		foreach ($imgurls as &$imgurl)
		{
			if (!$imgurl)
			{
				unset($imgurl);
			}

			// protocol-relative URL (//domain.com/logo.png)
			if (preg_match('|^//[a-z0-9-]+(\.[a-z0-9-]+)*(:[0-9]+)?(/.*)?$|i', $imgurl))
			{
				// We add url scheme to the url
				$imgurl = $urlparts['scheme'] . ':' . $imgurl;
			}

			// relative url? make it absolute
			$imgurl = $this->rel2abs($imgurl, $baseurl);
		}

		$imgurls = array_unique($imgurls);

		//the DomDocument class always converts to utf-8 internally outputs at utf-8 regardless
		//of the original charset. We need to convert back to the board charset, even if we're
		//ultimately going to convert back to utf-8 otherwise we'll try to convert from the
		//board charset to utf-8 on final output which causes problems if the board charset
		//isn't utf-8 and what we return *is*
		$charset = 'utf-8';
		if ($charset AND !vB_String::isVbCharset($charset))
		{
			$boardCharset = vB_String::getCharset();
			$title = vB_String::toCharset($title, $charset, $boardCharset);
			$meta = vB_String::toCharset($meta, $charset, $boardCharset);
			$imgurls = vB_String::toCharset($imgurls, $charset, $boardCharset);
		}

		return array(
			'title' => $title,
			'meta' => $meta,
			'images' => $imgurls,
		);
	}


	private function getMetaValues($dom)
	{
		$contentattributes = array('name', 'http-equiv', 'property');
		$singlevalues = array('charset');

		$values = array();
		foreach ($dom->getElementsByTagName("meta") as $metanode)
		{
			if ($metanode->hasAttributes())
			{
				//we assume that we only have one of the attributes.
				//however if there are multiple we'll store the content for
				//all of the attributes given
				foreach($contentattributes AS $attribute)
				{
					$metaItem = $metanode->attributes->getNamedItem($attribute);
					if (!empty($metaItem))
					{
						try
						{
							$name = $metaItem->nodeValue;
							$value = '';

							$metaValue = $metanode->attributes->getNamedItem('content');
							if (!empty($metaValue))
							{
								$value = $metaValue->nodeValue;
							}

							$values[$attribute][$name] = $value;

							$found = true;
						}
						catch(exception $e)
						{
							//nothing we can do- just continue;
						}
					}
				}

				foreach($singlevalues AS $attribute)
				{
					$metaItem = $metanode->attributes->getNamedItem($attribute);
					if (!empty($metaItem))
					{
						try
						{
							$value = $metaItem->nodeValue;
							$values[$attribute] = $value;
						}
						catch(exception $e)
						{
							//nothing we can do- just continue;
						}
					}
				}

			}
		}

		return $values;
	}

	private function getCharsetFromContentType($contenttype)
	{
		$charset = false;
		$temp = explode('=', $contenttype);
		if(isset($temp[1]))
		{
			$charset = $temp[1];
		}
		return $charset;
	}

	private function addCharset($text, $charset)
	{
		//the html parser reads the http-equiv meta tag for the charset (it doesn't care about the newer
		//charset meta) and assumes iso-8859-1 if it doesn't find it.  This is a pain in the rear but we
		//need to feed it the right charset.  However it doesn't need to be pretty so we won't worry
		//about things that the parser won't care about (for example if the tag is already there).
		//The results might be unpredictable if the tags conflict but that can only happen if there
		//is both a http header charset and a charset in the html that don't match -- which shouldn't
		//happen.
		$contenttag = '<meta http-equiv="Content-Type" content="text/html; charset=' . $charset . '" />';

		$newtext = preg_replace('#<head>#i', "$0$contenttag", $text, 1, $count);
		//no error and we matched the head tag
		if($newtext AND $count)
		{
			return $newtext;
		}

		$newtext = preg_replace('#<html>#i', "$0$contenttag", $text, 1, $count);
		//no error and we matched the html tag
		if($newtext AND $count)
		{
			return $newtext;
		}

		//if all else fails prepend it to the text and hope for the best.
		return $contenttag . $text;
	}

	/**
	 * This returns a link image by nodeid
	 *
	 * @param  int    Node ID
	 * @param  string Thumbnail version/size requested (SIZE_* constanst in vB_Api_Filedata)
	 *
	 * @return mixed  Array of filedataid,filesize, extension, filedata, htmltype.
	 */
	public function fetchImageByLinkId($linkid, $type = vB_Api_Filedata::SIZE_FULL)
	{
		$link = $this->getContent($linkid);
		$link = $link[$linkid];
		if (empty($link))
		{
			return array();
		}
		//First validate permission.
		if ($link['userid'] !=  vB::getUserContext()->fetchUserId())
		{
			if (!$link['showpublished'])
			{
				if (!vB::getUserContext()->hasChannelPermission('moderatorpermissions', 'caneditposts', $linkid, false, $link['parentid']))
				{
					throw new vB_Exception_Api('no_permission');
				}
			}
			else if (!vB::getUserContext()->getChannelPermission('forumpermissions', 'canview', $linkid, false, $link['parentid']))
			{
				throw new vB_Exception_Api('no_permission');
			}

		}
		//if we got here, this user is authorized to see this. image.
		$params = array('filedataid' => $link['filedataid'], 'type' => $type);
		$image = vB::getDbAssertor()->getRow('vBForum:getFiledataContent', $params);

		if (empty($image))
		{
			return false;
		}

		$imageHandler = vB_Image::instance();

		return $imageHandler->loadFileData($image, $type, true);
	}

	/**
	 * Function to convert relative URL to absolute given a base URL
	 * From http://bsd-noobz.com/blog/php-script-for-converting-relative-to-absolute-url
	 *
	 * @param  string the relative URL
	 * @param  string the base URL
	 *
	 * @return string the absolute URL
	 */
	protected function rel2abs($rel, $base)
	{
		if (vB_String::parseUrl($rel, PHP_URL_SCHEME) != '')
		{
			return $rel;
		}
		else if ($rel[0] == '#' || $rel[0] == '?')
		{
			return $base.$rel;
		}

		$parsed_base = vB_String::parseUrl($base);
		$abs = (($rel[0] == '/' OR empty($parsed_base['path'])) ? '' : preg_replace('#/[^/]*$#', '', $parsed_base['path']))."/$rel";
		$re  = array('#(/\.?/)#', '#/(?!\.\.)[^/]+/\.\./#');

		for ($n = 1; $n > 0; $abs = preg_replace($re, '/', $abs, -1, $n));

		return $parsed_base['scheme'].'://'.$parsed_base['host'].str_replace('../', '', $abs);
	}

	/**
	 * Cleans the input in the $data array, directly updating $data.
	 *
	 * @param mixed     Array of fieldname => data pairs, passed by reference.
	 * @param int|false Nodeid of the node being edited, false if creating new
	 */
	public function cleanInput($data, $nodeid = false)
	{
		$data = parent::cleanInput($data, $nodeid);

		$cleaner = vB::getCleaner();

		if (isset($data['filedataid']))
		{
			$data['filedataid'] = intval($data['filedataid']);
		}

		if (isset($data['url']))
		{
			$data['url'] = $cleaner->clean($data['url'], vB_Cleaner::TYPE_STR);
		}

		foreach (array('url_title', 'meta') as $fieldname)
		{
			if (isset($data[$fieldname]))
			{
				$data[$fieldname] = $cleaner->clean($data[$fieldname], vB_Cleaner::TYPE_NOHTML);
			}
		}

		return $data;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102784 $
|| #######################################################################
\*=========================================================================*/
