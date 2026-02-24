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
 * vB_Api_Content_Video
 *
 * @package vBApi
 * @author ebrown
 * @copyright Copyright (c) 2011
 * @version $Id: video.php 103174 2019-10-15 21:07:36Z ksours $
 * @access public
 */
class vB_Api_Content_Video extends vB_Api_Content_Text
{
	//override in client- the text name
	protected $contenttype = 'vBForum_Video';

	//The table for the type-specific data.
	protected $tablename = array('video', 'text');

	//Is text required for this content type?
	protected $textRequired = false;

	const THUMBNAIL_TTL = 432000; //5 days

	/**
	 * Constructor, no external instantiation
	 */
	protected function __construct()
	{
		parent::__construct();
		$this->library = vB_Library::instance('Content_Video');
	}


	/**
	 * Adds a new node.
	 *
	 * @param  mixed   Array of field => value pairs which define the record.
	 * @param  array   Array of options for the content being created.
	 *                 Understands skipTransaction, skipFloodCheck, floodchecktime, skipDupCheck, skipNotification, nl2br, autoparselinks.
	 *                 - nl2br: if TRUE, all \n will be converted to <br /> so that it's not removed by the html parser (e.g. comments).
	 *                 - wysiwyg: if true convert html to bbcode.  Defaults to true if not given.
	 *
	 * @return integer the new nodeid
	 */
	public function add($data, $options = array())
	{
		vB_Api::instanceInternal('hv')->verifyToken($data['hvinput'], 'post');

		if ((vB_Api::instanceInternal('node')->fetchAlbumChannel() == $data['parentid']) AND (!vB::getUserContext()->hasPermission('albumpermissions', 'picturefollowforummoderation')))
		{
			$data['approved'] = 0;
			$data['showapproved'] = 0;
		}

		return parent::add($data, $options);
	}

	/**
	 * Get information from video's URL.
	 * This method makes use of bbcode_video table to get provider information
	 *
	 * @param  string     $url
	 *
	 * @return array|bool Video data. False if the url is not supported or invalid
	 */
	public function getVideoFromUrl($url)
	{
		return $this->library->getVideoFromUrl($url);
	}

	/**
	 *	Will attempt to get the thumbnail url based on provider specific rules
	 *	otherwise will fall back to the page scraping behavior.
	 */
	public function getVideoThumbnailFromProvider($provider, $code, $url, $nodeid = false)
	{
		//we should really revisit our bbcode_video_*.xml rules.
		//we have too many exceptions in the code here.  Ideally we should have a modular
		//class based approach to handle different methods (the current one assumes scraping
		//the main url link which is cumbersome in a lot of ways.
		if($provider == 'youtube' OR $provider == 'youtube_share')
		{
			return 'https://img.youtube.com/vi/' . $code . '/hqdefault.jpg';
		}

		return $this->getVideoThumbnail($url, $nodeid);
	}

	/**
	 * Extracts the thumbnail from og:image meta data
	 *
	 * @param  string url of video
	 * @param  int    optional nodeid of video node
	 *
	 * @return mixed  url string or false
	 */
	public function getVideoThumbnail($url, $nodeid = false)
	{
		//Note that this is called from the template, and often there will be no nodeid
		if (!empty($nodeid))
		{
			$video = $this->getContent($nodeid);
			if (!empty($video))
			{
				$video = reset($video);
			}
		}

		if (empty($video))
		{
			//Try to get from cache first.
			$cacheKey = 'vB_Vid' . md5($url);
			$check = vB_Cache::instance(vB_Cache::CACHE_LARGE)->read($cacheKey);

			if (!empty($check))
			{
				return $check;
			}

			$video = $this->assertor->getRow('vBForum:video', array('url' => $url));
		}

		//check if we have the thumbnail in the video
		if (
			!empty($video)
			AND !empty($video['thumbnail'])
			AND !empty($video['thumbnail_date'])
			//if the thumbnail is too old we need to fetch a fresh one, it might have been updated
			AND ($video['thumbnail_date'] >= (vB::getRequest()->getTimeNow() - self::THUMBNAIL_TTL))
		)
		{
			return $video['thumbnail'];
		}

		// Try fetching it from the URL.

		/*
			Special case - facebook. Their regular video pages has several layers of black magic. Basically the entire relevant element is inside a comment unless
			you specify ?_fb_noscript=1 query param, and even then, the thumbnail is likely the 2nd or 3rd image with no good way of identifying which image is
			best from the DOM. Using the graph API would get us the thumbnail instantly, but that requires an access token, or in other words each forum owner has
			to set up a facebook app for their forum.
			Thankfully, using their "embeddable link" (which is what we use for the bbcode_video) seems to work fairly well with the logic below of "return the first
			image and hope for the best."
		 */
		// strpos is cheaper than preg_match, skip latter if URL has nothing to do with facebook
		if (strpos($url, 'facebook.com') !== false)
		{

			// more sophisticated check
			// Facebook's newest video URLs (video.php?v=... URLs now redirect to these) seem to be in the format of
			// www.facebook.com/{profile name}/videos/{video id}

			preg_match("#^(?<url>(?:https?\:\/\/)?(?:www.)?facebook\.com\/[^\/]*\/videos\/[0-9]+\/?.*)$#", $url, $matches);
			if (!empty($matches['url']))
			{
				$url = "https://www.facebook.com/plugins/video.php?href=" . urlencode($url);
			}
		}

		$data = vB_Api::instance('content_link')->parsePage($url);

		if (!empty($data['images']))
		{
			$thumbnail = $data['images'];

			// only return the first image. May want to change this later after product audit?
			if (is_array($thumbnail))
			{
				$thumbnail = $thumbnail[0];
			}

			//save the thumbnail so we don't have to fetch it next time it's needed
			if (!empty($video))
			{
				//there is a video record.  Put it there.
				$this->assertor->update('vBForum:video',
					array(
						'thumbnail' => $thumbnail,
						'thumbnail_date' => vB::getRequest()->getTimeNow(),
					),
					array('nodeid' => $video['nodeid'])
				);
				vB_Cache::allCacheEvent('nodeChg_' . $video['nodeid']);
			}
			else
			{
				//put into cache
				if (empty($cacheKey))
				{
					$cacheKey = 'vB_Vid' . md5($url);
				}

				vB_Cache::instance(vB_Cache::CACHE_LARGE)->write($cacheKey, $thumbnail,  self::THUMBNAIL_TTL);
			}

			return $thumbnail;
		}

		// we should probably have a default placeholder
		// we can return in case no image is found..
		return false;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103174 $
|| #######################################################################
\*=========================================================================*/
