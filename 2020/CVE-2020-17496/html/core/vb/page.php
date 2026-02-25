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

class vB_Page
{
	use vB_Trait_NoSerialize;

	/**
	 * Used for specific pages
	 */
	const TYPE_CUSTOM = 'custom';

	/**
	 * Used for generic pages such as default conversation page
	 */
	const TYPE_DEFAULT = 'default';

	const PAGE_BLOG = 'vbulletin-4ecbdac82f2c27.60323366';
	const PAGE_ARTICLE = 'vbulletin-p-cmshome5229f4e0c2ea71.91676461';	// CMS articles home page
	const PAGE_SOCIALGROUP = 'vbulletin-4ecbdac82f2c27.60323372';
	const PAGE_HOME = 'vbulletin-4ecbdac82ef5d4.12817784';
	const PAGE_ONLINE = 'vbulletin-4ecbdac82f07a5.18983925';
	const PAGE_MEMBERLIST = 'vbulletin-4ecbdac82f07a5.18983926';
	const PAGE_SEARCH = 'vbulletin-4ecbdac82efb61.17736147';
	const PAGE_SEARCHRESULT = 'vbulletin-4ecbdac82f2815.04471586';

	const TEMPLATE_CHANNEL		= 'vbulletin-4ecbdac9371313.62302700';
	const TEMPLATE_CATEGORY		= 'vbulletin-4ecbdac9371313.62302701';
	const TEMPLATE_CONVERSATION = 'vbulletin-4ecbdac93716c4.69967191';
	const TEMPLATE_BLOG			= 'vbulletin-4ecbdac93742a5.43676030';
	const TEMPLATE_ARTICLE_HOME	= 'vbulletin-pt-cmshome5229f9fc6f78f2.75718106';	// CMS articles home page template
	const TEMPLATE_ARTICLE_CATEGORY = 'vbulletin-pt-cmscatlist5229fcd0dd3da7.64934873'; // CMS article category listing page template
	const TEMPLATE_ARTICLE 		= 'vbulletin-pt-cmsarticle5229fcffd5d428.54773744';	// CMS article default page template
	const TEMPLATE_SOCIALGROUP	= 'vbulletin-sgroups93742a5.43676038';
	const TEMPLATE_SOCIALGROUP_CATEGORY = 'vbulletin-sgcatlist93742a5.43676040';
	const TEMPLATE_BLOGCONVERSATION			= 'vbulletin-4ecbdac93716c4.69967191';
	const TEMPLATE_SOCIALGROUPCONVERSATION	= 'vbulletin-sgtopic93742a5.43676039';

	/**
	 * Clones a page template with its widgets and returns the new page template id.
	 * @param int $pageTemplateId
	 * @return int
	 */
	public static function clonePageTemplate($pageTemplateId)
	{
		$db = vB::getDbAssertor();

		$templatePage = $db->getRow('pagetemplate', array(
			'pagetemplateid' => intval($pageTemplateId),
		));

		if (!$templatePage)
		{
			throw new Exception('Cannot find pagetemplate');
		}

		// clone page template
		$newTemplateId = $db->insert('pagetemplate', array(
			'title'	=> 'Clone of ' . $templatePage['title'],
			'screenlayoutid' => $templatePage['screenlayoutid'],
			'guid' => vB_Xml_Export_PageTemplate::createGUID($templatePage)
		));
		if (is_array($newTemplateId))
		{
			$newTemplateId = (int) array_pop($newTemplateId);
		}

		// clone widgets
		$widgets = $db->getRows('widgetinstance', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			vB_dB_Query::CONDITIONS_KEY => array('pagetemplateid'=>$pageTemplateId)
		));
		foreach ($widgets AS $widget)
		{
			unset($widget['widgetinstanceid']);
			$widget['pagetemplateid'] = $newTemplateId;
			$db->insert('widgetinstance', $widget);
		}

		return $newTemplateId;
	}

	/**
	 * Returns a list of default pagetemplate GUIDs.
	 *
	 * @return array    Array of pagetemplate.guid values for default templates, keyed by guids.
	 */
	public static function getDefaultPageTemplateGUIDs()
	{
		$defaults = array(
			'vbulletin-4ecbdac9370e30.09770013',
			'vbulletin-4ecbdac9371313.62302700',
			'vbulletin-4ecbdac9371313.62302701',
			'vbulletin-4ecbdac93716c4.69967191',
			'vbulletin-4ecbdac93716c4.69967191',
			'vbulletin-4ecbdac9371ab0.18191024',
			'vbulletin-4ecbdac9371e58.50519390',
			'vbulletin-4ecbdac9371e58.50519391',
			'vbulletin-4ecbdac9371e58.50519392',
			'vbulletin-4ecbdac9371e58.50519393',
			'vbulletin-4ecbdac93721f3.19350821',
			'vbulletin-4ecbdac9372590.52063766',
			'vbulletin-4ecbdac9372934.46376011',
			'vbulletin-4ecbdac9372cd6.23258244',
			'vbulletin-4ecbdac9373b62.95194677',
			'vbulletin-4ecbdac9373f09.61139031',
			'vbulletin-4ecbdac93742a5.43676026',
			'vbulletin-4ecbdac93742a5.43676027',
			'vbulletin-4ecbdac93742a5.43676028',
			'vbulletin-4ecbdac93742a5.43676029',
			'vbulletin-4ecbdac93742a5.43676030',
			'vbulletin-4ecbdac93742a5.43676031',
			'vbulletin-4ecbdac93742a5.43676032',
			'vbulletin-4ecbdac93742a5.43676034',
			'vbulletin-4ecbdac93742a5.43676035',
			'vbulletin-4ecbdac93742a5.43676037',
			'vbulletin-sgroups93742a5.43676038',
			'vbulletin-sgtopic93742a5.43676039',
			'vbulletin-sgcatlist93742a5.43676040',
			'vbulletin-4ecbdac93742a5.43676041',
			'vbulletin-4ecbdac93742a5.43676042',
			'vbulletin-4ecbdac93742a5.43676043',
			'vbulletin-513e3ab811d8d4.37160575',
			'vbulletin-4ecbdac93721f3.19350822',
			'vbulletin-pt-cmshome5229f9fc6f78f2.75718106',
			'vbulletin-pt-cmscatlist5229fcd0dd3da7.64934873',
			'vbulletin-pt-cmsarticle5229fcffd5d428.54773744',
			'vbulletin-pagetemplate-markuplibrary-796785120ec7e73ab.1002134871',
			'vbulletin-pagetemplate-apiform-5605adabb98994.13134185',
			'vbulletin-pagetemplate-resetpassword-5697ebc53d6573.06983939',
			'vbulletin-pmchat-pagetemplate-chat-573ca81b74e5b0.79208063',
			'vbulletin-pagetemplate-calendar-58af7aebda8e71.47586077',
			'vbulletin-pagetemplate-privacy-08ddbc35178028.74ec109e',
			'vbulletin-pagetemplate-homeclassic-5d5f16299ee2f2.74457343',
			'vbulletin-pagetemplate-homecommunity-5d6039ff498687.05096587',
		);

		$return = array();
		foreach ($defaults AS $__guid)
		{
			$return[$__guid] = $__guid;
		}

		return $return;
	}

	/**
	 * Gets the page template for display of blog channels
	 *
	 * @return integer
	 */
	public static function getChannelPageTemplate()
	{
		// use default pagetemplate for forum channels
		$pageTemplateId = vB::getDbAssertor()->getField('pagetemplate', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			vB_dB_Query::CONDITIONS_KEY => array('guid' => vB_Page::TEMPLATE_CHANNEL)
		));

		return $pageTemplateId;
	}

	/**
	 * Gets the page template for display of blog topics/conversations
	 *
	 * @return integer
	 */
	public static function getConversPageTemplate()
	{
		// use default pagetemplate for forum conversations
		$pageTemplateId = vB::getDbAssertor()->getField('pagetemplate', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			vB_dB_Query::CONDITIONS_KEY => array('guid' => vB_Page::TEMPLATE_CONVERSATION)
		));

		return $pageTemplateId;
	}

	/**
	 * Gets the page template for display of blog channels
	 *
	 * @return integer
	 */
	public static function getCategoryChannelPageTemplate()
	{
		// use default pagetemplate for forum categories
		$pageTemplateId = vB::getDbAssertor()->getField('pagetemplate', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			vB_dB_Query::CONDITIONS_KEY => array('guid' => vB_Page::TEMPLATE_CATEGORY)
		));

		return $pageTemplateId;
	}

	public static function getBlogPageTemplates()
	{
		$result = array();

		// TODO: is there any special condition to be a blog page template?
		$pagetemplates = vB::getDbAssertor()->assertQuery('pagetemplate', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT));

		foreach ($pagetemplates AS $pagetemplate)
		{
			if ($pagetemplate['guid'] == self::TEMPLATE_BLOG)
			{
				$result = array_merge(array($pagetemplate['pagetemplateid'] => $pagetemplate['title']), $result);
			}
			else
			{
				$result[$pagetemplate['pagetemplateid']] = $pagetemplate['title'];
			}
		}

		return $result;
	}

	/**
	 * Gets the page template for display of blog channels
	 *
	 * @return integer
	 */
	public static function getBlogChannelPageTemplate()
	{
		$options = vB::getDatastore()->getValue('options');

		if (isset($options['blog_pagetemplate']) AND !empty($options['blog_pagetemplate']))
		{
			$pageTemplateId = $options['blog_pagetemplate'];
		}
		else
		{
			// use default pagetemplate for blogs
			$pageTemplateId = vB::getDbAssertor()->getField('pagetemplate', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::CONDITIONS_KEY => array('guid' => vB_Page::TEMPLATE_BLOG)
			));
		}

		return $pageTemplateId;
	}

	/**
	 * Gets the page template for display of blog topics/conversations
	 *
	 * @return integer
	 */
	public static function getBlogConversPageTemplate()
	{
		$options = vB::getDatastore()->getValue('options');

		if (isset($options['blog_pagetemplate']) AND !empty($options['blog_pagetemplate']))
		{
			$pageTemplateId = $options['blog_pagetemplate'];
		}
		else
		{
			// use default pagetemplate for blogs
			$pageTemplateId = vB::getDbAssertor()->getField('pagetemplate', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::CONDITIONS_KEY => array('guid' => vB_Page::TEMPLATE_BLOGCONVERSATION)
			));
		}

		return $pageTemplateId;
	}

	/**
	 * Gets the page template for display of social group channels
	 *
	 * @return integer
	 */
	public static function getSGChannelPageTemplate()
	{
		$options = vB::getDatastore()->getValue('options');

		if (isset($options['sg_pagetemplate']) AND !empty($options['sg_pagetemplate']))
		{
			$pageTemplateId = $options['sg_pagetemplate'];
		}
		else
		{
			// use default pagetemplate for blogs
			$pageTemplateId = vB::getDbAssertor()->getField('pagetemplate', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::CONDITIONS_KEY => array('guid' => vB_Page::TEMPLATE_SOCIALGROUP)
			));
		}

		return $pageTemplateId;
	}

	/**
	 * Gets the page template for display of social group  topics/conversations
	 *
	 * @return integer
	 */
	public static function getSGConversPageTemplate()
	{
		$options = vB::getDatastore()->getValue('options');

		if (isset($options['sg_pagetemplate']) AND !empty($options['sg_pagetemplate']))
		{
			$pageTemplateId = $options['sg_pagetemplate'];
		}
		else
		{
			// use default pagetemplate for blogs
			$pageTemplateId = vB::getDbAssertor()->getField('pagetemplate', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::CONDITIONS_KEY => array('guid' => vB_Page::TEMPLATE_SOCIALGROUPCONVERSATION)
			));
		}

		return $pageTemplateId;
	}

	/**
	 * Gets the page template for display of social group categories
	 *
	 * @return integer
	 */
	public static function getSGCategoryPageTemplate()
	{
		$options = vB::getDatastore()->getValue('options');

		if (isset($options['sg_category_pagetemplate']) AND !empty($options['sg_category_pagetemplate']))
		{
			$pageTemplateId = $options['sg_category_pagetemplate'];
		}
		else
		{
			// use default pagetemplate for blogs
			$pageTemplateId = vB::getDbAssertor()->getField('pagetemplate', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::CONDITIONS_KEY => array('guid' => vB_Page::TEMPLATE_SOCIALGROUP_CATEGORY)
			));
		}

		return $pageTemplateId;
	}

	/**
	 * Gets the page template for display of social group  topics/conversations
	 *
	 * @return integer
	 */
	public static function getSGCategoryConversPageTemplate()
	{
		$options = vB::getDatastore()->getValue('options');

		if (isset($options['sg_category_pagetemplate']) AND !empty($options['sg_category_pagetemplate']))
		{
			$pageTemplateId = $options['sg_category_pagetemplate'];
		}
		else
		{
			// use default pagetemplate for blogs
			$pageTemplateId = vB::getDbAssertor()->getField('pagetemplate', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::CONDITIONS_KEY => array('guid' => vB_Page::TEMPLATE_CONVERSATION)
			));
		}

		return $pageTemplateId;
	}

	/**
	 * Gets the page template for display of article category channels
	 *
	 * @return integer
	 */
	public static function getArticleChannelPageTemplate()
	{
		// use default pagetemplate for forum channels
		$pageTemplateId = vB::getDbAssertor()->getField('pagetemplate', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			vB_dB_Query::CONDITIONS_KEY => array('guid' => vB_Page::TEMPLATE_ARTICLE_CATEGORY)
		));

		return $pageTemplateId;
	}

	/**
	 * Gets the page template for display of article detail
	 *
	 * @return integer
	 */
	public static function getArticleConversPageTemplate()
	{
		// use default pagetemplate for forum conversations
		$pageTemplateId = vB::getDbAssertor()->getField('pagetemplate', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			vB_dB_Query::CONDITIONS_KEY => array('guid' => vB_Page::TEMPLATE_ARTICLE)
		));

		return $pageTemplateId;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102727 $
|| #######################################################################
\*=========================================================================*/
