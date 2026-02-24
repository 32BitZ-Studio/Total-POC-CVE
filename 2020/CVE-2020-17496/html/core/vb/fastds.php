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

/* NOTE: This file contains the vB_FastDS Base Class /**
 *
 * There is some data that is heavily used, not excessively large, and changes rarely.
 * There are a number of in-memory caches for php. The most common is probably APC, but
 * there are a number of others. By caching the appropriate data we believe we can
 * significantly improve performance.  We'll build approximately from small to large:
 * first: phrases for the default language: 1 megabyte for the current default.
 * then datastore: under a megabyte.
 * then all templates for the default style: around 3 megabytes.
 *
 * note that this is shared among all users. We should only implement this for
 * caches which live on the current server. If we access a remote server, we probably
 * will be no faster than the existing datastore/cache implementations.

 * @package vBulletin
 * @author vBulletin Development Team
 * @version $Revision: 99788 $
 * @since $Date: 2018-10-24 17:26:31 -0700 (Wed, 24 Oct 2018) $
 
 */
abstract class vB_FastDS
{
	use vB_Trait_NoSerialize;

	protected static $enabled;
	protected static $fastInstance;

	protected $phrasesCached;
	protected $phRebuilt;
	protected $dsCached;
	protected $dsRebuilt;
	protected $templatesCached;
	protected $tmRebuilt;
	protected $prefix;
	protected $rebuilt;
	protected $language;
	protected $styleid;
	protected static $building = false;
	const TYPE_DATASTORE = 'ds';
	const TYPE_PHRASES = 'ph';
	const TYPE_TEMPLATES = 'tm';

	//There are some things that can't be cached.  We ignore those
	protected $skipDSCache = array('wol' => 1, 'cron' => '1', 'miscoptions' => 1);

	/** Returns a reference to the current fastDS object, or false
	*
	*	@return	mixed	either a fastDS instance or false
	**/
	public static function instance()
	{
		if (self::$building)
		{
			return false;
		}

		if (isset(self::$fastInstance))
		{
			return self::$fastInstance;
		}

		//If we already know we aren't set, return false
		if (isset(self::$enabled) AND !self::$enabled)
		{
			return false;
		}

		$config = vB::getConfig();

		if (!isset($config['fastDS']) OR !$config['fastDS'])
		{
			self::$enabled = false;
			return false;
		}

		if (isset($config['fastDSType']))
		{
			$class = 'vB_FastDS_' . $config['fastDSType'];
		}
		else
		{
			if (!is_callable('apc_fetch'))
			{
				return false;
			}
			$class = 'vB_FastDS_APC';
		}
		//Note that if there is a problem with cached data, on instantiotion the cache
		// object with set enabled to false.
		self::$enabled = true;
		self::$fastInstance = new $class($config);
		return self::$fastInstance;
	}


	/** standard constructor
	 *
	 * 	@param	mixed	The config object from vB::getConfig()
	 *
	 *	@return	a fastDS object
	 **/
	protected function __construct($config)
	{

		if (isset($config['fastDSPrefix']))
		{
			$this->prefix = $config['fastDSPrefix'];
		}
		else if (isset($config['Datastore']['prefix']))
		{
			$this->prefix = $config['Datastore']['prefix'] . 'fds';
		}
		else if (isset($config['Cache']['memcacheprefix']))
		{
			$this->prefix = $config['Cache']['memcacheprefix'] . 'fds';
		}
		else
		{
			if (!defined('TABLE_PREFIX'))
			{
				vB::getConfig();
			}
			$this->prefix = TABLE_PREFIX . 'fds';
		}

		$settings = $this->getValue('cacheSet', '');

		if (empty($settings))
		{
			$this->buildFastDS();
		}
		else
		{
			$this->restoreSettings($settings);
		}
		return $this;
	}

	/** Restores the settings from APC
	*
	* 	@param	mixed	the cached summary read from APC
	*/
	protected function restoreSettings($settings)
	{
		$this->phrasesCached = $settings['ph'];
		$this->phRebuilt = $settings['pht'];
		$this->dsCached = $settings['ds'];
		$this->dsRebuilt = $settings['dst'];
		$this->templatesCached = $settings['tm'];
		$this->tmRebuilt = $settings['tmt'];
		$this->language = $settings['lang'];
		$this->styleid = $settings['style'];
		$miscOptions = vB::getDbAssertor()->getRow('datastore', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'title' => 'miscoptions'));

		//If we don't have a value, rebuild everything.
		if (empty($miscOptions) OR !empty($miscOptions['errors']))
		{
			$this->buildFastDS();
			return;
		}

		if (!empty($miscOptions['data']))
		{
			$miscOptions = unserialize($miscOptions['data']);
		}


		$timeNow = vB::getRequest()->getTimeNow();

		if ($this->phrasesCached AND
			(empty($miscOptions['phrasedate']) OR
			($settings['pht'] < $miscOptions['phrasedate']) AND ($timeNow > $miscOptions['phrasedate']))
		)
		{
			$changed = true;
			$this->buildPhrases(9999999);
		}

		if ($this->dsCached AND
			(empty($miscOptions['dsdate']) OR
			($settings['dst'] < $miscOptions['dsdate']) AND ($timeNow > $miscOptions['dsdate']))
			)
		{
			$changed = true;
			$this->buildDatastore(9999999);
		}

		if ($this->templatesCached AND
			(empty($miscOptions['tmtdate']) OR
			($settings['tmt'] < $miscOptions['tmtdate']) AND ($timeNow > $miscOptions['tmtdate']))
		)
		{
			$changed = true;
			$this->buildTemplates(9999999);
		}

		if (!empty($changed))
		{
			$this->saveSettings();
		}
	}



	protected function saveSettings()
	{
		$this->setValue('cacheSet', array(
			'ph' =>$this->phrasesCached, 'ds' => $this->dsCached,
			'tm' => $this->templatesCached, 'pht' =>$this->phRebuilt,
			'dst' => $this->dsRebuilt, 'tmt' => $this->tmRebuilt,
			'style' => $this->styleid, 'lang' => $this->language
		));
	}


	/** reBuilds the fastDS data. This is called if the cached value is lost, or after upgrade.
	 *
	 **/
	public function buildFastDS()
	{
		self::$building = true;
		//make sure that we don't get a cached version.
		$this->phrasesCached = false;
		$this->dsCached = false;
		$this->templatesCached = false;
		$settings = array(false, false, false, false, false);
		unset($this->styleid);
		$config = vB::getConfig();

		if (!empty($config['fastDSLimit']))
		{
			$maxSize = intval($config['fastDSLimit']);
		}
		else
		{
			$maxSize = 6000000;
		}

		//we build from small to large. ;
		if ($maxSize > 10000)
		{
			$used = $this->buildPhrases($maxSize);
			if ($used > 0)
			{
				$maxSize -= $used;
				$used = $this->buildDatastore($maxSize);

				if ($used > 0)
				{
					$maxSize -= $used;
					$used -= $this->buildTemplates($maxSize);
				}
			}
		}
		$this->saveSettings();
		self::$building = false;
	}


	/** reBuilds the fastDS data. This is called if the cached value is lost, or after upgrade.
	 *
	 *	@param	integer		the maximum space allowed for caching this data.
	 *
	 *	@return	integer		estimate of the space used. Note that we can't be exact.
	 **/
	protected function buildPhrases($maxSize)
	{
		self::$building = true;
		$languageid = vB::getDatastore()->getOption('languageid');

		// Still don't have a language, fall back to master language
		if (!$languageid)
		{
			$languageid = -1;
		}
		$phrases = array();
		$this->language = $languageid;
		if ($languageid > -1)
		{
			$languages = vB::getDatastore()->getValue('languagecache');
		}



		//We sort by languageid. First we'll populate the default language,
		// then overwrite phrases with language-specific copies.  That way
		// we have something for every phrase, but translated phrases
		// where available.
		$phraseQry = vB::getDbAssertor()->assertQuery('phrase', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
		'languageid' => array($languageid, 0, -1)),
		array('field' => array('languageid'), 'direction' =>  array(vB_dB_Query::SORT_DESC)));

		$search = array(
			'/%/s',
			'/\{([0-9]+)\}/siU',
		);
		$replace = array(
			'%%',
			'%\\1$s',
		);
		$this->phrasesCached = true;
		$size = 0;
		$used = array();
		foreach ($phraseQry AS $phrasedata)
		{

			if (isset($used[$phrasedata['varname']]))
			{
				continue;
			}
			$used[$phrasedata['varname']] = 1;
			$phrase = $phrasedata['text'];

			if (strpos($phrase, '{1}') !== false)
			{
				$phrase = preg_replace($search, $replace, $phrase);
			}

			if ($size + strlen($phrase) > $maxSize)
			{
				self::$building = false;
				return false;
			}

			if (($phrasedata['languageid'] > -1)
				AND !empty($languages[$phrasedata['languageid']]['charset'])
				AND ($languages[$phrasedata['languageid']]['charset'] !== 'UTF-8'))
			{
				$phrase = vB_String::toCharset($phrase, $languages[$phrasedata['languageid']]['charset'], 'UTF-8');
			}

			$size += strlen($phrase) + strlen($phrasedata['varname']);
			$this->setPhrase($phrasedata['varname'], $phrase);
		}
		$this->phRebuilt = vB::getRequest()->getTimeNow();

		self::$building = false;
		return $size;
	}

	/** reBuilds the fastDS data. This is called if the cached value is lost, or after upgrade.
	 *
	 *	@param	integer		the maximum space allowed for caching this data.
	 *
	 *	@return	integer		estimate of the space used. Note that we can't be exact.
	 **/
	protected function buildDatastore($maxSize)
	{
		$dsData = vB::getDbAssertor()->assertQuery('datastore', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT));
		$size = 0;
		$this->dsCached = true;
		$used = array();
		self::$building = true;

		foreach ($dsData as $dsItem)
		{
			if ($size + strlen($dsItem['data']) > $maxSize)
			{
				//We weren't able to cache.  Let's un-set whatever we have.
				foreach($used AS $title)
				{
					$this->clearValue('ds' . $title);

				}

				$this->dsCached = false;
				self::$building = false;
				return $false;
			}
			$size += strlen($dsItem['data'])  + strlen($dsItem['title']);

			if (empty($dsItem['data']))
			{
				$data = '';
			}
			else if ($dsItem['unserialize'] > 0)
			{
				try
				{
					$data = unserialize($dsItem['data']);
				}
				catch(exception $e)
				{
					continue;
				}
			}
			else
			{
				$data = $dsItem;
			}
			$this->setDS($dsItem['title'], $data);

		}
		$this->dsRebuilt = vB::getRequest()->getTimeNow();
		self::$building = false;
		return $size;
	}


	/** reBuilds the fastDS data. This is called if the cached value is lost, or after upgrade.
	 *
	 *	@param	integer		the maximum space allowed for caching this data.
	 *
	 *	@return	integer		estimate of the space used. Note that we can't be exact.
	 **/
	protected function buildTemplates($maxSize)
	{
		self::$building = true;
		$styleid = vB::getDatastore()->getOption('styleid');

		// Still don't have a language, fall back to master language
		if (!$styleid)
		{
			$styleid = -1;
		}
		$this->styleid = $styleid;

		//We sort by languageid, descending. So for a given template, the first
		// record we get is what we want.

		$templates = vB::getDbAssertor()->assertQuery('template', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'styleid' => array($styleid, 0, -1)),
			 array('field' => array('styleid'), 'direction' =>  array(vB_dB_Query::SORT_DESC)));
		$size = 0;
		$this->templatesCached = true;
		$used = array();
		foreach ($templates as $template)
		{
			if (isset($used[$template['title']]))
			{
				continue;
			}
			$used[$template['title']] = 1;

			if ($size + strlen($template['template']) > $maxSize)
			{
				//We weren't able to cache.  Let's un-set whatever we have.
				foreach($used AS $template => $value)
				{
					$this->clearValue('tm' . $template);

				}
				$this->templatesCached = false;
				self::$building = false;
				return false;
			}

			$size += strlen($template['template'])  + strlen($template['title']);

			$this->setTemplate($template['title'], $template['template']);

		}
		$this->tmRebuilt = vB::getRequest()->getTimeNow();
		self::$building = false;
		return $size;
	}

	/** gets a value
	 *
	 * 	@param	string
	 * 	@param	mixed	string or array of string
	 *
	 *	@return	mixed	the value from fastDS
	 **/
	abstract protected function getValue($prefix, $keys);

	/** sets a value
	 *
	 * 	@param	string	key
	 *	@param	mixed	value to be stored

	 *	@return	bool	true if it succeeded, otherwise false
	 **/
	abstract protected function setValue($key, $value);

	/** sets a value
	 *
	 * 	@param	string	key
	 *	@param	mixed	value to be stored

	 *	@return	bool	true if it succeeded, otherwise false
	 **/
	abstract protected function clearValue($key);

	/** gets a datastore value
	 *
	 * 	@param	mixed	string or array of string
	 *
	 *	@return	mixed	the datastore value
	 **/
	public function getDS($dsKeys)
	{
		if ($this->dsCached)
		{
			//remove any keys we don't cache.
			if ((is_array($dsKeys)))
			{
				foreach($dsKeys AS $index => $dsKey)
				{
					if (isset($this->skipDSCache[$dsKey]))
					{
						unset($dsKeys[$index]);
					}
				}
				if (empty($dsKeys))
				{
					return array();
				}
			}
			else
			{
				if (isset($this->skipDSCache[$dsKeys]))
				{
					return false;
				}
			}
			$result =  $this->getValue('ds', $dsKeys);
			//check to see that it's good.

			if (empty($result))
			{
				//We rebuild the data, but no more often than every fifteen minutes.
				if (vB::getRequest()->getTimeNow() >= $this->dsRebuilt + 900)
				{
					$this->buildDatastore(9999999);
					$this->saveSettings();
					$result = $this->getValue('ds', $dsKeys);
				}
			}
			return $result;
		}
		return false;
	}

	/** sets a datastore value
	 *
	 * 	@param	string	key
	 *	@param	mixed	value to be stored

	 *	@return	bool	true if it succeeded, otherwise false
	 **/
	public function setDS($dsKey, $value)
	{
		if ($this->dsCached)
		{
			return $this->setValue('ds' . $dsKey, $value);
		}
		return false;
	}

	/** gets a phrase, or set of phrases, from the default language
	 *
	 * 	@param	mixed	string or array of strings
	 *  @param	int		languageid. Results are available for default language or -1
	 *
	 *	@return	string
	 **/
	public function getPhrases($varnames, $languageid)
	{
		if ($this->phrasesCached AND (($languageid == $this->language) OR ($languageid == -1)))
		{
			$result =  $this->getValue('ph', $varnames);
			//check to see that it's good.

			if (empty($result))
			{
				//We rebuild the data, but no more often than every fifteen minutes.
				if (vB::getRequest()->getTimeNow() >= $this->phRebuilt + 900)
				{
					$this->buildPhrases(9999999);
					$this->saveSettings();
					$result =  $this->getValue('ph', $varnames);
				}
			}
			return $result;
		}
		return false;
	}

	/** sets a default language phrase
	 *
	 * 	@param	string	key
	 *	@param	mixed	value to be stored

	 *	@return	bool	true if it succeeded, otherwise false
	 **/
	protected function setPhrase($varname, $value)
	{
		if ($this->templatesCached)
		{
			return $this->setValue('ph' . $varname, $value);
		}
		return false;
	}

	/** gets a template from the default style
	 *
	 * 	@param	mixed	string or array of string
	 *  @param	int		style. Results are available for default style or -1
	 *
	 *	@return	string- the template contents
	 **/
	public function getTemplates($templateNames, $styleid)
	{
		if ($this->templatesCached AND (($styleid == $this->styleid) OR ($styleid == -1)))
		{
			$result =  $this->getValue('tm', $templateNames);
			//check to see that it's good.

			if (empty($result))
			{
				//We rebuild the data, but no more often than every fifteen minutes.
				if (vB::getRequest()->getTimeNow() >= $this->tmRebuilt + 900)
				{
					$this->buildTemplates(9999999);
					$this->saveSettings();
					$result =  $this->getValue('tm', $templateNames);
				}
			}

			return $result;
		}
		return false;

	}

	/** sets a template value
	 *
	 * 	@param	string	key
	 *	@param	mixed	value to be stored

	 *	@return	bool	true if it succeeded, otherwise false
	 **/
	protected function setTemplate($title, $value)
	{
		if ($this->templatesCached)
		{
			return $this->setValue('tm' . $title, $value);
		}
		return false;
	}

	/**Sets date for next datastore rebuild.
	*	@param string	title of changed field
	**/
	public function setDsChanged($title)
	{
		if (!array_key_exists($title, $this->skipDSCache))
		{
			$options = vB::getDatastore()->getValue('miscoptions');
			//if either styleid changes we need to reset the template cache.  Simplest way is to clear if
			// options change

			if ($title == 'styleid')
			{
				$options['tmtdate']  = vB::getRequest()->getTimeNow();
			}
			$options['dsdate'] = vB::getRequest()->getTimeNow();

			vB::getDatastore()->build('miscoptions', serialize($options), 1);
		}

	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99788 $
|| #######################################################################
\*=========================================================================*/
