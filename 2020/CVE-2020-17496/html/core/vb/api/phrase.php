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
 * vB_Api_Phrase
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Phrase extends vB_Api
{
	protected $disableWhiteList = array('fetch', 'getPhrases');

	protected $styles = array();
	protected $phrasecache = array();

	/**
	 *
	 * @var vB_Library_Phrase
	 */
	protected $library;

	protected $shortcode_replace_map = array();

	protected function __construct()
	{
		parent::__construct();
		$this->library = vB_Library::instance('phrase');
	}

	/**
	 * Convert phrase text to sprintf format
	 *
	 * @param string $text
	 * @return string
	 */
	private static function convertPhraseText($text)
	{
		if (preg_match('/\{([0-9]+)\}/', $text))
		{
			$search = array(
				'/%/s',
				'/\{([0-9]+)\}/siU',
			);
			$replace = array(
				'%%',
				'%\\1$s',
			);
			$returnText = preg_replace($search, $replace, $text);
		}
		else
		{
			$returnText = $text;
		}

		return $returnText;
	}

	/**
	 * Fetch phrases by group
	 *
	 * @param mixed	Groups(s) to retrieve
	 * @param int $languageid Language ID. If not set, it will use current session's languageid
	 *
	 * @return array Phrase' texts
	 */
	public function fetchByGroup($groups, $languageid = NULL)
	{
		if (empty($groups))
		{
			return array();
		}

		if (!is_array($groups))
		{
			$groups = array($groups);
		}

		if ($languageid === NULL)
		{
			$languageid = $this->getLanguageid()["languageid"];
		}

		$phrasesdata = array();
		$phrasesdata = vB::getDbAssertor()->getRows('phrase', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'fieldname' => $groups,
			'languageid' => array($languageid, 0, -1),
		));

		return $this->parsePhrases($phrasesdata, array(), $languageid);
	}

	/**
	 * Fetch the "best" languageid in the order of current session's languageid,
	 * the default languageid from datastore,  or the master languageid (-1).
	 * This is the languageid that's used by fetch().
	 *
	 * @param bool	$getCharset		(Optional) true to also return charset of current
	 *								languageid. Default false.
	 *
	 * @return array 'languageid' => languageid used for current session's phrases
	 *
	 */
	public function getLanguageid($getCharset = false)
	{
		$languageid = null;
		$currentsession = vB::getCurrentSession();
		if ($currentsession)
		{
			$languageid = $currentsession->get('languageid');
			if (!$languageid)
			{
				$userinfo = vB::getCurrentSession()->fetch_userinfo();
				$languageid = $userinfo['languageid'];
			}
		}

		// Still no languageid, try to get current default languageid
		if (!$languageid)
		{
			$languageid = vB::getDatastore()->getOption('languageid');
		}

		// Still don't have a language, fall back to master language
		if (!$languageid)
		{
			$languageid = -1;
		}

		$returnArray = array('languageid' => $languageid);

		if ($getCharset)
		{
			$charset = vB::getDbAssertor()->getColumn('language', 'charset', array('languageid' => $languageid));
			if ($charset)
			{
				$charset = reset($charset);
			}
			else
			{
				//this is probably wrong, but at this point we really haven't the faintest idea and this is
				//the closest match for the historical behavior (which would return NULL based on some
				//a missing array key).  Since the only reported problem is the notice for the missing key
				//we'll stick with that behavior.
				$charset = '';
			}

			$returnArray['charset'] = $charset;
		}

		return $returnArray;
	}

	/**
	 * Fetch phrases
	 *
	 * @param array $phrases An array of phrase ID to be fetched
	 * @param int $languageid Language ID. If not set, it will use current session's languageid,
	 * 	if passed a 0, use the current user/forum default language.
	 *
	 * @return array -- phraseid => phrase value
	 * @deprecated -- use renderPhrases or getPhrases depending on if you
	 */
	public function fetch($phrases, $languageid = NULL)
	{
		$result = $this->getPhrases($phrases, $languageid);
		return $result['phrases'];
	}

	/**
	 * Fetch raw phrases
	 *
	 * Note that these are *not* suitable for display to the user as is
	 * since many phrases have placeholders and this will not substitute them.
	 * It is available in situations where the client expects to render the
	 * phrases itself (particularly in situations where the phrase can be
	 * cached and reused client side).
	 *
	 * @param array $phrases An array of phrase ID to be fetched
	 * @param int $languageid Language ID. If not set, it will use current session's languageid,
	 * 	if passed a 0, use the current user/forum default language.
	 *
	 * @return array --
	 * 	'phrases' -- array(phraseid => phrase value)
	 */
	public function getPhrases($phrases, $languageid = NULL)
	{
		if (empty($phrases))
		{
			return array('phrases' => array());
		}

		if (!is_array($phrases))
		{
			$phrases = array($phrases);
		}

		if ($languageid === NULL)
		{
			$languageid = $this->getLanguageid()["languageid"];
		}

		//0 means use the default
		if ($languageid == 0)
		{
			$languageid = vB::getDatastore()->getOption('languageid');
		}

		// Unset phrases which have already been fetched
		$phrasestofetch = array();
		$fromcache = array();

		foreach ($phrases AS $phrasevar)
		{
			if (!isset($this->phrasecache[$languageid][$phrasevar]))
			{
				$phrasestofetch[] = $phrasevar;
			}
			else
			{
				$fromcache[] = $phrasevar;
			}
		}

		$return = array();
		if (!empty($phrasestofetch))
		{
			//First try from fastds
			$fastDS =  vB_FastDS::instance();
			if ($fastDS)
			{
				$cached = $fastDS->getPhrases($phrasestofetch, $languageid);
			}
			$phrasesNotFound = array();
			if (!empty($cached))
			{
				foreach ($phrasestofetch as $index => $phraseKey)
				{
					if (!empty($cached[$phraseKey]))
					{
						$return[$phraseKey] = $cached[$phraseKey];
					}
					else
					{
						$phrasesNotFound[$index] = $phrasestofetch[$index];
					}
				}
			}
			else
			{
				$phrasesNotFound = $phrasestofetch;
			}

			if (!empty($phrasesNotFound))
			{
				$phrasesdata = vB::getDbAssertor()->getRows('phrase', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
					'varname' => $phrasesNotFound,
					'languageid' => array($languageid, 0, -1),
					vB_dB_Query::COLUMNS_KEY => array('varname', 'languageid', 'text')
				));
				$parsed = $this->parsePhrases($phrasesdata, $phrases, $languageid);
				$return = array_merge($return, $parsed);
			}

		}

		if (!empty($fromcache))
		{
			foreach ($fromcache AS $phraseid)
			{
				$phrasesdata[$phraseid] = $this->phrasecache[$languageid][$phraseid];
			}

			$parsed = $this->parsePhrases($phrasesdata, $phrases, $languageid);
			$return = array_merge($return, $parsed);
		}

		return array('phrases' => $return);
	}

	/**
	 * Handled output from query from fetch() and fetchByGroup()
	 *
	 * @param	array	Phrases from db
	 * @param	array	Phrases sent into to get from the db
	 *
	 * @return array	Phrases phrases
	 */
	protected function parsePhrases($phrasesdata, $phrases = array(), $languageid = -1)
	{
		$realphrases = array();
		foreach ($phrasesdata AS $phrase)
		{
			// User-selected language (>=1) overwrites custom phrase (0), which overwrites master language phrase (-1)
			if (empty($realphrases[$phrase['varname']]) OR $realphrases[$phrase['varname']]['languageid'] < $phrase['languageid'] )
			{
				$realphrases[$phrase['varname']] = $phrase;
			}
		}

		if(!isset($this->phrasecache[$languageid]))
		{
			$this->phrasecache[$languageid] = array();
		}

		$this->phrasecache[$languageid] = array_merge($this->phrasecache[$languageid], $realphrases);

		foreach ($phrases AS $phrasevar)
		{
			if (empty($realphrases[$phrasevar]) AND !empty($this->phrasecache[$languageid][$phrasevar]))
			{
				$realphrases[$phrasevar] = $this->phrasecache[$languageid][$phrasevar];
			}
		}

		$return = array();
		foreach ($realphrases AS $phrase)
		{
			// TODO: store this somewhere? -- might as well store phrases converted now to
			// stop all this real time conversion
			$return[$phrase['varname']] = self::convertPhraseText($phrase['text']);
		}

		return $return;
	}

	/**
	 * Fetch orphan phrases
	 * @return array Orphan phrases
	 */
	public function fetchOrphans()
	{
		$this->checkHasAdminPermission('canadminlanguages');
		$phrases = vB::getDbAssertor()->getRows('phrase_fetchorphans', array());
		return $phrases;
	}

	/**
	 * Process orphan phrases
	 * @param array $del Orphan phrases to be deleted. In format array('varname@fieldname')
	 * @param array $keep Orphan phrases to be kept
	 * @return void
	 */
	public function processOrphans($del, $keep)
	{
		$this->checkHasAdminPermission('canadminlanguages');

		require_once(DIR . '/includes/adminfunctions_language.php');

		if ($del)
		{
			vB::getDbAssertor()->assertQuery('deleteOrphans', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD,
				'del' => $del,
			));
		}

		if ($keep)
		{
			vB::getDbAssertor()->assertQuery('keepOrphans', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD,
				'keep' => $keep,
			));
		}
	}

	/**
	 * Find custom phrases that need updating
	 * @return array Updated phrases
	 */
	public function findUpdates()
	{
		$this->checkHasAdminPermission('canadminlanguages');

		// query custom phrases
		$customcache = array();
		$phrases = vB::getDbAssertor()->assertQuery('phrase_fetchupdates', array());
		foreach ($phrases as $phrase)
		{
			//this is probably really old and its unlikely that there is a older custom
			//phrase.  We probably couldn't tell if there was in any case.
			if ($phrase['globalversion'] == '')
			{
				continue;
			}

			//if we don't have a customversion the phrase is likely old or otherwise needs looking at.
			//note that some ad hoc "langauge 0" phrases don't have custom versions but they
			if ($phrase['customversion'] == '' OR vB_Library_Functions::isNewerVersion($phrase['globalversion'], $phrase['customversion']))
			{
				if (!$phrase['product'])
				{
					$phrase['product'] = 'vbulletin';
				}

				$customcache["$phrase[languageid]"]["$phrase[phraseid]"] = $phrase;
			}
		}

		return $customcache;
	}

	/**
	 * Search phrases
	 * @param array $criteria Criteria to search phrases. It may have the following items:
	 *              'searchstring'	=> Search for Text
	 *              'searchwhere'	=> Search in: 0 - Phrase Text Only, 1 - Phrase Variable Name Only, 2 - Phrase Text and  Phrase Variable Name
	 *              'casesensitive' => Case-Sensitive 1 - Yes, 0 - No
	 *              'exactmatch'	=> Exact Match 1 - Yes, 0 - No
	 *              'languageid'	=> Search in Language. The ID of the language
	 *              'phrasetype'	=> Phrase Type. Phrase group IDs to search in.
	 *              'transonly'		=> Search Translated Phrases Only  1 - Yes, 0 - No
	 *              'product'		=> Product ID to search in.
	 *
	 * @return array Phrases
	 */
	public function search($criteria)
	{
		//This should only be called from admincp, and the permission there is 'canadminlanguages'.
		if (!vB::getUserContext()->hasAdminPermission('canadminlanguages'))
		{
			throw new vB_Exception_Api('no_permission');
		}

		//if searchstring is not set, throw exception
		if ($criteria['searchstring'] == '')
		{
			throw new vB_Exception_Api('please_complete_required_fields');
		}
		$criteria['searchstring'] = vB::getCleaner()->clean($criteria['searchstring'], vB_Cleaner::TYPE_STR);

		//if searchwhere criteria is not set, defaults to 0 - Phrase Text Only search, mimicking admincp phrase search settings
		if (!isset($criteria['searchwhere']))
		{
			$criteria['searchwhere'] = 0;
		}
		$criteria['searchwhere'] = vB::getCleaner()->clean($criteria['searchwhere'], vB_Cleaner::TYPE_INT);

		//if casesensitive criteria is not set, defaults to 0, mimicking admincp phrase search settings
		if (!isset($criteria['casesensitive']))
		{
			$criteria['casesensitive'] = 0;
		}
		$criteria['casesensitive'] = vB::getCleaner()->clean($criteria['casesensitive'], vB_Cleaner::TYPE_INT);

		//if exactmatch criteria is not set, defaults to 0, mimicking admincp phrase search settings
		if (!isset($criteria['exactmatch']))
		{
			$criteria['exactmatch'] = 0;
		}
		$criteria['exactmatch'] = vB::getCleaner()->clean($criteria['exactmatch'], vB_Cleaner::TYPE_INT);

		//if language criteria is not set, defaults to -10, mimicking admincp phrase search settings
		if(!isset($criteria['languageid']))
		{
			$criteria['languageid'] = -10;
		}
		$criteria['languageid'] = vB::getCleaner()->clean($criteria['languageid'], vB_Cleaner::TYPE_INT);

		//if transonly criteria is not set, defaults to 0, mimicking admincp phrase search settings
		if (!isset($criteria['transonly']))
		{
			$criteria['transonly'] = 0;
		}
		$criteria['transonly'] = vB::getCleaner()->clean($criteria['transonly'], vB_Cleaner::TYPE_INT);

		//if product criteria is not set, defaults to all products, mimicking admincp phrase search settings
		if(!isset($criteria['product']))
		{
			$criteria['product']='';
		}
		$criteria['product'] = vB::getCleaner()->clean($criteria['product'], vB_Cleaner::TYPE_STR);


		$phrases = vB::getDbAssertor()->getRows('searchPhrases', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD,
			'criteria' => $criteria,
		));

		if (empty($phrases))
		{
			return array();
		}

		$phrasearray = array();
		foreach ($phrases as $phrase)
		{
			// check to see if the languageid is already set
			if ($criteria['languageid'] > 0 AND isset($phrasearray["$phrase[fieldname]"]["$phrase[varname]"]["{$criteria['languageid']}"]))
			{
				continue;
			}
			$phrasearray["{$phrase['fieldname']}"]["{$phrase['varname']}"]["{$phrase['languageid']}"] = $phrase;
		}

		return $phrasearray;
	}

	/**
	 * Find and replace phrases in languages
	 *
	 * @param array $replace A list of phrase ID to be replaced
	 * @param string $searchstring Search string
	 * @param string $replacestring Replace string
	 * @param int $languageid Language ID
	 * @return void
	 */
	public function replace($replace, $searchstring, $replacestring, $languageid)
	{
		$this->checkHasAdminPermission('canadminlanguages');

		if (empty($replace))
		{
			throw new vB_Exception_Api('please_complete_required_fields');
		}

		$userinfo = vB::getCurrentSession()->fetch_userinfo();

		require_once(DIR . '/includes/adminfunctions.php');
		$full_product_info = fetch_product_list(true);

		$phrases = vB::getDbAssertor()->assertQuery('phrase', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'phraseid' => $replace
		));

		$products =array();

		foreach ($phrases as $phrase)
		{
			$phrase['product'] = (empty($phrase['product']) ? 'vbulletin' : $phrase['product']);
			$phrase['text'] = str_replace($searchstring, $replacestring, $phrase['text']);

			if ($phrase['languageid'] == $languageid)
			{ // update
				vB::getDbAssertor()->assertQuery('phrase', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
					'text' => $phrase['text'],
					'username' => $userinfo['username'],
					'dateline' => vB::getRequest()->getTimeNow(),
					'version' => $full_product_info["$phrase[product]"]['version'],
					vB_dB_Query::CONDITIONS_KEY => array(
						'phraseid' => $phrase['phraseid']
					)
				));
			}
			else
			{ // insert
				/*insert query*/
				vB::getDbAssertor()->assertQuery('phrase_replace', array(
					'languageid' => $languageid,
					'varname' => $phrase['varname'],
					'text' => $phrase['text'],
					'fieldname' => $phrase['fieldname'],
					'product' => $phrase['product'],
					'username' => $userinfo['username'],
					'dateline' => vB::getRequest()->getTimeNow(),
					'version' => $full_product_info["$phrase[product]"]['version'],
				));
			}
			$products[$phrase['product']] = 1;
		}
		$this->library->setPhraseDate();
		return array_keys($products);
	}

	/**
	 * Delete a phrase
	 * @param int $phraseid Pharse ID to be deleted
	 * @return void
	 */
	public function delete($phraseid)
	{
		$this->checkHasAdminPermission('canadminlanguages');

		$getvarname = vB::getDbAssertor()->getRow('phrase', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'phraseid' => $phraseid,
		));

		if ($getvarname)
		{
			vB::getDbAssertor()->assertQuery('phrase', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
				'varname' => $getvarname['varname'],
				'fieldname' => $getvarname['fieldname'],
			));

			require_once(DIR . '/includes/adminfunctions.php');
			require_once(DIR . '/includes/adminfunctions_language.php');
			build_language(-1);
		}
		else
		{
			throw new vB_Exception_Api('invalid_phrase_specified');
		}
		return $getvarname;
	}

	/**
	 * Add a new phrase or update an existing phrase
	 * @param string $fieldname New Phrase Type for adding, old Phrase Type for editing
	 * @param string $varname New Varname for adding, old Varname for editing
	 * @param array $data Phrase data to be added or updated
	 *              'text' => Phrase text array.
	 *              'oldvarname' => Old varname for editing only
	 *              'oldfieldname' => Old fieldname for editing only
	 *              't' =>
	 *              'ismaster' =>
	 *              'product' => Product ID of the phrase
	 *
	 * @return standard success array
	 */
	public function save($fieldname, $varname, $data)
	{
		$this->checkHasAdminPermission('canadminlanguages');

		$this->library->save($fieldname, $varname, $data);

		return array('success' => true);
	}

	/**
	 * Fetches an array of existing phrase types from the database
	 *
	 * @param	boolean	If true, will return names run through ucfirst()
	 *
	 * @return	array
	 */
	public function fetch_phrasetypes($doUcFirst = false)
	{
		$out = array();
		$phrasetypes = vB::getDbAssertor()->assertQuery('phrasetype', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			vB_dB_Query::CONDITIONS_KEY => array(
				array('field' => 'editrows', 'value' => '0', 'operator' => vB_dB_Query::OPERATOR_NE)
			)
		));
		foreach ($phrasetypes as $phrasetype)
		{
			$out["{$phrasetype['fieldname']}"] = $phrasetype;
			$out["{$phrasetype['fieldname']}"]['field'] = $phrasetype['title'];
			$out["{$phrasetype['fieldname']}"]['title'] = ($doUcFirst ? ucfirst($phrasetype['title']) : $phrasetype['title']);
		}
		ksort($out);

		return $out;
	}

	/**
	 * Returns message and subject for an email.
	 *
	 * This does NOT insert the {shortcode} substitutions, that is done
	 * in the mail send() function where we know the recipient's username, etc.
	 *
	 * @param string $email_phrase Name of email phrase to fetch
	 * @param array $email_vars Variables for the email message phrase
	 * @param array $emailsub_vars Variables for the email subject phrase
	 * @param int $languageid Language ID from which to pull the phrase (see fetch_phrase $languageid)
	 * 	note that 0 means forum default language while null means the language for the current user.
	 * 	The former is the better default for this function because we rarely send email to the current
	 * 	user.  However we should really be passing that in consistantly.
	 * @param string	$emailsub_phrase If not empty, select the subject phrase with the given name
	 *
	 * @return array
	 */
	public function fetchEmailPhrases($email_phrase, $email_vars = array(), $emailsub_vars = array(), $languageid = 0, $emailsub_phrase = '')
	{
		if (empty($emailsub_phrase))
		{
			$emailsub_phrase = $email_phrase . '_gemailsubject';
		}

		$email_phrase .= '_gemailbody';

		$vbphrases = $this->getPhrases(array($email_phrase, $emailsub_phrase), $languageid);

		return array(
			'message' => $this->renderPhrase($vbphrases['phrases'][$email_phrase], $email_vars),
			'subject' => $this->renderPhrase($vbphrases['phrases'][$emailsub_phrase], $emailsub_vars),
		);
	}

	/**
	 * Returns message and subject for sending a private message
	 * (would also work for notifications if needed)
	 *
	 * This inserts the {shortcode} substitutions.
	 *
	 * This is intended to be a replacement for fetchEmailPhrases() and should be used
	 * in its place when the phrases are going to be used for a notification or private
	 * message sent within vBulletin. fetchEmailPhrases() should be used when sending
	 * an actual email. The function signature is the same with the exception of $userid
	 * as the *first* parameter, done this way since it is not optional.
	 *
	 * @param int $userid User ID of the recipient of the message.
	 * @param string $email_phrase Name of email phrase to fetch
	 * @param array $email_vars Variables for the email message phrase
	 * @param array $emailsub_vars Variables for the email subject phrase
	 * @param int $languageid Language ID from which to pull the phrase (see fetch_phrase $languageid)
	 * 	note that 0 means forum default language while null means the language for the current user.
	 * 	The former is the better default for this function because we rarely send email to the current
	 * 	user.  However we should really be passing that in consistantly.
	 * @param string	$emailsub_phrase If not empty, select the subject phrase with the given name
	 *
	 * @return array
	 */
	public function fetchPrivateMessagePhrases($userid, $email_phrase, $email_vars = array(), $emailsub_vars = array(), $languageid = 0, $emailsub_phrase = '')
	{
		if (!$languageid)
		{
			// since know who the recipient is, we can use their language preference
			$user = vB::getDbAssertor()->getRow('user', array('userid' => $userid));
			$languageid = (int) $user['languageid'];

			if (!$languageid)
			{
				$options = vB::getDatastore()->getValue('options');
				$languageid = (int) $options['languageid'];
			}
		}

		$phrases = $this->fetchEmailPhrases($email_phrase, $email_vars, $emailsub_vars, $languageid, $emailsub_phrase);

		// add the {shortcode} substitutions to the phrases
		$phrases = $this->doShortcodeReplacements($phrases, $userid);

		return $phrases;
	}

	private function doShortcodeReplacements($phrases, $userid = null)
	{
		$options = vB::getDatastore()->getValue('options');

		// Phrase {shortcode} replacements
		// This replacement happens in several places. Please keep them synchronized.
		// You can search for {shortcode} in php and js files.
		if (empty($this->shortcode_replace_map))
		{
			$this->shortcode_replace_map = array (
				'{sitename}'        => $options['bbtitle'],
				'{musername}'       => '{musername}',
				'{username}'        => '{username}',
				'{userid}'          => '{userid}',
				'{registerurl}'     => vB5_Route::buildUrl('register|fullurl'),
				'{activationurl}'   => vB5_Route::buildUrl('activateuser|fullurl'),
				'{helpurl}'         => vB5_Route::buildUrl('help|fullurl'),
				'{contacturl}'      => vB5_Route::buildUrl('contact-us|fullurl'),
				'{homeurl}'         => $options['frontendurl'],
				'{date}'            => vbdate($options['dateformat']),
				// ** leave deprecated codes in to avoid breaking existing data **
				// deprecated - the previous *_page codes have been replaced with the *url codes
				'{register_page}'   => vB5_Route::buildUrl('register|fullurl'),
				'{activation_page}' => vB5_Route::buildUrl('activateuser|fullurl'),
				'{help_page}'       => vB5_Route::buildUrl('help|fullurl'),
				// deprecated - session url codes are no longer needed
				'{sessionurl}'      => '',
				'{sessionurl_q}'    => '',
			);
		}

		// update user-specific information for each recipient
		if($userid)
		{
			$user_replacements = vB_Library::instance('user')->getEmailReplacementValues('', $userid);
			$this->shortcode_replace_map['{musername}'] = $user_replacements['{musername}'];
			$this->shortcode_replace_map['{username}'] = $user_replacements['{username}'];
			$this->shortcode_replace_map['{userid}'] = $user_replacements['{userid}'];
		}
		else
		{
			$session = vB::getCurrentSession();
			$userInfo = $session->fetch_userinfo();
			$this->shortcode_replace_map['{musername}'] = $userInfo['musername'];
			$this->shortcode_replace_map['{username}'] = $userInfo['username'];
			$this->shortcode_replace_map['{userid}'] = $userInfo['userid'];
		}

		// do the replacement
		$shortcode_find = array_keys($this->shortcode_replace_map);
		foreach ($phrases AS $k => $v)
		{
			$phrases[$k] = str_replace($shortcode_find, $this->shortcode_replace_map, $phrases[$k]);
		}

		return $phrases;
	}

	/**
	 * Replaces {shortcodes} in a string
	 *
	 * The phrase API might not be the best place for this function, since it just replaces
	 * shortcodes in an arbitrary string. But these shortcodes are mostly associated with
	 * phrases, so it makes the most sense right now. It also simplifies things, as we can
	 * reuse the doShortcodeReplacements function.
	 *
	 * @param  string The string of text containing the {shortcode} placeholders
	 *
	 * @return string The string with the {shortcodes} replaced with their corresponding values.
	 */
	public function replaceShortcodesInString($string)
	{
		// This function is only intended to replace shortcode values for the current user.

		$values = array();
		$values['arbitrary_string'] = (string) $string;

		$values = $this->doShortcodeReplacements($values);

		return $values['arbitrary_string'];
	}

	/**
	 *	Returns rendered phrases from phrase strings and/or data
	 *
	 *	@param array $phrases.  Array of phrases to rendered.  Each item is either a phrase_string or an array of
	 *		form (phrase_string, param1, param2, ...) (standard phrase format).  The keys of this array will be
	 *		preserved and used to index the corresponding rendered phrase on return.
	 *
	 *	@param int $languageid. The languageid to use to render the phrases.  The default (null) means use the
	 *		value for the current session/user.  The value of 0 means use the site default -- this should generally
	 *		not be passed as a hardcoded value but is useful because that is a value the user can set as their
	 *		languge.
	 *
	 *	@return array
	 *		'phrases' => array('key' => rendered phrase)
	 */
	public function renderPhrases($phrases, $languageid = null)
	{
		return $this->renderPhrasesInternal($phrases, $languageid, true);
	}

	/**
	 *	Returns rendered phrases from phrase strings and/or data
	 *
	 *	In some circumstances, primarily email, we need to defer shortcode replacement
	 *	because we need to handle things for a user other than the current logged in
	 *	user (many of the shortcodes are user specific).  This allows us to do that.
	 *
	 *	@param array $phrases.  Array of phrases to rendered.  Each item is either a phrase_string or an array of
	 *		form (phrase_string, param1, param2, ...) (standard phrase format).  The keys of this array will be
	 *		preserved and used to index the corresponding rendered phrase on return.
	 *
	 *	@param int $languageid. The languageid to use to render the phrases.  The default (null) means use the
	 *		value for the current session/user.  The value of 0 means use the site default -- this should generally
	 *		not be passed as a hardcoded value but is useful because that is a value the user can set as their
	 *		languge.
	 *
	 *	@return array
	 *		'phrases' => array('key' => rendered phrase)
	 */
	public function renderPhrasesNoShortcode($phrases, $languageid = null)
	{
		return $this->renderPhrasesInternal($phrases, $languageid, false);
	}

	private function renderPhrasesInternal($phrases, $languageid, $doShortcodes)
	{
		$phrasemap = array();
		$args = array();

		foreach($phrases AS $key => $phrase)
		{
			if(is_array($phrase))
			{
				$phrasemap[$key] = array_shift($phrase);
				$args[$key] = $phrase;
			}
			else
			{
				$phrasemap[$key] = $phrase;
				$args[$key] = array();
			}
		}

		$vbphrases = $this->getPhrases(array_unique($phrasemap), $languageid);
		$vbphrases = $vbphrases['phrases'];

		if($doShortcodes)
		{
			$vbphrases = $this->doShortcodeReplacements($vbphrases);
		}

		$return = array();
		foreach($phrasemap AS $key => $phrase)
		{
			if (isset($vbphrases[$phrase]))
			{
				$return[$key] = $this->renderPhrase($vbphrases[$phrase], $args[$key]);
			}
			else
			{
				$return[$key] = $phrase;
			}
		}

		return array('phrases' => $return);
	}

	private function renderPhrase($phrasestring, $args)
	{
		//nothing to replace, just return the string
		if(!count($args))
		{
			return $phrasestring;
		}

		$phrase = @vsprintf($phrasestring, $args);
		if($phrase !== false)
		{
			return $phrase;
		}
		else
		{
			//something went wrong -- let's put in some dummy args to ty to get
			//something vaguely valid.
			for ($i = count($args); $i < 10; $i++)
			{
				$args[$i] = '[ARG:' . ($i + 1) . ' UNDEFINED]';
			}

			$phrase = @vsprintf($phrasestring, $args);
			if($phrase !== false)
			{
				return $phrase;
			}
			// if it still doesn't work, just return the un-parsed text
			else
			{
				return $phrasestring;
			}
		}
	}

	/**
	 * Clears the phrase cache, needed primarily for unit test.
	 */
	public function clearPhraseCache()
	{
		$this->phrasecache = array();
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103756 $
|| #######################################################################
\*=========================================================================*/
