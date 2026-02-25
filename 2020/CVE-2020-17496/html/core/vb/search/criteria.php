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
 * Class to handle state about the requested search.
 * Handles capturing user level search terms and drilling them down to
 * a form more digestable to search implementations.  Handles creating
 * a user readable display of the search requested.  Stores search terms
 * for creation of a backlink reference.
 *
 * Insuffienct thought was given to how to store the search values internally.
 * That is, what needs to be persisted and what can be generated on each
 * load of the object.  We are storing more than we need to and there is
 * some duplication of effort in terms of passing all of the required
 * information to the object.  It works though, so its not a high priority to
 * change
 *
 */
/**
 * vB_Search_Criteria
 *
 * @package vBulletin
 * @subpackage Search
 * @author ebrown
 * @copyright Copyright (c) 2009
 * @version $Id: criteria.php 103374 2019-11-05 01:31:14Z jinsoojo.ib $
 * @access public
 */
class vB_Search_Criteria
{
	use vB_Trait_NoSerialize;

	//**************************************************************************
	//Basic filter functions

	/**
	 * vB_Search_Criteria::add_filter()
	 * This function adds a generic filter to the criteria.
	 *
	 * Should generally be used either internally in the criteria object, or in
	 * the add_advanced_fields function on the search type objects.  Search
	 * consumers should generally be calling higher level functions.
	 *
	 * @param string $field
	 * @param integer $op
	 * @param mixed $value This can be a single value, or an array of values
	 * @param boolean $is_restrictive Is this filter restrictive?  At least one
	 *	restrictive filter needs to be set to have a valid search.
	 * @return nothing
	*/
	public function add_filter($field, $op, $value, $is_restrictive = false, $is_additive = false)
	{
		if ($is_additive)
		{
			if (empty($this->filters[$field][$op]))
			{
				$this->filters[$field][$op] = $value;
			}
			elseif (is_array($this->filters[$field][$op]))
			{
				if (is_array($value))
				{
					$this->filters[$field][$op] += $value;
				}
				else
				{
					$this->filters[$field][$op][] = $value;
				}
			}
			else
			{
				$temp = $this->filters[$field][$op];
				$this->filters[$field][$op][] = $temp;
				$this->filters[$field][$op][] = $value;
			}
		}
		else
		{
			$this->filters[$field][$op] = $value;
		}
		if ($is_restrictive)
		{
			$this->criteria_set = true;
		}
	}

	public function reset_filter($field)
	{
		unset($this->filters[$field]);
	}

	public function setUser($userid)
	{
		$this->current_user = $userid;
	}

	public function getCurrentUser()
	{
		return $this->current_user;
	}

	function set_include_sticky($set = true)
	{
		$this->include_sticky = $set;
	}

	function get_include_sticky()
	{
		return $this->include_sticky;
	}

	/**
	 * Set the sort
	 *
	 * Only allow single field sorts
	 *
	 * @param string $field
	 * @param unknown_type $direction
	 */
	public function set_sort($field, $direction, $is_additive = true)
	{
		//handle variations on sort fields.
		// todo: search API sets direction to strtoupper, now we set it to strtolower...
		// but the querydefs generally prefers upper case .... what?
		$direction = strtolower($direction);
		if (strpos($direction, 'desc') === 0)
		{
			$direction = 'desc';
		}
		else
		{
			$direction = 'asc';
		}
		if (!$is_additive)
		{
			$this->sort = array();
		}
		$this->sort[strtolower($field)] = $direction;

		// API's search allows keyword to be empty
		if (defined('VB_API') AND VB_API === true)
		{
			$this->criteria_set = true;
		}
	}

	//**************************************************************************
	//High level filter functions

	/**
	 *	Filter by contenttype
	 */
	public function add_contenttype_filter($contenttypeid, $op = vB_Search_Core::OP_EQ)
	{
		$this_type = array();
		if (! is_array($contenttypeid))
		{
			$contenttypeid = array($contenttypeid);
		}

		foreach ($contenttypeid AS $contenttype)
		{
			$contenttype_id = vB_Types::instance()->getContentTypeID($contenttype);

			if (empty($contenttype_id) OR !is_numeric($contenttype_id))
			{
				$this->add_null_filter("Content type $contenttype does not exist.");
				continue;
			}
			$this_type[] = $contenttype_id;
		}
		if (empty($this_type))
		{
			return array();
		}
		$this->add_filter('contenttypeid', $op, $this_type);
		return $this_type;
	}

	/**
	 *	Set the keywords
	 *
	 *	@param string $keywords
	 * @param bool $titleonly true if onl
	 */
	public function add_keyword_filter($keywords, $titleonly)
	{
		if (!trim($keywords))
		{
			return;
		}
		$this->raw_keywords = $keywords;
		$this->titleonly = $titleonly;

		//this needs to be before sanitize for historical reasons.
		//sanitize probably needs to go away, but now is not the time.

		//$keywords = $this->quote_problem_words($keywords);

		$errors = array();
		$keywords = $this->sanitize_search_query($keywords, $errors);

		if (count($errors))
		{
			$this->errors = array_merge($this->errors, $errors);
			return;
		}

		//parse the query string into the words array.
		$words = $this->get_words($keywords);
		$this->keywords = $words;

// 		//set the keywords display
// 		$display_string = $this->format_keyword_display_string($words);
// 		$this->set_keyword_display_string($display_string);

// 		//set the words to highlight
// 		$highlights = array();
// 		foreach ($words as $word_item)
// 		{
// 			if ($word_item['joiner'] != 'NOT')
// 			{
// 				$highlights[] = $word_item['word'];
// 			}
// 		}
// 		$this->set_highlights($highlights);
		$this->criteria_set = true;
		return $words;
	}

	public function reset_keyword_filter()
	{
		unset($this->keywords, $this->raw_keywords, $this->titleonly);
	}

	public function reset_post_processors()
	{
		$this->post_processors = array();
	}

	/**
	 *	Set the user filter
	 *
	 * @param string $username.  The name of the user.
	 * @param bool $exactname.  If we should only look for an exact match
	 * @param enum $groupuser.  If we should only search for the group user, the item user,
	 *  or the default for the search type. On of the group constants in vB_Search_Core
	 */
	public function add_user_filter($username, $exactmatch)
	{
		//we don't actually have a username, do nothing.
		if (!trim($username))
		{
			return;
		}

		if (!$exactmatch AND strlen($username) < 3)
		{
			$this->add_error('searchnametooshort');
			return array();
		}

		$username = vB_String::htmlSpecialCharsUni($username);
		if ($exactmatch)
		{
			$user = vB_Api::instanceInternal("User")->fetchByUsername($username, array(vB_Api_User::USERINFO_AVATAR));
			$userid = empty($user['userid']) ? false : $user['userid'];
		}
		else
		{
			$userid = vB::getDbAssertor()->getColumn(
				'user', 'userid', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
					vB_dB_Query::CONDITIONS_KEY => array(
							array('field' => 'username', 'value' => "$username", 'operator' => vB_dB_Query::OPERATOR_INCLUDES)
					),
					array('field' => 'username', 'direction' => vB_dB_Query::SORT_ASC)
				)
			);
		}
		if (empty($userid))
		{
			$this->add_null_filter("$username not found");
		}
		else
		{
			$this->add_filter('userid', vB_Search_Core::OP_EQ, $userid, true);
		}
		return $userid;
	}

	/**
	 *	Add a filter for a tag
	 *
	 *	@param string $tag - the tag string to filter on
	 */
	public function add_tag_filter($tags)
	{
		require_once(DIR . '/includes/class_taggablecontent.php');
		if (!is_array($tags))
		{
			$tags = vB_Taggable_Content_Item::split_tag_list($tags);
		}

		$query = vB::getDbAssertor()->assertQuery('vBForum:tag', array(
			vB_dB_Query::TYPE_KEY=>vB_dB_Query::QUERY_SELECT,
			'tagtext' => $tags
		));

		$tags_not_found = array_flip($tags);
		$existing_tags = array();
		$synonyms = array();
		foreach($query AS $row)
		{
			unset($tags_not_found[$row['tagtext']]);
			if ($row['canonicaltagid'] == 0)
			{
				$existing_tags[$row['tagtext']] = $row['tagid'];
			}
			else
			{
				$synonyms[] = $row['canonicaltagid'];
			}
		}
		$tags_not_found = array_keys($tags_not_found);

		$canonical = vB_Api::instanceInternal('tags')->getTags(array_unique($synonyms));
		foreach($canonical['tags'] AS $row)
		{
			$existing_tags[$row['tagtext']] = $row['tagid'];
		}

		$this->add_filter('tag', vB_Search_Core::OP_EQ, $existing_tags, true);
		if (!empty($tags_not_found))
		{
			foreach ($tags_not_found as $tag)
			{
				$this->add_null_filter("Tag $tag does not exist.");
			}
		}
		return $existing_tags;
	}

	/**
	 * Add a filter for date
	 *
	 * @param ???? direction
	 * @param ???? the dateline to limit the query to.
	 */
	public function add_date_filter($direction, $dateline)
	{
		$this->add_filter('publishdate', $direction, $dateline, true);
	}

	/**
	 * Add a filter for date
	 *
	 * @param ???? direction
	 * @param ???? the dateline to limit the query to.
	 */
	public function add_last_filter($direction, $dateline)
	{
		$this->add_filter('lastcontent', $direction, $dateline, true);
	}

	/**
	 * Add a channel filter
	 * @param int $channelId
	 * @param bool $include_starter - flag to include the node itself into the list of children
	 */
	public function add_channel_filter($channelId, $depth = false, $include_starter = false, $depth_exact = false)
	{
		if (empty($channelId))
		{
			return;
		}

		$this->add_filter('channelid', vB_Search_Core::OP_EQ, $channelId, true, true);
		if ($include_starter)
		{
			$this->include_starter = true;
		}

		if (!empty($depth))
		{
			$this->depth = intval($depth);
		}

		if (!empty($depth_exact))
		{
			$this->depth_exact = true;
		}

	}

	/**
	 * Add a complex channel filter
	 */
	public function add_inc_exc_channel_filter($filterChannels)
	{
		// This is set by the runtime vB5_Template_Runtime::parseJSON() which is called when the search template
		// calls vb:compilesearch on the json
		$currentChannelid = $filterChannels['currentChannelid'] ?? 0;
		$cleaned = vB_Library::instance('widget')->cleanFilterNodes($filterChannels, $currentChannelid);
		/*
		$filterType = $cleaned['filterType'];
		$filterChannels = $cleaned['filterChannels'];
		$includeChildren = $cleaned['includeChildren'];
		*/
		if (empty($cleaned['filterChannels']))
		{
			return;
		}

		$this->add_filter('inc_exc_channel', vB_Search_Core::OP_COMPLEX, $cleaned, true, false);
	}

	/**
	 * Add a follow filter
	 * @param int $userId
	 */
	public function add_follow_filter($type, $userid)
	{
		$this->add_filter('follow', vB_Search_Core::OP_EQ, array('type' => $type, 'userid' => $userid));
	}

	/**
	 * Add an exclude filter. Will exclude that node's children from the results
	 * @param array|int $nodeId
	 */
	public function add_exclude_filter($nodeids)
	{
		if (!is_array($nodeids))
		{
			$nodeids = array($nodeids);
		}
		$this->add_filter('exclude', vB_Search_Core::OP_NEQ, $nodeids, false, true);
	}
	/**
	 * Adds special handleing for different views
	 * @param string $view
	 */
	public function add_view_filter($view)
	{
		$this->add_filter('view', vB_Search_Core::OP_EQ, $view);
		/* add post processing filters*/
		switch ($view)
		{
			/**
			 * only include the latest reply or comment (or the starter itself if no replies/comments yet) per starter in all the channels.
			 * Filters out the Channel nodes from the Search API nodes results.
			 * @include replies/comments in the second phase
			 */
			case vB_Api_Search::FILTER_VIEW_ACTIVITY :
				//this may be obsolete, but removing commented out call to removed method query
				break;
				/**
				 * The Topic view should only display the starter nodes for the specified channel.
				 * Filters out the Channel nodes from the Search API nodes results.
				 */
			case vB_Api_Search::FILTER_VIEW_TOPIC :
				break;
				/**
				 * The Conversation Detail view should only display the descendant nodes of (and including) the specified starter.
				 * Filters out the Comment node from the Search API nodes results.
				 */
			case vB_Api_Search::FILTER_VIEW_CONVERSATION_THREAD :
				break;
				/**
				 * The Conversation Detail view should only display the descendant nodes of (and including) the specified starter.
				 * the Comment nodes are not filtered out.
				 */
			case vB_Api_Search::FILTER_VIEW_CONVERSATION_STREAM :
				break;
			case vB_Api_Search::FILTER_VIEW_CONVERSATION_THREAD_SEARCH :
				$this->add_post_processors('PostProcessorAddComments');
				break;
		}

	}

	/**
	 * forces a 0 result query and adds a message to the query
	 * @param unknown_type $message
	 */
	public function add_null_filter($message)
	{
		$this->add_filter('null', vB_Search_Core::OP_EQ, $message);
	}

	public function add_post_processors($processor)
	{
		$this->post_processors[] = $processor;
	}

	public function get_post_processors()
	{
		return $this->post_processors;
	}
	//**************************************************************************
	//High level filter retrieval functions

	/**
	 * @deprecated We need a cleaner way to get at the filters on the
	 * search implementation side.
	 */
	public function get_filters($field)
	{
		if (isset($this->filters[$field]))
		{
			return $this->filters[$field];
		}
		else
		{
			return array();
		}
	}

	/**
	 *	Get the equals filters defined
	 * @return array Array of $filtername => $value for equals filters
	 * 	$value can either be a scalar or an array
	 */
	public function get_equals_filter($name, $force_array=false)
	{
		$filter = null;
		if (isset($this->filters[$name][vB_Search_Core::OP_EQ]))
		{
			$filter = $this->filters[$name][vB_Search_Core::OP_EQ];
			if ($force_array AND !is_array($filter))
			{
				$filter = array($filter);
			}
		}
		return $filter;
	}

	/**
	 *	Get the equals filters defined
	 * @return array Array of $filtername => $value for equals filters
	 * 	$value can either be a scalar or an array
	 */
	public function get_equals_filters($filterset = 'filters')
	{
		$return = array();
		foreach ($this->$filterset as $field => $field_filters)
		{
			if (isset($field_filters[vB_Search_Core::OP_EQ]))
			{
				$return[$field] = $field_filters[vB_Search_Core::OP_EQ];
			}
		}
		return $return;
	}

	/**
	 *	Get the complex filters defined
	 * @return array Array of $filtername => $value for complex filters
	 * 	$value can either be a scalar or an array, but is likely an array
	 */
	public function get_complex_filters($filterset = 'filters')
	{
		$return = array();
		foreach ($this->$filterset as $field => $field_filters)
		{
			if (isset($field_filters[vB_Search_Core::OP_COMPLEX]))
			{
				$return[$field] = $field_filters[vB_Search_Core::OP_COMPLEX];
			}
		}
		return $return;
	}

	public function has_topic_view_filter()
	{
		$viewTopics = (
			isset($this->filters['view'][vB_Search_Core::OP_EQ]) AND
			($this->filters['view'][vB_Search_Core::OP_EQ] == vB_Api_Search::FILTER_VIEW_TOPIC)
		);

		return $viewTopics;
	}

	/*
		Check if criteria has one of the basic OP_EQ filters, e.g.
		starter_only
		reply_only
	 */
	public function has_bool_filter_for($filter)
	{
		return isset($this->filters[$filter][vB_Search_Core::OP_EQ]);
	}

	public function get_bool_filter_for($filter)
	{
		if (isset($this->filters[$filter][vB_Search_Core::OP_EQ]))
		{
			return $this->filters[$filter][vB_Search_Core::OP_EQ];
		}

		return null;
	}


	/**
	 *	Get the equals filters defined
	 * @return array Array of $filtername => $value for equals filters
	 * 	$value can either be a scalar or an array
	 */
	public function get_GT_filters($filterset = 'filters')
	{
		$return = array();
		foreach ($this->$filterset as $field => $field_filters)
		{
			if (isset($field_filters[vB_Search_Core::OP_GTE]))
			{
				$return[$field] = $field_filters[vB_Search_Core::OP_GTE];
			}
		}
		return $return;
	}


	/**
	 *	Get the equals filters defined
	 *
	 *	@return array Array of $filtername => $value for equals filters
	 * 		$value can either be a scalar or an array
	 */
	public function get_LT_filters($filterset = 'filters')
	{
		$return = array();
		foreach ($this->$filterset as $field => $field_filters)
		{
			if (isset($field_filters[vB_Search_Core::OP_LTE]))
			{
				$return[$field] = $field_filters[vB_Search_Core::OP_LTE];
			}
		}
		return $return;
	}


	/**
	 *	Get the not equals filters defined
	 *
	 * 	@return array Array of $filtername => $value for not equals filters
	 * 		$value can either be a scalar or an array
	 */
	public function get_notequals_filters($filterset = 'filters')
	{
		$return = array();
		foreach ($this->$filterset as $field => $field_filters)
		{
			if (isset($field_filters[vB_Search_Core::OP_NEQ]))
			{
				$return[$field] = $field_filters[vB_Search_Core::OP_NEQ];
			}
		}

		return $return;
	}


	/**
	 *	Get the range filters defined
	 * @return array Array of $filtername => $value for not equals filters
	 * 	$value is array($min, $max).  A null value for $min or $max means
	 * 	no limit in that direction.
	 */
	public function get_range_filters($filterset = 'filters')
	{
		$return = array();
		foreach ($this->$filterset as $field => $field_filters)
		{
			//determine the range, null means unbounded.
			$item = array(null, null);
			$is_range_filter = false;
			//GT indicates minimum value
			if (isset($field_filters[vB_Search_Core::OP_GTE]))
			{
				$item[0] = $field_filters[vB_Search_Core::OP_GTE];
				$is_range_filter = true;
			}

			//LT indicates maximum value
			if (isset($field_filters[vB_Search_Core::OP_LTE]))
			{
				$item[1] = $field_filters[vB_Search_Core::OP_LTE];
				$is_range_filter = true;
			}
			if ($is_range_filter)
			{
				$return[$field] = $item;
			}
		}

		return $return;
	}

	/**
	 *	Return the parsed keywords to filter
	 *
	 *	@return array.  An array of array("word" => $word, "joiner" => $joiner)
	 * 	where $word is the keyword and $joiner indicates how the word should be
	 *		joined to the query.  $joiner should be one of "AND", "OR", or "NOT"
	 *		with the exception of the first item for which $joiner is NULL.
	 *		It is up to the search implementation to define exactly how to treat
	 *		the words specified.
	 */
	public function get_keywords()
	{
		return $this->keywords;
	}

	/**
	 *	Return the parsed keywords to filter
	 *
	 *	Return the raw query set to the criteria object.  Provided in case
	 * an implementation cannot or does not want to use the words array above.
	 * If the raw query is used then the display string and highlights should
	 * be set by the implementation to better reflect how the query is processed.
	 *
	 *	@return string
	 */
	public function get_raw_keywords()
	{
		return $this->raw_keywords;
	}

	/**
	 * Should the keywords be applied to the title or to both the title and the
	 *	keywords
	 *
	 *	@return boolean
	 */
	public function is_title_only()
	{
		return $this->titleonly;
	}

	public function get_target_userid()
	{
		// This is a hack to support who's online -- previously it attempted to
		// look the target user up based on the entered username (regardless of
		// whether or not it was a partial name which may or may not match any
		// users).  We only store the ids we found.  We'll assume that if we
		// only have a single user that we should count it. We need to check all
		// the possible user "fields" that the criteria can set.

		foreach (array('user', 'groupuser', 'defaultuser') AS $field)
		{
			$value = $this->get_equals_filter($field, true);
			if ($value AND count($value) == 1)
			{
				return $value[0];
			}
		}
		return null;
	}

	//**************************************************************************
	//Misc Public Functions
	public function has_errors()
	{
		return (bool) count($this->errors);
	}

	public function get_errors()
	{
		if (! $this->criteria_set)
		{
			//copy the array and add to the copy to avoid the potential
			//for creating a phantom error because this was called early
			//and then fixed.
			$errors = $this->errors;
			$errors[] = array('more_search_terms');
			return $errors;
		}
		else
			{
			return $this->errors;
			}
		}

	/**
	*	Add an error in processing.
	*	Intended to be used publically and by the advanced search fields
	*/
	public function add_error($error)
	{
		$this->errors[] = func_get_args();
	}

	public function get_sort()
	{
		return $this->sort;
	}

	public function get_sort_direction()
	{
		$dir = reset($this->sort);
		return $dir;
	}

	public function get_sort_field()
	{
		$dir = reset($this->sort);
		$field = key($this->sort);
		return $field;
	}

	public function getIncludeStarter()
	{
		return $this->include_starter;
	}

	public function getDepth()
	{
		return $this->depth;
	}

	public function getDepthExact()
	{
		return $this->depth_exact;
	}


	//**************************************************************************
	//Internal Functions

	/**
	 *	Break the keyword search into words
	 * @param string keywords -- keyword string as entered by the user
	 * @return array -- array of word records
	 *  array('word' => $word,  'joiner' => {'', 'NOT', 'AND', 'OR'})
	 *  The search implementation is expected to use these to build the search
	 *	 query.
	 */
	private function get_words($keywords)
	{
		$is_mb = preg_match('/&#([0-9]+);|[^\x00-\x7F]/siU', $keywords);
		// @todo handleing for thousand and decimal separators for numbers

		// removing punctuation
		$origKeywords = $keywords;
		$keywords = preg_replace('#(?!-)[\p{Pd}\p{Pe}\p{Pf}\p{Pi}\p{Po}\p{Ps}]#' . ($is_mb ? 'u' : ''), ' ', $keywords);

		// a tokenizing based approach to building a search query
		preg_match_all('#("[^"]*"|[^\s]+)#', $keywords, $matches, PREG_SET_ORDER);
		$token_joiner = null;
		$words = array();
		foreach ($matches AS $match)
		{
			if ($is_mb)
			{
				$match = preg_replace_callback('/&#([0-9]+);/siU', function($matches)
				{
					return vB_String::convertIntToUtf8($matches[1]);

				}, $match);
			}

			if ($is_mb)
			{
				$token = vB_String::vBStrToLower($match[1]);
			}
			else
			{
				$token = strtolower($match[1]);
			}
			//this means that we implicitly have a not joiner.
			if ($token[0] == '-')
			{
				//this effectively means two joiners, which is bad.
				if ($token_joiner)
				{
					$this->add_error('invalid_search_syntax');
				}
				else
				{
					$token = substr($token, 1);
					$token_joiner = 'not';
				}
			}

			switch ($token)
			{
				case 'or':
				case 'and':
				case 'not':
					// this isn't a searchable word, but a joiner
					$token_joiner = strtoupper($token);
					break;

				default:
					//$lowWord = strtolower($token);
					if (vB_Api_Search::is_index_word($token, true))
					{
						$words[] = array('word' => $token, 'joiner' => strtoupper($token_joiner));
					}
					else
					{
						$this->ignored_keywords[] = $match[1];
					}
					$token_joiner = null;
					break;
			}
		}

		if (empty($matches) AND !empty($origKeywords))
		{
			$this->ignored_keywords[] = $origKeywords;
		}

		return $words;
	}

	// #############################################################################
	// remove common syntax errors in search query string
	public function sanitize_search_query($query, &$errors)
	{
		$qu_find = array(
			'/\s+(\s*OR\s+)+/si',	// remove multiple OR strings
			'/^\s*(OR|AND|NOT|-)\s+/siU', 		// remove 'OR/AND/NOT/-' from beginning of query
			'/\s+(OR|AND|NOT|-)\s*$/siU', 		// remove 'OR/AND/NOT/-' from end of query
			'/\s+(-|NOT)\s+/si',	// remove trailing whitespace on '-' controls and translate 'not'
			'/\s+OR\s+/siU',		// capitalize ' or '
			'/\s+AND\s+/siU',		// remove ' and '
			'/\s+(-)+/s',			// remove ----word
			'/\s+/s',				// whitespace to single space
		);
		$qu_replace = array(
			' OR ',			// remove multiple OR strings
			'', 			// remove 'OR/AND/NOT/-' from beginning of query
			'',				// remove 'OR/AND/NOT/-' from end of query
			' -',			// remove trailing whitespace on '-' controls and translate 'not'
			' OR ',			// capitalize 'or '
			' ',			// remove ' and '
			' -',			// remove ----word
			' ',			// whitespace to single space
		);
		$query = trim(preg_replace($qu_find, $qu_replace, " $query "));

		// show error if query logic contains (apple OR -pear) or (-apple OR pear)
		if (strpos($query, ' OR -') !== false OR preg_match('/ -\w+ OR /siU', $query, $syntaxcheck))
		{
			$errors[] = 'invalid_search_syntax';
			return $query;
		}
		else if (!empty($query))
		{
			// check that we have some words that are NOT boolean controls
			$boolwords = array('AND', 'OR', 'NOT', '-AND', '-OR', '-NOT');
			foreach (explode(' ', strtoupper($query)) AS $key => $word)
			{
				if (!in_array($word, $boolwords))
				{
					// word is good - return the query
					return $query;
				}
			}
		}

		// no good words found - show no search terms error
		$errors[] = 'searchspecifyterms';
		return $query;
	}

	/**
	 * Make sure that a wildcard string is allowed.
	 * @param string $word -- the word to check for wildcard
	 * @return bool
	 */
	private function verify_wildcard($word)
	{
		//not sure what this is for -- probably doesn't do anything since * doesn't have
		//an upper case.  However the code I cribbed this from does it this way and it
		//doesn't hurt anything.
		$wordlower = strtolower($word);
		$options = vB::getDatastore()->get_value('options');
		$minlength = $options['minsearchlength'];

		return vB_Api_Search::is_index_word($wordlower, true);

		return true;
	}

	public function get_contenttype()
	{
		if (!isset($this->filters['contenttype'][vB_Search_Core::OP_EQ]))
		{
			return vB_Search_Core::TYPE_COMMON;
		}
		else
		{
			$types = $this->filters['contenttype'][vB_Search_Core::OP_EQ];
			if (count($types) <> 1)
			{
				return vB_Search_Core::TYPE_COMMON;
			}
			else
			{
				return $types[0];
			}
		}
		return $this->contenttype;
	}

	public function get_contenttypeid()
	{
		if (!isset($this->filters['contenttype'][vB_Search_Core::OP_EQ]))
		{
			return false;
		}
		else
		{
			$types = $this->filters['contenttype'][vB_Search_Core::OP_EQ];
			if (count($types) <> 1)
			{
				return false;
			}
			else
			{
				return $types[0];
			}
		}
	}

	/**
	 * vB_Search_Criteria::get_criteria_set()
	 * This function determines whether we have gotten some criteria
	 * that would limit the search results significantly. We don't want to
	 * do a search that would return the entire table.
	 *
	 *
	 * @return boolean
	 */
	public function get_criteria_set()
	{
		return $this->criteria_set;
	}

	/**
	 * sets the JSON criteria
	 * @param array $JSON
	 */
	public function setJSON(array $JSON)
	{
		$this->JSON = $JSON;
	}

	/**
	 * gets the JSON criteria
	 * @return array $JSON
	 */
	public function getJSON()
	{
		return $this->JSON;
	}

	/**
	 * (re)sets the caching flag
	 * @param boolean $flag
	 */
	public function setIgnoreCache($flag)
	{
		$this->ignoreCache = $flag;
	}

	/**
	 * gets the caching flag
	 * @return boolean
	 */
	public function getIgnoreCache()
	{
		if (vB_Api_Search::getCacheTTL() == 0)
		{
			return true;
		}

		return $this->ignoreCache;
	}

	/**
	 * (re)sets the nolimit flag
	 * @param boolean $set
	 */
	public function setNoLimit($set = 1)
	{
		$this->no_limit = $set;
	}

	/**
	 * gets the nolimit flag
	 * @return boolean
	 */
	public function getNoLimit()
	{
		return $this->no_limit;
	}

	public function get_ignored_keywords()
	{
		return $this->ignored_keywords;
	}

	public function setSearchContext($set = "none")
	{
		$this->search_context = (string) $set;
	}

	public function getSearchContext()
	{
		return $this->search_context;
	}

	public function setLimitOffset($set = 0)
	{
		// disallow negative
		$this->limit_offset = max(intval($set), 0);
	}
	public function getLimitOffset()
	{
		return $this->limit_offset;
	}
	public function setLimitCount($set = 0)
	{
		// disallow negative
		$this->limit_count = max(intval($set), 0);
	}
	public function getLimitCount()
	{
		return $this->limit_count;
	}

	public function setDoCount($set = false)
	{
		$this->do_count = (bool) $set;
		// If we're doing a count query, we want to disable the limits
		$this->setNoLimit(1);
		$this->setLimitCount(0);
		$this->getLimitOffset(0);
	}
	public function getDoCount()
	{
		return $this->do_count;
	}


	//filter variables

	//handle keyords/queries as a special case
	private $keywords = array();
	private $raw_keywords = "";
	private $ignored_keywords = array();
	private $titleonly = false;
	private $include_starter = false;
	private $depth = false;
	private $depth_exact = false;
	private $include_sticky = false;

	private $filters = array();

	private $sort = array();
	private $criteria_set = false;

	private $JSON = false;
	private $ignoreCache = false;
	private $post_processors = array();

	//display variables
	private $display_strings = array();
	private $common_words = array();
	private $highlights = array();
	private $search_string;
	private $current_user = 0;
	private $no_limit = 0;

	// topic fetch specific params
	private $search_context = "none";
	private $limit_offset = 0;
	private $limit_count = 0;
	private $do_count = false;

	//errors
	private $errors = array();
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103374 $
|| #######################################################################
\*=========================================================================*/
