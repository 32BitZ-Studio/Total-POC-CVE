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

class vB_Xml_Import_Page extends vB_Xml_Import
{
	/**
	 * Widgets referenced by instances in the imported template
	 * @var array
	 */
	protected $referencedTemplates;

	/**
	 * Checks if all referenced templates are already defined
	 * Also sets referencedTemplates class attribute to be used while importing
	 */
	protected function checkTemplates()
	{
		$requiredTemplates = array();

		$pages = is_array($this->parsedXML['page'][0]) ? $this->parsedXML['page'] : array($this->parsedXML['page']);
		foreach ($pages AS $page)
		{
			$requiredTemplates[] = $page['pageTemplateGuid'];
		}

		$existingPageTemplates = $this->db->getRows('pagetemplate', array('guid' => $requiredTemplates));
		foreach ($existingPageTemplates AS $pagetemplate)
		{
			$this->referencedTemplates[$pagetemplate['guid']] = $pagetemplate;
		}

		$missingTemplates = array_diff($requiredTemplates, array_keys($this->referencedTemplates));
		if (!empty($missingTemplates))
		{
			throw new Exception('Reference to undefined template(s): ' . implode(' ', $missingTemplates));
		}
	}

	protected function import($onlyGuid = array())
	{
		if (empty($this->parsedXML['page']))
		{
			$this->parsedXML['page'] = array();
		}

		if (is_string($onlyGuid))
		{
			$onlyGuid = array($onlyGuid);
		}

		// if needed, we can pass $onlyGuid so that checkTemplates
		// only checks the pages that are actually going to be imported..
		// see the commits for VBV-16631 for more details.
		$this->checkTemplates();

		// get all columns but the key
		$pageTable = $this->db->fetchTableStructure('page');
		$pageTableColumns = array_diff($pageTable['structure'], array($pageTable['key']));

		$pages = is_array($this->parsedXML['page'][0]) ? $this->parsedXML['page'] : array($this->parsedXML['page']);

		$phraseLib = vB_Library::instance('phrase');

		foreach ($pages AS $page)
		{
			if (!empty($onlyGuid) AND !in_array($page['guid'], $onlyGuid, true))
			{
				continue;
			}

			$values = array();
			foreach($pageTableColumns AS $col)
			{
				if (isset($page[$col]))
				{
					$values[$col] = $page[$col];
				}
			}
			$values['pagetemplateid'] = $this->referencedTemplates[$page['pageTemplateGuid']]['pagetemplateid'];

			if (isset($page['parentGuid']) AND !empty($page['parentGuid']))
			{
				$parent = $this->db->getRow('page', array('guid' => $page['parentGuid']));

				if ($parent)
				{
					$values['parentid'] = $parent['pageid'];
				}
				else if (!($this->options & vB_Xml_Import::OPTION_IGNOREMISSINGPARENTS))
				{
					throw new Exception('Couldn\'t find parent while attempting to import page ' . $page['guid']);
				}
			}

			$existingPage = $this->db->getRow('page', array('guid' => $page['guid']));
			if ($existingPage)
			{
				$pageId = $existingPage['pageid'];
				if ($this->options & self::OPTION_OVERWRITE)
				{
					$this->db->update('page', $values, array('pageid' => $pageId));
				}
			}
			else
			{
				$pageId = $this->db->insert('page', $values);
			}

			if (is_array($pageId))
			{
				$pageId = array_pop($pageId);
			}

			vB_Xml_Import::setImportedId(vB_Xml_Import::TYPE_PAGE, $page['guid'], $pageId);

			// Insert phrases for page title, meta description.
			$guidforphrase = vB_Library::instance('phrase')->cleanGuidForPhrase($page['guid']);
			$productid = (!empty($page['product']) ? $page['product'] : 'vbulletin');

			/*
				Save any custom page titles or meta descriptions.
				They are saved in the phrases for the specific language that
				the admin was using when the page was saved in sitebuilder...
				Let's pull all the existing phrases and if they don't match
				the provided defaults exactly, restore them after the fact.

				This might cause some weirdness with translations, but since the
				page XML doesn't provide any translations anyways (which we're
				replacing *all* instances of the phrase records with, regardless
				of languageid), I think any undefined behavior here is acceptable
				and not any worse than just overwriting completely with the default
				text.
			 */
			$assertor =  vB::getDbAssertor();

			// sometimes (in unit tests) metadescription might not be set.
			// Assume unset means metadescription will be saved as ""
			if (!isset($page['metadescription']))
			{
				$page['metadescription'] = "";
			}

			$doRestoreCustomPhrases = true; // if we ever add an overwrite option, we'd check that here.

			$pageTitlePhraseVarname = 'page_' . $guidforphrase . '_title';
			$pageMetaDescPhraseVarname = 'page_' . $guidforphrase . '_metadesc';
			$titlesToRestore = array();
			$descriptionsToRestore = array();
			if ($doRestoreCustomPhrases)
			{
				// Grab all non-default phrases
				$conditions = array(
					vB_dB_Query::CONDITIONS_KEY => array(
						array('field' => "fieldname", 'value' => "pagemeta", 'operator' => vB_dB_Query::OPERATOR_EQ),
						array('field' => "varname", 'value' => $pageTitlePhraseVarname, 'operator' => vB_dB_Query::OPERATOR_EQ),
						array('field' => "fieldname", 'value' => $page['title'], 'operator' => vB_dB_Query::OPERATOR_NE),
					),
				);
				$titlesToRestore = $assertor->getRows('phrase', $conditions);

				$conditions = array(
					vB_dB_Query::CONDITIONS_KEY => array(
						array('field' => "fieldname", 'value' => "pagemeta", 'operator' => vB_dB_Query::OPERATOR_EQ),
						array('field' => "varname", 'value' => $pageMetaDescPhraseVarname, 'operator' => vB_dB_Query::OPERATOR_EQ),
						array('field' => "fieldname", 'value' => $page['metadescription'], 'operator' => vB_dB_Query::OPERATOR_NE),
					),
				);
				$descriptionsToRestore = $assertor->getRows('phrase', $conditions);
			}

			// wrap everything in a transaction so we don't just lose the old titles & desc
			// if it happens to die in the middle somewhere.
			// This relies on the phrase LIB not committing anything, which it currently does not.
			$alreadyInTransaction = $assertor->inTransaction();
			if (!$alreadyInTransaction)
			{
				$assertor->beginTransaction();
			}

			$skipBuildLanguage = true;

			$phraseLib->save('pagemeta',
				$pageTitlePhraseVarname,
				array(
					'text' => array($page['title']),
					'ismaster' => 1,
					'product' => $productid,
					't' => 0,
					'oldvarname' => $pageTitlePhraseVarname,
					'oldfieldname' => 'global',
				),
				$skipBuildLanguage
			);

			$phraseLib->save('pagemeta',
				$pageMetaDescPhraseVarname,
				array(
					'text' => array($page['metadescription']),
					'ismaster' => 1,
					'product' => $productid,
					't' => 0,
					'oldvarname' => $pageMetaDescPhraseVarname,
					'oldfieldname' => 'global',
				),
				$skipBuildLanguage
			);



			// do the restores. REPLACE INTO just in case we hit some conflicts,
			// though we *shouldn't* since the phrase LIB generally wipes all the
			// related records before it does the master phrase inserts.
			foreach ($titlesToRestore AS $__phrase)
			{
				$assertor->replace('phrase',
					array(
						'languageid' => $__phrase['languageid'],
						'varname'    => $__phrase['varname'],
						'text'       => $__phrase['text'],
						'fieldname'  => $__phrase['fieldname'],
						'product'    => $__phrase['product'],
						'username'   => $__phrase['username'],
						'dateline'   => $__phrase['dateline'],
						'version'    => $__phrase['version'],
					)
				);
			}

			foreach ($descriptionsToRestore AS $__phrase)
			{
				$assertor->replace('phrase',
					array(
						'languageid' => $__phrase['languageid'],
						'varname'    => $__phrase['varname'],
						'text'       => $__phrase['text'],
						'fieldname'  => $__phrase['fieldname'],
						'product'    => $__phrase['product'],
						'username'   => $__phrase['username'],
						'dateline'   => $__phrase['dateline'],
						'version'    => $__phrase['version'],
					)
				);
			}

			// commit everything.
			if (!$alreadyInTransaction)
			{
				$assertor->commitTransaction();
			}
		}

		// Run the delayed build_language() that's usually called at the end of
		// vB_Library_Phrase::save();
		if ($pages)
		{
	 		vB_Library::instance('language')->rebuildAllLanguages();
		}
	}

	public function updatePageRoutes($xml = false)
	{
		if ($xml)
		{
			$this->parsedXML = $xml;
		}

		$currentPages = $this->db->assertQuery('page', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT));
		$existingPage = array();
		foreach($currentPages AS $pageInfo)
		{
			$existingPage[$pageInfo['guid']] = $pageInfo['pageid'];
		}

		$existingRoute = array();
		$currentRoutes = $this->db->assertQuery('routenew', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT));
		foreach($currentRoutes AS $routeInfo)
		{
			$existingRoute[$routeInfo['guid']] = $routeInfo['routeid'];
		}

		$pages = is_array($this->parsedXML['page'][0]) ? $this->parsedXML['page'] : array($this->parsedXML['page']);

		foreach ($pages AS $page)
		{

			if (isset($existingPage[$page['guid']]) AND isset($existingRoute[$page['routeGuid']]))
			{
				$this->db->update(
					'page',
					array('routeid' => $existingRoute[$page['routeGuid']]),
					array('pageid'	=> $existingPage[$page['guid']])
				);
			}
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102679 $
|| #######################################################################
\*=========================================================================*/
