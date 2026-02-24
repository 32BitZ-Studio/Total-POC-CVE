<?php
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

if (VB_AREA != 'Install' AND !isset($GLOBALS['vbulletin']->db))
{
	exit;
}

class vB_Upgrade_final extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/**
	 * The short version of the script
	 *
	 * @var	string
	 */
	public $SHORT_VERSION = 'final';

	/**
	 * The long version of the script
	 *
	 * @var	string
	 */
	public $LONG_VERSION  = 'final';

	/*Properties====================================================================*/

	/**
	 * Step #1 - Import Settings XML
	 *
	 *	WARNING: If you modify the step#, you must update vB_Upgrade_500a1 step_139() (and others)
	 */
	function step_1()
	{
		vB_Upgrade::createAdminSession();
		vB_Library::instance('usergroup')->buildDatastore();
		vB::getUserContext()->rebuildGroupAccess();
		vB_Channel::rebuildChannelTypes();

		if (VB_AREA == 'Upgrade')
		{
			$this->show_message($this->phrase['final']['import_latest_options']);
			require_once(DIR . '/includes/adminfunctions_options.php');

			if (!($xml = file_read(DIR . '/install/vbulletin-settings.xml')))
			{
				$this->add_error(sprintf($this->phrase['vbphrase']['file_not_found'], 'vbulletin-settings.xml'), self::PHP_TRIGGER_ERROR, true);
				return;
			}

			$this->show_message(sprintf($this->phrase['vbphrase']['importing_file'], 'vbulletin-settings.xml'));
			xml_import_settings($xml);

			$this->show_message($this->phrase['core']['import_done']);
		}
		else if (vB_Upgrade::isCLI())
		{
			$library = vB_Upgrade::fetch_library($this->registry, $this->phrase, '', false, null, false, array('execute' => false));
			$library->loadDSSettingsfromConfig();
			$this->show_message($this->phrase['core']['import_done']);
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Step #2 - Import Admin Help XML
	 *
	 */
	function step_2()
	{
		$this->show_message($this->phrase['final']['import_latest_adminhelp']);
		require_once(DIR . '/includes/adminfunctions_help.php');

		if (!($xml = file_read(DIR . '/install/vbulletin-adminhelp.xml')))
		{
			$this->add_error(sprintf($this->phrase['vbphrase']['file_not_found'], 'vbulletin-adminhelp.xml'), self::PHP_TRIGGER_ERROR, true);
			return;
		}

		$this->show_message(sprintf($this->phrase['vbphrase']['importing_file'], 'vbulletin-adminhelp.xml'));

		xml_import_help_topics($xml);
		$this->show_message($this->phrase['core']['import_done']);
	}

	/**
	 * Step #3 - Import Language XML
	 *
	 */
	function step_3()
	{
		$this->show_message($this->phrase['final']['import_latest_language']);
		require_once(DIR . '/includes/adminfunctions_language.php');

		if (!($xml = file_read(DIR . '/install/vbulletin-language.xml')))
		{
			$this->add_error(sprintf($this->phrase['vbphrase']['file_not_found'], 'vbulletin-language.xml'), self::PHP_TRIGGER_ERROR, true);
			return;
		}

		$this->show_message(sprintf($this->phrase['vbphrase']['importing_file'], 'vbulletin-language.xml'));

		xml_import_language($xml, -1, '', false, true, !defined('SUPPRESS_KEEPALIVE_ECHO'));
		$this->show_message($this->phrase['core']['import_done']);

		/* If fresh install, let's use the just imported language's charset as the default.
		 * vB_Upgrade's setup_environment() will overwrite this later from the upgrade phrases,
		 * but that doesn't matter because we just need the right charset for the custom language
		 * import below within the same session.
		 */
		if (VB_AREA == 'Install')
		{
			$assertor = vB::getDbAssertor();
			$row = $assertor->getRow('setting', array('varname' => 'languageid'));
			if ($row AND isset($row['value']))
			{
				$charset = $assertor->getColumn('language', 'charset', array('languageid' => $row['value']));
				if (is_array($charset))
				{
					$charset = $charset[0];
				}
				vB_Template_Runtime::addStyleVar('charset', $charset);
			}
		}

		// Try to import custom languages
		// List files in customlanguages dir
		$customlangdir = DIR . '/install/customlanguages';

		if (is_dir($customlangdir))
		{
			if ($dh = opendir($customlangdir))
			{
				$languagesLoaded = array();
				while (($file = readdir($dh)) !== false)
				{
					if (strpos($file, 'vbulletin-custom-language-') === 0)
					{
						if (!($xml = file_read($customlangdir . '/' . $file)))
						{
							$this->add_error(sprintf($this->phrase['vbphrase']['file_not_found'], $file), self::PHP_TRIGGER_ERROR, false);
						}
						else
						{
							// returns languageid, or false if the custom language wasn't imported
							$langid = xml_import_language($xml, 0, '', true, true, !defined('SUPPRESS_KEEPALIVE_ECHO'));
							if ($langid === false)
							{
								$this->show_message(sprintf($this->phrase['vbphrase']['skipping_file'], $file));
							}
							else
							{
								$languagesLoaded[] = $langid;

								$this->show_message(sprintf($this->phrase['vbphrase']['importing_file'], $file));
								$this->show_message($this->phrase['core']['import_done']);

								// VBV-14130 Only set the default language for fresh installs.
								if (VB_AREA == 'Install')
								{
									$vblangcode = $assertor->getColumn('language', 'vblangcode', array('languageid' => $langid));
									if (is_array($vblangcode))
									{
										$vblangcode = $vblangcode[0];
									}

									$config = vB::getConfig();
									if (isset($config['Install']['default_language_vblangcode']))
									{
										// If they set this in their backend config, use that to set the default. Note,
										// if they set this incorrectly, this won't change the default language.
										$setDefault = (	$config['Install']['default_language_vblangcode'] === $vblangcode );
									}
									else
									{
										// Set the default language to the imported custom language.
										// This isn't perfect, since we may have more than one custom
										// language, but it's better to set the last imported custom language
										// to be the default than to leave English as the default
										// if they downloaded the package with a different language than English
										$setDefault = true;
									}

									if ($setDefault)
									{
										vB::getDatastore()->setOption('languageid', $langid, true);
										$this->show_message(sprintf($this->phrase['final']['default_language_set_to_x'], $vblangcode, $file));
									}
								}
							}
						}
					}
				}
				closedir($dh);
			}
		}

		build_language_datastore();
	}

	/**
	 * Step #4 - Import widgets XML
	 *
	 *	WARNING: If you modify the step#, you must update vB_Upgrade_500a1 step_128() & vB_Upgrade_510a1 step_3()
	 */
	function step_4()
	{
		$this->show_message($this->phrase['final']['import_latest_widgets']);
		$widgetFile = DIR . '/install/vbulletin-widgets.xml';
		if (!($xml = file_read($widgetFile)))
		{
			$this->add_error(sprintf($this->phrase['vbphrase']['file_not_found'], 'vbulletin-widgets.xml'), self::PHP_TRIGGER_ERROR, true);
			return;
		}

		$this->show_message(sprintf($this->phrase['vbphrase']['importing_file'], 'vbulletin-widgets.xml'));

		$xml_importer = new vB_Xml_Import_Widget();
		$xml_importer->importFromFile($widgetFile);

		$this->show_message($this->phrase['core']['import_done']);
	}

	/**
	 * Step #5 - Import screenlayout XML
	 *
	 *	WARNING: If you modify the step#, you must update vB_Upgrade_514b3 step_1()
	 */
	function step_5()
	{
		$filename = 'vbulletin-screenlayouts.xml';
		$file = DIR . '/install/' . $filename;
		if (!file_exists($file))
		{
			$this->add_error(sprintf($this->phrase['vbphrase']['file_not_found'], $filename), self::PHP_TRIGGER_ERROR, true);
			return;
		}

		$this->show_message(sprintf($this->phrase['vbphrase']['importing_file'], $filename));

		$options = vB_Xml_Import::OPTION_OVERWRITE;
		$importer = new vB_Xml_Import_Screenlayout('vbulletin', $options);
		$importer->importFromFile($file);

		$this->show_message($this->phrase['core']['import_done']);
	}

	/**
	 * Step #6 - Import pagetemplates XML
	 *
	 *	WARNING: If you modify the step#, you must update vB_Upgrade_500a1 step_129() & vB_Upgrade_510a1 step_4()
	 *	WARNING: step_5 (import screenlayout XML) should be called before step_6 (import pagetemplates XML). Otherwise,
	 *			pagetemplate table may be missing its screenlayoutids. If it's not possible to call step_5() first,
	 *			you must add a step to fix the pagetemplates with missing screenlayoutids. See VBV-13771.
	 */
	function step_6()
	{
		vB_Upgrade::createAdminSession();

		$pageTemplateFile = DIR . '/install/vbulletin-pagetemplates.xml';
		if (!($xml = file_read($pageTemplateFile)))
		{
			$this->add_error(sprintf($this->phrase['vbphrase']['file_not_found'], 'vbulletin-pagetemplates.xml'), self::PHP_TRIGGER_ERROR, true);
			return;
		}

		$this->show_message(sprintf($this->phrase['vbphrase']['importing_file'], 'vbulletin-pagetemplates.xml'));

		// TODO: there might be some upgrades in which we do want to add some widgetinstances
		$options = (VB_AREA == 'Upgrade') ? 0 : vB_Xml_Import::OPTION_ADDWIDGETS;
		$xml_importer = new vB_Xml_Import_PageTemplate('vbulletin', $options);
		$xml_importer->importFromFile($pageTemplateFile);

		// Update widget instance config item values that use phrases (phrase:<phrasevarname>)
		// This updates all widget config items that need it, including pre-existing widget instances
		// This is needed because 500a30 step 1 imports the page templates, and the
		// phrase placeholders are not replaced in the admin config because the target phrase(s)
		// do not yet exist in the phrase table at that point. See VBV-12214.
		$pageTemplateImporter = new vB_Xml_Import_PageTemplate('vbulletin', 0);
		$pageTemplateImporter->replacePhrasePlaceholdersInWidgetConfigs();

		/*
			Until we add a way to store which pagetemplate is "default" or "protected", we're going with
			a list of hard-coded GUIDs in the page class.
			This check is to remind devs to add the guid to the function when they add a new pagetemplate.
			If the guid isn't added to the function, admins will be able to accidentally delete the pagetemplates
			via sitebuilder. VBV-14123
		 */
		$config = vB::getConfig();
		if (!empty($config['Misc']['debug']))
		{
			$knownDefaults = vB_Page::getDefaultPageTemplateGUIDs();
			$xml = $xml_importer::parseFile($pageTemplateFile);
			// probably unnecessary since nowadays the pagetemplatefile is never going to have just 1 pagetemplate, but copied
			// from pagetemplate importer
			$pageTemplates = is_array($xml['pagetemplate'][0]) ? $xml['pagetemplate'] : array($xml['pagetemplate']);
			$unknowns = array();
			foreach ($pageTemplates AS $__pagetemplate)
			{
				$__guid = $__pagetemplate['guid'];
				if (!isset($knownDefaults[$__guid]))
				{
					$unknowns[$__guid] = $__guid;
				}
			}

			// halt upgrade for dev.
			if (!empty($unknowns))
			{
				$guids = implode(",\n", $unknowns);
				$this->add_error(
					sprintf($this->phrase['vbphrase']['missing_pagetemplate_guids_in_vb_page'], $guids),
					self::PHP_TRIGGER_ERROR, true
				);
				return;
			}
		}

		$this->show_message($this->phrase['core']['import_done']);
	}

	/**
	 * Step #7 - Import pages XML
	 *
	 *	WARNING: If you modify the step#, you must update vB_Upgrade_500a1 step_131() & vB_Upgrade_510a1 step_5()
	 */
	function step_7()
	{
		vB_Upgrade::createAdminSession();

		// Importing pages
		$pageFile = DIR . '/install/vbulletin-pages.xml';
		if (!($xml = file_read($pageFile)))
		{
			$this->add_error(sprintf($this->phrase['vbphrase']['file_not_found'], 'vbulletin-pages.xml'), self::PHP_TRIGGER_ERROR, true);
			return;
		}

		$this->show_message(sprintf($this->phrase['vbphrase']['importing_file'], 'vbulletin-pages.xml'));

		$page_importer = new vB_Xml_Import_Page('vbulletin', 0);
		$page_importer->importFromFile($pageFile);
		build_language();

		$this->show_message($this->phrase['core']['import_done']);
	}

	/**
	 * Step #8 - Import channels XML
	 *
	 *	WARNING: If you modify the step#, you must update vB_Upgrade_500a1 step_132() & vB_Upgrade_510a1 step_6()
	 */
	function step_8()
	{
		vB_Upgrade::createAdminSession();

		// Import channels
		$channelFile = DIR . '/install/vbulletin-channels.xml';
		if (!($xml = file_read($channelFile)))
		{
			$this->add_error(sprintf($this->phrase['vbphrase']['file_not_found'], 'vbulletin-channels.xml'), self::PHP_TRIGGER_ERROR, true);
			return;
		}

		$this->show_message(sprintf($this->phrase['vbphrase']['importing_file'], 'vbulletin-channels.xml'));

		$channel_importer = new vB_Xml_Import_Channel('vbulletin', 0);
		$channel_importer->importFromFile($channelFile);

		// rebuild caches after adding channels
		vB::getUserContext()->rebuildGroupAccess();
		vB_Channel::rebuildChannelTypes();

		// Update widget instance config items that use channels (channelguid:<GUID>)
		$pageTemplateImporter = new vB_Xml_Import_PageTemplate('vbulletin', 0);
		$pageTemplateImporter->replaceChannelGuidsInWidgetConfigs();

		$this->show_message($this->phrase['core']['import_done']);
	}

	/**
	 * Step #9 - Import routes XML
	 *
	 *	WARNING: If you modify the step#, you must update vB_Upgrade_500a1 step_133(), vB_Upgrade_510a1 step_7() & vB_Upgrade_510a7 step_1()
	 */
	function step_9()
	{
		vB_Upgrade::createAdminSession();

		// Importing routes
		$routesFile = DIR . '/install/vbulletin-routes.xml';
		if (!($xml = file_read($routesFile)))
		{
			$this->add_error(sprintf($this->phrase['vbphrase']['file_not_found'], 'vbulletin-routes.xml'), self::PHP_TRIGGER_ERROR, true);
			return;
		}

		$this->show_message(sprintf($this->phrase['vbphrase']['importing_file'], 'vbulletin-routes.xml'));

		$route_importer = new vB_Xml_Import_Route();
		$route_importer->importFromFile($routesFile);

		// Update pages with new route ids
		$pageFile = DIR . '/install/vbulletin-pages.xml';
		$page_importer = new vB_Xml_Import_Page('vbulletin', 0);
		$parsedXML = $page_importer->parseFile($pageFile);
		$page_importer->updatePageRoutes($parsedXML);

		// Update channels with route ids
		$channelFile = DIR . '/install/vbulletin-channels.xml';
		$channel_importer = new vB_Xml_Import_Channel('vbulletin', 0);
		$parsedXML = $channel_importer->parseFile($channelFile);
		$channel_importer->updateChannelRoutes($parsedXML);

		$this->show_message($this->phrase['core']['import_done']);
	}

	/**
	 * After populating the node and channel tables with their data, we need to
	 * create the Channel widget instance configuration and update ONLY IF IT
	 * HASN'T BEEN ALREADY SET
	 *
	 * WARNING: If you modify the step#, you must update vB_Upgrade_500a1 step_134()
	 */
	function step_10()
	{
		// TODO Hard-coding widgetinstanceid = 1 and parentid = 1 in this
		// function seems fragile. Consider using vB_Xml_Import::getImportedId
		// to get the correct ID based on GUID

		$widgetid = $this->db->query_first("
			SELECT widgetinstanceid
			FROM `" . TABLE_PREFIX . "widgetinstance`
			WHERE widgetinstanceid = 1 AND adminconfig = ''
		");

		if (empty($widgetid))
		{
			$this->skip_message();
			return;
		}

		$contenttype = $this->db->query_first("
			SELECT contenttypeid
			FROM " . TABLE_PREFIX . "contenttype
			WHERE class = 'Channel'
		");
		$channelContentTypeId = $contenttype['contenttypeid'];

		$widgetConfig = array(
			'channel_node_ids' => array(),
		);

		$rootChannelResult = $this->db->query_read("
			SELECT *
			FROM " . TABLE_PREFIX . "node
			WHERE
				parentid = 1
				AND
				contenttypeid = $channelContentTypeId
		");
		while ($rootChannel = $this->db->fetch_array($rootChannelResult))
		{
			$widgetConfig['channel_node_ids'][] = $rootChannel['nodeid'];

			$subChannelResult = $this->db->query_read($q = "
				SELECT *
				FROM " . TABLE_PREFIX . "node
				WHERE
					parentid = $rootChannel[nodeid]
					AND
					contenttypeid = $channelContentTypeId
			");

			while ($subChannel = $this->db->fetch_array($subChannelResult))
			{
				$widgetConfig['channel_node_ids'][] = $subChannel['nodeid'];
			}
		}

		$this->run_query(
		sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'widgetinstance'),
			"
			UPDATE `" . TABLE_PREFIX . "widgetinstance`
			SET adminconfig = '" . $this->db->escape_string(serialize($widgetConfig)) . "'
			WHERE widgetinstanceid = 1 AND adminconfig = ''
			"
		);
	}

	/**
	 * Create the channel routes
	 *
	 *	WARNING: If you modify the step#, you must update vB_Upgrade_500a1 step_135()
	 */
	function step_11()
	{
		vB_Upgrade::createAdminSession();
		$channelXML = new vB_Xml_Import_Channel();
		$channelXML->fixMissingChannelRoutes();
		// We need to send a string into show_message().
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'node'));
	}

	/**
	 * Add routes to node table
	 *
	 *	WARNING: If you modify the step#, you must update vB_Upgrade_500a1 step_136()
	 */
	function step_12()
	{
		$contenttype = $this->db->query_first("
			SELECT contenttypeid
			FROM " . TABLE_PREFIX . "contenttype
			WHERE class = 'Channel'
		");
		$channelContentTypeId = $contenttype['contenttypeid'];

		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'node'));

		// updating channel routes
		$this->db->query_write("
			UPDATE " . TABLE_PREFIX . "node c
			SET c.routeid = (SELECT MAX(r.routeid) FROM " . TABLE_PREFIX . "routenew r WHERE r.contentid = c.nodeid AND class='vB5_Route_Channel')
			WHERE c.routeid = 0 AND c.contenttypeid = $channelContentTypeId
			"
		);
	}

	/**
	 * Reimport vBulletin default products
	 *
	 */
	function step_13($data = null)
	{
		/*
			It doesn't seem like the product install depends on the master style being updated, surprisingly enough.
			The installation also checks dependencies for the installing product (essentially the same code as
			vB_Upgrade_Product::import_dependencies()).

			Some notes about vB_Upgrade_Product::import_dependencies()

			import_dependencies() doesn't actually seem to import anything, but rather check the min/max versions
			& parent products to see if anything is incompatible, then throw an exception. The next upgrade step
			cactches this exception & disables the product.

			There's a bit of unused code at the end that seems to be used by another process to reimport the
			product, but the function itself doesn't import or install anything.

			It also seems a bit backwards, as if we don't have the latest XML data imported into the database, we
			could end up passing the dependency checks, importing the updated XML, then encountering a newly added
			dependency that *should've* failed but didn't since we wouldn't want to run the dependency checks
			twice.

			So it makes sense to me that first, we should update the default vbulletin products, then run the
			dependency check to see if anything needs disabling.

			Note, the vBulletin products don't have a lot of dependencies at the moment, mostly version checks that
			automatically get incremented at every version, so it's kind of pointless. It's probably more useful
			for third party products, but we will not be updating those in this upgrade step (their XMLs aren't
			guaranteed to be updated in the updated forum package since they're third party, and there might be
			other intracacies with their upgrades)
		 */
		$startat = isset($data['startat']) ? intval($data['startat']) : 0;
		$products = vB_Products::DEFAULT_VBULLETIN_PRODUCTS;


		$config = vB::getConfig();
		if (isset($config['Install']['product_autoinstall_addendum']))
		{
			$extraProducts = explode(',', $config['Install']['product_autoinstall_addendum']);
			foreach($extraProducts AS $__prod)
			{
				// Usually we expect it to be 'abc,defg,hijk' but let's
				// handle cases like 'abc, defg, hijk' or 'abc,defg,'.
				// Clean up any spaces, and any trailing commas.
				$__prod = trim($__prod, ', ');
				if (!empty($__prod))
				{
					$products[] = $__prod;
				}
			}
		}

		if (isset($products[$startat]))
		{
			$package = $products[$startat];
			$forceFreshInstall = true;
			$deferRebuild = true;
			// Viglink does not have a product class. We still want to update the templates/phrases/dependencies ETC
			// so skip the usual checks for viglink only.
			$skipProductAutoInstallCheck = ($package == 'viglink' ? true : false);
			$this->reinstallProductPackage($package, $forceFreshInstall, $deferRebuild, $skipProductAutoInstallCheck);
		}
		else
		{
			// we're done.
			// Let's rebuild everything but templates, and rely on style import @ step_15 to rebuild the templates/styles.
			$rebuildAll = false;
			$rebuild = array(
				'templates' => false,
				'hooks'     => true,
				'phrases'   => true,
				'options'   => true,
				'cron'      => true
			);
			require_once(DIR . '/includes/adminfunctions_product.php');
			do_rebuilds_after_product_install($rebuild, $rebuildAll);

			$this->show_message($this->phrase['core']['process_done']);
			return;
		}

		return array('startat' => ++$startat);
	}

	/**
	 * Check Product Dependencies
	 *
	 */
	function step_14()
	{
		/*
		 * Moved here from step_13 to keep it after the product imports. See above steps' notes.
		 */

		if (VB_AREA == 'Install')
		{
			$this->skip_message();
			return;
		}

		$this->show_message($this->phrase['final']['verifying_product_dependencies']);

		require_once(DIR . '/includes/class_upgrade_product.php');
		$this->product = new vB_Upgrade_Product($this->registry, $this->phrase['vbphrase'], true, $this->caller);

		$dependency_list = array();
		$product_dependencies = $this->db->query_read("
			SELECT pd.*
			FROM " . TABLE_PREFIX . "productdependency AS pd
			INNER JOIN " . TABLE_PREFIX . "product AS p ON (p.productid = pd.productid)
			WHERE
				pd.productid IN ('dummy') # // Any Integrated 3rd party products
					AND
				p.active = 1
			ORDER BY
				pd.dependencytype, pd.parentproductid, pd.minversion
		");
		while ($product_dependency = $this->db->fetch_array($product_dependencies))
		{
			$dependency_list["$product_dependency[productid]"][] = array(
				'dependencytype'  => $product_dependency['dependencytype'],
				'parentproductid' => $product_dependency['parentproductid'],
				'minversion'      => $product_dependency['minversion'],
				'maxversion'      => $product_dependency['maxversion'],
			);
		}

		$product_list = fetch_product_list(true);
		$disabled = array();

		foreach($dependency_list AS $productid => $dependencies)
		{
			$this->show_message(sprintf($this->phrase['final']['verifying_product_x'], $productid));
			$this->product->productinfo['productid'] = $productid;
			$disableproduct = false;
			try
			{
				$this->product->import_dependencies($dependencies);
			}
			catch(vB_Exception_AdminStopMessage $e)
			{
				$message = $this->stop_exception($e);
				$this->show_message($message);
				$disableproduct = true;
			}

			if ($disableproduct)
			{
				$disabled[] = $productid;
				$this->product->disable();
				$this->add_adminmessage(
					'disabled_product_x_y_z',
					array(
						'dismissable' => 1,
						'script'      => '',
						'action'      => '',
						'execurl'     => '',
						'method'      => '',
						'status'      => 'undone',
					),
					true,
					array($product_list["$productid"]['title'], $productid, $message)
				);
				$this->show_message(sprintf($this->phrase['final']['product_x_disabled'], $productid));
			}
		}

		if (!should_install_suite())
		{
			if (!$disabled['vbblog'] AND $product_list['vbblog']['active'])
			{
				$this->product = new vB_Upgrade_Product($this->registry, $this->phrase['vbphrase'], true, $this->caller);
				$this->product->productinfo['productid'] = 'vbblog';
				$this->product->disable();
				$this->show_message(sprintf($this->phrase['final']['product_x_disabled'], 'vbblog'));
			}
		}

	}

	/**
	 * Import Style XML
	 *
	 * @param	array	contains id to startat processing at
	 *
	 */
	function step_15($data = null)
	{
		$perpage = 1;
		$startat = intval($data['startat']);
		require_once(DIR . '/includes/functions_databuild.php');
		require_once(DIR . '/includes/adminfunctions_template.php');

		if (!($xml = file_read(DIR . '/install/vbulletin-style.xml')))
		{
			$this->add_error(sprintf($this->phrase['vbphrase']['file_not_found'], 'vbulletin-style.xml'), self::PHP_TRIGGER_ERROR, true);
			return;
		}

		if ($startat == 0)
		{
			$this->show_message(sprintf($this->phrase['vbphrase']['importing_file'], 'vbulletin-style.xml'));
		}

		$info = xml_import_style($xml, -1, -1, '', false, 1, false, $startat, $perpage);

		if (!$info['done'])
		{
			$this->show_message($info['output']);
			return array('startat' => $startat + $perpage);
		}
		else
		{
			vB_Upgrade::createAdminSession();
			build_bbcode_video(true);
			$this->show_message($this->phrase['core']['import_done']);
		}
	}

	/**
	 * Import Theme XMLs
	 *
	 */
	function step_16($data = null)
	{
		$result = $this->importThemes($data);
		if (!empty($result['messages']))
		{
			foreach ($result['messages'] AS $msg)
			{
				$this->show_message($msg);
			}
		}

		if (isset($result['startat']))
		{
			return array('startat' => $result['startat'] );
		}
	}

	function importThemes($data = null)
	{
		//defines $upgrade_options['theme_import'] array -- defined in a seperate file for easy editing.
		require(DIR . '/install/upgrade_options.php');

		$perpage = 1;
		$startat = intval($data['startat']);

		vB_Upgrade::createAdminSession();
		if ($startat == 0)
		{
			return array(
				'messages' => array(
					'import_themes' => $this->phrase['final']['import_themes']
				),
				// this is a hack to get the upgrader to output this message first, rather than
				// after all the outputs of xml_import_style() on the first iteration.
				'startat' => ++$startat
			);
		}
		$xml_importer = new vB_Xml_Import_Theme();

		try
		{
			$overwrite = true;
			if (isset($upgrade_options['theme_import']['overwrite']))
			{
				$overwrite = (boolean) $upgrade_options['theme_import']['overwrite'];
			}
			$info = $xml_importer->importThemes($perpage, $overwrite);
		}
		catch(vB_Exception_AdminStopMessage $e)
		{
			// If there was this exception, it most likely came from
			// failing to generate the default parent theme. We cannot
			// continue importing any themes without this parent theme.
			$message = $this->stop_exception($e);
			/*
			return array(
				'messages' => array(
					'exception' => $message,
					'skipping_try_again' => $this->phrase['core']['skipping_try_again'],
				)
			);
			$this->show_message($message);
			*/

			$this->add_error($message, self::PHP_TRIGGER_ERROR, true);
			return;
		}

		if (!$info['done'])
		{
			/*
			 * 	There's a problem after importing custom languages where the installer started off as ISO-8859-1, but the phrases
			 *	are likely imported as UTF-8, so any phrases with multibyte characters end up rendered mangled. The style importer
			 *	has at least 1 phrase, 'creating_a_new_style_called_x'.
			 *	This is a bit of a hack to convert those phrases to ISO-8859-1 on the fly so the upgrader will be able to show the
			 *	phrases with multibyte characters that are used by the style importer. This relies on the fact that the 'charset'
			 *	stylevar will be reset to the same as the installer ajax page initialization by vB_Upgrade->setup_environment().
			 */
			$languageid = vB_Api::instanceInternal('phrase')->getLanguageid(true);

			//bit of a hack, but some things come through as rendered phrases
			//some as standard phrase arrays that need to be rendered.
			//need to fix that so that everything comes out as a phrase array
			$output = $info['output'];
			if(is_array($output))
			{
				$output = $this->render_phrase_array($output);
			}
			$output = vB_String::toCharset($output, $languageid['charset'], vB_Template_Runtime::fetchStyleVar('charset'));

			return array(
				'messages' => array(
					'output' => $output
				),
				// startat has no meaning in this step. We just use it to keep this going until the theme importer has finished.
				'startat' => ++$startat
			);
		}
		else
		{
			return array('messages' => array('done' => $this->phrase['core']['import_done']));
		}
	}

	/**
	 * Reset all caches
	 */
	function step_17()
	{
		/*
		 * There are two reasons for reset cache in this class:
		 *  1- we want to run this once, no matter what version we are upgrading
		 *  2- we need to make sure that db has been updated with cache table
		 */

		$this->show_message($this->phrase['final']['resetting_cache']);

		// we need to restore original cache values, reverting the change in upgrade.php
		$config =& vB::getConfig();
		if (!empty($config['Backup']['Cache']['class']))
		{
			foreach ($config['Backup']['Cache']['class'] AS $key => $class)
			{
				$config['Cache']['class'][$key] = $class;
			}
		}

		// now reset all cache types
		vB_Cache::resetAllCache();

		//And set the fastDS cache for rebuild. We don't want to rebuild here- we might be running in CLI,
		// and a rebuild does nothing for the website. Also, we may be on two different server.
		//We want to force a fastDS rebuild, but we can't just call rebuild. There may be dual web servers,
		// and calling rebuild only rebuilds one of them.
		$options = vB::getDatastore()->getValue('miscoptions');
		$options['dsdate'] = vB::getRequest()->getTimeNow();
		$options['tmtdate'] = vB::getRequest()->getTimeNow();
		$options['phrasedate'] = vB::getRequest()->getTimeNow();
		vB::getDatastore()->build('miscoptions', serialize($options), 1);
	}

	/**
	 * Rebuild filesystem template cache
	 */
	function step_18()
	{
		if (vB::getDatastore()->getOption('cache_templates_as_files'))
		{
			$this->show_message($this->phrase['final']['rebuild_filesystem_template_cache']);
			vB_Upgrade::createAdminSession();
			$templateApi = vB_Api::instanceInternal('template');
			$templateApi->deleteAllTemplateFiles();
			$templateApi->saveAllTemplatesToFile();
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Import the password schemes
	 */
	function step_19()
	{
		$this->show_message($this->phrase['final']['import_password_schemes']);
		vB_Library::instance('login')->importPasswordSchemes();
	}

	/**
	 * Step #19 insert default notifications data.
	 */
	function step_20()
	{
		$this->show_message($this->phrase['final']['adding_notification_defaults']);
		$this->addNotificationDefaultData();
	}

	/**
	 * Step-less function to insert default notifications data. Note that categories must be added to the db
	 * before types can be added. This allows version-specific upgraders to call it without having to go back
	 * and change the calls every time the step#'s are shifted around.
	 */
	function addNotificationDefaultData()
	{
		// remember to add to caller: $this->show_message($this->phrase['final']['adding_notification_defaults']);

		$lib = vB_Library::instance('Notification');
		$classes = $lib->getDefaultTypes();
		foreach ($classes AS $class)
		{
			$lib->insertNotificationTypeToDB($class);
		}
	}


	function step_21()
	{
		if (VB_AREA == 'Install')
		{
			$this->skip_message();
			return;
		}

		$this->show_message($this->phrase['final']['check_for_updated_phrases']);

		vB_Upgrade::createAdminSession();
		$customcache = vB_Api::instanceInternal('phrase')->findUpdates();
		if (count($customcache) > 0)
		{
			$this->add_adminmessage(
				'custom_phrases_need_updating',
				array(
					'dismissable' => 1,
					'script'      => 'phrase.php',
					'action'      => 'findupdates',
					'execurl'     => 'phrase.php?do=findupdates',
					'method'      => 'get',
					'status'      => 'undone',
				),
				false
			);
		}
	}

	/**
	 * Step #22 Template Merge
	 * THIS SHOULD ALWAYS BE THE LAST STEP
	 * If this step changes vbulletin-upgrade.js must also be updated in the process_bad_response() function
	 *
	 * @param	array	contains start info
	 *
	 */
	function step_22($data = null)
	{
		//defines $upgrade_options['template_merge'] array -- defined in a seperate file for easy editing.
		require(DIR . '/install/upgrade_options.php');

		if ($data['options']['skiptemplatemerge'])
		{
			$this->skip_message();
			return;
		}

		if (isset($data['response']) AND $data['response'] == 'timeout')
		{
			$this->show_message($this->phrase['final']['step_timed_out']);
			return;
		}

		$this->show_message($this->phrase['final']['merge_template_changes']);
		$startat = intval($data['startat']);
		require_once(DIR . '/includes/class_template_merge.php');
		if ($startat < 0)
		{
			// finished, need to rebuild styles.
			// Style rebuild sometimes needs a session.
			vB_Upgrade::createAdminSession();

			if ($error = build_all_styles(0, 0, '', true))
			{
				$this->add_error($error, self::PHP_TRIGGER_ERROR, true);
				return false;
			}
			$this->show_message(sprintf($this->phrase['vbphrase']['processing_complete']));
			return;
		}

		$products = array("'vbulletin'");

		// VBV-14672: Skip merges for styles with GUID (currently themes only)
		$styleids = array();
		if (!empty($upgrade_options['template_merge']['skip_themes']))
		{
			$stylesWithGuidQry = vB::getDbAssertor()->assertQuery('vBInstall:getStylesWithGUID');
			foreach ($stylesWithGuidQry AS $row)
			{
				$styleids[] = intval($row['styleid']);
			}
		}

		$merge_data = new vB_Template_Merge_Data($this->registry);
		$merge_data->start_offset = $startat;
		if (intval($upgrade_options['template_merge']['batch_size']) > 0)
		{
			$merge_data->batch_size = intval($upgrade_options['template_merge']['batch_size']);
		}
		$merge_data->add_condition($c = "tnewmaster.product IN (" . implode(', ', $products) . ")");

		if (!empty($styleids))
		{
			$merge_data->add_condition($c = "tcustom.styleid NOT IN (" . implode(', ', $styleids) . ")");
		}

		$merge = new vB_Template_Merge($this->registry);
		if (intval($upgrade_options['template_merge']['time_limit']) > 0)
		{
			$merge->time_limit = intval($upgrade_options['template_merge']['time_limit']);
		}
		else
		{
			$merge->time_limit = 4;
		}

		$output = array();
		$completed = $merge->merge_templates($merge_data, $output);

		if ($output)
		{
			foreach($output AS $message)
			{
				$this->show_message($message);
			}
		}

		$processed = $merge->fetch_processed_count();
		$this->show_message(sprintf($this->phrase['core']['processed_x_records_starting_at_y'], $processed, $startat));
		if ($completed)
		{
			// Hack to allow style rebuild to be in its own iteration due to mitigate timeout concerns...
			$this->show_message(sprintf($this->phrase['final']['merge_complete_rebuilding_style_information']));
			$startat = -1;
			return array('startat' =>  $startat);
		}
		else
		{
			$startat = $startat + $processed;
			return array('startat' =>  $startat);
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103823 $
|| #######################################################################
\*=========================================================================*/
