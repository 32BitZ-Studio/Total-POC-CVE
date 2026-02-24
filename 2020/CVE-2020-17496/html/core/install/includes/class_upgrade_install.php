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
	exit(1);
}

class vB_Upgrade_install extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = 'install';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = 'install';

	/*Properties====================================================================*/


	/**
	* Step #1
	*
	 */

	function step_1($data = null)
	{
		$havetables = false;
		$vbexists = false;

		$tables = $this->db->query("SHOW TABLES");
		while ($table = $this->db->fetch_array($tables))
		{
			$havetables = true;
			break;
		}

		if ($havetables)
		{
			// see if there's a user table already
			$vbexists = $this->fetch_vbexists();
		}

		if ($data['htmlsubmit'] AND $data['response'] == 'yes')
		{
			$result = $this->db->query_write("SHOW TABLES");
			while ($currow = $this->db->fetch_array($result, vB_Database::DBARRAY_NUM))
			{
				if (in_array($currow[0], $data['htmldata']))
				{
					$this->db->query_write("DROP TABLE IF EXISTS $currow[0]");
					$this->show_message(sprintf($this->phrase['vbphrase']['remove_table'], $currow[0]));
				}
			}

			$vbexists = $this->fetch_vbexists();
			if (!$vbexists)
			{
				$havetables = false;
			}
			unset($data['response']);
		}

		if ($vbexists)
		{
			if ($data['response'])
			{
				if ($data['response'] == 'no')
				{
					$this->add_error($this->phrase['install']['new_install_cant_continue'], self::PHP_TRIGGER_ERROR, true);
					return;
				}
				else	// Data response = yes... fall down to schema load below
				{

				}
			}
			else
			{
				return array(
					'prompt'  => $this->phrase['install']['connect_success_vb_exists'],
					'confirm' => true,
					'ok'      => $this->phrase['vbphrase']['yes'],
					'cancel'  => $this->phrase['vbphrase']['no'],
				);
			}
		}

		if ($havetables)
		{
			if ($data['response'])
			{
				if ($data['response'] == 'no')
				{
					// fall down to below...
				}
				else
				{
					$schema =& $this->load_schema();

					$tables = array();
					$tables_result = $this->db->query_read("SHOW TABLES");
					while ($table = $this->db->fetch_array($tables_result, vB_Database::DBARRAY_NUM))
					{
						$tables["$table[0]"] = $table[0];
					}

					$default_tables = array_keys($schema['CREATE']['query']);

					$default_tables = array_merge($default_tables, $this->fetch_product_tables('dummy')); // Any Integrated 3rd party products

					$html = '<div class="advancedconfirmbody">';
					$html .= $this->phrase['install']['delete_tables_instructions'];
					$html .= "<p><label><input type=\"checkbox\" id=\"allbox\" onclick=\"js_check_all(this.form)\" />{$this->phrase['install']['select_deselect_all_tables']}</label></p>";

					$options = '';
					foreach ($tables AS $table)
					{
						if (substr($table, 0, strlen(TABLE_PREFIX)) == TABLE_PREFIX)
						{
							$table_basename = substr($table, strlen(TABLE_PREFIX));

							if (in_array($table_basename, $default_tables))
							{
								$checked = ' checked="checked"';
								$class = 'alt2';
							}
							else
							{
								$checked = '';
								$class = 'alt1';
							}

							$html .= "<label class=\"$class\" style=\"float:" . vB_Template_Runtime::fetchStyleVar('left') . "; display:block; width:250px; margin:0px 6px 6px 0px\"><input type=\"checkbox\" name=\"htmldata[]\" value=\"$table\"$checked />" . TABLE_PREFIX . "<strong>$table_basename</strong></label>\n";
						}
						else
						{
							$html .= "<label class=\"alt1\" style=\"float:" . vB_Template_Runtime::fetchStyleVar('left') . "; display:block; width:250px; margin:0px 6px 6px 0px\"><input type=\"checkbox\" name=\"htmldata[]\" value=\"$table\" /><strong>$table</strong></label>\n";
						}
					}
					$html .= '</div>';

					return array(
						'html'  => $html,
						'width' => '640px',
						'ok'    => $this->phrase['install']['delete_selected_tables'],
						'title' => $this->phrase['install']['reset_database'],
					);
				}
			}
			else
			{
				return array(
					'prompt'  => $this->phrase['install']['connect_success_tables_exist'],
					'confirm' => true,
					'ok'      => $this->phrase['vbphrase']['yes'],
					'cancel'  => $this->phrase['vbphrase']['no'],
				);
			}
		}

		$this->show_message($this->phrase['install']['connect_success']);
	}

	function step_2($data = null)
	{
		$charset = 'utf8';

		//see if we can use the mb4 version.
		$sql = "SHOW CHARACTER SET LIKE 'utf8mb4'";
		$result =  $this->db->query($sql);

		$row = $this->db->fetch_row($result);
		if ($row[0] == 'utf8mb4')
		{
			$charset = 'utf8mb4';
		}

		if (!empty($data['response']))
		{
			if ($data['response'] == 'yes')
			{
				$config = vB::getConfig();
				$dbname = $config['Database']['dbname'];

				$sql = "ALTER DATABASE $dbname CHARACTER SET '$charset'";
				$result = $this->db->query_write($sql);
				$this->show_message(sprintf($this->phrase['install']['database_charset_updated'], $charset));
				return;
			}
			else
			{
				$this->skip_message();
				return;
			}
		}

		$temp = $this->db->query("SELECT DATABASE()");
		$temp = $this->db->fetch_array($temp);

		$charset = $this->db->query("SHOW VARIABLES LIKE 'character_set_database'");
		$charset = $this->db->fetch_array($charset);

		if (strcasecmp($charset['Value'], 'utf8') != 0 AND strcasecmp($charset['Value'], 'utf8mb4') != 0)
		{
			return array(
				'prompt'  => sprintf($this->phrase['install']['change_database_charset'], $charset['Value']),
				'confirm' => true,
				'ok'      => $this->phrase['vbphrase']['yes'],
				'cancel'  => $this->phrase['vbphrase']['no'],
			);
		}

		//already utf-8
		$this->skip_message();
	}

	/**
	* Step #3 - Create Tables
	*
	*/
	function step_3()
	{
		$schema =& $this->load_schema();
		$this->exec_queries($schema['CREATE']['query'], $schema['CREATE']['explain']);
	}

	/**
	* Step #4 - Insert Data
	*
	*/
	function step_4()
	{
		$schema =& $this->load_schema();
		$this->exec_queries($schema['INSERT']['query'], $schema['INSERT']['explain']);
	}

	/**
	* Step #5 - Ask Options...
	*
	*/
	function step_5($data = null)
	{
		if (!$data['response'] && vB_Upgrade::isCLI())
		{
			//try to use config data from cli-specific file
			$vb5_config = vB_Upgrade_Cli::getConfigCLI();
			if(!empty($vb5_config['cli']['forum_data']))
			{
				$data = array('htmlsubmit' => 'yes','response' => 'yes', 'htmldata' => $vb5_config['cli']['forum_data']);
				// VBV-9931
				$data['htmldata']['frontendurl'] = substr($data['htmldata']['bburl'], 0, strpos($data['htmldata']['bburl'], '/core'));
			}
		}
		require_once(DIR . '/includes/adminfunctions_options.php');
		if ($data['response'])
		{
			$datastore = vB::getDatastore();
			$datastore->setOption('bbtitle', $data['htmldata']['bbtitle'], true);
			$datastore->setOption('bburl', $data['htmldata']['bburl'], true);
			$datastore->setOption('frontendurl', $data['htmldata']['frontendurl'], true);
			$datastore->setOption('webmasteremail', $data['htmldata']['webmasteremail'], true);

			if (!($xml = file_read(DIR . '/install/vbulletin-settings.xml')))
			{
				$this->add_error(sprintf($this->phrase['vbphrase']['file_not_found'], 'vbulletin-settings.xml'), self::PHP_TRIGGER_ERROR, true);
				return;
			}

			// Set a few additional options based on the configuration of this installation

			// 1. Image handling
			$gdinfo = fetch_gdinfo();
			if ($gdinfo['version'] >= 2)
			{
				if ($gdinfo['freetype'] == 'freetype')
				{
					$datastore->setOption('regimagetype', 'GDttf', true);
				}
			}
			else
			{
				$datastore->setOption('hv_type', '0', true);
				$datastore->setOption('regimagetype', '', true);
			}

			// 2. Need to set default language id!
			$languageinfo = $this->db->query_first("
				SELECT languageid
				FROM " . TABLE_PREFIX . "language
			");
			$datastore->setOption('languageid', $languageinfo['languageid'], true);

			// 3. CKEditor Emoji plugin setting
			// See also vB_Upgrade_556a1::step_2
			$charsets = vB::getDbAssertor()->getDbCharsets('text', 'rawtext');
			if ($charsets['effectiveCharset'] == 'utf8mb4')
			{
				$datastore->setOption('useemoji', 1, true);
			}

			// Now we can import the settings.
			// Need to import settings here to get the custom settings inserted ..
			xml_import_settings($xml);

			//Set the datastore custom profile fields cache.
			require_once(DIR . '/includes/adminfunctions_profilefield.php');
			build_profilefield_cache();

			$this->show_message($this->phrase['install']['general_settings_saved']);
			return;
		}

		$port = intval($_SERVER['SERVER_PORT']);
		$port = in_array($port, array(80, 443)) ? '' : ':' . $port;
		$scheme = (($port == ':443') OR (isset($_SERVER['HTTPS']) AND $_SERVER['HTTPS'] AND ($_SERVER['HTTPS'] != 'off'))) ? 'https://' : 'http://';

		$vboptions['bburl'] = $scheme . $_SERVER['SERVER_NAME'] . $port . substr(SCRIPTPATH,0, strpos(SCRIPTPATH, '/install/'));
		$vboptions['frontendurl'] = substr($vboptions['bburl'],0, strpos($vboptions['bburl'], '/core'));

		$webmaster = 'webmaster@' . preg_replace('#^www\.#', '', $_SERVER['SERVER_NAME']);

		$html = '<table cellspacing="0" cellpadding="4" border="0" align="center" width="100%" id="cpform_table" class="" style="border-collapse: separate;">
<tbody>
<tr valign="top">
	<td class="alt1">' .
		$this->phrase['install']['bbtitle'] . '
		<span id="htmldata[bbtitle]_error" class="usererror hidden">' . $this->phrase['install']['field_required'] . '</span>
	</td>
	<td class="alt1"><input type="text" tabindex="1" dir="ltr" size="40" value="Forums" name="htmldata[bbtitle]" class="bginput" vbrequire="1" /></td>
</tr>
<tr valign="top">
	<td class="alt1">' .
		$this->phrase['install']['bburl'] . '
		<span id="htmldata[bburl]_error" class="usererror hidden">' . $this->phrase['install']['field_required'] . '</span>
	</td>
	<td class="alt1"><input type="text" tabindex="1" dir="ltr" size="40" value="' . $vboptions['bburl'] . '" name="htmldata[bburl]" class="bginput" vbrequire="1" /></td>
</tr>
<tr valign="top">
	<td class="alt1">' .
		$this->phrase['install']['frontendurl'] . '
		<span id="htmldata[frontendurl]_error" class="usererror hidden">' . $this->phrase['install']['field_required'] . '</span>
	</td>
	<td class="alt1"><input type="text" tabindex="1" dir="ltr" size="40" value="' . $vboptions['frontendurl'] . '" name="htmldata[frontendurl]" class="bginput" vbrequire="1" /></td>
</tr>
<tr valign="top">
	<td class="alt1">' .
		$this->phrase['install']['webmasteremail'] . '
		<span id="htmldata[webmasteremail]_error" class="usererror hidden">' . $this->phrase['install']['field_required'] . '</span>
	</td>
	<td class="alt1"><input type="text" tabindex="1" dir="ltr" size="40" value="' . $webmaster . '" name="htmldata[webmasteremail]" class="bginput" vbrequire="1" /></td>
</tr>
</tbody></table>';

		return array(
			'html'       => $html,
			'width'      => '640px',
			'hidecancel' => true,
			'title'      => $this->phrase['install']['general_settings'],
			'reset'      => true,
		);
	}

	/**
	* Step #6 - Default User Setup...
	*
	*/
	function step_6($data = null)
	{
		vB_Upgrade::createAdminSession();
		if (! $data['response'] AND vB_Upgrade::isCLI())
		{
			$vb5_config = vB_Upgrade_Cli::getConfigCLI();

			if (!empty($vb5_config['cli']['user_data']))
			{
				$data = array('htmlsubmit' => "yes",'response' => "yes", 'htmldata' => $vb5_config['cli']['user_data']);
			}
			else
			{
				$data = array('htmlsubmit' => 'yes','response' => 'yes',
					'htmldata' => array('username' =>'admin', 'password' =>'password', 'confirmpassword' => 'password',
					'email'  => 'admin@invalid.nul'));
			}
		}

		if ($data['response'])
		{
			array_map('trim', $data['htmldata']);

			$errors = array();
			if (empty($data['htmldata']['username']))
			{
				$errors['username'] = $this->phrase['install']['error_username'];
			}
			if (empty($data['htmldata']['email']) OR !is_valid_email($data['htmldata']['email']))
			{
				$errors['email'] = $this->phrase['install']['error_email'];
			}
			if (empty($data['htmldata']['password']) OR empty($data['htmldata']['confirmpassword']))
			{
				if (empty($data['htmldata']['password']))
				{
					$errors['password'] = $this->phrase['install']['error_password'];
				}
				else if (empty($data['htmldata']['confirmpassword']))
				{
					$errors['confirmpassword'] = $this->phrase['install']['error_confirmpassword'];
				}
			}
			else if ($data['htmldata']['password'] != $data['htmldata']['confirmpassword'])
			{
				$errors['mismatch'] = $this->phrase['install']['error_password_not_match'];
			}
			else if ($data['htmldata']['password'] == $data['htmldata']['username'])
			{
				$errors['samepasswordasusername'] = $this->phrase['install']['error_same_password_as_username'];
			}

			// check if a user already exists. If so, DO NOT CREATE A NEW USER.
			$vbexists = $this->fetch_vbexists();
			if (!$vbexists)
			{
				$errors[] = $this->phrase['install']['user_table_missing'];	// we can't create a user without a user table.
			}
			else
			{
				vB::getConfig(); // this defines TABLE_PREFIX
				// assuming if user table exists, userid will exist. If a user exists, DO NOT CREATE A NEW USER
				if ($this->db->query_first("SELECT userid FROM " . trim(TABLE_PREFIX) . "user LIMIT 1"))
				{
					$errors[] = $this->phrase['install']['user_already_exists'];
				}
			}

			if (empty($errors))
			{
				require_once(DIR . '/includes/class_bitfield_builder.php');
				vB_Bitfield_Builder::save($this->db);

				$admin_defaults = array(
					/*'showsignatures', */ // don't show signatures inline by default
					'showavatars',
					'showimages',
					'adminemail',
					'dstauto',
					'receivepm',
					'showusercss',
					'receivefriendemailrequest',
					'vm_enable',
					'moderatefollowers',
					'enable_pmchat',
					'birthdayemail',
				);
				$admin_useroption = 0;
				foreach ($admin_defaults AS $bitfield)
				{
					$admin_useroption |= $this->registry->bf_misc_useroptions["$bitfield"];
				}

				///////////////
				//  will need these in both branches below, set them up here
				///////////////
				$loginLib = vB_Library::instance('login');

				//we do this at the end as part of shared code with the upgrade, but we need these values in
				//the DB *RIGHT NOW* so we can properly create the user(s)
				$loginLib->importPasswordSchemes();

				//ignore history check in set password.
				$passwordOptions = array('passwordhistorylength' => 0);
				$passwordOverrides = array('passwordhistory' => true);

				//moderator permissions
				$permissions = array_sum($this->registry->bf_misc_moderatorpermissions) - ($this->registry->bf_misc_moderatorpermissions['newthreademail'] +
					$this->registry->bf_misc_moderatorpermissions['newpostemail']);
				$permissions2 = array_sum($this->registry->bf_misc_moderatorpermissions2);

				if (vB_Upgrade::isCLI() AND !empty($vb5_config['cli']['superadmin']) AND !empty($vb5_config['cli']['saas_admin']))
				{
					/*get the administrator permissions*/
					$parser = new vB_XML_Parser(false, DIR . '/includes/xml/bitfield_vbulletin.xml');
					$bitfields = $parser->parse();
					$saas_admin_useroption = $superadminpermission = $adminpermission = 0;
					foreach ($bitfields['bitfielddefs']['group'] AS $topGroup)
					{
						if (($topGroup['name'] == 'ugp'))
						{
							foreach ($topGroup['group'] AS $group)
							{
								if ($group['name'] == 'adminpermissions')
								{
									foreach ($group['bitfield'] as $fielddef)
									{
										if (empty($vb5_config['cli']['removeAdminPermissions']) OR !in_array($fielddef['name'], $vb5_config['cli']['removeAdminPermissions']))
										{
											$adminpermission |= $fielddef['value'];
										}
										$superadminpermission |= $fielddef['value'];
									}
								}
								else if (($group['name'] == 'useroptions') AND !empty($vb5_config['cli']['saas_admin']['user_options']))
								{
									foreach ($group['bitfield'] as $fielddef)
									{
										if (in_array($fielddef['name'], $vb5_config['cli']['saas_admin']['user_options']))
										{
											$saas_admin_useroption |= $fielddef['value'];
										}
									}
								}
							}
						}
					}

					foreach ($vb5_config['cli']['saas_admin']['user_options'] AS $name => $bitfield)
					{
						$saas_admin_useroption |= $this->registry->bf_misc_useroptions["$bitfield"];
					}

					//saas admin user
					install_add_user(2, htmlspecialchars_uni($data['htmldata']['username']), $this->phrase['install']['usergroup_admin_usertitle'],
						$data['htmldata']['email'], $admin_useroption, $adminpermission, $permissions, $permissions2);

					$loginLib->setPassword(2, $data['htmldata']['password'], $passwordOptions, $passwordOverrides);

					//super admin
					install_add_user(1, htmlspecialchars_uni($vb5_config['cli']['superadmin']['username']), $this->phrase['install']['usergroup_admin_usertitle'],
						$vb5_config['cli']['superadmin']['email'], $saas_admin_useroption, $superadminpermission, $permissions, $permissions2);

					$loginLib->setPassword(1, $vb5_config['cli']['superadmin']['password'], $passwordOptions, $passwordOverrides);
				}
				else
				{
					install_add_user(1, htmlspecialchars_uni($data['htmldata']['username']), $this->phrase['install']['usergroup_admin_usertitle'],
						$data['htmldata']['email'], $admin_useroption, array_sum($this->registry->bf_ugp_adminpermissions) - 3, $permissions, $permissions2);

					$loginLib->setPassword(1, $data['htmldata']['password'], $passwordOptions, $passwordOverrides);
				}

				build_image_cache('smilie');
				build_image_cache('avatar');
				build_image_cache('icon');
				build_bbcode_cache();
				require_once(DIR . '/includes/functions_databuild.php');
				build_user_statistics();
				vB_Library::instance('usergroup')->buildDatastore();
				vB::getUserContext()->rebuildGroupAccess();
				require_once(DIR . '/includes/functions_cron.php');
				build_cron_next_run();
				require_once(DIR . '/includes/adminfunctions.php');
				build_attachment_permissions();

				$this->show_message($this->phrase['install']['administrator_account_created']);
				return;
			}
			else
			{
				if(vB_Upgrade::isCLI())
				{
					$this->add_error($errors, self::CLI_CONF_USER_DATA_MISSING, true);
				}
				else
				{
					foreach ($errors AS $key => $value)
					{
						$errors["$key"] = '<span class="usererror">' . $value . '</span>';
					}
				}
			}
		}
		else
		{
			if(vB_Upgrade::isCLI())
			{
				$errors['absentclioptionuser'] = $this->phrase['install']['absent_cli_config_option_user'];
				$this->add_error($errors, self::CLI_CONF_USER_DATA_MISSING, true);
			}
			$data['htmldata'] = array();
		}

		$html = '<table cellspacing="0" cellpadding="4" border="0" align="center" width="100%" id="cpform_table" class="" style="border-collapse: separate;">
<tbody>
<tr valign="top">
	<td class="alt1">' .
	 	$this->phrase['install']['username'] . $errors['username'] . '
		<span id="htmldata[username]_error" class="usererror hidden">' . $this->phrase['install']['field_required'] . '</span>
	</td>
	<td class="alt1">
		<div id="ctrl_username">
			<input type="text" tabindex="1" dir="ltr" size="35" value="' . htmlspecialchars_uni($data['htmldata']['username']) . '" id="it_username_1" name="htmldata[username]" class="bginput" vbrequire="1" />
		</div>
	</td>
</tr>
<tr valign="top">
	<td class="alt2">' .
		$this->phrase['install']['password'] . $errors['password'] . $errors['mismatch'] . $errors['samepasswordasusername'] . '
		<span id="htmldata[password]_error" class="usererror hidden">' . $this->phrase['install']['field_required'] . '</span>
	</td>
	<td class="alt2">
		<div id="ctrl_password">
			<input type="password" autocomplete="off" tabindex="1" size="35" value="' . htmlspecialchars_uni($data['htmldata']['password']) . '" name="htmldata[password]" class="bginput" vbrequire="1" />
		</div>
	</td>
</tr>
<tr valign="top">
	<td class="alt1">' .
		$this->phrase['install']['confirm_password'] . $errors['confirmpassword'] . $errors['mismatch'] . '
		<span id="htmldata[confirmpassword]_error" class="usererror hidden">' . $this->phrase['install']['field_required'] . '</span>
	</td>
	<td class="alt1">
		<div id="ctrl_confirmpassword">
			<input type="password" autocomplete="off" tabindex="1" size="35" value="' . htmlspecialchars_uni($data['htmldata']['confirmpassword']) . '" name="htmldata[confirmpassword]" class="bginput" vbrequire="1" />
		</div>
	</td>
</tr>
<tr valign="top">
	<td class="alt2">' .
		$this->phrase['install']['email_address'] . $errors['email'] . '
		<span id="htmldata[email]_error" class="usererror hidden">' . $this->phrase['install']['field_required'] . '</span>
	</td>
	<td class="alt2">
		<div id="ctrl_email">
			<input type="text" tabindex="1" dir="ltr" size="35" value="' . htmlspecialchars_uni($data['htmldata']['email']) . '" id="it_email_2" name="htmldata[email]" class="bginput" vbrequire="1" />
		</div>
	</td>
</tr>
</tbody></table>';

		return array(
			'html'       => $html,
			'width'      => '640px',
			'hidecancel' => true,
			'title'      => $this->phrase['install']['administrator_account_setup'],
			'reset'      => true,
		);
	}

	/**
	 * Step #7 - Insert install-only admin messages
	 *
	 * Most admin messages are added in upgrade steps to alert the admin
	 * about changes. But there are a few cases where we want to show an
	 * admin message after initial installation.
	 */
	function step_7()
	{
		// Add admin message to warn about links to empty privacy page VBV-18551
		$this->add_adminmessage(
			'after_install_check_privacy_policy_page',
			array(
				'dismissable' => 1,
				'script'      => '',
				'action'      => '',
				'execurl'     => '',
				'method'      => 'get',
				'status'      => 'undone',
			)
		);

		//add the guest user notice.
		//this doesn't *exactly* fit here, but it doesn't seem worth creating
		//an entirely new step over.  We want to move it to the end because it's
		//going to be more reliable if we have the system in place before calling
		//the notice lib and nothing really depends on it being in place before now.
		$data = array(
			'title' => 'default_guest_message',
			'text' => $this->phrase['install']['default_guest_message'],
			'displayorder' => 10,
			'active' => 1,
			'persistent' => 1,
			'dismissible' => 1,
			'criteria' => array('in_usergroup_x' => array('condition1' => 1)),
		);
		vB_Library::instance('notice')->save($data);

		// Add more here if needed.
	}

	/**
	* Load MYSQL schema
	*
	* @return	array
	*/
	private function &load_schema()
	{
		$db =& $this->db;
		$vbphrase =& $this->phrase['vbphrase'];
		$install_phrases =& $this->phrase['install'];
		$phrasetype =& $this->phrase['phrasetype'];
		$customphrases =& $this->phrase['custom'];

		if(vB_Upgrade::isCLI()) {
			require(DIR . '/install/mysql-schema.php');
		}
		else {
			require_once(DIR . '/install/mysql-schema.php');
		}

		return $schema;
	}

	/**
	* Verify if vB is installed -- this function should check all tables in the schema, not just the user table
	*
	* @return	bool
	*/
	private function fetch_vbexists()
	{
		vB::getConfig(); // this defines TABLE_PREFIX
		$this->db->hide_errors();
		$this->db->query_write("SHOW FIELDS FROM " . trim(TABLE_PREFIX) . "user");
		$this->db->show_errors();

		return ($this->db->errno() == 0);
	}

	/**
	* Executes schema queries...
	*
	* @var	array	Queries to execute
	* @var	array Description of queries
	*
	* @return	bool
	*/
	private function exec_queries($query, $explain)
	{
		foreach ($query AS $key => $value)
		{
			$this->run_query(
				$explain["$key"],
				$value
			);
		}
	}

	/**
	* Parse out table creation steps
	*
	* @var	string	Productid
	*
	* @return	array
	*/
	private function fetch_product_tables($productid)
	{
		// Hackish temporary workaround until product schema is moved to a file similar to how vB stores its schema
		$data = @file_get_contents(DIR . "/install/includes/class_upgrade_{$productid}.php");
		$tables = array();
		if (preg_match_all('#CREATE TABLE\s*"\s*\.\s*TABLE_PREFIX\s*\.\s*"([a-z0-9_-]+)#si', $data, $matches))
		{
			foreach($matches[1] AS $table)
			{
				$tables["$table"] = true;
			}
		}

		return array_keys($tables);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103823 $
|| #######################################################################
\*=========================================================================*/
