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

class vB_Xml_Import_Route extends vB_Xml_Import
{
	protected function import($onlyGuid = array())
	{
		// get all columns but the key
		$routeTable = $this->db->fetchTableStructure('routenew');
		$routeTableColumns = array_diff($routeTable['structure'], array('arguments', 'contentid', $routeTable['key']));

		if (empty($this->parsedXML['route']))
		{
			$this->parsedXML['route'] = array();
		}

		if (is_string($onlyGuid))
		{
			$onlyGuid = array($onlyGuid);
		}

		$routes = is_array($this->parsedXML['route'][0]) ? $this->parsedXML['route'] : array($this->parsedXML['route']);

		$redirects = array();
		foreach ($routes AS $route)
		{
			if (!empty($onlyGuid) AND !in_array($route['guid'], $onlyGuid, true))
			{
				continue;
			}

			$values = array();
			foreach($routeTableColumns AS $col)
			{
				if (isset($route[$col]))
				{
					$values[$col] = $route[$col];
				}
			}

			//this is a guid in the xml rather than an id which the db wants.
			//we can't look it up now because we might not have seen that route yet.
			if (isset($values['redirect301']))
			{
				$redirects[$route['guid']] = $values['redirect301'];
				unset($values['redirect301']);
			}

			if (!isset($route['class']))
			{
				$values['class'] = '';
			}
			$condition = array('guid' => $route['guid']);
			$existing = $this->db->getRow('routenew', $condition);

			if ($existing AND !empty($existing['routeid']))
			{
				//If we have a route with this guid we leave it alone. The customer may have intentionally changed it
				//see VBV-13586.
				$routeid = $existing['routeid'];
			}
			else
			{
				$class = (isset($route['class']) AND !empty($route['class']) AND class_exists($route['class'])) ? $route['class'] : vB5_Route::DEFAULT_CLASS;
				$values['arguments'] = call_user_func_array(array($class, 'importArguments'), array($route['arguments']));
				$values['contentid'] = call_user_func_array(array($class, 'importContentId'), array(unserialize($values['arguments'])));

				// route.regex needs to be unique. If it's not, add (usually append) -1, -2, -3 etc. at
				// the place where the marker is found in the route.
				// If regex ends up getting changed, prefix will be changed to match (note
				// that they both need to contain the marker placeholder).
				$testRegex = str_replace('{{DEDUPE-INSERT-MARKER}}', '', $values['regex']);
				$dupeCheck = $this->db->getRow('routenew', array('regex' => $testRegex));
				if (!empty($dupeCheck))
				{
					// need to change the URL for the new page going into the system
					if (strpos($values['regex'], '{{DEDUPE-INSERT-MARKER}}') !== false)
					{
						$i = 1;
						while(true)
						{
							$testRegex = str_replace('{{DEDUPE-INSERT-MARKER}}', '-' . $i, $values['regex']);
							$dupeCheck = $this->db->getRow('routenew', array('regex' => $testRegex));
							if (empty($dupeCheck))
							{
								// found a winner
								$values['regex'] = $testRegex;

								// prefix needs to match regex
								$values['prefix'] = str_replace('{{DEDUPE-INSERT-MARKER}}', '-' . $i, $values['prefix']);

								break;
							}

							// something's not right; let's avoid an infinite loop
							if ($i > 1000)
							{
								throw new Exception('Unable to rename route regex for ' . $values['guid'] . '. Possible infinite loop.');
							}

							++$i;
						}
					}
					else
					{
						// not sure what the best behavior is if we have an unresolvable conflict
						// do we throw an exception and cause the upgrade to fail?
						// if we get here, it means there is a newly added default vBulletin
						// route that doesn't contain the dedupe marker insertion point.
						// there's a unit test in place that *should* prevent that from ever shipping
					}
				}
				// always remove the insert marker, if it hasn't been already
				$values['regex'] = str_replace('{{DEDUPE-INSERT-MARKER}}', '', $values['regex']);
				$values['prefix'] = str_replace('{{DEDUPE-INSERT-MARKER}}', '', $values['prefix']);


				// do the insert
				$routeid = $this->db->insertIgnore('routenew', $values);

				//We need to make sure the name is unique. Collisions should be very rare but not impossible.

				if (is_array($routeid))
				{
					$routeid = array_pop($routeid);
				}
			}

			vB_Xml_Import::setImportedId(vB_Xml_Import::TYPE_ROUTE, $route['guid'], $routeid);
		}

		if (count($redirects))
		{
			$map = array();
			$routes = $this->db->select('routenew', array('guid' => $redirects), array('routeid', 'guid'));
			foreach ($routes AS $route)
			{
				$map[$route['guid']] = $route['routeid'];
			}

			foreach($redirects AS $source => $dest)
			{
				if (isset($map[$dest]))
				{
				 	$this->db->update('routenew', array('redirect301' => $map[$dest]), array('guid' => $source));
				}
				else
				{
					throw new Exception("Could not find redirect route '$dest' for route '$source'");
				}
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
