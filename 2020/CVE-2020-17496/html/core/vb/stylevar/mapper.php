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

/*	## Example ##
	$mapper = new vB_Stylevar_Mapper();

	// Mappings
	$mapper->addMapping('body_bg_color', 'body_bg_color2');
	$mapper->addMapping('body_link_color', 'body_link_color2', 'vbulletin', true);
	$mapper->addMapping('tabbar_bg', 'tabbar_bg2');
	$mapper->addMapping('body_bg_color.color', 'body_background.color');

	// Presets
	$mapper->addPreset('tabbar_bg.color', 'GREEN');

	// Process Mappings
	if ($mapper->load() AND $mapper->process())
	{
		echo 'Processing ';
		//$mapper->displayResults(); // DEBUG //
		$mapper->processResults();
	}
	else
	{
		echo 'Nothing to do ';
	}
*/

class vB_Stylevar_Mapper
{
	use vB_Trait_NoSerialize;

	var $assertor;
	var $dateline;

	// Flags
	var $loaded = false;
	var $mappings = false;
	var $processed = false;

	// Stylevar Data
	var $master = array();
	var $custom = array();
	var $result = array();

	// Mapping Data
	var $mapper = array();
	var $preset = array();
	var $delete = array();

	// Product Data
	var $styles = array();
	var $product = array();
	var $productlist = array();
	var $masterstyleid;

	function __construct($masterstyleid = -1)
	{
		// Set initial stuff
		$this->dateline = time();
		$this->assertor = vB::getDbAssertor();
		$this->productlist = vB::get_datastore()->get_value('products');
		$this->masterstyleid = $masterstyleid;

		$this->styles[] = $this->masterstyleid;
		$styles = $this->assertor->getRows(
			'getStylesForMaster',
			array(
				'masterid' => $this->masterstyleid
			)
		);

		foreach ($styles AS $style)
		{
			$this->styles[] = $style['styleid'];
		}
	}

	public function addMapping($mapfrom, $mapto, $product = 'vbulletin', $delete = false)
	{
		// Add a mapping
		$this->mappings = true;
		$this->mapper[$mapfrom][] = $mapto;

		list($source_var, $source_type) = explode('.', $mapfrom);
		list($destination_var, $destination_type) = explode('.', $mapto);

		if ($product)
		{
			$this->product[$destination_var] = $product;
		}

		if ($delete)
		{
			$this->delete[$source_var] = true;
		}
	}

	public function addPreset($mapto, $value, $forced = true, $verify = '')
	{
		// Add a preset
		$this->mappings = true;
		$this->preset[$mapto] =
			array(
				'value' => $value,
				'forced' => $forced,
				'verify' => $verify,
			);
	}

	public function removeStylevar($stylevar)
	{
		// Mark stylevar to be deleted
		list($source_var, $source_type) = explode('.', $stylevar);

		$this->delete[$source_var] = true;
	}

	function load()
	{
		// Get Stylevar Data
		$svdata = $this->assertor->getRows(
			'getStylevarData',
			array(
				'styles' => $this->styles,
				'masterid' => $this->masterstyleid,
			)
		);

		// Build master & custom lists
		foreach ($svdata AS $sv)
		{
			$this->loaded = true;
			$style = $sv['styleid'];
			$stylevar = $sv['stylevarid'];
			$data = @unserialize($sv['value']);

			// Store valid data only
			if (is_array($data))
			{
				if ($style == $this->masterstyleid)
				{
					$this->master[$stylevar] = $data;
				}
				else
				{
					$this->custom[$stylevar][$style] = $data;
				}
			}
		}

		return $this->loaded;
	}

	function process()
	{
		// No data !
		if (!$this->loaded)
		{
			return false;
		}

		// No mappings ..
		if (!$this->mappings)
		{
			return !empty($this->delete);  // We may still have deletes
		}

		/* For a preset to work, the destination stylevar must exist in the mapping results.
		   To help this happen we map each preset to itself, after all the main mappings.
		   This is still not a 100% guarantee that the preset will happen, but it helps. */

		foreach($this->preset AS $source => $data)
		{
			$this->addMapping($source, $source);
		}

		// Process mappings
		foreach($this->mapper AS $source => $destinations)
		{
			// Multiple destinations per source
			foreach($destinations AS $destination)
			{
				// Get stylevar names and value types
				list($source_var, $source_type) = explode('.', $source);
				list($destination_var, $destination_type) = explode('.', $destination);

				// Work out if merging whole stylevar and mapping types
				$merge = (!$source_type AND !$destination_type ? true : false);
				$source_type = ($source_type ? $source_type : $destination_type);
				$destination_type = ($destination_type ? $destination_type : $source_type);

				// Process the stylevars if they exist
				if ($this->custom[$source_var])
				{
					foreach($this->custom[$source_var] AS $style => $source_data)
					{
						/* If we have previously processed this stylevar, load it.
						   If not, load any custom version of the destination.
						   If we still have nothing, load the master values. If we
						   still have nothing, just start a new blank array */

						$destination_data = $this->result[$destination_var][$style];

						if (!$merge AND !$destination_data)
						{
							$destination_data = $this->custom[$destination_var][$style];
						}

						if (!$destination_data)
						{
							$destination_data = $this->master[$destination_var];
						}

						if (!$destination_data)
						{
							$destination_data = array();
						}

						if ($merge)
						{
							// Copy all source data into the destination
							foreach($source_data AS $source_type => $source_value)
							{
								$destination_data[$source_type] = $source_value;
							}
						}
						else
						{
							// Copy just the source datatype into the destination
							$destination_data[$destination_type] = $source_data[$source_type];

							// Remove the old datatype if its not the same as the new type
							if ($source_type != $destination_type)
							{
								unset($destination_data[$source_type]);
							}
						}

						// All done, save it
						$this->processed = true;
						$this->result[$destination_var][$style] = $destination_data;
					}
				}
			}
		}

		foreach($this->preset AS $source => $value_data)
		{
			list($source_var, $source_type) = explode('.', $source);

			/* Load the existing results if they already exist.
			   If not, load all the customised data. If neither
			   of these exist we cannot do anything. */

			$source_data = $this->result[$source_var];

			if (!$source_data)
			{
				$source_data = $this->custom[$source_var];
			}

			if ($source_data)
			{
				// Add the preset to each customised style
				foreach($source_data AS $style => $destination_data)
				{
					$exists = $destination_data[$source_type] ? true : false;
					$verify = $value_data['verify'] ? 'verify' . ucfirst($value_data['verify']) : false;

					if ($exists AND $verify)
					{
						$exists = $this->$verify($destination_data[$source_type]);
					}

					if(!$exists OR $value_data['forced'])
					{
						$this->processed = true;
						$destination_data[$source_type] = $value_data['value'];
						$this->result[$source_var][$style] = $destination_data;
					}
				}
			}
		}

		return ($this->processed OR !empty($this->delete));
	}

	// Debug Function //
	function displayResults($stop = false)
	{
		echo "<br />Results ; <br />";
		foreach($this->result AS $stylevar => $styledata)
		{
			$product = $this->product[$stylevar];
			echo "<br />Data for : $stylevar ($product) <br />";
			foreach($styledata AS $style => $data)
			{
				$svdata = @serialize($data);
				echo "Style $style : $svdata <br />";
			}
		}

		echo "<br />Deletes ; <br /><br />";
		foreach($this->delete AS $stylevar => $dummy)
		{
			echo "Delete : $stylevar <br />";
		}

		if ($stop)
		{
			print_r($this);
			exit;
		}
	}

	function processResults()
	{
		// Process each resulting stylevar for each style
		foreach($this->result AS $stylevar => $styledata)
		{
			foreach($styledata AS $style => $data)
			{
				// Only add if its for an installed product
				if ($this->productlist[$this->product[$stylevar]])
				{
					$this->addStlyevar($stylevar, $style, $data, $this->dateline);
				}
			}
		}

		// Process all the stylevar deletes
		foreach($this->delete AS $stylevar => $dummy)
		{
			$this->deleteStylevar($stylevar);
		}
	}

	function addStlyevar($stylevar, $style, $data, $time = 0, $user = 'SV-Mapper')
	{
		if (!$time)
		{
			$time = time();
		}

		// If valid data, add/update it
		if ($svdata = @serialize($data))
		{
			$replace[] = array(
				'stylevarid' => $stylevar,
				'styleid' => $style,
				'value' => $svdata,
				'dateline' => $time,
				'username' => $user,
			);

			$this->assertor->assertQuery(
				'replaceValues',
				array(
					'table' => 'stylevar',
					'values' => $replace,
				)
			);
		}
	}

	function deleteStylevar($stylevar)
	{
		/* Delete the stylevar if its set to be deleted
		   but only if it belongs to the core product(s),
		   we dont want to zap any modification stylevars */

		if ($this->delete[$stylevar])
		{
			// Remove style data
			$this->assertor->assertQuery(
				'deleteStylevarData',
				array(
					'stylevar' => $stylevar,
					'styles' => $this->styles,
					'products' => array('vbulletin'),
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED,
				)
			);

			$phrases = array(
				"stylevar_{$stylevar}_name",
				"stylevar_{$stylevar}_description",
			);

			// Remove phrase data
			$this->assertor->assertQuery(
				'deleteStylevarPhrases',
				array(
					'phrases' => $phrases,
					'products' => array('vbulletin'),
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED,
				)
			);
		}
	}

	function verifyUnits($unit)
	{
		$units = array(
			'%',
			'px',
			'pt',
			'em',
			'rem',
			'ch',
			'ex',
			'pc',
			'in',
			'cm',
			'mm',
			'vw',
			'vh',
			'vmin',
			'vmax',
		);

		return in_array($unit, $units);
	}

	/**
	 * Updates any stylevars that inherit from $oldname to inherit from $newname instead
	 *
	 * NOTE: This works mostly separate from stylevar mapping, since when you map from
	 * one stylevar to another, you're not necessary *renaming* it to the new one... you might
	 * be merely sourcing the value of one to populate the other. If you're actually
	 * renaming a stylevar, and the old one won't be used anymore, that's when you call
	 * this function. This should be called after doing the regular mapping.
	 *
	 * @param  string Old stylevar name (stylevarid)
	 * @param  string New stylevar name (stylevarid)
	 *
	 * @return bool   True if anything was updated, false otherwise.
	 */
	public function updateInheritance($oldname, $newname)
	{
		$updated = false;

		$stylevars = $this->assertor->getRows('stylevar', array(
			vB_dB_Query::CONDITIONS_KEY => array(
				array(
					'field' => 'value',
					'value' => $oldname,
					'operator' => vB_dB_Query::OPERATOR_INCLUDES,
				),
			),
		));

		foreach ($stylevars AS $stylevar)
		{
			$data = array();

			// rename the stylevar in any other stylevars that inherit from it
			if (strpos($stylevar['value'], $oldname) !== false)
			{
				$value = unserialize($stylevar['value']);
				foreach ($value AS $k => $v)
				{
					if (substr($k, 0, 9) == 'stylevar_')
					{
						if (strpos($v, $oldname) !== false)
						{
							$value[$k] = str_replace($oldname, $newname, $v);
						}
					}
				}
				$value = serialize($value);
				if ($value != $stylevar['value'])
				{
					$data['value'] = $value;

					// debug output
					//echo "STYLEVAR: $stylevar[stylevarid]\n" .
					//	"STYLEID: $stylevar[styleid]\n" .
					//	"FROM: $stylevar[value]\n" .
					//	"TO:   $value\n\n";
				}
			}

			if (!empty($data))
			{
				$conditions = array(
					'stylevarid' => $stylevar['stylevarid'],
					'styleid' => $stylevar['styleid'],
				);

				$this->assertor->update('stylevar', $data, $conditions);
				$updated = true;
			}
		}

		return $updated;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
