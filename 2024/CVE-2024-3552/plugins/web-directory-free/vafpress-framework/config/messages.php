<?php

return array(

	////////////////////////////////////////
	// Localized JS Message Configuration //
	////////////////////////////////////////

	/**
	 * Validation Messages
	 */
	'validation' => array(
		'alphabet'     => __('Value needs to be Alphabet', 'vp_w2dc_textdomain'),
		'alphanumeric' => __('Value needs to be Alphanumeric', 'vp_w2dc_textdomain'),
		'numeric'      => __('Value needs to be Numeric', 'vp_w2dc_textdomain'),
		'email'        => __('Value needs to be Valid Email', 'vp_w2dc_textdomain'),
		'url'          => __('Value needs to be Valid URL', 'vp_w2dc_textdomain'),
		'maxlength'    => __('Length needs to be less than {0} characters', 'vp_w2dc_textdomain'),
		'minlength'    => __('Length needs to be more than {0} characters', 'vp_w2dc_textdomain'),
		'maxselected'  => __('Select no more than {0} items', 'vp_w2dc_textdomain'),
		'minselected'  => __('Select at least {0} items', 'vp_w2dc_textdomain'),
		'required'     => __('This is required', 'vp_w2dc_textdomain'),
	),

	/**
	 * Import / Export Messages
	 */
	'util' => array(
		'import_success'    => __('Import succeed, option page will be refreshed..', 'vp_w2dc_textdomain'),
		'import_failed'     => __('Import failed', 'vp_w2dc_textdomain'),
		'export_success'    => __('Export succeed, copy the JSON formatted options', 'vp_w2dc_textdomain'),
		'export_failed'     => __('Export failed', 'vp_w2dc_textdomain'),
		'restore_success'   => __('Restoration succeed, option page will be refreshed..', 'vp_w2dc_textdomain'),
		'restore_nochanges' => __('Options identical to default', 'vp_w2dc_textdomain'),
		'restore_failed'    => __('Restoration failed', 'vp_w2dc_textdomain'),
	),

	/**
	 * Control Fields String
	 */
	'control' => array(
		// select2vp select box
		'select2vp_placeholder' => __('Select option(s)', 'vp_w2dc_textdomain'),
		// fontawesome chooser
		'fac_placeholder'     => __('Select an Icon', 'vp_w2dc_textdomain'),
	),

);

/**
 * EOF
 */