<?php 

$w2dc_color_schemes = array(
		'default' => array(
				'w2dc_primary_color' => '#428bca',
				'w2dc_secondary_color' => '#275379',
				'w2dc_links_color' => '#428bca',
				'w2dc_links_hover_color' => '#275379',
				'w2dc_button_1_color' => '#428bca',
				'w2dc_button_2_color' => '#275379',
				'w2dc_button_text_color' => '#FFFFFF',
				'w2dc_jquery_ui_schemas' => 'redmond',
		),
		'blue' => array(
				'w2dc_primary_color' => '#194df2',
				'w2dc_secondary_color' => '#8895a2',
				'w2dc_links_color' => '#96a1ad',
				'w2dc_links_hover_color' => '#2a6496',
				'w2dc_button_1_color' => '#96a1ad',
				'w2dc_button_2_color' => '#8895a2',
				'w2dc_button_text_color' => '#FFFFFF',
				'w2dc_jquery_ui_schemas' => 'start',
		),
		'gray' => array(
				'w2dc_primary_color' => '#acc7a6',
				'w2dc_secondary_color' => '#2d8ab7',
				'w2dc_links_color' => '#3299cb',
				'w2dc_links_hover_color' => '#236b8e',
				'w2dc_button_1_color' => '#3299cb',
				'w2dc_button_2_color' => '#2d8ab7',
				'w2dc_button_text_color' => '#FFFFFF',
				'w2dc_jquery_ui_schemas' => 'overcast',
		),
		'green' => array(
				'w2dc_primary_color' => '#6cc150',
				'w2dc_secondary_color' => '#64933d',
				'w2dc_links_color' => '#5b9d30',
				'w2dc_links_hover_color' => '#64933d',
				'w2dc_button_1_color' => '#5b9d30',
				'w2dc_button_2_color' => '#64933d',
				'w2dc_button_text_color' => '#FFFFFF',
				'w2dc_jquery_ui_schemas' => 'le-frog',
		),
		'orange' => array(
				'w2dc_primary_color' => '#ff6600',
				'w2dc_secondary_color' => '#404040',
				'w2dc_links_color' => '#4d4d4d',
				'w2dc_links_hover_color' => '#000000',
				'w2dc_button_1_color' => '#4d4d4d',
				'w2dc_button_2_color' => '#404040',
				'w2dc_button_text_color' => '#FFFFFF',
				'w2dc_jquery_ui_schemas' => 'ui-lightness',
		),
		'yellow' => array(
				'w2dc_primary_color' => '#a99d1a',
				'w2dc_secondary_color' => '#868600',
				'w2dc_links_color' => '#b8b900',
				'w2dc_links_hover_color' => '#868600',
				'w2dc_button_1_color' => '#b8b900',
				'w2dc_button_2_color' => '#868600',
				'w2dc_button_text_color' => '#FFFFFF',
				'w2dc_jquery_ui_schemas' => 'sunny',
		),
		'red' => array(
				'w2dc_primary_color' => '#679acd',
				'w2dc_secondary_color' => '#cb4862',
				'w2dc_links_color' => '#ed4e6e',
				'w2dc_links_hover_color' => '#cb4862',
				'w2dc_button_1_color' => '#ed4e6e',
				'w2dc_button_2_color' => '#cb4862',
				'w2dc_button_text_color' => '#FFFFFF',
				'w2dc_jquery_ui_schemas' => 'blitzer',
		),
);
global $w2dc_color_schemes;

function w2dc_affect_setting_w2dc_links_color($scheme) {
	global $w2dc_color_schemes;
	return $w2dc_color_schemes[$scheme]['w2dc_links_color'];
}
VP_W2DC_Security::instance()->whitelist_function('w2dc_affect_setting_w2dc_links_color');

function w2dc_affect_setting_w2dc_links_hover_color($scheme) {
	global $w2dc_color_schemes;
	return $w2dc_color_schemes[$scheme]['w2dc_links_hover_color'];
}
VP_W2DC_Security::instance()->whitelist_function('w2dc_affect_setting_w2dc_links_hover_color');

function w2dc_affect_setting_w2dc_button_1_color($scheme) {
	global $w2dc_color_schemes;
	return $w2dc_color_schemes[$scheme]['w2dc_button_1_color'];
}
VP_W2DC_Security::instance()->whitelist_function('w2dc_affect_setting_w2dc_button_1_color');

function w2dc_affect_setting_w2dc_button_2_color($scheme) {
	global $w2dc_color_schemes;
	return $w2dc_color_schemes[$scheme]['w2dc_button_2_color'];
}
VP_W2DC_Security::instance()->whitelist_function('w2dc_affect_setting_w2dc_button_2_color');

function w2dc_affect_setting_w2dc_button_text_color($scheme) {
	global $w2dc_color_schemes;
	return $w2dc_color_schemes[$scheme]['w2dc_button_text_color'];
}
VP_W2DC_Security::instance()->whitelist_function('w2dc_affect_setting_w2dc_button_text_color');

function w2dc_affect_setting_w2dc_primary_color($scheme) {
	global $w2dc_color_schemes;
	return $w2dc_color_schemes[$scheme]['w2dc_primary_color'];
}
VP_W2DC_Security::instance()->whitelist_function('w2dc_affect_setting_w2dc_primary_color');

function w2dc_affect_setting_w2dc_secandary_color($scheme) {
	global $w2dc_color_schemes;
	return $w2dc_color_schemes[$scheme]['w2dc_secandary_color'];
}
VP_W2DC_Security::instance()->whitelist_function('w2dc_affect_setting_w2dc_secandary_color');

function w2dc_affect_setting_w2dc_jquery_ui_schemas($scheme) {
	global $w2dc_color_schemes;
	return $w2dc_color_schemes[$scheme]['w2dc_jquery_ui_schemas'];
}
VP_W2DC_Security::instance()->whitelist_function('w2dc_affect_setting_w2dc_jquery_ui_schemas');

function w2dc_get_dynamic_option($option_name) {
	global $w2dc_color_schemes;

	if (!empty($_COOKIE['w2dc_compare_palettes'])) {
		$scheme = $_COOKIE['w2dc_compare_palettes'];
		if (isset($w2dc_color_schemes[$scheme][$option_name]))
			return $w2dc_color_schemes[$scheme][$option_name];
		else 
			return get_option($option_name);
	} else
		return get_option($option_name);
}

?>