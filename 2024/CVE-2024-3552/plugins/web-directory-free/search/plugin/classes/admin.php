<?php

class wcsearch_admin {

	public function __construct() {
		global $wcsearch_instance;
		
		$wcsearch_instance->demo_data_manager = new wcsearch_demo_data_manager;

		add_action('admin_enqueue_scripts', array($this, 'admin_enqueue_scripts_styles'), 0);

		add_action('admin_notices', 'wcsearch_renderMessages');
	}
	
	public function admin_enqueue_scripts_styles($hook) {
		global $wcsearch_instance;
		
		// include admin.css, rtl.css, bootstrap, custom.css and datepicker files in admin,
		// also in customizer and required for VC plugin, SiteOrigin plugin and widgets
		if (
			wcsearch_isPluginPageInAdmin() ||
			is_customize_preview() ||
			$hook == "widgets.php" ||
			get_post_meta(get_the_ID(), '_wpb_vc_js_status', true)
		) {
			
			wp_register_style('wcsearch-jquery-ui-style', WCSEARCH_RESOURCES_URL . 'css/jquery-ui/themes/smoothness/jquery-ui.css');
			wp_enqueue_style('wcsearch-jquery-ui-style');
			
			if (is_customize_preview()) {
				$this->enqueue_global_vars();
			} else {
				add_action('admin_head', array($this, 'enqueue_global_vars'));
			}
			
			wp_register_style('wcsearch_admin', WCSEARCH_RESOURCES_URL . 'css/admin.css', array(), WCSEARCH_VERSION);
			if (function_exists('is_rtl') && is_rtl()) {
				wp_register_style('wcsearch_admin_rtl', WCSEARCH_RESOURCES_URL . 'css/admin-rtl.css', array(), WCSEARCH_VERSION);
			}
			
			if ($admin_custom = wcsearch_isResource('css/admin-custom.css')) {
				wp_register_style('wcsearch_admin-custom', $admin_custom, array(), WCSEARCH_VERSION);
			}
		}
		
		if (wcsearch_isPluginPageInAdmin()) {
			
			wp_register_style('wcsearch_font_awesome', WCSEARCH_RESOURCES_URL . 'css/font-awesome.css', array(), WCSEARCH_VERSION);
			wp_register_script('wcsearch_js_functions', WCSEARCH_RESOURCES_URL . 'js/js_functions.js', array('jquery'), false, true);
			
			wp_enqueue_script('jquery-ui-selectmenu');
			wp_enqueue_script('jquery-ui-autocomplete');
			
			// disable drafts
			wp_dequeue_script('autosave');
		}
		
		wp_enqueue_style('wcsearch_font_awesome');
		wp_enqueue_style('wcsearch_admin');
		wp_enqueue_style('wcsearch_admin_rtl');
		wp_enqueue_script('wcsearch_js_functions');
		wp_enqueue_style('wcsearch_admin-custom');
	}

	public function enqueue_global_vars() {
		$ajaxurl = admin_url('admin-ajax.php');

		echo '
<script>
';
		
		$adapter_options = apply_filters("wcsearch_adapter_options", array());
		
		echo 'var wcsearch_js_objects = ' . json_encode(
				array(
						'ajaxurl' => $ajaxurl,
						'is_rtl' => (int)is_rtl(),
						'query_string' => http_build_query(wcsearch_get_query_string()),
						'adapter_options' => $adapter_options,
				)
		) . ';
';
		echo '</script>
';
	}

}
?>