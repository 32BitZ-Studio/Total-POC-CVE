<?php

/**
 * controller driven objects
 * 
 *
 */
class wcsearch_search_form {
	public $args = array();
	public $hidden_fields = array();
	public $common_fields = array();
	public $count_fields = array();
	public $search_form_id;
	
	public function __construct() {
		
		// random ID needed because there may be more than 1 search form on one page,
		// this is by default, getArgByPostId() then makes it form post ID
		$this->search_form_id = wcsearch_generateRandomVal();
	}
	
	public function setArgs($args) {
		
		// default form settings
		global $wcsearch_default_model_settings;

		$this->args = array_merge($wcsearch_default_model_settings, $args);
	}
	
	public function setArgsFromOldForm($args) {
		
		$this->args = apply_filters("wcsearch_set_args_from_old_form", $this->args, $args, $this);
		
		// default form settings
		global $wcsearch_default_model_settings;
		
		$this->args = array_merge($wcsearch_default_model_settings, $this->args);
	}
	
	public function getArgByPostId($post_id = null) {
		global $wcsearch_default_model_settings;
		
		if (!$post_id) {
			return false;
		}
		
		if (!($search_form_post = get_post($post_id))) {
			
			$wp_query_args = array(
					'title' => $post_id,
					'post_type' => WCSEARCH_FORM_TYPE,
			);
			
			$query = new WP_Query($wp_query_args);
			if ($query->posts) {
				$search_form_post = $query->posts[0];
			}
		}
		
		if (!$search_form_post) {
			return false;
		}
		
		$post_id = $search_form_post->ID;
		
		$this->args['id'] = $post_id;
		
		foreach ($wcsearch_default_model_settings AS $setting=>$value) {
			if (metadata_exists('post', $post_id, '_'.$setting)) {
				$this->args[$setting] = get_post_meta($post_id, '_'.$setting, true);
			}
		}
		
		if (get_post($post_id)) {
			if (is_string($this->args['model'])) {
				$this->args['model'] = json_decode($this->args['model'], true);
			}
		}
		
		$this->search_form_id = $post_id;
		
		return $this->args;
	}
	
	public function setCommonField($name, $value) {
	
		if (is_array($value)) {
			foreach ($value AS $val) {
				$this->common_fields[$name][] = $val;
			}
		} else {
			$this->common_fields[$name] = $value;
		}
	}
	
	public function setCountFields($args) {
	
		do_action("wcsearch_set_count_fields", $args, $this);
	}
	
	public function setCountField($name, $value) {
	
		if (is_array($value)) {
			foreach ($value AS $val) {
				$this->count_fields[$name][] = $val;
			}
		} else {
			$this->count_fields[$name] = $value;
		}
	}
	
	public function setHiddenField($name, $value) {
	
		$this->hidden_fields[$name] = $value;
	}
	
	public function outputHiddenFields() {
		
		do_action("wcsearch_output_hidden_fields", $this);
		
		$search_form_id = wcsearch_getValue($_REQUEST, 'wcsearch_test_form');
		if ($search_form_id && current_user_can('manage_options')) {
			$this->hidden_fields['wcsearch_test_form'] = $search_form_id;
		}
		
		foreach ($this->hidden_fields AS $name=>$value) {
			if (is_array($value)) {
				foreach ($value AS $val) {
					echo '<input type="hidden" name="' . esc_attr($name) . '[]" value="' . esc_attr($val) . '" class="wcsearch-hidden-field" />';
				}
			} else {
				echo '<input type="hidden" name="' . esc_attr($name) . '" value="' . esc_attr($value) . '" class="wcsearch-hidden-field" />';
			}
		}
		
		foreach ($this->common_fields AS $name=>$value) {
			if (is_array($value)) {
				foreach ($value AS $val) {
					echo '<input type="hidden" name="' . esc_attr($name) . '[]" value="' . esc_attr($val) . '" class="wcsearch-common-field" />';
				}
			} else {
				echo '<input type="hidden" name="' . esc_attr($name) . '" value="' . esc_attr($value) . '" class="wcsearch-common-field" />';
			}
		}
		
		foreach ($this->count_fields AS $name=>$value) {
			if (is_array($value)) {
				foreach ($value AS $val) {
					echo '<input type="hidden" name="' . esc_attr($name) . '[]" value="' . esc_attr($val) . '" class="wcsearch-count-field" />';
				}
			} else {
				echo '<input type="hidden" name="' . esc_attr($name) . '" value="' . esc_attr($value) . '" class="wcsearch-count-field" />';
			}
		}
		
		$is_search_button = false;
		if (isset($this->args['model']['placeholders'])) {
			foreach ($this->args['model']['placeholders'] AS $placeholder) {
				if (isset($placeholder['input']['type'])) {
					if ($placeholder['input']['type'] == 'button') {
						$is_search_button = true;
						break;
					}
				}
			}
		}
		if (!$is_search_button) {
			echo '<input type="submit" class="wcsearch-search-input-button wcsearch-submit-button-hidden" />';
		}
	}
	
	public function getSearchFormStyles() {
		$form_id =  esc_attr($this->search_form_id);
		$search_wrapper_id = "#wcsearch-search-wrapper-" . $form_id;
		$search_form_id = "#wcsearch-search-form-" .$form_id;
		
		echo "<style type=\"text/css\">";
		if ($this->args['bg_color']) {
			echo "
			$search_form_id	.wcsearch-search-grid {
				background-color: " . wcsearch_hex2rgba($this->args['bg_color'], $this->args['bg_transparency']/100) . " !important;
			}";
		} else {
			
		}
		if ($this->args['text_color']) {
			echo "
			$search_form_id .wcsearch-search-input,
			$search_form_id .wcsearch-search-input label,
			$search_form_id .wcsearch-search-input a,
			$search_form_id .wcsearch-search-placeholder {
				color: " . esc_attr($this->args['text_color']) . ";
			}";
		}
		if ($this->args['elements_color'] && $this->args['elements_color_secondary']) {
			echo "
			$search_form_id .wcsearch-search-grid select,
			$search_form_id .wcsearch-content .wcsearch-search-grid select:focus {
				background-image:
				linear-gradient(50deg, transparent 50%, #FFFFFF 50%),
				linear-gradient(130deg, #FFFFFF 50%, transparent 50%),
				linear-gradient(to right, " . esc_attr($this->args['elements_color']) . ", " . esc_attr($this->args['elements_color']) . ") !important;
			}
			$search_form_id .wcsearch-search-grid .wcsearch-checkbox .wcsearch-control-indicator,
			$search_form_id .wcsearch-search-grid .wcsearch-radio .wcsearch-control-indicator {
				border-color: " . esc_attr($this->args['elements_color']) . ";
			}
			$search_form_id .wcsearch-field-checkbox-item-checked {
				color: " . esc_attr($this->args['elements_color']) . ";
			}
			$search_form_id .wcsearch-search-grid .wcsearch-checkbox label input:checked ~ .wcsearch-control-indicator,
			$search_form_id .wcsearch-search-grid .wcsearch-radio label input:checked ~ .wcsearch-control-indicator {
				background: " . esc_attr($this->args['elements_color']) . ";
			}
			$search_wrapper_id .wcsearch-click-to-edit-search-button {
				background: " . esc_attr($this->args['elements_color']) . ";
			}
			$search_form_id .wcsearch-search-grid .ui-slider.ui-slider-horizontal .ui-widget-header {
				background-color: " . esc_attr($this->args['elements_color_secondary']) . ";
			}
			$search_form_id .wcsearch-search-grid .ui-slider.ui-widget-content .ui-slider-handle.ui-state-default,
			$search_form_id .wcsearch-search-grid .ui-slider.ui-widget-content .ui-slider-handle.ui-state-default:focus,
			$search_form_id .wcsearch-search-grid .ui-slider.ui-widget-content .ui-slider-handle.ui-state-default:active,
			$search_form_id .wcsearch-search-grid .ui-slider.ui-widget-content .ui-slider-handle.ui-state-focus,
			$search_form_id .wcsearch-search-grid .ui-slider.ui-widget-content .ui-slider-handle.ui-state-hover {
				border: 1px solid " . esc_attr($this->args['elements_color_secondary']) . ";
				background-color: " . esc_attr($this->args['elements_color']) . ";
			}
			$search_form_id .wcsearch-search-grid .wcsearch-search-input-button,
			$search_form_id .wcsearch-search-grid .wcsearch-date-reset-button {
				background-color: " . esc_attr($this->args['elements_color']) . " !important;
				border: 1px solid " . esc_attr($this->args['elements_color_secondary']) . " !important;
				color: #FFF !important;
			}
			$search_form_id .wcsearch-search-grid .wcsearch-search-input-reset-button {
				background-color: #FFF !important;
				color: " . esc_attr($this->args['elements_color']) . " !important;
				border: 1px solid " . esc_attr($this->args['elements_color_secondary']) . " !important;
			}
			$search_wrapper_id .wcsearch-apply-filters-float-btn,
			$search_wrapper_id .wcsearch-apply-filters-float-btn:before {
				background-color: " . esc_attr($this->args['elements_color']) . ";
			}
			.wcsearch-loader-$form_id:before {
				border-top-color: " . esc_attr($this->args['elements_color']) . " !important;
				border-bottom-color: " . esc_attr($this->args['elements_color']) . " !important;
			}
			";
			
		}
		
		echo "</style>";
	}
	
	public function getOverlayClasses() {
		$classes = array();
		
		if ($this->args['use_overlay']) {
			$classes[] = "wcsearch-search-grid-image";
		} 
		
		return implode(" ", $classes);
	}
	
	public function getOverlayAttributes() {
		$style = 'style="grid-gap: 30px;"';
		
		return $style;
	}
	
	public function getOptionsString() {
		$options = array();
		
		if (empty($this->args['target_url'])) {
			if (wcsearch_is_woo_active() && !wcsearch_is_w2dc_active()) {
				$search_url = get_permalink(wc_get_page_id('shop'));
			} else {
				global $wp;
				$search_url = home_url($wp->request);
			}
		} else {
			$search_url = $this->args['target_url'];
			$options['data-target_url'] = 1;
		}
		$search_url = apply_filters('wcsearch_search_url', $search_url, $this);
		
		$options['action'] = $search_url;
		$search_form_id = wcsearch_getValue($_REQUEST, 'wcsearch_test_form');
		if ($search_form_id && current_user_can('manage_options')) {
			$options['action'] = add_query_arg('wcsearch_test_form', $search_form_id, $options['action']);
		}
		$options['id'] = "wcsearch-search-form-" . $this->search_form_id;
		$options['data-id'] = $this->search_form_id;
		$options['data-used_by'] = $this->args['used_by'];
		$options['data-color'] = esc_attr($this->args['elements_color']);
		$options["autocomplete"] = "off";
		$options['class'] = "wcsearch-content wcsearch-search-form wcsearch-search-form-submit";
		
		if ($this->args['sticky_scroll']) {
			$options['class'] = $options['class'] . " wcsearch-sticky-scroll-form";
		}
		
		if ($this->args['use_border']) {
			$options['class'] = $options['class'] . " wcsearch-search-form-border";
		}
		
		if (!$this->args['use_border'] && !$this->args['bg_color']) {
			$options['class'] = $options['class'] . " wcsearch-search-form-no-border-no-bg";
		}
		
		if ($this->args['sticky_scroll_toppadding']) {
			$options['data-toppadding'] = $this->args['sticky_scroll_toppadding'];
		}
		
		if ($this->args['scroll_to']) {
			$options['data-scroll-to'] = $this->args['scroll_to'];
		}
		
		if ($this->args['auto_submit']) {
			$options['data-auto-submit'] = $this->args['auto_submit'];
		}
		
		if ($this->args['use_ajax']) {
			$options['data-use-ajax'] = $this->args['use_ajax'];
		}
		
		if (!empty($this->args['hash'])) {
			$options['data-hash'] = $this->args['hash'];
		}
		
		$options_string = '';
		foreach ($options AS $name=>$val) {
			$options_string .= esc_attr($name) . '="' . esc_attr($val) . '" ';
		}
		
		return $options_string;
	}

	public function display() {
		
		if (isset($this->args['model']['placeholders'])) {
			$search_form_model = new wcsearch_search_form_model($this->args['model']['placeholders'], $this->args['used_by']);
	
			wcsearch_renderTemplate('search_form.tpl.php',
				array(
					'args' => $this->args,
					'search_form' => $this,
					'search_form_model' => $search_form_model,
				)
			);
		} else {
			echo esc_html__("No placeholders in the form!", "WCSEARCH");
		}
	}
}
?>