<?php

class wcsearch_search_form_model {
	public $id;
	public $used_by = 'wc';
	public $placeholders = array();
	
	public function __construct($placeholders = array(), $used_by = 'wc') {
		
		$this->used_by = $used_by;
		$this->id = wcsearch_getValue($_REQUEST, 'post');
		
		if ($placeholders) {
			$this->placeholders = $placeholders;
		}
	}
	
	public function buildFieldsButtons($model_fields) {
		foreach ($model_fields AS $field) {
			echo '<div class="wcsearch-search-model-add-element-btn wcsearch-btn wcsearch-btn-primary ';

			$exists = false;
			foreach ($this->placeholders AS $placeholder) {
				if (isset($placeholder['input']['slug']) && $placeholder['input']['slug'] == $field['slug']) {
					$exists = true;
				}
			}
			
			if (!$exists) {
				echo 'wcsearch-search-model-add-element-btn-inactive';
			}
		
			echo '"'; 
			echo ' data-type="' . esc_attr($field['type']) . '" ';
			echo ' data-slug="' . esc_attr($field['slug']) . '" ';
			echo ' data-used_by="' . esc_attr($this->used_by) . '" ';
			if (isset($field['tax'])) {
				echo 'data-tax="' . esc_attr($field['tax']) . '" ';
			}
			if (isset($field['values'])) {
				echo 'data-values="' . esc_attr($field['values']) . '" ';
			}
			echo '>';
			if (isset($field['icon'])) {
				echo '<span class="wcsearch-fa ' . esc_attr($field['icon']) . '"></span> ';
			}
			echo esc_html($field['name']);
			echo '</div>';
		}
	}
	
	public function buildLayout($frontend = false) {
		
		foreach ($this->placeholders AS $placeholder) {
			$columns_number = $placeholder['columns'];
			$rows_number = $placeholder['rows'];
			
			$field_model = false;
			$advanced_search_class = '';
			$dependent_search_class = '';
			
			if (!empty($placeholder['input'])) {
				$type = wcsearch_getValue($placeholder['input'], 'type');
				$params = $placeholder['input'];
				
				$params = wcsearch_getModelOptions($type, $params);
				
				$field_model = new wcsearch_search_form_model_field($params, $frontend, $this->used_by);
				
				if (isset($field_model->params['visible_status']) && $field_model->params['visible_status'] == 'always_closed') {
					$advanced_search_class .= 'wcsearch-search-placeholder-always-closed';
				}
				
				if (isset($field_model->params['visible_status']) && $field_model->params['visible_status'] == 'more_filters') {
					$advanced_search_class .= 'wcsearch-search-placeholder-advanced-view';
					
					if (!wcsearch_isMoreFiltersOpen($this->placeholders)) {
						$advanced_search_class .= ' wcsearch-search-placeholder-advanced-view-closed';
					}
				}
				
				// show/hide this field by dependency
				if (!empty($field_model->params['dependency_tax'])) {
					$dependent_search_class = 'wcsearch-search-placeholder-dependency-view';
					
					$tax_name = $field_model->params['dependency_tax'];
					$query_items = array_filter(explode(",", wcsearch_get_query_string($tax_name)));
					
					if (!$query_items) {
						$dependent_search_class .= ' wcsearch-search-placeholder-dependency-view-closed';
						if (!empty($field_model->params['dependency_visibility'])) {
							$dependent_search_class .= ' wcsearch-search-placeholder-dependency-view-shaded';
						}
					} else {
						
						if (!empty($field_model->params['dependency_items'])) {
							$dep_items = explode(",", $field_model->params['dependency_items']);
							
							if (!empty($field_model->params['dependency_visibility'])) {
								$dependent_search_class .= ' wcsearch-search-placeholder-dependency-view-shaded';
							}
							
							if (!array_intersect($dep_items, $query_items)) {
								$dependent_search_class .= ' wcsearch-search-placeholder-dependency-view-closed';
							}
						}
					}
				}
			}
			
			if ($frontend) {
				$columns_class= 'wcsearch-search-placeholder-column-' . esc_attr($columns_number);
				echo '<div class="wcsearch-search-placeholder ' . esc_attr($columns_class) . ' ' . esc_attr($advanced_search_class) . ' ' . esc_attr($dependent_search_class) . '" style="grid-row-end: span ' . esc_attr($rows_number) . ';">';
			} else {
				$columns_class= 'wcsearch-search-model-placeholder-column-' . esc_attr($columns_number);
				echo '<div class="wcsearch-search-model-placeholder ' . esc_attr($columns_class) . '" data-grid-row-end="' . esc_attr($rows_number) . '">';
			}
			
			if ($field_model) {
				echo $field_model->getFieldModel();
			}
			
			echo '</div>';
		}
	}
}

function wcsearch_isMoreFiltersOpen($placeholders) {
	
	if (wcsearch_get_query_string('more_filters')) {
		return true;
	}
	
	foreach ($placeholders AS $placeholder) {
		if (!empty($placeholder['input'])) {
			$type = wcsearch_getValue($placeholder['input'], 'type');
			$params = $placeholder['input'];
			
			if ($type == 'more_filters') {
				$params = wcsearch_getModelOptions($type, $params);
				
				if (!empty($params['open_by_default'])) {
					return true;
				}
			}
		}
	}
}

function wcsearch_getModelOptions($type, $params) {
	global $wcsearch_model_options;

	// add default options when needed
	if (isset($wcsearch_model_options[$type])) {
		foreach ($wcsearch_model_options[$type] AS $option) {
			if (isset($params[$option['name']])) {
				$params[$option['name']] = $params[$option['name']];
			} elseif (isset($option['value'])) {
				$params[$option['name']] = $option['value'];
			}
		}
	}
	
	$wcsearch_model_options = apply_filters("wcsearch_model_options", $wcsearch_model_options);
	
	// from $_REQUEST
	if (!is_admin()) {
		$param_name = $params['slug'];
		
		// default values were set in model
		if (!isset($params['default_values']) && isset($params['values'])) {
			$params['default_values'] = $params['values'];
		}
		$params['values'] = wcsearch_get_query_string($param_name);
		
		// on tax terms pages
		if (
			!$params['values'] &&
			($default_query = wcsearch_get_default_query()) &&
			isset($default_query[$params['slug']])
		) {
			$params['values'] = $default_query[$params['slug']];
		}
	}
	
	//var_dump($params);

	return $params;
}

/**
 * called by:
 * 1. wcsearch_search_form_model::buildLayout() method
 * 2. AJAX request 'wcsearch_get_search_model'
 *
 */
class wcsearch_search_form_model_field {
	public $id;
	public $params = array();
	public $frontend = false;
	public $used_by = 'wc';
	
	public function __construct($params = array(), $frontend = false, $used_by = false) {
		if ($params) {
			$this->params = $params;
			$this->used_by = $used_by;
		} else {
			// by AJAX
			$this->params = $_POST;
			$this->used_by = wcsearch_getValue($_POST, 'used_by');
		}
		
		$this->frontend = $frontend;
	}
	
	public function getFieldModel() {
		$type = wcsearch_getValue($this->params, 'type');
		
		if ($this->frontend) {
			$template_path = "search_fields/frontend/";
		} else {
			$template_path = "search_fields/model/";
		}
		
		// strip slashes to render template,
		// we will escape attr in getOptionsString() later
		$this->params = wp_unslash($this->params);
		
		$this->params = wcsearch_getModelOptions($type, $this->params);
		
		$this->id = 'wcsearch_id_' . md5(serialize($this->params));
		
		$this->params['used_by'] = $this->used_by;
		
		if (!wcsearch_get_query_string()) {
			// set default input values when no search
			if (empty($this->params['values']) && isset($this->params['default_values'])) {
				$this->params['values'] = $this->params['default_values'];
			} elseif (!isset($this->params['values'])) {
				$this->params['values'] = '';
			}
		}
		
		if (wcsearch_getValue($this->params, 'visible_status')) {
			$this->params["visible_status"] = wcsearch_getValue($this->params, 'visible_status', 'always_opened');
		} else {
			$this->params["visible_status"] = "always_opened";
		}
		
		switch ($type) {
			case "tax":
			case "select":
				$tax_name = wcsearch_getValue($this->params, 'tax');
				if (
					(($tax_name = wcsearch_getValue($this->params, 'tax')) && taxonomy_exists($tax_name)) ||
					(($tax_name = wcsearch_getValue($this->params, 'slug')) && wcsearch_getValue($this->params, 'type') == 'select')
				) {
					$taxonomy = wcsearch_getValue(wcsearch_wrapper_get_taxonomies(array("name" => $tax_name), 'objects'), $tax_name);
					
					// set default placeholder
					if (!empty($this->params['new_field'])) {
						if (isset($this->params['placeholder'])) {
							$this->params['placeholder'] = sprintf(esc_html__('Select %s', 'WCSEARCH'), $taxonomy->labels->singular_name);
						}
						if (isset($this->params['placeholders'])) {
							$this->params['placeholders'] = sprintf(esc_html__('Select %s', 'WCSEARCH'), $taxonomy->labels->singular_name);
						}
					}
					
					$mode = wcsearch_getValue($this->params, 'mode', 'dropdown');
					$counter = wcsearch_getValue($this->params, 'counter', 1);
					$depth = wcsearch_getValue($this->params, 'depth', 1);
					$hide_empty = wcsearch_getValue($this->params, 'hide_empty', 0);
					$orderby = wcsearch_getValue($this->params, 'orderby', 'name');
					$order = wcsearch_getValue($this->params, 'order', 'ASC');
					$exact_terms = wcsearch_getValue($this->params, 'exact_terms', '');
					
					if (!empty($this->params['dependency_items']) && !empty($this->params['dependency_tax'])) {
						
						if (is_array($this->params['dependency_items'])) {
							$dependency_items = $this->params['dependency_items'];
						} else {
							$dependency_items = explode(",", $this->params['dependency_items']);
						}
						
						foreach ($dependency_items AS $key=>$d_item) {
							if (!is_numeric($d_item)) {
								if ($term = wcsearch_wrapper_get_term_by_slug($d_item, $this->params['dependency_tax'])) {
									$dependency_items[$key] = $term->term_id;
								}
							}
						}
						$this->params['dependency_items'] = implode(",", $dependency_items);
					}
					
					$categories_options = array(
							'taxonomy' => $tax_name,
							'hide_empty' => $hide_empty,
					);
					if ($orderby == 'menu_order') {
						$categories_options['menu_order'] = 'ASC';
					} else {
						$categories_options['orderby'] = $orderby;
						$categories_options['order'] = $order;
					}
					if ($exact_terms) {
						if (is_array($exact_terms)) {
							$this->params['exact_terms'] = $exact_terms;
						} else {
							$this->params['exact_terms'] = explode(",", $exact_terms);
						}
						$categories_options['exact_terms'] = $this->params['exact_terms'];
					} else {
						$this->params['exact_terms'] = '';
					}
					if ($depth == 1) {
						$categories_options['parent'] = 0;
					} else {
						$categories_options['depth'] = $depth;
					}
					
					if (in_array($mode, array('hierarhical_dropdown', 'dropdown', 'dropdown_keywords', 'multi_dropdown', 'dropdown_address'))) {
						
						$keywords_value = wcsearch_get_query_string('keywords');
						$address_value = wcsearch_get_query_string('address');
						
						if ($this->frontend) {
							$selection_items = array();
						} else {
							$selection_items = wcsearch_wrapper_get_categories($categories_options);
						}
						
						return wcsearch_renderTemplate($template_path . "tax_select.tpl.php",
								array_merge(array(
										"search_model" => $this,
										"tax_name" => $tax_name,
										"taxonomy" => $taxonomy,
										"selection_items" => $selection_items,
										"counter" => $counter,
										"depth" => $depth,
										"hide_empty" => $hide_empty,
										"keywords_value" => $keywords_value,
										"address_value" => $address_value,
						), $this->params), true);
					} elseif ($mode == 'radios' || $mode == 'checkboxes') {
						
						$columns = wcsearch_getValue($this->params, 'columns', 2);
						
						$selection_items = wcsearch_wrapper_get_categories($categories_options);
						
						return wcsearch_renderTemplate($template_path . "tax_radios_checkboxes.tpl.php",
								array_merge(array(
										"search_model" => $this,
										"tax_name" => $tax_name,
										"taxonomy" => $taxonomy,
										"mode" => $mode,
										"selection_items" => $selection_items,
										"columns" => $columns,
										"counter" => $counter,
										"depth" => $depth,
						), $this->params), true);
					} elseif ($mode == 'radios_buttons' || $mode == 'checkboxes_buttons') {
						
						$columns = wcsearch_getValue($this->params, 'columns', 2);
						
						$selection_items = wcsearch_wrapper_get_categories($categories_options);
						
						return wcsearch_renderTemplate($template_path . "tax_buttons.tpl.php",
								array_merge(array(
										"search_model" => $this,
										"tax_name" => $tax_name,
										"taxonomy" => $taxonomy,
										"mode" => $mode,
										"selection_items" => $selection_items,
										"columns" => $columns,
										"counter" => $counter,
										"depth" => $depth,
						), $this->params), true);
					} elseif ($mode == 'range') {
						
						$selection_items = wcsearch_wrapper_get_categories($categories_options);
						
						$min_max_options = array();
						foreach ($selection_items AS $term) {
							$min_max_options[$term->term_id] = $term->name;
						}
						
						return wcsearch_renderTemplate($template_path . "tax_range_slider.tpl.php",
								array_merge(array(
										"search_model" => $this,
										"tax_name" => $tax_name,
										"taxonomy" => $taxonomy,
										"mode" => $mode,
										"min_max_options" => $min_max_options,
										"counter" => $counter,
										"depth" => $depth,
						), $this->params), true);
					} elseif ($mode == 'single_slider') {
						
						$selection_items = wcsearch_wrapper_get_categories($categories_options);
						
						$min_max_options = array();
						foreach ($selection_items AS $term) {
							$min_max_options[$term->term_id] = $term->name;
						}
						
						return wcsearch_renderTemplate($template_path . "tax_single_slider.tpl.php",
								array_merge(array(
										"search_model" => $this,
										"tax_name" => $tax_name,
										"taxonomy" => $taxonomy,
										"mode" => $mode,
										"min_max_options" => $min_max_options,
										"counter" => $counter,
										"depth" => $depth,
						), $this->params), true);
					}
				}
				break;
				
			case "keywords":
				
				return wcsearch_renderTemplate($template_path . "keywords.tpl.php",
								array_merge(array("search_model" => $this), $this->params), true);
				
				break;
			case "string":
				
				// set default placeholder
				if (!empty($this->params['new_field'])) {
					
					$search_fields = wcsearch_get_model_fields($this->params['used_by']);
					foreach ($search_fields AS $search_field) {
						if ($search_field['type'] == 'string' && $search_field['slug'] == $this->params['slug']) {
							$this->params['placeholder'] = sprintf(esc_html__('Enter %s', 'WCSEARCH'), $search_field['name']);
							
							break;
						}
					}
				}
				
				return wcsearch_renderTemplate($template_path . "string.tpl.php",
								array_merge(array("search_model" => $this), $this->params), true);
				
				break;
			case "address":
				
				return wcsearch_renderTemplate($template_path . "address.tpl.php",
								array_merge(array("search_model" => $this), $this->params), true);
				
				break;
			case "radius":
				
				return wcsearch_renderTemplate($template_path . "radius.tpl.php",
								array_merge(array("search_model" => $this), $this->params), true);
				
				break;
			case "button":
				
				return wcsearch_renderTemplate($template_path . "button.tpl.php",
								array_merge(array("search_model" => $this), $this->params), true);
				
				break;
			case "reset":
				
				return wcsearch_renderTemplate($template_path . "reset.tpl.php",
								array_merge(array("search_model" => $this), $this->params), true);
				
				break;
			case "more_filters":
				
				$opened = wcsearch_get_query_string('more_filters');
				if (!$opened) {
					if (!empty($this->params['open_by_default'])) {
						$opened = true;
					}
				}
				
				return wcsearch_renderTemplate($template_path . "more_filters.tpl.php",
								array_merge(array(
										"search_model" => $this,
										"opened" => $opened,
								), $this->params), true);
				
				break;
			case "date":
				
				return wcsearch_renderTemplate($template_path . "date.tpl.php",
								array_merge(array(
										"search_model" => $this,
								), $this->params), true);
				
				break;
			case "price":
			case "number":
				$mode = wcsearch_getValue($this->params, 'mode', 'range');
				
				if ($mode == 'range') {
					$template = $template_path . "number_range_slider.tpl.php";
				} elseif ($mode == 'single_slider') {
					$template = $template_path . "number_single_slider.tpl.php";
				} elseif ($mode == 'min_max_one_dropdown') {
					$template = $template_path . "number_min_max_one_dropdown.tpl.php";
				} elseif ($mode == 'min_max_two_dropdowns') {
					if (
						wcsearch_get_query_string($this->params['slug']) &&
						count(explode('-', wcsearch_get_query_string($this->params['slug']))) == 1
					) {
						// if number=XX
						$template = $template_path . "number_min_max_one_dropdown.tpl.php";
					} else {
						// if number=XX-YY
						$template = $template_path . "number_min_max_two_dropdowns.tpl.php";
					}
				} elseif ($mode == 'radios') {
					$template = $template_path . "number_radios.tpl.php";
				} elseif ($mode == 'inputs') {
					$template = $template_path . "number_inputs.tpl.php";
				}
				
				return wcsearch_renderTemplate($template,
						array_merge(array("search_model" => $this, 'is_number' => ($type == "number") ? true : false), $this->params), true);
				
				break;
			case "featured":
				
				$counter = 0;
				if ($this->params['counter']) {
					$counter = wcsearch_get_featured_counter();
				}
				
				return wcsearch_renderTemplate($template_path . "featured.tpl.php",
						array_merge(array(
								"search_model" => $this,
								"counter_value" => $counter
				), $this->params), true);
				
				break;
			case "instock":
				
				$counter = 0;
				if ($this->params['counter']) {
					$counter = wcsearch_get_instock_counter();
				}
				
				return wcsearch_renderTemplate($template_path . "instock.tpl.php",
						array_merge(array(
								"search_model" => $this,
								"counter_value" => $counter
				), $this->params), true);
				
				break;
			case "onsale":
				
				$counter = 0;
				if ($this->params['counter']) {
					$counter = wcsearch_get_onsale_counter();
				}
				
				return wcsearch_renderTemplate($template_path . "onsale.tpl.php",
						array_merge(array(
								"search_model" => $this,
								"counter_value" => $counter
				), $this->params), true);
				
				break;
			case "hours":
				
				$counter = 0;
				if ($this->params['counter']) {
					$counter = wcsearch_get_count_num(array('hours' => $this->params['slug']));
				}
				
				return wcsearch_renderTemplate($template_path . "hours.tpl.php",
						array_merge(array(
								"search_model" => $this,
								"counter_value" => $counter
				), $this->params), true);
				
				break;
			case "ratings":
				
				$options = array(
						'5' => esc_html("5 stars", "WCSEARCH"),
						'4' => esc_html("4 stars", "WCSEARCH"),
						'3' => esc_html("3 stars", "WCSEARCH"),
						'2' => esc_html("2 stars", "WCSEARCH"),
						'1' => esc_html("1 stars", "WCSEARCH"),
				);
				
				return wcsearch_renderTemplate($template_path . "ratings.tpl.php",
						array_merge(array(
								"search_model" => $this,
								"options" => $options
				), $this->params), true);
				
				break;
		}
	}
	
	public function getOptionsString() {
		// take options only from default model
		$type = wcsearch_getValue($this->params, 'type');
		
		$options = wcsearch_getModelOptions($type, $this->params);
		
		if (isset($options['action'])) {
			unset($options['action']);
		}
		
		$options['used_by'] = $this->used_by;
		
		$data = "id='" . $this->id . "'";
		
		foreach ($options AS $name=>$value) {
			
			if (is_array($value)) {
				$value = implode(',', $value);
				//$value = json_encode($value);
			}
			
			$data .= ' data-'.$name.'="' . esc_attr($value) . '" ';
		}
		
		return $data;
	}
	
	public function openedClosedClass() {
		
		if ($this->params["visible_status"] == "closed") {
			return "wcsearch-search-input-closed";
		}
		if ($this->params["visible_status"] == "opened") {
			return "wcsearch-search-input-opened";
		}
		if ($this->params["visible_status"] == "always_closed") {
			return "wcsearch-search-input-always-closed";
		}
	}
}
?>