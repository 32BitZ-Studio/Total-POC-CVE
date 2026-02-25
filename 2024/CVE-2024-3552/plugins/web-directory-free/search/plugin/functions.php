<?php

/**
 *
wcsearch-tax-autocomplete		// tax autocomplete
wcsearch-tax-keywords			// tax + keywords autocomplete
wcsearch-tax-address			// tax + address autocomplete
wcsearch-multiselect-dropdown	// multiselect dropdown tax
wcsearch-keywords-autocomplete	// keywords autocomplete		
wcsearch-address-autocomplete	// address autocomplete		

 */

function wcsearch_tax_dropdowns_menu_init($params) {
	$attrs = array_merge(array(
			'uID' => 0,
			'field_name' => '',
			'count' => true,
			'tax' => '',
			'open_on_click' => true,
			'hide_empty' => false,
			'exact_terms' => array(),
			'autocomplete_field' => '',
			'autocomplete_field_value' => '',
			'autocomplete_ajax' => false,
			'placeholder' => false,
			'depth' => 1,
			'depth_level' => 1,
			'term_id' => 0,
			'parent' => '',
			'return_terms' => false,
			'functionality' => '', // wcsearch-tax-autocomplete, wcsearch-multiselect-dropdown, wcsearch-tax-keywords, wcsearch-tax-address
			'orderby' => 'name',
			'order' => 'ASC',
			'place_id' => '',
	), $params);
	extract($attrs);
	
	// unique ID need when we place some dropdowns groups on one page
	if (!$uID) {
		$uID = rand(1, 10000);
	}
	
	if ($tax) {
		if (!$field_name) {
			$field_name = 'selected_tax[' . $uID . ']';
		}
		
		if ($placeholder === false) {
			$taxonomy_obj = wcsearch_wrapper_get_taxonomy($tax);
			$placeholder = $taxonomy_obj->labels->name;
		}
		
		if (!is_array($term_id)) {
			$term_id = array_filter(explode(',', $term_id));
		}
		
		if (is_array($term_id)) {
			$field_value = implode(',', $term_id);
		} else {
			$field_value = $term_id;
		}
		
		$categories_options = array(
				'taxonomy' => $tax,
				'hide_empty' => $hide_empty,
				'parent' => $parent,
		);
		if ($orderby == 'menu_order') {
			$categories_options['menu_order'] = 'ASC';
		} else {
			$categories_options['orderby'] = $orderby;
			$categories_options['order'] = $order;
		}
		
		if ($exact_terms) {
			$categories_options['exact_terms'] = $exact_terms;
		}
		
		if ($depth_level == 1 && !$exact_terms) {
			$categories_options['parent'] = 0;
		}
		
		$terms = wcsearch_wrapper_get_categories($categories_options);
		
		if ($return_terms) {
			return $terms;
		}
		
		// do not place value when it doesn't belong to this dropdown,
		// avoid mismatch with heirarhical dropdowns
		if ($depth == 1) {
			foreach ($terms AS $id=>$term) {
				if ($term->term_id == $field_value) {
					$field_value_exists = true;
				}
			}
			if (empty($field_value_exists)) {
				$field_value = '';
			}
		}
		
		if ($depth_level == 1) {
			echo '<div id="wcsearch-tax-dropdowns-wrap-' . esc_attr($uID) . '" class="wcsearch-tax-dropdowns-wrap">';
			echo '<input type="hidden" name="' . esc_attr($field_name) . '" id="selected_tax[' . esc_attr($uID) . ']" value="' . esc_attr($field_value) . '" />';
			if ($exact_terms) {
				echo '<input type="hidden" id="exact_terms[' . esc_attr($uID) . ']" value="' . addslashes(implode(',', $exact_terms)) . '" />';
			}
		}
		
		if ($autocomplete_field) {
			$autocomplete_data = 'data-autocomplete-name="' . esc_attr($autocomplete_field) . '" data-autocomplete-value="' . esc_attr(stripslashes($autocomplete_field_value)) . '" data-default-icon="' . wcsearch_getDefaultTermIconUrl($tax) . '"';
			if ($autocomplete_ajax) {
				$autocomplete_data .= ' data-ajax-search=1';
			}
			if ($place_id) {
				$autocomplete_data .= ' data-place-id="' . $place_id . '"';
			}
		} else {
			$autocomplete_data = '';
		}
		
		if ($open_on_click) {
			$open_on_click_data = 'data-open-on-click="' . esc_attr($open_on_click) . '"';
		} else {
			$open_on_click_data = '';
		}
		echo '<select class="wcsearch-form-control wcsearch-autocomplete ' . esc_attr($functionality) . ' wcsearch-dropdowns-tax-' . esc_attr($tax) . '" data-id="' . esc_attr($uID) . '" data-placeholder="' . esc_attr($placeholder) . '" data-depth-level="' . esc_attr($depth_level) . '" data-tax="' . esc_attr($tax) . '" ' . $autocomplete_data . ' ' . $open_on_click_data . '>';
		foreach ($terms AS $term) {
			if ($count) {
				global $counter_calls_count;
				$counter_calls_count = array();
				
				$term_count = ' data-count="' . wcsearch_get_count_num(array('term' => $term)) . '"';
			} else {
				$term_count = '';
			}
			
			if (($term->term_id == $term_id) || (is_array($term_id) && in_array($term->term_id, $term_id))) {
				$selected = 'data-selected="selected"';
			} else {
				$selected = '';
			}
			if ($icon_file = wcsearch_getTermIconUrl($term->term_id, $tax)) {
				$icon = 'data-icon="' . esc_attr($icon_file) . '"';
			} else {
				$icon = 'data-icon="' . wcsearch_getDefaultTermIconUrl($tax) . '"';
			}
			
			$data = 'data-name="' . esc_attr($term->name)  . '" data-sublabel="" ' . $selected . ' ' . ($selected ? 'selected' : '') . ' ' . $icon . ' ' . $term_count;
			
			$data .= ' data-termid="'.esc_attr($term->term_id) . '" data-tax="'.esc_attr($term->taxonomy) . '"';

			echo '<option id="' . esc_attr($term->slug) . '" value="' . esc_attr($term->term_id) . '" ' . $data . '>' . esc_html($term->name) . '</option>';
			
			// when exact_terms - show them all on the first level at once
			if ($depth > 1 && !$exact_terms) {
				echo _wcsearch_tax_dropdowns_menu($tax, $term->term_id, $depth, 1, $term_id, $count, $exact_terms, $hide_empty, $orderby, $order);
			}
		}
		echo '</select>';
		if ($depth_level == 1) {
			echo '</div>';
		}
	} else {
		if ($autocomplete_field) {
			$autocomplete_data = 'data-autocomplete-name="' . esc_attr($autocomplete_field) . '" data-autocomplete-value="' . esc_attr(stripslashes($autocomplete_field_value)) . '" data-default-icon="' . wcsearch_getDefaultTermIconUrl() . '"';
			if ($autocomplete_ajax) {
				$autocomplete_data .= ' data-ajax-search=1';
			}
			if ($place_id) {
				$autocomplete_data .= ' data-place-id="' . $place_id . '"';
			}
		} else {
			$autocomplete_data = '';
		}
		
		echo '<div id="wcsearch-tax-dropdowns-wrap-' . esc_attr($uID) . '" class="wcsearch-tax-dropdowns-wrap">';
		echo '<div class="wcsearch-form-control wcsearch-autocomplete ' . esc_attr($functionality) . '" data-id="' . esc_attr($uID) . '" data-placeholder="' . esc_attr($placeholder) . '" ' . $autocomplete_data . '></div>';
		echo '</div>';
	}
}

function _wcsearch_tax_dropdowns_menu($tax, $parent = 0, $depth = 2, $current_level = 1, $term_id = null, $count = false, $exact_terms = array(), $hide_empty = false, $orderby = 'name', $order = 'ASC') {
	
	$categories_options = array(
			'taxonomy' => $tax,
			'hide_empty' => $hide_empty,
			'parent' => $parent,
	);
	if ($orderby == 'menu_order') {
		$categories_options['menu_order'] = 'ASC';
	} else {
		$categories_options['orderby'] = $orderby;
		$categories_options['order'] = $order;
	}
	
	/* if ($count) {
		// there is a wp bug with pad_counts in get_terms function - so we use this construction
		$terms = wp_list_filter(
				wcsearch_wrapper_get_categories($categories_options),
				array('parent' => $parent)
		);
	} else {
		$terms = wcsearch_wrapper_get_categories($categories_options);
	} */
	$terms = wcsearch_wrapper_get_categories($categories_options);
	
	$html = '';
	if ($terms && ($depth == 0 || !is_numeric($depth) || $depth > $current_level)) {
		foreach ($terms AS $key=>$term) {
			if ($exact_terms && (!in_array($term->term_id, $exact_terms) && !in_array($term->slug, $exact_terms))) {
				unset($terms[$key]);
			}
		}
	
		if ($terms) {
			$current_level++;

			foreach ($terms AS $term) {
				
				$sublabel = wcsearch_get_term_sublabel($term->parent, $tax);
				
				if ($count) {
					$term_count = ' data-count="' . wcsearch_get_count_num(array('term' => $term)) . '"';
				} else {
					$term_count = '';
				}
				if (($term->term_id == $term_id) || (is_array($term_id) && in_array($term->term_id, $term_id))) {
					$selected = 'data-selected="selected"';
				} else {
					$selected = '';
				}
				if ($icon_file = wcsearch_getTermIconUrl($term->term_id, $tax)) {
					$icon = 'data-icon="' . esc_url($icon_file) . '"';
				} else {
					$icon = 'data-icon="' . wcsearch_getDefaultTermIconUrl($tax) . '"';
				}
				
				$data = 'data-name="' . esc_attr($term->name)  . '" data-sublabel="' . esc_attr($sublabel) . '" ' . $selected . ' ' . ($selected ? 'selected' : '') . ' ' . $icon . ' ' . $term_count;
				
				$data .= ' data-termid="'.esc_attr($term->term_id) . '" data-tax="'.esc_attr($term->taxonomy) . '"';
			
				echo '<option id="' . esc_attr($term->slug) . '" value="' . esc_attr($term->term_id) . '" ' . $data . '>' . esc_html($term->name) . '</option>';
				if ($depth > $current_level) {
					echo _wcsearch_tax_dropdowns_menu($tax, $term->term_id, $depth, $current_level, $term_id, $count, $exact_terms, $hide_empty, $orderby, $order);
				}
			}
		}
	}
	return $html;
}

function wcsearch_get_term_sublabel($id, $tax, $separator = ', ', $return_array = false, &$chain = array()) {
	$parent = get_term($id, $tax);
	if (is_wp_error($parent) || !$parent) {
		if ($return_array) {
			return array();
		} else {
			return '';
		}
	}

	$name = $parent->name;

	if ($parent->parent && ($parent->parent != $parent->term_id)) {
		wcsearch_get_term_sublabel($parent->parent, $tax, $separator, $return_array, $chain);
	}

	$chain[] = $name;

	if ($return_array) {
		return $chain;
	} else {
		return implode($separator, $chain);
	}
}

/**
 * wcsearch-heirarhical-dropdown      // heirarhical tax
 * 
 */
function wcsearch_heirarhical_dropdowns_menu_init($params) {
	$attrs = array_merge(array(
			'uID' => 0,
			'field_name' => '',
			'count' => true,
			'tax' => '',
			'hide_empty' => false,
			'exact_terms' => array(),
			'autocomplete_field' => '',
			'autocomplete_field_value' => '',
			'autocomplete_ajax' => false,
			'placeholders' => '',
			'depth' => 1,
			'depth_level' => 1,
			'term_id' => 0,
			'parent' => 0,
			'functionality' => '',
			'orderby' => 'name',
			'order' => 'ASC',
	), $params);
	extract($attrs);
	
	// unique ID need when we place some dropdowns groups on one page
	if (!$uID) {
		$uID = rand(1, 10000);
	}
	
	if (!$field_name) {
		$field_name = 'selected_tax[' . $uID . ']';
	}
	
	if ($placeholders === false) {
		$taxonomy_obj = get_taxonomy($tax);
		$placeholders = $taxonomy_obj->labels->singular_name;
	} elseif (!is_array($placeholders) && json_decode($placeholders)) {
		$placeholders = json_decode($placeholders);
	} elseif (!empty($placeholders)) {
		$placeholders = $placeholders;
	} elseif (!empty($placeholder)) {
		$placeholders = $placeholder;
	}

	if ($term_id && $depth_level == 1) {
		$chain = array();
		$parent_id = $term_id;
		while ($parent_id != 0) {
			if ($term = get_term($parent_id, $tax)) {
				$chain[] = $term->term_id;
				$parent_id = $term->parent;
			} else {
				break;
			}
		}
		$chain[] = 0;
	} else {
		$chain[] = $parent;
	}
	
	$chain = array_reverse($chain);
	
	if (is_array($term_id)) {
		$field_value = implode(',', $term_id);
	} else {
		$field_value = $term_id;
	}
		
	if ($depth_level == 1) {
		echo '<div id="wcsearch-tax-dropdowns-wrap-' . esc_attr($uID) . '" class="wcsearch-tax-dropdowns-wrap">';
		echo '<input type="hidden" name="' . esc_attr($field_name) . '" id="selected_tax[' . esc_attr($uID) . ']" value="' . esc_attr($field_value) . '" />';
		if ($exact_terms) {
			echo '<input type="hidden" id="exact_terms[' . esc_attr($uID) . ']" value="' . addslashes(implode(',', $exact_terms)) . '" />';
		}
	}
		
	$chain_depth_level = $depth_level;
	
	$categories_options = array(
			'taxonomy' => $tax,
			'hide_empty' => $hide_empty,
	);
	if ($orderby == 'menu_order') {
		$categories_options['menu_order'] = 'ASC';
	} else {
		$categories_options['orderby'] = $orderby;
		$categories_options['order'] = $order;
	}
	
	if ($exact_terms) {
		$categories_options['exact_terms'] = $exact_terms;
	}
	
	foreach ($chain AS $key=>$parent) {
		$categories_options['parent'] = $parent;
		$terms = wcsearch_wrapper_get_categories($categories_options);
		
		if ($terms) {
			
			if (is_array($placeholders)) {
				if (isset($placeholders[$key])) {
					$chain_placeholder = $placeholders[$key];
				} else {
					$i = $key;
					while (!isset($placeholders[$i])) {
						$i--;
					}
					$chain_placeholder = $placeholders[$i];
				}
			} else {
				$chain_placeholder = $placeholders;
			}
			
			foreach ($terms AS $id=>$term) {
				if ($exact_terms && (!in_array($term->term_id, $exact_terms) && !in_array($term->slug, $exact_terms))) {
					unset($terms[$id]);
				}
			}
		
			if ($autocomplete_field) {
				$autocomplete_data = 'data-autocomplete-name="' . esc_attr($autocomplete_field) . '" data-autocomplete-value="' . esc_attr($autocomplete_field_value) . '"';
				if ($autocomplete_ajax) {
					$autocomplete_data .= ' data-ajax-search=1';
				}
			} else {
				$autocomplete_data = '';
			}
			echo '<select class="wcsearch-form-control wcsearch-autocomplete ' . esc_attr($functionality) . ' wcsearch-dropdowns-tax-' . esc_attr($tax) . '" data-id="' . esc_attr($uID) . '" data-placeholders="' . esc_attr($chain_placeholder) . '" data-depth-level="' . esc_attr($chain_depth_level) . '" data-tax="' . esc_attr($tax) . '" ' . $autocomplete_data . '>';
			foreach ($terms AS $term) {
				if ($count) {
					$term_count = 'data-count="' . wcsearch_get_count_num(array('term' => $term)) . '"';
				} else {
					$term_count = '';
				}
				if (isset($chain[$key+1]) && $term->term_id == $chain[$key+1]) {
					$selected = 'data-selected="selected"';
				} else {
					$selected = '';
				}
				if ($icon_file = wcsearch_getTermIconUrl($term->term_id, $tax)) {
					$icon = 'data-icon="' . esc_url($icon_file) . '"';
				} else {
					$icon = 'data-icon="' . wcsearch_getDefaultTermIconUrl($tax) . '"';
				}
				
				$data = 'data-name="' . esc_attr($term->name)  . '" data-sublabel="" ' . $selected . ' ' . $icon . ' ' . $term_count;
				
				$data .= ' data-termid="'.esc_attr($term->term_id) . '" data-tax="'.esc_attr($term->taxonomy) . '"';
		
				echo '<option id="' . esc_attr($term->slug) . '" value="' . esc_attr($term->term_id) . '" ' . $data . '>' . esc_html($term->name) . '</option>';
			}
			echo '</select>';
		}
		$chain_depth_level++;
	}
	
	if ($depth_level == 1) {
		echo '</div>';
	}
}

function wcsearch_tax_dropdowns_updateterms() {
	$parentid = wcsearch_getValue($_POST, 'parentid');
	$next_level = wcsearch_getValue($_POST, 'next_level');
	$tax = wcsearch_getValue($_POST, 'tax');
	$count = wcsearch_getValue($_POST, 'count');
	$hide_empty = wcsearch_getValue($_POST, 'hide_empty');
	
	$exact_terms = wcsearch_getValue($_POST, 'exact_terms');
	$exact_terms = array_filter(explode(",", $exact_terms));
	
	if (!$title = wcsearch_getValue($_POST, 'title')) {
		$title = esc_html__('Select term', 'WCSEARCH');
	}
	$uID = wcsearch_getValue($_POST, 'uID');

	if ($count) {
		// there is a wp bug with pad_counts in get_terms function - so we use this construction
		$terms = wp_list_filter(get_categories(array('taxonomy' => $tax, 'hide_empty' => $hide_empty)), array('parent' => $parentid));
	} else {
		$terms = get_categories(array('taxonomy' => $tax, 'hide_empty' => $hide_empty, 'parent' => $parentid));
	}
	if (!empty($terms)) {
		foreach ($terms AS $id=>$term) {
			if ($exact_terms && (!in_array($term->term_id, $exact_terms) && !in_array($term->slug, $exact_terms))) {
				unset($terms[$id]);
			}
		}

		if (!empty($terms)) {
			echo '<div id="wcsearch-wrap-chainlist-' . esc_attr($next_level) . '-' . esc_attr($uID) . '" class="wcsearch-row wcsearch-form-group">';
	
				echo '<div class="wcsearch-col-md-12">';
					echo '<select data-uid="' . esc_attr($uID) . '" data-level="' . esc_attr($next_level) . '" class="wcsearch-form-control wcsearch-selectmenu">';
					echo '<option value="">- ' . $title . ' -</option>';
					foreach ($terms as $term) {
						if (!$exact_terms || (in_array($term->term_id, $exact_terms) || in_array($term->slug, $exact_terms))) {
							if ($count) {
								$term_count = " (" . esc_attr($term->count) . ")";
							} else {
								$term_count = '';
							}
							$icon = '';
							
							echo '<option id="' . esc_attr($term->slug) . '" value="' . esc_attr($term->term_id) . '" ' . $icon . '>' . esc_html($term->name) . $term_count . '</option>';
						}
					}
					echo '</select>';
				echo '</div>';
			echo '</div>';
		}
	}
	
	die();
}

function wcsearch_getTermIconUrl($term_id, $tax) {
	
	$url = '';
	
	return apply_filters("wcsearch_get_term_icon_url", $url, $term_id, $tax);
}

function wcsearch_getDefaultTermIconUrl($tax = false) {
	return WCSEARCH_RESOURCES_URL . 'images/search.png';
}

function wcsearch_getEditFormIcon($id) {
	if (!($link = get_edit_post_link($id))) {
		
		$link = apply_filters("wcsearch_get_edit_form_link", $link, $id);
		
		if (!$link) {
			$link = wp_login_url(admin_url('post.php?post=' . $id . '&action=edit'));
		}
	}
	?>
	<a class="wcsearch-click-to-edit-search-button" href="<?php echo esc_url($link); ?>" title="<?php esc_attr_e('Click to edit search form', 'WCSEARCH'); ?>">
		<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20">
			<path d="M13.89 3.39l2.71 2.72c.46.46.42 1.24.03 1.64l-8.01 8.02-5.56 1.16 1.16-5.58s7.6-7.63 7.99-8.03c.39-.39 1.22-.39 1.68.07zm-2.73 2.79l-5.59 5.61 1.11 1.11 5.54-5.65zm-2.97 8.23l5.58-5.6-1.07-1.08-5.59 5.6z"></path>
		</svg>
	</a>
	<?php 
}

if (!function_exists('wcsearch_getValue')) {
	function wcsearch_getValue($target, $key, $default = false) {
		$target = is_object($target) ? (array) $target : $target;
	
		if (is_array($target) && isset($target[$key])) {
			$value = $target[$key];
		} else {
			$value = $default;
		}
	
		$value = apply_filters('wcsearch_get_value', $value, $target, $key, $default);
		
		if (is_string($value) && !is_serialized($value)) {
			$value = sanitize_text_field($value);
		}
		
		return $value;
	}
}

if (!function_exists('wcsearch_addMessage')) {
	function wcsearch_addMessage($message, $type = 'updated') {
		global $wcsearch_messages;
		
		if (is_array($message)) {
			foreach ($message AS $m) {
				wcsearch_addMessage($m, $type);
			}
			return ;
		}
	
		if (!isset($wcsearch_messages[$type]) || (isset($wcsearch_messages[$type]) && !in_array($message, $wcsearch_messages[$type]))) {
			$wcsearch_messages[$type][] = $message;
		}
	
		if (!isset($_SESSION['wcsearch_messages'][$type]) || (isset($_SESSION['wcsearch_messages'][$type]) && !in_array($message, $_SESSION['wcsearch_messages'][$type]))) {
			$_SESSION['wcsearch_messages'][$type][] = $message;
		}
	}
}

if (!function_exists('wcsearch_renderMessages')) {
	function wcsearch_renderMessages() {
		global $wcsearch_messages;
	
		$messages = array();
		if (isset($wcsearch_messages) && is_array($wcsearch_messages) && $wcsearch_messages) {
			$messages = $wcsearch_messages;
		}

		if (isset($_SESSION['wcsearch_messages'])) {
			$messages = array_merge($messages, $_SESSION['wcsearch_messages']);
		}
	
		$messages = wcsearch_superUnique($messages);
	
		foreach ($messages AS $type=>$messages) {
			$message_class = (is_admin()) ? $type : "wcsearch-" . $type;

			echo '<div class="' . esc_attr($message_class) . '">';
			foreach ($messages AS $message) {
				echo '<p>' . trim(preg_replace("/<p>(.*?)<\/p>/", "$1", $message)) . '</p>';
			}
			echo '</div>';
		}
		
		$wcsearch_messages = array();
		if (isset($_SESSION['wcsearch_messages'])) {
			unset($_SESSION['wcsearch_messages']);
		}
	}
	function wcsearch_superUnique($array) {
		$result = array_map("unserialize", array_unique(array_map("serialize", $array)));
		foreach ($result as $key => $value)
			if (is_array($value))
				$result[$key] = wcsearch_superUnique($value);
		return $result;
	}
}

function wcsearch_isResource($resource) {
	if (is_file(get_stylesheet_directory() . '/wcsearch-plugin/resources/' . $resource)) {
		return get_stylesheet_directory_uri() . '/wcsearch-plugin/resources/' . $resource;
	} elseif (is_file(WCSEARCH_RESOURCES_PATH . $resource)) {
		return WCSEARCH_RESOURCES_URL . $resource;
	}
	
	return false;
}

function wcsearch_isCustomResourceDir($dir) {
	if (is_dir(get_stylesheet_directory() . '/wcsearch-plugin/resources/' . $dir)) {
		return get_stylesheet_directory() . '/wcsearch-plugin/resources/' . $dir;
	}
	
	return false;
}

function wcsearch_getCustomResourceDirURL($dir) {
	if (is_dir(get_stylesheet_directory() . '/wcsearch-plugin/resources/' . $dir)) {
		return get_stylesheet_directory_uri() . '/wcsearch-plugin/resources/' . $dir;
	}
	
	return false;
}

/**
 * possible variants of templates and their paths:
 * - themes/theme/wcsearch-plugin/templates/template-custom.tpl.php
 * - themes/theme/wcsearch-plugin/templates/template.tpl.php
 * - plugins/wcsearch/templates/template-custom.tpl.php
 * - plugins/wcsearch/templates/template.tpl.php
 * 
 */
function wcsearch_isTemplate($template) {
	$custom_template = str_replace('.tpl.php', '', $template) . '-custom.tpl.php';
	$templates = array(
			$custom_template,
			$template
	);

	foreach ($templates AS $template_to_check) {
		// check if it is exact path in $template
		if (is_file($template_to_check)) {
			return $template_to_check;
		} elseif (is_file(get_stylesheet_directory() . '/wcsearch-plugin/templates/' . $template_to_check)) { // theme or child theme templates folder
			return get_stylesheet_directory() . '/wcsearch-plugin/templates/' . $template_to_check;
		} elseif (is_file(WCSEARCH_TEMPLATES_PATH . $template_to_check)) { // native plugin's templates folder
			return WCSEARCH_TEMPLATES_PATH . $template_to_check;
		}
	}

	return false;
}

if (!function_exists('wcsearch_renderTemplate')) {
	/**
	 * @param string|array $template
	 * @param array $args
	 * @param bool $return
	 * @return string
	 */
	function wcsearch_renderTemplate($template, $args = array(), $return = false) {
		global $wcsearch_instance;
	
		if ($args) {
			extract($args);
		}
		
		$template = apply_filters('wcsearch_render_template', $template, $args);
		
		if (is_array($template)) {
			$template_path = $template[0];
			$template_file = $template[1];
			$template = $template_path . $template_file;
		}
		
		$template = wcsearch_isTemplate($template);

		if ($template) {
			if ($return) {
				ob_start();
			}
		
			include($template);
			
			if ($return) {
				$output = ob_get_contents();
				ob_end_clean();
				return $output;
			}
		}
	}
}

function wcsearch_generateRandomVal($val = null) {
	if (!$val)
		return rand(1, 10000);
	else
		return $val;
}

function wcsearch_do_enqueue_scripts_styles($load_scripts_styles) {
	global $wcsearch_instance, $wcsearch_enqueued;
	
	if (get_option('wcsearch_force_include_js_css')) {
		return true;
	}
	
	if ((($wcsearch_instance->frontend_controllers || $load_scripts_styles) && !$wcsearch_enqueued)) {
		return true;
	}
	
	if ($wcsearch_instance->form_on_shop_page && wcsearch_is_shop()) {
		return true;
	}
}

function wcsearch_setFrontendController($shortcode, $shortcode_instance = null) {
	global $wcsearch_instance;

	$wcsearch_instance->frontend_controllers[$shortcode][] = $shortcode_instance;

	return $shortcode_instance;
}

function wcsearch_get_on_shop_page() {
	$args = array(
		'post_type' => WCSEARCH_FORM_TYPE,
		'post_status' => 'publish',
		'meta_query' => array(
				array(
						'key' => '_on_shop_page',
						'value'   => 1,
				),
		),
	);
	$query = new WP_Query;
	$posts = $query->query($args);
	wp_reset_postdata();
	
	if ($posts) {
		return $posts[0];
	}
}

function wcsearch_isPluginPageInAdmin() {
	global $pagenow;

if (
		is_admin() &&
		(
				(($pagenow == 'edit.php' || $pagenow == 'post-new.php') && ($post_type = wcsearch_getValue($_GET, 'post_type')) &&
						(in_array($post_type, array(WCSEARCH_FORM_TYPE)))
				) ||
				($pagenow == 'post.php' && ($post_id = wcsearch_getValue($_GET, 'post')) && ($post = get_post($post_id)) &&
						(in_array($post->post_type, array(WCSEARCH_FORM_TYPE)))
				) ||
				($pagenow == 'widgets.php')
		)
	) {
		return true;
	}
}

/**
 * returns array of installed plugins:
 * - WooCommerce,
 * - Web 2.0 Directory,
 * - Google Maps Locator,
 * - MapBox Locator
 * 
 * true when no other plugins,
 * 
 * false - when it is not standalone
 * 
 */
function wcsearch_is_standalone_plugin() {
	if (in_array('woocommerce-search/search.php', apply_filters('active_plugins', get_option('active_plugins')))) {
		$other_plugins = array();
		if (wcsearch_is_woo_active()) {
			$other_plugins['wc'] = esc_html__("WooCommerce search", "WCSEARCH");
		}
		if (defined('W2DC_VERSION') || defined('W2DCF_VERSION')) {
			$other_plugins['w2dc'] = esc_html__("Web 2.0 Directory search", "WCSEARCH");
		}
		if (defined('W2GM_VERSION')) {
			$other_plugins['w2dc'] = esc_html__("Google Maps Locator search", "WCSEARCH");
		}
		if (defined('W2MB_VERSION')) {
			$other_plugins['w2dc'] = esc_html__("MapBox Locator search", "WCSEARCH");
		}
		
		if ($other_plugins) {
			return $other_plugins;
		} else {
			return true;
		}
	} else {
		return false;
	}
}
function wcsearch_get_default_used_by() {

	if ($existing_used_by = get_post_meta(get_the_ID(), '_used_by', true)) {
		return $existing_used_by;
	}

	if (in_array('woocommerce-search/search.php', apply_filters('active_plugins', get_option('active_plugins')))) {
		return 'wc';
	} else {
		if (defined('W2DC_VERSION') || defined('W2DCF_VERSION')) {
			return 'w2dc';
		}
		if (defined('W2GM_VERSION')) {
			return 'w2gm';
		}
		if (defined('W2MB_VERSION')) {
			return 'w2mb';
		}
	}
}

function wcsearch_is_w2dc_active() {

	if (defined('W2DC_VERSION') || defined('W2DCF_VERSION') || defined('W2GM_VERSION') || defined('W2MB_VERSION')) {
		return true;
	}
}

function wcsearch_is_woo_active() {

	if (class_exists('woocommerce')) {
		return true;
	}
}

function wcsearch_is_shop() {

	if (!wcsearch_is_woo_active()) {
		return false;
	}
	
	if (is_shop()) {
		return true;
	} else {
		return false;
	}
}
function wcsearch_is_cart() {

	if (!wcsearch_is_woo_active()) {
		return false;
	}
	
	if (is_cart()) {
		return true;
	} else {
		return false;
	}
}
function wcsearch_is_checkout() {

	if (!wcsearch_is_woo_active()) {
		return false;
	}
	
	if (is_checkout()) {
		return true;
	} else {
		return false;
	}
}
function wcsearch_is_account_page() {

	if (!wcsearch_is_woo_active()) {
		return false;
	}
	
	if (is_account_page()) {
		return true;
	} else {
		return false;
	}
}
function wcsearch_is_view_order_page() {

	if (!wcsearch_is_woo_active()) {
		return false;
	}
	
	if (is_view_order_page()) {
		return true;
	} else {
		return false;
	}
}
function wcsearch_is_product_category() {

	if (!wcsearch_is_woo_active()) {
		return false;
	}
	
	if (is_product_category()) {
		return true;
	} else {
		return false;
	}
}
function wcsearch_is_product_tag() {

	if (!wcsearch_is_woo_active()) {
		return false;
	}
	
	if (is_product_tag()) {
		return true;
	} else {
		return false;
	}
}

function wcsearch_isWooPage() {
	
	if (!wcsearch_is_woo_active()) {
		return false;
	}
	
	if (wcsearch_is_shop()) {
		return wc_get_page_id('shop');
	}
	if (wcsearch_is_cart()) {
		return wc_get_page_id('cart');
	}
	if (wcsearch_is_checkout()) {
		return wc_get_page_id('checkout');
	}
	if (wcsearch_is_account_page() || wcsearch_is_view_order_page()) {
		return wc_get_page_id('myaccount');
	}
}

function wcsearch_get_model_fields($used_by) {

	return apply_filters("wcsearch_get_model_fields", array(), $used_by);
}

function wcsearch_get_min_max_numbers($used_by, $slug) {

	$vals = apply_filters("wcsearch_get_min_max_numbers", null, $used_by, $slug);
	
	if ($vals) {
		$min = floor($vals->min);
		$max = ceil($vals->max);
	} else {
		$min = 0;
		$max = 0;
	}
	$prices = range($min, $max);
	
	return $prices;
}

function wcsearch_price_format($value, $used_by, $slug) {

	return apply_filters("wcsearch_price_format", $value, $used_by, $slug);
}

function wcsearch_number_format($value, $used_by, $slug) {

	return apply_filters("wcsearch_number_format", $value, $used_by, $slug);
}

function wcsearch_min_max_options_to_range($min_max_options) {

	$results_array = array();

	if (!is_array($min_max_options)) {
		$min_max_options = explode(',', $min_max_options);
	}
	$min_max_options = array_filter(array_map('trim', $min_max_options), 'strlen');

	foreach ($min_max_options AS $key=>$option) {
		$min_max_options_range = array_filter(array_map('trim', explode('-', $option)), 'strlen');
		if (count($min_max_options_range) == 2) {
			$results_array = array_merge($results_array, range($min_max_options_range[0], $min_max_options_range[1]));
		} elseif (isset($min_max_options_range[0]) && is_numeric($min_max_options_range[0])) {
			$results_array[] = $min_max_options_range[0];
		} elseif (isset($min_max_options_range[1]) && is_numeric($min_max_options_range[1])) {
			$results_array[] = $min_max_options_range[1];
		} else {
			$results_array[] = $option;
		}
	}

	$results_array = array_values(array_filter($results_array, 'wcsearch_number_filter'));

	return $results_array;
}

function wcsearch_print_range_slider_code($params) {
	extract($params);
	
	$index = wcsearch_generateRandomVal();
	
	// min-max
	// min, 1, 10, 100, max
	// 1-100

	if (isset($tax)) {
		//taxonomy
		
		if ($min_max_options) {
			if (!is_array($min_max_options)) {
				$min_max_options = explode(',', $min_max_options);
			}
		} else {
			$min_max_options = array();
		}
		
		if (empty($min_max_options)) {
			return false;
		}

		foreach ($min_max_options AS $term_id=>$term_name) {
			$min_max_options_formatted[$term_id] = esc_attr($term_name);
		}
		$min_max_options = array_keys($min_max_options);
	} elseif ($is_number) {
		// digits

		$min_max_options = wcsearch_min_max_options_to_range($min_max_options);
		
		if (!$min_max_options) {
		// get min-max values of this field
			$min_max_options = wcsearch_get_min_max_numbers($used_by, $slug);
		}
		
		$min_max_options_formatted = $min_max_options;
		foreach ($min_max_options_formatted AS $key=>$value) {
			if (is_numeric($value)) {
				$min_max_options_formatted[$key] = wcsearch_number_format($value, $used_by, $slug);
			} else {
				$min_max_options_formatted[$key] = esc_attr($value);
			}
		}
	} elseif (!$is_number) {
		// price

		$min_max_options = wcsearch_min_max_options_to_range($min_max_options);

		if (!$min_max_options) {
			// get min-max values of this field
			$min_max_options = wcsearch_get_min_max_numbers($used_by, $slug);
		}
		
		$min_max_options_formatted = $min_max_options;
		foreach ($min_max_options_formatted AS $key=>$value) {
			if (is_numeric($value)) {
				$min_max_options_formatted[$key] = wcsearch_price_format($value, $used_by, $slug);
			} else {
				$min_max_options_formatted[$key] = esc_attr($value);
			}
		}
	}
	
	$min_value = '';
	$max_value = '';
	if ($values) {
		if (is_array($values)) {
			if (count($values) == 1) {
				$values = '-' . $values[0];
			} elseif (count($values) == 2) {
				$values = $values[0] . '-' . $values[1];
			}
		}
		
		$values = explode('-', $values);
		
		if (count($values) == 2) {
			if ($values[1] === '') {
				$max_value = end($min_max_options);
			} else {
				$max_value = $values[1];
			}
			
			if ($values[0] === '') {
				$min_value = reset($min_max_options);
			} else {
				$min_value = $values[0];
			}
		} else {
			$values = explode(',', $values[0]);

			$max_value = end($values);
			$min_value = reset($values);
		}
	} else {
		$max_value = end($min_max_options);
		$min_value = reset($min_max_options);
	}
	
	if (($key = array_search('min', $min_max_options, true)) !== false) {
		$min_max_options[$key] = esc_html__('min', 'WCSEARCH');
		$min_max_options_formatted[$key] = esc_html__('min', 'WCSEARCH');
	}
	if (($key = array_search('max', $min_max_options, true)) !== false) {
		$min_max_options[$key] = esc_html__('max', 'WCSEARCH');
		$min_max_options_formatted[$key] = esc_html__('max', 'WCSEARCH');
	}
	?>
	<?php if (count($min_max_options)): ?>
	<script>
	(function($) {
		"use strict";
			
		$(function() {
			var slider_params_<?php echo esc_attr($index); ?> = ['<?php echo implode("','", $min_max_options); ?>'];
			var slider_params_formatted_<?php echo esc_attr($index); ?> = ['<?php echo implode("','", $min_max_options_formatted); ?>'];
			var slider_min_<?php echo esc_attr($index); ?> = 0;
			var slider_max_<?php echo esc_attr($index); ?> = slider_params_<?php echo esc_attr($index); ?>.length-1;
			$('#range_slider_<?php echo esc_attr($index); ?>').slider({
				<?php if (function_exists('is_rtl') && is_rtl()): ?>
				isRTL: true,
				<?php endif; ?>
				min: slider_min_<?php echo esc_attr($index); ?>,
				max: slider_max_<?php echo esc_attr($index); ?>,
				range: true,
				values: [<?php echo ((($min = array_search($min_value, $min_max_options)) !== false) ? $min : 0); ?>, <?php echo ((($max = array_search($max_value, $min_max_options)) !== false) ? $max : count($min_max_options)-1); ?>],
				stop: function(event, ui) {
					var input = $("#<?php echo esc_attr($slug).'_'.esc_attr($index); ?>");
					
					input.trigger("change");
				},
				slide: function(event, ui) {
					if (slider_params_<?php echo esc_attr($index); ?>[ui.values[0]] == '<?php esc_html_e('min', 'WCSEARCH'); ?>') {
						var min = '';
					} else {
						var min = slider_params_<?php echo esc_attr($index); ?>[ui.values[0]];
					}
					if (slider_params_<?php echo esc_attr($index); ?>[ui.values[1]] == '<?php esc_html_e('max', 'WCSEARCH'); ?>') {
						var max = '';
					} else {
						var max = slider_params_<?php echo esc_attr($index); ?>[ui.values[1]];
					}

					format_input_<?php echo esc_attr($index); ?>(min, max);

					<?php if ($show_scale == "string"): ?>
					var values = $(this).slider("option", "values");
					var values_str = slider_params_formatted_<?php echo esc_attr($index); ?>[ui.values[0]] + ' - ' + slider_params_formatted_<?php echo esc_attr($index); ?>[ui.values[1]];
					$("#range_slider_<?php echo esc_attr($index); ?>_scale").html("<?php echo esc_attr($string_label); ?> "+values_str);
					<?php endif; ?>
				}
			}).each(function() {
				<?php if ($show_scale == "string"): ?>
				var values = $(this).slider("option", "values");
				var values_str = slider_params_formatted_<?php echo esc_attr($index); ?>[values[0]] + ' - ' + slider_params_formatted_<?php echo esc_attr($index); ?>[values[1]];
				$("#range_slider_<?php echo esc_attr($index); ?>_scale").html("<?php echo esc_attr($string_label); ?> "+values_str);
				<?php elseif ($show_scale == "scale"): ?>
				$.each(slider_params_formatted_<?php echo esc_attr($index); ?>, function(index, value) {
					<?php if (!is_rtl()): ?>
					var position = 'left';
					<?php else: ?>
					var position = 'right';
					<?php endif ?>
					<?php if ($odd_even_labels == "odd"): ?>
					var odd_even_label = 2;
					<?php else: ?>
					var odd_even_label = 1;
					<?php endif; ?>
					if (index % odd_even_label == 0) {
						var el = $('<label><span>|</span><span class="wcsearch-range-slider-label">' + value + '</span></label>').css(position, (100/(slider_params_<?php echo esc_attr($index); ?>.length-1))*index + '%');
					} else {
						var el = $('<label><span>|</span></label>').css(position, (100/(slider_params_<?php echo esc_attr($index); ?>.length-1))*index + '%');
					}
					$('#range_slider_<?php echo esc_attr($index); ?>_scale').append(el);
				});
				<?php endif; ?>
			});

			function format_input_<?php echo esc_attr($index); ?>(min, max) {

				<?php if (!empty($tax)): ?>
				var index_min;
				var index_max;
				$(slider_params_<?php echo esc_attr($index); ?>).each(function(i, val) {
					if (min == val) {
						index_min = i;
					}
					if (max == val) {
						index_max = i;
					}
				});
				
				var input = $("#<?php echo esc_attr($slug).'_'.esc_attr($index); ?>");
				if (index_min != 0 || index_max != (slider_params_<?php echo esc_attr($index); ?>.length - 1)) {
					input.val(slider_params_<?php echo esc_attr($index); ?>.slice(index_min, index_max));
				} else {
					input.val("");
				}
				<?php else: ?>
				var sep = '-';
				if (min == slider_params_<?php echo esc_attr($index); ?>[0]) {
					min = '';
				}
				if (max == slider_params_<?php echo esc_attr($index); ?>[slider_params_<?php echo esc_attr($index); ?>.length-1]) {
					max = '';
				}
				
				var input = $("#<?php echo esc_attr($slug).'_'.esc_attr($index); ?>");
				if (min || max) {
					input.val(min+sep+max);
				} else {
					input.val('');
				}
				<?php endif; ?>
			}
			format_input_<?php echo esc_attr($index); ?>('<?php echo esc_attr($min_value)?>', '<?php echo esc_attr($max_value)?>');
		});
	})(jQuery);
	</script>
	<div class="wcsearch-jquery-ui-slider">
		<div id="range_slider_<?php echo esc_attr($index); ?>" class="wcsearch-range-slider"></div>
		<div id="range_slider_<?php echo esc_attr($index); ?>_scale" class="wcsearch-range-slider-scale"></div>
		<input type="hidden" id="<?php echo esc_attr($slug).'_'.esc_attr($index); ?>" name="<?php echo esc_attr($field_name); ?>" <?php if (!empty($tax)): ?>data-tax="<?php echo esc_attr($tax); ?>"<?php endif; ?> value="" />
	</div>
	<?php endif; ?>
	<?php
}

function wcsearch_print_single_slider_code($params) {
	extract($params);
	
	// 1, 10, 100
	// 1-100
	
	$index = wcsearch_generateRandomVal();
	
	if (isset($tax)) {
		// taxonomy

		if (!is_array($min_max_options)) {
			$min_max_options = explode(',', $min_max_options);
		}

		if (empty($min_max_options)) {
			return false;
		}
	
		foreach ($min_max_options AS $term_id=>$term_name) {
			$min_max_options_formatted[$term_id] = esc_attr($term_name);
		}
		$min_max_options = array_keys($min_max_options);
	} elseif (isset($is_number)) {
		// digits

		$min_max_options = wcsearch_min_max_options_to_range($min_max_options);
		
		if (!$min_max_options) {
			// get min-max values of this field
			$min_max_options = wcsearch_get_min_max_numbers($used_by, $slug);
		}
	
		$min_max_options_formatted = $min_max_options;
		foreach ($min_max_options_formatted AS $key=>$_value) {
			if (is_numeric($_value)) {
				$min_max_options_formatted[$key] = wcsearch_number_format($_value, $used_by, $slug);
			} else {
				$min_max_options_formatted[$key] = esc_attr($_value);
			}
		}
		
		foreach ($min_max_options AS $key=>$_value) {
			$min_max_options[$key] = $_value;
		}
	} elseif (!isset($is_number)) {
		// price

		$min_max_options = wcsearch_min_max_options_to_range($min_max_options);
		
		if (!$min_max_options) {
		// get min-max values of this field
			$min_max_options = wcsearch_get_min_max_numbers($used_by, $slug);
		}
	
		$min_max_options_formatted = $min_max_options;
		foreach ($min_max_options_formatted AS $key=>$_value) {
			if (is_numeric($_value)) {
				$min_max_options_formatted[$key] = wcsearch_price_format($_value, $used_by, $slug);
			} else {
				$min_max_options_formatted[$key] = esc_attr($_value);
			}
		}
		
		foreach ($min_max_options AS $key=>$_value) {
			$min_max_options[$key] = $_value;
		}
	}
	
	// this is empty value in options, needed to reset input
	array_unshift($min_max_options, 0);
	array_unshift($min_max_options_formatted, "&nbsp;");
	
	$js_val = array_search($values, $min_max_options);
	
	$js_val = ($js_val ? $js_val : 0);

?>
<script>
(function($) {
	"use strict";
		
	$(function() {
		var slider_params_<?php echo esc_attr($index); ?> = ['<?php echo implode("','", $min_max_options); ?>'];
		var slider_params_formatted_<?php echo esc_attr($index); ?> = ['<?php echo implode("','", $min_max_options_formatted); ?>'];
			$('#single_slider_<?php echo esc_attr($index); ?>').slider({
				<?php if (function_exists('is_rtl') && is_rtl()): ?>
				isRTL: true,
				<?php endif; ?>
				range: false,
				value: <?php echo esc_js($js_val); ?>,
				max: slider_params_<?php echo esc_attr($index); ?>.length-1,
				stop: function(event, ui) {
					var input = $("#<?php echo esc_attr($slug).'_'.esc_attr($index); ?>");
					
					input.trigger("change");
				},
				slide: function(event, ui) {
					var val = slider_params_<?php echo esc_attr($index); ?>[ui.value];

					format_input_<?php echo esc_attr($index); ?>(val);

					<?php if ($show_scale == "string"): ?>
					var value = $(this).slider("option", "value");
					var value_str = slider_params_formatted_<?php echo esc_attr($index); ?>[ui.value];
					$("#single_slider_<?php echo esc_attr($index); ?>_scale").html("<?php echo esc_attr($string_label); ?> "+value_str);
					<?php endif; ?>
				}
			}).each(function() {
				<?php if ($show_scale == "string"): ?>
				var value = $(this).slider("value");
				var value_str = slider_params_formatted_<?php echo esc_attr($index); ?>[value];
				$("#single_slider_<?php echo esc_attr($index); ?>_scale").html("<?php echo esc_attr($string_label); ?> "+value_str);
				<?php elseif ($show_scale == "scale"): ?>
				$.each(slider_params_formatted_<?php echo esc_attr($index); ?>, function(index, value) {
					<?php if (!is_rtl()): ?>
					var position = 'left';
					<?php else: ?>
					var position = 'right';
					<?php endif ?>
					<?php if ($odd_even_labels == "odd"): ?>
					var odd_even_label = 2;
					<?php else: ?>
					var odd_even_label = 1;
					<?php endif; ?>
					if (index % odd_even_label == 0) {
						var el = $('<label><span>|</span><span class="wcsearch-range-slider-label">' + value + '</span></label>').css(position, (100/(slider_params_<?php echo esc_attr($index); ?>.length-1))*index + '%');
					} else {
						var el = $('<label><span>|</span></label>').css(position, (100/(slider_params_<?php echo esc_attr($index); ?>.length-1))*index + '%');
					}
					$('#single_slider_<?php echo esc_attr($index); ?>_scale').append(el);
				});
				<?php endif; ?>
			});

			function format_input_<?php echo esc_attr($index); ?>(value) {
				
				var input = $("#<?php echo esc_attr($slug).'_'.esc_attr($index); ?>");
				if (value) {
					input.val(value);
				} else {
					input.val('');
				}
				
			}
			format_input_<?php echo esc_attr($index); ?>("<?php echo esc_js($values); ?>");
		});
})(jQuery);
	</script>
	<div class="wcsearch-jquery-ui-slider">
		<div id="single_slider_<?php echo esc_attr($index); ?>" class="wcsearch-single-slider"></div>
		<div id="single_slider_<?php echo esc_attr($index); ?>_scale" class="wcsearch-single-slider-scale"></div>
		<input type="hidden" id="<?php echo esc_attr($slug).'_'.esc_attr($index); ?>" name="<?php echo esc_attr($field_name); ?>" <?php if (!empty($tax)): ?>data-tax="<?php echo esc_attr($tax); ?>"<?php endif; ?> value="" />
	</div>
	<?php
}

function wcsearch_print_radius_selectbox_code($params) {
	extract($params);
	
	// 1, 10, 100
	// 1-100
	// 1-20, 30, 50
	
	$index = wcsearch_generateRandomVal();

	$min_max_options = wcsearch_min_max_options_to_range($min_max_options);
	
	$dimension_unit = 'kilometers';
	if ($geocode_functions = wcsearch_geocode_functions()) {
		if (isset($geocode_functions['dimension_unit'])) {
			$dimension_unit = $geocode_functions['dimension_unit'];
		}
	}

	$min_max_options_formatted = $min_max_options;
	foreach ($min_max_options_formatted AS $key=>$_value) {
		$min_max_options_formatted[$key] = $_value . ' ' . esc_html(($dimension_unit == 'miles' ? _n("mile", "miles", $_value, "WCSEARCH") : _n("kilometer", "kilometers", $_value, "WCSEARCH")));
	}
		
	$value = trim($values, '-');
	
	$value = ($value ? $value : 0);
?>
<select class="wcsearch-selectbox-input wcsearch-form-control" id="<?php echo esc_attr($slug).'_'.esc_attr($index); ?>" name="<?php echo esc_attr($slug); ?>">
<?php foreach ($min_max_options_formatted AS $key=>$_value) :?>
	<option value="<?php echo esc_attr($min_max_options[$key])?>" <?php if ($value == $min_max_options[$key]) echo 'selected';?>><?php echo $_value; ?></option>
<?php endforeach; ?>
</select>
<?php
}

function wcsearch_print_radius_slider_code($params) {
	extract($params);
	
	// 1, 10, 100
	// 1-100
	// 1-20, 30, 50
	
	$index = wcsearch_generateRandomVal();

	$min_max_options = wcsearch_min_max_options_to_range($min_max_options);
	
	$dimension_unit = 'kilometers';
	if ($geocode_functions = wcsearch_geocode_functions()) {
		if (isset($geocode_functions['dimension_unit'])) {
			$dimension_unit = $geocode_functions['dimension_unit'];
		}
	}

	$min_max_options_formatted = $min_max_options;
	foreach ($min_max_options_formatted AS $key=>$_value) {
		if (is_numeric($_value)) {
			$min_max_options_formatted[$key] = '<strong>' . $_value . '</strong>' . ' ' . esc_html(($dimension_unit == 'miles' ? _n("mile", "miles", $_value, "WCSEARCH") : _n("kilometer", "kilometers", $_value, "WCSEARCH")));
		} else {
			$min_max_options_formatted[$key] = esc_attr($_value);
		}
	}
		
	$values = trim($values, '-');
	$value = array_search($values, $min_max_options);
	
	$value = ($value ? $value : 0);
?>
<script>
(function($) {
	"use strict";
		
	$(function() {
		var slider_params_<?php echo esc_attr($index); ?> = ['<?php echo implode("','", $min_max_options); ?>'];
		var slider_params_formatted_<?php echo esc_attr($index); ?> = ['<?php echo implode("','", $min_max_options_formatted); ?>'];
			$('#single_slider_<?php echo esc_attr($index); ?>').slider({
				<?php if (function_exists('is_rtl') && is_rtl()): ?>
				isRTL: true,
				<?php endif; ?>
				range: "min",
				value: <?php echo esc_js($value); ?>,
				max: slider_params_<?php echo esc_attr($index); ?>.length-1,
				stop: function(event, ui) {
					var input = $("#<?php echo esc_attr($slug).'_'.esc_attr($index); ?>");
					
					input.trigger("change");
				},
				slide: function(event, ui) {
					var val = slider_params_<?php echo esc_attr($index); ?>[ui.value];

					format_input_<?php echo esc_attr($index); ?>(val);

					var value = $(this).slider("option", "value");
					var value_str = slider_params_formatted_<?php echo esc_attr($index); ?>[ui.value];
					$("#single_slider_<?php echo esc_attr($index); ?>_string").html("<?php echo esc_attr($string_label); ?> "+" "+value_str);
				}
			}).each(function() {
				var value = $(this).slider("value");
				var value_str = slider_params_formatted_<?php echo esc_attr($index); ?>[value];
				$("#single_slider_<?php echo esc_attr($index); ?>_string").html("<?php echo esc_attr($string_label); ?> "+" "+value_str);
				<?php if ($show_scale == "scale"): ?>
				$.each(slider_params_<?php echo esc_attr($index); ?>, function(index, value) {
					<?php if (!is_rtl()): ?>
					var position = 'left';
					<?php else: ?>
					var position = 'right';
					<?php endif ?>
					<?php if ($odd_even_labels == "odd"): ?>
					var odd_even_label = 2;
					<?php else: ?>
					var odd_even_label = 1;
					<?php endif; ?>
					if (index % odd_even_label == 0) {
						var el = $('<label><span>|</span><span class="wcsearch-range-slider-label">' + value + '</span></label>').css(position, (100/(slider_params_<?php echo esc_attr($index); ?>.length-1))*index + '%');
					} else {
						var el = $('<label><span>|</span></label>').css(position, (100/(slider_params_<?php echo esc_attr($index); ?>.length-1))*index + '%');
					}
					$('#single_slider_<?php echo esc_attr($index); ?>_scale').append(el);
				});
				<?php endif; ?>
			});

			function format_input_<?php echo esc_attr($index); ?>(value) {
				
				var input = $("#<?php echo esc_attr($slug).'_'.esc_attr($index); ?>");
				if (value) {
					input.val(value);
				} else {
					input.val('');
				}
				
			}

			var val = slider_params_<?php echo esc_attr($index); ?>[<?php echo esc_js($value); ?>];
			format_input_<?php echo esc_attr($index); ?>(val);
		});
})(jQuery);
	</script>
	<div class="wcsearch-jquery-ui-slider">
		<div id="single_slider_<?php echo esc_attr($index); ?>_string" class="wcsearch-single-slider-string"></div>
		<div id="single_slider_<?php echo esc_attr($index); ?>" class="wcsearch-single-slider"></div>
		<?php if ($show_scale == "scale"): ?>
		<div id="single_slider_<?php echo esc_attr($index); ?>_scale" class="wcsearch-single-slider-scale"></div>
		<?php endif; ?>
		<input type="hidden" id="<?php echo esc_attr($slug).'_'.esc_attr($index); ?>" name="<?php echo esc_attr($slug); ?>" value="" />
	</div>
	<?php
}

function wcsearch_get_pagination_base() {
	$pagenum_link = explode('?', esc_url_raw(str_replace(999999999, '%#%', get_pagenum_link(999999999, false))));
	
	return $pagenum_link[0];
}

function wcsearch_get_allowed_search_params() {
	
	$allowed_params = apply_filters("wcsearch_allowed_params", array());
	
	return $allowed_params;
}

/**
 * returns array of query parameters,
 * or parameter value as string
 * 
 * @param string $param_name
 * @return mix string|array:
 */
function wcsearch_get_query_string($param_name = false) {

	$uri_params = array();

	if (!empty($_REQUEST['query_string'])) {
		$query_string_array = array_filter(explode('&', $_REQUEST['query_string']));
			
		foreach ($query_string_array AS $query_arg) {
			$query_arg = explode('=', $query_arg);
			if (count($query_arg) == 2) {
				$param = $query_arg[0];
				$value = $query_arg[1];
				$uri_params[$param] = $value;
			}
		}
	} else {
		$uri_params = $_GET;
	}
	
	$uri_params = array_intersect_key($uri_params, array_flip(wcsearch_get_allowed_search_params()));
	
	if ($param_name) {
		if (isset($uri_params[$param_name])) {
			return $uri_params[$param_name];
		} else {
			return '';
		}
	} else {
		return $uri_params;
	}
}

/**
 * get any query by default,
 * like tax terms pages
 * 
 * @return array
 */
function wcsearch_get_default_query() {
	$default_query = array();
	
	if (wcsearch_is_woo_active()) {
		if (is_product_category()) {
			$default_query['product_cat'] = get_queried_object()->term_id;
		}
		if (is_product_tag()) {
			$default_query['product_tag'] = get_queried_object()->term_id;
		}
		
		if (function_exists('wc_get_attribute_taxonomies')) {
			$wc_attribute_taxonomies = wc_get_attribute_taxonomies();
			foreach ($wc_attribute_taxonomies AS $taxonomy) {
				$tax_name = wc_attribute_taxonomy_name($taxonomy->attribute_name);
					
				if (is_tax($tax_name)) {
					$default_query[$tax_name] = get_queried_object()->term_id;
				}
			}
		}
	}
	
	$default_query = apply_filters("wcsearch_default_query", $default_query);

	return $default_query;
}

function wcsearch_number_filter($val) {
	$val = trim($val);
	if (is_numeric($val) || $val == 'min' || $val == 'max') {
		return true;
	}
}

function wcsearch_format_number_labels(&$min_max_options, $used_by, $slug) {
	$min_max_options = array_values(array_filter(explode(',', $min_max_options), 'wcsearch_number_filter'));
	$min_max_options = array_map('trim', $min_max_options);
	$min_max_labels = $min_max_options;
	foreach ($min_max_labels AS $key=>$value) {
		if (is_numeric($value)) {
			$min_max_labels[$key] = wcsearch_number_format($value, $used_by, $slug);
		}
	}
	
	return $min_max_labels;
}

function wcsearch_get_number_labels($min_max_options, $used_by, $slug) {
	$min_max_labels = wcsearch_format_number_labels($min_max_options, $used_by, $slug);
	
	$label_value_pair = array();
	
	if ($min_max_labels) {
		$key = 0;
		while ($key <= count($min_max_labels)) {
			if ($key == 0) {
				$option_label = sprintf(esc_html__('less than %s'), $min_max_labels[$key]);
				$option_value = '-' . $min_max_options[$key];
			} elseif ($key == count($min_max_options)) {
				$option_label = sprintf(esc_html__('more than %s'), $min_max_labels[$key-1]);
				$option_value = $min_max_options[$key-1] . '-';
			} else {
				$option_label = $min_max_labels[$key-1] . ' - ' . $min_max_labels[$key];
				$option_value = $min_max_options[$key-1] . '-' . $min_max_options[$key];
			}
			$label_value_pair[$option_label] = $option_value;
			
			$key++;
		}
	}
	
	return $label_value_pair;
}

function wcsearch_get_featured_counter() {

	if (wcsearch_is_woo_active()) {
		$args = array(
				'post_type' => 'product',
				'post__in'  => wc_get_featured_product_ids(),
		);
		$query = new WP_Query($args);
		
		return $query->found_posts;
	}
}

function wcsearch_get_onsale_counter() {

	if (wcsearch_is_woo_active()) {
		$args = array(
				'post_type' => 'product',
				'post__in'  => wc_get_product_ids_on_sale(),
		);
		$query = new WP_Query($args);
		
		return $query->found_posts;
	}
}

function wcsearch_get_hours_counter($slug) {

	return 0;
}

function wcsearch_get_instock_counter() {

	$args = array(
			'post_type' => 'product',
	);
	$args['meta_query'][] = array(
			'relation' => 'OR',
			array(
					'key'     => '_stock_status',
					'value'   => 'outofstock',
					'compare' => '!=',
			),
			array(
					'key'     => '_stock_status',
					'compare' => 'NOT EXISTS',
			)
	);

	$query = new WP_Query($args);

	return $query->found_posts;
}

function wcsearch_get_search_forms_posts() {

	$posts = get_posts(array(
			'post_type' => WCSEARCH_FORM_TYPE,
			'status' => 'publish',
			'posts_per_page' => -1
	));

	$search_forms = array();
	foreach ($posts AS $post) {
		$title = $post->post_title;
		if (!$title) {
			$title = esc_html__("(no title)", "WCSEARCH");
		}
		
		$search_forms[$post->ID] = $title;
	}
	
	return $search_forms;
}

function wcsearch_hex2rgba($color, $opacity = false) {

	$default = 'rgb(0,0,0)';

	//Return default if no color provided
	if(empty($color))
		return $default;

	//Sanitize $color if "#" is provided
	if ($color[0] == '#' ) {
		$color = substr( $color, 1 );
	}
	
	//Check if color has 6 or 3 characters and get values
	if (strlen($color) == 6) {
		$hex = array( $color[0] . $color[1], $color[2] . $color[3], $color[4] . $color[5] );
	} elseif ( strlen( $color ) == 3 ) {
		$hex = array( $color[0] . $color[0], $color[1] . $color[1], $color[2] . $color[2] );
	} else {
		return $default;
	}

	//Convert hexadec to rgb
	$rgb =  array_map('hexdec', $hex);

	//Check if opacity is set(rgba or rgb)
	if (abs($opacity) > 1) {
		$opacity = 1.0;
	} elseif (abs($opacity) < 0) {
		$opacity = 0;
	}

	$output = 'rgba('.implode(',',$rgb).','.$opacity.')';

	//Return rgb(a) color string
	return $output;
}

function wcsearch_number_option_label($label) {
	return $label;
}

function wcsearch_get_params_from_string($str) {

	$result = array();

	$params_pairs = explode("&", $str);
	
	foreach ($params_pairs AS $pair) {
		if (list($key, $value) = explode("=", $pair)) {
			$result[$key] = trim($value, "'\"");
		}
	}

	return $result;
}

function wcsearch_get_tax_terms_from_query_string($tax, $query_string = array()) {

	if (!$query_string) {
		$query_string = wcsearch_get_query_string();
	}

	return wcsearch_get_tax_terms_from_args($tax, $query_string);
}

function wcsearch_get_tax_terms_from_args($tax, $args) {
	$query = false;
	$relation = false;
	
	// back compatibility
	if (empty($args[$tax]) && !empty($args['field_' . $tax])) {
		$tax = 'field_' . $tax;
	}
	
	if (!empty($args[$tax])) {
		if (is_array($args[$tax])) {
			$query = implode(",", $args[$tax]);
		} else {
			$query = urldecode($args[$tax]);
		}
		
		if (!empty($args[$tax.'_relation']) && in_array($args[$tax.'_relation'], array('OR', 'AND'))) {
			$relation = $args[$tax.'_relation'];
		}
	}

	if ($query) {
		return array('query' => $query, 'relation' => $relation);
	}
}

$counter_calls_count = array();

/**
 * build counter tag,
 * 
 * counter_number returns to autocomplete dropdown through 'renew_source' method
 * 
 * @param mix $item
 * @param string $counter_number
 * @return string
 */
function wcsearch_get_count($item, &$counter_number = false) {

	$counter_data = '';
	$counter_class = '';

	if (isset($item['price'])) {
		$counter_data = 'data-price="' . esc_attr($item['price']) . '"';
		$counter_class = 'wcsearch-item-price-' . $item['price'];
	}
	if (isset($item['term'])) {
		$term = $item['term'];

		$counter_data = 'data-termid="' . esc_attr($term->term_id) . '" data-tax="' . esc_attr($term->taxonomy) . '"';
		$counter_class = 'wcsearch-item-term-' . esc_attr($term->term_id) . '-' . esc_attr($term->taxonomy);
		
		if (!empty($item['mode']) && $item['mode'] == 'radios') {
			$counter_data .= ' data-termmode="radios"';
		}
	}
	if (isset($item['option'])) {
		$option = $item['option'];
		if (in_array($option, array('featured', 'instock', 'onsale'))) {
			$counter_data = 'data-option=' . esc_attr($option);
			$counter_class = 'wcsearch-item-option-' . esc_attr($option);
		}
	}
	if (isset($item['hours'])) {
		$counter_data = 'data-hours=' . esc_attr($item['hours']);
		$counter_class = 'wcsearch-item-hours-' . esc_attr($item['hours']);
	}
	if (isset($item['ratings'])) {
		$option = $item['ratings'];
		if (in_array($option, array('1', '2', '3', '4', '5'))) {
			$counter_data = 'data-ratings=' . esc_attr($option);
			$counter_class = 'wcsearch-item-ratings-' . esc_attr($option);
		}
	}

	$count = wcsearch_get_count_num($item);
	
	$counter_number = $count;
	
	if ($count !== false) {
		return '<span class="wcsearch-item-count ' . $counter_class . '" ' . $counter_data . '>' . esc_html($count) . '</span>';
	} else {
		$counter_class .= ' wcsearch-item-count-blur';
		return '<span class="wcsearch-item-count ' . $counter_class . '" ' . $counter_data . '>xx</span>';
	}
}
function wcsearch_get_count_num($item, $nolimit = false, $empty_query = false) {
	global $counter_calls_count, $get_count_num_flag;

	if ($empty_query) {
		$query_string = array();
	} else {
		$query_string = wcsearch_get_query_string();
	}

	if (isset($item['price'])) {
		$query_string['price'] = $item['price'];
		
		if (isset($counter_calls_count['price'])) {
			$counter_calls_count['price']++;
		} else {
			$counter_calls_count['price'] = 1;
		}
	}
	
	if (!$empty_query) {
		$_taxonomies = wcsearch_get_all_taxonomies();
		foreach ($_taxonomies AS $tax_name=>$tax_slug) {
			$taxonomies[$tax_name] = wcsearch_get_tax_terms_from_query_string($tax_slug);
		}
	}
	
	if (isset($item['term'])) {
		$term = $item['term'];
		
		if (isset($term->taxonomy)) {
			if (!empty($taxonomies) && wcsearch_getValue($taxonomies[$term->taxonomy], 'relation') == 'AND') {
				$taxonomies[$term->taxonomy]['query'] .= ','.$term->term_id;
			} else {
				$taxonomies[$term->taxonomy]['query'] = $term->term_id;
			}
			
			if (isset($counter_calls_count[$term->taxonomy])) {
				$counter_calls_count[$term->taxonomy]++;
			} else {
				$counter_calls_count[$term->taxonomy] = 1;
			}
			
			if (wp_doing_ajax()) {
				$limit_counts = 1000;
			} else {
				$limit_counts = 100;
			}
			// return this value anyway, even counter limit exceeded
			if (!$nolimit) {
				if ($counter_calls_count[$term->taxonomy] > $limit_counts) {
					return false;
				}
			}
		} else {
			return false;
		}
	}
	
	if (isset($item['option'])) {
		$option = $item['option'];
			
		switch ($option) {
			case 'featured':
				$query_string['featured'] = 1;
				break;
			case 'instock':
				$query_string['instock'] = 1;
				break;
			case 'onsale':
				$query_string['onsale'] = 1;
				break;
		}
	}
	
	if (isset($item['hours'])) {
		$option = $item['hours'];
		
		$query_string[$option] = 1;
	}
	
	if (isset($item['ratings'])) {
		$query_string['ratings'] = $item['ratings'];
	}

	$args = array_merge(array(
			'price' => '',
			'featured' => 0,
			'onsale' => 0,
			'instock' => 0,
			'orderby' => '',
			'order' => '',
			'keywords' => '',
			'page' => 1,
			'posts_per_page' => -1,
			'taxonomies' => $taxonomies,
			'ratings' => array(),
	), wcsearch_get_default_query(), $query_string);

	$args = apply_filters("wcsearch_get_count_num_args", $args);
	
	unset($args['wcsearch_test_form']);
	
	unset($args['num']);
	unset($args['perpage']);
	$args['onepage'] = 1;

	$hash = md5(json_encode($args));
	
	// find out used_by
	if (isset($item['used_by'])) {
		$used_by = $item['used_by'];
	} elseif (isset($item['term'])) {
		$term = $item['term'];
		if (isset($term->taxonomy)) {
			$used_by = apply_filters("wcsearch_get_used_by_by_tax", "wc", $term->taxonomy);
		}
	} else {
		$used_by = 'wc';
	}
	
	if (isset($item['hours'])) {
		$use_cache = 0;
	} else {
		$use_cache = 1;
	}
	$use_cache = apply_filters("wcsearch_use_cache", $use_cache);
	
	if ($use_cache) {
		global $wpdb, $wcsearch_cache;
		
		if (!$wcsearch_cache) {
			$results = $wpdb->get_results("SELECT hash, val FROM {$wpdb->wcsearch_cache}", ARRAY_A);
			$table = array();
			foreach ($results AS $row) {
				$table[$row['hash']] = $row['val'];
			}
			$wcsearch_cache = $table;
		}
		if (isset($wcsearch_cache[$hash])) {
			return $wcsearch_cache[$hash];
		}
		
		$val = $wpdb->get_var("SELECT val FROM {$wpdb->wcsearch_cache} WHERE hash='{$hash}'");
		
		//var_dump($args);
		
		if ($val !== null) {
			return $val;
		} else {
			$get_count_num_flag = true;
			
			$class_name = apply_filters("wcsearch_query_class_name", "wcsearch_query", $used_by);
			$wcsearch_query = new $class_name($args, true);
			
			$q_products = $wcsearch_query->get_query();
			
			$get_count_num_flag = false;
			
			$wpdb->query("INSERT INTO {$wpdb->wcsearch_cache} VALUES('{$hash}', '{$q_products->found_posts}') ");
			
			return $q_products->found_posts;
		}
	} else {
		$get_count_num_flag = true;

		$class_name = apply_filters("wcsearch_query_class_name", "wcsearch_query", $used_by);
		$wcsearch_query = new $class_name($args, true);
		//var_dump($args);
		
		$q_products = $wcsearch_query->get_query();
		//var_dump($q_products->request);
		
		$get_count_num_flag = false;
		
		return $q_products->found_posts;
	}
}	

function wcsearch_render_star($star_num, $value) {
		$sub = $value - $star_num;
		if ($sub >= 0 || abs($sub) <= 0.25) {
			return 'wcsearch-fa-star';
		}  elseif (abs($sub) >= 0.25 && abs($sub) <= 0.75) {
			return 'wcsearch-fa-star-half-o';
		} else {
			return 'wcsearch-fa-star-o';
		}
}

function wcsearch_render_avg_rating($value, $stars_color) {

	return wcsearch_renderTemplate('avg_rating.tpl.php', array('value' => $value, 'stars_color' => $stars_color));
}

function wcsearch_geocode_functions() {

	$options = array();

	if (defined('W2DC_VERSION') || defined('W2DCF_VERSION')) {
		if (get_option("w2dc_map_type") == 'none') {
			return false;
		}
	
		$options = array(
				'autocomplete_service' => 'w2dc_autocompleteService',
				'address_autocomplete_code' => get_option('w2dc_address_autocomplete_code'),
				'geocode_field' => 'w2dc_geocodeField',
				'dimension_unit' => get_option('w2dc_miles_kilometers_in_search'),
		);
	}
	if (defined('W2GM_VERSION')) {
		$options = array(
				'autocomplete_service' => 'w2gm_autocompleteService',
				'address_autocomplete_code' => get_option('w2gm_address_autocomplete_code'),
				'geocode_field' => 'w2gm_geocodeField',
				'dimension_unit' => get_option('w2gm_miles_kilometers_in_search'),
		);
	}
	if (defined('W2MB_VERSION')) {
		$options = array(
				'autocomplete_service' => 'w2mb_autocompleteService',
				'address_autocomplete_code' => get_option('w2mb_address_autocomplete_code'),
				'geocode_field' => 'w2mb_geocodeField',
				'dimension_unit' => get_option('w2mb_miles_kilometers_in_search'),
		);
	}
	
	if (!$options) {
		return false;
	}
	
	$options['my_location_button'] = esc_html__('My Location', 'WCSEARCH');
	$options['my_location_button_error'] = esc_html__('GeoLocation service does not work on your device!', 'WCSEARCH');
	
	return $options;
}

function wcsearch_get_all_taxonomies() {

	$taxonomies = apply_filters("wcsearch_get_taxonomies", array());
	
	return $taxonomies;
}

function wcsearch_get_all_taxonomies_names() {

	$taxonomies_names = apply_filters("wcsearch_get_taxonomies_names", array());
	
	return $taxonomies_names;
}


function wcsearch_wrapper_get_taxonomies($args, $output = 'objects') {

	if (isset($args['name'])) {
		$tax_name = $args['name'];
	}
	
	$select_fields = apply_filters("wcsearch_select_fields", array());
	
	if (in_array($tax_name, $select_fields)) {

		$taxonomy = false;

		$content_field = apply_filters("wcsearch_get_select_field", null, $tax_name);
		
		if ($content_field) {
			$taxonomy = new stdClass();
			$taxonomy->labels = new stdClass();
			$taxonomy->labels->singular_name = $content_field->name;
			$taxonomy->labels->name = $content_field->name;
			$taxonomy->label = $content_field->name;
		}
		
		return array($tax_name => $taxonomy);
	} else {
		return get_taxonomies($args, $output);
	}
}

function wcsearch_wrapper_get_taxonomy($tax_name) {
	
	$select_fields = apply_filters("wcsearch_select_fields", array());
	
	if (in_array($tax_name, $select_fields)) {

		$content_field = apply_filters("wcsearch_get_select_field", null, $tax_name);
		
		if ($content_field) {
			$taxonomy = new stdClass();
			$taxonomy->labels = new stdClass();
			$taxonomy->labels->singular_name = $content_field->name;
			$taxonomy->labels->name = $content_field->name;
			$taxonomy->label = $content_field->name;
		}

		return $taxonomy;
	} else {
		return get_taxonomy($tax_name);
	}
}

function wcsearch_get_category_parents($id, $tax, &$chain = array()) {

	$parent = get_term($id, $tax);
	
	if (is_wp_error($parent) || !$parent) {
		return array();
	}

	$name = $parent->name;
	
	$chain[] = $name;

	if ($parent->parent && ($parent->parent != $parent->term_id)) {
		wcsearch_get_category_parents($parent->parent, $tax, $chain);
	}
	
	return $chain;
}

function wcsearch_wrapper_get_categories($categories_options) {

	$tax_name = $categories_options['taxonomy'];

	$select_fields = apply_filters("wcsearch_select_fields", array());
	
	if (in_array($tax_name, $select_fields)) {

		if (isset($categories_options['parent']) && $categories_options['parent'] != 0) {
			return array();
		}

		$selection_items = array();
		
		$content_field = apply_filters("wcsearch_get_select_field", null, $tax_name);
		
		if ($content_field) {
			if ($content_field->selection_items) {
				foreach ($content_field->selection_items AS $key=>$selection_item) {

					if (!empty($categories_options['exact_terms'])) {
						if (!in_array($key, $categories_options['exact_terms']) && !in_array($selection_item, $categories_options['exact_terms'])) {
							continue;
						}
					}

					$selection_item_obj = new stdClass();
					$selection_item_obj->term_id = $key;
					$selection_item_obj->slug = $selection_item;
					$selection_item_obj->name = $selection_item;
					$selection_item_obj->taxonomy = $tax_name;
					$selection_item_obj->is_select = true;
					
					$item['term'] = $selection_item_obj;
					$selection_item_obj->count = wcsearch_get_count_num($item, true, true);
					
					if (wcsearch_getValue($categories_options, 'hide_empty')) {
						if ($selection_item_obj->count) {
							$selection_items[] = $selection_item_obj;
						}
					} else {
						$selection_items[] = $selection_item_obj;
					}
				}
				
				if (wcsearch_getValue($categories_options, 'orderby') == 'name') {
					global $wcsearch_selection_items_order;
					$wcsearch_selection_items_order = wcsearch_getValue($categories_options, 'order');
					usort($selection_items, function ($a, $b) {
						global $wcsearch_selection_items_order;
						
						if ($wcsearch_selection_items_order == 'ASC') {
							return strcasecmp($a->name, $b->name);
						} else {
							return strcasecmp($b->name, $a->name);
						}
					});
				} elseif (wcsearch_getValue($categories_options, 'orderby') == 'count') {
					global $wcsearch_selection_items_order;
					$wcsearch_selection_items_order = wcsearch_getValue($categories_options, 'order');
					usort($selection_items, function ($a, $b) {
						global $wcsearch_selection_items_order;
							
						if ($wcsearch_selection_items_order == 'ASC') {
							if ($a->count == $b->count) {
								return 0;
							}
							return ($a->count > $b->count) ? 1 : -1;
						} else {
							if ($a->count == $b->count) {
								return 0;
							}
							return ($a->count < $b->count) ? 1 : -1;
						}
					});
				}
			}
		}
		
		return $selection_items;
	} else {
		$options = $categories_options;
		$options['pad_counts'] = true;
		$options['hide_empty'] = false;
		
		$terms = get_categories($options);
		
		foreach ($terms AS $key=>$term) {

			if (isset($options['depth'])) {

				$chain = array();

				wcsearch_get_category_parents($term->term_id, $term->taxonomy, $chain);
				
				if (count($chain) > $options['depth']) {
					unset($terms[$key]);
					
					continue;
				}
			}

			$item['term'] = $term;
			
			if (!empty($categories_options['exact_terms']) && !in_array($term->term_id, $categories_options['exact_terms']) && !in_array($term->slug, $categories_options['exact_terms'])) {
				unset($terms[$key]);
				
				continue;
			}
			
			$term->count = wcsearch_get_count_num($item, true, true);
			
			if (wcsearch_getValue($categories_options, 'hide_empty')) {
				if (!$term->count) {
					unset($terms[$key]);
				}
			}
		}
		
		$orderby = wcsearch_getValue($categories_options, 'orderby');
		if ($orderby == 'name') {
			global $wcsearch_selection_items_order;
			$wcsearch_selection_items_order = wcsearch_getValue($categories_options, 'order');
			usort($terms, function ($a, $b) {
				global $wcsearch_selection_items_order;
					
				if ($wcsearch_selection_items_order == 'ASC') {
					return strcasecmp($a->name, $b->name);
				} else {
					return strcasecmp($b->name, $a->name);
				}
			});
		} elseif ($orderby == 'count') {
			global $wcsearch_selection_items_order;
			$wcsearch_selection_items_order = wcsearch_getValue($categories_options, 'order');
			usort($terms, function ($a, $b) {
				global $wcsearch_selection_items_order;
					
				if ($wcsearch_selection_items_order == 'ASC') {
					if ($a->count == $b->count) {
						return 0;
					}
					return ($a->count > $b->count) ? 1 : -1;
				} else {
					if ($a->count == $b->count) {
						return 0;
					}
					return ($a->count < $b->count) ? 1 : -1;
				}
			});
		}
		
		return $terms;
	}
}

function wcsearch_wrapper_get_term($term_id, $tax_name = '') {

	$select_fields = apply_filters("wcsearch_select_fields", array());
	
	if ($tax_name && in_array($tax_name, $select_fields)) {

		$selection_item_obj = null;
		
		$content_field = apply_filters("wcsearch_get_select_field", null, $tax_name);
		
		if ($content_field) {
			if ($content_field->selection_items) {
				foreach ($content_field->selection_items AS $key=>$selection_item) {
					if ($term_id == $key) {
						$selection_item_obj = new stdClass();
						$selection_item_obj->term_id = $key;
						$selection_item_obj->slug = $selection_item;
						$selection_item_obj->name = $selection_item;
						$selection_item_obj->parent = 0;
						$selection_item_obj->taxonomy = $tax_name;
						$selection_item_obj->is_select = true;
					}
				}
			}
		}
		
		return $selection_item_obj;
	} else {
		return get_term($term_id, $tax_name);
	}
}

function wcsearch_wrapper_get_term_by_slug($term_slug, $tax_name = '') {

	$select_fields = apply_filters("wcsearch_select_fields", array());
	
	if ($tax_name && in_array($tax_name, $select_fields)) {

		$selection_item_obj = null;
		
		$content_field = apply_filters("wcsearch_get_select_field", null, $tax_name);
		
		if ($content_field) {
			if ($content_field->selection_items) {
				foreach ($content_field->selection_items AS $key=>$selection_item) {
					if ($term_slug == $selection_item) {
						$selection_item_obj = new stdClass();
						$selection_item_obj->term_id = $key;
						$selection_item_obj->slug = $selection_item;
						$selection_item_obj->name = $selection_item;
						$selection_item_obj->parent = 0;
						$selection_item_obj->taxonomy = $tax_name;
						$selection_item_obj->is_select = true;
					}
				}
			}
		}
		
		return $selection_item_obj;
	} else {
		return get_term_by("slug", $term_slug, $tax_name);
	}
}

function wcsearch_getDateFormat() {
	$wp_date_format = get_option('date_format');

	if (!$wp_date_format) {
		$wp_date_format = "d/m/Y";
	}

	return $wp_date_format;
}

function wcsearch_getDatePickerFormat() {
	$wp_date_format = wcsearch_getDateFormat();
	
	return str_replace(
			array('S',  'd', 'j',  'l',  'm', 'n',  'F',  'Y'),
			array('',  'dd', 'd', 'DD', 'mm', 'm', 'MM', 'yy'),
		$wp_date_format);
}

function wcsearch_getDatePickerLangCode($locale) {

	return apply_filters("wcsearch_get_datepicker_lang_code", $locale);
}

function wcsearch_print_datepickers_code($params) {
	extract($params);
	
	$index = wcsearch_generateRandomVal();
	
	$dateformat = wcsearch_getDatePickerFormat();
	
	if ($values) {
		$values = explode("-", $values);
		$start_value = $values[0];
		$end_value = $values[1];
	} else {
		$start_value = false;
		$end_value = false;
	}
	?>
	<script>
	(function($) {
		"use strict";
	
		$(function() {

			$('body').on("reset", "input[name=<?php echo $slug; ?>]", function() {
				$("#reset-date-max").trigger("click");
				$("#reset-date-min").trigger("click");
			});
			
			$("#wcsearch-field-input-<?php echo $index; ?>-min").datepicker({
				changeMonth: true,
				changeYear: true,
				<?php if (function_exists('is_rtl') && is_rtl()): ?>isRTL: true,<?php endif; ?>
					showButtonPanel: true,
					dateFormat: '<?php echo $dateformat; ?>',
					firstDay: <?php echo intval(get_option('start_of_week')); ?>,
					onSelect: function(dateText) {
						var tmstmp_str;
						var sDate = $("#wcsearch-field-input-<?php echo $index; ?>-min").datepicker("getDate");
						var set_min_date = $("#wcsearch-field-input-<?php echo $index; ?>-min").datepicker("getDate");
						if (sDate) {
							sDate.setMinutes(sDate.getMinutes() - sDate.getTimezoneOffset());
							tmstmp_str = $.datepicker.formatDate('@', sDate)/1000;
						} else {
							tmstmp_str = "";
						}
						$("#wcsearch-field-input-<?php echo $index; ?>-max").datepicker('option', 'minDate', set_min_date);

						var rDate = $("input[name=<?php echo $slug; ?>]").val().split("-");
						$("input[name=<?php echo $slug; ?>]").val(tmstmp_str+"-"+rDate[1]);

						$("input[name=<?php echo $slug; ?>]").trigger("change");
					}
			});
			<?php
			if ($lang_code = wcsearch_getDatePickerLangCode(get_locale())): ?>
			$("#wcsearch-field-input-<?php echo $index; ?>-min").datepicker($.datepicker.regional[ "<?php echo $lang_code; ?>" ]);
			<?php endif; ?>
		
			$("#wcsearch-field-input-<?php echo $index; ?>-max").datepicker({
					changeMonth: true,
					changeYear: true,
					showButtonPanel: true,
					dateFormat: '<?php echo $dateformat; ?>',
					firstDay: <?php echo intval(get_option('start_of_week')); ?>,
					onSelect: function(dateText) {
						var tmstmp_str;
						var sDate = $("#wcsearch-field-input-<?php echo $index; ?>-max").datepicker("getDate");
						var set_max_date = $("#wcsearch-field-input-<?php echo $index; ?>-max").datepicker("getDate");
						if (sDate) {
							sDate.setMinutes(sDate.getMinutes() - sDate.getTimezoneOffset());
							tmstmp_str = $.datepicker.formatDate('@', sDate)/1000;
						} else {
							tmstmp_str = "";
						}
						$("#wcsearch-field-input-<?php echo $index; ?>-min").datepicker('option', 'maxDate', set_max_date);

						var rDate = $("input[name=<?php echo $slug; ?>]").val().split("-");
						$("input[name=<?php echo $slug; ?>]").val(rDate[0]+"-"+tmstmp_str);

						$("input[name=<?php echo $slug; ?>]").trigger("change");
					}
			});
			<?php
			if ($lang_code = wcsearch_getDatePickerLangCode(get_locale())): ?>
			$("#wcsearch-field-input-<?php echo $index; ?>-max").datepicker($.datepicker.regional[ "<?php echo $lang_code; ?>" ]);
			<?php endif; ?>
		
			<?php if ($end_value): ?>
			$("#wcsearch-field-input-<?php echo $index; ?>-max").datepicker('setDate', $.datepicker.parseDate('dd/mm/yy', '<?php echo date('d/m/Y', $end_value); ?>'));
			$("#wcsearch-field-input-<?php echo $index; ?>-min").datepicker('option', 'maxDate', $("#wcsearch-field-input-<?php echo $index; ?>-max").datepicker('getDate'));
			<?php endif; ?>
			$("body").on("click", "#reset-date-max", function() {
				$.datepicker._clearDate('#wcsearch-field-input-<?php echo $index; ?>-max');
			})
		
			<?php if ($start_value): ?>
			$("#wcsearch-field-input-<?php echo $index; ?>-min").datepicker('setDate', $.datepicker.parseDate('dd/mm/yy', '<?php echo date('d/m/Y', $start_value); ?>'));
			$("#wcsearch-field-input-<?php echo $index; ?>-max").datepicker('option', 'minDate', $("#wcsearch-field-input-<?php echo $index; ?>-min").datepicker('getDate'));
			<?php endif; ?>
			$("body").on("click", "#reset-date-min", function() {
				$.datepicker._clearDate('#wcsearch-field-input-<?php echo $index; ?>-min');
			})
		});
	})(jQuery);
	</script>
		
	<div class="wcsearch-date-input-wrapper wcsearch-date-input-wrapper-<?php echo esc_attr($view); ?>">
		<div class="wcsearch-date-input-field">
			<div class="wcsearch-has-feedback">
				<input type="text" class="wcsearch-form-control" id="wcsearch-field-input-<?php echo $index; ?>-min" placeholder="<?php echo esc_attr($placeholder_start); ?>" />
				<span class="wcsearch-form-control-feedback wcsearch-fa wcsearch-fa-calendar"></span>
			</div>
			<input type="button" class="wcsearch-date-reset-button wcsearch-btn wcsearch-btn-primary" id="reset-date-min" value="<?php echo esc_attr($reset_label_text)?>" />
		</div>
		<div class="wcsearch-date-input-field">
			<div class="wcsearch-has-feedback">
				<input type="text" class="wcsearch-form-control" id="wcsearch-field-input-<?php echo $index; ?>-max" placeholder="<?php echo esc_attr($placeholder_end); ?>" />
				<span class="wcsearch-form-control-feedback wcsearch-fa wcsearch-fa-calendar"></span>
			</div>
			<input type="button" class="wcsearch-date-reset-button wcsearch-btn wcsearch-btn-primary" id="reset-date-max" value="<?php echo esc_attr($reset_label_text)?>" />
		</div>
		<input type="hidden" name="<?php echo esc_attr($slug); ?>" class="wcsearch-date-input" value="<?php echo esc_attr($start_value) . "-" . esc_attr($end_value); ?>" />
	</div>
<?php
}

function wcsearch_wrap_keywords_examples($example) {
	$example = esc_html(trim($example));
	if ($example) {
		return "<a href=\"javascript:void(0);\">{$example}</a>";
	}
}

function wcsearch_print_suggestions_code($try_to_search_text, $suggestions) {
	if ($suggestions) {
		$examples = explode(',', $suggestions);
		$wrapped = array_map(
				"wcsearch_wrap_keywords_examples",
				$examples
		);
		$suggestions = implode(', ', $wrapped);
	?>
	<p class="wcsearch-search-suggestions">
		<?php echo (esc_html__("Try to search", "WCSEARCH") != 'Try to search') ? esc_html__("Try to search", "WCSEARCH") : $try_to_search_text; ?>
		<?php $suggestions = explode(',', $suggestions); ?>
		<?php foreach ($suggestions AS $label): ?>
		<label><?php echo wp_kses($label, array('a' => array('href' => array())), array('javascript')); ?></label>
		<?php endforeach; ?>
	</p>
	<?php
	}
}

function wcsearch_get_term_option($terms_options_str, $term_id, $field) {

	$terms_options = json_decode($terms_options_str, true);
	
	if (isset($terms_options[$term_id][$field])) {
		return $terms_options[$term_id][$field];
	}
}

function wcsearch_get_luma_color($color) {
	$color = substr($color,1);
	$r = hexdec(substr($color,0,2));
	$g = hexdec(substr($color,2,2));
	$b = hexdec(substr($color,4,2));
	

	$luma = 0.2126 * $r + 0.7152 * $g + 0.0722 * $b; // per ITU-R BT.709

	return $luma;
}

?>