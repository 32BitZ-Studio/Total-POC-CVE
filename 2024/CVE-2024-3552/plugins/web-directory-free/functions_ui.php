<?php

function w2dc_tax_dropdowns_menu_init($params) {
	$attrs = array_merge(array(
			'uID' => 0,
			'field_name' => '',
			'count' => true,
			'tax' => 'category',
			'hide_empty' => false,
			'exact_terms' => array(),
			'autocomplete_field' => '',
			'autocomplete_field_value' => '',
			'autocomplete_ajax' => false,
			'placeholder' => '',
			'depth' => 1,
			'term_id' => 0,
			'directory_id' => false,
	), $params);
	extract($attrs);
	
	// unique ID need when we place some dropdowns groups on one page
	if (!$uID) {
		$uID = rand(1, 10000);
	}
	
	if (!$field_name) {
		$field_name = 'selected_tax[' . $uID . ']';
	}
	
	// we use array_merge with empty array because we need to flush keys in terms array
	if ($count) {
		$terms = array_merge(
				// there is a wp bug with pad_counts in get_terms function - so we use this construction
				wp_list_filter(
						get_categories(array(
								'taxonomy' => $tax,
								//'pad_counts' => true,
								'hide_empty' => $hide_empty,
						)),
						array('parent' => 0)
				), array());
	} else {
		$terms = array_merge(
				get_categories(array(
						'taxonomy' => $tax,
						//'pad_counts' => true,
						'hide_empty' => $hide_empty,
						'parent' => 0,
				)), array());
	}
	
	// show terms and/or autocomplete search field
	if ($terms || $autocomplete_field) {
		foreach ($terms AS $id=>$term) {
			if ($exact_terms && (!in_array($term->term_id, $exact_terms) && !in_array($term->slug, $exact_terms))) {
				unset($terms[$id]);
			}
		}
		
		// when selected exact sub-categories of non-root category
		if (empty($terms) && !empty($exact_terms)) {
			if ($count) {
				// there is a wp bug with pad_counts in get_terms function - so we use this construction
				$terms = wp_list_filter(get_categories(array('taxonomy' => $tax, 'include' => $exact_terms, /* 'pad_counts' => true, */ 'hide_empty' => $hide_empty)));
			} else {
				$terms = get_categories(array('taxonomy' => $tax, 'include' => $exact_terms, /* 'pad_counts' => true, */ 'hide_empty' => $hide_empty));
			}
		}
		
		$selected_tax_text = '';
		if ($term_id) {
			if ($term = get_term($term_id)) {
				$selected_tax_text = $term->name;
				$parents = w2dc_get_term_parents($term_id, $tax, false, false, ', ');
				if ($parents) {
					$selected_tax_text .= ', ' . $parents;
				}
			}
		}
		
		echo '<div id="w2dc-tax-dropdowns-wrap-' . $uID . '" class="w2dc-tax-dropdowns-wrap">';
		echo '<input type="hidden" name="' . $field_name . '" id="selected_tax[' . $uID . ']" class="selected_tax_' . $tax . '" value="' . $term_id . '" />';
		echo '<input type="hidden" name="' . $field_name . '_text" id="selected_tax_text[' . $uID . ']" class="selected_tax_text_' . $tax . '" value="' . $selected_tax_text . '" />';
		if ($exact_terms) {
			echo '<input type="hidden" id="exact_terms[' . $uID . ']" value="' . addslashes(implode(',', $exact_terms)) . '" />';
		}
		if ($autocomplete_field) {
			$autocomplete_data = 'data-autocomplete-name="' . esc_attr($autocomplete_field) . '" data-autocomplete-value="' . esc_attr($autocomplete_field_value) . '"';
			if ($autocomplete_ajax) {
				$autocomplete_data .= ' data-ajax-search=1';
			}
		} else {
			$autocomplete_data = '';
		}
		echo '<select class="w2dc-form-control w2dc-selectmenu-' . $tax . '" data-id="' . $uID . '" data-placeholder="' . esc_attr($placeholder) . '" ' . $autocomplete_data . ' data-default-icon="' . w2dc_getDefaultTermIconUrl($tax) . '">';
		foreach ($terms AS $term) {
			if ($count) {
				$term_count = 'data-count="' . w2dc_getTermCount($term->term_id, $directory_id) . ' ' . _n("result", "results", w2dc_getTermCount($term->term_id, $directory_id), "W2DC") . '"';
			} else {
				$term_count = '';
			}
			if ($term->term_id == $term_id) {
				$selected = 'data-selected="selected"';
			} else {
				$selected = '';
			}
			if ($icon_file = w2dc_getTermIconUrl($term->term_id)) {
				$icon = 'data-icon="' . $icon_file . '"';
			} else {
				$icon = 'data-icon="' . w2dc_getDefaultTermIconUrl($tax) . '"';
			}

			echo '<option id="' . $term->slug . '" value="' . $term->term_id . '" data-name="' . $term->name  . '" data-sublabel="" ' . $selected . ' ' . $icon . ' ' . $term_count . '>' . $term->name . '</option>';
			if ($depth > 1) {
				echo _w2dc_tax_dropdowns_menu($tax, $term->term_id, $depth, 1, $term_id, $count, $exact_terms, $hide_empty, $directory_id);
			}
		}
		echo '</select>';
		echo '</div>';
	}
}

function _w2dc_tax_dropdowns_menu($tax, $parent = 0, $depth = 2, $current_level = 1, $term_id = null, $count = false, $exact_terms = array(), $hide_empty = false, $directory_id = false) {
	if ($count) {
		// there is a wp bug with pad_counts in get_terms function - so we use this construction
		$terms = wp_list_filter(
				get_categories(array(
						'taxonomy' => $tax,
						//'pad_counts' => true,
						'hide_empty' => $hide_empty,
				)),
				array('parent' => $parent)
		);
	} else {
		$terms = get_categories(array(
				'taxonomy' => $tax,
				//'pad_counts' => true,
				'hide_empty' => $hide_empty,
				'parent' => $parent,
		));
	}
	
	$html = '';
	if ($terms && ($depth == 0 || !is_numeric($depth) || $depth > $current_level)) {
		foreach ($terms AS $key=>$term) {
			if ($exact_terms && (!in_array($term->term_id, $exact_terms) && !in_array($term->slug, $exact_terms))) {
				unset($terms[$key]);
			}
		}
	
		if ($terms) {
			$current_level++;
			
			$sublabel = w2dc_get_term_parents($term->parent, $tax, false, false, ', ');

			foreach ($terms AS $term) {
				
				$term_count = '';
				if ($count) {
					$term_count = 'data-count="' . w2dc_getTermCount($term->term_id, $directory_id) . ' ' . _n("result", "results", w2dc_getTermCount($term->term_id, $directory_id), "W2DC") . '"';
				}
				
				$selected = '';
				if ($term->term_id == $term_id) {
					$selected = 'data-selected="selected"';
				}
				
				$icon = '';
				if ($icon_file = w2dc_getTermIconUrl($term->term_id)) {
					$icon = 'data-icon="' . $icon_file . '"';
				}
			
				echo '<option id="' . $term->slug . '" value="' . $term->term_id . '" data-name="' . $term->name  . '" data-sublabel="' . $sublabel . '" ' . $selected . ' ' . $icon . ' ' . $term_count . '>' . $term->name . '</option>';
				if ($depth > $current_level) {
					echo _w2dc_tax_dropdowns_menu($tax, $term->term_id, $depth, $current_level, $term_id, $count, $exact_terms, $hide_empty, $directory_id);
				}
			}
		}
	}
	return $html;
}

function w2dc_tax_dropdowns_init($args) {
	$tax = w2dc_getValue($args, 'tax', 'category');
	$field_name = w2dc_getValue($args, 'field_name');
	$term_id = w2dc_getValue($args, 'term_id');
	$count = w2dc_getValue($args, 'count', true);
	$labels = w2dc_getValue($args, 'labels', array());
	$titles = w2dc_getValue($args, 'titles', array());
	$allow_add_term = w2dc_getValue($args, 'allow_add_term', array());
	$uID = w2dc_getValue($args, 'uID');
	$exact_terms = w2dc_getValue($args, 'exact_terms', array());
	$hide_empty = w2dc_getValue($args, 'hide_empty', false);
	$directory_id = w2dc_getValue($args, 'directory_id', false);
	
	// unique ID need when we place some dropdowns groups on one page
	if (!$uID) {
		$uID = rand(1, 10000);
	}

	$localized_data[$uID] = array(
			'labels'      => $labels,
			'titles'      => $titles,
			'allow_add_term' => $allow_add_term,
	);
	echo "<script>w2dc_js_objects['tax_dropdowns_" . $uID . "'] = " . json_encode($localized_data) . "</script>";

	if (!is_null($term_id) && $term_id != 0) {
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
	}
	$chain[] = 0;
	$chain = array_reverse($chain);

	if (!$field_name) {
		$field_name = 'selected_tax[' . $uID . ']';
	}

	echo '<div id="w2dc-tax-dropdowns-wrap-' . $uID . '" class="' . $tax . ' cs_count_' . (int)$count . ' cs_hide_empty_' . (int)$hide_empty . ' w2dc-tax-dropdowns-wrap">';
	echo '<input type="hidden" name="' . $field_name . '" id="selected_tax[' . $uID . ']" class="selected_tax_' . $tax . '" value="' . $term_id . '" />';
	echo '<input type="hidden" id="exact_terms[' . $uID . ']" value="' . addslashes(implode(',', $exact_terms)) . '" />';
	foreach ($chain AS $key=>$term_id) {
		if ($count) {
			// there is a wp bug with pad_counts in get_terms function - so we use this construction
			$terms = wp_list_filter(get_categories(array('taxonomy' => $tax, 'pad_counts' => true, 'hide_empty' => $hide_empty)), array('parent' => $term_id));
		} else {
			$terms = get_categories(array('taxonomy' => $tax, /* 'pad_counts' => true, */ 'hide_empty' => $hide_empty, 'parent' => $term_id));
		}

		if (!empty($terms)) {
			foreach ($terms AS $id=>$term) {
				if ($exact_terms && (!in_array($term->term_id, $exact_terms) && !in_array($term->slug, $exact_terms))) {
					unset($terms[$id]);
				}
			}

			// when selected exact sub-categories of non-root category
			if (empty($terms) && !empty($exact_terms)) {
				if ($count) {
					// there is a wp bug with pad_counts in get_terms function - so we use this construction
					$terms = wp_list_filter(get_categories(array('taxonomy' => $tax, 'include' => $exact_terms, /* 'pad_counts' => true, */ 'hide_empty' => $hide_empty)));
				} else {
					$terms = get_categories(array('taxonomy' => $tax, 'include' => $exact_terms, /* 'pad_counts' => true, */ 'hide_empty' => $hide_empty));
				}
			}

			if (!empty($terms)) {
				$level_num = $key + 1;
				echo '<div id="wrap_chainlist_' . $level_num . '_' .$uID . '" class="w2dc-row w2dc-form-group w2dc-location-input w2dc-location-chainlist">';
				
					$label_name = '';
					if (isset($labels[$key])) {
						$label_name = $labels[$key];
					}
					echo '<div class="w2dc-col-md-2">';
					echo '<label class="w2dc-control-label" for="chainlist_' . $level_num . '_' . $uID . '">' . $label_name . '</label>';
					echo '</div>';
	
					if (isset($labels[$key])) {
					echo '<div class="w2dc-col-md-10">';
					} else {
					echo '<div class="w2dc-col-md-12">';
					}
						echo '<select id="chainlist_' . $level_num . '_' . $uID . '" class="w2dc-form-control w2dc-selectmenu">';
						echo '<option value="">- ' . ((isset($titles[$key])) ? $titles[$key] : __('Select term', 'W2DC')) . ' -</option>';
						foreach ($terms AS $term) {
							if ($count)
								$term_count = " (" . w2dc_getTermCount($term->term_id, $directory_id) . ")";
							else
								 $term_count = '';
							if (isset($chain[$key+1]) && $term->term_id == $chain[$key+1]) {
								$selected = 'selected';
							} else
								$selected = '';
									
							if ($icon_file = w2dc_getTermIconUrl($term->term_id))
								$icon = 'data-class="term-icon" data-icon="' . $icon_file . '"';
							else
								$icon = '';
	
							echo '<option id="' . $term->slug . '" value="' . $term->term_id . '" ' . $selected . ' ' . $icon . '>' . $term->name . $term_count . '</option>';
						}
						echo '</select>';
						
						if (!empty($allow_add_term[$key])) {
							echo '<a class="w2dc-add-term-link" data-tax="' . $tax . '" data-parent="' . $term_id . '" data-uid="' . $uID . '" data-nonce="' . wp_create_nonce('w2dc_add_term_nonce') . '" data-exact-terms="' . implode(',', $exact_terms) . '" href="javascript:void(0);">' . sprintf(esc_html__('Add %s', 'W2DC'), $label_name) . '</a>';
						}
					echo '</div>';
				echo '</div>';
			}
		} else {
			if (isset($labels[$key])) {
				$label_name = $labels[$key];
			
				$level_num = $key + 1;
				
				if (!empty($allow_add_term[$key])) {
					echo '<div id="wrap_chainlist_' . $level_num . '_' .$uID . '" class="w2dc-row w2dc-form-group w2dc-location-input w2dc-location-chainlist">';
						echo '<div class="w2dc-col-md-10 w2dc-col-md-offset-2">';
						echo '<a class="w2dc-add-term-link" data-tax="' . $tax . '" data-parent="' . $term_id . '" data-uid="' . $uID . '" data-nonce="' . wp_create_nonce('w2dc_add_term_nonce') . '" data-exact-terms="' . implode(',', $exact_terms) . '" href="javascript:void(0);">' . sprintf(esc_html__('Add %s', 'W2DC'), $label_name) . '</a>';
						echo '</div>';
					echo '</div>';
				}
			}
		}
	}
	echo '</div>';
}

function w2dc_tax_dropdowns_updateterms() {
	$parentid = w2dc_getValue($_POST, 'parentid');
	$next_level = w2dc_getValue($_POST, 'next_level');
	$tax = w2dc_getValue($_POST, 'tax');
	$count = w2dc_getValue($_POST, 'count');
	$hide_empty = w2dc_getValue($_POST, 'hide_empty');
	$exact_terms = array_filter(explode(',', w2dc_getValue($_POST, 'exact_terms')));
	if (!$label = w2dc_getValue($_POST, 'label'))
		$label = '';
	if (!$title = w2dc_getValue($_POST, 'title'))
		$title = __('Select term', 'W2DC');
	$allow_add_term = w2dc_getValue($_POST, 'allow_add_term');
	$uID = w2dc_getValue($_POST, 'uID');
	$directory_id = w2dc_getValue($_POST, 'directory_id', false);
	
	if ($hide_empty == 'cs_hide_empty_1') {
		$hide_empty = true;
	} else {
		$hide_empty = false;
	}

	if ($count == 'cs_count_1') {
		// there is a wp bug with pad_counts in get_terms function - so we use this construction
		$terms = wp_list_filter(get_categories(array('taxonomy' => $tax, /* 'pad_counts' => true, */ 'hide_empty' => $hide_empty)), array('parent' => $parentid));
	} else {
		$terms = get_categories(array('taxonomy' => $tax, /* 'pad_counts' => true, */ 'hide_empty' => $hide_empty, 'parent' => $parentid));
	}
	if (!empty($terms)) {
		foreach ($terms AS $id=>$term) {
			if ($exact_terms && (!in_array($term->term_id, $exact_terms) && !in_array($term->slug, $exact_terms))) {
				unset($terms[$id]);
			}
		}

		if (!empty($terms)) {
			echo '<div id="wrap_chainlist_' . $next_level . '_' . $uID . '" class="w2dc-row w2dc-form-group w2dc-location-input w2dc-location-chainlist">';
	
				if ($label) {
					echo '<div class="w2dc-col-md-2">';
					echo '<label class="w2dc-control-label" for="chainlist_' . $next_level . '_' . $uID . '">' . $label . '</label>';
					echo '</div>';
				}
	
				if ($label) {
				echo '<div class="w2dc-col-md-10">';
				} else { 
				echo '<div class="w2dc-col-md-12">';
				}
					echo '<select id="chainlist_' . $next_level . '_' . $uID . '" class="w2dc-form-control w2dc-selectmenu">';
					echo '<option value="">- ' . $title . ' -</option>';
					foreach ($terms as $term) {
						if (!$exact_terms || (in_array($term->term_id, $exact_terms) || in_array($term->slug, $exact_terms))) {
							if ($count == 'cs_count_1') {
								$term_count = " (" . w2dc_getTermCount($term->term_id, $directory_id) . ")";
							} else {
								$term_count = '';
							}
							
							if ($icon_file = w2dc_getTermIconUrl($term->term_id))
								$icon = 'data-class="term-icon" data-icon="' . $icon_file . '"';
							else
								$icon = '';
							
							echo '<option id="' . $term->slug . '" value="' . $term->term_id . '" ' . $icon . '>' . $term->name . $term_count . '</option>';
						}
					}
					echo '</select>';
					
					if ($allow_add_term) {
						echo '<a class="w2dc-add-term-link" data-tax="' . $tax . '" data-parent="' . $parentid . '" data-uid="' . $uID . '" data-nonce="' . wp_create_nonce('w2dc_add_term_nonce') . '" data-exact-terms="' . implode(',', $exact_terms) . '" href="javascript:void(0);">' . sprintf(esc_html__('Add %s', 'W2DC'), $label) . '</a>';
					}
				echo '</div>';
			echo '</div>';
		}
	} elseif ($label) {
		if ($allow_add_term) {
			echo '<div id="wrap_chainlist_' . $next_level . '_' . $uID . '" class="w2dc-row w2dc-form-group w2dc-location-input w2dc-location-chainlist">';
				echo '<div class="w2dc-col-md-10 w2dc-col-md-offset-2">';
				echo '<a class="w2dc-add-term-link" data-tax="' . $tax . '" data-parent="' . $parentid . '" data-uid="' . $uID . '" data-nonce="' . wp_create_nonce('w2dc_add_term_nonce') . '" data-exact-terms="' . implode(',', $exact_terms) . '" href="javascript:void(0);">' . sprintf(esc_html__('Add %s', 'W2DC'), $label) . '</a>';
				echo '</div>';
			echo '</div>';
		}
	}
	
	die();
}

function w2dc_renderOptionsTerms($tax, $parent, $selected_terms, $level = 0) {
	$terms = get_terms($tax, array('parent' => $parent, 'hide_empty' => false));

	foreach ($terms AS $term) {
		echo '<option value="' . $term->term_id . '" ' . (($selected_terms && (in_array($term->term_id, $selected_terms) || in_array($term->slug, $selected_terms))) ? 'selected' : '') . '>' . (str_repeat('&nbsp;&nbsp;&nbsp;', $level)) . $term->name . '</option>';
		w2dc_renderOptionsTerms($tax, $term->term_id, $selected_terms, $level+1);
	}
	return $terms;
}
function w2dc_termsSelectList($name, $tax = 'category', $selected_terms = array()) {
	echo '<select multiple="multiple" name="' . $name . '[]" class="selected_terms_list w2dc-form-control w2dc-form-group" style="height: 300px">';
	echo '<option value="" ' . ((!$selected_terms) ? 'selected' : '') . '>' . __('- Select All -', 'W2DC') . '</option>';

	w2dc_renderOptionsTerms($tax, 0, $selected_terms);

	echo '</select>';
}

function w2dc_recaptcha() {
	if (get_option('w2dc_enable_recaptcha') && get_option('w2dc_recaptcha_public_key') && get_option('w2dc_recaptcha_private_key')) {
		if (get_option('w2dc_recaptcha_version') == 'v2') {
			return '<div class="g-recaptcha" data-sitekey="'.get_option('w2dc_recaptcha_public_key').'"></div>';
		} elseif (get_option('w2dc_recaptcha_version') == 'v3') {
			ob_start();
			?>
			<input type="hidden" id="g-recaptcha-response" name="g-recaptcha-response" />
			<script>
			(function($) {
				"use strict";

				$(function() {
					grecaptcha.ready(function() {
						grecaptcha.execute('<?php echo get_option('w2dc_recaptcha_public_key'); ?>').then(function(token) {
							$('#g-recaptcha-response').val(token);
						})
					});
				});
			})(jQuery);
			</script>
			<?php 
			return ob_get_clean();
		}
	}
}

function w2dc_is_recaptcha_passed() {
	if (get_option('w2dc_enable_recaptcha') && get_option('w2dc_recaptcha_public_key') && get_option('w2dc_recaptcha_private_key')) {
		if (isset($_POST['g-recaptcha-response'])) {
			$captcha = wcsearch_getValue($_POST, 'g-recaptcha-response');
		} else {
			return false;
		}
		
		$response = wp_remote_get("https://www.google.com/recaptcha/api/siteverify?secret=".get_option('w2dc_recaptcha_private_key')."&response=".$captcha."&remoteip=".$_SERVER['REMOTE_ADDR']);
		if (!is_wp_error($response)) {
			$body = wp_remote_retrieve_body($response);
			$json = json_decode($body);
			if ($json->success === false) {
				return false;
			} else {
				return true;
			}
		} else {
			return false;
		}
	} else {
		return true;
	}
}

function w2dc_orderLinks($base_url, $defaults = array(), $return = false, $shortcode_hash = null) {
	global $w2dc_instance;

	if (!empty(wcsearch_get_query_string('order_by'))) {
		$order_by = wcsearch_get_query_string('order_by');
		$order = wcsearch_get_query_string('order') ? wcsearch_get_query_string('order') : 'ASC';
	} else {
		if (isset($defaults['order_by']) && $defaults['order_by']) {
			$order_by = $defaults['order_by'];
			$order = w2dc_getValue($defaults, 'order', 'ASC');
		} else {
			$order_by = 'post_date';
			$order = 'DESC';
		}
	}
	
	global $w2dc_radius_params;
	if ($w2dc_radius_params) {
		if ((
				(empty($defaults['order_by']) || $defaults['order_by'] == 'distance') ||
				(empty(wcsearch_get_query_string('order_by')) || wcsearch_get_query_string('order_by') == 'distance')
			) &&
			get_option('w2dc_orderby_distance')
		) {
			$order_by = 'distance';
			$order = 'ASC';
		}
	}

	$ordering = array();
	if (get_option('w2dc_orderby_date')) {
		$ordering['post_date']['DESC'] = __('Newest first', 'W2DC');
		$ordering['post_date']['ASC'] = __('Oldest first', 'W2DC');
	}
	if (get_option('w2dc_orderby_title')) {
		$ordering['title']['ASC'] = __('From A to Z', 'W2DC');
		$ordering['title']['DESC'] = __('From Z to A', 'W2DC');
	}

	$exact_categories = array();
	if (!empty($defaults['categories'])) {
		if (!is_array($defaults['categories'])) {
			$exact_categories = array_filter(explode(',', $defaults['categories']));
		} else {
			$exact_categories = array_filter($defaults['categories']);
		}
	}
	if ($current_category = w2dc_isCategory()) {
		$exact_categories[] = $current_category->term_id;
	}
	// add ordering links from content fields
	$content_fields = $w2dc_instance->content_fields->getOrderingContentFieldsByDirectory();
	foreach ($content_fields AS $content_field) {
		if ($exact_categories && $content_field->categories) {
			if (array_intersect($content_field->categories, $exact_categories)) {
				$ordering[$content_field->slug] = $content_field->name;
			}
		} else {
			$ordering[$content_field->slug] = $content_field->name;
		}
	}
	
	$ordering_links = new w2dc_orderingLinks($ordering, $base_url, $order_by, $order);
	
	$ordering_links = apply_filters('w2dc_ordering_options', $ordering_links, $base_url, $defaults, $shortcode_hash);
	
	return $ordering_links;
}

add_filter('w2dc_ordering_options', 'w2dc_order_by_distance_html', 10, 3);
function w2dc_order_by_distance_html($ordering_links, $base_url, $defaults) {
	global $w2dc_radius_params;
	
	if ($w2dc_radius_params && get_option('w2dc_orderby_distance')) {
		$ordering_links->addLinks(array('distance' => array('ASC' => esc_html__('Distance', 'W2DC'))));
	}
	
	return $ordering_links;
}


function w2dc_orderingItems() {
	global $w2dc_instance;

	$ordering = array('post_date' => __('Date', 'W2DC'), 'title' => __('Title', 'W2DC'), 'rand' => __('Random', 'W2DC'));
	$content_fields = $w2dc_instance->content_fields->getOrderingContentFields();
	foreach ($content_fields AS $content_field) {
		$ordering[$content_field->slug] = $content_field->name;
	}
	$ordering = apply_filters('w2dc_default_orderby_options', $ordering);
	$ordering_items = array();
	foreach ($ordering AS $field_slug=>$field_name) {
		$ordering_items[] = array('value' => $field_slug, 'label' => $field_name);
	}
	
	return $ordering_items;
}

function w2dc_displayCategoriesTable($category_id = 0) {
	global $w2dc_instance;

	if ($w2dc_instance->current_directory->categories) {
		$exact_categories = $w2dc_instance->current_directory->categories;
	} else {
		$exact_categories = array();
	}

	$params = array(
			'parent' => $category_id,
			'depth' => get_option('w2dc_categories_nesting_level'),
			'hide_empty' => get_option('w2dc_hide_empty_categories'),
			'columns' => get_option('w2dc_categories_columns'),
			'count' => get_option('w2dc_show_category_count'),
			'max_subterms' => get_option('w2dc_subcategories_items'),
			'exact_terms' => $exact_categories,
			'menu' => 1,
			'order' => get_option('w2dc_categories_order'),
	);
	$categories_view = new w2dc_categories_view($params);
	$categories_view->display();
}

function w2dc_displayLocationsTable($location_id = 0) {
	global $w2dc_instance;

	if ($w2dc_instance->current_directory->locations) {
		$exact_locations = $w2dc_instance->current_directory->locations;
	} else {
		$exact_locations = array();
	}

	$params = array(
			'parent' => $location_id,
			'depth' => get_option('w2dc_locations_nesting_level'),
			'hide_empty' => get_option('w2dc_hide_empty_locations'),
			'columns' => get_option('w2dc_locations_columns'),
			'count' => get_option('w2dc_show_location_count'),
			'max_subterms' => get_option('w2dc_sublocations_items'),
			'exact_terms' => $exact_locations,
			'menu' => 1,
			'order' => get_option('w2dc_locations_order'),
	);
	$locations_view = new w2dc_locations_view($params);
	$locations_view->display();
}

function w2dc_terms_checklist($post_id) {
	if ($terms = get_categories(array('taxonomy' => W2DC_CATEGORIES_TAX, 'pad_counts' => true, 'hide_empty' => false, 'parent' => 0))) {
		$checked_categories_ids = array();
		$checked_categories = wp_get_object_terms($post_id, W2DC_CATEGORIES_TAX);
		foreach ($checked_categories AS $term)
			$checked_categories_ids[] = $term->term_id;

		echo '<ul id="w2dc-categorychecklist" class="w2dc-categorychecklist">';
		foreach ($terms AS $term) {
			$classes = '';
			$checked = '';
			if (in_array($term->term_id, $checked_categories_ids)) {
				$checked = 'checked';
			}
			
			if (defined('W2DC_EXPANDED_CATEGORIES_TREE') && W2DC_EXPANDED_CATEGORIES_TREE) {
				$classes .= 'active ';
			}
				
			echo '<li id="' . W2DC_CATEGORIES_TAX . '-' . $term->term_id . '" class="' . $classes . '">';
			echo '<label class="selectit"><input type="checkbox" ' . $checked . ' id="in-' . W2DC_CATEGORIES_TAX . '-' . $term->term_id . '" name="tax_input[' . W2DC_CATEGORIES_TAX . '][]" value="' . $term->term_id . '"> ' . $term->name . '</label>';
			echo _w2dc_terms_checklist($term->term_id, $checked_categories_ids);
			echo '</li>';
		}
		echo '</ul>';
	}
}
function _w2dc_terms_checklist($parent = 0, $checked_categories_ids = array()) {
	$html = '';
	if ($terms = get_categories(array('taxonomy' => W2DC_CATEGORIES_TAX, 'pad_counts' => true, 'hide_empty' => false, 'parent' => $parent))) {
		$html .= '<ul class="children">';
		foreach ($terms AS $term) {
			$checked = '';
			if (in_array($term->term_id, $checked_categories_ids)) {
				$checked = 'checked';
			}
			
			$classes = '';
			if (defined('W2DC_EXPANDED_CATEGORIES_TREE') && W2DC_EXPANDED_CATEGORIES_TREE) {
				$classes .= 'active ';
			}

			$html .= '<li id="' . W2DC_CATEGORIES_TAX . '-' . $term->term_id . '" class="' . $classes . '">';
			$html .= '<label class="selectit"><input type="checkbox" ' . $checked . ' id="in-' . W2DC_CATEGORIES_TAX . '-' . $term->term_id . '" name="tax_input[' . W2DC_CATEGORIES_TAX . '][]" value="' . $term->term_id . '"> ' . $term->name . '</label>';
			$html .= _w2dc_terms_checklist($term->term_id, $checked_categories_ids);
			$html .= '</li>';
		}
		$html .= '</ul>';
	}
	return $html;
}

function w2dc_tags_selectbox($listing) {
	$terms = get_categories(array('taxonomy' => W2DC_TAGS_TAX, 'pad_counts' => true, 'hide_empty' => false));
	$checked_tags_ids = array();
	$checked_tags_names = array();
	$checked_tags = wp_get_object_terms($listing->post->ID, W2DC_TAGS_TAX);
	foreach ($checked_tags AS $term) {
		$checked_tags_ids[] = $term->term_id;
		$checked_tags_names[] = $term->name;
	}
	
	$tags_data = 'var w2dc_tags_metabox_attrs = ' . json_encode(
		array(
			'tags_number' => $listing->level->tags_number,
			'unlimited_tags' => $listing->level->unlimited_tags,
			'tags_limit_message' => sprintf(esc_attr__('You can not enter more than %d tag(s)', 'W2DC'), $listing->level->tags_number),
		)
	);
	wp_add_inline_script('w2dc_js_functions', $tags_data, 'before');

	echo '<select name="' . W2DC_TAGS_TAX . '[]" multiple="multiple" class="w2dc-tokenizer">';
	foreach ($terms AS $term) {
		$checked = '';
		if (in_array($term->term_id, $checked_tags_ids)) {
			$checked = 'selected';
		}
		echo '<option value="' . esc_attr($term->name) . '" ' . $checked . '>' . $term->name . '</option>';
	}
	echo '</select>';
}

function w2dc_getTermIconUrl($term_id) {
	$term = get_term($term_id);

	if (!is_wp_error($term)) {
		if ($term->taxonomy == W2DC_CATEGORIES_TAX && ($category_icon = w2dc_getCategoryIconFile($term_id))) {
			return W2DC_CATEGORIES_ICONS_URL . $category_icon;
		}
		if ($term->taxonomy == W2DC_LOCATIONS_TAX && ($location_icon = w2dc_getLocationIconFile($term_id))) {
			return W2DC_LOCATIONS_ICONS_URL . $location_icon;
		}
	}
}

function w2dc_getDefaultTermIconUrl($tax) {
	if ($tax == W2DC_CATEGORIES_TAX) {
		return W2DC_CATEGORIES_ICONS_URL . 'search.png';
	}
	if ($tax == W2DC_LOCATIONS_TAX) {
		return W2DC_LOCATIONS_ICONS_URL . 'icon1.png';
	}
}

function w2dc_show_404() {
	status_header(404);
	nocache_headers();
	include(get_404_template());
	exit;
}


if (!function_exists('w2dc_renderPaginator')) {
	function w2dc_renderPaginator($query, $hash = null, $show_more_button = false, $frontend_controller = null) {
		global $w2dc_instance;
		
		if (empty($frontend_controller)) {
			$directory = $w2dc_instance->current_directory;
		} else {
			$directory = $frontend_controller->getListingsDirectory();
		}

		if (get_class($query) == 'WP_Query') {
			if (get_query_var('page'))
				$paged = get_query_var('page');
			elseif (get_query_var('paged'))
				$paged = get_query_var('paged');
			else
				$paged = 1;

			$total_pages = $query->max_num_pages;
			$total_lines = ceil($total_pages/10);
		
			if ($total_pages > 1) {
				$current_page = max(1, $paged);
				$current_line = floor(($current_page-1)/10) + 1;
		
				$previous_page = $current_page - 1;
				$next_page = $current_page + 1;
				$previous_line_page = floor(($current_page-1)/10)*10;
				$next_line_page = ceil($current_page/10)*10 + 1;
				
				if (!$show_more_button) {
					echo '<div class="w2dc-pagination-wrapper">';
					echo '<ul class="w2dc-pagination">';
					if ($total_pages > 10 && $current_page > 10)
						echo '<li class="w2dc-inactive previous_line"><a href="' . get_pagenum_link($previous_line_page) . '" title="' . esc_attr__('Previous Line', 'W2DC') . '" data-page=' . $previous_line_page . ' data-controller-hash=' . $hash . '><<</a></li>' ;
			
					if ($total_pages > 3 && $current_page > 1)
						echo '<li class="w2dc-inactive previous"><a href="' . get_pagenum_link($previous_page) . '" title="' . esc_attr__('Previous Page', 'W2DC') . '" data-page=' . $previous_page . ' data-controller-hash=' . $hash . '><</i></a></li>' ;
			
					$count = ($current_line-1)*10;
					$end = ($total_pages < $current_line*10) ? $total_pages : $current_line*10;
					while ($count < $end) {
						$count = $count + 1;
						if ($count == $current_page)
							echo '<li class="w2dc-active"><a href="' . get_pagenum_link($count) . '">' . $count . '</a></li>' ;
						else
							echo '<li class="w2dc-inactive"><a href="' . get_pagenum_link($count) . '" data-page=' . $count . ' data-controller-hash=' . $hash . '>' . $count . '</a></li>' ;
					}
			
					if ($total_pages > 3 && $current_page < $total_pages)
						echo '<li class="w2dc-inactive next"><a href="' . get_pagenum_link($next_page) . '" title="' . esc_attr__('Next Page', 'W2DC') . '" data-page=' . $next_page . ' data-controller-hash=' . $hash . '>></i></a></li>' ;
			
					if ($total_pages > 10 && $current_line < $total_lines)
						echo '<li class="w2dc-inactive next_line"><a href="' . get_pagenum_link($next_line_page) . '" title="' . esc_attr__('Next Line', 'W2DC') . '" data-page=' . $next_line_page . ' data-controller-hash=' . $hash . '>>></a></li>' ;
			
					echo '</ul>';
					echo '</div>';
				} else {
					if ($frontend_controller && !empty($frontend_controller->args['scrolling_paginator'])) {
						$scrolling_paginator_class = "w2dc-scrolling-paginator";
					} else {
						$scrolling_paginator_class = '';
					}
					echo '<div class="w2dc-row"><button class="w2dc-btn w2dc-btn-primary w2dc-btn-block w2dc-show-more-button ' . $scrolling_paginator_class . '" data-controller-hash="' . $hash . '">' . sprintf(__('Show more %s', 'W2DC'), $directory->plural) . '</button></div>';
				}
			}
		}
	}
}

function w2dc_renderSharingButton($post_id, $post_url, $button) {
	global $w2dc_social_services;

	$post_title = urlencode(get_the_title($post_id));
	if ($thumb_url = wp_get_attachment_image_src(get_post_thumbnail_id($post_id), array(200, 200))) {
		$post_thumbnail = urlencode($thumb_url[0]);
	} else {
		$post_thumbnail = '';
	}
	if (get_post_type($post_id) == W2DC_POST_TYPE) {
		$listing = new w2dc_listing;
		if ($listing->loadListingFromPost($post_id))
			$post_title = urlencode($listing->title());
	}
	$post_url = urlencode($post_url);

	if (isset($w2dc_social_services[$button])) {
		$share_url = false;
		$share_counter = false;
		switch ($button) {
			case 'facebook':
				$share_url = 'http://www.facebook.com/sharer.php?u=' . $post_url;
				if (get_option('w2dc_share_counter')) {
					$response = wp_remote_get('http://graph.facebook.com/?id=' . $post_url);
					if (!is_wp_error($response)) {
						$body = wp_remote_retrieve_body($response);
						$json = json_decode($body);
						$share_counter = (isset($json->share->share_count)) ? intval($json->share->share_count) : 0;
					}
				}
			break;
			case 'twitter':
				$share_url = 'http://twitter.com/share?url=' . $post_url . '&amp;text=' . $post_title;
				/* if (get_option('w2dc_share_counter')) {
					$response = wp_remote_get('https://urls.api.twitter.com/1/urls/count.json?url=' . $post_url);
					if (!is_wp_error($response)) {
						$body = wp_remote_retrieve_body($response);
						$json = json_decode($body);
						$share_counter = (isset($json->count)) ? intval($json->count) : 0;
					}
				} */
			break;
			case 'google':
				$share_url = 'https://plus.google.com/share?url=' . $post_url;
				if (get_option('w2dc_share_counter')) {
					$args = array(
				            'method' => 'POST',
				            'headers' => array(
				                'Content-Type' => 'application/json'
				            ),
				            'body' => json_encode(array(
				                'method' => 'pos.plusones.get',
				                'id' => 'p',
				                'method' => 'pos.plusones.get',
				                'jsonrpc' => '2.0',
				                'key' => 'p',
				                'apiVersion' => 'v1',
				                'params' => array(
				                    'nolog' => true,
				                    'id' => $post_url,
				                    'source' => 'widget',
				                    'userId' => '@viewer',
				                    'groupId' => '@self'
				                ) 
				             )),          
				            'sslverify'=>false
				        ); 
				    $response = wp_remote_post("https://clients6.google.com/rpc", $args);
					if (!is_wp_error($response)) {
						$body = wp_remote_retrieve_body($response);
						$json = json_decode($body);
						$share_counter = (isset($json->result->metadata->globalCounts->count)) ? intval($json->result->metadata->globalCounts->count) : 0;
					}
				}
			break;
			case 'digg':
				$share_url = 'http://www.digg.com/submit?url=' . $post_url;
			break;
			case 'reddit':
				$share_url = 'http://reddit.com/submit?url=' . $post_url . '&amp;title=' . $post_title;
				if (get_option('w2dc_share_counter')) {
					$response = wp_remote_get('https://www.reddit.com/api/info.json?url=' . $post_url);
					if (!is_wp_error($response)) {
						$body = wp_remote_retrieve_body($response);
						$json = json_decode($body);
						$share_counter = (isset($json->data->children[0]->data->score)) ? intval($json->data->children[0]->data->score) : 0;
					}
				}
			break;
			case 'linkedin':
				$share_url = 'http://www.linkedin.com/shareArticle?mini=true&amp;url=' . $post_url;
				if (get_option('w2dc_share_counter')) {
					$response = wp_remote_get('https://www.linkedin.com/countserv/count/share?url=' . $post_url . '&format=json');
					if (!is_wp_error($response)) {
						$body = wp_remote_retrieve_body($response);
						$json = json_decode($body);
						$share_counter = (isset($json->count)) ? intval($json->count) : 0;
					}
				}
			break;
			case 'pinterest':
				$share_url = 'https://www.pinterest.com/pin/create/button/?url=' . $post_url . '&amp;media=' . $post_thumbnail . '&amp;description=' . $post_title;
				if (get_option('w2dc_share_counter')) {
					$response = wp_remote_get('https://api.pinterest.com/v1/urls/count.json?url=' . $post_url);
					if (!is_wp_error($response)) {
						$body = preg_replace('/^receiveCount\((.*)\)$/', "\\1", $response['body']);
						$json = json_decode($body);
						$share_counter = (isset($json->count)) ? intval($json->count) : 0;
					}
				}
			break;
			case 'stumbleupon':
				$share_url = 'http://www.stumbleupon.com/submit?url=' . $post_url . '&amp;title=' . $post_title;
				if (get_option('w2dc_share_counter')) {
					$response = wp_remote_get('https://www.stumbleupon.com/services/1.01/badge.getinfo?url=' . $post_url);
					if (!is_wp_error($response)) {
						$body = wp_remote_retrieve_body($response);
						$json = json_decode($body);
						$share_counter = (isset($json->result->views)) ? intval($json->result->views) : 0;
					}
				}
			break;
			case 'tumblr':
				$share_url = 'http://www.tumblr.com/share/link?url=' . str_replace('http://', '', str_replace('https://', '', $post_url)) . '&amp;name=' . $post_title;
			break;
			case 'vk':
				$share_url = 'http://vkontakte.ru/share.php?url=' . $post_url;
				if (get_option('w2dc_share_counter')) {
					$response = wp_remote_get('https://vkontakte.ru/share.php?act=count&index=1&url=' . $post_url);
					if (!is_wp_error($response)) {
						$tmp = array();
						preg_match('/^VK.Share.count\(1, (\d+)\);$/i', $response['body'], $tmp);
						$share_counter = (isset($tmp[1])) ? intval($tmp[1]) : 0;
					}
				}
			break;
			case 'whatsapp':
				//$share_url = 'https://wa.me/?text=' . $post_url;
				$share_url = 'whatsapp://send?text=' . $post_url;
			break;
			case 'telegram':
				$share_url = 'https://telegram.me/share/url?url=' . $post_url . '&text=' . $post_title;
			break;
			case 'viber':
				$share_url = 'viber://forward?text=' . $post_url;
			break;
			case 'email':
				$share_url = 'mailto:?Subject=' . $post_title . '&amp;Body=' . $post_url;
			break;
		}

		if ($share_url !== false) {
			echo '<a href="'.$share_url.'" data-toggle="w2dc-tooltip" data-placement="top" title="'.sprintf(__('Share on %s', 'W2DC'),  $w2dc_social_services[$button]['label']).'" target="_blank"><img src="'.W2DC_RESOURCES_URL.'images/social/'.get_option('w2dc_share_buttons_style').'/'.$button.'.png" /></a>';
			if (get_option('w2dc_share_counter') && $share_counter !== false)
				echo '<span class="w2dc-share-count">'.number_format($share_counter).'</span>';
		}
	}
}

function w2dc_hintMessage($message, $placement = 'auto', $return = false) {
	$out = '<a class="w2dc-hint-icon" href="javascript:void(0);" data-content="' . esc_attr($message) . '" data-html="true" rel="popover" data-placement="' . esc_attr($placement) . '" data-trigger="hover"></a>';
	if ($return) {
		return $out;
	} else {
		echo $out;
	}
}

function w2dc_levelPriceString($level) {
	$price = apply_filters('w2dc_submitlisting_level_price', null, $level);
	if ($price === 0 || $price === "") {
		return '<span class="w2dc-price w2dc-payments-free">' .__('FREE', 'W2DC') . '</span>';
	} elseif (!is_null($price)) {
		if (!$level->eternal_active_period) {
			if ($level->active_period == 'day' && $level->active_interval == 1)
				$price .= '/<span class="w2dc-price-period">' . __('daily', 'W2DC') . '</span>';
			elseif ($level->active_period == 'day' && $level->active_interval > 1)
				$price .= '/<span class="w2dc-price-period">' . $level->active_interval . ' ' . _n('day', 'days', $level->active_interval, 'W2DC') . '</span>';
			elseif ($level->active_period == 'week' && $level->active_interval == 1)
				$price .= '/<span class="w2dc-price-period">' . __('weekly', 'W2DC') . '</span>';
			elseif ($level->active_period == 'week' && $level->active_interval > 1)
				$price .= '/<span class="w2dc-price-period">' . $level->active_interval . ' ' . _n('week', 'weeks', $level->active_interval, 'W2DC') . '</span>';
			elseif ($level->active_period == 'month' && $level->active_interval == 1)
				$price .= '/<span class="w2dc-price-period">' . __('monthly', 'W2DC') . '</span>';
			elseif ($level->active_period == 'month' && $level->active_interval > 1)
				$price .= '/<span class="w2dc-price-period">' . $level->active_interval . ' ' . _n('month', 'months', $level->active_interval, 'W2DC') . '</span>';
			elseif ($level->active_period == 'year' && $level->active_interval == 1)
				$price .= '/<span class="w2dc-price-period">' . __('annually', 'W2DC') . '</span>';
			elseif ($level->active_period == 'year' && $level->active_interval > 1)
				$price .= '/<span class="w2dc-price-period">' . $level->active_interval . ' ' . _n('year', 'years', $level->active_interval, 'W2DC') . '</span>';
		}
		return '<span class="w2dc-price">' . $price . '</span>';
	}
}

function w2dc_get_distance($location) {
	global $w2dc_order_by_distance;
	
	if (get_option('w2dc_miles_kilometers_in_search') == 'miles') {
		$dimention = esc_html__('mi', 'W2DC');
	} else {
		$dimention = esc_html__('km', 'W2DC');
	}
	
	if (isset($w2dc_order_by_distance[$location->id])) {
		return ' <span class="w2dc-orderby-distance w2dc-badge" title="' . esc_attr__('Distance from center', 'W2DC') . '">' . round($w2dc_order_by_distance[$location->id], 1) . ' ' . $dimention . '</span> ';
	}
}

?>