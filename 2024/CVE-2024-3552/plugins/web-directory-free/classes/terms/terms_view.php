<?php 

class w2dc_terms_view {
	public $attrs;
	public $depth;
	public $parent;
	public $columns;
	public $hide_empty;
	public $count;
	public $max_subterms;
	public $exact_terms = array();
	public $exact_terms_obj = array();
	public $col_md;
	public $tax;
	public $terms_icons_url;
	public $grid;
	public $grid_view;
	public $icons;
	public $menu;
	public $view_all_terms;
	public $directory;
	
	public function __construct($params) {
		$this->attrs = array_merge(array(
				'directory' => 0,
				'parent' => 0,
				'depth' => 2,
				'columns' => 2,
				'count' => true,
				'hide_empty' => false,
				'max_subterms' => 0,
				'exact_terms' => array(),
				'grid' => 0,
				'grid_view' => 0,
				'icons' => 1,
				'alphabetical' => 0,
				'order' => 'default', // 'default', 'name', 'count'
		), $params);

		$this->directory = $this->attrs['directory'];
		if (is_numeric($this->attrs['parent'])) {
			$this->parent = $this->attrs['parent'];
		} else {
			if ($term_obj = get_term_by('slug', $this->attrs['parent'], $this->tax)) {
				$this->parent = $term_obj->term_id;
			}
		}
		$this->depth = $this->attrs['depth'];
		$this->columns = $this->attrs['columns'];
		$this->count = $this->attrs['count'];
		$this->hide_empty = $this->attrs['hide_empty'];
		$this->max_subterms = $this->attrs['max_subterms'];
		$this->grid = $this->attrs['grid'];
		$this->grid_view = $this->attrs['grid_view'];
		$this->icons = $this->attrs['icons'];
		$this->menu = $this->attrs['menu'];
		
		// filter empty exact terms
		if (is_array($this->attrs['exact_terms']) && !empty($this->attrs['exact_terms'])) {
			foreach ($this->attrs['exact_terms'] AS $term) {
				if (is_numeric($term)) {
					if ($term_obj = get_term_by('id', $term, $this->tax)) {
						$count = w2dc_getTermCount($term_obj->term_id, $this->directory);
						
						if (!$this->hide_empty || $count > 0) {
							$this->exact_terms[] = $term_obj->term_id;
							$this->exact_terms_obj[] = $term_obj;
						}
					}
				} else {
					if ($term_obj = get_term_by('slug', $term, $this->tax)) {
						$count = w2dc_getTermCount($term_obj->term_id, $this->directory);
						
						if (!$this->hide_empty || $count > 0) {
							$this->exact_terms[] = $term_obj->term_id;
							$this->exact_terms_obj[] = $term_obj;
						}
					}
				}
			}
		}
		
		if ($this->attrs['depth'] > 2) {
			$this->depth = 2;
		}
		if ($this->depth == 0 || !is_numeric($this->depth)) {
			$this->depth = 1;
		}
		if ($this->columns > 4) {
			$this->columns = 4;
		}
		if ($this->columns == 0 || !is_numeric($this->columns)) {
			$this->columns = 1;
		}
		$this->col_md = 12/$this->columns;
	}
	
	public function getTerms($parent, $is_root = false) {
		// we use array_merge with empty array because we need to flush keys in terms array
		$terms = array_merge(
					// there is a wp bug with pad_counts in get_terms function - so we use this construction
					wp_list_filter(
							get_categories(array(
									'taxonomy' => $this->tax,
									'pad_counts' => true,
									'hide_empty' => $this->hide_empty,
									'include' => $this->exact_terms,
							)),
							array('parent' => $parent)
					), array()
		);
		
		if ($this->attrs['order'] == 'name') {
			usort($terms, function ($a, $b) {
				return strcasecmp($a->name, $b->name);
			});
		}
		
		if ($this->attrs['order'] == 'count') {
			usort($terms, function ($a, $b) {
				if ($a->count == $b->count) {
					return 0;
				}
				return ($a->count > $b->count) ? 1 : -1;
			});
		}
		
		// display sibling terms when current term does not have children and listings
		if (!$terms && !w2dc_getListings()) {
			if ($parent && $is_root) {
				$term_parent = get_term($parent, $this->tax);
				if (!is_wp_error($term_parent)) {
					$terms = $this->getTerms($term_parent->parent);
				}
			}
		}
		
		return $terms;
	}
	
	public function getCount($term) {
		return w2dc_getTermCount($term->term_id, $this->directory);
	}
	
	public function getWrapperClasses() {
		$classes[] = "w2dc-content";
		$classes[] = $this->wrapper_classes;
		$classes[] = "w2dc-terms-columns-" . $this->columns;
		if ($this->menu) {
			$classes[] = "w2dc-terms-menu";
		} else {
			$classes[] = "w2dc-terms-grid";
		}
		if ($this->grid) {
			$classes[] = $this->grid_classes;
		}
		$classes[] = "w2dc-terms-depth-" . $this->depth;
		
		return implode(' ', $classes);
	}
	
	public function renderFeaturedImage($term, $size = array(600, 400)) {
		if ($image_url = $this->getTermImageUrl($term->term_id, $size)) {
			$featured_image = 'style="background-image: url(' . $image_url . ');"';
		} else {
			$featured_image = '';
		}

		return $featured_image;
	}

	public function renderIconImage($term) {
		if ($this->icons && $icon_url= $this->getTermIconFile($term->term_id)) {
			$icon_image = '<img class="w2dc-field-icon" src="' . $icon_url . '" />';
		} else {
			$icon_image = '';
		}

		return $icon_image;
	}

	public function renderTermCount($term) {
		if ($this->count) {
			$term_count = '<span class="' . $this->term_count_classes . '">' . $this->getCount($term) . '</span>';
		} else {
			$term_count = '';
		}

		return $term_count;
	}
	
	public function highlightItem($term) {
		if ($this->parent && $term->term_id == $this->parent) {
			return $this->highlighted_item_classes;
		}
	}
	
	public function display() {
		global $w2dc_directory_flag;
		if ($this->directory) {
			$w2dc_directory_flag = $this->directory;
		}
		
		$terms = $this->getTerms($this->parent, true);
		
		if (!$terms && $this->exact_terms && (get_terms($this->tax, array('hide_empty' => false, 'parent' => $this->parent)))) {
			$terms = $this->exact_terms_obj;
		}
		

		if ($terms) {
			echo '<div class="' . $this->getWrapperClasses() . '">';
			switch ($this->grid_view) {
				case 0:
					$this->standardGridView($terms);
					break;
				case 1:
					$this->leftGridView($terms);
					break;
				case 2:
					$this->rightGridView($terms);
					break;
				case 3:
					$this->centerGridView($terms);
					break;
			}
			echo '</div>';
		}
		
		$w2dc_directory_flag = 0;
	}

	function standardGridView($terms) {
		$terms_number = count($terms);
		$counter = 0;
		$tcounter = 0;
		
		$order_letter = '0';
		
		foreach ($terms AS $key=>$term) {
			
			if ($this->attrs['alphabetical']) {
				$current_letter = $term->name[0];
				if ($current_letter != $order_letter) {
					if ($counter) {
						echo '</div>';
						$counter = 0;
					}
					
					echo '<div class="w2dc-row w2dc-terms-order-letter">';
					echo '<div class="w2dc-col-md-12">';
					echo strtoupper($current_letter);
					echo '</div>';
					echo '</div>';
					
					$order_letter = $current_letter;
				}
			}
			
			$tcounter++;
			if ($counter == 0) {
				echo '<div class="w2dc-row ' . $this->row_classes . '">';
			}
		
			echo '<div class="w2dc-col-md-' . $this->col_md . '">';
			echo '<div class="' . $this->column_classes . '">';
			if ($this->menu) {
				echo '<div class="' . $this->root_classes . ' ' . $this->item_classes . ' ' . $this->highlightItem($term) . '" ' . $this->renderFeaturedImage($term) . '><a href="' . get_term_link($term) . '" title="' . $term->name . '"><div class="w2dc-term-label"><div class="w2dc-term-label-justify">' . $this->renderIconImage($term) . $term->name . '</div>' . $this->renderTermCount($term) . '</div>' . do_action('w2dc_render_term', $term) . '</a></div>';
			} else {
				echo '<div class="' . $this->root_classes . ' ' . $this->item_classes . ' ' . $this->highlightItem($term) . '" ' . $this->renderFeaturedImage($term) . '><a href="' . get_term_link($term) . '" title="' . $term->name . '"><div class="w2dc-term-label"><div class="w2dc-term-label-justify">' . $this->renderIconImage($term) . $term->name . '&nbsp;' . $this->renderTermCount($term) . '</div></div>' . do_action('w2dc_render_term', $term) . '</a></div>';
			}
			echo $this->_display($term->term_id, 1);
			echo '</div>';
		
			echo '</div>';
		
			$counter++;
			if ($counter == $this->columns || ($tcounter == $terms_number && $counter != $this->columns)) {
				echo '</div>';
			}
			if ($counter == $this->columns) {
				$counter = 0;
			}
		}
	}
	function _display($parent, $depth_level) {
		$html = '';
		if ($this->depth == 0 || !is_numeric($this->depth) || $this->depth > $depth_level) {
			$terms = $this->getTerms($parent);
			if ($terms) {
				$depth_level++;
				$counter = 0;
				$html .= '<div class="' . $this->subterms_classes . '">';
				$html .= '<ul>';
				foreach ($terms AS $term) {
					if ($this->count) {
						$term_count = '<span class="' . $this->term_count_classes . '">' . $this->getCount($term) . '</span>';
					} else {
						$term_count = '';
					}
		
					if ($this->icons && $icon_url = $this->getTermIconFile($term->term_id)) {
						$icon_image = '<img class="w2dc-field-icon" src="' . $icon_url . '" />';
					} else {
						$icon_image = '';
					}
		
					$counter++;
					if ($this->max_subterms != 0 && $counter > $this->max_subterms) {
						$html .= '<li class="' . $this->item_classes . ' ' . $this->highlightItem($term) . '"><a href="' . get_term_link(intval($parent), $this->tax) . '">' . $this->view_all_terms . '</a></li>';
						break;
					} else {
						$html .= '<li class="' . $this->item_classes . ' ' . $this->highlightItem($term) . '"><a href="' . get_term_link($term) . '" title="' . $term->name . '">' . $icon_image . $term->name . $term_count . do_action('w2dc_render_term', $term) . '</a></li>';
					}
				}
				$html .= '</ul>';
				$html .= '</div>';
			}
		}
		return $html;
	}
	
	function leftGridView($terms) {
		echo '<div class="w2dc-row w2dc-left-grid-view ' . $this->row_classes . '">';
			if ($term = w2dc_getValue($terms, 0)) {
				echo '<div class="w2dc-col-md-6">';
					echo '<div class="' . $this->column_classes . '">';
						echo '<div class="' . $this->root_classes . ' ' . $this->item_classes . '" ' . $this->renderFeaturedImage($term, array(600, 600)) . '><a class="w2dc-grid-item-tall" href="' . get_term_link($term) . '" title="' . $term->name . '"><div class="w2dc-term-label"><div class="w2dc-term-label-justify">' . $this->renderIconImage($term) . $term->name . '&nbsp;' . $this->renderTermCount($term) . '</div></div>' . do_action('w2dc_render_term', $term) . '</a></div>';
					echo '</div>';
				echo '</div>';
			}
	
			echo '<div class="w2dc-col-md-6">';
				if ($term = w2dc_getValue($terms, 1)) {
					echo '<div class="w2dc-row ' . $this->row_classes . '">';
						echo '<div class="w2dc-col-md-12">';
							echo '<div class="' . $this->column_classes . '">';
								echo '<div class="' . $this->root_classes . ' ' . $this->item_classes . '" ' . $this->renderFeaturedImage($term) . '><a class="w2dc-grid-item-normal" href="' . get_term_link($term) . '" title="' . $term->name . '"><div class="w2dc-term-label"><div class="w2dc-term-label-justify">' . $this->renderIconImage($term) . $term->name . '&nbsp;' . $this->renderTermCount($term) . '</div></div>' . do_action('w2dc_render_term', $term) . '</a></div>';
							echo '</div>';
						echo '</div>';
					echo '</div>';
				}
	
				echo '<div class="w2dc-row ' . $this->row_classes . '">';
					if ($term = w2dc_getValue($terms, 2)) {
						echo '<div class="w2dc-col-md-6">';
							echo '<div class="' . $this->column_classes . '">';
								echo '<div class="' . $this->root_classes . ' ' . $this->item_classes . '" ' . $this->renderFeaturedImage($term) . '><a class="w2dc-grid-item-normal" href="' . get_term_link($term) . '" title="' . $term->name . '"><div class="w2dc-term-label"><div class="w2dc-term-label-justify">' . $this->renderIconImage($term) . $term->name . '&nbsp;' . $this->renderTermCount($term) . '</div></div>' . do_action('w2dc_render_term', $term) . '</a></div>';
							echo '</div>';
						echo '</div>';
					}
		
					if ($term = w2dc_getValue($terms, 3)) {
						echo '<div class="w2dc-col-md-6">';
							echo '<div class="' . $this->column_classes . '">';
								echo '<div class="' . $this->root_classes . ' ' . $this->item_classes . '" ' . $this->renderFeaturedImage($term) . '><a class="w2dc-grid-item-normal" href="' . get_term_link($term) . '" title="' . $term->name . '"><div class="w2dc-term-label"><div class="w2dc-term-label-justify">' . $this->renderIconImage($term) . $term->name . '&nbsp;' . $this->renderTermCount($term) . '</div></div>' . do_action('w2dc_render_term', $term) . '</a></div>';
							echo '</div>';
						echo '</div>';
					}
				echo '</div>';
			echo '</div>';
		echo '</div>';
	}
	
	function rightGridView($terms) {
		echo '<div class="w2dc-row w2dc-right-grid-view ' . $this->row_classes . '">';
			echo '<div class="w2dc-col-md-6">';
				if ($term = w2dc_getValue($terms, 0)) {
					echo '<div class="w2dc-row ' . $this->row_classes . '">';
						echo '<div class="w2dc-col-md-12">';
							echo '<div class="' . $this->column_classes . '">';
								echo '<div class="' . $this->root_classes . ' ' . $this->item_classes . '" ' . $this->renderFeaturedImage($term) . '><a class="w2dc-grid-item-normal" href="' . get_term_link($term) . '" title="' . $term->name . '"><div class="w2dc-term-label"><div class="w2dc-term-label-justify">' . $this->renderIconImage($term) . $term->name . '&nbsp;' . $this->renderTermCount($term) . '</div></div>' . do_action('w2dc_render_term', $term) . '</a></div>';
							echo '</div>';
						echo '</div>';
					echo '</div>';
				}
	
				echo '<div class="w2dc-row ' . $this->row_classes . '">';
					if ($term = w2dc_getValue($terms, 1)) {
						echo '<div class="w2dc-col-md-6">';
							echo '<div class="' . $this->column_classes . '">';
								echo '<div class="' . $this->root_classes . ' ' . $this->item_classes . '" ' . $this->renderFeaturedImage($term) . '><a class="w2dc-grid-item-normal" href="' . get_term_link($term) . '" title="' . $term->name . '"><div class="w2dc-term-label"><div class="w2dc-term-label-justify">' . $this->renderIconImage($term) . $term->name . '&nbsp;' . $this->renderTermCount($term) . '</div></div>' . do_action('w2dc_render_term', $term) . '</a></div>';
							echo '</div>';
						echo '</div>';
					}
		
					if ($term = w2dc_getValue($terms, 2)) {
						echo '<div class="w2dc-col-md-6">';
							echo '<div class="' . $this->column_classes . '">';
								echo '<div class="' . $this->root_classes . ' ' . $this->item_classes . '" ' . $this->renderFeaturedImage($term) . '><a class="w2dc-grid-item-normal" href="' . get_term_link($term) . '" title="' . $term->name . '"><div class="w2dc-term-label"><div class="w2dc-term-label-justify">' . $this->renderIconImage($term) . $term->name . '&nbsp;' . $this->renderTermCount($term) . '</div></div>' . do_action('w2dc_render_term', $term) . '</a></div>';
							echo '</div>';
						echo '</div>';
					}
				echo '</div>';
			echo '</div>';
			
			if ($term = w2dc_getValue($terms, 3)) {
				echo '<div class="w2dc-col-md-6">';
					echo '<div class="' . $this->column_classes . '">';
						echo '<div class="' . $this->root_classes . ' ' . $this->item_classes . '" ' . $this->renderFeaturedImage($term, array(600, 600)) . '><a class="w2dc-grid-item-tall" href="' . get_term_link($term) . '" title="' . $term->name . '"><div class="w2dc-term-label"><div class="w2dc-term-label-justify">' . $this->renderIconImage($term) . $term->name . '&nbsp;' . $this->renderTermCount($term) . '</div></div>' . do_action('w2dc_render_term', $term) . '</a></div>';
					echo '</div>';
				echo '</div>';
			}
		echo '</div>';
	}
	
	function centerGridView($terms) {
		echo '<div class="w2dc-row w2dc-center-grid-view ' . $this->row_classes . '">';
			if ($term = w2dc_getValue($terms, 0)) {
				echo '<div class="w2dc-col-md-3">';
					echo '<div class="' . $this->column_classes . '">';
						echo '<div class="' . $this->root_classes . ' ' . $this->item_classes . '" ' . $this->renderFeaturedImage($term) . '><a class="w2dc-grid-item-normal" href="' . get_term_link($term) . '" title="' . $term->name . '"><div class="w2dc-term-label"><div class="w2dc-term-label-justify">' . $this->renderIconImage($term) . $term->name . '&nbsp;' . $this->renderTermCount($term) . '</div></div>' . do_action('w2dc_render_term', $term) . '</a></div>';
					echo '</div>';
				echo '</div>';
			}
	
			if ($term = w2dc_getValue($terms, 1)) {
				echo '<div class="w2dc-col-md-6">';
					echo '<div class="' . $this->column_classes . '">';
						echo '<div class="' . $this->root_classes . ' ' . $this->item_classes . '" ' . $this->renderFeaturedImage($term) . '><a class="w2dc-grid-item-normal" href="' . get_term_link($term) . '" title="' . $term->name . '"><div class="w2dc-term-label"><div class="w2dc-term-label-justify">' . $this->renderIconImage($term) . $term->name . '&nbsp;' . $this->renderTermCount($term) . '</div></div>' . do_action('w2dc_render_term', $term) . '</a></div>';
					echo '</div>';
				echo '</div>';
			}
			
			if ($term = w2dc_getValue($terms, 2)) {
				echo '<div class="w2dc-col-md-3">';
					echo '<div class="' . $this->column_classes . '">';
						echo '<div class="' . $this->root_classes . ' ' . $this->item_classes . '" ' . $this->renderFeaturedImage($term) . '><a class="w2dc-grid-item-normal" href="' . get_term_link($term) . '" title="' . $term->name . '"><div class="w2dc-term-label"><div class="w2dc-term-label-justify">' . $this->renderIconImage($term) . $term->name . '&nbsp;' . $this->renderTermCount($term) . '</div></div>' . do_action('w2dc_render_term', $term) . '</a></div>';
					echo '</div>';
				echo '</div>';
			}
		echo '</div>';

		echo '<div class="w2dc-row w2dc-center-grid-view ' . $this->row_classes . '">';
			if ($term = w2dc_getValue($terms, 3)) {
				echo '<div class="w2dc-col-md-7">';
					echo '<div class="' . $this->column_classes . '">';
						echo '<div class="' . $this->root_classes . ' ' . $this->item_classes . '" ' . $this->renderFeaturedImage($term) . '><a class="w2dc-grid-item-normal" href="' . get_term_link($term) . '" title="' . $term->name . '"><div class="w2dc-term-label"><div class="w2dc-term-label-justify">' . $this->renderIconImage($term) . $term->name . '&nbsp;' . $this->renderTermCount($term) . '</div></div>' . do_action('w2dc_render_term', $term) . '</a></div>';
					echo '</div>';
				echo '</div>';
			}
	
			if ($term = w2dc_getValue($terms, 4)) {
				echo '<div class="w2dc-col-md-5">';
					echo '<div class="' . $this->column_classes . '">';
						echo '<div class="' . $this->root_classes . ' ' . $this->item_classes . '" ' . $this->renderFeaturedImage($term) . '><a class="w2dc-grid-item-normal" href="' . get_term_link($term) . '" title="' . $term->name . '"><div class="w2dc-term-label"><div class="w2dc-term-label-justify">' . $this->renderIconImage($term) . $term->name . '&nbsp;' . $this->renderTermCount($term) . '</div></div>' . do_action('w2dc_render_term', $term) . '</a></div>';
					echo '</div>';
				echo '</div>';
			}
		echo '</div>';
	}
}

class w2dc_categories_view extends w2dc_terms_view {
	public $tax = W2DC_CATEGORIES_TAX;
	public $wrapper_classes = 'w2dc-categories-table';
	public $row_classes = 'w2dc-categories-row';
	public $column_classes = 'w2dc-categories-column';
	public $root_classes = 'w2dc-categories-root';
	public $subterms_classes = 'w2dc-subcategories';
	public $item_classes = 'w2dc-category-item';
	public $highlighted_item_classes = 'w2dc-category-highlighted';
	public $term_count_classes = 'w2dc-category-count';
	public $grid_classes = 'w2dc-categories-grid';
	
	public function __construct($params) {
		parent::__construct($params);
		
		$this->view_all_terms = __("View all subcategories ->", "W2DC");
	}
	
	public function getTermIconFile($term_id) {
		if ($file = w2dc_getCategoryIconFile($term_id)) {
			return W2DC_CATEGORIES_ICONS_URL . $file;
		}
	}

	public function getTermImageUrl($term_id, $size) {
		return w2dc_getCategoryImageUrl($term_id, $size);
	}
}

class w2dc_locations_view extends w2dc_terms_view {
	public $tax = W2DC_LOCATIONS_TAX;
	public $wrapper_classes = 'w2dc-locations-table';
	public $row_classes = 'w2dc-locations-row';
	public $column_classes = 'w2dc-locations-column';
	public $root_classes = 'w2dc-locations-root';
	public $subterms_classes = 'w2dc-sublocations';
	public $item_classes = 'w2dc-location-item';
	public $highlighted_item_classes = 'w2dc-location-highlighted';
	public $term_count_classes = 'w2dc-location-count';
	public $grid_classes = 'w2dc-locations-grid';
	
	public function __construct($params) {
		parent::__construct($params);
		
		$this->view_all_terms = __("View all sublocations ->", "W2DC");
	}
	
	public function getTermIconFile($term_id) {
		if ($file = w2dc_getLocationIconFile($term_id)) {
			return W2DC_LOCATIONS_ICONS_URL . $file;
		}
	}

	public function getTermImageUrl($term_id, $size) {
		return w2dc_getLocationImageUrl($term_id, $size);
	}
}

/**
 * count listings in terms according to their directories (on listing save)
 */
add_action('set_object_terms', 'w2dc_count_terms_in_directories', 1, 4);
function w2dc_count_terms_in_directories($object_id, $terms, $tt_ids, $taxonomy) {
	global $w2dc_instance;
	
	if ($w2dc_instance->directories->isMultiDirectory()) {
		if (get_post_type($object_id) == W2DC_POST_TYPE && in_array($taxonomy, array(W2DC_CATEGORIES_TAX, W2DC_LOCATIONS_TAX))) {
			
			$listing = w2dc_getListing($object_id);
			
			if (in_array($listing->post->post_status, array('publish', 'draft'))) {
				$directory_id = $listing->directory->id;
				
				foreach ($terms AS $term_id) {
					$directories_count = get_term_meta($term_id, 'directories_count', true);
					
					if (!is_array($directories_count)) {
						$directories_count = array();
					}
					
					$directories_count[$directory_id][] = $object_id;
					
					$directories_count[$directory_id] = array_unique($directories_count[$directory_id]);
					
					update_term_meta($term_id, 'directories_count', $directories_count);
				}
			}
		}
	}
}

/**
 * count listings in terms according to their directories (on listing save)
 */
add_action('delete_term_relationships', 'w2dc_remove_terms_in_directories', 10, 3);
function w2dc_remove_terms_in_directories($object_id, $tt_ids, $taxonomy) {
	global $wpdb, $w2dc_instance;
	
	if ($w2dc_instance->directories->isMultiDirectory()) {
		if (get_post_type($object_id) == W2DC_POST_TYPE && in_array($taxonomy, array(W2DC_CATEGORIES_TAX, W2DC_LOCATIONS_TAX))) {
			$listing = w2dc_getListing($object_id);
			$directory_id = $listing->directory->id;
			
			foreach ($tt_ids AS $tt_id) {
				if ($term_id = $wpdb->get_var($wpdb->prepare("SELECT term_id FROM $wpdb->term_taxonomy WHERE term_taxonomy_id = %d", $tt_id))) {
					$directories_count = get_term_meta($term_id, 'directories_count', true);
					
					if (is_array($directories_count)) {
						if ($key = array_search($object_id, $directories_count[$directory_id])) {
							unset($directories_count[$directory_id][$key]);
						}
						
						update_term_meta($term_id, 'directories_count', $directories_count);
					}
				}
			}
		}
	}
}

?>