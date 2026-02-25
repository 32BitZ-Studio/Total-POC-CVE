<?php 

class w2dc_categories_manager {
	
	public function __construct() {
		add_action('add_meta_boxes', array($this, 'removeCategoriesMetabox'));
		add_action('add_meta_boxes', array($this, 'addCategoriesMetabox'));
		
		add_filter('manage_' . W2DC_CATEGORIES_TAX . '_custom_column', array($this, 'taxonomy_rows'), 15, 3);
		add_filter('manage_edit-' . W2DC_CATEGORIES_TAX . '_columns',  array($this, 'taxonomy_columns'));
		add_action(W2DC_CATEGORIES_TAX . '_edit_form_fields', array($this, 'select_icon_form'));
		add_action(W2DC_CATEGORIES_TAX . '_edit_form_fields', array($this, 'select_marker_image_form'));
		add_action(W2DC_CATEGORIES_TAX . '_edit_form_fields', array($this, 'select_marker_icon_form'));
		add_action(W2DC_CATEGORIES_TAX . '_edit_form_fields', array($this, 'select_marker_color_form'));
		add_action(W2DC_CATEGORIES_TAX . '_edit_form_fields', array($this, 'select_image_form'));
		add_action('edit_term', array($this, 'save_image'));

		if (w2dc_isCategoriesEditPageInAdmin()) {
			add_action('admin_enqueue_scripts', array($this, 'admin_enqueue_category_edit_scripts'));
		}

		add_action('wp_ajax_w2dc_select_category_icon_dialog', array($this, 'select_category_icon_dialog'));
		add_action('wp_ajax_w2dc_select_category_icon', array($this, 'select_category_icon'));
		add_action('wp_ajax_w2dc_select_category_marker_png_image_dialog', array($this, 'select_category_marker_png_image_dialog'));
		add_action('wp_ajax_w2dc_select_category_marker_png_image', array($this, 'select_category_marker_png_image'));
		add_action('wp_ajax_w2dc_select_category_marker_icon', array($this, 'select_category_marker_icon'));
		add_action('wp_ajax_w2dc_select_category_marker_color', array($this, 'select_category_marker_color'));
		
		add_filter('manage_' . W2DC_TAGS_TAX . '_custom_column', array($this, 'tags_taxonomy_rows'), 15, 3);
		add_filter('manage_edit-' . W2DC_TAGS_TAX . '_columns',  array($this, 'tags_taxonomy_columns'));

		// 'checked_ontop' for directory categories taxonomy must always be false
		add_filter('wp_terms_checklist_args', array($this, 'unset_checked_ontop'), 100);
	}
	
	// remove native locations taxonomy metabox from sidebar
	public function removeCategoriesMetabox() {
		remove_meta_box(W2DC_CATEGORIES_TAX . 'div', W2DC_POST_TYPE, 'side');
	}

	public function addCategoriesMetabox($post_type) {
		if ($post_type == W2DC_POST_TYPE && ($level = w2dc_getCurrentListingInAdmin()->level) && ($level->categories_number > 0 || $level->unlimited_categories)) {
			add_action('admin_enqueue_scripts', array($this, 'admin_enqueue_scripts_styles'));

			add_meta_box(W2DC_CATEGORIES_TAX,
					__('Listing categories', 'W2DC'),
					'post_categories_meta_box',
					W2DC_POST_TYPE,
					'normal',
					'high',
					array('taxonomy' => W2DC_CATEGORIES_TAX));
		}
	}
	
	public function unset_checked_ontop($args) {
		if (isset($args['taxonomy']) && $args['taxonomy'] == W2DC_CATEGORIES_TAX)
			$args['checked_ontop'] = false;

		return $args;
	}

	public function validateCategories($level, &$postarr, &$errors) {
		global $w2dc_instance;

		if (isset($postarr['tax_input'][W2DC_CATEGORIES_TAX][0]) && $postarr['tax_input'][W2DC_CATEGORIES_TAX][0] == 0)
			unset($postarr['tax_input'][W2DC_CATEGORIES_TAX][0]);

		if (
			$w2dc_instance->content_fields->getContentFieldBySlug('categories_list')->is_required &&
			(
			!isset($postarr['tax_input'][W2DC_CATEGORIES_TAX]) ||
			!is_array($postarr['tax_input'][W2DC_CATEGORIES_TAX]) ||
			!count($postarr['tax_input'][W2DC_CATEGORIES_TAX])
			)
		)
			$errors[] = __('Select at least one category!', 'W2DC');

		if (isset($postarr['tax_input'][W2DC_CATEGORIES_TAX]) && is_array($postarr['tax_input'][W2DC_CATEGORIES_TAX])) {
			if (!$level->unlimited_categories) {
				// remove unauthorized categories
				$postarr['tax_input'][W2DC_CATEGORIES_TAX] = array_slice($postarr['tax_input'][W2DC_CATEGORIES_TAX], 0, $level->categories_number, true);
			}

			if ($level->categories && array_diff($postarr['tax_input'][W2DC_CATEGORIES_TAX], $level->categories)) {
				$errors[] = __('Sorry, you can not choose some categories for this level!', 'W2DC');
			}

			$post_categories_ids = $postarr['tax_input'][W2DC_CATEGORIES_TAX];
		} else
			$post_categories_ids = array();

		return $post_categories_ids;
	}

	public function validateTags($level, &$postarr, &$errors) {
		if (isset($postarr[W2DC_TAGS_TAX]) && $postarr[W2DC_TAGS_TAX]) {
			
			if (!$level->unlimited_tags) {
				// remove unauthorized tags
				$postarr[W2DC_TAGS_TAX] = array_unique($postarr[W2DC_TAGS_TAX]);
				$postarr[W2DC_TAGS_TAX] = array_slice($postarr[W2DC_TAGS_TAX], 0, $level->tags_number, true);
			}
			
			$post_tags_ids = array();
			foreach ($postarr[W2DC_TAGS_TAX] AS $tag) {
				if ($term = term_exists($tag, W2DC_TAGS_TAX)) {
					$post_tags_ids[] = intval($term['term_id']);
				} else {
					if ($newterm = wp_insert_term($tag, W2DC_TAGS_TAX))
						if (!is_wp_error($newterm))
							$post_tags_ids[] = intval($newterm['term_id']);
				}
			}
		} else
			$post_tags_ids = array();

		return $post_tags_ids;
	}
	
	public function tags_taxonomy_columns($original_columns) {
		$new_columns = $original_columns;
		array_splice($new_columns, 1);
		$new_columns['w2dc_tags_id'] = __('Tag ID', 'W2DC');
		return array_merge($new_columns, $original_columns);
	}
	
	public function tags_taxonomy_rows($row, $column_name, $term_id) {
		if ($column_name == 'w2dc_tags_id') {
			return $row . $term_id;
		}
		return $row;
	}
	
	public function taxonomy_columns($original_columns) {
		$new_columns = $original_columns;
		array_splice($new_columns, 1);
		$new_columns['w2dc_category_id'] = __('Category ID', 'W2DC');
		$new_columns['w2dc_category_image'] = __('Image', 'W2DC');
		$new_columns['w2dc_category_icon'] = __('Icon', 'W2DC');
		if (get_option('w2dc_map_markers_type') == 'icons') {
			$new_columns['w2dc_marker_category_icon'] = __('Marker Icon', 'W2DC');
			$new_columns['w2dc_marker_category_color'] = __('Marker Color', 'W2DC');
		} elseif (get_option('w2dc_map_markers_type') == 'images') {
			$new_columns['w2dc_marker_category_image'] = __('Marker Image', 'W2DC');
		}
		if (isset($original_columns['description']))
			unset($original_columns['description']);
		return array_merge($new_columns, $original_columns);
	}
	
	public function taxonomy_rows($row, $column_name, $term_id) {
		if ($column_name == 'w2dc_category_id') {
			return $row . $term_id;
		}
		if ($column_name == 'w2dc_category_image') {
			$url = $this->get_featured_image_url($term_id);
			return $row . '<a href="' . get_edit_term_link($term_id, W2DC_CATEGORIES_TAX, W2DC_POST_TYPE) . '">' . ($url ? '<img src="' . $url . '" width="100" /><br />' : '') . __("Select image", "W2DC") . '</a>';
		}
		if ($column_name == 'w2dc_category_icon') {
			return $row . $this->choose_icon_link($term_id);
		}
		if (get_option('w2dc_map_markers_type') == 'icons') {
			if ($column_name == 'w2dc_marker_category_icon') {
				return $row . $this->choose_marker_icon_link($term_id);
			}
			if ($column_name == 'w2dc_marker_category_color') {
				return $row . $this->choose_marker_icon_color($term_id);
			}
		} elseif (get_option('w2dc_map_markers_type') == 'images') {
			return $row . $this->choose_marker_image($term_id);
		}
		return $row;
	}

	// Category Icon
	public function select_icon_form($term) {
		w2dc_renderTemplate('categories/select_icon_form.tpl.php', array('term' => $term));
	}
	public function choose_icon_link($term_id) {
		$icon_file = $this->getCategoryIconFile($term_id);
		w2dc_renderTemplate('categories/select_icon_link.tpl.php', array('term_id' => $term_id, 'icon_file' => $icon_file));
	}
	public function getCategoryIconFile($term_id) {
		return w2dc_getCategoryIconFile($term_id);
	}
	public function select_category_icon_dialog() {
		$categories_icons = array();
		
		$categories_icons_files = scandir(W2DC_CATEGORIES_ICONS_PATH);
		foreach ($categories_icons_files AS $file) {
			if (is_file(W2DC_CATEGORIES_ICONS_PATH . $file) && $file != '.' && $file != '..') {
				$categories_icons[] = $file;
			}
		}
		
		w2dc_renderTemplate('categories/select_icons_dialog.tpl.php', array('categories_icons' => $categories_icons));
		die();
	}
	public function select_category_icon() {
		if (isset($_POST['category_id']) && is_numeric($_POST['category_id'])) {
			$category_id = intval($_POST['category_id']);
			$icons = (array) get_option('w2dc_categories_icons');
			if (isset($_POST['icon_file']) && $_POST['icon_file']) {
				$icon_file = $_POST['icon_file'];
				if (is_file(W2DC_CATEGORIES_ICONS_PATH . $icon_file)) {
					$icons[$category_id] = $icon_file;
					update_option('w2dc_categories_icons', $icons);
					echo $category_id;
				}
			} else {
				if (isset($icons[$category_id])) {
					unset($icons[$category_id]);
				}
				update_option('w2dc_categories_icons', $icons);
			}
		}
		die();
	}

	// Category Map Marker Image
	public function select_marker_image_form($term) {
		if (get_option('w2dc_map_markers_type') == 'images') {
			w2dc_renderTemplate('categories/select_marker_image_form.tpl.php', array('term' => $term));
		}
	}
	public function choose_marker_image($term_id) {
		if (get_option('w2dc_map_markers_type') == 'images') {
			$image_png_name = $this->getCategoryMarkerImage($term_id);
			w2dc_renderTemplate('categories/select_marker_image_link.tpl.php', array('term_id' => $term_id, 'image_png_name' => $image_png_name));
		}
	}
	public function getCategoryMarkerImage($term_id) {
		if (($images = get_option('w2dc_categories_marker_images')) && is_array($images) && isset($images[$term_id])) {
			return $images[$term_id];
		}
	}
	public function select_category_marker_png_image() {
		if (isset($_POST['category_id']) && is_numeric($_POST['category_id'])) {
			$category_id = intval($_POST['category_id']);
			$markers_images = (array) get_option('w2dc_categories_marker_images');
			if (isset($_POST['image_name']) && $_POST['image_name']) {
				$image_name = $_POST['image_name'];
				$markers_images[$category_id] = $image_name;
				update_option('w2dc_categories_marker_images', $markers_images);
				echo $category_id;
			} else {
				if (isset($markers_images[$category_id])) {
					unset($markers_images[$category_id]);
				}
				update_option('w2dc_categories_marker_images', $markers_images);
			}
		}
		die();
	}
	public function select_category_marker_png_image_dialog() {
		$custom_map_images = array();

		$custom_map_images_themes = scandir(W2DC_MAP_ICONS_PATH . 'icons/');
		foreach ($custom_map_images_themes AS $dir) {
			if (is_dir(W2DC_MAP_ICONS_PATH . 'icons/' . $dir) && $dir != '.' && $dir != '..') {
				$custom_map_images_theme_files = scandir(W2DC_MAP_ICONS_PATH . 'icons/' . $dir);
				foreach ($custom_map_images_theme_files AS $file) {
					if (is_file(W2DC_MAP_ICONS_PATH . 'icons/' . $dir . '/' . $file) && $file != '.' && $file != '..') {
						$custom_map_images[$dir][] = $file;
					}
				}
			} elseif (is_file(W2DC_MAP_ICONS_PATH . 'icons/' . $dir) && $dir != '.' && $dir != '..') {
				$custom_map_images['..'][] = $dir;
			}
		}
		
		w2dc_renderTemplate('categories/select_marker_image_dialog.tpl.php', array('custom_map_images' => $custom_map_images));
		die();
	}
	
	// Category Map Marker Icon
	public function select_marker_icon_form($term) {
		if (get_option('w2dc_map_markers_type') == 'icons') {
			w2dc_renderTemplate('categories/select_marker_icon_form.tpl.php', array('term' => $term));
		}
	}
	public function choose_marker_icon_link($term_id) {
		if (get_option('w2dc_map_markers_type') == 'icons') {
			$icon_name = $this->getCategoryMarkerIcon($term_id);
			w2dc_renderTemplate('categories/select_marker_icon_link.tpl.php', array('term_id' => $term_id, 'icon_name' => $icon_name));
		}
	}
	public function getCategoryMarkerIcon($term_id) {
		if (($icons = get_option('w2dc_categories_marker_icons')) && is_array($icons) && isset($icons[$term_id])) {
			return $icons[$term_id];
		}
	}
	public function select_category_marker_icon() {
		if (isset($_POST['category_id']) && is_numeric($_POST['category_id'])) {
			$category_id = intval($_POST['category_id']);
			$markers_icons = (array) get_option('w2dc_categories_marker_icons');
			if (isset($_POST['icon_name']) && $_POST['icon_name']) {
				$icon_name = $_POST['icon_name'];
				if (in_array($icon_name, w2dc_get_fa_icons_names())) {
					$markers_icons[$category_id] = $icon_name;
					update_option('w2dc_categories_marker_icons', $markers_icons);
					echo $category_id;
				}
			} else {
				if (isset($markers_icons[$category_id])) {
					unset($markers_icons[$category_id]);
				}
				update_option('w2dc_categories_marker_icons', $markers_icons);
			}
		}
		die();
	}

	// Category Map Marker Color
	public function select_marker_color_form($term) {
		if (get_option('w2dc_map_markers_type') == 'icons') {
			w2dc_renderTemplate('categories/select_marker_color_form.tpl.php', array('term' => $term));
		}
	}
	public function choose_marker_icon_color($term_id) {
		$color = $this->getCategoryMarkerColor($term_id);
		w2dc_renderTemplate('categories/select_marker_color_link.tpl.php', array('term_id' => $term_id, 'color' => $color));
	}
	public function getCategoryMarkerColor($term_id) {
		if (($colors = get_option('w2dc_categories_marker_colors')) && is_array($colors) && isset($colors[$term_id]))
			return $colors[$term_id];
	}
	public function select_category_marker_color() {
		if (isset($_POST['category_id']) && is_numeric($_POST['category_id'])) {
			$category_id = intval($_POST['category_id']);
			$markers_colors = (array) get_option('w2dc_categories_marker_colors');
			if (isset($_POST['color']) && $_POST['color']) {
				$color = sanitize_hex_color($_POST['color']);
				$markers_colors[$category_id] = $color;
				update_option('w2dc_categories_marker_colors', $markers_colors);
				echo $category_id;
			} else {
				if (isset($markers_colors[$category_id])) {
					unset($markers_colors[$category_id]);
				}
				update_option('w2dc_categories_marker_colors', $markers_colors);
			}
		}
		die();
	}
	
	// Category Featured Image
	public function get_featured_image_id($term_id) {
		if (($images = get_option('w2dc_categories_images')) && is_array($images) && isset($images[$term_id])) {
			return $images[$term_id];
		}
	}
	public function get_featured_image_url($term_id, $size = 'full') {
		if ($image_id = $this->get_featured_image_id($term_id)) {
			$src = wp_get_attachment_image_src($image_id, $size);
			return is_array($src) ? $src[0] : null;
		}
	}
	public function select_image_form($term) {
		$attachment_id = $this->get_featured_image_id($term->term_id);
		$image_url = $this->get_featured_image_url($term->term_id);

		w2dc_renderTemplate('categories/select_image_form.tpl.php', array('term' => $term, 'attachment_id' => $attachment_id, 'image_url' => $image_url));
	}
	public function save_image($term_id) {
		// Ignore quick edit
		if (isset($_POST['action']) && $_POST['action'] == 'inline-save-tax') {
			return;
		}
		
		$attachment_id = isset($_POST['category_image_attachment_id']) ? (int)$_POST['category_image_attachment_id'] : null;
		
		$categories_images = (array) get_option('w2dc_categories_images');
		if (!empty($attachment_id)) {
			$categories_images[$term_id] = $attachment_id;
		} else {
			if (isset($categories_images[$term_id])) {
				unset($categories_images[$term_id]);
			}
		}
		update_option('w2dc_categories_images', $categories_images);
	}
	
	public function admin_enqueue_category_edit_scripts() {
		wp_enqueue_script('w2dc_categories_edit_scripts');
		wp_localize_script(
				'w2dc_categories_edit_scripts',
				'categories_icons',
				array(
						'categories_icons_url' => W2DC_CATEGORIES_ICONS_URL,
						'categories_markers_images_png_url' => W2DC_MAP_ICONS_URL . 'icons/',
						'ajax_dialog_title' => __('Select category icon', 'W2DC'),
						'ajax_marker_dialog_title' => __('Select marker', 'W2DC'),
				)
		);
		wp_enqueue_style('wp-color-picker');
		wp_enqueue_script('wp-color-picker');
		wp_enqueue_media();
	}
	
	public function admin_enqueue_scripts_styles() {
		wp_enqueue_script('w2dc_categories_scripts');

		if ($listing = w2dc_getCurrentListingInAdmin()) {
			if ($listing->level->unlimited_categories)
				$categories_number = 'unlimited';
			else 
				$categories_number = $listing->level->categories_number;

			wp_localize_script(
					'w2dc_categories_scripts',
					'level_categories',
					array(
							'level_categories_array' => $listing->level->categories,
							'level_categories_number' => $categories_number,
							'level_categories_notice_disallowed' => __('Sorry, you can not choose this category for this level!', 'W2DC'),
							'level_categories_notice_number' => sprintf(__('Sorry, you can not choose more than %d categories!', 'W2DC'), $categories_number)
					)
			);
		}
	}
}

?>