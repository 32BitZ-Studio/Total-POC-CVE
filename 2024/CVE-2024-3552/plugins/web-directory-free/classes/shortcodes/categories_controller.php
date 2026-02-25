<?php 

/**
 *  [webdirectory-categories] shortcode
 *
 *
 */
class w2dc_categories_controller extends w2dc_frontend_controller {

	public function init($args = array()) {
		global $w2dc_instance;
		
		parent::init($args);

		$shortcode_atts = array_merge(array(
				'custom_home' => 0,
				'directory' => 0,
				'parent' => 0,
				'depth' => 1,
				'columns' => 2,
				'count' => 1,
				'hide_empty' => 0,
				'subcats' => 0,
				'categories' => array(),
				'grid' => 0,
				'grid_view' => 0, // 3 types of view
				'icons' => 1,
				'menu' => 0,
				'order' => 'default', // 'default', 'name', 'count'
		), $args);
		$this->args = $shortcode_atts;

		if ($this->args['custom_home']) {
			if ($w2dc_instance->getShortcodeProperty(W2DC_MAIN_SHORTCODE, 'is_category')) {
				$category = $w2dc_instance->getShortcodeProperty(W2DC_MAIN_SHORTCODE, 'category');
				$this->args['parent'] = $category->term_id;
			}

			$this->args['depth'] = w2dc_getValue($args, 'depth', get_option('w2dc_categories_nesting_level'));
			$this->args['columns'] = w2dc_getValue($args, 'columns', get_option('w2dc_categories_columns'));
			$this->args['count'] = w2dc_getValue($args, 'count', get_option('w2dc_show_category_count'));
			$this->args['hide_empty'] = w2dc_getValue($args, 'hide_empty', get_option('w2dc_hide_empty_categories'));
			$this->args['subcats'] = w2dc_getValue($args, 'subcats', get_option('w2dc_subcategories_items'));
			if ($w2dc_instance->current_directory->categories) {
				$this->args['categories'] = implode(',', $w2dc_instance->current_directory->categories);
			}
		}

		if (isset($this->args['categories']) && !is_array($this->args['categories'])) {
			if ($categories = array_filter(explode(',', $this->args['categories']), 'trim')) {
				$this->args['categories'] = $categories;
			}
		}

		apply_filters('w2dc_categories_controller_construct', $this);
	}

	public function display() {
		global $w2dc_instance;
		
		$this->args['max_subterms'] = $this->args['subcats'];
		$this->args['exact_terms'] = $this->args['categories'];

		ob_start();

		if ($this->args['custom_home'] && $w2dc_instance->getShortcodeProperty(W2DC_MAIN_SHORTCODE, 'is_category') && !get_option('w2dc_show_categories_index')) {
			$this->args['depth'] = 1;
		}
		$categories_view = new w2dc_categories_view($this->args);
		$categories_view->display();

		$output = ob_get_clean();

		return $output;
	}
}

?>