<?php

class w2dc_elementor_widgets {

	protected static $instance = null;

	public static function get_instance() {
		if ( ! isset( static::$instance ) ) {
			static::$instance = new static;
		}

		return static::$instance;
	}

	protected function __construct() {
		require_once(W2DC_PATH . 'classes/widgets/elementor/widgets/elementor_widget.php');
		
		require_once(W2DC_PATH . 'classes/widgets/elementor/widgets/breadcrumbs.php');
		require_once(W2DC_PATH . 'classes/widgets/elementor/widgets/breadcrumbs.php');
		require_once(W2DC_PATH . 'classes/widgets/elementor/widgets/buttons.php');
		require_once(W2DC_PATH . 'classes/widgets/elementor/widgets/categories_sidebar.php');
		require_once(W2DC_PATH . 'classes/widgets/elementor/widgets/categories.php');
		require_once(W2DC_PATH . 'classes/widgets/elementor/widgets/content_field.php');
		require_once(W2DC_PATH . 'classes/widgets/elementor/widgets/content_fields_group.php');
		require_once(W2DC_PATH . 'classes/widgets/elementor/widgets/directory.php');
		require_once(W2DC_PATH . 'classes/widgets/elementor/widgets/levels_table.php');
		require_once(W2DC_PATH . 'classes/widgets/elementor/widgets/listing_comments.php');
		require_once(W2DC_PATH . 'classes/widgets/elementor/widgets/listing_contact.php');
		require_once(W2DC_PATH . 'classes/widgets/elementor/widgets/listing_fields.php');
		require_once(W2DC_PATH . 'classes/widgets/elementor/widgets/listing_gallery.php');
		require_once(W2DC_PATH . 'classes/widgets/elementor/widgets/listing_header.php');
		require_once(W2DC_PATH . 'classes/widgets/elementor/widgets/listing_map.php');
		require_once(W2DC_PATH . 'classes/widgets/elementor/widgets/listing_page.php');
		require_once(W2DC_PATH . 'classes/widgets/elementor/widgets/listing_report.php');
		require_once(W2DC_PATH . 'classes/widgets/elementor/widgets/listing_videos.php');
		require_once(W2DC_PATH . 'classes/widgets/elementor/widgets/listings_sidebar.php');
		require_once(W2DC_PATH . 'classes/widgets/elementor/widgets/listings.php');
		require_once(W2DC_PATH . 'classes/widgets/elementor/widgets/locations_sidebar.php');
		require_once(W2DC_PATH . 'classes/widgets/elementor/widgets/locations.php');
		require_once(W2DC_PATH . 'classes/widgets/elementor/widgets/map.php');
		require_once(W2DC_PATH . 'classes/widgets/elementor/widgets/search.php');
		require_once(W2DC_PATH . 'classes/widgets/elementor/widgets/slider.php');
		require_once(W2DC_PATH . 'classes/widgets/elementor/widgets/page_header.php');

		add_action('elementor/widgets/register', array($this, 'register_widgets'));
	}

	public function register_widgets() {

		\Elementor\Plugin::instance()->widgets_manager->register( new w2dc_breadcrumbs_elementor_widget() );
		\Elementor\Plugin::instance()->widgets_manager->register( new w2dc_buttons_elementor_widget() );
		\Elementor\Plugin::instance()->widgets_manager->register( new w2dc_categories_sidebar_elementor_widget() );
		\Elementor\Plugin::instance()->widgets_manager->register( new w2dc_categories_elementor_widget() );
		\Elementor\Plugin::instance()->widgets_manager->register( new w2dc_content_field_elementor_widget() );
		\Elementor\Plugin::instance()->widgets_manager->register( new w2dc_content_fields_group_elementor_widget() );
		\Elementor\Plugin::instance()->widgets_manager->register( new w2dc_directory_elementor_widget() );
		\Elementor\Plugin::instance()->widgets_manager->register( new w2dc_levels_table_elementor_widget() );
		\Elementor\Plugin::instance()->widgets_manager->register( new w2dc_listing_comments_elementor_widget() );
		\Elementor\Plugin::instance()->widgets_manager->register( new w2dc_listing_contact_elementor_widget() );
		\Elementor\Plugin::instance()->widgets_manager->register( new w2dc_listing_fields_elementor_widget() );
		\Elementor\Plugin::instance()->widgets_manager->register( new w2dc_listing_gallery_elementor_widget() );
		\Elementor\Plugin::instance()->widgets_manager->register( new w2dc_listing_header_elementor_widget() );
		\Elementor\Plugin::instance()->widgets_manager->register( new w2dc_listing_map_elementor_widget() );
		\Elementor\Plugin::instance()->widgets_manager->register( new w2dc_listing_page_elementor_widget() );
		\Elementor\Plugin::instance()->widgets_manager->register( new w2dc_listing_report_elementor_widget() );
		\Elementor\Plugin::instance()->widgets_manager->register( new w2dc_listing_videos_elementor_widget() );
		\Elementor\Plugin::instance()->widgets_manager->register( new w2dc_listings_sidebar_elementor_widget() );
		\Elementor\Plugin::instance()->widgets_manager->register( new w2dc_listings_elementor_widget() );
		\Elementor\Plugin::instance()->widgets_manager->register( new w2dc_locations_sidebar_elementor_widget() );
		\Elementor\Plugin::instance()->widgets_manager->register( new w2dc_locations_elementor_widget() );
		\Elementor\Plugin::instance()->widgets_manager->register( new w2dc_map_elementor_widget() );
		\Elementor\Plugin::instance()->widgets_manager->register( new w2dc_search_elementor_widget() );
		\Elementor\Plugin::instance()->widgets_manager->register( new w2dc_slider_elementor_widget() );
		\Elementor\Plugin::instance()->widgets_manager->register( new w2dc_page_header_elementor_widget() );
	}

}

function w2dc_load_elementor_widgets() {
	
	if (!defined('ELEMENTOR_VERSION')) {
		return;
	}

	w2dc_elementor_widgets::get_instance();
}
add_action('init', 'w2dc_load_elementor_widgets');

function w2dc_add_elementor_widget_categories($elements_manager) {

	$elements_manager->add_category(
			'directory-category',
			array(
				'title' => esc_html__('Directory elements', 'W2DC'),
				'icon' => 'eicon-code',
			)
	);
	
	$elements_manager->add_category(
			'directory-single-category',
			array(
				'title' => esc_html__('Directory single listing', 'W2DC'),
				'icon' => 'eicon-code',
			)
	);
}
add_action('elementor/elements/categories_registered', 'w2dc_add_elementor_widget_categories');


function w2dc_elementor_convert_params($params) {
	
	$el_params = array();
	
	foreach ($params AS $param) {
		
		$new_param = array(
				'type' => \Elementor\Controls_Manager::TEXT,
		);
		
		if (!empty($param['heading'])) {
			$new_param['label'] = $param['heading'];
		}
		if (!empty($param['description'])) {
			$new_param['description'] = $param['description'];
		}
		if (!empty($param['value'])) {
			$new_param['default'] = $param['value'];
		}
		
		switch ($param['type']) {
			
			case 'textarea':
				$new_param['type'] = \Elementor\Controls_Manager::TEXTAREA;
			break;
			
			case 'formid':
				$new_param['options'] = w2dc_elementor_get_formids();
				$new_param['type'] = \Elementor\Controls_Manager::SELECT;
			break;
			
			case 'mapstyle':
				$new_param['options'] = w2dc_elementor_get_mapstyles();
				$new_param['type'] = \Elementor\Controls_Manager::SELECT;
			break;
			
			case 'level':
				$new_param['options'] = w2dc_elementor_get_levels();
				$new_param['type'] = \Elementor\Controls_Manager::SELECT;
			break;
			
			case 'levels':
				$new_param['options'] = w2dc_elementor_get_levels();
				$new_param['type'] = \Elementor\Controls_Manager::SELECT2;
				$new_param['multiple'] = true;
				$new_param['default'] = array();
			break;
			
			case 'categoryfield':
				$new_param['options'] = w2dc_elementor_get_terms(W2DC_CATEGORIES_TAX);
				$new_param['type'] = \Elementor\Controls_Manager::SELECT;
			break;
			
			case 'categoriesfield':
				$new_param['options'] = w2dc_elementor_get_terms(W2DC_CATEGORIES_TAX);
				$new_param['type'] = \Elementor\Controls_Manager::SELECT2;
				$new_param['multiple'] = true;
				$new_param['default'] = array();
			break;
			
			case 'locationfield':
				$new_param['options'] = w2dc_elementor_get_terms(W2DC_LOCATIONS_TAX);
				$new_param['type'] = \Elementor\Controls_Manager::SELECT;
			break;
			
			case 'locationsfield':
				$new_param['options'] = w2dc_elementor_get_terms(W2DC_LOCATIONS_TAX);
				$new_param['type'] = \Elementor\Controls_Manager::SELECT2;
				$new_param['multiple'] = true;
				$new_param['default'] = array();
			break;
			
			case 'directory':
				$new_param['options'] = array(0 => esc_html__("- Auto -", "W2DC")) + w2dc_elementor_get_directories();
				$new_param['type'] = \Elementor\Controls_Manager::SELECT;
			break;
			
			case 'directories':
				if ($directories = w2dc_elementor_get_directories()) {
					$new_param['options'] = w2dc_elementor_get_directories();
					$new_param['type'] = \Elementor\Controls_Manager::SELECT2;
					$new_param['multiple'] = true;
				}
			break;
				
			case 'ordering':
				$new_param['options'] = w2dc_elementor_get_ordering();
				$new_param['type'] = \Elementor\Controls_Manager::SELECT;
			break;
			
			case 'contentfield':
				$new_param['options'] = w2dc_elementor_get_content_fields();
				$new_param['type'] = \Elementor\Controls_Manager::SELECT;
			break;
			
			case 'contentfields':
				$new_param['options'] = w2dc_elementor_get_content_fields();
				$new_param['type'] = \Elementor\Controls_Manager::SELECT2;
				$new_param['multiple'] = true;
			break;
			
			case 'contentfieldsgroup':
				$new_param['options'] = w2dc_elementor_get_content_fields_groups();
				$new_param['type'] = \Elementor\Controls_Manager::SELECT;
			break;
			
			case 'datefieldmin':
			case 'datefieldmax':
				$new_param['type'] = \Elementor\Controls_Manager::DATE_TIME;
				$new_param['picker_options'] = array('enableTime' => false);
			break;
			
			case 'dropdown':
				if (!empty($param['value']) && is_array($param['value'])) {
					$new_param['options'] = array_flip($param['value']);
					$new_param['type'] = \Elementor\Controls_Manager::SELECT;
				}
				
				break;
				
			case 'checkbox':
				if (!empty($param['value']) && is_array($param['value'])) {
					if (count($param['value']) == 2) {
						$new_param['options'] = array_flip($param['value']);
						$new_param['type'] = \Elementor\Controls_Manager::SELECT;
					} else {
						$new_param['options'] = array_flip($param['value']);
						$new_param['type'] = \Elementor\Controls_Manager::SELECT2;
						$new_param['multiple'] = true;
						$new_param['default'] = array();
					}
				} elseif(!is_array($param['value'])) {
					$new_param['type'] = \Elementor\Controls_Manager::SWITCHER;
				}
				
			break;
		}
		
		if (!empty($param['std'])) {
			$new_param['default'] = $param['std'];
		} else {
			if ($new_param['type'] == \Elementor\Controls_Manager::SELECT && !empty($new_param['options'])) {
				$_options = $new_param['options'];
				reset($_options);
				$new_param['default'] = key($_options) . '';
			}
		}
		
		if (!empty($param['dependency'])) {
			$dep_param_name = $param['dependency']['element'];
			$dep_param_value = $param['dependency']['value'];
			$new_param['condition'] = array($dep_param_name => $dep_param_value);
		}
		
		$new_param['label_block'] = true;
		
		$el_params[$param['param_name']] = $new_param;
	}
	
	return $el_params;
}

function w2dc_elementor_get_content_fields() {
	
	global $w2dc_instance;
	
	$content_fields = array(0 => esc_html__("- Select field -", "W2DC"));
	
	foreach ($w2dc_instance->content_fields->content_fields_array AS $content_field) {
		$content_fields[$content_field->id] = $content_field->name;
	}
	
	return $content_fields;
}

function w2dc_elementor_get_content_fields_groups() {
	
	global $w2dc_instance;
	
	$content_fields_groups = array(0 => esc_html__("- Select group -", "W2DC"));
	
	foreach ($w2dc_instance->content_fields->content_fields_groups_array AS $content_fields_group) {
		$content_fields_groups[$content_fields_group->id] = $content_fields_group->name;
	}
	
	return $content_fields_groups;
}

function w2dc_elementor_get_ordering() {
	
	$ordering = array(0 => esc_html__("- Default -", "W2DC"));
	
	$_ordering = w2dc_orderingItems();
	
	foreach ($_ordering AS $ordering_item) {
		$ordering[$ordering_item['value']] = $ordering_item['label'];
	}
	
	return $ordering;
}

function w2dc_elementor_get_directories() {
	
	global $w2dc_instance;
	
	$directories = array();
	
	if ($w2dc_instance->directories->isMultiDirectory()) {
		
		foreach ($w2dc_instance->directories->directories_array AS $directory) {
			$directories[$directory->id] = $directory->name;
		}
	}
	
	return $directories;
}

function w2dc_elementor_get_terms($tax, $parent = 0, &$options = array(), $level = 0) {
	
	$terms = get_terms(array(
			'taxonomy' => $tax,
			'parent' => $parent,
			'hide_empty' => false,
			'orderby' => 'name',
	));

	foreach ($terms AS $term) {
		$options[" $term->term_id"] = str_repeat("-&nbsp;", $level) . $term->name;
		
		w2dc_elementor_get_terms($tax, $term->term_id, $options, $level+1);
	}
	
	return (array) $options;
}

function w2dc_elementor_get_levels() {
	
	global $w2dc_instance;
	
	$levels = array();
	
	foreach ($w2dc_instance->levels->levels_array AS $level) {
		$levels[" $level->id"] = $level->name;
	}
	
	return $levels;
}

function w2dc_elementor_get_mapstyles() {
	
	if (w2dc_getMapEngine()) {

		$styles = array(0 => esc_html__("- Default -", "W2DC"));
			
		foreach (w2dc_getAllMapStyles() AS $style_name=>$style) {
			$styles[$style_name] = $style;
		}
	}
}

function w2dc_elementor_get_formids() {
	
	$search_forms = array();
	
	foreach (wcsearch_get_search_forms_posts() AS $id=>$title) {
		$search_forms[$id] = $title;
	}
	
	return $search_forms;
}

?>