<?php 

/**
 *  [webdirectory-demo-links] shortcode
 *  
 *  
 */

class w2dc_demo_links_controller {
	
	public static $instance;
	
	public $pages = array(
			"directory-classifieds" => "Directory & Classifieds",
			"custom-home-page-1" => "Custom Home Page 1",
			"custom-home-page-2" => "Custom Home Page 2",
			"custom-home-page-3" => "Custom Home Page 3",
			"custom-home-page-4" => "Custom Home Page 4",
			"custom-home-page-5" => "Custom Home Page 5",
			"custom-home-page-6" => "Custom Home Page 6",
			"search-ajax-map-listings" => "Search + AJAX Map + Listings",
			"connected-sticky-shortcodes" => "Connected Sticky Shortcodes",
			"4-columns" => "4 Columns",
			"only-sticky-featured" => "Only Sticky & Featured",
			"geolocation-with-listings" => "Geolocation with Listings",
			"listings-carousel" => "Listings Carousel",
			"webdirectory-search" => "[webdirectory-search]",
			"radius-circle-on-the-map" => "Radius circle on the map",
			"ajax-map" => "Ajax Map",
			"geolocation" => "Geolocation",
			"all-listings-of-location" => "All listings of a location",
			"search-form-on-map" => "Search Form on a map",
			"categories-search-on-map" => "Categories search on map",
			"draw-panel" => "Draw Panel",
			"webdirectory-categories" => "[webdirectory-categories]",
			"webdirectory-locations" => "[webdirectory-locations]",
			"webdirectory-slider" => "[webdirectory-slider]",
			"webdirectory-levels-table" => "[webdirectory-levels-table]",
			"webdirectory-buttons" => "[webdirectory-buttons]",
			"categories-search" => "Categories Search",
			"buttons-colors" => "Buttons & Colors",
			"locations-search-the-map" => "Locations search & the Map",
			"search-in-radius" => "Search in radius",
			"prices-search" => "Prices search",
			"dependent-search" => "Dependent search",
			"datepicker" => "Datepicker",
			"ratings-search" => "Ratings search",
			"more-filters" => "More filters",
			"opened-closed" => "Opened & Closed",
			"checkboxes-search" => "Checkboxes Search",
	);
	
	public $search_forms = array(
			'default' => 'Default',
			'home' => 'Home',
			'home-sidebar' => 'Home sidebar',
			'sidebar' => 'Sidebar',
			'sidebar-sticky' => 'Sidebar (sticky)',
			'on-map' => 'On Map',
			'one-row' => 'One row',
			'one-row-address' => 'One row + address',
			'one-row-sticky' => 'One row (sticky)',
			'checkboxes-search' => 'Checkboxes search',
			'categories-search' => 'Categories search',
			'locations-search' => 'Locations search',
			'search-in-radius' => 'Search in radius',
			'prices-search' => 'Prices search',
			'dependent-search' => 'Dependent search',
			'datepicker' => 'Datepicker',
			'ratings-search' => 'Ratings search',
			'more-filters' => 'More filters',
			'opened-closed' => 'Opened & Closed',
			'categories-on-map' => 'Categories on map',
			'buttons-colors' => 'Buttons & Colors',
	);

	public function init($args = array()) {
		
		apply_filters('w2dc_demo_links_controller_construct', $this);
	}

	public function next_page_slug($offset = 0) {
		$pages = $this->pages;
		$keys = array_keys($pages);
		
		$next_page_slug = $keys[0];
			
		global $post;
		if ($post && ($post_slug = $post->post_name) && array_key_exists($post_slug, $pages)) {
			foreach (array_keys($keys) AS $key) {
				if ($keys[$key] == $post_slug) {
					if (count($keys) <= $key+$offset+1) {
						$next_page_slug = $keys[0];
					} elseif (($key+$offset) == 0) {
						$next_page_slug = $keys[1];
					} else {
						$next_page_slug = $keys[$key+$offset+1];
					}
				}
			}
		}
		
		return $next_page_slug;
	}
	
	public function prev_page_slug($offset = 0) {
		$pages = $this->pages;
		$keys = array_keys($pages);
		
		$prev_page_slug = $keys[count($keys)-1];
			
		global $post;
		if ($post && ($post_slug = $post->post_name) && array_key_exists($post_slug, $pages)) {
			foreach (array_keys($keys) AS $key) {
				if ($keys[$key] == $post_slug) {
					if (count($keys) <= $key-$offset+1) {
						$prev_page_slug = $keys[count($keys)-2];
					} elseif (($key+$offset) == 0) {
						$prev_page_slug = $keys[count($keys)-1];
					} else {
						$prev_page_slug = $keys[$key-$offset-1];
					}
				}
			}
		}
		
		return $prev_page_slug;
	}

	public function display() {
		
		// display demo links only once
		if (!self::$instance) {
			self::$instance = true;
			
			$post_ids = false;
			$i = 0;
			foreach ($this->pages AS $page) {
				$post_ids = get_posts(array(
						'name'				=> $this->next_page_slug($i),
						'post_type'			=> 'page',
						'posts_per_page'	=> 1,
				));
				$i++;
				
				if ($post_ids) {
					break;
				}
			}
			if (!$post_ids) {
				return false;
			}
			$next_page = array_shift($post_ids);
			
			$post_ids = false;
			$i = 0;
			foreach ($this->pages AS $page) {
				$post_ids = get_posts(array(
						'name'				=> $this->prev_page_slug($i),
						'post_type'			=> 'page',
						'posts_per_page'	=> 1,
				));
				$i++;
				
				if ($post_ids) {
					break;
				}
			}
			if (!$post_ids) {
				return false;
			}
			$prev_page = array_shift($post_ids);
			
			return w2dc_renderTemplate("demo_links.tpl.php", array(
					'next_page' => $next_page,
					'prev_page' => $prev_page,
			), true);
		}
	}
}

?>