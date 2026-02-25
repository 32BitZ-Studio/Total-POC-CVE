<?php 

/**
 *  [wcsearch-demo-links] shortcode
 *  
 *  
 */

class wcsearch_demo_links_controller {
	
	public static $instance;
	
	public $pages = array(
			"search-products" => "Search products",
			"prices-search" => "Prices search",
			"categories-search" => "Categories search",
			"attributes-search" => "Attributes search",
			"scrolling-sidebar" => "Scrolling sidebar",
			"dependent-search" => "Dependent search",
			"more-filters-button" => "More filters button",
			"opened-closed" => "Opened & closed",
			"options-ratings" => "Options & ratings",
			"top-search-bar" => "Top search bar",
			"keywords-search" => "Keywords search",
			"predefined-category" => "Predefined category",
	);
	
	public $search_forms = array(
			'search-products' => 'Search products',
			'prices' => 'Prices',
			'categories' => 'Categories',
			'attributes' => 'Attributes',
			'scrolling-sidebar' => 'Scrolling sidebar',
			'dependency' => 'Dependency',
			'more-filters' => 'More filters',
			'opened-and-closed' => 'Opened and closed',
			"options-and-ratings" => "Options and ratings",
			'keywords-search-reset' => 'keywords+search+reset',
			'top-search-bar' => 'Top search bar',
	);

	public function init($args = array()) {
		
		apply_filters('wcsearch_demo_links_controller_construct', $this);
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
					if (count($keys) <= $key-$offset+1 && isset($keys[count($keys)-2])) {
						$prev_page_slug = $keys[count($keys)-2];
					} elseif (($key+$offset) == 0 && isset($keys[count($keys)-1])) {
						$prev_page_slug = $keys[count($keys)-1];
					} elseif (isset($keys[$key-$offset-1])) {
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
			
			return wcsearch_renderTemplate("demo_links.tpl.php", array(
					'next_page' => $next_page,
					'prev_page' => $prev_page,
			), true);
		}
	}
}

?>