<?php 

/**
 *  [webdirectory-page-header] shortcode
 *  
 *  
 */

define('W2DC_FEATURED_SIZE_WIDTH', 1920);
define('W2DC_FEATURED_SIZE_HEIGHT', 700);

class w2dc_page_header_controller extends w2dc_frontend_controller {

	public function init($args = array()) {
		parent::init($args);

		$shortcode_atts = array_merge(array(
				
		), $args);

		$this->args = $shortcode_atts;

		apply_filters('w2dc_page_header_controller_construct', $this);
	}
	
	public function getFeaturedImage() {
		$image_url = '';
		
		if ($listing = w2dc_isListing()) {
			$image_url = $listing->get_logo_url(array(W2DC_FEATURED_SIZE_WIDTH, W2DC_FEATURED_SIZE_HEIGHT));
		}
		if ($category = w2dc_isCategory()) {
			$image_url = w2dc_getCategoryImageUrl($category->term_id, array(W2DC_FEATURED_SIZE_WIDTH, W2DC_FEATURED_SIZE_HEIGHT));
		}
		if ($location = w2dc_isLocation()) {
			$image_url = w2dc_getLocationImageUrl($location->term_id, array(W2DC_FEATURED_SIZE_WIDTH, W2DC_FEATURED_SIZE_HEIGHT));
		}
	
		if (!$image_url) {
			$image_url = get_the_post_thumbnail_url(null, array(W2DC_FEATURED_SIZE_WIDTH, W2DC_FEATURED_SIZE_HEIGHT));
		}
		
		$image_url = apply_filters("w2dc_page_header_image", $image_url);
	
		return $image_url;
	}
	
	public function getPageHeaderTitle($title = '') {
		if ($listing = w2dc_isListing()) {
			$title = $listing->title();
		}
		if ($category = w2dc_isCategory()) {
			$title = $category->name;
		}
		if ($location = w2dc_isLocation()) {
			$title = $location->name;
		}
	
		if (!$title) {
			if (is_front_page() && 'posts' === get_option('show_on_front')) {
				$title = bloginfo('name');
			}
			elseif (is_home() && ($blog_page_id = get_option('page_for_posts')) > 0) {
				$title = bloginfo('name');
			}
			elseif (is_singular()) {
				$title = single_post_title('', false);
				
				$title = apply_filters('w2dc_page_title_singular', $title);
			}
			elseif (is_archive()) {
				$title = strip_tags(get_the_archive_title());
			}
			elseif (is_search()) {
				$title = sprintf( __('Search Results for: %s', 'WDT'), get_search_query());
			}
			elseif (is_404()) {
				$title = __('404!', 'WDT');
			}
		}
		
		$title = apply_filters("w2dc_page_header_title", $title);
	
		return $title;
	}

	public function display() {
		global $w2dc_instance;
		
		return w2dc_renderTemplate('frontend/page_header.tpl.php', array(
			'featured_image' => $this->getFeaturedImage(),
			'page_title' => $this->getPageHeaderTitle(),
			'shortcode_controller' => $this->getShortcodeController(),
		), true);
	}
}

?>