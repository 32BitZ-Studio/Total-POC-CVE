<?php 

class w2dc_content_field_content extends w2dc_content_field {
	protected $can_be_ordered = false;
	protected $is_categories = false;
	protected $is_slug = false;
	
	public function isNotEmpty($listing) {
		if (post_type_supports(W2DC_POST_TYPE, 'editor') && !empty($listing->post->post_content))
			return true;
		else
			return false;
	}

	public function validateValues(&$errors, $data) {
		$listing = w2dc_getCurrentListingInAdmin();
		if (post_type_supports(W2DC_POST_TYPE, 'editor') && $this->is_required && (!isset($data['post_content']) || !$data['post_content']))
			$errors[] = __('Listing content is required', 'W2DC');
		else
			return $listing->post->post_content;
	}
	
	public function renderOutput($listing, $group = null, $css_classes = '') {
		add_filter('the_content', 'wpautop');
		if (!get_option('w2dc_enable_html_description')) {
			remove_filter('the_content', 'do_shortcode', 11);
		}
		
		if (!($template = w2dc_isTemplate('content_fields/fields/content_output_'.$this->id.'.tpl.php'))) {
			$template = 'content_fields/fields/content_output.tpl.php';
		}
		
		$template = apply_filters('w2dc_content_field_output_template', $template, $this, $listing, $group);
		
		$query = new WP_Query('name=' . $listing->post->post_name . '&post_type=' . W2DC_POST_TYPE);
		while ($query->have_posts()) {
			$query->the_post();
			
			global $w2dc_do_listing_content;
			$w2dc_do_listing_content = true;
			$content = apply_filters('the_content', get_the_content());
			$w2dc_do_listing_content = false;
			
			if (!get_option('w2dc_enable_html_description')) {
				$content = strip_tags($content, '<p>');
			}
			
			w2dc_renderTemplate($template, array('content' => $content, 'content_field' => $this, 'listing' => $listing, 'group' => $group, 'css_classes' => $css_classes));
			break;
		}
		
		if (!get_option('w2dc_enable_html_description')) {
			add_filter('the_content', 'do_shortcode', 11);
		}
		remove_filter('the_content', 'wpautop');
		
		// this resets posts data back to the page's global $post,
		// that is why it should be commented to avoid $post mismatch in comments plugins
		//wp_reset_postdata();
	}
	
	public function renderOutputForMap($location, $listing) {
		return wpautop($listing->post->post_content);
	}
}
?>