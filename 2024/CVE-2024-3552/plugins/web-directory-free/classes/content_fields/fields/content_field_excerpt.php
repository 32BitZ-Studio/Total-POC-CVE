<?php 

class w2dc_content_field_excerpt extends w2dc_content_field {
	protected $can_be_ordered = false;
	protected $is_categories = false;
	protected $is_slug = false;
	
	public function isNotEmpty($listing) {
		if (post_type_supports(W2DC_POST_TYPE, 'excerpt') && ($listing->post->post_excerpt || (get_option('w2dc_cropped_content_as_excerpt') && $listing->post->post_content !== '')))
			return true;
		else
			return false;
	}

	public function validateValues(&$errors, $data) {
		$listing = w2dc_getCurrentListingInAdmin();
		if (post_type_supports(W2DC_POST_TYPE, 'excerpt') && $this->is_required && (!isset($data['post_excerpt']) || !$data['post_excerpt']))
			$errors[] = __('Listing excerpt is required', 'W2DC');
		else
			return $listing->post->post_excerpt;
	}
	
	public function renderOutput($listing, $group = null, $css_classes = '') {
		if (!($template = w2dc_isTemplate('content_fields/fields/excerpt_output_'.$this->id.'.tpl.php'))) {
			$template = 'content_fields/fields/excerpt_output.tpl.php';
		}
		
		$template = apply_filters('w2dc_content_field_output_template', $template, $this, $listing, $group);
		
		if (has_excerpt() || (get_option('w2dc_cropped_content_as_excerpt') && get_post()->post_content !== '')) {
			$content = w2dc_crop_content($listing->post->ID, get_option('w2dc_excerpt_length'), get_option('w2dc_strip_excerpt'), $listing->level->listings_own_page, $listing->level->nofollow);
		} else {
			$content = get_post()->post_excerpt;
		}
		
		w2dc_renderTemplate($template, array('content' => $content, 'content_field' => $this, 'listing' => $listing, 'group' => $group, 'css_classes' => $css_classes));
		
		/* $query = new WP_Query('name=' . $listing->post->post_name . '&post_type=' . W2DC_POST_TYPE);
		while ($query->have_posts()) {
			$query->the_post();
			w2dc_renderTemplate($template, array('content_field' => $this, 'listing' => $listing, 'group' => $group, 'css_classes' => $css_classes));
			break;
		}
		wp_reset_postdata(); */
	}
	
	public function renderOutputForMap($location, $listing) {
		if (get_option('w2dc_cropped_content_as_excerpt') && $listing->post->post_content !== '') {
			return w2dc_crop_content($listing->post->ID, get_option('w2dc_excerpt_length'), get_option('w2dc_strip_excerpt'), $listing->level->listings_own_page, $listing->level->nofollow);
		} elseif ($listing->post->post_excerpt) {
			return $listing->post->post_excerpt;
		}
	}
}
?>