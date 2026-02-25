<?php 

class w2dc_post {
	public $post;
	public $logo_image = false;
	
	/**
	 * Set post by object or ID and return object
	 * 
	 * @param mixed $post
	 * @return WP_Post, false
	 */
	public function setPost($post) {
		if (is_object($post)) {
			$this->post = $post;
			return $this->post;
		} elseif (is_numeric($post)) {
			if (!($this->post = get_post($post))) {
				return false;
			} else {
				return $this->post;
			}
		}
	}
	
	public function title() {
		$title = get_the_title($this->post);
		
		$title = apply_filters('w2dc_post_title', $title, $this);
		
		return $title;
	}
	
	public function url() {
		$permalink = get_permalink($this->post->ID);
		
		$permalink = apply_filters('w2dc_post_url', $permalink, $this);
		
		return $permalink;
	}

	public function getExcerptFromContent($words_length = 35) {
		$the_excerpt = strip_tags(strip_shortcodes($this->post->post_content));
		$words = explode(' ', $the_excerpt, $words_length + 1);
		if (count($words) > $words_length) {
			array_pop($words);
			array_push($words, '...');
			$the_excerpt = implode(' ', $words);
		}
		
		$the_excerpt = apply_filters('w2dc_get_excerpt_from_content', $the_excerpt, $words_length, $this);
		
		return $the_excerpt;
	}
	
	public function get_logo_url($size = 'full') {
		if ($this->logo_image && ($img = wp_get_attachment_image_src($this->logo_image, $size))) {
			return $img[0];
		}
	}
	
	public function increaseClicksStats() {
		
		$date = date('n-Y');
		$clicks_data = (array) get_post_meta($this->post->ID, '_clicks_data', true); // manual conversion to array is required due to "A non well formed numeric value encountered" notice
		
		if (isset($clicks_data[$date])) {
			$clicks_data[$date]++;
		} else {
			$clicks_data[$date] = 1;
		}
		update_post_meta($this->post->ID, '_clicks_data', $clicks_data);
	
		$total_clicks = get_post_meta($this->post->ID, '_total_clicks', true);
		
		if ($total_clicks) {
			$total_clicks++;
		} else {
			$total_clicks = 1;
		}
		update_post_meta($this->post->ID, '_total_clicks', $total_clicks);
	
		do_action('w2dc_increase_click_stats', $this);
	}
}

?>