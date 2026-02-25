<?php

class w2dc_avg_rating {
	public $ratings = array();
	public $ratings_count = 0;
	public $avg_value = 0;
	
	private $post_id;
	
	public function __construct($post_id) {
		global $wpdb;
		
		$this->post_id = $post_id;
	
		$like = $wpdb->esc_like(W2DC_RATING_PREFIX);
		
		$results = $wpdb->get_results($wpdb->prepare("SELECT * FROM {$wpdb->postmeta} WHERE post_id=%d AND meta_key LIKE %s", $post_id, $like.'%'), ARRAY_A);
		foreach ($results AS $row) {
			$rating = new w2dc_rating($row);
			$this->ratings[] = $rating;
			$this->avg_value += $rating->value;
			$this->ratings_count++;
		}
		if ($this->ratings_count) {
			$this->avg_value = $this->avg_value/$this->ratings_count;
		}
		$this->avg_value = number_format(round($this->avg_value, 1), 1);
	}
	
	public function update_avg_rating() {
		update_post_meta($this->post_id, W2DC_AVG_RATING_KEY, $this->avg_value);
	}
	
	public function render_star($star_num) {
		$sub = $this->avg_value - $star_num;
		if ($sub >= 0 || abs($sub) <= 0.25) {
			return 'w2dc-fa-star';
		} elseif (abs($sub) >= 0.25 && abs($sub) <= 0.75) {
			return 'w2dc-fa-star-half-o';
		} else {
			return 'w2dc-fa-star-o';
		}
	}
	
	public function get_percents_counts($counts) {
		if ($this->ratings) {
			return round($counts/$this->ratings_count*100);
		} else {
			return 0;
		}
	}
	
	public function calculateTotals() {
		$total_counts = array('1' => 0, '2' => 0, '3' => 0, '4' => 0, '5' => 0);
		foreach ($this->ratings AS $rating) {
			$total_counts[round($rating->value)]++;
		}
		krsort($total_counts);
		
		return $total_counts;
	}
}

class w2dc_rating {
	public $user_id;
	public $ip;
	public $value;

	private static $validation;

	public function __construct($row) {
		$this->value = $row['meta_value'];
		
		$part = str_replace(W2DC_RATING_PREFIX, '', $row['meta_key']);

		if (!self::$validation) {
			self::$validation = new w2dc_form_validation();
		}

		if (self::$validation->valid_ip($part)) {
			$this->ip = $part;
		} else {
			$this->user_id = $part;
		}
	}
	
	public function render_star($star_num) {
		if ($this->value >= $star_num) {
			return 'w2dc-fa-star';
		} else {
			return 'w2dc-fa-star-o';
		}
	}
}

function w2dc_build_single_rating($post_id, $user_id) {
	global $wpdb;
	
	if ($row = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->postmeta} WHERE post_id=%d AND meta_key=%s", $post_id, W2DC_RATING_PREFIX.$user_id), ARRAY_A)) {
		$rating = new w2dc_rating($row);
		return $rating;
	}
}

function w2dc_reset_ratings($post_id) {
	global $wpdb;
	
	return ($wpdb->query($wpdb->prepare("DELETE FROM {$wpdb->postmeta} WHERE post_id=%d AND (meta_key=%s OR meta_key LIKE %s)", $post_id, W2DC_AVG_RATING_KEY, W2DC_RATING_PREFIX.'%')) !== false) ? true : false;
}

?>