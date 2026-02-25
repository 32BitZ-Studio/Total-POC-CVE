<?php

class w2dc_listings_packages {
	public $listings_numbers = array();
	
	public function __construct() {
		add_action('show_user_profile', array($this, 'add_user_profile_fields'));
		add_action('edit_user_profile', array($this, 'add_user_profile_fields'));
		add_action('personal_options_update', array($this, 'save_user_profile_fields'));
		add_action('edit_user_profile_update', array($this, 'save_user_profile_fields'));
		
		add_action('w2dc_listing_package_process_activate', array($this, 'listing_activate_package'));
		
		// first of all if user has pre-paid listing(s) - simply activate it after creation
		add_filter('w2dc_listing_creation_front', array($this, 'activate_if_possible'), 1);

		add_action('w2dc_renew_html', array($this, 'renew_html'));
		add_filter('w2dc_listing_renew', array($this, 'renew_listing_order'), 1, 3);

		add_action('w2dc_raise_up_html', array($this, 'raiseup_html'));
		add_filter('w2dc_listing_raiseup', array($this, 'listing_raiseup_order'), 1, 3);

		add_filter('w2dc_level_upgrade_option', array($this, 'level_upgrade_option'), 10, 3);
		add_filter('w2dc_listing_upgrade', array($this, 'listing_upgrade_order'), 1, 3);
	}
	
	public function get_listings_of_user($user_id = false) {
		global $w2dc_instance;

		if (!$user_id) {
			$user_id = get_current_user_id();
		}
	
		foreach ($w2dc_instance->levels->levels_array as $level) {
			$this->listings_numbers[$level->id]['unlimited'] = false;
			$this->listings_numbers[$level->id]['number'] = 0;
			if (get_user_meta($user_id, '_listings_unlimited_'.$level->id, true)) {
				$this->listings_numbers[$level->id]['unlimited'] = true;
			}
			elseif ($listings_number = get_user_meta($user_id, '_listings_number_'.$level->id, true)) {
				$this->listings_numbers[$level->id]['number'] = (int)$listings_number;
			}
		}
		return $this->listings_numbers;
	}
	
	public function is_any_listing_to_create($user_id = false) {
		if (!$user_id) {
			$user_id = get_current_user_id();
		}
		
		$numbers = $this->get_listings_of_user($user_id);
		
		foreach ($numbers AS $level_id=>$listings_number) {
			if ($numbers[$level_id]['unlimited'] || $numbers[$level_id]['number'] > 0) {
				return $level_id;
				break;
			}
		}
	}
	
	public function can_user_create_listing_in_level($level_id, $user_id = false) {
		if (!$user_id) {
			$user_id = get_current_user_id();
		}
	
		$numbers = $this->get_listings_of_user($user_id);
	
		if ($numbers[$level_id]['unlimited'] || $numbers[$level_id]['number'] > 0) {
			return true;
		}
	}
	
	public function process_listing_creation_for_user($level_id, $user_id = false) {
		if (!$user_id) {
			$user_id = get_current_user_id();
		}
	
		$numbers = $this->get_listings_of_user($user_id);
		if (!$numbers[$level_id]['unlimited']) {
			update_user_meta($user_id, '_listings_number_'.$level_id, $numbers[$level_id]['number'] - 1);
			$this->listings_numbers[$level_id]['number'] = $numbers[$level_id]['number'] - 1;
		}
	}

	public function listing_activate_package($listing) {
		if ($listing->level->listings_in_package > 1) {
			$level_id = $listing->level->id;
			$user_id = $listing->post->post_author;
			
			$listings_numbers = $this->get_listings_of_user($user_id);
			update_user_meta($user_id, '_listings_number_'.$level_id, $listings_numbers[$level_id]['number'] + $listing->level->listings_in_package);

			$this->process_listing_creation_for_user($level_id, $user_id);
		}
	}
	
	public function add_user_profile_fields($user) {
		global $w2dc_instance;
		
		if (!apply_filters('w2dc_show_user_profile_fields', true)) {
			return false;
		}
		
		if (!current_user_can('edit_user', $user->ID)) {
			return false;
		}
	?>
		<h2><?php _e('Directory listings available', 'W2DC'); ?></h3>

		<table class="form-table">
		<?php
		$listings_number = $this->get_listings_of_user($user->ID);

		foreach ($w2dc_instance->levels->levels_array as $level):
		?>
			<tr>
				<th><label for="listings_number_<?php echo $level->id; ?>"><?php _e('Number of listings of level "'.esc_attr($level->name).'"', 'W2DC'); ?></label></th>
				<td>
					<input type="text" name="_listings_number_<?php echo $level->id; ?>" id="_listings_number_<?php echo $level->id; ?>" value="<?php echo esc_attr($listings_number[$level->id]['number']); ?>" class="regular-text listings_number" />
					<p>
						<input type="checkbox" name="_listings_unlimited_<?php echo $level->id; ?>" id="_listings_unlimited_<?php echo $level->id; ?>" <?php checked($listings_number[$level->id]['unlimited'], 1); ?> value="1" />
						<label for="_listings_unlimited_<?php echo $level->id; ?>"><?php _e('Unlimited', 'W2DC'); ?></label>
					</p>
				</td>
			</tr>
		<?php endforeach; ?>
		</table>
	<?php }
	
	public function save_user_profile_fields($user_id) {
		global $w2dc_instance;
		
		if (!apply_filters('w2dc_show_user_profile_fields', true)) {
			return false;
		}

		if (!current_user_can('edit_user', $user_id)) {
			return false;
		}

		foreach ($w2dc_instance->levels->levels_array as $level) {
			update_user_meta($user_id, '_listings_unlimited_'.$level->id, sanitize_text_field(w2dc_getValue($_POST, '_listings_unlimited_'.$level->id, 0)));
			update_user_meta($user_id, '_listings_number_'.$level->id, sanitize_text_field(w2dc_getValue($_POST, '_listings_number_'.$level->id, 0)));
		}
	}

	public function available_listings_descr($level_id, $action_string, $directory = false) {
		global $w2dc_instance;
		
		if (is_admin()) {
			return false;
		}

		$listings_number = $this->get_listings_of_user();
		
		$out = '';
		$number = 0;
		
		if (!$directory) {
			$directory = $w2dc_instance->current_directory;
		} 

		if ($listings_number[$level_id]['unlimited']) {
			$number = __("unlimited", "W2DC");
		} elseif ($listings_number[$level_id]['number']) {
			$number = $listings_number[$level_id]['number'];
		}
		if ($number) {
			$out = sprintf(__("You have <strong>%s</strong> %s to %s from your package.", "W2DC"), $number, _n($directory->single, $directory->plural, $number), $action_string);
		}
		
		return $out;
	}
	
	public function submitlisting_level_message($level, $directory = false) {
		$out = $this->available_listings_descr($level->id, __("submit", "W2DC"), $directory);

		if ($out) {
			return '<div class="w2dc-user-package-message">' . $out . '</div>';
		}
	}

	// if user has pre-paid listing(s) - simply activate it after creation
	public function activate_if_possible($listing) {
		if ($listing) {
			if ($this->can_user_create_listing_in_level($listing->level->id)) {
				$this->process_listing_creation_for_user($listing->level->id);
				return false;
			}
		}
		return $listing;
	}

	public function renew_html($listing) {
		$out = $this->available_listings_descr($listing->level->id, __("renew", "W2DC"));
		if ($out) {
			echo "<p>" . $out . "</p>";
		}
	}
	
	public function renew_listing_order($continue, $listing, $continue_invoke_hooks) {
		$user_id = $listing->post->post_author;
	
		if ($this->can_user_create_listing_in_level($listing->level->id, $user_id)) {
			$listing->processActivate(false, false);
			$this->process_listing_creation_for_user($listing->level->id, $user_id);
			$continue_invoke_hooks[0] = false;
			if (!defined('DOING_CRON')) {
				w2dc_addMessage(__("Listing was renewed successfully.", "W2DC"));
			}
			$continue_invoke_hooks[0] = false;
			return false;
		}
		return $continue;
	}
	
	public function raiseup_html($listing) {
		$out = $this->available_listings_descr($listing->level->id, __("raise up", "W2DC"));
		if ($out) {
			echo "<p>" . $out . "</p>";
		}
	}
	
	public function listing_raiseup_order($continue, $listing, $continue_invoke_hooks) {
		if ($this->can_user_create_listing_in_level($listing->level->id)) {
			$this->process_listing_creation_for_user($listing->level->id);
			$continue_invoke_hooks[0] = false;
			return true;
		}

		return $continue;
	}
	
	public function level_upgrade_option($link_text, $old_level, $new_level) {
		$out = $link_text;

		if ($this->can_user_create_listing_in_level($new_level->id)) {
			$out .= ' ' . __("(you can upgrade to this level for free)", "W2DC");
		}
		
		return $out;
	}

	public function listing_upgrade_order($continue, $listing, $continue_invoke_hooks) {
		$new_level_id = get_post_meta($listing->post->ID, '_new_level_id', true);

		if ($this->can_user_create_listing_in_level($new_level_id)) {
			$this->process_listing_creation_for_user($new_level_id);
			$continue_invoke_hooks[0] = false;
			return true;
		}

		return $continue;
	}
}
?>