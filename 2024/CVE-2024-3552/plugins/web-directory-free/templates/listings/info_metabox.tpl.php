<div id="misc-publishing-actions">
	<?php if ($w2dc_instance->directories->isMultiDirectory()): ?>
	<script>
		(function($) {
			"use strict";
	
			$(function() {
				$("#directory_id").on("change", function() {
					$("#publish").trigger('click');
				});
			});
		})(jQuery);
	</script>
	<div class="misc-pub-section">
		<label for="post_level"><?php _e('Directory', 'W2DC'); ?>:</label>
		<select id="directory_id" name="directory_id">
			<?php foreach ($w2dc_instance->directories->directories_array AS $directory): ?>
			<option value="<?php echo $directory->id; ?>" <?php selected($directory->id, $listing->directory->id, true); ?>><?php echo $directory->name; ?></option>
			<?php endforeach; ?>
		</select>
	</div>
	<?php endif; ?>

	<div class="misc-pub-section">
		<label for="post_level"><?php _e('Listing level', 'W2DC'); ?>:</label>
		<span id="post-level-display">
			<?php
			if ($listing->listing_created && $listing->level->isUpgradable())
					echo '<a href="' . admin_url('options.php?page=w2dc_upgrade&listing_id=' . $listing->post->ID) . '">';
			else
				echo '<b>'; ?>
			<?php echo apply_filters('w2dc_create_option', $listing->level->name, $listing); ?>
			<?php
			if ($listing->listing_created && $listing->level->isUpgradable())
				echo '</a>';
			else
				echo '</b>'; ?>
		</span>
	</div>

	<?php if ($listing->listing_created): ?>
	<div class="misc-pub-section">
		<label for="post_level"><?php _e('Listing status', 'W2DC'); ?>:</label>
		<span id="post-level-display">
			<?php if ($listing->status == 'active'): ?>
			<span class="w2dc-badge w2dc-listing-status-active"><?php _e('active', 'W2DC'); ?></span>
			<?php elseif ($listing->status == 'expired'): ?>
			<span class="w2dc-badge w2dc-listing-status-expired"><?php _e('expired', 'W2DC'); ?></span><br />
			<a href="<?php echo admin_url('options.php?page=w2dc_renew&listing_id=' . $listing->post->ID); ?>"><span class="w2dc-fa w2dc-fa-refresh w2dc-fa-lg"></span> <?php echo apply_filters('w2dc_renew_option', __('renew listing', 'W2DC'), $listing); ?></a>
			<?php elseif ($listing->status == 'unpaid'): ?>
			<span class="w2dc-badge w2dc-listing-status-unpaid"><?php _e('unpaid ', 'W2DC'); ?></span>
			<?php elseif ($listing->status == 'stopped'): ?>
			<span class="w2dc-badge w2dc-listing-status-stopped"><?php _e('stopped', 'W2DC'); ?></span>
			<?php endif;?>
			<?php do_action('w2dc_listing_status_option', $listing); ?>
		</span>
		<?php if (!$listing->level->eternal_active_period && get_post_meta($listing->post->ID, '_preexpiration_notification_sent', true)): ?>
		<br />
		<?php _e('Pre-expiration notification was sent', 'W2DC'); ?>
		<?php endif; ?>
	</div>
	
	<?php
	$post_type_object = get_post_type_object(W2DC_POST_TYPE);
	$can_publish = current_user_can($post_type_object->cap->publish_posts);
	?>
	<?php if ($can_publish && $listing->status != 'active'): ?>
	<div class="misc-pub-section">
		<input name="w2dc_save_as_active" value="Save as Active" class="button" type="submit">
	</div>
	<?php endif; ?>

	<?php if (get_option('w2dc_enable_stats')): ?>
	<div class="misc-pub-section">
		<label for="post_level"><?php echo sprintf(__('Click stats: %d', 'W2DC'), (get_post_meta($w2dc_instance->current_listing->post->ID, '_total_clicks', true) ? get_post_meta($w2dc_instance->current_listing->post->ID, '_total_clicks', true) : 0)); ?></label>
	</div>
	<?php endif; ?>

	<div class="misc-pub-section curtime">
		<span id="timestamp">
			<?php _e('Sorting date', 'W2DC'); ?>:
			<b><?php echo w2dc_formatDateTime($listing->order_date); ?></b>
			<?php if ($listing->level->raiseup_enabled && $listing->status == 'active'): ?>
			<br />
			<a href="<?php echo admin_url('options.php?page=w2dc_raise_up&listing_id=' . $listing->post->ID); ?>"><span class="w2dc-fa w2dc-fa-level-up w2dc-fa-lg"></span> <?php echo apply_filters('w2dc_raiseup_option', __('raise up listing', 'W2DC'), $listing); ?></a>
			<?php endif; ?>
		</span>
	</div>

	<?php if ($listing->level->eternal_active_period || $listing->expiration_date): ?>
	<div class="misc-pub-section curtime">
		<span id="timestamp">
			<?php _e('Expire on', 'W2DC'); ?>:
			<?php if ($listing->level->eternal_active_period): ?>
			<b><?php _e('Eternal active period', 'W2DC'); ?></b>
			<?php else: ?>
			<b><?php echo w2dc_formatDateTime($listing->expiration_date); ?></b>
			<?php endif; ?>
		</span>
	</div>
	<?php endif; ?>
	
	<?php do_action('w2dc_listing_info_metabox_html', $listing); ?>

	<?php endif; ?>
</div>