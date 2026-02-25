<?php w2dc_renderTemplate('admin_header.tpl.php'); ?>

<h2>
	<?php _e('Change level of listings', 'W2DC'); ?>
</h2>

<p><?php _e('The level of listings will be changed. You may upgrade or downgrade the level. If new level has an option of limited active period - expiration date of listing will be recalculated automatically.', 'W2DC'); ?></p>

<form action="<?php echo admin_url('options.php?page=w2dc_upgrade_bulk&listings_ids=' . implode(',', $listings_ids) . '&upgrade_action=upgrade&referer=' . urlencode($referer)); ?>" method="POST">
	<?php if ($action == 'show'): ?>
	<h3><?php _e('Change level of following listings', 'W2DC'); ?></h3>
	<ul>
	<?php foreach ($listings_ids AS $listing_id): ?>
	<?php $listing = new w2dc_listing; ?>
	<?php $listing->loadListingFromPost($listing_id); ?>
	<li><?php echo $listing->title(); ?></li>
	<?php endforeach; ?>
	</ul>

	<h3><?php _e('Choose new level', 'W2DC'); ?></h3>
	<?php foreach ($levels->levels_array AS $level): ?>
	<p>
		<label><input type="radio" name="new_level_id" value="<?php echo $level->id; ?>" /> <?php echo apply_filters('w2dc_level_upgrade_option', $level->name, $listing->level, $level); ?></label>
	</p>
	<?php endforeach; ?>

	<input type="submit" value="<?php esc_attr_e('Change level', 'W2DC'); ?>" class="button button-primary" id="submit" name="submit">
	&nbsp;&nbsp;&nbsp;
	<a href="<?php echo $referer; ?>" class="button button-primary"><?php _e('Cancel', 'W2DC'); ?></a>
	<?php elseif ($action == 'upgrade'): ?>
	<a href="<?php echo $referer; ?>" class="button button-primary"><?php _e('Go back ', 'W2DC'); ?></a>
	<?php endif; ?>
</form>

<?php w2dc_renderTemplate('admin_footer.tpl.php'); ?>