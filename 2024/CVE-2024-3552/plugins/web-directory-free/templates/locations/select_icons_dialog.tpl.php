		<input type="button" id="reset_icon" class="button button-primary button-large" value="<?php esc_attr_e('Reset icon image', 'W2DC'); ?>" />

		<div class="w2dc-icons-theme-block">
		<?php foreach ($locations_icons AS $icon): ?>
			<div class="w2dc-icon" icon_file="<?php echo $icon; ?>"><img src="<?php echo W2DC_LOCATIONS_ICONS_URL . $icon; ?>" title="<?php echo $icon; ?>" /></div>
		<?php endforeach;?>
		</div>
		<div class="w2dc-clearfix"></div>