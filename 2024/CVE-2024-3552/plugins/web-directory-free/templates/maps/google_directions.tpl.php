	<div class="w2dc-row w2dc-form-group">
		<?php if (get_option('w2dc_directions_functionality') == 'builtin'): ?>
		<div class="w2dc-form-group w2dc-col-md-12">
			<label class="w2dc-control-label"><?php _e('Get directions from:', 'W2DC'); ?></label>
			<div class="w2dc-has-feedback">
				<input type="text" id="w2dc-origin-address-<?php echo $map_id; ?>" class="w2dc-form-control <?php if (get_option('w2dc_address_autocomplete')): ?>w2dc-listing-field-autocomplete<?php endif; ?>" placeholder="<?php esc_attr_e('Enter address or zip code', 'W2DC'); ?>" />
				<?php if (get_option('w2dc_address_geocode')): ?>
				<span class="w2dc-get-location w2dc-form-control-feedback w2dc-glyphicon w2dc-glyphicon-screenshot"></span>
				<?php endif; ?>
			</div>
		</div>
		<div class="w2dc-form-group w2dc-col-md-12">
			<?php $i = 1; ?>
			<?php foreach ($locations_array AS $location): ?>
			<div class="w2dc-radio">
				<label>
					<input type="radio" name="daddr" class="w2dc-select-directions-<?php echo $map_id; ?>" <?php checked($i, 1); ?> value="<?php echo esc_attr($location->map_coords_1.' '.$location->map_coords_2); ?>" />
					<?php 
					if ($address = $location->getWholeAddress(false))
						echo $address;
					else 
						echo $location->map_coords_1.' '.$location->map_coords_2;
					?>
				</label>
			</div>
			<?php $i++; ?>
			<?php endforeach; ?>
		</div>
		<div class="w2dc-form-group w2dc-col-md-12">
			<input type="button" class="w2dc-get-directions-button front-btn w2dc-btn w2dc-btn-primary" data-id="<?php echo $map_id; ?>" value="<?php esc_attr_e('Get directions', 'W2DC'); ?>">
		</div>
		<div class="w2dc-form-group w2dc-col-md-12">
			<div id="w2dc-route-container-<?php echo $map_id; ?>" class="w2dc-route-container w2dc-map-direction-route"></div>
		</div>
		<?php elseif (get_option('w2dc_directions_functionality') == 'google'): ?>
		<label class="w2dc-col-md-12 w2dc-control-label"><?php _e('directions to:', 'W2DC'); ?></label>
		<form action="//google.com/maps/dir/" target="_blank">
			<input type="hidden" name="api" value="1" />
			<div class="w2dc-col-md-12">
				<?php $i = 1; ?>
				<?php foreach ($locations_array AS $location): ?>
				<div class="w2dc-radio">
					<label>
						<input type="radio" name="destination" class="w2dc-select-directions-<?php echo $map_id; ?>" <?php checked($i, 1); ?> value="<?php echo esc_attr($location->map_coords_1.','.$location->map_coords_2); ?>" />
						<?php 
						if ($address = $location->getWholeAddress(false))
							echo $address;
						else 
							echo $location->map_coords_1.' '.$location->map_coords_2;
						?>
					</label>
				</div>
				<?php $i++; ?>
				<?php endforeach; ?>
			</div>
			<div class="w2dc-col-md-12">
				<input class="w2dc-btn w2dc-btn-primary" type="submit" value="<?php esc_attr_e('Get directions', 'W2DC'); ?>" />
			</div>
		</form>
		<?php endif; ?>
	</div>