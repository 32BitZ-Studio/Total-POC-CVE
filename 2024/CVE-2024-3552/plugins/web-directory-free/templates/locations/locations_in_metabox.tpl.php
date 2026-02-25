		<div class="w2dc-location-in-metabox">
			<?php $uID = rand(1, 10000); ?>
			<input type="hidden" name="w2dc_location[<?php echo $uID;?>]" value="1" />

			<?php
			if (w2dc_is_anyone_in_taxonomy(W2DC_LOCATIONS_TAX)) {
				w2dc_tax_dropdowns_init(
					array(
						'tax' => W2DC_LOCATIONS_TAX,
						'term_id' => $location->selected_location,
						'count' => false,
						'labels' => $locations_levels->getNamesArray(),
						'titles' => $locations_levels->getSelectionsArray(),
						'allow_add_term' => $locations_levels->getAllowAddTermArray(),
						'uID' => $uID,
						'exact_locations' => $listing->level->locations,
					)
				);
			}
			?>

			<div class="w2dc-row w2dc-form-group w2dc-location-input w2dc-address-line-1-wrapper" <?php if (!w2dc_get_dynamic_option('w2dc_enable_address_line_1')): ?>style="display: none;"<?php endif; ?>>
				<div class="w2dc-col-md-2">
					<label class="w2dc-control-label">
						<?php
						if (!w2dc_get_dynamic_option('w2dc_enable_address_line_2'))
							_e('Address', 'W2DC');
						else
							_e('Address line 1', 'W2DC');
						?>
					</label>
				</div>
				<div class="w2dc-col-md-10">
					<div class="w2dc-has-feedback">
						<input type="text" id="address_line_<?php echo $uID;?>" name="address_line_1[<?php echo $uID;?>]" class="w2dc-address-line-1 w2dc-form-control <?php if (get_option('w2dc_address_autocomplete')): ?>w2dc-listing-field-autocomplete<?php endif; ?>" value="<?php echo esc_attr($location->address_line_1); ?>" placeholder="" />
						<input type="hidden" id="place_id_<?php echo $uID;?>" name="place_id[<?php echo $uID;?>]" class="w2dc-place-id-input" value="<?php echo esc_attr($location->place_id); ?>" />
						<?php if (get_option('w2dc_address_geocode')): ?>
						<span class="w2dc-get-location w2dc-form-control-feedback w2dc-glyphicon w2dc-glyphicon-screenshot"></span>
						<?php endif; ?>
					</div>
				</div>
			</div>

			<div class="w2dc-row w2dc-form-group w2dc-location-input w2dc-address-line-2-wrapper" <?php if (!w2dc_get_dynamic_option('w2dc_enable_address_line_2')): ?>style="display: none;"<?php endif; ?>>
				<div class="w2dc-col-md-2">
					<label class="w2dc-control-label">
						<?php
						if (!w2dc_get_dynamic_option('w2dc_enable_address_line_1'))
							_e('Address', 'W2DC');
						else
							_e('Address line 2', 'W2DC');
						?>
					</label>
				</div>
				<div class="w2dc-col-md-10">
					<input type="text" name="address_line_2[<?php echo $uID;?>]" class="w2dc-address-line-2 w2dc-form-control" value="<?php echo esc_attr($location->address_line_2); ?>" />
				</div>
			</div>

			<div class="w2dc-row w2dc-form-group w2dc-location-input w2dc-zip-or-postal-index-wrapper" <?php if (!w2dc_get_dynamic_option('w2dc_enable_postal_index')): ?>style="display: none;"<?php endif; ?>>
				<div class="w2dc-col-md-2">
					<label class="w2dc-control-label">
						<?php if (get_option("w2dc_zip_or_postal_text") == 'postal') esc_html_e('Postal code', 'W2DC'); else esc_html_e('Zip code', 'W2DC'); ?>
					</label>
				</div>
				<div class="w2dc-col-md-10">
					<input type="text" name="zip_or_postal_index[<?php echo $uID;?>]" class="w2dc-zip-or-postal-index w2dc-form-control" value="<?php echo esc_attr($location->zip_or_postal_index); ?>" />
				</div>
			</div>
			
			<?php if ($listing->level->map): ?>
			<div class="w2dc-row w2dc-form-group w2dc-location-input w2dc-additional-info-wrapper" <?php if (!w2dc_get_dynamic_option('w2dc_enable_additional_info')): ?>style="display: none;"<?php endif; ?>>
				<div class="w2dc-col-md-2">
					<label class="w2dc-control-label">
						<?php _e('Additional info for map marker infowindow', 'W2DC'); ?>
					</label>
				</div>
				<div class="w2dc-col-md-10">
					<textarea name="additional_info[<?php echo $uID;?>]" class="w2dc-additional-info w2dc-form-control" rows="2"><?php echo esc_textarea($location->additional_info); ?></textarea>
				</div>
			</div>

			<div class="w2dc-manual-coords-wrapper" <?php if (!w2dc_get_dynamic_option('w2dc_enable_manual_coords')): ?>style="display: none;"<?php endif; ?>>
				<div class="w2dc-row w2dc-location-input w2dc-form-group">
					<div class="w2dc-col-md-12 w2dc-checkbox">
						<label>
							<input type="checkbox" name="manual_coords[<?php echo $uID;?>]" value="1" class="w2dc-manual-coords" <?php if ($location->manual_coords) echo 'checked'; ?> /> <?php _e('Enter coordinates manually', 'W2DC'); ?>
						</label>
					</div>
				</div>

				<!-- w2dc-manual-coords-block - position required for jquery selector -->
				<div class="w2dc-manual-coords-block" <?php if (!$location->manual_coords) echo 'style="display: none;"'; ?>>
					<div class="w2dc-row w2dc-form-group w2dc-location-input">
						<div class="w2dc-col-md-2">
							<label class="w2dc-control-label">
								<?php _e('Latitude', 'W2DC'); ?>
							</label>
						</div>
						<div class="w2dc-col-md-10">
							<input type="text" name="map_coords_1[<?php echo $uID;?>]" class="w2dc-map-coords-1 w2dc-form-control" value="<?php echo esc_attr($location->map_coords_1); ?>">
						</div>
					</div>
	
					<div class="w2dc-row w2dc-form-group w2dc-location-input">
						<div class="w2dc-col-md-2">
							<label class="w2dc-control-label">
								<?php _e('Longitude', 'W2DC'); ?>
							</label>
						</div>
						<div class="w2dc-col-md-10">
							<input type="text" name="map_coords_2[<?php echo $uID;?>]" class="w2dc-map-coords-2 w2dc-form-control" value="<?php echo esc_attr($location->map_coords_2); ?>">
						</div>
					</div>
				</div>
			</div>

			<?php if ($listing->level->map_markers): ?>
			<div class="w2dc-row w2dc-location-input">
				<div class="w2dc-col-md-12">
					<a class="w2dc-select-map-icon" href="javascript: void(0);">
						<span class="w2dc-fa w2dc-fa-map-marker"></span>
						<?php _e('Select marker icon', 'W2DC'); ?><?php if (get_option('w2dc_map_markers_type') == 'icons') _e(' (icon and color may depend on selected categories)', 'W2DC'); ?>
					</a>
					<input type="hidden" name="map_icon_file[<?php echo $uID;?>]" class="w2dc-map-icon-file" value="<?php if ($location->map_icon_manually_selected) echo esc_attr($location->map_icon_file); ?>">
				</div>
			</div>
			<?php endif; ?>
		<?php endif; ?>

			<div class="w2dc-row w2dc-location-input">
				<div class="w2dc-col-md-12">
					<a href="javascript: void(0);" <?php if (!$delete_location_link) echo 'style="display:none;"'; ?> class="w2dc-delete-address">
						<span class="w2dc-fa w2dc-fa-minus"></span>
						<?php _e('Delete address', 'W2DC'); ?>
					</a>
				</div>
			</div>
		</div>