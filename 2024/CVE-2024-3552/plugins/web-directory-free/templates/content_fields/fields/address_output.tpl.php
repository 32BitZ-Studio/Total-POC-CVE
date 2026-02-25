<?php if ($listing->locations): ?>
<div class="w2dc-field w2dc-field-output-block <?php echo $content_field->printClasses($css_classes); ?>">
	<?php if ($content_field->icon_image || !$content_field->is_hide_name): ?>
	<span class="w2dc-field-caption <?php w2dc_is_any_field_name_in_group($group); ?>">
		<?php if ($content_field->icon_image): ?>
		<span <?php echo $content_field->getIconImageTagParams(); ?>></span>
		<?php endif; ?>
		<?php if (!$content_field->is_hide_name): ?>
		<span class="w2dc-field-name"><?php echo $content_field->name?>:</span>
		<?php endif; ?>
	</span>
	<?php endif; ?>
	<span class="w2dc-field-content w2dc-field-addresses">
	<?php foreach ($listing->locations AS $location): ?>
		<address class="w2dc-location" itemprop="address" itemscope itemtype="http://schema.org/PostalAddress">
			<?php if ($location->map_coords_1 && $location->map_coords_2): ?><span class="w2dc-show-on-map" data-location-id="<?php echo $location->id; ?>"><?php endif; ?>
			<?php echo $location->getWholeAddress(); ?>
			<?php if ($location->renderInfoFieldForMap()) echo '<div class="w2dc-location-additional-info">' . $location->renderInfoFieldForMap() . '</div>'; ?>
			<?php if ($location->map_coords_1 && $location->map_coords_2): ?></span><?php endif; ?>
			<?php echo w2dc_get_distance($location); ?>
		</address>
	<?php endforeach; ?>
	</span>
</div>
<?php endif; ?>