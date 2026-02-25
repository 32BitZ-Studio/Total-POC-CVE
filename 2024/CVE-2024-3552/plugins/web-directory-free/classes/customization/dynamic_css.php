<?php if (w2dc_get_dynamic_option('w2dc_listing_title_font')): ?>
header.w2dc-listing-header h2 {
	font-size: <?php echo w2dc_get_dynamic_option('w2dc_listing_title_font'); ?>px;
}
<?php endif; ?>

<?php if (w2dc_get_dynamic_option('w2dc_links_color')): ?>
div.w2dc-content a,
div.w2dc-content a:visited,
div.w2dc-content a:focus,
div.w2dc-content .w2dc-pagination > li > a,
div.w2dc-content .w2dc-pagination > li > a:visited,
div.w2dc-content .w2dc-pagination > li > a:focus,
div.w2dc-content .w2dc-btn-default, div.w2dc-content div.w2dc-btn-default:visited, div.w2dc-content .w2dc-btn-default:focus {
	color: <?php echo w2dc_get_dynamic_option('w2dc_links_color'); ?>;
}
<?php endif; ?>
<?php if (w2dc_get_dynamic_option('w2dc_links_hover_color')): ?>
div.w2dc-content a:hover,
div.w2dc-content .w2dc-pagination > li > a:hover {
	color: <?php echo w2dc_get_dynamic_option('w2dc_links_hover_color'); ?>;
}
<?php endif; ?>

<?php if (w2dc_get_dynamic_option('w2dc_button_1_color') && w2dc_get_dynamic_option('w2dc_button_2_color') && w2dc_get_dynamic_option('w2dc_button_text_color')): ?>
<?php if (!w2dc_get_dynamic_option('w2dc_button_gradient')): ?>
div.w2dc-content .w2dc-btn-primary,
div.w2dc-content a.w2dc-btn-primary,
div.w2dc-content input.w2dc-btn[type="submit"],
div.w2dc-content input.w2dc-btn[type="button"],
div.w2dc-content .w2dc-btn-primary:visited,
div.w2dc-content a.w2dc-btn-primary:visited,
div.w2dc-content input.w2dc-btn[type="submit"]:visited,
div.w2dc-content input.w2dc-btn[type="button"]:visited,
div.w2dc-content .w2dc-btn-primary:focus,
div.w2dc-content a.w2dc-btn-primary:focus,
div.w2dc-content input.w2dc-btn[type="submit"]:focus,
div.w2dc-content input.w2dc-btn[type="button"]:focus,
div.w2dc-content .w2dc-btn-primary:disabled,
div.w2dc-content a.w2dc-btn-primary:disabled,
div.w2dc-content .w2dc-btn-primary:disabled:focus,
div.w2dc-content a.w2dc-btn-primary:disabled:focus,
div.w2dc-content .w2dc-btn-primary:disabled:hover,
div.w2dc-content a.w2dc-btn-primary:disabled:hover,
form.w2dc-content .w2dc-btn-primary,
form.w2dc-content a.w2dc-btn-primary,
form.w2dc-content input.w2dc-btn[type="submit"],
form.w2dc-content input.w2dc-btn[type="button"],
form.w2dc-content .w2dc-btn-primary:visited,
form.w2dc-content a.w2dc-btn-primary:visited,
form.w2dc-content input.w2dc-btn[type="submit"]:visited,
form.w2dc-content input.w2dc-btn[type="button"]:visited,
form.w2dc-content .w2dc-btn-primary:focus,
form.w2dc-content a.w2dc-btn-primary:focus,
form.w2dc-content input.w2dc-btn[type="submit"]:focus,
form.w2dc-content input.w2dc-btn[type="button"]:focus,
form.w2dc-content .w2dc-btn-primary:disabled,
form.w2dc-content a.w2dc-btn-primary:disabled,
form.w2dc-content .w2dc-btn-primary:disabled:focus,
form.w2dc-content a.w2dc-btn-primary:disabled:focus,
form.w2dc-content .w2dc-btn-primary:disabled:hover,
form.w2dc-content a.w2dc-btn-primary:disabled:hover,
div.w2dc-content .wpcf7-form .wpcf7-submit,
div.w2dc-content .wpcf7-form .wpcf7-submit:visited,
div.w2dc-content .wpcf7-form .wpcf7-submit:focus {
	color: <?php echo w2dc_get_dynamic_option('w2dc_button_text_color'); ?> !important;
	background-color: <?php echo w2dc_get_dynamic_option('w2dc_button_1_color'); ?> !important;
	background-image: none !important;
	border-color: <?php echo w2dc_adjust_brightness(w2dc_get_dynamic_option('w2dc_button_1_color'), -20); ?> !important;
}
div.w2dc-content .w2dc-btn-primary:hover,
div.w2dc-content a.w2dc-btn-primary:hover,
div.w2dc-content input.w2dc-btn[type="submit"]:hover,
div.w2dc-content input.w2dc-btn[type="button"]:hover,
form.w2dc-content .w2dc-btn-primary:hover,
form.w2dc-content a.w2dc-btn-primary:hover,
form.w2dc-content input.w2dc-btn[type="submit"]:hover,
form.w2dc-content input.w2dc-btn[type="button"]:hover,
div.w2dc-content .wpcf7-form .wpcf7-submit:hover {
	color: <?php echo w2dc_get_dynamic_option('w2dc_button_text_color'); ?> !important;
	background-color: <?php echo w2dc_get_dynamic_option('w2dc_button_2_color'); ?> !important;
	background-image: none !important;
	border-color: <?php echo w2dc_adjust_brightness(w2dc_get_dynamic_option('w2dc_button_2_color'), -20); ?> !important;
	text-decoration: none !important;
}
<?php else: ?>
div.w2dc-content .w2dc-btn-primary,
div.w2dc-content a.w2dc-btn-primary,
div.w2dc-content input.w2dc-btn[type="submit"],
div.w2dc-content input.w2dc-btn[type="button"],
div.w2dc-content .w2dc-btn-primary:visited,
div.w2dc-content a.w2dc-btn-primary:visited,
div.w2dc-content input.w2dc-btn[type="submit"]:visited,
div.w2dc-content input.w2dc-btn[type="button"]:visited,
div.w2dc-content .w2dc-btn-primary:focus,
div.w2dc-content a.w2dc-btn-primary:focus,
div.w2dc-content input.w2dc-btn[type="submit"]:focus,
div.w2dc-content input.w2dc-btn[type="button"]:focus,
div.w2dc-content .w2dc-btn-primary:disabled,
div.w2dc-content a.w2dc-btn-primary:disabled,
div.w2dc-content .w2dc-btn-primary:disabled:focus,
div.w2dc-content a.w2dc-btn-primary:disabled:focus,
form.w2dc-content .w2dc-btn-primary,
form.w2dc-content a.w2dc-btn-primary,
form.w2dc-content input.w2dc-btn[type="submit"],
form.w2dc-content input.w2dc-btn[type="button"],
form.w2dc-content .w2dc-btn-primary:visited,
form.w2dc-content a.w2dc-btn-primary:visited,
form.w2dc-content input.w2dc-btn[type="submit"]:visited,
form.w2dc-content input.w2dc-btn[type="button"]:visited,
form.w2dc-content .w2dc-btn-primary:focus,
form.w2dc-content a.w2dc-btn-primary:focus,
form.w2dc-content input.w2dc-btn[type="submit"]:focus,
form.w2dc-content input.w2dc-btn[type="button"]:focus,
form.w2dc-content .w2dc-btn-primary:disabled,
form.w2dc-content a.w2dc-btn-primary:disabled,
form.w2dc-content .w2dc-btn-primary:disabled:focus,
form.w2dc-content a.w2dc-btn-primary:disabled:focus,
div.w2dc-content .w2dc-directory-frontpanel input[type="button"],
div.w2dc-content .wpcf7-form .wpcf7-submit,
div.w2dc-content .wpcf7-form .wpcf7-submit:visited,
div.w2dc-content .wpcf7-form .wpcf7-submit:focus {
	background: <?php echo w2dc_get_dynamic_option('w2dc_button_1_color'); ?> !important;
	background: -moz-linear-gradient(top, <?php echo w2dc_get_dynamic_option('w2dc_button_1_color'); ?> 0%, <?php echo w2dc_get_dynamic_option('w2dc_button_2_color'); ?> 100%) !important;
	background: -webkit-gradient(linear, left top, left bottom, color-stop(0%, <?php echo w2dc_get_dynamic_option('w2dc_button_1_color'); ?>), color-stop(100%, <?php echo w2dc_get_dynamic_option('w2dc_button_2_color'); ?>)) !important;
	background: -webkit-linear-gradient(top, <?php echo w2dc_get_dynamic_option('w2dc_button_1_color'); ?> 0%, <?php echo w2dc_get_dynamic_option('w2dc_button_2_color'); ?> 100%) !important;
	background: -o-linear-gradient(top, <?php echo w2dc_get_dynamic_option('w2dc_button_1_color'); ?> 0%, <?php echo w2dc_get_dynamic_option('w2dc_button_2_color'); ?> 100%) !important;
	background: -ms-linear-gradient(top, <?php echo w2dc_get_dynamic_option('w2dc_button_1_color'); ?> 0%, <?php echo w2dc_get_dynamic_option('w2dc_button_2_color'); ?> 100%) !important;
	background: linear-gradient(to bottom, <?php echo w2dc_get_dynamic_option('w2dc_button_1_color'); ?> 0%, <?php echo w2dc_get_dynamic_option('w2dc_button_2_color'); ?> 100%) !important;
	filter: progid:DXImageTransform.Microsoft.gradient( startColorstr= <?php echo w2dc_get_dynamic_option('w2dc_button_1_color'); ?> , endColorstr= <?php echo w2dc_get_dynamic_option('w2dc_button_2_color'); ?> ,GradientType=0 ) !important;
	color: <?php echo w2dc_get_dynamic_option('w2dc_button_text_color'); ?>;
	background-position: center !important;
	border: none;
}
div.w2dc-content .w2dc-btn-primary:hover,
div.w2dc-content a.w2dc-btn-primary:hover,
div.w2dc-content input.w2dc-btn[type="submit"]:hover,
div.w2dc-content input.w2dc-btn[type="button"]:hover,
form.w2dc-content .w2dc-btn-primary:hover,
form.w2dc-content a.w2dc-btn-primary:hover,
form.w2dc-content input.w2dc-btn[type="submit"]:hover,
form.w2dc-content input.w2dc-btn[type="button"]:hover,
div.w2dc-content .w2dc-directory-frontpanel input[type="button"]:hover,
div.w2dc-content .wpcf7-form .wpcf7-submit:hover {
	background: <?php echo w2dc_get_dynamic_option('w2dc_button_2_color'); ?> !important;
	background: -moz-linear-gradient(top, <?php echo w2dc_get_dynamic_option('w2dc_button_2_color'); ?> 0%, <?php echo w2dc_get_dynamic_option('w2dc_button_1_color'); ?> 100%) !important;
	background: -webkit-gradient(linear, left top, left bottom, color-stop(0%, <?php echo w2dc_get_dynamic_option('w2dc_button_2_color'); ?>), color-stop(100%, <?php echo w2dc_get_dynamic_option('w2dc_button_1_color'); ?>)) !important;
	background: -webkit-linear-gradient(top, <?php echo w2dc_get_dynamic_option('w2dc_button_2_color'); ?> 0%, <?php echo w2dc_get_dynamic_option('w2dc_button_1_color'); ?> 100%) !important;
	background: -o-linear-gradient(top, <?php echo w2dc_get_dynamic_option('w2dc_button_2_color'); ?> 0%, <?php echo w2dc_get_dynamic_option('w2dc_button_1_color'); ?> 100%) !important;
	background: -ms-linear-gradient(top, <?php echo w2dc_get_dynamic_option('w2dc_button_2_color'); ?> 0%, <?php echo w2dc_get_dynamic_option('w2dc_button_1_color'); ?> 100%) !important;
	background: linear-gradient(to bottom, <?php echo w2dc_get_dynamic_option('w2dc_button_2_color'); ?> 0%, <?php echo w2dc_get_dynamic_option('w2dc_button_1_color'); ?> 100%) !important;
	color: <?php echo w2dc_get_dynamic_option('w2dc_button_text_color'); ?>;
	background-position: center !important;
	border: none;
	text-decoration: none;
}
<?php endif; ?>
<?php endif; ?>

<?php if (w2dc_get_dynamic_option('w2dc_primary_color') && w2dc_get_dynamic_option('w2dc_secondary_color')): ?>
.w2dc-field-caption .w2dc-field-icon {
	color: <?php echo w2dc_get_dynamic_option('w2dc_primary_color'); ?>;
}
.w2dc-featured-label {
	background-color: <?php echo w2dc_get_dynamic_option('w2dc_secondary_color'); ?>;
}
.w2dc-sticky-ribbon span {
	background-color: <?php echo w2dc_get_dynamic_option('w2dc_secondary_color'); ?>;
}
.w2dc-sticky-ribbon span::before {
	border-left: 3px solid <?php echo w2dc_adjust_brightness(w2dc_get_dynamic_option('w2dc_secondary_color'), -20); ?>;
	border-top: 3px solid <?php echo w2dc_adjust_brightness(w2dc_get_dynamic_option('w2dc_secondary_color'), -20); ?>;
}
.w2dc-sticky-ribbon span::after {
	border-right: 3px solid <?php echo w2dc_adjust_brightness(w2dc_get_dynamic_option('w2dc_secondary_color'), -20); ?>;
	border-top: 3px solid <?php echo w2dc_adjust_brightness(w2dc_get_dynamic_option('w2dc_secondary_color'), -20); ?>;
}
.w2dc-content select:not(.w2dc-week-day-input),
.w2dc-content select:not(.w2dc-week-day-input):focus {
	background-image:
	linear-gradient(50deg, transparent 50%, #FFFFFF 50%),
	linear-gradient(130deg, #FFFFFF 50%, transparent 50%),
	linear-gradient(to right, <?php echo w2dc_get_dynamic_option('w2dc_primary_color'); ?>, <?php echo w2dc_get_dynamic_option('w2dc_primary_color'); ?>) !important;
}
.w2dc-content .w2dc-checkbox .w2dc-control-indicator,
.w2dc-content .w2dc-radio .w2dc-control-indicator {
	border-color: <?php echo w2dc_get_dynamic_option('w2dc_primary_color'); ?>;
}
.w2dc-content .w2dc-checkbox label input:checked ~ .w2dc-control-indicator,
.w2dc-content .w2dc-radio label input:checked ~ .w2dc-control-indicator {
	background: <?php echo w2dc_get_dynamic_option('w2dc_primary_color'); ?>;
}
.w2dc-content .ui-slider.ui-slider-horizontal .ui-widget-header {
	background-color: <?php echo w2dc_get_dynamic_option('w2dc_secondary_color'); ?>;
}
.w2dc-content .ui-slider.ui-widget-content .ui-slider-handle.ui-state-default,
.w2dc-content .ui-slider.ui-widget-content .ui-slider-handle.ui-state-default:focus,
.w2dc-content .ui-slider.ui-widget-content .ui-slider-handle.ui-state-default:active,
.w2dc-content .ui-slider.ui-widget-content .ui-slider-handle.ui-state-focus,
.w2dc-content .ui-slider.ui-widget-content .ui-slider-handle.ui-state-hover {
	border: 1px solid <?php echo w2dc_get_dynamic_option('w2dc_secondary_color'); ?>;
	background-color: <?php echo w2dc_get_dynamic_option('w2dc_primary_color'); ?>;
}
.w2dc-content .w2dc-map-info-window-title {
	background-color: <?php echo w2dc_get_dynamic_option('w2dc_primary_color'); ?>;
}
.w2dc-mapboxgl-popup-container {
	width: <?php echo w2dc_get_dynamic_option('w2dc_map_infowindow_width'); ?>px;
}
.w2dc-content .w2dc-category-label,
.w2dc-content .w2dc-tag-label {
	color: <?php echo w2dc_get_dynamic_option('w2dc_primary_color'); ?>;
	border-color: <?php echo w2dc_get_dynamic_option('w2dc_primary_color'); ?>;
}
div.w2dc-content .w2dc-pagination > li.w2dc-active > a,
div.w2dc-content .w2dc-pagination > li.w2dc-active > span,
div.w2dc-content .w2dc-pagination > li.w2dc-active > a:hover,
div.w2dc-content .w2dc-pagination > li.w2dc-active > span:hover,
div.w2dc-content .w2dc-pagination > li.w2dc-active > a:focus,
div.w2dc-content .w2dc-pagination > li.w2dc-active > span:focus {
	background-color: <?php echo w2dc_get_dynamic_option('w2dc_primary_color'); ?>;
	border-color: <?php echo w2dc_get_dynamic_option('w2dc_primary_color'); ?>;
	color: #FFFFFF;
}
figure.w2dc-listing-logo figcaption {
	background-color: <?php echo w2dc_get_dynamic_option('w2dc_primary_color'); ?>;
}
.w2dc-found-listings .w2dc-badge {
	background-color: <?php echo w2dc_get_dynamic_option('w2dc_primary_color'); ?>;
}
.w2dc-orderby-distance.w2dc-badge {
	background-color: <?php echo w2dc_get_dynamic_option('w2dc_primary_color'); ?>;
}
.w2dc-content .w2dc-choose-plan:hover,
.w2dc-choose-plan.w2dc-featured-level {
	border: 4px solid <?php echo w2dc_get_dynamic_option('w2dc_primary_color'); ?>;
}
.w2dc-rating-avgvalue span {
	background-color: <?php echo w2dc_get_dynamic_option('w2dc_primary_color'); ?>;
}
.w2dc-content.w2dc-search-map-form .w2dc-search-overlay {
	background-color: <?php echo w2dc_hex2rgba(w2dc_get_dynamic_option('w2dc_primary_color'), 0.8); ?>;
}
.w2dc-field-output-block-string .w2dc-field-phone-content,
.w2dc-field-output-block-website .w2dc-field-content {
	color: <?php echo w2dc_get_dynamic_option('w2dc_primary_color'); ?>;
	font-weight: bold;
}
.w2dc-loader:before {
	border-top-color: <?php echo w2dc_get_dynamic_option('w2dc_primary_color'); ?>;
	border-bottom-color: <?php echo w2dc_get_dynamic_option('w2dc_primary_color'); ?>;
}
.w2dc-listings-carousel-button-left,
.w2dc-listings-carousel-button-right,
.w2dc-remove-from-favourites-list,
.w2dc-content .w2dc-panel-heading.w2dc-choose-plan-head {
	background-color: <?php echo w2dc_get_dynamic_option('w2dc_primary_color'); ?>;
}
.w2dc-page-header-widget {
	background-color: <?php echo w2dc_get_dynamic_option('w2dc_primary_color'); ?>;
}
.w2dc-search-param {
	background-color: <?php echo w2dc_get_dynamic_option('w2dc_primary_color'); ?>;
}
.w2dc-field-checkbox-item-checked span {
	color: <?php echo w2dc_get_dynamic_option('w2dc_primary_color'); ?>;
}
.w2dc-bx-pager a.active img {
	border: 1px solid <?php echo w2dc_get_dynamic_option('w2dc_primary_color'); ?>;
}
<?php endif; ?>

<?php if (w2dc_get_dynamic_option('w2dc_listings_bottom_margin') >= 0): ?>
.w2dc-listings-block .w2dc-listing {
	margin-bottom: <?php echo w2dc_get_dynamic_option('w2dc_listings_bottom_margin'); ?>px;
}
<?php endif; ?>

<?php if (w2dc_get_dynamic_option('w2dc_listing_thumb_width')): ?>
/* It works with devices width more than 768 pixels. */
@media screen and (min-width: 769px) {
	.w2dc-listings-block .w2dc-listing-logo-wrap {
		width: <?php echo w2dc_get_dynamic_option('w2dc_listing_thumb_width'); ?>px;
		<?php if (w2dc_get_dynamic_option('w2dc_wrap_logo_list_view')): ?>
		margin-right: 20px;
		margin-bottom: 10px;
		<?php endif; ?>
	}
	.rtl .w2dc-listings-block .w2dc-listing-logo-wrap {
		margin-left: 20px;
		margin-right: 0;
	}
	.w2dc-listings-block figure.w2dc-listing-logo .w2dc-listing-logo-img img {
		width: <?php echo w2dc_get_dynamic_option('w2dc_listing_thumb_width'); ?>px;
	}
	.w2dc-listings-list-view .w2dc-listing-text-content-wrap {
		<?php if (!w2dc_get_dynamic_option('w2dc_wrap_logo_list_view')): ?>
		margin-left: <?php echo w2dc_get_dynamic_option('w2dc_listing_thumb_width'); ?>px;
		margin-right: 0;
		<?php endif; ?>
	}
	.rtl .w2dc-listings-list-view .w2dc-listing-text-content-wrap {
		<?php if (!w2dc_get_dynamic_option('w2dc_wrap_logo_list_view')): ?>
		margin-right: <?php echo w2dc_get_dynamic_option('w2dc_listing_thumb_width'); ?>px;
		margin-left: 0;
		<?php endif; ?>
	}
}
<?php endif; ?>

<?php if (w2dc_get_dynamic_option('w2dc_grid_view_logo_ratio')): ?>
.w2dc-listings-grid figure.w2dc-listing-logo .w2dc-listing-logo-img-wrap:before {
	padding-top: <?php echo w2dc_get_dynamic_option('w2dc_grid_view_logo_ratio'); ?>%;
}
<?php endif; ?>

<?php if (w2dc_get_dynamic_option('w2dc_share_buttons_width')): ?>
.w2dc-content .w2dc-share-button img {
	max-width: <?php echo get_option('w2dc_share_buttons_width'); ?>px;
}
.w2dc-content .w2dc-share-buttons {
	height: <?php echo get_option('w2dc_share_buttons_width')+10; ?>px;
}
<?php endif; ?>

<?php if (!w2dc_get_dynamic_option('w2dc_100_single_logo_width')): ?>
/* It works with devices width more than 768 pixels. */
@media screen and (min-width: 768px) {
	.w2dc-single-listing-logo-wrap {
		max-width: <?php echo w2dc_get_dynamic_option('w2dc_single_logo_width'); ?>px;
		float: left;
		margin: 0 20px 20px 0;
	}
	.rtl .w2dc-single-listing-logo-wrap {
		float: right;
		margin: 0 0 20px 20px;
	}
	/* temporarily */
	/*.w2dc-single-listing-text-content-wrap {
		margin-left: <?php echo w2dc_get_dynamic_option('w2dc_single_logo_width')+20; ?>px;
	}*/
}
<?php endif; ?>

<?php if (w2dc_get_dynamic_option('w2dc_hide_search_on_map_mobile')): ?>
/* It works with devices width less than 768 pixels. */
@media screen and (max-width: 768px) {
	.w2dc-map-sidebar {
		display: none !important;
	}
	.w2dc-map-sidebar-open .w2dc-map-canvas {
		width: 100% !important;
	}
}
<?php endif; ?>

<?php if (w2dc_get_dynamic_option('w2dc_listing_logo_bg_mode')): ?>
figure.w2dc-listing-logo .w2dc-listing-logo-img {
	background-size: <?php echo w2dc_get_dynamic_option('w2dc_listing_logo_bg_mode'); ?>;
}
<?php endif; ?>

<?php if (w2dc_get_dynamic_option('w2dc_map_marker_size')): ?>
.w2dc-map-marker,
.w2dc-map-marker-empty {
	height: <?php echo w2dc_get_dynamic_option('w2dc_map_marker_size'); ?>px;
	width: <?php echo w2dc_get_dynamic_option('w2dc_map_marker_size'); ?>px;
}
.w2dc-map-marker .w2dc-map-marker-icon {
	font-size: <?php echo round(0.55*w2dc_get_dynamic_option('w2dc_map_marker_size')); ?>px !important;
}
<?php endif; ?>

<?php if (w2dc_get_dynamic_option('w2dc_terms_links_color')): ?>
div.w2dc-content .w2dc-category-item a,
div.w2dc-content .w2dc-category-item a:visited,
div.w2dc-content .w2dc-category-item a:focus,
div.w2dc-content .w2dc-location-item a,
div.w2dc-content .w2dc-location-item a:visited,
div.w2dc-content .w2dc-location-item a:focus {
	color: <?php echo w2dc_get_dynamic_option('w2dc_terms_links_color'); ?>;
}
div.w2dc-content .w2dc-subcategories ul li a,
div.w2dc-content .w2dc-sublocations ul li a {
	color: <?php echo w2dc_get_dynamic_option('w2dc_terms_links_color'); ?>;
}
<?php endif; ?>
<?php if (w2dc_get_dynamic_option('w2dc_terms_links_hover_color')): ?>
div.w2dc-content .w2dc-category-item a:hover,
div.w2dc-content .w2dc-location-item a:hover,
div.w2dc-content .w2dc-categories-root.w2dc-category-highlighted a,
div.w2dc-content .w2dc-categories-root.w2dc-category-highlighted a:visited,
div.w2dc-content .w2dc-categories-root.w2dc-category-highlighted a:focus,
div.w2dc-content .w2dc-locations-root.w2dc-location-highlighted a,
div.w2dc-content .w2dc-locations-root.w2dc-location-highlighted a:visited,
div.w2dc-content .w2dc-locations-root.w2dc-location-highlighted a:focus {
	color: <?php echo w2dc_get_dynamic_option('w2dc_terms_links_hover_color'); ?>;
}
div.w2dc-content .w2dc-subcategories ul li a:hover,
div.w2dc-content .w2dc-sublocations ul li a:hover,
div.w2dc-content .w2dc-categories-root.w2dc-category-item a:hover,
div.w2dc-content .w2dc-locations-root.w2dc-category-item a:hover {
	color: <?php echo w2dc_get_dynamic_option('w2dc_terms_links_hover_color'); ?>;
}
<?php endif; ?>
<?php if (w2dc_get_dynamic_option('w2dc_terms_heading_bg_color')): ?>
div.w2dc-content .w2dc-categories-root.w2dc-category-item a,
div.w2dc-content .w2dc-locations-root.w2dc-location-item a {
	background-color: <?php echo w2dc_hex2rgba(w2dc_get_dynamic_option('w2dc_terms_heading_bg_color'), 0.25); ?>;
}
div.w2dc-content .w2dc-categories-root.w2dc-category-item a:hover,
div.w2dc-content .w2dc-locations-root.w2dc-location-item a:hover {
	background-color: <?php echo w2dc_hex2rgba(w2dc_get_dynamic_option('w2dc_terms_heading_bg_color'), 0.55); ?>;
}
div.w2dc-content.w2dc-terms-menu .w2dc-categories-root.w2dc-category-item a,
div.w2dc-content.w2dc-terms-menu .w2dc-locations-root.w2dc-location-item a {
	background-color: <?php echo w2dc_get_dynamic_option('w2dc_terms_heading_bg_color'); ?>;
}
<?php endif; ?>
<?php if (w2dc_get_dynamic_option('w2dc_terms_bg_color')): ?>
div.w2dc-content .w2dc-categories-column,
div.w2dc-content .w2dc-locations-column {
	background-color: <?php echo w2dc_get_dynamic_option('w2dc_terms_bg_color'); ?>;
}
div.w2dc-content .w2dc-subcategories ul li,
div.w2dc-content .w2dc-sublocations ul li {
	background-color: <?php echo w2dc_get_dynamic_option('w2dc_terms_bg_color'); ?>;
}
<?php endif; ?>
