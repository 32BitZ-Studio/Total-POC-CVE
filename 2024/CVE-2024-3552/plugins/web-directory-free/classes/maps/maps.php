<?php

class w2dc_maps {
	public $args;
	public $display_args;
	public $map_id;
	
	public $map_zoom;
	public $listings_array = array();
	public $locations_array = array();
	public $locations_option_array = array();

	public static $map_content_fields;

	public function __construct($args = array()) {
		$this->args = $args;
	}
	
	public function setUniqueId($unique_id) {
		$this->map_id = $unique_id;
	}

	public function collectLocations($listing, $show_summary_button = true, $show_readmore_button = true) {
		
		// this global array collects locations IDs to display on a map,
		// 1. radius search will not display markers ourside entered radius,
		// 2. on locations pages will not display markers from another location
		global $w2dc_address_locations, $w2dc_tax_terms_locations;

		if (count($listing->locations) == 1) {
			$this->map_zoom = $listing->map_zoom;
		}

		foreach ($listing->locations AS $location) {
			if ((!$w2dc_address_locations || in_array($location->id, $w2dc_address_locations)) && (!$w2dc_tax_terms_locations || in_array($location->selected_location, $w2dc_tax_terms_locations))) {
				if (($location->map_coords_1 && $location->map_coords_1 != '0.000000') || ($location->map_coords_2 && $location->map_coords_2 != '0.000000')) {
					$logo_image = '';
					if ($listing->level->logo_enabled) {
						if ($listing->logo_image) {
							$height = apply_filters('w2dc_map_infowindow_logo_height', 0);
							
							$logo_image = $listing->get_logo_url(array(get_option('w2dc_map_infowindow_logo_width'), $height));
						} elseif (get_option('w2dc_enable_nologo') && get_option('w2dc_nologo_url')) {
							$logo_image = get_option('w2dc_nologo_url');
						}
					}
	
					$listing_link = '';
					if ($listing->level->listings_own_page) {
						$listing_link = get_permalink($listing->post->ID);
					}
					
					$content_fields_output = $listing->setInfoWindowContent($this->map_id, $location, $show_summary_button, $show_readmore_button);
	
					$this->listings_array[] = $listing;
					$this->locations_array[] = $location;
					$this->locations_option_array[] = array(
							$location->id,
							$location->map_coords_1,
							$location->map_coords_2,
							$location->map_icon_file,
							$location->map_icon_color,
							$listing->map_zoom,
							$listing->title(),
							$logo_image,
							$listing_link,
							$content_fields_output,
							'post-' . $listing->post->ID,
							($listing->level->nofollow) ? 1 : 0,
					);
				}
			}
		}

		if ($this->locations_option_array)
			return true;
		else
			return false;
	}
	
	public function collectLocationsForAjax($listing) {	
		global $w2dc_address_locations, $w2dc_tax_terms_locations;

		foreach ($listing->locations AS $location) {
			if ((!$w2dc_address_locations || in_array($location->id, $w2dc_address_locations))  && (!$w2dc_tax_terms_locations || in_array($location->selected_location, $w2dc_tax_terms_locations))) {
				if (($location->map_coords_1 && $location->map_coords_1 != '0.000000') || ($location->map_coords_2 && $location->map_coords_2 != '0.000000')) {
					
					// generate empty infoWindow
					$content_fields_output = '<div class="w2dc-map-info-window"><div class="w2dc-map-info-window-inner"><div class="w2dc-map-info-window-inner-item"><div class="w2dc-map-info-window-content w2dc-clearfix"><div class="w2dc-loader"></div></div></div></div>';
					if (w2dc_getMapEngine() == 'google') {
						$tongue_pos = round(get_option('w2dc_map_infowindow_width')/2);
						$content_fields_output .= '<div style="position: absolute; left: ' . ($tongue_pos - 10) . 'px;"><div style="position: absolute; overflow: hidden; left: -6px; top: -1px; width: 16px; height: 30px;"><div class="w2dc-map-info-window-tongue" style="position: absolute; left: 6px; transform: skewX(22.6deg); transform-origin: 0px 0px 0px;  -webkit-transform: skewX(22.6deg); -webkit-transform-origin: 0px 0px 0px; height: 24px; width: 10px; box-shadow: 0px 1px 6px rgba(0, 0, 0, 0.6);"></div></div><div style="position: absolute; overflow: hidden; top: -1px; left: 10px; width: 16px; height: 30px;"><div class="w2dc-map-info-window-tongue" style="position: absolute; left: 0px; transform: skewX(-22.6deg); transform-origin: 10px 0px 0px; -webkit-transform: skewX(-22.6deg); -webkit-transform-origin: 10px 0px 0px; height: 24px; width: 10px; box-shadow: 0px 1px 6px rgba(0, 0, 0, 0.6);"></div></div></div>';
					}		
					$content_fields_output .= '</div>';
					
					$this->listings_array[] = $listing;
					$this->locations_array[] = $location;
					$this->locations_option_array[] = array(
							$location->id,
							$location->map_coords_1,
							$location->map_coords_2,
							$location->map_icon_file,
							$location->map_icon_color,
							null,
							null,
							null,
							null,
							$content_fields_output,
							null,
							null,
					);
				}
			}
		}
		if ($this->locations_option_array)
			return true;
		else
			return false;
	}
	
	public function buildListingsContent($show_directions_button = true, $show_readmore_button = true) {
		
		if (w2dc_getMapEngine() == 'mapbox') {
			if (!get_option("w2dc_show_directions")) {
				$show_directions_button = false;
			}
		}
		$show_directions_button = apply_filters("w2dc_show_directions_button", $show_directions_button);
		
		// order locations by distance from center
		$content_locations_array = array();
		
		global $w2dc_order_by_distance;
		if ($w2dc_order_by_distance) {
			foreach ($w2dc_order_by_distance AS $ordered_by_distance_location_id=>$ordered_by_distance_location) {
				foreach ($this->locations_array AS $key=>$location) {
					if ($location->id == $ordered_by_distance_location_id) {
						$content_locations_array[$key] = $location;
						break;
					}
				}
			}
		} else {
			$content_locations_array = $this->locations_array;
		}
		
		$out = '';
		foreach ($content_locations_array AS $key=>$location) {
			$listing = $this->listings_array[$key];
			$listing->setContentFields();
	
			$out .= w2dc_renderTemplate('frontend/listing_location.tpl.php', array('listing' => $listing, 'location' => $location, 'show_directions_button' => $show_directions_button, 'show_readmore_button' => $show_readmore_button), true);
		}
		return $out;
	}
	
	public function buildStaticMap() {
		if (w2dc_getMapEngine() == 'google') {
			$html = '<img src="//maps.googleapis.com/maps/api/staticmap?size=795x350&';
			foreach ($this->locations_array  AS $location) {
				if ($location->map_coords_1 != 0 && $location->map_coords_2 != 0) {
					$html .= 'markers=';
					if (get_option('w2dc_map_markers_type') == 'images' && W2DC_MAP_ICONS_URL && $location->map_icon_file) {
						$html .= 'icon:' . W2DC_MAP_ICONS_URL . 'icons/' . urlencode($location->map_icon_file) . '%7C';
					}
				}
				$html .= $location->map_coords_1 . ',' . $location->map_coords_2 . '&';
			}
			if ($this->map_zoom) {
				$html .= 'zoom=' . $this->map_zoom;
			}
			if (get_option('w2dc_google_api_key')) {
				$html .= '&key='.get_option('w2dc_google_api_key');
			}
			$html .= '" />';
		} elseif (w2dc_getMapEngine() == 'mapbox') {
			$html = '';
			if ($this->map_zoom) {
				$zoom = $this->map_zoom;
			} else {
				$zoom = 10;
			}
			foreach ($this->locations_array  AS $location) {
				$html .= '<address>' . $location->getWholeAddress(false) . '</address>';
				$html .= '<img src="' . w2dc_getMapBoxStyleForStatic() . '/static/';
				if ($location->map_coords_1 != 0 && $location->map_coords_2 != 0) {
					$html .= 'pin-l+ea3a83(' . $location->map_coords_2 . ',' . $location->map_coords_1 . ')/' . $location->map_coords_2 . ',' . $location->map_coords_1 . ',' . $zoom . '/';
				}
				$html .= '795x350?access_token=' . get_option('w2dc_mapbox_api_key') . '" /><br /><br />';
			}
		}
		return $html;
	}
	
	public function getWrapperAttributes() {
		$options = array();
	
		$options['class'] = "w2dc-content w2dc-map-wrapper";
		if (!empty($this->args['search_on_map_right'])) {
			$options['class'] .= " w2dc-map-sidebar-right";
		}
		if (!empty($this->args['search_on_map']) && !empty($this->args['search_on_map_open'])) {
			$options['class'] .= " w2dc-map-sidebar-open";
		}
		if (!empty($this->display_args['sticky_scroll'])) {
			$options['class'] .= " w2dc-sticky-scroll";
		}
		$options['style'] = "";
		if (!empty($this->display_args['height'])) {
			if ($this->display_args['height'] == '100%') {
				$options['style'] .= " height: 100%;";
			} else {
				$options['style'] .= " height: " . ($this->display_args['height'] + 2) . "px;";
			}
		} else {
			$options['style'] .= " height: 400px;";
		}
	
		$options['data-id'] = $this->map_id;
			
		$options_string = '';
		foreach ($options AS $name=>$val) {
			$options_string .= esc_attr($name) . '="' . esc_attr($val) . '" ';
		}
	
		return $options_string;
	}
	
	public function getCanvasWrapperAttributes() {
		$options = array();
	
		$options['class'] = "w2dc-map-canvas-wrapper";
	
		if (!empty($this->display_args['sticky_scroll_toppadding'])) {
			$options['data-toppadding'] = $this->display_args['sticky_scroll_toppadding'];
		}
		$options['data-height'] = $this->display_args['height'];
			
		$options_string = '';
		foreach ($options AS $name=>$val) {
			$options_string .= esc_attr($name) . '="' . esc_attr($val) . '" ';
		}
	
		return $options_string;
	}
	
	public function getCanvasAttributes() {
		$options = array();
	
		$options['class'] = "w2dc-map-canvas";
	
		$options['data-shortcode-hash'] = $this->map_id;
	
		$options['style'] = "";
		if (!empty($this->display_args['width'])) {
			$options['style'] .= " max-width: " . $this->display_args['width'] . "px;";
		}
		if (!empty($this->display_args['height'])) {
			if ($this->display_args['height'] == '100%') {
				$options['style'] .= " height: 100%;";
			} else {
				$options['style'] .= " height: " . $this->display_args['height'] . "px;";
			}
		} else {
			$options['style'] .= " height: 400px;";
		}
			
		$options_string = '';
		foreach ($options AS $name=>$val) {
			$options_string .= esc_attr($name) . '="' . esc_attr($val) . '" ';
		}
	
		return $options_string;
	}

	public function display($display_args = array()) {
		$this->display_args = array_merge(array(
				'show_directions' => true,
				'static_image' => false,
				'enable_radius_circle' => true,
				'enable_clusters' => true,
				'show_summary_button' => true,
				'show_readmore_button' => true,
				'width' => false,
				'height' => 400,
				'sticky_scroll' => false,
				'sticky_scroll_toppadding' => 10,
				'map_style_name' => '',
				'search_form' => false,
				'draw_panel' => false,
				'custom_home' => false,
				'enable_full_screen' => true,
				'enable_wheel_zoom' => true,
				'enable_dragging_touchscreens' => true,
				'center_map_onclick' => false,
				'enable_infowindow' => true,
				'close_infowindow_out_click' => true,
		), $display_args);
		
		$do_display_map = apply_filters('w2dc_do_display_map', true, $this);
		
		if ($do_display_map) {
			$locations_options = json_encode(w2dc_utf8ize($this->locations_option_array));
			$map_args = json_encode($this->args);
			
			$width = trim($this->display_args['width'], "px");
			$height = trim($this->display_args['height'], "px");
			
			// since WP 6.1.0 it adds unescaped decoding="async" in img tags breaking maps output 
			add_filter("wp_img_tag_add_decoding_attr", "__return_false", 1000);
			
			w2dc_renderTemplate('maps/map.tpl.php',
					array(
							'locations_options' => $locations_options,
							'locations_array' => $this->locations_array,
							'show_directions' => $this->display_args['show_directions'],
							'static_image' => $this->display_args['static_image'],
							'enable_radius_circle' => $this->display_args['enable_radius_circle'],
							'enable_clusters' => $this->display_args['enable_clusters'],
							'map_zoom' => $this->map_zoom,
							'show_summary_button' => $this->display_args['show_summary_button'],
							'show_readmore_button' => $this->display_args['show_readmore_button'],
							'map_style' => w2dc_getSelectedMapStyle($this->display_args['map_style_name']),
							'search_form' => $this->display_args['search_form'],
							'draw_panel' => $this->display_args['draw_panel'],
							'custom_home' => $this->display_args['custom_home'],
							'width' => $this->display_args['width'],
							'height' => $this->display_args['height'],
							'sticky_scroll' => $this->display_args['sticky_scroll'],
							'sticky_scroll_toppadding' => $this->display_args['sticky_scroll_toppadding'],
							'enable_full_screen' => $this->display_args['enable_full_screen'],
							'enable_wheel_zoom' => $this->display_args['enable_wheel_zoom'],
							'enable_dragging_touchscreens' => $this->display_args['enable_dragging_touchscreens'],
							'center_map_onclick' => $this->display_args['center_map_onclick'],
							'enable_infowindow' => $this->display_args['enable_infowindow'],
							'close_infowindow_out_click' => $this->display_args['close_infowindow_out_click'],
							'map_object' => $this,
							'map_id' => $this->map_id,
							'listings_content' => (!empty($this->args['search_on_map_listings']) && $this->args['search_on_map_listings'] != 'none') ? $this->buildListingsContent() : '',
							'map_args' => $map_args,
							'args' => $this->args
			));
		}
	}
	
	public function is_ajax_map_loading() {
		if (isset($this->args['ajax_map_loading']) && $this->args['ajax_map_loading'] && ((isset($this->args['start_address']) && $this->args['start_address']) || ((isset($this->args['start_latitude']) && $this->args['start_latitude']) && (isset($this->args['start_longitude']) && $this->args['start_longitude']))))
			return true;
		else
			return false;
	}
}

?>