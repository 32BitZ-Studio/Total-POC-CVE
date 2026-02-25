<?php

class w2dc_locationGeoname {
	
	private $last_ret;
	private $last_status = '';
	private $last_error = '';
	
	private function getURL($query) {
		if (w2dc_getMapEngine() == 'google') {
			$fullUrl = '';
			
			if (get_option('w2dc_address_autocomplete_code')) {
				$iso3166 = strtolower(get_option('w2dc_address_autocomplete_code'));
				if ($iso3166 == 'gb') {
					$iso3166 = 'uk';
				}
				$region = '&region='.$iso3166;
			} else {
				$region = '';
			}
			
			if (get_option('w2dc_google_api_key_server')) {
				$fullUrl = sprintf("https://maps.googleapis.com/maps/api/place/textsearch/json?query=%s&language=en&key=%s%s", urlencode($query), get_option('w2dc_google_api_key_server'), $region);
			}
			
			return $fullUrl;
		} elseif (w2dc_getMapEngine() == 'mapbox') {
			$fullUrl = '';
			
			if (get_option('w2dc_address_autocomplete_code')) {
				$iso3166 = strtolower(get_option('w2dc_address_autocomplete_code'));
				$country = '&country='.$iso3166;
			} else {
				$country = '';
			}
			
			if (get_option('w2dc_mapbox_api_key')) {
				// example:   https://docs.mapbox.com/playground/geocoding/
				// API docs:  https://docs.mapbox.com/api/search/geocoding/
				$fullUrl = sprintf("https://api.mapbox.com/geocoding/v5/mapbox.places/%s.json?language=en&access_token=%s%s", urlencode($query), get_option('w2dc_mapbox_api_key'), $country);
			}
			
			return $fullUrl;
		}
	}
	
	private function processResult($ret, $return) {
		$use_districts = true;
		$use_provinces = true;
		
		if ($ret) {
			if (w2dc_getMapEngine() == 'google') {
				$this->last_status = $ret["status"];
				
				if ($ret["status"] == "OK") {
					if ($return == 'coordinates') {
						return array($ret["results"][0]["geometry"]["location"]["lng"], $ret["results"][0]["geometry"]["location"]["lat"], $ret["results"][0]["place_id"]);
					} elseif ($return == 'geoname') {
						$geocoded_name = array();
						foreach ($ret["results"][0]["address_components"] AS $component) {
							if (@$component["types"][0] == "sublocality") {
								$town = $component["long_name"];
								$geocoded_name[] = $town;
							}
							if (@$component["types"][0] == "locality") {
								$city = $component["long_name"];
								$geocoded_name[] = $city;
							}
							if ($use_districts)
								if (@$component["types"][0] == "administrative_area_level_3") {
									$district = $component["long_name"];
									$geocoded_name[] = $district;
								}
							if ($use_provinces)
								if (@$component["types"][0] == "administrative_area_level_2") {
									$province = $component["long_name"];
									$geocoded_name[] = $province;
								}
							if (@$component["types"][0] == "administrative_area_level_1") {
								$state = $component["long_name"];
								$geocoded_name[] = $state;
							}
							if (@$component["types"][0] == "country") {
								$country = $component["long_name"];
								$geocoded_name[] = $country;
							}
						}
						return implode(', ', $geocoded_name);
					} elseif ($return == 'address') {
						return @$ret["results"][0]["formatted_address"];
					}
				} elseif (!empty($ret['error_message'])) {
					$this->last_error = $ret['error_message'];
					
					return new WP_Error(403, $ret['error_message']);
				}
			} elseif (w2dc_getMapEngine() == 'mapbox') {
				if (!empty($ret['features'])) {
					$this->last_status = 200;
					
					if ($return == 'coordinates') {
						return array($ret["features"][0]["geometry"]["coordinates"][0], $ret["features"][0]["geometry"]["coordinates"][1], $ret["features"][0]["id"]);
					} elseif ($return == 'geoname' && $return == 'address') {
						return @$ret["features"][0]["place_name"];
					}
				} elseif (!empty($ret['message'])) {
					$this->last_status = 403;
					$this->last_error = $ret['message'];
					
					return new WP_Error(403, $ret['message']);
				}
			}
		}
		return '';
	}

	public function geocodeRequest($query, $return = 'geoname') {
		$fullUrl = $this->getURL($query);

		$response = wp_remote_get($fullUrl);
		$body = wp_remote_retrieve_body($response);
		
		$ret = json_decode($body, true);
		
		$this->last_ret = $ret;
		
		if ($return == 'test') {
			if (is_wp_error($response)) {
				return new WP_Error(403, $response->get_error_message());
			} else {
				$result = $this->processResult($ret, $return);
				
				if (is_wp_error($result)) {
					return $result;
				} else {
					return $ret;
				}
			}
		}
		
		$address = $this->processResult($ret, $return);
		
		return $address;
	}
	
	public function getLastStatus() {
		return $this->last_status;
	}
	
	public function getLastError() {
		return $this->last_error;
	}
}
?>