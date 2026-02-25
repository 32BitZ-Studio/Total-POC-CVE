if (w2dc_js_objects.is_maps_used && !w2dc_maps_objects.notinclude_maps_api) {
	var w2dc_3rd_party_maps_plugin = false;
	var _warn = console.warn,
	    _error = console.error;
	console.error = function() {
	    var err = arguments[0];
	    if (typeof err == "string") {
		    if (err.indexOf('InvalidKeyMapError') != -1 || err.indexOf('MissingKeyMapError') != -1) {
		    	if (w2dc_3rd_party_maps_plugin)
					alert('Web 2.0 Directory plugin: another plugin or your theme calls Google Maps library without keys. This may cause problems with Google Maps, Geocoding, addition/edition listings locations, autocomplete on addresses fields.\n\nTry to find which plugin calls Google Maps library without keys. Insert keys in its settings or disable this plugin.');
				else
					alert('Web 2.0 Directory plugin: your Google browser API key is invalid or missing. Log in to console https://code.google.com/apis/console and generate new key. Follow instructions https://www.salephpscripts.com/wordpress_directory/demo/documentation/#google_maps_keys Or you can disable Google Maps in listings levels settings.');
		    }
		    if (err.indexOf('RefererNotAllowedMapError') != -1) {
		    	var hostname = window.location.hostname.replace('www.','');
		    	var protocol = window.location.protocol;
		    	alert('Web 2.0 Directory plugin: the current URL loading the Google Maps has not been added to the list of allowed referrers. Please check the "Accept requests from these HTTP referrers (web sites)" field in Google API console. Follow instructions https://www.salephpscripts.com/wordpress_directory/demo/documentation/#google_maps_keys \n\nTry one of the following URLs: *.'+hostname+'/*, '+protocol+'//'+hostname+'/*, '+protocol+'//www.'+hostname+'/*');
		    }
		    if (err.indexOf('RefererDeniedMapError') != -1) {
				alert('Web 2.0 Directory plugin: Your application was blocked for non-compliance with the Google Maps Platform Terms of Service, following several email notifications. To appeal the block and have your implementation reviewed, please complete this form. You will receive a response via email within a few business days.\n\nhttps://developers.google.com/maps/documentation/javascript/error-messages?hl=en');
			}
		    if (err.indexOf('ApiNotActivatedMapError') != -1) {
		    	alert('Web 2.0 Directory plugin: you have to enable following APIs in Google API console https://code.google.com/apis/console : Google Maps JavaScript API, Google Static Maps API, Google Places API Web Service, Google Maps Geocoding API and Google Maps Directions API. Follow instructions https://www.salephpscripts.com/wordpress_directory/demo/documentation/#google_maps_keys\n\nNote, that it requires some time for changes to take effect.');
		    }
		    if (err.indexOf('You have exceeded your request quota for this API.') != -1) {
		    	alert('Google Maps is no longer free. You must enable billing with a credit card and have a valid API key for all of your projects. https://developers.google.com/maps/gmp-get-started');
		    }
	    }
	    return _error.apply(console, arguments);
	};
	console.warn = function() {
		var err = arguments[0];
		if (typeof err == "string") {
			if (err.indexOf('InvalidKey') != -1 || err.indexOf('NoApiKeys') != -1) {
				if (w2dc_3rd_party_maps_plugin)
					alert('Web 2.0 Directory plugin: another plugin or your theme calls Google Maps library without keys. This may cause problems with Google Maps, Geocoding, addition/edition listings locations, autocomplete on addresses fields.\n\nTry to find which plugin calls Google Maps library without keys. Insert keys in its settings or disable this plugin.');
				else
					alert('Web 2.0 Directory plugin: your Google browser API key is invalid or missing. Log in to console https://code.google.com/apis/console and generate new key. Follow instructions https://www.salephpscripts.com/wordpress_directory/demo/documentation/#google_maps_keys');
			}
		}
		return _warn.apply(console, arguments);
	};
}

// google_maps_edit.js -------------------------------------------------------------------------------------------------------------------------------------------
(function($) {
	"use strict";

	var w2dc_load_maps_backend = function() {

		w2dc_geocoder_backend = new google.maps.Geocoder();

		if ($("#w2dc-map-canvas").length) {
			var mapOptions = {
					zoom: 1,
					scrollwheel: true,
					gestureHandling: 'greedy',
					disableDoubleClickZoom: true,
					mapTypeId: google.maps.MapTypeId.ROADMAP,
					fullscreenControl: false
			};
			if (w2dc_maps_objects.map_style) {
				mapOptions.styles = eval(w2dc_maps_objects.map_style);
			}
			w2dc_map_backend = new google.maps.Map(document.getElementById("w2dc-map-canvas"), mapOptions);

			var w2dc_coords_array_1 = new Array();
			var w2dc_coords_array_2 = new Array();

			if (w2dc_isAnyLocation_backend())
				w2dc_generateMap_backend();
			else
				w2dc_map_backend.setCenter(new google.maps.LatLng(w2dc_maps_objects.default_latitude, w2dc_maps_objects.default_longitude));

			google.maps.event.addListener(w2dc_map_backend, 'zoom_changed', function() {
				if (w2dc_allow_map_zoom_backend)
					$(".w2dc-map-zoom").val(w2dc_map_backend.getZoom());
			});
		}
	}

	window.w2dc_load_maps_api_backend = function() {
		$(document).trigger('w2dc_google_maps_api_loaded');

		window.addEventListener('load', w2dc_load_maps_backend());
		
		w2dc_load_maps_api(); // Load frontend maps
	}
	
	window.w2dc_setupAutocomplete = function() {
		$(".w2dc-listing-field-autocomplete").each( function() {
			var autocomplete_input = $(this);
			var place_id_input = autocomplete_input.parent().find(".w2dc-place-id-input");
			
			autocomplete_input.on("change paste keyup blur", function() {
				if ($(this).val() == '') {
					place_id_input.val('');
				}
			});
			
			if (google.maps && google.maps.places) {
				var code = w2dc_maps_objects.address_autocomplete_code;
				if (!code || code === "0") {
					var options = { };
				} else {
					var options = { componentRestrictions: {country: w2dc_maps_objects.address_autocomplete_code}};
				}
				var searchBox = new google.maps.places.Autocomplete(this, options);
				
				if ($("#w2dc-map-canvas").length) {
					google.maps.event.addListener(searchBox, 'place_changed', function () {
						var place = searchBox.getPlace();
						place_id_input.val(place.place_id);
						
						w2dc_generateMap_backend();
					});
				}
			}
		});
	}

	function w2dc_setMapCenter_backend(w2dc_coords_array_1, w2dc_coords_array_2) {
		var count = 0;
		var bounds = new google.maps.LatLngBounds();
		for (count == 0; count<w2dc_coords_array_1.length; count++)  {
			bounds.extend(new google.maps.LatLng(w2dc_coords_array_1[count], w2dc_coords_array_2[count]));
		}
		if (count == 1) {
			if ($(".w2dc-map-zoom").val() == '' || $(".w2dc-map-zoom").val() == 0)
				var zoom_level = 1;
			else
				var zoom_level = parseInt($(".w2dc-map-zoom").val());
		} else {
			w2dc_map_backend.fitBounds(bounds);
			var zoom_level = w2dc_map_backend.getZoom();
		}
		w2dc_map_backend.setCenter(bounds.getCenter());
	
		// allow/disallow map zoom in listener, this option needs because w2dc_map.setZoom() also calls this listener
		w2dc_allow_map_zoom_backend = false;
		w2dc_map_backend.setZoom(zoom_level);
		w2dc_allow_map_zoom_backend = true;
	}
	
	var w2dc_coords_array_1 = new Array();
	var w2dc_coords_array_2 = new Array();
	var w2dc_attempts = 0;
	window.w2dc_generateMap_backend = function() {
		w2dc_ajax_loader_target_show($("#w2dc-map-canvas"));
		w2dc_coords_array_1 = new Array();
		w2dc_coords_array_2 = new Array();
		w2dc_attempts = 0;
		w2dc_clearOverlays_backend();
		w2dc_geocodeAddress_backend(0);
		//w2dc_setupAutocomplete();
	}
	
	function w2dc_setFoundPoint(results, location_obj, i) {
		var point = results[0].geometry.location;
		$(".w2dc-map-coords-1:eq("+i+")").val(point.lat());
		$(".w2dc-map-coords-2:eq("+i+")").val(point.lng());
		var map_coords_1 = point.lat();
		var map_coords_2 = point.lng();
		w2dc_coords_array_1.push(map_coords_1);
		w2dc_coords_array_2.push(map_coords_2);
		location_obj.setPoint(point);
		location_obj.w2dc_placeMarker();
		w2dc_geocodeAddress_backend(i+1);

		if ((i+1) == $(".w2dc-location-in-metabox").length) {
			w2dc_setMapCenter_backend(w2dc_coords_array_1, w2dc_coords_array_2);
			w2dc_ajax_loader_target_hide("w2dc-map-canvas");
		}
	}

	window.w2dc_geocodeAddress_backend = function(i) {
		if ($(".w2dc-location-in-metabox:eq("+i+")").length) {
			var locations_drop_boxes = [];
			$(".w2dc-location-in-metabox:eq("+i+")").find("select").each(function(j, val) {
				if ($(this).val())
					locations_drop_boxes.push($(this).children(":selected").text());
			});
	
			var location_string = locations_drop_boxes.reverse().join(', ');
	
			if ($(".w2dc-manual-coords:eq("+i+")").is(":checked") && $(".w2dc-map-coords-1:eq("+i+")").val()!='' && $(".w2dc-map-coords-2:eq("+i+")").val()!='' && ($(".w2dc-map-coords-1:eq("+i+")").val()!=0 || $(".w2dc-map-coords-2:eq("+i+")").val()!=0)) {
				var map_coords_1 = $(".w2dc-map-coords-1:eq("+i+")").val();
				var map_coords_2 = $(".w2dc-map-coords-2:eq("+i+")").val();
				if ($.isNumeric(map_coords_1) && $.isNumeric(map_coords_2)) {
					var point = new google.maps.LatLng(map_coords_1, map_coords_2);
					w2dc_coords_array_1.push(map_coords_1);
					w2dc_coords_array_2.push(map_coords_2);
	
					var location_obj = new w2dc_glocation_backend(i, point, 
						location_string,
						$(".w2dc-address-line-1:eq("+i+")").val(),
						$(".w2dc-address-line-2:eq("+i+")").val(),
						$(".w2dc-zip-or-postal-index:eq("+i+")").val(),
						$(".w2dc-map-icon-file:eq("+i+")").val()
					);
					location_obj.w2dc_placeMarker();
				}
				w2dc_geocodeAddress_backend(i+1);
				if ((i+1) == $(".w2dc-location-in-metabox").length) {
					w2dc_setMapCenter_backend(w2dc_coords_array_1, w2dc_coords_array_2);
					w2dc_ajax_loader_target_hide("w2dc-map-canvas");
				}
			} else if (location_string || $(".w2dc-address-line-1:eq("+i+")").val() || $(".w2dc-address-line-2:eq("+i+")").val() || $(".w2dc-zip-or-postal-index:eq("+i+")").val()) {
				var location_obj = new w2dc_glocation_backend(i, null, 
					location_string,
					$(".w2dc-address-line-1:eq("+i+")").val(),
					$(".w2dc-address-line-2:eq("+i+")").val(),
					$(".w2dc-zip-or-postal-index:eq("+i+")").val(),
					$(".w2dc-map-icon-file:eq("+i+")").val()
				);

				// Geocode by address
				var code = w2dc_maps_objects.address_autocomplete_code;
				if (!code || code === "0") {
					var options = { 'address': location_obj.compileAddress() };
				} else {
					var options = { 'address': location_obj.compileAddress(), componentRestrictions: {country: w2dc_maps_objects.address_autocomplete_code}};
				}

				if (w2dc_geocoder_backend !== null) {
					w2dc_geocoder_backend.geocode( options, function(results, status) {
						if (status != google.maps.GeocoderStatus.OK) {
							if (status == google.maps.GeocoderStatus.OVER_QUERY_LIMIT && w2dc_attempts < 5) {
								w2dc_attempts++;
								setTimeout('w2dc_geocodeAddress_backend('+i+')', 2000);
							} else if (status == google.maps.GeocoderStatus.ZERO_RESULTS) {
								// last chance to find correct location with Places API
								var service = new google.maps.places.PlacesService(w2dc_map_backend);
								service.textSearch({
									query: options.address
								}, function(results, status) {
									if (status == google.maps.places.PlacesServiceStatus.OK) {
										w2dc_setFoundPoint(results, location_obj, i);
									} else {
										alert("Sorry, we are unable to geocode address (address line: "+options.address+" #"+(i)+") for the following reason: " + status);
										w2dc_ajax_loader_target_hide("w2dc-map-canvas");
									}
								});
							} else {
								alert("Sorry, we are unable to geocode address (address line:"+options.address+" #"+(i)+") for the following reason: " + status);
								w2dc_ajax_loader_target_hide("w2dc-map-canvas");
							}
						} else {
							w2dc_setFoundPoint(results, location_obj, i);
						}
					});
				} else {
					alert("Google Geocoder was not loaded. Check Google API keys and enable Google Maps Geocoding API in Google APIs console.");
					w2dc_ajax_loader_target_hide("w2dc-map-canvas");
				}
			} else
				w2dc_ajax_loader_target_hide("w2dc-map-canvas");
		} else
			w2dc_attempts = 0;
	}

	window.w2dc_placeMarker_backend = function(w2dc_glocation) {
		if (w2dc_maps_objects.map_markers_type != 'icons') {
			if (w2dc_maps_objects.global_map_icons_path != '') {
				var re = /(?:\.([^.]+))?$/;
				if (w2dc_glocation.map_icon_file && typeof re.exec(w2dc_maps_objects.global_map_icons_path+'icons/'+w2dc_glocation.map_icon_file)[1] != "undefined")
					var icon_file = w2dc_maps_objects.global_map_icons_path+'icons/'+w2dc_glocation.map_icon_file;
				else
					var icon_file = w2dc_maps_objects.global_map_icons_path+"blank.png";
		
				var customIcon = {
						url: icon_file,
						size: new google.maps.Size(parseInt(w2dc_maps_objects.marker_image_width), parseInt(w2dc_maps_objects.marker_image_height)),
						origin: new google.maps.Point(0, 0),
						anchor: new google.maps.Point(parseInt(w2dc_maps_objects.marker_image_anchor_x), parseInt(w2dc_maps_objects.marker_image_anchor_y))
				};
		
				var marker = new google.maps.Marker({
						position: w2dc_glocation.point,
						map: w2dc_map_backend,
						icon: customIcon,
						draggable: true
				});
			} else 
				var marker = new google.maps.Marker({
						position: w2dc_glocation.point,
						map: w2dc_map_backend,
						draggable: true
				});
			
			w2dc_markersArray_backend.push(marker);
			google.maps.event.addListener(marker, 'click', function() {
				w2dc_show_infoWindow_backend(w2dc_glocation, marker);
			});
		
			google.maps.event.addListener(marker, 'dragend', function(event) {
				var point = marker.getPosition();
				if (point !== undefined) {
					var selected_location_num = w2dc_glocation.index;
					$(".w2dc-manual-coords:eq("+w2dc_glocation.index+")").prop("checked", true);
					$(".w2dc-manual-coords:eq("+w2dc_glocation.index+")").parents(".w2dc-manual-coords-wrapper").find(".w2dc-manual-coords-block").show(200);
					
					$(".w2dc-map-coords-1:eq("+w2dc_glocation.index+")").val(point.lat());
					$(".w2dc-map-coords-2:eq("+w2dc_glocation.index+")").val(point.lng());
				}
			});
		} else {
			w2dc_load_richtext();
			
			var icon = false;
			var color = false;
			if (!w2dc_glocation.map_icon_file || (typeof location.map_icon_file == 'string' && w2dc_glocation.map_icon_file.indexOf("w2dc-fa-") == -1)) {
				if (!icon && w2dc_maps_objects.default_marker_icon) {
					icon = w2dc_maps_objects.default_marker_icon;
				}
			} else {
				icon = w2dc_glocation.map_icon_file;
			}
			if (!color) {
				if (w2dc_maps_objects.default_marker_color) {
					color = w2dc_maps_objects.default_marker_color;
				} else {
					color = '#428bca';
				}
			}
			
			if (icon) {
				var map_marker_icon = '<span class="w2dc-map-marker-icon w2dc-fa '+icon+'" style="color: '+color+';"></span>';
				var map_marker_class = 'w2dc-map-marker';
			} else {
				var map_marker_icon = '';
				var map_marker_class = 'w2dc-map-marker-empty';
			}

			var marker = new RichMarker({
				position: w2dc_glocation.point,
				map: w2dc_map_backend,
				flat: true,
				draggable: true,
				height: 40,
				content: '<div class="'+map_marker_class+'" style="background: '+color+' none repeat scroll 0 0;">'+map_marker_icon+'</div>'
			});
			
			w2dc_markersArray_backend.push(marker);
			google.maps.event.addListener(marker, 'position_changed', function(event) {
				var point = marker.getPosition();
				if (point !== undefined) {
					var selected_location_num = w2dc_glocation.index;
					$(".w2dc-manual-coords:eq("+w2dc_glocation.index+")").prop("checked", true);
					$(".w2dc-manual-coords:eq("+w2dc_glocation.index+")").parents(".w2dc-manual-coords-wrapper").find(".w2dc-manual-coords-block").show(200);
					
					$(".w2dc-map-coords-1:eq("+w2dc_glocation.index+")").val(point.lat());
					$(".w2dc-map-coords-2:eq("+w2dc_glocation.index+")").val(point.lng());
				}
			});
		}
	}
	
	// This function builds info Window and shows it hiding another
	function w2dc_show_infoWindow_backend(w2dc_glocation, marker) {
		var address = w2dc_glocation.compileHtmlAddress();
		var index = w2dc_glocation.index;
	
		// we use global w2dc_infoWindow_backend, not to close/open it - just to set new content (in order to prevent blinking)
		if (!w2dc_infoWindow_backend)
			w2dc_infoWindow_backend = new google.maps.InfoWindow();
	
		w2dc_infoWindow_backend.setContent(address);
		w2dc_infoWindow_backend.open(w2dc_map_backend, marker);
	}
	
	function w2dc_clearOverlays_backend() {
		if (w2dc_markersArray_backend) {
			for(var i = 0; i<w2dc_markersArray_backend.length; i++){
				w2dc_markersArray_backend[i].setMap(null);
			}
		}
	}
	
	function w2dc_isAnyLocation_backend() {
		var is_location = false;
		$(".w2dc-location-in-metabox").each(function(i, val) {
			var locations_drop_boxes = [];
			$(this).find("select").each(function(j, val) {
				if ($(this).val()) {
					is_location = true;
					return false;
				}
			});
	
			if ($(".w2dc-manual-coords:eq("+i+")").is(":checked") && $(".w2dc-map-coords-1:eq("+i+")").val()!='' && $(".w2dc-map-coords-2:eq("+i+")").val()!='' && ($(".w2dc-map-coords-1:eq("+i+")").val()!=0 || $(".w2dc-map-coords-2:eq("+i+")").val()!=0)) {
				is_location = true;
				return false;
			}
		});
		if (is_location)
			return true;
	
		if ($(".w2dc-address-line-1[value!='']").length != 0)
			return true;
	
		if ($(".w2dc-address-line-2[value!='']").length != 0)
			return true;
	
		if ($(".w2dc-zip-or-postal-index[value!='']").length != 0)
			return true;
	}
})(jQuery);

// google_maps_view.js -------------------------------------------------------------------------------------------------------------------------------------------
(function($) {
	"use strict";
	
	window.w2dc_buildPoint = function(lat, lng) {
		return new google.maps.LatLng(lat, lng);
	}

	window.w2dc_buildBounds = function() {
		return new google.maps.LatLngBounds();
	}

	window.w2dc_extendBounds = function(bounds, point) {
		bounds.extend(point);
	}

	window.w2dc_mapFitBounds = function(map_id, bounds) {
		w2dc_maps[map_id].fitBounds(bounds);
	}

	window.w2dc_getMarkerPosition = function(marker) {
		return marker.position;
	}

	window.w2dc_closeInfoWindow = function(map_id) {
		if (typeof w2dc_infoWindows[map_id] != 'undefined') {
			w2dc_infoWindows[map_id].close();
		}
		
		w2dc_checkWheelZoom(map_id);
	}
	
	window.w2dc_checkWheelZoom = function(map_id) {
		
		var attrs_array = w2dc_get_map_markers_attrs_array(map_id);
		
		var enable_wheel_zoom = attrs_array.enable_wheel_zoom;
		if (enable_wheel_zoom) {
			var enable_wheel_zoom = true;
		} else {
			var enable_wheel_zoom = false;
		}
		
		var options = {
				scrollwheel: enable_wheel_zoom
		};
		w2dc_maps[map_id].setOptions(options);
	}
	
	window.w2dc_geocodeAddress = function(address, callback) {
		if (typeof google.maps != 'undefined' && typeof google.maps.places != 'undefined') {
			var geocoder = new google.maps.Geocoder();
			geocoder.geocode({'address': address}, function(results, status) {
				if (status == google.maps.GeocoderStatus.OK) {
					var success = true;
					var lat = results[0].geometry.location.lat();
					var lng = results[0].geometry.location.lng();
				} else {
					var success = false;
				}
				callback(success, lat, lng);
			});
		} else {
			callback(false, 0, 0);
			
		}
	}
	
	window.w2dc_callMapResize = function(map_id) {
		google.maps.event.trigger(w2dc_maps[map_id], 'resize');
	}
	
	window.w2dc_setMapCenter = function(map_id, center) {
		w2dc_maps[map_id].setCenter(center);
	}
	
	window.w2dc_setMapZoom = function(map_id, zoom) {
		var listener = google.maps.event.addListener(w2dc_maps[map_id], "idle", function() { 
			w2dc_maps[map_id].setZoom(parseInt(zoom));
			google.maps.event.removeListener(listener); 
		});
		
	}
	
	window.w2dc_panTo = function(map_id, map_coords_1, map_coords_2) {
		w2dc_maps[map_id].panTo(new google.maps.LatLng(map_coords_1, map_coords_2));
	}

	window.w2dc_autocompleteService = function(term, address_autocomplete_code, common_array, response, callback) {
		var code = address_autocomplete_code;
		if (!code || code === "0") {
			var options = { input: term };
		} else {
			var options = { input: term, componentRestrictions: {country: address_autocomplete_code}};
		}
		
		var autoCompleteService = new google.maps.places.AutocompleteService();
		autoCompleteService.getPlacePredictions(options, function (predictions, status) {
			var output_predictions = [];
			$.map(predictions, function (prediction, i) {
				var output_prediction = {
						label: prediction.structured_formatting.main_text,
						value: prediction.description,
						name: prediction.structured_formatting.main_text,
						sublabel: prediction.structured_formatting.secondary_text,
						place_id: prediction.place_id
				};
				output_predictions.push(output_prediction);
			});
			
			callback(output_predictions, common_array, response);
		});
	}

	function w2dc_drawFreeHandPolygon(map_id) {
		var poly = new google.maps.Polyline({
			map: w2dc_maps[map_id],
			clickable:false,
			strokeColor: '#AA2143',
			strokeWeight: 2,
			zIndex: 1000,
		});
		
		var move = google.maps.event.addListener(w2dc_maps[map_id], 'mousemove', function(e) {
			poly.getPath().push(e.latLng);
		});
		
		google.maps.event.addListenerOnce(w2dc_maps[map_id], 'mouseup', function(e) {
			google.maps.event.removeListener(move);
			var path = poly.getPath();
			poly.setMap(null);
		
			// google likes to change letters-names of point property in the path,
			// check them all
			/*var letters = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','z','Mb'];
			for (var i in letters) {
				if (typeof path[letters[i]] != 'undefined' && path[letters[i]].length > 2) {
					var theArrayofLatLng = path[letters[i]];
				}
			}*/
			for (const [key, value] of Object.entries(path)) {
				if (Array.isArray(value)) {
					var theArrayofLatLng = path[key];
				}
			}
			var ArrayforPolygontoUse = w2dc_GDouglasPeucker(theArrayofLatLng, 50);
		
			var geo_poly = [];
			var lat_lng;
			for (lat_lng in ArrayforPolygontoUse) {
				geo_poly.push({'lat': ArrayforPolygontoUse[lat_lng].lat(), 'lng': ArrayforPolygontoUse[lat_lng].lng()});
			}

			if (geo_poly.length) {
				w2dc_sendGeoPolyAJAX(map_id, geo_poly);
			 
				var polyOptions = {
					map: w2dc_maps[map_id],
					fillColor: '#0099FF',
					fillOpacity: 0.3,
					strokeColor: '#AA2143',
					strokeWeight: 1,
					clickable: false,
					zIndex: 1,
					path:ArrayforPolygontoUse,
					editable: false
				}
	
				w2dc_polygons[map_id] = new google.maps.Polygon(polyOptions);
			}
	
			var drawButton = $(w2dc_maps[map_id].getDiv()).find('.w2dc-map-draw').get(0);
			drawButton.drawing_state = 0;
			window.removeEventListener('touchmove', w2dc_stop_touchmove_listener, { passive: false });
			w2dc_maps[map_id].setOptions({ draggableCursor: '' });
			$(drawButton).removeClass('w2dc-btn-active');
			w2dc_disableDrawingMode(map_id);
			google.maps.event.clearListeners(w2dc_maps[map_id].getDiv(), 'mousedown');
			
			var editButton = $(w2dc_maps[map_id].getDiv()).find('.w2dc-map-edit').get(0);
			$(editButton).removeAttr('disabled');
		});
	}
	function w2dc_enableDrawingMode(map_id) {
		$(w2dc_maps[map_id].getDiv()).find('.w2dc-map-custom-controls').hide();

		var options = {
				draggable: false, 
				scrollwheel: false,
				streetViewControl: false
		};
		w2dc_maps[map_id].setOptions(options);
	}
	function w2dc_disableDrawingMode(map_id) {
		$(w2dc_maps[map_id].getDiv()).find('.w2dc-map-custom-controls').show();
		//if ($('#w2dc-map-search-wrapper-'+map_id).length) $('#w2dc-map-search-wrapper-'+map_id).show();
		
		var attrs_array = w2dc_get_map_markers_attrs_array(map_id);
		
		var enable_wheel_zoom = attrs_array.enable_wheel_zoom;
		if (enable_wheel_zoom) {
			var enable_wheel_zoom = true;
		} else {
			var enable_wheel_zoom = false;
		}
		
		var enable_dragging_touchscreens = attrs_array.enable_dragging_touchscreens;
		if (enable_dragging_touchscreens || !('ontouchstart' in document.documentElement)) {
			var enable_dragging = true;
		} else {
			var enable_dragging = false;
		}

		w2dc_maps[map_id].setOptions({
			draggable: enable_dragging, 
			scrollwheel: enable_wheel_zoom,
			streetViewControl: true
		});
	}
	
	window.w2dc_setMapZoomCenter = function(map_id, map_attrs, markers_array) {
		if (
				typeof map_attrs.start_zoom != 'undefined' &&
				map_attrs.start_zoom > 0
				
				 //&& !map_attrs.geolocation // when commented - with enabled start zoom in the settings it zooms on initial page load
		)
			var zoom_level = map_attrs.start_zoom;
	    else if (markers_array.length == 1)
			var zoom_level = markers_array[0][5];
		else if (markers_array.length > 1)
			// fitbounds does not need zoom
			var zoom_level = false;
		else
			var zoom_level = 2;
	
	    if (typeof map_attrs.start_latitude != 'undefined' && map_attrs.start_latitude && typeof map_attrs.start_longitude != 'undefined' && map_attrs.start_longitude) {
	    	
	    	if (wcsearch_get_uri_param('swLat')) {
				var uri_bounds = new google.maps.LatLngBounds();
				var sw_point = new google.maps.LatLng(wcsearch_get_uri_param('swLat'), wcsearch_get_uri_param('swLng'));
				var ne_point = new google.maps.LatLng(wcsearch_get_uri_param('neLat'), wcsearch_get_uri_param('neLng'));
				uri_bounds.extend(sw_point);
				uri_bounds.extend(ne_point);
				
				w2dc_maps[map_id].fitBounds(uri_bounds, 0);
			} else {
				var start_latitude = map_attrs.start_latitude;
				var start_longitude = map_attrs.start_longitude;
				w2dc_setMapCenter(map_id, new google.maps.LatLng(start_latitude, start_longitude));
				if (zoom_level == false) {
					zoom_level = 12;
				}
				// especially set up setZoom on the map without "idle" listener, so it will not "fly" after load
				w2dc_maps[map_id].setZoom(parseInt(zoom_level));
			}

			if (typeof map_attrs.ajax_map_loading != 'undefined' && map_attrs.ajax_map_loading == 1) {
			    // use closures here
			    w2dc_setMapAjaxListener(w2dc_maps[map_id], map_id);
			}
	    } else if (typeof map_attrs.start_address != 'undefined' && map_attrs.start_address) {
	    	// use closures here
	    	w2dc_geocodeStartAddress(map_attrs, map_id, zoom_level);
	    } else if (markers_array.length == 1) {
	    	w2dc_setMapZoom(map_id, zoom_level);
		} else if (zoom_level) {
			// no fitbounds here
			w2dc_setMapCenter(map_id, new google.maps.LatLng(w2dc_maps_objects.default_latitude, w2dc_maps_objects.default_longitude));
		    w2dc_setMapZoom(map_id, zoom_level);
		}
	}
	
	window.w2dc_show_on_map_links = function() {
		$(".w2dc-show-on-map").each(function() {
			var location_id = $(this).data("location-id");

			var passed = false;
			for (var map_id in w2dc_maps) {
				if (typeof w2dc_global_locations_array[map_id] != 'undefined') {
					for (var i=0; i<w2dc_global_locations_array[map_id].length; i++) {
						if (typeof w2dc_global_locations_array[map_id][i] == 'object') {
							if (location_id == w2dc_global_locations_array[map_id][i].id) {
								passed = true;
							}
						}
					}
				}
			}
			if (passed) {
				$(this).parent('.w2dc-listing-figcaption-option').show();
			} else {
				$(this).css({'cursor': 'auto'});
				if ($(this).hasClass('w2dc-btn')) {
					$(this).hide();
				}
			}
		});
	}

	window.w2dc_load_maps = function() {
		for (var i=0; i<w2dc_map_markers_attrs_array.length; i++)
			if (typeof w2dc_maps[w2dc_map_markers_attrs_array[i].map_id] == 'undefined') // workaround for "tricky" themes and plugins to load maps twice
				w2dc_load_map(i);

		w2dc_show_on_map_links();
	}

	window.w2dc_load_maps_api = function() {
		$(document).trigger('w2dc_google_maps_api_loaded');

		// are there any markers?
		if (typeof w2dc_map_markers_attrs_array != 'undefined' && w2dc_map_markers_attrs_array.length) {
			_w2dc_map_markers_attrs_array = JSON.parse(JSON.stringify(w2dc_map_markers_attrs_array));
			window.addEventListener('load', w2dc_load_maps());
		}

		w2dc_load_ajax_initial_elements();
		
		w2dc_setupAutocomplete();

		window.w2dc_getDirections = function(origin, destination, map_id) {
			var directionsService = new google.maps.DirectionsService();
			if (typeof w2dc_directions_display[map_id] == "undefined") {
				w2dc_directions_display[map_id] = new google.maps.DirectionsRenderer(/*{map: w2dc_maps[map_id]}*/);
			}

			var request = {
				origin: origin,
				destination: destination,
				travelMode: google.maps.DirectionsTravelMode.DRIVING
			};

			directionsService.route(request, function(response, status) {
				if (status == google.maps.DirectionsStatus.OK) {
					w2dc_directions_display[map_id].setMap(null);
					w2dc_directions_display[map_id].setMap(w2dc_maps[map_id]);
					w2dc_directions_display[map_id].set('directions', null);
					$("#w2dc-route-container-"+map_id).html("");
					w2dc_directions_display[map_id].setPanel($("#w2dc-route-container-"+map_id)[0]);
					w2dc_directions_display[map_id].setDirections(response);
				} else {
					w2dc_handleDirectionsErrors(status);
				}
			});
		}
		
		$('body').on('click', '.w2dc-get-directions-button', function() {
			var map_id = $(this).data("id");
			var origin = $("#w2dc-origin-address-"+map_id).val();
			var destination = $(".w2dc-select-directions-"+map_id+":checked").val();
			
			w2dc_getDirections(origin, destination, map_id);
		});
		
		$('body').on('click', '.w2dc-show-on-map', function() {
			var location_id = $(this).data("location-id");
			var do_scroll_to_map = $(this).data("scroll-to-map");

			for (var map_id in w2dc_maps) {
				if (typeof w2dc_global_locations_array[map_id] != 'undefined') {
					for (var i=0; i<w2dc_global_locations_array[map_id].length; i++) {
						if (typeof w2dc_global_locations_array[map_id][i] == 'object') {
							if (location_id == w2dc_global_locations_array[map_id][i].id) {
								var location_obj = w2dc_global_locations_array[map_id][i];
								if (!location_obj.is_ajax_markers) {
									w2dc_showInfoWindow(location_obj, location_obj.marker, map_id);

									var map_attrs = w2dc_maps_attrs[map_id];
									if (typeof map_attrs.start_zoom != 'undefined' && map_attrs.start_zoom > 0) {
										w2dc_maps[map_id].setZoom(parseInt(map_attrs.start_zoom));
									}
									w2dc_maps[map_id].setCenter(location_obj.marker.position);
								} else {
									// show empty infoWindow
									w2dc_showInfoWindow(location_obj, location_obj.marker, map_id);
									
									var map_attrs = w2dc_maps_attrs[map_id];
									if (typeof map_attrs.start_zoom != 'undefined' && map_attrs.start_zoom > 0) {
										w2dc_maps[map_id].setZoom(parseInt(map_attrs.start_zoom));
									}
									w2dc_maps[map_id].setCenter(location_obj.marker.position);
									
									var post_data = {
											'locations_ids': [location_obj.id],
											'action': 'w2dc_get_map_marker_info',
											'map_id': map_id,
											'show_summary_button': location_obj.show_summary_button,
											'show_readmore_button': location_obj.show_readmore_button
									};
									$.ajax({
							    		type: "POST",
							    		url: w2dc_js_objects.ajaxurl,
							    		data: eval(post_data),
							    		map_id: map_id,
							    		dataType: 'json',
							    		success: function(response_from_the_action_function) {
							    			var marker_array = response_from_the_action_function[0];
							    			var map_coords_1 = marker_array[1];
									    	var map_coords_2 = marker_array[2];
									    	if ($.isNumeric(map_coords_1) && $.isNumeric(map_coords_2)) {
								    			var point = new google.maps.LatLng(map_coords_1, map_coords_2);
								    			//w2dc_maps[map_id].panTo(point);
						
								    			var new_location_obj = new w2dc_glocation(marker_array[0], point, 
								    				marker_array[3],
								    				marker_array[4],
								    				marker_array[6],
								    				marker_array[7],
								    				marker_array[8],
								    				marker_array[9],
								    				marker_array[10],
								    				marker_array[11],
								    				location_obj.show_summary_button,
								    				location_obj.show_readmore_button,
								    				this.map_id,
								    				true
									    		);
								    			w2dc_showInfoWindow(new_location_obj, location_obj.marker, this.map_id);
									    	}
							    		},
							    		complete: function() {
											//w2dc_ajax_loader_target_hide('w2dc-map-canvas-'+this.map_id);
										}
									});
								}
								
								if (do_scroll_to_map) {
									var offest_top = 100;
									$('html,body').animate({scrollTop: $('#w2dc-map-canvas-'+map_id).offset().top - offest_top}, 'slow');
								}
							}
						}
					}
				}
			}
		});
	}
	
	window.w2dc_init_maps = function() {
		if ((typeof google == 'undefined' || typeof google.maps == 'undefined') && !w2dc_maps_objects.notinclude_maps_api) {
			var script = document.createElement("script");
			script.type = "text/javascript";
			var key = '';
			var language = '';
			if (w2dc_maps_objects.google_api_key)
				key = "&key="+w2dc_maps_objects.google_api_key;
			if (w2dc_js_objects.lang)
				language = "&language="+w2dc_js_objects.lang;
			script.src = "//maps.google.com/maps/api/js?libraries=places"+key+"&callback="+w2dc_maps_callback.callback+language;
			document.body.appendChild(script);
		} else {
			w2dc_3rd_party_maps_plugin = true;
			window[w2dc_maps_callback.callback]();
		}
	}

	//$(function() {
	document.addEventListener("DOMContentLoaded", function() {
		w2dc_init_maps();
	});

	var w2dc_roadmap_name;
    var w2dc_satellite_name;
    window.w2dc_load_map = function(i) {
		var map_id = w2dc_map_markers_attrs_array[i].map_id;
		var markers_array = w2dc_map_markers_attrs_array[i].markers_array;
		var enable_radius_circle = w2dc_map_markers_attrs_array[i].enable_radius_circle;
		var enable_clusters = w2dc_map_markers_attrs_array[i].enable_clusters;
		var show_summary_button = w2dc_map_markers_attrs_array[i].show_summary_button;
		var map_style = w2dc_map_markers_attrs_array[i].map_style;
		var draw_panel = w2dc_map_markers_attrs_array[i].draw_panel;
		var show_readmore_button = w2dc_map_markers_attrs_array[i].show_readmore_button;
		var enable_full_screen = w2dc_map_markers_attrs_array[i].enable_full_screen;
		var enable_wheel_zoom = w2dc_map_markers_attrs_array[i].enable_wheel_zoom;
		var enable_dragging_touchscreens = w2dc_map_markers_attrs_array[i].enable_dragging_touchscreens;
		var show_directions = w2dc_map_markers_attrs_array[i].show_directions;
		var map_attrs = w2dc_map_markers_attrs_array[i].map_attrs;
		var min_zoom = map_attrs.min_zoom;
		var max_zoom = map_attrs.max_zoom;
		
		if (document.getElementById("w2dc-map-canvas-"+map_id)) {
			if (typeof w2dc_fullScreens[map_id] == "undefined" || !w2dc_fullScreens[map_id]) {
				if (!w2dc_js_objects.is_rtl) {
					var cposition = google.maps.ControlPosition.RIGHT_TOP;
				} else {
					var cposition = google.maps.ControlPosition.LEFT_TOP;
				}
				
				if (enable_wheel_zoom) {
					var enable_wheel_zoom = true;
				} else {
					var enable_wheel_zoom = false;
				}
				
				if (enable_dragging_touchscreens || !('ontouchstart' in document.documentElement)) {
					var enable_dragging = true;
				} else {
					var enable_dragging = false;
				}

				var mapOptions = {
						zoom: 1,
						draggable: enable_dragging,
						scrollwheel: enable_wheel_zoom,
						disableDoubleClickZoom: false,
					    streetViewControl: false,
					    streetViewControlOptions: {
					        position: cposition
					    },
						mapTypeControl: false,
						zoomControl: false,
						panControl: false,
						scaleControl: false,
						fullscreenControl: false
					  }
				if (map_style) {
					mapOptions.styles = eval(map_style);
				}
				
				if (min_zoom > 0) {
					mapOptions.minZoom = parseInt(min_zoom);
				}
				if (max_zoom > 0) {
					mapOptions.maxZoom = parseInt(max_zoom);
				}

				w2dc_maps[map_id] = new google.maps.Map(document.getElementById("w2dc-map-canvas-"+map_id), mapOptions);
				w2dc_maps_attrs[map_id] = map_attrs;

				if ($("#w2dc-map-wrapper-"+map_id).hasClass("w2dc-sticky-scroll")) {
					google.maps.event.addListenerOnce(w2dc_maps[map_id], 'idle', function(){
						w2dc_sticky_scroll();
					});
				}
				
				google.maps.event.addListener(w2dc_maps[map_id], 'idle', function() {
					if (typeof wcsearch_sticky_scroll != "undefined") {
						wcsearch_sticky_scroll();
					}
				});

			    var customControls;
			    google.maps.event.addListenerOnce(w2dc_maps[map_id], 'idle', function() {
			    	w2dc_maps[map_id].controls[cposition].clear();

			    	customControls = document.createElement('div');
				    customControls.index = -2;
				    
				    w2dc_maps[map_id].controls[cposition].push(customControls);
				    $(customControls).addClass('w2dc-map-custom-controls');
				    // required workaround, otherwise w2dc_maps[map_id].mapTypes.roadmap will be undefined on reload click
				    if (!w2dc_roadmap_name && typeof w2dc_maps[map_id].mapTypes.roadmap != "undefined") {
				    	w2dc_roadmap_name = w2dc_maps[map_id].mapTypes.roadmap.name;
				    }
				    // required workaround, otherwise w2dc_maps[map_id].mapTypes.satellite will be undefined on reload click
				    if (!w2dc_satellite_name && typeof w2dc_maps[map_id].mapTypes.satellite != "undefined") {
				    	w2dc_satellite_name = w2dc_maps[map_id].mapTypes.satellite.name;
				    }
				    $(customControls).html('<div class="w2dc-btn-group"><button class="w2dc-btn w2dc-btn-primary w2dc-map-btn-zoom-in"><span class="w2dc-glyphicon w2dc-glyphicon-plus"></span></button><button class="w2dc-btn w2dc-btn-primary w2dc-map-btn-zoom-out"><span class="w2dc-glyphicon w2dc-glyphicon-minus"></span></button></div> <div class="w2dc-btn-group"><button class="w2dc-btn w2dc-btn-primary w2dc-map-btn-roadmap">'+w2dc_roadmap_name+'</button><button class="w2dc-btn w2dc-btn-primary w2dc-map-btn-satellite">'+w2dc_satellite_name+'</button>'+(enable_full_screen ? '<button class="w2dc-btn w2dc-btn-primary w2dc-map-btn-fullscreen"><span class="w2dc-glyphicon w2dc-glyphicon-fullscreen"></span></button>' : '')+'</div>');

				    $(customControls).find('.w2dc-map-btn-zoom-in').get(0).addEventListener('click', function() {
				    	w2dc_maps[map_id].setZoom(w2dc_maps[map_id].getZoom() + 1);
				    });
				    $(customControls).find('.w2dc-map-btn-zoom-out').get(0).addEventListener('click', function() {
				    	w2dc_maps[map_id].setZoom(w2dc_maps[map_id].getZoom() - 1);
				    });
				    $(customControls).find('.w2dc-map-btn-roadmap').get(0).addEventListener('click', function() {
				    	w2dc_maps[map_id].setMapTypeId(google.maps.MapTypeId.ROADMAP);
				    });
				    $(customControls).find('.w2dc-map-btn-satellite').get(0).addEventListener('click', function() {
				    	w2dc_maps[map_id].setMapTypeId(google.maps.MapTypeId.HYBRID);
				    });
	
				    var bodyStyle = document.body.style;
				    if (document.body.runtimeStyle)
				        bodyStyle = document.body.runtimeStyle;
				    var originalOverflow = bodyStyle.overflow;
				    var thePanoramaOpened = false;

				    function openFullScreen() {
				    	var center = w2dc_maps[map_id].getCenter();
				    	
				    	document.body.style.overflow = "hidden";
				    	$(customControls).find('.w2dc-map-btn-fullscreen span').removeClass('w2dc-glyphicon-fullscreen');
				    	$(customControls).find('.w2dc-map-btn-fullscreen span').addClass('w2dc-glyphicon-resize-small');
				    	
				    	w2dc_callMapResize(map_id);
				        w2dc_setMapCenter(map_id, center);
				    	
				    	$("#w2dc-map-wrapper-"+map_id).addClass("w2dc-map-wrapper-full-screen");
				        
				        $(window).trigger('resize');
				        
				        $("body").addClass("w2dc-body-fullscreen-map");
				    }
				    function closeFullScreen() {
				    	var center = w2dc_maps[map_id].getCenter();
				    	
				    	document.body.style.overflow = originalOverflow;
			            $(customControls).find('.w2dc-map-btn-fullscreen span').removeClass('w2dc-glyphicon-resize-small');
				        $(customControls).find('.w2dc-map-btn-fullscreen span').addClass('w2dc-glyphicon-fullscreen');
	
				        w2dc_callMapResize(map_id);
				        w2dc_setMapCenter(map_id, center);
				    	
				    	$("#w2dc-map-wrapper-"+map_id).removeClass("w2dc-map-wrapper-full-screen");
				        
				        $(window).trigger('resize');
				        
				        $("body").removeClass("w2dc-body-fullscreen-map");
				    }
				    if (enable_full_screen) {
				    	$(customControls).find('.w2dc-map-btn-fullscreen').get(0).addEventListener('click', function() {
					    	if (typeof w2dc_fullScreens[map_id] == "undefined" || !w2dc_fullScreens[map_id]) {
					    		$("#w2dc-map-canvas-wrapper-"+map_id).addClass("w2dc-map-full-screen");
					    		w2dc_fullScreens[map_id] = true;
					    		openFullScreen();
					    	} else {
					    		$("#w2dc-map-canvas-wrapper-"+map_id).removeClass("w2dc-map-full-screen");
					    		w2dc_fullScreens[map_id] = false;
					    		closeFullScreen();
					    	}
					    });
					    var thePanorama = w2dc_maps[map_id].getStreetView();
					    google.maps.event.addListener(thePanorama, 'visible_changed', function() {
					    	thePanoramaOpened = (this.getVisible() ? true : false);
					    	if ($("#w2dc-map-sidebar-"+map_id).length) {
					    		if (thePanoramaOpened)
					    			$("#w2dc-map-sidebar-"+map_id).hide();
					    		else
					    			$("#w2dc-map-sidebar-"+map_id).show();
					    	}
					    });
					    $(document).on("keyup", function(e) {
					    	if (typeof w2dc_fullScreens[map_id] != "undefined" && w2dc_fullScreens[map_id] && e.keyCode == 27 && !thePanoramaOpened) {
					    		$("#w2dc-map-canvas-wrapper-"+map_id).removeClass("w2dc-map-full-screen");
					    		w2dc_fullScreens[map_id] = false;
					    		closeFullScreen();
					    	}
					    });
				    }

				    if (draw_panel) {
				    	var drawPanel = document.createElement('div');
				    	drawPanel.index = -1;
				    	
					    w2dc_maps[map_id].controls[cposition].push(drawPanel);
					    $(drawPanel).addClass('w2dc-map-draw-panel');
	
					    var drawButton = document.createElement('button');
					    $(drawButton)
					    .addClass('w2dc-btn w2dc-btn-primary w2dc-map-draw')
					    .attr("title", w2dc_maps_objects.draw_area_button)
					    .html('<span class="w2dc-glyphicon w2dc-glyphicon-pencil"></span>');
	
					    drawPanel.appendChild(drawButton);
					    drawButton.map_id = map_id;
						drawButton.drawing_state = 0;
						$(drawButton).on("click", function(e) {
							var map_id = drawButton.map_id;
							if (this.drawing_state == 0) {
								this.drawing_state = 1;
								//$('body').bind('touchmove', function(e){e.preventDefault()});
								window.addEventListener('touchmove', w2dc_stop_touchmove_listener, { passive: false });
								w2dc_clearMarkers(map_id);
								w2dc_closeInfoWindow(map_id);
								w2dc_removeShapes(map_id);
								w2dc_removeCircles(map_id);
			
								w2dc_enableDrawingMode(map_id);
								
								var editButton = $(w2dc_maps[map_id].getDiv()).find('.w2dc-map-edit').get(0);
								$(editButton).attr('disabled', 'disabled');
			
								// remove ajax_map_loading and set drawing_state
								var map_attrs_array;
								if (map_attrs_array = w2dc_get_map_markers_attrs_array(map_id)) {
									map_attrs_array.map_attrs.drawing_state = 1;
									google.maps.event.clearListeners(w2dc_maps[map_id], 'idle');
									delete map_attrs_array.map_attrs.ajax_map_loading;
								}
				
								w2dc_maps[map_id].setOptions({ draggableCursor: 'crosshair' });
								$(this).toggleClass('w2dc-btn-active');
								
								w2dc_maps[map_id].getDiv().map_id = map_id;
								if ($('body').hasClass('w2dc-touch')) {
									w2dc_drawFreeHandPolygon(this.map_id);
								} else {
									var draw_polygon_fn = function(e) {
										var el = e.target;
										do {
											if ($(el).hasClass('w2dc-map-draw-panel')) {
												return;
											}
										} while (el = el.parentNode);
										
										w2dc_drawFreeHandPolygon(this.map_id);
										
										w2dc_maps[map_id].getDiv().removeEventListener('mousedown', draw_polygon_fn);
									};
									
									w2dc_maps[map_id].getDiv().addEventListener('mousedown', draw_polygon_fn);
								}
							} else if (this.drawing_state == 1) {
								this.drawing_state = 0;
								window.removeEventListener('touchmove', w2dc_stop_touchmove_listener, { passive: false });
								w2dc_disableDrawingMode(map_id);
								w2dc_maps[map_id].setOptions({ draggableCursor: '' });
								$(this).toggleClass('w2dc-btn-active');
								google.maps.event.clearListeners(w2dc_maps[map_id].getDiv(), 'mousedown');
								
								// repair ajax_map_loading and set drawing_state
								var map_attrs_array;
								if (map_attrs_array = w2dc_get_map_markers_attrs_array(map_id)) {
									map_attrs_array.map_attrs.drawing_state = 0;
									if (typeof w2dc_get_original_map_markers_attrs_array(map_id).map_attrs.ajax_map_loading != 'undefined' && w2dc_get_original_map_markers_attrs_array(map_id).map_attrs.ajax_map_loading == 1) {
										map_attrs_array.map_attrs.ajax_map_loading = 1;
										google.maps.event.addListener(w2dc_maps[map_id], 'idle', function() {
											w2dc_setAjaxMarkers(w2dc_maps[map_id], map_id); // draw button
										});
									}
								}
							}
						});
					    
					    var editButton = document.createElement('button');
					    $(editButton)
					    .addClass('w2dc-btn w2dc-btn-primary w2dc-map-edit')
					    .attr("title", w2dc_maps_objects.edit_area_button)
					    .html('<span class="w2dc-glyphicon w2dc-glyphicon-edit"></span>')
					    .attr('disabled', 'disabled');
					    
					    drawPanel.appendChild(editButton);
					    editButton.map_id = map_id;
					    editButton.editing_state = 0;
					    $(editButton).on("click", function(e) {
					    	var map_id = editButton.map_id;
							if (this.editing_state == 0) {
								this.editing_state = 1;
								$(this).toggleClass('w2dc-btn-active');
								$(this).attr("title", w2dc_maps_objects.apply_area_button);
								if (typeof w2dc_polygons[map_id] != 'undefined') {
									w2dc_polygons[map_id].setOptions({'editable': true});
								}
							} else if (this.editing_state == 1) {
								this.editing_state = 0;
								$(this).toggleClass('w2dc-btn-active');
								$(this).attr("title", w2dc_maps_objects.edit_area_button);
								if (typeof w2dc_polygons[map_id] != 'undefined') {
									w2dc_polygons[map_id].setOptions({'editable': false});
									
									var path = w2dc_polygons[map_id].getPath();
									var theArrayofLatLng = path.j;
									var geo_poly = [];
									var lat_lng;
									
									for (const [key, value] of Object.entries(path)) {
										if (Array.isArray(value)) {
											var theArrayofLatLng = path[key];
										}
									}
									var ArrayforPolygontoUse = w2dc_GDouglasPeucker(theArrayofLatLng, 50);
								
									for (lat_lng in ArrayforPolygontoUse) {
										geo_poly.push({'lat': ArrayforPolygontoUse[lat_lng].lat(), 'lng': ArrayforPolygontoUse[lat_lng].lng()});
									}
									
									w2dc_sendGeoPolyAJAX(map_id, geo_poly);
								}
							}
					    });
					    
					    var reloadButton = document.createElement('button');
					    $(reloadButton)
					    .addClass('w2dc-btn w2dc-btn-primary w2dc-map-reload')
					    .attr("title", w2dc_maps_objects.reload_map_button)
					    .html('<span class="w2dc-glyphicon w2dc-glyphicon-refresh"></span>');
					    
					    drawPanel.appendChild(reloadButton);
					    reloadButton.map_id = map_id;
					    $(reloadButton).on("click", function(e) {
							var map_id = reloadButton.map_id;
							for (var i=0; i<w2dc_map_markers_attrs_array.length; i++) {
								if (w2dc_map_markers_attrs_array[i].map_id == map_id) {
									w2dc_map_markers_attrs_array[i] = JSON.parse(JSON.stringify(_w2dc_map_markers_attrs_array[i]));
									
									//$('body').unbind('touchmove');
									window.removeEventListener('touchmove', w2dc_stop_touchmove_listener, { passive: false });
			
									var editButton = $(w2dc_maps[map_id].getDiv()).find('.w2dc-map-edit').get(0);
									$(editButton).removeClass('w2dc-btn-active');
									$(editButton).find('.w2dc-map-edit-label').text(w2dc_maps_objects.edit_area_button);
									$(editButton).attr('disabled', 'disabled');
			
									w2dc_clearMarkers(map_id);
									w2dc_closeInfoWindow(map_id);
									w2dc_removeShapes(map_id);
									w2dc_removeCircles(map_id);
									w2dc_load_map(i);
									google.maps.event.trigger(w2dc_maps[map_id], 'idle');
									if (w2dc_global_markers_array[map_id].length) {
							    		var bounds = new google.maps.LatLngBounds();
							    		for (var j=0; j<w2dc_global_markers_array[map_id].length; j++) {
							    			var marker = w2dc_global_markers_array[map_id][j];
										    w2dc_extendBounds(bounds, w2dc_getMarkerPosition(marker));
							    		}
							    		w2dc_mapFitBounds(map_id, bounds);
							    		
							    		var map_attrs = w2dc_map_markers_attrs_array[i].map_attrs;
							    		var markers_array = w2dc_map_markers_attrs_array[i].markers_array;
							    		w2dc_setMapZoomCenter(map_id, map_attrs, markers_array);
							    	}
									
									if (typeof w2dc_controller_args_array[map_id].geo_poly != 'undefined') {
										w2dc_controller_args_array[map_id].geo_poly = [];
									}
									
									break;
								}
							}
						});
	
					    if (w2dc_maps_objects.enable_my_location_button) {
							google.maps.event.addListenerOnce(w2dc_maps[map_id], 'tilesloaded', function(){
								var locationButton = document.createElement('button');
								$(locationButton)
								.addClass('w2dc-btn w2dc-btn-primary w2dc-map-location')
								.attr("title", w2dc_maps_objects.my_location_button)
								.html('<span class="w2dc-glyphicon w2dc-glyphicon-screenshot"></span>');
	
								drawPanel.appendChild(locationButton);
								    
								locationButton.map_id = map_id;
								$(locationButton).on("click", function(e) {
									var map_id = locationButton.map_id;
									if (navigator.geolocation) {
									   	navigator.geolocation.getCurrentPosition(
									   		function(position) {
									    		var start_latitude = position.coords.latitude;
									    		var start_longitude = position.coords.longitude;
											    w2dc_maps[map_id].setCenter(new google.maps.LatLng(start_latitude, start_longitude));
									    	},
									    	function(e) {
										   		//alert(e.message);
										    },
										   	{timeout: 10000}
									    );
									}
								});
							});
					    }
				    }
				    
				    w2dc_geolocatePosition();
			    });
			} // end of (!fullScreen)

		    w2dc_global_markers_array[map_id] = [];
		    w2dc_global_locations_array[map_id] = [];

			var bounds = new google.maps.LatLngBounds();
		    if (markers_array.length) {
		    	if (typeof map_attrs.ajax_markers_loading != 'undefined' && map_attrs.ajax_markers_loading == 1)
					var is_ajax_markers = true;
				else
					var is_ajax_markers = false;
	
		    	var markers = [];
		    	for (var j=0; j<markers_array.length; j++) {
	    			var map_coords_1 = markers_array[j][1];
			    	var map_coords_2 = markers_array[j][2];
			    	if ($.isNumeric(map_coords_1) && $.isNumeric(map_coords_2)) {
		    			var point = new google.maps.LatLng(map_coords_1, map_coords_2);
		    			bounds.extend(point);
	
		    			var location_obj = new w2dc_glocation(
		    				markers_array[j][0],  // location ID
		    				point, 
		    				markers_array[j][3],  // map icon file
		    				markers_array[j][4],  // map icon color
		    				markers_array[j][6],  // listing title
		    				markers_array[j][7],  // logo image
		    				markers_array[j][8],  // listing link
		    				markers_array[j][9],  // content fields output
		    				markers_array[j][10],  // listing link anchor
		    				markers_array[j][11], // is nofollow link
		    				show_summary_button,
		    				show_readmore_button,
		    				map_id,
		    				is_ajax_markers
			    		);
			    		var marker = location_obj.w2dc_placeMarker(map_id);
			    		markers.push(marker);
	
			    		w2dc_global_locations_array[map_id].push(location_obj);
			    	}
	    		}
		    	
		    	// do not fit bounds when there is starting address or coordinates, otherwise it will not center as expected,
		    	// but do it when starting zoom was not defined
		    	if (
		    		(
		    				!(typeof map_attrs.start_latitude != 'undefined' && map_attrs.start_latitude && typeof map_attrs.start_longitude != 'undefined' && map_attrs.start_longitude)
				    		&
				    		!(typeof map_attrs.start_address != 'undefined' && map_attrs.start_address)
				    )
		    		||
		    		!(typeof map_attrs.start_zoom != 'undefined' && map_attrs.start_zoom)
		    	) {
		    		//w2dc_mapFitBounds(map_id, bounds);
		    		
		    		// wait until tiles will be completely loaded
		    		google.maps.event.addListenerOnce(w2dc_maps[map_id], 'idle', function() {
		    			w2dc_maps[map_id].fitBounds(bounds);
		    		})
		    	}
	
		    	w2dc_setClusters(enable_clusters, map_id, markers);
		    	
		    	if (typeof window['radius_params'] != 'undefined') {
					var radius_params = window['radius_params'];
					
					w2dc_saveGeocodedCoordinates(radius_params, map_id);
		
					if (enable_radius_circle) {
						w2dc_drawRadius(radius_params, map_id);
					}
				}
		    }
		    w2dc_setMapZoomCenter(map_id, map_attrs, markers_array);
		}
	}

	function w2dc_setMapAjaxListener(map, map_id) {
		
		google.maps.event.addListener(map, 'idle', function() {
			w2dc_setAjaxMarkers(map, map_id); // create listener
		});
	}
	function w2dc_geocodeStartAddress(map_attrs, map_id, zoom_level) {
		
		var start_address = map_attrs.start_address;
		function _geocodeStartAddress(status, start_latitude, start_longitude) {
			if (status == true) {
			    w2dc_setMapCenter(map_id, new google.maps.LatLng(start_latitude, start_longitude));
			    if (zoom_level) {
			    	w2dc_setMapZoom(map_id, zoom_level);
			    }
			    
			    if (typeof map_attrs.geolocation != 'undefined' && map_attrs.geolocation == 1) {
			    	w2dc_geolocatePosition();
				}
			    
			    if (typeof map_attrs.ajax_map_loading != 'undefined' && map_attrs.ajax_map_loading == 1) {
				    	/*delete map_attrs.swLat;
				    	delete map_attrs.swLng;
						delete map_attrs.neLat;
						delete map_attrs.neLng;
						delete map_attrs.action;*/
				    // use closures here
				    w2dc_setMapAjaxListener(w2dc_maps[map_id], map_id);
			    }
			}
		}
		w2dc_geocodeAddress(start_address, _geocodeStartAddress);
	}
	function w2dc_geolocatePosition() {
		if (navigator.geolocation) {
			
			var geolocation_maps = [];
	    	for (var map_id in w2dc_maps_attrs) {
	    		if (typeof w2dc_maps_attrs[map_id].geolocation != 'undefined' && w2dc_maps_attrs[map_id].geolocation == 1) {
	    			geolocation_maps.push({ 'map': w2dc_maps[map_id], 'map_id': map_id});
	    		}
	    	}
	    	if (geolocation_maps.length) {
	    		navigator.geolocation.getCurrentPosition(
	    			function(position) {
		    			var start_latitude = position.coords.latitude;
		    			var start_longitude = position.coords.longitude;
		    			//var start_latitude = 40.7143528;
		    			//var start_longitude = -74.0059731;
		    			
				    	for (var i in geolocation_maps) {
				    		var map_id = geolocation_maps[i].map_id;
				    		
				    		w2dc_setMapCenter(map_id, new google.maps.LatLng(start_latitude, start_longitude));

				    		if (typeof w2dc_maps_attrs[map_id].start_zoom != 'undefined' && w2dc_maps_attrs[map_id].start_zoom > 0) {
				    			w2dc_setMapZoom(map_id, w2dc_maps_attrs[map_id].start_zoom);
				    		}

				    		for (var j=0; j<w2dc_map_markers_attrs_array.length; j++) {
								if (w2dc_map_markers_attrs_array[j].map_id == map_id) {
									w2dc_map_markers_attrs_array[j].map_attrs.start_latitude = start_latitude;
									w2dc_map_markers_attrs_array[j].map_attrs.start_longitude = start_longitude;
									
									var post_params = w2dc_collectAJAXParams({ hash: map_id, from_set_ajax: 1 });
									post_params.ajax_action = 'ajax_markers';
									w2dc_startAJAXSearchOnMap(map_id, post_params);
								}
				    		}
				    	}
		    		}, 
		    		function(e) {
		    			//alert(e.message);
			    	},
			    	{timeout: 10000}
		    	);
	    	}
		}
	}
	function w2dc_project(latLng) {
		var TILE_SIZE = 256;
		var siny = Math.sin(latLng.lat() * Math.PI / 180);
		siny = Math.min(Math.max(siny, -0.9999), 0.9999);
		return new google.maps.Point(
		   TILE_SIZE * (0.5 + latLng.lng() / 360),
		   TILE_SIZE * (0.5 - Math.log((1 + siny) / (1 - siny)) / (4 * Math.PI)));
	}
	window.w2dc_setAjaxMarkers = function(map, map_id) {
		var bounds_change_max_offset = 140;
		var attrs_array = w2dc_get_map_markers_attrs_array(map_id);
		var map_attrs = attrs_array.map_attrs;
		
		/*var address_string = '';
		if (address_string = wcsearch_get_query_string_param('address')) {
			if (typeof w2dc_searchAddresses[map_id] == "undefined" || w2dc_searchAddresses[map_id] != address_string) {
				var geocoder = new google.maps.Geocoder();
				geocoder.geocode({'address': address_string}, function(results, status) {
					if (status == google.maps.GeocoderStatus.OK) {
						var latitude = results[0].geometry.location.lat();
						var longitude = results[0].geometry.location.lng();
					}
					map.panTo(new google.maps.LatLng(latitude, longitude));
				    
					w2dc_setAjaxMarkers(map, map_id);
				});
				w2dc_searchAddresses[map_id] = address_string;
				
				return false;
			}
		}*/
	
		var bounds_new = map.getBounds();
		if (bounds_new) {
			var south_west = bounds_new.getSouthWest();
			var north_east = bounds_new.getNorthEast();
		} else {
			return false;
		}
		
		wcsearch_insert_param_in_uri(
				['swLat', south_west.lat()],
				['swLng', south_west.lng()],
				['neLat', north_east.lat()],
				['neLng', north_east.lng()]
		);
	
		if (typeof map_attrs.swLat != 'undefined' && typeof map_attrs.swLng != 'undefined' && typeof map_attrs.neLat != 'undefined' && typeof map_attrs.neLng != 'undefined') {
			var bounds_old = new google.maps.LatLngBounds();
		    var sw_point = new google.maps.LatLng(map_attrs.swLat, map_attrs.swLng);
		    var ne_point = new google.maps.LatLng(map_attrs.neLat, map_attrs.neLng);
		    bounds_old.extend(sw_point);
		    bounds_old.extend(ne_point);
	
		    var scale = 1 << map.getZoom();
		    var worldCoordinate_new = w2dc_project(sw_point);
		    var worldCoordinate_old = w2dc_project(south_west);
		    if (
		    	(bounds_old.contains(south_west) && bounds_old.contains(north_east))
		    	||
			    	(bounds_change_max_offset > Math.abs(Math.floor(worldCoordinate_new.x*scale) - Math.floor(worldCoordinate_old.x*scale))
			    	&&
			    	bounds_change_max_offset > Math.abs(Math.floor(worldCoordinate_new.y*scale) - Math.floor(worldCoordinate_old.y*scale)))
		    ) {
		    	return false;
		    }
		}
		
		// save bounds
		for (var i=0; i<w2dc_map_markers_attrs_array.length; i++) {
			if (w2dc_map_markers_attrs_array[i].map_id == map_id) {
				w2dc_map_markers_attrs_array[i].map_attrs.swLat = south_west.lat();
				w2dc_map_markers_attrs_array[i].map_attrs.swLng = south_west.lng();
				w2dc_map_markers_attrs_array[i].map_attrs.neLat = north_east.lat();
				w2dc_map_markers_attrs_array[i].map_attrs.neLng = north_east.lng();
			}
		}
		
		var post_params = w2dc_collectAJAXParams({ hash: map_id, from_set_ajax: 1 });
		post_params.ajax_action = 'ajax_markers';

		// set to first page after collection
		post_params.paged = 1;
		
		post_params.swLat = south_west.lat();
		post_params.swLng = south_west.lng();
		post_params.neLat = north_east.lat();
		post_params.neLng = north_east.lng();
	
		w2dc_startAJAXSearchOnMap(map_id, post_params);
	}
	var w2dc_startAJAXSearchOnMap = function(map_id, post_params) {
		
		var attrs_array = w2dc_get_map_markers_attrs_array(map_id);
		var map_attrs = attrs_array.map_attrs;
		var enable_radius_circle = attrs_array.enable_radius_circle;
		var enable_clusters = attrs_array.enable_clusters;
		var show_summary_button = attrs_array.show_summary_button;
		var show_readmore_button = attrs_array.show_readmore_button;
		
		
		$.ajax({
			type: "POST",
			url: w2dc_js_objects.ajaxurl,
			data: post_params,
			dataType: 'json',
			success: function(response_from_the_action_function) {
				if (response_from_the_action_function) {
					var response_hash = response_from_the_action_function.hash;
					
					// check opened info window
					var opened_location_id;
					var keep_info_window_opened = false;
		    		if (typeof w2dc_infoWindows[map_id] != 'undefined') {
		    			opened_location_id = w2dc_infoWindows[map_id].location.id;
		    		}
	
					if (response_from_the_action_function.html) {
						var listings_block = $("#w2dc-controller-"+response_hash);
						listings_block.replaceWith(response_from_the_action_function.html);
						//w2dc_ajax_loader_target_hide('w2dc-controller-'+response_hash);
					}
					
					var map_listings_block = $("#w2dc-map-listings-panel-"+response_hash);
			    	if (map_listings_block.length) {
			    		map_listings_block.html(response_from_the_action_function.map_listings);
			    		
			    		if (opened_location_id) {
			    			w2dc_map_sidebar_scrollto(map_id, opened_location_id.id);
			    		}
			    	}
	
					w2dc_clearMarkers(map_id);
					w2dc_removeShapes(map_id);
					w2dc_removeCircles(map_id);
					
					if (typeof map_attrs.ajax_markers_loading != 'undefined' && map_attrs.ajax_markers_loading == 1) {
						var is_ajax_markers = true;
					} else {
						var is_ajax_markers = false;
					}
		
					var markers_array = response_from_the_action_function.map_markers;
					w2dc_global_locations_array[map_id] = [];
			    	for (var j=0; j<markers_array.length; j++) {
		    			var map_coords_1 = markers_array[j][1];
				    	var map_coords_2 = markers_array[j][2];
				    	if ($.isNumeric(map_coords_1) && $.isNumeric(map_coords_2)) {
			    			var point = new google.maps.LatLng(map_coords_1, map_coords_2);
	
			    			var location_obj = new w2dc_glocation(markers_array[j][0], point, 
			    				markers_array[j][3],
			    				markers_array[j][4],
			    				markers_array[j][6],
			    				markers_array[j][7],
			    				markers_array[j][8],
			    				markers_array[j][9],
			    				markers_array[j][10],
			    				markers_array[j][11],
			    				show_summary_button,
			    				show_readmore_button,
			    				map_id,
			    				is_ajax_markers
				    		);
				    		var marker = location_obj.w2dc_placeMarker(map_id);
	
				    		w2dc_global_locations_array[map_id].push(location_obj);
				    		
				    		// check opened info window
				    		if (opened_location_id == location_obj.id) {
				    			keep_info_window_opened = true;
				    		}
				    	}
		    		}
			    	
					if (!keep_info_window_opened) {
						w2dc_closeInfoWindow(map_id);
					}
			    	
			    	w2dc_setClusters(enable_clusters, map_id, w2dc_global_markers_array[map_id]);

			    	if (typeof response_from_the_action_function.radius_params != 'undefined') {
						var radius_params = response_from_the_action_function.radius_params;
						
						w2dc_saveGeocodedCoordinates(radius_params, map_id);

						if (enable_radius_circle) {
							
							w2dc_drawRadius(radius_params, map_id);
						}
					}
				}
			},
			complete: w2dc_completeAJAXSearchOnMap(map_id)
		});
	}
	var w2dc_completeAJAXSearchOnMap = function(map_id) {
		return function() {
			w2dc_equalColumnsHeight();
			w2dc_listings_carousel();
			w2dc_show_on_map_links();
		}
	}
	window.w2dc_drawRadius = function(radius_params, map_id) {
		var map_radius = parseFloat(radius_params.radius_value);
		
		if (radius_params.dimension == 'miles') {
			map_radius *= 1.609344;
		}
		
		var map_coords_1 = radius_params.map_coords_1;
		var map_coords_2 = radius_params.map_coords_2;

		if ($.isNumeric(map_coords_1) && $.isNumeric(map_coords_2)) {
			map_radius *= 1000; // we need radius exactly in meters
			w2dc_drawCircles[map_id] = new google.maps.Circle({
		    	center: new google.maps.LatLng(map_coords_1, map_coords_2),
		        radius: map_radius,
		        strokeColor: "#FF0000",
		        strokeOpacity: 0.25,
		        strokeWeight: 1,
		        fillColor: "#FF0000",
		        fillOpacity: 0.1,
		        map: w2dc_maps[map_id]
		    });
			google.maps.event.addListener(w2dc_drawCircles[map_id], 'mouseup', function(event) {
				w2dc_dragended = false;
			});
		}
	}
	
	var w2dc_bouncing_z_index = 0;
	var w2dc_bouncing_marker = null;
	window.w2dc_doMarkerBounce = function(element, times, distance, speed) {
		if (w2dc_bouncing_marker && !w2dc_bouncing_marker.is(':animated')) {
			w2dc_bouncing_marker.stop(true, true);
			
			for (var i = 0; i < times; i++) {
				element
				.animate({marginTop: '-='+distance},speed)
				.animate({marginTop: '+='+distance},speed);
			}
		}
		
		window.setTimeout(function() {
			w2dc_doMarkerBounce(element, times, distance, speed);
		}, 0);
	}
	
	window.w2dc_placeMarker = function(location, map_id) {
		
		var bounce_selectors = ".w2dc-show-on-map[data-location-id="+location.id+"], .w2dc-listing-has-location-"+location.id;
		
		// PNG images
		if (w2dc_maps_objects.map_markers_type != 'icons') {
			if (w2dc_maps_objects.global_map_icons_path != '') {
				var re = /(?:\.([^.]+))?$/;
				if (location.map_icon_file && typeof re.exec(w2dc_maps_objects.global_map_icons_path+'icons/'+location.map_icon_file)[1] != "undefined")
					var icon_file = w2dc_maps_objects.global_map_icons_path+'icons/'+location.map_icon_file;
				else
					var icon_file = w2dc_maps_objects.global_map_icons_path+"blank.png";
		
				var customIcon = {
					url: icon_file,
				    size: new google.maps.Size(parseInt(w2dc_maps_objects.marker_image_width), parseInt(w2dc_maps_objects.marker_image_height)),
				    origin: new google.maps.Point(0, 0),
				    anchor: new google.maps.Point(parseInt(w2dc_maps_objects.marker_image_anchor_x), parseInt(w2dc_maps_objects.marker_image_anchor_y))
				};
		
				var marker = new google.maps.Marker({
					position: location.point,
					map: w2dc_maps[map_id],
					icon: customIcon,
					animation: google.maps.Animation.DROP,
					location: location
				});
			} else {
				var marker = new google.maps.Marker({
					position: location.point,
					map: w2dc_maps[map_id],
					animation: google.maps.Animation.DROP,
					location: location
				});
			}
			
			$(document).on("mouseenter", bounce_selectors, {marker: marker}, function(event) {
				event.data.marker.setAnimation(google.maps.Animation.BOUNCE);
			});
			$(document).on("mouseleave", bounce_selectors, {marker: marker}, function(event) {
				event.data.marker.setAnimation(null);
			});
			
			w2dc_dragended = false;
		} else {
			// fa- Icons
			w2dc_load_richtext();
			
			if (location.map_icon_color)
				var map_marker_color = location.map_icon_color;
			else
				var map_marker_color = w2dc_maps_objects.default_marker_color;

			if (typeof location.map_icon_file == 'string' && location.map_icon_file.indexOf("w2dc-fa-") != -1) {
				var map_marker_icon = '<span class="w2dc-map-marker-icon w2dc-fa '+location.map_icon_file+'" style="color: '+map_marker_color+';"></span>';
				var map_marker_class = 'w2dc-map-marker';
			} else {
				if (w2dc_maps_objects.default_marker_icon) {
					var map_marker_icon = '<span class="w2dc-map-marker-icon w2dc-fa '+w2dc_maps_objects.default_marker_icon+'" style="color: '+map_marker_color+';"></span>';
					var map_marker_class = 'w2dc-map-marker';
				} else {
					var map_marker_icon = '';
					var map_marker_class = 'w2dc-map-marker-empty';
				}
			}

			var marker = new RichMarker({
				position: location.point,
				map: w2dc_maps[map_id],
				flat: true,
				location: location,
				content: '<div class="'+map_marker_class+' w2dc-map-marker-'+location.id+'" style="background: '+map_marker_color+' none repeat scroll 0 0;">'+map_marker_icon+'</div>'
			});
			
			w2dc_dragended = false;
			google.maps.event.addListener(w2dc_maps[map_id], 'dragend', function(event) {
			    w2dc_dragended = true;
			});
			google.maps.event.addListener(w2dc_maps[map_id], 'mouseup', function(event) {
				w2dc_dragended = false;
			});
			
			google.maps.event.addListener(marker, 'ready', function() {
				$(document).on("mouseenter", bounce_selectors, function(event) {
					if (!w2dc_bouncing_marker) {
						if ($('.w2dc-map-marker-'+location.id).is(':visible')) {
							w2dc_bouncing_z_index++;
							w2dc_bouncing_marker = $('.w2dc-map-marker-'+location.id).parent().parent();
							w2dc_bouncing_marker.css("z-index", w2dc_bouncing_z_index);
							w2dc_doMarkerBounce(w2dc_bouncing_marker, 10, '10px', 300);
						}
					}
				});
				$(document).on("mouseleave", bounce_selectors, function(event) {
					if (w2dc_bouncing_marker) {
						w2dc_bouncing_marker.finish();
						w2dc_bouncing_marker = null;
					}
				});
			});
		}
		
		w2dc_global_markers_array[map_id].push(marker);

		google.maps.event.addListener(marker, 'click', function() {
			if (!w2dc_dragended) {
				var attrs_array = w2dc_get_map_markers_attrs_array(map_id);
				if (attrs_array.center_map_onclick) {
					var map_attrs = attrs_array.map_attrs;
					if (typeof map_attrs.ajax_map_loading == 'undefined' || map_attrs.ajax_map_loading == 0) {
						w2dc_maps[map_id].panTo(marker.getPosition());
					}
				}
					
				w2dc_map_sidebar_scrollto(map_id, location.id);

				if (!location.is_ajax_markers) {
					w2dc_showInfoWindow(location, marker, map_id);
				} else {
					// show empty infoWindow
					w2dc_showInfoWindow(location, marker, map_id);
		
					var post_data = {
							'locations_ids': [location.id],
							'action': 'w2dc_get_map_marker_info',
							'map_id': map_id,
							'show_summary_button': location.show_summary_button,
							'show_readmore_button': location.show_readmore_button
					};
					$.ajax({
			    		type: "POST",
			    		url: w2dc_js_objects.ajaxurl,
			    		data: eval(post_data),
			    		dataType: 'json',
			    		success: function(response_from_the_action_function) {
				    		var marker_array = response_from_the_action_function[0];
				    		var map_coords_1 = marker_array[1];
						    var map_coords_2 = marker_array[2];
						    if ($.isNumeric(map_coords_1) && $.isNumeric(map_coords_2)) {
					    		var point = new google.maps.LatLng(map_coords_1, map_coords_2);

				    			var new_location_obj = new w2dc_glocation(marker_array[0], point, 
				    				marker_array[3],
				    				marker_array[4],
				    				marker_array[6],
				    				marker_array[7],
				    				marker_array[8],
				    				marker_array[9],
				    				marker_array[10],
				    				marker_array[11],
				    				location.show_summary_button,
				    				location.show_readmore_button,
				    				map_id,
				    				true
					    		);
					    	}
			    			
			    			w2dc_showInfoWindow(new_location_obj, marker, map_id);
			    		},
			    		complete: function() {
							//w2dc_ajax_loader_target_hide("w2dc-map-canvas-"+map_id);
						}
					});
				}
			}
		});
	
		return marker;
	}
	// This function builds info Window and shows it hiding another
	function w2dc_showInfoWindow(locations, marker, map_id) {
		
		var map_attrs = w2dc_get_map_markers_attrs_array(map_id);
		
		if (typeof map_attrs.enable_infowindow == 'undefined' || !map_attrs.enable_infowindow) {
			return;
		}
		
		// infobox_packed.js -------------------------------------------------------------------------------------------------------------------------------------------
		function InfoBox(t){t=t||{},google.maps.OverlayView.apply(this,arguments),this.content_=t.content||"",this.disableAutoPan_=t.disableAutoPan||!1,this.maxWidth_=t.maxWidth||0,this.pixelOffset_=t.pixelOffset||new google.maps.Size(0,0),this.position_=t.position||new google.maps.LatLng(0,0),this.zIndex_=t.zIndex||null,this.boxClass_=t.boxClass||"infoBox",this.boxStyle_=t.boxStyle||{},this.closeBoxMargin_=t.closeBoxMargin||"2px",this.closeBoxURL_=t.closeBoxURL||"http://www.google.com/intl/en_us/mapfiles/close.gif",""===t.closeBoxURL&&(this.closeBoxURL_=""),this.infoBoxClearance_=t.infoBoxClearance||new google.maps.Size(1,1),"undefined"==typeof t.visible&&(t.visible="undefined"==typeof t.isHidden?!0:!t.isHidden),this.isHidden_=!t.visible,this.alignBottom_=t.alignBottom||!1,this.pane_=t.pane||"floatPane",this.enableEventPropagation_=t.enableEventPropagation||!1,this.div_=null,this.closeListener_=null,this.moveListener_=null,this.contextListener_=null,this.eventListeners_=null,this.fixedWidthSet_=null}InfoBox.prototype=new google.maps.OverlayView,InfoBox.prototype.createInfoBoxDiv_=function(){var t,e,i,o=this,s=function(t){t.cancelBubble=!0,t.stopPropagation&&t.stopPropagation()},n=function(t){t.returnValue=!1,t.preventDefault&&t.preventDefault(),o.enableEventPropagation_||s(t)};if(!this.div_){if(this.div_=document.createElement("div"),this.setBoxStyle_(),"undefined"==typeof this.content_.nodeType?this.div_.innerHTML=this.getCloseBoxImg_()+this.content_:(this.div_.innerHTML=this.getCloseBoxImg_(),this.div_.appendChild(this.content_)),this.getPanes()[this.pane_].appendChild(this.div_),this.addClickHandler_(),this.div_.style.width?this.fixedWidthSet_=!0:0!==this.maxWidth_&&this.div_.offsetWidth>this.maxWidth_?(this.div_.style.width=this.maxWidth_,this.div_.style.overflow="auto",this.fixedWidthSet_=!0):(i=this.getBoxWidths_(),this.div_.style.width=this.div_.offsetWidth-i.left-i.right+"px",this.fixedWidthSet_=!1),this.panBox_(this.disableAutoPan_),!this.enableEventPropagation_){for(this.eventListeners_=[],e=["mousedown","mouseover","mouseout","mouseup","click","dblclick","touchstart","touchend","touchmove"],t=0;t<e.length;t++)this.eventListeners_.push(this.div_.addEventListener(e[t],s));this.eventListeners_.push(this.div_.addEventListener("mouseover",function(){this.style.cursor="default"}))}this.contextListener_=this.div_.addEventListener("contextmenu",n),google.maps.event.trigger(this,"domready")}},InfoBox.prototype.getCloseBoxImg_=function(){var t="";return""!==this.closeBoxURL_&&(t="<img",t+=" src='"+this.closeBoxURL_+"'",t+=" align=right",t+=" style='",t+=" position: relative;",t+=" cursor: pointer;",t+=" margin: "+this.closeBoxMargin_+";",t+="'>"),t},InfoBox.prototype.addClickHandler_=function(){var t;""!==this.closeBoxURL_?(t=this.div_.firstChild,this.closeListener_=t.addEventListener("click",this.getCloseClickHandler_())):this.closeListener_=null},InfoBox.prototype.getCloseClickHandler_=function(){var t=this;return function(e){e.cancelBubble=!0,e.stopPropagation&&e.stopPropagation(),google.maps.event.trigger(t,"closeclick"),t.close()}},InfoBox.prototype.panBox_=function(t){var e,i,o=0,s=0;if(!t&&(e=this.getMap(),e instanceof google.maps.Map)){e.getBounds().contains(this.position_)||e.setCenter(this.position_),i=e.getBounds();var n=e.getDiv(),h=n.offsetWidth,d=n.offsetHeight,l=this.pixelOffset_.width,r=this.pixelOffset_.height,a=this.div_.offsetWidth,p=this.div_.offsetHeight,_=this.infoBoxClearance_.width,f=this.infoBoxClearance_.height,v=this.getProjection().fromLatLngToContainerPixel(this.position_);if(v.x<-l+_?o=v.x+l-_:v.x+a+l+_>h&&(o=v.x+a+l+_-h),this.alignBottom_?v.y<-r+f+p?s=v.y+r-f-p:v.y+r+f>d&&(s=v.y+r+f-d):v.y<-r+f?s=v.y+r-f:v.y+p+r+f>d&&(s=v.y+p+r+f-d),0!==o||0!==s){{e.getCenter()}e.panBy(o,s)}}},InfoBox.prototype.setBoxStyle_=function(){var t,e;if(this.div_){this.div_.className=this.boxClass_,this.div_.style.cssText="",e=this.boxStyle_;for(t in e)e.hasOwnProperty(t)&&(this.div_.style[t]=e[t]);this.div_.style.WebkitTransform="translateZ(0)","undefined"!=typeof this.div_.style.opacity&&""!==this.div_.style.opacity&&(this.div_.style.MsFilter='"progid:DXImageTransform.Microsoft.Alpha(Opacity='+100*this.div_.style.opacity+')"',this.div_.style.filter="alpha(opacity="+100*this.div_.style.opacity+")"),this.div_.style.position="absolute",this.div_.style.visibility="hidden",null!==this.zIndex_&&(this.div_.style.zIndex=this.zIndex_)}},InfoBox.prototype.getBoxWidths_=function(){var t,e={top:0,bottom:0,left:0,right:0},i=this.div_;return document.defaultView&&document.defaultView.getComputedStyle?(t=i.ownerDocument.defaultView.getComputedStyle(i,""),t&&(e.top=parseInt(t.borderTopWidth,10)||0,e.bottom=parseInt(t.borderBottomWidth,10)||0,e.left=parseInt(t.borderLeftWidth,10)||0,e.right=parseInt(t.borderRightWidth,10)||0)):document.documentElement.currentStyle&&i.currentStyle&&(e.top=parseInt(i.currentStyle.borderTopWidth,10)||0,e.bottom=parseInt(i.currentStyle.borderBottomWidth,10)||0,e.left=parseInt(i.currentStyle.borderLeftWidth,10)||0,e.right=parseInt(i.currentStyle.borderRightWidth,10)||0),e},InfoBox.prototype.onRemove=function(){this.div_&&(this.div_.parentNode.removeChild(this.div_),this.div_=null)},InfoBox.prototype.draw=function(){this.createInfoBoxDiv_();var t=this.getProjection().fromLatLngToDivPixel(this.position_);this.div_.style.left=t.x+this.pixelOffset_.width+"px",this.alignBottom_?this.div_.style.bottom=-(t.y+this.pixelOffset_.height)+"px":this.div_.style.top=t.y+this.pixelOffset_.height+"px",this.div_.style.visibility=this.isHidden_?"hidden":"visible"},InfoBox.prototype.setOptions=function(t){"undefined"!=typeof t.boxClass&&(this.boxClass_=t.boxClass,this.setBoxStyle_()),"undefined"!=typeof t.boxStyle&&(this.boxStyle_=t.boxStyle,this.setBoxStyle_()),"undefined"!=typeof t.content&&this.setContent(t.content),"undefined"!=typeof t.disableAutoPan&&(this.disableAutoPan_=t.disableAutoPan),"undefined"!=typeof t.maxWidth&&(this.maxWidth_=t.maxWidth),"undefined"!=typeof t.pixelOffset&&(this.pixelOffset_=t.pixelOffset),"undefined"!=typeof t.alignBottom&&(this.alignBottom_=t.alignBottom),"undefined"!=typeof t.position&&this.setPosition(t.position),"undefined"!=typeof t.zIndex&&this.setZIndex(t.zIndex),"undefined"!=typeof t.closeBoxMargin&&(this.closeBoxMargin_=t.closeBoxMargin),"undefined"!=typeof t.closeBoxURL&&(this.closeBoxURL_=t.closeBoxURL),"undefined"!=typeof t.infoBoxClearance&&(this.infoBoxClearance_=t.infoBoxClearance),"undefined"!=typeof t.isHidden&&(this.isHidden_=t.isHidden),"undefined"!=typeof t.visible&&(this.isHidden_=!t.visible),"undefined"!=typeof t.enableEventPropagation&&(this.enableEventPropagation_=t.enableEventPropagation),this.div_&&this.draw()},InfoBox.prototype.setContent=function(t){this.content_=t,this.div_&&(this.closeListener_&&(google.maps.event.removeListener(this.closeListener_),this.closeListener_=null),this.fixedWidthSet_||(this.div_.style.width=""),"undefined"==typeof t.nodeType?this.div_.innerHTML=this.getCloseBoxImg_()+t:(this.div_.innerHTML=this.getCloseBoxImg_(),this.div_.appendChild(t)),this.fixedWidthSet_||(this.div_.style.width=this.div_.offsetWidth+"px","undefined"==typeof t.nodeType?this.div_.innerHTML=this.getCloseBoxImg_()+t:(this.div_.innerHTML=this.getCloseBoxImg_(),this.div_.appendChild(t))),this.addClickHandler_()),google.maps.event.trigger(this,"content_changed")},InfoBox.prototype.setPosition=function(t){this.position_=t,this.div_&&this.draw(),google.maps.event.trigger(this,"position_changed")},InfoBox.prototype.setZIndex=function(t){this.zIndex_=t,this.div_&&(this.div_.style.zIndex=t),google.maps.event.trigger(this,"zindex_changed")},InfoBox.prototype.setVisible=function(t){this.isHidden_=!t,this.div_&&(this.div_.style.visibility=this.isHidden_?"hidden":"visible")},InfoBox.prototype.getContent=function(){return this.content_},InfoBox.prototype.getPosition=function(){return this.position_},InfoBox.prototype.getZIndex=function(){return this.zIndex_},InfoBox.prototype.getVisible=function(){var t;return t="undefined"==typeof this.getMap()||null===this.getMap()?!1:!this.isHidden_},InfoBox.prototype.show=function(){this.isHidden_=!1,this.div_&&(this.div_.style.visibility="visible")},InfoBox.prototype.hide=function(){this.isHidden_=!0,this.div_&&(this.div_.style.visibility="hidden")},InfoBox.prototype.open=function(t,e){var i=this;e&&(this.position_=e.getPosition(),this.moveListener_=google.maps.event.addListener(e,"position_changed",function(){i.setPosition(this.getPosition())})),this.setMap(t),this.div_&&this.panBox_()},InfoBox.prototype.close=function(){var t;if(this.closeListener_&&(google.maps.event.removeListener(this.closeListener_),this.closeListener_=null),this.eventListeners_){for(t=0;t<this.eventListeners_.length;t++)google.maps.event.removeListener(this.eventListeners_[t]);this.eventListeners_=null}this.moveListener_&&(google.maps.event.removeListener(this.moveListener_),this.moveListener_=null),this.contextListener_&&(google.maps.event.removeListener(this.contextListener_),this.contextListener_=null),this.setMap(null)};
		
		var infowindow_width;
		var map_width = $('#w2dc-map-canvas-'+map_id).width();
		if (map_width < w2dc_maps_objects.infowindow_width) {
			infowindow_width = map_width;
		} else {
			infowindow_width = w2dc_maps_objects.infowindow_width;
		}
		
		if (Array.isArray(locations)) {
			var windowHtml = locations[0].content_fields;
			
			var _windowHtml = $(windowHtml);
			
			_windowHtml.find(".w2dc-map-info-window-inner").addClass("w2dc-map-info-window-inner-limit-height");
			
			for (var i=1; i < locations.length; i++) {
				var windowInnerHtml = locations[i].content_fields;
				
				windowInnerHtml = $(windowInnerHtml)[0].outerHTML;
				
				var inner = $(windowInnerHtml).find(".w2dc-map-info-window-inner-item");
				
				_windowHtml.find(".w2dc-map-info-window-inner-item").last().after(inner);
				
				// remove summary button when no listing excerpt veisible
				var listing_id = _windowHtml.find(".w2dc-info-window-summary-button").data("listing-id");
				if (!$("#post-"+listing_id).length) {
					var summary_btn = _windowHtml.find(".w2dc-info-window-summary-button");
					
					summary_btn.parent()
					.removeClass("w2dc-map-info-window-buttons")
					.addClass("w2dc-map-info-window-buttons-single");
					
					summary_btn.remove();
				}
				windowHtml = _windowHtml[0].outerHTML;
				
				$(document).on("mouseenter", ".w2dc-map-info-window", {map_id: map_id}, function(event) {
			    	var options = {
							scrollwheel: false
					};
					w2dc_maps[map_id].setOptions(options);
				});
				$(document).on("mouseleave", ".w2dc-map-info-window", {map_id: map_id}, function(event) {
					w2dc_checkWheelZoom(map_id);
				});
			}
		} else {
			var windowHtml = locations.content_fields;
			
			windowHtml = $(windowHtml)[0].outerHTML;
		}
		
		var tongue_pos = (parseInt(w2dc_maps_objects.infowindow_width)/2);
	            
	    var myOptions = {
	             content: windowHtml
	            ,alignBottom: true
	            ,disableAutoPan: false
	            ,pixelOffset: new google.maps.Size(-tongue_pos, parseInt(w2dc_maps_objects.infowindow_offset)-24)
	            ,zIndex: null
	            ,boxStyle: { 
	              width: infowindow_width+"px"
	             }
	    		,closeBoxURL: ""
	            ,infoBoxClearance: new google.maps.Size(1, 1)
	            ,isHidden: false
	            ,pane: "floatPane"
	            ,enableEventPropagation: true // required to scroll infowindow without map zoom
	    };
	
		w2dc_closeInfoWindow(map_id);
		
		if (typeof map_attrs.close_infowindow_out_click != 'undefined' && map_attrs.close_infowindow_out_click) {
			
			var dragended = false;
			google.maps.event.addListener(w2dc_maps[map_id], 'dragend', function(event) {
				dragended = true;
			});
			
			var map_iframe = $(w2dc_maps[map_id].getDiv()).find("iframe");
			var map_click_handle = function(e) {
				/*console.log($(e.target).parents(".gm-style"));
				console.log($(e.target).is('[class^="w2dc-"]'));*/
				if (!dragended && $(e.target).parents(".gm-style").length && !$(e.target).parents('.w2dc-map-info-window').length) {
					w2dc_closeInfoWindow(map_id);
					$(this).off("mouseup", map_click_handle);
					
				}
				
				dragended = false;
			};
			$("body").on("mouseup", map_iframe, map_click_handle);
		}
	
	    w2dc_infoWindows[map_id] = new InfoBox(myOptions);
	    w2dc_infoWindows[map_id].open(w2dc_maps[map_id], marker);
	    w2dc_infoWindows[map_id].marker = marker;
	    w2dc_infoWindows[map_id].location = locations;
	}

	window.w2dc_scrollToListing = function(anchor, map_id) {
		var scroll_to_anchor = $("#"+anchor);
		var sticky_scroll_toppadding = 0;
		if (typeof window["w2dc_sticky_scroll_toppadding_"+map_id] != 'undefined') {
			sticky_scroll_toppadding = window["w2dc_sticky_scroll_toppadding_"+map_id];
		}

		if (scroll_to_anchor.length) {
			$('html,body').animate({scrollTop: scroll_to_anchor.position().top - sticky_scroll_toppadding}, 'fast');
		}
	}

	function w2dc_handleDirectionsErrors(status){
	   if (status == google.maps.DirectionsStatus.NOT_FOUND)
	     alert("No corresponding geographic location could be found for one of the specified addresses. This may be due to the fact that the address is relatively new, or it may be incorrect.");
	   else if (status == google.maps.DirectionsStatus.ZERO_RESULTS)
	     alert("No route could be found between the origin and destination.");
	   else if (status == google.maps.DirectionsStatus.UNKNOWN_ERROR)
	     alert("A directions request could not be processed due to a server error. The request may succeed if you try again.");
	   else if (status == google.maps.DirectionsStatus.REQUEST_DENIED)
	     alert("The webpage is not allowed to use the directions service.");
	   else if (status == google.maps.DirectionsStatus.INVALID_REQUEST)
	     alert("The provided DirectionsRequest was invalid.");
	   else if (status == google.maps.DirectionsStatus.OVER_QUERY_LIMIT)
	     alert("The webpage has sent too many requests within the allowed time period.");
	   else alert("An unknown error occurred.");
	}
	window.w2dc_setClusters = function(enable_clusters, map_id, markers) {
		
		if (enable_clusters && typeof MarkerClusterer == 'function') {
			var clusterStyles = [];
			
			if (w2dc_maps_objects.global_map_icons_path != '') {
				var clusterStyles = [
					{
						url: w2dc_maps_objects.global_map_icons_path + 'clusters/icon_cluster1.png',
						height: 64,
						width: 64
					},
					{
						url: w2dc_maps_objects.global_map_icons_path + 'clusters/icon_cluster2.png',
						height: 74,
						width: 74
					},
					{
						url: w2dc_maps_objects.global_map_icons_path + 'clusters/icon_cluster3.png',
						height: 84,
						width: 84
					},
					{
						url: w2dc_maps_objects.global_map_icons_path + 'clusters/icon_cluster4.png',
						height: 94,
						width: 94
					},
					{
						url: w2dc_maps_objects.global_map_icons_path + 'clusters/icon_cluster5.png',
						height: 104,
						width: 104
					}
				];
			}
			var mcOptions = {
					zoomOnClick: false,
					gridSize: 40,
					styles: clusterStyles
			};
			
			var markerCluster = new MarkerClusterer(w2dc_maps[map_id], markers, mcOptions);
			 
			w2dc_markerClusters[map_id] = markerCluster;
			
			google.maps.event.addListener(markerCluster, 'clusterclick', function(cluster) {
				
				var map = w2dc_maps[map_id];
				
				var markers = cluster.getMarkers();
				
				var is_equalCoordinates = true;
				if (markers.length != 0) {
					for (var i=0; i < markers.length; i++) {
						var existingMarker = markers[i];
						var pos = existingMarker.getPosition();
						
						for (var j=0; j < markers.length; j++) {
							var markerToCompare = markers[j];
							var markerToComparePos = markerToCompare.getPosition();

							if (!markerToComparePos.equals(pos)) {
								is_equalCoordinates = false;
							}
						}
					}
				}
				
				if (!is_equalCoordinates) {
					map.fitBounds(cluster.getBounds());
				} else {
					
					var locations = [];
					for (var i=0; i < markers.length; i++) {
						locations.push(markers[i].location);
					}
					
					if (!locations[0].is_ajax_markers) {
						w2dc_showInfoWindow(locations, markers[0], map_id);
					} else {
						// show empty infoWindow
						w2dc_showInfoWindow(locations, markers[0], map_id);
						
						var post_data = {
								'locations_ids': locations.map(function(location) { return location.id }),
								'action': 'w2dc_get_map_marker_info',
								'map_id': map_id,
								'show_summary_button': locations[0].show_summary_button,
								'show_readmore_button': locations[0].show_readmore_button
						};
						$.ajax({
				    		type: "POST",
				    		url: w2dc_js_objects.ajaxurl,
				    		data: eval(post_data),
				    		dataType: 'json',
				    		success: function(response_from_the_action_function) {
				    			
				    			var new_location_objs = [];
				    			
				    			for (var i in response_from_the_action_function) {
				    			
					    			var marker_array = response_from_the_action_function[i];
					    			var map_coords_1 = marker_array[1];
							    	var map_coords_2 = marker_array[2];
							    	if ($.isNumeric(map_coords_1) && $.isNumeric(map_coords_2)) {
						    			var point = new google.maps.LatLng(map_coords_1, map_coords_2);
				
						    			new_location_objs.push(new w2dc_glocation(marker_array[0], point, 
						    				marker_array[3],
						    				marker_array[4],
						    				marker_array[6],
						    				marker_array[7],
						    				marker_array[8],
						    				marker_array[9],
						    				marker_array[10],
						    				marker_array[11],
						    				locations[0].show_summary_button,
						    				locations[0].show_readmore_button,
						    				map_id,
						    				true
							    		));
							    	}
				    			}
				    			
				    			w2dc_showInfoWindow(new_location_objs, markers[0], map_id);
				    		},
				    		complete: function() {
				    			
							}
						});
					}
				}
			});
		}
	}
	window.w2dc_clearMarkers = function(map_id) {
		if (typeof w2dc_markerClusters[map_id] != 'undefined')
			w2dc_markerClusters[map_id].clearMarkers();
	
		if (w2dc_global_markers_array[map_id]) {
			for(var i = 0; i<w2dc_global_markers_array[map_id].length; i++){
				w2dc_global_markers_array[map_id][i].setMap(null);
			}
		}
		w2dc_global_markers_array[map_id] = [];
		w2dc_global_locations_array[map_id] = [];
	}
	window.w2dc_removeCircles = function(map_id) {
		if (typeof w2dc_drawCircles[map_id] != 'undefined') {
			google.maps.event.clearListeners(w2dc_drawCircles[map_id], 'mouseup');
			w2dc_drawCircles[map_id].setMap(null);
		}
	}
	window.w2dc_removeShapes = function(map_id) {
		if (typeof w2dc_polygons[map_id] != 'undefined') {
			w2dc_polygons[map_id].setMap(null);
		}
	}
	window.w2dc_reloadMap = function(map_id) {
		if (typeof google != 'undefined' && typeof google.maps != 'undefined') {
    		var bounds = new google.maps.LatLngBounds();
    		for (var j=0; j<w2dc_global_markers_array[map_id].length; j++) {
    			var marker = w2dc_global_markers_array[map_id][j];
			    w2dc_extendBounds(bounds, w2dc_getMarkerPosition(marker));
    		}
    		w2dc_mapFitBounds(map_id, bounds);
    		
    		var map_attrs_array;
    		if (map_attrs_array = w2dc_get_map_markers_attrs_array(map_id)) {
    			var map_attrs = map_attrs_array.map_attrs;
    			var markers_array = map_attrs_array.markers_array;
    			
    			w2dc_setMapZoomCenter(map_id, map_attrs, markers_array);
    		}
		}
	}

	window.w2dc_geocodeField = function(field, error_message) {
		if (navigator.geolocation) {
			navigator.geolocation.getCurrentPosition(
				function(position) {
					var latlng = new google.maps.LatLng(position.coords.latitude, position.coords.longitude);
					var geocoder = new google.maps.Geocoder();
					geocoder.geocode({'latLng': latlng}, function(results, status) {
						if (status == google.maps.GeocoderStatus.OK) {
							if (results[0]) {
								field.val(results[0].formatted_address);
								field.trigger('change');
							}
						}
					});
			    },
			    function(e) {
			    	//alert(e.message);
		    	},
			    {enableHighAccuracy: true, timeout: 10000, maximumAge: 0}
		    );
		} else
			alert(error_message);
	}
})(jQuery);


//google_maps_clasterer.js -------------------------------------------------------------------------------------------------------------------------------------------
(function(){var d=null;function e(a){return function(b){this[a]=b}}function h(a){return function(){return this[a]}}var j;
function k(a,b,c){this.extend(k,google.maps.OverlayView);this.c=a;this.a=[];this.f=[];this.ca=[53,56,66,78,90];this.j=[];this.A=!1;c=c||{};this.g=c.gridSize||60;this.l=c.minimumClusterSize||2;this.J=c.maxZoom||d;this.j=c.styles||[];this.X=c.imagePath||this.Q;this.W=c.imageExtension||this.P;this.O=!0;if(c.zoomOnClick!=void 0)this.O=c.zoomOnClick;this.r=!1;if(c.averageCenter!=void 0)this.r=c.averageCenter;l(this);this.setMap(a);this.K=this.c.getZoom();var f=this;google.maps.event.addListener(this.c,
"zoom_changed",function(){var a=f.c.getZoom();if(f.K!=a)f.K=a,f.m()});google.maps.event.addListener(this.c,"idle",function(){f.i()});b&&b.length&&this.C(b,!1)}j=k.prototype;j.Q="http://google-maps-utility-library-v3.googlecode.com/svn/trunk/markerclusterer/images/m";j.P="png";j.extend=function(a,b){return function(a){for(var b in a.prototype)this.prototype[b]=a.prototype[b];return this}.apply(a,[b])};j.onAdd=function(){if(!this.A)this.A=!0,n(this)};j.draw=function(){};
function l(a){if(!a.j.length)for(var b=0,c;c=a.ca[b];b++)a.j.push({url:a.X+(b+1)+"."+a.W,height:c,width:c})}j.S=function(){for(var a=this.o(),b=new google.maps.LatLngBounds,c=0,f;f=a[c];c++)b.extend(f.getPosition());this.c.fitBounds(b)};j.z=h("j");j.o=h("a");j.V=function(){return this.a.length};j.ba=e("J");j.I=h("J");j.G=function(a,b){for(var c=0,f=a.length,g=f;g!==0;)g=parseInt(g/10,10),c++;c=Math.min(c,b);return{text:f,index:c}};j.$=e("G");j.H=h("G");
j.C=function(a,b){for(var c=0,f;f=a[c];c++)q(this,f);b||this.i()};function q(a,b){b.s=!1;b.draggable&&google.maps.event.addListener(b,"dragend",function(){b.s=!1;a.L()});a.a.push(b)}j.q=function(a,b){q(this,a);b||this.i()};function r(a,b){var c=-1;if(a.a.indexOf)c=a.a.indexOf(b);else for(var f=0,g;g=a.a[f];f++)if(g==b){c=f;break}if(c==-1)return!1;b.setMap(d);a.a.splice(c,1);return!0}j.Y=function(a,b){var c=r(this,a);return!b&&c?(this.m(),this.i(),!0):!1};
j.Z=function(a,b){for(var c=!1,f=0,g;g=a[f];f++)g=r(this,g),c=c||g;if(!b&&c)return this.m(),this.i(),!0};j.U=function(){return this.f.length};j.getMap=h("c");j.setMap=e("c");j.w=h("g");j.aa=e("g");
j.v=function(a){var b=this.getProjection(),c=new google.maps.LatLng(a.getNorthEast().lat(),a.getNorthEast().lng()),f=new google.maps.LatLng(a.getSouthWest().lat(),a.getSouthWest().lng()),c=b.fromLatLngToDivPixel(c);c.x+=this.g;c.y-=this.g;f=b.fromLatLngToDivPixel(f);f.x-=this.g;f.y+=this.g;c=b.fromDivPixelToLatLng(c);b=b.fromDivPixelToLatLng(f);a.extend(c);a.extend(b);return a};j.R=function(){this.m(!0);this.a=[]};
j.m=function(a){for(var b=0,c;c=this.f[b];b++)c.remove();for(b=0;c=this.a[b];b++)c.s=!1,a&&c.setMap(d);this.f=[]};j.L=function(){var a=this.f.slice();this.f.length=0;this.m();this.i();window.setTimeout(function(){for(var b=0,c;c=a[b];b++)c.remove()},0)};j.i=function(){n(this)};
function n(a){if(a.A)for(var b=a.v(new google.maps.LatLngBounds(a.c.getBounds().getSouthWest(),a.c.getBounds().getNorthEast())),c=0,f;f=a.a[c];c++)if(!f.s&&b.contains(f.getPosition())){for(var g=a,u=4E4,o=d,v=0,m=void 0;m=g.f[v];v++){var i=m.getCenter();if(i){var p=f.getPosition();if(!i||!p)i=0;else var w=(p.lat()-i.lat())*Math.PI/180,x=(p.lng()-i.lng())*Math.PI/180,i=Math.sin(w/2)*Math.sin(w/2)+Math.cos(i.lat()*Math.PI/180)*Math.cos(p.lat()*Math.PI/180)*Math.sin(x/2)*Math.sin(x/2),i=6371*2*Math.atan2(Math.sqrt(i),
Math.sqrt(1-i));i<u&&(u=i,o=m)}}o&&o.F.contains(f.getPosition())?o.q(f):(m=new s(g),m.q(f),g.f.push(m))}}function s(a){this.k=a;this.c=a.getMap();this.g=a.w();this.l=a.l;this.r=a.r;this.d=d;this.a=[];this.F=d;this.n=new t(this,a.z(),a.w())}j=s.prototype;
j.q=function(a){var b;a:if(this.a.indexOf)b=this.a.indexOf(a)!=-1;else{b=0;for(var c;c=this.a[b];b++)if(c==a){b=!0;break a}b=!1}if(b)return!1;if(this.d){if(this.r)c=this.a.length+1,b=(this.d.lat()*(c-1)+a.getPosition().lat())/c,c=(this.d.lng()*(c-1)+a.getPosition().lng())/c,this.d=new google.maps.LatLng(b,c),y(this)}else this.d=a.getPosition(),y(this);a.s=!0;this.a.push(a);b=this.a.length;b<this.l&&a.getMap()!=this.c&&a.setMap(this.c);if(b==this.l)for(c=0;c<b;c++)this.a[c].setMap(d);b>=this.l&&a.setMap(d);
a=this.c.getZoom();if((b=this.k.I())&&a>b)for(a=0;b=this.a[a];a++)b.setMap(this.c);else if(this.a.length<this.l)z(this.n);else{b=this.k.H()(this.a,this.k.z().length);this.n.setCenter(this.d);a=this.n;a.B=b;a.ga=b.text;a.ea=b.index;if(a.b)a.b.innerHTML=b.text;b=Math.max(0,a.B.index-1);b=Math.min(a.j.length-1,b);b=a.j[b];a.da=b.url;a.h=b.height;a.p=b.width;a.M=b.textColor;a.e=b.anchor;a.N=b.textSize;a.D=b.backgroundPosition;this.n.show()}return!0};
j.getBounds=function(){for(var a=new google.maps.LatLngBounds(this.d,this.d),b=this.o(),c=0,f;f=b[c];c++)a.extend(f.getPosition());return a};j.remove=function(){this.n.remove();this.a.length=0;delete this.a};j.T=function(){return this.a.length};j.o=h("a");j.getCenter=h("d");function y(a){a.F=a.k.v(new google.maps.LatLngBounds(a.d,a.d))}j.getMap=h("c");
function t(a,b,c){a.k.extend(t,google.maps.OverlayView);this.j=b;this.fa=c||0;this.u=a;this.d=d;this.c=a.getMap();this.B=this.b=d;this.t=!1;this.setMap(this.c)}j=t.prototype;
j.onAdd=function(){this.b=document.createElement("DIV");if(this.t)this.b.style.cssText=A(this,B(this,this.d)),this.b.innerHTML=this.B.text;this.getPanes().overlayMouseTarget.appendChild(this.b);var a=this;this.b.addEventListener("click",function(){var b=a.u.k;google.maps.event.trigger(b,"clusterclick",a.u);b.O&&a.c.fitBounds(a.u.getBounds())})};function B(a,b){var c=a.getProjection().fromLatLngToDivPixel(b);c.x-=parseInt(a.p/2,10);c.y-=parseInt(a.h/2,10);return c}
j.draw=function(){if(this.t){var a=B(this,this.d);this.b.style.top=a.y+"px";this.b.style.left=a.x+"px"}};function z(a){if(a.b)a.b.style.display="none";a.t=!1}j.show=function(){if(this.b)this.b.style.cssText=A(this,B(this,this.d)),this.b.style.display="";this.t=!0};j.remove=function(){this.setMap(d)};j.onRemove=function(){if(this.b&&this.b.parentNode)z(this),this.b.parentNode.removeChild(this.b),this.b=d};j.setCenter=e("d");
function A(a,b){var c=[];c.push("background-image:url('"+a.da+"');");c.push("background-position:"+(a.D?a.D:"0 0")+";");typeof a.e==="object"?(typeof a.e[0]==="number"&&a.e[0]>0&&a.e[0]<a.h?c.push("height:"+(a.h-a.e[0])+"px; padding-top:"+a.e[0]+"px;"):c.push("height:"+a.h+"px; line-height:"+a.h+"px;"),typeof a.e[1]==="number"&&a.e[1]>0&&a.e[1]<a.p?c.push("width:"+(a.p-a.e[1])+"px; padding-left:"+a.e[1]+"px;"):c.push("width:"+a.p+"px; text-align:center;")):c.push("height:"+a.h+"px; line-height:"+a.h+
"px; width:"+a.p+"px; text-align:center;");c.push("cursor:pointer; top:"+b.y+"px; left:"+b.x+"px; color:"+(a.M?a.M:"black")+"; position:absolute; font-size:"+(a.N?a.N:11)+"px; font-family:Arial,sans-serif; font-weight:bold");return c.join("")}window.MarkerClusterer=k;k.prototype.addMarker=k.prototype.q;k.prototype.addMarkers=k.prototype.C;k.prototype.clearMarkers=k.prototype.R;k.prototype.fitMapToMarkers=k.prototype.S;k.prototype.getCalculator=k.prototype.H;k.prototype.getGridSize=k.prototype.w;
k.prototype.getExtendedBounds=k.prototype.v;k.prototype.getMap=k.prototype.getMap;k.prototype.getMarkers=k.prototype.o;k.prototype.getMaxZoom=k.prototype.I;k.prototype.getStyles=k.prototype.z;k.prototype.getTotalClusters=k.prototype.U;k.prototype.getTotalMarkers=k.prototype.V;k.prototype.redraw=k.prototype.i;k.prototype.removeMarker=k.prototype.Y;k.prototype.removeMarkers=k.prototype.Z;k.prototype.resetViewport=k.prototype.m;k.prototype.repaint=k.prototype.L;k.prototype.setCalculator=k.prototype.$;
k.prototype.setGridSize=k.prototype.aa;k.prototype.setMaxZoom=k.prototype.ba;k.prototype.onAdd=k.prototype.onAdd;k.prototype.draw=k.prototype.draw;s.prototype.getCenter=s.prototype.getCenter;s.prototype.getSize=s.prototype.T;s.prototype.getMarkers=s.prototype.o;t.prototype.onAdd=t.prototype.onAdd;t.prototype.draw=t.prototype.draw;t.prototype.onRemove=t.prototype.onRemove;
})();

//richmarker-compiled.js -------------------------------------------------------------------------------------------------------------------------------------------
function w2dc_load_richtext() {
(function(){var b=true,f=false;function g(a){var c=a||{};this.d=this.c=f;if(a.visible==undefined)a.visible=b;if(a.shadow==undefined)a.shadow="7px -3px 5px rgba(88,88,88,0.7)";if(a.anchor==undefined)a.anchor=i.BOTTOM;this.setValues(c)}g.prototype=new google.maps.OverlayView;window.RichMarker=g;g.prototype.getVisible=function(){return this.get("visible")};g.prototype.getVisible=g.prototype.getVisible;g.prototype.setVisible=function(a){this.set("visible",a)};g.prototype.setVisible=g.prototype.setVisible;
g.prototype.s=function(){if(this.c){this.a.style.display=this.getVisible()?"":"none";this.draw()}};g.prototype.visible_changed=g.prototype.s;g.prototype.setFlat=function(a){this.set("flat",!!a)};g.prototype.setFlat=g.prototype.setFlat;g.prototype.getFlat=function(){return this.get("flat")};g.prototype.getFlat=g.prototype.getFlat;g.prototype.p=function(){return this.get("width")};g.prototype.getWidth=g.prototype.p;g.prototype.o=function(){return this.get("height")};g.prototype.getHeight=g.prototype.o;
g.prototype.setShadow=function(a){this.set("shadow",a);this.g()};g.prototype.setShadow=g.prototype.setShadow;g.prototype.getShadow=function(){return this.get("shadow")};g.prototype.getShadow=g.prototype.getShadow;g.prototype.g=function(){if(this.c)this.a.style.boxShadow=this.a.style.webkitBoxShadow=this.a.style.MozBoxShadow=this.getFlat()?"":this.getShadow()};g.prototype.flat_changed=g.prototype.g;g.prototype.setZIndex=function(a){this.set("zIndex",a)};g.prototype.setZIndex=g.prototype.setZIndex;
g.prototype.getZIndex=function(){return this.get("zIndex")};g.prototype.getZIndex=g.prototype.getZIndex;g.prototype.t=function(){if(this.getZIndex()&&this.c)this.a.style.zIndex=this.getZIndex()};g.prototype.zIndex_changed=g.prototype.t;g.prototype.getDraggable=function(){return this.get("draggable")};g.prototype.getDraggable=g.prototype.getDraggable;g.prototype.setDraggable=function(a){this.set("draggable",!!a)};g.prototype.setDraggable=g.prototype.setDraggable;
g.prototype.k=function(){if(this.c)this.getDraggable()?j(this,this.a):k(this)};g.prototype.draggable_changed=g.prototype.k;g.prototype.getPosition=function(){return this.get("position")};g.prototype.getPosition=g.prototype.getPosition;g.prototype.setPosition=function(a){this.set("position",a)};g.prototype.setPosition=g.prototype.setPosition;g.prototype.q=function(){this.draw()};g.prototype.position_changed=g.prototype.q;g.prototype.l=function(){return this.get("anchor")};g.prototype.getAnchor=g.prototype.l;
g.prototype.r=function(a){this.set("anchor",a)};g.prototype.setAnchor=g.prototype.r;g.prototype.n=function(){this.draw()};g.prototype.anchor_changed=g.prototype.n;function l(a,c){var d=document.createElement("DIV");d.innerHTML=c;if(d.childNodes.length==1)return d.removeChild(d.firstChild);else{for(var e=document.createDocumentFragment();d.firstChild;)e.appendChild(d.firstChild);return e}}function m(a,c){if(c)for(var d;d=c.firstChild;)c.removeChild(d)}
g.prototype.setContent=function(a){this.set("content",a)};g.prototype.setContent=g.prototype.setContent;g.prototype.getContent=function(){return this.get("content")};g.prototype.getContent=g.prototype.getContent;
g.prototype.j=function(){if(this.b){m(this,this.b);var a=this.getContent();if(a){if(typeof a=="string"){a=a.replace(/^\s*([\S\s]*)\b\s*$/,"$1");a=l(this,a)}this.b.appendChild(a);var c=this;a=this.b.getElementsByTagName("IMG");for(var d=0,e;e=a[d];d++){e.addEventListener("mousedown",function(h){if(c.getDraggable()){h.preventDefault&&h.preventDefault();h.returnValue=f}});e.addEventListener("load",function(){c.draw()})}google.maps.event.trigger(this,"domready")}this.c&&
this.draw()}};g.prototype.content_changed=g.prototype.j;function n(a,c){if(a.c){var d="";if(navigator.userAgent.indexOf("Gecko/")!==-1){if(c=="dragging")d="-moz-grabbing";if(c=="dragready")d="-moz-grab"}else if(c=="dragging"||c=="dragready")d="move";if(c=="draggable")d="pointer";if(a.a.style.cursor!=d)a.a.style.cursor=d}}
function o(a,c){if(a.getDraggable())if(!a.d){a.d=b;var d=a.getMap();a.m=d.get("draggable");d.set("draggable",f);a.h=c.clientX;a.i=c.clientY;n(a,"dragready");a.a.style.MozUserSelect="none";a.a.style.KhtmlUserSelect="none";a.a.style.WebkitUserSelect="none";a.a.unselectable="on";a.a.onselectstart=function(){return f};p(a);google.maps.event.trigger(a,"dragstart")}}
function q(a){if(a.getDraggable())if(a.d){a.d=f;a.getMap().set("draggable",a.m);a.h=a.i=a.m=null;a.a.style.MozUserSelect="";a.a.style.KhtmlUserSelect="";a.a.style.WebkitUserSelect="";a.a.unselectable="off";a.a.onselectstart=function(){};r(a);n(a,"draggable");google.maps.event.trigger(a,"dragend");a.draw()}}
function s(a,c){if(!a.getDraggable()||!a.d)q(a);else{var d=a.h-c.clientX,e=a.i-c.clientY;a.h=c.clientX;a.i=c.clientY;d=parseInt(a.a.style.left,10)-d;e=parseInt(a.a.style.top,10)-e;a.a.style.left=d+"px";a.a.style.top=e+"px";var h=t(a);a.setPosition(a.getProjection().fromDivPixelToLatLng(new google.maps.Point(d-h.width,e-h.height)));n(a,"dragging");google.maps.event.trigger(a,"drag")}}function k(a){if(a.f){google.maps.event.removeListener(a.f);delete a.f}n(a,"")}
function j(a,c){if(c){a.f=c.addEventListener("mousedown",function(d){o(a,d)});n(a,"draggable")}}function p(a){if(a.a.setCapture){a.a.setCapture(b);a.e=[a.a.addEventListener("mousemove",function(c){s(a,c)},b),a.a.addEventListener("mouseup",function(){q(a);a.a.releaseCapture()},b)]}else a.e=[window.addEventListener("mousemove",function(c){s(a,c)},b),window.addEventListener("mouseup",function(){q(a)},b)]}
function r(a){if(a.e){for(var c=0,d;d=a.e[c];c++)google.maps.event.removeListener(d);a.e.length=0}}
function t(a){var c=a.l();if(typeof c=="object")return c;var d=new google.maps.Size(0,0);if(!a.b)return d;var e=a.b.offsetWidth;a=a.b.offsetHeight;switch(c){case i.TOP:d.width=-e/2;break;case i.TOP_RIGHT:d.width=-e;break;case i.LEFT:d.height=-a/2;break;case i.MIDDLE:d.width=-e/2;d.height=-a/2;break;case i.RIGHT:d.width=-e;d.height=-a/2;break;case i.BOTTOM_LEFT:d.height=-a;break;case i.BOTTOM:d.width=-e/2;d.height=-a;break;case i.BOTTOM_RIGHT:d.width=-e;d.height=-a}return d}
g.prototype.onAdd=function(){if(!this.a){this.a=document.createElement("DIV");this.a.style.position="absolute"}if(this.getZIndex())this.a.style.zIndex=this.getZIndex();this.a.style.display=this.getVisible()?"":"none";if(!this.b){this.b=document.createElement("DIV");this.a.appendChild(this.b);var a=this;this.b.addEventListener("click",function(){google.maps.event.trigger(a,"click")});this.b.addEventListener("mouseover",function(){google.maps.event.trigger(a,"mouseover")});
this.b.addEventListener("mouseout",function(){google.maps.event.trigger(a,"mouseout")})}this.c=b;this.j();this.g();this.k();var c=this.getPanes();c&&c.overlayImage.appendChild(this.a);google.maps.event.trigger(this,"ready")};g.prototype.onAdd=g.prototype.onAdd;
g.prototype.draw=function(){if(!(!this.c||this.d)){var a=this.getProjection();if(a){var c=this.get("position");a=a.fromLatLngToDivPixel(c);c=t(this);this.a.style.top=a.y+c.height+"px";this.a.style.left=a.x+c.width+"px";a=this.b.offsetHeight;c=this.b.offsetWidth;c!=this.get("width")&&this.set("width",c);a!=this.get("height")&&this.set("height",a)}}};g.prototype.draw=g.prototype.draw;g.prototype.onRemove=function(){this.a&&this.a.parentNode&&this.a.parentNode.removeChild(this.a);k(this)};
g.prototype.onRemove=g.prototype.onRemove;var i={TOP_LEFT:1,TOP:2,TOP_RIGHT:3,LEFT:4,MIDDLE:5,RIGHT:6,BOTTOM_LEFT:7,BOTTOM:8,BOTTOM_RIGHT:9};window.RichMarkerPosition=i;
})();
};