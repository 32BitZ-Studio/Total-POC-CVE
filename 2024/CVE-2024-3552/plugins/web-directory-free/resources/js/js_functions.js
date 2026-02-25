var w2dc_maps = [];
var w2dc_maps_attrs = [];
var w2dc_infoWindows = [];
var w2dc_drawCircles = [];
var w2dc_searchAddresses = [];
var w2dc_polygons = [];
var w2dc_fullScreens = [];
var w2dc_global_markers_array = [];
var w2dc_global_locations_array = [];
var w2dc_markerClusters = [];
var w2dc_directions_display = [];
var w2dc_stop_touchmove_listener = function(e){
	e.preventDefault();
}
var w2dc_glocation = (function(id, point, map_icon_file, map_icon_color, listing_title, listing_logo, listing_url, content_fields, anchor, nofollow, show_summary_button, show_readmore_button, map_id, is_ajax_markers) {
	this.id = id;
	this.point = point;
	this.map_icon_file = map_icon_file;
	this.map_icon_color = map_icon_color;
	this.listing_title = listing_title;
	this.listing_logo = listing_logo;
	this.listing_url = listing_url;
	this.content_fields = content_fields;
	this.anchor = anchor;
	this.nofollow = nofollow;
	this.show_summary_button = show_summary_button;
	this.show_readmore_button = show_readmore_button;
	this.w2dc_placeMarker = function(map_id) {
		this.marker = w2dc_placeMarker(this, map_id);
		return this.marker;
	};
	this.is_ajax_markers = is_ajax_markers;
});
var _w2dc_map_markers_attrs_array;
var w2dc_dragended;
var ZOOM_FOR_SINGLE_MARKER = 17;

var w2dc_map_backend = null;
var w2dc_allow_map_zoom_backend = true; // allow/disallow map zoom in listener, this option needs because w2dc_map_backend.setZoom() also calls this listener
var w2dc_geocoder_backend = null;
var w2dc_infoWindow_backend = null;
var w2dc_markersArray_backend = [];
var w2dc_glocation_backend = (function(index, point, location, address_line_1, address_line_2, zip_or_postal_index, map_icon_file) {
	this.index = index;
	this.point = point;
	this.location = location;
	this.address_line_1 = address_line_1;
	this.address_line_2 = address_line_2;
	this.zip_or_postal_index = zip_or_postal_index;
	this.map_icon_file = map_icon_file;
	this.w2dc_placeMarker = function() {
		return w2dc_placeMarker_backend(this);
	};
	this.compileAddress = function() {
		var address = this.address_line_1;
		if (this.address_line_2)
			address += ", "+this.address_line_2;
		if (this.location) {
			if (address)
				address += " ";
			address += this.location;
		}
		if (w2dc_maps_objects.default_geocoding_location) {
			if (address)
				address += " ";
			address += w2dc_maps_objects.default_geocoding_location;
		}
		if (this.zip_or_postal_index) {
			if (address)
				address += " ";
			address += this.zip_or_postal_index;
		}
		return address;
	};
	this.compileHtmlAddress = function() {
		var address = this.address_line_1;
		if (this.address_line_2)
			address += ", "+this.address_line_2;
		if (this.location) {
			if (this.address_line_1 || this.address_line_2)
				address += "<br />";
			address += this.location;
		}
		if (this.zip_or_postal_index)
			address += " "+this.zip_or_postal_index;
		return address;
	};
	this.setPoint = function(point) {
		this.point = point;
	};
});

/* Stack-based Douglas Peucker line simplification routine 
returned is a reduced GLatLng array 
After code by  Dr. Gary J. Robinson,
Environmental Systems Science Centre,
University of Reading, Reading, UK
*/
function w2dc_GDouglasPeucker(source, kink) {
	var n_source, n_stack, n_dest, start, end, i, sig;    
	var dev_sqr, max_dev_sqr, band_sqr;
	var x12, y12, d12, x13, y13, d13, x23, y23, d23;
	var F = ((Math.PI / 180.0) * 0.5 );
	var index = new Array();
	var sig_start = new Array();
	var sig_end = new Array();

	if ( source.length < 3 ) 
		return(source);

	n_source = source.length;
	band_sqr = kink * 360.0 / (2.0 * Math.PI * 6378137.0);
	band_sqr *= band_sqr;
	n_dest = 0;
	sig_start[0] = 0;
	sig_end[0] = n_source-1;
	n_stack = 1;

	while ( n_stack > 0 ) {
		start = sig_start[n_stack-1];
		end = sig_end[n_stack-1];
		n_stack--;

		if ( (end - start) > 1 ) {
			x12 = (source[end].lng() - source[start].lng());
			y12 = (source[end].lat() - source[start].lat());
			if (Math.abs(x12) > 180.0) 
				x12 = 360.0 - Math.abs(x12);
			x12 *= Math.cos(F * (source[end].lat() + source[start].lat()));
			d12 = (x12*x12) + (y12*y12);

			for ( i = start + 1, sig = start, max_dev_sqr = -1.0; i < end; i++ ) {                                    
				x13 = (source[i].lng() - source[start].lng());
				y13 = (source[i].lat() - source[start].lat());
				if (Math.abs(x13) > 180.0) 
					x13 = 360.0 - Math.abs(x13);
				x13 *= Math.cos (F * (source[i].lat() + source[start].lat()));
				d13 = (x13*x13) + (y13*y13);

				x23 = (source[i].lng() - source[end].lng());
				y23 = (source[i].lat() - source[end].lat());
				if (Math.abs(x23) > 180.0) 
					x23 = 360.0 - Math.abs(x23);
				x23 *= Math.cos(F * (source[i].lat() + source[end].lat()));
				d23 = (x23*x23) + (y23*y23);

				if ( d13 >= ( d12 + d23 ) )
					dev_sqr = d23;
				else if ( d23 >= ( d12 + d13 ) )
					dev_sqr = d13;
				else
					dev_sqr = (x13 * y12 - y13 * x12) * (x13 * y12 - y13 * x12) / d12;// solve triangle

				if ( dev_sqr > max_dev_sqr  ){
					sig = i;
					max_dev_sqr = dev_sqr;
				}
			}

			if ( max_dev_sqr < band_sqr ) {
				index[n_dest] = start;
				n_dest++;
			} else {
				n_stack++;
				sig_start[n_stack-1] = sig;
				sig_end[n_stack-1] = end;
				n_stack++;
				sig_start[n_stack-1] = start;
				sig_end[n_stack-1] = sig;
			}
		} else {
			index[n_dest] = start;
			n_dest++;
		}
	}
	index[n_dest] = n_source-1;
	n_dest++;

	var r = new Array();
	for(var i=0; i < n_dest; i++)
		r.push(source[index[i]]);

	return r;
}

(function($) {
	"use strict";
	
	$(function() {
		w2dc_check_support();
		w2dc_add_body_classes();
		w2dc_get_rid_of_select2_choosen();
		w2dc_custom_input_controls();
		w2dc_my_location_buttons();
		w2dc_tokenizer();
		w2dc_equalColumnsHeight();
		w2dc_equalColumnsHeightEvent();
		w2dc_listings_carousel();
		w2dc_radius_slider();
		w2dc_hint();
		w2dc_favourites();
		w2dc_week_day_input();
		w2dc_check_is_week_day_closed();
		w2dc_listing_tabs();
		w2dc_dashboard_tabs();
		w2dc_sticky_scroll();
		w2dc_tooltips();
		w2dc_ratings();
		w2dc_hours_content_field();
		w2dc_full_height_maps();
		w2dc_load_comments();
		w2dc_content_fields_metabox();
		w2dc_upload_image();
		w2dc_media_metabox();
		w2dc_locations_metabox();
		w2dc_datetime_input();
		w2dc_expiration_date_metabox();
		w2dc_order_date_metabox();
		w2dc_add_term_links();
		w2dc_sort_terms();
	});

	window.w2dc_check_support = function() {
		
		$(".w2dc-license-support-checker").each(function() {
			
			var el 		= $(this);
			var nonce	= el.data("nonce");
			
			$.ajax({
				type: 'POST',
				url: w2dc_js_objects.ajaxurl,
				data: { 
					'action': 'w2dc_license_support_checker',
					'security': nonce
				},
				success: function(response) {
					
					if (response) {
						el.html(response);
					}
				}
			});
		});
	}
	
	window.w2dc_sort_terms = function() {
		if (typeof w2dc_order_term_data != 'undefined') {
			var base_index = parseInt(w2dc_order_term_data.paged) > 0 ? (parseInt(w2dc_order_term_data.paged) - 1) * parseInt($('#'+w2dc_order_term_data.per_page_id).val()) : 0;
			var tax_table  = $('#the-list');
		
			// If the tax table contains items.
			if (tax_table.length && !tax_table.find('tr:first-child').hasClass('no-items')) {
				
				tax_table.sortable({
					placeholder: "w2dc-drag-drop-tax-placeholder",
					axis: "y",
		
					// On start, set a height for the placeholder to prevent table jumps.
					start: function(event, ui) {
						const item  = $(ui.item[0]);
						const index = item.index();
						const colspan = item.children('th,td').filter(':visible').length;
						$('.w2dc-drag-drop-tax-placeholder')
						.css('height', item.css('height'))
						.css('display', 'flex')
						.css('width', '0');
					},
					update: function(event, ui) {
						var item = $(ui.item[0]);
						var taxonomy_ordering_data = [];
		
						tax_table.find('tr.ui-sortable-handle').each(function() {
							var ele = $(this);
							var term_data = {
								term_id: ele.attr('id').replace('tag-', ''),
								order: parseInt(ele.index()) + 1
							}
							taxonomy_ordering_data.push(term_data);
						});
						
						var data = {
							'action': 'w2dc_update_tax_order',
							'taxonomy_ordering_data': taxonomy_ordering_data,
							'base_index': base_index,
							'term_order_nonce': w2dc_order_term_data.term_order_nonce
						};
						
						$.ajax({
							type: 'POST',
							url: w2dc_js_objects.ajaxurl,
							data: data,
							dataType: 'JSON',
							success: function(response) {
								item.find('input[type="checkbox"]').show();
							}
						});
					}
				});
			}
		}
	}
	
	window.w2dc_upload_image = function() {
		$(document).on("click", ".w2dc-reset-image-button", function(e) {
			e.preventDefault();
			
			var form = $(this).parents(".w2dc-upload-image-form");
			form.parent().find(".w2dc-upload-image").css("background-image", "");
			form.parent().find('.w2dc-upload-image-input-' + form.data('name')).val("");
		});
		if (w2dc_js_objects.is_admin) {
			$(document).on('click', '.w2dc-upload-image-button', function(event) {
				event.preventDefault();
		
				var form = $(this).parents(".w2dc-upload-image-form");
				var frame = wp.media({
					title : w2dc_js_objects.media_dialog_title,
					multiple : false,
					library : { type : 'image'},
					button : { text : w2dc_js_objects.media_dialog_button_text},
				});
				frame.on('select', function() {
					var selected_images = [];
					var selection = frame.state().get('selection');
					selection.each(function(attachment) {
						attachment = attachment.toJSON();
						if (attachment.type == 'image') {
							
							var image_url = attachment.sizes.full.url;
							var attachment_id = attachment.id;
							form.find('.w2dc-upload-image').css("background-image", "url(" + image_url + ")");
							form.find('.w2dc-upload-image-input-' + form.data('name')).val(attachment_id);
						}
					
					});
				});
				frame.open();
			});
		} else {
			$(document).on("click", ".w2dc-upload-image-button", function(e) {
				e.preventDefault();
				
				$(this).parent().find("input").click();
			});
			$('.w2dc-upload-image-form').each(function() {
				var form = $(this);
				var action_url = form.data('action-url');
				form.fileupload({
					dataType: 'json',
					url: action_url,
					send: function (e, data) {
						w2dc_add_iloader_on_element(form);
					},
					done: function(e, data) {
						var result = data.result;
						if (result.uploaded_file) {
							var size = result.metadata.size;
							var width = result.metadata.width;
							var height = result.metadata.height;
							form.find('.w2dc-upload-image').css("background-image", "url(" + result.uploaded_file + ")");
							form.find('.w2dc-upload-image-input-' + form.data('name')).val(result.attachment_id);
						} else {
							form.find('.w2dc-upload-image').append("<p>"+result.error_msg+"</p>");
						}
						w2dc_delete_iloader_from_element(form);
					}
				});
			});
		}
	}

	window.w2dc_add_term_links = function() {
		$(document).on("click", ".w2dc-add-term-link", function(e) {
			e.preventDefault();
			
			var el = $(this);
			var tax = el.data('tax');
			var uid = el.data('uid');
			var exact_terms = el.data('exact-terms');
			var parent_id = el.data('parent');
			var nonce = el.data('nonce');
			var label = el.html();
			var saved_html = el[0].outerHTML;

			var add_form = $('<form class="w2dc-add-term-form"><input name="w2dc_add_term_input" class="w2dc-form-control w2dc-add-term-input" value="" /><a class="w2dc-btn w2dc-btn-primary w2dc-add-term-button">'+label+'</a> <a class="w2dc-btn w2dc-btn-primary w2dc-add-term-cancel">'+w2dc_js_objects.cancel_button+'</a></form>');
			add_form.on("submit", function(e) {
				e.preventDefault();
				
				$(add_form).find('.w2dc-add-term-button').trigger('click');
			});
			el.replaceWith(add_form);
			
			$(add_form).find('.w2dc-add-term-input').focus();
			
			$(add_form).on("click", ".w2dc-add-term-cancel", function(e) {
				e.preventDefault();
				
				$(this).parent().replaceWith(saved_html);
			});
			
			$(add_form).on("click", ".w2dc-add-term-button", function(e) {
				e.preventDefault();
				
				var input = $(this).parent().find('.w2dc-add-term-input');
				if (input.val()) {
					w2dc_ajax_loader_show();
					
					$.ajax({
						type: "POST",
						url: w2dc_js_objects.ajaxurl,
						data: { 
							'action': 'w2dc_add_term',
							'tax': tax,
							'parent_id': parent_id,
							'val': input.val(),
							'security': nonce
						},
						success: function(term_id){
							
							term_id = $.trim(term_id);
							
							if (term_id != 0) {
								$(add_form).find('.w2dc-add-term-cancel').trigger('click');
								
								w2dc_update_tax_wrapper(tax, uid, exact_terms, term_id);
							}
						},
						complete: function() {
							
						}
					});
				}
			});
		});
	}
	
	window.w2dc_update_tax_wrapper = function(tax, uid, exact_terms, selected_term) {
		var wrapper = $('div.'+tax);
		
		$.ajax({
			type: "POST",
			url: w2dc_js_objects.ajaxurl,
			data: { 'action': 'w2dc_update_tax_wrapper', 'tax': tax, 'exact_terms': exact_terms, 'selected_term': selected_term, 'uid': uid },
			success: function(response_from_the_action_function){
				if (response_from_the_action_function != 0) {
					wrapper.html('').append(response_from_the_action_function);
				}
			},
			complete: function() {
				w2dc_ajax_loader_hide();
			}
		});
	}
	
	window.w2dc_expiration_date_metabox = function() {
		if (typeof w2dc_expiration_date_metabox_attrs != 'undefined') {
			$("#expiration_date").datepicker({
				changeMonth: true,
				changeYear: true,
				isRTL: w2dc_expiration_date_metabox_attrs.isRTL,
				showButtonPanel: true,
				dateFormat: w2dc_expiration_date_metabox_attrs.dateFormat,
				firstDay: w2dc_expiration_date_metabox_attrs.firstDay,
				onSelect: function(dateText) {
					var tmstmp_str;
					var sDate = $("#expiration_date").datepicker("getDate");
					if (sDate) {
						sDate.setMinutes(sDate.getMinutes() - sDate.getTimezoneOffset());
						tmstmp_str = $.datepicker.formatDate('@', sDate)/1000;
					} else {
						tmstmp_str = 0;
					}
	
					$("input[name=expiration_date_tmstmp]").val(tmstmp_str);
				}
			});
			if (w2dc_expiration_date_metabox_attrs.lang_code) {
				$("#expiration_date").datepicker($.datepicker.regional[w2dc_expiration_date_metabox_attrs.lang_code]);
			}
	
			$("#expiration_date").datepicker('setDate', $.datepicker.parseDate('dd/mm/yy', w2dc_expiration_date_metabox_attrs.expiration_date_formatted));
		}
	}
	
	window.w2dc_order_date_metabox = function() {
		if (typeof w2dc_order_date_metabox_attrs != 'undefined') {
			$("#order_date").datepicker({
				changeMonth: true,
				changeYear: true,
				isRTL: w2dc_order_date_metabox_attrs.isRTL,
				showButtonPanel: true,
				dateFormat: w2dc_order_date_metabox_attrs.dateFormat,
				firstDay: w2dc_order_date_metabox_attrs.firstDay,
				onSelect: function(dateText) {
					var tmstmp_str;
					var sDate = $("#order_date").datepicker("getDate");
					if (sDate) {
						sDate.setMinutes(sDate.getMinutes() - sDate.getTimezoneOffset());
						tmstmp_str = $.datepicker.formatDate('@', sDate)/1000;
					} else {
						tmstmp_str = 0;
					}
					
					$("input[name=order_date_tmstmp]").val(tmstmp_str);
				}
			});
			if (w2dc_order_date_metabox_attrs.lang_code) {
				$("#order_date").datepicker($.datepicker.regional[w2dc_order_date_metabox_attrs.lang_code]);
			}
			
			$("#order_date").datepicker('setDate', $.datepicker.parseDate('dd/mm/yy', w2dc_order_date_metabox_attrs.order_date_formatted));
		}
	}
	
	window.w2dc_datetime_input = function() {
		if (typeof w2dc_datetime_input_attrs != 'undefined') {
			
			$.each(w2dc_datetime_input_attrs, function (index, field_attrs) {
				var field_id = field_attrs.field_id;
				
				$("#w2dc-field-input-" + field_id + "-start").datepicker({
					changeMonth: true,
					changeYear: true,
					isRTL: field_attrs.isRTL,
					showButtonPanel: true,
					dateFormat: field_attrs.dateFormat,
					firstDay: field_attrs.firstDay,
					onSelect: function(dateText) {
						var tmstmp_str;
						var sDate = $("#w2dc-field-input-" + field_id + "-start").datepicker("getDate");
						var set_min_date = $("#w2dc-field-input-" + field_id + "-start").datepicker("getDate");
						if (sDate) {
							sDate.setMinutes(sDate.getMinutes() - sDate.getTimezoneOffset());
							tmstmp_str = $.datepicker.formatDate('@', sDate)/1000;
						} else {
							tmstmp_str = 0;
						}
						$("#w2dc-field-input-" + field_id + "-end").datepicker('option', 'minDate', set_min_date);
		
						$("input[name=w2dc-field-input-" + field_id + "-start]").val(tmstmp_str);
					},
					onClose: function() {
						// this is workaround to prevent an issue when changing year-month on the end datepicker 
						setTimeout(function() {
							$("#w2dc-field-input-" + field_id + "-end").focus();
						}, 0);
					}
				});
				if (field_attrs.lang_code) {
					$("#w2dc-field-input-" + field_id + "-start").datepicker($.datepicker.regional[field_attrs.lang_code]);
				}
				
				$("#w2dc-field-input-" + field_id + "-end").datepicker({
					changeMonth: true,
					changeYear: true,
					isRTL: field_attrs.isRTL,
					showButtonPanel: true,
					dateFormat: field_attrs.dateFormat,
					firstDay: field_attrs.firstDay,
					onSelect: function(dateText) {
						var tmstmp_str;
						var sDate = $("#w2dc-field-input-" + field_id + "-end").datepicker("getDate");
						var set_max_date = $("#w2dc-field-input-" + field_id + "-end").datepicker("getDate");
						if (sDate) {
							sDate.setMinutes(sDate.getMinutes() - sDate.getTimezoneOffset());
							tmstmp_str = $.datepicker.formatDate('@', sDate)/1000;
						} else {
							tmstmp_str = 0;
						}
						$("#w2dc-field-input-" + field_id + "-start").datepicker('option', 'maxDate', set_max_date);
		
						$("input[name=w2dc-field-input-" + field_id + "-end]").val(tmstmp_str);
					}
				});
				if (field_attrs.lang_code) {
					$("#w2dc-field-input-" + field_id + "-end").datepicker($.datepicker.regional[field_attrs.lang_code]);
				}

				if (field_attrs.date_end) {
					$("#w2dc-field-input-" + field_id + "-end").datepicker('setDate', $.datepicker.parseDate('dd/mm/yy', field_attrs.date_end_formatted));
					$("#w2dc-field-input-" + field_id + "-start").datepicker('option', 'maxDate', $("#w2dc-field-input-" + field_id + "-end").datepicker('getDate'));
				}
				$('body').on('click', "#w2dc-reset-date-" + field_id + "-end", function() {
					$.datepicker._clearDate("#w2dc-field-input-" + field_id + "-end");
				})

				if (field_attrs.date_start) {
					$("#w2dc-field-input-" + field_id + "-start").datepicker('setDate', $.datepicker.parseDate('dd/mm/yy', field_attrs.date_start_formatted));
					$("#w2dc-field-input-" + field_id + "-end").datepicker('option', 'minDate', $("#w2dc-field-input-" + field_id + "-start").datepicker('getDate'));
				}
				$('body').on('click', "#w2dc-reset-date-" + field_id + "-start", function() {
					$.datepicker._clearDate("#w2dc-field-input-" + field_id + "-start");
				})
			});
		}
	}
	
	window.w2dc_locations_metabox = function() {
		if (typeof w2dc_locations_metabox_attrs != 'undefined') {
			if (w2dc_locations_metabox_attrs.is_map_markers) {
				if (w2dc_maps_objects.map_markers_type == 'images') {
					var map_icon_file_input;
					$(document).on("click", ".w2dc-select-map-icon", function() {
						map_icon_file_input = $(this).parents(".w2dc-location-input").find('.w2dc-map-icon-file');
			
						var dialog = $('<div id="w2dc-select-map-icon-dialog"></div>').dialog({
							dialogClass: 'w2dc-content',
							width: ($(window).width()*0.5),
							height: ($(window).height()*0.8),
							modal: true,
							resizable: false,
							draggable: false,
							title: w2dc_locations_metabox_attrs.images_dialog_title,
							open: function() {
								w2dc_ajax_loader_show();
								$.ajax({
									type: "POST",
									url: w2dc_js_objects.ajaxurl,
									data: {'action': 'w2dc_select_map_icon'},
									dataType: 'html',
									success: function(response_from_the_action_function){
										if (response_from_the_action_function != 0) {
											$('#w2dc-select-map-icon-dialog').html(response_from_the_action_function);
											if (map_icon_file_input.val())
												$(".w2dc-icon[icon_file='"+map_icon_file_input.val()+"']").addClass("w2dc-selected-icon");
										}
									},
									complete: function() {
										w2dc_ajax_loader_hide();
									}
								});
								$(document).on("click", ".ui-widget-overlay", function() { $('#w2dc-select-map-icon-dialog').remove(); });
							},
							close: function() {
								$('#w2dc-select-map-icon-dialog').remove();
							}
						});
					});
					$(document).on("click", ".w2dc-icon", function() {
						$(".w2dc-selected-icon").removeClass("w2dc-selected-icon");
						if (map_icon_file_input) {
							map_icon_file_input.val($(this).attr('icon_file'));
							map_icon_file_input = false;
							$(this).addClass("w2dc-selected-icon");
							$('#w2dc-select-map-icon-dialog').remove();
							w2dc_generateMap_backend();
						}
					});
					$(document).on("click", "#reset_icon", function() {
						if (map_icon_file_input) {
							$(".w2dc-selected-icon").removeClass("w2dc-selected-icon");
							map_icon_file_input.val('');
							map_icon_file_input = false;
							$('#w2dc-select-map-icon-dialog').remove();
							w2dc_generateMap_backend();
						}
					});
				} else {
					var map_icon_file_input;
					$(document).on("click", ".w2dc-select-map-icon", function() {
						map_icon_file_input = $(this).parents(".w2dc-location-input").find('.w2dc-map-icon-file');
		
						var dialog = $('<div id="select_marker_icon_dialog"></div>').dialog({
							dialogClass: 'w2dc-content',
							width: ($(window).width()*0.5),
							height: ($(window).height()*0.8),
							modal: true,
							resizable: false,
							draggable: false,
							title: w2dc_locations_metabox_attrs.icons_dialog_title,
							open: function() {
								w2dc_ajax_loader_show();
								$.ajax({
									type: "POST",
									url: w2dc_js_objects.ajaxurl,
									data: {'action': 'w2dc_select_fa_icon'},
									dataType: 'html',
									success: function(response_from_the_action_function){
										if (response_from_the_action_function != 0) {
											$('#select_marker_icon_dialog').html(response_from_the_action_function);
											if (map_icon_file_input.val())
												$("#"+map_icon_file_input.val()).addClass("w2dc-selected-icon");
										}
									},
									complete: function() {
										w2dc_ajax_loader_hide();
									}
								});
								$(document).on("click", ".ui-widget-overlay", function() { $('#select_marker_icon_dialog').remove(); });
							},
							close: function() {
								$('#select_marker_icon_dialog').remove();
							}
						});
					});
					$(document).on("click", ".w2dc-fa-icon", function() {
						$(".w2dc-selected-icon").removeClass("w2dc-selected-icon");
						if (map_icon_file_input) {
							map_icon_file_input.val($(this).attr('id'));
							map_icon_file_input = false;
							$(this).addClass("w2dc-selected-icon");
							$('#select_marker_icon_dialog').remove();
							w2dc_generateMap_backend();
						}
					});
					$(document).on("click", "#w2dc-reset-fa-icon", function() {
						if (map_icon_file_input) {
							$(".w2dc-selected-icon").removeClass("w2dc-selected-icon");
							map_icon_file_input.val('');
							map_icon_file_input = false;
							$('#select_marker_icon_dialog').remove();
							w2dc_generateMap_backend();
						}
					});
				}
			}
			
			$('body').on('click', ".add_address", function() {
				w2dc_ajax_loader_show();
				$.ajax({
					type: "POST",
					url: w2dc_js_objects.ajaxurl,
					data: { 'action': 'w2dc_add_location_in_metabox', 'post_id': w2dc_locations_metabox_attrs.post_id },
					success: function(response_from_the_action_function){
						if (response_from_the_action_function != 0) {
							$("#w2dc-locations-wrapper").append(response_from_the_action_function);
							$(".w2dc-delete-address").show();
							if (w2dc_locations_metabox_attrs.locations_number == $(".w2dc-location-in-metabox").length) {
								$(".add_address").hide();
							}
							if (w2dc_maps_objects.address_autocomplete && w2dc_js_objects.is_maps_used) {
								w2dc_setupAutocomplete();
							}
						}
					},
					complete: function() {
						w2dc_ajax_loader_hide();
					}
				});
			});
			$(document).on("click", ".w2dc-delete-address", function() {
				$(this).parents(".w2dc-location-in-metabox").remove();
				if ($(".w2dc-location-in-metabox").length == 1)
					$(".w2dc-delete-address").hide();
	
				if (w2dc_locations_metabox_attrs.is_map) {
					w2dc_generateMap_backend();
				}
	
				if (w2dc_locations_metabox_attrs.locations_number > $(".w2dc-location-in-metabox").length)
					$(".add_address").show();
			});
	
			$(document).on("click", ".w2dc-manual-coords", function() {
	        	if ($(this).is(":checked"))
	        		$(this).parents(".w2dc-manual-coords-wrapper").find(".w2dc-manual-coords-block").slideDown(200);
	        	else
	        		$(this).parents(".w2dc-manual-coords-wrapper").find(".w2dc-manual-coords-block").slideUp(200);
	        });
	
	        if (w2dc_locations_metabox_attrs.locations_number > $(".w2dc-location-in-metabox").length) {
				$(".add_address").show();
	        }
		}
	}
	
	window.w2dc_media_metabox = function() {
		if ($('#w2dc-images-upload-wrapper').length) {

			window.w2dc_image_attachment_tpl = function(attachment_id, uploaded_file, title, size, width, height) {
				var image_attachment_tpl = '<div class="w2dc-attached-item w2dc-move-label">' +
						'<input type="hidden" name="attached_image_id[]" class="w2dc-attached-item-id" value="'+attachment_id+'" />' +
						'<a href="'+uploaded_file+'" data-w2dc_lightbox="listing_images" class="w2dc-attached-item-img" style="background-image: url('+uploaded_file+')"></a>' +
						'<div class="w2dc-attached-item-input">' +
							'<input type="text" name="attached_image_title[]" class="w2dc-form-control" value="" placeholder="' + w2dc_media_metabox_attrs.images_input_placeholder + '" />' +
						'</div>';
						if (w2dc_media_metabox_attrs.images_logo_enabled) {
							image_attachment_tpl = image_attachment_tpl + '<div class="w2dc-attached-item-logo w2dc-radio">' +
							'<label>' +
								'<input type="radio" name="attached_image_as_logo" value="'+attachment_id+'"> ' + w2dc_media_metabox_attrs.images_input_label +
							'</label>' +
							'</div>';
						}
						image_attachment_tpl = image_attachment_tpl + '<div class="w2dc-attached-item-delete w2dc-fa w2dc-fa-trash-o" title="' + w2dc_media_metabox_attrs.images_remove_title + '"></div>' +
						'<div class="w2dc-attached-item-metadata">'+size+' ('+width+' x '+height+')</div>' +
					'</div>';

				return image_attachment_tpl;
			};

			window.w2dc_update_images_attachments_order = function() {
				$("#w2dc-attached-images-order").val($(".w2dc-attached-item-id").map(function() {
					return $(this).val();
				}).get());
			}
			window.w2dc_check_images_attachments_number = function() {
				if (w2dc_media_metabox_attrs.images_number > $("#w2dc-images-upload-wrapper .w2dc-attached-item").length) {
					if (w2dc_js_objects.is_admin) {
						$("#w2dc-admin-upload-functions").show();
					} else {
						$(".w2dc-upload-item").show();
					}
					return true;
				} else {
					if (w2dc_js_objects.is_admin) {
						$("#w2dc-admin-upload-functions").hide();
					} else {
						$(".w2dc-upload-item").hide();
					}
					return false;
				}
			}

			
		    var sortable_images = $("#w2dc-attached-images-wrapper").sortable({
			    delay: 50,
		    	placeholder: "ui-sortable-placeholder",
		    	items: ".w2dc-attached-item",
				helper: function(e, ui) {
					ui.children().each(function() {
						$(this).width($(this).width());
					});
					return ui;
				},
				start: function(e, ui){
					ui.placeholder.width(ui.item.width());
					ui.placeholder.height(ui.item.height());
				},
				update: function( event, ui ) {
					w2dc_update_images_attachments_order();
				}
			});

		    // disable sortable on android, otherwise it breaks click events on image, radio and delete button
		    var ua = navigator.userAgent.toLowerCase();
		    if (ua.indexOf("android") > -1) {
				sortable_images.sortable("disable");
			};

			w2dc_check_images_attachments_number();

			$("#w2dc-attached-images-wrapper").on("click", ".w2dc-attached-item-delete", function() {
				$(this).parents(".w2dc-attached-item").remove();
				
				$.ajax({
					url: w2dc_js_objects.ajaxurl,
					type: "POST",
					dataType: "json",
					data: {
						action: 'w2dc_remove_image',
						post_id: w2dc_media_metabox_attrs.object_id,
						attachment_id: $(this).parent().find(".w2dc-attached-item-id").val(),
						_wpnonce: w2dc_media_metabox_attrs.images_remove_image_nonce
					}
				});
		
				w2dc_check_images_attachments_number();
				w2dc_update_images_attachments_order();
			});

			if (!w2dc_js_objects.is_admin) {
				$(document).on("click", ".w2dc-upload-item-button", function(e){
					e.preventDefault();
					
					$(this).parent().find("input").click();
				});
	
				$('.w2dc-upload-item').fileupload({
					sequentialUploads: true,
					dataType: 'json',
					url: w2dc_media_metabox_attrs.images_fileupload_url,
					dropZone: $('.w2dc-drop-attached-item'),
					add: function (e, data) {
						if (w2dc_check_images_attachments_number()) {
							var jqXHR = data.submit();
						} else {
							return false;
						}
					},
					send: function (e, data) {
						w2dc_add_iloader_on_element($(this).find(".w2dc-drop-attached-item"));
					},
					done: function(e, data) {
						var result = data.result;
						if (result.uploaded_file) {
							var size = result.metadata.size;
							var width = result.metadata.width;
							var height = result.metadata.height;
							$(this).before(w2dc_image_attachment_tpl(result.attachment_id, result.uploaded_file, data.files[0].name, size, width, height));
							w2dc_custom_input_controls();
						} else {
							$(this).find(".w2dc-drop-attached-item").append("<p>"+result.error_msg+"</p>");
						}
						$(this).find(".w2dc-drop-zone").show();
						w2dc_delete_iloader_from_element($(this).find(".w2dc-drop-attached-item"));
						
						w2dc_check_images_attachments_number();
						w2dc_update_images_attachments_order();
					}
				});
			}
			
			if (w2dc_media_metabox_attrs.images_is_admin) {
				$('body').on('click', '#w2dc-admin-upload-image', function(event) {
					event.preventDefault();
			
					var frame = wp.media({
						title : w2dc_media_metabox_attrs.images_upload_image_title,
						multiple : true,
						library : { type : 'image'},
						button : { text : w2dc_media_metabox_attrs.images_upload_image_button},
					});
					frame.on('select', function() {
						var selected_images = [];
						var selection = frame.state().get('selection');
						selection.each(function(attachment) {
							attachment = attachment.toJSON();
							if (attachment.type == 'image') {
					
								if (w2dc_check_images_attachments_number()) {
									w2dc_ajax_loader_show();
			
									$.ajax({
										type: "POST",
										async: false,
										url: w2dc_js_objects.ajaxurl,
										data: {
											'action': 'w2dc_upload_media_image',
											'attachment_id': attachment.id,
											'post_id': w2dc_media_metabox_attrs.object_id,
											'_wpnonce': w2dc_media_metabox_attrs.images_upload_image_nonce,
										},
										attachment_id: attachment.id,
										attachment_url: attachment.sizes.full.url,
										attachment_title: attachment.title,
										dataType: "json",
										success: function (response_from_the_action_function) {
											if (response_from_the_action_function != 0) {
												var size = response_from_the_action_function.metadata.size;
												var width = response_from_the_action_function.metadata.width;
												var height = response_from_the_action_function.metadata.height;
												$("#w2dc-attached-images-wrapper").append(w2dc_image_attachment_tpl(this.attachment_id, this.attachment_url, this.attachment_title, size, width, height));
												w2dc_check_images_attachments_number();
												w2dc_update_images_attachments_order();
											}
												
											w2dc_ajax_loader_hide();
										}
									});
								}
							}
						
						});
					});
					frame.open();
				});
			}
		}
		
		if ($('#w2dc-attach-videos-functions').length) {
			window.w2dc_video_attachment_tpl = function(video_id, image_url) {
				var video_attachment_tpl = '<div class="w2dc-attached-item">' +
					'<input type="hidden" name="attached_video_id[]" value="'+video_id+'" />' +
					'<div class="w2dc-attached-item-img" style="background-image: url('+image_url+')"></div>' +
					'<div class="w2dc-attached-item-delete w2dc-fa w2dc-fa-trash-o" title="' + w2dc_media_metabox_attrs.videos_delete_title + '"></div>' +
				'</div>';

				return video_attachment_tpl;
			};

			window.w2dc_check_videos_attachments_number = function() {
				if (w2dc_media_metabox_attrs.videos_number > $("#w2dc-attached-videos-wrapper .w2dc-attached-item").length) {
					$("#w2dc-attach-videos-functions").show();
				} else {
					$("#w2dc-attach-videos-functions").hide();
				}
			}

			w2dc_check_videos_attachments_number();

			$("#w2dc-attached-videos-wrapper").on("click", ".w2dc-attached-item-delete", function() {
				$(this).parents(".w2dc-attached-item").remove();
	
				w2dc_check_videos_attachments_number();
			});
			
			window.attachVideo = function() {
				if ($("#w2dc-attach-video-input").val()) {
					var regExp_youtube = /^.*(youtu.be\/|v\/|u\/\w\/|embed\/|watch\?v=|\&v=)([^#\&\?]*).*/;
					var regExp_vimeo = /https?:\/\/(?:www\.|player\.)?vimeo.com\/(?:channels\/(?:\w+\/)?|groups\/([^\/]*)\/videos\/|album\/(\d+)\/video\/|video\/|)(\d+)(?:$|\/|\?)/;
					var matches_youtube = $("#w2dc-attach-video-input").val().match(regExp_youtube);
					var matches_vimeo = $("#w2dc-attach-video-input").val().match(regExp_vimeo);
					if (matches_youtube && matches_youtube[2].length == 11) {
						var video_id = matches_youtube[2];
						var image_url = 'http://i.ytimg.com/vi/'+video_id+'/0.jpg';
						$("#w2dc-attached-videos-wrapper").append(w2dc_video_attachment_tpl(video_id, image_url));

						w2dc_check_videos_attachments_number();
					} else if (matches_vimeo && (matches_vimeo[3].length == 8 || matches_vimeo[3].length == 9)) {
						var video_id = matches_vimeo[3];
						var url = "//vimeo.com/api/v2/video/" + video_id + ".json?callback=showVimeoThumb";
					    var script = document.createElement('script');
					    script.src = url;
					    $("#w2dc-attach-videos-functions").before(script);
					} else {
						alert(w2dc_media_metabox_attrs.videos_error_alert);
					}
				}
			};

			window.showVimeoThumb = function(data){
				var video_id = data[0].id;
			    var image_url = data[0].thumbnail_medium;
			    $("#w2dc-attached-videos-wrapper").append(w2dc_video_attachment_tpl(video_id, image_url));

			    w2dc_check_videos_attachments_number();
			};
		}
	}
	
	window.w2dc_my_location_buttons = function() {
		if (w2dc_maps_objects.enable_my_location_button) {
			$(".w2dc-get-location").attr("title", w2dc_maps_objects.my_location_button);
			$("body").on("click", ".w2dc-get-location", function() {
				if (!$(this).hasClass('w2dc-search-input-reset')) {
					var input = $(this).parent().find("input");
					w2dc_geocodeField(input, w2dc_maps_objects.my_location_button_error);
				} else {
					$(this).removeClass('w2dc-search-input-reset');
				}
			});
		}
	}
	
	window.w2dc_tokenizer = function() {
		function getUnique(value, index, self) { 
			return self.indexOf(value) === index;
		}
		
		var tokenizer = $(".w2dc-tokenizer").tokenize({
			onAddToken: function(value, text, e) {
				if (!w2dc_tags_metabox_attrs.unlimited_tags && tokenizer.toArray().filter(getUnique).length > w2dc_tags_metabox_attrs.tags_number) {
					tokenizer.tokenRemove(value);
					alert(w2dc_tags_metabox_attrs.tags_limit_message);
				}
			}
		});
	}

	window.w2dc_add_body_classes = function() {
		if ("ontouchstart" in document.documentElement)
			$("body").addClass("w2dc-touch");
		else
			$("body").addClass("w2dc-no-touch");
	}

	window.w2dc_listing_tabs = function() {
		var el = $('.w2dc-listing-tabs');
		var map = {};

		if (el.length) {
			$('.w2dc-listing-tabs li').each(function() { 
				var el = $(this);
				map[el.find('a').data('tab')] = el;
			});
	
			if (w2dc_js_objects.listing_tabs_order.length) {
				for (var i = 0, l = w2dc_js_objects.listing_tabs_order.length; i < l; i ++) {
					var tab = w2dc_js_objects.listing_tabs_order[i];
					
					if (map['#'+tab]) {
						el.append(map['#'+tab]);
					}
				}
				
				for (var i = 0, l = w2dc_js_objects.listing_tabs_order.length; i < l; i ++) {
					var tab = w2dc_js_objects.listing_tabs_order[i];
					
					if ($('#'+tab).length) {
						w2dc_show_tab($('.w2dc-listing-tabs a[data-tab="#'+tab+'"]'));
						break;
					}
				}
			} else {
				w2dc_show_tab($('.w2dc-listing-tabs a:first'));
			}
			
			$(document).on('click', '.w2dc-listing-tabs a', function(e) {	  
				e.preventDefault();
				w2dc_show_tab($(this));
				history.replaceState({}, "", $(this).data('tab'));
			});
			var hash = window.location.hash.substring(1);
			var searchParams = new URLSearchParams(window.location.search)
			if (hash == 'respond' || hash == 'comments' || searchParams.has('reviews_order_by') || hash.indexOf('comment-', 0) >= 0) {
				w2dc_show_tab($('.w2dc-listing-tabs a[data-tab="#comments-tab"]'));
			} else if (hash && $('.w2dc-listing-tabs a[data-tab="#'+hash+'"]').length) {
				w2dc_show_tab($('.w2dc-listing-tabs a[data-tab="#'+hash+'"]'));
			}
		}
	}
	// open reviews on click on reviews counter link
	$("a.w2rr-counter-reviews-link").on("click", function() {
		var anchor;
		if (anchor = $(this).attr("href").split("#").pop()) {
			if (anchor == "comments-tab" && $('.w2dc-listing-tabs a[data-tab="#'+anchor+'"]').length) {
				w2dc_show_tab($('.w2dc-listing-tabs a[data-tab="#'+anchor+'"]'));
			}
		}
	});
	window.w2dc_show_tab = function(tab) {
		$('.w2dc-listing-tabs li').removeClass('w2dc-active');
		tab.parent().addClass('w2dc-active');
		$('.w2dc-tab-content .w2dc-tab-pane').removeClass('w2dc-in w2dc-active');
		$('.w2dc-tab-content '+tab.data('tab')).addClass('w2dc-in w2dc-active');
		if (tab.data('tab') == '#addresses-tab') {
			w2dc_reload_maps();
		}
		tab.trigger("w2dc:show_tab");
	};
	window.w2dc_reload_maps = function() {
		for (var key in w2dc_maps) {
			if (typeof w2dc_maps[key] == 'object') {
				w2dc_reloadMap(key);
			}
		}
	};
	
	window.w2dc_radius_slider = function () {
		$('.w2dc-radius-slider').each(function() {
			var id = $(this).data("id");
			$('#radius_slider_'+id).slider({
				isRTL: w2dc_js_objects.is_rtl,
				min: parseInt(slider_params.min),
				max: parseInt(slider_params.max),
				range: "min",
				value: $("#radius_"+id).val(),
				slide: function(event, ui) {
					$("#radius_label_"+id).html(ui.value);
				},
				stop: function(event, ui) {
					$("#radius_"+id).val(ui.value);
					if (
						$("#radius_"+id).val() > 0 &&
						$(this).parents("form").find("input[name='address']").length &&
						$(this).parents("form").find("input[name='address']").val()
					) {
						$("#radius_"+id).trigger("change");
					}
				}
			});
		});
	}

	window.w2dc_hint = function () {
		$("a.w2dc-hint-icon").each(function() {
			$(this).w2dc_popover({
				trigger: "hover",
				//trigger: "manual",
				container: $(this).parents(".w2dc-content")
			});
		});
	}
	
	window.w2dc_favourites = function () {
		// Place listings to/from favourites list
		if ($(".add_to_favourites").length) {
			$('body').on('click', ".add_to_favourites", function() {
				var listing_id = $(this).attr("listingid");

				if ($.cookie("favourites") != null) {
					var favourites_array = $.cookie("favourites").split('*');
				} else {
					var favourites_array = new Array();
				}
				if (w2dc_in_array(listing_id, favourites_array) === false) {
					favourites_array.push(listing_id);
					$(this).find('span.w2dc-glyphicon').removeClass(w2dc_js_objects.not_in_favourites_icon).addClass(w2dc_js_objects.in_favourites_icon);
					$(this).find('span.w2dc-bookmark-button').text(w2dc_js_objects.not_in_favourites_msg);
				} else {
					for (var count=0; count<favourites_array.length; count++) {
						if (favourites_array[count] == listing_id) {
							delete favourites_array[count];
						}
					}
					$(this).find('span.w2dc-glyphicon').removeClass(w2dc_js_objects.in_favourites_icon).addClass(w2dc_js_objects.not_in_favourites_icon);
					$(this).find('span.w2dc-bookmark-button').text(w2dc_js_objects.in_favourites_msg);
				}
				$.cookie("favourites", favourites_array.join('*'), {expires: 365, path: "/"});
				return false;
			});
		}
	}
	
	window.w2dc_week_day_input = function () {
		// Set the same hours for all further selectboxes
		$('.w2dc-week-day-input-from-hour, .w2dc-week-day-input-to-hour, .w2dc-week-day-input-from-am-pm, .w2dc-week-day-input-to-am-pm').on('change', function() {
			var select_class = $(this).attr('class').replace('w2dc-week-day-input ', '');
			var index = $(this).index('.'+select_class);
			var val = $(this).val();
			
			$('.'+select_class).each(function(i, select) {
				if ($(this).index('.'+select_class) > index && !$(this).attr('disabled') && $(select).val() == "00:00") {
					$(this).val(val);
				}
			});
		});
	}
	
	window.w2dc_check_is_week_day_closed = function () {
		$('.closed_cb').each(function() {
			_w2dc_check_is_week_day_closed($(this));
		});
		$('body').on('click', '.closed_cb', function() {
			_w2dc_check_is_week_day_closed($(this));
		});
	}

	window._w2dc_check_is_week_day_closed = function (cb) {
		if (cb.is(":checked"))
			cb.parent().find(".w2dc-week-day-input").attr('disabled', 'disabled');
    	else
    		cb.parent().find(".w2dc-week-day-input").removeAttr('disabled');
	}
	
	if (!(/^((?!chrome|android).)*safari/i.test(navigator.userAgent))) {
		// refresh page on page back button (except safari)
		$(window).on('popstate', function() {
			//location.reload(true);
		});
	}
	
	window.w2dc_dashboard_tabs = function() {
		$('body').on('click', ".w2dc-dashboard-tabs.nav-tabs li", function(e) {
			window.location = $(this).find("a").attr("href");
		});
	}
	
	window.w2dc_sticky_scroll = function() {
		$('.w2dc-sticky-scroll').each(function() {
			var element = $(this);
			var id = element.data("id");
			var toppadding = (element.data("toppadding")) ? element.data("toppadding") : 0;
			var height = (element.data("height")) ? element.data("height") : null;
			
			if (toppadding == 0 && $("body").hasClass("admin-bar")) {
				toppadding = 32;
			}
			
			if ($('.site-header.header-fixed').length) {
				var headerHeight = $('.site-header.header-fixed').outerHeight();
				toppadding = toppadding + headerHeight;
			}

			if (!$("#w2dc-scroller-anchor-"+id).length) {
				var anchor = $("<div>", {
					id: 'w2dc-scroller-anchor-'+id
				});
				element.before(anchor);
	
				var background = $("<div>", {
					id: 'w2dc-sticky-scroll-background-'+id,
					style: {position: 'relative'}
				});
				element.after(background);
			}
				
			window["w2dc_sticky_scroll_toppadding_"+id] = toppadding;
	
			$("#w2dc-sticky-scroll-background-"+id).position().left = element.position().left;
			$("#w2dc-sticky-scroll-background-"+id).position().top = element.position().top;
			$("#w2dc-sticky-scroll-background-"+id).width(element.width());
			$("#w2dc-sticky-scroll-background-"+id).height(element.height());

			var w2dc_scroll_function = function(e) {
				var id = e.data.id;
				var toppadding = e.data.toppadding;
				var b = $(document).scrollTop();
				var d = $("#w2dc-scroller-anchor-"+id).offset().top - toppadding;
				var c = e.data.obj;
				var e = $("#w2dc-sticky-scroll-background-"+id);
				
				c.width(c.parent().width()).css({ 'z-index': 2 });
		
				// .w2dc-scroller-bottom - this is special class used to restrict the area of scroll of map canvas
				if ($(".w2dc-scroller-bottom").length) {
					var f = $(".w2dc-scroller-bottom").offset().top - (c.height() + toppadding);
				} else {
					var f = $(document).height();
				}
		
				if (f > c.height()) {
					if (b >= d && b < f) {
						c.css({ position: "fixed", top: toppadding });
						e.css({ position: "relative" });
					} else {
						if (b <= d) {
							c.stop().css({ position: "relative", top: "" });
							e.css({ position: "absolute" });
						}
						if (b >= f) {
							c.css({ position: "absolute" });
							c.stop().offset({ top: f + toppadding });
							e.css({ position: "relative" });
						}
					}
				} else {
					c.css({ position: "relative", top: "" });
					e.css({ position: "absolute" });
				}
			};
			if ($(document).width() >= 768) {
				var args = {id: id, obj: $(this), toppadding: toppadding};
				$(window).scroll(args, w2dc_scroll_function);
				w2dc_scroll_function({data: args});
			}

			$("#w2dc-sticky-scroll-background-"+id).css({ position: "relative" });
		});
	}
	
	window.w2dc_full_height_maps = function() {
		$('.w2dc-map-canvas-wrapper').each(function() {
			var element = $(this);
			var height = (element.data("height")) ? element.data("height") : null;
			
			if (height == '100%') {
				var toppadding = (element.data("toppadding")) ? element.data("toppadding") : 0;
				
				if (toppadding == 0 && $("body").hasClass("admin-bar")) {
					toppadding = 32;
				}
				
				if ($('.site-header.header-fixed').length) {
					var headerHeight = $('.site-header.header-fixed').outerHeight();
					toppadding = toppadding + headerHeight;
				}

				element.height(function(index, height) {
					return window.innerHeight - toppadding;
				});
				$(window).resize(function(){
					element.height(function(index, height) {
						return window.innerHeight - toppadding;
					});
				});
			}
		});
	}
	
	window.w2dc_tooltips = function() {
		$('[data-toggle="w2dc-tooltip"]').w2dc_tooltip({
			 trigger : 'hover'
		});
	}
	
	window.w2dc_ratings = function() {
		$('body').on('click', '.w2dc-rating-active .w2dc-rating-icon', function() {
			var rating = $(this).parent(".w2dc-rating-stars");
			var rating_wrapper = $(this).parents(".w2dc-rating");
			
			if (!rating.hasClass('w2dc-rating-active-noajax')) {
				rating_wrapper.fadeTo(2000, 0.3);
				
				$.ajax({
		        	url: w2dc_js_objects.ajaxurl,
		        	type: "POST",
		        	dataType: "json",
		            data: {
		            	action: 'w2dc_save_rating',
		            	rating: $(this).data("rating"),
		            	post_id: rating.data("listing"),
		            	_wpnonce: rating.data("nonce")
		            },
		            rating_wrapper: rating_wrapper,
		            success: function(response_from_the_action_function){
		            	if (response_from_the_action_function != 0 && response_from_the_action_function.html) {
		            		this.rating_wrapper
		            		.replaceWith(response_from_the_action_function.html)
		            		.fadeIn("fast");
		            	}
		            }
		        });
			} else {
				var rating_value = $(this).data("rating");
				rating.find('.w2dc-rating-noajax-value').val(rating_value);
				rating.find('.w2dc-rating-icon').each(function() {
					$(this).removeClass('w2dc-fa-star w2dc-fa-star-o')
					if ($(this).data("rating") <= rating_value) {
						$(this).addClass('w2dc-fa-star');
					} else {
						$(this).addClass('w2dc-fa-star-o');
					}
				});
			}
		});
	}

	window.w2dc_hours_content_field = function() {
		function close_option(option) {
			if (option.is(":checked")) {
				option.parents(".w2dc-week-day-wrap").find("select").attr("disabled", "disabled");
			} else {
				option.parents(".w2dc-week-day-wrap").find("select").removeAttr("disabled");
			}
		}
		$(".w2dc-closed-day-option").each(function() {
			close_option($(this));
		});
		$("body").on("change", ".w2dc-closed-day-option", function() {
			close_option($(this));
		});
		
		$("body").on("click", ".w2dc-clear-hours", function() {
			$(this).parents(".w2dc-field-input-block").find("select").each( function() { $(this).val($(this).find("option:first").val()).removeAttr('disabled'); });
			$(this).parents(".w2dc-field-input-block").find('input[type="checkbox"]').each( function() { $(this).prop("checked", false); });
			return false;
		});
	}

	window.w2dc_custom_input_controls = function() {
		// Custom input controls
		$(".w2dc-checkbox label, .w2dc-radio label").each(function() {
			if (!$(this).find(".w2dc-control-indicator").length) {
				$(this).append($("<div>").addClass("w2dc-control-indicator"));
			}
		});
	}
	$(document).ajaxComplete(function(event, xhr, settings) {
		if (settings.url === w2dc_js_objects.ajaxurl) {
			w2dc_custom_input_controls();
		}
	});

	window.w2dc_get_rid_of_select2_choosen = function() {
		$("select.w2dc-form-control, select.vp-input, select.w2dc-week-day-input, select.w2dc-tokenizer").each(function (i, obj) {
			// get rid of select2
			if ($(obj).hasClass('select2-hidden-accessible') || $('#s2id_' + $(obj).attr('id')).length) {
				$(obj).select2('destroy');
			}
			// get rid of chosen
			if ($('#' + $(obj).attr('id') + '_chosen').length) {
				$(obj).chosen('destroy');
			}
		});
	}

	window.w2dc_equalColumnsHeightEvent = function() {
		$(window).on('orientationchange resize', w2dc_equalColumnsHeight);
	}
		
	window.w2dc_equalColumnsHeight = function() {
		setTimeout(function(){
			$(".w2dc-listings-grid .w2dc-listing, .w2dc-mobile-listings-grid-2 .w2dc-listing").css('height', '');

			var currentTallest = 0;
			var currentRowStart = 0;
			var rowDivs = new Array();
			var $el;
			var topPosition = 0;
			$(".w2dc-listings-grid .w2dc-listing, .w2dc-mobile-listings-grid-2 .w2dc-listing").each(function() {
				$el = $(this);
				if ($(document).width() >= 768 && !$el.hasClass("w2dc-mobile-listings-grid-1")) {
					var topPostion = $el.position().top;
					if (currentRowStart != topPostion) {
						for (var currentDiv = 0 ; currentDiv < rowDivs.length ; currentDiv++) {
							rowDivs[currentDiv].height(currentTallest);
						}
						rowDivs.length = 0;
						currentRowStart = topPostion;
						currentTallest = $el.height();
						rowDivs.push($el);
					} else {
						rowDivs.push($el);
						currentTallest = (currentTallest < $el.height()) ? ($el.height()) : (currentTallest);
					}
					for (var currentDiv = 0 ; currentDiv < rowDivs.length ; currentDiv++) {
						rowDivs[currentDiv].height(currentTallest);
					}
				}
			});
		}, 500);
	}
	
	window.w2dc_isSidebarOpen = function(map_id) {
		return ($("#w2dc-map-wrapper-"+map_id).length && $("#w2dc-map-wrapper-"+map_id).hasClass("w2dc-map-sidebar-open"));
	}
	
	$.fn.swipeDetector = function (options) {
		// States: 0 - no swipe, 1 - swipe started, 2 - swipe released
		var swipeState = 0;
		// Coordinates when swipe started
		var startX = 0;
		var startY = 0;
		// Distance of swipe
		var pixelOffsetX = 0;
		var pixelOffsetY = 0;
		// Target element which should detect swipes.
		var swipeTarget = this;
		var defaultSettings = {
				// Amount of pixels, when swipe don't count.
				swipeThreshold: 70,
				// Flag that indicates that plugin should react only on touch events.
				// Not on mouse events too.
				useOnlyTouch: false
		};

		// Initializer
		(function init() {
			options = $.extend(defaultSettings, options);
			// Support touch and mouse as well.
			swipeTarget.on('mousedown touchstart', swipeStart);
			$('html').on('mouseup touchend', swipeEnd);
			$('html').on('mousemove touchmove', swiping);
		})();

		function swipeStart(event) {
			if (options.useOnlyTouch && !event.originalEvent.touches)
				return;

			if (event.originalEvent.touches)
				event = event.originalEvent.touches[0];

			if (swipeState === 0) {
				swipeState = 1;
				startX = event.clientX;
				startY = event.clientY;
			}
		}

		function swipeEnd(event) {
			if (swipeState === 2) {
				swipeState = 0;

				if (Math.abs(pixelOffsetX) > Math.abs(pixelOffsetY) &&
						Math.abs(pixelOffsetX) > options.swipeThreshold) { // Horizontal Swipe
					if (pixelOffsetX < 0) {
						swipeTarget.trigger($.Event('swipeLeft.sd'));
					} else {
						swipeTarget.trigger($.Event('swipeRight.sd'));
					}
				} else if (Math.abs(pixelOffsetY) > options.swipeThreshold) { // Vertical swipe
					if (pixelOffsetY < 0) {
						swipeTarget.trigger($.Event('swipeUp.sd'));
					} else {
						swipeTarget.trigger($.Event('swipeDown.sd'));
					}
				}
			}
		}

		function swiping(event) {
			// If swipe don't occuring, do nothing.
			if (swipeState !== 1) 
				return;

			if (event.originalEvent.touches) {
				event = event.originalEvent.touches[0];
			}

			var swipeOffsetX = event.clientX - startX;
			var swipeOffsetY = event.clientY - startY;

			if ((Math.abs(swipeOffsetX) > options.swipeThreshold) ||
					(Math.abs(swipeOffsetY) > options.swipeThreshold)) {
				swipeState = 2;
				pixelOffsetX = swipeOffsetX;
				pixelOffsetY = swipeOffsetY;
			}
		}

		return swipeTarget; // Return element available for chaining.
	}

	var w2dc_animation_finished = true;
	window.w2dc_listings_carousel = function() {

		$(".w2dc-listings-carousel-wrapper").each(function() {
			var id = $(this).data("controller-hash");
			var currentTallest = 0;
			$(this).find("article.w2dc-listing").each(function() {
				currentTallest = (currentTallest < $(this).height()) ? ($(this).height()) : (currentTallest);
			});
			$(this).height(currentTallest);
			
			var content = $("#w2dc-controller-"+id+" .w2dc-listings-block-content");
			var carousel = $("#w2dc-controller-"+id+" .w2dc-listings-carousel");
			var button_prev = $("#w2dc-controller-"+id+" .w2dc-listings-carousel-button-left");
			var button_next = $("#w2dc-controller-"+id+" .w2dc-listings-carousel-button-right");
			var slide_width = content.find("article.w2dc-listing").outerWidth(true);

			button_prev.on("click", function() {
				w2dc_prev_slide(content, slide_width);
			});
			
			button_next.on("click", function() {
				w2dc_next_slide(content, slide_width);
			});
			
			carousel.on("mousewheel", function(event, delta, deltaX, deltaY) {
				
				event.stopPropagation();
				event.preventDefault();
				
				if (delta > 0) {
					w2dc_prev_slide(content, slide_width);
				}
				if (deltaY < 0) {
					w2dc_next_slide(content, slide_width);
				}
			});
				
			$("#w2dc-controller-"+id+" .w2dc-listings-carousel")
			.swipeDetector({ swipeThreshold: 30 })
			.on("swipeRight.sd", function() {
				w2dc_prev_slide(content, slide_width);
			})
			.on("swipeLeft.sd", function() {
				w2dc_next_slide(content, slide_width);
			});
		});
	}
	window.w2dc_prev_slide = function(content, slide_width) {
		if (w2dc_animation_finished) {
			var listing = content.find("article.w2dc-listing:last");
			content
			.css({ "margin-left": -slide_width })
			.prepend(listing.clone());
			
			w2dc_animation_finished = false;
			content.animate({
				"margin-left": 0
			}, 300, function () { 
				listing.remove();
				w2dc_animation_finished = true;
			});
		}
	}
	window.w2dc_next_slide = function(content, slide_width) {
		if (w2dc_animation_finished) {
			var listing = content.find("article.w2dc-listing:first");
			content.append(listing.clone());
			
			w2dc_animation_finished = false;
			content.animate({
				"margin-left": -slide_width
			}, 300, function () { 
				listing.remove();
				content.css({ "margin-left": 0 })
				w2dc_animation_finished = true;
			});
		}
	}
	
	// AJAX Comments scripts
	window.w2dc_comments_ajax_load_template = function(params, my_global) {
        var my_global;
        var request_in_process = false;

        params.action = "w2dc_comments_load_template";

        $.ajax({
        	url: w2dc_js_objects.ajaxurl,
        	type: "POST",
        	dataType: "html",
            data: params,
            global: my_global,
            success: function( msg ){
                $(params.target_div).fadeIn().html(msg);
                request_in_process = false;
                if (typeof params.callback === "function") {
                    params.callback();
                }
            }
        });
    }
    $(document).on('submit', '#w2dc_default_add_comment_form', function(e) {
       e.preventDefault();

       var $this = $(this);
       $this.css('opacity', '0.5');

       var data = {
           action: "w2dc_comments_add_comment",
           post_id: $('#w2dc_comments_ajax_handle').data('post_id'),
           user_name: $('#w2dc_comments_user_name').val(),
           user_email: $('#w2dc_comments_user_email').val(),
           user_url: $('#w2dc_comments_user_url').val(),
           comment: $('#comment').val(),
           comment_parent: $('#comment_parent').val(),
           security: $('#w2dc_comments_nonce').val()
       };

       $.ajax({
        	url: w2dc_js_objects.ajaxurl,
        	type: "POST",
        	dataType: "html",
            data: data,
            global: false,
            success: function( msg ){
                w2dc_comments_ajax_load_template({
                    "target_div": "#w2dc_comments_ajax_target",
                    "template": $('#w2dc_comments_ajax_handle').attr('data-template'),
                    "post_id": $('#w2dc_comments_ajax_handle').attr('data-post_id'),
                    "security": $('#w2dc_comments_nonce').val()
                }, false );
                $('textarea').val('');
                $this.css('opacity', '1');
            }
        });
    });
    $(document).on('keypress', '#w2dc_default_add_comment_form textarea, #w2dc_default_add_comment_form input', function(e) {
        if (e.keyCode == '13') {
            e.preventDefault();
            $('#w2dc_default_add_comment_form').submit();
        }
    });
    window.w2dc_load_comments = function() {
        if ($('#w2dc_comments_ajax_handle').length) {

            var data = {
                "action": "w2dc_comments_load_template",
                "target_div": "#w2dc_comments_ajax_target",
                "template": $('#w2dc_comments_ajax_handle').data('template'),
                "post_id": $('#w2dc_comments_ajax_handle').data('post_id'),
                "security": $('#w2dc_comments_nonce').val()
            };

            $.ajax({
            	url: w2dc_js_objects.ajaxurl,
            	type: "POST",
            	dataType: "html",
                data: data,
                success: function(msg){
                    $("#w2dc_comments_ajax_target").fadeIn().html(msg); // Give a smooth fade in effect
                    if (window.location.hash && $(window.location.hash).length){
                        $('html, body').animate({
                            scrollTop: $(window.location.hash).offset().top
                        });
                        $(window.location.hash).addClass('w2dc-comments-highlight');
                    }
                }
            });

            $(document).on('click', '.w2dc-comments-time-handle', function(e) {
                $('.w2dc-comments-content').removeClass('w2dc-comments-highlight')
                comment_id = '#comment-' + $(this).attr('data-comment_id');
                $(comment_id).addClass('w2dc-comments-highlight');
            });
        }
    };
    $(document).on('click', '#w2dc_cancel_reply', function(e) {
    	$('#comment_parent').val(0);
    	$('#w2dc-comments-leave-comment-label').html(w2dc_js_objects.leave_comment);
    });
    $(document).on('click', '.w2dc-comment-reply', function(e) {
    	var comment_id = $(this).data("comment-id");
    	var comment_author = $(this).data("comment-author");
    	$('#comment_parent').val(comment_id);
    	$('#w2dc-comments-leave-comment-label').html(w2dc_js_objects.leave_reply+" "+comment_author+". <a id='w2dc_cancel_reply' href='javascript: void(0);'>"+w2dc_js_objects.cancel_reply+"</a>");
    });
    $(document).on('click', '.w2dc-comments-more-handle', function(e) {
        e.preventDefault();
        if ($(this).hasClass('w2dc-comments-more-open')) {
            $('a', this).html(w2dc_js_objects.more);
            $('#comment').css('height', '0');
        } else {
            $('a', this).html(w2dc_js_objects.less);
            $('#comment').css('height', '150');
        }
        $(this).toggleClass('w2dc-comments-more-open');
        $('.w2dc-comments-more-container').toggle();
    });
    
    window.w2dc_content_fields_metabox = function() {
    	hideShowFields_init();
    	
		$("input[name='tax_input\\[w2dc-category\\]\\[\\]']").change(function() { hideShowFields_onclick($(this)) });
		$("#w2dc-category-pop input[type=checkbox]").change(function() { hideShowFields_onclick($(this)) });

		function hideShowFields_init() {
			var selected_categories_ids = [];
			$.each($("input[name='tax_input\\[w2dc-category\\]\\[\\]']:checked"), function() {
				selected_categories_ids.push($(this).val());
			});

			$(".w2dc-content-fields-metabox").show();
			$(".w2dc-field-input-block").hide();
			$.each(w2dc_js_objects.fields_in_categories, function(index, value) {
				var show_field = false;
				if (value != undefined) {
					if (value.length > 0) {
						var key;
						for (key in value) {
							var key2;
							for (key2 in selected_categories_ids) {
								if (value[key] == selected_categories_ids[key2]) {
									show_field = true;
								}
							}
						}
					}

					if ((value.length == 0 || show_field) && $(".w2dc-field-input-block-"+index).length) {
						$(".w2dc-field-input-block-"+index).show();
					}
				}
			});
			$.each($(".w2dc-content-fields-metabox"), function() {
				if ($(this).find(".w2dc-field-input-block").filter(function() { return $(this).css("display") != "none"; }).length) {
					$(this).show();
				} else {
					$(this).hide();
				}
			});
		}
		
		function hideShowFields_onclick(input) {
			var checked = input.prop('checked');
			var id = input.val();
			
			var fields_to_apply = [];
			$.each(w2dc_js_objects.fields_in_categories, function(index, value) {
				if (value != undefined) {
					if (value.length > 0) {
						var key;
						for (key in value) {
							if (value[key] == id) {
								fields_to_apply.push(index);
							}
						}
					}
				}
			});
			
			for (var key in fields_to_apply) {
				var index = fields_to_apply[key];
				if (checked) {
					$(".w2dc-field-input-block-"+index).parents(".w2dc-content-fields-metabox").slideDown(500);
					$(".w2dc-field-input-block-"+index).slideDown(500);
				} else {
					$(".w2dc-field-input-block-"+index).slideUp(300, function() {
						var metabox = $(this).parents(".w2dc-content-fields-metabox");
						if (!metabox.find(".w2dc-field-input-block:visible").length) {
							metabox.slideUp(500);
						}
					});
				}
			}
		}
    };
	
	window.w2dc_scroll_to_anchor = function(scroll_to_anchor, offest_top) {
		if (typeof scroll_to_anchor != 'undefined' && scroll_to_anchor) {
			if (typeof offest_top == 'undefined' || !offest_top) {
				var offest_top = 0;
			}
			$('html,body').animate({scrollTop: scroll_to_anchor.offset().top - offest_top}, 'slow');
		}
	}
	
	window.w2dc_ajax_loader_target_show = function(target, scroll_to_anchor, offest_top) {
		if (typeof scroll_to_anchor != 'undefined' && scroll_to_anchor) {
			if (typeof offest_top == 'undefined' || !offest_top) {
				var offest_top = 0;
			}
			$('html,body').animate({scrollTop: scroll_to_anchor.offset().top - offest_top}, 'slow');
		}
		var id = target.attr("id");
		if (!$("[data-loader-id='"+id+"']").length) {
			var loader = $('<div data-loader-id="'+id+'" class="w2dc-ajax-target-loading"><div class="w2dc-loader"></div></div>');
			target.prepend(loader);
			loader.css({
				width: target.outerWidth()+10,
				height: target.outerHeight()+10
			});
			if (target.outerHeight() > 600) {
				loader.find(".w2dc-loader").addClass("w2dc-loader-max-top");
			}
		}
	}
	window.w2dc_ajax_loader_target_hide = function(id) {
		$("[data-loader-id='"+id+"']").remove();
	}
	
	window.w2dc_ajax_loader_show = function(msg) {
		var overlay = $('<div id="w2dc-ajax-loader-overlay"><div class="w2dc-loader"></div></div>');
	    $('body').append(overlay);
	}
	
	window.w2dc_ajax_loader_hide = function() {
		$("#w2dc-ajax-loader-overlay").remove();
	}

	window.w2dc_get_controller_args_array = function(hash) {
		if (typeof w2dc_controller_args_array != 'undefined' && Object.keys(w2dc_controller_args_array)) {
			for (var controller_hash in w2dc_controller_args_array) {
				if (controller_hash == hash) {
					return w2dc_controller_args_array[controller_hash];
				}
			}
		}
	}

	window.w2dc_get_map_markers_attrs_array = function(hash) {
		if (typeof w2dc_map_markers_attrs_array != 'undefined' && Object.keys(w2dc_map_markers_attrs_array)) {
			for (var i=0; i<w2dc_map_markers_attrs_array.length; i++) {
				if (hash == w2dc_map_markers_attrs_array[i].map_id) {
					return w2dc_map_markers_attrs_array[i];
				}
			}
		}
	}

	window.w2dc_get_original_map_markers_attrs_array = function(hash) {
		if (typeof _w2dc_map_markers_attrs_array != 'undefined' && Object.keys(_w2dc_map_markers_attrs_array)) {
			for (var i=0; i<_w2dc_map_markers_attrs_array.length; i++) {
				if (hash == _w2dc_map_markers_attrs_array[i].map_id) {
					return _w2dc_map_markers_attrs_array[i];
				}
			}
		}
	}
	
	window.w2dc_map_sidebar_scrollto = function(map_id, location_id) {
		if ($('#w2dc-map-listings-panel-'+map_id).length) {
			
			if ($('#w2dc-map-sidebar-'+map_id).hasClass('w2dc-map-sidebar-fixed')) {
				var sidebar_listings = $('#w2dc-map-sidebar-listings-wrapper-'+map_id);
			} else {
				var sidebar_listings = $('#w2dc-map-sidebar-'+map_id);
			}
			
			if (sidebar_listings.find('#post-'+location_id).length) {
				sidebar_listings.scrollTop(
						sidebar_listings.scrollTop()
						+
						sidebar_listings.find('#post-'+location_id).offset().top
						-
						sidebar_listings.offset().top
				);
			}
		}
	}
	
	window.w2dc_process_listings_ajax_response = function(response_from_the_action_function, do_replace, remove_shapes, do_replace_markers) {
		var response_hash = response_from_the_action_function.hash;
		if (response_from_the_action_function) {
			var listings_block = $('#w2dc-controller-'+response_hash);
			if (do_replace) {
				listings_block.replaceWith(response_from_the_action_function.html);
			} else {
				listings_block.find(".w2dc-listings-block-content").append(response_from_the_action_function.html);
			}
			
			w2dc_listings_carousel();
			
			if (response_from_the_action_function.map_markers && typeof w2dc_maps[response_hash] != 'undefined') {
				if (do_replace) {
					w2dc_clearMarkers(response_hash);
				}
				if (remove_shapes) {
					w2dc_removeShapes(response_hash);
					w2dc_removeCircles(response_hash);
				}
				w2dc_closeInfoWindow(response_hash);
				
				var markers_array = response_from_the_action_function.map_markers;
				
				var enable_radius_circle = 0;
				var enable_clusters = 0;
				var show_summary_button = 1;
				var show_readmore_button = 1;
				var is_ajax_markers = 0;
				var attrs_array;
				if (attrs_array = w2dc_get_map_markers_attrs_array(response_hash)) {
					var enable_radius_circle = attrs_array.enable_radius_circle;
					var enable_clusters = attrs_array.enable_clusters;
					var show_summary_button = attrs_array.show_summary_button;
					var show_readmore_button = attrs_array.show_readmore_button;
					var map_attrs = attrs_array.map_attrs;
					var is_ajax_markers = attrs_array.map_attrs.ajax_markers_loading;

					if (do_replace_markers) {
						attrs_array.markers_array = eval(response_from_the_action_function.map_markers);
					}
				}
				
				var map_id = response_hash;
				var existing_locations = [];
				if (typeof w2dc_global_locations_array[map_id] != 'undefined') {
					for (var i=0; i<w2dc_global_locations_array[map_id].length; i++) {
						if (typeof w2dc_global_locations_array[map_id][i] == 'object') {
							existing_locations.push(w2dc_global_locations_array[map_id][i].id);
						}
					}
				}

		    	for (var j=0; j<markers_array.length; j++) {
		    		if (!existing_locations.includes(markers_array[j][0])) {
		    			var map_coords_1 = markers_array[j][1];
				    	var map_coords_2 = markers_array[j][2];
				    	if ($.isNumeric(map_coords_1) && $.isNumeric(map_coords_2)) {
			    			var point = w2dc_buildPoint(map_coords_1, map_coords_2);
	
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
			    				response_hash,
			    				is_ajax_markers
				    		);
				    		var marker = location_obj.w2dc_placeMarker(response_hash);
				    		w2dc_global_locations_array[response_hash].push(location_obj);
				    	}
		    		}
	    		}
		    	
		    	// fit bounds only when no AJAX map
		    	if (typeof attrs_array.map_attrs.ajax_map_loading == 'undefined' || attrs_array.map_attrs.ajax_map_loading == 0) {
		    		if (w2dc_global_markers_array[response_hash].length) {
			    		var bounds = w2dc_buildBounds();
			    		for (var j=0; j<w2dc_global_markers_array[response_hash].length; j++) {
			    			var marker = w2dc_global_markers_array[response_hash][j];
			    			var marker_position = w2dc_getMarkerPosition(marker);
			    			w2dc_extendBounds(bounds, marker_position);
			    		}
			    		w2dc_mapFitBounds(response_hash, bounds);
	
			    		if (w2dc_global_markers_array[response_hash].length == 1) {
			    			w2dc_setMapZoom(response_hash, ZOOM_FOR_SINGLE_MARKER);
			    		}
		    		}
		    	}

	    		w2dc_setClusters(enable_clusters, response_hash, w2dc_global_markers_array[response_hash]);

	    		w2dc_removeCircles(response_hash);
			    if (enable_radius_circle && typeof response_from_the_action_function.radius_params != 'undefined') {
			    	var radius_params = response_from_the_action_function.radius_params;
			    	
			    	// PanTo only on AJAX Map
			    	if (w2dc_hasChangedGeocodedCoordinates(radius_params, response_hash)) {
						var map_coords_1 = radius_params.map_coords_1;
						var map_coords_2 = radius_params.map_coords_2;
						
						w2dc_panTo(response_hash, map_coords_1, map_coords_2);
					}
					
					w2dc_saveGeocodedCoordinates(radius_params, response_hash);
			    	
					w2dc_drawRadius(radius_params, response_hash);
				}
			}
			if (typeof response_from_the_action_function.map_listings != 'undefined' && typeof w2dc_maps[response_hash] != 'undefined') {
				var map_listings_block = $('#w2dc-map-listings-panel-'+response_hash);
		    	if (map_listings_block.length) {
		    		if (do_replace) {
		    			map_listings_block.html(response_from_the_action_function.map_listings);
		    		} else {
		    			map_listings_block.append(response_from_the_action_function.map_listings);
		    		}
		    	}
			}
		}
		w2dc_equalColumnsHeight();
		if (w2dc_js_objects.is_maps_used) {
			w2dc_show_on_map_links();
		}
		w2dc_sticky_scroll();
	}

	window.w2dc_load_ajax_initial_elements = function() {
		// We have to wait while Google Maps API will be completely loaded
		if (typeof w2dc_controller_args_array != 'undefined' && Object.keys(w2dc_controller_args_array)) {
			for (var controller_hash in w2dc_controller_args_array) {
				
				var post_params = { hash: controller_hash, from_set_ajax: 1 };
				post_params = w2dc_collectAJAXParams(post_params);
				post_params.ajax_action = 'ajax_initial_load';
				
				// ajax_map_loading=1 means that a map follows listings controller
				if (
						!(typeof post_params.ajax_map_loading != 'undefined' && post_params.ajax_map_loading == 1) &&
						(typeof post_params.ajax_initial_load != 'undefined' && post_params.ajax_initial_load == 1)
				) {
					post_params.ajax_initial_load = 0;
	
					$.post(
						w2dc_js_objects.ajaxurl,
						post_params,
						function(response_from_the_action_function) {
							w2dc_process_listings_ajax_response(response_from_the_action_function, true, true, true);
							
							var response_hash = response_from_the_action_function.hash;
							if (response_from_the_action_function.map_markers && typeof w2dc_maps[response_hash] != 'undefined') {
								if (typeof _w2dc_map_markers_attrs_array != 'undefined' && _w2dc_map_markers_attrs_array.length) {
									for (var i=0; i<_w2dc_map_markers_attrs_array.length; i++) {
										if (response_hash == _w2dc_map_markers_attrs_array[i].map_id) {
											_w2dc_map_markers_attrs_array[i].markers_array = eval(response_from_the_action_function.map_markers);
										}
									}
								}
							}
						},
						'json'
					);
				}
			}
		}
	}
	
	window.w2dc_ajax_iloader = $("<div>", { class: 'w2dc-ajax-iloader' }).html('<div class="rect1"></div><div class="rect2"></div><div class="rect3"></div><div class="rect4"></div><div class="rect5"></div>');
	window.w2dc_add_iloader_on_element = function(button) {
		button
		.attr('disabled', 'disabled')
		.wrapInner('<div class="w2dc-hidden"></div>')
		.append(w2dc_ajax_iloader);
	}
	window.w2dc_delete_iloader_from_element = function(button) {
		button.find(".w2dc-hidden").contents().unwrap();
		button.removeAttr('disabled').find(".w2dc-ajax-iloader").remove();
	}
	
	var w2dc_show_more_button_processing = false;
	$(window).scroll(function() {
		$('.w2dc-show-more-button.w2dc-scrolling-paginator:visible').each(function() {
			if ($(window).scrollTop() + $(window).height() > $(this).position().top) {
				if (!w2dc_show_more_button_processing) {
					w2dc_callShowMoreListings($(this));
				}
			}
		});
	});
	$('body').on('click', '.w2dc-show-more-button', function(e) {
		e.preventDefault();
		w2dc_callShowMoreListings($(this));
	});
	var w2dc_callShowMoreListings = function(button) {
		
		if (button.data("controller-hash")) {
			
			w2dc_add_iloader_on_element(button);
			
			var controller_hash = button.data("controller-hash");
			var post_params = w2dc_collectAJAXParams({ hash: controller_hash });
			post_params.ajax_action = 'show_more';
			
			if (typeof post_params.paged != 'undefined') {
				var paged = parseInt(post_params.paged)+1;
			} else {
				var paged = 2;
			}
			post_params.paged = paged;
			post_params.page = paged;
			post_params.do_append = 1;
			
			w2dc_show_more_button_processing = true;
			$.post(
				w2dc_js_objects.ajaxurl,
				post_params,
				w2dc_completeAJAXShowMore(button),
				'json'
			);
		}
	}
	var w2dc_completeAJAXShowMore = function(button) {
		return function(response_from_the_action_function) {
			var controller_hash = response_from_the_action_function.hash;
			
			w2dc_process_listings_ajax_response(response_from_the_action_function, false, false, false);
			
			if (typeof w2dc_controller_args_array[controller_hash].paged != 'undefined') {
				var paged = parseInt(w2dc_controller_args_array[controller_hash].paged)+1;
			} else {
				var paged = 2;
			}
			w2dc_controller_args_array[controller_hash].paged = paged;
			
			w2dc_show_more_button_processing = false;
			w2dc_delete_iloader_from_element(button);
			if (response_from_the_action_function.hide_show_more_listings_button) {
				button.hide();
			}
		}
	}
	
	window.w2dc_collectAJAXParams = function(post_params) {
		
		post_params.action = "w2dc_controller_request";
		
		var controller_hash = false;
		if (post_params.hash) {
			controller_hash = post_params.hash;
		} else {
			if ($(".w2dc-controller").length) {
				post_params.hash = $(".w2dc-controller").data("controller-hash");
				controller_hash = post_params.hash;
			} else {
				return post_params;
			}
		}
		
		w2dc_checkGeocodedCoordinates(controller_hash);
		
		// collect needed params from map FIRST OF ALL, then from listings, listings params can overwrite map's params
		var map_args_array;
		if (map_args_array = w2dc_get_map_markers_attrs_array(controller_hash)) {
			
			post_params = $.extend({}, post_params, map_args_array);
			post_params = $.extend({}, post_params, map_args_array.map_attrs);
			
			delete post_params.markers_array;
			delete post_params.map_attrs;
			
			post_params.with_map = 1;
			
			if (typeof map_args_array.map_attrs.ajax_map_loading != 'undefined' && map_args_array.map_attrs.ajax_map_loading == 1) {
				if (typeof post_params.from_set_ajax == 'undefined' || post_params.from_set_ajax == 0) {
					w2dc_setAjaxMarkers(w2dc_maps[controller_hash], controller_hash);
					
					// do not collect post params from listings controller
					//return post_params;
				}
			}
			
			if ($("#w2dc-map-listings-panel-"+controller_hash).length) {
				post_params.map_listings = 1;
			}
		}
		
		if ($("#w2dc-controller-"+controller_hash).length) {
			// collect needed params from listing block
			var listings_args_array;
			if (listings_args_array = w2dc_get_controller_args_array(controller_hash)) {
				post_params = $.extend({}, post_params, listings_args_array);
				
				var existing_listings = "";
				$("#w2dc-controller-"+controller_hash+" .w2dc-listings-block-content article[id^='post-']").each(function(index) {
					existing_listings = $(this).attr("id").replace("post-", "") + "," + existing_listings;
				});
				post_params.existing_listings = existing_listings;
			}
		} else {
			post_params.without_listings = 1;
		}
		
		// query string from wcsearch
		if (typeof wcsearch_query_string != "undefined") {
			post_params.query_string = wcsearch_query_string;
		}
		
		return post_params;
	}
	
	window.w2dc_callAJAXSearch = function(post_params) {
		post_params.from_set_ajax = 1;
		post_params = w2dc_collectAJAXParams(post_params);
		post_params.ajax_action = 'search';
		
		// set to first page after collection
		post_params.paged = 1;
		// clear existing listings, requires at random
		post_params.existing_listings = "";
		
		w2dc_startAJAXSearch(post_params);
	}
	
	window.w2dc_sendGeoPolyAJAX = function(map_id, geo_poly_ajax) {
		
		var post_params = { hash: map_id };
		post_params = w2dc_collectAJAXParams(post_params);
		post_params.geo_poly = geo_poly_ajax;
		// set to first page after collection
		post_params.paged = 1;
		post_params.ajax_action = 'geo_poly';
		
		// clear existing listings, requires at random
		post_params.existing_listings = "";
		
		$.post(
				w2dc_js_objects.ajaxurl,
				post_params,
				function(response_from_the_action_function) {
					w2dc_process_listings_ajax_response(response_from_the_action_function, true, false, false);
				},
				'json'
			);
	}
		
	var w2dc_search_requests_counter = 0;
	var w2dc_startAJAXSearch = function(post_params) {
		w2dc_search_requests_counter++;
		$.post(
				w2dc_js_objects.ajaxurl,
				post_params,
				w2dc_completeAJAXSearch(post_params),
				'json'
		);
	}
	
	var wcsearch_recount_attempts = 0;
	var wcsearch_max_counters = 200;
	var w2dc_completeAJAXSearch = function(post_params) {
		return function(response_from_the_action_function) {
			w2dc_search_requests_counter--;
			if (w2dc_search_requests_counter == 0) {
				
				if (typeof post_params.geo_poly != 'undefined' && post_params.geo_poly) {
					var remove_shapes = false;
				} else {
					var remove_shapes = true;
				}
				
				w2dc_process_listings_ajax_response(response_from_the_action_function, true, remove_shapes, true);
				
				var wcsearch_request_processing = false;
				
				// paginator clicked - do not need to recount
				var page = wcsearch_get_query_string_param('page');
				if (!page) {
					wcsearch_recount_attempts = 0;
					wcsearch_recount();
				}
			}
		}
	}
	
	if (w2dc_js_objects.ajax_load) {

		$('body').on('click', '.w2dc-listings-orderby-link', function(e) {
			e.preventDefault();
			
			var href = $(this).attr('href');
			window.history.pushState("", "", href);
			
			var controller_hash = $(this).data('controller-hash');
			var order_by = $(this).data('orderby');
			var order = $(this).data('order');
			
			wcsearch_extend_query_string_params({ 'order_by': order_by, 'order': order });
			
			var post_params = w2dc_collectAJAXParams({ hash: controller_hash });
			post_params.order_by = order_by;
			post_params.order = order;
			post_params.paged = 1;
			post_params.ajax_action = 'order';
			
			$.post(
					w2dc_js_objects.ajaxurl,
					post_params,
					function(response_from_the_action_function) {
						w2dc_process_listings_ajax_response(response_from_the_action_function, true, false, true);
					},
					'json'
			);
		});

		$('body').on('click', '.w2dc-pagination li.w2dc-active a', function(e) {
			e.preventDefault();
		});
		$('body').on('click', '.w2dc-listings-block .w2dc-pagination li a', function(e) {
			if ($(this).data('controller-hash')) {
				e.preventDefault();
				
				var href = $(this).attr('href');
				window.history.pushState("", "", href);
				
				var controller_hash = $(this).data('controller-hash');
				
				var anchor = $('#w2dc-controller-'+controller_hash);
				if (typeof window["w2dc_sticky_scroll_toppadding_"+controller_hash] != 'undefined') {
					var sticky_scroll_toppadding = window["w2dc_sticky_scroll_toppadding_"+controller_hash];
				} else {
					var sticky_scroll_toppadding = 0;
				}
				w2dc_scroll_to_anchor(anchor, sticky_scroll_toppadding);
				
				var post_params = w2dc_collectAJAXParams({ hash: controller_hash });
				post_params.paged = $(this).data('page');
				post_params.ajax_action = 'paginator';
				
				$.post(
						w2dc_js_objects.ajaxurl,
						post_params,
						function(response_from_the_action_function) {
							w2dc_process_listings_ajax_response(response_from_the_action_function, true, false, true);
						},
						'json'
				);
			}
		});
	}
	
	$('body').on('click', '.w2dc-map-search-toggle, .w2dc-map-sidebar-toggle-container, .w2dc-map-sidebar-toggle-container-mobile', function(e) {
		e.preventDefault();
		var id = $(this).data('id');
		
		if ($("#w2dc-map-wrapper-"+id).hasClass("w2dc-map-sidebar-open")) {
			w2dc_close_listings_sidebar(id);
		} else {
			w2dc_open_listings_sidebar(id);
		}
	});
	$('body').on('click', '.w2dc-map-directions-sidebar-close-button', function(e) {
		e.preventDefault();
		var id = $(this).data('id');
		
		w2dc_open_listings_sidebar(id);
	});
	
	window.w2dc_open_listings_sidebar = function(map_id) {
		$("#w2dc-map-wrapper-"+map_id).addClass("w2dc-map-sidebar-open");
		
		$("body").on('webkitTransitionEnd otransitionend oTransitionEnd msTransitionEnd transitionend', function(e) {
			w2dc_callMapResize(map_id);
		});
	}
	window.w2dc_close_listings_sidebar = function(map_id) {
		$("#w2dc-map-wrapper-"+map_id).removeClass("w2dc-map-sidebar-open");
		
		$("body").on('webkitTransitionEnd otransitionend oTransitionEnd msTransitionEnd transitionend', function(e) {
			w2dc_callMapResize(map_id);
		});
	}
	
	window.w2dc_hasChangedGeocodedCoordinates = function(radius_params, map_id) {
		var map_coords_1 = radius_params.map_coords_1;
		var map_coords_2 = radius_params.map_coords_2;
		
		if ($.isNumeric(map_coords_1) && $.isNumeric(map_coords_2)) {
			if (typeof w2dc_map_markers_attrs_array != 'undefined' && Object.keys(w2dc_map_markers_attrs_array)) {
				for (var i=0; i<w2dc_map_markers_attrs_array.length; i++) {
					if (w2dc_map_markers_attrs_array[i].map_id == map_id) {
						if (typeof w2dc_map_markers_attrs_array[i].map_attrs.geocoded_params != 'undefined') {
							if (
									w2dc_map_markers_attrs_array[i].map_attrs.geocoded_params.map_coords_1 == map_coords_1 &&
									w2dc_map_markers_attrs_array[i].map_attrs.geocoded_params.map_coords_2 == map_coords_2
							) {
								return false;
							}
						}
					}
				}
			}
		}
		
		return true;
	}
	window.w2dc_saveGeocodedCoordinates = function(radius_params, map_id) {
		var map_coords_1 = radius_params.map_coords_1;
		var map_coords_2 = radius_params.map_coords_2;
		
		if ($.isNumeric(map_coords_1) && $.isNumeric(map_coords_2) && wcsearch_get_query_string_param('address')) {
			if (typeof w2dc_map_markers_attrs_array != 'undefined' && Object.keys(w2dc_map_markers_attrs_array)) {
				for (var i=0; i<w2dc_map_markers_attrs_array.length; i++) {
					if (w2dc_map_markers_attrs_array[i].map_id == map_id) {
						w2dc_map_markers_attrs_array[i].map_attrs.geocoded_params = {};
						w2dc_map_markers_attrs_array[i].map_attrs.geocoded_params.map_coords_1 = map_coords_1;
						w2dc_map_markers_attrs_array[i].map_attrs.geocoded_params.map_coords_2 = map_coords_2;
						w2dc_map_markers_attrs_array[i].map_attrs.geocoded_params.address = wcsearch_get_query_string_param('address');
					}
				}
			}
		}
	}
	window.w2dc_checkGeocodedCoordinates = function(map_id) {
		
		if (typeof w2dc_map_markers_attrs_array != 'undefined' && Object.keys(w2dc_map_markers_attrs_array)) {
			for (var i=0; i<w2dc_map_markers_attrs_array.length; i++) {
				if (map_id == w2dc_map_markers_attrs_array[i].map_id) {
					if (typeof w2dc_map_markers_attrs_array[i].map_attrs.geocoded_params != 'undefined') {
						var address_string = wcsearch_get_query_string_param('address');
						
						if (w2dc_map_markers_attrs_array[i].map_attrs.geocoded_params.address != address_string) {
							delete w2dc_map_markers_attrs_array[i].map_attrs.geocoded_params.address;
							delete w2dc_map_markers_attrs_array[i].map_attrs.geocoded_params.map_coords_1;
							delete w2dc_map_markers_attrs_array[i].map_attrs.geocoded_params.map_coords_2;
						}
					}
				}
			}
		}
	}

	$('body').on('click', '.w2dc-list-view-btn', function() {
		var button = $(this);
		var hash = button.data('shortcode-hash');
		var listings_block = $('#w2dc-controller-'+hash).find('.w2dc-listings-block');
		if (listings_block.hasClass('w2dc-listings-grid')) {
			listings_block.find('.w2dc-listings-block-content').fadeTo("fast", 0, function() {
				button.removeClass('w2dc-btn-default').addClass('w2dc-btn-primary');
				button.parents('.w2dc-views-links').find('.w2dc-grid-view-btn').removeClass('w2dc-btn-primary').addClass('w2dc-btn-default');
				listings_block.removeClass('w2dc-listings-grid w2dc-listings-grid-1 w2dc-listings-grid-2 w2dc-listings-grid-3 w2dc-listings-grid-4');
				listings_block.addClass('w2dc-listings-list-view');
				listings_block.find('article.w2dc-listing').each(function() {
					$(this).css('height', 'auto');
				});
				$.cookie("w2dc_listings_view_"+hash, 'list', {expires: 365, path: "/"});
			});
			listings_block.find('.w2dc-listings-block-content').fadeTo("fast", 1);
		}
	});
	$('body').on('click', '.w2dc-grid-view-btn', function() {
		var button = $(this);
		var hash = button.data('shortcode-hash');
		var listings_block = $('#w2dc-controller-'+hash).find('.w2dc-listings-block');
		if (!listings_block.hasClass('w2dc-listings-grid')) {
			listings_block.find('.w2dc-listings-block-content').fadeTo("fast", 0, function() {
				button.removeClass('w2dc-btn-default').addClass('w2dc-btn-primary');
				button.parents('.w2dc-views-links').find('.w2dc-list-view-btn').removeClass('w2dc-btn-primary').addClass('w2dc-btn-default');
				listings_block.removeClass('w2dc-listings-list-view');
				listings_block.addClass('w2dc-listings-grid').addClass('w2dc-listings-grid-'+button.data('grid-columns'));
				w2dc_equalColumnsHeight();
				$.cookie("w2dc_listings_view_"+hash, 'grid', {expires: 365, path: "/"});
			});
			listings_block.find('.w2dc-listings-block-content').fadeTo("fast", 1);
		}
	});
	
	$('body').on('click', ".w2dc-remove-from-favourites-list", function() {
		var listing_id = $(this).attr("listingid");
		
		if ($.cookie("favourites") != null) {
			var favourites_array = $.cookie("favourites").split('*');
		} else {
			var favourites_array = new Array();
		}

		for (var count=0; count<favourites_array.length; count++) {
			if (favourites_array[count] == listing_id) {
				delete favourites_array[count];
			}
		}

		$(".w2dc-listing#post-"+listing_id).remove();
		
		$.cookie("favourites", favourites_array.join('*'), {expires: 365, path: "/"});
		return false;
	});
	
	// Select FA icon dialog
	$(document).on("click", ".w2dc-select-fa-icon", function() {
		var dialog_title = $(this).text();
		var icon_image_name = $(this).data("icon-image-name");
		var icon_image_name_obj = $("#"+icon_image_name);
		var icon_tag = $(this).data("icon-tag");
		var icon_tag_obj = $("."+icon_tag);
		
		var icon_click_event;
		var reset_icon_click_event;
		
		var dialog_obj = $('<div id="w2dc-select-fa-icon-dialog"></div>');
		dialog_obj.dialog({
			dialogClass: 'w2dc-content',
			width: ($(window).width()*0.5),
			height: ($(window).height()*0.8),
			modal: true,
			resizable: false,
			draggable: false,
			title: dialog_title,
			open: function() {
				w2dc_ajax_loader_show();
				$.ajax({
					type: "POST",
					url: w2dc_js_objects.ajaxurl,
					data: {'action': 'w2dc_select_fa_icon'},
					dataType: 'html',
					success: function(response_from_the_action_function){
						if (response_from_the_action_function != 0) {
							dialog_obj.html(response_from_the_action_function);
							if (icon_image_name_obj.val()) {
								$("#"+icon_image_name_obj.val()).addClass("w2dc-selected-icon");
							}

							icon_click_event = $(document).one("click", ".w2dc-fa-icon", function() {
								$(".w2dc-selected-icon").removeClass("w2dc-selected-icon");
								icon_image_name_obj.val($(this).attr('id'));
								icon_tag_obj.removeClass().addClass(icon_tag+' w2dc-icon-tag w2dc-fa '+icon_image_name_obj.val());
								icon_tag_obj.show();
								$(this).addClass("w2dc-selected-icon");
								reset_icon_click_event.off("click", "#w2dc-reset-fa-icon");
								dialog_obj.remove();
							});
							reset_icon_click_event = $(document).one("click", "#w2dc-reset-fa-icon", function() {
								$(".w2dc-selected-icon").removeClass("w2dc-selected-icon");
								icon_tag_obj.removeClass().addClass(icon_tag+' w2dc-icon-tag');
								icon_tag_obj.hide();
								icon_image_name_obj.val('');
								icon_click_event.off("click", ".w2dc-fa-icon");
								dialog_obj.remove();
							});
						}
					},
					complete: function() {
						w2dc_ajax_loader_hide();
					}
				});
				$(document).on("click", ".ui-widget-overlay", function() {
					icon_click_event.off("click", ".w2dc-fa-icon");
					reset_icon_click_event.off("click", "#w2dc-reset-fa-icon");
					dialog_obj.remove();
				});
			},
			close: function() {
				icon_click_event.off("click", ".w2dc-fa-icon");
				reset_icon_click_event.off("click", "#w2dc-reset-fa-icon");
				dialog_obj.remove();
			}
		});
	});
	
	// AJAX Contact form
	$(document).on('submit', '#w2dc_contact_form, #w2dc_report_form', function(e) {
		e.preventDefault();

		var $this = $(this);
		
		if ($this.attr('id') == 'w2dc_contact_form') {
			var type = 'contact';
		} else if ($this.attr('id') == 'w2dc_report_form') {
			var type = 'report';
		}
		var warning = $this.find('#'+type+'_warning');
		var listing_id = $this.find('#'+type+'_listing_id');
		var nonce = $this.find('#'+type+'_nonce');
		var name = $this.find('#'+type+'_name');
		var email = $this.find('#'+type+'_email');
		var message = $this.find('#'+type+'_message');
		var button = $this.find('.w2dc-send-message-button');
		var recaptcha = ($this.find('#g-recaptcha-response').length ? $this.find('#g-recaptcha-response').val() : '');
		
		$this.css('opacity', '0.5');
		warning.hide();
		button.val(w2dc_js_objects.send_button_sending).attr('disabled', 'disabled');

		var data = {
				action: "w2dc_contact_form",
				type: type,
				listing_id: listing_id.val(),
				name: name.val(),
				email: email.val(),
				message: message.val(),
				security: nonce.val(),
				'g-recaptcha-response': recaptcha
		};

		$.ajax({
				url: w2dc_js_objects.ajaxurl,
				type: "POST",
				dataType: "json",
				data: data,
				global: false,
				success: function(response_from_the_action_function) {
					if (response_from_the_action_function != 0) {
						if (response_from_the_action_function.error == '') {
							name.val(''),
							email.val(''),
							message.val(''),
							warning.html(response_from_the_action_function.success).show();
						} else {
							var error;
							if (typeof response_from_the_action_function.error == 'object') {
								error = '<ul>';
								$.each(response_from_the_action_function.error, function(key, value) {
									error = error + '<li>' + value + '</li>';
								});
	            				error = error + '</ul>';
	            			} else {
	            				error = response_from_the_action_function.error;
	            			}
							warning.html(error).show();
	            		}
	            		$this.css('opacity', '1');
	            		button.val(w2dc_js_objects.send_button_text).removeAttr('disabled');
					}
				}
		});
	});
})(jQuery);


function w2dc_make_slug(name) {
	name = name.toLowerCase();
	
	var defaultDiacriticsRemovalMap = [
	                                   {'base':'A', 'letters':/[\u0041\u24B6\uFF21\u00C0\u00C1\u00C2\u1EA6\u1EA4\u1EAA\u1EA8\u00C3\u0100\u0102\u1EB0\u1EAE\u1EB4\u1EB2\u0226\u01E0\u00C4\u01DE\u1EA2\u00C5\u01FA\u01CD\u0200\u0202\u1EA0\u1EAC\u1EB6\u1E00\u0104\u023A\u2C6F]/g},
	                                   {'base':'AA','letters':/[\uA732]/g},
	                                   {'base':'AE','letters':/[\u00C6\u01FC\u01E2]/g},
	                                   {'base':'AO','letters':/[\uA734]/g},
	                                   {'base':'AU','letters':/[\uA736]/g},
	                                   {'base':'AV','letters':/[\uA738\uA73A]/g},
	                                   {'base':'AY','letters':/[\uA73C]/g},
	                                   {'base':'B', 'letters':/[\u0042\u24B7\uFF22\u1E02\u1E04\u1E06\u0243\u0182\u0181]/g},
	                                   {'base':'C', 'letters':/[\u0043\u24B8\uFF23\u0106\u0108\u010A\u010C\u00C7\u1E08\u0187\u023B\uA73E]/g},
	                                   {'base':'D', 'letters':/[\u0044\u24B9\uFF24\u1E0A\u010E\u1E0C\u1E10\u1E12\u1E0E\u0110\u018B\u018A\u0189\uA779]/g},
	                                   {'base':'DZ','letters':/[\u01F1\u01C4]/g},
	                                   {'base':'Dz','letters':/[\u01F2\u01C5]/g},
	                                   {'base':'E', 'letters':/[\u0045\u24BA\uFF25\u00C8\u00C9\u00CA\u1EC0\u1EBE\u1EC4\u1EC2\u1EBC\u0112\u1E14\u1E16\u0114\u0116\u00CB\u1EBA\u011A\u0204\u0206\u1EB8\u1EC6\u0228\u1E1C\u0118\u1E18\u1E1A\u0190\u018E]/g},
	                                   {'base':'F', 'letters':/[\u0046\u24BB\uFF26\u1E1E\u0191\uA77B]/g},
	                                   {'base':'G', 'letters':/[\u0047\u24BC\uFF27\u01F4\u011C\u1E20\u011E\u0120\u01E6\u0122\u01E4\u0193\uA7A0\uA77D\uA77E]/g},
	                                   {'base':'H', 'letters':/[\u0048\u24BD\uFF28\u0124\u1E22\u1E26\u021E\u1E24\u1E28\u1E2A\u0126\u2C67\u2C75\uA78D]/g},
	                                   {'base':'I', 'letters':/[\u0049\u24BE\uFF29\u00CC\u00CD\u00CE\u0128\u012A\u012C\u0130\u00CF\u1E2E\u1EC8\u01CF\u0208\u020A\u1ECA\u012E\u1E2C\u0197]/g},
	                                   {'base':'J', 'letters':/[\u004A\u24BF\uFF2A\u0134\u0248]/g},
	                                   {'base':'K', 'letters':/[\u004B\u24C0\uFF2B\u1E30\u01E8\u1E32\u0136\u1E34\u0198\u2C69\uA740\uA742\uA744\uA7A2]/g},
	                                   {'base':'L', 'letters':/[\u004C\u24C1\uFF2C\u013F\u0139\u013D\u1E36\u1E38\u013B\u1E3C\u1E3A\u0141\u023D\u2C62\u2C60\uA748\uA746\uA780]/g},
	                                   {'base':'LJ','letters':/[\u01C7]/g},
	                                   {'base':'Lj','letters':/[\u01C8]/g},
	                                   {'base':'M', 'letters':/[\u004D\u24C2\uFF2D\u1E3E\u1E40\u1E42\u2C6E\u019C]/g},
	                                   {'base':'N', 'letters':/[\u004E\u24C3\uFF2E\u01F8\u0143\u00D1\u1E44\u0147\u1E46\u0145\u1E4A\u1E48\u0220\u019D\uA790\uA7A4]/g},
	                                   {'base':'NJ','letters':/[\u01CA]/g},
	                                   {'base':'Nj','letters':/[\u01CB]/g},
	                                   {'base':'O', 'letters':/[\u004F\u24C4\uFF2F\u00D2\u00D3\u00D4\u1ED2\u1ED0\u1ED6\u1ED4\u00D5\u1E4C\u022C\u1E4E\u014C\u1E50\u1E52\u014E\u022E\u0230\u00D6\u022A\u1ECE\u0150\u01D1\u020C\u020E\u01A0\u1EDC\u1EDA\u1EE0\u1EDE\u1EE2\u1ECC\u1ED8\u01EA\u01EC\u00D8\u01FE\u0186\u019F\uA74A\uA74C]/g},
	                                   {'base':'OI','letters':/[\u01A2]/g},
	                                   {'base':'OO','letters':/[\uA74E]/g},
	                                   {'base':'OU','letters':/[\u0222]/g},
	                                   {'base':'P', 'letters':/[\u0050\u24C5\uFF30\u1E54\u1E56\u01A4\u2C63\uA750\uA752\uA754]/g},
	                                   {'base':'Q', 'letters':/[\u0051\u24C6\uFF31\uA756\uA758\u024A]/g},
	                                   {'base':'R', 'letters':/[\u0052\u24C7\uFF32\u0154\u1E58\u0158\u0210\u0212\u1E5A\u1E5C\u0156\u1E5E\u024C\u2C64\uA75A\uA7A6\uA782]/g},
	                                   {'base':'S', 'letters':/[\u0053\u24C8\uFF33\u1E9E\u015A\u1E64\u015C\u1E60\u0160\u1E66\u1E62\u1E68\u0218\u015E\u2C7E\uA7A8\uA784]/g},
	                                   {'base':'T', 'letters':/[\u0054\u24C9\uFF34\u1E6A\u0164\u1E6C\u021A\u0162\u1E70\u1E6E\u0166\u01AC\u01AE\u023E\uA786]/g},
	                                   {'base':'TZ','letters':/[\uA728]/g},
	                                   {'base':'U', 'letters':/[\u0055\u24CA\uFF35\u00D9\u00DA\u00DB\u0168\u1E78\u016A\u1E7A\u016C\u00DC\u01DB\u01D7\u01D5\u01D9\u1EE6\u016E\u0170\u01D3\u0214\u0216\u01AF\u1EEA\u1EE8\u1EEE\u1EEC\u1EF0\u1EE4\u1E72\u0172\u1E76\u1E74\u0244]/g},
	                                   {'base':'V', 'letters':/[\u0056\u24CB\uFF36\u1E7C\u1E7E\u01B2\uA75E\u0245]/g},
	                                   {'base':'VY','letters':/[\uA760]/g},
	                                   {'base':'W', 'letters':/[\u0057\u24CC\uFF37\u1E80\u1E82\u0174\u1E86\u1E84\u1E88\u2C72]/g},
	                                   {'base':'X', 'letters':/[\u0058\u24CD\uFF38\u1E8A\u1E8C]/g},
	                                   {'base':'Y', 'letters':/[\u0059\u24CE\uFF39\u1EF2\u00DD\u0176\u1EF8\u0232\u1E8E\u0178\u1EF6\u1EF4\u01B3\u024E\u1EFE]/g},
	                                   {'base':'Z', 'letters':/[\u005A\u24CF\uFF3A\u0179\u1E90\u017B\u017D\u1E92\u1E94\u01B5\u0224\u2C7F\u2C6B\uA762]/g},
	                                   {'base':'a', 'letters':/[\u0061\u24D0\uFF41\u1E9A\u00E0\u00E1\u00E2\u1EA7\u1EA5\u1EAB\u1EA9\u00E3\u0101\u0103\u1EB1\u1EAF\u1EB5\u1EB3\u0227\u01E1\u00E4\u01DF\u1EA3\u00E5\u01FB\u01CE\u0201\u0203\u1EA1\u1EAD\u1EB7\u1E01\u0105\u2C65\u0250]/g},
	                                   {'base':'aa','letters':/[\uA733]/g},
	                                   {'base':'ae','letters':/[\u00E6\u01FD\u01E3]/g},
	                                   {'base':'ao','letters':/[\uA735]/g},
	                                   {'base':'au','letters':/[\uA737]/g},
	                                   {'base':'av','letters':/[\uA739\uA73B]/g},
	                                   {'base':'ay','letters':/[\uA73D]/g},
	                                   {'base':'b', 'letters':/[\u0062\u24D1\uFF42\u1E03\u1E05\u1E07\u0180\u0183\u0253]/g},
	                                   {'base':'c', 'letters':/[\u0063\u24D2\uFF43\u0107\u0109\u010B\u010D\u00E7\u1E09\u0188\u023C\uA73F\u2184]/g},
	                                   {'base':'d', 'letters':/[\u0064\u24D3\uFF44\u1E0B\u010F\u1E0D\u1E11\u1E13\u1E0F\u0111\u018C\u0256\u0257\uA77A]/g},
	                                   {'base':'dz','letters':/[\u01F3\u01C6]/g},
	                                   {'base':'e', 'letters':/[\u0065\u24D4\uFF45\u00E8\u00E9\u00EA\u1EC1\u1EBF\u1EC5\u1EC3\u1EBD\u0113\u1E15\u1E17\u0115\u0117\u00EB\u1EBB\u011B\u0205\u0207\u1EB9\u1EC7\u0229\u1E1D\u0119\u1E19\u1E1B\u0247\u025B\u01DD]/g},
	                                   {'base':'f', 'letters':/[\u0066\u24D5\uFF46\u1E1F\u0192\uA77C]/g},
	                                   {'base':'g', 'letters':/[\u0067\u24D6\uFF47\u01F5\u011D\u1E21\u011F\u0121\u01E7\u0123\u01E5\u0260\uA7A1\u1D79\uA77F]/g},
	                                   {'base':'h', 'letters':/[\u0068\u24D7\uFF48\u0125\u1E23\u1E27\u021F\u1E25\u1E29\u1E2B\u1E96\u0127\u2C68\u2C76\u0265]/g},
	                                   {'base':'hv','letters':/[\u0195]/g},
	                                   {'base':'i', 'letters':/[\u0069\u24D8\uFF49\u00EC\u00ED\u00EE\u0129\u012B\u012D\u00EF\u1E2F\u1EC9\u01D0\u0209\u020B\u1ECB\u012F\u1E2D\u0268\u0131]/g},
	                                   {'base':'j', 'letters':/[\u006A\u24D9\uFF4A\u0135\u01F0\u0249]/g},
	                                   {'base':'k', 'letters':/[\u006B\u24DA\uFF4B\u1E31\u01E9\u1E33\u0137\u1E35\u0199\u2C6A\uA741\uA743\uA745\uA7A3]/g},
	                                   {'base':'l', 'letters':/[\u006C\u24DB\uFF4C\u0140\u013A\u013E\u1E37\u1E39\u013C\u1E3D\u1E3B\u017F\u0142\u019A\u026B\u2C61\uA749\uA781\uA747]/g},
	                                   {'base':'lj','letters':/[\u01C9]/g},
	                                   {'base':'m', 'letters':/[\u006D\u24DC\uFF4D\u1E3F\u1E41\u1E43\u0271\u026F]/g},
	                                   {'base':'n', 'letters':/[\u006E\u24DD\uFF4E\u01F9\u0144\u00F1\u1E45\u0148\u1E47\u0146\u1E4B\u1E49\u019E\u0272\u0149\uA791\uA7A5]/g},
	                                   {'base':'nj','letters':/[\u01CC]/g},
	                                   {'base':'o', 'letters':/[\u006F\u24DE\uFF4F\u00F2\u00F3\u00F4\u1ED3\u1ED1\u1ED7\u1ED5\u00F5\u1E4D\u022D\u1E4F\u014D\u1E51\u1E53\u014F\u022F\u0231\u00F6\u022B\u1ECF\u0151\u01D2\u020D\u020F\u01A1\u1EDD\u1EDB\u1EE1\u1EDF\u1EE3\u1ECD\u1ED9\u01EB\u01ED\u00F8\u01FF\u0254\uA74B\uA74D\u0275]/g},
	                                   {'base':'oi','letters':/[\u01A3]/g},
	                                   {'base':'ou','letters':/[\u0223]/g},
	                                   {'base':'oo','letters':/[\uA74F]/g},
	                                   {'base':'p','letters':/[\u0070\u24DF\uFF50\u1E55\u1E57\u01A5\u1D7D\uA751\uA753\uA755]/g},
	                                   {'base':'q','letters':/[\u0071\u24E0\uFF51\u024B\uA757\uA759]/g},
	                                   {'base':'r','letters':/[\u0072\u24E1\uFF52\u0155\u1E59\u0159\u0211\u0213\u1E5B\u1E5D\u0157\u1E5F\u024D\u027D\uA75B\uA7A7\uA783]/g},
	                                   {'base':'s','letters':/[\u0073\u24E2\uFF53\u00DF\u015B\u1E65\u015D\u1E61\u0161\u1E67\u1E63\u1E69\u0219\u015F\u023F\uA7A9\uA785\u1E9B]/g},
	                                   {'base':'t','letters':/[\u0074\u24E3\uFF54\u1E6B\u1E97\u0165\u1E6D\u021B\u0163\u1E71\u1E6F\u0167\u01AD\u0288\u2C66\uA787]/g},
	                                   {'base':'tz','letters':/[\uA729]/g},
	                                   {'base':'u','letters':/[\u0075\u24E4\uFF55\u00F9\u00FA\u00FB\u0169\u1E79\u016B\u1E7B\u016D\u00FC\u01DC\u01D8\u01D6\u01DA\u1EE7\u016F\u0171\u01D4\u0215\u0217\u01B0\u1EEB\u1EE9\u1EEF\u1EED\u1EF1\u1EE5\u1E73\u0173\u1E77\u1E75\u0289]/g},
	                                   {'base':'v','letters':/[\u0076\u24E5\uFF56\u1E7D\u1E7F\u028B\uA75F\u028C]/g},
	                                   {'base':'vy','letters':/[\uA761]/g},
	                                   {'base':'w','letters':/[\u0077\u24E6\uFF57\u1E81\u1E83\u0175\u1E87\u1E85\u1E98\u1E89\u2C73]/g},
	                                   {'base':'x','letters':/[\u0078\u24E7\uFF58\u1E8B\u1E8D]/g},
	                                   {'base':'y','letters':/[\u0079\u24E8\uFF59\u1EF3\u00FD\u0177\u1EF9\u0233\u1E8F\u00FF\u1EF7\u1E99\u1EF5\u01B4\u024F\u1EFF]/g},
	                                   {'base':'z','letters':/[\u007A\u24E9\uFF5A\u017A\u1E91\u017C\u017E\u1E93\u1E95\u01B6\u0225\u0240\u2C6C\uA763]/g}
	                               ];
	for(var i=0; i<defaultDiacriticsRemovalMap.length; i++)
		name = name.replace(defaultDiacriticsRemovalMap[i].letters, defaultDiacriticsRemovalMap[i].base);

	//change spaces and other characters by '_'
	name = name.replace(/\W/gi, "_");
	// remove double '_'
	name = name.replace(/(\_)\1+/gi, "_");
	
	return name;
}

function w2dc_in_array(val, arr) 
{
	for (var i = 0; i < arr.length; i++) {
		if (arr[i] == val)
			return i;
	}
	return false;
}

function w2dc_find_get_parameter(parameterName) {
    var result = null,
        tmp = [];
    var items = location.search.substr(1).split("&");
    for (var index = 0; index < items.length; index++) {
        tmp = items[index].split("=");
        if (tmp[0] === parameterName) result = decodeURIComponent(tmp[1]);
    }
    return result;
}


/*!
 * jQuery Mousewheel 3.1.13 -------------------------------------------------------------------------------------------------------------------------------------------
 *
 * Copyright 2015 jQuery Foundation and other contributors
 * Released under the MIT license.
 * http://jquery.org/license
 */
!function(a){"function"==typeof define&&define.amd?define(["jquery"],a):"object"==typeof exports?module.exports=a:a(jQuery)}(function(a){function b(b){var g=b||window.event,h=i.call(arguments,1),j=0,l=0,m=0,n=0,o=0,p=0;if(b=a.event.fix(g),b.type="mousewheel","detail"in g&&(m=-1*g.detail),"wheelDelta"in g&&(m=g.wheelDelta),"wheelDeltaY"in g&&(m=g.wheelDeltaY),"wheelDeltaX"in g&&(l=-1*g.wheelDeltaX),"axis"in g&&g.axis===g.HORIZONTAL_AXIS&&(l=-1*m,m=0),j=0===m?l:m,"deltaY"in g&&(m=-1*g.deltaY,j=m),"deltaX"in g&&(l=g.deltaX,0===m&&(j=-1*l)),0!==m||0!==l){if(1===g.deltaMode){var q=a.data(this,"mousewheel-line-height");j*=q,m*=q,l*=q}else if(2===g.deltaMode){var r=a.data(this,"mousewheel-page-height");j*=r,m*=r,l*=r}if(n=Math.max(Math.abs(m),Math.abs(l)),(!f||f>n)&&(f=n,d(g,n)&&(f/=40)),d(g,n)&&(j/=40,l/=40,m/=40),j=Math[j>=1?"floor":"ceil"](j/f),l=Math[l>=1?"floor":"ceil"](l/f),m=Math[m>=1?"floor":"ceil"](m/f),k.settings.normalizeOffset&&this.getBoundingClientRect){var s=this.getBoundingClientRect();o=b.clientX-s.left,p=b.clientY-s.top}return b.deltaX=l,b.deltaY=m,b.deltaFactor=f,b.offsetX=o,b.offsetY=p,b.deltaMode=0,h.unshift(b,j,l,m),e&&clearTimeout(e),e=setTimeout(c,200),(a.event.dispatch||a.event.handle).apply(this,h)}}function c(){f=null}function d(a,b){return k.settings.adjustOldDeltas&&"mousewheel"===a.type&&b%120===0}var e,f,g=["wheel","mousewheel","DOMMouseScroll","MozMousePixelScroll"],h="onwheel"in document||document.documentMode>=9?["wheel"]:["mousewheel","DomMouseScroll","MozMousePixelScroll"],i=Array.prototype.slice;if(a.event.fixHooks)for(var j=g.length;j;)a.event.fixHooks[g[--j]]=a.event.mouseHooks;var k=a.event.special.mousewheel={version:"3.1.12",setup:function(){if(this.addEventListener)for(var c=h.length;c;)this.addEventListener(h[--c],b,!1);else this.onmousewheel=b;a.data(this,"mousewheel-line-height",k.getLineHeight(this)),a.data(this,"mousewheel-page-height",k.getPageHeight(this))},teardown:function(){if(this.removeEventListener)for(var c=h.length;c;)this.removeEventListener(h[--c],b,!1);else this.onmousewheel=null;a.removeData(this,"mousewheel-line-height"),a.removeData(this,"mousewheel-page-height")},getLineHeight:function(b){var c=a(b),d=c["offsetParent"in a.fn?"offsetParent":"parent"]();return d.length||(d=a("body")),parseInt(d.css("fontSize"),10)||parseInt(c.css("fontSize"),10)||16},getPageHeight:function(b){return a(b).height()},settings:{adjustOldDeltas:!0,normalizeOffset:!0}};a.fn.extend({mousewheel:function(a){return a?this.bind("mousewheel",a):this.trigger("mousewheel")},unmousewheel:function(a){return this.unbind("mousewheel",a)}})});


// tax_dropdowns.js -------------------------------------------------------------------------------------------------------------------------------------------
(function($) {
	"use strict";

	$(document).on('change', '.w2dc-tax-dropdowns-wrap select', function() {
		var select_box = $(this).attr('id').split('_');
		var parent = $(this).val();
		var current_level = select_box[1];
		var uID = select_box[2];

		var divclass = $(this).parents('.w2dc-tax-dropdowns-wrap').attr('class').split(' ');
		var tax = divclass[0];
		var count = divclass[1];
		var hide_empty = divclass[2];

		w2dc_update_tax(parent, tax, current_level, count, hide_empty, uID, function() {});
	});

	function w2dc_update_tax(parent, tax, current_level, count, hide_empty, uID, callback) {
		var current_level = parseInt(current_level);
		var next_level = current_level + 1;
		var prev_level = current_level - 1;
		var selects_length = $('#w2dc-tax-dropdowns-wrap-'+uID+' .w2dc-location-chainlist').length;
		
		if (parent)
			$('#selected_tax\\['+uID+'\\]').val(parent).trigger('change');
		else if (current_level > 1)
			$('#selected_tax\\['+uID+'\\]').val($('#chainlist_'+prev_level+'_'+uID).val()).trigger('change');
		else
			$('#selected_tax\\['+uID+'\\]').val(0).trigger('change');

		var exact_terms = $('#exact_terms\\['+uID+'\\]').val();

		for (var i=next_level; i<=selects_length; i++) {
			$('#wrap_chainlist_'+i+'_'+uID).remove();
		}
		
		if (parent && typeof w2dc_js_objects['tax_dropdowns_'+uID][uID] != undefined) {
			var labels_source = w2dc_js_objects['tax_dropdowns_'+uID][uID];

			if (labels_source.labels[current_level] != undefined)
				var label = labels_source.labels[current_level];
			else
				var label = '';
			if (labels_source.titles[current_level] != undefined)
				var title = labels_source.titles[current_level];
			else
				var title = '';
			if (labels_source.allow_add_term[current_level] != undefined)
				var allow_add_term = labels_source.allow_add_term[current_level];
			else
				var allow_add_term = '';

			$('#chainlist_'+current_level+'_'+uID).addClass('w2dc-ajax-loading').attr('disabled', 'disabled');
			$.post(
				w2dc_js_objects.ajaxurl,
				{
					'action': 'w2dc_tax_dropdowns_hook',
					'parentid': parent,
					'next_level': next_level,
					'tax': tax,
					'count': count,
					'hide_empty': hide_empty,
					'label': label,
					'title': title,
					'allow_add_term': allow_add_term,
					'exact_terms': exact_terms,
					'uID': uID
				},
				function(response_from_the_action_function){
					if (response_from_the_action_function != 0)
						$('#w2dc-tax-dropdowns-wrap-'+uID).append(response_from_the_action_function);

					$('#chainlist_'+current_level+'_'+uID).removeClass('w2dc-ajax-loading').removeAttr('disabled');
					
					callback();
				}
			);
		}
	}
	
	function first(p){for(var i in p)return p[i];}
}(jQuery));



// jquery.coo_kie.js -------------------------------------------------------------------------------------------------------------------------------------------
jQuery.cookie=function(e,i,o){if("undefined"==typeof i){var n=null;if(document.cookie&&""!=document.cookie)for(var r=document.cookie.split(";"),t=0;t<r.length;t++){var p=jQuery.trim(r[t]);if(p.substring(0,e.length+1)==e+"="){n=decodeURIComponent(p.substring(e.length+1));break}}return n}o=o||{},null===i&&(i="",o.expires=-1);var u="";if(o.expires&&("number"==typeof o.expires||o.expires.toUTCString)){var s;"number"==typeof o.expires?(s=new Date,s.setTime(s.getTime()+24*o.expires*60*60*1e3)):s=o.expires,u="; expires="+s.toUTCString()}var a=o.path?"; path="+o.path:"",c=o.domain?"; domain="+o.domain:"",m=o.secure?"; secure":"";document.cookie=[e,"=",encodeURIComponent(i),u,a,c,m].join("")};



// jquery.w2dc_bxslider.min.js -------------------------------------------------------------------------------------------------------------------------------------------
/**
 * w2dc_bxslider v4.2.1d
 * Copyright 2013-2017 Steven Wanderski
 * Written while drinking Belgian ales and listening to jazz
 * Licensed under MIT (http://opensource.org/licenses/MIT)
 * 
 * 22.09.2020 - added condition in if (slider.viewport.get(0).releasePointerCapture && typeof w2dc_lightbox == "undefined") {
 */
!function(R){var Z={mode:"horizontal",slideSelector:"",infiniteLoop:!0,hideControlOnEnd:!1,speed:500,easing:null,slideMargin:0,startSlide:0,randomStart:!1,captions:!1,ticker:!1,tickerHover:!1,adaptiveHeight:!1,adaptiveHeightSpeed:500,video:!1,useCSS:!0,preloadImages:"visible",responsive:!0,slideZIndex:50,wrapperClass:"w2dc-bx-wrapper",touchEnabled:!0,swipeThreshold:50,oneToOneTouch:!0,preventDefaultSwipeX:!0,preventDefaultSwipeY:!1,ariaLive:!0,ariaHidden:!0,keyboardEnabled:!1,pager:!0,pagerType:"full",pagerShortSeparator:" / ",pagerSelector:null,buildPager:null,pagerCustom:null,controls:!0,nextText:"Next",prevText:"Prev",nextSelector:null,prevSelector:null,autoControls:!1,startText:"Start",stopText:"Stop",autoControlsCombine:!1,autoControlsSelector:null,auto:!1,pause:4e3,autoStart:!0,autoDirection:"next",stopAutoOnClick:!1,autoHover:!1,autoDelay:0,autoSlideForOnePage:!1,minSlides:1,maxSlides:1,moveSlides:0,slideWidth:0,shrinkItems:!1,onSliderLoad:function(){return!0},onSlideBefore:function(){return!0},onSlideAfter:function(){return!0},onSlideNext:function(){return!0},onSlidePrev:function(){return!0},onSliderResize:function(){return!0},onAutoChange:function(){return!0}};R.fn.w2dc_bxslider=function(e){if(0===this.length)return this;if(1<this.length)return this.each(function(){R(this).w2dc_bxslider(e)}),this;var g={},p=this,n=R(window).width(),s=R(window).height();if(!R(p).data("w2dc_bxslider")){function o(){R(p).data("w2dc_bxslider")||(g.settings=R.extend({},Z,e),g.settings.slideWidth=parseInt(g.settings.slideWidth),g.children=p.children(g.settings.slideSelector),g.children.length<g.settings.minSlides&&(g.settings.minSlides=g.children.length),g.children.length<g.settings.maxSlides&&(g.settings.maxSlides=g.children.length),g.settings.randomStart&&(g.settings.startSlide=Math.floor(Math.random()*g.children.length)),g.active={index:g.settings.startSlide},g.carousel=1<g.settings.minSlides||1<g.settings.maxSlides,g.carousel&&(g.settings.preloadImages="all"),g.minThreshold=g.settings.minSlides*g.settings.slideWidth+(g.settings.minSlides-1)*g.settings.slideMargin,g.maxThreshold=g.settings.maxSlides*g.settings.slideWidth+(g.settings.maxSlides-1)*g.settings.slideMargin,g.working=!1,g.controls={},g.interval=null,g.animProp="vertical"===g.settings.mode?"top":"left",g.usingCSS=g.settings.useCSS&&"fade"!==g.settings.mode&&function(){for(var t=document.createElement("div"),e=["WebkitPerspective","MozPerspective","OPerspective","msPerspective"],i=0;i<e.length;i++)if(void 0!==t.style[e[i]])return g.cssPrefix=e[i].replace("Perspective","").toLowerCase(),g.animProp="-"+g.cssPrefix+"-transform",!0;return!1}(),"vertical"===g.settings.mode&&(g.settings.maxSlides=g.settings.minSlides),p.data("origStyle",p.attr("style")),p.children(g.settings.slideSelector).each(function(){R(this).data("origStyle",R(this).attr("style"))}),d())}function r(){var t=1,e=null;return"horizontal"===g.settings.mode&&0<g.settings.slideWidth?t=g.viewport.width()<g.minThreshold?g.settings.minSlides:g.viewport.width()>g.maxThreshold?g.settings.maxSlides:(e=g.children.first().width()+g.settings.slideMargin,Math.floor((g.viewport.width()+g.settings.slideMargin)/e)||1):"vertical"===g.settings.mode&&(t=g.settings.minSlides),t}function t(){for(var t="",e="",i=w(),n=0;n<i;n++)e="",g.settings.buildPager&&R.isFunction(g.settings.buildPager)||g.settings.pagerCustom?(e=g.settings.buildPager(n),g.pagerEl.addClass("w2dc-bx-custom-pager")):(e=n+1,g.pagerEl.addClass("w2dc-bx-default-pager")),t+='<div class="w2dc-bx-pager-item"><a href="" data-slide-index="'+n+'" class="w2dc-bx-pager-link">'+e+"</a></div>";g.pagerEl.html(t)}function a(){p.startAuto()}function l(){p.stopAuto()}function u(t){var e=r();g.settings.ariaHidden&&!g.settings.ticker&&(g.children.attr("aria-hidden","true"),g.children.slice(t,t+e).attr("aria-hidden","false"))}var d=function(){var t=g.children.eq(g.settings.startSlide);p.wrap('<div class="'+g.settings.wrapperClass+'"><div class="w2dc-bx-viewport"></div></div>'),g.viewport=p.parent(),g.settings.ariaLive&&!g.settings.ticker&&g.viewport.attr("aria-live","polite"),g.loader=R('<div class="w2dc-bx-loading" />'),g.viewport.prepend(g.loader),p.css({width:"horizontal"===g.settings.mode?1e3*g.children.length+215+"%":"auto",position:"relative"}),g.usingCSS&&g.settings.easing?p.css("-"+g.cssPrefix+"-transition-timing-function",g.settings.easing):g.settings.easing||(g.settings.easing="swing"),g.viewport.css({width:"100%",overflow:"hidden",position:"relative"}),g.viewport.parent().css({maxWidth:f()}),g.children.css({float:"horizontal"===g.settings.mode?"left":"none",listStyle:"none",position:"relative"}),g.children.css("width",m()),"horizontal"===g.settings.mode&&0<g.settings.slideMargin&&g.children.css("marginRight",g.settings.slideMargin),"vertical"===g.settings.mode&&0<g.settings.slideMargin&&g.children.css("marginBottom",g.settings.slideMargin),"fade"===g.settings.mode&&(g.children.css({position:"absolute",zIndex:0,display:"none"}),g.children.eq(g.settings.startSlide).css({zIndex:g.settings.slideZIndex,display:"block"})),g.controls.el=R('<div class="w2dc-bx-controls" />'),g.settings.captions&&P(),g.active.last=g.settings.startSlide===w()-1,g.settings.video&&p.fitVids(),"none"===g.settings.preloadImages?t=null:"all"!==g.settings.preloadImages&&!g.settings.ticker||(t=g.children),g.settings.ticker?g.settings.pager=!1:(g.settings.controls&&T(),g.settings.auto&&g.settings.autoControls&&k(),g.settings.pager&&b(),(g.settings.controls||g.settings.autoControls||g.settings.pager)&&g.viewport.after(g.controls.el)),null===t?h():c(t,h)},c=function(t,e){var i=t.find('img:not([src=""]), iframe').length,n=0;0!==i?t.find('img:not([src=""]), iframe').each(function(){R(this).one("load error",function(){++n===i&&e()}).each(function(){!this.complete&&""!=this.src||R(this).trigger("load")})}):e()},h=function(){var t,e,i;g.settings.infiniteLoop&&"fade"!==g.settings.mode&&!g.settings.ticker&&(t="vertical"===g.settings.mode?g.settings.minSlides:g.settings.maxSlides,e=g.children.slice(0,t).clone(!0).addClass("w2dc-bx-clone"),i=g.children.slice(-t).clone(!0).addClass("w2dc-bx-clone"),g.settings.ariaHidden&&(e.attr("aria-hidden",!0),i.attr("aria-hidden",!0)),p.append(e).prepend(i)),g.loader.remove(),S(),"vertical"===g.settings.mode&&(g.settings.adaptiveHeight=!0),g.viewport.height(v()),p.redrawSlider(),g.settings.onSliderLoad.call(p,g.active.index),g.initialized=!0,g.settings.responsive&&R(window).on("resize",V),g.settings.auto&&g.settings.autoStart&&(1<w()||g.settings.autoSlideForOnePage)&&W(),g.settings.ticker&&L(),g.settings.pager&&A(g.settings.startSlide),g.settings.controls&&H(),g.settings.touchEnabled&&!g.settings.ticker&&_(),g.settings.keyboardEnabled&&!g.settings.ticker&&R(document).keydown(F)},v=function(){var e=0,t=R();if("vertical"===g.settings.mode||g.settings.adaptiveHeight)if(g.carousel){var n=1===g.settings.moveSlides?g.active.index:g.active.index*x(),t=g.children.eq(n);for(i=1;i<=g.settings.maxSlides-1;i++)t=n+i>=g.children.length?t.add(g.children.eq(i-1)):t.add(g.children.eq(n+i))}else t=g.children.eq(g.active.index);else t=g.children;return"vertical"===g.settings.mode?(t.each(function(t){e+=R(this).outerHeight()}),0<g.settings.slideMargin&&(e+=g.settings.slideMargin*(g.settings.minSlides-1))):e=Math.max.apply(Math,t.map(function(){return R(this).outerHeight(!1)}).get()),"border-box"===g.viewport.css("box-sizing")?e+=parseFloat(g.viewport.css("padding-top"))+parseFloat(g.viewport.css("padding-bottom"))+parseFloat(g.viewport.css("border-top-width"))+parseFloat(g.viewport.css("border-bottom-width")):"padding-box"===g.viewport.css("box-sizing")&&(e+=parseFloat(g.viewport.css("padding-top"))+parseFloat(g.viewport.css("padding-bottom"))),e},f=function(){var t="100%";return 0<g.settings.slideWidth&&(t="horizontal"===g.settings.mode?g.settings.maxSlides*g.settings.slideWidth+(g.settings.maxSlides-1)*g.settings.slideMargin:g.settings.slideWidth),t},m=function(){var t=g.settings.slideWidth,e=g.viewport.width();if(0===g.settings.slideWidth||g.settings.slideWidth>e&&!g.carousel||"vertical"===g.settings.mode)t=e;else if(1<g.settings.maxSlides&&"horizontal"===g.settings.mode){if(e>g.maxThreshold)return t;e<g.minThreshold?t=(e-g.settings.slideMargin*(g.settings.minSlides-1))/g.settings.minSlides:g.settings.shrinkItems&&(t=Math.floor((e+g.settings.slideMargin)/Math.ceil((e+g.settings.slideMargin)/(t+g.settings.slideMargin))-g.settings.slideMargin))}return t},w=function(){var t=0,e=0,i=0;if(0<g.settings.moveSlides){if(!g.settings.infiniteLoop){for(;e<g.children.length;)++t,e=i+r(),i+=g.settings.moveSlides<=r()?g.settings.moveSlides:r();return i}t=Math.ceil(g.children.length/x())}else t=Math.ceil(g.children.length/r());return t},x=function(){return 0<g.settings.moveSlides&&g.settings.moveSlides<=r()?g.settings.moveSlides:r()},S=function(){var t,e,i;g.children.length>g.settings.maxSlides&&g.active.last&&!g.settings.infiniteLoop?"horizontal"===g.settings.mode?(t=(e=g.children.last()).position(),C(-(t.left-(g.viewport.width()-e.outerWidth())),"reset",0)):"vertical"===g.settings.mode&&(i=g.children.length-g.settings.minSlides,t=g.children.eq(i).position(),C(-t.top,"reset",0)):(t=g.children.eq(g.active.index*x()).position(),g.active.index===w()-1&&(g.active.last=!0),void 0!==t&&("horizontal"===g.settings.mode?C(-t.left,"reset",0):"vertical"===g.settings.mode&&C(-t.top,"reset",0)))},C=function(t,e,i,n){var s,o;g.usingCSS?(o="vertical"===g.settings.mode?"translate3d(0, "+t+"px, 0)":"translate3d("+t+"px, 0, 0)",p.css("-"+g.cssPrefix+"-transition-duration",i/1e3+"s"),"slide"===e?(p.css(g.animProp,o),0!==i?p.on("transitionend webkitTransitionEnd oTransitionEnd MSTransitionEnd",function(t){R(t.target).is(p)&&(p.off("transitionend webkitTransitionEnd oTransitionEnd MSTransitionEnd"),q())}):q()):"reset"===e?p.css(g.animProp,o):"ticker"===e&&(p.css("-"+g.cssPrefix+"-transition-timing-function","linear"),p.css(g.animProp,o),0!==i?p.on("transitionend webkitTransitionEnd oTransitionEnd MSTransitionEnd",function(t){R(t.target).is(p)&&(p.off("transitionend webkitTransitionEnd oTransitionEnd MSTransitionEnd"),C(n.resetValue,"reset",0),O())}):(C(n.resetValue,"reset",0),O()))):((s={})[g.animProp]=t,"slide"===e?p.animate(s,i,g.settings.easing,function(){q()}):"reset"===e?p.css(g.animProp,t):"ticker"===e&&p.animate(s,i,"linear",function(){C(n.resetValue,"reset",0),O()}))},b=function(){g.settings.pagerCustom?g.pagerEl=R(g.settings.pagerCustom):(g.pagerEl=R('<div class="w2dc-bx-pager" />'),g.settings.pagerSelector?R(g.settings.pagerSelector).html(g.pagerEl):g.controls.el.addClass("w2dc-bx-has-pager").append(g.pagerEl),t()),g.pagerEl.on("click touchend","a",z)},T=function(){g.controls.next=R('<a class="w2dc-bx-next" href="">'+g.settings.nextText+"</a>"),g.controls.prev=R('<a class="w2dc-bx-prev" href="">'+g.settings.prevText+"</a>"),g.controls.next.on("click touchend",E),g.controls.prev.on("click touchend",M),g.settings.nextSelector&&R(g.settings.nextSelector).append(g.controls.next),g.settings.prevSelector&&R(g.settings.prevSelector).append(g.controls.prev),g.settings.nextSelector||g.settings.prevSelector||(g.controls.directionEl=R('<div class="w2dc-bx-controls-direction" />'),g.controls.directionEl.append(g.controls.prev).append(g.controls.next),g.controls.el.addClass("w2dc-bx-has-controls-direction").append(g.controls.directionEl))},k=function(){g.controls.start=R('<div class="w2dc-bx-controls-auto-item"><a class="w2dc-bx-start" href="">'+g.settings.startText+"</a></div>"),g.controls.stop=R('<div class="w2dc-bx-controls-auto-item"><a class="w2dc-bx-stop" href="">'+g.settings.stopText+"</a></div>"),g.controls.autoEl=R('<div class="w2dc-bx-controls-auto" />'),g.controls.autoEl.on("click",".w2dc-bx-start",y),g.controls.autoEl.on("click",".w2dc-bx-stop",I),g.settings.autoControlsCombine?g.controls.autoEl.append(g.controls.start):g.controls.autoEl.append(g.controls.start).append(g.controls.stop),g.settings.autoControlsSelector?R(g.settings.autoControlsSelector).html(g.controls.autoEl):g.controls.el.addClass("w2dc-bx-has-controls-auto").append(g.controls.autoEl),D(g.settings.autoStart?"stop":"start")},P=function(){g.children.each(function(t){var e=R(this).find("img:first").attr("title");void 0!==e&&(""+e).length&&R(this).append('<div class="w2dc-bx-caption"><span>'+e+"</span></div>")})},E=function(t){t.preventDefault(),g.controls.el.hasClass("disabled")||(g.settings.auto&&g.settings.stopAutoOnClick&&p.stopAuto(),p.goToNextSlide())},M=function(t){t.preventDefault(),g.controls.el.hasClass("disabled")||(g.settings.auto&&g.settings.stopAutoOnClick&&p.stopAuto(),p.goToPrevSlide())},y=function(t){p.startAuto(),t.preventDefault()},I=function(t){p.stopAuto(),t.preventDefault()},z=function(t){var e,i;t.preventDefault(),g.controls.el.hasClass("disabled")||(g.settings.auto&&g.settings.stopAutoOnClick&&p.stopAuto(),void 0!==(e=R(t.currentTarget)).attr("data-slide-index")&&(i=parseInt(e.attr("data-slide-index")))!==g.active.index&&p.goToSlide(i))},A=function(i){var t=g.children.length;if("short"===g.settings.pagerType)return 1<g.settings.maxSlides&&(t=Math.ceil(g.children.length/g.settings.maxSlides)),void g.pagerEl.html(i+1+g.settings.pagerShortSeparator+t);g.pagerEl.find("a").removeClass("active"),g.pagerEl.each(function(t,e){R(e).find("a").eq(i).addClass("active")})},q=function(){var t;g.settings.infiniteLoop&&(t="",0===g.active.index?t=g.children.eq(0).position():g.active.index===w()-1&&g.carousel?t=g.children.eq((w()-1)*x()).position():g.active.index===g.children.length-1&&(t=g.children.eq(g.children.length-1).position()),t&&("horizontal"===g.settings.mode?C(-t.left,"reset",0):"vertical"===g.settings.mode&&C(-t.top,"reset",0))),g.working=!1,g.settings.onSlideAfter.call(p,g.children.eq(g.active.index),g.oldIndex,g.active.index)},D=function(t){g.settings.autoControlsCombine?g.controls.autoEl.html(g.controls[t]):(g.controls.autoEl.find("a").removeClass("active"),g.controls.autoEl.find("a:not(.w2dc-bx-"+t+")").addClass("active"))},H=function(){1===w()?(g.controls.prev.addClass("disabled"),g.controls.next.addClass("disabled")):!g.settings.infiniteLoop&&g.settings.hideControlOnEnd&&(0===g.active.index?(g.controls.prev.addClass("disabled"),g.controls.next.removeClass("disabled")):g.active.index===w()-1?(g.controls.next.addClass("disabled"),g.controls.prev.removeClass("disabled")):(g.controls.prev.removeClass("disabled"),g.controls.next.removeClass("disabled")))},W=function(){0<g.settings.autoDelay?setTimeout(p.startAuto,g.settings.autoDelay):(p.startAuto(),R(window).focus(a).blur(l)),g.settings.autoHover&&p.hover(function(){g.interval&&(p.stopAuto(!0),g.autoPaused=!0)},function(){g.autoPaused&&(p.startAuto(!0),g.autoPaused=null)})},L=function(){var t,e,i,n,s,o,r,a,l=0;"next"===g.settings.autoDirection?p.append(g.children.clone().addClass("w2dc-bx-clone")):(p.prepend(g.children.clone().addClass("w2dc-bx-clone")),t=g.children.first().position(),l="horizontal"===g.settings.mode?-t.left:-t.top),C(l,"reset",0),g.settings.pager=!1,g.settings.controls=!1,g.settings.autoControls=!1,g.settings.tickerHover&&(g.usingCSS?(n="horizontal"===g.settings.mode?4:5,g.viewport.hover(function(){e=p.css("-"+g.cssPrefix+"-transform"),i=parseFloat(e.split(",")[n]),C(i,"reset",0)},function(){a=0,g.children.each(function(t){a+="horizontal"===g.settings.mode?R(this).outerWidth(!0):R(this).outerHeight(!0)}),s=g.settings.speed/a,o="horizontal"===g.settings.mode?"left":"top",r=s*(a-Math.abs(parseInt(i))),O(r)})):g.viewport.hover(function(){p.stop()},function(){a=0,g.children.each(function(t){a+="horizontal"===g.settings.mode?R(this).outerWidth(!0):R(this).outerHeight(!0)}),s=g.settings.speed/a,o="horizontal"===g.settings.mode?"left":"top",r=s*(a-Math.abs(parseInt(p.css(o)))),O(r)})),O()},O=function(t){var e,i,n=t||g.settings.speed,s={left:0,top:0},o={left:0,top:0};"next"===g.settings.autoDirection?s=p.find(".w2dc-bx-clone").first().position():o=g.children.first().position(),e="horizontal"===g.settings.mode?-s.left:-s.top,i="horizontal"===g.settings.mode?-o.left:-o.top,C(e,"ticker",n,{resetValue:i})},F=function(t){var e,i,n,s,o=document.activeElement.tagName.toLowerCase();if(null==new RegExp(o,["i"]).exec("input|textarea")&&(e=p,i=R(window),n={top:i.scrollTop(),left:i.scrollLeft()},s=e.offset(),n.right=n.left+i.width(),n.bottom=n.top+i.height(),s.right=s.left+e.outerWidth(),s.bottom=s.top+e.outerHeight(),!(n.right<s.left||n.left>s.right||n.bottom<s.top||n.top>s.bottom))){if(39===t.keyCode)return E(t),!1;if(37===t.keyCode)return M(t),!1}},_=function(){g.touch={start:{x:0,y:0},end:{x:0,y:0}},g.viewport.on("touchstart MSPointerDown pointerdown",N),g.viewport.on("click",".w2dc_bxslider a",function(t){g.viewport.hasClass("click-disabled")&&(t.preventDefault(),g.viewport.removeClass("click-disabled"))})},N=function(t){if("touchstart"===t.type||0===t.button)if(t.preventDefault(),g.controls.el.addClass("disabled"),g.working)g.controls.el.removeClass("disabled");else{g.touch.originalPos=p.position();var e=t.originalEvent,i=void 0!==e.changedTouches?e.changedTouches:[e];if("function"==typeof PointerEvent&&void 0===e.pointerId)return;g.touch.start.x=i[0].pageX,g.touch.start.y=i[0].pageY,g.viewport.get(0).setPointerCapture&&(g.pointerId=e.pointerId,g.viewport.get(0).setPointerCapture(g.pointerId)),g.originalClickTarget=e.originalTarget||e.target,g.originalClickButton=e.button,g.originalClickButtons=e.buttons,g.originalEventType=e.type,g.hasMove=!1,g.viewport.on("touchmove MSPointerMove pointermove",X),g.viewport.on("touchend MSPointerUp pointerup",Y),g.viewport.on("MSPointerCancel pointercancel",B)}},B=function(t){t.preventDefault(),C(g.touch.originalPos.left,"reset",0),g.controls.el.removeClass("disabled"),g.viewport.off("MSPointerCancel pointercancel",B),g.viewport.off("touchmove MSPointerMove pointermove",X),g.viewport.off("touchend MSPointerUp pointerup",Y),g.viewport.get(0).releasePointerCapture&&"undefined"==typeof w2dc_lightbox&&g.viewport.get(0).releasePointerCapture(g.pointerId)},X=function(t){var e=t.originalEvent,i=void 0!==e.changedTouches?e.changedTouches:[e],n=Math.abs(i[0].pageX-g.touch.start.x),s=Math.abs(i[0].pageY-g.touch.start.y),o=0,r=0;g.hasMove=!0,(s<3*n&&g.settings.preventDefaultSwipeX||n<3*s&&g.settings.preventDefaultSwipeY)&&t.preventDefault(),"touchmove"!==t.type&&t.preventDefault(),"fade"!==g.settings.mode&&g.settings.oneToOneTouch&&(o="horizontal"===g.settings.mode?(r=i[0].pageX-g.touch.start.x,g.touch.originalPos.left+r):(r=i[0].pageY-g.touch.start.y,g.touch.originalPos.top+r),C(o,"reset",0))},Y=function(t){t.preventDefault(),g.viewport.off("touchmove MSPointerMove pointermove",X),g.controls.el.removeClass("disabled");var e=t.originalEvent,i=void 0!==e.changedTouches?e.changedTouches:[e],n=0,s=0;g.touch.end.x=i[0].pageX,g.touch.end.y=i[0].pageY,"fade"===g.settings.mode?(s=Math.abs(g.touch.start.x-g.touch.end.x))>=g.settings.swipeThreshold&&(g.touch.start.x>g.touch.end.x?p.goToNextSlide():p.goToPrevSlide(),p.stopAuto()):(n="horizontal"===g.settings.mode?(s=g.touch.end.x-g.touch.start.x,g.touch.originalPos.left):(s=g.touch.end.y-g.touch.start.y,g.touch.originalPos.top),(g.settings.infiniteLoop||!(0===g.active.index&&0<s||g.active.last&&s<0))&&Math.abs(s)>=g.settings.swipeThreshold?(s<0?p.goToNextSlide():p.goToPrevSlide(),p.stopAuto()):C(n,"reset",200)),g.viewport.off("touchend MSPointerUp pointerup",Y),g.viewport.get(0).releasePointerCapture&&"undefined"==typeof w2dc_lightbox&&g.viewport.get(0).releasePointerCapture(g.pointerId),!1!==g.hasMove||0!==g.originalClickButton&&"touchstart"!==g.originalEventType||R(g.originalClickTarget).trigger({type:"click",button:g.originalClickButton,buttons:g.originalClickButtons})},V=function(t){var e,i;g.initialized&&(g.working?window.setTimeout(V,10):(e=R(window).width(),i=R(window).height(),n===e&&s===i||(n=e,s=i,p.redrawSlider(),g.settings.onSliderResize.call(p,g.active.index))))};return p.goToSlide=function(t,e){var i,n,s,o,r,a=!0,l=0,d={left:0,top:0},c=null;if(g.oldIndex=g.active.index,g.active.index=(r=t)<0?g.settings.infiniteLoop?w()-1:g.active.index:r>=w()?g.settings.infiniteLoop?0:g.active.index:r,!g.working&&g.active.index!==g.oldIndex){if(g.working=!0,void 0!==(a=g.settings.onSlideBefore.call(p,g.children.eq(g.active.index),g.oldIndex,g.active.index))&&!a)return g.active.index=g.oldIndex,void(g.working=!1);"next"===e?g.settings.onSlideNext.call(p,g.children.eq(g.active.index),g.oldIndex,g.active.index)||(a=!1):"prev"===e&&(g.settings.onSlidePrev.call(p,g.children.eq(g.active.index),g.oldIndex,g.active.index)||(a=!1)),g.active.last=g.active.index>=w()-1,(g.settings.pager||g.settings.pagerCustom)&&A(g.active.index),g.settings.controls&&H(),"fade"===g.settings.mode?(g.settings.adaptiveHeight&&g.viewport.height()!==v()&&g.viewport.animate({height:v()},g.settings.adaptiveHeightSpeed),g.children.filter(":visible").fadeOut(g.settings.speed).css({zIndex:0}),g.children.eq(g.active.index).css("zIndex",g.settings.slideZIndex+1).fadeIn(g.settings.speed,function(){R(this).css("zIndex",g.settings.slideZIndex),q()})):(g.settings.adaptiveHeight&&g.viewport.height()!==v()&&g.viewport.animate({height:v()},g.settings.adaptiveHeightSpeed),!g.settings.infiniteLoop&&g.carousel&&g.active.last?"horizontal"===g.settings.mode?(d=(c=g.children.eq(g.children.length-1)).position(),l=g.viewport.width()-c.outerWidth()):(i=g.children.length-g.settings.minSlides,d=g.children.eq(i).position()):g.carousel&&g.active.last&&"prev"===e?(n=1===g.settings.moveSlides?g.settings.maxSlides-x():(w()-1)*x()-(g.children.length-g.settings.maxSlides),d=(c=p.children(".w2dc-bx-clone").eq(n)).position()):"next"===e&&0===g.active.index?(d=p.find("> .w2dc-bx-clone").eq(g.settings.maxSlides).position(),g.active.last=!1):0<=t&&(o=t*parseInt(x()),d=g.children.eq(o).position()),void 0!==d&&(s="horizontal"===g.settings.mode?-(d.left-l):-d.top,C(s,"slide",g.settings.speed)),g.working=!1),g.settings.ariaHidden&&u(g.active.index*x())}},p.goToNextSlide=function(){var t;!g.settings.infiniteLoop&&g.active.last||!0!==g.working&&(t=parseInt(g.active.index)+1,p.goToSlide(t,"next"))},p.goToPrevSlide=function(){var t;!g.settings.infiniteLoop&&0===g.active.index||!0===g.working||(t=parseInt(g.active.index)-1,p.goToSlide(t,"prev"))},p.startAuto=function(t){g.interval||(g.interval=setInterval(function(){"next"===g.settings.autoDirection?p.goToNextSlide():p.goToPrevSlide()},g.settings.pause),g.settings.onAutoChange.call(p,!0),g.settings.autoControls&&!0!==t&&D("stop"))},p.stopAuto=function(t){g.autoPaused&&(g.autoPaused=!1),g.interval&&(clearInterval(g.interval),g.interval=null,g.settings.onAutoChange.call(p,!1),g.settings.autoControls&&!0!==t&&D("start"))},p.getCurrentSlide=function(){return g.active.index},p.getCurrentSlideElement=function(){return g.children.eq(g.active.index)},p.getSlideElement=function(t){return g.children.eq(t)},p.getSlideCount=function(){return g.children.length},p.isWorking=function(){return g.working},p.redrawSlider=function(){g.children.add(p.find(".w2dc-bx-clone")).outerWidth(m()),g.viewport.css("height",v()),g.settings.ticker||S(),g.active.last&&(g.active.index=w()-1),g.active.index>=w()&&(g.active.last=!0),g.settings.pager&&!g.settings.pagerCustom&&(t(),A(g.active.index)),g.settings.ariaHidden&&u(g.active.index*x())},p.destroySlider=function(){g.initialized&&(g.initialized=!1,R(".w2dc-bx-clone",this).remove(),g.children.each(function(){void 0!==R(this).data("origStyle")?R(this).attr("style",R(this).data("origStyle")):R(this).removeAttr("style")}),void 0!==R(this).data("origStyle")?this.attr("style",R(this).data("origStyle")):R(this).removeAttr("style"),R(this).unwrap().unwrap(),g.controls.el&&g.controls.el.remove(),g.controls.next&&g.controls.next.remove(),g.controls.prev&&g.controls.prev.remove(),g.pagerEl&&g.settings.controls&&!g.settings.pagerCustom&&g.pagerEl.remove(),R(".w2dc-bx-caption",this).remove(),g.controls.autoEl&&g.controls.autoEl.remove(),clearInterval(g.interval),g.settings.responsive&&R(window).off("resize",V),g.settings.keyboardEnabled&&R(document).off("keydown",F),R(this).removeData("w2dc_bxslider"),R(window).off("blur",l).off("focus",a))},p.reloadSlider=function(t){void 0!==t&&(e=t),p.destroySlider(),o(),R(p).data("w2dc_bxslider",this)},o(),R(p).data("w2dc_bxslider",this),this}}}(jQuery);






/* ========================================================================
 * Bootstrap: tooltip.js v3.3.5
 * http://getbootstrap.com/javascript/#tooltip
 * Inspired by the original jQuery.tipsy by Jason Frame
 * ========================================================================
 * Copyright 2011-2015 Twitter, Inc.
 * Licensed under MIT (https://github.com/twbs/bootstrap/blob/master/LICENSE)
 * ======================================================================== */
+function ($) {
  'use strict';

  // TOOLTIP PUBLIC CLASS DEFINITION
  // ===============================

  var Tooltip = function (element, options) {
    this.type       = null
    this.options    = null
    this.enabled    = null
    this.timeout    = null
    this.hoverState = null
    this.$element   = null
    this.inState    = null

    this.init('w2dc_tooltip', element, options)
  }

  Tooltip.VERSION  = '3.3.5'

  Tooltip.TRANSITION_DURATION = 150

  Tooltip.DEFAULTS = {
    animation: true,
    placement: 'top',
    selector: false,
    template: '<div class="w2dc-tooltip" role="tooltip"><div class="w2dc-tooltip-arrow"></div><div class="w2dc-tooltip-inner"></div></div>',
    trigger: 'hover focus',
    title: '',
    delay: 0,
    html: false,
    container: false,
    viewport: {
      selector: 'body',
      padding: 0
    }
  }

  Tooltip.prototype.init = function (type, element, options) {
    this.enabled   = true
    this.type      = type
    this.$element  = $(element)
    this.options   = this.getOptions(options)
    this.$viewport = this.options.viewport && $($.isFunction(this.options.viewport) ? this.options.viewport.call(this, this.$element) : (this.options.viewport.selector || this.options.viewport))
    this.inState   = { click: false, hover: false, focus: false }

    if (this.$element[0] instanceof document.constructor && !this.options.selector) {
      throw new Error('`selector` option must be specified when initializing ' + this.type + ' on the window.document object!')
    }

    var triggers = this.options.trigger.split(' ')

    for (var i = triggers.length; i--;) {
      var trigger = triggers[i]

      if (trigger == 'click') {
        this.$element.on('click.' + this.type, this.options.selector, $.proxy(this.toggle, this))
      } else if (trigger != 'manual') {
        var eventIn  = trigger == 'hover' ? 'mouseenter' : 'focusin'
        var eventOut = trigger == 'hover' ? 'mouseleave' : 'focusout'

        this.$element.on(eventIn  + '.' + this.type, this.options.selector, $.proxy(this.enter, this))
        this.$element.on(eventOut + '.' + this.type, this.options.selector, $.proxy(this.leave, this))
      }
    }

    this.options.selector ?
      (this._options = $.extend({}, this.options, { trigger: 'manual', selector: '' })) :
      this.fixTitle()
  }

  Tooltip.prototype.getDefaults = function () {
    return Tooltip.DEFAULTS
  }

  Tooltip.prototype.getOptions = function (options) {
    options = $.extend({}, this.getDefaults(), this.$element.data(), options)

    if (options.delay && typeof options.delay == 'number') {
      options.delay = {
        show: options.delay,
        hide: options.delay
      }
    }

    return options
  }

  Tooltip.prototype.getDelegateOptions = function () {
    var options  = {}
    var defaults = this.getDefaults()

    this._options && $.each(this._options, function (key, value) {
      if (defaults[key] != value) options[key] = value
    })

    return options
  }

  Tooltip.prototype.enter = function (obj) {
    var self = obj instanceof this.constructor ?
      obj : $(obj.currentTarget).data('bs.' + this.type)

    if (!self) {
      self = new this.constructor(obj.currentTarget, this.getDelegateOptions())
      $(obj.currentTarget).data('bs.' + this.type, self)
    }

    if (obj instanceof $.Event) {
      self.inState[obj.type == 'focusin' ? 'focus' : 'hover'] = true
    }

    if (self.tip().hasClass('w2dc-in') || self.hoverState == 'in') {
      self.hoverState = 'in'
      return
    }

    clearTimeout(self.timeout)

    self.hoverState = 'in'

    if (!self.options.delay || !self.options.delay.show) return self.show()

    self.timeout = setTimeout(function () {
      if (self.hoverState == 'in') self.show()
    }, self.options.delay.show)
  }

  Tooltip.prototype.isInStateTrue = function () {
    for (var key in this.inState) {
      if (this.inState[key]) return true
    }

    return false
  }

  Tooltip.prototype.leave = function (obj) {
    var self = obj instanceof this.constructor ?
      obj : $(obj.currentTarget).data('bs.' + this.type)

    if (!self) {
      self = new this.constructor(obj.currentTarget, this.getDelegateOptions())
      $(obj.currentTarget).data('bs.' + this.type, self)
    }

    if (obj instanceof $.Event) {
      self.inState[obj.type == 'focusout' ? 'focus' : 'hover'] = false
    }

    if (self.isInStateTrue()) return

    clearTimeout(self.timeout)

    self.hoverState = 'out'

    if (!self.options.delay || !self.options.delay.hide) return self.hide()

    self.timeout = setTimeout(function () {
      if (self.hoverState == 'out') self.hide()
    }, self.options.delay.hide)
  }

  Tooltip.prototype.show = function () {
    var e = $.Event('show.bs.' + this.type)

    if (this.hasContent() && this.enabled) {
      this.$element.trigger(e)

      var inDom = $.contains(this.$element[0].ownerDocument.documentElement, this.$element[0])
      if (e.isDefaultPrevented() || !inDom) return
      var that = this

      var $tip = this.tip()

      var tipId = this.getUID(this.type)

      this.setContent()
      $tip.attr('id', tipId)
      this.$element.attr('aria-describedby', tipId)

      if (this.options.animation) $tip.addClass('w2dc-fade')

      var placement = typeof this.options.placement == 'function' ?
        this.options.placement.call(this, $tip[0], this.$element[0]) :
        this.options.placement

      var autoToken = /\s?auto?\s?/i
      var autoPlace = autoToken.test(placement)
      if (autoPlace) placement = placement.replace(autoToken, '') || 'top'

      $tip
        .detach()
        .css({ top: 0, left: 0, display: 'block' })
        .addClass('w2dc-'+placement)
        .data('bs.' + this.type, this)

      this.options.container ? $tip.appendTo(this.options.container) : $tip.insertAfter(this.$element)
      this.$element.trigger('inserted.bs.' + this.type)

      var pos          = this.getPosition()
      var actualWidth  = $tip[0].offsetWidth
      var actualHeight = $tip[0].offsetHeight

      if (autoPlace) {
        var orgPlacement = placement
        var viewportDim = this.getPosition(this.$viewport)

        placement = placement == 'bottom' && pos.bottom + actualHeight > viewportDim.bottom ? 'top'    :
                    placement == 'top'    && pos.top    - actualHeight < viewportDim.top    ? 'bottom' :
                    placement == 'right'  && pos.right  + actualWidth  > viewportDim.width  ? 'left'   :
                    placement == 'left'   && pos.left   - actualWidth  < viewportDim.left   ? 'right'  :
                    placement

        $tip
          .removeClass(orgPlacement)
          .addClass(placement)
      }

      var calculatedOffset = this.getCalculatedOffset(placement, pos, actualWidth, actualHeight)

      this.applyPlacement(calculatedOffset, placement)

      var complete = function () {
        var prevHoverState = that.hoverState
        that.$element.trigger('shown.bs.' + that.type)
        that.hoverState = null

        if (prevHoverState == 'out') that.leave(that)
      }

      $.support.transition && this.$tip.hasClass('w2dc-fade') ?
        $tip
          .one('bsTransitionEnd', complete)
          .emulateTransitionEnd(Tooltip.TRANSITION_DURATION) :
        complete()
    }
  }

  Tooltip.prototype.applyPlacement = function (offset, placement) {
    var $tip   = this.tip()
    var width  = $tip[0].offsetWidth
    var height = $tip[0].offsetHeight

    // manually read margins because getBoundingClientRect includes difference
    var marginTop = parseInt($tip.css('margin-top'), 10)
    var marginLeft = parseInt($tip.css('margin-left'), 10)

    // we must check for NaN for ie 8/9
    if (isNaN(marginTop))  marginTop  = 0
    if (isNaN(marginLeft)) marginLeft = 0

    offset.top  += marginTop
    offset.left += marginLeft

    // $.fn.offset doesn't round pixel values
    // so we use setOffset directly with our own function B-0
    $.offset.setOffset($tip[0], $.extend({
      using: function (props) {
        $tip.css({
          top: Math.round(props.top),
          left: Math.round(props.left)
        })
      }
    }, offset), 0)

    $tip.addClass('w2dc-in')

    // check to see if placing tip in new offset caused the tip to resize itself
    var actualWidth  = $tip[0].offsetWidth
    var actualHeight = $tip[0].offsetHeight

    if (placement == 'top' && actualHeight != height) {
      offset.top = offset.top + height - actualHeight
    }

    var delta = this.getViewportAdjustedDelta(placement, offset, actualWidth, actualHeight)

    if (delta.left) offset.left += delta.left
    else offset.top += delta.top

    var isVertical          = /top|bottom/.test(placement)
    var arrowDelta          = isVertical ? delta.left * 2 - width + actualWidth : delta.top * 2 - height + actualHeight
    var arrowOffsetPosition = isVertical ? 'offsetWidth' : 'offsetHeight'

    $tip.offset(offset)
    this.replaceArrow(arrowDelta, $tip[0][arrowOffsetPosition], isVertical)
  }

  Tooltip.prototype.replaceArrow = function (delta, dimension, isVertical) {
    this.arrow()
      .css(isVertical ? 'left' : 'top', 50 * (1 - delta / dimension) + '%')
      .css(isVertical ? 'top' : 'left', '')
  }

  Tooltip.prototype.setContent = function () {
    var $tip  = this.tip()
    var title = this.getTitle()

    $tip.find('.w2dc-tooltip-inner')[this.options.html ? 'html' : 'text'](title)
    $tip.removeClass('w2dc-fade w2dc-in w2dc-top w2dc-bottom w2dc-left w2dc-right')
  }

  Tooltip.prototype.hide = function (callback) {
    var that = this
    var $tip = $(this.$tip)
    var e    = $.Event('hide.bs.' + this.type)

    function complete() {
      if (that.hoverState != 'in') $tip.detach()
      that.$element
        .removeAttr('aria-describedby')
        .trigger('hidden.bs.' + that.type)
      callback && callback()
    }

    this.$element.trigger(e)

    if (e.isDefaultPrevented()) return

    $tip.removeClass('w2dc-in')

    $.support.transition && $tip.hasClass('w2dc-fade') ?
      $tip
        .one('bsTransitionEnd', complete)
        .emulateTransitionEnd(Tooltip.TRANSITION_DURATION) :
      complete()

    this.hoverState = null

    return this
  }

  Tooltip.prototype.fixTitle = function () {
    var $e = this.$element
    if ($e.attr('title') || typeof $e.attr('data-original-title') != 'string') {
      $e.attr('data-original-title', $e.attr('title') || '').attr('title', '')
    }
  }

  Tooltip.prototype.hasContent = function () {
    return this.getTitle()
  }

  Tooltip.prototype.getPosition = function ($element) {
    $element   = $element || this.$element

    var el     = $element[0]
    var isBody = el.tagName == 'BODY'

    var elRect    = el.getBoundingClientRect()
    if (elRect.width == null) {
      // width and height are missing in IE8, so compute them manually; see https://github.com/twbs/bootstrap/issues/14093
      elRect = $.extend({}, elRect, { width: elRect.right - elRect.left, height: elRect.bottom - elRect.top })
    }
    var elOffset  = isBody ? { top: 0, left: 0 } : $element.offset()
    var scroll    = { scroll: isBody ? document.documentElement.scrollTop || document.body.scrollTop : $element.scrollTop() }
    var outerDims = isBody ? { width: $(window).width(), height: $(window).height() } : null

    return $.extend({}, elRect, scroll, outerDims, elOffset)
  }

  Tooltip.prototype.getCalculatedOffset = function (placement, pos, actualWidth, actualHeight) {
    return placement == 'bottom' ? { top: pos.top + pos.height,   left: pos.left + pos.width / 2 - actualWidth / 2 } :
           placement == 'top'    ? { top: pos.top - actualHeight, left: pos.left + pos.width / 2 - actualWidth / 2 } :
           placement == 'left'   ? { top: pos.top + pos.height / 2 - actualHeight / 2, left: pos.left - actualWidth } :
        /* placement == 'right' */ { top: pos.top + pos.height / 2 - actualHeight / 2, left: pos.left + pos.width }

  }

  Tooltip.prototype.getViewportAdjustedDelta = function (placement, pos, actualWidth, actualHeight) {
    var delta = { top: 0, left: 0 }
    if (!this.$viewport) return delta

    var viewportPadding = this.options.viewport && this.options.viewport.padding || 0
    var viewportDimensions = this.getPosition(this.$viewport)

    if (/right|left/.test(placement)) {
      var topEdgeOffset    = pos.top - viewportPadding - viewportDimensions.scroll
      var bottomEdgeOffset = pos.top + viewportPadding - viewportDimensions.scroll + actualHeight
      if (topEdgeOffset < viewportDimensions.top) { // top overflow
        delta.top = viewportDimensions.top - topEdgeOffset
      } else if (bottomEdgeOffset > viewportDimensions.top + viewportDimensions.height) { // bottom overflow
        delta.top = viewportDimensions.top + viewportDimensions.height - bottomEdgeOffset
      }
    } else {
      var leftEdgeOffset  = pos.left - viewportPadding
      var rightEdgeOffset = pos.left + viewportPadding + actualWidth
      if (leftEdgeOffset < viewportDimensions.left) { // left overflow
        delta.left = viewportDimensions.left - leftEdgeOffset
      } else if (rightEdgeOffset > viewportDimensions.right) { // right overflow
        delta.left = viewportDimensions.left + viewportDimensions.width - rightEdgeOffset
      }
    }

    return delta
  }

  Tooltip.prototype.getTitle = function () {
    var title
    var $e = this.$element
    var o  = this.options

    title = $e.attr('data-original-title')
      || (typeof o.title == 'function' ? o.title.call($e[0]) :  o.title)

    return title
  }

  Tooltip.prototype.getUID = function (prefix) {
    do prefix += ~~(Math.random() * 1000000)
    while (document.getElementById(prefix))
    return prefix
  }

  Tooltip.prototype.tip = function () {
    if (!this.$tip) {
      this.$tip = $(this.options.template)
      if (this.$tip.length != 1) {
        throw new Error(this.type + ' `template` option must consist of exactly 1 top-level element!')
      }
    }
    return this.$tip
  }

  Tooltip.prototype.arrow = function () {
    return (this.$arrow = this.$arrow || this.tip().find('.w2dc-tooltip-arrow'))
  }

  Tooltip.prototype.enable = function () {
    this.enabled = true
  }

  Tooltip.prototype.disable = function () {
    this.enabled = false
  }

  Tooltip.prototype.toggleEnabled = function () {
    this.enabled = !this.enabled
  }

  Tooltip.prototype.toggle = function (e) {
    var self = this
    if (e) {
      self = $(e.currentTarget).data('bs.' + this.type)
      if (!self) {
        self = new this.constructor(e.currentTarget, this.getDelegateOptions())
        $(e.currentTarget).data('bs.' + this.type, self)
      }
    }

    if (e) {
      self.inState.click = !self.inState.click
      if (self.isInStateTrue()) self.enter(self)
      else self.leave(self)
    } else {
      self.tip().hasClass('w2dc-in') ? self.leave(self) : self.enter(self)
    }
  }

  Tooltip.prototype.destroy = function () {
    var that = this
    clearTimeout(this.timeout)
    this.hide(function () {
      that.$element.off('.' + that.type).removeData('bs.' + that.type)
      if (that.$tip) {
        that.$tip.detach()
      }
      that.$tip = null
      that.$arrow = null
      that.$viewport = null
    })
  }


  // TOOLTIP PLUGIN DEFINITION
  // =========================

  function Plugin(option) {
    return this.each(function () {
      var $this   = $(this)
      var data    = $this.data('bs.w2dc_tooltip')
      var options = typeof option == 'object' && option

      if (!data && /destroy|hide/.test(option)) return
      if (!data) $this.data('bs.w2dc_tooltip', (data = new Tooltip(this, options)))
      if (typeof option == 'string') data[option]()
    })
  }

  var old = $.fn.w2dc_tooltip

  $.fn.w2dc_tooltip             = Plugin
  $.fn.w2dc_tooltip.Constructor = Tooltip


  // TOOLTIP NO CONFLICT
  // ===================

  $.fn.w2dc_tooltip.noConflict = function () {
    $.fn.w2dc_tooltip = old
    return this
  }

}(jQuery);

/* ========================================================================
 * Bootstrap: popover.js v3.3.5
 * http://getbootstrap.com/javascript/#popovers
 * ========================================================================
 * Copyright 2011-2015 Twitter, Inc.
 * Licensed under MIT (https://github.com/twbs/bootstrap/blob/master/LICENSE)
 * ======================================================================== */
+function ($) {
  'use strict';

  // POPOVER PUBLIC CLASS DEFINITION
  // ===============================

  var Popover = function (element, options) {
    this.init('w2dc_popover', element, options)
  }

  if (!$.fn.w2dc_tooltip) throw new Error('Popover requires tooltip.js')

  Popover.VERSION  = '3.3.5'

  Popover.DEFAULTS = $.extend({}, $.fn.w2dc_tooltip.Constructor.DEFAULTS, {
    placement: 'right',
    trigger: 'click',
    content: '',
    template: '<div class="w2dc-popover" role="tooltip"><div class="w2dc-arrow"></div><h3 class="w2dc-popover-title"></h3><div class="w2dc-popover-content"></div></div>'
  })


  // NOTE: POPOVER EXTENDS tooltip.js
  // ================================

  Popover.prototype = $.extend({}, $.fn.w2dc_tooltip.Constructor.prototype)

  Popover.prototype.constructor = Popover

  Popover.prototype.getDefaults = function () {
    return Popover.DEFAULTS
  }

  Popover.prototype.setContent = function () {
    var $tip    = this.tip()
    var title   = this.getTitle()
    var content = this.getContent()

    $tip.find('.w2dc-popover-title')[this.options.html ? 'html' : 'text'](title)
    $tip.find('.w2dc-popover-content').children().detach().end()[ // we use append for html objects to maintain js events
      this.options.html ? (typeof content == 'string' ? 'html' : 'append') : 'text'
    ](content)

    $tip.removeClass('w2dc-fade w2dc-top w2dc-bottom w2dc-left w2dc-right w2dc-in')

    // IE8 doesn't accept hiding via the `:empty` pseudo selector, we have to do
    // this manually by checking the contents.
    if (!$tip.find('.w2dc-popover-title').html()) $tip.find('.w2dc-popover-title').hide()
  }

  Popover.prototype.hasContent = function () {
    return this.getTitle() || this.getContent()
  }

  Popover.prototype.getContent = function () {
    var $e = this.$element
    var o  = this.options

    return $e.attr('data-content')
      || (typeof o.content == 'function' ?
            o.content.call($e[0]) :
            o.content)
  }

  Popover.prototype.arrow = function () {
    return (this.$arrow = this.$arrow || this.tip().find('.arrow'))
  }
  // POPOVER PLUGIN DEFINITION
  // =========================

  function Plugin(option) {
    return this.each(function () {
      var $this   = $(this)
      var data    = $this.data('bs.w2dc_popover')
      var options = typeof option == 'object' && option

      if (!data && /destroy|hide/.test(option)) return
      if (!data) $this.data('bs.w2dc_popover', (data = new Popover(this, options)))
      if (typeof option == 'string') data[option]()
    })
  }

  var old = $.fn.w2dc_popover

  $.fn.w2dc_popover             = Plugin
  $.fn.w2dc_popover.Constructor = Popover


  // POPOVER NO CONFLICT
  // ===================

  $.fn.w2dc_popover.noConflict = function () {
    $.fn.popover = old
    return this
  }

}(jQuery);



// jquery.tokenize.js -------------------------------------------------------------------------------------------------------------------------------------------
!function(e){var t={BACKSPACE:8,TAB:9,ENTER:13,ESCAPE:27,ARROW_UP:38,ARROW_DOWN:40},n=null,o="tokenize",s=function(t,n){if(!n.data(o)){var s=new e.tokenize(e.extend({},e.fn.tokenize.defaults,t));n.data(o,s),s.init(n)}return n.data(o)};e.tokenize=function(t){void 0==t&&(t=e.fn.tokenize.defaults),this.options=t},e.extend(e.tokenize.prototype,{init:function(t){var n=this;this.select=t.attr("multiple","multiple").css({margin:0,padding:0,border:0}).hide(),this.container=e("<div />").attr("class",this.select.attr("class")).addClass("Tokenize"),1==this.options.maxElements&&this.container.addClass("OnlyOne"),this.dropdown=e("<ul />").addClass("Dropdown"),this.tokensContainer=e("<ul />").addClass("TokensContainer"),this.options.autosize&&this.tokensContainer.addClass("Autosize"),this.searchToken=e("<li />").addClass("TokenSearch").appendTo(this.tokensContainer),this.searchInput=e("<input />").appendTo(this.searchToken),this.options.searchMaxLength>0&&this.searchInput.attr("maxlength",this.options.searchMaxLength),this.select.prop("disabled")&&this.disable(),this.options.sortable&&("undefined"!=typeof e.ui?this.tokensContainer.sortable({items:"li.Token",cursor:"move",placeholder:"Token MovingShadow",forcePlaceholderSize:!0,update:function(){n.updateOrder()},start:function(){n.searchToken.hide()},stop:function(){n.searchToken.show()}}).disableSelection():(this.options.sortable=!1,console.log("jQuery UI is not loaded, sortable option has been disabled"))),this.container.append(this.tokensContainer).append(this.dropdown).insertAfter(this.select),this.tokensContainer.on("click",function(e){e.stopImmediatePropagation(),n.searchInput.get(0).focus(),n.updatePlaceholder(),n.dropdown.is(":hidden")&&""!=n.searchInput.val()&&n.search()}),this.searchInput.on("blur",function(){n.tokensContainer.removeClass("Focused")}),this.searchInput.on("focus click",function(){n.tokensContainer.addClass("Focused"),n.options.displayDropdownOnFocus&&"select"==n.options.datas&&n.search()}),this.searchInput.on("keydown",function(e){n.resizeSearchInput(),n.keydown(e)}),this.searchInput.on("keyup",function(e){n.keyup(e)}),this.searchInput.on("keypress",function(e){n.keypress(e)}),this.searchInput.on("paste",function(){setTimeout(function(){n.resizeSearchInput()},10),setTimeout(function(){var t=n.searchInput.val().split(",");t.length>1&&e.each(t,function(e,t){n.tokenAdd(t.trim(),"")})},20)}),e(document).on("click",function(){n.dropdownHide(),1==n.options.maxElements&&n.searchInput.val()&&n.tokenAdd(n.searchInput.val(),"")}),this.resizeSearchInput(),this.remap(!0),this.updatePlaceholder()},updateOrder:function(){if(this.options.sortable){var t,n,o=this;e.each(this.tokensContainer.sortable("toArray",{attribute:"data-value"}),function(s,i){n=e('option[value="'+i+'"]',o.select),void 0==t?n.prependTo(o.select):t.after(n),t=n}),this.options.onReorder(this)}},updatePlaceholder:function(){0!=this.options.placeholder&&(void 0==this.placeholder&&(this.placeholder=e("<li />").addClass("Placeholder").html(this.options.placeholder),this.placeholder.insertBefore(e("li:first-child",this.tokensContainer))),0==this.searchInput.val().length&&0==e("li.Token",this.tokensContainer).length?this.placeholder.show():this.placeholder.hide())},dropdownShow:function(){this.dropdown.show()},dropdownPrev:function(){e("li.Hover",this.dropdown).length>0?e("li.Hover",this.dropdown).is("li:first-child")?(e("li.Hover",this.dropdown).removeClass("Hover"),e("li:last-child",this.dropdown).addClass("Hover")):e("li.Hover",this.dropdown).removeClass("Hover").prev().addClass("Hover"):e("li:first",this.dropdown).addClass("Hover")},dropdownNext:function(){e("li.Hover",this.dropdown).length>0?e("li.Hover",this.dropdown).is("li:last-child")?(e("li.Hover",this.dropdown).removeClass("Hover"),e("li:first-child",this.dropdown).addClass("Hover")):e("li.Hover",this.dropdown).removeClass("Hover").next().addClass("Hover"):e("li:first",this.dropdown).addClass("Hover")},dropdownAddItem:function(t,n,o){if(void 0==o&&(o=n),!e('li[data-value="'+t+'"]',this.tokensContainer).length){var s=this,i=e("<li />").attr("data-value",t).attr("data-text",n).html(o).on("click",function(t){t.stopImmediatePropagation(),s.tokenAdd(e(this).attr("data-value"),e(this).attr("data-text"))}).on("mouseover",function(){e(this).addClass("Hover")}).on("mouseout",function(){e("li",s.dropdown).removeClass("Hover")});this.dropdown.append(i),this.options.onDropdownAddItem(t,n,o,this)}return this},dropdownHide:function(){this.dropdownReset(),this.dropdown.hide()},dropdownReset:function(){this.dropdown.html("")},resizeSearchInput:function(){this.searchInput.attr("size",Number(this.searchInput.val().length)+5),this.updatePlaceholder()},resetSearchInput:function(){this.searchInput.val(""),this.resizeSearchInput()},resetPendingTokens:function(){e("li.PendingDelete",this.tokensContainer).removeClass("PendingDelete")},keypress:function(e){String.fromCharCode(e.which)==this.options.delimiter&&(e.preventDefault(),this.tokenAdd(this.searchInput.val(),""))},keydown:function(n){switch(n.keyCode){case t.BACKSPACE:0==this.searchInput.val().length&&(n.preventDefault(),e("li.Token.PendingDelete",this.tokensContainer).length?this.tokenRemove(e("li.Token.PendingDelete").attr("data-value")):e("li.Token:last",this.tokensContainer).addClass("PendingDelete"),this.dropdownHide());break;case t.TAB:case t.ENTER:if(e("li.Hover",this.dropdown).length){var o=e("li.Hover",this.dropdown);n.preventDefault(),this.tokenAdd(o.attr("data-value"),o.attr("data-text"))}else this.searchInput.val()&&(n.preventDefault(),this.tokenAdd(this.searchInput.val(),""));this.resetPendingTokens();break;case t.ESCAPE:this.resetSearchInput(),this.dropdownHide(),this.resetPendingTokens();break;case t.ARROW_UP:n.preventDefault(),this.dropdownPrev();break;case t.ARROW_DOWN:n.preventDefault(),this.dropdownNext();break;default:this.resetPendingTokens()}},keyup:function(e){switch(this.updatePlaceholder(),e.keyCode){case t.TAB:case t.ENTER:case t.ESCAPE:case t.ARROW_UP:case t.ARROW_DOWN:break;case t.BACKSPACE:this.searchInput.val()?this.search():this.dropdownHide();break;default:this.searchInput.val()&&this.search()}},search:function(){var t=this,n=1;if(this.options.maxElements>0&&e("li.Token",this.tokensContainer).length>=this.options.maxElements)return!1;if("select"==this.options.datas){var o=!1,s=new RegExp(this.searchInput.val().replace(/[-[\]{}()*+?.,\\^$|#\s]/g,"\\$&"),"i");this.dropdownReset(),e("option",this.select).not(":selected, :disabled").each(function(){return n<=t.options.nbDropdownElements?void(s.test(e(this).html())&&(t.dropdownAddItem(e(this).attr("value"),e(this).html()),o=!0,n++)):!1}),o?(e("li:first",this.dropdown).addClass("Hover"),this.dropdownShow()):this.dropdownHide()}else this.debounce(function(){e.ajax({url:t.options.datas,data:t.options.searchParam+"="+t.searchInput.val(),dataType:t.options.dataType,success:function(o){return o&&(t.dropdownReset(),e.each(o,function(e,o){if(!(n<=t.options.nbDropdownElements))return!1;var s=void 0;o[t.options.htmlField]&&(s=o[t.options.htmlField]),t.dropdownAddItem(o[t.options.valueField],o[t.options.textField],s),n++}),e("li",t.dropdown).length)?(e("li:first",t.dropdown).addClass("Hover"),t.dropdownShow(),!0):void t.dropdownHide()},error:function(e,t){console.log("Error : "+t)}})},this.options.debounce)},debounce:function(e,t){var o=this,s=arguments,i=function(){e.apply(o,s),n=null};n&&clearTimeout(n),n=setTimeout(i,t||this.options.debounce)},tokenAdd:function(t,n,o){if(t=this.escape(t),void 0==t||""==t)return this;if((void 0==n||""==n)&&(n=t),void 0==o&&(o=!1),this.options.maxElements>0&&e("li.Token",this.tokensContainer).length>=this.options.maxElements)return this.resetSearchInput(),this;var s=this,i=e("<a />").addClass("Close").html("&#215;").on("click",function(e){e.stopImmediatePropagation(),s.tokenRemove(t)});if(e('option[value="'+t+'"]',this.select).length)e('option[value="'+t+'"]',this.select).attr("selected",!0).prop("selected",!0);else{if(!(this.options.newElements||!this.options.newElements&&e('li[data-value="'+t+'"]',this.dropdown).length>0))return this.resetSearchInput(),this;var a=e("<option />").attr("selected",!0).attr("value",t).attr("data-type","custom").prop("selected",!0).html(n);this.select.append(a)}return e('li.Token[data-value="'+t+'"]',this.tokensContainer).length>0?this:(e("<li />").addClass("Token").attr("data-value",t).append("<span>"+n+"</span>").prepend(i).insertBefore(this.searchToken),o||this.options.onAddToken(t,n,this),this.resetSearchInput(),this.dropdownHide(),this.updateOrder(),this)},tokenRemove:function(t){var n=e('option[value="'+t+'"]',this.select);return"custom"==n.attr("data-type")?n.remove():n.removeAttr("selected").prop("selected",!1),e('li.Token[data-value="'+t+'"]',this.tokensContainer).remove(),this.options.onRemoveToken(t,this),this.resizeSearchInput(),this.dropdownHide(),this.updateOrder(),this},clear:function(){var t=this;return e("li.Token",this.tokensContainer).each(function(){t.tokenRemove(e(this).attr("data-value"))}),this.options.onClear(this),this.dropdownHide(),this},disable:function(){return this.select.prop("disabled",!0),this.searchInput.prop("disabled",!0),this.container.addClass("Disabled"),this.options.sortable&&this.tokensContainer.sortable("disable"),this},enable:function(){return this.select.prop("disabled",!1),this.searchInput.prop("disabled",!1),this.container.removeClass("Disabled"),this.options.sortable&&this.tokensContainer.sortable("enable"),this},remap:function(t){var n=this,o=e("option:selected",this.select);return void 0==t&&(t=!1),this.clear(),o.each(function(){n.tokenAdd(e(this).val(),e(this).html(),t)}),this},toArray:function(){var t=[];return e("option:selected",this.select).each(function(){t.push(e(this).val())}),t},escape:function(e){return String(e).replace(/["]/g,function(){return""})}}),e.fn.tokenize=function(t){void 0==t&&(t={});var n=this.filter("select");return n.length>1?(n.each(function(){s(t,e(this))}),n):s(t,e(this))},e.fn.tokenize.defaults={datas:"select",placeholder:!1,searchParam:"search",searchMaxLength:0,debounce:0,delimiter:",",newElements:!0,autosize:!1,nbDropdownElements:10,displayDropdownOnFocus:!1,maxElements:0,sortable:!1,dataType:"json",valueField:"value",textField:"text",htmlField:"html",onAddToken:function(){},onRemoveToken:function(){},onClear:function(){},onReorder:function(){},onDropdownAddItem:function(){}}}(jQuery,"tokenize");
