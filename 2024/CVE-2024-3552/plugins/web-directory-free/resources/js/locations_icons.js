(function($) {
	"use strict";
	
	var location_icon_image_input;
	
	$(function() {
		var location_icon_image_url = locations_icons.locations_icons_url;

		$(document).on("click", ".select_icon_image", function() {
			location_icon_image_input = $(this).parent().find('.icon_image');

			var dialog = $('<div id="select_field_icon_dialog"></div>').dialog({
				dialogClass: 'w2dc-content',
				width: ($(window).width()*0.5),
				height: ($(window).height()*0.8),
				modal: true,
				resizable: false,
				draggable: false,
				title: locations_icons.ajax_dialog_title,
				open: function() {
					w2dc_ajax_loader_show();
					$.ajax({
						type: "POST",
						url: w2dc_js_objects.ajaxurl,
						data: {'action': 'w2dc_select_location_icon_dialog'},
						dataType: 'html',
						success: function(response_from_the_action_function){
							if (response_from_the_action_function != 0) {
								$('#select_field_icon_dialog').html(response_from_the_action_function);
								if (location_icon_image_input.val())
									$(".w2dc-icon[icon_file='"+location_icon_image_input.val()+"']").addClass("w2dc-selected-icon");
							}
						},
						complete: function() {
							w2dc_ajax_loader_hide();
						}
					});
					$(document).on("click", ".ui-widget-overlay", function() { $('#select_field_icon_dialog').remove(); });
				},
				close: function() {
					$('#select_field_icon_dialog').remove();
				}
			});
		});
		$(document).on("click", ".w2dc-icon", function() {
			$(".w2dc-selected-icon").removeClass("w2dc-selected-icon");
			var icon_file = $(this).attr('icon_file');
			w2dc_ajax_loader_show();
			$.ajax({
				type: "POST",
				url: w2dc_js_objects.ajaxurl,
				data: {'action': 'w2dc_select_location_icon', 'icon_file': icon_file, 'location_id': location_icon_image_input.parent().find(".location_id").val()},
				dataType: 'html',
				success: function(response_from_the_action_function){
					if (response_from_the_action_function != 0) {
						if (location_icon_image_input) {
							location_icon_image_input.val(icon_file);
							location_icon_image_input.parent().find(".icon_image_tag").attr('src', location_icon_image_url+icon_file).show();
							location_icon_image_input = false;
						}
					}
				},
				complete: function() {
					$(this).addClass("w2dc-selected-icon");
					$('#select_field_icon_dialog').remove();
					w2dc_ajax_loader_hide();
				}
			});
		});
		$(document).on("click", "#reset_icon", function() {
			$(".w2dc-selected-icon").removeClass("w2dc-selected-icon");
			w2dc_ajax_loader_show();
			$.ajax({
				type: "POST",
				url: w2dc_js_objects.ajaxurl,
				data: {'action': 'w2dc_select_location_icon', 'location_id': location_icon_image_input.parent().find(".location_id").val()},
				dataType: 'html',
				success: function(response_from_the_action_function){
					if (location_icon_image_input) {
						location_icon_image_input.val('');
						location_icon_image_input.parent().find(".icon_image_tag").attr('src', '').hide();
						location_icon_image_input = false;
					}
				},
				complete: function() {
					$('#select_field_icon_dialog').remove();
					w2dc_ajax_loader_hide();
				}
			});
		});
		
		$(document).on("click", "#w2dc-upload-location-featured", function(event) {
			event.preventDefault();
			
			var frame = wp.media({
				title : $(this).data("title"),
				multiple : false,
				library : { type : 'image'},
				button : { text : $(this).data("button")},
			});
			frame.on('select', function() {
				var selection = frame.state().get('selection');
				selection.each(function(attachment) {
					attachment = attachment.toJSON();
					if (attachment.type == 'image') {
						$("#w2dc-location-image").attr("src", attachment.sizes.full.url).show();
						$("#w2dc-location-image-attachment-id").val(attachment.id);
					}
				});
			});
			frame.open();
		});
		$(document).on("click", "#w2dc-remove-location-featured", function(event) {
			event.preventDefault();

			$("#w2dc-location-image").attr("src", "").hide();
			$("#w2dc-location-image-attachment-id").val(0);
		});
	});
})(jQuery);