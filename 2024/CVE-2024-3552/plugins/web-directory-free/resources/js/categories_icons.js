(function($) {
	"use strict";
	
	var category_icon_image_input, category_marker_icon_input, category_marker_icon_tag, category_marker_image_png_input;
	
	$(function() {
		var category_icon_image_url = categories_icons.categories_icons_url;

		$(document).on("click", ".select_icon_image", function() {
			category_icon_image_input = $(this).parent().find('.icon_image');

			var dialog = $('<div id="select_field_icon_dialog"></div>').dialog({
				dialogClass: 'w2dc-content',
				width: ($(window).width()*0.5),
				height: ($(window).height()*0.8),
				modal: true,
				resizable: false,
				draggable: false,
				title: categories_icons.ajax_dialog_title,
				open: function() {
					w2dc_ajax_loader_show();
					$.ajax({
						type: "POST",
						url: w2dc_js_objects.ajaxurl,
						data: {'action': 'w2dc_select_category_icon_dialog'},
						dataType: 'html',
						success: function(response_from_the_action_function){
							if (response_from_the_action_function != 0) {
								$('#select_field_icon_dialog').html(response_from_the_action_function);
								if (category_icon_image_input.val())
									$(".w2dc-icon[icon_file='"+category_icon_image_input.val()+"']").addClass("w2dc-selected-icon");
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
				data: {'action': 'w2dc_select_category_icon', 'icon_file': icon_file, 'category_id': category_icon_image_input.parent().find(".category_id").val()},
				dataType: 'html',
				success: function(response_from_the_action_function){
					if (response_from_the_action_function != 0) {
						if (category_icon_image_input) {
							category_icon_image_input.val(icon_file);
							category_icon_image_input.parent().find(".icon_image_tag").attr('src', category_icon_image_url+icon_file).show();
							category_icon_image_input = false;
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
				data: {'action': 'w2dc_select_category_icon', 'category_id': category_icon_image_input.parent().find(".category_id").val()},
				dataType: 'html',
				success: function(response_from_the_action_function){
					if (category_icon_image_input) {
						category_icon_image_input.val('');
						category_icon_image_input.parent().find(".icon_image_tag").attr('src', '').hide();
						category_icon_image_input = false;
					}
				},
				complete: function() {
					$('#select_field_icon_dialog').remove();
					w2dc_ajax_loader_hide();
				}
			});
		});

		var categories_markers_images_png_url = categories_icons.categories_markers_images_png_url;
		$(document).on("click", ".select_marker_png_image", function() {
			category_marker_image_png_input = $(this).parent().find('.marker_png_image');
			
			var dialog = $('<div id="select_marker_image_dialog"></div>').dialog({
				dialogClass: 'w2dc-content',
				width: ($(window).width()*0.5),
				height: ($(window).height()*0.8),
				modal: true,
				resizable: false,
				draggable: false,
				title: categories_icons.ajax_dialog_title,
				open: function() {
					w2dc_ajax_loader_show();
					$.ajax({
						type: "POST",
						url: w2dc_js_objects.ajaxurl,
						data: {'action': 'w2dc_select_category_marker_png_image_dialog'},
						dataType: 'html',
						success: function(response_from_the_action_function){
							if (response_from_the_action_function != 0) {
								$('#select_marker_image_dialog').html(response_from_the_action_function);
								if (category_marker_image_png_input.val())
									$(".w2dc-png-image[icon_file='"+category_marker_image_png_input.val()+"']").addClass("w2dc-selected-icon");
							}
						},
						complete: function() {
							w2dc_ajax_loader_hide();
						}
					});
					$(document).on("click", ".ui-widget-overlay", function() { $('#select_marker_image_dialog').remove(); });
				},
				close: function() {
					$('#select_marker_image_dialog').remove();
				}
			});
		});
		$(document).on("click", ".w2dc-png-image", function() {
			$(".w2dc-selected-icon").removeClass("w2dc-selected-icon");
			var icon_file = $(this).attr('icon_file');
			w2dc_ajax_loader_show();
			$.ajax({
				type: "POST",
				url: w2dc_js_objects.ajaxurl,
				data: {'action': 'w2dc_select_category_marker_png_image', 'image_name': icon_file, 'category_id': category_marker_image_png_input.parent().find(".category_id").val()},
				dataType: 'html',
				success: function(response_from_the_action_function){
					if (response_from_the_action_function != 0) {
						if (category_marker_image_png_input) {
							category_marker_image_png_input.val(icon_file);
							category_marker_image_png_input.parent().find(".w2dc-marker-image-png-tag").attr('src', categories_markers_images_png_url+icon_file).show();
							category_marker_image_png_input = false;
						}
					}
				},
				complete: function() {
					$(this).addClass("w2dc-selected-icon");
					$('#select_marker_image_dialog').remove();
					w2dc_ajax_loader_hide();
				}
			});
		});
		$(document).on("click", "#reset_png_image", function() {
			$(".w2dc-selected-icon").removeClass("w2dc-selected-icon");
			w2dc_ajax_loader_show();
			$.ajax({
				type: "POST",
				url: w2dc_js_objects.ajaxurl,
				data: {'action': 'w2dc_select_category_marker_png_image', 'category_id': category_marker_image_png_input.parent().find(".category_id").val()},
				dataType: 'html',
				success: function(response_from_the_action_function){
					if (category_marker_image_png_input) {
						category_marker_image_png_input.val('');
						category_marker_image_png_input.parent().find(".w2dc-marker-image-png-tag").attr('src', '').hide();
						category_marker_image_png_input = false;
					}
				},
				complete: function() {
					$('#select_marker_image_dialog').remove();
					w2dc_ajax_loader_hide();
				}
			});
		});
		
		$(document).on("click", ".select_marker_icon_image", function() {
			category_marker_icon_input = $(this).parent().find('.marker_icon_image');
			category_marker_icon_tag = $(this).parent().find('.w2dc-marker-icon-tag');

			var dialog = $('<div id="select_marker_icon_dialog"></div>').dialog({
				dialogClass: 'w2dc-content',
				width: ($(window).width()*0.5),
				height: ($(window).height()*0.8),
				modal: true,
				resizable: false,
				draggable: false,
				title: categories_icons.ajax_marker_dialog_title,
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
								if (category_marker_icon_input.val())
									$("#"+category_marker_icon_input.val()).addClass("w2dc-selected-icon");
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
			category_marker_icon_input.val($(this).attr('id'));
			w2dc_ajax_loader_show();
			$.ajax({
				type: "POST",
				url: w2dc_js_objects.ajaxurl,
				data: {'action': 'w2dc_select_category_marker_icon', 'icon_name': category_marker_icon_input.val(), 'category_id': category_marker_icon_input.parent().find(".category_id").val()},
				dataType: 'html',
				success: function(response_from_the_action_function){
					if (response_from_the_action_function != 0) {
						if (category_marker_icon_input) {
							category_marker_icon_tag.removeClass().addClass('w2dc-marker-icon-tag w2dc-fa '+category_marker_icon_input.val());
							category_marker_icon_input = false;
						}
					}
				},
				complete: function() {
					$(this).addClass("w2dc-selected-icon");
					$('#select_marker_icon_dialog').remove();
					w2dc_ajax_loader_hide();
				}
			});
		});
		$(document).on("click", "#w2dc-reset-fa-icon", function() {
			$(".w2dc-selected-icon").removeClass("w2dc-selected-icon");
			category_marker_icon_input.val('');
			w2dc_ajax_loader_show();
			$.ajax({
				type: "POST",
				url: w2dc_js_objects.ajaxurl,
				data: {'action': 'w2dc_select_category_marker_icon', 'category_id': category_marker_icon_input.parent().find(".category_id").val()},
				dataType: 'html',
				success: function(response_from_the_action_function){
					if (category_marker_icon_input) {
						category_marker_icon_tag.removeClass().addClass('w2dc-marker-icon-tag');
						category_marker_icon_input = false;
					}
				},
				complete: function() {
					$('#select_marker_icon_dialog').remove();
					w2dc_ajax_loader_hide();
				}
			});
		});
		
		$(".marker_color").wpColorPicker();
		$(document).on('focus', '.marker_color', function(){
			var parent = $(this).parent();
            $(this).wpColorPicker()
            parent.find('.wp-color-result').click();
        }); 
		$(document).on("click", ".save_color", function() {
			var category_marker_color_input = $(this).parents(".w2dc-content").find(".marker_color");
			w2dc_ajax_loader_show();
			$.ajax({
				type: "POST",
				url: w2dc_js_objects.ajaxurl,
				data: {'action': 'w2dc_select_category_marker_color', 'color': category_marker_color_input.val(), 'category_id': category_marker_color_input.parents(".w2dc-content").find(".category_id").val()},
				dataType: 'html',
				complete: function() {
					w2dc_ajax_loader_hide();
				}
			});
		});
		
		$(document).on("click", "#w2dc-upload-category-featured", function(event) {
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
						$("#w2dc-category-image").attr("src", attachment.sizes.full.url).show();
						$("#w2dc-category-image-attachment-id").val(attachment.id);
					}
				});
			});
			frame.open();
		});
		$(document).on("click", "#w2dc-remove-category-featured", function(event) {
			event.preventDefault();

			$("#w2dc-category-image").attr("src", "").hide();
			$("#w2dc-category-image-attachment-id").val(0);
		});
	});
})(jQuery);
