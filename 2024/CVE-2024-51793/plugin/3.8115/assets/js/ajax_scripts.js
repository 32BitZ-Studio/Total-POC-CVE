// JavaScript Document
(function($) {
    "use strict";

	$(document).on("change", "input.wcrb_select_service_radio", function(e) {
		$('.wc_rb_mb_customer').removeClass('displayNone');

		var nextsection = $(this).closest('.wc_rb_mb_services').next();

		if ( nextsection.length ) {
			$('html,body').animate({ 
				scrollTop: nextsection.offset().top
				},'slow');
		} else {
			var pos = $(".wc_rb_mb_customer").offset().top;
			$('body, html').animate({scrollTop: pos});	
		}
	});

	$(document).on("click", ".movetomanufactures", function(e) {
		e.preventDefault();
		var pos = $(".wc_rb_mb_manufactures").offset().top-250;
		$('body, html').animate({scrollTop: pos});
	});

	$(document).on("click", ".movetoservices", function(e) {
		e.preventDefault();

		if( $('input[name="book_deivce_name_other[]"]').length && $('input[name="book_deivce_name_other[]"]').val() == '' ) {
			alert($('input[name="enter_device_label_missing_msg"]').val());
		} else {
			var pos = $(".wcrb_services_holder").offset().top-250;
			$('body, html').animate({scrollTop: pos});
		}
	});

	$(document).on("click", "[dt_type_id]", function(e) {
		e.preventDefault();

		var $theTypeId = $(this).attr('dt_type_id');
		$(this).parent().closest('ul').find('.selected').removeClass("selected");
		$(this).addClass('selected');
		
		$('#wcrb_thetype_id').val($theTypeId);

		$("ul.manufacture_list").removeClass('displayNone');
		$('div.selectionnotice').addClass('displayNone');

		var pos = $("#wc_rb_mb_manufactures").offset().top;
		$('body, html').animate({scrollTop: pos});
	});

	function add_device_extra_field( $theDeviceId ) {
		var identifier = $brandID = $typeID = '';

		if ( $theDeviceId != '' ) {
			// .log($theDeviceId);
			if ( $theDeviceId == 'load_other_device' ) {
				var $typeID = $('[dt_device_id="load_other_device"]').attr('dt_device_type_id');
				var $brandID = $('[dt_device_id="load_other_device"]').attr('dt_device_brand_id');
			}
			var $warrantySt = $('#wcrb_booking_type').val();
			$.ajax({
				type: 'POST',
				data: {
					'action': 'rb_add_booking_device_row',
					'theDeviceId': $theDeviceId,
					'type_id': $typeID,
					'brand_id': $brandID
				},
				url: ajax_obj.ajax_url,
				dataType: 'json',
			
				beforeSend: function() {
					$('.selected_devices_message').html("<div class='loader'></div>");
				},
				success: function(response) {
					$('.wc_rb_mb_body.selected_devices .wcrb-btn-grp-services').remove();
					//console.log(response);
					var message = response.message;
					identifier	= response.identifier;

					$('.selected_devices').append(message);
					//
					$('.selected_devices_message').html("");

					var $select_service_label  = $('input[name="select_service_label"]').val();
					var $add_more_device_label = $('input[name="add_more_device_label"]').val();

					if ( $warrantySt == 'YES' ) {
						$('.wc_rb_mb_customer').removeClass('displayNone');
					} else {
						var $thehtml = '<div class="wcrb-btn-grp-services"><a class="button secondary movetomanufactures" href="#">'+$add_more_device_label+'</a><a class="button primary movetoservices" href="#">'+$select_service_label+'</a></div><div class="clearfix"></div>';
						$('.wc_rb_mb_body.selected_devices').append($thehtml);

						add_device_and_load_service( $theDeviceId, identifier );
					}
				}
			});
		}
	}
	
	$(document).on("click", ".delthisdevice", function(e) {
		e.preventDefault();

		var $totalDevices = $('.device-booking-row').length;
		var $identifier = $(this).attr('data-identifier');

		if ( $totalDevices > 1 ) {
			$(this).parents('.device-booking-row').remove();
			$('#'+$identifier).remove();
			$('.wc_rb_mb_device ul.manufacture_list .selected').removeClass("selected");
		} else {
			alert("Add another device to remove this device.");
		}
	});

	$(document).on("click", "[dt_device_id]", function(e) {
		e.preventDefault();

		var $theDeviceId = $(this).attr('dt_device_id');
		
		$(this).parent().closest('ul').find('.selected').removeClass("selected");
		$(this).addClass('selected');

		add_device_extra_field( $theDeviceId );
	});

	$(document).on("click", "[dt_device_g_id]", function(e) {
		e.preventDefault();

		var $theDeviceId = $(this).attr('dt_device_g_id');
		
		$(this).parent().closest('ul').find('.selected').removeClass("selected");
		$(this).addClass('selected');
		
		add_device_extra_field($theDeviceId);
	});

	$(document).on("change", "input[name='book_deivce_name_other[]']", function(e){
		var $identifier_class = $(this).attr('data-identifier');
		var $deviceName 	  = $(this).val();

		$('#'+$identifier_class).removeClass('displayNone');
		$('#'+$identifier_class+' .wc_rb_mb_head h2 span.wcrb_booking_device_label').html('('+$deviceName+')');
	});

	$(document).on("change", "input[name='book_device_serial_num[]']", function(e){
		var $identifier_class = $(this).attr('data-identifier');
		var $deviceName 	  = $(this).val();

		$('#'+$identifier_class+' .wc_rb_mb_head h2 span.wcrb_booking_device_serial').html('('+$deviceName+')');
	});

	function add_device_and_load_service( $theDeviceId, identifier ) {
		var $loadDirectCustomer = $("#loadDirectCustomer").val();

		if(typeof($loadDirectCustomer) != "undefined" && $loadDirectCustomer !== null) {
			$('.wc_rb_mb_customer').removeClass('displayNone');
		}

		var $wc_rb_mb_device_submit = $("#wc_rb_mb_device_submit").val();
		var $grouped_services_load = $("#grouped_services_load").val();

		//var pos = $(".service-message").offset().top;
		//$('body, html').animate({scrollTop: pos});
		var $action = 'wcrb_return_services_section';

		if ( $grouped_services_load == 'YES' ) {
			$action = 'wc_rb_update_services_list_grouped';
		}

		$.ajax({
			type: 'POST',
			data: {
				'action': $action,
				'theDeviceId': $theDeviceId,
				'theBrandNonce': $wc_rb_mb_device_submit,
				'identifier': identifier
			},
			url: ajax_obj.ajax_url,
			dataType: 'json',
			beforeSend: function() {
				$('.wcrb_services_holder_message').html("<div class='loader'></div>");
			},
			success: function(response) {
				//console.log(response);
				var message 		= response.message;
				$('#wcrb_thedevice_id').val($theDeviceId);

				var holder_message = '';
				$('.wcrb_services_holder_message').html(holder_message);

				if ( $grouped_services_load == 'YES' ) {
					$('.wcrb_services_holder').append(message).foundation();
				} else {
					$('.wcrb_services_holder').append(message);
				}
			}
		});
	}

	$(document).on("click", "[dt_warranty_device]", function(e) {
		e.preventDefault();

		var $theDeviceId = $(this).attr('dt_warranty_device');

		$(this).parent().closest('ul').find('.selected').removeClass("selected");
		$(this).addClass('selected');

		$('.wc_rb_mb_customer').removeClass('displayNone');
		var $wc_rb_mb_device_submit = $("#wc_rb_mb_device_submit").val();

		add_device_extra_field($theDeviceId);

		$('#wcrb_thedevice_id').val($theDeviceId);
	});

	$(document).on("submit", ".orderstatusholder form#wcrb_post_customer_msg", function(e) {
		e.preventDefault();
		var $form 	= $(this);
		var formData = $form.serialize();
		var $perform_act = "wcrb_post_customer_message_status";

		$.ajax({
			type: 'POST',
			data: formData + '&action='+$perform_act,
			url: ajax_obj.ajax_url,
			async: true,
			mimeTypes:"multipart/form-data",
			dataType: 'json',
			beforeSend: function() {
				$('.client_msg_post_reply').html("<div class='loader'></div>");
			},
			success: function(response) {
				//console.log(response);
				var message = response.message;
				var redirect_url = response.redirect_url;

				$('.client_msg_post_reply').html('<div class="callout success" data-closable="slide-out-right">'+message+'</div>');				

				if(typeof(redirect_url) != "undefined" && redirect_url !== null) {
					window.location = redirect_url;
				}
			}
		});
	});

	$(document).ready(function() {
		setTimeout(function() {
			var wcrb_thebrand_id = $('#wcrb_thebrand_id').val();
			if ( wcrb_thebrand_id != '' ) {
				var $loadDirectCustomer = $("#loadDirectCustomer").val();

				if(typeof($loadDirectCustomer) != "undefined" && $loadDirectCustomer !== null) {
					$('[dt_brand_id="'+wcrb_thebrand_id+'"]').removeClass("selected");
				} else {
					$('[dt_brand_id="'+wcrb_thebrand_id+'"]').trigger('click');
				}
			}
		},10);
	});

	$(document).on("click", '[dt_brand_id]', function(e) {
		e.preventDefault();

		var $theBrandId = $(this).attr('dt_brand_id');
		$(this).parent().closest('ul').find('.selected').removeClass("selected");
		$(this).addClass('selected');
		
		var $wc_rb_mb_device_submit = $("#wc_rb_mb_device_submit").val();
		
		var pos = $(".device-message").offset().top-250;
		$('body, html').animate({scrollTop: pos});

		$.ajax({
			type: 'POST',
			data: {
				'action': 'wc_rb_mb_update_devices',
				'theBrandId': $theBrandId, 
				'theBrandNonce': $wc_rb_mb_device_submit 
			},
			url: ajax_obj.ajax_url,
			dataType: 'json',

			beforeSend: function() {
				$('.device-message').html("<div class='loader'></div>");
			},
			success: function(response) {
				//console.log(response);
				var message 		= response.message;

				if ( message == 'load_other_device' ) {
					$('#wcrb_thebrand_id').val($theBrandId);
					$('.device-message').html("");
					add_device_extra_field(message);
				} else {
					$('#wcrb_thebrand_id').val($theBrandId);
					$('.device-message').html('<div data-closable="slide-out-right">'+message+'</div>');
				}
			}
		});
	});

	$(document).on("click", 'body [dt_brand_g_id]', function(e) {
		e.preventDefault();

		var $theTypeId = $('#wcrb_thetype_id').val();
		var $theBrandId = $(this).attr('dt_brand_g_id');
		$(this).parent().closest('ul').find('.selected').removeClass("selected");
		$(this).addClass('selected');
		
		$(".wc_rb_mb_device").removeClass('displayNone');

		var $wc_rb_mb_device_submit = $("#wc_rb_mb_device_submit").val();
		
		var $theTypeWarranty = 'NO';
		$theTypeWarranty = $(this).attr('dt_device_warranty');

		var pos = $(".device-message").offset().top-200;
		$('body, html').animate({scrollTop: pos});

		$.ajax({
			type: 'POST',
			data: {
				'action': 'wc_rb_mb_update_devices',
				'theBrandId': $theBrandId, 
				'theTypeId': $theTypeId,
				'typeWarranty' : $theTypeWarranty,
				'theBrandNonce': $wc_rb_mb_device_submit 
			},
			url: ajax_obj.ajax_url,
			dataType: 'json',

			beforeSend: function() {
				$('.device-message').html("<div class='loader'></div>");
			},
			success: function(response) {
				//console.log(response);
				var message = response.message;

				if ( message == 'load_other_device' ) {
					$('#wcrb_thebrand_id').val($theBrandId);
					$('.device-message').html("");
					add_device_extra_field( message );
				} else {
					$('#wcrb_thebrand_id').val($theBrandId);
					$('.device-message').html('<div data-closable="slide-out-right">'+message+'</div>');
				}
			}
		});
	});

	$(document).on('change', 'input[name="reciepetAttachment"]', function(e) {
		e.preventDefault();

		var fd = new FormData();
		var file = $(document).find('input[type="file"]');

		var individual_file = file[0].files[0];
		fd.append("file", individual_file);
		fd.append('action', 'wc_upload_file_ajax');  

		$.ajax({
			type: 'POST',
			url: ajax_obj.ajax_url,
			data: fd,
			contentType: false,
			processData: false,
			dataType: 'json',
			success: function(response) {
				var message = response;
				$('#jobAttachments').append(message);
				$("#jobAttachments").removeClass('displayNone');
				//console.log( response );
			}
		});
	});

	$(document).on('submit', "body form[name='wc_rb_device_form']", function(e) {
		e.preventDefault();
		var $form 	= $(this);
		var formData = $form.serialize();
		var $perform_act = "wc_rb_submit_booking_form";
		
		$.ajax({
			type: 'POST',
			data: formData + '&action='+$perform_act,
			url: ajax_obj.ajax_url,
			async: true,
			mimeTypes:"multipart/form-data",
			dataType: 'json',
			beforeSend: function() {
				$('.booking_message').html("<div class='loader'></div>");
			},
			success: function(response) {
				//console.log(response);
				var message = response.message;
				var success = response.success;
				
				if(success == "YES" ) {
					$('.final_customer_message').html('<div class="callout success" data-closable="slide-out-right">'+message+'</div>');
				} else {
					$('.booking_message').html('<div class="callout success" data-closable="slide-out-right">'+message+'</div>');
				}
			}
		});
	});

	$( document ).ready(function(e) {
		if( $('#auto_submit_status').length ) {
			$( "form[data-async]" ).submit();
		}
	});  

	$("form[data-async]").on("submit",function(e) {
	  	e.preventDefault();

	  	var $form 	= $(this);
	  	var $target = $($form.attr('data-target'));

	  	var formData = $form.serialize();
		var $input = $(this).find("input[name=form_type]");

		var $success_class = '.form-message';

		if ($form.attr('data-success-class') !== undefined ) {
			$success_class = $form.attr('data-success-class');
		}
		var $reload_location = $(this).find("input[name=reload_location]").val();

		if($input.val() == "wc_request_quote_form") {
			var $perform_act = "wc_cr_submit_quote_form";	
		} else if($input.val() == "wc_create_new_job_form") {
			var $perform_act = "wc_cr_create_new_job";
		} else {
			var $perform_act = $(this).find("input[name=form_action]").val();
			if ( typeof $perform_act === "undefined" ) {
				var $perform_act = "wc_cmp_rep_check_order_status";
			}
		}

		$.ajax({
			type: $form.attr('method'),
			data: formData + '&action='+$perform_act,
			url: ajax_obj.ajax_url,
			dataType: 'json',

			beforeSend: function() {
				$($success_class).html("<div class='loader'></div>");
			},
			success: function(response) {
				//console.log(response);
				var message 		= response.message;
				var success 		= response.success;
				var reset_select2 	= response.reset_select2;

				$($success_class).html('<div class="callout success" data-closable="slide-out-right">'+message+'</div>');
				if ($reload_location !== undefined ) {
					$reload_location = '.'+$reload_location;
					$($reload_location).load(window.location + " "+$reload_location);
					//console.log($reload_location);
				}
				
				if(success == "YES") {
					$form.trigger("reset");	
				
					if(reset_select2 == "YES") {
						$("#customer, #rep_devices").val(null).trigger('change');
					}
				}
			}
		});
	});

	$("form#wcrb_reviews").on("submit",function(e) {
		e.preventDefault();

		var $form 	= $(this);
		var $target = $($form.attr('data-target'));

		var formData = $form.serialize();
		var $input = $(this).find("input[name=form_type]");

		var $success_class = '.form-message';

	  $.ajax({
		  type: $form.attr('method'),
		  data: formData + '&action=wcrb_submit_case_bring_review',
		  url: ajax_obj.ajax_url,
		  dataType: 'json',

		  beforeSend: function() {
			  $($success_class).html("<div class='loader'></div>");
		  },
		  success: function(response) {
			//console.log(response);
			var message 		= response.message;
			var redirect_link = response.redirect_url;

			$($success_class).html('<div class="callout success" data-closable="slide-out-right">'+message+'</div>');

			  if ( redirect_link != null && redirect_link != '' ) {
				//redirect_link = redirect_link.replace('&#038;', '&');
				//redirect_link = redirect_link.replace('#038;', '&');
				window.location.href = redirect_link;
			  }
		  }
	  });
  });

	$(document).on("change", 'select.wcrbupdatedatalist', function(e) {
		e.preventDefault();

		var $brandId =  $('select[name="manufacture"]').find(":selected").val();
		var $typeId  =  $('select[name="devicetype"]').find(":selected").val();

		$.ajax({
			type: 'POST',
			data: {
				'action': 'wc_return_devices_datalist',
				'theBrandId': $brandId, 
				'theTypeId': $typeId
			},
			url: ajax_obj.ajax_url,
			dataType: 'json',

			beforeSend: function() {
				$('.adddevicecustomermessage').html("<div class='loader'></div>");
			},
			success: function(response) {
				//console.log(response);
				var message 		= response.message;
				$('.adddevicecustomermessage').html('');
				$('datalist#device_name_list').html(message);
			}
		});
	});
})(jQuery); //jQuery main function ends strict Mode on