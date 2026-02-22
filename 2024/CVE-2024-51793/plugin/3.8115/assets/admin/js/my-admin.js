// JavaScript Document
(function($) {
    "use strict";
	
	//calling foundation js
	jQuery(document).foundation();
	
	jQuery.fn.exists = function(){ return this.length > 0; }

	jQuery(document).on("keyup", "#wc_price, #wc_cost, .wc_validate_number", function(){
		var valid = /^-?[0-9]\d*(\.\d+)?$/.test(this.value),
		//var valid = /^\d{0,8}(\.\d{0,2})?$/.test(this.value),
		val = this.value;

		if(!valid){
			console.log("Invalid input!");
			this.value = val.substring(0, val.length - 1);
		}
	});

	jQuery("#btnPrint").on("click", function() {
		window.print();
	});

	jQuery(document).ready(function() {
		$('#customer, #technician, #select_rep_products, #select_product, #rep_devices, #select_rep_services, #job_technician, #job_customer, #selectjob_id').select2();
		
		if($('#updateUserFormReveal').exists()) {
			$('#updateUserFormReveal').foundation('open');
		}

		$("#current_date").text(return_date());
	});

	function return_time() {
		var d = new Date();
		var time = d.getHours() + ":" + d.getMinutes() + ":" + d.getSeconds();

		return time;
	}

	function return_date() {
		var d 		= new Date();
		var date 	= d.toLocaleString();   

		return date;
	}

	if ($('#updateStatus').length) {
		$('#statusFormReveal').foundation('toggle');
	}

	if ($('#updatePaymentStatus').length) {
		$('#paymentStatusFormReveal').foundation('toggle');
	}

	jQuery(document).on('click', '[checkbox-toggle-group]', function(e) {
		e.preventDefault();

		var $toToggle = $(this).attr('checkbox-toggle-group');
		var $action  = $(this).attr('class');

		if ( $action == 'unselect' ) {
			//Unselect all
			$('[name="'+$toToggle+'[]"]').prop( 'checked', false );
			//Change class to select
			$(this).toggleClass("unselect select");
		} else {
			//Select All 
			$('[name="'+$toToggle+'[]"]').prop( 'checked', true );

			//change class to unselect
			$(this).toggleClass("select unselect");
		}
		console.log($toToggle);
	});
})(jQuery); //jQuery main function ends strict Mode on