// JavaScript Document
(function($) {
    "use strict";
	
	$(document).ready(function() { wc_grand_total_calculations(); });
	
	function wc_grand_total_calculations() {
		var products_grand_total 	= 0;
		var parts_grand_total 		= 0;
		var service_grand_total 	= 0;
		var extra_grand_total 		= 0;
		var parts_tax_total 		= 0;
		var paroducts_tax_total 	= 0;
		var service_tax_total 		= 0;
		var extra_tax_total			= 0;
		var payment_grand_total 	= 0;

		var $prices_inclu_exclu = $("#wc_prices_inclu_exclu").val();

		var $tax_exc_type = 'exclusive';
		if ( $prices_inclu_exclu == 'inclusive' ) {
			$tax_exc_type = 'inclusive';
		}

		//Woo ?Products Calculations List.
		if ( $(".wc_product_price_total").length ) {
			var i = 1;
			$('.wc_product_price_total').each(function(i) {
				var quantity = $('[name="wc_product_qty[]"]').get(i).value;
				var price 	 = $('[name="wc_product_price[]"]').get(i).value;

				if(isNaN(quantity)) { 
					alert("Quantity needs to be a number!");
					$("[name='wc_product_qty[]']").get(i).value = 1;
					$("[name='wc_product_qty[]']").get(i).focus();
					return false;
				}
				if(isNaN(price)) { 
					alert("Price needs to be a number!");
					$("[name='wc_product_price[]']").get(i).value = 1;
					$("[name='wc_product_price[]']").get(i).focus();
					return false;
				}
		
				var total = parseFloat(price)*parseFloat(quantity);

				if(!isNaN(total)) {
					products_grand_total = parseFloat(total+products_grand_total);
				}

				//Calculate Parts Tax if exists
				if ( $(".wc_product_tax_price").length ) {
					var tax 	 = $('[name="wc_product_tax[]"]').get(i).value;

					if(isNaN(tax)) { 
						alert("Tax isn't a number!");
						$("[name='wc_product_tax[]']").get(i).focus();
						return false;
					}
					if ( $tax_exc_type == 'inclusive' ) {
						var $taxPrice = parseFloat(total)*parseFloat(tax)/(100+parseFloat(tax));
					} else {
						var $taxPrice = (parseFloat(total)/100)*parseFloat(tax);
					}
					if(!isNaN($taxPrice)) {
						paroducts_tax_total = parseFloat($taxPrice+paroducts_tax_total);
					}
				}
			});
		}

		//Parts Products.
		if ($(".wc_price_total").length) {
			var i = 1;
			$('.wc_price_total').each(function(i) {
				var quantity = $('[name="wc_part_qty[]"]').get(i).value;
				var price 	 = $('[name="wc_part_price[]"]').get(i).value;

				if(isNaN(quantity)) { 
					alert("Quantity needs to be a number!");
					$("[name='wc_part_qty[]']").get(i).value = 1;
					$("[name='wc_part_qty[]']").get(i).focus();
					return false;
				}
				if(isNaN(price)) { 
					alert("Price needs to be a number!");
					$("[name='wc_part_price[]']").get(i).value = 1;
					$("[name='wc_part_price[]']").get(i).focus();
					return false;
				}
		
				var total = parseFloat(price)*parseFloat(quantity);

				if(!isNaN(total)) {
					parts_grand_total = parseFloat(total+parts_grand_total);
				}

				//Calculate Parts Tax if exists
				if ($(".wc_part_tax_price").length) {
					var tax 	 = $('[name="wc_part_tax[]"]').get(i).value;
					if(isNaN(tax)) { 
						alert("Tax isn't a number!");
						$("[name='wc_part_tax[]']").get(i).focus();
						return false;
					}
					if ( $tax_exc_type == 'inclusive' ) {
						var $taxPrice = parseFloat(total)*parseFloat(tax)/(100+parseFloat(tax));
					} else {
						var $taxPrice = (parseFloat(total)/100)*parseFloat(tax);
					}
					if(!isNaN($taxPrice)) {
						parts_tax_total = parseFloat($taxPrice+parts_tax_total);
					}
				}
			});
		}

		//Services List.
		if ($(".wc_service_price_total").length) {
			var i = 1;
			$('.wc_service_price_total').each(function(i) {
				var quantity = $('[name="wc_service_qty[]"]').get(i).value;
				var price 	 = $('[name="wc_service_price[]"]').get(i).value;

				if(isNaN(quantity)) { 
					alert("Quantity needs to be a number!");
					$("[name='wc_service_qty[]']").get(i).value = 1;
					$("[name='wc_service_qty[]']").get(i).focus();
					return false;
				}
				if(isNaN(price)) { 
					alert("Price needs to be a number!");
					$("[name='wc_service_price[]']").get(i).value = 1;
					$("[name='wc_service_price[]']").get(i).focus();
					return false;
				}
		
				var total = parseFloat(price)*parseFloat(quantity);

				if(!isNaN(total)) {
					service_grand_total = parseFloat(total+service_grand_total);
				}

				//Calculate Parts Tax if exists
				if ($(".wc_service_tax_price").length) {
					var tax 	 = $('[name="wc_service_tax[]"]').get(i).value;
					if(isNaN(tax)) { 
						alert("Tax isn't a number!");
						$("[name='wc_service_tax[]']").get(i).focus();
						return false;
					}
					if ( $tax_exc_type == 'inclusive' ) {
						var $taxPrice = parseFloat(total)*parseFloat(tax)/(100+parseFloat(tax));
					} else {
						var $taxPrice = (parseFloat(total)/100)*parseFloat(tax);
					}
					if(!isNaN($taxPrice)) {
						service_tax_total = parseFloat($taxPrice+service_tax_total);
					}
				}
			});
		}

		//Extras Calculations List.
		if ($(".wc_extra_price_total").length) {
			var i = 1;
			$('.wc_extra_price_total').each(function(i) {
				var quantity = $('[name="wc_extra_qty[]"]').get(i).value;
				var price 	 = $('[name="wc_extra_price[]"]').get(i).value;

				if(isNaN(quantity)) { 
					alert("Quantity needs to be a number!");
					$("[name='wc_extra_qty[]']").get(i).value = 1;
					$("[name='wc_extra_qty[]']").get(i).focus();
					return false;
				}
				if(isNaN(price)) { 
					alert("Price needs to be a number!");
					$("[name='wc_extra_price[]']").get(i).value = 1;
					$("[name='wc_extra_price[]']").get(i).focus();
					return false;
				}
		
				var total = parseFloat(price)*parseFloat(quantity);

				if(!isNaN(total)) {
					extra_grand_total = parseFloat(total+extra_grand_total);
				}

				//Calculate Parts Tax if exists
				if ($(".wc_extra_tax_price").length) {
					var tax = $('[name="wc_extra_tax[]"]').get(i).value;
					if(isNaN(tax)) { 
						alert("Tax isn't a number!");
						$("[name='wc_extra_tax[]']").get(i).focus();
						return false;
					}
					if ( $tax_exc_type == 'inclusive' ) {
						var $taxPrice = parseFloat(total)*parseFloat(tax)/(100+parseFloat(tax));
					} else {
						var $taxPrice = (parseFloat(total)/100)*parseFloat(tax);
					}
					if(!isNaN($taxPrice)) {
						extra_tax_total = parseFloat($taxPrice+extra_tax_total);
					}
				}
			});
		}

		//Payments Calculations List.
		if ($('body [name="wcrb_payment_field[]"]').length) {
			var i = 1;
			$('body [name="wcrb_payment_field[]"]').each(function(i) {
				var payment = $('body [name="wcrb_payment_field[]"]').get(i).value;
				
				if(isNaN(payment)) { 
					return false;
				}
				payment = parseFloat(payment);
				if(!isNaN(payment)) {
					payment_grand_total = parseFloat(payment+payment_grand_total);
				}
			});
		}

		if ( $tax_exc_type == 'inclusive' ) {
			var grand_total = parseFloat(products_grand_total)+parseFloat(service_grand_total)+parseFloat(parts_grand_total)+parseFloat(extra_grand_total);
		} else {
			var grand_total = parseFloat(products_grand_total)+parseFloat(service_grand_total)+parseFloat(parts_grand_total)+parseFloat(extra_grand_total)+parseFloat(parts_tax_total)+parseFloat(paroducts_tax_total)+parseFloat(service_tax_total)+parseFloat(extra_tax_total);
		}
		var $theBalance = parseFloat(grand_total).toFixed(2)-parseFloat(payment_grand_total).toFixed(2);

		$(".wc_products_grandtotal .amount").html(wc_rb_format_currency( products_grand_total, "NO" ));
		$(".wc_parts_grandtotal .amount").html(wc_rb_format_currency( parts_grand_total, "NO" ));
		$(".wc_services_grandtotal .amount").html(wc_rb_format_currency( service_grand_total, "NO" ));
		$(".wc_extras_grandtotal .amount").html(wc_rb_format_currency( extra_grand_total, "NO" ));
		$(".wc_jobs_payments_total .amount").html(wc_rb_format_currency( payment_grand_total, "NO" ));

		$(".wc_grandtotal_balance .amount").html(wc_rb_format_currency( $theBalance, "YES" ));

		if ($(".wc_part_tax_price").length){
			$(".wc_parts_tax_total .amount").html(wc_rb_format_currency( parts_tax_total, "NO" ) );
		}
		if ($(".wc_service_tax_price").length){
			$(".wc_services_tax_total .amount").html(wc_rb_format_currency( service_tax_total, "NO" ) );
		}
		if ($(".wc_extra_tax_price").length){
			$(".wc_extras_tax_total .amount").html(wc_rb_format_currency( extra_tax_total, "NO" ) );
		}
		if ($(".wc_product_tax_price").length){
			$(".wc_products_tax_total .amount").html(wc_rb_format_currency( paroducts_tax_total, "NO" ) );
		}

		if ($(".wcrb_amount_payable").length) {
			wc_update_payment_mode( $theBalance );
		}
		$(".wc_grandtotal .amount").html(wc_rb_format_currency( grand_total, "YES" ));
	}

	function wc_update_payment_mode( grand_total ) {
		$(".wcrb_amount_payable_value").val(grand_total);
		$(".wcrb_amount_payable").html(wc_rb_format_currency( grand_total, "NO" ));
		var $wcRb_payment_amount = $('#wcRb_payment_amount').val();
		$(".wcrb_amount_paying").html(wc_rb_format_currency(parseFloat($wcRb_payment_amount), "NO"));
		var $theBalance = grand_total - parseFloat($wcRb_payment_amount);
		$(".wcrb_amount_balance").html(wc_rb_format_currency( $theBalance, "YES" ));
	}

	$(document).on("input", "#wcRb_payment_amount", function() {
		var grand_total = $(".wcrb_amount_payable_value").val();
		wc_update_payment_mode(grand_total);
	});

	function calculate_part_item_total(array_index) {
		var product_price 		= $("[name='wc_part_price[]']").get(array_index).value;
		var product_quantity 	= $("[name='wc_part_qty[]']").get(array_index).value;
		var $prices_inclu_exclu = $("#wc_prices_inclu_exclu").val();

		var $tax_exc_type = 'exclusive';
		if ( $prices_inclu_exclu == 'inclusive' ) {
			$tax_exc_type = 'inclusive';
		}
		
		
		if(isNaN(product_quantity)) { 
			alert("Quantity needs to be a number!");
			$("[name='wc_part_qty[]']").get(array_index).value = 1;
			$("[name='wc_part_qty[]']").get(array_index).focus();
			return false;
		}
		
		if(isNaN(product_price)) { 
			alert("Price needs to be a number!");
			$("[name='wc_part_price[]']").get(array_index).value = 1;
			$("[name='wc_part_price[]']").get(array_index).focus();
			return false;
		}

		var total 		= parseFloat(product_price)*parseFloat(product_quantity);
		
		var $calculated_tax = 0;
		var $calculated_tax_dp = 0;

		if (undefined !== $("[name='wc_part_tax[]']").get(array_index)){
			var product_tax	= $("[name='wc_part_tax[]']").get(array_index).value;

			if($("[name='wc_part_tax[]']").get(array_index).value.length) {
				// do something here
				if(isNaN(product_tax)) { 
					alert("Your tax seems not a number.");
					return false;
				} else {
					if ( $tax_exc_type == 'inclusive' ) {
						$calculated_tax = parseFloat(total)*parseFloat(product_tax)/(100+parseFloat(product_tax));
					} else {
						$calculated_tax = (parseFloat(total)/100)*parseFloat(product_tax);
					}

					$calculated_tax_dp = wc_rb_format_currency( $calculated_tax, "NO" );

					$(".wc_part_tax_price").get(array_index).innerHTML = $calculated_tax_dp;
				}	
			} else {
				$(".wc_part_tax_price").get(array_index).innerHTML = wc_rb_format_currency( $calculated_tax, "NO" );	
			}
		}
		if ( $tax_exc_type == 'inclusive' ) {
			var grand_total = parseFloat(total);
		} else {
			var grand_total = parseFloat(total)+parseFloat($calculated_tax);
		}
		
		$(".wc_price_total").get(array_index).innerHTML = wc_rb_format_currency( grand_total, "NO" );
		
		wc_grand_total_calculations();
	}

	function calculate_product_item_total(array_index) {
		var product_price 		= $("[name='wc_product_price[]']").get(array_index).value;
		var product_quantity 	= $("[name='wc_product_qty[]']").get(array_index).value;
		var $prices_inclu_exclu = $("#wc_prices_inclu_exclu").val();

		var $tax_exc_type = 'exclusive';
		if ( $prices_inclu_exclu == 'inclusive' ) {
			$tax_exc_type = 'inclusive';
		}
	

		if(isNaN(product_quantity)) { 
			alert("Quantity needs to be a number!");
			$("[name='wc_product_qty[]']").get(array_index).value = 1;
			$("[name='wc_product_qty[]']").get(array_index).focus();
			return false;
		}
		
		if(isNaN(product_price)) { 
			alert("Price needs to be a number!");
			$("[name='wc_product_price[]']").get(array_index).value = 1;
			$("[name='wc_product_price[]']").get(array_index).focus();
			return false;
		}

		var total 				= parseFloat(product_price)*parseFloat(product_quantity);
		
		var $calculated_tax 	= 0;
		var $calculated_tax_dp 	= 0;

		if (undefined !== $("[name='wc_product_tax[]']").get(array_index)){
			var product_tax			= $("[name='wc_product_tax[]']").get(array_index).value;

			if($("[name='wc_product_tax[]']").get(array_index).value.length) {
				// do something here
				if(isNaN(product_tax)) { 
					alert("Your tax seems not a number.");
					return false;
				} else {
					if ( $tax_exc_type == 'inclusive' ) {
						$calculated_tax = parseFloat(total)*parseFloat(product_tax)/(100+parseFloat(product_tax));
					} else {
						$calculated_tax = (parseFloat(total)/100)*parseFloat(product_tax);
					}
					$calculated_tax_dp = wc_rb_format_currency( $calculated_tax, "NO" );

					$(".wc_product_tax_price").get(array_index).innerHTML = $calculated_tax_dp;
				}	
			} else {
				$(".wc_product_tax_price").get(array_index).innerHTML = wc_rb_format_currency( $calculated_tax, "NO" );	
			}
		}
		if ( $tax_exc_type == 'inclusive' ) {
			var grand_total = parseFloat(total);
		} else {
			var grand_total = parseFloat(total)+parseFloat($calculated_tax);
		}
		
		$(".wc_product_price_total").get(array_index).innerHTML = wc_rb_format_currency( grand_total, "NO" );
		
		wc_grand_total_calculations();
	}
	
	function calculate_service_item_total(array_index) {
		var service_price 		= $("[name='wc_service_price[]']").get(array_index).value;
		var service_quantity 	= $("[name='wc_service_qty[]']").get(array_index).value;
		var $prices_inclu_exclu = $("#wc_prices_inclu_exclu").val();

		var $tax_exc_type = 'exclusive';
		if ( $prices_inclu_exclu == 'inclusive' ) {
			$tax_exc_type = 'inclusive';
		}

		if(isNaN(service_quantity)) { 
			alert("Quantity needs to be a number!");
			$("[name='wc_service_qty[]']").get(array_index).value = 1;
			$("[name='wc_service_qty[]']").get(array_index).focus();
			return false;
		}
		
		if(isNaN(service_price)) { 
			alert("Price needs to be a number!");
			$("[name='wc_service_price[]']").get(array_index).value = 1;
			$("[name='wc_service_price[]']").get(array_index).focus();
			return false;
		}
		
		var total 		= parseFloat(service_price)*parseFloat(service_quantity);
		
		var $calculated_tax = 0;
		var $calculated_tax_dp = 0;

		if (undefined !== $("[name='wc_service_tax[]']").get(array_index)){
			var service_tax			= $("[name='wc_service_tax[]']").get(array_index).value;

			if($("[name='wc_service_tax[]']").get(array_index).value.length) {
				// do something here
				if(isNaN(service_tax)) { 
					alert("Your tax seems not a number.");
					return false;
				} else {
					if ( $tax_exc_type == 'inclusive' ) {
						$calculated_tax = parseFloat(total)*parseFloat(service_tax)/(100+parseFloat(service_tax));
					} else {
						$calculated_tax = (parseFloat(total)/100)*parseFloat(service_tax);
					}

					$calculated_tax_dp = wc_rb_format_currency( $calculated_tax, "NO" );

					$(".wc_service_tax_price").get(array_index).innerHTML = $calculated_tax_dp;
				}	
			} else {
				$(".wc_service_tax_price").get(array_index).innerHTML = wc_rb_format_currency( $calculated_tax, "NO" );	
			}
		}
		if ( $tax_exc_type == 'inclusive' ) {
			var grand_total = parseFloat(total);
		} else {
			var grand_total = parseFloat(total)+parseFloat($calculated_tax);
		}

		$(".wc_service_price_total").get(array_index).innerHTML = wc_rb_format_currency( grand_total, "NO" );
		
		wc_grand_total_calculations();
	}
	
	function calculate_extra_item_total(array_index) {
		var service_price 		= $("[name='wc_extra_price[]']").get(array_index).value;
		var service_quantity 	= $("[name='wc_extra_qty[]']").get(array_index).value;
		var $prices_inclu_exclu = $("#wc_prices_inclu_exclu").val();

		var $tax_exc_type = 'exclusive';
		if ( $prices_inclu_exclu == 'inclusive' ) {
			$tax_exc_type = 'inclusive';
		}
		
		if(isNaN(service_quantity)) { 
			alert("Quantity needs to be a number!");
			$("[name='wc_extra_qty[]']").get(array_index).value = 1;
			$("[name='wc_extra_qty[]']").get(array_index).focus();
			return false;
		}
		
		if(isNaN(service_price)) { 
			alert("Price needs to be a number!");
			$("[name='wc_extra_price[]']").get(array_index).value = 1;
			$("[name='wc_extra_price[]']").get(array_index).focus();
			return false;
		}
		
		var total 	= parseFloat(service_price)*parseFloat(service_quantity);
		
		var $calculated_tax = 0;
		var $calculated_tax_dp = 0;

		if (undefined !== $("[name='wc_extra_tax[]']").get(array_index)){
			var extra_tax			= $("[name='wc_extra_tax[]']").get(array_index).value;

			if($("[name='wc_extra_tax[]']").get(array_index).value.length) {
				// do something here
				if(isNaN(extra_tax)) { 
					alert("Your tax seems not a number.");
					return false;
				} else {
					if ( $tax_exc_type == 'inclusive' ) {
						$calculated_tax = parseFloat(total)*parseFloat(extra_tax)/(100+parseFloat(extra_tax));
					} else {
						$calculated_tax = (parseFloat(total)/100)*parseFloat(extra_tax);
					}
					
					$calculated_tax_dp = wc_rb_format_currency( $calculated_tax, "NO" );
					
					$(".wc_extra_tax_price").get(array_index).innerHTML = $calculated_tax_dp;
				}	
			} else {
				$(".wc_extra_tax_price").get(array_index).innerHTML = wc_rb_format_currency( $calculated_tax, "NO" );	
			}
		}
		if ( $tax_exc_type == 'inclusive' ) {
			var grand_total = parseFloat(total);
		} else {
			var grand_total = parseFloat(total)+parseFloat($calculated_tax);
		}

		$(".wc_extra_price_total").get(array_index).innerHTML = wc_rb_format_currency( grand_total, "NO" );

		wc_grand_total_calculations();
	}
	
	$(document).on("change", "#wc_prices_inclu_exclu", function() {
		$("[name='wc_part_qty[]']").each(function(index){
			calculate_part_item_total(index);
		});

		$("[name='wc_product_qty[]']").each(function(index){
			calculate_product_item_total(index);
		});

		$("[name='wc_service_qty[]']").each(function(index){
			calculate_service_item_total(index);
		});

		$("[name='wc_extra_qty[]']").each(function(index){
			calculate_extra_item_total(index);
		});
	});

	//On Quantity Change call function
	$(document).on("change", "[name='wc_part_qty[]']", function(){
		var array_index = $(this).index("[name='wc_part_qty[]']");
		
		calculate_part_item_total(array_index);
	});
	
	//On Quantity Change call function
	$(document).on("change", "[name='wc_part_price[]']", function() {
		var array_index = $(this).index("[name='wc_part_price[]']");
		
		calculate_part_item_total(array_index);
	});

	//On Tax Change call function
	$(document).on("change", "[name='wc_part_tax[]']", function(){
		var array_index = $(this).index("[name='wc_part_tax[]']");
		
		calculate_part_item_total(array_index);
	});

	//On Quantity Change call function
	$(document).on("change", "[name='wc_product_qty[]']", function(){
		var array_index 		= $(this).index("[name='wc_product_qty[]']");
		
		calculate_product_item_total(array_index);
	});
	
	//On Quantity Change call function
	$(document).on("change", "[name='wc_product_price[]']", function(){
		var array_index 		= $(this).index("[name='wc_product_price[]']");
		
		calculate_product_item_total(array_index);
	});

	//On Product Tax Change
	$(document).on("change", "[name='wc_product_tax[]']", function(){
		var array_index 		= $(this).index("[name='wc_product_tax[]']");
		
		calculate_product_item_total(array_index);
	});
	
	//On Quantity Change call function
	$(document).on("change", "[name='wc_service_qty[]']", function(){
		var array_index 		= $(this).index("[name='wc_service_qty[]']");
		
		calculate_service_item_total(array_index);
	});
	
	//On Quantity Change call function
	$(document).on("change", "[name='wc_service_price[]']", function(){
		var array_index 		= $(this).index("[name='wc_service_price[]']");
		
		calculate_service_item_total(array_index);
	});
	
	//On Tax Change call function
	$(document).on("change", "[name='wc_service_tax[]']", function(){
		var array_index 		= $(this).index("[name='wc_service_tax[]']");
		
		calculate_service_item_total(array_index);
	});

	//On Quantity Change call function
	$(document).on("change", "[name='wc_extra_qty[]']", function(){
		var array_index 		= $(this).index("[name='wc_extra_qty[]']");
		
		calculate_extra_item_total(array_index);
	});
	
	//On Quantity Change call function
	$(document).on("change", "[name='wc_extra_price[]']", function(){
		var array_index 		= $(this).index("[name='wc_extra_price[]']");
		
		calculate_extra_item_total(array_index);
	});
	
	//On Tax Change call function
	$(document).on("change", "[name='wc_extra_tax[]']", function(){
		var array_index 		= $(this).index("[name='wc_extra_tax[]']");
		
		calculate_extra_item_total(array_index);
	});

	function wc_rb_format_currency( number, currency_display ) {
		var $wc_cr_selected_currency  = $('#wc_cr_selected_currency').val();
		var $wc_cr_currency_position  = $('#wc_cr_currency_position').val();
		var thouSep = $('#wc_cr_thousand_separator').val();
		var decSep  = $('#wc_cr_decimal_separator').val();
		var decPlaces = $('#wc_cr_number_of_decimals').val();

		var decPlaces = isNaN(decPlaces = Math.abs(decPlaces)) ? 2 : decPlaces;
		var decSep = typeof decSep === "undefined" ? "." : decSep;
		var thouSep = typeof thouSep === "undefined" ? "," : thouSep;
		var sign = number < 0 ? "-" : "";
		var i = String(parseInt(number = Math.abs(Number(number) || 0).toFixed(decPlaces)));
		var j = (j = i.length) > 3 ? j % 3 : 0;

		var $theREturn = 0;
		
		$theREturn = sign +
			(j ? i.substr(0, j) + thouSep : "") +
			i.substr(j).replace(/\B(?=(\d{3})+(?!\d))/g, thouSep) +
			(decPlaces ? decSep + Math.abs(number - i).toFixed(decPlaces).slice(2) : "");

		if ( currency_display == 'YES' ) {
			if ( $wc_cr_selected_currency != '' ) {
				switch( $wc_cr_currency_position ) {
					case 'right_space':
						$theREturn = $theREturn+' '+$wc_cr_selected_currency;		
						break;
					case 'left_space':
						$theREturn = $wc_cr_selected_currency+' '+$theREturn;
						break;
					case 'left':
						$theREturn = $wc_cr_selected_currency+$theREturn;
						break;	
					case 'right':
						$theREturn = $theREturn+$wc_cr_selected_currency;
						break;
					default:
						$theREturn = $theREturn+$wc_cr_selected_currency;
				}
			}
		}
		return $theREturn;
	}

	$("form[data-async]").on("submit",function(e) {
		e.preventDefault();
		return false;
	});

	$("form[data-async]").on("forminvalid.zf.abide", function(e,target) {
	  console.log("form is invalid");
	});

	$("form[data-async]").on("formvalid.zf.abide", function(e,target) {
		var $form 		 = $(this);
		var formData 	 = $form.serialize();

		var $input = $(this).find("input[name=form_type]");

		var $success_class = '.form-message';

		if ($form.attr('data-success-class') !== undefined ) {
			$success_class = $form.attr('data-success-class');
		}

		if($input.val() == "tax_form") {
			var $perform_act = "wc_post_taxes";	
		} else if($input.val() == "status_form") {
			var $perform_act = "wc_post_status";
		} else if($input.val() == "update_user") {
			var $perform_act = "wc_update_user_data";
		} else if ( $input.val() == 'payment_status_form' ) {
			var $perform_act = "wc_post_payment_status";
		} else if ( $input.val() == 'submit_default_pages_WP' ) {
			var $perform_act = "wc_post_default_pages_indexes";
		} else if ( $input.val() == 'submit_the_sms_configuration_form' ) {
			var $perform_act = "wc_post_sms_configuration_index";
		} else if ( $input.val() == 'wc_rb_update_methods_ac' ) {
			var $perform_act = "wc_rb_update_payment_methods";
		} else if ( $input.val() == 'wc_rb_update_sett_devices_brands' ) {
			var $perform_act = "wc_rb_update_device_settings";
		} else if ( $input.val() == 'add_device_form' ) {
			var $perform_act = "wc_add_device_for_manufacture";
		} else if ( $input.val() == 'add_part_fly_form' ) {
			var $perform_act = "wc_add_part_for_fly";
		} else if ( $input.val() == 'add_service_fly_form' ) {
			var $perform_act = "wc_add_service_for_fly";
		} else if ( $input.val() == 'wc_rb_update_sett_bookings' ) {
			var $perform_act = "wc_rb_update_booking_settings";
		} else if ( $input.val() == 'wc_rb_update_sett_services' ) {
			var $perform_act = "wc_rb_update_service_settings";
		} else if ( $input.val() == 'wc_rb_update_sett_account' ) {
			var $perform_act = "wc_rb_update_account_settings";
		} else if ( $input.val() == 'wc_rb_update_sett_taxes' ) {
			var $perform_act = "wc_rb_update_tax_settings";
		} else if ( $input.val() == 'maintenance_reminder_form' ) {
			var $perform_act = "wc_rb_update_maintenance_reminder";
		} else {
			var $perform_act = $(this).find("input[name=form_action]").val();
			if ( typeof $perform_act === "undefined" ) {
				var $perform_act = "wc_post_customer";
			}
		}
		//console.log( formData );
		$.ajax({
			type: $form.attr('method'),
			data: formData + '&action='+$perform_act,
			url: ajax_obj.ajax_url,
			dataType: 'json',

			beforeSend: function() {
				$($success_class).html("<div class='spinner is-active'></div>");
			},
			success: function(response) {
				//console.log(response);
				var message 		= response.message;
				var success 		= response.success;
				
				$($success_class).html('<div class="callout success" data-closable="slide-out-right">'+message+'<button class="close-button" aria-label="Dismiss alert" type="button" data-close><span aria-hidden="true">&times;</span></button></div>');
				
				if(success == "YES" && ( $perform_act == "wc_post_taxes" || $perform_act == "wc_post_status"  || $perform_act == "wc_post_payment_status" ) ) {
					$form.trigger("reset");	
				}

				if ($('#updateStatus').length) {
					location.reload();
				}

				if( $perform_act == "wc_post_status" ) {
					$("#job_status_wrapper").load(window.location + " #status_poststuff");
				} else if ( $perform_act == "wc_post_payment_status" ) {
					$("#payment_status_wrapper").load(window.location + " #paymentStatus_poststuff");
				} else if ( $perform_act == "wc_rb_update_maintenance_reminder" ) {
					$("#reminder_status_wrapper").load(window.location + " #reminderStatus_poststuff");

					if (success == 'YES') {
						//Something on Success
						$($form).trigger('reset');
					}
				} else if ($perform_act == "wc_add_device_for_manufacture") {
					var device_id		= response.device_id;
					$('#rep_devices_head').load(document.location + ' #rep_devices_head>*', function(){
						$("select#rep_devices").select2();
						//$('select#rep_devices').val('0').trigger('change');
						$('select#rep_devices').val(device_id);
						$('select#rep_devices').trigger('change');
					});
				} else if ($perform_act == "wc_add_part_for_fly") {
					//part_id
					var part_id	= response.part_id;
					$('#reloadPartsData').load(document.location + ' #reloadPartsData>*', function(){
						$("select#select_rep_products").select2();
						$('select#select_rep_products').val(part_id);
						$('select#select_rep_products').trigger('change');
					});
				} else if ($perform_act == "wc_add_service_for_fly") {
					//part_id
					var service_id	= response.service_id;
					$('#reloadServicesData').load(document.location + ' #reloadServicesData>*', function(){
						$("select#select_rep_services").select2();
						$('select#select_rep_services').val(service_id);
						$('select#select_rep_services').trigger('change');
					});
				} else {
					$("#poststuff_wrapper").load(window.location + " #poststuff");
				}
				if($perform_act == "wc_post_customer") {
					var user_id		= response.user_id;
					var user_value  = response.optionlabel;
					
					var newOption = new Option(user_value, user_id, true, true);
					// Append it to the select
					$('#updatecustomer').append(newOption).trigger('change');
					//$("select#customer").select2("destroy");
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

	$(document).on("submit", "form[id='submitAdminExtraField']", function(e) {
		e.preventDefault();

		var $form 	= $(this);
		var formData = $form.serialize();
		var $perform_act = "wc_add_extra_field_admin_side";

		var $post_ID = $('#post_ID').val();
		if( $post_ID == '' ) {
			$('.extrafield-form-message').html('<div class="callout success" data-closable="slide-out-right">Missing Post ID<button class="close-button" aria-label="Dismiss alert" type="button" data-close><span aria-hidden="true">&times;</span></button></div>');
		}

		$.ajax({
			type: 'POST',
			data: formData + '&post_ID='+ $post_ID + '&action='+$perform_act,
			url: ajax_obj.ajax_url,
			async: true,
			mimeTypes:"multipart/form-data",
			dataType: 'json',
			beforeSend: function() {
				$('.extrafield-form-message').html("<div class='loader'></div>");
			},
			success: function(response) {
				//console.log(response);
				var message = response.message;
				var success = response.success;
				
				$('.extrafield-form-message').html('<div class="callout success" data-closable="slide-out-right">'+message+'</div>');

				if (success == 'YES') {
					$("form[id='submitAdminExtraField']").trigger('reset');
					$("#reloadTheExtraFields").load(window.location + " .extrafieldstable");
				}
			}
		});
	});

	$("#wc_rb_sms_gateway").on("change", function(e, target) {
		var $gateway_selected = $("#wc_rb_sms_gateway").val();

		if ( $gateway_selected != "" ) {
			$.ajax({
				type: 'POST',
				data: {
					'action': 'wc_rb_return_sms_api_fields',
					'form_type': 'wc_rb_update_sms_api_fields',
					'wc_rb_sms_gateway': $gateway_selected
				},
				url: ajax_obj.ajax_url,
				dataType: 'json',
				beforeSend: function() {
					$('.form-message').html("<div class='spinner is-active'></div>");
				},
				success: function(response) {
					//console.log(response);
					$('.form-message').html("");
					
					var row  = response.html;

					$('#authenticaion_api_data').html(row);
				}
			});
		}
	});
	
	$("#addPart").on("click", function(e,target) {
		
		var product_id = $("#select_rep_products").val();
		var $prices_inclu_exclu = $("#wc_prices_inclu_exclu").val(); 
		
		if(product_id == "") {
			alert("Please select part to add");
		} else {
			$.ajax({
				type: 'POST',
				data: {
					'action': 'wc_update_parts_row',
					'product': product_id,
					'prices_inclu_exclu':$prices_inclu_exclu
				},
				url: ajax_obj.ajax_url,
				dataType: 'json',

				beforeSend: function() {
					$('.parts_body_message').html("<div class='spinner is-active'></div>");
				},
				success: function(response) {
					//console.log(response);
					$('.parts_body_message').html("");
					
					var row  = response.row;

					$('.parts_body').append(row);
					
					$("#select_rep_products").select2('val', 'All');
					
					//Calculations update //function defined in my-admin.js
					wc_grand_total_calculations();
					update_devices_dropdown();
				}
			});
		}	
	});

	$("#addProduct").on("click", function(e,target) {
		
		var product_id = $("#select_product").val();
		var $prices_inclu_exclu = $("#wc_prices_inclu_exclu").val();
		
		if(product_id == "") {
			alert("Please select part to add");
		} else {
			$.ajax({
				type: 'POST',
				data: {
					'action': 'wc_update_parts_row',
					'product': product_id,
					'product_type': 'woo',
					'prices_inclu_exclu':$prices_inclu_exclu
				},
				url: ajax_obj.ajax_url,
				dataType: 'json',

				beforeSend: function() {
					$('.products_body_message').html("<div class='spinner is-active'></div>");
				},
				success: function(response) {
					//console.log(response);
					$('.products_body_message').html("");
					
					var row  = response.row;

					$('.products_body').append(row);
					
					$("#select_product").select2('val', 'All');
					
					//Calculations update //function defined in my-admin.js
					wc_grand_total_calculations();
					update_devices_dropdown();
				}
			});
		}	
	});
	
	$("#addService").on("click", function(e,target) {
		var service_id  = $("#select_rep_services").val();
		var $devices_id = $('[name="device_post_id_html[]"]').serializeArray();
		var $prices_inclu_exclu = $("#wc_prices_inclu_exclu").val();

		if(service_id == "") {
			alert("Please select service to add");
		} else {
			$.ajax({
				type: 'POST',
				data: {
					'action': 'wc_update_services_row',
					'devices': $devices_id,
					'service': service_id,
					'prices_inclu_exclu':$prices_inclu_exclu
				},
				url: ajax_obj.ajax_url,
				dataType: 'json',

				beforeSend: function() {
					$('.services_body_message').html("<div class='spinner is-active'></div>");
				},
				success: function(response) {
					//console.log(response);
					$('.services_body_message').html("");
					
					var row  = response.row;

					$('.services_body').append(row);
					
					$("#select_rep_services").select2('val', 'All');
					
					//Calculations update //function defined in my-admin.js
					wc_grand_total_calculations();

					update_devices_dropdown();
				}
			});
		}	
	});
	
	$("#addExtra").on("click", function(e,target) {
		
		$.ajax({
			type: 'POST',
			data: {
				'action': 'wc_update_extra_row',
				'extra': 'yes'
			},
			url: ajax_obj.ajax_url,
			dataType: 'json',

			beforeSend: function() {
				$('.extra_body_message').html("<div class='spinner is-active'></div>");
			},
			success: function(response) {
				//console.log(response);
				$('.extra_body_message').html("");

				var row  = response.row;

				$('.extra_body').append(row);

				//Calculations update //function defined in my-admin.js
				wc_grand_total_calculations();

				update_devices_dropdown();
			}
		});
	});

	$("#addtheDevice").on("click", function(e,target) {
		e.preventDefault();

		var $device_post_id_html	= $('[name="device_post_id_html"]').val();
		var $device_serial_id_html	= $('[name="device_serial_id_html"]').val();
		var $device_login_html		= $('[name="device_login_html"]').val();
		var $device_note_html 		= $('[name="device_note_html"]').val();
		
		$.ajax({
			type: 'POST',
			data: {
				'action': 'wc_add_device_row',
				'device_post_id_html': $device_post_id_html,
				'device_serial_id_html': $device_serial_id_html,
				'device_login_html': $device_login_html,
				'device_note_html': $device_note_html,
			},
			url: ajax_obj.ajax_url,
			dataType: 'json',

			beforeSend: function() {
				$('.device_body_message').html("<div class='spinner is-active'></div>");
			},
			success: function(response) {
				//console.log(response);
				$('.device_body_message').html("");

				if ( $device_post_id_html == 'All' || $device_post_id_html == null ) {
					$('.device_body_message').html("Please select a device");
				} else {
					var row  = response.row;

					$('.devices_body').append(row);
					$('[name="device_post_id_html"]').select2('val', 'All');
					$('[name="device_serial_id_html"]').val('');
					$('[name="device_login_html"]').val('');
					$('[name="device_note_html"]').val('');

					update_devices_dropdown();
				}
			}
		});
	});

	function update_devices_dropdown() {
		var $available_devices = '';
		var $counter = 1;
		var $selectedSingle = '';

		if ( $('[name="device_post_name_html[]"]').length ) {
			var i = 0;
			$('[name="device_post_name_html[]"]').each(function(i) {
				var deviceName = $('[name="device_post_name_html[]"]').get(i).value;
				var deviceID   = $('[name="device_post_id_html[]"]').get(i).value;
				var deviceSerial = $('[name="device_serial_id_html[]"]').get(i).value;

				$selectedSingle = deviceID;

				if ( deviceSerial != '' ) {
					deviceID = deviceID+'_'+deviceSerial;
					deviceName = deviceName+' ('+deviceSerial+')';
				}
				if ( $counter > 1 ) {
					$selectedSingle = '';
				}
				if(deviceID) { 
					$available_devices += '<option value="'+deviceID+'">'+deviceName+'</option>';
				}
				$counter++;
			});
		}
		
		if ( $('select.thedevice_selecter_identity').length ) {
			var i = 0;
			$('select.thedevice_selecter_identity').each(function(i) {
				var currentSelected = $(this).val();
				var defaultOption   = $(this).attr('data-label');

				if ( defaultOption != '' && i == 0 ) {
					$available_devices = '<option value="">'+defaultOption+'</option>' + $available_devices;
				}
				$(this).empty().append($available_devices);

				if (currentSelected == '') {
					currentSelected = $selectedSingle;
				}
				$(this).val(currentSelected).change();
			});
		}
	}
	
	$(document).on('click', '.editmedevice', function(e) {
		e.preventDefault();

		var $device_post_id_html = $(this).parents('.item-row').find('[name="device_post_id_html[]"]').val();
		var $device_serial_id_html = $(this).parents('.item-row').find('[name="device_serial_id_html[]"]').val();
		var $device_login_html = $(this).parents('.item-row').find('[name="device_login_html[]"]').val();
		var $device_note_html = $(this).parents('.item-row').find('[name="device_note_html[]"]').val();

		$('#deviceselectrow [name="device_post_id_html"]').select2();
		$('#deviceselectrow [name="device_post_id_html"]').val($device_post_id_html);
		$('#deviceselectrow [name="device_post_id_html"]').trigger('change');
		
		$('#deviceselectrow [name="device_serial_id_html"]').val($device_serial_id_html);
		$('#deviceselectrow [name="device_login_html"]').val($device_login_html);
		$('#deviceselectrow [name="device_note_html"]').val($device_note_html);

		$(this).parents('.item-row').remove();
	});

	$(document).on('click', '.parts_body .delme, .services_body .delme, .extra_body .delme, .products_body .delme, .wc_devices_row .delme', function(e) {
		e.preventDefault();

		$(this).parents('.item-row').remove();
		wc_grand_total_calculations();
	});	
	
	$(document).on("click", '[data-open="update_maintenance_reminder"]', function(e) {
		e.preventDefault();

		var recordID 	= $(this).attr("recordid");

		if (history.pushState) {
			var newurl = window.location.protocol + "//" + window.location.host + window.location.pathname + '?page=wc-computer-rep-shop-handle&reminder_id='+recordID;
			window.history.pushState({path:newurl},'',newurl);
		}
		$("p.addmaintenancereminderbtn").html('');
		$("#maintenancereminderReveal #replacement_part_reminder").html('');

		$.ajax({
			type: 'POST',
			data: {
				'action': 'wc_rb_reload_maintenance_update',
				'recordID': recordID 
			},
			url: ajax_obj.ajax_url,
			dataType: 'json',

			beforeSend: function() {
				$('#maintenancereminderReveal #replacement_part_reminder').html("<div class='spinner is-active'>Loading...</div>");
			},
			success: function(response) {
				//console.log(response);
				var message 	= response.message;
				var success 	= response.success;
				
				$('#maintenancereminderReveal #replacement_part_reminder').html(message);
				$('#maintenancereminderReveal').foundation('toggle');
			}
		});
	});

	$(document).on("click", '[data-open="manualRequestFeedback"]', function(e) {
		e.preventDefault();

		var recordID 	= $(this).attr("recordid");
		var data_security = $(this).attr("data-security");

		$.ajax({
			type: 'POST',
			data: {
				'action': 'wcrb_request_feedback',
				'recordID': recordID,
				'data_security': data_security
			},
			url: ajax_obj.ajax_url,
			dataType: 'json',

			beforeSend: function() {
				$('.request_feedback_message').html("<div class='spinner is-active'>Loading...</div>");
			},
			success: function(response) {
				//console.log(response);
				var message 	= response.message;
				var success 	= response.success;
				
				$('.request_feedback_message').html('<div class="callout success" data-closable="slide-out-right">'+message+'<button class="close-button" aria-label="Dismiss alert" type="button" data-close><span aria-hidden="true">&times;</span></button></div>');

				$("#reloadFeedbackRequestFields").load(window.location + " #reloadFeedbackRequestFields");
				$("#wc_order_notes").load(window.location + " #wc_order_notes");
			}
		});
	});

	$(document).on("click", '[data-open="addjoblistpaymentreveal"]', function(e) {
		e.preventDefault();

		var recordID 	= $(this).attr("recordid");

		$("#addjoblistpaymentreveal #replacementpart_joblist_formfields").html('');

		$.ajax({
			type: 'POST',
			data: {
				'action': 'wc_add_joblist_payment_form_output',
				'recordID': recordID 
			},
			url: ajax_obj.ajax_url,
			dataType: 'json',

			beforeSend: function() {
				$('#addjoblistpaymentreveal #replacementpart_joblist_formfields').html("<div class='spinner is-active'>Loading...</div>");
			},
			success: function(response) {
				//console.log(response);
				var message 	= response.message;
				var success 	= response.success;
				
				$('#addjoblistpaymentreveal #replacementpart_joblist_formfields').html(message);
				//$('#addjoblistpaymentreveal').foundation('toggle');
			}
		});
	});

	$(document).on("click", '[data-open="wcrbduplicatejob"]', function(e) {
		e.preventDefault();

		var recordID 	= $(this).attr("recordid");

		$("#wcrbduplicatejob #replacementpart_dp_page_formfields").html('');

		$.ajax({
			type: 'POST',
			data: {
				'action': 'wcrb_return_duplicate_job_fields',
				'recordID': recordID 
			},
			url: ajax_obj.ajax_url,
			dataType: 'json',

			beforeSend: function() {
				$('#wcrbduplicatejob #replacementpart_dp_page_formfields').html("<div class='spinner is-active'>Loading...</div>");
			},
			success: function(response) {
				//console.log(response);
				var message 	= response.message;
				var success 	= response.success;
				
				$('#wcrbduplicatejob #replacementpart_dp_page_formfields').html(message);
				//$('#addjoblistpaymentreveal').foundation('toggle');
			}
		});
	});

	//Change Tax Status Functionality
	$(document).on("click", ".change_tax_status", function(e, target){
		e.preventDefault();

		var recordID 	= $(this).attr("data-value");
		var recordType 	= $(this).attr("data-type");

		if(recordID == "" && recordType == "") {
			alert("Please select correct value");
		} else {
			
			$.ajax({
				type: 'POST',
				data: {
					'action': 'wc_update_tax_or_status',
					'recordID': recordID, 
					'recordType': recordType 
				},
				url: ajax_obj.ajax_url,
				dataType: 'json',
	
				beforeSend: function() {
					if ( recordType == 'thePayment' ) {
						$('#paymentstatusmessage').html("<div class='spinner is-active'></div>");
					} else {
						$('.form-update-message').html("<div class='spinner is-active'></div>");
					}
				},
				success: function(response) {
					//console.log(response);
					var message 	= response.message;
					var success 	= response.success;
					
					$('.form-update-message').html('<div class="callout success" data-closable="slide-out-right">'+message+'<button class="close-button" aria-label="Dismiss alert" type="button" data-close><span aria-hidden="true">&times;</span></button></div>');
	
					if(recordType == "tax") {
						//$('#poststuff_wrapper').load(document.URL +  ' #poststuff_wrapper');
						$("#poststuff_wrapper").load(document.location + " #poststuff");
					} else if(recordType == "status" || recordType == "inventory_count") {
						$("#job_status_wrapper").load(document.location + " #status_poststuff");
					} else if(recordType == "paymentStatus") {
						$("#payment_status_wrapper").load(document.location + " #paymentStatus_poststuff");
					} else if ( recordType == 'thePayment' ) {
						$("#payments_received_INjob").load(window.location + " #payments_received_INjob", function() {
							wc_grand_total_calculations();
						});
						$("#wc_order_notes").load(window.location + " #wc_order_notes");

						$( "#paymentstatusmessage" ).html( message );

						$("#thepaymentstable").load(window.location + " #thepaymentstable");
					}
				}
			});
		}
	});

	//Change Tax Status Functionality
	$(document).on("submit", "#purchaseVerifiction", function(e, target){
		e.preventDefault();

		var $userEmail 		= $("#userEmail").val();
		var $SpurchaseCode 	= $("#purchaseCode").val();

		if($userEmail == "" && $SpurchaseCode == "") {
			alert("Please enter both values!");
		} else {
			$.ajax({
				type: 'POST',
				data: {
					'action': 'wc_check_and_verify_purchase',
					'purchaseCode': $SpurchaseCode, 
					'userEmail': $userEmail 
				},
				url: ajax_obj.ajax_url,
				dataType: 'json',
	
				beforeSend: function() {
					$('.purchase_verification_alert').html("<div class='spinner is-active'></div>");
				},
				success: function(response) {
					//console.log(response);
					var message 	= response.message;
					var success 	= response.success;
					
					$('.purchase_verification_alert').html('<div class="callout success" data-closable="slide-out-right">'+message+'<button class="close-button" aria-label="Dismiss alert" type="button" data-close><span aria-hidden="true">&times;</span></button></div>');
					$("#purchase_box_update").load(window.location + " #purchase_box_update > *");
				}
			});
		}
	});
	
	//Change Tax Status Functionality
	$(document).on("change", ".update_status", function(e, target){
		e.preventDefault();

		var recordID 	= $(this).attr("data-post");
		var statusValue	= $(this).val();
		
		if(recordID == "") {
			alert("Please select correct value");
		} else {
			
			$.ajax({
				type: 'POST',
				data: {
					'action': 'wc_update_job_status',
					'recordID': recordID,
					'orderStatus': statusValue
				},
				url: ajax_obj.ajax_url,
				dataType: 'json',
	
				beforeSend: function() {
					$( "table.wp-list-table" ).prepend( "<div class='spinner is-active'></div>" );
				},
				success: function(response) {
					//console.log(response);
					var message 	= response.message;
					
					$( "table.wp-list-table" ).prepend( message );

					//$('#poststuff_wrapper').load(document.URL +  ' #poststuff_wrapper');
					$("#wpbody").load(document.location + " #wpbody-content");
				}
			});
		}
	});

	//Change Tax Status Functionality
	$(document).on("click", "[data-type='submit-wc-cr-history']", function(e, target){
		e.preventDefault();

		var recordID 		= $(this).attr("data-job-id");
		var recordName		= $('[name="add_history_note"]').val();
		var recordType	  	= $('[name="wc_history_type"]').val();
		var emailCustomer	= $('[name="wc_email_customer_manual_msg"]:checked').val();
		
		if(recordID == "") {
			alert("Please select correct value");
		} else {
			
			$.ajax({
				type: 'POST',
				data: {
					'action': 'wc_add_job_history_manually',
					'recordID': recordID,
					'recordName': recordName,
					'emailCustomer': emailCustomer,
					'recordType': recordType
				},
				url: ajax_obj.ajax_url,
				dataType: 'json',
	
				beforeSend: function() {
					$( ".add_history_log" ).html( "<div class='spinner is-active'></div>" );
				},
				success: function(response) {
					//console.log(response);
					var message 	= response.message;
				
					$( ".add_history_log" ).html( message );
					$("#wc_order_notes").load(window.location + " #wc_order_notes");
				}
			});
		}
	});

	$(document).on("click", 'button#WCRB_submit_device_prices', function(e) {
		e.preventDefault();

		var $wcRB_job_ID = $(this).attr('data-job-id');
		var $nonce = $("#wcrb_nonce_setting_device_field").val();
		var $device_id = $('[name="device_id[]"]').serializeArray();
		var $device_price = $('[name="device_price[]"]').serializeArray();
		var $device_status = $('[name="device_status[]"]').serializeArray();

		$.ajax({
			type: 'POST',
			data: {
				'action': 'wc_rb_update_the_prices',
				'device_id': $device_id,
				'device_price': $device_price,
				'device_status': $device_status,
				'wcrb_nonce_setting_device_field': $nonce,
				'wcrb_job_id': $wcRB_job_ID,
			},
			url: ajax_obj.ajax_url,
			dataType: 'json',

			beforeSend: function() {
				$( ".prices_message" ).html( "<div class='spinner is-active'></div>" );
			},
			success: function(response) {
				var message = response.message;
				var success = response.success;

				$('.prices_message').html('<div class="callout success" data-closable="slide-out-right">'+message+'<button class="close-button" aria-label="Dismiss alert" type="button" data-close><span aria-hidden="true">&times;</span></button></div>');
				
				if (success == 'YES') {
					//Something on Success
				}
			}
		});
	});

	$(document).on("click", 'button#WCRB_submit_type_prices', function(e) {
		e.preventDefault();

		var $wcRB_job_ID = $(this).attr('data-job-id');
		var $nonce = $("#wcrb_nonce_setting_device_field").val();
		var $type_id = $('[name="type_id[]"]').serializeArray();
		var $type_price = $('[name="type_price[]"]').serializeArray();
		var $type_status = $('[name="type_status[]"]').serializeArray();

		$.ajax({
			type: 'POST',
			data: {
				'action': 'wc_rb_update_the_prices',
				'type_id': $type_id,
				'type_price': $type_price,
				'type_status': $type_status,
				'wcrb_nonce_setting_device_field': $nonce,
				'wcrb_job_id': $wcRB_job_ID,
			},
			url: ajax_obj.ajax_url,
			dataType: 'json',

			beforeSend: function() {
				$( ".prices_message" ).html( "<div class='spinner is-active'></div>" );
			},
			success: function(response) {
				var message = response.message;
				var success = response.success;

				$('.prices_message').html('<div class="callout success" data-closable="slide-out-right">'+message+'<button class="close-button" aria-label="Dismiss alert" type="button" data-close><span aria-hidden="true">&times;</span></button></div>');
				
				$(".reloadthedevices").load(window.location + " .reloadthedevices");

				if (success == 'YES') {
					//Something on Success
				}
			}
		});
	});

	$(document).on("click", 'button#WCRB_submit_brand_prices', function(e) {
		e.preventDefault();

		var $wcRB_job_ID = $(this).attr('data-job-id');
		var $nonce = $("#wcrb_nonce_setting_device_field").val();
		var $brand_id = $('[name="brand_id[]"]').serializeArray();
		var $brand_price = $('[name="brand_price[]"]').serializeArray();
		var $brand_status = $('[name="brand_status[]"]').serializeArray();

		$.ajax({
			type: 'POST',
			data: {
				'action': 'wc_rb_update_the_prices',
				'brand_id': $brand_id,
				'brand_price': $brand_price,
				'brand_status': $brand_status,
				'wcrb_nonce_setting_device_field': $nonce,
				'wcrb_job_id': $wcRB_job_ID,
			},
			url: ajax_obj.ajax_url,
			dataType: 'json',

			beforeSend: function() {
				$( ".prices_message" ).html( "<div class='spinner is-active'></div>" );
			},
			success: function(response) {
				var message = response.message;
				var success = response.success;

				$('.prices_message').html('<div class="callout success" data-closable="slide-out-right">'+message+'<button class="close-button" aria-label="Dismiss alert" type="button" data-close><span aria-hidden="true">&times;</span></button></div>');
				
				$(".reloadthedevices").load(window.location + " .reloadthedevices");

				if (success == 'YES') {
					//Something on Success
				}
			}
		});
	});

	$(document).on("click", '[target="wc_rb_generate_woo_order"]', function(e) {
		e.preventDefault();

		var $wcRB_job_ID = $(this).attr('recordid');

		$.ajax({
			type: 'POST',
			data: {
				'action': 'wc_rb_generate_woocommerce_order',
				'wcrb_submit_type': 'create_the_order',
				'wcrb_job_id': $wcRB_job_ID,
			},
			url: ajax_obj.ajax_url,
			dataType: 'json',

			beforeSend: function() {
				$( ".order_action_messages" ).html( "<div class='spinner is-active'></div>" );
			},
			success: function(response) {
				//console.log(response);
				var message = response.message;
				var success = response.success;
				
				//console.log(message);

				$('.order_action_messages').html('<div class="callout success" data-closable="slide-out-right">'+message+'<button class="close-button" aria-label="Dismiss alert" type="button" data-close><span aria-hidden="true">&times;</span></button></div>');
				
				$("#payments_received_INjob").load(window.location + " #payments_received_INjob", function() {
					wc_grand_total_calculations();
				});
			
				$("#wc_order_notes").load(window.location + " #wc_order_notes");

				if (success == 'YES') {
					//Something on Success
				}
			}
		});
	});

	$( '.wcrb_select_customers' ).select2({
		ajax: {
			url: ajaxurl,
			dataType: 'json',
			delay: 250, // delay in ms while typing when to perform a AJAX search
			data: function( params ) {
				return {
					q: params.term, // search query
					action: 'wcrb_return_customer_data_select2' // AJAX action for admin-ajax.php
				}
			},
			processResults: function( data ) {
				var options = []
				if( data ) {
					// data is the array of arrays with an ID and a label of the option
					$.each( data, function( index, text ) {
						options.push( { id: text[0], text: text[1] } )
					})
				}
				return {
					results: options
				}
			},
			cache: true
		},
		minimumInputLength: 3
	});

	$(document).on("change", '#updatecustomer', function(e) {
		var $value = $(this).val();

		$.ajax({
			type: 'POST',
			data: {
				'action': 'wcrb_reload_customer_data',
				'wcrb_load_reminder_form': 'yes',
				'post_user_id': $value,
			},
			url: ajax_obj.ajax_url,
			dataType: 'json',
			success: function(response) {
				//console.log(response);
				var message = response.message;

				$('.wcrb_customer_info').html(message);
			}
		});
	});

	$(document).on("click", '[target="wcrb_generate_estimate_to_order"]', function(e) {
		e.preventDefault();

		var $wcRB_job_ID = $(this).attr('recordid');

		$.ajax({
			type: 'POST',
			data: {
				'action': 'wcrb_generate_repair_order_from_estimate',
				'wcrb_submit_type': 'create_the_order',
				'wcrb_estimate_id': $wcRB_job_ID,
			},
			url: ajax_obj.ajax_url,
			dataType: 'json',

			beforeSend: function() {
				$( ".order_action_messages" ).html( "<div class='spinner is-active'></div>" );
			},
			success: function(response) {
				//console.log(response);
				var message = response.message;
				var success = response.success;
				
				//console.log(message);
				$('.order_action_messages').html('<div class="callout success" data-closable="slide-out-right">'+message+'<button class="close-button" aria-label="Dismiss alert" type="button" data-close><span aria-hidden="true">&times;</span></button></div>');

				if (success == 'YES') {
					//Something on Success
				}
			}
		});
	});

	$(document).on("click", '[target="wcrb_send_estimate_to_customer"]', function(e) {
		e.preventDefault();

		var $wcRB_job_ID = $(this).attr('recordid');

		$.ajax({
			type: 'POST',
			data: {
				'action': 'wcrb_send_estimate_to_customer',
				'wcrb_submit_type': 'send_the_email',
				'wcrb_estimate_id': $wcRB_job_ID,
			},
			url: ajax_obj.ajax_url,
			dataType: 'json',

			beforeSend: function() {
				$( ".order_action_messages" ).html( "<div class='spinner is-active'></div>" );
			},
			success: function(response) {
				//console.log(response);
				var message = response.message;
				var success = response.success;
				
				//console.log(message);
				$('.order_action_messages').html('<div class="callout success" data-closable="slide-out-right">'+message+'<button class="close-button" aria-label="Dismiss alert" type="button" data-close><span aria-hidden="true">&times;</span></button></div>');

				if (success == 'YES') {
					//Something on Success
				}
			}
		});
	});

	$(document).on("click", '[data-open="send_reminder_test"]', function(e) {
		e.preventDefault();

		var $reminderID = $(this).attr('recordid');

		$.ajax({
			type: 'POST',
			data: {
				'action': 'wcrb_load_reminder_test_form',
				'wcrb_load_reminder_form': 'yes',
				'reminder_id': $reminderID,
			},
			url: ajax_obj.ajax_url,
			dataType: 'json',

			beforeSend: function() {
				$( ".send_test_reminder" ).html( "<div class='spinner is-active'></div>" );
			},
			success: function(response) {
				//console.log(response);
				var message = response.message;

				$('.send_test_reminder').html(message);
				
				if (success == 'YES') {
					//Something on Success
				}
			}
		});
	});

	$(document).on("submit", "#submitTestReminderForm", function(e) {
		e.preventDefault();

		var $reminderID	 = $('[name="testReminderID"]').val();
		var $emailTestTo = $('[name="testReminderMailTo"]').val();

		$.ajax({
			type: 'POST',
			data: {
				'action': 'wcrb_send_reminder_test_form',
				'wcrb_send_reminder_form': 'yes',
				'reminder_id': $reminderID,
				'testmailto': $emailTestTo,
			},
			url: ajax_obj.ajax_url,
			dataType: 'json',

			beforeSend: function() {
				$( ".submittheremindertest" ).html( "<div class='spinner is-active'></div>" );
			},
			success: function(response) {
				//console.log(response);
				var message = response.message;

				$('.submittheremindertest').html(message);
				
				if (success == 'YES') {
					//Something on Success
				}
			}
		});
	});

	$(document).on("submit", 'form[name="wcrb_form_submit_payment"]', function(e) {
		e.preventDefault();

		var $wcrb_payment_note			 = $('[name="wcrb_payment_note"]').val();
		var $wcrb_payment_datetime 		 = $('[name="wcrb_payment_datetime"]').val();
		var $wcRB_payment_status 		 = $('[name="wcRB_payment_status"]').val();
		var $wcRB_payment_method 		 = $('[name="wcRB_payment_method"]').val();
		var $wcRb_payment_amount 		 = $('[name="wcRb_payment_amount"]').val();
		var $wcrb_job_id				 = $('[name="wcrb_job_id"]').val();
		var $wcrb_nonce_add_payment_field = $('[name="wcrb_nonce_add_payment_field"]').val();

		$.ajax({
			type: 'POST',
			data: {
				'action': 'wc_rb_add_payment_into_job',
				'wcrb_payment_note': $wcrb_payment_note,
				'wcrb_payment_datetime': $wcrb_payment_datetime,
				'wcRB_payment_status': $wcRB_payment_status,
				'wcRB_payment_method': $wcRB_payment_method,
				'wcRb_payment_amount': $wcRb_payment_amount,	
				'wcrb_job_id': $wcrb_job_id,
				'wcrb_nonce_add_payment_field': $wcrb_nonce_add_payment_field
			},
			url: ajax_obj.ajax_url,
			dataType: 'json',

			beforeSend: function() {
				$( ".wcrb_payment_status_msg" ).html( "<div class='spinner is-active'></div>" );
			},
			success: function(response) {
				//console.log(response);
				var message = response.message;
				var success = response.success;
				
				$('.wcrb_payment_status_msg').html('<div class="callout success" data-closable="slide-out-right">'+message+'<button class="close-button" aria-label="Dismiss alert" type="button" data-close><span aria-hidden="true">&times;</span></button></div>');
				$("#payments_received_INjob").load(window.location + " #payments_received_INjob", function() {
					wc_grand_total_calculations();
				});
				$("#wc_order_notes").load(window.location + " #wc_order_notes");

				if (success == 'YES') {
					$('form[name="wcrb_form_submit_payment"]').trigger('reset');
					$('.wcrb_amount_paying').html('0.00');
					$('select[name="wc_payment_status"]').val($wcRB_payment_status).change();
				}
			}
		});
	});

	$(document).on("submit", 'form[name="wcrb_jl_form_submit_payment"]', function(e) {
		e.preventDefault();

		var $wcrb_payment_note			 = $('[name="wcrb_payment_note"]').val();
		var $wcrb_payment_datetime 		 = $('[name="wcrb_payment_datetime"]').val();
		var $wcRB_payment_status 		 = $('[name="wcRB_payment_status"]').val();
		var $wcRB_payment_method 		 = $('[name="wcRB_payment_method"]').val();
		var $wcRb_payment_amount 		 = $('[name="wcRb_payment_amount"]').val();
		var $wcrb_job_id				 = $('[name="wcrb_job_id"]').val();
		var $wcRB_after_jobstatus 		 = $('[name="wcRB_after_jobstatus"]').val();
		var $wcrb_nonce_add_payment_field = $('[name="wcrb_nonce_add_payment_field"]').val();

		$.ajax({
			type: 'POST',
			data: {
				'action': 'wc_rb_add_payment_into_job',
				'wcrb_payment_note': $wcrb_payment_note,
				'wcrb_payment_datetime': $wcrb_payment_datetime,
				'wcRB_payment_status': $wcRB_payment_status,
				'wcRB_payment_method': $wcRB_payment_method,
				'wcRb_payment_amount': $wcRb_payment_amount,	
				'wcRB_after_jobstatus': $wcRB_after_jobstatus,
				'wcrb_job_id': $wcrb_job_id,
				'wcrb_nonce_add_payment_field': $wcrb_nonce_add_payment_field
			},
			url: ajax_obj.ajax_url,
			dataType: 'json',

			beforeSend: function() {
				$( ".set_addpayment_joblist_message" ).html( "<div class='spinner is-active'></div>" );
			},
			success: function(response) {
				//console.log(response);
				var message = response.message;
				var success = response.success;
				
				$('.set_addpayment_joblist_message').html('<div class="callout success" data-closable="slide-out-right">'+message+'<button class="close-button" aria-label="Dismiss alert" type="button" data-close><span aria-hidden="true">&times;</span></button></div>');

				if (success == 'YES') {
					$('form[name="wcrb_jl_form_submit_payment"]').trigger('reset');
					$('.wcrb_amount_paying').html('0.00');
					$("#post-"+$wcrb_job_id).load(document.location + " #post-"+$wcrb_job_id+">*");
				}
			}
		});
	});

	$(document).on("submit", 'form[name="wcrb_duplicate_page_return"]', function(e) {
		e.preventDefault();

		var $form 	= $(this);
		var formData = $form.serialize();
		var $perform_act = "wcrb_duplicate_page_perform";
		var $success_class = ".duplicate_page_return_message";

		$.ajax({
			type: 'POST',
			data: formData + '&action='+$perform_act,
			url: ajax_obj.ajax_url,
			async: true,
			mimeTypes:"multipart/form-data",
			dataType: 'json',
			beforeSend: function() {
				$($success_class).html( "<div class='spinner is-active'></div>" );
			},
			success: function(response) {
				//console.log(response);
				var message = response.message;
				var redirect_url = response.redirect_url;
				
				$($success_class).html('<div class="callout success" data-closable="slide-out-right">'+message+'<button class="close-button" aria-label="Dismiss alert" type="button" data-close><span aria-hidden="true">&times;</span></button></div>');

				if (redirect_url != 'NO') {
					console.log(redirect_url);
					window.location.href = redirect_url;
				}
			}
		});
	});
	
	jQuery(document).ready(function() {
        $('.bc-product-search').select2({
            ajax: {
                url: ajaxurl,
                data: function (params) {
                    return {
                        term         : params.term,
                        action       : 'woocommerce_json_search_products_and_variations',
                        security: $(this).attr('data-security'),
						exclude_type : $( this ).data( 'exclude_type' ),
						display_stock: $( this ).data( 'display_stock' )
                    };
                },
                processResults: function( data ) {
                    var terms = [];
                    if ( data ) {
                        $.each( data, function( id, text ) {
                            terms.push( { id: id, text: text } );
                        });
                    }
                    return {
                        results: terms
                    };
                },
                cache: true
            }
        });

		$(document).on('click', '.wcRbJob_services_wrap #reloadTheExtraFields .delmeextrafield', function(e) {
			var $array_index = $(this).attr("recordid");
			var $post_value = $(this).attr("data-value");
	
			$.ajax({
				type: 'POST',
				data: {
					'action': 'wcrb_delete_job_est_extra_field',
					'array_index': $array_index,
					'post_id':$post_value 
				},
				url: ajax_obj.ajax_url,
				dataType: 'json',
	
				beforeSend: function() {
					$('.wcRbJob_services_wrap #reloadTheExtraFields .attachment_body_message').html("<div class='spinner is-active'>Loading...</div>");
				},
				success: function(response) {
					//console.log(response);
					var message 	= response.message;
					var success 	= response.success;
					
					$('.wcRbJob_services_wrap #reloadTheExtraFields .attachment_body_message').html(message);
					
					if (success == 'YES') {
						$("#reloadTheExtraFields").load(window.location + " .extrafieldstable");
					}
				}
			});
		});
    });
})(jQuery); //jQuery main function ends strict Mode on