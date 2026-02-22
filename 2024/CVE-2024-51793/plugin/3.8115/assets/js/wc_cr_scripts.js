// JavaScript Document
(function($) {
    "use strict";
	
	//calling foundation js
	jQuery(document).foundation();
	
	jQuery(document).ready(function() {
		$('#rep_devices, #customer').select2();

		$("#customerFormReveal").on("click", function() {
			$("#addNewCustomer").toggleClass('displayBlock');

			if($('.addNewCustomer.displayBlock').length) {
				$("#verifyCustomer").val("1");
			} else {
				$("#verifyCustomer").val("0");
			}
		});

		$(".orderstatusholder").on("click", "a.wcCrJobHistoryHideShowBtn", function(event) {
			event.preventDefault();
			$(".wcCrShowHideHistory").toggle('displayBlock');
		});
	});

	function printDiv(divName) {
		var printContents = document.getElementById(divName).innerHTML;
		var originalContents = document.body.innerHTML;
   
		document.body.innerHTML = printContents;
   		window.print();
   		document.body.innerHTML = originalContents;
   }

   $(document).on('click', '#btnPrint', function() {
		printDiv('invoice-box');
   })
})(jQuery); //jQuery main function ends strict Mode on