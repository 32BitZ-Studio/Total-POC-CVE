/**
 * jQuery select2vp Sortable
 * - enable select2vp to be sortable via normal select element
 * 
 * author      : Vafour
 * inspired by : jQuery Chosen Sortable (https://github.com/mrhenry/jquery-chosen-sortable)
 * License     : GPL
 */

(function($){
	$.fn.extend({
		select2vpSortableOrder: function(){
			var $this = this.filter('[multiple]');

			$this.each(function(){
				var $select  = $(this);

				// skip elements not select2vp-ed
				if(typeof($select.data('select2vp')) !== 'object'){
					return false;
				}

				var $select2vp = $select.siblings('.select2vp-container'),
				    unselected = [],
				    sorted;

				$select.find('option').each(function(){
					!this.selected && unselected.push(this);
				});

				sorted = $($select2vp.find('.select2vp-choices li[class!="select2vp-search-field"]').map( function() {
					if (!this) {
						return undefined;
					}
					var id = $(this).data('select2vpData').id;
					return $select.find('option[value="' + id + '"]')[0];
				}));

				sorted.push.apply(sorted, unselected);
				$select.children().remove();
				$select.append(sorted);
			});

			return $this;
		},
		select2vpSortable: function(){
			var args         = Array.prototype.slice.call(arguments, 0);
			    $this        = this.filter('[multiple]'),
			    validMethods = ['destroy'];

			if(args.length === 0 || typeof(args[0]) === 'object')
			{
				var defaultOptions = {
					bindOrder       : 'formSubmit', // or sortableStop
					sortableOptions : {
						placeholder : 'ui-state-highlight',
						items       : 'li:not(.select2vp-search-field)',
						tolerance   : 'pointer'
					}
				};
				var options = $.extend(defaultOptions, args[0]);

				// Init select2vp only if not already initialized to prevent select2vp configuration loss
				if(typeof($this.data('select2vp')) !== 'object'){
					$this.select2vp();
				}

				$this.each(function(){
					var $select  = $(this),
					    $select2vpchoices = $select.siblings('.select2vp-container').find('.select2vp-choices');

					// Init jQuery UI Sortable
					$select2vpchoices.sortable(options.sortableOptions);

					switch(options.bindOrder){
						case 'sortableStop':
							// apply options ordering in sortstop event
							$select2vpchoices.on("sortstop.select2vpsortable", function( event, ui ) {
								$select.select2vpSortableOrder();
							});
							$select.on('change', function(e){
								$(this).select2vpSortableOrder();
							});
							break;
						default:
							// apply options ordering in form submit
							$select.closest('form').unbind('submit.select2vpsortable').on('submit.select2vpsortable', function(){
								$select.select2vpSortableOrder();
							});
					}

				});
			}
			else if(typeof(args[0] === 'string'))
			{
				if($.inArray(args[0], validMethods) == -1)
				{
					throw "Unknown method: " + args[0];
				}
				if(args[0] === 'destroy')
				{
					$this.select2vpSortableDestroy();
				}
			}
			return $this;
		},
		select2vpSortableDestroy: function(){
			var $this = this.filter('[multiple]');
			$this.each(function(){
				var $select         = $(this),
				    $select2vpchoices = $select.parent().find('.select2vp-choices');

				// unbind form submit event
				$select.closest('form').unbind('submit.select2vpsortable');

				// unbind sortstop event
				$select2vpchoices.unbind("sortstop.select2vpsortable");

				// destroy select2vpSortable
				$select2vpchoices.sortable('destroy');
			});
			return $this;
		}
	});
}(jQuery));