

var wcsearch_query_string = decodeURIComponent(wcsearch_js_objects.query_string); //place default values here

var wcsearch_recount_attempts = 0;
var wcsearch_max_counters = 200;
var wcsearch_request_processing = false;

var wcsearch_do_scroll = true;

(function($) {
	"use strict";
	
	$(function() {
		wcsearch_init();
	});
	
	window.wcsearch_init = function() {
		wcsearch_process_main_search_fields();
		wcsearch_custom_input_controls();
		wcsearch_setup_terms_separators();
		wcsearch_sticky_scroll();
		wcsearch_continue_recounting();
		wcsearch_init_open_close_dep_inputs();
		wcsearch_post_off_beforeunload();
	}
	
	window.wcsearch_post_off_beforeunload = function() {
		
		// Prevent WP from asking confirmation to navigate away from the current post in admin.
		if ($("#post").length) {
			$(window).off("beforeunload");
		}
	}
	
	window.wcsearch_init_open_close_dep_inputs = function() {
		$("form").each( function(index, form) {
			wcsearch_open_close_dep_inputs($(form));
		});
	}
	
	window.wcsearch_is_model = function() {
		return $(".wcsearch-search-model-wrapper").length;
	}
	
	window.wcsearch_search_input = (function(input) {
		this.input = input;
		
		this.get_value = function() {
			if (this.input.is(".wcsearch-hidden-field[type=hidden]")) {
				return { name: this.input.prop("name"), value: this.input.val() };
			}
			
			if (this.input.find("[type=checkbox]").length) {
				var checkboxes = this.input.find("[type=checkbox]");
				
				var checkboxes_name;
				var selected = [];
				checkboxes.each(function() {
					if ($(this).is(":checked")) {
						selected.push($(this).val());
					}
				    checkboxes_name = $(this).prop("name");
				});
				
				if (selected.length) {
					
					var result = [{ name: checkboxes_name, value: selected.join(",") }];
					
					if (this.input.data("relation") == "AND") {
						result.push({ name: checkboxes_name+"_relation", value: this.input.data("relation") });
					}
					
					return result;
				}
			}
			
			if (this.input.find("[type=radio]:checked").length) {
				var radio = this.input.find("[type=radio]:checked");
				
				return { name: radio.prop("name"), value: radio.val() };
			}
			
			if (this.input.attr("data-type") == "price" || this.input.attr("data-type") == "number") {
				
				var slug = this.input.attr("data-slug");
			
				// price 2 inputs/dropdowns cahnge price input
				if (this.input.find(".wcsearch-search-input-1, .wcsearch-search-input-2").length) {
					
					var min_input = this.input.find(".wcsearch-search-input-1");
					var max_input = this.input.find(".wcsearch-search-input-2");
					
					var min = '';
					if (min_input.val() && !isNaN(min_input.val())) {
						min = min_input.val();
					}
					var max = '';
					if (max_input.val() && !isNaN(max_input.val())) {
						max = max_input.val();
					}
					var val = '';
					if (min || max) {
						val = min+'-'+max;
					}
					
					this.input.find("input[name="+slug+"]").val(val); 
				}
				
				// price single dropdown
				if (this.input.find(".wcsearch-search-input-single-select").length) {
				
					var val = this.input.find(".wcsearch-search-input-single-select").val();
					
					return { name: slug, value: val };
				}
				
				// price range/single slider
				if (this.input.find("input[name="+slug+"]:not([type=radio])").length) {
					var val = this.input.find("input[name="+slug+"]").val();
					
					return { name: slug, value: val };
				}
			}
			
			if (this.input.find("input[name=more_filters]").length) {
				var val = this.input.find("input[name=more_filters]").val();
				
				return { name: 'more_filters', value: val };
			}
			
			if (this.input.find("input[name=radius]").length) {
				var val = this.input.find("input[name=radius]").val();
				
				return { name: 'radius', value: val };
			}
			
			if (this.input.find("input.wcsearch-date-input").length) {
				var val = this.input.find("input.wcsearch-date-input").val();
				var name = this.input.find("input.wcsearch-date-input").attr("name");
				
				if (val != "-") {
					return { name: name, value: val };
				}
			}
			
			if (this.input.find("input.wcsearch-search-string-input").length) {
				var val = this.input.find("input.wcsearch-search-string-input").val();
				var name = this.input.find("input.wcsearch-search-string-input").attr("name");
				
				return { name: name, value: val };
			}
			
			if (this.input.find("input.wcsearch-search-terms-buttons-input").length) {
				var val = this.input.find("input.wcsearch-search-terms-buttons-input").val();
				var name = this.input.find("input.wcsearch-search-terms-buttons-input").attr("name");
				
				if (val) {
					
					var result = [{ name: name, value: val }];
					
					if (this.input.data("relation") == "AND") {
						result.push({ name: name+"_relation", value: this.input.data("relation") });
					}
					
					return result;
				}
			}
			
			if (this.input.find(".wcsearch-main-search-field").length) {
				if (this.input.data("type") == "tax" || this.input.data("type") == "select") {
					var tax_val = this.input.find("[id^=selected_tax]").val();
					var tax_name = this.input.find("[id^=selected_tax]").prop("name");
					
					if (this.input.find("input[name='keywords'], input[name='address']").length) {
						// both keywords/address and tax
						
						var field_name = '';
						var place_id = '';
						if (this.input.find("input[name='keywords']").length) {
							field_name = "keywords";
						} else if (this.input.find("input[name='address']").length) {
							field_name = "address";
							if (this.input.find("input[name='place_id']").length) {
								place_id = this.input.find("input[name='place_id']").val();
							}
						}
						var string_val = this.input.find("input[name="+field_name+"]").val();
						
						if (string_val === '') {
							return { name: tax_name, value: tax_val };
						}
						
						if (tax_val === '') {
							if (string_val) {
								return [{ name: field_name, value: string_val }, { name: "place_id", value: place_id }];
							}
						} else {
							
							var string_in_select;
							// look through select, when found - it is tax term, not keywords/address
							if (this.input.find("select option").filter(function () { return $(this).text() == string_val; }).length) {
								string_in_select = { name: tax_name, value: tax_val };
							}
							
							if (string_in_select) {
								return string_in_select;
							} else {
								return [{ name: field_name, value: string_val }, { name: "place_id", value: place_id }];
							}
						}
					} else {
						// only tax
						
						var result = [{ name: tax_name, value: tax_val }];
						
						if (tax_val && this.input.data("relation") == "AND") {
							result.push({ name: tax_name+"_relation", value: this.input.data("relation") });
						}
						
						return result;
					}
				} else if (this.input.find("input[name='keywords'], input[name='address']").length) {
					
					var field_name = '';
					var place_id = '';
					if (this.input.find("input[name='keywords']").length) {
						field_name = "keywords";
					} else if (this.input.find("input[name='address']").length) {
						field_name = "address";
						if (this.input.find("input[name='place_id']").length) {
							place_id = this.input.find("input[name='place_id']").val();
						}
					}
					var string_val = this.input.find("input[name="+field_name+"]").val();
					
					return [{ name: field_name, value: string_val }, { name: "place_id", value: place_id }];
				}
			} else {
				// tax range slider
				if (this.input.has(".wcsearch-range-slider, .wcsearch-single-slider").find("input[data-tax]").length) {
					var tax_val = this.input.find("input[data-tax]").val();
					var tax_name = this.input.find("input[data-tax]").prop("name");
					
					return { name: tax_name, value: tax_val };
				}
			}
			
			if (this.input.find("select.wcsearch-selectbox-input").length) {
				var val = this.input.find("select.wcsearch-selectbox-input").val();
				var name = this.input.find("select.wcsearch-selectbox-input").attr("name");
				
				return { name: name, value: val };
			}
			
			return '';
		},
		this.reset = function() {
			
			if (this.input.hasClass("wcsearch-search-input-always-closed")) {
				return false;
			}
			
			// temporarily disable submission on changes while resetting
			wcsearch_request_processing = true;
			
			if (this.input.find(".wcsearch-main-search-field").length) {
				this.input.find(".wcsearch-main-search-field").trigger("reset");
			}
			
			if (this.input.find(".wcsearch-search-input-1, .wcsearch-search-input-2").length) {
				this.input.find("input, select").val('');
			}
			
			if (this.input.find("select").length) {
				this.input.find("select").prop('selectedIndex', 0);
			}
			
			if (this.input.find("[type=radio]").length) {
				this.input.find("[type=radio]").prop('checked', false);
				this.input.find(".wcsearch-radio-reset-btn").remove();
			}
			
			if (this.input.find("[type=checkbox]").length) {
				this.input.find("[type=checkbox]").prop('checked', false);
			}
			
			if (this.input.find("input.wcsearch-date-input").length) {
				this.input.find("input.wcsearch-date-input").trigger("reset");
			}
			
			if (this.input.find("input.wcsearch-search-string-input").length) {
				this.input.find("input.wcsearch-search-string-input").val('');
			}
			
			if (this.input.find("input.wcsearch-search-terms-buttons-input").length) {
				this.input.find("input.wcsearch-search-terms-buttons-input").val('');
				
				this.input.find(".wcsearch-search-term-button").removeClass("wcsearch-search-term-button-active");
			}
			
			// range slider
			if (this.input.find(".wcsearch-range-slider").length) {
				var slider = this.input.find(".wcsearch-range-slider");
				var options = slider.slider('option');
				
				slider.slider("values", [options.min, options.max]);
				slider.slider("option", "slide")(null, { values: [options.min, options.max] });
			}
			
			// single slider
			if (this.input.find(".wcsearch-single-slider").length) {
				var slider = this.input.find(".wcsearch-single-slider");
				var option = slider.slider("option");
				var input = this.input.find("input");
				
				if (this.input.data("default_values")) {
					var value = this.input.data("default_values");
				} else {
					var value = option.min;
				}
				
				slider.slider("value", value);
				slider.slider("option", "slide")(null, { value: value });
				input.val(value);
			}
			
			wcsearch_request_processing = false;
		},
		this.is_opened = function() {
			if (!this.input.hasClass("wcsearch-search-input-closed")) {
				return true;
			}
		},
		this.open = function() {
			this.input.removeClass("wcsearch-search-input-closed");
			this.input.addClass("wcsearch-search-input-opened");
		},
		this.close = function() {
			this.input.removeClass("wcsearch-search-input-opened");
			this.input.addClass("wcsearch-search-input-closed");
		}
	});
	
	window.wcsearch_get_luma_color = function(c) {
		var c = c.substring(1);      // strip #
		var rgb = parseInt(c, 16);   // convert rrggbb to decimal
		var r = (rgb >> 16) & 0xff;  // extract red
		var g = (rgb >>  8) & 0xff;  // extract green
		var b = (rgb >>  0) & 0xff;  // extract blue

		var luma = 0.2126 * r + 0.7152 * g + 0.0722 * b; // per ITU-R BT.709

		return luma;
	}
	
	window.wcsearch_sticky_scroll = function() {
		$('.wcsearch-sticky-scroll').each(function() {
			var element = $(this);
			var form = element.find("form");
			var id = form.data("id");
			var toppadding = (form.data("toppadding")) ? form.data("toppadding") : 0;
			
			if (element.parents("div[class*='-map-sidebar']").length) {
				var map_sidebar = element.parents("div[class*='-map-sidebar']");
				var search_wrapper = map_sidebar.find(".wcsearch-search-wrapper");
				var listings_wrapper = map_sidebar.find("div[class*='-map-sidebar-listings-wrapper']");
				
				if (listings_wrapper.length) {
					var listings_wrapper_height = map_sidebar.height() - search_wrapper.outerHeight();
					listings_wrapper.height(listings_wrapper_height);
				}
			} else {
				if ($("body").hasClass("admin-bar")) {
					toppadding = toppadding + 32;
				}
				
				if ($(window).height() >= 768) {
					if ($('.site-header.header-fixed').length) {
						var headerHeight = $('.site-header.header-fixed').outerHeight();
						toppadding = toppadding + headerHeight;
					}
				}
	
				if (!$("#wcsearch-scroller-anchor-"+id).length) {
					var anchor = $("<div>", {
						id: 'wcsearch-scroller-anchor-'+id
					});
					element.before(anchor);
		
					var background = $("<div>", {
						id: 'wcsearch-sticky-scroll-background-'+id,
						class: 'wcsearch-sticky-scroll-background',
						style: {position: 'relative'}
					});
					element.after(background);
				}
					
				window["wcsearch_sticky_scroll_toppadding_"+id] = toppadding;
		
				$("#wcsearch-sticky-scroll-background-"+id).position().left = element.position().left;
				$("#wcsearch-sticky-scroll-background-"+id).position().top = element.position().top;
				$("#wcsearch-sticky-scroll-background-"+id).width(element.width());
				$("#wcsearch-sticky-scroll-background-"+id).height(element.height());
	
				var wcsearch_scroll_function = function(e) {
					var id = e.data.id;
					var toppadding = e.data.toppadding;
					var b = $(document).scrollTop();
					var d = $("#wcsearch-scroller-anchor-"+id).offset().top - toppadding;
					var c = e.data.obj;
					var e = $("#wcsearch-sticky-scroll-background-"+id);
					
					c.width(c.parent().width()).css({ 'z-index': 100 });
			
					// .wcsearch-scroller-bottom - this is special class used to restrict the area of scroll of map canvas
					if ($(".wcsearch-scroller-bottom").length) {
						var f = $(".wcsearch-scroller-bottom").offset().top - (c.height() + toppadding);
					} else {
						var f = $(document).height();
					}
			
					if (f > c.height()) {
						if (b >= d && b < f) { // fixed
							c.css({ position: "fixed", top: toppadding });
							e.css({ position: "relative" });
						} else { // unfixed
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
				
				$("#wcsearch-sticky-scroll-background-"+id).css({ position: "relative" });
				
				//if ($(document).width() >= 768) {
				var args = {id: id, obj: $(this), toppadding: toppadding};
				$(window).scroll(args, wcsearch_scroll_function);
				wcsearch_scroll_function({data: args});
				//}
			}
		});
	}

	window.wcsearch_create_radio_control_reset = function(item) {
		var delete_btn = $("<span>", {
			class: "wcsearch-radio-reset-btn wcsearch-fa wcsearch-fa-close",
			title: wcsearch_js_objects.radio_reset_btn_title
		}).appendTo(item);
		
		$(document).on("click", ".wcsearch-radio-reset-btn", function() {
			$(this).parent().find("input").prop('checked', false);
			$(this).parents("label").find("input").trigger("change");
			$(this).remove();
		});
	}
	$(".wcsearch-radio label input:checked").each(function() {
		wcsearch_create_radio_control_reset($(this).parents("label"));
	});
	$(document).on("click", ".wcsearch-radio label", function(event) {
		if ($(event.target).is(".wcsearch-radio-reset-btn")) {
			return false;
		}
		
		$(this).parents(".wcsearch-search-input-terms-column").parent().find(".wcsearch-radio-reset-btn").remove();
		$(this).parents(".wcsearch-search-model-input-terms-column").parent().find(".wcsearch-radio-reset-btn").remove();
		
		wcsearch_create_radio_control_reset($(this));
	});
	window.wcsearch_custom_input_controls = function() {
		// Custom input controls
		$(".wcsearch-checkbox label, .wcsearch-radio label").each(function() {
			if (!$(this).find(".wcsearch-control-indicator").length) {
				$(this).append($("<div>").addClass("wcsearch-control-indicator"));
			}
		});
		
		var slider_input_controls = function(el) {
			var sheet = document.createElement('style');
			document.body.appendChild(sheet);
			
			var prefs = ['webkit-slider-runnable-track', 'moz-range-track', 'ms-track'];
			
			var id = $(el).attr('id');
			var slider_color = $('#'+id).css("background-color");
			var curVal = parseInt(el.value);
			var rating = (curVal + 1) / 2;
			var gradientVal = (curVal - 1) * 12.5;
			var style = '';

			$('.wcsearch-range-slider-labels.'+id+' li').removeClass('wcsearch-range-slider-labels-active wcsearch-range-slider-labels-selected');
			var curLabel = $('.wcsearch-range-slider-labels.'+id).find('li:nth-child(' + curVal + ')');
			curLabel.addClass('wcsearch-range-slider-labels-active wcsearch-range-slider-labels-selected');
			curLabel.prevAll().addClass('wcsearch-range-slider-labels-selected');

			$('.wcsearch-range-slider-value.'+id).html(rating);
			
			var gradient_destination = 'to right';
			if (wcsearch_js_objects.is_rtl) {
				gradient_destination = 'to left';
			}

			for (var i = 0; i < prefs.length; i++) {
				style += '#'+id+'::-' + prefs[i] + '{background: linear-gradient(' + gradient_destination + ', ' + slider_color + ' 0%, ' + slider_color + ' ' + gradientVal + '%, #f0f0f0 ' + gradientVal + '%, #f0f0f0 100%)}';
			}
			sheet.textContent = style;
			
			var sum = 0;
			$('.wcsearch-range-slider-value').each(function() {
				sum += Number($(this).text());
			});
			var avg = Math.round(sum/$('.wcsearch-range-slider-value').length*10)/10;
			var avg_percents = Math.round(((sum/$('.wcsearch-range-slider-value').length)-1)*25);
			$('.wcsearch-progress-circle span').text(avg.toFixed(1));
			$('.wcsearch-progress-circle').removeClass().addClass('wcsearch-progress-circle').addClass('p'+avg_percents);
			if (avg_percents > 50) {
				$('.wcsearch-progress-circle').addClass('wcsearch-over50');
			}
		}
		$(".wcsearch-range-slider-input").each(function () {
			slider_input_controls(this);
		});
		$(".wcsearch-range-slider-input").on('input', function () {
			slider_input_controls(this);
		});
		$('.wcsearch-range-slider-labels li').on('click', function () {
			var index = $(this).index();
			var input = $(this).parents('.wcsearch-range-slider').find('.wcsearch-range-slider-input');
			input.val(index + 1).trigger('input');
		});
	}
	
	window.wcsearch_ajax_loader_target_show = function(target, scroll_to_anchor, offest_top) {
		if (typeof scroll_to_anchor != 'undefined' && scroll_to_anchor) {
			if (typeof offest_top == 'undefined' || !offest_top) {
				var offest_top = 0;
			}
			$('html,body').animate({scrollTop: scroll_to_anchor.offset().top - offest_top}, 'slow');
		}
		var target_id = target.attr("id");
		var form_id = target.attr("data-form-id");
		if (!$("[data-loader-id='"+target_id+"']").length) {
			var loader = $('<div data-loader-id="'+target_id+'" class="wcsearch-ajax-target-loading"><div class="wcsearch-loader wcsearch-loader-'+form_id+'"></div></div>');
			target.prepend(loader);
			loader.css({
				width: target.innerWidth(),
				height: target.innerHeight()
			});
			if (target.outerHeight() > 600) {
				loader.find(".wcsearch-loader").addClass("wcsearch-loader-max-top");
			}
		}
	}
	window.wcsearch_ajax_loader_target_hide = function(target_id) {
		$("[data-loader-id='"+target_id+"']").remove();
	}
	
	window.wcsearch_ajax_loader_show = function(msg) {
		var overlay = $('<div id="wcsearch-ajax-loader-overlay"><div class="wcsearch-loader"></div></div>');
	    $('body').append(overlay);
	}
	
	window.wcsearch_ajax_loader_hide = function() {
		$("#wcsearch-ajax-loader-overlay").remove();
	}
	
	window.wcsearch_ajax_iloader = $("<div>", { class: 'wcsearch-ajax-iloader' }).html('<div class="rect1"></div><div class="rect2"></div><div class="rect3"></div><div class="rect4"></div><div class="rect5"></div>');
	window.wcsearch_add_iloader_on_element = function(button) {
		button
		.attr('disabled', 'disabled')
		.wrapInner('<div class="wcsearch-hidden"></div>')
		.append(wcsearch_ajax_iloader);
	}
	window.wcsearch_delete_iloader_from_element = function(button) {
		button.find(".wcsearch-hidden").contents().unwrap();
		button.removeAttr('disabled').find(".wcsearch-ajax-iloader").remove();
	}
})(jQuery);

(function($) {
	"use strict";
	
	$(document).on("click",
			".wcsearch-search-input-closed .wcsearch-search-input-label," +
			".wcsearch-search-input-opened .wcsearch-search-input-label",
	function() {
		
		var input = new wcsearch_search_input($(this).parents(".wcsearch-search-input"))
		
		if (input.is_opened()) {
			input.close();
		} else {
			input.open();
		}
		
		wcsearch_setup_terms_separators();
	});
	
	$("body").on("change",
			".wcsearch-search-model-input input[type=\"checkbox\"]," +
			".wcsearch-search-model-input input[type=\"radio\"]",
	function() {
		var input = $(this).parents(".wcsearch-search-model-input");
		var values = [];
		input.find("input:checked").each(function() {
			values.push($(this).val());
		});
		input.attr("data-values", values.join(','));
		
		wcsearch_model_update_placeholders();
	});
	
	$("body").on("change",
			".wcsearch-search-model-input input[name=\"price\"]," +
			".wcsearch-search-model-input input[name=\"radius\"]," +
			".wcsearch-search-model-input select",
	function() {
		var input = $(this).parents(".wcsearch-search-model-input");
		var values = $(this).val();
		
		input.attr("data-values", values);
		
		wcsearch_model_update_placeholders();
	});
	
	$("body").on("change",
			".wcsearch-search-model-input select[name=field_price_min]," +
			".wcsearch-search-model-input select[name=field_price_max]",
	function() {
		var input = $(this).parents(".wcsearch-search-model-input");
		var values = [input.find("select[name=field_price_min]").val(), input.find("select[name=field_price_max]").val()];
		input.attr("data-values", values.join('-'));
		
		wcsearch_model_update_placeholders();
	});
	
	$("body").on("change",
			".wcsearch-search-model-input input[id^='selected_tax']",
	function() {
		var input = $(this).parents(".wcsearch-search-model-input");
		var values = $(this).val();
		input.attr("data-values", values);
		
		wcsearch_model_update_placeholders();
	});
	
	$("body").on("change",
			".wcsearch-search-model-input-one-select select," +
			".wcsearch-search-model-input-tax-select select",
	function() {
		var input = $(this).parents(".wcsearch-search-model-input");
		var values = $(this).val();
		input.attr("data-values", values);
		
		wcsearch_model_update_placeholders();
	});
	
	$("body").on("change",
			".wcsearch-search-model-input-range input," +
			".wcsearch-search-model-input-single-slider input",
	function() {
		var input = $(this).parents(".wcsearch-search-model-input");
		var values = $(this).val();
		input.attr("data-values", values);
		
		wcsearch_model_update_placeholders();
	});
	
	$("body").on("change",
			".wcsearch-search-model-input-1," +
			".wcsearch-search-model-input-2",
	function() {
		var input = $(this).parents(".wcsearch-search-model-input");
		
		if (input.find(".wcsearch-search-model-input-1, .wcsearch-search-model-input-2").length) {
			
			var min_input = input.find(".wcsearch-search-model-input-1");
			var max_input = input.find(".wcsearch-search-model-input-2");
			
			var min = '';
			if (min_input.val() && !isNaN(min_input.val())) {
				min = min_input.val();
			}
			var max = '';
			if (max_input.val() && !isNaN(max_input.val())) {
				max = max_input.val();
			}
			var values = '';
			if (min || max) {
				values = min+'-'+max;
			}
			
			input.attr("data-values", values);
		}
		
		wcsearch_model_update_placeholders();
	});
	
	$("body").on("click",
			".wcsearch-search-input .wcsearch-search-term-button .wcsearch-btn," +
			".wcsearch-search-model-input .wcsearch-search-term-button .wcsearch-btn",
	function() {
		if (wcsearch_is_model()) {
			var input = $(this).parents(".wcsearch-search-model-input");
		} else {
			var input = $(this).parents(".wcsearch-search-input");
		}
		var btn_wrapper = $(this).parents(".wcsearch-search-term-button");
		var values = '';
		
		if (input.data("mode") == "checkboxes_buttons") {
			btn_wrapper.toggleClass("wcsearch-search-term-button-active");
			
			var selected_terms_ids = [];
			var selected_terms = input.find(".wcsearch-search-term-button-active");
			$.each(selected_terms, function() {
				selected_terms_ids.push($(this).data("term-id"));
			});
			if (selected_terms_ids) {
				values = selected_terms_ids.join(",");
			}
		} else if (input.data("mode") == "radios_buttons") {
			if (btn_wrapper.hasClass("wcsearch-search-term-button-active")) {
				input.find(".wcsearch-search-term-button").removeClass("wcsearch-search-term-button-active");
			} else {
				input.find(".wcsearch-search-term-button").removeClass("wcsearch-search-term-button-active");
				btn_wrapper.toggleClass("wcsearch-search-term-button-active");
				values = btn_wrapper.data("term-id");
			}
		} else {
			btn_wrapper.toggleClass("wcsearch-search-term-button-active");
			if (btn_wrapper.hasClass("wcsearch-search-term-button-active")) {
				values = btn_wrapper.data("term-id");
			}
		}
		
		if (wcsearch_is_model()) {
			input.attr("data-values", values);
			
			wcsearch_model_update_placeholders();
		} else {
			input.find("input.wcsearch-search-terms-buttons-input").val(values).trigger("change");
		}
	});
	
	window.wcsearch_setup_terms_separators = function() {
		$(
			".wcsearch-search-input-checkboxes," +
			".wcsearch-search-input-radios," +
			".wcsearch-search-input-checkboxes_buttons," +
			".wcsearch-search-input-radios_buttons," +
			".wcsearch-search-model-input-checkboxes," +
			".wcsearch-search-model-input-checkboxes_buttons," +
			".wcsearch-search-model-input-radios," +
			".wcsearch-search-model-input-radios_buttons"
		).each(function() {
			if (wcsearch_is_model()) {
				// model
				var container = $(this).find(".wcsearch-search-model-input-terms-columns");
			} else {
				// frontend
				var container = $(this).find(".wcsearch-search-input-terms-columns");
			}
			
			var input_data = $(this).data();
			
			var height_limit = input_data["height_limit"];
			if (height_limit > 0) {
				container.css("height", "auto");
				if (container.outerHeight() > height_limit) {

					if (input_data["how_to_limit"] == "use_scroll") {
						container.css("height", height_limit);
					} else if (input_data["how_to_limit"] == "show_more_less") {
						var overlay = $(this);
						
						container.parent().find(".wcsearch-search-separator-link").remove();
						
						var separator_link = $("<div />")
						.addClass("wcsearch-search-separator-link")
						.attr("data-status", "closed")
						.attr("data-text-open", input_data["text_open"])
						.attr("data-text-close", input_data["text_close"])
						.html(input_data["text_open"]+' <span class="wcsearch-fa wcsearch-fa-chevron-down"></span>');
							
						container.after(separator_link[0]);
						
						container.css("height", height_limit);
						container.css("overflow", "hidden");
						
						separator_link.on("click", function() {
							var status = $(this).attr("data-status");
							if (status === "closed") {
								$(this).attr("data-status", "opened");
							
								var chevron = $("<span />").addClass("wcsearch-fa wcsearch-fa-chevron-up");
								$(this).html($(this).data("text-close")+" ").append(chevron[0]);
								container.css("overflow", "auto");
								container.css("height", height_limit+50);
							} else {
								$(this).attr("data-status", "closed");
							
								var chevron = $("<span />").addClass("wcsearch-fa wcsearch-fa-chevron-down");
								$(this).html($(this).data("text-open")+" ").append(chevron[0]);
								container.css("overflow", "hidden");
								container.css("height", height_limit);
								container.scrollTop(0);
							}
						});
					}
				}
			}
		});
	};
	
	var wcsearch_used_by = 'wc';
	if ($(".wcsearch-search-form").length && $(".wcsearch-search-form").data("used_by")) {
		wcsearch_used_by = $(".wcsearch-search-form").data("used_by");
	} else if ($("[name='used_by']").length && $("[name='used_by']").val()) {
		wcsearch_used_by = $("[name='used_by']").val();
	}
	
	var wcsearch_submit_callback = wcsearch_js_objects.adapter_options[wcsearch_used_by].submit_callback;
	
	window.wcsearch_get_loop = function() {
		var selectors = wcsearch_js_objects.adapter_options[wcsearch_used_by].loop_selector_name;
		
		if (!$.isArray(selectors)) {
			selectors = [wcsearch_js_objects.adapter_options[wcsearch_used_by].loop_selector_name];
		}
		
		var selected_selector;
		$.each(selectors, function(index, selector_name) {
			var wcsearch_loop_name = "div[id^='"+selector_name+"']";
			
			if ($(wcsearch_loop_name).length) {
				selected_selector = $(wcsearch_loop_name);
				return false;
			}
		});
		
		return selected_selector;
	}
	
	window.wcsearch_add_common_fields = function(post_params, form) {
		form.find(".wcsearch-common-field").each(function() {
			if ($(this).attr("name").indexOf("[]") != -1) {
				var attr_name = $(this).attr("name");
				if (typeof post_params[attr_name] == 'undefined') {
					post_params[attr_name] = [];
				}
				post_params[attr_name].push($(this).attr("value"));
			} else {
				post_params[$(this).attr("name")] = $(this).attr("value");
			}
		})
		
		return post_params;
	}
	
	window.wcsearch_add_count_fields = function(post_params, form) {
		post_params.count_params = [];
		form.find(".wcsearch-count-field").each(function() {
			post_params.count_params.push({ name: $(this).attr("name"), value: $(this).attr("value") });
		})
		
		return post_params;
	}
	
	window.wcsearch_only_unique = function(value, index, self) {
		return self.indexOf(value) === index;
	}
	
	window.wcsearch_get_query_string_param = function(param_name) {
		
		var param_value;
		var parts = wcsearch_query_string.split('&');
		$.each(parts, function(index, key_value) {
			key_value = key_value.split('=');
			if (key_value[0] == param_name) {
				param_value = key_value[1];
				return;
			}
		});
		return param_value;
	}
	window.wcsearch_extend_query_string_params = function(params) {
		
		var parts = wcsearch_query_string.split('&');
		for (const [key, value] of Object.entries(params)) {
			var key_exists = false;
			$.each(parts, function(index, key_value) {
				key_value = key_value.split('=');
				if (key == key_value[0]) {
					parts[index] = key+'='+value;
					key_exists = true;
					return;
				}
			});
			if (!key_exists) {
				parts.push(key+'='+value);
			}
		}
		parts = parts.filter(wcsearch_only_unique);
		wcsearch_query_string = parts.join('&');
	}
	
	window.wcsearch_insert_param_in_uri = function(...args) {

		var hash = window.location.hash.substring(1);

		if (!Array.isArray(args[0]) && args.length == 2) {
			args = [[args[0], args[1]]];
		}
		
		var parts = document.location.search.substr(1).split('&').filter(Boolean);
		for (let [key, value] of args) {
			key = encodeURIComponent(key);
			value = encodeURIComponent(value);
			
			let key_exists = false;
			$.each(parts, function(index, key_value) {
				key_value = key_value.split('=');
				if (key == key_value[0]) {
					parts[index] = key+'='+value;
					key_exists = true;
					return;
				}
			});
			if (!key_exists) {
				parts.push(key+'='+value);
			}
		}
		
		let params = parts.join('&');

		if (hash) {
			hash = '#' + hash;
		}

		window.history.pushState("", "", "?" + params + hash);
	}
	
	window.wcsearch_remove_param_from_uri = function(...args) {
		
		var hash = window.location.hash.substring(1);
		
		var parts = document.location.search.substr(1).split('&').filter(Boolean);
		for (let key of args) {
			key = encodeURIComponent(key);
			
			$.each(parts, function(index, key_value) {
				key_value = key_value.split('=');
				if (key == key_value[0]) {
					parts.splice(index, 1)
					return;
				}
			});
		}
		
		let params = parts.join('&');
		
		if (hash) {
			hash = '#' + hash;
		}
		
		if (params) {
			window.history.pushState("", "", "?" + params + hash);
		} else {
			// remove params from URL
			var href = window.location.href;
			var url  = href.split('?');
			window.history.pushState("", "", url[0] + hash);
		}
		
	}
	
	window.wcsearch_get_uri_param = function(param) {
		
		var href = window.location.href;
		var url  = href.split('?');
		if (url.length == 2) {
			var parts = url[1].split('&');
			
			for (let key in parts) {
				let key_value = parts[key].split('=');
				if (param == key_value[0]) {
					return key_value[1];
				}
			};
		} else {
			return false;
		}
	}
	
	$('form.woocommerce-ordering').on("submit", function () {
		return false;
	});
	$(document).on("change", ".woocommerce-ordering .orderby", function(e) {
		
		// do not call request when clicking orderby without search form
		if ($(".wcsearch-search-form").length) {
			e.preventDefault();
			
			var form = $(".wcsearch-search-form");
			
			if (wcsearch_get_loop()) {
				var products_loop_id = wcsearch_get_loop().data("id");
			} else {
				var products_loop_id = null;
			}
			var orderby = $(this).val();
			
			wcsearch_extend_query_string_params({ orderby: orderby });
			var post_params = {
					'action': 'wcsearch_search_request',
					'pagination_base': wcsearch_js_objects.pagination_base,
					'query_string': wcsearch_query_string,
					'default_query': wcsearch_js_objects.default_query,
					'products_loop_id': products_loop_id
			};
			
			if (wcsearch_query_string) {
				window.history.pushState("", "", "?"+wcsearch_query_string);
			}
			
			post_params = wcsearch_add_common_fields(post_params, form);
			
			wcsearch_submit_request(post_params);
		}
	});
	
	$(document).on("click", "a.page-numbers", function(e) {
		
		// do not call request when clicking pagination without search form
		if ($(".wcsearch-search-form").length) {
			e.preventDefault();
			
			var form = $(".wcsearch-search-form");
			
			if (wcsearch_get_loop()) {
				var products_loop_id = wcsearch_get_loop().data("id");
			} else {
				var products_loop_id = null;
			}
			
			var parts = $(this).attr("href").split("/");
			$.each(parts, function(i, part) {
				if (part == 'page') {
					var page_num = parts[i+1];
					
					wcsearch_extend_query_string_params({ page: page_num });
					var post_params = {
							'action': 'wcsearch_search_request',
							'pagination_base': wcsearch_js_objects.pagination_base,
							'query_string': wcsearch_query_string,
							'default_query': wcsearch_js_objects.default_query,
							'products_loop_id': products_loop_id
					};
					
					post_params = wcsearch_add_common_fields(post_params, form);
					
					wcsearch_submit_request(post_params);
					
					return;
				}
			});
		}
	});
	
	window.wcsearch_filter_submit_params = function(search_inputs_value, form) {
		
		// check address when radius was set, remove radius when no address param
		var radius_parameter_passed = false;
		var radius_parameter_key;
		for (var attr in search_inputs_value) {
			var name = search_inputs_value[attr]['name'];
			
			if (name == 'radius') {
				radius_parameter_key = attr;
				
				for (var _attr in search_inputs_value) {
					if (search_inputs_value[_attr]['name'] == 'address') {
						radius_parameter_passed = true;
						break;
					}
				}
			}
		}
		if (radius_parameter_key && !radius_parameter_passed) {
			search_inputs_value.splice(radius_parameter_key, 1);
		}
		
		return search_inputs_value;
	}
	
	window.wcsearch_submit_form = function(form) {
		
		var form_id = form.data("id");
		var hash = form.data("hash");
		var use_ajax = true;
		var is_target_url = false;
		
		if (form.data("scroll-to") == 'products' && wcsearch_get_loop() && wcsearch_do_scroll) {
			$("html, body").animate({
				scrollTop: wcsearch_get_loop().offset().top
			});
		}
		wcsearch_do_scroll = true;
		
		if (form.data("use-ajax")) {
			use_ajax = true;
		} else {
			use_ajax = false;
		}
		
		if (form.data("target_url")) {
			is_target_url = true;
		} else {
			is_target_url = false;
		}
		
		// all_inputs -> search_inputs_value -> form_params -> URI_params -> wcsearch_query_string
		var all_inputs = form.find(".wcsearch-search-input, input.wcsearch-hidden-field[type=hidden]");
		var form_params = {};
		var search_inputs_value = [];
		
		all_inputs.each(function(i, _input) {
			var input = new wcsearch_search_input($(_input));
			
			var value_obj = input.get_value();

			if (value_obj) {
				if (Array.isArray(value_obj)) {
					var value_arr = value_obj;
					$.each(value_arr, function(index, value_obj) {
						search_inputs_value.push(value_obj);
					});
				} else {
					search_inputs_value.push(value_obj);
				}
			}
		});
		
		search_inputs_value = wcsearch_filter_submit_params(search_inputs_value, form);
		
		for (var attr in search_inputs_value) {
			if (search_inputs_value[attr]['value'] != false && search_inputs_value[attr]['value'] != '') {
				var value = search_inputs_value[attr]['value'];
				var name = search_inputs_value[attr]['name'];
				
				if (typeof form_params[name] == 'undefined' || form_params[name] == null) {
					form_params[name] = value;
				} else {
					var parts = form_params[name].split(',');
					var values = value.split(",");
					for (var key in values) {
						parts.push(values[key]);
					}
					
					parts = parts.filter(wcsearch_only_unique);
					form_params[name] = parts.join(',');
				}
			}
		}
		
		// save order params when they already persist in URI
		var save_order_params = [
			"orderby",
			"order_by",
			"order",
			"page_id",
			"swLat",
			"swLng",
			"neLat",
			"neLng",
		];
		
		for (var param in save_order_params) {
			var param_name = save_order_params[param];
			if (wcsearch_get_uri_param(param_name)) {
				form_params[param_name] = wcsearch_get_uri_param(param_name);
			}
		}
		
		if (typeof gtag != 'undefined') {
			gtag('event', 'search_results', form_params);
		}
		
		var URI_params = $.param(form_params);
		if (URI_params) {
			window.history.pushState("", "", "?"+URI_params);
		} else {
			// remove params from URL
			var href = window.location.href;
			var url  = href.split('?');
			window.history.pushState("", "", url[0]);
		}
		
		wcsearch_query_string = URI_params;
		
		if (use_ajax && !is_target_url) {
			if (wcsearch_get_loop()) {
				wcsearch_get_loop().attr("data-form-id", form_id);
			}
			var post_params = {
					'action': 'wcsearch_search_request',
					'form_id': form_id,
					'hash': hash,
					'pagination_base': wcsearch_js_objects.pagination_base,
					'query_string': wcsearch_query_string,
					'default_query': wcsearch_js_objects.default_query
			};
			post_params = wcsearch_add_common_fields(post_params, form);
			
			window[wcsearch_submit_callback](post_params);
		} else {
			var form_action = $(form).attr("action");
			var url = new URL(form_action);
			$.each(form_params, function(key, value) {
				url.searchParams.set(key, value); // setting your param
			});
			var submit_url = url.href; 
			
			window.location.href = submit_url;
		}
	};
	
	window.wcsearch_submit_request = function(post_params) {
		
		wcsearch_request_processing = true;
		wcsearch_ajax_loader_target_show($("#"+wcsearch_js_objects.loop_selector_name));
		
		// paginator clicked - do not need to recount
		var page = wcsearch_get_query_string_param('page');
		if (!page) {
			wcsearch_recount_attempts = 0;
			wcsearch_recount();
		}
		
		$.ajax({
				type: "POST",
				url: wcsearch_js_objects.ajaxurl,
				data: post_params,
				dataType: 'JSON',
				success: function(response_from_the_action_function) {
					if (wcsearch_get_loop()) {
						wcsearch_get_loop().html(response_from_the_action_function.products);
					}
					
					//wcsearch_ajax_loader_target_hide(wcsearch_js_objects.loop_selector_name);
				},
				complete: function() {
					wcsearch_request_processing = false;
					//wcsearch_ajax_loader_target_hide(wcsearch_js_objects.loop_selector_name);
				}
		});
	}
	
	window.wcsearch_recount = function() {
		var post_params = {
				'action': 'wcsearch_recount_request',
				'query_string': wcsearch_query_string,
				'counters': []
		};
		
		var recount_items = $(".wcsearch-item-count:not(.wcsearch-item-count-no-recount)").not(".wcsearch-search-input-always-closed .wcsearch-item-count");
		
		recount_items.addClass("wcsearch-item-count-blur");
		recount_items.slice(0, wcsearch_max_counters).map(function(index, obj) {
			if ($(obj).data()) {
				$(obj).addClass("wcsearch-item-count-blur");
				post_params.counters.push($(obj).data());
			}
		});
		
		var form = $(".wcsearch-search-form");
		post_params = wcsearch_add_common_fields(post_params, form);
		post_params = wcsearch_add_count_fields(post_params, form);
		
		wcsearch_recount_request(post_params);
	}
	window.wcsearch_sort_terms_by_counter = function(input_div) {
		var columns = input_div.find(".wcsearch-search-input-terms-column, .wcsearch-search-model-input-terms-column");
		if (columns.length) {
			columns.each(function() {
				var column = $(this);
				var sorted_elements = [];
				var terms = column.find(".wcsearch-checkbox, .wcsearch-radio");
				
				terms.each(function() {
					var count = $(this).find(".wcsearch-item-count").text();
					if (count != 'xx') {
						sorted_elements.push([this, parseInt(count)]);
						$(this).remove();
					}
				});
				
				sorted_elements.sort(function(a, b) {
					if (input_div.data("order") == 'DESC') {
						return a[1] < b[1];
					} else {
						return a[1] > b[1];
					}
				});
				
				$(sorted_elements).each(function() {
					column.append(this[0]);
				});
			});
		} else {
			var selects = input_div.find("select.wcsearch-form-control");
			if (selects.length) {
				selects.each(function() {
					var select = $(this);
					var sorted_elements = [];
					var terms = select.find("option");
					
					terms.each(function() {
						var count = $(this).attr("data-count");
						if (count != '') {
							sorted_elements.push([this, parseInt(count)]);
							$(this).remove();
						}
					});
					
					sorted_elements.sort(function(a, b) {
						if (input_div.data("order") == 'DESC') {
							return a[1] < b[1];
						} else {
							return a[1] > b[1];
						}
					});
					
					$(sorted_elements).each(function() {
						select.append(this[0]);
					});
				});
			}
		}
	}
	window.wcsearch_recount_request = function(post_params) {
		
		if (post_params.counters.length == 0) {
			return false;
		}
		
		$.ajax({
				type: "POST",
				url: wcsearch_js_objects.ajaxurl,
				data: post_params,
				query_string: wcsearch_query_string,
				dataType: 'JSON',
				success: function(response_from_the_action_function) {
					if (typeof response_from_the_action_function.counters == "object" && response_from_the_action_function.counters) {
						
						$(wcsearch_dropdowns).each(function(i, dropdown) {
							if (typeof dropdown.input != "undefined" && dropdown.input.hasClass("ui-autocomplete-input")) {
								// call initialization to avoid error
								dropdown.input.autocomplete();
								if (dropdown.input.autocomplete("widget").is(":visible")) {
									dropdown.is_open = true;
									dropdown.input.autocomplete("close");
								} else {
									dropdown.is_open = false;
								}
							}
						});
						
						$(response_from_the_action_function.counters).each(function(index, counter_tag) {
							if (typeof counter_tag.counter_term_id != "undefined") {
								var counter_term_id = counter_tag.counter_term_id;
								var counter_term_tax = counter_tag.counter_term_tax;
								var counter_item = counter_tag.counter_item;
								var counter_number = counter_tag.counter_number;
								
								$(".wcsearch-item-count[data-termid='"+counter_term_id+"'][data-tax='"+counter_term_tax+"']").replaceWith($(counter_item)[0]);
								
								$(".wcsearch-search-input-tax-select[data-counter=1] option[data-termid="+counter_term_id+"][data-tax='"+counter_term_tax+"']").attr("data-count", counter_number);
							} else if (typeof counter_tag.counter_price != "undefined") {
								var counter_price = counter_tag.counter_price;
								var counter_item = counter_tag.counter_item;
								
								$(".wcsearch-item-price-"+counter_price).each(function() {
									$(this).replaceWith($(counter_item)[0]);
								});
							} else if (typeof counter_tag.counter_option != "undefined") {
								var counter_option = counter_tag.counter_option;
								var counter_item = counter_tag.counter_item;
								
								$(".wcsearch-item-option-"+counter_option).each(function() {
									$(this).replaceWith($(counter_item)[0]);
								});
							} else if (typeof counter_tag.counter_hours != "undefined") {
								var counter_hours = counter_tag.counter_hours;
								var counter_item = counter_tag.counter_item;
								
								$(".wcsearch-item-hours-"+counter_hours).each(function() {
									$(this).replaceWith($(counter_item)[0]);
								});
							} else if (typeof counter_tag.counter_ratings != "undefined") {
								var counter_ratings = counter_tag.counter_ratings;
								var counter_item = counter_tag.counter_item;
								
								$(".wcsearch-item-ratings-"+counter_ratings).each(function() {
									$(this).replaceWith($(counter_item)[0]);
								});
							}
						});
					}

					if ($(".wcsearch-item-count.wcsearch-item-count-blur").length) {
						
						if (this.query_string == wcsearch_query_string) {
							wcsearch_continue_recounting();
						} else {
							wcsearch_recount_attempts = 0;
						}
					} else {
						$(".wcsearch-search-input[data-orderby='count'], .wcsearch-search-model-input[data-orderby='count']").each(function() {
							wcsearch_sort_terms_by_counter($(this));
						});
					}
				},
				complete: function() {
					$(wcsearch_dropdowns).each(function(i, dropdown) {
						if (typeof dropdown.input != "undefined" && dropdown.input.hasClass("ui-autocomplete-input") && dropdown.is_open) {
							dropdown.input.autocomplete("search", dropdown.input.val());
						}
					});
				}
		});
	}
	window.wcsearch_continue_recounting = function() {
		if ($(".wcsearch-item-count.wcsearch-item-count-blur").length) {
			var post_params = {
					'action': 'wcsearch_recount_request',
					'query_string': wcsearch_query_string,
					'counters': []
			};
			$(".wcsearch-item-count.wcsearch-item-count-blur:lt("+wcsearch_max_counters+")").map(function(index, obj) {
				post_params.counters.push($(obj).data());
			});
			
			var form = $(".wcsearch-search-form");
			post_params = wcsearch_add_common_fields(post_params, form);
			post_params = wcsearch_add_count_fields(post_params, form);
			
			wcsearch_recount_attempts++;
			if (wcsearch_recount_attempts < 20) {
				wcsearch_recount_request(post_params);
			} else {
				setTimeout( function() {
					wcsearch_recount_attempts = 0;
				}, 5000);
			}
		} else {
			wcsearch_recount_attempts = 0;
		}
	}
	
	var wcsearch_pointer_interal;
	window.wcsearch_show_pointer = function(form, input, message, time = 5000) {
		
		form.parent().find(".wcsearch-apply-filters-float-btn").remove();
		if (wcsearch_pointer_interal) {
			clearInterval(wcsearch_pointer_interal);
		}
		
		var input_top = input.offset().top;
		var form_top = form.offset().top;
		var pointer = $("<div />")
		.html('<span>' + message + '</span>')
		.addClass("wcsearch-apply-filters-float-btn")
		.css({ top: (input_top - form_top - 22) })
		.insertBefore(form)
		.on("click", function() {
			if (!wcsearch_request_processing) {
				wcsearch_submit_form(form);
				
				if (wcsearch_get_loop()) {
					$("html, body").animate({
						scrollTop: wcsearch_get_loop().offset().top
					});
				}
			}
		});
		
		wcsearch_pointer_interal = setInterval(function() {
			clearInterval(wcsearch_pointer_interal);
			form.parent().find(".wcsearch-apply-filters-float-btn").fadeOut(300, function() { $(this).remove() });
		}, time);
	}
	
	$(document).on("change", ".wcsearch-search-input input, .wcsearch-search-input select", function(e) {
		
		var input = $(this);
		var name = $(this).prop("name");
		var input_div = input.parents(".wcsearch-search-input");
		var form = input.parents("form");
		
		if (input.attr("type") == 'radio' || input.attr("type") == 'checkbox') {
			
			var use_pointer = input.parents(".wcsearch-search-input").data("use_pointer");
			
			if (use_pointer) {
				wcsearch_show_pointer(form, input, 'Search');
			}
		}
		
		if (!wcsearch_request_processing) {
			
			wcsearch_open_close_dep_inputs(form);
			
			// reset the same type of inputs before submit,
			if (wcsearch_js_objects.reset_same_inputs) {
				var field_slug = $(this).parents(".wcsearch-search-input").attr("data-slug");
				var the_same_inputs = form.find(".wcsearch-search-input[data-slug="+field_slug+"]").not(input_div);
				the_same_inputs.each(function(i, same_input) {
					var input = new wcsearch_search_input($(same_input));
					input.reset();
				});
			}
			
			if (!form.data("auto-submit")) {
				return false;
			}
			
			$(".wcsearch-item-count-no-recount").removeClass("wcsearch-item-count-no-recount");
			
			if (input_div.data("type") == "tax" && input_div.data("relation") == 'OR') {
				// do not recount self input items
				input_div.find(".wcsearch-item-count").addClass("wcsearch-item-count-no-recount");
			}
			
			wcsearch_submit_form(form);
		}
	});
	
	window.wcsearch_open_close_dep_inputs = function(form) {
		if (form.find(".wcsearch-search-input[data-dependency_tax]").length) {
			var dep_inputs = form.find(".wcsearch-search-input[data-dependency_tax]");
			dep_inputs.filter(Boolean); // filter empty dependency_tax=''
			
			var all_inputs = form.find(".wcsearch-search-input");
			
			dep_inputs.each( function(index, _dep_input) {
				
				var dep_input = $(_dep_input);
				var dep_tax = dep_input.data("dependency_tax");
				var dep_items = dep_input.data("dependency_items");
				// without "No dependency" option
				if (dep_tax) {
					var input_opened = false;
					
					all_inputs.each(function(i, _input) {
						var current_input_name = name;
						var input = new wcsearch_search_input($(_input));
						var value = input.get_value();
						
						if (value) {
							if (Array.isArray(value)) {
								var value_arr = value;
								$.each(value_arr, function(index, value) {

									if (value) {
										var input_values = value.value.toString().split(",").filter(item => item);
										
										if (dep_tax == value.name) {
											if (typeof dep_items != "undefined") {
												dep_items = dep_items.toString().split(",");
												
												if ($(input_values).filter(dep_items).length) {
													input_opened = true;
													return;
												}
											} else if (input_values.length) {
												input_opened = true;
												return;
											}
										}
									}
								});
							} else {
								var input_values = value.value.toString().split(",").filter(item => item);
								
								if (dep_tax == value.name) {
									if (typeof dep_items != "undefined") {
										dep_items = dep_items.toString().split(",");
										
										if ($(input_values).filter(dep_items).length) {
											input_opened = true;
											return;
										}
									} else if (input_values.length) {
										input_opened = true;
										return;
									}
								}
							}
						}
					});
					
					if (input_opened) {
						
						// call wcsearch_setup_terms_separators() only when it was closed
						if (dep_input.parents(".wcsearch-search-placeholder").hasClass("wcsearch-search-placeholder-dependency-view-closed")) {
							dep_input.parents(".wcsearch-search-placeholder").removeClass("wcsearch-search-placeholder-dependency-view-closed");
							
							wcsearch_setup_terms_separators();
						}
					} else {
						var dep_input_reset = new wcsearch_search_input(dep_input);
						dep_input_reset.reset();
						
						dep_input.parents(".wcsearch-search-placeholder").addClass("wcsearch-search-placeholder-dependency-view-closed");
					}
				}
			});
		}
	}
	
	$(".wcsearch-search-input-button").on("click", function(e) {
		e.preventDefault();
		
		var form = $(this).parents("form");
		
		if (!wcsearch_request_processing) {
			wcsearch_submit_form(form);
		}
	});
	
	$(".wcsearch-search-input-reset-button").on("click", function(e) {
		e.preventDefault();
		
		wcsearch_do_scroll = false;
		
		var form = $(this).parents("form");
		
		var inputs = form.find(".wcsearch-search-input");
		inputs.each(function(i, _input) {
			var input = new wcsearch_search_input($(_input));
			input.reset();
		});
		
		wcsearch_submit_form(form);
		
		wcsearch_open_close_dep_inputs(form);
	});
	
	$(".wcsearch-search-input-more-filters").on("click", function(e) {
		e.preventDefault();
		
		var form = $(this).parents("form");
		
		wcsearch_open_close_dep_inputs(form);
		
		var inputs = form.find(".wcsearch-search-input");
		inputs.each(function(i, _input) {
			
			if ($(_input).parent().hasClass("wcsearch-search-placeholder-advanced-view")) {
				$(_input).parent().toggleClass("wcsearch-search-placeholder-advanced-view-closed");
			}
			
			wcsearch_setup_terms_separators();
		});
		
		if ($(this).data("status") == "closed") {
			$(this).find("input").val(1);
			
			$(this).find("span.wcsearch-fa-chevron-down")
			.removeClass("wcsearch-fa-chevron-down")
			.addClass("wcsearch-fa-chevron-up");
			
			wcsearch_insert_param_in_uri('more_filters', 1);
			
			$(this).data("status", "opened");
		} else {
			$(this).find("input").val(0);
			
			$(this).find("span.wcsearch-fa-chevron-up")
			.removeClass("wcsearch-fa-chevron-up")
			.addClass("wcsearch-fa-chevron-down");
			
			wcsearch_remove_param_from_uri('more_filters');
			
			$(this).data("status", "closed");
		}
	});
	
	window.wcsearch_sort_autocomplete_items = function(a, b) {
		if (typeof a.is_listing != "undefined" && a.is_listing && (typeof b.is_listing == "undefined" || !b.is_listing)) {
			return -1;
		} else if (typeof a.is_listing == "undefined" || !a.is_listing) {
			if (a.starts_with && !b.starts_with) {
				return -1;
			} else if (a.term_in_name && !b.term_in_name) {
				return 1;
			} else if (!a.term_in_name && b.term_in_name) {
				return -1;
			} else if (a.is_term && !b.is_term) {
				return 1;
			} else if (!a.is_term && b.is_term) {
				return -1;
			} else if (a.parents == '' && b.parents != '') {
				return 1;
			} else if (a.parents != '' && b.parents == '') {
				return -1;
			} else if (a.name > b.name) {
				return -1;
			} else if (b.name > a.name) {
				return 1;
			} else {
				return 0;
			}
		}
	}
	
	var wcsearch_dropdowns = [];
	
	window.wcsearch_process_main_search_fields = function() {
		if (typeof tax_keywords != "undefined") {
			
			// tax autocomplete
			$(".wcsearch-tax-autocomplete").tax_autocomplete().each(function(i, dropdown) {
				wcsearch_dropdowns.push($(dropdown).tax_autocomplete().tax_autocomplete("instance"));
			});
			
			// tax + keywords autocomplete
			$(".wcsearch-tax-keywords").tax_keywords().each(function(i, dropdown) {
				wcsearch_dropdowns.push($(dropdown).tax_keywords().tax_keywords("instance"));
			});
			
			// tax + address autocomplete
			$(".wcsearch-tax-address").tax_address().each(function(i, dropdown) {
				wcsearch_dropdowns.push($(dropdown).tax_address().tax_address("instance"));
			});
			
			// address autocomplete
			$(".wcsearch-address-autocomplete").address_autocomplete().each(function(i, dropdown) {
				wcsearch_dropdowns.push($(dropdown).address_autocomplete().address_autocomplete("instance"));
			});
			
			// heirarhical tax
			$(".wcsearch-heirarhical-dropdown").heirarhical_dropdown().each(function(i, dropdown) {
				wcsearch_dropdowns.push($(dropdown).heirarhical_dropdown().heirarhical_dropdown("instance"));
			});
			
			// multiselect dropdown tax
			$(".wcsearch-multiselect-dropdown").multiselect_dropdown().each(function(i, dropdown) {
				wcsearch_dropdowns.push($(dropdown).multiselect_dropdown().multiselect_dropdown("instance"));
			});
			
			// keywords autocomplete
			$(".wcsearch-keywords-autocomplete").keywords_autocomplete().each(function(i, dropdown) {
				wcsearch_dropdowns.push($(dropdown).keywords_autocomplete().keywords_autocomplete("instance"));
			});
		}
	}
	
	// search suggestions links in string fields
	$(document).on("click", ".wcsearch-search-input .wcsearch-search-suggestions a", function() {
		var input = $(this).parents(".wcsearch-search-input").find(".wcsearch-search-string-input");
		var value = $(this).text();

		input.val(value)
		.trigger("focus")
		.trigger("change");
	});
	
	if (typeof $.ui.selectmenu != 'undefined' && typeof $.ui.autocomplete != 'undefined') {
		// search suggestions links in keywords/address fields
		$(document).on("click", ".wcsearch-search-input .wcsearch-search-suggestions a", function() {
			var input = $(this).parents(".wcsearch-search-input").find(".wcsearch-main-search-field");
			var value = $(this).text();

			input.val(value)
			.trigger("focus")
			.trigger("change");
			
			if (input.hasClass('ui-autocomplete-input')) {
				input.autocomplete("search", value);
			}
		});
		// redirect to listing
		$(document).on("click", ".wcsearch-dropdowns-menu a", function() {
			if ($(this).attr("target") == "_blank") {
				window.open($(this).attr("href"), '_blank');
			} else {
				window.location = $(this).attr("href");
			}
		});
		// correct menu width
		$.ui.autocomplete.prototype._resizeMenu = function () {
			var ul = this.menu.element;
			ul.outerWidth(this.element.outerWidth());
		}
		
		$(document).on('change paste keyup blur', '.wcsearch-main-search-field', function() {
			var input = $(this);
			if (input.val()) {
				input.parent().find(".wcsearch-dropdowns-menu-button").addClass("wcsearch-fa-close");
			} else {
				input.parent().find(".wcsearch-dropdowns-menu-button").removeClass("wcsearch-fa-close");
			}
		});
		$(document).on('click', '.wcsearch-fa-close', function(e) {
			var input = $(this).parent().find('.wcsearch-main-search-field');
			input.trigger("reset");
			input.trigger("change");
			
			$(this).removeClass('wcsearch-fa-close');
		});

		window.tax_keywords = $.widget("custom.tax_keywords", {
			wrapper: "",
			input: "",
			button: "",
			input_icon_class: "wcsearch-fa wcsearch-fa-search",
			wrapper_class: "wcsearch-dropdowns-menu-tax-keywords",
			cache: new Object(),

			_create: function() {
				this.wrapper = $("<div>")
				.addClass(this.wrapper_class)
				.insertAfter(this.element);
				
				// move select inside wrapper
				this.element.appendTo(this.wrapper);

				this.element.hide();
				this._createAutocomplete();
				this._createShowAllButton();
			},

			_appendWrapper: function() {
				var append_to = null; // append to body
				
				if (this.element.parents(".wcsearch-sticky-scroll").length) {
					// append to fixed fiv
					append_to = this.element.parents(".wcsearch-sticky-scroll");
				} else {
					// append to search form wrapper, otherwise autocomplete menu becomes blinking on search
					var append_to = this.element.parents(".wcsearch-search-wrapper");
				}
				
				return append_to;
			},
			
			_autocompleteWithOptions: function(input) {
				input.autocomplete({
					delay: 300,
					minLength: 0,
					appendTo: this._appendWrapper(),
					source: $.proxy(this, "_source"),
					open: function(event, ui) {
						if (navigator.userAgent.match(/(iPod|iPhone|iPad)/)) {
							$('.ui-autocomplete').off('menufocus hover mouseover mouseenter');
						}
					}/*,
					close: function() {
						input.trigger("focus");
						input.autocomplete("search", "");
					}*/
				});
			},
			
			_autocompleteRenderItem: function(input) {
				var default_icon_url = this.element.data('default-icon');
				
				input.autocomplete("widget").addClass("wcsearch-dropdowns-menu");
				input.autocomplete("instance")._renderItem = function(ul, item) {
					var label = item.label;
					
					var right_side_markup = '';
					if (typeof item.count != "undefined") {
						if (item.count !== '') {
							right_side_markup = '<span class="wcsearch-dropdowns-menu-search-counter"><span class="wcsearch-item-count" data-termid="' + item.termid + '" data-tax="' + item.tax + '">' + item.count + '</span></span>';
						} else {
							right_side_markup = '<span class="wcsearch-dropdowns-menu-search-counter"><span class="wcsearch-item-count wcsearch-item-count-blur wcsearch-item-term-' + item.termid + '-' + item.tax + '" data-termid="' + item.termid + '" data-tax="' + item.tax + '">xx</span></span>';
						}
					}
					if (typeof item.note != "undefined") {
						right_side_markup = '<span class="wcsearch-dropdowns-menu-search-note">' + item.note + '</span>';
					}
					
					var item_class = "wcsearch-dropdowns-menu-search";
					if (typeof item.is_term != "undefined" && item.is_term) {
						item_class = item_class + " wcsearch-dropdowns-menu-search-term";
					}
					if (typeof item.is_listing != "undefined" && item.is_listing) {
						item_class = item_class + " wcsearch-dropdowns-menu-search-listing";
					}
					
					var item_li_class = "";
					if (typeof item.option != "undefined" && $(item.option).data("selected")) {
						item_li_class = item_li_class + " wcsearch-dropdowns-menu-selected-item";
					}
					
					var place_id;
					if (typeof item.place_id != "undefined" && item.place_id) {
						place_id = item.place_id;
					}

					var li = $("<li>", {
						class: item_li_class
					});
					
					var wrapper = $("<div>", {
						html: label + right_side_markup,
						class: item_class,
						"data-place-id": place_id
					});

					var icon_class = "ui-icon";
					var icon_url;
					if (item.icon) {
						icon_url = item.icon;
					} else {
						icon_url = default_icon_url;
					}
					$("<span>", {
						style: "background-image: url('" + icon_url + "'); background-size: cover;",
						class: icon_class
					})
					.appendTo(wrapper);

					if (item.sublabel) {
						var sublabel = item.sublabel;

						$("<span>")
						.html(sublabel)
						.addClass("wcsearch-dropdowns-menu-search-sublabel")
						.appendTo(wrapper);
					} else {
						wrapper.addClass("wcsearch-dropdowns-menu-search-root");
					}
		
					return li.append(wrapper).appendTo(ul);
				};
			},
			
			_openMobileKeyboard: function() {
				if (typeof this.element.data("autocomplete-name") == 'undefined' && screen.height <= 768) {
					return false;
				} else {
					return true;
				}
			},
			
			_createAutocomplete: function() {
				var selected = this.element.find("[data-selected=\"selected\"]");
				if (this.element.data("autocomplete-name") && this.element.data("autocomplete-value")) {
					var value = this.element.data("autocomplete-value");
				} else {
					var value = selected.data("name") ? selected.data("name") : "";
				}

				this.input = $("<input>", {
							name: this.element.data("autocomplete-name") ? this.element.data("autocomplete-name") : "",
							readonly: this._openMobileKeyboard() ? false : true
				})
				.appendTo(this.wrapper)
				.val(value)
				.attr("placeholder", this.element.data("placeholder"))
				.addClass("wcsearch-form-control wcsearch-main-search-field");
				
				this._autocompleteWithOptions(this.input);
				this._autocompleteRenderItem(this.input);

				var element = this.element;
				var input = this.input;
				var id = this.element.data("id");

				this._on(input, {
					reset: function() {
						this.button.trigger("click");
						
						this.element.children("option").map(function() {
							$(this).removeData("selected").removeAttr("data-selected");
						});
					},
					autocompleteselect: function(event, ui) {
						this._trigger("select", event, {
							item: ui.item
						});
						
						// setup selected term in the options list
						this.element.children("option").map(function() {
							if ($(this).data("termid") == ui.item.value) {
								$(this).data("selected", "selected").attr("data-selected", "selected");
							} else {
								$(this).removeData("selected").removeAttr("data-selected");
							}
						});

						if (ui.item.is_term) {
							var name = wcsearch_HTML_entity_decode(ui.item.name);
							
							$('#selected_tax\\['+id+'\\]').val(ui.item.value);
							
							input.val(name);
							
							$('#selected_tax\\['+id+'\\]').trigger("wcsearch:selected_tax_change");
							$('#selected_tax\\['+id+'\\]').trigger("change");
						} else {
							var name = wcsearch_HTML_entity_decode(ui.item.value);
							
							$('#selected_tax\\['+id+'\\]').val('');

							input.val(name).trigger("change");
						}
						
						input.trigger("blur");
						
						event.preventDefault();
					},
					autocompletefocus: function(event, ui) {
						event.preventDefault();
					},
					click: function(event, ui) {
						// open list only when it already has a value
						if (!input.autocomplete("widget").is(":visible") && (input.val() || element.data("open-on-click"))) {
							
							// show all on click, empty search opens full list
							input.trigger("focusout");
							//input.autocomplete("search", input.val());
							input.autocomplete("search", '');
								
							wcsearch_continue_recounting();
						} else {
							input.autocomplete("close");
						}
					},
					autocompletesearch: function(event, ui) {
						if (input.val() == '') {
							$('#selected_tax\\['+id+'\\]').val('');
							
							// trigger custom event
							$('#selected_tax\\['+id+'\\]').trigger("wcsearch:selected_tax_change");
						}
					}
				});
				
				$(document).on("submit", "form", function() {
					input.autocomplete("close");
				});
			},

			_createShowAllButton: function() {
				var input = this.input,
				_this = this,
				id = this.element.data("id");

				this.wrapper.addClass("wcsearch-has-feedback");
				this.button = $("<span>", {
					class: "wcsearch-dropdowns-menu-button wcsearch-form-control-feedback " + this.input_icon_class + (input.val() ? " wcsearch-fa-close" : "")
				})
				.appendTo(this.wrapper)
				.on("click", function(e) {
					
					wcsearch_do_scroll = false;
					
					input.val('');
					if ($('#selected_tax\\['+id+'\\]').val()) {
						// submit search form on input reset
						$('#selected_tax\\['+id+'\\]').val('');
						//$('#selected_tax\\['+id+'\\]').trigger("change"); // probably unnecessary trigger
						
						// trigger custom event
						$('#selected_tax\\['+id+'\\]').trigger("wcsearch:selected_tax_change");
					} else {
						input.trigger('change');
					}
					
					wcsearch_do_scroll = false;

					if (_this._openMobileKeyboard()) {
						//input.autocomplete("search", input.val());
					} else {
						// Pass empty string as value to search for, displaying all results
						input.autocomplete("search", '');
					}
				});
			},

			_source: function(request, response) {
				var term = $.trim(request.term).toLowerCase();
				var matcher = new RegExp($.ui.autocomplete.escapeRegex(term), "i");
				var common_array = [];
				
				this.element.children("option").map(function() {
					$(this).prop("count", 11);
					
					var text = $(this).text(),
					value = $(this).val(),
					name = $(this).attr("data-name"),
					icon = $(this).attr("data-icon"),
					count = $(this).attr("data-count"),
					termid = $(this).attr("data-termid"),
					tax = $(this).attr("data-tax"),
					note = $(this).attr("data-note"),
					sublabel = $(this).attr("data-sublabel"),
					starts_with = $(this).attr("data-name").toLowerCase().startsWith(term),
					term_in_name = matcher.test(name),
					term_in_sublabel = matcher.test(sublabel);
					if (this.value && (!term || term_in_name || term_in_sublabel)) {
						common_array.push({
							label: text,
							value: value,
							name: name,
							full_value: name + ', ' + sublabel,
							count: count,
							termid: termid,
							tax: tax,
							note: note,
							icon: icon,
							sublabel: sublabel,
							option: this,
							is_term: true,
							is_listing: false,
							term_in_name: term_in_name,
							starts_with: starts_with
						});
					}
				});

				if (this.element.data("ajax-search") && term) {
					this.wrapper.find(".wcsearch-dropdowns-menu-button").addClass("wcsearch-search-input-loader");

					if (term in this.cache) {
						var cache_array = this.cache[term];
						this.wrapper.find(".wcsearch-dropdowns-menu-button").removeClass("wcsearch-search-input-loader");
						common_array = cache_array.slice(0); // simply duplicate this array

						response(common_array);
					} else {
						var do_links 		= this.input.parents(".wcsearch-search-input").data("do_links");
						var do_links_blank 	= this.input.parents(".wcsearch-search-input").data("do_links_blank");
						var orderby 		= this.input.parents(".wcsearch-search-input").data("orderby");
						var order 			= this.input.parents(".wcsearch-search-input").data("order");
						
						var used_by 		= this.input.parents(".wcsearch-search-input").data("used_by");
						
						var post_params = {
			            	action:          wcsearch_js_objects.adapter_options[used_by].keywords_search_action,
			            	query_string:    wcsearch_query_string,
			            	do_links:        do_links,
			            	do_links_blank:  do_links_blank,
			            	orderby:         orderby,
			            	order:           order,
			            	term:            term
			            }
						
						var form = this.input.parents("form");
						post_params = wcsearch_add_common_fields(post_params, form);
						
						$.ajax({
				        	url: wcsearch_js_objects.ajaxurl,
				        	type: "POST",
				        	dataType: "json",
				            data: post_params,
				            combobox: this,
				            success: function(response_from_the_action_function){
				            	if (response_from_the_action_function != 0 && response_from_the_action_function.listings) {
				            		var cache_array = [];
				            		response_from_the_action_function.listings.map(function(listing) {
				            			var starts_with = listing.name.toLowerCase().startsWith(term);
				            			
				            			var item = {
											label:        listing.title,      // text in option
											value:        listing.name,       // value depends on is_term
											name:         listing.name,       // text to place in input
											full_value:   listing.name,       // full value of the item
											icon:         listing.icon,
											sublabel:     listing.sublabel,   // sub-description
											option:       listing,
											is_term:      false,
											is_listing:   true,
											term_in_name: true,
											starts_with:  starts_with
				            			}
				            			common_array.push(item);
				            			cache_array.push(item);
				            		});
				            		common_array.sort(wcsearch_sort_autocomplete_items);

				            		this.combobox.cache[term] = common_array;
				            	}
				            	response(common_array);
				            },
				            complete: function() {
				            	this.combobox.wrapper.find(".wcsearch-dropdowns-menu-button").removeClass("wcsearch-search-input-loader");
				            }
				        });
					}
				} else {
					if (term) {
						common_array.sort(wcsearch_sort_autocomplete_items);
					}
					response(common_array);
				}
			},
			
			renew_source: function(counter_term_id, counter_number) {
				this.cache = new Object();
				
				this.element.children("option").map(function() {
					if ($(this).data("termid") == counter_term_id) {
						if (counter_number !== false) {
							$(this).attr("data-count", counter_number);
						}
					}
				});
			},

			_destroy: function() {
				this.wrapper.remove();
				this.element.show();
			},
		});
		
		window.tax_address = $.widget("custom.tax_address", tax_keywords, {
			wrapper: "",
			input: "",
			input_place_id: "",
			button: "",
			input_icon_class: "wcsearch-fa  wcsearch-fa-map-marker",
			wrapper_class: "wcsearch-dropdowns-menu-tax-autocomplete",
			
			_create: function() {
				this.wrapper = $("<div>")
				.addClass(this.wrapper_class)
				.insertAfter(this.element);
				
				// move select inside wrapper
				this.element.appendTo(this.wrapper);

				this.element.hide();
				this._createAutocomplete();
				this._createShowAllButton();
			},
			
			_createShowAllButton: function() {
				var input = this.input,
				input_place_id = this.input_place_id,
				_this = this,
				id = this.element.data("id"),
				used_by = this.input.parents(".wcsearch-search-input").data("used_by"),
				enable_my_location_button = wcsearch_js_objects.adapter_options[used_by].enable_my_location_button;

				this.wrapper.addClass("wcsearch-has-feedback");
				this.button = $("<span>", {
					class: "wcsearch-dropdowns-menu-button wcsearch-form-control-feedback" + (enable_my_location_button ? " wcsearch-get-location" : "") + " " + this.input_icon_class + (input.val() ? " wcsearch-fa-close" : "")
				})
				.appendTo(this.wrapper)
				.on("click", function(e) {
					
					wcsearch_do_scroll = false;
					
					if ($(this).hasClass("wcsearch-fa-close")) {
						input.val('');
						input_place_id.val('');
						if ($('#selected_tax\\['+id+'\\]').val()) {
							// submit search form on input reset
							$('#selected_tax\\['+id+'\\]').val('');
							//$('#selected_tax\\['+id+'\\]').trigger("change"); // probably unnecessary trigger
							
							// trigger custom event
							$('#selected_tax\\['+id+'\\]').trigger("wcsearch:selected_tax_change");
						} else {
							input.trigger('change');
						}
					} else if ($(this).hasClass("wcsearch-get-location")) {
						var geocode_field_callback = wcsearch_js_objects.geocode_functions.geocode_field;
						var geocode_field_error = wcsearch_js_objects.geocode_functions.my_location_button_error;
						
						window[geocode_field_callback](input, geocode_field_error);
					}

					if (_this._openMobileKeyboard()) {
						//input.autocomplete("search", input.val());
					} else {
						// Pass empty string as value to search for, displaying all results
						input.autocomplete("search", '');
					}
				})
				.on("mouseover", function(e) {
					if ($(this).hasClass("wcsearch-get-location") && !$(this).hasClass("wcsearch-fa-close")) {
						$(this).attr("title", wcsearch_js_objects.get_my_location_title);
					}
				});
			},
			
			_createAutocomplete: function() {
				var selected = this.element.find("[data-selected=\"selected\"]");
				if (this.element.data("autocomplete-name") && this.element.data("autocomplete-value")) {
					var value = this.element.data("autocomplete-value");
				} else {
					var value = selected.data("name") ? selected.data("name") : "";
				}

				this.input = $("<input>", {
							name: this.element.data("autocomplete-name") ? this.element.data("autocomplete-name") : "",
							readonly: this._openMobileKeyboard() ? false : true
				})
				.appendTo(this.wrapper)
				.val(value)
				.attr("placeholder", this.element.data("placeholder"))
				.addClass("wcsearch-form-control wcsearch-main-search-field");
				
				this._autocompleteWithOptions(this.input);
				this._autocompleteRenderItem(this.input);
				
				var place_id = this.element.data("place-id") ? this.element.data("place-id") : "";
				this.input_place_id = $("<input>", {
					type: "hidden",
					name: "place_id"
				})
				.appendTo(this.wrapper)
				.val(place_id);
				
				var element = this.element;
				var input = this.input;
				var input_place_id = this.input_place_id;
				var id = this.element.data("id");
				
				this._on(input, {
					reset: function() {
						
						wcsearch_do_scroll = false;
						
						input_place_id.val('');
						
						this.element.children("option").map(function() {
							$(this).removeData("selected").removeAttr("data-selected");
						});
						
						// do not use trigger("click"), otherwise it will click on "My location" button
						input.val('');
						if ($('#selected_tax\\['+id+'\\]').val()) {
							// submit search form on input reset
							$('#selected_tax\\['+id+'\\]').val('');
							$('#selected_tax\\['+id+'\\]').trigger("change");
							
							// trigger custom event
							$('#selected_tax\\['+id+'\\]').trigger("wcsearch:selected_tax_change");
						} else {
							input.trigger('change');
						}
						this.button.removeClass("wcsearch-fa-close");
						
						input.autocomplete("close");
					},
					autocompleteselect: function(event, ui) {
						this._trigger("select", event, {
							item: ui.item
						});
						
						if (typeof ui.item.place_id != "undefined") {
							input_place_id.val(ui.item.place_id);
						} else {
							input_place_id.val('');
						}
						
						if (ui.item.is_term) {
							var name = wcsearch_HTML_entity_decode(ui.item.name);
							
							$('#selected_tax\\['+id+'\\]').val(ui.item.value);
							
							// setup selected term in the options list
							this.element.children("option").map(function() {
								if ($(this).data("termid") == ui.item.value) {
									$(this).data("selected", "selected").attr("data-selected", "selected");
								} else {
									$(this).removeData("selected").removeAttr("data-selected");
								}
							});
							
							input.val(name);
							
							$('#selected_tax\\['+id+'\\]').trigger("wcsearch:selected_tax_change");
							$('#selected_tax\\['+id+'\\]').trigger("change");
						} else {
							var name = wcsearch_HTML_entity_decode(ui.item.value);
							
							$('#selected_tax\\['+id+'\\]').val('');
							
							input.val(name).trigger("change");
							
							/*var form = this.wrapper.parents("form");
							var radius_input = form.find(".wcsearch-search-input[data-slug=radius]").first();
							if (radius_input) {
								wcsearch_show_pointer(form, radius_input, 'what radius to search?', 1500000000);
							}*/
						}
						
						input.trigger("blur");
						
						event.preventDefault();
					},
					autocompletefocus: function(event, ui) {
						event.preventDefault();
					},
					click: function(event, ui) {
						// open list only when it already has a value
						if (!input.autocomplete("widget").is(":visible") && (input.val() || element.data("open-on-click"))) {
							if (this._openMobileKeyboard()) {
								input.trigger("focus");
								input.autocomplete("search", input.val());
							} else {
								wcsearch_do_scroll = false;
								input.trigger("focusout");
								wcsearch_do_scroll = false;
								input.autocomplete("search", '');
							}
							
							wcsearch_continue_recounting();
						} else {
							input.autocomplete("close");
						}
					},
					autocompletesearch: function(event, ui) {
						if (input.val() == '') {
							$('#selected_tax\\['+id+'\\]').val('');
							
							// trigger custom event
							$('#selected_tax\\['+id+'\\]').trigger("wcsearch:selected_tax_change");
						}
					},
					change: function(event, ui) {
						
						wcsearch_do_scroll = false;
						
						input_place_id.val('');
					}
				});
				
				$(document).on("submit", "form", function() {
					input.autocomplete("close");
				});
			},
			
			_source: function(request, response) {
				var term = $.trim(request.term).toLowerCase();
				var matcher = new RegExp($.ui.autocomplete.escapeRegex(term), "i");
				var common_array = [];
				
				this.element.children("option").map(function() {
					
					var text = $(this).text(),
					value = $(this).val(),
					name = $(this).attr("data-name"),
					icon = $(this).attr("data-icon"),
					count = $(this).attr("data-count"),
					termid = $(this).attr("data-termid"),
					tax = $(this).attr("data-tax"),
					note = $(this).attr("data-note"),
					sublabel = $(this).attr("data-sublabel"),
					place_id = $(this).attr("data-place_id"),
					starts_with = $(this).attr("data-name").toLowerCase().startsWith(term),
					term_in_name = matcher.test(name),
					term_in_sublabel = matcher.test(sublabel);
					if (this.value && (!term || term_in_name || term_in_sublabel)) {
						common_array.push({
							label: text,
							value: value,
							name: name,
							full_value: name + ', ' + sublabel,
							count: count,
							termid: termid,
							tax: tax,
							note: note,
							icon: icon,
							sublabel: sublabel,
							option: this,
							is_term: true,
							is_listing: false,
							term_in_name: term_in_name,
							starts_with: starts_with,
							place_id: place_id
						});
					}
				});

				if (term && wcsearch_js_objects.geocode_functions) {
					var autocomplete_service_callback = wcsearch_js_objects.geocode_functions.autocomplete_service;
					var autocomplete_code = wcsearch_js_objects.geocode_functions.address_autocomplete_code;
					
					window[autocomplete_service_callback](term, autocomplete_code, common_array, response, wcsearch_collect_locations_predictions);
				} else {
					if (term) {
						common_array.sort(wcsearch_sort_autocomplete_items);
					}
					response(common_array);
				}
			},
		});
		
		window.address_autocomplete = $.widget("custom.address_autocomplete", tax_keywords, {
			wrapper: "",
			input: "",
			input_place_id: "",
			button: "",
			input_icon_class: "wcsearch-fa  wcsearch-fa-map-marker",
			wrapper_class: "wcsearch-dropdowns-menu-address-autocomplete",
			
			_create: function() {
				this.wrapper = this.element.parent();

				this.element.hide();
				this._createAutocomplete();
				this._createShowAllButton();
			},
			
			_createShowAllButton: function() {
				var input = this.input,
				input_place_id = this.input_place_id,
				_this = this,
				id = this.element.data("id"),
				used_by = this.input.parents(".wcsearch-search-input").data("used_by"),
				enable_my_location_button = wcsearch_js_objects.adapter_options[used_by].enable_my_location_button;

				this.wrapper.addClass("wcsearch-has-feedback");
				this.button = $("<span>", {
					class: "wcsearch-dropdowns-menu-button wcsearch-form-control-feedback" + (enable_my_location_button ? " wcsearch-get-location" : "") + " " + this.input_icon_class + (input.val() ? " wcsearch-fa-close" : "")
				})
				.appendTo(this.wrapper)
				.on("click", function(e) {
					
					wcsearch_do_scroll = false;
					
					if ($(this).hasClass("wcsearch-fa-close")) {
						input.val('');
						input_place_id.val('');
					} else if ($(this).hasClass("wcsearch-get-location")) {
						var geocode_field_callback = wcsearch_js_objects.geocode_functions.geocode_field;
						var geocode_field_error = wcsearch_js_objects.geocode_functions.my_location_button_error;
						
						window[geocode_field_callback](input, geocode_field_error);
					}
					
					wcsearch_do_scroll = false;

					if (_this._openMobileKeyboard()) {
						//input.autocomplete("search", input.val());
					} else {
						// Pass empty string as value to search for, displaying all results
						input.autocomplete("search", '');
					}
				})
				.on("mouseover", function(e) {
					if ($(this).hasClass("wcsearch-get-location") && !$(this).hasClass("wcsearch-fa-close")) {
						$(this).attr("title", wcsearch_js_objects.get_my_location_title);
					}
				});
			},
			
			_createAutocomplete: function() {
				if (this.element.data("autocomplete-name") && this.element.data("autocomplete-value")) {
					var value = this.element.data("autocomplete-value");
				} else {
					var value = ""
				}
				
				this.input = $("<input>", {
					name: this.element.data("autocomplete-name") ? this.element.data("autocomplete-name") : "",
							readonly: this._openMobileKeyboard() ? false : true
				})
				.appendTo(this.wrapper)
				.val(value)
				.attr("placeholder", this.element.data("placeholder"))
				.addClass("wcsearch-form-control wcsearch-main-search-field");
				
				this._autocompleteWithOptions(this.input);
				this._autocompleteRenderItem(this.input);
				
				var place_id = this.element.data("place-id") ? this.element.data("place-id") : "";
				this.input_place_id = $("<input>", {
					type: "hidden",
					name: "place_id"
				})
				.appendTo(this.wrapper)
				.val(place_id);
				
				var element = this.element;
				var input = this.input;
				var input_place_id = this.input_place_id;
				var id = this.element.data("id");
				
				this._on(input, {
					reset: function() {
						
						wcsearch_do_scroll = false;
						
						input_place_id.val('');
						
						this.element.children("option").map(function() {
							$(this).removeData("selected").removeAttr("data-selected");
						});
						
						// do not use trigger("click"), otherwise it will click on "My location" button
						input.val('');
						input.trigger('change');
						
						this.button.removeClass("wcsearch-fa-close");
						
						input.autocomplete("close");
					},
					autocompleteselect: function(event, ui) {
						this._trigger("select", event, {
							item: ui.item
						});
						
						if (typeof ui.item.place_id != "undefined") {
							input_place_id.val(ui.item.place_id);
						} else {
							input_place_id.val('');
						}

						var name = wcsearch_HTML_entity_decode(ui.item.value);
						
						input.val(name);
						input.trigger('change');
						
						event.preventDefault();
					},
					autocompletefocus: function(event, ui) {
						event.preventDefault();
					},
					click: function(event, ui) {
						input.autocomplete("search", input.val());
					},
					change: function(event, ui) {
						
						wcsearch_do_scroll = false;
						
						input_place_id.val('');
					}
				});
				
				$(document).on("submit", "form", function() {
					input.autocomplete("close");
				});
			},
			
			_source: function(request, response) {
				var term = $.trim(request.term).toLowerCase();
				var matcher = new RegExp($.ui.autocomplete.escapeRegex(term), "i");
				var common_array = [];
				
				if (term) {

					if (term in this.cache) {
						var cache_array = this.cache[term];
						common_array = cache_array.slice(0); // simply duplicate this array

						response(common_array);
					} else {
						
						if (term && wcsearch_js_objects.geocode_functions) {
							var autocomplete_service_callback = wcsearch_js_objects.geocode_functions.autocomplete_service;
							var autocomplete_code = wcsearch_js_objects.geocode_functions.address_autocomplete_code;
							
							window[autocomplete_service_callback](term, autocomplete_code, common_array, response, wcsearch_collect_locations_predictions);
						} else {
							if (term) {
								common_array.sort(wcsearch_sort_autocomplete_items);
							}
							response(common_array);
						}
					}
				} else {
					response(common_array);
				}
			},
		});
		
		window.wcsearch_collect_locations_predictions = function(predictions, common_array, response) {
			$.map(predictions, function (prediction, i) {
				common_array.push({
					label: prediction.label,
					value: prediction.value,
					name: prediction.name,
					note: wcsearch_js_objects.prediction_note,
					icon: "",
					sublabel: prediction.sublabel,
					is_term: false,
					term_in_name: true,
					place_id: prediction.place_id
				});
			})

			response(common_array);
		}
		
		window.tax_autocomplete = $.widget("custom.tax_autocomplete", tax_keywords, {
			wrapper: "",
			input: "",
			button: "",
			input_icon_class: "wcsearch-fa  wcsearch-fa-search",
			wrapper_class: "wcsearch-dropdowns-menu-tax-autocomplete",
			
			_source: function(request, response) {
				var term = $.trim(request.term).toLowerCase();
				var matcher = new RegExp($.ui.autocomplete.escapeRegex(term), "i");
				var common_array = [];
				
				this.element.children("option").map(function() {
					
					var text = $(this).text(),
					value = $(this).val(),
					name = $(this).attr("data-name"),
					icon = $(this).attr("data-icon"),
					count = $(this).attr("data-count"),
					termid = $(this).attr("data-termid"),
					tax = $(this).attr("data-tax"),
					note = $(this).attr("data-note"),
					sublabel = $(this).attr("data-sublabel"),
					starts_with = $(this).attr("data-name").toLowerCase().startsWith(term),
					term_in_name = matcher.test(name),
					term_in_sublabel = matcher.test(sublabel);
					if (this.value && (!term || term_in_name || term_in_sublabel)) {
						common_array.push({
							label: text,
							value: value,
							name: name,
							full_value: name + ', ' + sublabel,
							count: count,
							termid: termid,
							tax: tax,
							note: note,
							icon: icon,
							sublabel: sublabel,
							option: this,
							is_term: true,
							is_listing: false,
							term_in_name: term_in_name,
							starts_with: starts_with
						});
					}
				});

				if (term) {
					common_array.sort(wcsearch_sort_autocomplete_items);
				}
				response(common_array);
			},
		});
		window.keywords_autocomplete = $.widget("custom.keywords_autocomplete", tax_keywords, {
			wrapper: "",
			input: "",
			button: "",
			input_icon_class: "wcsearch-fa  wcsearch-fa-search",
			wrapper_class: "wcsearch-dropdowns-menu-keywords-autocomplete",
			cache: new Object(),

			_create: function() {
				this.wrapper = this.element.parent();

				this.element.hide();
				this._createAutocomplete();
				this._createShowAllButton();
			},
			
			_createAutocomplete: function() {
				
				if (this.element.data("autocomplete-name") && this.element.data("autocomplete-value")) {
					var value = this.element.data("autocomplete-value");
				} else {
					var value = ""
				}
				
				this.input = $("<input>", {
					name: this.element.data("autocomplete-name") ? this.element.data("autocomplete-name") : "",
					readonly: this._openMobileKeyboard() ? false : true
				})
				.appendTo(this.wrapper)
				.val(value)
				.attr("placeholder", this.element.data("placeholder"))
				.addClass("wcsearch-form-control wcsearch-main-search-field");
				
				this._autocompleteWithOptions(this.input);
				this._autocompleteRenderItem(this.input);
				
				var input = this.input;

				this._on(input, {
					reset: function() {
						this.button.trigger("click");
						
						this.element.children("option").map(function() {
							$(this).removeData("selected").removeAttr("data-selected");
						});
					},
					autocompleteselect: function(event, ui) {
						this._trigger("select", event, {
							item: ui.item
						});

						input.val(ui.item.value);
						input.trigger('change');

						event.preventDefault();
					},
					autocompletefocus: function(event, ui) {
						event.preventDefault();
					},
					click: function(event, ui) {
						input.autocomplete("search", input.val());
					}
				});
			},
			
			_source: function(request, response) {
				var term = $.trim(request.term).toLowerCase();
				var matcher = new RegExp($.ui.autocomplete.escapeRegex(term), "i");
				var common_array = [];

				if (this.element.data("ajax-search") && term) {
					this.wrapper.find(".wcsearch-dropdowns-menu-button").addClass("wcsearch-search-input-loader");

					if (term in this.cache) {
						var cache_array = this.cache[term];
						this.wrapper.find(".wcsearch-dropdowns-menu-button").removeClass("wcsearch-search-input-loader");
						common_array = cache_array.slice(0); // simply duplicate this array

						response(common_array);
					} else {
						var do_links 		= this.input.parents(".wcsearch-search-input").data("do_links");
						var do_links_blank 	= this.input.parents(".wcsearch-search-input").data("do_links_blank");
						var orderby 		= this.input.parents(".wcsearch-search-input").data("orderby");
						var order 			= this.input.parents(".wcsearch-search-input").data("order");
						
						var used_by 		= this.input.parents(".wcsearch-search-input").data("used_by");
						
						var post_params = {
			            	action:          wcsearch_js_objects.adapter_options[used_by].keywords_search_action,
			            	query_string:    wcsearch_query_string,
			            	do_links:        do_links,
			            	do_links_blank:  do_links_blank,
			            	orderby:         orderby,
			            	order:           order,
			            	term:            term
			            }
						
						var form = this.input.parents("form");
						post_params = wcsearch_add_common_fields(post_params, form);
						
						$.ajax({
				        	url: wcsearch_js_objects.ajaxurl,
				        	type: "POST",
				        	dataType: "json",
				            data: post_params,
				            combobox: this,
				            success: function(response_from_the_action_function){
				            	if (response_from_the_action_function != 0 && response_from_the_action_function.listings) {
				            		var cache_array = [];
				            		response_from_the_action_function.listings.map(function(listing) {
				            			var starts_with = listing.title.toLowerCase().startsWith(term);
				            			
				            			var item = {
											label:        listing.title,      // text in option
											value:        listing.name,       // value depends on is_term
											name:         listing.name,       // text to place in input
											full_value:   listing.name,       // full value of the item
											icon:         listing.icon,
											sublabel:     listing.sublabel,   // sub-description
											option:       listing,
											is_term:      false,
											is_listing:   true,
											term_in_name: true,
											starts_with:  starts_with
										}
				            			common_array.push(item);
				            			cache_array.push(item);
				            		});
				            		common_array.sort(wcsearch_sort_autocomplete_items);

				            		this.combobox.cache[term] = common_array;
				            	}
				            	response(common_array);
				            },
				            complete: function() {
				            	this.combobox.wrapper.find(".wcsearch-dropdowns-menu-button").removeClass("wcsearch-search-input-loader");
				            }
				        });
					}
				} else {
					if (term) {
						common_array.sort(wcsearch_sort_autocomplete_items);
					}
					response(common_array);
				}
			}
		});
		window.heirarhical_dropdown = $.widget("custom.heirarhical_dropdown", tax_keywords, {
			input_icon_class: "wcsearch-fa  wcsearch-fa-search",
			wrapper_class: "wcsearch-dropdowns-menu-hierarhical",
			placeholders: "",
			
			_createAutocomplete: function() {
				
				var wrapper = this.wrapper;
				var id = this.element.data('id');
				var name = this.element.data('tax');
				var placeholders = this.element.data('placeholders');
				var depth_level = this.element.data('depth-level');
				
				this.input_value = $("<input>", {
					type: 'hidden'
				})
				.addClass('wcsearch-hierarhical-menu-'+id+'-depth-level-'+depth_level)
				.appendTo(wrapper);
				var input_value = this.input_value;

				var selected = this.element.find("[data-selected=\"selected\"]");
				if (this.element.data("autocomplete-name") && this.element.data("autocomplete-value")) {
					var value = this.element.data("autocomplete-value");
				} else {
					var value = selected.data("name") ? selected.data("name") : "";
				}
				this.input = $("<input>", {
						name: name,
						type: "text"
				})
				.appendTo(wrapper)
				.val(value)
				.attr("placeholder", placeholders)
				.addClass("wcsearch-form-control wcsearch-main-search-field");
				
				this._autocompleteWithOptions(this.input);
				this._autocompleteRenderItem(this.input);
				
				var element = this.element;
				var input = this.input;
				var tax = this.element.data('tax');
				
				this._on(input, {
					reset: function() {
						this.button.trigger("click");
						
						this.element.children("option").map(function() {
							$(this).removeData("selected").removeAttr("data-selected");
						});
					},
					autocompletechange: function(event, ui) {
						console.log(ui);
					},
					autocompleteselect: function(event, ui) {
						this._trigger("select", event, {
							item: ui.item
						});

						if (ui.item.is_term) {
							var name = ui.item.name;
							$('#selected_tax\\['+id+'\\]').val(ui.item.value);
							element.val(ui.item.value);
							
							// setup selected term in the options list
							this.element.children("option").map(function() {
								if ($(this).data("termid") == ui.item.value) {
									$(this).data("selected", "selected").attr("data-selected", "selected");
								} else {
									$(this).removeData("selected").removeAttr("data-selected");
								}
							});
							
						} else {
							var name = ui.item.value;
							$('#selected_tax\\['+id+'\\]').val('');
							element.val('');
						}
						//$('#selected_tax\\['+id+'\\]').trigger("change"); // this triggers the submission twice
						
						name = wcsearch_HTML_entity_decode(name);
						input.val(name);
						input.trigger('change');

						event.preventDefault();
						
						var selects = wrapper.parent().find('select');
						var curr_level = element.data('depth-level');
						
						selects.each(function(i) {
							if ($(this).data('depth-level') > curr_level) {
								$(this).parent().remove();
							}
						});
						
						input_value.val(ui.item.value);
						
						input.attr('disabled', 'disabled');
						
						var orderby = $(input).parents('.wcsearch-search-input').data("orderby");
						var order = $(input).parents('.wcsearch-search-input').data("order");
						var exact_terms = $(input).parents('.wcsearch-search-input').data("exact_terms");
						var hide_empty = $(input).parents('.wcsearch-search-input').data("hide_empty");
						
						var post_params = {
								'action': 'wcsearch_tax_hierarhical_dropdowns_hook',
								'parentid': ui.item.value,
								'tax': tax,
								'depth_level': depth_level+1,
								'placeholders': placeholders,
								'uID': id,
								'orderby': orderby,
								'order': order,
								'exact_terms': exact_terms,
								'hide_empty': hide_empty
						};
						
						var form = this.input.parents("form");
						post_params = wcsearch_add_common_fields(post_params, form);
						
						$.post(
								wcsearch_js_objects.ajaxurl,
								post_params,
								function(response_from_the_action_function) {
									
									if ($('.wcsearch-hierarhical-menu-'+id+'-depth-level-'+depth_level).length && $('.wcsearch-hierarhical-menu-'+id+'-depth-level-'+depth_level).val()) {
										var new_autocomplete = $(response_from_the_action_function);
										new_autocomplete.insertAfter(wrapper);
										
										var new_select = wrapper.parent().find('select');
										new_select.heirarhical_dropdown();
									}
									
									input.removeAttr('disabled');
								}
						);
					},
					autocompletefocus: function(event, ui) {
						event.preventDefault();
					},
					click: function(event, ui) {
						if (!input.autocomplete("widget").is(":visible")) {
							// show all on click
							input.trigger("focusout");
							input.autocomplete("search", '');
								
							wcsearch_continue_recounting();
						} else {
							input.autocomplete("close");
						}
					},
					autocompletesearch: function(event, ui) {
					}
				});
			},
			
			_createShowAllButton: function() {
				var element = this.element;
				var wrapper = this.wrapper;
				var input = this.input;
				var input_value = this.input_value;
				var id = this.element.data('id');
				var depth_level = this.element.data('depth-level');
				
				this.wrapper.addClass("wcsearch-has-feedback");
				this.button = $("<span>", {
					class: "wcsearch-dropdowns-menu-button wcsearch-form-control-feedback " + this.input_icon_class + (this.input.val() ? " wcsearch-fa-close" : "")
				})
				.appendTo(this.wrapper)
				.on("click", function(e) {
					
					wcsearch_do_scroll = false;
					
					var selects = wrapper.parent().find('select');
					var curr_level = element.data('depth-level');
					
					selects.each(function(i) {
						
						if ($(this).data('depth-level') > curr_level) {
							$(this).parent().remove();
						}
					});
					
					
					if (depth_level > 1) {
						$('#selected_tax\\['+id+'\\]').val($('.wcsearch-hierarhical-menu-'+id+'-depth-level-'+(depth_level-1)).val());
					} else {
						$('#selected_tax\\['+id+'\\]').val('');
					}
					$('#selected_tax\\['+id+'\\]').trigger("change");
					
					if ($(this).hasClass("wcsearch-fa-close")) {
						input.val('');
						$(this).removeClass('wcsearch-fa-close');
						
						element.val(0);
						input_value.val('');
					}
				});
			},
			
			_destroy: function() {
				// comment this line in hierarhical,
				// it gives error: too much recursion
				//this.wrapper.remove();
				this.element.show();
			},
		});
		
		window.multiselect_dropdown = $.widget("custom.multiselect_dropdown", tax_keywords, {
			input_icon_class: "wcsearch-fa  wcsearch-fa-search",
			wrapper_class: "wcsearch-dropdowns-menu-multiselect",
			placeholder: "",
			
			_createAutocomplete: function() {
				
				var create_item = function(input, element_id, item_id, label) {
					input.append(
						$("<div></div>")
						.addClass("wcsearch-dropdowns-multiselect-item")
						.text(label)
						.attr('data-id', item_id)
						.append(
								$("<div></div>")
								.addClass("wcsearch-fa wcsearch-fa-close wcsearch-dropdowns-multiselect-item-close")
								.on("click", function(event) {
									event.preventDefault();
									
									var item = $(this).parent();
									
									delete_item(input, element_id, item);
								})
						)
					);
					input.parent().find(".wcsearch-dropdowns-menu-button").addClass("wcsearch-fa-close");
				};
				var delete_item = function(input, element_id, item) {
					
					wcsearch_do_scroll = false;
					
					item.remove();
					
					var value = $('#selected_tax\\['+element_id+'\\]').val()
					.split(',')
					.filter(function (el) {
						return el != item.data('id');
					});
					$('#selected_tax\\['+element_id+'\\]').val(value.join()).trigger("change");
					
					if (value.length == 0) {
						placeholder.show();
						
						input.parent().find(".wcsearch-dropdowns-menu-button").removeClass("wcsearch-fa-close");
					}
				}
				
				this.placeholder = $("<div class='wcsearch-dropdowns-multiselect-placeholder'>"+this.element.data("placeholder")+"</div>");

				this.input = $("<div></div>")
				.addClass("wcsearch-form-control wcsearch-main-search-field wcsearch-main-search-field-multiselect ui-autocomplete-input")
				.html(this.placeholder)
				.appendTo(this.wrapper);
				
				this._autocompleteWithOptions(this.input);
				this._autocompleteRenderItem(this.input);

				var input = this.input;
				var id = this.element.data("id");
				var placeholder = this.placeholder;
				
				var selected = this.element.find("[data-selected=\"selected\"]");
				var values = [];
				$.each(selected, function() {
					create_item(input, id, $(this).attr("value"), $(this).text());
					
					values.push($(this).attr("value"));
					
					placeholder.hide();
				});
				$('#selected_tax\\['+id+'\\]').val(values.join(","));

				this._on(input, {
					reset: function() {
						this.button.trigger("click");
						
						this.element.children("option").map(function() {
							$(this).removeData("selected").removeAttr("data-selected");
						});
					},
					autocompleteselect: function(event, ui) {
						this._trigger("select", event, {
							item: ui.item
						});
						
						// do not close on select
						this.clicked_selected = true;

						if (ui.item.is_term) {
							var name = ui.item.name;
							var value = $('#selected_tax\\['+id+'\\]').val().split(',');
							if (value.includes(ui.item.value)) {
								var item = input.find(".wcsearch-dropdowns-multiselect-item[data-id='"+ui.item.value+"']");
								
								delete_item(input, id, item);
								
								return false;
							}
							value.push(ui.item.value);
							value = value.filter(function (el) {
								return el != '';
							});
							$('#selected_tax\\['+id+'\\]').val(value.join());
						} else {
							var name = ui.item.value;
							$('#selected_tax\\['+id+'\\]').val('');
						}
						$('#selected_tax\\['+id+'\\]').trigger("change");
						
						create_item(this.input, this.element.data("id"), ui.item.value, ui.item.label);
						
						placeholder.hide();

						event.preventDefault();
					},
					autocompleteclose: function(event, ui) {
						// do not close on select
						if (this.clicked_selected) {
							input.trigger("focus");
							input.autocomplete("search", "");
							
							this.clicked_selected = false;
						}
					},
					autocompletefocus: function(event, ui) {
						event.preventDefault();
					},
					click: function(event, ui) {
						
						// do not open when click to remove item
						if ($(event.target).is(".wcsearch-dropdowns-multiselect-item-close")) {
							return false;
						}
						
						if (!input.autocomplete("widget").is(":visible")) {
							input.trigger("focusout");
							input.autocomplete("search", "");
							
							wcsearch_continue_recounting();
							
						} else {
							input.autocomplete("close");
							
						}
					}
				});
			},
			
			_createShowAllButton: function() {
				
				wcsearch_do_scroll = false;
				
				this._super();
				
				var input = this.input;
				var placeholder = this.placeholder;
				var id = this.element.data('id');
				
				if ($('#selected_tax\\['+id+'\\]').val()) {
					this.button.addClass("wcsearch-fa-close");
				}
				
				this.button.on("click", function(e) {
					$('#selected_tax\\['+id+'\\]').val('');
					$('#selected_tax\\['+id+'\\]').trigger("change");
					
					input.find(".wcsearch-dropdowns-multiselect-item").remove();
					
					placeholder.show();
				});
			},

			_source: function(request, response) {
				var term = $.trim(request.term);
				var id = this.element.data("id");
				var selected_ids = $('#selected_tax\\['+id+'\\]').val().split(',');
				
				var common_array = [];
				
				var matcher = new RegExp($.ui.autocomplete.escapeRegex(term), "i");
				this.element.children("option").map(function() {
					var text = $(this).text(),
					value = $(this).val(),
					name = $(this).attr("data-name"),
					icon = $(this).attr("data-icon"),
					count = $(this).attr("data-count"),
					termid = $(this).attr("data-termid"),
					tax = $(this).attr("data-tax"),
					sublabel = $(this).attr("data-sublabel"),
					term_in_name = matcher.test(name),
					term_in_sublabel = matcher.test(sublabel),
					selected = selected_ids.includes(value) ? true : false;
					common_array.push({
						label: text,
						value: value,
						name: name,
						full_value: name + ', ' + sublabel,
						icon: icon,
						count: count,
						termid: termid,
						tax: tax,
						sublabel: sublabel,
						option: this,
						is_term: true,
						term_in_name: term_in_name,
						selected: selected
					});
				});

				response(common_array);
			},
			
			_destroy: function() {
				// comment this line in hierarhical,
				// it gives error: too much recursion
				//this.wrapper.remove();
				this.element.show();
			},
		});
	}

	$(document).on('change', '.wcsearch-tax-dropdowns-wrap select', function() {
		var select_box = $(this);
		var parent = select_box.val();
		var current_level = select_box.data('level');
		var uID = select_box.data('uid');
		
		var wrapper = select_box.parents('.wcsearch-tax-dropdowns-wrap');
		var tax = wrapper.data('tax');
		var count = wrapper.data('count');
		var hide_empty = wrapper.data('hide-empty');

		wcsearch_update_tax(parent, tax, current_level, count, hide_empty, uID, function() {});
	});

	function wcsearch_update_tax(parent, tax, current_level, count, hide_empty, uID, callback) {
		var current_level = parseInt(current_level);
		var next_level = current_level + 1;
		var prev_level = current_level - 1;
		var selects_length = $('#wcsearch-tax-dropdowns-wrap-'+uID+' select').length;
		
		if (parent) {
			$('#selected_tax\\['+uID+'\\]').val(parent).trigger('change');
		} else if (current_level > 1) {
			$('#selected_tax\\['+uID+'\\]').val($('#chainlist_'+prev_level+'_'+uID).val()).trigger('change');
		} else {
			$('#selected_tax\\['+uID+'\\]').val(0).trigger('change');
		}

		var exact_terms = $('#exact_terms\\['+uID+'\\]').val();

		for (var i=next_level; i<=selects_length; i++) {
			$('#wcsearch-wrap-chainlist-'+i+'-'+uID).remove();
		}
		
		if (parent) {
			var labels_source = wcsearch_js_objects['tax_dropdowns_'+uID][uID];

			if (labels_source.titles[current_level] != undefined) {
				var title = labels_source.titles[current_level];
			} else {
				var title = '';
			}

			$('#wcsearch-wrap-chainlist-'+current_level+'-'+uID+' select').attr('disabled', 'disabled');
			$.post(
				wcsearch_js_objects.ajaxurl,
				{
					'action': 'wcsearch_tax_dropdowns_hook',
					'parentid': parent,
					'next_level': next_level,
					'tax': tax,
					'count': count,
					'hide_empty': hide_empty,
					'title': title,
					'exact_terms': exact_terms,
					'uID': uID
				},
				function(response_from_the_action_function){
					if (response_from_the_action_function != 0)
						$('#wcsearch-tax-dropdowns-wrap-'+uID).append(response_from_the_action_function);

					$('#wcsearch-wrap-chainlist-'+current_level+'-'+uID+' select').removeAttr('disabled');
					
					callback();
				}
			);
		}
	}
	
	function wcsearch_HTML_entity_decode(str){
		return $('<textarea />').html(str).text(); // HTML Entity Decode
	}
	
	function first(p){for(var i in p)return p[i];}
}(jQuery))