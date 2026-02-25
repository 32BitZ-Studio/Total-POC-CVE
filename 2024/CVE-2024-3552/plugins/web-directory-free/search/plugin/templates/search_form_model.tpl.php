<?php wcsearch_renderTemplate('admin_header.tpl.php'); ?>

<?php 
global $wcsearch_model_options;
?>

<script>
	(function($) {
		"use strict";

		var wcsearch_element_loading = false;

	/**
	* 
	* contains all options of all model objects in one JSON array, following format example:
	* 
	* array(
	* 	'keywords' => array(
	* 		array(
	* 			"type" => "select",
	* 			"name" => "autocomplete",
	* 			"title" => "Autocomplete",
	* 			"options" => array(
	* 				0 => "No",
	* 				1 => "Yes"
	* 			),
	* 			"value" => 1
	* 		)
	* 	)
	* )
	**/
	var wcsearch_model_options = <?php echo json_encode($wcsearch_model_options); ?>;

	/**
	* 
	* contains placeholders and objects in one JSON array, following format example:
	* 
	* array(
	* 	'placeholders' => array(
	* 		"0" => array(
	* 				"columns": 1,
	* 				"rows": 1,
	* 				"input": ""
	* 		),
	* 		"1" => array(
	* 				"columns": 2,
	* 				"rows": 1,
	* 				"input": array(
	* 					"type" => "keywords",
	* 				),
	* 		),
	* 		"2" => array(
	* 				"columns": 1,
	* 				"rows": 2,
	* 				"input": array(
	* 					"type" => "tax",
	* 					"tax" => "product_cat",
	* 					"options" => array(
							"mode" => "autocomplete",
	* 					)
	* 				)
	* 		)
	* 	)
	* );
	**/
	var wcsearch_model = <?php echo json_encode($wcsearch_model); ?>;

	var wcsearch_model_column;

	var wcsearch_model_columns_counter = <?php echo esc_attr($search_form_data['columns_num']); ?>;

	$(document).on("mouseenter", ".wcsearch-checkbox, .wcsearch-radio, .wcsearch-search-term-button", function() {
		$(this).find(".wcsearch-model-options-link").show();
	})
	.on("mouseleave", ".wcsearch-checkbox, .wcsearch-radio, .wcsearch-search-term-button", function() {
		$(this).find(".wcsearch-model-options-link").hide();
	});

	window.wcsearch_setup_placeholder = function(placeholders) {

		placeholders.on("mouseover", function() {
			$(this).addClass("wcsearch-search-model-placeholder-hover");
		})
		.on("mouseleave", function() {
			$(this).removeClass("wcsearch-search-model-placeholder-hover");
		});

		// make placeholder for input to be droppable
		placeholders.each( function() {
			var placeholder = $(this);
			var placeholder_height = placeholder.outerHeight();
			placeholder.droppable({
				over: function(event, ui) {
					placeholder.addClass("wcsearch-search-model-placeholder-hover");
				},
				out: function(event, ui) {
					placeholder.removeClass("wcsearch-search-model-placeholder-hover");
				},
				drop: function(event, ui) {
					var input = placeholder.find(".wcsearch-search-model-input");
					var to_placeholder = ui.draggable.parent();
					
					if (input.length) {
						// move input from one placeholder to another
						input.appendTo(to_placeholder);
					}

					var rows_number = placeholder.attr("data-grid-row-end");
					if (!rows_number || rows_number == 'auto') {
						rows_number = 1;
					}

					var to_rows_number = to_placeholder.attr("data-grid-row-end");
					if (!to_rows_number || to_rows_number == 'auto') {
						to_rows_number = 1;
					}
					
					placeholder.css("grid-row-end", 'span '+parseInt(to_rows_number));
					placeholder.attr("data-grid-row-end", parseInt(to_rows_number));
					to_placeholder.css("grid-row-end", 'span '+parseInt(rows_number));
					to_placeholder.attr("data-grid-row-end", parseInt(rows_number));
					
					ui.draggable
					.appendTo(placeholder)
					.css("inset", "")
					.css("width", "100%");

					// used to avoid a bag in chrome
					ui.draggable.css({ "top": 0, "left": 0 });
	
					placeholder.removeClass("wcsearch-search-model-placeholder-hover");

					wcsearch_highlight_placeholder(placeholder);

					wcsearch_build_options(placeholder, null, null);

					wcsearch_setup_terms_separators();
					
					wcsearch_model_update_placeholders();
				}
			});
		});
	};

	window.wcsearch_highlight_placeholder = function(placeholder) {
		// remove term selection
		$(".wcsearch-term-wrapper-highlight").removeClass("wcsearch-term-wrapper-highlight");
		
		$(".wcsearch-search-model-placeholder-highlight").removeClass("wcsearch-search-model-placeholder-highlight");
		placeholder.addClass("wcsearch-search-model-placeholder-highlight");
	};

	// add placeholder buttons: wider/narrower, delete and options when placeholder not empty
	window.wcsearch_add_placeholder_buttons = function(placeholder) {
		if (!placeholder.find(".wcsearch-search-model-buttons-panel").length) {
			var buttons_panel = $("<div/>").addClass("wcsearch-search-model-buttons-panel");

			var extend_button = $("<span/>")
			.addClass("wcsearch-search-model-extend-button")
			.attr("title", "<?php esc_html_e("wider/narrower", "WCSEARCH"); ?>")
			.on("click", function() {
				var input = placeholder.find(".wcsearch-search-model-input");

				// add one column class when no columns defined
				if (!placeholder.hasClass("wcsearch-search-model-placeholder-column-1") &&
					!placeholder.hasClass("wcsearch-search-model-placeholder-column-2") &&
					!placeholder.hasClass("wcsearch-search-model-placeholder-column-3") &&
					!placeholder.hasClass("wcsearch-search-model-placeholder-column-4") &&
					!placeholder.hasClass("wcsearch-search-model-placeholder-column-5")
				) {
					placeholder.addClass("wcsearch-search-model-placeholder-column-1");
				}
					
				if (placeholder.hasClass("wcsearch-search-model-placeholder-column-1")) {
					// no more columns when search form is too narrow
					if (wcsearch_model_columns_counter > 1) {
						placeholder.removeClass("wcsearch-search-model-placeholder-column-1");
						placeholder.removeClass("wcsearch-search-model-placeholder-column-2");
						placeholder.removeClass("wcsearch-search-model-placeholder-column-3");
						placeholder.removeClass("wcsearch-search-model-placeholder-column-4");
						placeholder.removeClass("wcsearch-search-model-placeholder-column-5");
						placeholder.addClass("wcsearch-search-model-placeholder-column-2");
					}
				} else if (placeholder.hasClass("wcsearch-search-model-placeholder-column-2")) {
					if (wcsearch_model_columns_counter > 2) {
						placeholder.removeClass("wcsearch-search-model-placeholder-column-1");
						placeholder.removeClass("wcsearch-search-model-placeholder-column-2");
						placeholder.removeClass("wcsearch-search-model-placeholder-column-3");
						placeholder.removeClass("wcsearch-search-model-placeholder-column-4");
						placeholder.removeClass("wcsearch-search-model-placeholder-column-5");
						placeholder.addClass("wcsearch-search-model-placeholder-column-3");
					} else {
						placeholder.removeClass("wcsearch-search-model-placeholder-column-1");
						placeholder.removeClass("wcsearch-search-model-placeholder-column-2");
						placeholder.removeClass("wcsearch-search-model-placeholder-column-3");
						placeholder.removeClass("wcsearch-search-model-placeholder-column-4");
						placeholder.removeClass("wcsearch-search-model-placeholder-column-5");
						placeholder.addClass("wcsearch-search-model-placeholder-column-1");
					}
				} else if (placeholder.hasClass("wcsearch-search-model-placeholder-column-3")) {
					if (wcsearch_model_columns_counter > 3) {
						placeholder.removeClass("wcsearch-search-model-placeholder-column-1");
						placeholder.removeClass("wcsearch-search-model-placeholder-column-2");
						placeholder.removeClass("wcsearch-search-model-placeholder-column-3");
						placeholder.removeClass("wcsearch-search-model-placeholder-column-4");
						placeholder.removeClass("wcsearch-search-model-placeholder-column-5");
						placeholder.addClass("wcsearch-search-model-placeholder-column-4");
					} else {
						placeholder.removeClass("wcsearch-search-model-placeholder-column-1");
						placeholder.removeClass("wcsearch-search-model-placeholder-column-2");
						placeholder.removeClass("wcsearch-search-model-placeholder-column-3");
						placeholder.removeClass("wcsearch-search-model-placeholder-column-4");
						placeholder.removeClass("wcsearch-search-model-placeholder-column-5");
						placeholder.addClass("wcsearch-search-model-placeholder-column-1");
					}
				} else if (placeholder.hasClass("wcsearch-search-model-placeholder-column-4")) {
					if (wcsearch_model_columns_counter > 4) {
						placeholder.removeClass("wcsearch-search-model-placeholder-column-1");
						placeholder.removeClass("wcsearch-search-model-placeholder-column-2");
						placeholder.removeClass("wcsearch-search-model-placeholder-column-3");
						placeholder.removeClass("wcsearch-search-model-placeholder-column-4");
						placeholder.removeClass("wcsearch-search-model-placeholder-column-5");
						placeholder.addClass("wcsearch-search-model-placeholder-column-5");
					} else {
						placeholder.removeClass("wcsearch-search-model-placeholder-column-1");
						placeholder.removeClass("wcsearch-search-model-placeholder-column-2");
						placeholder.removeClass("wcsearch-search-model-placeholder-column-3");
						placeholder.removeClass("wcsearch-search-model-placeholder-column-4");
						placeholder.removeClass("wcsearch-search-model-placeholder-column-5");
						placeholder.addClass("wcsearch-search-model-placeholder-column-1");
					}
				} else if (placeholder.hasClass("wcsearch-search-model-placeholder-column-5")) {
					placeholder.removeClass("wcsearch-search-model-placeholder-column-1");
					placeholder.removeClass("wcsearch-search-model-placeholder-column-2");
					placeholder.removeClass("wcsearch-search-model-placeholder-column-3");
					placeholder.removeClass("wcsearch-search-model-placeholder-column-4");
					placeholder.removeClass("wcsearch-search-model-placeholder-column-5");
					placeholder.addClass("wcsearch-search-model-placeholder-column-1");
				}
	
				wcsearch_model_update_placeholders();
			});
			buttons_panel.append(extend_button[0]);
			
			var delete_button = $('<span class="wcsearch-search-model-delete-button" title="<?php esc_html_e("delete", "WCSEARCH"); ?>"></span>')
			.on("click", function() {
				var input = placeholder.find(".wcsearch-search-model-input");
				if (input.length) {
					var slug = input.data('slug');
					
					$(".wcsearch-search-tab-options").html("");
					wcsearch_open_tab("elements");

					placeholder.find(".wcsearch-search-model-input").remove();

					if (slug && !$(".wcsearch-search-model-input[data-slug="+slug+"]").length) {
						$(".wcsearch-search-model-add-element-btn[data-slug="+slug+"]").addClass("wcsearch-search-model-add-element-btn-inactive");
					}
				} else {
					placeholder.remove();
				}
				wcsearch_model_update_placeholders();
			});
			buttons_panel.append(delete_button[0]);

			var bottom_buttons_panel = $("<div/>").addClass("wcsearch-search-model-bottom-buttons-panel");
			var down_button = $("<span/>")
			.addClass("wcsearch-search-model-down-button")
			.attr("title", "<?php esc_html_e("add row", "WCSEARCH"); ?>")
			.on("click", function() {
				var rows_number = placeholder.attr("data-grid-row-end");
				if (!rows_number || rows_number == 'auto') {
					rows_number = 1;
				}
				placeholder.css("grid-row-end", 'span '+(parseInt(rows_number)+1));
				placeholder.attr("data-grid-row-end", parseInt(rows_number)+1);

				wcsearch_model_update_placeholders();
			});
			bottom_buttons_panel.append(down_button[0]);
			
			var up_button = $("<span/>")
			.addClass("wcsearch-search-model-up-button")
			.attr("title", "<?php esc_html_e("remove row", "WCSEARCH"); ?>")
			.on("click", function() {
				var rows_number = placeholder.attr("data-grid-row-end");
				if (rows_number > 1) {
					placeholder.css("grid-row-end", 'span '+(parseInt(rows_number)-1));
					placeholder.attr("data-grid-row-end", parseInt(rows_number)-1);
				}

				wcsearch_model_update_placeholders();
			});
			bottom_buttons_panel.append(up_button[0]);

			var top_buttons_panel = $("<div/>").addClass("wcsearch-search-model-top-buttons-panel");
			var add_button = $("<span/>")
			.addClass("wcsearch-search-model-add-button")
			.attr("title", "<?php esc_html_e("add placeholder here", "WCSEARCH"); ?>")
			.on("click", function() {
				wcsearch_add_placeholder_to_model(placeholder);

				wcsearch_model_update_placeholders();
			});
			top_buttons_panel.append(add_button[0]);
				
			placeholder.append(buttons_panel[0]);
			placeholder.append(bottom_buttons_panel[0]);
			placeholder.append(top_buttons_panel[0]);
		}
	};

	window.wcsearch_get_field_button = function(slug) {
		if ($(".wcsearch-search-model-add-element-btn[data-slug="+slug+"]").length) {
			return $(".wcsearch-search-model-add-element-btn[data-slug="+slug+"]");
		}
	};
	window.wcsearch_get_field_name = function(slug) {
		var button = wcsearch_get_field_button(slug);
		if (typeof button != "undefined" && button.length) {
			return wcsearch_get_field_button(slug).text().trim();
		} else {
			return "Element was not defined yet!";
		}
	};

	window.wcsearch_make_input_draggable = function(input) {
		input.draggable({
			revert: "invalid",
			zIndex: 1
		});

		input.each(function() {
			var move_button = $("<div/>").addClass("wcsearch-search-model-move-button");

			$(this).on({
				mouseover: function() {
					var slug = $(this).data("slug");
					
					var button = wcsearch_get_field_button(slug);
					if (typeof button != "undefined") {
						button.addClass("wcsearch-active");
						
						var name = wcsearch_get_field_name(slug);
						$(this).attr("title", name);
					}
				},
				mouseleave: function() {
					var slug = $(this).data("slug");

					var button = wcsearch_get_field_button(slug);
					if (typeof button != "undefined") {
						button.removeClass("wcsearch-active");
					}
				},
				drag: function() {
					
				}
			});
			
			$(this).append(move_button);
		});
	};
	
	window.wcsearch_get_options = function(type, tax) {
		var default_options = wcsearch_model_options[type];
		
		// clone options object
		var options = JSON.parse(JSON.stringify(default_options));

		// extend default options values by entered options values from wcsearch_model
		$.each(wcsearch_model.placeholders, function(placeholder_id, val) {
			if (val.input && val.input.type == type) {
				if (type == 'tax') {
					if (val.input.tax == tax) {
						if (typeof val.input.options != "undefined") {
							$.each(options, function(i, option) {
								var option_name = option.name;
								
								if (typeof val.input.options[option_name] != "undefined") {
									options[i].value = val.input.options[option_name];
								}
							});
						}
					}
				} else {
					if (typeof val.input.options != "undefined") {
						$.each(options, function(i, option) {
							var option_name = option.name;
							if (typeof val.input.options[option_name] != "undefined") {
								options[i].value = val.input.options[option_name];
							}
						});
					}
				}
			}
		});

		return options;
	};

	window.wcsearch_hide_show_options = function(delay, options) {
		var form = $("form.wcsearch-search-model-options-form");
		var type = form.attr('data-type');
		var tax = form.attr('data-tax');

		if (typeof options == "undefined") {
			var options = wcsearch_get_options(type, tax);
		}
		
		$.each(options, function(i, option) {
			var row = form.find(".wcsearch-dependency-option-"+option.name);
			var visible = true;
				
			if (typeof option.dependency != "undefined") {
				$.each(option.dependency, function(dep_field_name, dep_field_val) {

					var dep_value = String(dep_field_val).split(',');

					var field = $(".wcsearch-search-model-options-input[name="+dep_field_name+"]");
					var field_val = field.val();
					if (dep_value.indexOf(String(field_val)) != -1 || (dep_value[0] == "" && field_val != 0)) {
						visible = true;
					} else {
						visible = false;

						return false;
					}
				});
			}
			
			if (visible) {
				row.show(delay);
			} else {
				row.hide(delay);
			}
		});
	}

	$(document).on('change', '.wcsearch-search-model-options-input', function() {
		wcsearch_hide_show_options(200);

		$(this).parents("form").find(".wcsearch-search-model-options-button").trigger("click");
	});

	// save options first, then save form
	var wcsearch_apply_submit_click = false;
	$(document).on('click', '.wcsearch-submit-model', function() {

		if ($(this).parents("form").find(".wcsearch-search-model-options-button").length) {
			wcsearch_apply_submit_click = true;
			
			$(this).parents("form").find(".wcsearch-search-model-options-button").trigger("click");

			return false;
		}
	});
	
	window.wcsearch_unset_term_options = function(input, term_id, option_name) {
		if (input.attr("data-terms_options") !== false) {
			var terms_options = "";
			if (input.attr("data-terms_options")) {
				terms_options = JSON.parse(input.attr("data-terms_options"));
			}

			if (typeof terms_options[term_id] != "undefined") {
				if (typeof terms_options[term_id][option_name] != "undefined") {
					delete terms_options[term_id][option_name];
				}
				if ($.isEmptyObject(terms_options[term_id])) {
					delete terms_options[term_id];
				}
				if ($.isEmptyObject(terms_options)) {
					input.attr("data-terms_options", "");
				} else {
					input.attr("data-terms_options", JSON.stringify(terms_options));
				}
			}
		}
	}
	
	window.wcsearch_set_term_options = function(input, term_id, options) {
		if (input.attr("data-terms_options") !== false) {
			var terms_options = {};
			if (input.attr("data-terms_options")) {
				terms_options = JSON.parse(input.attr("data-terms_options"));
			}

			if (typeof terms_options[term_id] != "undefined") {
				$.extend(terms_options[term_id], options);
			} else {
				terms_options[term_id] = options;
			}

			input.attr("data-terms_options", JSON.stringify(terms_options));
		}
	}
	
	window.wcsearch_get_term_options = function(input, term_id) {
		if (input.attr("data-terms_options") !== false) {
			var terms_options = '';
			if (input.attr("data-terms_options")) {
				terms_options = JSON.parse(input.attr("data-terms_options"));
			}

			if (typeof terms_options[term_id] != "undefined") {
				return terms_options[term_id];
			}
		}
	}
	
	window.wcsearch_build_options = function(placeholder, term_id, term_name) {
		var input = placeholder.find(".wcsearch-search-model-input");

		if (input.length) {
			// call these functions later, after options form will be appended
			var funcs_to_call = [];
			var options_form = $("<form/>");
			var slug = input.data("slug");
			var field_name = wcsearch_get_field_name(slug);
			options_form.append('<h3>'+field_name+'</h3>');

			// build popup options
			var type = input.data("type");
			var tax = input.data("tax");
			if (typeof type != "undefined" && typeof wcsearch_model_options[type] != "undefined") {

				options_form.addClass("wcsearch-search-model-options-form");
				options_form.attr('data-type', type);
				options_form.attr('data-tax', tax);

				if (term_id) {
					var heading = $("<h4/>").html('<a href="javascript:void(0);"><?php esc_html_e("Element:", "WCSEARCH"); ?> '+field_name+'</a>');
					heading.on("click", function() {
						placeholder.trigger("click");
					});
					options_form.append(heading);
					options_form.append('<h4><?php esc_html_e("Item:", "WCSEARCH"); ?> '+term_name+'</h4>');
					
					var options = [
							{
								type: "color",
								name: "color",
								title: "<?php esc_html_e("Item color", "WCSEARCH"); ?>"
							}
					];
				} else {
					var options = wcsearch_get_options(type, tax);
				}

				// build options one-by-one
				$.each(options, function(i, option) {
					if (typeof option.type != "undefined") {

						var value = '';
						if (term_id) {
							var term_options = wcsearch_get_term_options(input, term_id);

							if (term_options && typeof term_options[option.name] != "undefined") {
								value = term_options[option.name];
							}
						} else {
							value = input.attr("data-"+option.name);
						}

						if (option.type == "hidden") {
							var field = $('<input type="hidden" name="'+option.name+'" />');
							// this escapes value, instead of 'value="'+value+'"'
							field.val(value);
							options_form.append(field);
							
							return;
						}

						var row = $("<div/>").addClass("wcsearch-search-model-options-row");

						if (typeof option.dependency != "undefined") {
							row.addClass("wcsearch-dependency-option-"+option.name);
						}

						var column_one = $("<div/>").addClass("wcsearch-search-model-options-column-one");
						var column_two = $("<div/>").addClass("wcsearch-search-model-options-column-two");
						var title = $("<div/>").addClass("wcsearch-search-model-options-column-title").html(option.title);
						var name = option.name;
						var multi_button = '';
						/*if (typeof option.multi != "undefined" && option.multi) {
							name = name + '[]';
							multi_button = $("<span/>").addClass("wcsearch-search-model-options-multi-button wcsearch-fa wcsearch-fa-plus");
							multi_button.attr("title", "<?php esc_html_e("Add", "WCSEARCH"); ?> " + option.title);
							multi_button.on("click", function(e) {
								var row_old = $(this).parents(".wcsearch-search-model-options-row");
								var row_new = $("<div/>").addClass("wcsearch-search-model-options-row");
								var column_one_empty = $("<div/>").addClass("wcsearch-search-model-options-column-one");
								var title_empty = $("<div/>").addClass("wcsearch-search-model-options-column-title");
								column_one_empty.append(title_empty);
								var column_two_copy = row_old.find(".wcsearch-search-model-options-column-two").clone();
								row_new.append(column_one_empty);
								row_new.append(column_two_copy);

								row_new.insertAfter(row_old);
								
								//options_form.append(row_new);
								console.log($(this));
								console.log(column_two_copy);
							});
							title.append(multi_button);
						}*/
						column_one.append(title);
						if (typeof option.description != "undefined") {
							column_one.append('<div class="wcsearch-search-model-options-column-description">'+option.description+'</div>');
						}
						
						if (option.type == "string") {
							var field = $('<input type="text" class="wcsearch-form-control wcsearch-search-model-options-input" name="'+name+'" />');
							// this escapes value, instead of 'value="'+value+'"'
							field.val(value);
							column_two.append(field);
						}
						if (option.type == "select") {
							var field = $('<select class="wcsearch-form-control wcsearch-search-model-options-input" name="'+name+'" /> </select>');

							$.each(option.options, function(index, option_val) {
								var default_value = '';
								if (value == index) {
									default_value = 'selected="selected"';
								}
								
								field.append($('<option value="'+index+'" '+default_value+'>'+option_val+'</option>'));
							});
							column_two.append(field);
						}
						if (option.type == "color") {
							var input_id = input.attr("id");
							var class_name = 'wcsearch-seach-model-'+slug+'-'+option.name;
							var field = $('<input type="text" class="'+class_name+'" name="'+name+'" />');
							// this escapes value, instead of 'value="'+value+'"'
							field.val(value);
							column_two.append(field);
							
							var fn_to_call = function() {
								var params = {'term_id': term_id};
								var fn_name = 'wcsearch_callback_'+type+'_'+option.name+'_'+input_id;

								wcsearch_apply_color($("."+class_name), window[fn_name], params);
								window[fn_name](value, params);
							};
							funcs_to_call.push(fn_to_call);
						}
						if (option.type == "exact_terms") {

							var tax = input.data("tax");

							var items = input.data("exact_terms");
							
							var field = $('<select class="wcsearch-form-control wcsearch-search-model-options-input" name="'+name+'" /> </select>');

							var tax_field_name = "exact_terms";
							var tax_field_class = "wcsearch-exact-terms";

							$.each(option.options, function(index, option_val) {
								var default_value = '';
								if (value == index) {
									default_value = 'selected="selected"';

									if (value > 0) {
										$.post(
												wcsearch_js_objects.ajaxurl,
												{
													"action": "wcsearch_get_tax_options",
													"tax": tax,
													"items": items,
													"field_name": tax_field_name,
													"field_class": tax_field_class
												},
												function(response_from_the_action_function) {
													if (response_from_the_action_function != 0 && response_from_the_action_function.html) {
														$(".wcsearch-exact-terms").remove();
														
														field.after(response_from_the_action_function.html)
													}
												},
												'json'
										);
									}
								}
								
								field.append($('<option value="'+index+'" '+default_value+'>'+option_val+'</option>'));
							});
							column_two.append(field);

							field.on("change", function(e) {

								$(".wcsearch-exact-terms").remove();

								var is_exact_terms = $(this).val();
								
								if (is_exact_terms > 0) {
									$.post(
											wcsearch_js_objects.ajaxurl,
											{
												"action": "wcsearch_get_tax_options",
												"tax": tax,
												"items": items,
												"field_name": tax_field_name,
												"field_class": tax_field_class
											},
											function(response_from_the_action_function) {
												if (response_from_the_action_function != 0 && response_from_the_action_function.html) {
													field.after(response_from_the_action_function.html);

													field.parents("form").find(".wcsearch-search-model-options-button").trigger("click");
												}
											},
											'json'
									);
								}
							});
						}
						if (option.type == "dependency") {

							var items = input.data("dependency_items");
							
							var field = $('<select class="wcsearch-form-control wcsearch-search-model-options-input" name="'+name+'" /> </select>');

							var tax_field_name = "dependency_items";
							var tax_field_class = "wcsearch-tax-dependency";

							$.each(option.options, function(index, option_val) {
								var default_value = '';
								if (value == index) {
									default_value = 'selected="selected"';

									$.post(
											wcsearch_js_objects.ajaxurl,
											{
												"action": "wcsearch_get_tax_options",
												"tax": index,
												"items": items,
												"field_name": tax_field_name,
												"field_class": tax_field_class
											},
											function(response_from_the_action_function) {
												if (response_from_the_action_function != 0 && response_from_the_action_function.html) {
													$(".wcsearch-tax-dependency").remove();
													
													field.after(response_from_the_action_function.html)
												}
											},
											'json'
									);
								}
								
								field.append($('<option value="'+index+'" '+default_value+'>'+option_val+'</option>'));
							});
							column_two.append(field);

							field.on("change", function(e) {

								$(".wcsearch-tax-dependency").remove();
								
								var tax = $(this).val();
								
								$.post(
										wcsearch_js_objects.ajaxurl,
										{
											"action": "wcsearch_get_tax_options",
											"tax": tax,
											"items": items,
											"field_name": tax_field_name,
											"field_class": tax_field_class
										},
										function(response_from_the_action_function) {
											if (response_from_the_action_function != 0 && response_from_the_action_function.html) {
												field.after(response_from_the_action_function.html)
											}
										},
										'json'
								);
							});
						}

						row.append(column_one);
						row.append(column_two);
						options_form.append(row);
					}
				});

				if (options.length) {
					// Apply button, hidden by default
					var apply_button = $('<button class="wcsearch-search-model-options-button wcsearch-btn wcsearch-btn-primary"><?php esc_html_e("Apply changes", "WCSEARCH"); ?></button>');
					apply_button.on("click", function(e) {
						e.preventDefault();

						wcsearch_ajax_loader_target_show(placeholder);

						if (!term_id) {
							var post_params = options_form.serializeArray();

							post_params.push({ name: "type", value: type });
							post_params.push({ name: "tax", value: input.attr("data-tax") });
							post_params.push({ name: "slug", value: input.attr("data-slug") });
							post_params.push({ name: "values", value: input.attr("data-values") });
							post_params.push({ name: "used_by", value: input.attr("data-used_by") });
						} else {
							var post_params = [];
							$.each(input.data(), function(option_name, option_value) {
								post_params.push({ name: option_name, value: input.attr("data-"+option_name) });
							});
							//post_params.push({ name: "selected_term_id", value: term_id });
						}

						post_params.push({ name: "action", value: "wcsearch_get_search_model" });
						$.post(
							wcsearch_js_objects.ajaxurl,
							post_params,
							function(response_from_the_action_function) {
								if (response_from_the_action_function != 0 && response_from_the_action_function.html) {
									input.replaceWith(response_from_the_action_function.html);
									input = placeholder.find(".wcsearch-search-model-input");
									wcsearch_make_input_draggable(input);

									// set new input ID
									wcsearch_insert_param_in_uri("input", input.attr("id"));
								}
								wcsearch_ajax_loader_target_hide(placeholder.attr("id"));

								wcsearch_custom_input_controls();

								wcsearch_setup_terms_separators();

								wcsearch_model_update_placeholders();

								if (wcsearch_apply_submit_click) {
									apply_button.remove();

									$(".wcsearch-submit-model").trigger("click");

									return true;
								}

								wcsearch_process_main_search_fields();

								wcsearch_recount();
							},
							'json'
						);
					});

					options_form.append(apply_button);
				}
			}

			$(".wcsearch-search-tab-options").html(options_form);

			$.each(funcs_to_call, function(fn_name) {
				funcs_to_call[fn_name]();
			});
			
			wcsearch_hide_show_options(0, options);
			
			wcsearch_open_tab("options");
		}
	};

	window.wcsearch_model_update_columns = function() {
		$(".wcsearch-model-columns-num").val(wcsearch_model_columns_counter);
	}

	window.wcsearch_add_placeholder_to_model = function(before_placeholder) {
		var new_placeholder = $("<div/>")
		.addClass("wcsearch-search-model-placeholder")
		.addClass("wcsearch-search-model-placeholder-column-1");
		
		// make placeholder element to be droppable
		wcsearch_setup_placeholder(new_placeholder);

		if (typeof before_placeholder == "undefined") {
			$(".wcsearch-search-model-grid").append(new_placeholder[0]);
		} else {
			before_placeholder.before(new_placeholder[0]);

			// move current placeholder lower to stay in the same column
			if (wcsearch_model_columns_counter > 1) {
				var b_placeholder_index = before_placeholder.index();
				var wrapper = before_placeholder.parent();
				var offset = wcsearch_model_columns_counter-1;
				
				wrapper.find(".wcsearch-search-model-placeholder").eq(b_placeholder_index+offset).after(before_placeholder);
			}
		}

		wcsearch_add_placeholder_buttons(new_placeholder);

		return $(new_placeholder);
	};
	
	window.wcsearch_model_update_placeholders = function() {

		wcsearch_set_grid();
		
		wcsearch_model.placeholders = [];
		$(".wcsearch-search-model-placeholder").each(function(placeholder_id, placeholder) {
			var placeholder = $(placeholder);
			var input = placeholder.find(".wcsearch-search-model-input");
			var columns = 1;
			if (placeholder.hasClass("wcsearch-search-model-placeholder-column-1")) {
				columns = 1;
			}
			if (placeholder.hasClass("wcsearch-search-model-placeholder-column-2")) {
				columns = 2;
			}
			if (placeholder.hasClass("wcsearch-search-model-placeholder-column-3")) {
				columns = 3;
			}
			if (placeholder.hasClass("wcsearch-search-model-placeholder-column-4")) {
				columns = 4;
			}
			if (placeholder.hasClass("wcsearch-search-model-placeholder-column-5")) {
				columns = 5;
			}

			var rows_number = placeholder.attr("data-grid-row-end");
			if (!rows_number || rows_number == 'auto') {
				rows_number = 1;
			}
			
			var p_obj = { 
					"columns": columns,
					"rows": parseInt(rows_number),
					"input": ""
			};
			if (input.length) {
				var type = input.data("type");
				var slug = input.data("slug");
				p_obj.input = {
						"type": type,
						"slug": slug
				};
				if (type == "tax") {
					p_obj.input.tax = input.data("tax");
				}
				$.each(input.data(), function(option_name, option_value) {
					// Assign values with their structure
					//if (typeof option_value != "object") {
						p_obj.input[option_name] = input.attr("data-"+option_name);
					//}
				});
				if (input.attr("data-values") !== false) {
					p_obj.input.values = input.attr("data-values");
				}
			}
			
			wcsearch_model.placeholders.push(p_obj);
		});

		wcsearch_set_grid();

		console.log(JSON.stringify(wcsearch_model));
		$(".wcsearch-model-input").val(JSON.stringify(wcsearch_model));
	};

	window.wcsearch_add_element_to_model = function(element_data, placeholder_to_add) {
		var type = element_data['type'];
		
		wcsearch_ajax_loader_target_show(placeholder_to_add);
		
		var post_params = $.extend({ "action": "wcsearch_get_search_model" }, element_data);
		post_params['new_field'] = true;
		$.each(wcsearch_model_options[type], function(i, opt) {
			post_params[opt.name] = opt.value;
		});

		// first call should take element title
		if ((type == 'tax' || type == 'select') && (typeof element_data['title'] != "undefined")) {
			post_params['title'] = element_data['title'];
		}
		
		$.post(
			wcsearch_js_objects.ajaxurl,
			post_params,
			function(response_from_the_action_function) {
				if (response_from_the_action_function != 0 && response_from_the_action_function.html) {
					placeholder_to_add.append($(response_from_the_action_function.html));
					var input = placeholder_to_add.find(".wcsearch-search-model-input");
					wcsearch_make_input_draggable(input);

					placeholder_to_add.trigger("click");
				}
				wcsearch_ajax_loader_target_hide(placeholder_to_add.attr("id"));

				// clear height before update
				placeholder_to_add.removeAttr("data-grid-row-end");
				
				wcsearch_model_update_placeholders();

				wcsearch_custom_input_controls();

				wcsearch_element_loading = false;
			},
			'json'
		);
	};

	window.wcsearch_set_grid = function () {
		var row_gap = 30;
		var row_height = 48;
		
		var row_height_with_borders = row_height+4;
		$(".wcsearch-search-model-grid").css("grid-gap", row_gap+"px");
		
		$(".wcsearch-search-model-placeholder").each(function() {
			var placeholder = $(this);
			var input = placeholder.find(".wcsearch-search-model-input");
			
			var rows_number = placeholder.attr("data-grid-row-end");
			if (!rows_number || rows_number == 'auto') {
				rows_number = 1;
				
				if (input.length) {
					rows_number = Math.ceil(parseInt(input.outerHeight())/(row_height+row_gap));
	
					if (parseInt(input.outerHeight()) > (rows_number*(row_height+row_gap))-row_gap) {
						rows_number++;
					}
				}

				placeholder.attr("data-grid-row-end", parseInt(rows_number));
			}
				
			placeholder.css("grid-row-end", 'span '+parseInt(rows_number));
		});
	}

	window.wcsearch_apply_color = function(color_picker, callback, params) {
		color_picker.wpColorPicker({
			width: 200,
			change: function(event, ui) {
				var color_input = ui.color.toString();
				callback(color_input, params);
			},
			clear: function() {
				callback(false, params);
			}
		});
	}
	window.wcsearch_shade_color = function(color, percent) {
	    var R = parseInt(color.substring(1,3),16);
	    var G = parseInt(color.substring(3,5),16);
	    var B = parseInt(color.substring(5,7),16);

	    R = parseInt(R * (100 + percent) / 100);
	    G = parseInt(G * (100 + percent) / 100);
	    B = parseInt(B * (100 + percent) / 100);

	    R = (R<255)?R:255;  
	    G = (G<255)?G:255;  
	    B = (B<255)?B:255;  

	    var RR = ((R.toString(16).length==1)?"0"+R.toString(16):R.toString(16));
	    var GG = ((G.toString(16).length==1)?"0"+G.toString(16):G.toString(16));
	    var BB = ((B.toString(16).length==1)?"0"+B.toString(16):B.toString(16));

	    return "#"+RR+GG+BB;
	}
	window.wcsearch_rgb_to_rgba = function(bg_color, transparency) {
		var re = /(rgb)\(([0-9]+),\s+([0-9]+),\s+([0-9]+)/; 
		var rea = /(rgba)\(([0-9]+),\s+([0-9]+),\s+([0-9]+)/; 
		var subst = 'rgba($2,$3,$4,'+transparency+')'; 

		var bg_color = bg_color.replace(re, subst);
		return bg_color.replace(rea, subst);
	}
	window.wcsearch_set_bg_transparency = function(percent) {
		var bg_color = $(".wcsearch-search-model-grid").css("background-color");
		var rgba_bg_color = wcsearch_rgb_to_rgba(bg_color, percent/100)
		$(".wcsearch-search-model-grid").css("background-color", rgba_bg_color);
	}
	window.wcsearch_apply_bg_color = function(color_input) {
		if (color_input) {
			$(".wcsearch-search-model-grid").css("background-color", color_input);
	
			wcsearch_set_bg_transparency($(".wcsearch-seach-model-bg-transparency").val());
		} else {
			$(".wcsearch-search-model-grid").css("background-color", "");
		}
	}
	window.wcsearch_apply_text_color = function(color_input) {
		var styles = '.wcsearch-search-model-input, .wcsearch-search-model-input a, .wcsearch-search-model-placeholder { color: '+color_input+'; }';
		$("head").append('<style>'+styles+'</style>');
	}
	window.wcsearch_apply_elements_color = function(color_input) {
		var primary_color = color_input;
		var secondary_color = wcsearch_shade_color(color_input, -40);

		$(".wcsearch-seach-model-elements-color-secondary").val(secondary_color);
			
		var styles = `
		.wcsearch-content .wcsearch-search-model-grid select,
		.wcsearch-content .wcsearch-search-model-grid select:focus {
			background-image:
			linear-gradient(50deg, transparent 50%, #FFFFFF 50%),
			linear-gradient(130deg, #FFFFFF 50%, transparent 50%),
			linear-gradient(to right, `+primary_color+`, `+primary_color+`) !important;
		}
		.wcsearch-content .wcsearch-search-model-grid .wcsearch-checkbox .wcsearch-control-indicator,
		.wcsearch-content .wcsearch-search-model-grid .wcsearch-radio .wcsearch-control-indicator {
			border-color: `+primary_color+`;
		}
		.wcsearch-field-checkbox-item-checked {
			color: `+primary_color+`;
		}
		.wcsearch-search-model .wcsearch-checkbox label input:checked ~ .wcsearch-control-indicator,
		.wcsearch-content .wcsearch-search-model-grid .wcsearch-radio label input:checked ~ .wcsearch-control-indicator {
			background: `+primary_color+`;
		}
		.wcsearch-content .wcsearch-search-model-grid .ui-slider.ui-slider-horizontal .ui-widget-header {
			background-color: `+secondary_color+`;
		}
		.wcsearch-content .wcsearch-search-model-grid .ui-slider.ui-widget-content .ui-slider-handle.ui-state-default,
		.wcsearch-content .wcsearch-search-model-grid .ui-slider.ui-widget-content .ui-slider-handle.ui-state-default:focus,
		.wcsearch-content .wcsearch-search-model-grid .ui-slider.ui-widget-content .ui-slider-handle.ui-state-default:active,
		.wcsearch-content .wcsearch-search-model-grid .ui-slider.ui-widget-content .ui-slider-handle.ui-state-focus,
		.wcsearch-content .wcsearch-search-model-grid .ui-slider.ui-widget-content .ui-slider-handle.ui-state-hover {
			border: 1px solid `+secondary_color+`;
			background-color: `+primary_color+`;
		}
		.wcsearch-content .wcsearch-search-model-grid .wcsearch-search-model-input-button,
		.wcsearch-content .wcsearch-search-model-grid .wcsearch-date-reset-button {
			background-color: `+primary_color+` !important;
			border: 1px solid `+secondary_color+` !important;
		}
		.wcsearch-content .wcsearch-search-model-grid .wcsearch-search-model-input-reset-button {
			color: `+primary_color+` !important;
			border: 1px solid `+secondary_color+` !important;
		}
		.wcsearch-content .wcsearch-loader:before {
			border-top-color: `+primary_color+` !important;
			border-bottom-color: `+primary_color+` !important;
		}
		`;
		$("head").append('<style>'+styles+'</style>');
	}
	
	window.wcsearch_admin_model_init = function () {
		// init inputs and placeholders
		wcsearch_make_input_draggable($(".wcsearch-search-model-input"));
		wcsearch_setup_placeholder($(".wcsearch-search-model-placeholder"));

		var tab = wcsearch_get_uri_param("tab");

		// options of opened element
		var input_id = wcsearch_get_uri_param("input");
		if (tab == 'options' && input_id && $("#"+input_id).length) {
			var placeholder = $("#"+input_id).parent();
			placeholder.trigger("click");
		}

		// open tab
		if (tab) {
			wcsearch_open_tab(tab);
		}
		
		// set input by default value
		wcsearch_model_update_columns();

		wcsearch_setup_terms_separators();
		
		// set input by default value
		wcsearch_model_update_placeholders();
	}

	window.wcsearch_open_tab = function(tab) {
		$(".wcsearch-search-tab-content").hide();
		$(".wcsearch-search-tab-content[data-tab="+tab+"]").show();

		if (!$(".wcsearch-search-tab-content[data-tab="+tab+"]").html()) {
			$(".wcsearch-search-tab-content[data-tab="+tab+"]").html("<?php esc_attr_e('Select element on the search form', 'WCSEARCH'); ?>");
		}

		$(".wcsearch-search-tab-title").removeClass("wcsearch-search-tab-active");
		$(".wcsearch-search-tab-title[data-tab="+tab+"]").addClass("wcsearch-search-tab-active");

		wcsearch_insert_param_in_uri("tab", tab);
	}
	
	$(function() {
		wcsearch_model_column = $(".wcsearch-search-model-column");
		
		$(".wcsearch-search-model-input-field, .wcsearch-search-model-input-radios input").disableSelection();

		$(document).on("click", ".wcsearch-search-model-placeholder", function(e) {
			wcsearch_highlight_placeholder($(this));
			
			var input = $(this).find(".wcsearch-search-model-input");
			if (input.length) {
				var term_id;
				var term_name;
				if ($(e.target).is(".wcsearch-model-options-link")) {
					term_id = $(e.target).data("term-id");
					term_name = $(e.target).data("term-name");

					$(e.target).parents(".wcsearch-term-wrapper").addClass("wcsearch-term-wrapper-highlight");
				}

				wcsearch_insert_param_in_uri("input", input.attr("id"));
				
				wcsearch_build_options($(this), term_id, term_name);
			} else {
				wcsearch_open_tab("elements");
			}
		});
		
		$(".wcsearch-search-model-placeholder").each(function() {
			wcsearch_add_placeholder_buttons($(this));
		});

		// add one column button
		$(".wcsearch-search-model-add-column-btn").on("click", function(e) {
			e.preventDefault();

			if (wcsearch_model_column.hasClass("wcsearch-search-model-column-1")) {
				wcsearch_model_column.removeClass("wcsearch-search-model-column-1");
				wcsearch_model_column.removeClass("wcsearch-search-model-column-2");
				wcsearch_model_column.removeClass("wcsearch-search-model-column-3");
				wcsearch_model_column.removeClass("wcsearch-search-model-column-4");
				wcsearch_model_column.removeClass("wcsearch-search-model-column-5");
				wcsearch_model_column.addClass("wcsearch-search-model-column-2");
				wcsearch_model_columns_counter = 2;
			} else if (wcsearch_model_column.hasClass("wcsearch-search-model-column-2")) {
				wcsearch_model_column.removeClass("wcsearch-search-model-column-1");
				wcsearch_model_column.removeClass("wcsearch-search-model-column-2");
				wcsearch_model_column.removeClass("wcsearch-search-model-column-3");
				wcsearch_model_column.removeClass("wcsearch-search-model-column-4");
				wcsearch_model_column.removeClass("wcsearch-search-model-column-5");
				wcsearch_model_column.addClass("wcsearch-search-model-column-3");
				wcsearch_model_columns_counter = 3;
			} else if (wcsearch_model_column.hasClass("wcsearch-search-model-column-3")) {
				wcsearch_model_column.removeClass("wcsearch-search-model-column-1");
				wcsearch_model_column.removeClass("wcsearch-search-model-column-2");
				wcsearch_model_column.removeClass("wcsearch-search-model-column-3");
				wcsearch_model_column.removeClass("wcsearch-search-model-column-4");
				wcsearch_model_column.removeClass("wcsearch-search-model-column-5");
				wcsearch_model_column.addClass("wcsearch-search-model-column-4");
				wcsearch_model_columns_counter = 4;
			} else if (wcsearch_model_column.hasClass("wcsearch-search-model-column-4")) {
				wcsearch_model_column.removeClass("wcsearch-search-model-column-1");
				wcsearch_model_column.removeClass("wcsearch-search-model-column-2");
				wcsearch_model_column.removeClass("wcsearch-search-model-column-3");
				wcsearch_model_column.removeClass("wcsearch-search-model-column-4");
				wcsearch_model_column.removeClass("wcsearch-search-model-column-5");
				wcsearch_model_column.addClass("wcsearch-search-model-column-5");
				wcsearch_model_columns_counter = 5;
			} else if (wcsearch_model_column.hasClass("wcsearch-search-model-column-5")) {
				wcsearch_model_column.removeClass("wcsearch-search-model-column-1");
				wcsearch_model_column.removeClass("wcsearch-search-model-column-2");
				wcsearch_model_column.removeClass("wcsearch-search-model-column-3");
				wcsearch_model_column.removeClass("wcsearch-search-model-column-4");
				wcsearch_model_column.removeClass("wcsearch-search-model-column-5");
				wcsearch_model_column.addClass("wcsearch-search-model-column-1");
				wcsearch_model_columns_counter = 1;
			}

			$(this).text("<?php esc_html_e('Add column', 'WCSEARCH'); ?>" + " (" + wcsearch_model_columns_counter + ")");

			wcsearch_model_update_columns();
			wcsearch_model_update_placeholders();
		});
		
		// add one placeholder button
		$(".wcsearch-search-model-add-placeholder-btn").on("click", function(e) {
			e.preventDefault();
			
			wcsearch_add_placeholder_to_model();

			wcsearch_model_update_placeholders();
		});

		// add new element button
		$(".wcsearch-search-model-add-element-btn").on("click", function(e) {
			e.preventDefault();

			var slug = $(this).data("slug");
			var element_data = $(this).data();

			// first call should take element title
			var field_name = wcsearch_get_field_name(slug);
			element_data.title = field_name;
			
			
			// avoid mismatch in adding elements when previous request was not finished
			if (!wcsearch_element_loading && slug) {
				var placeholder_to_add = false;

				$.each(wcsearch_model.placeholders, function(placeholder_id, placeholder) {
					var is_input = $($(".wcsearch-search-model-placeholder")[placeholder_id]).find(".wcsearch-search-model-input").length;
					if (!is_input) {
						placeholder_to_add = $($(".wcsearch-search-model-placeholder")[placeholder_id]);

						wcsearch_element_loading = true;
						wcsearch_add_element_to_model(element_data, placeholder_to_add);

						return false;
					}
					if ((placeholder_id+1) == wcsearch_model.placeholders.length) {
						placeholder_to_add = wcsearch_add_placeholder_to_model();

						wcsearch_element_loading = true;
						wcsearch_add_element_to_model(element_data, placeholder_to_add);

						return false;
					}
				});

				$(this).removeClass("wcsearch-search-model-add-element-btn-inactive");
				
				wcsearch_model_update_placeholders();
			}
		})
		.on("mouseover", function() {
			var slug = $(this).data("slug");
			
			$(".wcsearch-search-model-input[data-slug="+slug+"]").parent().addClass("wcsearch-search-model-placeholder-hover");
		})
		.on("mouseleave", function() {
			var slug = $(this).data("slug");
			
			$(".wcsearch-search-model-input[data-slug="+slug+"]").parent().removeClass("wcsearch-search-model-placeholder-hover");
		});

		wcsearch_apply_color($(".wcsearch-seach-model-bg-color"), wcsearch_apply_bg_color);
		<?php if ($search_form_data['bg_color']): ?>
		wcsearch_apply_bg_color("<?php echo $search_form_data['bg_color']; ?>");
		<?php endif; ?>
		
		wcsearch_apply_color($(".wcsearch-seach-model-text-color"), wcsearch_apply_text_color);
		wcsearch_apply_text_color("<?php echo $search_form_data['text_color']; ?>");
		
		wcsearch_apply_color($(".wcsearch-seach-model-elements-color"), wcsearch_apply_elements_color);
		wcsearch_apply_elements_color("<?php echo $search_form_data['elements_color']; ?>");

		<?php if ($search_form_data['bg_color']): ?>
		wcsearch_set_bg_transparency(<?php echo $search_form_data['bg_transparency']; ?>);
		<?php endif; ?>

		$(".wcsearch-search-tab-title").on("click", function(e) {
			e.preventDefault();
			var tab = $(this).data("tab");
			
			wcsearch_open_tab(tab);
		});
		
		$("body").on("change", ".wcsearch-seach-model-use-overlay-chbx", function() {
			if ($(this).is(':checked')) {
				$(".wcsearch-search-model-grid").addClass("wcsearch-search-model-grid-image");
			} else {
				$(".wcsearch-search-model-grid").removeClass("wcsearch-search-model-grid-image");
			}
		});
		$("body").on("change", ".wcsearch-seach-model-bg-transparency", function() {
			wcsearch_set_bg_transparency($(this).val());
		});
		$("body").on("change", ".wcsearch-seach-use-border-chbx", function() {
			if ($(this).is(':checked')) {
				$(".wcsearch-search-model-grid").addClass("wcsearch-search-model-grid-border");
			} else {
				$(".wcsearch-search-model-grid").removeClass("wcsearch-search-model-grid-border");
			}
		});

		if ($(".wcsearch-search-model-used-by select").length) {
			$(".wcsearch-search-model-used-by select").data("current_val", $(".wcsearch-search-model-used-by select").val());
		}
		$("body").on("change", ".wcsearch-search-model-used-by select", function() {
			if (!confirm("<?php esc_attr_e("All inputs will be droped and empty form saved. Continue?", "WCSEARCH"); ?>")) {
				$(this).val($(this).data("current_val"));
				
				return false;
			}
			$(".wcsearch-submit-model").trigger("click");
		});

		wcsearch_admin_model_init();
	});
})(jQuery);
</script>

<div class="wcsearch-content wcsearch-search-model-wrapper">
	<div class="wcsearch-search-model-sidebar">
		<div class="wcsearch-search-model-top-buttons">
			<input type="hidden" name="post_status" value="publish" />
			<input type="submit" class="wcsearch-btn wcsearch-btn-primary wcsearch-submit-model" value="<?php esc_attr_e('Save form', 'WCSEARCH'); ?>" name="submit" />
			<?php if (wcsearch_is_woo_active() && $search_form_data['used_by'] == 'wc'): ?>
			<a target="_blank" href="<?php echo add_query_arg('wcsearch_test_form', $search_form_model->id, wc_get_page_permalink( 'shop' )); ?>" class="wcsearch-btn wcsearch-btn-primary"><?php esc_attr_e('Test form', 'WCSEARCH'); ?></a>
			<?php endif; ?>
		</div>
		<div class="wcsearch-search-tabs">
			<div class="wcsearch-search-tab-titles-wrapper">
				<div class="wcsearch-search-tab-title wcsearch-search-tab-active" data-tab="elements">
					<a href="#elements"><?php esc_html_e('Elements', 'WCSEARCH'); ?></a>
				</div>
				<div class="wcsearch-search-tab-title" data-tab="form">
					<a href="#form"><?php esc_html_e('Form', 'WCSEARCH'); ?></a>
				</div>
				<div class="wcsearch-search-tab-title" data-tab="options">
					<a href="#elements"><?php esc_html_e('Options', 'WCSEARCH'); ?></a>
				</div>
			</div>
			<div class="wcsearch-search-tab-content wcsearch-search-tab-elements" data-tab="elements">
				<?php if (($all_plugins = wcsearch_is_standalone_plugin()) && is_array($all_plugins) && count($all_plugins) > 1): ?>
				<div class="wcsearch-search-model-options-row wcsearch-search-model-used-by">
					<div class="wcsearch-search-model-options-column">
						<?php esc_html_e('This search form is used by', 'WCSEARCH'); ?>
						<select class="wcsearch-form-control" name="used_by" autocomplete="off">
							<?php foreach ($all_plugins AS $plugin_slug=>$plugin_name): ?>
							<option value="<?php echo esc_attr($plugin_slug); ?>" <?php selected($search_form_data['used_by'], $plugin_slug); ?>><?php echo esc_html($plugin_name); ?></option>
							<?php endforeach; ?>
						</select>
					</div>
				</div>
				<?php else: ?>
				<input type="hidden" name="used_by" value="<?php echo wcsearch_get_default_used_by(); ?>" />
				<?php endif; ?>
				<div class="wcsearch-search-model-elements-panel">
					<input type="hidden" name="model" class="wcsearch-model-input" autocomplete="off" value="" />
					<input type="hidden" name="columns_num" class="wcsearch-model-columns-num" autocomplete="off" value="" />
					<?php $search_form_model->buildFieldsButtons(wcsearch_get_model_fields($search_form_data['used_by'])); ?>
				</div>
			</div>
			<div class="wcsearch-search-tab-content wcsearch-search-tab-form" data-tab="form" style="display: none;">
				<div class="wcsearch-search-model-form-panel">
					<?php if (wcsearch_is_woo_active() && $search_form_data['used_by'] == 'wc'): ?>
					<div class="wcsearch-search-model-options-row">
						<div class="wcsearch-search-model-options-column-one">
							<label for="on_shop_page" class="wcsearch-search-model-options-column-title">
								<?php esc_html_e('On the shop page', 'WCSEARCH'); ?>
							</label>
						</div>
						<div class="wcsearch-search-model-options-column-two">
							<input type="checkbox" id="on_shop_page" name="on_shop_page" class="wcsearch-seach-model-shop-page-chbx" value="1" autocomplete="off" <?php checked($search_form_data['on_shop_page'], true); ?> />
						</div>
					</div>
					<?php endif; ?>
					<div class="wcsearch-search-model-options-row">
						<div class="wcsearch-search-model-options-column-one">
							<label for="auto_submit" class="wcsearch-search-model-options-column-title">
								<?php esc_html_e('Auto-submit', 'WCSEARCH'); ?>
							</label>
							<div class="wcsearch-search-model-options-column-description">
								<?php esc_html_e('No search button required', 'WCSEARCH'); ?>
							</div>
						</div>
						<div class="wcsearch-search-model-options-column-two">
							<input type="checkbox" id="auto_submit" name="auto_submit" class="wcsearch-seach-model-auto-submit-chbx" value="1" autocomplete="off" <?php checked($search_form_data['auto_submit'], true); ?> />
						</div>
					</div>
					<div class="wcsearch-search-model-options-row">
						<div class="wcsearch-search-model-options-column-one">
							<label for="use_ajax" class="wcsearch-search-model-options-column-title">
								<?php esc_html_e('Use AJAX', 'WCSEARCH'); ?>
							</label>
							<div class="wcsearch-search-model-options-column-description">
								<?php esc_html_e('or enter target URL', 'WCSEARCH'); ?>
							</div>
						</div>
						<div class="wcsearch-search-model-options-column-two">
							<input type="checkbox" id="use_ajax" name="use_ajax" class="wcsearch-seach-model-useajax-chbx" value="1" autocomplete="off" <?php checked($search_form_data['use_ajax'], true); ?> />
						</div>
					</div>
					<div class="wcsearch-search-model-options-row">
						<div class="wcsearch-search-model-options-column-one">
							<label for="target_url" class="wcsearch-search-model-options-column-title">
								<?php esc_html_e('Target URL', 'WCSEARCH'); ?>
							</label>
							<div class="wcsearch-search-model-options-column-description">
								<?php esc_html_e('Submit form to this URL and display results', 'WCSEARCH'); ?>
							</div>
						</div>
						<div class="wcsearch-search-model-options-column-two">
							<input type="text" id="target_url" name="target_url" class="wcsearch-seach-target-url" value="<?php echo $search_form_data['target_url']; ?>" autocomplete="off" />
						</div>
					</div>
					<div class="wcsearch-search-model-options-row">
						<div class="wcsearch-search-model-options-column-one">
							<div  class="wcsearch-search-model-options-column-title">
								<?php esc_html_e('Background color', 'WCSEARCH'); ?>
							</div>
						</div>
						<div class="wcsearch-search-model-options-column-two">
							<input type="text" name="bg_color" class="wcsearch-seach-model-bg-color" autocomplete="off" value="<?php echo esc_attr($search_form_data['bg_color']); ?>" />
						</div>
					</div>
					<div class="wcsearch-search-model-options-row">
						<div class="wcsearch-search-model-options-column-one">
							<div class="wcsearch-search-model-options-column-title">
								<?php esc_html_e('Text color', 'WCSEARCH'); ?>
							</div>
						</div>
						<div class="wcsearch-search-model-options-column-two">
							<input type="text" name="text_color" class="wcsearch-seach-model-text-color" autocomplete="off" value="<?php echo esc_attr($search_form_data['text_color']); ?>" />
						</div>
					</div>
					<div class="wcsearch-search-model-options-row">
						<div class="wcsearch-search-model-options-column-one">
							<div  class="wcsearch-search-model-options-column-title">
								<?php esc_html_e('Elements color', 'WCSEARCH'); ?>
							</div>
						</div>
						<div class="wcsearch-search-model-options-column-two">
							<input type="text" name="elements_color" class="wcsearch-seach-model-elements-color" autocomplete="off" value="<?php echo esc_attr($search_form_data['elements_color']); ?>" />
							<input type="hidden" name="elements_color_secondary" class="wcsearch-seach-model-elements-color-secondary" value="" />
						</div>
					</div>
					<div class="wcsearch-search-model-options-row">
						<div class="wcsearch-search-model-options-column-one">
							<label for="use_overlay" class="wcsearch-search-model-options-column-title">
								<?php esc_html_e('Show overlay', 'WCSEARCH'); ?>
							</label>
						</div>
						<div class="wcsearch-search-model-options-column-two">
							<input type="checkbox" id="use_overlay" name="use_overlay" class="wcsearch-seach-model-use-overlay-chbx" value="1" autocomplete="off" <?php checked($search_form_data['use_overlay'], true); ?> />
						</div>
					</div>
					<div class="wcsearch-search-model-options-row">
						<div class="wcsearch-search-model-options-column-one">
							<div  class="wcsearch-search-model-options-column-title">
								<?php esc_html_e('Overlay transparency', 'WCSEARCH'); ?>
							</div>
						</div>
						<div class="wcsearch-search-model-options-column-two">
							<input type="number" name="bg_transparency" class="wcsearch-seach-model-bg-transparency" autocomplete="off" value="<?php echo esc_attr($search_form_data['bg_transparency']); ?>" />
						</div>
					</div>
					<div class="wcsearch-search-model-options-row">
						<div class="wcsearch-search-model-options-column-one">
							<label for="use_border" class="wcsearch-search-model-options-column-title">
								<?php esc_html_e('Use border', 'WCSEARCH'); ?>
							</label>
						</div>
						<div class="wcsearch-search-model-options-column-two">
							<input type="checkbox" id="use_border" name="use_border" class="wcsearch-seach-use-border-chbx" value="1" autocomplete="off" <?php checked($search_form_data['use_border'], true); ?> />
						</div>
					</div>
					<div class="wcsearch-search-model-options-row">
						<div class="wcsearch-search-model-options-column-one">
							<label for="scroll_to" class="wcsearch-search-model-options-column-title">
								<?php esc_html_e('Scroll to results after submit', 'WCSEARCH'); ?>
							</label>
						</div>
						<div class="wcsearch-search-model-options-column-two">
							<input type="checkbox" id="scroll_to" name="scroll_to" class="wcsearch-seach-scroll-to-chbx" value="products" autocomplete="off" <?php checked($search_form_data['scroll_to'], 'products'); ?> />
						</div>
					</div>
					<div class="wcsearch-search-model-options-row">
						<div class="wcsearch-search-model-options-column-one">
							<label for="sticky_scroll" class="wcsearch-search-model-options-column-title">
								<?php esc_html_e('Sticky scroll', 'WCSEARCH'); ?>
							</label>
						</div>
						<div class="wcsearch-search-model-options-column-two">
							<input type="checkbox" id="sticky_scroll" name="sticky_scroll" class="wcsearch-seach-sticky-scroll-chbx" value="1" autocomplete="off" <?php checked($search_form_data['sticky_scroll'], true); ?> />
						</div>
					</div>
					<div class="wcsearch-search-model-options-row">
						<div class="wcsearch-search-model-options-column-one">
							<label for="sticky_scroll_toppadding" class="wcsearch-search-model-options-column-title">
								<?php esc_html_e('Sticky scroll top padding', 'WCSEARCH'); ?>
							</label>
						</div>
						<div class="wcsearch-search-model-options-column-two">
							<input type="text" id="sticky_scroll_toppadding" name="sticky_scroll_toppadding" class="wcsearch-seach-sticky-scroll-toppadding" value="<?php echo $search_form_data['sticky_scroll_toppadding']; ?>" autocomplete="off" />
						</div>
					</div>
				</div>
			</div>
			<div class="wcsearch-search-tab-content wcsearch-search-tab-options" data-tab="options" style="display: none;">
				<?php esc_html_e('Select element on the search form', 'WCSEARCH'); ?>
			</div>
		</div>
		<div class="wcsearch-search-model-bottom-buttons">
			<input type="hidden" name="post_status" value="publish" />
			<input type="submit" class="wcsearch-btn wcsearch-btn-primary wcsearch-submit-model" value="<?php esc_attr_e('Save form', 'WCSEARCH'); ?>" name="submit" />
			<?php if (wcsearch_is_woo_active() && $search_form_data['used_by'] == 'wc'): ?>
			<a target="_blank" href="<?php echo add_query_arg('wcsearch_test_form', $search_form_model->id, wc_get_page_permalink( 'shop' )); ?>" class="wcsearch-btn wcsearch-btn-primary"><?php esc_attr_e('Test form', 'WCSEARCH'); ?></a>
			<?php endif; ?>
		</div>
	</div>
		
	<div class="wcsearch-search-model">
		<div class="wcsearch-search-model-top-buttons">
			<button class="wcsearch-search-model-add-column-btn wcsearch-btn wcsearch-btn-primary"><?php esc_html_e('Add column', 'WCSEARCH'); ?> (<?php echo esc_attr($search_form_data['columns_num']); ?>)</button>
			<button class="wcsearch-search-model-add-placeholder-btn wcsearch-btn wcsearch-btn-primary"><?php esc_html_e('Add placeholder', 'WCSEARCH'); ?></button>
		</div>
		
		<div class="wcsearch-search-model-column wcsearch-search-model-column-<?php echo esc_attr($search_form_data['columns_num']); ?>">
			<div class="wcsearch-search-model-grid <?php if ($search_form_data['use_overlay']): ?>wcsearch-search-model-grid-image<?php endif; ?> <?php if ($search_form_data['use_border']): ?>wcsearch-search-model-grid-border<?php endif; ?>">
				<?php $search_form_model->buildLayout(); ?>
			</div>
		</div>
	</div>
</div>

<?php wcsearch_renderTemplate('admin_footer.tpl.php'); ?>