(function () {
    'use strict';
    
    window.admin = {
        parts: {},
        pages: {}
    };
})();
(function () {
    'use strict';

    $(document).ready(function() {
        admin.parts.bulkActions();
        admin.parts.main();
        admin.parts.jqueryValidationCustomMethods();
        admin.parts.passwordVisibilityToggle();
        admin.parts.loadCKEditor();
        admin.parts.downloadCookieHandler();

        // Switch pages
        switch ($("body").data("page-id")) {
            case 'install':
                admin.pages.install();
                break;
            case 'login':
                admin.pages.loginForm();
                admin.pages.loginLdapForm();
                break;
            case 'dashboard':
                admin.pages.dashboard();
                admin.parts.widgetStatistics();
                admin.parts.widgetActionLog();
                admin.parts.widgetNews();
                break;
            case 'categories_list':
                admin.pages.categoriesAdmin();
                break;
            case 'clients_memberships_requests':
                admin.pages.clientsAccountsRequests();
                break;
            case 'clients_accounts_requests':
                admin.pages.clientsAccountsRequests();
                break;
            case 'file_editor':
                admin.pages.fileEditor();
                break;
            case 'client_form':
                admin.pages.clientForm();
                break;
            case 'user_form':
                admin.pages.userForm();
                break;
            case 'group_form':
                admin.pages.groupForm();
                break;
            case 'email_templates':
                admin.pages.emailTemplates();
                break;
            case 'default_template':
            case 'manage_files':
                admin.parts.filePreviewModal();
                break;
            case 'reset_password_enter_email':
                admin.pages.resetPasswordEnterEmail();
                break;
            case 'reset_password_enter_new':
                admin.pages.resetPasswordEnterNew();
                break;
            case 'upload_form':
                admin.pages.uploadForm();
                break;
            case 'import_orphans':
                admin.pages.importOrphans();
                break;
            case 'options':
                admin.pages.options();
                break;
            default:
                // do nothing
                break;
        }
    });
})();
(function () {
    'use strict';

    admin.pages.categoriesAdmin = function () {

        $(document).ready(function(){
            var validator = $("#process_category").validate({
                rules: {
                    category_name: {
                        required: true,
                    }
                },
                messages: {
                    category_name: {
                        required: json_strings.validation.no_name,
                    }
                },
                errorPlacement: function(error, element) {
                    error.appendTo(element.parent('div'));
                },
            });
        });
    };
})();
(function () {
    'use strict';

    admin.pages.clientForm = function () {

        $(document).ready(function(){
            var form_type = $("#client_form").data('form-type');

            var validator = $("#client_form").validate({
                rules: {
                    name: {
                        required: true
                    },
                    username: {
                        required: true,
                        minlength: json_strings.character_limits.user_min,
                        maxlength: json_strings.character_limits.user_max,
                        alphanumericUsername: true
                    },
                    email: {
                        required: true,
                        email: true
                    },
                    max_file_size: {
                        required: {
                            param: true,
                            depends: function(element) {
                                return form_type != 'new_client_self';
                            }
                        },
                        digits: true
                    },
                    password: {
                        required: {
                            param: true,
                            depends: function(element) {
                                if (form_type == 'new_client' || form_type == 'new_client_self') {
                                    return true;
                                }
                                if (form_type == 'edit_client' || form_type == 'edit_client_self') {
                                    if ($.trim($("#password").val()).length > 0) {
                                        return true;
                                    }
                                }
                                return false;
                            }
                        },
                        minlength: json_strings.character_limits.password_min,
                        maxlength: json_strings.character_limits.password_max,
                        passwordValidCharacters: true
                    }
                },
                messages: {
                    name: {
                        required: json_strings.validation.no_name
                    },
                    username: {
                        required: json_strings.validation.no_user,
                        minlength: json_strings.validation.length_user,
                        maxlength: json_strings.validation.length_user,
                        alphanumericUsername: json_strings.validation.alpha_user
                    },
                    email: {
                        required: json_strings.validation.no_email,
                        email: json_strings.validation.invalid_email
                    },
                    max_file_size: {
                        digits: json_strings.validation.file_size
                    },
                    password: {
                        required: json_strings.validation.no_pass,
                        minlength: json_strings.validation.length_pass,
                        maxlength: json_strings.validation.length_pass,
                        passwordValidCharacters: json_strings.validation.alpha_pass
                    }
                },
                errorPlacement: function(error, element) {
                    error.appendTo(element.parent('div'));
                }
            });
        });
    };
})();
(function () {
    'use strict';

    admin.pages.clientsAccountsRequests = function () {

        $(document).ready(function(){
            $('.change_all').click(function(e) {
                e.preventDefault();
                var target = $(this).data('target');
                var check = $(this).data('check');
                $("input[data-client='"+target+"']").prop("checked",check).change();
                check_client(target);
            });
            
            $('.account_action').on("change", function() {
                if ( $(this).prop('checked') == false )  {
                    var target = $(this).data('client');
                    $(".membership_action[data-client='"+target+"']").prop("checked",false).change();
                }
            });
    
            $('.checkbox_toggle').change(function() {
                var target = $(this).data('client');
                check_client(target);
            });
    
            function check_client(client_id) {
                $("input[data-clientid='"+client_id+"']").prop("checked",true);
            }
        });
    };
})();
(function () {
    'use strict';
    
    admin.pages.dashboard = function () {
        
        $(document).ready(function(){
            // Nothing here yet
        });
    };
})();
(function () {
    'use strict';

    admin.pages.emailTemplates = function () {

        $(document).ready(function(){
            $('.load_default').click(function(e) {
                e.preventDefault();

                var file = jQuery(this).data('file');
                var textarea = jQuery(this).data('textarea');
                var accept = confirm(json_strings.translations.email_templates.confirm_replace);
                
                if ( accept ) {
                    $.ajax({
                        url: "emails/"+file,
                        cache: false,
                        success: function (data){
                            $('#'+textarea).val(data);
                        },
                        error: function() {
                            alert(json_strings.translations.email_templates.loading_error);
                        }
                    });
                }
            });
    
            $('.preview').click(function(e) {
                e.preventDefault();
                var type	= jQuery(this).data('preview');
                var url		= json_strings.uri.base+ 'email-preview.php?t=' + type;
                window.open(url, "previewWindow", "width=800,height=600,scrollbars=yes");
            });
        });
    };
})();
(function () {
    'use strict';

    admin.pages.fileEditor = function () {

        $(document).ready(function(){
            var validator = $("#files").validate({
                errorPlacement: function(error, element) {
                    error.appendTo(element.parent('div'));
                }
            });

            var file = $('input[name^="file"]');

            file.filter('input[name$="[name]"]').each(function() {
                $(this).rules("add", {
                    required: true,
                    messages: {
                        required: json_strings.validation.no_name
                    }
                });
            });


            $('.copy-all').on('click', function() {
                if ( confirm( json_strings.translations.upload_form.copy_selection ) ) {
                    var target = $(this).data('target');
                    var type = $(this).data('type');
                    var selector = $('#'+target);
                    var val;
    
                    var selected = new Array();
                    $(selector).find('option:selected').each(function() {
                        selected.push($(this).val().toString());
                    });

                    $('.chosen-select[data-type="'+type+'"]').not(selector).each(function() {
                        $(this).find('option').each(function() {
                            val = $(this).val().toString();
                            if (selected.includes(val)) {
                                $(this).prop('selected', 'selected');
                            } else {
                                $(this).removeAttr('selected');
                            }
                        });
                        $(this).trigger('chosen:updated');
                    });
                }

                return false;
            });
        });
    };
})();
(function () {
    'use strict';

    admin.pages.groupForm = function () {

        $(document).ready(function(){
            var validator = $("#group_form").validate({
                rules: {
                    name: {
                        required: true
                    },
                },
                messages: {
                    name: {
                        required: json_strings.validation.no_name
                    },
                },
                errorPlacement: function(error, element) {
                    error.appendTo(element.parent('div'));
                }
            });
        });
    };
})();
(function () {
    'use strict';

    admin.pages.importOrphans = function () {

        $(document).ready(function(){
            $("#import_orphans").submit(function() {
				var checks = $("td>input:checkbox").serializeArray(); 
				
				if (checks.length == 0) { 
					alert(json_strings.translations.select_one_or_more);
					return false; 
				} 
			});
			
			/**
			 * Only select the current file when clicking an "edit" button
			 */
			$('.btn-edit-file').click(function(e) {
				$('#select_all').prop('checked', false);
				$('td .select_file_checkbox').prop('checked', false);
				$(this).parents('tr').find('td .select_file_checkbox').prop('checked', true);
				$("#import_orphans").submit();
			});
        });
    };
})();
(function () {
    'use strict';

    admin.pages.install = function () {

        $(document).ready(function(){
            var validator = $("#install_form").validate({
                rules: {
                    install_title: {
                        required: true,
                    },
                    base_uri: {
                        required: true
                        // url: true // Does not work on localhost
                    },
                    admin_name: {
                        required: true,
                    },
                    admin_email: {
                        required: true,
                        email: true
                    },
                    admin_username: {
                        required: true,
                        minlength: json_strings.character_limits.user_min,
                        maxlength: json_strings.character_limits.user_max,
                        alphanumericUsername: true
                    },
                    admin_pass: {
                        required: true,
                        minlength: json_strings.character_limits.password_min,
                        maxlength: json_strings.character_limits.password_max,
                        passwordValidCharacters: true
                    },
                },
                messages: {
                    category_name: {
                        required: json_strings.validation.no_name,
                    }
                },
                errorPlacement: function(error, element) {
                    error.appendTo(element.parent('div'));
                },
            });
        });
    };
})();
(function () {
    'use strict';

    admin.pages.loginForm = function () {

        $(document).ready(function(){
            var validator = $("#login_form").validate({
                rules: {
                    username: {
                        required: true,
                    },
                    password: {
                        required: true,
                    },
                },
                messages: {
                    username: {
                        required: json_strings.validation.no_user,
                    },
                    password: {
                        required: json_strings.validation.no_pass,
                    }
                },
                errorPlacement: function(error, element) {
                    error.appendTo(element.parent('div'));
                },
                submitHandler: function(form) {
                    var button_text = json_strings.login.button_text;
                    var button_loading_text = json_strings.login.logging_in;
                    var button_redirecting_text = json_strings.login.redirecting;

                    var url = $(form).attr('action');
                    $('.ajax_response').html('').removeClass('alert alert-danger alert-success').slideUp();
                    $('#submit').html('<i class="fa fa-cog fa-spin fa-fw"></i><span class="sr-only"></span> '+button_loading_text+'...');
                    $.ajax({
                        cache: false,
                        type: "post",
                        url: url,
                        data: $(form).serialize(),
                        success: function(response)
                        {
                            var json = jQuery.parseJSON(response);
                            if ( json.status == 'success' ) {
                                $('#submit').html('<i class="fa fa-check"></i><span class="sr-only"></span> '+button_redirecting_text+'...');
                                $('#submit').removeClass('btn-primary').addClass('btn-success');
                                setTimeout('window.location.href = "'+json.location+'"', 1000);
                            }
                            else {
                                $('.ajax_response').addClass('alert alert-danger').slideDown().html(json.message);
                                $('#submit').html(button_text);
                            }
                        }
                    });

                    return false;
                }
            });
        });
    };
})();
(function () {
    'use strict';

    admin.pages.loginLdapForm = function () {

        $(document).ready(function(){
            var validator = $("#login_ldap_form").validate({
                rules: {
                    ldap_email: {
                        required: true,
                    },
                    ldap_password: {
                        required: true,
                    },
                },
                messages: {
                    ldap_email: {
                        required: json_strings.validation.no_email,
                    },
                    ldap_password: {
                        required: json_strings.validation.no_pass,
                    }
                },
                errorPlacement: function(error, element) {
                    error.appendTo(element.parent('div'));
                },
                submitHandler: function(form) {
                    var button_text = json_strings.login.button_text;
                    var button_loading_text = json_strings.login.logging_in;
                    var button_redirecting_text = json_strings.login.redirecting;

                    var url = $(form).attr('action');
                    $('.ajax_response').html('').removeClass('alert-danger alert-success').slideUp();
                    $('#ldap_submit').html('<i class="fa fa-cog fa-spin fa-fw"></i><span class="sr-only"></span> '+button_loading_text+'...');
                    $.ajax({
                        cache: false,
                        type: "post",
                        url: url,
                        data: $(form).serialize(),
                        success: function(response)
                        {
                            var json = jQuery.parseJSON(response);
                            if ( json.status == 'success' ) {
                                $('#ldap_submit').html('<i class="fa fa-check"></i><span class="sr-only"></span> '+button_redirecting_text+'...');
                                $('#ldap_submit').removeClass('btn-primary').addClass('btn-success');
                                setTimeout('window.location.href = "'+json.location+'"', 1000);
                            }
                            else {
                                $('.ajax_response').addClass('alert-danger').slideDown().html(json.message);
                                $('#ldap_submit').html("'"+button_text+"'");
                            }
                        }
                    });

                    return false;
                }
            });
        });
    };
})();
(function () {
    'use strict';

    admin.pages.options = function () {

        $(document).ready(function(){
            $('#allowed_file_types')
            .tagify()
            .on('add', function(e, tagName){
                console.log('added', tagName)
            });

            var validator = $("#options").validate({
                errorPlacement: function(error, element) {
                    error.appendTo(element.parent('div'));
                },
            });
        });
    };
})();
(function () {
    'use strict';

    admin.pages.resetPasswordEnterEmail = function () {

        $(document).ready(function(){
            var validator = $("#reset_password_enter_email").validate({
                rules: {
                    email: {
                        required: true,
                        email: true,
                    },
                },
                messages: {
                    email: {
                        required: json_strings.validation.no_email,
                        email: json_strings.validation.invalid_email
                    },
                },
                errorPlacement: function(error, element) {
                    error.appendTo(element.parent('div'));
                }
            });
        });
    };
})();
(function () {
    'use strict';

    admin.pages.resetPasswordEnterNew = function () {

        $(document).ready(function(){
            var validator = $("#reset_password_enter_new").validate({
                rules: {
                    password: {
                        required: true,
                        minlength: json_strings.character_limits.password_min,
                        maxlength: json_strings.character_limits.password_max,
                        passwordValidCharacters: true
                    }
                },
                messages: {
                    password: {
                        required: json_strings.validation.no_pass,
                        minlength: json_strings.validation.length_pass,
                        maxlength: json_strings.validation.length_pass,
                        passwordValidCharacters: json_strings.validation.alpha_pass
                    }
                },
                errorPlacement: function(error, element) {
                    error.appendTo(element.parent('div'));
                }
            });
        });
    };
})();
(function () {
    'use strict';

    admin.pages.uploadForm = function () {

        $(document).ready(function(){
            var file_ids = [];
            var errors = 0;
            var successful = 0;

            // Send a keep alive action every 1 minute
            setInterval(function(){
                var timestamp = new Date().getTime()
                $.ajax({
                    type:	'GET',
                    cache:	false,
                    url:	'includes/ajax-keep-alive.php',
                    data:	'timestamp='+timestamp,
                    success: function(result) {
                        var dummy = result;
                    }
                });
            },1000*60);

            var uploader = $('#uploader').pluploadQueue();

            $('#upload_form').on('submit', function(e) {
                if (uploader.files.length > 0) {
                    uploader.bind('StateChanged', function() {
                        if (uploader.files.length === (uploader.total.uploaded + uploader.total.failed)) {
                            var action = $('#upload_form').attr('action') + '?ids=' + file_ids.toString() + '&type=new';
                            $('#upload_form').attr('action', action);
                            if (successful > 0) {
                                if (errors == 0) {
                                    window.location = action;
                                } else {
                                    $(`
                                        <div class="alert alert-info">`+json_strings.translations.upload_form.some_files_had_errors+`</div>
                                        <a class="btn btn-wide btn-primary" href="`+action+`">`+json_strings.translations.upload_form.continue_to_editor+`</a>
                                    `).insertBefore( "#upload_form" );
                                }
                                return;
                            }
                            // $('#upload_form')[0].submit();
                        }
                    });

                    uploader.start();

                    $("#btn-submit").hide();
                    $(".message_uploading").fadeIn();

                    uploader.bind('Error', function(uploader, error) {
                        var obj = JSON.parse(error.response);
                        $(
                            `<div class="alert alert-danger">`+obj.error.filename+`: `+obj.error.message+`</div>`
                        ).insertBefore( "#upload_form" );
                        //console.log(obj);
                    });
        
                    uploader.bind('FileUploaded', function (uploader, file, info) {
                        var obj = JSON.parse(info.response);
                        file_ids.push(obj.info.id);
                        successful++;
                    });

                    return false;
                } else {
                    alert(json_strings.translations.upload_form.no_files);
                }

                return false;
            });

            window.onbeforeunload = function (e) {
                var e = e || window.event;

                console.log('state? ' + uploader.state);

                // if uploading
                if(uploader.state === 2) {
                    //IE & Firefox
                    if (e) {
                        e.returnValue = json_strings.translations.upload_form.leave_confirm;
                    }

                    // For Safari
                    return json_strings.translations.upload_form.leave_confirm;
                }

            };

        });
    };
})();
(function () {
    'use strict';

    admin.pages.userForm = function () {

        $(document).ready(function(){
            var form_type = $("#user_form").data('form-type');

            var validator = $("#user_form").validate({
                rules: {
                    name: {
                        required: true
                    },
                    username: {
                        required: true,
                        minlength: json_strings.character_limits.user_min,
                        maxlength: json_strings.character_limits.user_max,
                        alphanumericUsername: true
                    },
                    email: {
                        required: true,
                        email: true
                    },
                    level: {
                        required: true
                    },
                    max_file_size: {
                        required: true,
                        digits: true
                    },
                    password: {
                        required: {
                            param: true,
                            depends: function(element) {
                                if (form_type == 'new_user') {
                                    return true;
                                }
                                if (form_type == 'edit_user' || form_type == 'edit_user_self') {
                                    if ($.trim($("#password").val()).length > 0) {
                                        return true;
                                    }
                                }
                                return false;
                            }
                        },
                        minlength: json_strings.character_limits.password_min,
                        maxlength: json_strings.character_limits.password_max,
                        passwordValidCharacters: true
                    }
                },
                messages: {
                    name: {
                        required: json_strings.validation.no_name
                    },
                    username: {
                        required: json_strings.validation.no_user,
                        minlength: json_strings.validation.length_user,
                        maxlength: json_strings.validation.length_user,
                        alphanumericUsername: json_strings.validation.alpha_user
                    },
                    email: {
                        required: json_strings.validation.no_email,
                        email: json_strings.validation.invalid_email
                    },
                    level: {
                        required: json_strings.validation.no_role
                    },
                    max_file_size: {
                        digits: json_strings.validation.file_size
                    },
                    password: {
                        required: json_strings.validation.no_pass,
                        minlength: json_strings.validation.length_pass,
                        maxlength: json_strings.validation.length_pass,
                        passwordValidCharacters: json_strings.validation.alpha_pass
                    }
                },
                errorPlacement: function(error, element) {
                    error.appendTo(element.parent('div'));
                }
            });
        });
    };
})();
/**
 * Apply bulk actions
 */
(function () {
    'use strict';

    admin.parts.bulkActions = function () {

        $(document).ready(function(e) {
            $(".batch_actions").on('submit', function(e) {
                var checks = $("td>input:checkbox").serializeArray();
                var action = $('#action').val();
                if (action != 'none') {
                        // Generic actions
                        if (action == 'delete') {
                            if (checks.length == 0) {
                                alert(json_strings.translations.select_one_or_more);
                                return false;
                            }
                            else {
                                var _formatted = sprintf(json_strings.translations.confirm_delete, checks.length);
                                if (!confirm(_formatted)) {
                                    e.preventDefault();
                                }
                            }
                        }

                        // Activities log actions
                        if (action == 'log_clear') {
                            var msg = json_strings.translations.confirm_delete_log;
                            if (!confirm(msg)) {
                                e.preventDefault();
                            }
                        }

                        if (action == 'log_download') {
                            e.preventDefault();
                            $(document).psendmodal();
                            Cookies.set('log_download_started', 0, { expires: 100 });
                            setTimeout(check_log_download_cookie, 1000);

                            $('.modal_content').html(`<p class="loading-icon">
                                                        <img src="`+json_strings.uri.assets_img+`/loading.svg" alt="Loading" /></p>
                                                        <p class="lead text-center text-info">`+json_strings.translations.download_wait+`</p>
                                                    `);
                            $('.modal_content').append('<iframe src="'+json_strings.uri.base+'includes/actions.log.export.php?format=csv"></iframe>');

                            return false;
                        }

                        // Manage files actions
                        if (action == 'unassign') {
                            var _formatted = sprintf(json_strings.translations.confirm_unassign, checks.length);
                            if (!confirm(_formatted)) {
                                e.preventDefault();
                            }
                        }

                        // Templates
                        if (action == 'zip') {
                            e.preventDefault();
                            var checkboxes = $("td>input:checkbox:checked").serializeArray();
                            if (checkboxes.length > 0) {
                                $(document).psendmodal();
    
                                Cookies.set('download_started', 0, { expires: 100 });
                                setTimeout(check_download_cookie, 1000);
                                $('.modal_content').html(`<p class="loading-icon"><img src="`+json_strings.uri.assets_img+`/loading.svg" alt="Loading" /></p>
                                                            <p class="lead text-center text-info">`+json_strings.translations.download_wait+`</p>
                                                            <p class="text-center text-info">`+json_strings.translations.download_long_wait+`</p>
                                                        `);
                                $.ajax({
                                    method: 'GET',
                                    url: json_strings.uri.base + 'process.php',
                                    data: { do:"return_files_ids", files:checkboxes }
                                }).done( function(rsp) {
                                    var url = json_strings.uri.base + 'process.php?do=download_zip&files=' + rsp;
                                    $('.modal_content').append("<iframe id='modal_zip'></iframe>");
                                    $('#modal_zip').attr('src', url);
                                });
                                return false;
                            }
                        }
                }
                else {
                    return false;
                }
            });
        });
    };
})();
(function () {
    'use strict';

    admin.parts.downloadCookieHandler = function () {
        $(document).ready(function() {
                /**
             * CLOSE THE ZIP DOWNLOAD MODAL
             * Solution to close the modal. Suggested by remez, based on
             * https://stackoverflow.com/questions/29532788/how-to-display-a-loading-animation-while-file-is-generated-for-download
             */
            var downloadTimeout;
            window.check_download_cookie = function() {
                if (Cookies.get("download_started") == 1) {
                    Cookies.set("download_started", "false", { expires: 100 });
                    remove_modal();
                } else {
                    downloadTimeout = setTimeout(check_download_cookie, 1000);
                }
            };

            // Close the log CSV download modal
            var logdownloadTimeout;
            window.check_log_download_cookie = function() {
                if (Cookies.get("log_download_started") == 1) {
                    Cookies.set("log_download_started", "false", { expires: 100 });
                    remove_modal();
                } else {
                    logdownloadTimeout = setTimeout(check_log_download_cookie, 1000);
                }
            };
        });
    }
})();
(function () {
    'use strict';

    admin.parts.filePreviewModal = function () {

        $(document).ready(function(e) {
            // Append modal
            var modal_layout = `<div id="previewModal" class="modal fade" tabindex="-1" role="dialog">
                <div class="modal-dialog modal-lg">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title"></h5>
                            <button type="button" class="close" data-dismiss="modal" aria-hidden="true">×</button>
                        </div>
                        <div class="modal-body">
                        </div>
                        <div class="modal-footer">
                        </div>
                    </div>
                </div>
            </div>`;
            $('body').append(modal_layout);

            // Button trigger
            $('.get-preview').on('click', function(e) {
                e.preventDefault();
                var url = $(this).data("url"); 
                var content = '';

                $.ajax({
                    method: "GET",
                    url: url,
                    cache: false,
                }).done(function(response) {
                    var obj = JSON.parse(response);
                    switch (obj.type) {
                        case 'video':
                            content = `
                                <div class="embed-responsive embed-responsive-16by9">
                                    <video controls>
                                        <source src="`+obj.file_url+`" format="`+obj.mime_type+`">
                                    </video>
                                </div>`;
                            break;
                        case 'audio':
                            content = `
                                <audio controls>
                                    <source src="`+obj.file_url+`" format="`+obj.mime_type+`">
                                </audio>`;
                            break;
                        case 'pdf':
                            content = `
                                <div class="embed-responsive embed-responsive-16by9">
                                    <iframe src="`+obj.file_url+`"></iframe>
                                </div>
                            `;
                            break;
                        case 'image':
                            content = `<img src="`+obj.file_url+`" class="img-responsive">`
                            break;
                        }
                    $('.modal-header h5').html(obj.name);
                    $('.modal-body').html(content);
                    // show modal
                    $('#previewModal').modal('show');
                }).fail(function(response) {
                    alert(json_strings.translations.preview_failed);
                }).always(function() {
                });    
            });

            // Remove content when closing modal
            $('#previewModal').on('hidden.bs.modal', function (e) {
                $('.modal-body').html('');
            })
        });
    };
})();
/**
 * Very simple custom modal dialog
 */
$.fn.psendmodal = function() {
	var modal_structure = `<div class="modal_overlay"></div>
							<div class="modal_psend">
								<div class="modal_title">
									<span>&nbsp;</span>
									<a href="#" class="modal_close">&times;</a>
								</div>
								<div class="modal_content"></div>
							</div>`;

	$('body').append(modal_structure);
	show_modal();

	function show_modal() {
		$('.modal_overlay').stop(true, true).fadeIn();
		$('.modal_psend').stop(true, true).fadeIn();
	}

	window.remove_modal = function() {
		$('.modal_overlay').stop(true, true).fadeOut(500, function() { $(this).remove(); });
		$('.modal_psend').stop(true, true).fadeOut(500, function() { $(this).remove(); });
		return false;
	}

	$(".modal_close").click(function(e) {
		e.preventDefault();
		remove_modal();
	});

	$(".modal_overlay").click(function(e) {
		e.preventDefault();
		remove_modal();
	});

	$(document).keyup(function(e) {
		if (e.keyCode == 27) { // Esc
			remove_modal();
		}
	});
};

(function () {
    'use strict';

    admin.parts.jqueryValidationCustomMethods = function () {

        $(document).ready(function(){
            jQuery.validator.addMethod("alphanumericUsername", function(value, element) {
                return this.optional(element) || /^[\w.]+$/i.test(value);
            }, json_strings.validation.alpha_user);

            jQuery.validator.addMethod("passwordValidCharacters", function(value, element) {
                return this.optional(element) || /^[0-9a-zA-Z`!"?$%\^&*()_\-+={\[}\]:;@~#|<,>.'\/\\]+$/.test(value);
            }, json_strings.validation.alpha_user);
        });
    };
})();
(function () {
    'use strict';

    admin.parts.loadCKEditor = function () {

        $(document).ready(function() {
            if (document.querySelector('textarea.ckeditor') !== null) {
                // CKEditor
                ClassicEditor
                    .create( document.querySelector( '.ckeditor' ), {
                        removePlugins: [ 'Heading', 'Link' ],
                        toolbar: [ 'bold', 'italic', 'bulletedList', 'numberedList', 'blockQuote' ]
                    })
                    .then( editor => {
                        window.editor = editor;
                    } )
                    .catch( error => {
                        console.error( 'There was a problem initializing the editor.', error );
                    } );
            }
        });
    }
})();
(function () {
    'use strict';

    admin.parts.main = function () {

        $(document).ready(function() {
            $(document).ready(function() {
                $('input:first').focus();
            });

            $('.confirm_generic').on('click', function(e) {
                if (!confirm(json_strings.translations.confirm_generic)) {
                    e.preventDefault();
                }
            });
    
            // Dismiss messages
            $('.message .close').on('click', function () {
                $(this).closest('.message').transition('fade');
            });
        
            window.resizeChosen = function() {
                $(".chosen-container").each(function() {
                    $(this).attr('style', 'width: 100%');
                });
            }
            
            window.prepare_sidebar = function() {
                var window_width = jQuery(window).width();
                if ( window_width < 769 ) {
                    $('.main_menu .active .dropdown_content').hide();
                    $('.main_menu li').removeClass('active');
            
                    if ( !$('body').hasClass('menu_contracted') ) {
                        $('body').addClass('menu_contracted');
                    }
                }
            }

            /** Main side menu */
            prepare_sidebar();

            resizeChosen();

            $('.main_menu > li.has_dropdown .nav_top_level').click(function(e) {
                e.preventDefault();

                var parent = $(this).parents('.has_dropdown');
                if ( $(parent).hasClass('active') ) {
                    $(parent).removeClass('active');
                    $(parent).find('.dropdown_content').stop().slideUp();
                }
                else {
                    if ( $('body').hasClass('menu_contracted') ) {
                        $('.main_menu li').removeClass('active');
                        $('.main_menu').find('.dropdown_content').stop().slideUp(100);
                    }
                    $(parent).addClass('active');
                    $(parent).find('.dropdown_content').stop().slideDown();
                }
            });

            $('.toggle_main_menu').click(function(e) {
                e.preventDefault();

                var window_width = jQuery(window).width();
                if ( window_width > 768 ) {
                    $('body').toggleClass('menu_contracted');
                    if ( $('body').hasClass('menu_contracted') ) {
                        Cookies.set("menu_contracted", 'true', { expires: 365 } );
                        $('.main_menu li').removeClass('active');
                        $('.main_menu').find('.dropdown_content').stop().hide();
                    }
                    else {
                        Cookies.set("menu_contracted", 'false', { expires: 365 } );
                        $('.current_nav').addClass('active');
                        $('.current_nav').find('.dropdown_content').stop().show();
                    }
                }
                else {
                    $('body').toggleClass('menu_hidden');
                    $('.main_menu li').removeClass('active');

                    if ( $('body').hasClass('menu_hidden') ) {
                        //Cookies.set("menu_hidden", 'true', { expires: 365 } );
                        $('.main_menu').find('.dropdown_content').stop().hide();
                    }
                    else {
                        //Cookies.set("menu_hidden", 'false', { expires: 365 } );
                    }
                }
            });

            /** Used on the public link modal on both manage files and the upload results */
            $(document).on('click', '.public_link_copy', function(e) {
                $(this).select();
                if ( document.execCommand("copy") ) {
                    var copied = '.copied';
                }
                else {
                    var copied = '.copied_not';
                }
                $(this).parents('.public_link_modal').find(copied).stop().fadeIn().delay(2000).fadeOut();
                $(this).mouseup(function() {
                    $(this).unbind("mouseup");
                    return false;
                });
            });


            /** Common for all tables */
            $("#select_all").click(function(){
                var status = $(this).prop("checked");
                /** Uncheck all first in case you used pagination */
                $("tr td input[type=checkbox].batch_checkbox").prop("checked",false);
                $("tr:visible td input[type=checkbox].batch_checkbox").prop("checked",status);
            });

            if ( $.isFunction($.fn.footable) ) {
                $('.footable').footable().find('> tbody > tr:not(.footable-row-detail):nth-child(even)').addClass('odd');
            }
            
            /** Pagination */
            $(".go_to_page").on("click", "button", function() {
                var _page = $('.go_to_page #page_number').data('link');
                var _page_no = parseInt($('.go_to_page #page_number').val());
                if (typeof _page_no == 'number'){
                    _page = _page.replace('_pgn_', _page_no);
                }
                window.location.href = _page;
            });

            /** Password generator */
            var hdl = new Jen(true);
            hdl.hardening(true);

            $('.btn_generate_password').click(function(e) {
                var target = $(this).parents('.form-group').find('.password_toggle');
                var min_chars = $(this).data('min');
                var max_chars = $(this).data('max');
                $(target).val( hdl.password( min_chars, max_chars ) );
            });


            /** File editor */
            if ( $.isFunction($.fn.datepicker) ) {
                $('.date-container .date-field').datepicker({
                    format			: 'dd-mm-yyyy',
                    autoclose		: true,
                    todayHighlight	: true
                });
            }

            $('.add-all').on('click', function() {
                var target = $(this).data('target');
                var selector = $('#'+target);
                $(selector).hide();
                //var selector = $(this).previous('.select_' + type);
                $(selector).find('option').each(function() {
                    $(this).prop('selected', true);
                });
                $(selector).trigger('chosen:updated');
                return false;
            });

            $('.remove-all').on('click', function() {
                var target = $(this).data('target');
                var selector = $('#'+target);
                //var selector = $(this).previous('.select_' + type);
                $(selector).find('option').each(function() {
                    $(this).prop('selected', false);
                });
                $(selector).trigger('chosen:updated');
                return false;
            });


            /** Misc */
            $('button').on('click', function() {
                $(this).blur();
            });

            /**
             * Modal: show a public file's URL
             */
            $('body').on('click', '.public_link', function(e) {
                $(document).psendmodal();
                var type = $(this).data('type');
                var public_url = $(this).data('public-url');

                if ( type == 'group' ) {
                    var link_base = json_strings.uri.public_group + '?';
                    var note_text = json_strings.translations.public_group_note;
                }
                else if ( type == 'file' ) {
                    var link_base = json_strings.uri.public_download + '?';
                    var note_text = json_strings.translations.public_file_note;
                }

                var content =  '<div class="public_link_modal">'+
                                    '<strong>'+json_strings.translations.copy_click_select+'</strong>'+
                                    '<div class="copied">'+json_strings.translations.copy_ok+'</div>'+
                                    '<div class="copied_not">'+json_strings.translations.copy_error+'</div>'+
                                    '<div class="form-group">'+
                                        '<textarea class="input-large public_link_copy form-control" rows="4" readonly>' + public_url + '</textarea>'+
                                    '</div>'+
                                    '<span class="note">' + note_text + '</span>'+
                                '</div>';
                var title 	= json_strings.translations.public_url;
                $('.modal_title span').html(title);
                $('.modal_content').html(content);
            });
            
            // Edit file + upload form
            if ( $.isFunction($.fn.chosen) ) {
                $('.chosen-select').chosen({
                    no_results_text	: json_strings.translations.no_results,
                    width			: "100%",
                    search_contains	: true
                });
            }
        });

        /**
         * Event: Scroll
         */
        jQuery(window).scroll(function(event) {
        });

        /**
         * Event: Resize
         */
        jQuery(window).resize(function($) {
            prepare_sidebar();

            resizeChosen();
        });
    };
})();
(function () {
    'use strict';

    admin.parts.passwordVisibilityToggle = function () {

        /**
         * Adapted from http://jsfiddle.net/Ngtp7/2/
         */
        $(function () {
            $(".password_toggle").each(function (index, input) {
                var $input = $(input);
                var $container	= $($input).next('.password_toggle');
                $(".password_toggler button").click(function () {
                    var change = "";
                    var icon = $(this).find('i');
                    if ($(this).hasClass('pass_toggler_show')) {
                        $(this).removeClass('pass_toggler_show').addClass('pass_toggler_hide');
                        $(icon).removeClass('glyphicon glyphicon-eye-open').addClass('glyphicon glyphicon-eye-close');
                        change = "text";
                    } else {
                        $(this).removeClass('pass_toggler_hide').addClass('pass_toggler_show');
                        $(icon).removeClass('glyphicon glyphicon-eye-close').addClass('glyphicon glyphicon-eye-open');
                        change = "password";
                    }
                    var rep = $("<input type='" + change + "' />")
                        .attr("id", $input.attr("id"))
                        .attr("name", $input.attr("name"))
                        .attr('class', $input.attr('class'))
                        .attr('maxlength', $input.attr('maxlength'))
                        .val($input.val())
                        .insertBefore($input);
                    $input.remove();
                    $input = rep;
                }).insertBefore($container);
            });
            return false;
        });
    };
})();
(function () {
    'use strict';
    
    admin.parts.widgetActionLog = function () {
        
        $(document).ready(function(){
            // Action log
            function ajax_widget_log( action ) {
                var target = $('#log_container');
                var select = $('#widget_actions_log_change');
                var list = $('<ul/>').addClass('none');

                target.html('');
                select.attr('disabled', 'disabled');
                $('#widget_actions_log .loading-icon').removeClass('none');

                $.ajax({
                    url: json_strings.uri.widgets+'ajax/actions-log.php',
                    data: { action:action },
                    cache: false,
                }).done(function(data) {
                    var obj = JSON.parse(data);
                    //console.log(obj);
                    $.each(obj.actions, function(i, item) {
                        var line = [];
                        var parts = {
                            part1: item.part1,
                            action: item.action,
                            part2: item.part2,
                            part3: item.part3,
                            part4: item.part4,
                        }

                        for (const key in parts) {
                            if (parts[key]) {
                                line.push('<span class="item_'+key+'">'+parts[key]+'</span>');
                            }
                        };

                        var icon;
                        switch (item.type) {
                            case 'system': icon = 'cog'; break;
                            case 'auth': icon = 'lock'; break;
                            case 'files': icon = 'file'; break;
                            case 'clients': icon = 'address-card'; break;
                            case 'users': icon = 'users'; break;
                            case 'groups': icon = 'th-large'; break;
                            case 'categories': icon = 'object-group'; break;
                            default: icon = 'cog'; break;
                        }
                        line = line.join(' ');
                        var li = $('<li/>')
                            .appendTo(list)
                            .html(`
                                <div class="date">
                                    <span>`+
                                        item.timestamp+`
                                    </span>
                                    <i class="fa fa-`+icon+`" aria-hidden="true"></i>
                                </div>
                                <div class="action">`+
                                    item.formatted+`
                                </div>
                            `);
                    });
                    //console.log(list);
                    target.append(list);
                    list.slideDown();
                }).fail(function(data) {
                    target.html(json_strings.translations.failed_loading_resource);
                }).always(function() {
                    $('#widget_actions_log .loading-icon').addClass('none');
                });

                $(select).removeAttr('disabled');
            }

            // Action log
            $('#widget_actions_log_change').on('change', function(e) {
                var action = $('#widget_actions_log_change option').filter(':selected').val()
                ajax_widget_log(action);
            });

			ajax_widget_log();
        });
    };
})();
(function () {
    'use strict';
    
    admin.parts.widgetNews = function () {
        
        $(document).ready(function(){
            // Action log
            function ajax_widget_news( action ) {
                var target = $('#news_container');
                var list = $('<ul/>').addClass('none home_news list-unstyled');

                target.html('');
                $('#widget_projectsend_news .loading-icon').removeClass('none');

                $.ajax({
                    url: json_strings.uri.widgets+'ajax/news.php',
                    cache: false,
                }).done(function(data) {
                    var obj = JSON.parse(data);
                    console.log(obj);
                    $.each(obj.items, function(i, item) {
                        var li = $('<li/>')
                            .appendTo(list)
                            .html(`
                                <span class="date">`+item.date+`</span>
                                    <a href="`+item.url+`" target="_blank">
                                        <h5>`+item.title+`</h5>
                                    </a>
                                <p>`+item.content+`</p>
                            `);
                    });
                    //console.log(list);
                    target.append(list);
                    list.slideDown();
                }).fail(function(data) {
                    target.html(json_strings.translations.failed_loading_resource);
                }).always(function() {
                    $('#widget_projectsend_news .loading-icon').addClass('none');
                });
            }

			ajax_widget_news();
        });
    };
})();

(function () {
    'use strict';
    
    admin.parts.widgetStatistics = function () {
        
        $(document).ready(function(){
            var chart;

            // Statistics chart
            function ajax_widget_statistics(days) {
                var _chart_container = $('#widget_statistics #chart_container');
                _chart_container.find('canvas').remove();
                $('#widget_statistics .loading-icon').removeClass('none');
                if (chart) {
                    chart.destroy();
                }
                $.ajax({
                    url: json_strings.uri.widgets+'ajax/statistics.php',
                    data: { days:days },
                    cache: false,
                }).done(function(data) {
                    var obj = JSON.parse(data);
                    _chart_container.append('<canvas id="chart_statistics"><canvas>');
                    chart = new Chart(document.getElementById('chart_statistics'), {
                        type: 'line',
                        data: obj.chart,
                        options: {
                            responsive: true,
                            title: {
                                display: false
                            },
                            tooltips: {
                                mode: 'index',
                                intersect: false
                            },
                            scales: {
                                xAxes: [{
                                    display: true,
                                }],
                                yAxes: [{
                                    display: true
                                }]
                            },
                            elements: {
                                line: {
                                    tension: 0
                                }
                            }
                        }
                    });
                }).fail(function(data) {
                    _chart_container.html(json_strings.translations.failed_loading_resource);
                }).always(function() {
                    $('#widget_statistics .loading-icon').addClass('none');
                });
    
                return;
            }

            // Statistics
            $('#widget_statistics button.get_statistics').on('click', function(e) {
                if ($(this).hasClass('active')) {
                    return false;
                }
                else {
                    var days = $(this).data('days');
                    $('#widget_statistics button.get_statistics').removeClass('btn-inverse active');
                    $(this).addClass('btn-inverse active');
                    ajax_widget_statistics(days);
                }
            });

			ajax_widget_statistics(15);
        });
    };
})();
//# sourceMappingURL=app.js.map
