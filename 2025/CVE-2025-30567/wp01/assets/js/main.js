(($) => {
    // replace-code start
    $(document).ready(function () {
        var all_replace_btns = $('.code-replace-btn'),
            replace_value,
			btnWord_open = $('#open_word').text(),
			btnWord_close = $('#close_word').text();

        var global_loader = document.createElement('div');
        global_loader.className = 'global-loader button updating-message';

        for (var i = 0; i < all_replace_btns.length; i++) {

            all_replace_btns[i].addEventListener('click', function (event) {

                // getting subling of needed td with "replace code"
                replace_tr = event.target.parentElement.parentElement.nextSibling;
                replace_tr_height = replace_tr.querySelector('.inner-code-replace-content').getBoundingClientRect().height - 5;
//
                if (replace_tr.classList.contains('active')) {
                    replace_tr.classList.remove('active');
                    event.target.classList.remove('active');
                    event.target.innerHTML = btnWord_open;
                    replace_tr.querySelector('span').style.height = 0;
                } else {
                    replace_tr.classList.add('active');
                    event.target.classList.add('active');
                    event.target.innerHTML = btnWord_close;
                    replace_tr.querySelector('span').style.height = replace_tr_height + 'px';
                }

            })
        }

        // replace-code end
        let current = '#step-1';

        if (document.location.hash) {
            current = document.location.hash;
        }

// start new

        // Backup download
        $('body').on('submit', '.ajax-file-download', function (e) {
            e.preventDefault();
            let url = $(this).attr('action');
            let fileName = $(this).find('input[name=filename]').val();
            let path = $(this).find('input[name=path]').val();
            $.post(url, {action: 'wp01_generate_zip_archive', target: fileName, path: path}, function (response) {
                var link = document.createElement('a');
                document.body.appendChild(link);
                link.href=response.url;
                link.click();
            });
        });
        // 

// end new

        $('.wp01-langSelect')
            .on('change', function () {
                setCookie('wp01-lang', $(this).val());
                $('body').append(global_loader);
                let url = $('.ajax-mail').attr('action');
                $.get(url, {action: 'wp01_change_language'}, function (response) {
                    if ('1' === response) {
                        document.location.reload();
                    }
                });
            });

        $('section.step').each(function (i) {

            let select = $('.steps-controller'),
                name = $(this).attr('id'),
                title = (i + 1) + '. ' + $(this).find('h1, h2, h3, h4, h5, h6').find('.name').first().text(),
                checked = '#' + $(this).attr('id') === current ? 'selected' : '';

            if (checked) {
                $(this).show();
            } else {
                $(this).hide();
            }

            select.append('<option value="' + name + '" ' + checked + '>' + title + '</option>');
        });

        $('.steps-controller').on('change', function () {

            let step = $(this).val(),
                next = $('#' + step);

            document.location.hash = '#' + step;

            $('.step').stop().slideUp();
            next.stop().slideDown(300, () => $(next).css('height', 'auto'));

            $('.steps-controller').val(step);
            $('.button-next-step').css('opacity', +next.next().is('.step'));
            $('.button-prev-step').css('opacity', +next.prev().is('.step'));
        }).trigger('change');

        $('.button-next-step').on('click', function () {

            let step = $('.steps-controller option:selected').next().val();

            if (!step) return;

            $('.steps-controller').val(step).trigger('change');
        });

        $('.button-prev-step').on('click', function () {

            let step = $('.steps-controller option:selected').prev().val();

            if (!step) return;

            $('.steps-controller').val(step).trigger('change');
        });

        $('.collapse-toggler').on('click', function () {

            let collapse = $($(this).attr('data-target'));

            if (!collapse.is('.collapse')) collapse = $(this).closest('.collapse');

            collapse.toggleClass('collapsed');
            collapse.find('.collapse-body').stop().slideToggle();
        });

        $('[href^="#"]').click(function (e) {
            e.preventDefault();

            let id = $(this).attr('href');

            if (id === '#') return false;

            let scroll = $(id).offset().top;

            $('html,body').animate({
                'scrollTop': scroll
            }, 1000);

            return false;
        });


        // Install plugin
        $('body').on('click', '.install-now', function (e) {
            e.preventDefault();
            var button = $(this);
            var slug = button.attr('data-slug');
            var url = button.attr('href');
            var redirect = $(button).data('redirect');
            button.text(wp.updates.l10n.installing);
            button.addClass('updating-message');
            wp.updates.installPlugin(
                {
                    slug: slug,
                    success: function () {
                        button.text(WPO1.activate);
                        button.toggleClass('install-now activate-now updating-message button-primary button-green');
                    }
                }
            );
        });


        $('body').on('click', '.activate-now', function (e) {
            e.preventDefault();

            var button = $(this);
            var url = button.attr('href');
            var redirect = button.attr('data-redirect');

            button.text(WPO1.activating);
            activatePlugin(url, redirect);

            return false;
        });


        $('body').on('click', '.modal-activate', function (e) {
			var actionIsntAllowed = $('#actionIsntAllowed').text();
			console.log(actionIsntAllowed);

            e.preventDefault();
            tb_show( actionIsntAllowed, '/?TB_inline&inlineId=my-modal-id&width=600&height=550' );

            $('#modal_plugin_activate').attr('href', $(this).attr('href'));

            return false;

        });


        $('body').on('click', '.deactivate-now', function (e) {
            e.preventDefault();
            var button = $(this);
            var url = button.attr('href');
            var redirect = button.attr('data-redirect');
            button.text(WPO1.deactivating);
            activatePlugin(url, redirect);
        });


        $('body').on('click', '.wp01-open-plugin-details-modal', function (e) {
            e.preventDefault();
            var button = $(this);
            var url = button.attr('href');
            var redirect = button.attr('data-redirect');
            button.addClass('updating-message');
            button.text(WPO1.activating + '...');
            activatePlugin(url, redirect);
        });


        $('body').on('submit', '.ajax-mail', function (event) {
            var elem = $(this);
	        var formArr = $(this).serializeArray();
            var data = $(this).serialize();

            // Оставновки события submit
            event.preventDefault();

            // Блокируем все поля и кнопки
            $('input, textarea, button', this).attr('disabled', 'disabled');

            // Отправка ajax запроса
            $.post(
                elem.attr('action'),
                {
                    action: 'wp01_callback_form',
                    data: data
                },
                function (response) {
                    if (1 == response) {

                        for (var i = 0; i < formArr.length; i++) {
                            if (formArr[i].name !== 'form') {
                                $('[name="' + formArr[i].name + '"]').val('');
                            }
                        }

                        alert('Спасибо! Мы свяжемся с вами в ближайшее время.');
                    } else {
                        alert('Ошибка отправки! Пожалуйста, сообщите об этом создателю плагина.');
                    }

                    // Разблокируем поля
                    $('input, textarea, button').removeAttr('disabled');
                }
            );

        });

        $(document).on('wp-plugin-installing', function (e) {
            // start install
            document.querySelector('body').appendChild(global_loader);
        });

        $(document).on('wp-plugin-install-success', function () {
            // end install
            setTimeout(function () {
                location.reload()
            }, 100)
        });

        $('.loader-btn').on('click', function () {
            if (this.classList.contains('thickbox') !== true && this.classList.contains('analog-options') !== true)
                document.querySelector('body').appendChild(global_loader);
        });

        $('#modal_plugin_close').on('click', function (e) {
            e.preventDefault();

            tb_remove();

            return false;
        });

        $('.settings').on('click', '.settings-btn', function () {
            $(this).parent().find('.settings-wrap').show();
        });

        $('.settings-close').on('click', function () {
            $('.settings-wrap').hide();
        });

        $(document).on('click', function (e) {
            if (!$(e.target).closest('.settings').length)
                $('.settings-wrap').hide();
        });

        $('body').on('submit', '.settings', function (event) {
            var elem = $(this);
            var formArr = $(this).serializeArray();
            var data = $(this).serialize();

            // Оставновки события submit
            event.preventDefault();

            // Блокируем все поля и кнопки
            $('input, textarea, button, select', this).attr('disabled', 'disabled');

            // Отправка ajax запроса
            $.post(
                elem.attr('action'),
                {
                    action: 'wp01_save_settings',
                    data: data
                },
                function (response) {
                    if (1 == response) {
                        window.location.reload();
                    } else {
                        alert('Ошибка отправки! Пожалуйста, сообщите об этом создателю плагина.');
                    }

                    // Разблокируем поля
                    $('input, textarea, button, select').removeAttr('disabled');
                }
            );

        });



    });

})(jQuery);


function activatePlugin(url, redirect) {
    if (typeof url === 'undefined' || !url) {
        return;
    }
    jQuery.ajax(
        {
            async: true,
            type: 'GET',
            url: url,
            success: function () {
                // Reload the page.
                if (typeof (redirect) !== 'undefined' && redirect !== '') {
                    window.location.replace(redirect);
                    location.reload();
                } else {
                    location.reload();
                }
            },
            error: function (jqXHR, exception) {
                var msg = '';
                if (jqXHR.status === 0) {
                    msg = 'Not connect.\n Verify Network.';
                } else if (jqXHR.status === 404) {
                    msg = 'Requested page not found. [404]';
                } else if (jqXHR.status === 500) {
                    msg = 'Internal Server Error [500].';
                } else if (exception === 'parsererror') {
                    msg = 'Requested JSON parse failed.';
                } else if (exception === 'timeout') {
                    msg = 'Time out error.';
                } else if (exception === 'abort') {
                    msg = 'Ajax request aborted.';
                } else {
                    msg = 'Uncaught Error.\n' + jqXHR.responseText;
                }
                console.log(msg);
            },
        }
    );
}

function getCookie(name) {
    let matches = document.cookie.match(new RegExp(
        "(?:^|; )" + name.replace(/([\.$?*|{}\(\)\[\]\\\/\+^])/g, '\\$1') + "=([^;]*)"
    ));
    return matches ? decodeURIComponent(matches[1]) : undefined;
}

function setCookie(name, value, options = {}) {

    options = Object.assign({path: '/'}, options);

    if (options.expires && options.expires.toUTCString) {
        options.expires = options.expires.toUTCString();
    }

    let updatedCookie = encodeURIComponent(name) + "=" + encodeURIComponent(value);

    for (let optionKey in options) {
        updatedCookie += "; " + optionKey;
        let optionValue = options[optionKey];
        if (optionValue !== true) {
            updatedCookie += "=" + optionValue;
        }
    }

    document.cookie = updatedCookie;
}
