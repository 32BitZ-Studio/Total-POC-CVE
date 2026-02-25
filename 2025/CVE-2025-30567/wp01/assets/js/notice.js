(($) => {
    $(document).ready(function () {
        $('.wp01-notice-dismiss-btn-forever').on('click', function () {

            $.get(
                ajaxurl,
                {
                    action: 'wp01_dismiss_notice_forever'
                },
                console.log
            );

            $(this).closest('.notice').slideUp();
        });

        $('.wp01-notice-dismiss-btn-for-week').on('click', function () {

            $.get(
                ajaxurl,
                {
                    action: 'wp01_dismiss_notice_for_week'
                },
                console.log
            );

            $(this).closest('.notice').slideUp();
        });
    });
})(jQuery);