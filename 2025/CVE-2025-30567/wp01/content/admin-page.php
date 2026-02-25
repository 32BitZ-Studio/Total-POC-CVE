<?php

if (!defined('ABSPATH')) {
    die('Don\'t hack please!');
}

add_thickbox();

include WP01__PLUGIN_DIR . 'content/' . WP01::get_language_dir() . '/head.php';

?>

<div class="wrap">
    <h2><?php _e('Улучшения от WP01', 'WP01') ?></h2>

    <div class="">
        <div class="call-to-action">
            <div class="left">
                <div class="notice notice-warning inline">
                    <p>
                        <strong><?php _e('Online версия инструкций:', 'WP01') ?></strong><br>
                        <?php

                        $text = __('Перед внедрением любых технических изменений, обновлением CMS/темы/плагинов сайта создайте бэкап (шаг 2, или <a href="https://plagin.wp01.ru/sozdanie-bekapa" target="_blank">Online</a>).<br> Если что-то пойдёт не так - воспользуйтесь <a href="https://plagin.wp01.ru/vosstanovlenie-iz-bekapa" target="_blank">данной инструкцией</a>.', 'WP01');
                        printf($text, '<a href="' . plugin_dir_url(WP01__PLUGIN_FILE) . 'content/recovery.pdf" target="_blank">recovery.pdf</a>');

                        ?>
                    </p>
                </div>
            </div>
            <div class="right">
                <div class="notice inline">
                    <p>
                        <strong><?php _e('Не смогли разобраться?', 'WP01') ?></strong>
                        <a href="https://wp01.ru" class="button button-green" target="_blank">
                            <?php _e('Заказать улучшения за деньги', 'WP01') ?>
                            <span class="dashicons dashicons-thumbs-up"></span>
                        </a>
                    </p>
                    <hr>
                    <p>
                        <strong><?php _e('Есть вопросы, нужна помощь?', 'WP01') ?></strong>
                        <a href="https://plagin.wp01.ru"
                           target="_blank"
                           class="button button-link"><?php _e('Страница поддержки плагина', 'WP01') ?></a>
                    </p>
                </div>
            </div>
        </div>
    </div>

    <?php include WP01__PLUGIN_DIR . 'content/admin-page-nav.php' ?>

    <div class="card">
        <?php

        foreach (WP01::get_steps() as $i => $step) {
            echo '<section class="step" id="' . $step['name'] . '" ' . ($i ? 'style="display: none"' : '') . '>';
            echo '<div class="clearfix"></div>';
            include $step['path'];
            echo '<div class="clearfix"></div>';
            echo '</section>';
        }

        ?>
    </div>

    <?php include WP01__PLUGIN_DIR . 'content/admin-page-nav.php' ?>

</div>
