<?php

if (!defined('ABSPATH')) {
    die('Don\'t hack please!');
}

?>
<div class="card tip">
    <h3>Подсказка</h3>
    <p>1. Все плагины устанавливаются в папку /wp-content/plugins/, поэтому,
        <br>если после активации сайт выдаст ошибку (белый экран), то просто
        <br>зайдите на FTP и деактивируйте конфликтный плагин, подставив
        <br>в название его папки цифру/букву. Для возобновления его работ
        <br>зайдите в админ панель сайта и нажмите "Активировать" рядом с плагином.</p>
    <p>2. Для просмотра мобильной версии
		<br>в браузерах на движке Chromium (Google Chrome, Yandex, Opera):
        <br>&nbsp; &nbsp;A. Откройте панель разработчика (клавиша "F12")
		<br>&nbsp; &nbsp;B. Выберите шаблон разрешения в разделе "Responsive",
		<br>&nbsp; &nbsp;или задайте необходимое по ширине/высоте, уточните ориентацию экрана
		<br>в браузерах на движке Gecko (Firefox, Waterfox, Avant Browser):
		<br>&nbsp; &nbsp;A. Откройте режим адаптивного дизайна (комбинация Ctrl+Shift+M)
		<br>&nbsp; &nbsp;B. Уточните ориентацию экрана и выберите шаблон разрешения,
		<br>&nbsp; &nbsp;или задайте необходимое по ширине/высоте
		</p>
</div>

<h2>Шаг 6/7. <span class="name">Дополнительные настройки</span></h2>

<div class="notice notice-warning notice-alt inline">
    <p>
        <strong>Важно:</strong><br>
        Представленные в данном разделе инструменты позволяют упростить внедрения, расширить возможности управления или проработать Frontend составляющую сайта. Перед их использованием для исключения ошибок изучите официальные инструкции/рекомендации в WordPress репозитории.
	</p>
</div>

<table class="widefat table-not-full-width plugins">
    <thead>
    <tr>
        <th style="width:100px">Сервис</th>
        <th>Назначение</th>
		<th>Язык</th>
        <th>Рекомендации</th>
    </tr>
    </thead>
    <tbody>
    <tr class="inactive">
        <td><a href="https://search.google.com/test/mobile-friendly" target="_blank">Google Search Console</a></td>
        <td>Проверка на адаптированность под мобильные устройства, предпросмотр 1 экрана и изучение кода<br><strong>Аналог:</strong> <a href="https://www.bing.com/webmaster/tools/mobile-friendliness" target="_blank">Проверка от Microsoft Bing</a>
        </td>
		<td>RUS
		</td>
        <td>Исключите ошибки
        </td>
    </tr>
    <tr class="inactive">
        <td><a href="https://bluetree.ai/screenfly/" target="_blank">Screenfly</a></td>
        <td>Проверка отображения сайта под разными разрешениями<br><strong>Аналоги:</strong> <a href="http://adaptivator.ru/" target="_blank">Adaptivator</a> и <a href="https://chrome.google.com/webstore/detail/i-love-adaptive-–-mobiler/dpfgmabfakicdmcijnddgbelfhfkddnb" target="_blank">I love adaptive (расширение для Chrome)</a><br><strong>Рекомендуем:</strong> <a href="https://blisk.io/" target="_blank">Blisk (браузер) - отображение мобильной/ПК версии в realtime</a>
        </td>
		<td>ENG
		</td>
        <td>Исключите ошибки
        </td>
    </tr>
    </tbody>
</table>

<h3>I. Плагины для ускорения</h3>
<p>Установите плагины соответствующие необходимым задачам</p>

<?php

$titles = array('Плагин', 'Статус', 'Аналоги', 'Замена кодом', 'Задача', 'Важность модуля', 'Управление', 'Инструкция по настройке');
$plugins = array(
    array(
        'name' => 'WPtouch',
        'icon' => WP01_Content::get_image_src('icons/6/wptouch_m.jpg'),
        'path' => 'wptouch/wptouch.php',
        'analogs' =>  array(
            array(
                'name' => 'WordPress Mobile Pack — Mobile Plugin for Progressive Web Apps & Hybrid Mobile Apps',
                'icon' => WP01_Content::get_image_src('icons/6/wordpress-mobile-pack_s.jpg'),
                'path' => 'wordpress-mobile-pack/wordpress-mobile-pack.php',
                'settings_link'  => '/admin.php?page=wmp-options',
            ),
            array(
                'name' => 'Jetpack от WordPress.com',
                'icon' => WP01_Content::get_image_src('icons/6/jetpack_s.jpg'),
                'path' => 'jetpack/jetpack.php',
				'settings_link'  => '/admin.php?page=jetpack',
            )
        ),
        'desc' => 'Внедрение мобильной версии на сайт',
		'rate' => 1,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a><br>Документация:<br> 
<a href="https://support.wptouch.com/category/1402-category" target = "_blank"><strong>ENG</strong></a> &nbsp; 
<a href="https://translate.google.com/translate?sl=auto&tl=ru&u=https://support.wptouch.com/category/1402-category" target = "_blank"><strong>RUS(GT)</strong></a> &nbsp; 
<a href="https://translate.yandex.ru/translate?lang=en-ru&url=https://support.wptouch.com/category/1402-category" target = "_blank"><strong>RUS(YT)</strong></a><br>',
        'settings_text'  => 'Активен, настроить',
        'settings_link'  => '/admin.php?page=wptouch-admin-general-settings',
    ),
    array(
        'name' => 'Менеджер обновлений WordPress (Отключить обновления, Отключить автоматические обновления)',
        'icon' => WP01_Content::get_image_src('icons/6/webcraftic-updates-manager_m.jpg'),
        'path' => 'webcraftic-updates-manager/webcraftic-updates-manager',
        'analogs' =>  array(
            array(
                'name' => 'Easy Updates Manager',
                'icon' => WP01_Content::get_image_src('icons/6/stops-core-theme-and-plugin-updates_s.jpg'),
				'path' => 'stops-core-theme-and-plugin-updates/main.php',
                'settings_link'  => '/index.php?page=mpsum-update-options',
            ),
            array(
                'name' => 'Disable All WordPress Updates',
                'icon' => WP01_Content::get_image_src('icons/6/disable-wordpress-updates_s.jpg'),
                'path' => 'disable-wordpress-updates/disable-updates.php',
				'settings_link'  => '',
            )
        ),
        'desc' => 'Управление автоматическими обновлениями темы/плагинов/CMS/переводов',
		'rate' => 2,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text'  => 'Активен, настроить',
        'settings_link'  => '/options-general.php?page=updates-wbcr_updates_manager',
    ),
    array(
        'name' => 'LuckyWP Scripts Control',
        'icon' => WP01_Content::get_image_src('icons/6/luckywp-scripts-control_m.jpg'),
        'path' => 'luckywp-scripts-control/luckywp-scripts-control.php',
        'analogs' =>  array(
            array(
                'name' => 'Header and Footer Scripts',
                'icon' => WP01_Content::get_image_src('icons/6/header-and-footer-scripts_s.jpg'),
                'path' => 'header-and-footer-scripts/shfs.php',
                'settings_link'  => '/options-general.php?page=header-and-footer-scripts%2Fshfs.php',
            ),
            array(
                'name' => 'DCO Insert Analytics Code',
                'icon' => WP01_Content::get_image_src('icons/6/dco-insert-analytics-code_s.jpg'),
                'path' => 'dco-insert-analytics-code/dco-insert-analytics-code.php',
				'settings_link'  => '/options-general.php?page=dco-insert-analytics-code',
            ),
            array(
                'name' => 'Head, Footer and Post Injections',
                'icon' => WP01_Content::get_image_src('icons/6/header-footer_s.jpg'),
                'path' => 'header-footer/plugin.php',
				'settings_link'  => '/options-general.php?page=header-footer%2Foptions.php',
            )
        ),
        'desc' => 'Удобное добавление произвольного кода в head/body область сайта',
		'rate' => 2,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text'  => 'Активен, настроить',
        'settings_link'  => '/options-general.php?page=lwpsc_scripts',
    ),
    array(
        'name' => 'Code Snippets',
        'icon' => WP01_Content::get_image_src('icons/6/code-snippets_m.jpg'),
        'path' => 'code-snippets/code-snippets.php',
        'analogs' =>  array(
            array(
                'name' => 'Woody ad snippets — Insert Header Footer Code, AdSense Ads',
                'icon' => WP01_Content::get_image_src('icons/6/widget-output-cache_s.jpg'),
                'path' => 'widget-output-cache/widget-output-cache.php',
                'settings_link'  => '/edit.php?post_type=wbcr-snippets',
            ),
            array(
                'name' => 'My Custom Functions',
                'icon' => WP01_Content::get_image_src('icons/6/my-custom-functions_s.jpg'),
                'path' => 'my-custom-functions/my-custom-functions.php',
				'settings_link'  => '/options-general.php?page=my-custom-functions',
            )
        ),
        'desc' => 'Управление фрагментами кода (виртуальный functions.php)',
		'rate' => 2,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text'  => 'Активен, настроить',
        'settings_link'  => '/admin.php?page=snippets',
		'code_replace' => '
<strong>Замена функции &quot;Виртуальный functions.php&quot;:</strong><br>
1. Перейдите в директорию плагинов вашего сайта (/wp-content/plugins/)<br>
2. Создайте папку с именем вашего плагина, например "virtual-functions"<br>
3. В этой папке создайте файл с расширением php, например "my-plugin.php"<br>
4. Разместите в файле следующий код:<br>
<div class="tc">
&lt;?php<br>
/*<br>
Plugin Name: WP01: виртуальный functions.php<br>
Description: Пользовательские коды, размещенные вручную в файле /wp-content/plugins/virtual-functions/my-plugin.php<br>
Version: 16.04.2020<br>
*/<br>
/* Начало кода 1 */<br>
/* Конец кода 1 */<br>
<br>
/* Начало кода 2 */<br>
/* Конец кода 2 */<br>
?&gt;<br>
</div>
5. Разместите необходимый пользовательский код. Для удобства чтения рекомендуем вставлять код между условных разделителей "Начало/Конец кода"<br>
6. В админ панели сайта выберите "Плагины" и активируйте плагин с указанным именем (например, WP01: виртуальный functions.php)
<br><br>
 
<strong>Примечание:</strong><br>
1. Если после активации плагина сайт выдаёт ошибку - удалите код и обновите страницу (Ctrl+F5)<br>
		'
    ),
    array(
        'name' => 'WP Rollback',
        'icon' => WP01_Content::get_image_src('icons/6/wp-rollback_m.jpg'),
        'path' => 'wp-rollback/wp-rollback.php',
        'desc' => 'Установка нужной версии темы/плагина с репозитория WordPress. Все настройки сохраняются',
		'rate' => 1,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a><br>Документация:<br> 
<a href="https://github.com/impress-org/wp-rollback/wiki" target = "_blank"><strong>ENG</strong></a> &nbsp; 
<a href="https://translate.google.com/translate?sl=auto&tl=ru&u=https://github.com/impress-org/wp-rollback/wiki" target = "_blank"><strong>RUS(GT)</strong></a> &nbsp; 
<a href="https://translate.yandex.ru/translate?lang=en-ru&url=https://github.com/impress-org/wp-rollback/wiki" target = "_blank"><strong>RUS(YT)</strong></a><br>',
        'settings_text' => 'Активен, используйте "Rollback" возле плагинов',
        'settings_link'  => '',
    ),
    array(
        'name' => 'WP Downgrade | Specific Core Version',
        'icon' => WP01_Content::get_image_src('icons/6/wp-downgrade_m.jpg'),
        'path' => 'wp-downgrade/wp-downgrade.php',
        'desc' => 'Обновление/откат CMS до нужной версии с репозитория WordPress. Все настройки сохраняются. <a href="https://wordpress.org/news/category/releases/" target="_blank">История версий CMS</a> (ENG)',
		'rate' => 1,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text'  => 'Активен, настроить',
        'settings_link'  => '/options-general.php?page=wp_downgrade',
	),		
    array(
        'icon' => WP01_Content::get_image_src('icons/3/media-cleaner_m.jpg'),
        'name' => 'Media Cleaner — Clean & Optimize Space',
        'path' => 'media-cleaner/media-cleaner.php',
        'analogs' =>  array(
            array(
                'name' => 'WPS Cleaner',
                'icon' => WP01_Content::get_image_src('icons/3/wps-cleaner_s.jpg'),
                'path' => 'wps-cleaner/wps-cleaner.php',
                'settings_link'  => '',
            )
        ),
        'desc' => 'Очистка сайта от неиспользуемых медиафайлов (оригиналов и автоматически создаваемых размерностей)<br> <strong>Рекомендуем:</strong> <a href="https://wordpress.org/plugins/my-simple-space/" target="_blank">Узнать используемое дисковое пространство</a>',
        'rate' => 2,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text' => 'Активен, настроить',
        'settings_link' => '/upload.php?page=wpmc_dashboard',
    )
);

WP01_Table::the_table($titles, $plugins);

?>

<h3>II. Быстрый бэкап</h3>
<p>Перед ручными внедрениями кода настоятельно рекомендуем сделать резервную копию файлов, которые будут редактироваться</p>

<?php 
/* start new */
$titles = array('Название', 'Расположение', 'Назначение', 'Управление');
    
        $structure = array(
/*          array(
                "filename" => '.htaccess',
                "path" => '/',
                'fullPath' => $_SERVER['DOCUMENT_ROOT'] . '/',
                "comment" => 'Файл дополнительной конфигурации веб-сервера',
                "button_text" => 'Скачать'
            ),
            array(
                "filename" => 'wp-config.php',
                "path" => '/',
                'fullPath' => $_SERVER['DOCUMENT_ROOT'] . '/',
                "comment" => 'Конфигурационный файл WordPress',
                "button_text" => 'Скачать'
            ),
*/
            array(
                "filename" => 'footer.php',
                "path" => '/wp-content/themes/'. get_template() . '/',
                'fullPath' => $_SERVER['DOCUMENT_ROOT'] . '/wp-content/themes/'. get_template() . '/',
                "comment" => 'Нижняя часть шаблона сайта',
                "button_text" => 'Скачать'
            ),
            array(
                "filename" => 'header.php',
                "path" => '/wp-content/themes/'. get_template() . '/',
                'fullPath' => $_SERVER['DOCUMENT_ROOT'] . '/wp-content/themes/'. get_template() . '/',
                "comment" => 'Верхняя часть шаблона сайта',
                "button_text" => 'Скачать'
            ),
            array(
                "filename" => 'functions.php',
                "path" => '/wp-content/themes/'. get_template() . '/',
                'fullPath' => $_SERVER['DOCUMENT_ROOT'] . '/wp-content/themes/'. get_template() . '/',
                "comment" => 'Файл темы с пользовательскими функциями',
                "button_text" => 'Скачать'
            )
        );

    WP01_Table::build_backup_table($titles, $structure); 
	/* end new */
?>

<h3>III. Ручные внедрения и сторонние программы</h3>
<p>Произведите установку/правку кода в соответствии с необходимой задачей</p>

<h4>1. Проанализируйте log – файл</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Найдите перегрузы в лог файле</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong>Выполните действия:</strong><br>
1. Скачайте программу <a href="https://404.su/soft/logmaster.rar">Logmaster</a> (<a href="https://wp01.ru/programs/logmaster.rar">альтернативная ссылка</a>) <br>
2. Запустите Logmaster и загрузите (Log-файл -> Загрузить) в софт log файл с вашего сервера<br>
&nbsp; &nbsp; Варианты получения log:<br>
&nbsp; &nbsp; - на хостинге, в папке "/logs" или подобной (зависит от хостера)<br>
&nbsp; &nbsp; - в панели управления. Например, в ISP: WWW -> Журналы<br>
&nbsp; &nbsp; - запросить у техподдержки хостера<br>
3. В правом списке программы (Результат) изучите ip адреса по столбику "%"<br>
4. Отфильтруйте левый список по выбранным ip (через "отобразить по ip") для получения информации по обращениям с указанного адреса.<br>
5. Примите решение по блокировки ip или ограничению доступа к файлам сайта.<br>
<br><strong>Примечание:</strong><br>
1. Для работы с большими списками и более удобной сортировки используйте выгрузку в Excel: Отчёты -> Лог-файл -> Excel<br>

    </div>
</div>
