<?php

if (!defined('ABSPATH')) {
    die('Don\'t hack please!');
}

?>
<div class="card tip">
    <h3>Подсказка</h3>

    <p>1. Запишите полученные данные из сервисов тестирования скорости сайтов. 
        <br>После вы сможете понять эффективность проведенных вами работ.</p>
    <p>2. При наличии должного опыта советуем просмотреть также
        <br>причины замедления сайта и рекомендации по их устранению,
        <br>которые отображаются в тестах Google PSI, GTmetrix и Pingdom.</p>
    <p>3. Все плагины устанавливаются в папку /wp-content/plugins/ поэтому,
        <br>если после активации сайт выдаст ошибку (белый экран), то просто
        <br>зайдите на FTP и деактивируйте конфликтный плагин подставив в название
        <br>его папки цифру/букву. Для возобновления его работ зайдите в админ панель
        <br>сайта и нажмите "Активировать" рядом с плагином.</p>
    <p>4. Некоторые настройки плагинов могут конфликтовать с темой вашего сайта,
        <br>или другими плагинами. Советуем активировать по очереди каждую
        <br>функцию в плагинах и проверять работу сайта.</p>
    <p>5. Для тестирования порядка отображения и скорости загрузки сайта
        <br>в браузерах на движке Chromium (Google Chrome, Yandex, Opera):
        <br>&nbsp; &nbsp;A. Откройте панель разработчика (клавиша "F12")
		<br>&nbsp; &nbsp;B. Перейдите в раздел "Network" и нажмите "&#9660;" рядом с "Online"
		<br>&nbsp; &nbsp;C. Выберите в пункте "Presets" сеть 3G, либо задайте скорость в "Add..."
		<br>в браузерах на движке Gecko (Firefox, Waterfox, Avant Browser):
		<br>&nbsp; &nbsp;A. Откройте режим адаптивного дизайна (комбинация Ctrl+Shift+M)
		<br>&nbsp; &nbsp;B. Выберите в пункте "Без ограничения" необходимую сеть.</p>
	<p>6. Для полноценного отображения сайта отключите для него 
        <br>все блокираторы рекламы (Adblock, AdGuard, Ghostery)</p>
	<p>7. Для анализа скорости и подключений метрик, онлайн-консультантов
		<br>и прочих трекеров удобно использовать Ghostery в <a href="https://chrome.google.com/webstore/detail/ghostery-–-privacy-ad-blo/mlomiejdfkolichcflejclcbmpeaniij/related?hl=ru" target="_blank">Chrome</a> / <a href="https://addons.mozilla.org/ru/firefox/addon/ghostery/" target="_blank">Mozilla</a></p>
</div>

<h2>Шаг 3/7. <span class="name">Ускорение загрузки</span></h2>

<div class="notice notice-warning notice-alt inline">
    <p>
        <strong>Важно:</strong><br>
        Для того, что бы понять насколько сайт медленно загружается, а также причины этого, проведите независимые тесты
        в 2-3 сервисах ДО ВНЕДРЕНИЯ МЕТОДОВ УСКОРЕНИЯ и повторите их вновь ПОСЛЕ ВСЕХ МЕРОПРИЯТИЙ.
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
        <td><a href="https://developers.google.com/speed/pagespeed/insights/" title="Google PageSpeed Insights" target="_blank">Google PSI</a></td>
        <td>Официальный сервис Google по определению скорости загрузки. Отображает баллы и даёт рекомендаций для ускорения мобильной/ПК версии сайта<br>
		<strong>Информация:</strong> <a href="https://googlechrome.github.io/lighthouse/scorecalc/" target="_blank">Калькулятор Lighthouse</a>
        </td>
		<td>RUS
		</td>
        <td>Стремитесь достичь > 90 баллов <a href="#" class="collapse-toggler" data-target="#info-collapse">СПРАВКА</a>
        </td>
    </tr>
    <tr class="inactive">
        <td><a href="https://seolik.ru/speed" target="_blank">SeoLik</a></td>
        <td>Тестирование скорости загрузки сайта с отображением ошибок. Имеются дополнительные инструменты для аудита и
            SEO исследований.
        </td>
		<td>RUS
		</td>
        <td>Стремитесь достичь > 90 баллов <a href="#" class="collapse-toggler" data-target="#info-collapse">СПРАВКА</a>
        </td>
    </tr>
    <tr class="inactive">
        <td><a href="https://gtmetrix.com" target="_blank">GTmetrix</a></td>
        <td>Анализ скорости работы сайта по данным Google PSI и YSlow. По результатам теста отображаются замечания и
            рекомендации.
        </td>
		<td>ENG
		</td>
        <td>Стремитесь достичь > 90 баллов <a href="#" class="collapse-toggler" data-target="#info-collapse">СПРАВКА</a>
        </td>
    </tr>
	<tr class="inactive">
        <td><a href="https://tools.pingdom.com" target="_blank">Pingdom</a></td>
        <td>Тестирование скорости загрузки сайта с возможностью выбора сервера. Отображает внутренний рейтинг, размер страницы, 
		время загрузки и количество произведенных сайтом запросов. Имеются рекомендации по повышению скорости и техническая информация.
        </td>
		<td>ENG
		</td>
        <td>Стремитесь достичь > 90 баллов <a href="#" class="collapse-toggler" data-target="#info-collapse">СПРАВКА</a>
        </td>
    </tr>
	<tr class="inactive">
        <td><a href="https://ping-admin.ru/free_test/" target="_blank">Ping-Admin</a></td>
        <td>Проверка доступности сайта из различных частей мира с отображением информации: затраченное время (общее, DNS, 
		соединение, SSL, ожидание ответа), скорость загрузки и размер кода страницы (в сжатом и используемом виде).<br>
		<strong>Рекомендуем:</strong> Сравните быстродействие и скорость канала связи своего хостинга с нашим. Подробнее: <a href="https://on.wp01.ru/" target="_blank">https://on.wp01.ru</a> (версия скрипта 0.2)
		</td>
		<td>ENG
		</td>
        <td>Стремитесь к меньшему времени загрузки
        </td>
	    </tr>
	<tr class="inactive">
        <td><a href="https://www.webpagetest.org/" target="_blank">WebPagetest</a></td>
        <td>Изучение скорости сайта с возможностью выбора места проведения теста, браузера, устройства (ПК, мобильное), имеются тонкие настройки (обработка JavaScript, SSL, Chrome и прочие).
        </td>
		<td>ENG
		</td>
        <td>Стремитесь к меньшему времени загрузки
        </td>
    </tr>
    </tbody>
</table>

<div class="collapse unstiled" id="info-collapse">
    <div class="collapse-body" style="display: none;">
        <div class="card">
            <h4>Справка</h4>
            <p>1. Если показатели скорости низкие (до 89 баллов) - возможно вы не в полной мере использовали возможности
                плагинов, проверьте настройки и повторите проверки!</p>
            <p>2. На скорость загрузки сайта влияют:</p>
            <ul>
                <li>мощность хостинга;</li>
                <li>количество сайтов на хостинге (узнать все соседствующие сайты: <a href="https://suip.biz/ru/?act=hostmap" target="_blank">https://suip.biz/ru/?act=hostmap</a>);</li>
                <li>посещаемость сайта;</li>
                <li>активированные плагины;</li>
                <li>чистота и корректность кода темы;</li>
				<li>уровень оптимизации изображений;</li>
				<li>количество внешних подключений (например, JivoSite, Google Analytics);</li>				
				<li>близость расположения хостинга к потенциальным клиентам (узнать город физического нахождения сайта по ip: <a href="https://2ip.ru/geoip/" target="_blank">https://2ip.ru/geoip/</a>);</li>
				<li>актуальность PHP версии - по возможности используйте PHP 7.4 (максимально поддерживаемая системой WordPress на данный момент версия).</li>
				<p><strong>ВАЖНО:</strong> почти всегда переход на более свежую версию PHP вызывает ошибки в работе плагинов, темы и/или CMS.<br>
				Рекомендуем производить смену PHP версии непосредственно программистом.<br>
				Официальные рекомендации WordPress: <a href="https://ru.wordpress.org/support/update-php/" target="_blank">https://ru.wordpress.org/support/update-php/</a></p>
            </ul>
			<p>3. Тест сайтов для России:<br>
			Сверьте скорость своего хостинга с работой <a href="https://www.reg.ru/hosting/?rlink=reflink-6247477" target="_blank">reg.ru</a> (на нём размещены наши сайты) указав для скана спецстраницу в сервисе <a href="https://ping-admin.ru/free_test/" target="_blank">https://ping-admin.ru</a> <strong>Подробнее:</strong> <a href="https://on.wp01.ru/" target="_blank">https://on.wp01.ru/</a><br>
			Скачайте и разместите у себя на хостинге файл <a href="https://on.wp01.ru/test_wp01.zip" target="_blank">wp01_test.zip</a> (704 Кб) для теста скорости канала связи хостинга. Сравните результаты с тестом по файлу на нашем хостинге: <code>https://on.wp01.ru/test_wp01.zip</code><br>
			Сверьте показания в Ping-Admin по скану тестового файла на вашем и нашем хостинге. При большой разнице (в несколько десятков раз) подумайте о смене хостинга.
			</p>	

            <p><strong>P.S.</strong> Если вы не смогли достичь высоких показателей - возможно стоит обратиться к программисту для
                переписывания темы сайта и замены наиболее "тяжелых" плагинов кодом.</p>
        </div>
    </div>
</div>

<h3>I. Плагины для ускорения</h3>
<p>Установите плагины соответствующие необходимым задачам</p>

<?php

$titles = array('Плагин', 'Статус', 'Аналоги', 'Замена кодом', 'Задача', 'Важность модуля', 'Управление', 'Инструкция по настройке');
$plugins = array(
    array(
        'icon' => WP01_Content::get_image_src('icons/3/autoptimize_m.jpg'),
        'name' => 'Autoptimize',
        'path' => 'autoptimize/autoptimize.php',
        'analogs' =>  array(
            array(
                'name' => 'Fast Velocity Minify',
                'icon' => WP01_Content::get_image_src('icons/3/fast-velocity-minify_s.jpg'),
                'path' => 'fast-velocity-minify/fvm.php',
                'settings_link'  => '/options-general.php?page=fastvelocity-min&tab=set',
            ),
            array(
                'name' => 'PageSpeed Ninja',
                'icon' => WP01_Content::get_image_src('icons/3/pagespeed-ninja_s.jpg'),
                'path' => 'psn-pagespeed-ninja/pagespeedninja.php',
                'settings_link'  => '/options-general.php?page=pagespeedninja',
            ),
            array(
                'name' => 'Clearfy — плагин для оптимизации WordPress',
                'icon' => WP01_Content::get_image_src('icons/3/clearfy_s.jpg'),
                'path' => 'clearfy/clearfy.php',
                'settings_link'  => '/options-general.php?page=quick_start-wbcr_clearfy',
            )
        ),
        'desc' => 'Оптимизация css/js/php кода сайта.<br> <strong>Рекомендуем:</strong> <a href="https://wordpress.org/plugins/autoclear-autoptimize-cache/" target="_blank">автоматическая очистка кэша "Autoptimize"</a>',
        'rate' => 3,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text' => 'Активен, настроить',
        'settings_link' => '/options-general.php?page=autoptimize',
		'code_replace' => '
<strong>Замена функции &quot;Удалить emojis&quot;:</strong><br>
1. Откройте файл functions.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">Code Snippets</a> (Шаг 6)<br>
2. Добавьте код:<br>
<div class="tc">
// WP01: Удаление emoji иконок<br>
remove_action(&#039;wp_head&#039;, &#039;print_emoji_detection_script&#039;, 7);<br>
remove_action(&#039;wp_print_styles&#039;, &#039;print_emoji_styles&#039;);<br><br>
</div>

<strong>Замена функции &quot;Удаление строк запроса&quot;:</strong><br>
1. Откройте файл functions.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">Code Snippets</a> (Шаг 6)<br>
2. Добавьте код:<br>
<div class="tc">
// Вариант 1. WP01: Удаление строк запроса из статических файлов<br>
function remove_cssjs_ver( $src ) {<br>
if( strpos( $src, &#039;?ver=&#039; ) )<br>
$src = remove_query_arg( &#039;ver&#039;, $src );<br>
return $src;<br>
}<br>
add_filter( &#039;style_loader_src&#039;, &#039;remove_cssjs_ver&#039;, 10, 2 );<br>
add_filter( &#039;script_loader_src&#039;, &#039;remove_cssjs_ver&#039;, 10, 2 );<br>
</div>
или <br>
<div class="tc">
// Вариант 2. WP01: Удаление строк запроса из статических файлов<br>
function nerodev_remove_query_string($src) {<br>
    $parts = explode(&#039;?ver=&#039;, $src);<br>
    return $parts[0];<br>
}<br>
add_filter(&#039;script_loader_src&#039;, &#039;nerodev_remove_query_string&#039;, 15, 1);<br>
add_filter(&#039;style_loader_src&#039;, &#039;nerodev_remove_query_string&#039;, 15, 1);<br><br>
</div>

<strong>Замена функции &quot;Предварительное подключение к сторонним доменам&quot;:</strong><br>
1. Откройте файл header.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/)<br>
2. Добавьте строчки (не более 6) до &lt;/head&gt; вида:<br>
<div class="tc">
&lt;link rel=&quot;preconnect&quot; href=&quot;URL адрес домена, к которому нужно сделать предподключение&quot;&gt;<br><br>
</div>

<strong>Примечание:</strong><br>
1. В случае обновления темы повторите установку кода (не актуально при использовании плагина для добавления кода)<br>
2. При нахождении в конце файла functions.php закрытия блока &quot;?&gt;&quot; разместите код до него.<br>
3. Если после установки кода сайт выдаёт ошибку - удалите код и обновите страницу (Ctrl+F5)
		'
    ),
    array(
        'icon' => WP01_Content::get_image_src('icons/3/wp-optimize_m.jpg'),
        'name' => 'WP-Optimize — Clean, Compress, Cache.',
        'path' => 'wp-optimize/wp-optimize.php',
        'analogs' =>  array(
            array(
                'name' => 'WP-DBManager',
                'icon' => WP01_Content::get_image_src('icons/3/wp-dbmanager_s.jpg'),
                'path' => 'wp-dbmanager/wp-dbmanager.php',
                'settings_link'  => '/admin.php?page=wp-dbmanager%2Fdatabase-manager.php',
            ),
            array(
                'name' => 'Advanced Database Cleaner',
                'icon' => WP01_Content::get_image_src('icons/3/advanced-db-cleaner_s.jpg'),
                'path' => 'advanced-database-cleaner/advanced-db-cleaner.php',
                'settings_link'  => '/admin.php?page=advanced_db_cleaner',
            ),
            array(
                'name' => 'WP Clean Up Optimizer: Optimize Database & WordPress',
                'icon' => WP01_Content::get_image_src('icons/3/wp-cleanup-optimizer_s.jpg'),
                'path' => 'wp-clean-up-optimizer/wp-cleanup-optimizer.php',
                'settings_link'  => '/admin.php?page=cpo_dashboard',
            )
        ),
        'desc' => 'Оптимизация и чистка MySQL',
        'rate' => 3,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text' => 'Активен, настроить',
        'settings_link' => '/admin.php?page=WP-Optimize',
		'code_replace' => '
<strong>Замена функции &quot;Оптимизировать таблицы базы данных&quot;:</strong><br>
1. Зайдите в phpMyAdmin и выберите необходимую базу данных<br>
2. Выберите вкладку &quot;SQL&quot;, введите запрос OPTIMIZE TABLE wp_posts; и нажмите &quot;Ок&quot;<br><br>

<strong>Замена функции &quot;Очистить все ревизии записей&quot;:</strong><br>
1. Зайдите в phpMyAdmin и выберите необходимую базу данных<br>
2. Выберите вкладку &quot;SQL&quot;, введите запрос DELETE FROM wp_posts WHERE post_type = &#039;revision&#039;; и нажмите &quot;Ок&quot;<br><br>

<strong>Замена функции &quot;Удаление спама&quot;:</strong><br>
1. Зайдите в phpMyAdmin и выберите необходимую базу данных<br>
2. Выберите вкладку &quot;SQL&quot;, введите запрос DELETE FROM wp_comments WHERE comment_approved = &#039;spam&#039;; и нажмите &quot;Ок&quot;<br><br>

<strong>Замена функции &quot;Удалить не одобренные комментарии&quot;:</strong><br>
1. Зайдите в phpMyAdmin и выберите необходимую базу данных<br>
2. Выберите вкладку &quot;SQL&quot;, введите запрос DELETE FROM wp_comments WHERE comment_approved = &#039;0&#039;; и нажмите &quot;Ок&quot;<br><br>

<strong>Замена функции &quot;Удалить транзиенты&quot;:</strong><br>
1. Зайдите в phpMyAdmin и выберите необходимую базу данных<br>
2. Выберите вкладку &quot;SQL&quot;, введите запрос DELETE FROM wp_options WHERE option_name LIKE (&#039;%\_transient\_%&#039;); и нажмите &quot;Ок&quot;<br><br>

<strong>Замена функции &quot;Удалить уведомления&quot;:</strong><br>
1. Зайдите в phpMyAdmin и выберите необходимую базу данных<br>
2. Выберите вкладку &quot;SQL&quot;, введите запрос DELETE FROM wp_comments WHERE comment_type = &#039;pingback&#039;; и нажмите &quot;Ок&quot;<br><br>

<strong>Замена функции &quot;Очистить метаданные записей&quot;:</strong><br>
1. Зайдите в phpMyAdmin и выберите необходимую базу данных<br>
2. Выберите вкладку &quot;SQL&quot;, введите запрос DELETE FROM wp_postmeta WHERE meta_key IN (&#039;_edit_lock&#039;, &#039;_edit_last&#039;,&#039;_wp_old_slug&#039;); и нажмите &quot;Ок&quot;<br><br>

<strong>Замена функции &quot;Очистить метаданные комментариев&quot;:</strong><br>
1. Зайдите в phpMyAdmin и выберите необходимую базу данных<br>
2. Выберите вкладку &quot;SQL&quot;, введите запрос DELETE FROM wp_commentmeta WHERE comment_id NOT IN (SELECT comment_id FROM wp_comments); и нажмите &quot;Ок&quot;<br><br>

<strong>Примечание:</strong><br>
1. Обязательно сделайте бэкап базы данных. В случае ошибки вы сможете восстановить работу сайта.
		'
    ),
    array(
        'icon' => WP01_Content::get_image_src('icons/3/db-cache-reloaded-fix_m.jpg'),
        'name' => 'DB Cache Reloaded Fix',
        'path' => 'db-cache-reloaded-fix/db-cache-reloaded.php',
        'desc' => 'Оптимизация запросов к MySQL.<br><strong>Важно: не поддерживает PHP &ge; 7.x</strong>',
        'rate' => 2,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'php_version' => 5,
        'settings_text' => 'Активен, настроить',
        'settings_link' => '/options-general.php?page=db-cache-reloaded-fix%2Fdb-cache-reloaded.php',
    ),
    array(
        'icon' => WP01_Content::get_image_src('icons/3/widget-output-cache_m.jpg'),
        'name' => 'Widget Output Cache',
        'path' => 'widget-output-cache/widget-output-cache.php',
        'desc' => 'Кэширование виджетов',
        'rate' => 2,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text' => 'Активен, настройка не требуется',
        'settings_link' => '',
    ),
    array(
        'icon' => WP01_Content::get_image_src('icons/3/wp-super-cache_m.jpg'),
        'name' => 'WP Super Cache',
        'path' => 'wp-super-cache/wp-cache.php',
        'analogs' =>  array(
            array(
                'name' => 'WP Fastest Cache',
                'icon' => WP01_Content::get_image_src('icons/3/wp-fastest-cache_s.jpg'),
                'path' => 'wp-fastest-cache/wpFastestCache.php',
                'settings_link'  => '/admin.php?page=wpfastestcacheoptions',
            ),
            array(
                'name' => 'W3 Total Cache',
                'icon' => WP01_Content::get_image_src('icons/3/w3-total-cache_s.jpg'),
                'path' => 'w3-total-cache/w3-total-cache.php',
                'settings_link'  => '/admin.php?page=w3tc_general',
            ),
            array(
                'name' => 'Cache Enabler',
                'icon' => WP01_Content::get_image_src('icons/3/cache-enabler_s.jpg'),
                'path' => 'cache-enabler/cache-enabler.php',
                'settings_link'  => '/options-general.php?page=cache-enabler',
            )
        ),
        'desc' => 'Кэширование страниц сайта<br> <strong>Рекомендуем:</strong> <a href="https://wordpress.org/plugins/wp-super-cache-clear-cache-menu/" target="_blank">удобная очистка кэша "WP Super Cache"</a>',
        'rate' => 3,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text' => 'Активен, настроить',
        'settings_link' => '/options-general.php?page=wpsupercache',
    ),
    array(
        'icon' => WP01_Content::get_image_src('icons/3/transients-manager_m.jpg'),
        'name' => 'Transients Manager',
        'path' => 'transients-manager/transients-manager.php',
        'analogs' =>  array(
            array(
                'name' => 'Transient Cleaner',
                'icon' => WP01_Content::get_image_src('icons/3/artiss-transient-cleaner_s.jpg'),
                'path' => 'artiss-transient-cleaner/artiss-transient-cleaner.php',
                'settings_link'  => '/tools.php?page=transient-options',
            ),
            array(
                'name' => 'Delete Expired Transients',
                'icon' => WP01_Content::get_image_src('icons/3/delete-expired-transients_s.jpg'),
                'path' => 'delete-expired-transients/delete-expired-transients.php',
                'settings_link'  => '/tools.php?page=delxtrans',
            ),
            array(
                'name' => 'WP-Optimize — Clean, Compress, Cache.',
                'icon' => WP01_Content::get_image_src('icons/3/wp-optimize_s.jpg'),
                'path' => 'wp-optimize/wp-optimize.php',
                'settings_link'  => '/admin.php?page=WP-Optimize',
            )
        ),
        'desc' => 'Управление транзиентами',
        'rate' => 1,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text' => 'Активен, открыть',
        'settings_link' => '/tools.php?page=pw-transients-manager',
    ),
    array(
        'icon' => WP01_Content::get_image_src('icons/3/a3-lazy-load_m.jpg'),
        'name' => 'a3 Lazy Load',
        'path' => 'a3-lazy-load/a3-lazy-load.php',
        'analogs' =>  array(
            array(
                'name' => 'Lazy Load by WP Rocket',
                'icon' => WP01_Content::get_image_src('icons/3/rocket-lazy-load_s.jpg'),
                'path' => 'rocket-lazy-load/rocket-lazy-load.php',
                'settings_link'  => '/options-general.php?page=rocket_lazyload',
            ),
            array(
                'name' => 'BJ Lazy Load',
                'icon' => WP01_Content::get_image_src('icons/3/bj-lazy-load_s.jpg'),
                'path' => 'bj-lazy-load/bj-lazy-load.php',
                'settings_link'  => '/options-general.php?page=bj-lazy-load',
            ),
            array(
                'name' => 'Lazy Load XT',
                'icon' => WP01_Content::get_image_src('icons/3/lazy-load-xt_s.jpg'),
                'path' => 'lazy-load-xt/lazy-load-xt.php',
                'settings_link'  => '/options-general.php?page=lazyloadxt',
            )
        ),
        'desc' => 'Ленивая загрузка графики',
        'rate' => 3,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text' => 'Активен, настроить',
        'settings_link' => '/options-general.php?page=a3-lazy-load',
		'code_replace' => '
<strong>Инструкция:</strong><br>
1. Скачайте bLazy.js по ссылке <a href="https://raw.github.com/dinbror/blazy/master/blazy.min.js" target="_blank">https://raw.github.com/dinbror/blazy/master/blazy.min.js</a><br>
2. Загрузите blazy.min.js в корневую папку и в самом конце файла напишите var blazy = new Blazy();<br>
3. Для картинок используйте конструкцию вида &lt;img class=&quot;b-lazy&quot; src=&quot;loading.gif&quot; data-src=&quot;image.jpg&quot; /&gt;<br>
4. В конце страницы поставьте &lt;script src=&quot;/blazy.min.js&quot;&gt;&lt;/script&gt;<br><br>

<strong>Примечание:</strong><br>
1. В пункте 3 изображение loading.gif - то, что будет показываться до загрузки основной картинки, а image.jpg -  основная картинка<br>
2. Если вы планируете использовать ленивую загрузку на всем сайте, то для удобства можете установить код &lt;script src=&quot;/blazy.min.js&quot;&gt;&lt;/script&gt; в файл footer.php  (находится в папке используемой темы (/wp-content/themes/название_темы/)) перед &lt;/body&gt;<br>
3. Подробно про ленивую загрузку изображений с использованием скрипта bLazy.js: <a href="http://dinbror.dk/blog/blazy/?ref=demo-page" target="_blank">http://dinbror.dk/blog/blazy/?ref=demo-page</a>
		'
    ),
    array(
        'icon' => WP01_Content::get_image_src('icons/3/plugin-load-filter_m.jpg'),
        'name' => 'Plugin Load Filter',
        'path' => 'plugin-load-filter/plugin-load-filter.php',
        'analogs' =>  array(
            array(
                'name' => 'Plugin Organizer',
                'icon' => WP01_Content::get_image_src('icons/3/plugin-organizer_s.jpg'),
                'path' => 'plugin-organizer/plugin-organizer.php',
                'settings_link'  => '/admin.php?page=Plugin_Organizer',
            )
        ),
        'desc' => 'Контроль работы плагинов на страницах',
        'rate' => 3,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a><br>Документация:<br> 
<a href="https://celtislab.net/en/wp-plugin-load-filter/" target = "_blank"><strong>ENG</strong></a> &nbsp; 
<a href="https://translate.google.com/translate?sl=auto&tl=ru&u=https://celtislab.net/en/wp-plugin-load-filter/" target = "_blank"><strong>RUS(GT)</strong></a> &nbsp; 
<a href="https://translate.yandex.ru/translate?lang=en-ru&url=https://celtislab.net/en/wp-plugin-load-filter/" target = "_blank"><strong>RUS(YT)</strong></a><br>',
        'settings_text' => 'Активен, настроить',
        'settings_link' => '/plugins.php?page=plugin_load_filter_admin_manage_page',
		'code_replace' => '
<strong>Замена функции &quot;Отключение скрипта на всем сайте&quot;:</strong><br>
1. Откройте файл functions.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">Code Snippets</a> (Шаг 6)<br>
2. Добавьте строчки<br>
<div class="tc">
// WP01: Отключение скрипта по handle на всем сайте<br>
add_action (&#039;wp_print_scripts&#039;,&#039;remove_javascript&#039;,100);<br>
function remove_javascript () {<br>
    wp_deregister_script (&#039;handle-плагина&#039;);<br>
}<br><br>
</div>

<strong>Замена функции &quot;Подключение скрипта только на нужных страницах&quot;:</strong><br>
1. Откройте файл functions.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">Code Snippets</a> (Шаг 6)<br>
2. Добавьте строчки<br>
<div class="tc">
// WP01: Подключение скрипта по handle на нужных страницах<br>
add_action ( &#039;wp_print_scripts&#039;, &#039;my_deregister_javascript&#039;, 100 );<br>
function my_deregister_javascript () {<br>
if ( !is_page (&#039;относительный-URL-страницы&#039;) ) {<br>
wp_deregister_script ( &#039;handle-плагина&#039; );<br>
}<br>
}<br><br>
</div>

<strong>Примечание:</strong><br>
1. Значение &quot;handle-плагина&quot; нужно заменить на handle идентификатор нужного плагина (например, плагин &quot;Contact Form 7&quot; имеет handle &quot;contact-form-7&quot;)<br>
2. Идентификатор handle указывается в файлах плагина рядом с wp_enqueue_script<br>
3. Значение &quot;is_page (&#039;относительный-URL-страницы&#039;)&quot; может принимать вид:<br>
is_single(&#039;6&#039;) - запись с идентификатором &quot;6&quot;<br>
is_page(&#039;6&#039;) - страница с идентификатором &quot;6&quot;<br>
is_page (&#039;contact&#039;) - страница вида http://сайт/contact/<br>
is_home() - главная страница сайта
		'
    ),
    array(
        'icon' => WP01_Content::get_image_src('icons/3/async-javascript_m.jpg'),
        'name' => 'Async JavaScript',
        'path' => 'async-javascript/async-javascript.php',
        'analogs' =>  array(
            array(
                'name' => 'CSS JS Manager, Async JavaScript, Defer Render Blocking CSS supports WooCommerce',
                'icon' => WP01_Content::get_image_src('icons/3/css-js-manager_s.jpg'),
                'path' => 'css-js-manager/css-js-manager.php',
                'settings_link'  => '/admin.php?page=css-js-manager',
            ),
            array(
                'name' => 'Asset CleanUp: Page Speed Booster',
                'icon' => WP01_Content::get_image_src('icons/3/wp-asset-clean-up_s.jpg'),
                'path' => 'wp-asset-clean-up/wpacu.php',
                'settings_link'  => '/admin.php?page=wpassetcleanup_getting_started',
            )
        ),
        'desc' => 'Асинхронная и отложенная загрузка JavaScript',
        'rate' => 2,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text' => 'Активен, настроить',
        'settings_link' => '/options-general.php?page=async-javascript',
		'code_replace' => '
<strong>Замена функции &quot;Подстановка параметра async&quot;:</strong><br>
1. Откройте файл functions.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">Code Snippets</a> (Шаг 6)<br>
2. Добавьте строчки<br>
<div class="tc">
// WP01: Добавление параметра async к выборочным скриптам<br>
function add_async_attribute($tag, $handle) {<br>
   // добавьте дескрипторы (названия) скриптов в массив ниже<br>
   $scripts_to_async = array(&#039;script1&#039;, &#039;script2&#039;, &#039;script3&#039;);<br>
   foreach($scripts_to_async as $async_script) {<br>
      if ($async_script === $handle) {<br>
         return str_replace(&#039; src&#039;, &#039; async src&#039;, $tag);<br>
      }<br>
   }<br>
   return $tag;<br>
}<br>
add_filter(&#039;script_loader_tag&#039;, &#039;add_async_attribute&#039;, 10, 2);<br><br>
</div>

<strong>Примечание:</strong><br>
1. Значение &quot;script1&quot; нужно заменить на handle идентификатор нужного скрипта<br>
2. Идентификатор handle указывается рядом с wp_enqueue_script или wp_register_script в коде подключения скриптов внутри темы или плагина
		'
    ),
    array(
        'icon' => WP01_Content::get_image_src('icons/3/local-google-analytics_m.jpg'),
        'name' => 'Local Google Analytics for WordPress — caches external requests',
        'path' => 'simple-google-analytics/simple_google_analytics.php',
        'analogs' =>  array(
            array(
                'name' => 'CAOS | Host Google Analytics Locally',
                'icon' => WP01_Content::get_image_src('icons/3/host-analyticsjs-local_s.jpg'),
                'path' => 'host-analyticsjs-local/host-analyticsjs-local.php',
                'settings_link'  => '/options-general.php?page=host_analyticsjs_local',
            )
        ),
        'desc' => 'Кэширование Google Analitics на вашем сайте<br> <strong>Рекомендуем:</strong> <a href="https://support.google.com/analytics/answer/1032399?hl=ru" target="_blank">проверка работы Google Analytics</a>',
        'rate' => 3,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text' => 'Активен, настроить',
        'settings_link' => '/options-general.php?page=ga_cache-wbcr_gac',
    ),
    array(
        'icon' => WP01_Content::get_image_src('icons/3/webp-express_m.jpg'),
        'name' => 'WebP Express',
        'path' => 'webp-express/webp-express.php',
        'analogs' =>  array(
            array(
                'name' => 'WebP Converter for Media',
                'icon' => WP01_Content::get_image_src('icons/3/webp-converter-for-media_s.jpg'),
                'path' => 'webp-converter-for-media/webp-converter-for-media.php',
                'settings_link'  => '/options-general.php?page=webpc_admin_page',
            ),
            array(
                'name' => 'Imagify – WebP & Image Compression and Optimization',
                'icon' => WP01_Content::get_image_src('icons/3/imagify_s.jpg'),
                'path' => 'imagify/imagify.php',
                'settings_link'  => '/options-general.php?page=imagify',
            ),
            array(
                'name' => 'Image optimization & Lazy Load by Optimole',
                'icon' => WP01_Content::get_image_src('icons/3/optimole-wp_s.jpg'),
                'path' => 'optimole-wp/optimole-wp.php',
                'settings_link'  => '/upload.php?page=optimole',
            )
        ),
        'desc' => 'Внедрение WebP формата + конвертация png/jpg<br> <strong>Рекомендуем:</strong> <a href="https://ru.wordpress.org/plugins/webp-express-plus/" target="_blank">исключение изображений из обработки в WebP</a>',
        'rate' => 3,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text' => 'Активен, настроить',
        'settings_link' => '/options-general.php?page=webp_express_settings_page',
		'code_replace' => '
<strong>Замена функции &quot;Добавить WebP к используемому формату&quot;:</strong><br>
1. Используйте вместо кода &lt;img src=&quot;/img/picture.jpg&quot; alt=&quot;мета-тег описания картинки&quot; /&gt; конструкцию:<br>
<div class="tc">
&lt;picture&gt;<br>
  &lt;source type=&quot;image/webp&quot; srcset=&quot;/img/picture.webp&quot; /&gt;<br>
  &lt;img src=&quot;/img/picture.jpg&quot; alt=&quot;мета-тег описания картинки&quot; /&gt;<br>
&lt;/picture&gt;<br><br>
</div>

<strong>альтернативный вариант:</strong><br>
<div class="tc">
&lt;picture&gt;<br>
  &lt;source srcset=&quot;img/myImage.webp&quot; type=&quot;image/webp&quot;&gt;<br>
  &lt;source srcset=&quot;img/OldJPEG.jpg&quot; type=&quot;image/jpeg&quot;&gt;<br>
  &lt;img src=&quot;img/OldJPEG.jpg&quot; alt=&quot;Alt Text!&quot;&gt;<br>
&lt;/picture&gt;<br><br>
</div>

<strong>2. Включение возможности загрузки Webp файлов через медиа библиотеку сайта:</strong><br>
2.1. Откройте файл functions.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">Code Snippets</a> (Шаг 6)<br>
2.2. Добавьте строчки<br>
<div class="tc">
// WP01: Поддержка загрузчиком сайта Webp формата<br>
function webp_upload_mimes( $existing_mimes ) {<br>
    // добавляем webp в список типов mime<br>
    $existing_mimes[&#039;webp&#039;] = &#039;image/webp&#039;;<br>
    // возвращаем массив обратно в функцию с добавлением типа MIME<br>
    return $existing_mimes;<br>
}<br>
add_filter( &#039;mime_types&#039;, &#039;webp_upload_mimes&#039; );<br><br>
</div>

<strong>Примечание:</strong><br>
1. Если на вашем компьютере не открываются Webp изображения - установите <a href="https://plagin.wp01.ru/soft/wp01_webpcodecsetup.zip">https://plagin.wp01.ru/soft/wp01_webpcodecsetup.zip</a><br>
2. Для быстрой конвертации в Webp воспользуйтесь онлайн-конвертерами:<br>
<a href="https://image.online-convert.com/ru/convert-to-webp" target="_blank">https://image.online-convert.com/ru/convert-to-webp</a>
		'
    ),
    array(
        'icon' => WP01_Content::get_image_src('icons/3/wp-smush_m.jpg'),
        'name' => 'Smush — Compress, Optimize and Lazy Load Images',
        'path' => 'wp-smushit/wp-smush.php',
        'analogs' =>  array(
            array(
                'name' => 'EWWW Image Optimizer',
                'icon' => WP01_Content::get_image_src('icons/3/ewww-image-optimizer_s.jpg'),
                'path' => 'ewww-image-optimizer/ewww-image-optimizer.php',
                'settings_link'  => '/options-general.php?page=ewww-image-optimizer%2Fewww-image-optimizer.php',
            ),
            array(
                'name' => 'ShortPixel Image Optimizer',
                'icon' => WP01_Content::get_image_src('icons/3/shortpixel-image-optimiser_s.jpg'),
                'path' => 'shortpixel-image-optimiser/wp-shortpixel.php',
                'settings_link'  => '/options-general.php?page=wp-shortpixel-settings',
            ),
            array(
                'name' => 'Compress JPEG & PNG images',
                'icon' => WP01_Content::get_image_src('icons/3/tiny-compress-images_s.jpg'),
                'path' => 'tiny-compress-images/tiny-compress-images.php',
                'settings_link'  => '/options-general.php?page=tinify',
            )
        ),
        'desc' => 'Сжатие и оптимизация изображений.<br> <strong>Рекомендуем:</strong> <a href="https://wordpress.org/plugins/wp-nonstop-smushit/" target="_blank">убрать ограничения в "Smush"</a>',
        'rate' => 2,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text' => 'Активен, настроить',
        'settings_link' => '/admin.php?page=smush',
    ),
    array(
        'icon' => WP01_Content::get_image_src('icons/3/heartbeat-control_m.jpg'),
        'name' => 'Heartbeat Control',
        'path' => 'heartbeat-control/heartbeat-control.php',
        'desc' => 'Управление частотой запросов к серверу (пульсация)',
        'rate' => 2,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text' => 'Активен, настроить',
        'settings_link' => '/options-general.php?page=heartbeat_control_settings',
		'code_replace' => '
<strong>Замена функции &quot;Полное отключение Heartbeat&quot;:</strong><br>
1. Откройте файл functions.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">Code Snippets</a> (Шаг 6)<br>
2. Добавьте строчки сразу же после тега &lt;?php с новой строки:<br>
<div class="tc">
// WP01: Отключение HeartBeat для всего сайта<br>
add_action(&#039;init&#039;, &#039;stop_heartbeat&#039;, 1);<br>
function stop_heartbeat() {<br>
 wp_deregister_script(&#039;heartbeat&#039;);<br>
 }<br><br>
</div>

<strong>Примечание:</strong><br>
1. В случае обновления темы повторите установку кода (не актуально при использовании плагина для добавления кода)<br>
2. Если после установки кода сайт выдаёт ошибку - удалите код и обновите страницу (Ctrl+F5)
		'
    ),
    array(
        'icon' => WP01_Content::get_image_src('icons/3/gonzales_m.jpg'),
        'name' => 'Менеджер скриптов и стилей для WordPress',
        'path' => 'gonzales/gonzales.php',
        'desc' => 'Отключение не нужных скриптов и стилей на страницах',
        'rate' => 3,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text' => 'Активен, управление в "admin bar"',
        'settings_link' => '',
		'code_replace' => '
<strong>Отключение css/js плагина "Contact-form-7"</strong><br>
CF7 внедряет стили/скрипты на всех страницах сайта. Что бы исключить лишнюю загрузку элементов примените код разрешения для нужных URL.<br>  
1. Откройте файл functions.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">Code Snippets</a> (Шаг 6)<br>
2. Добавьте строчки:<br>
<strong>Вариант кода №1</strong><br>
<div class="tc">
	/* WP01: Отключаем css/js плагина CF7 везде, кроме разрешенных страниц */<br>
add_filter(&#039;wp&#039;, &#039;cf7_disable_css_js&#039;);<br>
function cf7_disable_css_js(){<br>
	if( ! is_page(&#039;<font color="red">слаг или ID</font>&#039;) ){<br>
		add_filter( &#039;wpcf7_load_js&#039;, &#039;__return_false&#039; );<br>
		add_filter( &#039;wpcf7_load_css&#039;, &#039;__return_false&#039; );<br>
	}<br>
}<br>
</div>
<strong>Вариант кода №2</strong><br>
<div class="tc">
	/* WP01: Отключаем css/js плагина CF7 везде, кроме разрешенных страниц */<br>
add_action(&#039;wp_print_styles&#039;, &#039;my_deregister_javascript&#039;, 100 );<br>
function my_deregister_javascript(){<br>
	if( ! is_page (&#039;<font color="red">слаг или ID</font>&#039;) ){<br>
		wp_deregister_script( &#039;contact-form-7&#039; );<br>
		wp_deregister_style( &#039;contact-form-7&#039; );<br>
	}<br>
}<br>
</div>
<strong>Вариант кода №3</strong><br>
<div class="tc">
	/* WP01: Отключаем css/js плагина CF7 только на заданных страницах */<br>
add_action(&#039;wp_print_styles&#039;, &#039;my_deregister_javascript&#039;, 100 );<br>
function my_deregister_javascript(){<br>
	if( is_page (&#039;<font color="red">слаг или ID</font>&#039;) ){<br>
		wp_deregister_script( &#039;contact-form-7&#039; );<br>
		wp_deregister_style( &#039;contact-form-7&#039; );<br>
	}<br>
}<br><br>
</div>

<strong>Значение is_page(&#039;слаг или ID&#039;) может принимать вид:</strong><br>
is_front_page() - главная страница<br>
is_page(42) - страница с ID 42<br>
is_page(&#039;o-saite&#039;) - страница со слагом "o-saite"<br>
is_page( array(&#039;sample-page&#039;, &#039;contacts&#039;, 23, 34) ) - указание нескольких страниц<br>
is_page( sanitize_title(&#039;о-сайте&#039;) ) - страница со слагом "о-сайте"<br><br>

<strong>Примечание:</strong><br>
1. В случае обновления темы повторите установку кода (не актуально при использовании плагина для добавления кода)<br>
2. Если после установки кода сайт выдаёт ошибку - удалите код и обновите страницу (Ctrl+F5)<br>
3. В некоторых версиях CF7 хуки могут иметь вид:<br>
wp_deregister_script ( &#039;wpcf7cf-scripts&#039; );<br>
wp_deregister_style ( &#039;wpcf7cf-style&#039; );<br>
		'
    ),
    array(
        'icon' => WP01_Content::get_image_src('icons/3/wp-head-cleaner_m.jpg'),
        'name' => 'wp_head() cleaner',
        'path' => 'wp-head-cleaner/wp-head-cleaner.php',
        'analogs' =>  array(
            array(
                'name' => 'Remove Wordpress Overhead',
                'icon' => WP01_Content::get_image_src('icons/3/remove-wp-overhead_s.jpg'),
                'path' => 'remove-wp-overhead/remove-wordpress-overhead.php',
                'settings_link'  => '/options-general.php?page=remove_wordpress_overhead_settings',
            ),				
            array(
                'name' => 'Nietzsche — WP Head Cleaner',
                'icon' => WP01_Content::get_image_src('icons/3/nietzsche_s.jpg'),
                'path' => 'nietzsche/nietzsche.php',
                'settings_link'  => '',
            ),
            array(
                'name' => 'WP Clean Head',
                'icon' => WP01_Content::get_image_src('icons/3/wp-clean-head_s.jpg'),
                'path' => 'wp-clean-head/wp-clean-head.php',
                'settings_link'  => '',
            )
        ),
        'desc' => 'Отключение не нужных тегов/ссылок/данных в head блоке<br> <strong>Рекомендуем:</strong> <a href="https://ru.wordpress.org/plugins/disable-emojis/" target="_blank">Удаление кода/подключений поддержки в старых браузерах Emoji</a>',
        'rate' => 2,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text' => 'Активен, настроить',
        'settings_link' => '/options-general.php?page=wp_head_cleaner',
		'code_replace' => '
<strong>Замена функции &quot;Отключение XML-RPC&quot;:</strong><br>
<strong>Метод № 1</strong><br>
1. Откройте файл .htaccess находящийся в корне сайта<br>
2. Добавьте код<br>
<div class="tc">
# WP01: блокировка xmlrpc.php запросов<br>
&lt;Files xmlrpc.php&gt;<br>
order deny,allow<br>
deny from all<br>
&lt;/Files&gt;<br>
</div>
<strong>Метод № 2</strong><br>
1. Откройте файл functions.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">Code Snippets</a> (Шаг 6)<br>
2. Добавьте код<br>
<div class="tc">
# WP01: блокировка xmlrpc.php запросов<br>
add_filter(&#039;xmlrpc_enabled&#039;, &#039;__return_false&#039;);<br><br>
</div>
<strong>Замена функции &quot;Удаление ссылок Windows Live Writer&quot;:</strong><br>
1. Откройте файл functions.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">Code Snippets</a> (Шаг 6)<br>
2. Добавьте код<br>
<div class="tc">
# WP01: Удаление ссылок Windows Live Writer<br>
remove_action(&#039;wp_head&#039;, &#039;wlwmanifest_link&#039;);<br><br>
</div>

<strong>Замена функции &quot;Удаление отображения WordPress версии&quot;:</strong><br>
1. Откройте файл functions.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">Code Snippets</a> (Шаг 6)<br>
2. Добавьте код<br>
<div class="tc">
# WP01: Удаление ображения WordPress версии<br>
	// Удаление версии WordPress со страниц, RSS, скриптов и стилей<br>
add_filter(&#039;the_generator&#039;, &#039;__return_empty_string&#039;);<br>
function rem_wp_ver_css_js( $src ) {<br>
    if ( strpos( $src, &#039;ver=&#039; ) )<br>
        $src = remove_query_arg( &#039;ver&#039;, $src );<br>
    return $src;<br>
}<br>
add_filter( &#039;style_loader_src&#039;, &#039;rem_wp_ver_css_js&#039;, 9999 );<br>
add_filter( &#039;script_loader_src&#039;, &#039;rem_wp_ver_css_js&#039;, 9999 );<br>
	// Удаление версии WP из футера админки<br>
function kill_footer_version ($default) {<br>
return &#039;&#039;;<br>
}<br>
add_filter (&#039;update_footer&#039;, &#039;kill_footer_version&#039;, 999);<br>
	// Удаление сообщений &quot;Спасибо, что выбрали WordPress&quot;<br>
 function kill_footer_filter ($default) {<br>
return &#039;&#039;;<br>
}<br>
add_filter (&#039;admin_footer_text&#039;, &#039;kill_footer_filter&#039;);<br><br>
</div>

<strong>Замена функции &quot;Удаление Shortlinks&quot;:</strong><br>
1. Откройте файл functions.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">Code Snippets</a> (Шаг 6)<br>
2. Добавьте код<br>
<div class="tc">
# WP01: Удаление Shortlinks<br>
remove_action( &#039;wp_head&#039;, &#039;wp_shortlink_wp_head&#039; );<br><br>
</div>

<strong>Замена функции &quot;Отключение Emoji&quot;:</strong><br>
1. Откройте файл functions.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">Code Snippets</a> (Шаг 6)<br>
2. Добавьте код<br>
<div class="tc">
# WP01: Удаление Emoji<br>
remove_action( &#039;wp_head&#039;, &#039;print_emoji_detection_script&#039;, 7 );<br>
remove_action( &#039;admin_print_scripts&#039;, &#039;print_emoji_detection_script&#039; );<br>
remove_action( &#039;wp_print_styles&#039;, &#039;print_emoji_styles&#039; );<br>
remove_action( &#039;admin_print_styles&#039;, &#039;print_emoji_styles&#039; );<br>
remove_filter( &#039;the_content_feed&#039;, &#039;wp_staticize_emoji&#039; );<br>
remove_filter( &#039;comment_text_rss&#039;, &#039;wp_staticize_emoji&#039; );<br>
remove_filter( &#039;wp_mail&#039;, &#039;wp_staticize_emoji_for_email&#039; );<br>
add_filter( &#039;tiny_mce_plugins&#039;, &#039;disable_wp_emojis_in_tinymce&#039; );<br>
function disable_wp_emojis_in_tinymce( $plugins ) {<br>
    if ( is_array( $plugins ) ) {<br>
        return array_diff( $plugins, array( &#039;wpemoji&#039; ) );<br>
    } else {<br>
        return array();<br>
    }<br>
}<br><br>
</div>

<strong>Замена функции &quot;Отключение REST API&quot;:</strong><br>
1. Откройте файл functions.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">Code Snippets</a> (Шаг 6)<br>
2. Добавьте код<br>
<div class="tc">
# WP01: Отключение REST API<br>
add_filter( &#039;rest_authentication_errors&#039;, &#039;code_disable_rest_api&#039; );<br>
function code_disable_rest_api( $access ) {<br>
	return new WP_Error( &#039;rest_disabled&#039;, __( &#039;REST API disabled&#039; ), array( &#039;status&#039; =&gt; rest_authorization_required_code() ) );<br>
}<br>
</div>
3. Проверьте отключение добавив в URL значение wp-json (например, https://wp01.ru/wp-json) - если в открывшейся странице будет короткая строка, значит REST API отключен<br><br>

<strong>Замена функции &quot;Отключение oEmbed&quot;:</strong><br>
1. Откройте файл functions.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">Code Snippets</a> (Шаг 6)<br>
2. Добавьте код<br>
<div class="tc">
# WP01: Отключение oEmbed<br>
function disable_embeds_code_init() {<br>
	// Удаляем REST API<br>
remove_action( &#039;rest_api_init&#039;, &#039;wp_oembed_register_route&#039; );<br>
	// Выключаем обнаружение oEmbed<br>
add_filter( &#039;embed_oembed_discover&#039;, &#039;__return_false&#039; );<br>
	// Не фильтруем результаты oEmbed<br>
remove_filter( &#039;oembed_dataparse&#039;, &#039;wp_filter_oembed_result&#039;, 10 );<br>
	// Удаляем ссылки oEmbed<br>
remove_action( &#039;wp_head&#039;, &#039;wp_oembed_add_discovery_links&#039; );<br>
	// Удаляем oembed JavaScript из интерфейса и бэк-энда.<br>
remove_action( &#039;wp_head&#039;, &#039;wp_oembed_add_host_js&#039; );<br>
add_filter( &#039;tiny_mce_plugins&#039;, &#039;disable_embeds_tiny_mce_plugin&#039; );<br>
	// Удаляем все правила перезаписи<br>
add_filter( &#039;rewrite_rules_array&#039;, &#039;disable_embeds_rewrites&#039; );<br>
	// Удаляем фильтр результата oEmbed перед выполнением HTTP-запросов<br>
 remove_filter( &#039;pre_oembed_result&#039;, &#039;wp_filter_pre_oembed_result&#039;, 10 );<br>
}<br>
add_action( &#039;init&#039;, &#039;disable_embeds_code_init&#039;, 9999 );<br>
function disable_embeds_tiny_mce_plugin($plugins) {<br>
    return array_diff($plugins, array(&#039;wpembed&#039;));<br>
}<br>
function disable_embeds_rewrites($rules) {<br>
    foreach($rules as $rule =&gt; $rewrite) {<br>
        if(false !== strpos($rewrite, &#039;embed=true&#039;)) {<br>
            unset($rules[$rule]);<br>
        }<br>
    }<br>
    return $rules;<br>
}<br><br>
</div>

<strong>Примечание:</strong><br>
1. В случае обновления темы повторите установку кода (не актуально при использовании плагина для добавления кода)<br>
2. При нахождении в конце файла functions.php закрытия блока &quot;?&gt;&quot; разместите код до него.<br>
3. Если после установки кода сайт выдаёт ошибку - удалите код и обновите страницу (Ctrl+F5)
		'
    ),
    array(
        'icon' => WP01_Content::get_image_src('icons/3/disqus-conditional-load_m.jpg'),
        'name' => 'Disqus Conditional Load',
        'path' => 'disqus-conditional-load/disqus-conditional-load.php',
        'desc' => 'Отложенная загрузка комментариев в плагине Disqus <span id="server-ip-memory-usage"></span>',
        'rate' => 1,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text' => 'Активен, настроить',
        'settings_link' => '/admin.php?page=dcl-settings',
    ),
	array(
        'icon' => WP01_Content::get_image_src('icons/3/server-ip-memory-usage_m.jpg'),
        'name' => 'Server IP & Memory Usage Display',
        'path' => 'server-ip-memory-usage/server-ip-memory-usage.php',
        'analogs' =>  array(
            array(
                'name' => 'Memory Usage Bar',
                'icon' => WP01_Content::get_image_src('icons/3/memory-usage-bar_s.jpg'),
                'path' => 'memory-usage-bar/memory-usage-bar.php',
                'settings_link'  => '',
            ),
            array(
                'name' => 'WordPress WP Memory Limit, Memory Usage and Health Plugin',
                'icon' => WP01_Content::get_image_src('icons/3/wp-memory_s.jpg'),
                'path' => 'wp-memory/wpmemory.php',
                'settings_link'  => '/site-health.php?tab=debug',
            )
        ),
        'desc' => 'Отображение лимита памяти (серверного и WordPress)',
        'rate' => 1,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text' => 'Активен, настроить',
        'settings_link' => '',
    ),
    array(
        'icon' => WP01_Content::get_image_src('icons/3/usagedd_m.jpg'),
        'name' => 'UsageDD',
        'path' => 'usagedd/usagedd.php',
        'analogs' =>  array(
            array(
                'name' => 'Query Monitor',
                'icon' => WP01_Content::get_image_src('icons/3/query-monitor_s.jpg'),
                'path' => 'query-monitor/query-monitor.php',
                'settings_link'  => '',
            )
        ),
        'desc' => 'Отображение на страницах: времени генерации (TTFB и финального), <br>использования RAM, количества запросов к базе данных',
        'rate' => 1,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text' => 'Активен, настроить',
        'settings_link' => '',
		'code_replace' => '
<strong>Отображение на страницах запросов, времени генерации, использования RAM:</strong><br>
1. Откройте файл footer.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">LuckyWP Scripts Control</a> (Шаг 6)<br>
2. Добавьте до тега &lt;/body&gt; код (информация будет видна только администратору):<br>
<div class="tc">
	/* WP01: Отображение в подвале страницы: запросов, времени генерации, RAM */<br>
	&lt;?php<br>
	if ( is_user_logged_in() &amp;&amp; current_user_can(&#039;administrator&#039;) ){<br>
	?&gt;<br>
    &lt;small&gt;<br>
        &amp;nbsp; &lt;?php echo get_num_queries(); ?&gt; запросов | &lt;?php timer_stop(1); ?&gt; секунд | <br>
        &lt;?php echo round (memory_get_usage ()/1024/1024, 2) ?&gt; mb<br>
    &lt;/small&gt;<br>
	&lt;?php<br>
	}<br>
	?&gt;<br><br>
</div>
<strong>Примечание:</strong><br>
1. В случае обновления темы повторите установку кода (не актуально при использовании плагина для добавления кода)<br>
2. Если после установки кода сайт выдаёт ошибку - удалите код и обновите страницу (Ctrl+F5)
		'
    ),
    array(
        'icon' => WP01_Content::get_image_src('icons/3/remove-jquery-migrate_m.jpg'),
        'name' => 'Remove jQuery Migrate',
        'path' => 'remove-jquery-migrate/remove-jquery-migrate.php',
        'desc' => 'Отключает jQuery Migrate (jquery-migrate.js или jquery-migrate.min.js)',
        'rate' => 2,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text' => 'Активен, настроить',
        'settings_link' => '',
		'replace_level' => 'Полная',
		'code_replace' => '
<strong>Отключение "jquery-migrate.min.js":</strong><br>
1. Откройте файл functions.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">Code Snippets</a> (Шаг 6)<br>
2. Добавьте строчки:<br>
<div class="tc">
	/* WP01: Отключение jquery-migrate.min.js */<br>
	function remove_jq_migrate( $scripts ) {<br>
	if ( ! is_admin() &amp;&amp; isset( $scripts-&gt;registered[&#039;jquery&#039;] ) ) {<br>
	$script = $scripts-&gt;registered[&#039;jquery&#039;];<br>
	if ( $script-&gt;deps ) {<br>
	$script-&gt;deps = array_diff( $script-&gt;deps, array( &#039;jquery-migrate&#039; ) );<br>
	}<br>
	}<br>
	}<br>
	add_action( &#039;wp_default_scripts&#039;, &#039;remove_jq_migrate&#039; );<br><br>
</div>
<strong>Примечание:</strong><br>
1. В случае обновления темы повторите установку кода (не актуально при использовании плагина для добавления кода)<br>
2. Если после установки кода сайт выдаёт ошибку - удалите код и обновите страницу (Ctrl+F5)
		'		
    ),
    array(
        'icon' => WP01_Content::get_image_src('icons/3/version-control-for-jquery_m.jpg'),
        'name' => 'Version Control for jQuery',
        'path' => 'version-control-for-jquery/init.php',
        'desc' => 'Управление версиями jQuery Core/Migrate и их подключение из jQuery CDN.<br> <strong>Рекомендуем:</strong> <a href="https://wordpress.org/plugins/enable-jquery-migrate-helper/" target="_blank">выявление несовместимости плагинов c new jQuery</a> (WP &ge; 5.4)',
        'rate' => 1,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text' => 'Активен, настроить',
        'settings_link' => '/options-general.php?page=version_control_for_jquery',
    ),
    array(
        'icon' => WP01_Content::get_image_src('icons/3/css-js-manager_m.jpg'),
        'name' => 'CSS JS Manager, Async JavaScript, Defer Render Blocking CSS',
        'path' => 'css-js-manager/css-js-manager.php',
        'desc' => 'Исключение выборочных js/css из кода по условию, применение Defer/Async метода загрузки',
        'rate' => 1,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a><br>Документация:<br> 
<a href="https://www.piwebsolution.com/css-js-manager-documentation/" target = "_blank"><strong>ENG</strong></a> &nbsp; 
<a href="https://translate.google.com/translate?sl=auto&tl=ru&u=https://www.piwebsolution.com/css-js-manager-documentation/" target = "_blank"><strong>RUS(GT)</strong></a> &nbsp; 
<a href="https://translate.yandex.ru/translate?lang=en-ru&url=https://www.piwebsolution.com/css-js-manager-documentation/" target = "_blank"><strong>RUS(YT)</strong></a><br>',
        'settings_text' => 'Активен, настроить',
        'settings_link' => '/admin.php?page=css-js-manager',
    ),
    array(
        'icon' => WP01_Content::get_image_src('icons/3/http2-push-content_m.jpg'),
        'name' => 'HTTP2 push content',
        'path' => 'http2-push-content/http2-push-content.php',
        'analogs' =>  array(
            array(
                'name' => 'Better Resource Hints',
                'icon' => WP01_Content::get_image_src('icons/3/better-resource-hints_s.jpg'),
                'path' => 'better-resource-hints/better-resource-hints.php',
                'settings_link'  => '/options-general.php?page=better_resource_hints',
            )
        ),		
        'desc' => 'Push/Preload для css/js и других элементов сайта',
        'rate' => 1,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text' => 'Активен, настроить',
        'settings_link' => '/admin.php?page=http2-push-content',
    ),
    array(
        'icon' => WP01_Content::get_image_src('icons/3/wp-mobile-detect_m.jpg'),
        'name' => 'WP Mobile Detect',
        'path' => 'wp-mobile-detect/wp-mobile-detect.php',
        'analogs' =>  array(
            array(
                'name' => 'mobble',
                'icon' => WP01_Content::get_image_src('icons/3/mobble_s.jpg'),
                'path' => 'mobble/mobble.php',
                'settings_link'  => '/options-general.php?page=better_resource_hints',
            )
        ),	
        'desc' => 'Показ уникального контента для ПК/мобильных устройств',
        'rate' => 1,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
		'settings_text' => 'Активен, используйте шорткоды',
        'settings_link' => '',
		'code_replace' => '
<strong>Скрываем информацию на мобильных устройствах с помощью шорткода</strong><br>
1. Откройте файл functions.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">Code Snippets</a> (Шаг 6)<br>
2. Добавьте код:<br>
<div class="tc">
	/* WP01: Скрытие информации по шорткоду в мобильных устройствах */<br>
		function mobil_no_content($atts, $content = null) {<br>
		if (wp_is_mobile() &amp;&amp; !is_null($content)){<br>
		return &#039;&#039;;<br>
		}<br>
		return do_shortcode($content);<br>
		}<br>
		add_shortcode( &#039;nomobil&#039;, &#039;mobil_no_content&#039;);<br>
</div>
3. Используйте шорткод:<br>
[nomobil]информация не отображающаяся в мобильных[/nomobil]<br><br>

<strong>Скрываем информацию на мобильных/ПК с помощью CSS (с осторожностью)</strong><br>
1. Откройте файл functions.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">Code Snippets</a> (Шаг 6)<br>
2. Добавьте код:<br>
<div class="tc">
	/* WP01: Скрытие информации на мобильных/ПК через CSS */<br>
		add_action( &#039;wp_head&#039;, function () { ?&gt;<br>
		&lt;style&gt;<br>
		/* --------Видимый на ПК контент--------- */<br>
		@media screen and (max-width: 600px) {<br>
		.hidemobile {<br>
			visibility: hidden;<br>
			display: none;<br>
			}<br>
		}<br>
		/* --------Видимый на мобильных контент--------- */<br>
		.showmobile { display: none; }<br>
		@media only screen<br>
		and (min-device-width : 1px)<br>
		and (max-device-width : 600px){ .showmobile { display: inline; }}<br>
		&lt;/style&gt;<br>
		&lt;?php } );<br>
</div>
3. Используйте код в теле страницы для управления отображением контента:<br>
<div class="tc">
	&lt;div class=&quot;hidemobile&quot;&gt;<br>
		тут то, что показываем на ПК и скрываем на мобильных<br>
	&lt;/div&gt;<br>
	&lt;div class=&quot;showmobile&quot;&gt;<br>
		тут то, что показываем на мобильных и скрываем на ПК<br>
	&lt;/div&gt;<br><br>
</div>	

<strong>Скрываем информацию на мобильных/ПК в PHP файлах</strong><br>
1. Откройте PHP файл, находящийся в папке используемой темы (/wp-content/themes/название_темы/)<br>
2. Используйте код:<br>
<div class="tc">
	&lt;!-- WP01: Скрытие информации на мобильных/ПК в PHP файле --&gt;<br>
		&lt;?php if(wp_is_mobile()) { ?&gt;<br>
		тут то, что показываем на мобильных и скрываем на ПК<br>
		&lt;?php } else { ?&gt;<br>
		тут то, что показываем на ПК и скрываем на мобильных<br>
		&lt;?php } ?&gt;<br><br>
</div>
<strong>Примечание:</strong><br>
1. В случае обновления темы повторите установку кода (не актуально при использовании плагина для добавления кода)<br>
2. Если после установки кода сайт выдаёт ошибку - удалите код и обновите страницу (Ctrl+F5)<br>
		'
	),		
    array(
        'icon' => WP01_Content::get_image_src('icons/3/true-lazy-analytics_m.jpg'),
        'name' => 'True Lazy Analytics',
        'path' => 'true-lazy-analytics/true-lazy-analytics.php',
        'desc' => 'Отложенная загрузка для Google Analytics, Facebook Pixel, Hotjar, Яндекс Метрики и счётчика Liveinternet<br> <strong>Рекомендуем:</strong> <a href="https://support.google.com/analytics/answer/1032399?hl=ru" target="_blank">проверка работы Google Analytics</a> и <a href="https://yandex.ru/support/metrica/general/check-counter.html" target="_blank">проверка работы Яндекс Метрики</a>',
        'rate' => 2,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text' => 'Активен, настроить',
        'settings_link' => '/admin.php?page=true-lazy-analytics',
		'replace_level' => 'Полная',
		'code_replace' => '
<strong>Отложите загрузку "Яндекс Метрика":</strong><br>
1. Откройте файл footer.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">LuckyWP Scripts Control</a> (Шаг 6)<br>
2. Добавьте до тега &lt;/body&gt; код заменив идентификатор на свой:<br>
<div class="tc">
	/* WP01: Отложенная загрузка Яндекс Метрика */<br>
&lt;script&gt;<br>
let leLoadedJs = false;<br>
window.addEventListener(&#039;scroll&#039;, getExtJs,{passive: true});<br>
window.addEventListener(&#039;touchstart&#039;, getExtJs);<br>
window.addEventListener(&#039;mousemove&#039;, getExtJs);<br>
window.addEventListener(&#039;click&#039;, getExtJs);<br>
window.addEventListener(&#039;keydown&#039;, getExtJs);<br>
setTimeout(getExtJs,200);<br>
function getExtJs(){<br>
    if (leLoadedJs === false) {<br>
        leLoadedJs = true;<br>
        window.removeEventListener(&#039;scroll&#039;, getExtJs, false);<br>
        window.removeEventListener(&#039;touchstart&#039;, getExtJs, false);<br>
        window.removeEventListener(&#039;mousemove&#039;, getExtJs, false);<br>
        window.removeEventListener(&#039;click&#039;, getExtJs, false);<br>
        window.removeEventListener(&#039;keydown&#039;, getExtJs, false);<br>
        setTimeout(function(){<br>
            // START: стандартный отрывок из кода Я.метрики<br>
            (function(m,e,t,r,i,k,a){m[i]=m[i]||function(){(m[i].a=m[i].a||[]).push(arguments)};<br>
		    m[i].l=1*new Date();k=e.createElement(t),a=e.getElementsByTagName(t)[0],k.async=1,k.src=r,a.parentNode.insertBefore(k,a)})<br>
		    (window, document, &quot;script&quot;, &quot;https://mc.yandex.ru/metrika/tag.js&quot;, &quot;ym&quot;);<br>
		    ym(<font color="red">12345678</font>, &quot;init&quot;, {<br>
			    id:<font color="red">12345678</font>,<br>
			    clickmap:true,<br>
			    trackLinks:true,<br>
			    accurateTrackBounce:true<br>
		    });<br>
			// END: стандартный отрывок из кода Я.метрики<br>
        }, 100);<br>
    }<br>
}<br>
&lt;/script&gt;<br><br>
</div>

<strong>Отложите загрузку "Яндекс Метрика" по действию:</strong><br>
1. Откройте файл footer.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">LuckyWP Scripts Control</a> (Шаг 6)<br>
2. Добавьте до тега &lt;/body&gt; код заменив идентификатор на свой:<br>
<div class="tc">
	/* WP01: Отложенная загрузка Яндекс Метрика по действию */<br>
	&lt;script&gt;<br>
	var lazyscriptstimer,lazyscriptsmove=[&#039;click&#039;,&#039;scroll&#039;,&#039;mousemove&#039;,&#039;mouseover&#039;,&#039;touchstart&#039;],lazyscriptsdelay=15000,userAgent = navigator.userAgent || navigator.vendor || window.opera,lazyscripts = function () {<br>
	lazyscriptcallback();lazyscriptsmove.map(function(n) {window.removeEventListener(n, lazyscripts, false);});clearTimeout(lazyscriptstimer);};lazyscriptsmove.map(function(n) {window.addEventListener(n, lazyscripts, false);});<br>
	if((self.parent&amp;&amp;!(self.parent===self))&amp;&amp;(self.parent.frames.length!=0)){lazyscriptsdelay=0;}if (userAgent.match( /yandex\.com\/bots/i)){lazyscriptsdelay=0;}lazyscriptstimer=setTimeout(lazyscripts,lazyscriptsdelay);<br>
	function lazyscriptcallback()<br>
	{<br>
	// START: стандартный отрывок из кода Я.метрики<br>
	   (function(m,e,t,r,i,k,a){m[i]=m[i]||function(){(m[i].a=m[i].a||[]).push(arguments)};<br>
	   m[i].l=1*new Date();k=e.createElement(t),a=e.getElementsByTagName(t)[0],k.async=1,k.src=r,a.parentNode.insertBefore(k,a)})<br>
	   (window, document, &quot;script&quot;, &quot;https://mc.yandex.ru/metrika/tag.js&quot;, &quot;ym&quot;);<br>
	   ym(<font color="red">12345678</font>, &quot;init&quot;, {<br>
			clickmap:true,<br>
			trackLinks:true,<br>
			accurateTrackBounce:true,<br>
			webvisor:true<br>
	   });<br>
	// END: стандартный отрывок из кода Я.метрики<br>
	}<br>
	&lt;/script&gt;<br><br>
</div>

<strong>Отложите загрузку "Google Analytics":</strong><br>
1. Откройте файл footer.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">LuckyWP Scripts Control</a> (Шаг 6)<br>
2. Добавьте до тега &lt;/body&gt; код заменив идентификатор на свой:<br>
<div class="tc">
	/* WP01: Отложенная загрузка Google Analytics */<br>
	&lt;script&gt;<br>
let leLoadedJs = false;<br>
window.addEventListener(&#039;scroll&#039;, getExtJs,{passive: true});<br>
window.addEventListener(&#039;touchstart&#039;, getExtJs);<br>
window.addEventListener(&#039;mousemove&#039;, getExtJs);<br>
window.addEventListener(&#039;click&#039;, getExtJs);<br>
window.addEventListener(&#039;keydown&#039;, getExtJs);<br>
setTimeout(getExtJs,200);<br>
function getExtJs(){<br>
    if (leLoadedJs === false) {<br>
        leLoadedJs = true;<br>
        window.removeEventListener(&#039;scroll&#039;, getExtJs, false);<br>
        window.removeEventListener(&#039;touchstart&#039;, getExtJs, false);<br>
        window.removeEventListener(&#039;mousemove&#039;, getExtJs, false);<br>
        window.removeEventListener(&#039;click&#039;, getExtJs, false);<br>
        window.removeEventListener(&#039;keydown&#039;, getExtJs, false);<br>
        setTimeout(function() {<br>
            var GTMObject = document.createElement(&quot;script&quot;);<br>
    		GTMObject.src = &#039;https://www.googletagmanager.com/gtag/js?id=<font color="red">UA-123456789-1</font>&#039;;<br>
    		GTMObject.async = true;<br>
    		document.getElementsByTagName(&#039;head&#039;)[0].appendChild(GTMObject);<br>
    		window.dataLayer = window.dataLayer || [];<br>
    		function gtag(){dataLayer.push(arguments);}<br>
    		gtag(&#039;js&#039;, new Date());<br>
    		gtag(&#039;config&#039;, &#039;<font color="red">UA-123456789-1</font>&#039;);<br>
        }, 100);<br>
    }<br>
}<br>
&lt;/script&gt;<br><br>
</div>

<strong>Отложите загрузку внешних скриптов:</strong><br>
1. Откройте файл footer.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">LuckyWP Scripts Control</a> (Шаг 6)<br>
2. Добавьте до тега &lt;/body&gt; код заменив идентификатор на свой:<br>
<div class="tc">
	/* WP01: Отложенная загрузка внешних скриптов */<br>
	&lt;script&gt;<br>
let leLoadedJs = false;<br>
window.addEventListener(&#039;scroll&#039;, getExtJs,{passive: true});<br>
window.addEventListener(&#039;touchstart&#039;, getExtJs);<br>
window.addEventListener(&#039;mousemove&#039;, getExtJs);<br>
window.addEventListener(&#039;click&#039;, getExtJs);<br>
window.addEventListener(&#039;keydown&#039;, getExtJs);<br>
setTimeout(getExtJs,200);<br>
function getExtJs(){<br>
    if (leLoadedJs === false) {<br>
        leLoadedJs = true;<br>
        window.removeEventListener(&#039;scroll&#039;, getExtJs, false);<br>
        window.removeEventListener(&#039;touchstart&#039;, getExtJs, false);<br>
        window.removeEventListener(&#039;mousemove&#039;, getExtJs, false);<br>
        window.removeEventListener(&#039;click&#039;, getExtJs, false);<br>
        window.removeEventListener(&#039;keydown&#039;, getExtJs, false);<br>
        setTimeout(function() {<br>
				// START<br>
				// код внешних скриптов (всё, что между &lt;script&gt; и &lt;/script&gt;)<br>
				// END<br>
        }, 100);<br>
    }<br>
}<br>
&lt;/script&gt;<br><br>
</div>

<strong>Примечание:</strong><br>
1. В случае обновления темы повторите установку кода (не актуально при использовании плагина для добавления кода)<br>
2. Если после установки кода сайт выдаёт ошибку - удалите код и обновите страницу (Ctrl+F5)<br>
3. Значение "webvisor:true" для "Яндекс Метрика" отвечает за активацию "Вебвизор, карта скроллинга, аналитика форм". Если вы не планируете использовать вебвизор - просто удалите данную строчку<br>
4. Строчка "}, 100);" отвечает за время отложенной загрузки, в миллисекундах<br>
5. Отложенная загрузка "Яндекс Метрика" по действию осуществляет загрузку кода при наступлении события: click, scroll, mousemove, mouseover, touchstart
'
	),		
    array(
        'icon' => WP01_Content::get_image_src('icons/3/advanced-cron-manager_m.jpg'),
        'name' => 'Advanced Cron Manager — debug & control',
        'path' => 'advanced-cron-manager/advanced-cron-manager.php',
        'analogs' =>  array(
            array(
                'name' => 'WP Crontrol',
                'icon' => WP01_Content::get_image_src('icons/3/wp-crontrol_s.jpg'),
                'path' => 'wp-crontrol/wp-crontrol.php',
                'settings_link'  => '/tools.php?page=crontrol_admin_manage_page',
            ),				
            array(
                'name' => 'Cron Jobs',
                'icon' => WP01_Content::get_image_src('icons/3/leira-cron-jobs_s.jpg'),
                'path' => 'leira-cron-jobs/leira-cron-jobs.php',
                'settings_link'  => '/tools.php?page=leira-cron-jobs',
            )
        ),
        'desc' => 'Управление задачами планировщика (cron) и зарегистрированными расписаниями',
        'rate' => 2,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text' => 'Активен, настроить',
        'settings_link' => '/tools.php?page=advanced-cron-manager',
		'replace_level' => 'Частичная',
		'code_replace' => '
<font color="red">Внимание!</font><br>
Полное отключение крона приведет к ошибкам в работе CMS и плагинов.<br><br>		
<strong>Полное отключение запуска "wp-cron.php":</strong><br>

1. Добавьте в файл "wp-config.php" перед строчкой "/* Это всё..." :<br>
<code>define( &#039;DISABLE_WP_CRON&#039;, true );</code><br>
2. Отключить вывод ошибок<br>
Добавьте в файл "wp-config.php" перед строчкой "/* Это всё..." :<br>
	<code>ini_set(&#039;display_errors&#039;,&#039;Off&#039;);<br>
	ini_set(&#039;error_reporting&#039;, E_ALL );<br>
	define(&#039;WP_DEBUG&#039;, false);<br>
	define(&#039;WP_DEBUG_DISPLAY&#039;, false);</code><br>
			или альтернативный вариант:<br>
	<code>ini_set(&#039;display_errors&#039;,&#039;Off&#039;);<br>
	ini_set(&#039;error_reporting&#039;,0);</code><br><br>

<strong>Переназначьте выполнение крона:</strong><br>
1. После полного отключения запуска "wp-cron.php" перейдите в планировщик в панели управления на вашем хостинге (для ISP: Главное -> Планировщик).<br>
2. Добавьте с периодичностью от 5 минут до нескольких часов (в зависимости от нагрузки на ресурсы хостинга) выполнение команды:<br>
<code>wget -q -O - https://<font color="red">SAIT.RU</font>/wp-cron.php &gt; /dev/null 2&gt;&amp;1</code><br>
	или альтернативный вариант:<br>
<code>curl &quot;https://<font color="red">SAIT.RU</font>/wp-cron.php?doing_wp_cron&quot;</code><br><br>

<strong>Уточнения:</strong><br>
1. wp-cron.php - скрипт выполняющий обработку запланированных задач в WordPress<br>
2. Полное отключение крона оправдано лишь при чрезмерных нагрузках на сайт в связи с частым обращением к "wp-cron.php"<br>
3. Проблемы с настройкой планировщика на хостинге? Используйте запуск крона по ссылке <code>http://domen.com/wp-cron.php?doing_wp_cron</code> через один из cron-сервисов:<br>
<a href="https://cron-job.org/en/" target = "_blank">https://cron-job.org/en/</a> - полностью бесплатный<br>
<a href="http://www.onlinecronjobs.com/" target = "_blank">http://www.onlinecronjobs.com/</a> - есть бесплатный тариф с ограничениями<br>
<a href="https://cronless.com/" target = "_blank">https://cronless.com/</a>  - есть бесплатный тариф с ограничениями<br>
4. Для изучения обращений к "wp-cron.php" рекомендуем изучить log-файл, например, через программу <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">Logmaster</a> (Шаг 6)<br>
5. Проверить работу Cron можно создав запись, отложенная публикация которой по времени предшествует запуску крона по ссылке/команде. При успешном размещении записи крон будет считаться выполненным.
'
	),		
    array(
        'icon' => WP01_Content::get_image_src('icons/3/host-webfonts-local_m.jpg'),
        'name' => 'OMGF | Host Google Fonts Locally',
        'path' => 'host-webfonts-local/host-webfonts-local.php',
        'analogs' =>  array(
            array(
                'name' => 'Embed Google Fonts',
                'icon' => WP01_Content::get_image_src('icons/3/embed-google-fonts_s.jpg'),
                'path' => 'embed-google-fonts/embed-google-fonts.php',
                'settings_link'  => '',
            ),				
            array(
                'name' => 'Self-Hosted Google Fonts',
                'icon' => WP01_Content::get_image_src('icons/3/selfhost-google-fonts_s.jpg'),
                'path' => 'selfhost-google-fonts/selfhost-google-fonts.php',
                'settings_link'  => '/options-general.php?page=sgf_options',
            )
        ),
        'desc' => 'Перенос шрифтов с fonts.googleapis.com и fonts.gstatic.com в локальную папку сайта с последующим их подключением',
        'rate' => 2,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text' => 'Активен, настроить',
        'settings_link' => '/options-general.php?page=optimize-webfonts',
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

<h3>III. Ручные внедрения</h3>
<p>Произведите установку/правку кода в соответствии с необходимой задачей</p>

<h4>1. Уменьшите количество ревизий записей, установите интервал автосохранений</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Установите условия</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong>Выполните действия:</strong><br>
1. Откройте файл "wp-config.php" (находится в корневой директории сайта)<br>
2. После указания <code>define('WP_DEBUG', false);</code> с новой строчки пропишите:<br>
&nbsp; &nbsp; <code>define('WP_POST_REVISIONS', 5);</code><br>
&nbsp; &nbsp; <code>define('AUTOSAVE_INTERVAL', 300);</code>
<br>
    </div>
</div>

<h4>2. Активируйте кэширование</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Пропишите в файле .htaccess правила</div>
    <div class="collapse-body" style="display: none;">
            <pre>#WP01_CACHING_START
# Кэширование
&lt;ifModule mod_headers.c&gt;
# кэшировать html и htm файлы на 12 часов
   &lt;FilesMatch "\.(html|htm)$"&gt;
Header set Cache-Control "max-age=43200"
   &lt;/FilesMatch&gt;
# кэшировать css, javascript и текстовые файлы на одну неделю
   &lt;FilesMatch "\.(js|css|txt)$"&gt;
   Header set Cache-Control "max-age=604800"
   &lt;/FilesMatch&gt;
# кэшировать флэш и изображения на 1 год
   &lt;FilesMatch "\.(flv|swf|ico|gif|jpg|jpeg|png|webp)$"&gt;
   Header set Cache-Control "max-age=31536000"
   &lt;/FilesMatch&gt;
# кэшировать шрифты на 1 год
   &lt;FilesMatch "\.(eot|ttf|otf|svg|woff|woff2)$"&gt;
   Header set Cache-Control "max-age=31536000, public"
   &lt;/FilesMatch&gt;
# отключить кэширование для определенных расширений
   &lt;FilesMatch "\.(pl|php|cgi|spl|scgi|fcgi)$"&gt;
   Header unset Cache-Control
   &lt;/FilesMatch&gt;
&lt;/IfModule&gt;

# Условия кэширования
&lt;ifModule mod_expires.c&gt;
   ExpiresActive On
#по умолчанию кеш в 5 секунд
   ExpiresDefault "access plus 5 seconds"
#кэшировать флэш и изображения на 1 год
   ExpiresByType image/x-icon "access plus 31536000 seconds"
   ExpiresByType image/jpeg "access plus 31536000 seconds"
   ExpiresByType image/jpg "access plus 31536000 seconds"
   ExpiresByType image/png "access plus 31536000 seconds"
   ExpiresByType image/gif "access plus 31536000 seconds"
   ExpiresByType application/x-shockwave-flash "access plus 31536000 seconds"
   ExpiresByType image/webp "access plus 31536000 seconds"
# кэшировать шрифты на 1 год
   ExpiresByType application/x-font-ttf "access plus 31536000 seconds"
   ExpiresByType font/opentype "access plus 31536000 seconds"
   ExpiresByType application/x-font-woff "access plus 31536000 seconds"
   ExpiresByType application/x-font-woff2 "access plus 31536000 seconds"
   ExpiresByType image/svg+xml "access plus 31536000 seconds"
   ExpiresByType application/vnd.ms-fontobject "access plus 31536000 seconds"
#кэшировать css, javascript и текстовые файлы на одну неделю
   ExpiresByType text/css "access plus 604800 seconds"
   ExpiresByType text/javascript "access plus 604800 seconds"
   ExpiresByType application/javascript "access plus 604800 seconds"
   ExpiresByType application/x-javascript "access plus 604800 seconds"
#кэшировать html и htm файлы на 12 часов
   ExpiresByType text/html "access plus 43200 seconds"
#кэшировать xml файлы на десять минут
   ExpiresByType application/xhtml+xml "access plus 600 seconds"
&lt;/ifModule&gt;
#WP01_CACHING_END</pre>
    </div>
</div>

<h4>3. Сжатие файлов перед отправкой пользователю</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Пропишите в файле .htaccess правила</div>
    <div class="collapse-body" style="display: none;">
            <pre>#WP01_COMPRESSING_START
&lt;IfModule mod_deflate.c&gt;
# Сжатие HTML, CSS, JavaScript, текста, XML и шрифтов
   AddOutputFilterByType DEFLATE application/javascript
   AddOutputFilterByType DEFLATE application/rss+xml
   AddOutputFilterByType DEFLATE application/vnd.ms-fontobject
   AddOutputFilterByType DEFLATE application/x-font
   AddOutputFilterByType DEFLATE application/x-font-opentype
   AddOutputFilterByType DEFLATE application/x-font-otf
   AddOutputFilterByType DEFLATE application/x-font-truetype
   AddOutputFilterByType DEFLATE application/x-font-ttf
   AddOutputFilterByType DEFLATE application/font-woff
   AddOutputFilterByType DEFLATE application/x-javascript
   AddOutputFilterByType DEFLATE application/xhtml+xml
   AddOutputFilterByType DEFLATE application/xml
   AddOutputFilterByType DEFLATE font/opentype
   AddOutputFilterByType DEFLATE font/otf
   AddOutputFilterByType DEFLATE font/ttf
   AddOutputFilterByType DEFLATE font/woff
   AddOutputFilterByType DEFLATE font/eot
   AddOutputFilterByType DEFLATE image/svg+xml
   AddOutputFilterByType DEFLATE image/x-icon
   AddOutputFilterByType DEFLATE image/ico
   AddOutputFilterByType DEFLATE image/webp
   AddOutputFilterByType DEFLATE text/css
   AddOutputFilterByType DEFLATE text/html
   AddOutputFilterByType DEFLATE text/javascript
   AddOutputFilterByType DEFLATE text/plain
   AddOutputFilterByType DEFLATE text/xml
&lt;/IfModule&gt;
#WP01_COMPRESSING_END</pre>
    </div>
</div>

<h4>4. Используйте свежую версию PHP поддерживаемую WordPress</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Выполните рекомендации</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong><font color="red">Внимание!</font></strong><br>
Очень часто переход на более свежую версию PHP вызывает ошибки в работе плагинов, темы и/или CMS.<br>
Рекомендуем производить смену PHP версии непосредственно программистом.<br>
Официальные рекомендации WordPress: <a href="https://ru.wordpress.org/support/update-php/" target="_blank">https://ru.wordpress.org/support/update-php/</a><br>
<br>
<strong>Быстродействие* WordPress 5.3 на разных версиях PHP:</strong><br>
<table width="360" border="1" cellspacing="0" cellpadding="1">
           <tr align="center"><th width="25%">версия PHP</th><th width="30%">запросов/сек</th><th width="45%">быстрее, чем PHP 5.6</th></tr>
           <tr align="center"><td>5.6</td><td>97,71</td><td>в 0 раз</td></tr>
           <tr align="center"><td>7.0</td><td>256,81</td><td>в 2,63 раз</td></tr>
           <tr align="center"><td>7.1</td><td>256,99</td><td>в 2,63 раз</td></tr>
           <tr align="center"><td>7.2</td><td>273,07</td><td>в 2,79 раз</td></tr>
           <tr align="center"><td>7.3</td><td>305,59</td><td>в 3,13 раз</td></tr>
           <tr align="center"><td>7.4</td><td>313,42</td><td>в 3,21 раз</td></tr>
</table> 
<strong>Вывод:</strong> PHP 7.4 в 3,21 раза быстрее (больше обрабатывает запросов в секунду), чем PHP 5.6<br>
* по данным WPGutenberg<br>
<br>
<strong>Подтвержденная поддержка:</strong><br>
с WordPress 5.2: PHP 5.6.20-7.3<br>
с WordPress 5.3: PHP 5.6.20-7.4<br>
<br>
<strong>Алгоритм изменения версии PHP:</strong><br>
&nbsp; 1. Проверьте совместимость тем и плагинов с более свежей версией PHP с помощью "<a href="https://ru.wordpress.org/plugins/php-compatibility-checker/" target="_blank">PHP Compatibility Checker</a>"<br>
&nbsp; 2. Перейдите в панель управления вашим хостингом (например, ISPmanager)<br>
&nbsp; 3. В настройках сайта постепенно (например, 5.4 -> 5.5 -> 5.6 -> 7.0) увеличивайте версию PHP до максимально поддерживаемой (по данным "PHP Compatibility Checker"), параллельно тестируя проект на наличие ошибок<br>
&nbsp; 4. Если при активации более свежей версии PHP на сайте появляются ошибки - верните версию к ранее используемой, при необходимости обратитесь в техподдержку хостинга<br>
<br>
<strong>Справка:</strong><br>
На данный момент максимально поддерживаемая системой WordPress PHP версия 7.4
<br>
    </div>
</div>

<h4>5. Оптимизируйте png/jpg/gif изображения</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Воспользуйтесь online/offline инструментами</div>
    <div class="collapse-body" style="display: none;">
            <pre><a href="https://imagecompressor.com/ru/" target="_blank">https://imagecompressor.com/ru/</a> - оптимизация с управлением качества до 20 PNG/JPG изображений за 1 раз.</pre>
			<pre><a href="https://tinypng.com/" target="_blank">https://tinypng.com/</a> - оптимизация (автоматический выбор качества) до 20 PNG/JPG изображений (максимум 5 Мб.) за 1 раз.</pre>
			<pre><a href="https://www.onlineimagetool.com/ru/compress-png-jpg-webp-gif" target="_blank">https://www.onlineimagetool.com/ru/</a> - оптимизация PNG/JPG/WEBP/GIF изображений (без ограничений по количеству).</pre>
			<pre><a href="https://compressor.io/" target="_blank">https://compressor.io/</a> - оптимизация с выбором типа сжатия до 100 JPEG, PNG, SVG, GIF и WEBP изображений (или 10 Мб.) за 1 раз.</pre>			
			<pre><a href="https://gifcompressor.com/ru/" target="_blank">https://gifcompressor.com/ru/</a> - оптимизация до 20 GIF изображений за 1 раз.</pre>			
			<pre><a href="https://www.leapic.com/free-gif-optimizer.htm" target="_blank">GIF Optimizer</a> - программа (OS Windows) для оптимизации GIF (работает с 1 файлом за 1 раз).</pre>	
			<pre><a href="http://www.romeolight.com/products/gifmicro/" target="_blank">GIFmicro</a> - программа (OS Windows) для оптимизации GIF (массовая работа).</pre>	
 </div>
</div>

<h4>6. Оптимизируйте SVG изображения</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Воспользуйтесь online сервисами</div>
    <div class="collapse-body" style="display: none;">
			<pre><a href="https://vecta.io/nano" target="_blank">Nano SVG</a> - автоматическая оптимизация до 10 изображений (максимум 5 Мб.) за 1 раз.</pre>
			<pre><a href="https://jakearchibald.github.io/svgomg/" target="_blank">SVG Optimizer (Jake Archibald)</a> - пошаговая оптимизация 1 изображения.</pre>
			<pre><a href="https://petercollingridge.appspot.com/svg-optimiser" target="_blank">SVG Optimizer (Peter Collingridge)</a> - оптимизация 1 изображения с возможностью определения детализации.</pre>
			<pre><a href="https://compressor.io/" target="_blank">COMPRESSOR</a> - оптимизация с выбором типа сжатия до 100 SVG изображений (или 10 Мб.) за 1 раз.</pre>			
 </div>
</div>

<h4>7. Оптимизируйте файл иконок</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Воспользуйтесь online конструктором</div>
    <div class="collapse-body" style="display: none;">
<br>
Довольно часто в теме сайта используется собственный (не с fonts.gstatic.com) файл иконок, который содержит огромное количество векторных изображений.<br>
Хорошая практика - использовать только нужные иконки.<br>
<br>
<strong>Создание оптимизированного файла иконок:</strong><br>
1. В сервисе <a href="http://fontello.com/" target="_blank">http://fontello.com/</a> выберите используемый на вашем сайте набор иконок (например, Font Awesome).<br>
2. Отметьте нужные иконки в наборе и нажмите "Download webfont" для сохранения.<br>
3. Разместите сгенерированный файл в папку с нахождением иконок (например, wp-content/themes/имя_темы/assets/fonts)<br>
<br>
<strong>Примечание:</strong><br>
1. Обязательно создайте бэкап дефолтного файла набора иконок перед его заменой на сгенерированный.<br>
2. Если вы не знаете где находится файл иконок - изучите данные отчета Google PageSpeed Insights.<br>
Как правило, в пункте "Сократите глубину вложенности критических запросов" или в "Настройте показ всего текста во время загрузки веб-шрифтов" вы найдёте ссылку на файл иконок (например, fontawesome-webfont) с расширением woff2 или woff/ttf. 

    </div>
</div>

<h4>8. Предотвратите хотлинки на изображения</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Пропишите в файле .htaccess правила</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong><font color="red">Внимание!</font></strong><br>
Обязательно замените "SAIT.RU" на адрес вашего сайта (без http:// и www)
<br>
            <pre>#WP01_HOTLINKS_START
&lt;IfModule mod_rewrite.c&gt;
   RewriteEngine on
   RewriteCond %{HTTP_REFERER} !^$
#исключаем наш сайт
   RewriteCond %{HTTP_REFERER} !^http(s)?://(www\.)?<font color="red">SAIT.RU</font> [NC]
#добавляем домены в исключения
   RewriteCond %{HTTP_REFERER} !^http(s)?://(www\.)?google.com [NC]
   RewriteCond %{HTTP_REFERER} !^http(s)?://(www\.)?yandex.ru [NC]
   RewriteCond %{HTTP_REFERER} !^http(s)?://(www\.)?mail.ru [NC]
   RewriteCond %{HTTP_REFERER} !^http(s)?://(www\.)?subscribe.ru [NC]
   RewriteCond %{HTTP_REFERER} !^http(s)?://(www\.)?feedburner.com [NC]
   RewriteCond %{HTTP_REFERER} !^http(s)?://(www\.)?rambler.ru [NC]
   RewriteCond %{HTTP_REFERER} !^http(s)?://(www\.)?bing.com [NC]
   RewriteCond %{HTTP_REFERER} !^http(s)?://(www\.)?ask.com [NC]
   RewriteCond %{HTTP_REFERER} !^http(s)?://(www\.)?yahoo.com [NC]
   RewriteCond %{HTTP_REFERER} !^http(s)?://(www\.)?tut.by [NC]
   RewriteCond %{HTTP_REFERER} !^http(s)?://(www\.)?webalta.ru [NC]
   RewriteCond %{HTTP_REFERER} !^http(s)?://(www\.)?qip.ru [NC]
   RewriteCond %{HTTP_REFERER} !^http(s)?://(www\.)?poisk.ru [NC]
   RewriteCond %{HTTP_REFERER} !^http(s)?://(www\.)?ukr.net [NC]
   RewriteCond %{HTTP_REFERER} !^http(s)?://(www\.)?metabot.ru [NC]
#форматы, которые обрабатываем
   RewriteRule \.(jpg|jpeg|png|gif)$ - [NC,F,L]
&lt;/IfModule&gt;
#WP01_HOTLINKS_END</pre>
    </div>
</div>

<h4>9. Настройте показ всего текста во время загрузки веб-шрифтов</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Внесите правки в CSS файлы темы</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong>Дополните "@font-face" условиями:</strong><br>
1. Установите плагин "<a href="https://wordpress.org/plugins/string-locator/" target="_blank">String locator</a>" и перейдите в его <a href="/tools.php?page=string-locator" target="_blank">настройки</a><br>
2. Выберите в пункте "Search through" плагина активную тему сайта<br>
3. Введите в поле "Search string" значение "@font-face" и нажмите "Search"<br>
4. Поиск отразит в таблице файлы и номера строк, где были найдены значения "@font-face"<br>
5. Внесите правки во все значения "@font-face":<br>
5.1. Добавьте "local(&#039;Pacifico Regular&#039;), local(&#039;Pacifico-Regular&#039;)," после "src:"<br>
5.2. Добавьте "font-display: swap;" перед "}"<br>
5.3. Сохраните файл, проверьте работу сайта<br>
<br>
<strong>Примечание:</strong><br>
1. Обязательно создайте бэкап редактируемых CSS файлов, или активной темы<br>
2. В случае обновления темы повторите установку кода
    </div>
</div>

<h4>10. Настройте предварительную загрузку веб-шрифтов</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Задайте условия загрузки</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong>Используйте "preload" условия:</strong><br>
1. Откройте файл header.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/)<br>
2. Добавьте до тега &lt;/head&gt; код:<br>
<code>&lt;link rel=&quot;preload&quot; as=&quot;font&quot; href=&quot;<font color="red">УРЛ адрес до веб-шрифта</font>&quot; type=&quot;font/<font color="red">woff2</font>&quot; crossorigin&gt;</code>
<br>
<br><strong>Примечание:</strong><br>
1. Обязательно создайте бэкап редактируемого файла<br>
2. В случае обновления темы повторите установку кода<br>
3. Не забудьте заменить значение "УРЛ адрес до веб-шрифта" и MIME-тип
    </div>
</div>

<h4>11. Увеличьте лимит памяти для сценариев</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Пропишите увеличенные значения</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong>Внесите правки:</strong><br>
1. Уточните текущий лимит памяти для сценариев, установив плагин "<a href="#server-ip-memory-usage">Server IP & Memory Usage Display</a>" (доступен в таблице выше)<br>
2. Допишите в файл wp-config.php (находится в корне сайта), перед строкой "/* Это всё, дальше не редактируем. Успехов! */" условие:<br>
<code>define( &#039;WP_MEMORY_LIMIT&#039;, &#039;<font color="red">xyz</font>M&#039; );</code><br>
где "xyz" - значение, превосходящее текущий лимит, но не больше, чем предоставленно хостингом.<br> 
3. Проверьте сработку условия через установленный плагин (шаг 1).
<br>

<br><strong>Рекомендации:</strong><br>
1. Обязательно создайте бэкап редактируемого файла<br>
2. Для сайтов с низкой нагрузкой минимально рекомендуемое значение WP_MEMORY_LIMIT составляет 64. При установленном WooCommerce - 96<br>
3. Если условие не применилось - попробуйте прописать код без пробелов: <code>define(&#039;WP_MEMORY_LIMIT&#039;, &#039;<font color="red">xyz</font>M&#039;);"</code> или измените <code>memory_limit= <font color="red">xyz</font>M</code> в php.ini файле хостинга.<br>
4. При ошибке ограничения памяти в админ панели WordPress - пропишите <code>define( &#039;WP_MAX_MEMORY_LIMIT&#039;, &#039;<font color="red">xyz</font>M&#039; );</code> перед строкой "/* Это всё, дальше не редактируем. Успехов! */". В этом случае "<font color="red">xyz</font>" должно быть больше в 2 и более раз, чем для WP_MEMORY_LIMIT, но не превышать предоставленный хостингом лимит.
    </div>
</div>

<h4>12. Создайте DNS резолвинг</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Пропишите важные внешние ресурсы</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong>Создайте список предварительных соединений:</strong><br>
1. Откройте файл header.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/)<br>
2. Добавьте до тега &lt;/head&gt; код, указав адреса наиболее значимых/первостепенных внешних подключений (до 6 шт.):<br>
<code>&lt;link rel=&quot;dns-prefetch&quot; href=&quot;<font color="red">УРЛ адрес сайта</font>&quot; /&gt;</code>
<br>

<br><strong>Примечание:</strong><br>
1. Обязательно создайте бэкап редактируемого файла<br>
2. В случае обновления темы повторите установку кода<br>
3. Не забудьте заменить значение "УРЛ адрес сайта"
    </div>
</div>

<h4>13. Отключите загрузку dashicons.min.css во Frontend</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Установите код запрета иконок</div>
    <div class="collapse-body" style="display: none;">
<br>
Если в публичной части сайта не используется файл иконок "<a href="https://developer.wordpress.org/resource/dashicons/" target="_blank">Dashicons</a>" - отключите его загрузку в Frontend, оставив в Backend<br>

<br><strong>Создайте список предварительных соединений:</strong><br>
1. Откройте файл functions.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">Code Snippets</a> (Шаг 6)<br>
2. Добавьте код:<br>
<code>// WP01: удаление dashicons START<br>
	function wpdocs_dequeue_dashicon() {<br>
		if (current_user_can( &#039;update_core&#039; )){<br>
			return;<br>
		}<br>
		wp_deregister_style(&#039;dashicons&#039;);<br>
	}<br>
	add_action( &#039;wp_enqueue_scripts&#039;, &#039;wpdocs_dequeue_dashicon&#039; );<br>
// WP01: удаление dashicons END</code>
<br>

<br><strong>Примечание:</strong><br>
1. В случае обновления темы повторите установку кода (не актуально при использовании плагина для добавления кода)<br>
2. При нахождении в конце файла functions.php закрытия блока &quot;?&gt;&quot; разместите код до него.<br>
3. Если после установки кода сайт выдаёт ошибку - удалите код и обновите страницу (Ctrl+F5)
    </div>
</div>

<h4>14. Проверьте актуальность Яндекс.Метрика</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Изучите код на асинхронность</div>
    <div class="collapse-body" style="display: none;">
<br>
Сервис Яндекс.Метрика с обновлением функционала актуализирует код, который необходимо размещать на сайте.<br>
Старые версии метрики работают без использования асинхронного метода загрузки, что плохо влияет на быстродействие.<br>

<br><strong>Проверьте код:</strong><br>
1. Найдите расположение кода Я.Метрика на сайте (обычно находится в файле footer.php, или header.php используемой темы)<br>
2. Изучите код на наличие <code>k.async=1</code><br>
3. При отсутствии условия асинхронности обновите код, скопировав его с вашего аккаунта на сервисе <a href="https://metrika.yandex.ru/" target="_blank">Я.Метрика</a><br>

<br><strong>Примечание:</strong><br>
1. В случае обновления темы повторите установку кода<br>
2. Если после установки кода сайт выдаёт ошибку - удалите код и обновите страницу (Ctrl+F5)
    </div>
</div>

<h4>15. Отключите "агрессивную проверку" обновлений</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Используйте код</div>
    <div class="collapse-body" style="display: none;">
<br>

Для проверки обновлений ядра/темы/плагинов при генерации админ страницы, чтобы моментально показать вам результаты поиска новых версий, отправляются HTTP запросы. Такой подход создаёт неоправданную нагрузку и приводит к подвисаниям.<br>

<br><strong>Внедрите код:</strong><br>
1. Откройте файл functions.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">Code Snippets</a> (Шаг 6)<br>
2. Добавьте код:<br>
<code>//WP01: Отключение агрессивной проверки обновлений START<br>
	if( is_admin() ){<br>
	// Отключаем проверку обновлений при любом заходе в админку<br>
		remove_action( 'admin_init', '_maybe_update_core' );<br>
		remove_action( 'admin_init', '_maybe_update_plugins' );<br>
		remove_action( 'admin_init', '_maybe_update_themes' );<br>
<br>
	// Отключаем проверку обновлений при заходе на специальную страницу в админке<br>
		remove_action( 'load-plugins.php', 'wp_update_plugins' );<br>
		remove_action( 'load-themes.php', 'wp_update_themes' );<br>
<br>
	// Принудительная проверка при заходе на страницу обновлений - оставляем работу<br>
		//remove_action( 'load-update-core.php', 'wp_update_plugins' );<br>
		//remove_action( 'load-update-core.php', 'wp_update_themes' );<br>
<br>
	// Страница админки "Update/Install Plugin" или "Update/Install Theme" - оставляем работу<br>
		//remove_action( 'load-update.php', 'wp_update_plugins' );<br>
		//remove_action( 'load-update.php', 'wp_update_themes' );<br>
<br>
	// Событие крона для проверки наличия обновлений - оставляем работу<br>
		//remove_action( 'wp_version_check', 'wp_version_check' );<br>
		//remove_action( 'wp_update_plugins', 'wp_update_plugins' );<br>
		//remove_action( 'wp_update_themes', 'wp_update_themes' );<br>
<br>
	// Отключаем проверку необходимости обновления браузера в консоли<br>
		add_filter( 'pre_site_transient_browser_'. md5( $_SERVER['HTTP_USER_AGENT'] ), '__return_true' );<br>
	}<br>
	//WP01: Отключение агрессивной проверки обновлений END
</code>
<br>

<br><strong>Примечание:</strong><br>
1. Проверка обновлений ядра/темы/плагинов происходит по крону<br>
2. Для моментальной проверки обновлений перейдите на страницу "<a href="/wp-admin/update-core.php" target="_blank">Консоль -> Обновления</a>"<br>

<br><strong>Важно:</strong><br>
1. В случае обновления темы повторите установку кода (не актуально при использовании плагина для добавления кода)<br>
2. При нахождении в конце файла functions.php закрытия блока &quot;?&gt;&quot; разместите код до него.<br>
3. Если после установки кода сайт выдаёт ошибку - удалите код и обновите страницу (Ctrl+F5)
    </div>
</div>

<h4>16. Отложите загрузку JivoSite</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Откорректируйте код</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong>Используйте код отложенной загрузки:</strong><br>
1. Найдите расположение кода JivoSite на сайте (обычно находится в файле footer.php, или header.php используемой темы)<br>
2. Удалите используемый код онлайн консультанта, предварительно сохранив идентификатор (см. пример ниже).<br>
3. Используйте модифицированный код, заменив идентификатор на свой:<br>
<code>&lt;!-- WP01: JIVOSITE START --&gt;<br>
&lt;script type=&#039;text/javascript&#039;&gt;<br>
(function(){ document.jivositeloaded=0;var widget_id = &#039;<font color="red">идентификатор</font>&#039;;var d=document;var w=window;function l(){var s = d.createElement(&#039;script&#039;); s.type = &#039;text/javascript&#039;; s.async = true; s.src = &#039;//code.jivosite.com/script/widget/&#039;+widget_id; var ss = document.getElementsByTagName(&#039;script&#039;)[0]; ss.parentNode.insertBefore(s, ss);}//Стандартная строка кода JivoSite<br>
function zy(){<br>
    //Удаление EventListeners<br>
    if(w.detachEvent){//Поддержка IE8<br>
        w.detachEvent(&#039;onscroll&#039;,zy);<br>
        w.detachEvent(&#039;onmousemove&#039;,zy);<br>
        w.detachEvent(&#039;ontouchmove&#039;,zy);<br>
        w.detachEvent(&#039;onresize&#039;,zy);<br>
    }else {<br>
        w.removeEventListener(&quot;scroll&quot;, zy, false);<br>
        w.removeEventListener(&quot;mousemove&quot;, zy, false);<br>
        w.removeEventListener(&quot;touchmove&quot;, zy, false);<br>
        w.removeEventListener(&quot;resize&quot;, zy, false);<br>
    }<br>
    //Запуск функции загрузки JivoSite<br>
    if(d.readyState==&#039;complete&#039;){l();}else{if(w.attachEvent){w.attachEvent(&#039;onload&#039;,l);}else{w.addEventListener(&#039;load&#039;,l,false);}}<br>
    //Установка cookie по которому отличаем первый хит от второго<br>
    var cookie_date = new Date ( );<br>
    cookie_date.setTime ( cookie_date.getTime()+60*60*28*1000); //24 часа для Москвы<br>
    d.cookie = &quot;JivoSiteLoaded=1;path=/;expires=&quot; + cookie_date.toGMTString();<br>
}<br>
if (d.cookie.search ( &#039;JivoSiteLoaded&#039; )&lt;0){//Проверка: первый ли это визит на сайт, если да - назначаем EventListeners на события прокрутки, изменения размера окна браузера и скроллинга на ПК и мобильных устройствах, для отложенной загрузке JivoSite<br>
    if(w.attachEvent){// Поддержка IE8<br>
        w.attachEvent(&#039;onscroll&#039;,zy);<br>
        w.attachEvent(&#039;onmousemove&#039;,zy);<br>
        w.attachEvent(&#039;ontouchmove&#039;,zy);<br>
        w.attachEvent(&#039;onresize&#039;,zy);<br>
    }else {<br>
        w.addEventListener(&quot;scroll&quot;, zy, {capture: false, passive: true});<br>
        w.addEventListener(&quot;mousemove&quot;, zy, {capture: false, passive: true});<br>
        w.addEventListener(&quot;touchmove&quot;, zy, {capture: false, passive: true});<br>
        w.addEventListener(&quot;resize&quot;, zy, {capture: false, passive: true});<br>
    }<br>
}else {zy();}<br>
})();&lt;/script&gt;<br>
&lt;!-- WP01: JIVOSITE END --&gt;</code><br>

<br><strong>Пример идентификатора в новом коде:</strong><br>
<code>&lt;script src=&quot;//code.jivosite.com/widget/<font color="red">идентификатор</font>&quot; async&gt;&lt;/script&gt;</code><br>
<strong>Пример идентификатора в старом коде:</strong><br>
<code>&lt;!-- BEGIN JIVOSITE CODE {literal} --&gt;<br>
&lt;script type=&#039;text/javascript&#039;&gt;<br>
(function(){ var widget_id = &#039;<font color="red">идентификатор</font>&#039;;var d=document;var w=window;...</code><br>

<br><strong>Примечание:</strong><br>
1. В случае обновления темы повторите установку кода<br>
2. Если после установки кода сайт выдаёт ошибку - удалите код и обновите страницу (Ctrl+F5)<br>
<br>
<strong>P.S.</strong> Если вы не используете онлайн консультант на своём сайте и не хотели бы видеть его на других проектах сети - установите в браузер блокиратор "<a href="https://hellogoodbye.app/" target="_blank">Hello, Goodbye</a>"
    </div>
</div>

<h4>17. Отложите загрузку ВК виджетов</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Используйте код</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong>Произведите действия:</strong><br>
1. Замените код подключения JS скрипта "https://vk.com/js/api/openapi.js" (как правило, размещается в header.php темы сайта) следующей конструкцией:<br>
<code>
	&lt;script type=&quot;text/javascript&quot;&gt;<br>
		setTimeout(function(){<br>
			var VKO = document.createElement(&quot;script&quot;);<br>
			VKO.src = &#039;https://vk.com/js/api/openapi.js&#039;;<br>
			VKO.async = true;<br>
			document.getElementsByTagName(&#039;head&#039;)[0].appendChild(VKO);<br>
			VKO.onload = function(){<br><br>
				// ПРИМЕР (стандартный ВК код) инициализации виджета &quot;Сообщения сообщества&quot;<br>
				VK.Widgets.CommunityMessages(&quot;vk_community_messages&quot;, <font color="red">123456789</font>, {expanded: &quot;1&quot;,tooltipButtonText: &quot;Есть вопрос?&quot;});<br><br>
				// ПРИМЕР (стандартный ВК код) инициализации виджета для сообществ<br>
				VK.Widgets.Group(&quot;vk_groups&quot;, {mode: 3}, <font color="red">12345678</font>);<br><br
			};<br>
		},5000); // время отложенной загрузки, в миллисекундах (5000 = 5 сек)<br>
	&lt;/script&gt;
	</code><br>
2. Замените код отображения виджета в элементе страницы сайта на облегчённую версию:<br>
	Пример отображения виджета "Сообщения сообщества":<br>
	<code>
	&lt;div id=&quot;vk_community_messages&quot;&gt;&lt;/div&gt;
	</code><br>
	Пример отображения виджета для сообществ:<br>
	<code>
	&lt;div id=&quot;vk_groups&quot;&gt;&lt;/div&gt;
	</code>
<br>

<br><strong>Примечание:</strong><br>
1. Если после установки кода сайт выдаёт ошибку - удалите код и обновите страницу (Ctrl+F5)<br>
    </div>
</div>

<h4>18. Используйте минифицированную версию jQuery</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Замените файл</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong>Произведите действия:</strong><br>
1. Узнайте версию jQuery, которую использует сайт. Для этого определите УРЛ адрес, по которому загружается библиотека, а затем откройте её в редакторе. В самом начале файла будет указана версия (например, jQuery v1.12.4). <br>
&nbsp; Методы определения нахождения jQuery:<br>
&nbsp; - Просканируйте сайт в <a href="https://developers.google.com/speed/pagespeed/insights/" target="_blank">Google PSI</a> и изучите пункт "Устраните ресурсы, блокирующие отображение", в котором (в большинстве случаев) вы увидите ссылку на "jquery.js"<br>
&nbsp; - Откройте код страницы сайта (Ctrl+U) и через поиск (Ctrl+F) найдите файл "jquery.js"<br>
&nbsp; - Запустите консоль разработчика в браузере (Ctrl+Shift+I -> Network -> All), затем найдите используя фильтр файл "jquery.js"<br>
2. В открытом "jquery.js" файле определите использование минификации (удаление пробелов).<br>
&nbsp; Пример:<br>
&nbsp; Стандартный "jquery.js" v3.6.0: <a href="https://code.jquery.com/jquery-3.6.0.js" target="_blank">https://code.jquery.com/jquery-3.6.0.js</a> - 280,82 Кб.<br>
&nbsp; Минифицированный "jquery.js" v3.6.0: <a href="https://code.jquery.com/jquery-3.6.0.min.js" target="_blank">https://code.jquery.com/jquery-3.6.0.min.js</a> - 89,50 Кб.<br>
3. В случае использования на сайте стандартной версии jQuery замените файл на его минифицированную версию.<br>

<br><strong>Примечание:</strong><br>
1. Обязательно сделайте бэкап используемого сайтом файла "jquery.js"<br>
2. Имя используемого на сайте jQuery файла должно остаться неизменным
    </div>
</div>

<h4>19. Примените кэширование переводов</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Внедрите библиотеку</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong>Произведите действия:</strong><br>
1. Скачайте библиотеку <a href="https://github.com/pressjitsu/pomodoro/archive/refs/heads/master.zip" target="_blank">pomodoro</a>  <br>
2. Разархивируйте полученный архив и скопируйте из него файл "pomodoro.php" в папку "/wp-content/mu-plugins/"<br>
Скрипт начнёт работу, дополнительных действий не требуется.<br>

<br><strong>Примечание:</strong><br>
1. Чем больше плагинов вы используете на сайте, тем ощутимее будет эффект от работы скрипта<br>
2. Если в каталоге "/wp-content/" отсутствует папка "mu-plugins" - создаёте её самостоятельно<br>
3. В случае ошибок удалите файла "pomodoro.php" для деактивации работы библиотеки
    </div>
</div>

<h4>20. Ускорьте сайт с WooCommerce</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Отключите неиспользуемые ресурсы</div>
    <div class="collapse-body" style="display: none;">
<br>
<br><strong>Внедрите код:</strong><br>
1. Откройте файл functions.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">Code Snippets</a> (Шаг 6)<br>
2. Добавьте код:<br>
<code>//WP01: Отключение ресурсов магазина на тех страницах, где они не нужны. START<br>
add_action(<br>
    &#039;wp_enqueue_scripts&#039;,<br>
    function() {<br>
        // Если НЕ страницы магазина.<br>
        if ( ! is_woocommerce() &amp;&amp; ! is_cart() &amp;&amp; ! is_checkout() ) {<br>
            // Отключаем стили WooCommerce<br>
            wp_dequeue_style( &#039;woocommerce_frontend_styles&#039; );<br>
            wp_dequeue_style( &#039;woocommerce-general&#039;);<br>
            wp_dequeue_style( &#039;woocommerce-layout&#039; );<br>
            wp_dequeue_style( &#039;woocommerce-smallscreen&#039; );<br>
            wp_dequeue_style( &#039;woocommerce_fancybox_styles&#039; );<br>
            wp_dequeue_style( &#039;woocommerce_chosen_styles&#039; );<br>
            wp_dequeue_style( &#039;woocommerce_prettyPhoto_css&#039; );<br>
            wp_dequeue_style( &#039;select2&#039; );<br>
<br>
            // Отключаем скрипты WooCommerce<br>
            wp_dequeue_script( &#039;wc-add-payment-method&#039; );<br>
            wp_dequeue_script( &#039;wc-lost-password&#039; );<br>
            wp_dequeue_script( &#039;wc_price_slider&#039; );<br>
            wp_dequeue_script( &#039;wc-single-product&#039; );<br>
            wp_dequeue_script( &#039;wc-add-to-cart&#039; );<br>
            wp_dequeue_script( &#039;wc-cart-fragments&#039; );<br>
            wp_dequeue_script( &#039;wc-credit-card-form&#039; );<br>
            wp_dequeue_script( &#039;wc-checkout&#039; );<br>
            wp_dequeue_script( &#039;wc-add-to-cart-variation&#039; );<br>
            wp_dequeue_script( &#039;wc-single-product&#039; );<br>
            wp_dequeue_script( &#039;wc-cart&#039; ); <br>
            wp_dequeue_script( &#039;wc-chosen&#039; );<br>
            wp_dequeue_script( &#039;woocommerce&#039; );<br>
            wp_dequeue_script( &#039;prettyPhoto&#039; );<br>
            wp_dequeue_script( &#039;prettyPhoto-init&#039; );<br>
            wp_dequeue_script( &#039;jquery-blockui&#039; );<br>
            wp_dequeue_script( &#039;jquery-placeholder&#039; );<br>
            wp_dequeue_script( &#039;jquery-payment&#039; );<br>
            wp_dequeue_script( &#039;jqueryui&#039; );<br>
            wp_dequeue_script( &#039;fancybox&#039; );<br>
            wp_dequeue_script( &#039;wcqi-js&#039; );<br>
        }<br>
    },<br>
    99<br>
);<br>
	//WP01: Отключение ресурсов магазина на тех страницах, где они не нужны. END
</code>
<br>

<br><strong>Важно:</strong><br>
1. В случае обновления темы повторите установку кода (не актуально при использовании плагина для добавления кода)<br>
2. При нахождении в конце файла functions.php закрытия блока &quot;?&gt;&quot; разместите код до него.<br>
3. Если после установки кода сайт выдаёт ошибку - удалите код и обновите страницу (Ctrl+F5)
    </div>
</div>
