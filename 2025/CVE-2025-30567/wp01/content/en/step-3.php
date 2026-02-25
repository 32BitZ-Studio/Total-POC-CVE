<?php

if (!defined('ABSPATH')) {
    die('Don\'t hack please!');
}

?>
<div class="card tip">
    <h3>Hint</h3>

    <p>1. Write down the data obtained from the site speed testing services.
        <br>After that, you will be able to understand the effectiveness of your work.</p>
    <p>2. If you have the proper experience, we also recommend to review
        <br>on causes of website slowdown and recommendations of their removal,
        <br>which are displayed in tests Google PSI, GTmetrix and Pingdom.</p>
    <p>3. All plugins installs to /wp-content.plugins/ folder, 
        <br>so if site will display an error (white screen) after activation, then just
        <br>connect with FTP and deactivate plugin that caused conflict,
        <br>adding number/letter to title of the folder
        <br>To resume plugin functioning enter admin panel
        <br> of the website and press "Activate" beside of plugin.</p>
    <p>4. Some plugin's settings can conflict with theme of your website,
        <br>or with another plugins. We are advicing you to activate
        <br>every function in plugins by rotation and check efficiency of website.
    <p>5. To test the display order and loading speed of the site
        <br>in browsers on the Chromium engine (Google Chrome, Yandex, Opera):
        <br>&nbsp; &nbsp;A. Open the developer panel ("F12" key)
		<br>&nbsp; &nbsp;B. Go to the "Network" section and click "&#9660;" next to "Online"
		<br>&nbsp; &nbsp;C. Select the 3G network in the "Presets" item, or set the speed in "Add..."
		<br>in browsers on the Gecko engine (Firefox, Waterfox, Avant Browser):
		<br>&nbsp; &nbsp;A. Open the adaptive design mode (Ctrl+Shift+M combination)
		<br>&nbsp; &nbsp;B. Select the desired network in the "Unlimited" section.</p>
	<p>6. To fully display the site, disable all ad blockers for it
        <br>(Adblock, AdGuard, Ghostery)</p>
	<p>7. To analyze the speed and connections of metrics, online consultants, 
		<br>and other trackers, it is convenient to use Ghostery in <a href="https://chrome.google.com/webstore/detail/ghostery-–-privacy-ad-blo/mlomiejdfkolichcflejclcbmpeaniij/related?hl=en" target="_blank">Chrome</a> / <a href="https://addons.mozilla.org/en-US/firefox/addon/ghostery/" target="_blank">Mozilla</a></p></p>

</div>

<h2>Step 3/7. <span class="name">Loading acceleration</span></h2>
        <font color="red"><strong>ATTENTION:</strong></font>
		Part of the text is translated into English using a machine algorithm. As you develop, all materials will be of better quality.<br><br>

<div class="notice notice-warning notice-alt inline">
    <p>
        <strong>Important:</strong><br>
		To figure out how slowly website is loading and causes of slowing, make independent tests
        in 2-3 services BEFORE IMPLEMENTATION OF BOOSTING SPEED METHODS and repeat it again AFTER ALL ACTIONS.
    </p>
</div>

<table class="widefat table-not-full-width plugins">
    <thead>
    <tr>
        <th style="width:100px">Service</th>
        <th>Destination</th>
		<th>Language</th>
        <th>Recommendations</th>
    </tr>
    </thead>
    <tbody>
    <tr class="inactive">
        <td><a href="https://developers.google.com/speed/pagespeed/insights/" title="Google PageSpeed Insights" target="_blank">Google PSI</a></td>
        <td>Official Google service to define loading speed. Displays points and gives recommendations about improving mobile/PC website version.<br>
		<strong>Information:</strong> <a href="https://googlechrome.github.io/lighthouse/scorecalc/" target="_blank">Lighthouse Scoring Calculator</a>
        </td>
		<td>RUS
		</td>
        <td>Seek to attain > 90 points <a href="#" class="collapse-toggler" data-target="#info-collapse">REFERENCE</a>
        </td>
    </tr>
    <tr class="inactive">
        <td><a href="https://seolik.ru/speed" target="_blank">SeoLik</a></td>
        <td>Testing website's loading speed with displaying of mistakes. There are additional tools for audit
            and SEO research.
        </td>
		<td>RUS
		</td>
        <td>Seek to attain > 90 points <a href="#" class="collapse-toggler" data-target="#info-collapse">REFERENCE</a>
        </td>
    </tr>
    <tr class="inactive">
        <td><a href="https://gtmetrix.com" target="_blank">GTmetrix</a></td>
        <td>Analysis of a website speed according to Google PSI and YSlow data. Remarks and recommendation are displaying after results of the test.
        </td>
		<td>ENG
		</td>
        <td>Seek to attain > 90 points <a href="#" class="collapse-toggler" data-target="#info-collapse">REFERENCE</a>
        </td>
    </tr>
	<tr class="inactive">
        <td><a href="https://tools.pingdom.com" target="_blank">Pingdom</a></td>
        <td>Testing of website loading speed with an option to chose server. Displays inner rating, page size, 
		loading time and amount of requests made by website. There are recommendations about improving of a speed
        and technical information.
        </td>
		<td>ENG
		</td>
        <td>Seek to attain > 90 points <a href="#" class="collapse-toggler" data-target="#info-collapse">REFERENCE</a>
        </td>
    </tr>
	<tr class="inactive">
        <td><a href="https://ping-admin.ru/free_test/" target="_blank">Ping-Admin</a></td>
        <td>Testing of availability from different parts of world with displaying the following information: time spent (total, DNS, 
		connection, SSL, waiting of reply), loading speed and size of a page's code (in compressed and used type).<br>
		<strong>Recommend:</strong> Compare the performance and speed of your hosting's communication channel with ours. More detailed:<a href="https://on.wp01.ru/" target="_blank">https://on.wp01.ru</a> (RUS, script version 0.2)
        </td>
		<td>ENG
		</td>
        <td>Seek to less loading time
        </td>
    </tr>
	<tr class="inactive">
        <td><a href="https://www.webpagetest.org/" target="_blank">WebPagetest</a></td>
        <td>Study the speed of the site with the ability to choose the location of the test, browser, device (PC, mobile), there are fine-tuning (processing JavaScript, SSL, Chrome, and others).
        </td>
		<td>ENG
		</td>
        <td>Aim for less loading time
        </td>
    </tr>
    </tbody>
</table>

<div class="collapse unstiled" id="info-collapse">
    <div class="collapse-body" style="display: none;">
        <div class="card">
            <h4>Reference</h4>
            <p>1.
               If speed metrics are low (before 89 points) - then maybe 
               features of plugins are not fully utilized. 
               Check settings and repeat tests!</p>
            <p>2. The following parameters effects on a speed of website:</p>
            <ul>
                <li>hosting power;</li>
                <li>amount of websites of the hosting (check all adjacent sites: <a href="https://suip.biz/ru/?act=hostmap" target="_blank">https://suip.biz/ru/?act=hostmap</a>);</li>
                <li>site traffic;</li>
                <li>activated plugins;</li>
                <li>theme code's cleanliness and correctness;</li>
				<li>the level of optimization of images;</li>
				<li>number of external connections (for example, JivoSite, Google Analytics);</li>	
				<li>proximity of the hosting location to potential customers (find out the city of physical location of the site by ip: <a href="https://2ip.ru/geoip/" target="_blank">https://2ip.ru/geoip/</a>);</li>
				<li>the relevance of the PHP version - if possible use PHP 7.4 (the most supported version of WordPress at the moment).</li>
				<p><strong>IMPORTANT:</strong> almost always, switching to a newer version of PHP causes errors in plugins, themes, or CMS.<br>
				We recommend that you change the PHP version directly by the programmer.<br>
				Official WordPress recommendations: <a href="https://wordpress.org/support/update-php/" target="_blank">https://wordpress.org/support/update-php/</a></p>
            </ul>
			<p>3. Test sites for Russia:<br>
			Check the speed of your hosting with the work <a href="https://www.reg.ru/hosting/?rlink=reflink-6247477" target="_blank">reg.ru</a> (it hosts our sites) by specifying a special page for the scan in the service <a href="https://ping-admin.ru/free_test/" target="_blank">https://ping-admin.ru</a> <strong>More detailed:</strong> <a href="https://on.wp01.ru/" target="_blank">https://on.wp01.ru/</a><br>
			Download and place the file on your hosting <a href="https://on.wp01.ru/test_wp01.zip" target="_blank">wp01_test.zip</a> (704 Kb) to test the speed of the hosting communication channel. Compare the results with the file test on our hosting: <code>https://on.wp01.ru/test_wp01.zip</code><br>
			Check the readings in Ping-Admin on the scan of the test file on your and our hosting. If there is a big difference (several dozen times), consider changing the hosting.
			</p>	

            <p><strong>P.S.</strong> If you were unable to achieve high performance , you may need to contact a programmer to rewrite the site theme and replace the most "heavy" plugins with code.</p>
        </div>
    </div>
</div>


<h3>I. Plugins for acceleration</h3>
<p>Install plugins corresponding to the required tasks</p>

<?php

$titles = array('Plugin', 'Status', 'Analogs', 'Replace by code', 'Objective', 'Module importance', 'Control', 'Installation instruction');
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
        'desc' => 'Optimization of website code.<br> <strong>Recommend:</strong> <a href="https://wordpress.org/plugins/autoclear-autoptimize-cache/" target="_blank">automatic cache clearing "Autoptimize"</a>',
        'rate' => 3,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text' => 'to config',
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
        'desc' => 'Optimization and cleaning of MySQL',
        'rate' => 3,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text' => 'to config',
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
        'desc' => 'Optimization of requests to MySQL.<br><strong>Warning: does not support PHP &ge; 7. x</strong>',
        'rate' => 2,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'php_version' => 5,
        'settings_text' => 'to config',
        'settings_link' => '/options-general.php?page=db-cache-reloaded-fix%2Fdb-cache-reloaded.php',
    ),
    array(
        'icon' => WP01_Content::get_image_src('icons/3/widget-output-cache_m.jpg'),
        'name' => 'Widget Output Cache',
        'path' => 'widget-output-cache/widget-output-cache.php',
        'desc' => 'Caching of widgets',
        'rate' => 2,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text' => 'Activated,  no configuration required',
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
        'desc' => 'Caching of site pages<br> <strong>Recommend:</strong> <a href="https://wordpress.org/plugins/wp-super-cache-clear-cache-menu/" target="_blank">convenient cache clearing "WP Super Cache"</a>',
        'rate' => 3,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text' => 'to config',
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
        'desc' => 'Transition management',
        'rate' => 1,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text' => 'open',
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
        'desc' => "Graphic's lazy load",
        'rate' => 3,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text' => 'to config',
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
        'desc' => 'Control of plugins functioning on pages',
        'rate' => 3,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a><br>Documentation:<br> 
<a href="https://celtislab.net/en/wp-plugin-load-filter/" target = "_blank"><strong>ENG</strong></a>',
        'settings_text' => 'to config',
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
        'desc' => 'Async and delayed loading of javaScript',
        'rate' => 2,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text' => 'to config',
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
        'desc' => 'Caching of Google Analitics on your website<br> <strong>Recommend:</strong> <a href="https://support.google.com/analytics/answer/1032399?hl=en" target="_blank">checking how Gogle Analytics works</a>',
        'rate' => 3,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text' => 'to config',
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
        'desc' => 'Implementation of WebP format + png/jpg conversion<br> <strong>Recommend:</strong> <a href="https://ru.wordpress.org/plugins/webp-express-plus/" target="_blank">excluding images from processing in WebP</a>',
        'rate' => 3,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text' => 'to config',
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
        'desc' => 'Image compression and optimization. <br> <strong>Recommend:</strong> <a href="https://wordpress.org/plugins/wp-nonstop-smushit/" target="_blank">to remove restrictions in the "Smush"</a>',
        'rate' => 2,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text' => 'to config',
        'settings_link' => '/admin.php?page=smush',
    ),
    array(
        'icon' => WP01_Content::get_image_src('icons/3/heartbeat-control_m.jpg'),
        'name' => 'Heartbeat Control',
        'path' => 'heartbeat-control/heartbeat-control.php',
        'desc' => 'Managment of server request frequency',
        'rate' => 2,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text' => 'to config',
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
        'name' => 'WordPress Assets manager, dequeue scripts, dequeue styles',
        'path' => 'gonzales/gonzales.php',
        'desc' => 'Disabling unnecessary scripts and styles on pages',
        'rate' => 3,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text' => 'Activated, management in "admin bar"',
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
        'desc' => 'Disabling unnecessary tags/links in head block<br> <strong>Рекомендуем:</strong> <a href="https://ru.wordpress.org/plugins/disable-emojis/" target="_blank">Removing support code/connections in older Emoji Browsers</a>',
        'rate' => 2,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text' => 'to config',
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
        'desc' => 'Delayed comments loading in Disqus plugin <span id="server-ip-memory-usage"></span>',
        'rate' => 1,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text' => 'to config',
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
        'desc' => 'Displaying the memory limit (server and WordPress)',
        'rate' => 1,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text' => 'to config',
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
        'desc' => 'Display on pages: generation time (TTFB and final),<br> RAM usage, number of database requests',
        'rate' => 1,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text' => 'to config',
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
        'desc' => 'Disables jQuery Migrate (jquery-migrate.js или jquery-migrate.min.js)',
        'rate' => 2,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text' => 'to config',
        'settings_link' => '',
		'replace_level' => 'Full',
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
        'desc' => 'Version Control jQuery Core/Migrate and their connection from jQuery CDN.<br> <strong>Recommend:</strong> <a href="https://wordpress.org/plugins/enable-jquery-migrate-helper/" target="_blank">detecting plugin incompatibilities with new jQuery</a> (WP &ge; 5.4)',
        'rate' => 1,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text' => 'to config',
        'settings_link' => '/options-general.php?page=version_control_for_jquery',
    ),
    array(
        'icon' => WP01_Content::get_image_src('icons/3/css-js-manager_m.jpg'),
        'name' => 'CSS JS Manager, Async JavaScript, Defer Render Blocking CSS',
        'path' => 'css-js-manager/css-js-manager.php',
        'desc' => 'The exception is custom js/css from the code for the condition, use Defer/Async loading method',
        'rate' => 1,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a><br>Documentation:<br> 
<a href="https://www.piwebsolution.com/css-js-manager-documentation/" target = "_blank"><strong>ENG</strong></a>',
        'settings_text' => 'to config',
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
        'desc' => 'Push/Preload for the css/js and other elements of the website',
        'rate' => 1,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text' => 'to config',
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
        'desc' => 'Display unique content for PC/mobile devices',
        'rate' => 1,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
		'settings_text' => 'Active, use shortcodes',
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
		тут то, что показываем на мобильных и скрываем на ПК<br>
	&lt;/div&gt;<br>
	&lt;div class=&quot;showmobile&quot;&gt;<br>
		тут то, что показываем на ПК и скрываем на мобильных<br>
	&lt;/div&gt;<br><br>
</div>	

<strong>Скрываем информацию на мобильных/ПК в PHP файлах</strong><br>
1. Откройте PHP файл, находящийся в папке используемой темы (/wp-content/themes/название_темы/)<br>
2. Используйте код:<br>
<div class="tc">
	&lt;!-- WP01: Скрытие информации на мобильных/ПК в PHP файле --&gt;<br>
		&lt;?php if(wp_is_mobile()) { ?&gt;<br>
		тут то, что показываем на ПК и скрываем на мобильных<br>
		&lt;?php } else { ?&gt;<br>
		тут то, что показываем на мобильных и скрываем на ПК<br>
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
        'desc' => 'Lazy loading for Google Analytics, Facebook Pixel, Hotjar, Yandex Metrics Liveinternet counter<br> <strong>Recommend:</strong> <a href="https://support.google.com/analytics/answer/1032399?hl=en" target="_blank">checking how google Analytics works</a> и <a href="https://yandex.com/support/metrica/general/check-counter.html" target="_blank">checking the work of Yandex Metrica</a>',
        'rate' => 2,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text' => 'to config',
        'settings_link' => '/admin.php?page=true-lazy-analytics',
		'replace_level' => 'Full',
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
        'desc' => 'Manage scheduler tasks (cron) and registered schedules',
        'rate' => 2,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text' => 'to config',
        'settings_link' => '/tools.php?page=advanced-cron-manager',
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
        'desc' => 'Transferring fonts from fonts.googleapis.com and fonts.gstatic.com to the local folder of the site and then connect them',
        'rate' => 2,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text' => 'to config',
        'settings_link' => '/options-general.php?page=optimize-webfonts',
    )
);

WP01_Table::the_table($titles, $plugins);

?>

<h3>II. Quick backup</h3>
<p>Before manual code implementations, we strongly recommend making a backup copy of the files that will be edited</p>

<?php 
/* start new */
$titles = array('Name', 'Location', 'Appointment', 'Management');
    
        $structure = array(
/*
            array(
                "filename" => '.htaccess',
                "path" => '/',
                'fullPath' => $_SERVER['DOCUMENT_ROOT'] . '/',
                "comment" => 'Additional Web Server configuration file',
                "button_text" => 'Download'
            ),
            array(
                "filename" => 'wp-config.php',
                "path" => '/',
                'fullPath' => $_SERVER['DOCUMENT_ROOT'] . '/',
                "comment" => 'WordPress Configuration File',
                "button_text" => 'Download'
                
            ),
*/
            array(
                "filename" => 'footer.php',
                "path" => '/wp-content/themes/'. get_template() . '/',
                'fullPath' => $_SERVER['DOCUMENT_ROOT'] . '/wp-content/themes/'. get_template() . '/',
                "comment" => 'The lower part of the site template',
                "button_text" => 'Download'
            ),
            array(
                "filename" => 'header.php',
                "path" => '/wp-content/themes/'. get_template() . '/',
                'fullPath' => $_SERVER['DOCUMENT_ROOT'] . '/wp-content/themes/'. get_template() . '/',
                "comment" => 'The top part of the website template',
                "button_text" => 'Download'
            ),
            array(
                "filename" => 'functions.php',
                "path" => '/wp-content/themes/'. get_template() . '/',
                'fullPath' => $_SERVER['DOCUMENT_ROOT'] . '/wp-content/themes/'. get_template() . '/',
                "comment" => 'Theme file with custom functions',
                "button_text" => 'Download'
            )
        );

    WP01_Table::build_backup_table($titles, $structure); 
	/* end new */
?>

<h3>III. Manual implementations</h3>
<p>Install/edit the code according to the required task</p>

<h4>1. Reduce amount of records revisions and autosaves interval</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Set the conditions</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong>Follow the steps:</strong><br>
1. Open the file "wp-config.php" (located in the root directory of the site)<br>
2. After <code>define('WP_DEBUG', false);</code>write from a new line the following code:<br>
&nbsp; &nbsp; <code>define('WP_POST_REVISIONS', 5);</code><br>
&nbsp; &nbsp; <code>define('AUTOSAVE_INTERVAL', 300);</code>
<br>
    </div>
</div>

<h4>2. Activate the caching</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Write in .htaccess file the following rules</div>
    <div class="collapse-body" style="display: none;">
            <pre>#WP01_CACHING_START
# Caching
&lt;ifModule mod_headers.c&gt;
# to cache html and htm files for 12 hours
   &lt;FilesMatch "\.(html|htm)$"&gt;
Header set Cache-Control "max-age=43200"
   &lt;/FilesMatch&gt;
# to cache css, javascript and text files for one week
   &lt;FilesMatch "\.(js|css|txt)$"&gt;
   Header set Cache-Control "max-age=604800"
   &lt;/FilesMatch&gt;
# to cache flash and images for mounth
   &lt;FilesMatch "\.(flv|swf|ico|gif|jpg|jpeg|png|webp)$"&gt;
   Header set Cache-Control "max-age=31536000"
   &lt;/FilesMatch&gt;
# to cache the fonts for 1 year
   &lt;FilesMatch "\.(eot|ttf|otf|svg|woff|woff2)$"&gt;
   Header set Cache-Control "max-age=31556926, public"
   &lt;/FilesMatch&gt;
# disable caching for defined extensions
   &lt;FilesMatch "\.(pl|php|cgi|spl|scgi|fcgi)$"&gt;
   Header unset Cache-Control
   &lt;/FilesMatch&gt;
&lt;/IfModule&gt;

# Terms of caching
&lt;ifModule mod_expires.c&gt;
   ExpiresActive On
#cache in 5 seconds by default
   ExpiresDefault "access plus 5 seconds"
# to cache flash and images for 1 year
   ExpiresByType image/x-icon "access plus 31536000 seconds"
   ExpiresByType image/jpeg "access plus 31536000 seconds"
   ExpiresByType image/jpg "access plus 31536000 seconds"
   ExpiresByType image/png "access plus 31536000 seconds"
   ExpiresByType image/gif "access plus 31536000 seconds"
   ExpiresByType application/x-shockwave-flash "access plus 31536000 seconds"
   ExpiresByType image/webp "access plus 31536000 seconds"
# to cache fonts for 1 year
   ExpiresByType application/x-font-ttf "access plus 31556926 seconds"
   ExpiresByType font/opentype "access plus 31556926 seconds"
   ExpiresByType application/x-font-woff "access plus 31556926 seconds"
   ExpiresByType application/x-font-woff2 "access plus 31556926 seconds"
   ExpiresByType image/svg+xml "access plus 31556926 seconds"
   ExpiresByType application/vnd.ms-fontobject "access plus 31556926 seconds"
# to cache css, javascript and text files for one week
   ExpiresByType text/css "access plus 604800 seconds"
   ExpiresByType text/javascript "access plus 604800 seconds"
   ExpiresByType application/javascript "access plus 604800 seconds"
   ExpiresByType application/x-javascript "access plus 604800 seconds"
# to cache html and htm files for 12 hours
   ExpiresByType text/html "access plus 43200 seconds"
# to cache xml files for 10 minutes
   ExpiresByType application/xhtml+xml "access plus 600 seconds"
&lt;/ifModule&gt;
#WP01_CACHING_END</pre>
    </div>
</div>

<h4>3. Compressing files before sending to user</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Write in .htaccess file the following rules</div>
    <div class="collapse-body" style="display: none;">
            <pre>#WP01_COMPRESSING_START
&lt;IfModule mod_deflate.c&gt;
# Compressing HTML, CSS, JavaScript, text, XML and fonts
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

<h4>4. Use the latest version of PHP supported by WordPress</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Follow the recommendations</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong><font color="red">Attention!</font></strong><br>
Very often, switching to a more recent version of PHP causes errors in plugins, themes, and/or CMS.<br>
We recommend changing the PHP version directly by the programmer.<br>
Official WordPress recommendations: <a href="https://wordpress.org/support/update-php/" target="_blank">https://wordpress.org/support/update-php/</a><br>
<br>
<strong>WordPress 5.3 performance* on different versions of PHP:</strong><br>
<table width="360" border="1" cellspacing="0" cellpadding="1">
           <tr align="center"><th width="25%">version of PHP</th><th width="30%">requests/sec</th><th width="45%">faster than PHP 5.6</th></tr>
           <tr align="center"><td>5.6</td><td>97,71</td><td>0 times</td></tr>
           <tr align="center"><td>7.0</td><td>256,81</td><td>2,63 times</td></tr>
           <tr align="center"><td>7.1</td><td>256,99</td><td>2,63 times</td></tr>
           <tr align="center"><td>7.2</td><td>273,07</td><td>2,79 times</td></tr>
           <tr align="center"><td>7.3</td><td>305,59</td><td>3,13 times</td></tr>
           <tr align="center"><td>7.4</td><td>313,42</td><td>3,21 times</td></tr>
</table> 
<strong>Conclusion:</strong> PHP 7.4 is 3.21 times faster (more requests per second) than PHP 5.6<br>
* according to WPGutenberg<br>
<br>
<strong>Confirmed support:</strong><br>
WordPress 5.2: PHP 5.6.20-7.3<br>
WordPress 5.3: PHP 5.6.20-7.4<br>
<br>
<strong>Algorithm for changing the PHP version:</strong><br>
&nbsp; 1. Check the compatibility of themes and plugins with a more recent version of PHP using the "<a href="https://ru.wordpress.org/plugins/php-compatibility-checker/" target="_blank">PHP Compatibility Checker</a>"<br>
&nbsp; 2. Go to your hosting control panel (for example, ISPmanager)<br>
&nbsp; 3. In the site settings, gradually increase the PHP version (for example, 5.4 -> 5.5 -> 5.6 -> 7.0), simultaneously testing the project for errors<br>
&nbsp; 4. If errors appear on the site when activating a more recent version of PHP, return the version to the previously used one. if necessary, contact the hosting technical support<br>
<br>
<strong>Reference:</strong><br>
Currently the most supported WordPress system is PHP version 7.4
<br>
    </div>
</div>

<h4>5. Optimize png/jpg/gif images</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Use online/offline tools</div>
    <div class="collapse-body" style="display: none;">
            <pre><a href="https://imagecompressor.com/" target="_blank">https://imagecompressor.com/</a> - optimization with quality management of up to 20 images at a time.</pre>
			<pre><a href="https://tinypng.com/" target="_blank">https://tinypng.com/</a> - optimization (automatic quality selection) of up to 20 images (maximum 5 MB) at a time.</pre>
			<pre><a href="https://www.onlineimagetool.com/ru/compress-png-jpg-webp-gif" target="_blank">https://www.onlineimagetool.com/ru/</a> - optimize PNG/JPG/WEBP/GIF images (no limit on the number).</pre>
			<pre><a href="https://compressor.io/" target="_blank">https://compressor.io/</a> - optimization with a choice of compression type up to 100 JPEG, PNG, SVG, GIF and WEBP images (or 10 MB.) at a time.</pre>			
			<pre><a href="https://gifcompressor.com/ru/" target="_blank">https://gifcompressor.com/ru/</a> - optimize up to 20 GIF images at a time.</pre>			
			<pre><a href="https://www.leapic.com/free-gif-optimizer.htm" target="_blank">GIF Optimizer</a> - program (Windows OS) for GIF optimization (works with 1 file at a time).</pre>	
			<pre><a href="http://www.romeolight.com/products/gifmicro/" target="_blank">GIFmicro</a> - program (Windows OS) for GIF optimization (mass work).</pre>	
 </div>
</div>

<h4>6. Optimize SVG images</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Use the online constructor</div>
    <div class="collapse-body" style="display: none;">
			<pre><a href="https://vecta.io/nano" target="_blank">Nano SVG</a> - automatic optimization of up to 10 images (maximum 5 MB.) at a time.</pre>
			<pre><a href="https://jakearchibald.github.io/svgomg/" target="_blank">SVG Optimizer (Jake Archibald)</a> - step-by-step optimization of 1 image.</pre>
			<pre><a href="https://petercollingridge.appspot.com/svg-optimiser" target="_blank">SVG Optimizer (Peter Collingridge)</a> - optimization of 1 image with the ability to determine the detail.</pre>
			<pre><a href="https://compressor.io/" target="_blank">COMPRESSOR</a> - optimization with a choice of compression type up to 100 SVG images (or 10 MB.) at a time.</pre>			
 </div>
</div>

<h4>7. Optimize the icon file</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Use the online constructor</div>
    <div class="collapse-body" style="display: none;">
<br>
Quite often, the site theme uses its own icon file (not with fonts.gstatic.com), which contains a huge number of vector images.<br>
It is a good practice to use only the necessary icons.<br>
<br>
<strong>Creating an optimized icon file:</strong><br>
1. In the <a href="http://fontello.com/" target="_blank">http://fontello.com/</a> service, select the icon set used on your site (for example, Font Awesome).<br>
2. Select the desired icons in the set and click "Download webfont" to save them.<br>
3. Place the generated file in the folder where the icons are located (for example, wp-content/themes/name_theme/assets/fonts)<br>
<br>
<strong>Note:</strong><br>
1. Make sure to create a backup of the default icon set file before replacing it with the generated one.<br>
2. If you don't know where the icon file is located, check out the Google PageSpeed Insights report.<br>
Usually, under "Reduce the nesting depth of critical queries" or in "Configure the display of all text while loading web fonts", you will find a link to an icon file (for example, fontawesome-webfont) with the extension woff2 or woff/ttf.

    </div>
</div>

<h4>8. Prevent hotlinks to images</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Write in .htaccess file the following rules</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong><font color="red">Attention!</font></strong><br>
Be sure to replace "SAIT.RU" to the url of your website (without http:// и www)
<br>
            <pre>#WP01_HOTLINKS_START
&lt;IfModule mod_rewrite.c&gt;
   RewriteEngine on
   RewriteCond %{HTTP_REFERER} !^$
#excluding our site
   RewriteCond %{HTTP_REFERER} !^http(s)?://(www\.)?<font color="red">SAIT.RU</font> [NC]
#adding domains to the exceptions
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
#formats that we process
   RewriteRule \.(jpg|jpeg|png|gif)$ - [NC,F,L]
&lt;/IfModule&gt;
#WP01_HOTLINKS_END</pre>
    </div>
</div>

<h4>9. Configure the display of all text while loading web fonts</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Make edits to the theme's CSS files</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong>Complete "@font-face " with the following conditions:</strong><br>
1. Install the plugin "<a href="https://wordpress.org/plugins/string-locator/" target="_blank">String locator</a>" and go to its <a href="/tools.php?page=string-locator" target="_blank">settings</a><br>
2. Select the active site theme in the "Search through" section of the plugin<br>
3. Enter "@font-face in the "Search string" field and click "Search"<br>
4. The search will reflect in the table the files and line numbers where the values "@font-face" were found<br>
5. Make edits to all values of "@font-face":<br>
5.1. Add "local(&#039;Pacifico Regular&#039;), local(&#039;Pacifico-Regular&#039;)," after "src:"<br>
5.2. Add "font-display: swap;" before "}"<br>
5.3. Save the file and check how the site works<br>
<br>
<strong>Note:</strong><br>
1. Be sure to create a backup of the edited CSS files, or the active theme<br>
2. If the theme is updated, re-install the code
    </div>
</div>

<h4>10. Set up preloading of web fonts</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Set the upload conditions</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong>Use the "preload" conditions:</strong><br>
1. ОOpen the file header.php located in the folder of the theme you are using (/wp-content/themes/system_name/)<br>
2. Add the code before the tag &lt;/head&gt;<br>
<code>&lt;link rel=&quot;preload&quot; as=&quot;font&quot; href=&quot;<font color="red">URL address to the web font</font>&quot; type=&quot;font/<font color="red">woff2</font>&quot; crossorigin&gt;</code>
<br>
<br><strong>Note:</strong><br>
1. Be sure to create a backup of the file you are editing<br>
2. If the theme is updated, re-install the code<br>
3. Don't forget to replace the value "URL address to web font" and MIME type
    </div>
</div>

<h4>11. Increase the memory limit for scripts</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Write down the increased values</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong>Make edits:</strong><br>
1. Specify the current memory limit for scripts by installing the plugin "<a href="#server-ip-memory-usage">Server IP & Memory Usage Display</a>" (available in the table above)<br>
2. Add to the file wp-config.php (located in the root of the site), before the line "/ * This is all, then do not edit. Good luck! * /" condition:<br>
<code>define( &#039;WP_MEMORY_LIMIT&#039;, &#039;<font color="red">xyz</font>M&#039; );</code><br>
where "xyz" is a value that exceeds the current limit, but not more than provided by the hosting.<br> 
3. Check whether the condition is triggered via the installed plugin (step 1).
<br>

<br><strong>Recommendations:</strong><br>
1. Be sure to create a backup of the file you are editing<br>
2. For low-load sites, the minimum recommended value for WP_MEMORY_LIMIT is 64. If you've installed WooCommerce - 96<br>
3. If the condition does not apply, try to write the code without spaces: <code>define(&#039;WP_MEMORY_LIMIT&#039;, &#039;<font color="red">xyz</font>M&#039;);"</code> or change <code>memory_limit= <font color="red">xyz</font>M</code> in the hosting php.ini file.<br>
4. If there is a memory limit error in the WordPress admin panel, write it down <code>define( &#039;WP_MAX_MEMORY_LIMIT&#039;, &#039;<font color="red">xyz</font>M&#039; );</code> before the line "/ * This is all, then do not edit. Good luck!*/". In this case "<font color="red">xyz</font>" it should be more than 2 or more times than for WP_MEMORY_LIMIT, but not exceed the limit provided by the hosting.
    </div>
</div>

<h4>12. Create a DNS resolving</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">List of important external resources</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong>Create a list of pre-connections:</strong><br>
1. Open the file header.php located in the folder of the theme you are using (/wp-content/themes/system_name/)<br>
2. Add the code before the tag &lt;/head&gt;, specifying the addresses of the most important/primary external connections (up to 6 pcs.)<br>
<code>&lt;link rel=&quot;dns-prefetch&quot; href=&quot;<font color="red">URL address of the site</font>&quot; /&gt;</code>
<br>

<br><strong>Note:</strong><br>
1. Be sure to create a backup of the file you are editing<br>
2. If the theme is updated, re-install the code<br>
3. Don't forget to replace the value of "URL address of the website"
    </div>
</div>

<h4>13. Disable loading dashicons. min. css in Frontend</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Set the icon ban code</div>
    <div class="collapse-body" style="display: none;">
<br>
If the public part of the site does not use the icon file "<a href="https://developer.wordpress.org/resource/dashicons/" target="_blank">Dashicons</a>" - disable its loading in Frontend, leaving it in the Backend<br>

<br><strong>Create a list of pre-connections:</strong><br>
1. Open the file functions.php located in the folder of the theme you are using (/wp-content/themes/theme name/) or use the plugin <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">Code Snippets</a> (Step 6)<br>
2. Add the code:<br>
<code>// WP01: removal dashicons START<br>
	function wpdocs_dequeue_dashicon() {<br>
		if (current_user_can( &#039;update_core&#039; )){<br>
			return;<br>
		}<br>
		wp_deregister_style(&#039;dashicons&#039;);<br>
	}<br>
	add_action( &#039;wp_enqueue_scripts&#039;, &#039;wpdocs_dequeue_dashicon&#039; );<br>
// WP01: removal dashicons END</code>
<br>

<br><strong>Note:</strong><br>
1. If the theme is updated, re-install the code (not relevant when using the plugin to add code)<br>
2. When found at the end of the file functions.php after closing the block &quot;?&gt;&quot;, place the code before it.<br>
3. If the site displays an error after installing the code, delete the code and refresh the page (Ctrl+F5)
    </div>
</div>

<h4>14. Check the relevance of Yandex. Metrica</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Learn the code for asynchrony</div>
    <div class="collapse-body" style="display: none;">
<br>
The Yandex. Metrica service updates the code that needs to be placed on the site.<br>
Older versions of yandex. Metrica work without using the asynchronous loading method, which is bad for performance.<br>

<br><strong>Check the code:</strong><br>
1. Find the code layout of Ya.Metrica on the site (usually located in a file footer.php, or header.php the theme used)<br>
2. Check the code for availability <code>k.async=1</code><br>
3. If there is no asynchronous condition, update the code by copying it from your account on the serviceе <a href="https://metrika.yandex.ru/" target="_blank">Ya.Metrika</a><br>

<br><strong>Note:</strong><br>
1. If the theme is updated, re-install the code<br>
2. If the site gives an error after installing the code, delete the code and refresh the page (Ctrl+F5)
    </div>
</div>

<h4>15. Disable "aggressive checking" for updates</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Use the code</div>
    <div class="collapse-body" style="display: none;">
<br>

HTTP requests are sent to check for kernel/theme/plugin updates when generating an admin page to instantly show you the search results for new versions. This approach creates an unjustified load and leads to hangups.<br>

<br><strong>Embed the code:</strong><br>
1. Open the file functions.php located in the folder of the theme you are using (/wp-content/themes/theme name/) or use the plugin <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">Code Snippets</a> (Step 6)<br>
2. Add the code:<br>
<code>//WP01: Disabling aggressive update checking START<br>
	if( is_admin() ){<br>
	// Disable checking for updates whenever you go to the admin panel<br>
		remove_action( 'admin_init', '_maybe_update_core' );<br>
		remove_action( 'admin_init', '_maybe_update_plugins' );<br>
		remove_action( 'admin_init', '_maybe_update_themes' );<br>
<br>
	// Disable checking for updates when you go to a special page in the admin panel<br>
		remove_action( 'load-plugins.php', 'wp_update_plugins' );<br>
		remove_action( 'load-themes.php', 'wp_update_themes' );<br>
<br>
	// Forced verification when entering the update page - we leave the work<br>
		//remove_action( 'load-update-core.php', 'wp_update_plugins' );<br>
		//remove_action( 'load-update-core.php', 'wp_update_themes' );<br>
<br>
	// Admin page "Update/Install Plugin" or "Update/Install Theme" - leave the work<br>
		//remove_action( 'load-update.php', 'wp_update_plugins' );<br>
		//remove_action( 'load-update.php', 'wp_update_themes' );<br>
<br>
	// Cron event to check for updates-leave the job<br>
		//remove_action( 'wp_version_check', 'wp_version_check' );<br>
		//remove_action( 'wp_update_plugins', 'wp_update_plugins' );<br>
		//remove_action( 'wp_update_themes', 'wp_update_themes' );<br>
<br>
	// Disable checking whether the browser needs to be updated in the console<br>
		add_filter( 'pre_site_transient_browser_'. md5( $_SERVER['HTTP_USER_AGENT'] ), '__return_true' );<br>
	}<br>
	//WP01: Disabling aggressive update checkin END
</code>
<br>

<br><strong>Note:</strong><br>
1. Checking for kernel/theme/plugin updates is done by cron<br>
2. To instantly check for updates, go to "<a href="/wp-admin/update-core.php" target="_blank">Console -> Updates</a>"<br>

<br><strong>Important:</strong><br>
1. If the theme is updated, re-install the code (not relevant when using the plugin to add code)<br>
2. When found at the end of the file functions.php closing the block &quot;?&gt;&quot; place the code before it.<br>
3. If the site gives an error after installing the code, delete the code and refresh the page (Ctrl+F5)
    </div>
</div>

<h4>16. Delayed loading of JivoSite</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Correct the code</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong>Use the delayed upload code:</strong><br>
1. Find the jivosite code layout on the site (usually located in a file footer.php, or header.php theme used)<br>
2. Delete the online consultant code you are using by first saving the ID (see the example below).<br>
3. Use the modified code by replacing the ID with your own:<br>
<code>&lt;!-- WP01: JIVOSITE START --&gt;<br>
&lt;script type=&#039;text/javascript&#039;&gt;<br>
(function(){ document.jivositeloaded=0;var widget_id = &#039;<font color="red">id</font>&#039;;var d=document;var w=window;function l(){var s = d.createElement(&#039;script&#039;); s.type = &#039;text/javascript&#039;; s.async = true; s.src = &#039;//code.jivosite.com/script/widget/&#039;+widget_id; var ss = document.getElementsByTagName(&#039;script&#039;)[0]; ss.parentNode.insertBefore(s, ss);}//Standard line of code JivoSite<br>
function zy(){<br>
    //Удаление EventListeners<br>
    if(w.detachEvent){//IE8 Support<br>
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
    //Starting the download function JivoSite<br>
    if(d.readyState==&#039;complete&#039;){l();}else{if(w.attachEvent){w.attachEvent(&#039;onload&#039;,l);}else{w.addEventListener(&#039;load&#039;,l,false);}}<br>
    //Setting a cookie that distinguishes the first hit from the second<br>
    var cookie_date = new Date ( );<br>
    cookie_date.setTime ( cookie_date.getTime()+60*60*28*1000); //24 hours for Moscow<br>
    d.cookie = &quot;JivoSiteLoaded=1;path=/;expires=&quot; + cookie_date.toGMTString();<br>
}<br>
if (d.cookie.search ( &#039;JivoSiteLoaded&#039; )&lt;0){//Check: whether this is the first visit to the site, if yes-assign EventListeners for scrolling events, resizing the browser window and scrolling on PC and mobile devices, for delayed loading of jivosite<br>
    if(w.attachEvent){// IE8 Support<br>
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

<br><strong>Example of an ID in the new code:</strong><br>
<code>&lt;script src=&quot;//code.jivosite.com/widget/<font color="red">id</font>&quot; async&gt;&lt;/script&gt;</code><br>
<strong>Example of an ID in the old code:</strong><br>
<code>&lt;!-- BEGIN JIVOSITE CODE {literal} --&gt;<br>
&lt;script type=&#039;text/javascript&#039;&gt;<br>
(function(){ var widget_id = &#039;<font color="red">id</font>&#039;;var d=document;var w=window;...</code><br>

<br><strong>Note:</strong><br>
1. If the theme is updated, re-install the code<br>
2. If the site gives an error after installing the code, delete the code and refresh the page (Ctrl+F5)<br>
<br>
<strong>P.S.</strong> If you do not use an online consultant on your site and would not like to see it on other projects on the network, install a blocker in your browser "<a href="https://hellogoodbye.app/" target="_blank">Hello, Goodbye</a>"
    </div>
</div>

<h4>17. Postpone loading of VK widgets</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Use the code</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong>Perform actions:</strong><br>
1. Replace the JS script connection code "https://vk.com/js/api/openapi.js" (usually placed in header.php site themes) with the following construction:<br>
<code>
	&lt;script type=&quot;text/javascript&quot;&gt;<br>
		setTimeout(function(){<br>
			var VKO = document.createElement(&quot;script&quot;);<br>
			VKO.src = &#039;https://vk.com/js/api/openapi.js&#039;;<br>
			VKO.async = true;<br>
			document.getElementsByTagName(&#039;head&#039;)[0].appendChild(VKO);<br>
			VKO.onload = function(){<br><br>
				// EXAMPLE (standard VK code) of initialization of the &quot;Community Messages&quot; widget<br>
				VK.Widgets.CommunityMessages(&quot;vk_community_messages&quot;, <font color="red">123456789</font>, {expanded: &quot;1&quot;,tooltipButtonText: &quot;Есть вопрос?&quot;});<br><br>
				// EXAMPLE (standard VK code) of initializing a widget for communities<br>
				VK.Widgets.Group(&quot;vk_groups&quot;, {mode: 3}, <font color="red">12345678</font>);<br><br
			};<br>
		},5000); // delayed loading time, in milliseconds (5000 = 5 seconds)<br>
	&lt;/script&gt;
	</code><br>
2. Replace the widget display code in the site page element with the lite version:<br>
	Example of displaying the "Community Messages" widget":<br>
	<code>
	&lt;div id=&quot;vk_community_messages&quot;&gt;&lt;/div&gt;
	</code><br>
	Example of displaying a widget for communities:<br>
	<code>
	&lt;div id=&quot;vk_groups&quot;&gt;&lt;/div&gt;
	</code>
<br>

<br><strong>Note:</strong><br>
1. If the site returns an error after installing the code, delete the code and refresh the page (Ctrl+F5)<br>
    </div>
</div>

<h4>18. Use a minified version of jQuery</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Replace the file</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong>Perform actions:</strong><br>
1. Find out the version of jQuery that the site uses. To do this, determine the URL where the library is loaded, and then open it in the editor. At the very beginning of the file, the version will be specified (for example, jQuery v1.12.4). <br>
&nbsp; Methods for determining the jQuery location:<br>
&nbsp; - Scan the site in <a href="https://developers.google.com/speed/pagespeed/insights/" target="_blank">Google PSI</a> and study the item "Remove resources that block the display", in which (in most cases) you will see a link to "jquery.js"<br>
&nbsp; - Open the code of the site page (Ctrl+U) and use the search (Ctrl+F) to find the file "jquery.js"<br>
&nbsp; - Launch the developer console in the browser (Ctrl+Shift+I - > Network - > All), then use the filter to find the file "jquery.js"<br>
2. In the open "jquery.in the" js file, define the use of minification (removing spaces).<br>
&nbsp; Example:<br>
&nbsp; Standard "jquery.js" v3.6.0: <a href="https://code.jquery.com/jquery-3.6.0.js" target="_blank">https://code.jquery.com/jquery-3.6.0.js</a> - 280,82 Kb.<br>
&nbsp; Minified "jquery.js" v3.6.0: <a href="https://code.jquery.com/jquery-3.6.0.min.js" target="_blank">https://code.jquery.com/jquery-3.6.0.min.js</a> - 89,50 Kb.<br>
3. If you use the standard version of jQuery on the site, replace the file with its minified version.<br>

<br><strong>Note:</strong><br>
1. Be sure to make a backup of the file used by the site "jquery.js"<br>
2. The name of the jQuery file used on the site must remain unchanged
    </div>
</div>

<h4>19. Apply translation caching</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Implement the library</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong>Perform actions:</strong><br>
1. Download the library <a href="https://github.com/pressjitsu/pomodoro/archive/refs/heads/master.zip" target="_blank">pomodoro</a>  <br>
2. Unzip the resulting archive and copy the file from it "pomodoro.php" to the "/wp-content/mu-plugins folder/"<br>
The script will start working, no additional actions are required.<br>

<br><strong>Note:</strong><br>
1. The more plugins you use on the site, the more noticeable the effect of the script will be<br>
2. If the folder "mu-plugins" is missing in the "/wp-content/" directory, create it yourself<br>
3. In case of errors, delete the file "pomodoro.php" to deactivate the library
    </div>
</div>

<h4>20. Speed up your website with WooCommerce</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Disable unused resources</div>
    <div class="collapse-body" style="display: none;">
<br>
<br><strong>Embed the code:</strong><br>
1. Open the file functions.php located in the folder of the theme you are using (/wp-content/themes/theme name/) or use the plugin <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">Code Snippets</a> (Step 6)<br>
2. Add the code:<br>
<code>//WP01: Disabling store resources on pages where they are not needed. START<br>
add_action(<br>
    &#039;wp_enqueue_scripts&#039;,<br>
    function() {<br>
        // If NOT the store pages.<br>
        if ( ! is_woocommerce() &amp;&amp; ! is_cart() &amp;&amp; ! is_checkout() ) {<br>
            // Disabling WooCommerce styles<br>
            wp_dequeue_style( &#039;woocommerce_frontend_styles&#039; );<br>
            wp_dequeue_style( &#039;woocommerce-general&#039;);<br>
            wp_dequeue_style( &#039;woocommerce-layout&#039; );<br>
            wp_dequeue_style( &#039;woocommerce-smallscreen&#039; );<br>
            wp_dequeue_style( &#039;woocommerce_fancybox_styles&#039; );<br>
            wp_dequeue_style( &#039;woocommerce_chosen_styles&#039; );<br>
            wp_dequeue_style( &#039;woocommerce_prettyPhoto_css&#039; );<br>
            wp_dequeue_style( &#039;select2&#039; );<br>
<br>
            // Disabling WooCommerce scripts<br>
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
	//WP01: Disabling store resources on pages where they are not needed. END
</code>
<br>

<br><strong>Important:</strong><br>
1. If the theme is updated, re-install the code (not relevant when using the plugin to add code)<br>
2. When found at the end of a file functions.php after closing the &quot;?&gt;&quot; block, place the code before it.<br>
3. If the site returns an error after installing the code, delete the code and refresh the page (Ctrl+F5)
    </div>
</div>