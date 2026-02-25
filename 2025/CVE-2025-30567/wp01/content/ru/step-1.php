<?php

if (!defined('ABSPATH')) {
    die('Don\'t hack please!');
}

?>
<div class="card tip">
    <h3>Технические данные</h3>
    <ul>
        <li><strong>Версия WP:</strong>             <?php WP01_Content::the_wp_version() ?></li>
        <li><strong>Версия PHP:</strong>            <?php WP01_Content::the_php_version() ?></li>
        <li><strong>Лимит операт. памяти:</strong>  <?php WP01_Content::the_memory_limit() ?></li>
        <li><strong>Версия MySQL:</strong>          <?php WP01_Content::the_db_version() ?></li>
        <li>
            <strong>Расположение файлов сайта на хостинге:</strong><br>
            <code><?php echo ABSPATH ?></code>
        </li>
    </ul>
</div>
<h2>Шаг 1/7. <span class="name">Общая информация</span></h2>
<p>Добро пожаловать в "WP01" - инструмент для самостоятельного улучшения Wordpress сайта</p>

	<div class="notice notice-info notice-alt inline">
		<p>
			<strong>Пройдя все шаги, ваш сайт будет:</strong><br>
&bull; работать быстрее;<br>
&bull; соответствовать SEO стандартам;<br>
&bull; предотвращать проникновение вирусов;<br>
&bull; отражать спам;<br>
&bull; защищён от взлома;<br>
&bull; более удобен для пользователей;
		</p>
	</div>
	<p>С каждым свежим выпуском вы получаете новые техники.<br>
	Все представленные улучшения протестированы и используются в работе.<br>
	Наш опыт и знания перед вами, удачной настройки!
	</p>
<p>
			<i>С уважением,<br>
			Команда специалистов "WP01"</i>
</p>