<?php foreach ($listing->videos AS $video): ?>
	<?php if (strlen($video['id']) == 11): ?>
		<iframe width="100%" height="400" class="w2dc-video-iframe fitvidsignore" src="//www.youtube.com/embed/<?php echo $video['id']; ?>" frameborder="0" allowfullscreen></iframe>
	<?php elseif (strlen($video['id']) == 9): ?>
		<iframe width="100%" height="400" class="w2dc-video-iframe fitvidsignore" src="https://player.vimeo.com/video/<?php echo $video['id']; ?>?color=d1d1d1&title=0&byline=0&portrait=0" frameborder="0" webkitallowfullscreen mozallowfullscreen allowfullscreen></iframe>
	<?php endif; ?>
<?php endforeach; ?>