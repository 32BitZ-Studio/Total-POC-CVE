<?php if ($formatted_date_start || $formatted_date_end): ?>
	<?php
	if ($formatted_date_start) {
		echo $formatted_date_start;
	}
	if ($formatted_date_start && $formatted_date_end && $formatted_date_start != $formatted_date_end) {
		echo ' - ';
	}
	if ($formatted_date_end && $formatted_date_start != $formatted_date_end) {
		echo $formatted_date_end;
	}
	if($content_field->is_time) {
		echo ' ' . $content_field->value['hour'] . ':' . $content_field->value['minute'];
	}
	?>
<?php endif; ?>