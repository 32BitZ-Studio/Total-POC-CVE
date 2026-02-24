$("form[name=changePassword]").submit(function() {
	$.ajax({
		url: '/changePassword',
		type: 'POST',
		data: {
			oldPassword: $('#old').val(),
			newPassword: $('#new').val(),
			repeatedPassword: $('#repeated').val()
		},
		success: function() {
			alert('Password changed!');
		},
		error: function(xhr, ajaxOptions, thrownError) {
			alert('Error!');
		}
	});
	return false;
});

$("form[name=changeUserInfo]").submit(function() {
	$.ajax({
		url: '/changeUserInfo',
		type: 'POST',
		data: {
			weight: $('#weight').val(),
			height: $('#height').val(),
			dateOfBirth: $('#dateOfBirth').val()
		},
		success: function() {
			alert('Info changed');
		},
		error: function(xhr, ajaxOptions, thrownError) {
			alert('Error occured!');
		}
	});
	return false;
});

$( document ).ready(function() {
	if ($('#weight').val() == 0) {
		$('#weight').val('');
	}
	if ($('#height').val() == 0) {
		$('#height').val('');
	}
});