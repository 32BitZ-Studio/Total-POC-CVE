$(function () {

  $('.news-like').click(function () {
    var _this, workoutId;
    _this = this;
    workoutId = $(this).data('id');
    $.post('/workouts/' + workoutId + '/like', function (likesCount) {
      var newsLike = $(_this).parent();
      newsLike.find('.news-likes-count').text(likesCount);
      newsLike.append('<span>Liked!</span>')
      $(_this).remove();
    })
  })

  $('.invite').click(function() {
    var _this = this, id = $(this).data('id');
    $.ajax({
      url: '/users/' + id + '/invite',
      type: 'POST',
      success: function() {
        $(_this).parents('li').remove()
        alert('Request sent');
      }
    });
  });

  $('.accept-invitation').click(function() {
    var _this = this, id = $(this).data('id');
    $.ajax({
      url: '/users/' + id + '/accept',
      type: 'POST',
      success: function() {
        var li = $(_this).parents('li'), userName;
        userName = li.find('.user-name').text();
        li.text('You and ' + userName + ' are now friends');
        li.delay(2000).fadeOut('slow', function () {
          $(this).remove();
        });
      }
    });
  });

  $('.decline-invitation').click(function() {
    var _this = this, id = $(this).data('id');
    $.ajax({
      url: '/users/' + id + '/decline',
      type: 'POST',
      success: function() {
        var li = $(_this).parents('li');
        li.text('Request removed.');
        li.delay(2000).fadeOut('slow', function () {
          $(this).remove();
        });
      }
    });
  });

})