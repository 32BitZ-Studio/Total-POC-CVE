$("form[name=workout]").submit(function () {
  $.ajax({
    url: '/workouts',
    type: 'POST',
    data: $('form[name=workout]').serialize(),
    success: function () {
      window.location.pathname = "/workouts"
    },
    error: function () {
      alert('Error submitting report');
    }
  });
  return false;
});

$("a#addEntry").click(function() {
  var tableRow, createInputCell, notNullValues;

  createInputCell = function(name, value, displayText) {
    if (typeof displayText === 'undefined') {
      displayText = value;
    }
    return $('<td><input name="' + name + '" value="' + value + '" type="hidden" /><span>' + displayText + '</span></td>');
  };

  notNullValues = [$('#exerciseId').val(), $('#setsCount').val()];

  if (notNullValues.indexOf('') >= 0)
    return false;

  tableRow = $('<tr class="entry"></tr>')
    .append(createInputCell('entries[][exerciseId]', $('#exerciseId').val(), $('#exerciseId').find(':selected').text()))
    .append(createInputCell('entries[][setsCount]', $('#setsCount').val()))
    .append(createInputCell('entries[][repsPerSet]', $('#repsPerSet').val()))
    .append(createInputCell('entries[][weight]', $('#weight').val()));

  $('#exerciseId, #setsCount, #repsPerSet, #weight').val(null);
  $('#workoutEntries').append(tableRow);

  return false;
});