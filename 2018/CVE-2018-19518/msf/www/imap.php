<html>
<body>
<p>imap_open example exploitation page.  Use URL parameter 'server'.  Ex http://1.1.1.1/imap.php?server=EXPLOITHERE</p>
<?php
$server = htmlspecialchars($_GET["server"]);
$mbox = @imap_open("{".$server.":143}INBOX",'username','password');
echo '<p>Received: '.$server.'</p>';

$errors = imap_errors();
if (is_array($errors)) {
    $errors = array_unique($errors);
}
if (count($errors) && is_array($errors)) {
    $str_errors = '';
    foreach ($errors as $error) {
        $str_errors .= $error . ', ';
    }
    $str_errors = rtrim(trim($str_errors), ',');
}
if (!$mbox) {
    echo '<p>Errors: ' . ($str_errors);
}
?>

</body>
</html>
