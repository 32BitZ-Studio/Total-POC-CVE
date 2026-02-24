<?PHP

session_start();

unset($_SESSION['login']);
unset($_SESSION['ip']);
session_destroy();

header("Location: index.php\n\n");

?>
