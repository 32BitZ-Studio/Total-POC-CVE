<?PHP
function generate_token($timestamp, $username) {
    $myfile = fopen("master_secret.txt", "r") or die("Unable to open file!");
    $secret = fread($myfile,filesize("master_secret.txt"));
    return md5($secret . $timestamp . $username);
}

function validate_token($timestamp, $username, $token) {
    $myfile = fopen("master_secret.txt", "r") or die("Unable to open file!");
    $secret = fread($myfile,filesize("master_secret.txt"));
    return md5($secret . $timestamp . $username) == $token;

}


?>
