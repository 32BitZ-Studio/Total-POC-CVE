<?php
$one = array(0xa5, 0x00, 0x00, 0x00, 0x01, 0x3c, 0x00, 0x00, 0x49, 0xa9);
$two = array(0xa5, 0x00, 0x00, 0x00, 0x01, 0x5e, 0x00, 0x00, 0xbc, 0x19);

$fp = fsockopen("tcp://192.168.1.10", 5010, $errno, $errstr);
if(!$fp) {
    echo "ERROR: $errno - $errstr<br />\n";
} else {
    $str = "";
    foreach($one as $b) $str .= sprintf("%02x ", $b);
    echo("Sending: " . $str . "\n");
    fwrite($fp, pack("C*", ...$one));

    echo("Reading: ");
    for($i=0; $i<29; $i++) {
        $b = fgetc($fp);
        printf("%02x ", $b);
    }

    $str = "";
    foreach($two as $b) $str .= sprintf("%02x ", $b);
    echo("Sending: " . $str . "\n");
    fwrite($fp, pack("C*", ...$two));

    echo("Reading: ");
    for($i=0; $i<11; $i++) {
        $b = fgetc($fp);
        printf("%02x ", $b);
    }

    fclose($fp);
    echo("\nEnd\n\n");
}
?>
