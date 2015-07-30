<?php
/**
 * Created by PhpStorm.
 * User: Allan Lohse
 * Date: 27-05-2015
 * Time: 13:18
 */

 
require_once('al_memcache.php');

$time_start = microtime(true);
$load_test=10000;
$allan = new al_memcache();
$allan->set('test','.',10);

for($i=0;$i<$load_test; $i++){
    $temp = $allan->get('test');
}
$time_slut = microtime(true);
$result = $time_slut-$time_start;
print "<br>".$load_test." req / ".$result." sec";
print "<br>1 req ".$result/$load_test." sec";
print "<br>".(1/($result/$load_test))." req / sec";
exit;


$allan = new al_memcache();
$allan->set('test','allan',10);

$allan2 = new al_memcache();
$allan2->set('test2',true,10);

$allan3 = new al_memcache();
$allan3->set('test3',false,10);

$temp2 = array ();
$temp = array ($temp2);
$allan4 = new al_memcache();
$allan4->set('test4',$temp,10);
$flags=false;
if ($a = $allan->get('test')){
    print "Got value : ".$a."<br>";
    var2($flags);
}
$flags=false;
if ($a = $allan2->get('test2')){
    print "Got value : ".$a."<br>";
    var2($flags);
}
$flags=false;
if ($a = $allan3->get('test3')){
    print "Got value : ".$a."<br>";
    var2($flags);
}
$flags=false;
if ($a = $allan4->get('test4')){
    print "Got value : ".$a."<br>";
    var2($flags);
}
print "..<br>";
$memcache_obj = memcache_pconnect('127.0.0.1', 11211);
memcache_set($memcache_obj, 'test5', 'sdf2', false, 10);
memcache_set($memcache_obj, 'test6', true, false, 10);
memcache_set($memcache_obj, 'test7', false, false, 10);
$temp2 = array ();
$temp = array ($temp2);
memcache_set($memcache_obj, 'test8', $temp, false, 10);
#memcache_set($memcache_obj, 'test8', NULL, false, 10);

$flags=false;
if ($a = memcache_get($memcache_obj, 'test5',$flags)){
    print "5:Got value : ".$a."<br>";
    if ($flags){print "Got flags";} else {print "No flags";}print "<br>";
    var2($flags);
}
$flags=false;
if ($a = memcache_get($memcache_obj, 'test6',$flags)){
    print "6:Got value : ".$a."<br>";
    if ($flags){print "Got flags";} else {print "No flags";}print "<br>";
    var2($flags);
}
$flags=false;
if ($a = memcache_get($memcache_obj, 'test7',$flags)){
    print "7:Got value : ".$a."<br>";
    if ($flags){print "Got flags";} else {print "No flags";}print "<br>";
    var2($flags);
}
$flags=false;
if ($a = memcache_get($memcache_obj, 'test8',$flags)){
    print "8:Got value : ".$a."<br>";
    if ($flags){print "Got flags";} else {print "No flags";}print "<br>";
    if(empty($a)){
        print "a is empty<br>";

    }
    var2($flags);
}

function var2($flags){
    print "<br>";
    var_dump($flags);
    print "<br>";
}
exit;

echo time();
exit;

$ch = curl_init("https://www.google.com/");
#$fp = fopen("example_homepage.txt", "w");

curl_setopt($ch, CURLOPT_FILE, $fp);
curl_setopt($ch, CURLOPT_HEADER, 0);

curl_exec($ch);
curl_close($ch);
#fclose($fp);

print "<pre>".$fp."</pre>";

print "<br>Hello5<br>";

# explode laver array
$channels = array('1','2','3');
#$channels = 1;
echo is_array($channels) ? 'is array' : 'not array';
echo "<br>";
$yep = explode(",",$channels);
echo $yep;
echo $channels[0];

$sql = "AND channel_id IN (".((is_array($channels)) ? implode(",", $channels) : $channels).")";

echo $sql;
?>