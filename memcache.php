<?php
/**
 * Created by PhpStorm.
 * User: Allan Lohse
 * Date: 27-05-2015
 * Time: 13:24
 */

$servers = array(array('127.0.0.1', 11212));
$memcache = new Memcache;
$memcacheD = new Memcached;
$memcache->addServer('127.0.0.1', 11211);
$memcacheD->addServers($servers);
$memcacheD->setOption(Memcached::OPT_BINARY_PROTOCOL, true);

$checks = array(
    123,
    4542.32,
    'a string',
    true,
    array(123, 'string'),
    (object)array('key1' => 'value1'),
);
foreach ($checks as $i => $value) {
    print "<br>Checking WRITE with Memcache\n";
    $key = 'cachetest' . $i;
    $memcache->set($key, $value);
    usleep(100);
    $val = $memcache->get($key);
    $valD = $memcacheD->get($key);
    if ($val !== $valD) {
        print "Not compatible!";
        var_dump(compact('val', 'valD'));
    } else {
        print "WAS COMPAT\n";
        var_dump(compact('val', 'valD'));
    }

    print "<br>Checking WRITE with MemcacheD\n";
    $key = 'cachetest' . $i;
    $memcacheD->set($key, $value);
    usleep(100);
    $val = $memcache->get($key);
    $valD = $memcacheD->get($key);
    if ($val !== $valD) {
        print "Not compatible!";
        var_dump(compact('val', 'valD'));
    } else {
        print "WAS COMPAT\n";
        var_dump(compact('val', 'valD'));
    }
}


?>