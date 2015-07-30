<?php
/**
 * Created by PhpStorm.
 * User: Allan Lohse
 * Date: 27-05-2015
 * Time: 13:44
 */

/* OO API */
print "memcached lokal data :";
print " ". date('Y-m-d H:i:s') ."\n";
print "<a href=\"/phpMemcached/\" target=\"_blank\">phpMemcached</a>";
#$memcache_obj = new Memcache;
#$memcache_obj->connect('127.0.0.1', 11211);

/* connect to memcached server */
/*
set value of item with key 'var_key', using on-the-fly compression
expire time is 50 seconds
MEMCACHE_COMPRESSED
*/

#$memcache_obj->delete('allanlohse',0);
#$memcache_obj->set('allanlohse', 'sd', 0, 600);
echo "<br><hr>";
echo "<table>\n";
echo "<tr><th>Udloeb</th><th>Key</th><th>TTL</th></tr>\n";
getMemcacheKeys();
echo "</table>";
if ($_GET['key']){
    print "<a href='?key='>reset</a>";
}
print " <a href='".$_SERVER['PHP_SELF']."?key=".$_GET['key']."'>refresh</a>";

#echo "<br><hr>";
#echo "<br>result : ".$memcache_obj->get('cachetest3');
#echo "<br>result : ".$memcache_obj->get('allanlohse');
#sleep(11);
#echo "<br>result : ".$memcache_obj->get('allanlohse');

function getMemcacheKeys() {
    $memcache = new Memcache;
    $memcache->connect('127.0.0.1', 11211)
    or die ("Could not connect to memcache server");

    $list = array();
    $allSlabs = $memcache->getExtendedStats('slabs');
    $items = $memcache->getExtendedStats('items');
    foreach($allSlabs as $server => $slabs) {
        foreach($slabs AS $slabId => $slabMeta) {
            if (!is_numeric($slabId)) {
                continue;
            }
            $cdump = $memcache->getExtendedStats('cachedump',(int)$slabId);
            asort($cdump);
            foreach($cdump AS $keys => $arrVal) {
                if (!is_array($arrVal)) continue;

                foreach($arrVal AS $k => $v) {
                    if (!$_GET['key'] || (strpos($k, $_GET['key']) !==false)) {
                        print  "<tr><td>" . date('H:i:s d.m.Y', $v[1] + 108955) . "</td><td><a href='?key=".$k."'>" . $k . "</a></td><td>" . ($v[1] - time()) . "</td></tr>\n";
                    }
                }
            }
        }
    }
}

?>