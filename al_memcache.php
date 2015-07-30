<?php
/**
 * Created by PhpStorm.
 * User: Allan Lohse
 * Date: 11-06-2015
 * Time: 09:57
 */

class al_memcache {
    private $serverpool = false;
    private $m = false;

    public function __construct() {
    #    parent::__construct();
        $this->serverpool = Array('127.0.0.1');

        return true;
    }

    public function get($key) {
        if (!$this->m) {
            if (!$this->connect()) {
                return false;
            }
        }

        return $this->m->get($key);
    }

    public function set($key, $value, $expire = 0) {
        if (!$this->m) {
            if (!$this->connect()) {
                return false;
            }
        }
        return $this->m->set($key, $value, 0, $expire);
    }

    public function delete($key) {
        if (!$this->m) {
            if (!$this->connect()) {
                return false;
            }
        }

        return $this->m->delete($key);
    }

    private function connect() {
#        if (!function_exists('memcache_add')) {
 #           return false;
  #      }
        echo"connect<br>";
        $this->m = new Memcache;

        foreach ($this->serverpool as $server) {
            $this->m->addServer($server, 11211, false);
        }

        return true;
    }

}