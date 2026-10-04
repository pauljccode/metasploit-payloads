<?php
// Load transport functions only. Received packets are captured, never executed.
$source = file_get_contents($argv[1]);
$names = array('xor_bytes', 'dispatch_tcp', 'get_resource_map_id', 'register_stream',
  'close', 'read', 'get_rtype', 'select', 'add_reader', 'remove_reader');
foreach ($names as $name) {
  if (!preg_match('/^function ' . preg_quote($name, '/') . '\(.*?^\}/ms', $source, $match)) {
    fwrite(STDERR, 'Missing source function: ' . $name . "\n");
    exit(2);
  }
  $definition = $match[0];
  if ($name === 'read' || $name === 'select') {
    $definition = str_replace('function ' . $name . '(', 'function fixture_' . $name . '(', $definition);
  }
  eval($definition);
}
// Record real reads without changing their results. The peer holds the remainder
// until dispatch returns to select, so no scheduler-dependent sleep is needed.
function read($resource, $len=null) {
  $data = fixture_read($resource, $len);
  if (is_string($data)) $GLOBALS['bytes_read'] += strlen($data);
  return $data;
}
function select(&$r, &$w, &$e, $tv_sec=0, $tv_usec=0) {
  global $fragment_boundary, $bytes_read;
  if ($fragment_boundary > 0 && $bytes_read >= $fragment_boundary) {
    $fragment_boundary = 0;
    echo "WAITING_FOR_REMAINDER\n";
    fflush(STDOUT);
    if (fgets(STDIN) !== "continue\n") exit(2);
  }
  return fixture_select($r, $w, $e, $tv_sec, $tv_usec);
}
function my_print($message) {}
function dump_array($value, $label) {}
function get_c2_socket() { return $GLOBALS['receiver']; }
function decrypt_packet($packet) { return $packet; }
function create_response($packet) {
  $GLOBALS['received'][] = bin2hex($packet);
  return '';
}
function write_tlv_to_socket($socket, $response) {
  if (count($GLOBALS['received']) >= $GLOBALS['expected_count']) {
    if ($GLOBALS['mode'] === 'switch') $GLOBALS['next_transport_idx'] = 1;
    else $GLOBALS['running'] = false;
  }
}
$readers = array(); $resource_type_map = array(); $udp_host_map = array();
$mode = $argv[2];
$fragment_boundary = isset($argv[5]) ? (int)$argv[5] : 0;
$bytes_read = 0;
if ($mode === 'udp') {
  $receiver = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
  $sender = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
  socket_bind($receiver, '127.0.0.1', 0);
  socket_getsockname($receiver, $host, $port);
  socket_set_option($receiver, SOL_SOCKET, SO_RCVTIMEO, array('sec' => 1, 'usec' => 0));
  $resource_type_map[get_resource_map_id($receiver)] = 'socket';
  $udp_host_map[get_resource_map_id($receiver)] = array($host, $port);
  foreach (array("first\x00\xff", "second\x00\x80") as $data) {
    socket_sendto($sender, $data, strlen($data), 0, $host, $port);
  }
  $received = array(bin2hex(read($receiver)), bin2hex(read($receiver)));
  socket_close($receiver); socket_close($sender);
  echo json_encode(array('packets' => $received)), "\n";
  exit(0);
}
define('DISPATCH_EXIT', 0); define('DISPATCH_RETIRE', 1); define('DISPATCH_SWITCH', 2);
$receiver = stream_socket_client('tcp://127.0.0.1:' . $argv[3], $errno, $error, 5);
if ($receiver === false) { fwrite(STDERR, $error . "\n"); exit(2); }
register_stream($receiver);
$running = true; $session_expiry_end = time() + 5; $next_transport_idx = null;
$received = array(); $expected_count = (int)$argv[4];
$transport = array('_socket' => $receiver);
$result = dispatch_tcp($transport);
echo json_encode(array('result' => $result, 'packets' => $received)), "\n";
