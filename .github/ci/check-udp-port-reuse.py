"""Fork-only real-session reproduction; no payload commands beyond socket tests."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys

framework, payloads = (Path(arg).resolve() for arg in sys.argv[1:3])
mode = sys.argv[3]
out = Path(sys.argv[4]).resolve()
assert mode in ('baseline', 'candidate')
out.mkdir(parents=True, exist_ok=False)
base = '0aa09117dcee240eb92b3d559a01593dccd44c14'
candidate = '2c5e2503a742a07f671eaae358468cf43ae69fa7'
revision = base if mode == 'baseline' else candidate
assert subprocess.check_output(['git', '-C', str(framework), 'rev-parse', 'HEAD'], text=True).strip() == '5e598d5233bebecef2a44904a286769d83d31d12'
source = subprocess.check_output(['git', '-C', str(payloads), 'show', revision + ':php/meterpreter/meterpreter.php'])
digest = hashlib.sha256(source).hexdigest()
module = framework / 'test/modules/post/test/socket_channels.rb'
helper = framework / 'spec/support/acceptance/child_process.rb'
original_module, original_helper = module.read_bytes(), helper.read_bytes()
override = framework / 'data/meterpreter/meterpreter.php'
assert not override.exists()
override.parent.mkdir(exist_ok=True)
override.write_bytes(source)
env = dict(os.environ, SPEC_HELPER_LOAD_METASPLOIT='false', SESSION='meterpreter/php',
           RAILS_ENV='test', MSF_CFGROOT_CONFIG=str(out / 'config'),
           UDP_PROBE_SHA256=digest, SPEC_OPTS='--tag acceptance')


def replace_once(text, old, new):
    assert text.count(old) == 1, old
    return text.replace(old, new)


try:
    # Optional local packaged-Ruby environment; hosted CI uses Framework's lock.
    if os.environ.get('UDP_PROBE_GEMFILE'):
        env['BUNDLE_GEMFILE'] = os.environ['UDP_PROBE_GEMFILE']
        helper.write_bytes(original_helper.replace(
            b"'BUNDLE_GEMFILE' => File.join(framework_root, 'Gemfile')",
            b"'BUNDLE_GEMFILE' => ENV.fetch('BUNDLE_GEMFILE')"))
    text = original_module.decode()
    text = replace_once(text, 'server.bind(params.peerhost, params.peerport)', '''@udp_probe_count = (@udp_probe_count || 0) + 1
    raise 'Wrong Framework source' unless Msf::Config.install_root == Dir.pwd
    actual = Digest::SHA256.hexdigest(MetasploitPayloads.read('meterpreter', 'meterpreter.php'))
    raise 'Wrong PHP source' unless actual == ENV.fetch('UDP_PROBE_SHA256')
    @reused_udp_bridge_port = @previous_udp_bridge_port if @udp_probe_count == 4
    port = @udp_probe_count == 4 ? @previous_udp_local_port : params.peerport
    server.bind(params.peerhost, port)
    print_status("UDP_REUSE_TRACE iteration=#{@udp_probe_count} bind=#{server.addr[1]} sha256=#{actual}")''')
    text = replace_once(text, 'client = session.create(params)\n    [client, server]', '''client = session.create(params)
    # Retain the channels so garbage collection cannot race this controlled case.
    @probe_channels ||= []
    @probe_channels << client.channel
    raw_name = BasicSocket.instance_method(:getsockname)
    @previous_udp_local_port = Socket.unpack_sockaddr_in(raw_name.bind(client).call)[0]
    @previous_udp_bridge_port = Socket.unpack_sockaddr_in(raw_name.bind(client.channel.rsock).call)[0]
    print_status("UDP_REUSE_TRACE cid=#{client.channel.cid} internal_port=#{@previous_udp_local_port} bridge_port=#{@previous_udp_bridge_port}")
    [client, server]''')
    text = replace_once(text, "it '[UDP] Receives data from the peer' do\n      client, server_client = udp_socket_pair\n      data = Random.new.bytes(rand(10..100))", "it '[UDP] Receives data from the peer' do\n      client, server_client = udp_socket_pair\n      data = (0...83).map { |value| (value ^ 0xa5).chr }.join.b\n      @previous_udp_data = data")
    text = replace_once(text, "it '[UDP] Sends data to the peer' do\n      client, server_client = udp_socket_pair\n      data = Random.new.bytes(rand(10..100))", "it '[UDP] Sends data to the peer' do\n      client, server_client = udp_socket_pair\n      data = ['cc11599bbc9b687658d5757a0b4844c037e15e696aca7caac8fa246bb090e8bb314b29ac355615b11fd059d8a42e8ec8'].pack('H*')\n      queued = !!IO.select([server_client], nil, nil, 1)\n      print_status(\"UDP_BEFORE_SEND queued=#{queued}\")")
    text = replace_once(text, 'received, _ = server_client.recvfrom(data.length)\n        ret = received == data', '''received, peer = server_client.recvfrom(data.length)
        print_status("UDP_SEND_TRACE expected=#{data.unpack1('H*')} received=#{received.unpack1('H*')} previous=#{@previous_udp_data.unpack1('H*')} peer_port=#{peer[1]} client_port=#{client.localport} old_bridge_port=#{@reused_udp_bridge_port}")
        ret = received == data''')
    module.write_text(text)
    (out / 'test-instrumentation.diff').write_bytes(subprocess.check_output(['git', '-C', str(framework), 'diff', '--', str(module)]))
    args = ['ruby', '-Ilib', '-Ispec', '-S', 'rspec', 'spec/acceptance/meterpreter_spec.rb',
            '--require', 'acceptance_spec_helper.rb', '--tag', 'acceptance',
            '--example', 'php/meterpreter_reverse_tcp" payload and passes the "post/test/socket_channels',
            '--format', 'documentation', '--format', 'AllureRspec::RSpecFormatter',
            '--format', 'json', '--out', str(out / 'rspec.json')]
    with (out / 'acceptance.log').open('w') as log:
        process = subprocess.Popen(args, cwd=framework, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=480)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            raise
    shutil.copytree(framework / 'tmp/allure-raw-data', out / 'allure')
    result = json.loads((out / 'rspec.json').read_text())
    log = (out / 'acceptance.log').read_text(errors='replace')
    summary = result['summary']
    expected_failures = 1 if mode == 'baseline' else 0
    assert summary['example_count'] == 1 and summary['errors_outside_of_examples_count'] == 0, summary
    assert summary['failure_count'] == expected_failures and code == expected_failures, summary
    assert f'Passed: {18 - expected_failures}; Failed: {expected_failures}; Skipped: 0' in log
    trace = re.search(r'UDP_SEND_TRACE expected=(\w+) received=(\w+) previous=(\w+) peer_port=(\d+) client_port=(\d+) old_bridge_port=(\d+)', log)
    assert trace, 'Missing byte/peer trace'
    expected, received, previous, peer_port, client_port, bridge_port = trace.groups()
    if mode == 'baseline':
        assert received == previous[:len(expected)] and received != expected
        assert peer_port == bridge_port and peer_port != client_port
        assert 'UDP_BEFORE_SEND queued=true' in log
        assert 'FAILED: [UDP] Sends data to the peer' in result['examples'][0]['exception']['message']
    else:
        assert received == expected and peer_port == client_port
        assert 'UDP_BEFORE_SEND queued=false' in log
    receipt = dict(mode=mode, payload_revision=revision, payload_sha256=digest,
                   summary=summary, expected=expected, received=received, previous=previous,
                   peer_port=peer_port, client_port=client_port, old_bridge_port=bridge_port)
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt), flush=True)
finally:
    module.write_bytes(original_module)
    helper.write_bytes(original_helper)
    override.unlink()
