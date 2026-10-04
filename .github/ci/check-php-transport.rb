require 'json'
require 'open3'
require 'socket'
require 'timeout'

source, revision, group = ARGV
group ||= 'all'
abort 'Usage: ruby check-php-transport.rb SOURCE baseline|candidate [all|tcp|udp]' unless source && %w[baseline candidate].include?(revision) && %w[all tcp udp].include?(group)
fixture = File.join(__dir__, 'php-transport-fixture.php')
frame = ->(body) { ("\x00" * 24) + [body.bytesize + 8].pack('N') + ("\x00" * 4) + body }
first = frame.call('01234567' * 8)
second = frame.call('abcdefgh' * 8)
hex = ->(bytes) { bytes.unpack1('H*') }
cases = {
  'whole' => [[first], [first], 0],
  'header-gap' => [[first[0, 8], first[8..]], [first], 0],
  'body-gap' => [[first[0, 40], first[40..]], [first], 0],
  'coalesced' => [[first + second], [first, second], 0],
  'between-frames' => [[first, second], [first, second], 0],
  'second-header-gap' => [[first + second[0, 8], second[8..]], [first, second], 0],
  'second-body-gap' => [[first + second[0, 40], second[40..]], [first, second], 0],
  'eof-header' => [[first[0, 8]], [], 1],
  'eof-body' => [[first[0, 40]], [], 1],
  'invalid-length' => [["\x00" * 32], [], 1],
  'shutdown' => [[first + second], [first], 0],
  'switch' => [[first + second], [first], 2],
  'udp' => [[], ["first\x00\xff".b, "second\x00\x80".b], nil]
}
known_failures = %w[header-gap body-gap second-header-gap second-body-gap invalid-length udp]
cases.select! { |name, _| (name == 'udp') == (group == 'udp') } unless group == 'all'

cases.each do |name, (chunks, expected_packets, expected_result)|
  server = TCPServer.new('127.0.0.1', 0)
  peer = nil
  output = error = status = nil
  begin
    Open3.popen3('php', '-d', 'display_errors=stderr', fixture, File.expand_path(source), name,
                server.addr[1].to_s, expected_packets.length.to_s,
                (chunks.length > 1 ? chunks.first.bytesize : 0).to_s) do |stdin, stdout, stderr, child|
      error_reader = Thread.new { stderr.read }
      begin
        Timeout.timeout(15) do
          unless name == 'udp'
            peer = server.accept
            peer.write(chunks.first)
            peer.close if name.start_with?('eof-')
          end
          output = String.new
          released = false
          stdout.each_line do |line|
            if line.chomp == 'WAITING_FOR_REMAINDER'
              raise 'Unexpected fragment release request' if released || chunks.length != 2
              peer.write(chunks.last)
              stdin.write("continue\n")
              stdin.flush
              released = true
            else
              output << line
            end
          end
          status = child.value
          error = error_reader.value
        end
      ensure
        unless child.join(0)
          begin
            Process.kill('KILL', child.pid)
          rescue Errno::ESRCH
            # The child exited between the liveness check and termination.
          end
          child.join
        end
        error_reader.join
      end
    end
    raise "#{name}: PHP failed: #{error}" unless status.success?
    result = JSON.parse(output)
    matches = result.fetch('packets') == expected_packets.map(&hex)
    matches &&= result.fetch('result') == expected_result unless expected_result.nil?
    expected_match = revision == 'candidate' || !known_failures.include?(name)
    raise "#{revision} #{name}: unexpected result #{result.inspect}; #{error}" unless matches == expected_match
    raise "#{name}: unexpected candidate stderr: #{error}" if revision == 'candidate' && !error.empty?
    puts "#{revision} #{name}: #{matches ? 'PASS' : 'EXPECTED_BASELINE_FAILURE'}"
  ensure
    peer.close if peer && !peer.closed?
    server.close
  end
end
