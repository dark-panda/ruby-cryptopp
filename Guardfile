
guard 'minitest', :test_folders => 'test', :test_file_patterns => '*_test.rb' do
  watch(%r|^test/(.+)_test\.rb|)

  watch(%r{^lib/(.*/)?([^/]+)\.rb$}) do |m|
    "test/#{m[2]}_test.rb"
  end

  watch(%r|^test/test_helper\.rb|) do
    "test"
  end
end

if File.exists?('Guardfile.local')
  instance_eval File.read('Guardfile.local')
end

