# encoding: UTF-8

module RequestLogAnalyzer::RSpec::Helpers

  # Create or return a new TestingFormat
  def testing_format
    @testing_format ||= TestingFormat.create
  end

  # Load a log file from the fixture folder
  def log_fixture(name, extention = "log")
    File.dirname(__FILE__) + "/../fixtures/#{name}.#{extention}"
  end

  # Creates a log file given some lines
  def log_snippet(*lines)
    StringIO.new(lines.join("\n") << "\n")
  end

  # Request loopback
  def request(fields, format = testing_format)
    if fields.kind_of?(Array)
      format.request(*fields)
    else
      format.request(fields)
    end
  end

  # Run a specific command
  # Used to call request-log-analyzer through binary
  def run(arguments)
    binary = "#{File.dirname(__FILE__)}/../../bin/request-log-analyzer"
    arguments = arguments.join(' ') if arguments.kind_of?(Array)

    output = []
    IO.popen("#{binary} #{arguments}") do |pipe|
      output = pipe.readlines
    end
    $?.exitstatus.should == 0
    output
  end

  # Cleanup all temporary files generated by specs
  def cleanup_temp_files!
    Dir["#{File.dirname(__FILE__)}/../../tmp/spec.*tmp"].each do |file|
      File.unlink(file)
    end
  end

  # Return a filename that can be used as temporary file in specs
  def temp_output_file(file_type)
    File.expand_path("#{File.dirname(__FILE__)}/../../tmp/spec.#{file_type}.tmp")
  end
  
  # Check if a given string can be found in the given file
  # Returns the line number if found, nil otherwise
  def find_string_in_file(string, file, options = {})
    return nil unless File.exists?(file)
    
    line_counter = 0

    File.open( file ) do |io|
      io.each {|line|
        line_counter += 1
        line.chomp!

        p line if options[:debug]
        return line_counter if line.include? string
      }
    end
    
    return nil
  end
end
