# encoding: UTF-8

module RequestLogAnalyzer::Aggregator

  # Echo Aggregator. Writes everything to the screen when it is passed to this aggregator
  class DevelonAggregator < Base

    attr_accessor :warnings

    def prepare(additional_options={})
      @warnings = []
      #un singolo import riguarda un singolo files e quindi un singolo servizio
      @log_file=LogFile.find additional_options[:log_file_id]#LogFile.find_by_path("/Users/Andrea/Code/develon_log/tmp/log_example/develon.com-access.log.20110401.gz")
      @service=nil#@log_file.service
      @cached_entry={}
      @stime=Time.now
      @prec_timestamp=nil    
    end

    # Display every parsed line immediately to the terminal
    def aggregate(request)
      # @log_file ||= LogFile.find_by_path(request.lines.first[:source])
      @service  ||= @log_file.service
      # <RequestLogAnalyzer::FileFormat::Apache::Request:0x00000103a694e8 @lines=[
      #         {:remote_host=>"188.94.127.225", :remote_logname=>nil, :user=>nil, :timestamp=>20110331102259, :http_method=>"GET", :path=>"/img/t_news.gif", :http_version=>"1.1", :http_status=>200, :bytes_sent=>504, :line_type=>:access, :lineno=>1202, :source=>"/Users/Andrea/Code/develon_log/tmp/log_example/develon.com-access.log.20110401.gz"}],
      #          @attributes={:remote_host=>"188.94.127.225", :remote_logname=>nil, :user=>nil, :timestamp=>20110331102259, :http_method=>"GET", :path=>"/img/t_news.gif", :http_version=>"1.1", :http_status=>200, :bytes_sent=>504, :line_type=>:access, :lineno=>1202, :source=>"/Users/Andrea/Code/develon_log/tmp/log_example/develon.com-access.log.20110401.gz"}, @file_format=#<RequestLogAnalyzer::FileFormat::Apache:0x00000104c57240 @line_definitions={:access=>#<RequestLogAnalyzer::LineDefinition:0x00000104c59400 @name=:access, @captures=[{:name=>:remote_host, :type=>:string}, {:name=>:remote_logname, :type=>:nillable_string}, {:name=>:user, :type=>:nillable_string}, {:name=>:timestamp, :type=>:timestamp}, {:name=>:http_method, :type=>:string}, {:name=>:path, :type=>:path}, {:name=>:http_version, :type=>:string}, {:name=>:http_status, :type=>:integer}, {:name=>:bytes_sent, :type=>:traffic}], @teaser=nil, @regexp=/((?-mix:(?-mix:(?:(?:[a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*(?:[A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9]))|(?-mix:(?-mix:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(?-mix:(?-mix:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})|(?-mix:(?:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)::(?:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?))|(?-mix:(?:(?:[0-9A-Fa-f]{1,4}:){6})(?-mix:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))|(?-mix:(?:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)::(?:(?:[0-9A-Fa-f]{1,4}:)*)(?-mix:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))))))\ ([\w-]+)\ (\w+|-)\ \[((?-mix:(?-mix:\d{2}\/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\/\d{4}:\d{2}:\d{2}:\d{2}\ (?:[+-]\d{4}|[A-Z]{3,4}))|(?-mix:\d{2}\/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\/\d{4}\ \d{2}:\d{2}:\d{2})))?\]\ "([A-Z]+) (\S+) HTTP\/(\d+(?:\.\d+)*)"\ (\d{3})\ (\d+|-)/, @header=true, @footer=true>}, @report_trackers=[#<RequestLogAnalyzer::Tracker::Timespan:0x00000104c58cf8 @options={}, @should_update_checks=[]>, #<RequestLogAnalyzer::Tracker::HourlySpread:0x00000104c58898 @options={}, @should_update_checks=[]>, #<RequestLogAnalyzer::Tracker::Frequency:0x00000104c584b0 @options={:category=>:http_method, :title=>"HTTP methods"}, @should_update_checks=[]>, #<RequestLogAnalyzer::Tracker::Frequency:0x00000104c580c8 @options={:category=>:http_status, :title=>"HTTP statuses"}, @should_update_checks=[]>, #<RequestLogAnalyzer::Tracker::Frequency:0x00000104c57c90 @options={:category=>#<Proc:0x00000104c57f38@/Users/Andrea/Code/request-log-analyzer/lib/request_log_analyzer/file_format/apache.rb:106 (lambda)>, :title=>"Most popular URIs"}, @should_update_checks=[]>, #<RequestLogAnalyzer::Tracker::Traffic:0x00000104c573f8 @options={:traffic=>:bytes_sent, :category=>#<Proc:0x00000104c576a0@/Users/Andrea/Code/request-log-analyzer/lib/request_log_analyzer/file_format/apache.rb:112 (lambda)>, :title=>"Traffic"}
      #         , @should_update_checks=[]
      #       
      
      r=request.lines.first
      byts= r[:bytes_sent].to_i
      rowno=r[:lineno]
      norm_timestamp=LogEntry.get_timestamp_chunk r[:timestamp].to_s
      if @cached_entry[norm_timestamp].nil?
         @cached_entry[norm_timestamp]={:traffic=>byts,:rows=>rowno.to_s,:hit=>1}
         unless @prec_timestamp.nil?
           # l=LogEntry.find_or_initialize_by_aggregator_params(r[:timestamp],@service.id,@log_file.id)
           l=LogEntry.new :service_id=> @service.id ,:log_file_id=>@log_file.id,:ref_time=>(Time.parse @prec_timestamp.to_s)
           l.rows=@cached_entry[@prec_timestamp][:rows]
           l.hit=@cached_entry[@prec_timestamp][:hit]
           l.traffic=@cached_entry[@prec_timestamp][:traffic]
           l.save
           @cached_entry.delete @prec_timestamp
           @log_file.import_progress=@prec_timestamp
           @log_file.save       
         end
         @prec_timestamp=norm_timestamp
      else
         @cached_entry[norm_timestamp][:traffic]+=byts
         @cached_entry[norm_timestamp][:hit]+=1
         #@cached_entry[norm_timestamp][:rows]+= ",#{rowno}" #not request
      end
      # l=LogEntry.find_or_initialize_by_aggregator_params(r[:timestamp],@service.id,@log_file.id)
      #     l.traffic+=byts
      #     l.rows||=""
      #     l.rows+="#{rowno},"
      #     l.hit+=1
      #     l.save
      
      
      # 6070:access: {:remote_host=>"192.168.254.86", :remote_logname=>nil, :user=>nil, :timestamp=>20110401035925, :http_method=>"GET", :path=>"/jsp/it/index/index.jsp", :http_version=>"1.0", :http_status=>200, :bytes_sent=>13249, :source=>"/Users/Andrea/Code/develon_log/tmp/log_example/develon.com-access.log.20110401.gz"}
      #un update per entry ... o creo in memoria e bulk alla fine?
      #LogEntry.summarize()
      # puts request.inspect
      # request.lines.map { |l| 
      #       
      #       }
      #       puts "HEI" + Report.first.id.to_s
      #       puts "\nRequest: \n" + request.lines.map { |l| 
      #         "\t#{l[:lineno]}:#{l[:line_type]}: #{l.reject { |(k,v)| [:lineno, :line_type].include?(k) }.inspect}" }.join("\n")
    end

    # Capture all warnings during parsing
    def warning(type, message, lineno)
      @warnings << "WARNING #{type.inspect} on line #{lineno}: #{message}"
    end

    # Display every warning in the report when finished parsing
    def report(output)
      puts "HO FINITO , ho letto  #{@cached_entry.keys.size} VALORI in #{Time.now-@stime}!!!!!!!!"
      output.title("Warnings during parsing")
      @warnings.each { |w| output.puts(w) }
    end

  end
end