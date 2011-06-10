# encoding: UTF-8

module RequestLogAnalyzer::Aggregator

  # Echo Aggregator. Writes everything to the screen when it is passed to this aggregator
  class DevelonAggregator < Base

    attr_accessor :warnings

    def prepare(additional_options={})
      @warnings = []
      #un singolo import riguarda un singolo files e quindi un singolo servizio
      @log_file=LogFile.find additional_options[:log_file_id]#LogFile.find_by_path("/Users/Andrea/Code/develon_log/tmp/log_example/develon.com-access.log.20110401.gz")
      @log_file.update_attributes("status","reading")
      @service=nil
      @cached_entry={}
      @stime=Time.now
      @prec_timestamp=nil
      puts "Leggo #{@log_file.path} in #{Time.now-@stime}!!!!!!!!"
      
    end

    # Display every parsed line immediately to the terminal
    def aggregate(request)
      @service  ||= @log_file.service

      #DBG {:remote_host=>"188.94.127.225", :remote_logname=>nil, :user=>nil, :timestamp=>20110415181224, :http_method=>"GET", :path=>"/jspdevelon/jsp/web/rss.jsp", :http_version=>"1.1", :http_status=>200, :bytes_sent=>4585, :line_type=>:access, :lineno=>3804, :source=>"//Users/Andrea/Code/develon_log_old/tmp/log_example/develon.com-access.log.20110416.gz"}
      
      #       
      
      r=request.lines.first
      #Rails.logger.error "DBG #{request.inspect}"
      byts= r[:bytes_sent].to_i
      rowno=r[:lineno]
      norm_timestamp=LogEntry.get_timestamp_chunk r[:timestamp].to_s
      if @cached_entry[norm_timestamp].nil?
         @cached_entry[norm_timestamp]={:traffic=>byts,:rows=>rowno.to_s,:hit=>1}
         unless @prec_timestamp.nil?
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
   
    end

    # Capture all warnings during parsing
    def warning(type, message, lineno)
      @warnings << "WARNING #{type.inspect} on line #{lineno}: #{message}"
    end

    # Display every warning in the report when finished parsing
    def report(output)
      puts "Ho letto #{@log_file.path} in #{Time.now-@stime}!!!!!!!!"
      #output.title("Warnings during parsing")
      # @warnings.each { |w| output.puts(w) }
    end

  end
end