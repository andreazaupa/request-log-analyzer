# encoding: UTF-8

module RequestLogAnalyzer::FileFormat

  class Rack < Apache

    def self.create(*args)
      super(:rack, *args)
    end
  end
end
