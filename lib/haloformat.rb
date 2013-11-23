class HaloFormat
	class << self
		def header
			"{\"iea_policy\": {"
		end

		def footer
			"]}}"
		end

		def name
			#note: comma added to the end of each JSON element
			"\"name\": \""
		end

		def comma
			","
		end

		def commaend
			"\","
		end

		def leftbrace
			"["
		end

		def rightbrace
			"]"
		end

		def leftcurl
			"{"
		end

		def rightcurl
			"}"
		end

		def description
			"\"description\": \""
		end

		def platform
			"\"platform\": \""
		end

		def template
	    	"\"template\": \"false\","
		end

		def retired
	    	"\"retired\": \"false\","
	    end

	    def system
	    	"\"system\": \"false\","
	    end

	    def rules
	    	"\"rules\": [{"
		end

		def searchpattern
			"\"search pattern\": \""
		end

		def filepath
	    	"\"file_path\": \""
	    end

	    def kind
	    	"\"kind\": \""
	    end

	    def active
	    	"\"active\": true,"
	    end

	    def alert
	    	"\"alert\": true,"
	    end

	    def critical
	    	"\"critical\": true"
	    end

	    def check_name
	    	"\"name\": \""
	    end

	    def rule_construct_start
	    	header+
	    	name+"[30108] User authentication failed"+commaend+
	    	description+"User authentication failed."+commaend+
	    	platform+"linux"+commaend+
	    	template+"false"+commaend+
	    	retired+"false"+commaend+
	    	system+"false"+commaend
	    end

	    def check_construct
	    	rules+
	    	check_name+"User authentication failed"+commaend+
	    	searchpattern+"authentication failed"+commaend+
	    	filepath+"/var/log/httpd/error_log"+commaend+
	    	kind+"text"+commaend+
	    	active+
	    	alert+
	    	critical+
	    	rightcurl
	    end

	    def rule_construct_end
	    	footer
	    end
	end
end