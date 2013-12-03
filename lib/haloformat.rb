class Haloformat
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
	    	"\"rules\": ["
		end

		def searchpattern
			"\"search_pattern\": \""
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
	    	name+"Apache"+commaend+
	    	description+
	    	"Official OSSEC rules for OSSEC. Copyright (C) 2009 Trend Micro Inc. - All rights reserved. This program is a free software; you can redistribute it and/or modify it under the terms of the GNU General Public License (version 2) as published by the FSF - Free Software Foundation. License details: http://www.ossec.net/en/licensing.html"+commaend+
	    	platform+"linux"+commaend+
	    	template+
	    	retired+
	    	system
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

	    def full_rule
	    	rule_construct_start+check_construct+rule_construct_end
	    end
	end
end