#!/usr/bin/env ruby
$LOAD_PATH << File.expand_path('./lib')
require 'nokogiri'
require 'haloformat'
require 'directories'
require 'awesome_print'

=begin
Sample of OSSEC file

<group name="apache,">
  <rule id="30100" level="0">
    <decoded_as>apache-errorlog</decoded_as>
    <description>Apache messages grouped.</description>
  </rule>    

  <rule id="30101" level="0">
    <if_sid>30100</if_sid>
    <match>^[error] </match>
    <description>Apache error messages grouped.</description>
  </rule>
</group>
	
Sample of actual Halo rule

{
  "iea_policy": {
    "name": "Apache",
    "description": "Apache messages grouped.",
    "platform": "linux",
    "template": "false",
    "retired": "false",
    "system": "false",
    "rules": [
      {
        "name": "Apache error messages grouped.",
        "search pattern": "^[error] ",
        "file_path": "/var/log/apache2/error.log",
        "kind": "text",
        "active": true,
        "alert": true,
        "critical": true
      }
    ]
  }
}
=end

inputter = []
commands = []
i = 0
match_ary = []

ARGV.each {|arg| commands << arg}
rb_file_master = Dir.glob(Directories.ossec_dir+"*.xml")
#rb_file_master = Directories.ossec_dir+"*.xml"
rb_file_master.each do |rb_file|
  f = File.open(rb_file)
  doc = Nokogiri::XML(f)
  root = doc.root
  puts root["name"]
  items = root.xpath("rule")

  #items[11].xpath("match").each{|e| ap e.inner_text}

  until i == items.count
    if items[i].at_xpath("decoded_as") == nil || items[i]["frequency"] == nil || items[i].at_xpath("same_source_ip") == nil
      rule_id = items[i]["id"]
      level_id = items[i]["level"]
      if items[i].at_xpath("match") != nil
        check_match = items[i].at_xpath("match").inner_text
      elsif items[i].at_xpath("regex") != nil
        check_regex = items[i].at_xpath("regex").inner_text
      else
        check_match = nil
        check_regex = nil
      end
      check_desc = items[i].at_xpath("description").inner_text
      if items[i].at_xpath("info") != nil
        check_info = items[i].at_xpath("info").inner_text
      else check_info = nil
      end

=begin
      puts items[i]["id"]
      puts items[i]["level"]
      if items[i].at_xpath("match") != nil
        puts items[i].at_xpath("match").inner_text
        #items[i].xpath("match").each{|e| match_ary << e.inner_text} <-- this prints each <match>
      elsif items[i].at_xpath("regex") != nil
        puts items[i].at_xpath("regex").inner_text
      end
      puts items[i].at_xpath("description").inner_text
      if items[i].at_xpath("info") != nil
        puts items[i].at_xpath("info").inner_text
      end
=end
      
      inputter << [rule_id,
                  level_id,
                  check_match,
                  check_regex,
                  check_desc,
                  check_info]
    end
    i += 1
  end
  f.close
  ap inputter
end
#rb_file_master.each do |rb_file|
#	xml = Nokogiri::XML.parse(open rb_file)
=begin
      xml.css('group').each do |host|
        begin
          rule_id = host.css('id')
          check_decoded_as = host.css('decoded_as')
          check_if_sid = host.css('if_sid')
          check_regex = host.css('regex')
          check_name = host.css('group')
          check_desc = host.css('description')
          check_match = host.css('match')

          inputter << [rule_id.to_s,
               check_decoded_as.to_s,
		       		 check_if_sid.to_s,
		  			   check_regex.to_s,
		  			   check_name.to_s,
		  			   check_desc.to_s,
		  			   check_match.to_s]
        rescue Exception => e
          puts Messages.err
        next
        end
      end

  end


if ARGV[0] == 'convert'
	inputter.each do |matchers| 
	   unless matchers[5].empty?
	     puts matchers[0]+","+matchers[1]+","+matchers[2]+","+matchers[3]+","+matchers[4]+","+matchers[5]+","+matchers[6]
      #puts matchers[5]+"|"+matchers[4]
	end
end
puts Haloformat.full_rule

elsif ARGV[0] == 'list'
	puts "[+] List of OSSEC XML files..."
	rb_file_master.each do |filename|
		puts "[>>>] "+filename.gsub(/#{Directories.ossec_dir}/, '')
	end
else puts Messages.usage
end
=end