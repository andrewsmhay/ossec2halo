#!/usr/bin/env ruby
$LOAD_PATH << File.expand_path('./lib')
require 'nokogiri'
require 'haloformat'
require 'directories'

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

ARGV.each {|arg| commands << arg}
#rb_file_master = Dir.glob(Directories.ossec_dir+"*.xml")
rb_file_master = Directories.ossec_dir+"apache_rules.xml"
f = File.open(rb_file_master)
doc = Nokogiri::XML(f)
root = doc.root
puts root["name"]
items = root.xpath("rule")

puts items[11]["id"]
puts items[11]["level"]
puts items[11].at_xpath("match").inner_text
puts items[11].at_xpath("description").inner_text
f.close

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

match_ary = []
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