#!/usr/bin/env ruby
$LOAD_PATH << File.expand_path('./lib')
require 'nokogiri'
require 'haloformat'
require 'directories'
require 'awesome_print'
require 'exclusion'

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

match_ary = []

ARGV.each {|arg| commands << arg}

rb_file_master = Dir.glob(Directories.ossec_dir+"*.xml")
rb_file_master.each do |rb_file|
  f = File.open(rb_file)
  doc = Nokogiri::XML(f)
  root = doc.root
  rule_name = root["name"]
  items = root.xpath("rule")
  #items[11].xpath("match").each{|e| ap e.inner_text}
  i = 0
  until i == items.count
    if (items[i].at_xpath("match") != nil || items[i].at_xpath("regex") != nil)
      rule_id = items[i]["id"]
      level_id = items[i]["level"]
      
      if items[i].at_xpath("match") != nil
        check_match = items[i].at_xpath("match").inner_text
      
      elsif items[i].at_xpath("regex") != nil
        check_match = items[i].at_xpath("regex").inner_text
      
      else check_match = nil
      
      end
      
      check_desc = items[i].at_xpath("description").inner_text

      if items[i].at_xpath("info") != nil
        check_info = items[i].at_xpath("info").inner_text
      else check_info = nil
      end
      
      inputter << [rb_file.to_s.gsub(Directories.ossec_dir, ''),
                  rule_name.to_s.gsub(/\,$/, ''),
                  "OSSEC Rule: "+rule_id,
                  level_id,
                  check_match.to_s.gsub(/ $/, '\\s'),
                  check_desc,
                  check_info]
    end
    i += 1
  end
  f.close
end
#puts inputter

if ARGV[0] == 'convert'
	inputter.each do |matchers| 
       puts matchers[0].to_s+","+matchers[1].to_s+","+matchers[2].to_s+","+matchers[3].to_s+","+matchers[4].to_s+","+matchers[5].to_s
      #puts matchers[5]+"|"+matchers[4]
	end
  #puts Haloformat.full_rule

elsif ARGV[0] == 'list'
	puts "[+] List of OSSEC XML files..."
	rb_file_master.each do |filename|
		puts "[>>>] "+filename.gsub(/#{Directories.ossec_dir}/, '')
	end
else puts Messages.usage
end