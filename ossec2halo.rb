#!/usr/bin/env ruby
$LOAD_PATH << File.expand_path('./lib')
require 'nokogiri'
require 'haloformat'
require 'directories'
require 'exclusion'
require 'converter'

inputter = []
commands = []

match_ary = []


ARGV.each {|arg| commands << arg}
rb_file_master = Dir.glob(Directories.ossec_dir+"*.xml")

if ARGV[0] == 'convert'
  puts "Converting OSSEC .xml files to CloudPassage(r) Halo(r) .json format..."
  rb_file_master.each do |rb_file|
    f = File.open(rb_file)
    xmlStr = f.read

    # Use DocumentFragments for multiple root nodes
    doc = Nokogiri::XML::DocumentFragment.parse(xmlStr)
    items = doc.search("./group/rule")
    varData = doc.search("var")
    vars = {}

    varData.each do |v|
      vars[v.attr("name")] = v.text
    end

    # Parse variables
    doc.traverse do |node|
      if node.text?
        vars.each do |k, v|
          node.content = node.content.gsub(/\$#{k}/, v)
        end
      end
    end
    
    filename = rb_file.to_s.gsub(Directories.ossec_dir, '')
    zname = "OSSEC "+filename.gsub(/.xml/ , '')
    jname = "OSSEC_"+filename.gsub(/.xml/ , '.json')
    puts "[>>>] Generated "+jname+" in "+Directories.output_dir
    json_file = File.open(Directories.output_dir+jname, "w")
    json_file.write(Haloformat.header+
    Haloformat.name+zname+Haloformat.commaend+
    Haloformat.description+
    "Official OSSEC rules. Copyright (C) 2009-2014 Trend Micro Inc. - All rights reserved. License details: http://www.ossec.net/en/licensing.html"+
    Haloformat.commaend+
    Haloformat.platform+"linux"+Haloformat.commaend+
    Haloformat.template+
    Haloformat.retired+
    Haloformat.system+
    Haloformat.rules)

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
                    # rule_name.to_s.gsub(/\,$/, ''), # rule name not used anywhere. No use in parsing it
                    "",
                    rule_id,
                    level_id,
                    check_match.to_s.gsub( /\\/, '\\\\\\'),
                    check_desc.to_s.gsub( /\"/, '\\\"'),
                    check_info]
      end
      i += 1
    end
    f.close
    
    j = 0
    
    inputter.each do |json_ary|
      json_file.write("{"+Haloformat.check_name+
      json_ary[5]+" ("+json_ary[2]+")"+
      Haloformat.commaend+
      Haloformat.searchpattern+
      json_ary[4]+
      Haloformat.commaend+
      Haloformat.filepath+
      "/var/log/messages"+
      Haloformat.commaend+
      Haloformat.kind+
      "text"+
      Haloformat.commaend+
      Haloformat.active+
      Haloformat.alert+
      Haloformat.critical)
      if j < inputter.count-1
        json_file.write(Haloformat.rightcurl+",")
      elsif j == inputter.count-1
        json_file.write(Haloformat.rightcurl)
      end
      j+=1
    end
    json_file.write(Haloformat.footer)
    inputter.clear
    json_file.close
  end


elsif ARGV[0] == 'list'
	puts "[+] List of OSSEC XML files..."
	rb_file_master.each do |filename|
		puts "[>>>] "+filename.gsub(/#{Directories.ossec_dir}/, '')
	end

else puts Messages.usage
end