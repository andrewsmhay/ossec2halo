class Ruleconvert
	attr_accessor(:filename, :rulename, :ruledesc, :ruleplatform)

	def testing
		"Testing #{@ruledesc}"
	end
end

class Checkcrit 
	attr_accessor :critical
end

class Checkconvert
	attr_accessor(:chkname, :chksearch, :chkfilepath)
end


