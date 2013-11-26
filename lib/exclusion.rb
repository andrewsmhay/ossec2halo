class Exclusion
	class << self
		def rule_ids
			%w[ 40101 ]
		end

		def files
			%w[ policy_rules.xml local_rules.xml ]
		end
	end
end