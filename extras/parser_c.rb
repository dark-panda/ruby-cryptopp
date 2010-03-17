
module RDoc
	class CustomParser < C_Parser
		extend ParserFactory
		parse_files_matching(/\.(?:([CcHh])\1?|c([+xp])\2|y)\z/)

		def mangle_comment(comment)
			comment.sub!(%r{/\*+}) { " " * $&.length }
			comment.sub!(%r{\*+/}) { " " * $&.length }
			comment.gsub!(/^[ \t]*\*/m, '')
			comment
		end

		private
			def do_constants
				@body.scan(
					%r{
						CRYPTOPP_DEFINE_CONST\(
							\s*(\w+)\s*,
							\s*"([^"]+)"\s*,
							\s*(\w+)\s*
						\)\s*;
					}xm
				) do |klass, name, definition|
					handle_constants('const', klass, name, definition)
				end
				super
			end

			def do_methods
				@body.scan(
					%r{
						CRYPTOPP_MODULE_METHOD\(
							\s*(\w+)\s*,
							\s*"([^"]+)"\s*,
							\s*(\w+)\s*,
							\s*(-?\w+)\s*
						\)
						(?:;\s*/[*/]\s+in\s+(\w+?\.cpp))?
					}xm
				) do |mod, name, body, params, source_file|
					handle_method('module_function', mod, name, body, params, source_file)
				end

				@body.scan(
					%r{
						CRYPTOPP_CLASS_METHOD\(
							\s*(\w+)\s*,
							\s*"([^"]+)"\s*,
							\s*(\w+)\s*,
							\s*(-?\w+)\s*
						\)
						(?:;\s*/[*/]\s+in\s+(\w+?\.cpp))?
					}xm
				) do |klass, name, body, params, source_file|
					handle_method('method', "rb_cCryptoPP_#{klass}", name, body, params, source_file)
				end

				@body.scan(
					%r{
						rb_define_(
							singleton_method |
							method           |
							module_function  |
							private_method
						)
						\s*\(\s*([\w\.]+),
						\s*"([^"]+)",
						\s*(?:RUBY_METHOD_FUNC\(|VALUEFUNC\()?(\w+)\)?,
						\s*(-?\w+)\s*\)
						(?:;\s*/[*/]\s+in\s+(\w+?\.cpp))?
					}xm
				) do |type, var_name, meth_name, meth_body, param_count, source_file|
					handle_method(type, var_name, meth_name, meth_body, param_count, source_file)
				end
			end

			def do_aliases
				@body.scan(
					%r{
						CRYPTOPP_MODULE_METHOD_ALIAS\(
							\s*(\w+)\s*,
							\s*"([^"]+)"\s*,
							\s*"([^"]+)"\s*
						\)\s*;
					}xm
				) do |mod, new_name, old_name|
					@stats.num_methods += 1
					class_name = @known_classes[mod] || mod
					class_obj  = find_class(mod, class_name)

					class_obj.add_alias(Alias.new("", old_name, new_name, ""))
				end

				@body.scan(
					%r{
						CRYPTOPP_CLASS_METHOD_ALIAS\(
							\s*(\w+)\s*,
							\s*"([^"]+)"\s*,
							\s*"([^"]+)"\s*
						\)\s*;
					}xm
				) do |klass, new_name, old_name|
					klass = "rb_cCryptoPP_#{klass}"
					@stats.num_methods += 1
					class_name = @known_classes[klass] || klass
					class_obj  = find_class(klass, class_name)

					class_obj.add_alias(Alias.new("", old_name, new_name, ""))
				end
				super
			end
	end
end