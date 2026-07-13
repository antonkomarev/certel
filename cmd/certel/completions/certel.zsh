#compdef certel
#
# zsh completion for certel. Completes certel's top-level command names.
# Install with:
#   certel completion zsh > "${fpath[1]}/_certel"
# or source it from ~/.zshrc:
#   source <(certel completion zsh)
_certel() {
	if (( CURRENT == 2 )); then
		local -a commands
		commands=(
			'monitor:watch the configured targets and deliver webhook alerts'
			'check:probe one target once and print the result as JSON'
			'validate-config:validate a configuration file and exit'
			'healthcheck:probe a running monitor'\''s /healthz and exit 0 or 1'
			'version:print the version'
			'completion:print a shell completion script'
			'help:print usage'
		)
		_describe 'command' commands
	fi
}

# Autoloaded from fpath the file defines _certel; sourced directly it must
# register the completion itself.
if [[ $funcstack[1] == _certel ]]; then
	_certel "$@"
else
	compdef _certel certel
fi
