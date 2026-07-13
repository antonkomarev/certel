# bash completion for certel
#
# Completes certel's top-level command names. Install with:
#   certel completion bash > /usr/share/bash-completion/completions/certel
# or source it from ~/.bashrc:
#   source <(certel completion bash)
_certel() {
	if [[ ${COMP_CWORD} -eq 1 ]]; then
		local commands="monitor check validate-config healthcheck version completion help"
		COMPREPLY=($(compgen -W "${commands}" -- "${COMP_WORDS[COMP_CWORD]}"))
	fi
}
complete -F _certel certel
