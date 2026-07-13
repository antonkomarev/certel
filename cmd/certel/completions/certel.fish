# fish completion for certel. Completes certel's top-level command names.
# Install with:
#   certel completion fish > /usr/share/fish/vendor_completions.d/certel.fish
# or source it interactively:
#   certel completion fish | source
complete -c certel -f
complete -c certel -n __fish_use_subcommand -a monitor -d 'watch the configured targets and deliver webhook alerts'
complete -c certel -n __fish_use_subcommand -a check -d 'probe one target once and print the result as JSON'
complete -c certel -n __fish_use_subcommand -a validate-config -d 'validate a configuration file and exit'
complete -c certel -n __fish_use_subcommand -a healthcheck -d "probe a running monitor's /healthz and exit 0 or 1"
complete -c certel -n __fish_use_subcommand -a version -d 'print the version'
complete -c certel -n __fish_use_subcommand -a completion -d 'print a shell completion script'
complete -c certel -n __fish_use_subcommand -a help -d 'print usage'
