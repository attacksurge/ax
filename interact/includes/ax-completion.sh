#!/bin/bash

# Define the function that generates completions
_ax_completions()
{
    # The first word is the command itself (ax)
    local command="${COMP_WORDS[1]}"

    # The current word (what the user has typed so far)
    local cur_word="${COMP_WORDS[COMP_CWORD]}"

    # List of commands that should trigger file completion
    local file_completion_commands="account account account-setup build configure deploy disks exec fleet fleet2 images init ls power provider region rm scan scp select sizes ssh sync update"

    # Check if the current command is in the list of those that should trigger file completion
    if [[ " ${file_completion_commands} " =~ " ${command} " ]]; then
        # Use file and directory completion
        COMPREPLY=($(compgen -f -- ${cur_word}))
    else
        # List of all available commands for the 'ax' command
        local commands="account account account-setup build configure deploy disks exec fleet fleet2 images init ls power provider region rm scan scp select sizes ssh sync update"

        # Generate possible completion matches for commands and store them in COMPREPLY
        COMPREPLY=($(compgen -W "${commands}" -- ${cur_word}))
    fi

    return 0
}

# Use complete to apply the _ax_completions function for the 'ax' command
complete -F _ax_completions ax
