##! The UI for Log Stream Control
module LogStreamControl;

export {

    # Available log ids at https://www.bro.org/sphinx/scripts/base/frameworks/logging/main.bro.html#type-Log::ID

    ## This line tells Bro to only disable the specified log streams.
    # Predefined value is empty
    redef black_list_log_ids += {};

    ## This line tells Bro to only enable the specified log streams.
    # Predefined value is empty
    redef white_list_log_ids += {};

    ## The additional list of log ids that should never be disabled regardless of the contents of the white list or blacklist
    # The predefined values include logs useful for characterizing R-Scope performance and debugging scripts
    # Recommended usage is to leave this unmodified
    redef never_disabled_log_ids += {};

    # The rules of precedence:
    # never_disabled_log_ids are not disabled regardless of the contents of the white list or black list.
    # If both black and white lists are empty then all logs are enabled
    # If the black list is not empty only logs specified in the black_list are disabled, the white list is ignored
    # If the black list is empty and white list is not empty then all logs except the ones in the white list are disabled
}
