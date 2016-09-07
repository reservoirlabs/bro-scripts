##! Load this script to disable/ enable logging of specific streams

# Need to load explicitly to use LoadedScripts::LOG
@load policy/misc/loaded-scripts.bro

module LogStreamControl;

export {
	## any :bro:type:`Log::ID` explicitly disabled
	const black_list_log_ids: set[Log::ID] &redef;

	## any :bro:type:`Log::ID` explicitly enabled
	const white_list_log_ids: set[Log::ID] &redef;

	## The rules of precedence:
	# If a log_id is present in never_disabled_log_ids, then it is never disabled regardless of whether it is present in blacklist or
	# absent from the white list
	# If both black and white lists are empty then all logs are enabled - Case 1
	# If the black list is not empty only logs specified in the black_list are disabled, the white list is ignored - Case 2
	# If the black list is empty and white list is not empty then all logs except the ones in the white list are disabled - Case 3

	## :bro:type:`Log::ID` never disabled regardless of above settings
	const never_disabled_log_ids: set[Log::ID] = {
	    Reporter::LOG,
	    Notice::LOG,
	    Notice::ALARM_LOG,
	    Intel::LOG,
	    LoadedScripts::LOG
	}&redef;
}

# Setup the streams to be disabled in bro_init with a very low priority
# This ensures that all the active streams are defined before this event
event bro_init() &priority=-255
{
    local black_list_empty = |black_list_log_ids| == 0;
    local white_list_empty = |white_list_log_ids| == 0;

    # Case-1 Nothing to be done
    if (black_list_empty && white_list_empty)
    {
        return;
    }

    if (!black_list_empty && !white_list_empty)
    {
        Reporter::warning("Both black and white list contain entries, ignoring white list");
    }

    # Create a copy of the currently active streams
    # Copy since we are modifying the streams that will be active
    local active_streams = copy(Log::active_streams);

    # Case 2
    if (!black_list_empty) {
        for (stream_id in active_streams)
        {
            # Remove the specified streams if they are not part of never_disabled_log_ids
            if (stream_id in black_list_log_ids && stream_id !in never_disabled_log_ids)
            {
                Log::disable_stream(stream_id);
                Reporter::info(fmt("log %s disabled ", stream_id));
            }
        }
        return;
    }

    # Case 3
    if (!white_list_empty) {
        for (stream_id in active_streams)
        {
            # Don't disable the members of the white list or never_disabled_log_ids
            if (stream_id in white_list_log_ids || stream_id in never_disabled_log_ids)
            {
                next;
            }
            # Disable every other stream
            Log::disable_stream(stream_id);
            Reporter::info(fmt("log %s disabled ", stream_id));
        }
        return;
    }
}
