#!/usr/bin/gawk -f
BEGIN {
    name=""
    type=""
    signature=""
    action_signature=""
    action_parameters=""
    origlines=""
    fsm=0
}

fsm == 0 && /^\/\*FSM\*\*/ {
    origlines=origlines $0
    fsm=1
    name=""
    type=""
    signature=""
    action_signature=""
    action_parameters=""
    FS=":"
}

fsm == 0 {
    print $0
}

fsm == 1 && /^name:[ \t]*[a-zA-Z]/ {
    origlines=origlines "\n" $0
    name=$2
    fsm=2
    next
}
fsm == 2 && /^type:[ \t]*[a-zA-Z]/ {
    origlines=origlines "\n" $0
    type=$2
    fsm=3
    next
}

fsm == 3 && /^signature:\((.*)\)$/ {
    origlines=origlines "\n" $0
    signature=$2
    fsm=4
    next
}

fsm == 4 && /^action_signature:\((.*)\)$/ {
    origlines=origlines "\n" $0
    action_signature=$2
    fsm=5
    next
}

fsm == 5 && /^action_parameters:\((.*)\)$/ {
    origlines=origlines "\n" $0
    action_parameters=$2
    fsm=6
    FS=" "
    next
}

fsm == 6 && /^\#.*$/ {
    origlines=origlines "\n" $0
    skip=1
    next
}

fsm == 6 && /^END_FSM_TABLE/ {
    origlines=origlines "\n" $0
    fsm=7
    next
}

fsm == 7 && /[\/]?\*\*FSM_END\*\// {
    fsm=0
    print_origlines()
    generate_code(name, type, signature, action_signature, action_parameters)
    next
}

fsm == 6 {
    origlines=origlines "\n" $0
    state=$1
    event=$3
    action=$5
    new_state_success=$7
    new_state_failure=$9
    
    if (state != "-") {
        states[state]=state
    }
    events[event]=event
    actions[action]=action

    statemachine_action[state][event]=action
    statemachine_newstate[state][event]=new_state_success
    statemachine_failure[state][event]=new_state_failure
}

function print_origlines() {
    print origlines
}

function generate_event_enum(name, type) {
    comma=0
    print "enum sccp_" name "_event {"
    for (event in events) {
    	if (event != "-") {
        	print "	SCCP_EVENT_" toupper(event) ","
        }
    }
    print "};"
    print ""
    printf "static const char * %s_event_str[] = {", name
    for (event in events) {
        if (event != "-") {
            if (comma) {
                printf ","
            }
            printf "\"%s\"", tolower(event)
            comma=1
        }
    }
    print "};"
}

function generate_transition_table(name, type, action_signature) 
{
    print "	struct state_transitions {"
    print "		const boolean_t (*action) " action_signature ";"
    print "		const char * action_name;"
    print "		" type "_t newstate;"
    print "		" type "_t failstate;"
    print "	} const state_transition_table[" length(states) "][" length(events) "] = {"
    for (state in states) {
        if (state!="INITIAL") {
            print "		[" state "] = {"
            for (event in events) {
                if (statemachine_action[state]["-"] == "-") {
                    refevent="-"
                } else {
                    refevent=event
                }
                if (event != "-") {
                    resaction = statemachine_action[state][refevent]
                    resaction_str = "\"" statemachine_action[state][refevent] "\""
                    if (resaction=="" || resaction=="-") {
                        resaction="NULL"
                        resaction_str="\"no_action\""
                    }
                    resnewstate = statemachine_newstate[state][refevent]
                    if (resnewstate == "") {
                        resnewstate = toupper(type) "_SENTINEL"
                    }
                    resfailure = statemachine_failure[state][refevent]
                    if (resfailure == "") {
                        resfailure = toupper(type) "_SENTINEL"
                    }
                    print "			[SCCP_EVENT_" event "] = {" resaction "," resaction_str "," resnewstate "," resfailure "},"
                }
            }
            print "		},"
        }
    }
    print "	};"
}

function generate_fsm (name, type, signature, action_signature, action_parameters) 
{
    print "const " type "_t sccp_fsm_" name signature
    print "{"
    print "	" type "_t curstate;"
    print "	" type "_t newstate;"
    print ""
    generate_transition_table(name, type, action_signature)
    print ""
    print "	// get current state"
    print "	sccp_private_lock(device);"
    print "	curstate = device->privateData->" name ";"
    print "	sccp_private_unlock(device);"
    print "	newstate = curstate;"
    print ""
    print "	struct state_transitions const *curtransition = &state_transition_table[curstate][event];"
    print ""
    print "	sccp_log(DEBUGCAT_NEWCODE)(\"%s: (sccp_fsm_" name ") while in state:%s received event:%s\\n\", device->id,  " type "2str(curstate), " name "_event_str[event]);"
    print ""
    print "	// execute action and transition"
    print "	if (curtransition->newstate != " toupper(type) "_SENTINEL) {"
    print "		if (curtransition->action) {"
    print "			sccp_log(DEBUGCAT_NEWCODE)(\"%s: (sccp_fsm_" name ") executing action: %s on device:%s with curstate:%s\\n\", device->id, curtransition->action_name, device->id, " type "2str(curstate));"
    print "			if (curtransition->action" action_parameters") {"
    print "				newstate = curtransition->newstate;"
    print "			} else {"
    print "				newstate = curtransition->failstate;"
    print "				pbx_log(LOG_WARNING, \"%s: (sccp_fsm_" name ") action: %s returned FALSE\\n\", device->id, curtransition->action_name);";
    print "			}"
    print "		} else {"
    print "			if (curtransition->newstate) {"
    print "				newstate = curtransition->newstate;"
    print "			} else {"
    print "				newstate = curstate;"
    print "			}"
    print "		}"
    print ""
    print "		// set new state"
    print "		sccp_private_lock(device);"
    print "		device->privateData->" name " = newstate;"
    print "		sccp_private_unlock(device);"
    print "		sccp_log(DEBUGCAT_NEWCODE)(\"%s: (sccp_fsm_" name ") state:%s + action: %s -> newstate: %s\\n\", device->id, " type "2str(curstate), curtransition->action_name,  " type "2str(newstate));";
    print "	} else {"
    print "		pbx_log(LOG_NOTICE, \"%s: (sccp_fsm_" name ") action: %s ignored\\n\", device->id, curtransition->action_name);";
    print "	}"
    print ""
    print "	return newstate;"
    print "}"
}

function generate_code(name, type, signature, action_signature, action_parameters) {
    print "*/"
    print ""
    print "/*"
    print " * code below was generated by fsm.awk generator"
    print " * please do not change code until FSM_END marker."
    print " * any changes will be discarded."
    print " */"

    generate_event_enum(name)
    print ""
    generate_fsm(name, type, signature, action_signature, action_parameters)
    print ""

    print "/**FSM_END*/"
}

END {
}
