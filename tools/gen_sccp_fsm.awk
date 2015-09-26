#!/usr/bin/gawk -f
BEGIN {
    name=""
    statetype=""
    eventtype=""
    lock=""
    unlock=""
    stateorigin=""
    signature=""
    action_signature=""
    action_parameters=""
    origlines=""
    fsm="NONE"
}

fsm == "NONE" && /^\/\*FSM\*\*/ {
    origlines=origlines $0
    fsm="HEADER"
    name=""
    statetype=""
    eventtype=""
    lock=""
    unlock=""
    stateorigin=""
    signature=""
    action_signature=""
    action_parameters=""
    FS=":"
}

fsm == "NONE" {
    print $0
}

fsm == "HEADER" && /^name:[ \t]*[a-zA-Z]/ {
    origlines=origlines "\n" $0
    name=$2
    fsm="FSMNAME"
    next
}

fsm == "FSMNAME" && /^statetype:[ \t]*[a-zA-Z]/ {
    origlines=origlines "\n" $0
    statetype=$2
    fsm="STATETYPE"
    next
}

fsm == "STATETYPE" && /^eventtype:[ \t]*[a-zA-Z]/ {
    origlines=origlines "\n" $0
    eventtype=$2
    fsm="EVENTTYPE"
    next
}

fsm == "EVENTTYPE" && /^lock:.*/ {
    origlines=origlines "\n" $0
    lock=$2
    fsm="LOCK"
    next
}

fsm == "LOCK" && /^unlock:.*/ {
    origlines=origlines "\n" $0
    unlock=$2
    fsm="UNLOCK"
    next
}

fsm == "UNLOCK" && /^stateorigin:.*/ {
    origlines=origlines "\n" $0
    stateorigin=$2
    fsm="STATEORIGIN"
    next
}
fsm == "STATEORIGIN" && /^signature:\((.*)\)$/ {
    origlines=origlines "\n" $0
    signature=$2
    fsm="SIGNATURE"
    next
}

fsm == "SIGNATURE" && /^action_signature:\((.*)\)$/ {
    origlines=origlines "\n" $0
    action_signature=$2
    fsm="ACTION_SIGNATURE"
    next
}

fsm == "ACTION_SIGNATURE" && /^action_parameters:\((.*)\)$/ {
    origlines=origlines "\n" $0
    action_parameters=$2
    fsm="ACTION_PARAMETERS"
    FS=" "
    next
}

fsm == "ACTION_PARAMETERS" && /^\#.*$/ {
    origlines=origlines "\n" $0
    skip=1
    next
}

fsm == "ACTION_PARAMETERS" && /^END_FSM_TABLE/ {
    origlines=origlines "\n" $0
    fsm="END_FSM"
    next
}

fsm == "END_FSM" && /[\/]?\*\*FSM_END\*\// {
    fsm="NONE"
    print_origlines()
    generate_code(name, statetype, eventtype, lock, unlock, stateorigin, signature, action_signature, action_parameters)
    next
}

fsm == "ACTION_PARAMETERS" {
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

function generate_transition_table(name, statetype, action_signature) 
{
    print "	struct state_transitions {"
    print "		const boolean_t (*action) " action_signature ";"
    print "		const char * action_name;"
    print "		" statetype "_t newstate;"
    print "		" statetype "_t failstate;"
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
                        resnewstate = toupper(statetype) "_SENTINEL"
                    }
                    resfailure = statemachine_failure[state][refevent]
                    if (resfailure == "") {
                        resfailure = toupper(statetype) "_SENTINEL"
                    }
                    print "			[" event "] = {" resaction "," resaction_str "," resnewstate "," resfailure "},"
                }
            }
            print "		},"
        }
    }
    print "	};"
}

function generate_fsm (name, statetype, eventtype, lock, unlock, stateorigin, signature, action_signature, action_parameters) 
{
    print "const " statetype "_t sccp_fsm_" name signature
    print "{"
    print "	assert(s != NULL);"
    print "	sccp_session_t * const session = (sccp_session_t * const) s;		/* discard const */"
    print "	" statetype "_t curstate;"
    print "	" statetype "_t newstate;"
    print ""
    generate_transition_table(name, statetype, action_signature)
    print ""
    print "	// get current state"
    print "	"lock";"
    print "	curstate = " stateorigin ";"
    print "	"unlock";"
    print "	newstate = curstate;"
    print ""
    print "	struct state_transitions const *curtransition = &state_transition_table[curstate][event];"
    print ""
    print "	sccp_log(DEBUGCAT_NEWCODE)(\"%s: (sccp_fsm_" name ") while in state:%s received event:%s\\n\", session->designator, " statetype "2str(curstate), " eventtype "2str(event));"
    print ""
    print "	// execute action and transition"
    print "	if (curtransition->newstate != " toupper(statetype) "_SENTINEL) {"
    print "		if (curtransition->action) {"
    print "			sccp_log(DEBUGCAT_NEWCODE)(\"%s: (sccp_fsm_" name ") executing action: %s on device:%s with curstate:%s\\n\", session->designator, curtransition->action_name, session->designator, " statetype "2str(curstate));"
    print "			if (curtransition->action" action_parameters") {"
    print "				newstate = curtransition->newstate;"
    print "			} else {"
    print "				newstate = curtransition->failstate;"
    print "				pbx_log(LOG_WARNING, \"%s: (sccp_fsm_" name ") action: %s returned FALSE\\n\", session->designator, curtransition->action_name);";
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
    print "		"lock";"
    print "		" stateorigin " = newstate;"
    print "		"unlock";"
    print "		sccp_log(DEBUGCAT_NEWCODE)(\"%s: (sccp_fsm_" name ") state:%s + event: %s -> action: %s => newstate: %s\\n\", session->designator, " statetype "2str(curstate), " eventtype "2str(event), curtransition->action_name,  " statetype "2str(newstate));";
    print "	} else {"
    print "		pbx_log(LOG_NOTICE, \"%s: (sccp_fsm_" name ") action: %s ignored\\n\", session->designator, curtransition->action_name);";
    print "	}"
    print ""
    print "	return newstate;"
    print "}"
}

function generate_code(name, statetype, eventtype, lock, unlock, stateorigin, signature, action_signature, action_parameters) {
    print "*/"
    print ""
    print "/*"
    print " * code below was generated by fsm.awk generator"
    print " * please do not change code until FSM_END marker."
    print " * any changes will be discarded."
    print " */"

    generate_fsm(name, statetype, eventtype, lock, unlock, stateorigin, signature, action_signature, action_parameters)
    print ""

    print "/**FSM_END*/"
}

END {
}
