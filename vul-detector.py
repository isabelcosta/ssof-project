def get_patterns(filename):
    #file: 'patterns.txt'
    f = open(filename, 'r')
    #print f
    
    non_blank_count = 0
    pattern_parameters = 4
    dict_patterns = dict()
    
    """ Count patterns in patterns.txt """
    with open('patterns.txt') as infp:
        for line in infp:
            if line.strip():
                non_blank_count += 1
    
    """ Number of patterns """            
    patterns = non_blank_count // 4
    
    print 'Number of patterns to analyze found %d' % patterns
    
    for pat in range(0,patterns):
        vulnerability = f.readline().strip()
        entry_points = f.readline()
        sanit_valid = f.readline()
        sensit_sinks = f.readline()
        
        ent_point_v = entry_points.strip().split(",")
        sanit_valid_v = sanit_valid.strip().split(",")
        sensit_sinks_v = sensit_sinks.strip().split(",")
        """
        {
        SQL Injetion : [
                            [
                                 entry_point,
                                 sanitit_valid,
                                 sensitiv_sinks
                            ],
                            [
                                 entry_point,
                                 sanitit_valid,
                                 sensitiv_sinks
                            ]
                        ],
         XSS : [
                            [
                                 entry_point,
                                 sanitit_valid,
                                 sensitiv_sinks
                            ],
                            [
                                 entry_point,
                                 sanitit_valid,
                                 sensitiv_sinks
                            ]
                        ],
        }
        """
        
        if vulnerability in dict_patterns :
            dict_patterns[vulnerability].append([
                ent_point_v,
                sanit_valid_v,
                sensit_sinks_v        
            ])
            
        else :  
            dict_patterns[vulnerability] = [
                [
                    ent_point_v,
                    sanit_valid_v,
                    sensit_sinks_v
                ]
            ]
              
    
    return dict_patterns
    
#print vul_detector()

def parse_trace(filename):
    
    #file: 'trace.xt'
    f = open(filename, 'r')
    
    #reads START line
    f.readline()
    
    functions = [];    
    
    for line in f:
        if "->" in line:
            signature = line.split("-> ")[1].split(" /")[0]
        else:
            continue;
        
        method_args = signature.split("(")
        method = method_args[0]
        args = method_args[1][:-1].split(", ")
    
        functions = functions + [(method, args)]
    return functions

def discover_vulnerability(dict_patterns, functions):
    warnings = []
    for current_f in functions :
        for pattern in dict_patterns:
            for pat_carac in dict_patterns[pattern] :
                #logo a function é sensitive_sink
                if current_f[0] in pat_carac[2]:
                    warn = [pattern,"",current_f[0],current_f[1]]
                    last_sink_index = functions.index(current_f)
                    #look for sanitizer
                    for sanit_tuple in reversed(functions[:last_sink_index]):
                        if sanit_tuple[0] in pat_carac[1]:
                            warn[1] = sanit_tuple[0]
                            warnings += [warn]
    
    print "---- Found the following vulnerability ----"                        
    for warn in warnings:
        print "- Vulnerability: ", warn[0]
        print "- Validation/Sanitization functions: ", warn[1]
        print "- Sensitive Sink function: ", warn[2]
        print "- Args used by Sensitive Sink function: ", ", ".join(warn[3])
        
#discover_vulnerability(get_patterns("patterns.txt"), parse_trace("trace.xt"))