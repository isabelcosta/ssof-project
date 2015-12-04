f = open('patterns.txt', 'r')
print f

non_blank_count = 0

""" Count patterns in patterns.txt """
with open('patterns.txt') as infp:
    for line in infp:
        if line.strip():
            non_blank_count += 1

""" Number of patterns """            
patterns = non_blank_count // 4

print 'Number of patterns to analyze found %d' % patterns

for i in range(0,non_blank_count):
    f.readline()
