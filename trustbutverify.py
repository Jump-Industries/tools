import sys
import os


def main():
    print("\n")  # helps with first line visibility
    try:
        rule_file =open(sys.argv[1],"r")
    except:
        print("Usage: python trustbutverify.py <rules file> <1-4>")
        print("Rules file must be Snort/Suricata formatted")
        print("1 through 4 only displays matching severity level (1=low, 2=med, 3=high, 4=critical")
        sys.exit("ERROR, Cannot read rule file")

    with rule_file as f:

        try:
            filter = sys.argv[2]
        except:
            print("OK. Not filtering output")

        linenum = 0
        low=0
        med=0
        high=0
        crit=0

        for line in f:
            linenum += 1
            if line.find("#") == -1:
                # Any -> any rules
                if line.find("any any -> any any") != -1:
                    if (filter == '2') and line.find("content") != -1:
                        print("Line [" + str(linenum) + "] : MEDIUM : " + "any -> any rule. Consider scoping to appropriate endpoints\n")
                        print(line)
                        print("----------\n")
                        med += 1
                    if (filter == '3') and line.find("content") == -1:
                        print("Line [" + str( linenum) + "] : HIGH : " + "any -> any rule without content: fast pattern matching\n")
                        print(line)
                        print("----------\n")
                        high += 1
                # Regular Expressions and Content
                if (filter == '4') and line.find("pcre") != -1:
                    if line.find("content") == -1:
                        print("Line [" + str(linenum) + "] : CRITICAL : " + "Regex (pcre) Rule, without content: fast pattern matching\n")
                        print(line)
                        print("----------\n")
                        crit += 1
                    else:
                        if line.find("pcre") < line.find("content"):
                            print("Line [" + str(linenum) + "] : CRITICAL : " + "Regex (pcre) before Content in rule, swap their locations (order matters) \n")
                            print(line)
                            print("----------\n")
                            crit += 1
                # Missing TCP flow flags
                if line.find("tcp") != -1 or line.find("http") != -1:
                    if (filter == '2') and line.find("flow") == -1 and line.find("flag") == -1:
                        print("Line [" + str(linenum) + "] : MEDIUM: " + "TCP based rule without session awareness. Consider adding appropriate \"flow:\" direction\n")
                        print(line)
                        print("----------\n")
                        med += 1
    f.close()

    print("Final Stats:\n")
    print("Medium: [" + str(med) + "]")
    print("High: [" + str(high) + "]")
    print("Critical: [" + str(crit) + "]")


if __name__ == '__main__':
    main()
