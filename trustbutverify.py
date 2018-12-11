import sys
import os

def main():
    print("\n") #helps with first line visibility
    with open(sys.argv[1],"r") as f:
        linenum = 0
        for line in f:
            linenum += 1
            if(line.find("#") == -1):
                #Any -> any rules
                if(line.find("any any -> any any") != -1):
                    if(line.find("content") != -1):
                        print("Line [" + str(linenum) + "] : MEDIUM : " + "any -> any rule. Consider scoping to appropraite endpoints\n")
                        print(line)
                        print("----------\n")
                    if (line.find("content") == -1):
                        print("Line [" + str(linenum) + "] : HIGH : " + "any -> any rule without content: fast pattern matching\n")
                        print(line)
                        print("----------\n")
                #Regular Expressions and Content
                if (line.find("pcre") != -1):
                        if(line.find("content") == -1):
                            print("Line [" + str(linenum) + "] : CRITICAL : " + "Regex (pcre) Rule, without content: fast pattern matching\n")
                            print(line)
                            print("----------\n")
                        else:
                            if(line.find("pcre") < line.find("content")):
                                print("Line [" + str(linenum) + "] : CRITICAL : " + "Regex (pcre) before Content in rule, swap their locations (order matters) \n")
                                print(line)
                                print("----------\n")
                #Missing TCP flow flags
                if (line.find("tcp") != -1 or line.find("http") != -1):
                        if(line.find("flow") == -1 and line.find("flag") == -1):
                            print("Line [" + str(linenum) + "] : MEDIUM: " + "TCP based rule without session awareness. Consider adding appropriate \"flow:\" direction\n")
                            print(line)
                            print("----------\n")
    f.close()

if __name__ == '__main__':
    main()
